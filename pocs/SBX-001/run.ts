import "dotenv/config";

import { randomBytes, randomUUID } from "node:crypto";
import { Resolver } from "node:dns/promises";
import { lstat, mkdir, readFile, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { APIError, Sandbox, type NetworkPolicy } from "@vercel/sandbox";
import { fetchDnsAnalytics } from "./analytics.js";
import {
  ANALYTICS_ROW_LIMIT,
  ELIGIBLE_ALIAS_EMAIL,
  ELIGIBLE_PROJECT_ID,
  ELIGIBLE_TEAM_ID,
  EVENT_BRACKET_SKEW_MS,
  GATE_PATTERN,
  OPERATION_ID_PATTERN,
  QUERY_NONCE_PATTERN,
  SHA256_PATTERN,
  TEST_ID,
  TEST_ID_POC,
  ZONE_NAME,
  analyzeSecretPositiveRows,
  assessStage,
  expectedOperationId,
  gateAuthorization,
  historicalSuffixCollisionCount,
  publicQueryName,
  sha256Bytes,
  type PositiveAnalysis,
  type RunStage,
} from "./shared.js";

const scopeConfirmation = "I_CONTROL_FORM_APP_APP_AND_AUTHORIZE_BOUNDED_DNS_ANALYTICS_TESTING";
const wildcardConfirmation = "I_VERIFIED_SBX001_DNS_ONLY_WILDCARD_A_TO_192_0_2_1";
const remoteProbePath = "/tmp/sbx-001/dns-deny-probe.mjs";
const remoteSecretPath = "/tmp/sbx-001/operator-secret";
const httpsControlUrl = `https://${ZONE_NAME}/`;
const minimumVercelCallIntervalMs = 250;
const controlPlaneTimeoutMs = 30_000;
const dnsQueryTimeoutMs = 2_500;
const historicalLookbackMs = 24 * 60 * 60 * 1_000;

type PolicyLiteral = "allow-all" | "deny-all";

interface CommandRecord {
  commandId: string;
  exitCode: number;
  durationMs?: number;
  stdoutByteLength: number;
  stdoutSha256: string;
  stderrByteLength: number;
  stderrSha256: string;
}

interface CleanupRecord {
  orphanRecoveryAttempted: boolean;
  recoveredHandle: boolean;
  orphanAbsenceConfirmed: boolean;
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  deletionAbsenceCheckAttempted: boolean;
  deletionAbsenceConfirmed: boolean;
  errors: string[];
}

class IndeterminateError extends Error {}

class RateGate {
  private lastStartedAt = 0;

  async beforeVercelCall(): Promise<void> {
    const remaining = minimumVercelCallIntervalMs - (Date.now() - this.lastStartedAt);
    if (remaining > 0) await delay(remaining, undefined, { signal: AbortSignal.timeout(2_000) });
    this.lastStartedAt = Date.now();
  }
}

function controlSignal(timeoutMs = controlPlaneTimeoutMs): AbortSignal {
  return AbortSignal.timeout(timeoutMs);
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function safeError(error: unknown, secrets: string[]): string {
  let message = error instanceof Error ? error.message : String(error);
  for (const secret of secrets) {
    if (secret) message = message.split(secret).join("[REDACTED]");
  }
  return message.replace(/[\0\r\n]/gu, " ").slice(0, 1_000);
}

function isNotFound(error: unknown): boolean {
  return error instanceof APIError && error.response.status === 404;
}

function explicitCredentials(): { token: string; teamId: string; projectId: string } {
  const token = required("VERCEL_TOKEN");
  const teamId = required("VERCEL_TEAM_ID");
  const projectId = required("VERCEL_PROJECT_ID");
  if (teamId !== ELIGIBLE_TEAM_ID || projectId !== ELIGIBLE_PROJECT_ID) {
    throw new Error("SBX-001 requires the exact verified HackerOne-alias Vercel team and project");
  }
  return { token, teamId, projectId };
}

function proofKey(): string {
  const value = required("SBX001_PROOF_KEY");
  if (Buffer.byteLength(value) < 32 || Buffer.byteLength(value) > 256 || /[\0\r\n]/u.test(value)) {
    throw new Error("SBX001_PROOF_KEY must contain 32-256 bytes without control characters");
  }
  return value;
}

function cloudflareToken(): string {
  const value = required("CLOUDFLARE_API_TOKEN");
  if (Buffer.byteLength(value) < 20 || Buffer.byteLength(value) > 512 || /[\0\r\n]/u.test(value)) {
    throw new Error("CLOUDFLARE_API_TOKEN must contain 20-512 bytes without control characters");
  }
  return value;
}

async function verifyAliasIdentity(token: string, gate: RateGate): Promise<string> {
  await gate.beforeVercelCall();
  const response = await fetch("https://api.vercel.com/v2/user", {
    headers: { authorization: `Bearer ${token}` },
    signal: controlSignal(10_000),
  });
  if (!response.ok) throw new Error(`could not verify Vercel token identity (${response.status})`);
  const payload = await response.json() as { user?: { email?: unknown } };
  if (payload.user?.email !== ELIGIBLE_ALIAS_EMAIL) {
    throw new Error("Vercel token is not authenticated as the required HackerOne alias");
  }
  return payload.user.email;
}

function boundedInteger(value: string, name: string, minimum: number, maximum: number): number {
  if (!/^[0-9]+$/u.test(value)) throw new Error(`${name} must be an integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be from ${minimum} through ${maximum}`);
  }
  return parsed;
}

function parseArguments(argv: string[]): {
  stage: RunStage;
  gatePath?: string;
  analyticsWaitMs: number;
  analyticsPollMs: number;
} {
  let stage: RunStage | undefined;
  let gatePath: string | undefined;
  let analyticsWaitMs = 90 * 60 * 1_000;
  let analyticsPollMs = 5 * 60 * 1_000;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--stage") {
      const value = argv[++index];
      if (value !== "allow-control" && value !== "deny-control" && value !== "deny-secret") {
        throw new Error("--stage must be allow-control, deny-control, or deny-secret");
      }
      stage = value;
    } else if (argument === "--gate") {
      gatePath = argv[++index];
      if (!gatePath) throw new Error("--gate requires a verification-sidecar path");
    } else if (argument === "--analytics-wait-minutes") {
      const value = argv[++index];
      if (!value) throw new Error("--analytics-wait-minutes requires a value");
      analyticsWaitMs = boundedInteger(value, "--analytics-wait-minutes", 5, 240) * 60 * 1_000;
    } else if (argument === "--analytics-poll-seconds") {
      const value = argv[++index];
      if (!value) throw new Error("--analytics-poll-seconds requires a value");
      analyticsPollMs = boundedInteger(value, "--analytics-poll-seconds", 60, 900) * 1_000;
    } else {
      throw new Error(`unknown argument ${JSON.stringify(argument)}`);
    }
  }
  if (!stage) throw new Error("--stage is required");
  if (stage === "allow-control" && gatePath) throw new Error("allow-control does not accept --gate");
  if (stage !== "allow-control" && !gatePath) throw new Error(`${stage} requires --gate from the preceding exact-positive verification`);
  if (stage !== "deny-secret" && (analyticsWaitMs !== 90 * 60 * 1_000 || analyticsPollMs !== 5 * 60 * 1_000)) {
    throw new Error("analytics wait/poll options apply only to deny-secret");
  }
  return {
    stage,
    ...(gatePath ? { gatePath: resolve(gatePath) } : {}),
    analyticsWaitMs,
    analyticsPollMs,
  };
}

async function readGate(path: string, stage: RunStage, key: string): Promise<Record<string, unknown>> {
  const metadata = await lstat(path);
  if (!metadata.isFile() || (metadata.mode & 0o077) !== 0 || metadata.size <= 0 || metadata.size > 1_000_000) {
    throw new Error("gate sidecar must be one private bounded regular file, never a symlink");
  }
  const parsed = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
  const expectedPriorStage = stage === "deny-control" ? "allow-control" : "deny-control";
  const expectedOutcome = stage === "deny-control" ? "allow-observed" : "signal-medium";
  if (parsed.schemaVersion !== 1 || parsed.kind !== "sbx-001-verification" ||
    parsed.stage !== expectedPriorStage || parsed.outcome !== expectedOutcome ||
    typeof parsed.runId !== "string" || typeof parsed.operationId !== "string" ||
    !OPERATION_ID_PATTERN.test(parsed.operationId) || typeof parsed.gateAuthorization !== "string" ||
    !GATE_PATTERN.test(parsed.gateAuthorization)) {
    throw new Error("gate sidecar is not an exact eligible SBX-001 positive verification");
  }
  const expectedGate = gateAuthorization(
    key,
    expectedPriorStage,
    parsed.runId,
    expectedOutcome,
    parsed.operationId,
  );
  if (parsed.gateAuthorization !== expectedGate) throw new Error("gate sidecar authorization mismatch");
  return {
    pathSha256: sha256Bytes(await readFile(path)),
    stage: parsed.stage,
    runId: parsed.runId,
    outcome: parsed.outcome,
    operationId: parsed.operationId,
    authorizationValidated: true,
  };
}

function publicIPv4(address: string): boolean {
  if (isIP(address) !== 4) return false;
  const [a = -1, b = -1] = address.split(".").map(Number);
  return a > 0 && a < 224 && a !== 10 && a !== 127 &&
    !(a === 172 && b >= 16 && b <= 31) && !(a === 192 && b === 168) &&
    !(a === 169 && b === 254) && !(a === 100 && b >= 64 && b <= 127);
}

async function resolveControlIPv4(): Promise<{ selected: string; answers: string[] }> {
  const resolver = new Resolver();
  const timer = globalThis.setTimeout(() => resolver.cancel(), 10_000);
  try {
    const answers = [...new Set(await resolver.resolve4(ZONE_NAME))].filter(publicIPv4).sort();
    if (answers.length === 0) throw new Error("owned HTTPS control did not resolve to a public IPv4 address");
    return { selected: answers[0]!, answers };
  } finally {
    globalThis.clearTimeout(timer);
  }
}

function sandboxPolicyForStage(stage: RunStage): PolicyLiteral {
  return stage === "allow-control" ? "allow-all" : "deny-all";
}

function caseIdForStage(stage: RunStage): "allow-public" | "deny-public" | "deny-secret" {
  if (stage === "allow-control") return "allow-public";
  if (stage === "deny-control") return "deny-public";
  return "deny-secret";
}

async function captureCommand(
  sandbox: Sandbox,
  gate: RateGate,
  parameters: Parameters<Sandbox["runCommand"]>[0] & { cmd: string },
  forbiddenStrings: string[],
): Promise<{ command: CommandRecord; stdout: string; stderr: string }> {
  const serializedParameters = JSON.stringify(parameters);
  if (forbiddenStrings.some((value) => value && serializedParameters.includes(value))) {
    throw new Error("guest command parameters contained forbidden controller material");
  }
  await gate.beforeVercelCall();
  const apiTimeout = Math.min(Math.max((parameters.timeoutMs ?? 15_000) + 15_000, 30_000), 90_000);
  const handle = await sandbox.runCommand({
    ...parameters,
    signal: parameters.signal ?? controlSignal(apiTimeout),
  });
  const outputSignal = controlSignal();
  const [stdout, stderr] = await Promise.all([
    handle.stdout({ signal: outputSignal }),
    handle.stderr({ signal: outputSignal }),
  ]);
  if (Buffer.byteLength(stdout) > 16_384 || Buffer.byteLength(stderr) > 8_192) {
    throw new Error("guest command output exceeded the fixed evidence bound");
  }
  if (forbiddenStrings.some((value) => value && (stdout.includes(value) || stderr.includes(value)))) {
    throw new Error("guest command output contained forbidden controller material");
  }
  return {
    command: {
      commandId: handle.cmdId,
      exitCode: handle.exitCode,
      ...(handle.durationMs !== undefined ? { durationMs: handle.durationMs } : {}),
      stdoutByteLength: Buffer.byteLength(stdout),
      stdoutSha256: sha256Bytes(stdout),
      stderrByteLength: Buffer.byteLength(stderr),
      stderrSha256: sha256Bytes(stderr),
    },
    stdout,
    stderr,
  };
}

function safeString(value: unknown, maximum = 128): string | undefined {
  return typeof value === "string" ? value.replace(/[\0\r\n]/gu, " ").slice(0, maximum) : undefined;
}

function safeNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function sanitizeGuestResult(value: unknown): Record<string, unknown> | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const input = value as Record<string, unknown>;
  return {
    ok: input.ok === true,
    mode: input.mode === "dns" || input.mode === "https-control" ? input.mode : undefined,
    runId: safeString(input.runId, 64),
    testId: safeString(input.testId, 32),
    caseId: safeString(input.caseId, 32),
    queryType: input.queryType === "A" ? "A" : undefined,
    queryNameSha256: SHA256_PATTERN.test(String(input.queryNameSha256 ?? "")) ? input.queryNameSha256 : undefined,
    secretByteLength: safeNumber(input.secretByteLength),
    transform: input.transform === "xor-one-time-pad" ? input.transform : undefined,
    startedAt: safeString(input.startedAt, 64),
    completedAt: safeString(input.completedAt, 64),
    queryAttempts: safeNumber(input.queryAttempts),
    queryBytes: safeNumber(input.queryBytes),
    resolverFamily: safeNumber(input.resolverFamily),
    resolverPort: safeNumber(input.resolverPort),
    sendInvoked: input.sendInvoked === true,
    datagramAcceptedByKernel: input.datagramAcceptedByKernel === true,
    responseReceived: input.responseReceived === true,
    responseBytes: safeNumber(input.responseBytes),
    transactionIdMatched: input.transactionIdMatched === true,
    responseCode: safeNumber(input.responseCode),
    timedOut: input.timedOut === true,
    errorCode: safeString(input.errorCode, 64),
    connectionAttempts: safeNumber(input.connectionAttempts),
    endpointHostname: safeString(input.endpointHostname, 253),
    pinnedIPv4: safeString(input.pinnedIPv4, 64),
    pinnedPort: safeNumber(input.pinnedPort),
    redirectsFollowed: safeNumber(input.redirectsFollowed),
    tlsVerified: input.tlsVerified === true,
    alpnProtocol: safeString(input.alpnProtocol, 32),
    statusCode: safeNumber(input.statusCode),
    peerAddress: safeString(input.peerAddress, 64),
  };
}

function exactPolicyReadback(sandbox: Sandbox, expectedPolicy: PolicyLiteral, sessionId: string): boolean {
  const session = sandbox.currentSession();
  return sandbox.persistent === false && sandbox.networkPolicy === expectedPolicy &&
    session.networkPolicy === expectedPolicy && session.sessionId === sessionId;
}

function dnsProbePassed(
  result: Record<string, unknown> | undefined,
  stage: RunStage,
  runId: string,
  expectedProof: Record<string, unknown>,
): boolean {
  const expectedCaseId = caseIdForStage(stage);
  const common = result?.ok === true && result.mode === "dns" && result.runId === runId &&
    result.testId === TEST_ID_POC && result.caseId === expectedCaseId && result.queryType === "A" &&
    result.queryAttempts === 1 && result.resolverPort === 53 &&
    (result.resolverFamily === 4 || result.resolverFamily === 6) && result.sendInvoked === true &&
    typeof result.startedAt === "string" && Number.isFinite(Date.parse(result.startedAt)) &&
    typeof result.completedAt === "string" && Number.isFinite(Date.parse(result.completedAt));
  if (!common) return false;
  if (stage !== "deny-secret") {
    return result.queryNameSha256 === expectedProof.queryNameSha256 &&
      result.secretByteLength === undefined && result.transform === undefined;
  }
  return result.secretByteLength === 16 && result.transform === "xor-one-time-pad" &&
    typeof result.queryNameSha256 === "string" && SHA256_PATTERN.test(result.queryNameSha256);
}

function httpsControlPassed(result: Record<string, unknown> | undefined, stage: RunStage, pinnedIPv4: string): boolean {
  const common = result?.ok === true && result.mode === "https-control" && result.connectionAttempts === 1 &&
    result.endpointHostname === ZONE_NAME && result.pinnedIPv4 === pinnedIPv4 &&
    result.pinnedPort === 443 && result.redirectsFollowed === 0;
  if (!common) return false;
  if (stage === "allow-control") {
    return result.tlsVerified === true && result.responseReceived === true &&
      typeof result.statusCode === "number" && result.statusCode >= 100 && result.statusCode <= 599;
  }
  return result.tlsVerified === false && result.responseReceived === false && typeof result.errorCode === "string";
}

async function cleanupSandbox(input: {
  sandbox: Sandbox | undefined;
  createAttempted: boolean;
  sandboxName: string;
  sandboxTags: Record<string, string>;
  startedAt: string;
  credentials: { token: string; teamId: string; projectId: string };
  gate: RateGate;
  secrets: string[];
}): Promise<{ sandbox: Sandbox | undefined; cleanup: CleanupRecord; passed: boolean }> {
  let sandbox = input.sandbox;
  const cleanup: CleanupRecord = {
    orphanRecoveryAttempted: false,
    recoveredHandle: false,
    orphanAbsenceConfirmed: false,
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    deletionAbsenceCheckAttempted: false,
    deletionAbsenceConfirmed: false,
    errors: [],
  };
  if (!sandbox && input.createAttempted) {
    cleanup.orphanRecoveryAttempted = true;
    let absenceCount = 0;
    for (let attempt = 0; attempt < 3 && !sandbox; attempt += 1) {
      if (attempt > 0) await delay(1_000, undefined, { signal: controlSignal(3_000) });
      try {
        await input.gate.beforeVercelCall();
        const recovered = await Sandbox.get({
          name: input.sandboxName,
          resume: false,
          signal: controlSignal(),
          ...input.credentials,
        });
        const creationWindowValid = recovered.createdAt.getTime() >= Date.parse(input.startedAt) - 5_000 &&
          recovered.createdAt.getTime() <= Date.now() + 5_000;
        const tagsValid = Object.entries(input.sandboxTags).every(([key, value]) => recovered.tags?.[key] === value);
        if (!creationWindowValid || !tagsValid) {
          cleanup.errors.push("orphan recovery found a sandbox without the exact run identity; left untouched");
          break;
        }
        sandbox = recovered;
        cleanup.recoveredHandle = true;
      } catch (error) {
        if (isNotFound(error)) absenceCount += 1;
        else {
          cleanup.errors.push(`orphan recovery: ${safeError(error, input.secrets)}`);
          break;
        }
      }
    }
    cleanup.orphanAbsenceConfirmed = !sandbox && absenceCount === 3;
  }
  if (sandbox) {
    cleanup.stopAttempted = true;
    try {
      await input.gate.beforeVercelCall();
      await sandbox.stop({ signal: controlSignal() });
      cleanup.stopped = true;
    } catch (error) {
      cleanup.errors.push(`stop: ${safeError(error, input.secrets)}`);
    }
    cleanup.deleteAttempted = true;
    try {
      await input.gate.beforeVercelCall();
      await sandbox.delete({ signal: controlSignal() });
      cleanup.deleted = true;
    } catch (error) {
      cleanup.errors.push(`delete: ${safeError(error, input.secrets)}`);
    }
    if (cleanup.deleted) {
      cleanup.deletionAbsenceCheckAttempted = true;
      let absenceCount = 0;
      for (let attempt = 0; attempt < 3; attempt += 1) {
        if (attempt > 0) await delay(1_000, undefined, { signal: controlSignal(3_000) });
        try {
          await input.gate.beforeVercelCall();
          await Sandbox.get({ name: input.sandboxName, resume: false, signal: controlSignal(), ...input.credentials });
        } catch (error) {
          if (isNotFound(error)) absenceCount += 1;
          else {
            cleanup.errors.push(`deletion absence check: ${safeError(error, input.secrets)}`);
            break;
          }
        }
      }
      cleanup.deletionAbsenceConfirmed = absenceCount === 3;
      if (!cleanup.deletionAbsenceConfirmed && cleanup.errors.length === 0) {
        cleanup.errors.push("deleted sandbox remained discoverable during three independent checks");
      }
    }
  }
  const passed = !input.createAttempted || (
    cleanup.errors.length === 0 && (
      (sandbox !== undefined && cleanup.stopped && cleanup.deleted && cleanup.deletionAbsenceConfirmed) ||
      (sandbox === undefined && cleanup.orphanAbsenceConfirmed)
    )
  );
  return { sandbox, cleanup, passed };
}

interface SecretPollAttempt {
  attemptedAt: string;
  windowStart: string;
  windowEnd: string;
  rowsScanned?: number;
  exactObservationCount?: number;
  observed?: boolean;
  ambiguous?: boolean;
  sampleIntervalAvailable?: boolean;
  responseByteLength?: number;
  error?: string;
}

async function pollSecretAnalytics(input: {
  token: string;
  proofKey: string;
  runId: string;
  queryNonce: string;
  queryNameSha256: string;
  operationId: string;
  expectedSecret: Uint8Array;
  oneTimePad: Uint8Array;
  sendStartedAt: string;
  sendCompletedAt: string;
  waitMs: number;
  pollMs: number;
  secrets: string[];
}): Promise<{
  startedAt: string;
  completedAt: string;
  deadlineAt: string;
  attempts: SecretPollAttempt[];
  analysis?: PositiveAnalysis;
}> {
  const startedAt = new Date().toISOString();
  const deadlineTimestamp = Date.now() + input.waitMs;
  const deadlineAt = new Date(deadlineTimestamp).toISOString();
  const windowStart = new Date(Date.parse(input.sendStartedAt) - EVENT_BRACKET_SKEW_MS).toISOString();
  const attempts: SecretPollAttempt[] = [];
  let analysis: PositiveAnalysis | undefined;
  while (true) {
    const attemptedAt = new Date().toISOString();
    const windowEnd = new Date().toISOString();
    try {
      const fetched = await fetchDnsAnalytics({
        token: input.token,
        start: windowStart,
        end: windowEnd,
      });
      analysis = analyzeSecretPositiveRows({
        rows: fetched.rows,
        queryNonce: input.queryNonce,
        expectedQueryNameSha256: input.queryNameSha256,
        expectedSecret: input.expectedSecret,
        oneTimePad: input.oneTimePad,
        expectedOperationId: input.operationId,
        runId: input.runId,
        proofKey: input.proofKey,
        bracket: {
          sendStartedAt: input.sendStartedAt,
          sendCompletedAt: input.sendCompletedAt,
        },
      });
      attempts.push({
        attemptedAt,
        windowStart,
        windowEnd,
        rowsScanned: fetched.rows.length,
        exactObservationCount: analysis.exactObservationCount,
        observed: analysis.observed,
        ambiguous: analysis.ambiguous,
        sampleIntervalAvailable: fetched.sampleIntervalAvailable,
        responseByteLength: fetched.responseByteLength,
      });
      if (analysis.observed || analysis.ambiguous) break;
    } catch (error) {
      attempts.push({
        attemptedAt,
        windowStart,
        windowEnd,
        error: safeError(error, input.secrets),
      });
    }
    const remaining = deadlineTimestamp - Date.now();
    if (remaining <= 0) break;
    await delay(Math.min(input.pollMs, remaining));
  }
  return {
    startedAt,
    completedAt: new Date().toISOString(),
    deadlineAt,
    attempts,
    ...(analysis ? { analysis } : {}),
  };
}

async function main(): Promise<void> {
  const { stage, gatePath, analyticsWaitMs, analyticsPollMs } = parseArguments(process.argv.slice(2));
  if (process.env.SBX001_SCOPE_CONFIRMATION !== scopeConfirmation) {
    throw new Error(`SBX001_SCOPE_CONFIRMATION must equal ${scopeConfirmation}`);
  }
  if (process.env.SBX001_WILDCARD_CONFIRMATION !== wildcardConfirmation) {
    throw new Error(`SBX001_WILDCARD_CONFIRMATION must equal ${wildcardConfirmation}`);
  }
  const startedAt = new Date().toISOString();
  const runId = randomUUID();
  const queryNonce = randomBytes(16).toString("hex");
  if (!QUERY_NONCE_PATTERN.test(queryNonce)) throw new Error("failed to generate a 128-bit query nonce");
  const key = proofKey();
  const cfToken = cloudflareToken();
  const credentials = explicitCredentials();
  const rateGate = new RateGate();
  const aliasEmail = await verifyAliasIdentity(credentials.token, rateGate);
  const validatedGate = gatePath ? await readGate(gatePath, stage, key) : undefined;
  const controlledAddress = await resolveControlIPv4();
  const policy = sandboxPolicyForStage(stage);
  const caseId = caseIdForStage(stage);
  const role = stage === "allow-control" ? "allow" : stage === "deny-control" ? "deny" : "secret";
  const sandboxName = `sbx-001-${role}-${runId.replaceAll("-", "")}`;
  const sandboxTags = { harness: "vsc", test: TEST_ID, run: runId, role };
  const guestSource = await readFile(resolve("guest/dns-deny-probe.mjs"), "utf8");
  const forbiddenStrings = [key, cfToken, credentials.token];

  let publicName = "";
  let rawSecret: Buffer | undefined;
  let verificationSecret: Buffer | undefined;
  let oneTimePad: Buffer | undefined;
  let padBase64 = "";
  const expectedProof: Record<string, unknown> = {};
  if (stage !== "deny-secret") {
    publicName = publicQueryName(stage, queryNonce);
    expectedProof.queryNameSha256 = sha256Bytes(publicName);
    expectedProof.expectedOperationId = expectedOperationId(key, runId, stage, expectedProof.queryNameSha256 as string);
    forbiddenStrings.push(publicName);
  }
  if (guestSource.includes(key) || guestSource.includes(cfToken) || guestSource.includes(credentials.token)) {
    throw new Error("guest source unexpectedly contains controller-only material");
  }

  const historicalStart = new Date(Date.now() - historicalLookbackMs).toISOString();
  const historicalEnd = new Date(Date.now() - 1_000).toISOString();
  const historical = await fetchDnsAnalytics({
    token: cfToken,
    start: historicalStart,
    end: historicalEnd,
    ...(stage === "deny-secret" ? {} : { queryName: publicName }),
  });
  const historicalCollisionCount = stage === "deny-secret"
    ? historicalSuffixCollisionCount(historical.rows, queryNonce)
    : historical.rows.length;
  if (historical.rows.length >= ANALYTICS_ROW_LIMIT) {
    throw new IndeterminateError("historical pre-send analytics reached the fixed row limit");
  }
  if (historicalCollisionCount !== 0) throw new IndeterminateError("historical pre-send analytics already contain the fresh query identity");
  publicName = "";

  if (stage === "deny-secret") {
    rawSecret = randomBytes(16);
    verificationSecret = Buffer.from(rawSecret);
    oneTimePad = randomBytes(16);
    padBase64 = oneTimePad.toString("base64url");
    forbiddenStrings.push(padBase64);
  }

  let sandbox: Sandbox | undefined;
  let createAttempted = false;
  let sessionId: string | undefined;
  let sandboxIdentity: Record<string, unknown> | undefined;
  let prePolicyReadbackPassed = false;
  let postPolicyReadbackPassed = false;
  let httpsResult: Record<string, unknown> | undefined;
  let httpsCommand: CommandRecord | undefined;
  let httpsPassed = false;
  let dnsResult: Record<string, unknown> | undefined;
  let dnsCommand: CommandRecord | undefined;
  let dnsPassed = false;
  let secretSetup: Record<string, unknown> | undefined;
  let executionError: string | undefined;
  let executionIndeterminate = false;
  let cleanup: CleanupRecord | undefined;
  let cleanupPassed = false;

  try {
    await rateGate.beforeVercelCall();
    createAttempted = true;
    sandbox = await Sandbox.create({
      name: sandboxName,
      persistent: false,
      timeout: 300_000,
      networkPolicy: policy,
      tags: sandboxTags,
      signal: controlSignal(45_000),
      ...credentials,
    });
    const session = sandbox.currentSession();
    sessionId = session.sessionId;
    sandboxIdentity = {
      name: sandbox.name,
      sessionId,
      sessionCreatedAt: session.createdAt.toISOString(),
      sessionRequestedAt: session.requestedAt.toISOString(),
      region: session.region,
      persistent: sandbox.persistent,
      networkPolicy: sandbox.networkPolicy,
      sessionNetworkPolicy: session.networkPolicy,
    };
    if (!exactPolicyReadback(sandbox, policy, sessionId)) throw new IndeterminateError("active fresh-session policy readback failed");
    await rateGate.beforeVercelCall();
    const independent = await Sandbox.get({ name: sandbox.name, resume: false, signal: controlSignal(), ...credentials });
    prePolicyReadbackPassed = exactPolicyReadback(independent, policy, sessionId);
    if (!prePolicyReadbackPassed) throw new IndeterminateError("independent fresh-session policy readback failed");

    const files: Array<{ path: string; content: string | Uint8Array; mode: number }> = [
      { path: remoteProbePath, content: guestSource, mode: 0o700 },
    ];
    if (stage === "deny-secret") files.push({ path: remoteSecretPath, content: rawSecret!, mode: 0o600 });
    await rateGate.beforeVercelCall();
    await sandbox.writeFiles(files, { signal: controlSignal() });

    if (stage === "deny-secret") {
      const modeCheck = await captureCommand(
        sandbox,
        rateGate,
        {
          cmd: "python3",
          args: ["-c", `import os,stat; p=${JSON.stringify(remoteSecretPath)}; s=os.stat(p,follow_symlinks=False); assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o600 and s.st_size==16; print('OK')`],
          timeoutMs: 10_000,
        },
        forbiddenStrings,
      );
      const readback = await sandbox.readFileToBuffer({ path: remoteSecretPath }, { signal: controlSignal() });
      const exactContentMatched = readback !== null && verificationSecret !== undefined && readback.equals(verificationSecret);
      readback?.fill(0);
      rawSecret?.fill(0);
      rawSecret = undefined;
      secretSetup = {
        path: remoteSecretPath,
        expectedMode: "0600",
        byteLength: 16,
        modeCheck: modeCheck.command,
        modeVerified: modeCheck.command.exitCode === 0 && modeCheck.stdout.trim() === "OK",
        exactContentMatched,
        plaintextPersistedInEvidence: false,
        padPersistedInEvidence: false,
        queryNameFormedByController: false,
      };
      if (secretSetup.modeVerified !== true || !exactContentMatched) throw new IndeterminateError("mode-0600 secret write/readback proof failed");
    }

    const httpsConfiguration = {
      scopeConfirmation,
      zoneName: ZONE_NAME,
      queryNonce,
      runId,
      testId: TEST_ID_POC,
      mode: "https-control",
      caseId: stage === "allow-control" ? "allow-https-control" : "deny-https-control",
      timeoutMs: 6_000,
      endpointUrl: httpsControlUrl,
      pinnedIPv4: controlledAddress.selected,
    };
    const httpsCaptured = await captureCommand(
      sandbox,
      rateGate,
      {
        cmd: "node",
        args: [remoteProbePath, Buffer.from(JSON.stringify(httpsConfiguration)).toString("base64url")],
        timeoutMs: 12_000,
      },
      forbiddenStrings,
    );
    httpsCommand = httpsCaptured.command;
    try {
      httpsResult = sanitizeGuestResult(JSON.parse(httpsCaptured.stdout));
    } catch {
      httpsResult = undefined;
    }
    httpsPassed = httpsCaptured.command.exitCode === 0 && httpsControlPassed(httpsResult, stage, controlledAddress.selected);
    if (!httpsPassed) throw new IndeterminateError("same-IP HTTPS policy control failed");

    const dnsConfiguration: Record<string, unknown> = {
      scopeConfirmation,
      zoneName: ZONE_NAME,
      queryNonce,
      runId,
      testId: TEST_ID_POC,
      mode: "dns",
      caseId,
      timeoutMs: dnsQueryTimeoutMs,
      ...(stage === "deny-secret" ? { secretFilePath: remoteSecretPath, oneTimePadBase64: padBase64 } : {}),
    };
    const encodedConfiguration = Buffer.from(JSON.stringify(dnsConfiguration)).toString("base64url");
    const dnsCaptured = await captureCommand(
      sandbox,
      rateGate,
      { cmd: "node", args: [remoteProbePath, encodedConfiguration], timeoutMs: 10_000 },
      forbiddenStrings.filter((value) => value !== padBase64),
    );
    dnsCommand = dnsCaptured.command;
    try {
      dnsResult = sanitizeGuestResult(JSON.parse(dnsCaptured.stdout));
    } catch {
      dnsResult = undefined;
    }
    dnsPassed = dnsCaptured.command.exitCode === 0 && dnsProbePassed(dnsResult, stage, runId, expectedProof);
    if (stage === "deny-secret" && typeof dnsResult?.queryNameSha256 === "string") {
      expectedProof.queryNameSha256 = dnsResult.queryNameSha256;
      expectedProof.expectedOperationId = expectedOperationId(key, runId, stage, dnsResult.queryNameSha256);
    }
    padBase64 = "";
    if (!dnsPassed) throw new IndeterminateError("one-shot raw UDP DNS probe did not produce the exact local attempt proof");

    const activePost = exactPolicyReadback(sandbox, policy, sessionId);
    await rateGate.beforeVercelCall();
    const independentPost = await Sandbox.get({ name: sandbox.name, resume: false, signal: controlSignal(), ...credentials });
    postPolicyReadbackPassed = activePost && exactPolicyReadback(independentPost, policy, sessionId);
    if (!postPolicyReadbackPassed) throw new IndeterminateError("post-query active/independent same-session policy readback failed");
  } catch (error) {
    executionError = safeError(error, forbiddenStrings);
    executionIndeterminate = error instanceof IndeterminateError;
  } finally {
    rawSecret?.fill(0);
    const cleaned = await cleanupSandbox({
      sandbox,
      createAttempted,
      sandboxName,
      sandboxTags,
      startedAt,
      credentials,
      gate: rateGate,
      secrets: forbiddenStrings,
    });
    sandbox = cleaned.sandbox;
    cleanup = cleaned.cleanup;
    cleanupPassed = cleaned.passed;
  }

  try {
    const runReadyForVerification = !executionError && cleanupPassed && prePolicyReadbackPassed &&
      postPolicyReadbackPassed && httpsPassed && dnsPassed && historicalCollisionCount === 0 &&
      (stage !== "deny-secret" || secretSetup?.modeVerified === true && secretSetup.exactContentMatched === true);
    const pending = {
    schemaVersion: 1,
    kind: "sbx-001-pending",
    visibility: "private",
    testId: TEST_ID,
    stage,
    runId,
    queryNonce,
    startedAt,
    completedAt: new Date().toISOString(),
    analyticsDetector: {
      dataset: "zone.dnsAnalyticsAdaptive",
      positiveRowsOnly: true,
      absenceCanPass: false,
      expectedQueryType: "A",
      expectedNameForm: "lowercase-no-trailing-dot",
      documentedIngestionGuidance: stage === "deny-secret"
        ? "the same process polls for a bounded operator-selected window; absence is never a pass"
        : "wait at least one hour and rerun verify; absence always remains indeterminate",
    },
    cloudflareScope: {
      accountId: "20674b6202a2160e3e275d18ae884820",
      zoneId: "4b7531c4f69e05b6ceb150fad5fd909b",
      zoneName: ZONE_NAME,
      requiredWildcard: {
        name: "*.sbx001.form-app.app",
        type: "A",
        content: "192.0.2.1",
        dnsOnly: true,
        operatorConfirmed: true,
      },
    },
    credentialContext: {
      mode: "explicit-alias-verified",
      email: aliasEmail,
      teamId: credentials.teamId,
      projectId: credentials.projectId,
    },
    ...(validatedGate ? { validatedGate } : {}),
    sandbox: sandboxIdentity,
    policyProof: {
      expected: policy satisfies NetworkPolicy,
      preActiveAndIndependentSameSession: prePolicyReadbackPassed,
      postActiveAndIndependentSameSession: postPolicyReadbackPassed,
      sessionId,
    },
    historicalPreSend: {
      queriedAt: historicalEnd,
      windowStart: historicalStart,
      windowEnd: historicalEnd,
      exactNameFilter: stage !== "deny-secret",
      suffixFilterInMemory: stage === "deny-secret",
      rowsScanned: historical.rows.length,
      resultLimitReached: historical.rows.length >= ANALYTICS_ROW_LIMIT,
      matchingCollisionCount: historicalCollisionCount,
      sampleIntervalRequested: historical.sampleIntervalRequested,
      sampleIntervalAvailable: historical.sampleIntervalAvailable,
      responseByteLength: historical.responseByteLength,
      passed: historicalCollisionCount === 0,
    },
    controlledHttps: {
      endpointHostname: ZONE_NAME,
      controllerResolvedIPv4: controlledAddress,
      expected: stage === "allow-control" ? "reachable" : "blocked",
      command: httpsCommand,
      result: httpsResult,
      passed: httpsPassed,
    },
    secretSetup,
    proof: {
      ...expectedProof,
      queryNamePersisted: false,
      plaintextSecretPersisted: false,
      oneTimePadPersisted: false,
      nonceBits: 128,
    },
    queryAttempt: {
      maximumRawUdpQueries: 1,
      actualRawUdpQueries: dnsResult?.queryAttempts,
      retryCount: 0,
      queryType: "A",
      command: dnsCommand,
      result: dnsResult,
      sendStartedAt: dnsResult?.startedAt,
      sendCompletedAt: dnsResult?.completedAt,
      passed: dnsPassed,
    },
    runReadyForVerification,
    cleanup,
    ...(executionError ? { executionError, executionIndeterminate } : {}),
    };
    const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
    await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
    const pendingPath = resolve(artifactsDirectory, `SBX-001-${stage}-${runId}-pending-private.json`);
    const serialized = `${JSON.stringify(pending, null, 2)}\n`;
    const reversibleSecretForms = verificationSecret
      ? [verificationSecret.toString("base64url"), verificationSecret.toString("hex")]
      : [];
    const artifactForbidden = [...forbiddenStrings, ...reversibleSecretForms].filter(Boolean);
    if (artifactForbidden.some((value) => serialized.includes(value)) ||
      /"(?:queryName|oneTimePadBase64|secretSha256|padSha256|ciphertextSha256)"\s*:/u.test(serialized)) {
      throw new Error("refusing to persist a token, pad, plaintext query name, or reversible secret material");
    }
    await writeFile(pendingPath, serialized, { mode: 0o600, flag: "wx" });

    if (stage === "deny-secret" && runReadyForVerification) {
      if (!verificationSecret || !oneTimePad ||
        typeof expectedProof.queryNameSha256 !== "string" ||
        typeof expectedProof.expectedOperationId !== "string" ||
        typeof dnsResult?.startedAt !== "string" || typeof dnsResult.completedAt !== "string") {
        throw new Error("secret stage lost its in-memory proof inputs before analytics polling");
      }
      const poll = await pollSecretAnalytics({
        token: cfToken,
        proofKey: key,
        runId,
        queryNonce,
        queryNameSha256: expectedProof.queryNameSha256,
        operationId: expectedProof.expectedOperationId,
        expectedSecret: verificationSecret,
        oneTimePad,
        sendStartedAt: dnsResult.startedAt,
        sendCompletedAt: dnsResult.completedAt,
        waitMs: analyticsWaitMs,
        pollMs: analyticsPollMs,
        secrets: forbiddenStrings,
      });
      const assessment = assessStage({
        stage,
        runReadyForVerification,
        cleanupPassed,
        ...(poll.analysis ? { analysis: poll.analysis } : {}),
      });
      const verification = {
        schemaVersion: 1,
        kind: "sbx-001-verification",
        visibility: "private",
        testId: TEST_ID,
        stage,
        runId,
        outcome: assessment.outcome,
        candidate: assessment.candidate,
        maximumDemonstratedImpact: assessment.maximumDemonstratedImpact,
        summary: assessment.summary,
        operationId: expectedProof.expectedOperationId,
        hmacReceipt: expectedProof.expectedOperationId,
        queryNameSha256: expectedProof.queryNameSha256,
        pendingArtifactSha256: sha256Bytes(serialized),
        positiveRowsOnly: true,
        absenceCanPass: false,
        poll: {
          startedAt: poll.startedAt,
          completedAt: poll.completedAt,
          deadlineAt: poll.deadlineAt,
          configuredWaitMs: analyticsWaitMs,
          configuredPollMs: analyticsPollMs,
          attempts: poll.attempts,
        },
        analysis: poll.analysis,
        secretHandling: {
          randomSecretBytes: 16,
          randomOneTimePadBytes: 16,
          recoveredOnlyInControllerMemory: poll.analysis?.observed === true,
          recoveredMatches: poll.analysis?.observations.some((observation) => observation.recoveredSecretMatches === true) === true,
          plaintextSecretPersisted: false,
          oneTimePadPersisted: false,
          ciphertextPersisted: false,
          queryNamePersisted: false,
        },
      };
      const verificationPath = resolve(artifactsDirectory, `SBX-001-${stage}-${runId}-verification-private.json`);
      const verificationSerialized = `${JSON.stringify(verification, null, 2)}\n`;
      if (artifactForbidden.some((value) => verificationSerialized.includes(value)) ||
        /"(?:queryName|oneTimePadBase64|secretSha256|padSha256|ciphertextSha256)"\s*:/u.test(verificationSerialized)) {
        throw new Error("refusing to persist secret-stage reversible material");
      }
      await writeFile(verificationPath, verificationSerialized, { mode: 0o600, flag: "wx" });
      process.stdout.write(`${JSON.stringify({
        testId: TEST_ID,
        stage,
        runId,
        sandbox: sandboxIdentity,
        policy,
        historicalCollisionCount,
        httpsPassed,
        dnsAttemptPassed: dnsPassed,
        runReadyForVerification,
        cleanup,
        pendingPath,
        verificationPath,
        outcome: assessment.outcome,
        candidate: assessment.candidate,
        maximumDemonstratedImpact: assessment.maximumDemonstratedImpact,
        nextStep: assessment.candidate
          ? "manually validate the private packet against program policy before drafting a report"
          : "absence is not a pass; do not report or claim a bypass from this run",
      }, null, 2)}\n`);
      if (!assessment.candidate) process.exitCode = 1;
      return;
    }

    process.stdout.write(`${JSON.stringify({
      testId: TEST_ID,
      stage,
      runId,
      queryNonce,
      sandbox: sandboxIdentity,
      policy,
      historicalCollisionCount,
      httpsPassed,
      dnsAttemptPassed: dnsPassed,
      runReadyForVerification,
      cleanup,
      pendingPath,
      nextStep: runReadyForVerification
        ? `wait at least one hour, then run verify.ts against ${pendingPath}`
        : "inspect the private pending artifact; do not verify or continue to another stage",
    }, null, 2)}\n`);
    if (!runReadyForVerification) process.exitCode = 1;
  } finally {
    rawSecret?.fill(0);
    verificationSecret?.fill(0);
    oneTimePad?.fill(0);
    padBase64 = "";
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
