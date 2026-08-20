import "dotenv/config";

import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { Resolver } from "node:dns/promises";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { APIError, Sandbox, type NetworkPolicy } from "@vercel/sandbox";

const testId = "SBX-017-POC";
const scopeConfirmation = "I_CONTROL_THE_ENDPOINT_AND_AUTHORIZE_BOUNDED_HTTP3_TESTING";
const expectedCurlCffiVersion = "0.13.0";
const remoteProbePath = "/tmp/sbx-017/http3-deny-probe.py";
const remoteSitePackages = "/tmp/sbx-017/site-packages";
const remoteOperatorSecretPath = "/tmp/sbx-017/operator-secret";
const minimumControllerCallIntervalMs = 250;
const policySettleDelayMs = 1_500;
const controlPlaneTimeoutMs = 30_000;
const eligibleAliasEmail = "swve@wearehackerone.com";
const eligibleTeamId = "team_n98ERpVwV7HqmWRudAyK8sXQ";
const eligibleProjectId = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
const controlledEndpointHostname = "vsc-tls-deny-swve.cyrus-206.workers.dev";
const operationIdPattern = /^h3_[A-Za-z0-9_-]{43}$/u;
const canaryPattern = /^[A-Za-z0-9_-]{16,128}$/u;

type ProbeMode = "h3-v3only" | "https-v1";
export type QuicVerdict = "candidate" | "pass" | "indeterminate" | "error";

export interface ProbeRecord {
  caseId: string;
  mode: ProbeMode;
  canarySource: "controller-public-canary" | "operator-secret-file";
  configurationSha256: string;
  publicCanarySha256?: string;
  expectedOperationId: string;
  command: CommandRecord;
  result?: Record<string, unknown>;
}

export interface CommandRecord {
  commandId: string;
  exitCode: number;
  durationMs?: number;
  stdoutByteLength: number;
  stdoutSha256: string;
  stderrByteLength: number;
  stderrSha256: string;
}

export interface QuicAssessmentInput {
  setupPassed: boolean;
  allowH3ControlPassed: boolean;
  allowTcpControlPassed: boolean;
  denyUpdateAcknowledged: boolean;
  denyReadbackPassed: boolean;
  postDenyReadbackPassed: boolean;
  denyTcpPreBlocked: boolean;
  denyTcpPostBlocked: boolean;
  denyH3Succeeded: boolean;
  denyH3Blocked: boolean;
  cleanupPassed: boolean;
  executionError?: boolean;
}

export interface QuicAssessment {
  verdict: QuicVerdict;
  candidate: boolean;
  summary: string;
  controlsPassed: boolean;
}

class IndeterminateError extends Error {}

class RateGate {
  private lastStartedAt = 0;

  async beforeCall(): Promise<void> {
    const remaining = minimumControllerCallIntervalMs - (Date.now() - this.lastStartedAt);
    if (remaining > 0) await delay(remaining, undefined, { signal: controlSignal(2_000) });
    this.lastStartedAt = Date.now();
  }
}

function controlSignal(timeoutMs = controlPlaneTimeoutMs): AbortSignal {
  return AbortSignal.timeout(timeoutMs);
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function safeText(value: unknown, maximum = 256): string | undefined {
  return typeof value === "string"
    ? value.replace(/[\0\r\n]/gu, " ").slice(0, maximum)
    : undefined;
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function redact(value: string, secrets: string[]): string {
  return secrets.reduce(
    (output, secret) => secret.length === 0 ? output : output.split(secret).join("[REDACTED]"),
    value,
  );
}

function safeError(error: unknown, secrets: string[]): string {
  return redact(error instanceof Error ? error.message : String(error), secrets)
    .replace(/[\0\r\n]/gu, " ")
    .slice(0, 1_000);
}

function isNotFound(error: unknown): boolean {
  return error instanceof APIError && error.response.status === 404;
}

export function controlledEndpoint(environment: NodeJS.ProcessEnv = process.env): URL {
  if (environment.SBX017_SCOPE_CONFIRMATION !== scopeConfirmation) {
    throw new Error(`SBX017_SCOPE_CONFIRMATION must equal ${scopeConfirmation}`);
  }
  if (!environment.SBX017_H3_ENDPOINT_URL) throw new Error("SBX017_H3_ENDPOINT_URL is required");
  const endpoint = new URL(environment.SBX017_H3_ENDPOINT_URL);
  if (
    endpoint.protocol !== "https:" ||
    endpoint.username ||
    endpoint.password ||
    endpoint.search ||
    endpoint.hash ||
    (endpoint.port !== "" && endpoint.port !== "443") ||
    isIP(endpoint.hostname) !== 0 ||
    endpoint.pathname !== "/v1/h3-action" || endpoint.hostname !== controlledEndpointHostname ||
    endpoint.href !== `https://${controlledEndpointHostname}/v1/h3-action`
  ) {
    throw new Error(
      "SBX017_H3_ENDPOINT_URL must be a researcher-owned HTTPS URL on port 443 at /v1/h3-action with a DNS hostname and no credentials, query, or fragment",
    );
  }
  return endpoint;
}

function hmacKey(): string {
  const key = required("H3_ACTION_KEY");
  const byteLength = Buffer.byteLength(key);
  if (byteLength < 32 || byteLength > 256 || /[\0\r\n]/u.test(key)) {
    throw new Error("H3_ACTION_KEY must contain 32-256 bytes without control characters");
  }
  return key;
}

export function explicitCredentials(
  environment: NodeJS.ProcessEnv = process.env,
): { token: string; teamId: string; projectId: string } {
  const token = environment.VERCEL_TOKEN;
  const teamId = environment.VERCEL_TEAM_ID;
  const projectId = environment.VERCEL_PROJECT_ID;
  if (!token || !teamId || !projectId) {
    throw new Error("VERCEL_TOKEN, VERCEL_TEAM_ID, and VERCEL_PROJECT_ID are required");
  }
  if (teamId !== eligibleTeamId || projectId !== eligibleProjectId) {
    throw new Error("SBX-017 must use the verified HackerOne-alias Vercel team and project");
  }
  return { token, teamId, projectId };
}

async function verifyAliasIdentity(token: string): Promise<string> {
  const response = await fetch("https://api.vercel.com/v2/user", {
    headers: { Authorization: `Bearer ${token}` },
    signal: controlSignal(10_000),
  });
  if (!response.ok) throw new Error(`could not verify Vercel token identity (${response.status})`);
  const payload = await response.json() as { user?: { email?: unknown } };
  if (payload.user?.email !== eligibleAliasEmail) {
    throw new Error("Vercel token is not authenticated as the required HackerOne alias");
  }
  return payload.user.email;
}

function numeric(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function exactBoolean(value: unknown): boolean | undefined {
  return value === true ? true : value === false ? false : undefined;
}

function publicIPv4(value: string): boolean {
  if (isIP(value) !== 4) return false;
  const [a = -1, b = -1] = value.split(".").map(Number);
  if (a <= 0 || a >= 224 || a === 127) return false;
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return false;
  if ((a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127)) return false;
  if ((a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19))) return false;
  return true;
}

export function expectedOperationId(
  key: string,
  runId: string,
  caseId: string,
  canary: string,
): string {
  const message = [runId, caseId, canary].join("\n");
  return `h3_${createHmac("sha256", key).update(message).digest("base64url")}`;
}

export function buildProbeConfiguration(input: {
  endpointUrl: string;
  pinnedIPv4: string;
  runId: string;
  caseId: string;
  mode: ProbeMode;
  publicCanary?: string;
}): Record<string, unknown> {
  const configuration: Record<string, unknown> = {
    scopeConfirmation,
    endpointUrl: input.endpointUrl,
    pinnedIPv4: input.pinnedIPv4,
    runId: input.runId,
    testId,
    caseId: input.caseId,
    mode: input.mode,
    timeoutSeconds: 8,
    maxResponseBytes: 1_024,
  };
  if (input.caseId === "deny-h3-target") {
    if (input.mode !== "h3-v3only") {
      throw new Error("deny-h3-target is fixed to h3-v3only");
    }
    if (input.publicCanary !== undefined) {
      throw new Error("deny-h3-target must not receive a canary in guest configuration");
    }
  } else {
    if (!input.publicCanary || !canaryPattern.test(input.publicCanary)) {
      throw new Error("control probes require a bounded public canary");
    }
    configuration.publicCanary = input.publicCanary;
  }
  return configuration;
}

export function assessQuicDenyAll(input: QuicAssessmentInput): QuicAssessment {
  if (!input.cleanupPassed) {
    return {
      verdict: "error",
      candidate: false,
      controlsPassed: false,
      summary: "Owned sandbox cleanup failed; stop and inspect the resource manually.",
    };
  }
  if (input.executionError) {
    return {
      verdict: "error",
      candidate: false,
      controlsPassed: false,
      summary: "The controller failed before a valid boundary assessment completed.",
    };
  }
  const controlsPassed = input.setupPassed && input.allowH3ControlPassed &&
    input.allowTcpControlPassed && input.denyUpdateAcknowledged &&
    input.denyReadbackPassed && input.postDenyReadbackPassed &&
    input.denyTcpPreBlocked && input.denyTcpPostBlocked;
  if (!controlsPassed) {
    return {
      verdict: "indeterminate",
      candidate: false,
      controlsPassed: false,
      summary: "A setup, protocol, policy-readback, or same-IP TCP control failed.",
    };
  }
  if (input.denyH3Succeeded && !input.denyH3Blocked) {
    return {
      verdict: "candidate",
      candidate: true,
      controlsPassed: true,
      summary: "A v3only request exfiltrated the fresh synthetic operator secret over HTTP/3 after literal deny-all blocked HTTPS/TCP.",
    };
  }
  if (input.denyH3Blocked && !input.denyH3Succeeded) {
    return {
      verdict: "pass",
      candidate: false,
      controlsPassed: true,
      summary: "Literal deny-all blocked both HTTPS/TCP and the HTTP/3-only request to the same pinned endpoint.",
    };
  }
  return {
    verdict: "indeterminate",
    candidate: false,
    controlsPassed: true,
    summary: "The HTTP/3 result was neither an authenticated success nor a conclusive network block.",
  };
}

function sanitizeProbeResult(value: unknown): Record<string, unknown> | undefined {
  const input = record(value);
  if (!input) return undefined;
  const response = record(input.response);
  const operationId = typeof input.operationId === "string" && operationIdPattern.test(input.operationId)
    ? input.operationId
    : undefined;
  return {
    ok: exactBoolean(input.ok),
    phase: safeText(input.phase, 64),
    runId: safeText(input.runId, 128),
    testId: safeText(input.testId, 128),
    caseId: safeText(input.caseId, 128),
    probeMode: input.probeMode === "h3-v3only" || input.probeMode === "https-v1"
      ? input.probeMode
      : undefined,
    canarySource: input.canarySource === "controller-public-canary" ||
        input.canarySource === "operator-secret-file"
      ? input.canarySource
      : undefined,
    requestedHttpVersion: input.requestedHttpVersion === "v3only" || input.requestedHttpVersion === "v1"
      ? input.requestedHttpVersion
      : undefined,
    fallbackAllowed: exactBoolean(input.fallbackAllowed),
    endpointHostname: safeText(input.endpointHostname, 253),
    pinnedIPv4: safeText(input.pinnedIPv4, 64),
    pinnedPort: numeric(input.pinnedPort),
    tlsVerificationRequired: exactBoolean(input.tlsVerificationRequired),
    tlsVerifiedByClient: exactBoolean(input.tlsVerifiedByClient),
    redirectsAllowed: exactBoolean(input.redirectsAllowed),
    environmentProxyTrust: exactBoolean(input.environmentProxyTrust),
    proxyOptionForcedEmpty: exactBoolean(input.proxyOptionForcedEmpty),
    noProxyOption: input.noProxyOption === "*" ? "*" : undefined,
    dnsPinnedWithCurlResolve: exactBoolean(input.dnsPinnedWithCurlResolve),
    curlCffiVersion: safeText(input.curlCffiVersion, 32),
    response: response ? {
      statusCode: numeric(response.statusCode),
      actualHttpVersion: numeric(response.actualHttpVersion),
      primaryIp: safeText(response.primaryIp, 64),
      primaryPort: numeric(response.primaryPort),
      redirectCount: numeric(response.redirectCount),
      contentType: safeText(response.contentType, 128),
      cacheControl: safeText(response.cacheControl, 128),
      bodyByteLength: numeric(response.bodyByteLength),
      elapsedMs: numeric(response.elapsedMs),
    } : undefined,
    operationId,
    operationIdShapeValid: exactBoolean(input.operationIdShapeValid),
    authorized: exactBoolean(input.authorized),
    expectedHttp3ResponseVersion: numeric(input.expectedHttp3ResponseVersion),
    errorCode: safeText(input.errorCode, 64),
    receivedBodyByteLength: numeric(input.receivedBodyByteLength),
    retainedBodyByteLength: numeric(input.retainedBodyByteLength),
    maximumResponseBytes: numeric(input.maximumResponseBytes),
    errorType: safeText(input.errorType, 96),
    curlErrorCode: numeric(input.curlErrorCode),
    responseStatusCode: numeric(input.responseStatusCode),
    actualHttpVersion: numeric(input.actualHttpVersion),
    primaryIp: safeText(input.primaryIp, 64),
    primaryPort: numeric(input.primaryPort),
    durationMs: numeric(input.durationMs),
  };
}

function commonProbeControls(
  probe: ProbeRecord | undefined,
  runId: string,
  caseId: string,
  mode: ProbeMode,
  endpoint: URL,
  pinnedIPv4: string,
): { result?: Record<string, unknown>; response?: Record<string, unknown> } {
  const result = probe?.result;
  const response = record(result?.response);
  const expectedRequestedVersion = mode === "h3-v3only" ? "v3only" : "v1";
  const expectedCanarySource = caseId === "deny-h3-target"
    ? "operator-secret-file"
    : "controller-public-canary";
  const commonPassed = probe?.command.exitCode === 0 && result !== undefined &&
    result.runId === runId && result.testId === testId && result.caseId === caseId &&
    result.probeMode === mode && result.canarySource === expectedCanarySource &&
    result.requestedHttpVersion === expectedRequestedVersion &&
    result.fallbackAllowed === false && result.endpointHostname === endpoint.hostname &&
    result.pinnedIPv4 === pinnedIPv4 && result.pinnedPort === 443 &&
    result.tlsVerificationRequired === true && result.redirectsAllowed === false &&
    result.environmentProxyTrust === false && result.proxyOptionForcedEmpty === true &&
    result.noProxyOption === "*" && result.dnsPinnedWithCurlResolve === true &&
    result.curlCffiVersion === expectedCurlCffiVersion;
  return commonPassed
    ? { result, ...(response ? { response } : {}) }
    : {};
}

export function authenticatedProtocolSuccess(
  probe: ProbeRecord | undefined,
  runId: string,
  caseId: string,
  mode: ProbeMode,
  endpoint: URL,
  pinnedIPv4: string,
): boolean {
  const { result, response } = commonProbeControls(
    probe,
    runId,
    caseId,
    mode,
    endpoint,
    pinnedIPv4,
  );
  const expectedHttpVersion = mode === "h3-v3only" ? 30 : 2;
  const cacheControl = typeof response?.cacheControl === "string"
    ? response.cacheControl.toLowerCase().split(",").map((value) => value.trim())
    : [];
  return result?.ok === true && result.phase === "response" &&
    result.tlsVerifiedByClient === true && response?.statusCode === 200 &&
    response.actualHttpVersion === expectedHttpVersion && response.primaryIp === pinnedIPv4 &&
    response.primaryPort === 443 && response.redirectCount === 0 &&
    typeof response.contentType === "string" && response.contentType.toLowerCase().startsWith("application/json") &&
    cacheControl.includes("no-store") &&
    typeof response.bodyByteLength === "number" && response.bodyByteLength <= 1_024 &&
    result.authorized === true && result.operationIdShapeValid === true &&
    result.operationId === probe?.expectedOperationId;
}

export function conclusiveTcpBlock(
  probe: ProbeRecord | undefined,
  runId: string,
  endpoint: URL,
  pinnedIPv4: string,
  caseId = "deny-tcp-control",
): boolean {
  const { result } = commonProbeControls(
    probe,
    runId,
    caseId,
    "https-v1",
    endpoint,
    pinnedIPv4,
  );
  return result?.ok === false && result.phase === "request" &&
    result.curlErrorCode === 7 && result.responseStatusCode === 0 &&
    result.actualHttpVersion === 0 && (result.primaryIp === "" || result.primaryIp === pinnedIPv4) &&
    (result.primaryPort === -1 || result.primaryPort === 0 || result.primaryPort === 443) &&
    result.operationId === undefined;
}

export function conclusiveH3Block(
  probe: ProbeRecord | undefined,
  runId: string,
  endpoint: URL,
  pinnedIPv4: string,
): boolean {
  const caseId = "deny-h3-target";
  const { result } = commonProbeControls(
    probe,
    runId,
    caseId,
    "h3-v3only",
    endpoint,
    pinnedIPv4,
  );
  return result?.ok === false && result.phase === "request" &&
    (result.curlErrorCode === 7 || result.curlErrorCode === 28) &&
    result.responseStatusCode === 0 && result.actualHttpVersion === 0 &&
    (result.primaryIp === "" || result.primaryIp === pinnedIPv4) &&
    (result.primaryPort === -1 || result.primaryPort === 0 || result.primaryPort === 443) &&
    result.operationId === undefined;
}

async function captureCommand(
  sandbox: Sandbox,
  gate: RateGate,
  params: Parameters<Sandbox["runCommand"]>[0] & { cmd: string },
  secrets: string[],
): Promise<{ record: CommandRecord; stdout: string; stderr: string }> {
  const serializedParameters = JSON.stringify(params);
  if (secrets.some((secret) => secret && serializedParameters.includes(secret))) {
    throw new Error("guest command arguments or environment contained controller-only material");
  }
  await gate.beforeCall();
  const commandApiTimeoutMs = Math.min(Math.max((params.timeoutMs ?? 15_000) + 15_000, 30_000), 150_000);
  const command = await sandbox.runCommand({
    ...params,
    signal: params.signal ?? controlSignal(commandApiTimeoutMs),
  });
  const outputSignal = controlSignal();
  const [stdout, stderr] = await Promise.all([
    command.stdout({ signal: outputSignal }),
    command.stderr({ signal: outputSignal }),
  ]);
  if (Buffer.byteLength(stdout) > 64_000 || Buffer.byteLength(stderr) > 16_000) {
    throw new Error("guest command output exceeded the fixed evidence bound");
  }
  if (secrets.some((secret) => secret && (stdout.includes(secret) || stderr.includes(secret)))) {
    throw new Error("guest command output contained controller-only material");
  }
  return {
    record: {
      commandId: command.cmdId,
      exitCode: command.exitCode,
      ...(command.durationMs !== undefined ? { durationMs: command.durationMs } : {}),
      stdoutByteLength: Buffer.byteLength(stdout),
      stdoutSha256: sha256(stdout),
      stderrByteLength: Buffer.byteLength(stderr),
      stderrSha256: sha256(stderr),
    },
    stdout,
    stderr,
  };
}

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  const endpoint = controlledEndpoint();
  const controllerHmacKey = hmacKey();
  const operatorSecret = randomBytes(32).toString("base64url");
  const credentials = explicitCredentials();
  const verifiedAliasEmail = await verifyAliasIdentity(credentials.token);
  const controllerSecrets = [
    controllerHmacKey,
    operatorSecret,
    process.env.VERCEL_TOKEN ?? "",
  ].filter(Boolean);
  const dnsStartedAt = new Date().toISOString();
  const resolver = new Resolver();
  const dnsDeadline = globalThis.setTimeout(() => resolver.cancel(), 10_000);
  let resolved: Array<{ address: string; ttl: number }>;
  try {
    resolved = await resolver.resolve4(endpoint.hostname, { ttl: true });
  } finally {
    globalThis.clearTimeout(dnsDeadline);
  }
  const dnsCompletedAt = new Date().toISOString();
  const publicAnswers = resolved
    .filter((answer, index, all) =>
      publicIPv4(answer.address) && all.findIndex((candidate) => candidate.address === answer.address) === index
    )
    .sort((left, right) => left.address.localeCompare(right.address));
  if (publicAnswers.length === 0) {
    throw new Error("SBX017_H3_ENDPOINT_URL did not resolve to a public IPv4 address");
  }
  const pinnedIPv4 = publicAnswers[0]!.address;
  const runId = randomUUID();
  const sandboxName = `sbx-017-poc-${runId.replaceAll("-", "")}`;
  const sandboxTags = { harness: "vsc", test: "SBX-017", run: runId };
  const publicCanaries = {
    "allow-h3-control": `public_${randomBytes(18).toString("base64url")}`,
    "allow-tcp-control": `public_${randomBytes(18).toString("base64url")}`,
    "deny-tcp-control": `public_${randomBytes(18).toString("base64url")}`,
    "deny-tcp-post-control": `public_${randomBytes(18).toString("base64url")}`,
  } as const;
  const guestSource = await readFile(resolve("guest/http3-deny-probe.py"), "utf8");
  if (controllerSecrets.some((secret) => guestSource.includes(secret))) {
    throw new Error("guest source unexpectedly contains controller-only material");
  }
  const gate = new RateGate();
  const probes: ProbeRecord[] = [];
  let endpointRequestAttempts = 0;
  const policyTransitions: Record<string, unknown>[] = [];
  const cleanup = {
    orphanRecoveryAttempted: false,
    recoveredHandle: false,
    orphanAbsenceConfirmed: false,
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    deletionAbsenceCheckAttempted: false,
    deletionAbsenceConfirmed: false,
    errors: [] as string[],
  };
  const packageSetup: Record<string, unknown> = {
    requested: `curl_cffi==${expectedCurlCffiVersion}`,
    targetDirectory: remoteSitePackages,
  };
  const operatorSecretSetup: Record<string, unknown> = {
    path: remoteOperatorSecretPath,
    expectedMode: "0600",
    writtenBeforeDenyAll: false,
    verifiedBeforeDenyAll: false,
  };
  let sandbox: Sandbox | undefined;
  let createAttempted = false;
  let originalSessionId: string | undefined;
  let sandboxIdentity: Record<string, unknown> | undefined;
  let executionError: string | undefined;
  let executionIndeterminate = false;
  let setupPassed = false;
  let allowH3ControlPassed = false;
  let allowTcpControlPassed = false;
  let denyUpdateAcknowledged = false;
  let denyReadbackPassed = false;
  let postDenyReadbackPassed = false;
  let denyTcpPreBlocked = false;
  let denyTcpPostBlocked = false;
  let denyH3Succeeded = false;
  let denyH3Blocked = false;

  async function runProbe(
    caseId: string,
    mode: ProbeMode,
    publicCanary?: string,
  ): Promise<ProbeRecord> {
    if (!sandbox) throw new Error("sandbox is not available");
    const configuration = buildProbeConfiguration({
      endpointUrl: endpoint.href,
      pinnedIPv4,
      runId,
      caseId,
      mode,
      ...(publicCanary ? { publicCanary } : {}),
    });
    const serialized = JSON.stringify(configuration);
    if (controllerSecrets.some((secret) => serialized.includes(secret))) {
      throw new Error(`${caseId} guest configuration contains controller-only material`);
    }
    const requestCanary = caseId === "deny-h3-target" ? operatorSecret : publicCanary;
    if (!requestCanary) throw new Error(`${caseId} has no request canary source`);
    endpointRequestAttempts += 1;
    const captured = await captureCommand(
      sandbox,
      gate,
      {
        cmd: "python3",
        args: [remoteProbePath, Buffer.from(serialized).toString("base64url")],
        env: {
          PYTHONPATH: remoteSitePackages,
          HTTP_PROXY: "",
          HTTPS_PROXY: "",
          ALL_PROXY: "",
          NO_PROXY: "*",
        },
        timeoutMs: 15_000,
      },
      controllerSecrets,
    );
    let decoded: unknown;
    try {
      decoded = JSON.parse(captured.stdout);
    } catch {
      throw new Error(`${caseId} guest probe emitted invalid JSON`);
    }
    const result = sanitizeProbeResult(decoded);
    const probe: ProbeRecord = {
      caseId,
      mode,
      canarySource: caseId === "deny-h3-target"
        ? "operator-secret-file"
        : "controller-public-canary",
      configurationSha256: sha256(serialized),
      ...(publicCanary ? { publicCanarySha256: sha256(publicCanary) } : {}),
      expectedOperationId: expectedOperationId(controllerHmacKey, runId, caseId, requestCanary),
      command: captured.record,
      ...(result ? { result } : {}),
    };
    probes.push(probe);
    return probe;
  }

  try {
    await gate.beforeCall();
    createAttempted = true;
    sandbox = await Sandbox.create({
      name: sandboxName,
      persistent: false,
      timeout: 300_000,
      networkPolicy: "allow-all",
      tags: sandboxTags,
      signal: controlSignal(45_000),
      ...credentials,
    });
    const session = sandbox.currentSession();
    originalSessionId = session.sessionId;
    sandboxIdentity = {
      name: sandbox.name,
      sessionId: session.sessionId,
      sessionCreatedAt: session.createdAt.toISOString(),
      sessionRequestedAt: session.requestedAt.toISOString(),
      region: session.region,
      persistent: sandbox.persistent,
      initialNetworkPolicy: sandbox.networkPolicy,
      initialSessionNetworkPolicy: session.networkPolicy,
    };
    if (
      sandbox.persistent !== false || sandbox.networkPolicy !== "allow-all" ||
      session.networkPolicy !== "allow-all"
    ) {
      throw new IndeterminateError("fresh sandbox did not report literal allow-all");
    }

    const install = await captureCommand(
      sandbox,
      gate,
      {
        cmd: "python3",
        args: [
          "-m",
          "pip",
          "install",
          "--disable-pip-version-check",
          "--no-input",
          "--no-cache-dir",
          "--retries",
          "0",
          "--only-binary=:all:",
          "--target",
          remoteSitePackages,
          `curl_cffi==${expectedCurlCffiVersion}`,
        ],
        timeoutMs: 120_000,
      },
      controllerSecrets,
    );
    packageSetup.install = install.record;
    if (install.record.exitCode !== 0) {
      throw new IndeterminateError("pinned curl_cffi installation failed");
    }
    const versionCheck = await captureCommand(
      sandbox,
      gate,
      {
        cmd: "python3",
        args: [
          "-c",
          "import curl_cffi,json; from importlib.metadata import version; print(json.dumps({'distributionVersion':version('curl_cffi'),'curlBuild':curl_cffi.__curl_version__,'modulePath':curl_cffi.__file__},separators=(',',':')))",
        ],
        env: { PYTHONPATH: remoteSitePackages },
        timeoutMs: 10_000,
      },
      controllerSecrets,
    );
    packageSetup.versionCheck = versionCheck.record;
    let runtimeDetails: Record<string, unknown> | undefined;
    try {
      runtimeDetails = record(JSON.parse(versionCheck.stdout));
    } catch {
      runtimeDetails = undefined;
    }
    const observedVersion = safeText(runtimeDetails?.distributionVersion, 32);
    const curlBuild = safeText(runtimeDetails?.curlBuild, 512);
    const modulePath = safeText(runtimeDetails?.modulePath, 512);
    packageSetup.runtime = { observedVersion, curlBuild, modulePath };
    if (
      versionCheck.record.exitCode !== 0 || observedVersion !== expectedCurlCffiVersion ||
      !curlBuild?.includes("ngtcp2/") || !curlBuild.includes("nghttp3/") ||
      !modulePath?.startsWith(`${remoteSitePackages}/curl_cffi/`)
    ) {
      throw new IndeterminateError("curl_cffi version verification failed");
    }
    await gate.beforeCall();
    await sandbox.writeFiles([
      { path: remoteProbePath, content: guestSource, mode: 0o700 },
      { path: remoteOperatorSecretPath, content: operatorSecret, mode: 0o600 },
    ], { signal: controlSignal() });
    operatorSecretSetup.writtenBeforeDenyAll = true;
    const secretVerification = await captureCommand(
      sandbox,
      gate,
      {
        cmd: "python3",
        args: [
          "-c",
          `import os,stat; p=${JSON.stringify(remoteOperatorSecretPath)}; fd=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)); s=os.fstat(fd); d=os.read(fd,129); os.close(fd); assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o600 and len(d)==s.st_size and 16<=len(d)<=128; print('OK')`,
        ],
        timeoutMs: 10_000,
      },
      controllerSecrets,
    );
    operatorSecretSetup.verificationCommand = secretVerification.record;
    operatorSecretSetup.observedMode = "0600";
    const observedSecret = await sandbox.readFileToBuffer(
      { path: remoteOperatorSecretPath },
      { signal: controlSignal() },
    );
    const expectedSecret = Buffer.from(operatorSecret, "ascii");
    const exactSecretContentMatched = observedSecret !== null && observedSecret.equals(expectedSecret);
    observedSecret?.fill(0);
    expectedSecret.fill(0);
    operatorSecretSetup.exactContentMatched = exactSecretContentMatched;
    operatorSecretSetup.verifiedBeforeDenyAll = secretVerification.record.exitCode === 0 &&
      secretVerification.stdout.trim() === "OK" && exactSecretContentMatched;
    if (!operatorSecretSetup.verifiedBeforeDenyAll) {
      throw new IndeterminateError("synthetic operator-secret file verification failed");
    }
    setupPassed = true;

    const allowH3 = await runProbe(
      "allow-h3-control",
      "h3-v3only",
      publicCanaries["allow-h3-control"],
    );
    allowH3ControlPassed = authenticatedProtocolSuccess(
      allowH3,
      runId,
      allowH3.caseId,
      allowH3.mode,
      endpoint,
      pinnedIPv4,
    );
    if (!allowH3ControlPassed) {
      throw new IndeterminateError("allow-all HTTP/3 v3only control failed");
    }
    const allowTcp = await runProbe(
      "allow-tcp-control",
      "https-v1",
      publicCanaries["allow-tcp-control"],
    );
    allowTcpControlPassed = authenticatedProtocolSuccess(
      allowTcp,
      runId,
      allowTcp.caseId,
      allowTcp.mode,
      endpoint,
      pinnedIPv4,
    );
    if (!allowTcpControlPassed) {
      throw new IndeterminateError("allow-all HTTPS/TCP control failed");
    }

    const updateStartedAt = new Date().toISOString();
    await gate.beforeCall();
    await sandbox.update({ networkPolicy: "deny-all" }, { signal: controlSignal() });
    const activeSession = sandbox.currentSession();
    const activePolicyAfterUpdate = sandbox.networkPolicy as NetworkPolicy;
    denyUpdateAcknowledged = activePolicyAfterUpdate === "deny-all" &&
      activeSession.networkPolicy === "deny-all" && activeSession.sessionId === originalSessionId;
    await gate.beforeCall();
    const independentReadback = await Sandbox.get({
      name: sandbox.name,
      resume: false,
      signal: controlSignal(),
      ...credentials,
    });
    const independentSession = independentReadback.currentSession();
    denyReadbackPassed = independentReadback.networkPolicy === "deny-all" &&
      independentSession.networkPolicy === "deny-all" && independentSession.sessionId === originalSessionId;
    await delay(policySettleDelayMs, undefined, { signal: controlSignal(policySettleDelayMs + 2_000) });
    policyTransitions.push({
      stage: "allow-all-to-deny-all",
      startedAt: updateStartedAt,
      completedAt: new Date().toISOString(),
      settleDelayMs: policySettleDelayMs,
      updateAcknowledged: denyUpdateAcknowledged,
      activeHandleReadback: activePolicyAfterUpdate,
      activeSessionId: activeSession.sessionId,
      activeSessionReadback: activeSession.networkPolicy,
      independentReadback: independentReadback.networkPolicy,
      independentSessionId: independentSession.sessionId,
      independentSessionReadback: independentSession.networkPolicy,
    });
    if (!denyUpdateAcknowledged || !denyReadbackPassed) {
      throw new IndeterminateError("literal deny-all update or independent readback failed");
    }

    const denyTcp = await runProbe(
      "deny-tcp-control",
      "https-v1",
      publicCanaries["deny-tcp-control"],
    );
    denyTcpPreBlocked = conclusiveTcpBlock(denyTcp, runId, endpoint, pinnedIPv4);
    if (!denyTcpPreBlocked) {
      throw new IndeterminateError("HTTPS/TCP was not conclusively blocked at the pinned IP under deny-all");
    }

    const denyH3 = await runProbe("deny-h3-target", "h3-v3only");
    denyH3Succeeded = authenticatedProtocolSuccess(
      denyH3,
      runId,
      denyH3.caseId,
      denyH3.mode,
      endpoint,
      pinnedIPv4,
    );
    denyH3Blocked = !denyH3Succeeded && conclusiveH3Block(denyH3, runId, endpoint, pinnedIPv4);

    const postReadbackStartedAt = new Date().toISOString();
    const postActiveSession = sandbox.currentSession();
    await gate.beforeCall();
    const postIndependentReadback = await Sandbox.get({
      name: sandbox.name,
      resume: false,
      signal: controlSignal(),
      ...credentials,
    });
    const postIndependentSession = postIndependentReadback.currentSession();
    const postActiveSandboxPolicy = sandbox.networkPolicy as NetworkPolicy;
    postDenyReadbackPassed = postActiveSandboxPolicy === "deny-all" &&
      postActiveSession.networkPolicy === "deny-all" && postActiveSession.sessionId === originalSessionId &&
      postIndependentReadback.networkPolicy === "deny-all" &&
      postIndependentSession.networkPolicy === "deny-all" &&
      postIndependentSession.sessionId === originalSessionId;
    policyTransitions.push({
      stage: "post-h3-same-session-deny-all-barrier",
      startedAt: postReadbackStartedAt,
      completedAt: new Date().toISOString(),
      originalSessionId,
      activeSessionId: postActiveSession.sessionId,
      activeSandboxReadback: postActiveSandboxPolicy,
      activeSessionReadback: postActiveSession.networkPolicy,
      independentSessionId: postIndependentSession.sessionId,
      independentSandboxReadback: postIndependentReadback.networkPolicy,
      independentSessionReadback: postIndependentSession.networkPolicy,
      postDenyReadbackPassed,
    });
    if (!postDenyReadbackPassed) {
      throw new IndeterminateError("post-H3 literal deny-all or same-session readback failed");
    }

    const denyTcpPost = await runProbe(
      "deny-tcp-post-control",
      "https-v1",
      publicCanaries["deny-tcp-post-control"],
    );
    denyTcpPostBlocked = conclusiveTcpBlock(denyTcpPost, runId, endpoint, pinnedIPv4, "deny-tcp-post-control");
    if (!denyTcpPostBlocked) {
      throw new IndeterminateError("post-H3 HTTPS/TCP was not conclusively blocked under deny-all");
    }
  } catch (error) {
    executionError = safeError(error, controllerSecrets);
    executionIndeterminate = error instanceof IndeterminateError;
  } finally {
    if (!sandbox && createAttempted) {
      cleanup.orphanRecoveryAttempted = true;
      let notFoundCount = 0;
      for (let attempt = 0; attempt < 3 && !sandbox; attempt += 1) {
        if (attempt > 0) await delay(1_000, undefined, { signal: controlSignal(3_000) });
        try {
          await gate.beforeCall();
          const recovered = await Sandbox.get({
            name: sandboxName,
            resume: false,
            signal: controlSignal(),
            ...credentials,
          });
          const createdAt = recovered.createdAt.getTime();
          const creationWindowValid = Number.isFinite(createdAt) &&
            createdAt >= Date.parse(startedAt) - 5_000 && createdAt <= Date.now() + 5_000;
          const tagsValid = recovered.tags?.harness === sandboxTags.harness &&
            recovered.tags?.test === sandboxTags.test && recovered.tags?.run === sandboxTags.run;
          if (!creationWindowValid || !tagsValid) {
            cleanup.errors.push("orphan recovery found a sandbox without the exact run identity; left untouched");
            break;
          }
          sandbox = recovered;
          cleanup.recoveredHandle = true;
        } catch (error) {
          if (isNotFound(error)) {
            notFoundCount += 1;
          } else {
            cleanup.errors.push(`orphan recovery: ${safeError(error, controllerSecrets)}`);
            break;
          }
        }
      }
      cleanup.orphanAbsenceConfirmed = !sandbox && notFoundCount === 3;
    }
    if (sandbox) {
      cleanup.stopAttempted = true;
      try {
        await gate.beforeCall();
        await sandbox.stop({ signal: controlSignal() });
        cleanup.stopped = true;
      } catch (error) {
        cleanup.errors.push(`stop: ${safeError(error, controllerSecrets)}`);
      }
      cleanup.deleteAttempted = true;
      try {
        await gate.beforeCall();
        await sandbox.delete({ signal: controlSignal() });
        cleanup.deleted = true;
      } catch (error) {
        cleanup.errors.push(`delete: ${safeError(error, controllerSecrets)}`);
      }
      if (cleanup.deleted) {
        cleanup.deletionAbsenceCheckAttempted = true;
        let notFoundCount = 0;
        for (let attempt = 0; attempt < 3; attempt += 1) {
          if (attempt > 0) await delay(1_000, undefined, { signal: controlSignal(3_000) });
          try {
            await gate.beforeCall();
            await Sandbox.get({
              name: sandboxName,
              resume: false,
              signal: controlSignal(),
              ...credentials,
            });
          } catch (error) {
            if (isNotFound(error)) {
              notFoundCount += 1;
            } else {
              cleanup.errors.push(`deletion absence check: ${safeError(error, controllerSecrets)}`);
              break;
            }
          }
        }
        cleanup.deletionAbsenceConfirmed = notFoundCount === 3;
        if (!cleanup.deletionAbsenceConfirmed && cleanup.errors.length === 0) {
          cleanup.errors.push("deleted sandbox remained discoverable during independent absence checks");
        }
      }
    }
  }

  const cleanupPassed = !createAttempted || (
    cleanup.errors.length === 0 && (
      (sandbox !== undefined && cleanup.stopped && cleanup.deleted && cleanup.deletionAbsenceConfirmed) ||
      (sandbox === undefined && cleanup.orphanAbsenceConfirmed)
    )
  );
  const assessment = assessQuicDenyAll({
    setupPassed,
    allowH3ControlPassed,
    allowTcpControlPassed,
    denyUpdateAcknowledged,
    denyReadbackPassed,
    postDenyReadbackPassed,
    denyTcpPreBlocked,
    denyTcpPostBlocked,
    denyH3Succeeded,
    denyH3Blocked,
    cleanupPassed,
    ...(executionError && !executionIndeterminate ? { executionError: true } : {}),
  });
  const evidence = {
    schemaVersion: 2,
    visibility: "private",
    testId: "SBX-017",
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    scope: "one researcher-owned Vercel sandbox and one researcher-owned HTTP/3 endpoint",
    requestBounds: {
      endpointRequestAttempts,
      retainedProbeResults: probes.length,
      maximumEndpointRequests: 5,
      sequential: true,
      retryCount: 0,
      redirectsAllowed: false,
      minimumControllerCallIntervalMs,
    },
    endpoint: {
      origin: endpoint.origin,
      path: endpoint.pathname,
      pinnedIPv4,
      controllerResolvedAt: { startedAt: dnsStartedAt, completedAt: dnsCompletedAt },
      resolvedARecords: publicAnswers,
      contract: "{authorized:true,operationId:h3_+base64url(HMAC-SHA256(H3_ACTION_KEY,runId\\ncaseId\\ncanary))}",
    },
    credentialContext: {
      mode: "explicit-alias-verified",
      email: verifiedAliasEmail,
      teamId: credentials.teamId,
      projectId: credentials.projectId,
    },
    sandbox: sandboxIdentity,
    packageSetup,
    operatorSecretSetup,
    policy: {
      initial: "allow-all" satisfies NetworkPolicy,
      tightened: "deny-all" satisfies NetworkPolicy,
      transitions: policyTransitions,
    },
    guestMaterialGuards: {
      hmacKeyEnteredGuestSourceConfigurationArgumentsOrOutput: false,
      rawOperatorSecretEnteredGuestSourceConfigurationArgumentsOutputOrArtifact: false,
      keyedReceiptProofRetained: true,
      vercelTokenEnteredGuestSourceConfigurationArgumentsOrOutput: false,
      rawHttpResponseRetained: false,
    },
    probes,
    controls: {
      setupPassed,
      allowH3ControlPassed,
      allowTcpControlPassed,
      denyUpdateAcknowledged,
      denyReadbackPassed,
      postDenyReadbackPassed,
      denyTcpPreBlocked,
      denyTcpPostBlocked,
      denyH3Succeeded,
      denyH3Blocked,
    },
    assessment,
    cleanup,
    ...(executionError ? { executionError } : {}),
  };
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const privateEvidencePath = resolve(artifactsDirectory, `SBX-017-poc-${runId}-private.json`);
  const serializedEvidence = `${JSON.stringify(evidence, null, 2)}\n`;
  if (controllerSecrets.some((secret) => secret && serializedEvidence.includes(secret))) {
    throw new Error("refusing to write evidence containing controller-only material");
  }
  await writeFile(privateEvidencePath, serializedEvidence, { mode: 0o600, flag: "wx" });
  process.stdout.write(`${JSON.stringify({
    testId: "SBX-017",
    runId,
    verdict: assessment.verdict,
    candidate: assessment.candidate,
    summary: assessment.summary,
    endpointHostname: endpoint.hostname,
    pinnedIPv4,
    sandbox: sandboxIdentity,
    controls: evidence.controls,
    cleanup,
    privateEvidencePath,
    ...(executionError ? { executionError } : {}),
  }, null, 2)}\n`);
  if (assessment.verdict !== "pass") process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
