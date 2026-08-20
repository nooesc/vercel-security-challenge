import "dotenv/config";

import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { mkdir, open, readFile, unlink, writeFile, type FileHandle } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { APIError, Sandbox, type NetworkPolicy } from "@vercel/sandbox";
import { requestOnce } from "../../guest/wildcard-label-probe.mjs";
import { verifyEligibleAliasToken } from "../eligible-alias-identity.js";
import {
  assessSbx044,
  exactAllowPolicy,
  exactTransformPolicy,
  exactWildcardPolicy,
  SBX044_ALLOWED_HOST,
  SBX044_DENIED_HOST,
  SBX044_REDACTED_VALUE,
  SBX044_TEST_ID,
  SBX044_TRANSFORM_HEADER,
  SBX044_WILDCARD_PATTERN,
  type Sbx044AssessmentInput,
  type Sbx044CaseId,
  type Sbx044Cleanup,
  type Sbx044LedgerEvidence,
  type Sbx044PolicyProof,
  type Sbx044ProbeEvidence,
  type Sbx044Role,
} from "./verdict.js";

const SCOPE_CONFIRMATION = "I_CONTROL_BOTH_SBX044_CUSTOM_DOMAINS_AND_AUTHORIZE_BOUNDED_WILDCARD_TESTING";
const ALIAS_EMAIL = "swve@wearehackerone.com";
const TEAM_ID = "team_n98ERpVwV7HqmWRudAyK8sXQ";
const PROJECT_ID = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
const ALLOWED_ORIGIN = `https://${SBX044_ALLOWED_HOST}`;
const DENIED_ORIGIN = `https://${SBX044_DENIED_HOST}`;
const REMOTE_PROBE_PATH = "/tmp/sbx-044/wildcard-label-probe.mjs";
const CONTROL_TIMEOUT_MS = 30_000;
const INTER_REQUEST_MS = 350;
const PLATFORM_TRUST_NAMES = ["NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "SSL_CERT_FILE"];
const CONTROLLER_TRUST_NAMES = [
  "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF",
  "OPENSSL_MODULES", "SSL_CERT_DIR", "SSL_CERT_FILE",
].filter((name) => process.env[name] !== undefined).sort();
const OPERATION_ID = /^w44[rs]_[A-Za-z0-9_-]{43}$/u;

interface Credentials {
  token: string;
  teamId: string;
  projectId: string;
}

interface CommandRecord {
  caseId: Sbx044CaseId;
  startedAt: string;
  completedAt: string;
  commandId: string;
  exitCode: number;
  stdoutBytes: number;
  stdoutSha256: string;
  stderrBytes: number;
  stderrSha256: string;
  configurationSha256: string;
}

interface StageResult {
  allowed: Sbx044ProbeEvidence;
  denied: Sbx044ProbeEvidence;
  allowedAfter?: Sbx044ProbeEvidence;
  before: Sbx044PolicyProof;
  after: Sbx044PolicyProof;
  cleanup: Sbx044Cleanup;
  sessionId: string;
  sessionCreatedAt: string;
  sandboxName: string;
  sandboxCreatedAt: string;
  stageStartedAt: string;
  stageCompletedAt: string;
  region?: string;
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function explicitCredentials(environment: NodeJS.ProcessEnv = process.env): Credentials {
  const token = required(environment, "VERCEL_TOKEN");
  if (environment.VERCEL_TEAM_ID !== TEAM_ID || environment.VERCEL_PROJECT_ID !== PROJECT_ID) {
    throw new Error("SBX-044 requires the exact verified HackerOne-alias team and project");
  }
  return { token, teamId: TEAM_ID, projectId: PROJECT_ID };
}

function controlledConfiguration(environment: NodeJS.ProcessEnv = process.env): {
  allowedActionKey: string;
  deniedActionKey: string;
  allowedAdminKey: string;
  deniedAdminKey: string;
} {
  if (environment.SBX044_SCOPE_CONFIRMATION !== SCOPE_CONFIRMATION) {
    throw new Error(`SBX044_SCOPE_CONFIRMATION must equal ${SCOPE_CONFIRMATION}`);
  }
  if (environment.SBX044_ALLOWED_ORIGIN !== ALLOWED_ORIGIN || environment.SBX044_DENIED_ORIGIN !== DENIED_ORIGIN) {
    throw new Error("SBX-044 origins must be the two fixed researcher-owned Custom Domains");
  }
  const values = {
    allowedActionKey: required(environment, "SBX044_ALLOWED_ACTION_KEY"),
    deniedActionKey: required(environment, "SBX044_DENIED_ACTION_KEY"),
    allowedAdminKey: required(environment, "SBX044_ALLOWED_ADMIN_KEY"),
    deniedAdminKey: required(environment, "SBX044_DENIED_ADMIN_KEY"),
  };
  for (const [name, value] of Object.entries(values)) {
    if (Buffer.byteLength(value) < 32 || Buffer.byteLength(value) > 256 || /[\0\r\n]/u.test(value)) {
      throw new Error(`${name} must contain 32-256 bytes without control characters`);
    }
  }
  if (new Set(Object.values(values)).size !== 4) throw new Error("all SBX-044 Worker keys must be distinct");
  return values;
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function signal(timeout = CONTROL_TIMEOUT_MS): AbortSignal {
  return AbortSignal.timeout(timeout);
}

function safeError(error: unknown, secrets: string[]): string {
  let output = error instanceof Error ? error.message : String(error);
  for (const secret of secrets) if (secret) output = output.split(secret).join("[REDACTED]");
  return output.replace(/[\0\r\n]/gu, " ").slice(0, 1_000);
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function exactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((entry, index) => entry === wanted[index]);
}

function string(value: unknown, maximum = 4_096): string | undefined {
  return typeof value === "string" && value.length <= maximum ? value : undefined;
}

function number(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function boolean(value: unknown): boolean {
  return value === true;
}

function sanitizeProbe(value: unknown, commandExitCode: number): Sbx044ProbeEvidence {
  const root = object(value) ?? {};
  const request = object(root.request) ?? {};
  const trust = object(root.tlsTrust) ?? {};
  const transport = object(root.transport) ?? {};
  const trustNames = Array.isArray(trust.inheritedPlatformTrustEnvironmentNames)
    ? trust.inheritedPlatformTrustEnvironmentNames.filter((entry): entry is string => typeof entry === "string")
    : [];
  const evidence: Sbx044ProbeEvidence = {
    schemaVersion: number(root.schemaVersion) ?? -1,
    testId: string(root.testId, 64) ?? "missing",
    runId: string(root.runId, 128) ?? "missing",
    caseId: string(root.caseId, 128) ?? "missing",
    correlationCanary: string(root.correlationCanary, 256) ?? "missing",
    expectedRole: root.expectedRole === "allowed" ? "allowed" : "denied",
    commandExitCode,
    ok: boolean(root.ok),
    phase: string(root.phase, 64) ?? "missing",
    requestHostname: string(request.hostname, 256) ?? "missing",
    requestServername: string(request.servername, 256) ?? "missing",
    connectionAttempts: number(request.connectionAttempts) ?? -1,
    actualConnections: number(request.actualConnections) ?? -1,
    actualRequests: number(request.actualRequests) ?? -1,
    retries: number(request.retries) ?? -1,
    redirectsFollowed: number(request.redirectsFollowed) ?? -1,
    rejectUnauthorized: boolean(trust.rejectUnauthorized),
    controllerConfigurableCustomTrustAccepted: boolean(trust.controllerConfigurableCustomTrustAccepted),
    inheritedPlatformTrustEnvironmentNames: trustNames,
    tcpConnected: boolean(transport.tcpConnected),
    tlsAuthorized: boolean(transport.authorized),
    tlsEstablished: boolean(transport.tlsEstablished),
    responseReceived: boolean(root.responseReceived),
    durationMs: number(root.durationMs) ?? -1,
    ...(number(root.responseStatusCode) !== undefined ? { responseStatusCode: number(root.responseStatusCode)! } : {}),
    ...(root.responseRole === "allowed" || root.responseRole === "denied" ? { responseRole: root.responseRole } : {}),
    ...(typeof root.responseBrokered === "boolean" ? { responseBrokered: root.responseBrokered } : {}),
    ...(string(root.responseOperationId, 128) ? { responseOperationId: string(root.responseOperationId, 128)! } : {}),
    ...(string(transport.remoteAddress, 128) ? { remoteAddress: string(transport.remoteAddress, 128)! } : {}),
    ...(number(transport.remotePort) !== undefined ? { remotePort: number(transport.remotePort)! } : {}),
    ...(string(root.errorCode, 64) ? { errorCode: string(root.errorCode, 64)! } : {}),
    ...(number(root.errorErrno) !== undefined ? { errorErrno: number(root.errorErrno)! } : {}),
    ...(string(root.errorSyscall, 64) ? { errorSyscall: string(root.errorSyscall, 64)! } : {}),
  };
  return evidence;
}

function roleFor(caseId: Sbx044CaseId): Sbx044Role {
  return caseId.endsWith("allowed") || caseId.includes("allowed-") ? "allowed" : "denied";
}

function urlFor(runId: string, caseId: Sbx044CaseId, canary: string): string {
  const hostname = roleFor(caseId) === "allowed" ? SBX044_ALLOWED_HOST : SBX044_DENIED_HOST;
  const url = new URL("/v1/sbx044/action", `https://${hostname}`);
  url.search = new URLSearchParams({ run: runId, case: caseId, canary }).toString();
  return url.toString();
}

function probeConfiguration(runId: string, caseId: Sbx044CaseId, canary: string): Record<string, unknown> {
  return {
    scopeConfirmation: "researcher-controlled-sbx044-origins-only",
    testId: SBX044_TEST_ID,
    runId,
    caseId,
    canary,
    expectedRole: roleFor(caseId),
    researcherControlledHosts: [SBX044_ALLOWED_HOST, SBX044_DENIED_HOST],
    url: urlFor(runId, caseId, canary),
    timeoutMs: 8_000,
  };
}

export function expectedOperationId(
  actionKey: string,
  runId: string,
  caseId: Sbx044CaseId,
  canary: string,
  role: Sbx044Role,
  brokeredSecret?: string,
): string {
  const hostname = role === "allowed" ? SBX044_ALLOWED_HOST : SBX044_DENIED_HOST;
  const message = brokeredSecret === undefined
    ? `v1\n${SBX044_TEST_ID}\n${hostname}\n${role}\n${runId}\n${caseId}\n${canary}\nreach`
    : `v1\n${SBX044_TEST_ID}\n${hostname}\n${role}\n${runId}\n${caseId}\n${canary}\nsecret\n${brokeredSecret}`;
  const prefix = brokeredSecret === undefined ? "w44r" : "w44s";
  return `${prefix}_${createHmac("sha256", actionKey).update(message).digest("base64url")}`;
}

function isNotFound(error: unknown): boolean {
  return error instanceof APIError && error.response.status === 404;
}

function redactPolicy(value: unknown, secret?: string): unknown {
  let serialized = JSON.stringify(value);
  if (secret) serialized = serialized.split(secret).join(SBX044_REDACTED_VALUE);
  return JSON.parse(serialized) as unknown;
}

async function policyProof(
  kind: Sbx044PolicyProof["kind"],
  stage: Sbx044PolicyProof["stage"],
  sandbox: Sandbox,
  initialSessionId: string,
  credentials: Credentials,
  secret?: string,
): Promise<Sbx044PolicyProof> {
  const activeSession = sandbox.currentSession();
  const independent = await Sandbox.get({ name: sandbox.name, resume: false, ...credentials, signal: signal() });
  const independentSession = independent.currentSession();
  const raw = [sandbox.networkPolicy, activeSession.networkPolicy, independent.networkPolicy, independentSession.networkPolicy];
  const serialized = JSON.stringify(raw);
  return {
    kind,
    stage,
    initialSessionId,
    activeSessionId: activeSession.sessionId,
    independentSessionId: independentSession.sessionId,
    activeSandboxPolicy: redactPolicy(sandbox.networkPolicy, secret),
    activeSessionPolicy: redactPolicy(activeSession.networkPolicy, secret),
    independentSandboxPolicy: redactPolicy(independent.networkPolicy, secret),
    independentSessionPolicy: redactPolicy(independentSession.networkPolicy, secret),
    rawSecretPresentInReadbacks: secret !== undefined && serialized.includes(secret),
    platformRedactionMarkerPresent: serialized.includes(SBX044_REDACTED_VALUE),
  };
}

function policyProofLocallyValid(proof: Sbx044PolicyProof): boolean {
  const same = proof.initialSessionId === proof.activeSessionId && proof.initialSessionId === proof.independentSessionId;
  if (!same || proof.rawSecretPresentInReadbacks) return false;
  const policies = [proof.activeSandboxPolicy, proof.activeSessionPolicy, proof.independentSandboxPolicy, proof.independentSessionPolicy];
  if (proof.kind === "baseline") {
    return !proof.platformRedactionMarkerPresent && policies.every((value) =>
      exactAllowPolicy(value, [SBX044_ALLOWED_HOST, SBX044_DENIED_HOST])
    );
  }
  if (proof.kind === "public") {
    return !proof.platformRedactionMarkerPresent && policies.every((value) => exactWildcardPolicy(value, SBX044_WILDCARD_PATTERN));
  }
  return proof.platformRedactionMarkerPresent &&
    exactWildcardPolicy(proof.activeSandboxPolicy, SBX044_WILDCARD_PATTERN) &&
    exactTransformPolicy(proof.activeSessionPolicy, SBX044_WILDCARD_PATTERN, SBX044_REDACTED_VALUE) &&
    exactWildcardPolicy(proof.independentSandboxPolicy, SBX044_WILDCARD_PATTERN) &&
    exactTransformPolicy(proof.independentSessionPolicy, SBX044_WILDCARD_PATTERN, SBX044_REDACTED_VALUE);
}

async function adminRequest(
  role: Sbx044Role,
  adminKey: string,
  runId: string,
  init: RequestInit = {},
): Promise<Response> {
  const hostname = role === "allowed" ? SBX044_ALLOWED_HOST : SBX044_DENIED_HOST;
  const headers = new Headers(init.headers);
  headers.set("authorization", `Bearer ${adminKey}`);
  if (init.body) headers.set("content-type", "application/json");
  return fetch(new URL(`/v1/sbx044/admin/runs/${encodeURIComponent(runId)}`, `https://${hostname}`), {
    ...init,
    headers,
    redirect: "error",
    signal: signal(10_000),
  });
}

async function ledgerSnapshot(role: Sbx044Role, adminKey: string, runId: string): Promise<Sbx044LedgerEvidence> {
  const response = await adminRequest(role, adminKey, runId);
  if (!response.ok) throw new Error(`${role} ledger readback returned ${response.status}`);
  const root = object(await response.json());
  if (
    !root || !exactKeys(root, [
      "brokeredSecretDigestRetained", "configured", "events", "rawBrokeredSecretRetained", "role",
    ]) || typeof root.configured !== "boolean" || root.role !== role || !Array.isArray(root.events) ||
    root.rawBrokeredSecretRetained !== false || root.brokeredSecretDigestRetained !== false
  ) throw new Error(`${role} ledger readback shape was invalid`);
  const events = root.events.map((value): Sbx044LedgerEvidence["events"][number] => {
    const event = object(value);
    if (
      !event || !exactKeys(event, [
        "brokered", "canaryMatched", "caseId", "observedAt", "operationId", "ordinal", "role",
      ]) || event.role !== role || typeof event.caseId !== "string" ||
      typeof event.canaryMatched !== "boolean" || typeof event.brokered !== "boolean" ||
      typeof event.operationId !== "string" || !OPERATION_ID.test(event.operationId) ||
      typeof event.ordinal !== "number" || !Number.isInteger(event.ordinal) || event.ordinal <= 0 ||
      typeof event.observedAt !== "string" || Number.isNaN(Date.parse(event.observedAt))
    ) throw new Error(`${role} ledger event shape was invalid`);
    return {
      ordinal: event.ordinal,
      observedAt: event.observedAt,
      role,
      caseId: event.caseId,
      canaryMatched: event.canaryMatched,
      brokered: event.brokered,
      operationId: event.operationId,
    };
  });
  return {
    configured: root.configured,
    role,
    events,
    rawBrokeredSecretRetained: false,
    brokeredSecretDigestRetained: false,
  };
}

async function configureLedger(
  role: Sbx044Role,
  adminKey: string,
  runId: string,
  cases: Array<{ caseId: Sbx044CaseId; canary: string }>,
): Promise<void> {
  const response = await adminRequest(role, adminKey, runId, {
    method: "PUT",
    body: JSON.stringify({ cases }),
  });
  if (response.status !== 201) throw new Error(`${role} ledger configuration returned ${response.status}`);
  const snapshot = await ledgerSnapshot(role, adminKey, runId);
  if (!snapshot.configured || snapshot.events.length !== 0) throw new Error(`${role} ledger did not configure empty`);
}

function emptyProbe(runId: string, caseId: Sbx044CaseId, canary: string): Sbx044ProbeEvidence {
  return {
    schemaVersion: -1, testId: "missing", runId, caseId, correlationCanary: canary,
    expectedRole: roleFor(caseId), commandExitCode: -1, ok: false, phase: "missing",
    requestHostname: roleFor(caseId) === "allowed" ? SBX044_ALLOWED_HOST : SBX044_DENIED_HOST,
    requestServername: roleFor(caseId) === "allowed" ? SBX044_ALLOWED_HOST : SBX044_DENIED_HOST,
    connectionAttempts: 0, actualConnections: 0, actualRequests: 0, retries: 0,
    redirectsFollowed: 0, rejectUnauthorized: true,
    controllerConfigurableCustomTrustAccepted: false,
    inheritedPlatformTrustEnvironmentNames: [], tcpConnected: false,
    tlsAuthorized: false, tlsEstablished: false, responseReceived: false, durationMs: -1,
  };
}

function exactTrust(actual: string[], expected: string[]): boolean {
  const left = [...actual].sort();
  const right = [...expected].sort();
  return actual.join(",") === left.join(",") && new Set(actual).size === actual.length &&
    left.length === right.length && left.every((name, index) => name === right[index]);
}

function exactProbeAndEvent(
  probe: Sbx044ProbeEvidence,
  runId: string,
  caseId: Sbx044CaseId,
  canary: string,
  operationId: string,
  brokered: boolean,
  ledger: Sbx044LedgerEvidence,
  trustNames: string[],
): boolean {
  const role = roleFor(caseId);
  const hostname = role === "allowed" ? SBX044_ALLOWED_HOST : SBX044_DENIED_HOST;
  const caseEvents = ledger.events.filter((event) => event.caseId === caseId);
  return probe.schemaVersion === 1 && probe.testId === SBX044_TEST_ID && probe.runId === runId &&
    probe.caseId === caseId && probe.correlationCanary === canary && probe.expectedRole === role &&
    probe.commandExitCode === 0 && probe.ok && probe.phase === "response" &&
    probe.requestHostname === hostname && probe.requestServername === hostname &&
    probe.connectionAttempts === 1 && probe.actualConnections === 1 && probe.actualRequests === 1 &&
    probe.retries === 0 && probe.redirectsFollowed === 0 && probe.rejectUnauthorized &&
    !probe.controllerConfigurableCustomTrustAccepted && exactTrust(probe.inheritedPlatformTrustEnvironmentNames, trustNames) &&
    probe.tcpConnected && probe.tlsEstablished && probe.tlsAuthorized && probe.responseReceived &&
    probe.responseStatusCode === 200 && probe.responseRole === role && probe.responseBrokered === brokered &&
    probe.responseOperationId === operationId && ledger.configured && ledger.role === role &&
    caseEvents.length === 1 && caseEvents.filter((event) =>
      event.caseId === caseId && event.role === role && event.canaryMatched &&
      event.brokered === brokered && event.operationId === operationId
    ).length === 1;
}

async function cleanupSandbox(
  sandbox: Sandbox | undefined,
  sandboxName: string,
  createAttempted: boolean,
  startedAt: string,
  tags: Record<string, string>,
  credentials: Credentials,
  secrets: string[],
): Promise<{ sandbox?: Sandbox; cleanup: Sbx044Cleanup }> {
  const cleanup: Sbx044Cleanup = { stopped: false, deleted: false, absenceChecks: 0, errors: [] };
  let handle = sandbox;
  if (!handle && createAttempted) {
    for (let attempt = 0; attempt < 3 && !handle; attempt += 1) {
      if (attempt) await delay(750, undefined, { signal: signal(2_000) });
      try {
        const recovered = await Sandbox.get({ name: sandboxName, resume: false, ...credentials, signal: signal() });
        const created = recovered.createdAt.getTime();
        const recoveredTags = recovered.tags;
        const tagsMatch = recoveredTags?.harness === tags.harness && recoveredTags?.test === tags.test &&
          recoveredTags?.run === tags.run;
        if (!tagsMatch || created < Date.parse(startedAt) - 5_000 || created > Date.now() + 5_000) {
          cleanup.errors.push("orphan recovery found a sandbox without the exact run identity; left untouched");
          break;
        }
        handle = recovered;
      } catch (error) {
        if (!isNotFound(error)) {
          cleanup.errors.push(`orphan recovery: ${safeError(error, secrets)}`);
          break;
        }
      }
    }
  }
  if (handle) {
    try { await handle.stop({ signal: signal() }); cleanup.stopped = true; }
    catch (error) { cleanup.errors.push(`stop: ${safeError(error, secrets)}`); }
    try { await handle.delete({ signal: signal() }); cleanup.deleted = true; }
    catch (error) { cleanup.errors.push(`delete: ${safeError(error, secrets)}`); }
    if (cleanup.deleted) {
      for (let attempt = 0; attempt < 2; attempt += 1) {
        if (attempt) await delay(750, undefined, { signal: signal(2_000) });
        try { await Sandbox.get({ name: sandboxName, resume: false, ...credentials, signal: signal() }); }
        catch (error) { if (isNotFound(error)) cleanup.absenceChecks += 1; else cleanup.errors.push(`absence: ${safeError(error, secrets)}`); }
      }
    }
  }
  return { ...(handle ? { sandbox: handle } : {}), cleanup };
}

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  const credentials = explicitCredentials();
  const keys = controlledConfiguration();
  const runId = randomUUID();
  const cases = [
    "outside-pre-allowed", "outside-pre-denied", "baseline-allowed", "baseline-denied",
    "public-allowed-pre", "public-denied", "public-allowed-post", "secret-allowed",
    "secret-denied", "outside-post-allowed", "outside-post-denied",
  ] as const satisfies readonly Sbx044CaseId[];
  const canaries = Object.fromEntries(cases.map((caseId) => [caseId, `c44_${randomBytes(18).toString("base64url")}`])) as Record<Sbx044CaseId, string>;
  const brokeredSecret = `s44_${randomBytes(32).toString("base64url")}`;
  const actionKeyFor = (role: Sbx044Role): string => role === "allowed" ? keys.allowedActionKey : keys.deniedActionKey;
  const operationIds = Object.fromEntries(cases.map((caseId) => {
    const role = roleFor(caseId);
    const secret = caseId === "secret-allowed" || caseId === "secret-denied" ? brokeredSecret : undefined;
    return [caseId, expectedOperationId(actionKeyFor(role), runId, caseId, canaries[caseId], role, secret)];
  })) as Record<Sbx044CaseId, string> & { secretDeniedReach: string };
  operationIds.secretDeniedReach = expectedOperationId(
    keys.deniedActionKey, runId, "secret-denied", canaries["secret-denied"], "denied",
  );
  const operationValues = Object.values(operationIds);
  if (operationValues.some((value) => !OPERATION_ID.test(value)) || new Set(operationValues).size !== operationValues.length) {
    throw new Error("derived operation IDs were invalid or not unique");
  }
  const secrets = [credentials.token, keys.allowedActionKey, keys.deniedActionKey, keys.allowedAdminKey, keys.deniedAdminKey, brokeredSecret];
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  const lockPath = resolve(artifactsDirectory, "SBX-044-live-active.lock");
  const guestSource = await readFile(resolve("guest/wildcard-label-probe.mjs"), "utf8");
  if (secrets.some((secret) => guestSource.includes(secret))) throw new Error("guest source contains controller-only material");
  const commands: CommandRecord[] = [];
  const stageLifecycles: Array<{
    kind: Sbx044PolicyProof["kind"];
    sandboxName: string;
    sessionId: string;
    cleanup: Sbx044Cleanup;
  }> = [];
  let lock: FileHandle | undefined;
  let executionError: string | undefined;
  let allowedLedgerConfigured = false;
  let deniedLedgerConfigured = false;
  let ledgers: { allowed: Sbx044LedgerEvidence; denied: Sbx044LedgerEvidence } = {
    allowed: { configured: false, role: "allowed", events: [], rawBrokeredSecretRetained: false, brokeredSecretDigestRetained: false },
    denied: { configured: false, role: "denied", events: [], rawBrokeredSecretRetained: false, brokeredSecretDigestRetained: false },
  };
  const ledgerCleanup = { allowedDeleted: false, deniedDeleted: false, allowedAbsent: false, deniedAbsent: false, errors: [] as string[] };
  const outsidePreflight = {
    allowed: emptyProbe(runId, "outside-pre-allowed", canaries["outside-pre-allowed"]),
    denied: emptyProbe(runId, "outside-pre-denied", canaries["outside-pre-denied"]),
  };
  const outsidePostflight = {
    allowed: emptyProbe(runId, "outside-post-allowed", canaries["outside-post-allowed"]),
    denied: emptyProbe(runId, "outside-post-denied", canaries["outside-post-denied"]),
  };
  let baseline: StageResult | undefined;
  let publicStage: StageResult | undefined;
  let secretStage: StageResult | undefined;

  const runOutside = async (caseId: Sbx044CaseId): Promise<Sbx044ProbeEvidence> => {
    const raw = await requestOnce(probeConfiguration(runId, caseId, canaries[caseId]));
    await delay(INTER_REQUEST_MS, undefined, { signal: signal(2_000) });
    return sanitizeProbe(raw, 0);
  };

  const runStage = async (
    kind: Sbx044PolicyProof["kind"],
    policy: NetworkPolicy,
    allowedCase: Sbx044CaseId,
    deniedCase: Sbx044CaseId,
    allowedAfterCase?: Sbx044CaseId,
  ): Promise<StageResult> => {
    const stageStartedAt = new Date().toISOString();
    const sandboxName = `sbx-044-${kind}-${runId.replaceAll("-", "")}`;
    const tags = { harness: "vsc", test: SBX044_TEST_ID, run: runId, stage: kind };
    let sandbox: Sandbox | undefined;
    let createAttempted = false;
    let sessionId = "missing";
    let sessionCreatedAt = "missing";
    let sandboxCreatedAt = "missing";
    let region: string | undefined;
    let before: Sbx044PolicyProof | undefined;
    let after: Sbx044PolicyProof | undefined;
    let allowed = emptyProbe(runId, allowedCase, canaries[allowedCase]);
    let denied = emptyProbe(runId, deniedCase, canaries[deniedCase]);
    let allowedAfter = allowedAfterCase ? emptyProbe(runId, allowedAfterCase, canaries[allowedAfterCase]) : undefined;

    const runGuest = async (caseId: Sbx044CaseId): Promise<Sbx044ProbeEvidence> => {
      if (!sandbox) throw new Error("sandbox is unavailable");
      const configuration = probeConfiguration(runId, caseId, canaries[caseId]);
      const serialized = JSON.stringify(configuration);
      if (secrets.some((secret) => serialized.includes(secret))) throw new Error(`${caseId} guest configuration contains controller-only material`);
      const commandStartedAt = new Date().toISOString();
      const command = await sandbox.runCommand({
        cmd: "node", args: [REMOTE_PROBE_PATH, Buffer.from(serialized).toString("base64url")],
        timeoutMs: 20_000, signal: signal(),
      });
      const [stdout, stderr] = await Promise.all([command.stdout({ signal: signal() }), command.stderr({ signal: signal() })]);
      if (Buffer.byteLength(stdout) > 64_000 || Buffer.byteLength(stderr) > 16_000) throw new Error(`${caseId} guest output exceeded bounds`);
      if (secrets.some((secret) => stdout.includes(secret) || stderr.includes(secret))) throw new Error(`${caseId} guest output contains controller-only material`);
      let parsed: unknown;
      try { parsed = JSON.parse(stdout); } catch { throw new Error(`${caseId} guest output was not JSON`); }
      commands.push({
        caseId, startedAt: commandStartedAt, completedAt: new Date().toISOString(),
        commandId: command.cmdId, exitCode: command.exitCode,
        stdoutBytes: Buffer.byteLength(stdout), stdoutSha256: sha256(stdout),
        stderrBytes: Buffer.byteLength(stderr), stderrSha256: sha256(stderr),
        configurationSha256: sha256(serialized),
      });
      await delay(INTER_REQUEST_MS, undefined, { signal: signal(2_000) });
      return sanitizeProbe(parsed, command.exitCode);
    };

    let stageError: unknown;
    try {
      createAttempted = true;
      sandbox = await Sandbox.create({
        name: sandboxName, persistent: false, timeout: 300_000, resources: { vcpus: 2 },
        networkPolicy: policy, tags, ...credentials, signal: signal(),
      });
      const session = sandbox.currentSession();
      sessionId = session.sessionId;
      sessionCreatedAt = session.createdAt.toISOString();
      sandboxCreatedAt = sandbox.createdAt.toISOString();
      region = sandbox.region;
      if (sandbox.name !== sandboxName || sandbox.tags?.run !== runId || sandbox.tags.stage !== kind) {
        throw new Error(`${kind} sandbox identity mismatch`);
      }
      before = await policyProof(kind, "before", sandbox, sessionId, credentials, kind === "secret" ? brokeredSecret : undefined);
      if (!policyProofLocallyValid(before)) throw new Error(`${kind} pre-request policy proof failed`);
      await sandbox.writeFiles([{ path: REMOTE_PROBE_PATH, content: guestSource, mode: 0o700 }], { signal: signal() });
      allowed = await runGuest(allowedCase);
      const allowedLedger = await ledgerSnapshot("allowed", keys.allowedAdminKey, runId);
      if (!exactProbeAndEvent(
        allowed,
        runId,
        allowedCase,
        canaries[allowedCase],
        operationIds[allowedCase],
        kind === "secret",
        allowedLedger,
        PLATFORM_TRUST_NAMES,
      )) throw new Error(`${kind} A control failed before the B request`);
      denied = await runGuest(deniedCase);
      if (allowedAfterCase) allowedAfter = await runGuest(allowedAfterCase);
      after = await policyProof(kind, "after", sandbox, sessionId, credentials, kind === "secret" ? brokeredSecret : undefined);
      if (!policyProofLocallyValid(after)) throw new Error(`${kind} post-request policy proof failed`);
    } catch (error) {
      stageError = error;
    }
    let cleaned: { sandbox?: Sandbox; cleanup: Sbx044Cleanup };
    try {
      cleaned = await cleanupSandbox(sandbox, sandboxName, createAttempted, stageStartedAt, tags, credentials, secrets);
    } catch (error) {
      cleaned = {
        cleanup: {
          stopped: false,
          deleted: false,
          absenceChecks: 0,
          errors: [`cleanup orchestration: ${safeError(error, secrets)}`],
        },
      };
      stageError ??= error;
    }
    stageLifecycles.push({ kind, sandboxName, sessionId, cleanup: cleaned.cleanup });
    if (stageError) throw stageError;
    if (!before || !after) throw new Error(`${kind} stage did not capture both policy proofs`);
    return {
      allowed, denied, ...(allowedAfter ? { allowedAfter } : {}), before, after,
      cleanup: cleaned.cleanup, sessionId, sessionCreatedAt, sandboxName, sandboxCreatedAt,
      stageStartedAt, stageCompletedAt: new Date().toISOString(), ...(region ? { region } : {}),
    };
  };

  try {
    await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
    lock = await open(lockPath, "wx", 0o600);
    await lock.writeFile(`${JSON.stringify({ schemaVersion: 1, testId: SBX044_TEST_ID, runId, startedAt })}\n`);
    await lock.sync();
    await verifyEligibleAliasToken({
      token: credentials.token, expectedEmail: ALIAS_EMAIL, expectedTeamId: TEAM_ID,
      expectedProjectId: PROJECT_ID, manualEmailConfirmation: process.env.SBX044_ALIAS_EMAIL_CONFIRMATION,
    });
    const ledgerCases = cases.map((caseId) => ({ caseId, canary: canaries[caseId] }));
    allowedLedgerConfigured = true;
    await configureLedger("allowed", keys.allowedAdminKey, runId, ledgerCases);
    deniedLedgerConfigured = true;
    await configureLedger("denied", keys.deniedAdminKey, runId, ledgerCases);
    outsidePreflight.allowed = await runOutside("outside-pre-allowed");
    outsidePreflight.denied = await runOutside("outside-pre-denied");
    ledgers = {
      allowed: await ledgerSnapshot("allowed", keys.allowedAdminKey, runId),
      denied: await ledgerSnapshot("denied", keys.deniedAdminKey, runId),
    };
    if (
      !exactProbeAndEvent(
        outsidePreflight.allowed, runId, "outside-pre-allowed", canaries["outside-pre-allowed"],
        operationIds["outside-pre-allowed"], false, ledgers.allowed, CONTROLLER_TRUST_NAMES,
      ) ||
      !exactProbeAndEvent(
        outsidePreflight.denied, runId, "outside-pre-denied", canaries["outside-pre-denied"],
        operationIds["outside-pre-denied"], false, ledgers.denied, CONTROLLER_TRUST_NAMES,
      )
    ) throw new Error("outside keyed A/B preflight failed before sandbox creation");

    baseline = await runStage(
      "baseline", { allow: [SBX044_ALLOWED_HOST, SBX044_DENIED_HOST] },
      "baseline-allowed", "baseline-denied",
    );
    ledgers = {
      allowed: await ledgerSnapshot("allowed", keys.allowedAdminKey, runId),
      denied: await ledgerSnapshot("denied", keys.deniedAdminKey, runId),
    };
    if (
      !policyProofLocallyValid(baseline.before) || !policyProofLocallyValid(baseline.after) ||
      baseline.cleanup.errors.length !== 0 || !baseline.cleanup.stopped || !baseline.cleanup.deleted || baseline.cleanup.absenceChecks < 2 ||
      !exactProbeAndEvent(
        baseline.allowed, runId, "baseline-allowed", canaries["baseline-allowed"],
        operationIds["baseline-allowed"], false, ledgers.allowed, PLATFORM_TRUST_NAMES,
      ) ||
      !exactProbeAndEvent(
        baseline.denied, runId, "baseline-denied", canaries["baseline-denied"],
        operationIds["baseline-denied"], false, ledgers.denied, PLATFORM_TRUST_NAMES,
      )
    ) throw new Error("fresh exact A+B baseline controls failed");
    publicStage = await runStage(
      "public", { allow: [SBX044_WILDCARD_PATTERN] },
      "public-allowed-pre", "public-denied", "public-allowed-post",
    );
    ledgers = {
      allowed: await ledgerSnapshot("allowed", keys.allowedAdminKey, runId),
      denied: await ledgerSnapshot("denied", keys.deniedAdminKey, runId),
    };
    if (
      !publicStage.allowedAfter || !policyProofLocallyValid(publicStage.before) || !policyProofLocallyValid(publicStage.after) ||
      publicStage.cleanup.errors.length !== 0 || !publicStage.cleanup.stopped || !publicStage.cleanup.deleted ||
      publicStage.cleanup.absenceChecks < 2 || publicStage.sessionId === baseline.sessionId ||
      !exactProbeAndEvent(
        publicStage.allowed, runId, "public-allowed-pre", canaries["public-allowed-pre"],
        operationIds["public-allowed-pre"], false, ledgers.allowed, PLATFORM_TRUST_NAMES,
      ) ||
      !exactProbeAndEvent(
        publicStage.allowedAfter, runId, "public-allowed-post", canaries["public-allowed-post"],
        operationIds["public-allowed-post"], false, ledgers.allowed, PLATFORM_TRUST_NAMES,
      )
    ) throw new Error("wildcard-stage A controls or lifecycle proof failed");
    const publicProbeExact = exactProbeAndEvent(
      publicStage.denied, runId, "public-denied", canaries["public-denied"],
      operationIds["public-denied"], false, ledgers.denied, PLATFORM_TRUST_NAMES,
    );
    if (publicProbeExact) {
      const secretPolicy: NetworkPolicy = {
        allow: {
          [SBX044_WILDCARD_PATTERN]: [{ transform: [{ headers: { [SBX044_TRANSFORM_HEADER]: brokeredSecret } }] }],
        },
      };
      secretStage = await runStage("secret", secretPolicy, "secret-allowed", "secret-denied");
    }
    outsidePostflight.allowed = await runOutside("outside-post-allowed");
    outsidePostflight.denied = await runOutside("outside-post-denied");
    ledgers = {
      allowed: await ledgerSnapshot("allowed", keys.allowedAdminKey, runId),
      denied: await ledgerSnapshot("denied", keys.deniedAdminKey, runId),
    };
  } catch (error) {
    executionError = safeError(error, secrets);
    try {
      if (allowedLedgerConfigured) ledgers.allowed = await ledgerSnapshot("allowed", keys.allowedAdminKey, runId);
      if (deniedLedgerConfigured) ledgers.denied = await ledgerSnapshot("denied", keys.deniedAdminKey, runId);
    } catch (snapshotError) {
      executionError += `; ledger snapshot: ${safeError(snapshotError, secrets)}`;
    }
  } finally {
    for (const [role, configured, adminKey] of [
      ["allowed", allowedLedgerConfigured, keys.allowedAdminKey],
      ["denied", deniedLedgerConfigured, keys.deniedAdminKey],
    ] as const) {
      if (!configured) continue;
      try {
        const deletion = await adminRequest(role, adminKey, runId, { method: "DELETE" });
        const snapshot = await ledgerSnapshot(role, adminKey, runId);
        const deleted = deletion.ok;
        const absent = !snapshot.configured && snapshot.events.length === 0;
        if (role === "allowed") { ledgerCleanup.allowedDeleted = deleted; ledgerCleanup.allowedAbsent = absent; }
        else { ledgerCleanup.deniedDeleted = deleted; ledgerCleanup.deniedAbsent = absent; }
        if (!deleted || !absent) ledgerCleanup.errors.push(`${role} ledger cleanup failed`);
      } catch (error) {
        ledgerCleanup.errors.push(`${role} ledger cleanup: ${safeError(error, secrets)}`);
      }
    }
    if (lock) {
      try { await lock.close(); await unlink(lockPath); }
      catch (error) { ledgerCleanup.errors.push(`live lock cleanup: ${safeError(error, secrets)}`); }
    }
  }

  const baselineEvidence: Sbx044AssessmentInput["baseline"] = baseline ?? {
    allowed: emptyProbe(runId, "baseline-allowed", canaries["baseline-allowed"]),
    denied: emptyProbe(runId, "baseline-denied", canaries["baseline-denied"]),
    before: {
      kind: "baseline", stage: "before", initialSessionId: "missing", activeSessionId: "missing", independentSessionId: "missing",
      activeSandboxPolicy: undefined, activeSessionPolicy: undefined, independentSandboxPolicy: undefined,
      independentSessionPolicy: undefined, rawSecretPresentInReadbacks: false, platformRedactionMarkerPresent: false,
    },
    after: {
      kind: "baseline", stage: "after", initialSessionId: "missing", activeSessionId: "missing", independentSessionId: "missing",
      activeSandboxPolicy: undefined, activeSessionPolicy: undefined, independentSandboxPolicy: undefined,
      independentSessionPolicy: undefined, rawSecretPresentInReadbacks: false, platformRedactionMarkerPresent: false,
    },
    cleanup: { stopped: false, deleted: false, absenceChecks: 0, errors: ["stage missing"] }, sessionId: "missing",
  };
  const publicEvidence: Sbx044AssessmentInput["publicStage"] = publicStage && publicStage.allowedAfter ? {
    ...publicStage, allowedAfter: publicStage.allowedAfter,
  } : {
    ...baselineEvidence,
    allowed: emptyProbe(runId, "public-allowed-pre", canaries["public-allowed-pre"]),
    denied: emptyProbe(runId, "public-denied", canaries["public-denied"]),
    allowedAfter: emptyProbe(runId, "public-allowed-post", canaries["public-allowed-post"]),
    before: { ...baselineEvidence.before, kind: "public", stage: "before" },
    after: { ...baselineEvidence.after, kind: "public", stage: "after" },
  };
  const assessmentInput: Sbx044AssessmentInput = {
    ...(executionError ? { executionError } : {}),
    expectedRunId: runId, expectedCanaries: canaries, expectedOperationIds: operationIds,
    expectedControllerTrustEnvironmentNames: CONTROLLER_TRUST_NAMES,
    expectedSandboxTrustEnvironmentNames: PLATFORM_TRUST_NAMES,
    outsidePreflight, outsidePostflight, baseline: baselineEvidence, publicStage: publicEvidence,
    ...(secretStage ? { secretStage } : {}), ledgers, ledgerCleanup,
  };
  const assessment = assessSbx044(assessmentInput);
  const sandboxCleanupPassed = stageLifecycles.every((stage) =>
    stage.cleanup.stopped && stage.cleanup.deleted && stage.cleanup.absenceChecks >= 2 && stage.cleanup.errors.length === 0
  );
  const workerCleanupPassed = (!allowedLedgerConfigured || (ledgerCleanup.allowedDeleted && ledgerCleanup.allowedAbsent)) &&
    (!deniedLedgerConfigured || (ledgerCleanup.deniedDeleted && ledgerCleanup.deniedAbsent)) &&
    ledgerCleanup.errors.length === 0;
  const cleanupPassed = sandboxCleanupPassed && workerCleanupPassed;
  const evidence = {
    schemaVersion: 1,
    visibility: "private",
    testId: SBX044_TEST_ID,
    refinedHypothesis: "SBX-005 wildcard label-boundary crossing",
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    runtime: { sandboxSdk: "@vercel/sandbox@3.0.0", controllerNode: process.version },
    assessment,
    assessmentInput,
    account: { aliasEmail: ALIAS_EMAIL, teamId: TEAM_ID, projectId: PROJECT_ID },
    topology: {
      wildcardPattern: SBX044_WILDCARD_PATTERN,
      allowedOrigin: ALLOWED_ORIGIN,
      deniedOrigin: DENIED_ORIGIN,
      distinctWorkerDeploymentsRequired: true,
    },
    expectedCanaries: Object.fromEntries(Object.entries(canaries).map(([caseId, canary]) => [caseId, sha256(canary)])),
    expectedOperationIds: operationIds,
    outsidePreflight,
    stages: { baseline: baselineEvidence, public: publicEvidence, ...(secretStage ? { secret: secretStage } : {}) },
    outsidePostflight,
    ledgers,
    ledgerCleanup,
    stageLifecycles,
    cleanupPassed,
    commands,
    bounds: {
      sequential: true, minimumInterRequestMs: INTER_REQUEST_MS, retries: 0, redirects: 0,
      maximumSandboxRequests: secretStage ? 7 : 5,
    },
    retention: {
      rawActionKeys: false, rawAdminKeys: false, rawBrokeredSecret: false,
      brokeredSecretDigest: false, rawGuestOutput: false, rawResponseBodies: false,
      necessaryKeyedOperationIdsOnly: true,
    },
    ...(executionError ? { executionError } : {}),
  };
  const serialized = `${JSON.stringify(evidence, null, 2)}\n`;
  if (secrets.some((secret) => secret && serialized.includes(secret))) {
    throw new Error("refusing to persist evidence containing controller-only material");
  }
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const artifactPath = resolve(artifactsDirectory, `SBX-044-${runId}-private.json`);
  await writeFile(artifactPath, serialized, { encoding: "utf8", mode: 0o600, flag: "wx" });
  process.stdout.write(`${JSON.stringify({
    testId: SBX044_TEST_ID, refinedHypothesis: "SBX-005", runId,
    verdict: assessment.verdict, severity: assessment.severity, summary: assessment.summary,
    cleanupPassed, artifactPath,
  }, null, 2)}\n`);
  process.exitCode = assessment.verdict === "pass" ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
