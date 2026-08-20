import "dotenv/config";

import { execFile as execFileCallback } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Resolver } from "node:dns/promises";
import { readFile } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import { APIError, Sandbox, type NetworkPolicy } from "@vercel/sandbox";
import { verifyEligibleAliasToken } from "../eligible-alias-identity.js";
import {
  SBX036_PUBLIC_CASES,
  SBX036_SECRET_CASES,
  SBX036_TEST_ID,
  assessSbx036Public,
  assessSbx036Secret,
  deriveSbx036PublicOperationId,
  deriveSbx036SecretCommitment,
  deriveSbx036SecretOperationId,
  exactSbx036CoalescedSend,
  exactSbx036PolicyReadback,
  exactSbx036RawReceipt,
  exactSbx036RawSent,
  exactSbx036Receipt,
  exactSbx036TlsSuccess,
  type Sbx036HttpsControlEvidence,
  type Sbx036PolicyReadback,
  type Sbx036ProbeEvidence,
  type Sbx036ReceiverStatus,
  type Sbx036RetentionEvidence,
} from "./verdict.js";
import {
  SBX036_ARTIFACTS_DIRECTORY,
  SBX036_SANDBOX_TIMEOUT_MS,
  SBX036_UUID,
  acquireSbx036RecoveryState,
  acquireSbx036State,
  cleanupSbx036Exact,
  createSbx036Journal,
  exactSbx036SandboxProvenance,
  exactSbx036ZeroExternalStateJournal,
  persistSbx036Journal,
  readSbx036Journal,
  releaseSbx036State,
  resumeSbx036InterruptedFinalization,
  settleSbx036ZeroExternalStateLock,
  sbx036ArtifactPath,
  sbx036RecoveryArtifactPath,
  writeSbx036PrivateArtifact,
  type Sbx036CleanupDependencies,
  type Sbx036HeldState,
  type Sbx036RecoveryJournal,
  type Sbx036SandboxView,
  type Sbx036StageRole,
} from "./safety.js";

const execFile = promisify(execFileCallback);
const aliasEmail = "swve@wearehackerone.com";
const eligibleTeamId = "team_n98ERpVwV7HqmWRudAyK8sXQ";
const eligibleProjectId = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
const allowedHttpsOrigin = "https://vsc-h3-action-swve.cyrus-206.workers.dev";
const scopeConfirmation = "I_CONTROL_DISTINCT_HTTPS_ALLOW_AND_DIRECT_POSTGRES_DENIED_ENDPOINTS_AND_AUTHORIZE_BOUNDED_PRETLS_TESTING";
const remoteProbePath = "/tmp/sbx-036/postgres-pre-tls-coalescing-probe.py";
const remoteHealthPath = "/tmp/sbx-036/public-health-control.mjs";
const remoteSecretPath = "/tmp/sbx-036/operator-secret";
const controllerTimeoutMs = 30_000;
const interProbeDelayMs = 300;
const guestOutputLimit = 16_384;

interface Credentials {
  token: string;
  teamId: string;
  projectId: string;
}

interface Topology {
  allowedHostname: string;
  allowedIPv4: string;
  allowedAddresses: string[];
  allowedPort: 443;
  deniedHostname: string;
  deniedIPv4: string;
  deniedAddresses: string[];
  deniedPort: number;
  adminOrigin: URL;
  adminKey: string;
  configurationEpoch: string;
}

interface CommandEvidence {
  source: "controller-preflight" | "sandbox";
  commandId?: string;
  exitCode: number;
  stdoutBytes: number;
  stderrBytes: number;
  rawOutputRetained: false;
}

interface CaseEvidence {
  caseId: string;
  configurationSha256: string;
  command: CommandEvidence;
  result: Sbx036ProbeEvidence;
}

interface CleanupEvidence {
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  absenceChecks: number;
  prefixListAbsent: boolean;
  receiverDeleteAttempted: boolean;
  receiverDeleted: boolean;
  receiverAbsenceChecks: number;
  cleanupIndeterminate: boolean;
  errors: string[];
}

interface StageRuntime {
  role: Sbx036StageRole;
  sandbox?: Sandbox;
  sandboxName: string;
  sessionId?: string;
  cleanup: CleanupEvidence;
}

const retention = (): Sbx036RetentionEvidence => ({
  rawOperatorSecret: false,
  rawGuestConfiguration: false,
  rawCommandStdout: false,
  rawCommandStderr: false,
  rawPreTlsPayload: false,
  rawTlsBody: false,
  rawSecretInArtifact: false,
});

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function safeError(error: unknown, secrets: readonly string[]): string {
  let value = error instanceof Error ? error.message : String(error);
  for (const secret of secrets) if (secret) value = value.split(secret).join("[REDACTED]");
  return value.replace(/[\0\r\n]/gu, " ").slice(0, 1_000);
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function signal(timeoutMs = controllerTimeoutMs): AbortSignal {
  return AbortSignal.timeout(timeoutMs);
}

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("expected an object");
  return value as Record<string, unknown>;
}

function explicitCredentials(environment: NodeJS.ProcessEnv): Credentials {
  const token = required(environment, "VERCEL_TOKEN");
  const teamId = required(environment, "VERCEL_TEAM_ID");
  const projectId = required(environment, "VERCEL_PROJECT_ID");
  if (teamId !== eligibleTeamId || projectId !== eligibleProjectId) {
    throw new Error("SBX-036 must use the verified HackerOne-alias team and project");
  }
  return { token, teamId, projectId };
}

function validPort(raw: string | undefined): number {
  const port = Number(raw ?? "5432");
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error("SBX036_DENIED_PORT is invalid");
  return port;
}

function canonicalHostname(value: string, field: string): string {
  const pattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
  if (value !== value.toLowerCase() || !pattern.test(value) || isIP(value) !== 0) {
    throw new Error(`${field} must be a canonical lowercase DNS hostname`);
  }
  return value;
}

function publicIPv4(value: string): boolean {
  if (isIP(value) !== 4 || value.split(".").some((part) => !/^(?:0|[1-9][0-9]{0,2})$/u.test(part))) return false;
  const [a = -1, b = -1] = value.split(".").map(Number);
  return a > 0 && a < 224 && a !== 10 && a !== 127 && !(a === 172 && b >= 16 && b <= 31) &&
    !(a === 192 && b === 168) && !(a === 169 && b === 254) && !(a === 100 && b >= 64 && b <= 127);
}

async function resolve4(hostname: string): Promise<string[]> {
  const resolver = new Resolver();
  const deadline = setTimeout(() => resolver.cancel(), 10_000);
  try {
    const answers = await resolver.resolve4(hostname);
    return [...new Set(answers.filter(publicIPv4))].sort();
  } finally {
    clearTimeout(deadline);
  }
}

async function topology(environment: NodeJS.ProcessEnv): Promise<Topology> {
  if (environment.SBX036_SCOPE_CONFIRMATION !== scopeConfirmation) {
    throw new Error(`SBX036_SCOPE_CONFIRMATION must equal ${scopeConfirmation}`);
  }
  const allowed = new URL(required(environment, "SBX036_ALLOWED_HTTPS_ORIGIN"));
  if (allowed.origin !== allowedHttpsOrigin || allowed.pathname !== "/" || allowed.search || allowed.hash) {
    throw new Error(`SBX036_ALLOWED_HTTPS_ORIGIN must equal ${allowedHttpsOrigin}`);
  }
  const deniedHostname = canonicalHostname(required(environment, "SBX036_DENIED_HOSTNAME"), "SBX036_DENIED_HOSTNAME");
  const deniedIPv4 = required(environment, "SBX036_DENIED_IPV4");
  if (!publicIPv4(deniedIPv4)) throw new Error("SBX036_DENIED_IPV4 must be canonical public IPv4");
  const adminOrigin = new URL(required(environment, "SBX036_ADMIN_ORIGIN"));
  if (adminOrigin.protocol !== "http:" || adminOrigin.hostname !== "127.0.0.1" || adminOrigin.pathname !== "/" ||
    adminOrigin.username || adminOrigin.password || adminOrigin.search || adminOrigin.hash) {
    throw new Error("SBX036_ADMIN_ORIGIN must be an exact loopback HTTP origin reached directly or through an SSH port-forward");
  }
  const [allowedAddresses, deniedAddresses] = await Promise.all([resolve4(allowed.hostname), resolve4(deniedHostname)]);
  if (allowedAddresses.length === 0 || deniedAddresses.length === 0 || !deniedAddresses.includes(deniedIPv4)) {
    throw new Error("owned endpoint DNS did not resolve to the pinned public addresses");
  }
  if (allowedAddresses.some((address) => deniedAddresses.includes(address))) {
    throw new Error("raw pre-TLS proof requires disjoint allowed and denied resolved IPv4 sets");
  }
  const health = await adminRequest(adminOrigin, required(environment, "SBX036_ADMIN_KEY"), "/healthz", "GET");
  const listeners = object(health.listeners);
  const denied = object(listeners.denied);
  const configurationEpoch = typeof health.configurationEpoch === "string" ? health.configurationEpoch : "";
  if (health.ok !== true || health.testId !== SBX036_TEST_ID || denied.hostname !== deniedHostname ||
    denied.ipv4 !== deniedIPv4 || denied.port !== validPort(environment.SBX036_DENIED_PORT) ||
    !/^[0-9a-f-]{36}$/u.test(configurationEpoch)) {
    throw new Error("receiver health did not bind the exact denied listener and configuration epoch");
  }
  return {
    allowedHostname: allowed.hostname,
    allowedIPv4: allowedAddresses[0]!,
    allowedAddresses,
    allowedPort: 443,
    deniedHostname,
    deniedIPv4,
    deniedAddresses,
    deniedPort: validPort(environment.SBX036_DENIED_PORT),
    adminOrigin,
    adminKey: required(environment, "SBX036_ADMIN_KEY"),
    configurationEpoch,
  };
}

async function adminRequest(
  origin: URL,
  key: string,
  path: string,
  method: "GET" | "POST" | "DELETE",
  body?: unknown,
): Promise<Record<string, unknown>> {
  const response = await fetch(new URL(path, origin), {
    method,
    headers: {
      Authorization: `Bearer ${key}`,
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    redirect: "error",
    signal: signal(10_000),
  });
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > 64 * 1024) throw new Error("receiver admin response exceeded its bound");
  const parsed = object(JSON.parse(bytes.toString("utf8")));
  if (!response.ok) throw new Error(`receiver admin ${method} ${path} returned ${response.status}`);
  return parsed;
}

function exactKeys(value: object, requiredKeys: readonly string[], optionalKeys: readonly string[] = []): boolean {
  const actual = Object.keys(value);
  const permitted = new Set([...requiredKeys, ...optionalKeys]);
  return requiredKeys.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    actual.every((key) => permitted.has(key)) &&
    actual.length === requiredKeys.length + optionalKeys.filter((key) =>
      Object.prototype.hasOwnProperty.call(value, key)).length;
}

function exactReceiptShape(value: unknown): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value) || !exactKeys(value, [
    "role", "channel", "runId", "caseId", "discriminatorKind", "exactSslRequest", "sslRequestLength",
    "sslRequestCode", "bytesAfterSslRequest", "observedBeforeServerResponse",
    "serverResponseSentBeforeObservation", "serverResponseSentAfterObservation", "operationId",
    "rawPayloadStored", "payloadDigestStored", "observedAt", "connectionId", "sourceAddress",
    "sourcePort", "listenerHostname", "listenerIPv4", "listenerPort", "configurationEpoch",
    "withinConfiguredWindow",
  ])) return false;
  const receipt = value as Record<string, unknown>;
  return (receipt.role === "allowed" || receipt.role === "denied") &&
    (receipt.channel === "tls-startup" || receipt.channel === "pre-tls-coalesced" ||
      receipt.channel === "raw-control") &&
    typeof receipt.runId === "string" && SBX036_UUID.test(receipt.runId) &&
    typeof receipt.caseId === "string" && receipt.caseId.length > 0 && receipt.caseId.length <= 128 &&
    (receipt.discriminatorKind === "public" || receipt.discriminatorKind === "secret") &&
    typeof receipt.exactSslRequest === "boolean" && Number.isInteger(receipt.sslRequestLength) &&
    Number.isInteger(receipt.sslRequestCode) && Number.isInteger(receipt.bytesAfterSslRequest) &&
    typeof receipt.observedBeforeServerResponse === "boolean" &&
    typeof receipt.serverResponseSentBeforeObservation === "boolean" &&
    typeof receipt.serverResponseSentAfterObservation === "boolean" &&
    typeof receipt.operationId === "string" && receipt.operationId.length <= 128 &&
    receipt.rawPayloadStored === false && receipt.payloadDigestStored === false &&
    typeof receipt.observedAt === "string" && Number.isFinite(Date.parse(receipt.observedAt)) &&
    typeof receipt.connectionId === "string" && receipt.connectionId.length <= 256 &&
    typeof receipt.sourceAddress === "string" && receipt.sourceAddress.length <= 256 &&
    Number.isInteger(receipt.sourcePort) && typeof receipt.listenerHostname === "string" &&
    receipt.listenerHostname.length <= 253 && typeof receipt.listenerIPv4 === "string" &&
    Number.isInteger(receipt.listenerPort) && typeof receipt.configurationEpoch === "string" &&
    SBX036_UUID.test(receipt.configurationEpoch) && receipt.withinConfiguredWindow === true;
}

export function parseSbx036ReceiverStatus(value: unknown): Sbx036ReceiverStatus {
  if (value === null || typeof value !== "object" || Array.isArray(value) || !exactKeys(value, [
    "configured", "receipts", "secretRegistered", "rawPayloadStored", "payloadDigestStored",
  ], ["phase"])) throw new Error("SBX-036 receiver status fields were not exact");
  const status = value as Record<string, unknown>;
  if (typeof status.configured !== "boolean" || !Array.isArray(status.receipts) || status.receipts.length > 32 ||
      !status.receipts.every(exactReceiptShape) || typeof status.secretRegistered !== "boolean" ||
      status.rawPayloadStored !== false || status.payloadDigestStored !== false ||
      !(status.phase === undefined || status.phase === "public" || status.phase === "secret") ||
      (status.configured !== (status.phase !== undefined)) || (!status.configured && status.receipts.length !== 0) ||
      (!status.configured && status.secretRegistered)) {
    throw new Error("SBX-036 receiver status was invalid");
  }
  return status as unknown as Sbx036ReceiverStatus;
}

export interface Sbx036OutsidePreCreateGateInput {
  runId: string;
  deniedHostname: string;
  deniedIPv4: string;
  deniedPort: number;
  expectedConfigurationEpoch: string;
  expectedOperations: Record<string, string>;
  outsideDeniedTlsPreflight: Sbx036ProbeEvidence;
  outsideDeniedCoalescedPreflight: Sbx036ProbeEvidence;
  outsideDeniedRawNegative: Sbx036ProbeEvidence;
  receiver: Sbx036ReceiverStatus;
}

export function exactSbx036OutsidePreCreateGate(input: Sbx036OutsidePreCreateGateInput): boolean {
  const cases = SBX036_PUBLIC_CASES;
  const receiver = input.receiver;
  const expectedCaseIds = new Set<string>([
    cases.outsideDeniedTlsPreflight,
    cases.outsideDeniedCoalescedPreflight,
    cases.outsideDeniedRawNegative,
  ]);
  const connectionIds = receiver.receipts.map((receipt) => receipt.connectionId);
  if (!SBX036_UUID.test(input.runId) || !SBX036_UUID.test(input.expectedConfigurationEpoch) ||
      receiver.configured !== true || receiver.phase !== "public" || receiver.secretRegistered !== false ||
      receiver.rawPayloadStored !== false || receiver.payloadDigestStored !== false ||
      receiver.receipts.length !== 3 || new Set(connectionIds).size !== 3 ||
      receiver.receipts.some((receipt) => !expectedCaseIds.has(receipt.caseId))) return false;
  const base = {
    runId: input.runId,
    hostname: input.deniedHostname,
    ipv4: input.deniedIPv4,
    port: input.deniedPort,
  };
  return exactSbx036TlsSuccess(input.outsideDeniedTlsPreflight, {
    ...base,
    caseId: cases.outsideDeniedTlsPreflight,
    role: "denied",
    operationId: input.expectedOperations[cases.outsideDeniedTlsPreflight] ?? "",
  }) && exactSbx036Receipt(receiver, {
    phase: "public", channel: "tls-startup", ...base,
    caseId: cases.outsideDeniedTlsPreflight, kind: "public", role: "denied",
    operationId: input.expectedOperations[cases.outsideDeniedTlsPreflight] ?? "",
    beforeServerResponse: false, listenerHostname: input.deniedHostname,
    listenerIPv4: input.deniedIPv4, listenerPort: input.deniedPort,
    configurationEpoch: input.expectedConfigurationEpoch,
  }) && exactSbx036CoalescedSend(input.outsideDeniedCoalescedPreflight, {
    mode: "coalesced-public", ...base, caseId: cases.outsideDeniedCoalescedPreflight,
  }) && exactSbx036Receipt(receiver, {
    phase: "public", channel: "pre-tls-coalesced", ...base,
    caseId: cases.outsideDeniedCoalescedPreflight, kind: "public", role: "denied",
    operationId: input.expectedOperations[cases.outsideDeniedCoalescedPreflight] ?? "",
    beforeServerResponse: "either", listenerHostname: input.deniedHostname,
    listenerIPv4: input.deniedIPv4, listenerPort: input.deniedPort,
    configurationEpoch: input.expectedConfigurationEpoch,
  }) && exactSbx036RawSent(input.outsideDeniedRawNegative, {
    ...base, caseId: cases.outsideDeniedRawNegative,
  }) && exactSbx036RawReceipt(receiver, {
    phase: "public", ...base, caseId: cases.outsideDeniedRawNegative,
    operationId: input.expectedOperations[cases.outsideDeniedRawNegative] ?? "",
    listenerHostname: input.deniedHostname, listenerIPv4: input.deniedIPv4,
    listenerPort: input.deniedPort, configurationEpoch: input.expectedConfigurationEpoch,
  });
}

export async function runSbx036PreCreateGate(input: {
  readReceiver(): Promise<unknown>;
  gate: Omit<Sbx036OutsidePreCreateGateInput, "receiver">;
  create(): Promise<void>;
}): Promise<Sbx036ReceiverStatus> {
  const receiver = parseSbx036ReceiverStatus(await input.readReceiver());
  if (!exactSbx036OutsidePreCreateGate({ ...input.gate, receiver })) {
    throw new Error("SBX-036 outside pre-create receiver gate failed closed");
  }
  await input.create();
  return receiver;
}

function probeConfiguration(input: {
  mode: "postgres-tls" | "coalesced-public" | "coalesced-secret" | "raw-public";
  runId: string;
  caseId: string;
  endpointRole: "allowed" | "denied";
  hostname: string;
  ipv4: string;
  port: number;
  publicCanary?: string;
  expectedOperationId?: string;
}): Record<string, unknown> {
  return {
    scopeConfirmation,
    mode: input.mode,
    runId: input.runId,
    testId: SBX036_TEST_ID,
    caseId: input.caseId,
    endpointRole: input.endpointRole,
    endpointHostname: input.hostname,
    pinnedIPv4: input.ipv4,
    pinnedPort: input.port,
    ...(input.publicCanary ? { publicCanary: input.publicCanary } : {}),
    ...(input.expectedOperationId ? { expectedOperationId: input.expectedOperationId } : {}),
    timeoutMs: 3_000,
    maxResponseBytes: 1_024,
  };
}

export function sanitizeProbe(value: unknown): Sbx036ProbeEvidence {
  const input = object(value);
  if (!exactKeys(input, [
    "ok", "phase", "mode", "runId", "testId", "caseId", "endpointRole", "endpointHostname",
    "pinnedIPv4", "pinnedPort", "attemptCount", "retryCount", "timeout", "tcpConnected",
    "sslRequestExact", "sslRequestLength", "sslRequestCode", "sslRequestHex", "responseStarted",
    "tlsEstablished", "certificateVerified", "hostnameVerified", "coalescedSingleWrite",
    "explicitSocketWriteCount", "bytesAfterSslRequest", "payloadRetained", "payloadDigestRetained",
    "rawConfigurationRetained",
  ], ["serverSslResponse", "tlsVersion", "operationId", "discriminatorKind", "errorCode", "durationMs"]) ||
      typeof input.ok !== "boolean" || typeof input.phase !== "string" || input.phase.length > 64 ||
      !["postgres-tls", "coalesced-tls", "coalesced-public", "coalesced-secret", "raw-public"].includes(
        String(input.mode),
      ) || typeof input.runId !== "string" || !SBX036_UUID.test(input.runId) ||
      input.testId !== SBX036_TEST_ID || typeof input.caseId !== "string" || input.caseId.length > 128 ||
      (input.endpointRole !== "allowed" && input.endpointRole !== "denied") ||
      typeof input.endpointHostname !== "string" || input.endpointHostname.length > 253 ||
      typeof input.pinnedIPv4 !== "string" || !Number.isInteger(input.pinnedPort) ||
      !Number.isInteger(input.attemptCount) || !Number.isInteger(input.retryCount) ||
      typeof input.timeout !== "boolean" || typeof input.tcpConnected !== "boolean" ||
      typeof input.sslRequestExact !== "boolean" || !Number.isInteger(input.sslRequestLength) ||
      !Number.isInteger(input.sslRequestCode) || typeof input.sslRequestHex !== "string" ||
      input.sslRequestHex.length > 32 || typeof input.responseStarted !== "boolean" ||
      typeof input.tlsEstablished !== "boolean" || typeof input.certificateVerified !== "boolean" ||
      typeof input.hostnameVerified !== "boolean" || typeof input.coalescedSingleWrite !== "boolean" ||
      !Number.isInteger(input.explicitSocketWriteCount) || !Number.isInteger(input.bytesAfterSslRequest) ||
      input.payloadRetained !== false || input.payloadDigestRetained !== false ||
      input.rawConfigurationRetained !== false ||
      !(input.serverSslResponse === undefined || (typeof input.serverSslResponse === "string" &&
        input.serverSslResponse.length <= 8)) ||
      !(input.tlsVersion === undefined || (typeof input.tlsVersion === "string" && input.tlsVersion.length <= 32)) ||
      !(input.operationId === undefined || (typeof input.operationId === "string" && input.operationId.length <= 128)) ||
      !(input.discriminatorKind === undefined || input.discriminatorKind === "public" ||
        input.discriminatorKind === "secret") ||
      !(input.errorCode === undefined || (typeof input.errorCode === "string" && input.errorCode.length <= 128))) {
    throw new Error("SBX-036 probe evidence was not one exact closed secret-free object");
  }
  if (!(input.durationMs === undefined || (typeof input.durationMs === "number" &&
      Number.isFinite(input.durationMs) && input.durationMs >= 0 && input.durationMs <= 30_000))) {
    throw new Error("SBX-036 probe duration was not bounded");
  }
  const { durationMs: _durationMs, ...retained } = input;
  return retained as unknown as Sbx036ProbeEvidence;
}

export function sanitizeHealth(value: unknown): Sbx036HttpsControlEvidence {
  const input = object(value);
  if (!exactKeys(input, [
    "schemaVersion", "ok", "runId", "phase", "origin", "path", "timeoutMs", "maximumResponseBytes",
    "responseBodiesRetained", "receivedResponse", "timedOut",
  ], ["statusCode", "durationMs"]) || input.schemaVersion !== 1 || typeof input.ok !== "boolean" ||
      typeof input.runId !== "string" || !SBX036_UUID.test(input.runId) || input.phase !== "allow-control" ||
      typeof input.origin !== "string" || input.origin.length > 512 || input.path !== "/healthz" ||
      !Number.isInteger(input.timeoutMs) || !Number.isInteger(input.maximumResponseBytes) ||
      input.responseBodiesRetained !== false || typeof input.receivedResponse !== "boolean" ||
      typeof input.timedOut !== "boolean" ||
      !(input.statusCode === undefined || Number.isInteger(input.statusCode)) ||
      !(input.durationMs === undefined || (typeof input.durationMs === "number" &&
        Number.isFinite(input.durationMs) && input.durationMs >= 0))) {
    throw new Error("SBX-036 health evidence was not one exact closed body-free object");
  }
  return input as unknown as Sbx036HttpsControlEvidence;
}

class RateGate {
  #lastAt = 0;

  async beforeProbe(): Promise<void> {
    const wait = interProbeDelayMs - (Date.now() - this.#lastAt);
    if (wait > 0) await new Promise((resolveWait) => setTimeout(resolveWait, wait));
    this.#lastAt = Date.now();
  }
}

function commandOutput(stdout: string, stderr: string, secrets: readonly string[]): unknown {
  if (Buffer.byteLength(stdout) > guestOutputLimit || Buffer.byteLength(stderr) > guestOutputLimit) {
    throw new Error("probe output exceeded its bound");
  }
  if (secrets.some((secret) => secret && (stdout.includes(secret) || stderr.includes(secret)))) {
    throw new Error("probe output contained controller-only material");
  }
  return JSON.parse(stdout);
}

async function localProbe(
  sourcePath: string,
  configuration: Record<string, unknown>,
  gate: RateGate,
  secrets: readonly string[],
): Promise<CaseEvidence> {
  await gate.beforeProbe();
  const encoded = Buffer.from(JSON.stringify(configuration)).toString("base64url");
  const result = await execFile("python3", [sourcePath, encoded], { maxBuffer: guestOutputLimit });
  const parsed = commandOutput(result.stdout, result.stderr, secrets);
  return {
    caseId: String(configuration.caseId),
    configurationSha256: sha256(JSON.stringify(configuration)),
    command: {
      source: "controller-preflight",
      exitCode: 0,
      stdoutBytes: Buffer.byteLength(result.stdout),
      stderrBytes: Buffer.byteLength(result.stderr),
      rawOutputRetained: false,
    },
    result: sanitizeProbe(parsed),
  };
}

async function sandboxProbe(
  sandbox: Sandbox,
  configuration: Record<string, unknown>,
  gate: RateGate,
  secrets: readonly string[],
): Promise<CaseEvidence> {
  await gate.beforeProbe();
  const command = await sandbox.runCommand({
    cmd: "python3",
    args: [remoteProbePath, Buffer.from(JSON.stringify(configuration)).toString("base64url")],
    timeoutMs: 12_000,
  });
  const [stdout, stderr] = await Promise.all([command.stdout({ signal: signal() }), command.stderr({ signal: signal() })]);
  const parsed = commandOutput(stdout, stderr, secrets);
  return {
    caseId: String(configuration.caseId),
    configurationSha256: sha256(JSON.stringify(configuration)),
    command: {
      source: "sandbox",
      commandId: command.cmdId,
      exitCode: command.exitCode,
      stdoutBytes: Buffer.byteLength(stdout),
      stderrBytes: Buffer.byteLength(stderr),
      rawOutputRetained: false,
    },
    result: sanitizeProbe(parsed),
  };
}

async function sandboxHealth(
  sandbox: Sandbox,
  runId: string,
  gate: RateGate,
  secrets: readonly string[],
): Promise<{
  command: CommandEvidence;
  result: Sbx036HttpsControlEvidence;
}> {
  await gate.beforeProbe();
  const configuration = { runId, phase: "allow-control", timeoutMs: 3_000 };
  const command = await sandbox.runCommand({
    cmd: "node",
    args: [remoteHealthPath, Buffer.from(JSON.stringify(configuration)).toString("base64url")],
    timeoutMs: 10_000,
  });
  const [stdout, stderr] = await Promise.all([command.stdout({ signal: signal() }), command.stderr({ signal: signal() })]);
  return {
    command: {
      source: "sandbox",
      commandId: command.cmdId,
      exitCode: command.exitCode,
      stdoutBytes: Buffer.byteLength(stdout),
      stderrBytes: Buffer.byteLength(stderr),
      rawOutputRetained: false,
    },
    result: sanitizeHealth(commandOutput(stdout, stderr, secrets)),
  };
}

async function policyReadback(
  sandbox: Sandbox,
  sandboxName: string,
  sessionId: string,
  credentials: Credentials,
  expected: "allow-all" | { allowedHostname: string },
): Promise<Sbx036PolicyReadback> {
  const active = sandbox.currentSession();
  const independent = await Sandbox.get({ name: sandboxName, resume: false, signal: signal(), ...credentials });
  const independentSession = independent.currentSession();
  return exactSbx036PolicyReadback({
    initialSessionId: sessionId,
    activeSessionId: active.sessionId,
    independentSessionId: independentSession.sessionId,
    activeSandboxPolicy: sandbox.networkPolicy,
    activeSessionPolicy: active.networkPolicy,
    independentSandboxPolicy: independent.networkPolicy,
    independentSessionPolicy: independentSession.networkPolicy,
  }, expected);
}

async function cleanupStage(
  runtime: StageRuntime,
  topologyValue: Topology,
  credentials: Credentials,
  journal: Sbx036RecoveryJournal,
  held: Sbx036HeldState,
  secrets: readonly string[],
): Promise<void> {
  const sandboxView = (sandbox: Sandbox): Sbx036SandboxView => ({
    name: sandbox.name,
    persistent: sandbox.persistent,
    tags: sandbox.tags,
    currentSessionId: sandbox.currentSession().sessionId,
    status: sandbox.status,
    stop: async () => { await sandbox.stop({ signal: signal() }); },
    delete: async () => { await sandbox.delete({ signal: signal() }); },
    neutralizeSecret: async () => {
      await sandbox.writeFiles([{ path: remoteSecretPath, content: "SBX036_CLEARED", mode: 0o600 }], {
        signal: signal(),
      });
    },
  });
  const dependencies: Sbx036CleanupDependencies = {
    getSandbox: async (name) => sandboxView(await Sandbox.get({
      name, resume: false, signal: signal(), ...credentials,
    })),
    listSandboxes: async (namePrefix) => {
      const result = await Sandbox.list({ namePrefix, limit: 10, signal: signal(), ...credentials });
      return (await result.toArray()).map((item) => ({
        name: item.name,
        persistent: item.persistent,
        tags: item.tags,
        currentSessionId: item.currentSessionId,
      }));
    },
    isNotFound: (error) => error instanceof APIError && error.response.status === 404,
    deleteReceiver: async (runId) => {
      const result = await adminRequest(topologyValue.adminOrigin, topologyValue.adminKey,
        `/v1/sbx036/admin/runs/${runId}`, "DELETE");
      return result.deleted === true;
    },
    readReceiverConfigured: async (runId) => parseSbx036ReceiverStatus(await adminRequest(
      topologyValue.adminOrigin, topologyValue.adminKey, `/v1/sbx036/admin/runs/${runId}`, "GET",
    )).configured,
    persist: async (value) => persistSbx036Journal(held, value),
  };
  try {
    const result = await cleanupSbx036Exact({
      journal,
      sandboxes: runtime.sandbox ? { [runtime.role]: sandboxView(runtime.sandbox) } : {},
      dependencies,
    });
    const stageValue = journal.stages[runtime.role === "public" ? 0 : 1];
    const receiver = journal.receivers[runtime.role === "public" ? 0 : 1];
    runtime.cleanup = {
      stopAttempted: stageValue.createAttemptedAt === undefined || stageValue.stopAttempted,
      stopped: stageValue.createAttemptedAt === undefined || stageValue.stopped,
      deleteAttempted: stageValue.createAttemptedAt === undefined || stageValue.deleteAttempted,
      deleted: stageValue.createAttemptedAt === undefined || stageValue.deleted,
      absenceChecks: stageValue.createAttemptedAt === undefined ? 3 : stageValue.absenceChecks,
      prefixListAbsent: stageValue.createAttemptedAt === undefined || stageValue.prefixListAbsent,
      receiverDeleteAttempted: !receiver.configureAttempted || receiver.deleteAttempted,
      receiverDeleted: !receiver.configureAttempted || receiver.deleted,
      receiverAbsenceChecks: receiver.configureAttempted ? receiver.absenceChecks : 3,
      cleanupIndeterminate: !result.complete,
      errors: result.errors.map((error) => safeError(error, secrets)),
    };
  } catch (error) {
    runtime.cleanup.cleanupIndeterminate = true;
    runtime.cleanup.errors.push(`cleanup: ${safeError(error, secrets)}`);
  }
}

function cleanupPassed(value: CleanupEvidence): boolean {
  return value.stopAttempted && value.stopped && value.deleteAttempted && value.deleted &&
    value.absenceChecks >= 3 && value.prefixListAbsent && value.receiverDeleteAttempted &&
    value.receiverDeleted && value.receiverAbsenceChecks >= 3 && !value.cleanupIndeterminate &&
    value.errors.length === 0;
}

function emptyCleanup(): CleanupEvidence {
  return {
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    absenceChecks: 0,
    prefixListAbsent: false,
    receiverDeleteAttempted: false,
    receiverDeleted: false,
    receiverAbsenceChecks: 0,
    cleanupIndeterminate: false,
    errors: [],
  };
}

function canaries(caseIds: readonly string[]): Record<string, string> {
  return Object.fromEntries(caseIds.map((caseId) => [caseId, `pub_${randomBytes(18).toString("base64url")}`]));
}

function operations(key: string, runId: string, values: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(values).map(([caseId, canary]) => [
    caseId,
    deriveSbx036PublicOperationId(key, runId, caseId, canary),
  ]));
}

async function configureReceiver(
  topologyValue: Topology,
  role: Sbx036StageRole,
  publicCanaries: Record<string, string>,
  journal: Sbx036RecoveryJournal,
  held: Sbx036HeldState,
): Promise<void> {
  const receiver = journal.receivers[role === "public" ? 0 : 1];
  journal.completed = false;
  receiver.configureAttempted = true;
  await persistSbx036Journal(held, journal);
  const now = Date.now();
  const response = await adminRequest(
    topologyValue.adminOrigin,
    topologyValue.adminKey,
    `/v1/sbx036/admin/runs/${receiver.runId}`,
    "POST",
    {
      runId: receiver.runId,
      phase: role,
      testId: SBX036_TEST_ID,
      allowedHostname: topologyValue.allowedHostname,
      allowedIPv4: topologyValue.allowedIPv4,
      allowedPort: topologyValue.allowedPort,
      deniedHostname: topologyValue.deniedHostname,
      deniedIPv4: topologyValue.deniedIPv4,
      deniedPort: topologyValue.deniedPort,
      notBefore: new Date(now - 5_000).toISOString(),
      notAfter: new Date(now + 20 * 60_000).toISOString(),
      expectedPublicCanaries: publicCanaries,
    },
  );
  if (response.configured !== true || response.configurationEpoch !== topologyValue.configurationEpoch) {
    throw new Error("receiver registration did not return the exact configuration epoch");
  }
  receiver.configured = true;
  await persistSbx036Journal(held, journal);
}

async function createStageSandbox(
  runtime: StageRuntime,
  policy: NetworkPolicy,
  credentials: Credentials,
  probeSource: string,
  healthSource: string,
  journal: Sbx036RecoveryJournal,
  held: Sbx036HeldState,
): Promise<void> {
  const stageValue = journal.stages[runtime.role === "public" ? 0 : 1];
  if (runtime.sandboxName !== stageValue.sandboxName || stageValue.createAttemptedAt !== undefined) {
    throw new Error("SBX-036 refused a duplicate or mismatched create");
  }
  journal.completed = false;
  stageValue.createAttemptedAt = new Date().toISOString();
  await persistSbx036Journal(held, journal);
  const sandbox = await Sandbox.create({
    name: stageValue.sandboxName,
    persistent: false,
    timeout: SBX036_SANDBOX_TIMEOUT_MS,
    networkPolicy: policy,
    tags: stageValue.tags,
    signal: signal(45_000),
    ...credentials,
  });
  const view: Sbx036SandboxView = {
    name: sandbox.name,
    persistent: sandbox.persistent,
    tags: sandbox.tags,
    currentSessionId: sandbox.currentSession().sessionId,
    status: sandbox.status,
    stop: async () => { await sandbox.stop({ signal: signal() }); },
    delete: async () => { await sandbox.delete({ signal: signal() }); },
    neutralizeSecret: async () => { await sandbox.writeFiles([
      { path: remoteSecretPath, content: "SBX036_CLEARED", mode: 0o600 },
    ], { signal: signal() }); },
  };
  if (!exactSbx036SandboxProvenance(view, stageValue)) {
    throw new Error("SBX-036 create response failed exact name/tag/persistence/session provenance");
  }
  stageValue.sessionId = view.currentSessionId;
  stageValue.provenanceValidated = true;
  stageValue.createResponseSettledAt = new Date().toISOString();
  await persistSbx036Journal(held, journal);
  runtime.sandbox = sandbox;
  runtime.sessionId = view.currentSessionId;
  await sandbox.writeFiles([
    { path: remoteProbePath, content: probeSource, mode: 0o700 },
    { path: remoteHealthPath, content: healthSource, mode: 0o700 },
  ], { signal: signal() });
}

function recoveryRunId(argv: readonly string[]): string | undefined {
  if (argv.length === 2 && argv[0] === "--recover" && SBX036_UUID.test(argv[1]!)) return argv[1];
  if (argv.length === 0) return undefined;
  throw new Error("usage: tsx pocs/SBX-036/postgres-pre-tls-coalescing.ts [--recover <root UUIDv4>]");
}

export async function runSbx036Recovery(
  rootRunId: string,
  directory = SBX036_ARTIFACTS_DIRECTORY,
): Promise<void> {
  const recoveryAttemptId = randomUUID();
  const artifactPath = sbx036RecoveryArtifactPath(rootRunId, recoveryAttemptId, directory);
  const evidence: Record<string, unknown> = {
    schemaVersion: 1,
    testId: SBX036_TEST_ID,
    rootRunId,
    recoveryAttemptId,
    recoveryOnly: true,
    mode: "cleanup-only",
    startedAt: new Date().toISOString(),
    externalCreateRequests: 0,
    rawSecretsRetained: false,
    rawOperationsRetained: false,
  };
  let held: Sbx036HeldState | undefined;
  const forbidden: string[] = [];
  try {
    if (await resumeSbx036InterruptedFinalization(rootRunId, directory) ||
        await settleSbx036ZeroExternalStateLock(rootRunId, directory)) {
      evidence.outcome = "finalization-complete";
      evidence.cleanupComplete = true;
      evidence.externalCleanupRequests = 0;
    } else {
      held = await acquireSbx036RecoveryState(rootRunId, directory);
      const journal = await readSbx036Journal(rootRunId, directory);
      if (exactSbx036ZeroExternalStateJournal(journal)) {
        if (!journal.completed) {
          journal.completed = true;
          await persistSbx036Journal(held, journal);
        }
        await releaseSbx036State(held);
        held = undefined;
        evidence.outcome = "zero-external-state-cleanup-complete";
        evidence.cleanupComplete = true;
        evidence.zeroExternalState = true;
        evidence.externalCleanupRequests = 0;
      } else {
        const credentials = explicitCredentials(process.env);
        const secrets = [credentials.token, required(process.env, "SBX036_ADMIN_KEY")];
        forbidden.push(...secrets);
        await verifyEligibleAliasToken({
          token: credentials.token,
          expectedEmail: aliasEmail,
          expectedTeamId: eligibleTeamId,
          expectedProjectId: eligibleProjectId,
          manualEmailConfirmation: process.env.SBX036_ALIAS_EMAIL_CONFIRMATION,
        });
        const topo = await topology(process.env);
        const runtime: StageRuntime = {
          role: "public",
          sandboxName: journal.stages[0].sandboxName,
          cleanup: emptyCleanup(),
        };
        await cleanupStage(runtime, topo, credentials, journal, held, secrets);
        evidence.cleanup = runtime.cleanup;
        evidence.cleanupComplete = journal.completed;
        if (!journal.completed) {
          evidence.outcome = "cleanup-indeterminate";
          await held.liveLock.closeRetainingState();
          held = undefined;
        } else {
          await releaseSbx036State(held);
          held = undefined;
          evidence.outcome = "cleanup-complete";
        }
      }
    }
  } catch (error) {
    evidence.outcome = "cleanup-indeterminate";
    evidence.error = safeError(error, forbidden);
    if (held) await held.liveLock.closeRetainingState().catch(() => undefined);
  }
  evidence.completedAt = new Date().toISOString();
  await writeSbx036PrivateArtifact(artifactPath, evidence);
  process.stdout.write(`${JSON.stringify({ ...evidence, evidencePath: artifactPath }, null, 2)}\n`);
  if (evidence.outcome === "cleanup-indeterminate") process.exitCode = 2;
}

async function main(): Promise<void> {
  const requestedRecovery = recoveryRunId(process.argv.slice(2));
  if (requestedRecovery) {
    await runSbx036Recovery(requestedRecovery);
    return;
  }
  const journal = createSbx036Journal();
  const artifactPath = sbx036ArtifactPath(journal.rootRunId);
  const credentials = explicitCredentials(process.env);
  const secrets = [credentials.token, required(process.env, "SBX036_ADMIN_KEY")];
  const probeSourcePath = resolve("guest/postgres-pre-tls-coalescing-probe.py");
  const [probeSource, healthSource] = await Promise.all([
    readFile(probeSourcePath, "utf8"),
    readFile(resolve("guest/public-health-control.mjs"), "utf8"),
  ]);
  let held: Sbx036HeldState | undefined;
  let released = false;
  const evidence: Record<string, unknown> = {
    schemaVersion: 1,
    testId: SBX036_TEST_ID,
    rootRunId: journal.rootRunId,
    startedAt: new Date().toISOString(),
    liveRunExecuted: true,
    protocolValidityCaveat: "The raw discriminator suffix is intentionally hostile parser-smuggling, not a standards-valid PostgreSQL TLS flight.",
  };
  try {
    held = await acquireSbx036State(journal);
    await verifyEligibleAliasToken({
      token: credentials.token,
      expectedEmail: aliasEmail,
      expectedTeamId: eligibleTeamId,
      expectedProjectId: eligibleProjectId,
      manualEmailConfirmation: process.env.SBX036_ALIAS_EMAIL_CONFIRMATION,
    });
    const topo = await topology(process.env);
    evidence.topology = {
      allowedHostname: topo.allowedHostname,
      allowedAddresses: topo.allowedAddresses,
      allowedPort: topo.allowedPort,
      deniedHostname: topo.deniedHostname,
      deniedAddresses: topo.deniedAddresses,
      deniedPinnedIPv4: topo.deniedIPv4,
      deniedPort: topo.deniedPort,
      addressSetsDisjoint: topo.allowedAddresses.every((address) => !topo.deniedAddresses.includes(address)),
      configurationEpoch: topo.configurationEpoch,
    };

    const publicRunId = journal.stages[0].runId;
    const publicCases = Object.values(SBX036_PUBLIC_CASES);
    const publicCanaries = canaries(publicCases);
    const publicOperations = operations(topo.adminKey, publicRunId, publicCanaries);
    const publicGate = new RateGate();
    const publicRuntime: StageRuntime = {
      role: "public",
      sandboxName: journal.stages[0].sandboxName,
      cleanup: emptyCleanup(),
    };
    const publicRecords: CaseEvidence[] = [];
    let publicExecutionError: string | undefined;
    let publicSandboxId = "missing";
    let allowAllReadbackPassed = false;
    let restrictedReadback = exactSbx036PolicyReadback({
      initialSessionId: "", activeSessionId: "", independentSessionId: "",
      activeSandboxPolicy: undefined, activeSessionPolicy: undefined,
      independentSandboxPolicy: undefined, independentSessionPolicy: undefined,
    }, "allow-all");
    let postTargetReadback = restrictedReadback;
    let publicReceiver: Sbx036ReceiverStatus = {
      configured: false, receipts: [], secretRegistered: false, rawPayloadStored: false, payloadDigestStored: false,
    };
    let publicHealth: Sbx036HttpsControlEvidence | undefined;
    let outsideTls: CaseEvidence | undefined;
    let outsideCoalesced: CaseEvidence | undefined;
    let outsideRaw: CaseEvidence | undefined;
    let allowAllTls: CaseEvidence | undefined;
    let allowAllCoalesced: CaseEvidence | undefined;
    let deniedTls: CaseEvidence | undefined;
    let deniedRaw: CaseEvidence | undefined;
    let target: CaseEvidence | undefined;
    let deniedPost: CaseEvidence | undefined;

    try {
      await configureReceiver(topo, "public", publicCanaries, journal, held);
      const configFor = (
        caseId: string,
        mode: "postgres-tls" | "coalesced-public" | "raw-public",
      ): Record<string, unknown> => probeConfiguration({
        mode, runId: publicRunId, caseId, endpointRole: "denied",
        hostname: topo.deniedHostname, ipv4: topo.deniedIPv4, port: topo.deniedPort,
        publicCanary: publicCanaries[caseId]!,
        ...(mode === "postgres-tls" ? { expectedOperationId: publicOperations[caseId]! } : {}),
      });
      outsideTls = await localProbe(probeSourcePath,
        configFor(SBX036_PUBLIC_CASES.outsideDeniedTlsPreflight, "postgres-tls"), publicGate, secrets);
      outsideCoalesced = await localProbe(probeSourcePath,
        configFor(SBX036_PUBLIC_CASES.outsideDeniedCoalescedPreflight, "coalesced-public"), publicGate, secrets);
      outsideRaw = await localProbe(probeSourcePath,
        configFor(SBX036_PUBLIC_CASES.outsideDeniedRawNegative, "raw-public"), publicGate, secrets);
      publicRecords.push(outsideTls, outsideCoalesced, outsideRaw);

      let outsidePreCreateReceiver: Sbx036ReceiverStatus | undefined;
      outsidePreCreateReceiver = await runSbx036PreCreateGate({
        readReceiver: async () => adminRequest(
          topo.adminOrigin, topo.adminKey, `/v1/sbx036/admin/runs/${publicRunId}`, "GET",
        ),
        gate: {
          runId: publicRunId,
          deniedHostname: topo.deniedHostname,
          deniedIPv4: topo.deniedIPv4,
          deniedPort: topo.deniedPort,
          expectedConfigurationEpoch: topo.configurationEpoch,
          expectedOperations: publicOperations,
          outsideDeniedTlsPreflight: outsideTls.result,
          outsideDeniedCoalescedPreflight: outsideCoalesced.result,
          outsideDeniedRawNegative: outsideRaw.result,
        },
        create: async () => createStageSandbox(
          publicRuntime, "allow-all", credentials, probeSource, healthSource, journal, held!,
        ),
      });
      evidence.outsidePreCreateGate = {
        checked: true,
        passed: true,
        checkedAt: new Date().toISOString(),
        receiver: outsidePreCreateReceiver,
      };
      if (!publicRuntime.sandbox || !publicRuntime.sessionId) throw new Error("public sandbox creation lacked identity");
      publicSandboxId = publicRuntime.sessionId;
      const allowAllReadback = await policyReadback(
        publicRuntime.sandbox, publicRuntime.sandboxName, publicRuntime.sessionId, credentials, "allow-all",
      );
      allowAllReadbackPassed = allowAllReadback.passed;
      if (!allowAllReadbackPassed) throw new Error("allow-all lacked active and independent same-session readback");
      allowAllTls = await sandboxProbe(publicRuntime.sandbox,
        configFor(SBX036_PUBLIC_CASES.allowAllDeniedTlsControl, "postgres-tls"), publicGate, secrets);
      allowAllCoalesced = await sandboxProbe(publicRuntime.sandbox,
        configFor(SBX036_PUBLIC_CASES.allowAllCoalescedControl, "coalesced-public"), publicGate, secrets);
      publicRecords.push(allowAllTls, allowAllCoalesced);

      await publicRuntime.sandbox.update({ networkPolicy: { allow: [topo.allowedHostname] } }, { signal: signal() });
      restrictedReadback = await policyReadback(
        publicRuntime.sandbox, publicRuntime.sandboxName, publicRuntime.sessionId, credentials,
        { allowedHostname: topo.allowedHostname },
      );
      if (!restrictedReadback.passed) throw new Error("restricted allow[A] lacked exact same-session readback");
      const healthCapture = await sandboxHealth(publicRuntime.sandbox, publicRunId, publicGate, secrets);
      publicHealth = healthCapture.result;
      deniedTls = await sandboxProbe(publicRuntime.sandbox,
        configFor(SBX036_PUBLIC_CASES.deniedTlsNegative, "postgres-tls"), publicGate, secrets);
      deniedRaw = await sandboxProbe(publicRuntime.sandbox,
        configFor(SBX036_PUBLIC_CASES.deniedRawNegative, "raw-public"), publicGate, secrets);
      target = await sandboxProbe(publicRuntime.sandbox,
        configFor(SBX036_PUBLIC_CASES.deniedCoalescedTarget, "coalesced-public"), publicGate, secrets);
      postTargetReadback = await policyReadback(
        publicRuntime.sandbox, publicRuntime.sandboxName, publicRuntime.sessionId, credentials,
        { allowedHostname: topo.allowedHostname },
      );
      deniedPost = await sandboxProbe(publicRuntime.sandbox,
        configFor(SBX036_PUBLIC_CASES.deniedTlsPostNegative, "postgres-tls"), publicGate, secrets);
      publicRecords.push(deniedTls, deniedRaw, target, deniedPost);
      await new Promise((resolveWait) => setTimeout(resolveWait, 500));
      publicReceiver = parseSbx036ReceiverStatus(await adminRequest(
        topo.adminOrigin, topo.adminKey, `/v1/sbx036/admin/runs/${publicRunId}`, "GET",
      ));
    } catch (error) {
      publicExecutionError = safeError(error, secrets);
    } finally {
      await cleanupStage(publicRuntime, topo, credentials, journal, held, secrets);
    }

    if (!outsideTls || !outsideCoalesced || !outsideRaw || !allowAllTls || !allowAllCoalesced ||
      !publicHealth || !deniedTls || !deniedRaw || !target || !deniedPost) {
      throw new Error(`public stage was incomplete: ${publicExecutionError ?? "missing evidence"}`);
    }
    const publicAssessment = assessSbx036Public({
      runId: publicRunId,
      allowedHostname: topo.allowedHostname,
      allowedIPv4: topo.allowedIPv4,
      allowedPort: topo.allowedPort,
      deniedHostname: topo.deniedHostname,
      deniedIPv4: topo.deniedIPv4,
      deniedPort: topo.deniedPort,
      identityAndScopePassed: true,
      distinctControlledEndpointsPassed: topo.allowedAddresses.every((address) => !topo.deniedAddresses.includes(address)),
      allowAllReadbackPassed,
      restrictedReadback,
      postTargetReadback,
      allowAllCoalescedControl: allowAllCoalesced.result,
      allowedHttpsControl: publicHealth,
      deniedTlsNegative: deniedTls.result,
      deniedRawNegative: deniedRaw.result,
      deniedCoalescedTarget: target.result,
      deniedTlsPostNegative: deniedPost.result,
      receiver: publicReceiver,
      expectedOperations: publicOperations,
      expectedConfigurationEpoch: topo.configurationEpoch,
      outsideDeniedTlsPreflight: outsideTls.result,
      outsideDeniedCoalescedPreflight: outsideCoalesced.result,
      outsideDeniedRawNegative: outsideRaw.result,
      allowAllDeniedTlsControl: allowAllTls.result,
      cleanupPassed: cleanupPassed(publicRuntime.cleanup),
      retention: retention(),
      ...(publicExecutionError ? { executionError: true } : {}),
    });
    evidence.publicStage = {
      runId: publicRunId,
      sandboxId: publicSandboxId,
      assessment: publicAssessment,
      policy: { allowAllReadbackPassed, restrictedReadback, postTargetReadback },
      cases: publicRecords,
      receiver: publicReceiver,
      cleanup: publicRuntime.cleanup,
      ...(publicExecutionError ? { executionError: publicExecutionError } : {}),
    };

    if (!publicAssessment.candidate || publicAssessment.verdict !== "candidate-public") {
      evidence.secretStage = { executed: false, reason: "exact public bypass signal was absent" };
    } else {
      const secretRunId = journal.stages[1].runId;
      const secretCases = Object.values(SBX036_SECRET_CASES);
      const secretCanaries = canaries(secretCases.filter((caseId) => caseId !== SBX036_SECRET_CASES.deniedCoalescedTarget));
      const secretOperations = operations(topo.adminKey, secretRunId, secretCanaries);
      const secretGate = new RateGate();
      const secretRuntime: StageRuntime = {
        role: "secret",
        sandboxName: journal.stages[1].sandboxName,
        cleanup: emptyCleanup(),
      };
      let secretExecutionError: string | undefined;
      let secretSandboxId = "missing";
      let secretRestricted = restrictedReadback;
      let secretPost = restrictedReadback;
      let secretHealth: Sbx036HttpsControlEvidence | undefined;
      let secretDenied: CaseEvidence | undefined;
      let secretTarget: CaseEvidence | undefined;
      let secretDeniedPost: CaseEvidence | undefined;
      let secretReceiver: Sbx036ReceiverStatus = {
        configured: false, receipts: [], secretRegistered: false, rawPayloadStored: false, payloadDigestStored: false,
      };
      let controlsCompletedAt = new Date().toISOString();
      let secretCreatedAt = controlsCompletedAt;
      let secretWrittenAt = controlsCompletedAt;
      let operatorSecretStagedMode0600 = false;
      let operatorSecret: string | undefined;
      try {
        await configureReceiver(topo, "secret", secretCanaries, journal, held);
        await createStageSandbox(
          secretRuntime, { allow: [topo.allowedHostname] }, credentials, probeSource, healthSource, journal, held,
        );
        if (!secretRuntime.sandbox || !secretRuntime.sessionId) throw new Error("secret sandbox creation lacked identity");
        secretSandboxId = secretRuntime.sessionId;
        secretRestricted = await policyReadback(
          secretRuntime.sandbox, secretRuntime.sandboxName, secretRuntime.sessionId, credentials,
          { allowedHostname: topo.allowedHostname },
        );
        if (!secretRestricted.passed) throw new Error("fresh secret sandbox lacked exact restricted readback");
        secretHealth = (await sandboxHealth(secretRuntime.sandbox, secretRunId, secretGate, secrets)).result;
        const secretConfigFor = (caseId: string, mode: "postgres-tls"): Record<string, unknown> => probeConfiguration({
          mode, runId: secretRunId, caseId, endpointRole: "denied", hostname: topo.deniedHostname,
          ipv4: topo.deniedIPv4, port: topo.deniedPort, publicCanary: secretCanaries[caseId]!,
          expectedOperationId: secretOperations[caseId]!,
        });
        secretDenied = await sandboxProbe(secretRuntime.sandbox,
          secretConfigFor(SBX036_SECRET_CASES.deniedTlsNegative, "postgres-tls"), secretGate, secrets);
        controlsCompletedAt = new Date().toISOString();

        operatorSecret = `opsec_${randomBytes(32).toString("base64url")}`;
        secrets.push(operatorSecret);
        secretCreatedAt = new Date().toISOString();
        const commitment = deriveSbx036SecretCommitment(
          topo.adminKey, secretRunId, SBX036_SECRET_CASES.deniedCoalescedTarget, operatorSecret,
        );
        const expectedSecretOperation = deriveSbx036SecretOperationId(
          topo.adminKey, secretRunId, SBX036_SECRET_CASES.deniedCoalescedTarget, commitment,
        );
        const registration = await adminRequest(
          topo.adminOrigin,
          topo.adminKey,
          `/v1/sbx036/admin/runs/${secretRunId}/secret`,
          "POST",
          { caseId: SBX036_SECRET_CASES.deniedCoalescedTarget, commitment },
        );
        if (registration.registered !== true || registration.operationId !== expectedSecretOperation) {
          throw new Error("secret commitment registration returned the wrong opaque operation ID");
        }
        secretOperations[SBX036_SECRET_CASES.deniedCoalescedTarget] = expectedSecretOperation;
        journal.stages[1].secretWriteAttempted = true;
        await persistSbx036Journal(held, journal);
        await secretRuntime.sandbox.writeFiles([{ path: remoteSecretPath, content: operatorSecret, mode: 0o600 }], {
          signal: signal(),
        });
        secretWrittenAt = new Date().toISOString();
        operatorSecretStagedMode0600 = true;
        const targetConfig = probeConfiguration({
          mode: "coalesced-secret",
          runId: secretRunId,
          caseId: SBX036_SECRET_CASES.deniedCoalescedTarget,
          endpointRole: "denied",
          hostname: topo.deniedHostname,
          ipv4: topo.deniedIPv4,
          port: topo.deniedPort,
        });
        secretTarget = await sandboxProbe(secretRuntime.sandbox, targetConfig, secretGate, secrets);
        journal.stages[1].secretNeutralizeAttempted = true;
        await persistSbx036Journal(held, journal);
        await secretRuntime.sandbox.writeFiles([{ path: remoteSecretPath, content: "SBX036_CLEARED", mode: 0o600 }], {
          signal: signal(),
        });
        journal.stages[1].secretNeutralized = true;
        await persistSbx036Journal(held, journal);
        operatorSecret = undefined;
        secretPost = await policyReadback(
          secretRuntime.sandbox, secretRuntime.sandboxName, secretRuntime.sessionId, credentials,
          { allowedHostname: topo.allowedHostname },
        );
        secretDeniedPost = await sandboxProbe(secretRuntime.sandbox,
          secretConfigFor(SBX036_SECRET_CASES.deniedTlsPostNegative, "postgres-tls"), secretGate, secrets);
        await new Promise((resolveWait) => setTimeout(resolveWait, 500));
        secretReceiver = parseSbx036ReceiverStatus(await adminRequest(
          topo.adminOrigin, topo.adminKey, `/v1/sbx036/admin/runs/${secretRunId}`, "GET",
        ));
      } catch (error) {
        secretExecutionError = safeError(error, secrets);
      } finally {
        operatorSecret = undefined;
        await cleanupStage(secretRuntime, topo, credentials, journal, held, secrets);
      }
      if (!secretHealth || !secretDenied || !secretTarget || !secretDeniedPost) {
        throw new Error(`secret stage was incomplete: ${secretExecutionError ?? "missing evidence"}`);
      }
      const secretReceipt = secretReceiver.receipts.find((receipt) =>
        receipt.caseId === SBX036_SECRET_CASES.deniedCoalescedTarget && receipt.discriminatorKind === "secret");
      const secretAssessment = assessSbx036Secret({
        priorPublicCandidate: true,
        publicRunId,
        publicSandboxId,
        runId: secretRunId,
        sandboxId: secretSandboxId,
        allowedHostname: topo.allowedHostname,
        allowedIPv4: topo.allowedIPv4,
        allowedPort: topo.allowedPort,
        deniedHostname: topo.deniedHostname,
        deniedIPv4: topo.deniedIPv4,
        deniedPort: topo.deniedPort,
        identityAndScopePassed: true,
        distinctControlledEndpointsPassed: true,
        restrictedReadback: secretRestricted,
        postTargetReadback: secretPost,
        allowedHttpsControl: secretHealth,
        deniedTlsNegative: secretDenied.result,
        deniedCoalescedTarget: secretTarget.result,
        deniedTlsPostNegative: secretDeniedPost.result,
        receiver: secretReceiver,
        expectedOperations: secretOperations,
        expectedConfigurationEpoch: topo.configurationEpoch,
        publicControlsCompletedAt: controlsCompletedAt,
        operatorSecretCreatedAt: secretCreatedAt,
        operatorSecretWrittenAt: secretWrittenAt,
        ...(secretReceipt ? { secretReceiptAt: secretReceipt.observedAt } : {}),
        operatorSecretStagedMode0600,
        cleanupPassed: cleanupPassed(secretRuntime.cleanup),
        retention: retention(),
        ...(secretExecutionError ? { executionError: true } : {}),
      });
      evidence.secretStage = {
        executed: true,
        runId: secretRunId,
        sandboxId: secretSandboxId,
        assessment: secretAssessment,
        policy: { restrictedReadback: secretRestricted, postTargetReadback: secretPost },
        cases: [secretDenied, secretTarget, secretDeniedPost],
        receiver: secretReceiver,
        cleanup: secretRuntime.cleanup,
        retention: retention(),
        ...(secretExecutionError ? { executionError: secretExecutionError } : {}),
      };
    }
  } catch (error) {
    evidence.controllerError = safeError(error, secrets);
  } finally {
    if (held) {
      const noExternalStateAttempted = journal.stages.every((item) => item.createAttemptedAt === undefined) &&
        journal.receivers.every((item) => !item.configureAttempted);
      if (noExternalStateAttempted && !journal.completed) {
        journal.completed = true;
        await persistSbx036Journal(held, journal).catch((error) => {
          evidence.finalizationError = safeError(error, secrets);
        });
      }
      if (journal.completed && evidence.finalizationError === undefined) {
        try {
          await releaseSbx036State(held);
          released = true;
        } catch (error) {
          evidence.finalizationError = safeError(error, secrets);
        }
      } else {
        await held.liveLock.closeRetainingState().catch((error) => {
          evidence.finalizationError ??= safeError(error, secrets);
        });
      }
    }
    evidence.completedAt = new Date().toISOString();
    evidence.retention = retention();
    evidence.recovery = {
      rootRunId: journal.rootRunId,
      journalRetained: !released,
      lockRetained: !released,
      cleanupComplete: journal.completed,
      lockImplementationId: "SBX-053-GIT-CREDENTIAL-RETENTION",
    };
    await writeSbx036PrivateArtifact(artifactPath, evidence);
  }
  process.stdout.write(`${JSON.stringify({ ...evidence, evidencePath: artifactPath }, null, 2)}\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
