import "dotenv/config";

import { execFile } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { APIError, Sandbox, type NetworkPolicy } from "@vercel/sandbox";
import { verifyEligibleAliasToken, type EligibleAliasIdentityProof } from "../eligible-alias-identity.js";
import type { Sbx041ReceiverConfiguration } from "./receiver.js";
import {
  SBX041_TEST_ID,
  SBX041_PLATFORM_REDACTED_TRANSFORM,
  SBX041_TRANSFORM_HEADER,
  assessSbx041,
  deriveSbx041OperationId,
  exactTransformPolicy,
  exactTransformProjection,
  type Sbx041Assessment,
  type Sbx041GuestEvidence,
  type Sbx041PolicyProof,
  type Sbx041ProbeMode,
  type Sbx041ReceiverSnapshot,
  type Sbx041ResponseEvidence,
  type Sbx041TlsEvidence,
} from "./verdict.js";

const ALIAS_EMAIL = "swve@wearehackerone.com";
const TEAM_ID = "team_n98ERpVwV7HqmWRudAyK8sXQ";
const PROJECT_ID = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
const SCOPE_CONFIRMATION = "I_CONTROL_BOTH_SBX041_ORIGINS_AND_AUTHORIZE_BOUNDED_TLS_RESUMPTION_TESTING";
const REMOTE_PROBE_PATH = "/tmp/sbx-041/tls-resumption-probe.mjs";
const CONTROL_TIMEOUT_MS = 30_000;
const GUEST_OUTPUT_LIMIT = 24 * 1024;
const INTER_CASE_DELAY_MS = 350;
const executeFile = promisify(execFile);

interface Credentials {
  token: string;
  teamId: string;
  projectId: string;
}

interface ControlledOrigins {
  a: URL;
  b: URL;
}

interface CommandEvidence {
  caseId: string;
  commandId: string;
  exitCode: number;
  durationMs?: number;
  stdoutBytes: number;
  stderrBytes: number;
  rawOutputRetained: false;
}

interface CleanupEvidence {
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  absent: boolean;
  errors: string[];
}

interface InfrastructurePreflightEvidence {
  aHealth: boolean;
  bHealth: boolean;
  sniNoSession: Sbx041GuestEvidence;
  sniResume: Sbx041GuestEvidence;
  noSniNoSession: Sbx041GuestEvidence;
  noSniResume: Sbx041GuestEvidence;
  passed: boolean;
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function signal(timeoutMs = CONTROL_TIMEOUT_MS): AbortSignal {
  return AbortSignal.timeout(timeoutMs);
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function safeError(error: unknown, secrets: readonly string[]): string {
  let message = error instanceof Error ? error.message : String(error);
  for (const secret of secrets) if (secret) message = message.split(secret).join("[REDACTED]");
  return message.replace(/[\0\r\n]/gu, " ").slice(0, 1_000);
}

function exactOrigin(raw: string, name: string): URL {
  const origin = new URL(raw);
  if (origin.protocol !== "https:" || raw !== origin.origin || origin.port || origin.username || origin.password ||
    origin.pathname !== "/" || origin.search || origin.hash || origin.hostname !== origin.hostname.toLowerCase() ||
    isIP(origin.hostname) !== 0) throw new Error(`${name} must be an exact lower-case HTTPS origin`);
  return origin;
}

export function controlledOrigins(environment: NodeJS.ProcessEnv = process.env): ControlledOrigins {
  if (environment.SBX041_SCOPE_CONFIRMATION !== SCOPE_CONFIRMATION) {
    throw new Error(`SBX041_SCOPE_CONFIRMATION must equal ${SCOPE_CONFIRMATION}`);
  }
  const a = exactOrigin(environment.SBX041_A_PUBLIC_ORIGIN ?? "", "SBX041_A_PUBLIC_ORIGIN");
  const b = exactOrigin(environment.SBX041_B_PUBLIC_ORIGIN ?? "", "SBX041_B_PUBLIC_ORIGIN");
  if (a.origin === b.origin) throw new Error("SBX-041 requires distinct owned A and B origins");
  return { a, b };
}

export function explicitCredentials(environment: NodeJS.ProcessEnv = process.env): Credentials {
  const token = required(environment, "VERCEL_TOKEN");
  if (environment.VERCEL_TEAM_ID !== TEAM_ID || environment.VERCEL_PROJECT_ID !== PROJECT_ID) {
    throw new Error("SBX-041 requires the verified HackerOne-alias team and project");
  }
  return { token, teamId: TEAM_ID, projectId: PROJECT_ID };
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function string(value: unknown, maximum = 2_048): string | undefined {
  return typeof value === "string" && value.length <= maximum && !/[\0\r\n]/u.test(value) ? value : undefined;
}

function number(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function boolean(value: unknown): boolean {
  return value === true;
}

function tlsEvidence(value: unknown): Sbx041TlsEvidence | undefined {
  const input = object(value);
  const transportHost = string(input?.transportHost, 253);
  const identityHost = string(input?.identityHost, 253);
  const configuredServername = input?.configuredServername === null
    ? null
    : string(input?.configuredServername, 253);
  if (!input || !transportHost || !identityHost || configuredServername === undefined) return undefined;
  return {
    transportHost,
    identityHost,
    configuredServername,
    authorized: boolean(input.authorized),
    sessionReused: boolean(input.sessionReused),
    ...(string(input.protocol, 32) ? { protocol: string(input.protocol, 32)! } : {}),
    ...(string(input.alpnProtocol, 32) ? { alpnProtocol: string(input.alpnProtocol, 32)! } : {}),
    ...(string(input.peerCertificateFingerprint256, 128)
      ? { peerCertificateFingerprint256: string(input.peerCertificateFingerprint256, 128)! }
      : {}),
  };
}

function responseEvidence(value: unknown): Sbx041ResponseEvidence | undefined {
  const input = object(value);
  const statusCode = number(input?.statusCode);
  const bodyBytes = number(input?.bodyBytes);
  if (!input || statusCode === undefined || bodyBytes === undefined) return undefined;
  return {
    statusCode,
    bodyBytes,
    ...(string(input.operationId, 96) ? { operationId: string(input.operationId, 96)! } : {}),
    ...(string(input.service, 64) ? { service: string(input.service, 64)! } : {}),
  };
}

export function sanitizeGuest(value: unknown, mode: Sbx041ProbeMode, caseId: string): Sbx041GuestEvidence {
  const input = object(value) ?? {};
  const selectedMode = [
    "direct-b",
    "normal-a",
    "fronted-sni-no-session",
    "fronted-sni-resume",
    "fronted-nosni-no-session",
    "fronted-nosni-resume",
  ].includes(String(input.mode))
    ? input.mode as Sbx041ProbeMode
    : mode;
  return {
    schemaVersion: number(input.schemaVersion) ?? -1,
    testId: string(input.testId, 64) ?? "",
    caseId: string(input.caseId, 128) ?? caseId,
    mode: selectedMode,
    tlsVersionPinned: string(input.tlsVersionPinned, 32) ?? "",
    strictCertificateVerification: boolean(input.strictCertificateVerification),
    environmentProxyTrust: boolean(input.environmentProxyTrust),
    rawConfigurationRetained: boolean(input.rawConfigurationRetained),
    rawSessionRetained: boolean(input.rawSessionRetained),
    connectionAttempts: number(input.connectionAttempts) ?? -1,
    retryCount: number(input.retryCount) ?? -1,
    totalHttpRequests: number(input.totalHttpRequests) ?? -1,
    bTargetRequests: number(input.bTargetRequests) ?? -1,
    bAttackRequests: number(input.bAttackRequests) ?? -1,
    ok: boolean(input.ok),
    ...(number(input.sessionOffers) !== undefined ? { sessionOffers: number(input.sessionOffers)! } : {}),
    ...(typeof input.freshBConnection === "boolean" ? { freshBConnection: input.freshBConnection } : {}),
    ...(number(input.aSessionBytes) !== undefined ? { aSessionBytes: number(input.aSessionBytes)! } : {}),
    ...(string(input.aSessionSha256, 64) ? { aSessionSha256: string(input.aSessionSha256, 64)! } : {}),
    ...(typeof input.aCertificateValidForB === "boolean" ? { aCertificateValidForB: input.aCertificateValidForB } : {}),
    ...(typeof input.bIdentityValidatedAgainstAuthenticatedASessionCertificate === "boolean"
      ? { bIdentityValidatedAgainstAuthenticatedASessionCertificate: input.bIdentityValidatedAgainstAuthenticatedASessionCertificate }
      : {}),
    ...(tlsEvidence(input.aTls) ? { aTls: tlsEvidence(input.aTls)! } : {}),
    ...(tlsEvidence(input.bTls) ? { bTls: tlsEvidence(input.bTls)! } : {}),
    ...(responseEvidence(input.response) ? { response: responseEvidence(input.response)! } : {}),
    ...(responseEvidence(input.aResponse) ? { aResponse: responseEvidence(input.aResponse)! } : {}),
    ...(responseEvidence(input.bResponse) ? { bResponse: responseEvidence(input.bResponse)! } : {}),
    ...(string(input.failClosedReason, 512) ? { failClosedReason: string(input.failClosedReason, 512)! } : {}),
    ...(string(input.crossHostIdentityErrorCode, 64) ? { crossHostIdentityErrorCode: string(input.crossHostIdentityErrorCode, 64)! } : {}),
    ...(string(input.errorCode, 64) ? { errorCode: string(input.errorCode, 64)! } : {}),
    ...(string(input.errorSyscall, 64) ? { errorSyscall: string(input.errorSyscall, 64)! } : {}),
  };
}

function emptyGuest(mode: Sbx041ProbeMode, caseId: string): Sbx041GuestEvidence {
  return sanitizeGuest({}, mode, caseId);
}

function transformPolicy(aHost: string, transformValue: string): NetworkPolicy {
  return { allow: { [aHost]: [{ transform: [{ headers: { [SBX041_TRANSFORM_HEADER]: transformValue } }] }] } };
}

function redactPolicy(value: unknown, secret: string): unknown {
  return JSON.parse(JSON.stringify(value).split(secret).join(SBX041_PLATFORM_REDACTED_TRANSFORM));
}

async function policyProof(
  stage: "pre" | "post",
  sandbox: Sandbox,
  sessionId: string,
  credentials: Credentials,
  aHost: string,
  transformValue: string,
): Promise<Sbx041PolicyProof> {
  const activeSession = sandbox.currentSession();
  const independent = await Sandbox.get({ name: sandbox.name, resume: false, ...credentials, signal: signal() });
  const independentSession = independent.currentSession();
  // Sandbox-level readbacks expose only the allowed-host projection. Session-level
  // readbacks retain the rule structure but deliberately replace credential values
  // with Vercel's literal redaction marker.
  const exact = exactTransformProjection(sandbox.networkPolicy, aHost) &&
    exactTransformPolicy(activeSession.networkPolicy, aHost, SBX041_PLATFORM_REDACTED_TRANSFORM) &&
    exactTransformProjection(independent.networkPolicy, aHost) &&
    exactTransformPolicy(independentSession.networkPolicy, aHost, SBX041_PLATFORM_REDACTED_TRANSFORM);
  const sameSession = activeSession.sessionId === sessionId && independentSession.sessionId === sessionId;
  return {
    stage,
    initialSessionId: sessionId,
    activeSessionId: activeSession.sessionId,
    independentSessionId: independentSession.sessionId,
    activeSandboxPolicy: redactPolicy(sandbox.networkPolicy, transformValue),
    activeSessionPolicy: redactPolicy(activeSession.networkPolicy, transformValue),
    independentSandboxPolicy: redactPolicy(independent.networkPolicy, transformValue),
    independentSessionPolicy: redactPolicy(independentSession.networkPolicy, transformValue),
    passed: exact && sameSession,
  };
}

async function adminRequest(origin: URL, key: string, path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set("authorization", `Bearer ${key}`);
  if (init.body) headers.set("content-type", "application/json");
  return fetch(new URL(path, origin), { ...init, headers, signal: signal(10_000), redirect: "error" });
}

async function publicHealth(origin: URL, service: string): Promise<boolean> {
  const response = await fetch(new URL("/healthz", origin), { signal: signal(8_000), redirect: "error" });
  if (response.status !== 200) return false;
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > 1_024) return false;
  const body = object(JSON.parse(bytes.toString("utf8")));
  return body?.ok === true && body.service === service && body.hostMatched === true;
}

async function configureReceiver(origins: ControlledOrigins, key: string, config: Sbx041ReceiverConfiguration): Promise<void> {
  const response = await adminRequest(origins.a, key, `/v1/sbx041/admin/runs/${encodeURIComponent(config.runId)}`, {
    method: "PUT", body: JSON.stringify(config),
  });
  if (response.status !== 204) throw new Error(`receiver configuration returned ${response.status}`);
}

async function receiverSnapshot(a: URL, key: string, runId: string): Promise<Sbx041ReceiverSnapshot> {
  const response = await adminRequest(a, key, `/v1/sbx041/admin/runs/${encodeURIComponent(runId)}`);
  if (!response.ok) throw new Error(`receiver readback returned ${response.status}`);
  const value = await response.json() as Sbx041ReceiverSnapshot;
  if (!value.configured || !Array.isArray(value.a) || !Array.isArray(value.b)) throw new Error("receiver readback shape is invalid");
  return value;
}

function probeConfiguration(input: {
  mode: Sbx041ProbeMode;
  caseId: string;
  origins: ControlledOrigins;
  runId: string;
  canary: string;
}) {
  const resume = input.mode === "fronted-sni-resume" || input.mode === "fronted-nosni-resume";
  const noSession = input.mode === "fronted-sni-no-session" || input.mode === "fronted-nosni-no-session";
  const aPath = resume
    ? `/v1/sbx041/ticket/${encodeURIComponent(input.runId)}`
    : `/v1/sbx041/control/${encodeURIComponent(input.runId)}`;
  const bPath = resume
    ? `/v1/sbx041/action/${encodeURIComponent(input.runId)}`
    : noSession
      ? `/v1/sbx041/fronted-control/${encodeURIComponent(input.runId)}`
    : `/v1/sbx041/direct/${encodeURIComponent(input.runId)}`;
  return {
    scopeConfirmation: SCOPE_CONFIRMATION,
    researcherControlledHosts: [input.origins.a.hostname, input.origins.b.hostname],
    mode: input.mode,
    caseId: input.caseId,
    correlationCanary: input.canary,
    aHost: input.origins.a.hostname,
    aPort: 443,
    aPath,
    bHost: input.origins.b.hostname,
    bPort: 443,
    bPath,
    timeoutMs: 4_000,
    maxResponseBytes: 8_192,
  };
}

function delay(): Promise<void> {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, INTER_CASE_DELAY_MS));
}

async function runLocalProbe(
  sourcePath: string,
  config: ReturnType<typeof probeConfiguration>,
): Promise<Sbx041GuestEvidence> {
  const serialized = Buffer.from(JSON.stringify(config)).toString("base64url");
  const result = await executeFile(process.execPath, [sourcePath, serialized], {
    timeout: 20_000,
    maxBuffer: GUEST_OUTPUT_LIMIT,
  });
  if (Buffer.byteLength(result.stderr) > GUEST_OUTPUT_LIMIT) throw new Error("local preflight stderr exceeded its bound");
  let parsed: unknown;
  try { parsed = JSON.parse(result.stdout); } catch { throw new Error("local preflight emitted invalid JSON"); }
  return sanitizeGuest(parsed, config.mode, config.caseId);
}

function exactPreflightTls(
  value: Sbx041TlsEvidence | undefined,
  aHost: string,
  bHost: string,
  configuredServername: string | null,
  reused: boolean,
): boolean {
  return value?.transportHost === aHost && value.identityHost === bHost &&
    value.configuredServername === configuredServername && value.authorized === true &&
    value.protocol === "TLSv1.2" && value.alpnProtocol === "http/1.1" && value.sessionReused === reused;
}

function exactLocalNoSession(
  guest: Sbx041GuestEvidence,
  mode: Sbx041ProbeMode,
  caseId: string,
  origins: ControlledOrigins,
  configuredServername: string | null,
): boolean {
  return guest.testId === SBX041_TEST_ID && guest.mode === mode && guest.caseId === caseId && guest.ok === true &&
    guest.connectionAttempts === 1 && guest.sessionOffers === 0 && guest.totalHttpRequests === 1 &&
    guest.bTargetRequests === 1 && guest.bAttackRequests === 0 &&
    exactPreflightTls(guest.bTls, origins.a.hostname, origins.b.hostname, configuredServername, false) &&
    guest.response?.statusCode === 200 && guest.response.service === "sbx041-b-receiver";
}

function exactLocalResume(
  guest: Sbx041GuestEvidence,
  mode: Sbx041ProbeMode,
  caseId: string,
  origins: ControlledOrigins,
  configuredServername: string | null,
): boolean {
  return guest.testId === SBX041_TEST_ID && guest.mode === mode && guest.caseId === caseId && guest.ok === true &&
    guest.connectionAttempts === 2 && guest.sessionOffers === 1 && guest.totalHttpRequests === 2 &&
    guest.bTargetRequests === 1 && guest.bAttackRequests === 1 && guest.aCertificateValidForB === true &&
    guest.bIdentityValidatedAgainstAuthenticatedASessionCertificate === true &&
    guest.aTls?.transportHost === origins.a.hostname && guest.aTls.identityHost === origins.a.hostname &&
    guest.aTls.configuredServername === origins.a.hostname && guest.aTls.sessionReused === false &&
    exactPreflightTls(guest.bTls, origins.a.hostname, origins.b.hostname, configuredServername, true) &&
    guest.aResponse?.statusCode === 200 && guest.aResponse.service === "sbx041-a-receiver" &&
    guest.bResponse?.statusCode === 200 && guest.bResponse.service === "sbx041-b-receiver";
}

async function infrastructurePreflight(
  origins: ControlledOrigins,
  sourcePath: string,
  runId: string,
  canary: string,
): Promise<InfrastructurePreflightEvidence> {
  const [aHealth, bHealth] = await Promise.all([
    publicHealth(origins.a, "sbx041-a-receiver"),
    publicHealth(origins.b, "sbx041-b-receiver"),
  ]);
  if (!aHealth || !bHealth) throw new Error("owned A/B receiver health checks failed");
  await delay();
  const modes: Array<{ mode: Sbx041ProbeMode; caseId: string }> = [
    { mode: "fronted-sni-no-session", caseId: "preflight-sni-no-session" },
    { mode: "fronted-sni-resume", caseId: "preflight-sni-resume" },
    { mode: "fronted-nosni-no-session", caseId: "preflight-nosni-no-session" },
    { mode: "fronted-nosni-resume", caseId: "preflight-nosni-resume" },
  ];
  const guests: Sbx041GuestEvidence[] = [];
  for (const item of modes) {
    const config = {
      ...probeConfiguration({ mode: item.mode, caseId: item.caseId, origins, runId, canary }),
      aPath: "/healthz",
      bPath: "/healthz",
    };
    guests.push(await runLocalProbe(sourcePath, config));
    await delay();
  }
  const [sniNoSession, sniResume, noSniNoSession, noSniResume] = guests as [
    Sbx041GuestEvidence,
    Sbx041GuestEvidence,
    Sbx041GuestEvidence,
    Sbx041GuestEvidence,
  ];
  const passed = exactLocalNoSession(
    sniNoSession, "fronted-sni-no-session", "preflight-sni-no-session", origins, origins.b.hostname,
  ) && exactLocalResume(sniResume, "fronted-sni-resume", "preflight-sni-resume", origins, origins.b.hostname) &&
    exactLocalNoSession(noSniNoSession, "fronted-nosni-no-session", "preflight-nosni-no-session", origins, null) &&
    exactLocalResume(noSniResume, "fronted-nosni-resume", "preflight-nosni-resume", origins, null);
  return { aHealth, bHealth, sniNoSession, sniResume, noSniNoSession, noSniResume, passed };
}

async function runGuest(
  sandbox: Sandbox,
  config: ReturnType<typeof probeConfiguration>,
  secrets: readonly string[],
): Promise<{ guest: Sbx041GuestEvidence; command: CommandEvidence }> {
  const serialized = JSON.stringify(config);
  if (secrets.some((secret) => secret && serialized.includes(secret))) throw new Error("guest configuration contains controller-only material");
  const command = await sandbox.runCommand({
    cmd: "node",
    args: [REMOTE_PROBE_PATH, Buffer.from(serialized).toString("base64url")],
    timeoutMs: 20_000,
  });
  const [stdout, stderr] = await Promise.all([command.stdout({ signal: signal() }), command.stderr({ signal: signal() })]);
  if (Buffer.byteLength(stdout) > GUEST_OUTPUT_LIMIT || Buffer.byteLength(stderr) > GUEST_OUTPUT_LIMIT) {
    throw new Error(`${config.caseId} guest output exceeded its bound`);
  }
  if (secrets.some((secret) => secret && (stdout.includes(secret) || stderr.includes(secret)))) {
    throw new Error(`${config.caseId} guest output contained controller-only material`);
  }
  let parsed: unknown;
  try { parsed = JSON.parse(stdout); } catch { throw new Error(`${config.caseId} emitted invalid JSON`); }
  return {
    guest: sanitizeGuest(parsed, config.mode, config.caseId),
    command: {
      caseId: config.caseId,
      commandId: command.cmdId,
      exitCode: command.exitCode,
      ...(command.durationMs !== undefined ? { durationMs: command.durationMs } : {}),
      stdoutBytes: Buffer.byteLength(stdout),
      stderrBytes: Buffer.byteLength(stderr),
      rawOutputRetained: false,
    },
  };
}

function notFound(error: unknown): boolean {
  return error instanceof APIError && error.response.status === 404;
}

async function cleanupSandbox(sandbox: Sandbox | undefined, credentials: Credentials, secrets: readonly string[]): Promise<CleanupEvidence> {
  const cleanup: CleanupEvidence = {
    stopAttempted: false, stopped: false, deleteAttempted: false, deleted: false, absent: false, errors: [],
  };
  if (!sandbox) return cleanup;
  cleanup.stopAttempted = true;
  try { await sandbox.stop({ signal: signal() }); cleanup.stopped = true; }
  catch (error) { cleanup.errors.push(`stop: ${safeError(error, secrets)}`); }
  cleanup.deleteAttempted = true;
  try { await sandbox.delete({ signal: signal() }); cleanup.deleted = true; }
  catch (error) { cleanup.errors.push(`delete: ${safeError(error, secrets)}`); }
  try {
    await Sandbox.get({ name: sandbox.name, resume: false, ...credentials, signal: signal(8_000) });
    cleanup.errors.push("sandbox still exists after delete");
  } catch (error) {
    if (notFound(error)) cleanup.absent = true;
    else cleanup.errors.push(`absence check: ${safeError(error, secrets)}`);
  }
  return cleanup;
}

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  const runId = randomUUID();
  const credentials = explicitCredentials();
  const origins = controlledOrigins();
  const adminKey = required(process.env, "SBX041_ADMIN_KEY");
  if (adminKey.length < 32) throw new Error("SBX041_ADMIN_KEY must contain at least 32 characters");
  const transformValue = `broker_${randomBytes(32).toString("base64url")}`;
  const transformSha256 = sha256(transformValue);
  const canary = `corr_${randomBytes(18).toString("base64url")}`;
  const secrets = [credentials.token, adminKey, transformValue];
  const artifacts = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  await mkdir(artifacts, { recursive: true, mode: 0o700 });
  let sandbox: Sandbox | undefined;
  let sandboxName = `sbx-041-${runId.slice(0, 8)}`;
  let sessionId = "";
  let identityAndScopePassed = false;
  let identityProof: EligibleAliasIdentityProof | undefined;
  let infrastructurePreflightPassed = false;
  let infrastructure: InfrastructurePreflightEvidence = {
    aHealth: false,
    bHealth: false,
    sniNoSession: emptyGuest("fronted-sni-no-session", "preflight-sni-no-session"),
    sniResume: emptyGuest("fronted-sni-resume", "preflight-sni-resume"),
    noSniNoSession: emptyGuest("fronted-nosni-no-session", "preflight-nosni-no-session"),
    noSniResume: emptyGuest("fronted-nosni-resume", "preflight-nosni-resume"),
    passed: false,
  };
  let receiverConfigured = false;
  let receiverDeleted = false;
  let receiverAbsent = false;
  let executionError: string | undefined;
  let policyPre: Sbx041PolicyProof = {
    stage: "pre", initialSessionId: "", activeSessionId: "", independentSessionId: "",
    activeSandboxPolicy: {}, activeSessionPolicy: {}, independentSandboxPolicy: {}, independentSessionPolicy: {}, passed: false,
  };
  let policyPost: Sbx041PolicyProof = { ...policyPre, stage: "post" };
  let directBPre = emptyGuest("direct-b", "direct-b-pre");
  let normalA = emptyGuest("normal-a", "normal-a");
  let sniNoSession = emptyGuest("fronted-sni-no-session", "fronted-sni-no-session");
  let sniResume = emptyGuest("fronted-sni-resume", "fronted-sni-resume");
  let noSniNoSession = emptyGuest("fronted-nosni-no-session", "fronted-nosni-no-session");
  let noSniResume = emptyGuest("fronted-nosni-resume", "fronted-nosni-resume");
  let directBPost = emptyGuest("direct-b", "direct-b-post");
  let receiver: Sbx041ReceiverSnapshot = { configured: false, a: [], b: [] };
  const commands: CommandEvidence[] = [];
  const sourcePath = resolve("guest/tls-resumption-probe.mjs");
  let probeSourceSha256 = "";

  try {
    identityProof = await verifyEligibleAliasToken({
      token: credentials.token,
      expectedEmail: ALIAS_EMAIL,
      expectedTeamId: TEAM_ID,
      expectedProjectId: PROJECT_ID,
      manualEmailConfirmation: process.env.SBX041_ALIAS_EMAIL_CONFIRMATION,
    });
    const source = await readFile(sourcePath, "utf8");
    if (secrets.some((secret) => source.includes(secret))) throw new Error("guest source contains controller-only material");
    probeSourceSha256 = sha256(source);
    infrastructure = await infrastructurePreflight(origins, sourcePath, runId, canary);
    infrastructurePreflightPassed = infrastructure.passed;
    if (!infrastructurePreflightPassed) {
      throw new Error("owned A/B TLS 1.2 routing and cross-host resumption preflight failed");
    }
    await configureReceiver(origins, adminKey, {
      runId,
      aHost: origins.a.hostname,
      bHost: origins.b.hostname,
      correlationCanary: canary,
      transformHeaderSha256: transformSha256,
    });
    receiverConfigured = true;
    identityAndScopePassed = true;
    sandbox = await Sandbox.create({
      name: sandboxName,
      persistent: false,
      timeout: 180_000,
      networkPolicy: transformPolicy(origins.a.hostname, transformValue),
      tags: { harness: "vsc", test: "SBX-041", run: runId.slice(0, 12) },
      ...credentials,
      signal: signal(45_000),
    });
    sandboxName = sandbox.name;
    sessionId = sandbox.currentSession().sessionId;
    policyPre = await policyProof("pre", sandbox, sessionId, credentials, origins.a.hostname, transformValue);
    if (!policyPre.passed) throw new Error("exact active and independent transform-policy readbacks failed");
    await sandbox.writeFiles([{ path: REMOTE_PROBE_PATH, content: source, mode: 0o700 }], { signal: signal() });

    const order: Array<{ mode: Sbx041ProbeMode; caseId: string; assign(value: Sbx041GuestEvidence): void }> = [
      { mode: "direct-b", caseId: "direct-b-pre", assign: (value) => { directBPre = value; } },
      { mode: "normal-a", caseId: "normal-a", assign: (value) => { normalA = value; } },
      { mode: "fronted-sni-no-session", caseId: "fronted-sni-no-session", assign: (value) => { sniNoSession = value; } },
      { mode: "fronted-sni-resume", caseId: "fronted-sni-resume", assign: (value) => { sniResume = value; } },
      { mode: "fronted-nosni-no-session", caseId: "fronted-nosni-no-session", assign: (value) => { noSniNoSession = value; } },
      { mode: "fronted-nosni-resume", caseId: "fronted-nosni-resume", assign: (value) => { noSniResume = value; } },
      { mode: "direct-b", caseId: "direct-b-post", assign: (value) => { directBPost = value; } },
    ];
    let previousProbeStartedAt = 0;
    for (const item of order) {
      const waitMs = Math.max(0, 250 - (Date.now() - previousProbeStartedAt));
      if (waitMs > 0) await new Promise((resolveWait) => setTimeout(resolveWait, waitMs));
      previousProbeStartedAt = Date.now();
      const result = await runGuest(sandbox, probeConfiguration({
        mode: item.mode, caseId: item.caseId, origins, runId, canary,
      }), secrets);
      if (result.command.exitCode !== 0) throw new Error(`${item.caseId} guest command exited nonzero`);
      item.assign(result.guest);
      commands.push(result.command);
      await delay();
    }
    policyPost = await policyProof("post", sandbox, sessionId, credentials, origins.a.hostname, transformValue);
    await new Promise((resolveWait) => setTimeout(resolveWait, 750));
    receiver = await receiverSnapshot(origins.a, adminKey, runId);
  } catch (error) {
    executionError = safeError(error, secrets);
    if (receiverConfigured) {
      try { receiver = await receiverSnapshot(origins.a, adminKey, runId); } catch { /* retain bounded empty snapshot */ }
    }
  }

  const cleanup = await cleanupSandbox(sandbox, credentials, secrets);
  const cleanupPassed = cleanup.stopped && cleanup.deleted && cleanup.absent && cleanup.errors.length === 0;
  let assessment: Sbx041Assessment = assessSbx041({
    runId,
    aHost: origins.a.hostname,
    bHost: origins.b.hostname,
    expectedTransformSha256: transformSha256,
    expectedNormalOperationId: deriveSbx041OperationId(adminKey, runId, "normal-a", transformSha256),
    expectedSniTicketOperationId: deriveSbx041OperationId(adminKey, runId, "fronted-sni-resume-ticket", transformSha256),
    expectedSniAttackOperationId: deriveSbx041OperationId(adminKey, runId, "fronted-sni-resume-attack", transformSha256),
    expectedNoSniTicketOperationId: deriveSbx041OperationId(adminKey, runId, "fronted-nosni-resume-ticket", transformSha256),
    expectedNoSniAttackOperationId: deriveSbx041OperationId(adminKey, runId, "fronted-nosni-resume-attack", transformSha256),
    identityAndScopePassed,
    infrastructurePreflightPassed,
    policyPre,
    policyPost,
    directBPre,
    normalA,
    sniNoSession,
    sniResume,
    noSniNoSession,
    noSniResume,
    directBPost,
    receiver,
    cleanupPassed,
    ...(executionError ? { executionError: true } : {}),
  });

  if (receiverConfigured) {
    try {
      const deleted = await adminRequest(origins.a, adminKey, `/v1/sbx041/admin/runs/${encodeURIComponent(runId)}`, { method: "DELETE" });
      receiverDeleted = deleted.status === 204;
      const absent = await adminRequest(origins.a, adminKey, `/v1/sbx041/admin/runs/${encodeURIComponent(runId)}`);
      receiverAbsent = absent.status === 404;
    } catch (error) {
      executionError ??= `receiver cleanup: ${safeError(error, secrets)}`;
    }
  }
  const receiverCleanupPassed = receiverConfigured && receiverDeleted && receiverAbsent;
  if (!receiverCleanupPassed && assessment.verdict !== "error") {
    assessment = {
      verdict: "error", severity: "unknown", candidate: false, controlsPassed: false,
      exactSessionResumptionProof: assessment.exactSessionResumptionProof,
      exactBrokeredSecretReceipt: false,
      successfulVariants: [],
      summary: "Receiver cleanup failed.", signals: ["receiver cleanup passed: false"],
    };
  }

  const evidence = {
    schemaVersion: 1,
    testId: SBX041_TEST_ID,
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    assessment,
    credentialContext: {
      aliasEmail: ALIAS_EMAIL,
      teamId: TEAM_ID,
      projectId: PROJECT_ID,
      verificationMethod: identityProof?.method ?? "unverified",
      tokenStored: false,
    },
    origins: { a: origins.a.origin, b: origins.b.origin },
    infrastructure: {
      ...infrastructure,
      probeSourceSha256,
      note: "Outside-sandbox probes require both A-transport SNI-B/no-SNI routes and both TLS 1.2 cross-host resumptions to reach B before any sandbox is created.",
    },
    sandbox: { name: sandboxName, sessionId },
    policyPre,
    policyPost,
    commands,
    guest: { directBPre, normalA, sniNoSession, sniResume, noSniNoSession, noSniResume, directBPost },
    receiver,
    cleanup,
    receiverCleanup: { configured: receiverConfigured, deleted: receiverDeleted, absent: receiverAbsent, passed: receiverCleanupPassed },
    retention: {
      rawTransformValue: false,
      rawTlsSession: false,
      tlsSessionDigests: {
        sni: sniResume.aSessionSha256 !== undefined,
        noSni: noSniResume.aSessionSha256 !== undefined,
      },
      rawGuestConfiguration: false,
      rawCommandOutput: false,
    },
    rateAndRequestBounds: {
      minimumInterCaseDelayMs: INTER_CASE_DELAY_MS,
      sandboxGuestCommands: 7,
      sandboxConnectionAttemptCap: 9,
      sandboxHttpRequestCap: 7,
      retries: 0,
    },
    ...(executionError ? { executionError } : {}),
  };
  const serialized = `${JSON.stringify(evidence, null, 2)}\n`;
  if (secrets.some((secret) => secret && serialized.includes(secret))) {
    throw new Error("refusing to persist evidence containing controller-only material");
  }
  const evidencePath = resolve(artifacts, `SBX-041-${runId}-private.json`);
  await writeFile(evidencePath, serialized, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify({
    testId: SBX041_TEST_ID,
    runId,
    assessment,
    sandbox: evidence.sandbox,
    infrastructurePreflightPassed,
    receiverCleanup: evidence.receiverCleanup,
    evidencePath,
  }, null, 2)}\n`);
  if (assessment.verdict === "error" || assessment.verdict === "indeterminate") throw new Error(assessment.summary);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
