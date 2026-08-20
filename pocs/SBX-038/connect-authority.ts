import "dotenv/config";

import { randomBytes, randomUUID } from "node:crypto";
import { lstat, readFile, readdir } from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import tls from "node:tls";
import { APIError, Sandbox, type NetworkPolicy } from "@vercel/sandbox";
import { verifyEligibleAliasToken } from "../eligible-alias-identity.js";
import type { Sbx038ReceiverConfiguration } from "./receiver.js";
import {
  SBX038_TEST_ID,
  SBX038_TRANSFORM_HEADER,
  assessSbx038Stage,
  combineSbx038Assessments,
  deriveSbx038OperationId,
  deriveSbx038SecretCommitment,
  deriveSbx038TransformCommitment,
  exactTransformPolicy,
  exactTransformProjection,
  type Sbx038Assessment,
  type Sbx038BTransportProof,
  type Sbx038GuestEvidence,
  type Sbx038PolicyProof,
  type Sbx038ProbeMode,
  type Sbx038ReceiverSnapshot,
  type Sbx038StageInput,
  type Sbx038StageChronology,
  type Sbx038TlsEvidence,
} from "./verdict.js";
import {
  SBX038_ARTIFACTS_DIRECTORY,
  SBX038_CREATE_REQUEST_TIMEOUT_MS,
  SBX038_SANDBOX_TIMEOUT_MS,
  SBX038_UUID,
  acquireSbx038RecoveryState,
  acquireSbx038State,
  createSbx038Journal,
  dispatchSbx038Recovery,
  exactSbx038SandboxProvenance,
  exactSbx038ZeroExternalStateJournal,
  finalizeSbx038Artifact,
  finalizeSbx038RecoveryArtifact,
  parseSbx038Journal,
  persistSbx038Journal,
  proveSbx038SandboxAbsence,
  readSbx038Journal,
  releaseSbx038State,
  safeSbx038SafetyError,
  sbx038ArtifactPath,
  sbx038JournalCleanupComplete,
  sbx038JournalPath,
  sbx038LockPath,
  sbx038PrivateFileMode,
  sbx038RecoveryArtifactPath,
  sbx038Resource,
  sbx038UnknownCreateSettlementReached,
  writeSbx038Checkpoint,
  writeSbx038RecoveryArtifact,
  type Sbx038HeldState,
  type Sbx038Journal,
  type Sbx038ResourceJournal,
  type Sbx038SandboxProvenanceView,
  type Sbx038StageRole,
} from "./safety.js";

const ALIAS_EMAIL = "swve@wearehackerone.com";
const TEAM_ID = "team_n98ERpVwV7HqmWRudAyK8sXQ";
const PROJECT_ID = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
const SCOPE_CONFIRMATION = "I_CONTROL_BOTH_SBX038_ORIGINS_AND_AUTHORIZE_BOUNDED_CONNECT_AUTHORITY_TESTING";
const REMOTE_PROBE_PATH = "/tmp/sbx-038/connect-authority-probe.mjs";
const REMOTE_SECRET_PATH = "/tmp/sbx-038/operator-secret";
const CASE_DELAY_MS = 500;
const CONTROL_TIMEOUT_MS = 30_000;
const GUEST_OUTPUT_LIMIT = 24 * 1024;
const RECEIVER_ABSENCE_DELAYS_MS = [250, 750, 1_500] as const;

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

interface StageCleanup {
  secretOverwriteAttempted: boolean;
  secretOverwritten: boolean;
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  absenceChecks: number;
  absent: boolean;
  prefixListAbsent: boolean;
  completedAt: string;
  errors: string[];
}

interface StageResult {
  input: Sbx038StageInput;
  assessment: Sbx038Assessment;
  sandbox: { name: string; sessionId: string };
  commands: CommandEvidence[];
  cleanup: StageCleanup;
}

interface ReceiverCleanup {
  configureAttempted: boolean;
  configured: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  absenceChecks: number;
  absent: boolean;
  errors: string[];
}

interface LocalFinalizationProof {
  journalAbsent: boolean;
  liveLockAbsent: boolean;
  lockTransactionAbsent: boolean;
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function signal(timeoutMs = CONTROL_TIMEOUT_MS): AbortSignal {
  return AbortSignal.timeout(timeoutMs);
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

export function sbx038BTransportMode(
  environment: NodeJS.ProcessEnv = process.env,
): Sbx038BTransportProof["mode"] {
  const mode = environment.SBX038_B_TRANSPORT_MODE;
  if (mode !== "receiver-local" && mode !== "public-edge") {
    throw new Error("SBX038_B_TRANSPORT_MODE must be receiver-local or public-edge");
  }
  return mode;
}

export function controlledOrigins(environment: NodeJS.ProcessEnv = process.env): ControlledOrigins {
  if (environment.SBX038_SCOPE_CONFIRMATION !== SCOPE_CONFIRMATION) {
    throw new Error(`SBX038_SCOPE_CONFIRMATION must equal ${SCOPE_CONFIRMATION}`);
  }
  const a = exactOrigin(environment.SBX038_A_PUBLIC_ORIGIN ?? "", "SBX038_A_PUBLIC_ORIGIN");
  const b = exactOrigin(environment.SBX038_B_PUBLIC_ORIGIN ?? "", "SBX038_B_PUBLIC_ORIGIN");
  if (a.origin === b.origin) throw new Error("SBX-038 requires distinct owned A and B origins");
  return { a, b };
}

export function explicitCredentials(environment: NodeJS.ProcessEnv = process.env): Credentials {
  const token = required(environment, "VERCEL_TOKEN");
  if (environment.VERCEL_TEAM_ID !== TEAM_ID || environment.VERCEL_PROJECT_ID !== PROJECT_ID) {
    throw new Error("SBX-038 requires the verified HackerOne-alias team and project");
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

function tlsEvidence(value: unknown): Sbx038TlsEvidence | undefined {
  const input = object(value);
  if (!input) return undefined;
  const servername = string(input.servername, 253);
  if (!servername) return undefined;
  return {
    servername,
    authorized: boolean(input.authorized),
    ...(string(input.authorizationError, 256) ? { authorizationError: string(input.authorizationError, 256)! } : {}),
    ...(string(input.protocol, 32) ? { protocol: string(input.protocol, 32)! } : {}),
    ...(string(input.remoteAddress, 128) ? { remoteAddress: string(input.remoteAddress, 128)! } : {}),
    ...(number(input.remotePort) !== undefined ? { remotePort: number(input.remotePort)! } : {}),
  };
}

function responseEvidence(value: unknown): Sbx038GuestEvidence["outerResponse"] {
  const input = object(value);
  const statusCode = number(input?.statusCode);
  if (!input || statusCode === undefined) return undefined;
  return {
    statusCode,
    ...(string(input.operationId, 96) ? { operationId: string(input.operationId, 96)! } : {}),
    ...(number(input.bodyBytes) !== undefined ? { bodyBytes: number(input.bodyBytes)! } : {}),
    ...(typeof input.terminalConnectHeader === "boolean" ? { terminalConnectHeader: input.terminalConnectHeader } : {}),
  };
}

export function sanitizeGuest(
  value: unknown,
  mode: Sbx038ProbeMode,
  caseId: string,
  expectedRunId = "",
): Sbx038GuestEvidence {
  const input = object(value) ?? {};
  const trustEnvironmentNames = Array.isArray(input.trustEnvironmentNames) && input.trustEnvironmentNames.length <= 16
    ? input.trustEnvironmentNames.map((name) => string(name, 64) ?? "<invalid>")
    : ["<invalid>"];
  return {
    schemaVersion: number(input.schemaVersion) ?? -1,
    testId: string(input.testId, 64) ?? "",
    runId: string(input.runId, 128) ?? expectedRunId,
    caseId: string(input.caseId, 128) ?? caseId,
    mode: ["normal-a", "direct-b", "connect-a", "connect-b-public", "connect-b-secret"].includes(String(input.mode))
      ? input.mode as Sbx038ProbeMode
      : mode,
    outerHost: string(input.outerHost, 253) ?? "",
    outerPort: number(input.outerPort) ?? -1,
    ...(string(input.targetHost, 253) ? { targetHost: string(input.targetHost, 253)! } : {}),
    ...(number(input.targetPort) !== undefined ? { targetPort: number(input.targetPort)! } : {}),
    ...(string(input.connectAuthority, 300) ? { connectAuthority: string(input.connectAuthority, 300)! } : {}),
    ...(string(input.connectHostHeader, 253) ? { connectHostHeader: string(input.connectHostHeader, 253)! } : {}),
    connectionAttempts: number(input.connectionAttempts) ?? -1,
    retryCount: number(input.retryCount) ?? -1,
    maximumRequests: number(input.maximumRequests) ?? -1,
    actualRequests: number(input.actualRequests) ?? -1,
    strictCertificateVerification: boolean(input.strictCertificateVerification),
    environmentProxyTrust: boolean(input.environmentProxyTrust),
    trustEnvironmentNames,
    trustEnvironmentScanComplete: boolean(input.trustEnvironmentScanComplete),
    trustOverridesForbidden: boolean(input.trustOverridesForbidden),
    rawConfigurationRetained: boolean(input.rawConfigurationRetained),
    rawSecretRetained: boolean(input.rawSecretRetained),
    secretDigestRetained: boolean(input.secretDigestRetained),
    ok: boolean(input.ok),
    startedAt: string(input.startedAt, 32) ?? new Date(0).toISOString(),
    completedAt: string(input.completedAt, 32) ?? new Date(0).toISOString(),
    ...(tlsEvidence(input.outerTls) ? { outerTls: tlsEvidence(input.outerTls)! } : {}),
    ...(responseEvidence(input.outerResponse) ? { outerResponse: responseEvidence(input.outerResponse)! } : {}),
    ...(responseEvidence(input.connectResponse) ? { connectResponse: responseEvidence(input.connectResponse)! } : {}),
    ...(typeof input.tunnelEstablished === "boolean" ? { tunnelEstablished: input.tunnelEstablished } : {}),
    ...(tlsEvidence(input.nestedTls) ? { nestedTls: tlsEvidence(input.nestedTls)! } : {}),
    ...(responseEvidence(input.nestedResponse) ? { nestedResponse: responseEvidence(input.nestedResponse)! } : {}),
    ...(typeof input.secretFileValidated === "boolean" ? { secretFileValidated: input.secretFileValidated } : {}),
    ...(number(input.secretFileMode) !== undefined ? { secretFileMode: number(input.secretFileMode)! } : {}),
    ...(number(input.secretBytes) !== undefined ? { secretBytes: number(input.secretBytes)! } : {}),
    ...(string(input.errorCode, 64) ? { errorCode: string(input.errorCode, 64)! } : {}),
    ...(string(input.errorSyscall, 64) ? { errorSyscall: string(input.errorSyscall, 64)! } : {}),
    ...(Number.isSafeInteger(input.errorErrno) ? { errorErrno: input.errorErrno as number } : {}),
  };
}

function emptyGuest(mode: Sbx038ProbeMode, caseId: string, runId: string): Sbx038GuestEvidence {
  return sanitizeGuest({}, mode, caseId, runId);
}

function transformPolicy(aHost: string, transformValue: string): NetworkPolicy {
  return {
    allow: {
      [aHost]: [{ transform: [{ headers: { [SBX038_TRANSFORM_HEADER]: transformValue } }] }],
    },
  };
}

function redactPolicy(value: unknown, secret: string): unknown {
  return JSON.parse(JSON.stringify(value).split(secret).join("[REDACTED]"));
}

async function policyProof(
  stage: "pre" | "post",
  sandbox: Sandbox,
  sessionId: string,
  credentials: Credentials,
  aHost: string,
  transformValue: string,
): Promise<Sbx038PolicyProof> {
  const activeSession = sandbox.currentSession();
  const independent = await Sandbox.get({ name: sandbox.name, resume: false, ...credentials, signal: signal() });
  const independentSession = independent.currentSession();
  const exact = exactTransformProjection(sandbox.networkPolicy, aHost) &&
    exactTransformPolicy(activeSession.networkPolicy, aHost, transformValue) &&
    exactTransformProjection(independent.networkPolicy, aHost) &&
    exactTransformPolicy(independentSession.networkPolicy, aHost, transformValue);
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

async function configureReceiver(origins: ControlledOrigins, key: string, config: Sbx038ReceiverConfiguration): Promise<void> {
  const response = await adminRequest(origins.a, key, `/v1/sbx038/admin/runs/${encodeURIComponent(config.runId)}`, {
    method: "PUT", body: JSON.stringify(config),
  });
  if (response.status !== 204) throw new Error(`receiver configuration returned ${response.status}`);
}

async function receiverSnapshot(a: URL, key: string, runId: string): Promise<Sbx038ReceiverSnapshot> {
  const response = await adminRequest(a, key, `/v1/sbx038/admin/runs/${encodeURIComponent(runId)}`);
  if (!response.ok) throw new Error(`receiver readback returned ${response.status}`);
  const value = await response.json() as Sbx038ReceiverSnapshot;
  if (!value.configured || !Array.isArray(value.aHttp) || !Array.isArray(value.aConnect) || !Array.isArray(value.b)) {
    throw new Error("receiver readback shape is invalid");
  }
  return value;
}

async function publicHealth(origin: URL, service: string): Promise<boolean> {
  const response = await fetch(new URL("/healthz", origin), { signal: signal(8_000), redirect: "error" });
  if (response.status !== 200) return false;
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > 1_024) return false;
  const body = object(JSON.parse(bytes.toString("utf8")));
  return body?.ok === true && body.service === service;
}

async function bTransportHealth(
  origin: URL,
  mode: Sbx038BTransportProof["mode"],
  clock: ChronologyClock,
): Promise<Sbx038BTransportProof> {
  return await new Promise((resolveProof, rejectProof) => {
    const request = httpsRequest({
      protocol: "https:",
      hostname: origin.hostname,
      port: 443,
      servername: origin.hostname,
      method: "GET",
      path: "/healthz",
      agent: false,
      rejectUnauthorized: true,
      signal: signal(8_000),
      headers: { host: origin.hostname, connection: "close", accept: "application/json" },
    }, (response) => {
      const socket = response.socket as tls.TLSSocket;
      const chunks: Buffer[] = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += Buffer.byteLength(chunk);
        if (size > 1_024) {
          request.destroy(new Error("B health response exceeded its byte bound"));
          return;
        }
        chunks.push(Buffer.from(chunk));
      });
      response.once("aborted", () => rejectProof(new Error("B health response aborted")));
      response.once("error", rejectProof);
      response.once("end", () => {
        try {
          if (!response.complete || response.statusCode !== 200 || !socket.authorized) {
            throw new Error("B strict TLS health response was not exact");
          }
          const body = object(JSON.parse(Buffer.concat(chunks).toString("utf8")));
          if (body?.ok !== true || body.service !== "sbx038-b-action-receiver") {
            throw new Error("B health service identity did not match");
          }
          const protocol = socket.getProtocol() ?? undefined;
          resolveProof({
            mode,
            host: origin.hostname,
            port: 443,
            tls: {
              servername: origin.hostname,
              authorized: true,
              ...(protocol ? { protocol } : {}),
              ...(socket.remoteAddress ? { remoteAddress: socket.remoteAddress } : {}),
              ...(socket.remotePort !== undefined ? { remotePort: socket.remotePort } : {}),
            },
            healthStatus: 200,
            healthServiceMatched: true,
            completedAt: clock.mark(),
          });
        } catch (error) {
          rejectProof(error);
        }
      });
    });
    request.once("error", rejectProof);
    request.end();
  });
}

export function sbx038RawConnectRequest(a: URL, runId: string, canary: string): string {
  return [
    `CONNECT ${a.hostname}:443 HTTP/1.1`,
    `Host: ${a.hostname}`,
    `X-SBX038-Run: ${runId}`,
    `X-SBX038-Case: infrastructure-connect-a-${runId.slice(0, 8)}`,
    `X-SBX038-Canary: ${canary}`,
    "Connection: close",
    "",
    "",
  ].join("\r\n");
}

async function rawConnectPreflight(a: URL, runId: string, canary: string): Promise<boolean> {
  return await new Promise((resolvePreflight) => {
    const socket = tls.connect({ host: a.hostname, port: 443, servername: a.hostname, rejectUnauthorized: true, ALPNProtocols: ["http/1.1"] });
    let received = Buffer.alloc(0);
    const finish = (value: boolean) => { socket.destroy(); resolvePreflight(value); };
    const timer = setTimeout(() => finish(false), 8_000);
    socket.once("secureConnect", () => {
      socket.write(sbx038RawConnectRequest(a, runId, canary));
    });
    socket.on("data", (chunk) => {
      received = Buffer.concat([received, Buffer.from(chunk)]);
      const end = received.indexOf("\r\n\r\n");
      if (received.length > 16_384) { clearTimeout(timer); finish(false); return; }
      if (end >= 0) {
        clearTimeout(timer);
        const head = received.subarray(0, end).toString("latin1").toLowerCase();
        finish(/^http\/1\.[01] 405 /u.test(head) && head.includes("\r\nx-sbx038-terminal: 1\r\n"));
      }
    });
    socket.once("error", () => { clearTimeout(timer); finish(false); });
  });
}

function probeConfiguration(input: {
  mode: Sbx038ProbeMode;
  caseId: string;
  origins: ControlledOrigins;
  runId: string;
  canary: string;
}) {
  const connect = input.mode.startsWith("connect-");
  const targetA = input.mode === "connect-a";
  const targetB = input.mode === "connect-b-public" || input.mode === "connect-b-secret";
  const outerHost = input.mode === "direct-b" ? input.origins.b.hostname : input.origins.a.hostname;
  const targetHost = targetA ? input.origins.a.hostname : targetB ? input.origins.b.hostname : undefined;
  const outerPath = input.mode === "normal-a"
    ? `/v1/sbx038/control/${encodeURIComponent(input.runId)}`
    : input.mode === "direct-b"
      ? `/v1/sbx038/direct/${encodeURIComponent(input.runId)}`
      : undefined;
  const nestedPath = targetA
    ? `/v1/sbx038/control/${encodeURIComponent(input.runId)}`
    : targetB
      ? `/v1/sbx038/action/${encodeURIComponent(input.runId)}`
      : undefined;
  return {
    scopeConfirmation: SCOPE_CONFIRMATION,
    researcherControlledHosts: [input.origins.a.hostname, input.origins.b.hostname],
    runId: input.runId,
    mode: input.mode,
    caseId: input.caseId,
    correlationCanary: input.canary,
    outerHost,
    outerPort: 443,
    ...(connect ? { targetHost, targetPort: 443, nestedPath } : { outerPath }),
    ...(input.mode === "connect-b-secret" ? { secretFilePath: REMOTE_SECRET_PATH } : {}),
    timeoutMs: 4_000,
    maxResponseBytes: 8_192,
  };
}

async function runGuest(
  sandbox: Sandbox,
  config: ReturnType<typeof probeConfiguration>,
  secrets: readonly string[],
): Promise<{ guest: Sbx038GuestEvidence; command: CommandEvidence }> {
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
    guest: sanitizeGuest(parsed, config.mode, config.caseId, config.runId),
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

export function sbx038SandboxPrefixListOptions(namePrefix: string): {
  namePrefix: string;
  limit: 10;
  sortBy: "name";
  sortOrder: "asc";
} {
  return { namePrefix, limit: 10, sortBy: "name", sortOrder: "asc" };
}

function sandboxProvenanceView(sandbox: Sandbox): Sbx038SandboxProvenanceView {
  return {
    name: sandbox.name,
    persistent: sandbox.persistent,
    ...(sandbox.tags === undefined ? {} : { tags: { ...sandbox.tags } }),
    currentSessionId: sandbox.currentSession().sessionId,
  };
}

async function sandboxByName(credentials: Credentials, name: string): Promise<Sandbox | undefined> {
  try {
    return await Sandbox.get({ name, resume: false, ...credentials, signal: signal(10_000) });
  } catch (error) {
    if (notFound(error)) return undefined;
    throw error;
  }
}

async function sandboxPrefixViews(
  credentials: Credentials,
  namePrefix: string,
): Promise<readonly Sbx038SandboxProvenanceView[]> {
  const paginator = await Sandbox.list({
    ...sbx038SandboxPrefixListOptions(namePrefix),
    ...credentials,
    signal: signal(10_000),
  });
  return (await paginator.toArray()).map((sandbox) => ({
    name: sandbox.name,
    persistent: sandbox.persistent,
    ...(sandbox.tags === undefined ? {} : { tags: { ...sandbox.tags } }),
    currentSessionId: sandbox.currentSessionId,
  }));
}

async function pathAbsent(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return false;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return true;
    throw error;
  }
}

async function localFinalizationProof(held: Sbx038HeldState): Promise<LocalFinalizationProof> {
  return {
    journalAbsent: await pathAbsent(held.journalPath),
    liveLockAbsent: await pathAbsent(held.lockPath),
    lockTransactionAbsent: await pathAbsent(`${held.lockPath}.transaction`),
  };
}

async function cleanupSandbox(input: {
  sandbox?: Sandbox;
  credentials: Credentials;
  journal: Sbx038Journal;
  held: Sbx038HeldState;
  resource: Sbx038ResourceJournal;
  secrets: readonly string[];
}): Promise<StageCleanup> {
  const errors: string[] = [];
  let target = input.sandbox;
  const persist = async () => persistSbx038Journal(input.held, input.journal);
  const finish = (): StageCleanup => sbx038StageCleanupProjection(input.resource, errors);
  if (input.resource.createAttemptedAt === undefined) return finish();
  try {
    target ??= await sandboxByName(input.credentials, input.resource.name);
    if (target !== undefined) {
      const view = sandboxProvenanceView(target);
      if (!exactSbx038SandboxProvenance(view, input.resource)) {
        errors.push("cleanup refused a sandbox with inexact provenance");
        return finish();
      }
      if (input.resource.sessionId === undefined) {
        input.resource.sessionId = view.currentSessionId;
        input.resource.provenanceValidated = true;
        input.resource.createResponseSettledAt ??= new Date().toISOString();
        await persist();
      }
    } else if (input.resource.sessionId === undefined &&
      !sbx038UnknownCreateSettlementReached(input.resource)) {
      errors.push("create response remained unsettled before the terminal recovery horizon");
      return finish();
    }

    if (target !== undefined && input.resource.secretWriteAttempted && !input.resource.secretNeutralized) {
      input.resource.secretNeutralizeAttempted = true;
      await persist();
      try {
        await target.writeFiles([{ path: REMOTE_SECRET_PATH, content: "", mode: 0o600 }], { signal: signal() });
        input.resource.secretNeutralized = true;
        await persist();
      } catch {
        // Exact deletion plus the delayed absence bracket below is also a
        // complete neutralization proof; retain the intent meanwhile.
      }
    }

    if (input.resource.sessionId !== undefined) {
      if (!input.resource.stopAttempted) {
        input.resource.stopAttempted = true;
        await persist();
      }
      if (target !== undefined && !input.resource.stopped) {
        try {
          await target.stop({ signal: signal() });
          input.resource.stopped = true;
          await persist();
        } catch {
          // A response-lost stop is resolved only by the later delete/absence proof.
        }
      }
      if (!input.resource.deleteAttempted) {
        input.resource.deleteAttempted = true;
        await persist();
      }
      if (target !== undefined && !input.resource.deleted) {
        try {
          await target.delete({ signal: signal() });
          input.resource.deleted = true;
          await persist();
        } catch {
          // A response-lost delete is resolved only by exact delayed absence.
        }
      }
    }

    const absent = await proveSbx038SandboxAbsence(input.journal, input.resource, {
      getSandbox: async (name) => await Sandbox.get({
        name,
        resume: false,
        ...input.credentials,
        signal: signal(10_000),
      }),
      listSandboxes: async (namePrefix) => sandboxPrefixViews(input.credentials, namePrefix),
      isNotFound: notFound,
      persist: async () => persist(),
    });
    if (!absent) {
      errors.push("exact delayed named and sorted-prefix sandbox absence was not proven");
      return finish();
    }
    if (input.resource.sessionId !== undefined) {
      input.resource.stopped = true;
      input.resource.deleted = true;
      if (input.resource.secretWriteAttempted) {
        input.resource.secretNeutralizeAttempted = true;
        input.resource.secretNeutralized = true;
      }
      await persist();
    }
  } catch (error) {
    errors.push(safeError(error, input.secrets));
  }
  return finish();
}

export function sbx038StageCleanupProjection(
  resource: Sbx038ResourceJournal,
  errors: readonly string[] = [],
): StageCleanup {
  return {
    secretOverwriteAttempted: resource.secretNeutralizeAttempted,
    secretOverwritten: !resource.secretWriteAttempted || resource.secretNeutralized,
    stopAttempted: resource.stopAttempted,
    stopped: resource.stopped || resource.absenceOnlyValidated,
    deleteAttempted: resource.deleteAttempted,
    deleted: resource.deleted,
    absenceChecks: resource.absenceChecks,
    absent: resource.absenceChecks >= 3 && resource.prefixListAbsent,
    prefixListAbsent: resource.prefixListAbsent,
    completedAt: new Date().toISOString(),
    errors: [...errors],
  };
}

function emptyReceiver(): Sbx038ReceiverSnapshot {
  return {
    configured: false,
    nextSequence: 0,
    infrastructureConnect: [],
    aHttp: [],
    aConnect: [],
    b: [],
    unexpected: [],
    secretRegistered: false,
  };
}

function stageReceiver(
  snapshot: Sbx038ReceiverSnapshot,
  cases: Readonly<{ directPre: string; normalA: string; connectA: string; connectB: string; directPost: string }>,
): Sbx038ReceiverSnapshot {
  const wanted = new Set(Object.values(cases));
  return {
    ...snapshot,
    infrastructureConnect: snapshot.infrastructureConnect.map((event) => ({ ...event })),
    aHttp: snapshot.aHttp.filter((event) => wanted.has(event.caseId)).map((event) => ({ ...event })),
    aConnect: snapshot.aConnect.filter((event) => wanted.has(event.caseId)).map((event) => ({ ...event })),
    b: snapshot.b.filter((event) => wanted.has(event.caseId)).map((event) => ({ ...event })),
    unexpected: snapshot.unexpected.map((event) => ({ ...event })),
  };
}

interface ChronologyClock { mark(): string }

function chronologyClock(): ChronologyClock {
  let previous = 0;
  return {
    mark(): string {
      previous = Math.max(Date.now(), previous + 1);
      return new Date(previous).toISOString();
    },
  };
}

function blankInterval(caseId: string): Sbx038StageChronology["infrastructurePreflight"] {
  const at = new Date(0).toISOString();
  return { caseId, startedAt: at, completedAt: at, receiverSequenceBefore: 0, receiverSequenceAfter: 0 };
}

async function runStage(input: {
  stage: Sbx038StageRole;
  runId: string;
  origins: ControlledOrigins;
  credentials: Credentials;
  transformValue: string;
  transformCommitment: string;
  adminKey: string;
  canary: string;
  identityAndScopePassed: boolean;
  infrastructurePreflightPassed: boolean;
  bTransportProof: Sbx038BTransportProof;
  receiverConfiguredAt: string;
  infrastructurePreflight: Sbx038StageChronology["infrastructurePreflight"];
  journal: Sbx038Journal;
  held: Sbx038HeldState;
  clock: ChronologyClock;
  secret?: string;
  secretCommitment?: string;
}): Promise<StageResult> {
  const resource = sbx038Resource(input.journal, input.stage);
  const cases = {
    directPre: `${input.stage}-direct-b-pre`,
    normalA: `${input.stage}-normal-a`,
    connectA: `${input.stage}-connect-a`,
    connectB: input.stage === "public" ? "public-connect-b" : "secret-connect-b",
    directPost: `${input.stage}-direct-b-post`,
  } as const;
  const modeB: Sbx038ProbeMode = input.stage === "public" ? "connect-b-public" : "connect-b-secret";
  const expectedAOperationId = deriveSbx038OperationId(input.adminKey, input.runId, cases.normalA, input.canary);
  const expectedBOperationId = deriveSbx038OperationId(
    input.adminKey,
    input.runId,
    cases.connectB,
    input.stage === "public" ? input.canary : input.secretCommitment ?? "unregistered",
  );
  let sandbox: Sandbox | undefined;
  let sessionId = "";
  let secretWritten = false;
  let executionError: string | undefined;
  let policyPre: Sbx038PolicyProof = {
    stage: "pre", initialSessionId: "", activeSessionId: "", independentSessionId: "",
    activeSandboxPolicy: {}, activeSessionPolicy: {}, independentSandboxPolicy: {}, independentSessionPolicy: {}, passed: false,
  };
  let policyPost: Sbx038PolicyProof = { ...policyPre, stage: "post" };
  let directBPre = emptyGuest("direct-b", cases.directPre, input.runId);
  let normalA = emptyGuest("normal-a", cases.normalA, input.runId);
  let connectA = emptyGuest("connect-a", cases.connectA, input.runId);
  let connectB = emptyGuest(modeB, cases.connectB, input.runId);
  let directBPost = emptyGuest("direct-b", cases.directPost, input.runId);
  let receiver = emptyReceiver();
  const commands: CommandEvidence[] = [];
  const intervals: Sbx038StageChronology["probes"] = [];
  let policyPreCompletedAt = new Date(0).toISOString();
  let policyPostCompletedAt = new Date(0).toISOString();
  let receiverReadAt = new Date(0).toISOString();
  const stageSecrets = [input.credentials.token, input.adminKey, input.transformValue, input.secret ?? ""].filter(Boolean);
  const persist = async () => persistSbx038Journal(input.held, input.journal);
  try {
    input.journal.phase = input.stage;
    resource.createAttemptedAt = new Date().toISOString();
    await persist();
    sandbox = await Sandbox.create({
      name: resource.name,
      persistent: resource.persistent,
      timeout: resource.timeoutMs,
      networkPolicy: transformPolicy(input.origins.a.hostname, input.transformValue),
      tags: resource.tags,
      ...input.credentials,
      signal: signal(SBX038_CREATE_REQUEST_TIMEOUT_MS),
    });
    resource.createResponseSettledAt = new Date().toISOString();
    await persist();
    const provenance = sandboxProvenanceView(sandbox);
    if (!exactSbx038SandboxProvenance(provenance, resource)) {
      throw new Error("sandbox create response failed exact provenance");
    }
    sessionId = provenance.currentSessionId;
    resource.sessionId = sessionId;
    resource.provenanceValidated = true;
    await persist();
    policyPre = await policyProof("pre", sandbox, sessionId, input.credentials, input.origins.a.hostname, input.transformValue);
    if (!policyPre.passed) throw new Error("exact active and independent transform-policy readbacks failed");
    policyPreCompletedAt = input.clock.mark();
    const source = await readFile(resolve("guest/connect-authority-probe.mjs"), "utf8");
    if (stageSecrets.some((secret) => source.includes(secret))) throw new Error("guest source contains controller-only material");
    await sandbox.writeFiles([{ path: REMOTE_PROBE_PATH, content: source, mode: 0o700 }], { signal: signal() });
    if (input.stage === "secret") {
      if (!input.secret || !input.secretCommitment) throw new Error("secret stage is missing its fresh synthetic secret");
      resource.secretWriteAttempted = true;
      await persist();
      await sandbox.writeFiles([{ path: REMOTE_SECRET_PATH, content: input.secret, mode: 0o600 }], { signal: signal() });
      secretWritten = true;
    }
    const order: Array<{ mode: Sbx038ProbeMode; caseId: string; assign(value: Sbx038GuestEvidence): void }> = [
      { mode: "direct-b", caseId: cases.directPre, assign: (value) => { directBPre = value; } },
      { mode: "normal-a", caseId: cases.normalA, assign: (value) => { normalA = value; } },
      { mode: "connect-a", caseId: cases.connectA, assign: (value) => { connectA = value; } },
      { mode: modeB, caseId: cases.connectB, assign: (value) => { connectB = value; } },
      { mode: "direct-b", caseId: cases.directPost, assign: (value) => { directBPost = value; } },
    ];
    for (let index = 0; index < order.length; index += 1) {
      const item = order[index]!;
      const before = await receiverSnapshot(input.origins.a, input.adminKey, input.runId);
      const startedAt = input.clock.mark();
      const result = await runGuest(sandbox, probeConfiguration({
        mode: item.mode, caseId: item.caseId, origins: input.origins, runId: input.runId, canary: input.canary,
      }), stageSecrets);
      item.assign(result.guest);
      commands.push(result.command);
      const after = await receiverSnapshot(input.origins.a, input.adminKey, input.runId);
      const completedAt = input.clock.mark();
      intervals.push({
        caseId: item.caseId,
        startedAt,
        completedAt,
        receiverSequenceBefore: before.nextSequence,
        receiverSequenceAfter: after.nextSequence,
      });
      if (index + 1 < order.length) await new Promise((resolveWait) => setTimeout(resolveWait, CASE_DELAY_MS));
    }
    policyPost = await policyProof("post", sandbox, sessionId, input.credentials, input.origins.a.hostname, input.transformValue);
    policyPostCompletedAt = input.clock.mark();
    await new Promise((resolveWait) => setTimeout(resolveWait, 1_000));
    const cumulative = await receiverSnapshot(input.origins.a, input.adminKey, input.runId);
    receiverReadAt = input.clock.mark();
    receiver = stageReceiver(cumulative, cases);
  } catch (error) {
    executionError = safeError(error, stageSecrets);
    while (intervals.length < 5) {
      const caseId = [cases.directPre, cases.normalA, cases.connectA, cases.connectB, cases.directPost][intervals.length]!;
      const startedAt = input.clock.mark();
      intervals.push({ caseId, startedAt, completedAt: input.clock.mark(), receiverSequenceBefore: receiver.nextSequence,
        receiverSequenceAfter: receiver.nextSequence });
    }
    if (Date.parse(policyPreCompletedAt) === 0) policyPreCompletedAt = input.clock.mark();
    if (Date.parse(policyPostCompletedAt) === 0) policyPostCompletedAt = input.clock.mark();
    try {
      receiver = stageReceiver(await receiverSnapshot(input.origins.a, input.adminKey, input.runId), cases);
    } catch { /* retain bounded empty snapshot */ }
    receiverReadAt = input.clock.mark();
  }
  const cleanup = await cleanupSandbox({
    ...(sandbox ? { sandbox } : {}),
    credentials: input.credentials,
    journal: input.journal,
    held: input.held,
    resource,
    secrets: stageSecrets,
  });
  cleanup.completedAt = input.clock.mark();
  const cleanupPassed = cleanup.secretOverwritten && cleanup.stopped && cleanup.deleted && cleanup.absent && cleanup.errors.length === 0;
  const chronology: Sbx038StageChronology = {
    receiverConfiguredAt: input.receiverConfiguredAt,
    infrastructurePreflight: input.infrastructurePreflight,
    policyPreCompletedAt,
    probes: intervals,
    policyPostCompletedAt,
    receiverReadAt,
    cleanupCompletedAt: cleanup.completedAt,
  };
  const assessmentInput: Sbx038StageInput = {
    stage: input.stage,
    runId: input.runId,
    aHost: input.origins.a.hostname,
    bHost: input.origins.b.hostname,
    expectedTransformCommitment: input.transformCommitment,
    expectedAOperationId,
    expectedBOperationId,
    identityAndScopePassed: input.identityAndScopePassed,
    infrastructurePreflightPassed: input.infrastructurePreflightPassed,
    policyPre,
    policyPost,
    directBPre,
    normalA,
    connectA,
    connectB,
    directBPost,
    receiver,
    bTransportProof: input.bTransportProof,
    chronology,
    cleanupPassed,
    ...(executionError ? { executionError: true } : {}),
  };
  return {
    input: assessmentInput,
    assessment: assessSbx038Stage(assessmentInput),
    sandbox: { name: resource.name, sessionId },
    commands,
    cleanup,
  };
}

async function cleanupReceiver(input: {
  origins: ControlledOrigins;
  adminKey: string;
  runId: string;
  journal: Sbx038Journal;
  held: Sbx038HeldState;
  secrets: readonly string[];
}): Promise<ReceiverCleanup> {
  const errors: string[] = [];
  const persist = async () => persistSbx038Journal(input.held, input.journal);
  if (!input.journal.receiverConfigureAttempted) {
    return { configureAttempted: false, configured: false, deleteAttempted: false, deleted: false,
      absenceChecks: 0, absent: true, errors };
  }
  input.journal.receiverDeleteAttempted = true;
  await persist();
  let deleteSettled = false;
  try {
    const response = await adminRequest(
      input.origins.a,
      input.adminKey,
      `/v1/sbx038/admin/runs/${encodeURIComponent(input.runId)}`,
      { method: "DELETE" },
    );
    deleteSettled = response.status === 204 || response.status === 404;
  } catch {
    // Exact repeated readback absence below resolves response loss.
  }
  input.journal.receiverAbsenceChecks = 0;
  for (const delay of RECEIVER_ABSENCE_DELAYS_MS) {
    await new Promise((resolveWait) => setTimeout(resolveWait, delay));
    try {
      const response = await adminRequest(
        input.origins.a,
        input.adminKey,
        `/v1/sbx038/admin/runs/${encodeURIComponent(input.runId)}`,
      );
      if (response.status !== 404) break;
      input.journal.receiverAbsenceChecks += 1;
      await persist();
    } catch {
      break;
    }
  }
  if (deleteSettled || input.journal.receiverAbsenceChecks >= 3) {
    input.journal.receiverDeleted = true;
    await persist();
  }
  const absent = input.journal.receiverAbsenceChecks >= 3;
  if (!input.journal.receiverDeleted || !absent) {
    errors.push("receiver delete and three exact absence readbacks were not proven");
  }
  return {
    configureAttempted: true,
    configured: input.journal.receiverConfigured,
    deleteAttempted: input.journal.receiverDeleteAttempted,
    deleted: input.journal.receiverDeleted,
    absenceChecks: input.journal.receiverAbsenceChecks,
    absent,
    errors: errors.map((value) => safeError(value, input.secrets)),
  };
}

function errorAssessment(summary: string, publicProof = false): Sbx038Assessment {
  return {
    verdict: "error",
    severity: "unknown",
    candidate: false,
    controlsPassed: false,
    publicTunnelProofValid: publicProof,
    secretReceiptProofValid: false,
    summary,
    signals: ["controller, infrastructure, or cleanup failure"],
  };
}

function assertSecretFree(value: unknown, secrets: readonly string[]): void {
  const serialized = JSON.stringify(value);
  if (secrets.some((secret) => secret.length > 0 && serialized.includes(secret))) {
    throw new Error("refusing to persist SBX-038 evidence containing controller-only material");
  }
}

const SBX038_PRIVATE_ARTIFACT_MAX_BYTES = 256 * 1024;

async function readExactPrivateArtifact(path: string): Promise<Record<string, unknown>> {
  if (await sbx038PrivateFileMode(path) !== 0o600) {
    throw new Error("SBX-038 finalization source was not mode 0600");
  }
  const before = await lstat(path, { bigint: true });
  const bytes = await readFile(path);
  const after = await lstat(path, { bigint: true });
  if (before.dev !== after.dev || before.ino !== after.ino || bytes.length < 2 ||
    bytes.length > SBX038_PRIVATE_ARTIFACT_MAX_BYTES || await sbx038PrivateFileMode(path) !== 0o600) {
    throw new Error("SBX-038 finalization source changed identity or exceeded its bound");
  }
  const value = object(JSON.parse(bytes.toString("utf8")));
  if (!value) throw new Error("SBX-038 finalization source was not an object");
  return value;
}

export function exactSbx038PendingNormalFinalization(value: unknown, runId: string): boolean {
  const record = object(value);
  return record !== undefined && SBX038_UUID.test(runId) && record.schemaVersion === 1 &&
    record.testId === SBX038_TEST_ID && record.runId === runId && record.recoveryOnly === undefined &&
    record.externalCleanupComplete === true && record.localFinalizationPending === true &&
    record.localFinalization === undefined;
}

export function exactSbx038PendingRecoveryFinalization(
  value: unknown,
  runId: string,
  attemptId: string,
): boolean {
  const record = object(value);
  return record !== undefined && SBX038_UUID.test(runId) && SBX038_UUID.test(attemptId) &&
    record.schemaVersion === 1 && record.testId === SBX038_TEST_ID && record.runId === runId &&
    record.recoveryAttemptId === attemptId && record.recoveryOnly === true &&
    record.outcome === "external-cleanup-complete" && record.localFinalizationPending === true &&
    record.localFinalization === undefined && Array.isArray(record.resourceCleanup) &&
    record.resourceCleanup.length === 2 && object(record.receiverCleanup) !== undefined;
}

async function finishOriginalArtifact(
  runId: string,
  directory: string,
  proof: LocalFinalizationProof,
): Promise<void> {
  const path = sbx038ArtifactPath(runId, directory);
  const current = await readExactPrivateArtifact(path);
  if (!Object.values(proof).every((value) => value === true) ||
    !exactSbx038PendingNormalFinalization(current, runId)) {
    throw new Error("SBX-038 original artifact was not an exact cleanup-complete pending finalization");
  }
  await finalizeSbx038Artifact(runId, {
    ...current,
    localFinalizationPending: false,
    localFinalization: proof,
    finalizedAt: new Date().toISOString(),
  }, directory);
}

async function pendingRecoveryFinalizations(
  runId: string,
  directory: string,
): Promise<Array<{ attemptId: string; value: Record<string, unknown> }>> {
  const prefix = `SBX-038-${runId}-recovery-`;
  const suffix = "-private.json";
  const pending: Array<{ attemptId: string; value: Record<string, unknown> }> = [];
  for (const name of (await readdir(directory)).sort()) {
    if (!name.startsWith(prefix) || !name.endsWith(suffix)) continue;
    const attemptId = name.slice(prefix.length, -suffix.length);
    if (!SBX038_UUID.test(attemptId)) {
      throw new Error("SBX-038 found a malformed same-run recovery artifact name");
    }
    const value = await readExactPrivateArtifact(sbx038RecoveryArtifactPath(runId, attemptId, directory));
    if (exactSbx038PendingRecoveryFinalization(value, runId, attemptId)) pending.push({ attemptId, value });
  }
  if (pending.length > 1) throw new Error("SBX-038 found multiple pending cleanup-recovery finalizations");
  return pending;
}

async function finishRecoveryArtifact(
  runId: string,
  attemptId: string,
  directory: string,
  proof: LocalFinalizationProof,
  supplied?: Record<string, unknown>,
): Promise<void> {
  const current = supplied ?? await readExactPrivateArtifact(sbx038RecoveryArtifactPath(runId, attemptId, directory));
  if (!Object.values(proof).every((value) => value === true) ||
    !exactSbx038PendingRecoveryFinalization(current, runId, attemptId)) {
    throw new Error("SBX-038 recovery artifact was not an exact cleanup-complete pending finalization");
  }
  await finalizeSbx038RecoveryArtifact(runId, attemptId, {
    ...current,
    outcome: "cleanup-complete",
    localFinalizationPending: false,
    localFinalization: proof,
    finalizedAt: new Date().toISOString(),
  }, directory);
}

interface ReleasedFinalizationSource {
  proof: LocalFinalizationProof;
  source: "normal" | "cleanup-recovery";
  original: Record<string, unknown>;
  recovery?: { attemptId: string; value: Record<string, unknown> };
}

async function releasedFinalizationSource(
  runId: string,
  directory: string,
): Promise<ReleasedFinalizationSource | undefined> {
  const proof: LocalFinalizationProof = {
    journalAbsent: await pathAbsent(sbx038JournalPath(runId, directory)),
    liveLockAbsent: await pathAbsent(sbx038LockPath(directory)),
    lockTransactionAbsent: await pathAbsent(`${sbx038LockPath(directory)}.transaction`),
  };
  if (!Object.values(proof).every((value) => value === true)) return undefined;
  let original: Record<string, unknown>;
  try {
    original = await readExactPrivateArtifact(sbx038ArtifactPath(runId, directory));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  const normalPending = exactSbx038PendingNormalFinalization(original, runId);
  const recoveryPending = await pendingRecoveryFinalizations(runId, directory);
  if (normalPending && recoveryPending.length === 0) return { proof, source: "normal", original };
  if (!normalPending && recoveryPending.length === 1) {
    return { proof, source: "cleanup-recovery", original, recovery: recoveryPending[0]! };
  }
  if (!normalPending && recoveryPending.length === 0) return undefined;
  throw new Error("SBX-038 released finalization requires exactly one pending cleanup-complete source");
}

export async function hasExactSbx038ReleasedFinalization(
  runId: string,
  directory: string,
): Promise<boolean> {
  if (!SBX038_UUID.test(runId)) return false;
  return await releasedFinalizationSource(runId, directory) !== undefined;
}

export async function completeSbx038ReleasedFinalization(
  runId: string,
  directory: string,
  completionAttemptId: string = randomUUID(),
): Promise<{ source: "normal" | "cleanup-recovery"; sourceRecoveryAttemptId?: string; proof: LocalFinalizationProof }> {
  if (!SBX038_UUID.test(runId) || !SBX038_UUID.test(completionAttemptId)) {
    throw new Error("SBX-038 released finalization requires UUIDv4 identities");
  }
  const released = await releasedFinalizationSource(runId, directory);
  if (!released) {
    throw new Error("SBX-038 refused local finalization before exact journal/lock/transaction absence");
  }
  const { proof, source } = released;
  let sourceRecoveryAttemptId: string | undefined;
  if (source === "normal") {
    await finishOriginalArtifact(runId, directory, proof);
  } else {
    sourceRecoveryAttemptId = released.recovery!.attemptId;
    await finishRecoveryArtifact(runId, sourceRecoveryAttemptId, directory, proof, released.recovery!.value);
  }
  await writeSbx038RecoveryArtifact(runId, completionAttemptId, {
    schemaVersion: 1,
    testId: SBX038_TEST_ID,
    runId,
    recoveryAttemptId: completionAttemptId,
    recoveryOnly: true,
    outcome: "release-finalization-complete",
    externalCalls: 0,
    cleanupAttempted: false,
    source,
    ...(sourceRecoveryAttemptId ? { sourceRecoveryAttemptId } : {}),
    localFinalizationPending: false,
    localFinalization: proof,
  }, directory);
  return { source, ...(sourceRecoveryAttemptId ? { sourceRecoveryAttemptId } : {}), proof };
}

export interface Sbx038RecoveryRuntime {
  newAttemptId?(): string;
  dispatch?(runId: string, directory: string): ReturnType<typeof dispatchSbx038Recovery>;
  acquireState?(runId: string, directory: string): ReturnType<typeof acquireSbx038RecoveryState>;
  readJournal?(runId: string, directory: string): ReturnType<typeof readSbx038Journal>;
  verifyIdentity?(): Promise<void>;
  afterRelease?(): Promise<void>;
}

export async function runSbx038Recovery(
  runId: string,
  directory: string,
  runtime: Sbx038RecoveryRuntime = {},
): Promise<void> {
  if (!SBX038_UUID.test(runId)) throw new Error("SBX038_RECOVERY_RUN_ID must be a canonical UUIDv4");
  const attemptId = runtime.newAttemptId?.() ?? randomUUID();
  if (!SBX038_UUID.test(attemptId)) throw new Error("SBX-038 recovery attempt ID must be a canonical UUIDv4");
  if (await hasExactSbx038ReleasedFinalization(runId, directory)) {
    await completeSbx038ReleasedFinalization(runId, directory, attemptId);
    return;
  }
  const dispatch = await (runtime.dispatch?.(runId, directory) ?? dispatchSbx038Recovery(runId, directory));
  if (dispatch !== "continue-journal-recovery") {
    if (dispatch === "release-finalization-complete") {
      await completeSbx038ReleasedFinalization(runId, directory, attemptId);
      return;
    }
    const proof: LocalFinalizationProof = {
      journalAbsent: await pathAbsent(sbx038JournalPath(runId, directory)),
      liveLockAbsent: await pathAbsent(sbx038LockPath(directory)),
      lockTransactionAbsent: await pathAbsent(`${sbx038LockPath(directory)}.transaction`),
    };
    await writeSbx038RecoveryArtifact(runId, attemptId, {
      schemaVersion: 1, testId: SBX038_TEST_ID, runId, recoveryAttemptId: attemptId,
      recoveryOnly: true, outcome: dispatch, externalCalls: 0, localFinalization: proof,
    }, directory);
    return;
  }

  const credentials = explicitCredentials();
  const origins = controlledOrigins();
  const adminKey = required(process.env, "SBX038_ADMIN_KEY");
  const secrets = [credentials.token, adminKey];
  const held = await (runtime.acquireState?.(runId, directory) ?? acquireSbx038RecoveryState(runId, directory));
  const journal = await (runtime.readJournal?.(runId, directory) ?? readSbx038Journal(runId, directory));
  await writeSbx038RecoveryArtifact(runId, attemptId, {
    schemaVersion: 1, testId: SBX038_TEST_ID, runId, recoveryAttemptId: attemptId,
    recoveryOnly: true, outcome: "cleanup-in-progress", localFinalizationPending: true,
  }, directory);
  let receiverCleanup: ReceiverCleanup | undefined;
  const resourceCleanup: StageCleanup[] = [];
  let failure: string | undefined;
  let released = false;
  try {
    if (runtime.verifyIdentity) await runtime.verifyIdentity();
    else {
      await verifyEligibleAliasToken({
        token: credentials.token,
        expectedEmail: ALIAS_EMAIL,
        expectedTeamId: TEAM_ID,
        expectedProjectId: PROJECT_ID,
        manualEmailConfirmation: process.env.SBX038_ALIAS_EMAIL_CONFIRMATION,
      });
    }
    for (const role of ["public", "secret"] as const) {
      resourceCleanup.push(await cleanupSandbox({
        credentials, journal, held, resource: sbx038Resource(journal, role), secrets,
      }));
    }
    journal.phase = "cleanup";
    await persistSbx038Journal(held, journal);
    receiverCleanup = await cleanupReceiver({ origins, adminKey, runId, journal, held, secrets });
    if (!sbx038JournalCleanupComplete(journal) || receiverCleanup.errors.length > 0 ||
      resourceCleanup.some((item) => item.errors.length > 0)) {
      throw new Error("SBX-038 recovery did not prove exact cleanup");
    }
    journal.phase = "completed";
    journal.completed = true;
    await persistSbx038Journal(held, journal);
    await finalizeSbx038RecoveryArtifact(runId, attemptId, {
      schemaVersion: 1, testId: SBX038_TEST_ID, runId, recoveryAttemptId: attemptId,
      recoveryOnly: true, outcome: "external-cleanup-complete", resourceCleanup, receiverCleanup,
      localFinalizationPending: true,
    }, directory);
    await releaseSbx038State(held);
    released = true;
    await runtime.afterRelease?.();
    const proof = await localFinalizationProof(held);
    if (!Object.values(proof).every(Boolean)) throw new Error("SBX-038 local recovery finalization was incomplete");
    await finishRecoveryArtifact(runId, attemptId, directory, proof);
  } catch (error) {
    failure = safeSbx038SafetyError(error, secrets);
    if (!released) {
      await held.liveLock.closeRetainingState().catch(() => undefined);
      await finalizeSbx038RecoveryArtifact(runId, attemptId, {
        schemaVersion: 1, testId: SBX038_TEST_ID, runId, recoveryAttemptId: attemptId,
        recoveryOnly: true, outcome: "cleanup-incomplete", resourceCleanup, receiverCleanup,
        localFinalizationPending: true, failure,
      }, directory);
    }
  }
  if (failure) throw new Error(failure);
}

export async function main(): Promise<void> {
  const directory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? SBX038_ARTIFACTS_DIRECTORY);
  const recoveryRunId = process.env.SBX038_RECOVERY_RUN_ID;
  if (recoveryRunId) {
    await runSbx038Recovery(recoveryRunId, directory);
    return;
  }

  const credentials = explicitCredentials();
  const origins = controlledOrigins();
  const adminKey = required(process.env, "SBX038_ADMIN_KEY");
  if (adminKey.length < 32) throw new Error("SBX038_ADMIN_KEY must contain at least 32 characters");
  const bTransportMode = sbx038BTransportMode();
  const journal = createSbx038Journal();
  const runId = journal.runId;
  const held = await acquireSbx038State(journal, directory);
  const clock = chronologyClock();
  const transformValue = `broker_${randomBytes(32).toString("base64url")}`;
  const transformCommitment = deriveSbx038TransformCommitment(adminKey, runId, transformValue);
  const canary = `corr_${randomBytes(18).toString("base64url")}`;
  const sensitiveValues = [credentials.token, adminKey, transformValue];
  let operatorSecret: string | undefined;
  let secretCommitment: string | undefined;
  let receiverConfiguredAt = new Date(0).toISOString();
  let infrastructurePreflightPassed = false;
  let bTransportProof: Sbx038BTransportProof | undefined;
  let infrastructurePreflight = blankInterval(`infrastructure-connect-a-${runId.slice(0, 8)}`);
  let identityAndScopePassed = false;
  let publicStage: StageResult | undefined;
  let secretStage: StageResult | undefined;
  let crossStageIdentityPassed: boolean | undefined;
  let receiverCleanup: ReceiverCleanup = {
    configureAttempted: false, configured: false, deleteAttempted: false, deleted: false,
    absenceChecks: 0, absent: true, errors: [],
  };
  let finalAssessment = errorAssessment("SBX-038 did not start.");
  let executionError: string | undefined;

  await writeSbx038Checkpoint(runId, {
    schemaVersion: 1, testId: SBX038_TEST_ID, runId, startedAt: journal.startedAt,
    outcome: "in-progress", localFinalizationPending: true,
    retention: { token: false, adminKey: false, transformValue: false, operatorSecret: false },
  }, directory);
  try {
    await verifyEligibleAliasToken({
      token: credentials.token,
      expectedEmail: ALIAS_EMAIL,
      expectedTeamId: TEAM_ID,
      expectedProjectId: PROJECT_ID,
      manualEmailConfirmation: process.env.SBX038_ALIAS_EMAIL_CONFIRMATION,
    });
    if (!(await publicHealth(origins.a, "sbx038-a-terminal-receiver"))) {
      throw new Error("owned A receiver health check failed");
    }
    bTransportProof = await bTransportHealth(origins.b, bTransportMode, clock);
    journal.receiverConfigureAttempted = true;
    await persistSbx038Journal(held, journal);
    await configureReceiver(origins, adminKey, {
      runId,
      aHost: origins.a.hostname,
      bHost: origins.b.hostname,
      correlationCanary: canary,
      transformHeaderCommitment: transformCommitment,
    });
    journal.receiverConfigured = true;
    await persistSbx038Journal(held, journal);
    receiverConfiguredAt = clock.mark();
    const beforeInfrastructure = await receiverSnapshot(origins.a, adminKey, runId);
    const infrastructureStartedAt = clock.mark();
    infrastructurePreflightPassed = await rawConnectPreflight(origins.a, runId, canary);
    const afterInfrastructure = await receiverSnapshot(origins.a, adminKey, runId);
    const infrastructureCompletedAt = clock.mark();
    infrastructurePreflight = {
      caseId: `infrastructure-connect-a-${runId.slice(0, 8)}`,
      startedAt: infrastructureStartedAt,
      completedAt: infrastructureCompletedAt,
      receiverSequenceBefore: beforeInfrastructure.nextSequence,
      receiverSequenceAfter: afterInfrastructure.nextSequence,
    };
    if (!infrastructurePreflightPassed) {
      throw new Error("A did not preserve raw CONNECT to the terminal receiver");
    }
    identityAndScopePassed = true;
    publicStage = await runStage({
      stage: "public", runId, origins, credentials, transformValue, transformCommitment, adminKey, canary,
      identityAndScopePassed, infrastructurePreflightPassed, bTransportProof,
      receiverConfiguredAt, infrastructurePreflight,
      journal, held, clock,
    });
    finalAssessment = publicStage.assessment;
    if (publicStage.assessment.verdict === "candidate-medium") {
      operatorSecret = `opsec_${randomBytes(48).toString("base64url")}`;
      sensitiveValues.push(operatorSecret);
      secretCommitment = deriveSbx038SecretCommitment(adminKey, runId, operatorSecret);
      const registration = await adminRequest(origins.a, adminKey,
        `/v1/sbx038/admin/secrets/${encodeURIComponent(runId)}`, {
          method: "PUT", body: JSON.stringify({ secretCommitment }),
        });
      if (!registration.ok) throw new Error(`secret commitment registration returned ${registration.status}`);
      const registrationBody = await registration.json() as { operationId?: unknown };
      if (registrationBody.operationId !== deriveSbx038OperationId(adminKey, runId, "secret-connect-b", secretCommitment)) {
        throw new Error("receiver secret registration operation mismatch");
      }
      secretStage = await runStage({
        stage: "secret", runId, origins, credentials, transformValue, transformCommitment, adminKey, canary,
        identityAndScopePassed, infrastructurePreflightPassed, bTransportProof,
        receiverConfiguredAt, infrastructurePreflight,
        journal, held, clock, secret: operatorSecret, secretCommitment,
      });
      operatorSecret = undefined;
      crossStageIdentityPassed = publicStage.sandbox.name !== secretStage.sandbox.name &&
        publicStage.sandbox.sessionId.length > 0 && secretStage.sandbox.sessionId.length > 0 &&
        publicStage.sandbox.sessionId !== secretStage.sandbox.sessionId;
      finalAssessment = combineSbx038Assessments(publicStage.assessment, secretStage.assessment, {
        public: publicStage.sandbox, secret: secretStage.sandbox,
      });
    }
  } catch (error) {
    executionError = safeError(error, sensitiveValues);
    finalAssessment = errorAssessment(executionError, publicStage?.assessment.publicTunnelProofValid ?? false);
  } finally {
    operatorSecret = undefined;
    journal.phase = "cleanup";
    await persistSbx038Journal(held, journal).catch((error) => {
      executionError ??= safeError(error, sensitiveValues);
    });
    try {
      receiverCleanup = await cleanupReceiver({ origins, adminKey, runId, journal, held, secrets: sensitiveValues });
    } catch (error) {
      receiverCleanup.errors.push(safeError(error, sensitiveValues));
    }
  }

  const externalCleanupComplete = sbx038JournalCleanupComplete(journal) && receiverCleanup.errors.length === 0;
  if (!externalCleanupComplete) finalAssessment = errorAssessment(
    "SBX-038 exact sandbox or receiver cleanup remains incomplete.",
    finalAssessment.publicTunnelProofValid,
  );
  const evidence = {
    schemaVersion: 1,
    testId: SBX038_TEST_ID,
    runId,
    startedAt: journal.startedAt,
    completedAt: clock.mark(),
    assessment: finalAssessment,
    credentialContext: { aliasEmail: ALIAS_EMAIL, teamId: TEAM_ID, projectId: PROJECT_ID, tokenStored: false },
    origins: { a: origins.a.origin, b: origins.b.origin },
    infrastructure: {
      rawConnectTerminalPreflightPassed: infrastructurePreflightPassed,
      infrastructurePreflight,
      bTransportProof,
    },
    publicStage,
    ...(secretStage ? { secretStage } : {}),
    ...(crossStageIdentityPassed === undefined ? {} : { crossStageIdentityPassed }),
    receiverCleanup,
    externalCleanupComplete,
    localFinalizationPending: true,
    retention: {
      rawTransformValue: false, rawOperatorSecret: false, rawGuestConfiguration: false,
      rawCommandOutput: false, rawSecretBody: false, plainSecretDigest: false,
      secretCommitmentHmacOnly: secretCommitment !== undefined,
    },
    ...(executionError ? { executionError } : {}),
  };
  assertSecretFree(evidence, sensitiveValues);
  await finalizeSbx038Artifact(runId, evidence, directory);
  let localFinalization: LocalFinalizationProof | undefined;
  if (externalCleanupComplete) {
    journal.phase = "completed";
    journal.completed = true;
    await persistSbx038Journal(held, journal);
    await releaseSbx038State(held);
    localFinalization = await localFinalizationProof(held);
    if (!Object.values(localFinalization).every(Boolean)) {
      throw new Error("SBX-038 local lock/journal finalization was incomplete");
    }
    await finishOriginalArtifact(runId, directory, localFinalization);
  } else {
    await held.liveLock.closeRetainingState();
  }
  process.stdout.write(`${JSON.stringify({
    testId: SBX038_TEST_ID, runId, assessment: finalAssessment,
    externalCleanupComplete, localFinalization, evidencePath: sbx038ArtifactPath(runId, directory),
  }, null, 2)}\n`);
  if (finalAssessment.verdict === "error" || finalAssessment.verdict === "indeterminate") {
    throw new Error(finalAssessment.summary);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
