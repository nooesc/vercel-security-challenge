import "dotenv/config";

import { randomBytes, randomUUID } from "node:crypto";
import { resolve4 } from "node:dns/promises";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import tls from "node:tls";
import { APIError, Sandbox, type NetworkPolicy } from "@vercel/sandbox";
import type { Sbx040ReceiverConfiguration } from "./receiver.js";
import {
  SBX040_TEST_ID,
  SBX040_TRANSFORM_HEADER,
  assessSbx040Stage,
  combineSbx040Assessments,
  deriveSbx040Commitment,
  exactTransformPolicy,
  exactTransformProjection,
  type Sbx040Assessment,
  type Sbx040GuestEvidence,
  type Sbx040PolicyProof,
  type Sbx040ProbeMode,
  type Sbx040ReceiverSnapshot,
  type Sbx040Stage,
  type Sbx040StageInput,
} from "./verdict.js";

const ALIAS_EMAIL = "swve@wearehackerone.com";
const TEAM_ID = "team_n98ERpVwV7HqmWRudAyK8sXQ";
const PROJECT_ID = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
const SCOPE_CONFIRMATION = "I_CONTROL_BOTH_SBX040_VIRTUAL_HOSTS_AND_AUTHORIZE_BOUNDED_HTTP1_DESYNC_TESTING";
const REMOTE_PROBE_PATH = "/tmp/sbx-040/http1-desync-probe.mjs";
const CASE_DELAY_MS = 300;
const CONTROL_TIMEOUT_MS = 30_000;
const OUTPUT_LIMIT = 24 * 1024;

interface Credentials {
  token: string;
  teamId: string;
  projectId: string;
}

interface Origins {
  a: URL;
  b: URL;
  admin: URL;
}

interface CommandEvidence {
  caseId: string;
  commandId: string;
  exitCode: number;
  stdoutBytes: number;
  stderrBytes: number;
  rawOutputRetained: false;
}

interface CleanupEvidence {
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  absenceChecks: number;
  absent: boolean;
  receiverDeleteAttempted: boolean;
  receiverDeleted: boolean;
  receiverAbsent: boolean;
  errors: string[];
}

interface StageResult {
  input: Sbx040StageInput;
  assessment: Sbx040Assessment;
  commands: CommandEvidence[];
  cleanup: CleanupEvidence;
  infrastructure: {
    sameDirectIpv4Set: boolean;
    rawAValidated: boolean;
    rawBValidated: boolean;
  };
  executionError?: string;
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function signal(timeoutMs = CONTROL_TIMEOUT_MS): AbortSignal {
  return AbortSignal.timeout(timeoutMs);
}

function exactHttpsOrigin(raw: string, name: string): URL {
  const origin = new URL(raw);
  if (origin.protocol !== "https:" || raw !== origin.origin || origin.port || origin.username || origin.password ||
    origin.pathname !== "/" || origin.search || origin.hash || origin.hostname !== origin.hostname.toLowerCase() ||
    isIP(origin.hostname) !== 0) throw new Error(`${name} must be an exact lower-case HTTPS origin on port 443`);
  return origin;
}

function exactAdminOrigin(raw: string): URL {
  const origin = new URL(raw);
  if (origin.protocol !== "http:" || raw !== origin.origin || origin.hostname !== "127.0.0.1" ||
    !origin.port || origin.username || origin.password || origin.pathname !== "/" || origin.search || origin.hash) {
    throw new Error("SBX040_ADMIN_ORIGIN must be an exact loopback HTTP origin with an explicit port");
  }
  return origin;
}

export function controlledOrigins(environment: NodeJS.ProcessEnv = process.env): Origins {
  if (environment.SBX040_SCOPE_CONFIRMATION !== SCOPE_CONFIRMATION) {
    throw new Error(`SBX040_SCOPE_CONFIRMATION must equal ${SCOPE_CONFIRMATION}`);
  }
  const a = exactHttpsOrigin(environment.SBX040_A_PUBLIC_ORIGIN ?? "", "SBX040_A_PUBLIC_ORIGIN");
  const b = exactHttpsOrigin(environment.SBX040_B_PUBLIC_ORIGIN ?? "", "SBX040_B_PUBLIC_ORIGIN");
  if (a.origin === b.origin) throw new Error("SBX-040 requires distinct A and B virtual-host origins");
  return { a, b, admin: exactAdminOrigin(environment.SBX040_ADMIN_ORIGIN ?? "") };
}

export function explicitCredentials(environment: NodeJS.ProcessEnv = process.env): Credentials {
  const token = required(environment, "VERCEL_TOKEN");
  if (environment.VERCEL_TEAM_ID !== TEAM_ID || environment.VERCEL_PROJECT_ID !== PROJECT_ID) {
    throw new Error("SBX-040 requires the verified HackerOne-alias team and project");
  }
  return { token, teamId: TEAM_ID, projectId: PROJECT_ID };
}

async function verifyAlias(token: string): Promise<void> {
  const response = await fetch("https://api.vercel.com/v2/user", {
    headers: { authorization: `Bearer ${token}` },
    signal: signal(10_000),
    redirect: "error",
  });
  if (!response.ok) throw new Error(`Vercel alias verification returned ${response.status}`);
  const body = await response.json() as { user?: { email?: unknown } };
  if (body.user?.email !== ALIAS_EMAIL) throw new Error("Vercel token is not authenticated as the HackerOne alias");
}

function safeError(error: unknown, secrets: readonly string[]): string {
  let message = error instanceof Error ? error.message : String(error);
  for (const secret of secrets) if (secret) message = message.split(secret).join("[REDACTED]");
  return message.replace(/[\0\r\n]/gu, " ").slice(0, 1_000);
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function boundedString(value: unknown, maximum = 512): string | undefined {
  return typeof value === "string" && value.length <= maximum && !/[\0\r\n]/u.test(value) ? value : undefined;
}

function finite(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function responseEvidence(value: unknown): Sbx040GuestEvidence["firstResponse"] {
  const input = object(value);
  const statusCode = finite(input?.statusCode);
  const bodyBytes = finite(input?.bodyBytes);
  if (!input || statusCode === undefined || bodyBytes === undefined) return undefined;
  return {
    statusCode,
    bodyBytes,
    ...(boundedString(input.operationId, 96) ? { operationId: boundedString(input.operationId, 96)! } : {}),
    ...(typeof input.terminalHeader === "boolean" ? { terminalHeader: input.terminalHeader } : {}),
  };
}

export function sanitizeGuest(value: unknown, mode: Sbx040ProbeMode, caseId: string): Sbx040GuestEvidence {
  const input = object(value) ?? {};
  const observedMode = boundedString(input.mode, 64);
  return {
    schemaVersion: finite(input.schemaVersion) ?? -1,
    testId: boundedString(input.testId, 64) ?? "",
    caseId: boundedString(input.caseId, 128) ?? caseId,
    mode: observedMode && ["direct-b", "normal-a", "host-b", "cl-only", "te-only", "ambiguous-alone", "ambiguous-plus-a"].includes(observedMode)
      ? observedMode as Sbx040ProbeMode
      : mode,
    outerHost: boundedString(input.outerHost, 253) ?? "",
    outerPort: finite(input.outerPort) ?? -1,
    firstHost: boundedString(input.firstHost, 253) ?? "",
    connectionAttempts: finite(input.connectionAttempts) ?? -1,
    retryCount: finite(input.retryCount) ?? -1,
    maximumRequests: finite(input.maximumRequests) ?? -1,
    actualRequests: finite(input.actualRequests) ?? -1,
    tlsHandshakes: finite(input.tlsHandshakes) ?? -1,
    strictCertificateVerification: input.strictCertificateVerification === true,
    environmentProxyTrust: input.environmentProxyTrust === true,
    rawConfigurationRetained: input.rawConfigurationRetained === true,
    rawCredentialRetained: input.rawCredentialRetained === true,
    ok: input.ok === true,
    ...(responseEvidence(input.firstResponse) ? { firstResponse: responseEvidence(input.firstResponse)! } : {}),
    ...(responseEvidence(input.secondResponse) ? { secondResponse: responseEvidence(input.secondResponse)! } : {}),
    ...(boundedString(input.errorCode, 64) ? { errorCode: boundedString(input.errorCode, 64)! } : {}),
    ...(boundedString(input.errorSyscall, 64) ? { errorSyscall: boundedString(input.errorSyscall, 64)! } : {}),
  };
}

function emptyGuest(mode: Sbx040ProbeMode, caseId: string): Sbx040GuestEvidence {
  return sanitizeGuest({}, mode, caseId);
}

function transformPolicy(aHost: string, credential: string): NetworkPolicy {
  return { allow: { [aHost]: [{ transform: [{ headers: { [SBX040_TRANSFORM_HEADER]: credential } }] }] } };
}

function redactPolicy(value: unknown, credential: string): unknown {
  return JSON.parse(JSON.stringify(value).split(credential).join("[REDACTED]"));
}

function emptyPolicyProof(stage: "pre" | "post"): Sbx040PolicyProof {
  return {
    stage,
    initialSessionId: "",
    activeSessionId: "",
    independentSessionId: "",
    activeSandboxPolicy: {},
    activeSessionPolicy: {},
    independentSandboxPolicy: {},
    independentSessionPolicy: {},
    activeSandboxProjectionExact: false,
    activeSessionTransformExact: false,
    independentSandboxProjectionExact: false,
    independentSessionTransformExact: false,
    passed: false,
  };
}

async function policyProof(
  stage: "pre" | "post",
  sandbox: Sandbox,
  sessionId: string,
  credentials: Credentials,
  aHost: string,
  credential: string,
): Promise<Sbx040PolicyProof> {
  const activeSession = sandbox.currentSession();
  const independent = await Sandbox.get({ name: sandbox.name, resume: false, ...credentials, signal: signal() });
  const independentSession = independent.currentSession();
  const activeSandboxProjectionExact = exactTransformProjection(sandbox.networkPolicy, aHost);
  const activeSessionTransformExact = exactTransformPolicy(activeSession.networkPolicy, aHost, credential);
  const independentSandboxProjectionExact = exactTransformProjection(independent.networkPolicy, aHost);
  const independentSessionTransformExact = exactTransformPolicy(independentSession.networkPolicy, aHost, credential);
  const sameSession = activeSession.sessionId === sessionId && independentSession.sessionId === sessionId;
  return {
    stage,
    initialSessionId: sessionId,
    activeSessionId: activeSession.sessionId,
    independentSessionId: independentSession.sessionId,
    activeSandboxPolicy: redactPolicy(sandbox.networkPolicy, credential),
    activeSessionPolicy: redactPolicy(activeSession.networkPolicy, credential),
    independentSandboxPolicy: redactPolicy(independent.networkPolicy, credential),
    independentSessionPolicy: redactPolicy(independentSession.networkPolicy, credential),
    activeSandboxProjectionExact,
    activeSessionTransformExact,
    independentSandboxProjectionExact,
    independentSessionTransformExact,
    passed: activeSandboxProjectionExact && activeSessionTransformExact && independentSandboxProjectionExact &&
      independentSessionTransformExact && sameSession,
  };
}

async function adminRequest(origin: URL, key: string, path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set("authorization", `Bearer ${key}`);
  if (init.body) headers.set("content-type", "application/json");
  return fetch(new URL(path, origin), { ...init, headers, signal: signal(10_000), redirect: "error" });
}

async function configureReceiver(origin: URL, key: string, config: Sbx040ReceiverConfiguration): Promise<void> {
  const response = await adminRequest(origin, key, `/v1/sbx040/admin/runs/${encodeURIComponent(config.runId)}`, {
    method: "PUT",
    body: JSON.stringify(config),
  });
  if (response.status !== 204) throw new Error(`receiver configuration returned ${response.status}`);
}

async function receiverSnapshot(origin: URL, key: string, runId: string): Promise<Sbx040ReceiverSnapshot> {
  const response = await adminRequest(origin, key, `/v1/sbx040/admin/runs/${encodeURIComponent(runId)}`);
  if (!response.ok) throw new Error(`receiver readback returned ${response.status}`);
  const value = await response.json() as Sbx040ReceiverSnapshot;
  if (!value.configured || !Array.isArray(value.requests) || !Array.isArray(value.bActions) ||
    value.rawCredentialRetained !== false) throw new Error("receiver readback shape is invalid");
  return value;
}

function publicIpv4(address: string): boolean {
  const octets = address.split(".").map(Number);
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return false;
  const [a, b] = octets;
  return a !== 0 && a !== 10 && a !== 127 && !(a === 169 && b === 254) && !(a === 172 && b! >= 16 && b! <= 31) &&
    !(a === 192 && b === 168) && a! < 224;
}

async function exactSharedIpv4(aHost: string, bHost: string): Promise<boolean> {
  const [a, b] = await Promise.all([resolve4(aHost), resolve4(bHost)]);
  const aa = [...new Set(a)].sort();
  const bb = [...new Set(b)].sort();
  return aa.length > 0 && aa.every(publicIpv4) && bb.every(publicIpv4) &&
    aa.length === bb.length && aa.every((address, index) => address === bb[index]);
}

function rawPreflight(host: string, runId: string, caseId: string, canary: string): Promise<boolean> {
  return new Promise((resolveResult) => {
    const socket = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: true, ALPNProtocols: ["http/1.1"] });
    let bytes = Buffer.alloc(0);
    let done = false;
    const finish = (result: boolean) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket.destroy();
      resolveResult(result);
    };
    const timer = setTimeout(() => finish(false), 8_000);
    socket.once("secureConnect", () => socket.write([
      `GET /v1/sbx040/${runId}/health HTTP/1.1`,
      `Host: ${host}`,
      `X-SBX040-Case: ${caseId}`,
      `X-SBX040-Canary: ${canary}`,
      "Connection: close",
      "",
      "",
    ].join("\r\n")));
    socket.on("data", (chunk) => {
      bytes = Buffer.concat([bytes, Buffer.from(chunk)]);
      if (bytes.length > 16_384) return finish(false);
      const end = bytes.indexOf("\r\n\r\n");
      if (end < 0) return;
      const head = bytes.subarray(0, end).toString("latin1").toLowerCase();
      finish(/^http\/1\.[01] 204 /u.test(head) && head.includes("\r\nx-sbx040-raw-terminal: 1\r\n"));
    });
    socket.once("error", () => finish(false));
  });
}

export function probeConfiguration(input: {
  mode: Sbx040ProbeMode;
  caseId: string;
  runId: string;
  canary: string;
  aHost: string;
  bHost: string;
}) {
  return {
    scopeConfirmation: SCOPE_CONFIRMATION,
    mode: input.mode,
    runId: input.runId,
    caseId: input.caseId,
    canary: input.canary,
    aHost: input.aHost,
    bHost: input.bHost,
    outerHost: input.mode === "direct-b" ? input.bHost : input.aHost,
    outerPort: 443,
    timeoutMs: 5_000,
  };
}

async function runGuest(
  sandbox: Sandbox,
  config: ReturnType<typeof probeConfiguration>,
  secrets: readonly string[],
): Promise<{ guest: Sbx040GuestEvidence; command: CommandEvidence }> {
  const serialized = JSON.stringify(config);
  if (secrets.some((secret) => secret && serialized.includes(secret))) {
    throw new Error("guest configuration contains a controller-only credential");
  }
  const command = await sandbox.runCommand({
    cmd: "node",
    args: [REMOTE_PROBE_PATH, Buffer.from(serialized).toString("base64url")],
    timeoutMs: 20_000,
  });
  const [stdout, stderr] = await Promise.all([
    command.stdout({ signal: signal() }),
    command.stderr({ signal: signal() }),
  ]);
  if (Buffer.byteLength(stdout) > OUTPUT_LIMIT || Buffer.byteLength(stderr) > OUTPUT_LIMIT) {
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
      stdoutBytes: Buffer.byteLength(stdout),
      stderrBytes: Buffer.byteLength(stderr),
      rawOutputRetained: false,
    },
  };
}

function notFound(error: unknown): boolean {
  return error instanceof APIError && error.response.status === 404;
}

async function cleanup(
  sandbox: Sandbox | undefined,
  credentials: Credentials,
  origins: Origins,
  adminKey: string,
  receiverConfigured: boolean,
  runId: string,
  secrets: readonly string[],
): Promise<CleanupEvidence> {
  const result: CleanupEvidence = {
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    absenceChecks: 0,
    absent: false,
    receiverDeleteAttempted: false,
    receiverDeleted: false,
    receiverAbsent: false,
    errors: [],
  };
  if (sandbox) {
    result.stopAttempted = true;
    try { await sandbox.stop({ signal: signal() }); result.stopped = true; }
    catch (error) { result.errors.push(`stop: ${safeError(error, secrets)}`); }
    result.deleteAttempted = true;
    try { await sandbox.delete({ signal: signal() }); result.deleted = true; }
    catch (error) { result.errors.push(`delete: ${safeError(error, secrets)}`); }
    for (let index = 0; index < 3; index += 1) {
      try {
        await Sandbox.get({ name: sandbox.name, resume: false, ...credentials, signal: signal(8_000) });
        result.errors.push(`absence check ${index + 1}: sandbox still exists`);
      } catch (error) {
        if (notFound(error)) result.absenceChecks += 1;
        else result.errors.push(`absence check ${index + 1}: ${safeError(error, secrets)}`);
      }
    }
    result.absent = result.absenceChecks === 3;
  }
  if (receiverConfigured) {
    result.receiverDeleteAttempted = true;
    try {
      const deleted = await adminRequest(origins.admin, adminKey, `/v1/sbx040/admin/runs/${encodeURIComponent(runId)}`, { method: "DELETE" });
      result.receiverDeleted = deleted.status === 204;
      const absent = await adminRequest(origins.admin, adminKey, `/v1/sbx040/admin/runs/${encodeURIComponent(runId)}`);
      result.receiverAbsent = absent.status === 404;
    } catch (error) {
      result.errors.push(`receiver cleanup: ${safeError(error, secrets)}`);
    }
  }
  return result;
}

async function runStage(input: {
  stage: Sbx040Stage;
  rootRunId: string;
  origins: Origins;
  credentials: Credentials;
  adminKey: string;
  credential: string;
  sameDirectIpv4Set: boolean;
}): Promise<StageResult> {
  const runId = `${input.rootRunId}-${input.stage}`;
  const sandboxName = `sbx-040-${input.stage}-${input.rootRunId.slice(0, 8)}`;
  const canary = `corr_${randomBytes(18).toString("base64url")}`;
  const caseIds: Sbx040StageInput["caseIds"] = {
    "direct-b": `${runId}:direct-b-pre`,
    "normal-a": `${runId}:normal-a`,
    "host-b": `${runId}:host-b`,
    "cl-only": `${runId}:cl-only`,
    "te-only": `${runId}:te-only`,
    "ambiguous-alone": `${runId}:ambiguous-alone`,
    "ambiguous-plus-a": `${runId}:ambiguous-plus-a`,
    "direct-b-post": `${runId}:direct-b-post`,
  };
  const guests: Sbx040StageInput["guests"] = {
    "direct-b": emptyGuest("direct-b", caseIds["direct-b"]),
    "normal-a": emptyGuest("normal-a", caseIds["normal-a"]),
    "host-b": emptyGuest("host-b", caseIds["host-b"]),
    "cl-only": emptyGuest("cl-only", caseIds["cl-only"]),
    "te-only": emptyGuest("te-only", caseIds["te-only"]),
    "ambiguous-alone": emptyGuest("ambiguous-alone", caseIds["ambiguous-alone"]),
    "ambiguous-plus-a": emptyGuest("ambiguous-plus-a", caseIds["ambiguous-plus-a"]),
    "direct-b-post": emptyGuest("direct-b", caseIds["direct-b-post"]),
  };
  const commands: CommandEvidence[] = [];
  const secrets = [input.credentials.token, input.adminKey, input.credential];
  let receiverConfigured = false;
  let rawAValidated = false;
  let rawBValidated = false;
  let sandbox: Sandbox | undefined;
  let sessionId = "";
  let policyPre = emptyPolicyProof("pre");
  let policyPost = emptyPolicyProof("post");
  let receiver: Sbx040ReceiverSnapshot = { configured: false, requests: [], bActions: [], rawCredentialRetained: false };
  let executionError: string | undefined;
  try {
    await configureReceiver(input.origins.admin, input.adminKey, {
      runId,
      aHost: input.origins.a.hostname,
      bHost: input.origins.b.hostname,
      canary,
      credentialCommitment: deriveSbx040Commitment(input.adminKey, runId, input.credential),
    });
    receiverConfigured = true;
    rawAValidated = await rawPreflight(input.origins.a.hostname, runId, `${runId}:infra-a`, canary);
    rawBValidated = await rawPreflight(input.origins.b.hostname, runId, `${runId}:infra-b`, canary);
    const preflightSnapshot = await receiverSnapshot(input.origins.admin, input.adminKey, runId);
    const aEvent = preflightSnapshot.requests.find((event) => event.caseId === `${runId}:infra-a`);
    const bEvent = preflightSnapshot.requests.find((event) => event.caseId === `${runId}:infra-b`);
    rawAValidated = rawAValidated && aEvent?.role === "a" && aEvent.sni === input.origins.a.hostname;
    rawBValidated = rawBValidated && bEvent?.role === "b" && bEvent.sni === input.origins.b.hostname;
    if (!input.sameDirectIpv4Set || !rawAValidated || !rawBValidated) {
      throw new Error("A/B must resolve to the same direct raw TLS origin and both terminal preflights must pass");
    }
    sandbox = await Sandbox.create({
      name: sandboxName,
      persistent: false,
      timeout: 240_000,
      networkPolicy: transformPolicy(input.origins.a.hostname, input.credential),
      tags: { harness: "vsc", test: "SBX-040", run: input.rootRunId.slice(0, 12), stage: input.stage },
      ...input.credentials,
      signal: signal(45_000),
    });
    sessionId = sandbox.currentSession().sessionId;
    policyPre = await policyProof("pre", sandbox, sessionId, input.credentials, input.origins.a.hostname, input.credential);
    if (!policyPre.passed) throw new Error("exact active and independent transform-policy readbacks failed");
    const source = await readFile(resolve("guest/http1-desync-probe.mjs"), "utf8");
    if (secrets.some((secret) => source.includes(secret))) throw new Error("guest source contains controller-only material");
    await sandbox.writeFiles([{ path: REMOTE_PROBE_PATH, content: source, mode: 0o700 }], { signal: signal() });
    const order: Array<{ key: keyof typeof guests; mode: Sbx040ProbeMode }> = [
      { key: "direct-b", mode: "direct-b" },
      { key: "normal-a", mode: "normal-a" },
      { key: "host-b", mode: "host-b" },
      { key: "cl-only", mode: "cl-only" },
      { key: "te-only", mode: "te-only" },
      { key: "ambiguous-alone", mode: "ambiguous-alone" },
      { key: "ambiguous-plus-a", mode: "ambiguous-plus-a" },
      { key: "direct-b-post", mode: "direct-b" },
    ];
    for (let index = 0; index < order.length; index += 1) {
      const item = order[index]!;
      const result = await runGuest(sandbox, probeConfiguration({
        mode: item.mode,
        caseId: caseIds[item.key],
        runId,
        canary,
        aHost: input.origins.a.hostname,
        bHost: input.origins.b.hostname,
      }), secrets);
      guests[item.key] = result.guest;
      commands.push(result.command);
      if (index + 1 < order.length) await new Promise((resolveWait) => setTimeout(resolveWait, CASE_DELAY_MS));
    }
    policyPost = await policyProof("post", sandbox, sessionId, input.credentials, input.origins.a.hostname, input.credential);
    await new Promise((resolveWait) => setTimeout(resolveWait, 750));
    receiver = await receiverSnapshot(input.origins.admin, input.adminKey, runId);
  } catch (error) {
    executionError = safeError(error, secrets);
    if (receiverConfigured) {
      try { receiver = await receiverSnapshot(input.origins.admin, input.adminKey, runId); } catch { /* retain bounded empty snapshot */ }
    }
  }
  const cleanupEvidence = await cleanup(
    sandbox,
    input.credentials,
    input.origins,
    input.adminKey,
    receiverConfigured,
    runId,
    secrets,
  );
  const cleanupPassed = cleanupEvidence.stopped && cleanupEvidence.deleted && cleanupEvidence.absent &&
    cleanupEvidence.receiverDeleted && cleanupEvidence.receiverAbsent && cleanupEvidence.errors.length === 0;
  const stageInput: Sbx040StageInput = {
    stage: input.stage,
    runId,
    sandboxName,
    sessionId,
    aHost: input.origins.a.hostname,
    bHost: input.origins.b.hostname,
    canary,
    caseIds,
    guests,
    receiver,
    policyPre,
    policyPost,
    cleanupPassed,
  };
  return {
    input: stageInput,
    assessment: assessSbx040Stage(stageInput),
    commands,
    cleanup: cleanupEvidence,
    infrastructure: { sameDirectIpv4Set: input.sameDirectIpv4Set, rawAValidated, rawBValidated },
    ...(executionError ? { executionError } : {}),
  };
}

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  const rootRunId = randomUUID();
  const credentials = explicitCredentials();
  const origins = controlledOrigins();
  const adminKey = required(process.env, "SBX040_ADMIN_KEY");
  if (adminKey.length < 32 || /[\0\r\n]/u.test(adminKey)) throw new Error("SBX040_ADMIN_KEY must be a strong bounded value");
  const artifacts = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  await mkdir(artifacts, { recursive: true, mode: 0o700 });
  const sensitive = [credentials.token, adminKey];
  let publicCredential: string | undefined;
  let secretCredential: string | undefined;
  let publicStage: StageResult | undefined;
  let secretStage: StageResult | undefined;
  let executionError: string | undefined;
  try {
    await verifyAlias(credentials.token);
    const sameDirectIpv4Set = await exactSharedIpv4(origins.a.hostname, origins.b.hostname);
    if (!sameDirectIpv4Set) throw new Error("A and B do not resolve to one exact shared set of public IPv4 addresses");
    publicCredential = `public_${randomBytes(24).toString("base64url")}`;
    sensitive.push(publicCredential);
    publicStage = await runStage({
      stage: "public",
      rootRunId,
      origins,
      credentials,
      adminKey,
      credential: publicCredential,
      sameDirectIpv4Set,
    });
    publicCredential = undefined;
    if (publicStage.assessment.candidate) {
      secretCredential = `credential_${randomBytes(48).toString("base64url")}`;
      sensitive.push(secretCredential);
      secretStage = await runStage({
        stage: "secret",
        rootRunId,
        origins,
        credentials,
        adminKey,
        credential: secretCredential,
        sameDirectIpv4Set,
      });
      secretCredential = undefined;
    }
  } catch (error) {
    executionError = safeError(error, sensitive);
  } finally {
    publicCredential = undefined;
    secretCredential = undefined;
  }
  const combined = publicStage
    ? combineSbx040Assessments(publicStage.input, publicStage.assessment, secretStage?.input, secretStage?.assessment)
    : {
      outcome: "inconclusive" as const,
      candidate: false,
      severityCeiling: "none" as const,
      rationale: executionError ?? "SBX-040 did not start",
      distinctFreshSandboxes: false,
    };
  const evidence = {
    schemaVersion: 1,
    testId: SBX040_TEST_ID,
    rootRunId,
    startedAt,
    completedAt: new Date().toISOString(),
    assessment: combined,
    credentialContext: { aliasEmail: ALIAS_EMAIL, teamId: TEAM_ID, projectId: PROJECT_ID, tokenStored: false },
    origins: { a: origins.a.origin, b: origins.b.origin, sameRawOriginRequired: true },
    publicStage,
    ...(secretStage ? { secretStage } : {}),
    retention: {
      rawTransformCredential: false,
      transformCredentialDigest: false,
      transformCredentialHmacOnlyAtReceiver: true,
      rawGuestConfiguration: false,
      rawCommandOutput: false,
      rawReceiverHeaders: false,
      rawReceiverBodies: false,
    },
    rateLimit: { caseDelayMs: CASE_DELAY_MS, maximumStartedCasesPerSecond: 4 },
    ...(executionError ? { executionError } : {}),
  };
  const serialized = `${JSON.stringify(evidence, null, 2)}\n`;
  if (sensitive.some((value) => value && serialized.includes(value))) {
    throw new Error("refusing to persist evidence containing controller-only material");
  }
  const evidencePath = resolve(artifacts, `SBX-040-${rootRunId}-private.json`);
  await writeFile(evidencePath, serialized, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify({
    testId: SBX040_TEST_ID,
    rootRunId,
    assessment: combined,
    publicStage: publicStage?.assessment,
    secretStage: secretStage?.assessment,
    evidencePath,
    ...(executionError ? { executionError } : {}),
  }, null, 2)}\n`);
  if (executionError || combined.outcome === "inconclusive") throw new Error(executionError ?? combined.rationale);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
