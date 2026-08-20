import "dotenv/config";

import { execFile as execFileCallback } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Resolver } from "node:dns/promises";
import { mkdir, open, readFile, unlink, writeFile, type FileHandle } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import { Sandbox, type NetworkPolicy } from "@vercel/sandbox";
import { verifyEligibleAliasToken } from "../eligible-alias-identity.js";
import {
  SBX043_PUBLIC_CASES,
  SBX043_TEST_ID,
  assessSbx043Public,
  deriveSbx043GreetingTag,
  deriveSbx043PublicOperationId,
  exactSbx043PolicyReadback,
  type Sbx043PolicyReadback,
  type Sbx043ProbeEvidence,
  type Sbx043ProbeMode,
  type Sbx043ReceiverStatus,
  type Sbx043RetentionEvidence,
} from "./verdict.js";

const execFile = promisify(execFileCallback);
export const SBX043_SCOPE_CONFIRMATION =
  "I_CONTROL_DISTINCT_ALLOWED_AND_DENIED_ENDPOINTS_AND_AUTHORIZE_BOUNDED_SMTP_STARTTLS_TESTING";
export const SBX043_ALLOWED_HTTPS_ORIGIN = "https://vsc-h3-action-swve.cyrus-206.workers.dev";
const eligibleAliasEmail = "swve@wearehackerone.com";
const eligibleTeamId = "team_n98ERpVwV7HqmWRudAyK8sXQ";
const eligibleProjectId = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
const remoteProbePath = "/tmp/sbx-043/smtp-starttls-probe.py";
const guestOutputLimit = 16_384;

interface Credentials { token: string; teamId: string; projectId: string }
interface Topology {
  allowedOrigin: URL;
  allowedAddresses: string[];
  deniedHostname: string;
  deniedIPv4: string;
  deniedAddresses: string[];
  deniedPort: number;
  adminOrigin: URL;
  adminKey: string;
  configurationEpoch: string;
}
interface CleanupEvidence { stopAttempted: boolean; stopped: boolean; deleteAttempted: boolean; deleted: boolean; errors: string[] }
interface Runtime { name: string; sandbox?: Sandbox; sessionId?: string; cleanup: CleanupEvidence }
interface CommandEvidence { source: "controller-preflight" | "sandbox"; commandId?: string; exitCode: number; stdoutBytes: number; stderrBytes: number; rawOutputRetained: false }
interface CaseEvidence { caseId: string; configurationSha256: string; command: CommandEvidence; result: Sbx043ProbeEvidence; receiver: Sbx043ReceiverStatus; receiverCaseDeleted: boolean }

class RateGate {
  #lastAt = 0;
  async beforeProbe(): Promise<void> {
    const wait = 300 - (Date.now() - this.#lastAt);
    if (wait > 0) await delay(wait);
    this.#lastAt = Date.now();
  }
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("expected an object");
  return value as Record<string, unknown>;
}

function sha256(value: string | Buffer): string { return createHash("sha256").update(value).digest("hex"); }
function signal(timeoutMs = 30_000): AbortSignal { return AbortSignal.timeout(timeoutMs); }

function safeError(error: unknown, secrets: readonly string[]): string {
  let output = error instanceof Error ? error.message : String(error);
  for (const secret of secrets) if (secret) output = output.split(secret).join("[REDACTED]");
  return output.replace(/[\0\r\n]/gu, " ").slice(0, 1_000);
}

export function explicitSbx043Credentials(environment: NodeJS.ProcessEnv = process.env): Credentials {
  const token = required(environment, "VERCEL_TOKEN");
  const teamId = required(environment, "VERCEL_TEAM_ID");
  const projectId = required(environment, "VERCEL_PROJECT_ID");
  if (teamId !== eligibleTeamId || projectId !== eligibleProjectId) throw new Error("SBX-043 must use the verified HackerOne-alias Vercel team and project");
  return { token, teamId, projectId };
}

export function publicSbx043IPv4(value: string): boolean {
  if (isIP(value) !== 4 || value.split(".").some((part) => !/^(?:0|[1-9][0-9]{0,2})$/u.test(part))) return false;
  const [a = -1, b = -1, c = -1] = value.split(".").map(Number);
  return a > 0 && a < 224 && a !== 10 && a !== 127 && !(a === 172 && b >= 16 && b <= 31) &&
    !(a === 192 && b === 168) && !(a === 169 && b === 254) && !(a === 100 && b >= 64 && b <= 127) &&
    !(a === 192 && b === 0) && !(a === 198 && (b === 18 || b === 19)) &&
    !(a === 198 && b === 51 && c === 100) && !(a === 203 && b === 0 && c === 113);
}

function canonicalHostname(value: string, field: string): string {
  const pattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
  if (value !== value.toLowerCase() || isIP(value) !== 0 || !pattern.test(value)) throw new Error(`${field} must be a canonical lowercase DNS hostname`);
  return value;
}

async function resolve4(hostname: string): Promise<string[]> {
  const resolver = new Resolver();
  const cancel = setTimeout(() => resolver.cancel(), 10_000);
  try { return [...new Set((await resolver.resolve4(hostname)).filter(publicSbx043IPv4))].sort(); }
  finally { clearTimeout(cancel); }
}

async function adminRequest(topology: Pick<Topology, "adminOrigin" | "adminKey">, path: string, method: "GET" | "POST" | "DELETE", body?: unknown): Promise<Record<string, unknown>> {
  const response = await fetch(new URL(path, topology.adminOrigin), {
    method,
    headers: { Authorization: `Bearer ${topology.adminKey}`, ...(body === undefined ? {} : { "content-type": "application/json" }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    redirect: "error",
    signal: signal(10_000),
  });
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > 64 * 1024) throw new Error("receiver admin response exceeded its bound");
  const parsed = object(JSON.parse(bytes.toString("utf8")));
  if (!response.ok) throw new Error(`receiver ${method} ${path} returned ${response.status}`);
  return parsed;
}

async function loadTopology(environment: NodeJS.ProcessEnv): Promise<Topology> {
  if (environment.SBX043_SCOPE_CONFIRMATION !== SBX043_SCOPE_CONFIRMATION) throw new Error(`SBX043_SCOPE_CONFIRMATION must equal ${SBX043_SCOPE_CONFIRMATION}`);
  const allowedOrigin = new URL(required(environment, "SBX043_ALLOWED_HTTPS_ORIGIN"));
  if (allowedOrigin.origin !== SBX043_ALLOWED_HTTPS_ORIGIN || allowedOrigin.pathname !== "/" || allowedOrigin.search || allowedOrigin.hash) throw new Error(`SBX043_ALLOWED_HTTPS_ORIGIN must equal ${SBX043_ALLOWED_HTTPS_ORIGIN}`);
  const deniedHostname = canonicalHostname(required(environment, "SBX043_DENIED_HOSTNAME"), "SBX043_DENIED_HOSTNAME");
  const deniedIPv4 = required(environment, "SBX043_DENIED_IPV4");
  if (!publicSbx043IPv4(deniedIPv4)) throw new Error("SBX043_DENIED_IPV4 must be canonical public IPv4");
  const deniedPort = Number(environment.SBX043_DENIED_PORT ?? "587");
  if (!Number.isInteger(deniedPort) || deniedPort < 1 || deniedPort > 65_535 || deniedPort === 25) throw new Error("SBX043_DENIED_PORT must be a valid non-25 port (587 recommended)");
  const adminOrigin = new URL(required(environment, "SBX043_ADMIN_ORIGIN"));
  if (adminOrigin.protocol !== "http:" || adminOrigin.hostname !== "127.0.0.1" || adminOrigin.pathname !== "/" || adminOrigin.search || adminOrigin.hash) throw new Error("SBX043_ADMIN_ORIGIN must be an exact loopback HTTP origin");
  const adminKey = required(environment, "SBX043_ADMIN_KEY");
  if (adminKey.length < 32 || adminKey.length > 512 || /[\0\r\n]/u.test(adminKey)) throw new Error("SBX043_ADMIN_KEY is invalid");
  const [allowedAddresses, deniedAddresses] = await Promise.all([resolve4(allowedOrigin.hostname), resolve4(deniedHostname)]);
  if (allowedAddresses.length === 0 || deniedAddresses.length === 0 || !deniedAddresses.includes(deniedIPv4)) throw new Error("owned endpoint DNS did not resolve to the pinned public IPv4");
  if (allowedAddresses.some((address) => deniedAddresses.includes(address))) throw new Error("SBX-043 requires disjoint A and B IPv4 sets");
  const healthResponse = await fetch(new URL("/healthz", adminOrigin), { redirect: "error", signal: signal(10_000) });
  const health = object(await healthResponse.json());
  const listener = object(health.listener);
  const configurationEpoch = typeof health.configurationEpoch === "string" ? health.configurationEpoch : "";
  if (!healthResponse.ok || health.ok !== true || health.testId !== SBX043_TEST_ID || health.tlsReady !== true ||
      listener.hostname !== deniedHostname || listener.ipv4 !== deniedIPv4 || listener.port !== deniedPort ||
      !/^[0-9a-f-]{36}$/u.test(configurationEpoch)) throw new Error("receiver health did not bind exact B/TLS identity");
  return { allowedOrigin, allowedAddresses, deniedHostname, deniedIPv4, deniedAddresses, deniedPort, adminOrigin, adminKey, configurationEpoch };
}

export function buildSbx043ProbeConfiguration(input: {
  mode: Sbx043ProbeMode; runId: string; caseId: string; endpointHostname: string;
  endpointRole: "allowed" | "denied"; pinnedIPv4?: string; pinnedPort: number;
  publicCanary?: string; greetingTag?: string;
}): Record<string, unknown> {
  return {
    scopeConfirmation: SBX043_SCOPE_CONFIRMATION, mode: input.mode, runId: input.runId, testId: SBX043_TEST_ID,
    caseId: input.caseId, endpointRole: input.endpointRole, endpointHostname: input.endpointHostname,
    ...(input.pinnedIPv4 ? { pinnedIPv4: input.pinnedIPv4 } : {}), pinnedPort: input.pinnedPort,
    ...(input.publicCanary ? { publicCanary: input.publicCanary } : {}),
    ...(input.greetingTag ? { greetingTag: input.greetingTag } : {}), timeoutMs: 3_000, maxResponseBytes: 1_024,
  };
}

function casePath(runId: string, caseId: string): string { return `/v1/sbx043/admin/cases/${runId}/${caseId}`; }

async function registerPublicCase(topology: Topology, runId: string, caseId: string, mode: Exclude<Sbx043ProbeMode, "https-control" | "smtp-starttls-secret">, canary: string): Promise<{ greetingTag: string; operationId: string }> {
  const now = Date.now();
  const response = await adminRequest(topology, casePath(runId, caseId), "POST", {
    runId, caseId, phase: "public", mode, endpointBaseHostname: topology.deniedHostname,
    notBefore: new Date(now - 2_000).toISOString(), notAfter: new Date(now + 5 * 60_000).toISOString(),
    expectedPublicCanary: canary,
  });
  const greetingTag = typeof response.greetingTag === "string" ? response.greetingTag : "";
  const operationId = typeof response.expectedOperationId === "string" ? response.expectedOperationId : "";
  if (response.configured !== true || response.configurationEpoch !== topology.configurationEpoch ||
      greetingTag !== deriveSbx043GreetingTag(topology.adminKey, runId, caseId) ||
      operationId !== deriveSbx043PublicOperationId(topology.adminKey, runId, caseId, canary)) throw new Error("receiver registration identifiers were not exact");
  return { greetingTag, operationId };
}

async function executeProbe(sourcePath: string, configuration: Record<string, unknown>, gate: RateGate, forbidden: readonly string[], sandbox?: Sandbox): Promise<{ command: CommandEvidence; result: Sbx043ProbeEvidence }> {
  await gate.beforeProbe();
  const encoded = Buffer.from(JSON.stringify(configuration)).toString("base64url");
  if (!sandbox) {
    const capture = await execFile("python3", [sourcePath, encoded], { maxBuffer: guestOutputLimit });
    if (forbidden.some((value) => value && (capture.stdout.includes(value) || capture.stderr.includes(value)))) throw new Error("probe output contained forbidden material");
    return { command: { source: "controller-preflight", exitCode: 0, stdoutBytes: Buffer.byteLength(capture.stdout), stderrBytes: Buffer.byteLength(capture.stderr), rawOutputRetained: false }, result: object(JSON.parse(capture.stdout)) as unknown as Sbx043ProbeEvidence };
  }
  const command = await sandbox.runCommand({ cmd: "python3", args: [remoteProbePath, encoded], timeoutMs: 12_000 });
  const [stdout, stderr] = await Promise.all([command.stdout({ signal: signal() }), command.stderr({ signal: signal() })]);
  if (Buffer.byteLength(stdout) > guestOutputLimit || Buffer.byteLength(stderr) > guestOutputLimit || forbidden.some((value) => value && (stdout.includes(value) || stderr.includes(value)))) throw new Error("guest output was unsafe or oversized");
  return { command: { source: "sandbox", commandId: command.cmdId, exitCode: command.exitCode, stdoutBytes: Buffer.byteLength(stdout), stderrBytes: Buffer.byteLength(stderr), rawOutputRetained: false }, result: object(JSON.parse(stdout)) as unknown as Sbx043ProbeEvidence };
}

async function receiverCase(input: { topology: Topology; runId: string; caseId: string; mode: "direct-tls" | "raw-public" | "smtp-starttls-public"; canary: string; sourcePath: string; gate: RateGate; forbidden: string[]; sandbox?: Sandbox }): Promise<CaseEvidence> {
  const registered = await registerPublicCase(input.topology, input.runId, input.caseId, input.mode, input.canary);
  let receiverCaseDeleted = false;
  let captured: Omit<CaseEvidence, "receiverCaseDeleted"> | undefined;
  try {
    const configuration = buildSbx043ProbeConfiguration({ mode: input.mode, runId: input.runId, caseId: input.caseId,
      endpointHostname: input.topology.deniedHostname, endpointRole: "denied", pinnedIPv4: input.topology.deniedIPv4,
      pinnedPort: input.topology.deniedPort, publicCanary: input.canary,
      ...(input.mode === "smtp-starttls-public" ? { greetingTag: registered.greetingTag } : {}) });
    const executed = await executeProbe(input.sourcePath, configuration, input.gate, [...input.forbidden, input.canary], input.sandbox);
    await delay(350);
    const receiver = await adminRequest(input.topology, casePath(input.runId, input.caseId), "GET") as unknown as Sbx043ReceiverStatus;
    captured = { caseId: input.caseId, configurationSha256: sha256(JSON.stringify(configuration)), command: executed.command, result: executed.result, receiver };
  } finally {
    const response = await adminRequest(input.topology, casePath(input.runId, input.caseId), "DELETE");
    receiverCaseDeleted = response.deleted === true;
  }
  if (!captured || !receiverCaseDeleted) throw new Error(`receiver case ${input.caseId} was incomplete`);
  return { ...captured, receiverCaseDeleted };
}

async function httpsCase(topology: Topology, runId: string, sandbox: Sandbox, sourcePath: string, gate: RateGate, forbidden: string[]): Promise<Sbx043ProbeEvidence> {
  return (await executeProbe(sourcePath, buildSbx043ProbeConfiguration({ mode: "https-control", runId,
    caseId: SBX043_PUBLIC_CASES.allowedHttps, endpointHostname: topology.allowedOrigin.hostname,
    endpointRole: "allowed", pinnedPort: 443 }), gate, forbidden, sandbox)).result;
}

async function createSandbox(runtime: Runtime, policy: NetworkPolicy, credentials: Credentials, probeSource: string): Promise<void> {
  runtime.sandbox = await Sandbox.create({ name: runtime.name, persistent: false, timeout: 300_000, networkPolicy: policy,
    tags: { harness: "vsc", test: SBX043_TEST_ID }, signal: signal(45_000), ...credentials });
  runtime.sessionId = runtime.sandbox.currentSession().sessionId;
  await runtime.sandbox.writeFiles([{ path: remoteProbePath, content: probeSource, mode: 0o700 }], { signal: signal() });
}

async function policyReadback(runtime: Runtime, credentials: Credentials, expected: "allow-all" | { allowedHostname: string }): Promise<Sbx043PolicyReadback> {
  if (!runtime.sandbox || !runtime.sessionId) throw new Error("sandbox runtime was incomplete");
  const active = runtime.sandbox.currentSession();
  const independent = await Sandbox.get({ name: runtime.name, resume: false, signal: signal(), ...credentials });
  const independentSession = independent.currentSession();
  return exactSbx043PolicyReadback({ initialSessionId: runtime.sessionId, activeSessionId: active.sessionId,
    independentSessionId: independentSession.sessionId, activeSandboxPolicy: runtime.sandbox.networkPolicy,
    activeSessionPolicy: active.networkPolicy, independentSandboxPolicy: independent.networkPolicy,
    independentSessionPolicy: independentSession.networkPolicy }, expected);
}

function cleanup(): CleanupEvidence { return { stopAttempted: false, stopped: false, deleteAttempted: false, deleted: false, errors: [] }; }
async function cleanupSandbox(runtime: Runtime, secrets: string[]): Promise<void> {
  if (!runtime.sandbox) return;
  runtime.cleanup.stopAttempted = true;
  try { await runtime.sandbox.stop({ signal: signal() }); runtime.cleanup.stopped = true; } catch (error) { runtime.cleanup.errors.push(`stop: ${safeError(error, secrets)}`); }
  runtime.cleanup.deleteAttempted = true;
  try { await runtime.sandbox.delete({ signal: signal() }); runtime.cleanup.deleted = true; } catch (error) { runtime.cleanup.errors.push(`delete: ${safeError(error, secrets)}`); }
}
function clean(value: CleanupEvidence): boolean { return value.stopAttempted && value.stopped && value.deleteAttempted && value.deleted && value.errors.length === 0; }
function retention(): Sbx043RetentionEvidence { return { rawOperatorSecret: false, rawGuestConfiguration: false, rawCommandStdout: false, rawCommandStderr: false, rawSmtpTranscript: false, rawEhlo: false, rawSecretInArtifact: false, secretDigestInArtifact: false }; }

async function main(): Promise<void> {
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  const lockPath = resolve(artifactsDirectory, "SBX-043-live-active.lock");
  const credentials = explicitSbx043Credentials();
  const secrets = [credentials.token, required(process.env, "SBX043_ADMIN_KEY")];
  let lock: FileHandle | undefined;
  let artifactPath = resolve(artifactsDirectory, `SBX-043-public-${Date.now()}.json`);
  const evidence: Record<string, unknown> = { schemaVersion: 1, testId: SBX043_TEST_ID, startedAt: new Date().toISOString(), liveRunExecuted: true, publicCanaryOnly: true, secretStage: { executed: false, reason: "requires independent review of a public candidate" } };
  try {
    await mkdir(artifactsDirectory, { recursive: true });
    lock = await open(lockPath, "wx", 0o600);
    await verifyEligibleAliasToken({ token: credentials.token, expectedEmail: eligibleAliasEmail, expectedTeamId: eligibleTeamId,
      expectedProjectId: eligibleProjectId, manualEmailConfirmation: process.env.SBX043_ALIAS_EMAIL_CONFIRMATION });
    const topology = await loadTopology(process.env);
    const runId = randomUUID();
    artifactPath = resolve(artifactsDirectory, `SBX-043-public-${runId}.json`);
    evidence.runId = runId;
    evidence.topology = { allowedHostname: topology.allowedOrigin.hostname, allowedAddresses: topology.allowedAddresses,
      deniedHostname: topology.deniedHostname, deniedAddresses: topology.deniedAddresses,
      deniedPinnedIPv4: topology.deniedIPv4, deniedPort: topology.deniedPort, configurationEpoch: topology.configurationEpoch };
    const probePath = resolve("guest/smtp-starttls-probe.py");
    const probeSource = await readFile(probePath, "utf8");
    const canaries = Object.fromEntries(Object.values(SBX043_PUBLIC_CASES).filter((id) => id !== SBX043_PUBLIC_CASES.allowedHttps).map((id) => [id, randomBytes(16).toString("hex")]));
    const operations = Object.fromEntries(Object.entries(canaries).map(([id, value]) => [id, deriveSbx043PublicOperationId(topology.adminKey, runId, id, value)]));
    const gate = new RateGate();
    const common = { topology, runId, sourcePath: probePath, gate, forbidden: secrets };
    const outside = await receiverCase({ ...common, caseId: SBX043_PUBLIC_CASES.outsideSmtp, mode: "smtp-starttls-public", canary: canaries[SBX043_PUBLIC_CASES.outsideSmtp]! });

    const allowRuntime: Runtime = { name: `sbx-043-a-${runId.replaceAll("-", "").slice(0, 20)}`, cleanup: cleanup() };
    let allowReadback: Sbx043PolicyReadback | undefined;
    let allowReadbackPassed = false;
    let allowSmtp: CaseEvidence | undefined;
    try {
      await createSandbox(allowRuntime, "allow-all", credentials, probeSource);
      allowReadback = await policyReadback(allowRuntime, credentials, "allow-all");
      allowReadbackPassed = allowReadback.passed;
      if (!allowReadbackPassed || !allowRuntime.sandbox) throw new Error("allow-all readback failed");
      allowSmtp = await receiverCase({ ...common, sandbox: allowRuntime.sandbox, caseId: SBX043_PUBLIC_CASES.allowAllSmtp,
        mode: "smtp-starttls-public", canary: canaries[SBX043_PUBLIC_CASES.allowAllSmtp]! });
    } finally { await cleanupSandbox(allowRuntime, secrets); }
    if (!allowReadback || !allowSmtp) throw new Error("allow-all SMTP control was incomplete");

    const restrictedRuntime: Runtime = { name: `sbx-043-r-${runId.replaceAll("-", "").slice(0, 20)}`, cleanup: cleanup() };
    let restrictedReadback: Sbx043PolicyReadback | undefined;
    let postTargetReadback: Sbx043PolicyReadback | undefined;
    let allowedHttps: Sbx043ProbeEvidence | undefined;
    let direct: CaseEvidence | undefined;
    let raw: CaseEvidence | undefined;
    let target: CaseEvidence | undefined;
    let post: CaseEvidence | undefined;
    try {
      await createSandbox(restrictedRuntime, { allow: [topology.allowedOrigin.hostname] }, credentials, probeSource);
      if (!restrictedRuntime.sandbox) throw new Error("restricted sandbox was missing");
      restrictedReadback = await policyReadback(restrictedRuntime, credentials, { allowedHostname: topology.allowedOrigin.hostname });
      if (!restrictedReadback.passed) throw new Error("fresh exact allow[A] readback failed");
      allowedHttps = await httpsCase(topology, runId, restrictedRuntime.sandbox, probePath, gate, secrets);
      direct = await receiverCase({ ...common, sandbox: restrictedRuntime.sandbox, caseId: SBX043_PUBLIC_CASES.deniedDirectTls,
        mode: "direct-tls", canary: canaries[SBX043_PUBLIC_CASES.deniedDirectTls]! });
      raw = await receiverCase({ ...common, sandbox: restrictedRuntime.sandbox, caseId: SBX043_PUBLIC_CASES.deniedRaw,
        mode: "raw-public", canary: canaries[SBX043_PUBLIC_CASES.deniedRaw]! });
      target = await receiverCase({ ...common, sandbox: restrictedRuntime.sandbox, caseId: SBX043_PUBLIC_CASES.deniedSmtp,
        mode: "smtp-starttls-public", canary: canaries[SBX043_PUBLIC_CASES.deniedSmtp]! });
      postTargetReadback = await policyReadback(restrictedRuntime, credentials, { allowedHostname: topology.allowedOrigin.hostname });
      post = await receiverCase({ ...common, sandbox: restrictedRuntime.sandbox, caseId: SBX043_PUBLIC_CASES.deniedPostDirectTls,
        mode: "direct-tls", canary: canaries[SBX043_PUBLIC_CASES.deniedPostDirectTls]! });
    } finally { await cleanupSandbox(restrictedRuntime, secrets); }
    if (!restrictedReadback || !postTargetReadback || !allowedHttps || !direct || !raw || !target || !post) throw new Error("restricted stage was incomplete");
    const receiverCasesDeleted = [outside, allowSmtp, direct, raw, target, post].every((entry) => entry.receiverCaseDeleted);
    const assessment = assessSbx043Public({ runId, allowedHostname: topology.allowedOrigin.hostname,
      deniedHostname: topology.deniedHostname, deniedIPv4: topology.deniedIPv4, deniedPort: topology.deniedPort,
      identityAndScopePassed: true, distinctAddressSetsPassed: true, allowAllReadbackPassed: allowReadbackPassed,
      restrictedReadback, postTargetReadback, outsideSmtp: outside.result, outsideSmtpReceiver: outside.receiver,
      allowAllSmtp: allowSmtp.result, allowAllSmtpReceiver: allowSmtp.receiver, allowedHttps,
      deniedDirectTls: direct.result, deniedDirectTlsReceiver: direct.receiver, deniedRaw: raw.result,
      deniedRawReceiver: raw.receiver, deniedSmtp: target.result, deniedSmtpReceiver: target.receiver,
      deniedPostDirectTls: post.result, deniedPostDirectTlsReceiver: post.receiver, expectedOperations: operations,
      expectedConfigurationEpoch: topology.configurationEpoch,
      cleanupPassed: clean(allowRuntime.cleanup) && clean(restrictedRuntime.cleanup) && receiverCasesDeleted,
      retention: retention() });
    evidence.assessment = assessment;
    evidence.stages = { outside, allowAll: { readback: allowReadback, case: allowSmtp, cleanup: allowRuntime.cleanup },
      restricted: { restrictedReadback, allowedHttps, cases: [direct, raw, target, post], postTargetReadback, cleanup: restrictedRuntime.cleanup } };
    evidence.completedAt = new Date().toISOString();
    await writeFile(artifactPath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
    process.stdout.write(`${JSON.stringify({ testId: SBX043_TEST_ID, runId, assessment, artifactPath }, null, 2)}\n`);
    if (assessment.verdict === "error" || assessment.verdict === "indeterminate" || assessment.verdict === "alternate-root") process.exitCode = 2;
  } catch (error) {
    evidence.executionError = safeError(error, secrets);
    evidence.completedAt = new Date().toISOString();
    await mkdir(artifactsDirectory, { recursive: true });
    await writeFile(artifactPath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
    throw error;
  } finally {
    if (lock) { await lock.close(); try { await unlink(lockPath); } catch { /* owned lock already absent */ } }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void main().catch((error: unknown) => { process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
}
