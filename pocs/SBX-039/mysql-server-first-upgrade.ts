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
  SBX039_PUBLIC_CASES,
  SBX039_TEST_ID,
  assessSbx039Public,
  deriveSbx039GreetingTag,
  deriveSbx039PublicOperationId,
  exactSbx039PolicyReadback,
  type Sbx039HttpsEvidence,
  type Sbx039PolicyReadback,
  type Sbx039ProbeEvidence,
  type Sbx039ProbeMode,
  type Sbx039ReceiverStatus,
  type Sbx039RetentionEvidence,
} from "./verdict.js";

const execFile = promisify(execFileCallback);
export const SBX039_SCOPE_CONFIRMATION =
  "I_CONTROL_DISTINCT_ALLOWED_AND_DENIED_ENDPOINTS_AND_AUTHORIZE_BOUNDED_MYSQL_PRETLS_TESTING";
export const SBX039_ALLOWED_HTTPS_ORIGIN = "https://vsc-h3-action-swve.cyrus-206.workers.dev";
const eligibleAliasEmail = "swve@wearehackerone.com";
const eligibleTeamId = "team_n98ERpVwV7HqmWRudAyK8sXQ";
const eligibleProjectId = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
const remoteProbePath = "/tmp/sbx-039/mysql-upgrade-probe.py";
const controllerTimeoutMs = 30_000;
const guestOutputLimit = 16_384;
const minimumProbeIntervalMs = 300;

interface Credentials {
  token: string;
  teamId: string;
  projectId: string;
}

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
  result: Sbx039ProbeEvidence;
  receiver: Sbx039ReceiverStatus;
  receiverCaseDeleted: boolean;
}

interface HttpsCaseEvidence {
  caseId: string;
  configurationSha256: string;
  command: CommandEvidence;
  result: Sbx039HttpsEvidence;
}

interface CleanupEvidence {
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  errors: string[];
}

interface SandboxRuntime {
  name: string;
  sandbox?: Sandbox;
  sessionId?: string;
  cleanup: CleanupEvidence;
}

interface RegisteredCase {
  greetingTag: string;
  expectedOperationId: string;
}

class RateGate {
  #lastAt = 0;

  async beforeProbe(): Promise<void> {
    const wait = minimumProbeIntervalMs - (Date.now() - this.#lastAt);
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

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function signal(timeoutMs = controllerTimeoutMs): AbortSignal {
  return AbortSignal.timeout(timeoutMs);
}

function safeError(error: unknown, secrets: readonly string[]): string {
  let output = error instanceof Error ? error.message : String(error);
  for (const secret of secrets) if (secret) output = output.split(secret).join("[REDACTED]");
  return output.replace(/[\0\r\n]/gu, " ").slice(0, 1_000);
}

export function explicitSbx039Credentials(environment: NodeJS.ProcessEnv = process.env): Credentials {
  const token = required(environment, "VERCEL_TOKEN");
  const teamId = required(environment, "VERCEL_TEAM_ID");
  const projectId = required(environment, "VERCEL_PROJECT_ID");
  if (teamId !== eligibleTeamId || projectId !== eligibleProjectId) {
    throw new Error("SBX-039 must use the verified HackerOne-alias Vercel team and project");
  }
  return { token, teamId, projectId };
}

export function publicSbx039IPv4(value: string): boolean {
  if (isIP(value) !== 4 || value.split(".").some((part) => !/^(?:0|[1-9][0-9]{0,2})$/u.test(part))) return false;
  const [a = -1, b = -1, c = -1] = value.split(".").map(Number);
  return a > 0 && a < 224 && a !== 10 && a !== 127 && !(a === 172 && b >= 16 && b <= 31) &&
    !(a === 192 && b === 168) && !(a === 169 && b === 254) && !(a === 100 && b >= 64 && b <= 127) &&
    !(a === 192 && b === 0) && !(a === 198 && (b === 18 || b === 19)) &&
    !(a === 198 && b === 51 && c === 100) && !(a === 203 && b === 0 && c === 113);
}

function canonicalHostname(value: string, field: string): string {
  const pattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
  if (value !== value.toLowerCase() || isIP(value) !== 0 || !pattern.test(value)) {
    throw new Error(`${field} must be a canonical lowercase DNS hostname`);
  }
  return value;
}

function deniedPort(environment: NodeJS.ProcessEnv): number {
  const port = Number(environment.SBX039_DENIED_PORT ?? "3306");
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error("SBX039_DENIED_PORT is invalid");
  return port;
}

async function resolve4(hostname: string): Promise<string[]> {
  const resolver = new Resolver();
  const cancel = setTimeout(() => resolver.cancel(), 10_000);
  try {
    return [...new Set((await resolver.resolve4(hostname)).filter(publicSbx039IPv4))].sort();
  } finally {
    clearTimeout(cancel);
  }
}

async function adminRequest(
  topology: Pick<Topology, "adminOrigin" | "adminKey">,
  path: string,
  method: "GET" | "POST" | "DELETE",
  body?: unknown,
): Promise<Record<string, unknown>> {
  const response = await fetch(new URL(path, topology.adminOrigin), {
    method,
    headers: {
      Authorization: `Bearer ${topology.adminKey}`,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
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
  if (environment.SBX039_SCOPE_CONFIRMATION !== SBX039_SCOPE_CONFIRMATION) {
    throw new Error(`SBX039_SCOPE_CONFIRMATION must equal ${SBX039_SCOPE_CONFIRMATION}`);
  }
  const allowedOrigin = new URL(required(environment, "SBX039_ALLOWED_HTTPS_ORIGIN"));
  if (allowedOrigin.origin !== SBX039_ALLOWED_HTTPS_ORIGIN || allowedOrigin.pathname !== "/" ||
      allowedOrigin.search || allowedOrigin.hash || allowedOrigin.username || allowedOrigin.password) {
    throw new Error(`SBX039_ALLOWED_HTTPS_ORIGIN must equal ${SBX039_ALLOWED_HTTPS_ORIGIN}`);
  }
  const deniedHostname = canonicalHostname(required(environment, "SBX039_DENIED_HOSTNAME"), "SBX039_DENIED_HOSTNAME");
  const deniedIPv4 = required(environment, "SBX039_DENIED_IPV4");
  if (!publicSbx039IPv4(deniedIPv4)) throw new Error("SBX039_DENIED_IPV4 must be canonical public IPv4");
  const adminOrigin = new URL(required(environment, "SBX039_ADMIN_ORIGIN"));
  if (adminOrigin.protocol !== "http:" || adminOrigin.hostname !== "127.0.0.1" || adminOrigin.pathname !== "/" ||
      adminOrigin.search || adminOrigin.hash || adminOrigin.username || adminOrigin.password) {
    throw new Error("SBX039_ADMIN_ORIGIN must be an exact loopback HTTP origin or local SSH-forward endpoint");
  }
  const adminKey = required(environment, "SBX039_ADMIN_KEY");
  if (adminKey.length < 32 || adminKey.length > 512 || /[\0\r\n]/u.test(adminKey)) throw new Error("SBX039_ADMIN_KEY is invalid");
  const [allowedAddresses, deniedAddresses] = await Promise.all([
    resolve4(allowedOrigin.hostname),
    resolve4(deniedHostname),
  ]);
  if (allowedAddresses.length === 0 || deniedAddresses.length === 0 || !deniedAddresses.includes(deniedIPv4)) {
    throw new Error("owned endpoint DNS did not resolve to the pinned public IPv4");
  }
  if (allowedAddresses.some((address) => deniedAddresses.includes(address))) {
    throw new Error("SBX-039 requires disjoint allowed-A and denied-B resolved IPv4 sets");
  }
  const healthResponse = await fetch(new URL("/healthz", adminOrigin), { redirect: "error", signal: signal(10_000) });
  const health = object(await healthResponse.json());
  const listener = object(health.listener);
  const configurationEpoch = typeof health.configurationEpoch === "string" ? health.configurationEpoch : "";
  if (!healthResponse.ok || health.ok !== true || health.testId !== SBX039_TEST_ID ||
      listener.hostname !== deniedHostname || listener.ipv4 !== deniedIPv4 || listener.port !== deniedPort(environment) ||
      !/^[0-9a-f-]{36}$/u.test(configurationEpoch)) {
    throw new Error("receiver health did not bind the exact B identity, port, and configuration epoch");
  }
  return {
    allowedOrigin,
    allowedAddresses,
    deniedHostname,
    deniedIPv4,
    deniedAddresses,
    deniedPort: deniedPort(environment),
    adminOrigin,
    adminKey,
    configurationEpoch,
  };
}

export function buildSbx039ProbeConfiguration(input: {
  mode: Sbx039ProbeMode;
  runId: string;
  caseId: string;
  endpointHostname: string;
  endpointRole: "allowed" | "denied";
  pinnedIPv4?: string;
  pinnedPort: number;
  publicCanary?: string;
  greetingTag?: string;
}): Record<string, unknown> {
  return {
    scopeConfirmation: SBX039_SCOPE_CONFIRMATION,
    mode: input.mode,
    runId: input.runId,
    testId: SBX039_TEST_ID,
    caseId: input.caseId,
    endpointRole: input.endpointRole,
    endpointHostname: input.endpointHostname,
    ...(input.pinnedIPv4 ? { pinnedIPv4: input.pinnedIPv4 } : {}),
    pinnedPort: input.pinnedPort,
    ...(input.publicCanary ? { publicCanary: input.publicCanary } : {}),
    ...(input.greetingTag ? { greetingTag: input.greetingTag } : {}),
    timeoutMs: 3_000,
    maxResponseBytes: 512,
  };
}

function casePath(runId: string, caseId: string): string {
  return `/v1/sbx039/admin/cases/${runId}/${caseId}`;
}

async function registerCase(
  topology: Topology,
  runId: string,
  caseId: string,
  mode: Exclude<Sbx039ProbeMode, "https-control" | "mysql-coalesced-secret">,
  publicCanary: string,
): Promise<RegisteredCase> {
  const now = Date.now();
  const response = await adminRequest(topology, casePath(runId, caseId), "POST", {
    runId,
    caseId,
    phase: "public",
    mode,
    endpointBaseHostname: topology.deniedHostname,
    notBefore: new Date(now - 2_000).toISOString(),
    notAfter: new Date(now + 5 * 60_000).toISOString(),
    expectedPublicCanary: publicCanary,
  });
  const greetingTag = typeof response.greetingTag === "string" ? response.greetingTag : "";
  const expectedOperationId = typeof response.expectedOperationId === "string" ? response.expectedOperationId : "";
  if (response.configured !== true || response.configurationEpoch !== topology.configurationEpoch ||
      greetingTag !== deriveSbx039GreetingTag(topology.adminKey, runId, caseId) ||
      expectedOperationId !== deriveSbx039PublicOperationId(topology.adminKey, runId, caseId, publicCanary)) {
    throw new Error("receiver registration did not return exact case-bound identifiers");
  }
  return { greetingTag, expectedOperationId };
}

function commandOutput(stdout: string, stderr: string, forbidden: readonly string[]): unknown {
  if (Buffer.byteLength(stdout) > guestOutputLimit || Buffer.byteLength(stderr) > guestOutputLimit) {
    throw new Error("guest output exceeded its bound");
  }
  if (forbidden.some((value) => value && (stdout.includes(value) || stderr.includes(value)))) {
    throw new Error("guest output contained forbidden controller or canary material");
  }
  return JSON.parse(stdout);
}

function sanitizeProbe(value: unknown): Sbx039ProbeEvidence {
  return object(value) as unknown as Sbx039ProbeEvidence;
}

async function executeProbe(
  sourcePath: string,
  configuration: Record<string, unknown>,
  gate: RateGate,
  forbidden: readonly string[],
  sandbox?: Sandbox,
): Promise<{ command: CommandEvidence; result: Sbx039ProbeEvidence }> {
  await gate.beforeProbe();
  const encoded = Buffer.from(JSON.stringify(configuration)).toString("base64url");
  if (!sandbox) {
    const capture = await execFile("python3", [sourcePath, encoded], { maxBuffer: guestOutputLimit });
    return {
      command: {
        source: "controller-preflight",
        exitCode: 0,
        stdoutBytes: Buffer.byteLength(capture.stdout),
        stderrBytes: Buffer.byteLength(capture.stderr),
        rawOutputRetained: false,
      },
      result: sanitizeProbe(commandOutput(capture.stdout, capture.stderr, forbidden)),
    };
  }
  const command = await sandbox.runCommand({
    cmd: "python3",
    args: [remoteProbePath, encoded],
    timeoutMs: 12_000,
  });
  const [stdout, stderr] = await Promise.all([
    command.stdout({ signal: signal() }),
    command.stderr({ signal: signal() }),
  ]);
  return {
    command: {
      source: "sandbox",
      commandId: command.cmdId,
      exitCode: command.exitCode,
      stdoutBytes: Buffer.byteLength(stdout),
      stderrBytes: Buffer.byteLength(stderr),
      rawOutputRetained: false,
    },
    result: sanitizeProbe(commandOutput(stdout, stderr, forbidden)),
  };
}

async function receiverCase(input: {
  topology: Topology;
  runId: string;
  caseId: string;
  mode: "direct-tls" | "raw-public" | "mysql-split-public" | "mysql-coalesced-public";
  canary: string;
  sourcePath: string;
  gate: RateGate;
  forbidden: string[];
  sandbox?: Sandbox;
}): Promise<CaseEvidence> {
  const registered = await registerCase(input.topology, input.runId, input.caseId, input.mode, input.canary);
  let receiverCaseDeleted = false;
  let captured: Omit<CaseEvidence, "receiverCaseDeleted"> | undefined;
  try {
    const configuration = buildSbx039ProbeConfiguration({
      mode: input.mode,
      runId: input.runId,
      caseId: input.caseId,
      endpointHostname: input.topology.deniedHostname,
      endpointRole: "denied",
      pinnedIPv4: input.topology.deniedIPv4,
      pinnedPort: input.topology.deniedPort,
      publicCanary: input.canary,
      ...(input.mode.startsWith("mysql-") ? { greetingTag: registered.greetingTag } : {}),
    });
    const executed = await executeProbe(
      input.sourcePath,
      configuration,
      input.gate,
      [...input.forbidden, input.canary],
      input.sandbox,
    );
    await delay(350);
    const receiver = await adminRequest(input.topology, casePath(input.runId, input.caseId), "GET") as unknown as Sbx039ReceiverStatus;
    captured = {
      caseId: input.caseId,
      configurationSha256: sha256(JSON.stringify(configuration)),
      command: executed.command,
      result: executed.result,
      receiver,
    };
  } finally {
    const response = await adminRequest(input.topology, casePath(input.runId, input.caseId), "DELETE");
    receiverCaseDeleted = response.deleted === true;
    if (!receiverCaseDeleted) throw new Error(`receiver case ${input.caseId} was not deleted`);
  }
  if (!captured) throw new Error(`receiver case ${input.caseId} produced no evidence`);
  return { ...captured, receiverCaseDeleted };
}

async function httpsCase(
  topology: Topology,
  runId: string,
  sandbox: Sandbox,
  sourcePath: string,
  gate: RateGate,
  forbidden: readonly string[],
): Promise<HttpsCaseEvidence> {
  const configuration = buildSbx039ProbeConfiguration({
    mode: "https-control",
    runId,
    caseId: SBX039_PUBLIC_CASES.allowedHttps,
    endpointHostname: topology.allowedOrigin.hostname,
    endpointRole: "allowed",
    pinnedPort: 443,
  });
  const executed = await executeProbe(sourcePath, configuration, gate, forbidden, sandbox);
  return {
    caseId: SBX039_PUBLIC_CASES.allowedHttps,
    configurationSha256: sha256(JSON.stringify(configuration)),
    command: executed.command,
    result: executed.result as Sbx039HttpsEvidence,
  };
}

async function createSandbox(
  runtime: SandboxRuntime,
  policy: NetworkPolicy,
  credentials: Credentials,
  probeSource: string,
): Promise<void> {
  runtime.sandbox = await Sandbox.create({
    name: runtime.name,
    persistent: false,
    timeout: 300_000,
    networkPolicy: policy,
    tags: { harness: "vsc", test: SBX039_TEST_ID },
    signal: signal(45_000),
    ...credentials,
  });
  runtime.sessionId = runtime.sandbox.currentSession().sessionId;
  await runtime.sandbox.writeFiles([{ path: remoteProbePath, content: probeSource, mode: 0o700 }], { signal: signal() });
}

async function policyReadback(
  runtime: SandboxRuntime,
  credentials: Credentials,
  expected: "allow-all" | { allowedHostname: string },
): Promise<Sbx039PolicyReadback> {
  if (!runtime.sandbox || !runtime.sessionId) throw new Error("sandbox runtime was incomplete");
  const active = runtime.sandbox.currentSession();
  const independent = await Sandbox.get({ name: runtime.name, resume: false, signal: signal(), ...credentials });
  const independentSession = independent.currentSession();
  return exactSbx039PolicyReadback({
    initialSessionId: runtime.sessionId,
    activeSessionId: active.sessionId,
    independentSessionId: independentSession.sessionId,
    activeSandboxPolicy: runtime.sandbox.networkPolicy,
    activeSessionPolicy: active.networkPolicy,
    independentSandboxPolicy: independent.networkPolicy,
    independentSessionPolicy: independentSession.networkPolicy,
  }, expected);
}

function emptyCleanup(): CleanupEvidence {
  return { stopAttempted: false, stopped: false, deleteAttempted: false, deleted: false, errors: [] };
}

async function cleanupSandbox(runtime: SandboxRuntime, secrets: readonly string[]): Promise<void> {
  if (!runtime.sandbox) return;
  runtime.cleanup.stopAttempted = true;
  try { await runtime.sandbox.stop({ signal: signal() }); runtime.cleanup.stopped = true; }
  catch (error) { runtime.cleanup.errors.push(`stop: ${safeError(error, secrets)}`); }
  runtime.cleanup.deleteAttempted = true;
  try { await runtime.sandbox.delete({ signal: signal() }); runtime.cleanup.deleted = true; }
  catch (error) { runtime.cleanup.errors.push(`delete: ${safeError(error, secrets)}`); }
}

function cleanupPassed(value: CleanupEvidence): boolean {
  return value.stopAttempted && value.stopped && value.deleteAttempted && value.deleted && value.errors.length === 0;
}

function retention(): Sbx039RetentionEvidence {
  return {
    rawOperatorSecret: false,
    rawGuestConfiguration: false,
    rawCommandStdout: false,
    rawCommandStderr: false,
    rawClientHello: false,
    rawServerName: false,
    rawSecretInArtifact: false,
    secretDigestInArtifact: false,
  };
}

async function acquireLock(path: string): Promise<FileHandle> {
  await mkdir(resolve(path, ".."), { recursive: true });
  return await open(path, "wx", 0o600);
}

async function main(): Promise<void> {
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  const lockPath = resolve(artifactsDirectory, "SBX-039-live-active.lock");
  const credentials = explicitSbx039Credentials(process.env);
  const probePath = resolve("guest/mysql-upgrade-probe.py");
  const probeSource = await readFile(probePath, "utf8");
  const secrets = [credentials.token, required(process.env, "SBX039_ADMIN_KEY")];
  let lock: FileHandle | undefined;
  let artifactPath = resolve(artifactsDirectory, `SBX-039-public-${Date.now()}.json`);
  const evidence: Record<string, unknown> = {
    schemaVersion: 1,
    testId: SBX039_TEST_ID,
    startedAt: new Date().toISOString(),
    liveRunExecuted: true,
    publicCanaryOnly: true,
    secretStage: { executed: false, reason: "gated until an independently reviewed public candidate exists" },
  };
  try {
    lock = await acquireLock(lockPath);
    await verifyEligibleAliasToken({
      token: credentials.token,
      expectedEmail: eligibleAliasEmail,
      expectedTeamId: eligibleTeamId,
      expectedProjectId: eligibleProjectId,
      manualEmailConfirmation: process.env.SBX039_ALIAS_EMAIL_CONFIRMATION,
    });
    const topology = await loadTopology(process.env);
    const runId = randomUUID();
    artifactPath = resolve(artifactsDirectory, `SBX-039-public-${runId}.json`);
    evidence.runId = runId;
    evidence.topology = {
      allowedHostname: topology.allowedOrigin.hostname,
      allowedAddresses: topology.allowedAddresses,
      deniedHostname: topology.deniedHostname,
      deniedAddresses: topology.deniedAddresses,
      deniedPinnedIPv4: topology.deniedIPv4,
      deniedPort: topology.deniedPort,
      addressSetsDisjoint: topology.allowedAddresses.every((address) => !topology.deniedAddresses.includes(address)),
      configurationEpoch: topology.configurationEpoch,
    };
    const canaries = Object.fromEntries(Object.values(SBX039_PUBLIC_CASES)
      .filter((caseId) => caseId !== SBX039_PUBLIC_CASES.allowedHttps)
      .map((caseId) => [caseId, randomBytes(16).toString("hex")]));
    const operations = Object.fromEntries(Object.entries(canaries).map(([caseId, canary]) => [
      caseId,
      deriveSbx039PublicOperationId(topology.adminKey, runId, caseId, canary),
    ]));
    const gate = new RateGate();
    const common = {
      topology,
      runId,
      sourcePath: probePath,
      gate,
      forbidden: secrets,
    };
    const outside = await receiverCase({
      ...common,
      caseId: SBX039_PUBLIC_CASES.outsideCoalesced,
      mode: "mysql-coalesced-public",
      canary: canaries[SBX039_PUBLIC_CASES.outsideCoalesced]!,
    });

    const allowRuntime: SandboxRuntime = {
      name: `sbx-039-allow-${runId.replaceAll("-", "")}`,
      cleanup: emptyCleanup(),
    };
    let allowReadbackPassed = false;
    let allowDirect: CaseEvidence | undefined;
    let allowSplit: CaseEvidence | undefined;
    let allowCoalesced: CaseEvidence | undefined;
    try {
      await createSandbox(allowRuntime, "allow-all", credentials, probeSource);
      const readback = await policyReadback(allowRuntime, credentials, "allow-all");
      allowReadbackPassed = readback.passed;
      if (!allowReadbackPassed || !allowRuntime.sandbox) throw new Error("allow-all sandbox readback failed");
      allowDirect = await receiverCase({
        ...common, sandbox: allowRuntime.sandbox,
        caseId: SBX039_PUBLIC_CASES.allowAllDirectTls,
        mode: "direct-tls",
        canary: canaries[SBX039_PUBLIC_CASES.allowAllDirectTls]!,
      });
      allowSplit = await receiverCase({
        ...common, sandbox: allowRuntime.sandbox,
        caseId: SBX039_PUBLIC_CASES.allowAllSplit,
        mode: "mysql-split-public",
        canary: canaries[SBX039_PUBLIC_CASES.allowAllSplit]!,
      });
      allowCoalesced = await receiverCase({
        ...common, sandbox: allowRuntime.sandbox,
        caseId: SBX039_PUBLIC_CASES.allowAllCoalesced,
        mode: "mysql-coalesced-public",
        canary: canaries[SBX039_PUBLIC_CASES.allowAllCoalesced]!,
      });
    } finally {
      await cleanupSandbox(allowRuntime, secrets);
    }
    if (!allowDirect || !allowSplit || !allowCoalesced) throw new Error("allow-all control stage was incomplete");

    const restrictedRuntime: SandboxRuntime = {
      name: `sbx-039-deny-${runId.replaceAll("-", "")}`,
      cleanup: emptyCleanup(),
    };
    let restrictedReadback: Sbx039PolicyReadback | undefined;
    let postTargetReadback: Sbx039PolicyReadback | undefined;
    let allowedHttps: HttpsCaseEvidence | undefined;
    let deniedDirect: CaseEvidence | undefined;
    let deniedRaw: CaseEvidence | undefined;
    let deniedSplit: CaseEvidence | undefined;
    let deniedTarget: CaseEvidence | undefined;
    let deniedPost: CaseEvidence | undefined;
    try {
      await createSandbox(
        restrictedRuntime,
        { allow: [topology.allowedOrigin.hostname] },
        credentials,
        probeSource,
      );
      if (!restrictedRuntime.sandbox) throw new Error("restricted sandbox was missing");
      restrictedReadback = await policyReadback(
        restrictedRuntime,
        credentials,
        { allowedHostname: topology.allowedOrigin.hostname },
      );
      if (!restrictedReadback.passed) throw new Error("fresh exact allow[A] readback failed");
      allowedHttps = await httpsCase(topology, runId, restrictedRuntime.sandbox, probePath, gate, secrets);
      deniedDirect = await receiverCase({
        ...common, sandbox: restrictedRuntime.sandbox,
        caseId: SBX039_PUBLIC_CASES.deniedDirectTls,
        mode: "direct-tls",
        canary: canaries[SBX039_PUBLIC_CASES.deniedDirectTls]!,
      });
      deniedRaw = await receiverCase({
        ...common, sandbox: restrictedRuntime.sandbox,
        caseId: SBX039_PUBLIC_CASES.deniedRaw,
        mode: "raw-public",
        canary: canaries[SBX039_PUBLIC_CASES.deniedRaw]!,
      });
      deniedSplit = await receiverCase({
        ...common, sandbox: restrictedRuntime.sandbox,
        caseId: SBX039_PUBLIC_CASES.deniedSplit,
        mode: "mysql-split-public",
        canary: canaries[SBX039_PUBLIC_CASES.deniedSplit]!,
      });
      deniedTarget = await receiverCase({
        ...common, sandbox: restrictedRuntime.sandbox,
        caseId: SBX039_PUBLIC_CASES.deniedCoalesced,
        mode: "mysql-coalesced-public",
        canary: canaries[SBX039_PUBLIC_CASES.deniedCoalesced]!,
      });
      postTargetReadback = await policyReadback(
        restrictedRuntime,
        credentials,
        { allowedHostname: topology.allowedOrigin.hostname },
      );
      deniedPost = await receiverCase({
        ...common, sandbox: restrictedRuntime.sandbox,
        caseId: SBX039_PUBLIC_CASES.deniedPostDirectTls,
        mode: "direct-tls",
        canary: canaries[SBX039_PUBLIC_CASES.deniedPostDirectTls]!,
      });
    } finally {
      await cleanupSandbox(restrictedRuntime, secrets);
    }
    if (!restrictedReadback || !postTargetReadback || !allowedHttps || !deniedDirect || !deniedRaw ||
        !deniedSplit || !deniedTarget || !deniedPost) throw new Error("restricted public stage was incomplete");
    const receiverCasesDeleted = [outside, allowDirect, allowSplit, allowCoalesced, deniedDirect, deniedRaw,
      deniedSplit, deniedTarget, deniedPost].every((entry) => entry.receiverCaseDeleted);
    const clean = cleanupPassed(allowRuntime.cleanup) && cleanupPassed(restrictedRuntime.cleanup) && receiverCasesDeleted;
    const assessment = assessSbx039Public({
      runId,
      allowedHostname: topology.allowedOrigin.hostname,
      deniedHostname: topology.deniedHostname,
      deniedIPv4: topology.deniedIPv4,
      deniedPort: topology.deniedPort,
      identityAndScopePassed: true,
      distinctAddressSetsPassed: topology.allowedAddresses.every((address) => !topology.deniedAddresses.includes(address)),
      allowAllReadbackPassed: allowReadbackPassed,
      restrictedReadback,
      postTargetReadback,
      outsideCoalesced: outside.result,
      outsideCoalescedReceiver: outside.receiver,
      allowAllDirectTls: allowDirect.result,
      allowAllDirectTlsReceiver: allowDirect.receiver,
      allowAllSplit: allowSplit.result,
      allowAllSplitReceiver: allowSplit.receiver,
      allowAllCoalesced: allowCoalesced.result,
      allowAllCoalescedReceiver: allowCoalesced.receiver,
      allowedHttps: allowedHttps.result,
      deniedDirectTls: deniedDirect.result,
      deniedDirectTlsReceiver: deniedDirect.receiver,
      deniedRaw: deniedRaw.result,
      deniedRawReceiver: deniedRaw.receiver,
      deniedSplit: deniedSplit.result,
      deniedSplitReceiver: deniedSplit.receiver,
      deniedCoalesced: deniedTarget.result,
      deniedCoalescedReceiver: deniedTarget.receiver,
      deniedPostDirectTls: deniedPost.result,
      deniedPostDirectTlsReceiver: deniedPost.receiver,
      expectedOperations: operations,
      expectedConfigurationEpoch: topology.configurationEpoch,
      cleanupPassed: clean,
      retention: retention(),
    });
    evidence.assessment = assessment;
    evidence.stages = {
      outside: { case: outside },
      allowAll: {
        readbackPassed: allowReadbackPassed,
        cases: [allowDirect, allowSplit, allowCoalesced],
        cleanup: allowRuntime.cleanup,
      },
      restricted: {
        restrictedReadback,
        allowedHttps,
        cases: [deniedDirect, deniedRaw, deniedSplit, deniedTarget, deniedPost],
        postTargetReadback,
        cleanup: restrictedRuntime.cleanup,
      },
    };
    evidence.completedAt = new Date().toISOString();
    await mkdir(artifactsDirectory, { recursive: true });
    await writeFile(artifactPath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
    process.stdout.write(`${JSON.stringify({ testId: SBX039_TEST_ID, runId, assessment, artifactPath }, null, 2)}\n`);
    if (assessment.verdict === "error" || assessment.verdict === "indeterminate" || assessment.verdict === "alternate-root") {
      process.exitCode = 2;
    }
  } catch (error) {
    evidence.executionError = safeError(error, secrets);
    evidence.completedAt = new Date().toISOString();
    await mkdir(artifactsDirectory, { recursive: true });
    await writeFile(artifactPath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
    throw error;
  } finally {
    if (lock) {
      await lock.close();
      try { await unlink(lockPath); } catch { /* a closed owned lock may already be absent */ }
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
