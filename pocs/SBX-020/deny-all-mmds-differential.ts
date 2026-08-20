import "dotenv/config";

import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Sandbox, type NetworkPolicy } from "@vercel/sandbox";

const testId = "SBX-020-DIFFERENTIAL";
const eligibleAliasEmail = "swve@wearehackerone.com";
const eligibleTeamId = "team_n98ERpVwV7HqmWRudAyK8sXQ";
const eligibleProjectId = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
const healthOrigin = "https://vsc-h3-action-swve.cyrus-206.workers.dev";
const healthPath = "/healthz";
const healthTimeoutMs = 3_000;
const remoteHealthProbe = "/tmp/sbx-020/public-health-control.mjs";
const remoteMmdsProbe = "/tmp/sbx-020/mmds-link-local-probe.mjs";
const remoteDiscoveryRules = "/tmp/sbx-020/mmds-discovery-rules.mjs";
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const safeErrorCodePattern = /^[A-Za-z][A-Za-z0-9_]{0,63}$/u;

interface ExplicitCredentials {
  token: string;
  teamId: string;
  projectId: string;
}

interface SessionLike {
  sessionId: string;
  networkPolicy?: NetworkPolicy;
  region?: string;
  createdAt?: Date;
}

interface CommandLike {
  cmdId: string;
  exitCode: number;
  durationMs?: number;
  stdout(): Promise<string>;
  stderr(): Promise<string>;
}

export interface SandboxLike {
  name: string;
  persistent: boolean;
  networkPolicy?: NetworkPolicy;
  currentSession(): SessionLike;
  writeFiles(files: Array<{ path: string; content: string; mode: number }>): Promise<unknown>;
  runCommand(input: { cmd: string; args: string[]; timeoutMs: number }): Promise<CommandLike>;
  update(input: { networkPolicy: "deny-all" }): Promise<unknown>;
  stop(): Promise<unknown>;
  delete(): Promise<unknown>;
}

export interface DifferentialRuntime {
  create(input: {
    name: string;
    persistent: false;
    timeout: number;
    networkPolicy: "allow-all";
    tags: Record<string, string>;
    token: string;
    teamId: string;
    projectId: string;
  }): Promise<SandboxLike>;
  get(input: {
    name: string;
    resume: false;
    token: string;
    teamId: string;
    projectId: string;
  }): Promise<SandboxLike>;
}

interface Sources {
  health: string;
  mmds: string;
  discoveryRules: string;
}

interface ExecuteInput {
  runId: string;
  credentials: ExplicitCredentials;
  sources: Sources;
  aliasIdentityVerified: boolean;
}

interface HealthEvidence {
  ok: boolean;
  runId?: string;
  phase?: string;
  origin?: string;
  path?: string;
  timeoutMs?: number;
  responseBodiesRetained?: boolean;
  receivedResponse?: boolean;
  statusCode?: number;
  timedOut?: boolean;
  errorCode?: string;
  durationMs?: number;
}

interface MmdsAttempt {
  classification?: unknown;
  method?: unknown;
  path?: unknown;
  requestSucceeded?: unknown;
  statusCode?: unknown;
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function safeError(error: unknown, token: string): string {
  const raw = error instanceof Error ? error.message : String(error);
  return raw.split(token).join("[REDACTED]").replace(/[\0\r\n]/gu, " ").slice(0, 1_000);
}

function requiredCredentials(environment: NodeJS.ProcessEnv): ExplicitCredentials {
  const token = environment.VERCEL_TOKEN;
  const teamId = environment.VERCEL_TEAM_ID;
  const projectId = environment.VERCEL_PROJECT_ID;
  if (!token || !teamId || !projectId) {
    throw new Error("VERCEL_TOKEN, VERCEL_TEAM_ID, and VERCEL_PROJECT_ID are required");
  }
  if (teamId !== eligibleTeamId || projectId !== eligibleProjectId) {
    throw new Error("SBX-020 differential must use the verified HackerOne-alias Vercel team and project");
  }
  return { token, teamId, projectId };
}

async function verifyAliasIdentity(token: string): Promise<void> {
  const response = await fetch("https://api.vercel.com/v2/user", {
    headers: { Authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error(`could not verify Vercel token identity (${response.status})`);
  const payload = await response.json() as { user?: { email?: unknown } };
  if (payload.user?.email !== eligibleAliasEmail) {
    throw new Error("Vercel token is not authenticated as the required HackerOne alias");
  }
}

export function sanitizeHealthEvidence(value: unknown): HealthEvidence {
  const input = record(value);
  if (!input) return { ok: false };
  return {
    ok: input.ok === true,
    ...(typeof input.runId === "string" && uuidPattern.test(input.runId) ? { runId: input.runId } : {}),
    ...(input.phase === "allow-control" || input.phase === "deny-control" ? { phase: input.phase } : {}),
    ...(input.origin === healthOrigin ? { origin: healthOrigin } : {}),
    ...(input.path === healthPath ? { path: healthPath } : {}),
    ...(Number.isInteger(input.timeoutMs) ? { timeoutMs: input.timeoutMs as number } : {}),
    ...(input.responseBodiesRetained === false ? { responseBodiesRetained: false } : {}),
    ...(typeof input.receivedResponse === "boolean" ? { receivedResponse: input.receivedResponse } : {}),
    ...(Number.isInteger(input.statusCode) ? { statusCode: input.statusCode as number } : {}),
    ...(typeof input.timedOut === "boolean" ? { timedOut: input.timedOut } : {}),
    ...(typeof input.errorCode === "string" && safeErrorCodePattern.test(input.errorCode)
      ? { errorCode: input.errorCode }
      : {}),
    ...(Number.isInteger(input.durationMs) && (input.durationMs as number) >= 0
      ? { durationMs: input.durationMs as number }
      : {}),
  };
}

function healthAttributionPassed(value: HealthEvidence, runId: string, phase: string): boolean {
  return value.ok && value.runId === runId && value.phase === phase && value.origin === healthOrigin &&
    value.path === healthPath && value.timeoutMs === healthTimeoutMs && value.responseBodiesRetained === false &&
    typeof value.durationMs === "number" && value.durationMs <= healthTimeoutMs + 1_000;
}

export function allowHealthControlPassed(value: HealthEvidence, runId: string): boolean {
  return healthAttributionPassed(value, runId, "allow-control") && value.receivedResponse === true &&
    value.statusCode === 200 && value.timedOut === false && value.errorCode === undefined;
}

export function denyHealthControlActivelyBlocked(value: HealthEvidence, runId: string): boolean {
  return healthAttributionPassed(value, runId, "deny-control") && value.receivedResponse === false &&
    value.statusCode === undefined && value.timedOut === false && typeof value.errorCode === "string" &&
    !["ETIMEDOUT", "TimeoutError", "AbortError"].includes(value.errorCode);
}

export function exactDenyAllSameSession(input: {
  originalSessionId: string;
  activeSandboxPolicy: unknown;
  activeSessionId: string;
  activeSessionPolicy: unknown;
  independentSandboxPolicy: unknown;
  independentSessionId: string;
  independentSessionPolicy: unknown;
}): boolean {
  return input.originalSessionId.length > 0 && input.activeSessionId === input.originalSessionId &&
    input.independentSessionId === input.originalSessionId && input.activeSandboxPolicy === "deny-all" &&
    input.activeSessionPolicy === "deny-all" && input.independentSandboxPolicy === "deny-all" &&
    input.independentSessionPolicy === "deny-all";
}

export function summarizeMmdsDifferential(value: unknown, expectedRunId: string): Record<string, unknown> {
  const input = record(value);
  const bounds = record(input?.bounds);
  const flow = record(input?.flow);
  const attempts = Array.isArray(input?.attempts) ? input.attempts as MmdsAttempt[] : [];
  const tokenIndex = attempts.findIndex((attempt) => attempt.classification === "token");
  const rootIndex = attempts.findIndex((attempt) => attempt.classification === "discovery-root");
  const tokenAttempt = tokenIndex >= 0 ? attempts[tokenIndex] : undefined;
  const rootAttempt = rootIndex >= 0 ? attempts[rootIndex] : undefined;
  const attributionPassed = input?.ok === true && input.mode === "execute" && input.runId === expectedRunId &&
    input.testId === testId && input.caseId === "deny-all-mmds-after-public-block" &&
    input.target === "169.254.169.254" && input.bodyRetention === "none" &&
    input.tokenRetention === "guest-memory-only-during-flow" &&
    input.sensitiveLeafValueOrDigestRetention === "none" && bounds?.sequentialRequestsOnly === true &&
    typeof bounds.actualRequestCount === "number" && bounds.actualRequestCount === attempts.length &&
    attempts.length >= 3 && attempts.length <= 8;
  const token200 = tokenIndex >= 0 && tokenAttempt?.method === "PUT" &&
    tokenAttempt.path === "/latest/api/token" && tokenAttempt.requestSucceeded === true &&
    tokenAttempt.statusCode === 200 && flow?.tokenAcquired === true;
  const authenticatedRoot200 = token200 && rootIndex > tokenIndex && rootAttempt?.method === "GET" &&
    rootAttempt.path === "/" && rootAttempt.requestSucceeded === true && rootAttempt.statusCode === 200 &&
    flow?.discoveryStarted === true;
  return {
    attributionPassed,
    token200,
    authenticatedRoot200,
    requestCount: attempts.length,
    token: {
      method: tokenAttempt?.method === "PUT" ? "PUT" : undefined,
      path: tokenAttempt?.path === "/latest/api/token" ? "/latest/api/token" : undefined,
      responseReceived: tokenAttempt?.requestSucceeded === true,
      statusCode: Number.isInteger(tokenAttempt?.statusCode) ? tokenAttempt?.statusCode : undefined,
    },
    authenticatedRoot: {
      method: rootAttempt?.method === "GET" ? "GET" : undefined,
      path: rootAttempt?.path === "/" ? "/" : undefined,
      responseReceived: rootAttempt?.requestSucceeded === true,
      statusCode: Number.isInteger(rootAttempt?.statusCode) ? rootAttempt?.statusCode : undefined,
    },
    responseBodiesRetained: false,
    tokenBodyOrDigestRetained: false,
    sensitiveResponseDigestsRetained: false,
  };
}

async function runJsonCommand(
  sandbox: SandboxLike,
  path: string,
  configuration: Record<string, unknown>,
  maximumStdoutBytes: number,
): Promise<{ parsed: unknown; command: Record<string, unknown> }> {
  const command = await sandbox.runCommand({
    cmd: "node",
    args: [path, Buffer.from(JSON.stringify(configuration)).toString("base64url")],
    timeoutMs: 30_000,
  });
  const [stdout, stderr] = await Promise.all([command.stdout(), command.stderr()]);
  if (Buffer.byteLength(stdout) > maximumStdoutBytes || Buffer.byteLength(stderr) > 8_192) {
    throw new Error("guest command output exceeded its bound");
  }
  if (command.exitCode !== 0) throw new Error(`guest command exited ${command.exitCode}`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error("guest command emitted invalid JSON");
  }
  return {
    parsed,
    command: {
      commandId: command.cmdId,
      exitCode: command.exitCode,
      ...(command.durationMs !== undefined ? { durationMs: command.durationMs } : {}),
      stdoutByteLength: Buffer.byteLength(stdout),
      stderrByteLength: Buffer.byteLength(stderr),
    },
  };
}

const productionRuntime: DifferentialRuntime = {
  create: async (input) => await Sandbox.create(input) as unknown as SandboxLike,
  get: async (input) => await Sandbox.get(input) as unknown as SandboxLike,
};

export async function executeDenyAllMmdsDifferential(
  input: ExecuteInput,
  runtime: DifferentialRuntime = productionRuntime,
): Promise<Record<string, unknown>> {
  if (!uuidPattern.test(input.runId)) throw new Error("runId must be a canonical random UUID");
  if (!input.aliasIdentityVerified) throw new Error("alias identity must be verified before sandbox creation");
  const sandboxName = `sbx-020-diff-${input.runId}`;
  const healthConfig = (phase: "allow-control" | "deny-control") => ({
    runId: input.runId,
    phase,
    timeoutMs: healthTimeoutMs,
  });
  const mmdsConfig = {
    scopeConfirmation: "I_UNDERSTAND_THIS_TARGETS_ONLY_FIRECRACKER_MMDS",
    runId: input.runId,
    testId,
    caseId: "deny-all-mmds-after-public-block",
    target: "169.254.169.254",
    timeoutMs: 2_000,
    routeTimeoutMs: 1_500,
    interRequestDelayMs: 250,
    maxResponseBytes: 16_384,
  };
  const guestMaterial = `${input.sources.health}\n${input.sources.mmds}\n${input.sources.discoveryRules}\n${JSON.stringify({
    health: [healthConfig("allow-control"), healthConfig("deny-control")],
    mmds: mmdsConfig,
  })}`;
  if (guestMaterial.includes(input.credentials.token)) {
    throw new Error("guest material unexpectedly contains the Vercel credential");
  }

  const cleanup = {
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    errors: [] as string[],
  };
  const controls: Record<string, unknown> = {};
  const commands: Record<string, unknown> = {};
  let sandbox: SandboxLike | undefined;
  let sandboxEvidence: Record<string, unknown> | undefined;
  let executionError: string | undefined;
  let mmds: Record<string, unknown> | undefined;

  try {
    sandbox = await runtime.create({
      name: sandboxName,
      persistent: false,
      timeout: 180_000,
      networkPolicy: "allow-all",
      tags: { harness: "vsc", test: "SBX-020", run: input.runId, case: "deny-all-mmds-differential" },
      ...input.credentials,
    });
    const initialSession = sandbox.currentSession();
    const initialPolicyPassed = sandbox.name === sandboxName && sandbox.persistent === false &&
      sandbox.networkPolicy === "allow-all" && initialSession.networkPolicy === "allow-all";
    controls.initialAllowAllReadbackPassed = initialPolicyPassed;
    if (!initialPolicyPassed) throw new Error("fresh sandbox did not report literal allow-all");
    sandboxEvidence = {
      name: sandbox.name,
      persistent: sandbox.persistent,
      sessionId: initialSession.sessionId,
      region: initialSession.region,
    };

    await sandbox.writeFiles([
      { path: remoteHealthProbe, content: input.sources.health, mode: 0o700 },
      { path: remoteMmdsProbe, content: input.sources.mmds, mode: 0o700 },
      { path: remoteDiscoveryRules, content: input.sources.discoveryRules, mode: 0o600 },
    ]);

    const allowCommand = await runJsonCommand(sandbox, remoteHealthProbe, healthConfig("allow-control"), 8_192);
    commands.allowHealth = allowCommand.command;
    const allowHealth = sanitizeHealthEvidence(allowCommand.parsed);
    controls.allowHealth = allowHealth;
    const allowHealthPassed = allowHealthControlPassed(allowHealth, input.runId);
    controls.allowHealthPassed = allowHealthPassed;
    if (!allowHealthPassed) throw new Error("owned Worker health control failed under allow-all");

    await sandbox.update({ networkPolicy: "deny-all" });
    const activeSession = sandbox.currentSession();
    const independent = await runtime.get({ name: sandboxName, resume: false, ...input.credentials });
    const independentSession = independent.currentSession();
    const policyReadback = {
      originalSessionId: initialSession.sessionId,
      activeSessionId: activeSession.sessionId,
      independentSessionId: independentSession.sessionId,
      activeSandboxPolicy: sandbox.networkPolicy,
      activeSessionPolicy: activeSession.networkPolicy,
      independentSandboxPolicy: independent.networkPolicy,
      independentSessionPolicy: independentSession.networkPolicy,
    };
    const denyAllReadbackPassed = exactDenyAllSameSession(policyReadback);
    controls.denyAllReadback = { ...policyReadback, passed: denyAllReadbackPassed };
    if (!denyAllReadbackPassed) throw new Error("deny-all update lacked exact same-session readback");

    const denyCommand = await runJsonCommand(sandbox, remoteHealthProbe, healthConfig("deny-control"), 8_192);
    commands.denyHealth = denyCommand.command;
    const denyHealth = sanitizeHealthEvidence(denyCommand.parsed);
    controls.denyHealth = denyHealth;
    const denyHealthBlocked = denyHealthControlActivelyBlocked(denyHealth, input.runId);
    controls.denyHealthActivelyBlocked = denyHealthBlocked;
    if (!denyHealthBlocked) {
      throw new Error("owned Worker health request was not actively blocked by deny-all");
    }

    const mmdsCommand = await runJsonCommand(sandbox, remoteMmdsProbe, mmdsConfig, 65_536);
    commands.mmds = mmdsCommand.command;
    mmds = summarizeMmdsDifferential(mmdsCommand.parsed, input.runId);
    controls.mmdsToken200 = mmds.token200 === true;
    controls.mmdsAuthenticatedRoot200 = mmds.authenticatedRoot200 === true;
    if (mmds.attributionPassed !== true || mmds.token200 !== true || mmds.authenticatedRoot200 !== true) {
      throw new Error("MMDS did not return both a token and authenticated root under deny-all");
    }
  } catch (error) {
    executionError = safeError(error, input.credentials.token);
  } finally {
    if (sandbox) {
      cleanup.stopAttempted = true;
      try {
        await sandbox.stop();
        cleanup.stopped = true;
      } catch (error) {
        cleanup.errors.push(`stop: ${safeError(error, input.credentials.token)}`);
      }
      cleanup.deleteAttempted = true;
      try {
        await sandbox.delete();
        cleanup.deleted = true;
      } catch (error) {
        cleanup.errors.push(`delete: ${safeError(error, input.credentials.token)}`);
      }
    }
  }

  const candidate = executionError === undefined && cleanup.stopped && cleanup.deleted &&
    cleanup.errors.length === 0 && controls.initialAllowAllReadbackPassed === true &&
    controls.allowHealthPassed === true && controls.denyHealthActivelyBlocked === true &&
    controls.mmdsToken200 === true && controls.mmdsAuthenticatedRoot200 === true;
  return {
    schemaVersion: 1,
    testId,
    runId: input.runId,
    assessment: {
      outcome: candidate ? "candidate" : "indeterminate",
      candidate,
      rationale: candidate
        ? "literal deny-all blocked an owned public endpoint but allowed MMDS token and authenticated root responses"
        : "the differential or cleanup controls were incomplete",
    },
    credentialContext: {
      mode: "explicit-alias-verified",
      aliasEmail: eligibleAliasEmail,
      teamId: input.credentials.teamId,
      projectId: input.credentials.projectId,
      tokenStored: false,
    },
    sandbox: sandboxEvidence,
    controls,
    commands,
    mmds,
    retention: {
      responseBodies: false,
      tokenBodyOrDigest: false,
      sensitiveResponseDigests: false,
      commandOutputBodies: false,
    },
    cleanup,
    ...(executionError ? { executionError } : {}),
  };
}

async function main(): Promise<void> {
  const runId = randomUUID();
  const credentials = requiredCredentials(process.env);
  await verifyAliasIdentity(credentials.token);
  const [health, mmds, discoveryRules] = await Promise.all([
    readFile(resolve("guest/public-health-control.mjs"), "utf8"),
    readFile(resolve("guest/mmds-link-local-probe.mjs"), "utf8"),
    readFile(resolve("guest/mmds-discovery-rules.mjs"), "utf8"),
  ]);
  const evidence = await executeDenyAllMmdsDifferential({
    runId,
    credentials,
    sources: { health, mmds, discoveryRules },
    aliasIdentityVerified: true,
  });
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const evidencePath = resolve(artifactsDirectory, `SBX-020-differential-${runId}-private.json`);
  await writeFile(evidencePath, `${JSON.stringify({
    ...evidence,
    completedAt: new Date().toISOString(),
    sourceAttestation: {
      healthProbeSha256: createHash("sha256").update(health).digest("hex"),
      mmdsProbeSha256: createHash("sha256").update(mmds).digest("hex"),
      discoveryRulesSha256: createHash("sha256").update(discoveryRules).digest("hex"),
    },
  }, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify({
    testId,
    runId,
    assessment: evidence.assessment,
    controls: evidence.controls,
    cleanup: evidence.cleanup,
    retention: evidence.retention,
    evidencePath,
  }, null, 2)}\n`);
  const assessment = record(evidence.assessment);
  const cleanup = record(evidence.cleanup);
  if (assessment?.candidate !== true || cleanup?.stopped !== true || cleanup.deleted !== true) {
    throw new Error(typeof evidence.executionError === "string" ? evidence.executionError : "SBX-020 was indeterminate");
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
