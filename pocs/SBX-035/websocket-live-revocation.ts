import "dotenv/config";

import { randomBytes, randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Sandbox, type Command, type NetworkPolicy } from "@vercel/sandbox";
import { startSbx035Receiver, type Sbx035Receiver, type Sbx035ReceiverStatus } from "./receiver.js";
import {
  SBX035_CASE_ID,
  SBX035_TEST_ID,
  assessSbx035,
  derivePreOperationId,
  deriveSecretCommitment,
  deriveSecretOperationId,
  exactDenyAllSameSession,
  exactFreshActiveBlock,
  type Sbx035FreshBlockEvidence,
  type Sbx035RetainedEvidence,
} from "./verdict.js";

const eligibleAliasEmail = "swve@wearehackerone.com";
const eligibleTeamId = "team_n98ERpVwV7HqmWRudAyK8sXQ";
const eligibleProjectId = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
const scopeConfirmation = "I_CONTROL_THE_WSS_ORIGIN_AND_AUTHORIZE_ONE_SYNTHETIC_SECRET_SEND";
const remoteProbePath = "/tmp/sbx-035/websocket-revocation-probe.mjs";
const remoteSecretPath = "/tmp/sbx-035/operator-secret";
const controlTimeoutMs = 30_000;
const guestOutputLimit = 16 * 1024;

interface ExplicitCredentials {
  token: string;
  teamId: string;
  projectId: string;
}

interface CommandEvidence {
  commandId: string;
  exitCode: number;
  durationMs?: number;
  stdoutByteLength: number;
  stderrByteLength: number;
  rawOutputRetained: false;
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

export function explicitCredentials(environment: NodeJS.ProcessEnv): ExplicitCredentials {
  const token = required(environment, "VERCEL_TOKEN");
  const teamId = required(environment, "VERCEL_TEAM_ID");
  const projectId = required(environment, "VERCEL_PROJECT_ID");
  if (teamId !== eligibleTeamId || projectId !== eligibleProjectId) {
    throw new Error("SBX-035 must use the verified HackerOne-alias team and project");
  }
  return { token, teamId, projectId };
}

function publicIpv4(value: string): boolean {
  if (isIP(value) !== 4 || value.split(".").some((part) => !/^(?:0|[1-9][0-9]{0,2})$/u.test(part))) return false;
  const [a = -1, b = -1] = value.split(".").map(Number);
  return a > 0 && a < 224 && a !== 10 && a !== 127 && !(a === 172 && b >= 16 && b <= 31) &&
    !(a === 192 && b === 168) && !(a === 169 && b === 254) && !(a === 100 && b >= 64 && b <= 127);
}

export function controlledEndpoint(environment: NodeJS.ProcessEnv): { origin: URL; pinnedIPv4: string; receiverPort: number } {
  if (environment.SBX035_SCOPE_CONFIRMATION !== scopeConfirmation) {
    throw new Error(`SBX035_SCOPE_CONFIRMATION must equal ${scopeConfirmation}`);
  }
  const origin = new URL(required(environment, "SBX035_ENDPOINT_ORIGIN"));
  if (origin.protocol !== "https:" || origin.port || origin.username || origin.password || origin.pathname !== "/" ||
    origin.search || origin.hash || isIP(origin.hostname)) {
    throw new Error("SBX035_ENDPOINT_ORIGIN must be a bare HTTPS hostname on port 443");
  }
  const pinnedIPv4 = required(environment, "SBX035_PINNED_IPV4");
  if (!publicIpv4(pinnedIPv4)) throw new Error("SBX035_PINNED_IPV4 must be a canonical public IPv4 address");
  const receiverPort = Number(environment.SBX035_RECEIVER_PORT ?? "8788");
  if (!Number.isInteger(receiverPort) || receiverPort < 1 || receiverPort > 65_535) {
    throw new Error("SBX035_RECEIVER_PORT is invalid");
  }
  return { origin, pinnedIPv4, receiverPort };
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

export function exactAllowOnlyPolicy(value: unknown, hostname: string): boolean {
  const policy = object(value);
  return policy !== undefined && Object.keys(policy).length === 1 && Array.isArray(policy.allow) &&
    policy.allow.length === 1 && policy.allow[0] === hostname;
}

function signal(timeoutMs = controlTimeoutMs): AbortSignal {
  return AbortSignal.timeout(timeoutMs);
}

async function verifyAliasIdentity(token: string): Promise<void> {
  const response = await fetch("https://api.vercel.com/v2/user", {
    headers: { Authorization: `Bearer ${token}` },
    signal: signal(10_000),
  });
  if (!response.ok) throw new Error(`Vercel alias verification returned ${response.status}`);
  const payload = await response.json() as { user?: { email?: unknown } };
  if (payload.user?.email !== eligibleAliasEmail) throw new Error("Vercel token is not authenticated as the HackerOne alias");
}

function safeError(error: unknown, secrets: readonly string[]): string {
  let output = error instanceof Error ? error.message : String(error);
  for (const secret of secrets) if (secret) output = output.split(secret).join("[REDACTED]");
  return output.replace(/[\0\r\n]/gu, " ").slice(0, 1_000);
}

async function publicHealth(origin: URL): Promise<boolean> {
  const response = await fetch(new URL("/healthz", origin), { signal: signal(8_000), redirect: "error" });
  if (response.status !== 200) return false;
  const body = await response.arrayBuffer();
  if (body.byteLength > 1_024) return false;
  const value = object(JSON.parse(Buffer.from(body).toString("utf8")));
  return value?.ok === true && value.service === "sbx035-websocket-receiver";
}

function probeConfiguration(input: {
  mode: "retained" | "fresh-https" | "fresh-wss";
  runId: string;
  endpointHost: string;
  pinnedIPv4: string;
  publicCanary: string;
  expectedPreOperationId: string;
}) {
  return {
    scopeConfirmation,
    mode: input.mode,
    runId: input.runId,
    testId: SBX035_TEST_ID,
    caseId: SBX035_CASE_ID,
    endpointHost: input.endpointHost,
    pinnedIPv4: input.pinnedIPv4,
    pinnedPort: 443,
    websocketPath: "/v1/sbx035/ws",
    healthPath: "/healthz",
    publicCanary: input.publicCanary,
    expectedPreOperationId: input.expectedPreOperationId,
    readinessPath: `/tmp/sbx-035/${input.runId}-ready.json`,
    triggerPath: `/tmp/sbx-035/${input.runId}-trigger`,
    operatorSecretPath: remoteSecretPath,
    connectTimeoutMs: 3_000,
    ioTimeoutMs: 5_000,
    triggerTimeoutMs: 90_000,
  };
}

async function waitForSandboxFile(sandbox: Sandbox, path: string, timeoutMs: number): Promise<Buffer> {
  const started = Date.now();
  while (Date.now() - started <= timeoutMs) {
    const value = await sandbox.readFileToBuffer({ path }, { signal: signal(5_000) });
    if (value !== null) return value;
    await new Promise((resolveWait) => setTimeout(resolveWait, 75));
  }
  throw new Error(`timed out waiting for ${path}`);
}

function boundedJson(stdout: string, stderr: string, secrets: readonly string[]): unknown {
  if (Buffer.byteLength(stdout) > guestOutputLimit || Buffer.byteLength(stderr) > guestOutputLimit) {
    throw new Error("guest output exceeded its bound");
  }
  if (secrets.some((secret) => secret && (stdout.includes(secret) || stderr.includes(secret)))) {
    throw new Error("guest output contained controller-only material");
  }
  return JSON.parse(stdout);
}

async function captureFinished(command: Awaited<ReturnType<Sandbox["runCommand"]>>, secrets: readonly string[]): Promise<{
  parsed: unknown;
  command: CommandEvidence;
}> {
  const [stdout, stderr] = await Promise.all([command.stdout({ signal: signal() }), command.stderr({ signal: signal() })]);
  return {
    parsed: boundedJson(stdout, stderr, secrets),
    command: {
      commandId: command.cmdId,
      exitCode: command.exitCode,
      ...(command.durationMs !== undefined ? { durationMs: command.durationMs } : {}),
      stdoutByteLength: Buffer.byteLength(stdout),
      stderrByteLength: Buffer.byteLength(stderr),
      rawOutputRetained: false,
    },
  };
}

async function captureDetached(command: Command, secrets: readonly string[]): Promise<{
  parsed: unknown;
  command: CommandEvidence;
}> {
  const finished = await command.wait({ signal: signal(30_000) });
  return await captureFinished(finished, secrets);
}

function text(value: unknown, maximum = 1024): string | undefined {
  return typeof value === "string" && value.length <= maximum ? value : undefined;
}

function bool(value: unknown): boolean {
  return value === true;
}

function number(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : -1;
}

export function sanitizeFreshEvidence(value: unknown): Sbx035FreshBlockEvidence {
  const input = object(value) ?? {};
  return {
    ok: bool(input.ok),
    mode: input.mode === "fresh-wss" ? "fresh-wss" : "fresh-https",
    runId: text(input.runId, 36) ?? "",
    testId: text(input.testId, 64) ?? "",
    caseId: text(input.caseId, 128) ?? "",
    endpointHost: text(input.endpointHost, 253) ?? "",
    pinnedIPv4: text(input.pinnedIPv4, 15) ?? "",
    pinnedPort: number(input.pinnedPort),
    attemptCount: number(input.attemptCount),
    retryCount: number(input.retryCount),
    strictCertificateVerification: bool(input.strictCertificateVerification),
    environmentProxyTrust: bool(input.environmentProxyTrust),
    tcpConnected: bool(input.tcpConnected),
    tlsEstablished: bool(input.tlsEstablished),
    responseStarted: bool(input.responseStarted),
    receivedResponse: bool(input.receivedResponse),
    timedOut: bool(input.timedOut),
    durationMs: number(input.durationMs),
    ...(text(input.errorCode, 64) ? { errorCode: text(input.errorCode, 64)! } : {}),
  };
}

export function sanitizeRetainedEvidence(value: unknown): Sbx035RetainedEvidence {
  const input = object(value) ?? {};
  return {
    ok: bool(input.ok),
    mode: "retained",
    runId: text(input.runId, 36) ?? "",
    testId: text(input.testId, 64) ?? "",
    caseId: text(input.caseId, 128) ?? "",
    endpointHost: text(input.endpointHost, 253) ?? "",
    pinnedIPv4: text(input.pinnedIPv4, 15) ?? "",
    pinnedPort: number(input.pinnedPort),
    tcpConnected: bool(input.tcpConnected),
    tlsEstablished: bool(input.tlsEstablished),
    strictCertificateVerification: bool(input.strictCertificateVerification),
    websocketStatusCode: number(input.websocketStatusCode),
    websocketAcceptVerified: bool(input.websocketAcceptVerified),
    preOperationId: text(input.preOperationId, 64) ?? "",
    operatorSecretFileValidated: bool(input.operatorSecretFileValidated),
    operatorSecretFileMode: number(input.operatorSecretFileMode),
    secretFramesSent: number(input.secretFramesSent),
    ...(text(input.responseOperationId, 64) ? { responseOperationId: text(input.responseOperationId, 64)! } : {}),
    rawSecretRetained: bool(input.rawSecretRetained),
    rawConfigurationRetained: bool(input.rawConfigurationRetained),
    rawFramesRetained: bool(input.rawFramesRetained),
  };
}

function defaultFresh(mode: "fresh-https" | "fresh-wss"): Sbx035FreshBlockEvidence {
  return {
    ok: false, mode, runId: "", testId: "", caseId: "", endpointHost: "", pinnedIPv4: "", pinnedPort: -1,
    attemptCount: -1, retryCount: -1, strictCertificateVerification: false, environmentProxyTrust: false,
    tcpConnected: false, tlsEstablished: false, responseStarted: false, receivedResponse: false,
    timedOut: false, durationMs: -1,
  };
}

function defaultRetained(): Sbx035RetainedEvidence {
  return {
    ok: false, mode: "retained", runId: "", testId: "", caseId: "", endpointHost: "", pinnedIPv4: "",
    pinnedPort: -1, tcpConnected: false, tlsEstablished: false, strictCertificateVerification: false,
    websocketStatusCode: -1, websocketAcceptVerified: false, preOperationId: "",
    operatorSecretFileValidated: false, operatorSecretFileMode: -1, secretFramesSent: -1,
    rawSecretRetained: false, rawConfigurationRetained: false, rawFramesRetained: false,
  };
}

function emptyObserver(): Sbx035ReceiverStatus {
  return {
    configured: false, preAccepted: false, registered: false, secretAccepted: false,
    secretMessageCount: 0, rawSecretStored: false,
  };
}

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  const runId = randomUUID();
  const sandboxName = `sbx-035-${runId}`;
  const credentials = explicitCredentials(process.env);
  const endpoint = controlledEndpoint(process.env);
  const receiverKey = required(process.env, "SBX035_RECEIVER_KEY");
  const sensitiveValues = [credentials.token, receiverKey];
  const publicCanary = `corr_${randomBytes(18).toString("base64url")}`;
  const expectedPreOperationId = derivePreOperationId(receiverKey, runId, SBX035_CASE_ID, publicCanary);
  const initialPolicy = { allow: [endpoint.origin.hostname] } satisfies NetworkPolicy;
  const tags = { harness: "vsc", test: "SBX-035", run: runId };
  const cleanup = {
    secretOverwriteAttempted: false, secretOverwritten: false,
    stopAttempted: false, stopped: false, deleteAttempted: false, deleted: false,
    receiverRunDeleteAttempted: false, receiverRunDeleted: false, receiverRunAbsent: false,
    receiverCloseAttempted: false, receiverClosed: false, errors: [] as string[],
  };
  const commands: Record<string, CommandEvidence> = {};
  let receiver: Sbx035Receiver | undefined;
  let sandbox: Sandbox | undefined;
  let retainedCommand: Command | undefined;
  let executionError: string | undefined;
  let sessionId = "";
  let identityAndScopePassed = false;
  let initialAllowReadbackPassed = false;
  let denyAllSameSessionReadbackPassed = false;
  let retainedReadyBeforeDeny = false;
  let observerPre = emptyObserver();
  let observerFinal = emptyObserver();
  let freshHttps = defaultFresh("fresh-https");
  let freshWss = defaultFresh("fresh-wss");
  let retained = defaultRetained();
  let policyUpdatedAt = startedAt;
  let freshControlsCompletedAt = startedAt;
  let operatorSecretCreatedAt = startedAt;
  let operatorSecretWrittenAt = startedAt;
  let triggerWrittenAt = startedAt;
  let operatorSecretStagedMode0600 = false;
  let expectedSecretOperationId = `ws_${"A".repeat(43)}`;
  let operatorSecret: string | undefined;

  try {
    await verifyAliasIdentity(credentials.token);
    receiver = await startSbx035Receiver({ key: receiverKey, port: endpoint.receiverPort });
    if (!(await publicHealth(endpoint.origin))) throw new Error("Quick Tunnel did not route to the local SBX-035 receiver");
    identityAndScopePassed = true;

    sandbox = await Sandbox.create({
      name: sandboxName,
      persistent: false,
      timeout: 180_000,
      networkPolicy: initialPolicy,
      tags,
      signal: signal(45_000),
      ...credentials,
    });
    const initialSession = sandbox.currentSession();
    sessionId = initialSession.sessionId;
    const independentInitial = await Sandbox.get({ name: sandboxName, resume: false, signal: signal(), ...credentials });
    const independentInitialSession = independentInitial.currentSession();
    initialAllowReadbackPassed = sandbox.name === sandboxName && sandbox.persistent === false &&
      initialSession.sessionId === sessionId && independentInitialSession.sessionId === sessionId &&
      exactAllowOnlyPolicy(sandbox.networkPolicy, endpoint.origin.hostname) &&
      exactAllowOnlyPolicy(initialSession.networkPolicy, endpoint.origin.hostname) &&
      exactAllowOnlyPolicy(independentInitial.networkPolicy, endpoint.origin.hostname) &&
      exactAllowOnlyPolicy(independentInitialSession.networkPolicy, endpoint.origin.hostname);
    if (!initialAllowReadbackPassed) throw new Error("initial one-host allow policy readback failed");

    const source = await readFile(resolve("guest/websocket-revocation-probe.mjs"), "utf8");
    if (sensitiveValues.some((secret) => source.includes(secret))) throw new Error("guest source contains controller-only material");
    await sandbox.writeFiles([{ path: remoteProbePath, content: source, mode: 0o700 }], { signal: signal() });
    const base = { runId, endpointHost: endpoint.origin.hostname, pinnedIPv4: endpoint.pinnedIPv4, publicCanary, expectedPreOperationId };
    const retainedConfig = probeConfiguration({ ...base, mode: "retained" });
    retainedCommand = await sandbox.runCommand({
      cmd: "node",
      args: [remoteProbePath, Buffer.from(JSON.stringify(retainedConfig)).toString("base64url")],
      detached: true,
      timeoutMs: 120_000,
    });
    const readinessRaw = await waitForSandboxFile(sandbox, retainedConfig.readinessPath, 20_000);
    if (readinessRaw.length > 8_192) throw new Error("readiness evidence exceeded its bound");
    const readiness = object(JSON.parse(readinessRaw.toString("utf8")));
    retainedReadyBeforeDeny = readiness?.ready === true && readiness.runId === runId &&
      readiness.testId === SBX035_TEST_ID && readiness.caseId === SBX035_CASE_ID &&
      readiness.endpointHost === endpoint.origin.hostname && readiness.pinnedIPv4 === endpoint.pinnedIPv4 &&
      readiness.pinnedPort === 443 && readiness.tcpConnected === true && readiness.tlsEstablished === true &&
      readiness.strictCertificateVerification === true && readiness.websocketStatusCode === 101 &&
      readiness.websocketAcceptVerified === true && readiness.preOperationId === expectedPreOperationId &&
      readiness.rawConfigurationRetained === false && readiness.rawFramesRetained === false;
    if (!retainedReadyBeforeDeny) throw new Error("strict TLS/WebSocket public pre-canary control failed");
    observerPre = receiver.status(runId);
    if (!observerPre.preAccepted || observerPre.preOperationId !== expectedPreOperationId) {
      throw new Error("local receiver did not confirm the pre-canary HMAC action");
    }

    await sandbox.update({ networkPolicy: "deny-all" }, { signal: signal() });
    policyUpdatedAt = new Date().toISOString();
    const activeSession = sandbox.currentSession();
    const independent = await Sandbox.get({ name: sandboxName, resume: false, signal: signal(), ...credentials });
    const independentSession = independent.currentSession();
    denyAllSameSessionReadbackPassed = exactDenyAllSameSession({
      originalSessionId: sessionId,
      activeSessionId: activeSession.sessionId,
      independentSessionId: independentSession.sessionId,
      activeSandboxPolicy: sandbox.networkPolicy,
      activeSessionPolicy: activeSession.networkPolicy,
      independentSandboxPolicy: independent.networkPolicy,
      independentSessionPolicy: independentSession.networkPolicy,
    });
    if (!denyAllSameSessionReadbackPassed) throw new Error("literal deny-all lacked active and independent same-session readbacks");

    for (const mode of ["fresh-https", "fresh-wss"] as const) {
      const config = probeConfiguration({ ...base, mode });
      const finished = await sandbox.runCommand({
        cmd: "node",
        args: [remoteProbePath, Buffer.from(JSON.stringify(config)).toString("base64url")],
        timeoutMs: 15_000,
      });
      const captured = await captureFinished(finished, sensitiveValues);
      commands[mode] = captured.command;
      const sanitized = sanitizeFreshEvidence(captured.parsed);
      if (mode === "fresh-https") freshHttps = sanitized;
      else freshWss = sanitized;
      if (finished.exitCode !== 0 || !exactFreshActiveBlock(sanitized, {
        mode, runId, endpointHost: endpoint.origin.hostname, pinnedIPv4: endpoint.pinnedIPv4,
      })) throw new Error(`${mode} was not actively blocked at the exact pinned IPv4/SNI`);
    }
    freshControlsCompletedAt = new Date().toISOString();

    operatorSecret = `opsec_${randomBytes(32).toString("base64url")}`;
    operatorSecretCreatedAt = new Date().toISOString();
    sensitiveValues.push(operatorSecret);
    const commitment = deriveSecretCommitment(receiverKey, runId, SBX035_CASE_ID, operatorSecret);
    expectedSecretOperationId = deriveSecretOperationId(receiverKey, runId, SBX035_CASE_ID, commitment);
    if (receiver.register(runId, SBX035_CASE_ID, commitment) !== expectedSecretOperationId) {
      throw new Error("receiver registration returned the wrong opaque operation ID");
    }
    await sandbox.writeFiles([{ path: remoteSecretPath, content: operatorSecret, mode: 0o600 }], { signal: signal() });
    operatorSecretWrittenAt = new Date().toISOString();
    operatorSecretStagedMode0600 = true;
    await sandbox.writeFiles([{ path: retainedConfig.triggerPath, content: "go\n", mode: 0o600 }], { signal: signal() });
    triggerWrittenAt = new Date().toISOString();

    const retainedCapture = await captureDetached(retainedCommand, sensitiveValues);
    commands.retained = retainedCapture.command;
    retained = sanitizeRetainedEvidence(retainedCapture.parsed);
    observerFinal = receiver.status(runId);
  } catch (error) {
    executionError = safeError(error, sensitiveValues);
    if (receiver) observerFinal = receiver.status(runId);
  } finally {
    if (sandbox && operatorSecretStagedMode0600) {
      cleanup.secretOverwriteAttempted = true;
      try {
        await sandbox.writeFiles([{ path: remoteSecretPath, content: "", mode: 0o600 }], { signal: signal() });
        cleanup.secretOverwritten = true;
      } catch (error) {
        cleanup.errors.push(`secret overwrite: ${safeError(error, sensitiveValues)}`);
      }
    }
    operatorSecret = undefined;
    if (sandbox) {
      cleanup.stopAttempted = true;
      try { await sandbox.stop({ signal: signal() }); cleanup.stopped = true; }
      catch (error) { cleanup.errors.push(`stop: ${safeError(error, sensitiveValues)}`); }
      cleanup.deleteAttempted = true;
      try { await sandbox.delete({ signal: signal() }); cleanup.deleted = true; }
      catch (error) { cleanup.errors.push(`delete: ${safeError(error, sensitiveValues)}`); }
    }
    if (receiver) {
      cleanup.receiverRunDeleteAttempted = true;
      try {
        cleanup.receiverRunDeleted = receiver.deleteRun(runId);
        cleanup.receiverRunAbsent = receiver.status(runId).configured === false;
      } catch (error) {
        cleanup.errors.push(`receiver run delete: ${safeError(error, sensitiveValues)}`);
      }
      cleanup.receiverCloseAttempted = true;
      try { await receiver.close(); cleanup.receiverClosed = true; }
      catch (error) { cleanup.errors.push(`receiver close: ${safeError(error, sensitiveValues)}`); }
    }
  }

  const cleanupPassed = cleanup.secretOverwritten && cleanup.stopped && cleanup.deleted &&
    cleanup.receiverRunDeleted && cleanup.receiverRunAbsent && cleanup.receiverClosed && cleanup.errors.length === 0;
  const assessment = assessSbx035({
    runId,
    endpointHost: endpoint.origin.hostname,
    pinnedIPv4: endpoint.pinnedIPv4,
    expectedPreOperationId,
    expectedSecretOperationId,
    identityAndScopePassed,
    initialAllowReadbackPassed,
    denyAllSameSessionReadbackPassed,
    retainedReadyBeforeDeny,
    observerPre,
    freshHttps,
    freshWss,
    retained,
    observerFinal,
    policyUpdatedAt,
    freshControlsCompletedAt,
    operatorSecretCreatedAt,
    operatorSecretWrittenAt,
    triggerWrittenAt,
    ...(observerFinal.receiptAt ? { observerReceiptAt: observerFinal.receiptAt } : {}),
    operatorSecretStagedMode0600,
    cleanupPassed,
    retention: {
      rawOperatorSecret: false,
      rawGuestConfiguration: false,
      rawCommandStdout: false,
      rawCommandStderr: false,
      rawWebSocketFrames: false,
      rawSecretInArtifact: false,
      secretDigestInArtifact: false,
    },
    ...(executionError ? { executionError: true } : {}),
  });
  const evidence = {
    schemaVersion: 1,
    testId: SBX035_TEST_ID,
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    assessment,
    credentialContext: {
      aliasEmail: eligibleAliasEmail,
      teamId: credentials.teamId,
      projectId: credentials.projectId,
      tokenStored: false,
    },
    sandbox: { name: sandboxName, sessionId, initialPolicy, finalPolicy: "deny-all" },
    endpoint: { origin: endpoint.origin.origin, pinnedIPv4: endpoint.pinnedIPv4, pinnedPort: 443 },
    controls: {
      identityAndScopePassed,
      initialAllowReadbackPassed,
      denyAllSameSessionReadbackPassed,
      retainedReadyBeforeDeny,
      observerPre,
      freshHttps,
      freshWss,
      operatorSecretStagedMode0600,
    },
    retained,
    observerFinal,
    commands,
    ordering: {
      policyUpdatedAt,
      freshControlsCompletedAt,
      operatorSecretCreatedAt,
      operatorSecretWrittenAt,
      triggerWrittenAt,
      ...(observerFinal.receiptAt ? { observerReceiptAt: observerFinal.receiptAt } : {}),
    },
    retention: {
      rawOperatorSecret: false,
      rawGuestConfiguration: false,
      rawCommandStdout: false,
      rawCommandStderr: false,
      rawWebSocketFrames: false,
      rawSecretInArtifact: false,
      secretDigestInArtifact: false,
    },
    cleanup,
    ...(executionError ? { executionError } : {}),
  };
  const serialized = `${JSON.stringify(evidence, null, 2)}\n`;
  if (sensitiveValues.some((secret) => secret && serialized.includes(secret))) {
    throw new Error("refusing to persist evidence containing controller-only material");
  }
  const artifacts = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  await mkdir(artifacts, { recursive: true, mode: 0o700 });
  const evidencePath = resolve(artifacts, `SBX-035-${runId}-private.json`);
  await writeFile(evidencePath, serialized, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify({
    testId: SBX035_TEST_ID,
    runId,
    assessment,
    controls: evidence.controls,
    retained,
    observerFinal,
    cleanup,
    evidencePath,
  }, null, 2)}\n`);
  if (assessment.verdict === "error" || assessment.verdict === "indeterminate") {
    throw new Error(executionError ?? assessment.summary);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
