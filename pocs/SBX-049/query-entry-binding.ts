import "dotenv/config";

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdir, open, readFile, unlink, writeFile, type FileHandle } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { APIError, Sandbox, type NetworkPolicy } from "@vercel/sandbox";
import { verifyEligibleAliasToken } from "../eligible-alias-identity.js";
import {
  expectedOperationId,
  queryForCase,
  secretCommitment,
  SBX049_CASES,
  SBX049_REDACTED_VALUE,
  SBX049_TEST_ID,
  SBX049_TRANSFORM_HEADER,
  type Sbx049CaseId,
} from "./protocol.js";
import {
  assessSbx049,
  exactPolicyProof,
  type Sbx049AssessmentInput,
  type Sbx049CleanupEvidence,
  type Sbx049LedgerEvidence,
  type Sbx049PolicyProof,
  type Sbx049ProbeEvidence,
} from "./verdict.js";

const SCOPE_CONFIRMATION = "I_CONTROL_SBX049_ORIGIN_AND_AUTHORIZE_BOUNDED_QUERY_MATCHER_TESTING";
const ALIAS_EMAIL = "swve@wearehackerone.com";
const TEAM_ID = "team_n98ERpVwV7HqmWRudAyK8sXQ";
const PROJECT_ID = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
const REMOTE_PROBE_PATH = "/tmp/sbx-049/query-entry-binding-probe.mjs";
const CONTROL_TIMEOUT_MS = 30_000;
const INTER_REQUEST_MS = 350;

interface Credentials { token: string; teamId: string; projectId: string }

interface CommandRecord {
  caseId: Sbx049CaseId;
  commandId: string;
  exitCode: number;
  startedAt: string;
  completedAt: string;
  stdoutBytes: number;
  stdoutSha256: string;
  stderrBytes: number;
  stderrSha256: string;
  configurationSha256: string;
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

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

export function controlledInputs(environment: NodeJS.ProcessEnv = process.env): {
  credentials: Credentials;
  origin: URL;
  adminKey: string;
  actionKey: string;
} {
  if (environment.SBX049_SCOPE_CONFIRMATION !== SCOPE_CONFIRMATION) {
    throw new Error(`SBX049_SCOPE_CONFIRMATION must equal ${SCOPE_CONFIRMATION}`);
  }
  if (environment.SBX049_ALIAS_EMAIL_CONFIRMATION !== ALIAS_EMAIL ||
      environment.VERCEL_TEAM_ID !== TEAM_ID || environment.VERCEL_PROJECT_ID !== PROJECT_ID) {
    throw new Error("SBX-049 requires the exact verified HackerOne-alias identity, team, and project");
  }
  const origin = new URL(required(environment, "SBX049_PUBLIC_ORIGIN"));
  if (
    origin.protocol !== "https:" || origin.username || origin.password || origin.port ||
    origin.pathname !== "/" || origin.search || origin.hash || isIP(origin.hostname) !== 0 ||
    origin.hostname !== origin.hostname.toLowerCase()
  ) throw new Error("SBX049_PUBLIC_ORIGIN must be an exact lower-case researcher-controlled HTTPS origin");
  const adminKey = required(environment, "SBX049_ADMIN_KEY");
  const actionKey = required(environment, "SBX049_ACTION_KEY");
  if (Buffer.byteLength(adminKey) < 32 || Buffer.byteLength(adminKey) > 256 ||
      Buffer.byteLength(actionKey) < 32 || Buffer.byteLength(actionKey) > 256 || adminKey === actionKey ||
      /[\0\r\n]/u.test(adminKey + actionKey)) {
    throw new Error("SBX-049 keys must be distinct 32+ byte values without line breaks");
  }
  return {
    credentials: { token: required(environment, "VERCEL_TOKEN"), teamId: TEAM_ID, projectId: PROJECT_ID },
    origin,
    adminKey,
    actionKey,
  };
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function signal(timeout = CONTROL_TIMEOUT_MS): AbortSignal {
  return AbortSignal.timeout(timeout);
}

function isNotFound(error: unknown): boolean {
  return error instanceof APIError && error.response.status === 404;
}

function safeError(error: unknown, secrets: string[]): string {
  let output = error instanceof Error ? error.message : String(error);
  for (const secret of secrets) output = output.split(secret).join("[REDACTED]");
  return output.replace(/[\0\r\n]/gu, " ").slice(0, 1_000);
}

function redactPolicy(value: unknown, secret: string): unknown {
  return JSON.parse(JSON.stringify(value).split(secret).join(SBX049_REDACTED_VALUE)) as unknown;
}

async function policyProof(
  stage: Sbx049PolicyProof["stage"],
  sandbox: Sandbox,
  sessionId: string,
  credentials: Credentials,
  secret: string,
): Promise<Sbx049PolicyProof> {
  const activeSession = sandbox.currentSession();
  const independent = await Sandbox.get({ name: sandbox.name, resume: false, ...credentials, signal: signal() });
  const independentSession = independent.currentSession();
  const raw = [sandbox.networkPolicy, activeSession.networkPolicy, independent.networkPolicy, independentSession.networkPolicy];
  const serialized = JSON.stringify(raw);
  return {
    stage,
    initialSessionId: sessionId,
    activeSessionId: activeSession.sessionId,
    independentSessionId: independentSession.sessionId,
    activeSandboxPolicy: redactPolicy(sandbox.networkPolicy, secret),
    activeSessionPolicy: redactPolicy(activeSession.networkPolicy, secret),
    independentSandboxPolicy: redactPolicy(independent.networkPolicy, secret),
    independentSessionPolicy: redactPolicy(independentSession.networkPolicy, secret),
    rawSecretPresentInReadbacks: serialized.includes(secret),
    platformRedactionMarkerPresent: serialized.includes(SBX049_REDACTED_VALUE),
  };
}

function number(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function string(value: unknown, maximum = 4_096): string | undefined {
  return typeof value === "string" && value.length <= maximum ? value : undefined;
}

function sanitizeProbe(value: unknown, commandExitCode: number): Sbx049ProbeEvidence {
  const root = object(value) ?? {};
  const trustNames = Array.isArray(root.inheritedPlatformTrustEnvironmentNames)
    ? root.inheritedPlatformTrustEnvironmentNames.filter((entry): entry is string => typeof entry === "string")
    : [];
  return {
    schemaVersion: number(root.schemaVersion) ?? -1,
    testId: string(root.testId, 64) ?? "missing",
    runId: string(root.runId, 128) ?? "missing",
    caseId: string(root.caseId, 64) ?? "missing",
    correlationCanary: string(root.correlationCanary, 128) ?? "missing",
    commandExitCode,
    ok: root.ok === true,
    phase: string(root.phase, 64) ?? "missing",
    requestHostname: string(root.requestHostname, 256) ?? "missing",
    requestServername: string(root.requestServername, 256) ?? "missing",
    requestPath: string(root.requestPath, 4_096) ?? "missing",
    connectionAttempts: number(root.connectionAttempts) ?? -1,
    actualConnections: number(root.actualConnections) ?? -1,
    actualRequests: number(root.actualRequests) ?? -1,
    retries: number(root.retries) ?? -1,
    redirectsFollowed: number(root.redirectsFollowed) ?? -1,
    rejectUnauthorized: root.rejectUnauthorized === true,
    controllerConfigurableCustomTrustAccepted: root.controllerConfigurableCustomTrustAccepted === true,
    inheritedPlatformTrustEnvironmentNames: trustNames,
    tcpConnected: root.tcpConnected === true,
    tlsEstablished: root.tlsEstablished === true,
    tlsAuthorized: root.tlsAuthorized === true,
    responseReceived: root.responseReceived === true,
    ...(number(root.responseStatusCode) !== undefined ? { responseStatusCode: number(root.responseStatusCode)! } : {}),
    responseShapeValid: root.responseShapeValid === true,
    ...(typeof root.responseBrokered === "boolean" ? { responseBrokered: root.responseBrokered } : {}),
    ...(string(root.responseOperationId, 128) ? { responseOperationId: string(root.responseOperationId, 128)! } : {}),
    responseBodyRetained: root.responseBodyRetained === true,
    durationMs: number(root.durationMs) ?? -1,
    ...(string(root.errorCode, 64) ? { errorCode: string(root.errorCode, 64)! } : {}),
  };
}

async function adminRequest(
  origin: URL,
  adminKey: string,
  runId: string,
  init: RequestInit = {},
): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set("authorization", `Bearer ${adminKey}`);
  if (init.body) headers.set("content-type", "application/json");
  return await fetch(new URL(`/v1/sbx049/admin/runs/${encodeURIComponent(runId)}`, origin), {
    ...init,
    headers,
    redirect: "error",
    signal: signal(10_000),
  });
}

async function ledgerSnapshot(origin: URL, adminKey: string, runId: string): Promise<Sbx049LedgerEvidence> {
  const response = await adminRequest(origin, adminKey, runId);
  if (!response.ok) throw new Error(`SBX-049 ledger readback returned ${response.status}`);
  const root = object(await response.json());
  if (!root || !exactKeys(root, [
    "brokeredSecretDigestRetained", "configured", "events", "rawBrokeredSecretRetained",
  ]) || root.configured !== true || !Array.isArray(root.events) ||
      root.rawBrokeredSecretRetained !== false || root.brokeredSecretDigestRetained !== false) {
    throw new Error("SBX-049 ledger shape was invalid");
  }
  const events = root.events.map((raw): Sbx049LedgerEvidence["events"][number] => {
    const event = object(raw);
    if (!event || !exactKeys(event, [
      "brokered", "canaryMatched", "caseId", "observedAt", "operationId", "ordinal", "queryMatched",
    ]) || !SBX049_CASES.includes(event.caseId as Sbx049CaseId) || event.canaryMatched !== true ||
        event.queryMatched !== true || typeof event.brokered !== "boolean" ||
        typeof event.operationId !== "string" || typeof event.ordinal !== "number" ||
        typeof event.observedAt !== "string") throw new Error("SBX-049 ledger event was invalid");
    return {
      ordinal: event.ordinal,
      observedAt: event.observedAt,
      caseId: event.caseId as Sbx049CaseId,
      canaryMatched: true,
      queryMatched: true,
      brokered: event.brokered,
      operationId: event.operationId,
    };
  });
  return {
    configured: true,
    events,
    rawBrokeredSecretRetained: false,
    brokeredSecretDigestRetained: false,
  };
}

function emptyProbe(runId: string, caseId: Sbx049CaseId, canary: string, hostname: string): Sbx049ProbeEvidence {
  return {
    schemaVersion: -1, testId: "missing", runId, caseId, correlationCanary: canary,
    commandExitCode: -1, ok: false, phase: "missing", requestHostname: hostname,
    requestServername: hostname, requestPath: "missing", connectionAttempts: 0,
    actualConnections: 0, actualRequests: 0, retries: 0, redirectsFollowed: 0,
    rejectUnauthorized: true, controllerConfigurableCustomTrustAccepted: false,
    inheritedPlatformTrustEnvironmentNames: [], tcpConnected: false, tlsEstablished: false,
    tlsAuthorized: false, responseReceived: false, responseShapeValid: false,
    responseBodyRetained: false, durationMs: -1,
  };
}

async function cleanupSandbox(
  sandbox: Sandbox | undefined,
  sandboxName: string,
  createAttempted: boolean,
  credentials: Credentials,
  tags: Record<string, string>,
  secrets: string[],
): Promise<Sbx049CleanupEvidence["sandbox"]> {
  const cleanup = { stopped: false, deleted: false, absenceChecks: 0, errors: [] as string[] };
  let handle = sandbox;
  if (!handle && createAttempted) {
    try {
      const recovered = await Sandbox.get({ name: sandboxName, resume: false, ...credentials, signal: signal() });
      if (recovered.tags?.run === tags.run && recovered.tags?.test === tags.test) handle = recovered;
      else cleanup.errors.push("orphan recovery found a sandbox without the exact run tags; left untouched");
    } catch (error) {
      if (!isNotFound(error)) cleanup.errors.push(`orphan recovery: ${safeError(error, secrets)}`);
    }
  }
  if (handle) {
    try { await handle.stop({ signal: signal() }); cleanup.stopped = true; }
    catch (error) { cleanup.errors.push(`stop: ${safeError(error, secrets)}`); }
    try { await handle.delete({ signal: signal() }); cleanup.deleted = true; }
    catch (error) { cleanup.errors.push(`delete: ${safeError(error, secrets)}`); }
    if (cleanup.deleted) {
      for (let attempt = 0; attempt < 2; attempt += 1) {
        if (attempt) await delay(500);
        try { await Sandbox.get({ name: sandboxName, resume: false, ...credentials, signal: signal() }); }
        catch (error) {
          if (isNotFound(error)) cleanup.absenceChecks += 1;
          else cleanup.errors.push(`absence: ${safeError(error, secrets)}`);
        }
      }
    }
  }
  return cleanup;
}

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  const { credentials, origin, adminKey, actionKey } = controlledInputs();
  const runId = randomUUID();
  const canaries = Object.fromEntries(SBX049_CASES.map((caseId) =>
    [caseId, `c49_${randomBytes(18).toString("base64url")}`])) as Record<Sbx049CaseId, string>;
  const brokeredSecret = `s49_${randomBytes(32).toString("base64url")}`;
  const expectedOperationIds = Object.fromEntries(SBX049_CASES.map((caseId) => [caseId, {
    reach: expectedOperationId(actionKey, origin.hostname, runId, caseId, canaries[caseId]),
    secret: expectedOperationId(actionKey, origin.hostname, runId, caseId, canaries[caseId], brokeredSecret),
  }])) as Record<Sbx049CaseId, { reach: string; secret: string }>;
  const secrets = [credentials.token, adminKey, actionKey, brokeredSecret];
  const policy: NetworkPolicy = {
    allow: {
      [origin.hostname]: [{
        match: { queryString: [{ key: { exact: "role" }, value: { exact: "privileged" } }] },
        transform: [{ headers: { [SBX049_TRANSFORM_HEADER]: brokeredSecret } }],
      }],
    },
  };
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  const artifactPath = resolve(artifactsDirectory, `SBX-049-${runId}.json`);
  const lockPath = resolve(artifactsDirectory, "SBX-049-live-active.lock");
  const sandboxName = `sbx-049-${runId.replaceAll("-", "")}`;
  const tags = { harness: "vsc", test: SBX049_TEST_ID, run: runId };
  const guestSource = await readFile(resolve("guest/query-entry-binding-probe.mjs"), "utf8");
  if (secrets.some((secret) => guestSource.includes(secret))) throw new Error("guest source contains controller-only material");
  await mkdir(artifactsDirectory, { recursive: true });
  let lock: FileHandle | undefined;
  let sandbox: Sandbox | undefined;
  let createAttempted = false;
  let receiverConfigureAttempted = false;
  let executionError: string | undefined;
  let policyBefore: Sbx049PolicyProof | undefined;
  let policyAfter: Sbx049PolicyProof | undefined;
  let ledger: Sbx049LedgerEvidence = {
    configured: false, events: [], rawBrokeredSecretRetained: false, brokeredSecretDigestRetained: false,
  };
  const probes = Object.fromEntries(SBX049_CASES.map((caseId) =>
    [caseId, emptyProbe(runId, caseId, canaries[caseId], origin.hostname)])) as Record<Sbx049CaseId, Sbx049ProbeEvidence>;
  const commands: CommandRecord[] = [];
  const receiverCleanup: Sbx049CleanupEvidence["receiver"] = { deleted: false, absent: false, errors: [] };
  let sandboxCleanup: Sbx049CleanupEvidence["sandbox"] = { stopped: false, deleted: false, absenceChecks: 0, errors: [] };
  let identityProof: Awaited<ReturnType<typeof verifyEligibleAliasToken>> | undefined;

  try {
    lock = await open(lockPath, "wx", 0o600);
    identityProof = await verifyEligibleAliasToken({
      token: credentials.token,
      expectedEmail: ALIAS_EMAIL,
      expectedTeamId: TEAM_ID,
      expectedProjectId: PROJECT_ID,
      manualEmailConfirmation: process.env.SBX049_ALIAS_EMAIL_CONFIRMATION,
    });
    receiverConfigureAttempted = true;
    const configurationResponse = await adminRequest(origin, adminKey, runId, {
      method: "PUT",
      body: JSON.stringify({
        secretCommitment: secretCommitment(actionKey, brokeredSecret),
        cases: SBX049_CASES.map((caseId) => ({
          caseId,
          canary: canaries[caseId],
          rawQuery: queryForCase(runId, caseId, canaries[caseId]),
        })),
      }),
    });
    if (configurationResponse.status !== 201) throw new Error(`receiver configuration returned ${configurationResponse.status}`);
    await configurationResponse.arrayBuffer();
    ledger = await ledgerSnapshot(origin, adminKey, runId);
    if (ledger.events.length !== 0) throw new Error("receiver did not start with an empty ledger");

    createAttempted = true;
    sandbox = await Sandbox.create({
      name: sandboxName,
      persistent: false,
      timeout: 300_000,
      resources: { vcpus: 2 },
      networkPolicy: policy,
      tags,
      ...credentials,
      signal: signal(),
    });
    if (sandbox.name !== sandboxName || sandbox.tags?.run !== runId || sandbox.tags?.test !== SBX049_TEST_ID) {
      throw new Error("sandbox identity mismatch");
    }
    const sessionId = sandbox.currentSession().sessionId;
    policyBefore = await policyProof("before", sandbox, sessionId, credentials, brokeredSecret);
    if (!exactPolicyProof(policyBefore, origin.hostname)) throw new Error("pre-request policy proof failed");
    await sandbox.writeFiles([{ path: REMOTE_PROBE_PATH, content: guestSource, mode: 0o700 }], { signal: signal() });

    for (const [index, caseId] of SBX049_CASES.entries()) {
      const url = new URL("/v1/sbx049/action", origin);
      url.search = queryForCase(runId, caseId, canaries[caseId]);
      const configuration = {
        scopeConfirmation: "researcher-controlled-sbx049-origin-only",
        testId: SBX049_TEST_ID,
        runId,
        caseId,
        canary: canaries[caseId],
        origin: origin.toString(),
        url: url.toString(),
        timeoutMs: 8_000,
      };
      const serialized = JSON.stringify(configuration);
      if (secrets.some((secret) => serialized.includes(secret))) throw new Error(`${caseId} guest configuration contains controller-only material`);
      const commandStartedAt = new Date().toISOString();
      const command = await sandbox.runCommand({
        cmd: "node",
        args: [REMOTE_PROBE_PATH, Buffer.from(serialized).toString("base64url")],
        timeoutMs: 20_000,
        signal: signal(),
      });
      const [stdout, stderr] = await Promise.all([
        command.stdout({ signal: signal() }), command.stderr({ signal: signal() }),
      ]);
      if (Buffer.byteLength(stdout) > 64_000 || Buffer.byteLength(stderr) > 16_000 ||
          secrets.some((secret) => stdout.includes(secret) || stderr.includes(secret))) {
        throw new Error(`${caseId} guest output violated retention bounds`);
      }
      let raw: unknown;
      try { raw = JSON.parse(stdout); } catch { throw new Error(`${caseId} guest output was not JSON`); }
      probes[caseId] = sanitizeProbe(raw, command.exitCode);
      commands.push({
        caseId,
        commandId: command.cmdId,
        exitCode: command.exitCode,
        startedAt: commandStartedAt,
        completedAt: new Date().toISOString(),
        stdoutBytes: Buffer.byteLength(stdout),
        stdoutSha256: sha256(stdout),
        stderrBytes: Buffer.byteLength(stderr),
        stderrSha256: sha256(stderr),
        configurationSha256: sha256(serialized),
      });
      await delay(INTER_REQUEST_MS);
      ledger = await ledgerSnapshot(origin, adminKey, runId);
      if (ledger.events.length !== index + 1) throw new Error(`${caseId} did not produce exactly one fresh receiver event`);
      const expectedBrokered = caseId === "exact-pair";
      const expectedId = expectedBrokered ? expectedOperationIds[caseId].secret : expectedOperationIds[caseId].reach;
      if (caseId !== "combined-halves" &&
          (probes[caseId].responseBrokered !== expectedBrokered || probes[caseId].responseOperationId !== expectedId)) {
        throw new Error(`${caseId} control failed`);
      }
      await delay(INTER_REQUEST_MS);
    }
    policyAfter = await policyProof("after", sandbox, sessionId, credentials, brokeredSecret);
    if (!exactPolicyProof(policyAfter, origin.hostname)) throw new Error("post-request policy proof failed");
    ledger = await ledgerSnapshot(origin, adminKey, runId);
  } catch (error) {
    executionError = safeError(error, secrets);
  } finally {
    sandboxCleanup = await cleanupSandbox(sandbox, sandboxName, createAttempted, credentials, tags, secrets);
    if (receiverConfigureAttempted) {
      try {
        const response = await adminRequest(origin, adminKey, runId, { method: "DELETE" });
        receiverCleanup.deleted = response.status === 204 || response.status === 404;
        if (!receiverCleanup.deleted) receiverCleanup.errors.push(`receiver delete returned ${response.status}`);
      } catch (error) { receiverCleanup.errors.push(`receiver delete: ${safeError(error, secrets)}`); }
      try {
        const response = await adminRequest(origin, adminKey, runId);
        receiverCleanup.absent = response.status === 404;
        if (!receiverCleanup.absent) receiverCleanup.errors.push(`receiver absence returned ${response.status}`);
      } catch (error) { receiverCleanup.errors.push(`receiver absence: ${safeError(error, secrets)}`); }
    }
  }

  const missingProof = (stage: "before" | "after"): Sbx049PolicyProof => ({
    stage, initialSessionId: "missing", activeSessionId: "missing", independentSessionId: "missing",
    activeSandboxPolicy: null, activeSessionPolicy: null, independentSandboxPolicy: null,
    independentSessionPolicy: null, rawSecretPresentInReadbacks: false, platformRedactionMarkerPresent: false,
  });
  const assessmentInput: Sbx049AssessmentInput = {
    ...(executionError ? { executionError } : {}),
    runId,
    hostname: origin.hostname,
    canaries,
    expectedOperationIds,
    probes,
    policyBefore: policyBefore ?? missingProof("before"),
    policyAfter: policyAfter ?? missingProof("after"),
    ledger,
    cleanup: { sandbox: sandboxCleanup, receiver: receiverCleanup },
  };
  const assessment = assessSbx049(assessmentInput);
  const evidence = {
    schemaVersion: 1,
    testId: SBX049_TEST_ID,
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    identity: identityProof,
    origin: origin.origin,
    policy: { matcher: { key: "role", value: "privileged" }, transformedHeader: SBX049_TRANSFORM_HEADER },
    expectedOperationIds,
    matrix: probes,
    policyReadbacks: { before: assessmentInput.policyBefore, after: assessmentInput.policyAfter },
    receiverLedger: ledger,
    commands,
    cleanup: assessmentInput.cleanup,
    assessment,
    retention: {
      rawBrokeredSecret: false,
      brokeredSecretDigest: false,
      controllerKeys: false,
      rawGuestOutput: false,
    },
    evidencePath: artifactPath,
  };
  const serializedEvidence = `${JSON.stringify(evidence, null, 2)}\n`;
  if (secrets.some((secret) => serializedEvidence.includes(secret))) {
    throw new Error("refusing to persist SBX-049 evidence containing controller-only material");
  }
  await writeFile(artifactPath, serializedEvidence, { mode: 0o600, flag: "wx" });
  if (lock) {
    await lock.close();
    await unlink(lockPath).catch(() => undefined);
  }
  process.stdout.write(serializedEvidence);
  process.exitCode = assessment.outcome === "candidate-high" || assessment.outcome === "pass" ? 0 : 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
