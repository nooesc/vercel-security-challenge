import "dotenv/config";

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { APIError, Sandbox } from "@vercel/sandbox";
import { verifyEligibleAliasToken } from "../eligible-alias-identity.js";
import {
  acquireSbx054Lock,
  createSbx054Journal,
  loadSbx054Config,
  readSbx054Journal,
  removeSbx054Journal,
  sbx054ArtifactPath,
  SBX054_ARTIFACTS,
  SBX054_SANDBOX_TIMEOUT_MS,
  writeSbx054Journal,
  writeSbx054PrivateJson,
  type Sbx054Config,
  type Sbx054RecoveryJournal,
  type Sbx054Role,
} from "./safety.js";
import {
  assessSbx054,
  assertSbx054NoRawSecrets,
  deriveSbx054CanaryCommitment,
  deriveSbx054OperationId,
  deriveSbx054Receipt,
  deriveSbx054SecretProof,
  isSbx054PreconnectBlock,
  parseSbx054Guest,
  sameSbx054BlockTuple,
  SBX054_CASES,
  SBX054_DIGEST,
  SBX054_RUNTIME,
  SBX054_TEST_ID,
  type Sbx054Assessment,
  type Sbx054Controls,
  type Sbx054ExpectedProofs,
  type Sbx054GuestResult,
  type Sbx054ObserverSnapshot,
} from "./verdict.js";

const EXPECTED_SDK_VERSION = "3.0.0";
const REPOSITORY_ROOT = fileURLToPath(new URL("../../", import.meta.url));
const GUEST_SOURCE_PATH = resolve(REPOSITORY_ROOT, "guest/sbx-054-legacy-create-policy-probe.mjs");
const REMOTE_GUEST_PATH = "/tmp/sbx-054/legacy-create-policy-probe.mjs";
const REMOTE_SECRET_PATH = "/tmp/sbx-054/operator-secret";
const CONTROL_TIMEOUT_MS = 45_000;
const COMMAND_TIMEOUT_MS = 15_000;
const UNKNOWN_CREATE_SETTLEMENT_MS = CONTROL_TIMEOUT_MS + SBX054_SANDBOX_TIMEOUT_MS + 30_000;
const CONTROL_INTERVAL_MS = 275;
const MAX_RESPONSE_BYTES = 64 * 1024;

export const SBX054_FIXED_GUEST_SHA256 =
  "b07ce6f163f36221076402e21b3919a9771e7ab386e994315db04710ff0bafe6" as const;

export interface Sbx054SdkAudit {
  installedVersion: "3.0.0";
  runtimePresenceSelectsV2: true;
  runtimeAbsenceSelectsV3: true;
  sameNetworkPolicySerialization: true;
  serverBoundaryRequired: true;
}

export interface Sbx054PolicyReadback {
  role: Sbx054Role;
  stage: "pre-request" | "post-public" | "post-target-pre" | "post-target-final" | "final" | "cleanup";
  startedAt: string;
  completedAt: string;
  name: string;
  sessionId: string;
  independentSessionId: string;
  activeSandboxPolicy: "deny-all" | "unexpected";
  activeSessionPolicy: "deny-all" | "unexpected";
  independentSandboxPolicy: "deny-all" | "unexpected";
  independentSessionPolicy: "deny-all" | "unexpected";
  activeRoutes: number;
  independentRoutes: number;
  activeRuntime: string | null;
  independentRuntime: string | null;
  exactNameTagsPersistence: boolean;
  exactSession: boolean;
  exactRuntime: boolean;
  passed: boolean;
}

interface RuntimeState {
  comparator?: Sandbox;
  target?: Sandbox;
}

class Gate {
  private last = 0;
  private queue: Promise<void> = Promise.resolve();

  before(): Promise<void> {
    const current = this.queue.then(async () => {
      const remaining = CONTROL_INTERVAL_MS - (Date.now() - this.last);
      if (remaining > 0) await delay(remaining);
      this.last = Date.now();
    });
    this.queue = current.catch(() => undefined);
    return current;
  }
}

function signal(timeout = CONTROL_TIMEOUT_MS): AbortSignal {
  return AbortSignal.timeout(timeout);
}

function isNotFound(error: unknown): boolean {
  return error instanceof APIError && error.response.status === 404;
}

function exactTags(actual: Record<string, string> | undefined, expected: Record<string, string>): boolean {
  if (!actual) return false;
  const keys = Object.keys(expected);
  return Object.keys(actual).length === keys.length && keys.every((key) => actual[key] === expected[key]);
}

function classifyPolicy(value: unknown): "deny-all" | "unexpected" {
  return value === "deny-all" ? "deny-all" : "unexpected";
}

function freshCanary(): string {
  return `c54_${randomBytes(32).toString("base64url")}`;
}

function assertControllerRuntime(): void {
  const trust = [
    "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF", "OPENSSL_MODULES",
    "SSL_CERT_DIR", "SSL_CERT_FILE",
  ].filter((name) => process.env[name] !== undefined);
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0" || trust.length > 0 ||
      (process.env.NODE_OPTIONS !== undefined && process.env.NODE_OPTIONS.trim() !== "")) {
    throw new Error("SBX-054 controller refuses TLS trust overrides or runtime injection");
  }
}

export function sbx054ComparatorCreateParameters(
  config: Pick<Sbx054Config, "token" | "teamId" | "projectId">,
  name: string,
  tags: Record<string, string>,
) {
  return {
    token: config.token,
    teamId: config.teamId,
    projectId: config.projectId,
    name,
    persistent: false,
    timeout: SBX054_SANDBOX_TIMEOUT_MS,
    ports: [] as number[],
    env: {},
    networkPolicy: "deny-all" as const,
    tags,
    signal: signal(),
  };
}

export function sbx054TargetCreateParameters(
  config: Pick<Sbx054Config, "token" | "teamId" | "projectId">,
  name: string,
  tags: Record<string, string>,
) {
  return {
    ...sbx054ComparatorCreateParameters(config, name, tags),
    runtime: SBX054_RUNTIME,
  };
}

export async function auditSbx054SdkAndGuest(): Promise<{ audit: Sbx054SdkAudit; guestSource: string }> {
  const metadata = JSON.parse(await readFile(
    new URL("../../node_modules/@vercel/sandbox/package.json", import.meta.url), "utf8",
  )) as { version?: unknown };
  if (metadata.version !== EXPECTED_SDK_VERSION) throw new Error("SBX-054 SDK version changed");
  const client = await readFile(
    new URL("../../node_modules/@vercel/sandbox/dist/api-client/api-client.js", import.meta.url), "utf8",
  );
  if (!client.includes('const endpoint = params.runtime === void 0 ? "/v3/sandboxes" : "/v2/sandboxes";') ||
      !client.includes("networkPolicy: params.networkPolicy ? toAPINetworkPolicy(params.networkPolicy) : void 0")) {
    throw new Error("SBX-054 audited SDK route or policy serializer changed");
  }
  const guestSource = await readFile(GUEST_SOURCE_PATH, "utf8");
  const digest = createHash("sha256").update(guestSource, "utf8").digest("hex");
  if (digest !== SBX054_FIXED_GUEST_SHA256) throw new Error("SBX-054 fixed guest digest changed");
  return {
    audit: {
      installedVersion: "3.0.0",
      runtimePresenceSelectsV2: true,
      runtimeAbsenceSelectsV3: true,
      sameNetworkPolicySerialization: true,
      serverBoundaryRequired: true,
    },
    guestSource,
  };
}

async function verifyIdentity(config: Sbx054Config, gate: Gate): Promise<void> {
  const gatedFetch: typeof fetch = async (input, init) => {
    await gate.before();
    return fetch(input, init);
  };
  await verifyEligibleAliasToken({
    token: config.token,
    expectedEmail: config.expectedAlias,
    expectedTeamId: config.teamId,
    expectedProjectId: config.projectId,
    ...(config.manualAliasConfirmation === undefined
      ? {}
      : { manualEmailConfirmation: config.manualAliasConfirmation }),
    fetchImpl: gatedFetch,
  });
}

async function policyReadback(input: {
  config: Sbx054Config;
  gate: Gate;
  role: Sbx054Role;
  stage: Sbx054PolicyReadback["stage"];
  active: Sandbox;
  expectedName: string;
  expectedTags: Record<string, string>;
  expectedSessionId: string;
}): Promise<Sbx054PolicyReadback> {
  const startedAt = new Date().toISOString();
  await input.gate.before();
  const independent = await Sandbox.get({
    token: input.config.token,
    teamId: input.config.teamId,
    projectId: input.config.projectId,
    name: input.expectedName,
    resume: false,
    signal: signal(),
  });
  const activeSession = input.active.currentSession();
  const independentSession = independent.currentSession();
  const exactNameTagsPersistence = input.active.name === input.expectedName &&
    independent.name === input.expectedName && exactTags(input.active.tags, input.expectedTags) &&
    exactTags(independent.tags, input.expectedTags) && input.active.persistent === false &&
    independent.persistent === false;
  const exactSession = activeSession.sessionId === input.expectedSessionId &&
    independentSession.sessionId === input.expectedSessionId;
  const exactRuntime = input.role === "target"
    ? input.active.runtime === SBX054_RUNTIME && independent.runtime === SBX054_RUNTIME
    : true;
  const evidence: Sbx054PolicyReadback = {
    role: input.role,
    stage: input.stage,
    startedAt,
    completedAt: new Date().toISOString(),
    name: input.expectedName,
    sessionId: input.expectedSessionId,
    independentSessionId: independentSession.sessionId,
    activeSandboxPolicy: classifyPolicy(input.active.networkPolicy),
    activeSessionPolicy: classifyPolicy(activeSession.networkPolicy),
    independentSandboxPolicy: classifyPolicy(independent.networkPolicy),
    independentSessionPolicy: classifyPolicy(independentSession.networkPolicy),
    activeRoutes: input.active.routes.length,
    independentRoutes: independent.routes.length,
    activeRuntime: input.active.runtime ?? null,
    independentRuntime: independent.runtime ?? null,
    exactNameTagsPersistence,
    exactSession,
    exactRuntime,
    passed: false,
  };
  evidence.passed = exactNameTagsPersistence && exactSession && exactRuntime &&
    evidence.activeRoutes === 0 && evidence.independentRoutes === 0 &&
    evidence.activeSandboxPolicy === "deny-all" && evidence.activeSessionPolicy === "deny-all" &&
    evidence.independentSandboxPolicy === "deny-all" && evidence.independentSessionPolicy === "deny-all";
  return evidence;
}

async function readBoundedJson(response: Response): Promise<unknown> {
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) throw new Error("response exceeded bound");
  const bytes = Buffer.from(await response.arrayBuffer());
  try {
    if (bytes.byteLength > MAX_RESPONSE_BYTES) throw new Error("response exceeded bound");
    return bytes.byteLength === 0 ? undefined : JSON.parse(bytes.toString("utf8"));
  } finally {
    bytes.fill(0);
  }
}

async function adminRequest(input: {
  config: Sbx054Config;
  gate: Gate;
  path: string;
  method: "GET" | "PUT" | "DELETE";
  expected: number | readonly number[];
  body?: string | Buffer;
  contentType?: string;
}): Promise<unknown> {
  await input.gate.before();
  const response = await fetch(new URL(input.path, input.config.adminOrigin), {
    method: input.method,
    headers: {
      authorization: `Bearer ${input.config.adminKey}`,
      ...(input.body === undefined ? {} : { "content-type": input.contentType ?? "application/json" }),
    },
    ...(input.body === undefined ? {} : { body: input.body }),
    redirect: "error",
    signal: signal(),
  });
  const accepted = Array.isArray(input.expected) ? input.expected : [input.expected];
  if (!accepted.includes(response.status)) throw new Error("SBX-054 admin request status was unexpected");
  return readBoundedJson(response);
}

async function publicHealth(config: Sbx054Config, gate: Gate): Promise<boolean> {
  await gate.before();
  const response = await fetch(new URL("/healthz", config.publicOrigin), {
    method: "GET",
    redirect: "error",
    cache: "no-store",
    signal: signal(15_000),
  });
  const body = await readBoundedJson(response) as Record<string, unknown> | undefined;
  return response.status === 200 && body?.ok === true && body.testId === SBX054_TEST_ID &&
    body.hostMatched === true && body.receiverRuntimeTrustExact === true &&
    Array.isArray(body.receiverTrustEnvironmentNames) && body.receiverTrustEnvironmentNames.length === 0 &&
    body.receiverNodeOptionsPresent === false && body.receiverTlsVerificationDisabled === false;
}

function observerSnapshot(value: unknown): Sbx054ObserverSnapshot {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("SBX-054 observer snapshot was not an object");
  }
  const root = value as Record<string, unknown>;
  const expected = [
    "configured", "configuredAt", "events", "secretStaged", "secretCleared", "unexpectedRequests",
    "rawCanaryRetained", "rawSecretRetained", "rawBodyRetained", "secretDigestRetained",
    "receiverRuntimeTrustExact", "receiverTrustEnvironmentNames", "receiverNodeOptionsPresent",
    "receiverTlsVerificationDisabled",
  ].sort();
  if (Object.keys(root).sort().join("\0") !== expected.join("\0") || root.configured !== true ||
      typeof root.configuredAt !== "string" || !Array.isArray(root.events) ||
      typeof root.secretStaged !== "boolean" || typeof root.secretCleared !== "boolean" ||
      typeof root.unexpectedRequests !== "number" || !Number.isInteger(root.unexpectedRequests) ||
      root.unexpectedRequests < 0 || root.rawCanaryRetained !== false || root.rawSecretRetained !== false ||
      root.rawBodyRetained !== false || root.secretDigestRetained !== false ||
      root.receiverRuntimeTrustExact !== true || !Array.isArray(root.receiverTrustEnvironmentNames) ||
      root.receiverTrustEnvironmentNames.length !== 0 || root.receiverNodeOptionsPresent !== false ||
      root.receiverTlsVerificationDisabled !== false) {
    throw new Error("SBX-054 observer snapshot controls were invalid");
  }
  const requiredEventKeys = [
    "sequence", "observedAt", "kind", "caseId", "method", "hostHeaderLines", "hostHeaderValues",
    "hostMatched", "pathMatched", "canaryCommitment", "bodyLength", "secretMatched", "responseStatus",
  ];
  const optionalEventKeys = ["receipt", "secretProof", "operationId"];
  const allowedEventKeys = new Set([...requiredEventKeys, ...optionalEventKeys]);
  for (let index = 0; index < root.events.length; index += 1) {
    const raw = root.events[index];
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
      throw new Error("SBX-054 observer event was not an object");
    }
    const event = raw as Record<string, unknown>;
    const keys = Object.keys(event);
    if (!requiredEventKeys.every((key) => Object.prototype.hasOwnProperty.call(event, key)) ||
        keys.some((key) => !allowedEventKeys.has(key)) || event.sequence !== index + 1 ||
        typeof event.observedAt !== "string" || !Number.isFinite(Date.parse(event.observedAt)) ||
        (event.kind !== "public" && event.kind !== "secret") ||
        !(SBX054_CASES as readonly unknown[]).includes(event.caseId) ||
        typeof event.method !== "string" || typeof event.hostHeaderLines !== "number" ||
        !Number.isInteger(event.hostHeaderLines) || typeof event.hostHeaderValues !== "number" ||
        !Number.isInteger(event.hostHeaderValues) || typeof event.hostMatched !== "boolean" ||
        typeof event.pathMatched !== "boolean" || typeof event.canaryCommitment !== "string" ||
        !SBX054_DIGEST.test(event.canaryCommitment) || typeof event.bodyLength !== "number" ||
        !Number.isInteger(event.bodyLength) || event.bodyLength < 0 || event.bodyLength > 256 ||
        typeof event.secretMatched !== "boolean" || typeof event.responseStatus !== "number" ||
        !Number.isInteger(event.responseStatus) ||
        !["receipt", "secretProof", "operationId"].every((key) =>
          event[key] === undefined || (typeof event[key] === "string" && SBX054_DIGEST.test(event[key]))) ) {
      throw new Error("SBX-054 observer event fields were not exact");
    }
  }
  return root as unknown as Sbx054ObserverSnapshot;
}

async function getObserver(config: Sbx054Config, gate: Gate, runId: string): Promise<Sbx054ObserverSnapshot> {
  return observerSnapshot(await adminRequest({
    config, gate, path: `/v1/sbx054/admin/runs/${runId}`, method: "GET", expected: 200,
  }));
}

async function runGuest(input: {
  sandbox: Sandbox;
  gate: Gate;
  guestSource: string;
  config: Sbx054Config;
  kind: "public" | "secret";
  runId: string;
  caseId: typeof SBX054_CASES[number];
  canary: string;
}): Promise<Sbx054GuestResult> {
  await input.gate.before();
  await input.sandbox.currentSession().writeFiles([
    { path: REMOTE_GUEST_PATH, content: input.guestSource, mode: 0o700 },
  ], { signal: signal() });
  await input.gate.before();
  const command = await input.sandbox.currentSession().runCommand({
    cmd: "node",
    args: [
      REMOTE_GUEST_PATH,
      input.kind,
      input.config.publicOrigin.origin,
      input.runId,
      input.caseId,
      input.canary,
      ...(input.kind === "secret" ? [REMOTE_SECRET_PATH] : []),
    ],
    timeoutMs: COMMAND_TIMEOUT_MS,
    signal: signal(),
  });
  const [stdout, stderr] = await Promise.all([command.stdout(), command.stderr()]);
  return parseSbx054Guest(stdout, stderr, command.exitCode);
}

function allTrueControls(): Sbx054Controls {
  return {
    exactEligibleIdentity: true,
    sdkVersionPinned: true,
    sdkRouteBranchExact: true,
    sameDenyAllWirePolicy: true,
    comparatorCreatedOnV3: true,
    targetCreatedOnV2: true,
    exactDistinctNamesAndSessions: true,
    comparatorPreReadbackExact: true,
    comparatorPostReadbackExact: true,
    comparatorPostTargetPreReadbackExact: true,
    comparatorFinalReadbackExact: true,
    targetPreReadbackExact: true,
    targetPostPublicReadbackExact: true,
    targetFinalReadbackExact: true,
    fixedGuestDigestMatched: true,
    receiverPreflightPassed: true,
    receiverPostflightPassed: true,
    emptyLedgerBeforeRequests: true,
    postComparatorCompletedBeforeImpact: true,
    sequentialNoRetrySchedule: true,
    cleanupSucceeded: true,
  };
}

async function checkpointCreate<T>(input: {
  journal: Sbx054RecoveryJournal;
  role: Sbx054Role;
  create(): Promise<T>;
  sessionId(value: T): string;
}): Promise<T> {
  const resource = input.journal.resources[input.role === "comparator" ? 0 : 1];
  resource.createAttemptedAt = new Date().toISOString();
  await writeSbx054Journal(input.journal);
  const value = await input.create();
  resource.createSettledAt = new Date().toISOString();
  resource.sessionId = input.sessionId(value);
  await writeSbx054Journal(input.journal);
  return value;
}

async function waitUnknownCreate(resource: Sbx054RecoveryJournal["resources"][number]): Promise<void> {
  if (resource.createAttemptedAt === undefined || resource.createSettledAt !== undefined) return;
  const remaining = Date.parse(resource.createAttemptedAt) + UNKNOWN_CREATE_SETTLEMENT_MS - Date.now();
  if (remaining > 0) await delay(remaining);
}

async function cleanupSandbox(input: {
  config: Sbx054Config;
  gate: Gate;
  journal: Sbx054RecoveryJournal;
  role: Sbx054Role;
  active?: Sandbox;
}): Promise<boolean> {
  const resource = input.journal.resources[input.role === "comparator" ? 0 : 1];
  if (resource.createAttemptedAt === undefined) {
    resource.deleted = true;
    resource.absenceChecks = 2;
    await writeSbx054Journal(input.journal);
    return true;
  }
  await waitUnknownCreate(resource);
  let sandbox = input.active;
  if (!sandbox) {
    const checks = resource.sessionId === undefined ? 1 : 2;
    for (let check = 1; check <= checks; check += 1) {
      try {
        await input.gate.before();
        sandbox = await Sandbox.get({
          token: input.config.token,
          teamId: input.config.teamId,
          projectId: input.config.projectId,
          name: resource.name,
          resume: false,
          signal: signal(),
        });
        break;
      } catch (error) {
        if (!isNotFound(error)) return false;
        if (resource.sessionId === undefined) return false;
        resource.absenceChecks = check;
        await writeSbx054Journal(input.journal);
      }
    }
    if (!sandbox) {
      resource.deleted = true;
      await writeSbx054Journal(input.journal);
      return true;
    }
  }
  const createdAt = sandbox.createdAt.getTime();
  const attributed = sandbox.name === resource.name && exactTags(sandbox.tags, resource.tags) &&
    sandbox.persistent === false && createdAt >= Date.parse(input.journal.startedAt) - 5_000 &&
    createdAt <= Date.now() + 5_000 &&
    (input.role !== "target" || sandbox.runtime === SBX054_RUNTIME);
  if (!attributed) return false;
  if (resource.sessionId === undefined) {
    resource.sessionId = sandbox.currentSession().sessionId;
    resource.createSettledAt = new Date().toISOString();
    await writeSbx054Journal(input.journal);
  }
  try {
    if (sandbox.status === "running" || sandbox.status === "pending") {
      await input.gate.before();
      await sandbox.update({ networkPolicy: "deny-all" }, { signal: signal() });
      const sessionId = resource.sessionId ?? sandbox.currentSession().sessionId;
      const cleanupReadback = await policyReadback({
        config: input.config,
        gate: input.gate,
        role: input.role,
        stage: "cleanup",
        active: sandbox,
        expectedName: resource.name,
        expectedTags: resource.tags,
        expectedSessionId: sessionId,
      });
      if (!cleanupReadback.passed) return false;
      await input.gate.before();
      await sandbox.stop({ signal: signal() });
    }
    await input.gate.before();
    await sandbox.delete({ signal: signal() });
    for (let check = 1; check <= 2; check += 1) {
      await input.gate.before();
      try {
        await Sandbox.get({
          token: input.config.token,
          teamId: input.config.teamId,
          projectId: input.config.projectId,
          name: resource.name,
          resume: false,
          signal: signal(),
        });
        return false;
      } catch (error) {
        if (!isNotFound(error)) return false;
      }
      resource.absenceChecks = check;
      await writeSbx054Journal(input.journal);
    }
    resource.deleted = true;
    await writeSbx054Journal(input.journal);
    return true;
  } catch {
    return false;
  }
}

async function cleanupReceiver(config: Sbx054Config, gate: Gate, journal: Sbx054RecoveryJournal): Promise<boolean> {
  if (!journal.receiverConfigureAttempted) {
    journal.receiverDeleted = true;
    await writeSbx054Journal(journal);
    return true;
  }
  try {
    await adminRequest({
      config, gate, path: `/v1/sbx054/admin/runs/${journal.runId}/secret`, method: "DELETE",
      expected: [204, 404],
    });
    await adminRequest({
      config, gate, path: `/v1/sbx054/admin/runs/${journal.runId}`, method: "DELETE",
      expected: [204, 404],
    });
    for (let check = 0; check < 2; check += 1) {
      await adminRequest({
        config, gate, path: `/v1/sbx054/admin/runs/${journal.runId}`, method: "GET", expected: 404,
      });
    }
    journal.receiverDeleted = true;
    await writeSbx054Journal(journal);
    return true;
  } catch {
    return false;
  }
}

async function cleanupAll(
  config: Sbx054Config,
  gate: Gate,
  journal: Sbx054RecoveryJournal,
  runtime: RuntimeState,
): Promise<boolean> {
  const target = await cleanupSandbox({
    config, gate, journal, role: "target", ...(runtime.target === undefined ? {} : { active: runtime.target }),
  });
  const comparator = await cleanupSandbox({
    config, gate, journal, role: "comparator",
    ...(runtime.comparator === undefined ? {} : { active: runtime.comparator }),
  });
  const receiver = await cleanupReceiver(config, gate, journal);
  return target && comparator && receiver;
}

async function runRecovery(config: Sbx054Config): Promise<void> {
  const runId = config.recoveryRunId!;
  const lock = await acquireSbx054Lock(runId, true);
  const journal = await readSbx054Journal(runId);
  const gate = new Gate();
  let succeeded = false;
  try {
    await verifyIdentity(config, gate);
    succeeded = await cleanupAll(config, gate, journal, {});
    if (!succeeded) throw new Error("SBX-054 cleanup-only recovery was incomplete");
    journal.completed = true;
    await writeSbx054Journal(journal);
    const recoveryArtifact = resolve(
      SBX054_ARTIFACTS,
      `SBX-054-${runId}-recovery-${randomUUID()}-private.json`,
    );
    await writeSbx054PrivateJson(recoveryArtifact, {
      schemaVersion: 1,
      visibility: "private",
      testId: SBX054_TEST_ID,
      mode: "cleanup-only",
      runId,
      completedAt: new Date().toISOString(),
      cleanupSucceeded: true,
      rawSecretsRetained: false,
    }, false);
    await lock.release();
    await removeSbx054Journal(runId);
    process.stdout.write(`${JSON.stringify({ testId: SBX054_TEST_ID, mode: "cleanup-only", cleanupSucceeded: true })}\n`);
  } catch (error) {
    if (!succeeded) await lock.closeRetainingState().catch(() => undefined);
    throw error;
  }
}

export async function runSbx054(config: Sbx054Config): Promise<Sbx054Assessment> {
  assertControllerRuntime();
  const journal = createSbx054Journal();
  const lock = await acquireSbx054Lock(journal.runId, false);
  await writeSbx054Journal(journal);
  const gate = new Gate();
  const runtime: RuntimeState = {};
  const startedAt = new Date().toISOString();
  let secret: Buffer | undefined;
  let sdkAudit: Sbx054SdkAudit | undefined;
  let guestSource = "";
  let comparatorPre: Sbx054PolicyReadback | undefined;
  let comparatorPost: Sbx054PolicyReadback | undefined;
  let comparatorPostTargetPre: Sbx054PolicyReadback | undefined;
  let comparatorFinal: Sbx054PolicyReadback | undefined;
  let targetPre: Sbx054PolicyReadback | undefined;
  let targetPostPublic: Sbx054PolicyReadback | undefined;
  let targetFinal: Sbx054PolicyReadback | undefined;
  let comparatorResult: Sbx054GuestResult | undefined;
  let postComparatorResult: Sbx054GuestResult | undefined;
  let targetPublic: Sbx054GuestResult | undefined;
  let targetSecret: Sbx054GuestResult | undefined;
  let finalObserver: Sbx054ObserverSnapshot | undefined;
  let receiverPreflightPassed = false;
  let receiverPostflightPassed = false;
  let emptyLedgerBeforeRequests = false;
  let impactAttempted = false;
  let secretGeneratedAfterPublicSignal = false;
  let secretFileWrittenAfterPublicSignal = false;
  let secretFileRequestedMode: number | undefined;
  let publicObservedAt: string | undefined;
  let postComparatorCompletedAt: string | undefined;
  let secretGeneratedAt: string | undefined;
  let secretWrittenAt: string | undefined;
  let executionFailed = false;
  let cleanupSucceeded = false;
  let identityVerified = false;
  const canaries = Object.fromEntries(SBX054_CASES.map((caseId) => [caseId, freshCanary()])) as
    Record<typeof SBX054_CASES[number], string>;
  const commitments = Object.fromEntries(SBX054_CASES.map((caseId) => [
    caseId,
    deriveSbx054CanaryCommitment(config.actionKey, journal.runId, caseId, canaries[caseId]),
  ])) as Record<typeof SBX054_CASES[number], string>;
  const expected: Sbx054ExpectedProofs = {
    runId: journal.runId,
    comparatorCanaryCommitment: commitments["v3-deny-comparator"],
    targetCanaryCommitment: commitments["v2-runtime-deny-target"],
    postComparatorCanaryCommitment: commitments["v3-deny-comparator-post"],
    secretCanaryCommitment: commitments["v2-runtime-secret"],
    targetPublicReceipt: deriveSbx054Receipt(
      config.actionKey, "public", journal.runId, "v2-runtime-deny-target",
      commitments["v2-runtime-deny-target"], false,
    ),
  };

  try {
    await verifyIdentity(config, gate);
    identityVerified = true;
    ({ audit: sdkAudit, guestSource } = await auditSbx054SdkAndGuest());
    receiverPreflightPassed = await publicHealth(config, gate);
    if (!receiverPreflightPassed) throw new Error("SBX-054 receiver public preflight failed");
    journal.receiverConfigureAttempted = true;
    await writeSbx054Journal(journal);
    await adminRequest({
      config,
      gate,
      path: `/v1/sbx054/admin/runs/${journal.runId}`,
      method: "PUT",
      expected: 204,
      body: JSON.stringify({
        runId: journal.runId,
        publicHost: config.publicOrigin.hostname,
        cases: SBX054_CASES.map((caseId, index) => ({
          caseId,
          kind: index === 3 ? "secret" : "public",
          canaryCommitment: commitments[caseId],
        })),
      }),
    });
    journal.receiverConfigured = true;
    await writeSbx054Journal(journal);
    const empty = await getObserver(config, gate, journal.runId);
    emptyLedgerBeforeRequests = empty.events.length === 0 && !empty.secretStaged &&
      !empty.secretCleared && empty.unexpectedRequests === 0;
    if (!emptyLedgerBeforeRequests) throw new Error("SBX-054 receiver ledger was not empty");

    const comparatorResource = journal.resources[0];
    runtime.comparator = await checkpointCreate({
      journal,
      role: "comparator",
      create: async () => {
        await gate.before();
        return Sandbox.create(sbx054ComparatorCreateParameters(
          config, comparatorResource.name, comparatorResource.tags,
        ));
      },
      sessionId: (sandbox) => sandbox.currentSession().sessionId,
    });
    const comparatorSession = runtime.comparator.currentSession().sessionId;
    comparatorPre = await policyReadback({
      config, gate, role: "comparator", stage: "pre-request", active: runtime.comparator,
      expectedName: comparatorResource.name, expectedTags: comparatorResource.tags,
      expectedSessionId: comparatorSession,
    });
    if (!comparatorPre.passed) throw new Error("SBX-054 comparator pre-readback failed");
    comparatorResult = await runGuest({
      sandbox: runtime.comparator,
      gate,
      guestSource,
      config,
      kind: "public",
      runId: journal.runId,
      caseId: "v3-deny-comparator",
      canary: canaries["v3-deny-comparator"],
    });
    comparatorPost = await policyReadback({
      config, gate, role: "comparator", stage: "post-public", active: runtime.comparator,
      expectedName: comparatorResource.name, expectedTags: comparatorResource.tags,
      expectedSessionId: comparatorSession,
    });
    const afterComparator = await getObserver(config, gate, journal.runId);
    if (!comparatorPost.passed || !isSbx054PreconnectBlock(comparatorResult) ||
        afterComparator.events.length !== 0 || afterComparator.unexpectedRequests !== 0) {
      throw new Error("SBX-054 v3 comparator did not fail closed exactly");
    }

    const targetResource = journal.resources[1];
    runtime.target = await checkpointCreate({
      journal,
      role: "target",
      create: async () => {
        await gate.before();
        return Sandbox.create(sbx054TargetCreateParameters(config, targetResource.name, targetResource.tags));
      },
      sessionId: (sandbox) => sandbox.currentSession().sessionId,
    });
    const targetSession = runtime.target.currentSession().sessionId;
    if (targetSession === comparatorSession || targetResource.name === comparatorResource.name) {
      throw new Error("SBX-054 resource identities collided");
    }
    targetPre = await policyReadback({
      config, gate, role: "target", stage: "pre-request", active: runtime.target,
      expectedName: targetResource.name, expectedTags: targetResource.tags, expectedSessionId: targetSession,
    });
    if (!targetPre.passed) throw new Error("SBX-054 target pre-readback failed");
    targetPublic = await runGuest({
      sandbox: runtime.target,
      gate,
      guestSource,
      config,
      kind: "public",
      runId: journal.runId,
      caseId: "v2-runtime-deny-target",
      canary: canaries["v2-runtime-deny-target"],
    });
    targetPostPublic = await policyReadback({
      config, gate, role: "target", stage: "post-public", active: runtime.target,
      expectedName: targetResource.name, expectedTags: targetResource.tags, expectedSessionId: targetSession,
    });
    if (!targetPostPublic.passed) throw new Error("SBX-054 target post-public readback failed");
    const afterTargetPublic = await getObserver(config, gate, journal.runId);
    comparatorPostTargetPre = await policyReadback({
      config, gate, role: "comparator", stage: "post-target-pre", active: runtime.comparator,
      expectedName: comparatorResource.name, expectedTags: comparatorResource.tags,
      expectedSessionId: comparatorSession,
    });
    if (!comparatorPostTargetPre.passed) {
      throw new Error("SBX-054 post-target comparator pre-readback failed");
    }
    postComparatorResult = await runGuest({
      sandbox: runtime.comparator,
      gate,
      guestSource,
      config,
      kind: "public",
      runId: journal.runId,
      caseId: "v3-deny-comparator-post",
      canary: canaries["v3-deny-comparator-post"],
    });
    postComparatorCompletedAt = new Date().toISOString();
    comparatorFinal = await policyReadback({
      config, gate, role: "comparator", stage: "post-target-final", active: runtime.comparator,
      expectedName: comparatorResource.name, expectedTags: comparatorResource.tags,
      expectedSessionId: comparatorSession,
    });
    const afterPostComparator = await getObserver(config, gate, journal.runId);
    if (!comparatorFinal.passed || !isSbx054PreconnectBlock(postComparatorResult) ||
        !sameSbx054BlockTuple(comparatorResult, postComparatorResult) ||
        afterPostComparator.unexpectedRequests !== afterTargetPublic.unexpectedRequests ||
        JSON.stringify(afterPostComparator.events) !== JSON.stringify(afterTargetPublic.events)) {
      throw new Error("SBX-054 post-target v3 comparator did not fail closed exactly");
    }
    targetFinal = await policyReadback({
      config, gate, role: "target", stage: "final", active: runtime.target,
      expectedName: targetResource.name, expectedTags: targetResource.tags, expectedSessionId: targetSession,
    });
    finalObserver = await getObserver(config, gate, journal.runId);
    receiverPostflightPassed = await publicHealth(config, gate);
    if (!targetPostPublic.passed || !targetFinal.passed || !receiverPostflightPassed) {
      throw new Error("SBX-054 target final controls failed");
    }
    const provisional = assessSbx054({
      controls: allTrueControls(),
      expected,
      comparator: comparatorResult,
      postComparator: postComparatorResult,
      targetPublic,
      observer: finalObserver,
      impactAttempted: false,
      secretGeneratedAfterPublicSignal: false,
      secretFileWrittenAfterPublicSignal: false,
    });
    if (provisional.verdict === "candidate-medium") {
      publicObservedAt = afterPostComparator.events[0]!.observedAt;
      secret = randomBytes(48);
      secretGeneratedAt = new Date().toISOString();
      secretGeneratedAfterPublicSignal = Date.parse(secretGeneratedAt) >= Date.parse(publicObservedAt) &&
        postComparatorCompletedAt !== undefined &&
        Date.parse(secretGeneratedAt) >= Date.parse(postComparatorCompletedAt);
      if (!secretGeneratedAfterPublicSignal) throw new Error("SBX-054 secret chronology failed");
      impactAttempted = true;
      expected.targetSecretReceipt = deriveSbx054Receipt(
        config.actionKey, "secret", journal.runId, "v2-runtime-secret",
        commitments["v2-runtime-secret"], true,
      );
      expected.targetSecretProof = deriveSbx054SecretProof(
        secret, journal.runId, "v2-runtime-secret", commitments["v2-runtime-secret"],
      );
      expected.targetOperationId = deriveSbx054OperationId(
        config.actionKey, journal.runId, "v2-runtime-secret", expected.targetSecretProof,
      );
      await adminRequest({
        config,
        gate,
        path: `/v1/sbx054/admin/runs/${journal.runId}/secret`,
        method: "PUT",
        expected: 204,
        body: secret,
        contentType: "application/octet-stream",
      });
      await gate.before();
      await runtime.target.currentSession().writeFiles([
        { path: REMOTE_SECRET_PATH, content: secret, mode: 0o600 },
      ], { signal: signal() });
      secretWrittenAt = new Date().toISOString();
      secretFileRequestedMode = 0o600;
      secretFileWrittenAfterPublicSignal = Date.parse(secretWrittenAt) >= Date.parse(publicObservedAt);
      if (!secretFileWrittenAfterPublicSignal) throw new Error("SBX-054 file chronology failed");
      targetSecret = await runGuest({
        sandbox: runtime.target,
        gate,
        guestSource,
        config,
        kind: "secret",
        runId: journal.runId,
        caseId: "v2-runtime-secret",
        canary: canaries["v2-runtime-secret"],
      });
      secret.fill(0);
      secret = undefined;
    } else if (provisional.verdict !== "pass") {
      throw new Error("SBX-054 target result was not attributable");
    }
    if (impactAttempted) {
      targetFinal = await policyReadback({
        config, gate, role: "target", stage: "final", active: runtime.target,
        expectedName: targetResource.name, expectedTags: targetResource.tags, expectedSessionId: targetSession,
      });
      finalObserver = await getObserver(config, gate, journal.runId);
      receiverPostflightPassed = await publicHealth(config, gate);
      if (!targetFinal.passed || !receiverPostflightPassed) {
        throw new Error("SBX-054 post-impact target final controls failed");
      }
    }
  } catch {
    executionFailed = true;
  } finally {
    secret?.fill(0);
    cleanupSucceeded = await cleanupAll(config, gate, journal, runtime);
  }

  const exactDistinct = runtime.comparator !== undefined && runtime.target !== undefined &&
    runtime.comparator.name !== runtime.target.name &&
    runtime.comparator.currentSession().sessionId !== runtime.target.currentSession().sessionId;
  const controls: Sbx054Controls = {
    exactEligibleIdentity: identityVerified,
    sdkVersionPinned: sdkAudit?.installedVersion === "3.0.0",
    sdkRouteBranchExact: sdkAudit?.runtimePresenceSelectsV2 === true &&
      sdkAudit.runtimeAbsenceSelectsV3 === true,
    sameDenyAllWirePolicy: sdkAudit?.sameNetworkPolicySerialization === true,
    comparatorCreatedOnV3: runtime.comparator !== undefined,
    targetCreatedOnV2: runtime.target?.runtime === SBX054_RUNTIME,
    exactDistinctNamesAndSessions: exactDistinct,
    comparatorPreReadbackExact: comparatorPre?.passed === true,
    comparatorPostReadbackExact: comparatorPost?.passed === true,
    comparatorPostTargetPreReadbackExact: comparatorPostTargetPre?.passed === true,
    comparatorFinalReadbackExact: comparatorFinal?.passed === true,
    targetPreReadbackExact: targetPre?.passed === true,
    targetPostPublicReadbackExact: targetPostPublic?.passed === true,
    targetFinalReadbackExact: targetFinal?.passed === true,
    fixedGuestDigestMatched: guestSource.length > 0,
    receiverPreflightPassed,
    receiverPostflightPassed,
    emptyLedgerBeforeRequests,
    postComparatorCompletedBeforeImpact: postComparatorCompletedAt !== undefined &&
      (secretGeneratedAt === undefined || Date.parse(postComparatorCompletedAt) <= Date.parse(secretGeneratedAt)),
    sequentialNoRetrySchedule: true,
    cleanupSucceeded,
  };
  const assessment = comparatorResult && postComparatorResult && targetPublic && finalObserver
    ? assessSbx054({
        controls,
        expected,
        comparator: comparatorResult,
        postComparator: postComparatorResult,
        targetPublic,
        ...(targetSecret === undefined ? {} : { targetSecret }),
        observer: finalObserver,
        impactAttempted,
        secretGeneratedAfterPublicSignal,
        secretFileWrittenAfterPublicSignal,
        ...(secretFileRequestedMode === undefined ? {} : { secretFileRequestedMode }),
      })
    : {
        verdict: "indeterminate" as const,
        candidate: false,
        severity: "unknown" as const,
        v2PublicBoundaryReached: false,
        fileBackedSecretExfiltrated: false,
        summary: "The bounded live sequence did not produce complete attributable evidence.",
      };
  const evidence = {
    schemaVersion: 1,
    visibility: "private",
    testId: SBX054_TEST_ID,
    mode: "normal",
    runId: journal.runId,
    startedAt,
    completedAt: new Date().toISOString(),
    hypothesis: "legacy-runtime v2 create may fail to attach the accepted literal deny-all policy enforced by v3 create",
    distinctFrom: [
      "protocol and DNS parser bypasses",
      "policy update, resume, snapshot, and fork lifecycle paths",
      "same-owner functional override behavior",
    ],
    sdkAudit,
    identity: {
      aliasEmail: config.expectedAlias,
      teamId: config.teamId,
      projectId: config.projectId,
      verified: identityVerified,
    },
    resources: journal.resources.map((resource) => ({
      role: resource.role,
      name: resource.name,
      tags: resource.tags,
      sessionId: resource.sessionId ?? null,
      deleted: resource.deleted,
      absenceChecks: resource.absenceChecks,
    })),
    policyReadbacks: {
      comparatorPre,
      comparatorPost,
      targetPre,
      targetPostPublic,
      comparatorPostTargetPre,
      comparatorFinal,
      targetFinal,
    },
    guest: {
      comparator: comparatorResult ?? null,
      targetPublic: targetPublic ?? null,
      postComparator: postComparatorResult ?? null,
      targetSecret: targetSecret ?? null,
      rawOutputRetained: false,
      fixedGuestSha256: SBX054_FIXED_GUEST_SHA256,
    },
    observer: finalObserver ?? null,
    chronology: {
      publicObservedAt: publicObservedAt ?? null,
      postComparatorCompletedAt: postComparatorCompletedAt ?? null,
      secretGeneratedAt: secretGeneratedAt ?? null,
      secretWrittenAt: secretWrittenAt ?? null,
      secretGeneratedAfterPublicSignal,
      secretFileWrittenAfterPublicSignal,
    },
    retention: {
      rawCanariesRetained: false,
      rawSecretRetained: false,
      secretDigestRetained: false,
      rawAdminKeyRetained: false,
      rawActionKeyRetained: false,
      rawTokenRetained: false,
      rawGuestOutputRetained: false,
    },
    executionFailed,
    cleanupSucceeded,
    controls,
    assessment,
  };
  assertSbx054NoRawSecrets(evidence, [
    Buffer.from(config.token, "utf8"),
    Buffer.from(config.adminKey, "utf8"),
    Buffer.from(config.actionKey, "utf8"),
  ]);
  if (!cleanupSucceeded) {
    await lock.closeRetainingState();
    throw new Error("SBX-054 cleanup was incomplete; recovery journal and lock were retained");
  }
  journal.completed = true;
  await writeSbx054Journal(journal);
  await writeSbx054PrivateJson(sbx054ArtifactPath(journal.runId), evidence, false);
  await lock.release();
  await removeSbx054Journal(journal.runId);
  if (assessment.candidate) process.exitCode = 10;
  return assessment;
}

async function main(): Promise<void> {
  const config = loadSbx054Config();
  if (config.recoveryRunId !== undefined) {
    await runRecovery(config);
    return;
  }
  const assessment = await runSbx054(config);
  process.stdout.write(`${JSON.stringify({ testId: SBX054_TEST_ID, assessment })}\n`);
}

const invoked = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : "";
if (import.meta.url === invoked) {
  main().catch(() => {
    process.stderr.write("SBX-054 controller failed; raw errors and secrets were suppressed\n");
    process.exitCode = 1;
  });
}
