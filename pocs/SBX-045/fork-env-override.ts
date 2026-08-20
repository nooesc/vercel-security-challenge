import "dotenv/config";

import { createHash, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import {
  APIError,
  Sandbox,
  Snapshot,
  type NetworkPolicy,
} from "@vercel/sandbox";
import {
  ARTIFACTS_DIRECTORY,
  ELIGIBLE_ALIAS,
  ELIGIBLE_PROJECT_ID,
  ELIGIBLE_TEAM_ID,
  LIVE_LOCK_PATH,
  TEST_ID,
  acquireLiveLock,
  createRecoveryJournal,
  ensurePrivateDirectory,
  evidencePath,
  parseRecoveryJournal,
  readRecoveryJournal,
  recoveryJournalPath,
  removeRecoveryJournal,
  validateRunId,
  writePrivateJsonAtomically,
  type HeldLiveLock,
  type RecoveryJournal,
  type RecoveryResource,
  type ResourceRole,
} from "./safety.js";
import {
  assessForkEnvOverride,
  assertSerializedEvidenceExcludesRawValues,
  exactDigest,
  expectedDigest,
  parseGuestDigest,
  type DigestObservation,
  type ForkEnvOverrideAssessment,
} from "./verdict.js";

const SCOPE_CONFIRMATION =
  "I_RECHECKED_SBX045_SINGLE_ACCOUNT_SCOPE_AND_WILL_USE_ONLY_THE_ELIGIBLE_ALIAS";
const SYNTHETIC_ENV_KEY = "SBX045_SYNTHETIC_ENV";
const REMOTE_GUEST_PATH = "/tmp/sbx-045/env-digest.mjs";
const CONTROL_PLANE_TIMEOUT_MS = 30_000;
const COMMAND_TIMEOUT_MS = 20_000;
const SESSION_TIMEOUT_MS = 180_000;
const SNAPSHOT_EXPIRATION_MS = 60 * 60 * 1_000;
const REQUEST_INTERVAL_MS = 250;
const ABSENCE_INTERVAL_MS = 1_000;
const MAXIMUM_IDENTITY_RESPONSE_BYTES = 64 * 1024;
const MAXIMUM_REQUESTS = 100;
const EXPECTED_SDK_VERSION = "3.0.0";
export const FIXED_GUEST_SHA256 =
  "4519370feb7d9ed09249b9d1c75326422e3e34b558a005f09362e6faa9c2ab20";
export const CLEANUP_ORDER = ["target", "inheritance", "source"] as const;

interface ExplicitConfig {
  token: string;
  teamId: typeof ELIGIBLE_TEAM_ID;
  projectId: typeof ELIGIBLE_PROJECT_ID;
  expectedEmail: typeof ELIGIBLE_ALIAS;
  inheritanceControlEnabled: boolean;
  recoveryRunId?: string;
}

interface RequestAuditRecord {
  sequence: number;
  startedAt: string;
  completedAt?: string;
  method: string;
  origin: "sandbox-control-plane" | "identity";
  pathname: string;
  status?: number;
}

interface VerifiedIdentity {
  email: typeof ELIGIBLE_ALIAS;
  userIdSha256: string;
  exactMatch: true;
}

interface ResourceCleanupRecord {
  role: ResourceRole;
  name: string;
  discoveryAttempted: boolean;
  exactMatchCount?: number;
  exactProvenanceValidated: boolean;
  orphanRecovered: boolean;
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  firstAbsenceConfirmed: boolean;
  delayedSecondAbsenceConfirmed: boolean;
  snapshotEnumerationAttempted: boolean;
  snapshotEnumerationCompleted: boolean;
  snapshotIdsDeleted: string[];
  snapshotIdsConfirmedAbsent: string[];
  manualInspectionRequired: boolean;
  errors: SafeFailure[];
}

interface SafeFailure {
  kind: "api" | "other";
  status?: number;
  code?: string;
  message?: string;
}

interface SandboxControl {
  name: string;
  sessionId: string;
  status: string;
  independentStatus: string;
  exactName: boolean;
  exactTags: boolean;
  exactPersistence: boolean;
  denyAll: boolean;
  independentSessionMatch: boolean;
  independentDenyAll: boolean;
  sessionDenyAll: boolean;
  independentSessionDenyAll: boolean;
  independentTagsMatch: boolean;
  noRoutes: boolean;
  independentNoRoutes: boolean;
  sourceSnapshotId?: string;
  currentSnapshotId?: string;
  independentCurrentSnapshotId?: string;
  independentSourceSnapshotId?: string;
}

interface DigestExecution {
  observation: DigestObservation;
  sessionId: string;
  sessionIdUnchanged: boolean;
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function assertInstalledSdkVersion(): Promise<void> {
  const text = await readFile(
    new URL("../../node_modules/@vercel/sandbox/package.json", import.meta.url),
    "utf8",
  );
  let version: unknown;
  try {
    version = (JSON.parse(text) as { version?: unknown }).version;
  } catch {
    throw new Error("SBX-045 could not parse the installed Sandbox SDK package metadata");
  }
  if (version !== EXPECTED_SDK_VERSION) {
    throw new Error("SBX-045 requires a fresh API-semantics audit for the installed SDK version");
  }
}

export function loadExplicitConfig(
  environment: NodeJS.ProcessEnv = process.env,
): ExplicitConfig {
  if (environment.SBX045_SCOPE_CONFIRMATION !== SCOPE_CONFIRMATION) {
    throw new Error("SBX045_SCOPE_CONFIRMATION did not match the exact bounded-test attestation");
  }
  const token = required(environment, "VERCEL_TOKEN");
  if (token.length < 20 || token.length > 4_096 || /[\s\0]/u.test(token)) {
    throw new Error("VERCEL_TOKEN must be one bounded non-whitespace token");
  }
  // APIClient refreshes JWT-looking credentials through @vercel/oidc outside its injected
  // fetch seam. Requiring a PAT keeps every request inside the auditable request gate.
  if (token.split(".").length === 3) {
    throw new Error("SBX-045 requires a non-JWT Vercel PAT so every request is gated");
  }
  if (environment.VERCEL_TEAM_ID !== ELIGIBLE_TEAM_ID ||
      environment.VERCEL_PROJECT_ID !== ELIGIBLE_PROJECT_ID ||
      environment.SBX045_EXPECTED_ALIAS !== ELIGIBLE_ALIAS) {
    throw new Error("SBX-045 credentials are not bound to the exact eligible alias scope");
  }
  const inheritance = environment.SBX045_ENABLE_INHERITANCE_CONTROL;
  if (inheritance !== undefined && inheritance !== "0" && inheritance !== "1") {
    throw new Error("SBX045_ENABLE_INHERITANCE_CONTROL must be 0, 1, or unset");
  }
  const recoveryRunId = environment.SBX045_RECOVERY_RUN_ID;
  if (recoveryRunId !== undefined) validateRunId(recoveryRunId);
  return {
    token,
    teamId: ELIGIBLE_TEAM_ID,
    projectId: ELIGIBLE_PROJECT_ID,
    expectedEmail: ELIGIBLE_ALIAS,
    inheritanceControlEnabled: inheritance === "1",
    ...(recoveryRunId === undefined ? {} : { recoveryRunId }),
  };
}

function exactTags(actual: Record<string, string> | undefined, expected: Record<string, string>): boolean {
  if (actual === undefined) return false;
  const expectedKeys = Object.keys(expected);
  return Object.keys(actual).length === expectedKeys.length &&
    expectedKeys.every((key) => actual[key] === expected[key]);
}

function isDenyAll(policy: NetworkPolicy | undefined): boolean {
  return policy === "deny-all";
}

function apiCode(error: APIError<unknown>): string | undefined {
  const root = error.json;
  if (root === null || typeof root !== "object" || Array.isArray(root)) return undefined;
  const nested = (root as { error?: unknown }).error;
  if (nested === null || typeof nested !== "object" || Array.isArray(nested)) return undefined;
  const code = (nested as { code?: unknown }).code;
  return typeof code === "string" && code.length <= 128 ? code : undefined;
}

function safeFailure(error: unknown, forbidden: readonly string[] = []): SafeFailure {
  if (error instanceof APIError) {
    const code = apiCode(error);
    return {
      kind: "api",
      status: error.response.status,
      ...(code === undefined ? {} : { code }),
    };
  }
  let message = error instanceof Error ? error.message : String(error);
  for (const secret of forbidden) {
    if (secret.length > 0) message = message.split(secret).join("[REDACTED]");
  }
  return { kind: "other", message: message.slice(0, 512) };
}

function snapshotAbsent(error: unknown): boolean {
  return error instanceof APIError && (
    error.response.status === 404 ||
    (error.response.status === 410 &&
      [undefined, "not_found", "snapshot_not_found"].includes(apiCode(error)))
  );
}

function requestUrl(input: string | URL | Request): URL {
  return new URL(input instanceof Request ? input.url : input.toString());
}

export function createGatedFetch(
  rawFetch: typeof fetch = globalThis.fetch,
  now: () => number = Date.now,
  wait: (milliseconds: number) => Promise<void> = async (milliseconds) => {
    await delay(milliseconds);
  },
): { fetch: typeof fetch; records: RequestAuditRecord[] } {
  const records: RequestAuditRecord[] = [];
  let reservedRequests = 0;
  let lastStartedAt = 0;
  let scheduling = Promise.resolve();

  const gated = (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = requestUrl(input);
    const sandboxPath = url.origin === "https://vercel.com" &&
      /^\/api\/v[23]\/sandboxes(?:\/|$)/u.test(url.pathname);
    const identityPath = url.origin === "https://api.vercel.com" && url.pathname === "/v2/user";
    if (url.protocol !== "https:" || (!sandboxPath && !identityPath) ||
        url.username !== "" || url.password !== "" || url.hash !== "") {
      throw new Error("SBX-045 request gate rejected a non-allowlisted URL");
    }
    if (reservedRequests >= MAXIMUM_REQUESTS) {
      throw new Error("SBX-045 exceeded its fixed request budget");
    }
    const sequence = ++reservedRequests;

    let releaseSchedule!: () => void;
    const previous = scheduling;
    scheduling = new Promise<void>((resolve) => {
      releaseSchedule = resolve;
    });
    await previous;
    try {
      const remaining = REQUEST_INTERVAL_MS - (now() - lastStartedAt);
      if (remaining > 0) await wait(remaining);
      lastStartedAt = now();
    } finally {
      releaseSchedule();
    }

    const record: RequestAuditRecord = {
      sequence,
      startedAt: new Date(lastStartedAt).toISOString(),
      method: (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase(),
      origin: identityPath ? "identity" : "sandbox-control-plane",
      pathname: url.pathname,
    };
    records.push(record);
    try {
      const response = await rawFetch(input, { ...init, redirect: "error" });
      record.status = response.status;
      record.completedAt = new Date(now()).toISOString();
      return response;
    } catch (error) {
      record.completedAt = new Date(now()).toISOString();
      throw error;
    }
  }) as typeof fetch;
  return { fetch: gated, records };
}

async function boundedResponse(response: Response, maximumBytes: number): Promise<Buffer> {
  const reader = response.body?.getReader();
  if (!reader) return Buffer.alloc(0);
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      const chunk = Buffer.from(item.value);
      total += chunk.length;
      if (total > maximumBytes) {
        chunk.fill(0);
        for (const retained of chunks) retained.fill(0);
        await reader.cancel().catch(() => undefined);
        throw new Error("SBX-045 identity response exceeded its fixed byte limit");
      }
      chunks.push(chunk);
    }
    const result = Buffer.concat(chunks, total);
    for (const retained of chunks) retained.fill(0);
    return result;
  } finally {
    reader.releaseLock();
  }
}

async function verifyIdentity(config: ExplicitConfig, gatedFetch: typeof fetch): Promise<VerifiedIdentity> {
  const response = await gatedFetch("https://api.vercel.com/v2/user", {
    method: "GET",
    headers: { authorization: `Bearer ${config.token}`, accept: "application/json" },
    signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
  });
  if (!response.ok) throw new Error(`SBX-045 identity verification returned HTTP ${response.status}`);
  const body = await boundedResponse(response, MAXIMUM_IDENTITY_RESPONSE_BYTES);
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString("utf8"));
  } finally {
    body.fill(0);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("SBX-045 identity response was invalid");
  }
  const user = (parsed as { user?: unknown }).user;
  if (user === null || typeof user !== "object" || Array.isArray(user)) {
    throw new Error("SBX-045 identity response lacked a user");
  }
  const email = (user as { email?: unknown }).email;
  const id = (user as { id?: unknown }).id;
  if (email !== config.expectedEmail || typeof id !== "string" || id.length < 1 ||
      id.length > 256 || /[\0\r\n]/u.test(id)) {
    throw new Error("SBX-045 token did not resolve to the exact eligible alias identity");
  }
  return { email: ELIGIBLE_ALIAS, userIdSha256: sha256(id), exactMatch: true };
}

function sandboxCredentials(config: ExplicitConfig, fetch: typeof globalThis.fetch): {
  token: string;
  teamId: string;
  projectId: string;
  fetch: typeof globalThis.fetch;
} {
  return {
    token: config.token,
    teamId: config.teamId,
    projectId: config.projectId,
    fetch,
  };
}

function resource(journal: RecoveryJournal, role: ResourceRole): RecoveryResource {
  const match = journal.resources.find((entry) => entry.role === role);
  if (!match) throw new Error(`SBX-045 recovery journal lacks ${role}`);
  return match;
}

function addUnique(values: string[], value: string): void {
  if (!values.includes(value)) values.push(value);
}

function touchJournal(journal: RecoveryJournal): void {
  journal.updatedAt = new Date().toISOString();
}

async function persistJournal(journal: RecoveryJournal): Promise<void> {
  touchJournal(journal);
  const validated = parseRecoveryJournal(journal);
  await writePrivateJsonAtomically(recoveryJournalPath(journal.runId), validated);
}

function sourceCreateParams(
  config: ExplicitConfig,
  gatedFetch: typeof fetch,
  plan: RecoveryResource,
  sourceValue: string,
): Parameters<typeof Sandbox.create>[0] {
  return {
    ...sandboxCredentials(config, gatedFetch),
    name: plan.name,
    persistent: true,
    timeout: SESSION_TIMEOUT_MS,
    ports: [],
    networkPolicy: "deny-all",
    env: { [SYNTHETIC_ENV_KEY]: sourceValue },
    tags: plan.tags,
    snapshotExpiration: SNAPSHOT_EXPIRATION_MS,
    keepLastSnapshots: {
      count: 2,
      expiration: SNAPSHOT_EXPIRATION_MS,
      deleteEvicted: true,
    },
    signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
  };
}

export function forkEnvironmentOverride(
  overrideValue?: string,
): Record<string, never> | { env: Record<typeof SYNTHETIC_ENV_KEY, string> } {
  return overrideValue === undefined
    ? {}
    : { env: { [SYNTHETIC_ENV_KEY]: overrideValue } };
}

function forkParams(
  config: ExplicitConfig,
  gatedFetch: typeof fetch,
  sourceName: string,
  plan: RecoveryResource,
  overrideValue?: string,
): Parameters<typeof Sandbox.fork>[0] {
  return {
    ...sandboxCredentials(config, gatedFetch),
    sourceSandbox: sourceName,
    name: plan.name,
    persistent: false,
    timeout: SESSION_TIMEOUT_MS,
    ports: [],
    networkPolicy: "deny-all",
    ...forkEnvironmentOverride(overrideValue),
    tags: plan.tags,
    snapshotExpiration: SNAPSHOT_EXPIRATION_MS,
    keepLastSnapshots: {
      count: 1,
      expiration: SNAPSHOT_EXPIRATION_MS,
      deleteEvicted: true,
    },
    signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
  };
}

async function registerCreated(
  journal: RecoveryJournal,
  plan: RecoveryResource,
  sandbox: Sandbox,
): Promise<void> {
  const exactCreateResponse = sandbox.name === plan.name && exactTags(sandbox.tags, plan.tags) &&
    sandbox.persistent === plan.persistent && isDenyAll(sandbox.networkPolicy) &&
    isDenyAll(sandbox.currentSession().networkPolicy) && sandbox.status === "running" &&
    sandbox.routes.length === 0 && creationWindowContains(plan, sandbox.createdAt.getTime());
  if (!exactCreateResponse) {
    plan.createResponseProvenanceMismatch = true;
    await persistJournal(journal);
    throw new Error(`SBX-045 ${plan.role} create response failed exact provenance validation`);
  }
  plan.createdAt = sandbox.createdAt.toISOString();
  await persistJournal(journal);
}

async function beginCreate(journal: RecoveryJournal, plan: RecoveryResource): Promise<void> {
  if (plan.createAttemptedAt !== undefined) {
    throw new Error(`SBX-045 ${plan.role} creation may be attempted only once`);
  }
  plan.createAttemptedAt = new Date().toISOString();
  await persistJournal(journal);
}

export function fixedGuestCommandSpec(): {
  cmd: "node";
  args: [typeof REMOTE_GUEST_PATH];
  timeoutMs: typeof COMMAND_TIMEOUT_MS;
} {
  return {
    cmd: "node",
    args: [REMOTE_GUEST_PATH],
    timeoutMs: COMMAND_TIMEOUT_MS,
  };
}

async function runFixedGuestDigest(
  sandbox: Sandbox,
  forbidden: readonly string[],
): Promise<DigestExecution> {
  // Session.runCommand is deliberately used instead of Sandbox.runCommand. The latter may
  // transparently resume and retry, which would destroy lifecycle/session attribution.
  const session = sandbox.currentSession();
  const sessionId = session.sessionId;
  const command = await session.runCommand({
    ...fixedGuestCommandSpec(),
    signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
  });
  const [stdout, stderr] = await Promise.all([command.stdout(), command.stderr()]);
  if (forbidden.some((secret) => secret.length > 0 &&
      (stdout.includes(secret) || stderr.includes(secret)))) {
    throw new Error("SBX-045 guest output contained raw controller-only material");
  }
  return {
    observation: parseGuestDigest(stdout, stderr, command.exitCode),
    sessionId,
    sessionIdUnchanged: sandbox.currentSession().sessionId === sessionId,
  };
}

async function readbackControl(
  config: ExplicitConfig,
  gatedFetch: typeof fetch,
  sandbox: Sandbox,
  plan: RecoveryResource,
): Promise<SandboxControl> {
  const activeSessionId = sandbox.currentSession().sessionId;
  const independent = await Sandbox.get({
    ...sandboxCredentials(config, gatedFetch),
    name: plan.name,
    resume: false,
    signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
  });
  const independentSessionId = independent.currentSession().sessionId;
  return {
    name: sandbox.name,
    sessionId: activeSessionId,
    status: sandbox.status,
    independentStatus: independent.status,
    exactName: sandbox.name === plan.name && independent.name === plan.name,
    exactTags: exactTags(sandbox.tags, plan.tags),
    exactPersistence: sandbox.persistent === plan.persistent &&
      independent.persistent === plan.persistent,
    denyAll: isDenyAll(sandbox.networkPolicy),
    independentSessionMatch: independentSessionId === activeSessionId,
    independentDenyAll: isDenyAll(independent.networkPolicy),
    sessionDenyAll: isDenyAll(sandbox.currentSession().networkPolicy),
    independentSessionDenyAll: isDenyAll(independent.currentSession().networkPolicy),
    independentTagsMatch: exactTags(independent.tags, plan.tags),
    noRoutes: sandbox.routes.length === 0,
    independentNoRoutes: independent.routes.length === 0,
    ...(sandbox.sourceSnapshotId === undefined ? {} : { sourceSnapshotId: sandbox.sourceSnapshotId }),
    ...(sandbox.currentSnapshotId === undefined ? {} : { currentSnapshotId: sandbox.currentSnapshotId }),
    ...(independent.currentSnapshotId === undefined
      ? {}
      : { independentCurrentSnapshotId: independent.currentSnapshotId }),
    ...(independent.sourceSnapshotId === undefined
      ? {}
      : { independentSourceSnapshotId: independent.sourceSnapshotId }),
  };
}

function commitControlIdentifiers(plan: RecoveryResource, control: SandboxControl): void {
  if (!controlPassed(control)) {
    throw new Error(`SBX-045 refused to trust invalid ${plan.role} control identifiers`);
  }
  addUnique(plan.knownSessionIds, control.sessionId);
  if (control.currentSnapshotId !== undefined &&
      control.currentSnapshotId === control.independentCurrentSnapshotId) {
    addUnique(plan.knownSnapshotIds, control.currentSnapshotId);
  }
}

function controlPassed(control: SandboxControl): boolean {
  return control.exactName && control.exactTags && control.exactPersistence &&
    control.denyAll && control.independentSessionMatch &&
    control.independentDenyAll && control.sessionDenyAll &&
    control.independentSessionDenyAll && control.independentTagsMatch &&
    control.status === control.independentStatus &&
    control.noRoutes && control.independentNoRoutes;
}

function creationWindowContains(resourcePlan: RecoveryResource, createdAt: number): boolean {
  if (resourcePlan.createAttemptedAt === undefined || !Number.isFinite(createdAt)) return false;
  const attempted = Date.parse(resourcePlan.createAttemptedAt);
  return createdAt >= attempted - 5_000 && createdAt <= attempted + 5 * 60_000;
}

async function listExactSandboxes(
  config: ExplicitConfig,
  gatedFetch: typeof fetch,
  plan: RecoveryResource,
): Promise<Array<{
  name: string;
  persistent: boolean;
  createdAt: number;
  currentSessionId: string;
  status: string;
  tags?: Record<string, string> | undefined;
  networkPolicy?: { mode: string } | undefined;
}>> {
  const page = await Sandbox.list({
    ...sandboxCredentials(config, gatedFetch),
    namePrefix: plan.name,
    sortBy: "name",
    sortOrder: "asc",
    limit: 10,
    signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
  });
  if (page.pagination.next !== null) {
    throw new Error("SBX-045 exact sandbox discovery unexpectedly required pagination");
  }
  return page.sandboxes.filter((sandbox) => sandbox.name === plan.name);
}

async function listPlanSnapshots(
  config: ExplicitConfig,
  gatedFetch: typeof fetch,
  plan: RecoveryResource,
): Promise<Array<{
  id: string;
  sourceSessionId: string;
  status: "failed" | "created" | "deleted";
  createdAt: number;
}>> {
  const page = await Snapshot.list({
    ...sandboxCredentials(config, gatedFetch),
    name: plan.name,
    sortOrder: "asc",
    limit: 20,
    signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
  });
  if (page.pagination.next !== null) {
    throw new Error("SBX-045 snapshot cleanup unexpectedly required pagination");
  }
  return page.snapshots.map((snapshot) => ({
    id: snapshot.id,
    sourceSessionId: snapshot.sourceSessionId,
    status: snapshot.status,
    createdAt: snapshot.createdAt,
  }));
}

async function directSnapshotAbsent(
  config: ExplicitConfig,
  gatedFetch: typeof fetch,
  snapshotId: string,
): Promise<boolean> {
  try {
    const snapshot = await Snapshot.get({
      ...sandboxCredentials(config, gatedFetch),
      snapshotId,
      signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
    });
    return snapshot.status === "deleted";
  } catch (error) {
    return snapshotAbsent(error);
  }
}

async function cleanupSnapshots(
  config: ExplicitConfig,
  gatedFetch: typeof fetch,
  plan: RecoveryResource,
  record: ResourceCleanupRecord,
  persist: () => Promise<void>,
): Promise<void> {
  record.snapshotEnumerationAttempted = true;
  const snapshots = await listPlanSnapshots(config, gatedFetch, plan);
  record.snapshotEnumerationCompleted = true;
  for (const snapshot of snapshots) {
    if (snapshot.status === "deleted") continue;
    const knownSession = plan.knownSessionIds.includes(snapshot.sourceSessionId);
    const attributableOrphan = plan.createAttemptedAt !== undefined &&
      creationWindowContains(plan, snapshot.createdAt);
    if (!knownSession && !attributableOrphan) {
      throw new Error(`SBX-045 refused an unattributable ${plan.role} snapshot`);
    }
    addUnique(plan.knownSessionIds, snapshot.sourceSessionId);
    addUnique(plan.knownSnapshotIds, snapshot.id);
    await persist();
  }

  for (const snapshotId of [...plan.knownSnapshotIds]) {
    let snapshot: Snapshot | undefined;
    try {
      snapshot = await Snapshot.get({
        ...sandboxCredentials(config, gatedFetch),
        snapshotId,
        signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
      });
    } catch (error) {
      if (snapshotAbsent(error)) {
        addUnique(record.snapshotIdsConfirmedAbsent, snapshotId);
        continue;
      }
      throw error;
    }
    if (!plan.knownSessionIds.includes(snapshot.sourceSessionId)) {
      throw new Error(`SBX-045 refused to delete a ${plan.role} snapshot with foreign provenance`);
    }
    if (snapshot.status !== "deleted") {
      await snapshot.delete({ signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS) });
      addUnique(record.snapshotIdsDeleted, snapshotId);
    }
    if (!await directSnapshotAbsent(config, gatedFetch, snapshotId)) {
      throw new Error(`SBX-045 could not confirm exact ${plan.role} snapshot absence`);
    }
    addUnique(record.snapshotIdsConfirmedAbsent, snapshotId);
  }

  const finalSnapshots = await listPlanSnapshots(config, gatedFetch, plan);
  const active = finalSnapshots.filter((snapshot) => snapshot.status !== "deleted");
  if (active.length !== 0) {
    throw new Error(`SBX-045 ${plan.role} snapshot collection was not empty after cleanup`);
  }
}

function newCleanupRecord(plan: RecoveryResource): ResourceCleanupRecord {
  return {
    role: plan.role,
    name: plan.name,
    discoveryAttempted: false,
    exactProvenanceValidated: false,
    orphanRecovered: false,
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    firstAbsenceConfirmed: false,
    delayedSecondAbsenceConfirmed: false,
    snapshotEnumerationAttempted: false,
    snapshotEnumerationCompleted: false,
    snapshotIdsDeleted: [],
    snapshotIdsConfirmedAbsent: [],
    manualInspectionRequired: plan.createResponseProvenanceMismatch === true,
    errors: [],
  };
}

async function confirmDoubleAbsence(
  config: ExplicitConfig,
  gatedFetch: typeof fetch,
  plan: RecoveryResource,
  record: ResourceCleanupRecord,
): Promise<void> {
  record.firstAbsenceConfirmed = (await listExactSandboxes(config, gatedFetch, plan)).length === 0;
  if (!record.firstAbsenceConfirmed) return;
  await delay(ABSENCE_INTERVAL_MS, undefined, {
    signal: AbortSignal.timeout(ABSENCE_INTERVAL_MS + 2_000),
  });
  record.delayedSecondAbsenceConfirmed =
    (await listExactSandboxes(config, gatedFetch, plan)).length === 0;
}

async function cleanupResource(
  config: ExplicitConfig,
  gatedFetch: typeof fetch,
  journal: RecoveryJournal,
  plan: RecoveryResource,
  forbidden: readonly string[],
): Promise<ResourceCleanupRecord> {
  const record = newCleanupRecord(plan);
  if (plan.createAttemptedAt === undefined && plan.knownSnapshotIds.length === 0) {
    record.exactProvenanceValidated = true;
    record.firstAbsenceConfirmed = true;
    record.delayedSecondAbsenceConfirmed = true;
    record.snapshotEnumerationCompleted = true;
    return record;
  }
  const persist = async (): Promise<void> => persistJournal(journal);
  try {
    record.discoveryAttempted = true;
    const matches = await listExactSandboxes(config, gatedFetch, plan);
    record.exactMatchCount = matches.length;
    if (matches.length > 1) {
      throw new Error(`SBX-045 ${plan.role} discovery returned multiple exact names`);
    }
    if (matches.length === 1) {
      const match = matches[0]!;
      const exact = exactTags(match.tags, plan.tags) &&
        match.persistent === plan.persistent &&
        match.networkPolicy?.mode === "deny-all" &&
        creationWindowContains(plan, match.createdAt);
      if (!exact) throw new Error(`SBX-045 refused ${plan.role} cleanup without exact provenance`);
      if (plan.knownSessionIds.length > 0 &&
          !plan.knownSessionIds.includes(match.currentSessionId)) {
        throw new Error(`SBX-045 refused ${plan.role} cleanup after session drift`);
      }
      addUnique(plan.knownSessionIds, match.currentSessionId);
      record.exactProvenanceValidated = true;
      record.orphanRecovered = plan.createdAt === undefined;
      await persist();

      const handle = await Sandbox.get({
        ...sandboxCredentials(config, gatedFetch),
        name: plan.name,
        resume: false,
        signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
      });
      const session = handle.currentSession();
      const sessionId = session.sessionId;
      const sourceSnapshotId = session.sourceSnapshotId;
      if (handle.name !== plan.name || !exactTags(handle.tags, plan.tags) ||
          handle.persistent !== plan.persistent || !isDenyAll(handle.networkPolicy) ||
          !isDenyAll(session.networkPolicy) || handle.routes.length !== 0 ||
          sessionId !== match.currentSessionId || handle.status !== match.status) {
        throw new Error(`SBX-045 ${plan.role} cleanup handle failed exact validation`);
      }
      addUnique(plan.knownSessionIds, sessionId);
      if (handle.currentSnapshotId !== undefined) {
        addUnique(plan.knownSnapshotIds, handle.currentSnapshotId);
      }
      await persist();

      let stoppedSnapshotId: string | undefined;
      if (handle.status !== "stopped") {
        record.stopAttempted = true;
        const stopped = await session.stop({
          signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
        });
        if (stopped.session.id !== sessionId || stopped.session.status !== "stopped" ||
            stopped.session.sourceSnapshotId !== sourceSnapshotId ||
            !isDenyAll(stopped.session.networkPolicy) ||
            handle.currentSession().sessionId !== sessionId) {
          throw new Error(`SBX-045 ${plan.role} stop response failed exact session validation`);
        }
        if (stopped.snapshot !== undefined && stopped.snapshot.sourceSessionId !== sessionId) {
          throw new Error(`SBX-045 ${plan.role} stop snapshot failed source-session validation`);
        }
        stoppedSnapshotId = stopped.snapshot?.id;
        record.stopped = true;
      } else {
        record.stopped = true;
      }

      const deleteHandle = await Sandbox.get({
        ...sandboxCredentials(config, gatedFetch),
        name: plan.name,
        resume: false,
        signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
      });
      const deleteSession = deleteHandle.currentSession();
      if (deleteHandle.name !== plan.name || !exactTags(deleteHandle.tags, plan.tags) ||
          deleteHandle.persistent !== plan.persistent ||
          !isDenyAll(deleteHandle.networkPolicy) || !isDenyAll(deleteSession.networkPolicy) ||
          deleteHandle.routes.length !== 0 || deleteSession.sessionId !== sessionId ||
          deleteHandle.status !== "stopped" ||
          deleteSession.sourceSnapshotId !== sourceSnapshotId) {
        throw new Error(`SBX-045 ${plan.role} fresh delete handle failed exact validation`);
      }
      if (deleteHandle.currentSnapshotId !== undefined) {
        addUnique(plan.knownSnapshotIds, deleteHandle.currentSnapshotId);
      }
      if (stoppedSnapshotId !== undefined) addUnique(plan.knownSnapshotIds, stoppedSnapshotId);
      await persist();
      await cleanupSnapshots(config, gatedFetch, plan, record, persist);
      record.deleteAttempted = true;
      await deleteHandle.delete({ signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS) });
      record.deleted = true;
    } else {
      record.exactProvenanceValidated = true;
      record.orphanRecovered = plan.createdAt === undefined;
      await cleanupSnapshots(config, gatedFetch, plan, record, persist);
    }

    await confirmDoubleAbsence(config, gatedFetch, plan, record);
    if (!record.firstAbsenceConfirmed || !record.delayedSecondAbsenceConfirmed) {
      throw new Error(`SBX-045 could not confirm delayed ${plan.role} sandbox absence`);
    }
    if (record.manualInspectionRequired) {
      throw new Error(`SBX-045 ${plan.role} create response requires manual orphan inspection`);
    }
  } catch (error) {
    record.errors.push(safeFailure(error, forbidden));
  }
  return record;
}

async function cleanupAll(
  config: ExplicitConfig,
  gatedFetch: typeof fetch,
  journal: RecoveryJournal,
  forbidden: readonly string[],
): Promise<{ passed: boolean; resources: ResourceCleanupRecord[] }> {
  const records: ResourceCleanupRecord[] = [];
  for (const role of CLEANUP_ORDER) {
    const plan = journal.resources.find((entry) => entry.role === role);
    if (plan) records.push(await cleanupResource(config, gatedFetch, journal, plan, forbidden));
  }
  const passed = records.every((record) =>
    record.errors.length === 0 && record.exactProvenanceValidated &&
    record.firstAbsenceConfirmed && record.delayedSecondAbsenceConfirmed &&
    record.snapshotEnumerationCompleted &&
    record.snapshotIdsConfirmedAbsent.length >= record.snapshotIdsDeleted.length);
  return { passed, resources: records };
}

function auditSummary(records: RequestAuditRecord[]): {
  count: number;
  contiguousSequences: boolean;
  allCompleted: boolean;
  minimumStartIntervalMs?: number;
  withinRateLimit: boolean;
  records: RequestAuditRecord[];
} {
  const starts = records.map((record) => Date.parse(record.startedAt));
  const intervals = starts.slice(1).map((started, index) => started - starts[index]!);
  const minimum = intervals.length === 0 ? undefined : Math.min(...intervals);
  return {
    count: records.length,
    contiguousSequences: records.every((record, index) => record.sequence === index + 1),
    allCompleted: records.every((record) => record.completedAt !== undefined),
    ...(minimum === undefined ? {} : { minimumStartIntervalMs: minimum }),
    withinRateLimit: minimum === undefined || minimum >= REQUEST_INTERVAL_MS - 2,
    records,
  };
}

async function runCleanupOnly(
  config: ExplicitConfig,
  runId: string,
  lock: HeldLiveLock,
  gatedFetch: typeof fetch,
  requestRecords: RequestAuditRecord[],
): Promise<void> {
  const journalPath = recoveryJournalPath(runId);
  const journal = await readRecoveryJournal(journalPath);
  if (journal.runId !== runId) throw new Error("SBX-045 cleanup-only journal ID mismatch");
  const identity = await verifyIdentity(config, gatedFetch);
  const cleanup = await cleanupAll(config, gatedFetch, journal, [config.token]);
  const artifact = {
    schemaVersion: 1,
    visibility: "private",
    testId: TEST_ID,
    mode: "cleanup-only",
    runId,
    completedAt: new Date().toISOString(),
    identity,
    cleanup,
    requestAudit: auditSummary(requestRecords),
    rawSyntheticValuesRetained: false,
    rawCommandOutputRetained: false,
  };
  assertSerializedEvidenceExcludesRawValues(artifact, [config.token]);
  await writePrivateJsonAtomically(evidencePath(runId, true), artifact);
  if (!cleanup.passed) {
    process.stdout.write(`${JSON.stringify({
      testId: TEST_ID,
      runId,
      mode: "cleanup-only",
      cleanupPassed: false,
      recoveryRequired: true,
    })}\n`);
    process.exitCode = 1;
    return;
  }
  await lock.release();
  let journalRemoved = true;
  let journalRemovalFailure: SafeFailure | undefined;
  try {
    await removeRecoveryJournal(journalPath, runId);
  } catch (error) {
    journalRemoved = false;
    journalRemovalFailure = safeFailure(error, [config.token]);
    process.exitCode = 1;
  }
  process.stdout.write(`${JSON.stringify({
    testId: TEST_ID,
    runId,
    mode: "cleanup-only",
    cleanupPassed: true,
    recoveryRequired: false,
    journalRemoved,
    journalRemovalFailure,
  })}\n`);
}

async function runNormal(
  config: ExplicitConfig,
  journal: RecoveryJournal,
  lock: HeldLiveLock,
  guestSource: string,
  gatedFetch: typeof fetch,
  requestRecords: RequestAuditRecord[],
): Promise<void> {
  const journalPath = recoveryJournalPath(journal.runId);
  let sourceValue = `sbx045_${randomBytes(32).toString("base64url")}`;
  let overrideValue = `sbx045_${randomBytes(32).toString("base64url")}`;
  while (overrideValue === sourceValue) {
    overrideValue = `sbx045_${randomBytes(32).toString("base64url")}`;
  }
  const forbidden = [sourceValue, overrideValue, config.token];
  const sourceExpected = expectedDigest(sourceValue);
  const overrideExpected = expectedDigest(overrideValue);
  let identity: VerifiedIdentity | undefined;
  let sourceInitialControl: SandboxControl | undefined;
  let sourceControl: SandboxControl | undefined;
  let inheritanceControl: SandboxControl | undefined;
  let targetControl: SandboxControl | undefined;
  let sourceObserved: DigestObservation | undefined;
  let inheritanceObserved: DigestObservation | undefined;
  let targetObserved: DigestObservation | undefined;
  let sourceDigestSessionExact = false;
  let inheritanceDigestSessionExact = false;
  let targetDigestSessionExact = false;
  let assessment: ForkEnvOverrideAssessment | undefined;
  let setupFailure: SafeFailure | undefined;
  let sourceSnapshotId: string | undefined;
  const startedAt = new Date().toISOString();

  try {
    identity = await verifyIdentity(config, gatedFetch);
    const sourcePlan = resource(journal, "source");
    await beginCreate(journal, sourcePlan);
    const source = await Sandbox.create(
      sourceCreateParams(config, gatedFetch, sourcePlan, sourceValue),
    );
    await registerCreated(journal, sourcePlan, source);
    sourceInitialControl = await readbackControl(config, gatedFetch, source, sourcePlan);
    if (!controlPassed(sourceInitialControl) || sourceInitialControl.status !== "running") {
      throw new Error("SBX-045 source failed exact pre-mutation readback");
    }
    commitControlIdentifiers(sourcePlan, sourceInitialControl);
    await persistJournal(journal);
    const sourceSession = source.currentSession();
    const sourceGuestSessionId = sourceSession.sessionId;
    await sourceSession.writeFiles(
      [{ path: REMOTE_GUEST_PATH, content: guestSource, mode: 0o700 }],
      { signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS) },
    );
    const sourceExecution = await runFixedGuestDigest(source, forbidden);
    sourceObserved = sourceExecution.observation;
    sourceDigestSessionExact = sourceExecution.sessionId === sourceGuestSessionId &&
      sourceExecution.sessionIdUnchanged;
    if (!exactDigest(sourceObserved, sourceExpected)) {
      throw new Error("SBX-045 source hash-only control did not match synthetic source A");
    }
    if (!sourceDigestSessionExact) {
      throw new Error("SBX-045 source digest command changed lifecycle session");
    }

    const snapshot = await sourceSession.snapshot({
      expiration: SNAPSHOT_EXPIRATION_MS,
      signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
    });
    sourceSnapshotId = snapshot.snapshotId;
    const refreshedSource = await Sandbox.get({
      ...sandboxCredentials(config, gatedFetch),
      name: sourcePlan.name,
      resume: false,
      signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
    });
    sourceControl = await readbackControl(config, gatedFetch, refreshedSource, sourcePlan);
    await persistJournal(journal);
    if (!controlPassed(sourceControl) ||
        sourceControl.sessionId !== sourceGuestSessionId ||
        snapshot.sourceSessionId !== sourceGuestSessionId ||
        snapshot.status !== "created" ||
        sourceControl.currentSnapshotId !== sourceSnapshotId ||
        sourceControl.independentCurrentSnapshotId !== sourceSnapshotId ||
        sourceControl.status !== "stopped") {
      throw new Error("SBX-045 stopped source failed exact snapshot/policy/session readback");
    }
    commitControlIdentifiers(sourcePlan, sourceControl);
    addUnique(sourcePlan.knownSnapshotIds, snapshot.snapshotId);
    addUnique(sourcePlan.knownSessionIds, snapshot.sourceSessionId);
    await persistJournal(journal);

    if (journal.inheritanceControlEnabled) {
      const inheritancePlan = resource(journal, "inheritance");
      await beginCreate(journal, inheritancePlan);
      // `env` is intentionally omitted: this is the optional inheritance-only control.
      const inheritance = await Sandbox.fork(
        forkParams(config, gatedFetch, sourcePlan.name, inheritancePlan),
      );
      await registerCreated(journal, inheritancePlan, inheritance);
      inheritanceControl = await readbackControl(
        config,
        gatedFetch,
        inheritance,
        inheritancePlan,
      );
      if (!controlPassed(inheritanceControl) || inheritanceControl.status !== "running" ||
          inheritanceControl.sourceSnapshotId !== sourceSnapshotId ||
          inheritanceControl.independentSourceSnapshotId !== sourceSnapshotId ||
          inheritanceControl.sessionId === sourceControl.sessionId) {
        throw new Error("SBX-045 optional fork failed exact pre-command readback");
      }
      commitControlIdentifiers(inheritancePlan, inheritanceControl);
      await persistJournal(journal);
      const inheritanceExecution = await runFixedGuestDigest(inheritance, forbidden);
      inheritanceObserved = inheritanceExecution.observation;
      inheritanceDigestSessionExact =
        inheritanceExecution.sessionId === inheritanceControl.sessionId &&
        inheritanceExecution.sessionIdUnchanged;
      if (!controlPassed(inheritanceControl) ||
          inheritanceControl.sourceSnapshotId !== sourceSnapshotId ||
          inheritanceControl.independentSourceSnapshotId !== sourceSnapshotId ||
          !exactDigest(inheritanceObserved, sourceExpected) ||
          !inheritanceDigestSessionExact ||
          inheritanceControl.sessionId === sourceControl.sessionId) {
        throw new Error("SBX-045 optional omitted-env inheritance control failed");
      }
    }

    const targetPlan = resource(journal, "target");
    await beginCreate(journal, targetPlan);
    const target = await Sandbox.fork(
      forkParams(config, gatedFetch, sourcePlan.name, targetPlan, overrideValue),
    );
    await registerCreated(journal, targetPlan, target);
    targetControl = await readbackControl(config, gatedFetch, target, targetPlan);
    if (!controlPassed(targetControl) || targetControl.status !== "running" ||
        targetControl.sourceSnapshotId !== sourceSnapshotId ||
        targetControl.independentSourceSnapshotId !== sourceSnapshotId ||
        targetControl.sessionId === sourceControl.sessionId ||
        (inheritanceControl !== undefined &&
          targetControl.sessionId === inheritanceControl.sessionId)) {
      throw new Error("SBX-045 target fork failed exact pre-command readback");
    }
    commitControlIdentifiers(targetPlan, targetControl);
    await persistJournal(journal);
    const targetExecution = await runFixedGuestDigest(target, forbidden);
    targetObserved = targetExecution.observation;
    targetDigestSessionExact = targetExecution.sessionId === targetControl.sessionId &&
      targetExecution.sessionIdUnchanged;
    assessment = assessForkEnvOverride({
      sourceNameFreshAndExact: controlPassed(sourceInitialControl) &&
        sourceInitialControl.status === "running" && controlPassed(sourceControl) &&
        sourceControl.status === "stopped" &&
        sourcePlan.name.endsWith(sourcePlan.resourceId),
      targetNameFreshAndExact: controlPassed(targetControl) &&
        targetControl.status === "running" &&
        targetPlan.name.endsWith(targetPlan.resourceId),
      sourceAndTargetNamesDistinct: sourcePlan.name !== targetPlan.name &&
        sourcePlan.resourceId !== targetPlan.resourceId,
      sourceSessionExact: sourceInitialControl.sessionId === sourceControl.sessionId &&
        sourceControl.independentSessionMatch &&
        sourceControl.sessionId === snapshot.sourceSessionId,
      targetSessionExact: targetControl.independentSessionMatch &&
        targetControl.status === "running",
      sourceAndTargetSessionsDistinct: sourceControl.sessionId !== targetControl.sessionId,
      sourceDenyAllReadback: sourceControl.denyAll && sourceControl.independentDenyAll &&
        sourceControl.sessionDenyAll && sourceControl.independentSessionDenyAll,
      targetDenyAllReadback: targetControl.denyAll && targetControl.independentDenyAll &&
        targetControl.sessionDenyAll && targetControl.independentSessionDenyAll,
      sourceSnapshotExact: snapshot.status === "created" &&
        snapshot.sourceSessionId === sourceControl.sessionId &&
        sourceControl.currentSnapshotId === sourceSnapshotId &&
        sourceControl.independentCurrentSnapshotId === sourceSnapshotId,
      targetForkAttributedToSource: targetControl.sourceSnapshotId === sourceSnapshotId &&
        targetControl.independentSourceSnapshotId === sourceSnapshotId,
      sourceDigestControlPassed: exactDigest(sourceObserved, sourceExpected),
      inheritanceControlEnabled: journal.inheritanceControlEnabled,
      inheritanceControlPassed: journal.inheritanceControlEnabled
        ? inheritanceObserved !== undefined && inheritanceControl !== undefined &&
          exactDigest(inheritanceObserved, sourceExpected) &&
          controlPassed(inheritanceControl) &&
          inheritanceControl.status === "running" &&
          inheritanceControl.sourceSnapshotId === sourceSnapshotId &&
          inheritanceControl.independentSourceSnapshotId === sourceSnapshotId &&
          inheritanceDigestSessionExact &&
          inheritanceControl.sessionId !== targetControl.sessionId
        : true,
      fixedGuestCommandOnly: sourceDigestSessionExact && targetDigestSessionExact,
      commandLevelSyntheticKeyAbsent: true,
      sourceExpected,
      overrideExpected,
      targetObserved,
    });
  } catch (error) {
    setupFailure = safeFailure(error, forbidden);
  }

  const cleanup = await cleanupAll(config, gatedFetch, journal, forbidden);
  const requestAudit = auditSummary(requestRecords);
  const requestAuditPassed = requestAudit.count <= MAXIMUM_REQUESTS &&
    requestAudit.contiguousSequences && requestAudit.allCompleted && requestAudit.withinRateLimit;
  const finalVerdict = !cleanup.passed
    ? "error"
    : requestAuditPassed
      ? assessment?.verdict ?? "indeterminate"
      : "indeterminate";
  const durableAssessment = assessment === undefined
    ? undefined
    : {
        targetClass: assessment.targetClass,
        outcome: assessment.verdict === "candidate" ? "exact-source-observed" : assessment.verdict,
        summary: assessment.summary,
      };
  const durableVerdict = finalVerdict === "candidate"
    ? "exact-source-observed"
    : finalVerdict;
  const artifactFile = evidencePath(journal.runId);
  const baseArtifact = {
    schemaVersion: 1,
    visibility: "private",
    testId: TEST_ID,
    mode: "normal",
    runId: journal.runId,
    startedAt,
    sdkAudit: {
      installedVersion: EXPECTED_SDK_VERSION,
      endpoint: "/v2/sandboxes/:source/fork",
      documentedContract: "provided env replaces copied source env",
      clientForwardsEnvVerbatim: true,
      serverBoundaryRequiredForCandidate: true,
    },
    identity,
    resources: journal.resources.map((plan) => ({
      role: plan.role,
      name: plan.name,
      resourceId: plan.resourceId,
      tags: plan.tags,
      knownSessionIds: plan.knownSessionIds,
      knownSnapshotIds: plan.knownSnapshotIds,
    })),
    sourceSnapshotId,
    guestProgramSha256: sha256(guestSource),
    controls: {
      sourceInitial: sourceInitialControl,
      source: sourceControl,
      inheritance: inheritanceControl,
      target: targetControl,
      commandLevelSyntheticKeyAbsent: true,
      installedSdkSerializesEmptyCommandEnvMap: true,
      rawCommandOutputRetained: false,
      digestSessionAttribution: {
        source: sourceDigestSessionExact,
        inheritance: journal.inheritanceControlEnabled
          ? inheritanceDigestSessionExact
          : undefined,
        target: targetDigestSessionExact,
      },
    },
    digests: {
      sourceExpected,
      overrideExpected,
      sourceObserved,
      inheritanceObserved,
      targetObserved,
    },
    preCleanupTargetClass: assessment?.targetClass,
    setupFailure,
    cleanup,
    requestAudit: { ...requestAudit, passed: requestAuditPassed },
    rawSyntheticValuesRetained: false,
    rawCommandOutputRetained: false,
  };
  const persistArtifact = async (state: Record<string, unknown>): Promise<void> => {
    const artifact = { ...baseArtifact, completedAt: new Date().toISOString(), ...state };
    assertSerializedEvidenceExcludesRawValues(artifact, forbidden);
    await writePrivateJsonAtomically(artifactFile, artifact);
  };
  const dropSyntheticReferences = (): void => {
    // JavaScript strings cannot be zeroized, but no raw value is serialized or logged.
    sourceValue = "";
    overrideValue = "";
    forbidden[0] = "";
    forbidden[1] = "";
  };

  if (!cleanup.passed) {
    await persistArtifact({
      assessment: undefined,
      localFinalization: {
        status: "recovery-required",
        lockReleased: false,
        journalRemoved: false,
      },
      verdict: "error",
      candidate: false,
    });
    dropSyntheticReferences();
    process.stdout.write(`${JSON.stringify({
      testId: TEST_ID,
      runId: journal.runId,
      verdict: "error",
      candidate: false,
      cleanupPassed: false,
      recoveryRequired: true,
      recoveryCommand: `SBX045_RECOVERY_RUN_ID=${journal.runId} ./node_modules/.bin/tsx pocs/SBX-045/fork-env-override.ts`,
    })}\n`);
    process.exitCode = 1;
    return;
  }

  // Durable files are evidence-only and never self-promote to candidate=true. The candidate
  // decision is emitted only on stdout after this record, cleanup, lock release, and journal
  // removal all succeed, avoiding a rename-then-fsync split-brain candidate artifact.
  await persistArtifact({
    assessment: undefined,
    localFinalization: {
      status: "pending",
      lockReleased: false,
      journalRemoved: false,
    },
    verdict: "pending-finalization",
    candidate: false,
  });

  try {
    await lock.release();
  } catch (error) {
    const finalizationFailure = safeFailure(error, forbidden);
    await persistArtifact({
      assessment: undefined,
      localFinalization: {
        status: "lock-release-failed",
        lockReleased: false,
        journalRemoved: false,
        failure: finalizationFailure,
      },
      verdict: "error",
      candidate: false,
    });
    dropSyntheticReferences();
    process.exitCode = 1;
    process.stdout.write(`${JSON.stringify({
      testId: TEST_ID,
      runId: journal.runId,
      verdict: "error",
      candidate: false,
      cleanupPassed: true,
      recoveryRequired: true,
      finalizationFailure,
    })}\n`);
    return;
  }

  try {
    await removeRecoveryJournal(journalPath, journal.runId);
  } catch (error) {
    const finalizationFailure = safeFailure(error, forbidden);
    await persistArtifact({
      assessment: undefined,
      localFinalization: {
        status: "journal-removal-failed",
        lockReleased: true,
        journalRemoved: false,
        failure: finalizationFailure,
      },
      verdict: "error",
      candidate: false,
    });
    dropSyntheticReferences();
    process.exitCode = 1;
    process.stdout.write(`${JSON.stringify({
      testId: TEST_ID,
      runId: journal.runId,
      verdict: "error",
      candidate: false,
      cleanupPassed: true,
      recoveryRequired: false,
      finalizationFailure,
    })}\n`);
    return;
  }

  try {
    await persistArtifact({
      assessment: durableAssessment,
      localFinalization: {
        status: "complete",
        lockReleased: true,
        journalRemoved: true,
      },
      verdict: durableVerdict,
      candidate: false,
    });
  } catch (error) {
    const finalizationFailure = safeFailure(error, forbidden);
    dropSyntheticReferences();
    process.exitCode = 1;
    process.stdout.write(`${JSON.stringify({
      testId: TEST_ID,
      runId: journal.runId,
      verdict: "error",
      candidate: false,
      cleanupPassed: true,
      recoveryRequired: false,
      finalizationFailure,
    })}\n`);
    return;
  }
  dropSyntheticReferences();
  process.stdout.write(`${JSON.stringify({
    testId: TEST_ID,
    runId: journal.runId,
    verdict: finalVerdict,
    candidate: finalVerdict === "candidate",
    cleanupPassed: true,
    recoveryRequired: false,
    artifactPath: artifactFile,
    journalRemoved: true,
  })}\n`);
}

export async function main(): Promise<void> {
  const config = loadExplicitConfig();
  await assertInstalledSdkVersion();
  await ensurePrivateDirectory(ARTIFACTS_DIRECTORY);
  const requestGate = createGatedFetch();
  let lock: HeldLiveLock | undefined;
  let journal: RecoveryJournal | undefined;
  let durableJournal = false;
  try {
    if (config.recoveryRunId !== undefined) {
      lock = await acquireLiveLock(
        LIVE_LOCK_PATH,
        config.recoveryRunId,
        "cleanup-only",
      );
      await runCleanupOnly(
        config,
        config.recoveryRunId,
        lock,
        requestGate.fetch,
        requestGate.records,
      );
      return;
    }

    const guestSource = await readFile(
      new URL("../../guest/sbx-045-env-digest.mjs", import.meta.url),
      "utf8",
    );
    if (sha256(guestSource) !== FIXED_GUEST_SHA256) {
      throw new Error("SBX-045 fixed guest source failed its local integrity precondition");
    }

    journal = createRecoveryJournal(config.inheritanceControlEnabled);
    lock = await acquireLiveLock(LIVE_LOCK_PATH, journal.runId, "normal");
    try {
      await persistJournal(journal);
      durableJournal = true;
    } catch (error) {
      await lock.release();
      throw error;
    }
    await runNormal(
      config,
      journal,
      lock,
      guestSource,
      requestGate.fetch,
      requestGate.records,
    );
  } catch (error) {
    const failure = safeFailure(error, [config.token]);
    const recoveryRequired = (durableJournal || requestGate.records.length > 0) &&
      lock !== undefined && !lock.isReleased();
    process.stdout.write(`${JSON.stringify({
      testId: TEST_ID,
      runId: recoveryRequired ? (config.recoveryRunId ?? journal?.runId) : undefined,
      verdict: "error",
      candidate: false,
      recoveryRequired,
      failure,
    })}\n`);
    process.exitCode = 1;
  }
}

const invokedPath = process.argv[1] === undefined
  ? undefined
  : pathToFileURL(process.argv[1]).href;
if (invokedPath === import.meta.url) {
  void main().catch((error: unknown) => {
    process.stdout.write(`${JSON.stringify({
      testId: TEST_ID,
      verdict: "error",
      candidate: false,
      recoveryRequired: false,
      failure: safeFailure(error),
    })}\n`);
    process.exitCode = 1;
  });
}
