import "dotenv/config";

import {
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { mkdir, readFile, readdir, rename, unlink, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { Sandbox, Snapshot, type NetworkPolicy } from "@vercel/sandbox";
import {
  acquireSbx026LiveLock,
  apiFailureFromError,
  apiFailureFromResponse,
  assertDistinctVerifiedIdentities,
  conclusiveAuthorizationRejection,
  CONTROL_PLANE_TIMEOUT_MS,
  createAccountFetch,
  loadTwoOwnedAccounts,
  MINIMUM_VERCEL_REQUEST_INTERVAL_MS,
  oneShotSandboxRequest,
  readBoundedResponse,
  VercelRequestGate,
  verifyAccountIdentity,
  type AcquireSbx026LiveLockOptions,
  type AccountRole,
  type ApiFailure,
  type ExplicitAccountCredentials,
  type RequestAuditRecord,
  type Sbx026LiveLock,
  type VerifiedAccountIdentity,
} from "./shared.js";
import {
  assessForkAuthorization,
  type ForkAuthorizationAssessment,
} from "./fork-verdict.js";

const testId = "SBX-026-FORK";
const sessionTimeoutMs = 180_000;
const snapshotExpirationMs = 60 * 60 * 1_000;
const maximumAcceptedForkResponseBytes = 65_536;
const maximumCanaryReadBytes = 4_096;
const timestampSkewMs = 5_000;
const delayedAbsenceCheckMs = 1_000;
const maximumRecoveryManifestBytes = 65_536;
const recoveryFilePrefix = "SBX-026-fork-recovery-";

type ResourceRole =
  | "attacker-source"
  | "attacker-owner-fork"
  | "victim-source"
  | "victim-owner-fork"
  | "cross-fork";

interface AccountContext {
  credentials: ExplicitAccountCredentials;
  fetch: typeof fetch;
}

export interface RunNames {
  attackerSource: string;
  attackerOwnerFork: string;
  victimSource: string;
  victimOwnerFork: string;
  crossFork: string;
}

interface ResourcePlan {
  owner: AccountRole;
  role: ResourceRole;
  name: string;
  tags: Record<string, string>;
  createAttempted: boolean;
  created: boolean;
  knownSessionIds: Set<string>;
  knownSnapshotIds: Set<string>;
  cleanup: SandboxCleanupRecord;
  snapshotCleanup: SnapshotCleanupRecord;
}

interface RecoveryJournal {
  schemaVersion: 1;
  testId: typeof testId;
  runId: string;
  startedAt: string;
  crossAttemptStarted: boolean;
  accounts: {
    attacker: { teamId: string; projectId: string; expectedEmail: string };
    victim: { teamId: string; projectId: string; expectedEmail: string };
  };
  resources: Array<{
    owner: AccountRole;
    role: ResourceRole;
    name: string;
    tags: Record<string, string>;
    createAttempted: boolean;
    created: boolean;
    knownSessionIds: string[];
    knownSnapshotIds: string[];
  }>;
  tokensRetained: false;
  rawCanariesRetained: false;
}

export interface ForkRunIntent {
  runId: string;
  cleanupOnly: boolean;
  suppliedRunId: boolean;
}

interface SandboxCleanupRecord {
  owner: AccountRole;
  name: string;
  discoveryAttempted: boolean;
  exactMatchCount?: number;
  orphanRecovered: boolean;
  exactTagsValidated: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  absenceCheckAttempted: boolean;
  absenceConfirmed: boolean;
  delayedSecondAbsenceCheckRequired: boolean;
  delayedSecondAbsenceCheckAttempted: boolean;
  delayedSecondAbsenceConfirmed: boolean;
  errors: ApiFailure[];
}

interface SnapshotCleanupRecord {
  owner: AccountRole;
  sandboxName: string;
  enumerationAttempted: boolean;
  enumerationCompleted: boolean;
  discoveredIds: string[];
  directGetAttemptedIds: string[];
  directlyConfirmedAbsentIds: string[];
  deletedIds: string[];
  absenceCheckAttempted: boolean;
  absenceConfirmed: boolean;
  errors: ApiFailure[];
}

interface SourceFixture {
  sandbox: Sandbox;
  snapshot: Snapshot;
  plan: ResourcePlan;
  canary: Buffer;
  canaryPath: string;
  canarySha256: string;
}

interface SourceValidityRecord {
  attempted: boolean;
  exactName: boolean;
  exactSnapshot: boolean;
  exactTags: boolean;
  denyAll: boolean;
  persistent: boolean;
  stopped: boolean;
  sessionId?: string;
  passed: boolean;
  failure?: ApiFailure;
}

export interface AcceptedForkRecord {
  targetName: string;
  sessionId: string;
  sourceSnapshotId: string;
  createdAt: string;
  exactTags: true;
  denyAll: true;
  persistent: false;
}

export interface AcceptedForkExpectation {
  targetName: string;
  sourceSnapshotId: string;
  tags: Record<string, string>;
  earliestCreatedAtMs: number;
  latestCreatedAtMs: number;
}

export interface RequestAuditExpectation {
  crossForkPath: string;
  crossForkAttempts: number;
  foreignCrossForkSequence?: number;
  crossReadPath?: string;
  crossReadAttempts: number;
}

export interface RequestAuditAssessment {
  passed: boolean;
  contiguousSequences: boolean;
  completedRecords: boolean;
  globallyRateLimited: boolean;
  exactCrossForkCount: boolean;
  exactCrossReadCount: boolean;
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function safeFailure(error: unknown): ApiFailure {
  return apiFailureFromError(error);
}

function exactNotFound(failure: ApiFailure): boolean {
  return failure.kind === "api" && failure.status === 404;
}

function snapshotAbsent(failure: ApiFailure): boolean {
  return exactNotFound(failure) ||
    (failure.kind === "api" && failure.status === 410 &&
      [undefined, "snapshot_not_found", "not_found"].includes(failure.code));
}

function sandboxCredentials(context: AccountContext): {
  token: string;
  teamId: string;
  projectId: string;
  fetch: typeof fetch;
} {
  return {
    token: context.credentials.token,
    teamId: context.credentials.teamId,
    projectId: context.credentials.projectId,
    fetch: context.fetch,
  };
}

export function createRunNames(runId: string): RunNames {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(runId)) {
    throw new Error("runId must be one complete UUIDv4");
  }
  return {
    attackerSource: `sbx-026-fork-attacker-source-${runId}`,
    attackerOwnerFork: `sbx-026-fork-attacker-control-${runId}`,
    victimSource: `sbx-026-fork-victim-source-${runId}`,
    victimOwnerFork: `sbx-026-fork-victim-control-${runId}`,
    crossFork: `sbx-026-fork-cross-${runId}`,
  };
}

export function resolveForkRunIntent(
  environment: Readonly<Record<string, string | undefined>> = process.env,
): ForkRunIntent {
  const supplied = environment.SBX026_FORK_RUN_ID;
  if (supplied !== undefined) {
    createRunNames(supplied);
    return { runId: supplied, cleanupOnly: true, suppliedRunId: true };
  }
  return { runId: randomUUID(), cleanupOnly: false, suppliedRunId: false };
}

export function forkLiveLockOptions(
  intent: ForkRunIntent,
): AcquireSbx026LiveLockOptions {
  return {
    scope: "fork",
    runId: intent.runId,
    mode: intent.cleanupOnly ? "cleanup-only" : "normal",
  };
}

export function resourceTags(runId: string, role: ResourceRole): Record<string, string> {
  return {
    harness: "vsc",
    test: testId,
    run: runId,
    role,
  };
}

export function exactTags(
  actual: Record<string, string> | undefined,
  expected: Record<string, string>,
): boolean {
  if (!actual) return false;
  const actualEntries = Object.entries(actual).sort(([left], [right]) => left.localeCompare(right));
  const expectedEntries = Object.entries(expected).sort(([left], [right]) => left.localeCompare(right));
  return JSON.stringify(actualEntries) === JSON.stringify(expectedEntries);
}

export function requiresDelayedSecondAbsence(
  createAttempted: boolean,
  trustedLiveHandleCreated: boolean,
): boolean {
  return createAttempted && !trustedLiveHandleCreated;
}

export function sandboxCleanupCallsAuthorized(
  attackerExactIdentityVerified: boolean,
  victimExactIdentityVerified: boolean,
  identitiesVerifiedAndDistinct: boolean,
): boolean {
  return attackerExactIdentityVerified && victimExactIdentityVerified &&
    identitiesVerifiedAndDistinct;
}

export function allKnownSnapshotsDirectlyAbsent(
  knownSnapshotIds: readonly string[],
  directlyConfirmedAbsentIds: readonly string[],
): boolean {
  const confirmed = new Set(directlyConfirmedAbsentIds);
  return knownSnapshotIds.every((snapshotId) => confirmed.has(snapshotId));
}

function isDenyAll(policy: NetworkPolicy | undefined): boolean {
  return policy === "deny-all";
}

function validSessionId(value: unknown): value is string {
  return typeof value === "string" && /^sbx_[A-Za-z0-9_-]{8,128}$/u.test(value);
}

function allDistinct(values: readonly string[]): boolean {
  return values.length > 0 && values.every((value) => value.length > 0) &&
    new Set(values).size === values.length;
}

function objectRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function exactStringRecord(
  value: unknown,
  expected: Record<string, string>,
): boolean {
  const record = objectRecord(value);
  return record !== undefined &&
    Object.values(record).every((item) => typeof item === "string") &&
    exactTags(record as Record<string, string>, expected);
}

function responseDenyAll(value: unknown): boolean {
  return objectRecord(value)?.mode === "deny-all";
}

export function parseAcceptedForkPayload(
  value: unknown,
  expected: AcceptedForkExpectation,
): AcceptedForkRecord | undefined {
  const root = objectRecord(value);
  const sandbox = objectRecord(root?.sandbox);
  const session = objectRecord(root?.session);
  const targetName = sandbox?.name;
  const sessionId = session?.id;
  const sourceSnapshotId = session?.sourceSnapshotId;
  const createdAt = sandbox?.createdAt;
  if (
    targetName !== expected.targetName ||
    !validSessionId(sessionId) ||
    sandbox?.currentSessionId !== sessionId ||
    sourceSnapshotId !== expected.sourceSnapshotId ||
    sandbox?.persistent !== false ||
    !exactStringRecord(sandbox?.tags, expected.tags) ||
    !responseDenyAll(sandbox?.networkPolicy) ||
    !responseDenyAll(session?.networkPolicy) ||
    typeof createdAt !== "number" ||
    !Number.isFinite(createdAt) ||
    createdAt < expected.earliestCreatedAtMs ||
    createdAt > expected.latestCreatedAtMs
  ) {
    return undefined;
  }
  return {
    targetName,
    sessionId,
    sourceSnapshotId: expected.sourceSnapshotId,
    createdAt: new Date(createdAt).toISOString(),
    exactTags: true,
    denyAll: true,
    persistent: false,
  };
}

async function acceptedForkRecord(
  response: Response,
  expected: AcceptedForkExpectation,
): Promise<AcceptedForkRecord | undefined> {
  const body = await readBoundedResponse(response, maximumAcceptedForkResponseBytes);
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString("utf8"));
    return parseAcceptedForkPayload(parsed, expected);
  } catch {
    return undefined;
  } finally {
    parsed = undefined;
    body.fill(0);
  }
}

export function buildCrossForkBody(
  name: string,
  tags: Record<string, string>,
): Record<string, unknown> {
  return {
    name,
    persistent: false,
    timeout: sessionTimeoutMs,
    networkPolicy: { mode: "deny-all" },
    env: {},
    tags,
    snapshotExpiration: snapshotExpirationMs,
    keepLastSnapshots: {
      count: 1,
      expiration: snapshotExpirationMs,
      deleteEvicted: true,
    },
  };
}

export function assessRequestAudit(
  records: readonly RequestAuditRecord[],
  expected: RequestAuditExpectation,
): RequestAuditAssessment {
  const contiguousSequences = records.every((record, index) => record.sequence === index + 1);
  const completedRecords = records.every((record) => record.completedAt !== undefined);
  const globallyRateLimited = records.every((record, index) => {
    if (index === 0) return true;
    const previous = Date.parse(records[index - 1]!.startedAt);
    const current = Date.parse(record.startedAt);
    return Number.isFinite(previous) && Number.isFinite(current) &&
      current - previous >= MINIMUM_VERCEL_REQUEST_INTERVAL_MS - 2;
  });
  const foreignCrossForkRecords = expected.foreignCrossForkSequence === undefined
    ? []
    : records.filter(
      (record) =>
        record.sequence === expected.foreignCrossForkSequence &&
        record.origin === "vercel-sandbox-control-plane" &&
        record.method === "POST" &&
        record.pathname === expected.crossForkPath,
    );
  const crossReadCount = expected.crossReadPath === undefined
    ? 0
    : records.filter(
      (record) => record.method === "POST" && record.pathname === expected.crossReadPath,
    ).length;
  // Owner-control forks can have the same method and source pathname as the foreign
  // request. The controller therefore captures the exact gate sequence assigned to
  // its one attacker-scoped send instead of inferring identity from the pathname.
  const exactCrossForkCount = expected.crossForkAttempts === 0
    ? expected.foreignCrossForkSequence === undefined
    : expected.crossForkAttempts === 1 && foreignCrossForkRecords.length === 1;
  const exactCrossReadCount = crossReadCount === expected.crossReadAttempts;
  return {
    passed: contiguousSequences && completedRecords && globallyRateLimited &&
      exactCrossForkCount && exactCrossReadCount,
    contiguousSequences,
    completedRecords,
    globallyRateLimited,
    exactCrossForkCount,
    exactCrossReadCount,
  };
}

export function pendingForkFinalizationAssessment(): ForkAuthorizationAssessment {
  return {
    verdict: "indeterminate",
    candidate: false,
    controlsPassed: false,
    summary: "Final verdict withheld until the shared SBX-026 live lock is released.",
  };
}

export function releaseNeutralForkEvidenceState(
  resourceCleanupPassed: boolean,
  recoveryManifestRemoved: boolean,
): Record<string, unknown> {
  return {
    assessment: pendingForkFinalizationAssessment(),
    finalization: {
      status: "pending-recovery-or-live-lock-release",
      effectiveVerdict: "indeterminate",
      candidate: false,
      resourceCleanupPassed,
      recoveryManifestRemoved,
      finalAssessmentRetained: false,
    },
  };
}

export async function finalizeForkEvidenceAfterLiveLockRelease(
  pendingEvidence: Readonly<Record<string, unknown>>,
  evidencePath: string,
  liveLock: Pick<Sbx026LiveLock, "release">,
  releaseEligible: boolean,
  finalAssessment: ForkAuthorizationAssessment,
  finalizedAt = new Date().toISOString(),
): Promise<Record<string, unknown>> {
  if (!releaseEligible) return { ...pendingEvidence, evidencePath };

  // Construct no effective pass/candidate result until this succeeds. If release
  // fails, the durable artifact remains the neutral pending record written earlier.
  await liveLock.release();
  const pendingRecovery = objectRecord(pendingEvidence.recovery) ?? {};
  const pendingLiveLock = objectRecord(pendingRecovery.liveLock) ?? {};
  return {
    ...pendingEvidence,
    completedAt: finalizedAt,
    cleanupPassed: true,
    assessment: finalAssessment,
    finalization: {
      status: "complete",
      liveLockReleasedBeforeVerdict: true,
      durableEvidenceRemainsReleaseNeutral: true,
    },
    recovery: {
      ...pendingRecovery,
      liveLock: {
        ...pendingLiveLock,
        releasedAfterEvidenceWrite: true,
      },
    },
    evidencePath,
  };
}

function newResourcePlan(
  owner: AccountRole,
  role: ResourceRole,
  name: string,
  tags: Record<string, string>,
): ResourcePlan {
  return {
    owner,
    role,
    name,
    tags,
    createAttempted: false,
    created: false,
    knownSessionIds: new Set<string>(),
    knownSnapshotIds: new Set<string>(),
    cleanup: {
      owner,
      name,
      discoveryAttempted: false,
      orphanRecovered: false,
      exactTagsValidated: false,
      deleteAttempted: false,
      deleted: false,
      absenceCheckAttempted: false,
      absenceConfirmed: false,
      delayedSecondAbsenceCheckRequired: false,
      delayedSecondAbsenceCheckAttempted: false,
      delayedSecondAbsenceConfirmed: false,
      errors: [],
    },
    snapshotCleanup: {
      owner,
      sandboxName: name,
      enumerationAttempted: false,
      enumerationCompleted: false,
      discoveredIds: [],
      directGetAttemptedIds: [],
      directlyConfirmedAbsentIds: [],
      deletedIds: [],
      absenceCheckAttempted: false,
      absenceConfirmed: false,
      errors: [],
    },
  };
}

function planHasKnownCleanupState(plan: ResourcePlan): boolean {
  return plan.createAttempted || plan.knownSessionIds.size > 0 || plan.knownSnapshotIds.size > 0;
}

function sandboxPlanCleanupPassed(plan: ResourcePlan): boolean {
  return !planHasKnownCleanupState(plan) ||
    (plan.cleanup.absenceConfirmed && plan.cleanup.errors.length === 0);
}

function snapshotPlanCleanupPassed(plan: ResourcePlan): boolean {
  return !planHasKnownCleanupState(plan) ||
    (plan.snapshotCleanup.absenceConfirmed && plan.snapshotCleanup.errors.length === 0);
}

async function listExactSandboxes(
  context: AccountContext,
  plan: ResourcePlan,
): Promise<Array<{
  name: string;
  currentSessionId: string;
  status: string;
  tags?: Record<string, string> | undefined;
}>> {
  const result = await Sandbox.list({
    ...sandboxCredentials(context),
    namePrefix: plan.name,
    sortBy: "name",
    sortOrder: "asc",
    limit: 20,
    signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
  });
  const values = await result.toArray();
  return values.filter((value) => value.name === plan.name);
}

async function discardResponse(response: Response): Promise<void> {
  const body = await readBoundedResponse(response, maximumAcceptedForkResponseBytes);
  body.fill(0);
}

async function cleanupSandboxPlan(
  context: AccountContext,
  plan: ResourcePlan,
): Promise<void> {
  if (plan.cleanup.absenceConfirmed) return;
  plan.cleanup.discoveryAttempted = true;
  let matches: Awaited<ReturnType<typeof listExactSandboxes>>;
  try {
    matches = await listExactSandboxes(context, plan);
  } catch (error) {
    const failure = safeFailure(error);
    if (exactNotFound(failure)) {
      matches = [];
    } else {
      plan.cleanup.errors.push(failure);
      return;
    }
  }

  plan.cleanup.exactMatchCount = matches.length;
  if (
    matches.length === 0 &&
    requiresDelayedSecondAbsence(plan.createAttempted, plan.created)
  ) {
    plan.cleanup.delayedSecondAbsenceCheckRequired = true;
    try {
      await delay(delayedAbsenceCheckMs, undefined, {
        signal: AbortSignal.timeout(delayedAbsenceCheckMs + 2_000),
      });
      plan.cleanup.delayedSecondAbsenceCheckAttempted = true;
      matches = await listExactSandboxes(context, plan);
      plan.cleanup.exactMatchCount = matches.length;
      plan.cleanup.delayedSecondAbsenceConfirmed = matches.length === 0;
    } catch (error) {
      const failure = safeFailure(error);
      if (exactNotFound(failure)) {
        matches = [];
        plan.cleanup.exactMatchCount = 0;
        plan.cleanup.delayedSecondAbsenceConfirmed = true;
      } else {
        plan.cleanup.errors.push(failure);
        return;
      }
    }
  }
  if (matches.length === 0) {
    plan.cleanup.absenceCheckAttempted = true;
    plan.cleanup.absenceConfirmed = true;
    return;
  }
  if (matches.length !== 1) {
    plan.cleanup.errors.push({ kind: "other" });
    return;
  }

  const match = matches[0]!;
  plan.cleanup.orphanRecovered = !plan.created;
  plan.cleanup.exactTagsValidated = exactTags(match.tags, plan.tags);
  if (!plan.cleanup.exactTagsValidated) {
    plan.cleanup.errors.push({ kind: "other" });
    return;
  }
  if (validSessionId(match.currentSessionId)) plan.knownSessionIds.add(match.currentSessionId);

  plan.cleanup.deleteAttempted = true;
  const response = await oneShotSandboxRequest(
    context.credentials,
    context.fetch,
    `/v2/sandboxes/${encodeURIComponent(plan.name)}`,
    {
      method: "DELETE",
      signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
    },
    { projectId: context.credentials.projectId },
  ).catch((error: unknown) => {
    plan.cleanup.errors.push(safeFailure(error));
    return undefined;
  });
  if (response) {
    if (response.ok || [404, 410].includes(response.status)) {
      plan.cleanup.deleted = true;
      await discardResponse(response).catch(() => {
        plan.cleanup.errors.push({ kind: "other" });
      });
    } else {
      plan.cleanup.errors.push(await apiFailureFromResponse(response));
    }
  }

  plan.cleanup.absenceCheckAttempted = true;
  try {
    const remaining = await listExactSandboxes(context, plan);
    plan.cleanup.absenceConfirmed = remaining.length === 0;
    if (!plan.cleanup.absenceConfirmed) plan.cleanup.errors.push({ kind: "other" });
  } catch (error) {
    const failure = safeFailure(error);
    plan.cleanup.absenceConfirmed = exactNotFound(failure);
    if (!plan.cleanup.absenceConfirmed) plan.cleanup.errors.push(failure);
  }
}

async function listSnapshotsForPlan(
  context: AccountContext,
  plan: ResourcePlan,
): Promise<Array<{
  id: string;
  sourceSessionId: string;
  status: "failed" | "created" | "deleted";
}>> {
  const result = await Snapshot.list({
    ...sandboxCredentials(context),
    name: plan.name,
    limit: 50,
    sortOrder: "asc",
    signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
  });
  return (await result.toArray()).map((snapshot) => ({
    id: snapshot.id,
    sourceSessionId: snapshot.sourceSessionId,
    status: snapshot.status,
  }));
}

function snapshotBelongsToPlan(
  plan: ResourcePlan,
  snapshot: { id: string; sourceSessionId: string },
): boolean {
  return plan.knownSnapshotIds.has(snapshot.id) ||
    plan.knownSessionIds.has(snapshot.sourceSessionId);
}

async function cleanupSnapshotsForPlan(
  context: AccountContext,
  plan: ResourcePlan,
): Promise<void> {
  if (plan.snapshotCleanup.absenceConfirmed) return;
  const addUnique = (values: string[], value: string): void => {
    if (!values.includes(value)) values.push(value);
  };

  const directGet = async (snapshotId: string): Promise<{
    absent: boolean;
    sourceSessionId?: string;
    status?: "failed" | "created" | "deleted";
  }> => {
    plan.snapshotCleanup.directGetAttemptedIds.push(snapshotId);
    try {
      const snapshot = await Snapshot.get({
        ...sandboxCredentials(context),
        snapshotId,
        signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
      });
      if (snapshot.snapshotId !== snapshotId) {
        plan.snapshotCleanup.errors.push({ kind: "other" });
        return { absent: false };
      }
      if (snapshot.status === "deleted") {
        addUnique(plan.snapshotCleanup.directlyConfirmedAbsentIds, snapshotId);
        return { absent: true };
      }
      return {
        absent: false,
        sourceSessionId: snapshot.sourceSessionId,
        status: snapshot.status,
      };
    } catch (error) {
      const failure = safeFailure(error);
      if (snapshotAbsent(failure)) {
        addUnique(plan.snapshotCleanup.directlyConfirmedAbsentIds, snapshotId);
        return { absent: true };
      }
      plan.snapshotCleanup.errors.push(failure);
      return { absent: false };
    }
  };

  const cleanupKnownSnapshot = async (snapshotId: string): Promise<void> => {
    const initial = await directGet(snapshotId);
    if (initial.absent) return;
    if (
      initial.sourceSessionId === undefined ||
      !snapshotBelongsToPlan(plan, {
        id: snapshotId,
        sourceSessionId: initial.sourceSessionId,
      })
    ) {
      plan.snapshotCleanup.errors.push({ kind: "other" });
      return;
    }

    const response = await oneShotSandboxRequest(
      context.credentials,
      context.fetch,
      `/v2/sandboxes/snapshots/${encodeURIComponent(snapshotId)}`,
      {
        method: "DELETE",
        signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
      },
    ).catch((error: unknown) => {
      plan.snapshotCleanup.errors.push(safeFailure(error));
      return undefined;
    });
    if (response) {
      if (response.ok || [404, 410].includes(response.status)) {
        addUnique(plan.snapshotCleanup.deletedIds, snapshotId);
        await discardResponse(response).catch(() => {
          plan.snapshotCleanup.errors.push({ kind: "other" });
        });
      } else {
        plan.snapshotCleanup.errors.push(await apiFailureFromResponse(response));
      }
    }

    // A DELETE response or collection/list result is never absence proof. The exact
    // owner-scoped snapshot ID must independently resolve as missing/deleted.
    const confirmation = await directGet(snapshotId);
    if (!confirmation.absent) plan.snapshotCleanup.errors.push({ kind: "other" });
  };

  const discover = async (): Promise<Awaited<ReturnType<typeof listSnapshotsForPlan>> | undefined> => {
    plan.snapshotCleanup.enumerationAttempted = true;
    try {
      const snapshots = await listSnapshotsForPlan(context, plan);
      plan.snapshotCleanup.enumerationCompleted = true;
      for (const snapshot of snapshots) {
        if (snapshot.status === "deleted") continue;
        if (!snapshotBelongsToPlan(plan, snapshot)) {
          plan.snapshotCleanup.errors.push({ kind: "other" });
          continue;
        }
        addUnique(plan.snapshotCleanup.discoveredIds, snapshot.id);
        plan.knownSnapshotIds.add(snapshot.id);
      }
      return snapshots;
    } catch (error) {
      // Even a collection 404 is not proof that a known snapshot ID is absent.
      plan.snapshotCleanup.errors.push(safeFailure(error));
      return undefined;
    }
  };

  await discover();
  for (const snapshotId of [...plan.knownSnapshotIds]) {
    await cleanupKnownSnapshot(snapshotId);
  }

  plan.snapshotCleanup.absenceCheckAttempted = true;
  let finalSnapshots = await discover();
  const lateOwned = finalSnapshots?.filter(
    (snapshot) => snapshot.status !== "deleted" && snapshotBelongsToPlan(plan, snapshot),
  ) ?? [];
  for (const snapshot of lateOwned) {
    plan.knownSnapshotIds.add(snapshot.id);
    addUnique(plan.snapshotCleanup.discoveredIds, snapshot.id);
    await cleanupKnownSnapshot(snapshot.id);
  }
  if (lateOwned.length > 0) finalSnapshots = await discover();

  const activeOwned = finalSnapshots?.filter(
    (snapshot) => snapshot.status !== "deleted" && snapshotBelongsToPlan(plan, snapshot),
  ) ?? [];
  plan.snapshotCleanup.absenceConfirmed = finalSnapshots !== undefined &&
    activeOwned.length === 0 &&
    allKnownSnapshotsDirectlyAbsent(
      [...plan.knownSnapshotIds],
      plan.snapshotCleanup.directlyConfirmedAbsentIds,
    ) &&
    plan.snapshotCleanup.errors.length === 0;
  if (!plan.snapshotCleanup.absenceConfirmed && plan.snapshotCleanup.errors.length === 0) {
    plan.snapshotCleanup.errors.push({ kind: "other" });
  }
}

async function attemptSandboxCleanup(
  context: AccountContext,
  plan: ResourcePlan,
): Promise<void> {
  try {
    await cleanupSandboxPlan(context, plan);
  } catch (error) {
    plan.cleanup.errors.push(safeFailure(error));
  }
}

async function attemptSnapshotCleanup(
  context: AccountContext,
  plan: ResourcePlan,
): Promise<void> {
  try {
    await cleanupSnapshotsForPlan(context, plan);
  } catch (error) {
    plan.snapshotCleanup.errors.push(safeFailure(error));
  }
}

async function createSourceFixture(
  context: AccountContext,
  plan: ResourcePlan,
  canary: Buffer,
  canaryPath: string,
  persistRecovery: () => Promise<void>,
): Promise<SourceFixture> {
  plan.createAttempted = true;
  const sandbox = await Sandbox.create({
    ...sandboxCredentials(context),
    name: plan.name,
    persistent: true,
    timeout: sessionTimeoutMs,
    networkPolicy: "deny-all",
    env: {},
    tags: plan.tags,
    snapshotExpiration: snapshotExpirationMs,
    keepLastSnapshots: {
      count: 2,
      expiration: snapshotExpirationMs,
      deleteEvicted: true,
    },
    signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
  });
  plan.created = true;
  plan.knownSessionIds.add(sandbox.currentSession().sessionId);
  await persistRecovery();
  await sandbox.writeFiles(
    [{ path: canaryPath, content: canary, mode: 0o600 }],
    { signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS) },
  );
  const snapshot = await sandbox.snapshot({
    expiration: snapshotExpirationMs,
    signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
  });
  plan.knownSnapshotIds.add(snapshot.snapshotId);
  plan.knownSessionIds.add(snapshot.sourceSessionId);
  await persistRecovery();
  return {
    sandbox,
    snapshot,
    plan,
    canary,
    canaryPath,
    canarySha256: sha256(canary),
  };
}

async function boundedKnownPathRead(
  sandbox: Sandbox,
  path: string,
): Promise<Buffer | null> {
  const value = await sandbox.readFileToBuffer(
    { path },
    { signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS) },
  );
  if (value !== null && value.length > maximumCanaryReadBytes) {
    value.fill(0);
    throw new Error("known-path control read exceeded the fixed byte limit");
  }
  return value;
}

function exactCanary(value: Buffer | null, expected: Buffer): boolean {
  return value !== null && value.length === expected.length && timingSafeEqual(value, expected);
}

async function ownerForkControl(
  context: AccountContext,
  source: SourceFixture,
  forkPlan: ResourcePlan,
  persistRecovery: () => Promise<void>,
): Promise<boolean> {
  forkPlan.createAttempted = true;
  const fork = await Sandbox.fork({
    ...sandboxCredentials(context),
    sourceSandbox: source.plan.name,
    name: forkPlan.name,
    persistent: false,
    timeout: sessionTimeoutMs,
    networkPolicy: "deny-all",
    env: {},
    tags: forkPlan.tags,
    snapshotExpiration: snapshotExpirationMs,
    keepLastSnapshots: {
      count: 1,
      expiration: snapshotExpirationMs,
      deleteEvicted: true,
    },
    signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
  });
  forkPlan.created = true;
  forkPlan.knownSessionIds.add(fork.currentSession().sessionId);
  await persistRecovery();
  const value = await boundedKnownPathRead(fork, source.canaryPath);
  const canaryMatched = exactCanary(value, source.canary);
  value?.fill(0);
  const controlDataPassed = fork.name === forkPlan.name &&
    fork.sourceSnapshotId === source.snapshot.snapshotId &&
    fork.persistent === false &&
    isDenyAll(fork.networkPolicy) &&
    exactTags(fork.tags, forkPlan.tags) &&
    canaryMatched;
  await attemptSandboxCleanup(context, forkPlan);
  await attemptSnapshotCleanup(context, forkPlan);
  return controlDataPassed &&
    forkPlan.cleanup.absenceConfirmed &&
    forkPlan.cleanup.errors.length === 0 &&
    forkPlan.snapshotCleanup.absenceConfirmed &&
    forkPlan.snapshotCleanup.errors.length === 0;
}

async function sourceValidity(
  context: AccountContext,
  source: SourceFixture,
): Promise<SourceValidityRecord> {
  const record: SourceValidityRecord = {
    attempted: true,
    exactName: false,
    exactSnapshot: false,
    exactTags: false,
    denyAll: false,
    persistent: false,
    stopped: false,
    passed: false,
  };
  try {
    const readback = await Sandbox.get({
      ...sandboxCredentials(context),
      name: source.plan.name,
      resume: false,
      signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
    });
    const sessionId = readback.currentSession().sessionId;
    source.plan.knownSessionIds.add(sessionId);
    record.sessionId = sessionId;
    record.exactName = readback.name === source.plan.name;
    record.exactSnapshot = readback.currentSnapshotId === source.snapshot.snapshotId;
    record.exactTags = exactTags(readback.tags, source.plan.tags);
    record.denyAll = isDenyAll(readback.networkPolicy);
    record.persistent = readback.persistent;
    record.stopped = readback.status === "stopped";
    record.passed = record.exactName && record.exactSnapshot && record.exactTags &&
      record.denyAll && record.persistent && record.stopped;
  } catch (error) {
    record.failure = safeFailure(error);
  }
  return record;
}

function identityEvidence(identity: VerifiedAccountIdentity): {
  email: string;
  userIdSha256: string;
  exactMatch: true;
} {
  return {
    email: identity.email,
    userIdSha256: sha256(identity.userId),
    exactMatch: true,
  };
}

function serializePlan(plan: ResourcePlan): Record<string, unknown> {
  return {
    owner: plan.owner,
    role: plan.role,
    name: plan.name,
    tags: plan.tags,
    createAttempted: plan.createAttempted,
    created: plan.created,
    knownSessionIds: [...plan.knownSessionIds],
    knownSnapshotIds: [...plan.knownSnapshotIds],
    cleanup: plan.cleanup,
    snapshotCleanup: plan.snapshotCleanup,
  };
}

function recoveryJournalFor(
  runId: string,
  startedAt: string,
  crossAttemptStarted: boolean,
  accounts: ReturnType<typeof loadTwoOwnedAccounts>,
  plans: readonly ResourcePlan[],
): RecoveryJournal {
  return {
    schemaVersion: 1,
    testId,
    runId,
    startedAt,
    crossAttemptStarted,
    accounts: {
      attacker: {
        teamId: accounts.attacker.teamId,
        projectId: accounts.attacker.projectId,
        expectedEmail: accounts.attacker.expectedEmail,
      },
      victim: {
        teamId: accounts.victim.teamId,
        projectId: accounts.victim.projectId,
        expectedEmail: accounts.victim.expectedEmail,
      },
    },
    resources: plans.map((plan) => ({
      owner: plan.owner,
      role: plan.role,
      name: plan.name,
      tags: plan.tags,
      createAttempted: plan.createAttempted,
      created: plan.created,
      knownSessionIds: [...plan.knownSessionIds],
      knownSnapshotIds: [...plan.knownSnapshotIds],
    })),
    tokensRetained: false,
    rawCanariesRetained: false,
  };
}

async function writePrivateJsonAtomically(path: string, value: unknown): Promise<void> {
  const temporaryPath = `${path}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporaryPath, `${JSON.stringify(value, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
      flush: true,
    });
    await rename(temporaryPath, path);
  } catch (error) {
    await unlink(temporaryPath).catch(() => undefined);
    throw error;
  }
}

async function readBoundedPrivateJson(path: string): Promise<unknown> {
  const body = await readFile(path);
  try {
    if (body.length > maximumRecoveryManifestBytes) {
      throw new Error("recovery metadata exceeded its fixed byte limit");
    }
    return JSON.parse(body.toString("utf8"));
  } finally {
    body.fill(0);
  }
}

function validSnapshotId(value: unknown): value is string {
  return typeof value === "string" && /^snap_[A-Za-z0-9_-]{8,128}$/u.test(value);
}

function exactJournalAccount(
  value: unknown,
  expected: ExplicitAccountCredentials,
): boolean {
  const account = objectRecord(value);
  return account?.teamId === expected.teamId &&
    account.projectId === expected.projectId &&
    account.expectedEmail === expected.expectedEmail;
}

function hydrateCleanupOnlyPlans(
  value: unknown,
  runId: string,
  accounts: ReturnType<typeof loadTwoOwnedAccounts>,
  plans: readonly ResourcePlan[],
): { crossAttemptStarted: boolean } {
  const journal = objectRecord(value);
  if (
    journal?.schemaVersion !== 1 || journal.testId !== testId || journal.runId !== runId ||
    !exactJournalAccount(objectRecord(journal.accounts)?.attacker, accounts.attacker) ||
    !exactJournalAccount(objectRecord(journal.accounts)?.victim, accounts.victim) ||
    typeof journal.crossAttemptStarted !== "boolean" || !Array.isArray(journal.resources)
  ) {
    throw new Error("recovery journal did not match this exact run and owned account pair");
  }

  for (const plan of plans) {
    const matches = journal.resources.filter((candidate) => {
      const item = objectRecord(candidate);
      return item?.owner === plan.owner && item.role === plan.role && item.name === plan.name;
    });
    if (matches.length !== 1) {
      throw new Error("recovery journal did not contain one exact resource plan");
    }
    const item = objectRecord(matches[0])!;
    if (!exactStringRecord(item.tags, plan.tags)) {
      throw new Error("recovery journal resource tags did not match the deterministic run tags");
    }
    const sessionIds = item.knownSessionIds;
    const snapshotIds = item.knownSnapshotIds;
    if (
      typeof item.createAttempted !== "boolean" || typeof item.created !== "boolean" ||
      !Array.isArray(sessionIds) || !sessionIds.every(validSessionId) ||
      !Array.isArray(snapshotIds) || !snapshotIds.every(validSnapshotId)
    ) {
      throw new Error("recovery journal contained malformed bounded resource identifiers");
    }
    // A resumed process has no trusted live handle. Treat every deterministic plan as an
    // uncertain prior attempt so one immediate absence can never complete recovery.
    plan.createAttempted = true;
    plan.created = false;
    for (const sessionId of sessionIds) plan.knownSessionIds.add(sessionId);
    for (const snapshotId of snapshotIds) plan.knownSnapshotIds.add(snapshotId);
  }

  return { crossAttemptStarted: journal.crossAttemptStarted };
}

export async function runForkCrossTenant(): Promise<Record<string, unknown>> {
  const startedAtMs = Date.now();
  const startedAt = new Date(startedAtMs).toISOString();
  const runIntent = resolveForkRunIntent();
  const { runId } = runIntent;
  const names = createRunNames(runId);
  const accounts = loadTwoOwnedAccounts();
  const gate = new VercelRequestGate();
  const attackerContext: AccountContext = {
    credentials: accounts.attacker,
    fetch: createAccountFetch(accounts.attacker, gate),
  };
  const victimContext: AccountContext = {
    credentials: accounts.victim,
    fetch: createAccountFetch(accounts.victim, gate),
  };

  const plans = {
    attackerSource: newResourcePlan(
      "attacker",
      "attacker-source",
      names.attackerSource,
      resourceTags(runId, "attacker-source"),
    ),
    attackerOwnerFork: newResourcePlan(
      "attacker",
      "attacker-owner-fork",
      names.attackerOwnerFork,
      resourceTags(runId, "attacker-owner-fork"),
    ),
    victimSource: newResourcePlan(
      "victim",
      "victim-source",
      names.victimSource,
      resourceTags(runId, "victim-source"),
    ),
    victimOwnerFork: newResourcePlan(
      "victim",
      "victim-owner-fork",
      names.victimOwnerFork,
      resourceTags(runId, "victim-owner-fork"),
    ),
    crossForkAttackerScope: newResourcePlan(
      "attacker",
      "cross-fork",
      names.crossFork,
      resourceTags(runId, "cross-fork"),
    ),
    crossForkVictimScope: newResourcePlan(
      "victim",
      "cross-fork",
      names.crossFork,
      resourceTags(runId, "cross-fork"),
    ),
  };
  const allPlans = Object.values(plans);

  const artifactsDirectory = resolve("artifacts");
  const recoveryPath = resolve(
    artifactsDirectory,
    `${recoveryFilePrefix}${runId}.json`,
  );
  const evidencePath = resolve(
    artifactsDirectory,
    runIntent.cleanupOnly
      ? `SBX-026-fork-${runId}-cleanup-${startedAtMs}-private.json`
      : `SBX-026-fork-${runId}-private.json`,
  );
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });

  const unresolvedRecoveryFiles = (await readdir(artifactsDirectory)).filter((name) =>
    name.startsWith(recoveryFilePrefix) && name.endsWith(".json")
  );
  if (!runIntent.cleanupOnly && unresolvedRecoveryFiles.length > 0) {
    throw new Error(
      "an unfinished fork run exists; set SBX026_FORK_RUN_ID to that journal's UUID for cleanup-only recovery",
    );
  }

  // This is the single repository-global SBX-026 lock. It is acquired before the
  // first identity or Sandbox request and deliberately remains held if recovery
  // cannot be completed.
  const liveLock = await acquireSbx026LiveLock(forkLiveLockOptions(runIntent));

  let crossAttemptStarted = false;
  let recoveryManifestWritten = false;
  let recoveryManifestLoaded = false;
  let recoveryManifestRemoved = false;

  if (runIntent.cleanupOnly) {
    try {
      const recovered = hydrateCleanupOnlyPlans(
        await readBoundedPrivateJson(recoveryPath),
        runId,
        accounts,
        allPlans,
      );
      crossAttemptStarted = recovered.crossAttemptStarted;
      recoveryManifestLoaded = true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      // A shared lock can survive a crash before the first journal rename. No external
      // request is issued in that gap, but conservatively search every exact name.
      for (const plan of allPlans) {
        plan.createAttempted = true;
        plan.created = false;
      }
      crossAttemptStarted = true;
    }
  }

  const persistRecoveryJournal = async (): Promise<void> => {
    await writePrivateJsonAtomically(
      recoveryPath,
      recoveryJournalFor(runId, startedAt, crossAttemptStarted, accounts, allPlans),
    );
    recoveryManifestWritten = true;
  };
  await persistRecoveryJournal();

  const attackerCanary = randomBytes(32);
  const victimCanary = randomBytes(32);
  const attackerCanaryPath = `/vercel/sandbox/sbx-026-fork-attacker-${runId}.bin`;
  const victimCanaryPath = `/vercel/sandbox/sbx-026-fork-victim-${runId}.bin`;
  let attackerSource: SourceFixture | undefined;
  let victimSource: SourceFixture | undefined;
  let attackerIdentity: VerifiedAccountIdentity | undefined;
  let victimIdentity: VerifiedAccountIdentity | undefined;
  let attackerExactIdentityVerified = false;
  let victimExactIdentityVerified = false;
  let identitiesVerifiedAndDistinct = false;
  let attackerOwnerForkControlPassed = false;
  let victimOwnerForkControlPassed = false;
  let distinctSourceAndSessionIds = false;
  let victimOnlyCanaryAttribution = false;
  let preSourceValidity: SourceValidityRecord | undefined;
  let postSourceValidity: SourceValidityRecord | undefined;
  let crossForkRequestAttempts = 0;
  let foreignCrossForkSequence: number | undefined;
  let crossForkAccepted = false;
  let crossForkRejected = false;
  let crossForkRejectionConclusive = false;
  let crossForkFailure: ApiFailure | undefined;
  let crossForkRecord: AcceptedForkRecord | undefined;
  let crossForkResponseAttributable = false;
  let crossKnownPathReadAttempts = 0;
  let crossReadFailure: ApiFailure | undefined;
  let crossReadLength: number | undefined;
  let exactSyntheticVictimCanaryMatched = false;
  let setupError = false;
  let setupFailure: ApiFailure | undefined;
  let stopAtConfirmationPreserved = true;
  let sandboxCleanupAuthorized = false;
  let cleanupSkippedForUnverifiedIdentity = false;
  let derivedSandboxesAbsentBeforeSnapshotCleanup = false;
  let knownSnapshotsAbsentBeforeSourceCleanup = false;
  let testingEndedAtSequence: number | undefined;

  const crossForkAuditPath = `/api/v2/sandboxes/${encodeURIComponent(names.victimSource)}/fork`;
  let crossReadAuditPath: string | undefined;

  try {
    victimOnlyCanaryAttribution = attackerCanaryPath !== victimCanaryPath &&
      !timingSafeEqual(attackerCanary, victimCanary);
    if (!victimOnlyCanaryAttribution) {
      throw new Error("attacker and victim synthetic canaries were not distinct");
    }

    const [attackerIdentityResult, victimIdentityResult] = await Promise.allSettled([
      verifyAccountIdentity(accounts.attacker, attackerContext.fetch),
      verifyAccountIdentity(accounts.victim, victimContext.fetch),
    ]);
    if (attackerIdentityResult.status === "fulfilled") {
      attackerIdentity = attackerIdentityResult.value;
      attackerExactIdentityVerified = true;
    }
    if (victimIdentityResult.status === "fulfilled") {
      victimIdentity = victimIdentityResult.value;
      victimExactIdentityVerified = true;
    }
    if (!attackerIdentity || !victimIdentity) {
      throw new Error("both exact Vercel alias identity checks must succeed before Sandbox calls");
    }
    identitiesVerifiedAndDistinct = assertDistinctVerifiedIdentities(
      attackerIdentity,
      victimIdentity,
    );

    if (runIntent.cleanupOnly) {
      testingEndedAtSequence = gate.records.at(-1)?.sequence;
    } else {
      attackerSource = await createSourceFixture(
        attackerContext,
        plans.attackerSource,
        attackerCanary,
        attackerCanaryPath,
        persistRecoveryJournal,
      );
      attackerOwnerForkControlPassed = await ownerForkControl(
        attackerContext,
        attackerSource,
        plans.attackerOwnerFork,
        persistRecoveryJournal,
      );
      if (!attackerOwnerForkControlPassed) {
        throw new Error("attacker same-account fork control failed");
      }

      victimSource = await createSourceFixture(
        victimContext,
        plans.victimSource,
        victimCanary,
        victimCanaryPath,
        persistRecoveryJournal,
      );
      victimOwnerForkControlPassed = await ownerForkControl(
        victimContext,
        victimSource,
        plans.victimOwnerFork,
        persistRecoveryJournal,
      );
      if (!victimOwnerForkControlPassed) {
        throw new Error("victim same-account fork control failed");
      }

      const attackerOwnerForkSessionId = [...plans.attackerOwnerFork.knownSessionIds][0];
      const victimOwnerForkSessionId = [...plans.victimOwnerFork.knownSessionIds][0];
      distinctSourceAndSessionIds = attackerOwnerForkSessionId !== undefined &&
        victimOwnerForkSessionId !== undefined &&
        allDistinct([
          attackerSource.plan.name,
          victimSource.plan.name,
          attackerSource.snapshot.sourceSessionId,
          victimSource.snapshot.sourceSessionId,
          attackerSource.snapshot.snapshotId,
          victimSource.snapshot.snapshotId,
          attackerOwnerForkSessionId,
          victimOwnerForkSessionId,
        ]);
      if (!distinctSourceAndSessionIds) {
        throw new Error("source, snapshot, or owner-control session identifiers were not distinct");
      }

      preSourceValidity = await sourceValidity(victimContext, victimSource);
      if (!preSourceValidity.passed) {
        throw new Error("victim source failed the immediate pre-request validity check");
      }

      plans.crossForkAttackerScope.createAttempted = true;
      plans.crossForkVictimScope.createAttempted = true;
      crossAttemptStarted = true;
      await persistRecoveryJournal();
      crossForkRequestAttempts += 1;
      const sequenceBeforeCrossFork = gate.records.at(-1)?.sequence ?? 0;
      let crossResponse: Response | undefined;
      try {
        crossResponse = await oneShotSandboxRequest(
          accounts.attacker,
          attackerContext.fetch,
          `/v2/sandboxes/${encodeURIComponent(names.victimSource)}/fork`,
          {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(
              buildCrossForkBody(names.crossFork, plans.crossForkAttackerScope.tags),
            ),
            signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
          },
          { projectId: accounts.victim.projectId },
        );
      } catch (error) {
        crossForkFailure = safeFailure(error);
      }
      const crossInvocationRecords = gate.records.filter(
        (record) => record.sequence > sequenceBeforeCrossFork,
      );
      if (
        crossInvocationRecords.length === 1 &&
        crossInvocationRecords[0]!.origin === "vercel-sandbox-control-plane" &&
        crossInvocationRecords[0]!.method === "POST" &&
        crossInvocationRecords[0]!.pathname === crossForkAuditPath
      ) {
        foreignCrossForkSequence = crossInvocationRecords[0]!.sequence;
      }

      if (crossResponse) {
        if (crossResponse.ok) {
          crossForkAccepted = true;
          crossForkRecord = await acceptedForkRecord(
            crossResponse,
            {
              targetName: names.crossFork,
              sourceSnapshotId: victimSource.snapshot.snapshotId,
              tags: plans.crossForkAttackerScope.tags,
              earliestCreatedAtMs: startedAtMs - timestampSkewMs,
              latestCreatedAtMs: Date.now() + timestampSkewMs,
            },
          );
          crossForkResponseAttributable = crossForkRecord !== undefined;
          if (crossForkRecord) {
            // The public response schema does not identify the target project. Keep both
            // scope plans in orphan-recovery mode and bind snapshot cleanup to the one
            // returned session ID; exact-name/full-tag discovery determines placement.
            plans.crossForkAttackerScope.knownSessionIds.add(crossForkRecord.sessionId);
            plans.crossForkVictimScope.knownSessionIds.add(crossForkRecord.sessionId);
            await persistRecoveryJournal();
          }
        } else {
          crossForkRejected = true;
          crossForkFailure = await apiFailureFromResponse(crossResponse);
          crossForkRejectionConclusive = conclusiveAuthorizationRejection(crossForkFailure);
        }
      }

      // This is deliberately the first Vercel request after the raw cross-account fork.
      postSourceValidity = await sourceValidity(victimContext, victimSource);

      if (crossForkAccepted && crossForkRecord) {
        crossKnownPathReadAttempts += 1;
        crossReadAuditPath =
          `/api/v2/sandboxes/sessions/${encodeURIComponent(crossForkRecord.sessionId)}/fs/read`;
        const readResponse = await oneShotSandboxRequest(
          accounts.attacker,
          attackerContext.fetch,
          `/v2/sandboxes/sessions/${encodeURIComponent(crossForkRecord.sessionId)}/fs/read`,
          {
            method: "POST",
            headers: {
              accept: "application/octet-stream",
              "content-type": "application/json",
            },
            body: JSON.stringify({ path: victimCanaryPath }),
            signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
          },
        ).catch((error: unknown) => {
          crossReadFailure = safeFailure(error);
          return undefined;
        });
        if (readResponse) {
          if (readResponse.ok) {
            const body = await readBoundedResponse(readResponse, maximumCanaryReadBytes);
            crossReadLength = body.length;
            exactSyntheticVictimCanaryMatched = exactCanary(body, victimCanary);
            body.fill(0);
          } else {
            crossReadFailure = await apiFailureFromResponse(readResponse);
          }
        }
        testingEndedAtSequence = gate.records.at(-1)?.sequence;
        // Stop at the single exact canary confirmation. Only cleanup follows.
      } else {
        testingEndedAtSequence = gate.records.at(-1)?.sequence;
      }
    }
  } catch (error) {
    setupError = true;
    setupFailure = safeFailure(error);
    testingEndedAtSequence = gate.records.at(-1)?.sequence;
  } finally {
    attackerCanary.fill(0);
    victimCanary.fill(0);

    sandboxCleanupAuthorized = sandboxCleanupCallsAuthorized(
      attackerExactIdentityVerified,
      victimExactIdentityVerified,
      identitiesVerifiedAndDistinct,
    );
    cleanupSkippedForUnverifiedIdentity = !sandboxCleanupAuthorized;

    if (sandboxCleanupAuthorized) {
      // Dependency order is strict: derived forks first; every known snapshot is then
      // directly deleted/confirmed absent; source sandboxes are deleted last.
      const derivedPlans: Array<[AccountContext, ResourcePlan]> = [
        [victimContext, plans.crossForkVictimScope],
        [attackerContext, plans.crossForkAttackerScope],
        [attackerContext, plans.attackerOwnerFork],
        [victimContext, plans.victimOwnerFork],
      ];
      for (const [context, plan] of derivedPlans) {
        if (planHasKnownCleanupState(plan)) await attemptSandboxCleanup(context, plan);
      }
      derivedSandboxesAbsentBeforeSnapshotCleanup = derivedPlans.every(([, plan]) =>
        sandboxPlanCleanupPassed(plan)
      );

      if (derivedSandboxesAbsentBeforeSnapshotCleanup) {
        const snapshotPlans: Array<[AccountContext, ResourcePlan]> = [
          [victimContext, plans.crossForkVictimScope],
          [attackerContext, plans.crossForkAttackerScope],
          [attackerContext, plans.attackerOwnerFork],
          [victimContext, plans.victimOwnerFork],
          [attackerContext, plans.attackerSource],
          [victimContext, plans.victimSource],
        ];
        for (const [context, plan] of snapshotPlans) {
          if (planHasKnownCleanupState(plan)) await attemptSnapshotCleanup(context, plan);
        }
        knownSnapshotsAbsentBeforeSourceCleanup = snapshotPlans.every(([, plan]) =>
          snapshotPlanCleanupPassed(plan)
        );
      }

      if (knownSnapshotsAbsentBeforeSourceCleanup) {
        if (planHasKnownCleanupState(plans.attackerSource)) {
          await attemptSandboxCleanup(attackerContext, plans.attackerSource);
        }
        if (planHasKnownCleanupState(plans.victimSource)) {
          await attemptSandboxCleanup(victimContext, plans.victimSource);
        }
      }
    }

    const recordsAfterTesting = testingEndedAtSequence === undefined
      ? []
      : gate.records.filter((record) => record.sequence > testingEndedAtSequence!);
    stopAtConfirmationPreserved = recordsAfterTesting.every((record) => {
      return record.origin === "vercel-sandbox-control-plane" &&
        (
          record.method === "DELETE" ||
          (record.method === "GET" &&
            (
              record.pathname === "/api/v2/sandboxes" ||
              record.pathname === "/api/v2/sandboxes/snapshots" ||
              /^\/api\/v2\/sandboxes\/snapshots\/snap_[A-Za-z0-9_-]{8,128}$/u
                .test(record.pathname)
            ))
        );
    });
  }

  const requestAudit = assessRequestAudit(gate.records, {
    crossForkPath: crossForkAuditPath,
    crossForkAttempts: crossForkRequestAttempts,
    ...(foreignCrossForkSequence === undefined ? {} : { foreignCrossForkSequence }),
    ...(crossReadAuditPath ? { crossReadPath: crossReadAuditPath } : {}),
    crossReadAttempts: crossKnownPathReadAttempts,
  });

  const cleanupPassed = sandboxCleanupAuthorized &&
    derivedSandboxesAbsentBeforeSnapshotCleanup &&
    knownSnapshotsAbsentBeforeSourceCleanup &&
    allPlans.every((plan) =>
      sandboxPlanCleanupPassed(plan) && snapshotPlanCleanupPassed(plan)
    );

  if (cleanupPassed && recoveryManifestWritten) {
    try {
      await unlink(recoveryPath);
      recoveryManifestRemoved = true;
    } catch (error) {
      recoveryManifestRemoved = (error as NodeJS.ErrnoException).code === "ENOENT";
    }
  }
  const finalAssessment = assessForkAuthorization({
    setupError,
    cleanupPassed,
    requestAuditPassed: requestAudit.passed,
    identitiesVerifiedAndDistinct,
    attackerOwnerForkControlPassed,
    victimOwnerForkControlPassed,
    distinctSourceAndSessionIds,
    victimOnlyCanaryAttribution,
    victimSourceValidImmediatelyBefore: preSourceValidity?.passed === true,
    victimSourceValidImmediatelyAfter: postSourceValidity?.passed === true,
    crossForkRequestAttempts,
    crossForkAccepted,
    crossForkRejected,
    crossForkRejectionConclusive,
    crossForkResponseAttributable,
    crossKnownPathReadAttempts,
    exactSyntheticVictimCanaryMatched,
    stopAtConfirmationPreserved,
  });

  const probeCompletedAt = new Date().toISOString();
  const evidence: Record<string, unknown> = {
    schemaVersion: 1,
    testId,
    runId,
    startedAt,
    probeCompletedAt,
    runIntent,
    liveExecutionWasExplicitlyGated: true,
    identities: {
      attacker: attackerIdentity ? identityEvidence(attackerIdentity) : undefined,
      victim: victimIdentity ? identityEvidence(victimIdentity) : undefined,
      attackerExactIdentityVerified,
      victimExactIdentityVerified,
      distinct: identitiesVerifiedAndDistinct,
    },
    accountScopes: {
      attacker: {
        teamId: accounts.attacker.teamId,
        projectId: accounts.attacker.projectId,
        expectedEmail: accounts.attacker.expectedEmail,
      },
      victim: {
        teamId: accounts.victim.teamId,
        projectId: accounts.victim.projectId,
        expectedEmail: accounts.victim.expectedEmail,
      },
    },
    controls: {
      attackerOwnerForkControlPassed,
      victimOwnerForkControlPassed,
      distinctSourceAndSessionIds,
      victimOnlyCanaryAttribution,
      preSourceValidity,
      postSourceValidity,
    },
    syntheticCanaries: {
      attacker: {
        path: attackerCanaryPath,
        sha256: attackerSource?.canarySha256,
        length: 32,
      },
      victim: {
        path: victimCanaryPath,
        sha256: victimSource?.canarySha256,
        length: 32,
      },
      rawCanariesRetained: false,
      realEnvironmentSecretsUsed: false,
    },
    crossRequest: {
      rawNoRetry: true,
      attempts: crossForkRequestAttempts,
      auditSequence: foreignCrossForkSequence,
      method: "POST",
      path: crossForkAuditPath,
      attackerTeamId: accounts.attacker.teamId,
      victimProjectId: accounts.victim.projectId,
      victimSourceName: names.victimSource,
      accepted: crossForkAccepted,
      rejected: crossForkRejected,
      rejectionConclusive: crossForkRejectionConclusive,
      failure: crossForkFailure,
      response: crossForkRecord,
      responseAttributable: crossForkResponseAttributable,
      rawResponseBodyRetained: false,
    },
    crossKnownPathRead: {
      maximumAttempts: 1,
      attempts: crossKnownPathReadAttempts,
      path: victimCanaryPath,
      responseLength: crossReadLength,
      failure: crossReadFailure,
      exactSyntheticCanaryMatched: exactSyntheticVictimCanaryMatched,
      rawResponseBodyRetained: false,
    },
    requestAudit: {
      minimumIntervalMs: MINIMUM_VERCEL_REQUEST_INTERVAL_MS,
      assessment: requestAudit,
      records: gate.records,
      testingEndedAtSequence,
      stopAtConfirmationPreserved,
    },
    resources: allPlans.map(serializePlan),
    cleanupOrder: {
      sandboxCleanupAuthorized,
      cleanupSkippedForUnverifiedIdentity,
      derivedSandboxesAbsentBeforeSnapshotCleanup,
      knownSnapshotsAbsentBeforeSourceCleanup,
      dependencyOrder: ["derived-sandboxes", "known-snapshots", "source-sandboxes"],
      collectionNotFoundProvesKnownSnapshotAbsence: false,
    },
    recovery: {
      path: recoveryManifestRemoved ? undefined : recoveryPath,
      manifestWritten: recoveryManifestWritten,
      manifestLoaded: recoveryManifestLoaded,
      manifestRemoved: recoveryManifestRemoved,
      crossAttemptStarted,
      liveLock: {
        path: liveLock.path,
        testId: liveLock.metadata.testId,
        scope: liveLock.metadata.scope,
        runId: liveLock.metadata.runId,
        mode: liveLock.metadata.mode,
        createdAt: liveLock.metadata.createdAt,
        reclaimed: liveLock.reclaimed,
        leaseRetained: false,
        heldThroughEvidenceWrite: true,
        releaseEligibleAfterEvidenceWrite: cleanupPassed && recoveryManifestRemoved,
        releasedAfterEvidenceWrite: false,
      },
      suppliedRunIdCanOnlyCleanup: true,
    },
    setupError,
    setupFailure,
    ...releaseNeutralForkEvidenceState(cleanupPassed, recoveryManifestRemoved),
    evidenceGuards: {
      accountTokensRetained: false,
      rawForkResponseRetained: false,
      rawFileResponseRetained: false,
      rawCanariesRetained: false,
      environmentOverridesWereEmpty: true,
    },
  };

  await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
    flush: true,
  });
  const liveLockReleaseEligible = cleanupPassed && recoveryManifestRemoved;
  return finalizeForkEvidenceAfterLiveLockRelease(
    evidence,
    evidencePath,
    liveLock,
    liveLockReleaseEligible,
    finalAssessment,
  );
}

async function main(): Promise<void> {
  const evidence = await runForkCrossTenant();
  process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
}

const invokedUrl = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : undefined;
if (invokedUrl === import.meta.url) {
  main().catch((error: unknown) => {
    const failure = safeFailure(error);
    process.stderr.write(`${JSON.stringify({ testId, fatal: failure })}\n`);
    process.exitCode = 1;
  });
}
