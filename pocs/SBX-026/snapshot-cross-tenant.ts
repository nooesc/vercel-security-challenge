import "dotenv/config";

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  mkdir,
  open,
  readdir,
  rename,
  unlink,
} from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { Sandbox, Snapshot, type Snapshot as SnapshotInstance } from "@vercel/sandbox";
import {
  apiFailureFromError,
  apiFailureFromResponse,
  acquireSbx026LiveLock,
  assertDistinctVerifiedIdentities,
  conclusiveAuthorizationRejection,
  CONTROL_PLANE_TIMEOUT_MS,
  createAccountFetch,
  loadTwoOwnedAccounts,
  MINIMUM_VERCEL_REQUEST_INTERVAL_MS,
  oneShotSandboxRequest,
  readBoundedResponse,
  SBX026_LIVE_LOCK_PATH,
  VercelRequestGate,
  verifyAccountIdentity,
  type ApiFailure,
  type ExplicitAccountCredentials,
  type Sbx026LiveLock,
  type VerifiedAccountIdentity,
} from "./shared.js";
import {
  assessSnapshotAuthorization,
  type SnapshotAuthorizationAssessment,
} from "./verdict.js";

const testId = "SBX-026";
const sandboxTimeoutMs = 180_000;
const snapshotExpirationMs = 60 * 60_000;
const snapshotFreshnessMarginMs = 5 * 60_000;
const maximumJsonResponseBytes = 32_768;
const maximumSnapshotListItems = 10;
const maximumRecoveryManifestBytes = 32_768;
const timestampSkewMs = 5_000;
const ambiguousCreateAbsenceDelayMs = 1_000;
const maximumAmbiguousCreateChecks = 3;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const sessionIdPattern = /^sbx_[A-Za-z0-9]{20,128}$/u;
const snapshotIdPattern = /^snap_[A-Za-z0-9]{20,128}$/u;
const recoveryFilePrefix = "SBX-026-snapshot-recovery-";

export interface SnapshotRunIntent {
  runId: string;
  cleanupOnly: boolean;
}

type SandboxRole =
  | "attacker-source-control"
  | "attacker-restore-control"
  | "victim-source"
  | "victim-restore-control"
  | "cross-destination";

interface SandboxRecord {
  name: string;
  sessionId: string;
  teamId: string;
  projectId: string;
  createdAt: string;
  tagsMatched: boolean;
  networkPolicyDenyAll: boolean;
  sessionNetworkPolicyDenyAll: boolean;
  sourceSnapshotMatched?: boolean;
}

interface CleanupTarget {
  role: SandboxRole;
  account: ExplicitAccountCredentials;
  accountFetch: typeof fetch;
  name: string;
  tags: Record<string, string>;
  expectedSourceSnapshotId?: string;
  expectedSessionId?: string;
  creationAttempted: boolean;
  sandbox?: Sandbox;
  attributionValidated: boolean;
  recovered: boolean;
  stopNeeded: boolean;
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  absenceCheckAttempted: boolean;
  absenceObservations: number;
  delayedAbsenceChecks: number;
  absenceConfirmed: boolean;
  unsafeMetadataMismatch: boolean;
  failures: ApiFailure[];
}

interface SnapshotCleanupTarget {
  role: "attacker-control-snapshot" | "victim-snapshot";
  account: ExplicitAccountCredentials;
  accountFetch: typeof fetch;
  sourceSandboxName: string;
  sourceSessionId?: string;
  creationAttempted: boolean;
  snapshot?: SnapshotInstance;
  snapshotId?: string;
  deleteAttempted: boolean;
  deleted: boolean;
  absenceCheckAttempted: boolean;
  absenceConfirmed: boolean;
  directAbsenceCheckAttempted: boolean;
  directAbsenceConfirmed: boolean;
  directSnapshotIdsChecked: string[];
  absenceObservations: number;
  delayedAbsenceChecks: number;
  ambiguousCreateAbsenceConfirmed: boolean;
  cleanupDeferred: boolean;
  unsafeMetadataMismatch: boolean;
  failures: ApiFailure[];
}

interface ReadProof {
  attempted: boolean;
  status?: number;
  byteLength?: number;
  contentTypeMatched: boolean;
  exactCanaryMatched: boolean;
  failure?: ApiFailure;
  rawBodyRetained: false;
}

export interface AcceptedRestoreExpectation {
  name: string;
  snapshotId: string;
  tags: Record<string, string>;
  earliestCreatedAtMs: number;
  latestCreatedAtMs: number;
}

export interface AcceptedRestoreRecord {
  name: string;
  sessionId: string;
  createdAt: string;
  tagsMatched: true;
  networkPolicyDenyAll: true;
  sourceSnapshotMatched: true;
}

export function hasConfirmedAmbiguousCreateAbsence(absenceObservations: number): boolean {
  return Number.isSafeInteger(absenceObservations) && absenceObservations >= 2;
}

interface SnapshotValidityRecord {
  snapshotId: string;
  sourceSessionId: string;
  status: "created";
  createdAt: string;
  expiresAt: string;
  freshBeyondMargin: true;
}

export interface SnapshotValidationView {
  snapshotId: string;
  sourceSessionId: string;
  status: "failed" | "created" | "deleted";
  createdAt: Date;
  expiresAt: Date | undefined;
}

interface ListedSandboxMetadata {
  name: string;
  createdAt: number;
  tags?: Record<string, string>;
}

interface ListedSnapshotMetadata {
  id: string;
  sourceSessionId: string;
  status: "failed" | "created" | "deleted";
  createdAt: number;
}

interface RecoverySandboxEntry {
  role: SandboxRole;
  accountRole: "attacker" | "victim";
  name: string;
  tags: Record<string, string>;
  creationAttempted: boolean;
  expectedSourceSnapshotId?: string;
  expectedSessionId?: string;
}

interface RecoverySnapshotEntry {
  role: SnapshotCleanupTarget["role"];
  accountRole: "attacker" | "victim";
  sourceSandboxName: string;
  creationAttempted: boolean;
  sourceSessionId?: string;
  snapshotId?: string;
}

interface SnapshotRecoveryManifest {
  schemaVersion: 2;
  testId: typeof testId;
  packet: "snapshot";
  runId: string;
  startedAt: string;
  accounts: {
    attacker: {
      teamId: string;
      projectId: string;
      expectedEmail: string;
      userIdSha256?: string;
    };
    victim: {
      teamId: string;
      projectId: string;
      expectedEmail: string;
      userIdSha256?: string;
    };
  };
  crossAccountAttempt: {
    destinationName: string;
    creationAttempted: boolean;
    requestMayHaveBeenSentWhenTrue: true;
    retriesAllowed: false;
  };
  sandboxes: RecoverySandboxEntry[];
  snapshots: RecoverySnapshotEntry[];
  rawCanariesRetained: false;
  tokensRetained: false;
}

export function resolveSnapshotRunIntent(
  environment: Readonly<Record<string, string | undefined>>,
): SnapshotRunIntent {
  const supplied = environment.SBX026_RUN_ID;
  const runId = supplied ?? randomUUID();
  if (!uuidPattern.test(runId)) {
    throw new Error("SBX026_RUN_ID, when supplied, must be one canonical UUIDv4");
  }
  return { runId, cleanupOnly: supplied !== undefined };
}

export function snapshotRunNames(runId: string): Record<
  "attackerSource" | "attackerRestore" | "victimSource" | "victimRestore" | "crossDestination",
  string
> {
  if (!uuidPattern.test(runId)) throw new Error("snapshot run ID must be one canonical UUIDv4");
  return {
    attackerSource: `s26as-${runId}`,
    attackerRestore: `s26ar-${runId}`,
    victimSource: `s26vs-${runId}`,
    victimRestore: `s26vr-${runId}`,
    crossDestination: `s26xd-${runId}`,
  };
}

function nodeErrorCode(error: unknown): string | undefined {
  return error !== null && typeof error === "object" && "code" in error &&
      typeof (error as { code?: unknown }).code === "string"
    ? (error as { code: string }).code
    : undefined;
}

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("response did not contain the expected object");
  }
  return value as Record<string, unknown>;
}

function exactTags(value: unknown, expected: Record<string, string>): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const entries = Object.entries(value as Record<string, unknown>);
  const expectedEntries = Object.entries(expected);
  return entries.length === expectedEntries.length &&
    expectedEntries.every(([key, expectedValue]) =>
      (value as Record<string, unknown>)[key] === expectedValue
    );
}

function exactObjectKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(value, key)) &&
    Object.keys(value).every((key) => allowed.has(key));
}

function optionalIdentifier(
  value: unknown,
  pattern: RegExp,
  label: string,
): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new Error(`${label} was malformed`);
  }
  return value;
}

export function parseSnapshotRecoveryManifest(
  value: unknown,
  intent: SnapshotRunIntent,
  accounts: { attacker: ExplicitAccountCredentials; victim: ExplicitAccountCredentials },
  identityHashes: { attacker: string; victim: string },
): SnapshotRecoveryManifest {
  const root = object(value);
  if (!exactObjectKeys(root, [
    "schemaVersion",
    "testId",
    "packet",
    "runId",
    "startedAt",
    "accounts",
    "crossAccountAttempt",
    "sandboxes",
    "snapshots",
    "rawCanariesRetained",
    "tokensRetained",
  ])) {
    throw new Error("recovery manifest fields were incomplete or unexpected");
  }
  if (
    root.schemaVersion !== 2 || root.testId !== testId || root.packet !== "snapshot" ||
    root.runId !== intent.runId || typeof root.startedAt !== "string" ||
    !Number.isFinite(Date.parse(root.startedAt)) ||
    Date.parse(root.startedAt) > Date.now() + timestampSkewMs ||
    root.rawCanariesRetained !== false || root.tokensRetained !== false
  ) {
    throw new Error("recovery manifest did not match this exact snapshot run");
  }

  const rawAccounts = object(root.accounts);
  if (!exactObjectKeys(rawAccounts, ["attacker", "victim"])) {
    throw new Error("recovery manifest account fields were invalid");
  }
  const parsedAccounts = {} as SnapshotRecoveryManifest["accounts"];
  for (const role of ["attacker", "victim"] as const) {
    const raw = object(rawAccounts[role]);
    if (!exactObjectKeys(raw, ["teamId", "projectId", "expectedEmail"], ["userIdSha256"])) {
      throw new Error(`recovery manifest ${role} account fields were invalid`);
    }
    const expected = accounts[role];
    if (
      raw.teamId !== expected.teamId || raw.projectId !== expected.projectId ||
      raw.expectedEmail !== expected.expectedEmail ||
      (raw.userIdSha256 !== undefined && raw.userIdSha256 !== identityHashes[role])
    ) {
      throw new Error(`recovery manifest ${role} account binding mismatched`);
    }
    parsedAccounts[role] = {
      teamId: expected.teamId,
      projectId: expected.projectId,
      expectedEmail: expected.expectedEmail,
      ...(typeof raw.userIdSha256 === "string"
        ? { userIdSha256: raw.userIdSha256 }
        : {}),
    };
  }

  if (!Array.isArray(root.sandboxes) || root.sandboxes.length !== 5) {
    throw new Error("recovery manifest must contain five exact sandbox plans");
  }
  const names = snapshotRunNames(intent.runId);
  const sandboxExpectations: Array<{
    role: SandboxRole;
    accountRole: "attacker" | "victim";
    name: string;
  }> = [
    { role: "attacker-source-control", accountRole: "attacker", name: names.attackerSource },
    { role: "attacker-restore-control", accountRole: "attacker", name: names.attackerRestore },
    { role: "victim-source", accountRole: "victim", name: names.victimSource },
    { role: "victim-restore-control", accountRole: "victim", name: names.victimRestore },
    { role: "cross-destination", accountRole: "attacker", name: names.crossDestination },
  ];
  const parsedSandboxes: RecoverySandboxEntry[] = [];
  for (const expected of sandboxExpectations) {
    const matches = root.sandboxes.filter((entry) =>
      entry !== null && typeof entry === "object" && !Array.isArray(entry) &&
      (entry as { role?: unknown }).role === expected.role
    );
    if (matches.length !== 1) throw new Error(`recovery manifest lacked exact ${expected.role}`);
    const raw = object(matches[0]);
    if (!exactObjectKeys(
      raw,
      ["role", "accountRole", "name", "tags", "creationAttempted"],
      ["expectedSourceSnapshotId", "expectedSessionId"],
    )) {
      throw new Error(`recovery manifest ${expected.role} fields were invalid`);
    }
    const expectedTags = { test: testId, run: intent.runId, role: expected.role };
    if (
      raw.role !== expected.role || raw.accountRole !== expected.accountRole ||
      raw.name !== expected.name || !exactTags(raw.tags, expectedTags) ||
      typeof raw.creationAttempted !== "boolean"
    ) {
      throw new Error(`recovery manifest ${expected.role} attribution mismatched`);
    }
    const expectedSourceSnapshotId = optionalIdentifier(
      raw.expectedSourceSnapshotId,
      snapshotIdPattern,
      `${expected.role} source snapshot ID`,
    );
    const expectedSessionId = optionalIdentifier(
      raw.expectedSessionId,
      sessionIdPattern,
      `${expected.role} session ID`,
    );
    if (!raw.creationAttempted && (expectedSourceSnapshotId || expectedSessionId)) {
      throw new Error(`untouched ${expected.role} contained live identifiers`);
    }
    if (
      (expected.role === "attacker-source-control" || expected.role === "victim-source") &&
      expectedSourceSnapshotId !== undefined
    ) {
      throw new Error(`${expected.role} cannot have a source snapshot`);
    }
    parsedSandboxes.push({
      role: expected.role,
      accountRole: expected.accountRole,
      name: expected.name,
      tags: expectedTags,
      creationAttempted: raw.creationAttempted,
      ...(expectedSourceSnapshotId ? { expectedSourceSnapshotId } : {}),
      ...(expectedSessionId ? { expectedSessionId } : {}),
    });
  }

  if (!Array.isArray(root.snapshots) || root.snapshots.length !== 2) {
    throw new Error("recovery manifest must contain two exact snapshot plans");
  }
  const snapshotExpectations: Array<{
    role: SnapshotCleanupTarget["role"];
    accountRole: "attacker" | "victim";
    sourceSandboxName: string;
    sourceRole: SandboxRole;
  }> = [
    {
      role: "attacker-control-snapshot",
      accountRole: "attacker",
      sourceSandboxName: names.attackerSource,
      sourceRole: "attacker-source-control",
    },
    {
      role: "victim-snapshot",
      accountRole: "victim",
      sourceSandboxName: names.victimSource,
      sourceRole: "victim-source",
    },
  ];
  const parsedSnapshots: RecoverySnapshotEntry[] = [];
  for (const expected of snapshotExpectations) {
    const matches = root.snapshots.filter((entry) =>
      entry !== null && typeof entry === "object" && !Array.isArray(entry) &&
      (entry as { role?: unknown }).role === expected.role
    );
    if (matches.length !== 1) throw new Error(`recovery manifest lacked exact ${expected.role}`);
    const raw = object(matches[0]);
    if (!exactObjectKeys(
      raw,
      ["role", "accountRole", "sourceSandboxName", "creationAttempted"],
      ["sourceSessionId", "snapshotId"],
    )) {
      throw new Error(`recovery manifest ${expected.role} fields were invalid`);
    }
    const sourceSessionId = optionalIdentifier(
      raw.sourceSessionId,
      sessionIdPattern,
      `${expected.role} source session ID`,
    );
    const snapshotId = optionalIdentifier(raw.snapshotId, snapshotIdPattern, `${expected.role} ID`);
    const sourceSandbox = parsedSandboxes.find((entry) => entry.role === expected.sourceRole)!;
    if (
      raw.role !== expected.role || raw.accountRole !== expected.accountRole ||
      raw.sourceSandboxName !== expected.sourceSandboxName ||
      typeof raw.creationAttempted !== "boolean" ||
      (!raw.creationAttempted && (sourceSessionId || snapshotId)) ||
      (raw.creationAttempted &&
        (!sourceSessionId || sourceSessionId !== sourceSandbox.expectedSessionId))
    ) {
      throw new Error(`recovery manifest ${expected.role} attribution mismatched`);
    }
    parsedSnapshots.push({
      role: expected.role,
      accountRole: expected.accountRole,
      sourceSandboxName: expected.sourceSandboxName,
      creationAttempted: raw.creationAttempted,
      ...(sourceSessionId ? { sourceSessionId } : {}),
      ...(snapshotId ? { snapshotId } : {}),
    });
  }

  const attackerSnapshot = parsedSnapshots.find((entry) =>
    entry.role === "attacker-control-snapshot"
  )!;
  const victimSnapshot = parsedSnapshots.find((entry) => entry.role === "victim-snapshot")!;
  const attackerRestore = parsedSandboxes.find((entry) =>
    entry.role === "attacker-restore-control"
  )!;
  const victimRestore = parsedSandboxes.find((entry) => entry.role === "victim-restore-control")!;
  const crossDestination = parsedSandboxes.find((entry) => entry.role === "cross-destination")!;
  if (
    (attackerRestore.creationAttempted &&
      (!attackerSnapshot.snapshotId ||
        attackerRestore.expectedSourceSnapshotId !== attackerSnapshot.snapshotId)) ||
    (victimRestore.creationAttempted &&
      (!victimSnapshot.snapshotId || victimRestore.expectedSourceSnapshotId !== victimSnapshot.snapshotId)) ||
    (crossDestination.creationAttempted &&
      (!victimSnapshot.snapshotId ||
        crossDestination.expectedSourceSnapshotId !== victimSnapshot.snapshotId))
  ) {
    throw new Error("recovery manifest restore/source snapshot relationship mismatched");
  }

  const rawCross = object(root.crossAccountAttempt);
  if (!exactObjectKeys(rawCross, [
    "destinationName",
    "creationAttempted",
    "requestMayHaveBeenSentWhenTrue",
    "retriesAllowed",
  ]) || rawCross.destinationName !== names.crossDestination ||
    rawCross.creationAttempted !== crossDestination.creationAttempted ||
    rawCross.requestMayHaveBeenSentWhenTrue !== true || rawCross.retriesAllowed !== false) {
    throw new Error("recovery manifest cross-account attempt fields mismatched");
  }

  const knownSessionIds = parsedSandboxes.flatMap((entry) =>
    entry.expectedSessionId ? [entry.expectedSessionId] : []
  );
  const knownSnapshotIds = parsedSnapshots.flatMap((entry) =>
    entry.snapshotId ? [entry.snapshotId] : []
  );
  if (
    new Set(knownSessionIds).size !== knownSessionIds.length ||
    new Set(knownSnapshotIds).size !== knownSnapshotIds.length
  ) {
    throw new Error("recovery manifest identifiers were not distinct");
  }
  const anyAttempted = parsedSandboxes.some((entry) => entry.creationAttempted) ||
    parsedSnapshots.some((entry) => entry.creationAttempted);
  if (anyAttempted && (
    parsedAccounts.attacker.userIdSha256 !== identityHashes.attacker ||
    parsedAccounts.victim.userIdSha256 !== identityHashes.victim
  )) {
    throw new Error("attempted recovery manifest lacked exact verified identity bindings");
  }

  return {
    schemaVersion: 2,
    testId,
    packet: "snapshot",
    runId: intent.runId,
    startedAt: root.startedAt,
    accounts: parsedAccounts,
    crossAccountAttempt: {
      destinationName: names.crossDestination,
      creationAttempted: crossDestination.creationAttempted,
      requestMayHaveBeenSentWhenTrue: true,
      retriesAllowed: false,
    },
    sandboxes: parsedSandboxes,
    snapshots: parsedSnapshots,
    rawCanariesRetained: false,
    tokensRetained: false,
  };
}

function denyAllPolicy(value: unknown): boolean {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    (value as { mode?: unknown }).mode === "deny-all";
}

function boundedString(value: unknown, label: string, maximum = 256): string {
  if (
    typeof value !== "string" || value.length < 1 || value.length > maximum ||
    /[\0\r\n]/u.test(value)
  ) {
    throw new Error(`${label} was missing or malformed`);
  }
  return value;
}

export function parseAcceptedRestoreResponse(
  payload: unknown,
  expected: AcceptedRestoreExpectation,
): AcceptedRestoreRecord {
  const root = object(payload);
  const sandbox = object(root.sandbox);
  const session = object(root.session);
  const name = boundedString(sandbox.name, "sandbox name");
  const sessionId = boundedString(session.id, "session ID");
  const currentSessionId = boundedString(sandbox.currentSessionId, "current session ID");
  const createdAt = sandbox.createdAt;

  if (name !== expected.name) throw new Error("accepted restore returned a different sandbox name");
  if (sessionId !== currentSessionId) throw new Error("accepted restore session attribution mismatched");
  if (
    typeof createdAt !== "number" || !Number.isFinite(createdAt) ||
    createdAt < expected.earliestCreatedAtMs || createdAt > expected.latestCreatedAtMs
  ) {
    throw new Error("accepted restore creation time fell outside the run window");
  }
  if (!exactTags(sandbox.tags, expected.tags)) {
    throw new Error("accepted restore tags did not exactly match the run");
  }
  if (session.sourceSnapshotId !== expected.snapshotId) {
    throw new Error("accepted restore did not attribute the expected source snapshot");
  }
  if (!denyAllPolicy(sandbox.networkPolicy) || !denyAllPolicy(session.networkPolicy)) {
    throw new Error("accepted restore did not preserve the exact deny-all policy");
  }

  return {
    name,
    sessionId,
    createdAt: new Date(createdAt).toISOString(),
    tagsMatched: true,
    networkPolicyDenyAll: true,
    sourceSnapshotMatched: true,
  };
}

function sdkScope(account: ExplicitAccountCredentials, accountFetch: typeof fetch) {
  return {
    token: account.token,
    teamId: account.teamId,
    projectId: account.projectId,
    fetch: accountFetch,
  };
}

function makeCleanupTarget(
  role: SandboxRole,
  account: ExplicitAccountCredentials,
  accountFetch: typeof fetch,
  name: string,
  runTag: string,
): CleanupTarget {
  return {
    role,
    account,
    accountFetch,
    name,
    tags: { test: testId, run: runTag, role },
    creationAttempted: false,
    attributionValidated: false,
    recovered: false,
    stopNeeded: false,
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    absenceCheckAttempted: false,
    absenceObservations: 0,
    delayedAbsenceChecks: 0,
    absenceConfirmed: false,
    unsafeMetadataMismatch: false,
    failures: [],
  };
}

function makeSnapshotCleanupTarget(
  role: SnapshotCleanupTarget["role"],
  source: CleanupTarget,
): SnapshotCleanupTarget {
  return {
    role,
    account: source.account,
    accountFetch: source.accountFetch,
    sourceSandboxName: source.name,
    creationAttempted: false,
    deleteAttempted: false,
    deleted: false,
    absenceCheckAttempted: false,
    absenceConfirmed: false,
    directAbsenceCheckAttempted: false,
    directAbsenceConfirmed: false,
    directSnapshotIdsChecked: [],
    absenceObservations: 0,
    delayedAbsenceChecks: 0,
    ambiguousCreateAbsenceConfirmed: false,
    cleanupDeferred: false,
    unsafeMetadataMismatch: false,
    failures: [],
  };
}

function sandboxMetadataSafe(
  metadata: ListedSandboxMetadata,
  target: CleanupTarget,
  runStartedAtMs: number,
): boolean {
  return metadata.name === target.name &&
    exactTags(metadata.tags, target.tags) &&
    Number.isFinite(metadata.createdAt) &&
    metadata.createdAt >= runStartedAtMs - timestampSkewMs &&
    metadata.createdAt <= Date.now() + timestampSkewMs;
}

function sandboxRecord(
  sandbox: Sandbox,
  target: CleanupTarget,
  runStartedAtMs: number,
  expectedSnapshotId?: string,
): SandboxRecord {
  const session = sandbox.currentSession();
  const sessionId = session.sessionId;
  const record: SandboxRecord = {
    name: sandbox.name,
    sessionId,
    teamId: target.account.teamId,
    projectId: target.account.projectId,
    createdAt: sandbox.createdAt.toISOString(),
    tagsMatched: exactTags(sandbox.tags, target.tags),
    networkPolicyDenyAll: sandbox.networkPolicy === "deny-all",
    sessionNetworkPolicyDenyAll: session.networkPolicy === "deny-all",
    ...(expectedSnapshotId
      ? { sourceSnapshotMatched: sandbox.sourceSnapshotId === expectedSnapshotId }
      : {}),
  };
  if (
    record.name !== target.name || !record.tagsMatched || !record.networkPolicyDenyAll ||
    !record.sessionNetworkPolicyDenyAll ||
    sandbox.createdAt.getTime() < runStartedAtMs - timestampSkewMs ||
    sandbox.createdAt.getTime() > Date.now() + timestampSkewMs ||
    (expectedSnapshotId !== undefined && record.sourceSnapshotMatched !== true) ||
    (target.expectedSessionId !== undefined && record.sessionId !== target.expectedSessionId)
  ) {
    throw new Error(`${target.role} sandbox attribution failed`);
  }
  return record;
}

async function createTrackedSandbox(
  target: CleanupTarget,
  runStartedAtMs: number,
  journalCreateAttempt: () => Promise<void>,
  sourceSnapshotId?: string,
): Promise<{ sandbox: Sandbox; record: SandboxRecord }> {
  target.creationAttempted = true;
  if (sourceSnapshotId === undefined) delete target.expectedSourceSnapshotId;
  else target.expectedSourceSnapshotId = sourceSnapshotId;
  await journalCreateAttempt();
  const common = {
    ...sdkScope(target.account, target.accountFetch),
    name: target.name,
    persistent: false as const,
    timeout: sandboxTimeoutMs,
    networkPolicy: "deny-all" as const,
    tags: target.tags,
    signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
  };
  const sandbox = sourceSnapshotId === undefined
    ? await Sandbox.create(common)
    : await Sandbox.create({
      ...common,
      source: { type: "snapshot" as const, snapshotId: sourceSnapshotId },
    });
  const record = sandboxRecord(sandbox, target, runStartedAtMs, sourceSnapshotId);
  target.expectedSessionId = record.sessionId;
  target.sandbox = sandbox;
  target.attributionValidated = true;
  target.stopNeeded = true;
  await journalCreateAttempt();
  return { sandbox, record };
}

async function independentSandboxReadback(
  target: CleanupTarget,
  runStartedAtMs: number,
  expectedSessionId: string,
  expectedSnapshotId?: string,
): Promise<SandboxRecord> {
  const sandbox = await Sandbox.get({
    ...sdkScope(target.account, target.accountFetch),
    name: target.name,
    resume: false,
    signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
  });
  const record = sandboxRecord(sandbox, target, runStartedAtMs, expectedSnapshotId);
  if (record.sessionId !== expectedSessionId) {
    throw new Error(`${target.role} independent readback returned a different session`);
  }
  return record;
}

async function oneShotKnownPathRead(
  account: ExplicitAccountCredentials,
  accountFetch: typeof fetch,
  sessionId: string,
  path: string,
  expected: Buffer,
): Promise<ReadProof> {
  try {
    const response = await oneShotSandboxRequest(
      account,
      accountFetch,
      `/v2/sandboxes/sessions/${encodeURIComponent(sessionId)}/fs/read`,
      {
        method: "POST",
        headers: {
          accept: "application/octet-stream",
          "content-type": "application/json",
        },
        body: JSON.stringify({ path }),
        signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
      },
    );
    if (!response.ok) {
      return {
        attempted: true,
        status: response.status,
        contentTypeMatched: false,
        exactCanaryMatched: false,
        failure: await apiFailureFromResponse(response),
        rawBodyRetained: false,
      };
    }
    const contentTypeMatched = (response.headers.get("content-type") ?? "")
      .includes("application/octet-stream");
    if (!contentTypeMatched) {
      const discarded = await readBoundedResponse(response);
      discarded.fill(0);
      return {
        attempted: true,
        status: response.status,
        contentTypeMatched: false,
        exactCanaryMatched: false,
        failure: { kind: "other" },
        rawBodyRetained: false,
      };
    }
    const body = await readBoundedResponse(response, expected.length);
    try {
      return {
        attempted: true,
        status: response.status,
        byteLength: body.length,
        contentTypeMatched: true,
        exactCanaryMatched: response.status === 200 && body.equals(expected),
        rawBodyRetained: false,
      };
    } finally {
      body.fill(0);
    }
  } catch {
    return {
      attempted: true,
      contentTypeMatched: false,
      exactCanaryMatched: false,
      failure: { kind: "other" },
      rawBodyRetained: false,
    };
  }
}

export function validateSnapshot(
  snapshot: SnapshotValidationView,
  expectedSnapshotId: string,
  expectedSourceSessionId: string,
  runStartedAtMs: number,
): SnapshotValidityRecord {
  const createdAtMs = snapshot.createdAt.getTime();
  const expiresAt = snapshot.expiresAt;
  if (snapshot.snapshotId !== expectedSnapshotId) {
    throw new Error("snapshot ID attribution failed");
  }
  if (snapshot.status !== "created") throw new Error("snapshot did not have created status");
  if (snapshot.sourceSessionId !== expectedSourceSessionId) {
    throw new Error("snapshot source session attribution failed");
  }
  if (
    !Number.isFinite(createdAtMs) || createdAtMs < runStartedAtMs - timestampSkewMs ||
    createdAtMs > Date.now() + timestampSkewMs
  ) {
    throw new Error("snapshot creation time fell outside the run window");
  }
  if (!expiresAt || expiresAt.getTime() <= Date.now() + snapshotFreshnessMarginMs) {
    throw new Error("snapshot did not remain valid beyond the fixed freshness margin");
  }
  return {
    snapshotId: snapshot.snapshotId,
    sourceSessionId: snapshot.sourceSessionId,
    status: "created",
    createdAt: snapshot.createdAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    freshBeyondMargin: true,
  };
}

async function getValidSnapshot(
  target: SnapshotCleanupTarget,
  runStartedAtMs: number,
): Promise<SnapshotValidityRecord> {
  if (!target.snapshotId || !target.sourceSessionId) {
    throw new Error(`${target.role} lacks exact snapshot attribution`);
  }
  const snapshot = await Snapshot.get({
    ...sdkScope(target.account, target.accountFetch),
    snapshotId: target.snapshotId,
    signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
  });
  return validateSnapshot(snapshot, target.snapshotId, target.sourceSessionId, runStartedAtMs);
}

async function listExactSandboxes(target: CleanupTarget): Promise<{
  complete: boolean;
  exact: ListedSandboxMetadata[];
}> {
  const page = await Sandbox.list({
    ...sdkScope(target.account, target.accountFetch),
    namePrefix: target.name,
    limit: maximumSnapshotListItems,
    signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
  });
  const sandboxes = page.sandboxes as ListedSandboxMetadata[];
  return {
    complete: page.pagination.next === null,
    exact: sandboxes.filter((sandbox) => sandbox.name === target.name),
  };
}

async function rawDeleteSandbox(target: CleanupTarget): Promise<void> {
  if (!target.attributionValidated) {
    throw new Error(`refused raw deletion of unvalidated ${target.role} sandbox`);
  }
  target.deleteAttempted = true;
  try {
    const response = await oneShotSandboxRequest(
      target.account,
      target.accountFetch,
      `/v2/sandboxes/${encodeURIComponent(target.name)}`,
      { method: "DELETE", signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS) },
      { projectId: target.account.projectId },
    );
    if (response.ok) {
      const discarded = await readBoundedResponse(response, maximumJsonResponseBytes);
      discarded.fill(0);
      target.deleted = true;
      return;
    }
    const failure = await apiFailureFromResponse(response);
    if (failure.status === 404) target.deleted = true;
    else target.failures.push(failure);
  } catch {
    target.failures.push({ kind: "other" });
  }
}

async function cleanupSandbox(target: CleanupTarget, runStartedAtMs: number): Promise<void> {
  if (!target.creationAttempted) {
    target.absenceConfirmed = true;
    return;
  }

  if (!target.sandbox) {
    for (let check = 0; check < maximumAmbiguousCreateChecks; check += 1) {
      target.absenceCheckAttempted = true;
      try {
        const listed = await listExactSandboxes(target);
        if (!listed.complete || listed.exact.length > 1) {
          target.unsafeMetadataMismatch = true;
          break;
        }
        if (listed.exact.length === 0) {
          target.absenceObservations += 1;
          if (hasConfirmedAmbiguousCreateAbsence(target.absenceObservations)) {
            target.deleted = true;
            target.absenceConfirmed = true;
            return;
          }
        } else if (!sandboxMetadataSafe(listed.exact[0]!, target, runStartedAtMs)) {
          target.unsafeMetadataMismatch = true;
          break;
        } else {
          target.absenceObservations = 0;
          try {
            const recovered = await Sandbox.get({
              ...sdkScope(target.account, target.accountFetch),
              name: target.name,
              resume: false,
              signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
            });
            sandboxRecord(
              recovered,
              target,
              runStartedAtMs,
              target.expectedSourceSnapshotId,
            );
            target.sandbox = recovered;
            target.attributionValidated = true;
            target.recovered = true;
            target.stopNeeded = true;
            break;
          } catch (error) {
            target.failures.push(apiFailureFromError(error));
          }
        }
      } catch (error) {
        target.failures.push(apiFailureFromError(error));
      }

      if (check + 1 < maximumAmbiguousCreateChecks) {
        target.delayedAbsenceChecks += 1;
        await delay(ambiguousCreateAbsenceDelayMs);
      }
    }
  }

  if (!target.sandbox || !target.attributionValidated) {
    target.absenceConfirmed = false;
    return;
  }

  if (!target.deleted) {
    if (target.stopNeeded) {
      target.stopAttempted = true;
      try {
        await target.sandbox.stop({ signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS) });
        target.stopped = true;
        target.stopNeeded = false;
      } catch (error) {
        const failure = apiFailureFromError(error);
        if (failure.status === 404 || failure.status === 410) target.stopped = true;
        else target.failures.push(failure);
      }
    } else {
      target.stopped = true;
    }
    target.deleteAttempted = true;
    try {
      await target.sandbox.delete({ signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS) });
      target.deleted = true;
    } catch (error) {
      const failure = apiFailureFromError(error);
      if (failure.status === 404) target.deleted = true;
      else target.failures.push(failure);
    }
  }

  target.absenceCheckAttempted = true;
  try {
    let listed = await listExactSandboxes(target);
    if (
      listed.complete && listed.exact.length === 1 &&
      sandboxMetadataSafe(listed.exact[0]!, target, runStartedAtMs) &&
      target.attributionValidated && !target.unsafeMetadataMismatch
    ) {
      await rawDeleteSandbox(target);
      listed = await listExactSandboxes(target);
    }
    if (!listed.complete || listed.exact.length > 0) {
      if (listed.exact.some((item) => !sandboxMetadataSafe(item, target, runStartedAtMs))) {
        target.unsafeMetadataMismatch = true;
      }
      target.absenceConfirmed = false;
    } else {
      target.absenceObservations += 1;
      target.absenceConfirmed = true;
      target.deleted = true;
    }
  } catch (error) {
    target.failures.push(apiFailureFromError(error));
    target.absenceConfirmed = false;
  }
}

async function listSourceSnapshots(target: SnapshotCleanupTarget): Promise<{
  complete: boolean;
  snapshots: ListedSnapshotMetadata[];
}> {
  const page = await Snapshot.list({
    ...sdkScope(target.account, target.accountFetch),
    name: target.sourceSandboxName,
    limit: maximumSnapshotListItems,
    sortOrder: "desc",
    signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
  });
  return {
    complete: page.pagination.next === null,
    snapshots: page.snapshots as ListedSnapshotMetadata[],
  };
}

function snapshotMetadataSafe(
  metadata: ListedSnapshotMetadata,
  target: SnapshotCleanupTarget,
  runStartedAtMs: number,
): boolean {
  return snapshotIdPattern.test(metadata.id) && target.sourceSessionId !== undefined &&
    metadata.sourceSessionId === target.sourceSessionId &&
    Number.isFinite(metadata.createdAt) &&
    metadata.createdAt >= runStartedAtMs - timestampSkewMs &&
    metadata.createdAt <= Date.now() + timestampSkewMs;
}

function snapshotHandleSafeForCleanup(
  snapshot: SnapshotInstance,
  metadata: ListedSnapshotMetadata,
  target: SnapshotCleanupTarget,
  runStartedAtMs: number,
): boolean {
  const createdAt = snapshot.createdAt.getTime();
  return snapshot.snapshotId === metadata.id &&
    target.sourceSessionId !== undefined &&
    snapshot.sourceSessionId === target.sourceSessionId &&
    Number.isFinite(createdAt) &&
    createdAt >= runStartedAtMs - timestampSkewMs &&
    createdAt <= Date.now() + timestampSkewMs;
}

async function cleanupSnapshot(
  target: SnapshotCleanupTarget,
  runStartedAtMs: number,
  derivativesAbsent: boolean,
): Promise<void> {
  if (!target.creationAttempted) {
    target.absenceConfirmed = true;
    return;
  }
  if (!derivativesAbsent) {
    target.cleanupDeferred = true;
    return;
  }

  const knownSnapshotIds = new Set<string>(target.snapshotId ? [target.snapshotId] : []);

  // A snapshot call can time out after the service accepted it. With no returned ID,
  // one immediate empty collection read is not absence proof: wait for a second clean
  // observation, while recovering any exact source-session snapshot that appears.
  if (knownSnapshotIds.size === 0 && !target.snapshot) {
    for (let check = 0; check < maximumAmbiguousCreateChecks; check += 1) {
      target.absenceCheckAttempted = true;
      try {
        const listed = await listSourceSnapshots(target);
        if (!listed.complete) {
          target.unsafeMetadataMismatch = true;
          break;
        }
        for (const metadata of listed.snapshots) {
          if (!snapshotMetadataSafe(metadata, target, runStartedAtMs)) {
            target.unsafeMetadataMismatch = true;
            continue;
          }
          knownSnapshotIds.add(metadata.id);
        }
        if (target.unsafeMetadataMismatch || knownSnapshotIds.size > 0) break;
        target.absenceObservations += 1;
        if (hasConfirmedAmbiguousCreateAbsence(target.absenceObservations)) {
          target.ambiguousCreateAbsenceConfirmed = true;
          target.absenceConfirmed = true;
          target.deleted = true;
          return;
        }
      } catch (error) {
        target.failures.push(apiFailureFromError(error));
      }
      if (check + 1 < maximumAmbiguousCreateChecks) {
        target.delayedAbsenceChecks += 1;
        await delay(ambiguousCreateAbsenceDelayMs);
      }
    }
    if (knownSnapshotIds.size === 0) {
      target.absenceConfirmed = false;
      return;
    }
  }

  if (target.snapshot && target.snapshot.status !== "deleted") {
    target.deleteAttempted = true;
    try {
      await target.snapshot.delete({ signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS) });
      target.deleted = true;
    } catch (error) {
      const failure = apiFailureFromError(error);
      if (failure.status === 404) target.deleted = true;
      else target.failures.push(failure);
    }
  }

  target.absenceCheckAttempted = true;
  try {
    let listed = await listSourceSnapshots(target);
    if (!listed.complete) target.unsafeMetadataMismatch = true;
    const active = listed.snapshots.filter((snapshot) => snapshot.status !== "deleted");
    for (const metadata of active) {
      if (!snapshotMetadataSafe(metadata, target, runStartedAtMs)) {
        target.unsafeMetadataMismatch = true;
        continue;
      }
      knownSnapshotIds.add(metadata.id);
      try {
        const snapshot = await Snapshot.get({
          ...sdkScope(target.account, target.accountFetch),
          snapshotId: metadata.id,
          signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
        });
        if (!snapshotHandleSafeForCleanup(snapshot, metadata, target, runStartedAtMs)) {
          target.unsafeMetadataMismatch = true;
          continue;
        }
        if (snapshot.status === "deleted") continue;
        target.deleteAttempted = true;
        await snapshot.delete({ signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS) });
      } catch (error) {
        const failure = apiFailureFromError(error);
        if (failure.status !== 404) target.failures.push(failure);
      }
    }
    listed = await listSourceSnapshots(target);
    for (const metadata of listed.snapshots) {
      if (snapshotMetadataSafe(metadata, target, runStartedAtMs)) {
        knownSnapshotIds.add(metadata.id);
      }
    }
    const remaining = listed.snapshots.filter((snapshot) => snapshot.status !== "deleted");
    const collectionAbsenceConfirmed = listed.complete && remaining.length === 0 &&
      !target.unsafeMetadataMismatch;
    target.directAbsenceCheckAttempted = true;
    target.directSnapshotIdsChecked = [...knownSnapshotIds].sort();
    if (target.directSnapshotIdsChecked.length === 0) {
      target.directAbsenceConfirmed = false;
      target.absenceConfirmed = false;
      return;
    }
    let directAbsenceConfirmed = true;
    for (const snapshotId of target.directSnapshotIdsChecked) {
      try {
        const snapshot = await Snapshot.get({
          ...sdkScope(target.account, target.accountFetch),
          snapshotId,
          signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
        });
        if (
          snapshot.snapshotId !== snapshotId || snapshot.sourceSessionId !== target.sourceSessionId ||
          snapshot.status !== "deleted"
        ) {
          target.unsafeMetadataMismatch = true;
          directAbsenceConfirmed = false;
        }
      } catch (error) {
        const failure = apiFailureFromError(error);
        if (failure.status !== 404) {
          target.failures.push(failure);
          directAbsenceConfirmed = false;
        }
      }
    }
    target.directAbsenceConfirmed = directAbsenceConfirmed;
    target.absenceConfirmed = collectionAbsenceConfirmed && directAbsenceConfirmed &&
      !target.unsafeMetadataMismatch;
    if (target.absenceConfirmed) target.deleted = true;
  } catch (error) {
    target.failures.push(apiFailureFromError(error));
    target.absenceConfirmed = false;
  }
}

export function snapshotCleanupProofSufficient(proof: {
  creationAttempted: boolean;
  absenceConfirmed: boolean;
  directAbsenceCheckAttempted: boolean;
  directAbsenceConfirmed: boolean;
  directSnapshotIdsChecked: readonly string[];
  absenceObservations: number;
  delayedAbsenceChecks: number;
  ambiguousCreateAbsenceConfirmed: boolean;
  unsafeMetadataMismatch: boolean;
}): boolean {
  if (proof.unsafeMetadataMismatch) return false;
  if (!proof.creationAttempted) return true;
  if (!proof.absenceConfirmed) return false;
  if (proof.ambiguousCreateAbsenceConfirmed) {
    return proof.directSnapshotIdsChecked.length === 0 &&
      !proof.directAbsenceCheckAttempted && !proof.directAbsenceConfirmed &&
      hasConfirmedAmbiguousCreateAbsence(proof.absenceObservations) &&
      proof.delayedAbsenceChecks >= 1;
  }
  return proof.directAbsenceCheckAttempted && proof.directAbsenceConfirmed &&
    proof.directSnapshotIdsChecked.length > 0;
}

export function snapshotFinalizationPassed(state: {
  resourceCleanupPassed: boolean;
  recoveryManifestWritten: boolean;
  recoveryManifestRemoved: boolean;
  canonicalLiveLockRemoved: boolean;
}): boolean {
  return state.resourceCleanupPassed &&
    (!state.recoveryManifestWritten || state.recoveryManifestRemoved) &&
    state.canonicalLiveLockRemoved;
}

async function parseSuccessfulJson(response: Response): Promise<unknown> {
  const body = await readBoundedResponse(response, maximumJsonResponseBytes);
  try {
    return JSON.parse(body.toString("utf8"));
  } finally {
    body.fill(0);
  }
}

async function writeDurablePrivateJson(path: string, value: unknown): Promise<void> {
  const temporaryPath = `${path}.tmp`;
  const noFollow = "O_NOFOLLOW" in constants ? constants.O_NOFOLLOW : 0;
  const handle = await open(
    temporaryPath,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | noFollow,
    0o600,
  );
  try {
    await handle.chmod(0o600);
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8" });
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(temporaryPath, path);
  await syncParentDirectory(path);
}

async function syncParentDirectory(path: string): Promise<void> {
  const directory = await open(dirname(path), constants.O_RDONLY);
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

async function removeExactRecoveryJournalFiles(recoveryPath: string): Promise<void> {
  // Remove the non-authoritative temporary first. If that fails, the durable
  // descriptor at recoveryPath is left in place for cleanup-only recovery.
  for (const exactPath of [`${recoveryPath}.tmp`, recoveryPath]) {
    try {
      await unlink(exactPath);
    } catch (error) {
      if (nodeErrorCode(error) !== "ENOENT") throw error;
    }
  }
}

export function snapshotEvidenceAssessmentForPublication(
  assessment: SnapshotAuthorizationAssessment,
): SnapshotAuthorizationAssessment | {
  verdict: "pending-lock-release";
  candidate: false;
  controlsPassed: boolean;
  summary: string;
} {
  if (assessment.verdict !== "pass" && assessment.verdict !== "candidate") return assessment;
  return {
    verdict: "pending-lock-release",
    candidate: false,
    controlsPassed: assessment.controlsPassed,
    summary: "Authorization outcome remains provisional until the exact shared lock releases.",
  };
}

export async function publishSnapshotEvidenceBeforeRelease(
  input: {
    stagedEvidencePath: string;
    evidencePath: string;
    lock: Pick<Sbx026LiveLock, "release">;
    releaseAuthorized: boolean;
  },
  operations: {
    renameFile: (source: string, destination: string) => Promise<void>;
    syncPublishedParent: (path: string) => Promise<void>;
  } = {
    renameFile: rename,
    syncPublishedParent: syncParentDirectory,
  },
): Promise<boolean> {
  await operations.renameFile(input.stagedEvidencePath, input.evidencePath);
  await operations.syncPublishedParent(input.evidencePath);
  if (!input.releaseAuthorized) return false;
  await input.lock.release();
  return true;
}

export async function settleInitialSnapshotJournalFailure(
  input: {
    validRecoveryDescriptor: boolean;
    zeroVercelState: boolean;
    errorEvidenceWritten: boolean;
    lock: Pick<Sbx026LiveLock, "release">;
  },
  operations: {
    clearInvalidRecoveryFiles: () => Promise<boolean>;
    restoreValidRecoveryDescriptor: () => Promise<void>;
  },
): Promise<"released-zero-state" | "retained-valid-recovery"> {
  if (input.validRecoveryDescriptor) return "retained-valid-recovery";
  if (input.zeroVercelState && input.errorEvidenceWritten) {
    const cleared = await operations.clearInvalidRecoveryFiles();
    if (cleared) {
      try {
        await input.lock.release();
        return "released-zero-state";
      } catch (error) {
        await operations.restoreValidRecoveryDescriptor();
        throw error;
      }
    }
  }
  await operations.restoreValidRecoveryDescriptor();
  return "retained-valid-recovery";
}

export function hasValidZeroAttemptSnapshotRecoveryDescriptor(
  value: unknown,
  intent: SnapshotRunIntent,
  accounts: { attacker: ExplicitAccountCredentials; victim: ExplicitAccountCredentials },
): boolean {
  try {
    const manifest = parseSnapshotRecoveryManifest(value, intent, accounts, {
      attacker: "0".repeat(64),
      victim: "1".repeat(64),
    });
    return manifest.crossAccountAttempt.creationAttempted === false &&
      manifest.sandboxes.every((target) => target.creationAttempted === false) &&
      manifest.snapshots.every((target) => target.creationAttempted === false);
  } catch {
    return false;
  }
}

export function snapshotRecoveryManifestRemovalAuthorized(state: {
  identitiesVerifiedDistinct: boolean;
  resourceCleanupPassed: boolean;
  recoveryManifestWritten: boolean;
}): boolean {
  return state.identitiesVerifiedDistinct && state.resourceCleanupPassed &&
    state.recoveryManifestWritten;
}

export async function removeSnapshotRecoveryManifestIfAuthorized(
  state: {
    identitiesVerifiedDistinct: boolean;
    resourceCleanupPassed: boolean;
    recoveryManifestWritten: boolean;
  },
  removeExactManifest: () => Promise<void>,
): Promise<boolean> {
  if (!snapshotRecoveryManifestRemovalAuthorized(state)) return false;
  try {
    await removeExactManifest();
    return true;
  } catch (error) {
    return nodeErrorCode(error) === "ENOENT";
  }
}

async function readBoundedPrivateJson(path: string): Promise<unknown> {
  const noFollow = "O_NOFOLLOW" in constants ? constants.O_NOFOLLOW : 0;
  const handle = await open(path, constants.O_RDONLY | noFollow);
  let body: Buffer | undefined;
  try {
    const metadata = await handle.stat({ bigint: true });
    if (
      !metadata.isFile() || metadata.size < 2n ||
      metadata.size > BigInt(maximumRecoveryManifestBytes) ||
      (metadata.mode & 0o777n) !== 0o600n
    ) {
      throw new Error("recovery manifest must be a bounded regular mode-0600 file");
    }
    body = await handle.readFile();
    return JSON.parse(body.toString("utf8"));
  } finally {
    body?.fill(0);
    await handle.close();
  }
}

function recoveryManifestFor(
  runId: string,
  startedAt: string,
  accounts: { attacker: ExplicitAccountCredentials; victim: ExplicitAccountCredentials },
  identities: { attacker?: VerifiedAccountIdentity; victim?: VerifiedAccountIdentity },
  sandboxTargets: readonly CleanupTarget[],
  snapshotTargets: readonly SnapshotCleanupTarget[],
  crossDestination: CleanupTarget,
): SnapshotRecoveryManifest {
  const accountRoleForSandbox = (role: SandboxRole): "attacker" | "victim" =>
    role === "victim-source" || role === "victim-restore-control" ? "victim" : "attacker";
  const accountRoleForSnapshot = (
    role: SnapshotCleanupTarget["role"],
  ): "attacker" | "victim" => role === "victim-snapshot" ? "victim" : "attacker";
  return {
    schemaVersion: 2,
    testId,
    packet: "snapshot",
    runId,
    startedAt,
    accounts: {
      attacker: {
        teamId: accounts.attacker.teamId,
        projectId: accounts.attacker.projectId,
        expectedEmail: accounts.attacker.expectedEmail,
        ...(identities.attacker
          ? { userIdSha256: sha256(identities.attacker.userId) }
          : {}),
      },
      victim: {
        teamId: accounts.victim.teamId,
        projectId: accounts.victim.projectId,
        expectedEmail: accounts.victim.expectedEmail,
        ...(identities.victim ? { userIdSha256: sha256(identities.victim.userId) } : {}),
      },
    },
    crossAccountAttempt: {
      destinationName: crossDestination.name,
      creationAttempted: crossDestination.creationAttempted,
      requestMayHaveBeenSentWhenTrue: true,
      retriesAllowed: false,
    },
    sandboxes: sandboxTargets.map((target) => ({
      role: target.role,
      accountRole: accountRoleForSandbox(target.role),
      name: target.name,
      tags: target.tags,
      creationAttempted: target.creationAttempted,
      ...(target.expectedSourceSnapshotId
        ? { expectedSourceSnapshotId: target.expectedSourceSnapshotId }
        : {}),
      ...(target.expectedSessionId ? { expectedSessionId: target.expectedSessionId } : {}),
    })),
    snapshots: snapshotTargets.map((target) => ({
      role: target.role,
      accountRole: accountRoleForSnapshot(target.role),
      sourceSandboxName: target.sourceSandboxName,
      creationAttempted: target.creationAttempted,
      ...(target.sourceSessionId ? { sourceSessionId: target.sourceSessionId } : {}),
      ...(target.snapshotId ? { snapshotId: target.snapshotId } : {}),
    })),
    rawCanariesRetained: false,
    tokensRetained: false,
  };
}

function hydrateRecoveryTargets(
  manifest: SnapshotRecoveryManifest,
  sandboxTargets: readonly CleanupTarget[],
  snapshotTargets: readonly SnapshotCleanupTarget[],
): void {
  for (const target of sandboxTargets) {
    const recovered = manifest.sandboxes.find((entry) => entry.role === target.role);
    if (!recovered) throw new Error(`recovery manifest lacked ${target.role}`);
    target.creationAttempted = recovered.creationAttempted;
    if (recovered.expectedSourceSnapshotId) {
      target.expectedSourceSnapshotId = recovered.expectedSourceSnapshotId;
    } else {
      delete target.expectedSourceSnapshotId;
    }
    if (recovered.expectedSessionId) target.expectedSessionId = recovered.expectedSessionId;
    else delete target.expectedSessionId;
  }
  for (const target of snapshotTargets) {
    const recovered = manifest.snapshots.find((entry) => entry.role === target.role);
    if (!recovered) throw new Error(`recovery manifest lacked ${target.role}`);
    target.creationAttempted = recovered.creationAttempted;
    if (recovered.sourceSessionId) target.sourceSessionId = recovered.sourceSessionId;
    else delete target.sourceSessionId;
    if (recovered.snapshotId) target.snapshotId = recovered.snapshotId;
    else delete target.snapshotId;
  }
}

function cleanupTargetEvidence(target: CleanupTarget) {
  return {
    role: target.role,
    name: target.name,
    expectedSourceSnapshotId: target.expectedSourceSnapshotId,
    creationAttempted: target.creationAttempted,
    attributionValidated: target.attributionValidated,
    recovered: target.recovered,
    stopAttempted: target.stopAttempted,
    stopped: target.stopped,
    deleteAttempted: target.deleteAttempted,
    deleted: target.deleted,
    absenceCheckAttempted: target.absenceCheckAttempted,
    absenceObservations: target.absenceObservations,
    delayedAbsenceChecks: target.delayedAbsenceChecks,
    absenceConfirmed: target.absenceConfirmed,
    unsafeMetadataMismatch: target.unsafeMetadataMismatch,
    failures: target.failures,
  };
}

function snapshotCleanupEvidence(target: SnapshotCleanupTarget) {
  return {
    role: target.role,
    sourceSandboxName: target.sourceSandboxName,
    sourceSessionId: target.sourceSessionId,
    snapshotId: target.snapshotId,
    creationAttempted: target.creationAttempted,
    deleteAttempted: target.deleteAttempted,
    deleted: target.deleted,
    absenceCheckAttempted: target.absenceCheckAttempted,
    absenceConfirmed: target.absenceConfirmed,
    directAbsenceCheckAttempted: target.directAbsenceCheckAttempted,
    directAbsenceConfirmed: target.directAbsenceConfirmed,
    directSnapshotIdsChecked: target.directSnapshotIdsChecked,
    absenceObservations: target.absenceObservations,
    delayedAbsenceChecks: target.delayedAbsenceChecks,
    ambiguousCreateAbsenceConfirmed: target.ambiguousCreateAbsenceConfirmed,
    cleanupDeferred: target.cleanupDeferred,
    unsafeMetadataMismatch: target.unsafeMetadataMismatch,
    failures: target.failures,
  };
}

export async function runSnapshotCleanupSequence<
  SandboxState extends { absenceConfirmed: boolean },
  SnapshotState extends { absenceConfirmed: boolean },
>(
  targets: {
    crossDestination: SandboxState;
    victimRestore: SandboxState;
    attackerRestore: SandboxState;
    victimSnapshot: SnapshotState;
    attackerSnapshot: SnapshotState;
    victimSource: SandboxState;
    attackerSource: SandboxState;
  },
  operations: {
    cleanupSandbox: (target: SandboxState) => Promise<void>;
    cleanupSnapshot: (target: SnapshotState, derivativesAbsent: boolean) => Promise<void>;
  },
): Promise<void> {
  await operations.cleanupSandbox(targets.crossDestination);
  await operations.cleanupSandbox(targets.victimRestore);
  await operations.cleanupSandbox(targets.attackerRestore);
  await operations.cleanupSnapshot(
    targets.victimSnapshot,
    targets.crossDestination.absenceConfirmed && targets.victimRestore.absenceConfirmed,
  );
  await operations.cleanupSnapshot(
    targets.attackerSnapshot,
    targets.attackerRestore.absenceConfirmed,
  );
  if (targets.victimSnapshot.absenceConfirmed) {
    await operations.cleanupSandbox(targets.victimSource);
  }
  if (targets.attackerSnapshot.absenceConfirmed) {
    await operations.cleanupSandbox(targets.attackerSource);
  }
}

export async function runSnapshotCleanupOnly(input: {
  intent: SnapshotRunIntent;
  startedAt: string;
  recoveryPath: string;
  evidencePath: string;
  lock: Sbx026LiveLock;
  accounts: { attacker: ExplicitAccountCredentials; victim: ExplicitAccountCredentials };
  attackerFetch: typeof fetch;
  victimFetch: typeof fetch;
  gate: VercelRequestGate;
  sandboxTargets: readonly CleanupTarget[];
  snapshotTargets: readonly SnapshotCleanupTarget[];
  attackerSource: CleanupTarget;
  attackerRestore: CleanupTarget;
  victimSource: CleanupTarget;
  victimRestore: CleanupTarget;
  crossDestination: CleanupTarget;
  attackerSnapshot: SnapshotCleanupTarget;
  victimSnapshot: SnapshotCleanupTarget;
}): Promise<void> {
  let identitiesVerifiedDistinct = false;
  let evidenceWritten = false;
  let recoveryManifestRemoved = false;
  let lockRemoved = false;
  try {
    const attackerIdentity = await verifyAccountIdentity(
      input.accounts.attacker,
      input.attackerFetch,
    );
    const victimIdentity = await verifyAccountIdentity(input.accounts.victim, input.victimFetch);
    identitiesVerifiedDistinct = assertDistinctVerifiedIdentities(
      attackerIdentity,
      victimIdentity,
    );

    const manifest = parseSnapshotRecoveryManifest(
      await readBoundedPrivateJson(input.recoveryPath),
      input.intent,
      input.accounts,
      {
        attacker: sha256(attackerIdentity.userId),
        victim: sha256(victimIdentity.userId),
      },
    );
    hydrateRecoveryTargets(manifest, input.sandboxTargets, input.snapshotTargets);
    const resourceRunStartedAtMs = Date.parse(manifest.startedAt);

    await runSnapshotCleanupSequence(
      {
        crossDestination: input.crossDestination,
        victimRestore: input.victimRestore,
        attackerRestore: input.attackerRestore,
        victimSnapshot: input.victimSnapshot,
        attackerSnapshot: input.attackerSnapshot,
        victimSource: input.victimSource,
        attackerSource: input.attackerSource,
      },
      {
        cleanupSandbox: (target) => cleanupSandbox(target, resourceRunStartedAtMs),
        cleanupSnapshot: (target, derivativesAbsent) =>
          cleanupSnapshot(target, resourceRunStartedAtMs, derivativesAbsent),
      },
    );

    const resourceCleanupPassed = input.sandboxTargets.every((target) =>
      (!target.creationAttempted || target.absenceConfirmed) && !target.unsafeMetadataMismatch
    ) && input.snapshotTargets.every(snapshotCleanupProofSufficient);
    const evidence = {
      schemaVersion: 2,
      testId,
      packet: "snapshot",
      mode: "cleanup-only",
      runId: input.intent.runId,
      suppliedRunIdForcedCleanupOnly: true,
      noReplay: true,
      startedAt: input.startedAt,
      recoveredRunStartedAt: manifest.startedAt,
      completedAt: new Date().toISOString(),
      identities: {
        verifiedDistinct: identitiesVerifiedDistinct,
        attackerEmail: attackerIdentity.email,
        victimEmail: victimIdentity.email,
        attackerUserIdSha256: sha256(attackerIdentity.userId),
        victimUserIdSha256: sha256(victimIdentity.userId),
      },
      operations: {
        ownerScopedCleanupOnly: true,
        controlsCreated: 0,
        crossRestoreRequests: 0,
        crossKnownPathReads: 0,
        commands: 0,
        foreignOperations: 0,
      },
      requestAudit: { totalAttempts: input.gate.records.length, records: input.gate.records },
      cleanup: {
        sandboxes: input.sandboxTargets.map(cleanupTargetEvidence),
        snapshots: input.snapshotTargets.map(snapshotCleanupEvidence),
        resourceCleanupPassed,
        recoveryManifestLoaded: true,
        recoveryManifestRemovalPendingAfterEvidence: resourceCleanupPassed,
        canonicalLiveLockHeldThroughEvidence: true,
      },
      rawCanariesRetained: false,
      rawResponseBodiesRetained: false,
      tokensRetained: false,
    };
    await writeDurablePrivateJson(input.evidencePath, evidence);
    evidenceWritten = true;

    if (resourceCleanupPassed) {
      try {
        await unlink(input.recoveryPath);
        recoveryManifestRemoved = true;
      } catch (error) {
        recoveryManifestRemoved = nodeErrorCode(error) === "ENOENT";
      }
    }
    if (
      identitiesVerifiedDistinct && resourceCleanupPassed && recoveryManifestRemoved &&
      evidenceWritten
    ) {
      await input.lock.release();
      lockRemoved = true;
    }
    const completed = resourceCleanupPassed && recoveryManifestRemoved && lockRemoved;
    console.log(JSON.stringify({
      testId,
      packet: "snapshot",
      mode: "cleanup-only",
      runId: input.intent.runId,
      outcome: completed ? "cleanup-complete" : "cleanup-failed",
      crossRestoreRequests: 0,
      crossKnownPathReads: 0,
      foreignOperations: 0,
      recoveryManifestRemoved,
      canonicalLiveLockRemoved: lockRemoved,
      evidencePath: input.evidencePath,
    }, null, 2));
    process.exitCode = completed ? 0 : 1;
  } catch (error) {
    // Fail closed: the shared lock is deliberately retained for exact recovery.
    throw error;
  }
}

async function main(): Promise<void> {
  const accounts = loadTwoOwnedAccounts();
  const { attacker, victim } = accounts;
  const intent = resolveSnapshotRunIntent(process.env);
  const gate = new VercelRequestGate();
  const attackerFetch = createAccountFetch(attacker, gate);
  const victimFetch = createAccountFetch(victim, gate);
  const runStartedAtMs = Date.now();
  const startedAt = new Date(runStartedAtMs).toISOString();
  const runId = intent.runId;
  const runTag = runId;
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "artifacts");
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const unresolvedRecoveryFiles = (await readdir(artifactsDirectory)).filter((entry) =>
    entry.startsWith(recoveryFilePrefix) &&
    (entry.endsWith(".json") || entry.endsWith(".json.tmp"))
  );
  const recoveryFilename = `${recoveryFilePrefix}${runId}.json`;
  if (!intent.cleanupOnly && unresolvedRecoveryFiles.length > 0) {
    throw new Error(
      "unfinished snapshot recovery manifest exists; set SBX026_RUN_ID to its exact UUID for cleanup-only recovery",
    );
  }
  if (intent.cleanupOnly && unresolvedRecoveryFiles.some((entry) => entry !== recoveryFilename)) {
    throw new Error("cleanup-only mode refused non-matching or temporary snapshot recovery files");
  }
  const recoveryPath = resolve(artifactsDirectory, recoveryFilename);
  const evidencePath = resolve(
    artifactsDirectory,
    intent.cleanupOnly
      ? `SBX-026-snapshot-cleanup-only-${runId}-${randomUUID()}-private.json`
      : `SBX-026-snapshot-auth-${runId}-private.json`,
  );
  const names = snapshotRunNames(runId);
  const attackerCanaryPath = `/vercel/sandbox/sbx026-attacker-${runTag}.txt`;
  const victimCanaryPath = `/vercel/sandbox/sbx026-victim-${runTag}.txt`;
  const attackerCanary = randomBytes(48);
  const victimCanary = randomBytes(48);
  const attackerCanarySha256 = sha256(attackerCanary);
  const victimCanarySha256 = sha256(victimCanary);
  const attackerCanaryByteLength = attackerCanary.length;
  const victimCanaryByteLength = victimCanary.length;
  const syntheticMarkersVerifiedDistinct = attackerCanaryPath !== victimCanaryPath &&
    !attackerCanary.equals(victimCanary) && attackerCanarySha256 !== victimCanarySha256;
  if (!syntheticMarkersVerifiedDistinct) {
    attackerCanary.fill(0);
    victimCanary.fill(0);
    throw new Error("attacker and victim synthetic markers were not distinct");
  }

  const attackerSource = makeCleanupTarget(
    "attacker-source-control",
    attacker,
    attackerFetch,
    names.attackerSource,
    runTag,
  );
  const attackerRestore = makeCleanupTarget(
    "attacker-restore-control",
    attacker,
    attackerFetch,
    names.attackerRestore,
    runTag,
  );
  const victimSource = makeCleanupTarget(
    "victim-source",
    victim,
    victimFetch,
    names.victimSource,
    runTag,
  );
  const victimRestore = makeCleanupTarget(
    "victim-restore-control",
    victim,
    victimFetch,
    names.victimRestore,
    runTag,
  );
  const crossDestination = makeCleanupTarget(
    "cross-destination",
    attacker,
    attackerFetch,
    names.crossDestination,
    runTag,
  );
  const sandboxTargets = [
    attackerSource,
    attackerRestore,
    victimSource,
    victimRestore,
    crossDestination,
  ];
  const attackerSnapshot = makeSnapshotCleanupTarget("attacker-control-snapshot", attackerSource);
  const victimSnapshot = makeSnapshotCleanupTarget("victim-snapshot", victimSource);
  const snapshotTargets = [attackerSnapshot, victimSnapshot];

  let attackerIdentity: VerifiedAccountIdentity | undefined;
  let victimIdentity: VerifiedAccountIdentity | undefined;
  let identitiesVerifiedDistinct = false;
  let recoveryManifestWritten = false;
  let recoveryManifestRemoved = false;
  let activeLockRemoved = false;
  let evidenceWritten = false;
  let attackerSourceRecord: SandboxRecord | undefined;
  let attackerSourceReadback: SandboxRecord | undefined;
  let attackerRestoreRecord: SandboxRecord | undefined;
  let attackerRestoreReadback: SandboxRecord | undefined;
  let attackerSnapshotValidity: SnapshotValidityRecord | undefined;
  let attackerControlRead: ReadProof | undefined;
  let attackerSameAccountRestoreControlPassed = false;
  let victimSourceRecord: SandboxRecord | undefined;
  let victimSourceReadback: SandboxRecord | undefined;
  let victimRestoreRecord: SandboxRecord | undefined;
  let victimRestoreReadback: SandboxRecord | undefined;
  let victimSnapshotInitialValidity: SnapshotValidityRecord | undefined;
  let victimSnapshotPreValidity: SnapshotValidityRecord | undefined;
  let victimSnapshotPostValidity: SnapshotValidityRecord | undefined;
  let victimControlRead: ReadProof | undefined;
  let victimSameAccountRestoreControlPassed = false;
  let ownerSessionsVerifiedDistinct = false;
  let crossRestoreCallAttempts = 0;
  let crossRestoreRequestAttempts = 0;
  let crossKnownPathReadCallAttempts = 0;
  let crossKnownPathReadAttempts = 0;
  let crossRestoreStatus: number | undefined;
  let attackCreateRejected = false;
  let attackRejectionConclusive = false;
  let attackFailure: ApiFailure | undefined;
  let attackerCloneCreated = false;
  let acceptedRestoreRecord: AcceptedRestoreRecord | undefined;
  let attackerCloneReadback: SandboxRecord | undefined;
  let attackerCloneReadbackPassed = false;
  let attackerCloneSourceSnapshotMatched = false;
  let attackerReadAttempted = false;
  let attackerCrossRead: ReadProof | undefined;
  let exactSyntheticCanaryMatched = false;
  let setupError = false;
  let setupFailure: ApiFailure | undefined;
  let cleanupPassed = false;
  let assessment: SnapshotAuthorizationAssessment | undefined;

  const writeRecoveryManifest = async (): Promise<void> => {
    await writeDurablePrivateJson(
      recoveryPath,
      recoveryManifestFor(
        runId,
        startedAt,
        accounts,
        {
          ...(attackerIdentity ? { attacker: attackerIdentity } : {}),
          ...(victimIdentity ? { victim: victimIdentity } : {}),
        },
        sandboxTargets,
        snapshotTargets,
        crossDestination,
      ),
    );
    recoveryManifestWritten = true;
  };

  const liveLock = await acquireSbx026LiveLock({
    scope: "snapshot",
    runId,
    mode: intent.cleanupOnly ? "cleanup-only" : "normal",
  });

  if (intent.cleanupOnly) {
    try {
      await runSnapshotCleanupOnly({
        intent,
        startedAt,
        recoveryPath,
        evidencePath,
        lock: liveLock,
        accounts,
        attackerFetch,
        victimFetch,
        gate,
        sandboxTargets,
        snapshotTargets,
        attackerSource,
        attackerRestore,
        victimSource,
        victimRestore,
        crossDestination,
        attackerSnapshot,
        victimSnapshot,
      });
    } finally {
      attackerCanary.fill(0);
      victimCanary.fill(0);
    }
    return;
  }

  try {
    await writeRecoveryManifest();
  } catch (error) {
    let validRecoveryDescriptor = false;
    try {
      validRecoveryDescriptor = hasValidZeroAttemptSnapshotRecoveryDescriptor(
        await readBoundedPrivateJson(recoveryPath),
        { runId, cleanupOnly: true },
        accounts,
      );
    } catch {
      // The settlement below either removes only the invalid exact files and
      // releases a zero-state lock, or restores a valid cleanup descriptor.
    }

    const initialJournalFailureEvidence = {
      schemaVersion: 2,
      testId,
      packet: "snapshot",
      mode: "initial-journal-failure",
      runId,
      startedAt,
      completedAt: new Date().toISOString(),
      setup: { error: true, failure: apiFailureFromError(error) },
      operations: {
        vercelRequestAttempts: gate.records.length,
        sandboxCreateAttempts: sandboxTargets.filter((target) => target.creationAttempted).length,
        snapshotCreateAttempts: snapshotTargets.filter((target) => target.creationAttempted).length,
        crossRestoreRequests: 0,
        crossKnownPathReads: 0,
      },
      recovery: {
        validZeroAttemptDescriptorFound: validRecoveryDescriptor,
        exactRecoveryPath: recoveryPath,
        canonicalLiveLockHeldThroughEvidence: true,
      },
      rawCanariesRetained: false,
      rawResponseBodiesRetained: false,
      tokensRetained: false,
      assessment: {
        verdict: "error",
        candidate: false,
        controlsPassed: false,
        summary: "Initial recovery journal persistence failed before any Vercel request.",
      },
    };
    let errorEvidenceWritten = false;
    const canonicalFallbackEvidencePath = resolve(
      dirname(SBX026_LIVE_LOCK_PATH),
      `SBX-026-snapshot-initial-journal-error-${runId}-private.json`,
    );
    for (const errorEvidencePath of new Set([evidencePath, canonicalFallbackEvidencePath])) {
      try {
        await writeDurablePrivateJson(errorEvidencePath, initialJournalFailureEvidence);
        errorEvidenceWritten = true;
        break;
      } catch {
        // A valid descriptor is restored below before retaining the shared lock.
      }
    }

    const zeroVercelState = gate.records.length === 0 &&
      sandboxTargets.every((target) => !target.creationAttempted) &&
      snapshotTargets.every((target) => !target.creationAttempted);
    try {
      await settleInitialSnapshotJournalFailure({
        validRecoveryDescriptor,
        zeroVercelState,
        errorEvidenceWritten,
        lock: liveLock,
      }, {
        clearInvalidRecoveryFiles: async () => {
          try {
            await removeExactRecoveryJournalFiles(recoveryPath);
            return true;
          } catch {
            return false;
          }
        },
        restoreValidRecoveryDescriptor: async () => {
          try {
            await unlink(`${recoveryPath}.tmp`);
          } catch (cleanupError) {
            if (nodeErrorCode(cleanupError) !== "ENOENT") throw cleanupError;
          }
          await writeRecoveryManifest();
        },
      });
    } catch (settlementError) {
      attackerCanary.fill(0);
      victimCanary.fill(0);
      throw new AggregateError(
        [error, settlementError],
        "initial recovery journal failed and safe lock settlement did not complete",
      );
    }
    attackerCanary.fill(0);
    victimCanary.fill(0);
    throw error;
  }

  try {
    attackerIdentity = await verifyAccountIdentity(attacker, attackerFetch);
    victimIdentity = await verifyAccountIdentity(victim, victimFetch);
    identitiesVerifiedDistinct = assertDistinctVerifiedIdentities(attackerIdentity, victimIdentity);
    await writeRecoveryManifest();

    const attackerSourceCreated = await createTrackedSandbox(
      attackerSource,
      runStartedAtMs,
      writeRecoveryManifest,
    );
    attackerSourceRecord = attackerSourceCreated.record;
    attackerSourceReadback = await independentSandboxReadback(
      attackerSource,
      runStartedAtMs,
      attackerSourceRecord.sessionId,
    );
    await attackerSourceCreated.sandbox.writeFiles(
      [{ path: attackerCanaryPath, content: attackerCanary, mode: 0o600 }],
      { signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS) },
    );
    attackerSnapshot.sourceSessionId = attackerSourceRecord.sessionId;
    attackerSnapshot.creationAttempted = true;
    await writeRecoveryManifest();
    const attackerSnapshotHandle = await attackerSourceCreated.sandbox.snapshot({
      expiration: snapshotExpirationMs,
      signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
    });
    attackerSource.stopNeeded = false;
    validateSnapshot(
      attackerSnapshotHandle,
      attackerSnapshotHandle.snapshotId,
      attackerSourceRecord.sessionId,
      runStartedAtMs,
    );
    attackerSnapshot.snapshot = attackerSnapshotHandle;
    attackerSnapshot.snapshotId = attackerSnapshotHandle.snapshotId;
    attackerSnapshotValidity = await getValidSnapshot(attackerSnapshot, runStartedAtMs);
    await writeRecoveryManifest();

    const attackerRestoreCreated = await createTrackedSandbox(
      attackerRestore,
      runStartedAtMs,
      writeRecoveryManifest,
      attackerSnapshotHandle.snapshotId,
    );
    attackerRestoreRecord = attackerRestoreCreated.record;
    attackerRestoreReadback = await independentSandboxReadback(
      attackerRestore,
      runStartedAtMs,
      attackerRestoreRecord.sessionId,
      attackerSnapshotHandle.snapshotId,
    );
    attackerControlRead = await oneShotKnownPathRead(
      attacker,
      attackerFetch,
      attackerRestoreRecord.sessionId,
      attackerCanaryPath,
      attackerCanary,
    );
    const attackerControlContentPassed = attackerControlRead.exactCanaryMatched &&
      attackerRestoreRecord.sourceSnapshotMatched === true &&
      attackerRestoreReadback.sourceSnapshotMatched === true;
    await cleanupSandbox(attackerRestore, runStartedAtMs);
    await cleanupSnapshot(attackerSnapshot, runStartedAtMs, attackerRestore.absenceConfirmed);
    if (attackerSnapshot.absenceConfirmed) await cleanupSandbox(attackerSource, runStartedAtMs);
    attackerSameAccountRestoreControlPassed = attackerControlContentPassed &&
      attackerRestore.absenceConfirmed && attackerSnapshot.absenceConfirmed &&
      attackerSource.absenceConfirmed;
    if (!attackerSameAccountRestoreControlPassed) {
      throw new Error("attacker same-account snapshot restore or cleanup control failed");
    }

    const victimSourceCreated = await createTrackedSandbox(
      victimSource,
      runStartedAtMs,
      writeRecoveryManifest,
    );
    victimSourceRecord = victimSourceCreated.record;
    victimSourceReadback = await independentSandboxReadback(
      victimSource,
      runStartedAtMs,
      victimSourceRecord.sessionId,
    );
    await victimSourceCreated.sandbox.writeFiles(
      [{ path: victimCanaryPath, content: victimCanary, mode: 0o600 }],
      { signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS) },
    );
    victimSnapshot.sourceSessionId = victimSourceRecord.sessionId;
    victimSnapshot.creationAttempted = true;
    await writeRecoveryManifest();
    const victimSnapshotHandle = await victimSourceCreated.sandbox.snapshot({
      expiration: snapshotExpirationMs,
      signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
    });
    victimSource.stopNeeded = false;
    victimSnapshotInitialValidity = validateSnapshot(
      victimSnapshotHandle,
      victimSnapshotHandle.snapshotId,
      victimSourceRecord.sessionId,
      runStartedAtMs,
    );
    if (victimSnapshotHandle.snapshotId === attackerSnapshotValidity.snapshotId) {
      throw new Error("attacker and victim snapshot IDs were not distinct");
    }
    victimSnapshot.snapshot = victimSnapshotHandle;
    victimSnapshot.snapshotId = victimSnapshotHandle.snapshotId;
    await writeRecoveryManifest();

    const victimRestoreCreated = await createTrackedSandbox(
      victimRestore,
      runStartedAtMs,
      writeRecoveryManifest,
      victimSnapshotHandle.snapshotId,
    );
    victimRestoreRecord = victimRestoreCreated.record;
    const ownerSessionIds = [
      attackerSourceRecord.sessionId,
      attackerRestoreRecord.sessionId,
      victimSourceRecord.sessionId,
      victimRestoreRecord.sessionId,
    ];
    ownerSessionsVerifiedDistinct = new Set(ownerSessionIds).size === ownerSessionIds.length;
    if (!ownerSessionsVerifiedDistinct) {
      throw new Error("attacker and victim control session IDs were not all distinct");
    }
    victimRestoreReadback = await independentSandboxReadback(
      victimRestore,
      runStartedAtMs,
      victimRestoreRecord.sessionId,
      victimSnapshotHandle.snapshotId,
    );
    victimControlRead = await oneShotKnownPathRead(
      victim,
      victimFetch,
      victimRestoreRecord.sessionId,
      victimCanaryPath,
      victimCanary,
    );
    const victimControlContentPassed = victimControlRead.exactCanaryMatched &&
      victimRestoreRecord.sourceSnapshotMatched === true &&
      victimRestoreReadback.sourceSnapshotMatched === true;
    await cleanupSandbox(victimRestore, runStartedAtMs);
    victimSameAccountRestoreControlPassed = victimControlContentPassed &&
      victimRestore.absenceConfirmed;
    if (!victimSameAccountRestoreControlPassed) {
      throw new Error("victim same-account snapshot restore or cleanup control failed");
    }

    victimSnapshotPreValidity = await getValidSnapshot(victimSnapshot, runStartedAtMs);

    crossDestination.creationAttempted = true;
    crossDestination.expectedSourceSnapshotId = victimSnapshotHandle.snapshotId;
    await writeRecoveryManifest();
    crossRestoreCallAttempts += 1;
    const requestCountBeforeRestore = gate.records.length;
    let restoreTransportCountCaptured = false;
    try {
      const response = await oneShotSandboxRequest(
        attacker,
        attackerFetch,
        "/v3/sandboxes",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            projectId: attacker.projectId,
            name: crossDestination.name,
            source: { type: "snapshot", snapshotId: victimSnapshotHandle.snapshotId },
            ports: [],
            persistent: false,
            timeout: sandboxTimeoutMs,
            networkPolicy: { mode: "deny-all" },
            tags: crossDestination.tags,
          }),
          signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
        },
      );
      crossRestoreRequestAttempts += gate.records.length - requestCountBeforeRestore;
      restoreTransportCountCaptured = true;
      crossRestoreStatus = response.status;
      if (!response.ok) {
        attackCreateRejected = true;
        attackFailure = await apiFailureFromResponse(response);
        attackRejectionConclusive = conclusiveAuthorizationRejection(attackFailure);
      } else {
        attackerCloneCreated = true;
        const payload = await parseSuccessfulJson(response);
        acceptedRestoreRecord = parseAcceptedRestoreResponse(payload, {
          name: crossDestination.name,
          snapshotId: victimSnapshotHandle.snapshotId,
          tags: crossDestination.tags,
          earliestCreatedAtMs: runStartedAtMs - timestampSkewMs,
          latestCreatedAtMs: Date.now() + timestampSkewMs,
        });
        crossDestination.expectedSessionId = acceptedRestoreRecord.sessionId;
        await writeRecoveryManifest();
        const crossHandle = await Sandbox.get({
          ...sdkScope(attacker, attackerFetch),
          name: crossDestination.name,
          resume: false,
          signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
        });
        attackerCloneReadback = sandboxRecord(
          crossHandle,
          crossDestination,
          runStartedAtMs,
          victimSnapshotHandle.snapshotId,
        );
        crossDestination.sandbox = crossHandle;
        crossDestination.attributionValidated = true;
        crossDestination.stopNeeded = true;
        attackerCloneReadbackPassed = attackerCloneReadback.sessionId ===
          acceptedRestoreRecord.sessionId &&
          !ownerSessionIds.includes(attackerCloneReadback.sessionId);
        attackerCloneSourceSnapshotMatched =
          acceptedRestoreRecord.sourceSnapshotMatched &&
          attackerCloneReadback.sourceSnapshotMatched === true;
        if (attackerCloneReadbackPassed && attackerCloneSourceSnapshotMatched) {
          crossKnownPathReadCallAttempts += 1;
          attackerReadAttempted = true;
          const requestCountBeforeRead = gate.records.length;
          attackerCrossRead = await oneShotKnownPathRead(
            attacker,
            attackerFetch,
            attackerCloneReadback.sessionId,
            victimCanaryPath,
            victimCanary,
          );
          crossKnownPathReadAttempts += gate.records.length - requestCountBeforeRead;
          exactSyntheticCanaryMatched = attackerCrossRead.exactCanaryMatched;
        }
      }
    } catch (error) {
      attackFailure = apiFailureFromError(error);
    } finally {
      if (!restoreTransportCountCaptured) {
        crossRestoreRequestAttempts += gate.records.length - requestCountBeforeRestore;
      }
    }

    try {
      victimSnapshotPostValidity = await getValidSnapshot(victimSnapshot, runStartedAtMs);
    } catch {
      victimSnapshotPostValidity = undefined;
    }
  } catch (error) {
    setupError = true;
    setupFailure = apiFailureFromError(error);
  } finally {
    attackerCanary.fill(0);
    victimCanary.fill(0);

    await runSnapshotCleanupSequence(
      {
        crossDestination,
        victimRestore,
        attackerRestore,
        victimSnapshot,
        attackerSnapshot,
        victimSource,
        attackerSource,
      },
      {
        cleanupSandbox: (target) => cleanupSandbox(target, runStartedAtMs),
        cleanupSnapshot: (target, derivativesAbsent) =>
          cleanupSnapshot(target, runStartedAtMs, derivativesAbsent),
      },
    );

    const resourceCleanupPassed = sandboxTargets.every((target) =>
      (!target.creationAttempted || target.absenceConfirmed) && !target.unsafeMetadataMismatch
    ) && snapshotTargets.every(snapshotCleanupProofSufficient);

    const assessmentForCleanup = (cleanupState: boolean): SnapshotAuthorizationAssessment =>
      assessSnapshotAuthorization({
        setupError,
        cleanupPassed: cleanupState,
        identitiesVerifiedDistinct,
        ownerSessionsVerifiedDistinct,
        attackerSameAccountRestoreControlPassed,
        victimSameAccountRestoreControlPassed,
        victimSnapshotValidBeforeAttack: victimSnapshotPreValidity !== undefined,
        victimSnapshotValidAfterAttack: victimSnapshotPostValidity !== undefined,
        crossRestoreCallAttempts,
        crossRestoreRequestAttempts,
        crossKnownPathReadCallAttempts,
        crossKnownPathReadAttempts,
        attackCreateRejected,
        attackRejectionConclusive,
        crossDestinationObserved: attackerCloneCreated || crossDestination.recovered ||
          crossDestination.attributionValidated,
        attackerCloneCreated,
        attackerCloneReadbackPassed,
        attackerCloneSourceSnapshotMatched,
        attackerReadAttempted,
        exactSyntheticCanaryMatched,
      });

    // This full record is staged, published, and directory-synced while the canonical
    // lock exists. A pass/candidate is deliberately represented as pending in the file;
    // the controller emits the final verdict only after exact shared-lock release.
    cleanupPassed = resourceCleanupPassed;
    assessment = assessmentForCleanup(cleanupPassed);

    let evidence: Record<string, unknown> = {
      schemaVersion: 2,
      testId,
      packet: "snapshot",
      mode: "test",
      runId,
      startedAt,
      completedAt: new Date().toISOString(),
      sdk: "@vercel/sandbox@3.0.0",
      safeguards: {
        noEnumeration: true,
        onlyExactOwnedNamesListed: true,
        freshInternalRunId: true,
        unresolvedRecoveryManifestGatePassed: true,
        maximumCrossAccountKnownPathReads: 1,
        rawCanariesRetained: false,
        rawResponseBodiesRetained: false,
        tokensRetained: false,
        minimumVercelRequestIntervalMs: MINIMUM_VERCEL_REQUEST_INTERVAL_MS,
      },
      accounts: {
        attacker: {
          email: attackerIdentity?.email,
          userIdSha256: attackerIdentity ? sha256(attackerIdentity.userId) : undefined,
          teamId: attacker.teamId,
          projectId: attacker.projectId,
          identityExactMatch: attackerIdentity?.exactMatch ?? false,
        },
        victim: {
          email: victimIdentity?.email,
          userIdSha256: victimIdentity ? sha256(victimIdentity.userId) : undefined,
          teamId: victim.teamId,
          projectId: victim.projectId,
          identityExactMatch: victimIdentity?.exactMatch ?? false,
        },
        verifiedDistinct: identitiesVerifiedDistinct,
        noCrossMembershipManuallyConfirmed: true,
      },
      canaries: {
        attackerControl: {
          path: attackerCanaryPath,
          sha256: attackerCanarySha256,
          byteLength: attackerCanaryByteLength,
          rawValueRetained: false,
        },
        victim: {
          path: victimCanaryPath,
          sha256: victimCanarySha256,
          byteLength: victimCanaryByteLength,
          rawValueRetained: false,
        },
      },
      controls: {
        identitiesVerifiedDistinct,
        syntheticMarkersVerifiedDistinct,
        ownerSessionsVerifiedDistinct,
        attackerSameAccountRestoreControlPassed,
        attacker: {
          source: attackerSourceRecord,
          sourceReadback: attackerSourceReadback,
          snapshot: attackerSnapshotValidity,
          restore: attackerRestoreRecord,
          restoreReadback: attackerRestoreReadback,
          exactOneShotRead: attackerControlRead,
        },
        victimSameAccountRestoreControlPassed,
        victim: {
          source: victimSourceRecord,
          sourceReadback: victimSourceReadback,
          initialSnapshot: victimSnapshotInitialValidity,
          restore: victimRestoreRecord,
          restoreReadback: victimRestoreReadback,
          exactOneShotRead: victimControlRead,
          validBeforeAttack: victimSnapshotPreValidity,
          validAfterAttack: victimSnapshotPostValidity,
        },
      },
      attack: {
        restoreCallAttempts: crossRestoreCallAttempts,
        restoreRequestAttempts: crossRestoreRequestAttempts,
        restoreStatus: crossRestoreStatus,
        createRejected: attackCreateRejected,
        rejectionConclusive: attackRejectionConclusive,
        destinationObserved: attackerCloneCreated || crossDestination.recovered ||
          crossDestination.attributionValidated,
        failure: attackFailure,
        cloneCreated: attackerCloneCreated,
        acceptedRestore: acceptedRestoreRecord,
        independentCloneReadback: attackerCloneReadback,
        cloneReadbackPassed: attackerCloneReadbackPassed,
        sourceSnapshotMatched: attackerCloneSourceSnapshotMatched,
        knownPathReadCallAttempts: crossKnownPathReadCallAttempts,
        knownPathReadAttempts: crossKnownPathReadAttempts,
        readAttempted: attackerReadAttempted,
        read: attackerCrossRead,
        exactSyntheticCanaryMatched,
        rawBodyRetained: false,
      },
      setup: { error: setupError, failure: setupFailure },
      requestAudit: {
        totalAttempts: gate.records.length,
        records: gate.records,
      },
      cleanup: {
        sandboxes: sandboxTargets.map(cleanupTargetEvidence),
        snapshots: snapshotTargets.map(snapshotCleanupEvidence),
        resourcesPassed: resourceCleanupPassed,
        recoveryManifestWritten,
        recoveryManifestRemovalPendingAfterEvidence:
          snapshotRecoveryManifestRemovalAuthorized({
            identitiesVerifiedDistinct,
            resourceCleanupPassed,
            recoveryManifestWritten,
          }),
        canonicalLiveLockHeldThroughEvidence: true,
        canonicalLiveLockRemovalRequiredForPublication: true,
        resourceCleanupPassedAtEvidenceTime: cleanupPassed,
      },
      publication: {
        exactFinalPath: evidencePath,
        stagedUnderCanonicalLiveLock: true,
        finalPathSyncedBeforeCanonicalLiveLockRelease: true,
        persistedAssessmentIsReleaseNeutral: true,
        finalVerdictEmittedOnlyAfterCanonicalLiveLockRelease: true,
      },
      assessment: snapshotEvidenceAssessmentForPublication(assessment),
    };

    const stagedEvidencePath = `${evidencePath}.staged-${liveLock.metadata.lease}`;
    try {
      await writeDurablePrivateJson(stagedEvidencePath, evidence);
      evidenceWritten = true;

      recoveryManifestRemoved = await removeSnapshotRecoveryManifestIfAuthorized({
        identitiesVerifiedDistinct,
        resourceCleanupPassed,
        recoveryManifestWritten,
      }, () => removeExactRecoveryJournalFiles(recoveryPath));
      const cleanupReadyForLockRelease = resourceCleanupPassed &&
        (!recoveryManifestWritten || recoveryManifestRemoved);
      assessment = assessmentForCleanup(cleanupReadyForLockRelease);
      evidence = {
        ...evidence,
        cleanup: {
          ...(evidence.cleanup as Record<string, unknown>),
          recoveryManifestRemoved,
          cleanupReadyForLockRelease,
        },
        assessment: snapshotEvidenceAssessmentForPublication(assessment),
      };
      await writeDurablePrivateJson(stagedEvidencePath, evidence);

      activeLockRemoved = await publishSnapshotEvidenceBeforeRelease({
        stagedEvidencePath,
        evidencePath,
        lock: liveLock,
        releaseAuthorized:
          identitiesVerifiedDistinct && cleanupReadyForLockRelease && evidenceWritten,
      });
      cleanupPassed = snapshotFinalizationPassed({
        resourceCleanupPassed,
        recoveryManifestWritten,
        recoveryManifestRemoved,
        canonicalLiveLockRemoved: activeLockRemoved,
      });
    } catch (error) {
      cleanupPassed = false;
      assessment = assessmentForCleanup(false);
      let recoveryDescriptorRestored = recoveryManifestWritten && !recoveryManifestRemoved;
      let finalizationFailure: unknown = error;
      if (recoveryManifestWritten && recoveryManifestRemoved) {
        try {
          await writeRecoveryManifest();
          recoveryManifestRemoved = false;
          recoveryDescriptorRestored = true;
        } catch (recoveryError) {
          recoveryDescriptorRestored = false;
          finalizationFailure = new AggregateError(
            [error, recoveryError],
            "evidence finalization failed and the recovery descriptor could not be restored",
          );
        }
      }
      evidence = {
        ...evidence,
        cleanup: {
          ...(evidence.cleanup as Record<string, unknown>),
          canonicalLiveLockRemoved: activeLockRemoved,
          recoveryManifestWritten,
          recoveryManifestRemoved,
          recoveryDescriptorRestored,
          passed: false,
        },
        publication: {
          ...(evidence.publication as Record<string, unknown>),
          finalizationFailed: true,
          failure: apiFailureFromError(finalizationFailure),
        },
        assessment,
      };
      try {
        await writeDurablePrivateJson(stagedEvidencePath, evidence);
        activeLockRemoved = await publishSnapshotEvidenceBeforeRelease({
          stagedEvidencePath,
          evidencePath,
          lock: liveLock,
          releaseAuthorized:
            identitiesVerifiedDistinct && resourceCleanupPassed && recoveryManifestRemoved &&
            !recoveryDescriptorRestored,
        });
      } catch (errorPublicationFailure) {
        if (recoveryManifestWritten && recoveryManifestRemoved) {
          try {
            await writeRecoveryManifest();
            recoveryManifestRemoved = false;
          } catch {
            // Keep the exact lock even if the local filesystem cannot currently
            // restore the descriptor; never overlap an uncertain finalization.
          }
        }
        // Keep any safely staged error record and the canonical lock for inspection.
        finalizationFailure = new AggregateError(
          [finalizationFailure, errorPublicationFailure],
          "evidence error publication or safe lock settlement failed",
        );
      }
      // release() restores or preserves any exact claim on failure. Otherwise retain
      // the shared lock so no other SBX-026 packet can overlap unresolved recovery.
      throw finalizationFailure;
    }

    console.log(JSON.stringify({
      testId,
      runId,
      verdict: cleanupPassed ? assessment.verdict : "error",
      summary: assessment.summary,
      crossRestoreCallAttempts,
      crossRestoreRequestAttempts,
      crossKnownPathReadCallAttempts,
      crossKnownPathReadAttempts,
      exactSyntheticCanaryMatched,
      cleanupPassed,
      evidencePath,
      recoveryPath: recoveryManifestWritten && !recoveryManifestRemoved
        ? recoveryPath
        : undefined,
      activeLockPath: !activeLockRemoved ? SBX026_LIVE_LOCK_PATH : undefined,
    }, null, 2));
  }

  process.exitCode = !cleanupPassed
    ? 1
    : assessment?.verdict === "candidate"
    ? 2
    : assessment?.verdict === "pass"
    ? 0
    : assessment?.verdict === "indeterminate"
    ? 3
    : 1;
}

const executedPath = process.argv[1] ? resolve(process.argv[1]) : undefined;
if (executedPath === fileURLToPath(import.meta.url)) {
  main().catch((error: unknown) => {
    console.error(JSON.stringify({ testId, fatal: true, failure: apiFailureFromError(error) }));
    process.exitCode = 1;
  });
}
