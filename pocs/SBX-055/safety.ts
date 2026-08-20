import { randomUUID } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  acquireSbx055LiveLock,
  inspectSbx055PendingTransaction,
  recoverSbx055InterruptedAcquire,
  rollbackSbx055OrphanedNormalLock,
  rollbackSbx055InterruptedRelease,
  resumeSbx055InterruptedRelease,
  settleSbx055RemovalClaims,
  type Sbx055HeldLock as Sbx055AtomicLiveLock,
} from "./live-lock.js";

export const SBX055_TEST_ID = "SBX-055-STALE-INTERACTIVE-RESUME" as const;
export const SBX055_ALIAS = "swve@wearehackerone.com" as const;
export const SBX055_TEAM = "team_n98ERpVwV7HqmWRudAyK8sXQ" as const;
export const SBX055_PROJECT = "prj_CyyVykdN06Nrkla6KidZcecLgbCa" as const;
export const SBX055_SCOPE_CONFIRMATION =
  "I_AUTHORIZE_ONE_BOUNDED_SBX055_STALE_INTERACTIVE_RESUME_TEST" as const;
export const SBX055_SANDBOX_TIMEOUT_MS = 240_000 as const;
export const SBX055_SNAPSHOT_EXPIRATION_MS = 300_000 as const;
export const SBX055_CREATE_REQUEST_TIMEOUT_MS = 45_000 as const;
export const SBX055_UNKNOWN_CREATE_SETTLEMENT_MS =
  SBX055_CREATE_REQUEST_TIMEOUT_MS + SBX055_SANDBOX_TIMEOUT_MS + 30_000;
export const SBX055_ARTIFACTS_DIRECTORY = fileURLToPath(new URL("../../artifacts", import.meta.url));
export const SBX055_LIVE_LOCK = resolve(SBX055_ARTIFACTS_DIRECTORY, "SBX-055-live-active.lock");
export const SBX055_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SESSION_ID = /^sbx_[A-Za-z0-9_-]{8,192}$/u;
const SNAPSHOT_ID = /^snap_[A-Za-z0-9_-]{8,192}$/u;
const LOCAL_TLS_TRUST_ENVIRONMENT_NAMES = [
  "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF", "OPENSSL_MODULES",
  "SSL_CERT_DIR", "SSL_CERT_FILE",
] as const;

export type Sbx055Phase =
  | "pre-create" | "s1-running" | "s1-fixtures-ready" | "stale-token-issued"
  | "s1-stopped" | "s2-running" | "attack-complete" | "cleanup" | "complete";

export interface Sbx055Config {
  token: string;
  teamId: typeof SBX055_TEAM;
  projectId: typeof SBX055_PROJECT;
  expectedAlias: typeof SBX055_ALIAS;
  manualAliasConfirmation?: string;
  recoveryRunId?: string;
}

export interface Sbx055RecoveryJournal {
  schemaVersion: 1;
  testId: typeof SBX055_TEST_ID;
  runId: string;
  sandboxName: string;
  tags: Record<string, string>;
  marker1Path: string;
  marker2Path: string;
  persistent: true;
  timeoutMs: typeof SBX055_SANDBOX_TIMEOUT_MS;
  startedAt: string;
  updatedAt: string;
  phase: Sbx055Phase;
  createAttemptedAt?: string;
  createRequestSettledAt?: string;
  session1Id?: string;
  snapshotId?: string;
  session2Id?: string;
  stopAttempted: boolean;
  stopped: boolean;
  resumeAttempted: boolean;
  cleanupStopAttempted: boolean;
  cleanupStopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  sandboxAbsenceChecks: number;
  prefixListAbsent: boolean;
  snapshotsObserved: string[];
  snapshotDeleteIntents: string[];
  snapshotsDeleted: string[];
  snapshotAbsenceChecks: number;
  completed: boolean;
  rawCapabilitiesRetained: false;
}

export interface Sbx055HeldLock {
  liveLock: Sbx055AtomicLiveLock;
  lockPath: string;
  journalPath: string;
  lockMode: number;
  journalMode: number;
  runId: string;
}

export type Sbx055RecoveryDispatchOutcome =
  | "continue-journal-recovery"
  | "release-finalization-complete"
  | "zero-external-state-acquire-rolled-back";

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

export function requireStrictSbx055Environment(environment: NodeJS.ProcessEnv = process.env): void {
  if (environment.NODE_TLS_REJECT_UNAUTHORIZED === "0" ||
      (environment.NODE_OPTIONS !== undefined && environment.NODE_OPTIONS.trim() !== "") ||
      LOCAL_TLS_TRUST_ENVIRONMENT_NAMES.some((name) => environment[name] !== undefined)) {
    throw new Error("SBX-055 refuses local TLS trust overrides or runtime injection");
  }
}

export function loadSbx055Config(environment: NodeJS.ProcessEnv = process.env): Sbx055Config {
  requireStrictSbx055Environment(environment);
  if (environment.SBX055_SCOPE_CONFIRMATION !== SBX055_SCOPE_CONFIRMATION ||
      environment.VERCEL_TEAM_ID !== SBX055_TEAM ||
      environment.VERCEL_PROJECT_ID !== SBX055_PROJECT ||
      environment.SBX055_EXPECTED_ALIAS !== SBX055_ALIAS) {
    throw new Error("SBX-055 scope or exact eligible alias/team/project attestation failed");
  }
  const token = required(environment, "VERCEL_TOKEN");
  if (token.length < 20 || token.length > 4_096 || /[\s\0]/u.test(token) || token.split(".").length === 3) {
    throw new Error("SBX-055 requires one bounded opaque non-JWT Vercel PAT");
  }
  const recoveryRunId = environment.SBX055_RECOVERY_RUN_ID;
  if (recoveryRunId !== undefined && !SBX055_UUID.test(recoveryRunId)) {
    throw new Error("SBX055_RECOVERY_RUN_ID must be one canonical UUIDv4");
  }
  return {
    token,
    teamId: SBX055_TEAM,
    projectId: SBX055_PROJECT,
    expectedAlias: SBX055_ALIAS,
    ...(environment.SBX055_ALIAS_EMAIL_CONFIRMATION
      ? { manualAliasConfirmation: environment.SBX055_ALIAS_EMAIL_CONFIRMATION }
      : {}),
    ...(recoveryRunId ? { recoveryRunId } : {}),
  };
}

function exactKeys(value: object, requiredKeys: readonly string[], optionalKeys: readonly string[] = []): boolean {
  const actual = Object.keys(value);
  const permitted = new Set([...requiredKeys, ...optionalKeys]);
  return requiredKeys.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    actual.every((key) => permitted.has(key)) &&
    actual.length === requiredKeys.length + optionalKeys.filter((key) =>
      Object.prototype.hasOwnProperty.call(value, key)).length;
}

function exactRecord(actual: unknown, expected: Record<string, string>): boolean {
  if (actual === null || typeof actual !== "object" || Array.isArray(actual)) return false;
  const record = actual as Record<string, unknown>;
  const keys = Object.keys(expected);
  return Object.keys(record).length === keys.length && keys.every((key) => record[key] === expected[key]);
}

function timestamp(value: unknown): value is string {
  if (typeof value !== "string" || value.length !== 24) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

export function sbx055SandboxName(runId: string): string {
  if (!SBX055_UUID.test(runId)) throw new Error("SBX-055 name requires a canonical UUIDv4");
  return `sbx-055-${runId}`;
}

export function sbx055Tags(runId: string): Record<string, string> {
  return { harness: "vsc", test: SBX055_TEST_ID, run: runId };
}

export function sbx055MarkerPath(role: "s1" | "s2", runId: string): string {
  if (!SBX055_UUID.test(runId)) throw new Error("SBX-055 marker path requires a canonical UUIDv4");
  return `/tmp/sbx-055/${role}-${runId}.marker`;
}

export function sbx055JournalPath(runId: string): string {
  if (!SBX055_UUID.test(runId)) throw new Error("SBX-055 journal path requires a canonical UUIDv4");
  return resolve(SBX055_ARTIFACTS_DIRECTORY, `SBX-055-${runId}-recovery.json`);
}

export function sbx055ArtifactPath(runId: string): string {
  if (!SBX055_UUID.test(runId)) throw new Error("SBX-055 artifact path requires a canonical UUIDv4");
  return resolve(SBX055_ARTIFACTS_DIRECTORY, `SBX-055-${runId}-private.json`);
}

export function sbx055RecoveryArtifactPath(runId: string, attemptId: string): string {
  if (!SBX055_UUID.test(runId) || !SBX055_UUID.test(attemptId)) {
    throw new Error("SBX-055 recovery artifact path requires two canonical UUIDv4 values");
  }
  return resolve(SBX055_ARTIFACTS_DIRECTORY,
    `SBX-055-${runId}-recovery-${attemptId}-private.json`);
}

export function createSbx055Journal(now = new Date(), suppliedRunId?: string): Sbx055RecoveryJournal {
  const runId = suppliedRunId ?? randomUUID();
  if (!SBX055_UUID.test(runId)) throw new Error("SBX-055 run ID was not canonical");
  const at = now.toISOString();
  return {
    schemaVersion: 1,
    testId: SBX055_TEST_ID,
    runId,
    sandboxName: sbx055SandboxName(runId),
    tags: sbx055Tags(runId),
    marker1Path: sbx055MarkerPath("s1", runId),
    marker2Path: sbx055MarkerPath("s2", runId),
    persistent: true,
    timeoutMs: SBX055_SANDBOX_TIMEOUT_MS,
    startedAt: at,
    updatedAt: at,
    phase: "pre-create",
    stopAttempted: false,
    stopped: false,
    resumeAttempted: false,
    cleanupStopAttempted: false,
    cleanupStopped: false,
    deleteAttempted: false,
    deleted: false,
    sandboxAbsenceChecks: 0,
    prefixListAbsent: false,
    snapshotsObserved: [],
    snapshotDeleteIntents: [],
    snapshotsDeleted: [],
    snapshotAbsenceChecks: 0,
    completed: false,
    rawCapabilitiesRetained: false,
  };
}

export function parseSbx055Journal(value: unknown): Sbx055RecoveryJournal {
  if (value === null || typeof value !== "object" || Array.isArray(value) || !exactKeys(value, [
    "schemaVersion", "testId", "runId", "sandboxName", "tags", "marker1Path", "marker2Path",
    "persistent", "timeoutMs", "startedAt", "updatedAt", "phase", "stopAttempted", "stopped",
    "resumeAttempted", "cleanupStopAttempted", "cleanupStopped", "deleteAttempted", "deleted",
    "sandboxAbsenceChecks", "prefixListAbsent", "snapshotsObserved", "snapshotDeleteIntents",
    "snapshotsDeleted",
    "snapshotAbsenceChecks", "completed", "rawCapabilitiesRetained",
  ], ["createAttemptedAt", "createRequestSettledAt", "session1Id", "snapshotId", "session2Id"])) {
    throw new Error("SBX-055 recovery journal fields were not exact");
  }
  const record = value as Record<string, unknown>;
  const phases: readonly Sbx055Phase[] = ["pre-create", "s1-running", "s1-fixtures-ready",
    "stale-token-issued", "s1-stopped", "s2-running", "attack-complete", "cleanup", "complete"];
  const strings = (entry: unknown, pattern: RegExp): entry is string[] =>
    Array.isArray(entry) && new Set(entry).size === entry.length &&
    entry.every((item) => typeof item === "string" && pattern.test(item));
  if (record.schemaVersion !== 1 || record.testId !== SBX055_TEST_ID ||
      typeof record.runId !== "string" || !SBX055_UUID.test(record.runId) ||
      record.sandboxName !== sbx055SandboxName(record.runId) ||
      !exactRecord(record.tags, sbx055Tags(record.runId)) ||
      record.marker1Path !== sbx055MarkerPath("s1", record.runId) ||
      record.marker2Path !== sbx055MarkerPath("s2", record.runId) ||
      record.persistent !== true || record.timeoutMs !== SBX055_SANDBOX_TIMEOUT_MS ||
      !timestamp(record.startedAt) || !timestamp(record.updatedAt) ||
      Date.parse(record.updatedAt) < Date.parse(record.startedAt) ||
      !phases.includes(record.phase as Sbx055Phase) ||
      !(record.createAttemptedAt === undefined || timestamp(record.createAttemptedAt)) ||
      !(record.createRequestSettledAt === undefined || timestamp(record.createRequestSettledAt)) ||
      (record.createRequestSettledAt !== undefined && (record.createAttemptedAt === undefined ||
        Date.parse(record.createRequestSettledAt as string) < Date.parse(record.createAttemptedAt as string))) ||
      !(record.session1Id === undefined ||
        (typeof record.session1Id === "string" && SESSION_ID.test(record.session1Id))) ||
      !(record.session2Id === undefined ||
        (typeof record.session2Id === "string" && SESSION_ID.test(record.session2Id))) ||
      (record.session1Id !== undefined && record.session2Id !== undefined &&
        record.session1Id === record.session2Id) ||
      !(record.snapshotId === undefined ||
        (typeof record.snapshotId === "string" && SNAPSHOT_ID.test(record.snapshotId))) ||
      typeof record.stopAttempted !== "boolean" || typeof record.stopped !== "boolean" ||
      typeof record.resumeAttempted !== "boolean" || typeof record.cleanupStopAttempted !== "boolean" ||
      typeof record.cleanupStopped !== "boolean" || typeof record.deleteAttempted !== "boolean" ||
      typeof record.deleted !== "boolean" || !Number.isInteger(record.sandboxAbsenceChecks) ||
      (record.sandboxAbsenceChecks as number) < 0 || typeof record.prefixListAbsent !== "boolean" ||
      !strings(record.snapshotsObserved, SNAPSHOT_ID) ||
      !strings(record.snapshotDeleteIntents, SNAPSHOT_ID) || !strings(record.snapshotsDeleted, SNAPSHOT_ID) ||
      !(record.snapshotDeleteIntents as string[]).every((id) =>
        (record.snapshotsObserved as string[]).includes(id)) ||
      !(record.snapshotsDeleted as string[]).every((id) => (record.snapshotsObserved as string[]).includes(id)) ||
      !(record.snapshotsDeleted as string[]).every((id) =>
        (record.snapshotDeleteIntents as string[]).includes(id)) ||
      !Number.isInteger(record.snapshotAbsenceChecks) || (record.snapshotAbsenceChecks as number) < 0 ||
      typeof record.completed !== "boolean" || record.rawCapabilitiesRetained !== false) {
    throw new Error("SBX-055 recovery journal was invalid");
  }
  return record as unknown as Sbx055RecoveryJournal;
}

async function exactPrivateFile(path: string): Promise<number> {
  const metadata = await lstat(path);
  const mode = metadata.mode & 0o777;
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || mode !== 0o600) {
    throw new Error("SBX-055 private state was not a mode-0600 single-link regular file");
  }
  return mode;
}

async function exactPrivateFileExists(path: string): Promise<boolean> {
  try {
    await exactPrivateFile(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

async function requirePathAbsent(path: string, description: string): Promise<void> {
  try {
    await lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  throw new Error(`${description} remained after local recovery settlement`);
}

async function writeNewPrivateFile(path: string, bytes: string): Promise<number> {
  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  const handle = await open(path,
    fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | noFollow, 0o600);
  let identity: { device: bigint; inode: bigint } | undefined;
  try {
    const opened = await handle.stat({ bigint: true });
    identity = { device: opened.dev, inode: opened.ino };
    await handle.chmod(0o600);
    await handle.writeFile(bytes, "utf8");
    await handle.sync();
    await handle.close();
    return exactPrivateFile(path);
  } catch (error) {
    await handle.close().catch(() => undefined);
    if (identity !== undefined) {
      try {
        const current = await lstat(path, { bigint: true });
        if (current.dev === identity.device && current.ino === identity.inode) await unlink(path);
      } catch {
        // Preserve any pathname whose exact created inode cannot still be proven.
      }
    }
    throw error;
  }
}

export async function acquireSbx055Lock(journal: Sbx055RecoveryJournal): Promise<Sbx055HeldLock> {
  parseSbx055Journal(journal);
  await mkdir(SBX055_ARTIFACTS_DIRECTORY, { recursive: true, mode: 0o700 });
  const journalPath = sbx055JournalPath(journal.runId);
  const liveLock = await acquireSbx055LiveLock(SBX055_LIVE_LOCK, journal.runId, false);
  try {
    const lockMode = await exactPrivateFile(SBX055_LIVE_LOCK);
    const journalMode = await writeNewPrivateFile(journalPath, `${JSON.stringify(journal, null, 2)}\n`);
    return { liveLock, lockPath: SBX055_LIVE_LOCK, journalPath, lockMode, journalMode, runId: journal.runId };
  } catch (error) {
    await liveLock.release().catch(() => undefined);
    throw error;
  }
}

async function readJournalAtPath(runId: string, path: string): Promise<Sbx055RecoveryJournal> {
  await exactPrivateFile(path);
  const journal = parseSbx055Journal(JSON.parse(await readFile(path, "utf8")));
  if (journal.runId !== runId) throw new Error("SBX-055 recovery journal run ID changed");
  return journal;
}

async function acquireRecoveryAtPaths(runId: string, lockPath: string, journalPath: string): Promise<Sbx055HeldLock> {
  await recoverSbx055InterruptedAcquire(lockPath, runId);
  await rollbackSbx055InterruptedRelease(lockPath, runId);
  const liveLock = await acquireSbx055LiveLock(lockPath, runId, true);
  try {
    const lockMode = await exactPrivateFile(lockPath);
    const journalMode = await exactPrivateFile(journalPath);
    await readJournalAtPath(runId, journalPath);
    return { liveLock, lockPath, journalPath, lockMode, journalMode, runId };
  } catch (error) {
    await liveLock.closeRetainingState();
    throw error;
  }
}

export function acquireSbx055RecoveryLock(runId: string): Promise<Sbx055HeldLock> {
  return acquireRecoveryAtPaths(runId, SBX055_LIVE_LOCK, sbx055JournalPath(runId));
}

export function acquireSbx055RecoveryLockAtPathsForTest(
  runId: string, lockPath: string, journalPath: string,
): Promise<Sbx055HeldLock> {
  return acquireRecoveryAtPaths(runId, lockPath, journalPath);
}

async function dispatchRecoveryAtPaths(
  runId: string,
  lockPath: string,
  journalPath: string,
): Promise<Sbx055RecoveryDispatchOutcome> {
  if (!SBX055_UUID.test(runId)) throw new Error("SBX-055 recovery dispatcher requires a canonical UUIDv4");
  const removalSettlement = await settleSbx055RemovalClaims(lockPath, runId);
  const [transaction, journalPresent] = await Promise.all([
    inspectSbx055PendingTransaction(lockPath, runId),
    exactPrivateFileExists(journalPath),
  ]);
  if (transaction === undefined && removalSettlement.transactionOperation === "release" && !journalPresent) {
    await requirePathAbsent(lockPath, "SBX-055 finalized live lock");
    await requirePathAbsent(`${lockPath}.transaction`, "SBX-055 finalized transaction");
    return "release-finalization-complete";
  }
  if (transaction === undefined) {
    if (!journalPresent) {
      if (!await rollbackSbx055OrphanedNormalLock(lockPath, runId)) {
        throw new Error("SBX-055 recovery found neither an exact journal nor recoverable local lock state");
      }
      return "zero-external-state-acquire-rolled-back";
    }
    return "continue-journal-recovery";
  }
  if (transaction.operation === "release") {
    if (journalPresent) return "continue-journal-recovery";
    if (!await resumeFinalizationAtPaths(runId, lockPath, journalPath)) {
      throw new Error("SBX-055 release finalization transaction did not settle exactly");
    }
    await requirePathAbsent(lockPath, "SBX-055 finalized live lock");
    await requirePathAbsent(`${lockPath}.transaction`, "SBX-055 finalized transaction");
    return "release-finalization-complete";
  }
  if (transaction.mode === "cleanup-only" && !journalPresent) {
    throw new Error("SBX-055 cleanup takeover lost its journal; transaction retained");
  }
  if (transaction.mode === "normal" && journalPresent) {
    throw new Error("SBX-055 normal acquire unexpectedly had a journal; transaction retained");
  }
  if (!await recoverSbx055InterruptedAcquire(lockPath, runId)) {
    throw new Error("SBX-055 acquire transaction did not settle exactly");
  }
  if (journalPresent) return "continue-journal-recovery";
  await requirePathAbsent(lockPath, "SBX-055 zero-state live lock");
  await requirePathAbsent(`${lockPath}.transaction`, "SBX-055 zero-state transaction");
  return "zero-external-state-acquire-rolled-back";
}

export function dispatchSbx055Recovery(runId: string): Promise<Sbx055RecoveryDispatchOutcome> {
  return dispatchRecoveryAtPaths(runId, SBX055_LIVE_LOCK, sbx055JournalPath(runId));
}

export function dispatchSbx055RecoveryAtPathsForTest(
  runId: string,
  lockPath: string,
  journalPath: string,
): Promise<Sbx055RecoveryDispatchOutcome> {
  return dispatchRecoveryAtPaths(runId, lockPath, journalPath);
}

async function resumeFinalizationAtPaths(runId: string, lockPath: string, journalPath: string): Promise<boolean> {
  try {
    await lstat(journalPath);
    return false;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  return resumeSbx055InterruptedRelease(lockPath, runId);
}

export function resumeSbx055InterruptedFinalization(runId: string): Promise<boolean> {
  return resumeFinalizationAtPaths(runId, SBX055_LIVE_LOCK, sbx055JournalPath(runId));
}

export function resumeSbx055InterruptedFinalizationAtPathsForTest(
  runId: string, lockPath: string, journalPath: string,
): Promise<boolean> {
  return resumeFinalizationAtPaths(runId, lockPath, journalPath);
}

export function readSbx055Journal(runId: string): Promise<Sbx055RecoveryJournal> {
  return readJournalAtPath(runId, sbx055JournalPath(runId));
}

export async function persistSbx055Journal(
  lock: Sbx055HeldLock,
  journal: Sbx055RecoveryJournal,
): Promise<void> {
  if (lock.runId !== journal.runId || lock.journalPath !== sbx055JournalPath(journal.runId)) {
    throw new Error("SBX-055 journal/lock run mismatch");
  }
  journal.updatedAt = new Date().toISOString();
  parseSbx055Journal(journal);
  const temporary = `${lock.journalPath}.tmp-${randomUUID()}`;
  await writeNewPrivateFile(temporary, `${JSON.stringify(journal, null, 2)}\n`);
  try {
    await rename(temporary, lock.journalPath);
    await exactPrivateFile(lock.journalPath);
  } catch (error) {
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

export async function releaseSbx055LockAndJournal(
  lock: Sbx055HeldLock,
  removeJournal: () => Promise<void> = async () => unlink(lock.journalPath),
): Promise<void> {
  await lock.liveLock.releaseAfter(removeJournal);
  if (!lock.liveLock.isReleased()) throw new Error("SBX-055 atomic live lock did not reach released state");
}

export async function writeSbx055PrivateArtifact(path: string, value: unknown): Promise<number> {
  const record = value as { runId?: string; recoveryAttemptId?: string; recoveryOnly?: boolean };
  const expected = record.recoveryOnly === true
    ? sbx055RecoveryArtifactPath(record.runId ?? "", record.recoveryAttemptId ?? "")
    : sbx055ArtifactPath(record.runId ?? "");
  if (path !== expected) throw new Error("SBX-055 artifact path did not match its run ID");
  return writeNewPrivateFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

export function safeSbx055Error(error: unknown, forbidden: readonly string[] = []): string {
  let message = error instanceof Error ? `${error.name}: ${error.message}` : "unknown error";
  for (const value of forbidden) if (value.length > 0) message = message.split(value).join("<redacted>");
  return message.replace(/[\r\n\0]/gu, " ").slice(0, 512);
}

export function createSettlementReached(journal: Sbx055RecoveryJournal, now = Date.now()): boolean {
  return journal.createAttemptedAt !== undefined &&
    now >= Date.parse(journal.createAttemptedAt) + SBX055_UNKNOWN_CREATE_SETTLEMENT_MS;
}

export function zeroExternalStateJournal(journal: Sbx055RecoveryJournal): boolean {
  return journal.createAttemptedAt === undefined && journal.phase === "pre-create" &&
    journal.session1Id === undefined && journal.snapshotId === undefined && journal.session2Id === undefined &&
    !journal.stopAttempted && !journal.resumeAttempted && !journal.cleanupStopAttempted &&
    !journal.deleteAttempted && journal.snapshotsObserved.length === 0 &&
    journal.snapshotDeleteIntents.length === 0 && journal.snapshotsDeleted.length === 0;
}
