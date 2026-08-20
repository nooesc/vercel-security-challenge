import { randomUUID } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { SBX053_TEST_ID } from "./verdict.js";
import {
  acquireSbx053LiveLock,
  rollbackSbx053InterruptedAcquire,
  rollbackSbx053InterruptedRelease,
  resumeSbx053InterruptedRelease,
  type Sbx053HeldLock as Sbx053AtomicLiveLock,
} from "./live-lock.js";

export const SBX053_ARTIFACTS_DIRECTORY = fileURLToPath(new URL("../../artifacts", import.meta.url));
export const SBX053_LIVE_LOCK = resolve(SBX053_ARTIFACTS_DIRECTORY, "SBX-053-live-active.lock");
export const SBX053_SANDBOX_TIMEOUT_MS = 240_000 as const;
export const SBX053_CREATE_REQUEST_TIMEOUT_MS = 45_000 as const;
export const SBX053_UNKNOWN_CREATE_SETTLEMENT_MS =
  SBX053_CREATE_REQUEST_TIMEOUT_MS + SBX053_SANDBOX_TIMEOUT_MS + 30_000;

export const SBX053_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SESSION_ID = /^sbx_[A-Za-z0-9_-]{8,192}$/u;
export interface Sbx053RecoveryJournal {
  schemaVersion: 1;
  testId: typeof SBX053_TEST_ID;
  runId: string;
  sandboxName: string;
  tags: Record<string, string>;
  persistent: false;
  timeoutMs: typeof SBX053_SANDBOX_TIMEOUT_MS;
  startedAt: string;
  updatedAt: string;
  createAttemptedAt?: string;
  createRequestSettledAt?: string;
  sessionId?: string;
  authorityPreflightPassed: boolean;
  sandboxAttributed: boolean;
  guestProbeStaged: boolean;
  githubOnlyOpened: boolean;
  denyAllRestored: boolean;
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  absenceChecks: number;
  prefixListAbsent: boolean;
  completed: boolean;
  rawValuesRetained: false;
}

export interface Sbx053HeldLock {
  liveLock: Sbx053AtomicLiveLock;
  lockPath: string;
  journalPath: string;
  lockMode: number;
  journalMode: number;
  runId: string;
}

function timestamp(value: unknown): value is string {
  if (typeof value !== "string" || value.length !== 24) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function exactKeys(value: object, required: readonly string[], optional: readonly string[] = []): boolean {
  const actual = Object.keys(value);
  const permitted = new Set([...required, ...optional]);
  return required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    actual.every((key) => permitted.has(key)) &&
    actual.length === required.length + optional.filter((key) =>
      Object.prototype.hasOwnProperty.call(value, key)).length;
}

function exactRecord(actual: unknown, expected: Record<string, string>): boolean {
  if (actual === null || typeof actual !== "object" || Array.isArray(actual)) return false;
  const record = actual as Record<string, unknown>;
  const keys = Object.keys(expected);
  return Object.keys(record).length === keys.length && keys.every((key) => record[key] === expected[key]);
}

export function sbx053SandboxName(runId: string): string {
  if (!SBX053_UUID.test(runId)) throw new Error("SBX-053 run ID was not canonical");
  return `sbx-053-${runId}`;
}

export function sbx053Tags(runId: string): Record<string, string> {
  return { harness: "vsc", test: SBX053_TEST_ID, run: runId };
}

export function sbx053JournalPath(runId: string): string {
  if (!SBX053_UUID.test(runId)) throw new Error("SBX-053 run ID was not canonical");
  return resolve(SBX053_ARTIFACTS_DIRECTORY, `SBX-053-${runId}-recovery.json`);
}

export function sbx053ArtifactPath(runId: string): string {
  if (!SBX053_UUID.test(runId)) throw new Error("SBX-053 run ID was not canonical");
  return resolve(SBX053_ARTIFACTS_DIRECTORY, `SBX-053-${runId}-private.json`);
}

export function sbx053RecoveryArtifactPath(runId: string, recoveryAttemptId: string): string {
  if (!SBX053_UUID.test(runId) || !SBX053_UUID.test(recoveryAttemptId)) {
    throw new Error("SBX-053 recovery artifact path requires run and attempt UUIDv4 values");
  }
  return resolve(
    SBX053_ARTIFACTS_DIRECTORY,
    `SBX-053-${runId}-recovery-${recoveryAttemptId}-private.json`,
  );
}

export function createSbx053Journal(now: Date = new Date(), suppliedRunId?: string): Sbx053RecoveryJournal {
  const runId = suppliedRunId ?? randomUUID();
  if (!SBX053_UUID.test(runId)) throw new Error("SBX-053 run ID was not canonical");
  const at = now.toISOString();
  return {
    schemaVersion: 1,
    testId: SBX053_TEST_ID,
    runId,
    sandboxName: sbx053SandboxName(runId),
    tags: sbx053Tags(runId),
    persistent: false,
    timeoutMs: SBX053_SANDBOX_TIMEOUT_MS,
    startedAt: at,
    updatedAt: at,
    authorityPreflightPassed: false,
    sandboxAttributed: false,
    guestProbeStaged: false,
    githubOnlyOpened: false,
    denyAllRestored: true,
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    absenceChecks: 0,
    prefixListAbsent: false,
    completed: false,
    rawValuesRetained: false,
  };
}

export function parseSbx053Journal(value: unknown): Sbx053RecoveryJournal {
  if (value === null || typeof value !== "object" || Array.isArray(value) || !exactKeys(value, [
    "schemaVersion", "testId", "runId", "sandboxName", "tags", "persistent", "timeoutMs",
    "startedAt", "updatedAt", "authorityPreflightPassed", "sandboxAttributed", "guestProbeStaged",
    "githubOnlyOpened", "denyAllRestored", "stopAttempted",
    "stopped", "deleteAttempted", "deleted", "absenceChecks", "prefixListAbsent", "completed",
    "rawValuesRetained",
  ], ["createAttemptedAt", "createRequestSettledAt", "sessionId"])) {
    throw new Error("SBX-053 recovery journal fields were not exact");
  }
  const record = value as Record<string, unknown>;
  if (record.schemaVersion !== 1 || record.testId !== SBX053_TEST_ID ||
      typeof record.runId !== "string" || !SBX053_UUID.test(record.runId) ||
      record.sandboxName !== sbx053SandboxName(record.runId) ||
      !exactRecord(record.tags, sbx053Tags(record.runId)) || record.persistent !== false ||
      record.timeoutMs !== SBX053_SANDBOX_TIMEOUT_MS || !timestamp(record.startedAt) ||
      !timestamp(record.updatedAt) || Date.parse(record.updatedAt) < Date.parse(record.startedAt) ||
      !(record.createAttemptedAt === undefined || timestamp(record.createAttemptedAt)) ||
      !(record.createRequestSettledAt === undefined || timestamp(record.createRequestSettledAt)) ||
      (record.createRequestSettledAt !== undefined && (record.createAttemptedAt === undefined ||
        Date.parse(record.createRequestSettledAt as string) <
          Date.parse(record.createAttemptedAt as string))) ||
      !(record.sessionId === undefined ||
        (typeof record.sessionId === "string" && SESSION_ID.test(record.sessionId))) ||
      typeof record.authorityPreflightPassed !== "boolean" ||
      typeof record.sandboxAttributed !== "boolean" ||
      typeof record.guestProbeStaged !== "boolean" || typeof record.githubOnlyOpened !== "boolean" ||
      typeof record.denyAllRestored !== "boolean" ||
      typeof record.stopAttempted !== "boolean" || typeof record.stopped !== "boolean" ||
      typeof record.deleteAttempted !== "boolean" || typeof record.deleted !== "boolean" ||
      !Number.isInteger(record.absenceChecks) || (record.absenceChecks as number) < 0 ||
      typeof record.prefixListAbsent !== "boolean" || typeof record.completed !== "boolean" ||
      record.rawValuesRetained !== false) {
    throw new Error("SBX-053 recovery journal was invalid");
  }
  return record as unknown as Sbx053RecoveryJournal;
}

async function exactPrivateFile(path: string): Promise<number> {
  const metadata = await lstat(path);
  const mode = metadata.mode & 0o777;
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || mode !== 0o600) {
    throw new Error("SBX-053 private state was not a mode-0600 single-link regular file");
  }
  return mode;
}

async function writeNewPrivateFile(path: string, bytes: string): Promise<number> {
  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  const handle = await open(
    path,
    fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | noFollow,
    0o600,
  );
  try {
    await handle.chmod(0o600);
    await handle.writeFile(bytes, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  return exactPrivateFile(path);
}

export async function acquireSbx053Lock(journal: Sbx053RecoveryJournal): Promise<Sbx053HeldLock> {
  await mkdir(SBX053_ARTIFACTS_DIRECTORY, { recursive: true, mode: 0o700 });
  const journalPath = sbx053JournalPath(journal.runId);
  const liveLock = await acquireSbx053LiveLock(SBX053_LIVE_LOCK, journal.runId, false);
  try {
    const lockMode = await exactPrivateFile(SBX053_LIVE_LOCK);
    const journalMode = await writeNewPrivateFile(journalPath, `${JSON.stringify(journal, null, 2)}\n`);
    return {
      liveLock,
      lockPath: SBX053_LIVE_LOCK,
      journalPath,
      lockMode,
      journalMode,
      runId: journal.runId,
    };
  } catch (error) {
    await liveLock.release().catch(() => undefined);
    await unlink(journalPath).catch(() => undefined);
    throw error;
  }
}

async function readSbx053JournalAtPath(
  runId: string,
  journalPath: string,
): Promise<Sbx053RecoveryJournal> {
  await exactPrivateFile(journalPath);
  const journal = parseSbx053Journal(JSON.parse(await readFile(journalPath, "utf8")));
  if (journal.runId !== runId) throw new Error("SBX-053 recovery journal run ID changed");
  return journal;
}

async function acquireSbx053RecoveryLockAtPaths(
  runId: string,
  lockPath: string,
  journalPath: string,
): Promise<Sbx053HeldLock> {
  await rollbackSbx053InterruptedRelease(lockPath, runId);
  const liveLock = await acquireSbx053LiveLock(lockPath, runId, true);
  try {
    const lockMode = await exactPrivateFile(lockPath);
    const journalMode = await exactPrivateFile(journalPath);
    await readSbx053JournalAtPath(runId, journalPath);
    return {
      liveLock,
      lockPath,
      journalPath,
      lockMode,
      journalMode,
      runId,
    };
  } catch (error) {
    // Keep the newly reclaimed canonical lock in place. Once this process exits,
    // a later cleanup-only process can atomically reclaim it and inspect the
    // still-retained journal; deleting it here would strand recovery state.
    await liveLock.closeRetainingState();
    throw error;
  }
}

export async function acquireSbx053RecoveryLock(runId: string): Promise<Sbx053HeldLock> {
  return acquireSbx053RecoveryLockAtPaths(
    runId,
    SBX053_LIVE_LOCK,
    sbx053JournalPath(runId),
  );
}

/** Test seam for malformed/missing journal recovery after an atomic stale-lock reclaim. */
export async function acquireSbx053RecoveryLockAtPathsForTest(
  runId: string,
  lockPath: string,
  journalPath: string,
): Promise<Sbx053HeldLock> {
  return acquireSbx053RecoveryLockAtPaths(runId, lockPath, journalPath);
}

async function resumeSbx053InterruptedFinalizationAtPaths(
  runId: string,
  lockPath: string,
  journalPath: string,
): Promise<boolean> {
  try {
    await lstat(journalPath);
    return false;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  if (await resumeSbx053InterruptedRelease(lockPath, runId)) return true;
  return rollbackSbx053InterruptedAcquire(lockPath, runId);
}

export async function resumeSbx053InterruptedFinalization(runId: string): Promise<boolean> {
  return resumeSbx053InterruptedFinalizationAtPaths(
    runId,
    SBX053_LIVE_LOCK,
    sbx053JournalPath(runId),
  );
}

/** Test seam for a fresh process resuming a journal-committed release transaction. */
export async function resumeSbx053InterruptedFinalizationAtPathsForTest(
  runId: string,
  lockPath: string,
  journalPath: string,
): Promise<boolean> {
  return resumeSbx053InterruptedFinalizationAtPaths(runId, lockPath, journalPath);
}

export async function readSbx053Journal(runId: string): Promise<Sbx053RecoveryJournal> {
  return readSbx053JournalAtPath(runId, sbx053JournalPath(runId));
}

export async function persistSbx053Journal(
  lock: Sbx053HeldLock,
  journal: Sbx053RecoveryJournal,
): Promise<void> {
  if (lock.runId !== journal.runId || lock.journalPath !== sbx053JournalPath(journal.runId)) {
    throw new Error("SBX-053 journal/lock run mismatch");
  }
  journal.updatedAt = new Date().toISOString();
  parseSbx053Journal(journal);
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

export async function releaseSbx053LockAndJournal(
  lock: Sbx053HeldLock,
  removeJournal: () => Promise<void> = async () => unlink(lock.journalPath),
): Promise<void> {
  await lock.liveLock.releaseAfter(removeJournal);
  if (!lock.liveLock.isReleased()) throw new Error("SBX-053 atomic live lock did not reach released state");
}

export async function writeSbx053PrivateArtifact(path: string, value: unknown): Promise<number> {
  const record = value as { runId?: string; recoveryAttemptId?: string; recoveryOnly?: boolean };
  const expected = record.recoveryOnly === true
    ? sbx053RecoveryArtifactPath(record.runId ?? "", record.recoveryAttemptId ?? "")
    : sbx053ArtifactPath(record.runId ?? "");
  if (path !== expected) {
    throw new Error("SBX-053 artifact path did not match its run ID");
  }
  return writeNewPrivateFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

export function safeSbx053Error(error: unknown, forbidden: readonly string[] = []): string {
  let message = error instanceof Error ? `${error.name}: ${error.message}` : "unknown error";
  for (const value of forbidden) {
    if (value.length > 0) message = message.split(value).join("<redacted>");
  }
  return message.replace(/[\r\n\0]/gu, " ").slice(0, 512);
}

export function createSettlementReached(journal: Sbx053RecoveryJournal, now = Date.now()): boolean {
  return journal.createAttemptedAt !== undefined &&
    now >= Date.parse(journal.createAttemptedAt) + SBX053_UNKNOWN_CREATE_SETTLEMENT_MS;
}

export function unknownCreateSettlementReached(journal: Sbx053RecoveryJournal, now = Date.now()): boolean {
  return journal.sessionId === undefined && createSettlementReached(journal, now);
}
