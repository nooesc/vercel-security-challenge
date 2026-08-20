import { randomUUID } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  SBX052_ALIAS_EMAIL,
  SBX052_PROJECT_ID,
  SBX052_TEAM_ID,
  SBX052_TEST_ID,
} from "./verdict.js";
import {
  acquireSbx052LiveLock,
  rollbackSbx052InterruptedRelease,
  resumeSbx052InterruptedRelease,
  type Sbx052HeldLock as Sbx052AtomicLiveLock,
} from "./live-lock.js";

export const SBX052_SCOPE_CONFIRMATION =
  "I_OWN_THIS_ALIAS_SCOPE_AND_AUTHORIZE_ONE_BOUNDED_FS_NAMESPACE_TEST" as const;
export const SBX052_ARTIFACTS_DIRECTORY = fileURLToPath(new URL("../../artifacts", import.meta.url));
export const SBX052_LIVE_LOCK = resolve(SBX052_ARTIFACTS_DIRECTORY, "SBX-052-live-active.lock");
export const SBX052_SANDBOX_TIMEOUT_MS = 240_000 as const;
export const SBX052_CREATE_REQUEST_TIMEOUT_MS = 45_000 as const;
export const SBX052_UNKNOWN_CREATE_SETTLEMENT_MS =
  SBX052_CREATE_REQUEST_TIMEOUT_MS + SBX052_SANDBOX_TIMEOUT_MS + 30_000;

export const SBX052_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SESSION_ID = /^sbx_[A-Za-z0-9_-]{8,192}$/u;
const TOKEN = /^[^\s\0]{20,4096}$/u;

export interface Sbx052Config {
  token: string;
  teamId: typeof SBX052_TEAM_ID;
  projectId: typeof SBX052_PROJECT_ID;
  expectedAlias: typeof SBX052_ALIAS_EMAIL;
  recoveryRunId?: string;
}

export interface Sbx052RecoveryJournal {
  schemaVersion: 1;
  testId: typeof SBX052_TEST_ID;
  runId: string;
  sandboxName: string;
  tags: Record<string, string>;
  persistent: false;
  timeoutMs: typeof SBX052_SANDBOX_TIMEOUT_MS;
  startedAt: string;
  updatedAt: string;
  createAttemptedAt?: string;
  sessionId?: string;
  guestProbeStaged: boolean;
  guestMaterialRemoved: boolean;
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  absenceChecks: number;
  prefixListAbsent: boolean;
  completed: boolean;
  rawValuesRetained: false;
}

export interface Sbx052HeldLock {
  liveLock: Sbx052AtomicLiveLock;
  lockPath: string;
  journalPath: string;
  lockMode: number;
  journalMode: number;
  runId: string;
}

const FORBIDDEN_RUNTIME_VARIABLES = [
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "NODE_TLS_REJECT_UNAUTHORIZED",
  "NODE_EXTRA_CA_CERTS",
  "NODE_USE_SYSTEM_CA",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "OPENSSL_CONF",
  "OPENSSL_MODULES",
  "VERCEL_API_URL",
] as const;

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

export function loadSbx052Config(environment: NodeJS.ProcessEnv = process.env): Sbx052Config {
  if (environment.SBX052_SCOPE_CONFIRMATION !== SBX052_SCOPE_CONFIRMATION) {
    throw new Error("SBX052_SCOPE_CONFIRMATION did not match the exact bounded-test attestation");
  }
  if (environment.VERCEL_TEAM_ID !== SBX052_TEAM_ID ||
      environment.VERCEL_PROJECT_ID !== SBX052_PROJECT_ID ||
      environment.SBX052_ALIAS_EMAIL_CONFIRMATION !== SBX052_ALIAS_EMAIL) {
    throw new Error("SBX-052 credentials were not bound to the eligible alias/team/project");
  }
  for (const name of FORBIDDEN_RUNTIME_VARIABLES) {
    if (environment[name] !== undefined && environment[name] !== "") {
      throw new Error(`SBX-052 rejects runtime transport override ${name}`);
    }
  }
  const token = required(environment, "VERCEL_TOKEN");
  if (!TOKEN.test(token) || token.split(".").length === 3) {
    throw new Error("SBX-052 requires one bounded opaque Vercel PAT");
  }
  const recoveryRunId = environment.SBX052_RECOVERY_RUN_ID;
  if (recoveryRunId !== undefined && !SBX052_UUID.test(recoveryRunId)) {
    throw new Error("SBX052_RECOVERY_RUN_ID must be one canonical UUIDv4");
  }
  return {
    token,
    teamId: SBX052_TEAM_ID,
    projectId: SBX052_PROJECT_ID,
    expectedAlias: SBX052_ALIAS_EMAIL,
    ...(recoveryRunId === undefined ? {} : { recoveryRunId }),
  };
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

export function sbx052SandboxName(runId: string): string {
  if (!SBX052_UUID.test(runId)) throw new Error("SBX-052 run ID was not canonical");
  return `sbx-052-${runId}`;
}

export function sbx052Tags(runId: string): Record<string, string> {
  return { harness: "vsc", test: SBX052_TEST_ID, run: runId };
}

export function sbx052JournalPath(runId: string): string {
  if (!SBX052_UUID.test(runId)) throw new Error("SBX-052 run ID was not canonical");
  return resolve(SBX052_ARTIFACTS_DIRECTORY, `SBX-052-${runId}-recovery.json`);
}

export function sbx052ArtifactPath(runId: string): string {
  if (!SBX052_UUID.test(runId)) throw new Error("SBX-052 run ID was not canonical");
  return resolve(SBX052_ARTIFACTS_DIRECTORY, `SBX-052-${runId}-private.json`);
}

export function sbx052RecoveryArtifactPath(runId: string, recoveryAttemptId: string): string {
  if (!SBX052_UUID.test(runId) || !SBX052_UUID.test(recoveryAttemptId)) {
    throw new Error("SBX-052 recovery artifact path requires run and attempt UUIDv4 values");
  }
  return resolve(
    SBX052_ARTIFACTS_DIRECTORY,
    `SBX-052-${runId}-recovery-${recoveryAttemptId}-private.json`,
  );
}

export function createSbx052Journal(now: Date = new Date(), suppliedRunId?: string): Sbx052RecoveryJournal {
  const runId = suppliedRunId ?? randomUUID();
  if (!SBX052_UUID.test(runId)) throw new Error("SBX-052 run ID was not canonical");
  const at = now.toISOString();
  return {
    schemaVersion: 1,
    testId: SBX052_TEST_ID,
    runId,
    sandboxName: sbx052SandboxName(runId),
    tags: sbx052Tags(runId),
    persistent: false,
    timeoutMs: SBX052_SANDBOX_TIMEOUT_MS,
    startedAt: at,
    updatedAt: at,
    guestProbeStaged: false,
    guestMaterialRemoved: false,
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

export function parseSbx052Journal(value: unknown): Sbx052RecoveryJournal {
  if (value === null || typeof value !== "object" || Array.isArray(value) || !exactKeys(value, [
    "schemaVersion", "testId", "runId", "sandboxName", "tags", "persistent", "timeoutMs",
    "startedAt", "updatedAt", "guestProbeStaged", "guestMaterialRemoved", "stopAttempted",
    "stopped", "deleteAttempted", "deleted", "absenceChecks", "prefixListAbsent", "completed",
    "rawValuesRetained",
  ], ["createAttemptedAt", "sessionId"])) {
    throw new Error("SBX-052 recovery journal fields were not exact");
  }
  const record = value as Record<string, unknown>;
  if (record.schemaVersion !== 1 || record.testId !== SBX052_TEST_ID ||
      typeof record.runId !== "string" || !SBX052_UUID.test(record.runId) ||
      record.sandboxName !== sbx052SandboxName(record.runId) ||
      !exactRecord(record.tags, sbx052Tags(record.runId)) || record.persistent !== false ||
      record.timeoutMs !== SBX052_SANDBOX_TIMEOUT_MS || !timestamp(record.startedAt) ||
      !timestamp(record.updatedAt) || Date.parse(record.updatedAt) < Date.parse(record.startedAt) ||
      !(record.createAttemptedAt === undefined || timestamp(record.createAttemptedAt)) ||
      !(record.sessionId === undefined ||
        (typeof record.sessionId === "string" && SESSION_ID.test(record.sessionId))) ||
      typeof record.guestProbeStaged !== "boolean" || typeof record.guestMaterialRemoved !== "boolean" ||
      typeof record.stopAttempted !== "boolean" || typeof record.stopped !== "boolean" ||
      typeof record.deleteAttempted !== "boolean" || typeof record.deleted !== "boolean" ||
      !Number.isInteger(record.absenceChecks) || (record.absenceChecks as number) < 0 ||
      typeof record.prefixListAbsent !== "boolean" || typeof record.completed !== "boolean" ||
      record.rawValuesRetained !== false) {
    throw new Error("SBX-052 recovery journal was invalid");
  }
  return record as unknown as Sbx052RecoveryJournal;
}

async function exactPrivateFile(path: string): Promise<number> {
  const metadata = await lstat(path);
  const mode = metadata.mode & 0o777;
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || mode !== 0o600) {
    throw new Error("SBX-052 private state was not a mode-0600 single-link regular file");
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

export async function acquireSbx052Lock(journal: Sbx052RecoveryJournal): Promise<Sbx052HeldLock> {
  await mkdir(SBX052_ARTIFACTS_DIRECTORY, { recursive: true, mode: 0o700 });
  const journalPath = sbx052JournalPath(journal.runId);
  const liveLock = await acquireSbx052LiveLock(SBX052_LIVE_LOCK, journal.runId, false);
  try {
    const lockMode = await exactPrivateFile(SBX052_LIVE_LOCK);
    const journalMode = await writeNewPrivateFile(journalPath, `${JSON.stringify(journal, null, 2)}\n`);
    return {
      liveLock,
      lockPath: SBX052_LIVE_LOCK,
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

async function readSbx052JournalAtPath(
  runId: string,
  journalPath: string,
): Promise<Sbx052RecoveryJournal> {
  await exactPrivateFile(journalPath);
  const journal = parseSbx052Journal(JSON.parse(await readFile(journalPath, "utf8")));
  if (journal.runId !== runId) throw new Error("SBX-052 recovery journal run ID changed");
  return journal;
}

async function acquireSbx052RecoveryLockAtPaths(
  runId: string,
  lockPath: string,
  journalPath: string,
): Promise<Sbx052HeldLock> {
  await rollbackSbx052InterruptedRelease(lockPath, runId);
  const liveLock = await acquireSbx052LiveLock(lockPath, runId, true);
  try {
    const lockMode = await exactPrivateFile(lockPath);
    const journalMode = await exactPrivateFile(journalPath);
    await readSbx052JournalAtPath(runId, journalPath);
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

export async function acquireSbx052RecoveryLock(runId: string): Promise<Sbx052HeldLock> {
  return acquireSbx052RecoveryLockAtPaths(
    runId,
    SBX052_LIVE_LOCK,
    sbx052JournalPath(runId),
  );
}

/** Test seam for malformed/missing journal recovery after an atomic stale-lock reclaim. */
export async function acquireSbx052RecoveryLockAtPathsForTest(
  runId: string,
  lockPath: string,
  journalPath: string,
): Promise<Sbx052HeldLock> {
  return acquireSbx052RecoveryLockAtPaths(runId, lockPath, journalPath);
}

async function resumeSbx052InterruptedFinalizationAtPaths(
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
  return resumeSbx052InterruptedRelease(lockPath, runId);
}

export async function resumeSbx052InterruptedFinalization(runId: string): Promise<boolean> {
  return resumeSbx052InterruptedFinalizationAtPaths(
    runId,
    SBX052_LIVE_LOCK,
    sbx052JournalPath(runId),
  );
}

/** Test seam for a fresh process resuming a journal-committed release transaction. */
export async function resumeSbx052InterruptedFinalizationAtPathsForTest(
  runId: string,
  lockPath: string,
  journalPath: string,
): Promise<boolean> {
  return resumeSbx052InterruptedFinalizationAtPaths(runId, lockPath, journalPath);
}

export async function readSbx052Journal(runId: string): Promise<Sbx052RecoveryJournal> {
  return readSbx052JournalAtPath(runId, sbx052JournalPath(runId));
}

export async function persistSbx052Journal(
  lock: Sbx052HeldLock,
  journal: Sbx052RecoveryJournal,
): Promise<void> {
  if (lock.runId !== journal.runId || lock.journalPath !== sbx052JournalPath(journal.runId)) {
    throw new Error("SBX-052 journal/lock run mismatch");
  }
  journal.updatedAt = new Date().toISOString();
  parseSbx052Journal(journal);
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

export async function releaseSbx052LockAndJournal(
  lock: Sbx052HeldLock,
  removeJournal: () => Promise<void> = async () => unlink(lock.journalPath),
): Promise<void> {
  await lock.liveLock.releaseAfter(removeJournal);
  if (!lock.liveLock.isReleased()) throw new Error("SBX-052 atomic live lock did not reach released state");
}

export async function writeSbx052PrivateArtifact(path: string, value: unknown): Promise<number> {
  const record = value as { runId?: string; recoveryAttemptId?: string; recoveryOnly?: boolean };
  const expected = record.recoveryOnly === true
    ? sbx052RecoveryArtifactPath(record.runId ?? "", record.recoveryAttemptId ?? "")
    : sbx052ArtifactPath(record.runId ?? "");
  if (path !== expected) {
    throw new Error("SBX-052 artifact path did not match its run ID");
  }
  return writeNewPrivateFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

export function safeSbx052Error(error: unknown, forbidden: readonly string[] = []): string {
  let message = error instanceof Error ? `${error.name}: ${error.message}` : "unknown error";
  for (const value of forbidden) {
    if (value.length > 0) message = message.split(value).join("<redacted>");
  }
  return message.replace(/[\r\n\0]/gu, " ").slice(0, 512);
}

export function createSettlementReached(journal: Sbx052RecoveryJournal, now = Date.now()): boolean {
  return journal.createAttemptedAt !== undefined &&
    now >= Date.parse(journal.createAttemptedAt) + SBX052_UNKNOWN_CREATE_SETTLEMENT_MS;
}

export function unknownCreateSettlementReached(journal: Sbx052RecoveryJournal, now = Date.now()): boolean {
  return journal.sessionId === undefined && createSettlementReached(journal, now);
}
