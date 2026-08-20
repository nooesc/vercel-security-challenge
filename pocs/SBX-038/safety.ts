import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  acquireSbx038LiveLock,
  inspectSbx038PendingTransaction,
  recoverSbx038InterruptedAcquire,
  resumeSbx038InterruptedRelease,
  rollbackSbx038InterruptedRelease,
  rollbackSbx038OrphanedNormalLock,
  settleSbx038RemovalClaims,
  type Sbx038HeldLiveLock,
} from "./live-lock.js";

const SBX038_SAFETY_TEST_ID = "SBX-038-POC" as const;

export const SBX038_ARTIFACTS_DIRECTORY = fileURLToPath(new URL("../../artifacts", import.meta.url));
export const SBX038_SANDBOX_TIMEOUT_MS = 180_000 as const;
export const SBX038_CREATE_REQUEST_TIMEOUT_MS = 45_000 as const;
export const SBX038_UNKNOWN_CREATE_SETTLEMENT_MS =
  SBX038_SANDBOX_TIMEOUT_MS + SBX038_CREATE_REQUEST_TIMEOUT_MS + 15_000;
export const SBX038_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
export const SBX038_SESSION = /^sbx_[A-Za-z0-9_-]{20,100}$/u;
const ABSENCE_DELAYS_MS = [250, 1_000, 3_000] as const;
const MAXIMUM_PRIVATE_JSON_BYTES = 256 * 1024;

export type Sbx038StageRole = "public" | "secret";
export type Sbx038JournalPhase = "pre-create" | "public" | "secret" | "cleanup" | "completed";

export interface Sbx038ResourceJournal {
  role: Sbx038StageRole;
  name: string;
  tags: Record<string, string>;
  persistent: false;
  timeoutMs: typeof SBX038_SANDBOX_TIMEOUT_MS;
  createAttemptedAt?: string;
  createResponseSettledAt?: string;
  sessionId?: string;
  provenanceValidated: boolean;
  secretWriteAttempted: boolean;
  secretNeutralizeAttempted: boolean;
  secretNeutralized: boolean;
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  absenceChecks: number;
  prefixListAbsent: boolean;
  absenceOnlyValidated: boolean;
}

export interface Sbx038Journal {
  schemaVersion: 1;
  testId: typeof SBX038_SAFETY_TEST_ID;
  runId: string;
  startedAt: string;
  updatedAt: string;
  phase: Sbx038JournalPhase;
  receiverConfigureAttempted: boolean;
  receiverConfigured: boolean;
  receiverDeleteAttempted: boolean;
  receiverDeleted: boolean;
  receiverAbsenceChecks: number;
  resources: [Sbx038ResourceJournal, Sbx038ResourceJournal];
  completed: boolean;
  rawSecretsRetained: false;
  rawOperationsRetained: false;
}

export interface Sbx038HeldState {
  runId: string;
  directory: string;
  lockPath: string;
  journalPath: string;
  liveLock: Sbx038HeldLiveLock;
  lockMode: number;
  journalMode: number;
}

export type Sbx038RecoveryDispatch =
  | "continue-journal-recovery"
  | "release-finalization-complete"
  | "zero-external-state-acquire-rolled-back";

export interface Sbx038SandboxProvenanceView {
  name: string;
  persistent: boolean;
  tags?: Record<string, string>;
  currentSessionId: string;
}

export interface Sbx038AbsenceDependencies {
  getSandbox(name: string): Promise<unknown>;
  listSandboxes(namePrefix: string): Promise<readonly Sbx038SandboxProvenanceView[]>;
  isNotFound(error: unknown): boolean;
  persist(journal: Sbx038Journal): Promise<void>;
  wait?(milliseconds: number): Promise<void>;
  now?(): number;
  absenceDelaysMs?: readonly number[];
}

function timestamp(value: unknown): value is string {
  if (typeof value !== "string" || value.length !== 24) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function exactKeys(value: object, required: readonly string[], optional: readonly string[] = []): boolean {
  const keys = Object.keys(value);
  const permitted = new Set([...required, ...optional]);
  return required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    keys.every((key) => permitted.has(key)) &&
    keys.length === required.length + optional.filter((key) =>
      Object.prototype.hasOwnProperty.call(value, key)).length;
}

function exactRecord(actual: unknown, expected: Record<string, string>): boolean {
  const record = object(actual);
  const keys = Object.keys(expected);
  return record !== undefined && Object.keys(record).length === keys.length &&
    keys.every((key) => record[key] === expected[key]);
}

export function sbx038SandboxName(role: Sbx038StageRole, runId: string): string {
  if (!SBX038_UUID.test(runId)) throw new Error("SBX-038 sandbox name requires a canonical UUIDv4");
  return `sbx-038-${role}-${runId.replaceAll("-", "")}`;
}

export function sbx038Tags(role: Sbx038StageRole, runId: string): Record<string, string> {
  if (!SBX038_UUID.test(runId)) throw new Error("SBX-038 tags require a canonical UUIDv4");
  return { harness: "vsc", test: SBX038_SAFETY_TEST_ID, run: runId, role };
}

function resource(role: Sbx038StageRole, runId: string): Sbx038ResourceJournal {
  return {
    role,
    name: sbx038SandboxName(role, runId),
    tags: sbx038Tags(role, runId),
    persistent: false,
    timeoutMs: SBX038_SANDBOX_TIMEOUT_MS,
    provenanceValidated: false,
    secretWriteAttempted: false,
    secretNeutralizeAttempted: false,
    secretNeutralized: false,
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    absenceChecks: 0,
    prefixListAbsent: false,
    absenceOnlyValidated: false,
  };
}

export function createSbx038Journal(input: { runId?: string; now?: Date } = {}): Sbx038Journal {
  const runId = input.runId ?? randomUUID();
  if (!SBX038_UUID.test(runId)) throw new Error("SBX-038 journal requires a canonical UUIDv4");
  const at = (input.now ?? new Date()).toISOString();
  return {
    schemaVersion: 1,
    testId: SBX038_SAFETY_TEST_ID,
    runId,
    startedAt: at,
    updatedAt: at,
    phase: "pre-create",
    receiverConfigureAttempted: false,
    receiverConfigured: false,
    receiverDeleteAttempted: false,
    receiverDeleted: false,
    receiverAbsenceChecks: 0,
    resources: [resource("public", runId), resource("secret", runId)],
    completed: false,
    rawSecretsRetained: false,
    rawOperationsRetained: false,
  };
}

export function sbx038Resource(journal: Sbx038Journal, role: Sbx038StageRole): Sbx038ResourceJournal {
  const expectedIndex = role === "public" ? 0 : 1;
  const value = journal.resources[expectedIndex];
  if (value.role !== role) throw new Error("SBX-038 journal resource ordering was invalid");
  return value;
}

function parseResource(
  value: unknown,
  role: Sbx038StageRole,
  runId: string,
): Sbx038ResourceJournal {
  const record = object(value);
  if (record === undefined || !exactKeys(record, [
    "role", "name", "tags", "persistent", "timeoutMs", "provenanceValidated",
    "secretWriteAttempted", "secretNeutralizeAttempted", "secretNeutralized",
    "stopAttempted", "stopped", "deleteAttempted", "deleted", "absenceChecks",
    "prefixListAbsent", "absenceOnlyValidated",
  ], ["createAttemptedAt", "createResponseSettledAt", "sessionId"])) {
    throw new Error("SBX-038 resource journal fields were not exact");
  }
  const createAttemptedAt = record.createAttemptedAt;
  const createResponseSettledAt = record.createResponseSettledAt;
  const sessionId = record.sessionId;
  if (record.role !== role || record.name !== sbx038SandboxName(role, runId) ||
      !exactRecord(record.tags, sbx038Tags(role, runId)) || record.persistent !== false ||
      record.timeoutMs !== SBX038_SANDBOX_TIMEOUT_MS ||
      !(createAttemptedAt === undefined || timestamp(createAttemptedAt)) ||
      !(createResponseSettledAt === undefined || timestamp(createResponseSettledAt)) ||
      !(sessionId === undefined || (typeof sessionId === "string" && SBX038_SESSION.test(sessionId))) ||
      typeof record.provenanceValidated !== "boolean" ||
      typeof record.secretWriteAttempted !== "boolean" ||
      typeof record.secretNeutralizeAttempted !== "boolean" ||
      typeof record.secretNeutralized !== "boolean" || typeof record.stopAttempted !== "boolean" ||
      typeof record.stopped !== "boolean" || typeof record.deleteAttempted !== "boolean" ||
      typeof record.deleted !== "boolean" || !Number.isInteger(record.absenceChecks) ||
      (record.absenceChecks as number) < 0 || typeof record.prefixListAbsent !== "boolean" ||
      typeof record.absenceOnlyValidated !== "boolean") {
    throw new Error("SBX-038 resource journal was invalid");
  }
  const createAttempted = createAttemptedAt !== undefined;
  const knownSession = sessionId !== undefined;
  if (record.provenanceValidated !== knownSession ||
      (createResponseSettledAt !== undefined && (!createAttempted ||
        Date.parse(createResponseSettledAt as string) < Date.parse(createAttemptedAt as string))) ||
      (!createAttempted && (createResponseSettledAt !== undefined || knownSession ||
        record.secretWriteAttempted || record.secretNeutralizeAttempted || record.secretNeutralized ||
        record.stopAttempted || record.stopped || record.deleteAttempted || record.deleted ||
        record.absenceChecks !== 0 || record.prefixListAbsent || record.absenceOnlyValidated)) ||
      (role === "public" && (record.secretWriteAttempted || record.secretNeutralizeAttempted ||
        record.secretNeutralized)) ||
      (record.secretNeutralizeAttempted && !record.secretWriteAttempted) ||
      (record.secretNeutralized && !record.secretNeutralizeAttempted) ||
      (record.stopped && !record.stopAttempted) || (record.deleted && !record.deleteAttempted &&
        !record.absenceOnlyValidated) || (record.prefixListAbsent && (record.absenceChecks as number) < 3) ||
      (record.absenceOnlyValidated && (!createAttempted || knownSession || record.provenanceValidated ||
        !record.deleted || (record.absenceChecks as number) < 3 || !record.prefixListAbsent))) {
    throw new Error("SBX-038 resource journal lifecycle was inconsistent");
  }
  return record as unknown as Sbx038ResourceJournal;
}

export function parseSbx038Journal(value: unknown): Sbx038Journal {
  const record = object(value);
  if (record === undefined || !exactKeys(record, [
    "schemaVersion", "testId", "runId", "startedAt", "updatedAt", "phase",
    "receiverConfigureAttempted", "receiverConfigured", "receiverDeleteAttempted",
    "receiverDeleted", "receiverAbsenceChecks", "resources", "completed",
    "rawSecretsRetained", "rawOperationsRetained",
  ]) || record.schemaVersion !== 1 || record.testId !== SBX038_SAFETY_TEST_ID ||
      typeof record.runId !== "string" || !SBX038_UUID.test(record.runId) ||
      !timestamp(record.startedAt) || !timestamp(record.updatedAt) ||
      Date.parse(record.updatedAt) < Date.parse(record.startedAt as string) ||
      !["pre-create", "public", "secret", "cleanup", "completed"].includes(String(record.phase)) ||
      typeof record.receiverConfigureAttempted !== "boolean" ||
      typeof record.receiverConfigured !== "boolean" ||
      typeof record.receiverDeleteAttempted !== "boolean" || typeof record.receiverDeleted !== "boolean" ||
      !Number.isInteger(record.receiverAbsenceChecks) || (record.receiverAbsenceChecks as number) < 0 ||
      !Array.isArray(record.resources) || record.resources.length !== 2 ||
      typeof record.completed !== "boolean" || record.rawSecretsRetained !== false ||
      record.rawOperationsRetained !== false) {
    throw new Error("SBX-038 journal was not exact");
  }
  if ((record.receiverConfigured && !record.receiverConfigureAttempted) ||
      (record.receiverDeleteAttempted && !record.receiverConfigureAttempted) ||
      (record.receiverDeleted && !record.receiverDeleteAttempted) ||
      ((record.receiverAbsenceChecks as number) > 0 && !record.receiverDeleteAttempted)) {
    throw new Error("SBX-038 receiver journal lifecycle was inconsistent");
  }
  const resources: [Sbx038ResourceJournal, Sbx038ResourceJournal] = [
    parseResource(record.resources[0], "public", record.runId),
    parseResource(record.resources[1], "secret", record.runId),
  ];
  const journal = { ...record, resources } as unknown as Sbx038Journal;
  if (journal.completed && (journal.phase !== "completed" || !sbx038JournalCleanupComplete(journal))) {
    throw new Error("SBX-038 completed journal lacked exact cleanup proof");
  }
  return journal;
}

export function exactSbx038SandboxProvenance(
  value: Sbx038SandboxProvenanceView,
  expected: Sbx038ResourceJournal,
): boolean {
  return value.name === expected.name && value.persistent === false &&
    exactRecord(value.tags, expected.tags) && SBX038_SESSION.test(value.currentSessionId) &&
    (expected.sessionId === undefined || value.currentSessionId === expected.sessionId);
}

export function sbx038UnknownCreateSettlementReached(
  value: Sbx038ResourceJournal,
  now = Date.now(),
): boolean {
  return value.createAttemptedAt !== undefined && value.sessionId === undefined &&
    now >= Date.parse(value.createAttemptedAt) + SBX038_UNKNOWN_CREATE_SETTLEMENT_MS;
}

export function sbx038JournalCleanupComplete(journal: Sbx038Journal, now = Date.now()): boolean {
  const resourceComplete = (value: Sbx038ResourceJournal): boolean => {
    if (value.createAttemptedAt === undefined) return true;
    if (value.secretWriteAttempted && !value.secretNeutralized) return false;
    if (value.absenceChecks < 3 || !value.prefixListAbsent || !value.deleted) return false;
    if (value.sessionId === undefined) {
      return value.absenceOnlyValidated && sbx038UnknownCreateSettlementReached(value, now);
    }
    return value.provenanceValidated && value.stopAttempted && value.stopped && value.deleteAttempted;
  };
  const receiverComplete = !journal.receiverConfigureAttempted ||
    (journal.receiverDeleteAttempted && journal.receiverDeleted && journal.receiverAbsenceChecks >= 3);
  return receiverComplete && journal.resources.every(resourceComplete);
}

export function exactSbx038ZeroExternalStateJournal(journal: Sbx038Journal): boolean {
  try { parseSbx038Journal(journal); } catch { return false; }
  return journal.phase === "pre-create" && !journal.receiverConfigureAttempted &&
    journal.resources.every((value) => value.createAttemptedAt === undefined);
}

export function sbx038JournalPath(runId: string, directory = SBX038_ARTIFACTS_DIRECTORY): string {
  if (!SBX038_UUID.test(runId)) throw new Error("SBX-038 journal path requires a UUIDv4");
  return resolve(directory, `SBX-038-${runId}-recovery.json`);
}

export function sbx038ArtifactPath(runId: string, directory = SBX038_ARTIFACTS_DIRECTORY): string {
  if (!SBX038_UUID.test(runId)) throw new Error("SBX-038 artifact path requires a UUIDv4");
  return resolve(directory, `SBX-038-${runId}-private.json`);
}

export function sbx038RecoveryArtifactPath(
  runId: string,
  attemptId: string,
  directory = SBX038_ARTIFACTS_DIRECTORY,
): string {
  if (!SBX038_UUID.test(runId) || !SBX038_UUID.test(attemptId)) {
    throw new Error("SBX-038 recovery artifact path requires UUIDv4 values");
  }
  return resolve(directory, `SBX-038-${runId}-recovery-${attemptId}-private.json`);
}

export function sbx038LockPath(directory = SBX038_ARTIFACTS_DIRECTORY): string {
  return resolve(directory, "SBX-038-live-active.lock");
}

async function ensurePrivateDirectory(directory: string): Promise<void> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const metadata = await lstat(directory);
  const uid = process.getuid?.();
  if (uid === undefined || !metadata.isDirectory() || metadata.isSymbolicLink() ||
      metadata.uid !== uid || (metadata.mode & 0o777) !== 0o700) {
    throw new Error("SBX-038 private directory was not current-user-owned mode 0700");
  }
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(dirname(path), constants.O_RDONLY | (constants.O_DIRECTORY ?? 0));
  try { await handle.sync(); } finally { await handle.close(); }
}

async function privateFileIdentity(path: string): Promise<{ device: bigint; inode: bigint; mode: number }> {
  const metadata = await lstat(path, { bigint: true });
  const uid = process.getuid?.();
  if (uid === undefined || !metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1n ||
      (metadata.mode & 0o777n) !== 0o600n || metadata.uid !== BigInt(uid)) {
    throw new Error("SBX-038 private state was not an owned mode-0600 single-link regular file");
  }
  return { device: metadata.dev, inode: metadata.ino, mode: Number(metadata.mode & 0o777n) };
}

async function writeNewPrivateFile(path: string, bytes: string): Promise<number> {
  if (Buffer.byteLength(bytes) > MAXIMUM_PRIVATE_JSON_BYTES) {
    throw new Error("SBX-038 private JSON exceeded its byte bound");
  }
  await ensurePrivateDirectory(dirname(path));
  const noFollow = constants.O_NOFOLLOW ?? 0;
  const handle = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | noFollow, 0o600);
  let complete = false;
  try {
    await handle.chmod(0o600);
    await handle.writeFile(bytes, "utf8");
    await handle.sync();
    complete = true;
  } finally {
    await handle.close();
    if (!complete) await unlink(path).catch(() => undefined);
  }
  await syncDirectory(path);
  return (await privateFileIdentity(path)).mode;
}

async function readPrivateJson(path: string): Promise<unknown> {
  const before = await privateFileIdentity(path);
  const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const held = await handle.stat({ bigint: true });
    if (held.dev !== before.device || held.ino !== before.inode || held.size < 2n ||
        held.size > BigInt(MAXIMUM_PRIVATE_JSON_BYTES)) {
      throw new Error("SBX-038 private JSON changed identity or exceeded its byte bound");
    }
    return JSON.parse(await handle.readFile("utf8"));
  } finally { await handle.close(); }
}

async function replacePrivateFile(path: string, value: unknown, suffix: string): Promise<number> {
  await privateFileIdentity(path);
  const temporary = `${path}.${suffix}-${process.pid}-${randomUUID()}`;
  await writeNewPrivateFile(temporary, `${JSON.stringify(value, null, 2)}\n`);
  try {
    await rename(temporary, path);
    await syncDirectory(path);
    return (await privateFileIdentity(path)).mode;
  } catch (error) {
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

export async function acquireSbx038State(
  journal: Sbx038Journal,
  directory = SBX038_ARTIFACTS_DIRECTORY,
): Promise<Sbx038HeldState> {
  parseSbx038Journal(journal);
  await ensurePrivateDirectory(directory);
  const lockPath = sbx038LockPath(directory);
  const journalPath = sbx038JournalPath(journal.runId, directory);
  const liveLock = await acquireSbx038LiveLock(lockPath, journal.runId, false);
  try {
    const journalMode = await writeNewPrivateFile(journalPath, `${JSON.stringify(journal, null, 2)}\n`);
    return { runId: journal.runId, directory, lockPath, journalPath, liveLock,
      lockMode: (await privateFileIdentity(lockPath)).mode, journalMode };
  } catch (error) {
    await liveLock.release().catch(() => undefined);
    throw error;
  }
}

export async function persistSbx038Journal(
  held: Sbx038HeldState,
  journal: Sbx038Journal,
): Promise<void> {
  if (held.runId !== journal.runId || held.journalPath !== sbx038JournalPath(journal.runId, held.directory)) {
    throw new Error("SBX-038 lock and journal identities differed");
  }
  journal.updatedAt = new Date().toISOString();
  parseSbx038Journal(journal);
  await replacePrivateFile(held.journalPath, journal, "tmp");
}

export async function readSbx038Journal(
  runId: string,
  directory = SBX038_ARTIFACTS_DIRECTORY,
): Promise<Sbx038Journal> {
  const journal = parseSbx038Journal(await readPrivateJson(sbx038JournalPath(runId, directory)));
  if (journal.runId !== runId) throw new Error("SBX-038 journal changed run identity");
  return journal;
}

export async function acquireSbx038RecoveryState(
  runId: string,
  directory = SBX038_ARTIFACTS_DIRECTORY,
): Promise<Sbx038HeldState> {
  if (!SBX038_UUID.test(runId)) throw new Error("SBX-038 recovery requires a UUIDv4");
  const lockPath = sbx038LockPath(directory);
  await recoverSbx038InterruptedAcquire(lockPath, runId);
  await rollbackSbx038InterruptedRelease(lockPath, runId);
  const liveLock = await acquireSbx038LiveLock(lockPath, runId, true);
  const journalPath = sbx038JournalPath(runId, directory);
  try {
    await readSbx038Journal(runId, directory);
    return { runId, directory, lockPath, journalPath, liveLock,
      lockMode: (await privateFileIdentity(lockPath)).mode,
      journalMode: (await privateFileIdentity(journalPath)).mode };
  } catch (error) {
    await liveLock.closeRetainingState();
    throw error;
  }
}

export async function dispatchSbx038Recovery(
  runId: string,
  directory = SBX038_ARTIFACTS_DIRECTORY,
): Promise<Sbx038RecoveryDispatch> {
  if (!SBX038_UUID.test(runId)) throw new Error("SBX-038 recovery dispatcher requires a UUIDv4");
  const lockPath = sbx038LockPath(directory);
  const removal = await settleSbx038RemovalClaims(lockPath, runId);
  const transaction = await inspectSbx038PendingTransaction(lockPath, runId);
  let journalPresent = true;
  try { await privateFileIdentity(sbx038JournalPath(runId, directory)); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") journalPresent = false;
    else throw error;
  }
  if (transaction === undefined && removal.transactionOperation === "release" && !journalPresent) {
    return "release-finalization-complete";
  }
  if (transaction === undefined) {
    if (journalPresent) return "continue-journal-recovery";
    if (!await rollbackSbx038OrphanedNormalLock(lockPath, runId)) {
      throw new Error("SBX-038 found neither an exact journal nor a recoverable normal lock");
    }
    return "zero-external-state-acquire-rolled-back";
  }
  if (transaction.operation === "release") {
    if (journalPresent) return "continue-journal-recovery";
    if (!await resumeSbx038InterruptedRelease(lockPath, runId)) {
      throw new Error("SBX-038 interrupted release did not settle");
    }
    return "release-finalization-complete";
  }
  if (!await recoverSbx038InterruptedAcquire(lockPath, runId)) {
    throw new Error("SBX-038 interrupted acquire did not settle");
  }
  return journalPresent ? "continue-journal-recovery" : "zero-external-state-acquire-rolled-back";
}

export async function releaseSbx038State(held: Sbx038HeldState): Promise<void> {
  await held.liveLock.releaseAfter(async () => {
    const journal = await readSbx038Journal(held.runId, held.directory);
    if (!journal.completed || !sbx038JournalCleanupComplete(journal)) {
      throw new Error("SBX-038 refused release before exact cleanup completion");
    }
    await unlink(held.journalPath);
    await syncDirectory(held.journalPath);
  });
  if (!held.liveLock.isReleased()) throw new Error("SBX-038 restart-safe release did not complete");
}

export async function writeSbx038Checkpoint(
  runId: string,
  value: unknown,
  directory = SBX038_ARTIFACTS_DIRECTORY,
): Promise<number> {
  return writeNewPrivateFile(sbx038ArtifactPath(runId, directory), `${JSON.stringify(value, null, 2)}\n`);
}

export async function finalizeSbx038Artifact(
  runId: string,
  value: unknown,
  directory = SBX038_ARTIFACTS_DIRECTORY,
): Promise<number> {
  return replacePrivateFile(sbx038ArtifactPath(runId, directory), value, "final");
}

export async function writeSbx038RecoveryArtifact(
  runId: string,
  attemptId: string,
  value: unknown,
  directory = SBX038_ARTIFACTS_DIRECTORY,
): Promise<number> {
  return writeNewPrivateFile(
    sbx038RecoveryArtifactPath(runId, attemptId, directory),
    `${JSON.stringify(value, null, 2)}\n`,
  );
}

export async function finalizeSbx038RecoveryArtifact(
  runId: string,
  attemptId: string,
  value: unknown,
  directory = SBX038_ARTIFACTS_DIRECTORY,
): Promise<number> {
  return replacePrivateFile(sbx038RecoveryArtifactPath(runId, attemptId, directory), value, "final");
}

export async function sbx038PrivateFileMode(path: string): Promise<number> {
  return (await privateFileIdentity(path)).mode;
}

async function wait(dependencies: Sbx038AbsenceDependencies, milliseconds: number): Promise<void> {
  if (dependencies.wait) await dependencies.wait(milliseconds);
  else await new Promise((resolveWait) => setTimeout(resolveWait, milliseconds));
}

export async function proveSbx038SandboxAbsence(
  journal: Sbx038Journal,
  value: Sbx038ResourceJournal,
  dependencies: Sbx038AbsenceDependencies,
): Promise<boolean> {
  if (sbx038Resource(journal, value.role) !== value || value.createAttemptedAt === undefined) return false;
  value.absenceChecks = 0;
  value.prefixListAbsent = false;
  value.absenceOnlyValidated = false;
  const delays = dependencies.absenceDelaysMs ?? ABSENCE_DELAYS_MS;
  if (delays.length < 3 || delays.some((delay) => !Number.isSafeInteger(delay) || delay < 0)) return false;
  for (const delay of delays) {
    await wait(dependencies, delay);
    try {
      await dependencies.getSandbox(value.name);
      return false;
    } catch (error) {
      if (!dependencies.isNotFound(error)) return false;
      value.absenceChecks += 1;
      await dependencies.persist(journal);
    }
  }
  const listed = await dependencies.listSandboxes(value.name);
  if (listed.length !== 0) return false;
  value.prefixListAbsent = true;
  if (value.sessionId === undefined) {
    if (!sbx038UnknownCreateSettlementReached(value, dependencies.now?.() ?? Date.now())) return false;
    value.absenceOnlyValidated = true;
    value.deleted = true;
  }
  await dependencies.persist(journal);
  return true;
}

export function safeSbx038SafetyError(error: unknown, forbidden: readonly string[] = []): string {
  let message = error instanceof Error ? `${error.name}: ${error.message}` : "unknown error";
  for (const value of forbidden) if (value.length > 0) message = message.split(value).join("<redacted>");
  return message.replace(/[\0\r\n]/gu, " ").slice(0, 512);
}
