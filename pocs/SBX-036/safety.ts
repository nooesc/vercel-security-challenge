import { randomUUID } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, mkdir, open, rename, unlink } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  acquireSbx053LiveLock,
  rollbackSbx053InterruptedAcquire,
  rollbackSbx053InterruptedRelease,
  resumeSbx053InterruptedRelease,
  type Sbx053HeldLock,
} from "../SBX-053/live-lock.js";
import { SBX036_TEST_ID } from "./verdict.js";

export const SBX036_ARTIFACTS_DIRECTORY = fileURLToPath(new URL("../../artifacts", import.meta.url));
export const SBX036_LIVE_LOCK = resolve(SBX036_ARTIFACTS_DIRECTORY, "SBX-036-live-active.lock");
export const SBX036_SANDBOX_TIMEOUT_MS = 300_000 as const;
export const SBX036_CREATE_REQUEST_TIMEOUT_MS = 45_000 as const;
export const SBX036_CREATE_SETTLEMENT_MS =
  SBX036_CREATE_REQUEST_TIMEOUT_MS + SBX036_SANDBOX_TIMEOUT_MS + 30_000;
export const SBX036_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
export const SBX036_SESSION = /^sbx_[A-Za-z0-9_-]{20,100}$/u;
const ABSENCE_DELAYS_MS = [250, 1_000, 3_000] as const;

export type Sbx036StageRole = "public" | "secret";

export interface Sbx036StageJournal {
  role: Sbx036StageRole;
  runId: string;
  sandboxName: string;
  tags: Record<string, string>;
  persistent: false;
  timeoutMs: typeof SBX036_SANDBOX_TIMEOUT_MS;
  createAttemptedAt?: string;
  createResponseSettledAt?: string;
  provenanceValidated: boolean;
  sessionId?: string;
  secretWriteAttempted: boolean;
  secretNeutralizeAttempted: boolean;
  secretNeutralized: boolean;
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  absenceChecks: number;
  prefixListAbsent: boolean;
}

export interface Sbx036ReceiverJournal {
  role: Sbx036StageRole;
  runId: string;
  configureAttempted: boolean;
  configured: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  absenceChecks: number;
}

export interface Sbx036RecoveryJournal {
  schemaVersion: 1;
  testId: typeof SBX036_TEST_ID;
  rootRunId: string;
  startedAt: string;
  updatedAt: string;
  stages: [Sbx036StageJournal, Sbx036StageJournal];
  receivers: [Sbx036ReceiverJournal, Sbx036ReceiverJournal];
  completed: boolean;
  rawSecretsRetained: false;
  rawOperationsRetained: false;
}

export interface Sbx036HeldState {
  liveLock: Sbx053HeldLock;
  lockPath: string;
  journalPath: string;
  rootRunId: string;
  lockImplementationId: "SBX-053-GIT-CREDENTIAL-RETENTION";
}

export interface Sbx036SandboxView {
  name: string;
  persistent: boolean;
  tags: Record<string, string> | undefined;
  currentSessionId: string;
  status: string;
  stop(): Promise<void>;
  delete(): Promise<void>;
  neutralizeSecret(): Promise<void>;
}

export interface Sbx036SandboxListView {
  name: string;
  persistent: boolean;
  tags: Record<string, string> | undefined;
  currentSessionId: string;
}

export interface Sbx036CleanupDependencies {
  getSandbox(name: string): Promise<Sbx036SandboxView>;
  listSandboxes(namePrefix: string): Promise<Sbx036SandboxListView[]>;
  isNotFound(error: unknown): boolean;
  deleteReceiver(runId: string): Promise<boolean>;
  readReceiverConfigured(runId: string): Promise<boolean>;
  persist(journal: Sbx036RecoveryJournal): Promise<void>;
  wait?(milliseconds: number): Promise<void>;
  now?(): number;
  absenceDelaysMs?: readonly number[];
}

export interface Sbx036CleanupResult {
  complete: boolean;
  cleanupIndeterminate: boolean;
  errors: string[];
}

function timestamp(value: unknown): value is string {
  if (typeof value !== "string" || value.length !== 24) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
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
  if (actual === null || typeof actual !== "object" || Array.isArray(actual)) return false;
  const record = actual as Record<string, unknown>;
  const keys = Object.keys(expected);
  return Object.keys(record).length === keys.length && keys.every((key) => record[key] === expected[key]);
}

export function sbx036Tags(
  rootRunId: string,
  role: Sbx036StageRole,
  runId: string,
): Record<string, string> {
  if (!SBX036_UUID.test(rootRunId) || !SBX036_UUID.test(runId)) {
    throw new Error("SBX-036 tags require canonical UUIDv4 values");
  }
  return { harness: "vsc", test: SBX036_TEST_ID, root: rootRunId, run: runId, role };
}

export function sbx036SandboxName(role: Sbx036StageRole, runId: string): string {
  if (!SBX036_UUID.test(runId)) throw new Error("SBX-036 sandbox name requires a canonical UUIDv4");
  return `sbx-036-${role}-${runId.replaceAll("-", "")}`;
}

function stage(rootRunId: string, role: Sbx036StageRole, runId: string): Sbx036StageJournal {
  return {
    role,
    runId,
    sandboxName: sbx036SandboxName(role, runId),
    tags: sbx036Tags(rootRunId, role, runId),
    persistent: false,
    timeoutMs: SBX036_SANDBOX_TIMEOUT_MS,
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
  };
}

export function createSbx036Journal(input: {
  rootRunId?: string;
  publicRunId?: string;
  secretRunId?: string;
  now?: Date;
} = {}): Sbx036RecoveryJournal {
  const rootRunId = input.rootRunId ?? randomUUID();
  const publicRunId = input.publicRunId ?? randomUUID();
  const secretRunId = input.secretRunId ?? randomUUID();
  if (!SBX036_UUID.test(rootRunId) || !SBX036_UUID.test(publicRunId) ||
      !SBX036_UUID.test(secretRunId) || new Set([rootRunId, publicRunId, secretRunId]).size !== 3) {
    throw new Error("SBX-036 journal requires three distinct canonical UUIDv4 values");
  }
  const at = (input.now ?? new Date()).toISOString();
  return {
    schemaVersion: 1,
    testId: SBX036_TEST_ID,
    rootRunId,
    startedAt: at,
    updatedAt: at,
    stages: [stage(rootRunId, "public", publicRunId), stage(rootRunId, "secret", secretRunId)],
    receivers: [
      { role: "public", runId: publicRunId, configureAttempted: false, configured: false,
        deleteAttempted: false, deleted: false, absenceChecks: 0 },
      { role: "secret", runId: secretRunId, configureAttempted: false, configured: false,
        deleteAttempted: false, deleted: false, absenceChecks: 0 },
    ],
    completed: false,
    rawSecretsRetained: false,
    rawOperationsRetained: false,
  };
}

function parseStage(value: unknown, rootRunId: string, expectedRole: Sbx036StageRole): Sbx036StageJournal {
  if (value === null || typeof value !== "object" || Array.isArray(value) || !exactKeys(value, [
    "role", "runId", "sandboxName", "tags", "persistent", "timeoutMs", "provenanceValidated",
    "secretWriteAttempted", "secretNeutralizeAttempted", "secretNeutralized", "stopAttempted",
    "stopped", "deleteAttempted", "deleted", "absenceChecks", "prefixListAbsent",
  ], ["createAttemptedAt", "createResponseSettledAt", "sessionId"])) {
    throw new Error("SBX-036 stage journal fields were not exact");
  }
  const record = value as Record<string, unknown>;
  if (record.role !== expectedRole || typeof record.runId !== "string" || !SBX036_UUID.test(record.runId) ||
      record.sandboxName !== sbx036SandboxName(expectedRole, record.runId) ||
      !exactRecord(record.tags, sbx036Tags(rootRunId, expectedRole, record.runId)) ||
      record.persistent !== false || record.timeoutMs !== SBX036_SANDBOX_TIMEOUT_MS ||
      !(record.createAttemptedAt === undefined || timestamp(record.createAttemptedAt)) ||
      !(record.createResponseSettledAt === undefined || timestamp(record.createResponseSettledAt)) ||
      typeof record.provenanceValidated !== "boolean" ||
      !(record.sessionId === undefined || (typeof record.sessionId === "string" && SBX036_SESSION.test(record.sessionId))) ||
      typeof record.secretWriteAttempted !== "boolean" ||
      typeof record.secretNeutralizeAttempted !== "boolean" || typeof record.secretNeutralized !== "boolean" ||
      typeof record.stopAttempted !== "boolean" || typeof record.stopped !== "boolean" ||
      typeof record.deleteAttempted !== "boolean" || typeof record.deleted !== "boolean" ||
      !Number.isInteger(record.absenceChecks) || (record.absenceChecks as number) < 0 ||
      typeof record.prefixListAbsent !== "boolean" ||
      (record.provenanceValidated !== (record.sessionId !== undefined)) ||
      (record.createResponseSettledAt !== undefined && !record.provenanceValidated) ||
      (record.createAttemptedAt === undefined && (record.createResponseSettledAt !== undefined ||
        record.provenanceValidated || record.secretWriteAttempted || record.stopAttempted ||
        record.deleteAttempted || (record.absenceChecks as number) !== 0 || record.prefixListAbsent)) ||
      (record.stopped && !record.stopAttempted) || (record.deleteAttempted && !record.stopAttempted) ||
      (record.deleted && !record.deleteAttempted) ||
      ((record.absenceChecks as number) > 0 && !record.deleteAttempted && record.sessionId !== undefined) ||
      (record.prefixListAbsent && (record.absenceChecks as number) < 3) ||
      (record.secretWriteAttempted && expectedRole !== "secret") ||
      (record.secretNeutralizeAttempted && !record.secretWriteAttempted) ||
      (record.secretNeutralized && !record.secretNeutralizeAttempted)) {
    throw new Error("SBX-036 stage journal was invalid");
  }
  return record as unknown as Sbx036StageJournal;
}

function parseReceiver(value: unknown, expectedRole: Sbx036StageRole, runId: string): Sbx036ReceiverJournal {
  if (value === null || typeof value !== "object" || Array.isArray(value) || !exactKeys(value, [
    "role", "runId", "configureAttempted", "configured", "deleteAttempted", "deleted", "absenceChecks",
  ])) throw new Error("SBX-036 receiver journal fields were not exact");
  const record = value as Record<string, unknown>;
  if (record.role !== expectedRole || record.runId !== runId ||
      typeof record.configureAttempted !== "boolean" || typeof record.configured !== "boolean" ||
      typeof record.deleteAttempted !== "boolean" || typeof record.deleted !== "boolean" ||
      !Number.isInteger(record.absenceChecks) || (record.absenceChecks as number) < 0 ||
      (record.configured && !record.configureAttempted) || (record.deleted && !record.deleteAttempted)) {
    throw new Error("SBX-036 receiver journal was invalid");
  }
  return record as unknown as Sbx036ReceiverJournal;
}

export function parseSbx036Journal(value: unknown): Sbx036RecoveryJournal {
  if (value === null || typeof value !== "object" || Array.isArray(value) || !exactKeys(value, [
    "schemaVersion", "testId", "rootRunId", "startedAt", "updatedAt", "stages", "receivers",
    "completed", "rawSecretsRetained", "rawOperationsRetained",
  ])) throw new Error("SBX-036 recovery journal fields were not exact");
  const record = value as Record<string, unknown>;
  if (record.schemaVersion !== 1 || record.testId !== SBX036_TEST_ID ||
      typeof record.rootRunId !== "string" || !SBX036_UUID.test(record.rootRunId) ||
      !timestamp(record.startedAt) || !timestamp(record.updatedAt) ||
      Date.parse(record.updatedAt) < Date.parse(record.startedAt as string) ||
      !Array.isArray(record.stages) || record.stages.length !== 2 ||
      !Array.isArray(record.receivers) || record.receivers.length !== 2 ||
      typeof record.completed !== "boolean" || record.rawSecretsRetained !== false ||
      record.rawOperationsRetained !== false) throw new Error("SBX-036 recovery journal was invalid");
  const stages: [Sbx036StageJournal, Sbx036StageJournal] = [
    parseStage(record.stages[0], record.rootRunId, "public"),
    parseStage(record.stages[1], record.rootRunId, "secret"),
  ];
  const receivers: [Sbx036ReceiverJournal, Sbx036ReceiverJournal] = [
    parseReceiver(record.receivers[0], "public", stages[0].runId),
    parseReceiver(record.receivers[1], "secret", stages[1].runId),
  ];
  if (new Set([record.rootRunId, stages[0].runId, stages[1].runId]).size !== 3) {
    throw new Error("SBX-036 journal IDs were not distinct");
  }
  const journal = { ...(record as Omit<Sbx036RecoveryJournal, "stages" | "receivers">), stages, receivers };
  if (journal.completed && !sbx036JournalCleanupComplete(journal)) {
    throw new Error("SBX-036 completed journal lacked exact cleanup proof");
  }
  return journal;
}

export function sbx036JournalCleanupComplete(
  journal: Sbx036RecoveryJournal,
  now = Date.now(),
): boolean {
  const stageComplete = (value: Sbx036StageJournal): boolean => {
    if (value.createAttemptedAt === undefined) return true;
    const secretSafe = !value.secretWriteAttempted || value.secretNeutralized;
    if (!secretSafe || value.absenceChecks < 3 || !value.prefixListAbsent) return false;
    if (value.sessionId === undefined) return unknownSbx036CreateSettled(value, now);
    return value.provenanceValidated && value.stopAttempted && value.stopped &&
      value.deleteAttempted && value.deleted;
  };
  const receiverComplete = (value: Sbx036ReceiverJournal): boolean =>
    !value.configureAttempted || (value.deleteAttempted && value.deleted && value.absenceChecks >= 3);
  return journal.stages.every(stageComplete) && journal.receivers.every(receiverComplete);
}

export function exactSbx036ZeroExternalStateJournal(journal: Sbx036RecoveryJournal): boolean {
  try {
    parseSbx036Journal(journal);
  } catch {
    return false;
  }
  return journal.stages.every((stage) =>
    stage.createAttemptedAt === undefined && stage.createResponseSettledAt === undefined &&
    !stage.provenanceValidated && stage.sessionId === undefined && !stage.secretWriteAttempted &&
    !stage.secretNeutralizeAttempted && !stage.secretNeutralized && !stage.stopAttempted &&
    !stage.stopped && !stage.deleteAttempted && !stage.deleted && stage.absenceChecks === 0 &&
    !stage.prefixListAbsent) && journal.receivers.every((receiver) =>
    !receiver.configureAttempted && !receiver.configured && !receiver.deleteAttempted &&
    !receiver.deleted && receiver.absenceChecks === 0);
}

export function sbx036JournalPath(rootRunId: string, directory = SBX036_ARTIFACTS_DIRECTORY): string {
  if (!SBX036_UUID.test(rootRunId)) throw new Error("SBX-036 journal path requires UUIDv4");
  return resolve(directory, `SBX-036-recovery-${rootRunId}.json`);
}

export function sbx036ArtifactPath(rootRunId: string, directory = SBX036_ARTIFACTS_DIRECTORY): string {
  if (!SBX036_UUID.test(rootRunId)) throw new Error("SBX-036 artifact path requires UUIDv4");
  return resolve(directory, `SBX-036-${rootRunId}-private.json`);
}

export function sbx036RecoveryArtifactPath(
  rootRunId: string,
  attemptId: string,
  directory = SBX036_ARTIFACTS_DIRECTORY,
): string {
  if (!SBX036_UUID.test(rootRunId) || !SBX036_UUID.test(attemptId)) {
    throw new Error("SBX-036 recovery artifact requires UUIDv4 values");
  }
  return resolve(directory, `SBX-036-${rootRunId}-recovery-${attemptId}-private.json`);
}

async function exactPrivateFile(path: string): Promise<void> {
  const metadata = await lstat(path);
  const uid = process.getuid?.();
  if (uid === undefined) throw new Error("SBX-036 could not determine the current user ID");
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 ||
      (metadata.mode & 0o777) !== 0o600 || metadata.uid !== uid) {
    throw new Error("SBX-036 private state was not an owned mode-0600 single-link regular file");
  }
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(dirname(path), fsConstants.O_RDONLY);
  try { await handle.sync(); } finally { await handle.close(); }
}

async function readPrivateJson(path: string): Promise<unknown> {
  const before = await lstat(path);
  await exactPrivateFile(path);
  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  const handle = await open(path, fsConstants.O_RDONLY | noFollow);
  try {
    const held = await handle.stat();
    if (held.dev !== before.dev || held.ino !== before.ino || held.size < 2 || held.size > 64 * 1024) {
      throw new Error("SBX-036 private JSON changed identity or exceeded its bound");
    }
    return JSON.parse(await handle.readFile("utf8"));
  } finally {
    await handle.close();
  }
}

async function writeNewPrivateFile(path: string, bytes: string): Promise<void> {
  const parent = dirname(path);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const directory = await lstat(parent);
  const uid = process.getuid?.();
  if (uid === undefined || !directory.isDirectory() || directory.isSymbolicLink() ||
      directory.uid !== uid || (directory.mode & 0o777) !== 0o700) {
    throw new Error("SBX-036 private directory was not current-user-owned mode 0700");
  }
  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  const handle = await open(path, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | noFollow, 0o600);
  try {
    await handle.chmod(0o600);
    await handle.writeFile(bytes, "utf8");
    await handle.sync();
  } catch (error) {
    await handle.close().catch(() => undefined);
    await unlink(path).catch(() => undefined);
    throw error;
  }
  await handle.close();
  await exactPrivateFile(path);
  await syncDirectory(path);
}

export async function writeSbx036PrivateArtifact(path: string, value: unknown): Promise<void> {
  await writeNewPrivateFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

export async function acquireSbx036State(
  journal: Sbx036RecoveryJournal,
  directory = SBX036_ARTIFACTS_DIRECTORY,
): Promise<Sbx036HeldState> {
  parseSbx036Journal(journal);
  const lockPath = resolve(directory, "SBX-036-live-active.lock");
  const journalPath = sbx036JournalPath(journal.rootRunId, directory);
  const liveLock = await acquireSbx053LiveLock(lockPath, journal.rootRunId, false);
  try {
    await writeNewPrivateFile(journalPath, `${JSON.stringify(journal, null, 2)}\n`);
    return { liveLock, lockPath, journalPath, rootRunId: journal.rootRunId,
      lockImplementationId: "SBX-053-GIT-CREDENTIAL-RETENTION" };
  } catch (error) {
    await liveLock.release().catch(() => undefined);
    throw error;
  }
}

export async function readSbx036Journal(
  rootRunId: string,
  directory = SBX036_ARTIFACTS_DIRECTORY,
): Promise<Sbx036RecoveryJournal> {
  const path = sbx036JournalPath(rootRunId, directory);
  await exactPrivateFile(path);
  const journal = parseSbx036Journal(await readPrivateJson(path));
  if (journal.rootRunId !== rootRunId) throw new Error("SBX-036 journal root run changed");
  return journal;
}

export async function persistSbx036Journal(
  held: Sbx036HeldState,
  journal: Sbx036RecoveryJournal,
): Promise<void> {
  if (held.rootRunId !== journal.rootRunId || held.journalPath !== sbx036JournalPath(
    journal.rootRunId, dirname(held.journalPath),
  )) throw new Error("SBX-036 lock and journal were not bound to the same root run");
  journal.updatedAt = new Date().toISOString();
  parseSbx036Journal(journal);
  await exactPrivateFile(held.journalPath);
  const temporary = `${held.journalPath}.tmp-${process.pid}-${randomUUID()}`;
  await writeNewPrivateFile(temporary, `${JSON.stringify(journal, null, 2)}\n`);
  try {
    await rename(temporary, held.journalPath);
    await exactPrivateFile(held.journalPath);
    await syncDirectory(held.journalPath);
  } catch (error) {
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

export async function acquireSbx036RecoveryState(
  rootRunId: string,
  directory = SBX036_ARTIFACTS_DIRECTORY,
): Promise<Sbx036HeldState> {
  const lockPath = resolve(directory, "SBX-036-live-active.lock");
  const journalPath = sbx036JournalPath(rootRunId, directory);
  await rollbackSbx053InterruptedRelease(lockPath, rootRunId);
  const liveLock = await acquireSbx053LiveLock(lockPath, rootRunId, true);
  try {
    await exactPrivateFile(journalPath);
    await readSbx036Journal(rootRunId, directory);
    return { liveLock, lockPath, journalPath, rootRunId,
      lockImplementationId: "SBX-053-GIT-CREDENTIAL-RETENTION" };
  } catch (error) {
    await liveLock.closeRetainingState();
    throw error;
  }
}

export async function resumeSbx036InterruptedFinalization(
  rootRunId: string,
  directory = SBX036_ARTIFACTS_DIRECTORY,
): Promise<boolean> {
  const journalPath = sbx036JournalPath(rootRunId, directory);
  try {
    await lstat(journalPath);
    return false;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  return resumeSbx053InterruptedRelease(resolve(directory, "SBX-036-live-active.lock"), rootRunId);
}

export async function settleSbx036ZeroExternalStateLock(
  rootRunId: string,
  directory = SBX036_ARTIFACTS_DIRECTORY,
): Promise<boolean> {
  const journalPath = sbx036JournalPath(rootRunId, directory);
  try {
    await lstat(journalPath);
    return false;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const lockPath = resolve(directory, "SBX-036-live-active.lock");
  if (await rollbackSbx053InterruptedAcquire(lockPath, rootRunId)) return true;
  const exactDeadNormalLock = await acquireSbx053LiveLock(lockPath, rootRunId, true);
  await exactDeadNormalLock.release();
  return true;
}

export async function releaseSbx036State(held: Sbx036HeldState): Promise<void> {
  await held.liveLock.releaseAfter(async () => {
    await exactPrivateFile(held.journalPath);
    const journal = parseSbx036Journal(await readPrivateJson(held.journalPath));
    if (journal.rootRunId !== held.rootRunId || !journal.completed || !sbx036JournalCleanupComplete(journal)) {
      throw new Error("SBX-036 refused to release before exact cleanup completion");
    }
    await unlink(held.journalPath);
    await syncDirectory(held.journalPath);
  });
  if (!held.liveLock.isReleased()) throw new Error("SBX-036 live lock did not release");
}

export function exactSbx036SandboxProvenance(
  value: Sbx036SandboxView | Sbx036SandboxListView,
  expected: Sbx036StageJournal,
): boolean {
  return value.name === expected.sandboxName && value.persistent === false &&
    exactRecord(value.tags, expected.tags) && SBX036_SESSION.test(value.currentSessionId) &&
    (expected.sessionId === undefined || value.currentSessionId === expected.sessionId);
}

export function unknownSbx036CreateSettled(stageValue: Sbx036StageJournal, now = Date.now()): boolean {
  return stageValue.createAttemptedAt !== undefined && stageValue.sessionId === undefined &&
    now >= Date.parse(stageValue.createAttemptedAt) + SBX036_CREATE_SETTLEMENT_MS;
}

async function wait(dependencies: Sbx036CleanupDependencies, milliseconds: number): Promise<void> {
  if (dependencies.wait) await dependencies.wait(milliseconds);
  else await new Promise((resolveWait) => setTimeout(resolveWait, milliseconds));
}

async function recoverStageTarget(
  stageValue: Sbx036StageJournal,
  dependencies: Sbx036CleanupDependencies,
): Promise<Sbx036SandboxView | undefined> {
  const listed = await dependencies.listSandboxes(stageValue.sandboxName);
  if (listed.some((candidate) => candidate.name !== stageValue.sandboxName)) {
    throw new Error(`${stageValue.role} sandbox prefix list was not exact`);
  }
  const exactListed = listed.filter((candidate) => exactSbx036SandboxProvenance(candidate, stageValue));
  if (exactListed.length > 1 || listed.some((candidate) => candidate.name === stageValue.sandboxName &&
      !exactSbx036SandboxProvenance(candidate, stageValue))) {
    throw new Error(`${stageValue.role} sandbox list provenance was ambiguous`);
  }
  if (exactListed.length === 0) return undefined;
  const recovered = await dependencies.getSandbox(stageValue.sandboxName);
  if (!exactSbx036SandboxProvenance(recovered, stageValue) ||
      recovered.currentSessionId !== exactListed[0]!.currentSessionId) {
    throw new Error(`${stageValue.role} recovered sandbox failed exact get/list provenance`);
  }
  return recovered;
}

async function proveSandboxAbsence(
  journal: Sbx036RecoveryJournal,
  stageValue: Sbx036StageJournal,
  dependencies: Sbx036CleanupDependencies,
): Promise<boolean> {
  stageValue.absenceChecks = 0;
  stageValue.prefixListAbsent = false;
  const delays = dependencies.absenceDelaysMs ?? ABSENCE_DELAYS_MS;
  if (delays.length < 3 || delays.some((delay) => delay < 0)) return false;
  for (const delay of delays) {
    await wait(dependencies, delay);
    try {
      await dependencies.getSandbox(stageValue.sandboxName);
      return false;
    } catch (error) {
      if (!dependencies.isNotFound(error)) return false;
      stageValue.absenceChecks += 1;
      await dependencies.persist(journal);
    }
  }
  const listed = await dependencies.listSandboxes(stageValue.sandboxName);
  stageValue.prefixListAbsent = listed.length === 0;
  return stageValue.absenceChecks >= 3 && stageValue.prefixListAbsent;
}

async function cleanupStage(
  journal: Sbx036RecoveryJournal,
  stageValue: Sbx036StageJournal,
  supplied: Sbx036SandboxView | undefined,
  dependencies: Sbx036CleanupDependencies,
  errors: string[],
): Promise<boolean> {
  if (stageValue.createAttemptedAt === undefined) return true;
  if (stageValue.deleted && stageValue.absenceChecks >= 3 && stageValue.prefixListAbsent &&
      (!stageValue.secretWriteAttempted || stageValue.secretNeutralized)) return true;
  let target = supplied;
  if (target && !exactSbx036SandboxProvenance(target, stageValue)) {
    errors.push(`${stageValue.role} supplied sandbox failed exact provenance`);
    return false;
  }
  if (!target) {
    try { target = await recoverStageTarget(stageValue, dependencies); }
    catch (error) { errors.push(error instanceof Error ? error.message : "sandbox recovery failed"); return false; }
  }
  if (!target) {
    if (stageValue.sessionId !== undefined) {
      if (!stageValue.provenanceValidated || !stageValue.deleteAttempted) {
        errors.push(`${stageValue.role} known sandbox disappeared before a durable delete intent`);
        return false;
      }
      const absent = await proveSandboxAbsence(journal, stageValue, dependencies);
      if (!absent) {
        errors.push(`${stageValue.role} known sandbox delete lacked exact absence proof`);
        return false;
      }
      stageValue.stopped = true;
      stageValue.deleted = true;
      await dependencies.persist(journal);
      return true;
    }
    const settled = unknownSbx036CreateSettled(stageValue, (dependencies.now ?? Date.now)());
    if (!settled) {
      errors.push(`${stageValue.role} create response remained unsettled`);
      return false;
    }
    const absent = await proveSandboxAbsence(journal, stageValue, dependencies);
    if (!absent) errors.push(`${stageValue.role} settled unknown create lacked exact absence proof`);
    return absent;
  }
  if (!stageValue.provenanceValidated) {
    stageValue.sessionId = target.currentSessionId;
    stageValue.provenanceValidated = true;
    stageValue.createResponseSettledAt ??= new Date((dependencies.now ?? Date.now)()).toISOString();
    await dependencies.persist(journal);
  }
  if (stageValue.secretWriteAttempted && !stageValue.secretNeutralized) {
    stageValue.secretNeutralizeAttempted = true;
    await dependencies.persist(journal);
    try {
      await target.neutralizeSecret();
      stageValue.secretNeutralized = true;
      await dependencies.persist(journal);
    } catch {
      errors.push("secret neutralization response was unresolved");
      return false;
    }
  }
  if (!stageValue.stopped) {
    if (!stageValue.stopAttempted) {
      stageValue.stopAttempted = true;
      await dependencies.persist(journal);
    }
    if (target.status === "stopped") {
      stageValue.stopped = true;
      await dependencies.persist(journal);
    } else {
      try { await target.stop(); stageValue.stopped = true; await dependencies.persist(journal); }
      catch { /* A later exact stopped observation or deletion/absence settles response loss. */ }
    }
  }
  if (!stageValue.deleted) {
    if (!stageValue.deleteAttempted) {
      stageValue.deleteAttempted = true;
      await dependencies.persist(journal);
    }
    try { await target.delete(); stageValue.deleted = true; await dependencies.persist(journal); }
    catch { /* Three exact 404s plus prefix-list absence may settle response loss. */ }
  }
  const absent = await proveSandboxAbsence(journal, stageValue, dependencies);
  if (!absent) {
    errors.push(`${stageValue.role} sandbox absence proof was incomplete`);
    return false;
  }
  stageValue.stopped = true;
  stageValue.deleted = true;
  await dependencies.persist(journal);
  return true;
}

async function cleanupReceiver(
  journal: Sbx036RecoveryJournal,
  receiver: Sbx036ReceiverJournal,
  dependencies: Sbx036CleanupDependencies,
  errors: string[],
): Promise<boolean> {
  if (!receiver.configureAttempted) return true;
  if (receiver.deleted && receiver.absenceChecks >= 3) return true;
  if (!receiver.deleted) {
    if (!receiver.deleteAttempted) {
      receiver.deleteAttempted = true;
      await dependencies.persist(journal);
    }
    try { receiver.deleted = await dependencies.deleteReceiver(receiver.runId); }
    catch { /* configured:false readbacks can settle response loss */ }
    await dependencies.persist(journal);
  }
  receiver.absenceChecks = 0;
  const delays = dependencies.absenceDelaysMs ?? ABSENCE_DELAYS_MS;
  if (delays.length < 3) return false;
  for (const delay of delays) {
    await wait(dependencies, delay);
    try {
      if (await dependencies.readReceiverConfigured(receiver.runId)) {
        errors.push(`${receiver.role} receiver state remained configured`);
        return false;
      }
      receiver.absenceChecks += 1;
      await dependencies.persist(journal);
    } catch {
      errors.push(`${receiver.role} receiver absence readback failed`);
      return false;
    }
  }
  receiver.deleted = true;
  await dependencies.persist(journal);
  return true;
}

export async function cleanupSbx036Exact(input: {
  journal: Sbx036RecoveryJournal;
  sandboxes?: Partial<Record<Sbx036StageRole, Sbx036SandboxView>>;
  dependencies: Sbx036CleanupDependencies;
}): Promise<Sbx036CleanupResult> {
  const errors: string[] = [];
  const secret = await cleanupStage(input.journal, input.journal.stages[1], input.sandboxes?.secret,
    input.dependencies, errors);
  const publicStage = await cleanupStage(input.journal, input.journal.stages[0], input.sandboxes?.public,
    input.dependencies, errors);
  const secretReceiver = await cleanupReceiver(input.journal, input.journal.receivers[1], input.dependencies, errors);
  const publicReceiver = await cleanupReceiver(input.journal, input.journal.receivers[0], input.dependencies, errors);
  const complete = secret && publicStage && secretReceiver && publicReceiver && errors.length === 0 &&
    sbx036JournalCleanupComplete(input.journal, (input.dependencies.now ?? Date.now)());
  input.journal.completed = complete;
  await input.dependencies.persist(input.journal);
  return { complete, cleanupIndeterminate: !complete, errors };
}
