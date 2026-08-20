import { randomBytes, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { link, lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  acquireSbx026LiveLock,
  SBX026_LIVE_LOCK_PATH,
  type Sbx026LiveLock,
} from "../SBX-026/shared.js";
import { SBX056_TEST_ID } from "./verdict.js";

export const SBX056_ARTIFACTS_DIRECTORY = fileURLToPath(new URL("../../artifacts", import.meta.url));
export const SBX056_SANDBOX_TIMEOUT_MS = 180_000 as const;
export const SBX056_CREATE_TIMEOUT_MS = 45_000 as const;
export const SBX056_UNKNOWN_CREATE_SETTLEMENT_MS =
  SBX056_SANDBOX_TIMEOUT_MS + SBX056_CREATE_TIMEOUT_MS + 30_000;
export const SBX056_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SESSION = /^sbx_[A-Za-z0-9_-]{20,192}$/u;
const PROJECT = /^prj_[A-Za-z0-9]{8,128}$/u;

export type Sbx056Role = "control" | "victim";

export interface Sbx056TargetJournal {
  role: Sbx056Role;
  name: string;
  projectId: string;
  tags: Record<string, string>;
  createAttemptedAt?: string;
  createSettledAt?: string;
  sessionId?: string;
  provenanceValidated: boolean;
  zeroExternalStateConfirmed: boolean;
  absenceResolvedWithoutHandle: boolean;
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  exactNameAbsenceChecks: number;
  prefixAbsent: boolean;
}

export interface Sbx056Journal {
  schemaVersion: 1;
  testId: typeof SBX056_TEST_ID;
  runId: string;
  startedAt: string;
  updatedAt: string;
  ownerAuthorityPassed: boolean;
  scopedAuthorityPassed: boolean;
  publicControlPassed: boolean;
  victimMarkerStaged: boolean;
  crossReadDispatched: boolean;
  targets: [Sbx056TargetJournal, Sbx056TargetJournal];
  completed: boolean;
  rawTokensOrMarkersRetained: false;
}

export interface Sbx056HeldSafety {
  liveLock: Sbx026LiveLock;
  runId: string;
  journalPath: string;
  checkpointPath: string;
}

export interface Sbx056RecoverySafety {
  held: Sbx056HeldSafety;
  journal: Sbx056Journal;
  preJournalZeroStateRecovered: boolean;
}

export function sbx056MayReacquireFinalizationLock(
  journal: Sbx056Journal,
  canonicalLockAbsent: boolean,
  transactionAbsent: boolean,
): boolean {
  return journal.completed && canonicalLockAbsent && transactionAbsent &&
    journal.targets.every((target) => target.zeroExternalStateConfirmed ||
      target.absenceResolvedWithoutHandle || (target.provenanceValidated && target.stopped &&
        target.deleted && target.exactNameAbsenceChecks >= 2 && target.prefixAbsent));
}

function errorCode(error: unknown): string | undefined {
  return error !== null && typeof error === "object" && "code" in error &&
      typeof (error as { code?: unknown }).code === "string"
    ? (error as { code: string }).code
    : undefined;
}

async function pathAbsent(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return false;
  } catch (error) {
    if (errorCode(error) === "ENOENT") return true;
    throw error;
  }
}

function exactKeys(value: object, required: readonly string[], optional: readonly string[] = []): boolean {
  const keys = Object.keys(value);
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    keys.every((key) => allowed.has(key)) &&
    keys.length === required.length + optional.filter((key) =>
      Object.prototype.hasOwnProperty.call(value, key)).length;
}

function timestamp(value: unknown): value is string {
  if (typeof value !== "string" || value.length !== 24) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function exactRecord(value: unknown, expected: Record<string, string>): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(expected);
  return Object.keys(record).length === keys.length && keys.every((key) => record[key] === expected[key]);
}

export function sbx056Tags(runId: string, role: Sbx056Role): Record<string, string> {
  if (!SBX056_UUID.test(runId)) throw new Error("SBX-056 run ID was not canonical");
  return { harness: "vsc", test: SBX056_TEST_ID, run: runId, role };
}

export function sbx056Name(runId: string, role: Sbx056Role): string {
  if (!SBX056_UUID.test(runId)) throw new Error("SBX-056 run ID was not canonical");
  return `sbx-056-${role}-${runId}`;
}

export function sbx056FixedPath(runId: string, role: Sbx056Role): string {
  if (!SBX056_UUID.test(runId)) throw new Error("SBX-056 run ID was not canonical");
  return `/vercel/sandbox/.sbx-056-${role}-${runId.replaceAll("-", "")}.marker`;
}

export function sbx056JournalPath(runId: string): string {
  if (!SBX056_UUID.test(runId)) throw new Error("SBX-056 run ID was not canonical");
  return resolve(SBX056_ARTIFACTS_DIRECTORY, `SBX-056-${runId}-recovery.json`);
}

export function sbx056CheckpointPath(runId: string): string {
  if (!SBX056_UUID.test(runId)) throw new Error("SBX-056 run ID was not canonical");
  return resolve(SBX056_ARTIFACTS_DIRECTORY, `SBX-056-${runId}-checkpoint.json`);
}

export function sbx056ArtifactPath(runId: string): string {
  if (!SBX056_UUID.test(runId)) throw new Error("SBX-056 run ID was not canonical");
  return resolve(SBX056_ARTIFACTS_DIRECTORY, `SBX-056-${runId}-private.json`);
}

export function sbx056RecoveryArtifactPath(runId: string, attemptId: string): string {
  if (!SBX056_UUID.test(runId) || !SBX056_UUID.test(attemptId)) {
    throw new Error("SBX-056 recovery artifact IDs were not canonical UUIDv4 values");
  }
  return resolve(SBX056_ARTIFACTS_DIRECTORY,
    `SBX-056-${runId}-recovery-${attemptId}-private.json`);
}

function target(runId: string, role: Sbx056Role, projectId: string): Sbx056TargetJournal {
  if (!PROJECT.test(projectId)) throw new Error("SBX-056 project ID was invalid");
  return {
    role,
    name: sbx056Name(runId, role),
    projectId,
    tags: sbx056Tags(runId, role),
    provenanceValidated: false,
    zeroExternalStateConfirmed: false,
    absenceResolvedWithoutHandle: false,
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    exactNameAbsenceChecks: 0,
    prefixAbsent: false,
  };
}

export function createSbx056Journal(
  controlProjectId: string,
  victimProjectId: string,
  suppliedRunId: string = randomUUID(),
  now = new Date(),
): Sbx056Journal {
  if (!SBX056_UUID.test(suppliedRunId)) throw new Error("SBX-056 run ID was not canonical");
  if (controlProjectId === victimProjectId) throw new Error("SBX-056 projects must be distinct");
  const at = now.toISOString();
  return {
    schemaVersion: 1,
    testId: SBX056_TEST_ID,
    runId: suppliedRunId,
    startedAt: at,
    updatedAt: at,
    ownerAuthorityPassed: false,
    scopedAuthorityPassed: false,
    publicControlPassed: false,
    victimMarkerStaged: false,
    crossReadDispatched: false,
    targets: [target(suppliedRunId, "control", controlProjectId),
      target(suppliedRunId, "victim", victimProjectId)],
    completed: false,
    rawTokensOrMarkersRetained: false,
  };
}

function parseTarget(value: unknown, runId: string, role: Sbx056Role): Sbx056TargetJournal {
  if (value === null || typeof value !== "object" || Array.isArray(value) || !exactKeys(value, [
    "role", "name", "projectId", "tags", "provenanceValidated", "zeroExternalStateConfirmed",
    "absenceResolvedWithoutHandle", "stopAttempted", "stopped",
    "deleteAttempted", "deleted", "exactNameAbsenceChecks", "prefixAbsent",
  ], ["createAttemptedAt", "createSettledAt", "sessionId"])) {
    throw new Error("SBX-056 target journal fields were not exact");
  }
  const item = value as Record<string, unknown>;
  if (item.role !== role || item.name !== sbx056Name(runId, role) ||
      typeof item.projectId !== "string" || !PROJECT.test(item.projectId) ||
      !exactRecord(item.tags, sbx056Tags(runId, role)) ||
      !(item.createAttemptedAt === undefined || timestamp(item.createAttemptedAt)) ||
      !(item.createSettledAt === undefined || timestamp(item.createSettledAt)) ||
      (item.createSettledAt !== undefined && (item.createAttemptedAt === undefined ||
        Date.parse(item.createSettledAt as string) < Date.parse(item.createAttemptedAt as string))) ||
      !(item.sessionId === undefined || (typeof item.sessionId === "string" && SESSION.test(item.sessionId))) ||
      typeof item.provenanceValidated !== "boolean" || typeof item.stopAttempted !== "boolean" ||
      typeof item.zeroExternalStateConfirmed !== "boolean" ||
      typeof item.absenceResolvedWithoutHandle !== "boolean" ||
      typeof item.stopped !== "boolean" || typeof item.deleteAttempted !== "boolean" ||
      typeof item.deleted !== "boolean" || !Number.isSafeInteger(item.exactNameAbsenceChecks) ||
      (item.exactNameAbsenceChecks as number) < 0 || (item.exactNameAbsenceChecks as number) > 8 ||
      typeof item.prefixAbsent !== "boolean" ||
      (item.provenanceValidated && item.sessionId === undefined) ||
      (item.zeroExternalStateConfirmed && item.createAttemptedAt !== undefined) ||
      (item.absenceResolvedWithoutHandle && (item.createAttemptedAt === undefined ||
        (item.exactNameAbsenceChecks as number) < 2 || item.prefixAbsent !== true ||
        (!item.provenanceValidated && item.sessionId !== undefined))) ||
      (item.stopped && !item.stopAttempted) || (item.deleted && !item.deleteAttempted)) {
    throw new Error("SBX-056 target journal was invalid");
  }
  return item as unknown as Sbx056TargetJournal;
}

export function parseSbx056Journal(value: unknown): Sbx056Journal {
  if (value === null || typeof value !== "object" || Array.isArray(value) || !exactKeys(value, [
    "schemaVersion", "testId", "runId", "startedAt", "updatedAt", "ownerAuthorityPassed",
    "scopedAuthorityPassed", "publicControlPassed", "victimMarkerStaged", "crossReadDispatched",
    "targets", "completed", "rawTokensOrMarkersRetained",
  ])) throw new Error("SBX-056 journal fields were not exact");
  const item = value as Record<string, unknown>;
  if (item.schemaVersion !== 1 || item.testId !== SBX056_TEST_ID ||
      typeof item.runId !== "string" || !SBX056_UUID.test(item.runId) || !timestamp(item.startedAt) ||
      !timestamp(item.updatedAt) || Date.parse(item.updatedAt) < Date.parse(item.startedAt) ||
      typeof item.ownerAuthorityPassed !== "boolean" || typeof item.scopedAuthorityPassed !== "boolean" ||
      typeof item.publicControlPassed !== "boolean" || typeof item.victimMarkerStaged !== "boolean" ||
      typeof item.crossReadDispatched !== "boolean" || !Array.isArray(item.targets) ||
      item.targets.length !== 2 || typeof item.completed !== "boolean" ||
      item.rawTokensOrMarkersRetained !== false) throw new Error("SBX-056 journal was invalid");
  const targets = [parseTarget(item.targets[0], item.runId, "control"),
    parseTarget(item.targets[1], item.runId, "victim")] as [Sbx056TargetJournal, Sbx056TargetJournal];
  if (targets[0].projectId === targets[1].projectId ||
      (item.publicControlPassed && (!item.ownerAuthorityPassed || !item.scopedAuthorityPassed)) ||
      (item.victimMarkerStaged && !item.publicControlPassed) ||
      (item.crossReadDispatched && !item.victimMarkerStaged) ||
      (item.completed && !targets.every((entry) => entry.zeroExternalStateConfirmed ||
        entry.absenceResolvedWithoutHandle || (entry.provenanceValidated && entry.stopped && entry.deleted &&
          entry.exactNameAbsenceChecks >= 2 && entry.prefixAbsent)))) {
    throw new Error("SBX-056 journal relationships were invalid");
  }
  return { ...item, targets } as unknown as Sbx056Journal;
}

async function exactPrivate(path: string): Promise<void> {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 ||
      (metadata.mode & 0o777) !== 0o600) {
    throw new Error("SBX-056 private state must be a mode-0600 single-link regular file");
  }
}

async function syncDirectory(): Promise<void> {
  const handle = await open(SBX056_ARTIFACTS_DIRECTORY, constants.O_RDONLY);
  try { await handle.sync(); } finally { await handle.close(); }
}

async function writeTemporary(bytes: string, finalPath: string): Promise<string> {
  const temporary = `${finalPath}.tmp-${process.pid}-${randomBytes(16).toString("hex")}`;
  const handle = await open(temporary,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0), 0o600);
  try {
    await handle.chmod(0o600);
    await handle.writeFile(bytes, "utf8");
    await handle.sync();
  } finally { await handle.close(); }
  await exactPrivate(temporary);
  return temporary;
}

async function replacePrivate(path: string, value: unknown): Promise<void> {
  const temporary = await writeTemporary(`${JSON.stringify(value, null, 2)}\n`, path);
  try {
    await rename(temporary, path);
    await syncDirectory();
    await exactPrivate(path);
  } catch (error) {
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

export async function writeSbx056NoClobber(path: string, value: unknown): Promise<void> {
  const temporary = await writeTemporary(`${JSON.stringify(value, null, 2)}\n`, path);
  try {
    await link(temporary, path);
    await unlink(temporary);
    await syncDirectory();
    await exactPrivate(path);
  } catch (error) {
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

export async function acquireSbx056Safety(journal: Sbx056Journal, cleanupOnly = false): Promise<Sbx056HeldSafety> {
  await mkdir(SBX056_ARTIFACTS_DIRECTORY, { recursive: true, mode: 0o700 });
  const liveLock = await acquireSbx026LiveLock({
    scope: "session-command",
    lane: "project-scoped-read",
    runId: journal.runId,
    mode: cleanupOnly ? "cleanup-only" : "normal",
  });
  const journalPath = sbx056JournalPath(journal.runId);
  const held = { liveLock, runId: journal.runId, journalPath,
    checkpointPath: sbx056CheckpointPath(journal.runId) };
  try {
    if (cleanupOnly) {
      const parsed = parseSbx056Journal(JSON.parse(await readFile(journalPath, "utf8")));
      if (parsed.runId !== journal.runId || JSON.stringify(parsed) !== JSON.stringify(journal)) {
        throw new Error("SBX-056 recovery journal changed during lock acquisition");
      }
      await exactPrivate(journalPath);
    } else {
      await writeSbx056NoClobber(journalPath, journal);
    }
    return held;
  } catch (error) {
    if (!cleanupOnly) await liveLock.release().catch(() => undefined);
    throw error;
  }
}

export async function loadSbx056Recovery(runId: string): Promise<Sbx056Journal> {
  if (!SBX056_UUID.test(runId)) throw new Error("SBX-056 recovery run ID was not canonical");
  const path = sbx056JournalPath(runId);
  await exactPrivate(path);
  return parseSbx056Journal(JSON.parse(await readFile(path, "utf8")));
}

export async function acquireSbx056RecoverySafety(
  runId: string,
  controlProjectId: string,
  victimProjectId: string,
): Promise<Sbx056RecoverySafety> {
  if (!SBX056_UUID.test(runId)) throw new Error("SBX-056 recovery run ID was not canonical");
  await mkdir(SBX056_ARTIFACTS_DIRECTORY, { recursive: true, mode: 0o700 });
  const lockOptions = { scope: "session-command" as const, lane: "project-scoped-read", runId };
  let liveLock: Sbx026LiveLock;
  try {
    liveLock = await acquireSbx026LiveLock({ ...lockOptions, mode: "cleanup-only" });
  } catch (cleanupAcquireError) {
    const canonicalLockAbsent = await pathAbsent(SBX026_LIVE_LOCK_PATH);
    const transactionAbsent = await pathAbsent(`${SBX026_LIVE_LOCK_PATH}.transaction`);
    let journal: Sbx056Journal;
    try {
      await exactPrivate(sbx056JournalPath(runId));
      journal = parseSbx056Journal(JSON.parse(await readFile(sbx056JournalPath(runId), "utf8")));
    } catch {
      throw cleanupAcquireError;
    }
    if (journal.runId !== runId || journal.targets[0].projectId !== controlProjectId ||
        journal.targets[1].projectId !== victimProjectId ||
        !sbx056MayReacquireFinalizationLock(journal, canonicalLockAbsent, transactionAbsent)) {
      throw cleanupAcquireError;
    }
    liveLock = await acquireSbx026LiveLock({ ...lockOptions, mode: "normal" });
  }
  const held: Sbx056HeldSafety = {
    liveLock,
    runId,
    journalPath: sbx056JournalPath(runId),
    checkpointPath: sbx056CheckpointPath(runId),
  };
  const recovered = await recoverSbx056JournalAfterLock({
    journalPath: held.journalPath,
    runId,
    controlProjectId,
    victimProjectId,
  });
  return { held, ...recovered };
}

export async function recoverSbx056JournalAfterLock(input: {
  journalPath: string;
  runId: string;
  controlProjectId: string;
  victimProjectId: string;
}): Promise<Pick<Sbx056RecoverySafety, "journal" | "preJournalZeroStateRecovered">> {
  if (!SBX056_UUID.test(input.runId)) throw new Error("SBX-056 recovery run ID was not canonical");
  try {
    await exactPrivate(input.journalPath);
    const journal = parseSbx056Journal(JSON.parse(await readFile(input.journalPath, "utf8")));
    if (journal.runId !== input.runId || journal.targets[0].projectId !== input.controlProjectId ||
        journal.targets[1].projectId !== input.victimProjectId) {
      throw new Error("SBX-056 recovery journal identity did not match explicit configuration");
    }
    return { journal, preJournalZeroStateRecovered: false };
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw error;
    const journal = createSbx056Journal(input.controlProjectId, input.victimProjectId, input.runId);
    journal.targets[0].zeroExternalStateConfirmed = true;
    journal.targets[1].zeroExternalStateConfirmed = true;
    journal.completed = true;
    await writeSbx056NoClobber(input.journalPath, journal);
    return { journal, preJournalZeroStateRecovered: true };
  }
}

export async function persistSbx056Journal(held: Sbx056HeldSafety, journal: Sbx056Journal): Promise<void> {
  if (held.runId !== journal.runId || held.journalPath !== sbx056JournalPath(journal.runId)) {
    throw new Error("SBX-056 journal ownership changed");
  }
  journal.updatedAt = new Date().toISOString();
  parseSbx056Journal(journal);
  await replacePrivate(held.journalPath, journal);
}

export function sbx056UnknownCreateSettled(target: Sbx056TargetJournal, now = Date.now()): boolean {
  return target.createAttemptedAt !== undefined &&
    now >= Date.parse(target.createAttemptedAt) + SBX056_UNKNOWN_CREATE_SETTLEMENT_MS;
}

export async function finalizeSbx056Safety(input: {
  held: Sbx056HeldSafety;
  journal: Sbx056Journal;
  checkpoint: unknown;
  finalArtifact: unknown;
  artifactPath?: string;
  mutationHook?: (stage: "checkpoint-written" | "lock-released" | "artifact-written" |
    "checkpoint-removed" | "journal-removed") => void | Promise<void>;
}): Promise<void> {
  if (!input.journal.completed) throw new Error("SBX-056 cannot release safety state before cleanup completion");
  await persistSbx056Journal(input.held, input.journal);
  await replacePrivate(input.held.checkpointPath, input.checkpoint);
  await input.mutationHook?.("checkpoint-written");
  await input.held.liveLock.release();
  await input.mutationHook?.("lock-released");
  await writeSbx056NoClobber(input.artifactPath ?? sbx056ArtifactPath(input.journal.runId),
    input.finalArtifact);
  await input.mutationHook?.("artifact-written");
  await unlink(input.held.checkpointPath);
  await input.mutationHook?.("checkpoint-removed");
  await unlink(input.held.journalPath);
  await input.mutationHook?.("journal-removed");
  await syncDirectory();
}

export async function closeSbx056RetainingState(held: Sbx056HeldSafety): Promise<void> {
  // Closing the process while retaining the lock+journal is the fail-closed recovery protocol.
  void held;
}
