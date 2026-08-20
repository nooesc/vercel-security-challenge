import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { isIP } from "node:net";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  acquireSbx057LiveLock,
  inspectSbx057PendingTransaction,
  recoverSbx057InterruptedAcquire,
  resumeSbx057InterruptedRelease,
  rollbackSbx057InterruptedRelease,
  rollbackSbx057OrphanedNormalLock,
  settleSbx057RemovalClaims,
  type Sbx057HeldLock as AtomicHeldLock,
} from "./live-lock.js";
import { SBX057_TEST_ID, SBX057_UUID, type Sbx057Stage } from "./protocol.js";

export const SBX057_ALIAS = "swve@wearehackerone.com" as const;
export const SBX057_TEAM = "team_n98ERpVwV7HqmWRudAyK8sXQ" as const;
export const SBX057_PROJECT = "prj_CyyVykdN06Nrkla6KidZcecLgbCa" as const;
export const SBX057_SCOPE_CONFIRMATION =
  "I_CONTROL_BOTH_SBX057_ORIGINS_AND_AUTHORIZE_ONE_BOUNDED_WILDCARD_TRANSFORM_ISOLATION_TEST" as const;
export const SBX057_SANDBOX_TIMEOUT_MS = 180_000 as const;
export const SBX057_CREATE_REQUEST_TIMEOUT_MS = 45_000 as const;
export const SBX057_UNKNOWN_CREATE_SETTLEMENT_MS =
  SBX057_SANDBOX_TIMEOUT_MS + SBX057_CREATE_REQUEST_TIMEOUT_MS + 15_000;
export const SBX057_ARTIFACTS = fileURLToPath(new URL("../../artifacts", import.meta.url));
export const SBX057_LOCK_PATH = resolve(SBX057_ARTIFACTS, "SBX-057-live-active.lock");

export interface Sbx057Config {
  token: string;
  teamId: typeof SBX057_TEAM;
  projectId: typeof SBX057_PROJECT;
  alias: typeof SBX057_ALIAS;
  aOrigin: URL;
  bOrigin: URL;
  adminOrigin: URL;
  adminKey: string;
  actionKey: string;
  recoveryRunId?: string;
}

export interface Sbx057JournalResource {
  role: Sbx057Stage;
  name: string;
  tags: Record<string, string>;
  createAttemptedAt?: string;
  createSettledAt?: string;
  sessionId?: string;
  provenanceValidated: boolean;
  absenceOnlyValidated: boolean;
  stopAttempted: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  absenceChecks: number;
}

export interface Sbx057Journal {
  schemaVersion: 1;
  testId: typeof SBX057_TEST_ID;
  runId: string;
  startedAt: string;
  updatedAt: string;
  phase: "pre-create" | "comparator" | "target" | "cleanup" | "completed";
  receiverConfigureAttempted: boolean;
  receiverConfigured: boolean;
  receiverDeleted: boolean;
  resources: [Sbx057JournalResource, Sbx057JournalResource];
  completed: boolean;
  rawSecretsRetained: false;
}

export interface Sbx057HeldLock {
  runId: string;
  lockPath: string;
  journalPath: string;
  lockMode: number;
  journalMode: number;
  liveLock: AtomicHeldLock;
}

export type Sbx057RecoveryDispatch =
  | "continue-journal-recovery"
  | "release-finalization-complete"
  | "zero-external-state-acquire-rolled-back";

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function exactKey(value: string, name: string): string {
  if (Buffer.byteLength(value) < 32 || Buffer.byteLength(value) > 256 ||
      !/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error(`${name} must be one bounded opaque key`);
  return value;
}

function publicOrigin(raw: string, name: string): URL {
  const value = new URL(raw);
  if (value.origin !== raw || value.protocol !== "https:" || value.port !== "" ||
      value.username !== "" || value.password !== "" || value.pathname !== "/" ||
      value.search !== "" || value.hash !== "" || value.hostname !== value.hostname.toLowerCase() ||
      value.hostname.endsWith(".") || !value.hostname.endsWith(".trycloudflare.com") ||
      isIP(value.hostname) !== 0) throw new Error(`${name} must be one canonical Quick Tunnel HTTPS origin`);
  return value;
}

function adminOrigin(raw: string): URL {
  const value = new URL(raw);
  if (value.origin !== raw || value.protocol !== "http:" || value.hostname !== "127.0.0.1" ||
      !/^[0-9]{1,5}$/u.test(value.port) || Number(value.port) < 1 || Number(value.port) > 65_535 ||
      value.username !== "" || value.password !== "" || value.pathname !== "/" ||
      value.search !== "" || value.hash !== "") throw new Error("SBX057_ADMIN_ORIGIN was not exact loopback HTTP");
  return value;
}

export function requireStrictSbx057Environment(environment: NodeJS.ProcessEnv = process.env): void {
  if (environment.NODE_TLS_REJECT_UNAUTHORIZED === "0" || environment.NODE_OPTIONS) {
    throw new Error("SBX-057 refuses TLS or runtime injection overrides");
  }
}

export function loadSbx057Config(environment: NodeJS.ProcessEnv = process.env): Sbx057Config {
  requireStrictSbx057Environment(environment);
  if (environment.SBX057_SCOPE_CONFIRMATION !== SBX057_SCOPE_CONFIRMATION ||
      environment.SBX057_ALIAS_EMAIL_CONFIRMATION !== SBX057_ALIAS ||
      environment.VERCEL_TEAM_ID !== SBX057_TEAM || environment.VERCEL_PROJECT_ID !== SBX057_PROJECT) {
    throw new Error("SBX-057 exact scope and eligible identity confirmation were absent");
  }
  const token = required(environment, "VERCEL_TOKEN");
  if (token.length < 20 || token.length > 4_096 || /[\0\r\n\s]/u.test(token) ||
      token.split(".").length === 3) throw new Error("SBX-057 requires one bounded non-JWT Vercel PAT");
  const adminKey = exactKey(required(environment, "SBX057_ADMIN_KEY"), "SBX057_ADMIN_KEY");
  const actionKey = exactKey(required(environment, "SBX057_ACTION_KEY"), "SBX057_ACTION_KEY");
  if (adminKey === actionKey) throw new Error("SBX-057 keys must be distinct");
  const aOrigin = publicOrigin(required(environment, "SBX057_A_PUBLIC_ORIGIN"), "SBX057_A_PUBLIC_ORIGIN");
  const bOrigin = publicOrigin(required(environment, "SBX057_B_PUBLIC_ORIGIN"), "SBX057_B_PUBLIC_ORIGIN");
  if (aOrigin.hostname === bOrigin.hostname) throw new Error("SBX-057 A and B origins must be distinct");
  const recoveryRunId = environment.SBX057_RECOVERY_RUN_ID;
  if (recoveryRunId !== undefined && !SBX057_UUID.test(recoveryRunId)) {
    throw new Error("SBX057_RECOVERY_RUN_ID must be a canonical UUIDv4");
  }
  return {
    token,
    teamId: SBX057_TEAM,
    projectId: SBX057_PROJECT,
    alias: SBX057_ALIAS,
    aOrigin,
    bOrigin,
    adminOrigin: adminOrigin(environment.SBX057_ADMIN_ORIGIN ?? "http://127.0.0.1:43159"),
    adminKey,
    actionKey,
    ...(recoveryRunId === undefined ? {} : { recoveryRunId }),
  };
}

export function sbx057Name(role: Sbx057Stage, runId: string): string {
  if (!SBX057_UUID.test(runId)) throw new Error("SBX-057 resource name requires a canonical UUIDv4");
  return `sbx-057-${role}-${runId}`;
}

export function sbx057Tags(role: Sbx057Stage, runId: string): Record<string, string> {
  return { harness: "vsc", test: SBX057_TEST_ID, run: runId, role };
}

export function sbx057JournalPath(runId: string): string {
  if (!SBX057_UUID.test(runId)) throw new Error("SBX-057 journal path requires a canonical UUIDv4");
  return resolve(SBX057_ARTIFACTS, `SBX-057-${runId}-recovery.json`);
}

export function sbx057ArtifactPath(runId: string): string {
  if (!SBX057_UUID.test(runId)) throw new Error("SBX-057 artifact path requires a canonical UUIDv4");
  return resolve(SBX057_ARTIFACTS, `SBX-057-${runId}-private.json`);
}

export function sbx057RecoveryArtifactPath(runId: string, attemptId: string): string {
  if (!SBX057_UUID.test(runId) || !SBX057_UUID.test(attemptId)) {
    throw new Error("SBX-057 recovery artifact path requires canonical UUIDv4 values");
  }
  return resolve(SBX057_ARTIFACTS, `SBX-057-${runId}-recovery-${attemptId}-private.json`);
}

function resource(role: Sbx057Stage, runId: string): Sbx057JournalResource {
  return {
    role,
    name: sbx057Name(role, runId),
    tags: sbx057Tags(role, runId),
    provenanceValidated: false,
    absenceOnlyValidated: false,
    stopAttempted: false,
    deleteAttempted: false,
    deleted: false,
    absenceChecks: 0,
  };
}

export function createSbx057Journal(now = new Date(), suppliedRunId?: string): Sbx057Journal {
  const runId = suppliedRunId ?? randomUUID();
  if (!SBX057_UUID.test(runId)) throw new Error("SBX-057 journal run ID was invalid");
  const at = now.toISOString();
  return {
    schemaVersion: 1,
    testId: SBX057_TEST_ID,
    runId,
    startedAt: at,
    updatedAt: at,
    phase: "pre-create",
    receiverConfigureAttempted: false,
    receiverConfigured: false,
    receiverDeleted: false,
    resources: [resource("comparator", runId), resource("target", runId)],
    completed: false,
    rawSecretsRetained: false,
  };
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function exactKeys(value: object, required: readonly string[], optional: readonly string[] = []): boolean {
  const actual = Object.keys(value);
  const permitted = new Set([...required, ...optional]);
  return required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    actual.every((key) => permitted.has(key)) && actual.length === required.length +
      optional.filter((key) => Object.prototype.hasOwnProperty.call(value, key)).length;
}

function timestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value;
}

function exactTags(value: unknown, expected: Record<string, string>): boolean {
  const root = object(value);
  return root !== undefined && exactKeys(root, Object.keys(expected)) &&
    Object.entries(expected).every(([key, expectedValue]) => root[key] === expectedValue);
}

export function parseSbx057Journal(value: unknown): Sbx057Journal {
  const root = object(value);
  if (root === undefined || !exactKeys(root, [
    "schemaVersion", "testId", "runId", "startedAt", "updatedAt", "phase",
    "receiverConfigureAttempted", "receiverConfigured", "receiverDeleted", "resources",
    "completed", "rawSecretsRetained",
  ]) || root.schemaVersion !== 1 || root.testId !== SBX057_TEST_ID ||
      typeof root.runId !== "string" || !SBX057_UUID.test(root.runId) ||
      !timestamp(root.startedAt) || !timestamp(root.updatedAt) ||
      !["pre-create", "comparator", "target", "cleanup", "completed"].includes(String(root.phase)) ||
      typeof root.receiverConfigureAttempted !== "boolean" || typeof root.receiverConfigured !== "boolean" ||
      typeof root.receiverDeleted !== "boolean" || typeof root.completed !== "boolean" ||
      root.rawSecretsRetained !== false || !Array.isArray(root.resources) || root.resources.length !== 2) {
    throw new Error("SBX-057 journal was not exact");
  }
  const roles: Sbx057Stage[] = ["comparator", "target"];
  const resources = root.resources.map((value, index): Sbx057JournalResource => {
    const item = object(value);
    const role = roles[index]!;
    if (item === undefined || !exactKeys(item, [
      "role", "name", "tags", "provenanceValidated", "stopAttempted", "deleteAttempted",
      "deleted", "absenceChecks", "absenceOnlyValidated",
    ], ["createAttemptedAt", "createSettledAt", "sessionId"]) || item.role !== role ||
        item.name !== sbx057Name(role, root.runId as string) ||
        !exactTags(item.tags, sbx057Tags(role, root.runId as string)) ||
        !(item.createAttemptedAt === undefined || timestamp(item.createAttemptedAt)) ||
        !(item.createSettledAt === undefined || timestamp(item.createSettledAt)) ||
        !(item.sessionId === undefined || (typeof item.sessionId === "string" &&
          /^sbx_[A-Za-z0-9_-]{20,100}$/u.test(item.sessionId))) ||
        typeof item.provenanceValidated !== "boolean" || typeof item.absenceOnlyValidated !== "boolean" ||
        typeof item.stopAttempted !== "boolean" ||
        typeof item.deleteAttempted !== "boolean" || typeof item.deleted !== "boolean" ||
        typeof item.absenceChecks !== "number" || !Number.isInteger(item.absenceChecks) ||
        item.absenceChecks < 0 || (item.provenanceValidated && item.sessionId === undefined) ||
        (item.absenceOnlyValidated && (item.createAttemptedAt === undefined || item.sessionId !== undefined ||
          item.provenanceValidated || !item.deleted || item.absenceChecks < 3)) ||
        (item.deleted && (!item.provenanceValidated && !item.absenceOnlyValidated || item.absenceChecks < 3))) {
      throw new Error("SBX-057 journal resource was not exact");
    }
    return item as unknown as Sbx057JournalResource;
  });
  if ((root.receiverConfigured && !root.receiverConfigureAttempted) ||
      (root.completed && (root.phase !== "completed" || !root.receiverDeleted ||
        resources.some((entry) => entry.createAttemptedAt !== undefined && !entry.deleted)))) {
    throw new Error("SBX-057 journal lifecycle was inconsistent");
  }
  return { ...root, resources } as unknown as Sbx057Journal;
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(dirname(path), constants.O_RDONLY | (constants.O_DIRECTORY ?? 0));
  try { await handle.sync(); } finally { await handle.close(); }
}

async function privateMode(path: string): Promise<number> {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600) {
    throw new Error("SBX-057 private state was not a mode-0600 single-link regular file");
  }
  return stat.mode & 0o777;
}

async function writeNew(path: string, value: string): Promise<number> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const handle = await open(path, "wx", 0o600);
  try {
    await handle.chmod(0o600);
    await handle.writeFile(value, "utf8");
    await handle.sync();
  } finally { await handle.close(); }
  await syncDirectory(path);
  return privateMode(path);
}

export async function acquireSbx057Lock(journal: Sbx057Journal): Promise<Sbx057HeldLock> {
  parseSbx057Journal(journal);
  await mkdir(SBX057_ARTIFACTS, { recursive: true, mode: 0o700 });
  const journalPath = sbx057JournalPath(journal.runId);
  const liveLock = await acquireSbx057LiveLock(SBX057_LOCK_PATH, journal.runId, false);
  try {
    const journalMode = await writeNew(journalPath, `${JSON.stringify(journal, null, 2)}\n`);
    return {
      runId: journal.runId,
      lockPath: SBX057_LOCK_PATH,
      journalPath,
      lockMode: await privateMode(SBX057_LOCK_PATH),
      journalMode,
      liveLock,
    };
  } catch (error) {
    await liveLock.release().catch(() => undefined);
    throw error;
  }
}

export async function persistSbx057Journal(lock: Sbx057HeldLock, journal: Sbx057Journal): Promise<void> {
  if (lock.runId !== journal.runId || lock.journalPath !== sbx057JournalPath(journal.runId)) {
    throw new Error("SBX-057 journal/lock identity mismatch");
  }
  journal.updatedAt = new Date().toISOString();
  parseSbx057Journal(journal);
  const temporary = `${lock.journalPath}.tmp-${randomUUID()}`;
  await writeNew(temporary, `${JSON.stringify(journal, null, 2)}\n`);
  try {
    await rename(temporary, lock.journalPath);
    await syncDirectory(lock.journalPath);
    await privateMode(lock.journalPath);
  } catch (error) {
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

export async function readSbx057Journal(runId: string): Promise<Sbx057Journal> {
  const path = sbx057JournalPath(runId);
  await privateMode(path);
  return parseSbx057Journal(JSON.parse(await readFile(path, "utf8")));
}

export async function acquireSbx057RecoveryLock(runId: string): Promise<Sbx057HeldLock> {
  await recoverSbx057InterruptedAcquire(SBX057_LOCK_PATH, runId);
  await rollbackSbx057InterruptedRelease(SBX057_LOCK_PATH, runId);
  const journalPath = sbx057JournalPath(runId);
  const liveLock = await acquireSbx057LiveLock(SBX057_LOCK_PATH, runId, true);
  try {
    const journal = await readSbx057Journal(runId);
    if (journal.runId !== runId) throw new Error("SBX-057 recovery journal changed identity");
    return { runId, lockPath: SBX057_LOCK_PATH, journalPath,
      lockMode: await privateMode(SBX057_LOCK_PATH), journalMode: await privateMode(journalPath), liveLock };
  } catch (error) {
    await liveLock.closeRetainingState();
    throw error;
  }
}

export async function dispatchSbx057Recovery(runId: string): Promise<Sbx057RecoveryDispatch> {
  if (!SBX057_UUID.test(runId)) throw new Error("SBX-057 recovery dispatcher requires a UUIDv4");
  const removal = await settleSbx057RemovalClaims(SBX057_LOCK_PATH, runId);
  const transaction = await inspectSbx057PendingTransaction(SBX057_LOCK_PATH, runId);
  let journalPresent = true;
  try { await privateMode(sbx057JournalPath(runId)); } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") journalPresent = false;
    else throw error;
  }
  if (transaction === undefined && removal.transactionOperation === "release" && !journalPresent) {
    return "release-finalization-complete";
  }
  if (transaction === undefined) {
    if (journalPresent) return "continue-journal-recovery";
    if (!await rollbackSbx057OrphanedNormalLock(SBX057_LOCK_PATH, runId)) {
      throw new Error("SBX-057 recovery found no exact journal or orphaned normal lock");
    }
    return "zero-external-state-acquire-rolled-back";
  }
  if (transaction.operation === "release") {
    if (journalPresent) return "continue-journal-recovery";
    if (!await resumeSbx057InterruptedRelease(SBX057_LOCK_PATH, runId)) {
      throw new Error("SBX-057 release finalization did not settle");
    }
    return "release-finalization-complete";
  }
  if (!await recoverSbx057InterruptedAcquire(SBX057_LOCK_PATH, runId)) {
    throw new Error("SBX-057 interrupted acquire did not settle");
  }
  return journalPresent ? "continue-journal-recovery" : "zero-external-state-acquire-rolled-back";
}

export async function releaseSbx057LockAndJournal(lock: Sbx057HeldLock): Promise<void> {
  await lock.liveLock.releaseAfter(async () => {
    await unlink(lock.journalPath);
    await syncDirectory(lock.journalPath);
  });
  if (!lock.liveLock.isReleased()) throw new Error("SBX-057 atomic release did not complete");
}

export async function writeSbx057Artifact(runId: string, value: unknown): Promise<number> {
  return writeNew(sbx057ArtifactPath(runId), `${JSON.stringify(value, null, 2)}\n`);
}

/**
 * Replaces only a previously-created private checkpoint at the same exact path.
 * A crash before this rename leaves the fail-closed checkpoint durable; a crash
 * after it leaves the complete final artifact durable.
 */
export async function finalizeSbx057Artifact(runId: string, value: unknown): Promise<number> {
  const destination = sbx057ArtifactPath(runId);
  await privateMode(destination);
  const temporary = `${destination}.final-${randomUUID()}`;
  await writeNew(temporary, `${JSON.stringify(value, null, 2)}\n`);
  try {
    await rename(temporary, destination);
    await syncDirectory(destination);
    return privateMode(destination);
  } catch (error) {
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

export async function writeSbx057RecoveryArtifact(
  runId: string,
  attemptId: string,
  value: unknown,
): Promise<number> {
  return writeNew(sbx057RecoveryArtifactPath(runId, attemptId), `${JSON.stringify(value, null, 2)}\n`);
}

export async function finalizeSbx057RecoveryArtifact(
  runId: string,
  attemptId: string,
  value: unknown,
): Promise<number> {
  const destination = sbx057RecoveryArtifactPath(runId, attemptId);
  await privateMode(destination);
  const temporary = `${destination}.final-${randomUUID()}`;
  await writeNew(temporary, `${JSON.stringify(value, null, 2)}\n`);
  try {
    await rename(temporary, destination);
    await syncDirectory(destination);
    return privateMode(destination);
  } catch (error) {
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

export async function sbx057PrivateMode(path: string): Promise<number> {
  return privateMode(path);
}

export function safeSbx057Error(error: unknown, forbidden: readonly string[] = []): string {
  let message = error instanceof Error ? `${error.name}: ${error.message}` : "unknown error";
  for (const value of forbidden) if (value.length > 0) message = message.split(value).join("<redacted>");
  return message.replace(/[\0\r\n]/gu, " ").slice(0, 512);
}

export function createSettlementReached(resource: Sbx057JournalResource, now = Date.now()): boolean {
  return resource.createAttemptedAt !== undefined &&
    now >= Date.parse(resource.createAttemptedAt) + SBX057_UNKNOWN_CREATE_SETTLEMENT_MS;
}

export function zeroExternalState(journal: Sbx057Journal): boolean {
  return journal.phase === "pre-create" && !journal.receiverConfigureAttempted &&
    journal.resources.every((entry) => entry.createAttemptedAt === undefined && entry.sessionId === undefined &&
      !entry.stopAttempted && !entry.deleteAttempted && !entry.deleted && entry.absenceChecks === 0);
}
