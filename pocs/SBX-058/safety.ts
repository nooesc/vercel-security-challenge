import { randomBytes, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { link, lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  SBX026_LIVE_LOCK_PATH,
  acquireSbx026LiveLock,
  type Sbx026LiveLock,
} from "../SBX-026/shared.js";
import { SBX058_TEST_ID, SBX058_UUID } from "./protocol.js";

export const SBX058_ALIAS = "swve@wearehackerone.com" as const;
export const SBX058_TEAM = "team_n98ERpVwV7HqmWRudAyK8sXQ" as const;
export const SBX058_PROJECT = "prj_CyyVykdN06Nrkla6KidZcecLgbCa" as const;
export const SBX058_SCOPE_CONFIRMATION =
  "I_CONTROL_BOTH_SBX058_ORIGINS_AND_AUTHORIZE_ONE_BOUNDED_HEADER_ENTRY_BINDING_TEST" as const;
export const SBX058_SANDBOX_TIMEOUT_MS = 180_000 as const;
export const SBX058_CREATE_TIMEOUT_MS = 45_000 as const;
export const SBX058_UNKNOWN_CREATE_SETTLEMENT_MS =
  SBX058_SANDBOX_TIMEOUT_MS + SBX058_CREATE_TIMEOUT_MS + 30_000;
export const SBX058_ARTIFACTS = fileURLToPath(new URL("../../artifacts", import.meta.url));

export interface Sbx058Config {
  token: string;
  teamId: typeof SBX058_TEAM;
  projectId: typeof SBX058_PROJECT;
  aliasEmail: typeof SBX058_ALIAS;
  aOrigin: URL;
  pOrigin: URL;
  adminOrigin: URL;
  adminKey: string;
  actionKey: string;
  recoveryRunId?: string;
}

export interface Sbx058Journal {
  schemaVersion: 1;
  testId: typeof SBX058_TEST_ID;
  runId: string;
  startedAt: string;
  updatedAt: string;
  name: string;
  tags: Record<string, string>;
  receiverConfigureAttempted: boolean;
  receiverConfigured: boolean;
  createAttemptedAt?: string;
  createSettledAt?: string;
  sessionId?: string;
  provenanceValidated: boolean;
  zeroExternalStateConfirmed: boolean;
  absenceOnlyValidated: boolean;
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  absenceChecks: number;
  prefixAbsent: boolean;
  receiverDeleted: boolean;
  completed: boolean;
  rawSecretsRetained: false;
}

export interface Sbx058HeldSafety {
  liveLock: Sbx026LiveLock;
  runId: string;
  journalPath: string;
  journal: Sbx058Journal;
  lockMode: number;
  journalMode: number;
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function opaqueKey(value: string, name: string): string {
  if (Buffer.byteLength(value) < 32 || Buffer.byteLength(value) > 256 || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new Error(`${name} must be one bounded opaque key`);
  }
  return value;
}

function publicOrigin(raw: string, name: string): URL {
  const value = new URL(raw);
  if (raw !== value.origin || value.protocol !== "https:" || value.username || value.password || value.port ||
      value.pathname !== "/" || value.search || value.hash || value.hostname !== value.hostname.toLowerCase() ||
      value.hostname.endsWith(".") || isIP(value.hostname) !== 0 ||
      !value.hostname.endsWith(".trycloudflare.com")) {
    throw new Error(`${name} must be one canonical researcher-controlled Quick Tunnel origin`);
  }
  return value;
}

function loopbackOrigin(raw: string): URL {
  const value = new URL(raw);
  if (raw !== value.origin || value.protocol !== "http:" || value.hostname !== "127.0.0.1" ||
      !value.port || Number(value.port) < 1 || Number(value.port) > 65_535 || value.pathname !== "/" ||
      value.username || value.password || value.search || value.hash) {
    throw new Error("SBX058_ADMIN_ORIGIN must be canonical loopback HTTP");
  }
  return value;
}

export function loadSbx058Config(environment: NodeJS.ProcessEnv = process.env): Sbx058Config {
  if (environment.NODE_TLS_REJECT_UNAUTHORIZED === "0" || environment.NODE_OPTIONS) {
    throw new Error("SBX-058 refuses TLS or runtime injection overrides");
  }
  if (environment.SBX058_SCOPE_CONFIRMATION !== SBX058_SCOPE_CONFIRMATION ||
      environment.SBX058_ALIAS_EMAIL_CONFIRMATION !== SBX058_ALIAS ||
      environment.VERCEL_TEAM_ID !== SBX058_TEAM || environment.VERCEL_PROJECT_ID !== SBX058_PROJECT) {
    throw new Error("SBX-058 exact scope and eligible identity confirmation were absent");
  }
  const token = required(environment, "VERCEL_TOKEN");
  if (token.length < 20 || token.length > 4_096 || /[\0\r\n\s]/u.test(token) || token.split(".").length === 3) {
    throw new Error("SBX-058 requires one bounded non-JWT Vercel PAT");
  }
  const adminKey = opaqueKey(required(environment, "SBX058_ADMIN_KEY"), "SBX058_ADMIN_KEY");
  const actionKey = opaqueKey(required(environment, "SBX058_ACTION_KEY"), "SBX058_ACTION_KEY");
  if (adminKey === actionKey) throw new Error("SBX-058 keys must be distinct");
  const aOrigin = publicOrigin(required(environment, "SBX058_A_PUBLIC_ORIGIN"), "SBX058_A_PUBLIC_ORIGIN");
  const pOrigin = publicOrigin(required(environment, "SBX058_P_PUBLIC_ORIGIN"), "SBX058_P_PUBLIC_ORIGIN");
  if (aOrigin.origin === pOrigin.origin) throw new Error("SBX-058 A/P origins must be distinct");
  const recoveryRunId = environment.SBX058_RECOVERY_RUN_ID;
  if (recoveryRunId !== undefined && !SBX058_UUID.test(recoveryRunId)) {
    throw new Error("SBX058_RECOVERY_RUN_ID must be a canonical UUIDv4");
  }
  return {
    token,
    teamId: SBX058_TEAM,
    projectId: SBX058_PROJECT,
    aliasEmail: SBX058_ALIAS,
    aOrigin,
    pOrigin,
    adminOrigin: loopbackOrigin(environment.SBX058_ADMIN_ORIGIN ?? "http://127.0.0.1:43160"),
    adminKey,
    actionKey,
    ...(recoveryRunId ? { recoveryRunId } : {}),
  };
}

export function sbx058Name(runId: string): string {
  if (!SBX058_UUID.test(runId)) throw new Error("SBX-058 run ID was invalid");
  return `sbx-058-${runId}`;
}

export function sbx058Tags(runId: string): Record<string, string> {
  if (!SBX058_UUID.test(runId)) throw new Error("SBX-058 run ID was invalid");
  return { harness: "vsc", test: SBX058_TEST_ID, run: runId };
}

export function sbx058JournalPath(runId: string): string {
  if (!SBX058_UUID.test(runId)) throw new Error("SBX-058 journal run ID was invalid");
  return resolve(SBX058_ARTIFACTS, `SBX-058-${runId}-recovery.json`);
}

export function sbx058ArtifactPath(runId: string): string {
  if (!SBX058_UUID.test(runId)) throw new Error("SBX-058 artifact run ID was invalid");
  return resolve(SBX058_ARTIFACTS, `SBX-058-${runId}-private.json`);
}

export function sbx058RecoveryArtifactPath(runId: string, attemptId: string): string {
  if (!SBX058_UUID.test(runId) || !SBX058_UUID.test(attemptId)) {
    throw new Error("SBX-058 recovery artifact IDs were invalid");
  }
  return resolve(SBX058_ARTIFACTS, `SBX-058-${runId}-recovery-${attemptId}-private.json`);
}

export function createSbx058Journal(runId: string = randomUUID(), now = new Date()): Sbx058Journal {
  if (!SBX058_UUID.test(runId)) throw new Error("SBX-058 journal run ID was invalid");
  const at = now.toISOString();
  return {
    schemaVersion: 1,
    testId: SBX058_TEST_ID,
    runId,
    startedAt: at,
    updatedAt: at,
    name: sbx058Name(runId),
    tags: sbx058Tags(runId),
    receiverConfigureAttempted: false,
    receiverConfigured: false,
    provenanceValidated: false,
    zeroExternalStateConfirmed: false,
    absenceOnlyValidated: false,
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    absenceChecks: 0,
    prefixAbsent: false,
    receiverDeleted: false,
    completed: false,
    rawSecretsRetained: false,
  };
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function exactKeys(value: Record<string, unknown>, requiredKeys: readonly string[], optional: readonly string[] = []): boolean {
  const keys = Object.keys(value);
  const permitted = new Set([...requiredKeys, ...optional]);
  return requiredKeys.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    keys.every((key) => permitted.has(key)) && keys.length === requiredKeys.length +
      optional.filter((key) => Object.prototype.hasOwnProperty.call(value, key)).length;
}

function timestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function exactTags(value: unknown, expected: Record<string, string>): boolean {
  const root = object(value);
  return root !== undefined && exactKeys(root, Object.keys(expected)) &&
    Object.entries(expected).every(([key, expectedValue]) => root[key] === expectedValue);
}

export function parseSbx058Journal(value: unknown): Sbx058Journal {
  const root = object(value);
  if (!root || !exactKeys(root, [
    "absenceChecks", "absenceOnlyValidated", "completed", "deleteAttempted", "deleted", "name", "prefixAbsent",
    "provenanceValidated", "rawSecretsRetained", "receiverConfigureAttempted", "receiverConfigured",
    "receiverDeleted", "runId", "schemaVersion", "startedAt", "stopAttempted", "stopped", "tags",
    "testId", "updatedAt", "zeroExternalStateConfirmed",
  ], ["createAttemptedAt", "createSettledAt", "sessionId"]) || root.schemaVersion !== 1 ||
      root.testId !== SBX058_TEST_ID || typeof root.runId !== "string" || !SBX058_UUID.test(root.runId) ||
      root.name !== sbx058Name(root.runId) || !exactTags(root.tags, sbx058Tags(root.runId)) ||
      !timestamp(root.startedAt) || !timestamp(root.updatedAt) || Date.parse(root.updatedAt) < Date.parse(root.startedAt) ||
      !(root.createAttemptedAt === undefined || timestamp(root.createAttemptedAt)) ||
      !(root.createSettledAt === undefined || timestamp(root.createSettledAt)) ||
      !(root.sessionId === undefined || (typeof root.sessionId === "string" && /^sbx_[A-Za-z0-9_-]{20,100}$/u.test(root.sessionId))) ||
      typeof root.receiverConfigureAttempted !== "boolean" || typeof root.receiverConfigured !== "boolean" ||
      typeof root.provenanceValidated !== "boolean" || typeof root.zeroExternalStateConfirmed !== "boolean" ||
      typeof root.absenceOnlyValidated !== "boolean" ||
      typeof root.stopAttempted !== "boolean" ||
      typeof root.stopped !== "boolean" || typeof root.deleteAttempted !== "boolean" ||
      typeof root.deleted !== "boolean" || !Number.isSafeInteger(root.absenceChecks) ||
      (root.absenceChecks as number) < 0 || (root.absenceChecks as number) > 8 ||
      typeof root.prefixAbsent !== "boolean" || typeof root.receiverDeleted !== "boolean" ||
      typeof root.completed !== "boolean" || root.rawSecretsRetained !== false ||
      (root.provenanceValidated && root.sessionId === undefined) ||
      (root.zeroExternalStateConfirmed && root.createAttemptedAt !== undefined) ||
      (root.absenceOnlyValidated && (root.createAttemptedAt === undefined ||
        (root.absenceChecks as number) < 3 || root.prefixAbsent !== true)) ||
      (root.stopped && !root.stopAttempted) ||
      (root.deleted && !root.deleteAttempted && !root.absenceOnlyValidated) ||
      (root.completed && (!root.deleted ||
        (root.absenceChecks as number) < 3 || !root.prefixAbsent || !root.receiverDeleted) &&
        !root.zeroExternalStateConfirmed)) {
    throw new Error("SBX-058 journal was not exact");
  }
  return root as unknown as Sbx058Journal;
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

async function exactPrivate(path: string): Promise<number> {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 ||
      (metadata.mode & 0o777) !== 0o600) throw new Error("SBX-058 private file was not exact mode 0600");
  return metadata.mode & 0o777;
}

async function syncDirectory(): Promise<void> {
  const directory = await open(SBX058_ARTIFACTS, constants.O_RDONLY);
  try { await directory.sync(); } finally { await directory.close(); }
}

async function temporary(bytes: string, target: string): Promise<string> {
  const path = `${target}.tmp-${process.pid}-${randomBytes(16).toString("hex")}`;
  const handle = await open(path,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0), 0o600);
  try {
    await handle.chmod(0o600);
    await handle.writeFile(bytes, "utf8");
    await handle.sync();
  } finally { await handle.close(); }
  await exactPrivate(path);
  return path;
}

async function replacePrivate(path: string, value: unknown): Promise<void> {
  const temp = await temporary(`${JSON.stringify(value, null, 2)}\n`, path);
  try {
    await rename(temp, path);
    await syncDirectory();
    await exactPrivate(path);
  } catch (error) {
    await unlink(temp).catch(() => undefined);
    throw error;
  }
}

export async function writeSbx058NoClobber(path: string, value: unknown): Promise<void> {
  const temp = await temporary(`${JSON.stringify(value, null, 2)}\n`, path);
  try {
    await link(temp, path);
    await unlink(temp);
    await syncDirectory();
    await exactPrivate(path);
  } catch (error) {
    await unlink(temp).catch(() => undefined);
    throw error;
  }
}

export async function acquireSbx058Safety(
  mode: "normal" | "cleanup-only",
  suppliedRunId?: string,
): Promise<Sbx058HeldSafety> {
  const runId = suppliedRunId ?? randomUUID();
  if (!SBX058_UUID.test(runId)) throw new Error("SBX-058 safety run ID was invalid");
  await mkdir(SBX058_ARTIFACTS, { recursive: true, mode: 0o700 });
  const liveLock = await acquireSbx026LiveLock({
    scope: "session-command",
    runId,
    mode,
    lane: "sbx-058",
  });
  const journalPath = sbx058JournalPath(runId);
  try {
    let journal: Sbx058Journal;
    if (mode === "normal") {
      journal = createSbx058Journal(runId);
      await writeSbx058NoClobber(journalPath, journal);
    } else if (await pathAbsent(journalPath)) {
      journal = createSbx058Journal(runId);
    } else {
      await exactPrivate(journalPath);
      journal = parseSbx058Journal(JSON.parse(await readFile(journalPath, "utf8")));
    }
    const lockMode = (await lstat(SBX026_LIVE_LOCK_PATH)).mode & 0o777;
    const journalMode = await pathAbsent(journalPath) ? 0o600 : await exactPrivate(journalPath);
    return { liveLock, runId, journalPath, journal, lockMode, journalMode };
  } catch (error) {
    await liveLock.release().catch(() => undefined);
    throw error;
  }
}

export async function checkpointSbx058(held: Sbx058HeldSafety): Promise<void> {
  held.journal.updatedAt = new Date().toISOString();
  parseSbx058Journal(held.journal);
  await replacePrivate(held.journalPath, held.journal);
  held.journalMode = await exactPrivate(held.journalPath);
}

export function sbx058UnknownCreateSettled(journal: Sbx058Journal, now = Date.now()): boolean {
  return journal.createAttemptedAt !== undefined &&
    now - Date.parse(journal.createAttemptedAt) >= SBX058_UNKNOWN_CREATE_SETTLEMENT_MS;
}

export function markSbx058AbsenceOnlyTerminal(journal: Sbx058Journal): void {
  if (journal.createAttemptedAt === undefined || journal.absenceChecks < 3 || !journal.prefixAbsent) {
    throw new Error("SBX-058 absence-only terminal proof was incomplete");
  }
  journal.absenceOnlyValidated = true;
  journal.deleted = true;
  parseSbx058Journal(journal);
}

export async function finalizeSbx058Safety(held: Sbx058HeldSafety): Promise<{
  journalRemoved: boolean;
  liveLockRemoved: boolean;
}> {
  if (!held.journal.completed) throw new Error("SBX-058 refused to release incomplete recovery state");
  await checkpointSbx058(held);
  await held.liveLock.release();
  const liveLockRemoved = await pathAbsent(SBX026_LIVE_LOCK_PATH);
  if (!liveLockRemoved) throw new Error("SBX-058 global live lock remained after release");
  await unlink(held.journalPath);
  await syncDirectory();
  const journalRemoved = await pathAbsent(held.journalPath);
  if (!journalRemoved) throw new Error("SBX-058 journal remained after release");
  return { journalRemoved, liveLockRemoved };
}
