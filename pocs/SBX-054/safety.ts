import { randomBytes, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, readFile, rename, unlink, type FileHandle } from "node:fs/promises";
import { isIP } from "node:net";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { SBX054_TEST_ID, SBX054_UUID } from "./verdict.js";

export const SBX054_ALIAS = "swve@wearehackerone.com" as const;
export const SBX054_TEAM = "team_n98ERpVwV7HqmWRudAyK8sXQ" as const;
export const SBX054_PROJECT = "prj_CyyVykdN06Nrkla6KidZcecLgbCa" as const;
export const SBX054_SCOPE_CONFIRMATION =
  "I_RECHECKED_SBX054_SCOPE_AND_AUTHORIZE_ONE_BOUNDED_V2_V3_CREATE_POLICY_DIFFERENTIAL" as const;
export const SBX054_ARTIFACTS = fileURLToPath(new URL("../../artifacts", import.meta.url));
export const SBX054_LOCK_PATH = resolve(SBX054_ARTIFACTS, "SBX-054-live-active.lock");
export const SBX054_SANDBOX_TIMEOUT_MS = 180_000 as const;

export type Sbx054Role = "comparator" | "target";

export interface Sbx054Config {
  token: string;
  teamId: typeof SBX054_TEAM;
  projectId: typeof SBX054_PROJECT;
  expectedAlias: typeof SBX054_ALIAS;
  publicOrigin: URL;
  adminOrigin: URL;
  adminKey: string;
  actionKey: string;
  manualAliasConfirmation?: string;
  recoveryRunId?: string;
}

export interface Sbx054JournalResource {
  role: Sbx054Role;
  name: string;
  tags: Record<string, string>;
  createAttemptedAt?: string;
  createSettledAt?: string;
  sessionId?: string;
  deleted: boolean;
  absenceChecks: number;
}

export interface Sbx054RecoveryJournal {
  schemaVersion: 1;
  testId: typeof SBX054_TEST_ID;
  runId: string;
  startedAt: string;
  updatedAt: string;
  resources: [Sbx054JournalResource, Sbx054JournalResource];
  receiverConfigureAttempted: boolean;
  receiverConfigured: boolean;
  receiverDeleted: boolean;
  completed: boolean;
  rawSecretsRetained: false;
}

export interface Sbx054HeldLock {
  runId: string;
  path: string;
  mode: number;
  closeRetainingState(): Promise<void>;
  release(): Promise<void>;
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function exactPublicOrigin(raw: string): URL {
  const value = new URL(raw);
  if (raw !== value.origin || value.protocol !== "https:" || value.port !== "" ||
      value.username !== "" || value.password !== "" || value.pathname !== "/" ||
      value.search !== "" || value.hash !== "" || value.hostname !== value.hostname.toLowerCase() ||
      value.hostname.endsWith(".") || !value.hostname.endsWith(".trycloudflare.com") ||
      isIP(value.hostname) !== 0) {
    throw new Error("SBX054_PUBLIC_ORIGIN must be one fresh canonical Quick Tunnel HTTPS origin");
  }
  return value;
}

function exactAdminOrigin(raw: string): URL {
  const value = new URL(raw);
  if (raw !== value.origin || value.protocol !== "http:" || value.hostname !== "127.0.0.1" ||
      !/^[0-9]{1,5}$/u.test(value.port) || Number(value.port) < 1 || Number(value.port) > 65_535 ||
      value.username !== "" || value.password !== "" || value.pathname !== "/" ||
      value.search !== "" || value.hash !== "") {
    throw new Error("SBX054_ADMIN_ORIGIN must be one exact loopback HTTP origin");
  }
  return value;
}

function exactKey(value: string, name: string): string {
  if (Buffer.byteLength(value) < 32 || Buffer.byteLength(value) > 256 ||
      !/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error(`${name} was not one bounded key`);
  return value;
}

export function loadSbx054Config(environment: NodeJS.ProcessEnv = process.env): Sbx054Config {
  if (environment.SBX054_SCOPE_CONFIRMATION !== SBX054_SCOPE_CONFIRMATION ||
      environment.VERCEL_TEAM_ID !== SBX054_TEAM || environment.VERCEL_PROJECT_ID !== SBX054_PROJECT ||
      environment.SBX054_EXPECTED_ALIAS !== SBX054_ALIAS) {
    throw new Error("SBX-054 scope or exact eligible identity binding was absent");
  }
  const token = required(environment, "VERCEL_TOKEN");
  if (token.length < 20 || token.length > 4_096 || /[\0\r\n\s]/u.test(token) ||
      token.split(".").length === 3) throw new Error("SBX-054 requires one bounded non-JWT Vercel PAT");
  const adminKey = exactKey(required(environment, "SBX054_ADMIN_KEY"), "SBX054_ADMIN_KEY");
  const actionKey = exactKey(required(environment, "SBX054_ACTION_KEY"), "SBX054_ACTION_KEY");
  if (adminKey === actionKey) throw new Error("SBX-054 admin and action keys must be distinct");
  const recoveryRunId = environment.SBX054_RECOVERY_RUN_ID;
  if (recoveryRunId !== undefined && !SBX054_UUID.test(recoveryRunId)) {
    throw new Error("SBX054_RECOVERY_RUN_ID must be a canonical UUIDv4");
  }
  return {
    token,
    teamId: SBX054_TEAM,
    projectId: SBX054_PROJECT,
    expectedAlias: SBX054_ALIAS,
    publicOrigin: exactPublicOrigin(required(environment, "SBX054_PUBLIC_ORIGIN")),
    adminOrigin: exactAdminOrigin(environment.SBX054_ADMIN_ORIGIN ?? "http://127.0.0.1:43154"),
    adminKey,
    actionKey,
    ...(environment.SBX054_MANUAL_ALIAS_CONFIRMATION === undefined
      ? {}
      : { manualAliasConfirmation: environment.SBX054_MANUAL_ALIAS_CONFIRMATION }),
    ...(recoveryRunId === undefined ? {} : { recoveryRunId }),
  };
}

function timestamp(value: unknown): value is string {
  if (typeof value !== "string" || value.length !== 24) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
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
  const value = actual as Record<string, unknown>;
  const keys = Object.keys(expected);
  return Object.keys(value).length === keys.length && keys.every((key) => value[key] === expected[key]);
}

export function sbx054Name(role: Sbx054Role, runId: string): string {
  if (!SBX054_UUID.test(runId)) throw new Error("SBX-054 name requires UUIDv4");
  return `sbx-054-${role === "comparator" ? "v3" : "v2"}-${runId}`;
}

export function sbx054Tags(role: Sbx054Role, runId: string): Record<string, string> {
  return { harness: "vsc", test: SBX054_TEST_ID, run: runId, role };
}

export function sbx054JournalPath(runId: string): string {
  if (!SBX054_UUID.test(runId)) throw new Error("SBX-054 journal path requires UUIDv4");
  return resolve(SBX054_ARTIFACTS, `SBX-054-${runId}-recovery.json`);
}

export function sbx054ArtifactPath(runId: string): string {
  if (!SBX054_UUID.test(runId)) throw new Error("SBX-054 artifact path requires UUIDv4");
  return resolve(SBX054_ARTIFACTS, `SBX-054-${runId}-private.json`);
}

export function createSbx054Journal(now: Date = new Date(), suppliedRunId?: string): Sbx054RecoveryJournal {
  const runId = suppliedRunId ?? randomUUID();
  if (!SBX054_UUID.test(runId)) throw new Error("SBX-054 run ID was invalid");
  const at = now.toISOString();
  const resource = (role: Sbx054Role): Sbx054JournalResource => ({
    role,
    name: sbx054Name(role, runId),
    tags: sbx054Tags(role, runId),
    deleted: false,
    absenceChecks: 0,
  });
  return {
    schemaVersion: 1,
    testId: SBX054_TEST_ID,
    runId,
    startedAt: at,
    updatedAt: at,
    resources: [resource("comparator"), resource("target")],
    receiverConfigureAttempted: false,
    receiverConfigured: false,
    receiverDeleted: false,
    completed: false,
    rawSecretsRetained: false,
  };
}

export function parseSbx054Journal(value: unknown): Sbx054RecoveryJournal {
  if (value === null || typeof value !== "object" || Array.isArray(value) || !exactKeys(value, [
    "schemaVersion", "testId", "runId", "startedAt", "updatedAt", "resources",
    "receiverConfigureAttempted", "receiverConfigured", "receiverDeleted", "completed",
    "rawSecretsRetained",
  ])) throw new Error("SBX-054 journal fields were not exact");
  const root = value as Record<string, unknown>;
  if (root.schemaVersion !== 1 || root.testId !== SBX054_TEST_ID ||
      typeof root.runId !== "string" || !SBX054_UUID.test(root.runId) ||
      !timestamp(root.startedAt) || !timestamp(root.updatedAt) ||
      Date.parse(root.updatedAt) < Date.parse(root.startedAt) || !Array.isArray(root.resources) ||
      root.resources.length !== 2 || typeof root.receiverConfigureAttempted !== "boolean" ||
      typeof root.receiverConfigured !== "boolean" ||
      typeof root.receiverDeleted !== "boolean" || typeof root.completed !== "boolean" ||
      root.rawSecretsRetained !== false) throw new Error("SBX-054 journal was invalid");
  const roles: Sbx054Role[] = ["comparator", "target"];
  const resources = root.resources.map((raw, index): Sbx054JournalResource => {
    if (raw === null || typeof raw !== "object" || Array.isArray(raw) || !exactKeys(raw, [
      "role", "name", "tags", "deleted", "absenceChecks",
    ], ["createAttemptedAt", "createSettledAt", "sessionId"])) {
      throw new Error("SBX-054 journal resource fields were not exact");
    }
    const item = raw as Record<string, unknown>;
    const role = roles[index]!;
    if (item.role !== role || item.name !== sbx054Name(role, root.runId as string) ||
        !exactRecord(item.tags, sbx054Tags(role, root.runId as string)) ||
        !(item.createAttemptedAt === undefined || timestamp(item.createAttemptedAt)) ||
        !(item.createSettledAt === undefined || timestamp(item.createSettledAt)) ||
        (item.createSettledAt !== undefined && (item.createAttemptedAt === undefined ||
          Date.parse(item.createSettledAt as string) < Date.parse(item.createAttemptedAt as string))) ||
        !(item.sessionId === undefined || (typeof item.sessionId === "string" &&
          /^sbx_[A-Za-z0-9_-]{8,192}$/u.test(item.sessionId))) || typeof item.deleted !== "boolean" ||
        typeof item.absenceChecks !== "number" || !Number.isInteger(item.absenceChecks) ||
        item.absenceChecks < 0 || (item.deleted && item.absenceChecks < 2)) {
      throw new Error("SBX-054 journal resource was invalid");
    }
    return item as unknown as Sbx054JournalResource;
  });
  if ((root.receiverConfigured && !root.receiverConfigureAttempted) ||
      (root.completed && (!root.receiverDeleted || resources.some((entry) => !entry.deleted)))) {
    throw new Error("SBX-054 completed journal lacked exact cleanup");
  }
  return { ...root, resources } as unknown as Sbx054RecoveryJournal;
}

async function exactPrivateFile(path: string): Promise<number> {
  const metadata = await lstat(path);
  const mode = metadata.mode & 0o777;
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || mode !== 0o600) {
    throw new Error("SBX-054 private state was not an exact mode-0600 single-link regular file");
  }
  return mode;
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(dirname(path), constants.O_RDONLY);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export async function writeSbx054PrivateJson(path: string, value: unknown, replace: boolean): Promise<number> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.tmp-${process.pid}-${randomUUID()}`;
  const noFollow = constants.O_NOFOLLOW ?? 0;
  const handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | noFollow, 0o600);
  try {
    await handle.chmod(0o600);
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    if (!replace) {
      try {
        await lstat(path);
        throw new Error("SBX-054 refused to replace an existing final artifact");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    } else {
      try { await exactPrivateFile(path); } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
    await rename(temporary, path);
    await syncDirectory(path);
    return await exactPrivateFile(path);
  } catch (error) {
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

export async function writeSbx054Journal(journal: Sbx054RecoveryJournal): Promise<number> {
  journal.updatedAt = new Date().toISOString();
  return writeSbx054PrivateJson(sbx054JournalPath(journal.runId), parseSbx054Journal(journal), true);
}

export async function readSbx054Journal(runId: string): Promise<Sbx054RecoveryJournal> {
  const path = sbx054JournalPath(runId);
  await exactPrivateFile(path);
  return parseSbx054Journal(JSON.parse(await readFile(path, "utf8")));
}

interface LockMetadata {
  schemaVersion: 1;
  testId: typeof SBX054_TEST_ID;
  runId: string;
  pid: number;
  lease: string;
  createdAt: string;
}

function parseLock(value: unknown): LockMetadata {
  if (value === null || typeof value !== "object" || Array.isArray(value) || !exactKeys(value, [
    "schemaVersion", "testId", "runId", "pid", "lease", "createdAt",
  ])) throw new Error("SBX-054 lock fields were not exact");
  const lock = value as Record<string, unknown>;
  if (lock.schemaVersion !== 1 || lock.testId !== SBX054_TEST_ID ||
      typeof lock.runId !== "string" || !SBX054_UUID.test(lock.runId) ||
      typeof lock.pid !== "number" || !Number.isSafeInteger(lock.pid) || lock.pid < 1 ||
      typeof lock.lease !== "string" || !/^[0-9a-f]{64}$/u.test(lock.lease) ||
      !timestamp(lock.createdAt)) throw new Error("SBX-054 lock was invalid");
  return lock as unknown as LockMetadata;
}

function processAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

async function createLock(runId: string): Promise<Sbx054HeldLock> {
  const metadata: LockMetadata = {
    schemaVersion: 1,
    testId: SBX054_TEST_ID,
    runId,
    pid: process.pid,
    lease: randomBytes(32).toString("hex"),
    createdAt: new Date().toISOString(),
  };
  const handle = await open(SBX054_LOCK_PATH, "wx", 0o600);
  await handle.chmod(0o600);
  await handle.writeFile(`${JSON.stringify(metadata)}\n`, "utf8");
  await handle.sync();
  const held = await handle.stat();
  await syncDirectory(SBX054_LOCK_PATH);
  let closed = false;
  return {
    runId,
    path: SBX054_LOCK_PATH,
    mode: await exactPrivateFile(SBX054_LOCK_PATH),
    async closeRetainingState(): Promise<void> {
      if (closed) return;
      closed = true;
      await handle.close();
    },
    async release(): Promise<void> {
      if (closed) throw new Error("SBX-054 lock handle was already closed");
      const current = await lstat(SBX054_LOCK_PATH);
      if (current.dev !== held.dev || current.ino !== held.ino) {
        throw new Error("SBX-054 lock inode changed before release");
      }
      await unlink(SBX054_LOCK_PATH);
      await syncDirectory(SBX054_LOCK_PATH);
      closed = true;
      await handle.close();
    },
  };
}

export async function acquireSbx054Lock(runId: string, recovery: boolean): Promise<Sbx054HeldLock> {
  if (!SBX054_UUID.test(runId)) throw new Error("SBX-054 lock requires UUIDv4");
  await mkdir(SBX054_ARTIFACTS, { recursive: true, mode: 0o700 });
  if (recovery) {
    await exactPrivateFile(SBX054_LOCK_PATH);
    const existing = parseLock(JSON.parse(await readFile(SBX054_LOCK_PATH, "utf8")));
    if (existing.runId !== runId || processAlive(existing.pid)) {
      throw new Error("SBX-054 refused cleanup-only lock recovery");
    }
    const claim = `${SBX054_LOCK_PATH}.stale-${process.pid}-${randomUUID()}`;
    await rename(SBX054_LOCK_PATH, claim);
    try {
      const claimed = parseLock(JSON.parse(await readFile(claim, "utf8")));
      if (claimed.lease !== existing.lease || claimed.runId !== runId) {
        throw new Error("SBX-054 stale lock changed during claim");
      }
      const lock = await createLock(runId);
      await unlink(claim);
      await syncDirectory(SBX054_LOCK_PATH);
      return lock;
    } catch (error) {
      try { await rename(claim, SBX054_LOCK_PATH); } catch { /* retain best available recovery state */ }
      throw error;
    }
  }
  return createLock(runId);
}

export async function removeSbx054Journal(runId: string): Promise<void> {
  await unlink(sbx054JournalPath(runId));
  await syncDirectory(sbx054JournalPath(runId));
}
