import { constants } from "node:fs";
import {
  link,
  lstat,
  mkdir,
  open,
  readFile,
  rename,
  stat,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes, randomUUID } from "node:crypto";

export const TEST_ID = "SBX-045" as const;
export const ELIGIBLE_TEAM_ID = "team_n98ERpVwV7HqmWRudAyK8sXQ";
export const ELIGIBLE_PROJECT_ID = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
export const ELIGIBLE_ALIAS = "swve@wearehackerone.com";
export const ARTIFACTS_DIRECTORY = fileURLToPath(
  new URL("../../artifacts", import.meta.url),
);
export const LIVE_LOCK_PATH = resolve(ARTIFACTS_DIRECTORY, "SBX-045-live-active.lock");

export const CANONICAL_UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SESSION_ID_PATTERN = /^sbx_[A-Za-z0-9_-]{8,192}$/u;
const SNAPSHOT_ID_PATTERN = /^[A-Za-z][A-Za-z0-9_-]{7,191}$/u;
const LEASE_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const MAXIMUM_METADATA_BYTES = 128 * 1024;

export type ResourceRole = "source" | "inheritance" | "target";

export interface RecoveryResource {
  role: ResourceRole;
  resourceId: string;
  name: string;
  tags: Record<string, string>;
  persistent: boolean;
  createAttemptedAt?: string;
  createdAt?: string;
  createResponseProvenanceMismatch?: true;
  knownSessionIds: string[];
  knownSnapshotIds: string[];
}

export interface RecoveryJournal {
  schemaVersion: 1;
  testId: typeof TEST_ID;
  runId: string;
  startedAt: string;
  updatedAt: string;
  account: {
    teamId: typeof ELIGIBLE_TEAM_ID;
    projectId: typeof ELIGIBLE_PROJECT_ID;
    expectedEmail: typeof ELIGIBLE_ALIAS;
  };
  inheritanceControlEnabled: boolean;
  resources: RecoveryResource[];
  rawSyntheticValuesRetained: false;
}

interface LiveLockMetadata {
  schemaVersion: 1;
  testId: typeof TEST_ID;
  runId: string;
  pid: number;
  lease: string;
  createdAt: string;
  mode: "normal" | "cleanup-only";
}

interface SecureOpened<T> {
  handle: FileHandle;
  value: T;
  device: bigint;
  inode: bigint;
}

export interface HeldLiveLock {
  path: string;
  metadata: Readonly<LiveLockMetadata>;
  reclaimed: boolean;
  isReleased(): boolean;
  release(): Promise<void>;
}

function exactKeys(value: object, required: readonly string[], optional: readonly string[] = []): boolean {
  const actual = Object.keys(value);
  const permitted = new Set([...required, ...optional]);
  return required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    actual.every((key) => permitted.has(key)) &&
    actual.length === required.length + optional.filter((key) =>
      Object.prototype.hasOwnProperty.call(value, key)).length;
}

function canonicalTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || value.length !== 24) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

export function validateRunId(runId: string): void {
  if (!CANONICAL_UUID_PATTERN.test(runId)) {
    throw new Error("SBX-045 run ID must be one lowercase canonical UUIDv4");
  }
}

function expectedName(role: ResourceRole, resourceId: string): string {
  return `sbx-045-${role}-${resourceId}`;
}

function expectedTags(
  runId: string,
  role: ResourceRole,
  resourceId: string,
): Record<string, string> {
  return {
    harness: "vsc",
    test: TEST_ID,
    run: runId,
    role,
    resource: resourceId,
  };
}

function exactStringRecord(value: unknown, expected: Record<string, string>): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = value as Record<string, unknown>;
  const actualKeys = Object.keys(actual);
  const expectedKeys = Object.keys(expected);
  return actualKeys.length === expectedKeys.length && expectedKeys.every((key) =>
    actual[key] === expected[key]);
}

function parseResource(value: unknown, runId: string): RecoveryResource {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      !exactKeys(value, [
        "role", "resourceId", "name", "tags", "persistent", "knownSessionIds",
        "knownSnapshotIds",
      ], ["createAttemptedAt", "createdAt", "createResponseProvenanceMismatch"])) {
    throw new Error("SBX-045 recovery resource has unexpected or missing fields");
  }
  const resource = value as Record<string, unknown>;
  const role = resource.role;
  if (role !== "source" && role !== "inheritance" && role !== "target") {
    throw new Error("SBX-045 recovery resource role is invalid");
  }
  if (typeof resource.resourceId !== "string" ||
      !CANONICAL_UUID_PATTERN.test(resource.resourceId) ||
      resource.name !== expectedName(role, resource.resourceId) ||
      !exactStringRecord(resource.tags, expectedTags(runId, role, resource.resourceId)) ||
      typeof resource.persistent !== "boolean" ||
      (role === "source") !== resource.persistent) {
    throw new Error("SBX-045 recovery resource provenance is invalid");
  }
  if (resource.createAttemptedAt !== undefined && !canonicalTimestamp(resource.createAttemptedAt)) {
    throw new Error("SBX-045 recovery create-attempt timestamp is invalid");
  }
  if (resource.createdAt !== undefined && !canonicalTimestamp(resource.createdAt)) {
    throw new Error("SBX-045 recovery creation timestamp is invalid");
  }
  if (resource.createdAt !== undefined && resource.createAttemptedAt === undefined) {
    throw new Error("SBX-045 recovery resource cannot be created without an attempt");
  }
  if (resource.createResponseProvenanceMismatch === true &&
      resource.createAttemptedAt === undefined) {
    throw new Error("SBX-045 recovery mismatch cannot exist without a create attempt");
  }
  if (resource.createResponseProvenanceMismatch !== undefined &&
      resource.createResponseProvenanceMismatch !== true) {
    throw new Error("SBX-045 recovery provenance-mismatch marker is invalid");
  }
  if (!Array.isArray(resource.knownSessionIds) ||
      !resource.knownSessionIds.every((item) =>
        typeof item === "string" && SESSION_ID_PATTERN.test(item)) ||
      new Set(resource.knownSessionIds).size !== resource.knownSessionIds.length ||
      !Array.isArray(resource.knownSnapshotIds) ||
      !resource.knownSnapshotIds.every((item) =>
        typeof item === "string" && SNAPSHOT_ID_PATTERN.test(item)) ||
      new Set(resource.knownSnapshotIds).size !== resource.knownSnapshotIds.length) {
    throw new Error("SBX-045 recovery resource identifiers are invalid");
  }
  return resource as unknown as RecoveryResource;
}

export function parseRecoveryJournal(value: unknown): RecoveryJournal {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      !exactKeys(value, [
        "schemaVersion", "testId", "runId", "startedAt", "updatedAt", "account",
        "inheritanceControlEnabled", "resources", "rawSyntheticValuesRetained",
      ])) {
    throw new Error("SBX-045 recovery journal has unexpected or missing fields");
  }
  const journal = value as Record<string, unknown>;
  if (journal.schemaVersion !== 1 || journal.testId !== TEST_ID ||
      typeof journal.runId !== "string" || !CANONICAL_UUID_PATTERN.test(journal.runId) ||
      !canonicalTimestamp(journal.startedAt) || !canonicalTimestamp(journal.updatedAt) ||
      Date.parse(journal.updatedAt) < Date.parse(journal.startedAt) ||
      typeof journal.inheritanceControlEnabled !== "boolean" ||
      journal.rawSyntheticValuesRetained !== false) {
    throw new Error("SBX-045 recovery journal is invalid");
  }
  if (journal.account === null || typeof journal.account !== "object" ||
      Array.isArray(journal.account) ||
      !exactKeys(journal.account, ["teamId", "projectId", "expectedEmail"])) {
    throw new Error("SBX-045 recovery account binding is invalid");
  }
  const account = journal.account as Record<string, unknown>;
  if (account.teamId !== ELIGIBLE_TEAM_ID || account.projectId !== ELIGIBLE_PROJECT_ID ||
      account.expectedEmail !== ELIGIBLE_ALIAS) {
    throw new Error("SBX-045 recovery journal is outside the eligible alias scope");
  }
  if (!Array.isArray(journal.resources)) {
    throw new Error("SBX-045 recovery resources must be an array");
  }
  const resources = journal.resources.map((resource) => parseResource(resource, journal.runId as string));
  const expectedRoles: ResourceRole[] = journal.inheritanceControlEnabled
    ? ["source", "inheritance", "target"]
    : ["source", "target"];
  if (resources.length !== expectedRoles.length ||
      resources.some((resource, index) => resource.role !== expectedRoles[index]) ||
      new Set(resources.map((resource) => resource.name)).size !== resources.length ||
      new Set(resources.map((resource) => resource.resourceId)).size !== resources.length) {
    throw new Error("SBX-045 recovery resources are incomplete, reordered, or non-distinct");
  }
  return {
    schemaVersion: 1,
    testId: TEST_ID,
    runId: journal.runId as string,
    startedAt: journal.startedAt as string,
    updatedAt: journal.updatedAt as string,
    account: {
      teamId: ELIGIBLE_TEAM_ID,
      projectId: ELIGIBLE_PROJECT_ID,
      expectedEmail: ELIGIBLE_ALIAS,
    },
    inheritanceControlEnabled: journal.inheritanceControlEnabled,
    resources,
    rawSyntheticValuesRetained: false,
  };
}

export function createRecoveryJournal(
  inheritanceControlEnabled: boolean,
  now: Date = new Date(),
): RecoveryJournal {
  const runId = randomUUID();
  const roles: ResourceRole[] = inheritanceControlEnabled
    ? ["source", "inheritance", "target"]
    : ["source", "target"];
  const timestamp = now.toISOString();
  const journal: RecoveryJournal = {
    schemaVersion: 1,
    testId: TEST_ID,
    runId,
    startedAt: timestamp,
    updatedAt: timestamp,
    account: {
      teamId: ELIGIBLE_TEAM_ID,
      projectId: ELIGIBLE_PROJECT_ID,
      expectedEmail: ELIGIBLE_ALIAS,
    },
    inheritanceControlEnabled,
    resources: roles.map((role) => {
      const resourceId = randomUUID();
      return {
        role,
        resourceId,
        name: expectedName(role, resourceId),
        tags: expectedTags(runId, role, resourceId),
        persistent: role === "source",
        knownSessionIds: [],
        knownSnapshotIds: [],
      };
    }),
    rawSyntheticValuesRetained: false,
  };
  return parseRecoveryJournal(journal);
}

export function recoveryJournalPath(runId: string): string {
  validateRunId(runId);
  return resolve(ARTIFACTS_DIRECTORY, `SBX-045-recovery-${runId}.json`);
}

export function evidencePath(runId: string, cleanupOnly = false): string {
  validateRunId(runId);
  const suffix = cleanupOnly ? "cleanup" : "private";
  return resolve(ARTIFACTS_DIRECTORY, `SBX-045-${runId}-${suffix}.json`);
}

function filesystemErrorCode(error: unknown): string | undefined {
  return error !== null && typeof error === "object" && "code" in error &&
      typeof (error as { code?: unknown }).code === "string"
    ? (error as { code: string }).code
    : undefined;
}

function currentUid(): bigint {
  if (typeof process.getuid !== "function") {
    throw new Error("SBX-045 safety state requires a POSIX user ID");
  }
  return BigInt(process.getuid());
}

function noFollowFlag(): number {
  if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0) {
    throw new Error("SBX-045 safety state requires O_NOFOLLOW support");
  }
  return constants.O_NOFOLLOW;
}

export async function ensurePrivateDirectory(path = ARTIFACTS_DIRECTORY): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const info = await lstat(path, { bigint: true });
  if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== currentUid() ||
      (info.mode & 0o777n) !== 0o700n) {
    throw new Error("SBX-045 artifacts directory must be current-user-owned mode 0700");
  }
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, constants.O_RDONLY);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export async function writePrivateJsonAtomically(path: string, value: unknown): Promise<void> {
  await ensurePrivateDirectory(dirname(path));
  const temporaryPath = `${path}.${process.pid}.${randomBytes(16).toString("hex")}.tmp`;
  let handle: FileHandle | undefined;
  try {
    handle = await open(
      temporaryPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | noFollowFlag(),
      0o600,
    );
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporaryPath, path);
    await syncDirectory(dirname(path));
  } catch (error) {
    await handle?.close().catch(() => undefined);
    await unlink(temporaryPath).catch(() => undefined);
    throw error;
  }
}

async function openSecureJson<T>(
  path: string,
  parse: (value: unknown) => T,
): Promise<SecureOpened<T>> {
  const handle = await open(path, constants.O_RDONLY | noFollowFlag());
  try {
    const info = await handle.stat({ bigint: true });
    if (!info.isFile() || info.uid !== currentUid() || (info.mode & 0o777n) !== 0o600n ||
        info.size > BigInt(MAXIMUM_METADATA_BYTES)) {
      throw new Error("SBX-045 private metadata file failed ownership, mode, type, or size checks");
    }
    const text = await handle.readFile("utf8");
    const value = parse(JSON.parse(text));
    return { handle, value, device: info.dev, inode: info.ino };
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw error;
  }
}

export async function readRecoveryJournal(path: string): Promise<RecoveryJournal> {
  const opened = await openSecureJson(path, parseRecoveryJournal);
  try {
    return opened.value;
  } finally {
    await opened.handle.close();
  }
}

function parseLiveLock(value: unknown): LiveLockMetadata {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      !exactKeys(value, [
        "schemaVersion", "testId", "runId", "pid", "lease", "createdAt", "mode",
      ])) {
    throw new Error("SBX-045 live lock has unexpected or missing fields");
  }
  const lock = value as Record<string, unknown>;
  if (lock.schemaVersion !== 1 || lock.testId !== TEST_ID ||
      typeof lock.runId !== "string" || !CANONICAL_UUID_PATTERN.test(lock.runId) ||
      typeof lock.pid !== "number" || !Number.isSafeInteger(lock.pid) || lock.pid <= 0 ||
      typeof lock.lease !== "string" || !LEASE_PATTERN.test(lock.lease) ||
      !canonicalTimestamp(lock.createdAt) ||
      (lock.mode !== "normal" && lock.mode !== "cleanup-only")) {
    throw new Error("SBX-045 live lock metadata is invalid");
  }
  return lock as unknown as LiveLockMetadata;
}

async function createExclusiveLock(
  path: string,
  metadata: LiveLockMetadata,
): Promise<SecureOpened<LiveLockMetadata>> {
  const handle = await open(
    path,
    constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | noFollowFlag(),
    0o600,
  );
  try {
    await handle.writeFile(`${JSON.stringify(metadata)}\n`, "utf8");
    await handle.sync();
    const info = await handle.stat({ bigint: true });
    if (!info.isFile() || info.uid !== currentUid() || (info.mode & 0o777n) !== 0o600n) {
      throw new Error("SBX-045 live lock file was not securely created");
    }
    await syncDirectory(dirname(path));
    return { handle, value: metadata, device: info.dev, inode: info.ino };
  } catch (error) {
    await handle.close().catch(() => undefined);
    await unlink(path).catch(() => undefined);
    throw error;
  }
}

function defaultPidState(pid: number): "live" | "dead" | "uncertain" {
  try {
    process.kill(pid, 0);
    return "live";
  } catch (error) {
    const code = filesystemErrorCode(error);
    if (code === "ESRCH") return "dead";
    return "uncertain";
  }
}

async function sameFile(path: string, opened: SecureOpened<unknown>): Promise<boolean> {
  const info = await lstat(path, { bigint: true });
  return info.isFile() && !info.isSymbolicLink() &&
    info.dev === opened.device && info.ino === opened.inode;
}

async function openOptionalLiveLock(path: string): Promise<SecureOpened<LiveLockMetadata> | undefined> {
  try {
    return await openSecureJson(path, parseLiveLock);
  } catch (error) {
    if (filesystemErrorCode(error) === "ENOENT") return undefined;
    throw error;
  }
}

async function restoreInterruptedReclaim(
  path: string,
  runId: string,
  pidState: (pid: number) => "live" | "dead" | "uncertain",
): Promise<void> {
  const recoveryPath = `${path}.recovery`;
  const recovery = await openOptionalLiveLock(recoveryPath);
  if (!recovery) return;
  try {
    if (recovery.value.runId !== runId || pidState(recovery.value.pid) !== "dead") {
      throw new Error("SBX-045 interrupted lock recovery is not an exact dead-run match");
    }
    const canonical = await openOptionalLiveLock(path);
    if (!canonical) {
      await link(recoveryPath, path);
      await unlink(recoveryPath);
      await syncDirectory(dirname(path));
      return;
    }
    try {
      if (canonical.value.runId !== runId || pidState(canonical.value.pid) !== "dead") {
        throw new Error("SBX-045 canonical lock conflicts with interrupted recovery");
      }
      await unlink(recoveryPath);
      await syncDirectory(dirname(path));
    } finally {
      await canonical.handle.close();
    }
  } finally {
    await recovery.handle.close();
  }
}

async function clearCompletedRelease(
  path: string,
  runId: string,
  mode: "normal" | "cleanup-only",
): Promise<boolean> {
  const releasePath = `${path}.release`;
  const released = await openOptionalLiveLock(releasePath);
  if (!released) return false;
  try {
    const canonical = await openOptionalLiveLock(path);
    if (canonical) {
      await canonical.handle.close();
      throw new Error("SBX-045 completed-release claim conflicts with a canonical lock");
    }
    if (mode === "cleanup-only" && released.value.runId !== runId) {
      throw new Error("SBX-045 completed-release claim belongs to a different run");
    }
    if (!await sameFile(releasePath, released)) {
      throw new Error("SBX-045 completed-release claim changed before recovery");
    }
    await unlink(releasePath);
    await syncDirectory(dirname(path));
    return true;
  } finally {
    await released.handle.close();
  }
}

export async function acquireLiveLock(
  path: string,
  runId: string,
  mode: "normal" | "cleanup-only",
  pidState: (pid: number) => "live" | "dead" | "uncertain" = defaultPidState,
): Promise<HeldLiveLock> {
  validateRunId(runId);
  await ensurePrivateDirectory(dirname(path));
  const recoveryPath = `${path}.recovery`;
  const completedReleaseRecovered = await clearCompletedRelease(path, runId, mode);
  if (mode === "normal") {
    if (await stat(recoveryPath).then(() => true, (error: unknown) => {
      if (filesystemErrorCode(error) === "ENOENT") return false;
      throw error;
    })) {
      throw new Error("SBX-045 lock recovery is pending; normal execution is refused");
    }
  } else {
    await restoreInterruptedReclaim(path, runId, pidState);
  }

  const metadata: LiveLockMetadata = {
    schemaVersion: 1,
    testId: TEST_ID,
    runId,
    pid: process.pid,
    lease: randomBytes(32).toString("base64url"),
    createdAt: new Date().toISOString(),
    mode,
  };
  let held: SecureOpened<LiveLockMetadata>;
  let reclaimed = false;

  if (mode === "normal" || completedReleaseRecovered) {
    held = await createExclusiveLock(path, metadata);
    reclaimed = completedReleaseRecovered;
  } else {
    const stale = await openOptionalLiveLock(path);
    if (!stale) throw new Error("SBX-045 cleanup-only mode requires its retained live lock");
    try {
      if (stale.value.runId !== runId || pidState(stale.value.pid) !== "dead") {
        throw new Error("SBX-045 cleanup-only mode requires an exact dead-run lock");
      }
      if (!await sameFile(path, stale)) {
        throw new Error("SBX-045 stale live lock changed before reclamation");
      }
      await link(path, recoveryPath);
      const recovery = await openSecureJson(recoveryPath, parseLiveLock);
      try {
        if (recovery.device !== stale.device || recovery.inode !== stale.inode ||
            recovery.value.lease !== stale.value.lease || !await sameFile(path, stale)) {
          throw new Error("SBX-045 stale live-lock recovery claim changed");
        }
      } finally {
        await recovery.handle.close();
      }
      await unlink(path);
      try {
        held = await createExclusiveLock(path, metadata);
      } catch (error) {
        await link(recoveryPath, path).catch(() => undefined);
        throw error;
      }
      await unlink(recoveryPath);
      await syncDirectory(dirname(path));
      reclaimed = true;
    } finally {
      await stale.handle.close();
    }
  }

  let released = false;
  return {
    path,
    metadata,
    reclaimed,
    isReleased(): boolean {
      return released;
    },
    async release(): Promise<void> {
      if (released) throw new Error("SBX-045 live lock was already released");
      const current = await openSecureJson(path, parseLiveLock);
      const releasePath = `${path}.release`;
      try {
        if (current.device !== held.device || current.inode !== held.inode ||
            current.value.lease !== metadata.lease || current.value.runId !== metadata.runId) {
          throw new Error("SBX-045 live lock changed; refusing release");
        }
        await rename(path, releasePath);
        const claimed = await openSecureJson(releasePath, parseLiveLock);
        try {
          if (claimed.device !== held.device || claimed.inode !== held.inode ||
              claimed.value.lease !== metadata.lease) {
            throw new Error("SBX-045 release claim changed; refusing removal");
          }
        } finally {
          await claimed.handle.close();
        }
        // The rename is the release commit. A fixed, validated tombstone makes a crash or
        // directory-fsync failure recoverable by the next exact acquisition.
        released = true;
      } finally {
        await current.handle.close();
        await held.handle.close();
      }
      await syncDirectory(dirname(path)).catch(() => undefined);
      await unlink(releasePath).catch(() => undefined);
      await syncDirectory(dirname(path)).catch(() => undefined);
    },
  };
}

export async function removeRecoveryJournal(path: string, expectedRunId: string): Promise<void> {
  const journal = await readRecoveryJournal(path);
  if (journal.runId !== expectedRunId) {
    throw new Error("SBX-045 recovery journal changed before removal");
  }
  await unlink(path);
  await syncDirectory(dirname(path));
}

export async function readTextForTest(path: string): Promise<string> {
  return readFile(path, "utf8");
}
