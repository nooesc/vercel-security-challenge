import { randomUUID } from "node:crypto";
import { constants as fsConstants, type BigIntStats } from "node:fs";
import { isIP } from "node:net";
import { link, lstat, mkdir, open, readdir, rename, unlink, type FileHandle } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  SBX001_CASES,
  SBX001_DIRECT_TEST_ID,
  SBX001_RECEIVER_WINDOW_MS,
  type Sbx001CaseId,
  type Sbx001ReceiverSnapshot,
} from "./direct-shared.js";
import {
  acquireSbx001DirectLiveLock,
  inspectSbx001DirectPendingTransaction,
  rollbackSbx001DirectInterruptedAcquire,
  rollbackSbx001DirectOrphanedNormalLock,
  rollbackSbx001DirectInterruptedRelease,
  resumeSbx001DirectInterruptedRelease,
  settleSbx001DirectRemovalClaims,
  type Sbx001DirectHeldLock as AtomicLiveLock,
} from "./direct-live-lock.js";

export const SBX001_DIRECT_ARTIFACTS_DIRECTORY = fileURLToPath(new URL("../../artifacts", import.meta.url));
export const SBX001_DIRECT_LIVE_LOCK = resolve(
  SBX001_DIRECT_ARTIFACTS_DIRECTORY,
  "SBX-001-direct-active.lock",
);
export const SBX001_DIRECT_SANDBOX_TIMEOUT_MS = 300_000 as const;
export const SBX001_DIRECT_CREATE_REQUEST_TIMEOUT_MS = 45_000 as const;
export const SBX001_DIRECT_UNKNOWN_CREATE_SETTLEMENT_MS =
  SBX001_DIRECT_CREATE_REQUEST_TIMEOUT_MS + SBX001_DIRECT_SANDBOX_TIMEOUT_MS + 30_000;
export const SBX001_DIRECT_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SESSION_ID = /^sbx_[A-Za-z0-9_-]{8,192}$/u;
const OPERATION_ID = /^dns_[A-Za-z0-9_-]{43}$/u;
const MAXIMUM_PRIVATE_FILE_BYTES = 4 * 1024 * 1024;

export interface Sbx001DirectRecoveryJournal {
  schemaVersion: 1;
  testId: typeof SBX001_DIRECT_TEST_ID;
  runId: string;
  sandboxName: string;
  tags: Record<string, string>;
  persistent: false;
  timeoutMs: typeof SBX001_DIRECT_SANDBOX_TIMEOUT_MS;
  startedAt: string;
  updatedAt: string;
  receiverConfigureAttemptedAt?: string;
  receiverConfigured: boolean;
  createAttemptedAt?: string;
  createRequestSettledAt?: string;
  sessionId?: string;
  sandboxAttributed: boolean;
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  sandboxAbsenceChecks: number;
  sandboxPrefixAbsent: boolean;
  finalReceiverSnapshotCaptured: boolean;
  finalReceiverSnapshot?: Sbx001ReceiverSnapshot;
  receiverDeleteAttempted: boolean;
  receiverDeleted: boolean;
  receiverAbsenceChecks: number;
  artifactWriteAttemptedAt?: string;
  artifactWritten: boolean;
  completed: boolean;
  rawQueryNamesRetained: false;
  rawSecretsRetained: false;
  rawSecretDigestsRetained: false;
}

export interface Sbx001DirectHeldState {
  liveLock: AtomicLiveLock;
  lockPath: string;
  journalPath: string;
  lockMode: number;
  journalMode: number;
  runId: string;
}

interface Sbx001DirectPrivateFileIdentity {
  device: bigint;
  inode: bigint;
}

type JournalMutation = "journal-install-created" | "journal-installed" |
  "journal-created" | "journal-install-claimed" | "journal-checkpoint-opened" |
  "journal-checkpoint-partial" |
  "journal-checkpoint-written" | "journal-removal-claimed";
type JournalMutationHook = (mutation: JournalMutation) => void | Promise<void>;

interface JournalOwnership extends Sbx001DirectPrivateFileIdentity {
  sequence: number;
}

const journalIdentities = new WeakMap<Sbx001DirectHeldState, JournalOwnership>();
const artifactIdentities = new Map<string, Sbx001DirectPrivateFileIdentity>();

function heldStateWithJournalIdentity(
  held: Sbx001DirectHeldState,
  identity: JournalOwnership,
): Sbx001DirectHeldState {
  journalIdentities.set(held, identity);
  return held;
}

function timestamp(value: unknown): value is string {
  if (typeof value !== "string" || value.length !== 24) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function exactKeys(value: object, required: readonly string[], optional: readonly string[] = []): boolean {
  const actual = Object.keys(value);
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(value, key)) && actual.every((key) => allowed.has(key)) &&
    actual.length === required.length + optional.filter((key) => Object.hasOwn(value, key)).length;
}

function exactRecord(actual: unknown, expected: Record<string, string>): boolean {
  if (actual === null || typeof actual !== "object" || Array.isArray(actual)) return false;
  const record = actual as Record<string, unknown>;
  const keys = Object.keys(expected);
  return Object.keys(record).length === keys.length && keys.every((key) => record[key] === expected[key]);
}

function parseFinalReceiverSnapshot(value: unknown, runId: string): Sbx001ReceiverSnapshot {
  if (value === null || typeof value !== "object" || Array.isArray(value) || !exactKeys(value, [
    "configured", "runId", "configuredAt", "expiresAt", "observationWindowMs", "receipts", "arms",
    "secretRegistered", "rawQueryNamesRetained", "rawSecretsRetained", "rawSecretDigestsRetained",
  ], ["secretRegisteredAt"])) {
    throw new Error("SBX-001 direct final receiver snapshot fields were not exact");
  }
  const snapshot = value as Record<string, unknown>;
  if (snapshot.configured !== true || snapshot.runId !== runId || !timestamp(snapshot.configuredAt) ||
      !timestamp(snapshot.expiresAt) ||
      Date.parse(snapshot.expiresAt as string) - Date.parse(snapshot.configuredAt as string) !==
        SBX001_RECEIVER_WINDOW_MS ||
      snapshot.observationWindowMs !== SBX001_RECEIVER_WINDOW_MS || !Array.isArray(snapshot.receipts) ||
      !Array.isArray(snapshot.arms) || snapshot.arms.length > Object.keys(SBX001_CASES).length ||
      snapshot.receipts.length > Object.keys(SBX001_CASES).length ||
      typeof snapshot.secretRegistered !== "boolean" ||
      (snapshot.secretRegistered === true ? !timestamp(snapshot.secretRegisteredAt) :
        snapshot.secretRegisteredAt !== undefined) ||
      snapshot.rawQueryNamesRetained !== false || snapshot.rawSecretsRetained !== false ||
      snapshot.rawSecretDigestsRetained !== false) {
    throw new Error("SBX-001 direct final receiver snapshot was invalid");
  }

  const caseIds = new Set<string>(Object.values(SBX001_CASES));
  const armsByCase = new Map<Sbx001CaseId, { caseId: Sbx001CaseId; armedAt: string; operationId: string }>();
  for (const valueArm of snapshot.arms) {
    if (valueArm === null || typeof valueArm !== "object" || Array.isArray(valueArm) || !exactKeys(valueArm, [
      "caseId", "armedAt", "operationId",
    ])) throw new Error("SBX-001 direct final receiver arm fields were not exact");
    const arm = valueArm as Record<string, unknown>;
    if (typeof arm.caseId !== "string" || !caseIds.has(arm.caseId) || armsByCase.has(arm.caseId as Sbx001CaseId) ||
        !timestamp(arm.armedAt) || typeof arm.operationId !== "string" || !OPERATION_ID.test(arm.operationId) ||
        Date.parse(arm.armedAt) < Date.parse(snapshot.configuredAt as string) ||
        Date.parse(arm.armedAt) > Date.parse(snapshot.expiresAt as string)) {
      throw new Error("SBX-001 direct final receiver arm was invalid");
    }
    armsByCase.set(arm.caseId as Sbx001CaseId, {
      caseId: arm.caseId as Sbx001CaseId,
      armedAt: arm.armedAt,
      operationId: arm.operationId,
    });
  }

  const receiptCases = new Set<Sbx001CaseId>();
  for (const valueReceipt of snapshot.receipts) {
    if (valueReceipt === null || typeof valueReceipt !== "object" || Array.isArray(valueReceipt) ||
        !exactKeys(valueReceipt, [
          "runId", "caseId", "kind", "transport", "queryType", "authoritativeResponseSent", "operationId",
          "armedAt", "observedAt", "sourceAddress", "sourcePort", "duplicateCount", "withinConfiguredWindow",
          "rawQueryNameRetained", "rawSecretRetained", "rawSecretDigestRetained",
        ])) throw new Error("SBX-001 direct final receiver receipt fields were not exact");
    const receipt = valueReceipt as Record<string, unknown>;
    const caseId = receipt.caseId as Sbx001CaseId;
    const arm = armsByCase.get(caseId);
    if (receipt.runId !== runId || typeof receipt.caseId !== "string" || !caseIds.has(receipt.caseId) ||
        receiptCases.has(caseId) || !timestamp(receipt.armedAt) || !timestamp(receipt.observedAt) ||
        Date.parse(receipt.observedAt) < Date.parse(receipt.armedAt) ||
        typeof receipt.operationId !== "string" || !OPERATION_ID.test(receipt.operationId) ||
        arm === undefined || arm.armedAt !== receipt.armedAt || arm.operationId !== receipt.operationId ||
        receipt.kind !== (caseId === SBX001_CASES.denySecret ? "secret" : "public") ||
        (receipt.transport !== "udp" && receipt.transport !== "tcp") || receipt.queryType !== "A" ||
        typeof receipt.authoritativeResponseSent !== "boolean" ||
        typeof receipt.sourceAddress !== "string" || isIP(receipt.sourceAddress) === 0 ||
        !Number.isInteger(receipt.sourcePort) || Number(receipt.sourcePort) < 0 || Number(receipt.sourcePort) > 65_535 ||
        !Number.isInteger(receipt.duplicateCount) || Number(receipt.duplicateCount) < 0 ||
        receipt.withinConfiguredWindow !== true || receipt.rawQueryNameRetained !== false ||
        receipt.rawSecretRetained !== false || receipt.rawSecretDigestRetained !== false) {
      throw new Error("SBX-001 direct final receiver receipt was invalid");
    }
    receiptCases.add(caseId);
  }
  return value as Sbx001ReceiverSnapshot;
}

export function sbx001DirectSandboxName(runId: string): string {
  if (!SBX001_DIRECT_UUID.test(runId)) throw new Error("SBX-001 direct run ID was not canonical");
  return `sbx-001-direct-${runId.replaceAll("-", "")}`;
}

export function sbx001DirectTags(runId: string): Record<string, string> {
  return { harness: "vsc", test: "sbx-001-direct", run: runId };
}

export function sbx001DirectJournalPath(runId: string): string {
  if (!SBX001_DIRECT_UUID.test(runId)) throw new Error("SBX-001 direct run ID was not canonical");
  return resolve(SBX001_DIRECT_ARTIFACTS_DIRECTORY, `SBX-001-direct-${runId}-recovery.json`);
}

export function sbx001DirectArtifactPath(runId: string): string {
  if (!SBX001_DIRECT_UUID.test(runId)) throw new Error("SBX-001 direct run ID was not canonical");
  return resolve(SBX001_DIRECT_ARTIFACTS_DIRECTORY, `SBX-001-direct-${runId}-private.json`);
}

export function sbx001DirectFinalizationReceiptPath(runId: string): string {
  if (!SBX001_DIRECT_UUID.test(runId)) throw new Error("SBX-001 direct run ID was not canonical");
  return resolve(SBX001_DIRECT_ARTIFACTS_DIRECTORY, `SBX-001-direct-${runId}-finalization.json`);
}

export interface Sbx001DirectFinalizationReceipt {
  schemaVersion: 1;
  testId: typeof SBX001_DIRECT_TEST_ID;
  kind: "finalization-receipt";
  runId: string;
  artifactPath: string;
  finalizedAt: string;
  artifactWritten: true;
  journalRemoved: true;
  lockReleased: true;
  rawQueryNamesRetained: false;
  rawSecretsRetained: false;
  rawSecretDigestsRetained: false;
}

export function sbx001DirectRecoveryArtifactPath(runId: string, attemptId: string): string {
  if (!SBX001_DIRECT_UUID.test(runId) || !SBX001_DIRECT_UUID.test(attemptId)) {
    throw new Error("SBX-001 direct recovery artifact requires two canonical UUIDv4 values");
  }
  return resolve(
    SBX001_DIRECT_ARTIFACTS_DIRECTORY,
    `SBX-001-direct-${runId}-recovery-${attemptId}-private.json`,
  );
}

export function createSbx001DirectJournal(
  now: Date = new Date(),
  suppliedRunId?: string,
): Sbx001DirectRecoveryJournal {
  const runId = suppliedRunId ?? randomUUID();
  if (!SBX001_DIRECT_UUID.test(runId)) throw new Error("SBX-001 direct run ID was not canonical");
  const at = now.toISOString();
  return {
    schemaVersion: 1,
    testId: SBX001_DIRECT_TEST_ID,
    runId,
    sandboxName: sbx001DirectSandboxName(runId),
    tags: sbx001DirectTags(runId),
    persistent: false,
    timeoutMs: SBX001_DIRECT_SANDBOX_TIMEOUT_MS,
    startedAt: at,
    updatedAt: at,
    receiverConfigured: false,
    sandboxAttributed: false,
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    sandboxAbsenceChecks: 0,
    sandboxPrefixAbsent: false,
    finalReceiverSnapshotCaptured: false,
    receiverDeleteAttempted: false,
    receiverDeleted: false,
    receiverAbsenceChecks: 0,
    artifactWritten: false,
    completed: false,
    rawQueryNamesRetained: false,
    rawSecretsRetained: false,
    rawSecretDigestsRetained: false,
  };
}

export function parseSbx001DirectJournal(value: unknown): Sbx001DirectRecoveryJournal {
  if (value === null || typeof value !== "object" || Array.isArray(value) || !exactKeys(value, [
    "schemaVersion", "testId", "runId", "sandboxName", "tags", "persistent", "timeoutMs", "startedAt",
    "updatedAt", "receiverConfigured", "sandboxAttributed", "stopAttempted", "stopped", "deleteAttempted",
    "deleted", "sandboxAbsenceChecks", "sandboxPrefixAbsent", "finalReceiverSnapshotCaptured",
    "receiverDeleteAttempted", "receiverDeleted", "receiverAbsenceChecks", "artifactWritten", "completed",
    "rawQueryNamesRetained", "rawSecretsRetained", "rawSecretDigestsRetained",
  ], [
    "receiverConfigureAttemptedAt", "createAttemptedAt", "createRequestSettledAt", "sessionId",
    "artifactWriteAttemptedAt", "finalReceiverSnapshot",
  ])) throw new Error("SBX-001 direct recovery journal fields were not exact");
  const record = value as Record<string, unknown>;
  const runId = record.runId;
  if (record.schemaVersion !== 1 || record.testId !== SBX001_DIRECT_TEST_ID ||
      typeof runId !== "string" || !SBX001_DIRECT_UUID.test(runId) ||
      record.sandboxName !== sbx001DirectSandboxName(runId) || !exactRecord(record.tags, sbx001DirectTags(runId)) ||
      record.persistent !== false || record.timeoutMs !== SBX001_DIRECT_SANDBOX_TIMEOUT_MS ||
      !timestamp(record.startedAt) || !timestamp(record.updatedAt) ||
      Date.parse(record.updatedAt) < Date.parse(record.startedAt) ||
      !(record.receiverConfigureAttemptedAt === undefined || timestamp(record.receiverConfigureAttemptedAt)) ||
      !(record.createAttemptedAt === undefined || timestamp(record.createAttemptedAt)) ||
      !(record.createRequestSettledAt === undefined || timestamp(record.createRequestSettledAt)) ||
      (record.createRequestSettledAt !== undefined && (record.createAttemptedAt === undefined ||
        Date.parse(record.createRequestSettledAt as string) < Date.parse(record.createAttemptedAt as string))) ||
      !(record.sessionId === undefined || (typeof record.sessionId === "string" && SESSION_ID.test(record.sessionId))) ||
      !(record.artifactWriteAttemptedAt === undefined || timestamp(record.artifactWriteAttemptedAt)) ||
      typeof record.receiverConfigured !== "boolean" || typeof record.sandboxAttributed !== "boolean" ||
      typeof record.stopAttempted !== "boolean" || typeof record.stopped !== "boolean" ||
      typeof record.deleteAttempted !== "boolean" || typeof record.deleted !== "boolean" ||
      !Number.isInteger(record.sandboxAbsenceChecks) || Number(record.sandboxAbsenceChecks) < 0 ||
      typeof record.sandboxPrefixAbsent !== "boolean" || typeof record.finalReceiverSnapshotCaptured !== "boolean" ||
      typeof record.receiverDeleteAttempted !== "boolean" || typeof record.receiverDeleted !== "boolean" ||
      !Number.isInteger(record.receiverAbsenceChecks) || Number(record.receiverAbsenceChecks) < 0 ||
      typeof record.artifactWritten !== "boolean" || typeof record.completed !== "boolean" ||
      record.rawQueryNamesRetained !== false || record.rawSecretsRetained !== false ||
      record.rawSecretDigestsRetained !== false) {
    throw new Error("SBX-001 direct recovery journal was invalid");
  }
  if ((record.receiverConfigured === true && record.receiverConfigureAttemptedAt === undefined) ||
      (record.createRequestSettledAt !== undefined && record.createAttemptedAt === undefined) ||
      ((record.sessionId !== undefined || record.sandboxAttributed === true) && record.createAttemptedAt === undefined) ||
      (record.sandboxAttributed === true && record.sessionId === undefined) ||
      (record.stopped === true && record.stopAttempted !== true) ||
      (record.deleted === true && record.deleteAttempted !== true) ||
      (record.finalReceiverSnapshotCaptured === true && record.receiverConfigureAttemptedAt === undefined) ||
      (record.finalReceiverSnapshotCaptured !== (record.finalReceiverSnapshot !== undefined)) ||
      (record.receiverDeleted === true && record.receiverDeleteAttempted !== true) ||
      (record.artifactWritten === true && record.artifactWriteAttemptedAt === undefined) ||
      (record.completed === true && record.artifactWritten !== true)) {
    throw new Error("SBX-001 direct recovery journal checkpoint dependencies were invalid");
  }
  if (record.finalReceiverSnapshot !== undefined) parseFinalReceiverSnapshot(record.finalReceiverSnapshot, runId);
  return record as unknown as Sbx001DirectRecoveryJournal;
}

function errorCode(error: unknown): string | undefined {
  return error !== null && typeof error === "object" && "code" in error &&
      typeof (error as { code?: unknown }).code === "string"
    ? (error as { code: string }).code
    : undefined;
}

function noFollow(): number {
  if (typeof fsConstants.O_NOFOLLOW !== "number" || fsConstants.O_NOFOLLOW === 0) {
    throw new Error("SBX-001 direct private state requires O_NOFOLLOW support");
  }
  return fsConstants.O_NOFOLLOW;
}

function currentUserId(): bigint {
  if (typeof process.getuid !== "function") throw new Error("SBX-001 direct private state requires a POSIX UID");
  return BigInt(process.getuid());
}

function assertPrivateFile(metadata: BigIntStats, expectedLinks: bigint | undefined = 1n): void {
  if (!metadata.isFile() || metadata.uid !== currentUserId() ||
      (expectedLinks !== undefined && metadata.nlink !== expectedLinks) ||
      (metadata.mode & 0o777n) !== 0o600n) {
    throw new Error("SBX-001 direct private state was not an exact current-user mode-0600 regular file");
  }
}

function samePrivateFileIdentity(
  left: Sbx001DirectPrivateFileIdentity,
  right: Sbx001DirectPrivateFileIdentity,
): boolean {
  return left.device === right.device && left.inode === right.inode;
}

interface OpenedPrivateFile extends Sbx001DirectPrivateFileIdentity {
  handle: FileHandle;
  mode: number;
}

async function openPrivateFile(
  path: string,
  flags: number = fsConstants.O_RDONLY,
  expectedLinks: bigint | undefined = 1n,
): Promise<OpenedPrivateFile> {
  const before = await lstat(path, { bigint: true });
  if (!before.isFile() || before.uid !== currentUserId() ||
      (expectedLinks !== undefined && before.nlink !== expectedLinks) ||
      (before.mode & 0o777n) !== 0o600n) {
    throw new Error("SBX-001 direct private-state path failed exact security checks");
  }
  const handle = await open(path, flags | noFollow());
  try {
    const held = await handle.stat({ bigint: true });
    assertPrivateFile(held, expectedLinks);
    const identity = { device: held.dev, inode: held.ino };
    if (!samePrivateFileIdentity(identity, { device: before.dev, inode: before.ino })) {
      throw new Error("SBX-001 direct private-state path changed while opening");
    }
    const after = await lstat(path, { bigint: true });
    if (!samePrivateFileIdentity(identity, { device: after.dev, inode: after.ino })) {
      throw new Error("SBX-001 direct private-state path changed during inspection");
    }
    return { handle, mode: Number(held.mode & 0o777n), ...identity };
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw error;
  }
}

async function exactPrivateFileIdentity(path: string): Promise<Sbx001DirectPrivateFileIdentity & { mode: number }> {
  const opened = await openPrivateFile(path);
  await opened.handle.close();
  return { mode: opened.mode, device: opened.device, inode: opened.inode };
}

async function exactPrivateFile(path: string): Promise<number> {
  return (await exactPrivateFileIdentity(path)).mode;
}

async function readBounded(handle: FileHandle): Promise<Buffer> {
  const retained = Buffer.allocUnsafe(MAXIMUM_PRIVATE_FILE_BYTES + 1);
  let total = 0;
  while (total < retained.length) {
    const read = await handle.read(retained, total, retained.length - total, total);
    if (read.bytesRead === 0) break;
    total += read.bytesRead;
  }
  if (total === 0 || total > MAXIMUM_PRIVATE_FILE_BYTES) {
    retained.fill(0);
    throw new Error("SBX-001 direct private state exceeded its fixed byte bound");
  }
  const result = Buffer.from(retained.subarray(0, total));
  retained.fill(0);
  return result;
}

async function writeAll(handle: FileHandle, bytes: Buffer, position: number): Promise<void> {
  let written = 0;
  while (written < bytes.length) {
    const result = await handle.write(bytes, written, bytes.length - written, position + written);
    if (result.bytesWritten === 0) throw new Error("SBX-001 direct private-state write made no progress");
    written += result.bytesWritten;
  }
}

async function createNewPrivateFile(path: string, bytes: string): Promise<OpenedPrivateFile> {
  const handle = await open(
    path,
    fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_RDWR | noFollow(),
    0o600,
  );
  let identity: Sbx001DirectPrivateFileIdentity | undefined;
  try {
    const initial = await handle.stat({ bigint: true });
    identity = { device: initial.dev, inode: initial.ino };
    await handle.chmod(0o600);
    const encoded = Buffer.from(bytes, "utf8");
    try {
      if (encoded.length > MAXIMUM_PRIVATE_FILE_BYTES) throw new Error("SBX-001 direct private state was oversized");
      await writeAll(handle, encoded, 0);
      await handle.truncate(encoded.length);
      await handle.sync();
    } finally {
      encoded.fill(0);
    }
    const held = await handle.stat({ bigint: true });
    assertPrivateFile(held);
    identity = { device: held.dev, inode: held.ino };
    const current = await lstat(path, { bigint: true });
    if (!samePrivateFileIdentity(identity, { device: current.dev, inode: current.ino })) {
      throw new Error("SBX-001 direct private state lost pathname ownership during creation");
    }
    return { handle, mode: 0o600, ...identity };
  } catch (error) {
    await handle.close().catch(() => undefined);
    if (identity !== undefined) {
      try {
        const current = await lstat(path, { bigint: true });
        if (samePrivateFileIdentity(identity, { device: current.dev, inode: current.ino })) await unlink(path);
      } catch {
        // Preserve any pathname whose exact created inode cannot still be proven.
      }
    }
    throw error;
  }
}

function removalClaimPath(path: string, expected: Sbx001DirectPrivateFileIdentity): string {
  return `${path}.remove-${expected.device}-${expected.inode}`;
}

async function restoreClaimWithoutReplacement(claimPath: string, path: string): Promise<void> {
  await link(claimPath, path);
  await unlink(claimPath);
}

async function claimAndRemoveOwnedPrivateFile(
  path: string,
  expected: Sbx001DirectPrivateFileIdentity,
  hook?: JournalMutationHook,
  mutation?: JournalMutation,
  expectedLinks = 1n,
): Promise<void> {
  const current = await openPrivateFile(path, fsConstants.O_RDONLY, expectedLinks);
  try {
    if (!samePrivateFileIdentity(current, expected)) {
      throw new Error("SBX-001 direct private-state pathname was replaced; refusing removal");
    }
  } finally {
    await current.handle.close();
  }
  const claimPath = removalClaimPath(path, expected);
  try {
    await lstat(claimPath);
    throw new Error("SBX-001 direct deterministic removal claim already existed");
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw error;
  }
  await rename(path, claimPath);
  if (hook !== undefined && mutation !== undefined) await hook(mutation);
  const claimed = await openPrivateFile(claimPath, fsConstants.O_RDONLY, expectedLinks);
  try {
    if (!samePrivateFileIdentity(claimed, expected)) {
      await restoreClaimWithoutReplacement(claimPath, path).catch(() => undefined);
      throw new Error("SBX-001 direct private-state replacement was atomically claimed; preserved without removal");
    }
  } finally {
    await claimed.handle.close();
  }
  await unlink(claimPath);
}

async function writeNewPrivateFile(path: string, bytes: string): Promise<number> {
  const created = await createNewPrivateFile(path, bytes);
  await created.handle.close();
  return created.mode;
}

async function writeNoClobberOwnedPrivateFile(
  path: string,
  bytes: string,
  hook?: JournalMutationHook,
): Promise<Sbx001DirectPrivateFileIdentity & { mode: number }> {
  const installPath = `${path}.install`;
  const created = await createNewPrivateFile(installPath, bytes);
  try {
    await hook?.("journal-install-created");
    await link(installPath, path);
    await hook?.("journal-installed");
    const canonical = await openPrivateFile(path, fsConstants.O_RDONLY, 2n);
    try {
      if (!samePrivateFileIdentity(canonical, created)) {
        throw new Error("SBX-001 direct no-clobber installation did not retain its exact inode");
      }
    } finally {
      await canonical.handle.close();
    }
    await claimAndRemoveOwnedPrivateFile(installPath, created, hook, "journal-install-claimed", 2n);
    await hook?.("journal-created");
    return exactPrivateFileIdentity(path);
  } catch (error) {
    try {
      const install = await exactPrivateFileIdentity(installPath);
      if (samePrivateFileIdentity(install, created)) {
        await claimAndRemoveOwnedPrivateFile(installPath, created).catch(() => undefined);
      }
    } catch {
      // A child death leaves deterministic install state for the recovery dispatcher.
    }
    throw error;
  } finally {
    await created.handle.close().catch(() => undefined);
  }
}

async function writeNoClobberPrivateFile(path: string, bytes: string): Promise<number> {
  return (await writeNoClobberOwnedPrivateFile(path, bytes)).mode;
}

interface JournalCheckpointRecord {
  schemaVersion: 1;
  testId: typeof SBX001_DIRECT_TEST_ID;
  kind: "recovery-journal-checkpoint";
  sequence: number;
  journal: Sbx001DirectRecoveryJournal;
}

function encodeCheckpoint(journal: Sbx001DirectRecoveryJournal, sequence: number): Buffer {
  const record: JournalCheckpointRecord = {
    schemaVersion: 1,
    testId: SBX001_DIRECT_TEST_ID,
    kind: "recovery-journal-checkpoint",
    sequence,
    journal,
  };
  return Buffer.from(`${JSON.stringify(record)}\n`, "utf8");
}

function parseCheckpoint(value: unknown, expectedSequence: number): JournalCheckpointRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value) || !exactKeys(value, [
    "schemaVersion", "testId", "kind", "sequence", "journal",
  ])) throw new Error("SBX-001 direct journal checkpoint fields were not exact");
  const record = value as Record<string, unknown>;
  if (record.schemaVersion !== 1 || record.testId !== SBX001_DIRECT_TEST_ID ||
      record.kind !== "recovery-journal-checkpoint" || record.sequence !== expectedSequence) {
    throw new Error("SBX-001 direct journal checkpoint sequence or identity was invalid");
  }
  return { ...record, journal: parseSbx001DirectJournal(record.journal) } as JournalCheckpointRecord;
}

interface OpenedJournalLog extends OpenedPrivateFile {
  journal: Sbx001DirectRecoveryJournal;
  sequence: number;
  completeBytes: number;
  totalBytes: number;
}

async function openJournalLog(
  path: string,
  writable = false,
  expectedLinks: bigint | undefined = 1n,
): Promise<OpenedJournalLog> {
  const opened = await openPrivateFile(
    path,
    writable ? fsConstants.O_RDWR : fsConstants.O_RDONLY,
    expectedLinks,
  );
  try {
    const bytes = await readBounded(opened.handle);
    try {
      const lastNewline = bytes.lastIndexOf(0x0a);
      if (lastNewline < 0) throw new Error("SBX-001 direct journal lacked a complete checkpoint");
      const lines = bytes.subarray(0, lastNewline).toString("utf8").split("\n");
      let checkpoint: JournalCheckpointRecord | undefined;
      for (const [sequence, line] of lines.entries()) {
        if (line.length === 0) throw new Error("SBX-001 direct journal contained an empty checkpoint");
        let parsed: unknown;
        try {
          parsed = JSON.parse(line);
        } catch {
          throw new Error("SBX-001 direct journal checkpoint was not valid JSON");
        }
        checkpoint = parseCheckpoint(parsed, sequence);
      }
      if (checkpoint === undefined) throw new Error("SBX-001 direct journal had no checkpoints");
      return {
        ...opened,
        journal: checkpoint.journal,
        sequence: checkpoint.sequence,
        completeBytes: lastNewline + 1,
        totalBytes: bytes.length,
      };
    } finally {
      bytes.fill(0);
    }
  } catch (error) {
    await opened.handle.close().catch(() => undefined);
    throw error;
  }
}

async function optionalPrivateFile(path: string): Promise<OpenedPrivateFile | undefined> {
  try {
    return await openPrivateFile(path);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return undefined;
    throw error;
  }
}

async function removalClaims(path: string): Promise<string[]> {
  const prefix = `${basename(path)}.remove-`;
  return (await readdir(dirname(path))).filter((entry) => entry.startsWith(prefix))
    .map((entry) => resolve(dirname(path), entry)).sort();
}

async function settleJournalSidecars(runId: string, path: string): Promise<{ journalRemoved: boolean }> {
  let journalRemoved = false;
  const claims = await removalClaims(path);
  for (const claimPath of claims) {
    const claim = await openJournalLog(claimPath);
    try {
      if (claim.journal.runId !== runId) throw new Error("SBX-001 direct journal removal claim belonged to another run");
      await unlink(claimPath);
      journalRemoved = true;
    } finally {
      await claim.handle.close().catch(() => undefined);
    }
  }

  const installPath = `${path}.install`;
  for (const installClaim of await removalClaims(installPath)) {
    const claim = await openJournalLog(installClaim, false,
      (await lstat(installClaim, { bigint: true })).nlink);
    try {
      if (claim.journal.runId !== runId) throw new Error("SBX-001 direct journal install claim belonged to another run");
      await unlink(installClaim);
    } finally {
      await claim.handle.close().catch(() => undefined);
    }
  }

  let install: OpenedJournalLog | undefined;
  try {
    try {
      install = await openJournalLog(installPath, false,
        (await lstat(installPath, { bigint: true })).nlink);
    } catch (error) {
      if (errorCode(error) !== "ENOENT") throw error;
    }
    if (install !== undefined) {
      if (install.journal.runId !== runId) throw new Error("SBX-001 direct journal install belonged to another run");
      await claimAndRemoveOwnedPrivateFile(installPath, install, undefined, undefined,
        (await lstat(installPath, { bigint: true })).nlink);
    }
  } finally {
    await install?.handle.close().catch(() => undefined);
  }
  return { journalRemoved };
}

/** Test seam for deterministic no-clobber installation in an isolated directory. */
export async function writeSbx001DirectPrivateFileAtPathForTest(path: string, value: unknown): Promise<number> {
  return writeNoClobberPrivateFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

async function acquireStateAtPaths(
  journal: Sbx001DirectRecoveryJournal,
  lockPath: string,
  journalPath: string,
  hook?: JournalMutationHook,
): Promise<Sbx001DirectHeldState> {
  parseSbx001DirectJournal(journal);
  const liveLock = await acquireSbx001DirectLiveLock(lockPath, journal.runId, false);
  let journalIdentity: JournalOwnership | undefined;
  try {
    const lockMode = await exactPrivateFile(lockPath);
    const initial = encodeCheckpoint(journal, 0);
    let created: Sbx001DirectPrivateFileIdentity & { mode: number };
    try {
      created = await writeNoClobberOwnedPrivateFile(journalPath, initial.toString("utf8"), hook);
    } finally {
      initial.fill(0);
    }
    journalIdentity = { ...created, sequence: 0 };
    return heldStateWithJournalIdentity({
      liveLock,
      lockPath,
      journalPath,
      lockMode,
      journalMode: created.mode,
      runId: journal.runId,
    }, journalIdentity);
  } catch (error) {
    if (journalIdentity === undefined) {
      await liveLock.release().catch(() => undefined);
    } else {
      await liveLock.releaseAfter(async () => {
        await claimAndRemoveOwnedPrivateFile(journalPath, journalIdentity!, hook, "journal-removal-claimed");
      }).catch(() => undefined);
    }
    throw error;
  }
}

export async function acquireSbx001DirectState(
  journal: Sbx001DirectRecoveryJournal,
): Promise<Sbx001DirectHeldState> {
  await mkdir(SBX001_DIRECT_ARTIFACTS_DIRECTORY, { recursive: true, mode: 0o700 });
  return acquireStateAtPaths(journal, SBX001_DIRECT_LIVE_LOCK, sbx001DirectJournalPath(journal.runId));
}

export function acquireSbx001DirectStateAtPathsForTest(
  journal: Sbx001DirectRecoveryJournal,
  lockPath: string,
  journalPath: string,
  hook?: JournalMutationHook,
): Promise<Sbx001DirectHeldState> {
  return acquireStateAtPaths(journal, lockPath, journalPath, hook);
}

async function readAt(runId: string, path: string): Promise<OpenedJournalLog> {
  const opened = await openJournalLog(path);
  if (opened.journal.runId !== runId) {
    await opened.handle.close();
    throw new Error("SBX-001 direct recovery journal run ID changed");
  }
  return opened;
}

async function acquireRecoveryAtPaths(
  runId: string,
  lockPath: string,
  journalPath: string,
): Promise<Sbx001DirectHeldState> {
  await settleJournalSidecars(runId, journalPath);
  await rollbackSbx001DirectInterruptedRelease(lockPath, runId);
  const liveLock = await acquireSbx001DirectLiveLock(lockPath, runId, true);
  try {
    const lockMode = await exactPrivateFile(lockPath);
    const journal = await readAt(runId, journalPath);
    await journal.handle.close();
    return heldStateWithJournalIdentity({
      liveLock,
      lockPath,
      journalPath,
      lockMode,
      journalMode: journal.mode,
      runId,
    }, { device: journal.device, inode: journal.inode, sequence: journal.sequence });
  } catch (error) {
    await liveLock.closeRetainingState();
    throw error;
  }
}

export function acquireSbx001DirectRecoveryState(runId: string): Promise<Sbx001DirectHeldState> {
  return acquireRecoveryAtPaths(runId, SBX001_DIRECT_LIVE_LOCK, sbx001DirectJournalPath(runId));
}

export function acquireSbx001DirectRecoveryStateAtPathsForTest(
  runId: string,
  lockPath: string,
  journalPath: string,
): Promise<Sbx001DirectHeldState> {
  return acquireRecoveryAtPaths(runId, lockPath, journalPath);
}

async function resumeFinalizationAtPaths(runId: string, lockPath: string, journalPath: string): Promise<boolean> {
  const journalSettlement = await settleJournalSidecars(runId, journalPath);
  const lockSettlement = await settleSbx001DirectRemovalClaims(lockPath, runId);
  try {
    const journal = await readAt(runId, journalPath);
    await journal.handle.close();
    return false;
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw error;
  }
  const pending = await inspectSbx001DirectPendingTransaction(lockPath, runId);
  if (pending?.operation === "release") return resumeSbx001DirectInterruptedRelease(lockPath, runId);
  if (pending?.operation === "acquire") return rollbackSbx001DirectInterruptedAcquire(lockPath, runId);
  if (await rollbackSbx001DirectOrphanedNormalLock(lockPath, runId)) return true;
  return journalSettlement.journalRemoved || lockSettlement.canonicalRemoved ||
    lockSettlement.transactionOperation === "release";
}

export function resumeSbx001DirectInterruptedFinalization(runId: string): Promise<boolean> {
  return resumeFinalizationAtPaths(runId, SBX001_DIRECT_LIVE_LOCK, sbx001DirectJournalPath(runId));
}

export function resumeSbx001DirectInterruptedFinalizationAtPathsForTest(
  runId: string,
  lockPath: string,
  journalPath: string,
): Promise<boolean> {
  return resumeFinalizationAtPaths(runId, lockPath, journalPath);
}

export async function readSbx001DirectJournal(runId: string): Promise<Sbx001DirectRecoveryJournal> {
  const opened = await readAt(runId, sbx001DirectJournalPath(runId));
  await opened.handle.close();
  return opened.journal;
}

export async function readSbx001DirectJournalAtPathForTest(
  runId: string,
  path: string,
): Promise<Sbx001DirectRecoveryJournal> {
  const opened = await readAt(runId, path);
  await opened.handle.close();
  return opened.journal;
}

async function persistAt(
  held: Sbx001DirectHeldState,
  journal: Sbx001DirectRecoveryJournal,
  requireCanonicalPath: boolean,
  hook?: JournalMutationHook,
): Promise<void> {
  if (held.runId !== journal.runId ||
      (requireCanonicalPath && held.journalPath !== sbx001DirectJournalPath(journal.runId))) {
    throw new Error("SBX-001 direct journal/lock run mismatch");
  }
  const ownership = journalIdentities.get(held);
  if (ownership === undefined) throw new Error("SBX-001 direct held state lacked its journal ownership");
  journal.updatedAt = new Date().toISOString();
  parseSbx001DirectJournal(journal);
  const opened = await openJournalLog(held.journalPath, true);
  try {
    if (!samePrivateFileIdentity(opened, ownership)) {
      throw new Error("SBX-001 direct journal pathname was replaced before checkpoint persistence");
    }
    await hook?.("journal-checkpoint-opened");
    if (opened.totalBytes !== opened.completeBytes) {
      await opened.handle.truncate(opened.completeBytes);
      await opened.handle.sync();
    }
    const nextSequence = opened.sequence + 1;
    const encoded = encodeCheckpoint(journal, nextSequence);
    try {
      if (opened.completeBytes + encoded.length > MAXIMUM_PRIVATE_FILE_BYTES) {
        throw new Error("SBX-001 direct journal exceeded its append-only checkpoint bound");
      }
      const firstLength = Math.max(1, Math.floor(encoded.length / 2));
      await writeAll(opened.handle, encoded.subarray(0, firstLength), opened.completeBytes);
      await hook?.("journal-checkpoint-partial");
      await writeAll(opened.handle, encoded.subarray(firstLength), opened.completeBytes + firstLength);
      await hook?.("journal-checkpoint-written");
      await opened.handle.sync();
      const current = await exactPrivateFileIdentity(held.journalPath);
      if (!samePrivateFileIdentity(current, ownership)) {
        throw new Error("SBX-001 direct journal pathname was replaced during checkpoint persistence");
      }
      journalIdentities.set(held, { ...ownership, sequence: nextSequence });
    } finally {
      encoded.fill(0);
    }
  } finally {
    await opened.handle.close().catch(() => undefined);
  }
}

export function persistSbx001DirectJournal(
  held: Sbx001DirectHeldState,
  journal: Sbx001DirectRecoveryJournal,
): Promise<void> {
  return persistAt(held, journal, true);
}

export function persistSbx001DirectJournalAtPathForTest(
  held: Sbx001DirectHeldState,
  journal: Sbx001DirectRecoveryJournal,
  hook?: JournalMutationHook,
): Promise<void> {
  return persistAt(held, journal, false, hook);
}

async function releaseAt(held: Sbx001DirectHeldState, hook?: JournalMutationHook): Promise<void> {
  if (held.liveLock.isReleased()) {
    journalIdentities.delete(held);
    return;
  }
  const journalIdentity = journalIdentities.get(held);
  if (journalIdentity === undefined) throw new Error("SBX-001 direct held state lacked its owned journal identity");
  await held.liveLock.releaseAfter(async () => {
    await claimAndRemoveOwnedPrivateFile(held.journalPath, journalIdentity, hook, "journal-removal-claimed");
  });
  if (!held.liveLock.isReleased()) throw new Error("SBX-001 direct live lock did not reach released state");
  journalIdentities.delete(held);
}

export function releaseSbx001DirectState(held: Sbx001DirectHeldState): Promise<void> {
  return releaseAt(held);
}

export function releaseSbx001DirectStateAtPathForTest(
  held: Sbx001DirectHeldState,
  hook?: JournalMutationHook,
): Promise<void> {
  return releaseAt(held, hook);
}

async function readPrivateJson(path: string): Promise<{ value: unknown; identity: Sbx001DirectPrivateFileIdentity }> {
  const opened = await openPrivateFile(path);
  try {
    const bytes = await readBounded(opened.handle);
    try {
      let value: unknown;
      try {
        value = JSON.parse(bytes.toString("utf8"));
      } catch {
        throw new Error("SBX-001 direct private artifact was not valid JSON");
      }
      const current = await exactPrivateFileIdentity(path);
      if (!samePrivateFileIdentity(current, opened)) {
        throw new Error("SBX-001 direct private artifact pathname changed while reading");
      }
      return { value, identity: { device: opened.device, inode: opened.inode } };
    } finally {
      bytes.fill(0);
    }
  } finally {
    await opened.handle.close().catch(() => undefined);
  }
}

async function settleGenericInstall(path: string): Promise<void> {
  const installPath = `${path}.install`;
  for (const claimPath of await removalClaims(installPath)) {
    const claim = await openPrivateFile(claimPath, fsConstants.O_RDONLY,
      (await lstat(claimPath, { bigint: true })).nlink);
    try {
      await unlink(claimPath);
    } finally {
      await claim.handle.close().catch(() => undefined);
    }
  }
  let install: OpenedPrivateFile | undefined;
  let canonical: OpenedPrivateFile | undefined;
  try {
    try {
      install = await openPrivateFile(installPath, fsConstants.O_RDONLY,
        (await lstat(installPath, { bigint: true })).nlink);
    } catch (error) {
      if (errorCode(error) === "ENOENT") return;
      throw error;
    }
    canonical = await optionalPrivateFile(path);
    const links = canonical !== undefined && samePrivateFileIdentity(canonical, install) ? 2n : 1n;
    await claimAndRemoveOwnedPrivateFile(installPath, install, undefined, undefined, links);
  } finally {
    await canonical?.handle.close().catch(() => undefined);
    await install?.handle.close().catch(() => undefined);
  }
}

export async function writeSbx001DirectPrivateArtifact(path: string, value: unknown): Promise<number> {
  const record = value as { runId?: string; recoveryAttemptId?: string; mode?: string };
  const expected = record.mode === "cleanup-only"
    ? sbx001DirectRecoveryArtifactPath(record.runId ?? "", record.recoveryAttemptId ?? "")
    : sbx001DirectArtifactPath(record.runId ?? "");
  if (path !== expected) throw new Error("SBX-001 direct artifact path did not match its run ID");
  await settleGenericInstall(path);
  const created = await writeNoClobberOwnedPrivateFile(path, `${JSON.stringify(value, null, 2)}\n`);
  artifactIdentities.set(path, created);
  return created.mode;
}

/**
 * In-place post-release finalization is deliberately disabled. Controllers
 * must create the distinct immutable finalization receipt instead.
 */
export async function finalizeSbx001DirectPrivateArtifact(path: string, value: unknown): Promise<number> {
  const record = value as { runId?: string; mode?: string };
  if (record.mode === "cleanup-only" || path !== sbx001DirectArtifactPath(record.runId ?? "")) {
    throw new Error("SBX-001 direct final artifact path did not match its experiment run ID");
  }
  throw new Error("SBX-001 direct in-place artifact finalization is disabled; write an immutable finalization receipt");
}

export async function readSbx001DirectPendingArtifact(runId: string): Promise<unknown | undefined> {
  const path = sbx001DirectArtifactPath(runId);
  await settleGenericInstall(path);
  let read: { value: unknown; identity: Sbx001DirectPrivateFileIdentity };
  try {
    read = await readPrivateJson(path);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return undefined;
    throw error;
  }
  const record = read.value as { runId?: unknown; mode?: unknown };
  if (record === null || typeof record !== "object" || record.runId !== runId || record.mode === "cleanup-only") {
    throw new Error("SBX-001 direct pending artifact did not have exact experiment provenance");
  }
  artifactIdentities.set(path, read.identity);
  return read.value;
}

export function parseSbx001DirectFinalizationReceipt(value: unknown): Sbx001DirectFinalizationReceipt {
  if (value === null || typeof value !== "object" || Array.isArray(value) || !exactKeys(value, [
    "schemaVersion", "testId", "kind", "runId", "artifactPath", "finalizedAt", "artifactWritten",
    "journalRemoved", "lockReleased", "rawQueryNamesRetained", "rawSecretsRetained",
    "rawSecretDigestsRetained",
  ])) throw new Error("SBX-001 direct finalization receipt fields were not exact");
  const receipt = value as Record<string, unknown>;
  if (receipt.schemaVersion !== 1 || receipt.testId !== SBX001_DIRECT_TEST_ID ||
      receipt.kind !== "finalization-receipt" || typeof receipt.runId !== "string" ||
      !SBX001_DIRECT_UUID.test(receipt.runId) || receipt.artifactPath !== sbx001DirectArtifactPath(receipt.runId) ||
      !timestamp(receipt.finalizedAt) || receipt.artifactWritten !== true || receipt.journalRemoved !== true ||
      receipt.lockReleased !== true || receipt.rawQueryNamesRetained !== false || receipt.rawSecretsRetained !== false ||
      receipt.rawSecretDigestsRetained !== false) {
    throw new Error("SBX-001 direct finalization receipt was invalid");
  }
  return receipt as unknown as Sbx001DirectFinalizationReceipt;
}

async function requireAbsent(path: string, description: string): Promise<void> {
  try {
    await lstat(path, { bigint: true });
  } catch (error) {
    if (errorCode(error) === "ENOENT") return;
    throw error;
  }
  throw new Error(`${description} must be absent before finalization receipt creation`);
}

export async function writeSbx001DirectFinalizationReceipt(
  receipt: Sbx001DirectFinalizationReceipt,
): Promise<number> {
  const parsed = parseSbx001DirectFinalizationReceipt(receipt);
  const pending = await readSbx001DirectPendingArtifact(parsed.runId);
  if (pending === undefined) throw new Error("SBX-001 direct finalization receipt lacked its pending artifact");
  await requireAbsent(SBX001_DIRECT_LIVE_LOCK, "SBX-001 direct live lock");
  await requireAbsent(sbx001DirectJournalPath(parsed.runId), "SBX-001 direct recovery journal");
  const path = sbx001DirectFinalizationReceiptPath(parsed.runId);
  await settleGenericInstall(path);
  return writeNoClobberPrivateFile(path, `${JSON.stringify(parsed, null, 2)}\n`);
}

export async function readSbx001DirectFinalizationReceipt(
  runId: string,
): Promise<Sbx001DirectFinalizationReceipt | undefined> {
  const path = sbx001DirectFinalizationReceiptPath(runId);
  await settleGenericInstall(path);
  try {
    return parseSbx001DirectFinalizationReceipt((await readPrivateJson(path)).value);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return undefined;
    throw error;
  }
}

export function sbx001DirectCreateSettlementReached(
  journal: Sbx001DirectRecoveryJournal,
  now: number = Date.now(),
): boolean {
  return journal.createAttemptedAt !== undefined &&
    now >= Date.parse(journal.createAttemptedAt) + SBX001_DIRECT_UNKNOWN_CREATE_SETTLEMENT_MS;
}
