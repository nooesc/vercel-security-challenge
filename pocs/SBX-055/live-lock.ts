import { randomBytes } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import { link, lstat, mkdir, open, readdir, rename, unlink, type FileHandle } from "node:fs/promises";
import { basename, dirname, isAbsolute } from "node:path";

const TEST_ID = "SBX-055-STALE-INTERACTIVE-RESUME" as const;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const LEASE = /^[A-Za-z0-9_-]{43}$/u;
const MAXIMUM_METADATA_BYTES = 4_096;

type LockMode = "normal" | "cleanup-only";

interface LiveLockMetadata {
  schemaVersion: 1;
  testId: typeof TEST_ID;
  kind: "live-lock";
  runId: string;
  pid: number;
  lease: string;
  createdAt: string;
  mode: LockMode;
}

interface TransactionMetadata {
  schemaVersion: 1;
  testId: typeof TEST_ID;
  kind: "live-lock-transaction";
  runId: string;
  pid: number;
  lease: string;
  createdAt: string;
  mode: LockMode;
  operation: "acquire" | "release";
  targetLease?: string;
  targetPid?: number;
}

interface TransactionFinalizerMetadata {
  schemaVersion: 1;
  testId: typeof TEST_ID;
  kind: "live-lock-transaction-finalizer";
  runId: string;
  pid: number;
  lease: string;
  createdAt: string;
  targetTransactionPid: number;
  targetTransactionLease: string;
  targetOperation: "acquire" | "release";
  targetMode: LockMode;
  targetLockPid?: number;
  targetLockLease?: string;
}

type TransactionTarget = Pick<TransactionMetadata,
"runId" | "pid" | "lease" | "operation" | "mode" | "targetPid" | "targetLease">;

interface FileIdentity {
  device: bigint;
  inode: bigint;
}

interface OpenedSecureFile<T> extends FileIdentity {
  handle: FileHandle;
  metadata: T;
}

export interface Sbx055HeldLock {
  readonly runId: string;
  readonly path: string;
  isReleased(): boolean;
  closeRetainingState(): Promise<void>;
  releaseAfter(preCommit: () => Promise<void>): Promise<void>;
  release(): Promise<void>;
}

export interface Sbx055PendingTransaction {
  operation: "acquire" | "release";
  mode: "normal" | "cleanup-only";
}

export interface Sbx055RemovalSettlement {
  canonicalRemoved: boolean;
  transactionOperation?: "acquire" | "release";
}

export type Sbx055LiveLockMutation =
  | "acquire-transaction-created"
  | "acquire-replacement-created"
  | "acquire-stale-claimed"
  | "acquire-canonical-installed"
  | "acquire-replacement-removed"
  | "acquire-stale-removed"
  | "recover-target-removed"
  | "recover-replacement-removed"
  | "recover-source-linked"
  | "recover-stale-removed"
  | "recover-transaction-removed"
  | "finalizer-replacement-created"
  | "finalizer-election-created"
  | "finalizer-installed"
  | "finalizer-election-removed"
  | "finalizer-transaction-removed"
  | "orphan-release-transaction-created"
  | "orphan-canonical-removed"
  | "release-transaction-created"
  | "release-precommit-complete"
  | "release-canonical-claimed"
  | "release-transaction-claimed"
  | "acquire-transaction-claimed"
  | "release-canonical-removed";
type MutationHook = (mutation: Sbx055LiveLockMutation) => void | Promise<void>;

function errorCode(error: unknown): string | undefined {
  return error !== null && typeof error === "object" && "code" in error &&
      typeof (error as { code?: unknown }).code === "string"
    ? (error as { code: string }).code
    : undefined;
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
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function parseLiveLock(value: unknown): LiveLockMetadata {
  if (value === null || typeof value !== "object" || Array.isArray(value) || !exactKeys(value, [
    "schemaVersion", "testId", "kind", "runId", "pid", "lease", "createdAt", "mode",
  ])) {
    throw new Error("SBX-055 live-lock metadata fields were not exact");
  }
  const candidate = value as Record<string, unknown>;
  if (candidate.schemaVersion !== 1 || candidate.testId !== TEST_ID || candidate.kind !== "live-lock" ||
      typeof candidate.runId !== "string" || !UUID_V4.test(candidate.runId) ||
      typeof candidate.pid !== "number" || !Number.isSafeInteger(candidate.pid) || candidate.pid < 1 ||
      typeof candidate.lease !== "string" || !LEASE.test(candidate.lease) ||
      !timestamp(candidate.createdAt) ||
      (candidate.mode !== "normal" && candidate.mode !== "cleanup-only")) {
    throw new Error("SBX-055 live-lock metadata was invalid");
  }
  return candidate as unknown as LiveLockMetadata;
}

function parseTransaction(value: unknown): TransactionMetadata {
  if (value === null || typeof value !== "object" || Array.isArray(value) || !exactKeys(value, [
    "schemaVersion", "testId", "kind", "runId", "pid", "lease", "createdAt", "mode",
    "operation",
  ], ["targetLease", "targetPid"])) {
    throw new Error("SBX-055 lock-transaction metadata fields were not exact");
  }
  const candidate = value as Record<string, unknown>;
  const targetPresent = Object.prototype.hasOwnProperty.call(candidate, "targetLease");
  const targetPidPresent = Object.prototype.hasOwnProperty.call(candidate, "targetPid");
  if (candidate.schemaVersion !== 1 || candidate.testId !== TEST_ID ||
      candidate.kind !== "live-lock-transaction" ||
      typeof candidate.runId !== "string" || !UUID_V4.test(candidate.runId) ||
      typeof candidate.pid !== "number" || !Number.isSafeInteger(candidate.pid) || candidate.pid < 1 ||
      typeof candidate.lease !== "string" || !LEASE.test(candidate.lease) ||
      !timestamp(candidate.createdAt) ||
      (candidate.mode !== "normal" && candidate.mode !== "cleanup-only") ||
      (candidate.operation !== "acquire" && candidate.operation !== "release") ||
      targetPresent !== (candidate.operation === "release") ||
      targetPidPresent !== (candidate.operation === "release") ||
      (targetPresent && (typeof candidate.targetLease !== "string" || !LEASE.test(candidate.targetLease))) ||
      (targetPidPresent && (typeof candidate.targetPid !== "number" ||
        !Number.isSafeInteger(candidate.targetPid) || candidate.targetPid < 1))) {
    throw new Error("SBX-055 lock-transaction metadata was invalid");
  }
  return candidate as unknown as TransactionMetadata;
}

function parseTransactionFinalizer(value: unknown): TransactionFinalizerMetadata {
  if (value === null || typeof value !== "object" || Array.isArray(value) || !exactKeys(value, [
    "schemaVersion", "testId", "kind", "runId", "pid", "lease", "createdAt",
    "targetTransactionPid", "targetTransactionLease", "targetOperation", "targetMode",
  ], ["targetLockPid", "targetLockLease"])) {
    throw new Error("SBX-055 transaction-finalizer metadata fields were not exact");
  }
  const candidate = value as Record<string, unknown>;
  const targetLockPidPresent = Object.prototype.hasOwnProperty.call(candidate, "targetLockPid");
  const targetLockLeasePresent = Object.prototype.hasOwnProperty.call(candidate, "targetLockLease");
  if (candidate.schemaVersion !== 1 || candidate.testId !== TEST_ID ||
      candidate.kind !== "live-lock-transaction-finalizer" ||
      typeof candidate.runId !== "string" || !UUID_V4.test(candidate.runId) ||
      typeof candidate.pid !== "number" || !Number.isSafeInteger(candidate.pid) || candidate.pid < 1 ||
      typeof candidate.lease !== "string" || !LEASE.test(candidate.lease) ||
      !timestamp(candidate.createdAt) ||
      typeof candidate.targetTransactionPid !== "number" ||
      !Number.isSafeInteger(candidate.targetTransactionPid) || candidate.targetTransactionPid < 1 ||
      typeof candidate.targetTransactionLease !== "string" || !LEASE.test(candidate.targetTransactionLease) ||
      (candidate.targetOperation !== "acquire" && candidate.targetOperation !== "release") ||
      (candidate.targetMode !== "normal" && candidate.targetMode !== "cleanup-only") ||
      targetLockPidPresent !== (candidate.targetOperation === "release") ||
      targetLockLeasePresent !== (candidate.targetOperation === "release") ||
      (targetLockPidPresent && (typeof candidate.targetLockPid !== "number" ||
        !Number.isSafeInteger(candidate.targetLockPid) || candidate.targetLockPid < 1)) ||
      (targetLockLeasePresent && (typeof candidate.targetLockLease !== "string" ||
        !LEASE.test(candidate.targetLockLease)))) {
    throw new Error("SBX-055 transaction-finalizer metadata was invalid");
  }
  return candidate as unknown as TransactionFinalizerMetadata;
}

function sameIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return left.device === right.device && left.inode === right.inode;
}

function sameLiveLock(left: Readonly<LiveLockMetadata>, right: Readonly<LiveLockMetadata>): boolean {
  return left.schemaVersion === right.schemaVersion && left.testId === right.testId &&
    left.kind === right.kind && left.runId === right.runId && left.pid === right.pid &&
    left.lease === right.lease && left.createdAt === right.createdAt && left.mode === right.mode;
}

function sameTransaction(
  left: Readonly<TransactionMetadata>,
  right: Readonly<TransactionMetadata>,
): boolean {
  return left.schemaVersion === right.schemaVersion && left.testId === right.testId &&
    left.kind === right.kind && left.runId === right.runId && left.pid === right.pid &&
    left.lease === right.lease && left.createdAt === right.createdAt && left.mode === right.mode &&
    left.operation === right.operation && left.targetLease === right.targetLease &&
    left.targetPid === right.targetPid;
}

function sameTransactionFinalizer(
  left: Readonly<TransactionFinalizerMetadata>,
  right: Readonly<TransactionFinalizerMetadata>,
): boolean {
  return left.schemaVersion === right.schemaVersion && left.testId === right.testId &&
    left.kind === right.kind && left.runId === right.runId && left.pid === right.pid &&
    left.lease === right.lease && left.createdAt === right.createdAt &&
    left.targetTransactionPid === right.targetTransactionPid &&
    left.targetTransactionLease === right.targetTransactionLease &&
    left.targetOperation === right.targetOperation && left.targetMode === right.targetMode &&
    left.targetLockPid === right.targetLockPid && left.targetLockLease === right.targetLockLease;
}

function currentUserId(): bigint {
  if (typeof process.getuid !== "function") {
    throw new Error("SBX-055 live locking requires a POSIX process user ID");
  }
  return BigInt(process.getuid());
}

function noFollow(): number {
  if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0) {
    throw new Error("SBX-055 live locking requires O_NOFOLLOW support");
  }
  return constants.O_NOFOLLOW;
}

function assertSecureFile(metadata: BigIntStats, description: string): void {
  if (!metadata.isFile()) throw new Error(`${description} must be a regular file`);
  if ((metadata.mode & 0o777n) !== 0o600n) throw new Error(`${description} must have exact mode 0600`);
  if (metadata.uid !== currentUserId()) throw new Error(`${description} must be current-user-owned`);
}

async function assertSecureDirectory(path: string): Promise<void> {
  const parent = dirname(path);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const metadata = await lstat(parent, { bigint: true });
  if (!metadata.isDirectory() || metadata.uid !== currentUserId() ||
      (metadata.mode & 0o777n) !== 0o700n) {
    throw new Error("SBX-055 live-lock directory must be current-user-owned with exact mode 0700");
  }
}

async function readBoundedJson(handle: FileHandle): Promise<unknown> {
  const retained = Buffer.allocUnsafe(MAXIMUM_METADATA_BYTES + 1);
  let total = 0;
  try {
    while (total < retained.length) {
      const read = await handle.read(retained, total, retained.length - total, total);
      if (read.bytesRead === 0) break;
      total += read.bytesRead;
    }
    if (total === 0 || total > MAXIMUM_METADATA_BYTES) {
      throw new Error("SBX-055 live-lock metadata exceeded its fixed byte bound");
    }
    try {
      return JSON.parse(retained.subarray(0, total).toString("utf8"));
    } catch {
      throw new Error("SBX-055 live-lock metadata was not valid JSON");
    }
  } finally {
    retained.fill(0);
  }
}

async function openSecureMetadata<T>(
  path: string,
  description: string,
  parse: (value: unknown) => T,
): Promise<OpenedSecureFile<T>> {
  const before = await lstat(path, { bigint: true });
  assertSecureFile(before, `${description} path`);
  const handle = await open(path, constants.O_RDONLY | noFollow());
  try {
    const held = await handle.stat({ bigint: true });
    assertSecureFile(held, `${description} file`);
    const identity = { device: held.dev, inode: held.ino };
    if (!sameIdentity(identity, { device: before.dev, inode: before.ino })) {
      throw new Error(`${description} path changed while opening`);
    }
    const metadata = parse(await readBoundedJson(handle));
    const after = await lstat(path, { bigint: true });
    assertSecureFile(after, `${description} path`);
    if (!sameIdentity(identity, { device: after.dev, inode: after.ino })) {
      throw new Error(`${description} path changed while inspecting`);
    }
    return { handle, metadata, ...identity };
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw error;
  }
}

async function createSecureMetadata<T>(
  path: string,
  metadata: T,
  description: string,
  parse: (value: unknown) => T,
  equal: (left: Readonly<T>, right: Readonly<T>) => boolean,
): Promise<OpenedSecureFile<T>> {
  const handle = await open(
    path,
    constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | noFollow(),
    0o600,
  );
  let identity: FileIdentity | undefined;
  try {
    const initial = await handle.stat({ bigint: true });
    identity = { device: initial.dev, inode: initial.ino };
    await handle.chmod(0o600);
    const encoded = Buffer.from(`${JSON.stringify(metadata)}\n`, "utf8");
    try {
      if (encoded.length > MAXIMUM_METADATA_BYTES) throw new Error(`${description} was oversized`);
      await handle.write(encoded, 0, encoded.length, 0);
      await handle.truncate(encoded.length);
      await handle.sync();
    } finally {
      encoded.fill(0);
    }
    const held = await handle.stat({ bigint: true });
    assertSecureFile(held, `${description} file`);
    identity = { device: held.dev, inode: held.ino };
    const current = await lstat(path, { bigint: true });
    assertSecureFile(current, `${description} path`);
    if (!sameIdentity(identity, { device: current.dev, inode: current.ino }) ||
        !equal(parse(await readBoundedJson(handle)), metadata)) {
      throw new Error(`${description} lost inode or lease ownership during creation`);
    }
    return { handle, metadata, ...identity };
  } catch (error) {
    await handle.close().catch(() => undefined);
    if (identity !== undefined) {
      try {
        const current = await lstat(path, { bigint: true });
        if (sameIdentity(identity, { device: current.dev, inode: current.ino })) await unlink(path);
      } catch {
        // Preserve any path whose ownership cannot still be proven.
      }
    }
    throw error;
  }
}

async function restoreClaimWithoutReplacement(claimPath: string, path: string): Promise<boolean> {
  try {
    await link(claimPath, path);
  } catch (error) {
    if (errorCode(error) === "EEXIST") return false;
    throw error;
  }
  await unlink(claimPath);
  return true;
}

async function removeExactClaim<T>(
  path: string,
  expected: OpenedSecureFile<T>,
  description: string,
  parse: (value: unknown) => T,
  equal: (left: Readonly<T>, right: Readonly<T>) => boolean,
): Promise<void> {
  const current = await openSecureMetadata(path, description, parse);
  try {
    if (!sameIdentity(current, expected) || !equal(current.metadata, expected.metadata)) {
      throw new Error(`${description} ownership changed; refusing removal`);
    }
  } finally {
    await current.handle.close();
  }
  const final = await lstat(path, { bigint: true });
  assertSecureFile(final, `${description} path`);
  if (!sameIdentity({ device: final.dev, inode: final.ino }, expected)) {
    throw new Error(`${description} inode changed before removal`);
  }
  await unlink(path);
}

async function claimAndRemoveOwned<T>(
  path: string,
  opened: OpenedSecureFile<T & { pid: number; lease: string }>,
  description: string,
  parse: (value: unknown) => T,
  equal: (left: Readonly<T>, right: Readonly<T>) => boolean,
  hook?: MutationHook,
  mutation?: Sbx055LiveLockMutation,
): Promise<void> {
  const held = await opened.handle.stat({ bigint: true });
  assertSecureFile(held, `${description} held file`);
  if (!sameIdentity({ device: held.dev, inode: held.ino }, opened) ||
      !equal(parse(await readBoundedJson(opened.handle)), opened.metadata)) {
    throw new Error(`${description} held inode or lease changed`);
  }
  const claimPath = `${path}.remove-${opened.metadata.pid}-${opened.metadata.lease}`;
  try {
    const existingClaim = await openSecureMetadata(claimPath, `${description} removal claim`, parse);
    try {
      if (!sameIdentity(existingClaim, opened) || !equal(existingClaim.metadata, opened.metadata)) {
        throw new Error(`${description} removal claim did not match its held generation`);
      }
    } finally {
      await existingClaim.handle.close();
    }
    let fixed: OpenedSecureFile<T> | undefined;
    try {
      try {
        fixed = await openSecureMetadata(path, description, parse);
      } catch (error) {
        if (errorCode(error) !== "ENOENT") throw error;
      }
      if (fixed !== undefined) {
        if (!sameIdentity(fixed, opened) || !equal(fixed.metadata, opened.metadata)) {
          throw new Error(`${description} removal claim coexisted with a replacement fixed path`);
        }
        await removeExactClaim(path, opened, description, parse, equal);
      }
    } finally {
      await fixed?.handle.close().catch(() => undefined);
    }
    await removeExactClaim(claimPath, opened, `${description} removal claim`, parse, equal);
    return;
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw error;
  }
  const current = await openSecureMetadata(path, description, parse);
  try {
    if (!sameIdentity(current, opened) || !equal(current.metadata, opened.metadata)) {
      throw new Error(`${description} path was replaced; refusing release`);
    }
  } finally {
    await current.handle.close();
  }
  await rename(path, claimPath);
  if (hook !== undefined && mutation !== undefined) await hook(mutation);
  await removeExactClaim(claimPath, opened, `${description} removal claim`, parse, equal);
}

function lockMetadata(runId: string, mode: LockMode, lease?: string): LiveLockMetadata {
  return {
    schemaVersion: 1,
    testId: TEST_ID,
    kind: "live-lock",
    runId,
    pid: process.pid,
    lease: lease ?? randomBytes(32).toString("base64url"),
    createdAt: new Date().toISOString(),
    mode,
  };
}

function transactionMetadata(
  runId: string,
  mode: LockMode,
  operation: "acquire" | "release",
  targetLease?: string,
  targetPid?: number,
): TransactionMetadata {
  return {
    schemaVersion: 1,
    testId: TEST_ID,
    kind: "live-lock-transaction",
    runId,
    pid: process.pid,
    lease: randomBytes(32).toString("base64url"),
    createdAt: new Date().toISOString(),
    mode,
    operation,
    ...(targetLease === undefined ? {} : { targetLease }),
    ...(targetPid === undefined ? {} : { targetPid }),
  };
}

function transactionPath(path: string): string {
  return `${path}.transaction`;
}

async function createTransaction(
  path: string,
  runId: string,
  mode: LockMode,
  operation: "acquire" | "release",
  targetLease?: string,
  targetPid?: number,
): Promise<OpenedSecureFile<TransactionMetadata>> {
  if (await transactionFinalizationStatePresent(path)) {
    throw new Error("SBX-055 refused a transaction while finalization state exists");
  }
  const created = await createSecureMetadata(
    transactionPath(path),
    transactionMetadata(runId, mode, operation, targetLease, targetPid),
    "SBX-055 lock transaction",
    parseTransaction,
    sameTransaction,
  );
  if (!await transactionFinalizationStatePresent(path)) return created;
  try {
    await removeExactClaim(
      transactionPath(path),
      created,
      "SBX-055 lock transaction",
      parseTransaction,
      sameTransaction,
    );
  } finally {
    await created.handle.close().catch(() => undefined);
  }
  throw new Error("SBX-055 transaction raced existing finalization state");
}

function transactionFinalizerPath(path: string): string {
  return `${transactionPath(path)}.finalizer`;
}

async function transactionFinalizationStatePresent(path: string): Promise<boolean> {
  if ((await removalClaimPaths(transactionPath(path))).length !== 0) return true;
  try {
    await lstat(transactionFinalizerPath(path), { bigint: true });
    return true;
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw error;
  }
  const sidecars = await transactionFinalizerSidecars(path);
  return sidecars.elections.length !== 0 || sidecars.replacements.length !== 0;
}

async function removalClaimPaths(path: string): Promise<string[]> {
  const prefix = `${basename(path)}.remove-`;
  const entries = (await readdir(dirname(path))).filter((entry) => entry.startsWith(prefix));
  for (const entry of entries) {
    if (!/^[1-9][0-9]*-[A-Za-z0-9_-]{43}$/u.test(entry.slice(prefix.length))) {
      throw new Error("SBX-055 removal-claim name was malformed");
    }
  }
  return entries.map((entry) => `${dirname(path)}/${entry}`).sort();
}

function transactionFinalizerMetadata(
  target: Readonly<TransactionTarget>,
): TransactionFinalizerMetadata {
  return {
    schemaVersion: 1,
    testId: TEST_ID,
    kind: "live-lock-transaction-finalizer",
    runId: target.runId,
    pid: process.pid,
    lease: randomBytes(32).toString("base64url"),
    createdAt: new Date().toISOString(),
    targetTransactionPid: target.pid,
    targetTransactionLease: target.lease,
    targetOperation: target.operation,
    targetMode: target.mode,
    ...(target.targetPid === undefined ? {} : { targetLockPid: target.targetPid }),
    ...(target.targetLease === undefined ? {} : { targetLockLease: target.targetLease }),
  };
}

function exactFinalizerTarget(
  finalizer: Readonly<TransactionFinalizerMetadata>,
  target: Readonly<TransactionTarget>,
): boolean {
  return finalizer.runId === target.runId &&
    finalizer.targetTransactionPid === target.pid &&
    finalizer.targetTransactionLease === target.lease &&
    finalizer.targetOperation === target.operation && finalizer.targetMode === target.mode &&
    finalizer.targetLockPid === target.targetPid && finalizer.targetLockLease === target.targetLease;
}

function targetFromFinalizer(
  finalizer: Readonly<TransactionFinalizerMetadata>,
): TransactionTarget {
  return {
    runId: finalizer.runId,
    pid: finalizer.targetTransactionPid,
    lease: finalizer.targetTransactionLease,
    operation: finalizer.targetOperation,
    mode: finalizer.targetMode,
    ...(finalizer.targetLockPid === undefined ? {} : { targetPid: finalizer.targetLockPid }),
    ...(finalizer.targetLockLease === undefined ? {} : { targetLease: finalizer.targetLockLease }),
  };
}

async function optionalTransactionFinalizer(
  path: string,
): Promise<OpenedSecureFile<TransactionFinalizerMetadata> | undefined> {
  try {
    return await openSecureMetadata(
      transactionFinalizerPath(path),
      "SBX-055 transaction finalizer",
      parseTransactionFinalizer,
    );
  } catch (error) {
    if (errorCode(error) === "ENOENT") return undefined;
    throw error;
  }
}

function finalizerReplacementPath(path: string, metadata: TransactionFinalizerMetadata): string {
  return `${transactionFinalizerPath(path)}.next-${metadata.pid}-${metadata.lease}`;
}

function finalizerElectionPath(path: string, targetFinalizerLease: string): string {
  return `${transactionFinalizerPath(path)}.election-${targetFinalizerLease}`;
}

async function transactionFinalizerSidecars(path: string): Promise<{
  elections: string[];
  replacements: string[];
}> {
  const base = basename(transactionFinalizerPath(path));
  const entries = await readdir(dirname(path));
  const elections = entries.filter((entry) => entry.startsWith(`${base}.election-`));
  const replacements = entries.filter((entry) => entry.startsWith(`${base}.next-`));
  for (const entry of elections) {
    if (!LEASE.test(entry.slice(`${base}.election-`.length))) {
      throw new Error("SBX-055 transaction-finalizer election name was malformed");
    }
  }
  for (const entry of replacements) {
    if (!/^[1-9][0-9]*-[A-Za-z0-9_-]{43}$/u.test(entry.slice(`${base}.next-`.length))) {
      throw new Error("SBX-055 transaction-finalizer replacement name was malformed");
    }
  }
  return {
    elections: elections.map((entry) => `${dirname(path)}/${entry}`).sort(),
    replacements: replacements.map((entry) => `${dirname(path)}/${entry}`).sort(),
  };
}

async function settleTransactionFinalizerSidecars(
  path: string,
  target: Readonly<TransactionTarget>,
): Promise<void> {
  const sidecars = await transactionFinalizerSidecars(path);
  if (sidecars.elections.length > 1) {
    throw new Error("SBX-055 transaction-finalizer recovery found multiple elections");
  }
  const fixedPath = transactionFinalizerPath(path);
  if (sidecars.elections.length === 1) {
    const electionPath = sidecars.elections[0]!;
    const targetLease = electionPath.slice(electionPath.lastIndexOf(".election-") + 10);
    const election = await openSecureMetadata(
      electionPath,
      "SBX-055 transaction-finalizer election",
      parseTransactionFinalizer,
    );
    let fixed = await optionalTransactionFinalizer(path);
    try {
      if (!exactFinalizerTarget(election.metadata, target)) {
        throw new Error("SBX-055 transaction-finalizer election targeted another transaction");
      }
      if (fixed !== undefined && sameIdentity(fixed, election) &&
          sameTransactionFinalizer(fixed.metadata, election.metadata)) {
        if (fixed.metadata.lease === targetLease) {
          throw new Error("SBX-055 transaction-finalizer election reused its target generation");
        }
        const installedOwner = ownerState(election.metadata.pid);
        if (installedOwner === "live") {
          throw new Error("SBX-055 installed transaction-finalizer owner is live");
        }
        if (installedOwner !== "dead") {
          throw new Error("SBX-055 installed transaction-finalizer liveness was uncertain");
        }
        await removeExactClaim(
          electionPath,
          election,
          "SBX-055 transaction-finalizer election",
          parseTransactionFinalizer,
          sameTransactionFinalizer,
        );
      } else if (fixed !== undefined && fixed.metadata.lease === targetLease &&
          exactFinalizerTarget(fixed.metadata, target)) {
        const electionOwner = ownerState(election.metadata.pid);
        if (electionOwner === "live") {
          throw new Error("SBX-055 transaction-finalizer takeover owner is live");
        }
        if (electionOwner !== "dead") {
          throw new Error("SBX-055 transaction-finalizer takeover liveness was uncertain");
        }
        await rename(electionPath, fixedPath);
        await fixed.handle.close();
        fixed = undefined;
        const installed = await optionalTransactionFinalizer(path);
        if (installed === undefined || !sameIdentity(installed, election) ||
            !sameTransactionFinalizer(installed.metadata, election.metadata)) {
          await installed?.handle.close().catch(() => undefined);
          throw new Error("SBX-055 transaction-finalizer recovery installed another generation");
        }
        await installed.handle.close();
      } else {
        throw new Error("SBX-055 transaction-finalizer election had unknown fixed-path provenance");
      }
    } finally {
      await fixed?.handle.close().catch(() => undefined);
      await election.handle.close().catch(() => undefined);
    }
  }

  const replacements = (await transactionFinalizerSidecars(path)).replacements;
  const fixed = await optionalTransactionFinalizer(path);
  try {
    for (const replacementPath of replacements) {
      const replacement = await openSecureMetadata(
        replacementPath,
        "SBX-055 transaction-finalizer replacement",
        parseTransactionFinalizer,
      );
      try {
        if (!exactFinalizerTarget(replacement.metadata, target)) {
          throw new Error("SBX-055 transaction-finalizer replacement targeted another transaction");
        }
        if (fixed !== undefined && sameIdentity(fixed, replacement) &&
            sameTransactionFinalizer(fixed.metadata, replacement.metadata)) {
          await removeExactClaim(
            replacementPath,
            replacement,
            "SBX-055 transaction-finalizer replacement",
            parseTransactionFinalizer,
            sameTransactionFinalizer,
          );
          continue;
        }
        const state = ownerState(replacement.metadata.pid);
        if (state === "live") {
          throw new Error("SBX-055 transaction-finalizer replacement owner is live");
        }
        if (state !== "dead") {
          throw new Error("SBX-055 transaction-finalizer replacement liveness was uncertain");
        }
        await removeExactClaim(
          replacementPath,
          replacement,
          "SBX-055 transaction-finalizer replacement",
          parseTransactionFinalizer,
          sameTransactionFinalizer,
        );
      } finally {
        await replacement.handle.close().catch(() => undefined);
      }
    }
  } finally {
    await fixed?.handle.close().catch(() => undefined);
  }
}

async function acquireTransactionFinalizer(
  path: string,
  target: Readonly<TransactionTarget>,
  hook?: MutationHook,
): Promise<OpenedSecureFile<TransactionFinalizerMetadata>> {
  await settleTransactionFinalizerSidecars(path, target);
  const fixedPath = transactionFinalizerPath(path);
  const existing = await optionalTransactionFinalizer(path);
  if (existing === undefined) {
    const created = await createSecureMetadata(
      fixedPath,
      transactionFinalizerMetadata(target),
      "SBX-055 transaction finalizer",
      parseTransactionFinalizer,
      sameTransactionFinalizer,
    );
    await hook?.("finalizer-installed");
    return created;
  }
  let replacement: OpenedSecureFile<TransactionFinalizerMetadata> | undefined;
  let replacementPath: string | undefined;
  let electionPath: string | undefined;
  let electionCreated = false;
  try {
    if (!exactFinalizerTarget(existing.metadata, target)) {
      throw new Error("SBX-055 transaction finalizer targeted another transaction");
    }
    const state = ownerState(existing.metadata.pid);
    if (state === "live") throw new Error("SBX-055 transaction finalizer owner is live");
    if (state !== "dead") throw new Error("SBX-055 transaction finalizer liveness was uncertain");

    const metadata = transactionFinalizerMetadata(target);
    if (metadata.lease === existing.metadata.lease) {
      throw new Error("SBX-055 transaction-finalizer replacement repeated a lease");
    }
    replacementPath = finalizerReplacementPath(path, metadata);
    replacement = await createSecureMetadata(
      replacementPath,
      metadata,
      "SBX-055 transaction-finalizer replacement",
      parseTransactionFinalizer,
      sameTransactionFinalizer,
    );
    await hook?.("finalizer-replacement-created");
    electionPath = finalizerElectionPath(path, existing.metadata.lease);
    await link(replacementPath, electionPath);
    electionCreated = true;
    await hook?.("finalizer-election-created");

    const current = await optionalTransactionFinalizer(path);
    try {
      if (current === undefined || !sameIdentity(current, existing) ||
          !sameTransactionFinalizer(current.metadata, existing.metadata) ||
          ownerState(current.metadata.pid) !== "dead") {
        throw new Error("SBX-055 transaction finalizer changed during elected takeover");
      }
    } finally {
      await current?.handle.close();
    }
    await rename(replacementPath, fixedPath);
    replacementPath = undefined;
    await hook?.("finalizer-installed");
    const installed = await optionalTransactionFinalizer(path);
    try {
      if (installed === undefined || !sameIdentity(installed, replacement) ||
          !sameTransactionFinalizer(installed.metadata, metadata)) {
        throw new Error("SBX-055 transaction-finalizer replacement lost fixed-path ownership");
      }
    } finally {
      await installed?.handle.close();
    }
    await removeExactClaim(
      electionPath,
      replacement,
      "SBX-055 transaction-finalizer election",
      parseTransactionFinalizer,
      sameTransactionFinalizer,
    );
    electionPath = undefined;
    electionCreated = false;
    await hook?.("finalizer-election-removed");
    await existing.handle.close();
    return replacement;
  } catch (error) {
    if (!electionCreated && replacementPath !== undefined && replacement !== undefined) {
      await removeExactClaim(
        replacementPath,
        replacement,
        "SBX-055 transaction-finalizer replacement",
        parseTransactionFinalizer,
        sameTransactionFinalizer,
      ).catch(() => undefined);
    }
    await replacement?.handle.close().catch(() => undefined);
    await existing.handle.close().catch(() => undefined);
    throw error;
  }
}

async function requireOwnedTransactionFinalizer(
  path: string,
  expected: OpenedSecureFile<TransactionFinalizerMetadata>,
): Promise<void> {
  const current = await optionalTransactionFinalizer(path);
  try {
    if (current === undefined || !sameIdentity(current, expected) ||
        !sameTransactionFinalizer(current.metadata, expected.metadata) ||
        current.metadata.pid !== process.pid) {
      throw new Error("SBX-055 transaction-finalizer ownership changed");
    }
  } finally {
    await current?.handle.close();
  }
}

async function releaseTransactionFinalizer(
  path: string,
  finalizer: OpenedSecureFile<TransactionFinalizerMetadata>,
): Promise<void> {
  await requireOwnedTransactionFinalizer(path, finalizer);
  await removeExactClaim(
    transactionFinalizerPath(path),
    finalizer,
    "SBX-055 transaction finalizer",
    parseTransactionFinalizer,
    sameTransactionFinalizer,
  );
  await finalizer.handle.close();
}

function ownerState(pid: number): "live" | "dead" | "uncertain" {
  try {
    process.kill(pid, 0);
    return "live";
  } catch (error) {
    return errorCode(error) === "ESRCH" ? "dead" : "uncertain";
  }
}

async function optionalLiveLock(path: string): Promise<OpenedSecureFile<LiveLockMetadata> | undefined> {
  return optionalLiveLockAt(path, "SBX-055 live lock");
}

async function optionalLiveLockAt(
  path: string,
  description: string,
): Promise<OpenedSecureFile<LiveLockMetadata> | undefined> {
  try {
    return await openSecureMetadata(path, description, parseLiveLock);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return undefined;
    throw error;
  }
}

function exactAcquireTarget(
  lock: Readonly<LiveLockMetadata>,
  transaction: Readonly<TransactionMetadata>,
): boolean {
  return lock.runId === transaction.runId && lock.pid === transaction.pid &&
    lock.lease === transaction.lease && lock.mode === transaction.mode;
}

function exactDeadAcquireSource(
  lock: Readonly<LiveLockMetadata>,
  transaction: Readonly<TransactionMetadata>,
): boolean {
  return transaction.mode === "cleanup-only" && lock.runId === transaction.runId &&
    lock.lease !== transaction.lease && ownerState(lock.pid) === "dead";
}

async function recoverInterruptedAcquireAtPath(
  path: string,
  runId: string,
  hook?: MutationHook,
): Promise<boolean> {
  if (!isAbsolute(path)) throw new Error("SBX-055 live-lock path must be absolute");
  if (!UUID_V4.test(runId)) throw new Error("SBX-055 acquire recovery requires a canonical UUIDv4");
  await assertSecureDirectory(path);
  const settledRemoval = await settleRemovalClaimsAtPath(path, runId);
  const transaction = await optionalTransaction(path);
  if (transaction === undefined && settledRemoval.transactionOperation === "acquire") return true;
  if (transaction === undefined) {
    const dangling = await optionalTransactionFinalizer(path);
    if (dangling === undefined) return false;
    let finalizer: OpenedSecureFile<TransactionFinalizerMetadata> | undefined;
    try {
      if (dangling.metadata.runId !== runId || dangling.metadata.targetOperation !== "acquire") {
        await dangling.handle.close();
        return false;
      }
      if (ownerState(dangling.metadata.pid) !== "dead") {
        throw new Error("SBX-055 dangling acquire-finalizer owner was not proven dead");
      }
      const target = targetFromFinalizer(dangling.metadata);
      await dangling.handle.close();
      finalizer = await acquireTransactionFinalizer(path, target, hook);
      const reappeared = await optionalTransaction(path);
      if (reappeared !== undefined) {
        await reappeared.handle.close();
        throw new Error("SBX-055 acquire transaction reappeared while settling its finalizer");
      }
      await releaseTransactionFinalizer(path, finalizer);
      finalizer = undefined;
      return true;
    } catch (error) {
      await dangling.handle.close().catch(() => undefined);
      await finalizer?.handle.close().catch(() => undefined);
      throw error;
    }
  }
  if (transaction.metadata.operation !== "acquire") {
    await transaction.handle.close();
    return false;
  }

  const replacementPath = `${path}.next-${transaction.metadata.pid}-${transaction.metadata.lease}`;
  const stalePath = `${path}.stale-${transaction.metadata.pid}-${transaction.metadata.lease}`;
  let canonical: OpenedSecureFile<LiveLockMetadata> | undefined;
  let replacement: OpenedSecureFile<LiveLockMetadata> | undefined;
  let stale: OpenedSecureFile<LiveLockMetadata> | undefined;
  let finalizer: OpenedSecureFile<TransactionFinalizerMetadata> | undefined;
  try {
    if (transaction.metadata.runId !== runId) {
      throw new Error("SBX-055 refused a mismatched interrupted acquire transaction");
    }
    if (ownerState(transaction.metadata.pid) !== "dead") {
      throw new Error("SBX-055 refused to recover an acquire whose owner was not proven dead");
    }
    finalizer = await acquireTransactionFinalizer(path, transaction.metadata, hook);
    await requireOwnedTransactionFinalizer(path, finalizer);
    const currentTransaction = await optionalTransaction(path);
    try {
      if (currentTransaction === undefined || !sameIdentity(currentTransaction, transaction) ||
          !sameTransaction(currentTransaction.metadata, transaction.metadata)) {
        throw new Error("SBX-055 interrupted acquire transaction changed after finalizer election");
      }
    } finally {
      await currentTransaction?.handle.close();
    }
    canonical = await optionalLiveLock(path);
    replacement = await optionalLiveLockAt(
      replacementPath,
      "SBX-055 interrupted acquire replacement lock",
    );
    stale = await optionalLiveLockAt(stalePath, "SBX-055 interrupted acquire stale lock");

    if (replacement !== undefined && !exactAcquireTarget(replacement.metadata, transaction.metadata)) {
      throw new Error("SBX-055 interrupted acquire replacement was not its exact target lease");
    }
    if (stale !== undefined && !exactDeadAcquireSource(stale.metadata, transaction.metadata)) {
      throw new Error("SBX-055 interrupted acquire stale lock was not its exact dead source run");
    }
    const canonicalIsTarget = canonical !== undefined &&
      exactAcquireTarget(canonical.metadata, transaction.metadata);
    const canonicalIsSource = canonical !== undefined &&
      exactDeadAcquireSource(canonical.metadata, transaction.metadata);
    if (canonical !== undefined && !canonicalIsTarget && !canonicalIsSource) {
      throw new Error("SBX-055 interrupted acquire canonical lock had unknown provenance");
    }
    if (canonicalIsTarget && canonical !== undefined && replacement !== undefined &&
        (!sameIdentity(canonical, replacement) ||
          !sameLiveLock(canonical.metadata, replacement.metadata))) {
      throw new Error("SBX-055 interrupted acquire target paths did not share one exact inode");
    }

    if (transaction.metadata.mode === "normal") {
      if (stale !== undefined || canonicalIsSource) {
        throw new Error("SBX-055 normal interrupted acquire unexpectedly contained a stale source");
      }
      if (canonicalIsTarget && canonical !== undefined) {
        await removeExactClaim(path, canonical, "SBX-055 live lock", parseLiveLock, sameLiveLock);
        await canonical.handle.close();
        canonical = undefined;
        await hook?.("recover-target-removed");
      }
      if (replacement !== undefined) {
        await removeExactClaim(
          replacementPath,
          replacement,
          "SBX-055 interrupted acquire replacement lock",
          parseLiveLock,
          sameLiveLock,
        );
        await replacement.handle.close();
        replacement = undefined;
        await hook?.("recover-replacement-removed");
      }
    } else if (canonicalIsSource && canonical !== undefined) {
      if (stale !== undefined) {
        if (!sameIdentity(canonical, stale) || !sameLiveLock(canonical.metadata, stale.metadata)) {
          throw new Error("SBX-055 interrupted acquire duplicated a different stale source");
        }
        await removeExactClaim(
          stalePath,
          stale,
          "SBX-055 interrupted acquire stale lock",
          parseLiveLock,
          sameLiveLock,
        );
        await stale.handle.close();
        stale = undefined;
        await hook?.("recover-stale-removed");
      }
      if (replacement !== undefined) {
        await removeExactClaim(
          replacementPath,
          replacement,
          "SBX-055 interrupted acquire replacement lock",
          parseLiveLock,
          sameLiveLock,
        );
        await replacement.handle.close();
        replacement = undefined;
        await hook?.("recover-replacement-removed");
      }
      // The takeover had not claimed its source. Keep the exact dead source in
      // place so the caller can start a fresh ownership-bound takeover.
    } else if (stale !== undefined) {
      if (canonicalIsTarget && canonical !== undefined) {
        await removeExactClaim(path, canonical, "SBX-055 live lock", parseLiveLock, sameLiveLock);
        await canonical.handle.close();
        canonical = undefined;
        await hook?.("recover-target-removed");
      }
      if (replacement !== undefined) {
        await removeExactClaim(
          replacementPath,
          replacement,
          "SBX-055 interrupted acquire replacement lock",
          parseLiveLock,
          sameLiveLock,
        );
        await replacement.handle.close();
        replacement = undefined;
        await hook?.("recover-replacement-removed");
      }
      try {
        await link(stalePath, path);
      } catch (error) {
        if (errorCode(error) === "EEXIST") {
          throw new Error("SBX-055 interrupted acquire could not restore its exact stale source");
        }
        throw error;
      }
      await hook?.("recover-source-linked");
      const restored = await openSecureMetadata(path, "SBX-055 restored stale live lock", parseLiveLock);
      try {
        if (!sameIdentity(restored, stale) || !sameLiveLock(restored.metadata, stale.metadata)) {
          throw new Error("SBX-055 interrupted acquire restored a different stale source");
        }
      } finally {
        await restored.handle.close();
      }
      await removeExactClaim(
        stalePath,
        stale,
        "SBX-055 interrupted acquire stale lock",
        parseLiveLock,
        sameLiveLock,
      );
      await stale.handle.close();
      stale = undefined;
      await hook?.("recover-stale-removed");
    } else if (canonicalIsTarget && canonical !== undefined) {
      if (replacement !== undefined) {
        await removeExactClaim(
          replacementPath,
          replacement,
          "SBX-055 interrupted acquire replacement lock",
          parseLiveLock,
          sameLiveLock,
        );
        await replacement.handle.close();
        replacement = undefined;
        await hook?.("recover-replacement-removed");
      }
      // Its stale source was already removed. Complete the exact takeover by
      // retaining the installed target; the caller will reclaim this dead lease.
    } else {
      throw new Error("SBX-055 cleanup takeover lost both its exact source and target");
    }

    await requireOwnedTransactionFinalizer(path, finalizer);
    await removeExactClaim(
      transactionPath(path),
      transaction,
      "SBX-055 lock transaction",
      parseTransaction,
      sameTransaction,
    );
    await transaction.handle.close();
    await hook?.("recover-transaction-removed");
    await hook?.("finalizer-transaction-removed");
    await releaseTransactionFinalizer(path, finalizer);
    finalizer = undefined;
    await canonical?.handle.close();
    return true;
  } catch (error) {
    await stale?.handle.close().catch(() => undefined);
    await replacement?.handle.close().catch(() => undefined);
    await canonical?.handle.close().catch(() => undefined);
    await finalizer?.handle.close().catch(() => undefined);
    await transaction.handle.close().catch(() => undefined);
    throw error;
  }
}

async function optionalTransaction(
  path: string,
): Promise<OpenedSecureFile<TransactionMetadata> | undefined> {
  try {
    return await openSecureMetadata(
      transactionPath(path),
      "SBX-055 lock transaction",
      parseTransaction,
    );
  } catch (error) {
    if (errorCode(error) === "ENOENT") return undefined;
    throw error;
  }
}

async function settleExactRemovalClaim<T extends { runId: string; pid: number; lease: string }>(
  path: string,
  runId: string,
  description: string,
  parse: (value: unknown) => T,
  equal: (left: Readonly<T>, right: Readonly<T>) => boolean,
): Promise<T | undefined> {
  const claims = await removalClaimPaths(path);
  if (claims.length === 0) return undefined;
  if (claims.length !== 1) throw new Error(`${description} had multiple removal claims`);
  const claimPath = claims[0]!;
  const claim = await openSecureMetadata(claimPath, `${description} removal claim`, parse);
  let current: OpenedSecureFile<T> | undefined;
  try {
    if (claim.metadata.runId !== runId ||
        !claimPath.endsWith(`.remove-${claim.metadata.pid}-${claim.metadata.lease}`)) {
      throw new Error(`${description} removal claim provenance was not exact`);
    }
    const state = ownerState(claim.metadata.pid);
    if (state === "live") throw new Error(`${description} removal-claim owner is live`);
    if (state !== "dead") throw new Error(`${description} removal-claim owner liveness was uncertain`);
    try {
      current = await openSecureMetadata(path, description, parse);
    } catch (error) {
      if (errorCode(error) !== "ENOENT") throw error;
    }
    if (current !== undefined) {
      if (!sameIdentity(current, claim) || !equal(current.metadata, claim.metadata)) {
        throw new Error(`${description} removal claim coexisted with a replacement fixed path`);
      }
      await removeExactClaim(path, claim, description, parse, equal);
      await current.handle.close();
      current = undefined;
    }
    await removeExactClaim(
      claimPath,
      claim,
      `${description} removal claim`,
      parse,
      equal,
    );
    return claim.metadata;
  } finally {
    await current?.handle.close().catch(() => undefined);
    await claim.handle.close().catch(() => undefined);
  }
}

async function settleRemovalClaimsAtPath(
  path: string,
  runId: string,
): Promise<Sbx055RemovalSettlement> {
  if (!isAbsolute(path)) throw new Error("SBX-055 removal-claim recovery path must be absolute");
  if (!UUID_V4.test(runId)) throw new Error("SBX-055 removal-claim recovery requires a canonical UUIDv4");
  await assertSecureDirectory(path);
  const canonical = await settleExactRemovalClaim(
    path,
    runId,
    "SBX-055 live lock",
    parseLiveLock,
    sameLiveLock,
  );
  const transaction = await settleExactRemovalClaim(
    transactionPath(path),
    runId,
    "SBX-055 lock transaction",
    parseTransaction,
    sameTransaction,
  );
  return {
    canonicalRemoved: canonical !== undefined,
    ...(transaction === undefined ? {} : { transactionOperation: transaction.operation }),
  };
}

async function inspectPendingTransactionAtPath(
  path: string,
  runId: string,
): Promise<Sbx055PendingTransaction | undefined> {
  if (!isAbsolute(path)) throw new Error("SBX-055 live-lock path must be absolute");
  if (!UUID_V4.test(runId)) throw new Error("SBX-055 transaction inspection requires a canonical UUIDv4");
  await assertSecureDirectory(path);
  const transaction = await optionalTransaction(path);
  if (transaction === undefined) {
    const finalizer = await optionalTransactionFinalizer(path);
    if (finalizer === undefined) return undefined;
    try {
      if (finalizer.metadata.runId !== runId) {
        throw new Error("SBX-055 refused a mismatched pending transaction finalizer");
      }
      return {
        operation: finalizer.metadata.targetOperation,
        mode: finalizer.metadata.targetMode,
      };
    } finally {
      await finalizer.handle.close();
    }
  }
  try {
    if (transaction.metadata.runId !== runId) {
      throw new Error("SBX-055 refused a mismatched pending transaction");
    }
    return { operation: transaction.metadata.operation, mode: transaction.metadata.mode };
  } finally {
    await transaction.handle.close();
  }
}

async function rollbackOrphanedNormalLockAtPath(
  path: string,
  runId: string,
  hook?: MutationHook,
): Promise<boolean> {
  if (!isAbsolute(path)) throw new Error("SBX-055 live-lock path must be absolute");
  if (!UUID_V4.test(runId)) throw new Error("SBX-055 orphan rollback requires a canonical UUIDv4");
  await assertSecureDirectory(path);
  await settleRemovalClaimsAtPath(path, runId);
  const pendingTransaction = await optionalTransaction(path);
  if (pendingTransaction !== undefined) {
    await pendingTransaction.handle.close();
    throw new Error("SBX-055 orphan rollback refused a pending transaction");
  }
  const canonical = await optionalLiveLock(path);
  if (canonical === undefined) return false;
  let transaction: OpenedSecureFile<TransactionMetadata> | undefined;
  try {
    if (canonical.metadata.runId !== runId || canonical.metadata.mode !== "normal") {
      throw new Error("SBX-055 orphan rollback refused a foreign or non-normal lock");
    }
    const state = ownerState(canonical.metadata.pid);
    if (state === "live") throw new Error("SBX-055 orphan rollback refused a live lock owner");
    if (state !== "dead") throw new Error("SBX-055 orphan lock owner liveness was uncertain");
    const prefix = `${basename(path)}.`;
    const sidecars = (await readdir(dirname(path))).filter((entry) =>
      entry.startsWith(`${prefix}next-`) || entry.startsWith(`${prefix}stale-`));
    if (sidecars.length !== 0) {
      throw new Error("SBX-055 orphan rollback refused acquisition sidecars");
    }
    transaction = await createTransaction(
      path,
      runId,
      "normal",
      "release",
      canonical.metadata.lease,
      canonical.metadata.pid,
    );
    await hook?.("orphan-release-transaction-created");
    const current = await optionalLiveLock(path);
    try {
      if (current === undefined || !sameIdentity(current, canonical) ||
          !sameLiveLock(current.metadata, canonical.metadata) || ownerState(current.metadata.pid) !== "dead") {
        throw new Error("SBX-055 orphan lock changed after release serialization");
      }
    } finally {
      await current?.handle.close();
    }
    await removeExactClaim(path, canonical, "SBX-055 live lock", parseLiveLock, sameLiveLock);
    await hook?.("orphan-canonical-removed");
    await requireCanonicalAbsent(path);
    await removeExactClaim(
      transactionPath(path),
      transaction,
      "SBX-055 lock transaction",
      parseTransaction,
      sameTransaction,
    );
    await transaction.handle.close();
    transaction = undefined;
    return true;
  } finally {
    await transaction?.handle.close().catch(() => undefined);
    await canonical.handle.close().catch(() => undefined);
  }
}

async function resumeInterruptedReleaseAtPath(
  path: string,
  runId: string,
  hook?: MutationHook,
): Promise<boolean> {
  if (!isAbsolute(path)) throw new Error("SBX-055 live-lock path must be absolute");
  if (!UUID_V4.test(runId)) throw new Error("SBX-055 release recovery requires a canonical UUIDv4");
  await assertSecureDirectory(path);
  const settledRemoval = await settleRemovalClaimsAtPath(path, runId);
  const transaction = await optionalTransaction(path);
  if (transaction === undefined && settledRemoval.transactionOperation === "release") {
    const canonical = await optionalLiveLock(path);
    if (canonical !== undefined) {
      await canonical.handle.close();
      throw new Error("SBX-055 finalized release claim retained a canonical lock");
    }
    return true;
  }
  if (transaction === undefined) {
    const dangling = await optionalTransactionFinalizer(path);
    if (dangling === undefined) return false;
    let finalizer: OpenedSecureFile<TransactionFinalizerMetadata> | undefined;
    try {
      if (dangling.metadata.runId !== runId || dangling.metadata.targetOperation !== "release") {
        throw new Error("SBX-055 dangling transaction finalizer did not identify this release");
      }
      if (ownerState(dangling.metadata.pid) !== "dead") {
        throw new Error("SBX-055 dangling transaction-finalizer owner was not proven dead");
      }
      const target = targetFromFinalizer(dangling.metadata);
      await dangling.handle.close();
      finalizer = await acquireTransactionFinalizer(path, target, hook);
      const reappeared = await optionalTransaction(path);
      if (reappeared !== undefined) {
        await reappeared.handle.close();
        throw new Error("SBX-055 transaction reappeared while settling its finalizer");
      }
      const canonical = await optionalLiveLock(path);
      if (canonical !== undefined) {
        try {
          if (canonical.metadata.runId !== runId || canonical.metadata.pid !== target.targetPid ||
              canonical.metadata.lease !== target.targetLease || canonical.metadata.mode !== target.mode) {
            throw new Error("SBX-055 dangling release finalizer did not match its canonical lock");
          }
          await removeExactClaim(path, canonical, "SBX-055 live lock", parseLiveLock, sameLiveLock);
        } finally {
          await canonical.handle.close().catch(() => undefined);
        }
      }
      await releaseTransactionFinalizer(path, finalizer);
      finalizer = undefined;
      return true;
    } catch (error) {
      await dangling.handle.close().catch(() => undefined);
      await finalizer?.handle.close().catch(() => undefined);
      throw error;
    }
  }
  let canonical: OpenedSecureFile<LiveLockMetadata> | undefined;
  let finalizer: OpenedSecureFile<TransactionFinalizerMetadata> | undefined;
  try {
    if (transaction.metadata.operation !== "release" || transaction.metadata.runId !== runId ||
        transaction.metadata.targetLease === undefined || transaction.metadata.targetPid === undefined) {
      throw new Error("SBX-055 refused a mismatched or non-release transaction");
    }
    if (ownerState(transaction.metadata.pid) !== "dead") {
      throw new Error("SBX-055 refused to resume a release whose owner was not proven dead");
    }
    finalizer = await acquireTransactionFinalizer(path, transaction.metadata, hook);
    await requireOwnedTransactionFinalizer(path, finalizer);
    const currentTransaction = await optionalTransaction(path);
    try {
      if (currentTransaction === undefined || !sameIdentity(currentTransaction, transaction) ||
          !sameTransaction(currentTransaction.metadata, transaction.metadata)) {
        throw new Error("SBX-055 release transaction changed after finalizer election");
      }
    } finally {
      await currentTransaction?.handle.close();
    }
    canonical = await optionalLiveLock(path);
    if (canonical !== undefined &&
        (canonical.metadata.runId !== runId ||
          canonical.metadata.pid !== transaction.metadata.targetPid ||
          canonical.metadata.lease !== transaction.metadata.targetLease ||
          canonical.metadata.mode !== transaction.metadata.mode)) {
      throw new Error("SBX-055 interrupted release canonical lock did not match its transaction");
    }
    if (canonical !== undefined) {
      await removeExactClaim(path, canonical, "SBX-055 live lock", parseLiveLock, sameLiveLock);
      await canonical.handle.close();
      canonical = undefined;
    }
    await requireOwnedTransactionFinalizer(path, finalizer);
    await removeExactClaim(
      transactionPath(path),
      transaction,
      "SBX-055 lock transaction",
      parseTransaction,
      sameTransaction,
    );
    await transaction.handle.close();
    await hook?.("finalizer-transaction-removed");
    await releaseTransactionFinalizer(path, finalizer);
    finalizer = undefined;
    return true;
  } catch (error) {
    await canonical?.handle.close().catch(() => undefined);
    await finalizer?.handle.close().catch(() => undefined);
    await transaction.handle.close().catch(() => undefined);
    throw error;
  }
}

async function rollbackInterruptedReleaseAtPath(
  path: string,
  runId: string,
  hook?: MutationHook,
): Promise<boolean> {
  if (!isAbsolute(path)) throw new Error("SBX-055 live-lock path must be absolute");
  if (!UUID_V4.test(runId)) throw new Error("SBX-055 release rollback requires a canonical UUIDv4");
  await assertSecureDirectory(path);
  const settledRemoval = await settleRemovalClaimsAtPath(path, runId);
  const transaction = await optionalTransaction(path);
  if (transaction === undefined) {
    if (settledRemoval.transactionOperation === "release") return true;
    const dangling = await optionalTransactionFinalizer(path);
    if (dangling === undefined) return false;
    let finalizer: OpenedSecureFile<TransactionFinalizerMetadata> | undefined;
    try {
      if (dangling.metadata.runId !== runId || dangling.metadata.targetOperation !== "release" ||
          ownerState(dangling.metadata.pid) !== "dead") {
        throw new Error("SBX-055 dangling rollback finalizer was not an exact dead release");
      }
      const target = targetFromFinalizer(dangling.metadata);
      const canonical = await optionalLiveLock(path);
      try {
        if (canonical === undefined || canonical.metadata.runId !== runId ||
            canonical.metadata.pid !== target.targetPid || canonical.metadata.lease !== target.targetLease ||
            canonical.metadata.mode !== target.mode) {
          throw new Error("SBX-055 dangling rollback finalizer lacked its exact canonical lock");
        }
      } finally {
        await canonical?.handle.close();
      }
      await dangling.handle.close();
      finalizer = await acquireTransactionFinalizer(path, target, hook);
      const reappeared = await optionalTransaction(path);
      if (reappeared !== undefined) {
        await reappeared.handle.close();
        throw new Error("SBX-055 release transaction reappeared during rollback finalizer settlement");
      }
      await releaseTransactionFinalizer(path, finalizer);
      finalizer = undefined;
      return true;
    } catch (error) {
      await dangling.handle.close().catch(() => undefined);
      await finalizer?.handle.close().catch(() => undefined);
      throw error;
    }
  }
  let canonical: OpenedSecureFile<LiveLockMetadata> | undefined;
  let finalizer: OpenedSecureFile<TransactionFinalizerMetadata> | undefined;
  try {
    if (transaction.metadata.operation !== "release" || transaction.metadata.runId !== runId ||
        transaction.metadata.targetLease === undefined || transaction.metadata.targetPid === undefined) {
      throw new Error("SBX-055 refused a mismatched or non-release transaction");
    }
    if (ownerState(transaction.metadata.pid) !== "dead") {
      throw new Error("SBX-055 refused to roll back a release whose owner was not proven dead");
    }
    finalizer = await acquireTransactionFinalizer(path, transaction.metadata, hook);
    await requireOwnedTransactionFinalizer(path, finalizer);
    canonical = await optionalLiveLock(path);
    if (canonical === undefined || canonical.metadata.runId !== runId ||
        canonical.metadata.pid !== transaction.metadata.targetPid ||
        canonical.metadata.lease !== transaction.metadata.targetLease ||
        canonical.metadata.mode !== transaction.metadata.mode) {
      throw new Error("SBX-055 interrupted release lacked its exact canonical lock");
    }
    const currentTransaction = await optionalTransaction(path);
    try {
      if (currentTransaction === undefined || !sameIdentity(currentTransaction, transaction) ||
          !sameTransaction(currentTransaction.metadata, transaction.metadata)) {
        throw new Error("SBX-055 release transaction changed after rollback election");
      }
    } finally {
      await currentTransaction?.handle.close();
    }
    await removeExactClaim(
      transactionPath(path),
      transaction,
      "SBX-055 lock transaction",
      parseTransaction,
      sameTransaction,
    );
    await transaction.handle.close();
    await hook?.("finalizer-transaction-removed");
    await canonical.handle.close();
    await releaseTransactionFinalizer(path, finalizer);
    finalizer = undefined;
    return true;
  } catch (error) {
    await canonical?.handle.close().catch(() => undefined);
    await finalizer?.handle.close().catch(() => undefined);
    await transaction.handle.close().catch(() => undefined);
    throw error;
  }
}

async function requireCanonicalAbsent(path: string): Promise<void> {
  try {
    await lstat(path, { bigint: true });
  } catch (error) {
    if (errorCode(error) === "ENOENT") return;
    throw error;
  }
  throw new Error("SBX-055 fixed live-lock path survived or was replaced during release");
}

class HeldLiveLock implements Sbx055HeldLock {
  private released = false;
  private closedRetainingState = false;
  private canonicalRemoved = false;
  private preCommitCompleted = false;
  private pendingTransaction: OpenedSecureFile<TransactionMetadata> | undefined;

  constructor(
    readonly runId: string,
    readonly path: string,
    private readonly opened: OpenedSecureFile<LiveLockMetadata>,
    private readonly hook?: MutationHook,
  ) {}

  isReleased(): boolean {
    return this.released;
  }

  async closeRetainingState(): Promise<void> {
    if (this.released || this.closedRetainingState) return;
    const handles = [this.opened.handle,
      ...(this.pendingTransaction === undefined ? [] : [this.pendingTransaction.handle])];
    const results = await Promise.allSettled(handles.map(async (handle) => handle.close()));
    const failures = results.filter((result): result is PromiseRejectedResult => result.status === "rejected");
    if (failures.length > 0) {
      throw new AggregateError(failures.map((failure) => failure.reason),
        "SBX-055 failed to close retained lock descriptors");
    }
    this.closedRetainingState = true;
  }

  async release(): Promise<void> {
    return this.releaseAfter(async () => undefined);
  }

  async releaseAfter(preCommit: () => Promise<void>): Promise<void> {
    if (this.released) return;
    if (this.closedRetainingState) {
      throw new Error("SBX-055 cannot release a lock whose descriptors were closed while retaining state");
    }
    let transaction = this.pendingTransaction;
    try {
      if (transaction === undefined) {
        transaction = await createTransaction(
          this.path,
          this.runId,
          this.opened.metadata.mode,
          "release",
          this.opened.metadata.lease,
          this.opened.metadata.pid,
        );
        this.pendingTransaction = transaction;
        await this.hook?.("release-transaction-created");
      }
      if (!this.preCommitCompleted) {
        await preCommit();
        this.preCommitCompleted = true;
        await this.hook?.("release-precommit-complete");
      }
      if (!this.canonicalRemoved) {
        await claimAndRemoveOwned(
          this.path,
          this.opened,
          "SBX-055 live lock",
          parseLiveLock,
          sameLiveLock,
          this.hook,
          "release-canonical-claimed",
        );
        this.canonicalRemoved = true;
        await this.hook?.("release-canonical-removed");
      }
      await requireCanonicalAbsent(this.path);
      await claimAndRemoveOwned(
        transactionPath(this.path),
        transaction,
        "SBX-055 lock transaction",
        parseTransaction,
        sameTransaction,
        this.hook,
        "release-transaction-claimed",
      );
      this.pendingTransaction = undefined;
      await transaction.handle.close().catch(() => undefined);
      this.released = true;
      await this.opened.handle.close().catch(() => undefined);
    } catch (error) {
      if (transaction !== undefined && !this.canonicalRemoved && !this.preCommitCompleted) {
        try {
          await claimAndRemoveOwned(
            transactionPath(this.path),
            transaction,
            "SBX-055 lock transaction",
            parseTransaction,
            sameTransaction,
            this.hook,
            "release-transaction-claimed",
          );
          this.pendingTransaction = undefined;
          await transaction.handle.close().catch(() => undefined);
        } catch {
          // Retain both owned descriptors so the exact transaction removal can be retried.
        }
      }
      throw error;
    }
  }
}

async function acquireAtPath(
  path: string,
  runId: string,
  recovery: boolean,
  hook?: MutationHook,
): Promise<Sbx055HeldLock> {
  if (!isAbsolute(path)) throw new Error("SBX-055 live-lock path must be absolute");
  if (!UUID_V4.test(runId)) throw new Error("SBX-055 live lock requires a canonical UUIDv4");
  await assertSecureDirectory(path);
  await recoverInterruptedAcquireAtPath(path, runId);
  const mode: LockMode = recovery ? "cleanup-only" : "normal";
  const transaction = await createTransaction(path, runId, mode, "acquire");
  let existing: OpenedSecureFile<LiveLockMetadata> | undefined;
  let replacement: OpenedSecureFile<LiveLockMetadata> | undefined;
  let replacementPath: string | undefined;
  let staleClaimPath: string | undefined;
  let canonicalInstalled = false;
  try {
    await hook?.("acquire-transaction-created");
    existing = await optionalLiveLock(path);
    if (!recovery && existing !== undefined) {
      throw new Error("SBX-055 refused a normal run because the live lock already exists");
    }
    if (recovery) {
      if (existing === undefined || existing.metadata.runId !== runId) {
        throw new Error("SBX-055 cleanup-only mode refused a missing or mismatched live lock");
      }
      const state = ownerState(existing.metadata.pid);
      if (state === "live") throw new Error("SBX-055 cleanup-only mode refused a live lock owner");
      if (state !== "dead") throw new Error("SBX-055 live-lock owner liveness was uncertain");
    }

    const metadata = lockMetadata(runId, mode, transaction.metadata.lease);
    replacementPath = `${path}.next-${process.pid}-${metadata.lease}`;
    replacement = await createSecureMetadata(
      replacementPath,
      metadata,
      "SBX-055 replacement live lock",
      parseLiveLock,
      sameLiveLock,
    );
    await hook?.("acquire-replacement-created");

    if (existing !== undefined) {
      staleClaimPath = `${path}.stale-${process.pid}-${metadata.lease}`;
      await rename(path, staleClaimPath);
      const claimed = await openSecureMetadata(staleClaimPath, "SBX-055 stale live lock", parseLiveLock);
      try {
        if (!sameIdentity(claimed, existing) || !sameLiveLock(claimed.metadata, existing.metadata)) {
          throw new Error("SBX-055 stale live lock changed during atomic claim");
        }
      } finally {
        await claimed.handle.close();
      }
      await hook?.("acquire-stale-claimed");
    }

    await link(replacementPath, path);
    canonicalInstalled = true;
    const canonical = await openSecureMetadata(path, "SBX-055 live lock", parseLiveLock);
    try {
      if (!sameIdentity(canonical, replacement) || !sameLiveLock(canonical.metadata, metadata)) {
        throw new Error("SBX-055 replacement live lock lost inode or lease ownership");
      }
    } finally {
      await canonical.handle.close();
    }
    await hook?.("acquire-canonical-installed");
    await removeExactClaim(
      replacementPath,
      replacement,
      "SBX-055 replacement live lock",
      parseLiveLock,
      sameLiveLock,
    );
    replacementPath = undefined;
    await hook?.("acquire-replacement-removed");
    if (staleClaimPath !== undefined && existing !== undefined) {
      await removeExactClaim(
        staleClaimPath,
        existing,
        "SBX-055 stale live lock",
        parseLiveLock,
        sameLiveLock,
      );
      staleClaimPath = undefined;
      await hook?.("acquire-stale-removed");
    }
    await existing?.handle.close();
    existing = undefined;
    await claimAndRemoveOwned(
      transactionPath(path),
      transaction,
      "SBX-055 lock transaction",
      parseTransaction,
      sameTransaction,
      hook,
      "acquire-transaction-claimed",
    );
    await transaction.handle.close();
    return new HeldLiveLock(runId, path, replacement, hook);
  } catch (error) {
    if (!canonicalInstalled) {
      if (staleClaimPath !== undefined) {
        await restoreClaimWithoutReplacement(staleClaimPath, path).catch(() => false);
      }
      if (replacementPath !== undefined && replacement !== undefined) {
        await removeExactClaim(
          replacementPath,
          replacement,
          "SBX-055 replacement live lock",
          parseLiveLock,
          sameLiveLock,
        ).catch(() => undefined);
      }
      await claimAndRemoveOwned(
        transactionPath(path),
        transaction,
        "SBX-055 lock transaction",
        parseTransaction,
        sameTransaction,
        hook,
        "acquire-transaction-claimed",
      ).catch(() => undefined);
    }
    await existing?.handle.close().catch(() => undefined);
    await replacement?.handle.close().catch(() => undefined);
    await transaction.handle.close().catch(() => undefined);
    throw error;
  }
}

export async function acquireSbx055LiveLock(
  path: string,
  runId: string,
  recovery: boolean,
): Promise<Sbx055HeldLock> {
  return acquireAtPath(path, runId, recovery);
}

/** Test seam for cross-process verification against a fresh mode-0700 directory. */
export async function acquireSbx055LiveLockAtPathForTest(
  path: string,
  runId: string,
  recovery: boolean,
  hook?: MutationHook,
): Promise<Sbx055HeldLock> {
  return acquireAtPath(path, runId, recovery, hook);
}

/** Completes only one exact stale release transaction; never reclaims an ordinary lock. */
export async function resumeSbx055InterruptedRelease(
  path: string,
  runId: string,
): Promise<boolean> {
  return resumeInterruptedReleaseAtPath(path, runId);
}

/** Test seam for finalizer-election and release-recovery crash phases. */
export async function resumeSbx055InterruptedReleaseAtPathForTest(
  path: string,
  runId: string,
  hook?: MutationHook,
): Promise<boolean> {
  return resumeInterruptedReleaseAtPath(path, runId, hook);
}

/** Rolls back only one exact stale precommit release transaction, preserving its lock. */
export async function rollbackSbx055InterruptedRelease(
  path: string,
  runId: string,
): Promise<boolean> {
  return rollbackInterruptedReleaseAtPath(path, runId);
}

/** Test seam for precommit rollback response-loss and finalizer crash phases. */
export async function rollbackSbx055InterruptedReleaseAtPathForTest(
  path: string,
  runId: string,
  hook?: MutationHook,
): Promise<boolean> {
  return rollbackInterruptedReleaseAtPath(path, runId, hook);
}

/** Recovers every exact dead acquisition phase by rollback or safe completion. */
export async function recoverSbx055InterruptedAcquire(
  path: string,
  runId: string,
): Promise<boolean> {
  return recoverInterruptedAcquireAtPath(path, runId);
}

/** Test seam for real process-death faults during acquire recovery itself. */
export async function recoverSbx055InterruptedAcquireAtPathForTest(
  path: string,
  runId: string,
  hook?: MutationHook,
): Promise<boolean> {
  return recoverInterruptedAcquireAtPath(path, runId, hook);
}

/** Sanitized exact operation/mode inspection for the local recovery dispatcher. */
export async function inspectSbx055PendingTransaction(
  path: string,
  runId: string,
): Promise<Sbx055PendingTransaction | undefined> {
  return inspectPendingTransactionAtPath(path, runId);
}

/** Settles only exact dead-owner, generation-bound canonical/transaction removal claims. */
export async function settleSbx055RemovalClaims(
  path: string,
  runId: string,
): Promise<Sbx055RemovalSettlement> {
  return settleRemovalClaimsAtPath(path, runId);
}

/** Removes only one exact dead normal lock left before journal creation. */
export async function rollbackSbx055OrphanedNormalLock(
  path: string,
  runId: string,
): Promise<boolean> {
  return rollbackOrphanedNormalLockAtPath(path, runId);
}

/** Test seam for crash and concurrency verification of pre-journal orphan rollback. */
export async function rollbackSbx055OrphanedNormalLockAtPathForTest(
  path: string,
  runId: string,
  hook?: MutationHook,
): Promise<boolean> {
  return rollbackOrphanedNormalLockAtPath(path, runId, hook);
}
