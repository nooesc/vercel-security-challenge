import { randomBytes } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import { link, lstat, mkdir, open, rename, unlink, type FileHandle } from "node:fs/promises";
import { dirname, isAbsolute } from "node:path";

const TEST_ID = "SBX-052-FS-NAMESPACE" as const;
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
}

interface FileIdentity {
  device: bigint;
  inode: bigint;
}

interface OpenedSecureFile<T> extends FileIdentity {
  handle: FileHandle;
  metadata: T;
}

export interface Sbx052HeldLock {
  readonly runId: string;
  readonly path: string;
  isReleased(): boolean;
  closeRetainingState(): Promise<void>;
  releaseAfter(preCommit: () => Promise<void>): Promise<void>;
  release(): Promise<void>;
}

export type Sbx052LiveLockMutation = "release-transaction-created" |
  "release-precommit-complete" | "release-canonical-removed";
type MutationHook = (mutation: Sbx052LiveLockMutation) => void | Promise<void>;

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
    throw new Error("SBX-052 live-lock metadata fields were not exact");
  }
  const candidate = value as Record<string, unknown>;
  if (candidate.schemaVersion !== 1 || candidate.testId !== TEST_ID || candidate.kind !== "live-lock" ||
      typeof candidate.runId !== "string" || !UUID_V4.test(candidate.runId) ||
      typeof candidate.pid !== "number" || !Number.isSafeInteger(candidate.pid) || candidate.pid < 1 ||
      typeof candidate.lease !== "string" || !LEASE.test(candidate.lease) ||
      !timestamp(candidate.createdAt) ||
      (candidate.mode !== "normal" && candidate.mode !== "cleanup-only")) {
    throw new Error("SBX-052 live-lock metadata was invalid");
  }
  return candidate as unknown as LiveLockMetadata;
}

function parseTransaction(value: unknown): TransactionMetadata {
  if (value === null || typeof value !== "object" || Array.isArray(value) || !exactKeys(value, [
    "schemaVersion", "testId", "kind", "runId", "pid", "lease", "createdAt", "mode",
    "operation",
  ], ["targetLease"])) {
    throw new Error("SBX-052 lock-transaction metadata fields were not exact");
  }
  const candidate = value as Record<string, unknown>;
  const targetPresent = Object.prototype.hasOwnProperty.call(candidate, "targetLease");
  if (candidate.schemaVersion !== 1 || candidate.testId !== TEST_ID ||
      candidate.kind !== "live-lock-transaction" ||
      typeof candidate.runId !== "string" || !UUID_V4.test(candidate.runId) ||
      typeof candidate.pid !== "number" || !Number.isSafeInteger(candidate.pid) || candidate.pid < 1 ||
      typeof candidate.lease !== "string" || !LEASE.test(candidate.lease) ||
      !timestamp(candidate.createdAt) ||
      (candidate.mode !== "normal" && candidate.mode !== "cleanup-only") ||
      (candidate.operation !== "acquire" && candidate.operation !== "release") ||
      targetPresent !== (candidate.operation === "release") ||
      (targetPresent && (typeof candidate.targetLease !== "string" || !LEASE.test(candidate.targetLease)))) {
    throw new Error("SBX-052 lock-transaction metadata was invalid");
  }
  return candidate as unknown as TransactionMetadata;
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
    left.operation === right.operation && left.targetLease === right.targetLease;
}

function currentUserId(): bigint {
  if (typeof process.getuid !== "function") {
    throw new Error("SBX-052 live locking requires a POSIX process user ID");
  }
  return BigInt(process.getuid());
}

function noFollow(): number {
  if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0) {
    throw new Error("SBX-052 live locking requires O_NOFOLLOW support");
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
    throw new Error("SBX-052 live-lock directory must be current-user-owned with exact mode 0700");
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
      throw new Error("SBX-052 live-lock metadata exceeded its fixed byte bound");
    }
    try {
      return JSON.parse(retained.subarray(0, total).toString("utf8"));
    } catch {
      throw new Error("SBX-052 live-lock metadata was not valid JSON");
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
  opened: OpenedSecureFile<T>,
  description: string,
  parse: (value: unknown) => T,
  equal: (left: Readonly<T>, right: Readonly<T>) => boolean,
): Promise<void> {
  const held = await opened.handle.stat({ bigint: true });
  assertSecureFile(held, `${description} held file`);
  if (!sameIdentity({ device: held.dev, inode: held.ino }, opened) ||
      !equal(parse(await readBoundedJson(opened.handle)), opened.metadata)) {
    throw new Error(`${description} held inode or lease changed`);
  }
  const current = await openSecureMetadata(path, description, parse);
  try {
    if (!sameIdentity(current, opened) || !equal(current.metadata, opened.metadata)) {
      throw new Error(`${description} path was replaced; refusing release`);
    }
  } finally {
    await current.handle.close();
  }

  const claimPath = `${path}.remove-${process.pid}-${randomBytes(32).toString("hex")}`;
  let claimed = false;
  try {
    await rename(path, claimPath);
    claimed = true;
    await removeExactClaim(claimPath, opened, description, parse, equal);
    claimed = false;
  } catch (error) {
    if (claimed) await restoreClaimWithoutReplacement(claimPath, path).catch(() => false);
    throw error;
  }
}

function lockMetadata(runId: string, mode: LockMode): LiveLockMetadata {
  return {
    schemaVersion: 1,
    testId: TEST_ID,
    kind: "live-lock",
    runId,
    pid: process.pid,
    lease: randomBytes(32).toString("base64url"),
    createdAt: new Date().toISOString(),
    mode,
  };
}

function transactionMetadata(
  runId: string,
  mode: LockMode,
  operation: "acquire" | "release",
  targetLease?: string,
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
): Promise<OpenedSecureFile<TransactionMetadata>> {
  return createSecureMetadata(
    transactionPath(path),
    transactionMetadata(runId, mode, operation, targetLease),
    "SBX-052 lock transaction",
    parseTransaction,
    sameTransaction,
  );
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
  try {
    return await openSecureMetadata(path, "SBX-052 live lock", parseLiveLock);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return undefined;
    throw error;
  }
}

async function optionalTransaction(
  path: string,
): Promise<OpenedSecureFile<TransactionMetadata> | undefined> {
  try {
    return await openSecureMetadata(
      transactionPath(path),
      "SBX-052 lock transaction",
      parseTransaction,
    );
  } catch (error) {
    if (errorCode(error) === "ENOENT") return undefined;
    throw error;
  }
}

async function resumeInterruptedReleaseAtPath(path: string, runId: string): Promise<boolean> {
  if (!isAbsolute(path)) throw new Error("SBX-052 live-lock path must be absolute");
  if (!UUID_V4.test(runId)) throw new Error("SBX-052 release recovery requires a canonical UUIDv4");
  await assertSecureDirectory(path);
  const transaction = await optionalTransaction(path);
  if (transaction === undefined) return false;
  let canonical: OpenedSecureFile<LiveLockMetadata> | undefined;
  try {
    if (transaction.metadata.operation !== "release" || transaction.metadata.runId !== runId ||
        transaction.metadata.targetLease === undefined) {
      throw new Error("SBX-052 refused a mismatched or non-release transaction");
    }
    if (ownerState(transaction.metadata.pid) !== "dead") {
      throw new Error("SBX-052 refused to resume a release whose owner was not proven dead");
    }
    canonical = await optionalLiveLock(path);
    if (canonical !== undefined &&
        (canonical.metadata.runId !== runId ||
          canonical.metadata.pid !== transaction.metadata.pid ||
          canonical.metadata.lease !== transaction.metadata.targetLease ||
          canonical.metadata.mode !== transaction.metadata.mode)) {
      throw new Error("SBX-052 interrupted release canonical lock did not match its transaction");
    }
    if (canonical !== undefined) {
      await removeExactClaim(path, canonical, "SBX-052 live lock", parseLiveLock, sameLiveLock);
      await canonical.handle.close();
      canonical = undefined;
    }
    await removeExactClaim(
      transactionPath(path),
      transaction,
      "SBX-052 lock transaction",
      parseTransaction,
      sameTransaction,
    );
    await transaction.handle.close();
    return true;
  } catch (error) {
    await canonical?.handle.close().catch(() => undefined);
    await transaction.handle.close().catch(() => undefined);
    throw error;
  }
}

async function rollbackInterruptedReleaseAtPath(path: string, runId: string): Promise<boolean> {
  if (!isAbsolute(path)) throw new Error("SBX-052 live-lock path must be absolute");
  if (!UUID_V4.test(runId)) throw new Error("SBX-052 release rollback requires a canonical UUIDv4");
  await assertSecureDirectory(path);
  const transaction = await optionalTransaction(path);
  if (transaction === undefined) return false;
  let canonical: OpenedSecureFile<LiveLockMetadata> | undefined;
  try {
    if (transaction.metadata.operation !== "release" || transaction.metadata.runId !== runId ||
        transaction.metadata.targetLease === undefined) {
      throw new Error("SBX-052 refused a mismatched or non-release transaction");
    }
    if (ownerState(transaction.metadata.pid) !== "dead") {
      throw new Error("SBX-052 refused to roll back a release whose owner was not proven dead");
    }
    canonical = await optionalLiveLock(path);
    if (canonical === undefined || canonical.metadata.runId !== runId ||
        canonical.metadata.pid !== transaction.metadata.pid ||
        canonical.metadata.lease !== transaction.metadata.targetLease ||
        canonical.metadata.mode !== transaction.metadata.mode) {
      throw new Error("SBX-052 interrupted release lacked its exact canonical lock");
    }
    await removeExactClaim(
      transactionPath(path),
      transaction,
      "SBX-052 lock transaction",
      parseTransaction,
      sameTransaction,
    );
    await transaction.handle.close();
    await canonical.handle.close();
    return true;
  } catch (error) {
    await canonical?.handle.close().catch(() => undefined);
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
  throw new Error("SBX-052 fixed live-lock path survived or was replaced during release");
}

class HeldLiveLock implements Sbx052HeldLock {
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
        "SBX-052 failed to close retained lock descriptors");
    }
    this.closedRetainingState = true;
  }

  async release(): Promise<void> {
    return this.releaseAfter(async () => undefined);
  }

  async releaseAfter(preCommit: () => Promise<void>): Promise<void> {
    if (this.released) return;
    if (this.closedRetainingState) {
      throw new Error("SBX-052 cannot release a lock whose descriptors were closed while retaining state");
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
          "SBX-052 live lock",
          parseLiveLock,
          sameLiveLock,
        );
        this.canonicalRemoved = true;
        await this.hook?.("release-canonical-removed");
      }
      await requireCanonicalAbsent(this.path);
      await claimAndRemoveOwned(
        transactionPath(this.path),
        transaction,
        "SBX-052 lock transaction",
        parseTransaction,
        sameTransaction,
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
            "SBX-052 lock transaction",
            parseTransaction,
            sameTransaction,
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
): Promise<Sbx052HeldLock> {
  if (!isAbsolute(path)) throw new Error("SBX-052 live-lock path must be absolute");
  if (!UUID_V4.test(runId)) throw new Error("SBX-052 live lock requires a canonical UUIDv4");
  await assertSecureDirectory(path);
  const mode: LockMode = recovery ? "cleanup-only" : "normal";
  const transaction = await createTransaction(path, runId, mode, "acquire");
  let existing: OpenedSecureFile<LiveLockMetadata> | undefined;
  let replacement: OpenedSecureFile<LiveLockMetadata> | undefined;
  let replacementPath: string | undefined;
  let staleClaimPath: string | undefined;
  let canonicalInstalled = false;
  try {
    existing = await optionalLiveLock(path);
    if (!recovery && existing !== undefined) {
      throw new Error("SBX-052 refused a normal run because the live lock already exists");
    }
    if (recovery) {
      if (existing === undefined || existing.metadata.runId !== runId) {
        throw new Error("SBX-052 cleanup-only mode refused a missing or mismatched live lock");
      }
      const state = ownerState(existing.metadata.pid);
      if (state === "live") throw new Error("SBX-052 cleanup-only mode refused a live lock owner");
      if (state !== "dead") throw new Error("SBX-052 live-lock owner liveness was uncertain");
    }

    const metadata = lockMetadata(runId, mode);
    replacementPath = `${path}.next-${process.pid}-${metadata.lease}`;
    replacement = await createSecureMetadata(
      replacementPath,
      metadata,
      "SBX-052 replacement live lock",
      parseLiveLock,
      sameLiveLock,
    );

    if (existing !== undefined) {
      staleClaimPath = `${path}.stale-${process.pid}-${metadata.lease}`;
      await rename(path, staleClaimPath);
      const claimed = await openSecureMetadata(staleClaimPath, "SBX-052 stale live lock", parseLiveLock);
      try {
        if (!sameIdentity(claimed, existing) || !sameLiveLock(claimed.metadata, existing.metadata)) {
          throw new Error("SBX-052 stale live lock changed during atomic claim");
        }
      } finally {
        await claimed.handle.close();
      }
    }

    await link(replacementPath, path);
    canonicalInstalled = true;
    const canonical = await openSecureMetadata(path, "SBX-052 live lock", parseLiveLock);
    try {
      if (!sameIdentity(canonical, replacement) || !sameLiveLock(canonical.metadata, metadata)) {
        throw new Error("SBX-052 replacement live lock lost inode or lease ownership");
      }
    } finally {
      await canonical.handle.close();
    }
    await removeExactClaim(
      replacementPath,
      replacement,
      "SBX-052 replacement live lock",
      parseLiveLock,
      sameLiveLock,
    );
    replacementPath = undefined;
    if (staleClaimPath !== undefined && existing !== undefined) {
      await removeExactClaim(
        staleClaimPath,
        existing,
        "SBX-052 stale live lock",
        parseLiveLock,
        sameLiveLock,
      );
      staleClaimPath = undefined;
    }
    await existing?.handle.close();
    existing = undefined;
    await claimAndRemoveOwned(
      transactionPath(path),
      transaction,
      "SBX-052 lock transaction",
      parseTransaction,
      sameTransaction,
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
          "SBX-052 replacement live lock",
          parseLiveLock,
          sameLiveLock,
        ).catch(() => undefined);
      }
      await claimAndRemoveOwned(
        transactionPath(path),
        transaction,
        "SBX-052 lock transaction",
        parseTransaction,
        sameTransaction,
      ).catch(() => undefined);
    }
    await existing?.handle.close().catch(() => undefined);
    await replacement?.handle.close().catch(() => undefined);
    await transaction.handle.close().catch(() => undefined);
    throw error;
  }
}

export async function acquireSbx052LiveLock(
  path: string,
  runId: string,
  recovery: boolean,
): Promise<Sbx052HeldLock> {
  return acquireAtPath(path, runId, recovery);
}

/** Test seam for cross-process verification against a fresh mode-0700 directory. */
export async function acquireSbx052LiveLockAtPathForTest(
  path: string,
  runId: string,
  recovery: boolean,
  hook?: MutationHook,
): Promise<Sbx052HeldLock> {
  return acquireAtPath(path, runId, recovery, hook);
}

/** Completes only one exact stale release transaction; never reclaims an ordinary lock. */
export async function resumeSbx052InterruptedRelease(
  path: string,
  runId: string,
): Promise<boolean> {
  return resumeInterruptedReleaseAtPath(path, runId);
}

/** Rolls back only one exact stale precommit release transaction, preserving its lock. */
export async function rollbackSbx052InterruptedRelease(
  path: string,
  runId: string,
): Promise<boolean> {
  return rollbackInterruptedReleaseAtPath(path, runId);
}
