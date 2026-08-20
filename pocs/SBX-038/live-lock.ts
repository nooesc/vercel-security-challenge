/**
 * SBX-038 delegates its local single-run exclusion and restart protocol to the
 * frozen SBX-055 ownership-bound implementation.  Keeping this wrapper small
 * means the CONNECT packet does not fork the reviewed inode/lease, transaction,
 * finalizer, and deterministic removal-claim state machine.
 */
import {
  acquireSbx055LiveLock,
  acquireSbx055LiveLockAtPathForTest,
  inspectSbx055PendingTransaction,
  recoverSbx055InterruptedAcquire,
  recoverSbx055InterruptedAcquireAtPathForTest,
  resumeSbx055InterruptedRelease,
  resumeSbx055InterruptedReleaseAtPathForTest,
  rollbackSbx055InterruptedRelease,
  rollbackSbx055InterruptedReleaseAtPathForTest,
  rollbackSbx055OrphanedNormalLock,
  rollbackSbx055OrphanedNormalLockAtPathForTest,
  settleSbx055RemovalClaims,
  type Sbx055HeldLock,
  type Sbx055LiveLockMutation,
  type Sbx055PendingTransaction,
  type Sbx055RemovalSettlement,
} from "../SBX-055/live-lock.js";

export const SBX038_LIVE_LOCK_IMPLEMENTATION_ID =
  "SBX-055-STALE-INTERACTIVE-RESUME@201279cfc861d513c1b73d2b2e44468bece0ea2633c7b67f5b8e7c57148c5750" as const;

export type Sbx038HeldLiveLock = Sbx055HeldLock;
export type Sbx038LiveLockMutation = Sbx055LiveLockMutation;
export type Sbx038PendingTransaction = Sbx055PendingTransaction;
export type Sbx038RemovalSettlement = Sbx055RemovalSettlement;

type MutationHook = (mutation: Sbx038LiveLockMutation) => void | Promise<void>;

export function acquireSbx038LiveLock(
  path: string,
  runId: string,
  recovery: boolean,
): Promise<Sbx038HeldLiveLock> {
  return acquireSbx055LiveLock(path, runId, recovery);
}

/** Test seam: callers must supply a fresh, current-user-owned mode-0700 directory. */
export function acquireSbx038LiveLockAtPathForTest(
  path: string,
  runId: string,
  recovery: boolean,
  hook?: MutationHook,
): Promise<Sbx038HeldLiveLock> {
  return acquireSbx055LiveLockAtPathForTest(path, runId, recovery, hook);
}

export function inspectSbx038PendingTransaction(
  path: string,
  runId: string,
): Promise<Sbx038PendingTransaction | undefined> {
  return inspectSbx055PendingTransaction(path, runId);
}

export function settleSbx038RemovalClaims(
  path: string,
  runId: string,
): Promise<Sbx038RemovalSettlement> {
  return settleSbx055RemovalClaims(path, runId);
}

export function recoverSbx038InterruptedAcquire(path: string, runId: string): Promise<boolean> {
  return recoverSbx055InterruptedAcquire(path, runId);
}

export function recoverSbx038InterruptedAcquireAtPathForTest(
  path: string,
  runId: string,
  hook?: MutationHook,
): Promise<boolean> {
  return recoverSbx055InterruptedAcquireAtPathForTest(path, runId, hook);
}

export function resumeSbx038InterruptedRelease(path: string, runId: string): Promise<boolean> {
  return resumeSbx055InterruptedRelease(path, runId);
}

export function resumeSbx038InterruptedReleaseAtPathForTest(
  path: string,
  runId: string,
  hook?: MutationHook,
): Promise<boolean> {
  return resumeSbx055InterruptedReleaseAtPathForTest(path, runId, hook);
}

export function rollbackSbx038InterruptedRelease(path: string, runId: string): Promise<boolean> {
  return rollbackSbx055InterruptedRelease(path, runId);
}

export function rollbackSbx038InterruptedReleaseAtPathForTest(
  path: string,
  runId: string,
  hook?: MutationHook,
): Promise<boolean> {
  return rollbackSbx055InterruptedReleaseAtPathForTest(path, runId, hook);
}

export function rollbackSbx038OrphanedNormalLock(path: string, runId: string): Promise<boolean> {
  return rollbackSbx055OrphanedNormalLock(path, runId);
}

export function rollbackSbx038OrphanedNormalLockAtPathForTest(
  path: string,
  runId: string,
  hook?: MutationHook,
): Promise<boolean> {
  return rollbackSbx055OrphanedNormalLockAtPathForTest(path, runId, hook);
}
