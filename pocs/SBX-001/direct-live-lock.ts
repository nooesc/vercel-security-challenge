/**
 * SBX-001 uses the frozen, generation-bound SBX-055 live-lock transaction
 * implementation instead of maintaining a second copy of its finalizer,
 * deterministic removal-claim, and crash-recovery protocol.
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

export const SBX001_DIRECT_LIVE_LOCK_IMPLEMENTATION_ID =
  "SBX-055-STALE-INTERACTIVE-RESUME@201279cfc861d513c1b73d2b2e44468bece0ea2633c7b67f5b8e7c57148c5750" as const;

export type Sbx001DirectHeldLock = Sbx055HeldLock;
export type Sbx001DirectLiveLockMutation = Sbx055LiveLockMutation;
export type Sbx001DirectPendingTransaction = Sbx055PendingTransaction;
export type Sbx001DirectRemovalSettlement = Sbx055RemovalSettlement;

type MutationHook = (mutation: Sbx001DirectLiveLockMutation) => void | Promise<void>;

export function acquireSbx001DirectLiveLock(
  path: string,
  runId: string,
  recovery: boolean,
): Promise<Sbx001DirectHeldLock> {
  return acquireSbx055LiveLock(path, runId, recovery);
}

/** Test seam for cross-process crash injection in an isolated mode-0700 directory. */
export function acquireSbx001DirectLiveLockAtPathForTest(
  path: string,
  runId: string,
  recovery: boolean,
  hook?: MutationHook,
): Promise<Sbx001DirectHeldLock> {
  return acquireSbx055LiveLockAtPathForTest(path, runId, recovery, hook);
}

export function resumeSbx001DirectInterruptedRelease(path: string, runId: string): Promise<boolean> {
  return resumeSbx055InterruptedRelease(path, runId);
}

export function resumeSbx001DirectInterruptedReleaseAtPathForTest(
  path: string,
  runId: string,
  hook?: MutationHook,
): Promise<boolean> {
  return resumeSbx055InterruptedReleaseAtPathForTest(path, runId, hook);
}

export function rollbackSbx001DirectInterruptedRelease(path: string, runId: string): Promise<boolean> {
  return rollbackSbx055InterruptedRelease(path, runId);
}

export function rollbackSbx001DirectInterruptedReleaseAtPathForTest(
  path: string,
  runId: string,
  hook?: MutationHook,
): Promise<boolean> {
  return rollbackSbx055InterruptedReleaseAtPathForTest(path, runId, hook);
}

/**
 * Settles a dead acquire transaction and removes a journal-less normal lock.
 * This retains the historical SBX-001 rollback contract while delegating both
 * serialized operations to the frozen implementation.
 */
export async function rollbackSbx001DirectInterruptedAcquire(path: string, runId: string): Promise<boolean> {
  const transactionRecovered = await recoverSbx055InterruptedAcquire(path, runId);
  const orphanRecovered = await rollbackSbx055OrphanedNormalLock(path, runId);
  return transactionRecovered || orphanRecovered;
}

export function recoverSbx001DirectInterruptedAcquireAtPathForTest(
  path: string,
  runId: string,
  hook?: MutationHook,
): Promise<boolean> {
  return recoverSbx055InterruptedAcquireAtPathForTest(path, runId, hook);
}

export function inspectSbx001DirectPendingTransaction(
  path: string,
  runId: string,
): Promise<Sbx001DirectPendingTransaction | undefined> {
  return inspectSbx055PendingTransaction(path, runId);
}

export function settleSbx001DirectRemovalClaims(
  path: string,
  runId: string,
): Promise<Sbx001DirectRemovalSettlement> {
  return settleSbx055RemovalClaims(path, runId);
}

export function rollbackSbx001DirectOrphanedNormalLock(
  path: string,
  runId: string,
): Promise<boolean> {
  return rollbackSbx055OrphanedNormalLock(path, runId);
}

export function rollbackSbx001DirectOrphanedNormalLockAtPathForTest(
  path: string,
  runId: string,
  hook?: MutationHook,
): Promise<boolean> {
  return rollbackSbx055OrphanedNormalLockAtPathForTest(path, runId, hook);
}
