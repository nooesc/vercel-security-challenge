export type SessionCommandLane = "session-read" | "command-run";

export type SessionCommandVerdict = "pass" | "candidate" | "indeterminate" | "error";

export interface SessionCommandAssessmentInput {
  lane: SessionCommandLane;
  setupError?: string;
  cleanupPassed: boolean;
  exactIdentitiesVerified: boolean;
  identitiesDistinct: boolean;
  attackerOwnerControlPassed: boolean;
  victimOwnerControlPassed: boolean;
  sameAccountControlRequestCount: number;
  sameAccountControlImmediatelyPrecededCross: boolean;
  operationConstraintsPassed: boolean;
  foreignRequestAttempted: boolean;
  foreignRequestCount: number;
  crossKnownPathReadCount: number;
  deferredCrossOperationCount: number;
  foreignRejected: boolean;
  foreignRejectionConclusive: boolean;
  foreignSucceeded: boolean;
  exactMarkerConfirmed: boolean;
  qpsAuditPassed: boolean;
  rawMarkerOrBodyRetained: boolean;
}

export interface SessionCommandAssessment {
  verdict: SessionCommandVerdict;
  summary: string;
  outcomeSignalsMutuallyExclusive: boolean;
  outcomeSignalsConsistent: boolean;
  safetyInvariantsPassed: boolean;
}

function wholeNonNegative(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

export function assessSessionCommandAuthorization(
  input: SessionCommandAssessmentInput,
): SessionCommandAssessment {
  const countsValid = [
    input.sameAccountControlRequestCount,
    input.foreignRequestCount,
    input.crossKnownPathReadCount,
    input.deferredCrossOperationCount,
  ].every(wholeNonNegative);
  const expectedReadCount = input.foreignRequestAttempted && input.lane === "session-read" ? 1 : 0;
  const countConsistency =
    input.foreignRequestCount === (input.foreignRequestAttempted ? 1 : 0) &&
    input.crossKnownPathReadCount === expectedReadCount;
  const outcomeSignalsMutuallyExclusive = input.foreignRejected !== input.foreignSucceeded;
  const outcomeSignalsConsistent =
    outcomeSignalsMutuallyExclusive &&
    (!input.foreignRejectionConclusive || input.foreignRejected) &&
    (!input.foreignSucceeded || input.exactMarkerConfirmed) &&
    (!input.foreignRejected || !input.exactMarkerConfirmed);
  const safetyInvariantsPassed =
    countsValid &&
    input.sameAccountControlRequestCount <= 2 &&
    input.foreignRequestCount <= 1 &&
    input.crossKnownPathReadCount <= 1 &&
    !(input.lane === "command-run" && input.crossKnownPathReadCount > 0) &&
    input.deferredCrossOperationCount === 0 &&
    !input.rawMarkerOrBodyRetained &&
    input.qpsAuditPassed &&
    input.operationConstraintsPassed;

  if (input.setupError !== undefined) {
    return {
      verdict: "error",
      summary: "setup failed before a reportable authorization result was established",
      outcomeSignalsMutuallyExclusive,
      outcomeSignalsConsistent,
      safetyInvariantsPassed,
    };
  }
  if (!input.cleanupPassed) {
    return {
      verdict: "error",
      summary: "owner-token cleanup or independent absence confirmation failed",
      outcomeSignalsMutuallyExclusive,
      outcomeSignalsConsistent,
      safetyInvariantsPassed,
    };
  }
  if (
    !countsValid || input.sameAccountControlRequestCount > 2 ||
    input.foreignRequestCount > 1 || input.crossKnownPathReadCount > 1 ||
    (input.lane === "command-run" && input.crossKnownPathReadCount > 0)
  ) {
    return {
      verdict: "error",
      summary: "a fixed request-count safety limit was violated",
      outcomeSignalsMutuallyExclusive,
      outcomeSignalsConsistent,
      safetyInvariantsPassed,
    };
  }
  if (
    input.deferredCrossOperationCount !== 0 || input.rawMarkerOrBodyRetained ||
    !input.qpsAuditPassed || !input.operationConstraintsPassed
  ) {
    return {
      verdict: "error",
      summary: "a lane safety or evidence-retention invariant failed",
      outcomeSignalsMutuallyExclusive,
      outcomeSignalsConsistent,
      safetyInvariantsPassed,
    };
  }
  if (
    !input.exactIdentitiesVerified || !input.identitiesDistinct ||
    !input.attackerOwnerControlPassed || !input.victimOwnerControlPassed ||
    input.sameAccountControlRequestCount !== 2 ||
    !input.sameAccountControlImmediatelyPrecededCross
  ) {
    return {
      verdict: "indeterminate",
      summary: "identity or immediately preceding same-account control was not proven",
      outcomeSignalsMutuallyExclusive,
      outcomeSignalsConsistent,
      safetyInvariantsPassed,
    };
  }
  if (!input.foreignRequestAttempted || !countConsistency) {
    return {
      verdict: "indeterminate",
      summary: "the lane did not produce exactly one auditable cross-account request",
      outcomeSignalsMutuallyExclusive,
      outcomeSignalsConsistent,
      safetyInvariantsPassed,
    };
  }
  if (!outcomeSignalsConsistent) {
    return {
      verdict: "indeterminate",
      summary: "success, rejection, and exact-marker signals were inconsistent",
      outcomeSignalsMutuallyExclusive,
      outcomeSignalsConsistent,
      safetyInvariantsPassed,
    };
  }
  if (input.foreignRejected) {
    return input.foreignRejectionConclusive
      ? {
          verdict: "pass",
          summary: "the single foreign request received a conclusive authorization rejection",
          outcomeSignalsMutuallyExclusive,
          outcomeSignalsConsistent,
          safetyInvariantsPassed,
        }
      : {
          verdict: "indeterminate",
          summary: "the foreign request failed without a conclusive authorization rejection",
          outcomeSignalsMutuallyExclusive,
          outcomeSignalsConsistent,
          safetyInvariantsPassed,
        };
  }
  if (!input.exactMarkerConfirmed) {
    return {
      verdict: "indeterminate",
      summary: "the foreign response did not exactly confirm the synthetic marker",
      outcomeSignalsMutuallyExclusive,
      outcomeSignalsConsistent,
      safetyInvariantsPassed,
    };
  }
  return {
    verdict: "candidate",
    summary: "the single foreign request exactly confirmed the synthetic marker",
    outcomeSignalsMutuallyExclusive,
    outcomeSignalsConsistent,
    safetyInvariantsPassed,
  };
}
