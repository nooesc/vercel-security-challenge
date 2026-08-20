export type SnapshotAuthorizationVerdict =
  | "pass"
  | "candidate"
  | "indeterminate"
  | "error";

export interface SnapshotAuthorizationAssessmentInput {
  setupError: boolean;
  cleanupPassed: boolean;
  identitiesVerifiedDistinct: boolean;
  ownerSessionsVerifiedDistinct: boolean;
  attackerSameAccountRestoreControlPassed: boolean;
  victimSameAccountRestoreControlPassed: boolean;
  victimSnapshotValidBeforeAttack: boolean;
  victimSnapshotValidAfterAttack: boolean;
  crossRestoreCallAttempts: number;
  crossRestoreRequestAttempts: number;
  crossKnownPathReadCallAttempts: number;
  crossKnownPathReadAttempts: number;
  attackCreateRejected: boolean;
  attackRejectionConclusive: boolean;
  crossDestinationObserved: boolean;
  attackerCloneCreated: boolean;
  attackerCloneReadbackPassed: boolean;
  attackerCloneSourceSnapshotMatched: boolean;
  attackerReadAttempted: boolean;
  exactSyntheticCanaryMatched: boolean;
}

export interface SnapshotAuthorizationAssessment {
  verdict: SnapshotAuthorizationVerdict;
  candidate: boolean;
  controlsPassed: boolean;
  summary: string;
}

export function assessSnapshotAuthorization(
  input: SnapshotAuthorizationAssessmentInput,
): SnapshotAuthorizationAssessment {
  if (!input.cleanupPassed) {
    return {
      verdict: "error",
      candidate: false,
      controlsPassed: false,
      summary: "Owned-resource cleanup or independent absence verification failed.",
    };
  }

  if (input.setupError) {
    return {
      verdict: "error",
      candidate: false,
      controlsPassed: false,
      summary: "The controller failed before a valid authorization assessment completed.",
    };
  }

  const requestCountersSafe = [
    input.crossRestoreCallAttempts,
    input.crossRestoreRequestAttempts,
    input.crossKnownPathReadCallAttempts,
    input.crossKnownPathReadAttempts,
  ].every((value) => Number.isSafeInteger(value) && value >= 0 && value <= 1) &&
    input.crossRestoreCallAttempts === input.crossRestoreRequestAttempts &&
    input.crossKnownPathReadCallAttempts === input.crossKnownPathReadAttempts;
  if (!requestCountersSafe) {
    return {
      verdict: "error",
      candidate: false,
      controlsPassed: false,
      summary: "The one-shot cross-account request limit was exceeded or could not be proven.",
    };
  }

  const stateCoherent =
    (!input.attackRejectionConclusive || input.attackCreateRejected) &&
    !(input.attackCreateRejected && input.attackerCloneCreated) &&
    (!input.attackerCloneCreated || input.crossDestinationObserved) &&
    (!input.attackerCloneReadbackPassed || input.attackerCloneCreated) &&
    (!input.attackerCloneSourceSnapshotMatched || input.attackerCloneReadbackPassed) &&
    (input.attackerReadAttempted === (input.crossKnownPathReadCallAttempts === 1)) &&
    (!input.attackerReadAttempted || input.attackerCloneSourceSnapshotMatched) &&
    (!input.exactSyntheticCanaryMatched || input.attackerReadAttempted);
  if (!stateCoherent) {
    return {
      verdict: "error",
      candidate: false,
      controlsPassed: false,
      summary: "The restore, source attribution, readback, and read state violated harness invariants.",
    };
  }

  const controlsPassed = input.identitiesVerifiedDistinct &&
    input.ownerSessionsVerifiedDistinct &&
    input.attackerSameAccountRestoreControlPassed &&
    input.victimSameAccountRestoreControlPassed &&
    input.victimSnapshotValidBeforeAttack &&
    input.victimSnapshotValidAfterAttack;

  if (!controlsPassed) {
    return {
      verdict: "indeterminate",
      candidate: false,
      controlsPassed: false,
      summary: "Two-account identity/session, same-account restore, or pre/post victim snapshot controls failed.",
    };
  }

  const oneRestoreRequest = input.crossRestoreCallAttempts === 1 &&
    input.crossRestoreRequestAttempts === 1;
  const candidateOutcome = oneRestoreRequest &&
    input.crossKnownPathReadCallAttempts === 1 &&
    input.crossKnownPathReadAttempts === 1 &&
    !input.attackCreateRejected &&
    !input.attackRejectionConclusive &&
    input.crossDestinationObserved &&
    input.attackerCloneCreated &&
    input.attackerCloneReadbackPassed &&
    input.attackerCloneSourceSnapshotMatched &&
    input.attackerReadAttempted &&
    input.exactSyntheticCanaryMatched;

  if (candidateOutcome) {
    return {
      verdict: "candidate",
      candidate: true,
      controlsPassed: true,
      summary: "Attacker credentials restored a victim-owned snapshot and read the exact synthetic victim file once.",
    };
  }

  const cleanRejection = oneRestoreRequest &&
    input.crossKnownPathReadCallAttempts === 0 &&
    input.crossKnownPathReadAttempts === 0 &&
    input.attackCreateRejected &&
    input.attackRejectionConclusive &&
    !input.crossDestinationObserved &&
    !input.attackerCloneCreated &&
    !input.attackerCloneReadbackPassed &&
    !input.attackerCloneSourceSnapshotMatched &&
    !input.attackerReadAttempted &&
    !input.exactSyntheticCanaryMatched;

  if (cleanRejection) {
    return {
      verdict: "pass",
      candidate: false,
      controlsPassed: true,
      summary: "The control plane rejected the single cross-account snapshot restore while the victim snapshot remained valid.",
    };
  }

  return {
    verdict: "indeterminate",
    candidate: false,
    controlsPassed: true,
    summary: "The cross-account outcome was contradictory, retried, or did not prove exact disclosure or a clean authorization denial.",
  };
}
