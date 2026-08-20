export type ForkAuthorizationVerdict =
  | "pass"
  | "candidate"
  | "indeterminate"
  | "error";

export interface ForkAuthorizationAssessmentInput {
  setupError: boolean;
  cleanupPassed: boolean;
  requestAuditPassed: boolean;
  identitiesVerifiedAndDistinct: boolean;
  attackerOwnerForkControlPassed: boolean;
  victimOwnerForkControlPassed: boolean;
  distinctSourceAndSessionIds: boolean;
  victimOnlyCanaryAttribution: boolean;
  victimSourceValidImmediatelyBefore: boolean;
  victimSourceValidImmediatelyAfter: boolean;
  crossForkRequestAttempts: number;
  crossForkAccepted: boolean;
  crossForkRejected: boolean;
  crossForkRejectionConclusive: boolean;
  crossForkResponseAttributable: boolean;
  crossKnownPathReadAttempts: number;
  exactSyntheticVictimCanaryMatched: boolean;
  stopAtConfirmationPreserved: boolean;
}

export interface ForkAuthorizationAssessment {
  verdict: ForkAuthorizationVerdict;
  candidate: boolean;
  controlsPassed: boolean;
  summary: string;
}

export function assessForkAuthorization(
  input: ForkAuthorizationAssessmentInput,
): ForkAuthorizationAssessment {
  if (
    input.crossForkRequestAttempts > 1 ||
    input.crossKnownPathReadAttempts > 1 ||
    (input.crossKnownPathReadAttempts > 0 && !input.crossForkAccepted) ||
    (input.crossForkAccepted && input.crossForkRejected) ||
    !input.stopAtConfirmationPreserved
  ) {
    return {
      verdict: "error",
      candidate: false,
      controlsPassed: false,
      summary: "A bounded-test invariant was violated; do not interpret the authorization outcome.",
    };
  }

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
      summary: "The controller failed before a valid fork-authorization assessment completed.",
    };
  }

  const controlsPassed = input.requestAuditPassed &&
    input.identitiesVerifiedAndDistinct &&
    input.attackerOwnerForkControlPassed &&
    input.victimOwnerForkControlPassed &&
    input.distinctSourceAndSessionIds &&
    input.victimOnlyCanaryAttribution &&
    input.victimSourceValidImmediatelyBefore &&
    input.victimSourceValidImmediatelyAfter &&
    input.crossForkRequestAttempts === 1;

  if (!controlsPassed) {
    return {
      verdict: "indeterminate",
      candidate: false,
      controlsPassed: false,
      summary: "An identity, distinct-fixture, owner-fork, source-validity, or request-audit control failed.",
    };
  }

  if (
    input.crossForkAccepted &&
    input.crossForkResponseAttributable &&
    input.crossKnownPathReadAttempts === 1 &&
    input.exactSyntheticVictimCanaryMatched
  ) {
    return {
      verdict: "candidate",
      candidate: true,
      controlsPassed: true,
      summary: "Attacker credentials forked the owned victim source and read the exact synthetic victim canary.",
    };
  }

  if (
    input.crossForkRejected &&
    input.crossForkRejectionConclusive &&
    !input.crossForkAccepted &&
    input.crossKnownPathReadAttempts === 0
  ) {
    return {
      verdict: "pass",
      candidate: false,
      controlsPassed: true,
      summary: "The control plane conclusively rejected the single cross-account fork request.",
    };
  }

  return {
    verdict: "indeterminate",
    candidate: false,
    controlsPassed: true,
    summary: "The cross-account result proved neither a conclusive denial nor exact synthetic victim-data access.",
  };
}
