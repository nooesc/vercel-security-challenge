export type LifecycleVerdict = "pass" | "candidate" | "indeterminate";

export interface LifecycleAssessmentInput {
  preChangeTransformControlPassed: boolean;
  tightenAcknowledged: boolean;
  tightenReadbackDenyAll: boolean;
  postChangeBlocked: boolean;
  sourceStopSnapshotCaptured: boolean;
  resumedWithNewSession: boolean;
  resumedFromCapturedSnapshot: boolean;
  resumedReadbackDenyAll: boolean;
  postLifecycleRemovedSecretAction: boolean;
  postLifecycleBlocked: boolean;
  postLifecycleUnexpectedReachability: boolean;
  reachabilityControlPassed: boolean;
}

export interface LifecycleAssessment {
  verdict: LifecycleVerdict;
  summary: string;
  signals: string[];
}

export function assessLifecyclePolicyRestore(
  input: LifecycleAssessmentInput,
): LifecycleAssessment {
  const requiredBeforeLifecycle: Array<[string, boolean]> = [
    ["pre-change credential transform control passed", input.preChangeTransformControlPassed],
    ["deny-all update was acknowledged", input.tightenAcknowledged],
    ["control-plane readback reported deny-all", input.tightenReadbackDenyAll],
    ["fresh same-session request was blocked after tightening", input.postChangeBlocked],
    ["persistent stop produced a snapshot", input.sourceStopSnapshotCaptured],
    ["resume created a different session", input.resumedWithNewSession],
    ["the new session resumed from the captured snapshot", input.resumedFromCapturedSnapshot],
    ["resumed control-plane readback reported deny-all", input.resumedReadbackDenyAll],
  ];
  const missing = requiredBeforeLifecycle
    .filter(([, passed]) => !passed)
    .map(([description]) => description);

  if (missing.length > 0) {
    return {
      verdict: "indeterminate",
      summary: "A required precondition failed, so post-lifecycle behavior cannot be attributed safely.",
      signals: missing.map((description) => `missing: ${description}`),
    };
  }

  if (input.postLifecycleRemovedSecretAction) {
    return {
      verdict: "candidate",
      summary: "The resumed sandbox used the removed controller-only credential to authorize an action.",
      signals: [
        "the post-resume observer event carried the exact removed credential",
        "the credential-gated observer action executed exactly once for the post-resume case",
      ],
    };
  }

  if (input.postLifecycleUnexpectedReachability) {
    return {
      verdict: "indeterminate",
      summary: "The resumed request reached the observer without the removed credential; this is not an SBX-025 credential-restore proof.",
      signals: ["deny-all post-resume traffic was observed without the removed credential"],
    };
  }

  if (!input.postLifecycleBlocked) {
    return {
      verdict: "indeterminate",
      summary: "The post-resume request was neither a credential-restore candidate nor a proven block.",
      signals: ["post-resume network outcome was ambiguous"],
    };
  }

  if (!input.reachabilityControlPassed) {
    return {
      verdict: "indeterminate",
      summary: "The post-resume deny result lacks a successful same-session reachability control.",
      signals: ["plain-allow reachability control did not pass after the deny observation"],
    };
  }

  return {
    verdict: "pass",
    summary: "The removed transform did not reappear after persistent stop and resume.",
    signals: [
      "fresh requests were blocked both before and after resume while deny-all was active",
      "the resumed session reached the observer only after a plain allow rule was installed",
      "the plain-allow control did not carry or use the removed credential",
    ],
  };
}
