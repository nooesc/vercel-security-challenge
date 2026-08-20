import { describe, expect, it } from "vitest";
import {
  assessLifecyclePolicyRestore,
  type LifecycleAssessmentInput,
} from "../pocs/SBX-025/verdict.js";

function passingInput(): LifecycleAssessmentInput {
  return {
    preChangeTransformControlPassed: true,
    tightenAcknowledged: true,
    tightenReadbackDenyAll: true,
    postChangeBlocked: true,
    sourceStopSnapshotCaptured: true,
    resumedWithNewSession: true,
    resumedFromCapturedSnapshot: true,
    resumedReadbackDenyAll: true,
    postLifecycleRemovedSecretAction: false,
    postLifecycleBlocked: true,
    postLifecycleUnexpectedReachability: false,
    reachabilityControlPassed: true,
  };
}

describe("SBX-025 lifecycle verdict", () => {
  it("reports a candidate only for exact removed-secret action use after resume", () => {
    expect(
      assessLifecyclePolicyRestore({
        ...passingInput(),
        postLifecycleRemovedSecretAction: true,
        postLifecycleBlocked: false,
        reachabilityControlPassed: false,
      }),
    ).toMatchObject({ verdict: "candidate" });
  });

  it("passes only with a post-resume block and same-session reachability control", () => {
    expect(assessLifecyclePolicyRestore(passingInput())).toMatchObject({ verdict: "pass" });
    expect(
      assessLifecyclePolicyRestore({
        ...passingInput(),
        reachabilityControlPassed: false,
      }),
    ).toMatchObject({ verdict: "indeterminate" });
  });

  it("does not misclassify credential-free deny-all reachability as credential restoration", () => {
    expect(
      assessLifecyclePolicyRestore({
        ...passingInput(),
        postLifecycleBlocked: false,
        postLifecycleUnexpectedReachability: true,
      }),
    ).toMatchObject({ verdict: "indeterminate" });
  });

  it("requires the tighten, snapshot, and new-session attribution controls", () => {
    for (const field of [
      "tightenReadbackDenyAll",
      "postChangeBlocked",
      "sourceStopSnapshotCaptured",
      "resumedWithNewSession",
      "resumedFromCapturedSnapshot",
      "resumedReadbackDenyAll",
    ] as const) {
      expect(
        assessLifecyclePolicyRestore({
          ...passingInput(),
          [field]: false,
        }),
      ).toMatchObject({ verdict: "indeterminate" });
    }
  });
});
