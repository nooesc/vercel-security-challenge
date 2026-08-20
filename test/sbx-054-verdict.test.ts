import { describe, expect, it } from "vitest";
import {
  assessSbx054,
  isSbx054ExactEnotfoundDnsDenial,
  parseSbx054Guest,
  type Sbx054AssessmentInput,
  type Sbx054GuestResult,
  type Sbx054ObserverEvent,
  type Sbx054ObserverSnapshot,
} from "../pocs/SBX-054/verdict.js";

const digest = (character: string): string => character.repeat(64);

function blocked(
  caseId: "v3-deny-comparator" | "v2-runtime-deny-target" | "v3-deny-comparator-post",
): Sbx054GuestResult {
  return {
    schemaVersion: 1,
    testId: "SBX-054",
    kind: "public",
    caseId,
    requestAttempts: 1,
    connectionAttempts: 1,
    redirectsFollowed: 0,
    rejectUnauthorized: true,
    controllerConfigurableCustomTrustAccepted: false,
    inheritedPlatformTrustEnvironmentNames: [
      "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "SSL_CERT_FILE",
    ],
    nodeOptionsPresent: false,
    tlsAuthorized: false,
    receivedResponse: false,
    statusCode: null,
    durationMs: 40,
    receipt: null,
    secretProof: null,
    operationId: null,
    secretFileMode: null,
    secretFileDeleted: null,
    error: { name: "Error", code: "EAI_AGAIN", syscall: "getaddrinfo", errno: -3001 },
  };
}

function enotfoundTarget(): Sbx054GuestResult {
  const result = blocked("v2-runtime-deny-target");
  result.error = { name: "Error", code: "ENOTFOUND", syscall: "getaddrinfo", errno: -3008 };
  return result;
}

function success(
  kind: "public" | "secret",
  caseId: "v2-runtime-deny-target" | "v2-runtime-secret",
  receipt: string,
  secretProof: string | null = null,
  operationId: string | null = null,
): Sbx054GuestResult {
  return {
    schemaVersion: 1,
    testId: "SBX-054",
    kind,
    caseId,
    requestAttempts: 1,
    connectionAttempts: 1,
    redirectsFollowed: 0,
    rejectUnauthorized: true,
    controllerConfigurableCustomTrustAccepted: false,
    inheritedPlatformTrustEnvironmentNames: [
      "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "SSL_CERT_FILE",
    ],
    nodeOptionsPresent: false,
    tlsAuthorized: true,
    receivedResponse: true,
    statusCode: 200,
    durationMs: 80,
    receipt,
    secretProof,
    operationId,
    secretFileMode: kind === "secret" ? 0o600 : null,
    secretFileDeleted: kind === "secret" ? true : null,
    error: null,
  };
}

function event(
  sequence: number,
  kind: "public" | "secret",
  caseId: "v2-runtime-deny-target" | "v2-runtime-secret",
  commitment: string,
  receipt: string,
  secretProof?: string,
  operationId?: string,
): Sbx054ObserverEvent {
  return {
    sequence,
    observedAt: `2026-08-19T12:00:0${sequence}.000Z`,
    kind,
    caseId,
    method: kind === "public" ? "GET" : "POST",
    hostHeaderLines: 1,
    hostHeaderValues: 1,
    hostMatched: true,
    pathMatched: true,
    canaryCommitment: commitment,
    bodyLength: kind === "public" ? 0 : 48,
    secretMatched: kind === "secret",
    responseStatus: 200,
    receipt,
    ...(secretProof === undefined ? {} : { secretProof }),
    ...(operationId === undefined ? {} : { operationId }),
  };
}

function observer(events: Sbx054ObserverEvent[] = []): Sbx054ObserverSnapshot {
  return {
    configured: true,
    configuredAt: "2026-08-19T12:00:00.000Z",
    events,
    secretStaged: false,
    secretCleared: events.some((item) => item.kind === "secret"),
    unexpectedRequests: 0,
    rawCanaryRetained: false,
    rawSecretRetained: false,
    rawBodyRetained: false,
    secretDigestRetained: false,
    receiverRuntimeTrustExact: true,
    receiverTrustEnvironmentNames: [],
    receiverNodeOptionsPresent: false,
    receiverTlsVerificationDisabled: false,
  };
}

function input(): Sbx054AssessmentInput {
  return {
    controls: {
      exactEligibleIdentity: true,
      sdkVersionPinned: true,
      sdkRouteBranchExact: true,
      sameDenyAllWirePolicy: true,
      comparatorCreatedOnV3: true,
      targetCreatedOnV2: true,
      exactDistinctNamesAndSessions: true,
      comparatorPreReadbackExact: true,
      comparatorPostReadbackExact: true,
      comparatorPostTargetPreReadbackExact: true,
      comparatorFinalReadbackExact: true,
      targetPreReadbackExact: true,
      targetPostPublicReadbackExact: true,
      targetFinalReadbackExact: true,
      fixedGuestDigestMatched: true,
      receiverPreflightPassed: true,
      receiverPostflightPassed: true,
      emptyLedgerBeforeRequests: true,
      postComparatorCompletedBeforeImpact: true,
      sequentialNoRetrySchedule: true,
      cleanupSucceeded: true,
    },
    expected: {
      runId: "00000000-0000-4000-8000-000000000054",
      comparatorCanaryCommitment: digest("1"),
      targetCanaryCommitment: digest("2"),
      postComparatorCanaryCommitment: digest("3"),
      secretCanaryCommitment: digest("4"),
      targetPublicReceipt: digest("5"),
    },
    comparator: blocked("v3-deny-comparator"),
    postComparator: blocked("v3-deny-comparator-post"),
    targetPublic: blocked("v2-runtime-deny-target"),
    observer: observer(),
    impactAttempted: false,
    secretGeneratedAfterPublicSignal: false,
    secretFileWrittenAfterPublicSignal: false,
  };
}

describe("SBX-054 fail-closed verdict", () => {
  it("passes only the same exact pre-connect block with an empty observer", () => {
    expect(assessSbx054(input())).toMatchObject({
      verdict: "pass",
      candidate: false,
      severity: "none",
    });
  });

  it("accepts the exact Node24 ENOTFOUND tuple only as a noncandidate DNS-denial pass", () => {
    const value = input();
    value.targetPublic = enotfoundTarget();
    expect(isSbx054ExactEnotfoundDnsDenial(value.targetPublic)).toBe(true);
    expect(assessSbx054(value)).toMatchObject({
      verdict: "pass",
      candidate: false,
      severity: "none",
      v2PublicBoundaryReached: false,
    });

    value.observer = observer([event(
      1, "public", "v2-runtime-deny-target", value.expected.targetCanaryCommitment,
      value.expected.targetPublicReceipt,
    )]);
    expect(assessSbx054(value)).toMatchObject({ verdict: "indeterminate", candidate: false });
  });

  it("rejects near-miss ENOTFOUND tuples and never admits ENOTFOUND into the v3 candidate bracket", () => {
    for (const mutation of [
      { error: { name: "Error", code: "ENOTFOUND", syscall: "getaddrinfo", errno: -3001 } },
      { error: { name: "Error", code: "ENOTFOUND", syscall: "connect", errno: -3008 } },
      { tlsAuthorized: true },
      { durationMs: 5_001 },
    ] as const) {
      const value = input();
      value.targetPublic = { ...enotfoundTarget(), ...mutation };
      expect(isSbx054ExactEnotfoundDnsDenial(value.targetPublic)).toBe(false);
      expect(assessSbx054(value)).toMatchObject({ verdict: "indeterminate", candidate: false });
    }

    const comparator = input();
    comparator.comparator = {
      ...enotfoundTarget(),
      caseId: "v3-deny-comparator",
    };
    comparator.postComparator = {
      ...enotfoundTarget(),
      caseId: "v3-deny-comparator-post",
    };
    comparator.targetPublic = success(
      "public", "v2-runtime-deny-target", comparator.expected.targetPublicReceipt,
    );
    comparator.observer = observer([event(
      1, "public", "v2-runtime-deny-target", comparator.expected.targetCanaryCommitment,
      comparator.expected.targetPublicReceipt,
    )]);
    expect(assessSbx054(comparator)).toMatchObject({ verdict: "indeterminate", candidate: false });
  });

  it("classifies one exact v2-only public receipt as Medium before impact", () => {
    const value = input();
    value.targetPublic = success(
      "public", "v2-runtime-deny-target", value.expected.targetPublicReceipt,
    );
    value.observer = observer([event(
      1, "public", "v2-runtime-deny-target", value.expected.targetCanaryCommitment,
      value.expected.targetPublicReceipt,
    )]);
    expect(assessSbx054(value)).toMatchObject({
      verdict: "candidate-medium",
      v2PublicBoundaryReached: true,
      fileBackedSecretExfiltrated: false,
    });
  });

  it("requires matching guest and observer HMACs plus a deleted 0600 file for High", () => {
    const value = input();
    value.expected.targetSecretReceipt = digest("6");
    value.expected.targetSecretProof = digest("7");
    value.expected.targetOperationId = digest("8");
    value.targetPublic = success(
      "public", "v2-runtime-deny-target", value.expected.targetPublicReceipt,
    );
    value.targetSecret = success(
      "secret", "v2-runtime-secret", value.expected.targetSecretReceipt,
      value.expected.targetSecretProof, value.expected.targetOperationId,
    );
    value.observer = observer([
      event(1, "public", "v2-runtime-deny-target", value.expected.targetCanaryCommitment,
        value.expected.targetPublicReceipt),
      event(2, "secret", "v2-runtime-secret", value.expected.secretCanaryCommitment,
        value.expected.targetSecretReceipt, value.expected.targetSecretProof,
        value.expected.targetOperationId),
    ]);
    value.impactAttempted = true;
    value.secretGeneratedAfterPublicSignal = true;
    value.secretFileWrittenAfterPublicSignal = true;
    value.secretFileRequestedMode = 0o600;
    expect(assessSbx054(value)).toMatchObject({
      verdict: "candidate-high",
      candidate: true,
      severity: "high",
      fileBackedSecretExfiltrated: true,
    });
  });

  it("rejects a comparator reach, duplicate event, mismatched proof, or failed readback", () => {
    const comparatorReach = input();
    comparatorReach.comparator = success(
      "public", "v2-runtime-deny-target", comparatorReach.expected.targetPublicReceipt,
    );
    expect(assessSbx054(comparatorReach).verdict).toBe("indeterminate");

    const duplicate = input();
    duplicate.targetPublic = success("public", "v2-runtime-deny-target", duplicate.expected.targetPublicReceipt);
    const reached = event(1, "public", "v2-runtime-deny-target",
      duplicate.expected.targetCanaryCommitment, duplicate.expected.targetPublicReceipt);
    duplicate.observer = observer([reached, { ...reached, sequence: 2 }]);
    expect(assessSbx054(duplicate).verdict).toBe("indeterminate");

    const failedControl = input();
    failedControl.controls.targetPostPublicReadbackExact = false;
    expect(assessSbx054(failedControl).verdict).toBe("indeterminate");

    const changedPostComparator = input();
    changedPostComparator.postComparator.error = {
      name: "Error", code: "ENETUNREACH", syscall: "connect", errno: -101,
    };
    expect(assessSbx054(changedPostComparator).verdict).toBe("indeterminate");
  });

  it("parses one exact bounded guest line and rejects extra fields", () => {
    const result = blocked("v3-deny-comparator");
    expect(parseSbx054Guest(`${JSON.stringify(result)}\n`, "", 0)).toEqual(result);
    expect(() => parseSbx054Guest(`${JSON.stringify({ ...result, extra: true })}\n`, "", 0))
      .toThrow(/fields/u);
    expect(() => parseSbx054Guest(`${JSON.stringify(result)}\n`, "unexpected", 0))
      .toThrow(/bounded/u);
  });

  it("accepts only sorted unique names from the three observed inherited trust inputs", () => {
    const result = blocked("v3-deny-comparator");
    expect(parseSbx054Guest(`${JSON.stringify(result)}\n`, "", 0)
      .inheritedPlatformTrustEnvironmentNames).toEqual([
        "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "SSL_CERT_FILE",
      ]);
    expect(() => parseSbx054Guest(`${JSON.stringify({
      ...result,
      inheritedPlatformTrustEnvironmentNames: ["SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS"],
    })}\n`, "", 0)).toThrow(/invalid/u);
    expect(() => parseSbx054Guest(`${JSON.stringify({
      ...result,
      inheritedPlatformTrustEnvironmentNames: ["CUSTOM_CA_PATH"],
    })}\n`, "", 0)).toThrow(/invalid/u);
    expect(() => parseSbx054Guest(`${JSON.stringify({
      ...result,
      controllerConfigurableCustomTrustAccepted: true,
    })}\n`, "", 0)).toThrow(/invalid/u);
  });
});
