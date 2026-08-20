import { describe, expect, it } from "vitest";
import {
  assessSbx048,
  assertNoTokenMaterial,
  exactDenyAll,
  exactForwardPolicy,
  exactForwardSandboxProjection,
  exactRawForwardPolicy,
  SBX048_TEST_ID,
  type Sbx048AssessmentInput,
  type Sbx048ControlPlaneAttempt,
  type Sbx048ReceiverRecord,
} from "../pocs/SBX-048/verdict.js";

const hostname = "p.example.test";
const forwardAudience = "https://p.example.test/v1/sbx048/forward/5b38a846-c6db-4fe1-a90e-4902e76fe213";

function attempt(
  kind: Sbx048ControlPlaneAttempt["kind"],
  statusCode: number,
  exact = false,
): Sbx048ControlPlaneAttempt {
  const mutation = kind === "brokered-token-policy-mutation";
  return {
    kind,
    method: mutation ? "POST" : "GET",
    endpointFamily: mutation
      ? "/v2/sandboxes/sessions/:sessionId/network-policy"
      : "/v2/sandboxes/sessions/:sessionId",
    requestCount: 1,
    statusCode,
    responseBodyRetained: false,
    responseHeadersRetained: false,
    rawTokenRetained: false,
    rawTokenDigestRetained: false,
    ...(exact ? {
      exactSession: true,
      exactPolicy: true,
      policyShape: mutation ? "literal-mode" as const : "legacy-raw-custom" as const,
    } : {}),
  };
}

function record(read = attempt("brokered-token-read", 403)): Sbx048ReceiverRecord {
  return {
    schemaVersion: 1,
    testId: SBX048_TEST_ID,
    runId: "5b38a846-c6db-4fe1-a90e-4902e76fe213",
    observedAt: "2026-08-19T00:00:00.000Z",
    requestAttributed: true,
    oidcHeaderLines: 1,
    oidcHeaderValues: 1,
    forwardedMetadataExact: true,
    correlationExact: true,
    oidc: {
      verifier: "independent-jose",
      signatureVerified: true,
      algorithmRs256: true,
      issuerVerified: true,
      audienceVerified: true,
      temporalClaimsVerified: true,
      exactSourceIdentityVerified: true,
      wrongAudienceRejected: true,
      issuer: "https://oidc.vercel.com/team_example",
      audience: forwardAudience,
      identity: {
        teamId: "team_example",
        projectId: "prj_example",
        sandboxId: "sbx_example",
        sandboxName: "sbx-048-poc-example",
      },
      ownerIdClaimPresent: false,
      teamIdClaimPresent: true,
      rawTokenRetained: false,
      rawTokenDigestRetained: false,
    },
    fakeControl: attempt("fake-token-read", 401),
    brokeredRead: read,
    mutationAttemptedOnlyAfterExactRead: false,
    controlPlaneRequestCounts: { fakeToken: 1, brokeredRead: 1, brokeredMutation: 0, total: 2 },
    responseOperationId: "oid48_abcdefghijklmnopqrstuvwx",
    rawRequestHeadersRetained: false,
    rawTokenRetained: false,
    rawTokenDigestRetained: false,
  };
}

function input(value = record()): Sbx048AssessmentInput {
  return {
    scopeAndAliasPassed: true,
    sandboxFreshAndExact: true,
    directOwnedOriginControlPassed: true,
    forwardPolicyReadbackBefore: true,
    ownerTokenSameRouteReadPassed: true,
    receiverConfigurationExact: true,
    guestRequestCount: 1,
    guestResponseMatchedRecord: true,
    record: value,
    ownerObservedDenyAllAfterMutation: false,
    ownerFinalOriginalPolicy: true,
    cleanupPassed: true,
  };
}

describe("SBX-048 policy shape checks", () => {
  it("distinguishes SDK projection, raw custom response, and literal deny-all", () => {
    expect(exactForwardPolicy({ allow: { [hostname]: [{ forwardURL: forwardAudience }] } }, hostname, forwardAudience)).toBe(true);
    expect(exactForwardSandboxProjection({ allow: [hostname] }, hostname)).toBe(true);
    expect(exactForwardSandboxProjection({ allow: [hostname, "other.example"] }, hostname)).toBe(false);
    expect(exactForwardSandboxProjection({ allow: [hostname], deny: [] }, hostname)).toBe(false);
    expect(exactRawForwardPolicy({
      mode: "custom",
      allowedDomains: [hostname],
      allowedCIDRs: [],
      deniedCIDRs: [],
      injectionRules: [],
      forwardRules: [{ domain: hostname, forwardURL: forwardAudience }],
    }, hostname, forwardAudience)).toBe(true);
    expect(exactDenyAll({ mode: "deny-all" })).toBe(true);
    expect(exactDenyAll("deny-all")).toBe(false);
  });

  it("rejects broadened raw policies and unknown rule fields", () => {
    const base = {
      mode: "custom",
      allowedDomains: [hostname],
      forwardRules: [{ domain: hostname, forwardURL: forwardAudience }],
    };
    expect(exactRawForwardPolicy({ ...base, allowedDomains: [hostname, "other.example"] }, hostname, forwardAudience)).toBe(false);
    expect(exactRawForwardPolicy({ ...base, forwardRules: [{ ...base.forwardRules[0], match: {} }] }, hostname, forwardAudience)).toBe(false);
    expect(exactRawForwardPolicy({ ...base, unexpected: true }, hostname, forwardAudience)).toBe(false);
  });
});

describe("SBX-048 verdict", () => {
  it("passes only on a conclusive control-plane authentication rejection", () => {
    expect(assessSbx048(input())).toMatchObject({
      verdict: "pass",
      candidate: false,
      maximumDemonstratedImpact: "none",
      controlsPassed: true,
    });
  });

  it("reports exact read acceptance as a real authentication-bypass candidate", () => {
    const value = record(attempt("brokered-token-read", 200, true));
    expect(assessSbx048(input(value))).toMatchObject({
      verdict: "candidate",
      candidate: true,
      maximumDemonstratedImpact: "read-only-authentication-bypass",
    });
  });

  it("promotes only an independently observed and restored exact mutation", () => {
    const value = record(attempt("brokered-token-read", 200, true));
    value.brokeredMutation = attempt("brokered-token-policy-mutation", 200, true);
    value.mutationAttemptedOnlyAfterExactRead = true;
    value.controlPlaneRequestCounts = { fakeToken: 1, brokeredRead: 1, brokeredMutation: 1, total: 3 };
    expect(assessSbx048({
      ...input(value),
      ownerObservedDenyAllAfterMutation: true,
    })).toMatchObject({
      verdict: "candidate",
      maximumDemonstratedImpact: "same-sandbox-policy-modification",
    });
  });

  it("fails closed on control drift, wrong audience, extra calls, and missing restoration", () => {
    const cases: Sbx048AssessmentInput[] = [];
    cases.push({ ...input(), cleanupPassed: false });
    const wrongAudience = record();
    wrongAudience.oidc!.wrongAudienceRejected = false;
    cases.push(input(wrongAudience));
    const extraCall = record();
    extraCall.controlPlaneRequestCounts = { fakeToken: 1, brokeredRead: 1, brokeredMutation: 1, total: 3 };
    cases.push(input(extraCall));
    const mutation = record(attempt("brokered-token-read", 200, true));
    mutation.brokeredMutation = attempt("brokered-token-policy-mutation", 200, true);
    mutation.mutationAttemptedOnlyAfterExactRead = true;
    mutation.controlPlaneRequestCounts = { fakeToken: 1, brokeredRead: 1, brokeredMutation: 1, total: 3 };
    cases.push({ ...input(mutation), ownerObservedDenyAllAfterMutation: true, ownerFinalOriginalPolicy: false });
    const readWithoutShape = record(attempt("brokered-token-read", 200, true));
    delete readWithoutShape.brokeredRead!.policyShape;
    cases.push(input(readWithoutShape));
    const readWithMutationFlag = record(attempt("brokered-token-read", 200, true));
    readWithMutationFlag.mutationAttemptedOnlyAfterExactRead = true;
    cases.push(input(readWithMutationFlag));
    const mutationWithoutShape = record(attempt("brokered-token-read", 200, true));
    mutationWithoutShape.brokeredMutation = attempt("brokered-token-policy-mutation", 200, true);
    delete mutationWithoutShape.brokeredMutation.policyShape;
    mutationWithoutShape.mutationAttemptedOnlyAfterExactRead = true;
    mutationWithoutShape.controlPlaneRequestCounts = { fakeToken: 1, brokeredRead: 1, brokeredMutation: 1, total: 3 };
    cases.push({ ...input(mutationWithoutShape), ownerObservedDenyAllAfterMutation: true });
    for (const field of ["rawRequestHeadersRetained", "rawTokenRetained", "rawTokenDigestRetained"] as const) {
      const retained = record() as unknown as Record<string, unknown>;
      retained[field] = true;
      cases.push(input(retained as unknown as Sbx048ReceiverRecord));
    }
    for (const value of cases) expect(assessSbx048(value)).toMatchObject({ verdict: "indeterminate", candidate: false });
  });
});

describe("SBX-048 retention guard", () => {
  it("rejects raw owner or proxy token material", () => {
    const owner = "owner-token-never-artifact";
    const proxy = "proxy-token-never-artifact";
    expect(() => assertNoTokenMaterial(input(), [owner, proxy])).not.toThrow();
    expect(() => assertNoTokenMaterial({ safe: input(), leaked: proxy }, [owner, proxy])).toThrow();
  });
});
