import { describe, expect, it } from "vitest";
import {
  assessSbx034,
  exactDirectBFirewallBlock,
  exactGuestManualNoFollowRequest,
  exactHttpsUrl,
  exactPlatformOidcVerification,
  type Sbx034AssessmentInput,
  type Sbx034PlatformOidcVerification,
  type Sbx034RedirectDestinationEvent,
} from "../pocs/SBX-034/verdict.js";

const expected = {
  runId: "d9ffca35-78bf-45dd-84b1-7b0382e7903d",
  testId: "SBX-034-POC",
  caseId: "host-forwardurl-redirect",
  correlationId: "corr_Cm8a0E0YS6iFpPbk3oYh",
  guestRequestUrl: "https://allowed.form-app.app/action?case=sbx034",
  forwardObserverUrl: "https://forward-a.form-app.app/v1/proxy/run/forward/action?case=sbx034",
  redirectTargetUrl: "https://denied-b.form-app.app/v1/redirect-target?case=sbx034",
  oidcAudience: "https://forward-a.form-app.app/v1/proxy/run/forward",
  operationId: "op_sbx034_exact_redirect_b",
  identity: {
    teamId: "team_n98ERpVwV7HqmWRudAyK8sXQ",
    projectId: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    sandboxId: "sbx_session_exact",
    sessionId: "sbx_session_exact",
    sandboxName: "sbx-034-owned",
  },
};

function exactVerification(
  overrides: Partial<Sbx034PlatformOidcVerification> = {},
): Sbx034PlatformOidcVerification {
  return {
    tokenOrdinal: 1,
    verifier: "observer-b-independent-jose",
    signatureVerified: true,
    algorithm: "RS256",
    issuer: "https://oidc.vercel.com",
    jwksUrl: "https://oidc.vercel.com/.well-known/jwks",
    audience: expected.oidcAudience,
    temporalClaimsVerified: true,
    identity: { ...expected.identity },
    rawTokenRetained: false,
    ...overrides,
  };
}

function destinationEvent(
  overrides: Partial<Sbx034RedirectDestinationEvent> = {},
): Sbx034RedirectDestinationEvent {
  return {
    runId: expected.runId,
    testId: expected.testId,
    caseId: expected.caseId,
    correlationId: expected.correlationId,
    requestUrl: expected.redirectTargetUrl,
    operationId: expected.operationId,
    attributableToSourceRedirect: true,
    oidcHeaderCount: 1,
    oidcValueCount: 1,
    oidcVerifications: [exactVerification()],
    ...overrides,
  };
}

function input(): Sbx034AssessmentInput {
  return {
    cleanupPassed: true,
    identityAndScopePassed: true,
    forwardPolicyConfiguredExactly: true,
    initialPolicyReadbackPassed: true,
    finalPolicyReadbackPassed: true,
    sameSessionPassed: true,
    sourceRedirectConfiguredExactly: true,
    expected: structuredClone(expected),
    guest: {
      commandExitCode: 0,
      ok: true,
      runId: expected.runId,
      testId: expected.testId,
      caseId: expected.caseId,
      correlationId: expected.correlationId,
      requestUrl: expected.guestRequestUrl,
      method: "GET",
      maximumRequests: 1,
      actualRequests: 1,
      retryCount: 0,
      redirectMode: "manual",
      redirectsAllowed: false,
      redirectsFollowed: 0,
      environmentProxyTrust: false,
    },
    directBPre: {
      caseId: `${expected.caseId}-direct-b-pre`,
      maximumRequests: 1,
      actualRequests: 1,
      retryCount: 0,
      redirectsAllowed: false,
      samePinnedDestination: true,
      conclusiveFirewallBlock: true,
      destinationObserverEventCount: 0,
    },
    directBPost: {
      caseId: `${expected.caseId}-direct-b-post`,
      maximumRequests: 1,
      actualRequests: 1,
      retryCount: 0,
      redirectsAllowed: false,
      samePinnedDestination: true,
      conclusiveFirewallBlock: true,
      destinationObserverEventCount: 0,
    },
    source: {
      eventCount: 1,
      event: {
        runId: expected.runId,
        testId: expected.testId,
        caseId: expected.caseId,
        correlationId: expected.correlationId,
        requestUrl: expected.forwardObserverUrl,
        redirectStatusCode: 307,
        location: expected.redirectTargetUrl,
      },
    },
    destination: { eventCount: 0 },
  };
}

function withDestination(base: Sbx034AssessmentInput, event = destinationEvent()): Sbx034AssessmentInput {
  base.destination = { eventCount: 1, event };
  base.guest.responseOperationId = event.operationId;
  return base;
}

describe("SBX-034 forwardURL host-side redirect verdict", () => {
  it("passes only after the exact redirect fires and B remains absent between direct block controls", () => {
    expect(assessSbx034(input())).toMatchObject({
      verdict: "pass",
      severity: "none",
      candidate: false,
      controlsPassed: true,
      oidcProofValid: false,
    });
  });

  it("classifies exact bare redirect misrouting as Medium without credential impact", () => {
    const testInput = withDestination(input(), destinationEvent({
      oidcHeaderCount: 0,
      oidcValueCount: 0,
      oidcVerifications: [],
    }));
    expect(assessSbx034(testInput)).toMatchObject({
      verdict: "candidate-medium",
      severity: "medium",
      candidate: true,
      controlsPassed: true,
      oidcProofValid: false,
    });
  });

  it("classifies High only with one exact independently verified platform token", () => {
    const verdict = assessSbx034(withDestination(input()));
    expect(verdict).toMatchObject({
      verdict: "candidate-high",
      severity: "high",
      candidate: true,
      controlsPassed: true,
      oidcProofValid: true,
    });
    expect(verdict.signals).toContain("audience and team/project/sandbox/session/name identity matched exactly");
  });

  it("requires exactly 307 and the B operation ID returned through the guest response", () => {
    const wrongStatus = withDestination(input());
    wrongStatus.source.event!.redirectStatusCode = 302;
    expect(assessSbx034(wrongStatus).verdict).toBe("indeterminate");

    const missingReceipt = withDestination(input());
    delete missingReceipt.guest.responseOperationId;
    expect(assessSbx034(missingReceipt).verdict).toBe("indeterminate");

    const wrongReceipt = withDestination(input());
    wrongReceipt.guest.responseOperationId = "op_unrelated";
    expect(assessSbx034(wrongReceipt).verdict).toBe("indeterminate");
  });

  it("accepts a cryptographically verified issuer path only on exact HTTPS oidc.vercel.com", () => {
    const issuer = "https://oidc.vercel.com/team_n98ERpVwV7HqmWRudAyK8sXQ";
    const verification = exactVerification({
      issuer,
      jwksUrl: `${issuer}/.well-known/jwks`,
    });
    expect(exactPlatformOidcVerification(verification, expected)).toBe(true);
    expect(assessSbx034(withDestination(input(), destinationEvent({
      oidcVerifications: [verification],
    }))).verdict).toBe("candidate-high");
  });

  it("validates exact HTTPS strings without audience normalization", () => {
    expect(exactHttpsUrl(expected.oidcAudience, expected.oidcAudience)).toBe(true);
    expect(exactHttpsUrl(`${expected.oidcAudience}/`, expected.oidcAudience)).toBe(false);
    expect(exactHttpsUrl("http://oidc.vercel.com", "http://oidc.vercel.com")).toBe(false);
    expect(exactHttpsUrl("https://user:pass@example.com/", "https://user:pass@example.com/")).toBe(false);
    expect(exactHttpsUrl("https://example.com/#fragment", "https://example.com/#fragment")).toBe(false);
  });

  it("exports strict guest and direct-B control discriminators", () => {
    const testInput = input();
    expect(exactGuestManualNoFollowRequest(testInput.guest, testInput.expected)).toBe(true);
    expect(exactDirectBFirewallBlock(testInput.directBPre, `${expected.caseId}-direct-b-pre`)).toBe(true);
    testInput.guest.redirectMode = "follow";
    testInput.directBPre.destinationObserverEventCount = 1;
    expect(exactGuestManualNoFollowRequest(testInput.guest, testInput.expected)).toBe(false);
    expect(exactDirectBFirewallBlock(testInput.directBPre, `${expected.caseId}-direct-b-pre`)).toBe(false);
  });

  it.each([
    ["non-independent verifier", { verifier: "source-a-helper" }],
    ["unverified signature", { signatureVerified: false }],
    ["wrong algorithm", { algorithm: "HS256" }],
    ["non-HTTPS issuer", { issuer: "http://oidc.vercel.com" }],
    ["issuer suffix attack", { issuer: "https://oidc.vercel.com.attacker.test" }],
    ["issuer path mutation", { issuer: "https://oidc.vercel.com/tenant" }],
    ["wrong JWKS", { jwksUrl: "https://attacker.test/.well-known/jwks" }],
    ["audience trailing slash", { audience: `${expected.oidcAudience}/` }],
    ["audience path mutation", { audience: `${expected.oidcAudience}/nested` }],
    ["temporal claims unchecked", { temporalClaimsVerified: false }],
    ["raw token retained", { rawTokenRetained: true }],
    ["verification error present", { verificationError: "claim mismatch" }],
  ] satisfies Array<[string, Partial<Sbx034PlatformOidcVerification>]>) (
    "downgrades %s to Medium despite exact B misrouting",
    (_name, mutation) => {
      const verification = exactVerification(mutation);
      expect(exactPlatformOidcVerification(verification, expected)).toBe(false);
      const verdict = assessSbx034(withDestination(input(), destinationEvent({
        oidcVerifications: [verification],
      })));
      expect(verdict).toMatchObject({ verdict: "candidate-medium", severity: "medium", oidcProofValid: false });
    },
  );

  it.each([
    "teamId",
    "projectId",
    "sandboxId",
    "sessionId",
    "sandboxName",
  ] as const)("downgrades an exact-looking token with a mismatched %s", (claim) => {
    const verification = exactVerification({
      identity: { ...expected.identity, [claim]: `${expected.identity[claim]}-wrong` },
    });
    expect(exactPlatformOidcVerification(verification, expected)).toBe(false);
    expect(assessSbx034(withDestination(input(), destinationEvent({
      oidcVerifications: [verification],
    }))).verdict).toBe("candidate-medium");
  });

  it("does not call multiple token headers or verification records High", () => {
    const duplicateHeaders = destinationEvent({ oidcHeaderCount: 2, oidcValueCount: 2 });
    expect(assessSbx034(withDestination(input(), duplicateHeaders)).verdict).toBe("candidate-medium");

    const duplicateVerifications = destinationEvent({
      oidcVerifications: [exactVerification(), { ...exactVerification(), tokenOrdinal: 2 }],
    });
    expect(assessSbx034(withDestination(input(), duplicateVerifications)).verdict).toBe("candidate-medium");
  });

  it.each([
    ["identityAndScopePassed", false],
    ["forwardPolicyConfiguredExactly", false],
    ["initialPolicyReadbackPassed", false],
    ["finalPolicyReadbackPassed", false],
    ["sameSessionPassed", false],
    ["sourceRedirectConfiguredExactly", false],
  ] satisfies Array<[keyof Sbx034AssessmentInput, boolean]>)(
    "keeps valid-token B reachability indeterminate when %s fails",
    (field, value) => {
      const testInput = withDestination(input());
      Object.assign(testInput, { [field]: value });
      expect(assessSbx034(testInput)).toMatchObject({
        verdict: "indeterminate",
        candidate: false,
        oidcProofValid: false,
      });
    },
  );

  it("requires manual/no-follow exactly once with no retry or proxy environment", () => {
    for (const mutate of [
      (value: Sbx034AssessmentInput) => { value.guest.maximumRequests = 2; },
      (value: Sbx034AssessmentInput) => { value.guest.actualRequests = 2; },
      (value: Sbx034AssessmentInput) => { value.guest.retryCount = 1; },
      (value: Sbx034AssessmentInput) => { value.guest.redirectMode = "follow"; },
      (value: Sbx034AssessmentInput) => { value.guest.redirectsAllowed = true; },
      (value: Sbx034AssessmentInput) => { value.guest.redirectsFollowed = 1; },
      (value: Sbx034AssessmentInput) => { value.guest.environmentProxyTrust = true; },
    ]) {
      const testInput = withDestination(input());
      mutate(testInput);
      expect(assessSbx034(testInput).verdict).toBe("indeterminate");
    }
  });

  it("requires conclusive direct-B blocks both before and after", () => {
    const preFailed = withDestination(input());
    preFailed.directBPre.conclusiveFirewallBlock = false;
    expect(assessSbx034(preFailed).verdict).toBe("indeterminate");

    const postFailed = withDestination(input());
    postFailed.directBPost.samePinnedDestination = false;
    expect(assessSbx034(postFailed).verdict).toBe("indeterminate");
  });

  it("refuses ambiguous, duplicated, or wrongly attributed B activity", () => {
    const duplicated = withDestination(input());
    duplicated.destination.eventCount = 2;
    expect(assessSbx034(duplicated).verdict).toBe("indeterminate");

    const wrongCorrelation = withDestination(input(), destinationEvent({ correlationId: "wrong" }));
    expect(assessSbx034(wrongCorrelation).verdict).toBe("indeterminate");

    const wrongTarget = withDestination(input(), destinationEvent({ requestUrl: "https://other.form-app.app/" }));
    expect(assessSbx034(wrongTarget).verdict).toBe("indeterminate");

    const notAttributed = withDestination(input(), destinationEvent({ attributableToSourceRedirect: false }));
    expect(assessSbx034(notAttributed).verdict).toBe("indeterminate");
  });

  it("does not pass contradictory zero-count destination evidence", () => {
    const testInput = input();
    testInput.destination = { eventCount: 0, event: destinationEvent() };
    expect(assessSbx034(testInput).verdict).toBe("indeterminate");
  });

  it("returns error on execution or cleanup failure before considering a valid token", () => {
    const cleanupFailed = withDestination(input());
    cleanupFailed.cleanupPassed = false;
    expect(assessSbx034(cleanupFailed)).toMatchObject({ verdict: "error", candidate: false });

    const executionFailed = withDestination(input());
    executionFailed.executionError = true;
    expect(assessSbx034(executionFailed)).toMatchObject({ verdict: "error", candidate: false });
  });

  it("rejects malformed expected endpoints before any classification", () => {
    const testInput = withDestination(input());
    testInput.expected.oidcAudience = "http://forward-a.form-app.app/v1/proxy/run/forward";
    expect(assessSbx034(testInput)).toMatchObject({ verdict: "indeterminate", candidate: false });
  });
});
