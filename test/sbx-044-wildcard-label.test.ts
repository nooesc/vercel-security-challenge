import { describe, expect, it } from "vitest";
import { expectedOperationId } from "../pocs/SBX-044/wildcard-label-scope.js";
import {
  assessSbx044,
  conclusiveWildcardBlock,
  SBX044_ALLOWED_HOST,
  SBX044_DENIED_HOST,
  SBX044_REDACTED_VALUE,
  SBX044_TEST_ID,
  SBX044_TRANSFORM_HEADER,
  SBX044_WILDCARD_PATTERN,
  type Sbx044AssessmentInput,
  type Sbx044CaseId,
  type Sbx044LedgerEvidence,
  type Sbx044PolicyProof,
  type Sbx044ProbeEvidence,
  type Sbx044Role,
} from "../pocs/SBX-044/verdict.js";

const runId = "11111111-2222-4333-8444-555555555555";
const controllerTrust: string[] = [];
const sandboxTrust = ["NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "SSL_CERT_FILE"];
const allowedKey = "a".repeat(48);
const deniedKey = "b".repeat(48);
const secret = `s44_${"c".repeat(43)}`;
const cases = [
  "outside-pre-allowed", "outside-pre-denied", "baseline-allowed", "baseline-denied",
  "public-allowed-pre", "public-denied", "public-allowed-post", "secret-allowed",
  "secret-denied", "outside-post-allowed", "outside-post-denied",
] as const satisfies readonly Sbx044CaseId[];
const canaries = Object.fromEntries(cases.map((caseId, index) => [
  caseId,
  `c44_${String(index).padStart(2, "0")}${"x".repeat(22)}`,
])) as Record<Sbx044CaseId, string>;

function role(caseId: Sbx044CaseId): Sbx044Role {
  return caseId.endsWith("allowed") || caseId.includes("allowed-") ? "allowed" : "denied";
}

const operations = Object.fromEntries(cases.map((caseId) => {
  const itemRole = role(caseId);
  const itemSecret = caseId === "secret-allowed" || caseId === "secret-denied" ? secret : undefined;
  return [caseId, expectedOperationId(
    itemRole === "allowed" ? allowedKey : deniedKey,
    runId,
    caseId,
    canaries[caseId],
    itemRole,
    itemSecret,
  )];
})) as Sbx044AssessmentInput["expectedOperationIds"];
operations.secretDeniedReach = expectedOperationId(
  deniedKey, runId, "secret-denied", canaries["secret-denied"], "denied",
);

function probe(caseId: Sbx044CaseId, input: { brokered?: boolean; blocked?: boolean; operationId?: string } = {}): Sbx044ProbeEvidence {
  const itemRole = role(caseId);
  const hostname = itemRole === "allowed" ? SBX044_ALLOWED_HOST : SBX044_DENIED_HOST;
  const trust = caseId.startsWith("outside-") ? controllerTrust : sandboxTrust;
  if (input.blocked) {
    return {
      schemaVersion: 1, testId: SBX044_TEST_ID, runId, caseId,
      correlationCanary: canaries[caseId], expectedRole: itemRole, commandExitCode: 0,
      ok: false, phase: "transport", requestHostname: hostname, requestServername: hostname,
      connectionAttempts: 1, actualConnections: 0, actualRequests: 0, retries: 0,
      redirectsFollowed: 0, rejectUnauthorized: true,
      controllerConfigurableCustomTrustAccepted: false,
      inheritedPlatformTrustEnvironmentNames: trust, tcpConnected: false,
      tlsAuthorized: false, tlsEstablished: false, responseReceived: false,
      errorCode: "EHOSTUNREACH", errorErrno: -113, errorSyscall: "connect", durationMs: 31,
    };
  }
  return {
    schemaVersion: 1, testId: SBX044_TEST_ID, runId, caseId,
    correlationCanary: canaries[caseId], expectedRole: itemRole, commandExitCode: 0,
    ok: true, phase: "response", requestHostname: hostname, requestServername: hostname,
    connectionAttempts: 1, actualConnections: 1, actualRequests: 1, retries: 0,
    redirectsFollowed: 0, rejectUnauthorized: true,
    controllerConfigurableCustomTrustAccepted: false,
    inheritedPlatformTrustEnvironmentNames: trust, tcpConnected: true,
    tlsAuthorized: true, tlsEstablished: true, responseReceived: true,
    responseStatusCode: 200, responseRole: itemRole, responseBrokered: input.brokered ?? false,
    responseOperationId: input.operationId ?? operations[caseId], remoteAddress: "104.21.1.1",
    remotePort: 443, durationMs: 80,
  };
}

function proof(kind: Sbx044PolicyProof["kind"], stage: Sbx044PolicyProof["stage"], session: string): Sbx044PolicyProof {
  const baselinePolicy = { allow: [SBX044_ALLOWED_HOST, SBX044_DENIED_HOST] };
  const wildcardPolicy = { allow: [SBX044_WILDCARD_PATTERN] };
  const transformPolicy = {
    allow: {
      [SBX044_WILDCARD_PATTERN]: [{ transform: [{ headers: { [SBX044_TRANSFORM_HEADER]: SBX044_REDACTED_VALUE } }] }],
    },
  };
  return {
    kind, stage, initialSessionId: session, activeSessionId: session, independentSessionId: session,
    activeSandboxPolicy: kind === "baseline" ? baselinePolicy : wildcardPolicy,
    activeSessionPolicy: kind === "baseline" ? baselinePolicy : kind === "public" ? wildcardPolicy : transformPolicy,
    independentSandboxPolicy: kind === "baseline" ? baselinePolicy : wildcardPolicy,
    independentSessionPolicy: kind === "baseline" ? baselinePolicy : kind === "public" ? wildcardPolicy : transformPolicy,
    rawSecretPresentInReadbacks: false,
    platformRedactionMarkerPresent: kind === "secret",
  };
}

function cleanup() {
  return { stopped: true, deleted: true, absenceChecks: 2, errors: [] as string[] };
}

function ledger(roleValue: Sbx044Role, eventCases: Sbx044CaseId[]): Sbx044LedgerEvidence {
  return {
    configured: true, role: roleValue,
    rawBrokeredSecretRetained: false, brokeredSecretDigestRetained: false,
    events: eventCases.map((caseId, index) => ({
      ordinal: index + 1, observedAt: new Date(1_800_000_000_000 + index).toISOString(),
      role: roleValue, caseId, canaryMatched: true,
      brokered: caseId === "secret-allowed" || caseId === "secret-denied",
      operationId: operations[caseId],
    })),
  };
}

function input(outcome: "pass" | "medium" | "high"): Sbx044AssessmentInput {
  const publicDenied = outcome === "pass" ? probe("public-denied", { blocked: true }) : probe("public-denied");
  const allowedEvents: Sbx044CaseId[] = [
    "outside-pre-allowed", "baseline-allowed", "public-allowed-pre", "public-allowed-post", "outside-post-allowed",
  ];
  const deniedEvents: Sbx044CaseId[] = ["outside-pre-denied", "baseline-denied"];
  if (outcome !== "pass") deniedEvents.push("public-denied");
  if (outcome === "high") { allowedEvents.push("secret-allowed"); deniedEvents.push("secret-denied"); }
  deniedEvents.push("outside-post-denied");
  const base: Sbx044AssessmentInput = {
    expectedRunId: runId, expectedCanaries: canaries, expectedOperationIds: operations,
    expectedControllerTrustEnvironmentNames: controllerTrust,
    expectedSandboxTrustEnvironmentNames: sandboxTrust,
    outsidePreflight: { allowed: probe("outside-pre-allowed"), denied: probe("outside-pre-denied") },
    outsidePostflight: { allowed: probe("outside-post-allowed"), denied: probe("outside-post-denied") },
    baseline: {
      allowed: probe("baseline-allowed"), denied: probe("baseline-denied"),
      before: proof("baseline", "before", "sbx_BaselineSession1234567890"),
      after: proof("baseline", "after", "sbx_BaselineSession1234567890"),
      cleanup: cleanup(), sessionId: "sbx_BaselineSession1234567890",
    },
    publicStage: {
      allowed: probe("public-allowed-pre"), denied: publicDenied,
      allowedAfter: probe("public-allowed-post"),
      before: proof("public", "before", "sbx_PublicSession123456789012"),
      after: proof("public", "after", "sbx_PublicSession123456789012"),
      cleanup: cleanup(), sessionId: "sbx_PublicSession123456789012",
    },
    ledgers: { allowed: ledger("allowed", allowedEvents), denied: ledger("denied", deniedEvents) },
    ledgerCleanup: { allowedDeleted: true, deniedDeleted: true, allowedAbsent: true, deniedAbsent: true, errors: [] },
  };
  if (outcome === "high") {
    base.secretStage = {
      allowed: probe("secret-allowed", { brokered: true }),
      denied: probe("secret-denied", { brokered: true }),
      before: proof("secret", "before", "sbx_SecretSession123456789012"),
      after: proof("secret", "after", "sbx_SecretSession123456789012"),
      cleanup: cleanup(), sessionId: "sbx_SecretSession123456789012",
    };
  }
  return base;
}

describe("SBX-044 wildcard label verdict", () => {
  it("passes only for an attributable pre-connect block with zero B event", () => {
    const fixture = input("pass");
    expect(conclusiveWildcardBlock(fixture.publicStage.denied, fixture, "public-denied")).toBe(true);
    expect(assessSbx044(fixture)).toMatchObject({ verdict: "pass", candidate: false });

    fixture.publicStage.denied.errorCode = "EAI_AGAIN";
    fixture.publicStage.denied.errorSyscall = "getaddrinfo";
    fixture.publicStage.denied.errorErrno = -3001;
    expect(conclusiveWildcardBlock(fixture.publicStage.denied, fixture, "public-denied")).toBe(true);
    expect(assessSbx044(fixture)).toMatchObject({ verdict: "pass", candidate: false });
  });

  it("classifies an exact deeper-host receipt as Medium", () => {
    expect(assessSbx044(input("medium"))).toMatchObject({
      verdict: "candidate-medium", candidate: true, severity: "medium", publicBoundaryEscape: true,
    });
  });

  it("classifies only the exact secret-bound B receipt as High", () => {
    expect(assessSbx044(input("high"))).toMatchObject({
      verdict: "candidate-high", candidate: true, severity: "high", brokeredSecretDisclosed: true,
    });
    const wrong = input("high");
    wrong.secretStage!.denied.responseOperationId = operations.secretDeniedReach;
    expect(assessSbx044(wrong)).toMatchObject({ verdict: "candidate-medium", brokeredSecretDisclosed: false });
  });

  it("rejects noncanonical DNS, reset, timeout, and observer-contact outcomes as clean blocks", () => {
    for (const [code, syscall] of [
      ["EAI_AGAIN", "connect"], ["ENOTFOUND", "getaddrinfo"],
      ["ECONNRESET", "read"], ["ETIMEDOUT", "connect"],
    ] as const) {
      const fixture = input("pass");
      fixture.publicStage.denied.errorCode = code;
      fixture.publicStage.denied.errorSyscall = syscall;
      expect(conclusiveWildcardBlock(fixture.publicStage.denied, fixture, "public-denied")).toBe(false);
      expect(assessSbx044(fixture)).toMatchObject({
        verdict: "indeterminate", candidate: false, controlsPassed: true,
      });
    }
    const contacted = input("pass");
    contacted.ledgers.denied.events.push({
      ordinal: 4, observedAt: new Date().toISOString(), role: "denied", caseId: "public-denied",
      canaryMatched: true, brokered: false, operationId: operations["public-denied"],
    });
    expect(conclusiveWildcardBlock(contacted.publicStage.denied, contacted, "public-denied")).toBe(false);
  });

  it("requires the exact errno for either accepted pre-connect block", () => {
    const wrongErrno = input("pass");
    wrongErrno.publicStage.denied.errorErrno = -1;
    expect(assessSbx044(wrongErrno)).toMatchObject({ verdict: "indeterminate", candidate: false });

    wrongErrno.publicStage.denied.errorCode = "EAI_AGAIN";
    wrongErrno.publicStage.denied.errorSyscall = "getaddrinfo";
    expect(assessSbx044(wrongErrno)).toMatchObject({ verdict: "indeterminate", candidate: false });
  });

  it("requires exact raw policy shapes, same-session reads, postflight, and cleanup", () => {
    const policyMismatch = input("medium");
    policyMismatch.publicStage.before.activeSessionPolicy = { allow: [SBX044_DENIED_HOST] };
    expect(assessSbx044(policyMismatch)).toMatchObject({ verdict: "indeterminate", candidate: false });
    const sessionMismatch = input("medium");
    sessionMismatch.publicStage.after.independentSessionId = "sbx_DifferentSession123456789";
    expect(assessSbx044(sessionMismatch)).toMatchObject({ verdict: "indeterminate", candidate: false });
    const postflightMismatch = input("medium");
    postflightMismatch.outsidePostflight.denied.responseOperationId = operations["outside-pre-denied"];
    expect(assessSbx044(postflightMismatch)).toMatchObject({ verdict: "indeterminate", candidate: false });
    const dirty = input("medium");
    dirty.publicStage.cleanup.deleted = false;
    expect(assessSbx044(dirty)).toMatchObject({ verdict: "indeterminate", candidate: false });
  });

  it("rejects correlation, trust, role, operation, TLS, and duplicate-ID mismatches", () => {
    for (const mutate of [
      (fixture: Sbx044AssessmentInput) => { fixture.publicStage.allowed.correlationCanary = "wrong"; },
      (fixture: Sbx044AssessmentInput) => { fixture.publicStage.allowed.inheritedPlatformTrustEnvironmentNames = []; },
      (fixture: Sbx044AssessmentInput) => { fixture.publicStage.allowed.responseRole = "denied"; },
      (fixture: Sbx044AssessmentInput) => { fixture.publicStage.allowed.responseOperationId = operations["baseline-allowed"]; },
      (fixture: Sbx044AssessmentInput) => { fixture.publicStage.allowed.tlsAuthorized = false; },
      (fixture: Sbx044AssessmentInput) => { fixture.expectedOperationIds["public-allowed-pre"] = fixture.expectedOperationIds["baseline-allowed"]; },
    ]) {
      const fixture = input("medium");
      mutate(fixture);
      expect(assessSbx044(fixture)).toMatchObject({ verdict: "indeterminate", candidate: false });
    }
  });

  it("rejects duplicate same-case events and swapped before/after proof labels", () => {
    const duplicate = input("medium");
    const original = duplicate.ledgers.denied.events.find((event) => event.caseId === "public-denied")!;
    duplicate.ledgers.denied.events.push({ ...original, ordinal: 99 });
    expect(assessSbx044(duplicate)).toMatchObject({ verdict: "indeterminate", candidate: false });

    const swapped = input("medium");
    swapped.publicStage.before.stage = "after";
    expect(assessSbx044(swapped)).toMatchObject({ verdict: "indeterminate", candidate: false });
  });

  it("rejects missing retention attestations, cross-role events, and secret-stage cleanup failure", () => {
    const missingRetention = input("medium");
    delete (missingRetention.ledgers.denied as Partial<Sbx044LedgerEvidence>).rawBrokeredSecretRetained;
    expect(assessSbx044(missingRetention)).toMatchObject({ verdict: "indeterminate", candidate: false });

    const crossRole = input("medium");
    crossRole.ledgers.denied.events[0]!.role = "allowed";
    expect(assessSbx044(crossRole)).toMatchObject({ verdict: "indeterminate", candidate: false });

    const dirtySecret = input("high");
    dirtySecret.secretStage!.cleanup.deleted = false;
    expect(assessSbx044(dirtySecret)).toMatchObject({ verdict: "indeterminate", candidate: false });
  });
});
