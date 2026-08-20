import { describe, expect, it } from "vitest";
import {
  armPath,
  proxyAudience,
  requestPath,
  SBX050_CASES,
  SBX050_CREDENTIAL_HEADER,
  SBX050_EVENT_CASES,
  SBX050_PUBLIC_TRIGGER,
  SBX050_TRIGGER_HEADER,
  type Sbx050CaseId,
  type Sbx050EventCaseId,
} from "../pocs/SBX-050/protocol.js";
import {
  assessSbx050,
  exactPhasePolicy,
  type Sbx050AssessmentInput,
  type Sbx050ExpectedIdentity,
  type Sbx050LedgerEvent,
  type Sbx050PolicyStage,
  type Sbx050ProbeEvidence,
} from "../pocs/SBX-050/verdict.js";

const runId = "12345678-1234-4123-8123-123456789abc";
const aOrigin = "https://a.example.test";
const pOrigin = "https://p.example.test";
const aHostname = "a.example.test";
const pHostname = "p.example.test";
const sessionId = "sbx_abcdefghijklmnopqrstuvwxyz";
const identity: Sbx050ExpectedIdentity = {
  aliasEmail: "swve@wearehackerone.com",
  aliasIdentityVerified: true,
  teamId: "team_abcdefghijklmno",
  projectId: "prj_abcdefghijklmno",
  sandboxName: "sbx050-owned-test",
  sessionId,
};
const canaries = Object.fromEntries(SBX050_CASES.map((caseId, index) => [
  caseId, `c50_${String(index).padStart(24, "0")}`,
])) as Record<Sbx050CaseId, string>;
const operations = Object.fromEntries(SBX050_EVENT_CASES.map((caseId, index) => [caseId, {
  pass: `chain50_${String(index + 1).padStart(43, "a")}`,
  ...(caseId === "arm-without-trigger" ? { candidate: `chain50_${"z".repeat(43)}` } : {}),
}])) as Record<Sbx050EventCaseId, { pass: string; candidate?: string }>;

const publicPolicy = {
  allow: { [aHostname]: [{
    match: { headers: [{ key: { exact: SBX050_TRIGGER_HEADER }, value: { exact: SBX050_PUBLIC_TRIGGER } }] },
    forwardURL: proxyAudience(pOrigin, runId),
  }] },
};
const transformPolicy = {
  allow: { [aHostname]: [{
    match: { path: { exact: armPath(runId) } },
    transform: [{ headers: {
      [SBX050_CREDENTIAL_HEADER]: "<redacted>", [SBX050_TRIGGER_HEADER]: "<redacted>",
    } }],
  }] },
};
const finalPolicy = {
  allow: { [aHostname]: [
    transformPolicy.allow[aHostname]![0],
    {
      match: { headers: [{ key: { exact: SBX050_TRIGGER_HEADER }, value: { exact: "<trigger>" } }] },
      forwardURL: proxyAudience(pOrigin, runId),
    },
  ] },
};

function at(second: number): string {
  return new Date(Date.UTC(2026, 0, 1, 0, 0, second)).toISOString();
}

function oidcFields(proxy: boolean): Pick<Sbx050LedgerEvent,
  "oidcHeaderCount" | "oidcOfficialVerified" | "oidcIndependentRs256Verified" | "oidcAudienceMatched" |
  "oidcSourceMatched" | "oidcIssuerVerified" | "oidcTemporalVerified"> & Partial<Sbx050LedgerEvent> {
  return proxy ? {
    oidcHeaderCount: 1,
    oidcOfficialVerified: true,
    oidcIndependentRs256Verified: true,
    oidcAudienceMatched: true,
    oidcSourceMatched: true,
    oidcIssuerVerified: true,
    oidcTemporalVerified: true,
    oidcIssuer: `https://oidc.vercel.com/${identity.teamId}`,
    oidcAudience: proxyAudience(pOrigin, runId),
    oidcTeamId: identity.teamId,
    oidcProjectId: identity.projectId,
    oidcSessionId: identity.sessionId,
    oidcSandboxName: identity.sandboxName,
  } : {
    oidcHeaderCount: 0,
    oidcOfficialVerified: false,
    oidcIndependentRs256Verified: false,
    oidcAudienceMatched: false,
    oidcSourceMatched: false,
    oidcIssuerVerified: false,
    oidcTemporalVerified: false,
  };
}

function event(
  caseId: Sbx050EventCaseId,
  ordinal: number,
  second: number,
  candidate: boolean,
): Sbx050LedgerEvent {
  const publicForward = caseId === "public-forward-control";
  const transformed = caseId === "transform-alone-control" || caseId === "arm-without-trigger";
  const proxy = publicForward || (candidate && caseId === "arm-without-trigger");
  return {
    ordinal,
    observedAt: at(second),
    caseId,
    role: proxy ? "P" : "A",
    canaryMatched: true,
    originalRequestMatched: true,
    credentialHeaderCount: transformed ? 1 : 0,
    triggerHeaderCount: publicForward || transformed ? 1 : 0,
    credentialMatched: transformed,
    triggerMatched: transformed,
    ...oidcFields(proxy),
    operationId: caseId === "arm-without-trigger" && candidate
      ? operations[caseId].candidate!
      : operations[caseId].pass,
  };
}

function responseProbe(
  caseId: Sbx050EventCaseId,
  start: number,
  end: number,
  candidate: boolean,
): Sbx050ProbeEvidence {
  const publicForward = caseId === "public-forward-control";
  const transformed = caseId === "transform-alone-control" || caseId === "arm-without-trigger";
  const proxy = publicForward || (candidate && caseId === "arm-without-trigger");
  return {
    schemaVersion: 1,
    testId: "SBX-050-POC",
    runId,
    caseId,
    correlationCanary: canaries[caseId],
    commandExitCode: 0,
    startedAt: at(start),
    completedAt: at(end),
    ok: true,
    phase: "response",
    requestHostname: aHostname,
    requestServername: aHostname,
    requestPath: requestPath(runId, caseId, canaries[caseId]),
    sentCredentialHeader: false,
    sentHiddenTriggerHeader: false,
    sentPublicTriggerHeader: publicForward,
    connectionAttempts: 1,
    actualConnections: 1,
    actualRequests: 1,
    retries: 0,
    redirectsFollowed: 0,
    rejectUnauthorized: true,
    controllerConfigurableCustomTrustAccepted: false,
    inheritedPlatformTrustEnvironmentNames: [],
    tcpConnected: true,
    tlsEstablished: true,
    tlsAuthorized: true,
    responseReceived: true,
    responseStatusCode: 200,
    responseShapeValid: true,
    responseRole: proxy ? "P" : "A",
    responseCredentialMatched: transformed,
    responseTriggerMatched: transformed,
    responseOidcVerified: proxy,
    responseOperationId: caseId === "arm-without-trigger" && candidate
      ? operations[caseId].candidate!
      : operations[caseId].pass,
    responseBodyRetained: false,
    timedOut: false,
    durationMs: 25,
    controllerIdentity: identity,
  };
}

function blockedProbe(caseId: "direct-p-pre" | "direct-p-post", start: number, end: number): Sbx050ProbeEvidence {
  return {
    schemaVersion: 1,
    testId: "SBX-050-POC",
    runId,
    caseId,
    correlationCanary: canaries[caseId],
    commandExitCode: 0,
    startedAt: at(start),
    completedAt: at(end),
    ok: false,
    phase: "network-error",
    requestHostname: pHostname,
    requestServername: pHostname,
    requestPath: requestPath(runId, caseId, canaries[caseId]),
    sentCredentialHeader: false,
    sentHiddenTriggerHeader: false,
    sentPublicTriggerHeader: false,
    connectionAttempts: 1,
    actualConnections: 0,
    actualRequests: 0,
    retries: 0,
    redirectsFollowed: 0,
    rejectUnauthorized: true,
    controllerConfigurableCustomTrustAccepted: false,
    inheritedPlatformTrustEnvironmentNames: [],
    tcpConnected: false,
    tlsEstablished: false,
    tlsAuthorized: false,
    responseReceived: false,
    responseShapeValid: false,
    responseBodyRetained: false,
    timedOut: false,
    durationMs: 25,
    errorCode: "EAI_AGAIN",
    errorSyscall: "getaddrinfo",
    errorErrno: -3001,
    errorClass: "dns-resolution",
    controllerIdentity: identity,
  };
}

function policyProof(stage: Sbx050PolicyStage, start: number, end: number) {
  const policy = stage === "public-forward" ? publicPolicy : stage === "transform-alone" ? transformPolicy : finalPolicy;
  const finalStage = stage === "final-before" || stage === "final-after";
  const readbackCode = stage === "public-forward" ? "exact-public-forward" as const
    : stage === "transform-alone" ? "exact-transform-alone" as const
      : "exact-final-matchers" as const;
  return {
    stage,
    startedAt: at(start),
    completedAt: at(end),
    initialSessionId: sessionId,
    activeSessionId: sessionId,
    independentSessionId: sessionId,
    activeSandboxPolicy: { allow: [aHostname] },
    activeSessionPolicy: policy,
    independentSandboxPolicy: { allow: [aHostname] },
    independentSessionPolicy: policy,
    rawCredentialPresentInReadbacks: false,
    hiddenTriggerPresentInRetainedReadbacks: false,
    platformRedactionMarkerPresent: stage !== "public-forward",
    finalHiddenMatcherComparedExactlyBeforeSanitization: finalStage,
    finalHiddenMatcherMarkerPresent: finalStage,
    projectionMode: finalStage ? "exact-matchers" as const : "not-final" as const,
    readbackDiagnostic: {
      stage,
      configuredPolicy: readbackCode,
      activeSandboxPolicy: "exact-top-host-list" as const,
      activeSessionPolicy: readbackCode,
      independentSandboxPolicy: "exact-top-host-list" as const,
      independentSessionPolicy: readbackCode,
      activeIdentity: "exact" as const,
      independentIdentity: "exact" as const,
      projectionMode: finalStage ? "exact-matchers" as const : "not-final" as const,
      continuationAllowed: true,
      containsSecrets: false as const,
    },
    identity,
  };
}

function fixture(candidate = false): Sbx050AssessmentInput {
  return {
    runId,
    aOrigin,
    aHostname,
    pHostname,
    pOrigin,
    canaries: structuredClone(canaries),
    expectedOperationIds: structuredClone(operations),
    expectedIdentity: structuredClone(identity),
    probes: {
      "public-forward-control": responseProbe("public-forward-control", 4, 6, false),
      "transform-alone-control": responseProbe("transform-alone-control", 9, 11, false),
      "final-plain-pre": responseProbe("final-plain-pre", 14, 16, false),
      "direct-p-pre": blockedProbe("direct-p-pre", 17, 18),
      "arm-without-trigger": responseProbe("arm-without-trigger", 19, 21, candidate),
      "direct-p-post": blockedProbe("direct-p-post", 22, 23),
      "final-plain-post": responseProbe("final-plain-post", 24, 26, false),
    },
    policyProofs: {
      "public-forward": policyProof("public-forward", 2, 3),
      "transform-alone": policyProof("transform-alone", 7, 8),
      "final-before": policyProof("final-before", 12, 13),
      "final-after": policyProof("final-after", 27, 28),
    },
    ledger: {
      configured: true,
      configuredAt: at(0),
      emptyReadAt: at(1),
      events: [
        event("public-forward-control", 1, 5, false),
        event("transform-alone-control", 2, 10, false),
        event("final-plain-pre", 3, 15, false),
        event("arm-without-trigger", 4, 20, candidate),
        event("final-plain-post", 5, 25, false),
      ],
      unexpectedARequests: 0,
      unexpectedPRequests: 0,
      unattributedRequests: 0,
      rawCredentialRetained: false,
      credentialDigestRetained: false,
      rawHiddenTriggerRetained: false,
      hiddenTriggerDigestRetained: false,
      rawOidcTokenRetained: false,
      oidcTokenDigestRetained: false,
      receiverRuntimeTrustExact: true,
      receiverRuntimeTrustEnvironmentNames: [],
      receiverNodeOptionsPresent: false,
      receiverTlsVerificationDisabled: false,
    },
    cleanup: {
      startedAt: at(29),
      completedAt: at(30),
      sandbox: { stopped: true, deleted: true, absenceChecks: 2, errors: [] },
      receiver: { deleted: true, absent: true, absenceChecks: 2, errors: [] },
    },
    retention: {
      guestSourceScanned: true,
      guestConfigurationsScanned: true,
      guestArgvScanned: true,
      guestEnvironmentScanned: true,
      guestStagedFilesScanned: true,
      guestStdoutScanned: true,
      guestResultsScanned: true,
      controllerArtifactScanned: true,
      hiddenTriggerAbsentFromAllGuestMaterial: true,
      credentialAbsentFromAllGuestMaterial: true,
      rawCredentialRetained: false,
      credentialDigestRetained: false,
      rawHiddenTriggerRetained: false,
      hiddenTriggerDigestRetained: false,
      rawOidcTokenRetained: false,
      oidcTokenDigestRetained: false,
    },
    localState: {
      lockAcquired: true,
      lockMode: 0o600,
      artifactMode: 0o600,
      preexistingLockAbsent: true,
      lockReleased: true,
      recoveryJournalCreated: true,
      recoveryJournalMode: 0o600,
      recoveryJournalReleased: true,
    },
  };
}

function matcherlessFinalRetainedPolicy(): typeof finalPolicy {
  const policy = structuredClone(finalPolicy) as typeof finalPolicy;
  delete (policy.allow[aHostname]![0] as { match?: unknown }).match;
  delete (policy.allow[aHostname]![1] as { match?: unknown }).match;
  return policy;
}

function useMatcherlessFinalProjection(input: Sbx050AssessmentInput): void {
  const policy = matcherlessFinalRetainedPolicy();
  for (const stage of ["final-before", "final-after"] as const) {
    const proof = input.policyProofs[stage];
    proof.activeSessionPolicy = structuredClone(policy);
    proof.independentSessionPolicy = structuredClone(policy);
    proof.finalHiddenMatcherComparedExactlyBeforeSanitization = false;
    proof.finalHiddenMatcherMarkerPresent = false;
    proof.projectionMode = "matcherless-redacted";
    proof.readbackDiagnostic = {
      ...proof.readbackDiagnostic,
      activeSessionPolicy: "exact-final-matcherless-redacted",
      independentSessionPolicy: "exact-final-matcherless-redacted",
      projectionMode: "matcherless-redacted",
    };
  }
}

describe("SBX-050 verdict", () => {
  it("classifies the exact A-side termination as a clean negative", () => {
    expect(assessSbx050(fixture(false))).toMatchObject({
      outcome: "pass", candidate: false, severity: "none", controlsPassed: true,
    });
  });

  it("classifies only exact credential+trigger+OIDC receipt at P as conditional High", () => {
    expect(assessSbx050(fixture(true))).toMatchObject({
      outcome: "candidate-high", candidate: true, severity: "conditional-high",
      postTransformForwardingProven: true, credentialReceiptProven: true,
      reportReady: false,
      reportabilityStatus: "hold-pending-semantics-clarification",
      semanticsClarificationRequired: true,
    });
    expect(assessSbx050(fixture(true)).rationale).toMatch(/conditional pending confirmation/u);
  });

  it("keeps matcherless A indeterminate but still allows only the full behavioral P proof to candidate", () => {
    const aSide = fixture(false);
    useMatcherlessFinalProjection(aSide);
    expect(assessSbx050(aSide)).toMatchObject({
      outcome: "indeterminate", candidate: false, controlsPassed: true,
      postTransformForwardingProven: false, credentialReceiptProven: false,
    });
    expect(assessSbx050(aSide).rationale).toMatch(/omitted both final-rule matchers/u);

    const pSide = fixture(true);
    useMatcherlessFinalProjection(pSide);
    expect(assessSbx050(pSide)).toMatchObject({
      outcome: "candidate-high", candidate: true, controlsPassed: true,
      postTransformForwardingProven: true, credentialReceiptProven: true,
      reportabilityStatus: "hold-pending-semantics-clarification",
    });

    pSide.ledger.events[3]!.oidcAudienceMatched = false;
    expect(assessSbx050(pSide)).toMatchObject({ outcome: "indeterminate", candidate: false });
  });

  it("requires final-after to retain the exact final-before projection mode", () => {
    const input = fixture(false);
    const after = input.policyProofs["final-after"];
    const policy = matcherlessFinalRetainedPolicy();
    after.activeSessionPolicy = structuredClone(policy);
    after.independentSessionPolicy = structuredClone(policy);
    after.finalHiddenMatcherComparedExactlyBeforeSanitization = false;
    after.finalHiddenMatcherMarkerPresent = false;
    after.projectionMode = "matcherless-redacted";
    after.readbackDiagnostic = {
      ...after.readbackDiagnostic,
      activeSessionPolicy: "exact-final-matcherless-redacted",
      independentSessionPolicy: "exact-final-matcherless-redacted",
      projectionMode: "matcherless-redacted",
    };
    expect(assessSbx050(input)).toMatchObject({ outcome: "indeterminate", candidate: false });
  });

  it("does not promote P+OIDC without the keyed credential receipt", () => {
    const input = fixture(true);
    input.ledger.events[3]!.credentialHeaderCount = 0;
    input.ledger.events[3]!.credentialMatched = false;
    input.probes["arm-without-trigger"].responseCredentialMatched = false;
    expect(assessSbx050(input)).toMatchObject({ outcome: "indeterminate", candidate: false });
  });

  it("requires the public control to carry one public trigger without matching the hidden commitment", () => {
    const missingHeader = fixture();
    missingHeader.ledger.events[0]!.triggerHeaderCount = 0;
    expect(assessSbx050(missingHeader).outcome).toBe("indeterminate");
    const hiddenMatched = fixture();
    hiddenMatched.ledger.events[0]!.triggerMatched = true;
    expect(assessSbx050(hiddenMatched).outcome).toBe("indeterminate");
  });

  it("rejects a clean negative if any A event actually carried an OIDC header", () => {
    const input = fixture(false);
    input.ledger.events[3]!.oidcHeaderCount = 1;
    expect(assessSbx050(input)).toMatchObject({ outcome: "indeterminate", candidate: false });
  });

  it("accepts exact phase policies and rejects a missing final matcher", () => {
    expect(exactPhasePolicy("public-forward", publicPolicy, aHostname, runId, pOrigin)).toBe(true);
    expect(exactPhasePolicy("transform-alone", transformPolicy, aHostname, runId, pOrigin)).toBe(true);
    expect(exactPhasePolicy("final-before", finalPolicy, aHostname, runId, pOrigin)).toBe(true);
    const dropped = structuredClone(finalPolicy);
    delete (dropped.allow[aHostname]![1] as { match?: unknown }).match;
    expect(exactPhasePolicy("final-before", dropped, aHostname, runId, pOrigin)).toBe(false);
  });

  it("makes transform redaction and hidden-matcher proof stage-specific", () => {
    const publicMarker = fixture();
    publicMarker.policyProofs["public-forward"].platformRedactionMarkerPresent = true;
    expect(assessSbx050(publicMarker).outcome).toBe("indeterminate");
    const missingComparison = fixture();
    missingComparison.policyProofs["final-before"].finalHiddenMatcherComparedExactlyBeforeSanitization = false;
    expect(assessSbx050(missingComparison).outcome).toBe("indeterminate");
  });

  it("binds proof stage labels and rejects permutation", () => {
    const input = fixture();
    input.policyProofs["public-forward"].stage = "transform-alone";
    expect(assessSbx050(input).outcome).toBe("indeterminate");
  });

  it("requires globally unique patterned canaries and operation IDs", () => {
    const duplicateCanary = fixture();
    duplicateCanary.canaries["final-plain-post"] = duplicateCanary.canaries["final-plain-pre"];
    expect(assessSbx050(duplicateCanary).outcome).toBe("indeterminate");
    const duplicateOperation = fixture();
    duplicateOperation.expectedOperationIds["arm-without-trigger"].candidate =
      duplicateOperation.expectedOperationIds["arm-without-trigger"].pass;
    expect(assessSbx050(duplicateOperation).outcome).toBe("indeterminate");
  });

  it("requires exact distinct HTTPS A/P origins and canonical UUID", () => {
    const same = fixture();
    same.pOrigin = same.aOrigin;
    same.pHostname = same.aHostname;
    expect(assessSbx050(same).outcome).toBe("indeterminate");
    const badRun = fixture();
    badRun.runId = "not-a-uuid";
    expect(assessSbx050(badRun).outcome).toBe("indeterminate");
  });

  it("requires exact coherent direct-P DNS denial tuples, not an error code alone", () => {
    const input = fixture();
    input.probes["direct-p-pre"].actualConnections = 1;
    expect(assessSbx050(input).outcome).toBe("indeterminate");
    const missing = fixture();
    delete missing.probes["direct-p-post"].errorSyscall;
    expect(assessSbx050(missing).outcome).toBe("indeterminate");
  });

  it("handles a connection reset only with its separate coherent transport tuple", () => {
    const input = fixture();
    for (const caseId of ["direct-p-pre", "direct-p-post"] as const) {
      Object.assign(input.probes[caseId], {
        errorCode: "ECONNRESET",
        errorClass: "connection-reset",
        errorSyscall: "read",
        errorErrno: -104,
        actualConnections: 1,
        actualRequests: 0,
        tcpConnected: true,
        tlsEstablished: false,
        tlsAuthorized: false,
      });
    }
    expect(assessSbx050(input).outcome).toBe("pass");
    input.probes["direct-p-post"].errorSyscall = "connect";
    expect(assessSbx050(input).outcome).toBe("indeterminate");
  });

  it("rejects ECONNRESET after authorized TLS or after an HTTP request was sent", () => {
    const afterTls = fixture();
    Object.assign(afterTls.probes["direct-p-pre"], {
      errorCode: "ECONNRESET",
      errorClass: "connection-reset",
      errorSyscall: "read",
      errorErrno: -104,
      actualConnections: 1,
      actualRequests: 1,
      tcpConnected: true,
      tlsEstablished: true,
      tlsAuthorized: true,
    });
    expect(assessSbx050(afterTls).outcome).toBe("indeterminate");

    const requestSentWithoutAuthorizedTls = fixture();
    Object.assign(requestSentWithoutAuthorizedTls.probes["direct-p-post"], {
      errorCode: "ECONNRESET",
      errorClass: "connection-reset",
      errorSyscall: "read",
      errorErrno: -104,
      actualConnections: 1,
      actualRequests: 1,
      tcpConnected: true,
      tlsEstablished: false,
      tlsAuthorized: false,
    });
    expect(assessSbx050(requestSentWithoutAuthorizedTls).outcome).toBe("indeterminate");
  });

  it("rejects event timestamp inversion but allows an event exactly on a probe boundary", () => {
    const inverted = fixture();
    inverted.ledger.events[3]!.observedAt = at(22);
    expect(assessSbx050(inverted).outcome).toBe("indeterminate");
    const boundary = fixture();
    boundary.ledger.events[3]!.observedAt = boundary.probes["arm-without-trigger"].startedAt;
    const assessed = assessSbx050(boundary);
    expect(assessed.outcome, JSON.stringify(assessed)).toBe("pass");
  });

  it("requires strict interval separation and rejects equality between adjacent operations", () => {
    const input = fixture();
    input.probes["direct-p-pre"].startedAt = input.probes["final-plain-pre"].completedAt;
    expect(assessSbx050(input).outcome).toBe("indeterminate");
  });

  it("rejects extra, reordered, and unattributed ingress", () => {
    const extra = fixture();
    extra.ledger.events.push({ ...extra.ledger.events[0]!, ordinal: 6 });
    expect(assessSbx050(extra).outcome).toBe("indeterminate");
    const unattributed = fixture();
    unattributed.ledger.unattributedRequests = 1;
    expect(assessSbx050(unattributed).outcome).toBe("indeterminate");
  });

  it("rejects swapped sessions and OIDC claim identities", () => {
    const proof = fixture(true);
    proof.policyProofs["transform-alone"].identity = { ...identity, sessionId: `${sessionId}_other` };
    expect(assessSbx050(proof).outcome).toBe("indeterminate");
    const oidc = fixture(true);
    oidc.ledger.events[3]!.oidcProjectId = "prj_wrongidentity";
    expect(assessSbx050(oidc).outcome).toBe("indeterminate");
    const probe = fixture(true);
    probe.probes["arm-without-trigger"].controllerIdentity = { ...identity, sandboxName: "other" };
    expect(assessSbx050(probe).outcome).toBe("indeterminate");
  });

  it("fails closed on global hidden-material scans and mode-0600 state", () => {
    const scan = fixture();
    scan.retention.guestArgvScanned = false;
    expect(assessSbx050(scan).outcome).toBe("indeterminate");
    const mode = fixture();
    mode.localState.artifactMode = 0o644;
    expect(assessSbx050(mode).outcome).toBe("indeterminate");
  });

  it("requires the receiver verifier process to attest unmodified TLS/runtime trust", () => {
    const input = fixture(true);
    input.ledger.receiverRuntimeTrustExact = false as true;
    input.ledger.receiverRuntimeTrustEnvironmentNames = ["NODE_EXTRA_CA_CERTS"];
    expect(assessSbx050(input)).toMatchObject({ outcome: "indeterminate", candidate: false });
  });

  it("globally gates classification on stop/delete/absence cleanup", () => {
    const input = fixture(true);
    input.cleanup.sandbox.absenceChecks = 1;
    expect(assessSbx050(input)).toMatchObject({ outcome: "error", candidate: false });
  });
});
