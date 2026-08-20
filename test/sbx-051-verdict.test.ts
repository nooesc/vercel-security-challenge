import { describe, expect, it } from "vitest";
import {
  assertSbx051EvidenceHasNoRawCapabilities,
  assessSbx051,
  exactSbx051ReadbackPair,
  type Sbx051AssessmentInput,
  type Sbx051CleanupResource,
  type Sbx051CredentialIssuance,
  type Sbx051Chronology,
  type Sbx051SandboxReadback,
} from "../pocs/SBX-051/verdict.js";
import type { Sbx051InteractiveAttempt } from "../pocs/SBX-051/protocol.js";

const aSession = "sbx_session_a_exact";
const bSession = "sbx_session_b_exact";

function wireFields() {
  return {
    webSocketClient: "ws@8.21.0" as const,
    unexpectedResponseObserved: false,
    handshakeStatusCode: null,
    handshakeResponseBodyRetained: false as const,
    handshakeResponseHeadersRetained: false as const,
  };
}

function readback(role: "A" | "B"): Sbx051SandboxReadback {
  const session = role === "A" ? aSession : bSession;
  const ownPath = role === "A"
    ? "/tmp/sbx-051/a-123e4567-e89b-42d3-a456-426614174000.marker"
    : "/tmp/sbx-051/b-123e4567-e89b-42d3-a456-426614174001.marker";
  const otherPath = role === "A"
    ? "/tmp/sbx-051/b-123e4567-e89b-42d3-a456-426614174001.marker"
    : "/tmp/sbx-051/a-123e4567-e89b-42d3-a456-426614174000.marker";
  return {
    role,
    name: `sbx-051-${role.toLowerCase()}-123e4567-e89b-42d3-a456-426614174000`,
    markerPath: ownPath,
    otherMarkerPath: otherPath,
    otherMarkerAbsent: true,
    activeSessionId: session,
    independentSessionId: session,
    activeStatus: "running",
    independentStatus: "running",
    exactName: true,
    exactTags: true,
    independentTags: true,
    nonpersistent: true,
    independentNonpersistent: true,
    sandboxDenyAll: true,
    sessionDenyAll: true,
    independentSandboxDenyAll: true,
    independentSessionDenyAll: true,
    interactivePort: role === "A" ? 41_051 : 41_052,
    independentInteractivePort: role === "A" ? 41_051 : 41_052,
    exactSingleInteractiveRoute: true,
    independentRouteCount: 0,
    ownerMarkerExact: true,
    markerMode0600: true,
    markerLength: 43,
    rawMarkerRetained: false,
    rawMarkerDigestRetained: false,
  };
}

function issuance(
  purpose: Sbx051CredentialIssuance["purpose"],
  sourceRole: "A" | "B",
): Sbx051CredentialIssuance {
  return {
    purpose,
    sourceRole,
    exactSourceSession: true,
    method: "POST",
    endpointFamily: "/v2/sandboxes/sessions/:sessionId/interactive",
    requestCount: 1,
    retryCount: 0,
    statusCode: 200,
    exactResponseShape: true,
    canonicalWssUrl: true,
    tokenStructurallyValid: true,
    responseBodyRetained: false,
    responseHeadersRetained: false,
    rawUrlRetained: false,
    queryBearingUrlRetained: false,
    rawTokenRetained: false,
    rawTokenDigestRetained: false,
  };
}

function rejectedNegative(
  purpose: "missing-token-negative" | "random-token-negative",
): Sbx051InteractiveAttempt {
  return {
    purpose,
    urlRole: "B",
    tokenSource: purpose === "missing-token-negative" ? "none" : "random",
    urlCredentialPurpose: "b-owner-control",
    tokenCredentialPurpose: purpose === "missing-token-negative" ? "none" : "random",
    requestCount: 1,
    retryCount: 0,
    ...wireFields(),
    unexpectedResponseObserved: true,
    handshakeStatusCode: 403,
    opened: false,
    openedExactIssuedUrl: false,
    emptyNegotiatedProtocol: false,
    emptyNegotiatedExtensions: false,
    startMessageExpected: false,
    startMessagesSent: 0,
    exactStartMessage: true,
    binaryFrames: 0,
    textControlFrames: 0,
    outputBytes: 0,
    exactExpectedMarker: false,
    exactUnexpectedMarker: false,
    exitCode: null,
    terminal: "http-response-before-open",
    rawOutputRetained: false,
    rawMarkerRetained: false,
    rawTokenRetained: false,
    rawTokenDigestRetained: false,
    queryBearingUrlRetained: false,
  };
}

function positive(
  purpose: "a-owner-control" | "b-owner-control" | "a-token-b-attack" | "b-target-validation",
): Sbx051InteractiveAttempt {
  return {
    purpose,
    urlRole: purpose === "a-owner-control" ? "A" : "B",
    tokenSource: purpose === "b-owner-control" || purpose === "b-target-validation" ? "B" : "A",
    urlCredentialPurpose: purpose === "a-owner-control"
      ? "a-owner-control"
      : purpose === "b-owner-control" ? "b-owner-control" : "b-attack-target",
    tokenCredentialPurpose: purpose === "a-owner-control"
      ? "a-owner-control"
      : purpose === "b-owner-control" ? "b-owner-control"
        : purpose === "b-target-validation" ? "b-attack-target" : "a-attack",
    requestCount: 1,
    retryCount: 0,
    ...wireFields(),
    opened: true,
    openedExactIssuedUrl: true,
    emptyNegotiatedProtocol: true,
    emptyNegotiatedExtensions: true,
    startMessageExpected: true,
    startMessagesSent: 1,
    exactStartMessage: true,
    binaryFrames: 1,
    textControlFrames: 1,
    outputBytes: 43,
    exactExpectedMarker: true,
    exactUnexpectedMarker: false,
    exitCode: 0,
    terminal: "closed-after-exit",
    rawOutputRetained: false,
    rawMarkerRetained: false,
    rawTokenRetained: false,
    rawTokenDigestRetained: false,
    queryBearingUrlRetained: false,
  };
}

function rejectedAttack(): Sbx051InteractiveAttempt {
  return {
    purpose: "a-token-b-attack",
    urlRole: "B",
    tokenSource: "A",
    urlCredentialPurpose: "b-attack-target",
    tokenCredentialPurpose: "a-attack",
    requestCount: 1,
    retryCount: 0,
    ...wireFields(),
    unexpectedResponseObserved: true,
    handshakeStatusCode: 401,
    opened: false,
    openedExactIssuedUrl: false,
    emptyNegotiatedProtocol: false,
    emptyNegotiatedExtensions: false,
    startMessageExpected: true,
    startMessagesSent: 0,
    exactStartMessage: false,
    binaryFrames: 0,
    textControlFrames: 0,
    outputBytes: 0,
    exactExpectedMarker: false,
    exactUnexpectedMarker: false,
    exitCode: null,
    terminal: "http-response-before-open",
    rawOutputRetained: false,
    rawMarkerRetained: false,
    rawTokenRetained: false,
    rawTokenDigestRetained: false,
    queryBearingUrlRetained: false,
  };
}

function cleanup(role: "A" | "B"): Sbx051CleanupResource {
  return {
    role,
    attempted: true,
    sessionIdKnownAtCleanup: true,
    exactProvenance: true,
    stopAttempted: true,
    stopped: true,
    deleteAttempted: true,
    deleted: true,
    firstAbsence: true,
    secondAbsence: true,
    namedAbsenceChecks: 2,
    absenceDelayMs: 750,
    errors: [],
  };
}

function chronology(targetValidation = false): Sbx051Chronology {
  const at = (second: number) => `2026-08-19T12:00:${String(second).padStart(2, "0")}.000Z`;
  const stages: Sbx051Chronology["steps"][number]["stage"][] = [
    "issue-a-owner-control",
    "issue-b-owner-control",
    "missing-token-negative",
    "random-token-negative",
    "a-owner-control",
    "b-owner-control",
    "issue-a-attack",
    "issue-b-attack-target",
    "a-token-b-attack",
    ...(targetValidation ? ["b-target-validation" as const] : []),
  ];
  return {
    preReadbacksCompletedAt: at(0),
    steps: stages.map((stage, index) => ({
      stage,
      startedAt: at(index * 2 + 1),
      completedAt: at(index * 2 + 2),
    })),
    postReadbacksStartedAt: at(targetValidation ? 21 : 19),
    postReadbacksCompletedAt: at(targetValidation ? 22 : 20),
    cleanupStartedAt: at(targetValidation ? 23 : 21),
    cleanupCompletedAt: at(targetValidation ? 24 : 22),
  };
}

function candidateInput(): Sbx051AssessmentInput {
  return {
    schemaVersion: 1,
    testId: "SBX-051-INTERACTIVE-TOKEN-BINDING",
    scopeAndAliasPassed: true,
    installedWireAuditPassed: true,
    distinctSandboxNames: true,
    distinctSessionIds: true,
    distinctMarkerPaths: true,
    distinctMarkerValues: true,
    distinctReturnedUrlBindings: true,
    allIssuedTokensDistinct: true,
    attackTokenIssuedFreshAndUsedOnce: true,
    bTargetTokenUseCount: 0,
    chronology: chronology(),
    preAttackReadbacks: [readback("A"), readback("B")],
    postAttackReadbacks: [readback("A"), readback("B")],
    issuances: [
      issuance("a-owner-control", "A"),
      issuance("b-owner-control", "B"),
      issuance("a-attack", "A"),
      issuance("b-attack-target", "B"),
    ],
    attempts: [
      rejectedNegative("missing-token-negative"),
      rejectedNegative("random-token-negative"),
      positive("a-owner-control"),
      positive("b-owner-control"),
      positive("a-token-b-attack"),
    ],
    requestAudit: {
      allAllowlisted: true,
      contiguous: true,
      completed: true,
      withinRateLimit: true,
      rawInteractiveCredentialRequests: 4,
      websocketConnections: 5,
      unexpectedRequests: 0,
      bindingOperations: [
        "interactive-A",
        "interactive-B",
        "websocket-missing-token-negative",
        "websocket-random-token-negative",
        "websocket-a-owner-control",
        "websocket-b-owner-control",
        "interactive-A",
        "interactive-B",
        "websocket-a-token-b-attack",
      ],
    },
    cleanup: {
      passed: true,
      resources: [cleanup("B"), cleanup("A")],
    },
    rawMarkersRetained: false,
    rawMarkerDigestsRetained: false,
    rawInteractiveTokensRetained: false,
    rawInteractiveTokenDigestsRetained: false,
    queryBearingUrlsRetained: false,
    commandOutputRetained: false,
    websocketErrorsRetained: false,
  };
}

function passInput(): Sbx051AssessmentInput {
  const value = candidateInput();
  value.bTargetTokenUseCount = 1;
  value.attempts[4] = rejectedAttack();
  value.attempts.push(positive("b-target-validation"));
  value.chronology = chronology(true);
  value.requestAudit.websocketConnections = 6;
  value.requestAudit.bindingOperations.push("websocket-b-target-validation");
  return value;
}

function expectIndeterminate(value: Sbx051AssessmentInput): void {
  expect(assessSbx051(value)).toMatchObject({
    verdict: "indeterminate",
    candidate: false,
    maximumDemonstratedImpact: "none",
  });
}

describe("SBX-051 conservative assessment", () => {
  it("accepts only the exact two-role preflight projection and rejects independent route drift", () => {
    const exact = candidateInput().preAttackReadbacks;
    expect(exactSbx051ReadbackPair(exact)).toBe(true);

    const projectedRoute = candidateInput().preAttackReadbacks;
    projectedRoute[0].independentRouteCount = 1;
    expect(exactSbx051ReadbackPair(projectedRoute)).toBe(false);

    const swappedCrossPath = candidateInput().preAttackReadbacks;
    swappedCrossPath[0].otherMarkerPath = swappedCrossPath[0].markerPath;
    expect(exactSbx051ReadbackPair(swappedCrossPath)).toBe(false);
  });

  it("reports a same-owner candidate only for the exact B marker through the fresh A token", () => {
    expect(assessSbx051(candidateInput())).toEqual({
      verdict: "candidate",
      candidate: true,
      controlsPassed: true,
      maximumDemonstratedImpact: "same-owner-cross-sandbox-file-read",
      reportability: "program-clarification-required",
      summary: "Under same-owner conditions, a fresh A-issued token was accepted at a fresh B target URL and returned B's exact marker; reportability requires program clarification.",
    });
  });

  it("returns pass only after exact rejection and exact same-target B-token validation", () => {
    const value = passInput();
    expect(assessSbx051(value)).toMatchObject({
      verdict: "pass",
      candidate: false,
      controlsPassed: true,
      maximumDemonstratedImpact: "none",
      reportability: "none",
    });
  });

  it("does not call generic transport failures, redirects, or 5xx a clean rejection", () => {
    const transport = candidateInput();
    transport.attempts[4] = {
      ...rejectedAttack(),
      unexpectedResponseObserved: false,
      handshakeStatusCode: null,
      terminal: "transport-error",
    };
    expectIndeterminate(transport);

    for (const status of [302, 503]) {
      const value = candidateInput();
      value.attempts[4] = { ...rejectedAttack(), handshakeStatusCode: status };
      expectIndeterminate(value);
    }
  });

  it("does not pass on 401/403 unless the same B target works with its own fresh token", () => {
    const noValidation = candidateInput();
    noValidation.attempts[4] = rejectedAttack();
    expectIndeterminate(noValidation);

    const deadValidation = passInput();
    deadValidation.attempts[5] = {
      ...positive("b-target-validation"),
      opened: false,
      openedExactIssuedUrl: false,
      startMessagesSent: 0,
      exactStartMessage: false,
      binaryFrames: 0,
      textControlFrames: 0,
      outputBytes: 0,
      exactExpectedMarker: false,
      exitCode: null,
      terminal: "transport-error",
    };
    expectIndeterminate(deadValidation);
  });

  it("rejects swapped readbacks, sessions, names, and post-attack drift despite summary booleans", () => {
    const cases: Sbx051AssessmentInput[] = [];

    const swapped = candidateInput();
    swapped.preAttackReadbacks = [readback("B"), readback("A")];
    cases.push(swapped);

    const sameSession = candidateInput();
    sameSession.preAttackReadbacks[1].activeSessionId = aSession;
    sameSession.preAttackReadbacks[1].independentSessionId = aSession;
    sameSession.postAttackReadbacks[1].activeSessionId = aSession;
    sameSession.postAttackReadbacks[1].independentSessionId = aSession;
    cases.push(sameSession);

    const sameName = candidateInput();
    sameName.preAttackReadbacks[1].name = sameName.preAttackReadbacks[0].name;
    sameName.postAttackReadbacks[1].name = sameName.postAttackReadbacks[0].name;
    cases.push(sameName);

    const drift = candidateInput();
    drift.postAttackReadbacks[1].name = `${drift.postAttackReadbacks[1].name}-changed`;
    cases.push(drift);

    for (const value of cases) expectIndeterminate(value);
  });

  it("ties every exact output length to the stable owner marker length", () => {
    const ownerMismatch = candidateInput();
    ownerMismatch.attempts[2]!.outputBytes = 42;
    expectIndeterminate(ownerMismatch);

    const attackMismatch = candidateInput();
    attackMismatch.attempts[4]!.outputBytes = 42;
    expectIndeterminate(attackMismatch);

    const postLengthDrift = candidateInput();
    postLengthDrift.postAttackReadbacks[1].markerLength = 44;
    expectIndeterminate(postLengthDrift);
  });

  it("requires both cross-marker paths to be absent before and after the attack", () => {
    const presentInA = candidateInput();
    presentInA.preAttackReadbacks[0].otherMarkerAbsent = false;
    expectIndeterminate(presentInA);

    const swappedPath = candidateInput();
    swappedPath.postAttackReadbacks[1].otherMarkerPath = swappedPath.postAttackReadbacks[1].markerPath;
    expectIndeterminate(swappedPath);
  });

  it("requires one non-overlapping exact chronology and fails closed when it is missing", () => {
    const reordered = candidateInput();
    [reordered.chronology.steps[0], reordered.chronology.steps[1]] = [
      reordered.chronology.steps[1]!,
      reordered.chronology.steps[0]!,
    ];
    expectIndeterminate(reordered);

    const overlap = candidateInput();
    overlap.chronology.steps[1]!.startedAt = overlap.chronology.steps[0]!.startedAt;
    expectIndeterminate(overlap);

    const missing = candidateInput();
    (missing as unknown as { chronology?: unknown }).chronology = undefined;
    expect(() => assessSbx051(missing)).not.toThrow();
    expectIndeterminate(missing);
  });

  it("rejects swapped, duplicate, extra, or retried issuance/attempt evidence", () => {
    const swappedIssuance = candidateInput();
    [swappedIssuance.issuances[0], swappedIssuance.issuances[1]] = [
      swappedIssuance.issuances[1]!,
      swappedIssuance.issuances[0]!,
    ];
    expectIndeterminate(swappedIssuance);

    const swappedAttempt = candidateInput();
    [swappedAttempt.attempts[0], swappedAttempt.attempts[1]] = [
      swappedAttempt.attempts[1]!,
      swappedAttempt.attempts[0]!,
    ];
    expectIndeterminate(swappedAttempt);

    const extra = candidateInput();
    extra.attempts.push(positive("a-token-b-attack"));
    expectIndeterminate(extra);

    const retriedIssuance = candidateInput();
    (retriedIssuance.issuances[2] as unknown as { retryCount: number }).retryCount = 1;
    expectIndeterminate(retriedIssuance);

    const retriedAttempt = candidateInput();
    (retriedAttempt.attempts[4] as unknown as { retryCount: number }).retryCount = 1;
    expectIndeterminate(retriedAttempt);
  });

  it("rejects mixed URL/token roles and any non-exact attack result", () => {
    const wrongUrl = candidateInput();
    wrongUrl.attempts[4]!.urlRole = "A";
    expectIndeterminate(wrongUrl);

    const wrongToken = candidateInput();
    wrongToken.attempts[4]!.tokenSource = "B";
    expectIndeterminate(wrongToken);

    const ownerUrlReusedForAttack = candidateInput();
    ownerUrlReusedForAttack.attempts[4]!.urlCredentialPurpose = "b-owner-control";
    expectIndeterminate(ownerUrlReusedForAttack);

    const targetTokenUsed = candidateInput();
    targetTokenUsed.attempts[4]!.tokenCredentialPurpose = "b-owner-control";
    expectIndeterminate(targetTokenUsed);

    const fabricatedSummary = candidateInput();
    fabricatedSummary.requestAudit.bindingOperations[7] = "interactive-A";
    expectIndeterminate(fabricatedSummary);

    const swappedMarker = candidateInput();
    swappedMarker.attempts[4]!.exactExpectedMarker = false;
    swappedMarker.attempts[4]!.exactUnexpectedMarker = true;
    expectIndeterminate(swappedMarker);

    const nonzeroExit = candidateInput();
    nonzeroExit.attempts[4]!.exitCode = 1;
    expectIndeterminate(nonzeroExit);

    const extraFrame = candidateInput();
    extraFrame.attempts[4]!.textControlFrames = 2;
    expectIndeterminate(extraFrame);

    const changedUrl = candidateInput();
    changedUrl.attempts[4]!.openedExactIssuedUrl = false;
    expectIndeterminate(changedUrl);

    const negotiatedProtocol = candidateInput();
    negotiatedProtocol.attempts[4]!.emptyNegotiatedProtocol = false;
    expectIndeterminate(negotiatedProtocol);

    const negotiatedExtension = candidateInput();
    negotiatedExtension.attempts[4]!.emptyNegotiatedExtensions = false;
    expectIndeterminate(negotiatedExtension);

    const protocolError = candidateInput();
    protocolError.attempts[4]!.terminal = "protocol-error";
    expectIndeterminate(protocolError);
  });

  it("does not call a malformed never-opened cross attempt a clean pass", () => {
    const value = candidateInput();
    value.attempts[4] = {
      ...rejectedAttack(),
      emptyNegotiatedProtocol: true,
      emptyNegotiatedExtensions: true,
      exactStartMessage: true,
    };
    expectIndeterminate(value);
  });

  it("fails closed on request-accounting and freshness/provenance controls", () => {
    const cases = candidateInput();
    cases.requestAudit.websocketConnections = 6;
    expectIndeterminate(cases);

    const unexpected = candidateInput();
    unexpected.requestAudit.unexpectedRequests = 1;
    expectIndeterminate(unexpected);

    const noncontiguous = candidateInput();
    noncontiguous.requestAudit.contiguous = false;
    expectIndeterminate(noncontiguous);

    const reused = candidateInput();
    reused.attackTokenIssuedFreshAndUsedOnce = false;
    expectIndeterminate(reused);

    const usedTargetToken = candidateInput();
    usedTargetToken.bTargetTokenUseCount = 1;
    expectIndeterminate(usedTargetToken);

    const sourceMismatch = candidateInput();
    sourceMismatch.issuances[2]!.exactSourceSession = false;
    expectIndeterminate(sourceMismatch);
  });

  it("requires reverse-order, provenance-bound stop/delete and two absence checks", () => {
    const wrongOrder = candidateInput();
    wrongOrder.cleanup.resources.reverse();
    expectIndeterminate(wrongOrder);

    const noProvenance = candidateInput();
    noProvenance.cleanup.resources[0]!.exactProvenance = false;
    expectIndeterminate(noProvenance);

    const oneAbsence = candidateInput();
    oneAbsence.cleanup.resources[1]!.secondAbsence = false;
    expectIndeterminate(oneAbsence);

    const weakAbsence = candidateInput();
    weakAbsence.cleanup.resources[0]!.namedAbsenceChecks = 0;
    expectIndeterminate(weakAbsence);

    const unknownSession = candidateInput();
    unknownSession.cleanup.resources[0]!.sessionIdKnownAtCleanup = false;
    expectIndeterminate(unknownSession);

    const error = candidateInput();
    error.cleanup.resources[0]!.errors.push({ kind: "api", status: 500 });
    expectIndeterminate(error);

    const summaryLie = candidateInput();
    summaryLie.cleanup.passed = false;
    expectIndeterminate(summaryLie);
  });

  it("rejects every declared retention violation", () => {
    const topLevelFields = [
      "rawMarkersRetained",
      "rawMarkerDigestsRetained",
      "rawInteractiveTokensRetained",
      "rawInteractiveTokenDigestsRetained",
      "queryBearingUrlsRetained",
      "commandOutputRetained",
      "websocketErrorsRetained",
    ] as const;
    for (const field of topLevelFields) {
      const value = candidateInput();
      (value as unknown as Record<string, unknown>)[field] = true;
      expectIndeterminate(value);
    }

    const attempt = candidateInput();
    (attempt.attempts[4] as unknown as { rawTokenRetained: boolean }).rawTokenRetained = true;
    expectIndeterminate(attempt);

    const issued = candidateInput();
    (issued.issuances[2] as unknown as { rawTokenDigestRetained: boolean })
      .rawTokenDigestRetained = true;
    expectIndeterminate(issued);
  });

  it("rejects raw tokens, markers, query URLs, and WebSocket URLs in durable evidence", () => {
    const token = "transient-token-should-not-survive";
    const marker = "transient-marker-should-not-survive";
    expect(() => assertSbx051EvidenceHasNoRawCapabilities({ note: token }, [token, marker]))
      .toThrow(/forbidden transient material/u);
    expect(() => assertSbx051EvidenceHasNoRawCapabilities({ note: marker }, [token, marker]))
      .toThrow(/forbidden transient material/u);
    expect(() => assertSbx051EvidenceHasNoRawCapabilities({ url: "https://example.test/?token=x" }, []))
      .toThrow(/raw WebSocket URL/u);
    expect(() => assertSbx051EvidenceHasNoRawCapabilities({ url: "wss://interactive.vercel.run/x" }, []))
      .toThrow(/raw WebSocket URL/u);
    expect(() => assertSbx051EvidenceHasNoRawCapabilities(candidateInput(), [token, marker]))
      .not.toThrow();
  });
});
