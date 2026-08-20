import { describe, expect, it } from "vitest";
import type { Sbx055InteractiveAttempt } from "../pocs/SBX-055/protocol.js";
import {
  assertSbx055EvidenceHasNoRawCapabilities,
  assessSbx055,
  exactSbx055Readbacks,
  type Sbx055AssessmentInput,
  type Sbx055ChronologyStage,
  type Sbx055CleanupProof,
  type Sbx055CredentialIssuance,
  type Sbx055SandboxReadback,
  type Sbx055SnapshotCleanup,
} from "../pocs/SBX-055/verdict.js";

const runId = "123e4567-e89b-42d3-a456-426614174000";
const sandboxName = `sbx-055-${runId}`;
const s1SessionId = "sbx_aaaaaaaaaaaaaaaaaaaa";
const s2SessionId = "sbx_bbbbbbbbbbbbbbbbbbbb";
const s1SnapshotId = "snap_cccccccccccccccccccc";
const s2SnapshotId = "snap_dddddddddddddddddddd";

function readback(
  stage: Sbx055SandboxReadback["stage"],
  role: Sbx055SandboxReadback["role"],
): Sbx055SandboxReadback {
  const sessionId = role === "S1" ? s1SessionId : s2SessionId;
  const sourceSnapshotId = role === "S1" ? null : s1SnapshotId;
  const port = role === "S1" ? 41_055 : 41_056;
  return {
    stage,
    role,
    name: sandboxName,
    independentName: sandboxName,
    listedName: sandboxName,
    activeSessionId: sessionId,
    independentSessionId: sessionId,
    listedSessionId: sessionId,
    activeStatus: "running",
    independentStatus: "running",
    listedStatus: "running",
    activeTagsExact: true,
    independentTagsExact: true,
    listedTagsExact: true,
    activePersistent: true,
    independentPersistent: true,
    listedPersistent: true,
    activeTimeoutMs: 240_000,
    independentTimeoutMs: 240_000,
    listedTimeoutMs: 240_000,
    activeDenyAll: true,
    activeSessionDenyAll: true,
    independentDenyAll: true,
    independentSessionDenyAll: true,
    listedDenyAll: true,
    activeInteractivePort: port,
    independentInteractivePort: port,
    activeExactSingleInteractiveRoute: true,
    independentRouteCount: 0,
    sourceSnapshotId,
    independentSourceSnapshotId: sourceSnapshotId,
    independentResumeFalse: true,
    listQueryExactNamePrefix: true,
    exactOneListedSandbox: true,
    listPaginationComplete: true,
  };
}

function issuance(
  purpose: Sbx055CredentialIssuance["purpose"],
  role: "S1" | "S2",
): Sbx055CredentialIssuance {
  return {
    purpose,
    sourceRole: role,
    sourceSessionId: role === "S1" ? s1SessionId : s2SessionId,
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
    rawUrlDigestRetained: false,
    queryBearingUrlRetained: false,
    rawTokenRetained: false,
    rawTokenDigestRetained: false,
  };
}

function negative(
  purpose: "missing-token-negative" | "random-token-negative",
): Sbx055InteractiveAttempt {
  const tokenSource = purpose === "missing-token-negative" ? "none" : "random";
  return {
    purpose,
    issuedUrlRole: "S1",
    tokenSourceSession: tokenSource,
    expectedRuntimeRole: "none",
    urlCredentialPurpose: "s1-owner-control",
    tokenCredentialPurpose: tokenSource,
    requestCount: 1,
    retryCount: 0,
    webSocketClient: "ws@8.21.0",
    statusCategory: "auth-rejected",
    unexpectedResponseObserved: true,
    handshakeStatusCode: 403,
    handshakeResponseBodyRetained: false,
    handshakeResponseHeadersRetained: false,
    opened: false,
    authenticated: false,
    openedExactIssuedUrl: false,
    emptyNegotiatedProtocol: false,
    emptyNegotiatedExtensions: false,
    startMessageExpected: false,
    startMessagesSent: 0,
    exactStartMessage: true,
    binaryFrames: 0,
    textControlFrames: 0,
    outputBytes: 0,
    markerMatched: false,
    crossMarkerAbsent: false,
    exitCode: null,
    protocolValid: false,
    terminal: "http-response-before-open",
    rawOutputRetained: false,
    rawMarkerRetained: false,
    rawTokenRetained: false,
    rawTokenDigestRetained: false,
    queryBearingUrlRetained: false,
  };
}

function positive(
  purpose: "s1-owner-control" | "stale-s1-token-on-s2" | "s2-owner-control",
): Sbx055InteractiveAttempt {
  const issuedUrlRole = purpose === "s2-owner-control" ? "S2" : "S1";
  const expectedRuntimeRole = purpose === "s1-owner-control" ? "S1" : "S2";
  const credentialPurpose = purpose === "stale-s1-token-on-s2"
    ? "s1-fresh-stale"
    : purpose;
  return {
    purpose,
    issuedUrlRole,
    tokenSourceSession: issuedUrlRole,
    expectedRuntimeRole,
    urlCredentialPurpose: credentialPurpose,
    tokenCredentialPurpose: credentialPurpose,
    requestCount: 1,
    retryCount: 0,
    webSocketClient: "ws@8.21.0",
    statusCategory: "websocket-opened",
    unexpectedResponseObserved: false,
    handshakeStatusCode: null,
    handshakeResponseBodyRetained: false,
    handshakeResponseHeadersRetained: false,
    opened: true,
    authenticated: true,
    openedExactIssuedUrl: true,
    emptyNegotiatedProtocol: true,
    emptyNegotiatedExtensions: true,
    startMessageExpected: true,
    startMessagesSent: 1,
    exactStartMessage: true,
    binaryFrames: 1,
    textControlFrames: 1,
    outputBytes: purpose === "s1-owner-control" ? 43 : 47,
    markerMatched: true,
    crossMarkerAbsent: true,
    exitCode: 0,
    protocolValid: true,
    terminal: "closed-after-exit",
    rawOutputRetained: false,
    rawMarkerRetained: false,
    rawTokenRetained: false,
    rawTokenDigestRetained: false,
    queryBearingUrlRetained: false,
  };
}

function rejectedStale(statusCode: 401 | 403 = 401): Sbx055InteractiveAttempt {
  return {
    purpose: "stale-s1-token-on-s2",
    issuedUrlRole: "S1",
    tokenSourceSession: "S1",
    expectedRuntimeRole: "S2",
    urlCredentialPurpose: "s1-fresh-stale",
    tokenCredentialPurpose: "s1-fresh-stale",
    requestCount: 1,
    retryCount: 0,
    webSocketClient: "ws@8.21.0",
    statusCategory: "auth-rejected",
    unexpectedResponseObserved: true,
    handshakeStatusCode: statusCode,
    handshakeResponseBodyRetained: false,
    handshakeResponseHeadersRetained: false,
    opened: false,
    authenticated: false,
    openedExactIssuedUrl: false,
    emptyNegotiatedProtocol: false,
    emptyNegotiatedExtensions: false,
    startMessageExpected: true,
    startMessagesSent: 0,
    exactStartMessage: false,
    binaryFrames: 0,
    textControlFrames: 0,
    outputBytes: 0,
    markerMatched: false,
    crossMarkerAbsent: false,
    exitCode: null,
    protocolValid: false,
    terminal: "http-response-before-open",
    rawOutputRetained: false,
    rawMarkerRetained: false,
    rawTokenRetained: false,
    rawTokenDigestRetained: false,
    queryBearingUrlRetained: false,
  };
}

function chronology(passShape = false): Sbx055AssessmentInput["chronology"] {
  const stages: Sbx055ChronologyStage[] = [
    "s1-readbacks",
    "write-read-m1",
    "issue-s1-owner-control",
    "missing-token-negative",
    "random-token-negative",
    "s1-owner-control",
    "m2-absence-before-stop",
    "issue-s1-fresh-stale",
    "stop-s1",
    "snapshot-created",
    "resume-s2",
    "s2-pre-readbacks",
    "verify-m1-persisted",
    "write-read-m2",
    "stale-s1-token-on-s2",
    ...(passShape ? ["issue-s2-owner-control" as const, "s2-owner-control" as const] : []),
    "s2-post-readbacks",
    "cleanup",
  ];
  const at = (millisecond: number) =>
    `2026-08-19T12:00:00.${String(millisecond).padStart(3, "0")}Z`;
  return stages.map((stage, index) => ({
    stage,
    startedAt: at(index * 2),
    completedAt: at(index * 2 + 1),
  }));
}

function snapshotCleanup(
  sourceRole: "S1" | "S2",
  snapshotId: string,
): Sbx055SnapshotCleanup {
  return {
    snapshotId,
    sourceRole,
    sourceSessionId: sourceRole === "S1" ? s1SessionId : s2SessionId,
    exactProvenance: true,
    deleteAttempted: true,
    deleted: true,
    firstAbsence: true,
    secondAbsence: true,
    absenceChecks: 2,
    errors: [],
  };
}

function cleanup(): Sbx055CleanupProof {
  return {
    passed: true,
    sandbox: {
      attempted: true,
      exactProvenance: true,
      s2SessionIdKnown: true,
      stopAttempted: true,
      stopped: true,
      deleteAttempted: true,
      deleted: true,
      firstAbsence: true,
      secondAbsence: true,
      thirdAbsence: true,
      namedAbsenceChecks: 3,
      prefixListAbsent: true,
      errors: [],
    },
    snapshotEnumerationComplete: true,
    snapshotListPaginationComplete: true,
    observedSnapshotCount: 2,
    unexpectedSnapshots: 0,
    snapshots: [
      snapshotCleanup("S2", s2SnapshotId),
      snapshotCleanup("S1", s1SnapshotId),
    ],
    journalRemoved: true,
    liveLockReleased: true,
  };
}

function candidateInput(): Sbx055AssessmentInput {
  return {
    schemaVersion: 1,
    testId: "SBX-055-STALE-INTERACTIVE-RESUME",
    runId,
    sandboxName,
    scopeAndAliasPassed: true,
    installedWireAuditPassed: true,
    sameOwnerOnly: true,
    expectedTimeoutMs: 240_000,
    lifecycle: {
      sandboxName,
      s1SessionId,
      stopAttempted: true,
      stopped: true,
      snapshotCaptured: true,
      snapshotId: s1SnapshotId,
      snapshotSourceSessionId: s1SessionId,
      snapshotStatus: "created",
      resumeAttempted: true,
      resumedFromExactSnapshot: true,
      resumeResponseExact: true,
      sameNameResumed: true,
      s2SessionId,
      distinctSessionIds: true,
    },
    markers: {
      s1Path: `/tmp/sbx-055/s1-${runId}.marker`,
      s2Path: `/tmp/sbx-055/s2-${runId}.marker`,
      s1FixtureSessionId: s1SessionId,
      s2FixtureSessionId: s2SessionId,
      s1Length: 43,
      s2Length: 47,
      distinctMarkerValues: true,
      s1FixedCommandShape: true,
      s1SessionUnchanged: true,
      s1WrittenAfterCreate: true,
      s1Mode0600: true,
      s1LocalReadExactBeforeStop: true,
      s2AbsentBeforeStop: true,
      s1PersistedAfterResume: true,
      s1Mode0600AfterResume: true,
      s1LocalReadExactAfterResume: true,
      s2FixedCommandShape: true,
      s2SessionUnchanged: true,
      s2WrittenOnlyAfterResume: true,
      s2Mode0600: true,
      s2LocalReadExactAfterResume: true,
      rawMarkersRetained: false,
      rawMarkerDigestsRetained: false,
    },
    readbacks: [
      readback("s1-pre-stop", "S1"),
      readback("s2-pre-attempt", "S2"),
      readback("s2-post-attempt", "S2"),
    ],
    issuances: [
      issuance("s1-owner-control", "S1"),
      issuance("s1-fresh-stale", "S1"),
    ],
    attempts: [
      negative("missing-token-negative"),
      negative("random-token-negative"),
      positive("s1-owner-control"),
      positive("stale-s1-token-on-s2"),
    ],
    chronology: chronology(),
    allIssuedTokensDistinct: true,
    staleTokenUnusedBeforeAttack: true,
    staleCredentialPairUsedUnchanged: true,
    s1OwnerTokenUseCount: 1,
    staleTokenUseCount: 1,
    s2OwnerTokenUseCount: 0,
    requestAudit: {
      allAllowlisted: true,
      contiguous: true,
      completed: true,
      withinRateLimit: true,
      interactiveCredentialRequests: 2,
      websocketConnections: 4,
      unexpectedRequests: 0,
    },
    cleanup: cleanup(),
    rawInteractiveTokensRetained: false,
    rawInteractiveTokenDigestsRetained: false,
    rawInteractiveUrlsRetained: false,
    rawInteractiveUrlDigestsRetained: false,
    queryBearingUrlsRetained: false,
    commandOutputRetained: false,
    commandOutputDigestsRetained: false,
    websocketErrorsRetained: false,
  };
}

function passInput(): Sbx055AssessmentInput {
  const value = candidateInput();
  value.issuances.push(issuance("s2-owner-control", "S2"));
  value.attempts[3] = rejectedStale();
  value.attempts.push(positive("s2-owner-control"));
  value.chronology = chronology(true);
  value.s2OwnerTokenUseCount = 1;
  value.requestAudit.interactiveCredentialRequests = 3;
  value.requestAudit.websocketConnections = 5;
  return value;
}

function expectIndeterminate(value: Sbx055AssessmentInput): void {
  expect(assessSbx055(value)).toMatchObject({
    verdict: "indeterminate",
    candidate: false,
    maximumDemonstratedImpact: "none",
  });
}

describe("SBX-055 conservative verdict", () => {
  it("requires exact active, independent, and list identity across distinct S1/S2 sessions", () => {
    const exact = candidateInput();
    expect(exactSbx055Readbacks(exact)).toBe(true);

    const sameSession = candidateInput();
    sameSession.lifecycle.s2SessionId = s1SessionId;
    sameSession.readbacks[1].activeSessionId = s1SessionId;
    sameSession.readbacks[1].independentSessionId = s1SessionId;
    sameSession.readbacks[1].listedSessionId = s1SessionId;
    sameSession.readbacks[2].activeSessionId = s1SessionId;
    sameSession.readbacks[2].independentSessionId = s1SessionId;
    sameSession.readbacks[2].listedSessionId = s1SessionId;
    expect(exactSbx055Readbacks(sameSession)).toBe(false);

    const staleList = candidateInput();
    staleList.readbacks[1].listedSessionId = s1SessionId;
    expect(exactSbx055Readbacks(staleList)).toBe(false);

    const projectedRouteDrift = candidateInput();
    projectedRouteDrift.readbacks[0].independentRouteCount = 1;
    expect(exactSbx055Readbacks(projectedRouteDrift)).toBe(false);

    const accidentalResume = candidateInput();
    accidentalResume.readbacks[1].independentResumeFalse = false;
    expect(exactSbx055Readbacks(accidentalResume)).toBe(false);
  });

  it("reports only the exact stale-S1 capability read of post-resume M2, capped at Medium", () => {
    expect(assessSbx055(candidateInput())).toEqual({
      verdict: "candidate",
      candidate: true,
      controlsPassed: true,
      maximumDemonstratedImpact: "same-owner-stale-session-file-read",
      maximumSeverity: "medium",
      reportability: "program-clarification-required",
      summary: "The unused S1 interactive capability survived stop/snapshot/resume and read the exact M2 file created only in distinct session S2; impact is same-owner and clarification-gated.",
    });
  });

  it("passes only after exact stale 401/403 and an exact fresh-S2 M2 owner control", () => {
    expect(assessSbx055(passInput())).toMatchObject({
      verdict: "pass",
      candidate: false,
      controlsPassed: true,
      maximumSeverity: "none",
      reportability: "none",
    });

    const noOwnerValidation = candidateInput();
    noOwnerValidation.attempts[3] = rejectedStale(403);
    expectIndeterminate(noOwnerValidation);

    const wrongOwnerOutput = passInput();
    wrongOwnerOutput.attempts[4]!.markerMatched = false;
    wrongOwnerOutput.attempts[4]!.protocolValid = false;
    expectIndeterminate(wrongOwnerOutput);
  });

  it("treats DNS/TCP/TLS-like transport failures, redirects, 404/410, and 5xx as indeterminate", () => {
    const transport = passInput();
    transport.attempts[3] = {
      ...rejectedStale(),
      statusCategory: "transport-error",
      unexpectedResponseObserved: false,
      handshakeStatusCode: null,
      terminal: "transport-error",
    };
    expectIndeterminate(transport);

    const timeout = passInput();
    timeout.attempts[3] = {
      ...rejectedStale(),
      statusCategory: "timeout",
      unexpectedResponseObserved: false,
      handshakeStatusCode: null,
      terminal: "timeout",
    };
    expectIndeterminate(timeout);

    for (const statusCode of [301, 404, 410, 429, 500, 503]) {
      const value = passInput();
      value.attempts[3] = {
        ...rejectedStale(),
        statusCategory: "other-http-response",
        handshakeStatusCode: statusCode,
      };
      expectIndeterminate(value);
    }

    const impossibleOpened401 = passInput();
    impossibleOpened401.attempts[3] = {
      ...positive("stale-s1-token-on-s2"),
      statusCategory: "auth-rejected",
      unexpectedResponseObserved: true,
      handshakeStatusCode: 401,
    };
    expectIndeterminate(impossibleOpened401);
  });

  it("rejects S1-marker, mixed, duplicate, nonexact, and protocol-error attack output", () => {
    const cases: Sbx055AssessmentInput[] = [];

    const s1Marker = candidateInput();
    s1Marker.attempts[3]!.markerMatched = false;
    s1Marker.attempts[3]!.crossMarkerAbsent = false;
    s1Marker.attempts[3]!.protocolValid = false;
    cases.push(s1Marker);

    const mixed = candidateInput();
    mixed.attempts[3]!.binaryFrames = 2;
    mixed.attempts[3]!.outputBytes = 90;
    mixed.attempts[3]!.protocolValid = false;
    cases.push(mixed);

    const duplicate = candidateInput();
    duplicate.attempts[3]!.textControlFrames = 2;
    duplicate.attempts[3]!.protocolValid = false;
    cases.push(duplicate);

    const nonexact = candidateInput();
    nonexact.attempts[3]!.outputBytes = 46;
    cases.push(nonexact);

    const protocolError = candidateInput();
    protocolError.attempts[3] = {
      ...positive("stale-s1-token-on-s2"),
      statusCategory: "protocol-error",
      protocolValid: false,
      terminal: "protocol-error",
    };
    cases.push(protocolError);

    for (const value of cases) expectIndeterminate(value);
  });

  it("binds the old issued URL/token to S1 while requiring the expected runtime to be S2", () => {
    const runtimeCollapsed = candidateInput();
    runtimeCollapsed.attempts[3]!.expectedRuntimeRole = "S1";
    expectIndeterminate(runtimeCollapsed);

    const issuedAsS2 = candidateInput();
    issuedAsS2.attempts[3]!.issuedUrlRole = "S2";
    issuedAsS2.attempts[3]!.tokenSourceSession = "S2";
    expectIndeterminate(issuedAsS2);

    const changedPair = candidateInput();
    changedPair.staleCredentialPairUsedUnchanged = false;
    expectIndeterminate(changedPair);
  });

  it("requires stop-snapshot-resume provenance and the captured S1 snapshot", () => {
    const sameSessionSummaryLie = candidateInput();
    sameSessionSummaryLie.lifecycle.distinctSessionIds = false;
    expectIndeterminate(sameSessionSummaryLie);

    const wrongSource = candidateInput();
    wrongSource.lifecycle.snapshotSourceSessionId = s2SessionId;
    expectIndeterminate(wrongSource);

    const wrongResumedSnapshot = candidateInput();
    wrongResumedSnapshot.readbacks[1].sourceSnapshotId = s2SnapshotId;
    wrongResumedSnapshot.readbacks[1].independentSourceSnapshotId = s2SnapshotId;
    expectIndeterminate(wrongResumedSnapshot);

    for (const field of ["stopAttempted", "stopped", "snapshotCaptured", "resumeAttempted",
      "resumedFromExactSnapshot", "resumeResponseExact", "sameNameResumed"] as const) {
      const value = candidateInput();
      value.lifecycle[field] = false;
      expectIndeterminate(value);
    }
  });

  it("requires M2 absence before stop, persisted M1, and exact post-resume mode-0600 M2", () => {
    for (const field of ["s1FixedCommandShape", "s1SessionUnchanged", "s1WrittenAfterCreate",
      "s1Mode0600", "s1LocalReadExactBeforeStop",
      "s2AbsentBeforeStop", "s1PersistedAfterResume", "s1Mode0600AfterResume",
      "s1LocalReadExactAfterResume", "s2FixedCommandShape", "s2SessionUnchanged",
      "s2WrittenOnlyAfterResume", "s2Mode0600",
      "s2LocalReadExactAfterResume", "distinctMarkerValues"] as const) {
      const value = candidateInput();
      value.markers[field] = false;
      expectIndeterminate(value);
    }

    const pathDrift = candidateInput();
    pathDrift.markers.s2Path = "/tmp/sbx-055/s2-wrong.marker";
    expectIndeterminate(pathDrift);

    const wrongFixtureSession = candidateInput();
    wrongFixtureSession.markers.s2FixtureSessionId = s1SessionId;
    expectIndeterminate(wrongFixtureSession);
  });

  it("requires missing/random 401/403 negatives and the exact S1 owner marker", () => {
    const missingTransport = candidateInput();
    missingTransport.attempts[0] = {
      ...negative("missing-token-negative"),
      statusCategory: "transport-error",
      unexpectedResponseObserved: false,
      handshakeStatusCode: null,
      terminal: "transport-error",
    };
    expectIndeterminate(missingTransport);

    const random404 = candidateInput();
    random404.attempts[1] = {
      ...negative("random-token-negative"),
      statusCategory: "other-http-response",
      handshakeStatusCode: 404,
    };
    expectIndeterminate(random404);

    const ownerWrong = candidateInput();
    ownerWrong.attempts[2]!.markerMatched = false;
    ownerWrong.attempts[2]!.protocolValid = false;
    expectIndeterminate(ownerWrong);
  });

  it("rejects reordered, overlapping, duplicate-window, or wrong-shape chronology", () => {
    const reordered = candidateInput();
    [reordered.chronology[4], reordered.chronology[5]] = [
      reordered.chronology[5]!,
      reordered.chronology[4]!,
    ];
    expectIndeterminate(reordered);

    const overlap = candidateInput();
    overlap.chronology[1]!.startedAt = overlap.chronology[0]!.startedAt;
    expectIndeterminate(overlap);

    const duplicateWindow = candidateInput();
    duplicateWindow.chronology[1]!.startedAt = duplicateWindow.chronology[0]!.startedAt;
    duplicateWindow.chronology[1]!.completedAt = duplicateWindow.chronology[0]!.completedAt;
    expectIndeterminate(duplicateWindow);

    const passUsingCandidateShape = passInput();
    passUsingCandidateShape.chronology = chronology();
    expectIndeterminate(passUsingCandidateShape);
  });

  it("requires fresh unused T1, exact use counts, ordered issuances, and no retries/extras", () => {
    const staleUsedEarly = candidateInput();
    staleUsedEarly.staleTokenUnusedBeforeAttack = false;
    expectIndeterminate(staleUsedEarly);

    const duplicateUse = candidateInput();
    (duplicateUse as unknown as { staleTokenUseCount: number }).staleTokenUseCount = 2;
    expectIndeterminate(duplicateUse);

    const swappedIssuance = candidateInput();
    [swappedIssuance.issuances[0], swappedIssuance.issuances[1]] = [
      swappedIssuance.issuances[1]!,
      swappedIssuance.issuances[0]!,
    ];
    expectIndeterminate(swappedIssuance);

    const retried = candidateInput();
    (retried.issuances[1] as unknown as { retryCount: number }).retryCount = 1;
    expectIndeterminate(retried);

    const extraAttempt = candidateInput();
    extraAttempt.attempts.push(positive("s2-owner-control"));
    expectIndeterminate(extraAttempt);

    const accountingLie = candidateInput();
    accountingLie.requestAudit.websocketConnections = 5;
    expectIndeterminate(accountingLie);
  });

  it("requires exact snapshot and sandbox deletion/absence plus journal and lock release", () => {
    const missingSnapshot = candidateInput();
    missingSnapshot.cleanup.snapshots = [snapshotCleanup("S2", s2SnapshotId)];
    missingSnapshot.cleanup.observedSnapshotCount = 1;
    expectIndeterminate(missingSnapshot);

    const duplicateSnapshot = candidateInput();
    duplicateSnapshot.cleanup.snapshots[0]!.snapshotId = s1SnapshotId;
    expectIndeterminate(duplicateSnapshot);

    const weakSnapshotAbsence = candidateInput();
    weakSnapshotAbsence.cleanup.snapshots[1]!.secondAbsence = false;
    expectIndeterminate(weakSnapshotAbsence);

    const partialSnapshotCount = candidateInput();
    partialSnapshotCount.cleanup.snapshots[1]!.absenceChecks = 1;
    expectIndeterminate(partialSnapshotCount);

    const weakSandboxAbsence = candidateInput();
    weakSandboxAbsence.cleanup.sandbox.thirdAbsence = false;
    expectIndeterminate(weakSandboxAbsence);

    const partialSandboxCount = candidateInput();
    partialSandboxCount.cleanup.sandbox.namedAbsenceChecks = 2;
    expectIndeterminate(partialSandboxCount);

    const unexpectedSnapshot = candidateInput();
    unexpectedSnapshot.cleanup.unexpectedSnapshots = 1;
    expectIndeterminate(unexpectedSnapshot);

    const prefixPresent = candidateInput();
    prefixPresent.cleanup.sandbox.prefixListAbsent = false;
    expectIndeterminate(prefixPresent);

    const journalRetained = candidateInput();
    journalRetained.cleanup.journalRemoved = false;
    expectIndeterminate(journalRetained);

    const lockRetained = candidateInput();
    lockRetained.cleanup.liveLockReleased = false;
    expectIndeterminate(lockRetained);

    const cleanupError = candidateInput();
    cleanupError.cleanup.sandbox.errors.push({ kind: "api", status: 500 });
    expectIndeterminate(cleanupError);
  });

  it("rejects every retention violation and recursively detects raw capabilities", () => {
    for (const field of ["rawInteractiveTokensRetained", "rawInteractiveTokenDigestsRetained",
      "rawInteractiveUrlsRetained", "rawInteractiveUrlDigestsRetained", "queryBearingUrlsRetained",
      "commandOutputRetained", "commandOutputDigestsRetained", "websocketErrorsRetained"] as const) {
      const value = candidateInput();
      (value as unknown as Record<string, unknown>)[field] = true;
      expectIndeterminate(value);
    }

    const marker = candidateInput();
    (marker.markers as unknown as { rawMarkersRetained: boolean }).rawMarkersRetained = true;
    expectIndeterminate(marker);

    const attempt = candidateInput();
    (attempt.attempts[3] as unknown as { rawTokenDigestRetained: boolean })
      .rawTokenDigestRetained = true;
    expectIndeterminate(attempt);

    const token = "transient-interactive-token";
    const markerValue = "transient-marker-value";
    expect(() => assertSbx055EvidenceHasNoRawCapabilities({ nested: token }, [token, markerValue]))
      .toThrow(/forbidden transient material/u);
    expect(() => assertSbx055EvidenceHasNoRawCapabilities({ nested: markerValue }, [token, markerValue]))
      .toThrow(/forbidden transient material/u);
    expect(() => assertSbx055EvidenceHasNoRawCapabilities({ url: "wss://example.vercel.run/x" }, []))
      .toThrow(/raw WebSocket capability/u);
    expect(() => assertSbx055EvidenceHasNoRawCapabilities({ url: "https://x.test/?token=y" }, []))
      .toThrow(/raw WebSocket capability/u);
    expect(() => assertSbx055EvidenceHasNoRawCapabilities(candidateInput(), [token, markerValue]))
      .not.toThrow();
  });
});
