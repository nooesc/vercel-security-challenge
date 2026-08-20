import {
  type Sbx055AttemptPurpose,
  type Sbx055InteractiveAttempt,
  type Sbx055Role,
} from "./protocol.js";
import {
  SBX055_SANDBOX_TIMEOUT_MS,
  SBX055_TEST_ID,
  SBX055_UUID,
  sbx055MarkerPath,
  sbx055SandboxName,
} from "./safety.js";

export { SBX055_TEST_ID };

const SESSION_ID = /^sbx_[A-Za-z0-9_-]{8,192}$/u;
const SNAPSHOT_ID = /^snap_[A-Za-z0-9_-]{8,192}$/u;

export type Sbx055ReadbackStage = "s1-pre-stop" | "s2-pre-attempt" | "s2-post-attempt";

export interface Sbx055SandboxReadback {
  stage: Sbx055ReadbackStage;
  role: Sbx055Role;
  name: string;
  independentName: string;
  listedName: string;
  activeSessionId: string;
  independentSessionId: string;
  listedSessionId: string;
  activeStatus: string;
  independentStatus: string;
  listedStatus: string;
  activeTagsExact: boolean;
  independentTagsExact: boolean;
  listedTagsExact: boolean;
  activePersistent: boolean;
  independentPersistent: boolean;
  listedPersistent: boolean;
  activeTimeoutMs: number;
  independentTimeoutMs: number;
  listedTimeoutMs: number;
  activeDenyAll: boolean;
  activeSessionDenyAll: boolean;
  independentDenyAll: boolean;
  independentSessionDenyAll: boolean;
  listedDenyAll: boolean;
  activeInteractivePort: number | null;
  independentInteractivePort: number | null;
  activeExactSingleInteractiveRoute: boolean;
  independentRouteCount: number;
  sourceSnapshotId: string | null;
  independentSourceSnapshotId: string | null;
  independentResumeFalse: boolean;
  listQueryExactNamePrefix: boolean;
  exactOneListedSandbox: boolean;
  listPaginationComplete: boolean;
}

export interface Sbx055LifecycleProof {
  sandboxName: string;
  s1SessionId: string;
  stopAttempted: boolean;
  stopped: boolean;
  snapshotCaptured: boolean;
  snapshotId: string;
  snapshotSourceSessionId: string;
  snapshotStatus: "created" | "failed" | "deleted";
  resumeAttempted: boolean;
  resumedFromExactSnapshot: boolean;
  resumeResponseExact: boolean;
  sameNameResumed: boolean;
  s2SessionId: string;
  distinctSessionIds: boolean;
}

export interface Sbx055MarkerProof {
  s1Path: string;
  s2Path: string;
  s1FixtureSessionId: string;
  s2FixtureSessionId: string;
  s1Length: number;
  s2Length: number;
  distinctMarkerValues: boolean;
  s1FixedCommandShape: boolean;
  s1SessionUnchanged: boolean;
  s1WrittenAfterCreate: boolean;
  s1Mode0600: boolean;
  s1LocalReadExactBeforeStop: boolean;
  s2AbsentBeforeStop: boolean;
  s1PersistedAfterResume: boolean;
  s1Mode0600AfterResume: boolean;
  s1LocalReadExactAfterResume: boolean;
  s2FixedCommandShape: boolean;
  s2SessionUnchanged: boolean;
  s2WrittenOnlyAfterResume: boolean;
  s2Mode0600: boolean;
  s2LocalReadExactAfterResume: boolean;
  rawMarkersRetained: false;
  rawMarkerDigestsRetained: false;
}

export type Sbx055IssuancePurpose =
  | "s1-owner-control"
  | "s1-fresh-stale"
  | "s2-owner-control";

export interface Sbx055CredentialIssuance {
  purpose: Sbx055IssuancePurpose;
  sourceRole: Sbx055Role;
  sourceSessionId: string;
  exactSourceSession: boolean;
  method: "POST";
  endpointFamily: "/v2/sandboxes/sessions/:sessionId/interactive";
  requestCount: 1;
  retryCount: 0;
  statusCode: 200;
  exactResponseShape: boolean;
  canonicalWssUrl: boolean;
  tokenStructurallyValid: boolean;
  responseBodyRetained: false;
  responseHeadersRetained: false;
  rawUrlRetained: false;
  rawUrlDigestRetained: false;
  queryBearingUrlRetained: false;
  rawTokenRetained: false;
  rawTokenDigestRetained: false;
}

export type Sbx055ChronologyStage =
  | "s1-readbacks"
  | "write-read-m1"
  | "issue-s1-owner-control"
  | "missing-token-negative"
  | "random-token-negative"
  | "s1-owner-control"
  | "issue-s1-fresh-stale"
  | "m2-absence-before-stop"
  | "stop-s1"
  | "snapshot-created"
  | "resume-s2"
  | "s2-pre-readbacks"
  | "verify-m1-persisted"
  | "write-read-m2"
  | "stale-s1-token-on-s2"
  | "issue-s2-owner-control"
  | "s2-owner-control"
  | "s2-post-readbacks"
  | "cleanup";

export interface Sbx055ChronologyStep {
  stage: Sbx055ChronologyStage;
  startedAt: string;
  completedAt: string;
}

export interface Sbx055SnapshotCleanup {
  snapshotId: string;
  sourceRole: Sbx055Role;
  sourceSessionId: string;
  exactProvenance: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  firstAbsence: boolean;
  secondAbsence: boolean;
  absenceChecks: number;
  errors: Array<{ kind: "api" | "other"; status?: number; code?: string; message?: string }>;
}

export interface Sbx055SandboxCleanup {
  attempted: boolean;
  exactProvenance: boolean;
  s2SessionIdKnown: boolean;
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  firstAbsence: boolean;
  secondAbsence: boolean;
  thirdAbsence: boolean;
  namedAbsenceChecks: number;
  prefixListAbsent: boolean;
  errors: Array<{ kind: "api" | "other"; status?: number; code?: string; message?: string }>;
}

export interface Sbx055CleanupProof {
  passed: boolean;
  sandbox: Sbx055SandboxCleanup;
  snapshotEnumerationComplete: boolean;
  snapshotListPaginationComplete: boolean;
  observedSnapshotCount: number;
  unexpectedSnapshots: number;
  snapshots: Sbx055SnapshotCleanup[];
  journalRemoved: boolean;
  liveLockReleased: boolean;
}

export interface Sbx055AssessmentInput {
  schemaVersion: 1;
  testId: typeof SBX055_TEST_ID;
  runId: string;
  sandboxName: string;
  scopeAndAliasPassed: boolean;
  installedWireAuditPassed: boolean;
  sameOwnerOnly: true;
  expectedTimeoutMs: typeof SBX055_SANDBOX_TIMEOUT_MS;
  lifecycle: Sbx055LifecycleProof;
  markers: Sbx055MarkerProof;
  readbacks: [Sbx055SandboxReadback, Sbx055SandboxReadback, Sbx055SandboxReadback];
  issuances: Sbx055CredentialIssuance[];
  attempts: Sbx055InteractiveAttempt[];
  chronology: Sbx055ChronologyStep[];
  allIssuedTokensDistinct: boolean;
  staleTokenUnusedBeforeAttack: boolean;
  staleCredentialPairUsedUnchanged: boolean;
  s1OwnerTokenUseCount: 1;
  staleTokenUseCount: 1;
  s2OwnerTokenUseCount: 0 | 1;
  requestAudit: {
    allAllowlisted: boolean;
    contiguous: boolean;
    completed: boolean;
    withinRateLimit: boolean;
    interactiveCredentialRequests: number;
    websocketConnections: number;
    unexpectedRequests: number;
  };
  cleanup: Sbx055CleanupProof;
  rawInteractiveTokensRetained: false;
  rawInteractiveTokenDigestsRetained: false;
  rawInteractiveUrlsRetained: false;
  rawInteractiveUrlDigestsRetained: false;
  queryBearingUrlsRetained: false;
  commandOutputRetained: false;
  commandOutputDigestsRetained: false;
  websocketErrorsRetained: false;
}

export interface Sbx055Assessment {
  verdict: "candidate" | "pass" | "indeterminate";
  candidate: boolean;
  controlsPassed: boolean;
  maximumDemonstratedImpact: "none" | "same-owner-stale-session-file-read";
  maximumSeverity: "none" | "medium";
  reportability: "none" | "program-clarification-required";
  summary: string;
}

function validTimestamp(value: string): number | undefined {
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value
    ? milliseconds
    : undefined;
}

function exactReadback(
  readback: Sbx055SandboxReadback,
  stage: Sbx055ReadbackStage,
  role: Sbx055Role,
  expectedName: string,
  expectedSessionId: string,
  expectedSourceSnapshotId: string | null,
): boolean {
  return readback.stage === stage && readback.role === role &&
    readback.name === expectedName && readback.independentName === expectedName &&
    readback.listedName === expectedName && SESSION_ID.test(expectedSessionId) &&
    readback.activeSessionId === expectedSessionId &&
    readback.independentSessionId === expectedSessionId &&
    readback.listedSessionId === expectedSessionId && readback.activeStatus === "running" &&
    readback.independentStatus === "running" && readback.listedStatus === "running" &&
    readback.activeTagsExact && readback.independentTagsExact && readback.listedTagsExact &&
    readback.activePersistent && readback.independentPersistent && readback.listedPersistent &&
    readback.activeTimeoutMs === SBX055_SANDBOX_TIMEOUT_MS &&
    readback.independentTimeoutMs === SBX055_SANDBOX_TIMEOUT_MS &&
    readback.listedTimeoutMs === SBX055_SANDBOX_TIMEOUT_MS && readback.activeDenyAll &&
    readback.activeSessionDenyAll && readback.independentDenyAll &&
    readback.independentSessionDenyAll && readback.listedDenyAll &&
    readback.activeInteractivePort !== null &&
    Number.isSafeInteger(readback.activeInteractivePort) && readback.activeInteractivePort >= 1 &&
    readback.activeInteractivePort <= 65_535 &&
    readback.independentInteractivePort === readback.activeInteractivePort &&
    readback.activeExactSingleInteractiveRoute && readback.independentRouteCount === 0 &&
    readback.sourceSnapshotId === expectedSourceSnapshotId &&
    readback.independentSourceSnapshotId === expectedSourceSnapshotId &&
    readback.independentResumeFalse && readback.listQueryExactNamePrefix &&
    readback.exactOneListedSandbox && readback.listPaginationComplete;
}

export function exactSbx055Readbacks(input: Sbx055AssessmentInput): boolean {
  if (!SBX055_UUID.test(input.runId) || input.sandboxName !== sbx055SandboxName(input.runId) ||
      !SESSION_ID.test(input.lifecycle.s1SessionId) || !SESSION_ID.test(input.lifecycle.s2SessionId) ||
      input.lifecycle.s1SessionId === input.lifecycle.s2SessionId ||
      !SNAPSHOT_ID.test(input.lifecycle.snapshotId)) return false;
  const [s1, s2Pre, s2Post] = input.readbacks;
  return exactReadback(s1, "s1-pre-stop", "S1", input.sandboxName,
    input.lifecycle.s1SessionId, null) &&
    exactReadback(s2Pre, "s2-pre-attempt", "S2", input.sandboxName,
      input.lifecycle.s2SessionId, input.lifecycle.snapshotId) &&
    exactReadback(s2Post, "s2-post-attempt", "S2", input.sandboxName,
      input.lifecycle.s2SessionId, input.lifecycle.snapshotId);
}

function exactLifecycle(input: Sbx055AssessmentInput): boolean {
  const value = input.lifecycle;
  return value.sandboxName === input.sandboxName && value.s1SessionId === input.readbacks[0].activeSessionId &&
    value.stopAttempted && value.stopped && value.snapshotCaptured &&
    SNAPSHOT_ID.test(value.snapshotId) && value.snapshotSourceSessionId === value.s1SessionId &&
    value.snapshotStatus === "created" && value.resumeAttempted && value.resumedFromExactSnapshot &&
    value.resumeResponseExact && value.sameNameResumed && value.s2SessionId === input.readbacks[1].activeSessionId &&
    value.s2SessionId === input.readbacks[2].activeSessionId && value.distinctSessionIds &&
    value.s1SessionId !== value.s2SessionId;
}

function exactMarkers(input: Sbx055AssessmentInput): boolean {
  const value = input.markers;
  return value.s1Path === sbx055MarkerPath("s1", input.runId) &&
    value.s2Path === sbx055MarkerPath("s2", input.runId) && value.s1Path !== value.s2Path &&
    value.s1FixtureSessionId === input.lifecycle.s1SessionId &&
    value.s2FixtureSessionId === input.lifecycle.s2SessionId &&
    value.s1Length >= 32 && value.s1Length <= 256 && value.s2Length >= 32 &&
    value.s2Length <= 256 && value.distinctMarkerValues && value.s1FixedCommandShape &&
    value.s1SessionUnchanged && value.s1WrittenAfterCreate &&
    value.s1Mode0600 && value.s1LocalReadExactBeforeStop && value.s2AbsentBeforeStop &&
    value.s1PersistedAfterResume && value.s1Mode0600AfterResume &&
    value.s1LocalReadExactAfterResume && value.s2FixedCommandShape && value.s2SessionUnchanged &&
    value.s2WrittenOnlyAfterResume && value.s2Mode0600 &&
    value.s2LocalReadExactAfterResume && value.rawMarkersRetained === false &&
    value.rawMarkerDigestsRetained === false;
}

function exactIssuance(
  value: Sbx055CredentialIssuance | undefined,
  purpose: Sbx055IssuancePurpose,
  role: Sbx055Role,
  sessionId: string,
): boolean {
  return value !== undefined && value.purpose === purpose && value.sourceRole === role &&
    value.sourceSessionId === sessionId && value.exactSourceSession && value.method === "POST" &&
    value.endpointFamily === "/v2/sandboxes/sessions/:sessionId/interactive" &&
    value.requestCount === 1 && value.retryCount === 0 && value.statusCode === 200 &&
    value.exactResponseShape && value.canonicalWssUrl && value.tokenStructurallyValid &&
    value.responseBodyRetained === false && value.responseHeadersRetained === false &&
    value.rawUrlRetained === false && value.rawUrlDigestRetained === false &&
    value.queryBearingUrlRetained === false &&
    value.rawTokenRetained === false && value.rawTokenDigestRetained === false;
}

function exactAttemptBase(
  value: Sbx055InteractiveAttempt | undefined,
  purpose: Sbx055AttemptPurpose,
): value is Sbx055InteractiveAttempt {
  return value !== undefined && value.purpose === purpose && value.requestCount === 1 &&
    value.retryCount === 0 && value.webSocketClient === "ws@8.21.0" &&
    value.handshakeResponseBodyRetained === false &&
    value.handshakeResponseHeadersRetained === false && value.rawOutputRetained === false &&
    value.rawMarkerRetained === false && value.rawTokenRetained === false &&
    value.rawTokenDigestRetained === false && value.queryBearingUrlRetained === false;
}

function exactNegative(
  value: Sbx055InteractiveAttempt | undefined,
  purpose: "missing-token-negative" | "random-token-negative",
): boolean {
  const tokenSource = purpose === "missing-token-negative" ? "none" : "random";
  return exactAttemptBase(value, purpose) && value.issuedUrlRole === "S1" &&
    value.tokenSourceSession === tokenSource && value.expectedRuntimeRole === "none" &&
    value.urlCredentialPurpose === "s1-owner-control" &&
    value.tokenCredentialPurpose === tokenSource && !value.opened && !value.openedExactIssuedUrl &&
    !value.authenticated && value.statusCategory === "auth-rejected" && !value.protocolValid &&
    !value.emptyNegotiatedProtocol && !value.emptyNegotiatedExtensions &&
    !value.startMessageExpected && value.startMessagesSent === 0 && value.exactStartMessage &&
    value.binaryFrames === 0 && value.textControlFrames === 0 && value.outputBytes === 0 &&
    !value.markerMatched && !value.crossMarkerAbsent && value.exitCode === null &&
    value.unexpectedResponseObserved &&
    (value.handshakeStatusCode === 401 || value.handshakeStatusCode === 403) &&
    value.terminal === "http-response-before-open";
}

function exactPositive(
  value: Sbx055InteractiveAttempt | undefined,
  purpose: "s1-owner-control" | "stale-s1-token-on-s2" | "s2-owner-control",
  issuedUrlRole: Sbx055Role,
  expectedRuntimeRole: Sbx055Role,
  credentialPurpose: Sbx055IssuancePurpose,
): boolean {
  return exactAttemptBase(value, purpose) && value.issuedUrlRole === issuedUrlRole &&
    value.tokenSourceSession === issuedUrlRole &&
    value.expectedRuntimeRole === expectedRuntimeRole &&
    value.urlCredentialPurpose === credentialPurpose &&
    value.tokenCredentialPurpose === credentialPurpose && value.opened &&
    value.authenticated && value.openedExactIssuedUrl && !value.unexpectedResponseObserved &&
    value.handshakeStatusCode === null && value.emptyNegotiatedProtocol &&
    value.emptyNegotiatedExtensions && value.startMessageExpected &&
    value.startMessagesSent === 1 && value.exactStartMessage && value.binaryFrames === 1 &&
    value.textControlFrames === 1 && value.outputBytes >= 32 && value.outputBytes <= 256 &&
    value.markerMatched && value.crossMarkerAbsent && value.exitCode === 0 && value.protocolValid &&
    value.statusCategory === "websocket-opened" && value.terminal === "closed-after-exit";
}

function exactStaleBinding(
  value: Sbx055InteractiveAttempt | undefined,
): value is Sbx055InteractiveAttempt {
  return exactAttemptBase(value, "stale-s1-token-on-s2") && value.issuedUrlRole === "S1" &&
    value.tokenSourceSession === "S1" && value.expectedRuntimeRole === "S2" &&
    value.urlCredentialPurpose === "s1-fresh-stale" &&
    value.tokenCredentialPurpose === "s1-fresh-stale" && value.startMessageExpected;
}

function exactStaleRejection(value: Sbx055InteractiveAttempt | undefined): boolean {
  return exactStaleBinding(value) && !value.opened && !value.openedExactIssuedUrl &&
    !value.authenticated && value.statusCategory === "auth-rejected" && !value.protocolValid &&
    !value.emptyNegotiatedProtocol && !value.emptyNegotiatedExtensions &&
    value.startMessagesSent === 0 && !value.exactStartMessage && value.binaryFrames === 0 &&
    value.textControlFrames === 0 && value.outputBytes === 0 && !value.markerMatched &&
    !value.crossMarkerAbsent && value.exitCode === null && value.unexpectedResponseObserved &&
    (value.handshakeStatusCode === 401 || value.handshakeStatusCode === 403) &&
    value.terminal === "http-response-before-open";
}

function chronologyStages(passShape: boolean): Sbx055ChronologyStage[] {
  return [
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
}

function exactChronology(value: readonly Sbx055ChronologyStep[], passShape: boolean): boolean {
  const expected = chronologyStages(passShape);
  if (!Array.isArray(value) || value.length !== expected.length ||
      value.some((step, index) => step.stage !== expected[index])) return false;
  let previous = -Infinity;
  const windows = new Set<string>();
  for (const step of value) {
    const startedAt = validTimestamp(step.startedAt);
    const completedAt = validTimestamp(step.completedAt);
    if (startedAt === undefined || completedAt === undefined || startedAt < previous ||
        completedAt < startedAt || !windows.add(`${step.startedAt}/${step.completedAt}`)) return false;
    previous = completedAt;
  }
  return true;
}

function exactSnapshotCleanup(
  value: Sbx055SnapshotCleanup,
  input: Sbx055AssessmentInput,
): boolean {
  const expectedSession = value.sourceRole === "S1"
    ? input.lifecycle.s1SessionId
    : input.lifecycle.s2SessionId;
  return SNAPSHOT_ID.test(value.snapshotId) && value.sourceSessionId === expectedSession &&
    value.exactProvenance && value.deleteAttempted && value.deleted && value.firstAbsence &&
    value.secondAbsence && value.absenceChecks === 2 && value.errors.length === 0;
}

function exactCleanup(input: Sbx055AssessmentInput): boolean {
  const value = input.cleanup;
  const sandbox = value.sandbox;
  const uniqueSnapshotIds = new Set(value.snapshots.map((entry) => entry.snapshotId));
  return value.passed && sandbox.attempted && sandbox.exactProvenance && sandbox.s2SessionIdKnown &&
    sandbox.stopAttempted && sandbox.stopped && sandbox.deleteAttempted && sandbox.deleted &&
    sandbox.firstAbsence && sandbox.secondAbsence && sandbox.thirdAbsence &&
    sandbox.namedAbsenceChecks === 3 && sandbox.prefixListAbsent && sandbox.errors.length === 0 &&
    value.snapshotEnumerationComplete && value.snapshotListPaginationComplete &&
    value.observedSnapshotCount === value.snapshots.length && value.unexpectedSnapshots === 0 &&
    value.snapshots.length >= 1 && value.snapshots.length <= 8 &&
    uniqueSnapshotIds.size === value.snapshots.length &&
    value.snapshots.some((entry) => entry.snapshotId === input.lifecycle.snapshotId &&
      entry.sourceRole === "S1" && entry.sourceSessionId === input.lifecycle.s1SessionId) &&
    value.snapshots.every((entry) => exactSnapshotCleanup(entry, input)) &&
    value.journalRemoved && value.liveLockReleased;
}

function baseControls(input: Sbx055AssessmentInput): boolean {
  const passShape = input.attempts.length === 5;
  const expectedIssuances = passShape ? 3 : 2;
  const expectedCredentialRequests = expectedIssuances;
  return input.schemaVersion === 1 && input.testId === SBX055_TEST_ID &&
    input.scopeAndAliasPassed && input.installedWireAuditPassed && input.sameOwnerOnly === true &&
    input.expectedTimeoutMs === SBX055_SANDBOX_TIMEOUT_MS && exactSbx055Readbacks(input) &&
    exactLifecycle(input) && exactMarkers(input) && input.issuances.length === expectedIssuances &&
    exactIssuance(input.issuances[0], "s1-owner-control", "S1", input.lifecycle.s1SessionId) &&
    exactIssuance(input.issuances[1], "s1-fresh-stale", "S1", input.lifecycle.s1SessionId) &&
    (!passShape || exactIssuance(input.issuances[2], "s2-owner-control", "S2",
      input.lifecycle.s2SessionId)) &&
    (input.attempts.length === 4 || input.attempts.length === 5) &&
    exactNegative(input.attempts[0], "missing-token-negative") &&
    exactNegative(input.attempts[1], "random-token-negative") &&
    exactPositive(input.attempts[2], "s1-owner-control", "S1", "S1", "s1-owner-control") &&
    exactStaleBinding(input.attempts[3]) &&
    (!passShape || exactAttemptBase(input.attempts[4], "s2-owner-control")) &&
    input.attempts[2]?.outputBytes === input.markers.s1Length &&
    input.allIssuedTokensDistinct && input.staleTokenUnusedBeforeAttack &&
    input.staleCredentialPairUsedUnchanged && input.s1OwnerTokenUseCount === 1 &&
    input.staleTokenUseCount === 1 && input.s2OwnerTokenUseCount === (passShape ? 1 : 0) &&
    exactChronology(input.chronology, passShape) && input.requestAudit.allAllowlisted &&
    input.requestAudit.contiguous && input.requestAudit.completed && input.requestAudit.withinRateLimit &&
    input.requestAudit.interactiveCredentialRequests === expectedCredentialRequests &&
    input.requestAudit.websocketConnections === input.attempts.length &&
    input.requestAudit.unexpectedRequests === 0 && exactCleanup(input) &&
    input.rawInteractiveTokensRetained === false &&
    input.rawInteractiveTokenDigestsRetained === false && input.rawInteractiveUrlsRetained === false &&
    input.rawInteractiveUrlDigestsRetained === false && input.queryBearingUrlsRetained === false &&
    input.commandOutputRetained === false && input.commandOutputDigestsRetained === false &&
    input.websocketErrorsRetained === false;
}

export function assessSbx055(input: Sbx055AssessmentInput): Sbx055Assessment {
  if (!baseControls(input)) {
    return {
      verdict: "indeterminate",
      candidate: false,
      controlsPassed: false,
      maximumDemonstratedImpact: "none",
      maximumSeverity: "none",
      reportability: "none",
      summary: "A required identity, lifecycle, marker, protocol, chronology, retention, or cleanup control failed.",
    };
  }

  const stale = input.attempts[3];
  if (input.attempts.length === 4 && input.issuances.length === 2 &&
      input.s2OwnerTokenUseCount === 0 &&
      exactPositive(stale, "stale-s1-token-on-s2", "S1", "S2", "s1-fresh-stale") &&
      stale?.outputBytes === input.markers.s2Length) {
    return {
      verdict: "candidate",
      candidate: true,
      controlsPassed: true,
      maximumDemonstratedImpact: "same-owner-stale-session-file-read",
      maximumSeverity: "medium",
      reportability: "program-clarification-required",
      summary: "The unused S1 interactive capability survived stop/snapshot/resume and read the exact M2 file created only in distinct session S2; impact is same-owner and clarification-gated.",
    };
  }

  if (input.attempts.length === 5 && input.issuances.length === 3 &&
      input.s2OwnerTokenUseCount === 1 && exactStaleRejection(stale) &&
      exactPositive(input.attempts[4], "s2-owner-control", "S2", "S2", "s2-owner-control") &&
      input.attempts[4]?.outputBytes === input.markers.s2Length) {
    return {
      verdict: "pass",
      candidate: false,
      controlsPassed: true,
      maximumDemonstratedImpact: "none",
      maximumSeverity: "none",
      reportability: "none",
      summary: "The exact stale S1 capability returned 401/403 after resume, then a fresh S2 capability read the exact M2 owner-control file.",
    };
  }

  return {
    verdict: "indeterminate",
    candidate: false,
    controlsPassed: true,
    maximumDemonstratedImpact: "none",
    maximumSeverity: "none",
    reportability: "none",
    summary: "The stale-capability attempt was neither an exact M2 read nor an exact 401/403 followed by a validated fresh-S2 owner control.",
  };
}

export function assertSbx055EvidenceHasNoRawCapabilities(
  value: unknown,
  forbidden: readonly string[],
): void {
  const serialized = JSON.stringify(value);
  for (const secret of forbidden) {
    if (secret.length > 0 && serialized.includes(secret)) {
      throw new Error("SBX-055 durable evidence contained forbidden transient material");
    }
  }
  if (/wss:\/\/|[?&]token=/iu.test(serialized)) {
    throw new Error("SBX-055 durable evidence contained a raw WebSocket capability");
  }
}
