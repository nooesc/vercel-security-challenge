import {
  type Sbx051AttemptPurpose,
  type Sbx051InteractiveAttempt,
  type Sbx051Role,
} from "./protocol.js";
import { SBX051_TEST_ID } from "./safety.js";

export interface Sbx051SandboxReadback {
  role: Sbx051Role;
  name: string;
  markerPath: string;
  otherMarkerPath: string;
  otherMarkerAbsent: boolean;
  activeSessionId: string;
  independentSessionId: string;
  activeStatus: string;
  independentStatus: string;
  exactName: boolean;
  exactTags: boolean;
  independentTags: boolean;
  nonpersistent: boolean;
  independentNonpersistent: boolean;
  sandboxDenyAll: boolean;
  sessionDenyAll: boolean;
  independentSandboxDenyAll: boolean;
  independentSessionDenyAll: boolean;
  interactivePort: number | null;
  independentInteractivePort: number | null;
  exactSingleInteractiveRoute: boolean;
  independentRouteCount: number;
  ownerMarkerExact: boolean;
  markerMode0600: boolean;
  markerLength: number;
  rawMarkerRetained: false;
  rawMarkerDigestRetained: false;
}

export interface Sbx051CredentialIssuance {
  purpose: "a-owner-control" | "b-owner-control" | "a-attack" | "b-attack-target";
  sourceRole: Sbx051Role;
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
  queryBearingUrlRetained: false;
  rawTokenRetained: false;
  rawTokenDigestRetained: false;
}

export interface Sbx051CleanupResource {
  role: Sbx051Role;
  attempted: boolean;
  sessionIdKnownAtCleanup: boolean;
  exactProvenance: boolean;
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  firstAbsence: boolean;
  secondAbsence: boolean;
  namedAbsenceChecks: 0 | 2;
  absenceDelayMs: 0 | 750 | 2_000;
  errors: Array<{ kind: "api" | "other"; status?: number; code?: string; message?: string }>;
}

export interface Sbx051AssessmentInput {
  schemaVersion: 1;
  testId: typeof SBX051_TEST_ID;
  scopeAndAliasPassed: boolean;
  installedWireAuditPassed: boolean;
  distinctSandboxNames: boolean;
  distinctSessionIds: boolean;
  distinctMarkerPaths: boolean;
  distinctMarkerValues: boolean;
  distinctReturnedUrlBindings: boolean;
  allIssuedTokensDistinct: boolean;
  attackTokenIssuedFreshAndUsedOnce: boolean;
  bTargetTokenUseCount: 0 | 1;
  chronology: Sbx051Chronology;
  preAttackReadbacks: [Sbx051SandboxReadback, Sbx051SandboxReadback];
  postAttackReadbacks: [Sbx051SandboxReadback, Sbx051SandboxReadback];
  issuances: Sbx051CredentialIssuance[];
  attempts: Sbx051InteractiveAttempt[];
  requestAudit: {
    allAllowlisted: boolean;
    contiguous: boolean;
    completed: boolean;
    withinRateLimit: boolean;
    rawInteractiveCredentialRequests: number;
    websocketConnections: number;
    unexpectedRequests: number;
    bindingOperations: string[];
  };
  cleanup: {
    passed: boolean;
    resources: Sbx051CleanupResource[];
  };
  rawMarkersRetained: false;
  rawMarkerDigestsRetained: false;
  rawInteractiveTokensRetained: false;
  rawInteractiveTokenDigestsRetained: false;
  queryBearingUrlsRetained: false;
  commandOutputRetained: false;
  websocketErrorsRetained: false;
}

export interface Sbx051ChronologyStep {
  stage:
    | "issue-a-owner-control"
    | "issue-b-owner-control"
    | "missing-token-negative"
    | "random-token-negative"
    | "a-owner-control"
    | "b-owner-control"
    | "issue-a-attack"
    | "issue-b-attack-target"
    | "a-token-b-attack"
    | "b-target-validation";
  startedAt: string;
  completedAt: string;
}

export interface Sbx051Chronology {
  preReadbacksCompletedAt: string;
  steps: Sbx051ChronologyStep[];
  postReadbacksStartedAt: string;
  postReadbacksCompletedAt: string;
  cleanupStartedAt: string;
  cleanupCompletedAt: string;
}

export interface Sbx051Assessment {
  verdict: "candidate" | "pass" | "indeterminate";
  candidate: boolean;
  controlsPassed: boolean;
  maximumDemonstratedImpact: "none" | "same-owner-cross-sandbox-file-read";
  reportability: "none" | "program-clarification-required";
  summary: string;
}

function exactReadback(readback: Sbx051SandboxReadback, role: Sbx051Role): boolean {
  const markerRole = role.toLowerCase();
  const markerPattern = new RegExp(
    `^/tmp/sbx-051/${markerRole}-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\.marker$`,
    "u",
  );
  return readback.role === role && readback.activeSessionId === readback.independentSessionId &&
    markerPattern.test(readback.markerPath) && readback.otherMarkerPath !== readback.markerPath &&
    readback.otherMarkerAbsent &&
    readback.activeStatus === "running" && readback.independentStatus === "running" &&
    readback.exactName && readback.exactTags && readback.independentTags &&
    readback.nonpersistent && readback.independentNonpersistent && readback.sandboxDenyAll &&
    readback.sessionDenyAll && readback.independentSandboxDenyAll &&
    readback.independentSessionDenyAll && readback.interactivePort !== null &&
    readback.interactivePort === readback.independentInteractivePort &&
    Number.isSafeInteger(readback.interactivePort) && readback.interactivePort >= 1 &&
    readback.interactivePort <= 65_535 && readback.exactSingleInteractiveRoute &&
    readback.independentRouteCount === 0 && readback.ownerMarkerExact &&
    readback.markerMode0600 && readback.markerLength >= 32 && readback.markerLength <= 256 &&
    readback.rawMarkerRetained === false && readback.rawMarkerDigestRetained === false;
}

export function exactSbx051ReadbackPair(
  readbacks: readonly [Sbx051SandboxReadback, Sbx051SandboxReadback],
): boolean {
  const [a, b] = readbacks;
  return exactReadback(a, "A") && exactReadback(b, "B") && a.name !== b.name &&
    a.activeSessionId !== b.activeSessionId && a.markerPath !== b.markerPath &&
    a.otherMarkerPath === b.markerPath && b.otherMarkerPath === a.markerPath;
}

function exactIssuance(
  issuance: Sbx051CredentialIssuance | undefined,
  purpose: Sbx051CredentialIssuance["purpose"],
  role: Sbx051Role,
): boolean {
  return issuance !== undefined && issuance.purpose === purpose && issuance.sourceRole === role &&
    issuance.exactSourceSession && issuance.method === "POST" &&
    issuance.endpointFamily === "/v2/sandboxes/sessions/:sessionId/interactive" &&
    issuance.requestCount === 1 && issuance.retryCount === 0 && issuance.statusCode === 200 &&
    issuance.exactResponseShape && issuance.canonicalWssUrl && issuance.tokenStructurallyValid &&
    issuance.responseBodyRetained === false && issuance.responseHeadersRetained === false &&
    issuance.rawUrlRetained === false && issuance.queryBearingUrlRetained === false &&
    issuance.rawTokenRetained === false && issuance.rawTokenDigestRetained === false;
}

function exactAttemptBase(
  attempt: Sbx051InteractiveAttempt | undefined,
  purpose: Sbx051AttemptPurpose,
): attempt is Sbx051InteractiveAttempt {
  return attempt !== undefined && attempt.purpose === purpose && attempt.requestCount === 1 &&
    attempt.retryCount === 0 && attempt.webSocketClient === "ws@8.21.0" &&
    attempt.handshakeResponseBodyRetained === false &&
    attempt.handshakeResponseHeadersRetained === false && attempt.rawOutputRetained === false &&
    attempt.rawMarkerRetained === false && attempt.rawTokenRetained === false &&
    attempt.rawTokenDigestRetained === false && attempt.queryBearingUrlRetained === false;
}

function exactRejectedNegative(
  attempt: Sbx051InteractiveAttempt | undefined,
  purpose: "missing-token-negative" | "random-token-negative",
  tokenSource: "none" | "random",
): boolean {
  const expectedTokenCredential = purpose === "missing-token-negative" ? "none" : "random";
  return exactAttemptBase(attempt, purpose) && attempt.urlRole === "B" &&
    attempt.tokenSource === tokenSource && !attempt.opened && !attempt.openedExactIssuedUrl &&
    attempt.urlCredentialPurpose === "b-owner-control" &&
    attempt.tokenCredentialPurpose === expectedTokenCredential &&
    !attempt.emptyNegotiatedProtocol && !attempt.emptyNegotiatedExtensions &&
    !attempt.startMessageExpected && attempt.startMessagesSent === 0 && attempt.exactStartMessage &&
    attempt.binaryFrames === 0 && attempt.textControlFrames === 0 && attempt.outputBytes === 0 &&
    !attempt.exactExpectedMarker && !attempt.exactUnexpectedMarker && attempt.exitCode === null &&
    attempt.unexpectedResponseObserved &&
    (attempt.handshakeStatusCode === 401 || attempt.handshakeStatusCode === 403) &&
    attempt.terminal === "http-response-before-open";
}

function exactPositive(
  attempt: Sbx051InteractiveAttempt | undefined,
  purpose: "a-owner-control" | "b-owner-control" | "a-token-b-attack" | "b-target-validation",
  urlRole: Sbx051Role,
  tokenSource: Sbx051Role,
): boolean {
  const expectedUrlCredential = purpose === "a-owner-control"
    ? "a-owner-control"
    : purpose === "b-owner-control" ? "b-owner-control" : "b-attack-target";
  const expectedTokenCredential = purpose === "a-owner-control"
    ? "a-owner-control"
    : purpose === "b-owner-control" ? "b-owner-control"
      : purpose === "b-target-validation" ? "b-attack-target" : "a-attack";
  return exactAttemptBase(attempt, purpose) && attempt.urlRole === urlRole &&
    attempt.tokenSource === tokenSource && attempt.opened && attempt.openedExactIssuedUrl &&
    attempt.urlCredentialPurpose === expectedUrlCredential &&
    attempt.tokenCredentialPurpose === expectedTokenCredential &&
    !attempt.unexpectedResponseObserved && attempt.handshakeStatusCode === null &&
    attempt.emptyNegotiatedProtocol && attempt.emptyNegotiatedExtensions &&
    attempt.startMessageExpected && attempt.startMessagesSent === 1 && attempt.exactStartMessage &&
    attempt.binaryFrames >= 1 && attempt.binaryFrames <= 16 && attempt.textControlFrames === 1 &&
    attempt.outputBytes >= 32 && attempt.outputBytes <= 256 && attempt.exactExpectedMarker &&
    !attempt.exactUnexpectedMarker && attempt.exitCode === 0 &&
    attempt.terminal === "closed-after-exit";
}

function exactAttackHttpRejection(attempt: Sbx051InteractiveAttempt | undefined): boolean {
  return exactAttemptBase(attempt, "a-token-b-attack") && attempt.urlRole === "B" &&
    attempt.tokenSource === "A" && attempt.urlCredentialPurpose === "b-attack-target" &&
    attempt.tokenCredentialPurpose === "a-attack" && !attempt.opened &&
    !attempt.openedExactIssuedUrl && !attempt.emptyNegotiatedProtocol &&
    !attempt.emptyNegotiatedExtensions && attempt.startMessageExpected &&
    attempt.startMessagesSent === 0 && !attempt.exactStartMessage && attempt.binaryFrames === 0 &&
    attempt.textControlFrames === 0 && attempt.outputBytes === 0 &&
    !attempt.exactExpectedMarker && !attempt.exactUnexpectedMarker && attempt.exitCode === null &&
    attempt.unexpectedResponseObserved &&
    (attempt.handshakeStatusCode === 401 || attempt.handshakeStatusCode === 403) &&
    attempt.terminal === "http-response-before-open";
}

function timestamp(value: string): number | undefined {
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value
    ? milliseconds
    : undefined;
}

function exactChronology(value: Sbx051Chronology | undefined, targetValidation: boolean): boolean {
  const expectedStages: Sbx051ChronologyStep["stage"][] = [
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
  if (value === undefined || value === null || typeof value !== "object" ||
      !Array.isArray(value.steps) || value.steps.length !== expectedStages.length ||
      value.steps.some((step, index) => step.stage !== expectedStages[index])) return false;
  const pre = timestamp(value.preReadbacksCompletedAt);
  const postStart = timestamp(value.postReadbacksStartedAt);
  const postEnd = timestamp(value.postReadbacksCompletedAt);
  const cleanupStart = timestamp(value.cleanupStartedAt);
  const cleanupEnd = timestamp(value.cleanupCompletedAt);
  if (pre === undefined || postStart === undefined || postEnd === undefined ||
      cleanupStart === undefined || cleanupEnd === undefined) return false;
  let previous = pre;
  const windows = new Set<string>();
  for (const step of value.steps) {
    const started = timestamp(step.startedAt);
    const completed = timestamp(step.completedAt);
    if (started === undefined || completed === undefined || started < previous || completed < started) return false;
    if (step.stage.startsWith("issue-") && !windows.add(`${step.startedAt}/${step.completedAt}`)) return false;
    previous = completed;
  }
  return postStart >= previous && postEnd >= postStart && cleanupStart >= postEnd &&
    cleanupEnd >= cleanupStart;
}

function baseControls(input: Sbx051AssessmentInput): boolean {
  const [preA, preB] = input.preAttackReadbacks;
  const [postA, postB] = input.postAttackReadbacks;
  const cleanupRoles = input.cleanup.resources.map((entry) => entry.role).join("");
  const aOwnerAttempt = input.attempts[2];
  const bOwnerAttempt = input.attempts[3];
  const targetValidation = input.attempts.length === 6;
  const expectedBindingOperations = [
    "interactive-A",
    "interactive-B",
    "websocket-missing-token-negative",
    "websocket-random-token-negative",
    "websocket-a-owner-control",
    "websocket-b-owner-control",
    "interactive-A",
    "interactive-B",
    "websocket-a-token-b-attack",
    ...(targetValidation ? ["websocket-b-target-validation"] : []),
  ];
  return input.schemaVersion === 1 && input.testId === SBX051_TEST_ID &&
    input.scopeAndAliasPassed && input.installedWireAuditPassed && input.distinctSandboxNames &&
    input.distinctSessionIds && input.distinctMarkerPaths && input.distinctMarkerValues &&
    input.distinctReturnedUrlBindings && input.allIssuedTokensDistinct &&
    input.attackTokenIssuedFreshAndUsedOnce &&
    input.bTargetTokenUseCount === (targetValidation ? 1 : 0) &&
    exactChronology(input.chronology, targetValidation) &&
    exactSbx051ReadbackPair(input.preAttackReadbacks) &&
    exactSbx051ReadbackPair(input.postAttackReadbacks) &&
    preA.name === postA.name && preB.name === postB.name &&
    preA.markerPath === postA.markerPath && preB.markerPath === postB.markerPath &&
    preA.activeSessionId === postA.activeSessionId && preB.activeSessionId === postB.activeSessionId &&
    preA.markerLength === postA.markerLength && preB.markerLength === postB.markerLength &&
    input.issuances.length === 4 &&
    exactIssuance(input.issuances[0], "a-owner-control", "A") &&
    exactIssuance(input.issuances[1], "b-owner-control", "B") &&
    exactIssuance(input.issuances[2], "a-attack", "A") &&
    exactIssuance(input.issuances[3], "b-attack-target", "B") &&
    (input.attempts.length === 5 || input.attempts.length === 6) &&
    exactRejectedNegative(input.attempts[0], "missing-token-negative", "none") &&
    exactRejectedNegative(input.attempts[1], "random-token-negative", "random") &&
    exactPositive(input.attempts[2], "a-owner-control", "A", "A") &&
    exactPositive(input.attempts[3], "b-owner-control", "B", "B") &&
    (!targetValidation || exactAttemptBase(input.attempts[5], "b-target-validation")) &&
    aOwnerAttempt?.outputBytes === preA.markerLength &&
    bOwnerAttempt?.outputBytes === preB.markerLength &&
    input.requestAudit.allAllowlisted && input.requestAudit.contiguous &&
    input.requestAudit.completed && input.requestAudit.withinRateLimit &&
    input.requestAudit.rawInteractiveCredentialRequests === 4 &&
    input.requestAudit.websocketConnections === input.attempts.length &&
    input.requestAudit.unexpectedRequests === 0 &&
    Array.isArray(input.requestAudit.bindingOperations) &&
    input.requestAudit.bindingOperations.length === expectedBindingOperations.length &&
    input.requestAudit.bindingOperations.every((operation, index) =>
      operation === expectedBindingOperations[index]) &&
    input.cleanup.passed && input.cleanup.resources.length === 2 && cleanupRoles === "BA" &&
    input.cleanup.resources.every((entry) => entry.attempted && entry.exactProvenance &&
      entry.sessionIdKnownAtCleanup && entry.namedAbsenceChecks === 2 &&
      entry.absenceDelayMs === 750 &&
      entry.stopAttempted && entry.stopped && entry.deleteAttempted && entry.deleted &&
      entry.firstAbsence && entry.secondAbsence && entry.errors.length === 0) &&
    input.rawMarkersRetained === false && input.rawMarkerDigestsRetained === false &&
    input.rawInteractiveTokensRetained === false &&
    input.rawInteractiveTokenDigestsRetained === false &&
    input.queryBearingUrlsRetained === false && input.commandOutputRetained === false &&
    input.websocketErrorsRetained === false;
}

export function assessSbx051(input: Sbx051AssessmentInput): Sbx051Assessment {
  if (!baseControls(input)) {
    return {
      verdict: "indeterminate",
      candidate: false,
      controlsPassed: false,
      maximumDemonstratedImpact: "none",
      reportability: "none",
      summary: "A required scope, provenance, token-isolation, negative, owner, rate, retention, or cleanup control failed.",
    };
  }
  const attack = input.attempts[4];
  if (input.attempts.length === 5 && input.bTargetTokenUseCount === 0 && attack !== undefined &&
      exactPositive(attack, "a-token-b-attack", "B", "A") &&
      attack.outputBytes === input.preAttackReadbacks[1].markerLength &&
      attack.outputBytes === input.postAttackReadbacks[1].markerLength) {
    return {
      verdict: "candidate",
      candidate: true,
      controlsPassed: true,
      maximumDemonstratedImpact: "same-owner-cross-sandbox-file-read",
      reportability: "program-clarification-required",
      summary: "Under same-owner conditions, a fresh A-issued token was accepted at a fresh B target URL and returned B's exact marker; reportability requires program clarification.",
    };
  }
  const validation = input.attempts[5];
  if (input.attempts.length === 6 && input.bTargetTokenUseCount === 1 &&
      exactAttackHttpRejection(attack) &&
      exactPositive(validation, "b-target-validation", "B", "B") &&
      validation!.outputBytes === input.preAttackReadbacks[1].markerLength &&
      validation!.outputBytes === input.postAttackReadbacks[1].markerLength) {
    return {
      verdict: "pass",
      candidate: false,
      controlsPassed: true,
      maximumDemonstratedImpact: "none",
      reportability: "none",
      summary: "The exact B target returned 401/403 for the fresh A token, then returned B's exact marker with its own fresh B token.",
    };
  }
  return {
    verdict: "indeterminate",
    candidate: false,
    controlsPassed: true,
    maximumDemonstratedImpact: "none",
    reportability: "none",
    summary: "The cross-session attempt neither proved same-owner token interchangeability nor a validated exact 401/403 rejection.",
  };
}

export function assertSbx051EvidenceHasNoRawCapabilities(
  value: unknown,
  forbidden: readonly string[],
): void {
  const serialized = JSON.stringify(value);
  for (const secret of forbidden) {
    if (secret.length > 0 && serialized.includes(secret)) {
      throw new Error("SBX-051 durable evidence contained forbidden transient material");
    }
  }
  if (/[?&]token=|wss:\/\//iu.test(serialized)) {
    throw new Error("SBX-051 durable evidence contained a token-bearing or raw WebSocket URL");
  }
}
