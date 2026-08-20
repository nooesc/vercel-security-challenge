import { createHmac } from "node:crypto";

export const SBX046_TEST_ID = "SBX-046" as const;
export const SBX046_PORT = 3_000 as const;
export const SBX046_CANARY_PATH = "/v1/sbx046/canary" as const;

export const SBX046_CASE_IDS = [
  "local-pre",
  "external-pre",
  "local-post-readback",
  "external-post-5s",
  "external-post-30s",
  "external-post-90s",
  "local-post-final",
] as const;

export type Sbx046CaseId = typeof SBX046_CASE_IDS[number];
export type Sbx046PostCaseId = Extract<Sbx046CaseId,
  "external-post-5s" | "external-post-30s" | "external-post-90s">;
export type Sbx046Verdict = "candidate-low" | "pass" | "indeterminate" | "error";
export type Sbx046PostClassification = "exact-reach" | "conclusive-denial" | "ambiguous";

export interface Sbx046RouteData {
  url: string;
  subdomain: string;
  port: number;
}

export interface Sbx046CreationEvidence {
  attempts: number;
  requestedAt: string;
  createdAt: string;
  completedAt: string;
  sandboxName: string;
  sessionId: string;
  persistent: boolean;
  status: string;
  tags: Record<string, string>;
  routes: Sbx046RouteData[];
  sourceSnapshotId: string | null;
}

export type Sbx046ReadbackStage = "initial" | "post-update" | "final";
export type Sbx046ReadbackSource = "active" | "independent";

export interface Sbx046RouteReadback {
  stage: Sbx046ReadbackStage;
  source: Sbx046ReadbackSource;
  observedAt: string;
  sandboxName: string;
  sessionId: string;
  persistent: boolean;
  status: string;
  tags: Record<string, string>;
  routes: Sbx046RouteData[];
  domainPort: number;
  domainValue: string | null;
  domainLookupThrew: boolean;
}

export interface Sbx046ReadbackPair {
  active: Sbx046RouteReadback;
  independent: Sbx046RouteReadback;
}

export interface Sbx046UpdateEvidence {
  method: "Sandbox.update";
  attempts: number;
  requestedPorts: number[];
  requestedAt: string;
  acknowledgedAt: string;
  acknowledged: boolean;
  sandboxName: string;
  sessionIdBefore: string;
  sessionIdAfter: string;
  responseRoutes: Sbx046RouteData[];
}

export interface Sbx046ServiceResponseEvidence {
  schemaVersion: 1;
  testId: string;
  runId: string;
  caseId: string;
  sandboxName: string;
  sessionId: string;
  port: number;
  serviceInstanceId: string;
  challenge: string;
  operationId: string;
  requestBodyValidated: boolean;
  ok: boolean;
}

export interface Sbx046TransportError {
  code: string;
  syscall: string;
  errno?: number;
}

export interface Sbx046ProbeEvidence {
  schemaVersion: 1;
  testId: string;
  runId: string;
  caseId: Sbx046CaseId;
  origin: "loopback" | "saved-public-route";
  sandboxName: string;
  sessionId: string;
  port: number;
  serviceInstanceId: string;
  challenge: string;
  expectedOperationId: string;
  requestMethod: "POST";
  requestPath: string;
  requestOrigin: string;
  startedAt: string;
  completedAt: string;
  elapsedSinceRevocationAckMs: number | null;
  requestAttempts: number;
  connectionAttempts: number;
  actualRequests: number;
  retries: number;
  redirectsFollowed: number;
  freshConnection: boolean;
  strictTlsVerification: boolean;
  proxyConfigurationAccepted: boolean;
  tlsTrustConfigurationAccepted: boolean;
  rawConfigurationRetained: boolean;
  tcpConnected: boolean;
  tlsEstablished: boolean;
  tlsAuthorized: boolean;
  responseReceived: boolean;
  responseStatusCode?: number;
  responseBytes?: number;
  serviceHeaderValidated?: boolean;
  cacheControlValidated?: boolean;
  connectionCloseValidated?: boolean;
  contentTypeValidated?: boolean;
  contentLengthValidated?: boolean;
  serviceResponse?: Sbx046ServiceResponseEvidence;
  timedOut: boolean;
  error?: Sbx046TransportError;
  durationMs: number;
  rawRequestBodyRetained: boolean;
  rawResponseBodyRetained: boolean;
}

export interface Sbx046LedgerEvent {
  schemaVersion: 1;
  testId: string;
  runId: string;
  sandboxName: string;
  sessionId: string;
  port: number;
  serviceInstanceId: string;
  caseId: Sbx046CaseId;
  challenge: string;
  operationId: string;
  observedAt: string;
  method: "POST";
  path: string;
  requestBodyValidated: boolean;
  rawHmacKeyRetained: boolean;
  rawRequestBodyRetained: boolean;
  derivedDigestRetained: boolean;
}

export interface Sbx046LedgerEvidence {
  configured: boolean;
  events: Sbx046LedgerEvent[];
  rawHmacKeyRetained: boolean;
  hmacKeyDigestRetained: boolean;
  rawLogRetained: boolean;
}

export interface Sbx046CleanupEvidence {
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  absenceChecks: number;
  exactNameAbsent: boolean;
  prefixListAbsent: boolean;
  guestConfigDeleted: boolean;
  guestLedgerDeleted: boolean;
  errors: string[];
}

export interface Sbx046StorageEvidence {
  guestConfigMode: number;
  guestLedgerMode: number;
  artifactMode: number;
  liveLockMode: number;
  liveLockReleased: boolean;
  rawHmacKeyRetained: boolean;
  hmacKeyDigestRetained: boolean;
  rawRequestBodyRetained: boolean;
  rawResponseBodyRetained: boolean;
}

export interface Sbx046ExpectedMaterial {
  runId: string;
  sandboxName: string;
  sessionId: string;
  tags: Record<string, string>;
  route: Sbx046RouteData;
  serviceInstanceId: string;
  challenges: Record<Sbx046CaseId, string>;
  operationIds: Record<Sbx046CaseId, string>;
}

export interface Sbx046AssessmentInput {
  executionError?: string;
  identityAndScopePassed: boolean;
  expected: Sbx046ExpectedMaterial;
  creation: Sbx046CreationEvidence;
  initialReadbacks: Sbx046ReadbackPair;
  update: Sbx046UpdateEvidence;
  postUpdateReadbacks: Sbx046ReadbackPair;
  finalReadbacks: Sbx046ReadbackPair;
  probes: Record<Sbx046CaseId, Sbx046ProbeEvidence>;
  ledger: Sbx046LedgerEvidence;
  cleanup: Sbx046CleanupEvidence;
  storage: Sbx046StorageEvidence;
}

export interface Sbx046Assessment {
  verdict: Sbx046Verdict;
  severity: "low" | "none" | "unknown";
  candidate: boolean;
  controlsPassed: boolean;
  sustainedRevocationFailure: boolean;
  postProbeClassifications: Record<Sbx046PostCaseId, Sbx046PostClassification>;
  summary: string;
  signals: string[];
}

const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SANDBOX_NAME = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/u;
const SESSION_ID = /^sbx_[A-Za-z0-9_-]{16,124}$/u;
const SUBDOMAIN = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/u;
const INSTANCE_ID = /^svc46_[A-Za-z0-9_-]{24}$/u;
const CHALLENGE = /^ch46_[A-Za-z0-9_-]{24}$/u;
const OPERATION_ID = /^op46_[A-Za-z0-9_-]{43}$/u;
const CANONICAL_BASE64URL = /^[A-Za-z0-9_-]+$/u;
const TERMINAL_ROUTE_STATUS = new Set([404, 410, 421]);
const POST_CASES: readonly Sbx046PostCaseId[] = [
  "external-post-5s",
  "external-post-30s",
  "external-post-90s",
];
const MINIMUM_POST_DELAY: Record<Sbx046PostCaseId, number> = {
  "external-post-5s": 5_000,
  "external-post-30s": 30_000,
  "external-post-90s": 90_000,
};
const MAXIMUM_POST_DELAY: Record<Sbx046PostCaseId, number> = {
  "external-post-5s": 25_000,
  "external-post-30s": 50_000,
  "external-post-90s": 115_000,
};

function timestamp(value: string): number | undefined {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : undefined;
}

function exactStringRecord(actual: Record<string, string>, expected: Record<string, string>): boolean {
  const actualKeys = Object.keys(actual).sort();
  const expectedKeys = Object.keys(expected).sort();
  return actualKeys.length === expectedKeys.length && actualKeys.every((key, index) =>
    key === expectedKeys[index] && actual[key] === expected[key]);
}

function exactCaseKeySet(value: object): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...SBX046_CASE_IDS].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function exactRoute(actual: Sbx046RouteData, expected: Sbx046RouteData): boolean {
  return actual.port === expected.port && actual.url === expected.url && actual.subdomain === expected.subdomain;
}

function exactRouteList(actual: Sbx046RouteData[], expected: Sbx046RouteData[]): boolean {
  return actual.length === expected.length && actual.every((route, index) => {
    const wanted = expected[index];
    return wanted !== undefined && exactRoute(route, wanted);
  });
}

function validExpectedMaterial(expected: Sbx046ExpectedMaterial): boolean {
  const challengeValues = SBX046_CASE_IDS.map((caseId) => expected.challenges[caseId]);
  const operationValues = SBX046_CASE_IDS.map((caseId) => expected.operationIds[caseId]);
  let parsedRoute: URL;
  try {
    parsedRoute = new URL(expected.route.url);
  } catch {
    return false;
  }
  const exactPublicRoute = expected.route.port === SBX046_PORT && SUBDOMAIN.test(expected.route.subdomain) &&
    expected.route.url === `https://${expected.route.subdomain}.vercel.run` &&
    parsedRoute.protocol === "https:" && parsedRoute.username === "" && parsedRoute.password === "" &&
    parsedRoute.hostname === `${expected.route.subdomain}.vercel.run` && parsedRoute.port === "" &&
    parsedRoute.pathname === "/" && parsedRoute.search === "" && parsedRoute.hash === "";
  return RUN_ID.test(expected.runId) && SANDBOX_NAME.test(expected.sandboxName) &&
    SESSION_ID.test(expected.sessionId) && INSTANCE_ID.test(expected.serviceInstanceId) && exactPublicRoute &&
    expected.tags.harness === "vsc" && expected.tags.test === SBX046_TEST_ID &&
    expected.tags.run === expected.runId && exactCaseKeySet(expected.challenges) &&
    exactCaseKeySet(expected.operationIds) && challengeValues.every((value) => CHALLENGE.test(value)) &&
    operationValues.every((value) => OPERATION_ID.test(value)) &&
    new Set(challengeValues).size === SBX046_CASE_IDS.length &&
    new Set(operationValues).size === SBX046_CASE_IDS.length;
}

function exactIdentity(
  value: {
    sandboxName: string;
    sessionId: string;
    persistent: boolean;
    status: string;
    tags: Record<string, string>;
  },
  expected: Sbx046ExpectedMaterial,
): boolean {
  return value.sandboxName === expected.sandboxName && value.sessionId === expected.sessionId &&
    value.persistent === false && value.status === "running" && exactStringRecord(value.tags, expected.tags);
}

function creationPassed(input: Sbx046AssessmentInput): boolean {
  const { creation, expected } = input;
  const requestedAt = timestamp(creation.requestedAt);
  const createdAt = timestamp(creation.createdAt);
  const completedAt = timestamp(creation.completedAt);
  return creation.attempts === 1 && exactIdentity(creation, expected) &&
    exactRouteList(creation.routes, [expected.route]) && creation.sourceSnapshotId === null &&
    requestedAt !== undefined && createdAt !== undefined && completedAt !== undefined &&
    createdAt >= requestedAt - 5_000 && createdAt <= completedAt + 5_000 && requestedAt <= completedAt;
}

function readbackPassed(
  readback: Sbx046RouteReadback,
  stage: Sbx046ReadbackStage,
  source: Sbx046ReadbackSource,
  expected: Sbx046ExpectedMaterial,
): boolean {
  if (readback.stage !== stage || readback.source !== source || timestamp(readback.observedAt) === undefined ||
      !exactIdentity(readback, expected) || readback.domainPort !== SBX046_PORT) {
    return false;
  }
  if (stage === "initial") {
    return exactRouteList(readback.routes, [expected.route]) && !readback.domainLookupThrew &&
      readback.domainValue === expected.route.url;
  }
  return readback.routes.length === 0 && readback.domainLookupThrew && readback.domainValue === null;
}

function readbackPairPassed(
  pair: Sbx046ReadbackPair,
  stage: Sbx046ReadbackStage,
  expected: Sbx046ExpectedMaterial,
): boolean {
  const activeAt = timestamp(pair.active.observedAt);
  const independentAt = timestamp(pair.independent.observedAt);
  return readbackPassed(pair.active, stage, "active", expected) &&
    readbackPassed(pair.independent, stage, "independent", expected) && activeAt !== undefined &&
    independentAt !== undefined && activeAt <= independentAt;
}

function updatePassed(input: Sbx046AssessmentInput): boolean {
  const update = input.update;
  const requestedAt = timestamp(update.requestedAt);
  const acknowledgedAt = timestamp(update.acknowledgedAt);
  return update.method === "Sandbox.update" && update.attempts === 1 && update.requestedPorts.length === 0 &&
    update.acknowledged && update.sandboxName === input.expected.sandboxName &&
    update.sessionIdBefore === input.expected.sessionId && update.sessionIdAfter === input.expected.sessionId &&
    update.responseRoutes.length === 0 && requestedAt !== undefined && acknowledgedAt !== undefined &&
    requestedAt <= acknowledgedAt;
}

function exactProbeBase(
  probe: Sbx046ProbeEvidence,
  caseId: Sbx046CaseId,
  input: Sbx046AssessmentInput,
): boolean {
  const expected = input.expected;
  const startedAt = timestamp(probe.startedAt);
  const completedAt = timestamp(probe.completedAt);
  const local = caseId.startsWith("local-");
  const expectedOrigin = local ? `http://127.0.0.1:${SBX046_PORT}` : expected.route.url;
  return probe.schemaVersion === 1 && probe.testId === SBX046_TEST_ID && probe.runId === expected.runId &&
    probe.caseId === caseId && probe.origin === (local ? "loopback" : "saved-public-route") &&
    probe.sandboxName === expected.sandboxName && probe.sessionId === expected.sessionId &&
    probe.port === SBX046_PORT && probe.serviceInstanceId === expected.serviceInstanceId &&
    probe.challenge === expected.challenges[caseId] && probe.expectedOperationId === expected.operationIds[caseId] &&
    probe.requestMethod === "POST" && probe.requestPath === SBX046_CANARY_PATH &&
    probe.requestOrigin === expectedOrigin && probe.requestAttempts === 1 && probe.connectionAttempts === 1 &&
    probe.actualRequests === 1 && probe.retries === 0 && probe.redirectsFollowed === 0 &&
    probe.freshConnection && probe.strictTlsVerification === !local && !probe.proxyConfigurationAccepted &&
    !probe.tlsTrustConfigurationAccepted && !probe.rawConfigurationRetained && startedAt !== undefined &&
    completedAt !== undefined && startedAt <= completedAt && Number.isFinite(probe.durationMs) &&
    probe.durationMs >= 0 && probe.durationMs <= 10_000 && !probe.rawRequestBodyRetained &&
    !probe.rawResponseBodyRetained;
}

function exactServiceResponse(
  response: Sbx046ServiceResponseEvidence | undefined,
  caseId: Sbx046CaseId,
  input: Sbx046AssessmentInput,
): boolean {
  const expected = input.expected;
  return response !== undefined && response.schemaVersion === 1 && response.testId === SBX046_TEST_ID &&
    response.runId === expected.runId &&
    response.caseId === caseId && response.sandboxName === expected.sandboxName &&
    response.sessionId === expected.sessionId && response.port === SBX046_PORT &&
    response.serviceInstanceId === expected.serviceInstanceId && response.challenge === expected.challenges[caseId] &&
    response.operationId === expected.operationIds[caseId] && response.requestBodyValidated && response.ok;
}

function matchingEvents(
  input: Sbx046AssessmentInput,
  caseId: Sbx046CaseId,
): Sbx046LedgerEvent[] {
  return input.ledger.events.filter((event) => event.caseId === caseId);
}

function exactLedgerEvent(
  event: Sbx046LedgerEvent,
  probe: Sbx046ProbeEvidence,
  caseId: Sbx046CaseId,
  input: Sbx046AssessmentInput,
): boolean {
  const observedAt = timestamp(event.observedAt);
  const startedAt = timestamp(probe.startedAt);
  const completedAt = timestamp(probe.completedAt);
  return event.schemaVersion === 1 && event.testId === SBX046_TEST_ID && event.runId === input.expected.runId &&
    event.sandboxName === input.expected.sandboxName && event.sessionId === input.expected.sessionId &&
    event.port === SBX046_PORT && event.serviceInstanceId === input.expected.serviceInstanceId &&
    event.caseId === caseId && event.challenge === input.expected.challenges[caseId] &&
    event.operationId === input.expected.operationIds[caseId] && event.method === "POST" &&
    event.path === SBX046_CANARY_PATH && event.requestBodyValidated && !event.rawHmacKeyRetained &&
    !event.rawRequestBodyRetained && !event.derivedDigestRetained && observedAt !== undefined &&
    startedAt !== undefined && completedAt !== undefined && observedAt >= startedAt - 10_000 &&
    observedAt <= completedAt + 10_000;
}

function exactSingleLedgerEvent(
  input: Sbx046AssessmentInput,
  caseId: Sbx046CaseId,
): boolean {
  const events = matchingEvents(input, caseId);
  return events.length === 1 && events[0] !== undefined &&
    exactLedgerEvent(events[0], input.probes[caseId], caseId, input);
}

function noLedgerEvent(input: Sbx046AssessmentInput, caseId: Sbx046CaseId): boolean {
  return matchingEvents(input, caseId).length === 0;
}

function exactReach(input: Sbx046AssessmentInput, caseId: Sbx046CaseId): boolean {
  const probe = input.probes[caseId];
  const local = caseId.startsWith("local-");
  return exactProbeBase(probe, caseId, input) && probe.elapsedSinceRevocationAckMs === (
    caseId === "local-pre" || caseId === "external-pre" ? null : probe.elapsedSinceRevocationAckMs
  ) && probe.tcpConnected && probe.tlsEstablished === !local && probe.tlsAuthorized === !local &&
    probe.responseReceived && probe.responseStatusCode === 200 && !probe.timedOut && probe.error === undefined &&
    probe.responseBytes !== undefined && Number.isSafeInteger(probe.responseBytes) &&
    probe.responseBytes > 0 && probe.responseBytes <= 4_096 && probe.serviceHeaderValidated === true &&
    probe.cacheControlValidated === true && probe.connectionCloseValidated === true &&
    probe.contentTypeValidated === true && probe.contentLengthValidated === true &&
    exactServiceResponse(probe.serviceResponse, caseId, input) && exactSingleLedgerEvent(input, caseId);
}

function postTimingPassed(input: Sbx046AssessmentInput, caseId: Sbx046PostCaseId): boolean {
  const probe = input.probes[caseId];
  const ackAt = timestamp(input.update.acknowledgedAt);
  const startedAt = timestamp(probe.startedAt);
  const elapsed = probe.elapsedSinceRevocationAckMs;
  return ackAt !== undefined && startedAt !== undefined && elapsed !== null && Number.isFinite(elapsed) &&
    elapsed >= MINIMUM_POST_DELAY[caseId] && elapsed <= MAXIMUM_POST_DELAY[caseId] &&
    Math.abs(startedAt - ackAt - elapsed) <= 2_000;
}

export function exactConclusiveRouteDenial(
  input: Sbx046AssessmentInput,
  caseId: Sbx046PostCaseId,
): boolean {
  const probe = input.probes[caseId];
  if (!exactProbeBase(probe, caseId, input) || !postTimingPassed(input, caseId) || probe.timedOut ||
      probe.serviceResponse !== undefined || !noLedgerEvent(input, caseId)) {
    return false;
  }
  const dnsWithdrawal = !probe.tcpConnected && !probe.tlsEstablished && !probe.tlsAuthorized &&
    !probe.responseReceived && probe.responseStatusCode === undefined && probe.error?.code === "ENOTFOUND" &&
    probe.error.syscall === "getaddrinfo";
  const terminalHttp = probe.tcpConnected && probe.tlsEstablished && probe.tlsAuthorized &&
    probe.responseReceived && probe.responseStatusCode !== undefined &&
    TERMINAL_ROUTE_STATUS.has(probe.responseStatusCode) && probe.error === undefined &&
    probe.serviceHeaderValidated !== true;
  return dnsWithdrawal || terminalHttp;
}

function exactPostReach(input: Sbx046AssessmentInput, caseId: Sbx046PostCaseId): boolean {
  return postTimingPassed(input, caseId) && exactReach(input, caseId);
}

function classifyPostProbe(
  input: Sbx046AssessmentInput,
  caseId: Sbx046PostCaseId,
): Sbx046PostClassification {
  if (exactPostReach(input, caseId)) return "exact-reach";
  if (exactConclusiveRouteDenial(input, caseId)) return "conclusive-denial";
  return "ambiguous";
}

function ledgerShapePassed(input: Sbx046AssessmentInput): boolean {
  return input.ledger.configured && !input.ledger.rawHmacKeyRetained && !input.ledger.hmacKeyDigestRetained &&
    !input.ledger.rawLogRetained && input.ledger.events.every((event) =>
      SBX046_CASE_IDS.includes(event.caseId) && CHALLENGE.test(event.challenge) && OPERATION_ID.test(event.operationId)
    );
}

function chronologicalControlsPassed(input: Sbx046AssessmentInput): boolean {
  const initialAt = timestamp(input.initialReadbacks.independent.observedAt);
  const localPreStartedAt = timestamp(input.probes["local-pre"].startedAt);
  const localPreCompletedAt = timestamp(input.probes["local-pre"].completedAt);
  const externalPreStartedAt = timestamp(input.probes["external-pre"].startedAt);
  const externalPreCompletedAt = timestamp(input.probes["external-pre"].completedAt);
  const updateRequestedAt = timestamp(input.update.requestedAt);
  const updateAckAt = timestamp(input.update.acknowledgedAt);
  const postActiveAt = timestamp(input.postUpdateReadbacks.active.observedAt);
  const postIndependentAt = timestamp(input.postUpdateReadbacks.independent.observedAt);
  const localPostStartedAt = timestamp(input.probes["local-post-readback"].startedAt);
  const localPostCompletedAt = timestamp(input.probes["local-post-readback"].completedAt);
  const post5StartedAt = timestamp(input.probes["external-post-5s"].startedAt);
  const post5CompletedAt = timestamp(input.probes["external-post-5s"].completedAt);
  const post30StartedAt = timestamp(input.probes["external-post-30s"].startedAt);
  const post30CompletedAt = timestamp(input.probes["external-post-30s"].completedAt);
  const post90StartedAt = timestamp(input.probes["external-post-90s"].startedAt);
  const post90CompletedAt = timestamp(input.probes["external-post-90s"].completedAt);
  const finalActiveAt = timestamp(input.finalReadbacks.active.observedAt);
  const finalIndependentAt = timestamp(input.finalReadbacks.independent.observedAt);
  const localFinalStartedAt = timestamp(input.probes["local-post-final"].startedAt);
  const localFinalCompletedAt = timestamp(input.probes["local-post-final"].completedAt);
  const ordered = [
    initialAt,
    localPreStartedAt,
    localPreCompletedAt,
    externalPreStartedAt,
    externalPreCompletedAt,
    updateRequestedAt,
    updateAckAt,
    postActiveAt,
    postIndependentAt,
    localPostStartedAt,
    localPostCompletedAt,
    post5StartedAt,
    post5CompletedAt,
    post30StartedAt,
    post30CompletedAt,
    post90StartedAt,
    post90CompletedAt,
    finalActiveAt,
    finalIndependentAt,
    localFinalStartedAt,
    localFinalCompletedAt,
  ];
  return ordered.every((value): value is number => value !== undefined) &&
    ordered.every((value, index) => index === 0 || ordered[index - 1]! <= value!);
}

function cleanupPassed(cleanup: Sbx046CleanupEvidence): boolean {
  return cleanup.stopAttempted && cleanup.stopped && cleanup.deleteAttempted && cleanup.deleted &&
    cleanup.absenceChecks >= 3 && cleanup.exactNameAbsent && cleanup.prefixListAbsent &&
    cleanup.guestConfigDeleted && cleanup.guestLedgerDeleted && cleanup.errors.length === 0;
}

function storagePassed(storage: Sbx046StorageEvidence): boolean {
  return storage.guestConfigMode === 0o600 && storage.guestLedgerMode === 0o600 &&
    storage.artifactMode === 0o600 && storage.liveLockMode === 0o600 && storage.liveLockReleased &&
    !storage.rawHmacKeyRetained && !storage.hmacKeyDigestRetained && !storage.rawRequestBodyRetained &&
    !storage.rawResponseBodyRetained;
}

function ledgerSecretFree(ledger: Sbx046LedgerEvidence): boolean {
  return !ledger.rawHmacKeyRetained && !ledger.hmacKeyDigestRetained && !ledger.rawLogRetained;
}

function baseControlsPassed(input: Sbx046AssessmentInput): boolean {
  const preElapsed = input.probes["local-pre"].elapsedSinceRevocationAckMs === null &&
    input.probes["external-pre"].elapsedSinceRevocationAckMs === null;
  const localPostElapsed = input.probes["local-post-readback"].elapsedSinceRevocationAckMs;
  const localFinalElapsed = input.probes["local-post-final"].elapsedSinceRevocationAckMs;
  return input.identityAndScopePassed && validExpectedMaterial(input.expected) && creationPassed(input) &&
    exactCaseKeySet(input.probes) &&
    readbackPairPassed(input.initialReadbacks, "initial", input.expected) && exactReach(input, "local-pre") &&
    exactReach(input, "external-pre") && preElapsed && updatePassed(input) &&
    readbackPairPassed(input.postUpdateReadbacks, "post-update", input.expected) &&
    localPostElapsed !== null && localPostElapsed >= 0 && exactReach(input, "local-post-readback") &&
    readbackPairPassed(input.finalReadbacks, "final", input.expected) &&
    localFinalElapsed !== null && localFinalElapsed >= 90_000 && exactReach(input, "local-post-final") &&
    ledgerShapePassed(input) && chronologicalControlsPassed(input);
}

export function assessSbx046(input: Sbx046AssessmentInput): Sbx046Assessment {
  const postProbeClassifications = Object.fromEntries(POST_CASES.map((caseId) =>
    [caseId, classifyPostProbe(input, caseId)])) as Record<Sbx046PostCaseId, Sbx046PostClassification>;
  const signals: string[] = [];

  if (input.executionError || !cleanupPassed(input.cleanup) || !storagePassed(input.storage) ||
      !ledgerSecretFree(input.ledger)) {
    return {
      verdict: "error",
      severity: "unknown",
      candidate: false,
      controlsPassed: false,
      sustainedRevocationFailure: false,
      postProbeClassifications,
      summary: "Execution, cleanup, or secret-free mode-0600 evidence storage failed.",
      signals,
    };
  }

  const controlsPassed = baseControlsPassed(input);
  if (!controlsPassed) {
    return {
      verdict: "indeterminate",
      severity: "unknown",
      candidate: false,
      controlsPassed: false,
      sustainedRevocationFailure: false,
      postProbeClassifications,
      summary: "A freshness, route, same-session readback, keyed control, timing, or attribution condition failed.",
      signals,
    };
  }

  signals.push("the initial saved public route and loopback service both produced exact keyed controls");
  signals.push("active and independent same-session readbacks showed zero routes after ports=[]");
  signals.push("the loopback canary remained healthy after revocation and after the final public probe");

  const classes = POST_CASES.map((caseId) => postProbeClassifications[caseId]);
  if (classes.every((value) => value === "exact-reach")) {
    signals.push("the saved public route reached the same keyed service at +5s, +30s, and +90s");
    return {
      verdict: "candidate-low",
      severity: "low",
      candidate: true,
      controlsPassed: true,
      sustainedRevocationFailure: true,
      postProbeClassifications,
      summary: "The removed published-port route still reached the exact same-session canary through +90 seconds.",
      signals,
    };
  }

  if (classes.every((value) => value === "conclusive-denial")) {
    signals.push("all three saved-route probes ended in attributable route withdrawal with zero guest events");
    return {
      verdict: "pass",
      severity: "none",
      candidate: false,
      controlsPassed: true,
      sustainedRevocationFailure: false,
      postProbeClassifications,
      summary: "The old published-port route was conclusively withdrawn after ports=[].",
      signals,
    };
  }

  return {
    verdict: "indeterminate",
    severity: "unknown",
    candidate: false,
    controlsPassed: true,
    sustainedRevocationFailure: false,
    postProbeClassifications,
    summary: "Post-revocation results were mixed, ambiguous, duplicated, or not joined to an exact guest event.",
    signals,
  };
}

export function deriveSbx046OperationId(
  hmacKeyBase64Url: string,
  expected: Pick<Sbx046ExpectedMaterial, "runId" | "sandboxName" | "sessionId" | "serviceInstanceId">,
  caseId: Sbx046CaseId,
  challenge: string,
): string {
  if (!CANONICAL_BASE64URL.test(hmacKeyBase64Url)) throw new Error("SBX-046 HMAC key is not base64url");
  const key = Buffer.from(hmacKeyBase64Url, "base64url");
  if (key.length < 32 || key.length > 64 || key.toString("base64url") !== hmacKeyBase64Url) {
    throw new Error("SBX-046 HMAC key must be a canonical 32-64 byte base64url value");
  }
  const message = JSON.stringify([
    SBX046_TEST_ID,
    expected.runId,
    expected.sandboxName,
    expected.sessionId,
    SBX046_PORT,
    expected.serviceInstanceId,
    caseId,
    challenge,
  ]);
  return `op46_${createHmac("sha256", key).update(message).digest("base64url")}`;
}

export function assertSbx046EvidenceExcludesRawValues(
  evidence: unknown,
  forbiddenValues: readonly string[],
): void {
  const serialized = JSON.stringify(evidence);
  for (const value of forbiddenValues) {
    if (value.length > 0 && serialized.includes(value)) {
      throw new Error("SBX-046 evidence retained forbidden raw material");
    }
  }
}
