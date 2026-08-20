import { createHmac } from "node:crypto";

export const SBX038_TEST_ID = "SBX-038-POC";
export const SBX038_TRANSFORM_HEADER = "x-sbx038-brokered-canary";

export type Sbx038Verdict = "pass" | "candidate-medium" | "candidate-high" | "indeterminate" | "error";
export type Sbx038Severity = "none" | "medium" | "high" | "unknown";
export type Sbx038ProbeMode = "normal-a" | "direct-b" | "connect-a" | "connect-b-public" | "connect-b-secret";

export interface Sbx038TlsEvidence {
  servername: string;
  authorized: boolean;
  authorizationError?: string;
  protocol?: string;
  remoteAddress?: string;
  remotePort?: number;
}

export interface Sbx038ResponseEvidence {
  statusCode: number;
  operationId?: string;
  bodyBytes?: number;
  terminalConnectHeader?: boolean;
}

export interface Sbx038GuestEvidence {
  schemaVersion: number;
  testId: string;
  runId: string;
  caseId: string;
  mode: Sbx038ProbeMode;
  outerHost: string;
  outerPort: number;
  targetHost?: string;
  targetPort?: number;
  connectAuthority?: string;
  connectHostHeader?: string;
  connectionAttempts: number;
  retryCount: number;
  maximumRequests: number;
  actualRequests: number;
  strictCertificateVerification: boolean;
  environmentProxyTrust: boolean;
  trustEnvironmentNames: string[];
  trustEnvironmentScanComplete: boolean;
  trustOverridesForbidden: boolean;
  rawConfigurationRetained: boolean;
  rawSecretRetained: boolean;
  secretDigestRetained: boolean;
  ok: boolean;
  startedAt: string;
  completedAt: string;
  outerTls?: Sbx038TlsEvidence;
  outerResponse?: Sbx038ResponseEvidence;
  connectResponse?: Sbx038ResponseEvidence;
  tunnelEstablished?: boolean;
  nestedTls?: Sbx038TlsEvidence;
  nestedResponse?: Sbx038ResponseEvidence;
  secretFileValidated?: boolean;
  secretFileMode?: number;
  secretBytes?: number;
  errorCode?: string;
  errorSyscall?: string;
  errorErrno?: number;
}

export interface Sbx038PolicyProof {
  stage: "pre" | "post";
  initialSessionId: string;
  activeSessionId: string;
  independentSessionId: string;
  activeSandboxPolicy: unknown;
  activeSessionPolicy: unknown;
  independentSandboxPolicy: unknown;
  independentSessionPolicy: unknown;
  passed: boolean;
}

export interface Sbx038AHttpEvent {
  sequence: number;
  observedAt: string;
  caseId: string;
  method: string;
  requestTarget: string;
  transformHeaderLines: number;
  transformHeaderValues: number;
  transformHeaderCommitment?: string;
  transformCommitmentMatched: boolean;
  responseStatus: number;
  operationId?: string;
}

export interface Sbx038AConnectEvent {
  sequence: number;
  observedAt: string;
  caseId: string;
  requestTarget: string;
  hostHeader?: string;
  transformHeaderLines: number;
  transformHeaderValues: number;
  transformHeaderCommitment?: string;
  transformCommitmentMatched: boolean;
  terminalResponseStatus: 405;
  openedOutboundConnection: false;
}

export interface Sbx038BEvent {
  sequence: number;
  observedAt: string;
  caseId: string;
  stage: "public" | "secret" | "direct";
  method: string;
  requestTarget: string;
  hostHeaderLines: number;
  hostHeaderValues: number;
  hostHeaderMatched: boolean;
  tlsTerminatedLocally: boolean;
  tlsServername?: string;
  canaryMatched: boolean;
  secretCommitmentMatched: boolean;
  bodyBytes: number;
  rawBodyRetained: false;
  operationId?: string;
}

export interface Sbx038UnexpectedIngressEvent {
  sequence: number;
  observedAt: string;
  role: "a" | "b";
  attribution: "run-header" | "path-run" | "canary";
  reason: "wrong-path" | "wrong-method" | "wrong-case" | "wrong-canary" | "wrong-run-header" | "invalid-host" | "invalid-body";
  method: string;
  caseId?: string;
}

export interface Sbx038ReceiverSnapshot {
  configured: boolean;
  nextSequence: number;
  infrastructureConnect: Sbx038AConnectEvent[];
  aHttp: Sbx038AHttpEvent[];
  aConnect: Sbx038AConnectEvent[];
  b: Sbx038BEvent[];
  unexpected: Sbx038UnexpectedIngressEvent[];
  secretRegistered: boolean;
}

export interface Sbx038ProbeInterval {
  caseId: string;
  startedAt: string;
  completedAt: string;
  receiverSequenceBefore: number;
  receiverSequenceAfter: number;
}

export interface Sbx038StageChronology {
  receiverConfiguredAt: string;
  infrastructurePreflight: Sbx038ProbeInterval;
  policyPreCompletedAt: string;
  probes: Sbx038ProbeInterval[];
  policyPostCompletedAt: string;
  receiverReadAt: string;
  cleanupCompletedAt: string;
}

export interface Sbx038BTransportProof {
  mode: "receiver-local" | "public-edge";
  host: string;
  port: 443;
  tls: Sbx038TlsEvidence;
  healthStatus: 200;
  healthServiceMatched: true;
  completedAt: string;
}

export interface Sbx038StageInput {
  stage: "public" | "secret";
  runId: string;
  aHost: string;
  bHost: string;
  expectedTransformCommitment: string;
  expectedAOperationId: string;
  expectedBOperationId: string;
  identityAndScopePassed: boolean;
  infrastructurePreflightPassed: boolean;
  policyPre: Sbx038PolicyProof;
  policyPost: Sbx038PolicyProof;
  directBPre: Sbx038GuestEvidence;
  normalA: Sbx038GuestEvidence;
  connectA: Sbx038GuestEvidence;
  connectB: Sbx038GuestEvidence;
  directBPost: Sbx038GuestEvidence;
  receiver: Sbx038ReceiverSnapshot;
  bTransportProof: Sbx038BTransportProof;
  chronology: Sbx038StageChronology;
  cleanupPassed: boolean;
  executionError?: boolean;
}

export interface Sbx038Assessment {
  verdict: Sbx038Verdict;
  severity: Sbx038Severity;
  candidate: boolean;
  controlsPassed: boolean;
  publicTunnelProofValid: boolean;
  secretReceiptProofValid: boolean;
  summary: string;
  signals: string[];
}

export interface Sbx038StageIdentity {
  name: string;
  sessionId: string;
}

export interface Sbx038CrossStageIdentity {
  public: Sbx038StageIdentity;
  secret: Sbx038StageIdentity;
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function exactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function text(value: string): boolean {
  return value.length > 0 && value.length <= 1_024 && !/[\0\r\n]/u.test(value);
}

function operation(value: string | undefined): boolean {
  return value !== undefined && /^cx_[A-Za-z0-9_-]{24,64}$/u.test(value);
}

export function deriveSbx038OperationId(key: string, runId: string, caseId: string, signal: string): string {
  if (![key, runId, caseId, signal].every(text)) throw new Error("operation-id input is invalid");
  return `cx_${createHmac("sha256", key).update(`${runId}\0${caseId}\0${signal}`).digest("base64url")}`;
}

export function deriveSbx038SecretCommitment(key: string, runId: string, secret: string | Buffer): string {
  if (!text(key) || !text(runId) || (typeof secret === "string" ? secret.length : secret.length) < 16) {
    throw new Error("secret-commitment input is invalid");
  }
  return createHmac("sha256", key).update(`${runId}\0secret\0`).update(secret).digest("hex");
}

export function deriveSbx038TransformCommitment(key: string, runId: string, transformValue: string): string {
  if (![key, runId, transformValue].every(text)) throw new Error("transform-commitment input is invalid");
  return createHmac("sha256", key).update(`${runId}\0transform\0${transformValue}`).digest("hex");
}

export function exactTransformPolicy(value: unknown, aHost: string, transformValue: string): boolean {
  const policy = object(value);
  const allow = object(policy?.allow);
  if (!policy || !allow || !exactKeys(policy, ["allow"]) || !exactKeys(allow, [aHost])) return false;
  const rules = allow[aHost];
  if (!Array.isArray(rules) || rules.length !== 1) return false;
  const rule = object(rules[0]);
  if (!rule || !exactKeys(rule, ["transform"]) || !Array.isArray(rule.transform) || rule.transform.length !== 1) return false;
  const transform = object(rule.transform[0]);
  const headers = object(transform?.headers);
  return transform !== undefined && headers !== undefined && exactKeys(transform, ["headers"]) &&
    exactKeys(headers, [SBX038_TRANSFORM_HEADER]) && headers[SBX038_TRANSFORM_HEADER] === transformValue;
}

export function exactTransformProjection(value: unknown, aHost: string): boolean {
  const policy = object(value);
  return policy !== undefined && exactKeys(policy, ["allow"]) && Array.isArray(policy.allow) &&
    policy.allow.length === 1 && policy.allow[0] === aHost;
}

export function exactPolicyProof(
  proof: Sbx038PolicyProof,
  aHost: string,
  transformValue: string,
  expectedSessionId: string,
): boolean {
  const exact = exactTransformProjection(proof.activeSandboxPolicy, aHost) &&
    exactTransformPolicy(proof.activeSessionPolicy, aHost, transformValue) &&
    exactTransformProjection(proof.independentSandboxPolicy, aHost) &&
    exactTransformPolicy(proof.independentSessionPolicy, aHost, transformValue);
  const sameSession = proof.initialSessionId === expectedSessionId && proof.activeSessionId === expectedSessionId &&
    proof.independentSessionId === expectedSessionId;
  return proof.passed === exact && proof.passed === sameSession && exact && sameSession;
}

function exactAttempt(guest: Sbx038GuestEvidence, input: Sbx038StageInput, mode: Sbx038ProbeMode, caseId: string): boolean {
  const maximumRequests = mode.startsWith("connect-") ? 2 : 1;
  const allowedTrustEnvironmentNames = new Set([
    "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF", "OPENSSL_MODULES",
    "SSL_CERT_DIR", "SSL_CERT_FILE",
  ]);
  const trustNames = guest.trustEnvironmentNames;
  const exactTrustNames = Array.isArray(trustNames) && new Set(trustNames).size === trustNames.length &&
    trustNames.every((name) => allowedTrustEnvironmentNames.has(name)) &&
    trustNames.every((name, index) => index === 0 || trustNames[index - 1]! < name);
  return guest.schemaVersion === 1 && guest.testId === SBX038_TEST_ID && guest.runId === input.runId &&
    guest.caseId === caseId && guest.mode === mode &&
    guest.outerPort === 443 && guest.connectionAttempts === 1 && guest.retryCount === 0 &&
    guest.maximumRequests === maximumRequests && Number.isSafeInteger(guest.actualRequests) &&
    guest.actualRequests >= 0 && guest.actualRequests <= maximumRequests &&
    guest.strictCertificateVerification === true && guest.environmentProxyTrust === false && exactTrustNames &&
    guest.trustEnvironmentScanComplete === true && guest.trustOverridesForbidden === true &&
    guest.rawConfigurationRetained === false && guest.rawSecretRetained === false && guest.secretDigestRetained === false &&
    guest.outerHost === (mode === "direct-b" ? input.bHost : input.aHost) &&
    instant(guest.startedAt) !== undefined && instant(guest.completedAt) !== undefined &&
    instant(guest.startedAt)! <= instant(guest.completedAt)!;
}

function instant(value: string): number | undefined {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : undefined;
}

function withinSequence(sequence: number, interval: Sbx038ProbeInterval): boolean {
  return Number.isSafeInteger(sequence) && sequence > interval.receiverSequenceBefore &&
    sequence <= interval.receiverSequenceAfter;
}

function exactInterval(interval: Sbx038ProbeInterval | undefined, caseId: string): interval is Sbx038ProbeInterval {
  if (!interval || interval.caseId !== caseId) return false;
  const started = instant(interval.startedAt);
  const completed = instant(interval.completedAt);
  return started !== undefined && completed !== undefined && started <= completed &&
    Number.isSafeInteger(interval.receiverSequenceBefore) && Number.isSafeInteger(interval.receiverSequenceAfter) &&
    interval.receiverSequenceBefore >= 0 && interval.receiverSequenceBefore <= interval.receiverSequenceAfter;
}

function exactTls(value: Sbx038TlsEvidence | undefined, host: string): boolean {
  return value !== undefined && value.servername === host && value.authorized === true && value.authorizationError === undefined &&
    typeof value.protocol === "string" && value.protocol.startsWith("TLSv1.");
}

function eventFor<T extends { caseId: string }>(events: T[], caseId: string): T | undefined {
  const matching = events.filter((event) => event.caseId === caseId);
  return matching.length === 1 ? matching[0] : undefined;
}

function exactChronology(input: Sbx038StageInput): boolean {
  const cases = [
    `${input.stage}-direct-b-pre`,
    `${input.stage}-normal-a`,
    `${input.stage}-connect-a`,
    input.stage === "public" ? "public-connect-b" : "secret-connect-b",
    `${input.stage}-direct-b-post`,
  ];
  const chronology = input.chronology;
  const expectedSequenceDeltas = [0, 1, 1, 1, 0];
  const infrastructureCase = `infrastructure-connect-a-${input.runId.slice(0, 8)}`;
  if (!exactInterval(chronology.infrastructurePreflight, infrastructureCase) || chronology.probes.length !== cases.length ||
    !chronology.probes.every((interval, index) => exactInterval(interval, cases[index]!))) return false;
  const receiverConfiguredAt = instant(chronology.receiverConfiguredAt);
  const policyPreCompletedAt = instant(chronology.policyPreCompletedAt);
  const policyPostCompletedAt = instant(chronology.policyPostCompletedAt);
  const receiverReadAt = instant(chronology.receiverReadAt);
  const cleanupCompletedAt = instant(chronology.cleanupCompletedAt);
  const infrastructureStartedAt = instant(chronology.infrastructurePreflight.startedAt);
  const infrastructureCompletedAt = instant(chronology.infrastructurePreflight.completedAt);
  if ([receiverConfiguredAt, policyPreCompletedAt, policyPostCompletedAt, receiverReadAt, cleanupCompletedAt,
    infrastructureStartedAt, infrastructureCompletedAt].some((value) => value === undefined)) return false;
  const ordered = [
    receiverConfiguredAt!, infrastructureStartedAt!, infrastructureCompletedAt!, policyPreCompletedAt!,
    ...chronology.probes.flatMap((interval) => [instant(interval.startedAt)!, instant(interval.completedAt)!]),
    policyPostCompletedAt!, receiverReadAt!, cleanupCompletedAt!,
  ];
  if (!ordered.every((value, index) => index === 0 || ordered[index - 1]! < value)) return false;
  const infrastructure = eventFor(input.receiver.infrastructureConnect, infrastructureCase);
  if (input.receiver.infrastructureConnect.length !== 1 || !infrastructure ||
    infrastructure.requestTarget !== `${input.aHost}:443` || infrastructure.hostHeader !== input.aHost ||
    infrastructure.transformHeaderLines !== 0 || infrastructure.transformHeaderValues !== 0 ||
    infrastructure.transformHeaderCommitment !== undefined || infrastructure.transformCommitmentMatched !== false ||
    infrastructure.terminalResponseStatus !== 405 || infrastructure.openedOutboundConnection !== false ||
    !withinSequence(infrastructure.sequence, chronology.infrastructurePreflight)) return false;

  const normal = eventFor(input.receiver.aHttp, cases[1]!);
  const connectA = eventFor(input.receiver.aConnect, cases[2]!);
  const attackA = eventFor(input.receiver.aConnect, cases[3]!);
  const attackB = eventFor(input.receiver.b, cases[3]!);
  const allExpectedEvents = [normal, connectA, attackA, attackB].filter((event) => event !== undefined);
  const allReceiverEvents = [...input.receiver.aHttp, ...input.receiver.aConnect, ...input.receiver.b];
  return input.receiver.configured === true && input.receiver.unexpected.length === 0 &&
    input.receiver.nextSequence === chronology.probes[chronology.probes.length - 1]!.receiverSequenceAfter &&
    input.receiver.aHttp.length === 1 && normal !== undefined &&
    input.receiver.aConnect.length === 1 + (attackA ? 1 : 0) && connectA !== undefined &&
    input.receiver.b.length === (attackB ? 1 : 0) && !(attackA && attackB) &&
    allExpectedEvents.length === allReceiverEvents.length &&
    withinSequence(normal.sequence, chronology.probes[1]!) &&
    withinSequence(connectA.sequence, chronology.probes[2]!) &&
    (attackA === undefined || withinSequence(attackA.sequence, chronology.probes[3]!)) &&
    (attackB === undefined || withinSequence(attackB.sequence, chronology.probes[3]!)) &&
    (input.stage === "public"
      ? chronology.probes[0]!.receiverSequenceBefore === chronology.infrastructurePreflight.receiverSequenceAfter
      : chronology.probes[0]!.receiverSequenceBefore >= chronology.infrastructurePreflight.receiverSequenceAfter) &&
    chronology.probes.every((interval, index) =>
      interval.receiverSequenceAfter - interval.receiverSequenceBefore === expectedSequenceDeltas[index]) &&
    chronology.probes.every((interval, index) => index === 0 ||
      chronology.probes[index - 1]!.receiverSequenceAfter === interval.receiverSequenceBefore);
}

function directBlocked(guest: Sbx038GuestEvidence, input: Sbx038StageInput, caseId: string): boolean {
  const receiver = input.receiver.b.filter((event) => event.caseId === caseId);
  const attributableSignal =
    (guest.errorCode === "EAI_AGAIN" && guest.errorSyscall === "getaddrinfo" && guest.errorErrno === -3001) ||
    (guest.errorCode === "EHOSTUNREACH" && guest.errorSyscall === "connect" && guest.errorErrno === -113);
  const startedAt = instant(guest.startedAt);
  const completedAt = instant(guest.completedAt);
  const boundedPreconnectDuration = startedAt !== undefined && completedAt !== undefined &&
    completedAt >= startedAt && completedAt - startedAt <= 8_000;
  const activeFailure = guest.ok === false && guest.outerTls === undefined && guest.outerResponse === undefined &&
    guest.actualRequests === 0 && attributableSignal && boundedPreconnectDuration;
  return exactAttempt(guest, input, "direct-b", caseId) && activeFailure && receiver.length === 0;
}

function normalAControl(input: Sbx038StageInput, caseId: string): boolean {
  const guest = input.normalA;
  const event = eventFor(input.receiver.aHttp, caseId);
  return exactAttempt(guest, input, "normal-a", caseId) && guest.actualRequests === 1 &&
    guest.ok === true && exactTls(guest.outerTls, input.aHost) &&
    guest.outerResponse?.statusCode === 200 && guest.outerResponse.operationId === input.expectedAOperationId &&
    event !== undefined && event.method === "GET" && event.transformHeaderLines === 1 && event.transformHeaderValues === 1 &&
    event.transformHeaderCommitment === input.expectedTransformCommitment && event.transformCommitmentMatched === true &&
    event.responseStatus === 200 && event.operationId === input.expectedAOperationId;
}

function connectAControl(input: Sbx038StageInput, caseId: string): boolean {
  const guest = input.connectA;
  const event = eventFor(input.receiver.aConnect, caseId);
  const transformSafe = event !== undefined && (
    (event.transformHeaderLines === 0 && event.transformHeaderValues === 0 &&
      event.transformHeaderCommitment === undefined && event.transformCommitmentMatched === false) ||
    (event.transformHeaderLines === 1 && event.transformHeaderValues === 1 &&
      event.transformHeaderCommitment === input.expectedTransformCommitment && event.transformCommitmentMatched === true)
  );
  const terminal = guest.ok === false && guest.tunnelEstablished === false && guest.connectResponse?.statusCode === 405 &&
    guest.connectResponse.terminalConnectHeader === true && guest.connectResponse.bodyBytes === 0 &&
    guest.nestedTls === undefined && guest.nestedResponse === undefined && event !== undefined &&
    event.requestTarget === `${input.aHost}:443` && event.hostHeader === input.aHost &&
    transformSafe && event.terminalResponseStatus === 405 && event.openedOutboundConnection === false;
  return exactAttempt(guest, input, "connect-a", caseId) && guest.actualRequests === 1 &&
    exactTls(guest.outerTls, input.aHost) &&
    guest.targetHost === input.aHost && guest.targetPort === 443 &&
    guest.connectAuthority === `${input.aHost}:443` && guest.connectHostHeader === input.aHost && terminal;
}

function exactConnectIdentity(guest: Sbx038GuestEvidence, input: Sbx038StageInput): boolean {
  return exactTls(guest.outerTls, input.aHost) && guest.targetHost === input.bHost && guest.targetPort === 443 &&
    guest.connectAuthority === `${input.bHost}:443` && guest.connectHostHeader === input.aHost;
}

function exactBTransportProof(input: Sbx038StageInput): boolean {
  const proof = input.bTransportProof;
  const completedAt = instant(proof.completedAt);
  const receiverConfiguredAt = instant(input.chronology.receiverConfiguredAt);
  return (proof.mode === "receiver-local" || proof.mode === "public-edge") &&
    proof.host === input.bHost && proof.port === 443 && exactTls(proof.tls, input.bHost) &&
    proof.healthStatus === 200 && proof.healthServiceMatched === true && completedAt !== undefined &&
    receiverConfiguredAt !== undefined && completedAt < receiverConfiguredAt;
}

function exactBEventTransport(event: Sbx038BEvent, input: Sbx038StageInput): boolean {
  return input.bTransportProof.mode === "receiver-local"
    ? event.tlsTerminatedLocally === true && event.tlsServername === input.bHost
    : input.bTransportProof.mode === "public-edge" && event.tlsTerminatedLocally === false &&
      event.tlsServername === undefined;
}

function publicTunnel(input: Sbx038StageInput, caseId: string): boolean {
  const guest = input.connectB;
  const event = eventFor(input.receiver.b, caseId);
  const aAttackEvents = input.receiver.aConnect.filter((entry) => entry.caseId === caseId);
  return exactAttempt(guest, input, "connect-b-public", caseId) && guest.actualRequests === 2 &&
    guest.ok === true && exactConnectIdentity(guest, input) && guest.connectResponse !== undefined &&
    guest.connectResponse.statusCode >= 200 && guest.connectResponse.statusCode < 300 &&
    guest.connectResponse.terminalConnectHeader === false && guest.connectResponse.bodyBytes === 0 && guest.tunnelEstablished === true &&
    exactTls(guest.nestedTls, input.bHost) && guest.nestedResponse?.statusCode === 200 &&
    guest.nestedResponse.operationId === input.expectedBOperationId && operation(input.expectedBOperationId) &&
    aAttackEvents.length === 0 && event !== undefined && event.stage === "public" && event.method === "GET" &&
    event.hostHeaderLines === 1 && event.hostHeaderValues === 1 && event.hostHeaderMatched === true &&
    exactBEventTransport(event, input) &&
    event.canaryMatched === true && event.secretCommitmentMatched === false && event.bodyBytes === 0 &&
    event.rawBodyRetained === false && event.operationId === input.expectedBOperationId;
}

function secretTunnel(input: Sbx038StageInput, caseId: string): boolean {
  const guest = input.connectB;
  const event = eventFor(input.receiver.b, caseId);
  const aAttackEvents = input.receiver.aConnect.filter((entry) => entry.caseId === caseId);
  return exactAttempt(guest, input, "connect-b-secret", caseId) && guest.actualRequests === 2 &&
    guest.ok === true && exactConnectIdentity(guest, input) && guest.connectResponse !== undefined &&
    guest.connectResponse.statusCode >= 200 && guest.connectResponse.statusCode < 300 &&
    guest.connectResponse.terminalConnectHeader === false && guest.connectResponse.bodyBytes === 0 && guest.tunnelEstablished === true &&
    exactTls(guest.nestedTls, input.bHost) && guest.nestedResponse?.statusCode === 200 &&
    guest.nestedResponse.operationId === input.expectedBOperationId && operation(input.expectedBOperationId) &&
    guest.secretFileValidated === true && guest.secretFileMode === 0o600 &&
    Number.isSafeInteger(guest.secretBytes) && (guest.secretBytes ?? 0) >= 16 && (guest.secretBytes ?? 0) <= 4_096 &&
    aAttackEvents.length === 0 && input.receiver.secretRegistered === true && event !== undefined &&
    event.stage === "secret" && event.method === "POST" && event.canaryMatched === true &&
    event.hostHeaderLines === 1 && event.hostHeaderValues === 1 && event.hostHeaderMatched === true &&
    exactBEventTransport(event, input) &&
    event.secretCommitmentMatched === true && event.bodyBytes === guest.secretBytes && event.rawBodyRetained === false &&
    event.operationId === input.expectedBOperationId;
}

function result(
  verdict: Sbx038Verdict,
  severity: Sbx038Severity,
  controlsPassed: boolean,
  publicTunnelProofValid: boolean,
  secretReceiptProofValid: boolean,
  summary: string,
  signals: string[],
): Sbx038Assessment {
  return {
    verdict,
    severity,
    candidate: verdict === "candidate-medium" || verdict === "candidate-high",
    controlsPassed,
    publicTunnelProofValid,
    secretReceiptProofValid,
    summary,
    signals,
  };
}

export function assessSbx038Stage(input: Sbx038StageInput): Sbx038Assessment {
  if (!input.cleanupPassed) {
    return result("error", "unknown", false, false, false, "Strict owned-resource cleanup failed.", ["cleanup passed: false"]);
  }
  if (input.executionError) {
    return result("error", "unknown", false, false, false, "Controller execution failed before complete assessment.", ["execution error: true"]);
  }
  if (!input.identityAndScopePassed || !input.infrastructurePreflightPassed || input.aHost === input.bHost ||
    !text(input.runId) || !text(input.aHost) || !text(input.bHost)) {
    return result("indeterminate", "unknown", false, false, false, "Identity, scope, or raw CONNECT infrastructure preflight failed.", ["preflight incomplete"]);
  }
  const expectedSessionId = input.policyPre.initialSessionId;
  // Policy proofs are produced after redacting the transform value from serialized evidence. The
  // controller sets `passed` only after checking the exact unredacted active and independent views.
  const policyAttested = exactPolicyProof(input.policyPre, input.aHost, "[REDACTED]", expectedSessionId) &&
    exactPolicyProof(input.policyPost, input.aHost, "[REDACTED]", expectedSessionId) &&
    input.policyPre.initialSessionId === input.policyPost.initialSessionId &&
    input.policyPre.stage === "pre" && input.policyPost.stage === "post";
  const preCase = `${input.stage}-direct-b-pre`;
  const normalCase = `${input.stage}-normal-a`;
  const connectACase = `${input.stage}-connect-a`;
  const attackCase = input.stage === "public" ? "public-connect-b" : "secret-connect-b";
  const postCase = `${input.stage}-direct-b-post`;
  const preBlocked = directBlocked(input.directBPre, input, preCase);
  const postBlocked = directBlocked(input.directBPost, input, postCase);
  const directDiagnosticsSame = input.directBPre.errorCode === input.directBPost.errorCode &&
    input.directBPre.errorSyscall === input.directBPost.errorSyscall &&
    input.directBPre.errorErrno === input.directBPost.errorErrno;
  const normal = normalAControl(input, normalCase);
  const connectA = connectAControl(input, connectACase);
  const chronology = exactChronology(input);
  const bTransport = exactBTransportProof(input);
  const controls = policyAttested && preBlocked && postBlocked && directDiagnosticsSame && normal && connectA &&
    chronology && bTransport;
  if (!controls) {
    return result("indeterminate", "unknown", false, false, false, "One or more required policy, direct-B, transformed-A, or CONNECT-A controls failed.", [
      `policy readbacks: ${policyAttested}`,
      `direct B pre/post blocked: ${preBlocked}/${postBlocked}`,
      `direct B pre/post diagnostics identical: ${directDiagnosticsSame}`,
      `normal transformed A: ${normal}`,
      `terminal CONNECT A: ${connectA}`,
      `chronology and exhaustive ingress: ${chronology}`,
      `B TLS/SNI/health transport proof: ${bTransport}`,
    ]);
  }
  const publicProof = input.stage === "public" && publicTunnel(input, attackCase);
  const secretProof = input.stage === "secret" && secretTunnel(input, attackCase);
  if (secretProof) {
    return result("candidate-high", "high", true, false, true,
      "Denied B received the exact fresh mode-0600 synthetic file secret through a CONNECT tunnel authorized as A.",
      ["outer TLS/SNI/Host=A", "CONNECT authority=B:443", "nested verified TLS/action at B", "exact commitment-backed secret receipt"]);
  }
  if (publicProof) {
    return result("candidate-medium", "medium", true, true, false,
      "A CONNECT authority mismatch opened a verified tunnel to denied B, but no file-secret stage is included in this assessment.",
      ["outer TLS/SNI/Host=A", "CONNECT authority=B:443", "B-only nested verified TLS/action"]);
  }
  const attackAEvent = eventFor(input.receiver.aConnect, attackCase);
  const attackBEvent = eventFor(input.receiver.b, attackCase);
  const attackMode: Sbx038ProbeMode = input.stage === "public" ? "connect-b-public" : "connect-b-secret";
  const exactAttackAttempt = exactAttempt(input.connectB, input, attackMode, attackCase);
  const attackTransformSafe = attackAEvent !== undefined && (
    (attackAEvent.transformHeaderLines === 0 && attackAEvent.transformHeaderValues === 0 &&
      attackAEvent.transformHeaderCommitment === undefined && attackAEvent.transformCommitmentMatched === false) ||
    (attackAEvent.transformHeaderLines === 1 && attackAEvent.transformHeaderValues === 1 &&
      attackAEvent.transformHeaderCommitment === input.expectedTransformCommitment &&
      attackAEvent.transformCommitmentMatched === true)
  );
  const terminalAtA = attackAEvent !== undefined && exactConnectIdentity(input.connectB, input) &&
    input.connectB.actualRequests === 1 && input.connectB.ok === false && input.connectB.tunnelEstablished === false &&
    input.connectB.connectResponse?.statusCode === 405 && input.connectB.connectResponse.terminalConnectHeader === true &&
    input.connectB.connectResponse.bodyBytes === 0 && input.connectB.nestedTls === undefined &&
    input.connectB.nestedResponse === undefined && attackAEvent.requestTarget === `${input.bHost}:443` &&
    attackAEvent.hostHeader === input.aHost && attackAEvent.terminalResponseStatus === 405 &&
    attackAEvent.openedOutboundConnection === false && attackTransformSafe;
  if (!attackBEvent && exactAttackAttempt && terminalAtA) {
    return result("pass", "none", true, false, false,
      "The exact authority-mismatched CONNECT request reached the owned A terminal and did not reach denied B.",
      ["A terminal sink received and rejected the exact CONNECT B authority"]);
  }
  return result("indeterminate", "unknown", true, false, false,
    "CONNECT behavior was neither a complete B-only boundary break nor a conclusive block.",
    ["ambiguous observer or guest evidence"]);
}

export function combineSbx038Assessments(
  publicAssessment: Sbx038Assessment,
  secretAssessment?: Sbx038Assessment,
  identities?: Sbx038CrossStageIdentity,
): Sbx038Assessment {
  if (publicAssessment.verdict === "error" || publicAssessment.verdict === "indeterminate") return publicAssessment;
  if (publicAssessment.verdict !== "candidate-medium") return publicAssessment;
  if (!secretAssessment) return publicAssessment;
  if (secretAssessment.verdict === "candidate-high") {
    const distinct = identities !== undefined && text(identities.public.name) && text(identities.public.sessionId) &&
      text(identities.secret.name) && text(identities.secret.sessionId) &&
      identities.public.name !== identities.secret.name && identities.public.sessionId !== identities.secret.sessionId;
    if (!distinct) {
      return {
        ...publicAssessment,
        summary: "Public CONNECT boundary bypass remains valid, but High is withheld because the secret stage was not proven to use a distinct fresh sandbox and session.",
        signals: [...publicAssessment.signals, "fresh secret sandbox identity proof: false"],
      };
    }
    return {
      ...secretAssessment,
      publicTunnelProofValid: true,
      signals: [...publicAssessment.signals, ...secretAssessment.signals],
    };
  }
  if (secretAssessment.verdict === "error" || secretAssessment.verdict === "indeterminate") {
    return result("indeterminate", "unknown", false, true, false,
      "Public tunnel proof succeeded, but the fresh secret stage did not produce a complete safely cleaned assessment.",
      [...publicAssessment.signals, ...secretAssessment.signals]);
  }
  return publicAssessment;
}
