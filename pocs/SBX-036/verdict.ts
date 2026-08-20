import { createHmac, timingSafeEqual } from "node:crypto";

export const SBX036_TEST_ID = "SBX-036-POC";
export const SBX036_SSL_REQUEST_CODE = 80_877_103;
export const SBX036_SSL_REQUEST_HEX = "0000000804d2162f";

export const SBX036_PUBLIC_CASES = {
  outsideDeniedTlsPreflight: "outside-b-tls-preflight",
  outsideDeniedCoalescedPreflight: "outside-b-coalesced-preflight",
  outsideDeniedRawNegative: "outside-b-raw-negative",
  allowAllDeniedTlsControl: "allowall-b-tls-control",
  allowAllCoalescedControl: "allowall-b-coalesced-control",
  allowedTlsControl: "restricted-a-tls-control",
  deniedTlsNegative: "restricted-b-tls-negative",
  deniedRawNegative: "restricted-b-raw-negative",
  deniedCoalescedTarget: "restricted-b-coalesced-target",
  deniedTlsPostNegative: "restricted-b-tls-post-negative",
} as const;

export const SBX036_SECRET_CASES = {
  allowedTlsControl: "secret-a-tls-control",
  deniedTlsNegative: "secret-b-tls-negative",
  deniedCoalescedTarget: "secret-b-coalesced-target",
  deniedTlsPostNegative: "secret-b-tls-post-negative",
} as const;

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const publicOperationPattern = /^pgp_[A-Za-z0-9_-]{43}$/u;
const secretOperationPattern = /^pgs_[A-Za-z0-9_-]{43}$/u;
const sha256Pattern = /^[a-f0-9]{64}$/u;
const activeBlockCodes = new Set([
  "ECONNRESET",
  "EHOSTUNREACH",
  "EPIPE",
  "EOF",
  "PG_TLS_REJECTED",
]);

export type Sbx036ProbeMode =
  | "postgres-tls"
  | "coalesced-tls"
  | "coalesced-public"
  | "coalesced-secret"
  | "raw-public";
export type Sbx036EndpointRole = "allowed" | "denied";
export type Sbx036Verdict = "candidate-high" | "candidate-public" | "pass" | "indeterminate" | "error";

export interface Sbx036ProbeEvidence {
  ok: boolean;
  phase: string;
  mode: Sbx036ProbeMode;
  runId: string;
  testId: string;
  caseId: string;
  endpointRole: Sbx036EndpointRole;
  endpointHostname: string;
  pinnedIPv4: string;
  pinnedPort: number;
  attemptCount: number;
  retryCount: number;
  timeout: boolean;
  tcpConnected: boolean;
  sslRequestExact: boolean;
  sslRequestLength: number;
  sslRequestCode: number;
  sslRequestHex: string;
  responseStarted: boolean;
  serverSslResponse?: string;
  tlsEstablished: boolean;
  certificateVerified: boolean;
  hostnameVerified: boolean;
  tlsVersion?: string;
  operationId?: string;
  coalescedSingleWrite: boolean;
  explicitSocketWriteCount: number;
  bytesAfterSslRequest: number;
  discriminatorKind?: "public" | "secret";
  payloadRetained: false;
  payloadDigestRetained: false;
  rawConfigurationRetained: false;
  errorCode?: string;
}

export interface Sbx036HttpsControlEvidence {
  schemaVersion: number;
  ok: boolean;
  runId: string;
  phase: "allow-control";
  origin: string;
  path: "/healthz";
  timeoutMs: number;
  maximumResponseBytes: number;
  responseBodiesRetained: false;
  receivedResponse: boolean;
  statusCode?: number;
  timedOut: boolean;
  durationMs?: number;
}

export interface Sbx036Receipt {
  role: Sbx036EndpointRole;
  channel: "tls-startup" | "pre-tls-coalesced" | "raw-control";
  runId: string;
  caseId: string;
  discriminatorKind: "public" | "secret";
  exactSslRequest: boolean;
  sslRequestLength: number;
  sslRequestCode: number;
  bytesAfterSslRequest: number;
  observedBeforeServerResponse: boolean;
  serverResponseSentBeforeObservation: boolean;
  serverResponseSentAfterObservation: boolean;
  operationId: string;
  rawPayloadStored: false;
  payloadDigestStored: false;
  observedAt: string;
  connectionId: string;
  sourceAddress: string;
  sourcePort: number;
  listenerHostname: string;
  listenerIPv4: string;
  listenerPort: number;
  configurationEpoch: string;
  withinConfiguredWindow: boolean;
}

export interface Sbx036ReceiverStatus {
  configured: boolean;
  phase?: "public" | "secret";
  receipts: Sbx036Receipt[];
  secretRegistered: boolean;
  rawPayloadStored: false;
  payloadDigestStored: false;
}

export interface Sbx036PolicyReadback {
  initialSessionId: string;
  activeSessionId: string;
  independentSessionId: string;
  activeSandboxPolicy: unknown;
  activeSessionPolicy: unknown;
  independentSandboxPolicy: unknown;
  independentSessionPolicy: unknown;
  exact: boolean;
  sameSession: boolean;
  passed: boolean;
}

export interface Sbx036RetentionEvidence {
  rawOperatorSecret: false;
  rawGuestConfiguration: false;
  rawCommandStdout: false;
  rawCommandStderr: false;
  rawPreTlsPayload: false;
  rawTlsBody: false;
  rawSecretInArtifact: false;
}

export interface Sbx036PublicAssessmentInput {
  runId: string;
  allowedHostname: string;
  allowedIPv4: string;
  allowedPort: number;
  deniedHostname: string;
  deniedIPv4: string;
  deniedPort: number;
  identityAndScopePassed: boolean;
  distinctControlledEndpointsPassed: boolean;
  allowAllReadbackPassed: boolean;
  restrictedReadback: Sbx036PolicyReadback;
  postTargetReadback: Sbx036PolicyReadback;
  allowAllCoalescedControl: Sbx036ProbeEvidence;
  allowedHttpsControl: Sbx036HttpsControlEvidence;
  deniedTlsNegative: Sbx036ProbeEvidence;
  deniedRawNegative: Sbx036ProbeEvidence;
  deniedCoalescedTarget: Sbx036ProbeEvidence;
  deniedTlsPostNegative: Sbx036ProbeEvidence;
  receiver: Sbx036ReceiverStatus;
  expectedOperations: Record<string, string>;
  expectedConfigurationEpoch: string;
  outsideDeniedTlsPreflight: Sbx036ProbeEvidence;
  outsideDeniedCoalescedPreflight: Sbx036ProbeEvidence;
  outsideDeniedRawNegative: Sbx036ProbeEvidence;
  allowAllDeniedTlsControl: Sbx036ProbeEvidence;
  cleanupPassed: boolean;
  retention: Sbx036RetentionEvidence;
  executionError?: boolean;
}

export interface Sbx036SecretAssessmentInput {
  priorPublicCandidate: boolean;
  publicRunId: string;
  publicSandboxId: string;
  runId: string;
  sandboxId: string;
  allowedHostname: string;
  allowedIPv4: string;
  allowedPort: number;
  deniedHostname: string;
  deniedIPv4: string;
  deniedPort: number;
  identityAndScopePassed: boolean;
  distinctControlledEndpointsPassed: boolean;
  restrictedReadback: Sbx036PolicyReadback;
  postTargetReadback: Sbx036PolicyReadback;
  allowedHttpsControl: Sbx036HttpsControlEvidence;
  deniedTlsNegative: Sbx036ProbeEvidence;
  deniedCoalescedTarget: Sbx036ProbeEvidence;
  deniedTlsPostNegative: Sbx036ProbeEvidence;
  receiver: Sbx036ReceiverStatus;
  expectedOperations: Record<string, string>;
  expectedConfigurationEpoch: string;
  publicControlsCompletedAt: string;
  operatorSecretCreatedAt: string;
  operatorSecretWrittenAt: string;
  secretReceiptAt?: string;
  operatorSecretStagedMode0600: boolean;
  cleanupPassed: boolean;
  retention: Sbx036RetentionEvidence;
  executionError?: boolean;
}

export interface Sbx036Assessment {
  verdict: Sbx036Verdict;
  candidate: boolean;
  severity: "high" | "medium" | "none" | "unknown";
  controlsPassed: boolean;
  summary: string;
}

function hmac(key: string, value: string): string {
  return createHmac("sha256", key).update(value).digest("base64url");
}

export function deriveSbx036PublicOperationId(
  key: string,
  runId: string,
  caseId: string,
  canary: string,
): string {
  return `pgp_${hmac(key, `public\n${runId}\n${caseId}\n${canary}`)}`;
}

export function deriveSbx036SecretCommitment(
  key: string,
  runId: string,
  caseId: string,
  secret: string,
): string {
  return createHmac("sha256", key)
    .update(`commit\n${runId}\n${caseId}\n${secret}`)
    .digest("hex");
}

export function deriveSbx036SecretOperationId(
  key: string,
  runId: string,
  caseId: string,
  commitment: string,
): string {
  return `pgs_${hmac(key, `accepted\n${runId}\n${caseId}\n${commitment}`)}`;
}

export function equalSbx036Commitments(left: string, right: string): boolean {
  if (!sha256Pattern.test(left) || !sha256Pattern.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

export function exactSbx036AllowAllPolicy(value: unknown): boolean {
  return value === "allow-all";
}

export function exactSbx036OneHostPolicy(value: unknown, hostname: string): boolean {
  const policy = object(value);
  if (!policy || Object.keys(policy).length !== 1 || !Object.hasOwn(policy, "allow")) return false;
  const allow = policy.allow;
  if (Array.isArray(allow)) return allow.length === 1 && allow[0] === hostname;
  const rules = object(allow);
  return rules !== undefined && Object.keys(rules).length === 1 && Object.hasOwn(rules, hostname) &&
    Array.isArray(rules[hostname]) && (rules[hostname] as unknown[]).length === 0;
}

export function exactSbx036PolicyReadback(
  value: Omit<Sbx036PolicyReadback, "exact" | "sameSession" | "passed">,
  expected: "allow-all" | { allowedHostname: string },
): Sbx036PolicyReadback {
  const exact = expected === "allow-all"
    ? exactSbx036AllowAllPolicy(value.activeSandboxPolicy) &&
      exactSbx036AllowAllPolicy(value.activeSessionPolicy) &&
      exactSbx036AllowAllPolicy(value.independentSandboxPolicy) &&
      exactSbx036AllowAllPolicy(value.independentSessionPolicy)
    : exactSbx036OneHostPolicy(value.activeSandboxPolicy, expected.allowedHostname) &&
      exactSbx036OneHostPolicy(value.activeSessionPolicy, expected.allowedHostname) &&
      exactSbx036OneHostPolicy(value.independentSandboxPolicy, expected.allowedHostname) &&
      exactSbx036OneHostPolicy(value.independentSessionPolicy, expected.allowedHostname);
  const sameSession = value.initialSessionId.length > 0 && value.activeSessionId === value.initialSessionId &&
    value.independentSessionId === value.initialSessionId;
  return { ...value, exact, sameSession, passed: exact && sameSession };
}

function exactProbeBase(
  evidence: Sbx036ProbeEvidence,
  expected: {
    mode: Sbx036ProbeMode;
    runId: string;
    caseId: string;
    role: Sbx036EndpointRole;
    hostname: string;
    ipv4: string;
    port: number;
  },
): boolean {
  return evidence.mode === expected.mode && evidence.runId === expected.runId &&
    evidence.testId === SBX036_TEST_ID && evidence.caseId === expected.caseId &&
    evidence.endpointRole === expected.role && evidence.endpointHostname === expected.hostname &&
    evidence.pinnedIPv4 === expected.ipv4 && evidence.pinnedPort === expected.port &&
    evidence.attemptCount === 1 && evidence.retryCount === 0 && evidence.timeout === false &&
    evidence.sslRequestExact === true && evidence.sslRequestLength === 8 &&
    evidence.sslRequestCode === SBX036_SSL_REQUEST_CODE && evidence.sslRequestHex === SBX036_SSL_REQUEST_HEX &&
    evidence.payloadRetained === false && evidence.payloadDigestRetained === false &&
    evidence.rawConfigurationRetained === false;
}

export function exactSbx036TlsSuccess(
  evidence: Sbx036ProbeEvidence,
  expected: { runId: string; caseId: string; role: Sbx036EndpointRole; hostname: string; ipv4: string; port: number; operationId: string },
): boolean {
  return publicOperationPattern.test(expected.operationId) && exactProbeBase(evidence, {
    mode: "postgres-tls",
    runId: expected.runId,
    caseId: expected.caseId,
    role: expected.role,
    hostname: expected.hostname,
    ipv4: expected.ipv4,
    port: expected.port,
  }) && evidence.ok === true && evidence.phase === "complete" && evidence.tcpConnected === true &&
    evidence.responseStarted === true && evidence.serverSslResponse === "S" && evidence.tlsEstablished === true &&
    evidence.certificateVerified === true && evidence.hostnameVerified === true &&
    (evidence.tlsVersion === "TLSv1.2" || evidence.tlsVersion === "TLSv1.3") &&
    evidence.operationId === expected.operationId && evidence.coalescedSingleWrite === false &&
    evidence.explicitSocketWriteCount === 2 && evidence.bytesAfterSslRequest === 0;
}

export function exactSbx036HttpsControl(
  evidence: Sbx036HttpsControlEvidence,
  expected: { runId: string; hostname: string },
): boolean {
  return evidence.schemaVersion === 1 && evidence.ok === true && evidence.runId === expected.runId &&
    evidence.phase === "allow-control" && evidence.origin === `https://${expected.hostname}` &&
    evidence.path === "/healthz" && evidence.timeoutMs >= 1_000 && evidence.timeoutMs <= 5_000 &&
    evidence.maximumResponseBytes === 1_024 && evidence.responseBodiesRetained === false &&
    evidence.receivedResponse === true && evidence.statusCode === 200 && evidence.timedOut === false &&
    (evidence.durationMs === undefined || (Number.isFinite(evidence.durationMs) && evidence.durationMs >= 0));
}

export function exactSbx036TlsBlock(
  evidence: Sbx036ProbeEvidence,
  expected: { runId: string; caseId: string; hostname: string; ipv4: string; port: number },
): boolean {
  return exactProbeBase(evidence, {
    mode: "postgres-tls",
    runId: expected.runId,
    caseId: expected.caseId,
    role: "denied",
    hostname: expected.hostname,
    ipv4: expected.ipv4,
    port: expected.port,
  }) && evidence.ok === false && evidence.tlsEstablished === false && evidence.certificateVerified === false &&
    evidence.hostnameVerified === false && evidence.operationId === undefined &&
    evidence.coalescedSingleWrite === false && evidence.explicitSocketWriteCount === (evidence.tcpConnected ? 1 : 0) &&
    evidence.bytesAfterSslRequest === 0 && typeof evidence.errorCode === "string" &&
    activeBlockCodes.has(evidence.errorCode);
}

export function exactSbx036CoalescedSend(
  evidence: Sbx036ProbeEvidence,
  expected: {
    mode: "coalesced-public" | "coalesced-secret";
    runId: string;
    caseId: string;
    hostname: string;
    ipv4: string;
    port: number;
  },
): boolean {
  return exactProbeBase(evidence, {
    ...expected,
    role: "denied",
  }) && evidence.ok === true && evidence.phase === "sent" && evidence.tcpConnected === true &&
    evidence.tlsEstablished === false && evidence.certificateVerified === false &&
    evidence.hostnameVerified === false && evidence.coalescedSingleWrite === true &&
    evidence.explicitSocketWriteCount === 1 && evidence.bytesAfterSslRequest > 32 &&
    evidence.bytesAfterSslRequest <= 256 && evidence.discriminatorKind ===
      (expected.mode === "coalesced-public" ? "public" : "secret");
}

export function exactSbx036Receipt(
  receiver: Sbx036ReceiverStatus,
  expected: {
    phase: "public" | "secret";
    channel: "tls-startup" | "pre-tls-coalesced";
    runId: string;
    caseId: string;
    kind: "public" | "secret";
    role: Sbx036EndpointRole;
    operationId: string;
    beforeServerResponse: boolean | "either";
    listenerHostname: string;
    listenerIPv4: string;
    listenerPort: number;
    configurationEpoch: string;
  },
): boolean {
  const operationPattern = expected.kind === "public" ? publicOperationPattern : secretOperationPattern;
  if (!receiver.configured || receiver.phase !== expected.phase || receiver.rawPayloadStored !== false ||
    receiver.payloadDigestStored !== false || !operationPattern.test(expected.operationId)) return false;
  const matches = receiver.receipts.filter((receipt) => receipt.runId === expected.runId &&
    receipt.caseId === expected.caseId && receipt.operationId === expected.operationId);
  if (matches.length !== 1) return false;
  const receipt = matches[0]!;
  const timingMatched = expected.beforeServerResponse === "either"
    ? receipt.observedBeforeServerResponse !== receipt.serverResponseSentBeforeObservation &&
      receipt.serverResponseSentAfterObservation === receipt.observedBeforeServerResponse
    : receipt.observedBeforeServerResponse === expected.beforeServerResponse &&
      receipt.serverResponseSentBeforeObservation === !expected.beforeServerResponse &&
      receipt.serverResponseSentAfterObservation === expected.beforeServerResponse;
  return receipt.role === expected.role && receipt.channel === expected.channel &&
    receipt.discriminatorKind === expected.kind && receipt.exactSslRequest === true &&
    receipt.sslRequestLength === 8 && receipt.sslRequestCode === SBX036_SSL_REQUEST_CODE &&
    receipt.bytesAfterSslRequest > 0 && receipt.bytesAfterSslRequest <= 256 &&
    timingMatched &&
    receipt.listenerHostname === expected.listenerHostname && receipt.listenerIPv4 === expected.listenerIPv4 &&
    receipt.listenerPort === expected.listenerPort && receipt.configurationEpoch === expected.configurationEpoch &&
    receipt.connectionId.length >= 16 && receipt.sourceAddress.length > 0 &&
    Number.isInteger(receipt.sourcePort) && receipt.sourcePort > 0 && receipt.sourcePort <= 65_535 &&
    receipt.withinConfiguredWindow === true &&
    receipt.rawPayloadStored === false && receipt.payloadDigestStored === false &&
    Number.isFinite(Date.parse(receipt.observedAt));
}

export function exactSbx036RawNegativeSend(
  evidence: Sbx036ProbeEvidence,
  expected: { runId: string; caseId: string; hostname: string; ipv4: string; port: number },
): boolean {
  return evidence.mode === "raw-public" && evidence.runId === expected.runId &&
    evidence.testId === SBX036_TEST_ID && evidence.caseId === expected.caseId &&
    evidence.endpointRole === "denied" && evidence.endpointHostname === expected.hostname &&
    evidence.pinnedIPv4 === expected.ipv4 && evidence.pinnedPort === expected.port &&
    evidence.attemptCount === 1 && evidence.retryCount === 0 && evidence.tlsEstablished === false &&
    evidence.certificateVerified === false && evidence.hostnameVerified === false &&
    evidence.sslRequestExact === false && evidence.sslRequestLength === 0 && evidence.sslRequestCode === 0 &&
    evidence.sslRequestHex === "" && evidence.coalescedSingleWrite === false &&
    evidence.explicitSocketWriteCount <= 1 && evidence.bytesAfterSslRequest > 0 &&
    evidence.bytesAfterSslRequest <= 256 && evidence.discriminatorKind === "public" &&
    evidence.payloadRetained === false && evidence.payloadDigestRetained === false &&
    evidence.rawConfigurationRetained === false &&
    (evidence.ok === true || (typeof evidence.errorCode === "string" && activeBlockCodes.has(evidence.errorCode)));
}

export function exactSbx036RawSent(
  evidence: Sbx036ProbeEvidence,
  expected: { runId: string; caseId: string; hostname: string; ipv4: string; port: number },
): boolean {
  return exactSbx036RawNegativeSend(evidence, expected) && evidence.ok === true && evidence.phase === "sent" &&
    evidence.tcpConnected === true && evidence.explicitSocketWriteCount === 1 && evidence.timeout === false;
}

export function exactSbx036RawReceipt(
  receiver: Sbx036ReceiverStatus,
  expected: {
    phase: "public" | "secret";
    runId: string;
    caseId: string;
    operationId: string;
    listenerHostname: string;
    listenerIPv4: string;
    listenerPort: number;
    configurationEpoch: string;
  },
): boolean {
  if (!receiver.configured || receiver.phase !== expected.phase || receiver.rawPayloadStored !== false ||
    receiver.payloadDigestStored !== false || !publicOperationPattern.test(expected.operationId)) return false;
  const matches = receiver.receipts.filter((receipt) => receipt.runId === expected.runId &&
    receipt.caseId === expected.caseId && receipt.operationId === expected.operationId);
  if (matches.length !== 1) return false;
  const receipt = matches[0]!;
  return receipt.role === "denied" && receipt.channel === "raw-control" &&
    receipt.discriminatorKind === "public" && receipt.exactSslRequest === false &&
    receipt.sslRequestLength === 0 && receipt.sslRequestCode === 0 &&
    receipt.bytesAfterSslRequest > 0 && receipt.bytesAfterSslRequest <= 256 &&
    receipt.observedBeforeServerResponse === true && receipt.serverResponseSentBeforeObservation === false &&
    receipt.serverResponseSentAfterObservation === false && receipt.listenerHostname === expected.listenerHostname &&
    receipt.listenerIPv4 === expected.listenerIPv4 && receipt.listenerPort === expected.listenerPort &&
    receipt.configurationEpoch === expected.configurationEpoch && receipt.connectionId.length >= 16 &&
    receipt.sourceAddress.length > 0 && Number.isInteger(receipt.sourcePort) && receipt.sourcePort > 0 &&
    receipt.sourcePort <= 65_535 && receipt.withinConfiguredWindow === true &&
    receipt.rawPayloadStored === false && receipt.payloadDigestStored === false &&
    Number.isFinite(Date.parse(receipt.observedAt));
}

export function exactSbx036CoalescedActiveBlock(
  evidence: Sbx036ProbeEvidence,
  expected: {
    mode: "coalesced-public" | "coalesced-secret";
    runId: string;
    caseId: string;
    hostname: string;
    ipv4: string;
    port: number;
  },
): boolean {
  return evidence.mode === expected.mode && evidence.runId === expected.runId &&
    evidence.testId === SBX036_TEST_ID && evidence.caseId === expected.caseId &&
    evidence.endpointRole === "denied" && evidence.endpointHostname === expected.hostname &&
    evidence.pinnedIPv4 === expected.ipv4 && evidence.pinnedPort === expected.port &&
    evidence.attemptCount === 1 && evidence.retryCount === 0 && evidence.ok === false &&
    evidence.phase === "connect" && evidence.timeout === false && evidence.tcpConnected === false &&
    evidence.sslRequestExact === true && evidence.sslRequestLength === 8 &&
    evidence.sslRequestCode === SBX036_SSL_REQUEST_CODE && evidence.sslRequestHex === SBX036_SSL_REQUEST_HEX &&
    evidence.coalescedSingleWrite === true && evidence.explicitSocketWriteCount === 0 &&
    evidence.bytesAfterSslRequest > 32 && evidence.bytesAfterSslRequest <= 256 &&
    evidence.discriminatorKind === (expected.mode === "coalesced-public" ? "public" : "secret") &&
    typeof evidence.errorCode === "string" && activeBlockCodes.has(evidence.errorCode) &&
    evidence.payloadRetained === false && evidence.payloadDigestRetained === false &&
    evidence.rawConfigurationRetained === false;
}

function noReceipt(receiver: Sbx036ReceiverStatus, runId: string, caseId: string): boolean {
  return receiver.receipts.every((receipt) => receipt.runId !== runId || receipt.caseId !== caseId);
}

function zeroRetention(retention: Sbx036RetentionEvidence): boolean {
  return Object.values(retention).every((value) => value === false);
}

export function assessSbx036Public(input: Sbx036PublicAssessmentInput): Sbx036Assessment {
  const idsValid = uuidPattern.test(input.runId);
  const publicCases = SBX036_PUBLIC_CASES;
  const allowAllReceipt = exactSbx036Receipt(input.receiver, {
    phase: "public",
    channel: "pre-tls-coalesced",
    runId: input.runId,
    caseId: publicCases.allowAllCoalescedControl,
    kind: "public",
    role: "denied",
    operationId: input.expectedOperations[publicCases.allowAllCoalescedControl] ?? "",
    beforeServerResponse: "either",
    listenerHostname: input.deniedHostname,
    listenerIPv4: input.deniedIPv4,
    listenerPort: input.deniedPort,
    configurationEpoch: input.expectedConfigurationEpoch,
  });
  const outsideTls = exactSbx036TlsSuccess(input.outsideDeniedTlsPreflight, {
    runId: input.runId,
    caseId: publicCases.outsideDeniedTlsPreflight,
    role: "denied",
    hostname: input.deniedHostname,
    ipv4: input.deniedIPv4,
    port: input.deniedPort,
    operationId: input.expectedOperations[publicCases.outsideDeniedTlsPreflight] ?? "",
  }) && exactSbx036Receipt(input.receiver, {
    phase: "public",
    channel: "tls-startup",
    runId: input.runId,
    caseId: publicCases.outsideDeniedTlsPreflight,
    kind: "public",
    role: "denied",
    operationId: input.expectedOperations[publicCases.outsideDeniedTlsPreflight] ?? "",
    beforeServerResponse: false,
    listenerHostname: input.deniedHostname,
    listenerIPv4: input.deniedIPv4,
    listenerPort: input.deniedPort,
    configurationEpoch: input.expectedConfigurationEpoch,
  });
  const outsideCoalesced = exactSbx036CoalescedSend(input.outsideDeniedCoalescedPreflight, {
    mode: "coalesced-public",
    runId: input.runId,
    caseId: publicCases.outsideDeniedCoalescedPreflight,
    hostname: input.deniedHostname,
    ipv4: input.deniedIPv4,
    port: input.deniedPort,
  }) && exactSbx036Receipt(input.receiver, {
    phase: "public",
    channel: "pre-tls-coalesced",
    runId: input.runId,
    caseId: publicCases.outsideDeniedCoalescedPreflight,
    kind: "public",
    role: "denied",
    operationId: input.expectedOperations[publicCases.outsideDeniedCoalescedPreflight] ?? "",
    beforeServerResponse: "either",
    listenerHostname: input.deniedHostname,
    listenerIPv4: input.deniedIPv4,
    listenerPort: input.deniedPort,
    configurationEpoch: input.expectedConfigurationEpoch,
  });
  const outsideRawNegative = exactSbx036RawSent(input.outsideDeniedRawNegative, {
    runId: input.runId,
    caseId: publicCases.outsideDeniedRawNegative,
    hostname: input.deniedHostname,
    ipv4: input.deniedIPv4,
    port: input.deniedPort,
  }) && exactSbx036RawReceipt(input.receiver, {
    phase: "public",
    runId: input.runId,
    caseId: publicCases.outsideDeniedRawNegative,
    operationId: input.expectedOperations[publicCases.outsideDeniedRawNegative] ?? "",
    listenerHostname: input.deniedHostname,
    listenerIPv4: input.deniedIPv4,
    listenerPort: input.deniedPort,
    configurationEpoch: input.expectedConfigurationEpoch,
  });
  const allowAllDeniedTls = exactSbx036TlsSuccess(input.allowAllDeniedTlsControl, {
    runId: input.runId,
    caseId: publicCases.allowAllDeniedTlsControl,
    role: "denied",
    hostname: input.deniedHostname,
    ipv4: input.deniedIPv4,
    port: input.deniedPort,
    operationId: input.expectedOperations[publicCases.allowAllDeniedTlsControl] ?? "",
  }) && exactSbx036Receipt(input.receiver, {
    phase: "public",
    channel: "tls-startup",
    runId: input.runId,
    caseId: publicCases.allowAllDeniedTlsControl,
    kind: "public",
    role: "denied",
    operationId: input.expectedOperations[publicCases.allowAllDeniedTlsControl] ?? "",
    beforeServerResponse: false,
    listenerHostname: input.deniedHostname,
    listenerIPv4: input.deniedIPv4,
    listenerPort: input.deniedPort,
    configurationEpoch: input.expectedConfigurationEpoch,
  });
  const allowedHttps = exactSbx036HttpsControl(input.allowedHttpsControl, {
    runId: input.runId,
    hostname: input.allowedHostname,
  });
  const preBlocked = exactSbx036TlsBlock(input.deniedTlsNegative, {
    runId: input.runId,
    caseId: publicCases.deniedTlsNegative,
    hostname: input.deniedHostname,
    ipv4: input.deniedIPv4,
    port: input.deniedPort,
  }) && noReceipt(input.receiver, input.runId, publicCases.deniedTlsNegative);
  const postBlocked = exactSbx036TlsBlock(input.deniedTlsPostNegative, {
    runId: input.runId,
    caseId: publicCases.deniedTlsPostNegative,
    hostname: input.deniedHostname,
    ipv4: input.deniedIPv4,
    port: input.deniedPort,
  }) && noReceipt(input.receiver, input.runId, publicCases.deniedTlsPostNegative);
  const targetSent = exactSbx036CoalescedSend(input.deniedCoalescedTarget, {
    mode: "coalesced-public",
    runId: input.runId,
    caseId: publicCases.deniedCoalescedTarget,
    hostname: input.deniedHostname,
    ipv4: input.deniedIPv4,
    port: input.deniedPort,
  });
  const targetBlocked = exactSbx036CoalescedActiveBlock(input.deniedCoalescedTarget, {
    mode: "coalesced-public",
    runId: input.runId,
    caseId: publicCases.deniedCoalescedTarget,
    hostname: input.deniedHostname,
    ipv4: input.deniedIPv4,
    port: input.deniedPort,
  });
  const targetReceipt = exactSbx036Receipt(input.receiver, {
    phase: "public",
    channel: "pre-tls-coalesced",
    runId: input.runId,
    caseId: publicCases.deniedCoalescedTarget,
    kind: "public",
    role: "denied",
    operationId: input.expectedOperations[publicCases.deniedCoalescedTarget] ?? "",
    beforeServerResponse: "either",
    listenerHostname: input.deniedHostname,
    listenerIPv4: input.deniedIPv4,
    listenerPort: input.deniedPort,
    configurationEpoch: input.expectedConfigurationEpoch,
  });
  const rawNegative = exactSbx036RawNegativeSend(input.deniedRawNegative, {
    runId: input.runId,
    caseId: publicCases.deniedRawNegative,
    hostname: input.deniedHostname,
    ipv4: input.deniedIPv4,
    port: input.deniedPort,
  }) && noReceipt(input.receiver, input.runId, publicCases.deniedRawNegative);
  const controlsPassed = idsValid && input.identityAndScopePassed && input.distinctControlledEndpointsPassed &&
    input.allowAllReadbackPassed && input.restrictedReadback.passed && input.postTargetReadback.passed &&
    outsideTls && outsideCoalesced && outsideRawNegative && allowAllDeniedTls &&
    exactSbx036CoalescedSend(input.allowAllCoalescedControl, {
      mode: "coalesced-public",
      runId: input.runId,
      caseId: publicCases.allowAllCoalescedControl,
      hostname: input.deniedHostname,
      ipv4: input.deniedIPv4,
      port: input.deniedPort,
    }) && allowAllReceipt && allowedHttps && preBlocked && rawNegative && postBlocked &&
    (targetSent || targetBlocked) && zeroRetention(input.retention);

  if (input.executionError || !input.cleanupPassed) {
    return {
      verdict: "error",
      candidate: false,
      severity: "unknown",
      controlsPassed,
      summary: "The public discriminator stage or mandatory sandbox/receiver cleanup failed.",
    };
  }
  if (controlsPassed && targetSent && targetReceipt) {
    return {
      verdict: "candidate-public",
      candidate: true,
      severity: "medium",
      controlsPassed: true,
      summary: "The denied, distinct-IP listener received a bounded public discriminator appended to the exact PostgreSQL SSLRequest before any TLS ClientHello/SNI authorization, while ordinary TLS to that hostname was blocked.",
    };
  }
  if (controlsPassed && (targetBlocked || targetSent) &&
    noReceipt(input.receiver, input.runId, publicCases.deniedCoalescedTarget)) {
    return {
      verdict: "pass",
      candidate: false,
      severity: "none",
      controlsPassed: true,
      summary: "The restricted firewall did not forward the coalesced public discriminator to the denied listener.",
    };
  }
  return {
    verdict: "indeterminate",
    candidate: false,
    severity: "unknown",
    controlsPassed,
    summary: "The public discriminator matrix lacked an exact control, readback, block, or authenticated receipt.",
  };
}

export function assessSbx036Secret(input: Sbx036SecretAssessmentInput): Sbx036Assessment {
  const cases = SBX036_SECRET_CASES;
  const freshIdentity = uuidPattern.test(input.publicRunId) && uuidPattern.test(input.runId) &&
    input.publicRunId !== input.runId && input.publicSandboxId.length > 0 && input.sandboxId.length > 0 &&
    input.publicSandboxId !== input.sandboxId;
  const allowedHttps = exactSbx036HttpsControl(input.allowedHttpsControl, {
    runId: input.runId,
    hostname: input.allowedHostname,
  });
  const preBlocked = exactSbx036TlsBlock(input.deniedTlsNegative, {
    runId: input.runId,
    caseId: cases.deniedTlsNegative,
    hostname: input.deniedHostname,
    ipv4: input.deniedIPv4,
    port: input.deniedPort,
  }) && noReceipt(input.receiver, input.runId, cases.deniedTlsNegative);
  const postBlocked = exactSbx036TlsBlock(input.deniedTlsPostNegative, {
    runId: input.runId,
    caseId: cases.deniedTlsPostNegative,
    hostname: input.deniedHostname,
    ipv4: input.deniedIPv4,
    port: input.deniedPort,
  }) && noReceipt(input.receiver, input.runId, cases.deniedTlsPostNegative);
  const targetSent = exactSbx036CoalescedSend(input.deniedCoalescedTarget, {
    mode: "coalesced-secret",
    runId: input.runId,
    caseId: cases.deniedCoalescedTarget,
    hostname: input.deniedHostname,
    ipv4: input.deniedIPv4,
    port: input.deniedPort,
  });
  const targetBlocked = exactSbx036CoalescedActiveBlock(input.deniedCoalescedTarget, {
    mode: "coalesced-secret",
    runId: input.runId,
    caseId: cases.deniedCoalescedTarget,
    hostname: input.deniedHostname,
    ipv4: input.deniedIPv4,
    port: input.deniedPort,
  });
  const targetOperation = input.expectedOperations[cases.deniedCoalescedTarget] ?? "";
  const targetReceipt = exactSbx036Receipt(input.receiver, {
    phase: "secret",
    channel: "pre-tls-coalesced",
    runId: input.runId,
    caseId: cases.deniedCoalescedTarget,
    kind: "secret",
    role: "denied",
    operationId: targetOperation,
    beforeServerResponse: "either",
    listenerHostname: input.deniedHostname,
    listenerIPv4: input.deniedIPv4,
    listenerPort: input.deniedPort,
    configurationEpoch: input.expectedConfigurationEpoch,
  });
  const controlsAt = Date.parse(input.publicControlsCompletedAt);
  const createdAt = Date.parse(input.operatorSecretCreatedAt);
  const writtenAt = Date.parse(input.operatorSecretWrittenAt);
  const receiptAt = input.secretReceiptAt === undefined ? Number.NaN : Date.parse(input.secretReceiptAt);
  const stagingOrderingPassed = [controlsAt, createdAt, writtenAt].every(Number.isFinite) &&
    controlsAt <= createdAt && createdAt <= writtenAt;
  const receiptOrderingPassed = stagingOrderingPassed && Number.isFinite(receiptAt) && writtenAt <= receiptAt;
  const baseControlsPassed = input.priorPublicCandidate && freshIdentity && input.identityAndScopePassed &&
    input.distinctControlledEndpointsPassed && input.restrictedReadback.passed && input.postTargetReadback.passed &&
    allowedHttps && preBlocked && postBlocked && (targetSent || targetBlocked) &&
    input.receiver.secretRegistered === true &&
    input.operatorSecretStagedMode0600 && stagingOrderingPassed && zeroRetention(input.retention);
  const cleanTargetNegative = noReceipt(input.receiver, input.runId, cases.deniedCoalescedTarget);
  const candidateControlsPassed = baseControlsPassed && receiptOrderingPassed;
  const passControlsPassed = baseControlsPassed && cleanTargetNegative;
  const controlsPassed = candidateControlsPassed || passControlsPassed;

  if (input.executionError || !input.cleanupPassed) {
    return {
      verdict: "error",
      candidate: false,
      severity: "unknown",
      controlsPassed,
      summary: "The fresh secret stage or mandatory sandbox/receiver cleanup failed.",
    };
  }
  if (candidateControlsPassed && targetSent && targetReceipt && secretOperationPattern.test(targetOperation)) {
    return {
      verdict: "candidate-high",
      candidate: true,
      severity: "high",
      controlsPassed: true,
      summary: "A fresh restricted sandbox exfiltrated one file-backed synthetic secret to the denied distinct-IP listener in bytes coalesced after the exact PostgreSQL SSLRequest, with an opaque commitment-backed receipt.",
    };
  }
  if (passControlsPassed && (targetBlocked || targetSent)) {
    return {
      verdict: "pass",
      candidate: false,
      severity: "none",
      controlsPassed: true,
      summary: "The fresh secret-stage firewall did not forward the coalesced discriminator to the denied listener.",
    };
  }
  return {
    verdict: "indeterminate",
    candidate: false,
    severity: "unknown",
    controlsPassed,
    summary: "The fresh secret stage lacked an exact control, ordering proof, or commitment-backed receipt.",
  };
}
