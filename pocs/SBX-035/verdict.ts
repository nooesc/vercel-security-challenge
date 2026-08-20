import { createHmac } from "node:crypto";

export const SBX035_TEST_ID = "SBX-035-POC";
export const SBX035_CASE_ID = "websocket-live-policy-revocation";

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const publicCanaryPattern = /^corr_[A-Za-z0-9_-]{24}$/u;
const preOperationPattern = /^pre_[A-Za-z0-9_-]{43}$/u;
const secretOperationPattern = /^ws_[A-Za-z0-9_-]{43}$/u;
const activeErrorCodes = new Set(["ECONNRESET", "EPIPE", "EOF"]);
const preConnectBlockErrorCodes = new Set(["EHOSTUNREACH"]);

export type Sbx035Verdict = "candidate-high" | "pass" | "indeterminate" | "error";

export interface Sbx035FreshBlockEvidence {
  ok: boolean;
  mode: "fresh-https" | "fresh-wss";
  runId: string;
  testId: string;
  caseId: string;
  endpointHost: string;
  pinnedIPv4: string;
  pinnedPort: number;
  attemptCount: number;
  retryCount: number;
  strictCertificateVerification: boolean;
  environmentProxyTrust: boolean;
  tcpConnected: boolean;
  tlsEstablished: boolean;
  responseStarted: boolean;
  receivedResponse: boolean;
  timedOut: boolean;
  durationMs: number;
  errorCode?: string;
}

export interface Sbx035RetainedEvidence {
  ok: boolean;
  mode: "retained";
  runId: string;
  testId: string;
  caseId: string;
  endpointHost: string;
  pinnedIPv4: string;
  pinnedPort: number;
  tcpConnected: boolean;
  tlsEstablished: boolean;
  strictCertificateVerification: boolean;
  websocketStatusCode: number;
  websocketAcceptVerified: boolean;
  preOperationId: string;
  operatorSecretFileValidated: boolean;
  operatorSecretFileMode: number;
  secretFramesSent: number;
  responseOperationId?: string;
  rawSecretRetained: boolean;
  rawConfigurationRetained: boolean;
  rawFramesRetained: boolean;
}

export interface Sbx035ObserverEvidence {
  configured: boolean;
  preAccepted: boolean;
  preOperationId?: string;
  registered: boolean;
  secretAccepted: boolean;
  secretMessageCount: number;
  operationId?: string;
  rawSecretStored: boolean;
}

export interface Sbx035RetentionEvidence {
  rawOperatorSecret: boolean;
  rawGuestConfiguration: boolean;
  rawCommandStdout: boolean;
  rawCommandStderr: boolean;
  rawWebSocketFrames: boolean;
  rawSecretInArtifact: boolean;
  secretDigestInArtifact: boolean;
}

export interface Sbx035AssessmentInput {
  runId: string;
  endpointHost: string;
  pinnedIPv4: string;
  expectedPreOperationId: string;
  expectedSecretOperationId: string;
  identityAndScopePassed: boolean;
  initialAllowReadbackPassed: boolean;
  denyAllSameSessionReadbackPassed: boolean;
  retainedReadyBeforeDeny: boolean;
  observerPre: Sbx035ObserverEvidence;
  freshHttps: Sbx035FreshBlockEvidence;
  freshWss: Sbx035FreshBlockEvidence;
  retained: Sbx035RetainedEvidence;
  observerFinal: Sbx035ObserverEvidence;
  policyUpdatedAt: string;
  freshControlsCompletedAt: string;
  operatorSecretCreatedAt: string;
  operatorSecretWrittenAt: string;
  triggerWrittenAt: string;
  observerReceiptAt?: string;
  operatorSecretStagedMode0600: boolean;
  cleanupPassed: boolean;
  retention: Sbx035RetentionEvidence;
  executionError?: boolean;
}

export interface Sbx035Assessment {
  verdict: Sbx035Verdict;
  severity: "high" | "none" | "unknown";
  candidate: boolean;
  controlsPassed: boolean;
  summary: string;
  signals: string[];
}

function hmacBase64Url(key: string, value: string): string {
  return createHmac("sha256", key).update(value).digest("base64url");
}

export function derivePreOperationId(key: string, runId: string, caseId: string, publicCanary: string): string {
  return `pre_${hmacBase64Url(key, `pre\n${runId}\n${caseId}\n${publicCanary}`)}`;
}

export function deriveSecretCommitment(key: string, runId: string, caseId: string, secret: string): string {
  return createHmac("sha256", key)
    .update(`commit\n${runId}\n${caseId}\n${secret}`)
    .digest("hex");
}

export function deriveSecretOperationId(key: string, runId: string, caseId: string, commitment: string): string {
  return `ws_${hmacBase64Url(key, `accepted\n${runId}\n${caseId}\n${commitment}`)}`;
}

export function exactDenyAllSameSession(input: {
  originalSessionId: string;
  activeSessionId: string;
  independentSessionId: string;
  activeSandboxPolicy: unknown;
  activeSessionPolicy: unknown;
  independentSandboxPolicy: unknown;
  independentSessionPolicy: unknown;
}): boolean {
  return input.originalSessionId.length > 0 && input.activeSessionId === input.originalSessionId &&
    input.independentSessionId === input.originalSessionId && input.activeSandboxPolicy === "deny-all" &&
    input.activeSessionPolicy === "deny-all" && input.independentSandboxPolicy === "deny-all" &&
    input.independentSessionPolicy === "deny-all";
}

export function exactFreshActiveBlock(
  evidence: Sbx035FreshBlockEvidence,
  expected: {
    mode: "fresh-https" | "fresh-wss";
    runId: string;
    endpointHost: string;
    pinnedIPv4: string;
  },
): boolean {
  const activelyBlocked = evidence.tcpConnected === true
    ? typeof evidence.errorCode === "string" && activeErrorCodes.has(evidence.errorCode)
    : typeof evidence.errorCode === "string" && preConnectBlockErrorCodes.has(evidence.errorCode);
  return evidence.ok === true && evidence.mode === expected.mode && evidence.runId === expected.runId &&
    evidence.testId === SBX035_TEST_ID && evidence.caseId === SBX035_CASE_ID &&
    evidence.endpointHost === expected.endpointHost && evidence.pinnedIPv4 === expected.pinnedIPv4 &&
    evidence.pinnedPort === 443 && evidence.attemptCount === 1 && evidence.retryCount === 0 &&
    evidence.strictCertificateVerification === true && evidence.environmentProxyTrust === false &&
    evidence.tlsEstablished === false && evidence.responseStarted === false &&
    evidence.receivedResponse === false && evidence.timedOut === false &&
    Number.isFinite(evidence.durationMs) && evidence.durationMs >= 0 && evidence.durationMs <= 4_000 &&
    activelyBlocked;
}

function validTimestamp(value: string): number | undefined {
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : undefined;
}

function exactRetention(retention: Sbx035RetentionEvidence): boolean {
  return Object.values(retention).every((value) => value === false);
}

function exactObserverPre(
  observer: Sbx035ObserverEvidence,
  expectedPreOperationId: string,
): boolean {
  return observer.configured === true && observer.preAccepted === true &&
    observer.preOperationId === expectedPreOperationId && observer.registered === false &&
    observer.secretAccepted === false && observer.secretMessageCount === 0 &&
    observer.operationId === undefined && observer.rawSecretStored === false;
}

function exactRetainedBase(
  retained: Sbx035RetainedEvidence,
  input: Sbx035AssessmentInput,
): boolean {
  return retained.mode === "retained" && retained.runId === input.runId &&
    retained.testId === SBX035_TEST_ID && retained.caseId === SBX035_CASE_ID &&
    retained.endpointHost === input.endpointHost && retained.pinnedIPv4 === input.pinnedIPv4 &&
    retained.pinnedPort === 443 && retained.tcpConnected === true && retained.tlsEstablished === true &&
    retained.strictCertificateVerification === true && retained.websocketStatusCode === 101 &&
    retained.websocketAcceptVerified === true && retained.preOperationId === input.expectedPreOperationId &&
    retained.operatorSecretFileValidated === true && retained.operatorSecretFileMode === 0o600 &&
    retained.rawSecretRetained === false && retained.rawConfigurationRetained === false &&
    retained.rawFramesRetained === false;
}

export function assessSbx035(input: Sbx035AssessmentInput): Sbx035Assessment {
  const signals: string[] = [];
  const policyAt = validTimestamp(input.policyUpdatedAt);
  const controlsAt = validTimestamp(input.freshControlsCompletedAt);
  const createdAt = validTimestamp(input.operatorSecretCreatedAt);
  const writtenAt = validTimestamp(input.operatorSecretWrittenAt);
  const triggerAt = validTimestamp(input.triggerWrittenAt);
  const receiptAt = input.observerReceiptAt === undefined ? undefined : validTimestamp(input.observerReceiptAt);
  const orderingPassed = policyAt !== undefined && controlsAt !== undefined && createdAt !== undefined &&
    writtenAt !== undefined && triggerAt !== undefined && policyAt <= controlsAt && controlsAt <= createdAt &&
    createdAt <= writtenAt && writtenAt <= triggerAt;
  const expectedIdsValid = uuidPattern.test(input.runId) && preOperationPattern.test(input.expectedPreOperationId) &&
    secretOperationPattern.test(input.expectedSecretOperationId);
  const freshHttpsBlocked = exactFreshActiveBlock(input.freshHttps, {
    mode: "fresh-https",
    runId: input.runId,
    endpointHost: input.endpointHost,
    pinnedIPv4: input.pinnedIPv4,
  });
  const freshWssBlocked = exactFreshActiveBlock(input.freshWss, {
    mode: "fresh-wss",
    runId: input.runId,
    endpointHost: input.endpointHost,
    pinnedIPv4: input.pinnedIPv4,
  });
  const retainedBase = exactRetainedBase(input.retained, input);
  const controlsPassed = expectedIdsValid && input.identityAndScopePassed &&
    input.initialAllowReadbackPassed && input.denyAllSameSessionReadbackPassed &&
    input.retainedReadyBeforeDeny && exactObserverPre(input.observerPre, input.expectedPreOperationId) &&
    freshHttpsBlocked && freshWssBlocked && orderingPassed && input.operatorSecretStagedMode0600 &&
    retainedBase && exactRetention(input.retention);

  if (freshHttpsBlocked) signals.push("fresh HTTPS to the pinned owned origin was actively blocked after deny-all");
  if (freshWssBlocked) signals.push("fresh WSS to the same pinned owned origin was actively blocked after deny-all");
  if (controlsPassed) signals.push("the original strictly verified WebSocket predates the same-session deny-all readbacks");

  const candidateProof = controlsPassed && input.retained.ok === true &&
    input.retained.secretFramesSent === 1 &&
    input.retained.responseOperationId === input.expectedSecretOperationId &&
    input.observerFinal.configured === true && input.observerFinal.preAccepted === true &&
    input.observerFinal.preOperationId === input.expectedPreOperationId &&
    input.observerFinal.registered === true && input.observerFinal.secretAccepted === true &&
    input.observerFinal.secretMessageCount === 1 &&
    input.observerFinal.operationId === input.expectedSecretOperationId &&
    input.observerFinal.rawSecretStored === false && receiptAt !== undefined && triggerAt !== undefined &&
    receiptAt >= triggerAt;

  if (candidateProof) signals.push("the retained socket delivered the one-time operator secret and received matching opaque HMAC proof");

  if (input.executionError || !input.cleanupPassed) {
    return {
      verdict: "error",
      severity: "unknown",
      candidate: false,
      controlsPassed,
      summary: "The run or mandatory sandbox/observer cleanup failed.",
      signals,
    };
  }
  if (candidateProof) {
    return {
      verdict: "candidate-high",
      severity: "high",
      candidate: true,
      controlsPassed: true,
      summary: "A WebSocket opened while allowed remained usable after literal deny-all and exfiltrated a fresh synthetic operator secret while new HTTPS and WSS connections were blocked.",
      signals,
    };
  }
  const conclusivePass = controlsPassed && input.retained.secretFramesSent <= 1 &&
    input.retained.responseOperationId === undefined && input.observerFinal.secretAccepted === false &&
    input.observerFinal.secretMessageCount <= 1 && input.observerFinal.operationId === undefined;
  if (conclusivePass) {
    return {
      verdict: "pass",
      severity: "none",
      candidate: false,
      controlsPassed: true,
      summary: "The deny-all update prevented the retained WebSocket from producing a validated secret receipt.",
      signals,
    };
  }
  return {
    verdict: "indeterminate",
    severity: "unknown",
    candidate: false,
    controlsPassed,
    summary: "The exact revocation matrix or receipt attribution was incomplete.",
    signals,
  };
}

export function isSbx035PublicCanary(value: string): boolean {
  return publicCanaryPattern.test(value);
}
