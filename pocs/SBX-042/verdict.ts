import { createHmac } from "node:crypto";

export const SBX042_TEST_ID = "SBX-042-POC";
export const SBX042_SCOPE_CONFIRMATION =
  "I_CONTROL_THE_SBX042_TLS13_EARLY_DATA_ENDPOINT_AND_AUTHORIZE_TWO_BOUNDED_REVOCATION_RUNS";

export type Sbx042Verdict = "pass" | "candidate-medium" | "candidate-high" | "indeterminate" | "error";
export type Sbx042Severity = "none" | "medium" | "high" | "unknown";
export type Sbx042Stage = "public" | "secret";

export interface Sbx042PolicyReadback {
  expected: "allow-endpoint" | "deny-all";
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

export interface Sbx042ProbeEvidence {
  schemaVersion: number;
  testId: string;
  mode: "bootstrap" | "fresh" | "early";
  stage: Sbx042Stage | "preflight";
  runId: string;
  caseId: string;
  hostname: string;
  pinnedIPv4: string;
  port: number;
  attemptCount: number;
  retryCount: number;
  strictCertificateVerification: boolean;
  environmentProxyTrust: boolean;
  tlsVersionPinned: string;
  timedOut: boolean;
  tcpConnected: boolean;
  tlsEstablished: boolean;
  verificationPassed: boolean;
  sessionTicketReceived: boolean;
  sessionFileValidated: boolean;
  sessionFileMode?: number;
  sessionBytes?: number;
  maxEarlyData?: number;
  sessionReused: boolean;
  earlyDataAccepted: boolean;
  earlyPayloadBytes: number;
  postHandshakeBytesSent: number;
  secretFileValidated: boolean;
  secretFileMode?: number;
  processExitCode?: number;
  connectErrno?: number;
  rawConfigurationRetained: false;
  rawSessionRetained: false;
  rawPayloadRetained: false;
  rawSecretRetained: false;
  secretDigestRetained: false;
}

export interface Sbx042ReceiverEvent {
  runId: string;
  caseId: string;
  kind: "public" | "secret";
  observedAt: string;
  accepted: boolean;
  payloadBytes: number;
  commitmentMatched: boolean;
  operationId?: string;
  rawPayloadRetained: false;
  payloadDigestRetained: false;
}

export interface Sbx042ReceiverSnapshot {
  configured: boolean;
  tls13EarlyDataEnabled: boolean;
  antiReplayEnabled: boolean;
  completedHandshakes: number;
  noEarlyDataConnections: number;
  earlyDataReadEnds: number;
  resumedSessions: number;
  malformedFrames: number;
  events: Sbx042ReceiverEvent[];
}

export interface Sbx042CleanupEvidence {
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  deletionAbsenceConfirmed: boolean;
  receiverDeleteAttempted: boolean;
  receiverDeleted: boolean;
  receiverAbsent: boolean;
  errors: string[];
}

export interface Sbx042RetentionEvidence {
  rawOperatorSecret: false;
  operatorSecretDigest: false;
  rawSessionTicket: false;
  rawEarlyPayload: false;
  rawGuestConfiguration: false;
  rawCommandOutput: false;
}

export interface Sbx042StageEvidence {
  stage: Sbx042Stage;
  runId: string;
  caseId: string;
  sandboxName: string;
  sessionId: string;
  hostname: string;
  pinnedIPv4: string;
  port: number;
  identityAndScopePassed: boolean;
  outsideEarlyDataPreflightPassed: boolean;
  allowReadback: Sbx042PolicyReadback;
  denyReadbackBefore: Sbx042PolicyReadback;
  denyReadbackAfter: Sbx042PolicyReadback;
  bootstrap: Sbx042ProbeEvidence;
  freshControl: Sbx042ProbeEvidence;
  earlyAttempt: Sbx042ProbeEvidence;
  receiverBeforeFresh: Sbx042ReceiverSnapshot;
  receiverAfterFresh: Sbx042ReceiverSnapshot;
  receiverFinal: Sbx042ReceiverSnapshot;
  expectedOperationId: string;
  ticketCompletedAt: string;
  denyUpdateCompletedAt: string;
  freshControlCompletedAt: string;
  payloadCreatedAt: string;
  earlyAttemptCompletedAt: string;
  secretFileStagedMode0600: boolean;
  cleanup: Sbx042CleanupEvidence;
  retention: Sbx042RetentionEvidence;
  executionError?: boolean;
}

export interface Sbx042Assessment {
  verdict: Sbx042Verdict;
  severity: Sbx042Severity;
  candidate: boolean;
  controlsPassed: boolean;
  publicBoundaryProof: boolean;
  secretExfiltrationProof: boolean;
  summary: string;
  signals: string[];
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const operationPattern = /^ed_[A-Za-z0-9_-]{43}$/u;
const casePattern = /^[a-z0-9][a-z0-9-]{0,63}$/u;
const activeBlockErrnos = new Set([1, 13, 65, 101, 113]);

function hmac(key: string, value: string | Buffer): string {
  return createHmac("sha256", key).update(value).digest("base64url");
}

export function deriveSbx042SecretCommitment(
  key: string,
  runId: string,
  caseId: string,
  secret: Buffer,
): string {
  return createHmac("sha256", key).update(`secret\0${runId}\0${caseId}\0`).update(secret).digest("hex");
}

export function deriveSbx042OperationId(key: string, runId: string, caseId: string, signal: string): string {
  return `ed_${hmac(key, `accepted\0${runId}\0${caseId}\0${signal}`)}`;
}

function policyShape(value: unknown, hostname: string): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const policy = value as Record<string, unknown>;
  if (Object.keys(policy).length !== 1 || !("allow" in policy)) return false;
  const allow = policy.allow;
  if (Array.isArray(allow)) return allow.length === 1 && allow[0] === hostname;
  if (allow === null || typeof allow !== "object" || Array.isArray(allow)) return false;
  const entries = Object.entries(allow as Record<string, unknown>);
  return entries.length === 1 && entries[0]?.[0] === hostname && Array.isArray(entries[0][1]) &&
    entries[0][1].length === 0;
}

export function exactSbx042PolicyReadback(
  input: Omit<Sbx042PolicyReadback, "exact" | "sameSession" | "passed" | "expected">,
  expected: "deny-all" | { hostname: string },
): Sbx042PolicyReadback {
  const predicate = (value: unknown): boolean => expected === "deny-all"
    ? value === "deny-all"
    : policyShape(value, expected.hostname);
  const sameSession = input.initialSessionId.length > 0 && input.activeSessionId === input.initialSessionId &&
    input.independentSessionId === input.initialSessionId;
  const exact = predicate(input.activeSandboxPolicy) && predicate(input.activeSessionPolicy) &&
    predicate(input.independentSandboxPolicy) && predicate(input.independentSessionPolicy);
  return {
    ...input,
    expected: expected === "deny-all" ? "deny-all" : "allow-endpoint",
    exact,
    sameSession,
    passed: exact && sameSession,
  };
}

function exactProbeBase(
  value: Sbx042ProbeEvidence,
  stage: Sbx042Stage,
  mode: Sbx042ProbeEvidence["mode"],
  input: Sbx042StageEvidence,
): boolean {
  return value.schemaVersion === 1 && value.testId === SBX042_TEST_ID && value.mode === mode &&
    value.stage === stage && value.runId === input.runId && value.caseId === input.caseId &&
    value.hostname === input.hostname && value.pinnedIPv4 === input.pinnedIPv4 && value.port === input.port &&
    value.attemptCount === 1 && value.retryCount === 0 && value.strictCertificateVerification === true &&
    value.environmentProxyTrust === false && value.tlsVersionPinned === "TLSv1.3" &&
    value.rawConfigurationRetained === false && value.rawSessionRetained === false &&
    value.rawPayloadRetained === false && value.rawSecretRetained === false &&
    value.secretDigestRetained === false;
}

function exactBootstrap(input: Sbx042StageEvidence): boolean {
  const value = input.bootstrap;
  return exactProbeBase(value, input.stage, "bootstrap", input) && value.timedOut === false &&
    value.tcpConnected && value.tlsEstablished && value.verificationPassed && value.sessionTicketReceived &&
    value.sessionFileValidated && value.sessionFileMode === 0o600 && (value.sessionBytes ?? 0) > 0 &&
    (value.sessionBytes ?? 0) <= 65_536 && (value.maxEarlyData ?? 0) >= 256 && !value.sessionReused &&
    !value.earlyDataAccepted && value.earlyPayloadBytes === 0 && value.postHandshakeBytesSent === 0 &&
    value.processExitCode === 0;
}

function exactFreshBlock(input: Sbx042StageEvidence): boolean {
  const value = input.freshControl;
  const countersUnchanged = input.receiverAfterFresh.completedHandshakes ===
      input.receiverBeforeFresh.completedHandshakes &&
    input.receiverAfterFresh.resumedSessions === input.receiverBeforeFresh.resumedSessions &&
    input.receiverAfterFresh.earlyDataReadEnds === input.receiverBeforeFresh.earlyDataReadEnds &&
    input.receiverAfterFresh.events.length === input.receiverBeforeFresh.events.length;
  return exactProbeBase(value, input.stage, "fresh", input) && value.timedOut === false &&
    value.tcpConnected === false && value.tlsEstablished === false && value.verificationPassed === false &&
    value.sessionTicketReceived === false && value.sessionReused === false && value.earlyDataAccepted === false &&
    value.earlyPayloadBytes === 0 && value.postHandshakeBytesSent === 0 &&
    value.connectErrno !== undefined && activeBlockErrnos.has(value.connectErrno) && countersUnchanged;
}

function exactEarlyAttempt(input: Sbx042StageEvidence): boolean {
  const value = input.earlyAttempt;
  return exactProbeBase(value, input.stage, "early", input) && value.timedOut === false && value.tcpConnected &&
    value.tlsEstablished && value.verificationPassed && value.sessionReused && value.earlyDataAccepted &&
    value.earlyPayloadBytes >= 32 && value.earlyPayloadBytes <= 512 && value.postHandshakeBytesSent === 0 &&
    value.processExitCode === 0 && (input.stage === "public"
      ? value.secretFileValidated === false && value.secretFileMode === undefined
      : value.secretFileValidated === true && value.secretFileMode === 0o600);
}

function exactEarlyBlock(input: Sbx042StageEvidence): boolean {
  const value = input.earlyAttempt;
  return exactProbeBase(value, input.stage, "early", input) && value.timedOut === false &&
    value.tcpConnected === false && value.tlsEstablished === false && value.verificationPassed === false &&
    value.sessionReused === false && value.earlyDataAccepted === false && value.postHandshakeBytesSent === 0 &&
    value.connectErrno !== undefined && activeBlockErrnos.has(value.connectErrno) &&
    input.receiverFinal.events.length === input.receiverAfterFresh.events.length &&
    input.receiverFinal.completedHandshakes === input.receiverAfterFresh.completedHandshakes;
}

function exactReceiverReceipt(input: Sbx042StageEvidence): boolean {
  const matches = input.receiverFinal.events.filter((event) => event.runId === input.runId &&
    event.caseId === input.caseId && event.kind === input.stage && event.accepted &&
    event.operationId === input.expectedOperationId);
  const deltas = input.receiverFinal.completedHandshakes === input.receiverAfterFresh.completedHandshakes + 1 &&
    input.receiverFinal.resumedSessions === input.receiverAfterFresh.resumedSessions + 1 &&
    input.receiverFinal.earlyDataReadEnds === input.receiverAfterFresh.earlyDataReadEnds + 1;
  return input.receiverFinal.configured && input.receiverFinal.tls13EarlyDataEnabled &&
    input.receiverFinal.antiReplayEnabled && input.receiverFinal.malformedFrames === 0 && deltas &&
    matches.length === 1 && matches[0]?.commitmentMatched === (input.stage === "secret") &&
    matches[0]?.rawPayloadRetained === false && matches[0]?.payloadDigestRetained === false;
}

function timestamp(value: string): number | undefined {
  const result = Date.parse(value);
  return Number.isFinite(result) ? result : undefined;
}

function exactOrdering(input: Sbx042StageEvidence): boolean {
  const values = [input.ticketCompletedAt, input.denyUpdateCompletedAt, input.freshControlCompletedAt,
    input.payloadCreatedAt, input.earlyAttemptCompletedAt].map(timestamp);
  if (values.some((value) => value === undefined)) return false;
  const [ticket, deny, fresh, payload, early] = values as [number, number, number, number, number];
  return ticket <= deny && deny <= fresh && fresh <= payload && payload <= early;
}

function cleanupPassed(value: Sbx042CleanupEvidence): boolean {
  return value.stopAttempted && value.stopped && value.deleteAttempted && value.deleted &&
    value.deletionAbsenceConfirmed && value.receiverDeleteAttempted && value.receiverDeleted &&
    value.receiverAbsent && value.errors.length === 0;
}

function retentionPassed(value: Sbx042RetentionEvidence): boolean {
  return Object.values(value).every((entry) => entry === false);
}

function stageControls(input: Sbx042StageEvidence): boolean {
  return uuidPattern.test(input.runId) && casePattern.test(input.caseId) && operationPattern.test(input.expectedOperationId) &&
    input.sandboxName.length > 0 && input.sessionId.length > 0 && input.identityAndScopePassed &&
    input.outsideEarlyDataPreflightPassed && input.allowReadback.passed && input.denyReadbackBefore.passed &&
    input.denyReadbackAfter.passed && exactBootstrap(input) && exactFreshBlock(input) && exactOrdering(input) &&
    retentionPassed(input.retention) && cleanupPassed(input.cleanup) &&
    (input.stage === "public" ? !input.secretFileStagedMode0600 : input.secretFileStagedMode0600);
}

export function assessSbx042(
  publicStage: Sbx042StageEvidence,
  secretStage?: Sbx042StageEvidence,
): Sbx042Assessment {
  const signals: string[] = [];
  const publicControls = stageControls(publicStage);
  const publicReceipt = publicControls && exactEarlyAttempt(publicStage) && exactReceiverReceipt(publicStage);
  const publicBlocked = publicControls && exactEarlyBlock(publicStage);

  if (exactFreshBlock(publicStage)) signals.push("a normal fresh TLS connection was actively blocked after literal deny-all");
  if (publicReceipt) signals.push("the fresh resumed TLS 1.3 connection delivered its public canary as accepted 0-RTT data");

  const secretControls = secretStage !== undefined && stageControls(secretStage) &&
    secretStage.stage === "secret" && publicStage.sandboxName !== secretStage.sandboxName &&
    publicStage.sessionId !== secretStage.sessionId;
  const secretReceipt = secretStage !== undefined && secretControls && exactEarlyAttempt(secretStage) &&
    exactReceiverReceipt(secretStage);
  if (secretReceipt) signals.push("a separate fresh sandbox exfiltrated one mode-0600 synthetic file secret as accepted 0-RTT data");

  if (publicStage.executionError || secretStage?.executionError) {
    return { verdict: "error", severity: "unknown", candidate: false, controlsPassed: false,
      publicBoundaryProof: false, secretExfiltrationProof: false,
      summary: "The bounded run encountered an execution error; do not infer a boundary result.", signals };
  }
  if (!publicControls) {
    return { verdict: "indeterminate", severity: "unknown", candidate: false, controlsPassed: false,
      publicBoundaryProof: false, secretExfiltrationProof: false,
      summary: "One or more identity, ticket, policy, fresh-block, ordering, cleanup, or retention controls failed.", signals };
  }
  if (secretReceipt) {
    return { verdict: "candidate-high", severity: "high", candidate: true, controlsPassed: true,
      publicBoundaryProof: true, secretExfiltrationProof: true,
      summary: "After literal deny-all, TLS 1.3 0-RTT carried a fresh mode-0600 synthetic file secret to the owned endpoint.", signals };
  }
  if (publicReceipt) {
    if (secretStage !== undefined && !secretControls) {
      signals.push("the independently gated secret stage was attempted but its controls did not all pass");
    }
    return { verdict: "candidate-medium", severity: "medium", candidate: true, controlsPassed: true,
      publicBoundaryProof: true, secretExfiltrationProof: false,
      summary: "After literal deny-all, TLS 1.3 0-RTT carried the exact public canary to the owned endpoint.", signals };
  }
  if (publicBlocked) {
    return { verdict: "pass", severity: "none", candidate: false, controlsPassed: true,
      publicBoundaryProof: false, secretExfiltrationProof: false,
      summary: "Literal deny-all actively blocked both normal fresh TLS and the fresh resumed 0-RTT attempt.", signals };
  }
  return { verdict: "indeterminate", severity: "unknown", candidate: false, controlsPassed: true,
    publicBoundaryProof: false, secretExfiltrationProof: false,
    summary: "The 0-RTT attempt was neither an exact active block nor an authenticated early-data receipt.", signals };
}
