import { createHmac, timingSafeEqual } from "node:crypto";

export const SBX043_TEST_ID = "SBX-043-POC";

export const SBX043_PUBLIC_CASES = {
  outsideSmtp: "outside-b-smtp-starttls",
  allowAllSmtp: "allowall-b-smtp-starttls",
  allowedHttps: "restricted-a-https",
  deniedDirectTls: "restricted-b-direct-tls",
  deniedRaw: "restricted-b-raw",
  deniedSmtp: "restricted-b-smtp-starttls",
  deniedPostDirectTls: "restricted-b-direct-tls-post",
} as const;

export const SBX043_SECRET_CASES = {
  allowedHttps: "secret-a-https",
  deniedDirectTls: "secret-b-direct-tls",
  deniedSmtp: "secret-b-smtp-starttls",
  deniedPostDirectTls: "secret-b-direct-tls-post",
} as const;

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const operationPattern = /^sm_[A-Za-z0-9_-]{43}$/u;
const commitmentPattern = /^[A-Za-z0-9_-]{43}$/u;
const canaryPattern = /^[a-f0-9]{32}$/u;

export type Sbx043ProbeMode =
  | "https-control"
  | "direct-tls"
  | "raw-public"
  | "smtp-starttls-public"
  | "smtp-starttls-secret";

export interface Sbx043ProbeEvidence {
  ok: boolean;
  phase: string;
  mode: Sbx043ProbeMode;
  runId: string;
  testId: string;
  caseId: string;
  endpointRole: "allowed" | "denied";
  endpointHostname: string;
  pinnedIPv4?: string;
  pinnedPort: number;
  attemptCount: 1;
  retryCount: 0;
  tcpConnected: boolean;
  validGreetingReceived: boolean;
  greetingTagMatched: boolean;
  ehloSent: boolean;
  ehloBytes: number;
  startTlsAdvertised: boolean;
  startTlsCommandSent: boolean;
  startTlsReadyReceived: boolean;
  clientHelloGenerated: boolean;
  clientHelloSent: boolean;
  tlsHandshakeComplete: boolean;
  peerCertificateVerified: boolean;
  postTlsEhloComplete: boolean;
  explicitSocketWriteCount: number;
  operatorSecretFileValidated: boolean;
  operatorSecretFileMode?: number;
  secretReadAfterGreeting?: boolean;
  receivedResponse: boolean;
  statusCode?: number;
  timedOut: boolean;
  errorCode?: string;
  rawConfigurationRetained: false;
  rawEhloRetained: false;
  rawOperatorSecretRetained: false;
}

export interface Sbx043ReceiverStatus {
  configured: boolean;
  runId?: string;
  caseId?: string;
  phase?: "public" | "secret";
  mode?: Exclude<Sbx043ProbeMode, "https-control">;
  connectionCount: number;
  greetingWriteCount: number;
  exactEhloCount: number;
  startTlsCommandCount: number;
  tlsHandshakeCount: number;
  postTlsEhloCount: number;
  clientHelloCount: number;
  rawFrameCount: number;
  exactPayloadReceiptCount: number;
  malformedCount: number;
  operationId?: string;
  receiptAt?: string;
  listenerHostname?: string;
  listenerIPv4?: string;
  listenerPort?: number;
  configurationEpoch?: string;
  withinConfiguredWindow: boolean;
  secretCommitmentMatched: boolean;
  rawInboundStored: false;
  rawEhloStored: false;
  rawSecretStored: false;
  payloadDigestStored: false;
}

export interface Sbx043PolicyReadback {
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

export interface Sbx043RetentionEvidence {
  rawOperatorSecret: false;
  rawGuestConfiguration: false;
  rawCommandStdout: false;
  rawCommandStderr: false;
  rawSmtpTranscript: false;
  rawEhlo: false;
  rawSecretInArtifact: false;
  secretDigestInArtifact: false;
}

export interface Sbx043Assessment {
  verdict: "candidate-high" | "candidate-public" | "candidate-reach" | "pass" | "alternate-root" | "indeterminate" | "error";
  candidate: boolean;
  severity: "high" | "medium" | "none" | "unknown";
  controlsPassed: boolean;
  summary: string;
  signals: string[];
}

export interface Sbx043PublicAssessmentInput {
  runId: string;
  allowedHostname: string;
  deniedHostname: string;
  deniedIPv4: string;
  deniedPort: number;
  identityAndScopePassed: boolean;
  distinctAddressSetsPassed: boolean;
  allowAllReadbackPassed: boolean;
  restrictedReadback: Sbx043PolicyReadback;
  postTargetReadback: Sbx043PolicyReadback;
  outsideSmtp: Sbx043ProbeEvidence;
  outsideSmtpReceiver: Sbx043ReceiverStatus;
  allowAllSmtp: Sbx043ProbeEvidence;
  allowAllSmtpReceiver: Sbx043ReceiverStatus;
  allowedHttps: Sbx043ProbeEvidence;
  deniedDirectTls: Sbx043ProbeEvidence;
  deniedDirectTlsReceiver: Sbx043ReceiverStatus;
  deniedRaw: Sbx043ProbeEvidence;
  deniedRawReceiver: Sbx043ReceiverStatus;
  deniedSmtp: Sbx043ProbeEvidence;
  deniedSmtpReceiver: Sbx043ReceiverStatus;
  deniedPostDirectTls: Sbx043ProbeEvidence;
  deniedPostDirectTlsReceiver: Sbx043ReceiverStatus;
  expectedOperations: Record<string, string>;
  expectedConfigurationEpoch: string;
  cleanupPassed: boolean;
  retention: Sbx043RetentionEvidence;
  executionError?: boolean;
}

export interface Sbx043SecretAssessmentInput {
  priorPublicCandidate: boolean;
  publicRunId: string;
  publicSandboxId: string;
  runId: string;
  sandboxId: string;
  identityAndScopePassed: boolean;
  distinctAddressSetsPassed: boolean;
  restrictedReadback: Sbx043PolicyReadback;
  postTargetReadback: Sbx043PolicyReadback;
  allowedHttps: Sbx043ProbeEvidence;
  deniedDirectTls: Sbx043ProbeEvidence;
  deniedDirectTlsReceiver: Sbx043ReceiverStatus;
  deniedSmtp: Sbx043ProbeEvidence;
  deniedSmtpReceiver: Sbx043ReceiverStatus;
  deniedPostDirectTls: Sbx043ProbeEvidence;
  deniedPostDirectTlsReceiver: Sbx043ReceiverStatus;
  expectedSecretOperationId: string;
  expectedConfigurationEpoch: string;
  operatorSecretStagedMode0600: boolean;
  cleanupPassed: boolean;
  retention: Sbx043RetentionEvidence;
  executionError?: boolean;
}

function hmac(key: string, value: string | Buffer): string {
  return createHmac("sha256", key).update(value).digest("base64url");
}

export function isSbx043Canary(value: string): boolean {
  return canaryPattern.test(value);
}

export function deriveSbx043GreetingTag(key: string, runId: string, caseId: string): string {
  return hmac(key, `greeting\n${runId}\n${caseId}`).slice(0, 16);
}

export function deriveSbx043PublicOperationId(key: string, runId: string, caseId: string, canary: string): string {
  if (!isSbx043Canary(canary)) throw new Error("public canary is invalid");
  return `sm_${hmac(key, `public\n${runId}\n${caseId}\n${canary}`)}`;
}

export function deriveSbx043SecretCommitment(key: string, runId: string, caseId: string, secret: string | Buffer): string {
  const bytes = Buffer.isBuffer(secret) ? secret : Buffer.from(secret, "ascii");
  if (bytes.length !== 32 || !/^[a-f0-9]{32}$/u.test(bytes.toString("ascii"))) throw new Error("secret must be 32 lowercase hex bytes");
  return hmac(key, Buffer.concat([Buffer.from(`secret\n${runId}\n${caseId}\n`, "utf8"), bytes]));
}

export function deriveSbx043SecretOperationId(key: string, runId: string, caseId: string, commitment: string): string {
  if (!commitmentPattern.test(commitment)) throw new Error("secret commitment is invalid");
  return `sm_${hmac(key, `secret-operation\n${runId}\n${caseId}\n${commitment}`)}`;
}

export function safeSbx043Equal(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function canonicalPolicy(value: unknown): string | undefined {
  if (value === "allow-all" || value === "deny-all") return value;
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const input = value as Record<string, unknown>;
  if (Object.keys(input).length !== 1 || !("allow" in input)) return undefined;
  if (Array.isArray(input.allow) && input.allow.length === 1 && typeof input.allow[0] === "string") {
    return `allow:${input.allow[0]}`;
  }
  if (input.allow && typeof input.allow === "object" && !Array.isArray(input.allow)) {
    const keys = Object.keys(input.allow as Record<string, unknown>);
    if (keys.length === 1) return `allow:${keys[0]}`;
  }
  return undefined;
}

export function exactSbx043PolicyReadback(
  input: Omit<Sbx043PolicyReadback, "exact" | "sameSession" | "passed">,
  expected: "allow-all" | { allowedHostname: string },
): Sbx043PolicyReadback {
  const wanted = expected === "allow-all" ? "allow-all" : `allow:${expected.allowedHostname}`;
  const values = [
    input.activeSandboxPolicy,
    input.activeSessionPolicy,
    input.independentSandboxPolicy,
    input.independentSessionPolicy,
  ].map(canonicalPolicy);
  const exact = values.every((value) => value === wanted);
  const sameSession = Boolean(input.initialSessionId) && input.activeSessionId === input.initialSessionId &&
    input.independentSessionId === input.initialSessionId;
  return { ...input, exact, sameSession, passed: exact && sameSession };
}

function retentionPassed(value: Sbx043RetentionEvidence): boolean {
  return Object.values(value).every((entry) => entry === false);
}

function receiverBound(status: Sbx043ReceiverStatus, input: {
  runId: string; caseId: string; epoch: string; hostname: string; ipv4: string; port: number;
}): boolean {
  return status.configured && status.runId === input.runId && status.caseId === input.caseId &&
    status.configurationEpoch === input.epoch && status.listenerHostname === input.hostname &&
    status.listenerIPv4 === input.ipv4 && status.listenerPort === input.port && status.withinConfiguredWindow &&
    status.rawInboundStored === false && status.rawEhloStored === false && status.rawSecretStored === false &&
    status.payloadDigestStored === false;
}

function noReceiverContact(status: Sbx043ReceiverStatus): boolean {
  return status.connectionCount === 0 && status.exactPayloadReceiptCount === 0 && status.operationId === undefined;
}

function normalSmtpPassed(probe: Sbx043ProbeEvidence, receiver: Sbx043ReceiverStatus, operationId: string): boolean {
  return probe.ok && probe.mode === "smtp-starttls-public" && probe.tcpConnected && probe.validGreetingReceived &&
    probe.greetingTagMatched && probe.ehloSent && probe.startTlsAdvertised && probe.startTlsCommandSent &&
    probe.startTlsReadyReceived && probe.tlsHandshakeComplete && probe.peerCertificateVerified &&
    probe.postTlsEhloComplete && receiver.connectionCount === 1 && receiver.greetingWriteCount === 1 &&
    receiver.exactEhloCount === 1 && receiver.startTlsCommandCount === 1 && receiver.tlsHandshakeCount === 1 &&
    receiver.postTlsEhloCount === 1 && receiver.exactPayloadReceiptCount === 1 && receiver.operationId === operationId;
}

export function assessSbx043Public(input: Sbx043PublicAssessmentInput): Sbx043Assessment {
  const signals: string[] = [];
  const identity = input.identityAndScopePassed && input.distinctAddressSetsPassed &&
    input.allowedHostname !== input.deniedHostname && input.allowedHostname !== input.deniedIPv4;
  const readbacks = input.allowAllReadbackPassed && input.restrictedReadback.passed && input.postTargetReadback.passed;
  const outsideBound = receiverBound(input.outsideSmtpReceiver, {
    runId: input.runId, caseId: SBX043_PUBLIC_CASES.outsideSmtp, epoch: input.expectedConfigurationEpoch,
    hostname: input.deniedHostname, ipv4: input.deniedIPv4, port: input.deniedPort,
  });
  const allowBound = receiverBound(input.allowAllSmtpReceiver, {
    runId: input.runId, caseId: SBX043_PUBLIC_CASES.allowAllSmtp, epoch: input.expectedConfigurationEpoch,
    hostname: input.deniedHostname, ipv4: input.deniedIPv4, port: input.deniedPort,
  });
  const targetBound = receiverBound(input.deniedSmtpReceiver, {
    runId: input.runId, caseId: SBX043_PUBLIC_CASES.deniedSmtp, epoch: input.expectedConfigurationEpoch,
    hostname: input.deniedHostname, ipv4: input.deniedIPv4, port: input.deniedPort,
  });
  const operationsValid = Object.values(input.expectedOperations).every((value) => operationPattern.test(value));
  const outsidePassed = outsideBound && normalSmtpPassed(
    input.outsideSmtp, input.outsideSmtpReceiver, input.expectedOperations[SBX043_PUBLIC_CASES.outsideSmtp] ?? "",
  );
  const allowPassed = allowBound && normalSmtpPassed(
    input.allowAllSmtp, input.allowAllSmtpReceiver, input.expectedOperations[SBX043_PUBLIC_CASES.allowAllSmtp] ?? "",
  );
  const allowedHttpsPassed = input.allowedHttps.ok && input.allowedHttps.mode === "https-control" &&
    input.allowedHttps.receivedResponse && input.allowedHttps.statusCode === 200;
  const directSilent = noReceiverContact(input.deniedDirectTlsReceiver) && noReceiverContact(input.deniedPostDirectTlsReceiver);
  const rawSilent = noReceiverContact(input.deniedRawReceiver);
  const controlsPassed = identity && readbacks && outsidePassed && allowPassed && allowedHttpsPassed &&
    operationsValid && input.cleanupPassed && retentionPassed(input.retention);
  const targetReceipt = targetBound && input.deniedSmtpReceiver.exactPayloadReceiptCount === 1 &&
    input.deniedSmtpReceiver.exactEhloCount === 1 && input.deniedSmtpReceiver.operationId ===
      input.expectedOperations[SBX043_PUBLIC_CASES.deniedSmtp] &&
    input.deniedSmtp.validGreetingReceived && input.deniedSmtp.greetingTagMatched && input.deniedSmtp.ehloSent;
  const targetReach = targetBound && input.deniedSmtpReceiver.connectionCount > 0 &&
    input.deniedSmtpReceiver.greetingWriteCount > 0 && input.deniedSmtp.validGreetingReceived &&
    input.deniedSmtp.greetingTagMatched;
  const alternate = !directSilent || !rawSilent;

  if (outsidePassed) signals.push("owned B completed a standards-shaped SMTP STARTTLS flow outside Sandbox");
  if (allowPassed) signals.push("allow-all completed the same SMTP STARTTLS flow with verified B certificate");
  if (allowedHttpsPassed) signals.push("exact allow[A] reached the allowed HTTPS control");
  if (directSilent && rawSilent) signals.push("direct TLS and immediate raw B controls produced no receiver contact");
  if (targetReach) signals.push("the case-bound SMTP greeting from denied B reached the restricted guest");
  if (targetReceipt) signals.push("denied B received the exact EHLO canary before TLS authorization");

  if (input.executionError || !controlsPassed) {
    return { verdict: "error", candidate: false, severity: "unknown", controlsPassed, summary: "Required identity, topology, interoperability, policy, cleanup, or retention controls did not all pass.", signals };
  }
  if (alternate) {
    return { verdict: "alternate-root", candidate: false, severity: "unknown", controlsPassed, summary: "A direct TLS or immediate raw path contacted B, so this run does not isolate SMTP STARTTLS pre-authorization forwarding.", signals };
  }
  if (targetReceipt) {
    return { verdict: "candidate-public", candidate: true, severity: "medium", controlsPassed, summary: "Exact allow[A] forwarded an attacker-controlled EHLO line to denied SMTP B before any TLS ClientHello/SNI authorization.", signals };
  }
  if (targetReach) {
    return { verdict: "candidate-reach", candidate: true, severity: "medium", controlsPassed, summary: "Exact allow[A] contacted denied SMTP B and relayed its case-bound greeting, but no exact client canary reached B.", signals };
  }
  if (noReceiverContact(input.deniedSmtpReceiver)) {
    return { verdict: "pass", candidate: false, severity: "none", controlsPassed, summary: "The firewall failed closed before contacting denied SMTP B.", signals };
  }
  return { verdict: "indeterminate", candidate: false, severity: "unknown", controlsPassed, summary: "The target outcome did not match an attributable SMTP STARTTLS result.", signals };
}

export function assessSbx043Secret(input: Sbx043SecretAssessmentInput): Sbx043Assessment {
  const signals: string[] = [];
  const distinctRun = uuidPattern.test(input.publicRunId) && uuidPattern.test(input.runId) &&
    input.publicRunId !== input.runId && input.publicSandboxId !== input.sandboxId;
  const base = input.priorPublicCandidate && distinctRun && input.identityAndScopePassed &&
    input.distinctAddressSetsPassed && input.restrictedReadback.passed && input.postTargetReadback.passed &&
    input.allowedHttps.ok && input.allowedHttps.statusCode === 200 && input.operatorSecretStagedMode0600 &&
    input.cleanupPassed && retentionPassed(input.retention) && operationPattern.test(input.expectedSecretOperationId);
  const negatives = noReceiverContact(input.deniedDirectTlsReceiver) && noReceiverContact(input.deniedPostDirectTlsReceiver);
  const target = input.deniedSmtpReceiver.configured && input.deniedSmtpReceiver.runId === input.runId &&
    input.deniedSmtpReceiver.caseId === SBX043_SECRET_CASES.deniedSmtp &&
    input.deniedSmtpReceiver.configurationEpoch === input.expectedConfigurationEpoch &&
    input.deniedSmtpReceiver.exactPayloadReceiptCount === 1 && input.deniedSmtpReceiver.exactEhloCount === 1 &&
    input.deniedSmtpReceiver.secretCommitmentMatched &&
    input.deniedSmtpReceiver.operationId === input.expectedSecretOperationId &&
    input.deniedSmtp.mode === "smtp-starttls-secret" && input.deniedSmtp.validGreetingReceived &&
    input.deniedSmtp.greetingTagMatched && input.deniedSmtp.ehloSent &&
    input.deniedSmtp.operatorSecretFileValidated && input.deniedSmtp.operatorSecretFileMode === 0o600 &&
    input.deniedSmtp.secretReadAfterGreeting === true;
  if (distinctRun) signals.push("secret proof used a fresh run and fresh sandbox after the public candidate");
  if (negatives) signals.push("fresh restricted direct-TLS controls produced no denied-B receiver contact");
  if (target) signals.push("denied B accepted the exact commitment-backed file-secret EHLO without retaining it");
  const controlsPassed = base && negatives;
  if (input.executionError || !controlsPassed) {
    return { verdict: "error", candidate: false, severity: "unknown", controlsPassed, summary: "Fresh-secret identity, policy, negative, cleanup, or retention controls did not all pass.", signals };
  }
  if (target) {
    return { verdict: "candidate-high", candidate: true, severity: "high", controlsPassed, summary: "A fresh exact-allow[A] sandbox exfiltrated one mode-0600 synthetic file secret to denied SMTP B in a pre-TLS EHLO line.", signals };
  }
  return { verdict: "pass", candidate: false, severity: "none", controlsPassed, summary: "The fresh file secret did not reach denied SMTP B.", signals };
}
