import { createHmac, timingSafeEqual } from "node:crypto";

export const SBX039_TEST_ID = "SBX-039-POC";

export const SBX039_PUBLIC_CASES = {
  outsideCoalesced: "outside-b-mysql-coalesced",
  allowAllDirectTls: "allowall-b-direct-tls",
  allowAllSplit: "allowall-b-mysql-split",
  allowAllCoalesced: "allowall-b-mysql-coalesced",
  allowedHttps: "restricted-a-https",
  deniedDirectTls: "restricted-b-direct-tls",
  deniedRaw: "restricted-b-raw",
  deniedSplit: "restricted-b-mysql-split",
  deniedCoalesced: "restricted-b-mysql-coalesced",
  deniedPostDirectTls: "restricted-b-direct-tls-post",
} as const;

export const SBX039_SECRET_CASES = {
  allowedHttps: "secret-a-https",
  deniedDirectTls: "secret-b-direct-tls",
  deniedCoalesced: "secret-b-mysql-coalesced",
  deniedPostDirectTls: "secret-b-direct-tls-post",
} as const;

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const operationPattern = /^my_[A-Za-z0-9_-]{43}$/u;
const commitmentPattern = /^[a-f0-9]{64}$/u;
const hexCanaryPattern = /^[a-f0-9]{32}$/u;

export type Sbx039ProbeMode =
  | "https-control"
  | "direct-tls"
  | "raw-public"
  | "greeting-only"
  | "mysql-split-public"
  | "mysql-coalesced-public"
  | "mysql-coalesced-secret";

export interface Sbx039ProbeEvidence {
  ok: boolean;
  phase: string;
  mode: Sbx039ProbeMode;
  runId: string;
  testId: string;
  caseId: string;
  endpointRole: "allowed" | "denied";
  endpointHostname: string;
  pinnedIPv4?: string;
  pinnedPort: number;
  attemptCount: number;
  retryCount: number;
  tcpConnected: boolean;
  validGreetingReceived: boolean;
  greetingTagMatched: boolean;
  sslRequestExact: boolean;
  sslRequestBytes: number;
  clientHelloGenerated: boolean;
  clientHelloSent: boolean;
  clientHelloBytes: number;
  explicitSocketWriteCount: number;
  interWriteDelayMs: number;
  serverNameKind?: "public" | "secret";
  operatorSecretFileValidated: boolean;
  operatorSecretFileMode?: number;
  receivedResponse: boolean;
  statusCode?: number;
  timedOut: boolean;
  errorCode?: string;
  rawConfigurationRetained: false;
  rawServerNameRetained: false;
  rawOperatorSecretRetained: false;
}

export interface Sbx039ReceiverStatus {
  configured: boolean;
  runId?: string;
  caseId?: string;
  phase?: "public" | "secret";
  mode?: Exclude<Sbx039ProbeMode, "https-control">;
  connectionCount: number;
  greetingWriteCount: number;
  sslRequestCount: number;
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
  rawServerNameStored: false;
  rawSecretStored: false;
  payloadDigestStored: false;
}

export interface Sbx039HttpsEvidence {
  ok: boolean;
  mode: "https-control";
  runId: string;
  testId: string;
  caseId: string;
  endpointRole: "allowed";
  endpointHostname: string;
  pinnedPort: 443;
  attemptCount: 1;
  retryCount: 0;
  tcpConnected: boolean;
  receivedResponse: boolean;
  statusCode?: number;
  timedOut: boolean;
  rawConfigurationRetained: false;
  rawServerNameRetained: false;
  rawOperatorSecretRetained: false;
}

export interface Sbx039PolicyReadback {
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

export interface Sbx039RetentionEvidence {
  rawOperatorSecret: false;
  rawGuestConfiguration: false;
  rawCommandStdout: false;
  rawCommandStderr: false;
  rawClientHello: false;
  rawServerName: false;
  rawSecretInArtifact: false;
  secretDigestInArtifact: false;
}

export type Sbx039PublicVerdict =
  | "candidate-public"
  | "candidate-reach"
  | "pass"
  | "alternate-root"
  | "indeterminate"
  | "error";

export interface Sbx039Assessment {
  verdict: Sbx039PublicVerdict | "candidate-high";
  candidate: boolean;
  severity: "high" | "medium" | "none" | "unknown";
  controlsPassed: boolean;
  variant?: "coalesced-upgrade" | "server-first-upgrade" | "preauthorization-connect";
  summary: string;
  signals: string[];
}

export interface Sbx039PublicAssessmentInput {
  runId: string;
  allowedHostname: string;
  deniedHostname: string;
  deniedIPv4: string;
  deniedPort: number;
  identityAndScopePassed: boolean;
  distinctAddressSetsPassed: boolean;
  allowAllReadbackPassed: boolean;
  restrictedReadback: Sbx039PolicyReadback;
  postTargetReadback: Sbx039PolicyReadback;
  outsideCoalesced: Sbx039ProbeEvidence;
  outsideCoalescedReceiver: Sbx039ReceiverStatus;
  allowAllDirectTls: Sbx039ProbeEvidence;
  allowAllDirectTlsReceiver: Sbx039ReceiverStatus;
  allowAllSplit: Sbx039ProbeEvidence;
  allowAllSplitReceiver: Sbx039ReceiverStatus;
  allowAllCoalesced: Sbx039ProbeEvidence;
  allowAllCoalescedReceiver: Sbx039ReceiverStatus;
  allowedHttps: Sbx039HttpsEvidence;
  deniedDirectTls: Sbx039ProbeEvidence;
  deniedDirectTlsReceiver: Sbx039ReceiverStatus;
  deniedRaw: Sbx039ProbeEvidence;
  deniedRawReceiver: Sbx039ReceiverStatus;
  deniedSplit: Sbx039ProbeEvidence;
  deniedSplitReceiver: Sbx039ReceiverStatus;
  deniedCoalesced: Sbx039ProbeEvidence;
  deniedCoalescedReceiver: Sbx039ReceiverStatus;
  deniedPostDirectTls: Sbx039ProbeEvidence;
  deniedPostDirectTlsReceiver: Sbx039ReceiverStatus;
  expectedOperations: Record<string, string>;
  expectedConfigurationEpoch: string;
  cleanupPassed: boolean;
  retention: Sbx039RetentionEvidence;
  executionError?: boolean;
}

export interface Sbx039SecretAssessmentInput {
  priorPublicCandidate: boolean;
  publicRunId: string;
  publicSandboxId: string;
  runId: string;
  sandboxId: string;
  allowedHostname: string;
  deniedHostname: string;
  deniedIPv4: string;
  deniedPort: number;
  identityAndScopePassed: boolean;
  distinctAddressSetsPassed: boolean;
  restrictedReadback: Sbx039PolicyReadback;
  postTargetReadback: Sbx039PolicyReadback;
  allowedHttps: Sbx039HttpsEvidence;
  deniedDirectTls: Sbx039ProbeEvidence;
  deniedDirectTlsReceiver: Sbx039ReceiverStatus;
  deniedCoalesced: Sbx039ProbeEvidence;
  deniedCoalescedReceiver: Sbx039ReceiverStatus;
  deniedPostDirectTls: Sbx039ProbeEvidence;
  deniedPostDirectTlsReceiver: Sbx039ReceiverStatus;
  expectedSecretOperationId: string;
  expectedConfigurationEpoch: string;
  publicControlsCompletedAt: string;
  operatorSecretCreatedAt: string;
  operatorSecretWrittenAt: string;
  secretReceiptAt?: string;
  operatorSecretStagedMode0600: boolean;
  cleanupPassed: boolean;
  retention: Sbx039RetentionEvidence;
  executionError?: boolean;
}

function hmac(key: string, value: string | Buffer): string {
  return createHmac("sha256", key).update(value).digest("base64url");
}

export function deriveSbx039GreetingTag(key: string, runId: string, caseId: string): string {
  return hmac(key, `greeting\n${runId}\n${caseId}`).slice(0, 16);
}

export function deriveSbx039PublicOperationId(
  key: string,
  runId: string,
  caseId: string,
  canary: string,
): string {
  return `my_${hmac(key, `public\n${runId}\n${caseId}\n${canary}`)}`;
}

export function deriveSbx039SecretCommitment(
  key: string,
  runId: string,
  caseId: string,
  secret: string,
): string {
  return createHmac("sha256", key).update(`secret\n${runId}\n${caseId}\n${secret}`).digest("hex");
}

export function deriveSbx039SecretOperationId(
  key: string,
  runId: string,
  caseId: string,
  commitment: string,
): string {
  return `my_${hmac(key, `accepted\n${runId}\n${caseId}\n${commitment}`)}`;
}

function policyShape(value: unknown, allowedHostname: string): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 1 || !("allow" in record)) return false;
  const allow = record.allow;
  if (Array.isArray(allow)) return allow.length === 1 && allow[0] === allowedHostname;
  if (allow === null || typeof allow !== "object" || Array.isArray(allow)) return false;
  const entries = Object.entries(allow as Record<string, unknown>);
  return entries.length === 1 && entries[0]?.[0] === allowedHostname && Array.isArray(entries[0][1]) && entries[0][1].length === 0;
}

export function exactSbx039PolicyReadback(
  input: Omit<Sbx039PolicyReadback, "exact" | "sameSession" | "passed">,
  expected: "allow-all" | { allowedHostname: string },
): Sbx039PolicyReadback {
  const predicate = (value: unknown): boolean => expected === "allow-all"
    ? value === "allow-all"
    : policyShape(value, expected.allowedHostname);
  const sameSession = input.initialSessionId.length > 0 && input.activeSessionId === input.initialSessionId &&
    input.independentSessionId === input.initialSessionId;
  const exact = predicate(input.activeSandboxPolicy) && predicate(input.activeSessionPolicy) &&
    predicate(input.independentSandboxPolicy) && predicate(input.independentSessionPolicy);
  return { ...input, exact, sameSession, passed: exact && sameSession };
}

function exactRetention(value: Sbx039RetentionEvidence): boolean {
  return Object.values(value).every((entry) => entry === false);
}

function exactProbe(
  value: Sbx039ProbeEvidence,
  expected: {
    mode: Sbx039ProbeMode;
    runId: string;
    caseId: string;
    hostname: string;
    ipv4?: string;
    port: number;
  },
): boolean {
  return value.ok === true && value.mode === expected.mode && value.runId === expected.runId &&
    value.testId === SBX039_TEST_ID && value.caseId === expected.caseId &&
    value.endpointHostname === expected.hostname && value.pinnedPort === expected.port &&
    (expected.ipv4 === undefined || value.pinnedIPv4 === expected.ipv4) && value.attemptCount === 1 &&
    value.retryCount === 0 && value.rawConfigurationRetained === false &&
    value.rawServerNameRetained === false && value.rawOperatorSecretRetained === false;
}

function exactHttps(value: Sbx039HttpsEvidence, runId: string, caseId: string, hostname: string): boolean {
  return exactProbe(value as Sbx039ProbeEvidence, {
    mode: "https-control", runId, caseId, hostname, port: 443,
  }) && value.endpointRole === "allowed" && value.tcpConnected === true &&
    value.receivedResponse === true && value.statusCode === 200 && value.timedOut === false;
}

function expectedReceipt(
  value: Sbx039ReceiverStatus,
  expected: {
    runId: string;
    caseId: string;
    mode: Exclude<Sbx039ProbeMode, "https-control">;
    operationId: string;
    epoch: string;
    hostname: string;
    ipv4: string;
    port: number;
    secret?: boolean;
  },
): boolean {
  return value.configured === true && value.runId === expected.runId && value.caseId === expected.caseId &&
    value.mode === expected.mode && value.connectionCount === 1 && value.greetingWriteCount === 1 &&
    value.exactPayloadReceiptCount === 1 && value.operationId === expected.operationId &&
    value.withinConfiguredWindow === true && value.listenerHostname === expected.hostname &&
    value.listenerIPv4 === expected.ipv4 && value.listenerPort === expected.port &&
    value.configurationEpoch === expected.epoch && value.malformedCount === 0 &&
    value.secretCommitmentMatched === (expected.secret === true) && value.rawInboundStored === false &&
    value.rawServerNameStored === false && value.rawSecretStored === false && value.payloadDigestStored === false;
}

function noReceipt(value: Sbx039ReceiverStatus, expected: {
  runId: string;
  caseId: string;
  mode: Exclude<Sbx039ProbeMode, "https-control">;
  epoch: string;
  hostname: string;
  ipv4: string;
  port: number;
}, requireNoConnection: boolean): boolean {
  return value.configured === true && value.runId === expected.runId && value.caseId === expected.caseId &&
    value.mode === expected.mode && (!requireNoConnection || value.connectionCount === 0) &&
    value.exactPayloadReceiptCount === 0 && value.operationId === undefined && value.malformedCount === 0 &&
    value.listenerHostname === expected.hostname && value.listenerIPv4 === expected.ipv4 &&
    value.listenerPort === expected.port && value.configurationEpoch === expected.epoch &&
    value.withinConfiguredWindow === true && value.secretCommitmentMatched === false && value.rawInboundStored === false &&
    value.rawServerNameStored === false && value.rawSecretStored === false && value.payloadDigestStored === false;
}

function blockedOrSilent(value: Sbx039ProbeEvidence): boolean {
  return value.clientHelloSent === false || value.errorCode !== undefined || value.receivedResponse === false;
}

export function assessSbx039Public(input: Sbx039PublicAssessmentInput): Sbx039Assessment {
  const signals: string[] = [];
  const topology = uuidPattern.test(input.runId) && input.identityAndScopePassed && input.distinctAddressSetsPassed &&
    input.allowedHostname !== input.deniedHostname && input.deniedPort >= 1 && input.deniedPort <= 65_535;
  const outsideOperation = input.expectedOperations[SBX039_PUBLIC_CASES.outsideCoalesced] ?? "";
  const allowDirectOperation = input.expectedOperations[SBX039_PUBLIC_CASES.allowAllDirectTls] ?? "";
  const allowSplitOperation = input.expectedOperations[SBX039_PUBLIC_CASES.allowAllSplit] ?? "";
  const allowCoalescedOperation = input.expectedOperations[SBX039_PUBLIC_CASES.allowAllCoalesced] ?? "";
  const splitOperation = input.expectedOperations[SBX039_PUBLIC_CASES.deniedSplit] ?? "";
  const targetOperation = input.expectedOperations[SBX039_PUBLIC_CASES.deniedCoalesced] ?? "";
  const idsValid = [outsideOperation, allowDirectOperation, allowSplitOperation, allowCoalescedOperation, splitOperation, targetOperation]
    .every((value) => operationPattern.test(value));
  const receiverBase = {
    runId: input.runId,
    epoch: input.expectedConfigurationEpoch,
    hostname: input.deniedHostname,
    ipv4: input.deniedIPv4,
    port: input.deniedPort,
  };
  const outsidePassed = exactProbe(input.outsideCoalesced, {
    mode: "mysql-coalesced-public", runId: input.runId, caseId: SBX039_PUBLIC_CASES.outsideCoalesced,
    hostname: input.deniedHostname, ipv4: input.deniedIPv4, port: input.deniedPort,
  }) && input.outsideCoalesced.validGreetingReceived && input.outsideCoalesced.greetingTagMatched &&
    input.outsideCoalesced.sslRequestExact && input.outsideCoalesced.clientHelloSent &&
    input.outsideCoalesced.explicitSocketWriteCount === 1 && expectedReceipt(input.outsideCoalescedReceiver, {
      ...receiverBase, caseId: SBX039_PUBLIC_CASES.outsideCoalesced, mode: "mysql-coalesced-public",
      operationId: outsideOperation,
    });
  const allowDirectPassed = exactProbe(input.allowAllDirectTls, {
    mode: "direct-tls", runId: input.runId, caseId: SBX039_PUBLIC_CASES.allowAllDirectTls,
    hostname: input.deniedHostname, ipv4: input.deniedIPv4, port: input.deniedPort,
  }) && input.allowAllDirectTls.clientHelloSent && expectedReceipt(input.allowAllDirectTlsReceiver, {
    ...receiverBase, caseId: SBX039_PUBLIC_CASES.allowAllDirectTls, mode: "direct-tls",
    operationId: allowDirectOperation,
  });
  const allowCoalescedPassed = exactProbe(input.allowAllCoalesced, {
    mode: "mysql-coalesced-public", runId: input.runId, caseId: SBX039_PUBLIC_CASES.allowAllCoalesced,
    hostname: input.deniedHostname, ipv4: input.deniedIPv4, port: input.deniedPort,
  }) && input.allowAllCoalesced.validGreetingReceived && input.allowAllCoalesced.greetingTagMatched &&
    input.allowAllCoalesced.sslRequestExact && input.allowAllCoalesced.clientHelloSent &&
    input.allowAllCoalesced.explicitSocketWriteCount === 1 && expectedReceipt(input.allowAllCoalescedReceiver, {
      ...receiverBase, caseId: SBX039_PUBLIC_CASES.allowAllCoalesced, mode: "mysql-coalesced-public",
      operationId: allowCoalescedOperation,
    });
  const allowSplitPassed = exactProbe(input.allowAllSplit, {
    mode: "mysql-split-public", runId: input.runId, caseId: SBX039_PUBLIC_CASES.allowAllSplit,
    hostname: input.deniedHostname, ipv4: input.deniedIPv4, port: input.deniedPort,
  }) && input.allowAllSplit.validGreetingReceived && input.allowAllSplit.greetingTagMatched &&
    input.allowAllSplit.sslRequestExact && input.allowAllSplit.clientHelloSent &&
    input.allowAllSplit.explicitSocketWriteCount === 2 && input.allowAllSplit.interWriteDelayMs === 250 &&
    expectedReceipt(input.allowAllSplitReceiver, {
      ...receiverBase, caseId: SBX039_PUBLIC_CASES.allowAllSplit, mode: "mysql-split-public",
      operationId: allowSplitOperation,
    });
  const allowedHttpsPassed = exactHttps(
    input.allowedHttps, input.runId, SBX039_PUBLIC_CASES.allowedHttps, input.allowedHostname,
  );
  const directNegative = exactProbe(input.deniedDirectTls, {
    mode: "direct-tls", runId: input.runId, caseId: SBX039_PUBLIC_CASES.deniedDirectTls,
    hostname: input.deniedHostname, ipv4: input.deniedIPv4, port: input.deniedPort,
  }) && noReceipt(input.deniedDirectTlsReceiver, {
    ...receiverBase, caseId: SBX039_PUBLIC_CASES.deniedDirectTls, mode: "direct-tls",
  }, true);
  const rawNegative = exactProbe(input.deniedRaw, {
    mode: "raw-public", runId: input.runId, caseId: SBX039_PUBLIC_CASES.deniedRaw,
    hostname: input.deniedHostname, ipv4: input.deniedIPv4, port: input.deniedPort,
  }) && noReceipt(input.deniedRawReceiver, {
    ...receiverBase, caseId: SBX039_PUBLIC_CASES.deniedRaw, mode: "raw-public",
  }, true);
  const postNegative = exactProbe(input.deniedPostDirectTls, {
    mode: "direct-tls", runId: input.runId, caseId: SBX039_PUBLIC_CASES.deniedPostDirectTls,
    hostname: input.deniedHostname, ipv4: input.deniedIPv4, port: input.deniedPort,
  }) && noReceipt(input.deniedPostDirectTlsReceiver, {
    ...receiverBase, caseId: SBX039_PUBLIC_CASES.deniedPostDirectTls, mode: "direct-tls",
  }, true);
  const splitBase = exactProbe(input.deniedSplit, {
    mode: "mysql-split-public", runId: input.runId, caseId: SBX039_PUBLIC_CASES.deniedSplit,
    hostname: input.deniedHostname, ipv4: input.deniedIPv4, port: input.deniedPort,
  });
  const splitReceipt = splitBase && expectedReceipt(input.deniedSplitReceiver, {
    ...receiverBase, caseId: SBX039_PUBLIC_CASES.deniedSplit, mode: "mysql-split-public", operationId: splitOperation,
  });
  const splitNoReceipt = splitBase && noReceipt(input.deniedSplitReceiver, {
    ...receiverBase, caseId: SBX039_PUBLIC_CASES.deniedSplit, mode: "mysql-split-public",
  }, false);
  const targetBase = exactProbe(input.deniedCoalesced, {
    mode: "mysql-coalesced-public", runId: input.runId, caseId: SBX039_PUBLIC_CASES.deniedCoalesced,
    hostname: input.deniedHostname, ipv4: input.deniedIPv4, port: input.deniedPort,
  });
  const targetReceipt = targetBase && input.deniedCoalesced.validGreetingReceived &&
    input.deniedCoalesced.greetingTagMatched && input.deniedCoalesced.sslRequestExact &&
    input.deniedCoalesced.clientHelloSent && input.deniedCoalesced.explicitSocketWriteCount === 1 &&
    expectedReceipt(input.deniedCoalescedReceiver, {
      ...receiverBase, caseId: SBX039_PUBLIC_CASES.deniedCoalesced, mode: "mysql-coalesced-public",
      operationId: targetOperation,
    });
  const targetNoReceipt = targetBase && noReceipt(input.deniedCoalescedReceiver, {
    ...receiverBase, caseId: SBX039_PUBLIC_CASES.deniedCoalesced, mode: "mysql-coalesced-public",
  }, false);
  const targetReach = targetBase && input.deniedCoalesced.validGreetingReceived &&
    input.deniedCoalesced.greetingTagMatched && input.deniedCoalescedReceiver.connectionCount === 1 &&
    input.deniedCoalescedReceiver.greetingWriteCount === 1 && input.deniedCoalescedReceiver.exactPayloadReceiptCount === 0;
  const controlsPassed = topology && idsValid && input.allowAllReadbackPassed && input.restrictedReadback.passed &&
    input.postTargetReadback.passed && outsidePassed && allowDirectPassed && allowSplitPassed && allowCoalescedPassed &&
    allowedHttpsPassed && directNegative && rawNegative && postNegative && exactRetention(input.retention);

  if (outsidePassed) signals.push("the owned MySQL listener accepted the exact coalesced flight outside Sandbox");
  if (allowCoalescedPassed) signals.push("the same coalesced flight reached B under allow-all");
  if (allowSplitPassed) signals.push("a normal split MySQL SSLRequest then ClientHello reached B under allow-all");
  if (allowedHttpsPassed) signals.push("exact allow[A] remained functional for the allowed HTTPS control");
  if (directNegative) signals.push("a direct denied-SNI ClientHello produced no B connection or receipt");
  if (rawNegative) signals.push("an immediate raw frame produced no B connection or receipt");
  if (targetReceipt) signals.push("B received the exact denied-SNI canary after its MySQL greeting and SSLRequest");

  if (input.executionError || !input.cleanupPassed) {
    return { verdict: "error", candidate: false, severity: "unknown", controlsPassed, summary: "Execution or mandatory cleanup failed.", signals };
  }
  if (!directNegative && input.deniedDirectTlsReceiver.exactPayloadReceiptCount > 0 ||
      !rawNegative && input.deniedRawReceiver.exactPayloadReceiptCount > 0) {
    return {
      verdict: "alternate-root", candidate: false, severity: "unknown", controlsPassed: false,
      summary: "A simpler direct-TLS or raw forwarding path reached B, so this run does not isolate a MySQL server-first root cause.", signals,
    };
  }
  if (controlsPassed && targetReceipt && (splitReceipt || splitNoReceipt)) {
    const variant = splitReceipt ? "server-first-upgrade" : "coalesced-upgrade";
    return {
      verdict: "candidate-public", candidate: true, severity: "medium", controlsPassed: true, variant,
      summary: splitReceipt
        ? "Exact allow[A] forwarded a denied-SNI ClientHello to B after the server-first MySQL upgrade, including when the SSLRequest and ClientHello were split."
        : "Exact allow[A] forwarded the denied-SNI ClientHello only when the MySQL SSLRequest and ClientHello were coalesced.",
      signals,
    };
  }
  if (controlsPassed && targetReach && (splitReceipt || splitNoReceipt)) {
    return {
      verdict: "candidate-reach", candidate: true, severity: "medium", controlsPassed: true,
      variant: "preauthorization-connect",
      summary: "The denied MySQL endpoint accepted a connection and its uniquely tagged server greeting reached the guest before any authorizable SNI existed, but no exact client canary reached B.",
      signals,
    };
  }
  if (controlsPassed && targetNoReceipt && splitNoReceipt && !input.deniedCoalesced.validGreetingReceived &&
      input.deniedCoalescedReceiver.connectionCount === 0) {
    return {
      verdict: "pass", candidate: false, severity: "none", controlsPassed: true,
      summary: "The firewall failed closed before contacting or forwarding bytes to denied MySQL B.", signals,
    };
  }
  return {
    verdict: "indeterminate", candidate: false, severity: "unknown", controlsPassed,
    summary: blockedOrSilent(input.deniedCoalesced)
      ? "The target was blocked, but one or more attribution controls were incomplete."
      : "The target outcome did not match a single isolated server-first forwarding variant.",
    signals,
  };
}

export function assessSbx039Secret(input: Sbx039SecretAssessmentInput): Sbx039Assessment {
  const signals: string[] = [];
  const receiverBase = {
    runId: input.runId,
    epoch: input.expectedConfigurationEpoch,
    hostname: input.deniedHostname,
    ipv4: input.deniedIPv4,
    port: input.deniedPort,
  };
  const allowedHttps = exactHttps(input.allowedHttps, input.runId, SBX039_SECRET_CASES.allowedHttps, input.allowedHostname);
  const directNegative = exactProbe(input.deniedDirectTls, {
    mode: "direct-tls", runId: input.runId, caseId: SBX039_SECRET_CASES.deniedDirectTls,
    hostname: input.deniedHostname, ipv4: input.deniedIPv4, port: input.deniedPort,
  }) && noReceipt(input.deniedDirectTlsReceiver, {
    ...receiverBase, caseId: SBX039_SECRET_CASES.deniedDirectTls, mode: "direct-tls",
  }, true);
  const postNegative = exactProbe(input.deniedPostDirectTls, {
    mode: "direct-tls", runId: input.runId, caseId: SBX039_SECRET_CASES.deniedPostDirectTls,
    hostname: input.deniedHostname, ipv4: input.deniedIPv4, port: input.deniedPort,
  }) && noReceipt(input.deniedPostDirectTlsReceiver, {
    ...receiverBase, caseId: SBX039_SECRET_CASES.deniedPostDirectTls, mode: "direct-tls",
  }, true);
  const targetProbe = exactProbe(input.deniedCoalesced, {
    mode: "mysql-coalesced-secret", runId: input.runId, caseId: SBX039_SECRET_CASES.deniedCoalesced,
    hostname: input.deniedHostname, ipv4: input.deniedIPv4, port: input.deniedPort,
  }) && input.deniedCoalesced.validGreetingReceived && input.deniedCoalesced.greetingTagMatched &&
    input.deniedCoalesced.sslRequestExact && input.deniedCoalesced.clientHelloSent &&
    input.deniedCoalesced.explicitSocketWriteCount === 1 &&
    input.deniedCoalesced.operatorSecretFileValidated === true && input.deniedCoalesced.operatorSecretFileMode === 0o600;
  const targetReceipt = targetProbe && operationPattern.test(input.expectedSecretOperationId) &&
    expectedReceipt(input.deniedCoalescedReceiver, {
      ...receiverBase, caseId: SBX039_SECRET_CASES.deniedCoalesced, mode: "mysql-coalesced-secret",
      operationId: input.expectedSecretOperationId, secret: true,
    });
  const publicAt = Date.parse(input.publicControlsCompletedAt);
  const createdAt = Date.parse(input.operatorSecretCreatedAt);
  const writtenAt = Date.parse(input.operatorSecretWrittenAt);
  const receiptAt = input.secretReceiptAt === undefined ? Number.NaN : Date.parse(input.secretReceiptAt);
  const ordered = [publicAt, createdAt, writtenAt, receiptAt].every(Number.isFinite) &&
    publicAt <= createdAt && createdAt <= writtenAt && writtenAt <= receiptAt;
  const controlsPassed = input.priorPublicCandidate && uuidPattern.test(input.publicRunId) && uuidPattern.test(input.runId) &&
    input.publicRunId !== input.runId && input.publicSandboxId.length > 0 && input.sandboxId.length > 0 &&
    input.publicSandboxId !== input.sandboxId && input.identityAndScopePassed && input.distinctAddressSetsPassed &&
    input.restrictedReadback.passed && input.postTargetReadback.passed && allowedHttps && directNegative && postNegative &&
    input.operatorSecretStagedMode0600 && exactRetention(input.retention) && ordered;

  if (allowedHttps) signals.push("the fresh secret sandbox retained exact allowed-A connectivity");
  if (directNegative && postNegative) signals.push("direct denied-SNI controls remained absent before and after the target");
  if (targetReceipt) signals.push("B matched the exact file-backed secret commitment from the denied ClientHello SNI");

  if (input.executionError || !input.cleanupPassed) {
    return { verdict: "error", candidate: false, severity: "unknown", controlsPassed, summary: "Secret-stage execution or cleanup failed.", signals };
  }
  if (controlsPassed && targetReceipt) {
    return {
      verdict: "candidate-high", candidate: true, severity: "high", controlsPassed: true,
      summary: "A fresh restricted sandbox exfiltrated one exact mode-0600 synthetic file secret to denied MySQL B inside the pre-authorization ClientHello SNI.",
      signals,
    };
  }
  return {
    verdict: "indeterminate", candidate: false, severity: "unknown", controlsPassed,
    summary: "The fresh-secret proof or a mandatory isolation control was incomplete.", signals,
  };
}

export function isSbx039Canary(value: string): boolean {
  return hexCanaryPattern.test(value);
}

export function safeCommitmentEqual(left: string, right: string): boolean {
  if (!commitmentPattern.test(left) || !commitmentPattern.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}
