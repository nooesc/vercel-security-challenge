import {
  OPERATION_ID_PATTERN,
  queryForCase,
  SBX049_CASES,
  SBX049_REDACTED_VALUE,
  SBX049_TEST_ID,
  SBX049_TRANSFORM_HEADER,
  type Sbx049CaseId,
} from "./protocol.js";

const SESSION_ID = /^sbx_[A-Za-z0-9_-]{20,100}$/u;
const TRUST_NAMES = new Set([
  "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF",
  "OPENSSL_MODULES", "SSL_CERT_DIR", "SSL_CERT_FILE",
]);

export interface Sbx049ProbeEvidence {
  schemaVersion: number;
  testId: string;
  runId: string;
  caseId: string;
  correlationCanary: string;
  commandExitCode: number;
  ok: boolean;
  phase: string;
  requestHostname: string;
  requestServername: string;
  requestPath: string;
  connectionAttempts: number;
  actualConnections: number;
  actualRequests: number;
  retries: number;
  redirectsFollowed: number;
  rejectUnauthorized: boolean;
  controllerConfigurableCustomTrustAccepted: boolean;
  inheritedPlatformTrustEnvironmentNames: string[];
  tcpConnected: boolean;
  tlsEstablished: boolean;
  tlsAuthorized: boolean;
  responseReceived: boolean;
  responseStatusCode?: number;
  responseShapeValid: boolean;
  responseBrokered?: boolean;
  responseOperationId?: string;
  responseBodyRetained: boolean;
  durationMs: number;
  errorCode?: string;
}

export interface Sbx049PolicyProof {
  stage: "before" | "after";
  initialSessionId: string;
  activeSessionId: string;
  independentSessionId: string;
  activeSandboxPolicy: unknown;
  activeSessionPolicy: unknown;
  independentSandboxPolicy: unknown;
  independentSessionPolicy: unknown;
  rawSecretPresentInReadbacks: boolean;
  platformRedactionMarkerPresent: boolean;
}

export interface Sbx049LedgerEvent {
  ordinal: number;
  observedAt: string;
  caseId: Sbx049CaseId;
  canaryMatched: true;
  queryMatched: true;
  brokered: boolean;
  operationId: string;
}

export interface Sbx049LedgerEvidence {
  configured: boolean;
  events: Sbx049LedgerEvent[];
  rawBrokeredSecretRetained: false;
  brokeredSecretDigestRetained: false;
}

export interface Sbx049CleanupEvidence {
  sandbox: { stopped: boolean; deleted: boolean; absenceChecks: number; errors: string[] };
  receiver: { deleted: boolean; absent: boolean; errors: string[] };
}

export interface Sbx049AssessmentInput {
  executionError?: string;
  runId: string;
  hostname: string;
  canaries: Record<Sbx049CaseId, string>;
  expectedOperationIds: Record<Sbx049CaseId, { reach: string; secret: string }>;
  probes: Record<Sbx049CaseId, Sbx049ProbeEvidence>;
  policyBefore: Sbx049PolicyProof;
  policyAfter: Sbx049PolicyProof;
  ledger: Sbx049LedgerEvidence;
  cleanup: Sbx049CleanupEvidence;
}

export interface Sbx049Assessment {
  outcome: "pass" | "candidate-high" | "indeterminate" | "error";
  candidate: boolean;
  severity: "none" | "high" | "unknown";
  controlsPassed: boolean;
  queryEntryAssociationBypassed: boolean;
  brokeredSecretProven: boolean;
  rationale: string;
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function exactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((entry, index) => entry === wanted[index]);
}

export function exactSandboxProjection(value: unknown, hostname: string): boolean {
  const policy = object(value);
  return policy !== undefined && exactKeys(policy, ["allow"]) && Array.isArray(policy.allow) &&
    policy.allow.length === 1 && policy.allow[0] === hostname;
}

export function exactQueryTransformPolicy(
  value: unknown,
  hostname: string,
  expectedHeaderValue = SBX049_REDACTED_VALUE,
): boolean {
  const policy = object(value);
  const allow = object(policy?.allow);
  if (!policy || !allow || !exactKeys(policy, ["allow"]) || !exactKeys(allow, [hostname])) return false;
  const rules = allow[hostname];
  if (!Array.isArray(rules) || rules.length !== 1) return false;
  const rule = object(rules[0]);
  const match = object(rule?.match);
  const queryString = match?.queryString;
  const transform = rule?.transform;
  if (!rule || !match || !exactKeys(rule, ["match", "transform"]) ||
      !exactKeys(match, ["queryString"]) || !Array.isArray(queryString) || queryString.length !== 1 ||
      !Array.isArray(transform) || transform.length !== 1) return false;
  const entry = object(queryString[0]);
  const key = object(entry?.key);
  const matcherValue = object(entry?.value);
  if (!entry || !key || !matcherValue || !exactKeys(entry, ["key", "value"]) ||
      !exactKeys(key, ["exact"]) || !exactKeys(matcherValue, ["exact"]) ||
      key.exact !== "role" || matcherValue.exact !== "privileged") return false;
  const transformEntry = object(transform[0]);
  const headers = object(transformEntry?.headers);
  return transformEntry !== undefined && headers !== undefined && exactKeys(transformEntry, ["headers"]) &&
    exactKeys(headers, [SBX049_TRANSFORM_HEADER]) && headers[SBX049_TRANSFORM_HEADER] === expectedHeaderValue;
}

/**
 * The session API currently projects the configured transform but omits its
 * request matcher. Keep that projection exact and prove matcher enforcement
 * with the request matrix: exact-pair must broker while each isolated half
 * must remain unbrokered. If creation dropped the matcher entirely, those
 * half-controls would fail and a candidate would be impossible.
 */
export function exactQueryTransformReadbackProjection(
  value: unknown,
  hostname: string,
  expectedHeaderValue = SBX049_REDACTED_VALUE,
): boolean {
  if (exactQueryTransformPolicy(value, hostname, expectedHeaderValue)) return true;
  const policy = object(value);
  const allow = object(policy?.allow);
  if (!policy || !allow || !exactKeys(policy, ["allow"]) || !exactKeys(allow, [hostname])) return false;
  const rules = allow[hostname];
  if (!Array.isArray(rules) || rules.length !== 1) return false;
  const rule = object(rules[0]);
  if (!rule || !exactKeys(rule, ["transform"]) || !Array.isArray(rule.transform) ||
      rule.transform.length !== 1) return false;
  const transformEntry = object(rule.transform[0]);
  const headers = object(transformEntry?.headers);
  return transformEntry !== undefined && headers !== undefined &&
    exactKeys(transformEntry, ["headers"]) && exactKeys(headers, [SBX049_TRANSFORM_HEADER]) &&
    headers[SBX049_TRANSFORM_HEADER] === expectedHeaderValue;
}

export function exactPolicyProof(proof: Sbx049PolicyProof, hostname: string): boolean {
  if (proof.stage !== "before" && proof.stage !== "after") return false;
  return SESSION_ID.test(proof.initialSessionId) && proof.activeSessionId === proof.initialSessionId &&
    proof.independentSessionId === proof.initialSessionId && !proof.rawSecretPresentInReadbacks &&
    proof.platformRedactionMarkerPresent &&
    exactSandboxProjection(proof.activeSandboxPolicy, hostname) &&
    exactQueryTransformReadbackProjection(proof.activeSessionPolicy, hostname) &&
    exactSandboxProjection(proof.independentSandboxPolicy, hostname) &&
    exactQueryTransformReadbackProjection(proof.independentSessionPolicy, hostname);
}

function trustNamesValid(names: string[]): boolean {
  const sorted = [...names].sort();
  return names.every((name) => TRUST_NAMES.has(name)) && new Set(names).size === names.length &&
    names.join(",") === sorted.join(",");
}

function exactEvent(
  ledger: Sbx049LedgerEvidence,
  caseId: Sbx049CaseId,
  operationId: string,
  brokered: boolean,
): boolean {
  const matches = ledger.events.filter((event) => event.caseId === caseId);
  const event = matches[0];
  return matches.length === 1 && event !== undefined && event.canaryMatched && event.queryMatched &&
    event.brokered === brokered && event.operationId === operationId &&
    Number.isInteger(event.ordinal) && event.ordinal > 0 && !Number.isNaN(Date.parse(event.observedAt));
}

function exactProbe(
  input: Sbx049AssessmentInput,
  caseId: Sbx049CaseId,
  operationId: string,
  brokered: boolean,
): boolean {
  const probe = input.probes[caseId];
  return probe.schemaVersion === 1 && probe.testId === SBX049_TEST_ID && probe.runId === input.runId &&
    probe.caseId === caseId && probe.correlationCanary === input.canaries[caseId] &&
    probe.commandExitCode === 0 && probe.ok && probe.phase === "response" &&
    probe.requestHostname === input.hostname && probe.requestServername === input.hostname &&
    probe.requestPath === `/v1/sbx049/action?${queryForCase(input.runId, caseId, input.canaries[caseId])}` &&
    probe.connectionAttempts === 1 && probe.actualConnections === 1 && probe.actualRequests === 1 &&
    probe.retries === 0 && probe.redirectsFollowed === 0 && probe.rejectUnauthorized &&
    !probe.controllerConfigurableCustomTrustAccepted && trustNamesValid(probe.inheritedPlatformTrustEnvironmentNames) &&
    probe.tcpConnected && probe.tlsEstablished && probe.tlsAuthorized && probe.responseReceived &&
    probe.responseStatusCode === 200 && probe.responseShapeValid && probe.responseBrokered === brokered &&
    probe.responseOperationId === operationId && !probe.responseBodyRetained && probe.durationMs >= 0 &&
    exactEvent(input.ledger, caseId, operationId, brokered);
}

function ledgerShapeValid(ledger: Sbx049LedgerEvidence): boolean {
  return ledger.configured && !ledger.rawBrokeredSecretRetained && !ledger.brokeredSecretDigestRetained &&
    ledger.events.length === SBX049_CASES.length &&
    new Set(ledger.events.map((event) => event.caseId)).size === SBX049_CASES.length &&
    new Set(ledger.events.map((event) => event.ordinal)).size === SBX049_CASES.length &&
    ledger.events.every((event, index) => event.caseId === SBX049_CASES[index] && event.ordinal === index + 1 &&
      OPERATION_ID_PATTERN.test(event.operationId) && event.canaryMatched && event.queryMatched &&
      Number.isInteger(event.ordinal) && event.ordinal > 0 && !Number.isNaN(Date.parse(event.observedAt)));
}

function cleanupPassed(cleanup: Sbx049CleanupEvidence): boolean {
  return cleanup.sandbox.stopped && cleanup.sandbox.deleted && cleanup.sandbox.absenceChecks >= 2 &&
    cleanup.sandbox.errors.length === 0 && cleanup.receiver.deleted && cleanup.receiver.absent &&
    cleanup.receiver.errors.length === 0;
}

export function assessSbx049(input: Sbx049AssessmentInput): Sbx049Assessment {
  if (input.executionError || !cleanupPassed(input.cleanup)) {
    return {
      outcome: "error", candidate: false, severity: "unknown", controlsPassed: false,
      queryEntryAssociationBypassed: false, brokeredSecretProven: false,
      rationale: input.executionError ?? "strict sandbox or receiver cleanup did not complete",
    };
  }
  const policies = exactPolicyProof(input.policyBefore, input.hostname) &&
    exactPolicyProof(input.policyAfter, input.hostname);
  const ledger = ledgerShapeValid(input.ledger);
  const positive = exactProbe(input, "exact-pair", input.expectedOperationIds["exact-pair"].secret, true);
  const keyHalf = exactProbe(input, "key-half", input.expectedOperationIds["key-half"].reach, false);
  const valueHalf = exactProbe(input, "value-half", input.expectedOperationIds["value-half"].reach, false);
  const controlsPassed = policies && ledger && positive && keyHalf && valueHalf;
  if (!controlsPassed) {
    return {
      outcome: "indeterminate", candidate: false, severity: "unknown", controlsPassed: false,
      queryEntryAssociationBypassed: false, brokeredSecretProven: false,
      rationale: "policy readbacks, positive transform, or isolated half controls were not exact",
    };
  }
  if (exactProbe(
    input,
    "combined-halves",
    input.expectedOperationIds["combined-halves"].secret,
    true,
  )) {
    return {
      outcome: "candidate-high", candidate: true, severity: "high", controlsPassed: true,
      queryEntryAssociationBypassed: true, brokeredSecretProven: true,
      rationale: "role=user and decoy=privileged received the controller-only credential transform even though neither query entry satisfied both matcher halves",
    };
  }
  if (exactProbe(
    input,
    "combined-halves",
    input.expectedOperationIds["combined-halves"].reach,
    false,
  )) {
    return {
      outcome: "pass", candidate: false, severity: "none", controlsPassed: true,
      queryEntryAssociationBypassed: false, brokeredSecretProven: false,
      rationale: "key and value remained bound to the same query entry",
    };
  }
  return {
    outcome: "indeterminate", candidate: false, severity: "unknown", controlsPassed: true,
    queryEntryAssociationBypassed: false, brokeredSecretProven: false,
    rationale: "the decisive combined-halves response was absent or did not match either exact operation proof",
  };
}
