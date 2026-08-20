export const SBX044_TEST_ID = "SBX-044-POC" as const;
export const SBX044_ALLOWED_HOST = "s44a.one.form-app.app" as const;
export const SBX044_DENIED_HOST = "s44a.one.two.form-app.app" as const;
export const SBX044_WILDCARD_PATTERN = "s44a.*.form-app.app" as const;
export const SBX044_TRANSFORM_HEADER = "x-sbx044-brokered-secret" as const;
export const SBX044_REDACTED_VALUE = "<redacted>" as const;

export type Sbx044Role = "allowed" | "denied";
export type Sbx044CaseId =
  | "outside-pre-allowed"
  | "outside-pre-denied"
  | "baseline-allowed"
  | "baseline-denied"
  | "public-allowed-pre"
  | "public-denied"
  | "public-allowed-post"
  | "secret-allowed"
  | "secret-denied"
  | "outside-post-allowed"
  | "outside-post-denied";

export interface Sbx044ProbeEvidence {
  schemaVersion: number;
  testId: string;
  runId: string;
  caseId: string;
  correlationCanary: string;
  expectedRole: Sbx044Role;
  commandExitCode: number;
  ok: boolean;
  phase: string;
  requestHostname: string;
  requestServername: string;
  connectionAttempts: number;
  actualConnections: number;
  actualRequests: number;
  retries: number;
  redirectsFollowed: number;
  rejectUnauthorized: boolean;
  controllerConfigurableCustomTrustAccepted: boolean;
  inheritedPlatformTrustEnvironmentNames: string[];
  tcpConnected: boolean;
  tlsAuthorized: boolean;
  tlsEstablished: boolean;
  responseReceived: boolean;
  responseStatusCode?: number;
  responseRole?: Sbx044Role;
  responseBrokered?: boolean;
  responseOperationId?: string;
  remoteAddress?: string;
  remotePort?: number;
  errorCode?: string;
  errorErrno?: number;
  errorSyscall?: string;
  durationMs: number;
}

export interface Sbx044PolicyProof {
  kind: "baseline" | "public" | "secret";
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

export interface Sbx044Cleanup {
  stopped: boolean;
  deleted: boolean;
  absenceChecks: number;
  errors: string[];
}

export interface Sbx044LedgerEvent {
  ordinal: number;
  observedAt: string;
  role: Sbx044Role;
  caseId: string;
  canaryMatched: boolean;
  brokered: boolean;
  operationId: string;
}

export interface Sbx044LedgerEvidence {
  configured: boolean;
  role: Sbx044Role;
  events: Sbx044LedgerEvent[];
  rawBrokeredSecretRetained: boolean;
  brokeredSecretDigestRetained: boolean;
}

interface Sbx044Stage {
  allowed: Sbx044ProbeEvidence;
  denied: Sbx044ProbeEvidence;
  before: Sbx044PolicyProof;
  after: Sbx044PolicyProof;
  cleanup: Sbx044Cleanup;
  sessionId: string;
}

export interface Sbx044AssessmentInput {
  executionError?: string;
  expectedRunId: string;
  expectedCanaries: Record<Sbx044CaseId, string>;
  expectedOperationIds: Record<Sbx044CaseId, string> & { secretDeniedReach: string };
  expectedControllerTrustEnvironmentNames: string[];
  expectedSandboxTrustEnvironmentNames: string[];
  outsidePreflight: { allowed: Sbx044ProbeEvidence; denied: Sbx044ProbeEvidence };
  outsidePostflight: { allowed: Sbx044ProbeEvidence; denied: Sbx044ProbeEvidence };
  baseline: Sbx044Stage;
  publicStage: Sbx044Stage & { allowedAfter: Sbx044ProbeEvidence };
  secretStage?: Sbx044Stage;
  ledgers: { allowed: Sbx044LedgerEvidence; denied: Sbx044LedgerEvidence };
  ledgerCleanup: {
    allowedDeleted: boolean;
    deniedDeleted: boolean;
    allowedAbsent: boolean;
    deniedAbsent: boolean;
    errors: string[];
  };
}

export interface Sbx044Assessment {
  verdict: "pass" | "candidate-medium" | "candidate-high" | "indeterminate" | "error";
  candidate: boolean;
  severity: "none" | "medium" | "high" | "unknown";
  controlsPassed: boolean;
  publicBoundaryEscape: boolean;
  brokeredSecretDisclosed: boolean;
  summary: string;
}

const OPERATION_ID = /^w44[rs]_[A-Za-z0-9_-]{43}$/u;
const SESSION_ID = /^sbx_[A-Za-z0-9]{20,80}$/u;
const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANARY = /^c44_[A-Za-z0-9_-]{24}$/u;
const TRUST_NAMES = new Set([
  "NODE_EXTRA_CA_CERTS",
  "NODE_USE_SYSTEM_CA",
  "OPENSSL_CONF",
  "OPENSSL_MODULES",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
]);

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

export function exactAllowPolicy(value: unknown, hosts: string[]): boolean {
  const policy = object(value);
  const allow = policy?.allow;
  if (!policy || !exactKeys(policy, ["allow"]) || !Array.isArray(allow)) return false;
  return allow.length === hosts.length && new Set(allow).size === hosts.length &&
    hosts.every((host) => allow.includes(host));
}

export function exactWildcardPolicy(value: unknown, pattern: string): boolean {
  const policy = object(value);
  return policy !== undefined && exactKeys(policy, ["allow"]) && Array.isArray(policy.allow) &&
    policy.allow.length === 1 && policy.allow[0] === pattern;
}

export function exactTransformPolicy(value: unknown, pattern: string, expectedValue: string): boolean {
  const policy = object(value);
  const allow = object(policy?.allow);
  if (!policy || !allow || !exactKeys(policy, ["allow"]) || !exactKeys(allow, [pattern])) return false;
  const rules = allow[pattern];
  if (!Array.isArray(rules) || rules.length !== 1) return false;
  const rule = object(rules[0]);
  if (!rule || !exactKeys(rule, ["transform"]) || !Array.isArray(rule.transform) || rule.transform.length !== 1) return false;
  const transform = object(rule.transform[0]);
  const headers = object(transform?.headers);
  return transform !== undefined && headers !== undefined && exactKeys(transform, ["headers"]) &&
    exactKeys(headers, [SBX044_TRANSFORM_HEADER]) && headers[SBX044_TRANSFORM_HEADER] === expectedValue;
}

function exactTrustNames(actual: string[], expected: string[]): boolean {
  const valid = actual.every((name) => TRUST_NAMES.has(name));
  const sorted = [...actual].sort();
  const wanted = [...expected].sort();
  return valid && new Set(actual).size === actual.length && actual.join(",") === sorted.join(",") &&
    sorted.length === wanted.length && sorted.every((name, index) => name === wanted[index]);
}

function expectedHost(role: Sbx044Role): string {
  return role === "allowed" ? SBX044_ALLOWED_HOST : SBX044_DENIED_HOST;
}

function exactLedgerEvent(
  ledger: Sbx044LedgerEvidence,
  role: Sbx044Role,
  caseId: Sbx044CaseId,
  operationId: string,
  brokered: boolean,
): boolean {
  const caseEvents = ledger.events.filter((event) => event.caseId === caseId);
  const event = caseEvents[0];
  return ledger.configured && ledger.role === role && !ledger.rawBrokeredSecretRetained &&
    !ledger.brokeredSecretDigestRetained && caseEvents.length === 1 && event !== undefined &&
    event.role === role && event.canaryMatched && event.operationId === operationId &&
    event.brokered === brokered && Number.isInteger(event.ordinal) && event.ordinal > 0 &&
    !Number.isNaN(Date.parse(event.observedAt));
}

function ledgerShapePassed(input: Sbx044AssessmentInput): boolean {
  const allowedCases = new Set<Sbx044CaseId>([
    "outside-pre-allowed", "baseline-allowed", "public-allowed-pre",
    "public-allowed-post", "outside-post-allowed",
    ...(input.secretStage ? ["secret-allowed" as const] : []),
  ]);
  const deniedCases = new Set<Sbx044CaseId>([
    "outside-pre-denied", "baseline-denied", "public-denied", "outside-post-denied",
    ...(input.secretStage ? ["secret-denied" as const] : []),
  ]);
  const exactLedger = (ledger: Sbx044LedgerEvidence, role: Sbx044Role, cases: Set<Sbx044CaseId>): boolean =>
    ledger.configured === true && ledger.role === role && ledger.rawBrokeredSecretRetained === false &&
    ledger.brokeredSecretDigestRetained === false && ledger.events.every((event) =>
      event.role === role && cases.has(event.caseId as Sbx044CaseId) && Number.isInteger(event.ordinal) &&
      event.ordinal > 0 && !Number.isNaN(Date.parse(event.observedAt)) && event.canaryMatched === true &&
      typeof event.brokered === "boolean" && OPERATION_ID.test(event.operationId)
    ) && new Set(ledger.events.map((event) => event.ordinal)).size === ledger.events.length &&
    new Set(ledger.events.map((event) => event.caseId)).size === ledger.events.length;
  return exactLedger(input.ledgers.allowed, "allowed", allowedCases) &&
    exactLedger(input.ledgers.denied, "denied", deniedCases);
}

function noLedgerEvent(ledger: Sbx044LedgerEvidence, caseId: Sbx044CaseId): boolean {
  return ledger.events.every((event) => event.caseId !== caseId);
}

function exactSuccess(
  probe: Sbx044ProbeEvidence,
  input: Sbx044AssessmentInput,
  caseId: Sbx044CaseId,
  role: Sbx044Role,
  brokered: boolean,
  trustNames: string[],
  operationOverride?: string,
): boolean {
  const operationId = operationOverride ?? input.expectedOperationIds[caseId];
  const ledger = role === "allowed" ? input.ledgers.allowed : input.ledgers.denied;
  return probe.schemaVersion === 1 && probe.testId === SBX044_TEST_ID &&
    probe.runId === input.expectedRunId && probe.caseId === caseId &&
    probe.correlationCanary === input.expectedCanaries[caseId] &&
    probe.expectedRole === role && probe.commandExitCode === 0 && probe.ok && probe.phase === "response" &&
    probe.requestHostname === expectedHost(role) && probe.requestServername === expectedHost(role) &&
    probe.connectionAttempts === 1 && probe.actualConnections === 1 && probe.actualRequests === 1 &&
    probe.retries === 0 && probe.redirectsFollowed === 0 && probe.rejectUnauthorized &&
    !probe.controllerConfigurableCustomTrustAccepted && exactTrustNames(probe.inheritedPlatformTrustEnvironmentNames, trustNames) &&
    probe.tcpConnected && probe.tlsEstablished && probe.tlsAuthorized && probe.responseReceived &&
    probe.responseStatusCode === 200 && probe.responseRole === role && probe.responseBrokered === brokered &&
    probe.responseOperationId === operationId && OPERATION_ID.test(operationId) &&
    typeof probe.remoteAddress === "string" && probe.remoteAddress.length > 0 && probe.remotePort === 443 &&
    exactLedgerEvent(ledger, role, caseId, operationId, brokered);
}

export function conclusiveWildcardBlock(
  probe: Sbx044ProbeEvidence,
  input: Sbx044AssessmentInput,
  caseId: "public-denied" | "secret-denied",
): boolean {
  const exactConnectBlock = probe.errorCode === "EHOSTUNREACH" && probe.errorSyscall === "connect" &&
    probe.errorErrno === -113;
  const exactDnsBlock = probe.errorCode === "EAI_AGAIN" && probe.errorSyscall === "getaddrinfo" &&
    probe.errorErrno === -3001;
  const exactTransportBlock = exactConnectBlock || exactDnsBlock;
  return probe.schemaVersion === 1 && probe.testId === SBX044_TEST_ID &&
    probe.runId === input.expectedRunId && probe.caseId === caseId &&
    probe.correlationCanary === input.expectedCanaries[caseId] && probe.expectedRole === "denied" &&
    probe.commandExitCode === 0 && !probe.ok && probe.phase === "transport" &&
    probe.requestHostname === SBX044_DENIED_HOST && probe.requestServername === SBX044_DENIED_HOST &&
    probe.connectionAttempts === 1 && probe.actualConnections === 0 && probe.actualRequests === 0 &&
    probe.retries === 0 && probe.redirectsFollowed === 0 && probe.rejectUnauthorized &&
    !probe.controllerConfigurableCustomTrustAccepted &&
    exactTrustNames(probe.inheritedPlatformTrustEnvironmentNames, input.expectedSandboxTrustEnvironmentNames) &&
    !probe.tcpConnected && !probe.tlsEstablished && !probe.tlsAuthorized && !probe.responseReceived &&
    probe.remoteAddress === undefined && probe.remotePort === undefined && exactTransportBlock &&
    probe.durationMs >= 0 && probe.durationMs <= 2_500 &&
    noLedgerEvent(input.ledgers.denied, caseId);
}

function policyProofPassed(proof: Sbx044PolicyProof, expectedKind: Sbx044PolicyProof["kind"]): boolean {
  const sameSession = SESSION_ID.test(proof.initialSessionId) && proof.activeSessionId === proof.initialSessionId &&
    proof.independentSessionId === proof.initialSessionId;
  if (!sameSession || proof.kind !== expectedKind || proof.rawSecretPresentInReadbacks) return false;
  if (expectedKind === "baseline") {
    return !proof.platformRedactionMarkerPresent &&
      [proof.activeSandboxPolicy, proof.activeSessionPolicy, proof.independentSandboxPolicy, proof.independentSessionPolicy]
        .every((policy) => exactAllowPolicy(policy, [SBX044_ALLOWED_HOST, SBX044_DENIED_HOST]));
  }
  if (expectedKind === "public") {
    return !proof.platformRedactionMarkerPresent &&
      [proof.activeSandboxPolicy, proof.activeSessionPolicy, proof.independentSandboxPolicy, proof.independentSessionPolicy]
        .every((policy) => exactWildcardPolicy(policy, SBX044_WILDCARD_PATTERN));
  }
  return proof.platformRedactionMarkerPresent &&
    exactWildcardPolicy(proof.activeSandboxPolicy, SBX044_WILDCARD_PATTERN) &&
    exactTransformPolicy(proof.activeSessionPolicy, SBX044_WILDCARD_PATTERN, SBX044_REDACTED_VALUE) &&
    exactWildcardPolicy(proof.independentSandboxPolicy, SBX044_WILDCARD_PATTERN) &&
    exactTransformPolicy(proof.independentSessionPolicy, SBX044_WILDCARD_PATTERN, SBX044_REDACTED_VALUE);
}

function cleanupPassed(cleanup: Sbx044Cleanup): boolean {
  return cleanup.stopped && cleanup.deleted && cleanup.absenceChecks >= 2 && cleanup.errors.length === 0;
}

function stagePolicyPassed(stage: Sbx044Stage, kind: Sbx044PolicyProof["kind"]): boolean {
  return SESSION_ID.test(stage.sessionId) && stage.before.initialSessionId === stage.sessionId &&
    stage.after.initialSessionId === stage.sessionId && stage.before.stage === "before" &&
    stage.after.stage === "after" && policyProofPassed(stage.before, kind) &&
    policyProofPassed(stage.after, kind) && cleanupPassed(stage.cleanup);
}

function ledgerCleanupPassed(input: Sbx044AssessmentInput): boolean {
  return input.ledgerCleanup.allowedDeleted && input.ledgerCleanup.deniedDeleted &&
    input.ledgerCleanup.allowedAbsent && input.ledgerCleanup.deniedAbsent &&
    input.ledgerCleanup.errors.length === 0;
}

function distinctSessions(input: Sbx044AssessmentInput): boolean {
  const sessions = [input.baseline.sessionId, input.publicStage.sessionId];
  if (input.secretStage) sessions.push(input.secretStage.sessionId);
  return sessions.every((session) => SESSION_ID.test(session)) && new Set(sessions).size === sessions.length;
}

function exactPostflight(input: Sbx044AssessmentInput): boolean {
  return exactSuccess(
    input.outsidePostflight.allowed, input, "outside-post-allowed", "allowed", false,
    input.expectedControllerTrustEnvironmentNames,
  ) && exactSuccess(
    input.outsidePostflight.denied, input, "outside-post-denied", "denied", false,
    input.expectedControllerTrustEnvironmentNames,
  );
}

export function assessSbx044(input: Sbx044AssessmentInput): Sbx044Assessment {
  if (input.executionError) {
    return {
      verdict: "error", candidate: false, severity: "unknown", controlsPassed: false,
      publicBoundaryEscape: false, brokeredSecretDisclosed: false,
      summary: "Execution failed before a complete assessment.",
    };
  }
  const operationIds = Object.values(input.expectedOperationIds);
  const canaries = Object.values(input.expectedCanaries);
  const fixedMaterialValid = RUN_ID.test(input.expectedRunId) && operationIds.length === 12 &&
    operationIds.every((value) => OPERATION_ID.test(value)) && new Set(operationIds).size === operationIds.length &&
    canaries.length === 11 && canaries.every((value) => CANARY.test(value)) &&
    new Set(canaries).size === canaries.length;
  const outsidePreflightPassed = exactSuccess(
    input.outsidePreflight.allowed, input, "outside-pre-allowed", "allowed", false,
    input.expectedControllerTrustEnvironmentNames,
  ) && exactSuccess(
    input.outsidePreflight.denied, input, "outside-pre-denied", "denied", false,
    input.expectedControllerTrustEnvironmentNames,
  );
  const baselinePassed = stagePolicyPassed(input.baseline, "baseline") &&
    exactSuccess(
      input.baseline.allowed, input, "baseline-allowed", "allowed", false,
      input.expectedSandboxTrustEnvironmentNames,
    ) && exactSuccess(
      input.baseline.denied, input, "baseline-denied", "denied", false,
      input.expectedSandboxTrustEnvironmentNames,
    );
  const publicControls = stagePolicyPassed(input.publicStage, "public") &&
    exactSuccess(
      input.publicStage.allowed, input, "public-allowed-pre", "allowed", false,
      input.expectedSandboxTrustEnvironmentNames,
    ) && exactSuccess(
      input.publicStage.allowedAfter, input, "public-allowed-post", "allowed", false,
      input.expectedSandboxTrustEnvironmentNames,
    );
  const globalControls = fixedMaterialValid && outsidePreflightPassed && baselinePassed && publicControls &&
    distinctSessions(input) && exactPostflight(input) && ledgerShapePassed(input) &&
    (!input.secretStage || cleanupPassed(input.secretStage.cleanup)) && ledgerCleanupPassed(input);
  if (!globalControls) {
    return {
      verdict: "indeterminate", candidate: false, severity: "unknown", controlsPassed: false,
      publicBoundaryEscape: false, brokeredSecretDisclosed: false,
      summary: "A keyed endpoint, policy, same-session, cleanup, or postflight control failed.",
    };
  }
  const publicBoundaryEscape = exactSuccess(
    input.publicStage.denied, input, "public-denied", "denied", false,
    input.expectedSandboxTrustEnvironmentNames,
  );
  const publicBlocked = conclusiveWildcardBlock(input.publicStage.denied, input, "public-denied");
  if (!publicBoundaryEscape && !publicBlocked) {
    return {
      verdict: "indeterminate", candidate: false, severity: "unknown", controlsPassed: true,
      publicBoundaryEscape: false, brokeredSecretDisclosed: false,
      summary: "The deeper-host result was neither an exact keyed receipt nor an attributable pre-connect block.",
    };
  }
  if (publicBlocked) {
    return {
      verdict: "pass", candidate: false, severity: "none", controlsPassed: true,
      publicBoundaryEscape: false, brokeredSecretDisclosed: false,
      summary: "The documented one-label wildcard matched A and blocked the deeper B hostname.",
    };
  }
  const secret = input.secretStage;
  if (!secret) {
    return {
      verdict: "candidate-medium", candidate: true, severity: "medium", controlsPassed: true,
      publicBoundaryEscape: true, brokeredSecretDisclosed: false,
      summary: "The middle wildcard matched more than one DNS label; no credential proof was attempted.",
    };
  }
  const secretControls = stagePolicyPassed(secret, "secret") &&
    exactSuccess(
      secret.allowed, input, "secret-allowed", "allowed", true,
      input.expectedSandboxTrustEnvironmentNames,
    );
  if (!secretControls) {
    return {
      verdict: "candidate-medium", candidate: true, severity: "medium", controlsPassed: true,
      publicBoundaryEscape: true, brokeredSecretDisclosed: false,
      summary: "The public boundary escape is proven, but the fresh credential stage was inconclusive.",
    };
  }
  const brokeredSecretDisclosed = exactSuccess(
    secret.denied, input, "secret-denied", "denied", true,
    input.expectedSandboxTrustEnvironmentNames,
  );
  if (brokeredSecretDisclosed) {
    return {
      verdict: "candidate-high", candidate: true, severity: "high", controlsPassed: true,
      publicBoundaryEscape: true, brokeredSecretDisclosed: true,
      summary: "A controller-only brokered credential reached the deeper hostname outside the documented wildcard scope.",
    };
  }
  if (
    conclusiveWildcardBlock(secret.denied, input, "secret-denied") ||
    exactSuccess(
      secret.denied, input, "secret-denied", "denied", false,
      input.expectedSandboxTrustEnvironmentNames,
      input.expectedOperationIds.secretDeniedReach,
    )
  ) {
    return {
      verdict: "candidate-medium", candidate: true, severity: "medium", controlsPassed: true,
      publicBoundaryEscape: true, brokeredSecretDisclosed: false,
      summary: "The wildcard scope violation is proven, but the brokered credential was not proven at B.",
    };
  }
  return {
    verdict: "candidate-medium", candidate: true, severity: "medium", controlsPassed: true,
    publicBoundaryEscape: true, brokeredSecretDisclosed: false,
    summary: "The wildcard scope violation is proven; the optional credential stage needs review.",
  };
}
