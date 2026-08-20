import {
  armPath,
  CANARY_PATTERN,
  OPERATION_ID_PATTERN,
  proxyAudience,
  requestPath,
  RUN_ID_PATTERN,
  SBX050_CASES,
  SBX050_CREDENTIAL_HEADER,
  SBX050_EVENT_CASES,
  SBX050_PUBLIC_TRIGGER,
  SBX050_REDACTED_VALUE,
  SBX050_TEST_ID,
  SBX050_TRIGGER_HEADER,
  SBX050_TRIGGER_MARKER,
  type Sbx050CaseId,
  type Sbx050EventCaseId,
  type Sbx050Role,
} from "./protocol.js";

const SESSION_ID = /^sbx_[A-Za-z0-9_-]{20,100}$/u;
const ELIGIBLE_ALIAS = "swve@wearehackerone.com";
const TEAM_ID = /^team_[A-Za-z0-9_-]{8,100}$/u;
const PROJECT_ID = /^prj_[A-Za-z0-9_-]{8,100}$/u;
export const SBX050_SEMANTICS_QUESTION =
  "For multiple record-form rules on one domain, are all match predicates evaluated against the guest’s original request before any transform, or may a header injected by one rule satisfy a separate forwardURL rule? Do array order or injection-before-forward phases have defined semantics?";
const NOT_REPORTABLE = {
  reportReady: false as const,
  reportabilityStatus: "not-reportable" as const,
  semanticsClarificationRequired: false,
};
const CONDITIONAL_HOLD = {
  reportReady: false as const,
  reportabilityStatus: "hold-pending-semantics-clarification" as const,
  semanticsClarificationRequired: true,
};
const TRUST_NAMES = new Set([
  "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF",
  "OPENSSL_MODULES", "SSL_CERT_DIR", "SSL_CERT_FILE",
]);

export type Sbx050PolicyStage = "public-forward" | "transform-alone" | "final-before" | "final-after";

export type Sbx050PolicyProjectionMode = "not-final" | "exact-matchers" | "matcherless-redacted";
export type Sbx050DiagnosticProjectionMode = Sbx050PolicyProjectionMode | "undetermined";
export type Sbx050PolicyReadbackCode =
  | "not-observed"
  | "exact-top-host-list"
  | "exact-public-forward"
  | "exact-transform-alone"
  | "exact-final-matchers"
  | "exact-final-matcherless-redacted"
  | "unexpected";
export type Sbx050IdentityReadbackCode = "not-observed" | "exact" | "unexpected";

export interface Sbx050PolicyReadbackDiagnostic {
  stage: Sbx050PolicyStage;
  configuredPolicy: Sbx050PolicyReadbackCode;
  activeSandboxPolicy: Sbx050PolicyReadbackCode;
  activeSessionPolicy: Sbx050PolicyReadbackCode;
  independentSandboxPolicy: Sbx050PolicyReadbackCode;
  independentSessionPolicy: Sbx050PolicyReadbackCode;
  activeIdentity: Sbx050IdentityReadbackCode;
  independentIdentity: Sbx050IdentityReadbackCode;
  projectionMode: Sbx050DiagnosticProjectionMode;
  continuationAllowed: boolean;
  containsSecrets: false;
}

export interface Sbx050ExpectedIdentity {
  aliasEmail: string;
  aliasIdentityVerified: boolean;
  teamId: string;
  projectId: string;
  sandboxName: string;
  sessionId: string;
}

export interface Sbx050ProbeEvidence {
  schemaVersion: number;
  testId: string;
  runId: string;
  caseId: string;
  correlationCanary: string;
  commandExitCode: number;
  startedAt: string;
  completedAt: string;
  ok: boolean;
  phase: string;
  requestHostname: string;
  requestServername: string;
  requestPath: string;
  sentCredentialHeader: boolean;
  sentHiddenTriggerHeader: boolean;
  sentPublicTriggerHeader: boolean;
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
  responseRole?: Sbx050Role;
  responseCredentialMatched?: boolean;
  responseTriggerMatched?: boolean;
  responseOidcVerified?: boolean;
  responseOperationId?: string;
  responseBodyRetained: boolean;
  timedOut: boolean;
  durationMs: number;
  errorCode?: string;
  errorSyscall?: string;
  errorErrno?: number;
  errorClass?: "dns-resolution" | "connection-reset" | "route-unreachable";
  controllerIdentity: Sbx050ExpectedIdentity;
}

export interface Sbx050PolicyProof {
  stage: Sbx050PolicyStage;
  startedAt: string;
  completedAt: string;
  initialSessionId: string;
  activeSessionId: string;
  independentSessionId: string;
  activeSandboxPolicy: unknown;
  activeSessionPolicy: unknown;
  independentSandboxPolicy: unknown;
  independentSessionPolicy: unknown;
  rawCredentialPresentInReadbacks: boolean;
  hiddenTriggerPresentInRetainedReadbacks: boolean;
  platformRedactionMarkerPresent: boolean;
  finalHiddenMatcherComparedExactlyBeforeSanitization: boolean;
  finalHiddenMatcherMarkerPresent: boolean;
  projectionMode: Sbx050PolicyProjectionMode;
  readbackDiagnostic: Sbx050PolicyReadbackDiagnostic;
  identity: Sbx050ExpectedIdentity;
}

export interface Sbx050LedgerEvent {
  ordinal: number;
  observedAt: string;
  caseId: Sbx050EventCaseId;
  role: Sbx050Role;
  canaryMatched: true;
  originalRequestMatched: true;
  credentialHeaderCount: number;
  triggerHeaderCount: number;
  credentialMatched: boolean;
  triggerMatched: boolean;
  oidcHeaderCount: number;
  oidcOfficialVerified: boolean;
  oidcIndependentRs256Verified: boolean;
  oidcAudienceMatched: boolean;
  oidcSourceMatched: boolean;
  oidcIssuerVerified: boolean;
  oidcTemporalVerified: boolean;
  oidcIssuer?: string;
  oidcAudience?: string;
  oidcTeamId?: string;
  oidcProjectId?: string;
  oidcSessionId?: string;
  oidcSandboxName?: string;
  operationId: string;
}

export interface Sbx050LedgerEvidence {
  configured: boolean;
  configuredAt: string;
  emptyReadAt: string;
  events: Sbx050LedgerEvent[];
  unexpectedARequests: number;
  unexpectedPRequests: number;
  unattributedRequests: number;
  rawCredentialRetained: false;
  credentialDigestRetained: false;
  rawHiddenTriggerRetained: false;
  hiddenTriggerDigestRetained: false;
  rawOidcTokenRetained: false;
  oidcTokenDigestRetained: false;
  receiverRuntimeTrustExact: true;
  receiverRuntimeTrustEnvironmentNames: string[];
  receiverNodeOptionsPresent: false;
  receiverTlsVerificationDisabled: false;
}

export interface Sbx050CleanupEvidence {
  startedAt: string;
  completedAt: string;
  sandbox: { stopped: boolean; deleted: boolean; absenceChecks: number; errors: string[] };
  receiver: { deleted: boolean; absent: boolean; absenceChecks: number; errors: string[] };
}

export interface Sbx050RetentionEvidence {
  guestSourceScanned: boolean;
  guestConfigurationsScanned: boolean;
  guestArgvScanned: boolean;
  guestEnvironmentScanned: boolean;
  guestStagedFilesScanned: boolean;
  guestStdoutScanned: boolean;
  guestResultsScanned: boolean;
  controllerArtifactScanned: boolean;
  hiddenTriggerAbsentFromAllGuestMaterial: boolean;
  credentialAbsentFromAllGuestMaterial: boolean;
  rawCredentialRetained: false;
  credentialDigestRetained: false;
  rawHiddenTriggerRetained: false;
  hiddenTriggerDigestRetained: false;
  rawOidcTokenRetained: false;
  oidcTokenDigestRetained: false;
}

export interface Sbx050LocalStateEvidence {
  lockAcquired: boolean;
  lockMode: number;
  artifactMode: number;
  preexistingLockAbsent: boolean;
  lockReleased: boolean;
  recoveryJournalCreated: boolean;
  recoveryJournalMode: number;
  recoveryJournalReleased: boolean;
}

export interface Sbx050AssessmentInput {
  executionError?: string;
  runId: string;
  aOrigin: string;
  aHostname: string;
  pHostname: string;
  pOrigin: string;
  canaries: Record<Sbx050CaseId, string>;
  expectedOperationIds: Record<Sbx050EventCaseId, { pass: string; candidate?: string }>;
  expectedIdentity: Sbx050ExpectedIdentity;
  probes: Record<Sbx050CaseId, Sbx050ProbeEvidence>;
  policyProofs: Record<Sbx050PolicyStage, Sbx050PolicyProof>;
  ledger: Sbx050LedgerEvidence;
  cleanup: Sbx050CleanupEvidence;
  retention: Sbx050RetentionEvidence;
  localState: Sbx050LocalStateEvidence;
}

export interface Sbx050Assessment {
  outcome: "pass" | "candidate-high" | "indeterminate" | "error";
  candidate: boolean;
  severity: "none" | "conditional-high" | "unknown";
  controlsPassed: boolean;
  chronologyPassed: boolean;
  postTransformForwardingProven: boolean;
  credentialReceiptProven: boolean;
  reportReady: false;
  reportabilityStatus: "not-reportable" | "hold-pending-semantics-clarification";
  semanticsClarificationRequired: boolean;
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

function exactMatcher(value: unknown, expected: string): boolean {
  const matcher = object(value);
  return matcher !== undefined && exactKeys(matcher, ["exact"]) && matcher.exact === expected;
}

function topProjection(value: unknown, hostname: string): boolean {
  const policy = object(value);
  return policy !== undefined && exactKeys(policy, ["allow"]) && Array.isArray(policy.allow) &&
    policy.allow.length === 1 && policy.allow[0] === hostname;
}

function exactIdentity(actual: Sbx050ExpectedIdentity, expected: Sbx050ExpectedIdentity): boolean {
  return expected.aliasEmail === ELIGIBLE_ALIAS && expected.aliasIdentityVerified &&
    TEAM_ID.test(expected.teamId) && PROJECT_ID.test(expected.projectId) &&
    SESSION_ID.test(expected.sessionId) && expected.sandboxName.length > 0 && expected.sandboxName.length <= 256 &&
    actual.aliasEmail === expected.aliasEmail && actual.aliasIdentityVerified === true &&
    actual.teamId === expected.teamId && actual.projectId === expected.projectId &&
    actual.sessionId === expected.sessionId && actual.sandboxName === expected.sandboxName;
}

function policyRules(value: unknown, hostname: string): unknown[] | undefined {
  const policy = object(value);
  const allow = object(policy?.allow);
  if (!policy || !allow || !exactKeys(policy, ["allow"]) || !exactKeys(allow, [hostname])) return;
  return Array.isArray(allow[hostname]) ? allow[hostname] as unknown[] : undefined;
}

function exactTransformRule(value: unknown, runId: string, matcherMayBeOmitted: boolean): boolean {
  const rule = object(value);
  if (!rule || !Array.isArray(rule.transform) || rule.transform.length !== 1 ||
      !(exactKeys(rule, ["match", "transform"]) || (matcherMayBeOmitted && exactKeys(rule, ["transform"])))) return false;
  if (rule.match !== undefined) {
    const match = object(rule.match);
    if (!match || !exactKeys(match, ["path"]) || !exactMatcher(match.path, armPath(runId))) return false;
  } else if (!matcherMayBeOmitted) return false;
  const entry = object(rule.transform[0]);
  const headers = object(entry?.headers);
  return entry !== undefined && headers !== undefined && exactKeys(entry, ["headers"]) &&
    exactKeys(headers, [SBX050_CREDENTIAL_HEADER, SBX050_TRIGGER_HEADER]) &&
    headers[SBX050_CREDENTIAL_HEADER] === SBX050_REDACTED_VALUE &&
    headers[SBX050_TRIGGER_HEADER] === SBX050_REDACTED_VALUE;
}

function exactForwardRule(
  value: unknown,
  audience: string,
  trigger: string,
  matcherMayBeOmitted: boolean,
): boolean {
  const rule = object(value);
  if (!rule || rule.forwardURL !== audience ||
      !(exactKeys(rule, ["forwardURL", "match"]) || (matcherMayBeOmitted && exactKeys(rule, ["forwardURL"])))) return false;
  if (rule.match !== undefined) {
    const match = object(rule.match);
    const headers = match?.headers;
    if (!match || !exactKeys(match, ["headers"]) || !Array.isArray(headers) || headers.length !== 1) return false;
    const entry = object(headers[0]);
    return entry !== undefined && exactKeys(entry, ["key", "value"]) &&
      exactMatcher(entry.key, SBX050_TRIGGER_HEADER) && exactMatcher(entry.value, trigger);
  }
  return matcherMayBeOmitted;
}

function exactMatcherlessFinalPolicy(
  value: unknown,
  hostname: string,
  runId: string,
  pOrigin: string,
): boolean {
  const rules = policyRules(value, hostname);
  const transform = object(rules?.[0]);
  const forward = object(rules?.[1]);
  return rules?.length === 2 && transform !== undefined && forward !== undefined &&
    exactKeys(transform, ["transform"]) && exactTransformRule(transform, runId, true) &&
    exactKeys(forward, ["forwardURL"]) &&
    exactForwardRule(forward, proxyAudience(pOrigin, runId), SBX050_TRIGGER_MARKER, true);
}

export function exactPhasePolicy(
  stage: Exclude<Sbx050PolicyStage, "final-after">,
  value: unknown,
  hostname: string,
  runId: string,
  pOrigin: string,
  matcherMayBeOmitted = false,
): boolean {
  const rules = policyRules(value, hostname);
  if (!rules) return false;
  const audience = proxyAudience(pOrigin, runId);
  if (stage === "public-forward") {
    return rules.length === 1 && exactForwardRule(rules[0], audience, SBX050_PUBLIC_TRIGGER, matcherMayBeOmitted);
  }
  if (stage === "transform-alone") {
    return rules.length === 1 && exactTransformRule(rules[0], runId, matcherMayBeOmitted);
  }
  return rules.length === 2 && exactTransformRule(rules[0], runId, matcherMayBeOmitted) &&
    exactForwardRule(rules[1], audience, SBX050_TRIGGER_MARKER, matcherMayBeOmitted);
}

export function exactPolicyProof(
  proof: Sbx050PolicyProof,
  hostname: string,
  runId: string,
  pOrigin: string,
  expectedIdentity: Sbx050ExpectedIdentity,
): boolean {
  const normalizedStage = proof.stage === "final-after" ? "final-before" : proof.stage;
  const matcherMayBeOmitted = normalizedStage !== "final-before";
  const transformPresent = normalizedStage !== "public-forward";
  const finalStage = normalizedStage === "final-before";
  const expectedCode: Sbx050PolicyReadbackCode = normalizedStage === "public-forward"
    ? "exact-public-forward"
    : normalizedStage === "transform-alone"
      ? "exact-transform-alone"
      : proof.projectionMode === "exact-matchers"
        ? "exact-final-matchers"
        : "exact-final-matcherless-redacted";
  const diagnostic = proof.readbackDiagnostic;
  const finalModeValid = finalStage
    ? proof.projectionMode === "exact-matchers" || proof.projectionMode === "matcherless-redacted"
    : proof.projectionMode === "not-final";
  const diagnosticValid = diagnostic.stage === proof.stage && diagnostic.configuredPolicy === (
    finalStage ? "exact-final-matchers" : expectedCode
  ) && diagnostic.activeSessionPolicy === expectedCode &&
    diagnostic.independentSessionPolicy === expectedCode && diagnostic.activeIdentity === "exact" &&
    diagnostic.independentIdentity === "exact" && diagnostic.projectionMode === proof.projectionMode &&
    diagnostic.continuationAllowed && diagnostic.containsSecrets === false && (
      finalStage
        ? diagnostic.activeSandboxPolicy === "exact-top-host-list" &&
          diagnostic.independentSandboxPolicy === "exact-top-host-list"
        : (diagnostic.activeSandboxPolicy === "exact-top-host-list" ||
            diagnostic.activeSandboxPolicy === expectedCode) &&
          (diagnostic.independentSandboxPolicy === "exact-top-host-list" ||
            diagnostic.independentSandboxPolicy === expectedCode)
    );
  const sandboxExact = (value: unknown): boolean => finalStage
    ? topProjection(value, hostname)
    : topProjection(value, hostname) ||
      exactPhasePolicy(normalizedStage, value, hostname, runId, pOrigin, matcherMayBeOmitted);
  const sessionExact = (value: unknown): boolean => proof.projectionMode === "matcherless-redacted"
    ? exactMatcherlessFinalPolicy(value, hostname, runId, pOrigin)
    : exactPhasePolicy(normalizedStage, value, hostname, runId, pOrigin, matcherMayBeOmitted);
  return SESSION_ID.test(proof.initialSessionId) && proof.activeSessionId === proof.initialSessionId &&
    proof.independentSessionId === proof.initialSessionId && proof.initialSessionId === expectedIdentity.sessionId &&
    exactIdentity(proof.identity, expectedIdentity) && !proof.rawCredentialPresentInReadbacks &&
    !proof.hiddenTriggerPresentInRetainedReadbacks && proof.platformRedactionMarkerPresent === transformPresent &&
    proof.finalHiddenMatcherComparedExactlyBeforeSanitization ===
      (finalStage && proof.projectionMode === "exact-matchers") &&
    proof.finalHiddenMatcherMarkerPresent === (finalStage && proof.projectionMode === "exact-matchers") &&
    finalModeValid && diagnosticValid &&
    validInterval(proof.startedAt, proof.completedAt) && sandboxExact(proof.activeSandboxPolicy) &&
    sessionExact(proof.activeSessionPolicy) &&
    sandboxExact(proof.independentSandboxPolicy) &&
    sessionExact(proof.independentSessionPolicy);
}

function ms(value: string): number {
  return Date.parse(value);
}

function validInstant(value: string): boolean {
  const parsed = ms(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function validInterval(start: string, end: string): boolean {
  return validInstant(start) && validInstant(end) && ms(start) < ms(end);
}

function before(left: string, right: string): boolean {
  return validInstant(left) && validInstant(right) && ms(left) < ms(right);
}

function eventWithinProbe(event: Sbx050LedgerEvent, probe: Sbx050ProbeEvidence): boolean {
  return validInterval(probe.startedAt, probe.completedAt) && validInstant(event.observedAt) &&
    ms(probe.startedAt) <= ms(event.observedAt) && ms(event.observedAt) <= ms(probe.completedAt);
}

export function chronologyValid(input: Sbx050AssessmentInput): boolean {
  const p = input.probes;
  const proofs = input.policyProofs;
  const event = (caseId: Sbx050EventCaseId): Sbx050LedgerEvent | undefined =>
    input.ledger.events.find((entry) => entry.caseId === caseId);
  const intervals = SBX050_CASES.map((caseId) => p[caseId]);
  if (!validInstant(input.ledger.configuredAt) || !validInstant(input.ledger.emptyReadAt) ||
      !before(input.ledger.configuredAt, input.ledger.emptyReadAt) ||
      !before(input.ledger.emptyReadAt, proofs["public-forward"].startedAt) ||
      !before(proofs["public-forward"].completedAt, p["public-forward-control"].startedAt) ||
      !before(p["public-forward-control"].completedAt, proofs["transform-alone"].startedAt) ||
      !before(proofs["transform-alone"].completedAt, p["transform-alone-control"].startedAt) ||
      !before(p["transform-alone-control"].completedAt, proofs["final-before"].startedAt) ||
      !before(proofs["final-before"].completedAt, p["final-plain-pre"].startedAt) ||
      !before(p["final-plain-pre"].completedAt, p["direct-p-pre"].startedAt) ||
      !before(p["direct-p-pre"].completedAt, p["arm-without-trigger"].startedAt) ||
      !before(p["arm-without-trigger"].completedAt, p["direct-p-post"].startedAt) ||
      !before(p["direct-p-post"].completedAt, p["final-plain-post"].startedAt) ||
      !before(p["final-plain-post"].completedAt, proofs["final-after"].startedAt) ||
      !before(proofs["final-after"].completedAt, input.cleanup.startedAt) ||
      !validInterval(input.cleanup.startedAt, input.cleanup.completedAt)) return false;
  if (intervals.some((probe) => !validInterval(probe.startedAt, probe.completedAt))) return false;
  return SBX050_EVENT_CASES.every((caseId) => {
    const found = event(caseId);
    return found !== undefined && eventWithinProbe(found, p[caseId]);
  });
}

function trustNamesValid(names: string[]): boolean {
  const sorted = [...names].sort();
  return names.every((name) => TRUST_NAMES.has(name)) && new Set(names).size === names.length &&
    names.join(",") === sorted.join(",");
}

function expectedEventShape(caseId: Sbx050EventCaseId, candidate: boolean): {
  role: Sbx050Role; credential: boolean; trigger: boolean; triggerCount: number; oidc: boolean;
} {
  if (caseId === "public-forward-control") {
    return { role: "P", credential: false, trigger: false, triggerCount: 1, oidc: true };
  }
  if (caseId === "transform-alone-control") {
    return { role: "A", credential: true, trigger: true, triggerCount: 1, oidc: false };
  }
  if (caseId === "arm-without-trigger") return candidate
    ? { role: "P", credential: true, trigger: true, triggerCount: 1, oidc: true }
    : { role: "A", credential: true, trigger: true, triggerCount: 1, oidc: false };
  return { role: "A", credential: false, trigger: false, triggerCount: 0, oidc: false };
}

function exactEvent(
  input: Sbx050AssessmentInput,
  caseId: Sbx050EventCaseId,
  operationId: string,
  candidate: boolean,
): boolean {
  const shape = expectedEventShape(caseId, candidate);
  const matches = input.ledger.events.filter((entry) => entry.caseId === caseId);
  const event = matches[0];
  const proxy = shape.role === "P";
  const identity = input.expectedIdentity;
  const oidcFacts = proxy
    ? event?.oidcIssuerVerified === true && event.oidcTemporalVerified === true &&
      event.oidcIssuer === `https://oidc.vercel.com/${identity.teamId}` &&
      event.oidcAudience === proxyAudience(input.pOrigin, input.runId) &&
      event.oidcTeamId === identity.teamId && event.oidcProjectId === identity.projectId &&
      event.oidcSessionId === identity.sessionId && event.oidcSandboxName === identity.sandboxName
    : event?.oidcIssuerVerified === false && event.oidcTemporalVerified === false &&
      event.oidcIssuer === undefined && event.oidcAudience === undefined && event.oidcTeamId === undefined &&
      event.oidcProjectId === undefined && event.oidcSessionId === undefined && event.oidcSandboxName === undefined;
  return matches.length === 1 && event !== undefined && event.role === shape.role &&
    event.canaryMatched && event.originalRequestMatched &&
    event.credentialHeaderCount === (shape.credential ? 1 : 0) &&
    event.triggerHeaderCount === shape.triggerCount &&
    event.credentialMatched === shape.credential && event.triggerMatched === shape.trigger &&
    event.oidcHeaderCount === (proxy ? 1 : 0) && event.oidcOfficialVerified === proxy &&
    event.oidcIndependentRs256Verified === proxy && event.oidcAudienceMatched === proxy &&
    event.oidcSourceMatched === proxy && oidcFacts && event.operationId === operationId &&
    Number.isInteger(event.ordinal) && event.ordinal > 0 && !Number.isNaN(Date.parse(event.observedAt));
}

function exactResponseProbe(
  input: Sbx050AssessmentInput,
  caseId: Sbx050EventCaseId,
  operationId: string,
  candidate: boolean,
): boolean {
  const probe = input.probes[caseId];
  const shape = expectedEventShape(caseId, candidate);
  return probe.schemaVersion === 1 && probe.testId === SBX050_TEST_ID && probe.runId === input.runId &&
    probe.caseId === caseId && probe.correlationCanary === input.canaries[caseId] &&
    probe.commandExitCode === 0 && probe.ok && probe.phase === "response" &&
    exactIdentity(probe.controllerIdentity, input.expectedIdentity) &&
    probe.requestHostname === input.aHostname && probe.requestServername === input.aHostname &&
    probe.requestPath === requestPath(input.runId, caseId, input.canaries[caseId]) &&
    !probe.sentCredentialHeader && !probe.sentHiddenTriggerHeader &&
    probe.sentPublicTriggerHeader === (caseId === "public-forward-control") &&
    probe.connectionAttempts === 1 && probe.actualConnections === 1 && probe.actualRequests === 1 &&
    probe.retries === 0 && probe.redirectsFollowed === 0 && probe.rejectUnauthorized &&
    !probe.controllerConfigurableCustomTrustAccepted && trustNamesValid(probe.inheritedPlatformTrustEnvironmentNames) &&
    probe.tcpConnected && probe.tlsEstablished && probe.tlsAuthorized && probe.responseReceived && !probe.timedOut &&
    probe.responseStatusCode === 200 && probe.responseShapeValid && probe.responseRole === shape.role &&
    probe.responseCredentialMatched === shape.credential && probe.responseTriggerMatched === shape.trigger &&
    probe.responseOidcVerified === shape.oidc && probe.responseOperationId === operationId &&
    !probe.responseBodyRetained && probe.durationMs >= 0 && exactEvent(input, caseId, operationId, candidate);
}

export function directBlockTransportCoherent(probe: Sbx050ProbeEvidence): boolean {
  if (probe.errorCode === "EAI_AGAIN") {
    return probe.errorClass === "dns-resolution" && probe.errorSyscall === "getaddrinfo" &&
      probe.errorErrno === -3001 && probe.actualConnections === 0 && probe.actualRequests === 0 &&
      !probe.tcpConnected && !probe.tlsEstablished && !probe.tlsAuthorized;
  }
  if (probe.errorCode === "EHOSTUNREACH" || probe.errorCode === "ENETUNREACH") {
    const errno = probe.errorCode === "EHOSTUNREACH" ? -113 : -101;
    return probe.errorClass === "route-unreachable" && probe.errorSyscall === "connect" &&
      probe.errorErrno === errno && probe.actualConnections === 0 && probe.actualRequests === 0 &&
      !probe.tcpConnected && !probe.tlsEstablished && !probe.tlsAuthorized;
  }
  if (probe.errorCode === "ECONNRESET") {
    return probe.errorClass === "connection-reset" && probe.errorSyscall === "read" &&
      probe.errorErrno === -104 && probe.actualConnections === 1 && probe.tcpConnected &&
      !probe.tlsEstablished && !probe.tlsAuthorized && probe.actualRequests === 0;
  }
  return false;
}

export interface Sbx050DirectBlockExpectation {
  runId: string;
  caseId: "direct-p-pre" | "direct-p-post";
  canary: string;
  pHostname: string;
  expectedIdentity: Sbx050ExpectedIdentity;
}

export function exactDirectBlockProbe(
  probe: Sbx050ProbeEvidence,
  expected: Sbx050DirectBlockExpectation,
): boolean {
  return probe.schemaVersion === 1 && probe.testId === SBX050_TEST_ID && probe.runId === expected.runId &&
    probe.caseId === expected.caseId && probe.correlationCanary === expected.canary &&
    probe.commandExitCode === 0 && !probe.ok && probe.phase === "network-error" &&
    exactIdentity(probe.controllerIdentity, expected.expectedIdentity) &&
    probe.requestHostname === expected.pHostname && probe.requestServername === expected.pHostname &&
    probe.requestPath === requestPath(expected.runId, expected.caseId, expected.canary) &&
    !probe.sentCredentialHeader && !probe.sentHiddenTriggerHeader && !probe.sentPublicTriggerHeader &&
    probe.connectionAttempts === 1 && probe.retries === 0 &&
    probe.redirectsFollowed === 0 && probe.rejectUnauthorized &&
    !probe.controllerConfigurableCustomTrustAccepted && trustNamesValid(probe.inheritedPlatformTrustEnvironmentNames) &&
    !probe.responseReceived && !probe.responseShapeValid && !probe.responseBodyRetained && !probe.timedOut &&
    directBlockTransportCoherent(probe) && probe.durationMs >= 0 && probe.durationMs <= 5_000;
}

function exactDirectBlock(input: Sbx050AssessmentInput, caseId: "direct-p-pre" | "direct-p-post"): boolean {
  return exactDirectBlockProbe(input.probes[caseId], {
    runId: input.runId,
    caseId,
    canary: input.canaries[caseId],
    pHostname: input.pHostname,
    expectedIdentity: input.expectedIdentity,
  });
}

function ledgerShapeValid(ledger: Sbx050LedgerEvidence): boolean {
  return ledger.configured && !ledger.rawCredentialRetained && !ledger.credentialDigestRetained &&
    !ledger.rawHiddenTriggerRetained && !ledger.hiddenTriggerDigestRetained &&
    !ledger.rawOidcTokenRetained && !ledger.oidcTokenDigestRetained &&
    ledger.receiverRuntimeTrustExact && ledger.receiverRuntimeTrustEnvironmentNames.length === 0 &&
    !ledger.receiverNodeOptionsPresent && !ledger.receiverTlsVerificationDisabled &&
    ledger.unexpectedARequests === 0 && ledger.unexpectedPRequests === 0 && ledger.unattributedRequests === 0 &&
    ledger.events.length === SBX050_EVENT_CASES.length &&
    new Set(ledger.events.map((event) => event.caseId)).size === SBX050_EVENT_CASES.length &&
    new Set(ledger.events.map((event) => event.ordinal)).size === SBX050_EVENT_CASES.length &&
    ledger.events.every((event, index) => event.caseId === SBX050_EVENT_CASES[index] &&
      event.ordinal === index + 1 && OPERATION_ID_PATTERN.test(event.operationId));
}

function cleanupPassed(cleanup: Sbx050CleanupEvidence): boolean {
  return cleanup.sandbox.stopped && cleanup.sandbox.deleted && cleanup.sandbox.absenceChecks >= 2 &&
    cleanup.sandbox.errors.length === 0 && cleanup.receiver.deleted && cleanup.receiver.absent &&
    cleanup.receiver.absenceChecks >= 2 && cleanup.receiver.errors.length === 0;
}

function exactHttpsOrigin(raw: string, hostname: string): boolean {
  try {
    const parsed = new URL(raw);
    return raw === parsed.origin && parsed.protocol === "https:" && !parsed.username && !parsed.password &&
      !parsed.port && parsed.pathname === "/" && !parsed.search && !parsed.hash &&
      parsed.hostname === hostname && parsed.hostname === parsed.hostname.toLowerCase();
  } catch {
    return false;
  }
}

function inputShapeValid(input: Sbx050AssessmentInput): boolean {
  if (!RUN_ID_PATTERN.test(input.runId) || !exactIdentity(input.expectedIdentity, input.expectedIdentity) ||
      !exactHttpsOrigin(input.aOrigin, input.aHostname) || !exactHttpsOrigin(input.pOrigin, input.pHostname) ||
      input.aOrigin === input.pOrigin || input.aHostname === input.pHostname) return false;
  if (!exactKeys(input.canaries, [...SBX050_CASES]) ||
      !SBX050_CASES.every((caseId) => CANARY_PATTERN.test(input.canaries[caseId])) ||
      new Set(SBX050_CASES.map((caseId) => input.canaries[caseId])).size !== SBX050_CASES.length) return false;
  if (!exactKeys(input.expectedOperationIds, [...SBX050_EVENT_CASES])) return false;
  const ids: string[] = [];
  for (const caseId of SBX050_EVENT_CASES) {
    const value = input.expectedOperationIds[caseId];
    const expectedKeys = caseId === "arm-without-trigger" ? ["candidate", "pass"] : ["pass"];
    if (!exactKeys(value as unknown as Record<string, unknown>, expectedKeys) ||
        !OPERATION_ID_PATTERN.test(value.pass) ||
        (caseId === "arm-without-trigger" &&
          (typeof value.candidate !== "string" || !OPERATION_ID_PATTERN.test(value.candidate)))) return false;
    ids.push(value.pass);
    if (value.candidate) ids.push(value.candidate);
  }
  if (new Set(ids).size !== ids.length) return false;
  const retention = input.retention;
  if (!retention.guestSourceScanned || !retention.guestConfigurationsScanned || !retention.guestArgvScanned ||
      !retention.guestEnvironmentScanned || !retention.guestStagedFilesScanned || !retention.guestStdoutScanned ||
      !retention.guestResultsScanned || !retention.controllerArtifactScanned ||
      !retention.hiddenTriggerAbsentFromAllGuestMaterial || !retention.credentialAbsentFromAllGuestMaterial ||
      retention.rawCredentialRetained || retention.credentialDigestRetained || retention.rawHiddenTriggerRetained ||
      retention.hiddenTriggerDigestRetained || retention.rawOidcTokenRetained || retention.oidcTokenDigestRetained) return false;
  return input.localState.lockAcquired && input.localState.preexistingLockAbsent && input.localState.lockReleased &&
    input.localState.lockMode === 0o600 && input.localState.artifactMode === 0o600 &&
    input.localState.recoveryJournalCreated && input.localState.recoveryJournalMode === 0o600 &&
    input.localState.recoveryJournalReleased;
}

export function assessSbx050(input: Sbx050AssessmentInput): Sbx050Assessment {
  if (input.executionError || !cleanupPassed(input.cleanup)) {
    return {
      outcome: "error", candidate: false, severity: "unknown", controlsPassed: false,
      chronologyPassed: false, postTransformForwardingProven: false, credentialReceiptProven: false,
      ...NOT_REPORTABLE,
      rationale: input.executionError ?? "strict sandbox or receiver cleanup did not complete",
    };
  }
  const inputShape = inputShapeValid(input);
  if (!inputShape) {
    return {
      outcome: "indeterminate", candidate: false, severity: "unknown", controlsPassed: false,
      chronologyPassed: false, postTransformForwardingProven: false, credentialReceiptProven: false,
      ...NOT_REPORTABLE,
      rationale: "run identity, owned origins, canaries, operation IDs, retention scans, or mode-0600 state was not exact",
    };
  }
  const policyStages = ["public-forward", "transform-alone", "final-before", "final-after"] as const;
  const finalProjectionModeConsistent =
    input.policyProofs["final-before"].projectionMode === input.policyProofs["final-after"].projectionMode;
  const policies = finalProjectionModeConsistent && policyStages.every((stage) =>
    input.policyProofs[stage].stage === stage &&
    exactPolicyProof(input.policyProofs[stage], input.aHostname, input.runId, input.pOrigin, input.expectedIdentity));
  const chronology = chronologyValid(input);
  const ledger = ledgerShapeValid(input.ledger);
  const publicForward = exactResponseProbe(
    input, "public-forward-control", input.expectedOperationIds["public-forward-control"].pass, false,
  );
  const transformAlone = exactResponseProbe(
    input, "transform-alone-control", input.expectedOperationIds["transform-alone-control"].pass, false,
  );
  const plainPre = exactResponseProbe(
    input, "final-plain-pre", input.expectedOperationIds["final-plain-pre"].pass, false,
  );
  const directPre = exactDirectBlock(input, "direct-p-pre");
  const directPost = exactDirectBlock(input, "direct-p-post");
  const plainPost = exactResponseProbe(
    input, "final-plain-post", input.expectedOperationIds["final-plain-post"].pass, false,
  );
  const controlsPassed = policies && chronology && ledger && publicForward && transformAlone &&
    plainPre && directPre && directPost && plainPost;
  if (!controlsPassed) {
    return {
      outcome: "indeterminate", candidate: false, severity: "unknown", controlsPassed: false,
      chronologyPassed: chronology, postTransformForwardingProven: false, credentialReceiptProven: false,
      ...NOT_REPORTABLE,
      rationale: "a phase policy, chronology join, transform/forward control, direct-P block, or ordered event gate was not exact",
    };
  }
  const candidateId = input.expectedOperationIds["arm-without-trigger"].candidate;
  if (candidateId && exactResponseProbe(input, "arm-without-trigger", candidateId, true)) {
    return {
      outcome: "candidate-high", candidate: true, severity: "conditional-high", controlsPassed: true,
      chronologyPassed: true, postTransformForwardingProven: true, credentialReceiptProven: true,
      ...CONDITIONAL_HOLD,
      rationale: "conditional pending confirmation that record-form rules use original-request-only/isolated matching: P independently verified RS256 OIDC aud=P and exact source identity, then proved receipt of both hidden host-injected headers although the guest supplied neither",
    };
  }
  if (exactResponseProbe(
    input, "arm-without-trigger", input.expectedOperationIds["arm-without-trigger"].pass, false,
  )) {
    if (input.policyProofs["final-before"].projectionMode === "matcherless-redacted") {
      return {
        outcome: "indeterminate", candidate: false, severity: "unknown", controlsPassed: true,
        chronologyPassed: true, postTransformForwardingProven: false, credentialReceiptProven: false,
        ...NOT_REPORTABLE,
        rationale: "the platform omitted both final-rule matchers from otherwise exact ordered readbacks; an A-side outcome cannot distinguish matcher enforcement from matcherless execution",
      };
    }
    return {
      outcome: "pass", candidate: false, severity: "none", controlsPassed: true,
      chronologyPassed: true, postTransformForwardingProven: false, credentialReceiptProven: false,
      ...NOT_REPORTABLE,
      rationale: "the final arm request terminated only at A with both injected values and zero proxy/OIDC event",
    };
  }
  return {
    outcome: "indeterminate", candidate: false, severity: "unknown", controlsPassed: true,
    chronologyPassed: true, postTransformForwardingProven: false, credentialReceiptProven: false,
    ...NOT_REPORTABLE,
    rationale: "the decisive request was not an exact A negative or exact P credential proof; P reachability or a secretless receipt is not classified as a finding",
  };
}
