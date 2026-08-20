import {
  SBX058_CANARY,
  SBX058_CASES,
  SBX058_DECOY_HEADER,
  SBX058_EVENT_CASES,
  SBX058_MATCH_HEADER,
  SBX058_MATCH_VALUE,
  SBX058_OPERATION,
  SBX058_RECEIPT,
  SBX058_TEST_ID,
  SBX058_UUID,
  headerModeForCase,
  proxyAudience,
  requestPath,
  type Sbx058CaseId,
  type Sbx058EventCaseId,
  type Sbx058HeaderMode,
  type Sbx058Role,
} from "./protocol.js";
import type { Sbx058ReceiverEvent, Sbx058ReceiverSnapshot } from "./receiver.js";

const SESSION = /^sbx_[A-Za-z0-9_-]{20,100}$/u;
const TEAM = /^team_[A-Za-z0-9_-]{8,100}$/u;
const PROJECT = /^prj_[A-Za-z0-9_-]{8,100}$/u;
const TRUST_NAMES = [
  "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF",
  "OPENSSL_MODULES", "SSL_CERT_DIR", "SSL_CERT_FILE",
].sort();

export type Sbx058ProjectionMode = "exact-matchers" | "matcherless";

export interface Sbx058Identity {
  aliasEmail: string;
  aliasIdentityVerified: boolean;
  teamId: string;
  projectId: string;
  sandboxName: string;
  sessionId: string;
}

export interface Sbx058PolicyProof {
  stage: "before" | "after";
  startedAt: string;
  completedAt: string;
  expectedSessionId: string;
  activeSessionId: string;
  independentSessionId: string;
  activeSandboxPolicy: unknown;
  activeSessionPolicy: unknown;
  independentSandboxPolicy: unknown;
  independentSessionPolicy: unknown;
  configuredPolicyComparedExactlyInMemory: true;
  projectionMode: Sbx058ProjectionMode;
  identity: Sbx058Identity;
  containsControllerSecrets: false;
}

export interface Sbx058ProbeEvidence {
  schemaVersion: number;
  testId: string;
  runId: string;
  caseId: string;
  correlationCanary: string;
  targetRole: string;
  headerMode: string;
  commandExitCode: number;
  startedAt: string;
  completedAt: string;
  ok: boolean;
  phase: string;
  requestHostname: string;
  requestServername: string;
  requestHostHeader: string;
  requestPath: string;
  routeHeaderSent: boolean;
  decoyHeaderSent: boolean;
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
  responseRole?: string;
  responseOidcVerified?: boolean;
  responseOperationId?: string;
  responseReceipt?: string;
  responseBodyRetained: boolean;
  timedOut: boolean;
  durationMs: number;
  errorCode?: string;
  errorSyscall?: string;
  errorErrno?: number;
  errorClass?: "dns-resolution" | "connection-reset" | "route-unreachable";
  controllerIdentity: Sbx058Identity;
}

export interface Sbx058CleanupEvidence {
  startedAt: string;
  sandboxCompletedAt: string;
  completedAt: string;
  sandbox: {
    exactProvenance: boolean;
    absenceOnlyValidated: boolean;
    stopAttempted: boolean;
    stopped: boolean;
    deleteAttempted: boolean;
    deleted: boolean;
    absenceChecks: number;
    prefixAbsent: boolean;
    errors: string[];
  };
  receiver: {
    deleteAttempted: boolean;
    deleted: boolean;
    absenceChecks: number;
    errors: string[];
  };
  journalCompleted: boolean;
  journalRemoved: boolean;
  liveLockRemoved: boolean;
}

export interface Sbx058RetentionEvidence {
  guestSourceScanned: boolean;
  guestConfigurationScanned: boolean;
  guestArgvScanned: boolean;
  guestEnvironmentScanned: boolean;
  guestStagedFilesScanned: boolean;
  guestStdoutScanned: boolean;
  guestResultsScanned: boolean;
  controllerArtifactScanned: boolean;
  adminKeyAbsent: boolean;
  actionKeyAbsent: boolean;
  vercelTokenAbsent: boolean;
  rawOidcTokenRetained: false;
  oidcTokenDigestRetained: false;
  rawGuestOutputRetained: false;
  standaloneGuestOutputDigestRetained: false;
  artifactMode: number;
  journalMode: number;
  lockMode: number;
}

export interface Sbx058ExpectedEventProof {
  operationId: string;
  receipt: string;
}

export interface Sbx058AssessmentInput {
  controllerError?: string;
  runId: string;
  aOrigin: string;
  pOrigin: string;
  canaries: Record<Sbx058CaseId, string>;
  expectedIdentity: Sbx058Identity;
  observedIdentity: Sbx058Identity;
  expectedEvents: Record<Sbx058EventCaseId, Partial<Record<Sbx058Role, Sbx058ExpectedEventProof>>>;
  policyBefore: Sbx058PolicyProof;
  policyAfter: Sbx058PolicyProof;
  probes: Record<Sbx058CaseId, Sbx058ProbeEvidence>;
  ledger: Sbx058ReceiverSnapshot;
  cleanup: Sbx058CleanupEvidence;
  retention: Sbx058RetentionEvidence;
}

export interface Sbx058Assessment {
  outcome: "candidate-high" | "pass" | "indeterminate" | "error";
  candidate: boolean;
  severity: "conditional-high" | "none" | "unknown";
  controlsPassed: boolean;
  chronologyPassed: boolean;
  headerEntryBindingBypassed: boolean;
  independentProxyProofPassed: boolean;
  reportReady: false;
  reportabilityStatus: "not-reportable" | "hold-pending-semantics-clarification";
  rationale: string;
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((entry, index) => entry === wanted[index]);
}

function timestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function interval(startedAt: string, completedAt: string): boolean {
  return timestamp(startedAt) && timestamp(completedAt) && Date.parse(startedAt) < Date.parse(completedAt);
}

function before(left: string, right: string): boolean {
  return timestamp(left) && timestamp(right) && Date.parse(left) < Date.parse(right);
}

function exactOrigin(raw: string): URL | undefined {
  try {
    const value = new URL(raw);
    return raw === value.origin && value.protocol === "https:" && !value.username && !value.password &&
      !value.port && value.pathname === "/" && !value.search && !value.hash &&
      value.hostname === value.hostname.toLowerCase() ? value : undefined;
  } catch {
    return;
  }
}

function exactIdentity(actual: Sbx058Identity, expected: Sbx058Identity): boolean {
  return expected.aliasEmail === "swve@wearehackerone.com" && expected.aliasIdentityVerified &&
    TEAM.test(expected.teamId) && PROJECT.test(expected.projectId) && SESSION.test(expected.sessionId) &&
    expected.sandboxName.length > 0 && expected.sandboxName.length <= 256 &&
    actual.aliasEmail === expected.aliasEmail && actual.aliasIdentityVerified &&
    actual.teamId === expected.teamId && actual.projectId === expected.projectId &&
    actual.sandboxName === expected.sandboxName && actual.sessionId === expected.sessionId;
}

function exactMatcher(value: unknown, expected: string): boolean {
  const root = object(value);
  return root !== undefined && exactKeys(root, ["exact"]) && root.exact === expected;
}

function exactConfiguredPolicy(value: unknown, aHostname: string, audience: string): boolean {
  const root = object(value);
  const allow = object(root?.allow);
  if (!root || !allow || !exactKeys(root, ["allow"]) || !exactKeys(allow, [aHostname]) ||
      !Array.isArray(allow[aHostname]) || allow[aHostname].length !== 1) return false;
  const rule = object(allow[aHostname][0]);
  const match = object(rule?.match);
  if (!rule || !match || !exactKeys(rule, ["forwardURL", "match"]) || rule.forwardURL !== audience ||
      !exactKeys(match, ["headers"]) || !Array.isArray(match.headers) || match.headers.length !== 1) return false;
  const entry = object(match.headers[0]);
  return entry !== undefined && exactKeys(entry, ["key", "value"]) &&
    exactMatcher(entry.key, SBX058_MATCH_HEADER) && exactMatcher(entry.value, SBX058_MATCH_VALUE);
}

function exactSandboxProjection(value: unknown, aHostname: string): boolean {
  const root = object(value);
  return root !== undefined && exactKeys(root, ["allow"]) && Array.isArray(root.allow) &&
    root.allow.length === 1 && root.allow[0] === aHostname;
}

function exactSessionProjection(
  value: unknown,
  aHostname: string,
  audience: string,
  mode: Sbx058ProjectionMode,
): boolean {
  if (mode === "exact-matchers") return exactConfiguredPolicy(value, aHostname, audience);
  const root = object(value);
  const allow = object(root?.allow);
  if (!root || !allow || !exactKeys(root, ["allow"]) || !exactKeys(allow, [aHostname]) ||
      !Array.isArray(allow[aHostname]) || allow[aHostname].length !== 1) return false;
  const rule = object(allow[aHostname][0]);
  return rule !== undefined && exactKeys(rule, ["forwardURL"]) && rule.forwardURL === audience;
}

export function exactSbx058PolicyProof(
  proof: Sbx058PolicyProof,
  stage: "before" | "after",
  aHostname: string,
  audience: string,
  expectedIdentity: Sbx058Identity,
): boolean {
  return proof.stage === stage && interval(proof.startedAt, proof.completedAt) &&
    proof.expectedSessionId === expectedIdentity.sessionId && proof.activeSessionId === expectedIdentity.sessionId &&
    proof.independentSessionId === expectedIdentity.sessionId && proof.configuredPolicyComparedExactlyInMemory &&
    (proof.projectionMode === "exact-matchers" || proof.projectionMode === "matcherless") &&
    exactIdentity(proof.identity, expectedIdentity) && proof.containsControllerSecrets === false &&
    exactSandboxProjection(proof.activeSandboxPolicy, aHostname) &&
    exactSessionProjection(proof.activeSessionPolicy, aHostname, audience, proof.projectionMode) &&
    exactSandboxProjection(proof.independentSandboxPolicy, aHostname) &&
    exactSessionProjection(proof.independentSessionPolicy, aHostname, audience, proof.projectionMode);
}

function exactTrustNames(names: string[]): boolean {
  return names.length === new Set(names).size && names.every((entry) => TRUST_NAMES.includes(entry)) &&
    names.every((entry, index) => index === 0 || names[index - 1]! < entry);
}

function headerExpectation(caseId: Sbx058EventCaseId): {
  route: number;
  decoy: number;
  routeMatched: boolean;
  decoyMatched: boolean;
} {
  return {
    route: caseId === "value-half" ? 0 : 1,
    decoy: caseId === "value-half" || caseId === "combined-halves" ? 1 : 0,
    routeMatched: caseId === "exact-pair",
    decoyMatched: caseId === "value-half" || caseId === "combined-halves",
  };
}

function exactOidc(event: Sbx058ReceiverEvent, input: Sbx058AssessmentInput, role: Sbx058Role): boolean {
  const identity = input.expectedIdentity;
  if (role === "A") {
    return event.oidcHeaderLines === 0 && event.oidcHeaderValues === 0 &&
      !event.oidcOfficialVerified && !event.oidcIndependentRs256Verified && !event.oidcAudienceMatched &&
      !event.oidcSourceMatched && !event.oidcIssuerVerified && !event.oidcTemporalVerified &&
      event.oidcIssuer === undefined && event.oidcAudience === undefined && event.oidcTeamId === undefined &&
      event.oidcProjectId === undefined && event.oidcSessionId === undefined && event.oidcSandboxName === undefined;
  }
  return event.oidcHeaderLines === 1 && event.oidcHeaderValues === 1 &&
    event.oidcOfficialVerified && event.oidcIndependentRs256Verified && event.oidcAudienceMatched &&
    event.oidcSourceMatched && event.oidcIssuerVerified && event.oidcTemporalVerified &&
    event.oidcIssuer === `https://oidc.vercel.com/${identity.teamId}` &&
    event.oidcAudience === proxyAudience(input.pOrigin, input.runId) &&
    event.oidcTeamId === identity.teamId && event.oidcProjectId === identity.projectId &&
    event.oidcSessionId === identity.sessionId && event.oidcSandboxName === identity.sandboxName;
}

function exactEvent(
  input: Sbx058AssessmentInput,
  caseId: Sbx058EventCaseId,
  role: Sbx058Role,
): Sbx058ReceiverEvent | undefined {
  const matches = input.ledger.events.filter((event) => event.caseId === caseId);
  const event = matches[0];
  const expected = input.expectedEvents[caseId][role];
  const headers = headerExpectation(caseId);
  const index = SBX058_EVENT_CASES.indexOf(caseId);
  if (matches.length !== 1 || !event || !expected || event.ordinal !== index + 1 ||
      !timestamp(event.observedAt) || event.role !== role || event.method !== "GET" ||
      !event.hostMatched || !event.pathMatched || !event.correlationHeadersExact ||
      event.forwardedMetadataExact !== (role === "P") ||
      event.routeHeaderLines !== headers.route || event.routeHeaderValues !== headers.route ||
      event.decoyHeaderLines !== headers.decoy || event.decoyHeaderValues !== headers.decoy ||
      event.routeValueMatched !== headers.routeMatched || event.decoyValueMatched !== headers.decoyMatched ||
      event.operationId !== expected.operationId || event.receipt !== expected.receipt ||
      !SBX058_OPERATION.test(event.operationId) || !SBX058_RECEIPT.test(event.receipt) ||
      !exactOidc(event, input, role)) return;
  return event;
}

function exactProbe(
  input: Sbx058AssessmentInput,
  caseId: Sbx058EventCaseId,
  role: Sbx058Role,
): boolean {
  const probe = input.probes[caseId];
  const event = exactEvent(input, caseId, role);
  if (!event) return false;
  const a = new URL(input.aOrigin);
  const mode = headerModeForCase(caseId);
  const headers = headerExpectation(caseId);
  return probe.schemaVersion === 1 && probe.testId === SBX058_TEST_ID && probe.runId === input.runId &&
    probe.caseId === caseId && probe.correlationCanary === input.canaries[caseId] &&
    probe.targetRole === "A" && probe.headerMode === mode && probe.commandExitCode === 0 && probe.ok &&
    probe.phase === "response" && exactIdentity(probe.controllerIdentity, input.expectedIdentity) &&
    probe.requestHostname === a.hostname && probe.requestServername === a.hostname &&
    probe.requestHostHeader === a.hostname && probe.requestPath === requestPath(input.runId, caseId, input.canaries[caseId]) &&
    probe.routeHeaderSent === (headers.route === 1) && probe.decoyHeaderSent === (headers.decoy === 1) &&
    probe.connectionAttempts === 1 && probe.actualConnections === 1 && probe.actualRequests === 1 &&
    probe.retries === 0 && probe.redirectsFollowed === 0 && probe.rejectUnauthorized &&
    !probe.controllerConfigurableCustomTrustAccepted && exactTrustNames(probe.inheritedPlatformTrustEnvironmentNames) &&
    probe.tcpConnected && probe.tlsEstablished && probe.tlsAuthorized && probe.responseReceived &&
    probe.responseStatusCode === 200 && probe.responseShapeValid && probe.responseRole === role &&
    probe.responseOidcVerified === (role === "P") && probe.responseOperationId === event.operationId &&
    probe.responseReceipt === event.receipt && !probe.responseBodyRetained && !probe.timedOut &&
    Number.isFinite(probe.durationMs) && probe.durationMs >= 0 && interval(probe.startedAt, probe.completedAt) &&
    Date.parse(probe.startedAt) <= Date.parse(event.observedAt) &&
    Date.parse(event.observedAt) <= Date.parse(probe.completedAt);
}

export function directBlockTransportCoherent(probe: Sbx058ProbeEvidence): boolean {
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
    return probe.errorClass === "connection-reset" && probe.errorSyscall === "read" && probe.errorErrno === -104 &&
      probe.actualConnections === 1 && probe.actualRequests === 0 && probe.tcpConnected &&
      !probe.tlsEstablished && !probe.tlsAuthorized;
  }
  return false;
}

export function directBlockTuple(probe: Sbx058ProbeEvidence): string | undefined {
  if (!directBlockTransportCoherent(probe)) return;
  return [
    probe.errorClass,
    probe.errorCode,
    probe.errorSyscall,
    String(probe.errorErrno),
    String(probe.actualConnections),
    String(probe.actualRequests),
    String(probe.tcpConnected),
    String(probe.tlsEstablished),
    String(probe.tlsAuthorized),
  ].join("|");
}

function exactDirectBlock(input: Sbx058AssessmentInput, caseId: "direct-p-pre" | "direct-p-post"): boolean {
  const probe = input.probes[caseId];
  const p = new URL(input.pOrigin);
  return probe.schemaVersion === 1 && probe.testId === SBX058_TEST_ID && probe.runId === input.runId &&
    probe.caseId === caseId && probe.correlationCanary === input.canaries[caseId] &&
    probe.targetRole === "P" && probe.headerMode === "none" && probe.commandExitCode === 0 && !probe.ok &&
    probe.phase === "network-error" && exactIdentity(probe.controllerIdentity, input.expectedIdentity) &&
    probe.requestHostname === p.hostname && probe.requestServername === p.hostname &&
    probe.requestHostHeader === p.hostname && probe.requestPath === requestPath(input.runId, caseId, input.canaries[caseId]) &&
    !probe.routeHeaderSent && !probe.decoyHeaderSent && probe.connectionAttempts === 1 &&
    probe.retries === 0 && probe.redirectsFollowed === 0 && probe.rejectUnauthorized &&
    !probe.controllerConfigurableCustomTrustAccepted && exactTrustNames(probe.inheritedPlatformTrustEnvironmentNames) &&
    !probe.responseReceived && !probe.responseShapeValid && !probe.responseBodyRetained && !probe.timedOut &&
    directBlockTransportCoherent(probe) && Number.isFinite(probe.durationMs) &&
    probe.durationMs >= 0 && probe.durationMs <= 5_000 && interval(probe.startedAt, probe.completedAt);
}

export function chronologyValid(input: Sbx058AssessmentInput): boolean {
  const p = input.probes;
  const beforeProof = input.policyBefore;
  const afterProof = input.policyAfter;
  if (!timestamp(input.ledger.configuredAt) || !input.ledger.emptyReadAt || !timestamp(input.ledger.emptyReadAt) ||
      !timestamp(input.ledger.snapshotAt) || !timestamp(input.cleanup.sandboxCompletedAt) ||
      !before(input.ledger.configuredAt, input.ledger.emptyReadAt) ||
      !before(input.ledger.emptyReadAt, beforeProof.startedAt) ||
      !before(beforeProof.completedAt, p["direct-p-pre"].startedAt) ||
      !before(p["direct-p-pre"].completedAt, p["exact-pair"].startedAt) ||
      !before(p["exact-pair"].completedAt, p["key-half"].startedAt) ||
      !before(p["key-half"].completedAt, p["value-half"].startedAt) ||
      !before(p["value-half"].completedAt, p["combined-halves"].startedAt) ||
      !before(p["combined-halves"].completedAt, p["direct-p-post"].startedAt) ||
      !before(p["direct-p-post"].completedAt, afterProof.startedAt) ||
      !before(afterProof.completedAt, input.cleanup.startedAt) ||
      !interval(input.cleanup.startedAt, input.cleanup.completedAt) ||
      Date.parse(input.cleanup.startedAt) > Date.parse(input.cleanup.sandboxCompletedAt) ||
      Date.parse(input.cleanup.sandboxCompletedAt) > Date.parse(input.ledger.snapshotAt) ||
      Date.parse(input.ledger.snapshotAt) > Date.parse(input.cleanup.completedAt)) return false;
  return SBX058_EVENT_CASES.every((caseId) => {
    const event = input.ledger.events.find((entry) => entry.caseId === caseId);
    const probe = p[caseId];
    return event !== undefined && interval(probe.startedAt, probe.completedAt) && timestamp(event.observedAt) &&
      Date.parse(probe.startedAt) <= Date.parse(event.observedAt) &&
      Date.parse(event.observedAt) <= Date.parse(probe.completedAt);
  });
}

function cleanupExact(cleanup: Sbx058CleanupEvidence): boolean {
  const sandboxErrorsExact = cleanup.sandbox.errors.length === 0 ||
    (cleanup.sandbox.absenceOnlyValidated && cleanup.sandbox.errors.length === 1 &&
      cleanup.sandbox.errors[0]?.startsWith("delete: ") === true);
  return cleanup.sandbox.exactProvenance && cleanup.sandbox.stopAttempted && cleanup.sandbox.stopped &&
    cleanup.sandbox.deleteAttempted && cleanup.sandbox.deleted && cleanup.sandbox.absenceChecks >= 3 &&
    cleanup.sandbox.prefixAbsent && sandboxErrorsExact && cleanup.receiver.deleteAttempted &&
    cleanup.receiver.deleted && cleanup.receiver.absenceChecks >= 2 && cleanup.receiver.errors.length === 0 &&
    cleanup.journalCompleted && cleanup.journalRemoved && cleanup.liveLockRemoved;
}

function retentionExact(value: Sbx058RetentionEvidence): boolean {
  return value.guestSourceScanned && value.guestConfigurationScanned && value.guestArgvScanned &&
    value.guestEnvironmentScanned && value.guestStagedFilesScanned && value.guestStdoutScanned &&
    value.guestResultsScanned && value.controllerArtifactScanned && value.adminKeyAbsent &&
    value.actionKeyAbsent && value.vercelTokenAbsent && !value.rawOidcTokenRetained &&
    !value.oidcTokenDigestRetained && !value.rawGuestOutputRetained &&
    !value.standaloneGuestOutputDigestRetained && value.artifactMode === 0o600 &&
    value.journalMode === 0o600 && value.lockMode === 0o600;
}

function ledgerExact(ledger: Sbx058ReceiverSnapshot): boolean {
  return ledger.configured && timestamp(ledger.snapshotAt) && ledger.events.length === SBX058_EVENT_CASES.length &&
    ledger.unexpectedARequests === 0 && ledger.unexpectedPRequests === 0 && ledger.unattributedRequests === 0 &&
    !ledger.rawOidcTokenRetained && !ledger.oidcTokenDigestRetained && ledger.receiverRuntimeTrustExact &&
    ledger.receiverRuntimeTrustEnvironmentNames.length === 0 && !ledger.receiverNodeOptionsPresent &&
    !ledger.receiverTlsVerificationDisabled && new Set(ledger.events.map((event) => event.caseId)).size ===
      SBX058_EVENT_CASES.length && ledger.events.every((event, index) =>
        event.caseId === SBX058_EVENT_CASES[index] && event.ordinal === index + 1);
}

function inputShapeExact(input: Sbx058AssessmentInput): boolean {
  const a = exactOrigin(input.aOrigin);
  const p = exactOrigin(input.pOrigin);
  if (!SBX058_UUID.test(input.runId) || !a || !p || a.origin === p.origin ||
      !exactIdentity(input.observedIdentity, input.expectedIdentity) ||
      !exactKeys(input.canaries, SBX058_CASES) || !SBX058_CASES.every((caseId) =>
        SBX058_CANARY.test(input.canaries[caseId])) ||
      new Set(SBX058_CASES.map((caseId) => input.canaries[caseId])).size !== SBX058_CASES.length ||
      !exactKeys(input.expectedEvents, SBX058_EVENT_CASES)) return false;
  const allProofs: string[] = [];
  for (const caseId of SBX058_EVENT_CASES) {
    const entry = input.expectedEvents[caseId];
    const roles = caseId === "combined-halves" ? ["A", "P"] : caseId === "exact-pair" ? ["P"] : ["A"];
    if (!exactKeys(entry as Record<string, unknown>, roles)) return false;
    for (const role of roles as Sbx058Role[]) {
      const proof = entry[role];
      if (!proof || !SBX058_OPERATION.test(proof.operationId) || !SBX058_RECEIPT.test(proof.receipt)) return false;
      allProofs.push(proof.operationId, proof.receipt);
    }
  }
  return new Set(allProofs).size === allProofs.length && retentionExact(input.retention);
}

export function assessSbx058(input: Sbx058AssessmentInput): Sbx058Assessment {
  if (input.controllerError || !cleanupExact(input.cleanup)) {
    return {
      outcome: "error", candidate: false, severity: "unknown", controlsPassed: false,
      chronologyPassed: false, headerEntryBindingBypassed: false, independentProxyProofPassed: false,
      reportReady: false, reportabilityStatus: "not-reportable",
      rationale: input.controllerError ?? "strict sandbox, receiver, journal, or live-lock cleanup was incomplete",
    };
  }
  if (!inputShapeExact(input)) {
    return {
      outcome: "indeterminate", candidate: false, severity: "unknown", controlsPassed: false,
      chronologyPassed: false, headerEntryBindingBypassed: false, independentProxyProofPassed: false,
      reportReady: false, reportabilityStatus: "not-reportable",
      rationale: "run identity, distinct origins, canaries, keyed proofs, eligible identity, retention, or private modes were not exact",
    };
  }
  const a = new URL(input.aOrigin);
  const audience = proxyAudience(input.pOrigin, input.runId);
  const policies = input.policyBefore.projectionMode === input.policyAfter.projectionMode &&
    exactSbx058PolicyProof(input.policyBefore, "before", a.hostname, audience, input.expectedIdentity) &&
    exactSbx058PolicyProof(input.policyAfter, "after", a.hostname, audience, input.expectedIdentity);
  const chronology = chronologyValid(input);
  const ledger = ledgerExact(input.ledger);
  const directPre = exactDirectBlock(input, "direct-p-pre");
  const exactPair = exactProbe(input, "exact-pair", "P");
  const keyHalf = exactProbe(input, "key-half", "A");
  const valueHalf = exactProbe(input, "value-half", "A");
  const directPost = exactDirectBlock(input, "direct-p-post");
  const directTupleExact = directBlockTuple(input.probes["direct-p-pre"]) !== undefined &&
    directBlockTuple(input.probes["direct-p-pre"]) === directBlockTuple(input.probes["direct-p-post"]);
  const controlsPassed = policies && chronology && ledger && directPre && directPost && directTupleExact &&
    exactPair && keyHalf && valueHalf;
  if (!controlsPassed) {
    return {
      outcome: "indeterminate", candidate: false, severity: "unknown", controlsPassed: false,
      chronologyPassed: chronology, headerEntryBindingBypassed: false, independentProxyProofPassed: false,
      reportReady: false, reportabilityStatus: "not-reportable",
      rationale: "a policy readback, direct-P barrier, exact-pair positive, isolated half negative, chronology, or exhaustive ledger gate was not exact",
    };
  }
  if (exactProbe(input, "combined-halves", "P")) {
    return {
      outcome: "candidate-high", candidate: true, severity: "conditional-high", controlsPassed: true,
      chronologyPassed: true, headerEntryBindingBypassed: true, independentProxyProofPassed: true,
      reportReady: false, reportabilityStatus: "hold-pending-semantics-clarification",
      rationale: "conditional candidate: P independently verified RS256 OIDC, exact source identity, and a controller-keyed receipt even though the required header name and value appeared only on separate original-request entries",
    };
  }
  if (exactProbe(input, "combined-halves", "A")) {
    return {
      outcome: "pass", candidate: false, severity: "none", controlsPassed: true,
      chronologyPassed: true, headerEntryBindingBypassed: false, independentProxyProofPassed: false,
      reportReady: false, reportabilityStatus: "not-reportable",
      rationale: "the matcher kept its exact key and exact value bound to one header entry",
    };
  }
  return {
    outcome: "indeterminate", candidate: false, severity: "unknown", controlsPassed: true,
    chronologyPassed: true, headerEntryBindingBypassed: false, independentProxyProofPassed: false,
    reportReady: false, reportabilityStatus: "not-reportable",
    rationale: "the combined-halves request was neither one exact A negative nor an independently verified P proof",
  };
}

export { exactConfiguredPolicy };
