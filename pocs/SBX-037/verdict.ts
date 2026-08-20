export type Sbx037Verdict =
  | "pass"
  | "candidate-medium"
  | "candidate-high"
  | "indeterminate"
  | "error";

export type Sbx037Severity = "none" | "medium" | "high" | "unknown";
export type Sbx037RequestTargetForm = "origin" | "absolute" | "network-path";
export type Sbx037AttackOutcome = "pass" | "candidate-medium" | "candidate-high" | "indeterminate";

export const SBX037_ALIAS_EMAIL = "swve@wearehackerone.com";
export const SBX037_TEAM_ID = "team_n98ERpVwV7HqmWRudAyK8sXQ";
export const SBX037_PROJECT_ID = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
const INHERITED_PLATFORM_TRUST_ENVIRONMENT_NAMES = new Set([
  "NODE_EXTRA_CA_CERTS",
  "NODE_USE_SYSTEM_CA",
  "OPENSSL_CONF",
  "OPENSSL_MODULES",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
]);
const FALLBACK_RECEIPT_ID = /^rt37f_[A-Za-z0-9_-]{24}$/u;

function exactInheritedPlatformTrustEnvironmentNames(value: unknown): value is string[] {
  if (!Array.isArray(value) || value.length > INHERITED_PLATFORM_TRUST_ENVIRONMENT_NAMES.size ||
    !value.every((name): name is string =>
      typeof name === "string" && INHERITED_PLATFORM_TRUST_ENVIRONMENT_NAMES.has(name))) return false;
  const sorted = [...value].sort();
  return new Set(value).size === value.length && value.every((name, index) => name === sorted[index]);
}

export interface Sbx037ExpectedIdentity {
  teamId: string;
  projectId: string;
  sandboxId: string;
  sessionId: string;
  sandboxName: string;
}

export interface Sbx037ExpectedAttackCase {
  caseId: string;
  correlationId: string;
  targetForm: Exclude<Sbx037RequestTargetForm, "origin">;
  rawRequestTarget: string;
  pTerminalUrl: string;
  bCollectUrl: string;
  operationId: string;
  actionOperationId: string;
  terminalStatusCode: number;
  method: "POST";
  bodySource: "file";
  bodyFileMode: number;
}

export interface Sbx037ExpectedSyntaxControl {
  caseId: string;
  correlationId: string;
  targetForm: Exclude<Sbx037RequestTargetForm, "origin">;
  rawRequestTarget: string;
  bCollectUrl: string;
  operationId: string;
  syntaxSupported: boolean;
  terminalStatusCode: number;
  method: "POST";
  bodySource: "public";
  requestBodyBytes: number;
}

export interface Sbx037ExpectedEvidence {
  runId: string;
  testId: "SBX-037-POC";
  aliasEmail: string;
  identity: Sbx037ExpectedIdentity;
  aOrigin: string;
  pOrigin: string;
  bOrigin: string;
  pinnedAIpv4: string;
  pinnedPIpv4: string;
  pinnedBIpv4: string;
  forwardAudienceP: string;
  initialBAllow: {
    caseId: string;
    correlationId: string;
    requestUrl: string;
    operationId: string;
    statusCode: number;
  };
  directBPre: { caseId: string; correlationId: string; requestUrl: string };
  directBPost: { caseId: string; correlationId: string; requestUrl: string };
  originControl: {
    caseId: string;
    correlationId: string;
    aRequestUrl: string;
    rawRequestTarget: string;
    pTerminalUrl: string;
    operationId: string;
    terminalStatusCode: number;
    method: "GET" | "POST";
    bodySource: "public";
    requestBodyBytes: number;
  };
  syntaxControls: Sbx037ExpectedSyntaxControl[];
  pSyntaxControls: Sbx037ExpectedSyntaxControl[];
  attacks: Sbx037ExpectedAttackCase[];
}

export interface Sbx037ScopeEvidence {
  authenticatedAliasEmail: string;
  authenticatedTeamId: string;
  authenticatedProjectId: string;
  scopeConfirmation: "researcher-controlled-sbx037-origins-only";
  ownedOrigins: string[];
  unownedEndpointCount: number;
}

export interface Sbx037PolicyReadbackEvidence {
  stage: "pre-attack" | "post-attack";
  activeSessionId: string;
  independentSessionId: string;
  activePolicy: unknown;
  independentPolicy: unknown;
}

export interface Sbx037InitialBAllowEvent {
  runId: string;
  testId: string;
  caseId: string;
  correlationId: string;
  requestUrl: string;
  operationId: string;
}

export interface Sbx037InitialBAllowEvidence {
  caseId: string;
  correlationId: string;
  requestUrl: string;
  maximumConnections: number;
  actualConnections: number;
  maximumRequests: number;
  actualRequests: number;
  retryCount: number;
  redirectsAllowed: boolean;
  redirectsFollowed: number;
  connectionReused: boolean;
  commandExitCode: number;
  conclusiveReachability: boolean;
  responseStatusCode?: number;
  responseOperationId?: string;
  responseRole?: "B";
  destinationObserverEventCount: number;
  destinationObserverEvent?: Sbx037InitialBAllowEvent;
}

export interface Sbx037DirectBBlockEvidence {
  caseId: string;
  correlationId: string;
  requestUrl: string;
  maximumConnections: number;
  actualConnections: number;
  maximumRequests: number;
  actualRequests: number;
  commandExitCode: number;
  retryCount: number;
  redirectsAllowed: boolean;
  connectionReused: boolean;
  configuredPinnedDestinationIpv4: string;
  tcpConnected: boolean;
  tlsEstablished: boolean;
  observedRemoteAddress?: string;
  errorCode: string;
  durationMs: number;
  samePinnedDestination: boolean;
  conclusiveFirewallBlock: boolean;
  destinationObserverEventCount: number;
}

export interface Sbx037GuestRawRequestEvidence {
  commandExitCode: number;
  ok: boolean;
  runId: string;
  testId: string;
  caseId: string;
  correlationId: string;
  targetForm: string;
  connectionRole: string;
  syntaxSupported: boolean | "missing";
  method: string;
  bodySource: string;
  requestBodyBytes?: number;
  operatorSecretLoaded: boolean;
  bodyFileMode?: number;
  httpVersion: string;
  tcpHost: string;
  tcpPort: number;
  tlsServername: string;
  httpHost: string;
  rawRequestTarget: string;
  maximumConnections: number;
  actualConnections: number;
  maximumRequests: number;
  actualRequests: number;
  retryCount: number;
  redirectsAllowed: boolean;
  redirectsFollowed: number;
  connectionReused: boolean;
  environmentProxyTrust: boolean;
  tlsTrust: {
    inheritedPlatformTrustEnvironmentNames: string[];
    controllerConfigurableCustomTrustAccepted: boolean;
    rejectUnauthorized: boolean;
  };
  pinnedDestinationIpv4: string;
  transportTcpConnected: boolean;
  transportTlsEstablished: boolean;
  transportAuthorized: boolean;
  transportRemoteAddress: string;
  transportRemotePort: number;
  transportAlpnProtocol: string;
  responseStatusCode?: number;
  responseOperationId?: string;
  responseFallbackReceiptId?: string;
  responseRole?: "A" | "P" | "B";
}

export interface Sbx037VerifiedOidcIdentity {
  teamId: string;
  projectId: string;
  sandboxId: string;
  sessionId: string;
  sandboxName: string;
}

/** Sanitized output only. A raw JWT is never valid verdict input. */
export interface Sbx037PlatformOidcVerification {
  tokenOrdinal: number;
  verifier: "sink-p-independent-jose" | "observer-b-independent-jose";
  signatureVerified: boolean;
  algorithm: string;
  issuer: string;
  jwksUrl: string;
  audience: string | string[];
  temporalClaimsVerified: boolean;
  identity: Sbx037VerifiedOidcIdentity;
  rawTokenRetained: boolean;
  verificationError?: string;
}

export interface Sbx037TerminalPEvent {
  runId: string;
  testId: string;
  caseId: string;
  correlationId: string;
  requestUrl: string;
  operationId: string;
  terminalResponse: boolean;
  forwardedMetadataValid: boolean;
  responseStatusCode: number;
  oidcHeaderCount: number;
  oidcValueCount: number;
  oidcVerifications: Sbx037PlatformOidcVerification[];
}

export interface Sbx037TerminalPEvidence {
  eventCount: number;
  event?: Sbx037TerminalPEvent;
}

/** Sanitized proof of B's non-reflecting file-backed HMAC action. */
export interface Sbx037OperatorSecretActionVerification {
  actionOrdinal: number;
  verifier: "observer-b-independent-file-hmac";
  algorithm: "HMAC-SHA256";
  secretSource: "controller-file-mode-0600";
  secretFileMode: number;
  hmacVerified: boolean;
  actionAuthorized: boolean;
  operationId: string;
  nonReflecting: boolean;
  rawSecretRetained: boolean;
  rawSecretReflected: boolean;
  responseBodyContainedSecret: boolean;
  verificationError?: string;
}

export interface Sbx037DestinationBEvent {
  runId: string;
  testId: string;
  caseId: string;
  correlationId: string;
  requestUrl: string;
  operationId: string;
  correlationMatched: boolean;
  responseStatusCode: number;
  oidcHeaderCount: number;
  oidcValueCount: number;
  oidcVerifications: Sbx037PlatformOidcVerification[];
  operatorSecretActions: Sbx037OperatorSecretActionVerification[];
}

export interface Sbx037DestinationBEvidence {
  eventCount: number;
  event?: Sbx037DestinationBEvent;
}

export type Sbx037FallbackRole = "A" | "P" | "B";

export interface Sbx037FallbackHeaderCardinality {
  lines: number;
  values: number;
}

export interface Sbx037FallbackOidcVerification
  extends Omit<Sbx037PlatformOidcVerification, "verifier"> {
  verifier: "observer-a-independent-jose" | Sbx037PlatformOidcVerification["verifier"];
  exactClaimsVerified: boolean;
}

/**
 * Secret-free, pre-dispatch receiver evidence for an attack that did not reach
 * the normal P/B terminal handler. Raw tokens and request bodies are never
 * valid fallback evidence.
 */
export interface Sbx037SanitizedFallbackEvent {
  observedAt: string;
  role: Sbx037FallbackRole;
  reason: "unmatched-a-route" | "unmatched-forward-path" | "unmatched-collect-path";
  runId: string;
  testId: string;
  caseId: string;
  correlationId: string;
  correlationMatched: boolean;
  method: string;
  requestTarget: string;
  host: string;
  bodyLength?: number;
  forwardedHeaderCounts: {
    host: Sbx037FallbackHeaderCardinality;
    scheme: Sbx037FallbackHeaderCardinality;
    port: Sbx037FallbackHeaderCardinality;
    path: Sbx037FallbackHeaderCardinality;
  };
  oidcHeaderCount: number;
  oidcValueCount: number;
  tokenVerified: boolean;
  algorithmRs256: boolean;
  issuerVerified: boolean;
  audienceVerified: boolean;
  temporalClaimsVerified: boolean;
  exactClaimsVerified: boolean;
  oidcVerifications: Sbx037FallbackOidcVerification[];
  operatorSecretBodyPresent: boolean;
  operatorSecretActionAttempted: boolean;
  operatorSecretActionAuthorized: boolean;
  actionOperationId?: string;
  operatorSecretActions: Sbx037OperatorSecretActionVerification[];
  receiptId: string;
  rawOidcTokenRetained: boolean;
  rawRequestBodyRetained: boolean;
  rawOperatorSecretRetained: boolean;
  rawOperatorSecretReflected: boolean;
  responseBodyContainedSecret: boolean;
  derivedSecretDigestRetained: boolean;
  terminalResponse: boolean;
  redirectAttempted: boolean;
  fetchAttempted: boolean;
  proxyAttempted: boolean;
  locationHeaderPresent: boolean;
  responseStatus: number;
}

export interface Sbx037SanitizedFallbackEvidence {
  eventCount: number;
  event?: Sbx037SanitizedFallbackEvent;
}

export interface Sbx037AttackCaseEvidence {
  caseId: string;
  targetForm: Exclude<Sbx037RequestTargetForm, "origin">;
  guest: Sbx037GuestRawRequestEvidence;
  p: Sbx037TerminalPEvidence;
  b: Sbx037DestinationBEvidence;
  fallback?: Sbx037SanitizedFallbackEvidence;
}

export interface Sbx037SyntaxAEvent {
  runId: string;
  testId: string;
  caseId: string;
  correlationId: string;
  correlationMatched: boolean;
  method: string;
  rawRequestTarget: string;
  targetForm: string;
  exactSyntaxTarget: boolean;
  publicBodyMatched: boolean;
  bodyLength: number;
  oidcHeaderCount: number;
  operationId?: string;
  terminalResponse: boolean;
  responseStatusCode: number;
}

export interface Sbx037SyntaxControlEvidence {
  caseId: string;
  targetForm: Exclude<Sbx037RequestTargetForm, "origin">;
  guest: Sbx037GuestRawRequestEvidence;
  a: { eventCount: number; event?: Sbx037SyntaxAEvent };
  bEventCount: number;
}

export interface Sbx037SyntaxPEvent extends Sbx037SyntaxAEvent {
  hostMatched: boolean;
  forwardedMetadataAbsent: boolean;
  redirectAttempted: boolean;
  fetchAttempted: boolean;
  proxyAttempted: boolean;
  locationHeaderPresent: boolean;
}

export interface Sbx037PSyntaxControlEvidence {
  caseId: string;
  targetForm: Exclude<Sbx037RequestTargetForm, "origin">;
  guest: Sbx037GuestRawRequestEvidence;
  p: { eventCount: number; event?: Sbx037SyntaxPEvent };
  bEventCount: number;
}

export interface Sbx037SourceBehaviorEvidence {
  redirectsIssued: number;
  outboundFetches: number;
  proxiedRequests: number;
}

export interface Sbx037CleanupEvidence {
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  sandboxAbsenceChecks: number;
  receiverDeleteAttempted: boolean;
  receiverDeleted: boolean;
  receiverAbsent: boolean;
  liveLockReleased: boolean;
  errors: string[];
}

export interface Sbx037EvidenceStorageEvidence {
  fileMode: number;
  rawTokensAbsent: boolean;
  rawOperatorSecretsAbsent: boolean;
  controllerCredentialsAbsent: boolean;
  controllerConfiguredCustomTrustAbsent: boolean;
  strictTlsVerificationRequired: boolean;
  inheritedPlatformTrustEnvironmentNamesObserved: string[];
}

export interface Sbx037AssessmentInput {
  executionError?: boolean;
  expected: Sbx037ExpectedEvidence;
  scope: Sbx037ScopeEvidence;
  policyPre: Sbx037PolicyReadbackEvidence;
  policyPost: Sbx037PolicyReadbackEvidence;
  initialBAllow: Sbx037InitialBAllowEvidence;
  directBPre: Sbx037DirectBBlockEvidence;
  directBPost: Sbx037DirectBBlockEvidence;
  originGuest: Sbx037GuestRawRequestEvidence;
  originP: Sbx037TerminalPEvidence;
  sourceBehavior: Sbx037SourceBehaviorEvidence;
  syntaxControls: Sbx037SyntaxControlEvidence[];
  pSyntaxControls: Sbx037PSyntaxControlEvidence[];
  attacks: Sbx037AttackCaseEvidence[];
  unexpectedPEventCount: number;
  unexpectedBEventCount: number;
  unexpectedFallbackEventCount?: number;
  cleanup: Sbx037CleanupEvidence;
  evidenceStorage: Sbx037EvidenceStorageEvidence;
}

export interface Sbx037AttackAssessment {
  caseId: string;
  targetForm: Exclude<Sbx037RequestTargetForm, "origin">;
  outcome: Sbx037AttackOutcome;
  oidcProofValid: boolean;
  operatorSecretProofValid: boolean;
  syntaxUnsupported: boolean;
  fallbackAttribution: "not-used" | Sbx037FallbackRole | "unattributed" | "invalid";
  terminalCloseLane: boolean;
  reason: string;
}

export interface Sbx037Assessment {
  verdict: Sbx037Verdict;
  severity: Sbx037Severity;
  candidate: boolean;
  controlsPassed: boolean;
  oidcAtBProofValid: boolean;
  operatorSecretProofValid: boolean;
  terminalCloseLane: boolean;
  summary: string;
  signals: string[];
  attacks: Sbx037AttackAssessment[];
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

function exactText(value: string): boolean {
  return value.length > 0 && value.length <= 2_048 && !/[\0\r\n]/u.test(value);
}

function nonnegativeInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function statusCode(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 100 && value <= 599;
}

function exactHttpsOrigin(value: string): boolean {
  if (!exactText(value)) return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" && parsed.origin === value && parsed.hostname.length > 0 &&
      parsed.username === "" && parsed.password === "" && parsed.pathname === "/" &&
      parsed.search === "" && parsed.hash === "";
  } catch {
    return false;
  }
}

export function exactHttpsUrl(actual: string, expected: string): boolean {
  if (actual !== expected || !exactText(actual)) return false;
  try {
    const parsed = new URL(actual);
    return parsed.protocol === "https:" && parsed.hostname.length > 0 &&
      parsed.username === "" && parsed.password === "" && parsed.hash === "";
  } catch {
    return false;
  }
}

function rawOriginTarget(url: string): string {
  const parsed = new URL(url);
  return `${parsed.pathname}${parsed.search}`;
}

function expectedForwardReceiverUrl(forwardAudience: string, forwardedTarget: string): string {
  return `${forwardAudience}${forwardedTarget}`;
}

function canonicalPublicIpv4(value: string): boolean {
  const octets = value.split(".");
  if (octets.length !== 4 || octets.some((part) => !/^(?:0|[1-9][0-9]{0,2})$/u.test(part))) return false;
  const [a = -1, b = -1, c = -1, d = -1] = octets.map(Number);
  return [a, b, c, d].every((part) => part >= 0 && part <= 255) && a > 0 && a < 224 && a !== 10 && a !== 127 &&
    !(a === 100 && b >= 64 && b <= 127) && !(a === 169 && b === 254) &&
    !(a === 172 && b >= 16 && b <= 31) && !(a === 192 && b === 168) &&
    !(a === 192 && b === 0 && (c === 0 || c === 2)) && !(a === 198 && (b === 18 || b === 19)) &&
    !(a === 198 && b === 51 && c === 100) && !(a === 203 && b === 0 && c === 113);
}

export function exactAudienceClaim(actual: string | string[], expected: string): boolean {
  return typeof actual === "string"
    ? actual === expected
    : Array.isArray(actual) && actual.length === 1 && actual[0] === expected;
}

function exactPlatformIssuerAndJwks(issuer: string, jwksUrl: string): boolean {
  if (!exactText(issuer) || !exactText(jwksUrl)) return false;
  try {
    const parsed = new URL(issuer);
    if (parsed.protocol !== "https:" || parsed.hostname !== "oidc.vercel.com" ||
      parsed.username !== "" || parsed.password !== "" || parsed.search !== "" || parsed.hash !== "") return false;
    return exactHttpsUrl(jwksUrl, `${issuer.replace(/\/$/u, "")}/.well-known/jwks`);
  } catch {
    return false;
  }
}

export function exactForwardPolicy(value: unknown, hostnameA: string, forwardAudienceP: string): boolean {
  const policy = object(value);
  const allow = object(policy?.allow);
  if (!policy || !allow || !exactKeys(policy, ["allow"]) || !exactKeys(allow, [hostnameA])) return false;
  const rules = allow[hostnameA];
  if (!Array.isArray(rules) || rules.length !== 1) return false;
  const rule = object(rules[0]);
  return rule !== undefined && exactKeys(rule, ["forwardURL"]) && rule.forwardURL === forwardAudienceP;
}

function exactIdentity(actual: Sbx037VerifiedOidcIdentity, expected: Sbx037ExpectedIdentity): boolean {
  return actual.teamId === expected.teamId && actual.projectId === expected.projectId &&
    actual.sandboxId === expected.sandboxId && actual.sessionId === expected.sessionId &&
    actual.sandboxName === expected.sandboxName;
}

export function exactPlatformOidcVerification(
  verification: Sbx037PlatformOidcVerification | undefined,
  expected: Sbx037ExpectedEvidence,
  verifier: Sbx037PlatformOidcVerification["verifier"],
): boolean {
  return verification !== undefined && verification.tokenOrdinal === 1 &&
    verification.verifier === verifier && verification.signatureVerified === true &&
    verification.algorithm === "RS256" &&
    exactPlatformIssuerAndJwks(verification.issuer, verification.jwksUrl) &&
    exactAudienceClaim(verification.audience, expected.forwardAudienceP) &&
    verification.temporalClaimsVerified === true && verification.rawTokenRetained === false &&
    verification.verificationError === undefined && exactIdentity(verification.identity, expected.identity);
}

function unique(values: string[]): boolean {
  return new Set(values).size === values.length;
}

function exactExpectedAttack(
  attack: Sbx037ExpectedAttackCase,
  expected: Sbx037ExpectedEvidence,
): boolean {
  if (![attack.caseId, attack.correlationId, attack.operationId, attack.actionOperationId].every(exactText) ||
    attack.operationId === attack.actionOperationId ||
    !statusCode(attack.terminalStatusCode) ||
    attack.method !== "POST" || attack.bodySource !== "file" ||
    Object.hasOwn(attack, "requestBodyBytes") ||
    attack.bodyFileMode !== 0o600 ||
    !exactHttpsUrl(attack.pTerminalUrl, attack.pTerminalUrl) ||
    !exactHttpsUrl(attack.bCollectUrl, attack.bCollectUrl)) return false;
  const bUrl = new URL(attack.bCollectUrl);
  const pUrl = new URL(attack.pTerminalUrl);
  if (bUrl.origin !== expected.bOrigin || pUrl.origin !== expected.pOrigin ||
    attack.pTerminalUrl !== expectedForwardReceiverUrl(expected.forwardAudienceP, rawOriginTarget(attack.bCollectUrl))) {
    return false;
  }
  if (attack.targetForm === "absolute") return attack.rawRequestTarget === attack.bCollectUrl;
  return attack.targetForm === "network-path" && attack.rawRequestTarget === `//${bUrl.host}${rawOriginTarget(attack.bCollectUrl)}`;
}

function exactExpectedSyntaxControl(
  control: Sbx037ExpectedSyntaxControl,
  expected: Sbx037ExpectedEvidence,
): boolean {
  if (![control.caseId, control.correlationId, control.operationId].every(exactText) ||
    control.method !== "POST" || control.bodySource !== "public" ||
    !Number.isSafeInteger(control.requestBodyBytes) || control.requestBodyBytes <= 0 ||
    typeof control.syntaxSupported !== "boolean" ||
    control.terminalStatusCode !== (control.syntaxSupported ? 202 : 400) ||
    !exactHttpsUrl(control.bCollectUrl, control.bCollectUrl) ||
    new URL(control.bCollectUrl).origin !== expected.bOrigin) return false;
  const bUrl = new URL(control.bCollectUrl);
  return control.targetForm === "absolute"
    ? control.rawRequestTarget === control.bCollectUrl
    : control.targetForm === "network-path" &&
      control.rawRequestTarget === `//${bUrl.host}${rawOriginTarget(control.bCollectUrl)}`;
}

function exactExpectedEvidence(expected: Sbx037ExpectedEvidence): boolean {
  if (expected.testId !== "SBX-037-POC" ||
    expected.aliasEmail !== SBX037_ALIAS_EMAIL || expected.identity.teamId !== SBX037_TEAM_ID ||
    expected.identity.projectId !== SBX037_PROJECT_ID ||
    ![expected.runId, expected.aliasEmail, expected.identity.teamId, expected.identity.projectId,
      expected.identity.sandboxId, expected.identity.sessionId, expected.identity.sandboxName].every(exactText) ||
    !exactHttpsOrigin(expected.aOrigin) || !exactHttpsOrigin(expected.pOrigin) || !exactHttpsOrigin(expected.bOrigin) ||
    !unique([expected.aOrigin, expected.pOrigin, expected.bOrigin]) ||
    !canonicalPublicIpv4(expected.pinnedAIpv4) || !canonicalPublicIpv4(expected.pinnedPIpv4) ||
    !canonicalPublicIpv4(expected.pinnedBIpv4) ||
    !exactHttpsUrl(expected.forwardAudienceP, expected.forwardAudienceP) ||
    new URL(expected.forwardAudienceP).origin !== expected.pOrigin ||
    !Array.isArray(expected.syntaxControls) || !Array.isArray(expected.pSyntaxControls) || !Array.isArray(expected.attacks) ||
    expected.syntaxControls.length !== 2 ||
    expected.syntaxControls.filter((entry) => entry.targetForm === "absolute").length !== 1 ||
    expected.syntaxControls.filter((entry) => entry.targetForm === "network-path").length !== 1 ||
    expected.attacks.length < 1 || expected.attacks.length > 2) return false;

  const supportedForms = expected.syntaxControls.filter((entry) => entry.syntaxSupported).map((entry) => entry.targetForm);
  if (supportedForms.length < 1 || !unique(supportedForms) ||
    expected.pSyntaxControls.length !== supportedForms.length ||
    expected.attacks.length !== supportedForms.length ||
    expected.pSyntaxControls.some((entry) => entry.syntaxSupported !== true) ||
    supportedForms.some((form) =>
      expected.pSyntaxControls.filter((entry) => entry.targetForm === form).length !== 1 ||
      expected.attacks.filter((entry) => entry.targetForm === form).length !== 1) ||
    expected.pSyntaxControls.some((entry) => !supportedForms.includes(entry.targetForm)) ||
    expected.attacks.some((entry) => !supportedForms.includes(entry.targetForm))) return false;

  const initial = expected.initialBAllow;
  const origin = expected.originControl;
  const direct = [expected.directBPre, expected.directBPost];
  if (![initial.caseId, initial.correlationId, initial.operationId, origin.caseId, origin.correlationId,
    origin.operationId, ...direct.flatMap((entry) => [entry.caseId, entry.correlationId])].every(exactText) ||
    !statusCode(initial.statusCode) || !statusCode(origin.terminalStatusCode) ||
    !["GET", "POST"].includes(origin.method) || origin.bodySource !== "public" ||
    !Number.isSafeInteger(origin.requestBodyBytes) || origin.requestBodyBytes <= 0 ||
    !exactHttpsUrl(initial.requestUrl, initial.requestUrl) || new URL(initial.requestUrl).origin !== expected.bOrigin ||
    !exactHttpsUrl(origin.aRequestUrl, origin.aRequestUrl) || new URL(origin.aRequestUrl).origin !== expected.aOrigin ||
    origin.rawRequestTarget !== rawOriginTarget(origin.aRequestUrl) || origin.rawRequestTarget.startsWith("//") ||
    !exactHttpsUrl(origin.pTerminalUrl, origin.pTerminalUrl) || new URL(origin.pTerminalUrl).origin !== expected.pOrigin ||
    origin.pTerminalUrl !== expectedForwardReceiverUrl(expected.forwardAudienceP, origin.rawRequestTarget) ||
    direct.some((entry) => !exactHttpsUrl(entry.requestUrl, entry.requestUrl) || new URL(entry.requestUrl).origin !== expected.bOrigin) ||
    !expected.syntaxControls.every((entry) => exactExpectedSyntaxControl(entry, expected)) ||
    !expected.pSyntaxControls.every((entry) => exactExpectedSyntaxControl(entry, expected)) ||
    !expected.attacks.every((entry) => exactExpectedAttack(entry, expected))) return false;

  const caseIds = [initial.caseId, origin.caseId, ...direct.map((entry) => entry.caseId),
    ...expected.syntaxControls.map((entry) => entry.caseId),
    ...expected.pSyntaxControls.map((entry) => entry.caseId), ...expected.attacks.map((entry) => entry.caseId)];
  const correlations = [initial.correlationId, origin.correlationId, ...direct.map((entry) => entry.correlationId),
    ...expected.syntaxControls.map((entry) => entry.correlationId),
    ...expected.pSyntaxControls.map((entry) => entry.correlationId), ...expected.attacks.map((entry) => entry.correlationId)];
  const operations = [initial.operationId, origin.operationId,
    ...expected.syntaxControls.map((entry) => entry.operationId),
    ...expected.pSyntaxControls.map((entry) => entry.operationId),
    ...expected.attacks.flatMap((entry) => [entry.operationId, entry.actionOperationId])];
  return unique(caseIds) && unique(correlations) && unique(operations);
}

function exactScope(scope: Sbx037ScopeEvidence, expected: Sbx037ExpectedEvidence): boolean {
  const origins = [expected.aOrigin, expected.pOrigin, expected.bOrigin].sort();
  const owned = [...scope.ownedOrigins].sort();
  return scope.authenticatedAliasEmail === expected.aliasEmail &&
    scope.authenticatedTeamId === expected.identity.teamId &&
    scope.authenticatedProjectId === expected.identity.projectId &&
    scope.scopeConfirmation === "researcher-controlled-sbx037-origins-only" &&
    scope.unownedEndpointCount === 0 && owned.length === origins.length && unique(owned) &&
    owned.every((origin, index) => origin === origins[index]);
}

export function exactPolicyReadback(
  evidence: Sbx037PolicyReadbackEvidence,
  expected: Sbx037ExpectedEvidence,
  stage: Sbx037PolicyReadbackEvidence["stage"],
): boolean {
  const a = new URL(expected.aOrigin);
  return evidence.stage === stage && evidence.activeSessionId === expected.identity.sessionId &&
    evidence.independentSessionId === expected.identity.sessionId &&
    exactForwardPolicy(evidence.activePolicy, a.hostname, expected.forwardAudienceP) &&
    exactForwardPolicy(evidence.independentPolicy, a.hostname, expected.forwardAudienceP);
}

function exactInitialBAllow(
  evidence: Sbx037InitialBAllowEvidence,
  expected: Sbx037ExpectedEvidence,
): boolean {
  const wanted = expected.initialBAllow;
  const event = evidence.destinationObserverEvent;
  return evidence.caseId === wanted.caseId && evidence.correlationId === wanted.correlationId &&
    exactHttpsUrl(evidence.requestUrl, wanted.requestUrl) && evidence.maximumConnections === 1 &&
    evidence.actualConnections === 1 && evidence.maximumRequests === 1 && evidence.actualRequests === 1 &&
    evidence.retryCount === 0 && evidence.redirectsAllowed === false && evidence.redirectsFollowed === 0 &&
    evidence.connectionReused === false && evidence.commandExitCode === 0 &&
    evidence.conclusiveReachability === true && evidence.responseStatusCode === wanted.statusCode &&
    evidence.responseOperationId === wanted.operationId && evidence.responseRole === "B" &&
    evidence.destinationObserverEventCount === 1 &&
    event !== undefined && event.runId === expected.runId && event.testId === expected.testId &&
    event.caseId === wanted.caseId && event.correlationId === wanted.correlationId &&
    exactHttpsUrl(event.requestUrl, wanted.requestUrl) && event.operationId === wanted.operationId;
}

export function exactDirectBFirewallBlock(
  evidence: Sbx037DirectBBlockEvidence,
  fullExpected: Sbx037ExpectedEvidence,
  expected: Sbx037ExpectedEvidence["directBPre"] | Sbx037ExpectedEvidence["directBPost"],
): boolean {
  const preConnectDeny = ["EHOSTUNREACH", "ENETUNREACH"].includes(evidence.errorCode) &&
    evidence.actualConnections === 0 && evidence.tcpConnected === false &&
    evidence.tlsEstablished === false && evidence.observedRemoteAddress === undefined;
  const connectedReset = evidence.errorCode === "ECONNRESET" && evidence.actualConnections === 1 &&
    evidence.tcpConnected === true && evidence.tlsEstablished === false &&
    evidence.observedRemoteAddress === fullExpected.pinnedBIpv4;
  return evidence.caseId === expected.caseId && evidence.correlationId === expected.correlationId &&
    exactHttpsUrl(evidence.requestUrl, expected.requestUrl) && evidence.maximumConnections === 1 &&
    evidence.maximumRequests === 1 && evidence.actualRequests === 0 && evidence.commandExitCode === 0 &&
    evidence.retryCount === 0 && evidence.redirectsAllowed === false && evidence.connectionReused === false &&
    evidence.configuredPinnedDestinationIpv4 === fullExpected.pinnedBIpv4 &&
    evidence.durationMs >= 0 && evidence.durationMs <= 2_000 && (preConnectDeny || connectedReset) &&
    evidence.samePinnedDestination === true && evidence.conclusiveFirewallBlock === true &&
    evidence.destinationObserverEventCount === 0;
}

export function exactRawGuestRequest(
  guest: Sbx037GuestRawRequestEvidence,
  expected: Sbx037ExpectedEvidence,
  wanted: {
    caseId: string;
    correlationId: string;
    targetForm: Sbx037RequestTargetForm;
    rawRequestTarget: string;
    operationId: string;
    terminalStatusCode: number;
    method: "GET" | "POST";
    bodySource: "public" | "file";
    requestBodyBytes?: number;
    bodyFileMode?: number;
    syntaxSupported?: boolean;
  },
  connectionOrigin: "a" | "p" = "a",
  expectedResponseRole: "A" | "P" | "B" = connectionOrigin === "a" ? "A" : "P",
): boolean {
  const destination = new URL(connectionOrigin === "a" ? expected.aOrigin : expected.pOrigin);
  const pinnedIpv4 = connectionOrigin === "a" ? expected.pinnedAIpv4 : expected.pinnedPIpv4;
  const syntaxSupported = wanted.syntaxSupported ?? true;
  return guest.commandExitCode === 0 && guest.ok === true && guest.runId === expected.runId &&
    guest.testId === expected.testId && guest.caseId === wanted.caseId &&
    guest.correlationId === wanted.correlationId && guest.targetForm === wanted.targetForm &&
    guest.connectionRole === connectionOrigin &&
    guest.syntaxSupported === syntaxSupported && guest.method === wanted.method &&
    guest.bodySource === wanted.bodySource &&
    (wanted.bodySource === "file"
      ? guest.operatorSecretLoaded === true && guest.requestBodyBytes === undefined &&
        !Object.hasOwn(guest, "requestBodyBytes") && guest.bodyFileMode === 0o600 && wanted.bodyFileMode === 0o600
      : guest.operatorSecretLoaded === false && guest.requestBodyBytes === wanted.requestBodyBytes &&
        guest.bodyFileMode === undefined) &&
    guest.httpVersion === "1.1" &&
    guest.tcpHost === destination.hostname && guest.tcpPort === 443 && guest.tlsServername === destination.hostname &&
    guest.httpHost === destination.host && guest.rawRequestTarget === wanted.rawRequestTarget &&
    guest.maximumConnections === 1 && guest.actualConnections === 1 && guest.maximumRequests === 1 &&
    guest.actualRequests === 1 && guest.retryCount === 0 && guest.redirectsAllowed === false &&
    guest.redirectsFollowed === 0 && guest.connectionReused === false &&
    guest.environmentProxyTrust === false &&
    exactInheritedPlatformTrustEnvironmentNames(guest.tlsTrust?.inheritedPlatformTrustEnvironmentNames) &&
    guest.tlsTrust.controllerConfigurableCustomTrustAccepted === false &&
    guest.tlsTrust.rejectUnauthorized === true && guest.responseStatusCode === wanted.terminalStatusCode &&
    (syntaxSupported
      ? guest.responseOperationId === wanted.operationId
      : guest.responseOperationId === undefined && !Object.hasOwn(guest, "responseOperationId")) &&
    guest.responseFallbackReceiptId === undefined && !Object.hasOwn(guest, "responseFallbackReceiptId") &&
    guest.responseRole === expectedResponseRole &&
    guest.pinnedDestinationIpv4 === pinnedIpv4 && guest.transportTcpConnected === true &&
    guest.transportTlsEstablished === true && guest.transportAuthorized === true &&
    guest.transportRemoteAddress === pinnedIpv4 && guest.transportRemotePort === 443 &&
    guest.transportAlpnProtocol === "http/1.1";
}

function exactSyntaxControl(
  evidence: Sbx037SyntaxControlEvidence,
  expected: Sbx037ExpectedEvidence,
  wanted: Sbx037ExpectedSyntaxControl,
): boolean {
  const event = evidence.a.event;
  const common = evidence.caseId === wanted.caseId && evidence.targetForm === wanted.targetForm &&
    exactRawGuestRequest(evidence.guest, expected, wanted) && evidence.a.eventCount === 1 &&
    event !== undefined && event.runId === expected.runId && event.testId === expected.testId &&
    event.caseId === wanted.caseId && event.correlationId === wanted.correlationId &&
    event.correlationMatched === true && event.method === wanted.method && event.publicBodyMatched === true &&
    event.bodyLength === wanted.requestBodyBytes && event.oidcHeaderCount === 0 &&
    event.terminalResponse === true && event.responseStatusCode === wanted.terminalStatusCode &&
    evidence.bEventCount === 0;
  if (!common) return false;
  if (wanted.syntaxSupported) {
    return event.rawRequestTarget === wanted.rawRequestTarget && event.targetForm === wanted.targetForm &&
      event.exactSyntaxTarget === true && event.operationId === wanted.operationId;
  }
  return wanted.terminalStatusCode === 400 &&
    event.rawRequestTarget === rawOriginTarget(wanted.bCollectUrl) && event.targetForm === "other" &&
    event.exactSyntaxTarget === false && event.operationId === undefined;
}

function exactPSyntaxControl(
  evidence: Sbx037PSyntaxControlEvidence,
  expected: Sbx037ExpectedEvidence,
  wanted: Sbx037ExpectedSyntaxControl,
): boolean {
  const event = evidence.p.event;
  return wanted.syntaxSupported === true && evidence.caseId === wanted.caseId && evidence.targetForm === wanted.targetForm &&
    exactRawGuestRequest(evidence.guest, expected, wanted, "p") && evidence.p.eventCount === 1 &&
    event !== undefined && event.runId === expected.runId && event.testId === expected.testId &&
    event.caseId === wanted.caseId && event.correlationId === wanted.correlationId &&
    event.correlationMatched === true && event.method === wanted.method &&
    event.bodyLength === wanted.requestBodyBytes && event.rawRequestTarget === wanted.rawRequestTarget &&
    event.targetForm === wanted.targetForm && event.exactSyntaxTarget === true &&
    event.hostMatched === true && event.publicBodyMatched === true && event.oidcHeaderCount === 0 &&
    event.forwardedMetadataAbsent === true && event.operationId === wanted.operationId &&
    event.terminalResponse === true && event.redirectAttempted === false &&
    event.fetchAttempted === false && event.proxyAttempted === false && event.locationHeaderPresent === false &&
    event.responseStatusCode === wanted.terminalStatusCode && evidence.bEventCount === 0;
}

function exactTerminalP(
  evidence: Sbx037TerminalPEvidence,
  expected: Sbx037ExpectedEvidence,
  wanted: { caseId: string; correlationId: string; pTerminalUrl: string; operationId: string; terminalStatusCode: number },
): boolean {
  const event = evidence.event;
  return evidence.eventCount === 1 && event !== undefined && event.runId === expected.runId &&
    event.testId === expected.testId && event.caseId === wanted.caseId &&
    event.correlationId === wanted.correlationId && exactHttpsUrl(event.requestUrl, wanted.pTerminalUrl) &&
    event.operationId === wanted.operationId && event.terminalResponse === true && event.forwardedMetadataValid === true &&
    event.responseStatusCode === wanted.terminalStatusCode && event.oidcHeaderCount === 1 &&
    event.oidcValueCount === 1 && event.oidcVerifications.length === 1 &&
    exactPlatformOidcVerification(event.oidcVerifications[0], expected, "sink-p-independent-jose");
}

function exactEmptyP(evidence: Sbx037TerminalPEvidence): boolean {
  return evidence.eventCount === 0 && evidence.event === undefined;
}

function exactEmptyB(evidence: Sbx037DestinationBEvidence): boolean {
  return evidence.eventCount === 0 && evidence.event === undefined;
}

function exactDestinationB(
  evidence: Sbx037DestinationBEvidence,
  expected: Sbx037ExpectedEvidence,
  wanted: Sbx037ExpectedAttackCase,
): evidence is Sbx037DestinationBEvidence & { event: Sbx037DestinationBEvent } {
  const event = evidence.event;
  return evidence.eventCount === 1 && event !== undefined && event.runId === expected.runId &&
    event.testId === expected.testId && event.caseId === wanted.caseId &&
    event.correlationId === wanted.correlationId && exactHttpsUrl(event.requestUrl, wanted.bCollectUrl) &&
    event.operationId === wanted.operationId && event.correlationMatched === true &&
    event.responseStatusCode === wanted.terminalStatusCode && nonnegativeInteger(event.oidcHeaderCount) &&
    nonnegativeInteger(event.oidcValueCount) && Array.isArray(event.oidcVerifications) &&
    Array.isArray(event.operatorSecretActions);
}

function exactEmptyFallback(evidence: Sbx037SanitizedFallbackEvidence | undefined): boolean {
  return evidence === undefined || (evidence.eventCount === 0 && evidence.event === undefined);
}

function exactInstrumentedEmptyFallback(evidence: Sbx037SanitizedFallbackEvidence | undefined): boolean {
  return evidence !== undefined && evidence.eventCount === 0 && evidence.event === undefined;
}

function syntaxSupportedForStatus(status: number): boolean {
  return ![400, 414, 431, 501, 505].includes(status);
}

function exactFallbackGuestRequest(
  guest: Sbx037GuestRawRequestEvidence,
  expected: Sbx037ExpectedEvidence,
  wanted: Sbx037ExpectedAttackCase,
  responseStatusCode: number,
  responseRole: Sbx037FallbackRole | undefined,
  responseFallbackReceiptId: string | undefined,
): boolean {
  const a = new URL(expected.aOrigin);
  const fallbackReceiptExact = responseFallbackReceiptId === undefined
    ? guest.responseFallbackReceiptId === undefined && !Object.hasOwn(guest, "responseFallbackReceiptId") &&
      (guest.responseRole === undefined && !Object.hasOwn(guest, "responseRole") ||
        guest.responseRole === "A" || guest.responseRole === "P" || guest.responseRole === "B")
    : FALLBACK_RECEIPT_ID.test(responseFallbackReceiptId) &&
      guest.responseFallbackReceiptId === responseFallbackReceiptId && guest.responseRole === responseRole;
  return guest.commandExitCode === 0 && guest.ok === true && guest.runId === expected.runId &&
    guest.testId === expected.testId && guest.caseId === wanted.caseId &&
    guest.correlationId === wanted.correlationId && guest.targetForm === wanted.targetForm &&
    guest.connectionRole === "a" && guest.syntaxSupported === syntaxSupportedForStatus(responseStatusCode) &&
    guest.method === wanted.method && guest.bodySource === wanted.bodySource &&
    guest.operatorSecretLoaded === true && guest.requestBodyBytes === undefined &&
    !Object.hasOwn(guest, "requestBodyBytes") && guest.bodyFileMode === 0o600 && wanted.bodyFileMode === 0o600 &&
    guest.httpVersion === "1.1" && guest.tcpHost === a.hostname && guest.tcpPort === 443 &&
    guest.tlsServername === a.hostname && guest.httpHost === a.host &&
    guest.rawRequestTarget === wanted.rawRequestTarget && guest.maximumConnections === 1 &&
    guest.actualConnections === 1 && guest.maximumRequests === 1 && guest.actualRequests === 1 &&
    guest.retryCount === 0 && guest.redirectsAllowed === false && guest.redirectsFollowed === 0 &&
    guest.connectionReused === false && guest.environmentProxyTrust === false &&
    exactInheritedPlatformTrustEnvironmentNames(guest.tlsTrust?.inheritedPlatformTrustEnvironmentNames) &&
    guest.tlsTrust.controllerConfigurableCustomTrustAccepted === false &&
    guest.tlsTrust.rejectUnauthorized === true && guest.responseStatusCode === responseStatusCode &&
    guest.responseOperationId === undefined && !Object.hasOwn(guest, "responseOperationId") && fallbackReceiptExact &&
    guest.pinnedDestinationIpv4 === expected.pinnedAIpv4 && guest.transportTcpConnected === true &&
    guest.transportTlsEstablished === true && guest.transportAuthorized === true &&
    guest.transportRemoteAddress === expected.pinnedAIpv4 && guest.transportRemotePort === 443 &&
    guest.transportAlpnProtocol === "http/1.1";
}

function exactFallbackCommon(
  evidence: Sbx037SanitizedFallbackEvidence | undefined,
  expected: Sbx037ExpectedEvidence,
  wanted: Sbx037ExpectedAttackCase,
  guest: Sbx037GuestRawRequestEvidence,
): evidence is Sbx037SanitizedFallbackEvidence & { event: Sbx037SanitizedFallbackEvent } {
  const event = evidence?.event;
  return evidence?.eventCount === 1 && event !== undefined &&
    exactText(event.observedAt) && !Number.isNaN(Date.parse(event.observedAt)) &&
    event.runId === expected.runId && event.testId === expected.testId && event.caseId === wanted.caseId &&
    event.correlationId === wanted.correlationId && event.correlationMatched === true &&
    event.method === wanted.method && exactText(event.requestTarget) && exactText(event.host) &&
    event.bodyLength === undefined && !Object.hasOwn(event, "bodyLength") &&
    FALLBACK_RECEIPT_ID.test(event.receiptId) && event.terminalResponse === true && event.responseStatus === 404 &&
    exactFallbackHeaderSetShape(event.forwardedHeaderCounts) &&
    nonnegativeInteger(event.oidcHeaderCount) && event.oidcHeaderCount <= 2 &&
    nonnegativeInteger(event.oidcValueCount) && event.oidcValueCount <= 2 &&
    Array.isArray(event.oidcVerifications) && event.oidcVerifications.length <= 2 &&
    Array.isArray(event.operatorSecretActions) && event.operatorSecretActions.length <= 1 &&
    event.redirectAttempted === false && event.fetchAttempted === false && event.proxyAttempted === false &&
    event.locationHeaderPresent === false && event.rawOidcTokenRetained === false &&
    event.rawRequestBodyRetained === false && event.rawOperatorSecretRetained === false &&
    event.rawOperatorSecretReflected === false && event.responseBodyContainedSecret === false &&
    event.derivedSecretDigestRetained === false &&
    exactFallbackGuestRequest(guest, expected, wanted, event.responseStatus, event.role, event.receiptId);
}

function exactFallbackHeaderCardinality(
  value: Sbx037FallbackHeaderCardinality,
  lines: number,
  values = lines,
): boolean {
  const record = object(value);
  return record !== undefined && exactKeys(record, ["lines", "values"]) &&
    value.lines === lines && value.values === values;
}

function exactFallbackHeaderSetShape(value: Sbx037SanitizedFallbackEvent["forwardedHeaderCounts"]): boolean {
  const record = object(value);
  return record !== undefined && exactKeys(record, ["host", "scheme", "port", "path"]) &&
    Object.values(value).every((entry) =>
      nonnegativeInteger(entry.lines) && entry.lines <= 2 &&
      nonnegativeInteger(entry.values) && entry.values <= 2);
}

function exactFallbackHeaderSet(
  value: Sbx037SanitizedFallbackEvent["forwardedHeaderCounts"],
  count: number,
): boolean {
  return exactFallbackHeaderSetShape(value) &&
    exactFallbackHeaderCardinality(value.host, count) &&
    exactFallbackHeaderCardinality(value.scheme, count) &&
    exactFallbackHeaderCardinality(value.port, count) &&
    exactFallbackHeaderCardinality(value.path, count);
}

function exactFallbackVerificationShape(
  verification: Sbx037FallbackOidcVerification,
  verifier: Sbx037FallbackOidcVerification["verifier"],
): boolean {
  return verification.tokenOrdinal === 1 && verification.verifier === verifier &&
    verification.signatureVerified === true && verification.algorithm === "RS256" &&
    exactPlatformIssuerAndJwks(verification.issuer, verification.jwksUrl) &&
    (typeof verification.audience === "string"
      ? exactText(verification.audience)
      : Array.isArray(verification.audience) && verification.audience.length === 1 &&
        exactText(verification.audience[0] ?? "")) &&
    typeof verification.temporalClaimsVerified === "boolean" &&
    typeof verification.exactClaimsVerified === "boolean" &&
    [verification.identity.teamId, verification.identity.projectId, verification.identity.sandboxId,
      verification.identity.sessionId, verification.identity.sandboxName].every(exactText) &&
    verification.rawTokenRetained === false &&
    (verification.verificationError === undefined || exactText(verification.verificationError));
}

function exactFallbackOidcProof(
  event: Sbx037SanitizedFallbackEvent,
  expected: Sbx037ExpectedEvidence,
  verifier: Sbx037PlatformOidcVerification["verifier"],
): boolean {
  const verification = event.oidcVerifications[0];
  return event.oidcHeaderCount === 1 && event.oidcValueCount === 1 && event.tokenVerified === true &&
    event.algorithmRs256 === true && event.issuerVerified === true && event.audienceVerified === true &&
    event.temporalClaimsVerified === true && event.exactClaimsVerified === true &&
    event.oidcVerifications.length === 1 && verification !== undefined &&
    verification.exactClaimsVerified === true && exactFallbackVerificationShape(verification, verifier) &&
    exactPlatformOidcVerification(verification as Sbx037PlatformOidcVerification, expected, verifier);
}

function exactNoFallbackOidc(event: Sbx037SanitizedFallbackEvent): boolean {
  return event.oidcHeaderCount === 0 && event.oidcValueCount === 0 && event.tokenVerified === false &&
    event.algorithmRs256 === false && event.issuerVerified === false && event.audienceVerified === false &&
    event.temporalClaimsVerified === false && event.exactClaimsVerified === false &&
    event.oidcVerifications.length === 0;
}

function exactFallbackBOidcEnvelope(
  event: Sbx037SanitizedFallbackEvent,
  expected: Sbx037ExpectedEvidence,
): boolean {
  if (event.oidcHeaderCount === 0 || event.oidcValueCount === 0) return exactNoFallbackOidc(event);
  if (event.oidcHeaderCount !== 1 || event.oidcValueCount !== 1) return false;
  if (exactFallbackOidcProof(event, expected, "observer-b-independent-jose")) return true;
  if (event.tokenVerified !== false || event.oidcVerifications.length > 1) return false;
  return event.oidcVerifications.every((verification) =>
    exactFallbackVerificationShape(verification, "observer-b-independent-jose"));
}

function exactNoFallbackSecret(event: Sbx037SanitizedFallbackEvent): boolean {
  return event.operatorSecretBodyPresent === false && event.operatorSecretActionAttempted === false &&
    event.operatorSecretActionAuthorized === false && event.actionOperationId === undefined &&
    !Object.hasOwn(event, "actionOperationId") && event.operatorSecretActions.length === 0;
}

function exactFallbackBSecret(
  event: Sbx037SanitizedFallbackEvent,
  wanted: Sbx037ExpectedAttackCase,
): boolean {
  if (exactNoFallbackSecret(event)) return true;
  if (event.operatorSecretBodyPresent === true && event.operatorSecretActionAttempted === true &&
    event.operatorSecretActionAuthorized === false && event.actionOperationId === undefined &&
    !Object.hasOwn(event, "actionOperationId") && event.operatorSecretActions.length === 0) return true;
  return event.operatorSecretBodyPresent === true && event.operatorSecretActionAttempted === true &&
    event.operatorSecretActionAuthorized === true && event.actionOperationId === wanted.actionOperationId &&
    event.operatorSecretActions.length === 1 &&
    exactOperatorSecretAction(event.operatorSecretActions[0], wanted.actionOperationId);
}

function exactFallbackA(
  evidence: Sbx037SanitizedFallbackEvidence | undefined,
  expected: Sbx037ExpectedEvidence,
  wanted: Sbx037ExpectedAttackCase,
  guest: Sbx037GuestRawRequestEvidence,
): boolean {
  const event = evidence?.event;
  return exactFallbackCommon(evidence, expected, wanted, guest) && event !== undefined &&
    event.role === "A" && event.reason === "unmatched-a-route" &&
    event.host === new URL(expected.aOrigin).host && event.requestTarget === wanted.rawRequestTarget &&
    exactFallbackHeaderSet(event.forwardedHeaderCounts, 0) && exactNoFallbackOidc(event) &&
    exactNoFallbackSecret(event);
}

function exactFallbackP(
  evidence: Sbx037SanitizedFallbackEvidence | undefined,
  expected: Sbx037ExpectedEvidence,
  wanted: Sbx037ExpectedAttackCase,
  guest: Sbx037GuestRawRequestEvidence,
): boolean {
  const event = evidence?.event;
  if (!exactFallbackCommon(evidence, expected, wanted, guest) || !event || event.role !== "P" ||
    event.reason !== "unmatched-forward-path" || event.host !== new URL(expected.pOrigin).host ||
    !exactFallbackHeaderSet(event.forwardedHeaderCounts, 1) ||
    !exactFallbackOidcProof(event, expected, "sink-p-independent-jose") || !exactNoFallbackSecret(event)) return false;
  return true;
}

function exactFallbackB(
  evidence: Sbx037SanitizedFallbackEvidence | undefined,
  expected: Sbx037ExpectedEvidence,
  wanted: Sbx037ExpectedAttackCase,
  guest: Sbx037GuestRawRequestEvidence,
): boolean {
  const event = evidence?.event;
  if (!exactFallbackCommon(evidence, expected, wanted, guest) || !event || event.role !== "B" ||
    event.reason !== "unmatched-collect-path" || event.host !== new URL(expected.bOrigin).host ||
    !(exactFallbackHeaderSet(event.forwardedHeaderCounts, 0) || exactFallbackHeaderSet(event.forwardedHeaderCounts, 1)) ||
    !exactFallbackBOidcEnvelope(event, expected) || !exactFallbackBSecret(event, wanted)) return false;
  return true;
}

export function exactOperatorSecretAction(
  verification: Sbx037OperatorSecretActionVerification | undefined,
  operationId: string,
): boolean {
  return verification !== undefined && verification.actionOrdinal === 1 &&
    verification.verifier === "observer-b-independent-file-hmac" && verification.algorithm === "HMAC-SHA256" &&
    verification.secretSource === "controller-file-mode-0600" && verification.secretFileMode === 0o600 &&
    verification.hmacVerified === true && verification.actionAuthorized === true &&
    verification.operationId === operationId && verification.nonReflecting === true &&
    verification.rawSecretRetained === false && verification.rawSecretReflected === false &&
    verification.responseBodyContainedSecret === false && verification.verificationError === undefined;
}

function exactCleanup(cleanup: Sbx037CleanupEvidence): boolean {
  return cleanup.stopAttempted === true && cleanup.stopped === true && cleanup.deleteAttempted === true &&
    cleanup.deleted === true && cleanup.sandboxAbsenceChecks === 3 && cleanup.receiverDeleteAttempted === true &&
    cleanup.receiverDeleted === true && cleanup.receiverAbsent === true && cleanup.liveLockReleased === true &&
    Array.isArray(cleanup.errors) && cleanup.errors.length === 0;
}

function exactEvidenceStorage(storage: Sbx037EvidenceStorageEvidence): boolean {
  return storage.fileMode === 0o600 && storage.rawTokensAbsent === true &&
    storage.rawOperatorSecretsAbsent === true && storage.controllerCredentialsAbsent === true &&
    storage.controllerConfiguredCustomTrustAbsent === true && storage.strictTlsVerificationRequired === true &&
    exactInheritedPlatformTrustEnvironmentNames(storage.inheritedPlatformTrustEnvironmentNamesObserved);
}

function assessAttack(
  evidence: Sbx037AttackCaseEvidence,
  expected: Sbx037ExpectedEvidence,
  wanted: Sbx037ExpectedAttackCase,
): Sbx037AttackAssessment {
  const base = { caseId: wanted.caseId, targetForm: wanted.targetForm };
  const unsupported = evidence.caseId === wanted.caseId && evidence.targetForm === wanted.targetForm &&
    evidence.guest.commandExitCode === 0 &&
    evidence.guest.runId === expected.runId && evidence.guest.testId === expected.testId &&
    evidence.guest.caseId === wanted.caseId && evidence.guest.correlationId === wanted.correlationId &&
    evidence.guest.targetForm === wanted.targetForm && evidence.guest.syntaxSupported === false &&
    evidence.guest.connectionRole === "a" &&
    evidence.guest.method === wanted.method && evidence.guest.bodySource === wanted.bodySource &&
    evidence.guest.operatorSecretLoaded === true && evidence.guest.requestBodyBytes === undefined &&
    !Object.hasOwn(evidence.guest, "requestBodyBytes") &&
    evidence.guest.bodyFileMode === wanted.bodyFileMode && evidence.guest.httpVersion === "1.1" &&
    evidence.guest.tcpHost === new URL(expected.aOrigin).hostname && evidence.guest.tcpPort === 443 &&
    evidence.guest.tlsServername === new URL(expected.aOrigin).hostname &&
    evidence.guest.httpHost === new URL(expected.aOrigin).host &&
    evidence.guest.rawRequestTarget === wanted.rawRequestTarget &&
    evidence.guest.maximumConnections === 1 && evidence.guest.actualConnections === 1 &&
    evidence.guest.maximumRequests === 1 && evidence.guest.actualRequests === 1 &&
    evidence.guest.retryCount === 0 && evidence.guest.redirectsAllowed === false &&
    evidence.guest.redirectsFollowed === 0 && evidence.guest.connectionReused === false &&
    evidence.guest.environmentProxyTrust === false &&
    exactInheritedPlatformTrustEnvironmentNames(
      evidence.guest.tlsTrust?.inheritedPlatformTrustEnvironmentNames,
    ) &&
    evidence.guest.tlsTrust.controllerConfigurableCustomTrustAccepted === false &&
    evidence.guest.tlsTrust.rejectUnauthorized === true &&
    evidence.guest.responseFallbackReceiptId === undefined &&
    !Object.hasOwn(evidence.guest, "responseFallbackReceiptId") && evidence.guest.responseRole === "A" &&
    evidence.guest.pinnedDestinationIpv4 === expected.pinnedAIpv4 &&
    evidence.guest.transportTcpConnected === true && evidence.guest.transportTlsEstablished === true &&
    evidence.guest.transportAuthorized === true && evidence.guest.transportRemoteAddress === expected.pinnedAIpv4 &&
    evidence.guest.transportRemotePort === 443 && evidence.guest.transportAlpnProtocol === "http/1.1" &&
    exactEmptyP(evidence.p) && exactEmptyB(evidence.b);
  if (unsupported) {
    return { ...base, outcome: "indeterminate", oidcProofValid: false, operatorSecretProofValid: false,
      syntaxUnsupported: true, fallbackAttribution: "not-used", terminalCloseLane: false,
      reason: "the raw request-target syntax was unsupported" };
  }
  if (evidence.caseId !== wanted.caseId || evidence.targetForm !== wanted.targetForm) {
    return { ...base, outcome: "indeterminate", oidcProofValid: false, operatorSecretProofValid: false, syntaxUnsupported: false,
      fallbackAttribution: "invalid", terminalCloseLane: false,
      reason: "the attack case or target form was not exact" };
  }

  const primaryGuestPExact = exactRawGuestRequest(evidence.guest, expected, wanted, "a", "P");
  const primaryGuestBExact = exactRawGuestRequest(evidence.guest, expected, wanted, "a", "B");
  const pExact = primaryGuestPExact && exactTerminalP(evidence.p, expected, wanted);
  const bExact = primaryGuestBExact && exactDestinationB(evidence.b, expected, wanted);
  const fallbackEmpty = exactEmptyFallback(evidence.fallback);
  if (pExact && exactEmptyB(evidence.b) && fallbackEmpty) {
    return { ...base, outcome: "pass", oidcProofValid: false, operatorSecretProofValid: false, syntaxUnsupported: false,
      fallbackAttribution: "not-used", terminalCloseLane: false,
      reason: "the supported raw target terminated only at authenticated P and B remained absent" };
  }
  if (bExact && exactEmptyP(evidence.p) && fallbackEmpty) {
    const event = evidence.b.event!;
    const oidcProofValid = event.oidcHeaderCount === 1 && event.oidcValueCount === 1 &&
      event.oidcVerifications.length === 1 &&
      exactPlatformOidcVerification(event.oidcVerifications[0], expected, "observer-b-independent-jose");
    const operatorSecretProofValid = event.operatorSecretActions.length === 1 &&
      exactOperatorSecretAction(event.operatorSecretActions[0], wanted.actionOperationId);
    if (oidcProofValid || operatorSecretProofValid) {
      return { ...base, outcome: "candidate-high", oidcProofValid, operatorSecretProofValid, syntaxUnsupported: false,
        fallbackAttribution: "not-used", terminalCloseLane: false,
        reason: "denied B returned the exact correlated receipt and independently proved credential impact" };
    }
    return { ...base, outcome: "candidate-medium", oidcProofValid: false, operatorSecretProofValid: false,
      syntaxUnsupported: false, fallbackAttribution: "not-used", terminalCloseLane: false,
      reason: "denied B was reached exactly, but no exact independently verified credential action was proved" };
  }

  if (!exactEmptyP(evidence.p) || !exactEmptyB(evidence.b)) {
    return { ...base, outcome: "indeterminate", oidcProofValid: false, operatorSecretProofValid: false,
      syntaxUnsupported: false, fallbackAttribution: "invalid", terminalCloseLane: false,
      reason: "primary and fallback sink activity was missing, mixed, duplicated, or not exactly attributable" };
  }

  if (exactFallbackP(evidence.fallback, expected, wanted, evidence.guest)) {
    return { ...base, outcome: "pass", oidcProofValid: false, operatorSecretProofValid: false,
      syntaxUnsupported: false, fallbackAttribution: "P", terminalCloseLane: false,
      reason: "P independently authenticated an exact non-escaping path-join rejection and A/B remained absent" };
  }
  if (exactFallbackA(evidence.fallback, expected, wanted, evidence.guest)) {
    return { ...base, outcome: "pass", oidcProofValid: false, operatorSecretProofValid: false,
      syntaxUnsupported: false, fallbackAttribution: "A", terminalCloseLane: false,
      reason: "A returned an exact correlated ingress rejection and P/B remained absent" };
  }
  if (exactFallbackB(evidence.fallback, expected, wanted, evidence.guest)) {
    const event = evidence.fallback!.event!;
    const oidcProofValid = exactFallbackOidcProof(event, expected, "observer-b-independent-jose");
    const operatorSecretProofValid = event.operatorSecretActions.length === 1 &&
      exactOperatorSecretAction(event.operatorSecretActions[0], wanted.actionOperationId);
    if (oidcProofValid || operatorSecretProofValid) {
      return { ...base, outcome: "candidate-high", oidcProofValid, operatorSecretProofValid,
        syntaxUnsupported: false, fallbackAttribution: "B", terminalCloseLane: false,
        reason: "sanitized fallback evidence joined denied B to the guest receipt and independently proved credential impact" };
    }
    return { ...base, outcome: "candidate-medium", oidcProofValid: false, operatorSecretProofValid: false,
      syntaxUnsupported: false, fallbackAttribution: "B", terminalCloseLane: false,
      reason: "sanitized fallback evidence joined denied B to the guest receipt without exact credential proof" };
  }

  if (exactInstrumentedEmptyFallback(evidence.fallback) &&
    exactFallbackGuestRequest(evidence.guest, expected, wanted, 404, undefined, undefined)) {
    return { ...base, outcome: "indeterminate", oidcProofValid: false, operatorSecretProofValid: false,
      syntaxUnsupported: false, fallbackAttribution: "unattributed", terminalCloseLane: true,
      reason: "the diagnostic rerun again returned a terminal 404 with zero attributable A/P/B fallback events" };
  }

  return { ...base, outcome: "indeterminate", oidcProofValid: false, operatorSecretProofValid: false,
    syntaxUnsupported: false, fallbackAttribution: "invalid", terminalCloseLane: false,
    reason: "raw request, receipt, or sanitized fallback evidence was not exact" };
}

function result(
  verdict: Sbx037Verdict,
  severity: Sbx037Severity,
  controlsPassed: boolean,
  summary: string,
  signals: string[],
  attacks: Sbx037AttackAssessment[] = [],
): Sbx037Assessment {
  return {
    verdict,
    severity,
    candidate: verdict === "candidate-medium" || verdict === "candidate-high",
    controlsPassed,
    oidcAtBProofValid: verdict === "candidate-high" && attacks.some((entry) => entry.oidcProofValid),
    operatorSecretProofValid: verdict === "candidate-high" && attacks.some((entry) => entry.operatorSecretProofValid),
    terminalCloseLane: verdict === "indeterminate" && attacks.some((entry) => entry.terminalCloseLane),
    summary,
    signals,
    attacks,
  };
}

export function assessSbx037(input: Sbx037AssessmentInput): Sbx037Assessment {
  if (!exactCleanup(input.cleanup)) {
    return result("error", "unknown", false,
      "Strict sandbox, receiver, absence, or lock cleanup failed; no finding is classified.",
      ["cleanup was not exact"]);
  }
  if (!exactEvidenceStorage(input.evidenceStorage)) {
    return result("error", "unknown", false,
      "Secret-free mode-0600 evidence requirements failed; no finding is classified.",
      ["evidence storage was not exact"]);
  }
  if (input.executionError) {
    return result("error", "unknown", false,
      "Controller execution failed before a complete SBX-037 assessment.", ["execution error: true"]);
  }

  const expectedValid = exactExpectedEvidence(input.expected);
  const scopeValid = expectedValid && exactScope(input.scope, input.expected);
  const policyPreValid = expectedValid && exactPolicyReadback(input.policyPre, input.expected, "pre-attack");
  const policyPostValid = expectedValid && exactPolicyReadback(input.policyPost, input.expected, "post-attack");
  const initialAllowValid = expectedValid && exactInitialBAllow(input.initialBAllow, input.expected);
  const directPreValid = expectedValid && exactDirectBFirewallBlock(input.directBPre, input.expected, input.expected.directBPre);
  const directPostValid = expectedValid && exactDirectBFirewallBlock(input.directBPost, input.expected, input.expected.directBPost);
  const originGuestValid = expectedValid && exactRawGuestRequest(input.originGuest, input.expected, {
    ...input.expected.originControl,
    targetForm: "origin",
  }, "a", "P");
  const originPValid = expectedValid && exactTerminalP(input.originP, input.expected, input.expected.originControl);
  const sourceTerminalOnly = input.sourceBehavior.redirectsIssued === 0 &&
    input.sourceBehavior.outboundFetches === 0 && input.sourceBehavior.proxiedRequests === 0;
  const fallbackInstrumented = input.attacks.some((entry) => entry.fallback !== undefined);
  const fallbackReceiptIds = input.attacks.flatMap((entry) => entry.fallback?.event?.receiptId ?? []);
  const reservedIds = [input.expected.initialBAllow.operationId, input.expected.originControl.operationId,
    ...input.expected.syntaxControls.map((entry) => entry.operationId),
    ...input.expected.pSyntaxControls.map((entry) => entry.operationId),
    ...input.expected.attacks.flatMap((entry) => [entry.operationId, entry.actionOperationId])];
  const fallbackReceiptSetValid = unique(fallbackReceiptIds) &&
    fallbackReceiptIds.every((receiptId) => FALLBACK_RECEIPT_ID.test(receiptId) && !reservedIds.includes(receiptId));
  const fallbackAccountingValid = fallbackInstrumented
    ? input.attacks.every((entry) => entry.fallback !== undefined) && input.unexpectedFallbackEventCount === 0
    : input.unexpectedFallbackEventCount === undefined || input.unexpectedFallbackEventCount === 0;
  const eventAccountingValid = input.unexpectedPEventCount === 0 && input.unexpectedBEventCount === 0 &&
    fallbackAccountingValid && fallbackReceiptSetValid;
  const exactSyntaxSet = expectedValid && input.syntaxControls.length === input.expected.syntaxControls.length &&
    unique(input.syntaxControls.map((entry) => entry.caseId)) &&
    input.expected.syntaxControls.every((wanted) => {
      const actual = input.syntaxControls.find((entry) => entry.caseId === wanted.caseId);
      return actual !== undefined && exactSyntaxControl(actual, input.expected, wanted);
    });
  const exactPSyntaxSet = expectedValid && input.pSyntaxControls.length === input.expected.pSyntaxControls.length &&
    unique(input.pSyntaxControls.map((entry) => entry.caseId)) &&
    input.expected.pSyntaxControls.every((wanted) => {
      const actual = input.pSyntaxControls.find((entry) => entry.caseId === wanted.caseId);
      return actual !== undefined && exactPSyntaxControl(actual, input.expected, wanted);
    });
  const exactCaseSet = expectedValid && input.attacks.length === input.expected.attacks.length &&
    unique(input.attacks.map((entry) => entry.caseId)) &&
    input.expected.attacks.every((wanted) => input.attacks.some((entry) =>
      entry.caseId === wanted.caseId && entry.targetForm === wanted.targetForm));
  const controlsPassed = expectedValid && scopeValid && policyPreValid && policyPostValid &&
    initialAllowValid && exactSyntaxSet && exactPSyntaxSet && directPreValid && directPostValid && originGuestValid && originPValid &&
    sourceTerminalOnly && eventAccountingValid && exactCaseSet;

  if (!controlsPassed) {
    return result("indeterminate", "unknown", false,
      "A scope, policy/session, direct-B, origin/P, terminal-source, event-accounting, or case-set control failed.", [
        `expected/scope: ${expectedValid}/${scopeValid}`,
        `policy pre/post: ${policyPreValid}/${policyPostValid}`,
        `initial B allow: ${initialAllowValid}`,
        `initial A raw-target syntax controls exact with zero B events: ${exactSyntaxSet}`,
        `initial P raw-target syntax controls exact with zero OIDC/B events: ${exactPSyntaxSet}`,
        `direct B pre/post blocked with zero events: ${directPreValid}/${directPostValid}`,
        `origin guest/P OIDC: ${originGuestValid}/${originPValid}`,
        `P redirects/fetches/proxies all zero: ${sourceTerminalOnly}`,
        `unexpected P/B/fallback events zero: ${eventAccountingValid}`,
        `exact unique attack case set: ${exactCaseSet}`,
      ]);
  }

  const assessments = input.expected.attacks.map((wanted) =>
    assessAttack(input.attacks.find((entry) => entry.caseId === wanted.caseId)!, input.expected, wanted));
  if (assessments.some((entry) => entry.terminalCloseLane)) {
    return result("indeterminate", "unknown", true,
      "The diagnostic rerun again produced a terminal response with zero attributable A/P/B fallback evidence; close this lane.",
      assessments.map((entry) => `${entry.caseId}: ${entry.reason}`), assessments);
  }
  const ambiguous = assessments.some((entry) => entry.outcome === "indeterminate" && !entry.syntaxUnsupported);
  if (ambiguous) {
    return result("indeterminate", "unknown", true,
      "At least one raw target was unsupported or produced missing, mixed, duplicate, or unattributed sink evidence.",
      assessments.map((entry) => `${entry.caseId}: ${entry.reason}`), assessments);
  }
  if (assessments.some((entry) => entry.outcome === "candidate-high")) {
    return result("candidate-high", "high", true,
      "A supported raw request-target reached denied B with an independently verified platform token or synthetic operator-secret action.", [
        "B reachability was bracketed by conclusive direct blocks with zero B events",
        "the B operation ID matched the guest's single fresh-connection response",
        "High is based only on an exact independent token or file-backed HMAC action proof",
      ], assessments);
  }
  if (assessments.some((entry) => entry.outcome === "candidate-medium")) {
    return result("candidate-medium", "medium", true,
      "A supported raw request-target reached denied B, but exact credential receipt was not demonstrated.", [
        "B reachability was exactly attributable to one request-target case",
        "credential impact is not claimed",
      ], assessments);
  }
  if (assessments.some((entry) => entry.syntaxUnsupported)) {
    return result("indeterminate", "unknown", true,
      "At least one optional raw target syntax was unsupported; a clean pass cannot be claimed.",
      assessments.map((entry) => `${entry.caseId}: ${entry.reason}`), assessments);
  }
  return result("pass", "none", true,
    "Every supported raw request-target terminated at an exact owned A/P negative sink while denied B remained absent.", [
      "origin-form and attack requests used fresh one-request A connections",
      "the same raw targets passed independent public A/P controls before forwarding",
      "P never redirected, fetched, or proxied",
      "direct B was blocked before and after with zero B events",
    ], assessments);
}
