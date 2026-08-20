import { createHmac } from "node:crypto";

export const SBX041_TEST_ID = "SBX-041-POC";
export const SBX041_TRANSFORM_HEADER = "x-sbx041-brokered-canary";
export const SBX041_PLATFORM_REDACTED_TRANSFORM = "<redacted>";

export type Sbx041Verdict = "pass" | "candidate-medium" | "candidate-high" | "indeterminate" | "error";
export type Sbx041ProbeMode =
  | "direct-b"
  | "normal-a"
  | "fronted-sni-no-session"
  | "fronted-sni-resume"
  | "fronted-nosni-no-session"
  | "fronted-nosni-resume";

export interface Sbx041TlsEvidence {
  transportHost: string;
  identityHost: string;
  configuredServername: string | null;
  authorized: boolean;
  protocol?: string;
  alpnProtocol?: string;
  sessionReused: boolean;
  peerCertificateFingerprint256?: string;
}

export interface Sbx041ResponseEvidence {
  statusCode: number;
  bodyBytes: number;
  operationId?: string;
  service?: string;
}

export interface Sbx041GuestEvidence {
  schemaVersion: number;
  testId: string;
  caseId: string;
  mode: Sbx041ProbeMode;
  tlsVersionPinned: string;
  strictCertificateVerification: boolean;
  environmentProxyTrust: boolean;
  rawConfigurationRetained: boolean;
  rawSessionRetained: boolean;
  connectionAttempts: number;
  retryCount: number;
  totalHttpRequests: number;
  bTargetRequests: number;
  bAttackRequests: number;
  ok: boolean;
  sessionOffers?: number;
  freshBConnection?: boolean;
  aSessionBytes?: number;
  aSessionSha256?: string;
  aCertificateValidForB?: boolean;
  bIdentityValidatedAgainstAuthenticatedASessionCertificate?: boolean;
  aTls?: Sbx041TlsEvidence;
  bTls?: Sbx041TlsEvidence;
  response?: Sbx041ResponseEvidence;
  aResponse?: Sbx041ResponseEvidence;
  bResponse?: Sbx041ResponseEvidence;
  failClosedReason?: string;
  crossHostIdentityErrorCode?: string;
  errorCode?: string;
  errorSyscall?: string;
}

export interface Sbx041PolicyProof {
  stage: "pre" | "post";
  initialSessionId: string;
  activeSessionId: string;
  independentSessionId: string;
  activeSandboxPolicy: unknown;
  activeSessionPolicy: unknown;
  independentSandboxPolicy: unknown;
  independentSessionPolicy: unknown;
  passed: boolean;
}

export interface Sbx041AEvent {
  observedAt: string;
  caseId: string;
  kind: "control" | "ticket";
  method: string;
  requestTarget: string;
  hostHeaderLines: number;
  hostHeaderValues: number;
  hostMatched: boolean;
  canaryMatched: boolean;
  transformHeaderLines: number;
  transformHeaderValues: number;
  transformHeaderSha256?: string;
  transformCommitmentMatched: boolean;
  responseStatus: number;
  operationId?: string;
}

export interface Sbx041BEvent {
  observedAt: string;
  caseId: string;
  kind: "direct" | "fronted-control" | "action";
  method: string;
  requestTarget: string;
  hostHeaderLines: number;
  hostHeaderValues: number;
  hostMatched: boolean;
  canaryMatched: boolean;
  transformHeaderLines: number;
  transformHeaderValues: number;
  transformHeaderSha256?: string;
  transformCommitmentMatched: boolean;
  responseStatus: number;
  operationId?: string;
}

export interface Sbx041ReceiverSnapshot {
  configured: boolean;
  a: Sbx041AEvent[];
  b: Sbx041BEvent[];
}

export interface Sbx041AssessmentInput {
  runId: string;
  aHost: string;
  bHost: string;
  expectedTransformSha256: string;
  expectedNormalOperationId: string;
  expectedSniTicketOperationId: string;
  expectedSniAttackOperationId: string;
  expectedNoSniTicketOperationId: string;
  expectedNoSniAttackOperationId: string;
  identityAndScopePassed: boolean;
  infrastructurePreflightPassed: boolean;
  policyPre: Sbx041PolicyProof;
  policyPost: Sbx041PolicyProof;
  directBPre: Sbx041GuestEvidence;
  normalA: Sbx041GuestEvidence;
  sniNoSession: Sbx041GuestEvidence;
  sniResume: Sbx041GuestEvidence;
  noSniNoSession: Sbx041GuestEvidence;
  noSniResume: Sbx041GuestEvidence;
  directBPost: Sbx041GuestEvidence;
  receiver: Sbx041ReceiverSnapshot;
  cleanupPassed: boolean;
  executionError?: boolean;
}

export interface Sbx041Assessment {
  verdict: Sbx041Verdict;
  severity: "none" | "medium" | "high" | "unknown";
  candidate: boolean;
  controlsPassed: boolean;
  exactSessionResumptionProof: boolean;
  exactBrokeredSecretReceipt: boolean;
  successfulVariants: Array<"configured-sni-b" | "no-sni">;
  summary: string;
  signals: string[];
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

export function deriveSbx041OperationId(key: string, runId: string, caseId: string, signal: string): string {
  return `rs_${createHmac("sha256", key).update(`${runId}\0${caseId}\0${signal}`).digest("base64url").slice(0, 36)}`;
}

export function exactTransformPolicy(value: unknown, aHost: string, transformValue: string): boolean {
  const policy = object(value);
  const allow = object(policy?.allow);
  if (!policy || !allow || !exactKeys(policy, ["allow"]) || !exactKeys(allow, [aHost])) return false;
  const rules = allow[aHost];
  if (!Array.isArray(rules) || rules.length !== 1) return false;
  const rule = object(rules[0]);
  if (!rule || !exactKeys(rule, ["transform"]) || !Array.isArray(rule.transform) || rule.transform.length !== 1) return false;
  const transform = object(rule.transform[0]);
  const headers = object(transform?.headers);
  return transform !== undefined && headers !== undefined && exactKeys(transform, ["headers"]) &&
    exactKeys(headers, [SBX041_TRANSFORM_HEADER]) && headers[SBX041_TRANSFORM_HEADER] === transformValue;
}

export function exactTransformProjection(value: unknown, aHost: string): boolean {
  const policy = object(value);
  return policy !== undefined && exactKeys(policy, ["allow"]) && Array.isArray(policy.allow) &&
    policy.allow.length === 1 && policy.allow[0] === aHost;
}

export function exactPolicyProof(
  proof: Sbx041PolicyProof,
  aHost: string,
  transformValue: string,
  expectedSessionId: string,
): boolean {
  const exact = exactTransformProjection(proof.activeSandboxPolicy, aHost) &&
    exactTransformPolicy(proof.activeSessionPolicy, aHost, transformValue) &&
    exactTransformProjection(proof.independentSandboxPolicy, aHost) &&
    exactTransformPolicy(proof.independentSessionPolicy, aHost, transformValue);
  const sameSession = proof.initialSessionId === expectedSessionId && proof.activeSessionId === expectedSessionId &&
    proof.independentSessionId === expectedSessionId;
  return proof.passed === exact && proof.passed === sameSession && exact && sameSession;
}

function exactAttempt(guest: Sbx041GuestEvidence, mode: Sbx041ProbeMode, caseId: string): boolean {
  return guest.schemaVersion === 1 && guest.testId === SBX041_TEST_ID && guest.caseId === caseId && guest.mode === mode &&
    guest.tlsVersionPinned === "TLSv1.2" && guest.strictCertificateVerification === true &&
    guest.environmentProxyTrust === false && guest.rawConfigurationRetained === false && guest.rawSessionRetained === false &&
    guest.retryCount === 0;
}

function exactTls(
  value: Sbx041TlsEvidence | undefined,
  transportHost: string,
  identityHost: string,
  configuredServername: string | null,
  reused: boolean,
): boolean {
  return value?.transportHost === transportHost && value.identityHost === identityHost &&
    value.configuredServername === configuredServername && value.authorized === true &&
    value.protocol === "TLSv1.2" && value.alpnProtocol === "http/1.1" && value.sessionReused === reused;
}

function events<T extends { caseId: string }>(items: T[], caseId: string): T[] {
  return items.filter((item) => item.caseId === caseId);
}

function directBlocked(guest: Sbx041GuestEvidence, input: Sbx041AssessmentInput, caseId: string): boolean {
  const attributable = guest.errorCode === "EAI_AGAIN" || guest.errorCode === "EHOSTUNREACH";
  return exactAttempt(guest, "direct-b", caseId) && guest.connectionAttempts === 1 && guest.totalHttpRequests === 0 &&
    guest.bTargetRequests === 0 && guest.bAttackRequests === 0 && guest.ok === false && attributable && !guest.bTls && !guest.response &&
    events(input.receiver.b, caseId).length === 0;
}

function exactAEvent(
  event: Sbx041AEvent | undefined,
  input: Sbx041AssessmentInput,
  caseId: string,
  kind: "control" | "ticket",
  operationId: string,
): boolean {
  return event?.caseId === caseId && event.kind === kind && event.method === "GET" && event.canaryMatched === true &&
    event.hostHeaderLines === 1 && event.hostHeaderValues === 1 && event.hostMatched === true &&
    event.transformHeaderLines === 1 && event.transformHeaderValues === 1 &&
    event.transformHeaderSha256 === input.expectedTransformSha256 && event.transformCommitmentMatched === true &&
    event.responseStatus === 200 && event.operationId === operationId;
}

function normalControl(input: Sbx041AssessmentInput): boolean {
  const caseId = "normal-a";
  const matches = events(input.receiver.a, caseId);
  return exactAttempt(input.normalA, "normal-a", caseId) && input.normalA.connectionAttempts === 1 &&
    input.normalA.totalHttpRequests === 1 && input.normalA.bTargetRequests === 0 && input.normalA.bAttackRequests === 0 &&
    input.normalA.ok === true && exactTls(input.normalA.aTls, input.aHost, input.aHost, input.aHost, false) &&
    input.normalA.response?.statusCode === 200 &&
    input.normalA.response.operationId === input.expectedNormalOperationId && matches.length === 1 &&
    exactAEvent(matches[0], input, caseId, "control", input.expectedNormalOperationId);
}

type Sbx041Variant = "configured-sni-b" | "no-sni";
type Sbx041VariantOutcome = "blocked" | "medium" | "high" | "unknown";

interface VariantDefinition {
  variant: Sbx041Variant;
  noSessionMode: Sbx041ProbeMode;
  noSessionCase: string;
  resumeMode: Sbx041ProbeMode;
  resumeCase: string;
  ticketCase: string;
  attackCase: string;
  configuredServername: string | null;
  noSession: Sbx041GuestEvidence;
  resume: Sbx041GuestEvidence;
  ticketOperationId: string;
  attackOperationId: string;
}

function variants(input: Sbx041AssessmentInput): VariantDefinition[] {
  return [
    {
      variant: "configured-sni-b",
      noSessionMode: "fronted-sni-no-session",
      noSessionCase: "fronted-sni-no-session",
      resumeMode: "fronted-sni-resume",
      resumeCase: "fronted-sni-resume",
      ticketCase: "fronted-sni-resume-ticket",
      attackCase: "fronted-sni-resume-attack",
      configuredServername: input.bHost,
      noSession: input.sniNoSession,
      resume: input.sniResume,
      ticketOperationId: input.expectedSniTicketOperationId,
      attackOperationId: input.expectedSniAttackOperationId,
    },
    {
      variant: "no-sni",
      noSessionMode: "fronted-nosni-no-session",
      noSessionCase: "fronted-nosni-no-session",
      resumeMode: "fronted-nosni-resume",
      resumeCase: "fronted-nosni-resume",
      ticketCase: "fronted-nosni-resume-ticket",
      attackCase: "fronted-nosni-resume-attack",
      configuredServername: null,
      noSession: input.noSniNoSession,
      resume: input.noSniResume,
      ticketOperationId: input.expectedNoSniTicketOperationId,
      attackOperationId: input.expectedNoSniAttackOperationId,
    },
  ];
}

function noSessionBlocked(input: Sbx041AssessmentInput, definition: VariantDefinition): boolean {
  const guest = definition.noSession;
  const attributable = guest.errorCode === "EAI_AGAIN" || guest.errorCode === "EHOSTUNREACH" ||
    guest.errorCode === "ECONNRESET";
  return exactAttempt(guest, definition.noSessionMode, definition.noSessionCase) && guest.connectionAttempts === 1 &&
    guest.sessionOffers === 0 && guest.freshBConnection === true && guest.totalHttpRequests === 0 &&
    guest.bTargetRequests === 0 && guest.bAttackRequests === 0 && guest.ok === false && attributable &&
    !guest.bTls && !guest.response && events(input.receiver.b, definition.noSessionCase).length === 0;
}

function exactTicketPrelude(input: Sbx041AssessmentInput, definition: VariantDefinition): boolean {
  const guest = definition.resume;
  const ticketCase = definition.ticketCase;
  const matches = events(input.receiver.a, ticketCase);
  return exactAttempt(guest, definition.resumeMode, definition.resumeCase) &&
    exactTls(guest.aTls, input.aHost, input.aHost, input.aHost, false) &&
    Number.isSafeInteger(guest.aSessionBytes) && (guest.aSessionBytes ?? 0) > 0 && (guest.aSessionBytes ?? 0) <= 65_536 &&
    /^[a-f0-9]{64}$/u.test(guest.aSessionSha256 ?? "") && guest.aCertificateValidForB === true &&
    guest.aResponse?.statusCode === 200 && guest.aResponse.operationId === definition.ticketOperationId &&
    matches.length === 1 && exactAEvent(matches[0], input, ticketCase, "ticket", definition.ticketOperationId);
}

function exactBEvent(
  event: Sbx041BEvent | undefined,
  input: Sbx041AssessmentInput,
  definition: VariantDefinition,
  withSecret: boolean,
): boolean {
  return event?.caseId === definition.attackCase && event.kind === "action" && event.method === "GET" &&
    event.hostHeaderLines === 1 && event.hostHeaderValues === 1 && event.hostMatched === true &&
    event.canaryMatched === true && event.responseStatus === (withSecret ? 200 : 401) &&
    (withSecret
      ? event.transformHeaderLines === 1 && event.transformHeaderValues === 1 &&
        event.transformHeaderSha256 === input.expectedTransformSha256 && event.transformCommitmentMatched === true &&
        event.operationId === definition.attackOperationId
      : event.transformCommitmentMatched === false && event.operationId === undefined);
}

function sessionBase(input: Sbx041AssessmentInput, definition: VariantDefinition): boolean {
  const guest = definition.resume;
  return exactTicketPrelude(input, definition) && guest.connectionAttempts === 2 && guest.sessionOffers === 1 &&
    guest.totalHttpRequests === 2 && guest.freshBConnection === true && guest.bTargetRequests === 1 &&
    guest.bAttackRequests === 1 && guest.ok === true &&
    exactTls(guest.bTls, input.aHost, input.bHost, definition.configuredServername, true) &&
    guest.bIdentityValidatedAgainstAuthenticatedASessionCertificate === true;
}

function exactHighCandidate(input: Sbx041AssessmentInput, definition: VariantDefinition): boolean {
  const guest = definition.resume;
  const attackCase = definition.attackCase;
  const matches = events(input.receiver.b, attackCase);
  return sessionBase(input, definition) && guest.bResponse?.statusCode === 200 &&
    guest.bResponse.operationId === definition.attackOperationId && matches.length === 1 &&
    exactBEvent(matches[0], input, definition, true);
}

function exactMediumCandidate(input: Sbx041AssessmentInput, definition: VariantDefinition): boolean {
  const guest = definition.resume;
  const matches = events(input.receiver.b, definition.attackCase);
  return sessionBase(input, definition) && guest.bResponse?.statusCode === 401 &&
    guest.bResponse.operationId === undefined && matches.length === 1 && exactBEvent(matches[0], input, definition, false);
}

function exactFailClosed(input: Sbx041AssessmentInput, definition: VariantDefinition): boolean {
  const guest = definition.resume;
  const attributable = guest.errorCode === "EAI_AGAIN" || guest.errorCode === "EHOSTUNREACH";
  return exactTicketPrelude(input, definition) && guest.connectionAttempts === 2 && guest.sessionOffers === 1 &&
    guest.freshBConnection === true && guest.totalHttpRequests === 1 && guest.bTargetRequests === 0 &&
    guest.bAttackRequests === 0 && guest.ok === false && attributable && !guest.bTls &&
    events(input.receiver.b, definition.attackCase).length === 0;
}

function variantOutcome(input: Sbx041AssessmentInput, definition: VariantDefinition): Sbx041VariantOutcome {
  if (exactHighCandidate(input, definition)) return "high";
  if (exactMediumCandidate(input, definition)) return "medium";
  if (exactFailClosed(input, definition)) return "blocked";
  return "unknown";
}

function result(
  verdict: Sbx041Verdict,
  severity: Sbx041Assessment["severity"],
  controlsPassed: boolean,
  exactSessionResumptionProof: boolean,
  exactBrokeredSecretReceipt: boolean,
  successfulVariants: Sbx041Assessment["successfulVariants"],
  summary: string,
  signals: string[],
): Sbx041Assessment {
  return {
    verdict,
    severity,
    candidate: verdict === "candidate-high" || verdict === "candidate-medium",
    controlsPassed,
    exactSessionResumptionProof,
    exactBrokeredSecretReceipt,
    successfulVariants,
    summary,
    signals,
  };
}

export function assessSbx041(input: Sbx041AssessmentInput): Sbx041Assessment {
  if (input.executionError || !input.cleanupPassed) {
    return result("error", "unknown", false, false, false, [],
      "Controller execution or cleanup failed before a complete assessment.", ["execution/cleanup failure"]);
  }
  const expectedSessionId = input.policyPre.initialSessionId;
  const policy = exactPolicyProof(
    input.policyPre,
    input.aHost,
    SBX041_PLATFORM_REDACTED_TRANSFORM,
    expectedSessionId,
  ) && exactPolicyProof(
    input.policyPost,
    input.aHost,
    SBX041_PLATFORM_REDACTED_TRANSFORM,
    expectedSessionId,
  );
  const pre = directBlocked(input.directBPre, input, "direct-b-pre");
  const post = directBlocked(input.directBPost, input, "direct-b-post");
  const normal = normalControl(input);
  const definitions = variants(input);
  const frontedControls = definitions.map((definition) => noSessionBlocked(input, definition));
  const controls = input.identityAndScopePassed && input.infrastructurePreflightPassed && input.receiver.configured &&
    policy && pre && post && normal && frontedControls.every(Boolean);
  if (!controls) {
    return result("indeterminate", "unknown", false, false, false, [],
      "One or more scope, infrastructure, policy, direct-B, or transformed-A controls failed.", [
        `policy readback: ${policy}`,
        `direct B pre/post blocked: ${pre}/${post}`,
        `normal transformed A: ${normal}`,
        `fronted no-session controls blocked (SNI/no-SNI): ${frontedControls.join("/")}`,
      ]);
  }
  const outcomes = definitions.map((definition) => variantOutcome(input, definition));
  const recognized = outcomes.every((outcome) => outcome !== "unknown");
  const successfulVariants = definitions
    .filter((_definition, index) => outcomes[index] === "high" || outcomes[index] === "medium")
    .map((definition) => definition.variant);
  const expectedAEvents = 1 + definitions.length;
  const expectedBEvents = successfulVariants.length;
  const exactGlobalCounts = input.receiver.a.length === expectedAEvents && input.receiver.b.length === expectedBEvents;
  if (recognized && exactGlobalCounts && outcomes.includes("high")) {
    return result("candidate-high", "high", true, true, true, successfulVariants,
      "An A TLS session was reused over a fresh A-transport connection for denied Host B, and B received the exact A-only brokered credential.", [
        `variant outcomes (configured-SNI-B/no-SNI): ${outcomes.join("/")}`,
        "matched no-session counterparts blocked: true",
        "exact non-reflected brokered secret receipt at B: true",
      ]);
  }
  if (recognized && exactGlobalCounts && outcomes.includes("medium")) {
    return result("candidate-medium", "medium", true, true, false, successfulVariants,
      "An A TLS session was reused and a correlated denied-Host-B request reached B, but the A-only brokered credential was not received.", [
        `variant outcomes (configured-SNI-B/no-SNI): ${outcomes.join("/")}`,
        "matched no-session counterparts blocked: true",
        "brokered secret receipt at B: false",
      ]);
  }
  if (recognized && exactGlobalCounts && outcomes.every((outcome) => outcome === "blocked")) {
    return result("pass", "none", true, false, false, [],
      "Both fresh A-transport session offers were actively blocked before TLS or HTTP reached B.", [
        "SNI-B session variant blocked: true",
        "no-SNI session variant blocked: true",
        "B HTTP requests: 0",
      ]);
  }
  return result("indeterminate", "unknown", true,
    input.sniResume.bTls?.sessionReused === true || input.noSniResume.bTls?.sessionReused === true,
    false,
    successfulVariants,
    "The attack produced neither an exact credential-bearing resumption candidate nor an attributable fail-closed result.", [
      `variant outcomes (configured-SNI-B/no-SNI): ${outcomes.join("/")}`,
      `exact global receiver counts: ${exactGlobalCounts}`,
    ]);
}
