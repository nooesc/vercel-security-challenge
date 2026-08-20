import { createHmac } from "node:crypto";

export const SBX040_TEST_ID = "SBX-040-POC";
export const SBX040_TRANSFORM_HEADER = "x-sbx040-credential";

export type Sbx040Stage = "public" | "secret";
export type Sbx040ProbeMode =
  | "direct-b"
  | "normal-a"
  | "host-b"
  | "cl-only"
  | "te-only"
  | "ambiguous-alone"
  | "ambiguous-plus-a";

export interface Sbx040ResponseEvidence {
  statusCode: number;
  operationId?: string;
  terminalHeader?: boolean;
  bodyBytes: number;
}

export interface Sbx040GuestEvidence {
  schemaVersion: number;
  testId: string;
  caseId: string;
  mode: Sbx040ProbeMode;
  outerHost: string;
  outerPort: number;
  firstHost: string;
  connectionAttempts: number;
  retryCount: number;
  maximumRequests: number;
  actualRequests: number;
  tlsHandshakes: number;
  strictCertificateVerification: boolean;
  environmentProxyTrust: boolean;
  rawConfigurationRetained: boolean;
  rawCredentialRetained: boolean;
  ok: boolean;
  firstResponse?: Sbx040ResponseEvidence;
  secondResponse?: Sbx040ResponseEvidence;
  errorCode?: string;
  errorSyscall?: string;
}

export type Sbx040Framing = "none" | "content-length" | "chunked" | "cl-te";

export interface Sbx040RequestEvent {
  caseId: string;
  connectionId: string;
  requestIndex: number;
  sni: string;
  host: string;
  method: string;
  target: string;
  role: "a" | "b" | "unknown";
  framing: Sbx040Framing;
  contentLength?: number;
  transferEncodingLines: number;
  contentLengthLines: number;
  headerBytes: number;
  headerSha256: string;
  complete: boolean;
  transformHeaderLines: number;
  transformCredentialMatched: boolean;
  terminalResponseStatus?: number;
  rawHeadersRetained: false;
  rawBodyRetained: false;
}

export interface Sbx040BAction {
  caseId: string;
  connectionId: string;
  parentRequestIndex: number;
  canaryMatched: boolean;
  nestedAHostMatched: boolean;
  nestedCaseMatched: boolean;
  transformHeaderLines: number;
  transformCredentialMatched: boolean;
  nestedHeaderBytes: number;
  nestedHeaderSha256: string;
  bodyBytesObserved: number;
  operationId: string;
  responseStatus: 200;
  rawCredentialRetained: false;
  rawBodyRetained: false;
}

export interface Sbx040ReceiverSnapshot {
  configured: boolean;
  requests: Sbx040RequestEvent[];
  bActions: Sbx040BAction[];
  rawCredentialRetained: false;
}

export interface Sbx040PolicyProof {
  stage: "pre" | "post";
  initialSessionId: string;
  activeSessionId: string;
  independentSessionId: string;
  activeSandboxPolicy: unknown;
  activeSessionPolicy: unknown;
  independentSandboxPolicy: unknown;
  independentSessionPolicy: unknown;
  activeSandboxProjectionExact: boolean;
  activeSessionTransformExact: boolean;
  independentSandboxProjectionExact: boolean;
  independentSessionTransformExact: boolean;
  passed: boolean;
}

export interface Sbx040StageInput {
  stage: Sbx040Stage;
  runId: string;
  sandboxName: string;
  sessionId: string;
  aHost: string;
  bHost: string;
  canary: string;
  caseIds: Record<Sbx040ProbeMode | "direct-b-post", string>;
  guests: Record<Sbx040ProbeMode | "direct-b-post", Sbx040GuestEvidence>;
  receiver: Sbx040ReceiverSnapshot;
  policyPre: Sbx040PolicyProof;
  policyPost: Sbx040PolicyProof;
  cleanupPassed: boolean;
}

export interface Sbx040Assessment {
  outcome: "candidate" | "pass" | "inconclusive";
  candidate: boolean;
  controlsPassed: boolean;
  rationale: string;
  evidence: {
    policyPre: boolean;
    policyPost: boolean;
    directBPreBlocked: boolean;
    directBPostBlocked: boolean;
    normalATransformed: boolean;
    hostBMismatchBlocked: boolean;
    clOnlyClean: boolean;
    teOnlyClean: boolean;
    ambiguousAloneNoAction: boolean;
    attackUsedOneTlsConnection: boolean;
    attackBAction: boolean;
    exactCredentialAtB: boolean;
    cleanupPassed: boolean;
  };
}

export interface Sbx040CombinedAssessment {
  outcome: "high-candidate" | "public-candidate" | "pass" | "inconclusive";
  candidate: boolean;
  severityCeiling: "high" | "medium" | "none";
  rationale: string;
  distinctFreshSandboxes: boolean;
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

export function deriveSbx040Commitment(adminKey: string, runId: string, credential: string): string {
  return createHmac("sha256", adminKey)
    .update("sbx040-transform\0")
    .update(runId)
    .update("\0")
    .update(credential)
    .digest("hex");
}

export function deriveSbx040OperationId(adminKey: string, runId: string, caseId: string): string {
  return `op_${createHmac("sha256", adminKey)
    .update("sbx040-operation\0")
    .update(runId)
    .update("\0")
    .update(caseId)
    .digest("base64url")
    .slice(0, 24)}`;
}

export function exactTransformPolicy(value: unknown, aHost: string, credential: string): boolean {
  const policy = object(value);
  if (!policy || !exactKeys(policy, ["allow"])) return false;
  const allow = object(policy.allow);
  if (!allow || !exactKeys(allow, [aHost])) return false;
  const rules = allow[aHost];
  if (!Array.isArray(rules) || rules.length !== 1) return false;
  const rule = object(rules[0]);
  if (!rule || !exactKeys(rule, ["transform"]) || !Array.isArray(rule.transform) || rule.transform.length !== 1) return false;
  const transform = object(rule.transform[0]);
  const headers = object(transform?.headers);
  return transform !== undefined && headers !== undefined && exactKeys(transform, ["headers"]) &&
    exactKeys(headers, [SBX040_TRANSFORM_HEADER]) && headers[SBX040_TRANSFORM_HEADER] === credential;
}

export function exactTransformProjection(value: unknown, aHost: string): boolean {
  const policy = object(value);
  return policy !== undefined && exactKeys(policy, ["allow"]) && Array.isArray(policy.allow) &&
    policy.allow.length === 1 && policy.allow[0] === aHost;
}

export function exactPolicyProof(
  proof: Sbx040PolicyProof,
  aHost: string,
  expectedSessionId: string,
): boolean {
  const exact = exactTransformProjection(proof.activeSandboxPolicy, aHost) &&
    exactTransformPolicy(proof.activeSessionPolicy, aHost, "[REDACTED]") &&
    exactTransformProjection(proof.independentSandboxPolicy, aHost) &&
    exactTransformPolicy(proof.independentSessionPolicy, aHost, "[REDACTED]") &&
    proof.activeSandboxProjectionExact && proof.activeSessionTransformExact &&
    proof.independentSandboxProjectionExact && proof.independentSessionTransformExact;
  const same = proof.initialSessionId === expectedSessionId && proof.activeSessionId === expectedSessionId &&
    proof.independentSessionId === expectedSessionId;
  return proof.passed && exact && same;
}

function exactGuest(
  guest: Sbx040GuestEvidence,
  mode: Sbx040ProbeMode,
  caseId: string,
  input: Sbx040StageInput,
): boolean {
  const maximum = mode === "ambiguous-plus-a" ? 2 : 1;
  return guest.schemaVersion === 1 && guest.testId === SBX040_TEST_ID && guest.caseId === caseId &&
    guest.mode === mode && guest.outerPort === 443 && guest.outerHost === (mode === "direct-b" ? input.bHost : input.aHost) &&
    guest.firstHost === (mode === "host-b" || mode === "direct-b" ? input.bHost : input.aHost) &&
    guest.connectionAttempts === 1 && guest.retryCount === 0 && guest.maximumRequests === maximum &&
    Number.isSafeInteger(guest.actualRequests) && guest.actualRequests >= 0 && guest.actualRequests <= maximum &&
    Number.isSafeInteger(guest.tlsHandshakes) && guest.tlsHandshakes >= 0 && guest.tlsHandshakes <= 1 &&
    guest.strictCertificateVerification && !guest.environmentProxyTrust && !guest.rawConfigurationRetained &&
    !guest.rawCredentialRetained;
}

function requestsFor(input: Sbx040StageInput, key: Sbx040ProbeMode | "direct-b-post"): Sbx040RequestEvent[] {
  return input.receiver.requests.filter((event) => event.caseId === input.caseIds[key]);
}

function actionsFor(input: Sbx040StageInput, key: Sbx040ProbeMode | "direct-b-post"): Sbx040BAction[] {
  return input.receiver.bActions.filter((event) => event.caseId === input.caseIds[key]);
}

function activelyBlocked(guest: Sbx040GuestEvidence): boolean {
  return !guest.ok && guest.actualRequests === 0 && guest.tlsHandshakes === 0 &&
    ["EHOSTUNREACH", "EAI_AGAIN"].includes(guest.errorCode ?? "");
}

export function assessSbx040Stage(input: Sbx040StageInput): Sbx040Assessment {
  const pre = exactPolicyProof(input.policyPre, input.aHost, input.sessionId);
  const post = exactPolicyProof(input.policyPost, input.aHost, input.sessionId);
  const directPre = input.guests["direct-b"];
  const directPost = input.guests["direct-b-post"];
  const directBPreBlocked = exactGuest(directPre, "direct-b", input.caseIds["direct-b"], input) &&
    activelyBlocked(directPre) && requestsFor(input, "direct-b").length === 0 && actionsFor(input, "direct-b").length === 0;
  const directBPostBlocked = exactGuest(directPost, "direct-b", input.caseIds["direct-b-post"], input) &&
    activelyBlocked(directPost) && requestsFor(input, "direct-b-post").length === 0 && actionsFor(input, "direct-b-post").length === 0;

  const normalGuest = input.guests["normal-a"];
  const normalRequests = requestsFor(input, "normal-a");
  const normalATransformed = exactGuest(normalGuest, "normal-a", input.caseIds["normal-a"], input) &&
    normalGuest.ok && normalGuest.actualRequests === 1 && normalGuest.tlsHandshakes === 1 &&
    normalRequests.length === 1 && normalRequests[0]?.role === "a" && normalRequests[0]?.sni === input.aHost &&
    normalRequests[0]?.transformHeaderLines === 1 && normalRequests[0]?.transformCredentialMatched === true;

  const hostGuest = input.guests["host-b"];
  const hostBMismatchBlocked = exactGuest(hostGuest, "host-b", input.caseIds["host-b"], input) &&
    !hostGuest.ok && requestsFor(input, "host-b").length === 0 && actionsFor(input, "host-b").length === 0;

  const clGuest = input.guests["cl-only"];
  const clRequests = requestsFor(input, "cl-only");
  const clOnlyClean = exactGuest(clGuest, "cl-only", input.caseIds["cl-only"], input) && clGuest.ok &&
    clGuest.actualRequests === 1 && clRequests.length === 1 && clRequests[0]?.role === "a" && clRequests[0]?.sni === input.aHost &&
    clRequests[0]?.framing === "content-length" &&
    actionsFor(input, "cl-only").length === 0;

  const teGuest = input.guests["te-only"];
  const teRequests = requestsFor(input, "te-only");
  const teOnlyClean = exactGuest(teGuest, "te-only", input.caseIds["te-only"], input) && teGuest.ok &&
    teGuest.actualRequests === 1 && teRequests.length === 1 && teRequests[0]?.role === "a" && teRequests[0]?.sni === input.aHost &&
    teRequests[0]?.framing === "chunked" &&
    actionsFor(input, "te-only").length === 0;

  const aloneGuest = input.guests["ambiguous-alone"];
  const aloneRequests = requestsFor(input, "ambiguous-alone");
  const ambiguousAloneNoAction = exactGuest(aloneGuest, "ambiguous-alone", input.caseIds["ambiguous-alone"], input) &&
    aloneGuest.ok && aloneGuest.actualRequests === 1 &&
    aloneRequests.some((event) => event.role === "a" && event.sni === input.aHost && event.framing === "cl-te") &&
    actionsFor(input, "ambiguous-alone").length === 0;

  const attackGuest = input.guests["ambiguous-plus-a"];
  const attackActions = actionsFor(input, "ambiguous-plus-a");
  const action = attackActions[0];
  const attackRequests = requestsFor(input, "ambiguous-plus-a");
  const attackUsedOneTlsConnection = exactGuest(
    attackGuest,
    "ambiguous-plus-a",
    input.caseIds["ambiguous-plus-a"],
    input,
  ) && attackGuest.actualRequests === 2 && attackGuest.tlsHandshakes === 1;
  const attackBAction = attackActions.length === 1 && action?.canaryMatched === true &&
    action.nestedAHostMatched && action.nestedCaseMatched && action.responseStatus === 200 &&
    attackRequests.some((event) => event.connectionId === action.connectionId && event.role === "a" &&
      event.sni === input.aHost && event.framing === "cl-te") &&
    attackRequests.some((event) => event.connectionId === action.connectionId && event.role === "b" &&
      event.sni === input.aHost && event.complete === false) &&
    attackGuest.secondResponse?.statusCode === 200 && attackGuest.secondResponse.operationId === action.operationId;
  const exactCredentialAtB = attackBAction && action?.transformHeaderLines === 1 &&
    action.transformCredentialMatched && !action.rawCredentialRetained && !action.rawBodyRetained &&
    input.receiver.rawCredentialRetained === false;

  const controlsPassed = pre && post && directBPreBlocked && directBPostBlocked && normalATransformed &&
    hostBMismatchBlocked && clOnlyClean && teOnlyClean && ambiguousAloneNoAction && input.cleanupPassed;
  const candidate = controlsPassed && attackUsedOneTlsConnection && attackBAction && exactCredentialAtB;
  const cleanPass = controlsPassed && attackUsedOneTlsConnection && attackActions.length === 0 &&
    attackGuest.secondResponse?.statusCode !== 200;
  return {
    outcome: candidate ? "candidate" : cleanPass ? "pass" : "inconclusive",
    candidate,
    controlsPassed,
    rationale: candidate
      ? "an A-only transformed credential was observed by the denied B virtual host only when CL.TE desynchronization was followed by a separately transformed A request"
      : cleanPass
        ? "all controls passed and the CL.TE sequence produced no B credential action"
        : "one or more attribution, policy, framing, or cleanup gates did not pass",
    evidence: {
      policyPre: pre,
      policyPost: post,
      directBPreBlocked,
      directBPostBlocked,
      normalATransformed,
      hostBMismatchBlocked,
      clOnlyClean,
      teOnlyClean,
      ambiguousAloneNoAction,
      attackUsedOneTlsConnection,
      attackBAction,
      exactCredentialAtB,
      cleanupPassed: input.cleanupPassed,
    },
  };
}

export function combineSbx040Assessments(
  publicInput: Sbx040StageInput,
  publicAssessment: Sbx040Assessment,
  secretInput?: Sbx040StageInput,
  secretAssessment?: Sbx040Assessment,
): Sbx040CombinedAssessment {
  const distinctFreshSandboxes = secretInput !== undefined && publicInput.sandboxName !== secretInput.sandboxName &&
    publicInput.sessionId !== secretInput.sessionId;
  if (publicAssessment.candidate && secretAssessment?.candidate && distinctFreshSandboxes) {
    return {
      outcome: "high-candidate",
      candidate: true,
      severityCeiling: "high",
      rationale: "the same parser differential moved a fresh controller-only credential from transformed A traffic to denied B in a second sandbox",
      distinctFreshSandboxes,
    };
  }
  if (publicAssessment.candidate) {
    return {
      outcome: "public-candidate",
      candidate: true,
      severityCeiling: "medium",
      rationale: "the public canary crossed the A-to-B domain boundary, but a fresh-sandbox secret reproduction is absent",
      distinctFreshSandboxes,
    };
  }
  return {
    outcome: publicAssessment.outcome === "pass" ? "pass" : "inconclusive",
    candidate: false,
    severityCeiling: "none",
    rationale: publicAssessment.rationale,
    distinctFreshSandboxes,
  };
}
