export type Sbx034Verdict =
  | "pass"
  | "candidate-medium"
  | "candidate-high"
  | "indeterminate"
  | "error";

export type Sbx034Severity = "none" | "medium" | "high" | "unknown";

export interface Sbx034ExpectedIdentity {
  teamId: string;
  projectId: string;
  sandboxId: string;
  sessionId: string;
  sandboxName: string;
}

export interface Sbx034ExpectedEvidence {
  runId: string;
  testId: string;
  caseId: string;
  correlationId: string;
  guestRequestUrl: string;
  forwardObserverUrl: string;
  redirectTargetUrl: string;
  oidcAudience: string;
  operationId: string;
  identity: Sbx034ExpectedIdentity;
}

export interface Sbx034GuestRequestEvidence {
  commandExitCode: number;
  ok: boolean;
  runId: string;
  testId: string;
  caseId: string;
  correlationId: string;
  requestUrl: string;
  method: string;
  maximumRequests: number;
  actualRequests: number;
  retryCount: number;
  redirectMode: string;
  redirectsAllowed: boolean;
  redirectsFollowed: number;
  environmentProxyTrust: boolean;
  responseOperationId?: string;
}

export interface Sbx034DirectBBlockEvidence {
  caseId: string;
  maximumRequests: number;
  actualRequests: number;
  retryCount: number;
  redirectsAllowed: boolean;
  samePinnedDestination: boolean;
  conclusiveFirewallBlock: boolean;
  destinationObserverEventCount: number;
}

export interface Sbx034RedirectSourceEvent {
  runId: string;
  testId: string;
  caseId: string;
  correlationId: string;
  requestUrl: string;
  redirectStatusCode: number;
  location: string;
}

export interface Sbx034RedirectSourceEvidence {
  eventCount: number;
  event?: Sbx034RedirectSourceEvent;
}

export interface Sbx034VerifiedOidcIdentity {
  teamId: string;
  projectId: string;
  sandboxId: string;
  sessionId: string;
  sandboxName: string;
}

/**
 * Sanitized output from B's independent JWT verifier. The verdict engine never
 * accepts a raw JWT and does not itself perform network/JWKS operations.
 */
export interface Sbx034PlatformOidcVerification {
  tokenOrdinal: number;
  verifier: string;
  signatureVerified: boolean;
  algorithm: string;
  issuer: string;
  jwksUrl: string;
  audience: string;
  temporalClaimsVerified: boolean;
  identity: Sbx034VerifiedOidcIdentity;
  rawTokenRetained: boolean;
  verificationError?: string;
}

export interface Sbx034RedirectDestinationEvent {
  runId: string;
  testId: string;
  caseId: string;
  correlationId: string;
  requestUrl: string;
  operationId: string;
  attributableToSourceRedirect: boolean;
  oidcHeaderCount: number;
  oidcValueCount: number;
  oidcVerifications: Sbx034PlatformOidcVerification[];
}

export interface Sbx034RedirectDestinationEvidence {
  eventCount: number;
  event?: Sbx034RedirectDestinationEvent;
}

export interface Sbx034AssessmentInput {
  executionError?: boolean;
  cleanupPassed: boolean;
  identityAndScopePassed: boolean;
  forwardPolicyConfiguredExactly: boolean;
  initialPolicyReadbackPassed: boolean;
  finalPolicyReadbackPassed: boolean;
  sameSessionPassed: boolean;
  sourceRedirectConfiguredExactly: boolean;
  expected: Sbx034ExpectedEvidence;
  guest: Sbx034GuestRequestEvidence;
  directBPre: Sbx034DirectBBlockEvidence;
  directBPost: Sbx034DirectBBlockEvidence;
  source: Sbx034RedirectSourceEvidence;
  destination: Sbx034RedirectDestinationEvidence;
}

export interface Sbx034Assessment {
  verdict: Sbx034Verdict;
  severity: Sbx034Severity;
  candidate: boolean;
  controlsPassed: boolean;
  oidcProofValid: boolean;
  summary: string;
  signals: string[];
}

function exactText(value: string): boolean {
  return value.length > 0 && value.length <= 1_024 && !/[\0\r\n]/u.test(value);
}

function nonnegativeInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
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

function exactPlatformIssuerAndJwks(issuer: string, jwksUrl: string): boolean {
  if (!exactText(issuer) || !exactText(jwksUrl)) return false;
  try {
    const parsedIssuer = new URL(issuer);
    if (parsedIssuer.protocol !== "https:" || parsedIssuer.hostname !== "oidc.vercel.com" ||
      parsedIssuer.username !== "" || parsedIssuer.password !== "" ||
      parsedIssuer.search !== "" || parsedIssuer.hash !== "") return false;
    const expectedJwks = `${issuer.replace(/\/$/u, "")}/.well-known/jwks`;
    return exactHttpsUrl(jwksUrl, expectedJwks);
  } catch {
    return false;
  }
}

function exactExpectedEvidence(expected: Sbx034ExpectedEvidence): boolean {
  const identity = expected.identity;
  const textValid = [
    expected.runId,
    expected.testId,
    expected.caseId,
    expected.correlationId,
    expected.operationId,
    identity.teamId,
    identity.projectId,
    identity.sandboxId,
    identity.sessionId,
    identity.sandboxName,
  ].every(exactText);
  if (!textValid || expected.testId !== "SBX-034-POC" ||
    !exactHttpsUrl(expected.guestRequestUrl, expected.guestRequestUrl) ||
    !exactHttpsUrl(expected.forwardObserverUrl, expected.forwardObserverUrl) ||
    !exactHttpsUrl(expected.redirectTargetUrl, expected.redirectTargetUrl) ||
    !exactHttpsUrl(expected.oidcAudience, expected.oidcAudience)) return false;
  const forwardUrl = new URL(expected.forwardObserverUrl);
  const targetUrl = new URL(expected.redirectTargetUrl);
  const audienceUrl = new URL(expected.oidcAudience);
  return forwardUrl.origin !== targetUrl.origin && audienceUrl.origin === forwardUrl.origin;
}

export function exactGuestManualNoFollowRequest(
  guest: Sbx034GuestRequestEvidence,
  expected: Sbx034ExpectedEvidence,
): boolean {
  return guest.commandExitCode === 0 && guest.ok === true &&
    guest.runId === expected.runId && guest.testId === expected.testId &&
    guest.caseId === expected.caseId && guest.correlationId === expected.correlationId &&
    exactHttpsUrl(guest.requestUrl, expected.guestRequestUrl) && guest.method === "GET" &&
    guest.maximumRequests === 1 && guest.actualRequests === 1 && guest.retryCount === 0 &&
    guest.redirectMode === "manual" && guest.redirectsAllowed === false &&
    guest.redirectsFollowed === 0 && guest.environmentProxyTrust === false;
}

export function exactDirectBFirewallBlock(
  evidence: Sbx034DirectBBlockEvidence,
  expectedCaseId: string,
): boolean {
  return evidence.caseId === expectedCaseId && evidence.maximumRequests === 1 &&
    evidence.actualRequests === 1 && evidence.retryCount === 0 &&
    evidence.redirectsAllowed === false && evidence.samePinnedDestination === true &&
    evidence.conclusiveFirewallBlock === true && evidence.destinationObserverEventCount === 0;
}

export function exactPlatformOidcVerification(
  verification: Sbx034PlatformOidcVerification | undefined,
  expected: Sbx034ExpectedEvidence,
): boolean {
  if (!verification || !exactExpectedEvidence(expected)) return false;
  const identity = verification.identity;
  return verification.tokenOrdinal === 1 &&
    verification.verifier === "observer-b-independent-jose" &&
    verification.signatureVerified === true && verification.algorithm === "RS256" &&
    exactPlatformIssuerAndJwks(verification.issuer, verification.jwksUrl) &&
    exactHttpsUrl(verification.audience, expected.oidcAudience) &&
    verification.temporalClaimsVerified === true && verification.rawTokenRetained === false &&
    verification.verificationError === undefined &&
    identity.teamId === expected.identity.teamId &&
    identity.projectId === expected.identity.projectId &&
    identity.sandboxId === expected.identity.sandboxId &&
    identity.sessionId === expected.identity.sessionId &&
    identity.sandboxName === expected.identity.sandboxName;
}

function exactSourceRedirect(
  source: Sbx034RedirectSourceEvidence,
  expected: Sbx034ExpectedEvidence,
): boolean {
  const event = source.event;
  return source.eventCount === 1 && event !== undefined &&
    event.runId === expected.runId && event.testId === expected.testId &&
    event.caseId === expected.caseId && event.correlationId === expected.correlationId &&
    exactHttpsUrl(event.requestUrl, expected.forwardObserverUrl) &&
    event.redirectStatusCode === 307 &&
    exactHttpsUrl(event.location, expected.redirectTargetUrl);
}

function exactDestinationAttribution(
  destination: Sbx034RedirectDestinationEvidence,
  expected: Sbx034ExpectedEvidence,
): destination is Sbx034RedirectDestinationEvidence & { event: Sbx034RedirectDestinationEvent } {
  const event = destination.event;
  return destination.eventCount === 1 && event !== undefined &&
    event.runId === expected.runId && event.testId === expected.testId &&
    event.caseId === expected.caseId && event.correlationId === expected.correlationId &&
    exactHttpsUrl(event.requestUrl, expected.redirectTargetUrl) &&
    event.operationId === expected.operationId && event.attributableToSourceRedirect === true &&
    nonnegativeInteger(event.oidcHeaderCount) && nonnegativeInteger(event.oidcValueCount) &&
    Array.isArray(event.oidcVerifications);
}

function result(
  verdict: Sbx034Verdict,
  severity: Sbx034Severity,
  controlsPassed: boolean,
  oidcProofValid: boolean,
  summary: string,
  signals: string[],
): Sbx034Assessment {
  return {
    verdict,
    severity,
    candidate: verdict === "candidate-medium" || verdict === "candidate-high",
    controlsPassed,
    oidcProofValid,
    summary,
    signals,
  };
}

export function assessSbx034(input: Sbx034AssessmentInput): Sbx034Assessment {
  if (!input.cleanupPassed) {
    return result(
      "error",
      "unknown",
      false,
      false,
      "Strict owned-resource cleanup failed; the redirect evidence must not be classified.",
      ["cleanup passed: false"],
    );
  }
  if (input.executionError) {
    return result(
      "error",
      "unknown",
      false,
      false,
      "Controller execution failed before a complete SBX-034 assessment.",
      ["execution error: true"],
    );
  }

  const expectedValid = exactExpectedEvidence(input.expected);
  const guestValid = expectedValid && exactGuestManualNoFollowRequest(input.guest, input.expected);
  const preBlocked = expectedValid && exactDirectBFirewallBlock(
    input.directBPre,
    `${input.expected.caseId}-direct-b-pre`,
  );
  const postBlocked = expectedValid && exactDirectBFirewallBlock(
    input.directBPost,
    `${input.expected.caseId}-direct-b-post`,
  );
  const sourceValid = expectedValid && exactSourceRedirect(input.source, input.expected);
  const controlsPassed = input.identityAndScopePassed && input.forwardPolicyConfiguredExactly &&
    input.initialPolicyReadbackPassed && input.finalPolicyReadbackPassed && input.sameSessionPassed &&
    input.sourceRedirectConfiguredExactly && expectedValid && guestValid && preBlocked && postBlocked && sourceValid;

  if (!controlsPassed) {
    return result(
      "indeterminate",
      "unknown",
      false,
      false,
      "An exact scope, policy/session, manual one-request guest, source redirect, or direct-B block control failed.",
      [
        `identity/scope: ${input.identityAndScopePassed}`,
        `forward policy exact: ${input.forwardPolicyConfiguredExactly}`,
        `initial/final policy readback: ${input.initialPolicyReadbackPassed}/${input.finalPolicyReadbackPassed}`,
        `same session: ${input.sameSessionPassed}`,
        `guest manual one-request/no-follow: ${guestValid}`,
        `direct B pre/post conclusively blocked: ${preBlocked}/${postBlocked}`,
        `source redirect exact: ${sourceValid}`,
      ],
    );
  }

  if (input.destination.eventCount === 0 && input.destination.event === undefined) {
    return result(
      "pass",
      "none",
      true,
      false,
      "The host-side source emitted the exact redirect, but the independently blocked B observer recorded no destination request.",
      [
        "the guest made exactly one manual/no-follow request",
        "direct B was conclusively blocked before and after the redirect case",
        "B recorded zero redirect-correlated events",
      ],
    );
  }

  if (!exactDestinationAttribution(input.destination, input.expected)) {
    return result(
      "indeterminate",
      "unknown",
      true,
      false,
      "Destination activity was present but failed exact single-event redirect attribution.",
      [
        `destination event count: ${input.destination.eventCount}`,
        "run/test/case/correlation, target URL, operation ID, or source-redirect attribution mismatched",
      ],
    );
  }

  const event = input.destination.event;
  if (input.guest.responseOperationId !== event.operationId) {
    return result(
      "indeterminate",
      "unknown",
      true,
      false,
      "B activity did not match the operation ID returned through the guest's single no-follow request.",
      ["guest response operation ID did not equal the independently recorded B operation ID"],
    );
  }
  const oidcProofValid = event.oidcHeaderCount === 1 && event.oidcValueCount === 1 &&
    event.oidcVerifications.length === 1 &&
    exactPlatformOidcVerification(event.oidcVerifications[0], input.expected);
  if (oidcProofValid) {
    return result(
      "candidate-high",
      "high",
      true,
      true,
      "The host-side redirect reached denied B with exactly one independently verified Vercel Sandbox OIDC token for the exact sandbox session.",
      [
        "B recorded exactly one redirect-correlated request",
        "B independently verified one RS256 token from https://oidc.vercel.com",
        "audience and team/project/sandbox/session/name identity matched exactly",
        "final policy, same-session, direct-block, and cleanup controls all passed",
      ],
    );
  }

  return result(
    "candidate-medium",
    "medium",
    true,
    false,
    "The host-side redirect reached denied B, but no single exact independently verified platform OIDC token was demonstrated.",
    [
      "B recorded exactly one redirect-correlated request despite conclusive direct blocks",
      `OIDC header/value counts: ${event.oidcHeaderCount}/${event.oidcValueCount}`,
      `independent OIDC verification records: ${event.oidcVerifications.length}`,
      "credential impact is not claimed without the complete exact token proof",
    ],
  );
}
