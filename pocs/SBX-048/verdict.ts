export const SBX048_TEST_ID = "SBX-048-OIDC-CONTROL-PLANE-CONFUSION" as const;

export interface Sbx048Policy {
  allow: Record<string, Array<{ forwardURL: string }>>;
}

export interface Sbx048OidcEvidence {
  verifier: "independent-jose";
  signatureVerified: boolean;
  algorithmRs256: boolean;
  issuerVerified: boolean;
  audienceVerified: boolean;
  temporalClaimsVerified: boolean;
  exactSourceIdentityVerified: boolean;
  wrongAudienceRejected: boolean;
  issuer: string;
  audience: string;
  identity: {
    teamId: string;
    projectId: string;
    sandboxId: string;
    sandboxName: string;
  };
  ownerIdClaimPresent: boolean;
  teamIdClaimPresent: boolean;
  rawTokenRetained: false;
  rawTokenDigestRetained: false;
}

export interface Sbx048ControlPlaneAttempt {
  kind: "fake-token-read" | "brokered-token-read" | "brokered-token-policy-mutation";
  method: "GET" | "POST";
  endpointFamily: "/v2/sandboxes/sessions/:sessionId" | "/v2/sandboxes/sessions/:sessionId/network-policy";
  requestCount: 1;
  statusCode: number;
  responseBodyRetained: false;
  responseHeadersRetained: false;
  rawTokenRetained: false;
  rawTokenDigestRetained: false;
  exactSession?: boolean;
  exactPolicy?: boolean;
  policyShape?: "legacy-raw-custom" | "v2-projected" | "literal-mode";
  transportError?: boolean;
}

export interface Sbx048ReceiverRecord {
  schemaVersion: 1;
  testId: typeof SBX048_TEST_ID;
  runId: string;
  observedAt: string;
  requestAttributed: boolean;
  oidcHeaderLines: number;
  oidcHeaderValues: number;
  forwardedMetadataExact: boolean;
  correlationExact: boolean;
  oidc?: Sbx048OidcEvidence;
  fakeControl: Sbx048ControlPlaneAttempt;
  brokeredRead?: Sbx048ControlPlaneAttempt;
  brokeredMutation?: Sbx048ControlPlaneAttempt;
  mutationAttemptedOnlyAfterExactRead: boolean;
  controlPlaneRequestCounts: {
    fakeToken: 1;
    brokeredRead: 1;
    brokeredMutation: 0 | 1;
    total: 2 | 3;
  };
  responseOperationId: string;
  rawRequestHeadersRetained: false;
  rawTokenRetained: false;
  rawTokenDigestRetained: false;
}

export interface Sbx048AssessmentInput {
  scopeAndAliasPassed: boolean;
  sandboxFreshAndExact: boolean;
  directOwnedOriginControlPassed: boolean;
  forwardPolicyReadbackBefore: boolean;
  ownerTokenSameRouteReadPassed: boolean;
  receiverConfigurationExact: boolean;
  guestRequestCount: number;
  guestResponseMatchedRecord: boolean;
  record?: Sbx048ReceiverRecord;
  ownerObservedDenyAllAfterMutation: boolean;
  ownerFinalOriginalPolicy: boolean;
  cleanupPassed: boolean;
}

export interface Sbx048Assessment {
  verdict: "candidate" | "pass" | "indeterminate";
  candidate: boolean;
  maximumDemonstratedImpact: "none" | "read-only-authentication-bypass" | "same-sandbox-policy-modification";
  summary: string;
  controlsPassed: boolean;
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

export function exactForwardPolicy(value: unknown, hostname: string, forwardURL: string): boolean {
  const policy = object(value);
  const allow = object(policy?.allow);
  if (!policy || !allow || !exactKeys(policy, ["allow"]) || !exactKeys(allow, [hostname])) return false;
  const rules = allow[hostname];
  if (!Array.isArray(rules) || rules.length !== 1) return false;
  const rule = object(rules[0]);
  return rule !== undefined && exactKeys(rule, ["forwardURL"]) && rule.forwardURL === forwardURL;
}

export function exactForwardSandboxProjection(value: unknown, hostname: string): boolean {
  const policy = object(value);
  return policy !== undefined && exactKeys(policy, ["allow"]) &&
    Array.isArray(policy.allow) && policy.allow.length === 1 && policy.allow[0] === hostname;
}

export function exactRawForwardPolicy(value: unknown, hostname: string, forwardURL: string): boolean {
  const policy = object(value);
  if (!policy) return false;
  const allowed = new Set([
    "allowedCIDRs", "allowedDomains", "deniedCIDRs", "forwardRules", "injectionRules", "mode",
  ]);
  if (Object.keys(policy).some((key) => !allowed.has(key)) || policy.mode !== "custom") return false;
  if (!Array.isArray(policy.allowedDomains) || policy.allowedDomains.length !== 1 || policy.allowedDomains[0] !== hostname) {
    return false;
  }
  for (const key of ["allowedCIDRs", "deniedCIDRs", "injectionRules"] as const) {
    if (policy[key] !== undefined && (!Array.isArray(policy[key]) || policy[key].length !== 0)) return false;
  }
  if (!Array.isArray(policy.forwardRules) || policy.forwardRules.length !== 1) return false;
  const rule = object(policy.forwardRules[0]);
  return rule !== undefined && exactKeys(rule, ["domain", "forwardURL"]) &&
    rule.domain === hostname && rule.forwardURL === forwardURL;
}

export function exactDenyAll(value: unknown): boolean {
  const policy = object(value);
  return policy !== undefined && exactKeys(policy, ["mode"]) && policy.mode === "deny-all";
}

function exactAttempt(
  attempt: Sbx048ControlPlaneAttempt | undefined,
  kind: Sbx048ControlPlaneAttempt["kind"],
  method: Sbx048ControlPlaneAttempt["method"],
  endpointFamily: Sbx048ControlPlaneAttempt["endpointFamily"],
): attempt is Sbx048ControlPlaneAttempt {
  return attempt !== undefined && attempt.kind === kind && attempt.method === method &&
    attempt.endpointFamily === endpointFamily && attempt.requestCount === 1 &&
    attempt.responseBodyRetained === false && attempt.responseHeadersRetained === false &&
    attempt.rawTokenRetained === false && attempt.rawTokenDigestRetained === false &&
    attempt.transportError !== true;
}

function exactOidc(evidence: Sbx048OidcEvidence | undefined): boolean {
  return evidence !== undefined && evidence.verifier === "independent-jose" &&
    evidence.signatureVerified && evidence.algorithmRs256 && evidence.issuerVerified &&
    evidence.audienceVerified && evidence.temporalClaimsVerified &&
    evidence.exactSourceIdentityVerified && evidence.wrongAudienceRejected &&
    evidence.rawTokenRetained === false && evidence.rawTokenDigestRetained === false;
}

function baseControls(input: Sbx048AssessmentInput): boolean {
  const record = input.record;
  if (!record) return false;
  const fake = record.fakeControl;
  return input.scopeAndAliasPassed && input.sandboxFreshAndExact &&
    input.directOwnedOriginControlPassed && input.forwardPolicyReadbackBefore &&
    input.ownerTokenSameRouteReadPassed && input.receiverConfigurationExact &&
    input.guestRequestCount === 1 && input.guestResponseMatchedRecord &&
    record.schemaVersion === 1 && record.testId === SBX048_TEST_ID &&
    record.requestAttributed && record.oidcHeaderLines === 1 && record.oidcHeaderValues === 1 &&
    record.forwardedMetadataExact && record.correlationExact &&
    record.rawRequestHeadersRetained === false && record.rawTokenRetained === false &&
    record.rawTokenDigestRetained === false && exactOidc(record.oidc) &&
    exactAttempt(fake, "fake-token-read", "GET", "/v2/sandboxes/sessions/:sessionId") &&
    (fake.statusCode === 401 || fake.statusCode === 403) &&
    record.controlPlaneRequestCounts.fakeToken === 1 && record.controlPlaneRequestCounts.brokeredRead === 1 &&
    (record.controlPlaneRequestCounts.brokeredMutation === 0 || record.controlPlaneRequestCounts.brokeredMutation === 1) &&
    record.controlPlaneRequestCounts.total === 2 + record.controlPlaneRequestCounts.brokeredMutation &&
    input.cleanupPassed;
}

export function assessSbx048(input: Sbx048AssessmentInput): Sbx048Assessment {
  if (!baseControls(input)) {
    return {
      verdict: "indeterminate",
      candidate: false,
      maximumDemonstratedImpact: "none",
      summary: "A required scope, identity, policy, OIDC, fake-token, attribution, or cleanup control failed.",
      controlsPassed: false,
    };
  }

  const record = input.record!;
  const read = record.brokeredRead;
  if (!exactAttempt(read, "brokered-token-read", "GET", "/v2/sandboxes/sessions/:sessionId")) {
    return {
      verdict: "indeterminate",
      candidate: false,
      maximumDemonstratedImpact: "none",
      summary: "The one brokered-token read was missing, malformed, or transport-indeterminate.",
      controlsPassed: true,
    };
  }

  if ((read.statusCode === 401 || read.statusCode === 403) && record.brokeredMutation === undefined &&
      record.mutationAttemptedOnlyAfterExactRead === false && input.ownerFinalOriginalPolicy &&
      !input.ownerObservedDenyAllAfterMutation && record.controlPlaneRequestCounts.brokeredMutation === 0) {
    return {
      verdict: "pass",
      candidate: false,
      maximumDemonstratedImpact: "none",
      summary: "The Sandbox control plane rejected the exact-audience proxy OIDC token and no mutation was attempted.",
      controlsPassed: true,
    };
  }

  if (read.statusCode !== 200 || read.exactSession !== true || read.exactPolicy !== true ||
      read.policyShape !== "legacy-raw-custom") {
    return {
      verdict: "indeterminate",
      candidate: false,
      maximumDemonstratedImpact: "none",
      summary: "The brokered-token read was neither a conclusive authentication rejection nor an exact source-session acceptance.",
      controlsPassed: true,
    };
  }

  const mutation = record.brokeredMutation;
  if (mutation === undefined) {
    if (!input.ownerFinalOriginalPolicy || input.ownerObservedDenyAllAfterMutation ||
        record.controlPlaneRequestCounts.brokeredMutation !== 0 ||
        record.mutationAttemptedOnlyAfterExactRead !== false) {
      return {
        verdict: "indeterminate",
        candidate: false,
        maximumDemonstratedImpact: "none",
        summary: "The read was accepted but the final owner-side policy state was not cleanly verified.",
        controlsPassed: true,
      };
    }
    return {
      verdict: "candidate",
      candidate: true,
      maximumDemonstratedImpact: "read-only-authentication-bypass",
      summary: "A proxy OIDC token restricted to the forwardURL audience authenticated one exact Sandbox control-plane session read.",
      controlsPassed: true,
    };
  }

  if (!record.mutationAttemptedOnlyAfterExactRead ||
      record.controlPlaneRequestCounts.brokeredMutation !== 1 ||
      !exactAttempt(
        mutation,
        "brokered-token-policy-mutation",
        "POST",
        "/v2/sandboxes/sessions/:sessionId/network-policy",
      )) {
    return {
      verdict: "indeterminate",
      candidate: false,
      maximumDemonstratedImpact: "read-only-authentication-bypass",
      summary: "The read bypass was exact, but the mutation sequence or evidence was invalid.",
      controlsPassed: true,
    };
  }

  if (mutation.statusCode === 200 && mutation.exactSession === true && mutation.exactPolicy === true &&
      mutation.policyShape === "literal-mode" &&
      input.ownerObservedDenyAllAfterMutation && input.ownerFinalOriginalPolicy) {
    return {
      verdict: "candidate",
      candidate: true,
      maximumDemonstratedImpact: "same-sandbox-policy-modification",
      summary: "The audience-restricted proxy OIDC token read the exact source session and changed its network policy before owner-token restoration.",
      controlsPassed: true,
    };
  }

  if ((mutation.statusCode === 401 || mutation.statusCode === 403) &&
      !input.ownerObservedDenyAllAfterMutation && input.ownerFinalOriginalPolicy) {
    return {
      verdict: "candidate",
      candidate: true,
      maximumDemonstratedImpact: "read-only-authentication-bypass",
      summary: "The proxy OIDC token authenticated an exact session read, while the policy mutation was rejected.",
      controlsPassed: true,
    };
  }

  return {
    verdict: "indeterminate",
    candidate: false,
    maximumDemonstratedImpact: "read-only-authentication-bypass",
    summary: "The read bypass was exact, but mutation impact or restoration was not conclusively attributed.",
    controlsPassed: true,
  };
}

export function assertNoTokenMaterial(value: unknown, forbiddenTokens: readonly string[]): void {
  const serialized = JSON.stringify(value);
  for (const token of forbiddenTokens) {
    if (token.length > 0 && serialized.includes(token)) {
      throw new Error("SBX-048 evidence retained raw token material");
    }
  }
}
