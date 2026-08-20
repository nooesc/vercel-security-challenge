import { describe, expect, it } from "vitest";
import {
  assessSbx037,
  exactAudienceClaim,
  exactForwardPolicy,
  exactOperatorSecretAction,
  exactPlatformOidcVerification,
  SBX037_ALIAS_EMAIL,
  SBX037_PROJECT_ID,
  SBX037_TEAM_ID,
  type Sbx037AssessmentInput,
  type Sbx037DestinationBEvent,
  type Sbx037ExpectedAttackCase,
  type Sbx037ExpectedEvidence,
  type Sbx037ExpectedSyntaxControl,
  type Sbx037GuestRawRequestEvidence,
  type Sbx037OperatorSecretActionVerification,
  type Sbx037PlatformOidcVerification,
  type Sbx037SanitizedFallbackEvent,
  type Sbx037SyntaxControlEvidence,
  type Sbx037TerminalPEvent,
} from "../pocs/SBX-037/verdict.js";

const aOrigin = "https://a-owned.example.test";
const pOrigin = "https://p-owned.example.test";
const bOrigin = "https://b-owned.example.test";
const runId = "run-037-exact";
const forwardAudienceP = `${pOrigin}/v1/sbx037/forward/${runId}`;
const pinnedAIpv4 = "104.21.10.37";
const pinnedPIpv4 = "104.21.20.37";
const pinnedBIpv4 = "172.67.10.37";

const absolute: Sbx037ExpectedAttackCase = {
  caseId: "absolute-target-attack",
  correlationId: "corr_absolute_target",
  targetForm: "absolute",
  rawRequestTarget: `${bOrigin}/v1/sbx037/collect/${runId}/absolute`,
  pTerminalUrl: `${forwardAudienceP}/v1/sbx037/collect/${runId}/absolute`,
  bCollectUrl: `${bOrigin}/v1/sbx037/collect/${runId}/absolute`,
  operationId: "op_absolute_exact",
  actionOperationId: "action_op_absolute_exact",
  terminalStatusCode: 202,
  method: "POST",
  bodySource: "file",
  bodyFileMode: 0o600,
};

const networkPath: Sbx037ExpectedAttackCase = {
  caseId: "network-path-target-attack",
  correlationId: "corr_network_path_target",
  targetForm: "network-path",
  rawRequestTarget: `//b-owned.example.test/v1/sbx037/collect/${runId}/network-path`,
  pTerminalUrl: `${forwardAudienceP}/v1/sbx037/collect/${runId}/network-path`,
  bCollectUrl: `${bOrigin}/v1/sbx037/collect/${runId}/network-path`,
  operationId: "op_network_path_exact",
  actionOperationId: "action_op_network_path_exact",
  terminalStatusCode: 202,
  method: "POST",
  bodySource: "file",
  bodyFileMode: 0o600,
};

const expected: Sbx037ExpectedEvidence = {
  runId,
  testId: "SBX-037-POC",
  aliasEmail: SBX037_ALIAS_EMAIL,
  identity: {
    teamId: SBX037_TEAM_ID,
    projectId: SBX037_PROJECT_ID,
    sandboxId: "sbx_exact",
    sessionId: "session_exact",
    sandboxName: "sbx-037-owned",
  },
  aOrigin,
  pOrigin,
  bOrigin,
  pinnedAIpv4,
  pinnedPIpv4,
  pinnedBIpv4,
  forwardAudienceP,
  initialBAllow: {
    caseId: "direct-b-allow-control",
    correlationId: "corr_direct_b_allow",
    requestUrl: `${bOrigin}/v1/sbx037/direct/${runId}/allow`,
    operationId: "op_direct_b_allow",
    statusCode: 204,
  },
  directBPre: {
    caseId: "direct-b-pre",
    correlationId: "corr_direct_b_pre",
    requestUrl: `${bOrigin}/v1/sbx037/direct/${runId}/pre`,
  },
  directBPost: {
    caseId: "direct-b-post",
    correlationId: "corr_direct_b_post",
    requestUrl: `${bOrigin}/v1/sbx037/direct/${runId}/post`,
  },
  originControl: {
    caseId: "origin-form-terminal",
    correlationId: "corr_origin_form",
    aRequestUrl: `${aOrigin}/v1/sbx037/original/${runId}/origin`,
    rawRequestTarget: `/v1/sbx037/original/${runId}/origin`,
    pTerminalUrl: `${forwardAudienceP}/v1/sbx037/original/${runId}/origin`,
    operationId: "op_origin_terminal",
    terminalStatusCode: 202,
    method: "POST",
    bodySource: "public",
    requestBodyBytes: 32,
  },
  syntaxControls: [
    {
      caseId: "absolute-syntax-control",
      correlationId: "corr_absolute_syntax",
      targetForm: "absolute",
      rawRequestTarget: `${bOrigin}/v1/sbx037/collect/${runId}/syntax-absolute`,
      bCollectUrl: `${bOrigin}/v1/sbx037/collect/${runId}/syntax-absolute`,
      operationId: "op_absolute_syntax",
      syntaxSupported: true,
      terminalStatusCode: 202,
      method: "POST",
      bodySource: "public",
      requestBodyBytes: 30,
    },
    {
      caseId: "network-path-syntax-control",
      correlationId: "corr_network_syntax",
      targetForm: "network-path",
      rawRequestTarget: `//b-owned.example.test/v1/sbx037/collect/${runId}/syntax-network`,
      bCollectUrl: `${bOrigin}/v1/sbx037/collect/${runId}/syntax-network`,
      operationId: "op_network_syntax",
      syntaxSupported: true,
      terminalStatusCode: 202,
      method: "POST",
      bodySource: "public",
      requestBodyBytes: 29,
    },
  ],
  pSyntaxControls: [
    {
      caseId: "absolute-p-syntax-control",
      correlationId: "corr_absolute_p_syntax",
      targetForm: "absolute",
      rawRequestTarget: `${bOrigin}/v1/sbx037/collect/${runId}/syntax-p-absolute`,
      bCollectUrl: `${bOrigin}/v1/sbx037/collect/${runId}/syntax-p-absolute`,
      operationId: "op_absolute_p_syntax",
      syntaxSupported: true,
      terminalStatusCode: 202,
      method: "POST",
      bodySource: "public",
      requestBodyBytes: 32,
    },
    {
      caseId: "network-p-syntax-control",
      correlationId: "corr_network_p_syntax",
      targetForm: "network-path",
      rawRequestTarget: `//b-owned.example.test/v1/sbx037/collect/${runId}/syntax-p-network`,
      bCollectUrl: `${bOrigin}/v1/sbx037/collect/${runId}/syntax-p-network`,
      operationId: "op_network_p_syntax",
      syntaxSupported: true,
      terminalStatusCode: 202,
      method: "POST",
      bodySource: "public",
      requestBodyBytes: 31,
    },
  ],
  attacks: [absolute, networkPath],
};

function oidc(
  verifier: Sbx037PlatformOidcVerification["verifier"],
  overrides: Partial<Sbx037PlatformOidcVerification> = {},
): Sbx037PlatformOidcVerification {
  return {
    tokenOrdinal: 1,
    verifier,
    signatureVerified: true,
    algorithm: "RS256",
    issuer: `https://oidc.vercel.com/${SBX037_TEAM_ID}`,
    jwksUrl: `https://oidc.vercel.com/${SBX037_TEAM_ID}/.well-known/jwks`,
    audience: forwardAudienceP,
    temporalClaimsVerified: true,
    identity: { ...expected.identity },
    rawTokenRetained: false,
    ...overrides,
  };
}

function pEvent(wanted: typeof expected.originControl | Sbx037ExpectedAttackCase): Sbx037TerminalPEvent {
  return {
    runId,
    testId: expected.testId,
    caseId: wanted.caseId,
    correlationId: wanted.correlationId,
    requestUrl: wanted.pTerminalUrl,
    operationId: wanted.operationId,
    terminalResponse: true,
    forwardedMetadataValid: true,
    responseStatusCode: wanted.terminalStatusCode,
    oidcHeaderCount: 1,
    oidcValueCount: 1,
    oidcVerifications: [oidc("sink-p-independent-jose")],
  };
}

function guest(
  wanted: typeof expected.originControl | Sbx037ExpectedAttackCase | Sbx037ExpectedSyntaxControl,
  targetForm: Sbx037GuestRawRequestEvidence["targetForm"],
  destination: "a" | "p" = "a",
  responseRole: "A" | "P" | "B" = destination === "p"
    ? "P"
    : wanted.caseId === "origin-form-terminal"
      ? "P"
      : wanted.caseId.includes("syntax-control")
        ? "A"
        : "P",
): Sbx037GuestRawRequestEvidence {
  const origin = new URL(destination === "a" ? aOrigin : pOrigin);
  const pinnedIpv4 = destination === "a" ? pinnedAIpv4 : pinnedPIpv4;
  return {
    commandExitCode: 0,
    ok: true,
    runId,
    testId: expected.testId,
    caseId: wanted.caseId,
    correlationId: wanted.correlationId,
    targetForm,
    connectionRole: destination,
    syntaxSupported: true,
    method: wanted.method,
    bodySource: wanted.bodySource,
    operatorSecretLoaded: wanted.bodySource === "file",
    ...(wanted.bodySource === "file"
      ? { bodyFileMode: wanted.bodyFileMode }
      : { requestBodyBytes: wanted.requestBodyBytes }),
    httpVersion: "1.1",
    tcpHost: origin.hostname,
    tcpPort: 443,
    tlsServername: origin.hostname,
    httpHost: origin.host,
    rawRequestTarget: wanted.rawRequestTarget,
    maximumConnections: 1,
    actualConnections: 1,
    maximumRequests: 1,
    actualRequests: 1,
    retryCount: 0,
    redirectsAllowed: false,
    redirectsFollowed: 0,
    connectionReused: false,
    environmentProxyTrust: false,
    tlsTrust: {
      inheritedPlatformTrustEnvironmentNames: [
        "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF",
        "OPENSSL_MODULES", "SSL_CERT_DIR", "SSL_CERT_FILE",
      ],
      controllerConfigurableCustomTrustAccepted: false,
      rejectUnauthorized: true,
    },
    pinnedDestinationIpv4: pinnedIpv4,
    transportTcpConnected: true,
    transportTlsEstablished: true,
    transportAuthorized: true,
    transportRemoteAddress: pinnedIpv4,
    transportRemotePort: 443,
    transportAlpnProtocol: "http/1.1",
    responseStatusCode: wanted.terminalStatusCode,
    responseOperationId: wanted.operationId,
    responseRole,
  };
}

function hmacAction(
  operationId: string,
  overrides: Partial<Sbx037OperatorSecretActionVerification> = {},
): Sbx037OperatorSecretActionVerification {
  return {
    actionOrdinal: 1,
    verifier: "observer-b-independent-file-hmac",
    algorithm: "HMAC-SHA256",
    secretSource: "controller-file-mode-0600",
    secretFileMode: 0o600,
    hmacVerified: true,
    actionAuthorized: true,
    operationId,
    nonReflecting: true,
    rawSecretRetained: false,
    rawSecretReflected: false,
    responseBodyContainedSecret: false,
    ...overrides,
  };
}

function bEvent(
  wanted: Sbx037ExpectedAttackCase,
  overrides: Partial<Sbx037DestinationBEvent> = {},
): Sbx037DestinationBEvent {
  return {
    runId,
    testId: expected.testId,
    caseId: wanted.caseId,
    correlationId: wanted.correlationId,
    requestUrl: wanted.bCollectUrl,
    operationId: wanted.operationId,
    correlationMatched: true,
    responseStatusCode: wanted.terminalStatusCode,
    oidcHeaderCount: 0,
    oidcValueCount: 0,
    oidcVerifications: [],
    operatorSecretActions: [],
    ...overrides,
  };
}

function passAttack(wanted: Sbx037ExpectedAttackCase) {
  return {
    caseId: wanted.caseId,
    targetForm: wanted.targetForm,
    guest: guest(wanted, wanted.targetForm),
    p: { eventCount: 1, event: pEvent(wanted) },
    b: { eventCount: 0 },
  };
}

function bAttack(wanted: Sbx037ExpectedAttackCase, event = bEvent(wanted)) {
  return {
    caseId: wanted.caseId,
    targetForm: wanted.targetForm,
    guest: guest(wanted, wanted.targetForm, "a", "B"),
    p: { eventCount: 0 },
    b: { eventCount: 1, event },
  };
}

function fallbackEvent(
  wanted: Sbx037ExpectedAttackCase,
  role: "A" | "P" | "B",
  overrides: Partial<Sbx037SanitizedFallbackEvent> = {},
): Sbx037SanitizedFallbackEvent {
  const basePath = new URL(forwardAudienceP).pathname;
  const requestTarget = role === "A"
    ? wanted.rawRequestTarget
    : role === "P"
      ? `${basePath}${wanted.rawRequestTarget}`
      : wanted.rawRequestTarget;
  const host = new URL(role === "A" ? aOrigin : role === "P" ? pOrigin : bOrigin).host;
  const receiptId = `rt37f_${role.repeat(24)}`;
  const forwardedCount = role === "A" ? 0 : 1;
  const fallbackOidc = role === "P"
    ? [{ ...oidc("sink-p-independent-jose"), exactClaimsVerified: true }]
    : [];
  return {
    observedAt: "2026-08-19T12:00:00.000Z",
    role,
    reason: role === "A" ? "unmatched-a-route" : role === "P" ? "unmatched-forward-path" : "unmatched-collect-path",
    runId,
    testId: expected.testId,
    caseId: wanted.caseId,
    correlationId: wanted.correlationId,
    correlationMatched: true,
    method: wanted.method,
    requestTarget,
    host,
    forwardedHeaderCounts: {
      host: { lines: forwardedCount, values: forwardedCount },
      scheme: { lines: forwardedCount, values: forwardedCount },
      port: { lines: forwardedCount, values: forwardedCount },
      path: { lines: forwardedCount, values: forwardedCount },
    },
    oidcHeaderCount: role === "P" ? 1 : 0,
    oidcValueCount: role === "P" ? 1 : 0,
    tokenVerified: role === "P",
    algorithmRs256: role === "P",
    issuerVerified: role === "P",
    audienceVerified: role === "P",
    temporalClaimsVerified: role === "P",
    exactClaimsVerified: role === "P",
    oidcVerifications: fallbackOidc,
    operatorSecretBodyPresent: false,
    operatorSecretActionAttempted: false,
    operatorSecretActionAuthorized: false,
    operatorSecretActions: [],
    receiptId,
    rawOidcTokenRetained: false,
    rawRequestBodyRetained: false,
    rawOperatorSecretRetained: false,
    rawOperatorSecretReflected: false,
    responseBodyContainedSecret: false,
    derivedSecretDigestRetained: false,
    terminalResponse: true,
    redirectAttempted: false,
    fetchAttempted: false,
    proxyAttempted: false,
    locationHeaderPresent: false,
    responseStatus: 404,
    ...overrides,
  };
}

function fallbackAttack(
  wanted: Sbx037ExpectedAttackCase,
  role: "A" | "P" | "B",
  event = fallbackEvent(wanted, role),
) {
  const guestEvidence = guest(wanted, wanted.targetForm);
  guestEvidence.syntaxSupported = true;
  guestEvidence.responseStatusCode = event.responseStatus;
  delete guestEvidence.responseOperationId;
  guestEvidence.responseFallbackReceiptId = event.receiptId;
  guestEvidence.responseRole = event.role;
  return {
    caseId: wanted.caseId,
    targetForm: wanted.targetForm,
    guest: guestEvidence,
    p: { eventCount: 0 },
    b: { eventCount: 0 },
    fallback: { eventCount: 1, event },
  };
}

function unattributedFallbackAttack(wanted: Sbx037ExpectedAttackCase) {
  const guestEvidence = guest(wanted, wanted.targetForm);
  guestEvidence.syntaxSupported = true;
  guestEvidence.responseStatusCode = 404;
  delete guestEvidence.responseOperationId;
  guestEvidence.responseRole = "P";
  return {
    caseId: wanted.caseId,
    targetForm: wanted.targetForm,
    guest: guestEvidence,
    p: { eventCount: 0 },
    b: { eventCount: 0 },
    fallback: { eventCount: 0 },
  };
}

function syntaxControl(wanted: Sbx037ExpectedSyntaxControl) {
  return {
    caseId: wanted.caseId,
    targetForm: wanted.targetForm,
    guest: guest(wanted, wanted.targetForm),
    a: {
      eventCount: 1,
      event: {
        runId,
        testId: expected.testId,
        caseId: wanted.caseId,
        correlationId: wanted.correlationId,
        correlationMatched: true,
        method: wanted.method,
        rawRequestTarget: wanted.rawRequestTarget,
        targetForm: wanted.targetForm,
        exactSyntaxTarget: true,
        publicBodyMatched: true,
        bodyLength: wanted.requestBodyBytes,
        oidcHeaderCount: 0,
        operationId: wanted.operationId,
        terminalResponse: true,
        responseStatusCode: wanted.terminalStatusCode,
      },
    },
    bEventCount: 0,
  };
}

function unsupportedSyntaxControl(wanted: Sbx037ExpectedSyntaxControl): Sbx037SyntaxControlEvidence {
  const guestEvidence = guest(wanted, wanted.targetForm);
  guestEvidence.syntaxSupported = false;
  guestEvidence.responseStatusCode = 400;
  delete guestEvidence.responseOperationId;
  return {
    caseId: wanted.caseId,
    targetForm: wanted.targetForm,
    guest: guestEvidence,
    a: {
      eventCount: 1,
      event: {
        runId,
        testId: expected.testId,
        caseId: wanted.caseId,
        correlationId: wanted.correlationId,
        correlationMatched: true,
        method: wanted.method,
        rawRequestTarget: new URL(wanted.bCollectUrl).pathname,
        targetForm: "other",
        exactSyntaxTarget: false,
        publicBodyMatched: true,
        bodyLength: wanted.requestBodyBytes,
        oidcHeaderCount: 0,
        terminalResponse: true,
        responseStatusCode: 400,
      },
    },
    bEventCount: 0,
  };
}

function pSyntaxControl(wanted: Sbx037ExpectedSyntaxControl) {
  return {
    caseId: wanted.caseId,
    targetForm: wanted.targetForm,
    guest: guest(wanted, wanted.targetForm, "p"),
    p: {
      eventCount: 1,
      event: {
        runId,
        testId: expected.testId,
        caseId: wanted.caseId,
        correlationId: wanted.correlationId,
        correlationMatched: true,
        method: wanted.method,
        rawRequestTarget: wanted.rawRequestTarget,
        targetForm: wanted.targetForm,
        exactSyntaxTarget: true,
        hostMatched: true,
        publicBodyMatched: true,
        bodyLength: wanted.requestBodyBytes,
        oidcHeaderCount: 0,
        forwardedMetadataAbsent: true,
        operationId: wanted.operationId,
        terminalResponse: true,
        redirectAttempted: false,
        fetchAttempted: false,
        proxyAttempted: false,
        locationHeaderPresent: false,
        responseStatusCode: wanted.terminalStatusCode,
      },
    },
    bEventCount: 0,
  };
}

function input(): Sbx037AssessmentInput {
  const policy = { allow: { "a-owned.example.test": [{ forwardURL: forwardAudienceP }] } };
  return {
    expected: structuredClone(expected),
    scope: {
      authenticatedAliasEmail: expected.aliasEmail,
      authenticatedTeamId: expected.identity.teamId,
      authenticatedProjectId: expected.identity.projectId,
      scopeConfirmation: "researcher-controlled-sbx037-origins-only",
      ownedOrigins: [aOrigin, pOrigin, bOrigin],
      unownedEndpointCount: 0,
    },
    policyPre: {
      stage: "pre-attack",
      activeSessionId: expected.identity.sessionId,
      independentSessionId: expected.identity.sessionId,
      activePolicy: structuredClone(policy),
      independentPolicy: structuredClone(policy),
    },
    policyPost: {
      stage: "post-attack",
      activeSessionId: expected.identity.sessionId,
      independentSessionId: expected.identity.sessionId,
      activePolicy: structuredClone(policy),
      independentPolicy: structuredClone(policy),
    },
    initialBAllow: {
      caseId: expected.initialBAllow.caseId,
      correlationId: expected.initialBAllow.correlationId,
      requestUrl: expected.initialBAllow.requestUrl,
      maximumConnections: 1,
      actualConnections: 1,
      maximumRequests: 1,
      actualRequests: 1,
      retryCount: 0,
      redirectsAllowed: false,
      redirectsFollowed: 0,
      connectionReused: false,
      commandExitCode: 0,
      conclusiveReachability: true,
      responseStatusCode: expected.initialBAllow.statusCode,
      responseOperationId: expected.initialBAllow.operationId,
      responseRole: "B",
      destinationObserverEventCount: 1,
      destinationObserverEvent: {
        runId,
        testId: expected.testId,
        caseId: expected.initialBAllow.caseId,
        correlationId: expected.initialBAllow.correlationId,
        requestUrl: expected.initialBAllow.requestUrl,
        operationId: expected.initialBAllow.operationId,
      },
    },
    directBPre: {
      ...expected.directBPre,
      maximumConnections: 1,
      actualConnections: 0,
      maximumRequests: 1,
      actualRequests: 0,
      commandExitCode: 0,
      retryCount: 0,
      redirectsAllowed: false,
      connectionReused: false,
      configuredPinnedDestinationIpv4: pinnedBIpv4,
      tcpConnected: false,
      tlsEstablished: false,
      errorCode: "EHOSTUNREACH",
      durationMs: 500,
      samePinnedDestination: true,
      conclusiveFirewallBlock: true,
      destinationObserverEventCount: 0,
    },
    directBPost: {
      ...expected.directBPost,
      maximumConnections: 1,
      actualConnections: 0,
      maximumRequests: 1,
      actualRequests: 0,
      commandExitCode: 0,
      retryCount: 0,
      redirectsAllowed: false,
      connectionReused: false,
      configuredPinnedDestinationIpv4: pinnedBIpv4,
      tcpConnected: false,
      tlsEstablished: false,
      errorCode: "ENETUNREACH",
      durationMs: 500,
      samePinnedDestination: true,
      conclusiveFirewallBlock: true,
      destinationObserverEventCount: 0,
    },
    originGuest: guest(expected.originControl, "origin"),
    originP: { eventCount: 1, event: pEvent(expected.originControl) },
    sourceBehavior: { redirectsIssued: 0, outboundFetches: 0, proxiedRequests: 0 },
    syntaxControls: expected.syntaxControls.map(syntaxControl),
    pSyntaxControls: expected.pSyntaxControls.map(pSyntaxControl),
    attacks: [passAttack(absolute), passAttack(networkPath)],
    unexpectedPEventCount: 0,
    unexpectedBEventCount: 0,
    cleanup: {
      stopAttempted: true,
      stopped: true,
      deleteAttempted: true,
      deleted: true,
      sandboxAbsenceChecks: 3,
      receiverDeleteAttempted: true,
      receiverDeleted: true,
      receiverAbsent: true,
      liveLockReleased: true,
      errors: [],
    },
    evidenceStorage: {
      fileMode: 0o600,
      rawTokensAbsent: true,
      rawOperatorSecretsAbsent: true,
      controllerCredentialsAbsent: true,
      controllerConfiguredCustomTrustAbsent: true,
      strictTlsVerificationRequired: true,
      inheritedPlatformTrustEnvironmentNamesObserved: [
        "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF",
        "OPENSSL_MODULES", "SSL_CERT_DIR", "SSL_CERT_FILE",
      ],
    },
  };
}

describe("SBX-037 fail-closed verdict", () => {
  it("passes only when both supported attack targets terminate at authenticated P and B stays absent", () => {
    expect(assessSbx037(input())).toMatchObject({
      verdict: "pass",
      severity: "none",
      candidate: false,
      controlsPassed: true,
      oidcAtBProofValid: false,
      operatorSecretProofValid: false,
    });
  });

  it("derives a network-only exact case set after absolute-form is conclusively unsupported at A", () => {
    const value = input();
    const absoluteSyntax = value.expected.syntaxControls.find((entry) => entry.targetForm === "absolute")!;
    absoluteSyntax.syntaxSupported = false;
    absoluteSyntax.terminalStatusCode = 400;
    const networkPSyntax = value.expected.pSyntaxControls.find((entry) => entry.targetForm === "network-path")!;
    value.expected.pSyntaxControls = [networkPSyntax];
    value.expected.attacks = [networkPath];
    value.syntaxControls = [
      unsupportedSyntaxControl(absoluteSyntax),
      syntaxControl(value.expected.syntaxControls.find((entry) => entry.targetForm === "network-path")!),
    ];
    value.pSyntaxControls = [pSyntaxControl(networkPSyntax)];
    value.attacks = [passAttack(networkPath)];
    expect(assessSbx037(value)).toMatchObject({
      verdict: "pass", candidate: false, controlsPassed: true,
    });

    const high = structuredClone(value);
    high.attacks = [bAttack(networkPath, bEvent(networkPath, {
      operatorSecretActions: [hmacAction(networkPath.actionOperationId)],
    }))];
    expect(assessSbx037(high)).toMatchObject({
      verdict: "candidate-high", candidate: true, operatorSecretProofValid: true,
    });

    const inactiveEvent = structuredClone(value);
    inactiveEvent.unexpectedBEventCount = 1;
    expect(assessSbx037(inactiveEvent)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
  });

  it("rejects zero supported forms and malformed unsupported diagnostics", () => {
    const none = input();
    for (const control of none.expected.syntaxControls) {
      control.syntaxSupported = false;
      control.terminalStatusCode = 400;
    }
    none.expected.pSyntaxControls = [];
    none.expected.attacks = [];
    none.syntaxControls = none.expected.syntaxControls.map(unsupportedSyntaxControl);
    none.pSyntaxControls = [];
    none.attacks = [];
    expect(assessSbx037(none)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });

    const malformed = input();
    const absoluteSyntax = malformed.expected.syntaxControls[0]!;
    absoluteSyntax.syntaxSupported = false;
    absoluteSyntax.terminalStatusCode = 400;
    malformed.expected.pSyntaxControls = [malformed.expected.pSyntaxControls[1]!];
    malformed.expected.attacks = [networkPath];
    const diagnostic = unsupportedSyntaxControl(absoluteSyntax);
    diagnostic.a.event!.rawRequestTarget = absoluteSyntax.rawRequestTarget;
    malformed.syntaxControls = [diagnostic, syntaxControl(malformed.expected.syntaxControls[1]!)];
    malformed.pSyntaxControls = [pSyntaxControl(malformed.expected.pSyntaxControls[0]!)];
    malformed.attacks = [passAttack(networkPath)];
    expect(assessSbx037(malformed)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
  });

  it("classifies an exact sanitized B fallback as Medium without credential proof", () => {
    const value = input();
    value.attacks[0]!.fallback = { eventCount: 0 };
    value.attacks[1] = fallbackAttack(networkPath, "B", fallbackEvent(networkPath, "B", {
      requestTarget: "/arbitrary-host-side-rewrite-that-missed-collect",
    }));
    value.unexpectedFallbackEventCount = 0;
    expect(assessSbx037(value)).toMatchObject({
      verdict: "candidate-medium",
      severity: "medium",
      candidate: true,
      controlsPassed: true,
      terminalCloseLane: false,
    });
    expect(assessSbx037(value).attacks[1]).toMatchObject({
      outcome: "candidate-medium", fallbackAttribution: "B", oidcProofValid: false,
      operatorSecretProofValid: false,
    });
  });

  it("requires independent OIDC or the keyed file-secret action for a High B fallback", () => {
    const token = input();
    token.attacks[0]!.fallback = { eventCount: 0 };
    token.attacks[1] = fallbackAttack(networkPath, "B", fallbackEvent(networkPath, "B", {
      oidcHeaderCount: 1,
      oidcValueCount: 1,
      tokenVerified: true,
      algorithmRs256: true,
      issuerVerified: true,
      audienceVerified: true,
      temporalClaimsVerified: true,
      exactClaimsVerified: true,
      oidcVerifications: [{ ...oidc("observer-b-independent-jose"), exactClaimsVerified: true }],
    }));
    token.unexpectedFallbackEventCount = 0;
    expect(assessSbx037(token)).toMatchObject({
      verdict: "candidate-high", oidcAtBProofValid: true, operatorSecretProofValid: false,
    });

    const secret = input();
    secret.attacks[0]!.fallback = { eventCount: 0 };
    secret.attacks[1] = fallbackAttack(networkPath, "B", fallbackEvent(networkPath, "B", {
      operatorSecretBodyPresent: true,
      operatorSecretActionAttempted: true,
      operatorSecretActionAuthorized: true,
      actionOperationId: networkPath.actionOperationId,
      operatorSecretActions: [hmacAction(networkPath.actionOperationId)],
    }));
    secret.unexpectedFallbackEventCount = 0;
    expect(assessSbx037(secret)).toMatchObject({
      verdict: "candidate-high", oidcAtBProofValid: false, operatorSecretProofValid: true,
    });

    const wrongAudience = structuredClone(token);
    wrongAudience.attacks[1]!.fallback!.event!.oidcVerifications[0]!.audience = bOrigin;
    wrongAudience.attacks[1]!.fallback!.event!.oidcVerifications[0]!.verificationError = "non-exact-audience";
    wrongAudience.attacks[1]!.fallback!.event!.tokenVerified = false;
    wrongAudience.attacks[1]!.fallback!.event!.audienceVerified = false;
    expect(assessSbx037(wrongAudience)).toMatchObject({
      verdict: "candidate-medium", oidcAtBProofValid: false,
    });
  });

  it("keeps exact B reachability at Medium when a safely sanitized body fails the keyed action", () => {
    const value = input();
    value.attacks[0]!.fallback = { eventCount: 0 };
    value.attacks[1] = fallbackAttack(networkPath, "B", fallbackEvent(networkPath, "B", {
      operatorSecretBodyPresent: true,
      operatorSecretActionAttempted: true,
      operatorSecretActionAuthorized: false,
    }));
    value.unexpectedFallbackEventCount = 0;
    expect(assessSbx037(value)).toMatchObject({
      verdict: "candidate-medium",
      severity: "medium",
      candidate: true,
      operatorSecretProofValid: false,
    });

    const inconsistent = structuredClone(value);
    inconsistent.attacks[1]!.fallback!.event!.actionOperationId = networkPath.actionOperationId;
    expect(assessSbx037(inconsistent)).toMatchObject({
      verdict: "indeterminate", candidate: false,
    });
  });

  it("treats exact P path-join and exact A ingress fallbacks as clean negatives", () => {
    for (const role of ["P", "A"] as const) {
      const value = input();
      value.attacks[0]!.fallback = { eventCount: 0 };
      const event = fallbackEvent(networkPath, role, role === "P"
        ? { requestTarget: "/arbitrary-forward-path-rewrite" }
        : {});
      value.attacks[1] = fallbackAttack(networkPath, role, event);
      value.unexpectedFallbackEventCount = 0;
      expect(assessSbx037(value)).toMatchObject({
        verdict: "pass", severity: "none", candidate: false, controlsPassed: true,
      });
      expect(assessSbx037(value).attacks[1]).toMatchObject({
        outcome: "pass", fallbackAttribution: role, terminalCloseLane: false,
      });
    }
  });

  it("makes a second exact 404 with zero fallback events terminal indeterminate and closes the lane", () => {
    const value = input();
    value.attacks[0]!.fallback = { eventCount: 0 };
    value.attacks[1] = unattributedFallbackAttack(networkPath);
    value.unexpectedFallbackEventCount = 0;
    expect(assessSbx037(value)).toMatchObject({
      verdict: "indeterminate",
      severity: "unknown",
      candidate: false,
      controlsPassed: true,
      terminalCloseLane: true,
    });
    expect(assessSbx037(value).attacks[1]).toMatchObject({
      outcome: "indeterminate", fallbackAttribution: "unattributed", terminalCloseLane: true,
    });
  });

  it("requires the guest response receipt and role to match the exact fallback record", () => {
    const wrongReceipt = input();
    wrongReceipt.attacks[0]!.fallback = { eventCount: 0 };
    wrongReceipt.attacks[1] = fallbackAttack(networkPath, "B");
    wrongReceipt.attacks[1]!.guest.responseFallbackReceiptId = `rt37f_${"X".repeat(24)}`;
    wrongReceipt.unexpectedFallbackEventCount = 0;
    expect(assessSbx037(wrongReceipt).attacks[1]).toMatchObject({
      outcome: "indeterminate", fallbackAttribution: "invalid",
    });

    const wrongRole = input();
    wrongRole.attacks[0]!.fallback = { eventCount: 0 };
    wrongRole.attacks[1] = fallbackAttack(networkPath, "B");
    wrongRole.attacks[1]!.guest.responseRole = "P";
    wrongRole.unexpectedFallbackEventCount = 0;
    expect(assessSbx037(wrongRole).attacks[1]).toMatchObject({
      outcome: "indeterminate", fallbackAttribution: "invalid",
    });

    const receiverOnly = input();
    receiverOnly.attacks[0]!.fallback = { eventCount: 0 };
    receiverOnly.attacks[1] = fallbackAttack(networkPath, "B");
    delete receiverOnly.attacks[1]!.guest.responseFallbackReceiptId;
    delete receiverOnly.attacks[1]!.guest.responseRole;
    receiverOnly.unexpectedFallbackEventCount = 0;
    expect(assessSbx037(receiverOnly).attacks[1]).toMatchObject({
      outcome: "indeterminate", fallbackAttribution: "invalid",
    });
  });

  it("requires the exact receiver role on every normal control and primary attack response", () => {
    const missingInitialRole = input();
    delete missingInitialRole.initialBAllow.responseRole;
    expect(assessSbx037(missingInitialRole)).toMatchObject({
      verdict: "indeterminate", controlsPassed: false,
    });

    const wrongInitialRole = input();
    (wrongInitialRole.initialBAllow as { responseRole?: string }).responseRole = "P";
    expect(assessSbx037(wrongInitialRole)).toMatchObject({
      verdict: "indeterminate", controlsPassed: false,
    });

    const missingARole = input();
    delete missingARole.syntaxControls[0]!.guest.responseRole;
    expect(assessSbx037(missingARole)).toMatchObject({
      verdict: "indeterminate", controlsPassed: false,
    });

    const wrongARole = input();
    wrongARole.syntaxControls[0]!.guest.responseRole = "P";
    expect(assessSbx037(wrongARole)).toMatchObject({
      verdict: "indeterminate", controlsPassed: false,
    });

    const missingPRole = input();
    delete missingPRole.pSyntaxControls[0]!.guest.responseRole;
    expect(assessSbx037(missingPRole)).toMatchObject({
      verdict: "indeterminate", controlsPassed: false,
    });

    const wrongPRole = input();
    wrongPRole.originGuest.responseRole = "A";
    expect(assessSbx037(wrongPRole)).toMatchObject({
      verdict: "indeterminate", controlsPassed: false,
    });

    const pEvidenceWithBRole = input();
    pEvidenceWithBRole.attacks[0]!.guest.responseRole = "B";
    expect(assessSbx037(pEvidenceWithBRole)).toMatchObject({
      verdict: "indeterminate", controlsPassed: true,
    });
    expect(assessSbx037(pEvidenceWithBRole).attacks[0]).toMatchObject({ outcome: "indeterminate" });

    const bEvidenceWithPRole = input();
    bEvidenceWithPRole.attacks[0] = bAttack(absolute);
    bEvidenceWithPRole.attacks[0]!.guest.responseRole = "P";
    expect(assessSbx037(bEvidenceWithPRole)).toMatchObject({
      verdict: "indeterminate", controlsPassed: true,
    });
    expect(assessSbx037(bEvidenceWithPRole).attacks[0]).toMatchObject({ outcome: "indeterminate" });
  });

  it("rejects malformed, mixed, duplicate, or unexpectedly accounted fallback evidence", () => {
    const malformed = input();
    malformed.attacks[0]!.fallback = { eventCount: 0 };
    malformed.attacks[1] = fallbackAttack(networkPath, "P");
    malformed.attacks[1]!.fallback!.event!.correlationId = "corr_wrong";
    malformed.unexpectedFallbackEventCount = 0;
    expect(assessSbx037(malformed)).toMatchObject({ verdict: "indeterminate", candidate: false });

    const wrongHost = input();
    wrongHost.attacks[0]!.fallback = { eventCount: 0 };
    wrongHost.attacks[1] = fallbackAttack(networkPath, "B");
    wrongHost.attacks[1]!.fallback!.event!.host = new URL(aOrigin).host;
    wrongHost.unexpectedFallbackEventCount = 0;
    expect(assessSbx037(wrongHost)).toMatchObject({ verdict: "indeterminate", candidate: false });

    const partialForwardedMetadata = input();
    partialForwardedMetadata.attacks[0]!.fallback = { eventCount: 0 };
    partialForwardedMetadata.attacks[1] = fallbackAttack(networkPath, "P");
    partialForwardedMetadata.attacks[1]!.fallback!.event!.forwardedHeaderCounts.path = { lines: 0, values: 0 };
    partialForwardedMetadata.unexpectedFallbackEventCount = 0;
    expect(assessSbx037(partialForwardedMetadata)).toMatchObject({ verdict: "indeterminate", candidate: false });

    const retained = input();
    retained.attacks[0]!.fallback = { eventCount: 0 };
    retained.attacks[1] = fallbackAttack(networkPath, "B");
    retained.attacks[1]!.fallback!.event!.rawRequestBodyRetained = true;
    retained.unexpectedFallbackEventCount = 0;
    expect(assessSbx037(retained)).toMatchObject({ verdict: "indeterminate", candidate: false });

    const duplicate = input();
    duplicate.attacks[0]!.fallback = { eventCount: 0 };
    duplicate.attacks[1] = fallbackAttack(networkPath, "B");
    duplicate.attacks[1]!.fallback!.eventCount = 2;
    duplicate.unexpectedFallbackEventCount = 0;
    expect(assessSbx037(duplicate)).toMatchObject({ verdict: "indeterminate", candidate: false });

    const mixed = input();
    mixed.attacks[0]!.fallback = { eventCount: 0 };
    mixed.attacks[1]!.fallback = { eventCount: 1, event: fallbackEvent(networkPath, "P") };
    mixed.unexpectedFallbackEventCount = 0;
    expect(assessSbx037(mixed)).toMatchObject({ verdict: "indeterminate", candidate: false });

    const unexpected = input();
    unexpected.attacks[0]!.fallback = { eventCount: 0 };
    unexpected.attacks[1] = fallbackAttack(networkPath, "A");
    unexpected.unexpectedFallbackEventCount = 1;
    expect(assessSbx037(unexpected)).toMatchObject({
      verdict: "indeterminate", candidate: false, controlsPassed: false,
    });
  });

  it("classifies exact attributable B reachability without a credential as Medium", () => {
    const value = input();
    value.attacks[0] = bAttack(absolute);
    expect(assessSbx037(value)).toMatchObject({
      verdict: "candidate-medium",
      severity: "medium",
      candidate: true,
    });
  });

  it("classifies High for exactly one independently verified Vercel token at B", () => {
    const value = input();
    value.attacks[0] = bAttack(absolute, bEvent(absolute, {
      oidcHeaderCount: 1,
      oidcValueCount: 1,
      oidcVerifications: [oidc("observer-b-independent-jose")],
    }));
    expect(assessSbx037(value)).toMatchObject({
      verdict: "candidate-high",
      severity: "high",
      oidcAtBProofValid: true,
      operatorSecretProofValid: false,
    });
  });

  it("classifies High for one exact non-reflecting file-backed HMAC action at B", () => {
    const value = input();
    value.attacks[0] = bAttack(absolute, bEvent(absolute, {
      operatorSecretActions: [hmacAction(absolute.actionOperationId)],
    }));
    expect(assessSbx037(value)).toMatchObject({
      verdict: "candidate-high",
      severity: "high",
      oidcAtBProofValid: false,
      operatorSecretProofValid: true,
    });
  });

  it("rejects multi-audience and duplicate-token evidence as High", () => {
    expect(exactAudienceClaim([forwardAudienceP, "https://other.example.test"], forwardAudienceP)).toBe(false);
    const multiAudience = input();
    multiAudience.attacks[0] = bAttack(absolute, bEvent(absolute, {
      oidcHeaderCount: 1,
      oidcValueCount: 1,
      oidcVerifications: [oidc("observer-b-independent-jose", {
        audience: [forwardAudienceP, "https://other.example.test"],
      })],
    }));
    expect(assessSbx037(multiAudience)).toMatchObject({ verdict: "candidate-medium", oidcAtBProofValid: false });

    const duplicate = input();
    duplicate.attacks[0] = bAttack(absolute, bEvent(absolute, {
      oidcHeaderCount: 2,
      oidcValueCount: 2,
      oidcVerifications: [oidc("observer-b-independent-jose"), {
        ...oidc("observer-b-independent-jose"), tokenOrdinal: 2,
      }],
    }));
    expect(assessSbx037(duplicate)).toMatchObject({ verdict: "candidate-medium", oidcAtBProofValid: false });
  });

  it("requires the guest receipt and B event operation IDs to match the keyed expectation", () => {
    const wrongGuestReceipt = input();
    wrongGuestReceipt.attacks[0] = bAttack(absolute);
    wrongGuestReceipt.attacks[0]!.guest.responseOperationId = "op_wrong";
    expect(assessSbx037(wrongGuestReceipt).verdict).toBe("indeterminate");

    const wrongBReceipt = input();
    wrongBReceipt.attacks[0] = bAttack(absolute, bEvent(absolute, { operationId: "op_wrong" }));
    expect(assessSbx037(wrongBReceipt).verdict).toBe("indeterminate");
  });

  it("refuses pre/post direct-B event leakage even when an attack has a valid token", () => {
    for (const lane of ["directBPre", "directBPost"] as const) {
      const value = input();
      value.attacks[0] = bAttack(absolute, bEvent(absolute, {
        oidcHeaderCount: 1,
        oidcValueCount: 1,
        oidcVerifications: [oidc("observer-b-independent-jose")],
      }));
      value[lane].destinationObserverEventCount = 1;
      expect(assessSbx037(value)).toMatchObject({ verdict: "indeterminate", candidate: false });
    }
  });

  it("refuses a source that redirects, fetches, or proxies", () => {
    for (const key of ["redirectsIssued", "outboundFetches", "proxiedRequests"] as const) {
      const value = input();
      value.sourceBehavior[key] = 1;
      expect(assessSbx037(value)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
    }
  });

  it("requires both initial raw-target controls to terminate exactly at A with zero B events", () => {
    const routedDownstream = input();
    routedDownstream.syntaxControls[0]!.bEventCount = 1;
    expect(assessSbx037(routedDownstream)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });

    const normalizedAtA = input();
    normalizedAtA.syntaxControls[1]!.a.event!.rawRequestTarget = "/normalized-by-downstream";
    expect(assessSbx037(normalizedAtA)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
  });

  it("requires both raw-target controls to terminate directly at P with zero OIDC, forwarded metadata, and B events", () => {
    const routedByP = input();
    routedByP.pSyntaxControls[0]!.bEventCount = 1;
    expect(assessSbx037(routedByP)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });

    const oidcAtP = input();
    oidcAtP.pSyntaxControls[0]!.p.event!.oidcHeaderCount = 1;
    expect(assessSbx037(oidcAtP)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });

    const forwardedAtP = input();
    forwardedAtP.pSyntaxControls[1]!.p.event!.forwardedMetadataAbsent = false;
    expect(assessSbx037(forwardedAtP)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });

    const wrongPeer = input();
    wrongPeer.pSyntaxControls[1]!.guest.transportRemoteAddress = pinnedAIpv4;
    expect(assessSbx037(wrongPeer)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
  });

  it("requires exact pinned-A verified transport for controls and every candidate", () => {
    const wrongPeer = input();
    wrongPeer.attacks[0] = bAttack(absolute, bEvent(absolute, {
      operatorSecretActions: [hmacAction(absolute.actionOperationId)],
    }));
    wrongPeer.attacks[0]!.guest.transportRemoteAddress = "104.21.10.38";
    expect(assessSbx037(wrongPeer)).toMatchObject({ verdict: "indeterminate", candidate: false });

    const unverifiedTls = input();
    unverifiedTls.originGuest.transportAuthorized = false;
    expect(assessSbx037(unverifiedTls)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
  });

  it("distinguishes inherited platform CA trust from any configurable custom-trust or verification bypass", () => {
    const inheritedOnly = input();
    inheritedOnly.originGuest.tlsTrust.inheritedPlatformTrustEnvironmentNames = [
      "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF",
      "OPENSSL_MODULES", "SSL_CERT_DIR", "SSL_CERT_FILE",
    ];
    expect(assessSbx037(inheritedOnly).controlsPassed).toBe(true);

    const unsortedNames = input();
    unsortedNames.originGuest.tlsTrust.inheritedPlatformTrustEnvironmentNames = [
      "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS",
    ];
    expect(assessSbx037(unsortedNames)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });

    const unknownName = input();
    unknownName.originGuest.tlsTrust.inheritedPlatformTrustEnvironmentNames = ["CUSTOM_CA_PATH"];
    expect(assessSbx037(unknownName)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });

    const customTrust = input();
    customTrust.originGuest.tlsTrust.controllerConfigurableCustomTrustAccepted = true;
    expect(assessSbx037(customTrust)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });

    const verificationDisabled = input();
    verificationDisabled.attacks[0]!.guest.tlsTrust.rejectUnauthorized = false;
    expect(assessSbx037(verificationDisabled).verdict).toBe("indeterminate");

    const dishonestStorage = input();
    dishonestStorage.evidenceStorage.controllerConfiguredCustomTrustAbsent = false;
    expect(assessSbx037(dishonestStorage)).toMatchObject({ verdict: "error", controlsPassed: false });
  });

  it("requires the exact appended P URL and exact forwarded metadata", () => {
    const wrongUrl = input();
    wrongUrl.originP.event!.requestUrl = forwardAudienceP;
    expect(assessSbx037(wrongUrl)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });

    const wrongMetadata = input();
    wrongMetadata.originP.event!.forwardedMetadataValid = false;
    expect(assessSbx037(wrongMetadata)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
  });

  it("accepts only enumerated bounded direct-B firewall deny signatures", () => {
    const connectedReset = input();
    Object.assign(connectedReset.directBPre, {
      actualConnections: 1,
      tcpConnected: true,
      tlsEstablished: false,
      observedRemoteAddress: pinnedBIpv4,
      errorCode: "ECONNRESET",
    });
    expect(assessSbx037(connectedReset).controlsPassed).toBe(true);

    for (const errorCode of ["ETIMEDOUT", "ECONNREFUSED", "EAI_AGAIN"]) {
      const value = input();
      value.directBPre.errorCode = errorCode;
      expect(assessSbx037(value)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
    }
  });

  it("refuses mixed P/B activity and duplicated B events", () => {
    const mixed = input();
    mixed.attacks[0] = bAttack(absolute, bEvent(absolute, {
      oidcHeaderCount: 1,
      oidcValueCount: 1,
      oidcVerifications: [oidc("observer-b-independent-jose")],
    }));
    mixed.attacks[0]!.p = { eventCount: 1, event: pEvent(absolute) };
    expect(assessSbx037(mixed)).toMatchObject({ verdict: "indeterminate", candidate: false });

    const duplicate = input();
    duplicate.attacks[0] = bAttack(absolute);
    duplicate.attacks[0]!.b.eventCount = 2;
    expect(assessSbx037(duplicate)).toMatchObject({ verdict: "indeterminate", candidate: false });
  });

  it("refuses duplicate/mixed attack case accounting", () => {
    const value = input();
    value.attacks[1] = structuredClone(value.attacks[0]!);
    expect(assessSbx037(value)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });

    const unexpected = input();
    unexpected.unexpectedBEventCount = 1;
    expect(assessSbx037(unexpected)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
  });

  it("makes unsupported syntax indeterminate and never a pass", () => {
    const value = input();
    const unsupported = value.attacks[1]!;
    unsupported.guest.syntaxSupported = false;
    unsupported.guest.responseRole = "A";
    unsupported.guest.ok = false;
    delete unsupported.guest.responseStatusCode;
    delete unsupported.guest.responseOperationId;
    unsupported.p = { eventCount: 0 };
    expect(assessSbx037(value)).toMatchObject({ verdict: "indeterminate", candidate: false });
    expect(assessSbx037(value).attacks[1]).toMatchObject({ syntaxUnsupported: true });
  });

  it("lets an exact candidate override only an optional unsupported sibling case", () => {
    const value = input();
    value.attacks[0] = bAttack(absolute, bEvent(absolute, {
      operatorSecretActions: [hmacAction(absolute.actionOperationId)],
    }));
    const unsupported = value.attacks[1]!;
    unsupported.guest.syntaxSupported = false;
    unsupported.guest.responseRole = "A";
    unsupported.guest.ok = false;
    delete unsupported.guest.responseStatusCode;
    delete unsupported.guest.responseOperationId;
    unsupported.p = { eventCount: 0 };
    expect(assessSbx037(value)).toMatchObject({ verdict: "candidate-high", operatorSecretProofValid: true });
  });

  it("does not let a candidate mask ambiguous sibling evidence", () => {
    const value = input();
    value.attacks[0] = bAttack(absolute, bEvent(absolute, {
      operatorSecretActions: [hmacAction(absolute.actionOperationId)],
    }));
    value.attacks[1]!.b = { eventCount: 2, event: bEvent(networkPath) };
    value.attacks[1]!.p = { eventCount: 0 };
    expect(assessSbx037(value)).toMatchObject({
      verdict: "indeterminate",
      candidate: false,
      operatorSecretProofValid: false,
    });
  });

  it("requires exact active and independent same-session policy readbacks", () => {
    const wrongSession = input();
    wrongSession.policyPost.independentSessionId = "other_session";
    expect(assessSbx037(wrongSession)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });

    expect(exactForwardPolicy(
      { allow: { "a-owned.example.test": [{ forwardURL: forwardAudienceP }], extra: [] } },
      "a-owned.example.test",
      forwardAudienceP,
    )).toBe(false);
  });

  it("requires the origin-form terminal P baseline to verify exactly one exact-audience token", () => {
    const value = input();
    value.originP.event!.oidcVerifications[0]!.audience = [forwardAudienceP, "https://extra.example.test"];
    expect(assessSbx037(value)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
  });

  it("downgrades wrong B identity, verifier, raw retention, or secret reflection to Medium", () => {
    const tokenMutations: Array<Partial<Sbx037PlatformOidcVerification>> = [
      { verifier: "sink-p-independent-jose" },
      { identity: { ...expected.identity, sessionId: "wrong_session" } },
      { rawTokenRetained: true },
    ];
    for (const mutation of tokenMutations) {
      const value = input();
      const verification = oidc("observer-b-independent-jose", mutation);
      expect(exactPlatformOidcVerification(verification, expected, "observer-b-independent-jose")).toBe(false);
      value.attacks[0] = bAttack(absolute, bEvent(absolute, {
        oidcHeaderCount: 1,
        oidcValueCount: 1,
        oidcVerifications: [verification],
      }));
      expect(assessSbx037(value)).toMatchObject({ verdict: "candidate-medium", oidcAtBProofValid: false });
    }

    const reflected = hmacAction(absolute.actionOperationId, { rawSecretReflected: true });
    expect(exactOperatorSecretAction(reflected, absolute.actionOperationId)).toBe(false);
    const value = input();
    value.attacks[0] = bAttack(absolute, bEvent(absolute, {
      operatorSecretActions: [reflected],
    }));
    expect(assessSbx037(value)).toMatchObject({ verdict: "candidate-medium", operatorSecretProofValid: false });
  });

  it("requires the distinct keyed HMAC action operation ID, not B's public receipt ID", () => {
    const publicReceiptOnly = input();
    publicReceiptOnly.attacks[0] = bAttack(absolute, bEvent(absolute, {
      operatorSecretActions: [hmacAction(absolute.operationId)],
    }));
    expect(assessSbx037(publicReceiptOnly)).toMatchObject({
      verdict: "candidate-medium",
      operatorSecretProofValid: false,
    });

    const value = input();
    value.attacks[0] = bAttack(absolute, bEvent(absolute, {
      operatorSecretActions: [hmacAction("op_other")],
    }));
    expect(assessSbx037(value)).toMatchObject({ verdict: "candidate-medium", operatorSecretProofValid: false });
  });

  it("requires public receipt and secret action operation IDs to be globally unique and non-equal", () => {
    const equalWithinCase = input();
    equalWithinCase.expected.attacks[0]!.actionOperationId = equalWithinCase.expected.attacks[0]!.operationId;
    expect(assessSbx037(equalWithinCase)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });

    const duplicateAcrossCases = input();
    duplicateAcrossCases.expected.attacks[1]!.actionOperationId =
      duplicateAcrossCases.expected.attacks[0]!.actionOperationId;
    expect(assessSbx037(duplicateAcrossCases)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
  });

  it("returns error on cleanup, evidence-security, or execution failure", () => {
    const cleanup = input();
    cleanup.cleanup.sandboxAbsenceChecks = 2;
    expect(assessSbx037(cleanup)).toMatchObject({ verdict: "error", candidate: false });

    const storage = input();
    storage.evidenceStorage.fileMode = 0o644;
    expect(assessSbx037(storage)).toMatchObject({ verdict: "error", candidate: false });

    const execution = input();
    execution.executionError = true;
    expect(assessSbx037(execution)).toMatchObject({ verdict: "error", candidate: false });
  });

  it("requires the initial B allow control before accepting later block or attack evidence", () => {
    const value = input();
    value.initialBAllow.destinationObserverEventCount = 0;
    delete value.initialBAllow.destinationObserverEvent;
    expect(assessSbx037(value)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
  });
});
