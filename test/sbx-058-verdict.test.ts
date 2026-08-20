import { describe, expect, it } from "vitest";
import {
  assessSbx058,
  directBlockTuple,
  directBlockTransportCoherent,
  exactSbx058PolicyProof,
  type Sbx058AssessmentInput,
  type Sbx058Identity,
  type Sbx058ProbeEvidence,
} from "../pocs/SBX-058/verdict.js";
import {
  SBX058_CASES,
  SBX058_EVENT_CASES,
  proxyAudience,
  requestPath,
  type Sbx058CaseId,
  type Sbx058EventCaseId,
  type Sbx058Role,
} from "../pocs/SBX-058/protocol.js";
import type { Sbx058ReceiverEvent } from "../pocs/SBX-058/receiver.js";

const runId = "123e4567-e89b-42d3-a456-426614174058";
const aOrigin = "https://a-sbx058.trycloudflare.com";
const pOrigin = "https://p-sbx058.trycloudflare.com";
const aHostname = new URL(aOrigin).hostname;
const pHostname = new URL(pOrigin).hostname;
const identity: Sbx058Identity = {
  aliasEmail: "swve@wearehackerone.com",
  aliasIdentityVerified: true,
  teamId: "team_n98ERpVwV7HqmWRudAyK8sXQ",
  projectId: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
  sandboxName: `sbx-058-${runId}`,
  sessionId: "sbx_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
};
const canaries = Object.fromEntries(SBX058_CASES.map((caseId) => [
  caseId,
  `s58_${caseId}_${"C".repeat(22)}`,
])) as Record<Sbx058CaseId, string>;
const symbols = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J"];
const proof = (index: number) => ({
  operationId: `s58op_${symbols[index * 2]!.repeat(43)}`,
  receipt: `s58rcpt_${symbols[index * 2 + 1]!.repeat(43)}`,
});
const expectedEvents: Sbx058AssessmentInput["expectedEvents"] = {
  "exact-pair": { P: proof(0) },
  "key-half": { A: proof(1) },
  "value-half": { A: proof(2) },
  "combined-halves": { A: proof(3), P: proof(4) },
};

function sessionPolicy(matcher = true): unknown {
  return {
    allow: {
      [aHostname]: [{
        ...(matcher ? {
          match: { headers: [{ key: { exact: "x-sbx058-route" }, value: { exact: "privileged" } }] },
        } : {}),
        forwardURL: proxyAudience(pOrigin, runId),
      }],
    },
  };
}

const topPolicy = { allow: [aHostname] };

function policy(stage: "before" | "after", start: string, end: string, matcher = true) {
  return {
    stage,
    startedAt: start,
    completedAt: end,
    expectedSessionId: identity.sessionId,
    activeSessionId: identity.sessionId,
    independentSessionId: identity.sessionId,
    activeSandboxPolicy: topPolicy,
    activeSessionPolicy: sessionPolicy(matcher),
    independentSandboxPolicy: topPolicy,
    independentSessionPolicy: sessionPolicy(matcher),
    configuredPolicyComparedExactlyInMemory: true as const,
    projectionMode: matcher ? "exact-matchers" as const : "matcherless" as const,
    identity,
    containsControllerSecrets: false as const,
  };
}

function oidc(role: Sbx058Role) {
  return role === "P" ? {
    oidcHeaderLines: 1,
    oidcHeaderValues: 1,
    oidcOfficialVerified: true,
    oidcIndependentRs256Verified: true,
    oidcAudienceMatched: true,
    oidcSourceMatched: true,
    oidcIssuerVerified: true,
    oidcTemporalVerified: true,
    oidcIssuer: `https://oidc.vercel.com/${identity.teamId}`,
    oidcAudience: proxyAudience(pOrigin, runId),
    oidcTeamId: identity.teamId,
    oidcProjectId: identity.projectId,
    oidcSessionId: identity.sessionId,
    oidcSandboxName: identity.sandboxName,
  } : {
    oidcHeaderLines: 0,
    oidcHeaderValues: 0,
    oidcOfficialVerified: false,
    oidcIndependentRs256Verified: false,
    oidcAudienceMatched: false,
    oidcSourceMatched: false,
    oidcIssuerVerified: false,
    oidcTemporalVerified: false,
  };
}

function headerFacts(caseId: Sbx058EventCaseId) {
  return {
    route: caseId === "value-half" ? 0 : 1,
    decoy: caseId === "value-half" || caseId === "combined-halves" ? 1 : 0,
    routeMatched: caseId === "exact-pair",
    decoyMatched: caseId === "value-half" || caseId === "combined-halves",
  };
}

const eventTimes: Record<Sbx058EventCaseId, string> = {
  "exact-pair": "2026-08-19T12:00:00.070Z",
  "key-half": "2026-08-19T12:00:00.100Z",
  "value-half": "2026-08-19T12:00:00.130Z",
  "combined-halves": "2026-08-19T12:00:00.160Z",
};

function event(caseId: Sbx058EventCaseId, role: Sbx058Role): Sbx058ReceiverEvent {
  const facts = headerFacts(caseId);
  const wanted = expectedEvents[caseId][role]!;
  return {
    ordinal: SBX058_EVENT_CASES.indexOf(caseId) + 1,
    observedAt: eventTimes[caseId],
    caseId,
    role,
    method: "GET",
    hostMatched: true,
    pathMatched: true,
    correlationHeadersExact: true,
    forwardedMetadataExact: role === "P",
    routeHeaderLines: facts.route,
    routeHeaderValues: facts.route,
    decoyHeaderLines: facts.decoy,
    decoyHeaderValues: facts.decoy,
    routeValueMatched: facts.routeMatched,
    decoyValueMatched: facts.decoyMatched,
    ...oidc(role),
    operationId: wanted.operationId,
    receipt: wanted.receipt,
  };
}

const probeTimes: Record<Sbx058CaseId, [string, string]> = {
  "direct-p-pre": ["2026-08-19T12:00:00.040Z", "2026-08-19T12:00:00.050Z"],
  "exact-pair": ["2026-08-19T12:00:00.060Z", "2026-08-19T12:00:00.080Z"],
  "key-half": ["2026-08-19T12:00:00.090Z", "2026-08-19T12:00:00.110Z"],
  "value-half": ["2026-08-19T12:00:00.120Z", "2026-08-19T12:00:00.140Z"],
  "combined-halves": ["2026-08-19T12:00:00.150Z", "2026-08-19T12:00:00.170Z"],
  "direct-p-post": ["2026-08-19T12:00:00.180Z", "2026-08-19T12:00:00.190Z"],
};

function responseProbe(caseId: Sbx058EventCaseId, role: Sbx058Role): Sbx058ProbeEvidence {
  const target = new URL(aOrigin);
  const wanted = expectedEvents[caseId][role]!;
  const facts = headerFacts(caseId);
  return {
    schemaVersion: 1,
    testId: "SBX-058-HEADER-ENTRY-BINDING",
    runId,
    caseId,
    correlationCanary: canaries[caseId],
    targetRole: "A",
    headerMode: caseId,
    commandExitCode: 0,
    startedAt: probeTimes[caseId][0],
    completedAt: probeTimes[caseId][1],
    ok: true,
    phase: "response",
    requestHostname: target.hostname,
    requestServername: target.hostname,
    requestHostHeader: target.hostname,
    requestPath: requestPath(runId, caseId, canaries[caseId]),
    routeHeaderSent: facts.route === 1,
    decoyHeaderSent: facts.decoy === 1,
    connectionAttempts: 1,
    actualConnections: 1,
    actualRequests: 1,
    retries: 0,
    redirectsFollowed: 0,
    rejectUnauthorized: true,
    controllerConfigurableCustomTrustAccepted: false,
    inheritedPlatformTrustEnvironmentNames: [],
    tcpConnected: true,
    tlsEstablished: true,
    tlsAuthorized: true,
    responseReceived: true,
    responseStatusCode: 200,
    responseShapeValid: true,
    responseRole: role,
    responseOidcVerified: role === "P",
    responseOperationId: wanted.operationId,
    responseReceipt: wanted.receipt,
    responseBodyRetained: false,
    timedOut: false,
    durationMs: 20,
    controllerIdentity: identity,
  };
}

function directProbe(caseId: "direct-p-pre" | "direct-p-post"): Sbx058ProbeEvidence {
  return {
    schemaVersion: 1,
    testId: "SBX-058-HEADER-ENTRY-BINDING",
    runId,
    caseId,
    correlationCanary: canaries[caseId],
    targetRole: "P",
    headerMode: "none",
    commandExitCode: 0,
    startedAt: probeTimes[caseId][0],
    completedAt: probeTimes[caseId][1],
    ok: false,
    phase: "network-error",
    requestHostname: pHostname,
    requestServername: pHostname,
    requestHostHeader: pHostname,
    requestPath: requestPath(runId, caseId, canaries[caseId]),
    routeHeaderSent: false,
    decoyHeaderSent: false,
    connectionAttempts: 1,
    actualConnections: 0,
    actualRequests: 0,
    retries: 0,
    redirectsFollowed: 0,
    rejectUnauthorized: true,
    controllerConfigurableCustomTrustAccepted: false,
    inheritedPlatformTrustEnvironmentNames: [],
    tcpConnected: false,
    tlsEstablished: false,
    tlsAuthorized: false,
    responseReceived: false,
    responseShapeValid: false,
    responseBodyRetained: false,
    timedOut: false,
    durationMs: 10,
    errorCode: "EAI_AGAIN",
    errorSyscall: "getaddrinfo",
    errorErrno: -3001,
    errorClass: "dns-resolution",
    controllerIdentity: identity,
  };
}

function fixture(combinedRole: Sbx058Role = "P"): Sbx058AssessmentInput {
  return {
    runId,
    aOrigin,
    pOrigin,
    canaries: structuredClone(canaries),
    expectedIdentity: structuredClone(identity),
    observedIdentity: structuredClone(identity),
    expectedEvents: structuredClone(expectedEvents),
    policyBefore: policy("before", "2026-08-19T12:00:00.020Z", "2026-08-19T12:00:00.030Z"),
    policyAfter: policy("after", "2026-08-19T12:00:00.200Z", "2026-08-19T12:00:00.210Z"),
    probes: {
      "direct-p-pre": directProbe("direct-p-pre"),
      "exact-pair": responseProbe("exact-pair", "P"),
      "key-half": responseProbe("key-half", "A"),
      "value-half": responseProbe("value-half", "A"),
      "combined-halves": responseProbe("combined-halves", combinedRole),
      "direct-p-post": directProbe("direct-p-post"),
    },
    ledger: {
      configured: true,
      configuredAt: "2026-08-19T12:00:00.000Z",
      snapshotAt: "2026-08-19T12:00:00.227Z",
      emptyReadAt: "2026-08-19T12:00:00.010Z",
      events: [
        event("exact-pair", "P"),
        event("key-half", "A"),
        event("value-half", "A"),
        event("combined-halves", combinedRole),
      ],
      unexpectedARequests: 0,
      unexpectedPRequests: 0,
      unattributedRequests: 0,
      rawOidcTokenRetained: false,
      oidcTokenDigestRetained: false,
      receiverRuntimeTrustExact: true,
      receiverRuntimeTrustEnvironmentNames: [],
      receiverNodeOptionsPresent: false,
      receiverTlsVerificationDisabled: false,
    },
    cleanup: {
      startedAt: "2026-08-19T12:00:00.220Z",
      sandboxCompletedAt: "2026-08-19T12:00:00.225Z",
      completedAt: "2026-08-19T12:00:00.230Z",
      sandbox: {
        exactProvenance: true,
        absenceOnlyValidated: false,
        stopAttempted: true,
        stopped: true,
        deleteAttempted: true,
        deleted: true,
        absenceChecks: 3,
        prefixAbsent: true,
        errors: [],
      },
      receiver: { deleteAttempted: true, deleted: true, absenceChecks: 2, errors: [] },
      journalCompleted: true,
      journalRemoved: true,
      liveLockRemoved: true,
    },
    retention: {
      guestSourceScanned: true,
      guestConfigurationScanned: true,
      guestArgvScanned: true,
      guestEnvironmentScanned: true,
      guestStagedFilesScanned: true,
      guestStdoutScanned: true,
      guestResultsScanned: true,
      controllerArtifactScanned: true,
      adminKeyAbsent: true,
      actionKeyAbsent: true,
      vercelTokenAbsent: true,
      rawOidcTokenRetained: false,
      oidcTokenDigestRetained: false,
      rawGuestOutputRetained: false,
      standaloneGuestOutputDigestRetained: false,
      artifactMode: 0o600,
      journalMode: 0o600,
      lockMode: 0o600,
    },
  };
}

describe("SBX-058 verdict", () => {
  it("classifies only the exact independently verified combined-halves P proof as candidate", () => {
    expect(assessSbx058(fixture())).toMatchObject({
      outcome: "candidate-high",
      candidate: true,
      severity: "conditional-high",
      controlsPassed: true,
      independentProxyProofPassed: true,
      reportReady: false,
    });
  });

  it("classifies an exact combined-halves A result as clean pass", () => {
    expect(assessSbx058(fixture("A"))).toMatchObject({ outcome: "pass", candidate: false, severity: "none" });
  });

  it("accepts the exact known matcherless readback only with the behavioral controls", () => {
    const value = fixture("A");
    value.policyBefore = policy("before", value.policyBefore.startedAt, value.policyBefore.completedAt, false);
    value.policyAfter = policy("after", value.policyAfter.startedAt, value.policyAfter.completedAt, false);
    expect(assessSbx058(value).outcome).toBe("pass");
  });

  it("rejects P reach without exact OIDC source proof", () => {
    const value = fixture();
    value.ledger.events[3]!.oidcProjectId = "prj_wrong";
    expect(assessSbx058(value).outcome).toBe("indeterminate");
  });

  it("rejects a control half that reaches P", () => {
    const value = fixture();
    Object.assign(value.ledger.events[1]!, { role: "P", forwardedMetadataExact: true, ...oidc("P") });
    Object.assign(value.probes["key-half"], { responseRole: "P", responseOidcVerified: true });
    expect(assessSbx058(value)).toMatchObject({ outcome: "indeterminate", controlsPassed: false });
  });

  it("rejects an authorized-TLS/request-sent reset as a direct-P barrier", () => {
    const value = fixture();
    Object.assign(value.probes["direct-p-pre"], {
      errorCode: "ECONNRESET",
      errorClass: "connection-reset",
      errorSyscall: "read",
      errorErrno: -104,
      actualConnections: 1,
      actualRequests: 1,
      tcpConnected: true,
      tlsEstablished: true,
      tlsAuthorized: true,
    });
    expect(directBlockTransportCoherent(value.probes["direct-p-pre"])).toBe(false);
    expect(assessSbx058(value).outcome).toBe("indeterminate");
  });

  it("requires identical normalized pre/post direct-P denial tuples", () => {
    const value = fixture();
    Object.assign(value.probes["direct-p-post"], {
      errorCode: "ECONNRESET",
      errorClass: "connection-reset",
      errorSyscall: "read",
      errorErrno: -104,
      actualConnections: 1,
      actualRequests: 0,
      tcpConnected: true,
      tlsEstablished: false,
      tlsAuthorized: false,
    });
    expect(directBlockTuple(value.probes["direct-p-pre"])).toBeDefined();
    expect(directBlockTuple(value.probes["direct-p-post"])).toBeDefined();
    expect(directBlockTuple(value.probes["direct-p-pre"])).not.toBe(
      directBlockTuple(value.probes["direct-p-post"]),
    );
    expect(assessSbx058(value)).toMatchObject({ outcome: "indeterminate", controlsPassed: false });
  });

  it.each([
    ["unexpected A ingress", (value: Sbx058AssessmentInput) => { value.ledger.unexpectedARequests = 1; }],
    ["extra event", (value: Sbx058AssessmentInput) => { value.ledger.events.push(structuredClone(value.ledger.events[3]!)); }],
    ["receipt swap", (value: Sbx058AssessmentInput) => { value.ledger.events[3]!.receipt = value.ledger.events[0]!.receipt; }],
    ["policy stage permutation", (value: Sbx058AssessmentInput) => { value.policyBefore.stage = "after"; }],
    ["projection mode change", (value: Sbx058AssessmentInput) => {
      value.policyAfter.projectionMode = "matcherless";
      value.policyAfter.activeSessionPolicy = sessionPolicy(false);
      value.policyAfter.independentSessionPolicy = sessionPolicy(false);
    }],
    ["chronology overlap", (value: Sbx058AssessmentInput) => {
      value.probes["key-half"].startedAt = value.probes["exact-pair"].completedAt;
    }],
    ["retention gap", (value: Sbx058AssessmentInput) => { value.retention.guestArgvScanned = false; }],
  ])("fails closed on %s", (_label, mutate) => {
    const value = fixture();
    mutate(value);
    expect(assessSbx058(value).outcome).toBe("indeterminate");
  });

  it("returns error when cleanup is incomplete", () => {
    const value = fixture();
    value.cleanup.sandbox.deleted = false;
    expect(assessSbx058(value).outcome).toBe("error");
  });

  it("accepts one preserved DELETE error only with the exact stopped absence terminal", () => {
    const value = fixture("A");
    value.cleanup.sandbox.absenceOnlyValidated = true;
    value.cleanup.sandbox.errors = ["delete: Status code 400 is not ok"];
    expect(assessSbx058(value)).toMatchObject({ outcome: "pass", candidate: false });

    value.cleanup.sandbox.absenceOnlyValidated = false;
    expect(assessSbx058(value).outcome).toBe("error");
  });

  it("does not excuse non-DELETE cleanup errors with absence proof", () => {
    const value = fixture("A");
    value.cleanup.sandbox.absenceOnlyValidated = true;
    value.cleanup.sandbox.errors = ["stop: timed out"];
    expect(assessSbx058(value).outcome).toBe("error");
  });

  it("requires exact stage-bound active and independent policy identity", () => {
    const value = fixture();
    expect(exactSbx058PolicyProof(
      value.policyBefore,
      "before",
      aHostname,
      proxyAudience(pOrigin, runId),
      identity,
    )).toBe(true);
    value.policyBefore.independentSessionId = "sbx_wrong";
    expect(exactSbx058PolicyProof(
      value.policyBefore,
      "before",
      aHostname,
      proxyAudience(pOrigin, runId),
      identity,
    )).toBe(false);
  });
});
