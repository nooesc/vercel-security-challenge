import { describe, expect, it } from "vitest";
import {
  SBX041_TEST_ID,
  SBX041_PLATFORM_REDACTED_TRANSFORM,
  SBX041_TRANSFORM_HEADER,
  assessSbx041,
  exactTransformPolicy,
  type Sbx041AEvent,
  type Sbx041AssessmentInput,
  type Sbx041BEvent,
  type Sbx041GuestEvidence,
  type Sbx041PolicyProof,
  type Sbx041ProbeMode,
} from "../pocs/SBX-041/verdict.js";

const aHost = "a.trycloudflare.com";
const bHost = "b.trycloudflare.com";
const runId = "run-sbx041";
const transformSha = "a".repeat(64);
const operations = {
  normal: `rs_${"A".repeat(36)}`,
  sniTicket: `rs_${"B".repeat(36)}`,
  sniAttack: `rs_${"C".repeat(36)}`,
  noSniTicket: `rs_${"D".repeat(36)}`,
  noSniAttack: `rs_${"E".repeat(36)}`,
};

function policyValue(value = SBX041_PLATFORM_REDACTED_TRANSFORM) {
  return { allow: { [aHost]: [{ transform: [{ headers: { [SBX041_TRANSFORM_HEADER]: value } }] }] } };
}

function policy(stage: "pre" | "post"): Sbx041PolicyProof {
  return {
    stage,
    initialSessionId: "sbx_same",
    activeSessionId: "sbx_same",
    independentSessionId: "sbx_same",
    activeSandboxPolicy: { allow: [aHost] },
    activeSessionPolicy: policyValue(),
    independentSandboxPolicy: { allow: [aHost] },
    independentSessionPolicy: policyValue(),
    passed: true,
  };
}

function base(mode: Sbx041ProbeMode, caseId: string): Sbx041GuestEvidence {
  return {
    schemaVersion: 1,
    testId: SBX041_TEST_ID,
    caseId,
    mode,
    tlsVersionPinned: "TLSv1.2",
    strictCertificateVerification: true,
    environmentProxyTrust: false,
    rawConfigurationRetained: false,
    rawSessionRetained: false,
    connectionAttempts: 1,
    retryCount: 0,
    totalHttpRequests: 0,
    bTargetRequests: 0,
    bAttackRequests: 0,
    ok: false,
  };
}

function tls(identityHost: string, configuredServername: string | null, reused: boolean) {
  return {
    transportHost: identityHost === aHost ? aHost : aHost,
    identityHost,
    configuredServername,
    authorized: true,
    protocol: "TLSv1.2",
    alpnProtocol: "http/1.1",
    sessionReused: reused,
  };
}

function directBlocked(caseId: string): Sbx041GuestEvidence {
  return { ...base("direct-b", caseId), errorCode: "EAI_AGAIN" };
}

function frontedBlocked(mode: Sbx041ProbeMode, caseId: string): Sbx041GuestEvidence {
  return { ...base(mode, caseId), sessionOffers: 0, freshBConnection: true, errorCode: "ECONNRESET" };
}

function aEvent(caseId: string, kind: "control" | "ticket", operationId: string): Sbx041AEvent {
  return {
    observedAt: "2026-08-19T00:00:00.000Z",
    caseId,
    kind,
    method: "GET",
    requestTarget: `/v1/sbx041/${kind}/${runId}`,
    hostHeaderLines: 1,
    hostHeaderValues: 1,
    hostMatched: true,
    canaryMatched: true,
    transformHeaderLines: 1,
    transformHeaderValues: 1,
    transformHeaderSha256: transformSha,
    transformCommitmentMatched: true,
    responseStatus: 200,
    operationId,
  };
}

function bEvent(caseId: string, operationId: string): Sbx041BEvent {
  return {
    observedAt: "2026-08-19T00:00:01.000Z",
    caseId,
    kind: "action",
    method: "GET",
    requestTarget: `/v1/sbx041/action/${runId}`,
    hostHeaderLines: 1,
    hostHeaderValues: 1,
    hostMatched: true,
    canaryMatched: true,
    transformHeaderLines: 1,
    transformHeaderValues: 1,
    transformHeaderSha256: transformSha,
    transformCommitmentMatched: true,
    responseStatus: 200,
    operationId,
  };
}

function resumed(
  mode: "fronted-sni-resume" | "fronted-nosni-resume",
  operationId: string,
): Sbx041GuestEvidence {
  const configuredServername = mode === "fronted-sni-resume" ? bHost : null;
  return {
    ...base(mode, mode),
    connectionAttempts: 2,
    totalHttpRequests: 2,
    bTargetRequests: 1,
    bAttackRequests: 1,
    ok: true,
    sessionOffers: 1,
    freshBConnection: true,
    aSessionBytes: 1_024,
    aSessionSha256: "b".repeat(64),
    aCertificateValidForB: true,
    bIdentityValidatedAgainstAuthenticatedASessionCertificate: true,
    aTls: tls(aHost, aHost, false),
    bTls: tls(bHost, configuredServername, true),
    aResponse: {
      statusCode: 200,
      bodyBytes: 58,
      operationId: mode === "fronted-sni-resume" ? operations.sniTicket : operations.noSniTicket,
    },
    bResponse: { statusCode: 200, bodyBytes: 58, operationId },
  };
}

function resumeBlocked(mode: "fronted-sni-resume" | "fronted-nosni-resume"): Sbx041GuestEvidence {
  const value = resumed(mode, mode === "fronted-sni-resume" ? operations.sniAttack : operations.noSniAttack);
  value.totalHttpRequests = 1;
  value.bTargetRequests = 0;
  value.bAttackRequests = 0;
  value.ok = false;
  value.errorCode = "EHOSTUNREACH";
  delete value.bTls;
  delete value.bResponse;
  return value;
}

function input(): Sbx041AssessmentInput {
  return {
    runId,
    aHost,
    bHost,
    expectedTransformSha256: transformSha,
    expectedNormalOperationId: operations.normal,
    expectedSniTicketOperationId: operations.sniTicket,
    expectedSniAttackOperationId: operations.sniAttack,
    expectedNoSniTicketOperationId: operations.noSniTicket,
    expectedNoSniAttackOperationId: operations.noSniAttack,
    identityAndScopePassed: true,
    infrastructurePreflightPassed: true,
    policyPre: policy("pre"),
    policyPost: policy("post"),
    directBPre: directBlocked("direct-b-pre"),
    normalA: {
      ...base("normal-a", "normal-a"),
      totalHttpRequests: 1,
      ok: true,
      aTls: tls(aHost, aHost, false),
      response: { statusCode: 200, bodyBytes: 58, operationId: operations.normal },
    },
    sniNoSession: frontedBlocked("fronted-sni-no-session", "fronted-sni-no-session"),
    sniResume: resumed("fronted-sni-resume", operations.sniAttack),
    noSniNoSession: frontedBlocked("fronted-nosni-no-session", "fronted-nosni-no-session"),
    noSniResume: resumeBlocked("fronted-nosni-resume"),
    directBPost: directBlocked("direct-b-post"),
    receiver: {
      configured: true,
      a: [
        aEvent("normal-a", "control", operations.normal),
        aEvent("fronted-sni-resume-ticket", "ticket", operations.sniTicket),
        aEvent("fronted-nosni-resume-ticket", "ticket", operations.noSniTicket),
      ],
      b: [bEvent("fronted-sni-resume-attack", operations.sniAttack)],
    },
    cleanupPassed: true,
  };
}

describe("SBX-041 verdict", () => {
  it("requires the exact A-only transform policy", () => {
    expect(exactTransformPolicy(policyValue("broker"), aHost, "broker")).toBe(true);
    expect(exactTransformPolicy(
      policyValue(),
      aHost,
      SBX041_PLATFORM_REDACTED_TRANSFORM,
    )).toBe(true);
    expect(exactTransformPolicy(
      policyValue("[REDACTED]"),
      aHost,
      SBX041_PLATFORM_REDACTED_TRANSFORM,
    )).toBe(false);
    expect(exactTransformPolicy({ allow: { [aHost]: [] } }, aHost, "broker")).toBe(false);
  });

  it("classifies exact session reuse with A-only credential receipt at B as High", () => {
    expect(assessSbx041(input())).toMatchObject({
      verdict: "candidate-high",
      severity: "high",
      candidate: true,
      controlsPassed: true,
      exactSessionResumptionProof: true,
      exactBrokeredSecretReceipt: true,
      successfulVariants: ["configured-sni-b"],
    });
  });

  it("classifies both attributable session-path blocks as pass", () => {
    const value = input();
    value.sniResume = resumeBlocked("fronted-sni-resume");
    value.receiver.b = [];
    expect(assessSbx041(value)).toMatchObject({ verdict: "pass", severity: "none", controlsPassed: true });
  });

  it("rejects a no-session reach, unsafe identity, or duplicate B action", () => {
    const noSession = input();
    delete noSession.sniNoSession.errorCode;
    noSession.sniNoSession.ok = true;
    noSession.sniNoSession.totalHttpRequests = 1;
    noSession.sniNoSession.bTargetRequests = 1;
    expect(assessSbx041(noSession)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });

    const unsafe = input();
    unsafe.sniResume.aCertificateValidForB = false;
    expect(assessSbx041(unsafe)).toMatchObject({ verdict: "indeterminate", candidate: false });

    const duplicate = input();
    duplicate.receiver.b.push({ ...duplicate.receiver.b[0]! });
    expect(assessSbx041(duplicate)).toMatchObject({ verdict: "indeterminate", candidate: false });
  });
});
