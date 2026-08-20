import { describe, expect, it } from "vitest";
import {
  SBX038_TEST_ID,
  SBX038_TRANSFORM_HEADER,
  assessSbx038Stage,
  combineSbx038Assessments,
  exactPolicyProof,
  exactTransformPolicy,
  exactTransformProjection,
  type Sbx038GuestEvidence,
  type Sbx038PolicyProof,
  type Sbx038ReceiverSnapshot,
  type Sbx038StageInput,
} from "../pocs/SBX-038/verdict.js";

const aHost = "a.research.test";
const bHost = "b.research.test";
const runId = "run-sbx038-verdict";
const transformCommitment = "a".repeat(64);
const aOperation = `cx_${"A".repeat(32)}`;
const publicOperation = `cx_${"B".repeat(32)}`;
const secretOperation = `cx_${"C".repeat(32)}`;

function transformPolicy(value = "[REDACTED]") {
  return { allow: { [aHost]: [{ transform: [{ headers: { [SBX038_TRANSFORM_HEADER]: value } }] }] } };
}

function policy(stage: "pre" | "post", overrides: Partial<Sbx038PolicyProof> = {}): Sbx038PolicyProof {
  return {
    stage,
    initialSessionId: "sbx_same",
    activeSessionId: "sbx_same",
    independentSessionId: "sbx_same",
    activeSandboxPolicy: { allow: [aHost] },
    activeSessionPolicy: transformPolicy(),
    independentSandboxPolicy: { allow: [aHost] },
    independentSessionPolicy: transformPolicy(),
    passed: true,
    ...overrides,
  };
}

function tls(host: string) {
  return { servername: host, authorized: true, protocol: "TLSv1.3", remoteAddress: "203.0.113.1", remotePort: 443 };
}

function baseGuest(mode: Sbx038GuestEvidence["mode"], caseId: string, outerHost = aHost): Sbx038GuestEvidence {
  const connect = mode.startsWith("connect-");
  return {
    schemaVersion: 1,
    testId: SBX038_TEST_ID,
    runId,
    caseId,
    mode,
    outerHost,
    outerPort: 443,
    connectionAttempts: 1,
    retryCount: 0,
    maximumRequests: connect ? 2 : 1,
    actualRequests: mode === "direct-b" ? 0 : connect ? 1 : 1,
    strictCertificateVerification: true,
    environmentProxyTrust: false,
    trustEnvironmentNames: [],
    trustEnvironmentScanComplete: true,
    trustOverridesForbidden: true,
    rawConfigurationRetained: false,
    rawSecretRetained: false,
    secretDigestRetained: false,
    ok: false,
    startedAt: "2026-08-19T00:00:20.000Z",
    completedAt: "2026-08-19T00:00:21.000Z",
  };
}

function blocked(caseId: string): Sbx038GuestEvidence {
  return {
    ...baseGuest("direct-b", caseId, bHost),
    errorCode: "EAI_AGAIN",
    errorSyscall: "getaddrinfo",
    errorErrno: -3001,
  };
}

function normal(caseId: string): Sbx038GuestEvidence {
  return {
    ...baseGuest("normal-a", caseId), ok: true, outerTls: tls(aHost),
    outerResponse: { statusCode: 200, operationId: aOperation, bodyBytes: 57 },
  };
}

function connectA(caseId: string): Sbx038GuestEvidence {
  return {
    ...baseGuest("connect-a", caseId),
    outerTls: tls(aHost),
    targetHost: aHost,
    targetPort: 443,
    connectAuthority: `${aHost}:443`,
    connectHostHeader: aHost,
    tunnelEstablished: false,
    connectResponse: { statusCode: 405, terminalConnectHeader: true, bodyBytes: 0 },
  };
}

function connectB(caseId: string, stage: "public" | "secret"): Sbx038GuestEvidence {
  return {
    ...baseGuest(stage === "public" ? "connect-b-public" : "connect-b-secret", caseId),
    ok: true,
    actualRequests: 2,
    outerTls: tls(aHost),
    targetHost: bHost,
    targetPort: 443,
    connectAuthority: `${bHost}:443`,
    connectHostHeader: aHost,
    connectResponse: { statusCode: 200, terminalConnectHeader: false, bodyBytes: 0 },
    tunnelEstablished: true,
    nestedTls: tls(bHost),
    nestedResponse: { statusCode: 200, operationId: stage === "public" ? publicOperation : secretOperation, bodyBytes: 57 },
    ...(stage === "secret" ? { secretFileValidated: true, secretFileMode: 0o600, secretBytes: 64 } : {}),
  };
}

function receiver(stage: "public" | "secret", attackAtA = false): Sbx038ReceiverSnapshot {
  const prefix = stage;
  const attackCase = stage === "public" ? "public-connect-b" : "secret-connect-b";
  const base = stage === "public" ? 1 : 4;
  return {
    configured: true,
    nextSequence: base + 3,
    unexpected: [],
    infrastructureConnect: [{
      sequence: 1,
      observedAt: "2026-08-19T00:00:01.500Z",
      caseId: `infrastructure-connect-a-${runId.slice(0, 8)}`,
      requestTarget: `${aHost}:443`,
      hostHeader: aHost,
      transformHeaderLines: 0,
      transformHeaderValues: 0,
      transformCommitmentMatched: false,
      terminalResponseStatus: 405,
      openedOutboundConnection: false,
    }],
    secretRegistered: stage === "secret",
    aHttp: [{
      sequence: base + 1,
      observedAt: "2026-08-19T00:00:00.000Z",
      caseId: `${prefix}-normal-a`,
      method: "GET",
      requestTarget: `/v1/sbx038/control/${runId}`,
      transformHeaderLines: 1,
      transformHeaderValues: 1,
      transformHeaderCommitment: transformCommitment,
      transformCommitmentMatched: true,
      responseStatus: 200,
      operationId: aOperation,
    }],
    aConnect: [{
      sequence: base + 2,
      observedAt: "2026-08-19T00:00:01.000Z",
      caseId: `${prefix}-connect-a`,
      requestTarget: `${aHost}:443`,
      hostHeader: aHost,
      transformHeaderLines: 1,
      transformHeaderValues: 1,
      transformHeaderCommitment: transformCommitment,
      transformCommitmentMatched: true,
      terminalResponseStatus: 405,
      openedOutboundConnection: false,
    }, ...(attackAtA ? [{
      sequence: base + 3,
      observedAt: "2026-08-19T00:00:02.000Z",
      caseId: attackCase,
      requestTarget: `${bHost}:443`,
      hostHeader: aHost,
      transformHeaderLines: 1,
      transformHeaderValues: 1,
      transformHeaderCommitment: transformCommitment,
      transformCommitmentMatched: true,
      terminalResponseStatus: 405 as const,
      openedOutboundConnection: false as const,
    }] : [])],
    b: attackAtA ? [] : [{
      sequence: base + 3,
      observedAt: "2026-08-19T00:00:03.000Z",
      caseId: attackCase,
      stage,
      method: stage === "public" ? "GET" : "POST",
      requestTarget: `/v1/sbx038/action/${runId}`,
      hostHeaderLines: 1,
      hostHeaderValues: 1,
      hostHeaderMatched: true,
      tlsTerminatedLocally: true,
      tlsServername: bHost,
      canaryMatched: true,
      secretCommitmentMatched: stage === "secret",
      bodyBytes: stage === "public" ? 0 : 64,
      rawBodyRetained: false,
      operationId: stage === "public" ? publicOperation : secretOperation,
    }],
  };
}

function chronology(stage: "public" | "secret") {
  const attackCase = stage === "public" ? "public-connect-b" : "secret-connect-b";
  const base = stage === "public" ? 1 : 4;
  const cases = [
    `${stage}-direct-b-pre`, `${stage}-normal-a`, `${stage}-connect-a`, attackCase, `${stage}-direct-b-post`,
  ];
  const sequenceBounds = [
    [base, base], [base, base + 1], [base + 1, base + 2], [base + 2, base + 3], [base + 3, base + 3],
  ];
  return {
    receiverConfiguredAt: "2026-08-19T00:00:00.000Z",
    infrastructurePreflight: {
      caseId: `infrastructure-connect-a-${runId.slice(0, 8)}`,
      startedAt: "2026-08-19T00:00:01.000Z",
      completedAt: "2026-08-19T00:00:02.000Z",
      receiverSequenceBefore: 0,
      receiverSequenceAfter: 1,
    },
    policyPreCompletedAt: "2026-08-19T00:00:03.000Z",
    probes: cases.map((caseId, index) => ({
      caseId,
      startedAt: `2026-08-19T00:00:${String(4 + index * 2).padStart(2, "0")}.000Z`,
      completedAt: `2026-08-19T00:00:${String(5 + index * 2).padStart(2, "0")}.000Z`,
      receiverSequenceBefore: sequenceBounds[index]![0]!,
      receiverSequenceAfter: sequenceBounds[index]![1]!,
    })),
    policyPostCompletedAt: "2026-08-19T00:00:14.000Z",
    receiverReadAt: "2026-08-19T00:00:15.000Z",
    cleanupCompletedAt: "2026-08-19T00:00:16.000Z",
  };
}

function input(stage: "public" | "secret", overrides: Partial<Sbx038StageInput> = {}): Sbx038StageInput {
  return {
    stage,
    runId,
    aHost,
    bHost,
    expectedTransformCommitment: transformCommitment,
    expectedAOperationId: aOperation,
    expectedBOperationId: stage === "public" ? publicOperation : secretOperation,
    identityAndScopePassed: true,
    infrastructurePreflightPassed: true,
    policyPre: policy("pre"),
    policyPost: policy("post"),
    directBPre: blocked(`${stage}-direct-b-pre`),
    normalA: normal(`${stage}-normal-a`),
    connectA: connectA(`${stage}-connect-a`),
    connectB: connectB(stage === "public" ? "public-connect-b" : "secret-connect-b", stage),
    directBPost: blocked(`${stage}-direct-b-post`),
    receiver: receiver(stage),
    bTransportProof: {
      mode: "receiver-local",
      host: bHost,
      port: 443,
      tls: tls(bHost),
      healthStatus: 200,
      healthServiceMatched: true,
      completedAt: "2026-08-18T23:59:59.000Z",
    },
    chronology: chronology(stage),
    cleanupPassed: true,
    ...overrides,
  };
}

describe("SBX-038 verdict", () => {
  it("requires exact transform policy and active/independent same-session projections", () => {
    expect(exactTransformPolicy(transformPolicy("broker"), aHost, "broker")).toBe(true);
    expect(exactTransformProjection({ allow: [aHost] }, aHost)).toBe(true);
    expect(exactPolicyProof(policy("pre"), aHost, "[REDACTED]", "sbx_same")).toBe(true);
    expect(exactTransformPolicy({ allow: { [aHost]: [] } }, aHost, "broker")).toBe(false);
    expect(exactPolicyProof(policy("pre", { independentSessionId: "sbx_other" }), aHost, "[REDACTED]", "sbx_same")).toBe(false);
  });

  it("classifies B-only nested verified public action as Medium", () => {
    expect(assessSbx038Stage(input("public"))).toMatchObject({
      verdict: "candidate-medium",
      severity: "medium",
      candidate: true,
      controlsPassed: true,
      publicTunnelProofValid: true,
      secretReceiptProofValid: false,
    });
  });

  it("accepts an exact public-edge TLS proof and rejects forged termination-mode combinations", () => {
    const publicEdge = input("public");
    publicEdge.bTransportProof.mode = "public-edge";
    publicEdge.receiver.b[0]!.tlsTerminatedLocally = false;
    delete publicEdge.receiver.b[0]!.tlsServername;
    expect(assessSbx038Stage(publicEdge)).toMatchObject({ verdict: "candidate-medium", candidate: true });

    const forgedMode = input("public");
    forgedMode.bTransportProof.mode = "public-edge";
    expect(assessSbx038Stage(forgedMode)).toMatchObject({ verdict: "indeterminate", candidate: false });

    const forgedTls = input("public");
    forgedTls.bTransportProof.tls = { ...tls("other.research.test"), authorized: true };
    expect(assessSbx038Stage(forgedTls)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
  });

  it("classifies exact mode-0600 commitment-backed secret receipt as High", () => {
    const assessment = assessSbx038Stage(input("secret"));
    expect(assessment).toMatchObject({
      verdict: "candidate-high",
      severity: "high",
      candidate: true,
      controlsPassed: true,
      secretReceiptProofValid: true,
    });
    expect(combineSbx038Assessments(assessSbx038Stage(input("public")), assessment, {
      public: { name: "sbx-038-public", sessionId: "sbx_public" },
      secret: { name: "sbx-038-secret", sessionId: "sbx_secret" },
    })).toMatchObject({
      verdict: "candidate-high",
      publicTunnelProofValid: true,
      secretReceiptProofValid: true,
    });
  });

  it("passes when the terminal A sink receives the mismatched CONNECT and B sees nothing", () => {
    const connect = connectB("public-connect-b", "public");
    connect.ok = false;
    connect.actualRequests = 1;
    connect.tunnelEstablished = false;
    connect.connectResponse = { statusCode: 405, terminalConnectHeader: true, bodyBytes: 0 };
    delete connect.nestedTls;
    delete connect.nestedResponse;
    expect(assessSbx038Stage(input("public", {
      connectB: connect,
      receiver: receiver("public", true),
    }))).toMatchObject({ verdict: "pass", severity: "none", controlsPassed: true });
  });

  it("does not call an unattributed HTTP rejection a clean pass", () => {
    const connect = connectB("public-connect-b", "public");
    connect.ok = false;
    connect.actualRequests = 1;
    connect.tunnelEstablished = false;
    connect.connectResponse = { statusCode: 403, terminalConnectHeader: false, bodyBytes: 0 };
    delete connect.nestedTls;
    delete connect.nestedResponse;
    const emptyAttackReceiver = receiver("public", true);
    emptyAttackReceiver.aConnect.pop();
    emptyAttackReceiver.nextSequence = 3;
    const times = chronology("public");
    times.probes[3]!.receiverSequenceAfter = 3;
    times.probes[4]!.receiverSequenceBefore = 3;
    times.probes[4]!.receiverSequenceAfter = 3;
    expect(assessSbx038Stage(input("public", {
      connectB: connect,
      receiver: emptyAttackReceiver,
      chronology: times,
    }))).toMatchObject({ verdict: "indeterminate", candidate: false });
  });

  it("fails closed on unexpected ingress, chronology drift, trust overrides, and incomplete B TLS/Host proof", () => {
    const unexpected = input("public");
    unexpected.receiver.unexpected.push({
      sequence: 5,
      observedAt: "2026-08-19T00:00:10.500Z",
      role: "b",
      attribution: "run-header",
      reason: "wrong-path",
      method: "GET",
    });
    expect(assessSbx038Stage(unexpected)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });

    const reordered = input("public");
    reordered.chronology.probes[3]!.startedAt = reordered.chronology.probes[2]!.completedAt;
    expect(assessSbx038Stage(reordered)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });

    const override = input("public");
    override.connectB.trustOverridesForbidden = false;
    expect(assessSbx038Stage(override)).toMatchObject({ verdict: "indeterminate", candidate: false });

    const missingTls = input("public");
    missingTls.receiver.b[0]!.tlsTerminatedLocally = false;
    delete missingTls.receiver.b[0]!.tlsServername;
    expect(assessSbx038Stage(missingTls)).toMatchObject({ verdict: "indeterminate", candidate: false });
  });

  it("refuses severity when cleanup, direct blocks, or exact secret proof is missing", () => {
    expect(assessSbx038Stage(input("public", { cleanupPassed: false }))).toMatchObject({ verdict: "error" });
    expect(assessSbx038Stage(input("public", {
      directBPost: { ...blocked("public-direct-b-post"), outerTls: tls(bHost) },
    }))).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
    const weakSecret = input("secret");
    weakSecret.connectB = { ...weakSecret.connectB, secretFileMode: 0o644 };
    expect(assessSbx038Stage(weakSecret)).toMatchObject({ verdict: "indeterminate", candidate: false });
  });

  it("rejects refused, timed-out, and reset direct-B failures as non-attributable infrastructure signals", () => {
    for (const errorCode of ["ECONNREFUSED", "ETIMEDOUT", "ECONNRESET"]) {
      expect(assessSbx038Stage(input("public", {
        directBPre: { ...blocked("public-direct-b-pre"), errorCode },
      }))).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
    }
  });

  it("requires exact matching pre/post direct-B diagnostic tuples and bounded preconnect duration", () => {
    const missingSyscall = blocked("public-direct-b-pre");
    delete missingSyscall.errorSyscall;
    const missingErrno = blocked("public-direct-b-pre");
    delete missingErrno.errorErrno;
    for (const directBPre of [
      missingSyscall,
      { ...blocked("public-direct-b-pre"), errorSyscall: "connect" },
      missingErrno,
      { ...blocked("public-direct-b-pre"), errorErrno: -3002 },
      { ...blocked("public-direct-b-pre"), completedAt: "2026-08-19T00:00:29.000Z" },
    ]) {
      expect(assessSbx038Stage(input("public", { directBPre }))).toMatchObject({
        verdict: "indeterminate",
        controlsPassed: false,
      });
    }
    expect(assessSbx038Stage(input("public", {
      directBPost: {
        ...blocked("public-direct-b-post"),
        errorCode: "EHOSTUNREACH",
        errorSyscall: "connect",
        errorErrno: -113,
      },
    }))).toMatchObject({ verdict: "indeterminate", controlsPassed: false });

    const hostUnreachable = input("public");
    hostUnreachable.directBPre = {
      ...blocked("public-direct-b-pre"), errorCode: "EHOSTUNREACH", errorSyscall: "connect", errorErrno: -113,
    };
    hostUnreachable.directBPost = {
      ...blocked("public-direct-b-post"), errorCode: "EHOSTUNREACH", errorSyscall: "connect", errorErrno: -113,
    };
    expect(assessSbx038Stage(hostUnreachable)).toMatchObject({ verdict: "candidate-medium", controlsPassed: true });
  });

  it("rejects a hidden cross-stage receiver event inside a probe sequence delta", () => {
    const evidence = input("secret");
    evidence.receiver.aHttp[0]!.sequence += 1;
    evidence.receiver.aConnect[0]!.sequence += 1;
    evidence.receiver.b[0]!.sequence += 1;
    evidence.receiver.nextSequence += 1;
    for (let index = 1; index < evidence.chronology.probes.length; index += 1) {
      evidence.chronology.probes[index]!.receiverSequenceAfter += 1;
      if (index > 1) evidence.chronology.probes[index]!.receiverSequenceBefore += 1;
    }
    expect(assessSbx038Stage(evidence)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
  });

  it("withholds High when public and secret stages are not proven to be distinct sandboxes and sessions", () => {
    const publicAssessment = assessSbx038Stage(input("public"));
    const secretAssessment = assessSbx038Stage(input("secret"));
    expect(combineSbx038Assessments(publicAssessment, secretAssessment)).toMatchObject({
      verdict: "candidate-medium",
      severity: "medium",
      publicTunnelProofValid: true,
      secretReceiptProofValid: false,
    });
    expect(combineSbx038Assessments(publicAssessment, secretAssessment, {
      public: { name: "sbx-public", sessionId: "sbx_same" },
      secret: { name: "sbx-secret", sessionId: "sbx_same" },
    })).toMatchObject({ verdict: "candidate-medium", severity: "medium" });
  });
});
