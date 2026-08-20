import { describe, expect, it } from "vitest";
import {
  SBX039_PUBLIC_CASES,
  SBX039_TEST_ID,
  assessSbx039Public,
  deriveSbx039PublicOperationId,
  exactSbx039PolicyReadback,
  type Sbx039PolicyReadback,
  type Sbx039ProbeEvidence,
  type Sbx039PublicAssessmentInput,
  type Sbx039ReceiverStatus,
} from "../pocs/SBX-039/verdict.js";

const key = "v".repeat(64);
const runId = "2d35d023-786d-45c2-9fe4-a5fd537c9291";
const allowedHostname = "a.example.com";
const deniedHostname = "b.example.com";
const deniedIPv4 = "203.0.113.20";
const deniedPort = 3306;
const epoch = "c487dd18-54b2-438d-ac9d-3070e26827f8";

function policy(): Sbx039PolicyReadback {
  return exactSbx039PolicyReadback({
    initialSessionId: "sbx_one",
    activeSessionId: "sbx_one",
    independentSessionId: "sbx_one",
    activeSandboxPolicy: { allow: [allowedHostname] },
    activeSessionPolicy: { allow: [allowedHostname] },
    independentSandboxPolicy: { allow: [allowedHostname] },
    independentSessionPolicy: { allow: [allowedHostname] },
  }, { allowedHostname });
}

function probe(caseId: string, mode: Sbx039ProbeEvidence["mode"], overrides: Partial<Sbx039ProbeEvidence> = {}): Sbx039ProbeEvidence {
  return {
    ok: true,
    phase: "sent",
    mode,
    runId,
    testId: SBX039_TEST_ID,
    caseId,
    endpointRole: mode === "https-control" ? "allowed" : "denied",
    endpointHostname: mode === "https-control" ? allowedHostname : deniedHostname,
    ...(mode === "https-control" ? {} : { pinnedIPv4: deniedIPv4 }),
    pinnedPort: mode === "https-control" ? 443 : deniedPort,
    attemptCount: 1,
    retryCount: 0,
    tcpConnected: true,
    validGreetingReceived: mode.startsWith("mysql-"),
    greetingTagMatched: mode.startsWith("mysql-"),
    sslRequestExact: true,
    sslRequestBytes: mode.startsWith("mysql-") ? 36 : 0,
    clientHelloGenerated: mode !== "raw-public" && mode !== "https-control",
    clientHelloSent: mode !== "raw-public" && mode !== "https-control",
    clientHelloBytes: mode !== "raw-public" && mode !== "https-control" ? 512 : 0,
    explicitSocketWriteCount: mode === "mysql-split-public" ? 2 : 1,
    interWriteDelayMs: mode === "mysql-split-public" ? 250 : 0,
    ...(mode === "https-control" ? {} : { serverNameKind: "public" as const }),
    operatorSecretFileValidated: false,
    receivedResponse: mode === "https-control" || mode.startsWith("mysql-"),
    ...(mode === "https-control" ? { statusCode: 200 } : {}),
    timedOut: false,
    rawConfigurationRetained: false,
    rawServerNameRetained: false,
    rawOperatorSecretRetained: false,
    ...overrides,
  };
}

function receiver(
  caseId: string,
  mode: NonNullable<Sbx039ReceiverStatus["mode"]>,
  operationId?: string,
  overrides: Partial<Sbx039ReceiverStatus> = {},
): Sbx039ReceiverStatus {
  return {
    configured: true,
    runId,
    caseId,
    phase: "public",
    mode,
    connectionCount: operationId ? 1 : 0,
    greetingWriteCount: operationId ? 1 : 0,
    sslRequestCount: mode.startsWith("mysql-") && operationId ? 1 : 0,
    clientHelloCount: operationId ? 1 : 0,
    rawFrameCount: mode === "raw-public" && operationId ? 1 : 0,
    exactPayloadReceiptCount: operationId ? 1 : 0,
    malformedCount: 0,
    ...(operationId ? { operationId, receiptAt: "2026-08-19T03:00:00.000Z" } : {}),
    listenerHostname: deniedHostname,
    listenerIPv4: deniedIPv4,
    listenerPort: deniedPort,
    configurationEpoch: epoch,
    withinConfiguredWindow: true,
    secretCommitmentMatched: false,
    rawInboundStored: false,
    rawServerNameStored: false,
    rawSecretStored: false,
    payloadDigestStored: false,
    ...overrides,
  };
}

function operation(caseId: string): string {
  return deriveSbx039PublicOperationId(key, runId, caseId, "0123456789abcdef0123456789abcdef");
}

function fixture(): Sbx039PublicAssessmentInput {
  const operations = Object.fromEntries(Object.values(SBX039_PUBLIC_CASES).map((caseId) => [caseId, operation(caseId)]));
  return {
    runId,
    allowedHostname,
    deniedHostname,
    deniedIPv4,
    deniedPort,
    identityAndScopePassed: true,
    distinctAddressSetsPassed: true,
    allowAllReadbackPassed: true,
    restrictedReadback: policy(),
    postTargetReadback: policy(),
    outsideCoalesced: probe(SBX039_PUBLIC_CASES.outsideCoalesced, "mysql-coalesced-public"),
    outsideCoalescedReceiver: receiver(SBX039_PUBLIC_CASES.outsideCoalesced, "mysql-coalesced-public", operations[SBX039_PUBLIC_CASES.outsideCoalesced]),
    allowAllDirectTls: probe(SBX039_PUBLIC_CASES.allowAllDirectTls, "direct-tls"),
    allowAllDirectTlsReceiver: receiver(SBX039_PUBLIC_CASES.allowAllDirectTls, "direct-tls", operations[SBX039_PUBLIC_CASES.allowAllDirectTls]),
    allowAllSplit: probe(SBX039_PUBLIC_CASES.allowAllSplit, "mysql-split-public"),
    allowAllSplitReceiver: receiver(SBX039_PUBLIC_CASES.allowAllSplit, "mysql-split-public", operations[SBX039_PUBLIC_CASES.allowAllSplit]),
    allowAllCoalesced: probe(SBX039_PUBLIC_CASES.allowAllCoalesced, "mysql-coalesced-public"),
    allowAllCoalescedReceiver: receiver(SBX039_PUBLIC_CASES.allowAllCoalesced, "mysql-coalesced-public", operations[SBX039_PUBLIC_CASES.allowAllCoalesced]),
    allowedHttps: probe(SBX039_PUBLIC_CASES.allowedHttps, "https-control") as Sbx039PublicAssessmentInput["allowedHttps"],
    deniedDirectTls: probe(SBX039_PUBLIC_CASES.deniedDirectTls, "direct-tls", {
      tcpConnected: false, clientHelloSent: false, receivedResponse: false, errorCode: "EHOSTUNREACH",
    }),
    deniedDirectTlsReceiver: receiver(SBX039_PUBLIC_CASES.deniedDirectTls, "direct-tls"),
    deniedRaw: probe(SBX039_PUBLIC_CASES.deniedRaw, "raw-public", {
      tcpConnected: false, receivedResponse: false, errorCode: "EHOSTUNREACH",
    }),
    deniedRawReceiver: receiver(SBX039_PUBLIC_CASES.deniedRaw, "raw-public"),
    deniedSplit: probe(SBX039_PUBLIC_CASES.deniedSplit, "mysql-split-public"),
    deniedSplitReceiver: receiver(SBX039_PUBLIC_CASES.deniedSplit, "mysql-split-public", undefined, {
      connectionCount: 1, greetingWriteCount: 1, sslRequestCount: 1,
    }),
    deniedCoalesced: probe(SBX039_PUBLIC_CASES.deniedCoalesced, "mysql-coalesced-public"),
    deniedCoalescedReceiver: receiver(SBX039_PUBLIC_CASES.deniedCoalesced, "mysql-coalesced-public", operations[SBX039_PUBLIC_CASES.deniedCoalesced]),
    deniedPostDirectTls: probe(SBX039_PUBLIC_CASES.deniedPostDirectTls, "direct-tls", {
      tcpConnected: false, clientHelloSent: false, receivedResponse: false, errorCode: "EHOSTUNREACH",
    }),
    deniedPostDirectTlsReceiver: receiver(SBX039_PUBLIC_CASES.deniedPostDirectTls, "direct-tls"),
    expectedOperations: operations,
    expectedConfigurationEpoch: epoch,
    cleanupPassed: true,
    retention: {
      rawOperatorSecret: false,
      rawGuestConfiguration: false,
      rawCommandStdout: false,
      rawCommandStderr: false,
      rawClientHello: false,
      rawServerName: false,
      rawSecretInArtifact: false,
      secretDigestInArtifact: false,
    },
  };
}

describe("SBX-039 verdict", () => {
  it("requires exact same-session policy readback", () => {
    expect(policy()).toMatchObject({ exact: true, sameSession: true, passed: true });
    expect(exactSbx039PolicyReadback({
      ...policy(), independentSessionId: "sbx_other",
    }, { allowedHostname })).toMatchObject({ exact: true, sameSession: false, passed: false });
  });

  it("classifies only the isolated coalesced upgrade receipt as candidate-public", () => {
    expect(assessSbx039Public(fixture())).toMatchObject({
      verdict: "candidate-public",
      candidate: true,
      severity: "medium",
      controlsPassed: true,
      variant: "coalesced-upgrade",
    });
  });

  it("classifies a clean fail-closed matrix as pass", () => {
    const input = fixture();
    input.deniedSplit = probe(SBX039_PUBLIC_CASES.deniedSplit, "mysql-split-public", {
      tcpConnected: false, validGreetingReceived: false, greetingTagMatched: false,
      clientHelloGenerated: false, clientHelloSent: false, receivedResponse: false, errorCode: "EHOSTUNREACH",
    });
    input.deniedSplitReceiver = receiver(SBX039_PUBLIC_CASES.deniedSplit, "mysql-split-public");
    input.deniedCoalesced = probe(SBX039_PUBLIC_CASES.deniedCoalesced, "mysql-coalesced-public", {
      tcpConnected: false, validGreetingReceived: false, greetingTagMatched: false,
      clientHelloGenerated: false, clientHelloSent: false, receivedResponse: false, errorCode: "EHOSTUNREACH",
    });
    input.deniedCoalescedReceiver = receiver(SBX039_PUBLIC_CASES.deniedCoalesced, "mysql-coalesced-public");
    expect(assessSbx039Public(input)).toMatchObject({ verdict: "pass", candidate: false, severity: "none" });
  });

  it("rejects a simpler raw forwarding leak as an alternate root", () => {
    const input = fixture();
    input.deniedRawReceiver = receiver(
      SBX039_PUBLIC_CASES.deniedRaw,
      "raw-public",
      operation(SBX039_PUBLIC_CASES.deniedRaw),
    );
    expect(assessSbx039Public(input)).toMatchObject({
      verdict: "alternate-root",
      candidate: false,
      controlsPassed: false,
    });
  });
});
