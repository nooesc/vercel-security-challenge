import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  SBX046_CANARY_PATH,
  SBX046_CASE_IDS,
  SBX046_PORT,
  SBX046_TEST_ID,
  assertSbx046EvidenceExcludesRawValues,
  assessSbx046,
  deriveSbx046OperationId,
  exactConclusiveRouteDenial,
  type Sbx046AssessmentInput,
  type Sbx046CaseId,
  type Sbx046LedgerEvent,
  type Sbx046ProbeEvidence,
  type Sbx046ReadbackSource,
  type Sbx046ReadbackStage,
  type Sbx046RouteReadback,
} from "../pocs/SBX-046/verdict.js";

const runId = "12345678-1234-4123-8123-123456789abc";
const sandboxName = "sbx-046-test-12345678";
const sessionId = "sbx_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234";
const serviceInstanceId = `svc46_${"S".repeat(24)}`;
const route = {
  url: "https://sbx046owned.vercel.run",
  subdomain: "sbx046owned",
  port: SBX046_PORT,
};
const tags = { harness: "vsc", test: SBX046_TEST_ID, run: runId, role: "revocation" };
const caseCharacters: Record<Sbx046CaseId, string> = {
  "local-pre": "A",
  "external-pre": "B",
  "local-post-readback": "C",
  "external-post-5s": "D",
  "external-post-30s": "E",
  "external-post-90s": "F",
  "local-post-final": "G",
};
const challenges = Object.fromEntries(SBX046_CASE_IDS.map((caseId) =>
  [caseId, `ch46_${caseCharacters[caseId].repeat(24)}`])) as Record<Sbx046CaseId, string>;
const operationIds = Object.fromEntries(SBX046_CASE_IDS.map((caseId) =>
  [caseId, `op46_${caseCharacters[caseId].repeat(43)}`])) as Record<Sbx046CaseId, string>;
const epoch = Date.parse("2026-08-19T12:00:00.000Z");

function at(milliseconds: number): string {
  return new Date(epoch + milliseconds).toISOString();
}

function readback(
  stage: Sbx046ReadbackStage,
  source: Sbx046ReadbackSource,
  milliseconds: number,
): Sbx046RouteReadback {
  const initial = stage === "initial";
  return {
    stage,
    source,
    observedAt: at(milliseconds),
    sandboxName,
    sessionId,
    persistent: false,
    status: "running",
    tags: { ...tags },
    routes: initial ? [{ ...route }] : [],
    domainPort: SBX046_PORT,
    domainValue: initial ? route.url : null,
    domainLookupThrew: !initial,
  };
}

function timing(caseId: Sbx046CaseId): {
  started: number;
  completed: number;
  elapsed: number | null;
} {
  switch (caseId) {
    case "local-pre": return { started: 5_000, completed: 6_000, elapsed: null };
    case "external-pre": return { started: 7_000, completed: 8_000, elapsed: null };
    case "local-post-readback": return { started: 13_000, completed: 14_000, elapsed: 3_000 };
    case "external-post-5s": return { started: 15_000, completed: 16_000, elapsed: 5_000 };
    case "external-post-30s": return { started: 40_000, completed: 41_000, elapsed: 30_000 };
    case "external-post-90s": return { started: 100_000, completed: 101_000, elapsed: 90_000 };
    case "local-post-final": return { started: 104_000, completed: 105_000, elapsed: 94_000 };
  }
}

function exactReachProbe(caseId: Sbx046CaseId): Sbx046ProbeEvidence {
  const local = caseId.startsWith("local-");
  const value = timing(caseId);
  return {
    schemaVersion: 1,
    testId: SBX046_TEST_ID,
    runId,
    caseId,
    origin: local ? "loopback" : "saved-public-route",
    sandboxName,
    sessionId,
    port: SBX046_PORT,
    serviceInstanceId,
    challenge: challenges[caseId],
    expectedOperationId: operationIds[caseId],
    requestMethod: "POST",
    requestPath: SBX046_CANARY_PATH,
    requestOrigin: local ? `http://127.0.0.1:${SBX046_PORT}` : route.url,
    startedAt: at(value.started),
    completedAt: at(value.completed),
    elapsedSinceRevocationAckMs: value.elapsed,
    requestAttempts: 1,
    connectionAttempts: 1,
    actualRequests: 1,
    retries: 0,
    redirectsFollowed: 0,
    freshConnection: true,
    strictTlsVerification: !local,
    proxyConfigurationAccepted: false,
    tlsTrustConfigurationAccepted: false,
    rawConfigurationRetained: false,
    tcpConnected: true,
    tlsEstablished: !local,
    tlsAuthorized: !local,
    responseReceived: true,
    responseStatusCode: 200,
    responseBytes: 384,
    serviceHeaderValidated: true,
    cacheControlValidated: true,
    connectionCloseValidated: true,
    contentTypeValidated: true,
    contentLengthValidated: true,
    serviceResponse: {
      schemaVersion: 1,
      testId: SBX046_TEST_ID,
      runId,
      caseId,
      sandboxName,
      sessionId,
      port: SBX046_PORT,
      serviceInstanceId,
      challenge: challenges[caseId],
      operationId: operationIds[caseId],
      requestBodyValidated: true,
      ok: true,
    },
    timedOut: false,
    durationMs: 1_000,
    rawRequestBodyRetained: false,
    rawResponseBodyRetained: false,
  };
}

function ledgerEvent(caseId: Sbx046CaseId): Sbx046LedgerEvent {
  const value = timing(caseId);
  return {
    schemaVersion: 1,
    testId: SBX046_TEST_ID,
    runId,
    sandboxName,
    sessionId,
    port: SBX046_PORT,
    serviceInstanceId,
    caseId,
    challenge: challenges[caseId],
    operationId: operationIds[caseId],
    observedAt: at(value.started + 500),
    method: "POST",
    path: SBX046_CANARY_PATH,
    requestBodyValidated: true,
    rawHmacKeyRetained: false,
    rawRequestBodyRetained: false,
    derivedDigestRetained: false,
  };
}

function validInput(): Sbx046AssessmentInput {
  return {
    identityAndScopePassed: true,
    expected: {
      runId,
      sandboxName,
      sessionId,
      tags: { ...tags },
      route: { ...route },
      serviceInstanceId,
      challenges: { ...challenges },
      operationIds: { ...operationIds },
    },
    creation: {
      attempts: 1,
      requestedAt: at(0),
      createdAt: at(1_000),
      completedAt: at(2_000),
      sandboxName,
      sessionId,
      persistent: false,
      status: "running",
      tags: { ...tags },
      routes: [{ ...route }],
      sourceSnapshotId: null,
    },
    initialReadbacks: {
      active: readback("initial", "active", 3_000),
      independent: readback("initial", "independent", 4_000),
    },
    update: {
      method: "Sandbox.update",
      attempts: 1,
      requestedPorts: [],
      requestedAt: at(9_000),
      acknowledgedAt: at(10_000),
      acknowledged: true,
      sandboxName,
      sessionIdBefore: sessionId,
      sessionIdAfter: sessionId,
      responseRoutes: [],
    },
    postUpdateReadbacks: {
      active: readback("post-update", "active", 11_000),
      independent: readback("post-update", "independent", 12_000),
    },
    finalReadbacks: {
      active: readback("final", "active", 102_000),
      independent: readback("final", "independent", 103_000),
    },
    probes: Object.fromEntries(SBX046_CASE_IDS.map((caseId) =>
      [caseId, exactReachProbe(caseId)])) as Record<Sbx046CaseId, Sbx046ProbeEvidence>,
    ledger: {
      configured: true,
      events: SBX046_CASE_IDS.map(ledgerEvent),
      rawHmacKeyRetained: false,
      hmacKeyDigestRetained: false,
      rawLogRetained: false,
    },
    cleanup: {
      stopAttempted: true,
      stopped: true,
      deleteAttempted: true,
      deleted: true,
      absenceChecks: 3,
      exactNameAbsent: true,
      prefixListAbsent: true,
      guestConfigDeleted: true,
      guestLedgerDeleted: true,
      errors: [],
    },
    storage: {
      guestConfigMode: 0o600,
      guestLedgerMode: 0o600,
      artifactMode: 0o600,
      liveLockMode: 0o600,
      liveLockReleased: true,
      rawHmacKeyRetained: false,
      hmacKeyDigestRetained: false,
      rawRequestBodyRetained: false,
      rawResponseBodyRetained: false,
    },
  };
}

function deniedProbe(
  caseId: "external-post-5s" | "external-post-30s" | "external-post-90s",
  kind: "dns" | "http",
): Sbx046ProbeEvidence {
  const probe = exactReachProbe(caseId);
  delete probe.serviceResponse;
  delete probe.responseBytes;
  delete probe.serviceHeaderValidated;
  delete probe.cacheControlValidated;
  delete probe.connectionCloseValidated;
  delete probe.contentTypeValidated;
  delete probe.contentLengthValidated;
  probe.tcpConnected = kind === "http";
  probe.tlsEstablished = kind === "http";
  probe.tlsAuthorized = kind === "http";
  probe.responseReceived = kind === "http";
  if (kind === "dns") {
    delete probe.responseStatusCode;
    probe.error = { code: "ENOTFOUND", syscall: "getaddrinfo", errno: -3_008 };
  } else {
    probe.responseStatusCode = caseId === "external-post-90s" ? 410 : 404;
  }
  return probe;
}

function passInput(): Sbx046AssessmentInput {
  const input = validInput();
  input.probes["external-post-5s"] = deniedProbe("external-post-5s", "dns");
  input.probes["external-post-30s"] = deniedProbe("external-post-30s", "http");
  input.probes["external-post-90s"] = deniedProbe("external-post-90s", "http");
  input.ledger.events = input.ledger.events.filter((event) => !event.caseId.startsWith("external-post-"));
  return input;
}

describe("SBX-046 published-port revocation verdict", () => {
  it("classifies only sustained +5s/+30s/+90s exact same-service reach as Low", () => {
    expect(assessSbx046(validInput())).toMatchObject({
      verdict: "candidate-low",
      severity: "low",
      candidate: true,
      controlsPassed: true,
      sustainedRevocationFailure: true,
      postProbeClassifications: {
        "external-post-5s": "exact-reach",
        "external-post-30s": "exact-reach",
        "external-post-90s": "exact-reach",
      },
    });
  });

  it("passes only when every post-revocation probe is a terminal denial with zero events", () => {
    const input = passInput();
    expect(exactConclusiveRouteDenial(input, "external-post-5s")).toBe(true);
    expect(exactConclusiveRouteDenial(input, "external-post-30s")).toBe(true);
    expect(exactConclusiveRouteDenial(input, "external-post-90s")).toBe(true);
    expect(assessSbx046(input)).toMatchObject({
      verdict: "pass",
      severity: "none",
      candidate: false,
      controlsPassed: true,
      postProbeClassifications: {
        "external-post-5s": "conclusive-denial",
        "external-post-30s": "conclusive-denial",
        "external-post-90s": "conclusive-denial",
      },
    });
  });

  it("keeps immediate-only and every reach/deny mixture indeterminate", () => {
    const immediateOnly = passInput();
    immediateOnly.probes["external-post-5s"] = exactReachProbe("external-post-5s");
    immediateOnly.ledger.events.push(ledgerEvent("external-post-5s"));
    expect(assessSbx046(immediateOnly)).toMatchObject({
      verdict: "indeterminate",
      candidate: false,
      controlsPassed: true,
    });

    const lateOnly = passInput();
    lateOnly.probes["external-post-90s"] = exactReachProbe("external-post-90s");
    lateOnly.ledger.events.push(ledgerEvent("external-post-90s"));
    expect(assessSbx046(lateOnly)).toMatchObject({ verdict: "indeterminate", candidate: false });
  });

  it("treats EAI_AGAIN, timeouts, TLS errors, resets, and refusals as ambiguous", () => {
    for (const error of [
      { code: "EAI_AGAIN", syscall: "getaddrinfo", errno: -3_001 },
      { code: "ECONNRESET", syscall: "read", errno: -54 },
      { code: "ECONNREFUSED", syscall: "connect", errno: -61 },
      { code: "CERT_HAS_EXPIRED", syscall: "tls" },
    ]) {
      const input = passInput();
      const probe = deniedProbe("external-post-30s", "dns");
      probe.error = error;
      input.probes["external-post-30s"] = probe;
      expect(assessSbx046(input).postProbeClassifications["external-post-30s"]).toBe("ambiguous");
      expect(assessSbx046(input).verdict).toBe("indeterminate");
    }
    const timeout = passInput();
    timeout.probes["external-post-30s"] = deniedProbe("external-post-30s", "dns");
    timeout.probes["external-post-30s"].timedOut = true;
    expect(assessSbx046(timeout)).toMatchObject({ verdict: "indeterminate", candidate: false });
  });

  it("does not accept an HTTP error that still carries the canary service marker as route withdrawal", () => {
    const input = passInput();
    input.probes["external-post-30s"].serviceHeaderValidated = true;
    expect(exactConclusiveRouteDenial(input, "external-post-30s")).toBe(false);
    expect(assessSbx046(input)).toMatchObject({ verdict: "indeterminate", candidate: false });
  });

  it("keeps all-502 and all-503 edge responses indeterminate", () => {
    for (const statusCode of [502, 503]) {
      const input = validInput();
      for (const caseId of ["external-post-5s", "external-post-30s", "external-post-90s"] as const) {
        input.probes[caseId] = deniedProbe(caseId, "http");
        input.probes[caseId].responseStatusCode = statusCode;
      }
      input.ledger.events = input.ledger.events.filter((event) => !event.caseId.startsWith("external-post-"));
      expect(assessSbx046(input)).toMatchObject({
        verdict: "indeterminate",
        candidate: false,
        controlsPassed: true,
        postProbeClassifications: {
          "external-post-5s": "ambiguous",
          "external-post-30s": "ambiguous",
          "external-post-90s": "ambiguous",
        },
      });
    }
  });

  it("rejects response/event disagreement and duplicate events", () => {
    const responseOnly = validInput();
    responseOnly.ledger.events = responseOnly.ledger.events.filter((event) => event.caseId !== "external-post-30s");
    expect(assessSbx046(responseOnly).postProbeClassifications["external-post-30s"]).toBe("ambiguous");

    const eventOnly = passInput();
    eventOnly.ledger.events.push(ledgerEvent("external-post-30s"));
    expect(assessSbx046(eventOnly).postProbeClassifications["external-post-30s"]).toBe("ambiguous");

    const duplicate = validInput();
    duplicate.ledger.events.push({ ...ledgerEvent("external-post-90s") });
    expect(assessSbx046(duplicate).postProbeClassifications["external-post-90s"]).toBe("ambiguous");
    expect(assessSbx046(duplicate)).toMatchObject({ verdict: "indeterminate", candidate: false });
  });

  it("withholds a finding for wrong identity, session, tags, route, or service instance", () => {
    const mutations: Array<(input: Sbx046AssessmentInput) => void> = [
      (input) => { input.initialReadbacks.independent.sessionId = `${sessionId}X`; },
      (input) => { input.postUpdateReadbacks.active.tags.run = "wrong"; },
      (input) => { input.finalReadbacks.independent.sandboxName = "other-sandbox"; },
      (input) => { input.creation.routes[0]!.subdomain = "other"; },
      (input) => { input.probes["local-post-final"].serviceInstanceId = `svc46_${"Z".repeat(24)}`; },
      (input) => { input.probes["external-post-90s"].requestOrigin = "https://other.vercel.run"; },
      (input) => { input.ledger.events.find((event) => event.caseId === "external-post-90s")!.sessionId = `${sessionId}X`; },
    ];
    for (const mutate of mutations) {
      const input = validInput();
      mutate(input);
      expect(assessSbx046(input)).toMatchObject({ verdict: "indeterminate", candidate: false });
    }
  });

  it("requires active and independent route removal plus domain() failure", () => {
    for (const mutate of [
      (input: Sbx046AssessmentInput) => { input.postUpdateReadbacks.independent.routes = [{ ...route }]; },
      (input: Sbx046AssessmentInput) => { input.postUpdateReadbacks.active.domainLookupThrew = false; },
      (input: Sbx046AssessmentInput) => { input.finalReadbacks.independent.domainValue = route.url; },
      (input: Sbx046AssessmentInput) => { input.postUpdateReadbacks.active.observedAt = at(12_500); },
      (input: Sbx046AssessmentInput) => { input.update.requestedPorts = [SBX046_PORT]; },
      (input: Sbx046AssessmentInput) => { input.update.sessionIdAfter = `${sessionId}X`; },
    ]) {
      const input = validInput();
      mutate(input);
      expect(assessSbx046(input)).toMatchObject({
        verdict: "indeterminate",
        controlsPassed: false,
        candidate: false,
      });
    }
  });

  it("requires initial route, pre-route, and post-revocation local service controls", () => {
    for (const caseId of ["local-pre", "external-pre", "local-post-readback", "local-post-final"] as const) {
      const input = validInput();
      input.probes[caseId].serviceResponse!.operationId = `op46_${"Z".repeat(43)}`;
      expect(assessSbx046(input)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
    }
    const initial = validInput();
    initial.initialReadbacks.active.routes = [];
    expect(assessSbx046(initial)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
  });

  it("rejects early or mislabeled delayed probes", () => {
    const early = validInput();
    early.probes["external-post-90s"].elapsedSinceRevocationAckMs = 89_999;
    expect(assessSbx046(early).postProbeClassifications["external-post-90s"]).toBe("ambiguous");

    const clockMismatch = validInput();
    clockMismatch.probes["external-post-30s"].elapsedSinceRevocationAckMs = 35_000;
    expect(assessSbx046(clockMismatch).postProbeClassifications["external-post-30s"]).toBe("ambiguous");
  });

  it("requires every control and probe interval to be fully non-overlapping", () => {
    const overlaps: Array<(input: Sbx046AssessmentInput) => void> = [
      (input) => { input.probes["local-pre"].startedAt = at(3_999); },
      (input) => { input.probes["external-pre"].startedAt = at(5_999); },
      (input) => { input.update.requestedAt = at(7_999); },
      (input) => { input.postUpdateReadbacks.active.observedAt = at(9_999); },
      (input) => { input.probes["local-post-readback"].startedAt = at(11_999); },
      (input) => { input.probes["external-post-5s"].startedAt = at(13_999); },
      (input) => { input.probes["external-post-30s"].startedAt = at(15_999); },
      (input) => { input.probes["external-post-90s"].startedAt = at(40_999); },
      (input) => { input.finalReadbacks.active.observedAt = at(100_999); },
      (input) => { input.probes["local-post-final"].startedAt = at(102_999); },
      (input) => { input.probes["local-post-final"].completedAt = at(103_999); },
    ];
    for (const overlap of overlaps) {
      const input = validInput();
      overlap(input);
      expect(assessSbx046(input)).toMatchObject({
        verdict: "indeterminate",
        candidate: false,
        controlsPassed: false,
      });
    }
  });

  it("returns error for execution, cleanup, or storage integrity failure", () => {
    const execution = validInput();
    execution.executionError = "bounded controller failure";
    expect(assessSbx046(execution)).toMatchObject({ verdict: "error", candidate: false });

    const cleanup = validInput();
    cleanup.cleanup.absenceChecks = 2;
    expect(assessSbx046(cleanup)).toMatchObject({ verdict: "error", candidate: false });

    const storage = validInput();
    storage.storage.artifactMode = 0o644;
    expect(assessSbx046(storage)).toMatchObject({ verdict: "error", candidate: false });

    const retained = validInput();
    retained.ledger.rawHmacKeyRetained = true;
    expect(assessSbx046(retained)).toMatchObject({ verdict: "error", candidate: false });
  });

  it("does not allow malformed or degenerate keyed material to become a candidate", () => {
    const malformed = validInput();
    malformed.expected.challenges["external-post-90s"] = "not-a-challenge";
    expect(assessSbx046(malformed)).toMatchObject({ verdict: "indeterminate", candidate: false });

    const duplicate = validInput();
    duplicate.expected.operationIds["external-post-90s"] = duplicate.expected.operationIds["external-post-30s"];
    expect(assessSbx046(duplicate)).toMatchObject({ verdict: "indeterminate", candidate: false });

    const extraCase = validInput();
    Object.assign(extraCase.probes, { "unplanned-extra-request": exactReachProbe("local-pre") });
    expect(assessSbx046(extraCase)).toMatchObject({ verdict: "indeterminate", candidate: false });

    const wrongRoute = validInput();
    wrongRoute.expected.route.url = "http://sbx046owned.vercel.run";
    expect(assessSbx046(wrongRoute)).toMatchObject({ verdict: "indeterminate", candidate: false });

    const nonCanonicalRoute = validInput();
    nonCanonicalRoute.expected.route.url = "https://sbx046owned.vercel.run/";
    expect(assessSbx046(nonCanonicalRoute)).toMatchObject({ verdict: "indeterminate", candidate: false });
  });
});

describe("SBX-046 keyed evidence helpers", () => {
  it("derives the guest-compatible HMAC operation ID", () => {
    const key = Buffer.alloc(32, 7).toString("base64url");
    const message = JSON.stringify([
      SBX046_TEST_ID,
      runId,
      sandboxName,
      sessionId,
      SBX046_PORT,
      serviceInstanceId,
      "external-post-90s",
      challenges["external-post-90s"],
    ]);
    const expected = `op46_${createHmac("sha256", Buffer.alloc(32, 7)).update(message).digest("base64url")}`;
    expect(deriveSbx046OperationId(
      key,
      { runId, sandboxName, sessionId, serviceInstanceId },
      "external-post-90s",
      challenges["external-post-90s"],
    )).toBe(expected);
    expect(() => deriveSbx046OperationId(
      Buffer.alloc(16, 7).toString("base64url"),
      { runId, sandboxName, sessionId, serviceInstanceId },
      "external-post-90s",
      challenges["external-post-90s"],
    )).toThrow();
  });

  it("rejects raw HMAC key or request body in serialized evidence", () => {
    const key = Buffer.alloc(32, 9).toString("base64url");
    const requestBody = `public:${challenges["external-post-90s"]}`;
    expect(() => assertSbx046EvidenceExcludesRawValues(
      { verdict: assessSbx046(validInput()) },
      [key, requestBody],
    )).not.toThrow();
    expect(() => assertSbx046EvidenceExcludesRawValues({ nested: { key } }, [key, requestBody])).toThrow();
    expect(() => assertSbx046EvidenceExcludesRawValues({ body: requestBody }, [key, requestBody])).toThrow();
  });
});
