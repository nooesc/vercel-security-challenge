import { describe, expect, it } from "vitest";
import {
  SBX040_TEST_ID,
  SBX040_TRANSFORM_HEADER,
  assessSbx040Stage,
  combineSbx040Assessments,
  type Sbx040GuestEvidence,
  type Sbx040PolicyProof,
  type Sbx040ProbeMode,
  type Sbx040RequestEvent,
  type Sbx040StageInput,
} from "../pocs/SBX-040/verdict.js";

const aHost = "a.research.test";
const bHost = "b.research.test";
function guest(mode: Sbx040ProbeMode, caseId: string, overrides: Partial<Sbx040GuestEvidence> = {}): Sbx040GuestEvidence {
  const maximum = mode === "ambiguous-plus-a" ? 2 : 1;
  return {
    schemaVersion: 1,
    testId: SBX040_TEST_ID,
    caseId,
    mode,
    outerHost: mode === "direct-b" ? bHost : aHost,
    outerPort: 443,
    firstHost: mode === "direct-b" || mode === "host-b" ? bHost : aHost,
    connectionAttempts: 1,
    retryCount: 0,
    maximumRequests: maximum,
    actualRequests: maximum,
    tlsHandshakes: 1,
    strictCertificateVerification: true,
    environmentProxyTrust: false,
    rawConfigurationRetained: false,
    rawCredentialRetained: false,
    ok: true,
    firstResponse: { statusCode: 204, terminalHeader: true, bodyBytes: 0 },
    ...overrides,
  };
}

function proof(stage: "pre" | "post", sessionId = "session-public"): Sbx040PolicyProof {
  const projection = { allow: [aHost] };
  const redacted = { allow: { [aHost]: [{ transform: [{ headers: { [SBX040_TRANSFORM_HEADER]: "[REDACTED]" } }] }] } };
  return {
    stage,
    initialSessionId: sessionId,
    activeSessionId: sessionId,
    independentSessionId: sessionId,
    activeSandboxPolicy: projection,
    activeSessionPolicy: redacted,
    independentSandboxPolicy: projection,
    independentSessionPolicy: redacted,
    activeSandboxProjectionExact: true,
    activeSessionTransformExact: true,
    independentSandboxProjectionExact: true,
    independentSessionTransformExact: true,
    passed: true,
  };
}

function event(
  caseId: string,
  role: "a" | "b",
  framing: Sbx040RequestEvent["framing"],
  overrides: Partial<Sbx040RequestEvent> = {},
): Sbx040RequestEvent {
  return {
    caseId,
    connectionId: `conn-${caseId}`,
    requestIndex: role === "a" ? 0 : 1,
    sni: aHost,
    host: role === "a" ? aHost : bHost,
    method: role === "a" ? "POST" : "POST",
    target: `/v1/sbx040/run/${role}`,
    role,
    framing,
    transferEncodingLines: framing === "chunked" || framing === "cl-te" ? 1 : 0,
    contentLengthLines: framing === "content-length" || framing === "cl-te" ? 1 : 0,
    headerBytes: 200,
    headerSha256: "a".repeat(64),
    complete: role === "a",
    transformHeaderLines: role === "a" ? 1 : 0,
    transformCredentialMatched: role === "a",
    terminalResponseStatus: 204,
    rawHeadersRetained: false,
    rawBodyRetained: false,
    ...overrides,
  };
}

function candidateInput(stage: "public" | "secret" = "public", sessionId = "session-public"): Sbx040StageInput {
  const runId = `run-${stage}`;
  const caseIds: Sbx040StageInput["caseIds"] = {
    "direct-b": `${runId}:direct-pre`,
    "normal-a": `${runId}:normal-a`,
    "host-b": `${runId}:host-b`,
    "cl-only": `${runId}:cl-only`,
    "te-only": `${runId}:te-only`,
    "ambiguous-alone": `${runId}:alone`,
    "ambiguous-plus-a": `${runId}:attack`,
    "direct-b-post": `${runId}:direct-post`,
  };
  const operationId = "op_owned_operation";
  const attackConnection = "conn-attack";
  return {
    stage,
    runId,
    sandboxName: `sandbox-${stage}`,
    sessionId,
    aHost,
    bHost,
    canary: "canary",
    caseIds,
    guests: {
      "direct-b": guest("direct-b", caseIds["direct-b"], {
        ok: false, actualRequests: 0, tlsHandshakes: 0, errorCode: "EHOSTUNREACH",
      }),
      "normal-a": guest("normal-a", caseIds["normal-a"]),
      "host-b": guest("host-b", caseIds["host-b"], { ok: false, firstResponse: { statusCode: 403, bodyBytes: 0 } }),
      "cl-only": guest("cl-only", caseIds["cl-only"]),
      "te-only": guest("te-only", caseIds["te-only"]),
      "ambiguous-alone": guest("ambiguous-alone", caseIds["ambiguous-alone"]),
      "ambiguous-plus-a": guest("ambiguous-plus-a", caseIds["ambiguous-plus-a"], {
        secondResponse: { statusCode: 200, operationId, terminalHeader: true, bodyBytes: 0 },
      }),
      "direct-b-post": guest("direct-b", caseIds["direct-b-post"], {
        ok: false, actualRequests: 0, tlsHandshakes: 0, errorCode: "EAI_AGAIN",
      }),
    },
    receiver: {
      configured: true,
      rawCredentialRetained: false,
      requests: [
        event(caseIds["normal-a"], "a", "none"),
        event(caseIds["cl-only"], "a", "content-length"),
        event(caseIds["te-only"], "a", "chunked"),
        event(caseIds["ambiguous-alone"], "a", "cl-te"),
        event(caseIds["ambiguous-alone"], "b", "content-length", { complete: false }),
        event(caseIds["ambiguous-plus-a"], "a", "cl-te", { connectionId: attackConnection }),
        event(caseIds["ambiguous-plus-a"], "b", "content-length", {
          connectionId: attackConnection,
          complete: false,
        }),
      ],
      bActions: [{
        caseId: caseIds["ambiguous-plus-a"],
        connectionId: attackConnection,
        parentRequestIndex: 1,
        canaryMatched: true,
        nestedAHostMatched: true,
        nestedCaseMatched: true,
        transformHeaderLines: 1,
        transformCredentialMatched: true,
        nestedHeaderBytes: 300,
        nestedHeaderSha256: "b".repeat(64),
        bodyBytesObserved: 300,
        operationId,
        responseStatus: 200,
        rawCredentialRetained: false,
        rawBodyRetained: false,
      }],
    },
    policyPre: proof("pre", sessionId),
    policyPost: proof("post", sessionId),
    cleanupPassed: true,
  };
}

describe("SBX-040 verdict", () => {
  it("requires every control and the same-connection B receipt for a candidate", () => {
    const input = candidateInput();
    const result = assessSbx040Stage(input);
    expect(result).toMatchObject({ outcome: "candidate", candidate: true, controlsPassed: true });
    expect(Object.values(result.evidence).every(Boolean)).toBe(true);
  });

  it("rejects a B action without exact transform-credential validation", () => {
    const input = candidateInput();
    input.receiver.bActions[0]!.transformCredentialMatched = false;
    const result = assessSbx040Stage(input);
    expect(result.candidate).toBe(false);
    expect(result.evidence.exactCredentialAtB).toBe(false);
  });

  it("rejects a single-framing control that reaches B", () => {
    const input = candidateInput();
    input.receiver.requests.push(event(input.caseIds["cl-only"], "b", "content-length"));
    const result = assessSbx040Stage(input);
    expect(result.controlsPassed).toBe(false);
    expect(result.evidence.clOnlyClean).toBe(false);
  });

  it("promotes only a distinct fresh secret-stage reproduction to high", () => {
    const publicInput = candidateInput("public", "session-public");
    const secretInput = candidateInput("secret", "session-secret");
    const combined = combineSbx040Assessments(
      publicInput,
      assessSbx040Stage(publicInput),
      secretInput,
      assessSbx040Stage(secretInput),
    );
    expect(combined).toMatchObject({ outcome: "high-candidate", severityCeiling: "high", distinctFreshSandboxes: true });
  });
});
