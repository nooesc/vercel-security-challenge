import { describe, expect, it } from "vitest";
import { expectedOperationId, queryForCase, SBX049_CASES, type Sbx049CaseId } from "../pocs/SBX-049/protocol.js";
import {
  assessSbx049,
  exactQueryTransformPolicy,
  exactQueryTransformReadbackProjection,
  type Sbx049AssessmentInput,
} from "../pocs/SBX-049/verdict.js";

const runId = "12345678-1234-4123-8123-123456789abc";
const hostname = "owned.example";
const actionKey = "action-".padEnd(40, "b");
const secret = `s49_${"c".repeat(43)}`;
const sessionId = "sbx_abcdefghijklmnopqrstuvwxyz";
const canaries = Object.fromEntries(SBX049_CASES.map((caseId, index) =>
  [caseId, `c49_${String(index).padStart(24, "0")}`])) as Record<Sbx049CaseId, string>;
const operations = Object.fromEntries(SBX049_CASES.map((caseId) => [caseId, {
  reach: expectedOperationId(actionKey, hostname, runId, caseId, canaries[caseId]),
  secret: expectedOperationId(actionKey, hostname, runId, caseId, canaries[caseId], secret),
}])) as Record<Sbx049CaseId, { reach: string; secret: string }>;
const fullPolicy = {
  allow: {
    [hostname]: [{
      match: { queryString: [{ key: { exact: "role" }, value: { exact: "privileged" } }] },
      transform: [{ headers: { "x-sbx049-brokered-secret": "<redacted>" } }],
    }],
  },
};

function fixture(combinedBrokered = true): Sbx049AssessmentInput {
  const brokered = (caseId: Sbx049CaseId): boolean =>
    caseId === "exact-pair" || (caseId === "combined-halves" && combinedBrokered);
  const operation = (caseId: Sbx049CaseId): string =>
    brokered(caseId) ? operations[caseId].secret : operations[caseId].reach;
  return {
    runId,
    hostname,
    canaries,
    expectedOperationIds: operations,
    probes: Object.fromEntries(SBX049_CASES.map((caseId) => [caseId, {
      schemaVersion: 1,
      testId: "SBX-049-POC",
      runId,
      caseId,
      correlationCanary: canaries[caseId],
      commandExitCode: 0,
      ok: true,
      phase: "response",
      requestHostname: hostname,
      requestServername: hostname,
      requestPath: `/v1/sbx049/action?${queryForCase(runId, caseId, canaries[caseId])}`,
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
      responseBrokered: brokered(caseId),
      responseOperationId: operation(caseId),
      responseBodyRetained: false,
      durationMs: 25,
    }])) as unknown as Sbx049AssessmentInput["probes"],
    policyBefore: {
      stage: "before",
      initialSessionId: sessionId,
      activeSessionId: sessionId,
      independentSessionId: sessionId,
      activeSandboxPolicy: { allow: [hostname] },
      activeSessionPolicy: fullPolicy,
      independentSandboxPolicy: { allow: [hostname] },
      independentSessionPolicy: fullPolicy,
      rawSecretPresentInReadbacks: false,
      platformRedactionMarkerPresent: true,
    },
    policyAfter: {
      stage: "after",
      initialSessionId: sessionId,
      activeSessionId: sessionId,
      independentSessionId: sessionId,
      activeSandboxPolicy: { allow: [hostname] },
      activeSessionPolicy: fullPolicy,
      independentSandboxPolicy: { allow: [hostname] },
      independentSessionPolicy: fullPolicy,
      rawSecretPresentInReadbacks: false,
      platformRedactionMarkerPresent: true,
    },
    ledger: {
      configured: true,
      events: SBX049_CASES.map((caseId, index) => ({
        ordinal: index + 1,
        observedAt: new Date(1_700_000_000_000 + index).toISOString(),
        caseId,
        canaryMatched: true,
        queryMatched: true,
        brokered: brokered(caseId),
        operationId: operation(caseId),
      })),
      rawBrokeredSecretRetained: false,
      brokeredSecretDigestRetained: false,
    },
    cleanup: {
      sandbox: { stopped: true, deleted: true, absenceChecks: 2, errors: [] },
      receiver: { deleted: true, absent: true, errors: [] },
    },
  };
}

describe("SBX-049 verdict", () => {
  it("requires the exact key/value matcher entry", () => {
    expect(exactQueryTransformPolicy(fullPolicy, hostname)).toBe(true);
    const detached = structuredClone(fullPolicy);
    detached.allow[hostname]![0]!.match.queryString[0]!.key.exact = "decoy";
    expect(exactQueryTransformPolicy(detached, hostname)).toBe(false);
  });

  it("accepts only the exact matcher-less session readback projection", () => {
    const projection = {
      allow: {
        [hostname]: [{
          transform: [{ headers: { "x-sbx049-brokered-secret": "<redacted>" } }],
        }],
      },
    };
    expect(exactQueryTransformReadbackProjection(projection, hostname)).toBe(true);
    const extra = structuredClone(projection);
    (extra.allow[hostname]![0] as Record<string, unknown>).unexpected = true;
    expect(exactQueryTransformReadbackProjection(extra, hostname)).toBe(false);
  });

  it("classifies exact controller-secret proof on combined halves as High", () => {
    expect(assessSbx049(fixture(true))).toMatchObject({
      outcome: "candidate-high",
      candidate: true,
      severity: "high",
      controlsPassed: true,
      queryEntryAssociationBypassed: true,
      brokeredSecretProven: true,
    });
  });

  it("classifies a clean non-brokered combined request as pass", () => {
    expect(assessSbx049(fixture(false))).toMatchObject({
      outcome: "pass",
      candidate: false,
      severity: "none",
      controlsPassed: true,
    });
  });

  it("rejects reordered, extra, or unknown ledger events", () => {
    const reordered = fixture(true);
    [reordered.ledger.events[1], reordered.ledger.events[2]] = [reordered.ledger.events[2]!, reordered.ledger.events[1]!];
    expect(assessSbx049(reordered).outcome).toBe("indeterminate");
    const extra = fixture(true);
    extra.ledger.events.push({ ...extra.ledger.events[0]!, ordinal: 5 });
    expect(assessSbx049(extra).outcome).toBe("indeterminate");
  });

  it("refuses a candidate when either isolated half is transformed", () => {
    const input = fixture(true);
    input.probes["value-half"].responseBrokered = true;
    input.probes["value-half"].responseOperationId = operations["value-half"].secret;
    input.ledger.events[2]!.brokered = true;
    input.ledger.events[2]!.operationId = operations["value-half"].secret;
    expect(assessSbx049(input)).toMatchObject({ outcome: "indeterminate", candidate: false, controlsPassed: false });
  });

  it("globally gates a finding on strict cleanup", () => {
    const input = fixture(true);
    input.cleanup.sandbox.absenceChecks = 1;
    expect(assessSbx049(input)).toMatchObject({ outcome: "error", candidate: false });
  });
});
