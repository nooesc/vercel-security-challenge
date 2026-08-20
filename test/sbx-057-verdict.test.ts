import { describe, expect, it } from "vitest";
import {
  SBX057_CASES,
  SBX057_REDACTED_VALUE,
  SBX057_TEST_ID,
  SBX057_TRANSFORM_HEADER,
  casePath,
  expectedOperationId,
  expectedReceipt,
  secretCommitment,
  type Sbx057CaseId,
} from "../pocs/SBX-057/protocol.js";
import { assessSbx057, type Sbx057AssessmentInput, type Sbx057PolicyProof,
  type Sbx057ProbeEvidence } from "../pocs/SBX-057/verdict.js";

const RUN = "123e4567-e89b-42d3-a456-426614174000";
const A = "a-sbx057.trycloudflare.com";
const B = "b-sbx057.trycloudflare.com";
const ADMIN = "A".repeat(43);
const ACTION = "B".repeat(43);
const SECRETS = { comparator: "cmp-controller-secret", target: "target-controller-secret" };
const CANARIES = Object.fromEntries(SBX057_CASES.map((caseId, index) => [
  caseId, `s57_${caseId}_${String.fromCharCode(65 + index).repeat(22)}`,
])) as Record<Sbx057CaseId, string>;
const COMMITMENTS = {
  comparator: secretCommitment(ACTION, RUN, "comparator", SECRETS.comparator),
  target: secretCommitment(ACTION, RUN, "target", SECRETS.target),
};
const OPERATIONS = Object.fromEntries(SBX057_CASES.map((caseId) => [
  caseId,
  expectedOperationId(ACTION, RUN, caseId, CANARIES[caseId],
    caseId.startsWith("comparator-") ? COMMITMENTS.comparator : COMMITMENTS.target),
])) as Record<Sbx057CaseId, string>;

function at(seconds: number): string {
  return new Date(Date.UTC(2026, 7, 19, 0, 0, seconds)).toISOString();
}

function receipt(sequence: number, caseId: Sbx057CaseId, count: number, matched: boolean,
  status: number, operationId?: string): string {
  return expectedReceipt(ADMIN, RUN, sequence, caseId, CANARIES[caseId],
    caseId.endsWith("-a") ? "A" : "B", count, matched, false, status, operationId);
}

const RECEIPTS = {
  comparatorAAction: receipt(1, "comparator-a", 1, true, 200, OPERATIONS["comparator-a"]),
  comparatorBNone: receipt(2, "comparator-b", 0, false, 202),
  comparatorBAction: receipt(2, "comparator-b", 1, true, 200, OPERATIONS["comparator-b"]),
  targetAAction: receipt(3, "target-a", 1, true, 200, OPERATIONS["target-a"]),
  targetBNone: receipt(4, "target-b", 0, false, 202),
  targetBAction: receipt(4, "target-b", 1, true, 200, OPERATIONS["target-b"]),
};

function policy(stage: "comparator" | "target", sessionId: string, captured: number): Sbx057PolicyProof {
  const other = stage === "comparator" ? B : "*";
  const top = { allow: [A, other] };
  const session = { allow: {
    [A]: [{ transform: [{ headers: { [SBX057_TRANSFORM_HEADER]: SBX057_REDACTED_VALUE } }] }],
    [other]: [],
  } };
  return {
    stage, capturedAt: at(captured), expectedSessionId: sessionId,
    activeSessionId: sessionId, independentSessionId: sessionId,
    activeSandboxPolicy: structuredClone(top), activeSessionPolicy: structuredClone(session),
    independentSandboxPolicy: structuredClone(top), independentSessionPolicy: structuredClone(session),
    configuredPolicyComparedExactlyInMemory: true, rawSecretPresentInReadbacks: false,
    platformRedactionMarkerPresent: true,
  };
}

function probe(caseId: Sbx057CaseId, status: 200 | 202, started: number, observed: number,
  completed: number, responseReceipt: string): Sbx057ProbeEvidence {
  const hostname = caseId.endsWith("-a") ? A : B;
  return {
    schemaVersion: 1, testId: SBX057_TEST_ID, runId: RUN, caseId, canary: CANARIES[caseId],
    commandExitCode: 0, ok: true, requestHostname: hostname, requestServername: hostname,
    requestHostHeader: hostname, requestPath: casePath(RUN, caseId), connectionAttempts: 1,
    actualConnections: 1, actualRequests: 1, retries: 0, redirectsFollowed: 0,
    rejectUnauthorized: true, controllerConfigurableCustomTrustAccepted: false,
    inheritedPlatformTrustEnvironmentNames: [], tcpConnected: true, tlsEstablished: true,
    tlsAuthorized: true, responseReceived: true, responseStatusCode: status,
    responseShapeValid: true, responseRole: caseId.endsWith("-a") ? "A" : "B",
    responseReceipt, ...(status === 200 ? { responseOperationId: OPERATIONS[caseId] } : {}),
    responseBodyRetained: false, durationMs: (completed - started) * 1_000,
    startedAt: at(started), completedAt: at(completed),
  };
}

function event(caseId: Sbx057CaseId, sequence: number, status: 200 | 202, observed: number,
  eventReceipt: string) {
  const action = status === 200;
  return {
    sequence, observedAt: at(observed), kind: "expected" as const,
    role: caseId.endsWith("-a") ? "A" as const : "B" as const,
    caseId, method: "GET", hostMatched: true, pathMatched: true, correlationHeadersExact: true,
    transformHeaderLines: action ? 1 : 0, transformHeaderValues: action ? 1 : 0,
    transformCommitmentMatched: action, crossCommitmentMatched: false,
    responseStatus: status, receipt: eventReceipt,
    ...(action ? { operationId: OPERATIONS[caseId] } : {}),
  };
}

function input(mode: "pass" | "candidate" | "alternate" = "pass"): Sbx057AssessmentInput {
  const comparatorSession = `sbx_${"c".repeat(24)}`;
  const targetSession = `sbx_${"t".repeat(24)}`;
  const alternate = mode === "alternate";
  const targetLeak = mode === "candidate";
  const cBStatus = alternate ? 200 : 202;
  const cBReceipt = alternate ? RECEIPTS.comparatorBAction : RECEIPTS.comparatorBNone;
  const tBStatus = targetLeak ? 200 : 202;
  const tBReceipt = targetLeak ? RECEIPTS.targetBAction : RECEIPTS.targetBNone;
  const events = [
    event("comparator-a", 1, 200, 3, RECEIPTS.comparatorAAction),
    event("comparator-b", 2, cBStatus, 6, cBReceipt),
    ...(!alternate ? [
      event("target-a", 3, 200, 11, RECEIPTS.targetAAction),
      event("target-b", 4, tBStatus, 14, tBReceipt),
    ] : []),
  ];
  return {
    runId: RUN,
    identity: { alias: "swve@wearehackerone.com", teamId: "team", projectId: "project" },
    expectedIdentity: { alias: "swve@wearehackerone.com", teamId: "team", projectId: "project" },
    aHostname: A, bHostname: B, comparatorCommitment: COMMITMENTS.comparator,
    targetCommitment: COMMITMENTS.target, canaries: structuredClone(CANARIES),
    expectedOperationIds: structuredClone(OPERATIONS), expectedReceipts: structuredClone(RECEIPTS),
    resources: [
      { role: "comparator", name: `sbx-057-comparator-${RUN}`, sessionId: comparatorSession,
        persistent: false, tags: { harness: "vsc", test: SBX057_TEST_ID, run: RUN, role: "comparator" } },
      ...(!alternate ? [{ role: "target" as const, name: `sbx-057-target-${RUN}`, sessionId: targetSession,
        persistent: false as const, tags: { harness: "vsc", test: SBX057_TEST_ID, run: RUN, role: "target" } }] : []),
    ],
    policies: {
      comparatorBefore: policy("comparator", comparatorSession, 1),
      comparatorAfter: policy("comparator", comparatorSession, 7),
      ...(!alternate ? {
        targetBefore: policy("target", targetSession, 9),
        targetAfter: policy("target", targetSession, 15),
      } : {}),
    },
    probes: {
      "comparator-a": probe("comparator-a", 200, 2, 3, 4, RECEIPTS.comparatorAAction),
      "comparator-b": probe("comparator-b", cBStatus, 5, 6, 7, cBReceipt),
      ...(!alternate ? {
        "target-a": probe("target-a", 200, 10, 11, 12, RECEIPTS.targetAAction),
        "target-b": probe("target-b", tBStatus, 13, 14, 15, tBReceipt),
      } : {}),
    },
    ledger: {
      schemaVersion: 1, testId: SBX057_TEST_ID, runId: RUN, configuredAt: at(0),
      configurationValid: true, rawSecretsRetained: false, unexpectedIngressCount: 0,
      unattributedIngressCount: 0, events,
    },
    cleanup: {
      resources: [
        { role: "comparator", exactProvenance: true, stopAttempted: true, stopped: true,
          deleteAttempted: true, deleted: true, absenceChecks: 3, errors: [] },
        ...(!alternate ? [{ role: "target" as const, exactProvenance: true, stopAttempted: true, stopped: true,
          deleteAttempted: true, deleted: true, absenceChecks: 3, errors: [] }] : []),
      ],
      receiverDeleteAttempted: true, receiverDeleted: true, receiverAbsenceChecks: 2,
      completedAt: at(alternate ? 10 : 17), journalRemoved: true, liveLockRemoved: true,
      lockTransactionRemoved: true, errors: [],
    },
    retention: {
      guestSourceContainsComparatorSecret: false, guestSourceContainsTargetSecret: false,
      guestConfigurationContainsComparatorSecret: false, guestConfigurationContainsTargetSecret: false,
      guestEnvironmentContainsSecrets: false, guestArgvContainsSecrets: false,
      guestFilesContainSecrets: false, guestStdoutContainsSecrets: false, guestResultContainsSecrets: false,
      artifactContainsRawSecrets: false, artifactContainsStandaloneSecretDigests: false,
      receiverRetainedRawSecrets: false, artifactMode: 0o600, lockMode: 0o600, journalMode: 0o600,
    },
    comparatorCleanupCompletedAt: at(8), receiverSnapshotAt: at(alternate ? 9 : 16),
  };
}

describe("SBX-057 verdict", () => {
  it("passes only the clean comparator and clean wildcard target", () => {
    expect(assessSbx057(input("pass"))).toMatchObject({ outcome: "pass", candidate: false, controlsPassed: true });
  });

  it("accepts a causal target policy-to-probe edge serialized in the same millisecond", () => {
    const value = input("pass");
    value.policies.targetBefore!.capturedAt = value.probes["target-a"]!.startedAt;
    expect(assessSbx057(value)).toMatchObject({ outcome: "pass", candidate: false, controlsPassed: true });
  });

  it("still rejects a target probe that predates its policy proof", () => {
    const value = input("pass");
    value.policies.targetBefore!.capturedAt = at(11);
    expect(assessSbx057(value)).toMatchObject({ outcome: "indeterminate", candidate: false });
  });

  it("raises High only when the target B event proves the target secret", () => {
    expect(assessSbx057(input("candidate"))).toMatchObject({
      outcome: "candidate-high", candidate: true, severity: "high", wildcardCredentialLeakProven: true,
    });
  });

  it("stops on an exact-domain comparator leak as a distinct High root", () => {
    expect(assessSbx057(input("alternate"))).toMatchObject({
      outcome: "alternate-root", candidate: true, severity: "high", wildcardCredentialLeakProven: false,
    });
  });

  it.each([
    ["extra ingress", (value: Sbx057AssessmentInput) => { value.ledger.unexpectedIngressCount = 1; }],
    ["cross-secret match", (value: Sbx057AssessmentInput) => { value.ledger.events[3]!.crossCommitmentMatched = true; }],
    ["extra event", (value: Sbx057AssessmentInput) => { value.ledger.events.push(structuredClone(value.ledger.events[3]!)); }],
    ["wrong target receipt", (value: Sbx057AssessmentInput) => { value.ledger.events[3]!.receipt = RECEIPTS.comparatorBAction; }],
    ["raw secret retention", (value: Sbx057AssessmentInput) => { value.retention.artifactContainsRawSecrets = true; }],
    ["cleanup gap", (value: Sbx057AssessmentInput) => { value.cleanup.resources[1]!.absenceChecks = 2; }],
    ["chronology overlap", (value: Sbx057AssessmentInput) => { value.probes["target-b"]!.startedAt = at(11); }],
    ["wildcard policy omission", (value: Sbx057AssessmentInput) => {
      value.policies.targetBefore!.activeSessionPolicy = { allow: { [A]: [] } };
    }],
    ["wrong independent session", (value: Sbx057AssessmentInput) => {
      value.policies.targetAfter!.independentSessionId = `sbx_${"z".repeat(24)}`;
    }],
    ["duplicate resource role", (value: Sbx057AssessmentInput) => {
      value.resources[1] = structuredClone(value.resources[0]!);
    }],
    ["reused commitment", (value: Sbx057AssessmentInput) => {
      value.targetCommitment = value.comparatorCommitment;
    }],
    ["duplicate operation proof", (value: Sbx057AssessmentInput) => {
      value.expectedOperationIds["target-b"] = value.expectedOperationIds["target-a"];
    }],
    ["non-owned public origin", (value: Sbx057AssessmentInput) => { value.bHostname = "example.com"; }],
    ["controller error", (value: Sbx057AssessmentInput) => { value.controllerError = "bounded error"; }],
  ])("fails closed for %s", (_name, mutate) => {
    const value = input("candidate");
    mutate(value);
    expect(assessSbx057(value).outcome).not.toBe("candidate-high");
  });
});
