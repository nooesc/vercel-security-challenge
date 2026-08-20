import { describe, expect, it } from "vitest";
import {
  assessSbx047,
  type Sbx047AssessmentInput,
  type Sbx047GuestResult,
  type Sbx047ObserverEvent,
} from "../pocs/SBX-047/verdict.js";

const digest = (character: string): string => character.repeat(64);
const transformSha = digest("a");

function guest(
  kind: "public" | "action",
  caseId: string,
  receipt: string,
  operationId: string | null = null,
  secretProof: string | null = null,
): Sbx047GuestResult {
  return {
    schemaVersion: 1,
    testId: "SBX-047",
    kind,
    caseId,
    receivedResponse: true,
    statusCode: 200,
    durationMs: 42,
    receipt,
    operationId,
    secretProof,
    error: null,
  };
}

function blocked(): Sbx047GuestResult {
  return {
    schemaVersion: 1,
    testId: "SBX-047",
    kind: "public",
    caseId: "target-public",
    receivedResponse: false,
    statusCode: null,
    durationMs: 35,
    receipt: null,
    operationId: null,
    secretProof: null,
    error: { name: "TypeError", code: "EAI_AGAIN", syscall: "getaddrinfo", errno: -3001 },
  };
}

function event(
  sequence: number,
  kind: "public" | "action",
  caseId: string,
  receipt: string,
  options: { transform?: boolean; operationId?: string; secretProof?: string } = {},
): Sbx047ObserverEvent {
  const transformed = options.transform ?? true;
  return {
    sequence,
    observedAt: `2026-08-19T06:00:0${sequence}.000Z`,
    kind,
    caseId,
    method: "GET",
    requestTarget: `/v1/sbx047/${kind}/run/${caseId}/canary`,
    hostHeaderLines: 1,
    hostHeaderValues: 1,
    hostMatched: true,
    canaryMatched: true,
    transformHeaderLines: transformed ? 1 : 0,
    transformHeaderValues: transformed ? 1 : 0,
    ...(transformed ? { transformHeaderSha256: transformSha } : {}),
    transformCommitmentMatched: transformed,
    responseStatus: 200,
    receipt,
    ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
    ...(options.secretProof === undefined ? {} : { secretProof: options.secretProof }),
  };
}

function input(): Sbx047AssessmentInput {
  const sourceReceipt = digest("1");
  const sourceActionReceipt = digest("2");
  const sourceOperation = digest("3");
  const sourceProof = digest("4");
  const inheritanceReceipt = digest("5");
  return {
    controls: {
      exactEligibleAlias: true,
      sdk300ForkOverrideSerialized: true,
      sourcePolicyReadbacksExact: true,
      sourcePublicControlPassed: true,
      sourceNonreflectingActionPassed: true,
      inheritancePolicyReadbacksExact: true,
      inheritancePublicControlPassed: true,
      targetForkResponseDenyAll: true,
      targetActiveDenyAll: true,
      targetIndependentDenyAll: true,
      targetCurrentSessionDenyAll: true,
      targetIndependentCurrentSessionDenyAll: true,
      exactDistinctNamesAndSessions: true,
      fixedGuestProgram: true,
      guestSessionAttributionPassed: true,
      observerPreflightPassed: true,
      observerPostflightPassed: true,
      sequentialNoRetrySchedule: true,
    },
    expected: {
      runId: "run-047",
      sourcePublicCaseId: "source-public",
      sourceActionCaseId: "source-action",
      inheritancePublicCaseId: "inheritance-public",
      publicCaseId: "target-public",
      actionCaseId: "target-action",
      canary: "canary-047",
      publicReceipt: digest("6"),
      transformHeaderSha256: transformSha,
    },
    targetPublic: blocked(),
    observerEvents: [
      event(1, "public", "source-public", sourceReceipt),
      event(2, "action", "source-action", sourceActionReceipt, {
        operationId: sourceOperation,
        secretProof: sourceProof,
      }),
      event(3, "public", "inheritance-public", inheritanceReceipt),
    ],
    actionStagedAfterPublicSignal: false,
  };
}

describe("SBX-047 conservative fork-policy assessment", () => {
  it("returns a clean negative only for a bounded attributable pre-connect block and no target event", () => {
    expect(assessSbx047(input())).toMatchObject({
      verdict: "pass",
      candidate: false,
      severity: "none",
    });
  });

  it("classifies one exact public target event without a stale transform as Medium only", () => {
    const value = input();
    value.targetPublic = guest("public", "target-public", value.expected.publicReceipt);
    value.observerEvents.push(event(4, "public", "target-public", value.expected.publicReceipt, {
      transform: false,
    }));
    expect(assessSbx047(value)).toMatchObject({
      verdict: "candidate",
      candidate: true,
      severity: "medium",
      publicBoundaryReached: true,
      protectedActionExecuted: false,
    });
  });

  it("requires an exact staged proof and opaque operation ID for High", () => {
    const value = input();
    const actionReceipt = digest("7");
    const operationId = digest("8");
    const secretProof = digest("9");
    value.expected.actionReceipt = actionReceipt;
    value.expected.operationId = operationId;
    value.expected.secretProof = secretProof;
    value.targetPublic = guest("public", "target-public", value.expected.publicReceipt);
    value.targetAction = guest("action", "target-action", actionReceipt, operationId, secretProof);
    value.observerEvents.push(
      event(4, "public", "target-public", value.expected.publicReceipt),
      event(5, "action", "target-action", actionReceipt, { operationId, secretProof }),
    );
    value.actionStagedAfterPublicSignal = true;
    expect(assessSbx047(value)).toMatchObject({
      verdict: "candidate",
      candidate: true,
      severity: "high",
      protectedActionExecuted: true,
    });
  });

  it("rejects an extra or unknown observer case instead of filtering it away", () => {
    const value = input();
    value.observerEvents.push(event(4, "public", "unknown-case", digest("b")));
    expect(assessSbx047(value)).toMatchObject({ verdict: "indeterminate", candidate: false });
  });

  it("rejects duplicate target events", () => {
    const value = input();
    value.targetPublic = guest("public", "target-public", value.expected.publicReceipt);
    value.observerEvents.push(
      event(4, "public", "target-public", value.expected.publicReceipt, { transform: false }),
      event(5, "public", "target-public", value.expected.publicReceipt, { transform: false }),
    );
    expect(assessSbx047(value)).toMatchObject({ verdict: "indeterminate", candidate: false });
  });

  it("does not preserve Medium when protected-action staging/accounting is inconsistent", () => {
    const value = input();
    value.targetPublic = guest("public", "target-public", value.expected.publicReceipt);
    value.observerEvents.push(event(4, "public", "target-public", value.expected.publicReceipt));
    value.actionStagedAfterPublicSignal = true;
    expect(assessSbx047(value)).toMatchObject({ verdict: "indeterminate", candidate: false });
  });

  it("fails closed when any lifecycle/control boolean is false", () => {
    const value = input();
    value.controls.targetIndependentCurrentSessionDenyAll = false;
    expect(assessSbx047(value)).toMatchObject({ verdict: "indeterminate", candidate: false });
  });
});
