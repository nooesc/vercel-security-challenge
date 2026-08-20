import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  ABSENCE_CONFIRMATION_DELAY_MS,
  assertDistinctBoundedSessionIds,
  commandRequestPayload,
  confirmTwoAbsences,
  conclusiveSessionCommandRejection,
  createFixturePlans,
  finalizeSessionCommandAfterLiveLockRelease,
  orchestrateAuthorizationRequests,
  orchestrateCleanupOnlyRecovery,
  parseCommandResponse,
  parseSessionCommandLane,
  resolveRunMode,
  releaseNeutralSessionCommandEvidenceState,
  sessionCommandLiveLockOptions,
  type AuthorizationOperation,
} from "../pocs/SBX-026/session-command-cross-tenant.js";
import {
  assessSessionCommandAuthorization,
  type SessionCommandAssessmentInput,
} from "../pocs/SBX-026/session-command-verdict.js";

function baseline(
  patch: Partial<SessionCommandAssessmentInput> = {},
): SessionCommandAssessmentInput {
  return {
    lane: "session-read",
    cleanupPassed: true,
    exactIdentitiesVerified: true,
    identitiesDistinct: true,
    attackerOwnerControlPassed: true,
    victimOwnerControlPassed: true,
    sameAccountControlRequestCount: 2,
    sameAccountControlImmediatelyPrecededCross: true,
    operationConstraintsPassed: true,
    foreignRequestAttempted: true,
    foreignRequestCount: 1,
    crossKnownPathReadCount: 1,
    deferredCrossOperationCount: 0,
    foreignRejected: true,
    foreignRejectionConclusive: true,
    foreignSucceeded: false,
    exactMarkerConfirmed: false,
    qpsAuditPassed: true,
    rawMarkerOrBodyRetained: false,
    ...patch,
  };
}

describe("SBX-026 session/command lane selection", () => {
  it("allows one named lane and forbids --all, multiple lanes, and unknown options", () => {
    expect(parseSessionCommandLane(["--lane=session-read"])).toBe("session-read");
    expect(parseSessionCommandLane(["--lane=command-run"])).toBe("command-run");
    expect(() => parseSessionCommandLane(["--all"])).toThrow(/forbidden/u);
    expect(() => parseSessionCommandLane([
      "--lane=session-read",
      "--lane=command-run",
    ])).toThrow(/exactly one/u);
    expect(() => parseSessionCommandLane(["--lane=nested-command-log"])).toThrow(/exactly/u);
    expect(() => parseSessionCommandLane([])).toThrow(/exactly one/u);
  });

  it("turns every supplied run UUID into cleanup-only mode", () => {
    const completedRunId = "11111111-1111-4111-8111-111111111111";
    expect(resolveRunMode({ SBX026_RUN_ID: completedRunId })).toEqual({
      runId: completedRunId,
      cleanupOnly: true,
    });
    expect(resolveRunMode({})).toMatchObject({ cleanupOnly: false });
  });

  it("binds the shared live lock to the exact session-command lane and run mode", () => {
    const runId = "33333333-3333-4333-8333-333333333333";
    expect(sessionCommandLiveLockOptions("session-read", runId, false)).toEqual({
      scope: "session-command",
      lane: "session-read",
      runId,
      mode: "normal",
    });
    expect(sessionCommandLiveLockOptions("command-run", runId, true)).toEqual({
      scope: "session-command",
      lane: "command-run",
      runId,
      mode: "cleanup-only",
    });
  });
});

describe("SBX-026 fixture and request orchestration", () => {
  const runId = "22222222-2222-4222-8222-222222222222";
  const attackerMarker = "attacker_marker_that_is_distinct";
  const victimMarker = "victim_marker_that_is_distinct";
  const attackerSessionId = "sbx_attacker_session_12345";
  const victimSessionId = "sbx_victim_session_67890";

  it("requires distinct bounded markers, known paths, and session IDs", () => {
    const plans = createFixturePlans("session-read", runId, attackerMarker, victimMarker);
    expect(plans.attacker.marker).not.toBe(plans.victim.marker);
    expect(plans.attacker.knownPath).not.toBe(plans.victim.knownPath);
    expect(assertDistinctBoundedSessionIds(attackerSessionId, victimSessionId)).toBe(true);
    expect(() => assertDistinctBoundedSessionIds(attackerSessionId, attackerSessionId)).toThrow(
      /distinct/u,
    );
    expect(() => assertDistinctBoundedSessionIds("not-a-session", victimSessionId)).toThrow(
      /bounded/u,
    );
    expect(() => createFixturePlans(
      "session-read",
      runId,
      attackerMarker,
      attackerMarker,
    )).toThrow(/markers must be distinct/u);
  });

  it("performs both cleanup recoveries without dispatching a control or foreign request", async () => {
    const recoveries: string[] = [];
    const dispatches: AuthorizationOperation[] = [];
    const result = await orchestrateCleanupOnlyRecovery(
      async () => {
        recoveries.push("attacker");
        return true;
      },
      async () => {
        recoveries.push("victim");
        return true;
      },
      async (operation) => {
        dispatches.push(operation);
        return { exactMarkerConfirmed: true };
      },
    );
    expect(recoveries).toEqual(["attacker", "victim"]);
    expect(dispatches).toEqual([]);
    expect(result).toMatchObject({
      attackerRecoveryPassed: true,
      victimRecoveryPassed: true,
      attackerOwnerControlPassed: false,
      victimOwnerControlPassed: false,
      foreignDispatched: false,
    });
  });

  it("requires two absence confirmations separated by the bounded delay", async () => {
    const events: string[] = [];
    const result = await confirmTwoAbsences(
      async () => {
        events.push("404");
        return true;
      },
      async (milliseconds) => {
        events.push(`delay:${milliseconds}`);
      },
    );
    expect(result).toEqual({
      confirmed: true,
      attempts: 2,
      delayMs: ABSENCE_CONFIRMATION_DELAY_MS,
    });
    expect(events).toEqual([
      "404",
      `delay:${ABSENCE_CONFIRMATION_DELAY_MS}`,
      "404",
    ]);
    expect(ABSENCE_CONFIRMATION_DELAY_MS).toBeGreaterThanOrEqual(1_000);

    let postRecoveryProbes = 0;
    await expect(confirmTwoAbsences(
      async () => {
        postRecoveryProbes += 1;
        return true;
      },
      async () => undefined,
      true,
    )).resolves.toMatchObject({ confirmed: true, attempts: 2 });
    expect(postRecoveryProbes).toBe(1);

    const observations = [true, false];
    await expect(confirmTwoAbsences(
      async () => observations.shift() ?? false,
      async () => undefined,
    )).resolves.toEqual({
      confirmed: false,
      attempts: 2,
      delayMs: ABSENCE_CONFIRMATION_DELAY_MS,
    });
  });

  it("dispatches victim control immediately before attacker-to-victim foreign operation", async () => {
    const plans = createFixturePlans("command-run", runId, attackerMarker, victimMarker);
    const operations: AuthorizationOperation[] = [];
    const result = await orchestrateAuthorizationRequests({
      cleanupOnly: false,
      lane: "command-run",
      attacker: { ...plans.attacker, sessionId: attackerSessionId },
      victim: { ...plans.victim, sessionId: victimSessionId },
    }, async (operation) => {
      operations.push(operation);
      return { exactMarkerConfirmed: true };
    });
    expect(operations.map((operation) => operation.phase)).toEqual([
      "attacker-owner-control",
      "victim-owner-control",
      "foreign",
    ]);
    expect(operations[0]).toMatchObject({
      actor: "attacker",
      target: "attacker",
      sessionId: attackerSessionId,
      marker: attackerMarker,
      knownPath: plans.attacker.knownPath,
    });
    expect(operations[1]).toMatchObject({
      actor: "victim",
      target: "victim",
      sessionId: victimSessionId,
      marker: victimMarker,
      knownPath: plans.victim.knownPath,
    });
    expect(operations[2]).toMatchObject({
      actor: "attacker",
      target: "victim",
      sessionId: victimSessionId,
      marker: victimMarker,
      knownPath: plans.victim.knownPath,
    });
    expect(result.foreignDispatched).toBe(true);
  });
});

describe("SBX-026 session/command evidence finalization", () => {
  function pendingEvidence(mode: "test" | "cleanup-only"): Record<string, unknown> {
    return {
      mode,
      ...releaseNeutralSessionCommandEvidenceState(mode),
      liveLock: { releasedAfterEvidenceWrite: false },
    };
  }

  it("leaves a neutral artifact and emits no success stdout when lock release fails", async () => {
    const pending = pendingEvidence("test");
    const directory = await mkdtemp(join(tmpdir(), "sbx026-session-finalization-"));
    const evidencePath = join(directory, "pending.json");
    await writeFile(evidencePath, `${JSON.stringify(pending)}\n`, { mode: 0o600, flag: "wx" });
    const release = vi.fn(async () => {
      throw new Error("injected release failure");
    });
    const constructFinal = vi.fn(() => ({ verdict: "candidate" }));
    const successStdout = vi.fn();

    try {
      await expect(finalizeSessionCommandAfterLiveLockRelease(
        "test",
        pending,
        evidencePath,
        { release },
        true,
        constructFinal,
        successStdout,
      )).rejects.toThrow(/injected release failure/u);

      expect(release).toHaveBeenCalledOnce();
      expect(constructFinal).not.toHaveBeenCalled();
      expect(successStdout).not.toHaveBeenCalled();
      expect(pending).toMatchObject({
        assessment: { verdict: "indeterminate" },
        finalization: {
          status: "pending-recovery-or-live-lock-release",
          effectiveVerdict: "indeterminate",
          candidate: false,
          finalAssessmentRetained: false,
          liveLockReleased: false,
        },
        liveLock: { releasedAfterEvidenceWrite: false },
      });
      const durable = JSON.parse(await readFile(evidencePath, "utf8")) as Record<string, unknown>;
      expect(durable).toEqual(pending);
      expect(durable).not.toHaveProperty("completedAt");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("constructs and emits a final verdict only after successful release", async () => {
    const order: string[] = [];
    const final = await finalizeSessionCommandAfterLiveLockRelease(
      "test",
      pendingEvidence("test"),
      "/private/pending.json",
      { release: async () => { order.push("release"); } },
      true,
      () => {
        order.push("construct-final");
        return { verdict: "candidate", summary: "synthetic candidate" };
      },
      () => { order.push("success-stdout"); },
      "2026-08-19T00:00:00.000Z",
    );

    expect(order).toEqual(["release", "construct-final", "success-stdout"]);
    expect(final).toMatchObject({
      verdict: "candidate",
      completedAt: "2026-08-19T00:00:00.000Z",
      evidencePath: "/private/pending.json",
      finalization: {
        status: "complete",
        liveLockReleasedBeforeVerdict: true,
        durableEvidenceRemainsReleaseNeutral: true,
      },
    });
  });

  it("keeps cleanup-only outcome pending and emits nothing for unresolved recovery", async () => {
    const pending = pendingEvidence("cleanup-only");
    const release = vi.fn(async () => undefined);
    const constructFinal = vi.fn(() => ({ outcome: "cleanup-complete" }));
    const successStdout = vi.fn();

    await expect(finalizeSessionCommandAfterLiveLockRelease(
      "cleanup-only",
      pending,
      "/private/cleanup-pending.json",
      { release },
      false,
      constructFinal,
      successStdout,
    )).resolves.toBeUndefined();

    expect(release).not.toHaveBeenCalled();
    expect(constructFinal).not.toHaveBeenCalled();
    expect(successStdout).not.toHaveBeenCalled();
    expect(pending).toMatchObject({
      outcome: "pending-live-lock-release",
      finalization: { effectiveVerdict: "indeterminate", candidate: false },
    });
  });
});

describe("SBX-026 session/command verdict", () => {
  it("accepts only session/command-appropriate authorization rejections", () => {
    expect(conclusiveSessionCommandRejection({ kind: "api", status: 403 })).toBe(true);
    expect(conclusiveSessionCommandRejection({ kind: "api", status: 404 })).toBe(true);
    expect(conclusiveSessionCommandRejection({
      kind: "api",
      status: 422,
      code: "forbidden",
    })).toBe(true);
    expect(conclusiveSessionCommandRejection({
      kind: "api",
      status: 422,
      code: "snapshot_not_found",
    })).toBe(false);
    expect(conclusiveSessionCommandRejection({ kind: "api", status: 401 })).toBe(false);
    expect(conclusiveSessionCommandRejection({ kind: "api", status: 410 })).toBe(false);
  });

  it("passes only a conclusive rejection after both owner controls", () => {
    expect(assessSessionCommandAuthorization(baseline())).toMatchObject({
      verdict: "pass",
      outcomeSignalsMutuallyExclusive: true,
      outcomeSignalsConsistent: true,
      safetyInvariantsPassed: true,
    });
    expect(assessSessionCommandAuthorization(baseline({
      foreignRejectionConclusive: false,
    })).verdict).toBe("indeterminate");
    expect(assessSessionCommandAuthorization(baseline({
      sameAccountControlRequestCount: 1,
    })).verdict).toBe("indeterminate");
    expect(assessSessionCommandAuthorization(baseline({
      attackerOwnerControlPassed: false,
    })).verdict).toBe("indeterminate");
    expect(assessSessionCommandAuthorization(baseline({
      victimOwnerControlPassed: false,
    })).verdict).toBe("indeterminate");
  });

  it("marks an exact synthetic marker confirmation as a candidate", () => {
    expect(assessSessionCommandAuthorization(baseline({
      foreignRejected: false,
      foreignRejectionConclusive: false,
      foreignSucceeded: true,
      exactMarkerConfirmed: true,
    }))).toMatchObject({
      verdict: "candidate",
      outcomeSignalsMutuallyExclusive: true,
      outcomeSignalsConsistent: true,
    });

    expect(assessSessionCommandAuthorization(baseline({
      lane: "command-run",
      crossKnownPathReadCount: 0,
      foreignRejected: false,
      foreignRejectionConclusive: false,
      foreignSucceeded: true,
      exactMarkerConfirmed: true,
    })).verdict).toBe("candidate");
  });

  it("keeps contradictory or incomplete response signals indeterminate", () => {
    expect(assessSessionCommandAuthorization(baseline({
      foreignRejected: true,
      foreignSucceeded: true,
      exactMarkerConfirmed: true,
    }))).toMatchObject({
      verdict: "indeterminate",
      outcomeSignalsConsistent: false,
    });
    expect(assessSessionCommandAuthorization(baseline({
      foreignRejected: true,
      foreignSucceeded: false,
      exactMarkerConfirmed: true,
    }))).toMatchObject({
      verdict: "indeterminate",
      outcomeSignalsConsistent: false,
    });
    expect(assessSessionCommandAuthorization(baseline({
      foreignRejected: false,
      foreignRejectionConclusive: true,
      foreignSucceeded: true,
      exactMarkerConfirmed: true,
    }))).toMatchObject({ verdict: "indeterminate", outcomeSignalsConsistent: false });
    expect(assessSessionCommandAuthorization(baseline({
      foreignRejected: false,
      foreignSucceeded: false,
      foreignRejectionConclusive: false,
    })).verdict).toBe("indeterminate");
    expect(assessSessionCommandAuthorization(baseline({
      foreignRejected: false,
      foreignSucceeded: true,
      foreignRejectionConclusive: false,
      exactMarkerConfirmed: false,
    }))).toMatchObject({ verdict: "indeterminate", outcomeSignalsConsistent: false });
  });

  it("turns request, read, cleanup, rate, deferred-operation, and retention violations into errors", () => {
    for (const patch of [
      { foreignRequestCount: 2 },
      { sameAccountControlRequestCount: 3 },
      { crossKnownPathReadCount: 2 },
      { lane: "command-run", crossKnownPathReadCount: 1 },
      { cleanupPassed: false },
      { qpsAuditPassed: false },
      { deferredCrossOperationCount: 1 },
      { rawMarkerOrBodyRetained: true },
      { operationConstraintsPassed: false },
    ] satisfies Array<Partial<SessionCommandAssessmentInput>>) {
      expect(assessSessionCommandAuthorization(baseline(patch)).verdict).toBe("error");
    }
  });
});

describe("SBX-026 harmless command proof", () => {
  const marker = "synthetic_marker_for_unit_test";
  const sessionId = "sbx_session_owned_fixture";
  const first = {
    id: "cmd_test",
    name: "printf",
    args: ["%s", marker],
    cwd: "/vercel/sandbox",
    sessionId,
    exitCode: null,
    startedAt: 1,
  };
  const final = { ...first, exitCode: 0 };

  it("uses direct printf without a shell or filesystem operation", () => {
    expect(commandRequestPayload(marker)).toEqual({
      command: "printf",
      args: ["%s", marker],
      cwd: "/vercel/sandbox",
      env: {},
      sudo: false,
      wait: true,
      logs: true,
      timeout: 5_000,
    });
  });

  it("requires coherent command envelopes, exact stdout, and exit zero", () => {
    const exact = Buffer.from([
      JSON.stringify({ command: first }),
      JSON.stringify({ stream: "stdout", data: marker }),
      JSON.stringify({ command: final }),
      "",
    ].join("\n"));
    expect(parseCommandResponse(exact, sessionId, marker)).toMatchObject({
      exact: true,
      lineCount: 3,
      stdoutBytes: Buffer.byteLength(marker),
      stderrBytes: 0,
      finalExitCode: 0,
      sessionIdMatched: true,
      commandShapeMatched: true,
    });

    const onlyEchoedInArgs = Buffer.from([
      JSON.stringify({ command: first }),
      JSON.stringify({ command: final }),
      "",
    ].join("\n"));
    expect(parseCommandResponse(onlyEchoedInArgs, sessionId, marker).exact).toBe(false);

    const wrongSession = Buffer.from([
      JSON.stringify({ command: { ...first, sessionId: "foreign" } }),
      JSON.stringify({ stream: "stdout", data: marker }),
      JSON.stringify({ command: { ...final, sessionId: "foreign" } }),
      "",
    ].join("\n"));
    expect(parseCommandResponse(wrongSession, sessionId, marker)).toMatchObject({
      exact: false,
      sessionIdMatched: false,
    });
  });
});
