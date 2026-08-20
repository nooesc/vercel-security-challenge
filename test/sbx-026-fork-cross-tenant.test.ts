import { describe, expect, it, vi } from "vitest";
import {
  allKnownSnapshotsDirectlyAbsent,
  assessRequestAudit,
  buildCrossForkBody,
  createRunNames,
  exactTags,
  finalizeForkEvidenceAfterLiveLockRelease,
  forkLiveLockOptions,
  parseAcceptedForkPayload,
  releaseNeutralForkEvidenceState,
  requiresDelayedSecondAbsence,
  resolveForkRunIntent,
  resourceTags,
  sandboxCleanupCallsAuthorized,
} from "../pocs/SBX-026/fork-cross-tenant.js";
import {
  assessForkAuthorization,
  type ForkAuthorizationAssessmentInput,
} from "../pocs/SBX-026/fork-verdict.js";
import {
  conclusiveAuthorizationRejection,
  type RequestAuditRecord,
} from "../pocs/SBX-026/shared.js";

const runId = "123e4567-e89b-42d3-a456-426614174000";

function baseAssessment(): ForkAuthorizationAssessmentInput {
  return {
    setupError: false,
    cleanupPassed: true,
    requestAuditPassed: true,
    identitiesVerifiedAndDistinct: true,
    attackerOwnerForkControlPassed: true,
    victimOwnerForkControlPassed: true,
    distinctSourceAndSessionIds: true,
    victimOnlyCanaryAttribution: true,
    victimSourceValidImmediatelyBefore: true,
    victimSourceValidImmediatelyAfter: true,
    crossForkRequestAttempts: 1,
    crossForkAccepted: false,
    crossForkRejected: true,
    crossForkRejectionConclusive: true,
    crossForkResponseAttributable: false,
    crossKnownPathReadAttempts: 0,
    exactSyntheticVictimCanaryMatched: false,
    stopAtConfirmationPreserved: true,
  };
}

describe("SBX-026 fork authorization verdict", () => {
  it("passes only a single conclusive authorization rejection", () => {
    expect(assessForkAuthorization(baseAssessment())).toMatchObject({
      verdict: "pass",
      candidate: false,
      controlsPassed: true,
    });
  });

  it("requires exact synthetic victim content for a candidate", () => {
    expect(assessForkAuthorization({
      ...baseAssessment(),
      crossForkAccepted: true,
      crossForkRejected: false,
      crossForkRejectionConclusive: false,
      crossForkResponseAttributable: true,
      crossKnownPathReadAttempts: 1,
      exactSyntheticVictimCanaryMatched: true,
    })).toMatchObject({
      verdict: "candidate",
      candidate: true,
      controlsPassed: true,
    });
  });

  it("does not promote accepted fork creation without exact data attribution", () => {
    for (const patch of [
      { crossForkResponseAttributable: false },
      { crossKnownPathReadAttempts: 0 },
      { exactSyntheticVictimCanaryMatched: false },
    ]) {
      expect(assessForkAuthorization({
        ...baseAssessment(),
        crossForkAccepted: true,
        crossForkRejected: false,
        crossForkRejectionConclusive: false,
        crossForkResponseAttributable: true,
        crossKnownPathReadAttempts: 1,
        exactSyntheticVictimCanaryMatched: true,
        ...patch,
      })).toMatchObject({ verdict: "indeterminate", candidate: false });
    }
  });

  it("requires both owner controls and immediate pre/post source validity", () => {
    for (const field of [
      "identitiesVerifiedAndDistinct",
      "attackerOwnerForkControlPassed",
      "victimOwnerForkControlPassed",
      "distinctSourceAndSessionIds",
      "victimOnlyCanaryAttribution",
      "victimSourceValidImmediatelyBefore",
      "victimSourceValidImmediatelyAfter",
      "requestAuditPassed",
    ] as const) {
      expect(assessForkAuthorization({
        ...baseAssessment(),
        [field]: false,
      })).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
    }
  });

  it("fails closed on multiple cross attempts, impossible outcomes, or post-confirmation testing", () => {
    for (const patch of [
      { crossForkRequestAttempts: 2 },
      { crossKnownPathReadAttempts: 2 },
      { crossKnownPathReadAttempts: 1, crossForkAccepted: false },
      { crossForkAccepted: true, crossForkRejected: true },
      { stopAtConfirmationPreserved: false },
      { cleanupPassed: false },
      { setupError: true },
    ]) {
      expect(assessForkAuthorization({
        ...baseAssessment(),
        ...patch,
      })).toMatchObject({ verdict: "error", candidate: false });
    }
  });

  it("does not treat 401 or 410 as a conclusive scoped authorization result", () => {
    expect(conclusiveAuthorizationRejection({ kind: "api", status: 401 })).toBe(false);
    expect(conclusiveAuthorizationRejection({ kind: "api", status: 410 })).toBe(false);
    expect(conclusiveAuthorizationRejection({ kind: "api", status: 403 })).toBe(true);
    expect(conclusiveAuthorizationRejection({ kind: "api", status: 404 })).toBe(true);
  });
});

describe("SBX-026 fork packet construction", () => {
  it("uses the complete UUID in every deterministic resource name", () => {
    const names = createRunNames(runId);
    for (const name of Object.values(names)) {
      expect(name).toContain(runId);
      expect(name.length).toBeLessThanOrEqual(128);
    }
    expect(() => createRunNames(runId.slice(0, 8))).toThrow(/UUIDv4/u);
  });

  it("makes every supplied or reused run ID cleanup-only", () => {
    expect(resolveForkRunIntent({ SBX026_FORK_RUN_ID: runId })).toEqual({
      runId,
      cleanupOnly: true,
      suppliedRunId: true,
    });
    expect(() => resolveForkRunIntent({ SBX026_FORK_RUN_ID: runId.slice(0, 8) }))
      .toThrow(/UUIDv4/u);
  });

  it("requires a delayed second absence for an attempted create without a live handle", () => {
    expect(requiresDelayedSecondAbsence(true, false)).toBe(true);
    expect(requiresDelayedSecondAbsence(true, true)).toBe(false);
    expect(requiresDelayedSecondAbsence(false, false)).toBe(false);
  });

  it("refuses every Sandbox cleanup call unless both exact identities are distinct", () => {
    expect(sandboxCleanupCallsAuthorized(true, true, true)).toBe(true);
    expect(sandboxCleanupCallsAuthorized(false, true, true)).toBe(false);
    expect(sandboxCleanupCallsAuthorized(true, false, true)).toBe(false);
    expect(sandboxCleanupCallsAuthorized(true, true, false)).toBe(false);
  });

  it("requires direct absence confirmation for every known snapshot ID", () => {
    const known = ["snap_one12345", "snap_two12345"];
    expect(allKnownSnapshotsDirectlyAbsent(known, known)).toBe(true);
    expect(allKnownSnapshotsDirectlyAbsent(known, [known[0]!])).toBe(false);
    // A collection/list 404 cannot be passed to or substitute for direct ID evidence.
    expect(allKnownSnapshotsDirectlyAbsent(known, [])).toBe(false);
  });

  it("maps fresh and recovery runs to the shared fork lock modes", () => {
    expect(forkLiveLockOptions({
      runId,
      cleanupOnly: false,
      suppliedRunId: false,
    })).toEqual({ scope: "fork", runId, mode: "normal" });
    expect(forkLiveLockOptions({
      runId,
      cleanupOnly: true,
      suppliedRunId: true,
    })).toEqual({ scope: "fork", runId, mode: "cleanup-only" });
  });

  it("builds an empty-env, nonpersistent, deny-all raw fork body", () => {
    const tags = resourceTags(runId, "cross-fork");
    const body = buildCrossForkBody(createRunNames(runId).crossFork, tags);
    expect(body).toMatchObject({
      name: createRunNames(runId).crossFork,
      persistent: false,
      networkPolicy: { mode: "deny-all" },
      env: {},
      tags,
    });
    expect(JSON.stringify(body)).not.toContain("TOKEN");
  });

  it("requires an exact full tag set before cleanup", () => {
    const tags = resourceTags(runId, "victim-source");
    expect(exactTags({ ...tags }, tags)).toBe(true);
    expect(exactTags({ ...tags, extra: "no" }, tags)).toBe(false);
    expect(exactTags({ ...tags, run: "wrong" }, tags)).toBe(false);
    expect(exactTags(undefined, tags)).toBe(false);
  });

  it("accepts only a fully attributable exact-victim-snapshot fork response", () => {
    const targetName = createRunNames(runId).crossFork;
    const tags = resourceTags(runId, "cross-fork");
    const createdAt = 1_750;
    const payload = {
      sandbox: {
        name: targetName,
        currentSessionId: "sbx_12345678",
        createdAt,
        persistent: false,
        tags,
        networkPolicy: { mode: "deny-all" },
      },
      session: {
        id: "sbx_12345678",
        sourceSnapshotId: "snap_1234567890123456789012345678",
        networkPolicy: { mode: "deny-all" },
      },
    };
    const expected = {
      targetName,
      sourceSnapshotId: payload.session.sourceSnapshotId,
      tags,
      earliestCreatedAtMs: 1_000,
      latestCreatedAtMs: 2_000,
    };
    expect(parseAcceptedForkPayload(
      payload,
      expected,
    )).toMatchObject({
      targetName,
      sessionId: "sbx_12345678",
      sourceSnapshotId: payload.session.sourceSnapshotId,
      exactTags: true,
      denyAll: true,
      persistent: false,
    });
    expect(parseAcceptedForkPayload(
      { ...payload, sandbox: { name: "wrong" } },
      expected,
    )).toBeUndefined();
    expect(parseAcceptedForkPayload(
      { ...payload, session: { ...payload.session, sourceSnapshotId: "snap_wrong" } },
      expected,
    )).toBeUndefined();
    expect(parseAcceptedForkPayload(
      { ...payload, sandbox: { ...payload.sandbox, tags: { ...tags, extra: "no" } } },
      expected,
    )).toBeUndefined();
    expect(parseAcceptedForkPayload(
      { ...payload, sandbox: { ...payload.sandbox, currentSessionId: "sbx_different" } },
      expected,
    )).toBeUndefined();
  });
});

describe("SBX-026 global request audit", () => {
  function record(
    sequence: number,
    startedAtMs: number,
    method: string,
    pathname: string,
  ): RequestAuditRecord {
    return {
      sequence,
      startedAt: new Date(startedAtMs).toISOString(),
      completedAt: new Date(startedAtMs + 10).toISOString(),
      method,
      origin: "vercel-sandbox-control-plane",
      pathname,
      status: 403,
    };
  }

  it("proves one raw fork and at most one raw known-path read", () => {
    const forkPath = `/api/v2/sandboxes/${createRunNames(runId).victimSource}/fork`;
    const readPath = "/api/v2/sandboxes/sessions/sbx_12345678/fs/read";
    const records = [
      record(1, 1_000, "GET", "/api/v2/sandboxes"),
      // The victim owner-control fork legitimately has the same method/path as
      // the later attacker-scoped request.
      record(2, 1_250, "POST", forkPath),
      record(3, 1_500, "GET", "/api/v2/sandboxes"),
      record(4, 1_750, "POST", forkPath),
      record(5, 2_000, "GET", `/api/v2/sandboxes/${createRunNames(runId).victimSource}`),
      record(6, 2_250, "POST", readPath),
    ];
    expect(assessRequestAudit(records, {
      crossForkPath: forkPath,
      crossForkAttempts: 1,
      foreignCrossForkSequence: 4,
      crossReadPath: readPath,
      crossReadAttempts: 1,
    })).toMatchObject({ passed: true });

    expect(assessRequestAudit(records, {
      crossForkPath: forkPath,
      crossForkAttempts: 1,
      foreignCrossForkSequence: 3,
      crossReadPath: readPath,
      crossReadAttempts: 1,
    })).toMatchObject({ passed: false, exactCrossForkCount: false });

    expect(assessRequestAudit(records, {
      crossForkPath: forkPath,
      crossForkAttempts: 2,
      foreignCrossForkSequence: 4,
      crossReadPath: readPath,
      crossReadAttempts: 1,
    })).toMatchObject({ passed: false, exactCrossForkCount: false });
  });

  it("fails on non-contiguous, unfinished, or over-rate records", () => {
    const forkPath = `/api/v2/sandboxes/${createRunNames(runId).victimSource}/fork`;
    const good = [record(1, 1_000, "POST", forkPath)];
    const missingCompletion = [{ ...good[0]! }];
    delete missingCompletion[0]!.completedAt;
    const wrongSequence = [{ ...good[0]!, sequence: 2 }];
    const tooFast = [...good, record(2, 1_100, "GET", "/api/v2/sandboxes")];
    const expected = {
      crossForkPath: forkPath,
      crossForkAttempts: 1,
      foreignCrossForkSequence: 1,
      crossReadAttempts: 0,
    };
    expect(assessRequestAudit(missingCompletion, expected).passed).toBe(false);
    expect(assessRequestAudit(wrongSequence, expected).passed).toBe(false);
    expect(assessRequestAudit(tooFast, expected).passed).toBe(false);
  });
});

describe("SBX-026 fork evidence finalization", () => {
  const candidateAssessment = {
    verdict: "candidate" as const,
    candidate: true,
    controlsPassed: true,
    summary: "synthetic candidate",
  };

  function pendingEvidence(): Record<string, unknown> {
    return {
      ...releaseNeutralForkEvidenceState(true, true),
      recovery: { liveLock: { releasedAfterEvidenceWrite: false } },
    };
  }

  it("never returns or mutates an effective candidate when live-lock release fails", async () => {
    const staged = pendingEvidence();
    const release = vi.fn(async () => {
      throw new Error("injected release failure");
    });

    await expect(finalizeForkEvidenceAfterLiveLockRelease(
      staged,
      "/private/pending.json",
      { release },
      true,
      candidateAssessment,
      "2026-08-19T00:00:00.000Z",
    )).rejects.toThrow(/injected release failure/u);

    expect(release).toHaveBeenCalledOnce();
    expect(staged).toMatchObject({
      assessment: { verdict: "indeterminate", candidate: false },
      finalization: { candidate: false, finalAssessmentRetained: false },
      recovery: { liveLock: { releasedAfterEvidenceWrite: false } },
    });
    expect(staged).not.toHaveProperty("cleanupPassed");
  });

  it("returns a final verdict only after successful live-lock release", async () => {
    const release = vi.fn(async () => undefined);
    const result = await finalizeForkEvidenceAfterLiveLockRelease(
      pendingEvidence(),
      "/private/pending.json",
      { release },
      true,
      candidateAssessment,
      "2026-08-19T00:00:00.000Z",
    );

    expect(release).toHaveBeenCalledOnce();
    expect(result).toMatchObject({
      completedAt: "2026-08-19T00:00:00.000Z",
      cleanupPassed: true,
      assessment: candidateAssessment,
      finalization: { status: "complete", liveLockReleasedBeforeVerdict: true },
      recovery: { liveLock: { releasedAfterEvidenceWrite: true } },
    });
  });

  it("keeps an unresolved recovery neutral without attempting release", async () => {
    const release = vi.fn(async () => undefined);
    const result = await finalizeForkEvidenceAfterLiveLockRelease(
      pendingEvidence(),
      "/private/pending.json",
      { release },
      false,
      candidateAssessment,
    );

    expect(release).not.toHaveBeenCalled();
    expect(result).toMatchObject({
      assessment: { verdict: "indeterminate", candidate: false },
      finalization: { candidate: false, finalAssessmentRetained: false },
      recovery: { liveLock: { releasedAfterEvidenceWrite: false } },
    });
    expect(result).not.toHaveProperty("cleanupPassed");
  });
});
