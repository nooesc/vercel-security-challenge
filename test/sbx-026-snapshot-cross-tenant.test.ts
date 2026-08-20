import { describe, expect, it, vi } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import {
  assessSnapshotAuthorization,
  type SnapshotAuthorizationAssessmentInput,
} from "../pocs/SBX-026/verdict.js";
import {
  hasValidZeroAttemptSnapshotRecoveryDescriptor,
  hasConfirmedAmbiguousCreateAbsence,
  parseAcceptedRestoreResponse,
  parseSnapshotRecoveryManifest,
  publishSnapshotEvidenceBeforeRelease,
  removeSnapshotRecoveryManifestIfAuthorized,
  resolveSnapshotRunIntent,
  runSnapshotCleanupOnly,
  runSnapshotCleanupSequence,
  settleInitialSnapshotJournalFailure,
  snapshotCleanupProofSufficient,
  snapshotEvidenceAssessmentForPublication,
  snapshotFinalizationPassed,
  snapshotRecoveryManifestRemovalAuthorized,
  snapshotRunNames,
  validateSnapshot,
} from "../pocs/SBX-026/snapshot-cross-tenant.js";
import {
  SBX026_LIVE_LOCK_PATH,
  type ExplicitAccountCredentials,
} from "../pocs/SBX-026/shared.js";

const runId = "11111111-1111-4111-8111-111111111111";
const otherRunId = "22222222-2222-4222-8222-222222222222";
const attackerUserHash = "a".repeat(64);
const victimUserHash = "b".repeat(64);

function accountFixtures(): {
  attacker: ExplicitAccountCredentials;
  victim: ExplicitAccountCredentials;
} {
  return {
    attacker: {
      role: "attacker",
      token: "attacker-token-value-0000000000000000",
      teamId: "team_Attacker",
      projectId: "prj_Attacker",
      expectedEmail: "attacker@wearehackerone.com",
    },
    victim: {
      role: "victim",
      token: "victim-token-value-000000000000000000",
      teamId: "team_Victim",
      projectId: "prj_Victim",
      expectedEmail: "victim@wearehackerone.com",
    },
  };
}

function recoveryManifestFixture(): Record<string, unknown> {
  const names = snapshotRunNames(runId);
  const attackerSourceSessionId = `sbx_${"A".repeat(20)}`;
  const attackerRestoreSessionId = `sbx_${"B".repeat(20)}`;
  const victimSourceSessionId = `sbx_${"C".repeat(20)}`;
  const victimRestoreSessionId = `sbx_${"D".repeat(20)}`;
  const crossSessionId = `sbx_${"E".repeat(20)}`;
  const attackerSnapshotId = `snap_${"A".repeat(20)}`;
  const victimSnapshotId = `snap_${"B".repeat(20)}`;
  const entry = (
    role: string,
    accountRole: "attacker" | "victim",
    name: string,
    sourceSnapshotId: string | undefined,
    sessionId: string,
  ) => ({
    role,
    accountRole,
    name,
    tags: { test: "SBX-026", run: runId, role },
    creationAttempted: true,
    ...(sourceSnapshotId ? { expectedSourceSnapshotId: sourceSnapshotId } : {}),
    expectedSessionId: sessionId,
  });
  return {
    schemaVersion: 2,
    testId: "SBX-026",
    packet: "snapshot",
    runId,
    startedAt: new Date(Date.now() - 1_000).toISOString(),
    accounts: {
      attacker: {
        teamId: "team_Attacker",
        projectId: "prj_Attacker",
        expectedEmail: "attacker@wearehackerone.com",
        userIdSha256: attackerUserHash,
      },
      victim: {
        teamId: "team_Victim",
        projectId: "prj_Victim",
        expectedEmail: "victim@wearehackerone.com",
        userIdSha256: victimUserHash,
      },
    },
    crossAccountAttempt: {
      destinationName: names.crossDestination,
      creationAttempted: true,
      requestMayHaveBeenSentWhenTrue: true,
      retriesAllowed: false,
    },
    sandboxes: [
      entry("attacker-source-control", "attacker", names.attackerSource, undefined,
        attackerSourceSessionId),
      entry("attacker-restore-control", "attacker", names.attackerRestore, attackerSnapshotId,
        attackerRestoreSessionId),
      entry("victim-source", "victim", names.victimSource, undefined, victimSourceSessionId),
      entry("victim-restore-control", "victim", names.victimRestore, victimSnapshotId,
        victimRestoreSessionId),
      entry("cross-destination", "attacker", names.crossDestination, victimSnapshotId,
        crossSessionId),
    ],
    snapshots: [
      {
        role: "attacker-control-snapshot",
        accountRole: "attacker",
        sourceSandboxName: names.attackerSource,
        creationAttempted: true,
        sourceSessionId: attackerSourceSessionId,
        snapshotId: attackerSnapshotId,
      },
      {
        role: "victim-snapshot",
        accountRole: "victim",
        sourceSandboxName: names.victimSource,
        creationAttempted: true,
        sourceSessionId: victimSourceSessionId,
        snapshotId: victimSnapshotId,
      },
    ],
    rawCanariesRetained: false,
    tokensRetained: false,
  };
}

function zeroAttemptRecoveryManifestFixture(): Record<string, unknown> {
  const manifest = recoveryManifestFixture();
  for (const account of Object.values(
    manifest.accounts as Record<string, Record<string, unknown>>,
  )) {
    delete account.userIdSha256;
  }
  (manifest.crossAccountAttempt as Record<string, unknown>).creationAttempted = false;
  manifest.sandboxes = (manifest.sandboxes as Array<Record<string, unknown>>).map((entry) => ({
    role: entry.role,
    accountRole: entry.accountRole,
    name: entry.name,
    tags: entry.tags,
    creationAttempted: false,
  }));
  manifest.snapshots = (manifest.snapshots as Array<Record<string, unknown>>).map((entry) => ({
    role: entry.role,
    accountRole: entry.accountRole,
    sourceSandboxName: entry.sourceSandboxName,
    creationAttempted: false,
  }));
  return manifest;
}

function cleanupOnlyFailureInput(
  attackerFetch: typeof fetch,
  victimFetch: typeof fetch,
  recoveryPath: string,
): unknown {
  const unreachableTarget = { absenceConfirmed: false };
  return {
    intent: { runId, cleanupOnly: true },
    startedAt: new Date().toISOString(),
    recoveryPath,
    evidencePath: `${recoveryPath}.evidence`,
    lock: {
      path: `${recoveryPath}.lock`,
      metadata: {
        schemaVersion: 1,
        testId: "SBX-026",
        scope: "snapshot",
        runId,
        pid: process.pid,
        lease: "A".repeat(43),
        createdAt: new Date().toISOString(),
        mode: "cleanup-only",
      },
      reclaimed: false,
      release: vi.fn(async () => undefined),
    },
    accounts: accountFixtures(),
    attackerFetch,
    victimFetch,
    gate: { records: [] },
    sandboxTargets: [],
    snapshotTargets: [],
    attackerSource: unreachableTarget,
    attackerRestore: unreachableTarget,
    victimSource: unreachableTarget,
    victimRestore: unreachableTarget,
    crossDestination: unreachableTarget,
    attackerSnapshot: unreachableTarget,
    victimSnapshot: unreachableTarget,
  };
}

function baseInput(): SnapshotAuthorizationAssessmentInput {
  return {
    setupError: false,
    cleanupPassed: true,
    identitiesVerifiedDistinct: true,
    ownerSessionsVerifiedDistinct: true,
    attackerSameAccountRestoreControlPassed: true,
    victimSameAccountRestoreControlPassed: true,
    victimSnapshotValidBeforeAttack: true,
    victimSnapshotValidAfterAttack: true,
    crossRestoreCallAttempts: 1,
    crossRestoreRequestAttempts: 1,
    crossKnownPathReadCallAttempts: 0,
    crossKnownPathReadAttempts: 0,
    attackCreateRejected: true,
    attackRejectionConclusive: true,
    crossDestinationObserved: false,
    attackerCloneCreated: false,
    attackerCloneReadbackPassed: false,
    attackerCloneSourceSnapshotMatched: false,
    attackerReadAttempted: false,
    exactSyntheticCanaryMatched: false,
  };
}

describe("SBX-026 snapshot authorization verdict", () => {
  it("passes only after one clean rejection and a valid post-attack snapshot control", () => {
    expect(assessSnapshotAuthorization(baseInput())).toMatchObject({
      verdict: "pass",
      candidate: false,
      controlsPassed: true,
    });
    expect(assessSnapshotAuthorization({
      ...baseInput(),
      victimSnapshotValidAfterAttack: false,
    })).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
  });

  it("requires both exact identities and both same-account restore controls", () => {
    for (const field of [
      "identitiesVerifiedDistinct",
      "ownerSessionsVerifiedDistinct",
      "attackerSameAccountRestoreControlPassed",
      "victimSameAccountRestoreControlPassed",
      "victimSnapshotValidBeforeAttack",
      "victimSnapshotValidAfterAttack",
    ] as const) {
      expect(assessSnapshotAuthorization({
        ...baseInput(),
        [field]: false,
      })).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
    }
  });

  it("requires one restore, one read, exact source attribution, and independent clone readback", () => {
    const candidate = {
      ...baseInput(),
      crossKnownPathReadCallAttempts: 1,
      crossKnownPathReadAttempts: 1,
      attackCreateRejected: false,
      attackRejectionConclusive: false,
      crossDestinationObserved: true,
      attackerCloneCreated: true,
      attackerCloneReadbackPassed: true,
      attackerCloneSourceSnapshotMatched: true,
      attackerReadAttempted: true,
      exactSyntheticCanaryMatched: true,
    } satisfies SnapshotAuthorizationAssessmentInput;
    expect(assessSnapshotAuthorization(candidate)).toMatchObject({
      verdict: "candidate",
      candidate: true,
      controlsPassed: true,
    });

    for (const patch of [
      {
        attackerCloneReadbackPassed: false,
        attackerCloneSourceSnapshotMatched: false,
        attackerReadAttempted: false,
        crossKnownPathReadCallAttempts: 0,
        crossKnownPathReadAttempts: 0,
        exactSyntheticCanaryMatched: false,
      },
      {
        attackerCloneSourceSnapshotMatched: false,
        attackerReadAttempted: false,
        crossKnownPathReadCallAttempts: 0,
        crossKnownPathReadAttempts: 0,
        exactSyntheticCanaryMatched: false,
      },
      { exactSyntheticCanaryMatched: false },
    ]) {
      expect(assessSnapshotAuthorization({ ...candidate, ...patch })).toMatchObject({
        verdict: "indeterminate",
        candidate: false,
      });
    }
  });

  it("treats retries and call/transport counter mismatches as safety errors", () => {
    for (const patch of [
      { crossRestoreCallAttempts: 2, crossRestoreRequestAttempts: 2 },
      { crossRestoreCallAttempts: 1, crossRestoreRequestAttempts: 0 },
      { crossKnownPathReadCallAttempts: 2, crossKnownPathReadAttempts: 2 },
      { crossKnownPathReadCallAttempts: 1, crossKnownPathReadAttempts: 0 },
      { crossKnownPathReadCallAttempts: -1, crossKnownPathReadAttempts: -1 },
      { crossRestoreCallAttempts: Number.NaN, crossRestoreRequestAttempts: Number.NaN },
      { crossRestoreCallAttempts: 0.5, crossRestoreRequestAttempts: 0.5 },
    ]) {
      expect(assessSnapshotAuthorization({ ...baseInput(), ...patch })).toMatchObject({
        verdict: "error",
        candidate: false,
        controlsPassed: false,
      });
    }
  });

  it("rejects contradictory accepted-and-rejected states", () => {
    expect(assessSnapshotAuthorization({
      ...baseInput(),
      crossDestinationObserved: true,
      attackerCloneCreated: true,
      attackerCloneReadbackPassed: true,
      attackerCloneSourceSnapshotMatched: true,
    })).toMatchObject({ verdict: "error", candidate: false });
    expect(assessSnapshotAuthorization({
      ...baseInput(),
      crossKnownPathReadCallAttempts: 1,
      crossKnownPathReadAttempts: 1,
      attackerReadAttempted: true,
    })).toMatchObject({ verdict: "error", candidate: false });
    expect(assessSnapshotAuthorization({
      ...baseInput(),
      crossDestinationObserved: true,
    })).toMatchObject({ verdict: "indeterminate", candidate: false });
  });

  it("treats cleanup or setup failures as errors", () => {
    expect(assessSnapshotAuthorization({
      ...baseInput(),
      cleanupPassed: false,
    })).toMatchObject({ verdict: "error" });
    expect(assessSnapshotAuthorization({
      ...baseInput(),
      setupError: true,
    })).toMatchObject({ verdict: "error" });
  });
});

describe("SBX-026 accepted restore parser", () => {
  it("accepts only the exact name, tags, session, source snapshot, policy, and time window", () => {
    const expected = {
      name: "s26x-0123456789abcdef0123456789abcdef",
      snapshotId: "snap_victim",
      tags: { test: "SBX-026", run: "run", role: "cross-destination" },
      earliestCreatedAtMs: 1_000,
      latestCreatedAtMs: 2_000,
    };
    const payload = {
      sandbox: {
        name: expected.name,
        currentSessionId: "sbx_session",
        createdAt: 1_500,
        tags: expected.tags,
        networkPolicy: { mode: "deny-all" },
      },
      session: {
        id: "sbx_session",
        sourceSnapshotId: expected.snapshotId,
        networkPolicy: { mode: "deny-all" },
      },
    };
    expect(parseAcceptedRestoreResponse(payload, expected)).toMatchObject({
      name: expected.name,
      sessionId: "sbx_session",
      sourceSnapshotMatched: true,
      tagsMatched: true,
      networkPolicyDenyAll: true,
    });
    expect(() => parseAcceptedRestoreResponse({
      ...payload,
      session: { ...payload.session, sourceSnapshotId: "snap_other" },
    }, expected)).toThrow(/source snapshot/u);
    expect(() => parseAcceptedRestoreResponse({
      ...payload,
      sandbox: { ...payload.sandbox, createdAt: 9_000 },
    }, expected)).toThrow(/creation time/u);
    expect(() => parseAcceptedRestoreResponse({
      ...payload,
      sandbox: { ...payload.sandbox, name: "s26x-wrong" },
    }, expected)).toThrow(/sandbox name/u);
    expect(() => parseAcceptedRestoreResponse({
      ...payload,
      session: { ...payload.session, id: "sbx_other" },
    }, expected)).toThrow(/session attribution/u);
    expect(() => parseAcceptedRestoreResponse({
      ...payload,
      sandbox: { ...payload.sandbox, tags: { ...expected.tags, extra: "untrusted" } },
    }, expected)).toThrow(/tags/u);
    expect(() => parseAcceptedRestoreResponse({
      ...payload,
      session: { ...payload.session, networkPolicy: { mode: "allow-all" } },
    }, expected)).toThrow(/deny-all/u);
  });
});

describe("SBX-026 ambiguous create cleanup", () => {
  it("requires two absence observations and rejects malformed counters", () => {
    expect(hasConfirmedAmbiguousCreateAbsence(0)).toBe(false);
    expect(hasConfirmedAmbiguousCreateAbsence(1)).toBe(false);
    expect(hasConfirmedAmbiguousCreateAbsence(2)).toBe(true);
    expect(hasConfirmedAmbiguousCreateAbsence(Number.NaN)).toBe(false);
    expect(hasConfirmedAmbiguousCreateAbsence(1.5)).toBe(false);
  });
});

describe("SBX-026 snapshot identity binding", () => {
  it("requires Snapshot.get to return the exact requested snapshot ID", () => {
    const now = Date.now();
    const expectedSnapshotId = `snap_${"A".repeat(20)}`;
    const expectedSessionId = `sbx_${"A".repeat(20)}`;
    const valid = {
      snapshotId: expectedSnapshotId,
      sourceSessionId: expectedSessionId,
      status: "created" as const,
      createdAt: new Date(now),
      expiresAt: new Date(now + 60 * 60_000),
    };
    expect(validateSnapshot(valid, expectedSnapshotId, expectedSessionId, now)).toMatchObject({
      snapshotId: expectedSnapshotId,
      sourceSessionId: expectedSessionId,
    });
    expect(() => validateSnapshot(
      { ...valid, snapshotId: `snap_${"B".repeat(20)}` },
      expectedSnapshotId,
      expectedSessionId,
      now,
    )).toThrow(/snapshot ID attribution/u);
  });
});

describe("SBX-026 canonical live lock and no-replay intent", () => {
  it("uses one fixed repository lock path independent of the artifacts override", () => {
    const expected = resolve(
      dirname(fileURLToPath(import.meta.url)),
      "../artifacts/SBX-026-live-active.lock",
    );
    expect(SBX026_LIVE_LOCK_PATH).toBe(expected);
    expect(SBX026_LIVE_LOCK_PATH).not.toContain("custom-artifacts");
  });

  it("turns every supplied run ID into cleanup-only mode", () => {
    expect(resolveSnapshotRunIntent({ SBX026_RUN_ID: runId })).toEqual({
      runId,
      cleanupOnly: true,
    });
    expect(resolveSnapshotRunIntent({})).toMatchObject({ cleanupOnly: false });
    expect(() => resolveSnapshotRunIntent({ SBX026_RUN_ID: "not-a-run" })).toThrow(/UUIDv4/u);
  });

});

describe("SBX-026 exact cleanup-only recovery manifest", () => {
  const intent = { runId, cleanupOnly: true } as const;
  const identityHashes = { attacker: attackerUserHash, victim: victimUserHash };

  it("accepts only the exact deterministic account/resource manifest", () => {
    const parsed = parseSnapshotRecoveryManifest(
      recoveryManifestFixture(),
      intent,
      accountFixtures(),
      identityHashes,
    );
    expect(parsed).toMatchObject({
      testId: "SBX-026",
      packet: "snapshot",
      runId,
      crossAccountAttempt: { creationAttempted: true, retriesAllowed: false },
      rawCanariesRetained: false,
      tokensRetained: false,
    });
  });

  it("rejects replay, foreign scope, foreign tags, and missing identity bindings", () => {
    const replay = recoveryManifestFixture();
    replay.runId = otherRunId;
    expect(() => parseSnapshotRecoveryManifest(
      replay,
      intent,
      accountFixtures(),
      identityHashes,
    )).toThrow(/exact snapshot run/u);

    const foreignScope = recoveryManifestFixture();
    (foreignScope.accounts as { attacker: { teamId: string } }).attacker.teamId = "team_Foreign";
    expect(() => parseSnapshotRecoveryManifest(
      foreignScope,
      intent,
      accountFixtures(),
      identityHashes,
    )).toThrow(/account binding/u);

    const foreignTags = recoveryManifestFixture();
    const sandboxes = foreignTags.sandboxes as Array<{ tags: Record<string, string> }>;
    sandboxes[4]!.tags.run = otherRunId;
    expect(() => parseSnapshotRecoveryManifest(
      foreignTags,
      intent,
      accountFixtures(),
      identityHashes,
    )).toThrow(/attribution/u);

    const unbound = recoveryManifestFixture();
    delete (unbound.accounts as { attacker: { userIdSha256?: string } }).attacker.userIdSha256;
    expect(() => parseSnapshotRecoveryManifest(
      unbound,
      intent,
      accountFixtures(),
      identityHashes,
    )).toThrow(/identity bindings/u);
  });

  it("rejects cross-owner plans and duplicate live identifiers before cleanup dispatch", () => {
    const foreignOwner = recoveryManifestFixture();
    const foreignOwnerSandboxes = foreignOwner.sandboxes as Array<{ accountRole: string }>;
    foreignOwnerSandboxes[4]!.accountRole = "victim";
    expect(() => parseSnapshotRecoveryManifest(
      foreignOwner,
      intent,
      accountFixtures(),
      identityHashes,
    )).toThrow(/attribution/u);

    const duplicate = recoveryManifestFixture();
    const duplicateSandboxes = duplicate.sandboxes as Array<{ expectedSessionId: string }>;
    duplicateSandboxes[4]!.expectedSessionId = duplicateSandboxes[0]!.expectedSessionId;
    expect(() => parseSnapshotRecoveryManifest(
      duplicate,
      intent,
      accountFixtures(),
      identityHashes,
    )).toThrow(/identifiers were not distinct/u);
  });
});

describe("SBX-026 cleanup-only orchestration", () => {
  it("runs derived sandboxes before snapshots and sources", async () => {
    interface State {
      label: string;
      absenceConfirmed: boolean;
    }
    const state = (label: string): State => ({ label, absenceConfirmed: false });
    const targets = {
      crossDestination: state("cross-destination"),
      victimRestore: state("victim-restore"),
      attackerRestore: state("attacker-restore"),
      victimSnapshot: state("victim-snapshot"),
      attackerSnapshot: state("attacker-snapshot"),
      victimSource: state("victim-source"),
      attackerSource: state("attacker-source"),
    };
    const order: string[] = [];
    await runSnapshotCleanupSequence(targets, {
      cleanupSandbox: async (target) => {
        order.push(`sandbox:${target.label}`);
        target.absenceConfirmed = true;
      },
      cleanupSnapshot: async (target, derivativesAbsent) => {
        expect(derivativesAbsent).toBe(true);
        order.push(`snapshot:${target.label}`);
        target.absenceConfirmed = true;
      },
    });
    expect(order).toEqual([
      "sandbox:cross-destination",
      "sandbox:victim-restore",
      "sandbox:attacker-restore",
      "snapshot:victim-snapshot",
      "snapshot:attacker-snapshot",
      "sandbox:victim-source",
      "sandbox:attacker-source",
    ]);
  });

  it("never treats an empty direct-ID loop or one immediate list as snapshot absence", () => {
    const base = {
      creationAttempted: true,
      absenceConfirmed: true,
      directAbsenceCheckAttempted: false,
      directAbsenceConfirmed: false,
      directSnapshotIdsChecked: [] as string[],
      absenceObservations: 1,
      delayedAbsenceChecks: 0,
      ambiguousCreateAbsenceConfirmed: true,
      unsafeMetadataMismatch: false,
    };
    expect(snapshotCleanupProofSufficient(base)).toBe(false);
    expect(snapshotCleanupProofSufficient({
      ...base,
      absenceObservations: 2,
      delayedAbsenceChecks: 1,
    })).toBe(true);
    expect(snapshotCleanupProofSufficient({
      ...base,
      ambiguousCreateAbsenceConfirmed: false,
      directAbsenceCheckAttempted: true,
      directAbsenceConfirmed: true,
    })).toBe(false);
    expect(snapshotCleanupProofSufficient({
      ...base,
      ambiguousCreateAbsenceConfirmed: false,
      directAbsenceCheckAttempted: true,
      directAbsenceConfirmed: true,
      directSnapshotIdsChecked: [`snap_${"A".repeat(20)}`],
    })).toBe(true);
  });

  it("cannot finalize a pass/candidate unless resources, manifest, and owned lock finalize", () => {
    const complete = {
      resourceCleanupPassed: true,
      recoveryManifestWritten: true,
      recoveryManifestRemoved: true,
      canonicalLiveLockRemoved: true,
    };
    expect(snapshotFinalizationPassed(complete)).toBe(true);
    for (const patch of [
      { resourceCleanupPassed: false },
      { recoveryManifestRemoved: false },
      { canonicalLiveLockRemoved: false },
    ]) {
      expect(snapshotFinalizationPassed({ ...complete, ...patch })).toBe(false);
    }
  });

  it("retains the exact recovery descriptor and lock when normal-run identity verification fails", async () => {
    const removeExactManifest = vi.fn(async () => undefined);
    expect(snapshotRecoveryManifestRemovalAuthorized({
      identitiesVerifiedDistinct: false,
      resourceCleanupPassed: true,
      recoveryManifestWritten: true,
    })).toBe(false);
    await expect(removeSnapshotRecoveryManifestIfAuthorized({
      identitiesVerifiedDistinct: false,
      resourceCleanupPassed: true,
      recoveryManifestWritten: true,
    }, removeExactManifest)).resolves.toBe(false);
    expect(removeExactManifest).not.toHaveBeenCalled();
    expect(snapshotFinalizationPassed({
      resourceCleanupPassed: true,
      recoveryManifestWritten: true,
      recoveryManifestRemoved: false,
      canonicalLiveLockRemoved: false,
    })).toBe(false);
    expect(snapshotRecoveryManifestRemovalAuthorized({
      identitiesVerifiedDistinct: true,
      resourceCleanupPassed: true,
      recoveryManifestWritten: true,
    })).toBe(true);
    await expect(removeSnapshotRecoveryManifestIfAuthorized({
      identitiesVerifiedDistinct: true,
      resourceCleanupPassed: true,
      recoveryManifestWritten: true,
    }, removeExactManifest)).resolves.toBe(true);
    expect(removeExactManifest).toHaveBeenCalledOnce();
  });

  it("recognizes only an exact zero-attempt descriptor after the initial journal write fails", () => {
    const exact = zeroAttemptRecoveryManifestFixture();
    expect(hasValidZeroAttemptSnapshotRecoveryDescriptor(
      exact,
      { runId, cleanupOnly: true },
      accountFixtures(),
    )).toBe(true);

    const attempted = structuredClone(exact);
    (attempted.sandboxes as Array<Record<string, unknown>>)[0]!.creationAttempted = true;
    expect(hasValidZeroAttemptSnapshotRecoveryDescriptor(
      attempted,
      { runId, cleanupOnly: true },
      accountFixtures(),
    )).toBe(false);

    const foreign = structuredClone(exact);
    foreign.runId = otherRunId;
    expect(hasValidZeroAttemptSnapshotRecoveryDescriptor(
      foreign,
      { runId, cleanupOnly: true },
      accountFixtures(),
    )).toBe(false);
  });

  it("settles an initial journal failure without leaving a lock that lacks recovery", async () => {
    const retainedRelease = vi.fn(async () => undefined);
    const retainedClear = vi.fn(async () => true);
    const retainedRestore = vi.fn(async () => undefined);
    await expect(settleInitialSnapshotJournalFailure({
      validRecoveryDescriptor: true,
      zeroVercelState: true,
      errorEvidenceWritten: true,
      lock: { release: retainedRelease },
    }, {
      clearInvalidRecoveryFiles: retainedClear,
      restoreValidRecoveryDescriptor: retainedRestore,
    })).resolves.toBe("retained-valid-recovery");
    expect(retainedClear).not.toHaveBeenCalled();
    expect(retainedRelease).not.toHaveBeenCalled();
    expect(retainedRestore).not.toHaveBeenCalled();

    const order: string[] = [];
    await expect(settleInitialSnapshotJournalFailure({
      validRecoveryDescriptor: false,
      zeroVercelState: true,
      errorEvidenceWritten: true,
      lock: { release: async () => { order.push("release"); } },
    }, {
      clearInvalidRecoveryFiles: async () => {
        order.push("clear-exact-invalid-journal");
        return true;
      },
      restoreValidRecoveryDescriptor: async () => { order.push("restore"); },
    })).resolves.toBe("released-zero-state");
    expect(order).toEqual(["clear-exact-invalid-journal", "release"]);

    const restoreWithoutEvidence = vi.fn(async () => undefined);
    const releaseWithoutEvidence = vi.fn(async () => undefined);
    await expect(settleInitialSnapshotJournalFailure({
      validRecoveryDescriptor: false,
      zeroVercelState: true,
      errorEvidenceWritten: false,
      lock: { release: releaseWithoutEvidence },
    }, {
      clearInvalidRecoveryFiles: vi.fn(async () => true),
      restoreValidRecoveryDescriptor: restoreWithoutEvidence,
    })).resolves.toBe("retained-valid-recovery");
    expect(releaseWithoutEvidence).not.toHaveBeenCalled();
    expect(restoreWithoutEvidence).toHaveBeenCalledOnce();
  });

  it("restores a valid descriptor if zero-state shared-lock release fails", async () => {
    const restore = vi.fn(async () => undefined);
    await expect(settleInitialSnapshotJournalFailure({
      validRecoveryDescriptor: false,
      zeroVercelState: true,
      errorEvidenceWritten: true,
      lock: { release: async () => { throw new Error("injected release failure"); } },
    }, {
      clearInvalidRecoveryFiles: async () => true,
      restoreValidRecoveryDescriptor: restore,
    })).rejects.toThrow(/injected release failure/u);
    expect(restore).toHaveBeenCalledOnce();
  });

  it("publishes a release-neutral assessment instead of a persisted pass/candidate", () => {
    for (const verdict of ["pass", "candidate"] as const) {
      expect(snapshotEvidenceAssessmentForPublication({
        verdict,
        candidate: verdict === "candidate",
        controlsPassed: true,
        summary: "would otherwise be final",
      })).toEqual({
        verdict: "pending-lock-release",
        candidate: false,
        controlsPassed: true,
        summary: "Authorization outcome remains provisional until the exact shared lock releases.",
      });
    }
  });

  it("never releases the shared lock when evidence rename or directory sync fails", async () => {
    for (const failingOperation of ["rename", "sync"] as const) {
      const release = vi.fn(async () => undefined);
      const order: string[] = [];
      await expect(publishSnapshotEvidenceBeforeRelease({
        stagedEvidencePath: "/private/staged",
        evidencePath: "/private/final",
        lock: { release },
        releaseAuthorized: true,
      }, {
        renameFile: async () => {
          order.push("rename");
          if (failingOperation === "rename") throw new Error("injected rename failure");
        },
        syncPublishedParent: async () => {
          order.push("sync");
          if (failingOperation === "sync") throw new Error("injected sync failure");
        },
      })).rejects.toThrow(new RegExp(`injected ${failingOperation} failure`, "u"));
      expect(release).not.toHaveBeenCalled();
      expect(order).toEqual(failingOperation === "rename" ? ["rename"] : ["rename", "sync"]);
    }
  });

  it("releases only after final evidence publication and directory sync", async () => {
    const order: string[] = [];
    const released = await publishSnapshotEvidenceBeforeRelease({
      stagedEvidencePath: "/private/staged",
      evidencePath: "/private/final",
      lock: { release: async () => { order.push("release"); } },
      releaseAuthorized: true,
    }, {
      renameFile: async () => { order.push("rename"); },
      syncPublishedParent: async () => { order.push("sync"); },
    });
    expect(released).toBe(true);
    expect(order).toEqual(["rename", "sync", "release"]);
  });

  it("sends zero Sandbox requests when exact identity verification fails", async () => {
    const requestedUrls: string[] = [];
    const attackerFetch = vi.fn(async (input: RequestInfo | URL) => {
      requestedUrls.push(String(input));
      return new Response(JSON.stringify({
        user: { id: "usr_attacker", email: "wrong@wearehackerone.com" },
      }), { status: 200, headers: { "content-type": "application/json" } });
    }) as unknown as typeof fetch;
    const victimFetch = vi.fn() as unknown as typeof fetch;
    await expect(runSnapshotCleanupOnly(cleanupOnlyFailureInput(
      attackerFetch,
      victimFetch,
      "/does-not-need-to-exist",
    ) as never)).rejects.toThrow(/token email/u);
    expect(requestedUrls).toHaveLength(1);
    expect(requestedUrls.every((url) => url.endsWith("/v2/user"))).toBe(true);
    expect(requestedUrls.some((url) => url.includes("/sandboxes"))).toBe(false);
    expect(victimFetch).not.toHaveBeenCalled();
  });

  it("sends zero Sandbox requests when the recovery manifest is foreign", async () => {
    const temporaryDirectory = await mkdtemp(join(tmpdir(), "sbx026-snapshot-test-"));
    const recoveryPath = join(temporaryDirectory, "foreign.json");
    const foreign = recoveryManifestFixture();
    foreign.packet = "fork";
    await writeFile(recoveryPath, `${JSON.stringify(foreign)}\n`, { mode: 0o600 });
    const requestedUrls: string[] = [];
    const identityFetch = (email: string, id: string) => vi.fn(async (input: RequestInfo | URL) => {
      requestedUrls.push(String(input));
      return new Response(JSON.stringify({ user: { id, email } }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch;
    try {
      await expect(runSnapshotCleanupOnly(cleanupOnlyFailureInput(
        identityFetch("attacker@wearehackerone.com", "usr_attacker"),
        identityFetch("victim@wearehackerone.com", "usr_victim"),
        recoveryPath,
      ) as never)).rejects.toThrow(/exact snapshot run/u);
      expect(requestedUrls).toHaveLength(2);
      expect(requestedUrls.every((url) => url.endsWith("/v2/user"))).toBe(true);
      expect(requestedUrls.some((url) => url.includes("/sandboxes"))).toBe(false);
    } finally {
      await rm(temporaryDirectory, { recursive: true, force: true });
    }
  });
});
