import { randomUUID } from "node:crypto";
import { APIError, Sandbox } from "@vercel/sandbox";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanupSbx053Exact,
  runSbx053Recovery,
  sbx053ChronologyIsCanonical,
  type Sbx053RecoveryConfig,
  type Sbx053RecoveryRuntime,
} from "../pocs/SBX-053/git-source-credential-retention.js";
import {
  createSettlementReached,
  createSbx053Journal,
  SBX053_UNKNOWN_CREATE_SETTLEMENT_MS,
  type Sbx053HeldLock,
} from "../pocs/SBX-053/safety.js";

const VERCEL_TOKEN = "offline_vercel_recovery_token_ABCDEFGHIJKLMNOPQRSTUVWXYZ";

afterEach(() => {
  vi.restoreAllMocks();
});

function config(): Sbx053RecoveryConfig {
  return {
    vercelToken: VERCEL_TOKEN,
    teamId: "team_n98ERpVwV7HqmWRudAyK8sXQ",
    projectId: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    expectedAlias: "swve@wearehackerone.com",
    recoveryRunId: "12345678-1234-4abc-8def-1234567890ab",
  };
}

function fakeLock(runId: string): Sbx053HeldLock {
  return {
    runId,
    lockPath: "/offline/SBX-053.lock",
    journalPath: `/offline/SBX-053-${runId}.json`,
    lockMode: 0o600,
    journalMode: 0o600,
    liveLock: {
      runId,
      path: "/offline/SBX-053.lock",
      isReleased: () => false,
      closeRetainingState: async () => undefined,
      releaseAfter: async () => undefined,
      release: async () => undefined,
    },
  };
}

function runtime(input: {
  journal: ReturnType<typeof createSbx053Journal>;
  resume?: boolean;
  cleanup?: Sbx053RecoveryRuntime["cleanup"];
}) {
  const artifact = { value: undefined as unknown };
  const verifyIdentity = vi.fn(async () => undefined);
  const acquireLock = vi.fn(async (runId: string) => fakeLock(runId));
  const readJournal = vi.fn(async () => input.journal);
  const cleanup = vi.fn(input.cleanup ?? (async () => true));
  const persist = vi.fn(async () => undefined);
  const release = vi.fn(async () => undefined);
  const closeRetainingState = vi.fn(async () => undefined);
  const overrides: Partial<Sbx053RecoveryRuntime> = {
    newAttemptId: randomUUID,
    resumeInterruptedFinalization: vi.fn(async () => input.resume ?? false),
    acquireLock,
    readJournal,
    verifyIdentity,
    cleanup,
    persist,
    release,
    closeRetainingState,
    writeArtifact: vi.fn(async (_path, value) => {
      artifact.value = value;
      return 0o600;
    }),
  };
  return {
    overrides,
    artifact,
    verifyIdentity,
    acquireLock,
    readJournal,
    cleanup,
    persist,
    release,
    closeRetainingState,
  };
}

describe("SBX-053 cleanup-only recovery", () => {
  it("completes a pre-create journal locally without Git material or identity/network work", async () => {
    const journal = createSbx053Journal(new Date(), config().recoveryRunId);
    const controls = runtime({ journal });
    const result = await runSbx053Recovery(config(), journal.runId, controls.overrides);
    expect(result).toMatchObject({
      recoveryOnly: true,
      outcome: "cleanup-complete",
      cleanup: {
        liveLockReleased: true,
        recoveryJournalDeleted: true,
      },
    });
    expect(controls.verifyIdentity).not.toHaveBeenCalled();
    expect(controls.cleanup).toHaveBeenCalledWith(expect.objectContaining({
      allowSettledUnknownAbsence: true,
    }));
    expect(JSON.stringify(controls.artifact.value)).not.toContain(VERCEL_TOKEN);
    expect(controls.artifact.value).not.toHaveProperty("assessment");
    const chronology = (controls.artifact.value as { chronology: Parameters<
      typeof sbx053ChronologyIsCanonical>[0] }).chronology;
    expect(sbx053ChronologyIsCanonical(chronology)).toBe(true);
  });

  it("retains an unknown late-create journal until the full settlement horizon", async () => {
    const attempted = Date.now();
    const earlyJournal = createSbx053Journal(new Date(attempted), config().recoveryRunId);
    earlyJournal.createAttemptedAt = new Date(attempted).toISOString();
    const early = runtime({
      journal: earlyJournal,
      cleanup: async ({ journal }) => createSettlementReached(journal, attempted +
        SBX053_UNKNOWN_CREATE_SETTLEMENT_MS - 1),
    });
    const earlyResult = await runSbx053Recovery(config(), earlyJournal.runId, early.overrides);
    expect(earlyResult.outcome).toBe("cleanup-incomplete");
    expect(early.verifyIdentity).toHaveBeenCalledOnce();
    expect(early.release).not.toHaveBeenCalled();
    expect(early.closeRetainingState).toHaveBeenCalledOnce();

    const settled = runtime({
      journal: earlyJournal,
      cleanup: async ({ journal }) => createSettlementReached(journal, attempted +
        SBX053_UNKNOWN_CREATE_SETTLEMENT_MS),
    });
    const settledResult = await runSbx053Recovery(config(), earlyJournal.runId, settled.overrides);
    expect(settledResult.outcome).toBe("cleanup-complete");
    expect(settled.release).toHaveBeenCalledOnce();
  });

  it("finishes a journal-committed release locally before attempting ordinary recovery", async () => {
    const journal = createSbx053Journal(new Date(), config().recoveryRunId);
    const controls = runtime({ journal, resume: true });
    const result = await runSbx053Recovery(config(), journal.runId, controls.overrides);
    expect(result.outcome).toBe("cleanup-complete");
    expect(controls.acquireLock).not.toHaveBeenCalled();
    expect(controls.readJournal).not.toHaveBeenCalled();
    expect(controls.verifyIdentity).not.toHaveBeenCalled();
    expect(controls.cleanup).not.toHaveBeenCalled();
    expect(controls.artifact.value).toMatchObject({
      interruptedFinalizationResumed: true,
      retention: {
        vulnerabilityVerdictEmitted: false,
        experimentEvidenceOverwritten: false,
      },
    });
  });
});

describe("SBX-053 exact late-create cleanup", () => {
  it("does not accept an early 404, then requires three exact 404s and a prefix-list absence", async () => {
    const now = Date.now();
    const early = createSbx053Journal(new Date(now), config().recoveryRunId);
    early.createAttemptedAt = new Date(now).toISOString();
    const get = vi.spyOn(Sandbox, "get").mockRejectedValue(
      new APIError(new Response(null, { status: 404 })),
    );
    const list = vi.spyOn(Sandbox, "list").mockResolvedValue({
      toArray: async () => [],
    } as never);
    const earlyEvidence = {
      createUnknown: false,
      recoveredByExactName: false,
      stopAttempted: false,
      stopped: false,
      deleteAttempted: false,
      deleted: false,
      absenceChecks: 0,
      prefixListAbsent: false,
      liveLockReleased: false,
      recoveryJournalDeleted: false,
    };
    await expect(cleanupSbx053Exact({
      config: config(),
      journal: early,
      lock: fakeLock(early.runId),
      allowSettledUnknownAbsence: true,
      evidence: earlyEvidence,
      persistOverride: async () => undefined,
    })).resolves.toBe(false);
    expect(earlyEvidence.createUnknown).toBe(true);
    expect(get).toHaveBeenCalledOnce();
    expect(list).not.toHaveBeenCalled();

    get.mockClear();
    const attempted = now - SBX053_UNKNOWN_CREATE_SETTLEMENT_MS;
    const settled = createSbx053Journal(new Date(attempted), config().recoveryRunId);
    settled.createAttemptedAt = new Date(attempted).toISOString();
    const settledEvidence = { ...earlyEvidence, createUnknown: false };
    await expect(cleanupSbx053Exact({
      config: config(),
      journal: settled,
      lock: fakeLock(settled.runId),
      allowSettledUnknownAbsence: true,
      evidence: settledEvidence,
      persistOverride: async () => undefined,
    })).resolves.toBe(true);
    expect(get).toHaveBeenCalledTimes(4);
    expect(list).toHaveBeenCalledOnce();
    expect(settledEvidence).toMatchObject({
      createUnknown: false,
      absenceChecks: 3,
      prefixListAbsent: true,
    });
    expect(settled).toMatchObject({
      absenceChecks: 3,
      prefixListAbsent: true,
    });
  });
});
