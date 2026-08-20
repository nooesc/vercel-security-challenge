import { randomUUID } from "node:crypto";
import { lstat, mkdtemp, readFile, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import type { Session } from "@vercel/sandbox";
import { describe, expect, it, vi } from "vitest";
import {
  parseSbx052Cleanup,
  parseSbx052Observation,
  parseSbx052Setup,
  readBoundedSessionFile,
  runSbx052Recovery,
} from "../pocs/SBX-052/fs-namespace.js";
import {
  acquireSbx052RecoveryLockAtPathsForTest,
  createSbx052Journal,
  type Sbx052Config,
  type Sbx052HeldLock,
} from "../pocs/SBX-052/safety.js";

const RUN_ID = "12345678-1234-4abc-8def-1234567890ab";
const BOOT = "11111111-2222-4333-8444-555555555555";
const TOKEN = "vcp_sbx052-recovery-test-token-abcdefghijklmnopqrstuvwxyz";

function recoveryConfig(): Sbx052Config {
  return {
    token: TOKEN,
    teamId: "team_n98ERpVwV7HqmWRudAyK8sXQ",
    projectId: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    expectedAlias: "swve@wearehackerone.com",
  };
}

function definitelyDeadPid(): number {
  for (const candidate of [2_147_483_647, 2_147_483_646, 1_999_999_999]) {
    try {
      process.kill(candidate, 0);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ESRCH") return candidate;
    }
  }
  throw new Error("SBX-052 test could not find one definitely absent process ID");
}

async function writeStaleLiveLock(path: string, runId: string): Promise<void> {
  await writeFile(path, `${JSON.stringify({
    schemaVersion: 1,
    testId: "SBX-052-FS-NAMESPACE",
    kind: "live-lock",
    runId,
    pid: definitelyDeadPid(),
    lease: "A".repeat(43),
    createdAt: new Date().toISOString(),
    mode: "normal",
  })}\n`, { mode: 0o600, flag: "wx" });
}

function line(value: unknown): string {
  return `${JSON.stringify(value)}\n`;
}

describe("SBX-052 controller protocol", () => {
  it("parses only exact setup, observation, and cleanup messages", () => {
    expect(parseSbx052Setup(line({
      schemaVersion: 1,
      testId: "SBX-052",
      operation: "setup",
      runId: RUN_ID,
      ready: true,
      directoryMode: 0o700,
      ownedMode: 0o600,
      ownedRelativeLink: true,
      procAbsoluteLink: true,
    }), RUN_ID)).toMatchObject({ ready: true });
    expect(parseSbx052Observation(line({
      schemaVersion: 1,
      testId: "SBX-052",
      operation: "observe",
      runId: RUN_ID,
      directBootId: BOOT,
      linkedBootId: BOOT,
      directBytes: 37,
      linkedBytes: 37,
      ownedLinkTarget: "owned.txt",
      procLinkTarget: "/proc/sys/kernel/random/boot_id",
    }), RUN_ID)).toMatchObject({ directBootId: BOOT, linkedBootId: BOOT });
    expect(parseSbx052Cleanup(line({
      schemaVersion: 1,
      testId: "SBX-052",
      operation: "cleanup",
      runId: RUN_ID,
      directoryRemoved: true,
      probeRemoved: true,
    }), RUN_ID)).toMatchObject({ directoryRemoved: true, probeRemoved: true });
  });

  it("rejects extra fields, multiple lines, wrong link targets, and noncanonical boot IDs", () => {
    const valid = {
      schemaVersion: 1,
      testId: "SBX-052",
      operation: "observe",
      runId: RUN_ID,
      directBootId: BOOT,
      linkedBootId: BOOT,
      directBytes: 37,
      linkedBytes: 37,
      ownedLinkTarget: "owned.txt",
      procLinkTarget: "/proc/sys/kernel/random/boot_id",
    };
    expect(() => parseSbx052Observation(line({ ...valid, extra: true }), RUN_ID)).toThrow(/not exact/u);
    expect(() => parseSbx052Observation(`${line(valid)}${line(valid)}`, RUN_ID)).toThrow(/one bounded/u);
    expect(() => parseSbx052Observation(line({ ...valid, procLinkTarget: "/proc/self/environ" }), RUN_ID))
      .toThrow(/not exact/u);
    expect(() => parseSbx052Observation(line({ ...valid, directBootId: "not-a-uuid" }), RUN_ID))
      .toThrow(/not exact/u);
    expect(() => parseSbx052Observation(line({
      ...valid,
      directBootId: "00000000-0000-0000-0000-000000000000",
      linkedBootId: "00000000-0000-0000-0000-000000000000",
    }), RUN_ID)).toThrow(/not exact/u);
    expect(() => parseSbx052Observation(line({
      ...valid,
      directBootId: "11111111-2222-1333-8444-555555555555",
      linkedBootId: "11111111-2222-1333-8444-555555555555",
    }), RUN_ID)).toThrow(/not exact/u);
    expect(() => parseSbx052Observation(line({
      ...valid,
      directBootId: "11111111-2222-4333-7444-555555555555",
      linkedBootId: "11111111-2222-4333-7444-555555555555",
    }), RUN_ID)).toThrow(/not exact/u);
  });

  it("performs one SDK read invocation and does not claim visibility into transport retries", async () => {
    const readFileMock = vi.fn().mockResolvedValue(Readable.from([Buffer.from(`${BOOT}\n`)]));
    const result = await readBoundedSessionFile({
      session: { readFile: readFileMock } as unknown as Session,
      path: "/proc/sys/kernel/random/boot_id",
      ordinal: 5,
      caseId: "proc-direct",
      pathClass: "proc-direct",
    });
    expect(result.bytes.toString("utf8")).toBe(`${BOOT}\n`);
    expect(result.operation).toMatchObject({
      sdkInvocations: 1,
      transportAttemptsObserved: false,
      found: true,
      returnedBytes: 37,
      rawOutputRetained: false,
    });
    expect(readFileMock).toHaveBeenCalledTimes(1);
    expect(readFileMock).toHaveBeenCalledWith(
      { path: "/proc/sys/kernel/random/boot_id" },
      { signal: expect.any(AbortSignal) },
    );
  });

  it("fails closed on missing, empty, or oversized server file responses", async () => {
    const request = (value: unknown) => readBoundedSessionFile({
      session: { readFile: vi.fn().mockResolvedValue(value) } as unknown as Session,
      path: "/tmp/sbx-052-x",
      ordinal: 3,
      caseId: "owned-direct" as const,
      pathClass: "owned-file" as const,
    });
    await expect(request(null)).rejects.toThrow(/absent/u);
    await expect(request(Readable.from([]))).rejects.toThrow(/empty/u);
    await expect(request(Readable.from([Buffer.alloc(129)]))).rejects.toThrow(/byte ceiling/u);
  });

  it("locally completes an exact pre-create journal without identity or sandbox requests", async () => {
    const runId = randomUUID();
    const attemptId = randomUUID();
    const journal = createSbx052Journal(new Date(), runId);
    const fakeLock = {} as Sbx052HeldLock;
    const verifyIdentity = vi.fn(async () => undefined);
    const result = await runSbx052Recovery(recoveryConfig(), runId, {
      newAttemptId: () => attemptId,
      resumeInterruptedFinalization: async () => false,
      acquireLock: async () => fakeLock,
      readJournal: async () => journal,
      verifyIdentity,
      persistJournal: async () => undefined,
      releaseLockAndJournal: async () => undefined,
    });
    try {
      expect(result).toMatchObject({
        runId,
        recoveryAttemptId: attemptId,
        recoveryOnly: true,
        mode: "cleanup-only",
        outcome: "cleanup-complete",
        recoveryPath: "pre-create-local-only",
        zeroExternalStateProved: true,
        identityVerificationAttempted: false,
        externalCleanupPathEntered: false,
        cleanup: {
          stopAttempted: false,
          stopped: false,
          deleteAttempted: false,
          deleted: false,
          absenceChecks: 0,
          exactNameAbsent: true,
          prefixListAbsent: true,
        },
      });
      expect(verifyIdentity).not.toHaveBeenCalled();
      expect(result).not.toHaveProperty("assessment");
      expect(result).not.toHaveProperty("verdict");
      expect(result).not.toHaveProperty("controlsPassed");
      const artifact = JSON.parse(await readFile(result.evidencePath, "utf8")) as Record<string, unknown>;
      expect(artifact).toMatchObject({
        recoveryOnly: true,
        mode: "cleanup-only",
        outcome: "cleanup-complete",
        recoveryPath: "pre-create-local-only",
        zeroExternalStateProved: true,
        identityVerificationAttempted: false,
        externalCleanupPathEntered: false,
        identityAndScopePassed: false,
      });
      expect(artifact).not.toHaveProperty("assessment");
      expect(artifact).not.toHaveProperty("verdict");
      expect(artifact).not.toHaveProperty("controlsPassed");
      expect((await lstat(result.evidencePath)).mode & 0o777).toBe(0o600);
    } finally {
      await unlink(result.evidencePath).catch(() => undefined);
    }
  });

  it("replays a pre-create journal whose cleanup proof was persisted before release crashed", async () => {
    const runId = randomUUID();
    const attemptId = randomUUID();
    const journal = createSbx052Journal(new Date(), runId);
    journal.completed = true;
    const fakeLock = {} as Sbx052HeldLock;
    const verifyIdentity = vi.fn(async () => undefined);
    const persistJournal = vi.fn(async () => undefined);
    const releaseLockAndJournal = vi.fn(async () => undefined);
    const result = await runSbx052Recovery(recoveryConfig(), runId, {
      newAttemptId: () => attemptId,
      resumeInterruptedFinalization: async () => false,
      acquireLock: async () => fakeLock,
      readJournal: async () => journal,
      verifyIdentity,
      persistJournal,
      releaseLockAndJournal,
    });
    try {
      expect(result).toMatchObject({
        recoveryOnly: true,
        mode: "cleanup-only",
        outcome: "cleanup-complete",
        recoveryPath: "pre-create-local-only",
        zeroExternalStateProved: true,
        identityVerificationAttempted: false,
        externalCleanupPathEntered: false,
        cleanup: {
          stopAttempted: false,
          deleteAttempted: false,
          absenceChecks: 0,
          exactNameAbsent: true,
          prefixListAbsent: true,
          liveLockReleased: true,
          recoveryJournalDeleted: true,
        },
      });
      expect(verifyIdentity).not.toHaveBeenCalled();
      expect(persistJournal).toHaveBeenCalledOnce();
      expect(releaseLockAndJournal).toHaveBeenCalledOnce();
    } finally {
      await unlink(result.evidencePath).catch(() => undefined);
    }
  });

  it("classifies an exact interrupted release completion without reopening the journal", async () => {
    const runId = randomUUID();
    const attemptId = randomUUID();
    const acquireLock = vi.fn(async () => ({} as Sbx052HeldLock));
    const readJournal = vi.fn(async () => createSbx052Journal(new Date(), runId));
    const verifyIdentity = vi.fn(async () => undefined);
    const result = await runSbx052Recovery(recoveryConfig(), runId, {
      newAttemptId: () => attemptId,
      resumeInterruptedFinalization: async () => true,
      acquireLock,
      readJournal,
      verifyIdentity,
    });
    try {
      expect(result).toMatchObject({
        recoveryOnly: true,
        mode: "cleanup-only",
        outcome: "cleanup-complete",
        recoveryPath: "interrupted-finalization-local-only",
        zeroExternalStateProved: false,
        interruptedFinalizationProved: true,
        identityVerificationAttempted: false,
        externalCleanupPathEntered: false,
        cleanup: {
          exactNameAbsent: true,
          prefixListAbsent: true,
          liveLockReleased: true,
          recoveryJournalDeleted: true,
        },
      });
      expect(acquireLock).not.toHaveBeenCalled();
      expect(readJournal).not.toHaveBeenCalled();
      expect(verifyIdentity).not.toHaveBeenCalled();
      const artifact = JSON.parse(await readFile(result.evidencePath, "utf8")) as Record<string, unknown>;
      expect(artifact).toMatchObject({
        mode: "cleanup-only",
        outcome: "cleanup-complete",
        recoveryPath: "interrupted-finalization-local-only",
        interruptedFinalizationProved: true,
      });
    } finally {
      await unlink(result.evidencePath).catch(() => undefined);
    }
  });

  it("writes unique token-safe failure evidence around lock acquisition and journal parsing", async () => {
    const runId = randomUUID();
    const beforeLockAttempt = randomUUID();
    const afterLockAttempt = randomUUID();
    const release = vi.fn(async () => undefined);
    const closeRetainingState = vi.fn(async () => undefined);
    const readJournal = vi.fn(async () => {
      throw new Error(`malformed recovery journal ${TOKEN}`);
    });
    const before = await runSbx052Recovery(recoveryConfig(), runId, {
      newAttemptId: () => beforeLockAttempt,
      resumeInterruptedFinalization: async () => false,
      acquireLock: async () => {
        throw new Error(`live owner or missing lock ${TOKEN}`);
      },
    });
    const after = await runSbx052Recovery(recoveryConfig(), runId, {
      newAttemptId: () => afterLockAttempt,
      resumeInterruptedFinalization: async () => false,
      acquireLock: async () => ({} as Sbx052HeldLock),
      readJournal,
      releaseLockAndJournal: release,
      closeRetainingState,
    });
    try {
      expect(before).toMatchObject({
        recoveryOnly: true,
        mode: "cleanup-only",
        outcome: "cleanup-incomplete",
      });
      expect(after).toMatchObject({
        recoveryOnly: true,
        mode: "cleanup-only",
        outcome: "cleanup-incomplete",
      });
      expect(before.evidencePath).not.toBe(after.evidencePath);
      expect(readJournal).toHaveBeenCalledOnce();
      expect(release).not.toHaveBeenCalled();
      expect(closeRetainingState).toHaveBeenCalledOnce();
      for (const path of [before.evidencePath, after.evidencePath]) {
        const raw = await readFile(path, "utf8");
        expect(raw).not.toContain(TOKEN);
        expect(JSON.parse(raw)).toMatchObject({
          recoveryOnly: true,
          mode: "cleanup-only",
          outcome: "cleanup-incomplete",
          identityAndScopePassed: false,
          retention: { experimentEvidenceOverwritten: false, rawValues: false, token: false },
        });
        expect((await lstat(path)).mode & 0o777).toBe(0o600);
      }
    } finally {
      await Promise.all([before.evidencePath, after.evidencePath].map(async (path) =>
        unlink(path).catch(() => undefined)));
    }
  });

  it("refuses local pre-create completion when the journal claims later guest activity", async () => {
    const runId = randomUUID();
    const attemptId = randomUUID();
    const journal = createSbx052Journal(new Date(), runId);
    journal.guestProbeStaged = true;
    const fakeLock = {} as Sbx052HeldLock;
    const verifyIdentity = vi.fn(async () => undefined);
    const releaseLockAndJournal = vi.fn(async () => undefined);
    const closeRetainingState = vi.fn(async () => undefined);
    const result = await runSbx052Recovery(recoveryConfig(), runId, {
      newAttemptId: () => attemptId,
      resumeInterruptedFinalization: async () => false,
      acquireLock: async () => fakeLock,
      readJournal: async () => journal,
      verifyIdentity,
      persistJournal: async () => undefined,
      releaseLockAndJournal,
      closeRetainingState,
    });
    try {
      expect(result).toMatchObject({
        recoveryOnly: true,
        mode: "cleanup-only",
        outcome: "cleanup-incomplete",
        recoveryPath: "pre-create-local-only",
        zeroExternalStateProved: false,
        identityVerificationAttempted: false,
        externalCleanupPathEntered: false,
      });
      expect(verifyIdentity).not.toHaveBeenCalled();
      expect(releaseLockAndJournal).not.toHaveBeenCalled();
      expect(closeRetainingState).toHaveBeenCalledOnce();
    } finally {
      await unlink(result.evidencePath).catch(() => undefined);
    }
  });

  it("records failure after a real stale-lock reclaim finds a missing or malformed journal", async () => {
    for (const journalState of ["missing", "malformed"] as const) {
      const directory = await mkdtemp(join(tmpdir(), `sbx-052-recovery-${journalState}-`));
      const runId = randomUUID();
      const attemptId = randomUUID();
      const lockPath = join(directory, "SBX-052-live-active.lock");
      const journalPath = join(directory, `SBX-052-${runId}-recovery.json`);
      let evidencePath: string | undefined;
      try {
        await writeStaleLiveLock(lockPath, runId);
        if (journalState === "malformed") {
          await writeFile(journalPath, "{malformed\n", { mode: 0o600, flag: "wx" });
        }
        const secondJournalRead = vi.fn(async () => createSbx052Journal(new Date(), runId));
        const result = await runSbx052Recovery(recoveryConfig(), runId, {
          newAttemptId: () => attemptId,
          resumeInterruptedFinalization: async () => false,
          acquireLock: async (exactRunId) =>
            acquireSbx052RecoveryLockAtPathsForTest(exactRunId, lockPath, journalPath),
          readJournal: secondJournalRead,
        });
        evidencePath = result.evidencePath;
        expect(result).toMatchObject({
          runId,
          recoveryAttemptId: attemptId,
          recoveryOnly: true,
          mode: "cleanup-only",
          outcome: "cleanup-incomplete",
        });
        expect(secondJournalRead).not.toHaveBeenCalled();
        const retainedLock = JSON.parse(await readFile(lockPath, "utf8")) as Record<string, unknown>;
        expect(retainedLock).toMatchObject({
          runId,
          pid: process.pid,
          mode: "cleanup-only",
          kind: "live-lock",
        });
        const rawArtifact = await readFile(result.evidencePath, "utf8");
        expect(rawArtifact).not.toContain(TOKEN);
        expect(JSON.parse(rawArtifact)).toMatchObject({
          recoveryOnly: true,
          mode: "cleanup-only",
          outcome: "cleanup-incomplete",
          identityAndScopePassed: false,
        });
        expect((await lstat(result.evidencePath)).mode & 0o777).toBe(0o600);
      } finally {
        if (evidencePath !== undefined) await unlink(evidencePath).catch(() => undefined);
        await rm(directory, { recursive: true, force: true });
      }
    }
  });

  it("is import-safe and contains no top-level invocation shortcut", async () => {
    const source = await readFile("pocs/SBX-052/fs-namespace.ts", "utf8");
    expect(source).toContain("if (import.meta.url === invokedPath)");
    expect(source).not.toContain("void main()");
    await expect(import("../pocs/SBX-052/fs-namespace.js")).resolves.toBeDefined();
  });
});
