import { randomUUID } from "node:crypto";
import { lstat, readFile, unlink } from "node:fs/promises";
import { afterEach, describe, expect, it } from "vitest";
import {
  acquireSbx053Lock,
  createSbx053Journal,
  parseSbx053Journal,
  persistSbx053Journal,
  readSbx053Journal,
  releaseSbx053LockAndJournal,
  safeSbx053Error,
  sbx053ArtifactPath,
  sbx053RecoveryArtifactPath,
  SBX053_LIVE_LOCK,
  SBX053_UNKNOWN_CREATE_SETTLEMENT_MS,
  unknownCreateSettlementReached,
  writeSbx053PrivateArtifact,
} from "../pocs/SBX-053/safety.js";

const cleanupPaths = new Set<string>();

afterEach(async () => {
  await Promise.all([...cleanupPaths].map((path) => unlink(path).catch(() => undefined)));
  cleanupPaths.clear();
});

describe("SBX-053 safety", () => {
  it("round-trips only an exact secret-free recovery journal", () => {
    const journal = createSbx053Journal(new Date("2026-08-19T00:00:00.000Z"),
      "12345678-1234-4abc-8def-1234567890ab");
    expect(parseSbx053Journal(structuredClone(journal))).toEqual(journal);
    expect(JSON.stringify(journal)).not.toMatch(/token|password|secret|credential|digest/iu);
    expect(() => parseSbx053Journal({ ...journal, extra: true })).toThrow(/fields/u);
    expect(() => parseSbx053Journal({ ...journal, tags: { ...journal.tags, role: "other" } }))
      .toThrow(/invalid/u);
    expect(() => parseSbx053Journal({ ...journal, sessionId: "bad" })).toThrow(/invalid/u);
  });

  it("keeps unknown create outcomes indeterminate until the full settlement horizon", () => {
    const attemptedAt = "2026-08-19T00:00:00.000Z";
    const journal = { ...createSbx053Journal(new Date(attemptedAt)), createAttemptedAt: attemptedAt };
    const base = Date.parse(attemptedAt);
    expect(unknownCreateSettlementReached(journal, base + SBX053_UNKNOWN_CREATE_SETTLEMENT_MS - 1)).toBe(false);
    expect(unknownCreateSettlementReached(journal, base + SBX053_UNKNOWN_CREATE_SETTLEMENT_MS)).toBe(true);
    expect(unknownCreateSettlementReached({ ...journal, sessionId: "sbx_abcdefghijklmnop" },
      base + SBX053_UNKNOWN_CREATE_SETTLEMENT_MS)).toBe(false);
  });

  it("uses exact mode-0600 lock/journal files and releases them in retry-safe order", async () => {
    const journal = createSbx053Journal();
    const lock = await acquireSbx053Lock(journal);
    cleanupPaths.add(lock.lockPath);
    cleanupPaths.add(lock.journalPath);
    expect(lock.lockPath).toBe(SBX053_LIVE_LOCK);
    expect(lock.lockMode).toBe(0o600);
    expect(lock.journalMode).toBe(0o600);
    journal.createAttemptedAt = new Date().toISOString();
    await persistSbx053Journal(lock, journal);
    expect(await readSbx053Journal(journal.runId)).toMatchObject({
      runId: journal.runId,
      createAttemptedAt: journal.createAttemptedAt,
    });
    await expect(releaseSbx053LockAndJournal(lock, async () => {
      throw new Error("injected journal unlink failure");
    })).rejects.toThrow(/journal unlink failure/u);
    expect(lock.liveLock.isReleased()).toBe(false);
    await expect(lstat(lock.lockPath)).resolves.toBeDefined();
    await expect(lstat(lock.journalPath)).resolves.toBeDefined();
    await expect(lstat(`${lock.lockPath}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
    await releaseSbx053LockAndJournal(lock);
    await expect(lstat(lock.lockPath)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(lock.journalPath)).rejects.toMatchObject({ code: "ENOENT" });
    cleanupPaths.delete(lock.lockPath);
    cleanupPaths.delete(lock.journalPath);
  });

  it("never overwrites experiment evidence with a recovery-only artifact", async () => {
    const runId = randomUUID();
    const experiment = sbx053ArtifactPath(runId);
    const recoveryAttemptId = randomUUID();
    const recovery = sbx053RecoveryArtifactPath(runId, recoveryAttemptId);
    const successfulAttemptId = randomUUID();
    const successfulRecovery = sbx053RecoveryArtifactPath(runId, successfulAttemptId);
    cleanupPaths.add(experiment);
    cleanupPaths.add(recovery);
    cleanupPaths.add(successfulRecovery);
    expect(experiment).not.toBe(recovery);
    await writeSbx053PrivateArtifact(experiment, { runId, kind: "experiment" });
    await writeSbx053PrivateArtifact(recovery, {
      runId,
      recoveryAttemptId,
      recoveryOnly: true,
      kind: "recovery",
    });
    await writeSbx053PrivateArtifact(successfulRecovery, {
      runId,
      recoveryAttemptId: successfulAttemptId,
      recoveryOnly: true,
      kind: "successful-recovery",
    });
    expect(JSON.parse(await readFile(experiment, "utf8"))).toMatchObject({ kind: "experiment" });
    expect(JSON.parse(await readFile(recovery, "utf8"))).toMatchObject({ kind: "recovery" });
    expect(JSON.parse(await readFile(successfulRecovery, "utf8")))
      .toMatchObject({ kind: "successful-recovery" });
    expect((await lstat(experiment)).mode & 0o777).toBe(0o600);
    expect((await lstat(recovery)).mode & 0o777).toBe(0o600);
    expect((await lstat(successfulRecovery)).mode & 0o777).toBe(0o600);
    await expect(writeSbx053PrivateArtifact(experiment, { runId, kind: "overwrite" }))
      .rejects.toMatchObject({ code: "EEXIST" });
  });

  it("redacts forbidden material from bounded error text", () => {
    const secret = "vcp_this-must-not-leak";
    const result = safeSbx053Error(new Error(`failed with ${secret}\nsecond line`), [secret]);
    expect(result).not.toContain(secret);
    expect(result).toContain("<redacted>");
    expect(result).not.toContain("\n");
    expect(result.length).toBeLessThanOrEqual(512);
  });
});
