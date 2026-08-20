import { randomUUID } from "node:crypto";
import { lstat, readFile, unlink } from "node:fs/promises";
import { afterEach, describe, expect, it } from "vitest";
import {
  acquireSbx052Lock,
  createSbx052Journal,
  loadSbx052Config,
  parseSbx052Journal,
  persistSbx052Journal,
  readSbx052Journal,
  releaseSbx052LockAndJournal,
  safeSbx052Error,
  sbx052ArtifactPath,
  sbx052RecoveryArtifactPath,
  SBX052_LIVE_LOCK,
  SBX052_SCOPE_CONFIRMATION,
  SBX052_UNKNOWN_CREATE_SETTLEMENT_MS,
  unknownCreateSettlementReached,
  writeSbx052PrivateArtifact,
} from "../pocs/SBX-052/safety.js";

const cleanupPaths = new Set<string>();

function environment(): NodeJS.ProcessEnv {
  return {
    VERCEL_TOKEN: "vcp_abcdefghijklmnopqrstuvwxyz0123456789",
    VERCEL_TEAM_ID: "team_n98ERpVwV7HqmWRudAyK8sXQ",
    VERCEL_PROJECT_ID: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    SBX052_ALIAS_EMAIL_CONFIRMATION: "swve@wearehackerone.com",
    SBX052_SCOPE_CONFIRMATION,
  };
}

afterEach(async () => {
  await Promise.all([...cleanupPaths].map((path) => unlink(path).catch(() => undefined)));
  cleanupPaths.clear();
});

describe("SBX-052 safety", () => {
  it("accepts only the exact alias/team/project/scope and an opaque PAT", () => {
    expect(loadSbx052Config(environment())).toMatchObject({
      expectedAlias: "swve@wearehackerone.com",
      teamId: "team_n98ERpVwV7HqmWRudAyK8sXQ",
      projectId: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    });
    expect(() => loadSbx052Config({ ...environment(), VERCEL_TEAM_ID: "team_other" })).toThrow(/eligible/u);
    expect(() => loadSbx052Config({ ...environment(), SBX052_SCOPE_CONFIRMATION: "yes" })).toThrow(/attestation/u);
    expect(() => loadSbx052Config({ ...environment(), VERCEL_TOKEN: "a.b.c" })).toThrow(/opaque/u);
    expect(() => loadSbx052Config({ ...environment(), HTTPS_PROXY: "http://127.0.0.1:1" }))
      .toThrow(/transport override/u);
    expect(() => loadSbx052Config({ ...environment(), NODE_TLS_REJECT_UNAUTHORIZED: "0" }))
      .toThrow(/transport override/u);
  });

  it("round-trips only an exact secret-free recovery journal", () => {
    const journal = createSbx052Journal(new Date("2026-08-19T00:00:00.000Z"),
      "12345678-1234-4abc-8def-1234567890ab");
    expect(parseSbx052Journal(structuredClone(journal))).toEqual(journal);
    expect(JSON.stringify(journal)).not.toMatch(/token|bootId|canary|digest/iu);
    expect(() => parseSbx052Journal({ ...journal, extra: true })).toThrow(/fields/u);
    expect(() => parseSbx052Journal({ ...journal, tags: { ...journal.tags, role: "other" } }))
      .toThrow(/invalid/u);
    expect(() => parseSbx052Journal({ ...journal, sessionId: "bad" })).toThrow(/invalid/u);
  });

  it("keeps unknown create outcomes indeterminate until the full settlement horizon", () => {
    const attemptedAt = "2026-08-19T00:00:00.000Z";
    const journal = { ...createSbx052Journal(new Date(attemptedAt)), createAttemptedAt: attemptedAt };
    const base = Date.parse(attemptedAt);
    expect(unknownCreateSettlementReached(journal, base + SBX052_UNKNOWN_CREATE_SETTLEMENT_MS - 1)).toBe(false);
    expect(unknownCreateSettlementReached(journal, base + SBX052_UNKNOWN_CREATE_SETTLEMENT_MS)).toBe(true);
    expect(unknownCreateSettlementReached({ ...journal, sessionId: "sbx_abcdefghijklmnop" },
      base + SBX052_UNKNOWN_CREATE_SETTLEMENT_MS)).toBe(false);
  });

  it("uses exact mode-0600 lock/journal files and releases them in retry-safe order", async () => {
    const journal = createSbx052Journal();
    const lock = await acquireSbx052Lock(journal);
    cleanupPaths.add(lock.lockPath);
    cleanupPaths.add(lock.journalPath);
    expect(lock.lockPath).toBe(SBX052_LIVE_LOCK);
    expect(lock.lockMode).toBe(0o600);
    expect(lock.journalMode).toBe(0o600);
    journal.createAttemptedAt = new Date().toISOString();
    await persistSbx052Journal(lock, journal);
    expect(await readSbx052Journal(journal.runId)).toMatchObject({
      runId: journal.runId,
      createAttemptedAt: journal.createAttemptedAt,
    });
    await expect(releaseSbx052LockAndJournal(lock, async () => {
      throw new Error("injected journal unlink failure");
    })).rejects.toThrow(/journal unlink failure/u);
    expect(lock.liveLock.isReleased()).toBe(false);
    await expect(lstat(lock.lockPath)).resolves.toBeDefined();
    await expect(lstat(lock.journalPath)).resolves.toBeDefined();
    await expect(lstat(`${lock.lockPath}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
    await releaseSbx052LockAndJournal(lock);
    await expect(lstat(lock.lockPath)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(lock.journalPath)).rejects.toMatchObject({ code: "ENOENT" });
    cleanupPaths.delete(lock.lockPath);
    cleanupPaths.delete(lock.journalPath);
  });

  it("never overwrites experiment evidence with a recovery-only artifact", async () => {
    const runId = randomUUID();
    const experiment = sbx052ArtifactPath(runId);
    const recoveryAttemptId = randomUUID();
    const recovery = sbx052RecoveryArtifactPath(runId, recoveryAttemptId);
    const successfulAttemptId = randomUUID();
    const successfulRecovery = sbx052RecoveryArtifactPath(runId, successfulAttemptId);
    cleanupPaths.add(experiment);
    cleanupPaths.add(recovery);
    cleanupPaths.add(successfulRecovery);
    expect(experiment).not.toBe(recovery);
    await writeSbx052PrivateArtifact(experiment, { runId, kind: "experiment" });
    await writeSbx052PrivateArtifact(recovery, {
      runId,
      recoveryAttemptId,
      recoveryOnly: true,
      kind: "recovery",
    });
    await writeSbx052PrivateArtifact(successfulRecovery, {
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
    await expect(writeSbx052PrivateArtifact(experiment, { runId, kind: "overwrite" }))
      .rejects.toMatchObject({ code: "EEXIST" });
  });

  it("redacts forbidden material from bounded error text", () => {
    const secret = "vcp_this-must-not-leak";
    const result = safeSbx052Error(new Error(`failed with ${secret}\nsecond line`), [secret]);
    expect(result).not.toContain(secret);
    expect(result).toContain("<redacted>");
    expect(result).not.toContain("\n");
    expect(result.length).toBeLessThanOrEqual(512);
  });
});
