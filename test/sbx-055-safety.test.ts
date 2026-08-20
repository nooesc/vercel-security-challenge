import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { lstat, readFile, unlink, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  SBX055_ALIAS,
  SBX055_LIVE_LOCK,
  SBX055_PROJECT,
  SBX055_SCOPE_CONFIRMATION,
  SBX055_TEAM,
  acquireSbx055Lock,
  acquireSbx055RecoveryLock,
  createSettlementReached,
  createSbx055Journal,
  loadSbx055Config,
  parseSbx055Journal,
  persistSbx055Journal,
  readSbx055Journal,
  releaseSbx055LockAndJournal,
  safeSbx055Error,
  sbx055ArtifactPath,
  sbx055JournalPath,
  sbx055RecoveryArtifactPath,
  writeSbx055PrivateArtifact,
  zeroExternalStateJournal,
} from "../pocs/SBX-055/safety.js";

const cleanupPaths = new Set<string>();
const repositoryDirectory = resolve(".");
const safetyModuleUrl = pathToFileURL(
  resolve(repositoryDirectory, "pocs/SBX-055/safety.ts"),
).href;

async function runOneShot(source: string): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const child = spawn(process.execPath, [
    "--import", "tsx", "--input-type=module", "--eval", source,
  ], { cwd: repositoryDirectory, env: { ...process.env }, stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => { stdout += chunk; });
  child.stderr.on("data", (chunk: string) => { stderr += chunk; });
  const code = await new Promise<number | null>((resolveExit, rejectExit) => {
    child.once("error", rejectExit);
    child.once("exit", resolveExit);
  });
  return { code, stdout, stderr };
}

afterEach(async () => {
  await Promise.all([...cleanupPaths].map((path) => unlink(path).catch(() => undefined)));
  cleanupPaths.clear();
});

function environment(): NodeJS.ProcessEnv {
  return {
    SBX055_SCOPE_CONFIRMATION: SBX055_SCOPE_CONFIRMATION,
    SBX055_EXPECTED_ALIAS: SBX055_ALIAS,
    VERCEL_TEAM_ID: SBX055_TEAM,
    VERCEL_PROJECT_ID: SBX055_PROJECT,
    VERCEL_TOKEN: "offline_opaque_vercel_pat_for_sbx055",
  };
}

describe.sequential("SBX-055 safety", () => {
  it("requires the exact alias/team/project/attestation and refuses runtime trust injection", () => {
    expect(loadSbx055Config(environment())).toMatchObject({
      expectedAlias: SBX055_ALIAS,
      teamId: SBX055_TEAM,
      projectId: SBX055_PROJECT,
    });
    for (const patch of [
      { SBX055_SCOPE_CONFIRMATION: "wrong" },
      { SBX055_EXPECTED_ALIAS: "other@example.test" },
      { VERCEL_TEAM_ID: "team_other" },
      { VERCEL_PROJECT_ID: "prj_other" },
      { NODE_TLS_REJECT_UNAUTHORIZED: "0" },
      { NODE_OPTIONS: "--require=/tmp/unsafe" },
      { SSL_CERT_FILE: "/tmp/custom.pem" },
    ]) expect(() => loadSbx055Config({ ...environment(), ...patch })).toThrow();
  });

  it("round-trips only the exact secret-free lifecycle journal", () => {
    const journal = createSbx055Journal(new Date("2026-08-19T00:00:00.000Z"),
      "12345678-1234-4abc-8def-1234567890ab");
    expect(parseSbx055Journal(structuredClone(journal))).toEqual(journal);
    expect(JSON.stringify(journal)).not.toMatch(/token|url|digest|markerValue|output/iu);
    expect(zeroExternalStateJournal(journal)).toBe(true);
    expect(() => parseSbx055Journal({ ...journal, extra: true })).toThrow(/fields/u);
    expect(() => parseSbx055Journal({ ...journal, session1Id: "bad" })).toThrow(/invalid/u);
    expect(() => parseSbx055Journal({
      ...journal,
      snapshotsObserved: ["snap_aaaaaaaaaaaaaaaaaaaa"],
      snapshotsDeleted: ["snap_aaaaaaaaaaaaaaaaaaaa"],
    })).toThrow(/invalid/u);
    expect(() => parseSbx055Journal({
      ...journal,
      snapshotDeleteIntents: ["snap_aaaaaaaaaaaaaaaaaaaa"],
    })).toThrow(/invalid/u);
    expect(() => parseSbx055Journal({
      ...journal,
      session1Id: "sbx_abcdefghijklmnopqrst",
      session2Id: "sbx_abcdefghijklmnopqrst",
    })).toThrow(/invalid/u);
  });

  it("distinguishes a pre-create zero-state journal from any attempted external state", () => {
    const journal = createSbx055Journal();
    expect(zeroExternalStateJournal(journal)).toBe(true);
    const attemptedAt = journal.startedAt;
    const attempted = { ...journal, createAttemptedAt: attemptedAt };
    expect(zeroExternalStateJournal(attempted)).toBe(false);
    expect(createSettlementReached(attempted, Date.parse(attemptedAt))).toBe(false);
  });

  it("uses exact mode-0600 lock/journal files and atomically retains them on failed release", async () => {
    const journal = createSbx055Journal();
    const lock = await acquireSbx055Lock(journal);
    cleanupPaths.add(lock.lockPath);
    cleanupPaths.add(lock.journalPath);
    expect(lock.lockPath).toBe(SBX055_LIVE_LOCK);
    expect(lock.lockMode).toBe(0o600);
    expect(lock.journalMode).toBe(0o600);
    journal.createAttemptedAt = new Date().toISOString();
    await persistSbx055Journal(lock, journal);
    expect(await readSbx055Journal(journal.runId)).toMatchObject({
      runId: journal.runId,
      createAttemptedAt: journal.createAttemptedAt,
    });
    await expect(releaseSbx055LockAndJournal(lock, async () => {
      throw new Error("injected journal unlink failure");
    })).rejects.toThrow(/journal unlink failure/u);
    expect(lock.liveLock.isReleased()).toBe(false);
    await expect(lstat(lock.lockPath)).resolves.toBeDefined();
    await expect(lstat(lock.journalPath)).resolves.toBeDefined();
    await releaseSbx055LockAndJournal(lock);
    await expect(lstat(lock.lockPath)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(lock.journalPath)).rejects.toMatchObject({ code: "ENOENT" });
    cleanupPaths.delete(lock.lockPath);
    cleanupPaths.delete(lock.journalPath);
  });

  it("preserves a pre-existing journal byte-for-byte when normal acquisition collides", async () => {
    const journal = createSbx055Journal();
    const journalPath = sbx055JournalPath(journal.runId);
    const bytes = Buffer.from(`${JSON.stringify(journal, null, 2)}\n`, "utf8");
    cleanupPaths.add(SBX055_LIVE_LOCK);
    cleanupPaths.add(`${SBX055_LIVE_LOCK}.transaction`);
    cleanupPaths.add(journalPath);
    await writeFile(journalPath, bytes, { mode: 0o600, flag: "wx" });
    await expect(acquireSbx055Lock(journal)).rejects.toMatchObject({ code: "EEXIST" });
    expect(await readFile(journalPath)).toEqual(bytes);
    expect((await lstat(journalPath)).mode & 0o777).toBe(0o600);
    await expect(lstat(SBX055_LIVE_LOCK)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(`${SBX055_LIVE_LOCK}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
    bytes.fill(0);
  });

  it("writes experiment and recovery evidence to unique no-clobber mode-0600 paths", async () => {
    const runId = randomUUID();
    const experiment = sbx055ArtifactPath(runId);
    const recoveryAttemptId = randomUUID();
    const recovery = sbx055RecoveryArtifactPath(runId, recoveryAttemptId);
    cleanupPaths.add(experiment);
    cleanupPaths.add(recovery);
    await writeSbx055PrivateArtifact(experiment, { runId, recoveryOnly: false, kind: "experiment" });
    await writeSbx055PrivateArtifact(recovery, {
      runId, recoveryAttemptId, recoveryOnly: true, kind: "cleanup-only",
    });
    expect(JSON.parse(await readFile(experiment, "utf8"))).toMatchObject({ kind: "experiment" });
    expect(JSON.parse(await readFile(recovery, "utf8"))).toMatchObject({ kind: "cleanup-only" });
    expect((await lstat(experiment)).mode & 0o777).toBe(0o600);
    expect((await lstat(recovery)).mode & 0o777).toBe(0o600);
    await expect(writeSbx055PrivateArtifact(experiment, { runId })).rejects.toMatchObject({ code: "EEXIST" });
  });

  it("durably retains a snapshot delete intent across a real process crash", async () => {
    const runId = randomUUID();
    const snapshotId = "snap_aaaaaaaaaaaaaaaaaaaa";
    const journalPath = sbx055JournalPath(runId);
    cleanupPaths.add(SBX055_LIVE_LOCK);
    cleanupPaths.add(`${SBX055_LIVE_LOCK}.transaction`);
    cleanupPaths.add(journalPath);
    const crashed = await runOneShot(`
const safety = await import(${JSON.stringify(safetyModuleUrl)});
const journal = safety.createSbx055Journal(new Date(), ${JSON.stringify(runId)});
const lock = await safety.acquireSbx055Lock(journal);
journal.snapshotsObserved.push(${JSON.stringify(snapshotId)});
journal.snapshotDeleteIntents.push(${JSON.stringify(snapshotId)});
await safety.persistSbx055Journal(lock, journal);
process.exit(79);
`);
    expect(crashed).toMatchObject({ code: 79, stderr: "" });
    const persisted = await readSbx055Journal(runId);
    expect(persisted.snapshotDeleteIntents).toEqual([snapshotId]);
    expect(persisted.snapshotsDeleted).toEqual([]);

    const recovered = await acquireSbx055RecoveryLock(runId);
    const recoveryJournal = await readSbx055Journal(runId);
    recoveryJournal.snapshotsDeleted.push(snapshotId);
    await persistSbx055Journal(recovered, recoveryJournal);
    expect((await readSbx055Journal(runId)).snapshotsDeleted).toEqual([snapshotId]);
    await releaseSbx055LockAndJournal(recovered);
    cleanupPaths.delete(SBX055_LIVE_LOCK);
    cleanupPaths.delete(`${SBX055_LIVE_LOCK}.transaction`);
    cleanupPaths.delete(journalPath);
  });

  it("redacts forbidden material from bounded error text", () => {
    const secret = "capability-that-must-not-leak";
    const safe = safeSbx055Error(new Error(`failed ${secret}\nagain`), [secret]);
    expect(safe).not.toContain(secret);
    expect(safe).toContain("<redacted>");
    expect(safe).not.toContain("\n");
    expect(safe.length).toBeLessThanOrEqual(512);
  });
});
