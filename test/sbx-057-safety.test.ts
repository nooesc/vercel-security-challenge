import { randomUUID } from "node:crypto";
import { lstat, mkdtemp, readFile, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { acquireSbx057LiveLockAtPathForTest } from "../pocs/SBX-057/live-lock.js";
import {
  SBX057_ALIAS,
  SBX057_ARTIFACTS,
  SBX057_LOCK_PATH,
  SBX057_PROJECT,
  SBX057_SCOPE_CONFIRMATION,
  SBX057_TEAM,
  acquireSbx057Lock,
  createSettlementReached,
  createSbx057Journal,
  finalizeSbx057Artifact,
  loadSbx057Config,
  parseSbx057Journal,
  persistSbx057Journal,
  readSbx057Journal,
  releaseSbx057LockAndJournal,
  safeSbx057Error,
  sbx057ArtifactPath,
  sbx057JournalPath,
  writeSbx057Artifact,
  zeroExternalState,
} from "../pocs/SBX-057/safety.js";

const cleanup = new Set<string>();

afterEach(async () => {
  await Promise.all([...cleanup].map((path) => unlink(path).catch(() => undefined)));
  cleanup.clear();
  await unlink(SBX057_LOCK_PATH).catch(() => undefined);
  await unlink(`${SBX057_LOCK_PATH}.transaction`).catch(() => undefined);
});

function environment(): NodeJS.ProcessEnv {
  return {
    SBX057_SCOPE_CONFIRMATION: SBX057_SCOPE_CONFIRMATION,
    SBX057_ALIAS_EMAIL_CONFIRMATION: SBX057_ALIAS,
    VERCEL_TEAM_ID: SBX057_TEAM,
    VERCEL_PROJECT_ID: SBX057_PROJECT,
    VERCEL_TOKEN: "offline_opaque_vercel_pat_for_sbx057",
    SBX057_ADMIN_KEY: "A".repeat(43),
    SBX057_ACTION_KEY: "B".repeat(43),
    SBX057_A_PUBLIC_ORIGIN: "https://a-sbx057.trycloudflare.com",
    SBX057_B_PUBLIC_ORIGIN: "https://b-sbx057.trycloudflare.com",
    SBX057_ADMIN_ORIGIN: "http://127.0.0.1:43159",
  };
}

describe.sequential("SBX-057 safety", () => {
  it("requires exact identity, scope, two origins, and distinct controller keys", () => {
    expect(loadSbx057Config(environment())).toMatchObject({
      alias: SBX057_ALIAS, teamId: SBX057_TEAM, projectId: SBX057_PROJECT,
    });
    for (const patch of [
      { SBX057_SCOPE_CONFIRMATION: "wrong" },
      { SBX057_ALIAS_EMAIL_CONFIRMATION: "wrong@example.test" },
      { VERCEL_TEAM_ID: "team_other" },
      { VERCEL_PROJECT_ID: "project_other" },
      { SBX057_B_PUBLIC_ORIGIN: "https://a-sbx057.trycloudflare.com" },
      { SBX057_ACTION_KEY: "A".repeat(43) },
      { NODE_TLS_REJECT_UNAUTHORIZED: "0" },
      { NODE_OPTIONS: "--require=/tmp/unsafe" },
    ]) expect(() => loadSbx057Config({ ...environment(), ...patch })).toThrow();
  });

  it("round-trips only the exact secret-free two-resource journal", () => {
    const journal = createSbx057Journal(new Date("2026-08-19T00:00:00.000Z"),
      "123e4567-e89b-42d3-a456-426614174000");
    expect(parseSbx057Journal(structuredClone(journal))).toEqual(journal);
    expect(zeroExternalState(journal)).toBe(true);
    expect(JSON.stringify(journal)).not.toContain("A".repeat(43));
    expect(JSON.stringify(journal)).not.toContain("B".repeat(43));
    expect(() => parseSbx057Journal({ ...journal, extra: true })).toThrow();
    const malformed = structuredClone(journal);
    malformed.resources[0].sessionId = "bad";
    expect(() => parseSbx057Journal(malformed)).toThrow();
    const impossible = structuredClone(journal);
    impossible.resources[0].deleted = true;
    impossible.resources[0].absenceChecks = 3;
    expect(() => parseSbx057Journal(impossible)).toThrow();
    const zeroStateComplete = structuredClone(journal);
    zeroStateComplete.receiverDeleted = true;
    zeroStateComplete.phase = "completed";
    zeroStateComplete.completed = true;
    expect(parseSbx057Journal(zeroStateComplete)).toEqual(zeroStateComplete);

    const absenceOnly = structuredClone(journal);
    absenceOnly.resources[0].createAttemptedAt = absenceOnly.startedAt;
    absenceOnly.resources[0].absenceOnlyValidated = true;
    absenceOnly.resources[0].deleted = true;
    absenceOnly.resources[0].absenceChecks = 3;
    expect(parseSbx057Journal(absenceOnly).resources[0].absenceOnlyValidated).toBe(true);
  });

  it("recognizes the conservative unknown-create settlement horizon", () => {
    const journal = createSbx057Journal(new Date("2026-08-19T00:00:00.000Z"));
    const resource = journal.resources[0];
    resource.createAttemptedAt = journal.startedAt;
    expect(createSettlementReached(resource, Date.parse(journal.startedAt))).toBe(false);
    expect(createSettlementReached(resource, Date.parse(journal.startedAt) + 1_000_000)).toBe(true);
    expect(zeroExternalState(journal)).toBe(false);
  });

  it("creates mode-0600 lock and journal and atomically removes both on release", async () => {
    const journal = createSbx057Journal();
    const lock = await acquireSbx057Lock(journal);
    cleanup.add(lock.journalPath);
    cleanup.add(lock.lockPath);
    cleanup.add(`${lock.lockPath}.transaction`);
    expect((await lstat(lock.lockPath)).mode & 0o777).toBe(0o600);
    expect((await lstat(lock.journalPath)).mode & 0o777).toBe(0o600);
    journal.phase = "cleanup";
    await persistSbx057Journal(lock, journal);
    expect((await readSbx057Journal(journal.runId)).phase).toBe("cleanup");
    await releaseSbx057LockAndJournal(lock);
    await expect(lstat(lock.lockPath)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(lock.journalPath)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(`${lock.lockPath}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("retains the canonical lock when the journal precommit cannot complete", async () => {
    const journal = createSbx057Journal();
    const lock = await acquireSbx057Lock(journal);
    cleanup.add(lock.journalPath);
    cleanup.add(lock.lockPath);
    cleanup.add(`${lock.lockPath}.transaction`);
    await unlink(lock.journalPath);
    await expect(releaseSbx057LockAndJournal(lock)).rejects.toThrow();
    expect((await lstat(lock.lockPath)).isFile()).toBe(true);
    await lock.liveLock.closeRetainingState();
  });

  it("permits exactly one concurrent O_EXCL live-lock winner", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx-057-lock-"));
    const path = join(directory, "SBX-057-live-active.lock");
    cleanup.add(path);
    cleanup.add(`${path}.transaction`);
    const firstRun = randomUUID();
    const secondRun = randomUUID();
    const results = await Promise.allSettled([
      acquireSbx057LiveLockAtPathForTest(path, firstRun, false),
      acquireSbx057LiveLockAtPathForTest(path, secondRun, false),
    ]);
    expect(results.filter((entry) => entry.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((entry) => entry.status === "rejected")).toHaveLength(1);
    const winner = results.find((entry): entry is PromiseFulfilledResult<Awaited<ReturnType<typeof acquireSbx057LiveLockAtPathForTest>>> =>
      entry.status === "fulfilled")!.value;
    await winner.release();
  });

  it("is byte-mechanically identical to the fully crash-tested SBX-055 lock after identifier normalization", async () => {
    const mature = await readFile("pocs/SBX-055/live-lock.ts", "utf8");
    const current = (await readFile("pocs/SBX-057/live-lock.ts", "utf8"))
      .replaceAll("Sbx057", "Sbx055")
      .replaceAll("sbx057", "sbx055")
      .replaceAll("SBX057", "SBX055")
      .replaceAll("SBX-057-WILDCARD-EMPTY-ISOLATION", "SBX-055-STALE-INTERACTIVE-RESUME")
      .replaceAll("SBX-057", "SBX-055");
    expect(current).toBe(mature);
  });

  it("uses a durable checkpoint then a mode-0600 same-path final replacement", async () => {
    const runId = randomUUID();
    const path = sbx057ArtifactPath(runId);
    cleanup.add(path);
    expect(await writeSbx057Artifact(runId, { finalizationPending: true, candidate: false })).toBe(0o600);
    expect(await finalizeSbx057Artifact(runId, { finalizationPending: false, outcome: "pass" })).toBe(0o600);
    expect(JSON.parse(await readFile(path, "utf8"))).toEqual({ finalizationPending: false, outcome: "pass" });
    await expect(writeSbx057Artifact(runId, {})).rejects.toMatchObject({ code: "EEXIST" });
  });

  it("redacts bounded errors without retaining forbidden values", () => {
    const secret = "controller-only-secret";
    const value = safeSbx057Error(new Error(`failure ${secret}\nnext`), [secret]);
    expect(value).toContain("<redacted>");
    expect(value).not.toContain(secret);
    expect(value).not.toContain("\n");
  });

  it("keeps all private artifacts under the repository artifact directory", () => {
    expect(sbx057JournalPath("123e4567-e89b-42d3-a456-426614174000").startsWith(SBX057_ARTIFACTS)).toBe(true);
  });
});
