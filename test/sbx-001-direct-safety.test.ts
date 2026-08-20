import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { lstat, mkdtemp, readFile, readdir, rename, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { acquireSbx001DirectLiveLockAtPathForTest } from "../pocs/SBX-001/direct-live-lock.js";
import type { Sbx001ReceiverSnapshot } from "../pocs/SBX-001/direct-shared.js";
import {
  SBX001_DIRECT_UNKNOWN_CREATE_SETTLEMENT_MS,
  acquireSbx001DirectRecoveryStateAtPathsForTest,
  acquireSbx001DirectStateAtPathsForTest,
  createSbx001DirectJournal,
  parseSbx001DirectJournal,
  persistSbx001DirectJournalAtPathForTest,
  readSbx001DirectJournalAtPathForTest,
  releaseSbx001DirectState,
  releaseSbx001DirectStateAtPathForTest,
  resumeSbx001DirectInterruptedFinalizationAtPathsForTest,
  sbx001DirectCreateSettlementReached,
  writeSbx001DirectPrivateFileAtPathForTest,
} from "../pocs/SBX-001/direct-safety.js";

const temporaryDirectories: string[] = [];
const repositoryDirectory = resolve(".");
const liveLockModuleUrl = pathToFileURL(resolve(repositoryDirectory, "pocs/SBX-001/direct-live-lock.ts")).href;
const safetyModuleUrl = pathToFileURL(resolve(repositoryDirectory, "pocs/SBX-001/direct-safety.ts")).href;

async function runOneShot(source: string): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const child = spawn(process.execPath, [
    "--import", "tsx", "--input-type=module", "--eval", source,
  ], {
    cwd: repositoryDirectory,
    env: { ...process.env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => { stdout += chunk; });
  child.stderr.on("data", (chunk: string) => { stderr += chunk; });
  const code = await new Promise<number | null>((resolveExit, reject) => {
    child.once("error", reject);
    child.once("close", resolveExit);
  });
  return { code, stdout, stderr };
}

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

async function temporaryState(): Promise<{ directory: string; lockPath: string; journalPath: string }> {
  const directory = await mkdtemp(join(tmpdir(), "sbx-001-direct-safety-"));
  temporaryDirectories.push(directory);
  return {
    directory,
    lockPath: join(directory, "SBX-001-direct-active.lock"),
    journalPath: join(directory, "SBX-001-direct-recovery.json"),
  };
}

function finalReceiverSnapshot(runId: string): Sbx001ReceiverSnapshot {
  return {
    configured: true,
    runId,
    configuredAt: "2026-08-19T04:00:00.000Z",
    expiresAt: "2026-08-19T04:20:00.000Z",
    observationWindowMs: 1_200_000,
    receipts: [],
    arms: [],
    secretRegistered: false,
    rawQueryNamesRetained: false,
    rawSecretsRetained: false,
    rawSecretDigestsRetained: false,
  };
}

describe.sequential("SBX-001 direct durable local safety", () => {
  it("retains unknown-create uncertainty through the request plus terminal/expiry horizon", () => {
    const started = Date.parse("2026-08-19T04:00:00.000Z");
    const journal = createSbx001DirectJournal(new Date(started), randomUUID());
    journal.createAttemptedAt = new Date(started + 1_000).toISOString();
    const terminal = Date.parse(journal.createAttemptedAt) + SBX001_DIRECT_UNKNOWN_CREATE_SETTLEMENT_MS;
    expect(sbx001DirectCreateSettlementReached(journal, terminal - 1)).toBe(false);
    expect(sbx001DirectCreateSettlementReached(journal, terminal)).toBe(true);
  });

  it("keeps every before/after external mutation checkpoint recovery-parseable", () => {
    const journal = createSbx001DirectJournal(new Date("2026-08-19T04:00:00.000Z"), randomUUID());
    const checkpoint = (): void => { expect(parseSbx001DirectJournal(structuredClone(journal))).toEqual(journal); };
    checkpoint(); // Crash before receiver configure.
    journal.receiverConfigureAttemptedAt = "2026-08-19T04:00:01.000Z";
    checkpoint(); // Crash after request began, before receiver acknowledgement.
    journal.receiverConfigured = true;
    checkpoint(); // Crash after receiver configure.
    journal.createAttemptedAt = "2026-08-19T04:00:02.000Z";
    checkpoint(); // Crash after create request began, before a response.
    journal.createRequestSettledAt = "2026-08-19T04:00:03.000Z";
    journal.sessionId = "sbx_exact_owned_session";
    journal.sandboxAttributed = true;
    checkpoint(); // Crash after exact create attribution.
    journal.stopAttempted = true;
    checkpoint(); // Crash before stop acknowledgement.
    journal.stopped = true;
    checkpoint(); // Crash after stop acknowledgement.
    journal.deleteAttempted = true;
    checkpoint(); // Crash before delete acknowledgement.
    journal.deleted = true;
    journal.sandboxAbsenceChecks = 3;
    journal.sandboxPrefixAbsent = true;
    checkpoint(); // Crash after Sandbox deletion proof.
    journal.finalReceiverSnapshot = finalReceiverSnapshot(journal.runId);
    journal.finalReceiverSnapshotCaptured = true;
    journal.receiverDeleteAttempted = true;
    checkpoint(); // Crash after final snapshot, before receiver deletion.
    journal.receiverDeleted = true;
    journal.receiverAbsenceChecks = 3;
    checkpoint(); // Crash after receiver deletion proof.
    journal.artifactWriteAttemptedAt = "2026-08-19T04:00:04.000Z";
    checkpoint(); // Crash before artifact fsync.
    journal.artifactWritten = true;
    checkpoint(); // Crash after artifact fsync, before release.
    journal.completed = true;
    checkpoint();
  });

  it("writes mode-0600 fsynced no-clobber private state", async () => {
    const state = await temporaryState();
    await expect(writeSbx001DirectPrivateFileAtPathForTest(state.journalPath, {
      schemaVersion: 1,
      rawQueryNamesRetained: false,
      rawSecretsRetained: false,
    })).resolves.toBe(0o600);
    const metadata = await lstat(state.journalPath);
    expect(metadata.isFile()).toBe(true);
    expect(metadata.mode & 0o777).toBe(0o600);
    await expect(writeSbx001DirectPrivateFileAtPathForTest(state.journalPath, { replaced: true }))
      .rejects.toMatchObject({ code: "EEXIST" });
  });

  it("preserves a pre-existing journal byte-for-byte when state acquisition gets EEXIST", async () => {
    const state = await temporaryState();
    const journal = createSbx001DirectJournal(new Date(), randomUUID());
    const bytes = Buffer.from("pre-existing recovery bytes\n", "utf8");
    await writeFile(state.journalPath, bytes, { mode: 0o600, flag: "wx" });

    await expect(acquireSbx001DirectStateAtPathsForTest(
      journal,
      state.lockPath,
      state.journalPath,
    )).rejects.toMatchObject({ code: "EEXIST" });

    expect(await readFile(state.journalPath)).toEqual(bytes);
    expect((await lstat(state.journalPath)).mode & 0o777).toBe(0o600);
    await expect(lstat(state.lockPath)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(`${state.lockPath}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readdir(state.directory)).toEqual(["SBX-001-direct-recovery.json"]);
  });

  it("refuses to unlink a replacement journal and keeps the live lock precommitted for retry", async () => {
    const state = await temporaryState();
    const journal = createSbx001DirectJournal(new Date(), randomUUID());
    const held = await acquireSbx001DirectStateAtPathsForTest(
      journal,
      state.lockPath,
      state.journalPath,
    );
    const ownedPath = join(state.directory, "owned-journal");
    const replacement = Buffer.from("replacement recovery bytes\n", "utf8");
    await rename(state.journalPath, ownedPath);
    await writeFile(state.journalPath, replacement, { mode: 0o600, flag: "wx" });

    await expect(releaseSbx001DirectState(held)).rejects.toThrow(/replaced/u);
    expect(await readFile(state.journalPath)).toEqual(replacement);
    await expect(lstat(state.lockPath)).resolves.toBeDefined();
    await expect(lstat(`${state.lockPath}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });

    await unlink(state.journalPath);
    await rename(ownedPath, state.journalPath);
    await releaseSbx001DirectState(held);
    await expect(lstat(state.lockPath)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(state.journalPath)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readdir(state.directory)).toEqual([]);
  });

  it("never adopts or clobbers a journal replacement before checkpoint persistence", async () => {
    const state = await temporaryState();
    const journal = createSbx001DirectJournal(new Date(), randomUUID());
    const held = await acquireSbx001DirectStateAtPathsForTest(journal, state.lockPath, state.journalPath);
    const ownedPath = join(state.directory, "owned-journal");
    const replacement = Buffer.from("foreign journal replacement\n", "utf8");
    await rename(state.journalPath, ownedPath);
    await writeFile(state.journalPath, replacement, { mode: 0o600, flag: "wx" });
    journal.receiverConfigureAttemptedAt = new Date().toISOString();

    await expect(persistSbx001DirectJournalAtPathForTest(held, journal)).rejects.toThrow();
    expect(await readFile(state.journalPath)).toEqual(replacement);
    await unlink(state.journalPath);
    await rename(ownedPath, state.journalPath);
    await persistSbx001DirectJournalAtPathForTest(held, journal);
    expect((await readSbx001DirectJournalAtPathForTest(journal.runId, state.journalPath))
      .receiverConfigureAttemptedAt).toBe(journal.receiverConfigureAttemptedAt);
    await releaseSbx001DirectState(held);
    expect(await readdir(state.directory)).toEqual([]);
  });

  it("detects a journal pathname replacement during an open-inode checkpoint without overwriting it", async () => {
    const state = await temporaryState();
    const journal = createSbx001DirectJournal(new Date(), randomUUID());
    const held = await acquireSbx001DirectStateAtPathsForTest(journal, state.lockPath, state.journalPath);
    const ownedPath = join(state.directory, "owned-journal");
    const replacement = Buffer.from("during-checkpoint replacement\n", "utf8");
    journal.receiverConfigureAttemptedAt = new Date().toISOString();

    await expect(persistSbx001DirectJournalAtPathForTest(held, journal, async (mutation) => {
      if (mutation !== "journal-checkpoint-opened") return;
      await rename(state.journalPath, ownedPath);
      await writeFile(state.journalPath, replacement, { mode: 0o600, flag: "wx" });
    })).rejects.toThrow(/replaced during/u);
    expect(await readFile(state.journalPath)).toEqual(replacement);

    await unlink(state.journalPath);
    await rename(ownedPath, state.journalPath);
    await persistSbx001DirectJournalAtPathForTest(held, journal);
    await releaseSbx001DirectState(held);
    expect(await readdir(state.directory)).toEqual([]);
  });

  it("atomically claims a journal removal and preserves a raced claim replacement", async () => {
    const state = await temporaryState();
    const journal = createSbx001DirectJournal(new Date(), randomUUID());
    const held = await acquireSbx001DirectStateAtPathsForTest(journal, state.lockPath, state.journalPath);
    const metadata = await lstat(state.journalPath, { bigint: true });
    const claimPath = `${state.journalPath}.remove-${metadata.dev}-${metadata.ino}`;
    const ownedClaim = join(state.directory, "owned-removal-claim");
    const replacement = Buffer.from("claim pathname replacement\n", "utf8");

    await expect(releaseSbx001DirectStateAtPathForTest(held, async (mutation) => {
      if (mutation !== "journal-removal-claimed") return;
      await rename(claimPath, ownedClaim);
      await writeFile(claimPath, replacement, { mode: 0o600, flag: "wx" });
    })).rejects.toThrow(/replacement was atomically claimed/u);
    expect(await readFile(state.journalPath)).toEqual(replacement);
    await expect(lstat(state.lockPath)).resolves.toBeDefined();

    await unlink(state.journalPath);
    await rename(ownedClaim, state.journalPath);
    await releaseSbx001DirectState(held);
    expect(await readdir(state.directory)).toEqual([]);
  });

  it("keeps the owned lock while journal removal fails and retries the exact release", async () => {
    const state = await temporaryState();
    const runId = randomUUID();
    const lock = await acquireSbx001DirectLiveLockAtPathForTest(state.lockPath, runId, false);
    await writeFile(state.journalPath, "durable recovery state\n", { mode: 0o600, flag: "wx" });
    await expect(lock.releaseAfter(async () => {
      throw new Error("injected journal removal failure");
    })).rejects.toThrow(/injected journal removal/u);
    expect(lock.isReleased()).toBe(false);
    await expect(lstat(state.lockPath)).resolves.toBeDefined();
    await expect(lstat(state.journalPath)).resolves.toBeDefined();
    await lock.releaseAfter(async () => unlink(state.journalPath));
    expect(lock.isReleased()).toBe(true);
    await expect(lstat(state.lockPath)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(`${state.lockPath}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("recovers both deterministic initial journal-install child-death windows", async () => {
    for (const [index, mutation] of ["journal-install-created", "journal-installed"].entries()) {
      const state = await temporaryState();
      const runId = randomUUID();
      const crashed = await runOneShot(`
const safety = await import(${JSON.stringify(safetyModuleUrl)});
const journal = safety.createSbx001DirectJournal(new Date(), ${JSON.stringify(runId)});
await safety.acquireSbx001DirectStateAtPathsForTest(
  journal,
  ${JSON.stringify(state.lockPath)},
  ${JSON.stringify(state.journalPath)},
  async (mutation) => {
    if (mutation === ${JSON.stringify(mutation)}) process.exit(${90 + index});
  },
);
`);
      expect(crashed).toMatchObject({ code: 90 + index, stdout: "", stderr: "" });

      const recovered = await runOneShot(`
const safety = await import(${JSON.stringify(safetyModuleUrl)});
const completed = await safety.resumeSbx001DirectInterruptedFinalizationAtPathsForTest(
  ${JSON.stringify(runId)},
  ${JSON.stringify(state.lockPath)},
  ${JSON.stringify(state.journalPath)},
);
if (!completed) {
  const held = await safety.acquireSbx001DirectRecoveryStateAtPathsForTest(
    ${JSON.stringify(runId)},
    ${JSON.stringify(state.lockPath)},
    ${JSON.stringify(state.journalPath)},
  );
  await safety.releaseSbx001DirectState(held);
}
process.stdout.write(JSON.stringify({ completed }) + "\\n");
`);
      const retained = await Promise.all((await readdir(state.directory)).map(async (entry) => ({
        entry,
        mode: (await lstat(join(state.directory, entry))).mode & 0o777,
        links: (await lstat(join(state.directory, entry))).nlink,
      })));
      expect(recovered.code, `${mutation}: ${recovered.stderr} ${JSON.stringify(retained)}`).toBe(0);
      expect(recovered.stderr).toBe("");
      expect(JSON.parse(recovered.stdout)).toEqual({ completed: index === 0 });
      expect(await readdir(state.directory)).toEqual([]);
    }
  });

  it("ignores a child-killed partial checkpoint and retains a complete checkpoint", async () => {
    for (const [index, mutation] of ["journal-checkpoint-partial", "journal-checkpoint-written"].entries()) {
      const state = await temporaryState();
      const runId = randomUUID();
      const attemptedAt = "2026-08-19T05:00:00.000Z";
      const crashed = await runOneShot(`
const safety = await import(${JSON.stringify(safetyModuleUrl)});
const journal = safety.createSbx001DirectJournal(new Date("2026-08-19T04:00:00.000Z"), ${JSON.stringify(runId)});
const held = await safety.acquireSbx001DirectStateAtPathsForTest(
  journal,
  ${JSON.stringify(state.lockPath)},
  ${JSON.stringify(state.journalPath)},
);
journal.receiverConfigureAttemptedAt = ${JSON.stringify(attemptedAt)};
await safety.persistSbx001DirectJournalAtPathForTest(held, journal, async (mutation) => {
  if (mutation === ${JSON.stringify(mutation)}) process.exit(${94 + index});
});
`);
      expect(crashed).toMatchObject({ code: 94 + index, stdout: "", stderr: "" });

      const recovered = await runOneShot(`
const safety = await import(${JSON.stringify(safetyModuleUrl)});
const held = await safety.acquireSbx001DirectRecoveryStateAtPathsForTest(
  ${JSON.stringify(runId)},
  ${JSON.stringify(state.lockPath)},
  ${JSON.stringify(state.journalPath)},
);
const journal = await safety.readSbx001DirectJournalAtPathForTest(
  ${JSON.stringify(runId)},
  ${JSON.stringify(state.journalPath)},
);
await safety.releaseSbx001DirectState(held);
process.stdout.write(JSON.stringify({ attemptedAt: journal.receiverConfigureAttemptedAt ?? null }) + "\\n");
`);
      expect(recovered).toMatchObject({ code: 0, stderr: "" });
      expect(JSON.parse(recovered.stdout)).toEqual({ attemptedAt: index === 0 ? null : attemptedAt });
      expect(await readdir(state.directory)).toEqual([]);
    }
  });

  it("finishes a child death after deterministic journal removal claim with no sidecars", async () => {
    const state = await temporaryState();
    const runId = randomUUID();
    const crashed = await runOneShot(`
const safety = await import(${JSON.stringify(safetyModuleUrl)});
const journal = safety.createSbx001DirectJournal(new Date(), ${JSON.stringify(runId)});
const held = await safety.acquireSbx001DirectStateAtPathsForTest(
  journal,
  ${JSON.stringify(state.lockPath)},
  ${JSON.stringify(state.journalPath)},
);
await safety.releaseSbx001DirectStateAtPathForTest(held, async (mutation) => {
  if (mutation === "journal-removal-claimed") process.exit(97);
});
`);
    expect(crashed).toMatchObject({ code: 97, stdout: "", stderr: "" });
    expect((await readdir(state.directory)).some((entry) => entry.includes(".remove-"))).toBe(true);

    const recovered = await runOneShot(`
const safety = await import(${JSON.stringify(safetyModuleUrl)});
const completed = await safety.resumeSbx001DirectInterruptedFinalizationAtPathsForTest(
  ${JSON.stringify(runId)},
  ${JSON.stringify(state.lockPath)},
  ${JSON.stringify(state.journalPath)},
);
process.stdout.write(JSON.stringify({ completed }) + "\\n");
`);
    expect(recovered).toMatchObject({ code: 0, stdout: "{\"completed\":true}\n", stderr: "" });
    expect(await readdir(state.directory)).toEqual([]);
  });

  it("rolls back every dead normal-acquire crash phase exactly once without sidecars", async () => {
    const mutations = [
      "acquire-transaction-created",
      "acquire-replacement-created",
      "acquire-canonical-installed",
    ] as const;
    for (const [index, mutation] of mutations.entries()) {
      const state = await temporaryState();
      const runId = randomUUID();
      const crashed = await runOneShot(`
const locks = await import(${JSON.stringify(liveLockModuleUrl)});
await locks.acquireSbx001DirectLiveLockAtPathForTest(
  ${JSON.stringify(state.lockPath)},
  ${JSON.stringify(runId)},
  false,
  async (mutation) => {
    if (mutation === ${JSON.stringify(mutation)}) process.exit(${75 + index});
  },
);
`);
      expect(crashed).toMatchObject({ code: 75 + index, stdout: "", stderr: "" });
      await expect(lstat(`${state.lockPath}.transaction`)).resolves.toBeDefined();

      const recovered = await runOneShot(`
const locks = await import(${JSON.stringify(liveLockModuleUrl)});
const completed = await locks.rollbackSbx001DirectInterruptedAcquire(
  ${JSON.stringify(state.lockPath)},
  ${JSON.stringify(runId)},
);
process.stdout.write(JSON.stringify({ completed }) + "\\n");
`);
      expect(recovered).toMatchObject({ code: 0, stdout: "{\"completed\":true}\n", stderr: "" });

      const second = await runOneShot(`
const locks = await import(${JSON.stringify(liveLockModuleUrl)});
const completed = await locks.rollbackSbx001DirectInterruptedAcquire(
  ${JSON.stringify(state.lockPath)},
  ${JSON.stringify(runId)},
);
process.stdout.write(JSON.stringify({ completed }) + "\\n");
`);
      expect(second).toMatchObject({ code: 0, stdout: "{\"completed\":false}\n", stderr: "" });
      expect(await readdir(state.directory)).toEqual([]);
    }
  });

  it("recovers deterministic lock and transaction removal claims after real child deaths", async () => {
    for (const [index, scenario] of ["acquire-transaction-claimed", "release-canonical-claimed"].entries()) {
      const state = await temporaryState();
      const runId = randomUUID();
      const crashed = await runOneShot(`
const locks = await import(${JSON.stringify(liveLockModuleUrl)});
const lock = await locks.acquireSbx001DirectLiveLockAtPathForTest(
  ${JSON.stringify(state.lockPath)},
  ${JSON.stringify(runId)},
  false,
  async (mutation) => {
    if (mutation === ${JSON.stringify(scenario)}) process.exit(${100 + index});
  },
);
await lock.release();
`);
      expect(crashed).toMatchObject({ code: 100 + index, stdout: "", stderr: "" });
      expect((await readdir(state.directory)).some((entry) => entry.includes(".remove-"))).toBe(true);

      const recovered = await runOneShot(`
const locks = await import(${JSON.stringify(liveLockModuleUrl)});
const completed = ${index === 0
    ? `await locks.rollbackSbx001DirectInterruptedAcquire(${JSON.stringify(state.lockPath)}, ${JSON.stringify(runId)})`
    : `await locks.resumeSbx001DirectInterruptedRelease(${JSON.stringify(state.lockPath)}, ${JSON.stringify(runId)})`};
process.stdout.write(JSON.stringify({ completed }) + "\\n");
`);
      expect(recovered).toMatchObject({ code: 0, stdout: "{\"completed\":true}\n", stderr: "" });
      expect(await readdir(state.directory)).toEqual([]);
    }
  });

  it("restores and reclaims a dead cleanup source after stale rename but before install", async () => {
    const state = await temporaryState();
    const runId = randomUUID();
    const staleOwner = await runOneShot(`
const locks = await import(${JSON.stringify(liveLockModuleUrl)});
const lock = await locks.acquireSbx001DirectLiveLockAtPathForTest(
  ${JSON.stringify(state.lockPath)},
  ${JSON.stringify(runId)},
  false,
);
await lock.closeRetainingState();
`);
    expect(staleOwner).toMatchObject({ code: 0, stdout: "", stderr: "" });

    const crashed = await runOneShot(`
const locks = await import(${JSON.stringify(liveLockModuleUrl)});
await locks.acquireSbx001DirectLiveLockAtPathForTest(
  ${JSON.stringify(state.lockPath)},
  ${JSON.stringify(runId)},
  true,
  async (mutation) => {
    if (mutation === "acquire-stale-claimed") process.exit(79);
  },
);
`);
    expect(crashed).toMatchObject({ code: 79, stdout: "", stderr: "" });
    await expect(lstat(state.lockPath)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(`${state.lockPath}.transaction`)).resolves.toBeDefined();

    const recovered = await runOneShot(`
const locks = await import(${JSON.stringify(liveLockModuleUrl)});
const completed = await locks.rollbackSbx001DirectInterruptedAcquire(
  ${JSON.stringify(state.lockPath)},
  ${JSON.stringify(runId)},
);
process.stdout.write(JSON.stringify({ completed }) + "\\n");
`);
    expect(recovered).toMatchObject({ code: 0, stdout: "{\"completed\":true}\n", stderr: "" });
    expect(await readdir(state.directory)).toEqual([]);
  });

  it("preserves an unknown canonical replacement while refusing dead-acquire recovery", async () => {
    const state = await temporaryState();
    const runId = randomUUID();
    const crashed = await runOneShot(`
const locks = await import(${JSON.stringify(liveLockModuleUrl)});
await locks.acquireSbx001DirectLiveLockAtPathForTest(
  ${JSON.stringify(state.lockPath)},
  ${JSON.stringify(runId)},
  false,
  async (mutation) => {
    if (mutation === "acquire-replacement-created") process.exit(80);
  },
);
`);
    expect(crashed).toMatchObject({ code: 80, stdout: "", stderr: "" });

    const foreignPath = join(state.directory, "foreign.lock");
    const foreignRunId = randomUUID();
    const foreign = await runOneShot(`
const locks = await import(${JSON.stringify(liveLockModuleUrl)});
const lock = await locks.acquireSbx001DirectLiveLockAtPathForTest(
  ${JSON.stringify(foreignPath)},
  ${JSON.stringify(foreignRunId)},
  false,
);
await lock.closeRetainingState();
`);
    expect(foreign).toMatchObject({ code: 0, stdout: "", stderr: "" });
    await rename(foreignPath, state.lockPath);
    const replacement = await readFile(state.lockPath);

    const refused = await runOneShot(`
const locks = await import(${JSON.stringify(liveLockModuleUrl)});
await locks.rollbackSbx001DirectInterruptedAcquire(
  ${JSON.stringify(state.lockPath)},
  ${JSON.stringify(runId)},
);
`);
    expect(refused.code).not.toBe(0);
    expect(refused.stderr).toMatch(/unknown provenance/u);
    expect(await readFile(state.lockPath)).toEqual(replacement);
  });

  it("lets a fresh process finish a crash after journal removal but before lock removal", async () => {
    const state = await temporaryState();
    const runId = randomUUID();
    const crashed = await runOneShot(`
import { unlink, writeFile } from "node:fs/promises";
const locks = await import(${JSON.stringify(liveLockModuleUrl)});
await writeFile(${JSON.stringify(state.journalPath)}, "durable recovery state\\n", { mode: 0o600, flag: "wx" });
const lock = await locks.acquireSbx001DirectLiveLockAtPathForTest(
  ${JSON.stringify(state.lockPath)},
  ${JSON.stringify(runId)},
  false,
  async (mutation) => {
    if (mutation === "release-precommit-complete") process.exit(76);
  },
);
await lock.releaseAfter(async () => unlink(${JSON.stringify(state.journalPath)}));
`);
    expect(crashed).toMatchObject({ code: 76, stdout: "", stderr: "" });
    await expect(lstat(state.journalPath)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(state.lockPath)).resolves.toBeDefined();
    await expect(lstat(`${state.lockPath}.transaction`)).resolves.toBeDefined();

    const recovered = await runOneShot(`
const locks = await import(${JSON.stringify(liveLockModuleUrl)});
const completed = await locks.resumeSbx001DirectInterruptedRelease(
  ${JSON.stringify(state.lockPath)},
  ${JSON.stringify(runId)},
);
process.stdout.write(JSON.stringify({ completed }) + "\\n");
`);
    expect(recovered).toMatchObject({ code: 0, stdout: "{\"completed\":true}\n", stderr: "" });
    await expect(lstat(state.lockPath)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(`${state.lockPath}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("binds release to the held inode and never unlinks a pathname replacement", async () => {
    const state = await temporaryState();
    const backup = join(state.directory, "held-lock");
    const lock = await acquireSbx001DirectLiveLockAtPathForTest(state.lockPath, randomUUID(), false);
    const original = await readFile(state.lockPath);
    await rename(state.lockPath, backup);
    await writeFile(state.lockPath, original, { mode: 0o600, flag: "wx" });
    const replacement = await readFile(state.lockPath);
    await expect(lock.release()).rejects.toThrow(/replaced/u);
    expect(await readFile(state.lockPath)).toEqual(replacement);
    await unlink(state.lockPath);
    await rename(backup, state.lockPath);
    await lock.release();
    expect(lock.isReleased()).toBe(true);
    original.fill(0);
    replacement.fill(0);
  });

  it("durably checkpoints the final receiver snapshot after Sandbox stop and before receiver deletion", async () => {
    const source = await readFile("pocs/SBX-001/direct-run.ts", "utf8");
    const cleanup = source.slice(source.indexOf("async function cleanupSandbox"),
      source.indexOf("function cleanupComplete"));
    const stop = cleanup.indexOf("await sandbox.stop");
    const receiverCleanup = cleanup.indexOf("await cleanupSbx001Receiver");
    const helper = source.slice(source.indexOf("export async function cleanupSbx001Receiver"),
      source.indexOf("function receiverArm"));
    const finalSnapshot = helper.indexOf("input.journal.finalReceiverSnapshot = finalReceiverSnapshot");
    const snapshotPersist = helper.indexOf("await input.persist()", finalSnapshot);
    const receiverDeleteIntent = helper.indexOf("input.journal.receiverDeleteAttempted = true", snapshotPersist);
    const receiverDelete = helper.indexOf("await input.deleteReceiver()", receiverDeleteIntent);
    expect(stop).toBeGreaterThan(0);
    expect(receiverCleanup).toBeGreaterThan(stop);
    expect(finalSnapshot).toBeGreaterThan(0);
    expect(snapshotPersist).toBeGreaterThan(finalSnapshot);
    expect(receiverDeleteIntent).toBeGreaterThan(snapshotPersist);
    expect(receiverDelete).toBeGreaterThan(receiverDeleteIntent);
  });
});
