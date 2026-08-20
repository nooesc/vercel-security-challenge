import { randomUUID } from "node:crypto";
import { spawn, type ChildProcess, type ChildProcessWithoutNullStreams } from "node:child_process";
import { lstat, mkdtemp, readFile, rename, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { acquireSbx055LiveLockAtPathForTest } from "../pocs/SBX-055/live-lock.js";

interface ChildOutcome {
  result: "won" | "lost";
  message?: string;
}

const repositoryDirectory = resolve(".");
const lockModuleUrl = pathToFileURL(
  resolve(repositoryDirectory, "pocs/SBX-055/live-lock.ts"),
).href;
const safetyModuleUrl = pathToFileURL(
  resolve(repositoryDirectory, "pocs/SBX-055/safety.ts"),
).href;

interface OneShotResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

async function runOneShot(source: string): Promise<OneShotResult> {
  const child = spawn(process.execPath, [
    "--import",
    "tsx",
    "--input-type=module",
    "--eval",
    source,
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
  const code = await exitCode(child);
  return { code, stdout, stderr };
}

function workerSource(path: string, runId: string, recovery: boolean, hold: boolean): string {
  return `
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
try {
  const lock = await lockModule.acquireSbx055LiveLockAtPathForTest(
    ${JSON.stringify(path)},
    ${JSON.stringify(runId)},
    ${JSON.stringify(recovery)},
  );
  process.stdout.write(JSON.stringify({ result: "won" }) + "\\n");
  if (${JSON.stringify(hold)}) {
    process.stdin.setEncoding("utf8");
    process.stdin.once("data", async (instruction) => {
      try {
        if (String(instruction).trim() === "release") await lock.release();
        process.exit(0);
      } catch (error) {
        process.stderr.write(error instanceof Error ? error.message : String(error));
        process.exit(2);
      }
    });
    process.stdin.resume();
  } else {
    process.exit(0);
  }
} catch (error) {
  process.stdout.write(JSON.stringify({
    result: "lost",
    message: error instanceof Error ? error.message : String(error),
  }) + "\\n");
  process.exit(0);
}
`;
}

function spawnWorker(
  path: string,
  runId: string,
  recovery: boolean,
  hold: boolean,
): ChildProcessWithoutNullStreams {
  return spawn(process.execPath, [
    "--import",
    "tsx",
    "--input-type=module",
    "--eval",
    workerSource(path, runId, recovery, hold),
  ], {
    cwd: repositoryDirectory,
    env: { ...process.env },
    stdio: ["pipe", "pipe", "pipe"],
  });
}

async function firstOutcome(child: ChildProcessWithoutNullStreams): Promise<ChildOutcome> {
  return new Promise<ChildOutcome>((resolveOutcome, rejectOutcome) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    const finish = (callback: () => void): void => {
      if (settled) return;
      settled = true;
      callback();
    };
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
      const newline = stdout.indexOf("\n");
      if (newline < 0) return;
      finish(() => {
        try {
          resolveOutcome(JSON.parse(stdout.slice(0, newline)) as ChildOutcome);
        } catch (error) {
          rejectOutcome(error);
        }
      });
    });
    child.stderr.on("data", (chunk: string) => { stderr += chunk; });
    child.once("error", (error) => finish(() => rejectOutcome(error)));
    child.once("exit", (code) => finish(() => rejectOutcome(new Error(
      `SBX-055 lock worker exited ${code ?? "without status"}: ${stderr.slice(0, 256)}`,
    ))));
  });
}

async function exitCode(child: ChildProcess): Promise<number | null> {
  if (child.exitCode !== null) return child.exitCode;
  return new Promise<number | null>((resolveExit, rejectExit) => {
    child.once("error", rejectExit);
    child.once("exit", resolveExit);
  });
}

async function finishWorker(
  child: ChildProcessWithoutNullStreams,
  instruction: "release" | "abandon",
): Promise<void> {
  child.stdin.end(`${instruction}\n`);
  expect(await exitCode(child)).toBe(0);
}

async function temporaryLock(): Promise<{ directory: string; path: string }> {
  const directory = await mkdtemp(join(tmpdir(), "sbx-055-live-lock-"));
  return { directory, path: join(directory, "SBX-055-live-active.lock") };
}

async function leaveStaleLock(path: string, runId: string): Promise<void> {
  const owner = spawnWorker(path, runId, false, false);
  expect(await firstOutcome(owner)).toEqual({ result: "won" });
  expect(await exitCode(owner)).toBe(0);
}

describe.sequential("SBX-055 cross-process live lock", () => {
  it("refuses a live exact owner and permits the exact cleanup only after ESRCH", async () => {
    const temporary = await temporaryLock();
    const runId = randomUUID();
    const owner = spawnWorker(temporary.path, runId, false, true);
    try {
      expect(await firstOutcome(owner)).toEqual({ result: "won" });
      const metadata = JSON.parse(await readFile(temporary.path, "utf8")) as Record<string, unknown>;
      expect(metadata).toMatchObject({
        schemaVersion: 1,
        testId: "SBX-055-STALE-INTERACTIVE-RESUME",
        kind: "live-lock",
        runId,
        pid: owner.pid,
        mode: "normal",
      });
      expect(metadata.lease).toMatch(/^[A-Za-z0-9_-]{43}$/u);
      expect((await lstat(temporary.path)).mode & 0o777).toBe(0o600);

      const rejected = spawnWorker(temporary.path, runId, true, false);
      expect(await firstOutcome(rejected)).toMatchObject({
        result: "lost",
        message: expect.stringMatching(/live lock owner/u),
      });
      expect(await exitCode(rejected)).toBe(0);

      await finishWorker(owner, "abandon");
      const recovered = await acquireSbx055LiveLockAtPathForTest(temporary.path, runId, true);
      await recovered.release();
      expect(recovered.isReleased()).toBe(true);
      await expect(lstat(temporary.path)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      if (owner.exitCode === null) {
        owner.kill("SIGKILL");
        await exitCode(owner).catch(() => undefined);
      }
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });

  it("allows exactly one of two same-run cleanup processes to reclaim one stale lease", async () => {
    const temporary = await temporaryLock();
    const runId = randomUUID();
    let first: ChildProcessWithoutNullStreams | undefined;
    let second: ChildProcessWithoutNullStreams | undefined;
    try {
      await leaveStaleLock(temporary.path, runId);
      first = spawnWorker(temporary.path, runId, true, true);
      second = spawnWorker(temporary.path, runId, true, true);
      const outcomes = await Promise.all([firstOutcome(first), firstOutcome(second)]);
      expect(outcomes.filter((outcome) => outcome.result === "won")).toHaveLength(1);
      expect(outcomes.filter((outcome) => outcome.result === "lost")).toHaveLength(1);
      const winner = outcomes[0]!.result === "won" ? first : second;
      const loser = winner === first ? second : first;
      await finishWorker(winner, "release");
      expect(await exitCode(loser)).toBe(0);
      await expect(lstat(temporary.path)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(`${temporary.path}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      for (const child of [first, second]) {
        if (child?.exitCode === null) child.kill("SIGKILL");
      }
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });

  it("leaves a mismatched-run lock byte-identical", async () => {
    const temporary = await temporaryLock();
    const exactRunId = randomUUID();
    try {
      await leaveStaleLock(temporary.path, exactRunId);
      const before = await readFile(temporary.path);
      await expect(acquireSbx055LiveLockAtPathForTest(
        temporary.path,
        randomUUID(),
        true,
      )).rejects.toThrow(/mismatched/u);
      expect(await readFile(temporary.path)).toEqual(before);
      const recovered = await acquireSbx055LiveLockAtPathForTest(
        temporary.path,
        exactRunId,
        true,
      );
      await recovered.release();
      before.fill(0);
    } finally {
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });

  it("refuses to release a replaced pathname and never unlinks the replacement", async () => {
    const temporary = await temporaryLock();
    const backup = join(temporary.directory, "original-held-lock");
    const lock = await acquireSbx055LiveLockAtPathForTest(
      temporary.path,
      randomUUID(),
      false,
    );
    try {
      const original = await readFile(temporary.path);
      await rename(temporary.path, backup);
      await writeFile(temporary.path, original, { mode: 0o600, flag: "wx" });
      const replacement = await readFile(temporary.path);
      await expect(lock.release()).rejects.toThrow(/replaced/u);
      expect(lock.isReleased()).toBe(false);
      expect(await readFile(temporary.path)).toEqual(replacement);
      expect(await readFile(backup)).toEqual(original);
      await expect(lstat(`${temporary.path}.transaction`)).resolves.toBeDefined();
      await unlink(temporary.path);
      await rename(backup, temporary.path);
      await expect(lock.release()).resolves.toBeUndefined();
      expect(lock.isReleased()).toBe(true);
      await expect(lstat(`${temporary.path}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
      original.fill(0);
      replacement.fill(0);
    } finally {
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });

  it("retains its owned descriptor across a transient release-transaction collision", async () => {
    const temporary = await temporaryLock();
    const lock = await acquireSbx055LiveLockAtPathForTest(
      temporary.path,
      randomUUID(),
      false,
    );
    const transaction = `${temporary.path}.transaction`;
    try {
      await writeFile(transaction, "transient exact-path blocker\n", { mode: 0o600, flag: "wx" });
      await expect(lock.release()).rejects.toMatchObject({ code: "EEXIST" });
      expect(lock.isReleased()).toBe(false);
      await unlink(transaction);
      await expect(lock.release()).resolves.toBeUndefined();
      expect(lock.isReleased()).toBe(true);
      await expect(lstat(temporary.path)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(transaction)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });

  it("keeps the transaction and replacement when the fixed path reappears during release", async () => {
    const temporary = await temporaryLock();
    const replacement = Buffer.from("same-user replacement must survive\n", "utf8");
    const lock = await acquireSbx055LiveLockAtPathForTest(
      temporary.path,
      randomUUID(),
      false,
      async (mutation) => {
        if (mutation === "release-canonical-removed") {
          await writeFile(temporary.path, replacement, { mode: 0o600, flag: "wx" });
        }
      },
    );
    try {
      await expect(lock.release()).rejects.toThrow(/survived or was replaced/u);
      expect(lock.isReleased()).toBe(false);
      expect(await readFile(temporary.path)).toEqual(replacement);
      await expect(lstat(`${temporary.path}.transaction`)).resolves.toBeDefined();

      await unlink(temporary.path);
      await expect(lock.release()).resolves.toBeUndefined();
      expect(lock.isReleased()).toBe(true);
      await expect(lstat(`${temporary.path}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      replacement.fill(0);
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });

  it("lets a fresh process finish a crash after canonical removal without a stuck transaction", async () => {
    const temporary = await temporaryLock();
    const runId = randomUUID();
    const journalPath = join(temporary.directory, `SBX-055-${runId}-recovery.json`);
    try {
      const crashed = await runOneShot(`
import { writeFile, unlink } from "node:fs/promises";
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await writeFile(${JSON.stringify(journalPath)}, "journal\\n", { mode: 0o600, flag: "wx" });
const lock = await lockModule.acquireSbx055LiveLockAtPathForTest(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
  false,
  async (mutation) => {
    if (mutation === "release-canonical-removed") process.exit(77);
  },
);
await lock.releaseAfter(async () => unlink(${JSON.stringify(journalPath)}));
`);
      expect(crashed).toMatchObject({ code: 77, stderr: "" });
      await expect(lstat(temporary.path)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(journalPath)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(`${temporary.path}.transaction`)).resolves.toBeDefined();

      const resumed = await runOneShot(`
const safety = await import(${JSON.stringify(safetyModuleUrl)});
const completed = await safety.resumeSbx055InterruptedFinalizationAtPathsForTest(
  ${JSON.stringify(runId)},
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(journalPath)},
);
process.stdout.write(JSON.stringify({ completed }) + "\\n");
`);
      expect(resumed).toMatchObject({ code: 0, stderr: "" });
      expect(JSON.parse(resumed.stdout)).toEqual({ completed: true });
      await expect(lstat(temporary.path)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(journalPath)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(`${temporary.path}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });

  it("lets a fresh process finish a crash after journal commit while the canonical remains", async () => {
    const temporary = await temporaryLock();
    const runId = randomUUID();
    const journalPath = join(temporary.directory, `SBX-055-${runId}-recovery.json`);
    try {
      const crashed = await runOneShot(`
import { writeFile, unlink } from "node:fs/promises";
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await writeFile(${JSON.stringify(journalPath)}, "journal\\n", { mode: 0o600, flag: "wx" });
const lock = await lockModule.acquireSbx055LiveLockAtPathForTest(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
  false,
  async (mutation) => {
    if (mutation === "release-precommit-complete") process.exit(76);
  },
);
await lock.releaseAfter(async () => unlink(${JSON.stringify(journalPath)}));
`);
      expect(crashed).toMatchObject({ code: 76, stderr: "" });
      await expect(lstat(temporary.path)).resolves.toBeDefined();
      await expect(lstat(journalPath)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(`${temporary.path}.transaction`)).resolves.toBeDefined();

      const resumed = await runOneShot(`
const safety = await import(${JSON.stringify(safetyModuleUrl)});
const completed = await safety.resumeSbx055InterruptedFinalizationAtPathsForTest(
  ${JSON.stringify(runId)},
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(journalPath)},
);
process.stdout.write(JSON.stringify({ completed }) + "\\n");
`);
      expect(resumed).toMatchObject({ code: 0, stderr: "" });
      expect(JSON.parse(resumed.stdout)).toEqual({ completed: true });
      await expect(lstat(temporary.path)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(journalPath)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(`${temporary.path}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });

  it("keeps the lock and journal when unlink fails, then lets a fresh process retry", async () => {
    const temporary = await temporaryLock();
    const runId = randomUUID();
    const journalPath = join(temporary.directory, `SBX-055-${runId}-recovery.json`);
    try {
      const failed = await runOneShot(`
import { writeFile } from "node:fs/promises";
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await writeFile(${JSON.stringify(journalPath)}, "journal\\n", { mode: 0o600, flag: "wx" });
const lock = await lockModule.acquireSbx055LiveLockAtPathForTest(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
  false,
);
try {
  await lock.releaseAfter(async () => { throw new Error("injected journal unlink failure"); });
  process.exit(8);
} catch {
  await lock.closeRetainingState();
  process.stdout.write("retained\\n");
}
`);
      expect(failed).toMatchObject({ code: 0, stdout: "retained\n", stderr: "" });
      await expect(lstat(temporary.path)).resolves.toBeDefined();
      await expect(lstat(journalPath)).resolves.toBeDefined();
      await expect(lstat(`${temporary.path}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });

      const retried = await runOneShot(`
import { unlink } from "node:fs/promises";
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
const lock = await lockModule.acquireSbx055LiveLockAtPathForTest(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
  true,
);
await lock.releaseAfter(async () => unlink(${JSON.stringify(journalPath)}));
process.stdout.write("released\\n");
`);
      expect(retried).toMatchObject({ code: 0, stdout: "released\n", stderr: "" });
      await expect(lstat(temporary.path)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(journalPath)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(`${temporary.path}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });

  it("rolls back a fresh-process crash before journal precommit and then recovers normally", async () => {
    const temporary = await temporaryLock();
    const runId = randomUUID();
    const journalPath = join(temporary.directory, `SBX-055-${runId}-recovery.json`);
    try {
      const crashed = await runOneShot(`
import { writeFile } from "node:fs/promises";
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
const safety = await import(${JSON.stringify(safetyModuleUrl)});
const journal = safety.createSbx055Journal(new Date(), ${JSON.stringify(runId)});
await writeFile(${JSON.stringify(journalPath)}, JSON.stringify(journal) + "\\n", {
  mode: 0o600,
  flag: "wx",
});
const lock = await lockModule.acquireSbx055LiveLockAtPathForTest(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
  false,
  async (mutation) => {
    if (mutation === "release-transaction-created") process.exit(78);
  },
);
await lock.releaseAfter(async () => { throw new Error("precommit should not run"); });
`);
      expect(crashed).toMatchObject({ code: 78, stderr: "" });
      await expect(lstat(temporary.path)).resolves.toBeDefined();
      await expect(lstat(journalPath)).resolves.toBeDefined();
      await expect(lstat(`${temporary.path}.transaction`)).resolves.toBeDefined();

      const recovered = await runOneShot(`
const safety = await import(${JSON.stringify(safetyModuleUrl)});
const lock = await safety.acquireSbx055RecoveryLockAtPathsForTest(
  ${JSON.stringify(runId)},
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(journalPath)},
);
await safety.releaseSbx055LockAndJournal(lock);
process.stdout.write("recovered\\n");
`);
      expect(recovered).toMatchObject({ code: 0, stdout: "recovered\n", stderr: "" });
      await expect(lstat(temporary.path)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(journalPath)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(`${temporary.path}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });

  it("rolls back every dead normal-acquire crash phase without stranding sidecars", async () => {
    const mutations = [
      "acquire-transaction-created",
      "acquire-replacement-created",
      "acquire-canonical-installed",
      "acquire-replacement-removed",
    ] as const;
    for (const [index, mutation] of mutations.entries()) {
      const temporary = await temporaryLock();
      const runId = randomUUID();
      try {
        const crashed = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await lockModule.acquireSbx055LiveLockAtPathForTest(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
  false,
  async (mutation) => {
    if (mutation === ${JSON.stringify(mutation)}) process.exit(${80 + index});
  },
);
`);
        expect(crashed).toMatchObject({ code: 80 + index, stderr: "" });
        const recovered = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
const recovered = await lockModule.recoverSbx055InterruptedAcquire(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
);
process.stdout.write(JSON.stringify({ recovered }) + "\\n");
`);
        expect(recovered).toMatchObject({ code: 0, stderr: "" });
        expect(JSON.parse(recovered.stdout)).toEqual({ recovered: true });
        await expect(lstat(temporary.path)).rejects.toMatchObject({ code: "ENOENT" });
        await expect(lstat(`${temporary.path}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
        const directoryEntries = await import("node:fs/promises").then(({ readdir }) =>
          readdir(temporary.directory));
        expect(directoryEntries).toEqual([]);
      } finally {
        await rm(temporary.directory, { recursive: true, force: true });
      }
    }
  });

  it("rolls back or completes every dead cleanup-takeover crash phase, then reclaims exactly once", async () => {
    const mutations = [
      "acquire-transaction-created",
      "acquire-replacement-created",
      "acquire-stale-claimed",
      "acquire-canonical-installed",
      "acquire-replacement-removed",
      "acquire-stale-removed",
    ] as const;
    for (const [index, mutation] of mutations.entries()) {
      const temporary = await temporaryLock();
      const runId = randomUUID();
      try {
        await leaveStaleLock(temporary.path, runId);
        const crashed = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await lockModule.acquireSbx055LiveLockAtPathForTest(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
  true,
  async (mutation) => {
    if (mutation === ${JSON.stringify(mutation)}) process.exit(${90 + index});
  },
);
`);
        expect(crashed).toMatchObject({ code: 90 + index, stderr: "" });
        const recovered = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
const recovered = await lockModule.recoverSbx055InterruptedAcquire(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
);
const lock = await lockModule.acquireSbx055LiveLockAtPathForTest(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
  true,
);
await lock.release();
process.stdout.write(JSON.stringify({ recovered }) + "\\n");
`);
        expect(recovered).toMatchObject({ code: 0, stderr: "" });
        expect(JSON.parse(recovered.stdout)).toEqual({ recovered: true });
        await expect(lstat(temporary.path)).rejects.toMatchObject({ code: "ENOENT" });
        await expect(lstat(`${temporary.path}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
        const directoryEntries = await import("node:fs/promises").then(({ readdir }) =>
          readdir(temporary.directory));
        expect(directoryEntries).toEqual([]);
      } finally {
        await rm(temporary.directory, { recursive: true, force: true });
      }
    }
  });

  it("converges after recovery dies between restoring the source link and removing its stale alias", async () => {
    const temporary = await temporaryLock();
    const runId = randomUUID();
    try {
      await leaveStaleLock(temporary.path, runId);
      const takeoverCrash = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await lockModule.acquireSbx055LiveLockAtPathForTest(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
  true,
  async (mutation) => {
    if (mutation === "acquire-stale-claimed") process.exit(96);
  },
);
`);
      expect(takeoverCrash).toMatchObject({ code: 96, stderr: "" });

      const recoveryCrash = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await lockModule.recoverSbx055InterruptedAcquireAtPathForTest(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
  async (mutation) => {
    if (mutation === "recover-source-linked") process.exit(97);
  },
);
`);
      expect(recoveryCrash).toMatchObject({ code: 97, stderr: "" });
      const transaction = JSON.parse(await readFile(`${temporary.path}.transaction`, "utf8")) as {
        pid: number; lease: string;
      };
      const stalePath = `${temporary.path}.stale-${transaction.pid}-${transaction.lease}`;
      const [canonicalMetadata, staleMetadata] = await Promise.all([
        lstat(temporary.path, { bigint: true }),
        lstat(stalePath, { bigint: true }),
      ]);
      expect(canonicalMetadata.dev).toBe(staleMetadata.dev);
      expect(canonicalMetadata.ino).toBe(staleMetadata.ino);
      expect(await readFile(temporary.path)).toEqual(await readFile(stalePath));

      const converged = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
const recovered = await lockModule.recoverSbx055InterruptedAcquire(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
);
const lock = await lockModule.acquireSbx055LiveLockAtPathForTest(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
  true,
);
await lock.release();
process.stdout.write(JSON.stringify({ recovered }) + "\\n");
`);
      expect(converged).toMatchObject({ code: 0, stderr: "" });
      expect(JSON.parse(converged.stdout)).toEqual({ recovered: true });
      await expect(lstat(temporary.path)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(stalePath)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(`${temporary.path}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });

  it("recovers both serialized pre-journal orphan-removal crash phases", async () => {
    const mutations = ["orphan-release-transaction-created", "orphan-canonical-removed"] as const;
    for (const [index, mutation] of mutations.entries()) {
      const temporary = await temporaryLock();
      const runId = randomUUID();
      try {
        await leaveStaleLock(temporary.path, runId);
        const crashed = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await lockModule.rollbackSbx055OrphanedNormalLockAtPathForTest(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
  async (mutation) => {
    if (mutation === ${JSON.stringify(mutation)}) process.exit(${110 + index});
  },
);
`);
        expect(crashed).toMatchObject({ code: 110 + index, stderr: "" });
        await expect(lstat(`${temporary.path}.transaction`)).resolves.toBeDefined();

        const recovered = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
const recovered = await lockModule.resumeSbx055InterruptedRelease(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
);
process.stdout.write(JSON.stringify({ recovered }) + "\\n");
`);
        expect(recovered).toMatchObject({ code: 0, stderr: "" });
        expect(JSON.parse(recovered.stdout)).toEqual({ recovered: true });
        expect(await import("node:fs/promises").then(({ readdir }) =>
          readdir(temporary.directory))).toEqual([]);
      } finally {
        await rm(temporary.directory, { recursive: true, force: true });
      }
    }
  });

  it("recovers every dead transaction-finalizer takeover phase", async () => {
    const mutations = [
      "finalizer-replacement-created",
      "finalizer-election-created",
      "finalizer-installed",
      "finalizer-election-removed",
      "finalizer-transaction-removed",
    ] as const;
    for (const [index, mutation] of mutations.entries()) {
      const temporary = await temporaryLock();
      const runId = randomUUID();
      try {
        await leaveStaleLock(temporary.path, runId);
        const transactionCrash = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await lockModule.rollbackSbx055OrphanedNormalLockAtPathForTest(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
  async (mutation) => {
    if (mutation === "orphan-release-transaction-created") process.exit(120);
  },
);
`);
        expect(transactionCrash).toMatchObject({ code: 120, stderr: "" });
        const initialFinalizerCrash = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await lockModule.resumeSbx055InterruptedReleaseAtPathForTest(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
  async (mutation) => {
    if (mutation === "finalizer-installed") process.exit(121);
  },
);
`);
        expect(initialFinalizerCrash).toMatchObject({ code: 121, stderr: "" });

        const takeoverCrash = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await lockModule.resumeSbx055InterruptedReleaseAtPathForTest(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
  async (mutation) => {
    if (mutation === ${JSON.stringify(mutation)}) process.exit(${130 + index});
  },
);
`);
        expect(takeoverCrash).toMatchObject({ code: 130 + index, stderr: "" });

        const converged = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
const recovered = await lockModule.resumeSbx055InterruptedRelease(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
);
process.stdout.write(JSON.stringify({ recovered }) + "\\n");
`);
        expect(converged).toMatchObject({ code: 0, stderr: "" });
        expect(JSON.parse(converged.stdout)).toEqual({ recovered: true });
        expect(await import("node:fs/promises").then(({ readdir }) =>
          readdir(temporary.directory))).toEqual([]);
      } finally {
        await rm(temporary.directory, { recursive: true, force: true });
      }
    }
  });

  it("serializes two release recoverers and blocks a replacement transaction until finalizer release", async () => {
    const temporary = await temporaryLock();
    const runId = randomUUID();
    let first: ChildProcessWithoutNullStreams | undefined;
    let second: ChildProcessWithoutNullStreams | undefined;
    try {
      await leaveStaleLock(temporary.path, runId);
      const transactionCrash = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await lockModule.rollbackSbx055OrphanedNormalLockAtPathForTest(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
  async (mutation) => {
    if (mutation === "orphan-release-transaction-created") process.exit(140);
  },
);
`);
      expect(transactionCrash).toMatchObject({ code: 140, stderr: "" });

      const initialFinalizerCrash = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await lockModule.resumeSbx055InterruptedReleaseAtPathForTest(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
  async (mutation) => {
    if (mutation === "finalizer-installed") process.exit(141);
  },
);
`);
      expect(initialFinalizerCrash).toMatchObject({ code: 141, stderr: "" });

      const recoverySource = `
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
try {
  const recovered = await lockModule.resumeSbx055InterruptedReleaseAtPathForTest(
    ${JSON.stringify(temporary.path)},
    ${JSON.stringify(runId)},
    async (mutation) => {
      if (mutation === "finalizer-transaction-removed") {
        process.stdout.write(JSON.stringify({ result: "won" }) + "\\n");
        await new Promise((resolve) => process.stdin.once("data", resolve));
      }
    },
  );
  if (!recovered) throw new Error("release recovery did not settle");
} catch (error) {
  process.stdout.write(JSON.stringify({
    result: "lost",
    message: error instanceof Error ? error.message : String(error),
  }) + "\\n");
}
`;
      const spawnRecovery = (): ChildProcessWithoutNullStreams => spawn(process.execPath, [
        "--import", "tsx", "--input-type=module", "--eval", `
${recoverySource}
`], {
        cwd: repositoryDirectory,
        env: { ...process.env },
        stdio: ["pipe", "pipe", "pipe"],
      });
      first = spawnRecovery();
      second = spawnRecovery();
      const outcomes = await Promise.all([firstOutcome(first), firstOutcome(second)]);
      expect(outcomes.filter((outcome) => outcome.result === "won")).toHaveLength(1);
      expect(outcomes.filter((outcome) => outcome.result === "lost")).toHaveLength(1);
      const winner = outcomes[0]!.result === "won" ? first : second;
      const loser = winner === first ? second : first;
      expect(outcomes.find((outcome) => outcome.result === "lost")?.message).toMatch(
        /election|finalizer|EEXIST/u,
      );
      expect(await exitCode(loser)).toBe(0);
      await expect(lstat(temporary.path)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(`${temporary.path}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
      const finalizerPath = `${temporary.path}.transaction.finalizer`;
      const finalizerBefore = await readFile(finalizerPath);

      const lateLoser = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
try {
  await lockModule.resumeSbx055InterruptedRelease(
    ${JSON.stringify(temporary.path)},
    ${JSON.stringify(runId)},
  );
  process.stdout.write("unexpected-success\\n");
} catch (error) {
  process.stdout.write((error instanceof Error ? error.message : String(error)) + "\\n");
}
`);
      expect(lateLoser).toMatchObject({ code: 0, stderr: "" });
      expect(lateLoser.stdout).toMatch(/owner was not proven dead/u);
      expect(await readFile(finalizerPath)).toEqual(finalizerBefore);

      const prematureAcquirer = spawnWorker(temporary.path, runId, false, false);
      expect(await firstOutcome(prematureAcquirer)).toMatchObject({
        result: "lost",
        message: expect.stringMatching(/finalization state exists/u),
      });
      expect(await exitCode(prematureAcquirer)).toBe(0);
      expect(await readFile(finalizerPath)).toEqual(finalizerBefore);

      await finishWorker(winner, "release");
      const successor = spawnWorker(temporary.path, runId, false, true);
      expect(await firstOutcome(successor)).toEqual({ result: "won" });
      await finishWorker(successor, "release");
      await expect(lstat(temporary.path)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(`${temporary.path}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(finalizerPath)).rejects.toMatchObject({ code: "ENOENT" });
      finalizerBefore.fill(0);
    } finally {
      for (const child of [first, second]) {
        if (child?.exitCode === null) {
          child.kill("SIGKILL");
          await exitCode(child).catch(() => undefined);
        }
      }
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });

  it("recovers discoverable canonical and transaction removal claims after process death", async () => {
    const mutations = ["release-canonical-claimed", "release-transaction-claimed"] as const;
    for (const [index, mutation] of mutations.entries()) {
      const temporary = await temporaryLock();
      const runId = randomUUID();
      const journalPath = join(temporary.directory, `SBX-055-${runId}-recovery.json`);
      try {
        const crashed = await runOneShot(`
import { writeFile, unlink } from "node:fs/promises";
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await writeFile(${JSON.stringify(journalPath)}, "journal\\n", { mode: 0o600, flag: "wx" });
const lock = await lockModule.acquireSbx055LiveLockAtPathForTest(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
  false,
  async (mutation) => {
    if (mutation === ${JSON.stringify(mutation)}) process.exit(${150 + index});
  },
);
await lock.releaseAfter(async () => unlink(${JSON.stringify(journalPath)}));
`);
        expect(crashed).toMatchObject({ code: 150 + index, stderr: "" });
        const before = await import("node:fs/promises").then(({ readdir }) =>
          readdir(temporary.directory));
        expect(before.some((entry) => entry.includes(".remove-"))).toBe(true);
        const recovered = await runOneShot(`
const safety = await import(${JSON.stringify(safetyModuleUrl)});
const outcome = await safety.dispatchSbx055RecoveryAtPathsForTest(
  ${JSON.stringify(runId)},
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(journalPath)},
);
process.stdout.write(JSON.stringify({ outcome }) + "\\n");
`);
        expect(recovered).toMatchObject({ code: 0, stderr: "" });
        expect(JSON.parse(recovered.stdout)).toEqual({ outcome: "release-finalization-complete" });
        expect(await import("node:fs/promises").then(({ readdir }) =>
          readdir(temporary.directory))).toEqual([]);
      } finally {
        await rm(temporary.directory, { recursive: true, force: true });
      }
    }
  });

  it("recovers an acquire transaction removal claim before journal creation", async () => {
    const temporary = await temporaryLock();
    const runId = randomUUID();
    const journalPath = join(temporary.directory, `SBX-055-${runId}-recovery.json`);
    try {
      const crashed = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await lockModule.acquireSbx055LiveLockAtPathForTest(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
  false,
  async (mutation) => {
    if (mutation === "acquire-transaction-claimed") process.exit(152);
  },
);
`);
      expect(crashed).toMatchObject({ code: 152, stderr: "" });
      expect((await import("node:fs/promises").then(({ readdir }) =>
        readdir(temporary.directory))).some((entry) => entry.includes(".transaction.remove-"))).toBe(true);
      const recovered = await runOneShot(`
const safety = await import(${JSON.stringify(safetyModuleUrl)});
const outcome = await safety.dispatchSbx055RecoveryAtPathsForTest(
  ${JSON.stringify(runId)},
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(journalPath)},
);
process.stdout.write(JSON.stringify({ outcome }) + "\\n");
`);
      expect(recovered).toMatchObject({ code: 0, stderr: "" });
      expect(JSON.parse(recovered.stdout)).toEqual({ outcome: "zero-external-state-acquire-rolled-back" });
      expect(await import("node:fs/promises").then(({ readdir }) =>
        readdir(temporary.directory))).toEqual([]);
    } finally {
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });

  it("preserves replacement fixed paths when exact removal claims coexist", async () => {
    const cases = ["release-canonical-claimed", "release-transaction-claimed"] as const;
    for (const [index, mutation] of cases.entries()) {
      const temporary = await temporaryLock();
      const runId = randomUUID();
      const journalPath = join(temporary.directory, `SBX-055-${runId}-recovery.json`);
      try {
        const crashed = await runOneShot(`
import { writeFile, unlink } from "node:fs/promises";
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await writeFile(${JSON.stringify(journalPath)}, "journal\\n", { mode: 0o600, flag: "wx" });
const lock = await lockModule.acquireSbx055LiveLockAtPathForTest(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
  false,
  async (mutation) => {
    if (mutation === ${JSON.stringify(mutation)}) process.exit(${153 + index});
  },
);
await lock.releaseAfter(async () => unlink(${JSON.stringify(journalPath)}));
`);
        expect(crashed).toMatchObject({ code: 153 + index, stderr: "" });
        const entries = await import("node:fs/promises").then(({ readdir }) =>
          readdir(temporary.directory));
        const suffix = mutation === "release-canonical-claimed" ? ".lock.remove-" : ".transaction.remove-";
        const claimName = entries.find((entry) => entry.includes(suffix));
        expect(claimName).toBeDefined();
        const claimPath = join(temporary.directory, claimName!);
        const fixedPath = mutation === "release-canonical-claimed"
          ? temporary.path
          : `${temporary.path}.transaction`;
        const claimBytes = await readFile(claimPath);
        await writeFile(fixedPath, claimBytes, { mode: 0o600, flag: "wx" });
        const replacementBytes = await readFile(fixedPath);
        const claimBefore = await readFile(claimPath);
        const settled = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
try {
  await lockModule.settleSbx055RemovalClaims(
    ${JSON.stringify(temporary.path)},
    ${JSON.stringify(runId)},
  );
  process.stdout.write("unexpected-success\\n");
} catch (error) {
  process.stdout.write((error instanceof Error ? error.message : String(error)) + "\\n");
}
`);
        expect(settled).toMatchObject({ code: 0, stderr: "" });
        expect(settled.stdout).toMatch(/replacement fixed path/u);
        expect(await readFile(fixedPath)).toEqual(replacementBytes);
        expect(await readFile(claimPath)).toEqual(claimBefore);
        claimBytes.fill(0);
        replacementBytes.fill(0);
        claimBefore.fill(0);
      } finally {
        await rm(temporary.directory, { recursive: true, force: true });
      }
    }
  });

  it("settles a dead dangling rollback finalizer while preserving the journal and canonical lock", async () => {
    const temporary = await temporaryLock();
    const runId = randomUUID();
    const journalPath = join(temporary.directory, `SBX-055-${runId}-recovery.json`);
    try {
      const transactionCrash = await runOneShot(`
import { writeFile } from "node:fs/promises";
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
const safety = await import(${JSON.stringify(safetyModuleUrl)});
const journal = safety.createSbx055Journal(new Date(), ${JSON.stringify(runId)});
await writeFile(${JSON.stringify(journalPath)}, JSON.stringify(journal) + "\\n", {
  mode: 0o600,
  flag: "wx",
});
const lock = await lockModule.acquireSbx055LiveLockAtPathForTest(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
  false,
  async (mutation) => {
    if (mutation === "release-transaction-created") process.exit(155);
  },
);
await lock.releaseAfter(async () => { throw new Error("precommit must not run"); });
`);
      expect(transactionCrash).toMatchObject({ code: 155, stderr: "" });
      const rollbackCrash = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await lockModule.rollbackSbx055InterruptedReleaseAtPathForTest(
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(runId)},
  async (mutation) => {
    if (mutation === "finalizer-transaction-removed") process.exit(156);
  },
);
`);
      expect(rollbackCrash).toMatchObject({ code: 156, stderr: "" });
      await expect(lstat(temporary.path)).resolves.toBeDefined();
      await expect(lstat(journalPath)).resolves.toBeDefined();
      await expect(lstat(`${temporary.path}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(`${temporary.path}.transaction.finalizer`)).resolves.toBeDefined();

      const recovered = await runOneShot(`
const safety = await import(${JSON.stringify(safetyModuleUrl)});
const lock = await safety.acquireSbx055RecoveryLockAtPathsForTest(
  ${JSON.stringify(runId)},
  ${JSON.stringify(temporary.path)},
  ${JSON.stringify(journalPath)},
);
await safety.releaseSbx055LockAndJournal(lock);
process.stdout.write("recovered\\n");
`);
      expect(recovered).toMatchObject({ code: 0, stdout: "recovered\n", stderr: "" });
      expect(await import("node:fs/promises").then(({ readdir }) =>
        readdir(temporary.directory))).toEqual([]);
    } finally {
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });
}, 60_000);
