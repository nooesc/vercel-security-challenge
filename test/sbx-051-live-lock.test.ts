import { randomUUID } from "node:crypto";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { lstat, mkdtemp, readFile, rename, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { acquireSbx051LiveLockAtPathForTest } from "../pocs/SBX-051/live-lock.js";

interface ChildOutcome {
  result: "won" | "lost";
  message?: string;
}

const repositoryDirectory = resolve(".");
const lockModuleUrl = pathToFileURL(
  resolve(repositoryDirectory, "pocs/SBX-051/live-lock.ts"),
).href;

function workerSource(path: string, runId: string, recovery: boolean, hold: boolean): string {
  return `
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
try {
  const lock = await lockModule.acquireSbx051LiveLockAtPathForTest(
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
      `SBX-051 lock worker exited ${code ?? "without status"}: ${stderr.slice(0, 256)}`,
    ))));
  });
}

async function exitCode(child: ChildProcessWithoutNullStreams): Promise<number | null> {
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
  const directory = await mkdtemp(join(tmpdir(), "sbx-051-live-lock-"));
  return { directory, path: join(directory, "SBX-051-live-active.lock") };
}

async function leaveStaleLock(path: string, runId: string): Promise<void> {
  const owner = spawnWorker(path, runId, false, false);
  expect(await firstOutcome(owner)).toEqual({ result: "won" });
  expect(await exitCode(owner)).toBe(0);
}

describe.sequential("SBX-051 cross-process live lock", () => {
  it("refuses a live exact owner and permits the exact cleanup only after ESRCH", async () => {
    const temporary = await temporaryLock();
    const runId = randomUUID();
    const owner = spawnWorker(temporary.path, runId, false, true);
    try {
      expect(await firstOutcome(owner)).toEqual({ result: "won" });
      const metadata = JSON.parse(await readFile(temporary.path, "utf8")) as Record<string, unknown>;
      expect(metadata).toMatchObject({
        schemaVersion: 1,
        testId: "SBX-051-INTERACTIVE-TOKEN-BINDING",
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
      const recovered = await acquireSbx051LiveLockAtPathForTest(temporary.path, runId, true);
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
      await expect(acquireSbx051LiveLockAtPathForTest(
        temporary.path,
        randomUUID(),
        true,
      )).rejects.toThrow(/mismatched/u);
      expect(await readFile(temporary.path)).toEqual(before);
      const recovered = await acquireSbx051LiveLockAtPathForTest(
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
    const lock = await acquireSbx051LiveLockAtPathForTest(
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
      await expect(lstat(`${temporary.path}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
      await unlink(temporary.path);
      await rename(backup, temporary.path);
      await expect(lock.release()).resolves.toBeUndefined();
      expect(lock.isReleased()).toBe(true);
      original.fill(0);
      replacement.fill(0);
    } finally {
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });

  it("retains its owned descriptor across a transient release-transaction collision", async () => {
    const temporary = await temporaryLock();
    const lock = await acquireSbx051LiveLockAtPathForTest(
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
    const lock = await acquireSbx051LiveLockAtPathForTest(
      temporary.path,
      randomUUID(),
      false,
      async (mutation) => {
        expect(mutation).toBe("release-canonical-removed");
        await writeFile(temporary.path, replacement, { mode: 0o600, flag: "wx" });
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
}, 20_000);
