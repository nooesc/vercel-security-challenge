import { spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { lstat, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import {
  SBX038_LIVE_LOCK_IMPLEMENTATION_ID,
  acquireSbx038LiveLockAtPathForTest,
  resumeSbx038InterruptedReleaseAtPathForTest,
} from "../pocs/SBX-038/live-lock.js";

const repositoryDirectory = resolve(".");
const lockModuleUrl = pathToFileURL(resolve(repositoryDirectory, "pocs/SBX-038/live-lock.ts")).href;

async function exitCode(child: ChildProcess): Promise<number | null> {
  if (child.exitCode !== null) return child.exitCode;
  return new Promise<number | null>((resolveExit, rejectExit) => {
    child.once("error", rejectExit);
    child.once("exit", resolveExit);
  });
}

describe.sequential("SBX-038 ownership-bound live lock", () => {
  it("permits exactly one concurrent O_EXCL winner", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx-038-lock-"));
    const path = join(directory, "SBX-038-live-active.lock");
    try {
      const results = await Promise.allSettled([
        acquireSbx038LiveLockAtPathForTest(path, randomUUID(), false),
        acquireSbx038LiveLockAtPathForTest(path, randomUUID(), false),
      ]);
      const winners = results.filter((entry): entry is PromiseFulfilledResult<Awaited<ReturnType<
        typeof acquireSbx038LiveLockAtPathForTest
      >>> => entry.status === "fulfilled");
      expect(winners).toHaveLength(1);
      expect(results.filter((entry) => entry.status === "rejected")).toHaveLength(1);
      await winners[0]!.value.release();
      await expect(lstat(path)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("lets a fresh process finish a release crash after the journal precommit", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx-038-release-"));
    const path = join(directory, "SBX-038-live-active.lock");
    const journalPath = join(directory, "journal.json");
    const runId = randomUUID();
    try {
      const source = `
import { unlink } from "node:fs/promises";
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
const lock = await lockModule.acquireSbx038LiveLockAtPathForTest(
  ${JSON.stringify(path)}, ${JSON.stringify(runId)}, false,
  async (mutation) => { if (mutation === "release-precommit-complete") process.exit(76); },
);
await lock.releaseAfter(async () => unlink(${JSON.stringify(journalPath)}));
`;
      await writeFile(journalPath, "{}\n", { mode: 0o600, flag: "wx" });
      const child = spawn(process.execPath, [
        "--import", "tsx", "--input-type=module", "--eval", source,
      ], { cwd: repositoryDirectory, stdio: ["ignore", "pipe", "pipe"] });
      expect(await exitCode(child)).toBe(76);
      await expect(lstat(journalPath)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(path)).resolves.toBeDefined();
      await expect(lstat(`${path}.transaction`)).resolves.toBeDefined();

      expect(await resumeSbx038InterruptedReleaseAtPathForTest(path, runId)).toBe(true);
      await expect(lstat(path)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(`${path}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("pins the reviewed SBX-055 lock implementation hash", () => {
    expect(SBX038_LIVE_LOCK_IMPLEMENTATION_ID).toContain(
      "201279cfc861d513c1b73d2b2e44468bece0ea2633c7b67f5b8e7c57148c5750",
    );
  });
});
