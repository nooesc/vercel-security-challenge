import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { access, copyFile, lstat, mkdtemp, readFile, readlink, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const SOURCE = resolve("guest/sbx-052-fs-namespace-probe.mjs");
const temporary: string[] = [];

async function execute(script: string, args: string[]) {
  return new Promise<{ code: number | null; stdout: string; stderr: string }>((resolveRun, reject) => {
    const child = spawn(process.execPath, [script, ...args], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { PATH: process.env.PATH },
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk) => stdout.push(Buffer.from(chunk)));
    child.stderr.on("data", (chunk) => stderr.push(Buffer.from(chunk)));
    child.once("error", reject);
    child.once("close", (code) => resolveRun({
      code,
      stdout: Buffer.concat(stdout).toString("utf8"),
      stderr: Buffer.concat(stderr).toString("utf8"),
    }));
  });
}

afterEach(async () => {
  await Promise.all(temporary.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("SBX-052 guest probe", () => {
  it("creates only the owned canary and two exact symlinks, observes, then self-cleans", async () => {
    const scratch = await mkdtemp(resolve(tmpdir(), "sbx-052-guest-test-"));
    temporary.push(scratch);
    const script = resolve(scratch, "probe.mjs");
    await copyFile(SOURCE, script);
    const runId = randomUUID();
    const remoteDirectory = `/tmp/sbx-052-${runId}`;
    temporary.push(remoteDirectory);
    const canary = "can52_abcdefghijklmnopqrstuvwxyzABCDEF";
    expect(canary).toHaveLength(38);

    const setup = await execute(script, ["setup", runId, canary]);
    expect(setup.code).toBe(0);
    expect(setup.stderr).toBe("");
    expect(setup.stdout).not.toContain(canary);
    expect(JSON.parse(setup.stdout)).toMatchObject({
      schemaVersion: 1,
      testId: "SBX-052",
      operation: "setup",
      runId,
      ready: true,
      directoryMode: 0o700,
      ownedMode: 0o600,
      ownedRelativeLink: true,
      procAbsoluteLink: true,
    });
    expect(await readFile(`${remoteDirectory}/owned.txt`, "utf8")).toBe(`${canary}\n`);
    expect(await readlink(`${remoteDirectory}/owned-link`)).toBe("owned.txt");
    expect(await readlink(`${remoteDirectory}/proc-link`)).toBe("/proc/sys/kernel/random/boot_id");
    expect((await lstat(`${remoteDirectory}/owned-link`)).isSymbolicLink()).toBe(true);
    expect((await lstat(`${remoteDirectory}/proc-link`)).isSymbolicLink()).toBe(true);

    const procAvailable = await access("/proc/sys/kernel/random/boot_id")
      .then(() => true, () => false);
    const observation = await execute(script, ["observe", runId]);
    if (procAvailable) {
      expect(observation.code).toBe(0);
      expect(observation.stderr).toBe("");
      const parsed = JSON.parse(observation.stdout) as Record<string, unknown>;
      expect(parsed.directBootId).toMatch(/^[0-9a-f-]{36}$/u);
      expect(parsed.linkedBootId).toBe(parsed.directBootId);
      expect(parsed.directBytes).toBe(37);
      expect(parsed.linkedBytes).toBe(37);
    } else {
      expect(observation).toEqual({
        code: 1,
        stdout: "",
        stderr: "SBX-052 guest probe failed\n",
      });
    }

    const cleanup = await execute(script, ["cleanup", runId]);
    expect(cleanup.code).toBe(0);
    expect(cleanup.stderr).toBe("");
    expect(JSON.parse(cleanup.stdout)).toMatchObject({
      operation: "cleanup",
      directoryRemoved: true,
      probeRemoved: true,
    });
    await expect(lstat(remoteDirectory)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(script)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("rejects noncanonical run IDs and never echoes attacker-controlled input", async () => {
    const scratch = await mkdtemp(resolve(tmpdir(), "sbx-052-guest-test-"));
    temporary.push(scratch);
    const script = resolve(scratch, "probe.mjs");
    await copyFile(SOURCE, script);
    const attacker = "not-a-run-id-DO-NOT-ECHO";
    const result = await execute(script, ["observe", attacker]);
    expect(result.code).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("SBX-052 guest probe failed\n");
    expect(result.stderr).not.toContain(attacker);
  });

  it("has no network capability and limits deletion to the full-UUID directory and its own file", async () => {
    const source = await readFile(SOURCE, "utf8");
    expect(source).not.toMatch(/node:(?:http|https|net|tls|dgram)/u);
    expect(source).not.toMatch(/\bfetch\s*\(/u);
    expect(source).toContain("`/tmp/sbx-052-${runId}`");
    expect(source).toContain("rm(paths.directory, { recursive: true, force: true })");
    expect(source).toContain("unlink(fileURLToPath(import.meta.url))");
    expect(source).toContain("-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-");
    expect(source).not.toMatch(/\/proc\/(?:[0-9]+|self)\/(?:environ|mem|root)/u);
  });
});
