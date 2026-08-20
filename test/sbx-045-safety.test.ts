import { chmod, lstat, mkdtemp, readFile, rename, rm, symlink } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  ELIGIBLE_ALIAS,
  ELIGIBLE_PROJECT_ID,
  ELIGIBLE_TEAM_ID,
  acquireLiveLock,
  createRecoveryJournal,
  parseRecoveryJournal,
  readRecoveryJournal,
  writePrivateJsonAtomically,
} from "../pocs/SBX-045/safety.js";
import {
  CLEANUP_ORDER,
  FIXED_GUEST_SHA256,
  createGatedFetch,
  fixedGuestCommandSpec,
  forkEnvironmentOverride,
  loadExplicitConfig,
} from "../pocs/SBX-045/fork-env-override.js";

const confirmation =
  "I_RECHECKED_SBX045_SINGLE_ACCOUNT_SCOPE_AND_WILL_USE_ONLY_THE_ELIGIBLE_ALIAS";

function environment(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    SBX045_SCOPE_CONFIRMATION: confirmation,
    SBX045_EXPECTED_ALIAS: ELIGIBLE_ALIAS,
    VERCEL_TOKEN: `vcp_${"x".repeat(40)}`,
    VERCEL_TEAM_ID: ELIGIBLE_TEAM_ID,
    VERCEL_PROJECT_ID: ELIGIBLE_PROJECT_ID,
    ...extra,
  };
}

describe("SBX-045 exact local intent", () => {
  it("cleans derived forks before the source", () => {
    expect(CLEANUP_ORDER).toEqual(["target", "inheritance", "source"]);
  });

  it("creates distinct source and target names containing complete fresh UUIDs", () => {
    const journal = createRecoveryJournal(false, new Date("2026-08-19T12:00:00.000Z"));
    expect(journal.resources.map((entry) => entry.role)).toEqual(["source", "target"]);
    expect(new Set(journal.resources.map((entry) => entry.name)).size).toBe(2);
    for (const entry of journal.resources) {
      expect(entry.name).toBe(`sbx-045-${entry.role}-${entry.resourceId}`);
      expect(entry.name).toContain(entry.resourceId);
      expect(entry.tags).toEqual({
        harness: "vsc",
        test: "SBX-045",
        run: journal.runId,
        role: entry.role,
        resource: entry.resourceId,
      });
    }
  });

  it("adds exactly one separately named optional inheritance fork", () => {
    const journal = createRecoveryJournal(true);
    expect(journal.resources.map((entry) => entry.role)).toEqual([
      "source",
      "inheritance",
      "target",
    ]);
    expect(new Set(journal.resources.map((entry) => entry.resourceId)).size).toBe(3);
  });

  it("omits env entirely for inheritance and sends one explicit same-key override for target", () => {
    const inherited = forkEnvironmentOverride();
    const overridden = forkEnvironmentOverride("synthetic-B");
    expect(Object.prototype.hasOwnProperty.call(inherited, "env")).toBe(false);
    expect(overridden).toEqual({ env: { SBX045_SYNTHETIC_ENV: "synthetic-B" } });
  });

  it("builds one fixed guest command with no command-level environment", () => {
    const command = fixedGuestCommandSpec();
    expect(command).toEqual({
      cmd: "node",
      args: ["/tmp/sbx-045/env-digest.mjs"],
      timeoutMs: 20_000,
    });
    expect(Object.prototype.hasOwnProperty.call(command, "env")).toBe(false);
  });

  it("pins the exact reviewed guest bytes before any remote request", async () => {
    const guest = await readFile(
      new URL("../guest/sbx-045-env-digest.mjs", import.meta.url),
    );
    expect(createHash("sha256").update(guest).digest("hex")).toBe(FIXED_GUEST_SHA256);
  });

  it("pins digest commands to Session and keeps durable files evidence-only", async () => {
    const source = await readFile(
      new URL("../pocs/SBX-045/fork-env-override.ts", import.meta.url),
      "utf8",
    );
    expect(source).toContain("const command = await session.runCommand({");
    expect(source).not.toContain("const command = await sandbox.runCommand({");
    const pending = source.indexOf('status: "pending"');
    const release = source.indexOf("await lock.release();", pending);
    const remove = source.indexOf("await removeRecoveryJournal", release);
    const complete = source.indexOf('status: "complete"', remove);
    expect(pending).toBeGreaterThan(0);
    expect(release).toBeGreaterThan(pending);
    expect(remove).toBeGreaterThan(release);
    expect(complete).toBeGreaterThan(remove);
    expect(source).toContain('outcome: assessment.verdict === "candidate" ? "exact-source-observed"');
    expect(source).toContain("verdict: durableVerdict,\n      candidate: false");
  });

  it("rejects journals with secrets, foreign tags, duplicate IDs, or reordered roles", () => {
    const base = createRecoveryJournal(false);
    expect(() => parseRecoveryJournal({ ...base, sourceValue: "raw-A" })).toThrow();
    expect(() => parseRecoveryJournal({
      ...base,
      resources: base.resources.map((entry, index) => index === 0
        ? { ...entry, tags: { ...entry.tags, role: "target" } }
        : entry),
    })).toThrow();
    expect(() => parseRecoveryJournal({
      ...base,
      resources: [base.resources[1], base.resources[0]],
    })).toThrow();
    expect(() => parseRecoveryJournal({
      ...base,
      resources: base.resources.map((entry, index) => index === 1
        ? {
            ...entry,
            resourceId: base.resources[0]!.resourceId,
            name: `sbx-045-target-${base.resources[0]!.resourceId}`,
            tags: {
              ...entry.tags,
              resource: base.resources[0]!.resourceId,
            },
          }
        : entry),
    })).toThrow();
  });
});

describe("SBX-045 explicit scope configuration", () => {
  it("accepts only the eligible alias team/project and a non-JWT PAT", () => {
    expect(loadExplicitConfig(environment())).toMatchObject({
      teamId: ELIGIBLE_TEAM_ID,
      projectId: ELIGIBLE_PROJECT_ID,
      expectedEmail: ELIGIBLE_ALIAS,
      inheritanceControlEnabled: false,
    });
    expect(() => loadExplicitConfig(environment({ VERCEL_TEAM_ID: "team_wrong" }))).toThrow();
    expect(() => loadExplicitConfig(environment({ SBX045_EXPECTED_ALIAS: "other@example.test" }))).toThrow();
    expect(() => loadExplicitConfig(environment({ VERCEL_TOKEN: "a.b.c" }))).toThrow();
  });

  it("makes a supplied run ID cleanup-only and rejects malformed recovery IDs", () => {
    const runId = "123e4567-e89b-42d3-a456-426614174000";
    expect(loadExplicitConfig(environment({ SBX045_RECOVERY_RUN_ID: runId }))).toMatchObject({
      recoveryRunId: runId,
    });
    expect(() => loadExplicitConfig(environment({
      SBX045_RECOVERY_RUN_ID: "../../foreign",
    }))).toThrow();
  });
});

describe("SBX-045 bounded request gate", () => {
  it("allows only identity and Sandbox control-plane origins and spaces starts", async () => {
    let clock = 10_000;
    const calls: string[] = [];
    const fakeFetch = (async (input: string | URL | Request): Promise<Response> => {
      calls.push(input instanceof Request ? input.url : input.toString());
      return new Response("{}", { status: 200 });
    }) as typeof fetch;
    const gate = createGatedFetch(
      fakeFetch,
      () => clock,
      async (milliseconds) => {
        clock += milliseconds;
      },
    );
    await gate.fetch("https://api.vercel.com/v2/user");
    await gate.fetch("https://vercel.com/api/v2/sandboxes?teamId=owned");
    expect(calls).toHaveLength(2);
    expect(Date.parse(gate.records[1]!.startedAt) - Date.parse(gate.records[0]!.startedAt))
      .toBeGreaterThanOrEqual(250);
    expect(gate.records[1]).not.toHaveProperty("body");
    expect(gate.records[1]).not.toHaveProperty("query");
    await expect(gate.fetch("https://example.com/collect")).rejects.toThrow();
    await expect(gate.fetch("http://vercel.com/api/v2/sandboxes")).rejects.toThrow();
    await expect(gate.fetch("https://vercel.com/api/v1/projects")).rejects.toThrow();
    await expect(gate.fetch("https://vercel.com/api/v2/sandboxsevil")).rejects.toThrow();
  });

  it("reserves the fixed request budget before concurrent calls can queue", async () => {
    let clock = Date.now();
    let calls = 0;
    const gate = createGatedFetch(
      (async () => {
        calls += 1;
        return new Response("{}", { status: 200 });
      }) as typeof fetch,
      () => clock,
      async (milliseconds) => {
        clock += milliseconds;
      },
    );
    const results = await Promise.allSettled(Array.from({ length: 101 }, async () =>
      gate.fetch("https://vercel.com/api/v2/sandboxes")));
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(100);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect(calls).toBe(100);
  });
});

describe("SBX-045 private recovery state and live lock", () => {
  it("writes a mode-0600 journal that round-trips through strict validation", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx-045-state-"));
    await chmod(directory, 0o700);
    try {
      const path = join(directory, "journal.json");
      const journal = createRecoveryJournal(false);
      await writePrivateJsonAtomically(path, journal);
      expect((await lstat(path)).mode & 0o777).toBe(0o600);
      expect(await readRecoveryJournal(path)).toEqual(journal);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("is exclusive, validates stale-run reclamation, and releases only its lease", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx-045-lock-"));
    await chmod(directory, 0o700);
    try {
      const path = join(directory, "live.lock");
      const runId = createRecoveryJournal(false).runId;
      const first = await acquireLiveLock(path, runId, "normal");
      await expect(acquireLiveLock(path, createRecoveryJournal(false).runId, "normal"))
        .rejects.toThrow();
      const recovered = await acquireLiveLock(path, runId, "cleanup-only", () => "dead");
      expect(recovered.reclaimed).toBe(true);
      await recovered.release();
      await expect(lstat(path)).rejects.toMatchObject({ code: "ENOENT" });
      // The stale handle cannot remove or replace a later lease.
      await expect(first.release()).rejects.toThrow();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("refuses a symlink at the live-lock path", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx-045-symlink-"));
    await chmod(directory, 0o700);
    try {
      const target = join(directory, "target");
      const path = join(directory, "live.lock");
      await writePrivateJsonAtomically(target, { harmless: true });
      await symlink(target, path);
      await expect(acquireLiveLock(path, createRecoveryJournal(false).runId, "normal"))
        .rejects.toThrow();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("recovers a fixed completed-release tombstone for the exact cleanup run", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx-045-release-"));
    await chmod(directory, 0o700);
    try {
      const path = join(directory, "live.lock");
      const runId = createRecoveryJournal(false).runId;
      const interrupted = await acquireLiveLock(path, runId, "normal");
      await rename(path, `${path}.release`);
      const recovered = await acquireLiveLock(path, runId, "cleanup-only");
      expect(recovered.reclaimed).toBe(true);
      await recovered.release();
      await expect(interrupted.release()).rejects.toThrow();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
