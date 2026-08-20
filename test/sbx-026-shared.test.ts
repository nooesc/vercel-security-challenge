import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  chmod,
  lstat,
  mkdtemp,
  readFile,
  rename,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it, vi } from "vitest";
import {
  acquireSbx026LiveLockAtPathForTest,
  apiFailureFromResponse,
  assertDistinctVerifiedIdentities,
  conclusiveAuthorizationRejection,
  createAccountFetch,
  loadTwoOwnedAccounts,
  MINIMUM_VERCEL_REQUEST_INTERVAL_MS,
  NO_CROSS_MEMBERSHIP_CONFIRMATION,
  OWNERSHIP_CONFIRMATION,
  oneShotSandboxRequest,
  readBoundedResponse,
  SBX026_LIVE_LOCK_FILENAME,
  SBX026_LIVE_LOCK_PATH,
  sandboxControlPlaneUrl,
  SCOPE_CONFIRMATION,
  VercelRequestGate,
  verifyAccountIdentity,
  type ExplicitAccountCredentials,
  type AcquireSbx026LiveLockOptions,
  type Sbx026LiveLockTestMutation,
} from "../pocs/SBX-026/shared.js";

const attacker: ExplicitAccountCredentials = {
  role: "attacker",
  token: "attacker-token-with-more-than-twenty-bytes",
  teamId: "team_attacker",
  projectId: "prj_attacker",
  expectedEmail: "attacker@wearehackerone.com",
};

function validEnvironment(): Record<string, string> {
  return {
    SBX026_SCOPE_CONFIRMATION: SCOPE_CONFIRMATION,
    SBX026_OWNERSHIP_CONFIRMATION: OWNERSHIP_CONFIRMATION,
    SBX026_NO_CROSS_MEMBERSHIP_CONFIRMATION: NO_CROSS_MEMBERSHIP_CONFIRMATION,
    SBX026_ATTACKER_TOKEN: attacker.token,
    SBX026_ATTACKER_TEAM_ID: attacker.teamId,
    SBX026_ATTACKER_PROJECT_ID: attacker.projectId,
    SBX026_ATTACKER_EMAIL: attacker.expectedEmail,
    SBX026_VICTIM_TOKEN: "victim-token-with-more-than-twenty-bytes",
    SBX026_VICTIM_TEAM_ID: "team_victim",
    SBX026_VICTIM_PROJECT_ID: "prj_victim",
    SBX026_VICTIM_EMAIL: "victim@wearehackerone.com",
  };
}

describe("SBX-026 two-account prerequisites", () => {
  it("accepts only two distinct explicit HackerOne-alias scopes", () => {
    expect(loadTwoOwnedAccounts(validEnvironment())).toMatchObject({
      attacker: { role: "attacker", expectedEmail: "attacker@wearehackerone.com" },
      victim: { role: "victim", expectedEmail: "victim@wearehackerone.com" },
    });

    for (const patch of [
      { SBX026_OWNERSHIP_CONFIRMATION: "no" },
      { SBX026_NO_CROSS_MEMBERSHIP_CONFIRMATION: "no" },
      { SBX026_VICTIM_EMAIL: "victim@example.com" },
      { SBX026_VICTIM_EMAIL: attacker.expectedEmail },
      { SBX026_VICTIM_TOKEN: attacker.token },
      { SBX026_VICTIM_TEAM_ID: attacker.teamId },
      { SBX026_VICTIM_PROJECT_ID: attacker.projectId },
    ]) {
      expect(() => loadTwoOwnedAccounts({ ...validEnvironment(), ...patch })).toThrow();
    }
  });

  it("requires identity responses to resolve to distinct Vercel users", () => {
    const attackerIdentity = {
      email: "attacker@wearehackerone.com",
      userId: "user_attacker",
      exactMatch: true as const,
    };
    const victimIdentity = {
      email: "victim@wearehackerone.com",
      userId: "user_victim",
      exactMatch: true as const,
    };
    expect(assertDistinctVerifiedIdentities(attackerIdentity, victimIdentity)).toBe(true);
    expect(() => assertDistinctVerifiedIdentities(attackerIdentity, {
      ...victimIdentity,
      userId: attackerIdentity.userId,
    })).toThrow(/distinct Vercel users/u);
  });
});

describe("SBX-026 controlled Vercel transport", () => {
  it("allows only the exact account authorization, team, and Sandbox/identity endpoints", async () => {
    const baseFetch = vi.fn<typeof fetch>(async () =>
      new Response(JSON.stringify({ user: { id: "user_attacker", email: attacker.expectedEmail } }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    );
    const gate = new VercelRequestGate();
    const accountFetch = createAccountFetch(attacker, gate, baseFetch);

    await expect(verifyAccountIdentity(attacker, accountFetch)).resolves.toEqual({
      email: attacker.expectedEmail,
      userId: "user_attacker",
      exactMatch: true,
    });
    await expect(accountFetch(
      `https://vercel.com/api/v2/sandboxes?teamId=${attacker.teamId}`,
      { headers: { Authorization: `Bearer ${attacker.token}` } },
    )).resolves.toBeInstanceOf(Response);

    await expect(accountFetch(
      "https://vercel.com/api/v2/sandboxes?teamId=team_victim",
      { headers: { Authorization: `Bearer ${attacker.token}` } },
    )).rejects.toThrow(/teamId/u);
    await expect(accountFetch(
      `https://vercel.com/api/v10/projects?teamId=${attacker.teamId}`,
      { headers: { Authorization: `Bearer ${attacker.token}` } },
    )).rejects.toThrow(/non-Sandbox/u);
    await expect(accountFetch(
      `https://vercel.com/api/v2/sandboxes?teamId=${attacker.teamId}`,
      { headers: { Authorization: "Bearer wrong" } },
    )).rejects.toThrow(/authorization/u);
    expect(baseFetch).toHaveBeenCalledTimes(2);
    expect(gate.records).toHaveLength(2);
    expect(Date.parse(gate.records[1]!.startedAt) - Date.parse(gate.records[0]!.startedAt))
      .toBeGreaterThanOrEqual(MINIMUM_VERCEL_REQUEST_INTERVAL_MS);
  });

  it("constructs only bounded Sandbox URLs with an optional exact project query", () => {
    expect(sandboxControlPlaneUrl(
      attacker,
      "/v2/sandboxes/victim/fork",
      { projectId: "prj_victim" },
    ).href).toBe(
      "https://vercel.com/api/v2/sandboxes/victim/fork?teamId=team_attacker&projectId=prj_victim",
    );
    expect(() => sandboxControlPlaneUrl(
      attacker,
      "/v2/sandboxes/victim/fork",
      { projectId: "invalid" },
    )).toThrow(/projectId/u);
    expect(() => sandboxControlPlaneUrl(
      attacker,
      "/v2/sandboxes/victim/fork",
      { cursor: "opaque" } as unknown as { projectId?: string },
    )).toThrow(/only an exact projectId/u);
  });

  it("makes exactly one transport attempt even for a retryable server response", async () => {
    const baseFetch = vi.fn<typeof fetch>(async () =>
      new Response(JSON.stringify({ error: { code: "internal_error" } }), { status: 503 })
    );
    const gate = new VercelRequestGate();
    const accountFetch = createAccountFetch(attacker, gate, baseFetch);
    const response = await oneShotSandboxRequest(
      attacker,
      accountFetch,
      "/v3/sandboxes",
      {
        method: "POST",
        body: "{}",
        headers: { "content-type": "application/json" },
        signal: AbortSignal.timeout(1_000),
      },
    );
    expect(response.status).toBe(503);
    expect(baseFetch).toHaveBeenCalledTimes(1);
    expect(gate.records).toHaveLength(1);
  });

  it("caps retained response bytes and stores only bounded API failure fields", async () => {
    await expect(readBoundedResponse(new Response("12345"), 4)).rejects.toThrow(/exceeded/u);
    await expect(apiFailureFromResponse(new Response(JSON.stringify({
      error: { code: "not_found", message: "do not retain me" },
    }), { status: 404 }))).resolves.toEqual({
      kind: "api",
      status: 404,
      code: "not_found",
    });
    expect(conclusiveAuthorizationRejection({ kind: "api", status: 404 })).toBe(true);
    expect(conclusiveAuthorizationRejection({ kind: "api", status: 422, code: "snapshot_not_found" }))
      .toBe(true);
    expect(conclusiveAuthorizationRejection({ kind: "api", status: 429 })).toBe(false);
    expect(conclusiveAuthorizationRejection({ kind: "api", status: 401 })).toBe(false);
    expect(conclusiveAuthorizationRejection({ kind: "api", status: 410 })).toBe(false);
    expect(conclusiveAuthorizationRejection({ kind: "other" })).toBe(false);
  });
});

type ChildOutcome = {
  result: "won" | "lost" | "crashed";
  scope?: string;
  message?: string;
  mutation?: Sbx026LiveLockTestMutation;
};

const repositoryDirectory = resolve(".");
const sharedModuleUrl = pathToFileURL(
  resolve(repositoryDirectory, "pocs/SBX-026/shared.ts"),
).href;

function lockWorkerSource(
  path: string,
  options: AcquireSbx026LiveLockOptions,
  holdWinner: boolean,
  crashAt?: Sbx026LiveLockTestMutation,
): string {
  return `
const shared = await import(${JSON.stringify(sharedModuleUrl)});
try {
  const crashAt = ${JSON.stringify(crashAt)};
  const lock = await shared.acquireSbx026LiveLockAtPathForTest(
    ${JSON.stringify(path)},
    ${JSON.stringify(options)},
    (mutation) => {
      if (mutation === crashAt) {
        process.stdout.write(JSON.stringify({ result: "crashed", mutation }) + "\\n");
        process.exit(86);
      }
    },
  );
  process.stdout.write(JSON.stringify({ result: "won", scope: lock.metadata.scope }) + "\\n");
  if (${JSON.stringify(holdWinner)}) {
    process.stdin.setEncoding("utf8");
    process.stdin.once("data", async (instruction) => {
      try {
        if (String(instruction).trim() === "release") await lock.release();
        process.exit(0);
      } catch (error) {
        process.stderr.write(String(error instanceof Error ? error.message : error));
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

function spawnLockWorker(
  path: string,
  options: AcquireSbx026LiveLockOptions,
  holdWinner: boolean,
  crashAt?: Sbx026LiveLockTestMutation,
): ChildProcessWithoutNullStreams {
  return spawn(process.execPath, [
    "--import",
    "tsx",
    "--input-type=module",
    "--eval",
    lockWorkerSource(path, options, holdWinner, crashAt),
  ], {
    cwd: repositoryDirectory,
    env: { ...process.env },
    stdio: ["pipe", "pipe", "pipe"],
  });
}

async function childFirstOutcome(child: ChildProcessWithoutNullStreams): Promise<ChildOutcome> {
  return new Promise<ChildOutcome>((resolveOutcome, rejectOutcome) => {
    let settled = false;
    let stdout = "";
    let stderr = "";
    const finish = (callback: () => void): void => {
      if (settled) return;
      settled = true;
      callback();
    };
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
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
    child.once("error", (error) => finish(() => rejectOutcome(error)));
    child.once("exit", (code) => finish(() => rejectOutcome(new Error(
      `lock worker exited ${code ?? "without status"} before an outcome (${stderr.slice(0, 256)})`,
    ))));
  });
}

async function childExitCode(child: ChildProcessWithoutNullStreams): Promise<number | null> {
  if (child.exitCode !== null) return child.exitCode;
  return new Promise<number | null>((resolveExit, rejectExit) => {
    child.once("error", rejectExit);
    child.once("exit", (code) => resolveExit(code));
  });
}

async function makeTemporaryLock(): Promise<{ directory: string; path: string }> {
  const directory = await mkdtemp(join(tmpdir(), "sbx026-shared-lock-"));
  return { directory, path: join(directory, SBX026_LIVE_LOCK_FILENAME) };
}

async function leaveStaleLock(
  path: string,
  options: AcquireSbx026LiveLockOptions,
): Promise<void> {
  const child = spawnLockWorker(path, options, false);
  expect(await childFirstOutcome(child)).toMatchObject({ result: "won" });
  expect(await childExitCode(child)).toBe(0);
}

async function endHeldWorker(
  child: ChildProcessWithoutNullStreams,
  instruction: "release" | "abandon",
): Promise<void> {
  child.stdin.end(`${instruction}\n`);
  expect(await childExitCode(child)).toBe(0);
}

async function expectWorkerCrash(
  child: ChildProcessWithoutNullStreams,
  mutation: Sbx026LiveLockTestMutation,
): Promise<void> {
  expect(await childFirstOutcome(child)).toEqual({ result: "crashed", mutation });
  expect(await childExitCode(child)).toBe(86);
}

async function expectAllNormalScopesRefused(
  path: string,
  runId: string,
): Promise<void> {
  for (const options of [
    { scope: "snapshot", runId, mode: "normal" },
    { scope: "fork", runId, mode: "normal" },
    { scope: "session-command", lane: "session-read", runId, mode: "normal" },
  ] as const) {
    await expect(acquireSbx026LiveLockAtPathForTest(path, options)).rejects.toThrow(
      /sentinel exists|live lock already exists/u,
    );
  }
}

describe.sequential("SBX-026 cross-process live lock", () => {
  it("uses one repository path regardless of cwd or environment overrides", async () => {
    const temporary = await makeTemporaryLock();
    try {
      const source = `
process.chdir(${JSON.stringify(temporary.directory)});
process.env.HARNESS_ARTIFACTS_DIR = ${JSON.stringify(join(temporary.directory, "other"))};
process.env.SBX026_LIVE_LOCK_PATH = ${JSON.stringify(join(temporary.directory, "wrong.lock"))};
const shared = await import(${JSON.stringify(sharedModuleUrl)});
process.stdout.write(shared.SBX026_LIVE_LOCK_PATH + "\\n");
`;
      const child = spawn(process.execPath, [
        "--import",
        "tsx",
        "--input-type=module",
        "--eval",
        source,
      ], {
        cwd: repositoryDirectory,
        env: { ...process.env },
        stdio: ["pipe", "pipe", "pipe"],
      });
      const output = await new Promise<string>((resolveOutput, rejectOutput) => {
        let stdout = "";
        let stderr = "";
        child.stdout.setEncoding("utf8");
        child.stderr.setEncoding("utf8");
        child.stdout.on("data", (chunk: string) => {
          stdout += chunk;
        });
        child.stderr.on("data", (chunk: string) => {
          stderr += chunk;
        });
        child.once("error", rejectOutput);
        child.once("exit", (code) => {
          if (code === 0) resolveOutput(stdout.trim());
          else rejectOutput(new Error(`path worker exited ${code}: ${stderr.slice(0, 256)}`));
        });
      });
      expect(output).toBe(SBX026_LIVE_LOCK_PATH);
      expect(SBX026_LIVE_LOCK_PATH).toBe(resolve(
        repositoryDirectory,
        "artifacts/SBX-026-live-active.lock",
      ));
    } finally {
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });

  it("refuses to reclaim a live exact owner and reclaims it only after ESRCH", async () => {
    const temporary = await makeTemporaryLock();
    const options: AcquireSbx026LiveLockOptions = {
      scope: "snapshot",
      lane: "restore",
      runId: randomUUID(),
      mode: "normal",
    };
    const owner = spawnLockWorker(temporary.path, options, true);
    try {
      expect(await childFirstOutcome(owner)).toMatchObject({ result: "won", scope: "snapshot" });
      const metadata = JSON.parse(await readFile(temporary.path, "utf8")) as Record<string, unknown>;
      expect(metadata).toMatchObject({
        schemaVersion: 1,
        testId: "SBX-026",
        scope: "snapshot",
        lane: "restore",
        runId: options.runId,
        pid: owner.pid,
        mode: "normal",
      });
      expect((await lstat(temporary.path)).mode & 0o777).toBe(0o600);
      await expect(acquireSbx026LiveLockAtPathForTest(temporary.path, {
        ...options,
        mode: "cleanup-only",
      })).rejects.toThrow(/owner PID is live/u);

      await endHeldWorker(owner, "abandon");
      const reclaimed = await acquireSbx026LiveLockAtPathForTest(temporary.path, {
        ...options,
        mode: "cleanup-only",
      });
      expect(reclaimed.reclaimed).toBe(true);
      await reclaimed.release();
      await expect(lstat(temporary.path)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      if (owner.exitCode === null) {
        owner.kill("SIGKILL");
        await childExitCode(owner).catch(() => undefined);
      }
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });

  it("lets exactly one cleanup-only process atomically reclaim one stale lease", async () => {
    const temporary = await makeTemporaryLock();
    const runId = randomUUID();
    const normal: AcquireSbx026LiveLockOptions = { scope: "fork", runId, mode: "normal" };
    try {
      await leaveStaleLock(temporary.path, normal);
      const cleanup: AcquireSbx026LiveLockOptions = { ...normal, mode: "cleanup-only" };
      const first = spawnLockWorker(temporary.path, cleanup, true);
      const second = spawnLockWorker(temporary.path, cleanup, true);
      const outcomes = await Promise.all([childFirstOutcome(first), childFirstOutcome(second)]);
      expect(outcomes.filter((outcome) => outcome.result === "won")).toHaveLength(1);
      expect(outcomes.filter((outcome) => outcome.result === "lost")).toHaveLength(1);
      const winner = outcomes[0]!.result === "won" ? first : second;
      const loser = winner === first ? second : first;
      await endHeldWorker(winner, "release");
      expect(await childExitCode(loser)).toBe(0);
      await expect(lstat(temporary.path)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });

  it("keeps a recognized blocker across every primary reclaim mutation", async () => {
    const stages: readonly Sbx026LiveLockTestMutation[] = [
      "transaction-created",
      "canonical-replacement-created",
      "canonical-replaced",
      "transaction-removed",
    ];
    for (const stage of stages) {
      const temporary = await makeTemporaryLock();
      const runId = randomUUID();
      const normal: AcquireSbx026LiveLockOptions = { scope: "fork", runId, mode: "normal" };
      try {
        await leaveStaleLock(temporary.path, normal);
        const crashing = spawnLockWorker(
          temporary.path,
          { ...normal, mode: "cleanup-only" },
          false,
          stage,
        );
        await expectWorkerCrash(crashing, stage);
        const canonicalExists = await lstat(temporary.path).then(() => true, () => false);
        const transactionExists = await lstat(`${temporary.path}.transaction`)
          .then(() => true, () => false);
        expect(canonicalExists || transactionExists).toBe(true);
        await expectAllNormalScopesRefused(temporary.path, runId);

        const recovered = await acquireSbx026LiveLockAtPathForTest(temporary.path, {
          ...normal,
          mode: "cleanup-only",
        });
        await recovered.release();
      } finally {
        await rm(temporary.directory, { recursive: true, force: true });
      }
    }
  }, 20_000);

  it("keeps the fixed transaction sentinel present across guarded stale-sentinel takeover", async () => {
    const stages: readonly Sbx026LiveLockTestMutation[] = [
      "recovery-guard-created",
      "transaction-replacement-created",
      "transaction-replaced",
      "recovery-guard-removed",
    ];
    for (const stage of stages) {
      const temporary = await makeTemporaryLock();
      const runId = randomUUID();
      const normal: AcquireSbx026LiveLockOptions = { scope: "snapshot", runId, mode: "normal" };
      try {
        const initial = spawnLockWorker(
          temporary.path,
          normal,
          false,
          "transaction-created",
        );
        await expectWorkerCrash(initial, "transaction-created");
        await expect(lstat(`${temporary.path}.transaction`)).resolves.toBeDefined();
        await expect(lstat(temporary.path)).rejects.toMatchObject({ code: "ENOENT" });

        const crashing = spawnLockWorker(
          temporary.path,
          { ...normal, mode: "cleanup-only" },
          false,
          stage,
        );
        await expectWorkerCrash(crashing, stage);
        await expect(lstat(`${temporary.path}.transaction`)).resolves.toBeDefined();
        await expectAllNormalScopesRefused(temporary.path, runId);

        const recovered = await acquireSbx026LiveLockAtPathForTest(temporary.path, {
          ...normal,
          mode: "cleanup-only",
        });
        await recovered.release();
      } finally {
        await rm(temporary.directory, { recursive: true, force: true });
      }
    }
  }, 20_000);

  it("keeps the transaction sentinel while a stale recovery guard is itself reclaimed", async () => {
    const stages: readonly Sbx026LiveLockTestMutation[] = [
      "stale-recovery-guard-claimed",
      "recovery-guard-replaced",
      "stale-recovery-guard-removed",
    ];
    for (const stage of stages) {
      const temporary = await makeTemporaryLock();
      const runId = randomUUID();
      const normal: AcquireSbx026LiveLockOptions = { scope: "fork", runId, mode: "normal" };
      const cleanup: AcquireSbx026LiveLockOptions = { ...normal, mode: "cleanup-only" };
      try {
        const initial = spawnLockWorker(
          temporary.path,
          normal,
          false,
          "transaction-created",
        );
        await expectWorkerCrash(initial, "transaction-created");
        const guardOwner = spawnLockWorker(
          temporary.path,
          cleanup,
          false,
          "recovery-guard-created",
        );
        await expectWorkerCrash(guardOwner, "recovery-guard-created");

        const crashing = spawnLockWorker(temporary.path, cleanup, false, stage);
        await expectWorkerCrash(crashing, stage);
        await expect(lstat(`${temporary.path}.transaction`)).resolves.toBeDefined();
        await expectAllNormalScopesRefused(temporary.path, runId);

        const recovered = await acquireSbx026LiveLockAtPathForTest(temporary.path, cleanup);
        await recovered.release();
      } finally {
        await rm(temporary.directory, { recursive: true, force: true });
      }
    }
  }, 20_000);

  it("keeps mismatched packet, lane, and run locks byte-identical", async () => {
    const temporary = await makeTemporaryLock();
    const runId = randomUUID();
    const exact: AcquireSbx026LiveLockOptions = {
      scope: "snapshot",
      lane: "restore",
      runId,
      mode: "normal",
    };
    try {
      await leaveStaleLock(temporary.path, exact);
      const before = await readFile(temporary.path);
      await expect(acquireSbx026LiveLockAtPathForTest(temporary.path, {
        scope: "fork",
        runId,
        mode: "cleanup-only",
      })).rejects.toThrow(/non-matching/u);
      expect(await readFile(temporary.path)).toEqual(before);
      await expect(acquireSbx026LiveLockAtPathForTest(temporary.path, {
        ...exact,
        lane: "different-lane",
        mode: "cleanup-only",
      })).rejects.toThrow(/non-matching/u);
      expect(await readFile(temporary.path)).toEqual(before);
      await expect(acquireSbx026LiveLockAtPathForTest(temporary.path, {
        ...exact,
        runId: randomUUID(),
        mode: "cleanup-only",
      })).rejects.toThrow(/non-matching/u);
      expect(await readFile(temporary.path)).toEqual(before);

      const reclaimed = await acquireSbx026LiveLockAtPathForTest(temporary.path, {
        ...exact,
        mode: "cleanup-only",
      });
      await reclaimed.release();
      before.fill(0);
    } finally {
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });

  it("keeps a mismatched global transaction sentinel byte-identical", async () => {
    const temporary = await makeTemporaryLock();
    const runId = randomUUID();
    const exact: AcquireSbx026LiveLockOptions = {
      scope: "session-command",
      lane: "session-read",
      runId,
      mode: "normal",
    };
    const transaction = `${temporary.path}.transaction`;
    try {
      const initial = spawnLockWorker(
        temporary.path,
        exact,
        false,
        "transaction-created",
      );
      await expectWorkerCrash(initial, "transaction-created");
      const before = await readFile(transaction);
      for (const mismatched of [
        { scope: "fork", runId, mode: "cleanup-only" },
        {
          scope: "session-command",
          lane: "command-run",
          runId,
          mode: "cleanup-only",
        },
        {
          scope: "session-command",
          lane: "session-read",
          runId: randomUUID(),
          mode: "cleanup-only",
        },
      ] as const) {
        await expect(acquireSbx026LiveLockAtPathForTest(temporary.path, mismatched))
          .rejects.toThrow(/non-matching transaction/u);
        expect(await readFile(transaction)).toEqual(before);
      }
      const recovered = await acquireSbx026LiveLockAtPathForTest(temporary.path, {
        ...exact,
        mode: "cleanup-only",
      });
      await recovered.release();
      before.fill(0);
    } finally {
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });

  it("allows exactly one concurrent normal fork or session-command packet", async () => {
    const temporary = await makeTemporaryLock();
    const fork = spawnLockWorker(temporary.path, {
      scope: "fork",
      runId: randomUUID(),
      mode: "normal",
    }, true);
    const session = spawnLockWorker(temporary.path, {
      scope: "session-command",
      lane: "session-read",
      runId: randomUUID(),
      mode: "normal",
    }, true);
    try {
      const outcomes = await Promise.all([childFirstOutcome(fork), childFirstOutcome(session)]);
      expect(outcomes.filter((outcome) => outcome.result === "won")).toHaveLength(1);
      expect(outcomes.filter((outcome) => outcome.result === "lost")).toHaveLength(1);
      const winner = outcomes[0]!.result === "won" ? fork : session;
      const loser = winner === fork ? session : fork;
      await endHeldWorker(winner, "release");
      expect(await childExitCode(loser)).toBe(0);
    } finally {
      for (const child of [fork, session]) {
        if (child.exitCode === null) child.kill("SIGKILL");
      }
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });

  it("rejects symlinks, wrong modes, and oversized metadata without following or replacing them", async () => {
    const temporary = await makeTemporaryLock();
    const target = join(temporary.directory, "target");
    const targetBody = Buffer.from("do-not-touch", "utf8");
    const runId = randomUUID();
    const exact: AcquireSbx026LiveLockOptions = { scope: "fork", runId, mode: "cleanup-only" };
    try {
      await chmod(temporary.directory, 0o755);
      await expect(acquireSbx026LiveLockAtPathForTest(temporary.path, {
        ...exact,
        mode: "normal",
      })).rejects.toThrow(/exact mode 0700/u);
      await chmod(temporary.directory, 0o700);
      await expect(acquireSbx026LiveLockAtPathForTest(temporary.path, {
        ...exact,
        runId: "00000000-0000-0000-0000-000000000000",
        mode: "normal",
      })).rejects.toThrow(/canonical UUID/u);

      await writeFile(target, targetBody, { mode: 0o600, flag: "wx" });
      await symlink(target, temporary.path);
      await expect(acquireSbx026LiveLockAtPathForTest(temporary.path, exact))
        .rejects.toThrow(/regular file/u);
      expect(await readFile(target)).toEqual(targetBody);
      await unlink(temporary.path);

      await leaveStaleLock(temporary.path, { ...exact, mode: "normal" });
      const staleBody = await readFile(temporary.path);
      await chmod(temporary.path, 0o644);
      await expect(acquireSbx026LiveLockAtPathForTest(temporary.path, exact))
        .rejects.toThrow(/exact mode 0600/u);
      expect(await readFile(temporary.path)).toEqual(staleBody);
      await unlink(temporary.path);

      const oversized = Buffer.alloc(4_097, 0x78);
      await writeFile(temporary.path, oversized, { mode: 0o600, flag: "wx" });
      await expect(acquireSbx026LiveLockAtPathForTest(temporary.path, exact))
        .rejects.toThrow(/fixed byte bound/u);
      expect((await lstat(temporary.path)).size).toBe(4_097);
      oversized.fill(0);
      staleBody.fill(0);
    } finally {
      targetBody.fill(0);
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });

  it("blocks every acquisition until the release transaction reaches its linearization point", async () => {
    const preLinearization: readonly Sbx026LiveLockTestMutation[] = [
      "release-transaction-created",
      "release-canonical-claimed",
      "release-canonical-removed",
    ];
    for (const stage of preLinearization) {
      const temporary = await makeTemporaryLock();
      const runId = randomUUID();
      const normal: AcquireSbx026LiveLockOptions = {
        scope: "session-command",
        lane: "command-run",
        runId,
        mode: "normal",
      };
      const owner = spawnLockWorker(temporary.path, normal, true, stage);
      try {
        expect(await childFirstOutcome(owner)).toMatchObject({ result: "won" });
        owner.stdin.end("release\n");
        expect(await childExitCode(owner)).toBe(86);
        await expect(lstat(`${temporary.path}.transaction`)).resolves.toBeDefined();
        await expectAllNormalScopesRefused(temporary.path, runId);

        const recovered = await acquireSbx026LiveLockAtPathForTest(temporary.path, {
          ...normal,
          mode: "cleanup-only",
        });
        await recovered.release();
      } finally {
        if (owner.exitCode === null) owner.kill("SIGKILL");
        await rm(temporary.directory, { recursive: true, force: true });
      }
    }

    const temporary = await makeTemporaryLock();
    const runId = randomUUID();
    const normal: AcquireSbx026LiveLockOptions = { scope: "fork", runId, mode: "normal" };
    const owner = spawnLockWorker(
      temporary.path,
      normal,
      true,
      "release-transaction-removed",
    );
    try {
      expect(await childFirstOutcome(owner)).toMatchObject({ result: "won" });
      owner.stdin.end("release\n");
      expect(await childExitCode(owner)).toBe(86);
      await expect(lstat(temporary.path)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(`${temporary.path}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
      const successor = await acquireSbx026LiveLockAtPathForTest(temporary.path, {
        scope: "snapshot",
        runId: randomUUID(),
        mode: "normal",
      });
      await successor.release();
    } finally {
      if (owner.exitCode === null) owner.kill("SIGKILL");
      await rm(temporary.directory, { recursive: true, force: true });
    }
  }, 20_000);

  it("never rejects release while both canonical and fixed transaction blockers are absent", async () => {
    const successfulRetry = await makeTemporaryLock();
    try {
      const lock = await acquireSbx026LiveLockAtPathForTest(successfulRetry.path, {
        scope: "fork",
        runId: randomUUID(),
        mode: "normal",
      }, (mutation) => {
        if (mutation === "release-canonical-removed") {
          throw new Error("injected ordinary post-canonical error");
        }
      });
      await expect(lock.release()).resolves.toBeUndefined();
      await expect(lstat(successfulRetry.path)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(`${successfulRetry.path}.transaction`))
        .rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(successfulRetry.directory, { recursive: true, force: true });
    }

    const failedRetry = await makeTemporaryLock();
    try {
      const transactionPath = `${failedRetry.path}.transaction`;
      const replacementPath = `${transactionPath}.injected-replacement`;
      const lock = await acquireSbx026LiveLockAtPathForTest(failedRetry.path, {
        scope: "snapshot",
        runId: randomUUID(),
        mode: "normal",
      }, async (mutation) => {
        if (mutation !== "release-canonical-removed") return;
        const bytes = await readFile(transactionPath);
        try {
          await rename(transactionPath, replacementPath);
          await writeFile(transactionPath, bytes, { mode: 0o600, flag: "wx" });
        } finally {
          bytes.fill(0);
        }
        throw new Error("injected transaction ownership swap");
      });
      await expect(lock.release()).rejects.toThrow(/injected transaction ownership swap/u);
      await expect(lstat(failedRetry.path)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(transactionPath)).resolves.toBeDefined();
    } finally {
      await rm(failedRetry.directory, { recursive: true, force: true });
    }

    const postLinearization = await makeTemporaryLock();
    try {
      const lock = await acquireSbx026LiveLockAtPathForTest(postLinearization.path, {
        scope: "fork",
        runId: randomUUID(),
        mode: "normal",
      }, (mutation) => {
        if (mutation === "release-transaction-removed") {
          throw new Error("injected post-linearization claim-cleanup error");
        }
      });
      await expect(lock.release()).resolves.toBeUndefined();
      await expect(lstat(postLinearization.path)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(`${postLinearization.path}.transaction`))
        .rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(postLinearization.directory, { recursive: true, force: true });
    }
  });

  it("refuses to release a replaced path and leaves the replacement untouched", async () => {
    const temporary = await makeTemporaryLock();
    const backup = join(temporary.directory, "original-held-lock");
    const lock = await acquireSbx026LiveLockAtPathForTest(temporary.path, {
      scope: "session-command",
      lane: "command-run",
      runId: randomUUID(),
      mode: "normal",
    });
    try {
      const original = await readFile(temporary.path);
      await rename(temporary.path, backup);
      await writeFile(temporary.path, original, { mode: 0o600, flag: "wx" });
      const replacement = await readFile(temporary.path);
      await expect(lock.release()).rejects.toThrow(/replaced/u);
      expect(await readFile(temporary.path)).toEqual(replacement);
      expect(await readFile(backup)).toEqual(original);
      original.fill(0);
      replacement.fill(0);
    } finally {
      await rm(temporary.directory, { recursive: true, force: true });
    }
  });
});
