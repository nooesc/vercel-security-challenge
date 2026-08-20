import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { lstat, mkdtemp, readFile, rm, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import {
  acquireSbx055LiveLockAtPathForTest,
} from "../pocs/SBX-055/live-lock.js";
import type { Sbx055InteractiveAttempt } from "../pocs/SBX-055/protocol.js";
import {
  auditSbx055InstalledWire,
  createSbx055RequestGate,
  exactSbx055S1Barrier,
  exactSbx055S2Barrier,
  exactSbx055RecoveredStopSnapshotId,
  exactSbx055SnapshotDelete404Checkpoint,
  exactSbx055UnresolvedResumeHandle,
  planSbx055SnapshotCleanup,
  shouldMintSbx055S2Credential,
  shouldIssueSbx055CleanupStop,
  writeSbx055LocalRecoveryCompletion,
} from "../pocs/SBX-055/stale-interactive-resume.js";
import type { Sbx055SandboxReadback } from "../pocs/SBX-055/verdict.js";
import {
  SBX055_ALIAS,
  SBX055_PROJECT,
  SBX055_SANDBOX_TIMEOUT_MS,
  SBX055_SNAPSHOT_EXPIRATION_MS,
  SBX055_TEAM,
  dispatchSbx055RecoveryAtPathsForTest,
  createSbx055Journal,
  sbx055RecoveryArtifactPath,
} from "../pocs/SBX-055/safety.js";

const repositoryDirectory = resolve(".");
const lockModuleUrl = pathToFileURL(resolve(repositoryDirectory, "pocs/SBX-055/live-lock.ts")).href;
const safetyModuleUrl = pathToFileURL(resolve(repositoryDirectory, "pocs/SBX-055/safety.ts")).href;

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

const pat = "offline_controller_pat_never_sent_055";
const s1 = "sbx_offline_controller_session_s1_055";

function fakeClock() {
  let milliseconds = 0;
  return {
    now: () => milliseconds,
    wait: async (duration: number) => { milliseconds += duration; },
  };
}

function authorization() {
  return { authorization: `Bearer ${pat}` };
}

function staleRejection(): Sbx055InteractiveAttempt {
  return {
    purpose: "stale-s1-token-on-s2",
    issuedUrlRole: "S1",
    tokenSourceSession: "S1",
    expectedRuntimeRole: "S2",
    urlCredentialPurpose: "s1-fresh-stale",
    tokenCredentialPurpose: "s1-fresh-stale",
    requestCount: 1,
    retryCount: 0,
    webSocketClient: "ws@8.21.0",
    statusCategory: "auth-rejected",
    unexpectedResponseObserved: true,
    handshakeStatusCode: 403,
    handshakeResponseBodyRetained: false,
    handshakeResponseHeadersRetained: false,
    opened: false,
    authenticated: false,
    openedExactIssuedUrl: false,
    emptyNegotiatedProtocol: false,
    emptyNegotiatedExtensions: false,
    startMessageExpected: true,
    startMessagesSent: 0,
    exactStartMessage: false,
    binaryFrames: 0,
    textControlFrames: 0,
    outputBytes: 0,
    markerMatched: false,
    crossMarkerAbsent: false,
    exitCode: null,
    protocolValid: false,
    terminal: "http-response-before-open",
    rawOutputRetained: false,
    rawMarkerRetained: false,
    rawTokenRetained: false,
    rawTokenDigestRetained: false,
    queryBearingUrlRetained: false,
  };
}

function readback(role: "S1" | "S2", journal = createSbx055Journal()): Sbx055SandboxReadback {
  const sessionId = role === "S1" ? "sbx_aaaaaaaaaaaaaaaaaaaa" : "sbx_bbbbbbbbbbbbbbbbbbbb";
  const snapshotId = "snap_cccccccccccccccccccc";
  return {
    stage: role === "S1" ? "s1-pre-stop" : "s2-pre-attempt",
    role,
    name: journal.sandboxName,
    independentName: journal.sandboxName,
    listedName: journal.sandboxName,
    activeSessionId: sessionId,
    independentSessionId: sessionId,
    listedSessionId: sessionId,
    activeStatus: "running",
    independentStatus: "running",
    listedStatus: "running",
    activeTagsExact: true,
    independentTagsExact: true,
    listedTagsExact: true,
    activePersistent: true,
    independentPersistent: true,
    listedPersistent: true,
    activeTimeoutMs: SBX055_SANDBOX_TIMEOUT_MS,
    independentTimeoutMs: SBX055_SANDBOX_TIMEOUT_MS,
    listedTimeoutMs: SBX055_SANDBOX_TIMEOUT_MS,
    activeDenyAll: true,
    activeSessionDenyAll: true,
    independentDenyAll: true,
    independentSessionDenyAll: true,
    listedDenyAll: true,
    activeInteractivePort: role === "S1" ? 41_055 : 41_056,
    independentInteractivePort: role === "S1" ? 41_055 : 41_056,
    activeExactSingleInteractiveRoute: true,
    independentRouteCount: 0,
    sourceSnapshotId: role === "S1" ? null : snapshotId,
    independentSourceSnapshotId: role === "S1" ? null : snapshotId,
    independentResumeFalse: true,
    listQueryExactNamePrefix: true,
    exactOneListedSandbox: true,
    listPaginationComplete: true,
  };
}

function negative(purpose: "missing-token-negative" | "random-token-negative"): Sbx055InteractiveAttempt {
  const value = staleRejection();
  const source = purpose === "missing-token-negative" ? "none" : "random";
  return {
    ...value,
    purpose,
    tokenSourceSession: source,
    expectedRuntimeRole: "none",
    urlCredentialPurpose: "s1-owner-control",
    tokenCredentialPurpose: source,
    startMessageExpected: false,
    exactStartMessage: true,
  };
}

function owner(role: "S1" | "S2"): Sbx055InteractiveAttempt {
  const purpose = role === "S1" ? "s1-owner-control" : "s2-owner-control";
  return {
    ...staleRejection(),
    purpose,
    issuedUrlRole: role,
    tokenSourceSession: role,
    expectedRuntimeRole: role,
    urlCredentialPurpose: purpose,
    tokenCredentialPurpose: purpose,
    statusCategory: "websocket-opened",
    unexpectedResponseObserved: false,
    handshakeStatusCode: null,
    opened: true,
    authenticated: true,
    openedExactIssuedUrl: true,
    emptyNegotiatedProtocol: true,
    emptyNegotiatedExtensions: true,
    startMessagesSent: 1,
    exactStartMessage: true,
    binaryFrames: 1,
    textControlFrames: 1,
    outputBytes: 43,
    markerMatched: true,
    crossMarkerAbsent: true,
    exitCode: 0,
    protocolValid: true,
    terminal: "closed-after-exit",
  };
}

describe("SBX-055 controller", () => {
  it("pins the installed SDK lifecycle and WebSocket wire offline", async () => {
    await expect(auditSbx055InstalledWire()).resolves.toBe(true);
  });

  it("admits only the exact persistent no-user-port create and no guest environment", async () => {
    let calls = 0;
    const rawFetch = (async () => {
      calls += 1;
      return Response.json({ ok: true });
    }) as typeof fetch;
    const journal = createSbx055Journal();
    const gate = createSbx055RequestGate(rawFetch, pat, journal, fakeClock());
    const body = {
      projectId: SBX055_PROJECT,
      ports: [],
      timeout: SBX055_SANDBOX_TIMEOUT_MS,
      resources: { vcpus: 2 },
      name: journal.sandboxName,
      persistent: true,
      networkPolicy: { mode: "deny-all" },
      tags: journal.tags,
      snapshotExpiration: SBX055_SNAPSHOT_EXPIRATION_MS,
      __interactive: true,
    };
    const url = `https://vercel.com/api/v3/sandboxes?teamId=${SBX055_TEAM}`;
    await gate.fetch(url, {
      method: "POST",
      headers: { ...authorization(), "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    await expect(gate.fetch(url, {
      method: "POST",
      headers: { ...authorization(), "content-type": "application/json" },
      body: JSON.stringify({ ...body, env: { SECRET: "forbidden" } }),
    })).rejects.toThrow(/nonexact persistent create/u);
    expect(calls).toBe(1);
  });

  it("serializes exact owner calls and stores only operation labels", async () => {
    const rawUrls: string[] = [];
    const rawFetch = (async (input: string | URL | Request) => {
      rawUrls.push(input.toString());
      return Response.json({ ok: true });
    }) as typeof fetch;
    const journal = createSbx055Journal();
    const gate = createSbx055RequestGate(rawFetch, pat, journal, fakeClock());
    gate.registerSession("S1", s1);
    await gate.fetch("https://api.vercel.com/v2/user", { headers: authorization() });
    await gate.fetch(`https://vercel.com/api/v2/sandboxes/sessions/${s1}/interactive?teamId=${SBX055_TEAM}`, {
      method: "POST",
      headers: { ...authorization(), "content-type": "application/json" },
      body: "{}",
    });
    expect(rawUrls).toHaveLength(2);
    expect(gate.summary()).toMatchObject({
      count: 2,
      contiguous: true,
      completed: true,
      withinRateLimit: true,
      minimumStartIntervalMs: 250,
      interactiveCredentialRequests: 1,
      websocketConnections: 0,
      unexpectedRequests: 0,
    });
    const durable = JSON.stringify(gate.summary());
    expect(durable).not.toContain(pat);
    expect(durable).not.toContain(s1);
    expect(durable).not.toContain("teamId=");
  });

  it("blocks foreign origins, unknown sessions, wrong auth, and retryable responses without retry", async () => {
    let calls = 0;
    const journal = createSbx055Journal();
    const rawFetch = (async () => {
      calls += 1;
      return new Response("discarded", { status: 503 });
    }) as typeof fetch;
    const gate = createSbx055RequestGate(rawFetch, pat, journal, fakeClock());
    await expect(gate.fetch("https://example.test/v2/user", { headers: authorization() }))
      .rejects.toThrow(/foreign origin|URL/u);
    await expect(gate.fetch("https://api.vercel.com/v2/user", {
      headers: { authorization: "Bearer wrong" },
    })).rejects.toThrow(/authorization/u);
    await expect(gate.fetch(`https://vercel.com/api/v2/sandboxes/sessions/${s1}/interactive?teamId=${SBX055_TEAM}`, {
      method: "POST", headers: authorization(), body: "{}",
    })).rejects.toThrow(/non-allowlisted/u);
    expect(calls).toBe(0);
    await expect(gate.fetch("https://api.vercel.com/v2/user", { headers: authorization() }))
      .rejects.toMatchObject({ name: "AbortError" });
    expect(calls).toBe(1);
  });

  it("mints an S2 control only for the exact sanitized stale 401/403", () => {
    const exact = staleRejection();
    expect(shouldMintSbx055S2Credential(exact)).toBe(true);
    for (const altered of [
      { ...exact, handshakeStatusCode: 404 },
      { ...exact, statusCategory: "other-http-response" as const },
      { ...exact, opened: true, authenticated: true },
      { ...exact, issuedUrlRole: "S2" as const },
      { ...exact, expectedRuntimeRole: "S1" as const },
      { ...exact, startMessagesSent: 1 as const },
    ]) expect(shouldMintSbx055S2Credential(altered)).toBe(false);
  });

  it("fails the S1 stale-mint barrier on every mutated provenance or behavioral control", () => {
    const journal = createSbx055Journal();
    journal.session1Id = "sbx_aaaaaaaaaaaaaaaaaaaa";
    const exact = {
      journal,
      readback: readback("S1", journal),
      m1WrittenAfterCreate: true,
      m1Mode0600: true,
      m1ReadExact: true,
      m2Absent: true,
      marker1Length: 43,
      attempts: [negative("missing-token-negative"), negative("random-token-negative"), owner("S1")],
    };
    expect(exactSbx055S1Barrier(exact)).toBe(true);
    expect(exactSbx055S1Barrier({ ...exact, readback: { ...exact.readback, listedSessionId: "sbx_wrong" } }))
      .toBe(false);
    expect(exactSbx055S1Barrier({ ...exact, m1Mode0600: false })).toBe(false);
    expect(exactSbx055S1Barrier({ ...exact, m2Absent: false })).toBe(false);
    expect(exactSbx055S1Barrier({ ...exact, attempts: [
      { ...exact.attempts[0]!, handshakeStatusCode: 404 }, exact.attempts[1]!, exact.attempts[2]!,
    ] })).toBe(false);
    expect(exactSbx055S1Barrier({ ...exact, attempts: [
      exact.attempts[0]!, { ...exact.attempts[1]!, opened: true }, exact.attempts[2]!,
    ] })).toBe(false);
    expect(exactSbx055S1Barrier({ ...exact, attempts: [
      exact.attempts[0]!, exact.attempts[1]!, { ...exact.attempts[2]!, markerMatched: false },
    ] })).toBe(false);
  });

  it("fails the S2 attack barrier on readback, persisted-M1, or new-M2 control drift", () => {
    const journal = createSbx055Journal();
    journal.session1Id = "sbx_aaaaaaaaaaaaaaaaaaaa";
    journal.session2Id = "sbx_bbbbbbbbbbbbbbbbbbbb";
    journal.snapshotId = "snap_cccccccccccccccccccc";
    const exact = {
      journal,
      readback: readback("S2", journal),
      m1Persisted: true,
      m1Mode0600: true,
      m1ReadExact: true,
      m2WrittenAfterResume: true,
      m2Mode0600: true,
      m2ReadExact: true,
    };
    expect(exactSbx055S2Barrier(exact)).toBe(true);
    expect(exactSbx055S2Barrier({ ...exact, readback: { ...exact.readback, sourceSnapshotId: null } }))
      .toBe(false);
    expect(exactSbx055S2Barrier({ ...exact, m1Persisted: false })).toBe(false);
    expect(exactSbx055S2Barrier({ ...exact, m1Mode0600: false })).toBe(false);
    expect(exactSbx055S2Barrier({ ...exact, m2WrittenAfterResume: false })).toBe(false);
    expect(exactSbx055S2Barrier({ ...exact, m2Mode0600: false })).toBe(false);
    expect(exactSbx055S2Barrier({ ...exact, m2ReadExact: false })).toBe(false);
  });

  it("never drops a stop-returned snapshot when exhaustive list visibility lags", () => {
    const s1Snapshot = "snap_aaaaaaaaaaaaaaaaaaaa";
    const s2StopSnapshot = "snap_bbbbbbbbbbbbbbbbbbbb";
    expect(planSbx055SnapshotCleanup(
      [s1Snapshot, s2StopSnapshot],
      [s1Snapshot],
    )).toEqual({
      allSnapshotIds: [s1Snapshot, s2StopSnapshot],
      missingKnownIds: [s2StopSnapshot],
    });
    expect(() => planSbx055SnapshotCleanup([s1Snapshot, s1Snapshot], [s1Snapshot]))
      .toThrow(/duplicate/u);
  });

  it("retains a lost resume until one exact distinct S2 handle is durably attributable", () => {
    const journal = createSbx055Journal();
    journal.session1Id = "sbx_aaaaaaaaaaaaaaaaaaaa";
    journal.snapshotId = "snap_cccccccccccccccccccc";
    journal.resumeAttempted = true;
    const base = {
      name: journal.sandboxName,
      tags: journal.tags,
      persistent: true,
      sessionId: "sbx_bbbbbbbbbbbbbbbbbbbb",
      sourceSnapshotId: journal.snapshotId,
      status: "running",
    };
    expect(exactSbx055UnresolvedResumeHandle(journal, base)).toBe(true);
    expect(exactSbx055UnresolvedResumeHandle(journal, {
      ...base, sessionId: journal.session1Id,
    })).toBe(false);
    expect(exactSbx055UnresolvedResumeHandle(journal, {
      ...base, sourceSnapshotId: "snap_dddddddddddddddddddd",
    })).toBe(false);
    expect(exactSbx055UnresolvedResumeHandle({ ...journal, resumeAttempted: false }, base)).toBe(false);
  });

  it("never reissues an unresolved lifecycle or cleanup stop and requires one attributed snapshot", () => {
    const journal = createSbx055Journal();
    expect(shouldIssueSbx055CleanupStop(journal, "running")).toBe(true);
    expect(shouldIssueSbx055CleanupStop({
      ...journal, stopAttempted: true, stopped: false,
    }, "running")).toBe(false);
    expect(shouldIssueSbx055CleanupStop({
      ...journal, cleanupStopAttempted: true, cleanupStopped: false,
    }, "running")).toBe(false);
    expect(shouldIssueSbx055CleanupStop({
      ...journal, resumeAttempted: true,
    }, "running")).toBe(false);
    expect(shouldIssueSbx055CleanupStop(journal, "stopped")).toBe(false);

    const sessionId = "sbx_aaaaaaaaaaaaaaaaaaaa";
    const exact = { id: "snap_aaaaaaaaaaaaaaaaaaaa", sourceSessionId: sessionId, status: "created" };
    expect(exactSbx055RecoveredStopSnapshotId(sessionId, [exact])).toBe(exact.id);
    expect(exactSbx055RecoveredStopSnapshotId(sessionId, [])).toBeUndefined();
    expect(exactSbx055RecoveredStopSnapshotId(sessionId, [exact, {
      ...exact, id: "snap_bbbbbbbbbbbbbbbbbbbb",
    }])).toBeUndefined();
    expect(exactSbx055RecoveredStopSnapshotId(sessionId, [{ ...exact, status: "pending" }]))
      .toBeUndefined();
  });

  it("accepts a snapshot 404 only after a durable ID-bound delete intent", () => {
    const journal = createSbx055Journal();
    const snapshotId = "snap_aaaaaaaaaaaaaaaaaaaa";
    journal.snapshotsObserved.push(snapshotId);
    expect(exactSbx055SnapshotDelete404Checkpoint(journal, snapshotId)).toBe("unattempted");
    journal.snapshotDeleteIntents.push(snapshotId);
    expect(exactSbx055SnapshotDelete404Checkpoint(journal, snapshotId)).toBe("intent-recorded");
    journal.snapshotsDeleted.push(snapshotId);
    expect(exactSbx055SnapshotDelete404Checkpoint(journal, snapshotId)).toBe("completed");
    expect(exactSbx055SnapshotDelete404Checkpoint(journal, "snap_bbbbbbbbbbbbbbbbbbbb"))
      .toBe("unattempted");
  });

  it("dispatches both release-finalization crash shapes to disjoint local recovery evidence", async () => {
    for (const [index, mutation] of [
      "release-precommit-complete",
      "release-canonical-removed",
    ].entries()) {
      const directory = await mkdtemp(join(tmpdir(), "sbx-055-controller-finalize-"));
      const lockPath = join(directory, "SBX-055-live-active.lock");
      const runId = randomUUID();
      const journalPath = join(directory, `SBX-055-${runId}-recovery.json`);
      const recoveryAttemptId = randomUUID();
      const artifactPath = sbx055RecoveryArtifactPath(runId, recoveryAttemptId);
      try {
        const crashed = await runOneShot(`
import { writeFile, unlink } from "node:fs/promises";
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
const safety = await import(${JSON.stringify(safetyModuleUrl)});
const journal = safety.createSbx055Journal(new Date(), ${JSON.stringify(runId)});
await writeFile(${JSON.stringify(journalPath)}, JSON.stringify(journal) + "\\n", {
  mode: 0o600,
  flag: "wx",
});
const lock = await lockModule.acquireSbx055LiveLockAtPathForTest(
  ${JSON.stringify(lockPath)},
  ${JSON.stringify(runId)},
  false,
  async (mutation) => {
    if (mutation === ${JSON.stringify(mutation)}) process.exit(${101 + index});
  },
);
await lock.releaseAfter(async () => unlink(${JSON.stringify(journalPath)}));
`);
        expect(crashed).toMatchObject({ code: 101 + index, stderr: "" });
        await expect(lstat(journalPath)).rejects.toMatchObject({ code: "ENOENT" });
        const outcome = await dispatchSbx055RecoveryAtPathsForTest(runId, lockPath, journalPath);
        expect(outcome).toBe("release-finalization-complete");
        if (outcome === "continue-journal-recovery") {
          throw new Error("test expected local finalization completion");
        }
        const written = await writeSbx055LocalRecoveryCompletion({
          token: pat,
          teamId: SBX055_TEAM,
          projectId: SBX055_PROJECT,
          expectedAlias: SBX055_ALIAS,
        }, runId, outcome, recoveryAttemptId);
        expect(written.artifactPath).toBe(artifactPath);
        const evidence = JSON.parse(await readFile(artifactPath, "utf8")) as Record<string, unknown>;
        expect(evidence).toMatchObject({
          recoveryOnly: true,
          mode: "cleanup-only",
          outcome: "release-finalization-complete",
          externalRequests: 0,
          cleanupAttempted: false,
          journalRemoved: true,
          liveLockReleased: true,
        });
        expect(JSON.stringify(evidence)).not.toMatch(/"(?:assessment|verdict|candidate|controlsPassed)"/u);
        expect((await lstat(artifactPath)).mode & 0o777).toBe(0o600);
        await expect(lstat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
        await expect(lstat(`${lockPath}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
      } finally {
        await unlink(artifactPath).catch(() => undefined);
        await rm(directory, { recursive: true, force: true });
      }
    }
  });

  it("dispatches only a missing-journal normal acquire as zero state and retains cleanup takeover", async () => {
    const normalDirectory = await mkdtemp(join(tmpdir(), "sbx-055-controller-normal-acquire-"));
    const normalLockPath = join(normalDirectory, "SBX-055-live-active.lock");
    const normalRunId = randomUUID();
    const normalJournalPath = join(normalDirectory, `SBX-055-${normalRunId}-recovery.json`);
    try {
      const crashed = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await lockModule.acquireSbx055LiveLockAtPathForTest(
  ${JSON.stringify(normalLockPath)},
  ${JSON.stringify(normalRunId)},
  false,
  async (mutation) => {
    if (mutation === "acquire-canonical-installed") process.exit(103);
  },
);
`);
      expect(crashed).toMatchObject({ code: 103, stderr: "" });
      await expect(dispatchSbx055RecoveryAtPathsForTest(
        normalRunId, normalLockPath, normalJournalPath,
      )).resolves.toBe("zero-external-state-acquire-rolled-back");
      await expect(lstat(normalLockPath)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(`${normalLockPath}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(normalDirectory, { recursive: true, force: true });
    }

    const cleanupDirectory = await mkdtemp(join(tmpdir(), "sbx-055-controller-cleanup-acquire-"));
    const cleanupLockPath = join(cleanupDirectory, "SBX-055-live-active.lock");
    const cleanupRunId = randomUUID();
    const cleanupJournalPath = join(cleanupDirectory, `SBX-055-${cleanupRunId}-recovery.json`);
    try {
      const stale = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await lockModule.acquireSbx055LiveLockAtPathForTest(
  ${JSON.stringify(cleanupLockPath)},
  ${JSON.stringify(cleanupRunId)},
  false,
);
process.exit(0);
`);
      expect(stale).toMatchObject({ code: 0, stderr: "" });
      const takeover = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await lockModule.acquireSbx055LiveLockAtPathForTest(
  ${JSON.stringify(cleanupLockPath)},
  ${JSON.stringify(cleanupRunId)},
  true,
  async (mutation) => {
    if (mutation === "acquire-stale-claimed") process.exit(104);
  },
);
`);
      expect(takeover).toMatchObject({ code: 104, stderr: "" });
      const transactionBefore = await readFile(`${cleanupLockPath}.transaction`);
      await expect(dispatchSbx055RecoveryAtPathsForTest(
        cleanupRunId, cleanupLockPath, cleanupJournalPath,
      )).rejects.toThrow(/lost its journal/u);
      expect(await readFile(`${cleanupLockPath}.transaction`)).toEqual(transactionBefore);
      transactionBefore.fill(0);
    } finally {
      await rm(cleanupDirectory, { recursive: true, force: true });
    }
  });

  it("recovers the completed-acquire/pre-journal zero-state window and rejects unsafe orphan locks", async () => {
    const completedDirectory = await mkdtemp(join(tmpdir(), "sbx-055-controller-post-acquire-"));
    const completedLockPath = join(completedDirectory, "SBX-055-live-active.lock");
    const completedRunId = randomUUID();
    const completedJournalPath = join(completedDirectory, `SBX-055-${completedRunId}-recovery.json`);
    try {
      const crashed = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await lockModule.acquireSbx055LiveLockAtPathForTest(
  ${JSON.stringify(completedLockPath)},
  ${JSON.stringify(completedRunId)},
  false,
);
process.exit(105);
`);
      expect(crashed).toMatchObject({ code: 105, stderr: "" });
      await expect(lstat(completedLockPath)).resolves.toBeDefined();
      await expect(lstat(`${completedLockPath}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(completedJournalPath)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(dispatchSbx055RecoveryAtPathsForTest(
        completedRunId, completedLockPath, completedJournalPath,
      )).resolves.toBe("zero-external-state-acquire-rolled-back");
      await expect(lstat(completedLockPath)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(completedDirectory, { recursive: true, force: true });
    }

    const liveDirectory = await mkdtemp(join(tmpdir(), "sbx-055-controller-live-orphan-"));
    const liveLockPath = join(liveDirectory, "SBX-055-live-active.lock");
    const liveRunId = randomUUID();
    const liveJournalPath = join(liveDirectory, `SBX-055-${liveRunId}-recovery.json`);
    const liveLock = await acquireSbx055LiveLockAtPathForTest(liveLockPath, liveRunId, false);
    try {
      const before = await readFile(liveLockPath);
      await expect(dispatchSbx055RecoveryAtPathsForTest(
        liveRunId, liveLockPath, liveJournalPath,
      )).rejects.toThrow(/live lock owner/u);
      expect(await readFile(liveLockPath)).toEqual(before);
      before.fill(0);
    } finally {
      await liveLock.release();
      await rm(liveDirectory, { recursive: true, force: true });
    }

    const foreignDirectory = await mkdtemp(join(tmpdir(), "sbx-055-controller-foreign-orphan-"));
    const foreignLockPath = join(foreignDirectory, "SBX-055-live-active.lock");
    const foreignRunId = randomUUID();
    const foreignJournalPath = join(foreignDirectory, `SBX-055-${foreignRunId}-recovery.json`);
    try {
      const owner = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await lockModule.acquireSbx055LiveLockAtPathForTest(
  ${JSON.stringify(foreignLockPath)},
  ${JSON.stringify(foreignRunId)},
  false,
);
process.exit(0);
`);
      expect(owner).toMatchObject({ code: 0, stderr: "" });
      const before = await readFile(foreignLockPath);
      await expect(dispatchSbx055RecoveryAtPathsForTest(
        randomUUID(), foreignLockPath, foreignJournalPath,
      )).rejects.toThrow(/foreign/u);
      expect(await readFile(foreignLockPath)).toEqual(before);
      before.fill(0);
      await expect(dispatchSbx055RecoveryAtPathsForTest(
        foreignRunId, foreignLockPath, foreignJournalPath,
      )).resolves.toBe("zero-external-state-acquire-rolled-back");
    } finally {
      await rm(foreignDirectory, { recursive: true, force: true });
    }

    const cleanupDirectory = await mkdtemp(join(tmpdir(), "sbx-055-controller-cleanup-orphan-"));
    const cleanupLockPath = join(cleanupDirectory, "SBX-055-live-active.lock");
    const cleanupRunId = randomUUID();
    const cleanupJournalPath = join(cleanupDirectory, `SBX-055-${cleanupRunId}-recovery.json`);
    try {
      const source = await runOneShot(`
const lockModule = await import(${JSON.stringify(lockModuleUrl)});
await lockModule.acquireSbx055LiveLockAtPathForTest(
  ${JSON.stringify(cleanupLockPath)},
  ${JSON.stringify(cleanupRunId)},
  false,
);
process.exit(0);
`);
      expect(source).toMatchObject({ code: 0, stderr: "" });
      const cleanupLock = await acquireSbx055LiveLockAtPathForTest(cleanupLockPath, cleanupRunId, true);
      try {
        const before = await readFile(cleanupLockPath);
        await expect(dispatchSbx055RecoveryAtPathsForTest(
          cleanupRunId, cleanupLockPath, cleanupJournalPath,
        )).rejects.toThrow(/non-normal/u);
        expect(await readFile(cleanupLockPath)).toEqual(before);
        before.fill(0);
      } finally {
        await cleanupLock.release();
      }
    } finally {
      await rm(cleanupDirectory, { recursive: true, force: true });
    }
  });

  it("keeps the exact lifecycle order, candidate short-circuit, cleanup, and import guard in source", () => {
    const source = readFileSync("pocs/SBX-055/stale-interactive-resume.ts", "utf8");
    expect(source.indexOf('timed("m2-absence-before-stop"')).toBeLessThan(
      source.indexOf('timed("issue-s1-fresh-stale"'),
    );
    expect(source.indexOf('timed("issue-s1-fresh-stale"')).toBeLessThan(
      source.indexOf('timed("stop-s1"'),
    );
    expect(source.indexOf('timed("stale-s1-token-on-s2"')).toBeLessThan(
      source.indexOf('if (exactAuthRejection(staleAttempt))'),
    );
    expect(source.indexOf('if (exactAuthRejection(staleAttempt))')).toBeLessThan(
      source.indexOf('timed("issue-s2-owner-control"'),
    );
    expect(source).toContain('staleBaseUrl = stale.baseUrl');
    expect(source).toContain('staleToken = stale.token');
    expect(source).toContain('persistent: true');
    expect(source).toContain('ports: []');
    expect(source).toContain('networkPolicy: "deny-all"');
    expect(source).toContain('independentRouteCount: independent.routes.length');
    expect(source).toContain('zeroExternalStateJournal(journal)');
    expect(source).toContain('exactSbx055S1Barrier({');
    expect(source).toContain('exactSbx055S2Barrier({');
    expect(source.indexOf('exactSbx055S2Barrier({')).toBeLessThan(
      source.indexOf('timed("stale-s1-token-on-s2"'),
    );
    expect(source).toContain('planSbx055SnapshotCleanup(');
    expect(source).toContain('cleanupSbx055(config, gate, journal, lock');
    expect(source).toContain('import.meta.url === pathToFileURL(process.argv[1]).href');
    expect(source).not.toContain('.openInteractive(');
    expect(source).not.toContain('roleUrlsDistinct');
    expect(source).not.toMatch(/\bca\s*:/u);
    expect(source).not.toMatch(/checkServerIdentity\s*:/u);
    expect(source).not.toMatch(/secureContext\s*:/u);
  });
});
