import { chmod, lstat, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Sandbox } from "@vercel/sandbox";
import { describe, expect, it, vi } from "vitest";
import {
  SBX051_ALIAS,
  SBX051_PROJECT,
  SBX051_SCOPE_CONFIRMATION,
  SBX051_TEAM,
  SBX051_TEST_ID,
  SBX051_UUID,
  createSbx051Journal,
  loadSbx051Config,
  parseSbx051Journal,
  sbx051ArtifactPath,
  sbx051JournalPath,
  sbx051MarkerPath,
  sbx051Name,
  sbx051RecoveryArtifactPath,
  sbx051Tags,
  writeSbx051PrivateJson,
  writeSbx051PrivateJsonNoClobber,
} from "../pocs/SBX-051/safety.js";
import {
  cleanupSbx051Resource,
  createSbx051RequestGate,
  finalizeSbx051LocalCleanup,
  type CleanupEvidence,
} from "../pocs/SBX-051/interactive-token-binding.js";

const offlinePat = `vcp_${"offline-never-sent-".repeat(3)}`;

function environment(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    VERCEL_TOKEN: offlinePat,
    VERCEL_TEAM_ID: SBX051_TEAM,
    VERCEL_PROJECT_ID: SBX051_PROJECT,
    SBX051_EXPECTED_ALIAS: SBX051_ALIAS,
    SBX051_ALIAS_EMAIL_CONFIRMATION: SBX051_ALIAS,
    SBX051_SCOPE_CONFIRMATION,
    ...extra,
  };
}

describe("SBX-051 exact scope and local runtime safety", () => {
  it("accepts only the fixed alias/team/project/scope and an opaque non-JWT PAT", () => {
    expect(loadSbx051Config(environment())).toEqual({
      token: offlinePat,
      teamId: SBX051_TEAM,
      projectId: SBX051_PROJECT,
      expectedAlias: SBX051_ALIAS,
      manualAliasConfirmation: SBX051_ALIAS,
    });

    expect(() => loadSbx051Config(environment({
      SBX051_SCOPE_CONFIRMATION: "I_AUTHORIZE_SOMETHING_ELSE",
    }))).toThrow();
    expect(() => loadSbx051Config(environment({ VERCEL_TEAM_ID: "team_foreign" }))).toThrow();
    expect(() => loadSbx051Config(environment({ VERCEL_PROJECT_ID: "prj_foreign" }))).toThrow();
    expect(() => loadSbx051Config(environment({ SBX051_EXPECTED_ALIAS: "other@example.test" }))).toThrow();
    expect(() => loadSbx051Config(environment({ VERCEL_TOKEN: "header.payload.signature" }))).toThrow();
    expect(() => loadSbx051Config(environment({ VERCEL_TOKEN: "short" }))).toThrow();
    expect(() => loadSbx051Config(environment({ VERCEL_TOKEN: `${offlinePat}\n` }))).toThrow();
  });

  it("rejects every local TLS trust override and nonempty NODE_OPTIONS", () => {
    const trustVariables = [
      "NODE_EXTRA_CA_CERTS",
      "NODE_USE_SYSTEM_CA",
      "OPENSSL_CONF",
      "OPENSSL_MODULES",
      "SSL_CERT_DIR",
      "SSL_CERT_FILE",
    ] as const;
    for (const name of trustVariables) {
      expect(() => loadSbx051Config(environment({ [name]: "" }))).toThrow();
    }
    expect(() => loadSbx051Config(environment({ NODE_TLS_REJECT_UNAUTHORIZED: "0" }))).toThrow();
    expect(() => loadSbx051Config(environment({ NODE_OPTIONS: "--require ./inject.cjs" }))).toThrow();
    expect(loadSbx051Config(environment({ NODE_OPTIONS: "" })).teamId).toBe(SBX051_TEAM);
  });

  it("makes only a canonical UUIDv4 eligible for cleanup-only recovery", () => {
    const runId = "123e4567-e89b-42d3-a456-426614174000";
    expect(loadSbx051Config(environment({ SBX051_RECOVERY_RUN_ID: runId }))).toMatchObject({
      recoveryRunId: runId,
    });
    for (const invalid of ["../../foreign", "123e4567-e89b-12d3-a456-426614174000", ""] as const) {
      expect(() => loadSbx051Config(environment({ SBX051_RECOVERY_RUN_ID: invalid }))).toThrow();
    }
  });
});

describe("SBX-051 strict private recovery journal", () => {
  it("derives two distinct owned resources and marker paths from one fresh run", () => {
    const journal = createSbx051Journal(new Date("2026-08-19T12:00:00.000Z"));
    expect(journal.testId).toBe(SBX051_TEST_ID);
    expect(journal.runId).toMatch(SBX051_UUID);
    expect(journal.resources.map((entry) => entry.role)).toEqual(["A", "B"]);
    expect(new Set(journal.resources.map((entry) => entry.name)).size).toBe(2);
    expect(new Set(journal.resources.map((entry) => entry.markerPath)).size).toBe(2);

    for (const entry of journal.resources) {
      expect(entry.name).toBe(sbx051Name(entry.role, journal.runId));
      expect(entry.tags).toEqual(sbx051Tags(entry.role, journal.runId));
      expect(entry.markerPath).toBe(sbx051MarkerPath(entry.role, journal.runId));
      expect(entry.createAttempted).toBe(false);
      expect(entry).not.toHaveProperty("sessionId");
    }
    expect(sbx051JournalPath(journal.runId)).toContain(journal.runId);
    expect(sbx051ArtifactPath(journal.runId)).toContain(journal.runId);
    const recoveryAttemptId = createSbx051Journal().runId;
    expect(sbx051RecoveryArtifactPath(journal.runId, recoveryAttemptId)).not.toBe(
      sbx051ArtifactPath(journal.runId),
    );
  });

  it("round-trips exact provenance without retaining marker or interactive-token material", () => {
    const journal = createSbx051Journal();
    journal.resources[0].createAttempted = true;
    journal.resources[0].sessionId = "sbx_offline_A_session_051";
    const parsed = parseSbx051Journal(structuredClone(journal));
    expect(parsed).toEqual(journal);
    expect(parsed.rawMarkersRetained).toBe(false);
    expect(parsed.rawInteractiveTokensRetained).toBe(false);

    const serialized = JSON.stringify(parsed);
    expect(serialized).not.toContain("raw-marker-secret-that-must-never-persist");
    expect(serialized).not.toContain("raw-interactive-token-that-must-never-persist");
    expect(serialized).not.toContain(offlinePat);
  });

  it("rejects extra secret fields, reordered roles, foreign provenance, and malformed sessions", () => {
    const base = createSbx051Journal();
    expect(() => parseSbx051Journal({ ...base, token: "raw-interactive-token" })).toThrow();
    expect(() => parseSbx051Journal({ ...base, marker: "raw-marker" })).toThrow();
    expect(() => parseSbx051Journal({ ...base, rawMarkersRetained: true })).toThrow();
    expect(() => parseSbx051Journal({ ...base, rawInteractiveTokensRetained: true })).toThrow();
    expect(() => parseSbx051Journal({
      ...base,
      resources: [base.resources[1], base.resources[0]],
    })).toThrow();
    expect(() => parseSbx051Journal({
      ...base,
      resources: base.resources.map((entry, index) => index === 0
        ? { ...entry, tags: { ...entry.tags, run: "foreign" } }
        : entry),
    })).toThrow();
    expect(() => parseSbx051Journal({
      ...base,
      resources: base.resources.map((entry, index) => index === 1
        ? { ...entry, sessionId: "not-a-session" }
        : entry),
    })).toThrow();
  });

  it("rejects noncanonical names, paths, and journal timestamps", () => {
    expect(() => sbx051Name("A", "../../foreign")).toThrow();
    expect(() => sbx051MarkerPath("B", "00000000-0000-0000-0000-000000000000")).toThrow();
    const base = createSbx051Journal();
    expect(() => parseSbx051Journal({ ...base, updatedAt: "2026-08-19" })).toThrow();
    expect(() => parseSbx051Journal({
      ...base,
      startedAt: "2026-08-19T12:00:01.000Z",
      updatedAt: "2026-08-19T12:00:00.000Z",
    })).toThrow();
  });

  it("writes mode-0600 private JSON atomically", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx-051-private-"));
    await chmod(directory, 0o700);
    try {
      const path = join(directory, "evidence.json");
      const journal = createSbx051Journal();
      await writeSbx051PrivateJson(path, journal);
      expect((await lstat(path)).mode & 0o777).toBe(0o600);
      expect(JSON.parse(await readFile(path, "utf8"))).toEqual(journal);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("writes recovery evidence to an exclusive no-clobber target", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx-051-recovery-evidence-"));
    await chmod(directory, 0o700);
    try {
      const originalPath = join(directory, "experiment.json");
      const recoveryPath = join(directory, "recovery.json");
      await writeSbx051PrivateJson(originalPath, { kind: "experiment" });
      await writeSbx051PrivateJsonNoClobber(recoveryPath, { kind: "recovery-one" });
      await expect(writeSbx051PrivateJsonNoClobber(recoveryPath, { kind: "recovery-two" }))
        .rejects.toMatchObject({ code: "EEXIST" });
      expect(JSON.parse(await readFile(originalPath, "utf8"))).toEqual({ kind: "experiment" });
      expect(JSON.parse(await readFile(recoveryPath, "utf8"))).toEqual({ kind: "recovery-one" });
      expect((await lstat(recoveryPath)).mode & 0o777).toBe(0o600);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});

describe("SBX-051 response-lost create recovery", () => {
  it("never resolves an attempted create from short absence snapshots without a session handle", async () => {
    const journal = createSbx051Journal();
    const plan = journal.resources[0];
    plan.createAttempted = true;
    const list = vi.spyOn(Sandbox, "list").mockResolvedValue({
      sandboxes: [],
      pagination: { next: null },
    } as never);
    const get = vi.spyOn(Sandbox, "get").mockResolvedValue(undefined as never);
    const waits: number[] = [];
    try {
      const config = loadSbx051Config(environment());
      const gate = createSbx051RequestGate(
        (async () => { throw new Error("network must remain unused"); }) as typeof fetch,
        config.token,
        journal.resources,
      );
      const result = await cleanupSbx051Resource(
        config,
        gate,
        journal,
        plan,
        async (milliseconds) => { waits.push(milliseconds); },
      );
      expect(result).toMatchObject({
        attempted: true,
        sessionIdKnownAtCleanup: false,
        exactProvenance: false,
        stopped: false,
        deleted: false,
        firstAbsence: true,
        secondAbsence: true,
        namedAbsenceChecks: 2,
        absenceDelayMs: 2_000,
      });
      expect(result.errors).toHaveLength(1);
      expect(waits).toEqual([2_000, 2_000]);
      expect(plan).not.toHaveProperty("sessionId");
      expect(list).toHaveBeenCalledTimes(3);
      expect(get).toHaveBeenCalledTimes(3);

      const cleanup: CleanupEvidence = {
        passed: false,
        journalRemoved: false,
        lockReleased: false,
        resources: [result],
      };
      let releases = 0;
      let removals = 0;
      await finalizeSbx051LocalCleanup(cleanup, {
        release: async () => { releases += 1; },
        isReleased: () => releases > 0,
      }, async () => { removals += 1; });
      expect(cleanup).toMatchObject({
        passed: false,
        journalRemoved: false,
        lockReleased: false,
      });
      expect(releases).toBe(0);
      expect(removals).toBe(0);
    } finally {
      vi.restoreAllMocks();
    }
  });
});

describe("SBX-051 retry-safe cleanup finalization", () => {
  it("never removes the only journal until lock unlink is proven", async () => {
    const cleanup = (): CleanupEvidence => ({
      passed: true,
      journalRemoved: false,
      lockReleased: false,
      resources: [],
    });

    const lockFailure = cleanup();
    let journalRemovals = 0;
    await finalizeSbx051LocalCleanup(lockFailure, {
      release: async () => { throw new Error("injected unlink failure"); },
      isReleased: () => false,
    }, async () => { journalRemovals += 1; });
    expect(lockFailure).toMatchObject({ passed: false, lockReleased: false, journalRemoved: false });
    expect(journalRemovals).toBe(0);

    const journalFailure = cleanup();
    const events: string[] = [];
    await finalizeSbx051LocalCleanup(journalFailure, {
      release: async () => { events.push("lock-unlinked"); },
      isReleased: () => true,
    }, async () => {
      events.push("journal-remove");
      throw new Error("injected journal failure");
    });
    expect(events).toEqual(["lock-unlinked", "journal-remove"]);
    expect(journalFailure).toMatchObject({ passed: false, lockReleased: true, journalRemoved: false });
  });
});
