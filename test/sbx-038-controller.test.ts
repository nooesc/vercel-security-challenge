import { randomUUID } from "node:crypto";
import { chmod, lstat, mkdtemp, readFile, readdir, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  completeSbx038ReleasedFinalization,
  controlledOrigins,
  exactSbx038PendingNormalFinalization,
  exactSbx038PendingRecoveryFinalization,
  explicitCredentials,
  sbx038BTransportMode,
  sbx038RawConnectRequest,
  sbx038SandboxPrefixListOptions,
  sbx038StageCleanupProjection,
  runSbx038Recovery,
  sanitizeGuest,
} from "../pocs/SBX-038/connect-authority.js";
import {
  acquireSbx038State,
  createSbx038Journal,
  persistSbx038Journal,
  releaseSbx038State,
  sbx038ArtifactPath,
  sbx038JournalPath,
  sbx038LockPath,
  sbx038RecoveryArtifactPath,
  sbx038Resource,
  writeSbx038Checkpoint,
  writeSbx038RecoveryArtifact,
} from "../pocs/SBX-038/safety.js";

const scope = "I_CONTROL_BOTH_SBX038_ORIGINS_AND_AUTHORIZE_BOUNDED_CONNECT_AUTHORITY_TESTING";

describe("SBX-038 controller local gates", () => {
  it("requires exact distinct owned HTTPS origins and the fixed alias team/project", () => {
    expect(controlledOrigins({
      SBX038_SCOPE_CONFIRMATION: scope,
      SBX038_A_PUBLIC_ORIGIN: "https://a.research.test",
      SBX038_B_PUBLIC_ORIGIN: "https://b.research.test",
    })).toMatchObject({
      a: { hostname: "a.research.test" },
      b: { hostname: "b.research.test" },
    });
    expect(() => controlledOrigins({
      SBX038_SCOPE_CONFIRMATION: scope,
      SBX038_A_PUBLIC_ORIGIN: "https://a.research.test",
      SBX038_B_PUBLIC_ORIGIN: "https://a.research.test",
    })).toThrow(/distinct/u);
    expect(() => controlledOrigins({
      SBX038_SCOPE_CONFIRMATION: scope,
      SBX038_A_PUBLIC_ORIGIN: "https://a.research.test/path",
      SBX038_B_PUBLIC_ORIGIN: "https://b.research.test",
    })).toThrow(/exact lower-case HTTPS origin/u);

    expect(explicitCredentials({
      VERCEL_TOKEN: "local-token",
      VERCEL_TEAM_ID: "team_n98ERpVwV7HqmWRudAyK8sXQ",
      VERCEL_PROJECT_ID: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    })).toEqual({
      token: "local-token",
      teamId: "team_n98ERpVwV7HqmWRudAyK8sXQ",
      projectId: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    });
    expect(() => explicitCredentials({ VERCEL_TOKEN: "local-token" })).toThrow(/HackerOne-alias/u);
  });

  it("sanitizes guest evidence without accepting extra raw response or secret material", () => {
    const evidence = sanitizeGuest({
      schemaVersion: 1,
      testId: "SBX-038-POC",
      runId: "123e4567-e89b-42d3-a456-426614174000",
      caseId: "public-connect-b",
      mode: "connect-b-public",
      outerHost: "a.research.test",
      outerPort: 443,
      targetHost: "b.research.test",
      targetPort: 443,
      connectAuthority: "b.research.test:443",
      connectHostHeader: "a.research.test",
      connectionAttempts: 1,
      retryCount: 0,
      maximumRequests: 1,
      actualRequests: 1,
      strictCertificateVerification: true,
      environmentProxyTrust: false,
      trustEnvironmentNames: ["NODE_USE_SYSTEM_CA", "SSL_CERT_FILE"],
      trustEnvironmentScanComplete: true,
      trustOverridesForbidden: true,
      rawConfigurationRetained: false,
      rawSecretRetained: false,
      secretDigestRetained: false,
      ok: true,
      errorErrno: -3001,
      startedAt: "2026-08-19T00:00:00.000Z",
      completedAt: "2026-08-19T00:00:01.000Z",
      connectResponse: { statusCode: 200, bodyBytes: 0, rawBody: "must-not-survive" },
      nestedResponse: { statusCode: 200, operationId: `cx_${"A".repeat(32)}`, rawBody: "must-not-survive" },
      rawSecret: "must-not-survive",
    }, "connect-b-public", "public-connect-b");
    expect(evidence.nestedResponse).toEqual({ statusCode: 200, operationId: `cx_${"A".repeat(32)}` });
    expect(evidence.errorErrno).toBe(-3001);
    expect(evidence.connectResponse).toEqual({ statusCode: 200, bodyBytes: 0 });
    expect(evidence.trustEnvironmentNames).toEqual(["NODE_USE_SYSTEM_CA", "SSL_CERT_FILE"]);
    expect(JSON.stringify(evidence)).not.toContain("must-not-survive");
  });

  it("builds the exact run-attributed raw CONNECT preflight and sorted bounded prefix list", () => {
    const runId = "123e4567-e89b-42d3-a456-426614174000";
    expect(sbx038RawConnectRequest(new URL("https://a.research.test"), runId, "corr_public")).toBe([
      "CONNECT a.research.test:443 HTTP/1.1",
      "Host: a.research.test",
      `X-SBX038-Run: ${runId}`,
      "X-SBX038-Case: infrastructure-connect-a-123e4567",
      "X-SBX038-Canary: corr_public",
      "Connection: close",
      "",
      "",
    ].join("\r\n"));
    expect(sbx038SandboxPrefixListOptions("sbx-038-public-")).toEqual({
      namePrefix: "sbx-038-public-", limit: 10, sortBy: "name", sortOrder: "asc",
    });
  });

  it("requires an explicit B TLS termination mode", () => {
    expect(sbx038BTransportMode({ SBX038_B_TRANSPORT_MODE: "public-edge" })).toBe("public-edge");
    expect(sbx038BTransportMode({ SBX038_B_TRANSPORT_MODE: "receiver-local" })).toBe("receiver-local");
    expect(() => sbx038BTransportMode({})).toThrow(/must be receiver-local or public-edge/u);
  });

  it("treats only terminal-horizon absence-only create loss as stopped and deleted cleanup", () => {
    const journal = createSbx038Journal({ runId: "123e4567-e89b-42d3-a456-426614174000" });
    const resource = sbx038Resource(journal, "public");
    resource.createAttemptedAt = "2026-08-19T00:00:00.000Z";
    resource.absenceChecks = 3;
    resource.prefixListAbsent = true;
    resource.absenceOnlyValidated = true;
    resource.deleted = true;
    expect(sbx038StageCleanupProjection(resource)).toMatchObject({
      stopAttempted: false,
      stopped: true,
      deleteAttempted: false,
      deleted: true,
      absenceChecks: 3,
      absent: true,
      prefixListAbsent: true,
      errors: [],
    });
  });

  it("completes a normal release-before-artifact-finalization crash with zero external calls", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx-038-normal-finalize-"));
    const runId = randomUUID();
    const originalPath = sbx038ArtifactPath(runId, directory);
    const pending = {
      schemaVersion: 1,
      testId: "SBX-038-POC",
      runId,
      marker: "normal-release-before-finish",
      externalCleanupComplete: true,
      localFinalizationPending: true,
    };
    const originalFetch = globalThis.fetch;
    let externalCalls = 0;
    globalThis.fetch = (() => {
      externalCalls += 1;
      throw new Error("external call forbidden in local finalization");
    }) as typeof fetch;
    try {
      const journal = createSbx038Journal({ runId });
      const held = await acquireSbx038State(journal, directory);
      await writeSbx038Checkpoint(runId, pending, directory);
      journal.phase = "completed";
      journal.completed = true;
      await persistSbx038Journal(held, journal);
      await releaseSbx038State(held);
      expect(exactSbx038PendingNormalFinalization(pending, runId)).toBe(true);
      await expect(runSbx038Recovery(runId, directory)).resolves.toBeUndefined();
      const finalized = JSON.parse(await readFile(originalPath, "utf8")) as Record<string, unknown>;
      expect(finalized).toMatchObject({
        marker: "normal-release-before-finish",
        externalCleanupComplete: true,
        localFinalizationPending: false,
        localFinalization: { journalAbsent: true, liveLockAbsent: true, lockTransactionAbsent: true },
      });
      const completionName = (await readdir(directory)).find((name) =>
        name.startsWith(`SBX-038-${runId}-recovery-`) && name.endsWith("-private.json"));
      expect(completionName).toBeDefined();
      const completionPath = join(directory, completionName!);
      const completion = JSON.parse(await readFile(completionPath, "utf8")) as Record<string, unknown>;
      expect(completion).toMatchObject({
        recoveryOnly: true,
        outcome: "release-finalization-complete",
        externalCalls: 0,
        cleanupAttempted: false,
        source: "normal",
        localFinalizationPending: false,
      });
      expect((await lstat(originalPath)).mode & 0o777).toBe(0o600);
      expect((await lstat(completionPath)).mode & 0o777).toBe(0o600);
      expect(externalCalls).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("finishes the exact prior cleanup-recovery artifact without clobbering an inconclusive original", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx-038-recovery-finalize-"));
    const runId = randomUUID();
    const priorAttemptId = randomUUID();
    const originalPath = sbx038ArtifactPath(runId, directory);
    const priorPath = sbx038RecoveryArtifactPath(runId, priorAttemptId, directory);
    const original = {
      schemaVersion: 1,
      testId: "SBX-038-POC",
      runId,
      externalCleanupComplete: false,
      localFinalizationPending: true,
      marker: "must-remain-byte-identical",
    };
    const prior = {
      schemaVersion: 1,
      testId: "SBX-038-POC",
      runId,
      recoveryAttemptId: priorAttemptId,
      recoveryOnly: true,
      outcome: "external-cleanup-complete",
      resourceCleanup: [{ role: "public" }, { role: "secret" }],
      receiverCleanup: { absent: true },
      localFinalizationPending: true,
    };
    const originalFetch = globalThis.fetch;
    let externalCalls = 0;
    globalThis.fetch = (() => {
      externalCalls += 1;
      throw new Error("external call forbidden in cleanup-recovery finalization");
    }) as typeof fetch;
    try {
      const journal = createSbx038Journal({ runId });
      const held = await acquireSbx038State(journal, directory);
      await writeSbx038Checkpoint(runId, original, directory);
      await writeSbx038RecoveryArtifact(runId, priorAttemptId, prior, directory);
      journal.phase = "completed";
      journal.completed = true;
      await persistSbx038Journal(held, journal);
      await releaseSbx038State(held);
      const originalBytes = await readFile(originalPath);
      expect(exactSbx038PendingNormalFinalization(original, runId)).toBe(false);
      expect(exactSbx038PendingRecoveryFinalization(prior, runId, priorAttemptId)).toBe(true);
      for (const inexact of [
        { ...prior, schemaVersion: 2 },
        { ...prior, runId: randomUUID() },
        { ...prior, recoveryAttemptId: randomUUID() },
        { ...prior, outcome: "cleanup-complete" },
        { ...prior, recoveryOnly: false },
        { ...prior, localFinalizationPending: false },
        { ...prior, resourceCleanup: [{}] },
        { ...prior, receiverCleanup: undefined },
      ]) expect(exactSbx038PendingRecoveryFinalization(inexact, runId, priorAttemptId)).toBe(false);
      await expect(runSbx038Recovery(runId, directory)).resolves.toBeUndefined();
      expect(await readFile(originalPath)).toEqual(originalBytes);
      expect(JSON.parse(await readFile(priorPath, "utf8"))).toMatchObject({
        outcome: "cleanup-complete",
        localFinalizationPending: false,
        localFinalization: { journalAbsent: true, liveLockAbsent: true, lockTransactionAbsent: true },
      });
      const completionName = (await readdir(directory)).find((name) =>
        name.startsWith(`SBX-038-${runId}-recovery-`) && name.endsWith("-private.json") &&
        !name.includes(priorAttemptId));
      expect(completionName).toBeDefined();
      const completionPath = join(directory, completionName!);
      expect(JSON.parse(await readFile(completionPath, "utf8"))).toMatchObject({
        outcome: "release-finalization-complete",
        externalCalls: 0,
        source: "cleanup-recovery",
        sourceRecoveryAttemptId: priorAttemptId,
      });
      expect(externalCalls).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("preserves a pending cleanup proof across an actual post-release fault and retries locally", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx-038-post-release-fault-"));
    const runId = randomUUID();
    const faultedAttemptId = randomUUID();
    const completionAttemptId = randomUUID();
    const journal = createSbx038Journal({ runId });
    const held = await acquireSbx038State(journal, directory);
    const originalPath = sbx038ArtifactPath(runId, directory);
    const faultedPath = sbx038RecoveryArtifactPath(runId, faultedAttemptId, directory);
    const completionPath = sbx038RecoveryArtifactPath(runId, completionAttemptId, directory);
    const original = {
      schemaVersion: 1,
      testId: "SBX-038-POC",
      runId,
      externalCleanupComplete: false,
      localFinalizationPending: true,
      marker: "recovery-must-not-clobber-original",
    };
    const environment = {
      VERCEL_TOKEN: "local-token",
      VERCEL_TEAM_ID: "team_n98ERpVwV7HqmWRudAyK8sXQ",
      VERCEL_PROJECT_ID: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
      SBX038_SCOPE_CONFIRMATION: scope,
      SBX038_A_PUBLIC_ORIGIN: "https://a.research.test",
      SBX038_B_PUBLIC_ORIGIN: "https://b.research.test",
      SBX038_ADMIN_KEY: "A".repeat(32),
    };
    const previous = Object.fromEntries(Object.keys(environment).map((name) => [name, process.env[name]]));
    const originalFetch = globalThis.fetch;
    let externalCalls = 0;
    globalThis.fetch = (() => {
      externalCalls += 1;
      throw new Error("external call forbidden in injected recovery");
    }) as typeof fetch;
    Object.assign(process.env, environment);
    try {
      await writeSbx038Checkpoint(runId, original, directory);
      const originalBytes = await readFile(originalPath);
      await expect(runSbx038Recovery(runId, directory, {
        newAttemptId: () => faultedAttemptId,
        dispatch: async () => "continue-journal-recovery",
        acquireState: async () => held,
        readJournal: async () => journal,
        verifyIdentity: async () => undefined,
        afterRelease: async () => { throw new Error("injected fault after release"); },
      })).rejects.toThrow(/injected fault after release/u);
      expect(await readFile(originalPath)).toEqual(originalBytes);
      expect(JSON.parse(await readFile(faultedPath, "utf8"))).toMatchObject({
        recoveryAttemptId: faultedAttemptId,
        outcome: "external-cleanup-complete",
        localFinalizationPending: true,
      });
      expect(JSON.stringify(JSON.parse(await readFile(faultedPath, "utf8"))))
        .not.toContain("cleanup-incomplete");
      await expect(lstat(sbx038JournalPath(runId, directory))).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(sbx038LockPath(directory))).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(`${sbx038LockPath(directory)}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });

      await expect(runSbx038Recovery(runId, directory, {
        newAttemptId: () => completionAttemptId,
      })).resolves.toBeUndefined();
      expect(await readFile(originalPath)).toEqual(originalBytes);
      expect(JSON.parse(await readFile(faultedPath, "utf8"))).toMatchObject({
        outcome: "cleanup-complete",
        localFinalizationPending: false,
      });
      expect(JSON.parse(await readFile(completionPath, "utf8"))).toMatchObject({
        outcome: "release-finalization-complete",
        externalCalls: 0,
        source: "cleanup-recovery",
        sourceRecoveryAttemptId: faultedAttemptId,
      });
      expect(externalCalls).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
      for (const [name, value] of Object.entries(previous)) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("fails closed on inexact or non-private released-finalization evidence", async () => {
    const runId = randomUUID();
    const exact = {
      schemaVersion: 1,
      testId: "SBX-038-POC",
      runId,
      externalCleanupComplete: true,
      localFinalizationPending: true,
    };
    expect(exactSbx038PendingNormalFinalization(exact, runId)).toBe(true);
    for (const inexact of [
      { ...exact, schemaVersion: 2 },
      { ...exact, testId: "SBX-038" },
      { ...exact, runId: randomUUID() },
      { ...exact, externalCleanupComplete: false },
      { ...exact, localFinalizationPending: false },
      { ...exact, recoveryOnly: true },
    ]) expect(exactSbx038PendingNormalFinalization(inexact, runId)).toBe(false);

    const directory = await mkdtemp(join(tmpdir(), "sbx-038-inexact-finalize-"));
    try {
      await writeSbx038Checkpoint(runId, exact, directory);
      await chmod(sbx038ArtifactPath(runId, directory), 0o644);
      await expect(completeSbx038ReleasedFinalization(runId, directory, randomUUID()))
        .rejects.toThrow(/mode-0600|mode 0600|private state/u);
      await chmod(sbx038ArtifactPath(runId, directory), 0o600);
      const lockPath = sbx038LockPath(directory);
      for (const blocker of [sbx038JournalPath(runId, directory), lockPath, `${lockPath}.transaction`]) {
        await writeFile(blocker, "block\n", { mode: 0o600, flag: "wx" });
        await expect(completeSbx038ReleasedFinalization(runId, directory, randomUUID()))
          .rejects.toThrow(/exact journal\/lock\/transaction absence/u);
        await unlink(blocker);
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
