import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { lstat, mkdtemp, readFile, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  assessSbx001DirectAfterFinalReceiver,
  attributeSbx001RecoveredHandle,
  cleanupSbx001Receiver,
  completeSbx001PendingFinalization,
  matchExactSbx001RecoveredHandle,
  releaseAndWriteSbx001FinalizationReceipt,
  requireSbx001FinalReceiverSnapshot,
  sbx001SandboxPrefixListOptions,
} from "../pocs/SBX-001/direct-run.js";
import {
  SBX001_DIRECT_LIVE_LOCK,
  acquireSbx001DirectState,
  createSbx001DirectJournal,
  sbx001DirectArtifactPath,
  sbx001DirectFinalizationReceiptPath,
  sbx001DirectJournalPath,
} from "../pocs/SBX-001/direct-safety.js";
import { SBX001_DIRECT_SCOPE_CONFIRMATION, SBX001_RECEIVER_WINDOW_MS } from "../pocs/SBX-001/direct-shared.js";

const repositoryDirectory = resolve(".");
const directRunPath = resolve(repositoryDirectory, "pocs/SBX-001/direct-run.ts");
const directSafetyUrl = pathToFileURL(resolve(repositoryDirectory, "pocs/SBX-001/direct-safety.ts")).href;
const sandboxModuleUrl = pathToFileURL(resolve(repositoryDirectory, "node_modules/@vercel/sandbox/dist/index.js")).href;
const temporaryDirectories: string[] = [];
const generatedPaths: string[] = [];

afterEach(async () => {
  await Promise.all(generatedPaths.splice(0).map((path) => unlink(path).catch(() => undefined)));
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

function recoveredHandle(input: {
  name?: string;
  tags?: Record<string, string>;
  persistent?: boolean;
  sessions?: unknown[];
  mutations?: { stop: number; delete: number };
}) {
  const sessions = [...(input.sessions ?? ["sbx_exact_owned_session"])];
  return {
    name: input.name ?? "owned-name",
    tags: input.tags ?? { owner: "exact" },
    persistent: input.persistent ?? false,
    currentSession: () => ({ sessionId: sessions.shift() }),
    stop: async () => { if (input.mutations) input.mutations.stop += 1; },
    delete: async () => { if (input.mutations) input.mutations.delete += 1; },
  };
}

function finalSnapshot(runId: string): Record<string, unknown> {
  const configuredAt = "2026-08-19T04:00:00.000Z";
  return {
    configured: true,
    runId,
    configuredAt,
    expiresAt: new Date(Date.parse(configuredAt) + SBX001_RECEIVER_WINDOW_MS).toISOString(),
    observationWindowMs: SBX001_RECEIVER_WINDOW_MS,
    receipts: [],
    arms: [],
    secretRegistered: false,
    rawQueryNamesRetained: false,
    rawSecretsRetained: false,
    rawSecretDigestsRetained: false,
  };
}

function pendingExperimentArtifact(runId: string): Record<string, unknown> {
  return {
    schemaVersion: 1,
    visibility: "private",
    testId: "SBX-001-DIRECT",
    runId,
    startedAt: "2026-08-19T04:00:00.000Z",
    completedAt: "2026-08-19T04:01:00.000Z",
    runtime: {},
    assessment: {
      verdict: "candidate-medium",
      candidate: true,
      severity: "medium",
      controlsPassed: true,
      secretPhaseAuthorized: true,
      summary: "exact pending candidate fixture",
    },
    scope: {},
    outsidePreflight: {},
    sandbox: {},
    policy: {},
    guest: {},
    commands: {},
    receiver: {
      configured: false,
      rawQueryNamesRetained: false,
      rawSecretsRetained: false,
      rawSecretDigestsRetained: false,
    },
    controllerArms: {},
    receiverObservations: {},
    expectedOperations: {},
    secretGate: {},
    requestBounds: {},
    cleanup: {
      sandboxCreateAttempted: false,
      sandboxRecovered: false,
      sandboxAlreadyAbsent: false,
      sandboxRecoveryChecks: 0,
      sandboxRecoveryObservationMs: 0,
      stopAttempted: false,
      stopped: false,
      deleteAttempted: false,
      deleted: false,
      absenceChecks: 0,
      absenceConfirmed: false,
      receiverConfigureAttempted: false,
      receiverAlreadyAbsent: false,
      receiverDeleteAttempted: false,
      receiverDeleted: false,
      receiverAbsenceChecks: 0,
      receiverAbsenceConfirmed: false,
      errors: [],
    },
    durableSafety: {
      liveLockMode: 0o600,
      recoveryJournalMode: 0o600,
      finalReceiverSnapshotCaptured: false,
      exactCleanupComplete: true,
      artifactFsyncedBeforeJournalAndLockRelease: true,
      localFinalizationPendingAtArtifactWrite: true,
    },
    reportability: { requiresFinalizationReceipt: true, reportable: false },
    retention: {
      rawQueryName: false,
      rawOperatorSecret: false,
      rawSecretDigest: false,
      rawGuestConfiguration: false,
      rawCommandOutput: false,
    },
  };
}

async function runChild(args: string[], environment: NodeJS.ProcessEnv = {}): Promise<{
  code: number | null;
  stdout: string;
  stderr: string;
}> {
  const child = spawn(process.execPath, args, {
    cwd: repositoryDirectory,
    env: { PATH: process.env.PATH, ...environment },
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

describe.sequential("SBX-001 direct recovery controller", () => {
  it("uses the exact stable SDK query shape for every sandbox prefix absence check", () => {
    expect(sbx001SandboxPrefixListOptions("sbx-001-owned-name")).toEqual({
      namePrefix: "sbx-001-owned-name",
      limit: 10,
      sortBy: "name",
      sortOrder: "asc",
    });
  });

  it("binds one exact recovered handle session and persists attribution before exposing it", async () => {
    const journal = createSbx001DirectJournal(new Date("2026-08-19T04:00:00.000Z"), randomUUID());
    const resource = recoveredHandle({ sessions: ["sbx_exact_owned_session"] });
    let sessionReads = 0;
    resource.currentSession = () => {
      sessionReads += 1;
      return { sessionId: "sbx_exact_owned_session" };
    };
    const checkpoints: Array<{ sessionId?: string; attributed: boolean }> = [];
    const exposed = await attributeSbx001RecoveredHandle({
      resource,
      sandboxName: "owned-name",
      sandboxTags: { owner: "exact" },
      journal,
      persist: async () => { checkpoints.push({
        ...(journal.sessionId === undefined ? {} : { sessionId: journal.sessionId }),
        attributed: journal.sandboxAttributed,
      }); },
    });
    expect(exposed).toBe(resource);
    expect(checkpoints).toEqual([{ sessionId: "sbx_exact_owned_session", attributed: true }]);
    expect(sessionReads).toBe(1);
  });

  it.each([
    ["mismatched tags", recoveredHandle({ tags: { owner: "other" } }), undefined],
    ["malformed session", recoveredHandle({ sessions: ["not-canonical"] }), undefined],
    ["replaced journaled session", recoveredHandle({ sessions: ["sbx_replacement_session"] }), "sbx_original_session"],
  ])("rejects %s without persistence or Sandbox mutation", async (_label, resource, journaledSessionId) => {
    const journal = createSbx001DirectJournal(new Date("2026-08-19T04:00:00.000Z"), randomUUID());
    journal.createAttemptedAt = "2026-08-19T04:00:01.000Z";
    if (journaledSessionId) journal.sessionId = journaledSessionId;
    const mutations = { stop: 0, delete: 0 };
    resource.stop = async () => { mutations.stop += 1; };
    resource.delete = async () => { mutations.delete += 1; };
    let persists = 0;
    await expect(attributeSbx001RecoveredHandle({
      resource,
      sandboxName: "owned-name",
      sandboxTags: { owner: "exact" },
      journal,
      persist: async () => { persists += 1; },
    })).rejects.toThrow(/non-exact provenance or session/u);
    expect({ persists, mutations, attributed: journal.sandboxAttributed }).toEqual({
      persists: 0,
      mutations: { stop: 0, delete: 0 },
      attributed: false,
    });
  });

  it("retains unattributed state and exposes no handle when attribution persistence fails", async () => {
    const journal = createSbx001DirectJournal(new Date("2026-08-19T04:00:00.000Z"), randomUUID());
    journal.createAttemptedAt = "2026-08-19T04:00:01.000Z";
    const mutations = { stop: 0, delete: 0 };
    const resource = recoveredHandle({ mutations });
    await expect(attributeSbx001RecoveredHandle({
      resource,
      sandboxName: "owned-name",
      sandboxTags: { owner: "exact" },
      journal,
      persist: async () => { throw new Error("injected attribution persistence failure"); },
    })).rejects.toThrow(/injected attribution persistence failure/u);
    expect(journal).not.toHaveProperty("sessionId");
    expect(journal.sandboxAttributed).toBe(false);
    expect(mutations).toEqual({ stop: 0, delete: 0 });
  });

  it("requires the configured receiver's exact final snapshot and never assesses an older candidate", () => {
    const runId = randomUUID();
    expect(() => requireSbx001FinalReceiverSnapshot({
      status: 404,
      value: undefined,
      runId,
      receiverConfigured: true,
    })).toThrow(/required final snapshot/u);
    expect(() => requireSbx001FinalReceiverSnapshot({
      status: 200,
      value: { ...finalSnapshot(runId), runId: randomUUID() },
      runId,
      receiverConfigured: true,
    })).toThrow(/exact identity/u);
    expect(requireSbx001FinalReceiverSnapshot({
      status: 404,
      value: undefined,
      runId,
      receiverConfigured: false,
    })).toBeUndefined();
    expect(requireSbx001FinalReceiverSnapshot({
      status: 200,
      value: finalSnapshot(runId),
      runId,
      receiverConfigured: true,
    })).toMatchObject({ configured: true, runId });

    let olderCandidateAssessed = false;
    const assessment = assessSbx001DirectAfterFinalReceiver({
      assessmentInput: {} as never,
      receiverConfigured: true,
      finalReceiverSnapshotCaptured: false,
      assess: (() => {
        olderCandidateAssessed = true;
        return {
          verdict: "candidate-high",
          candidate: true,
          severity: "high",
          controlsPassed: true,
          secretPhaseAuthorized: true,
          summary: "older candidate fixture",
        };
      }) as never,
    });
    expect(olderCandidateAssessed).toBe(false);
    expect(assessment).toMatchObject({ verdict: "error", candidate: false });
  });

  it("durably journals the sanitized final receiver snapshot before DELETE intent and request", async () => {
    const runId = randomUUID();
    const journal = createSbx001DirectJournal(new Date("2026-08-19T04:00:00.000Z"), runId);
    journal.receiverConfigureAttemptedAt = "2026-08-19T04:00:01.000Z";
    journal.receiverConfigured = true;
    const events: string[] = [];
    const cleanup = await cleanupSbx001Receiver({
      receiverConfigureAttempted: true,
      runId,
      journal,
      forbidden: [],
      readFinal: async () => ({ status: 200, value: finalSnapshot(runId) }),
      persist: async () => {
        events.push(journal.receiverDeleteAttempted ? "persist-delete-intent" : "persist-final-snapshot");
      },
      deleteReceiver: async () => { events.push("receiver-delete"); return { status: 204 }; },
      checkAbsent: async () => undefined,
      wait: async () => undefined,
    });
    expect(events.slice(0, 3)).toEqual([
      "persist-final-snapshot",
      "persist-delete-intent",
      "receiver-delete",
    ]);
    expect(journal.finalReceiverSnapshot).toEqual(finalSnapshot(runId));
    expect(journal.finalReceiverSnapshotCaptured).toBe(true);
    expect(cleanup).toMatchObject({
      receiverDeleteAttempted: true,
      receiverDeleted: true,
      receiverAbsenceChecks: 3,
      receiverAbsenceConfirmed: true,
      errors: [],
    });
  });

  it.each([
    ["404", { status: 404, value: undefined }],
    ["malformed", { status: 200, value: { configured: true } }],
  ])("performs zero receiver DELETE when a configured final snapshot is %s", async (_label, finalRead) => {
    const runId = randomUUID();
    const journal = createSbx001DirectJournal(new Date("2026-08-19T04:00:00.000Z"), runId);
    journal.receiverConfigureAttemptedAt = "2026-08-19T04:00:01.000Z";
    journal.receiverConfigured = true;
    let deletes = 0;
    const cleanup = await cleanupSbx001Receiver({
      receiverConfigureAttempted: true,
      runId,
      journal,
      forbidden: [],
      readFinal: async () => finalRead,
      persist: async () => undefined,
      deleteReceiver: async () => { deletes += 1; return { status: 204 }; },
      checkAbsent: async () => undefined,
      wait: async () => undefined,
    });
    expect(deletes).toBe(0);
    expect(journal.receiverDeleteAttempted).toBe(false);
    expect(cleanup).toMatchObject({ receiverDeleteAttempted: false, receiverAbsenceChecks: 0 });
    expect(cleanup.errors[0]).toMatch(/final receiver snapshot/u);
  });

  it("performs zero receiver DELETE and restores memory when final-snapshot persistence fails", async () => {
    const runId = randomUUID();
    const journal = createSbx001DirectJournal(new Date("2026-08-19T04:00:00.000Z"), runId);
    journal.receiverConfigureAttemptedAt = "2026-08-19T04:00:01.000Z";
    journal.receiverConfigured = true;
    let deletes = 0;
    const cleanup = await cleanupSbx001Receiver({
      receiverConfigureAttempted: true,
      runId,
      journal,
      forbidden: [],
      readFinal: async () => ({ status: 200, value: finalSnapshot(runId) }),
      persist: async () => { throw new Error("injected final-snapshot persistence failure"); },
      deleteReceiver: async () => { deletes += 1; return { status: 204 }; },
      checkAbsent: async () => undefined,
      wait: async () => undefined,
    });
    expect(deletes).toBe(0);
    expect(journal).not.toHaveProperty("finalReceiverSnapshot");
    expect(journal.finalReceiverSnapshotCaptured).toBe(false);
    expect(journal.receiverDeleteAttempted).toBe(false);
    expect(cleanup.errors).toEqual([
      "final receiver snapshot: injected final-snapshot persistence failure",
    ]);
  });

  it("recovers a crash after receiver DELETE from the exact persisted final snapshot when GET is now 404", async () => {
    const runId = randomUUID();
    const journal = createSbx001DirectJournal(new Date("2026-08-19T04:00:00.000Z"), runId);
    journal.receiverConfigureAttemptedAt = "2026-08-19T04:00:01.000Z";
    journal.receiverConfigured = true;
    journal.finalReceiverSnapshot = finalSnapshot(runId) as never;
    journal.finalReceiverSnapshotCaptured = true;
    journal.receiverDeleteAttempted = true;
    let deletes = 0;
    const recovered = await cleanupSbx001Receiver({
      receiverConfigureAttempted: true,
      runId,
      journal,
      forbidden: [],
      readFinal: async () => ({ status: 404, value: undefined }),
      persist: async () => undefined,
      deleteReceiver: async () => { deletes += 1; return { status: 404 }; },
      checkAbsent: async () => undefined,
      wait: async () => undefined,
    });
    expect(deletes).toBe(1);
    expect(recovered.finalReceiverSnapshot).toEqual(finalSnapshot(runId));
    expect(recovered).toMatchObject({
      receiverAlreadyAbsent: true,
      receiverDeleteAttempted: true,
      receiverAbsenceChecks: 3,
      receiverAbsenceConfirmed: true,
      errors: [],
    });
  });

  it("recovers a crash after local release but before the immutable finalization receipt", async () => {
    const runId = randomUUID();
    let released = false;
    let receipt: { runId: string } | undefined;
    await expect(releaseAndWriteSbx001FinalizationReceipt({
      release: async () => { released = true; },
      afterRelease: () => { throw new Error("injected crash before receipt"); },
      writeReceipt: async () => { receipt = { runId }; },
    })).rejects.toThrow(/crash before receipt/u);
    expect(released).toBe(true);
    expect(receipt).toBeUndefined();

    const recovered = await completeSbx001PendingFinalization({
      runId,
      readReceipt: async () => receipt,
      retainedJournalExists: async () => false,
      readPendingArtifact: async () => pendingExperimentArtifact(runId),
      writeReceipt: async () => (receipt = { runId }),
    });
    expect(recovered).toEqual({ outcome: "receipt-created", receipt: { runId } });
  });

  it("treats a crash after the receipt as already finalized and never clobbers it", async () => {
    const runId = randomUUID();
    const immutableReceipt = { runId, finalizedAt: "2026-08-19T04:02:00.000Z" };
    let receipt: typeof immutableReceipt | undefined;
    await expect(releaseAndWriteSbx001FinalizationReceipt({
      release: async () => undefined,
      writeReceipt: async () => { receipt = immutableReceipt; },
      afterReceipt: () => { throw new Error("injected crash after receipt"); },
    })).rejects.toThrow(/crash after receipt/u);
    let writes = 0;
    const recovered = await completeSbx001PendingFinalization({
      runId,
      readReceipt: async () => receipt,
      retainedJournalExists: async () => false,
      readPendingArtifact: async () => { throw new Error("pending artifact should not be reread"); },
      writeReceipt: async () => { writes += 1; return immutableReceipt; },
    });
    expect(recovered).toEqual({ outcome: "already-finalized", receipt: immutableReceipt });
    expect(writes).toBe(0);
  });

  it("settles a real zero-attempt child locally despite booby-trapped external seams", async () => {
    const runId = randomUUID();
    const setup = await runChild([
      "--import", "tsx", "--input-type=module", "--eval", `
const safety = await import(${JSON.stringify(directSafetyUrl)});
const journal = safety.createSbx001DirectJournal(new Date("2026-08-19T04:00:00.000Z"), ${JSON.stringify(runId)});
const held = await safety.acquireSbx001DirectState(journal);
await held.liveLock.closeRetainingState();
`,
    ]);
    expect(setup).toEqual({ code: 0, stdout: "", stderr: "" });
    generatedPaths.push(sbx001DirectJournalPath(runId), SBX001_DIRECT_LIVE_LOCK);

    const directory = await mkdtemp(join(tmpdir(), "sbx-001-controller-trap-"));
    temporaryDirectories.push(directory);
    const trapPath = join(directory, "trap.mjs");
    await writeFile(trapPath, `
import { Sandbox } from ${JSON.stringify(sandboxModuleUrl)};
const fail = (name) => { throw new Error("EXTERNAL_SEAM_USED:" + name); };
globalThis.fetch = async () => fail("fetch");
Sandbox.create = async () => fail("Sandbox.create");
Sandbox.get = async () => fail("Sandbox.get");
Sandbox.list = async () => fail("Sandbox.list");
`, { mode: 0o600, flag: "wx" });

    const recovered = await runChild(["--import", "tsx", directRunPath], {
      NODE_OPTIONS: `--import=${trapPath}`,
      SBX001_SCOPE_CONFIRMATION: SBX001_DIRECT_SCOPE_CONFIRMATION,
      SBX001_RECOVERY_RUN_ID: runId,
    });
    expect(recovered).toMatchObject({ code: 0, stderr: "" });
    expect(recovered.stdout).not.toContain("EXTERNAL_SEAM_USED");
    const output = JSON.parse(recovered.stdout) as { artifactPath: string };
    generatedPaths.push(output.artifactPath);
    expect(output.artifactPath).not.toBe(sbx001DirectArtifactPath(runId));
    const artifact = JSON.parse(await readFile(output.artifactPath, "utf8")) as Record<string, unknown>;
    expect(artifact).toMatchObject({
      runId,
      recoveryOnly: true,
      mode: "cleanup-only",
      outcome: "cleanup-complete",
      settledLocallyWithoutExternalState: true,
    });
    expect((await lstat(output.artifactPath)).mode & 0o777).toBe(0o600);
    await expect(lstat(sbx001DirectJournalPath(runId))).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(SBX001_DIRECT_LIVE_LOCK)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("a fresh child completes crash-before-receipt state locally and crash-after-receipt recovery is idempotent", async () => {
    const runId = randomUUID();
    const artifactPath = sbx001DirectArtifactPath(runId);
    const receiptPath = sbx001DirectFinalizationReceiptPath(runId);
    generatedPaths.push(artifactPath, receiptPath, sbx001DirectJournalPath(runId), SBX001_DIRECT_LIVE_LOCK);
    const artifact = pendingExperimentArtifact(runId);
    const crashed = await runChild([
      "--import", "tsx", "--input-type=module", "--eval", `
const safety = await import(${JSON.stringify(directSafetyUrl)});
const journal = safety.createSbx001DirectJournal(new Date("2026-08-19T04:00:00.000Z"), ${JSON.stringify(runId)});
const held = await safety.acquireSbx001DirectState(journal);
journal.artifactWriteAttemptedAt = "2026-08-19T04:01:01.000Z";
await safety.persistSbx001DirectJournal(held, journal);
await safety.writeSbx001DirectPrivateArtifact(${JSON.stringify(artifactPath)}, ${JSON.stringify(artifact)});
journal.artifactWritten = true;
journal.completed = true;
await safety.persistSbx001DirectJournal(held, journal);
await safety.releaseSbx001DirectState(held);
process.exit(77);
`,
    ]);
    expect(crashed).toMatchObject({ code: 77, stdout: "", stderr: "" });
    await expect(lstat(receiptPath)).rejects.toMatchObject({ code: "ENOENT" });
    const immutableArtifact = await readFile(artifactPath);

    const directory = await mkdtemp(join(tmpdir(), "sbx-001-finalization-trap-"));
    temporaryDirectories.push(directory);
    const trapPath = join(directory, "trap.mjs");
    await writeFile(trapPath, `
import { Sandbox } from ${JSON.stringify(sandboxModuleUrl)};
const fail = (name) => { throw new Error("EXTERNAL_SEAM_USED:" + name); };
globalThis.fetch = async () => fail("fetch");
Sandbox.create = async () => fail("Sandbox.create");
Sandbox.get = async () => fail("Sandbox.get");
Sandbox.list = async () => fail("Sandbox.list");
`, { mode: 0o600, flag: "wx" });
    const environment = {
      NODE_OPTIONS: `--import=${trapPath}`,
      SBX001_SCOPE_CONFIRMATION: SBX001_DIRECT_SCOPE_CONFIRMATION,
      SBX001_RECOVERY_RUN_ID: runId,
    };
    const beforeReceipt = await runChild(["--import", "tsx", directRunPath], environment);
    expect(beforeReceipt).toMatchObject({ code: 0, stderr: "" });
    expect(JSON.parse(beforeReceipt.stdout)).toMatchObject({
      runId,
      outcome: "receipt-created",
      externalRequests: 0,
      finalizationReceiptPath: receiptPath,
      localStateReleased: true,
      reportable: true,
    });
    expect((await lstat(receiptPath)).mode & 0o777).toBe(0o600);
    expect(await readFile(artifactPath)).toEqual(immutableArtifact);
    const immutableReceipt = await readFile(receiptPath);

    const afterReceipt = await runChild(["--import", "tsx", directRunPath], environment);
    expect(afterReceipt).toMatchObject({ code: 0, stderr: "" });
    expect(JSON.parse(afterReceipt.stdout)).toMatchObject({
      runId,
      outcome: "already-finalized",
      externalRequests: 0,
      finalizationReceiptPath: receiptPath,
    });
    expect(await readFile(receiptPath)).toEqual(immutableReceipt);
    expect(await readFile(artifactPath)).toEqual(immutableArtifact);
    immutableArtifact.fill(0);
    immutableReceipt.fill(0);
  });

  it("the matcher itself rejects a journal/session substitution", () => {
    expect(matchExactSbx001RecoveredHandle({
      resource: recoveredHandle({ sessions: ["sbx_replacement_session"] }),
      sandboxName: "owned-name",
      sandboxTags: { owner: "exact" },
      journaledSessionId: "sbx_original_session",
    })).toEqual({ matched: false });
  });
});
