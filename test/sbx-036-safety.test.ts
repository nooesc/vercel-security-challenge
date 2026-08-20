import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstat, mkdtemp, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  SBX036_CREATE_SETTLEMENT_MS,
  acquireSbx036RecoveryState,
  acquireSbx036State,
  cleanupSbx036Exact,
  createSbx036Journal,
  exactSbx036ZeroExternalStateJournal,
  parseSbx036Journal,
  persistSbx036Journal,
  readSbx036Journal,
  releaseSbx036State,
  sbx036ArtifactPath,
  sbx036JournalPath,
  sbx036RecoveryArtifactPath,
  writeSbx036PrivateArtifact,
  type Sbx036CleanupDependencies,
  type Sbx036RecoveryJournal,
  type Sbx036SandboxView,
  type Sbx036StageJournal,
} from "../pocs/SBX-036/safety.js";

const directories: string[] = [];

class NotFound extends Error {}

afterEach(async () => {
  await Promise.all(directories.splice(0).map(async (directory) => rm(directory, { recursive: true, force: true })));
});

function journal(): Sbx036RecoveryJournal {
  return createSbx036Journal({
    rootRunId: "123e4567-e89b-42d3-a456-426614174100",
    publicRunId: "223e4567-e89b-42d3-a456-426614174101",
    secretRunId: "323e4567-e89b-42d3-a456-426614174102",
    now: new Date("2026-08-19T00:00:00.000Z"),
  });
}

function sandbox(stage: Sbx036StageJournal, overrides: Partial<Sbx036SandboxView> = {}): Sbx036SandboxView {
  return {
    name: stage.sandboxName,
    persistent: false,
    tags: { ...stage.tags },
    currentSessionId: "sbx_abcdefghijklmnopqrstuvwxyz012345",
    status: "running",
    stop: async () => undefined,
    delete: async () => undefined,
    neutralizeSecret: async () => undefined,
    ...overrides,
  };
}

function dependencies(input: {
  journal: Sbx036RecoveryJournal;
  get?: (name: string) => Promise<Sbx036SandboxView>;
  list?: (prefix: string) => Promise<Array<Pick<Sbx036SandboxView,
    "name" | "persistent" | "tags" | "currentSessionId">>>;
  deleteReceiver?: (runId: string) => Promise<boolean>;
  readReceiver?: (runId: string) => Promise<boolean>;
  now?: number;
  persisted?: Sbx036RecoveryJournal[];
  persistFn?: (value: Sbx036RecoveryJournal) => Promise<void>;
}): Sbx036CleanupDependencies {
  return {
    getSandbox: input.get ?? (async () => { throw new NotFound(); }),
    listSandboxes: input.list ?? (async () => []),
    isNotFound: (error) => error instanceof NotFound,
    deleteReceiver: input.deleteReceiver ?? (async () => true),
    readReceiverConfigured: input.readReceiver ?? (async () => false),
    persist: input.persistFn ?? (async (value) => { input.persisted?.push(structuredClone(value)); }),
    wait: async () => undefined,
    absenceDelaysMs: [0, 1, 2],
    now: () => input.now ?? Date.parse("2026-08-19T00:00:01.000Z"),
  };
}

describe("SBX-036 durable safety", () => {
  it("round-trips only the exact secret-free two-stage journal", () => {
    const value = journal();
    expect(parseSbx036Journal(structuredClone(value))).toEqual(value);
    expect(exactSbx036ZeroExternalStateJournal(value)).toBe(true);
    expect(exactSbx036ZeroExternalStateJournal({ ...value, completed: true })).toBe(true);
    expect(exactSbx036ZeroExternalStateJournal({
      ...value,
      receivers: [{ ...value.receivers[0], configureAttempted: true }, value.receivers[1]],
    })).toBe(false);
    expect(exactSbx036ZeroExternalStateJournal({
      ...value,
      stages: [{ ...value.stages[0], createAttemptedAt: value.startedAt }, value.stages[1]],
    })).toBe(false);
    expect(JSON.stringify(value)).not.toMatch(/token|adminKey|canary|operationId|commitment|digest/iu);
    expect(() => parseSbx036Journal({ ...value, extra: true })).toThrow(/fields/u);
    expect(() => parseSbx036Journal({
      ...value,
      stages: [{ ...value.stages[0], tags: { ...value.stages[0].tags, role: "secret" } }, value.stages[1]],
    })).toThrow(/invalid/u);
    expect(() => parseSbx036Journal({
      ...value,
      stages: [{ ...value.stages[0], sessionId: "bad", provenanceValidated: true }, value.stages[1]],
    })).toThrow(/invalid/u);
  });

  it("retains an unsettled unknown create and never retries create or deletes an unattributed resource", async () => {
    const value = journal();
    value.stages[0].createAttemptedAt = "2026-08-19T00:00:00.000Z";
    let gets = 0;
    let deletes = 0;
    const result = await cleanupSbx036Exact({
      journal: value,
      dependencies: dependencies({
        journal: value,
        get: async () => { gets += 1; throw new NotFound(); },
        list: async () => [],
        now: Date.parse(value.stages[0].createAttemptedAt) + SBX036_CREATE_SETTLEMENT_MS - 1,
        deleteReceiver: async () => { deletes += 1; return true; },
      }),
    });
    expect(result).toMatchObject({ complete: false, cleanupIndeterminate: true });
    expect(gets).toBe(0);
    expect(deletes).toBe(0);
    expect(value.stages[0].provenanceValidated).toBe(false);
    expect(value.stages[0].sessionId).toBeUndefined();
  });

  it("retains the real lock and mode-0600 journal after create response loss without a session", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx-036-unknown-create-"));
    directories.push(directory);
    const value = createSbx036Journal();
    const held = await acquireSbx036State(value, directory);
    value.stages[0].createAttemptedAt = new Date().toISOString();
    await persistSbx036Journal(held, value);
    const result = await cleanupSbx036Exact({
      journal: value,
      dependencies: dependencies({
        journal: value,
        persistFn: async (current) => persistSbx036Journal(held, current),
        now: Date.parse(value.stages[0].createAttemptedAt) + SBX036_CREATE_SETTLEMENT_MS - 1,
      }),
    });
    expect(result.complete).toBe(false);
    expect((await lstat(held.lockPath)).mode & 0o777).toBe(0o600);
    expect((await lstat(held.journalPath)).mode & 0o777).toBe(0o600);
    expect((await readSbx036Journal(value.rootRunId, directory)).stages[0].sessionId).toBeUndefined();
    await held.liveLock.closeRetainingState();
  });

  it("accepts settled unknown create only after three named absences and exact empty prefix list", async () => {
    const value = journal();
    value.stages[0].createAttemptedAt = "2026-08-19T00:00:00.000Z";
    let gets = 0;
    const result = await cleanupSbx036Exact({
      journal: value,
      dependencies: dependencies({
        journal: value,
        get: async () => { gets += 1; throw new NotFound(); },
        list: async () => [],
        now: Date.parse(value.stages[0].createAttemptedAt) + SBX036_CREATE_SETTLEMENT_MS,
      }),
    });
    expect(result.complete).toBe(true);
    expect(gets).toBe(3);
    expect(value.stages[0]).toMatchObject({ absenceChecks: 3, prefixListAbsent: true });
  });

  it("never stops or deletes supplied handles with wrong name, tags, persistence, or session", async () => {
    for (const mutate of [
      (stage: Sbx036StageJournal) => sandbox(stage, { name: `${stage.sandboxName}-other` }),
      (stage: Sbx036StageJournal) => sandbox(stage, { tags: { ...stage.tags, run: randomUUID() } }),
      (stage: Sbx036StageJournal) => sandbox(stage, { persistent: true }),
      (stage: Sbx036StageJournal) => sandbox(stage, { currentSessionId: "not-a-session" }),
    ]) {
      const value = journal();
      value.stages[0].createAttemptedAt = new Date().toISOString();
      let stops = 0;
      let deletes = 0;
      const bad = mutate(value.stages[0]);
      bad.stop = async () => { stops += 1; };
      bad.delete = async () => { deletes += 1; };
      const result = await cleanupSbx036Exact({
        journal: value,
        sandboxes: { public: bad },
        dependencies: dependencies({ journal: value }),
      });
      expect(result.complete).toBe(false);
      expect({ stops, deletes }).toEqual({ stops: 0, deletes: 0 });
    }
  });

  it("journals recovered exact get/list provenance before delete and settles delete response loss", async () => {
    const value = journal();
    const stage = value.stages[0];
    stage.createAttemptedAt = new Date().toISOString();
    const events: string[] = [];
    let absent = false;
    const recovered = sandbox(stage, {
      stop: async () => { events.push("stop"); },
      delete: async () => { events.push("delete"); absent = true; throw new Error("lost response"); },
    });
    const persisted: Sbx036RecoveryJournal[] = [];
    const result = await cleanupSbx036Exact({
      journal: value,
      dependencies: dependencies({
        journal: value,
        persisted,
        list: async () => absent ? [] : [{
          name: recovered.name, persistent: recovered.persistent, tags: recovered.tags,
          currentSessionId: recovered.currentSessionId,
        }],
        get: async () => { if (absent) throw new NotFound(); return recovered; },
      }),
    });
    expect(result.complete).toBe(true);
    expect(events).toEqual(["stop", "delete"]);
    const provenanceCheckpoint = persisted.findIndex((entry) => entry.stages[0].provenanceValidated);
    const deleteIntent = persisted.findIndex((entry) => entry.stages[0].deleteAttempted);
    expect(provenanceCheckpoint).toBeGreaterThanOrEqual(0);
    expect(deleteIntent).toBeGreaterThan(provenanceCheckpoint);
    expect(value.stages[0]).toMatchObject({ deleted: true, absenceChecks: 3, prefixListAbsent: true });
  });

  it("finishes a known-session delete after a crash before the three absence checkpoints", async () => {
    const value = journal();
    const stage = value.stages[0];
    stage.createAttemptedAt = new Date().toISOString();
    stage.createResponseSettledAt = new Date().toISOString();
    stage.sessionId = "sbx_abcdefghijklmnopqrstuvwxyz012345";
    stage.provenanceValidated = true;
    stage.stopAttempted = true;
    stage.stopped = true;
    stage.deleteAttempted = true;
    stage.deleted = false;
    const result = await cleanupSbx036Exact({
      journal: value,
      dependencies: dependencies({ journal: value, get: async () => { throw new NotFound(); }, list: async () => [] }),
    });
    expect(result.complete).toBe(true);
    expect(stage).toMatchObject({ stopped: true, deleted: true, absenceChecks: 3, prefixListAbsent: true });
  });

  it("reissues only idempotent cleanup after persisted stop/delete intents and never create", async () => {
    const value = journal();
    const stage = value.stages[0];
    stage.createAttemptedAt = new Date().toISOString();
    stage.createResponseSettledAt = new Date().toISOString();
    stage.sessionId = "sbx_abcdefghijklmnopqrstuvwxyz012345";
    stage.provenanceValidated = true;
    stage.stopAttempted = true;
    stage.stopped = false;
    stage.deleteAttempted = true;
    stage.deleted = false;
    value.receivers[0].configureAttempted = true;
    value.receivers[0].configured = true;
    value.receivers[0].deleteAttempted = true;
    let stops = 0;
    let sandboxDeletes = 0;
    let receiverDeletes = 0;
    const target = sandbox(stage, {
      stop: async () => { stops += 1; },
      delete: async () => { sandboxDeletes += 1; },
    });
    const result = await cleanupSbx036Exact({
      journal: value,
      sandboxes: { public: target },
      dependencies: dependencies({
        journal: value,
        deleteReceiver: async () => { receiverDeletes += 1; return true; },
      }),
    });
    expect(result.complete).toBe(true);
    expect({ stops, sandboxDeletes, receiverDeletes }).toEqual({ stops: 1, sandboxDeletes: 1, receiverDeletes: 1 });
    expect(stage).toMatchObject({ stopped: true, deleted: true, absenceChecks: 3 });
    expect(value.receivers[0]).toMatchObject({ deleted: true, absenceChecks: 3 });
  });

  it("retains state when receiver cleanup is incomplete", async () => {
    const value = journal();
    value.receivers[0].configureAttempted = true;
    value.receivers[0].configured = true;
    const result = await cleanupSbx036Exact({
      journal: value,
      dependencies: dependencies({ journal: value, readReceiver: async () => true }),
    });
    expect(result).toMatchObject({ complete: false, cleanupIndeterminate: true });
    expect(value.receivers[0]).toMatchObject({ deleteAttempted: true, absenceChecks: 0 });
  });

  it("persists secret neutralization intent and retains on response loss before any stop/delete", async () => {
    const value = journal();
    const stage = value.stages[1];
    stage.createAttemptedAt = new Date().toISOString();
    stage.sessionId = "sbx_abcdefghijklmnopqrstuvwxyz012345";
    stage.provenanceValidated = true;
    stage.createResponseSettledAt = new Date().toISOString();
    stage.secretWriteAttempted = true;
    let stops = 0;
    let deletes = 0;
    const target = sandbox(stage, {
      neutralizeSecret: async () => { throw new Error("lost overwrite response"); },
      stop: async () => { stops += 1; },
      delete: async () => { deletes += 1; },
    });
    const result = await cleanupSbx036Exact({
      journal: value,
      sandboxes: { secret: target },
      dependencies: dependencies({ journal: value }),
    });
    expect(result.complete).toBe(false);
    expect(stage).toMatchObject({ secretNeutralizeAttempted: true, secretNeutralized: false });
    expect({ stops, deletes }).toEqual({ stops: 0, deletes: 0 });

    const retry = sandbox(stage, {
      neutralizeSecret: async () => undefined,
      stop: async () => { stops += 1; },
      delete: async () => { deletes += 1; },
    });
    const retried = await cleanupSbx036Exact({
      journal: value,
      sandboxes: { secret: retry },
      dependencies: dependencies({ journal: value }),
    });
    expect(retried.complete).toBe(true);
    expect(stage).toMatchObject({ secretNeutralized: true, deleted: true, absenceChecks: 3 });
    expect({ stops, deletes }).toEqual({ stops: 1, deletes: 1 });
  });

  it("uses mode-0600 no-clobber evidence and ownership-bound lock/journal release", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx-036-safety-"));
    directories.push(directory);
    const value = createSbx036Journal();
    const held = await acquireSbx036State(value, directory);
    expect((await lstat(held.lockPath)).mode & 0o777).toBe(0o600);
    expect((await lstat(held.journalPath)).mode & 0o777).toBe(0o600);
    await expect(acquireSbx036RecoveryState(randomUUID(), directory)).rejects.toThrow(/mismatch|refused|run/u);
    expect((await readSbx036Journal(value.rootRunId, directory)).rootRunId).toBe(value.rootRunId);
    value.completed = true;
    await persistSbx036Journal(held, value);
    await releaseSbx036State(held);
    await expect(lstat(held.lockPath)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(held.journalPath)).rejects.toMatchObject({ code: "ENOENT" });

    const experiment = sbx036ArtifactPath(value.rootRunId, directory);
    const recovery = sbx036RecoveryArtifactPath(value.rootRunId, randomUUID(), directory);
    await writeSbx036PrivateArtifact(experiment, { rootRunId: value.rootRunId, kind: "experiment" });
    await writeSbx036PrivateArtifact(recovery, { rootRunId: value.rootRunId, recoveryOnly: true });
    expect((await lstat(experiment)).mode & 0o777).toBe(0o600);
    expect((await lstat(recovery)).mode & 0o777).toBe(0o600);
    await expect(writeSbx036PrivateArtifact(experiment, { overwrite: true })).rejects.toMatchObject({ code: "EEXIST" });
  });

  it("preserves byte-identical pre-existing journal state on an EEXIST acquisition", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx-036-journal-collision-"));
    directories.push(directory);
    const value = createSbx036Journal();
    const path = sbx036JournalPath(value.rootRunId, directory);
    const bytes = Buffer.from("pre-existing-recovery-state\n", "utf8");
    await writeFile(path, bytes, { mode: 0o600, flag: "wx" });
    await expect(acquireSbx036State(value, directory)).rejects.toMatchObject({ code: "EEXIST" });
    expect(await readFile(path)).toEqual(bytes);
    await expect(lstat(join(directory, "SBX-036-live-active.lock"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("reclaims a dead exact owner with its committed journal intact", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx-036-dead-owner-"));
    directories.push(directory);
    const value = journal();
    const moduleUrl = new URL("../pocs/SBX-036/safety.ts", import.meta.url).href;
    const source = `
const safety = await import(${JSON.stringify(moduleUrl)});
const value = safety.createSbx036Journal(${JSON.stringify({
      rootRunId: value.rootRunId,
      publicRunId: value.stages[0].runId,
      secretRunId: value.stages[1].runId,
    })});
await safety.acquireSbx036State(value, ${JSON.stringify(directory)});
process.stdout.write("acquired\\n");
`;
    expect(execFileSync(process.execPath, [
      "--import", "tsx", "--input-type=module", "--eval", source,
    ], { encoding: "utf8" })).toBe("acquired\n");
    const recovered = await acquireSbx036RecoveryState(value.rootRunId, directory);
    const recoveredJournal = await readSbx036Journal(value.rootRunId, directory);
    recoveredJournal.completed = true;
    await persistSbx036Journal(recovered, recoveredJournal);
    await releaseSbx036State(recovered);
    await expect(lstat(recovered.lockPath)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(recovered.journalPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("preserves a replacement lock rather than releasing a different inode", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx-036-replacement-"));
    directories.push(directory);
    const value = createSbx036Journal();
    const held = await acquireSbx036State(value, directory);
    value.completed = true;
    await persistSbx036Journal(held, value);
    const bytes = await readFile(held.lockPath);
    await rename(held.lockPath, `${held.lockPath}.owned`);
    await writeFile(held.lockPath, bytes, { mode: 0o600, flag: "wx" });
    await expect(releaseSbx036State(held)).rejects.toThrow();
    expect(await readFile(held.lockPath)).toEqual(bytes);
    await expect(lstat(held.journalPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("imports the controller without executing main or making an external call", () => {
    const source = `
globalThis.fetch = async () => { throw new Error("fetch-called-on-import"); };
await import(${JSON.stringify(new URL("../pocs/SBX-036/postgres-pre-tls-coalescing.ts", import.meta.url).href)});
process.stdout.write("import-safe\\n");
`;
    expect(execFileSync(process.execPath, [
      "--import", "tsx", "--input-type=module", "--eval", source,
    ], { encoding: "utf8" })).toBe("import-safe\n");
  });

  it("releases both zero-attempt completion checkpoints without credentials or external calls", async () => {
    const value = journal();
    const safetyUrl = new URL("../pocs/SBX-036/safety.ts", import.meta.url).href;
    const controllerUrl = new URL("../pocs/SBX-036/postgres-pre-tls-coalescing.ts", import.meta.url).href;
    for (const completedBeforeRecovery of [false, true]) {
      const directory = await mkdtemp(join(tmpdir(), "sbx-036-zero-attempt-recovery-"));
      directories.push(directory);
    const acquireSource = `
const safety = await import(${JSON.stringify(safetyUrl)});
const value = safety.createSbx036Journal({ ...${JSON.stringify({
      rootRunId: value.rootRunId,
      publicRunId: value.stages[0].runId,
      secretRunId: value.stages[1].runId,
    })}, now: new Date(${JSON.stringify(value.startedAt)}) });
const held = await safety.acquireSbx036State(value, ${JSON.stringify(directory)});
if (${JSON.stringify(completedBeforeRecovery)}) {
  value.completed = true;
  await safety.persistSbx036Journal(held, value);
}
process.stdout.write("acquired-zero-state\\n");
`;
    expect(execFileSync(process.execPath, [
      "--import", "tsx", "--input-type=module", "--eval", acquireSource,
    ], { encoding: "utf8" })).toBe("acquired-zero-state\n");

    const recoverySource = `
globalThis.fetch = async () => { throw new Error("network-booby-trap"); };
const controller = await import(${JSON.stringify(controllerUrl)});
await controller.runSbx036Recovery(${JSON.stringify(value.rootRunId)}, ${JSON.stringify(directory)});
if (process.exitCode) throw new Error("recovery-set-exit-code-" + process.exitCode);
`;
    const output = execFileSync(process.execPath, [
      "--import", "tsx", "--input-type=module", "--eval", recoverySource,
    ], {
      encoding: "utf8",
      env: {
        ...process.env,
        DOTENV_CONFIG_PATH: "/dev/null",
        SBX036_VERCEL_TOKEN: "",
        SBX036_ADMIN_KEY: "",
        SBX036_TEAM_ID: "",
        SBX036_PROJECT_ID: "",
      },
    });
    const printed = JSON.parse(output) as Record<string, unknown>;
    expect(printed).toMatchObject({
      testId: "SBX-036-POC",
      rootRunId: value.rootRunId,
      recoveryOnly: true,
      mode: "cleanup-only",
      zeroExternalState: true,
      outcome: "zero-external-state-cleanup-complete",
      cleanupComplete: true,
      externalCreateRequests: 0,
      externalCleanupRequests: 0,
    });
    expect(printed).not.toHaveProperty("assessment");
    expect(printed).not.toHaveProperty("candidate");
    expect(printed).not.toHaveProperty("verdict");
    await expect(lstat(sbx036JournalPath(value.rootRunId, directory))).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(join(directory, "SBX-036-live-active.lock"))).rejects.toMatchObject({ code: "ENOENT" });
    const files = await readdir(directory);
    expect(files).toHaveLength(1);
    expect(files[0]).toMatch(new RegExp(`^SBX-036-${value.rootRunId}-recovery-[0-9a-f-]+-private\\.json$`, "u"));
    const artifact = JSON.parse(await readFile(join(directory, files[0]!), "utf8")) as Record<string, unknown>;
    const { evidencePath, ...printedArtifact } = printed;
    expect(evidencePath).toBe(join(directory, files[0]!));
    expect(artifact).toEqual(printedArtifact);
    }
  });
});
