import { randomUUID } from "node:crypto";
import { lstat, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  SBX038_UNKNOWN_CREATE_SETTLEMENT_MS,
  acquireSbx038State,
  createSbx038Journal,
  exactSbx038SandboxProvenance,
  finalizeSbx038Artifact,
  parseSbx038Journal,
  persistSbx038Journal,
  proveSbx038SandboxAbsence,
  readSbx038Journal,
  releaseSbx038State,
  sbx038ArtifactPath,
  sbx038JournalCleanupComplete,
  sbx038RecoveryArtifactPath,
  sbx038Resource,
  sbx038UnknownCreateSettlementReached,
  writeSbx038Checkpoint,
  writeSbx038RecoveryArtifact,
} from "../pocs/SBX-038/safety.js";

describe.sequential("SBX-038 durable safety state", () => {
  it("round-trips exact public/secret resources and rejects impossible create provenance", () => {
    const at = new Date("2026-08-19T12:00:00.000Z");
    const journal = createSbx038Journal({
      runId: "123e4567-e89b-42d3-a456-426614174000",
      now: at,
    });
    expect(parseSbx038Journal(structuredClone(journal))).toEqual(journal);
    expect(journal.resources.map((value) => value.role)).toEqual(["public", "secret"]);
    expect(JSON.stringify(journal)).not.toMatch(/token|operatorSecret|adminKey/u);

    const unknown = sbx038Resource(journal, "public");
    unknown.createAttemptedAt = journal.startedAt;
    unknown.createResponseSettledAt = journal.startedAt;
    expect(parseSbx038Journal(structuredClone(journal))).toEqual(journal);
    expect(sbx038UnknownCreateSettlementReached(unknown, at.getTime())).toBe(false);
    expect(sbx038UnknownCreateSettlementReached(
      unknown,
      at.getTime() + SBX038_UNKNOWN_CREATE_SETTLEMENT_MS,
    )).toBe(true);

    const malformed = structuredClone(journal);
    malformed.resources[0].sessionId = "bad";
    malformed.resources[0].provenanceValidated = true;
    expect(() => parseSbx038Journal(malformed)).toThrow();
    const untrusted = structuredClone(journal);
    untrusted.resources[0].sessionId = `sbx_${"A".repeat(24)}`;
    expect(() => parseSbx038Journal(untrusted)).toThrow();
  });

  it("requires exact full create provenance", () => {
    const journal = createSbx038Journal();
    const expected = sbx038Resource(journal, "public");
    const sessionId = `sbx_${"A".repeat(24)}`;
    const exact = { name: expected.name, persistent: false, tags: expected.tags, currentSessionId: sessionId };
    expect(exactSbx038SandboxProvenance(exact, expected)).toBe(true);
    expect(exactSbx038SandboxProvenance({ ...exact, persistent: true }, expected)).toBe(false);
    expect(exactSbx038SandboxProvenance({ ...exact, tags: { ...expected.tags, extra: "x" } }, expected)).toBe(false);
    expect(exactSbx038SandboxProvenance({ ...exact, name: `${expected.name}-other` }, expected)).toBe(false);
  });

  it("durably proves a settled unknown create absent without inventing a session", async () => {
    const at = new Date("2026-08-19T12:00:00.000Z");
    const journal = createSbx038Journal({ now: at });
    const unknown = sbx038Resource(journal, "public");
    unknown.createAttemptedAt = journal.startedAt;
    let persisted = 0;
    const notFound = Object.assign(new Error("not found"), { code: "ENOENT" });
    expect(await proveSbx038SandboxAbsence(journal, unknown, {
      async getSandbox() { throw notFound; },
      async listSandboxes() { return []; },
      isNotFound(error) { return error === notFound; },
      async persist(value) { parseSbx038Journal(structuredClone(value)); persisted += 1; },
      async wait() { /* deterministic local test */ },
      now: () => at.getTime() + SBX038_UNKNOWN_CREATE_SETTLEMENT_MS,
      absenceDelaysMs: [0, 0, 0],
    })).toBe(true);
    expect(persisted).toBe(4);
    expect(Object.prototype.hasOwnProperty.call(unknown, "sessionId")).toBe(false);
    expect(unknown).toMatchObject({
      provenanceValidated: false,
      absenceChecks: 3,
      prefixListAbsent: true,
      absenceOnlyValidated: true,
      deleted: true,
    });
    expect(sbx038JournalCleanupComplete(journal, at.getTime() + SBX038_UNKNOWN_CREATE_SETTLEMENT_MS)).toBe(true);
  });

  it("writes mode-0600 no-clobber checkpoints and per-attempt recovery artifacts", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx-038-artifacts-"));
    const runId = randomUUID();
    const attemptId = randomUUID();
    try {
      expect(await writeSbx038Checkpoint(runId, { finalizationPending: true }, directory)).toBe(0o600);
      const artifactPath = sbx038ArtifactPath(runId, directory);
      expect((await lstat(artifactPath)).mode & 0o777).toBe(0o600);
      await expect(writeSbx038Checkpoint(runId, { clobber: true }, directory)).rejects.toMatchObject({
        code: "EEXIST",
      });
      expect(await finalizeSbx038Artifact(runId, { finalizationPending: false }, directory)).toBe(0o600);
      expect(JSON.parse(await readFile(artifactPath, "utf8"))).toEqual({ finalizationPending: false });

      expect(await writeSbx038RecoveryArtifact(runId, attemptId, { recoveryOnly: true }, directory)).toBe(0o600);
      const recoveryPath = sbx038RecoveryArtifactPath(runId, attemptId, directory);
      expect((await lstat(recoveryPath)).mode & 0o777).toBe(0o600);
      await expect(writeSbx038RecoveryArtifact(runId, attemptId, {}, directory)).rejects.toMatchObject({
        code: "EEXIST",
      });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("fsyncs a mode-0600 journal and transactionally removes journal and lock", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx-038-state-"));
    const journal = createSbx038Journal();
    const held = await acquireSbx038State(journal, directory);
    try {
      expect(held.lockMode).toBe(0o600);
      expect(held.journalMode).toBe(0o600);
      journal.phase = "completed";
      journal.completed = true;
      await persistSbx038Journal(held, journal);
      expect((await readSbx038Journal(journal.runId, directory)).completed).toBe(true);
      await releaseSbx038State(held);
      await expect(lstat(held.journalPath)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(held.lockPath)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(`${held.lockPath}.transaction`)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      if (!held.liveLock.isReleased()) await held.liveLock.closeRetainingState();
      await rm(directory, { recursive: true, force: true });
    }
  });
});
