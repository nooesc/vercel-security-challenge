import { randomUUID } from "node:crypto";
import { lstat, mkdir, readFile, rm, unlink } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  createSbx056Journal,
  finalizeSbx056Safety,
  parseSbx056Journal,
  recoverSbx056JournalAfterLock,
  sbx056ArtifactPath,
  sbx056CheckpointPath,
  sbx056FixedPath,
  sbx056Name,
  sbx056JournalPath,
  sbx056MayReacquireFinalizationLock,
  sbx056RecoveryArtifactPath,
  sbx056Tags,
  sbx056UnknownCreateSettled,
  writeSbx056NoClobber,
  SBX056_UNKNOWN_CREATE_SETTLEMENT_MS,
} from "../pocs/SBX-056/safety.js";

const RUN = "12345678-1234-4abc-8def-1234567890ab";
const CONTROL = "prj_ControlProject1234567890";
const VICTIM = "prj_VictimProject1234567890";

describe("SBX-056 durable safety state", () => {
  it("derives two exact, distinct project/name/tag/path plans from one UUID", () => {
    const journal = createSbx056Journal(CONTROL, VICTIM, RUN,
      new Date("2026-08-19T12:00:00.000Z"));
    expect(journal.targets.map((target) => target.role)).toEqual(["control", "victim"]);
    expect(journal.targets.map((target) => target.projectId)).toEqual([CONTROL, VICTIM]);
    expect(journal.targets[0]).toMatchObject({
      name: sbx056Name(RUN, "control"), tags: sbx056Tags(RUN, "control"),
      zeroExternalStateConfirmed: false, absenceResolvedWithoutHandle: false,
    });
    expect(sbx056FixedPath(RUN, "control")).toBe(
      "/vercel/sandbox/.sbx-056-control-1234567812344abc8def1234567890ab.marker");
    expect(sbx056FixedPath(RUN, "victim")).not.toBe(sbx056FixedPath(RUN, "control"));
    expect(parseSbx056Journal(journal)).toEqual(journal);
  });

  it("rejects invalid IDs, identical projects, extra fields, target permutation, and raw retention", () => {
    expect(() => createSbx056Journal(CONTROL, CONTROL, RUN)).toThrow(/distinct/u);
    expect(() => createSbx056Journal("bad", VICTIM, RUN)).toThrow(/project ID/u);
    expect(() => createSbx056Journal(CONTROL, VICTIM, "not-a-uuid")).toThrow(/canonical/u);
    const journal = createSbx056Journal(CONTROL, VICTIM, RUN);
    expect(() => parseSbx056Journal({ ...journal, extra: true })).toThrow(/fields/u);
    expect(() => parseSbx056Journal({ ...journal, rawTokensOrMarkersRetained: true })).toThrow();
    expect(() => parseSbx056Journal({ ...journal,
      targets: [journal.targets[1], journal.targets[0]] })).toThrow();
  });

  it("enforces phase ordering and session/provenance relationships", () => {
    const journal = createSbx056Journal(CONTROL, VICTIM, RUN);
    expect(() => parseSbx056Journal({ ...journal, publicControlPassed: true })).toThrow(/relationships/u);
    expect(() => parseSbx056Journal({ ...journal, victimMarkerStaged: true })).toThrow(/relationships/u);
    expect(() => parseSbx056Journal({ ...journal, crossReadDispatched: true })).toThrow(/relationships/u);
    const target = { ...journal.targets[0], provenanceValidated: true };
    expect(() => parseSbx056Journal({ ...journal, targets: [target, journal.targets[1]] })).toThrow();
  });

  it("recognizes unknown-create settlement after the full request-plus-lifetime horizon", () => {
    const target = createSbx056Journal(CONTROL, VICTIM, RUN).targets[0];
    const attempted = Date.parse("2026-08-19T12:00:00.000Z");
    target.createAttemptedAt = new Date(attempted).toISOString();
    expect(sbx056UnknownCreateSettled(target,
      attempted + SBX056_UNKNOWN_CREATE_SETTLEMENT_MS - 1)).toBe(false);
    expect(sbx056UnknownCreateSettled(target,
      attempted + SBX056_UNKNOWN_CREATE_SETTLEMENT_MS)).toBe(true);
  });

  it("allows completion only for zero-state, settled-unknown, or fully deleted targets", () => {
    const zero = createSbx056Journal(CONTROL, VICTIM, RUN);
    zero.targets[0].zeroExternalStateConfirmed = true;
    zero.targets[1].zeroExternalStateConfirmed = true;
    zero.completed = true;
    expect(parseSbx056Journal(zero).completed).toBe(true);

    const broken = createSbx056Journal(CONTROL, VICTIM, RUN);
    broken.completed = true;
    expect(() => parseSbx056Journal(broken)).toThrow(/relationships/u);

    const deleted = createSbx056Journal(CONTROL, VICTIM, RUN);
    for (const target of deleted.targets) {
      target.createAttemptedAt = "2026-08-19T12:00:00.000Z";
      target.createSettledAt = "2026-08-19T12:00:01.000Z";
      target.sessionId = `sbx_${target.role}_abcdefghijklmnopqrstuvwxyz`;
      target.provenanceValidated = true;
      target.stopAttempted = true;
      target.stopped = true;
      target.deleteAttempted = true;
      target.deleted = true;
      target.exactNameAbsenceChecks = 2;
      target.prefixAbsent = true;
    }
    deleted.completed = true;
    expect(parseSbx056Journal(deleted).completed).toBe(true);
  });

  it("writes mode-0600 no-clobber private artifacts", async () => {
    const directory = resolve("artifacts", `SBX-056-test-${process.pid}-${Date.now()}`);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const path = resolve(directory, "artifact.json");
    await writeSbx056NoClobber(path, { safe: true });
    const metadata = await lstat(path);
    expect(metadata.mode & 0o777).toBe(0o600);
    expect(metadata.nlink).toBe(1);
    expect(JSON.parse(await readFile(path, "utf8"))).toEqual({ safe: true });
    await expect(writeSbx056NoClobber(path, { overwritten: true })).rejects.toMatchObject({ code: "EEXIST" });
    await rm(directory, { recursive: true });
  });

  it("recovers the crash window after atomic lock acquire but before any create-capable journal", async () => {
    const directory = resolve("artifacts", `SBX-056-prejournal-${process.pid}-${Date.now()}`);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const journalPath = resolve(directory, "recovery.json");
    const recovered = await recoverSbx056JournalAfterLock({ journalPath, runId: RUN,
      controlProjectId: CONTROL, victimProjectId: VICTIM });
    expect(recovered.preJournalZeroStateRecovered).toBe(true);
    expect(recovered.journal).toMatchObject({ completed: true,
      targets: [{ zeroExternalStateConfirmed: true }, { zeroExternalStateConfirmed: true }] });
    expect((await lstat(journalPath)).mode & 0o777).toBe(0o600);
    const reopened = await recoverSbx056JournalAfterLock({ journalPath, runId: RUN,
      controlProjectId: CONTROL, victimProjectId: VICTIM });
    expect(reopened.preJournalZeroStateRecovered).toBe(false);
    await expect(recoverSbx056JournalAfterLock({ journalPath, runId: RUN,
      controlProjectId: VICTIM, victimProjectId: CONTROL })).rejects.toThrow(/identity/u);
    await rm(directory, { recursive: true });
  });

  it("keeps artifact paths private and run-specific", () => {
    expect(sbx056ArtifactPath(RUN)).toMatch(new RegExp(`SBX-056-${RUN}-private\\.json$`, "u"));
  });

  it("keeps every finalization crash boundary restart-safe", async () => {
    const stages = ["checkpoint-written", "lock-released", "artifact-written",
      "checkpoint-removed", "journal-removed"] as const;
    for (const crashStage of stages) {
      const runId = randomUUID();
      const journal = createSbx056Journal(CONTROL, VICTIM, runId);
      journal.targets[0].zeroExternalStateConfirmed = true;
      journal.targets[1].zeroExternalStateConfirmed = true;
      journal.completed = true;
      const journalPath = sbx056JournalPath(runId);
      const checkpointPath = sbx056CheckpointPath(runId);
      const artifactPath = sbx056RecoveryArtifactPath(runId, randomUUID());
      await writeSbx056NoClobber(journalPath, journal);
      let released = false;
      const held = {
        runId,
        journalPath,
        checkpointPath,
        liveLock: { release: async () => { released = true; } },
      } as unknown as Parameters<typeof finalizeSbx056Safety>[0]["held"];
      await expect(finalizeSbx056Safety({ held, journal, checkpoint: { safe: true },
        finalArtifact: { safe: true }, artifactPath,
        mutationHook: (stage) => { if (stage === crashStage) throw new Error(`crash-${stage}`); } }))
        .rejects.toThrow(`crash-${crashStage}`);
      const journalStillExists = await lstat(journalPath).then(() => true).catch(() => false);
      const artifactExists = await lstat(artifactPath).then(() => true).catch(() => false);
      if (crashStage === "checkpoint-written") {
        expect(released).toBe(false);
        expect(journalStillExists).toBe(true);
      } else if (crashStage === "journal-removed") {
        expect(released).toBe(true);
        expect(journalStillExists).toBe(false);
        expect(artifactExists).toBe(true);
      } else {
        expect(released).toBe(true);
        expect(journalStillExists).toBe(true);
        expect(sbx056MayReacquireFinalizationLock(journal, true, true)).toBe(true);
      }
      await unlink(journalPath).catch(() => undefined);
      await unlink(checkpointPath).catch(() => undefined);
      await unlink(artifactPath).catch(() => undefined);
    }
    const runId = randomUUID();
    const journal = createSbx056Journal(CONTROL, VICTIM, runId);
    journal.targets[0].zeroExternalStateConfirmed = true;
    journal.targets[1].zeroExternalStateConfirmed = true;
    journal.completed = true;
    const journalPath = sbx056JournalPath(runId);
    const checkpointPath = sbx056CheckpointPath(runId);
    const artifactPath = sbx056RecoveryArtifactPath(runId, randomUUID());
    await writeSbx056NoClobber(journalPath, journal);
    await writeSbx056NoClobber(artifactPath, { occupied: true });
    const held = { runId, journalPath, checkpointPath,
      liveLock: { release: async () => undefined } } as unknown as
      Parameters<typeof finalizeSbx056Safety>[0]["held"];
    await expect(finalizeSbx056Safety({ held, journal, checkpoint: { safe: true },
      finalArtifact: { safe: true }, artifactPath })).rejects.toMatchObject({ code: "EEXIST" });
    expect(await lstat(journalPath)).toBeDefined();
    expect(sbx056MayReacquireFinalizationLock(journal, true, true)).toBe(true);
    expect(sbx056MayReacquireFinalizationLock(journal, false, true)).toBe(false);
    expect(sbx056MayReacquireFinalizationLock(journal, true, false)).toBe(false);
    await unlink(journalPath);
    await unlink(checkpointPath);
    await unlink(artifactPath);
  });
});
