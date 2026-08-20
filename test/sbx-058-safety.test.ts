import { describe, expect, it } from "vitest";
import {
  SBX058_ALIAS,
  SBX058_PROJECT,
  SBX058_SCOPE_CONFIRMATION,
  SBX058_TEAM,
  SBX058_UNKNOWN_CREATE_SETTLEMENT_MS,
  createSbx058Journal,
  loadSbx058Config,
  markSbx058AbsenceOnlyTerminal,
  parseSbx058Journal,
  sbx058UnknownCreateSettled,
} from "../pocs/SBX-058/safety.js";

const runId = "123e4567-e89b-42d3-a456-426614174058";

function environment(): NodeJS.ProcessEnv {
  return {
    SBX058_SCOPE_CONFIRMATION: SBX058_SCOPE_CONFIRMATION,
    SBX058_ALIAS_EMAIL_CONFIRMATION: SBX058_ALIAS,
    VERCEL_TEAM_ID: SBX058_TEAM,
    VERCEL_PROJECT_ID: SBX058_PROJECT,
    VERCEL_TOKEN: "vcp_" + "T".repeat(40),
    SBX058_ADMIN_KEY: "A".repeat(32),
    SBX058_ACTION_KEY: "B".repeat(32),
    SBX058_A_PUBLIC_ORIGIN: "https://a-sbx058.trycloudflare.com",
    SBX058_P_PUBLIC_ORIGIN: "https://p-sbx058.trycloudflare.com",
  };
}

describe("SBX-058 safety", () => {
  it("loads only exact eligible, distinct-origin configuration", () => {
    const value = loadSbx058Config(environment());
    expect(value).toMatchObject({ teamId: SBX058_TEAM, projectId: SBX058_PROJECT });
    expect(value.aOrigin.origin).not.toBe(value.pOrigin.origin);
  });

  it.each([
    ["scope", { SBX058_SCOPE_CONFIRMATION: "wrong" }],
    ["alias", { SBX058_ALIAS_EMAIL_CONFIRMATION: "other@example.test" }],
    ["same keys", { SBX058_ACTION_KEY: "A".repeat(32) }],
    ["same origins", { SBX058_P_PUBLIC_ORIGIN: "https://a-sbx058.trycloudflare.com" }],
    ["TLS override", { NODE_TLS_REJECT_UNAUTHORIZED: "0" }],
    ["runtime override", { NODE_OPTIONS: "--require=x" }],
  ])("rejects %s drift", (_label, mutation) => {
    expect(() => loadSbx058Config({ ...environment(), ...mutation })).toThrow();
  });

  it("round-trips the exact pre-create journal", () => {
    const journal = createSbx058Journal(runId, new Date("2026-08-19T12:00:00.000Z"));
    expect(parseSbx058Journal(JSON.parse(JSON.stringify(journal)))).toEqual(journal);
  });

  it("permits a completed zero-external-state recovery only before create", () => {
    const journal = createSbx058Journal(runId);
    journal.zeroExternalStateConfirmed = true;
    journal.receiverDeleted = true;
    journal.completed = true;
    expect(parseSbx058Journal(journal).completed).toBe(true);
    expect(() => parseSbx058Journal({ ...journal, createAttemptedAt: new Date().toISOString() })).toThrow();
  });

  it("keeps unknown create unsettled until the full expiry horizon", () => {
    const journal = createSbx058Journal(runId);
    const start = Date.parse("2026-08-19T12:00:00.000Z");
    journal.createAttemptedAt = new Date(start).toISOString();
    expect(sbx058UnknownCreateSettled(journal, start + SBX058_UNKNOWN_CREATE_SETTLEMENT_MS - 1)).toBe(false);
    expect(sbx058UnknownCreateSettled(journal, start + SBX058_UNKNOWN_CREATE_SETTLEMENT_MS)).toBe(true);
  });

  it.each([undefined, "sbx_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"])(
    "accepts exact absence-only terminal recovery with session %s without inventing a delete attempt",
    (sessionId) => {
      const journal = createSbx058Journal(runId);
      journal.createAttemptedAt = "2026-08-19T12:00:00.000Z";
      if (sessionId) {
        journal.sessionId = sessionId;
        journal.provenanceValidated = true;
      }
      journal.absenceChecks = 3;
      journal.prefixAbsent = true;
      markSbx058AbsenceOnlyTerminal(journal);
      journal.receiverDeleted = true;
      journal.completed = true;
      expect(parseSbx058Journal(journal)).toMatchObject({
        deleteAttempted: false,
        absenceOnlyValidated: true,
        deleted: true,
        completed: true,
      });
    },
  );

  it("rejects completed state without exact cleanup or zero-state proof", () => {
    const journal = createSbx058Journal(runId);
    journal.completed = true;
    expect(() => parseSbx058Journal(journal)).toThrow();
  });

  it("finalizes a stopped nonpersistent journal after DELETE error absence proof", () => {
    const journal = createSbx058Journal(runId);
    journal.createAttemptedAt = "2026-08-19T12:00:00.000Z";
    journal.sessionId = "sbx_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
    journal.provenanceValidated = true;
    journal.stopAttempted = true;
    journal.stopped = true;
    journal.deleteAttempted = true;
    journal.absenceChecks = 3;
    journal.prefixAbsent = true;
    markSbx058AbsenceOnlyTerminal(journal);
    expect(parseSbx058Journal(journal)).toMatchObject({
      stopped: true,
      deleteAttempted: true,
      absenceOnlyValidated: true,
      deleted: true,
    });
  });
});
