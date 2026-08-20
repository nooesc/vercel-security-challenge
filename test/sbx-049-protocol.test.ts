import { describe, expect, it } from "vitest";
import {
  commitmentMatches,
  expectedOperationId,
  queryForCase,
  secretCommitment,
  SBX049_CASES,
} from "../pocs/SBX-049/protocol.js";

const runId = "12345678-1234-4123-8123-123456789abc";
const canary = "c49_abcdefghijklmnopqrstuvwx";
const key = "a".repeat(32);
const secret = `s49_${"b".repeat(43)}`;

describe("SBX-049 protocol", () => {
  it("generates the exact four association matrix queries", () => {
    expect(SBX049_CASES.map((caseId) => queryForCase(runId, caseId, canary))).toEqual([
      `run=${runId}&case=exact-pair&canary=${canary}&role=privileged`,
      `run=${runId}&case=key-half&canary=${canary}&role=user`,
      `run=${runId}&case=value-half&canary=${canary}&decoy=privileged`,
      `run=${runId}&case=combined-halves&canary=${canary}&role=user&decoy=privileged`,
    ]);
  });

  it("domain-separates reachability and secret operation proofs", () => {
    const reach = expectedOperationId(key, "owned.example", runId, "combined-halves", canary);
    const brokered = expectedOperationId(key, "owned.example", runId, "combined-halves", canary, secret);
    expect(reach).toMatch(/^q49r_/u);
    expect(brokered).toMatch(/^q49s_/u);
    expect(reach).not.toBe(brokered);
  });

  it("validates the secret only through a keyed commitment", () => {
    const commitment = secretCommitment(key, secret);
    expect(commitmentMatches(key, secret, commitment)).toBe(true);
    expect(commitmentMatches(key, `s49_${"c".repeat(43)}`, commitment)).toBe(false);
  });
});
