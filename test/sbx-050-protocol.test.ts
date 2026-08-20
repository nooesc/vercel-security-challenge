import { describe, expect, it } from "vitest";
import {
  commitmentMatches,
  expectedOperationId,
  requestPath,
  valueCommitment,
} from "../pocs/SBX-050/protocol.js";

const actionKey = "action-key-".padEnd(40, "a");
const otherKey = "other-key-".padEnd(40, "b");
const runId = "12345678-1234-4123-8123-123456789abc";
const canary = "c50_abcdefghijklmnopqrstuvwx";

describe("SBX-050 protocol", () => {
  it("binds opaque operations to role and every receipt fact", () => {
    const base = expectedOperationId(
      actionKey, "a.example.test", runId, "arm-without-trigger", canary, "A", true, true, false,
    );
    expect(base).toMatch(/^chain50_[A-Za-z0-9_-]{43}$/u);
    expect(expectedOperationId(
      actionKey, "p.example.test", runId, "arm-without-trigger", canary, "P", true, true, true,
    )).not.toBe(base);
    expect(expectedOperationId(
      otherKey, "a.example.test", runId, "arm-without-trigger", canary, "A", true, true, false,
    )).not.toBe(base);
  });

  it("uses keyed commitments and rejects a wrong key, value, or shape", () => {
    const credential = `s50_${"c".repeat(43)}`;
    const commitment = valueCommitment(actionKey, "credential", credential);
    expect(commitmentMatches(actionKey, "credential", credential, commitment)).toBe(true);
    expect(commitmentMatches(otherKey, "credential", credential, commitment)).toBe(false);
    expect(commitmentMatches(actionKey, "credential", `s50_${"d".repeat(43)}`, commitment)).toBe(false);
    expect(commitmentMatches(actionKey, "credential", "invalid", commitment)).toBe(false);
  });

  it("builds only the exact arm and plain paths", () => {
    expect(requestPath(runId, "arm-without-trigger", canary)).toBe(
      `/v1/sbx050/arm/${runId}?case=arm-without-trigger&canary=${canary}`,
    );
    expect(requestPath(runId, "final-plain-pre", canary)).toBe(
      `/v1/sbx050/request/${runId}/final-plain-pre?case=final-plain-pre&canary=${canary}`,
    );
  });
});
