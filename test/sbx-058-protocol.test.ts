import { describe, expect, it } from "vitest";
import {
  expectedOperationId,
  expectedReceipt,
  headerModeForCase,
  proxyAudience,
  requestPath,
  safeEqual,
} from "../pocs/SBX-058/protocol.js";

const key = "K".repeat(32);
const runId = "123e4567-e89b-42d3-a456-426614174058";
const canary = `s58_exact-pair_${"A".repeat(22)}`;

describe("SBX-058 protocol", () => {
  it("frames role and header association into distinct operation IDs", () => {
    const a = expectedOperationId(key, runId, "exact-pair", canary, "A", 1, 0, true, false, false);
    const p = expectedOperationId(key, runId, "exact-pair", canary, "P", 1, 0, true, false, true);
    expect(a).not.toBe(p);
    expect(safeEqual(a, a)).toBe(true);
    expect(safeEqual(a, p)).toBe(false);
  });

  it("binds receipts to ordinal, role, and operation", () => {
    const operation = expectedOperationId(key, runId, "exact-pair", canary, "P", 1, 0, true, false, true);
    const receipt = expectedReceipt(key, runId, 1, "exact-pair", canary, "P", operation);
    expect(receipt).toMatch(/^s58rcpt_/u);
    expect(expectedReceipt(key, runId, 2, "exact-pair", canary, "P", operation)).not.toBe(receipt);
  });

  it("constructs canonical paths and proxy audience", () => {
    expect(requestPath(runId, "exact-pair", canary)).toContain("/request/");
    expect(proxyAudience("https://proxy.example.test", runId)).toBe(
      `https://proxy.example.test/v1/sbx058/proxy/${runId}`,
    );
    expect(headerModeForCase("direct-p-post")).toBe("none");
  });
});
