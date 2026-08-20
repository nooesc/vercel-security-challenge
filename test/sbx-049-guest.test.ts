import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { validateConfiguration } from "../guest/query-entry-binding-probe.mjs";

const base = {
  scopeConfirmation: "researcher-controlled-sbx049-origin-only",
  testId: "SBX-049-POC",
  runId: "12345678-1234-4123-8123-123456789abc",
  canary: "c49_abcdefghijklmnopqrstuvwx",
  origin: "https://owned.example/",
  timeoutMs: 8000,
};

describe("SBX-049 guest", () => {
  it("accepts only the exact decisive combined-halves request", () => {
    const caseId = "combined-halves";
    const url = `${base.origin}v1/sbx049/action?run=${base.runId}&case=${caseId}&canary=${base.canary}&role=user&decoy=privileged`;
    expect(validateConfiguration({ ...base, caseId, url }).url.toString()).toBe(url);
    expect(() => validateConfiguration({
      ...base,
      caseId,
      url: url.replace("role=user", "role=privileged"),
    })).toThrow(/exact controlled action URL/u);
  });

  it("rejects extra controller fields and non-HTTPS origins", () => {
    const caseId = "key-half";
    const url = `${base.origin}v1/sbx049/action?run=${base.runId}&case=${caseId}&canary=${base.canary}&role=user`;
    expect(() => validateConfiguration({ ...base, caseId, url, headers: {} })).toThrow(/fields are not exact/u);
    expect(() => validateConfiguration({
      ...base,
      origin: "http://owned.example/",
      caseId,
      url: url.replace("https:", "http:"),
    })).toThrow(/HTTPS origin/u);
  });

  it("contains no transform-header name or controller secret channel", async () => {
    const source = await readFile("guest/query-entry-binding-probe.mjs", "utf8");
    expect(source).not.toContain("x-sbx049-brokered-secret");
    expect(source).not.toContain("SBX049_ACTION_KEY");
    expect(source).not.toContain("SBX049_ADMIN_KEY");
  });
});
