import { describe, expect, it } from "vitest";
import { validateConfiguration } from "../guest/wildcard-label-probe.mjs";

const runId = "11111111-2222-4333-8444-555555555555";
const canary = `c44_${"x".repeat(24)}`;

function configuration(overrides: Record<string, unknown> = {}) {
  return {
    scopeConfirmation: "researcher-controlled-sbx044-origins-only",
    testId: "SBX-044-POC",
    runId,
    caseId: "public-allowed-pre",
    canary,
    expectedRole: "allowed",
    researcherControlledHosts: ["s44a.one.form-app.app", "s44a.one.two.form-app.app"],
    url: `https://s44a.one.form-app.app/v1/sbx044/action?run=${runId}&case=public-allowed-pre&canary=${canary}`,
    timeoutMs: 8_000,
    ...overrides,
  };
}

describe("SBX-044 guest configuration", () => {
  it("accepts only the fixed A/B host and role mapping", () => {
    expect(validateConfiguration(configuration()).url.hostname).toBe("s44a.one.form-app.app");
    expect(() => validateConfiguration(configuration({
      researcherControlledHosts: ["attacker.invalid", "s44a.one.two.form-app.app"],
      url: `https://attacker.invalid/v1/sbx044/action?run=${runId}&case=public-allowed-pre&canary=${canary}`,
    }))).toThrow(/exact fixed SBX-044 A\/B pair/u);
    expect(() => validateConfiguration(configuration({ expectedRole: "denied" }))).toThrow(/role map/u);
  });

  it("rejects path, correlation, header, and TLS trust overrides", () => {
    expect(() => validateConfiguration(configuration({
      url: `https://s44a.one.form-app.app/other?run=${runId}&case=public-allowed-pre&canary=${canary}`,
    }))).toThrow(/fixed HTTPS action path/u);
    expect(() => validateConfiguration(configuration({ caseId: "different" }))).toThrow(/correlation/u);
    expect(() => validateConfiguration(configuration({ headers: { x: "y" } }))).toThrow(/forbidden/u);
    expect(() => validateConfiguration(configuration({ ca: "certificate" }))).toThrow(/forbidden/u);
    expect(() => validateConfiguration(configuration({ secureContext: {} }))).toThrow(/forbidden/u);
  });

  it("fails closed when global TLS verification is disabled", () => {
    const previous = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    try { expect(() => validateConfiguration(configuration())).toThrow(/NODE_TLS_REJECT_UNAUTHORIZED/u); }
    finally {
      if (previous === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
      else process.env.NODE_TLS_REJECT_UNAUTHORIZED = previous;
    }
  });
});
