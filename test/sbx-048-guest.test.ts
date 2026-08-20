import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  requestOptions,
  runProbe,
  validateConfiguration,
} from "../guest/sbx-048-forward-probe.mjs";

const runId = "5b38a846-c6db-4fe1-a90e-4902e76fe213";

function configuration() {
  return {
    scopeConfirmation: "researcher-controlled-sbx048-origin-only" as const,
    runId,
    testId: "SBX-048-OIDC-CONTROL-PLANE-CONFUSION" as const,
    caseId: "brokered-control-plane-probe" as const,
    correlationCanary: "c48_abcdefghijklmnopqrstuvwx",
    expectedMode: "forward" as const,
    publicOrigin: "https://p.example.test",
    sourcePath: `/v1/sbx048/source/${runId}`,
    timeoutMs: 5_000,
  };
}

const originalTlsDisable = process.env.NODE_TLS_REJECT_UNAUTHORIZED;

afterEach(() => {
  if (originalTlsDisable === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = originalTlsDisable;
});

describe("SBX-048 guest probe", () => {
  it("accepts one exact owned HTTPS request and has no configurable trust or proxy knobs", () => {
    const validated = validateConfiguration(configuration());
    expect(validated.hostname).toBe("p.example.test");
    const options = requestOptions(validated);
    expect(options).toMatchObject({
      hostname: "p.example.test",
      servername: "p.example.test",
      method: "GET",
      path: `/v1/sbx048/source/${runId}`,
      rejectUnauthorized: true,
      agent: false,
    });
    expect(options).not.toHaveProperty("ca");
    expect(options).not.toHaveProperty("secureContext");
    expect(options).not.toHaveProperty("checkServerIdentity");
  });

  it("rejects extra fields and every target/origin/trust mutation", () => {
    for (const value of [
      { ...configuration(), publicOrigin: "http://p.example.test" },
      { ...configuration(), publicOrigin: "https://p.example.test/path" },
      { ...configuration(), sourcePath: "/other" },
      { ...configuration(), expectedMode: "other" },
      { ...configuration(), ca: "forbidden" },
      { ...configuration(), checkServerIdentity: "forbidden" },
    ]) expect(() => validateConfiguration(value)).toThrow();
  });

  it("fails before networking when Node globally disables TLS verification", async () => {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    await expect(runProbe(configuration())).rejects.toThrow("NODE_TLS_REJECT_UNAUTHORIZED=0 is forbidden");
  });

  it("ships no custom CA, secure-context, proxy, retry, redirect, or token handling", () => {
    const source = readFileSync(resolve("guest/sbx-048-forward-probe.mjs"), "utf8");
    expect(source).not.toMatch(/\bca\s*:/u);
    expect(source).not.toMatch(/secureContext\s*:/u);
    expect(source).not.toMatch(/checkServerIdentity\s*:/u);
    expect(source).not.toContain("vercel-sandbox-oidc-token");
    expect(source).not.toContain("HTTP_PROXY");
    expect(source).not.toContain("HTTPS_PROXY");
  });
});
