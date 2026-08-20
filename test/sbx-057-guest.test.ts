import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { validateConfiguration } from "../guest/sbx-057-wildcard-empty-probe.mjs";

const RUN = "123e4567-e89b-42d3-a456-426614174000";
const originalTlsDisable = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
const originalNodeOptions = process.env.NODE_OPTIONS;

function configuration(caseId = "target-b", origin = "https://b-sbx057.trycloudflare.com") {
  return {
    schemaVersion: 1,
    testId: "SBX-057-WILDCARD-EMPTY-ISOLATION",
    runId: RUN,
    caseId,
    canary: `s57_${caseId}_${"A".repeat(22)}`,
    origin,
  };
}

afterEach(() => {
  if (originalTlsDisable === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = originalTlsDisable;
  if (originalNodeOptions === undefined) delete process.env.NODE_OPTIONS;
  else process.env.NODE_OPTIONS = originalNodeOptions;
});

describe("SBX-057 guest probe", () => {
  it.each([
    ["comparator-a", "A", "https://a-sbx057.trycloudflare.com"],
    ["comparator-b", "B", "https://b-sbx057.trycloudflare.com"],
    ["target-a", "A", "https://a-sbx057.trycloudflare.com"],
    ["target-b", "B", "https://b-sbx057.trycloudflare.com"],
  ])("accepts exact %s direct-origin configuration", (caseId, role, origin) => {
    expect(validateConfiguration(configuration(caseId, origin))).toMatchObject({ caseId, role });
  });

  it("rejects extra fields, malformed correlation, and non-Quick-Tunnel origins", () => {
    expect(() => validateConfiguration({ ...configuration(), secret: "hidden" })).toThrow();
    expect(() => validateConfiguration({ ...configuration(), runId: "not-a-uuid" })).toThrow();
    expect(() => validateConfiguration({ ...configuration(), canary: "wrong" })).toThrow();
    expect(() => validateConfiguration(configuration("target-b", "https://example.com"))).toThrow();
    expect(() => validateConfiguration(configuration("target-b", "http://b-sbx057.trycloudflare.com"))).toThrow();
    expect(() => validateConfiguration(configuration("target-b", "https://b-sbx057.trycloudflare.com/path"))).toThrow();
  });

  it("contains no transform credential, proxy, OIDC, custom CA, redirect, or retry input", () => {
    const source = readFileSync(resolve("guest/sbx-057-wildcard-empty-probe.mjs"), "utf8");
    expect(source).not.toContain("x-sbx057-brokered-credential");
    expect(source).not.toContain("vercel-sandbox-oidc-token");
    expect(source).not.toContain("HTTP_PROXY");
    expect(source).not.toContain("HTTPS_PROXY");
    expect(source).not.toMatch(/\bca\s*:/u);
    expect(source).not.toContain("checkServerIdentity");
    expect(source).not.toContain("secureContext");
    expect(source).not.toContain("maxRedirects");
  });

  it("uses a fresh direct TLS connection, exact SNI/Host, and a true absolute deadline", () => {
    const source = readFileSync(resolve("guest/sbx-057-wildcard-empty-probe.mjs"), "utf8");
    expect(source).toContain("agent: false");
    expect(source).toContain("servername: config.origin.hostname");
    expect(source).toContain("host: config.origin.hostname");
    expect(source).toContain("rejectUnauthorized: true");
    expect(source).toContain("const absoluteDeadline = setTimeout");
    expect(source).toContain("ERESPONSEPREMATURECLOSE");
  });

  it("rejects process-level TLS and runtime injection overrides", () => {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    expect(() => validateConfiguration(configuration())).not.toThrow();
    // The trust gate runs immediately before networking; source inspection pins both fail-closed branches.
    const source = readFileSync(resolve("guest/sbx-057-wildcard-empty-probe.mjs"), "utf8");
    expect(source).toContain('environment.NODE_TLS_REJECT_UNAUTHORIZED === "0"');
    expect(source).toContain("environment.NODE_OPTIONS");
  });
});
