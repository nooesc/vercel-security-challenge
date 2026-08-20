import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  requestOptions,
  runProbe,
  validateConfiguration,
} from "../guest/sbx-050-action-chain-probe.mjs";

const runId = "12345678-1234-4123-8123-123456789abc";
const canary = "c50_abcdefghijklmnopqrstuvwx";
const originalTlsDisable = process.env.NODE_TLS_REJECT_UNAUTHORIZED;

function configuration(caseId = "arm-without-trigger", targetOrigin = "https://a.example.test") {
  const pathname = caseId === "arm-without-trigger" || caseId === "transform-alone-control"
    ? `/v1/sbx050/arm/${runId}`
    : `/v1/sbx050/request/${runId}/${caseId}`;
  return {
    scopeConfirmation: "researcher-controlled-sbx050-origins-only",
    testId: "SBX-050-POC",
    runId,
    caseId,
    correlationCanary: canary,
    targetOrigin,
    requestPath: `${pathname}?${new URLSearchParams({ case: caseId, canary }).toString()}`,
    sendPublicTrigger: caseId === "public-forward-control",
    timeoutMs: 5_000,
  };
}

afterEach(() => {
  if (originalTlsDisable === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = originalTlsDisable;
});

describe("SBX-050 guest probe", () => {
  it("omits both hidden headers on the decisive request", () => {
    const validated = validateConfiguration(configuration());
    const options = requestOptions(validated);
    expect(options).toMatchObject({
      hostname: "a.example.test",
      servername: "a.example.test",
      path: configuration().requestPath,
      rejectUnauthorized: true,
      agent: false,
    });
    const headers = Object.fromEntries(Object.entries(options.headers).map(([key, value]) => [key.toLowerCase(), value]));
    expect(headers["x-sbx050-run"]).toBe(runId);
    expect(headers).not.toHaveProperty("x-sbx050-brokered-credential");
    expect(headers).not.toHaveProperty("x-sbx050-route-trigger");
  });

  it("sends only the disposable public trigger in phase 1", () => {
    const options = requestOptions(validateConfiguration(configuration("public-forward-control")));
    expect(options.headers).toMatchObject({
      "x-sbx050-route-trigger": "sbx050-public-forward-control",
    });
    expect(options.headers).not.toHaveProperty("x-sbx050-brokered-credential");
  });

  it("rejects hidden-value shapes, extra fields, path drift, and non-HTTPS targets", () => {
    expect(() => validateConfiguration({ ...configuration(), hiddenTrigger: `t50_${"x".repeat(32)}` })).toThrow();
    expect(() => validateConfiguration({ ...configuration(), requestPath: "/wrong" })).toThrow(/requestPath/u);
    expect(() => validateConfiguration(configuration("arm-without-trigger", "http://a.example.test"))).toThrow(/HTTPS/u);
    expect(() => validateConfiguration({
      ...configuration(), correlationCanary: `c50_${"s50_"}${"x".repeat(20)}`,
    })).toThrow();
  });

  it("rejects a public-trigger request in any non-public phase", () => {
    expect(() => validateConfiguration({ ...configuration(), sendPublicTrigger: true })).toThrow();
  });

  it("fails before networking when TLS verification is globally disabled", async () => {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    await expect(runProbe(configuration())).rejects.toThrow(/unsafe guest trust/u);
  });

  it("ships no configurable CA, proxy, retry, redirect, OIDC, or secret value", () => {
    const source = readFileSync(resolve("guest/sbx-050-action-chain-probe.mjs"), "utf8");
    expect(source).not.toMatch(/\bca\s*:/u);
    expect(source).not.toMatch(/secureContext\s*:/u);
    expect(source).not.toMatch(/checkServerIdentity\s*:/u);
    expect(source).not.toContain("vercel-sandbox-oidc-token");
    expect(source).not.toContain("HTTP_PROXY");
    expect(source).not.toContain("HTTPS_PROXY");
    expect(source).not.toMatch(/s50_[A-Za-z0-9_-]{43}/u);
    expect(source).not.toMatch(/t50_[A-Za-z0-9_-]{32}/u);
  });
});
