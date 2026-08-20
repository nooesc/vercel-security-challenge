import { describe, expect, it } from "vitest";
import {
  requestOptions,
  validateConfiguration,
} from "../guest/sbx-058-header-binding-probe.mjs";

const runId = "123e4567-e89b-42d3-a456-426614174058";
const origin = "https://alpha-sbx058.trycloudflare.com";

function configuration(caseId: string, headerMode = caseId, targetRole = "A"): Record<string, unknown> {
  const canary = `s58_${caseId}_${"A".repeat(22)}`;
  const family = caseId.startsWith("direct-p-") ? "direct" : "request";
  return {
    scopeConfirmation: "researcher-controlled-sbx058-origins-only",
    testId: "SBX-058-HEADER-ENTRY-BINDING",
    runId,
    caseId,
    correlationCanary: canary,
    headerMode,
    targetRole,
    targetOrigin: origin,
    requestPath: `/v1/sbx058/${family}/${runId}/${caseId}?canary=${canary}`,
    timeoutMs: 4_000,
  };
}

describe("SBX-058 guest probe", () => {
  it.each([
    ["exact-pair", { "x-sbx058-route": "privileged" }],
    ["key-half", { "x-sbx058-route": "ordinary" }],
    ["value-half", { "x-sbx058-decoy": "privileged" }],
    ["combined-halves", { "x-sbx058-route": "ordinary", "x-sbx058-decoy": "privileged" }],
  ])("emits the exact %s header shape", (caseId, expected) => {
    const validated = validateConfiguration(configuration(caseId));
    const options = requestOptions(validated) as { headers: Record<string, string>; rejectUnauthorized: boolean };
    expect(options.headers).toMatchObject(expected);
    expect(options.headers["vercel-sandbox-oidc-token"]).toBeUndefined();
    expect(options.rejectUnauthorized).toBe(true);
  });

  it("emits no matcher header for direct-P controls", () => {
    const validated = validateConfiguration(configuration("direct-p-pre", "none", "P"));
    const options = requestOptions(validated) as { headers: Record<string, string> };
    expect(options.headers["x-sbx058-route"]).toBeUndefined();
    expect(options.headers["x-sbx058-decoy"]).toBeUndefined();
  });

  it.each([
    ["wrong header mode", { ...configuration("combined-halves"), headerMode: "exact-pair" }],
    ["direct target role", { ...configuration("direct-p-pre", "none", "P"), targetRole: "A" }],
    ["event target role", { ...configuration("key-half"), targetRole: "P" }],
    ["path", { ...configuration("key-half"), requestPath: "/wrong" }],
    ["origin", { ...configuration("key-half"), targetOrigin: "http://alpha-sbx058.trycloudflare.com" }],
    ["extra field", { ...configuration("key-half"), extra: true }],
  ])("rejects %s drift", (_label, value) => {
    expect(() => validateConfiguration(value)).toThrow();
  });
});
