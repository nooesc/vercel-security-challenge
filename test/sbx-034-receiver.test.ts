import { afterEach, describe, expect, it } from "vitest";
import { createSbx034Receiver, exactAudienceClaim } from "../pocs/SBX-034/receiver.js";
import {
  requestOptions,
  validateRedirectProbeConfig,
} from "../guest/forwardurl-redirect-probe.mjs";

const adminKey = "a".repeat(32);
const aOrigin = "https://a-owned.example.test";
const bOrigin = "https://b-owned.example.test";
const runId = "run-034-test";
const canary = "corr_test_034";

const handles: Array<{ close(): Promise<void> }> = [];

afterEach(async () => {
  await Promise.all(handles.splice(0).map(async (handle) => handle.close()));
});

function configuration() {
  const redirect = new URL(`/v1/sbx034/target/${runId}`, bOrigin);
  redirect.search = new URLSearchParams({ run: runId, case: "redirect-attack", canary }).toString();
  return {
    runId,
    originalHost: new URL(aOrigin).hostname,
    forwardAudience: new URL(`/v1/sbx034/forward/${runId}`, aOrigin).toString(),
    redirectUrl: redirect.toString(),
    expectedTeamId: "team_test",
    expectedProjectId: "project_test",
    expectedSandboxId: "sbx_test",
    expectedSandboxName: "sbx-034-test",
    correlationCanary: canary,
  };
}

describe("SBX-034 guest one-shot contract", () => {
  it("hard-codes manual redirect handling, one request, no retries, and verified TLS", () => {
    const parsed = validateRedirectProbeConfig({
      scopeConfirmation: "researcher-controlled-sbx034-origins-only",
      redirectMode: "manual",
      maxRedirects: 0,
      retryCount: 0,
      researcherControlledHosts: ["a-owned.example.test", "b-owned.example.test"],
      runId,
      testId: "SBX-034-POC",
      caseId: "redirect-attack",
      correlationId: canary,
      destinationHost: "a-owned.example.test",
      destinationPort: 443,
      tlsServername: "a-owned.example.test",
      httpHost: "a-owned.example.test",
      path: `/v1/sbx034/original/${runId}/redirect-attack`,
      headers: { "x-sbx034-case": "redirect-attack" },
      timeoutMs: 5_000,
    });
    const options = requestOptions(parsed);
    expect(options).toMatchObject({
      agent: false,
      rejectUnauthorized: true,
      method: "GET",
      servername: "a-owned.example.test",
    });
    expect(options).not.toHaveProperty("maxRedirects");
  });

  it.each([
    { redirectMode: "follow", maxRedirects: 0, retryCount: 0 },
    { redirectMode: "manual", maxRedirects: 1, retryCount: 0 },
    { redirectMode: "manual", maxRedirects: 0, retryCount: 1 },
  ])("rejects unsafe redirect/retry configuration %#", (override) => {
    expect(() => validateRedirectProbeConfig({
      scopeConfirmation: "researcher-controlled-sbx034-origins-only",
      researcherControlledHosts: ["a-owned.example.test", "b-owned.example.test"],
      runId,
      testId: "SBX-034-POC",
      caseId: "redirect-attack",
      correlationId: canary,
      destinationHost: "a-owned.example.test",
      tlsServername: "a-owned.example.test",
      httpHost: "a-owned.example.test",
      path: "/probe",
      ...override,
    })).toThrow();
  });
});

describe("SBX-034 two-role receiver", () => {
  it("rejects additional JWT audiences instead of treating membership as exact", () => {
    const expected = "https://a-owned.example.test/v1/sbx034/forward/run";
    expect(exactAudienceClaim(expected, expected)).toBe(true);
    expect(exactAudienceClaim([expected], expected)).toBe(true);
    expect(exactAudienceClaim([expected, "https://other.example.test/"], expected)).toBe(false);
    expect(exactAudienceClaim("https://other.example.test/", expected)).toBe(false);
  });

  it("records bare/invalid destination activity without ever treating it as verified OIDC", async () => {
    const receiver = await createSbx034Receiver({ adminKey, aPublicOrigin: aOrigin, bPublicOrigin: bOrigin });
    handles.push(receiver);
    const aLocal = `http://127.0.0.1:${receiver.aPort}`;
    const bLocal = `http://127.0.0.1:${receiver.bPort}`;
    const adminUrl = `${aLocal}/v1/sbx034/admin/runs/${runId}`;
    const auth = { Authorization: `Bearer ${adminKey}` };

    const registration = await fetch(adminUrl, {
      method: "POST",
      headers: { ...auth, "Content-Type": "application/json" },
      body: JSON.stringify(configuration()),
    });
    expect(registration.status).toBe(201);

    const direct = await fetch(
      `${bLocal}/v1/sbx034/direct/${runId}?${new URLSearchParams({ case: "direct-b-allow", canary })}`,
    );
    expect(direct.status).toBe(204);

    const fakeToken = "not.a.valid-platform-token";
    const target = await fetch(
      `${bLocal}/v1/sbx034/target/${runId}?${new URLSearchParams({ run: runId, case: "redirect-attack", canary })}`,
      { headers: { "vercel-sandbox-oidc-token": fakeToken } },
    );
    expect(target.status).toBe(401);

    const readback = await fetch(adminUrl, { headers: auth });
    const body = await readback.text();
    expect(body).not.toContain(fakeToken);
    const parsed = JSON.parse(body) as {
      directRecords: unknown[];
      bRecords: Array<{ tokenVerified: boolean; oidcVerifications: unknown[] }>;
    };
    expect(parsed.directRecords).toHaveLength(1);
    expect(parsed.bRecords).toHaveLength(1);
    expect(parsed.bRecords[0]).toMatchObject({ tokenVerified: false, oidcVerifications: [] });
  });

  it("uses the official proxy verifier at A and records a missing-token request as unauthenticated", async () => {
    const receiver = await createSbx034Receiver({ adminKey, aPublicOrigin: aOrigin, bPublicOrigin: bOrigin });
    handles.push(receiver);
    const aLocal = `http://127.0.0.1:${receiver.aPort}`;
    const adminUrl = `${aLocal}/v1/sbx034/admin/runs/${runId}`;
    const auth = { Authorization: `Bearer ${adminKey}` };
    await fetch(adminUrl, {
      method: "POST",
      headers: { ...auth, "Content-Type": "application/json" },
      body: JSON.stringify(configuration()),
    });
    const response = await fetch(`${aLocal}/v1/sbx034/forward/${runId}/original`, {
      headers: { "x-sbx034-case": "redirect-attack", "x-sbx-harness-canary": canary },
    });
    expect(response.status).toBe(403);
    const readback = await fetch(adminUrl, { headers: auth });
    const body = await readback.text();
    expect(body).not.toContain(OIDC_PLACEHOLDER);
    const parsed = JSON.parse(body) as { aRecords: Array<{ authenticated: boolean; oidcHeaderCount: number }> };
    expect(parsed.aRecords).toEqual([
      expect.objectContaining({ authenticated: false, oidcHeaderCount: 0 }),
    ]);
  });
});

const OIDC_PLACEHOLDER = "vercel-sandbox-oidc-token-value-never-present";
