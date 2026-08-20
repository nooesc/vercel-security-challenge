import { afterEach, describe, expect, it } from "vitest";
import {
  controlPlaneMutation,
  controlPlaneRead,
  createSbx048Receiver,
  requireStrictReceiverTlsEnvironment,
  validateConfiguration,
  type ReceiverConfiguration,
  type ReceiverHandle,
} from "../pocs/SBX-048/receiver.js";
import { SBX048_TEST_ID, type Sbx048OidcEvidence } from "../pocs/SBX-048/verdict.js";

const runId = "5b38a846-c6db-4fe1-a90e-4902e76fe213";
const origin = new URL("https://p.example.test");
const token = "eyJhbGciOiJSUzI1NiJ9.test.signature";

function configuration(): ReceiverConfiguration {
  return {
    runId,
    publicOrigin: origin.origin,
    forwardAudience: `${origin.origin}/v1/sbx048/forward/${runId}`,
    wrongAudience: `${origin.origin}/v1/sbx048/wrong-audience/${runId}`,
    sourceHostname: origin.hostname,
    sourcePath: `/v1/sbx048/source/${runId}`,
    expectedTeamId: "team_example",
    expectedProjectId: "prj_example",
    expectedSandboxId: "sbx_example",
    expectedSandboxName: "sbx-048-poc-example",
    correlationCanary: "c48_abcdefghijklmnopqrstuvwx",
    mutationEnabled: true,
  };
}

function rawForwardPolicy() {
  return {
    mode: "custom",
    allowedDomains: [origin.hostname],
    allowedCIDRs: [],
    deniedCIDRs: [],
    injectionRules: [],
    forwardRules: [{ domain: origin.hostname, forwardURL: configuration().forwardAudience }],
  };
}

function evidence(): Sbx048OidcEvidence {
  const config = configuration();
  return {
    verifier: "independent-jose",
    signatureVerified: true,
    algorithmRs256: true,
    issuerVerified: true,
    audienceVerified: true,
    temporalClaimsVerified: true,
    exactSourceIdentityVerified: true,
    wrongAudienceRejected: true,
    issuer: `https://oidc.vercel.com/${config.expectedTeamId}`,
    audience: config.forwardAudience,
    identity: {
      teamId: config.expectedTeamId,
      projectId: config.expectedProjectId,
      sandboxId: config.expectedSandboxId,
      sandboxName: config.expectedSandboxName,
    },
    ownerIdClaimPresent: false,
    teamIdClaimPresent: true,
    rawTokenRetained: false,
    rawTokenDigestRetained: false,
  };
}

describe("SBX-048 receiver configuration", () => {
  it("accepts only the exact owned origin, paths, identity, and explicit mutation gate", () => {
    expect(validateConfiguration(configuration(), origin)).toEqual(configuration());
    for (const mutation of [
      { ...configuration(), mutationEnabled: false },
      { ...configuration(), sourceHostname: "other.example.test" },
      { ...configuration(), forwardAudience: `${origin.origin}/other` },
      { ...configuration(), wrongAudience: configuration().forwardAudience },
      { ...configuration(), ca: "forbidden" },
    ]) expect(() => validateConfiguration(mutation, origin)).toThrow();
  });

  it("rejects local TLS trust overrides and runtime injection before binding", async () => {
    const mutations: Array<[string, string]> = [
      ["NODE_TLS_REJECT_UNAUTHORIZED", "0"],
      ["NODE_OPTIONS", "--require=/tmp/injected.cjs"],
      ["NODE_EXTRA_CA_CERTS", "/tmp/custom.pem"],
      ["NODE_USE_SYSTEM_CA", "1"],
      ["OPENSSL_CONF", "/tmp/openssl.cnf"],
      ["OPENSSL_MODULES", "/tmp/modules"],
      ["SSL_CERT_DIR", "/tmp/certs"],
      ["SSL_CERT_FILE", "/tmp/cert.pem"],
    ];
    for (const [name, value] of mutations) {
      expect(() => requireStrictReceiverTlsEnvironment({ [name]: value })).toThrow("TLS trust overrides");
      const previous = process.env[name];
      const wasPresent = Object.prototype.hasOwnProperty.call(process.env, name);
      process.env[name] = value;
      try {
        await expect(createSbx048Receiver({
          adminKey: "a".repeat(64),
          publicOrigin: origin.origin,
        })).rejects.toThrow("TLS trust overrides");
      } finally {
        if (wasPresent) process.env[name] = previous;
        else delete process.env[name];
      }
    }
  });
});

describe("SBX-048 raw control-plane attempts", () => {
  it("uses one exact bearer GET and retains no response or token material", async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const fakeFetch = (async (input: string | URL | globalThis.Request, init?: RequestInit) => {
      calls.push({ url: input.toString(), ...(init ? { init } : {}) });
      return Response.json({ session: { id: "sbx_example", networkPolicy: rawForwardPolicy() } }, { status: 200 });
    }) as typeof fetch;
    const result = await controlPlaneRead(fakeFetch, token, configuration(), "brokered-token-read");
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe("https://vercel.com/api/v2/sandboxes/sessions/sbx_example?teamId=team_example");
    expect(new Headers(calls[0]?.init?.headers).get("authorization")).toBe(`Bearer ${token}`);
    expect(result).toMatchObject({ statusCode: 200, exactSession: true, exactPolicy: true, policyShape: "legacy-raw-custom" });
    expect(JSON.stringify(result)).not.toContain(token);
  });

  it("gates the one mutation body to literal deny-all and validates the raw response", async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const fakeFetch = (async (input: string | URL | globalThis.Request, init?: RequestInit) => {
      calls.push({ url: input.toString(), ...(init ? { init } : {}) });
      return Response.json({ session: { id: "sbx_example", networkPolicy: { mode: "deny-all" } } }, { status: 200 });
    }) as typeof fetch;
    const result = await controlPlaneMutation(fakeFetch, token, configuration());
    expect(calls).toHaveLength(1);
    expect(calls[0]?.init?.method).toBe("POST");
    expect(calls[0]?.init?.body).toBe(JSON.stringify({ mode: "deny-all" }));
    expect(result).toMatchObject({ statusCode: 200, exactSession: true, exactPolicy: true, policyShape: "literal-mode" });
    expect(JSON.stringify(result)).not.toContain(token);
  });
});

describe("SBX-048 receiver sequencing", () => {
  let handle: ReceiverHandle | undefined;
  afterEach(async () => {
    await handle?.close();
    handle = undefined;
  });

  it("performs fake/read/mutation exactly once and exposes only sanitized evidence", async () => {
    const calls: Array<{ authorization: string | null; method: string }> = [];
    const fakeFetch = (async (_input: string | URL | globalThis.Request, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      calls.push({ authorization: headers.get("authorization"), method: init?.method ?? "GET" });
      if (headers.get("authorization")?.startsWith("Bearer sbx048-invalid-control-")) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      if (init?.method === "POST") {
        return Response.json({ session: { id: "sbx_example", networkPolicy: { mode: "deny-all" } } });
      }
      return Response.json({ session: { id: "sbx_example", networkPolicy: rawForwardPolicy() } });
    }) as typeof fetch;
    handle = await createSbx048Receiver({
      adminKey: "a".repeat(64),
      publicOrigin: origin.origin,
      fetchImpl: fakeFetch,
      verifyImpl: async (supplied) => ({ accepted: supplied === token, evidence: evidence() }),
    });
    const local = `http://127.0.0.1:${handle.port}`;
    const admin = `${local}/v1/sbx048/admin/runs/${runId}`;
    const auth = { authorization: `Bearer ${"a".repeat(64)}` };
    expect((await fetch(admin, {
      method: "POST",
      headers: { ...auth, "content-type": "application/json" },
      body: JSON.stringify(configuration()),
    })).status).toBe(201);

    const direct = await fetch(`${local}/v1/sbx048/source/${runId}`, {
      headers: {
        "x-sbx048-run": runId,
        "x-sbx048-case": "brokered-control-plane-probe",
        "x-sbx048-canary": configuration().correlationCanary,
      },
    });
    expect(direct.status).toBe(200);
    expect((await fetch(`${admin}/fake-control`, { method: "POST", headers: auth })).status).toBe(200);

    const forwarded = await fetch(`${local}/v1/sbx048/forward/${runId}/joined-path`, {
      headers: {
        "vercel-sandbox-oidc-token": token,
        "vercel-forwarded-host": origin.hostname,
        "vercel-forwarded-scheme": "https",
        "vercel-forwarded-port": "443",
        "vercel-forwarded-path": configuration().sourcePath,
        "x-sbx048-run": runId,
        "x-sbx048-case": "brokered-control-plane-probe",
        "x-sbx048-canary": configuration().correlationCanary,
      },
    });
    expect(forwarded.status).toBe(202);
    const responseBody = await forwarded.json() as Record<string, unknown>;
    expect(responseBody).toMatchObject({ authenticated: true, controlPlaneReadStatus: 200, mutationStatus: 200 });
    expect(calls).toHaveLength(3);
    expect(calls.map((entry) => entry.method)).toEqual(["GET", "GET", "POST"]);

    const readbackResponse = await fetch(admin, { headers: auth });
    const readbackText = await readbackResponse.text();
    expect(readbackText).not.toContain(token);
    const readback = JSON.parse(readbackText) as {
      directRecords: unknown[];
      records: Array<Record<string, unknown>>;
    };
    expect(readback.directRecords).toHaveLength(1);
    expect(readback.records).toHaveLength(1);
    expect(readback.records[0]).toMatchObject({
      testId: SBX048_TEST_ID,
      rawTokenRetained: false,
      rawTokenDigestRetained: false,
      controlPlaneRequestCounts: { fakeToken: 1, brokeredRead: 1, brokeredMutation: 1, total: 3 },
    });
  });

  it("never mutates when the one brokered read is rejected", async () => {
    const methods: string[] = [];
    const fakeFetch = (async (_input: string | URL | globalThis.Request, init?: RequestInit) => {
      methods.push(init?.method ?? "GET");
      return Response.json({ error: "forbidden" }, { status: 403 });
    }) as typeof fetch;
    handle = await createSbx048Receiver({
      adminKey: "b".repeat(64),
      publicOrigin: origin.origin,
      fetchImpl: fakeFetch,
      verifyImpl: async () => ({ accepted: true, evidence: evidence() }),
    });
    const local = `http://127.0.0.1:${handle.port}`;
    const admin = `${local}/v1/sbx048/admin/runs/${runId}`;
    const auth = { authorization: `Bearer ${"b".repeat(64)}` };
    await fetch(admin, {
      method: "POST",
      headers: { ...auth, "content-type": "application/json" },
      body: JSON.stringify(configuration()),
    });
    await fetch(`${admin}/fake-control`, { method: "POST", headers: auth });
    await fetch(`${local}/v1/sbx048/forward/${runId}`, {
      headers: {
        "vercel-sandbox-oidc-token": token,
        "vercel-forwarded-host": origin.hostname,
        "vercel-forwarded-scheme": "https",
        "vercel-forwarded-port": "443",
        "vercel-forwarded-path": configuration().sourcePath,
        "x-sbx048-run": runId,
        "x-sbx048-case": "brokered-control-plane-probe",
        "x-sbx048-canary": configuration().correlationCanary,
      },
    });
    expect(methods).toEqual(["GET", "GET"]);
    const readback = await (await fetch(admin, { headers: auth })).json() as { records: Array<Record<string, unknown>> };
    expect(readback.records[0]).toMatchObject({
      mutationAttemptedOnlyAfterExactRead: false,
      controlPlaneRequestCounts: { brokeredMutation: 0, total: 2 },
    });
    expect(readback.records[0]).not.toHaveProperty("brokeredMutation");
  });

  it("atomically consumes one concurrent brokered delivery before verification awaits", async () => {
    const methods: string[] = [];
    const fakeFetch = (async (_input: string | URL | globalThis.Request, init?: RequestInit) => {
      methods.push(init?.method ?? "GET");
      const authorization = new Headers(init?.headers).get("authorization");
      if (authorization?.startsWith("Bearer sbx048-invalid-control-")) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      if (init?.method === "POST") {
        return Response.json({ session: { id: "sbx_example", networkPolicy: { mode: "deny-all" } } });
      }
      return Response.json({ session: { id: "sbx_example", networkPolicy: rawForwardPolicy() } });
    }) as typeof fetch;
    let releaseVerification: (() => void) | undefined;
    const verificationGate = new Promise<void>((resolve) => {
      releaseVerification = resolve;
    });
    handle = await createSbx048Receiver({
      adminKey: "c".repeat(64),
      publicOrigin: origin.origin,
      fetchImpl: fakeFetch,
      verifyImpl: async () => {
        await verificationGate;
        return { accepted: true, evidence: evidence() };
      },
    });
    const local = `http://127.0.0.1:${handle.port}`;
    const admin = `${local}/v1/sbx048/admin/runs/${runId}`;
    const auth = { authorization: `Bearer ${"c".repeat(64)}` };
    await fetch(admin, {
      method: "POST",
      headers: { ...auth, "content-type": "application/json" },
      body: JSON.stringify(configuration()),
    });
    await fetch(`${admin}/fake-control`, { method: "POST", headers: auth });
    const headers = {
      "vercel-sandbox-oidc-token": token,
      "vercel-forwarded-host": origin.hostname,
      "vercel-forwarded-scheme": "https",
      "vercel-forwarded-port": "443",
      "vercel-forwarded-path": configuration().sourcePath,
      "x-sbx048-run": runId,
      "x-sbx048-case": "brokered-control-plane-probe",
      "x-sbx048-canary": configuration().correlationCanary,
    };
    const first = fetch(`${local}/v1/sbx048/forward/${runId}`, { headers });
    await new Promise<void>((resolve) => setTimeout(resolve, 10));
    const second = await fetch(`${local}/v1/sbx048/forward/${runId}`, { headers });
    expect(second.status).toBe(409);
    releaseVerification?.();
    expect((await first).status).toBe(202);
    expect(methods).toEqual(["GET", "GET", "POST"]);
    const readback = await (await fetch(admin, { headers: auth })).json() as { records: unknown[] };
    expect(readback.records).toHaveLength(1);
  });
});
