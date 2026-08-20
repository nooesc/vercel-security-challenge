import http from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import {
  createSbx058Receiver,
  exactProxyAttribution,
  receiverRuntimeAttestation,
  validateReceiverConfiguration,
  type Sbx058ReceiverHandle,
} from "../pocs/SBX-058/receiver.js";
import { proxyAudience, requestPath } from "../pocs/SBX-058/protocol.js";

const runId = "123e4567-e89b-42d3-a456-426614174058";
const A = new URL("https://a-sbx058.trycloudflare.com");
const P = new URL("https://p-sbx058.trycloudflare.com");
const adminKey = "A".repeat(32);
const actionKey = "B".repeat(32);
const cases = ["exact-pair", "key-half", "value-half", "combined-halves"] as const;

function canary(caseId: string): string {
  return `s58_${caseId}_${"C".repeat(22)}`;
}

function configuration(): Record<string, unknown> {
  return {
    runId,
    aHostname: A.hostname,
    forwardAudience: proxyAudience(P, runId),
    expectedTeamId: "team_example123",
    expectedProjectId: "prj_example123",
    expectedSessionId: "sbx_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
    expectedSandboxName: `sbx-058-${runId}`,
    cases: cases.map((caseId) => ({ caseId, canary: canary(caseId), requestPath: requestPath(runId, caseId, canary(caseId)) })),
  };
}

async function rawRequest(port: number, options: {
  method?: string;
  path: string;
  headers?: Record<string, string>;
  body?: string;
}): Promise<{ status: number; body: string }> {
  return await new Promise((resolve, reject) => {
    const request = http.request({
      hostname: "127.0.0.1",
      port,
      method: options.method ?? "GET",
      path: options.path,
      headers: options.headers,
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      response.on("end", () => resolve({
        status: response.statusCode ?? 0,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    request.once("error", reject);
    if (options.body) request.write(options.body);
    request.end();
  });
}

describe("SBX-058 receiver", () => {
  let handle: Sbx058ReceiverHandle | undefined;
  afterEach(async () => { await handle?.close(); handle = undefined; });

  it("validates an exact ordered receiver configuration", () => {
    expect(validateReceiverConfiguration(configuration(), runId, A, P).cases.map((entry) => entry.caseId)).toEqual(cases);
    expect(() => validateReceiverConfiguration({ ...configuration(), extra: true }, runId, A, P)).toThrow();
  });

  it("requires a clean receiver trust environment", () => {
    expect(receiverRuntimeAttestation({})).toMatchObject({ receiverRuntimeTrustExact: true });
    expect(() => receiverRuntimeAttestation({ NODE_TLS_REJECT_UNAUTHORIZED: "0" })).toThrow();
    expect(() => receiverRuntimeAttestation({ NODE_EXTRA_CA_CERTS: "/tmp/ca.pem" })).toThrow();
  });

  it("records exact header line/value facts and counts correlated wrong-path ingress", async () => {
    handle = await createSbx058Receiver({
      adminKey,
      actionKey,
      aPublicOrigin: A.origin,
      pPublicOrigin: P.origin,
      aPort: 0,
      pPort: 0,
    });
    const adminPath = `/v1/sbx058/admin/runs/${runId}`;
    const configured = await rawRequest(handle.aPort, {
      method: "PUT",
      path: adminPath,
      headers: { authorization: `Bearer ${adminKey}`, "content-type": "application/json" },
      body: JSON.stringify(configuration()),
    });
    expect(configured.status).toBe(201);
    expect((await rawRequest(handle.aPort, {
      path: adminPath,
      headers: { authorization: `Bearer ${adminKey}` },
    })).status).toBe(200);
    const caseId = "exact-pair";
    const probe = await rawRequest(handle.aPort, {
      path: requestPath(runId, caseId, canary(caseId)),
      headers: {
        host: A.hostname,
        "x-sbx058-run": runId,
        "x-sbx058-case": caseId,
        "x-sbx058-canary": canary(caseId),
        "x-sbx058-route": "privileged",
      },
    });
    expect(probe.status).toBe(200);
    const wrong = await rawRequest(handle.aPort, {
      path: `/wrong/${runId}`,
      headers: {
        host: A.hostname,
        "x-sbx058-run": runId,
        "x-sbx058-case": "key-half",
        "x-sbx058-canary": canary("key-half"),
        "x-sbx058-route": "ordinary",
      },
    });
    expect(wrong.status).toBe(400);
    expect((await rawRequest(handle.aPort, { path: "/totally-uncorrelated" })).status).toBe(404);
    const snapshot = JSON.parse((await rawRequest(handle.aPort, {
      path: adminPath,
      headers: { authorization: `Bearer ${adminKey}` },
    })).body) as {
      events: Array<Record<string, unknown>>;
      unexpectedARequests: number;
      unattributedRequests: number;
    };
    expect(snapshot.events[0]).toMatchObject({
      caseId,
      role: "A",
      routeHeaderLines: 1,
      routeHeaderValues: 1,
      routeValueMatched: true,
      decoyHeaderLines: 0,
      oidcHeaderLines: 0,
    });
    expect(snapshot.unexpectedARequests).toBe(1);
    expect(snapshot.unattributedRequests).toBe(1);
  });

  it("binds proxy meta.host to P while reconstructing exact A URL and forwarded fields", () => {
    const config = validateReceiverConfiguration(configuration(), runId, A, P);
    const configured = config.cases[0]!;
    const request = new Request(new URL(configured.requestPath, A), {
      headers: { host: A.hostname },
    });
    expect(exactProxyAttribution(request, P.host, {
      host: [A.hostname], scheme: ["https"], port: ["443"], path: [configured.requestPath],
    }, configured, config)).toBe(true);
    expect(exactProxyAttribution(request, A.host, {
      host: [A.hostname], scheme: ["https"], port: ["443"], path: [configured.requestPath],
    }, configured, config)).toBe(false);
  });
});
