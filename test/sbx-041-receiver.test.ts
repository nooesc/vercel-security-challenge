import { createHash } from "node:crypto";
import { request } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { startSbx041Receiver, type Sbx041ReceiverHandle } from "../pocs/SBX-041/receiver.js";
import { SBX041_TRANSFORM_HEADER } from "../pocs/SBX-041/verdict.js";

const handles: Sbx041ReceiverHandle[] = [];

async function rawGet(url: string, headers: Record<string, string>): Promise<{ status: number; body: string }> {
  return await new Promise((resolve, reject) => {
    const outgoing = request(url, { method: "GET", headers }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      response.on("end", () => resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
    });
    outgoing.once("error", reject);
    outgoing.end();
  });
}

afterEach(async () => {
  await Promise.all(handles.splice(0).map((handle) => handle.close()));
});

describe("SBX-041 receiver", () => {
  it("records exact A/B transform commitments and never reflects the brokered value", async () => {
    const adminKey = "admin-key-with-at-least-thirty-two-characters";
    const transform = "controller-only-brokered-value";
    const transformSha256 = createHash("sha256").update(transform).digest("hex");
    const runId = "receiver-local";
    const canary = "receiver-canary";
    const handle = await startSbx041Receiver({
      adminKey,
      aPublicOrigin: "https://a.trycloudflare.com",
      bPublicOrigin: "https://b.trycloudflare.com",
      aPort: 0,
      bPort: 0,
    });
    handles.push(handle);
    const a = `http://127.0.0.1:${handle.aPort}`;
    const b = `http://127.0.0.1:${handle.bPort}`;
    const configured = await fetch(`${a}/v1/sbx041/admin/runs/${runId}`, {
      method: "PUT",
      headers: { authorization: `Bearer ${adminKey}`, "content-type": "application/json" },
      body: JSON.stringify({
        runId,
        aHost: "a.trycloudflare.com",
        bHost: "b.trycloudflare.com",
        correlationCanary: canary,
        transformHeaderSha256: transformSha256,
      }),
    });
    expect(configured.status).toBe(204);

    const commonHeaders = {
      "x-sbx041-canary": canary,
      [SBX041_TRANSFORM_HEADER]: transform,
      "content-length": "0",
    };
    const normal = await rawGet(`${a}/v1/sbx041/control/${runId}`, {
      ...commonHeaders, host: "a.trycloudflare.com", "x-sbx041-case": "normal-a",
    });
    const action = await rawGet(`${b}/v1/sbx041/action/${runId}`, {
      ...commonHeaders, host: "b.trycloudflare.com", "x-sbx041-case": "fronted-sni-resume-attack",
    });
    expect(normal.status).toBe(200);
    expect(action.status).toBe(200);
    expect(action.body).not.toContain(transform);

    const snapshot = await fetch(`${a}/v1/sbx041/admin/runs/${runId}`, {
      headers: { authorization: `Bearer ${adminKey}` },
    }).then((response) => response.json()) as { a: Array<Record<string, unknown>>; b: Array<Record<string, unknown>> };
    expect(snapshot.a).toHaveLength(1);
    expect(snapshot.b).toHaveLength(1);
    expect(snapshot.b[0]).toMatchObject({
      caseId: "fronted-sni-resume-attack",
      kind: "action",
      hostHeaderLines: 1,
      hostHeaderValues: 1,
      hostMatched: true,
      transformHeaderLines: 1,
      transformHeaderValues: 1,
      transformHeaderSha256: transformSha256,
      transformCommitmentMatched: true,
      responseStatus: 200,
    });
    expect(JSON.stringify(snapshot)).not.toContain(transform);
  });
});
