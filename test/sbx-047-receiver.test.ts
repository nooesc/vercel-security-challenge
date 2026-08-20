import { randomBytes, randomUUID } from "node:crypto";
import { request } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import {
  startSbx047Receiver,
  type Sbx047ReceiverHandle,
} from "../pocs/SBX-047/receiver.js";
import {
  SBX047_TRANSFORM_HEADER,
  deriveSbx047OperationId,
  deriveSbx047Receipt,
  deriveSbx047SecretProof,
  parseSbx047ObserverSnapshot,
  sha256Sbx047,
} from "../pocs/SBX-047/verdict.js";

const handles: Sbx047ReceiverHandle[] = [];

async function localRequest(
  port: number,
  path: string,
  options: { method?: string; headers?: Record<string, string>; body?: string } = {},
): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const outgoing = request({
      hostname: "127.0.0.1",
      port,
      path,
      method: options.method ?? "GET",
      headers: options.headers,
    }, (incoming) => {
      const chunks: Buffer[] = [];
      incoming.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      incoming.once("end", () => resolve({
        status: incoming.statusCode ?? 0,
        text: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    outgoing.once("error", reject);
    if (options.body !== undefined) outgoing.write(options.body);
    outgoing.end();
  });
}

afterEach(async () => {
  await Promise.all(handles.splice(0).map((handle) => handle.close()));
});

describe("SBX-047 owned observer protocol", () => {
  it("records commitments only and gates a nonreflecting staged action", async () => {
    const adminKey = randomBytes(32).toString("hex");
    const transform = `s47_${randomBytes(32).toString("base64url")}`;
    const stagedSecret = `s47_${randomBytes(32).toString("base64url")}`;
    const transformSha = sha256Sbx047(transform);
    const runId = randomUUID();
    const canary = "canary-047";
    const host = "owned-sbx047.example.test";
    const handle = await startSbx047Receiver({
      adminKey,
      publicOrigin: `https://${host}`,
      port: 0,
    });
    handles.push(handle);
    const base = `http://127.0.0.1:${handle.port}`;
    const authorization = { authorization: `Bearer ${adminKey}` };

    const configure = await fetch(`${base}/v1/sbx047/admin/runs/${runId}`, {
      method: "PUT",
      headers: { ...authorization, "content-type": "application/json" },
      body: JSON.stringify({ runId, publicHost: host, canary, transformHeaderSha256: transformSha }),
    });
    expect(configure.status).toBe(204);

    const publicCase = "source-public-control";
    const publicResponse = await localRequest(
      handle.port,
      `/v1/sbx047/public/${runId}/${publicCase}/${canary}`,
      { headers: { host, [SBX047_TRANSFORM_HEADER]: transform } },
    );
    const publicReceipt = deriveSbx047Receipt(
      adminKey, runId, "public", publicCase, canary, transformSha,
    );
    expect(publicResponse.status).toBe(200);
    expect(JSON.parse(publicResponse.text)).toEqual({
      receipt: publicReceipt,
      operationId: null,
      secretProof: null,
    });

    const stage = await fetch(`${base}/v1/sbx047/admin/runs/${runId}/stage`, {
      method: "PUT",
      headers: { ...authorization, "content-type": "application/json" },
      body: JSON.stringify({ runId, secret: stagedSecret }),
    });
    expect(stage.status).toBe(204);
    const actionCase = "source-protected-control";
    const secretProof = deriveSbx047SecretProof(stagedSecret, runId, actionCase, canary);
    const operationId = deriveSbx047OperationId(adminKey, runId, actionCase, secretProof);
    const actionReceipt = deriveSbx047Receipt(
      adminKey, runId, "action", actionCase, canary, transformSha,
    );
    const actionResponse = await localRequest(
      handle.port,
      `/v1/sbx047/action/${runId}/${actionCase}/${canary}`,
      { headers: { host, [SBX047_TRANSFORM_HEADER]: transform } },
    );
    expect(actionResponse.status).toBe(200);
    expect(JSON.parse(actionResponse.text)).toEqual({ receipt: actionReceipt, operationId, secretProof });

    const snapshotResponse = await fetch(`${base}/v1/sbx047/admin/runs/${runId}`, {
      headers: authorization,
    });
    const snapshotText = await snapshotResponse.text();
    const snapshot = parseSbx047ObserverSnapshot(JSON.parse(snapshotText));
    expect(snapshot.actionStaged).toBe(true);
    expect(snapshot.events).toHaveLength(2);
    expect(snapshot.events[0]).toMatchObject({
      sequence: 1,
      kind: "public",
      caseId: publicCase,
      transformHeaderSha256: transformSha,
      transformCommitmentMatched: true,
      receipt: publicReceipt,
    });
    expect(snapshot.events[1]).toMatchObject({
      sequence: 2,
      kind: "action",
      caseId: actionCase,
      transformHeaderSha256: transformSha,
      operationId,
      secretProof,
    });
    expect(snapshotText).not.toContain(transform);
    expect(snapshotText).not.toContain(stagedSecret);
    expect(actionResponse.text).not.toContain(transform);

    expect((await fetch(`${base}/v1/sbx047/admin/runs/${runId}/stage`, {
      method: "DELETE",
      headers: authorization,
    })).status).toBe(204);
    expect((await fetch(`${base}/v1/sbx047/admin/runs/${runId}`, {
      method: "DELETE",
      headers: authorization,
    })).status).toBe(204);
    expect((await fetch(`${base}/v1/sbx047/admin/runs/${runId}`, {
      headers: authorization,
    })).status).toBe(404);
  });

  it("does not expose admin operations through the public Host even with the key", async () => {
    const adminKey = randomBytes(32).toString("hex");
    const host = "owned-sbx047.example.test";
    const handle = await startSbx047Receiver({ adminKey, publicOrigin: `https://${host}`, port: 0 });
    handles.push(handle);
    const response = await localRequest(
      handle.port,
      `/v1/sbx047/admin/runs/${randomUUID()}`,
      { headers: { host, authorization: `Bearer ${adminKey}` } },
    );
    expect(response.status).toBe(401);
  });
});
