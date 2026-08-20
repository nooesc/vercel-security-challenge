import { randomUUID } from "node:crypto";
import { request } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import {
  startSbx054Receiver,
  type Sbx054ReceiverHandle,
} from "../pocs/SBX-054/receiver.js";
import {
  deriveSbx054CanaryCommitment,
  deriveSbx054OperationId,
  deriveSbx054Receipt,
  deriveSbx054SecretProof,
  SBX054_CASES,
} from "../pocs/SBX-054/verdict.js";

const ADMIN_KEY = "a".repeat(64);
const ACTION_KEY = "b".repeat(64);
const PUBLIC_ORIGIN = "https://owned-sbx054.trycloudflare.com";
const PUBLIC_HOST = "owned-sbx054.trycloudflare.com";
const opened: Sbx054ReceiverHandle[] = [];

async function localRequest(input: {
  port: number;
  path: string;
  method?: string;
  headers?: Record<string, string>;
  body?: Buffer;
}): Promise<{ status: number; json?: unknown }> {
  return new Promise((resolve, reject) => {
    const outgoing = request({
      hostname: "127.0.0.1",
      port: input.port,
      path: input.path,
      method: input.method ?? "GET",
      headers: input.headers,
    }, (incoming) => {
      const chunks: Buffer[] = [];
      incoming.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      incoming.once("end", () => {
        const body = Buffer.concat(chunks);
        try {
          resolve({
            status: incoming.statusCode ?? 0,
            ...(body.byteLength === 0 ? {} : { json: JSON.parse(body.toString("utf8")) }),
          });
        } finally {
          body.fill(0);
          for (const chunk of chunks) chunk.fill(0);
        }
      });
    });
    outgoing.once("error", reject);
    if (input.body !== undefined) outgoing.write(input.body);
    outgoing.end();
  });
}

afterEach(async () => {
  await Promise.all(opened.splice(0).map((handle) => handle.close()));
});

async function start() {
  const handle = await startSbx054Receiver({
    adminKey: ADMIN_KEY,
    actionKey: ACTION_KEY,
    publicOrigin: PUBLIC_ORIGIN,
    port: 0,
  });
  opened.push(handle);
  return {
    handle,
    local: `http://127.0.0.1:${handle.port}`,
    runId: randomUUID(),
  };
}

function canaries() {
  return {
    "v3-deny-comparator": `c54_${"a".repeat(43)}`,
    "v2-runtime-deny-target": `c54_${"b".repeat(43)}`,
    "v3-deny-comparator-post": `c54_${"c".repeat(43)}`,
    "v2-runtime-secret": `c54_${"d".repeat(43)}`,
  } as const;
}

async function configure(local: string, runId: string) {
  const values = canaries();
  const response = await fetch(`${local}/v1/sbx054/admin/runs/${runId}`, {
    method: "PUT",
    headers: { authorization: `Bearer ${ADMIN_KEY}`, "content-type": "application/json" },
    body: JSON.stringify({
      runId,
      publicHost: PUBLIC_HOST,
      cases: SBX054_CASES.map((caseId, index) => ({
        caseId,
        kind: index === 3 ? "secret" : "public",
        canaryCommitment: deriveSbx054CanaryCommitment(ACTION_KEY, runId, caseId, values[caseId]),
      })),
    }),
  });
  expect(response.status).toBe(204);
  return values;
}

async function snapshot(local: string, runId: string) {
  const response = await fetch(`${local}/v1/sbx054/admin/runs/${runId}`, {
    headers: { authorization: `Bearer ${ADMIN_KEY}` },
  });
  expect(response.status).toBe(200);
  return await response.json() as Record<string, unknown>;
}

describe("SBX-054 HMAC-only receiver", () => {
  it("starts empty, emits only keyed public evidence, then accepts one exact staged secret", async () => {
    const { handle, local, runId } = await start();
    const values = await configure(local, runId);
    expect(await snapshot(local, runId)).toMatchObject({
      configured: true,
      events: [],
      secretStaged: false,
      secretCleared: false,
      rawCanaryRetained: false,
      rawSecretRetained: false,
      rawBodyRetained: false,
      secretDigestRetained: false,
    });

    const targetCommitment = deriveSbx054CanaryCommitment(
      ACTION_KEY, runId, "v2-runtime-deny-target", values["v2-runtime-deny-target"],
    );
    const publicResponse = await localRequest({
      port: handle.port,
      path: `/v1/sbx054/public/${runId}/v2-runtime-deny-target/${values["v2-runtime-deny-target"]}`,
      headers: { host: PUBLIC_HOST },
    });
    expect(publicResponse.status).toBe(200);
    expect(publicResponse.json).toEqual({
      receipt: deriveSbx054Receipt(
        ACTION_KEY, "public", runId, "v2-runtime-deny-target", targetCommitment, false,
      ),
      secretProof: null,
      operationId: null,
    });

    const secret = Buffer.from("owned-mode-0600-secret-material-ABCDEFGHIJKLMNOPQRSTUVWXYZ", "utf8");
    const stage = await fetch(`${local}/v1/sbx054/admin/runs/${runId}/secret`, {
      method: "PUT",
      headers: { authorization: `Bearer ${ADMIN_KEY}`, "content-type": "application/octet-stream" },
      body: secret,
    });
    expect(stage.status).toBe(204);
    const secretCommitment = deriveSbx054CanaryCommitment(
      ACTION_KEY, runId, "v2-runtime-secret", values["v2-runtime-secret"],
    );
    const proof = deriveSbx054SecretProof(secret, runId, "v2-runtime-secret", secretCommitment);
    const operation = deriveSbx054OperationId(ACTION_KEY, runId, "v2-runtime-secret", proof);
    const action = await localRequest({
      port: handle.port,
      path: `/v1/sbx054/secret/${runId}/v2-runtime-secret/${values["v2-runtime-secret"]}`,
      method: "POST",
      headers: {
        host: PUBLIC_HOST,
        "content-type": "application/octet-stream",
        "content-length": String(secret.byteLength),
      },
      body: secret,
    });
    expect(action.status).toBe(200);
    expect(action.json).toEqual({
      receipt: deriveSbx054Receipt(
        ACTION_KEY, "secret", runId, "v2-runtime-secret", secretCommitment, true,
      ),
      secretProof: proof,
      operationId: operation,
    });
    const final = await snapshot(local, runId);
    expect(final).toMatchObject({ secretStaged: false, secretCleared: true, unexpectedRequests: 0 });
    expect((final.events as unknown[])).toHaveLength(2);
    const serialized = JSON.stringify(final);
    expect(serialized).not.toContain(secret.toString("utf8"));
    for (const canary of Object.values(values)) expect(serialized).not.toContain(canary);
    expect(serialized).not.toContain(ADMIN_KEY);
    expect(serialized).not.toContain(ACTION_KEY);
    secret.fill(0);
  });

  it("refuses secret staging until the exact target public event exists", async () => {
    const { handle, local, runId } = await start();
    await configure(local, runId);
    const secret = Buffer.alloc(48, 7);
    const response = await fetch(`${local}/v1/sbx054/admin/runs/${runId}/secret`, {
      method: "PUT",
      headers: { authorization: `Bearer ${ADMIN_KEY}`, "content-type": "application/octet-stream" },
      body: secret,
    });
    expect(response.status).toBe(409);
    secret.fill(0);
  });

  it("records an unexpected comparator reach instead of letting it look like an empty denial", async () => {
    const { handle, local, runId } = await start();
    const values = await configure(local, runId);
    const response = await localRequest({
      port: handle.port,
      path: `/v1/sbx054/public/${runId}/v3-deny-comparator/${values["v3-deny-comparator"]}`,
      headers: { host: PUBLIC_HOST },
    });
    expect(response.status).toBe(200);
    const state = await snapshot(local, runId);
    expect(state.events).toHaveLength(1);
    expect(state).toMatchObject({ unexpectedRequests: 0 });
    expect((state.events as Array<Record<string, unknown>>)[0]).toMatchObject({
      caseId: "v3-deny-comparator",
      kind: "public",
      pathMatched: true,
    });
  });
});
