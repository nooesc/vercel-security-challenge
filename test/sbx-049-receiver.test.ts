import http from "node:http";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createSbx049Receiver, type Sbx049ReceiverHandle } from "../pocs/SBX-049/receiver.js";
import {
  expectedOperationId,
  queryForCase,
  secretCommitment,
  SBX049_CASES,
  SBX049_TRANSFORM_HEADER,
  type Sbx049CaseId,
} from "../pocs/SBX-049/protocol.js";

const adminKey = "admin-".padEnd(40, "a");
const actionKey = "action-".padEnd(40, "b");
const secret = `s49_${"c".repeat(43)}`;
const runId = "12345678-1234-4123-8123-123456789abc";
const hostname = "owned.example";
const canaries = Object.fromEntries(SBX049_CASES.map((caseId, index) =>
  [caseId, `c49_${String(index).padStart(24, "0")}`])) as Record<Sbx049CaseId, string>;

interface ResponseData { status: number; body: string }

function request(
  port: number,
  path: string,
  options: { method?: string; admin?: boolean; secret?: string; body?: unknown } = {},
): Promise<ResponseData> {
  const body = options.body === undefined ? undefined : JSON.stringify(options.body);
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1",
      port,
      path,
      method: options.method ?? "GET",
      headers: {
        host: hostname,
        ...(options.admin ? { authorization: `Bearer ${adminKey}` } : {}),
        ...(options.secret ? { [SBX049_TRANSFORM_HEADER]: options.secret } : {}),
        ...(body ? { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) } : {}),
      },
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      response.on("end", () => resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.once("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

describe("SBX-049 receiver", () => {
  let handle: Sbx049ReceiverHandle;

  beforeEach(async () => {
    handle = createSbx049Receiver({
      adminKey,
      actionKey,
      publicOrigin: `https://${hostname}`,
      port: 0,
    });
    if (!handle.server.listening) await new Promise<void>((resolve) => handle.server.once("listening", resolve));
  });

  afterEach(async () => await handle.close());

  it("records only exact attributed operations and never retains the secret", async () => {
    const configuration = {
      secretCommitment: secretCommitment(actionKey, secret),
      cases: SBX049_CASES.map((caseId) => ({
        caseId,
        canary: canaries[caseId],
        rawQuery: queryForCase(runId, caseId, canaries[caseId]),
      })),
    };
    const configured = await request(handle.port, `/v1/sbx049/admin/runs/${runId}`, {
      method: "PUT", admin: true, body: configuration,
    });
    expect(configured.status).toBe(201);

    for (const caseId of SBX049_CASES) {
      const brokered = caseId === "exact-pair" || caseId === "combined-halves";
      const result = await request(
        handle.port,
        `/v1/sbx049/action?${queryForCase(runId, caseId, canaries[caseId])}`,
        brokered ? { secret } : {},
      );
      expect(result.status).toBe(200);
      expect(JSON.parse(result.body)).toMatchObject({
        caseId,
        brokered,
        operationId: expectedOperationId(
          actionKey, hostname, runId, caseId, canaries[caseId], brokered ? secret : undefined,
        ),
      });
    }

    const snapshot = await request(handle.port, `/v1/sbx049/admin/runs/${runId}`, { admin: true });
    expect(snapshot.status).toBe(200);
    expect(snapshot.body).not.toContain(secret);
    expect(JSON.parse(snapshot.body)).toMatchObject({
      configured: true,
      rawBrokeredSecretRetained: false,
      brokeredSecretDigestRetained: false,
    });
    expect(JSON.parse(snapshot.body).events.map((event: { caseId: string; ordinal: number }) =>
      [event.caseId, event.ordinal])).toEqual(SBX049_CASES.map((caseId, index) => [caseId, index + 1]));
  });

  it("rejects an uncommitted transform value and an inexact query without recording", async () => {
    const configuration = {
      secretCommitment: secretCommitment(actionKey, secret),
      cases: SBX049_CASES.map((caseId) => ({
        caseId,
        canary: canaries[caseId],
        rawQuery: queryForCase(runId, caseId, canaries[caseId]),
      })),
    };
    expect((await request(handle.port, `/v1/sbx049/admin/runs/${runId}`, {
      method: "PUT", admin: true, body: configuration,
    })).status).toBe(201);
    expect((await request(
      handle.port,
      `/v1/sbx049/action?${queryForCase(runId, "exact-pair", canaries["exact-pair"])}`,
      { secret: `s49_${"d".repeat(43)}` },
    )).status).toBe(403);
    expect((await request(
      handle.port,
      `/v1/sbx049/action?${queryForCase(runId, "key-half", canaries["key-half"])}&extra=1`,
    )).status).toBe(404);
    const snapshot = JSON.parse((await request(
      handle.port, `/v1/sbx049/admin/runs/${runId}`, { admin: true },
    )).body);
    expect(snapshot.events).toEqual([]);
  });
});
