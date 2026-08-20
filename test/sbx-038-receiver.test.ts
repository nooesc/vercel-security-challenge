import { randomBytes } from "node:crypto";
import { request as requestHttp } from "node:http";
import net, { type AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { startSbx038Receiver, type Sbx038ReceiverHandle } from "../pocs/SBX-038/receiver.js";
import {
  SBX038_TRANSFORM_HEADER,
  deriveSbx038OperationId,
  deriveSbx038SecretCommitment,
  deriveSbx038TransformCommitment,
} from "../pocs/SBX-038/verdict.js";

const handles: Sbx038ReceiverHandle[] = [];

afterEach(async () => {
  await Promise.all(handles.splice(0).map((handle) => handle.close()));
});

async function fixture() {
  const adminKey = randomBytes(32).toString("hex");
  const transform = `broker_${randomBytes(16).toString("hex")}`;
  const runId = "receiver-local-run";
  const canary = "receiver-public-canary";
  const handle = await startSbx038Receiver({
    adminKey,
    aPublicOrigin: "https://a.research.test",
    bPublicOrigin: "https://b.research.test",
    aPort: 0,
    bPort: 0,
  });
  handles.push(handle);
  const a = `http://127.0.0.1:${handle.aPort}`;
  const b = `http://127.0.0.1:${handle.bPort}`;
  const admin = (path: string, init: RequestInit = {}) => fetch(`${a}${path}`, {
    ...init,
    headers: { authorization: `Bearer ${adminKey}`, "content-type": "application/json", ...init.headers },
  });
  const configure = (wantedRunId: string, wantedCanary: string) => admin(`/v1/sbx038/admin/runs/${wantedRunId}`, {
    method: "PUT",
    body: JSON.stringify({
      runId: wantedRunId,
      aHost: "a.research.test",
      bHost: "b.research.test",
      correlationCanary: wantedCanary,
      transformHeaderCommitment: deriveSbx038TransformCommitment(adminKey, wantedRunId, transform),
    }),
  });
  const configured = await configure(runId, canary);
  expect(configured.status).toBe(204);
  return { adminKey, transform, runId, canary, handle, a, b, admin, configure };
}

function rawConnect(port: number, request: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1", () => socket.write(request));
    const chunks: Buffer[] = [];
    socket.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    socket.once("end", () => resolve(Buffer.concat(chunks).toString("latin1")));
    socket.once("error", reject);
  });
}

function localRequest(
  port: number,
  path: string,
  input: { method?: string; headers: Record<string, string>; body?: Buffer },
): Promise<{ status: number; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const request = requestHttp({ host: "127.0.0.1", port, path, method: input.method ?? "GET", headers: input.headers }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      response.once("end", () => resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks) }));
    });
    request.once("error", reject);
    request.end(input.body);
  });
}

function streamingLocalRequest(
  port: number,
  path: string,
  input: { method: string; headers: Record<string, string> },
) {
  let resolveResponse!: (value: { status: number; body: Buffer }) => void;
  let rejectResponse!: (error: Error) => void;
  const response = new Promise<{ status: number; body: Buffer }>((resolve, reject) => {
    resolveResponse = resolve;
    rejectResponse = reject;
  });
  const request = requestHttp({ host: "127.0.0.1", port, path, method: input.method, headers: input.headers },
    (incoming) => {
      const chunks: Buffer[] = [];
      incoming.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      incoming.once("end", () => resolveResponse({ status: incoming.statusCode ?? 0, body: Buffer.concat(chunks) }));
    });
  request.once("error", rejectResponse);
  return { request, response };
}

describe("SBX-038 owned receiver", () => {
  it("records transformed A, terminal CONNECT, and public B without acting as a proxy", async () => {
    const f = await fixture();
    const normalCase = "public-normal-a";
    const aOperation = deriveSbx038OperationId(f.adminKey, f.runId, normalCase, f.canary);
    const normal = await localRequest(f.handle.aPort, `/v1/sbx038/control/${f.runId}`, {
      headers: {
        "x-sbx038-case": normalCase,
        "x-sbx038-canary": f.canary,
        "x-sbx038-run": f.runId,
        host: "a.research.test",
        [SBX038_TRANSFORM_HEADER]: f.transform,
      },
    });
    expect(normal.status).toBe(200);
    expect(JSON.parse(normal.body.toString("utf8"))).toEqual({ operationId: aOperation });

    const connectCase = "public-connect-a";
    const connectResponse = await rawConnect(f.handle.aPort, [
      "CONNECT a.research.test:443 HTTP/1.1",
      "Host: a.research.test",
      `X-SBX038-Case: ${connectCase}`,
      `X-SBX038-Canary: ${f.canary}`,
      `X-SBX038-Run: ${f.runId}`,
      `${SBX038_TRANSFORM_HEADER}: ${f.transform}`,
      "Connection: close",
      "",
      "",
    ].join("\r\n"));
    expect(connectResponse).toContain("HTTP/1.1 405 Method Not Allowed\r\n");
    expect(connectResponse.toLowerCase()).toContain("x-sbx038-terminal: 1\r\n");

    const publicCase = "public-connect-b";
    const bOperation = deriveSbx038OperationId(f.adminKey, f.runId, publicCase, f.canary);
    const publicAction = await localRequest(f.handle.bPort, `/v1/sbx038/action/${f.runId}`, {
      headers: {
        "x-sbx038-case": publicCase,
        "x-sbx038-canary": f.canary,
        "x-sbx038-run": f.runId,
        host: "b.research.test",
      },
    });
    expect(publicAction.status).toBe(200);
    expect(JSON.parse(publicAction.body.toString("utf8"))).toEqual({ operationId: bOperation });

    const snapshotResponse = await f.admin(`/v1/sbx038/admin/runs/${f.runId}`);
    const snapshot = await snapshotResponse.json() as Record<string, unknown>;
    expect(snapshot).toMatchObject({
      configured: true,
      nextSequence: 3,
      infrastructureConnect: [],
      unexpected: [],
      secretRegistered: false,
      aHttp: [{
        sequence: 1,
        caseId: normalCase,
        transformHeaderLines: 1,
        transformCommitmentMatched: true,
        operationId: aOperation,
      }],
      aConnect: [{
        sequence: 2,
        caseId: connectCase,
        requestTarget: "a.research.test:443",
        terminalResponseStatus: 405,
        openedOutboundConnection: false,
        transformCommitmentMatched: true,
      }],
      b: [{
        sequence: 3,
        caseId: publicCase,
        stage: "public",
        canaryMatched: true,
        tlsTerminatedLocally: false,
        bodyBytes: 0,
        operationId: bOperation,
      }],
    });
    expect(JSON.stringify(snapshot)).not.toContain(f.transform);
  });

  it("accepts only a registered HMAC commitment and never retains the raw secret body", async () => {
    const f = await fixture();
    const secret = Buffer.from(`opsec_${randomBytes(32).toString("base64url")}`);
    const commitment = deriveSbx038SecretCommitment(f.adminKey, f.runId, secret);
    const registered = await f.admin(`/v1/sbx038/admin/secrets/${f.runId}`, {
      method: "PUT", body: JSON.stringify({ secretCommitment: commitment }),
    });
    expect(registered.status).toBe(200);
    const expected = deriveSbx038OperationId(f.adminKey, f.runId, "secret-connect-b", commitment);
    await expect(registered.json()).resolves.toEqual({ operationId: expected });
    const response = await localRequest(f.handle.bPort, `/v1/sbx038/action/${f.runId}`, {
      method: "POST",
      headers: {
        "x-sbx038-case": "secret-connect-b",
        "x-sbx038-canary": f.canary,
        "x-sbx038-run": f.runId,
        host: "b.research.test",
        "content-length": String(secret.length),
      },
      body: secret,
    });
    expect(response.status).toBe(200);
    expect(JSON.parse(response.body.toString("utf8"))).toEqual({ operationId: expected });
    const snapshot = await (await f.admin(`/v1/sbx038/admin/runs/${f.runId}`)).json() as Record<string, unknown>;
    expect(snapshot).toMatchObject({
      secretRegistered: true,
      b: [{
        caseId: "secret-connect-b",
        stage: "secret",
        secretCommitmentMatched: true,
        bodyBytes: secret.length,
        rawBodyRetained: false,
        operationId: expected,
      }],
    });
    expect(JSON.stringify(snapshot)).not.toContain(secret.toString("utf8"));
    secret.fill(0);
  });

  it("binds every structured ingress path to the exact run selected by its headers", async () => {
    const f = await fixture();
    const otherRunId = "receiver-other-run";
    expect((await f.configure(otherRunId, "receiver-other-canary")).status).toBe(204);
    const aHeaders = {
      "x-sbx038-case": "public-normal-a",
      "x-sbx038-canary": f.canary,
      "x-sbx038-run": f.runId,
      host: "a.research.test",
      [SBX038_TRANSFORM_HEADER]: f.transform,
    };
    const bHeaders = {
      "x-sbx038-canary": f.canary,
      "x-sbx038-run": f.runId,
      host: "b.research.test",
    };
    expect((await localRequest(f.handle.aPort, `/v1/sbx038/control/${otherRunId}`, {
      headers: aHeaders,
    })).status).toBe(400);
    expect((await localRequest(f.handle.bPort, `/v1/sbx038/direct/${otherRunId}`, {
      headers: { ...bHeaders, "x-sbx038-case": "public-direct-b-pre" },
    })).status).toBe(400);
    expect((await localRequest(f.handle.bPort, `/v1/sbx038/action/${otherRunId}`, {
      headers: { ...bHeaders, "x-sbx038-case": "public-connect-b" },
    })).status).toBe(400);

    const primary = await (await f.admin(`/v1/sbx038/admin/runs/${f.runId}`)).json() as Record<string, unknown>;
    expect(primary).toMatchObject({
      nextSequence: 3,
      aHttp: [],
      b: [],
      unexpected: [
        { sequence: 1, role: "a", attribution: "run-header", reason: "wrong-path" },
        { sequence: 2, role: "b", attribution: "run-header", reason: "wrong-path" },
        { sequence: 3, role: "b", attribution: "run-header", reason: "wrong-path" },
      ],
    });
    await expect((await f.admin(`/v1/sbx038/admin/runs/${otherRunId}`)).json()).resolves.toMatchObject({
      nextSequence: 0,
      aHttp: [],
      b: [],
      unexpected: [],
    });
  });

  it("records correlated health ingress and rejects ambiguous canary configuration", async () => {
    const f = await fixture();
    expect((await f.configure("receiver-duplicate-canary", f.canary)).status).toBe(409);
    expect((await f.configure("receiver-unique-canary", "receiver-unique-canary")).status).toBe(204);
    const headers = {
      "x-sbx038-case": "public-connect-b",
      "x-sbx038-canary": f.canary,
      "x-sbx038-run": f.runId,
    };
    expect((await localRequest(f.handle.aPort, "/healthz", {
      headers: { ...headers, host: "a.research.test" },
    })).status).toBe(200);
    expect((await localRequest(f.handle.bPort, "/healthz", {
      headers: { ...headers, host: "b.research.test" },
    })).status).toBe(200);
    await expect((await f.admin(`/v1/sbx038/admin/runs/${f.runId}`)).json()).resolves.toMatchObject({
      nextSequence: 2,
      unexpected: [
        { sequence: 1, role: "a", attribution: "run-header", reason: "wrong-path" },
        { sequence: 2, role: "b", attribution: "run-header", reason: "wrong-path" },
      ],
    });
  });

  it("rejects inexact action bodies and methods while retaining exact replay chronology", async () => {
    const f = await fixture();
    const secret = Buffer.from(`opsec_${randomBytes(32).toString("base64url")}`);
    const wrongSecret = Buffer.from(`opsec_${randomBytes(32).toString("base64url")}`);
    const commonHeaders = {
      "x-sbx038-canary": f.canary,
      "x-sbx038-run": f.runId,
      host: "b.research.test",
    };
    const secretRequest = (body: Buffer) => localRequest(f.handle.bPort, `/v1/sbx038/action/${f.runId}`, {
      method: "POST",
      headers: {
        ...commonHeaders,
        "x-sbx038-case": "secret-connect-b",
        "content-length": String(body.length),
      },
      body,
    });

    expect((await secretRequest(secret)).status).toBe(401);
    const commitment = deriveSbx038SecretCommitment(f.adminKey, f.runId, secret);
    expect((await f.admin(`/v1/sbx038/admin/secrets/${f.runId}`, {
      method: "PUT", body: JSON.stringify({ secretCommitment: commitment }),
    })).status).toBe(200);
    expect((await secretRequest(wrongSecret)).status).toBe(401);
    expect((await localRequest(f.handle.bPort, `/v1/sbx038/action/${f.runId}`, {
      headers: {
        ...commonHeaders,
        "x-sbx038-case": "public-connect-b",
        "content-length": "1",
      },
      body: Buffer.from("x"),
    })).status).toBe(401);
    expect((await secretRequest(Buffer.alloc(4 * 1024 + 1, 0x78))).status).toBe(400);
    expect((await localRequest(f.handle.bPort, `/v1/sbx038/action/${f.runId}`, {
      headers: { ...commonHeaders, "x-sbx038-case": "secret-connect-b" },
    })).status).toBe(400);
    expect((await localRequest(f.handle.bPort, `/v1/sbx038/action/${f.runId}`, {
      method: "POST",
      headers: { ...commonHeaders, "x-sbx038-case": "public-connect-b", "content-length": "0" },
    })).status).toBe(400);

    const expected = deriveSbx038OperationId(f.adminKey, f.runId, "secret-connect-b", commitment);
    const first = await secretRequest(secret);
    const replay = await secretRequest(secret);
    expect(first.status).toBe(200);
    expect(replay.status).toBe(200);
    expect(JSON.parse(first.body.toString("utf8"))).toEqual({ operationId: expected });
    expect(JSON.parse(replay.body.toString("utf8"))).toEqual({ operationId: expected });
    const snapshot = await (await f.admin(`/v1/sbx038/admin/runs/${f.runId}`)).json() as Record<string, unknown>;
    expect(snapshot).toMatchObject({
      nextSequence: 8,
      b: [
        { sequence: 1, stage: "secret", secretCommitmentMatched: false },
        { sequence: 2, stage: "secret", secretCommitmentMatched: false },
        { sequence: 3, stage: "public", bodyBytes: 1 },
        { sequence: 7, stage: "secret", secretCommitmentMatched: true, operationId: expected },
        { sequence: 8, stage: "secret", secretCommitmentMatched: true, operationId: expected },
      ],
      unexpected: [
        { sequence: 4, reason: "invalid-body" },
        { sequence: 5, reason: "wrong-method" },
        { sequence: 6, reason: "wrong-method" },
      ],
    });
    expect(JSON.stringify(snapshot)).not.toContain(secret.toString("utf8"));
    expect(JSON.stringify(snapshot)).not.toContain(wrongSecret.toString("utf8"));
    secret.fill(0);
    wrongSecret.fill(0);
  });

  it("blocks deletion while secret registration JSON is still being read", async () => {
    const f = await fixture();
    const secret = Buffer.from(`opsec_${randomBytes(32).toString("base64url")}`);
    const commitment = deriveSbx038SecretCommitment(f.adminKey, f.runId, secret);
    const body = Buffer.from(JSON.stringify({ secretCommitment: commitment }));
    const started = new Promise<void>((resolve) => f.handle.aServer.once("request", () => resolve()));
    const pending = streamingLocalRequest(f.handle.aPort, `/v1/sbx038/admin/secrets/${f.runId}`, {
      method: "PUT",
      headers: {
        authorization: `Bearer ${f.adminKey}`,
        "content-type": "application/json",
        "content-length": String(body.length),
      },
    });
    pending.request.write(body.subarray(0, 1));
    await started;
    const blockedDelete = await f.admin(`/v1/sbx038/admin/runs/${f.runId}`, { method: "DELETE" });
    pending.request.end(body.subarray(1));
    const registered = await pending.response;
    expect(blockedDelete.status).toBe(409);
    expect(registered.status).toBe(200);
    await expect((await f.admin(`/v1/sbx038/admin/runs/${f.runId}`)).json()).resolves.toMatchObject({
      secretRegistered: true,
    });
    expect((await f.admin(`/v1/sbx038/admin/runs/${f.runId}`, { method: "DELETE" })).status).toBe(204);
    secret.fill(0);
    body.fill(0);
  });

  it("blocks deletion while an exact secret action body is still being read", async () => {
    const f = await fixture();
    const secret = Buffer.from(`opsec_${randomBytes(32).toString("base64url")}`);
    const commitment = deriveSbx038SecretCommitment(f.adminKey, f.runId, secret);
    expect((await f.admin(`/v1/sbx038/admin/secrets/${f.runId}`, {
      method: "PUT", body: JSON.stringify({ secretCommitment: commitment }),
    })).status).toBe(200);
    const started = new Promise<void>((resolve) => f.handle.bServer.once("request", () => resolve()));
    const pending = streamingLocalRequest(f.handle.bPort, `/v1/sbx038/action/${f.runId}`, {
      method: "POST",
      headers: {
        "x-sbx038-case": "secret-connect-b",
        "x-sbx038-canary": f.canary,
        "x-sbx038-run": f.runId,
        host: "b.research.test",
        "content-length": String(secret.length),
      },
    });
    pending.request.write(secret.subarray(0, 1));
    await started;
    const blockedDelete = await f.admin(`/v1/sbx038/admin/runs/${f.runId}`, { method: "DELETE" });
    pending.request.end(secret.subarray(1));
    const action = await pending.response;
    expect(blockedDelete.status).toBe(409);
    expect(action.status).toBe(200);
    await expect((await f.admin(`/v1/sbx038/admin/runs/${f.runId}`)).json()).resolves.toMatchObject({
      nextSequence: 1,
      b: [{ sequence: 1, secretCommitmentMatched: true }],
    });
    expect((await f.admin(`/v1/sbx038/admin/runs/${f.runId}`, { method: "DELETE" })).status).toBe(204);
    secret.fill(0);
  });

  it("requires admin authorization and deletes run state exactly", async () => {
    const f = await fixture();
    expect((await fetch(`${f.a}/v1/sbx038/admin/runs/${f.runId}`)).status).toBe(401);
    expect((await f.admin(`/v1/sbx038/admin/runs/${f.runId}`, { method: "DELETE" })).status).toBe(204);
    expect((await f.admin(`/v1/sbx038/admin/runs/${f.runId}`)).status).toBe(404);
  });

  it("counts run-correlated wrong-path ingress on both receiver roles without retaining raw paths", async () => {
    const f = await fixture();
    const headers = {
      "x-sbx038-case": "public-connect-b",
      "x-sbx038-canary": f.canary,
      "x-sbx038-run": f.runId,
    };
    expect((await fetch(`${f.a}/wrong/private-looking-value`, {
      headers: { ...headers, host: "a.research.test" },
    })).status).toBe(404);
    expect((await fetch(`${f.b}/wrong/another-private-looking-value`, {
      headers: { ...headers, host: "b.research.test" },
    })).status).toBe(404);
    const snapshot = await (await f.admin(`/v1/sbx038/admin/runs/${f.runId}`)).json() as Record<string, unknown>;
    expect(snapshot).toMatchObject({
      nextSequence: 2,
      unexpected: [
        { sequence: 1, role: "a", attribution: "run-header", reason: "wrong-path" },
        { sequence: 2, role: "b", attribution: "run-header", reason: "wrong-path" },
      ],
    });
    expect(JSON.stringify(snapshot)).not.toContain("private-looking-value");
  });

  it("closes the A listener when the B listener cannot start", async () => {
    const occupiedB = net.createServer();
    await new Promise<void>((resolve) => occupiedB.listen(0, "127.0.0.1", resolve));
    const bPort = (occupiedB.address() as AddressInfo).port;
    const temporaryA = net.createServer();
    await new Promise<void>((resolve) => temporaryA.listen(0, "127.0.0.1", resolve));
    const aPort = (temporaryA.address() as AddressInfo).port;
    await new Promise<void>((resolve, reject) => temporaryA.close((error) => error ? reject(error) : resolve()));
    await expect(startSbx038Receiver({
      adminKey: randomBytes(32).toString("hex"),
      aPublicOrigin: "https://a.research.test",
      bPublicOrigin: "https://b.research.test",
      aPort,
      bPort,
    })).rejects.toThrow();
    const replacementA = net.createServer();
    await new Promise<void>((resolve, reject) => {
      replacementA.once("error", reject);
      replacementA.listen(aPort, "127.0.0.1", () => resolve());
    });
    await Promise.all([occupiedB, replacementA].map((server) =>
      new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))));
  });
});
