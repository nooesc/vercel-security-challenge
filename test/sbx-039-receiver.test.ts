import { once } from "node:events";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { afterEach, describe, expect, it } from "vitest";
import {
  buildMysqlHandshakeV10,
  exactMysqlSslRequest,
  parseTlsClientHelloSni,
  startSbx039Receiver,
  type Sbx039Receiver,
} from "../pocs/SBX-039/receiver.js";
import {
  SBX039_TEST_ID,
  deriveSbx039PublicOperationId,
} from "../pocs/SBX-039/verdict.js";

const key = "k".repeat(64);
const hostname = "b.example.com";
const advertisedIPv4 = "198.51.100.20";
const canary = "0123456789abcdef0123456789abcdef";
const runId = "8b27cbcc-20ad-4f1d-a94e-ff5f85db96f1";
const openReceivers: Sbx039Receiver[] = [];

afterEach(async () => {
  await Promise.all(openReceivers.splice(0).map(async (receiver) => receiver.close()));
});

async function captureClientHello(serverName: string): Promise<Buffer> {
  let server: Server | undefined;
  let client: ReturnType<typeof tlsConnect> | undefined;
  try {
    const captured = new Promise<Buffer>((resolveCapture, reject) => {
      server = createServer((socket) => {
        socket.once("data", (chunk) => { resolveCapture(Buffer.from(chunk)); socket.destroy(); });
        socket.once("error", reject);
      });
      server.once("error", reject);
    });
    server!.listen(0, "127.0.0.1");
    await once(server!, "listening");
    const address = server!.address();
    if (!address || typeof address === "string") throw new Error("capture listener address unavailable");
    client = tlsConnect({ host: "127.0.0.1", port: address.port, servername: serverName, rejectUnauthorized: false });
    client.on("error", () => undefined);
    return await captured;
  } finally {
    client?.destroy();
    if (server?.listening) await new Promise<void>((resolveClose) => server!.close(() => resolveClose()));
  }
}

function sslRequest(): Buffer {
  const flags = 0x00000800 | 0x00000200 | 0x00008000 | 0x00080000;
  const payload = Buffer.alloc(32);
  payload.writeUInt32LE(flags, 0);
  payload.writeUInt32LE(16 * 1024 * 1024, 4);
  payload[8] = 0x2d;
  return Buffer.concat([Buffer.from([32, 0, 0, 1]), payload]);
}

async function admin(receiver: Sbx039Receiver, method: "GET" | "POST" | "DELETE", caseId: string, body?: unknown) {
  const response = await fetch(`${receiver.adminOrigin}/v1/sbx039/admin/cases/${runId}/${caseId}`, {
    method,
    headers: { Authorization: `Bearer ${key}`, ...(body === undefined ? {} : { "content-type": "application/json" }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: response.status, body: await response.json() as Record<string, unknown> };
}

async function configure(receiver: Sbx039Receiver, caseId: string, mode: "direct-tls" | "mysql-coalesced-public") {
  const now = Date.now();
  return await admin(receiver, "POST", caseId, {
    runId,
    caseId,
    phase: "public",
    mode,
    endpointBaseHostname: hostname,
    notBefore: new Date(now - 1_000).toISOString(),
    notAfter: new Date(now + 60_000).toISOString(),
    expectedPublicCanary: canary,
  });
}

async function connect(receiver: Sbx039Receiver): Promise<Socket> {
  const socket = createConnection({ host: "127.0.0.1", port: receiver.listenerPort });
  await once(socket, "connect");
  return socket;
}

describe("SBX-039 receiver", () => {
  it("builds a bounded HandshakeV10 and recognizes the exact SSLRequest", () => {
    const greeting = buildMysqlHandshakeV10("0123456789abcdef", 7);
    expect(greeting.readUIntLE(0, 3)).toBe(greeting.length - 4);
    expect(greeting[3]).toBe(0);
    expect(greeting[4]).toBe(10);
    expect(greeting.includes(Buffer.from("8.0.0-sbx039-0123456789abcdef\0"))).toBe(true);
    expect(exactMysqlSslRequest(sslRequest())).toBe(true);
    const changed = sslRequest();
    changed[8] = (changed[8] ?? 0) ^ 1;
    expect(exactMysqlSslRequest(changed)).toBe(false);
  });

  it("parses the SNI from a real Node TLS ClientHello", async () => {
    const expected = `s39p-${canary}.${hostname}`;
    const hello = await captureClientHello(expected);
    expect(parseTlsClientHelloSni(hello)).toEqual({ status: "complete", serverName: expected });
    expect(parseTlsClientHelloSni(hello.subarray(0, 7))).toEqual({ status: "incomplete" });
  });

  it("attributes a segmented MySQL SSLRequest plus ClientHello without storing raw SNI", async () => {
    const receiver = await startSbx039Receiver({
      key,
      adminPort: 0,
      listenerBindHost: "127.0.0.1",
      listenerPort: 0,
      listenerHostname: hostname,
      listenerIPv4: advertisedIPv4,
    });
    openReceivers.push(receiver);
    const caseId = "mysql-segmented-public";
    const configured = await configure(receiver, caseId, "mysql-coalesced-public");
    expect(configured.status).toBe(201);
    const hello = await captureClientHello(`s39p-${canary}.${hostname}`);
    const request = sslRequest();
    const socket = await connect(receiver);
    const [greeting] = await once(socket, "data") as [Buffer];
    expect(greeting.includes(Buffer.from(String(configured.body.greetingTag)))).toBe(true);
    socket.write(request.subarray(0, 9));
    socket.write(request.subarray(9));
    socket.write(hello.subarray(0, 13));
    socket.write(hello.subarray(13));
    await once(socket, "close");
    const status = await admin(receiver, "GET", caseId);
    expect(status.body).toMatchObject({
      configured: true,
      runId,
      caseId,
      mode: "mysql-coalesced-public",
      connectionCount: 1,
      greetingWriteCount: 1,
      sslRequestCount: 1,
      clientHelloCount: 1,
      exactPayloadReceiptCount: 1,
      malformedCount: 0,
      operationId: deriveSbx039PublicOperationId(key, runId, caseId, canary),
      configurationEpoch: receiver.configurationEpoch,
      rawInboundStored: false,
      rawServerNameStored: false,
      rawSecretStored: false,
      payloadDigestStored: false,
    });
  });

  it("keeps direct TLS as a separately attributable control", async () => {
    const receiver = await startSbx039Receiver({
      key,
      adminPort: 0,
      listenerBindHost: "127.0.0.1",
      listenerPort: 0,
      listenerHostname: hostname,
      listenerIPv4: advertisedIPv4,
    });
    openReceivers.push(receiver);
    const caseId = "direct-tls-control";
    expect((await configure(receiver, caseId, "direct-tls")).status).toBe(201);
    const socket = await connect(receiver);
    await once(socket, "data");
    socket.end(await captureClientHello(`s39p-${canary}.${hostname}`));
    await once(socket, "close");
    const status = await admin(receiver, "GET", caseId);
    expect(status.body).toMatchObject({
      connectionCount: 1,
      sslRequestCount: 0,
      clientHelloCount: 1,
      exactPayloadReceiptCount: 1,
      operationId: deriveSbx039PublicOperationId(key, runId, caseId, canary),
    });
  });

  it("exposes only bounded health metadata without the admin key", async () => {
    const receiver = await startSbx039Receiver({
      key,
      adminPort: 0,
      listenerBindHost: "127.0.0.1",
      listenerPort: 0,
      listenerHostname: hostname,
      listenerIPv4: advertisedIPv4,
    });
    openReceivers.push(receiver);
    const response = await fetch(`${receiver.adminOrigin}/healthz`);
    expect(response.status).toBe(200);
    const body = await response.json() as Record<string, unknown>;
    expect(body).toMatchObject({ ok: true, testId: SBX039_TEST_ID, activeCase: false });
    expect(JSON.stringify(body)).not.toContain(key);
  });
});
