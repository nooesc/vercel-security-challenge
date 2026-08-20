import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { createServer as createHttpServer, type IncomingMessage, type Server as HttpServer } from "node:http";
import { isIP, createServer as createTcpServer, type Server as TcpServer, type Socket } from "node:net";
import { pathToFileURL } from "node:url";
import {
  SBX039_TEST_ID,
  deriveSbx039GreetingTag,
  deriveSbx039PublicOperationId,
  deriveSbx039SecretCommitment,
  deriveSbx039SecretOperationId,
  isSbx039Canary,
  safeCommitmentEqual,
  type Sbx039ProbeMode,
  type Sbx039ReceiverStatus,
} from "./verdict.js";

const CLIENT_SSL = 0x00000800;
const CLIENT_PROTOCOL_41 = 0x00000200;
const CLIENT_SECURE_CONNECTION = 0x00008000;
const CLIENT_PLUGIN_AUTH = 0x00080000;
const CLIENT_FLAGS = CLIENT_SSL | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
const RAW_MAGIC = Buffer.from("SBX039R1", "ascii");
const maxInboundBytes = 32 * 1024;
const maxAdminBodyBytes = 16 * 1024;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const casePattern = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const hostnamePattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const commitmentPattern = /^[a-f0-9]{64}$/u;
const secretPattern = /^[a-f0-9]{32}$/u;
const publicModes = new Set<Sbx039CaseMode>(["direct-tls", "raw-public", "mysql-split-public", "mysql-coalesced-public"]);

type Sbx039CaseMode = Exclude<Sbx039ProbeMode, "https-control">;

interface CaseConfiguration {
  runId: string;
  caseId: string;
  phase: "public" | "secret";
  mode: Sbx039CaseMode;
  endpointBaseHostname: string;
  notBefore: number;
  notAfter: number;
  expectedPublicCanary?: string;
  expectedSecretCommitment?: string;
}

interface CaseState extends CaseConfiguration {
  greetingTag: string;
  expectedPublicServerName?: string;
  expectedOperationId: string;
  connectionCount: number;
  greetingWriteCount: number;
  sslRequestCount: number;
  clientHelloCount: number;
  rawFrameCount: number;
  exactPayloadReceiptCount: number;
  malformedCount: number;
  operationId?: string;
  receiptAt?: string;
  withinConfiguredWindow: boolean;
  secretCommitmentMatched: boolean;
  sockets: Set<Socket>;
}

interface ConnectionState {
  buffer: Buffer;
  sslRequestCounted: boolean;
  clientHelloCounted: boolean;
  rawFrameCounted: boolean;
  malformed: boolean;
}

export interface ParsedClientHello {
  status: "complete" | "incomplete" | "invalid";
  serverName?: string;
}

export interface Sbx039Receiver {
  adminOrigin: string;
  listenerPort: number;
  configurationEpoch: string;
  close(): Promise<void>;
}

function writeUInt24LE(value: number): Buffer {
  const output = Buffer.alloc(3);
  output.writeUIntLE(value, 0, 3);
  return output;
}

export function buildMysqlHandshakeV10(greetingTag: string, connectionId = 1): Buffer {
  if (!/^[A-Za-z0-9_-]{16}$/u.test(greetingTag)) throw new Error("greeting tag is invalid");
  const version = Buffer.from(`8.0.0-sbx039-${greetingTag}\0`, "ascii");
  const authPart1 = Buffer.from("s39proof", "ascii");
  const authPart2 = Buffer.from("serverproof!\0", "ascii");
  const payload = Buffer.concat([
    Buffer.from([0x0a]),
    version,
    Buffer.from([
      connectionId & 0xff,
      (connectionId >>> 8) & 0xff,
      (connectionId >>> 16) & 0xff,
      (connectionId >>> 24) & 0xff,
    ]),
    authPart1,
    Buffer.from([0x00, CLIENT_FLAGS & 0xff, (CLIENT_FLAGS >>> 8) & 0xff, 0x2d, 0x02, 0x00,
      (CLIENT_FLAGS >>> 16) & 0xff, (CLIENT_FLAGS >>> 24) & 0xff, 21]),
    Buffer.alloc(10),
    authPart2,
    Buffer.from("mysql_native_password\0", "ascii"),
  ]);
  return Buffer.concat([writeUInt24LE(payload.length), Buffer.from([0x00]), payload]);
}

export function exactMysqlSslRequest(buffer: Buffer): boolean {
  if (buffer.length < 36 || buffer.readUIntLE(0, 3) !== 32 || buffer[3] !== 1) return false;
  const payload = buffer.subarray(4, 36);
  return payload.readUInt32LE(0) === CLIENT_FLAGS && payload.readUInt32LE(4) === 16 * 1024 * 1024 &&
    payload[8] === 0x2d && payload.subarray(9).every((byte) => byte === 0);
}

function parseClientHelloBody(body: Buffer): ParsedClientHello {
  let offset = 0;
  if (body.length < 35) return { status: "invalid" };
  offset += 2 + 32;
  const sessionLength = body[offset];
  if (sessionLength === undefined || offset + 1 + sessionLength > body.length) return { status: "invalid" };
  offset += 1 + sessionLength;
  if (offset + 2 > body.length) return { status: "invalid" };
  const cipherLength = body.readUInt16BE(offset);
  offset += 2;
  if (cipherLength < 2 || cipherLength % 2 !== 0 || offset + cipherLength > body.length) return { status: "invalid" };
  offset += cipherLength;
  const compressionLength = body[offset];
  if (compressionLength === undefined || compressionLength < 1 || offset + 1 + compressionLength > body.length) {
    return { status: "invalid" };
  }
  offset += 1 + compressionLength;
  if (offset + 2 > body.length) return { status: "invalid" };
  const extensionsLength = body.readUInt16BE(offset);
  offset += 2;
  if (offset + extensionsLength !== body.length) return { status: "invalid" };
  const end = offset + extensionsLength;
  while (offset < end) {
    if (offset + 4 > end) return { status: "invalid" };
    const type = body.readUInt16BE(offset);
    const length = body.readUInt16BE(offset + 2);
    offset += 4;
    if (offset + length > end) return { status: "invalid" };
    if (type === 0) {
      if (length < 5) return { status: "invalid" };
      const listLength = body.readUInt16BE(offset);
      if (listLength + 2 !== length) return { status: "invalid" };
      let nameOffset = offset + 2;
      const listEnd = offset + 2 + listLength;
      while (nameOffset < listEnd) {
        if (nameOffset + 3 > listEnd) return { status: "invalid" };
        const nameType = body[nameOffset];
        const nameLength = body.readUInt16BE(nameOffset + 1);
        nameOffset += 3;
        if (nameOffset + nameLength > listEnd) return { status: "invalid" };
        if (nameType === 0) {
          let serverName: string;
          try { serverName = body.subarray(nameOffset, nameOffset + nameLength).toString("ascii"); }
          catch { return { status: "invalid" }; }
          if (serverName !== serverName.toLowerCase() || !hostnamePattern.test(serverName)) return { status: "invalid" };
          return { status: "complete", serverName };
        }
        nameOffset += nameLength;
      }
      return { status: "invalid" };
    }
    offset += length;
  }
  return { status: "invalid" };
}

export function parseTlsClientHelloSni(buffer: Buffer): ParsedClientHello {
  let recordOffset = 0;
  const handshakeParts: Buffer[] = [];
  let handshakeBytes = 0;
  while (true) {
    if (buffer.length - recordOffset < 5) return { status: "incomplete" };
    const contentType = buffer[recordOffset];
    const major = buffer[recordOffset + 1];
    const recordLength = buffer.readUInt16BE(recordOffset + 3);
    if (contentType !== 0x16 || major !== 0x03 || recordLength < 4 || recordLength > 18_432) {
      return { status: "invalid" };
    }
    if (buffer.length - recordOffset < 5 + recordLength) return { status: "incomplete" };
    const payload = buffer.subarray(recordOffset + 5, recordOffset + 5 + recordLength);
    handshakeParts.push(payload);
    handshakeBytes += payload.length;
    if (handshakeBytes > maxInboundBytes) return { status: "invalid" };
    const handshake = Buffer.concat(handshakeParts, handshakeBytes);
    if (handshake.length >= 4) {
      if (handshake[0] !== 0x01) return { status: "invalid" };
      const length = handshake.readUIntBE(1, 3);
      if (length < 35 || length > maxInboundBytes) return { status: "invalid" };
      if (handshake.length >= 4 + length) return parseClientHelloBody(handshake.subarray(4, 4 + length));
    }
    recordOffset += 5 + recordLength;
    if (recordOffset === buffer.length) return { status: "incomplete" };
  }
}

function json(response: import("node:http").ServerResponse, status: number, value: unknown): void {
  const body = Buffer.from(`${JSON.stringify(value)}\n`);
  response.writeHead(status, {
    "cache-control": "no-store, max-age=0",
    "content-length": body.length,
    "content-type": "application/json; charset=utf-8",
    "x-content-type-options": "nosniff",
  });
  response.end(body);
}

function authorized(request: IncomingMessage, key: string): boolean {
  const header = request.headers.authorization;
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return false;
  const supplied = Buffer.from(header.slice(7));
  const expected = Buffer.from(key);
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const value of request) {
    const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
    total += chunk.length;
    if (total > maxAdminBodyBytes) throw new Error("admin body exceeded its bound");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks, total).toString("utf8"));
}

function parseConfiguration(value: unknown, expectedHostname: string): CaseConfiguration {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("case configuration must be an object");
  const input = value as Record<string, unknown>;
  const allowedKeys = new Set([
    "runId", "caseId", "phase", "mode", "endpointBaseHostname", "notBefore", "notAfter",
    "expectedPublicCanary", "expectedSecretCommitment",
  ]);
  const unknown = Object.keys(input).find((key) => !allowedKeys.has(key));
  if (unknown) throw new Error(`unknown case field ${unknown}`);
  const { runId, caseId, phase, mode, endpointBaseHostname, notBefore, notAfter } = input;
  if (typeof runId !== "string" || !uuidPattern.test(runId) || typeof caseId !== "string" || !casePattern.test(caseId)) {
    throw new Error("runId or caseId is invalid");
  }
  if (phase !== "public" && phase !== "secret") throw new Error("phase is invalid");
  if (mode !== "direct-tls" && mode !== "raw-public" && mode !== "greeting-only" &&
      mode !== "mysql-split-public" && mode !== "mysql-coalesced-public" && mode !== "mysql-coalesced-secret") {
    throw new Error("mode is invalid");
  }
  if (endpointBaseHostname !== expectedHostname || typeof notBefore !== "string" || typeof notAfter !== "string") {
    throw new Error("endpoint identity or time window is invalid");
  }
  const before = Date.parse(notBefore);
  const after = Date.parse(notAfter);
  const now = Date.now();
  if (!Number.isFinite(before) || !Number.isFinite(after) || before > now || after < now || after - before > 30 * 60_000) {
    throw new Error("case time window is invalid");
  }
  const publicCanary = input.expectedPublicCanary;
  const secretCommitment = input.expectedSecretCommitment;
  if (publicModes.has(mode)) {
    if (phase !== "public" || typeof publicCanary !== "string" || !isSbx039Canary(publicCanary) ||
        secretCommitment !== undefined) throw new Error("public expectation is invalid");
  } else if (mode === "mysql-coalesced-secret") {
    if (phase !== "secret" || typeof secretCommitment !== "string" || !commitmentPattern.test(secretCommitment) ||
        publicCanary !== undefined) throw new Error("secret expectation is invalid");
  } else if (publicCanary !== undefined || secretCommitment !== undefined || phase !== "public") {
    throw new Error("greeting-only expectation is invalid");
  }
  return {
    runId, caseId, phase, mode, endpointBaseHostname, notBefore: before, notAfter: after,
    ...(typeof publicCanary === "string" ? { expectedPublicCanary: publicCanary } : {}),
    ...(typeof secretCommitment === "string" ? { expectedSecretCommitment: secretCommitment } : {}),
  };
}

function statusOf(state: CaseState | undefined, listener: {
  hostname: string; ipv4: string; port: number; epoch: string;
}): Sbx039ReceiverStatus {
  if (!state) {
    return {
      configured: false,
      connectionCount: 0,
      greetingWriteCount: 0,
      sslRequestCount: 0,
      clientHelloCount: 0,
      rawFrameCount: 0,
      exactPayloadReceiptCount: 0,
      malformedCount: 0,
      withinConfiguredWindow: false,
      secretCommitmentMatched: false,
      rawInboundStored: false,
      rawServerNameStored: false,
      rawSecretStored: false,
      payloadDigestStored: false,
    };
  }
  return {
    configured: true,
    runId: state.runId,
    caseId: state.caseId,
    phase: state.phase,
    mode: state.mode,
    connectionCount: state.connectionCount,
    greetingWriteCount: state.greetingWriteCount,
    sslRequestCount: state.sslRequestCount,
    clientHelloCount: state.clientHelloCount,
    rawFrameCount: state.rawFrameCount,
    exactPayloadReceiptCount: state.exactPayloadReceiptCount,
    malformedCount: state.malformedCount,
    ...(state.operationId ? { operationId: state.operationId } : {}),
    ...(state.receiptAt ? { receiptAt: state.receiptAt } : {}),
    listenerHostname: listener.hostname,
    listenerIPv4: listener.ipv4,
    listenerPort: listener.port,
    configurationEpoch: listener.epoch,
    withinConfiguredWindow: state.withinConfiguredWindow,
    secretCommitmentMatched: state.secretCommitmentMatched,
    rawInboundStored: false,
    rawServerNameStored: false,
    rawSecretStored: false,
    payloadDigestStored: false,
  };
}

function closeServer(server: HttpServer | TcpServer): Promise<void> {
  return new Promise((resolveClose, reject) => {
    server.close((error) => error ? reject(error) : resolveClose());
  });
}

export async function startSbx039Receiver(options: {
  key: string;
  adminHost?: "127.0.0.1";
  adminPort: number;
  listenerBindHost?: "0.0.0.0" | "127.0.0.1";
  listenerPort: number;
  listenerHostname: string;
  listenerIPv4: string;
}): Promise<Sbx039Receiver> {
  if (options.key.length < 32 || options.key.length > 512 || /[\0\r\n]/u.test(options.key)) {
    throw new Error("receiver key must contain from 32 through 512 single-line characters");
  }
  if (!Number.isInteger(options.adminPort) || options.adminPort < 0 || options.adminPort > 65_535 ||
      !Number.isInteger(options.listenerPort) || options.listenerPort < 0 || options.listenerPort > 65_535) {
    throw new Error("receiver ports are invalid");
  }
  if (!hostnamePattern.test(options.listenerHostname) || options.listenerHostname !== options.listenerHostname.toLowerCase() ||
      isIP(options.listenerHostname) !== 0 || isIP(options.listenerIPv4) !== 4) {
    throw new Error("listener advertised identity is invalid");
  }
  const adminHost = options.adminHost ?? "127.0.0.1";
  const listenerBindHost = options.listenerBindHost ?? "0.0.0.0";
  const configurationEpoch = randomUUID();
  const cases = new Map<string, CaseState>();
  let activeKey: string | undefined;
  let actualListenerPort = options.listenerPort;

  const listener = createTcpServer((socket) => {
    if (!activeKey) { socket.destroy(); return; }
    const state = cases.get(activeKey);
    if (!state) { socket.destroy(); return; }
    const now = Date.now();
    if (now < state.notBefore || now > state.notAfter) {
      state.withinConfiguredWindow = false;
      socket.destroy();
      return;
    }
    state.connectionCount += 1;
    state.sockets.add(socket);
    socket.setTimeout(5_000);
    const greeting = buildMysqlHandshakeV10(state.greetingTag, state.connectionCount);
    socket.write(greeting);
    state.greetingWriteCount += 1;
    const connection: ConnectionState = {
      buffer: Buffer.alloc(0), sslRequestCounted: false, clientHelloCounted: false,
      rawFrameCounted: false, malformed: false,
    };

    const fail = (): void => {
      if (!connection.malformed) {
        connection.malformed = true;
        state.malformedCount += 1;
      }
      socket.destroy();
    };

    const acceptServerName = (serverName: string): void => {
      if (state.exactPayloadReceiptCount > 0) { fail(); return; }
      let accepted = false;
      if (state.phase === "public" && state.expectedPublicServerName === serverName && state.expectedPublicCanary) {
        accepted = true;
      } else if (state.phase === "secret" && state.expectedSecretCommitment) {
        const escaped = state.endpointBaseHostname.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
        const match = new RegExp(`^s39s-([a-f0-9]{32})\\.${escaped}$`, "u").exec(serverName);
        if (match?.[1] && secretPattern.test(match[1])) {
          const secret = Buffer.from(match[1], "ascii");
          try {
            const actual = deriveSbx039SecretCommitment(options.key, state.runId, state.caseId, secret.toString("ascii"));
            accepted = safeCommitmentEqual(actual, state.expectedSecretCommitment);
            state.secretCommitmentMatched = accepted;
          } finally {
            secret.fill(0);
          }
        }
      }
      if (!accepted) { fail(); return; }
      const observedAt = Date.now();
      if (observedAt < state.notBefore || observedAt > state.notAfter) {
        state.withinConfiguredWindow = false;
        fail();
        return;
      }
      state.exactPayloadReceiptCount = 1;
      state.operationId = state.expectedOperationId;
      state.receiptAt = new Date(observedAt).toISOString();
      socket.end();
    };

    const process = (): void => {
      if (connection.malformed || state.exactPayloadReceiptCount > 0) return;
      if (state.mode === "raw-public") {
        if (connection.buffer.length < RAW_MAGIC.length + 2) return;
        if (!connection.buffer.subarray(0, RAW_MAGIC.length).equals(RAW_MAGIC)) { fail(); return; }
        const length = connection.buffer.readUInt16BE(RAW_MAGIC.length);
        if (length < 1 || length > 300) { fail(); return; }
        if (connection.buffer.length < RAW_MAGIC.length + 2 + length) return;
        if (!connection.rawFrameCounted) { state.rawFrameCount += 1; connection.rawFrameCounted = true; }
        const serverName = connection.buffer.subarray(RAW_MAGIC.length + 2, RAW_MAGIC.length + 2 + length).toString("ascii");
        acceptServerName(serverName);
        return;
      }
      let helloBytes = connection.buffer;
      if (state.mode !== "direct-tls" && state.mode !== "greeting-only") {
        if (connection.buffer.length < 36) return;
        if (!exactMysqlSslRequest(connection.buffer)) { fail(); return; }
        if (!connection.sslRequestCounted) { state.sslRequestCount += 1; connection.sslRequestCounted = true; }
        helloBytes = connection.buffer.subarray(36);
        if (helloBytes.length === 0) return;
      }
      if (state.mode === "greeting-only") return;
      const parsed = parseTlsClientHelloSni(helloBytes);
      if (parsed.status === "incomplete") return;
      if (parsed.status === "invalid" || !parsed.serverName) { fail(); return; }
      if (!connection.clientHelloCounted) { state.clientHelloCount += 1; connection.clientHelloCounted = true; }
      acceptServerName(parsed.serverName);
    };

    socket.on("data", (chunk: Buffer) => {
      if (connection.buffer.length + chunk.length > maxInboundBytes) { fail(); return; }
      connection.buffer = Buffer.concat([connection.buffer, chunk]);
      process();
    });
    socket.on("timeout", () => socket.destroy());
    socket.on("error", () => undefined);
    socket.on("close", () => {
      connection.buffer.fill(0);
      state.sockets.delete(socket);
    });
  });
  listener.on("error", () => undefined);
  await new Promise<void>((resolveListen, reject) => {
    listener.once("error", reject);
    listener.listen(options.listenerPort, listenerBindHost, () => {
      listener.off("error", reject);
      const address = listener.address();
      if (!address || typeof address === "string") { reject(new Error("listener address unavailable")); return; }
      actualListenerPort = address.port;
      resolveListen();
    });
  });

  const admin = createHttpServer(async (request, response) => {
    const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
    if (request.method === "GET" && url.pathname === "/healthz") {
      json(response, 200, {
        ok: true,
        testId: SBX039_TEST_ID,
        configurationEpoch,
        listener: {
          hostname: options.listenerHostname,
          ipv4: options.listenerIPv4,
          port: actualListenerPort,
        },
        activeCase: activeKey !== undefined,
      });
      return;
    }
    if (!authorized(request, options.key)) { json(response, 401, { ok: false }); return; }
    const match = /^\/v1\/sbx039\/admin\/cases\/([0-9a-f-]{36})\/([a-z0-9-]{1,63})$/u.exec(url.pathname);
    if (!match?.[1] || !match[2] || !uuidPattern.test(match[1]) || !casePattern.test(match[2])) {
      json(response, 404, { ok: false });
      return;
    }
    const key = `${match[1]}:${match[2]}`;
    try {
      if (request.method === "POST") {
        if (activeKey !== undefined || cases.has(key)) { json(response, 409, { ok: false, reason: "case-active" }); return; }
        const config = parseConfiguration(await readJson(request), options.listenerHostname);
        if (config.runId !== match[1] || config.caseId !== match[2]) throw new Error("path/body identity mismatch");
        const greetingTag = deriveSbx039GreetingTag(options.key, config.runId, config.caseId);
        const expectedPublicServerName = config.expectedPublicCanary
          ? `s39p-${config.expectedPublicCanary}.${config.endpointBaseHostname}`
          : undefined;
        const expectedOperationId = config.expectedPublicCanary
          ? deriveSbx039PublicOperationId(options.key, config.runId, config.caseId, config.expectedPublicCanary)
          : config.expectedSecretCommitment
            ? deriveSbx039SecretOperationId(options.key, config.runId, config.caseId, config.expectedSecretCommitment)
            : `my_${createHmac("sha256", options.key).update(`greeting-only\n${config.runId}\n${config.caseId}`).digest("base64url")}`;
        const state: CaseState = {
          ...config,
          greetingTag,
          ...(expectedPublicServerName ? { expectedPublicServerName } : {}),
          expectedOperationId,
          connectionCount: 0,
          greetingWriteCount: 0,
          sslRequestCount: 0,
          clientHelloCount: 0,
          rawFrameCount: 0,
          exactPayloadReceiptCount: 0,
          malformedCount: 0,
          withinConfiguredWindow: true,
          secretCommitmentMatched: false,
          sockets: new Set(),
        };
        cases.set(key, state);
        activeKey = key;
        json(response, 201, { configured: true, greetingTag, expectedOperationId, configurationEpoch });
        return;
      }
      const state = cases.get(key);
      if (request.method === "GET") { json(response, 200, statusOf(state, {
        hostname: options.listenerHostname, ipv4: options.listenerIPv4, port: actualListenerPort, epoch: configurationEpoch,
      })); return; }
      if (request.method === "DELETE") {
        if (state) for (const socket of state.sockets) socket.destroy();
        const deleted = cases.delete(key);
        if (activeKey === key) activeKey = undefined;
        json(response, 200, { deleted });
        return;
      }
      json(response, 405, { ok: false });
    } catch {
      json(response, 400, { ok: false, reason: "invalid-request" });
    }
  });
  await new Promise<void>((resolveListen, reject) => {
    admin.once("error", reject);
    admin.listen(options.adminPort, adminHost, () => {
      admin.off("error", reject);
      resolveListen();
    });
  });
  const adminAddress = admin.address();
  if (!adminAddress || typeof adminAddress === "string") throw new Error("admin address unavailable");
  return {
    adminOrigin: `http://${adminHost}:${adminAddress.port}`,
    listenerPort: actualListenerPort,
    configurationEpoch,
    async close(): Promise<void> {
      for (const state of cases.values()) for (const socket of state.sockets) socket.destroy();
      await Promise.all([closeServer(admin), closeServer(listener)]);
    },
  };
}

async function cli(): Promise<void> {
  const key = process.env.SBX039_ADMIN_KEY;
  const listenerHostname = process.env.SBX039_DENIED_HOSTNAME;
  const listenerIPv4 = process.env.SBX039_DENIED_IPV4;
  const listenerPort = Number(process.env.SBX039_DENIED_PORT ?? "3306");
  const adminPort = Number(process.env.SBX039_ADMIN_PORT ?? "43139");
  if (!key || !listenerHostname || !listenerIPv4) {
    throw new Error("SBX039_ADMIN_KEY, SBX039_DENIED_HOSTNAME, and SBX039_DENIED_IPV4 are required");
  }
  const receiver = await startSbx039Receiver({
    key, adminPort, listenerPort, listenerHostname, listenerIPv4,
  });
  process.stdout.write(`${JSON.stringify({
    ready: true,
    testId: SBX039_TEST_ID,
    adminOrigin: receiver.adminOrigin,
    listenerPort: receiver.listenerPort,
    configurationEpoch: receiver.configurationEpoch,
  })}\n`);
  const stop = async (): Promise<void> => { await receiver.close(); process.exit(0); };
  process.once("SIGINT", () => { void stop(); });
  process.once("SIGTERM", () => { void stop(); });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void cli().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
