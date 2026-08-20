import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer as createHttpServer, type IncomingMessage, type Server as HttpServer } from "node:http";
import { createServer as createTcpServer, isIP, type Server as TcpServer, type Socket } from "node:net";
import { createSecureContext, TLSSocket } from "node:tls";
import { pathToFileURL } from "node:url";
import {
  SBX043_TEST_ID,
  deriveSbx043GreetingTag,
  deriveSbx043PublicOperationId,
  deriveSbx043SecretCommitment,
  deriveSbx043SecretOperationId,
  isSbx043Canary,
  safeSbx043Equal,
  type Sbx043ProbeMode,
  type Sbx043ReceiverStatus,
} from "./verdict.js";

const rawMagic = Buffer.from("SBX043R1", "ascii");
const maxInboundBytes = 32 * 1024;
const maxAdminBodyBytes = 16 * 1024;
const maxSmtpLineBytes = 512;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const casePattern = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const hostnamePattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const commitmentPattern = /^[A-Za-z0-9_-]{43}$/u;
const secretPattern = /^[a-f0-9]{32}$/u;

type Sbx043CaseMode = Exclude<Sbx043ProbeMode, "https-control">;

interface CaseConfiguration {
  runId: string;
  caseId: string;
  phase: "public" | "secret";
  mode: Sbx043CaseMode;
  endpointBaseHostname: string;
  notBefore: number;
  notAfter: number;
  expectedPublicCanary?: string;
  expectedSecretCommitment?: string;
}

interface CaseState extends CaseConfiguration {
  greetingTag: string;
  expectedPublicProofName?: string;
  expectedOperationId: string;
  connectionCount: number;
  greetingWriteCount: number;
  exactEhloCount: number;
  startTlsCommandCount: number;
  tlsHandshakeCount: number;
  postTlsEhloCount: number;
  clientHelloCount: number;
  rawFrameCount: number;
  exactPayloadReceiptCount: number;
  malformedCount: number;
  operationId?: string;
  receiptAt?: string;
  withinConfiguredWindow: boolean;
  secretCommitmentMatched: boolean;
  sockets: Set<Socket | TLSSocket>;
}

export interface ParsedClientHello {
  status: "complete" | "incomplete" | "invalid";
  serverName?: string;
}

export interface Sbx043Receiver {
  adminOrigin: string;
  listenerPort: number;
  configurationEpoch: string;
  close(): Promise<void>;
}

function parseClientHelloBody(body: Buffer): ParsedClientHello {
  let offset = 34;
  if (body.length < 35) return { status: "invalid" };
  const sessionLength = body[offset];
  if (sessionLength === undefined || offset + 1 + sessionLength > body.length) return { status: "invalid" };
  offset += 1 + sessionLength;
  if (offset + 2 > body.length) return { status: "invalid" };
  const cipherLength = body.readUInt16BE(offset);
  offset += 2;
  if (cipherLength < 2 || cipherLength % 2 !== 0 || offset + cipherLength > body.length) return { status: "invalid" };
  offset += cipherLength;
  const compressionLength = body[offset];
  if (compressionLength === undefined || compressionLength < 1 || offset + 1 + compressionLength > body.length) return { status: "invalid" };
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
      const listEnd = nameOffset + listLength;
      while (nameOffset < listEnd) {
        if (nameOffset + 3 > listEnd) return { status: "invalid" };
        const nameType = body[nameOffset];
        const nameLength = body.readUInt16BE(nameOffset + 1);
        nameOffset += 3;
        if (nameOffset + nameLength > listEnd) return { status: "invalid" };
        if (nameType === 0) {
          const serverName = body.subarray(nameOffset, nameOffset + nameLength).toString("ascii");
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

export function parseSbx043ClientHelloSni(buffer: Buffer): ParsedClientHello {
  let recordOffset = 0;
  const parts: Buffer[] = [];
  let total = 0;
  while (true) {
    if (buffer.length - recordOffset < 5) return { status: "incomplete" };
    const length = buffer.readUInt16BE(recordOffset + 3);
    if (buffer[recordOffset] !== 0x16 || buffer[recordOffset + 1] !== 0x03 || length < 4 || length > 18_432) {
      return { status: "invalid" };
    }
    if (buffer.length - recordOffset < 5 + length) return { status: "incomplete" };
    parts.push(buffer.subarray(recordOffset + 5, recordOffset + 5 + length));
    total += length;
    if (total > maxInboundBytes) return { status: "invalid" };
    const handshake = Buffer.concat(parts, total);
    if (handshake.length >= 4) {
      if (handshake[0] !== 0x01) return { status: "invalid" };
      const bodyLength = handshake.readUIntBE(1, 3);
      if (bodyLength < 35 || bodyLength > maxInboundBytes) return { status: "invalid" };
      if (handshake.length >= 4 + bodyLength) return parseClientHelloBody(handshake.subarray(4, 4 + bodyLength));
    }
    recordOffset += 5 + length;
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
  const allowedKeys = new Set(["runId", "caseId", "phase", "mode", "endpointBaseHostname", "notBefore", "notAfter", "expectedPublicCanary", "expectedSecretCommitment"]);
  const unknown = Object.keys(input).find((key) => !allowedKeys.has(key));
  if (unknown) throw new Error(`unknown case field ${unknown}`);
  const { runId, caseId, phase, mode, endpointBaseHostname, notBefore, notAfter } = input;
  if (typeof runId !== "string" || !uuidPattern.test(runId) || typeof caseId !== "string" || !casePattern.test(caseId)) throw new Error("runId or caseId is invalid");
  if (phase !== "public" && phase !== "secret") throw new Error("phase is invalid");
  if (mode !== "direct-tls" && mode !== "raw-public" && mode !== "smtp-starttls-public" && mode !== "smtp-starttls-secret") throw new Error("mode is invalid");
  if (endpointBaseHostname !== expectedHostname || typeof notBefore !== "string" || typeof notAfter !== "string") throw new Error("endpoint identity or time window is invalid");
  const before = Date.parse(notBefore);
  const after = Date.parse(notAfter);
  const now = Date.now();
  if (!Number.isFinite(before) || !Number.isFinite(after) || before > now || after < now || after - before > 30 * 60_000) throw new Error("case time window is invalid");
  const publicCanary = input.expectedPublicCanary;
  const secretCommitment = input.expectedSecretCommitment;
  if (mode === "smtp-starttls-secret") {
    if (phase !== "secret" || typeof secretCommitment !== "string" || !commitmentPattern.test(secretCommitment) || publicCanary !== undefined) throw new Error("secret expectation is invalid");
  } else if (phase !== "public" || typeof publicCanary !== "string" || !isSbx043Canary(publicCanary) || secretCommitment !== undefined) {
    throw new Error("public expectation is invalid");
  }
  return {
    runId, caseId, phase, mode, endpointBaseHostname, notBefore: before, notAfter: after,
    ...(typeof publicCanary === "string" ? { expectedPublicCanary: publicCanary } : {}),
    ...(typeof secretCommitment === "string" ? { expectedSecretCommitment: secretCommitment } : {}),
  };
}

function statusOf(state: CaseState | undefined, listener: { hostname: string; ipv4: string; port: number; epoch: string }): Sbx043ReceiverStatus {
  if (!state) return {
    configured: false, connectionCount: 0, greetingWriteCount: 0, exactEhloCount: 0,
    startTlsCommandCount: 0, tlsHandshakeCount: 0, postTlsEhloCount: 0, clientHelloCount: 0,
    rawFrameCount: 0, exactPayloadReceiptCount: 0, malformedCount: 0, withinConfiguredWindow: false,
    secretCommitmentMatched: false, rawInboundStored: false, rawEhloStored: false, rawSecretStored: false,
    payloadDigestStored: false,
  };
  return {
    configured: true, runId: state.runId, caseId: state.caseId, phase: state.phase, mode: state.mode,
    connectionCount: state.connectionCount, greetingWriteCount: state.greetingWriteCount,
    exactEhloCount: state.exactEhloCount, startTlsCommandCount: state.startTlsCommandCount,
    tlsHandshakeCount: state.tlsHandshakeCount, postTlsEhloCount: state.postTlsEhloCount,
    clientHelloCount: state.clientHelloCount, rawFrameCount: state.rawFrameCount,
    exactPayloadReceiptCount: state.exactPayloadReceiptCount, malformedCount: state.malformedCount,
    ...(state.operationId ? { operationId: state.operationId } : {}),
    ...(state.receiptAt ? { receiptAt: state.receiptAt } : {}),
    listenerHostname: listener.hostname, listenerIPv4: listener.ipv4, listenerPort: listener.port,
    configurationEpoch: listener.epoch, withinConfiguredWindow: state.withinConfiguredWindow,
    secretCommitmentMatched: state.secretCommitmentMatched, rawInboundStored: false, rawEhloStored: false,
    rawSecretStored: false, payloadDigestStored: false,
  };
}

function closeServer(server: HttpServer | TcpServer): Promise<void> {
  return new Promise((resolveClose, reject) => server.close((error) => error ? reject(error) : resolveClose()));
}

export async function startSbx043Receiver(options: {
  key: string;
  tlsKey: string | Buffer;
  tlsCert: string | Buffer;
  adminHost?: "127.0.0.1";
  adminPort: number;
  listenerBindHost?: "0.0.0.0" | "127.0.0.1";
  listenerPort: number;
  listenerHostname: string;
  listenerIPv4: string;
}): Promise<Sbx043Receiver> {
  if (options.key.length < 32 || options.key.length > 512 || /[\0\r\n]/u.test(options.key)) throw new Error("receiver key is invalid");
  if (!Number.isInteger(options.adminPort) || options.adminPort < 0 || options.adminPort > 65_535 || !Number.isInteger(options.listenerPort) || options.listenerPort < 0 || options.listenerPort > 65_535) throw new Error("receiver ports are invalid");
  if (!hostnamePattern.test(options.listenerHostname) || options.listenerHostname !== options.listenerHostname.toLowerCase() || isIP(options.listenerHostname) !== 0 || isIP(options.listenerIPv4) !== 4) throw new Error("listener advertised identity is invalid");
  const secureContext = createSecureContext({ key: options.tlsKey, cert: options.tlsCert, minVersion: "TLSv1.2" });
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
    if (now < state.notBefore || now > state.notAfter) { state.withinConfiguredWindow = false; socket.destroy(); return; }
    state.connectionCount += 1;
    state.sockets.add(socket);
    socket.setTimeout(5_000);
    let buffer = Buffer.alloc(0);
    let malformed = false;
    let smtpStage: "ehlo" | "starttls" | "upgrading" = "ehlo";

    const fail = (): void => {
      if (!malformed) { malformed = true; state.malformedCount += 1; }
      socket.destroy();
    };
    const acceptProof = (proofName: string): boolean => {
      if (state.exactPayloadReceiptCount > 0) return false;
      let accepted = false;
      if (state.phase === "public" && state.expectedPublicProofName === proofName) {
        accepted = true;
      } else if (state.phase === "secret" && state.expectedSecretCommitment) {
        const escaped = state.endpointBaseHostname.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
        const match = new RegExp(`^s43s-([a-f0-9]{32})\\.${escaped}$`, "u").exec(proofName);
        if (match?.[1] && secretPattern.test(match[1])) {
          const secret = Buffer.from(match[1], "ascii");
          try {
            const commitment = deriveSbx043SecretCommitment(options.key, state.runId, state.caseId, secret);
            accepted = safeSbx043Equal(commitment, state.expectedSecretCommitment);
            state.secretCommitmentMatched = accepted;
          } finally { secret.fill(0); }
        }
      }
      const observedAt = Date.now();
      if (!accepted || observedAt < state.notBefore || observedAt > state.notAfter) {
        if (observedAt < state.notBefore || observedAt > state.notAfter) state.withinConfiguredWindow = false;
        return false;
      }
      state.exactPayloadReceiptCount = 1;
      state.operationId = state.expectedOperationId;
      state.receiptAt = new Date(observedAt).toISOString();
      return true;
    };

    const processDirect = (): void => {
      const parsed = parseSbx043ClientHelloSni(buffer);
      if (parsed.status === "incomplete") return;
      if (parsed.status === "invalid" || !parsed.serverName) { fail(); return; }
      state.clientHelloCount += 1;
      if (!acceptProof(parsed.serverName)) { fail(); return; }
      socket.end();
    };
    const processRaw = (): void => {
      if (buffer.length < rawMagic.length + 2) return;
      if (!buffer.subarray(0, rawMagic.length).equals(rawMagic)) { fail(); return; }
      const length = buffer.readUInt16BE(rawMagic.length);
      if (length < 1 || length > 300 || buffer.length < rawMagic.length + 2 + length) return;
      state.rawFrameCount += 1;
      const name = buffer.subarray(rawMagic.length + 2, rawMagic.length + 2 + length).toString("ascii");
      if (!acceptProof(name)) { fail(); return; }
      socket.end();
    };

    const processPostTls = (secure: TLSSocket): void => {
      let encryptedBuffer = Buffer.alloc(0);
      secure.on("data", (chunk: Buffer) => {
        if (encryptedBuffer.length + chunk.length > maxSmtpLineBytes) { encryptedBuffer.fill(0); secure.destroy(); return; }
        encryptedBuffer = Buffer.concat([encryptedBuffer, chunk]);
        const end = encryptedBuffer.indexOf("\r\n");
        if (end < 0) return;
        const line = encryptedBuffer.subarray(0, end).toString("ascii");
        encryptedBuffer.fill(0);
        if (line !== "EHLO post.sbx043.invalid") { state.malformedCount += 1; secure.destroy(); return; }
        state.postTlsEhloCount += 1;
        secure.end("250 post-tls-ok\r\n");
      });
      secure.once("close", () => encryptedBuffer.fill(0));
    };

    const startTls = (): void => {
      smtpStage = "upgrading";
      socket.off("data", onData);
      buffer.fill(0);
      buffer = Buffer.alloc(0);
      const secure = new TLSSocket(socket, { isServer: true, secureContext, requestCert: false });
      state.sockets.add(secure);
      secure.setTimeout(5_000);
      secure.once("secure", () => { state.tlsHandshakeCount += 1; processPostTls(secure); });
      secure.on("timeout", () => secure.destroy());
      secure.on("error", () => undefined);
      secure.once("close", () => state.sockets.delete(secure));
    };

    const processSmtp = (): void => {
      while (smtpStage !== "upgrading") {
        const end = buffer.indexOf("\r\n");
        if (end < 0) { if (buffer.length > maxSmtpLineBytes) fail(); return; }
        const line = buffer.subarray(0, end).toString("ascii");
        const next = Buffer.from(buffer.subarray(end + 2));
        buffer.fill(0);
        buffer = next;
        if (smtpStage === "ehlo") {
          const match = /^EHLO ([a-z0-9.-]{1,253})$/u.exec(line);
          if (!match?.[1] || !acceptProof(match[1])) { fail(); return; }
          state.exactEhloCount += 1;
          smtpStage = "starttls";
          socket.write(`250-${state.endpointBaseHostname}\r\n250-STARTTLS\r\n250 SIZE 1024\r\n`);
        } else {
          if (line !== "STARTTLS" || buffer.length !== 0) { fail(); return; }
          state.startTlsCommandCount += 1;
          socket.write("220 2.0.0 Ready to start TLS\r\n", startTls);
          return;
        }
      }
    };

    function onData(chunk: Buffer): void {
      if (buffer.length + chunk.length > maxInboundBytes) { fail(); return; }
      buffer = Buffer.concat([buffer, chunk]);
      if (state!.mode === "direct-tls") processDirect();
      else if (state!.mode === "raw-public") processRaw();
      else processSmtp();
    }

    if (state.mode === "smtp-starttls-public" || state.mode === "smtp-starttls-secret") {
      socket.write(`220 s43-${state.greetingTag}.${state.endpointBaseHostname} ESMTP SBX043\r\n`);
      state.greetingWriteCount += 1;
    }
    socket.on("data", onData);
    socket.on("timeout", () => socket.destroy());
    socket.on("error", () => undefined);
    socket.once("close", () => { buffer.fill(0); state.sockets.delete(socket); });
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
      json(response, 200, { ok: true, testId: SBX043_TEST_ID, configurationEpoch, tlsReady: true,
        listener: { hostname: options.listenerHostname, ipv4: options.listenerIPv4, port: actualListenerPort },
        activeCase: activeKey !== undefined });
      return;
    }
    if (!authorized(request, options.key)) { json(response, 401, { ok: false }); return; }
    const match = /^\/v1\/sbx043\/admin\/cases\/([0-9a-f-]{36})\/([a-z0-9-]{1,63})$/u.exec(url.pathname);
    if (!match?.[1] || !match[2] || !uuidPattern.test(match[1]) || !casePattern.test(match[2])) { json(response, 404, { ok: false }); return; }
    const key = `${match[1]}:${match[2]}`;
    try {
      if (request.method === "POST") {
        if (activeKey !== undefined || cases.has(key)) { json(response, 409, { ok: false, reason: "case-active" }); return; }
        const config = parseConfiguration(await readJson(request), options.listenerHostname);
        if (config.runId !== match[1] || config.caseId !== match[2]) throw new Error("path/body identity mismatch");
        const greetingTag = deriveSbx043GreetingTag(options.key, config.runId, config.caseId);
        const expectedPublicProofName = config.expectedPublicCanary ? `s43p-${config.expectedPublicCanary}.${config.endpointBaseHostname}` : undefined;
        const expectedOperationId = config.expectedPublicCanary
          ? deriveSbx043PublicOperationId(options.key, config.runId, config.caseId, config.expectedPublicCanary)
          : deriveSbx043SecretOperationId(options.key, config.runId, config.caseId, config.expectedSecretCommitment!);
        const state: CaseState = {
          ...config, greetingTag, ...(expectedPublicProofName ? { expectedPublicProofName } : {}), expectedOperationId,
          connectionCount: 0, greetingWriteCount: 0, exactEhloCount: 0, startTlsCommandCount: 0,
          tlsHandshakeCount: 0, postTlsEhloCount: 0, clientHelloCount: 0, rawFrameCount: 0,
          exactPayloadReceiptCount: 0, malformedCount: 0, withinConfiguredWindow: true,
          secretCommitmentMatched: false, sockets: new Set(),
        };
        cases.set(key, state);
        activeKey = key;
        json(response, 201, { configured: true, greetingTag, expectedOperationId, configurationEpoch });
        return;
      }
      const state = cases.get(key);
      if (request.method === "GET") { json(response, 200, statusOf(state, { hostname: options.listenerHostname, ipv4: options.listenerIPv4, port: actualListenerPort, epoch: configurationEpoch })); return; }
      if (request.method === "DELETE") {
        if (state) for (const activeSocket of state.sockets) activeSocket.destroy();
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
    admin.listen(options.adminPort, adminHost, () => { admin.off("error", reject); resolveListen(); });
  });
  const adminAddress = admin.address();
  if (!adminAddress || typeof adminAddress === "string") throw new Error("admin address unavailable");
  return {
    adminOrigin: `http://${adminHost}:${adminAddress.port}`,
    listenerPort: actualListenerPort,
    configurationEpoch,
    async close(): Promise<void> {
      for (const state of cases.values()) for (const activeSocket of state.sockets) activeSocket.destroy();
      await Promise.all([closeServer(admin), closeServer(listener)]);
    },
  };
}

async function cli(): Promise<void> {
  const key = process.env.SBX043_ADMIN_KEY;
  const listenerHostname = process.env.SBX043_DENIED_HOSTNAME;
  const listenerIPv4 = process.env.SBX043_DENIED_IPV4;
  const tlsKeyPath = process.env.SBX043_TLS_KEY_PATH;
  const tlsCertPath = process.env.SBX043_TLS_CERT_PATH;
  const listenerPort = Number(process.env.SBX043_DENIED_PORT ?? "587");
  const adminPort = Number(process.env.SBX043_ADMIN_PORT ?? "43143");
  if (!key || !listenerHostname || !listenerIPv4 || !tlsKeyPath || !tlsCertPath) throw new Error("SBX043 admin, listener, and TLS environment values are required");
  const [tlsKey, tlsCert] = await Promise.all([readFile(tlsKeyPath), readFile(tlsCertPath)]);
  const receiver = await startSbx043Receiver({ key, tlsKey, tlsCert, adminPort, listenerPort, listenerHostname, listenerIPv4 });
  process.stdout.write(`${JSON.stringify({ ready: true, testId: SBX043_TEST_ID, adminOrigin: receiver.adminOrigin,
    listenerPort: receiver.listenerPort, configurationEpoch: receiver.configurationEpoch })}\n`);
  const stop = async (): Promise<void> => { await receiver.close(); process.exit(0); };
  process.once("SIGINT", () => { void stop(); });
  process.once("SIGTERM", () => { void stop(); });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void cli().catch((error: unknown) => { process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
}
