import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { Duplex } from "node:stream";
import {
  SBX035_CASE_ID,
  derivePreOperationId,
  deriveSecretCommitment,
  deriveSecretOperationId,
} from "./verdict.js";

const websocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const canaryPattern = /^corr_[A-Za-z0-9_-]{24}$/u;
const secretPattern = /^opsec_[A-Za-z0-9_-]{43}$/u;
const commitmentPattern = /^[a-f0-9]{64}$/u;

interface RunState {
  runId: string;
  caseId: string;
  publicCanary: string;
  socket: Duplex;
  buffer: Buffer;
  stage: "pre" | "secret" | "complete";
  preAccepted: boolean;
  preOperationId?: string;
  registered: boolean;
  secretCommitment?: string;
  expectedOperationId?: string;
  secretAccepted: boolean;
  secretMessageCount: number;
  operationId?: string;
  receiptAt?: string;
}

export interface Sbx035ReceiverStatus {
  configured: boolean;
  preAccepted: boolean;
  preOperationId?: string;
  registered: boolean;
  secretAccepted: boolean;
  secretMessageCount: number;
  operationId?: string;
  receiptAt?: string;
  rawSecretStored: false;
}

export interface Sbx035Receiver {
  origin: string;
  register(runId: string, caseId: string, commitment: string): string;
  status(runId: string): Sbx035ReceiverStatus;
  deleteRun(runId: string): boolean;
  close(): Promise<void>;
}

interface ParsedFrame {
  opcode: number;
  payload: Buffer;
  rest: Buffer;
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

function closeSocket(socket: Duplex, code: number, reason: string): void {
  if (socket.destroyed) return;
  const reasonBytes = Buffer.from(reason, "utf8").subarray(0, 64);
  const payload = Buffer.alloc(2 + reasonBytes.length);
  payload.writeUInt16BE(code, 0);
  reasonBytes.copy(payload, 2);
  socket.end(serverFrame(0x8, payload));
}

function serverFrame(opcode: number, payload: Buffer): Buffer {
  if (payload.length > 125) throw new Error("server frame exceeded 125 bytes");
  return Buffer.concat([Buffer.from([0x80 | opcode, payload.length]), payload]);
}

function serverJson(socket: Duplex, value: unknown): void {
  socket.write(serverFrame(0x1, Buffer.from(JSON.stringify(value), "utf8")));
}

export function parseMaskedClientFrame(buffer: Buffer): ParsedFrame | undefined {
  if (buffer.length < 2) return undefined;
  const first = buffer[0]!;
  const second = buffer[1]!;
  if ((first & 0x70) !== 0 || (first & 0x80) === 0) throw new Error("fragmented or extended frame");
  if ((second & 0x80) === 0) throw new Error("client frame was not masked");
  const length = second & 0x7f;
  if (length > 125) throw new Error("client frame exceeded 125 bytes");
  const offset = 6;
  if (buffer.length < offset + length) return undefined;
  const mask = buffer.subarray(2, 6);
  const payload = Buffer.alloc(length);
  for (let index = 0; index < length; index += 1) payload[index] = buffer[offset + index]! ^ mask[index % 4]!;
  return { opcode: first & 0x0f, payload, rest: buffer.subarray(offset + length) };
}

function validUpgrade(request: IncomingMessage): { runId: string; caseId: string; publicCanary: string } | undefined {
  const host = request.headers.host;
  if (!host || request.method !== "GET") return undefined;
  const url = new URL(request.url ?? "/", `http://${host}`);
  const runId = url.searchParams.get("run") ?? "";
  const caseId = url.searchParams.get("case") ?? "";
  const publicCanary = url.searchParams.get("canary") ?? "";
  const connection = request.headers.connection?.toLowerCase().split(",").map((value) => value.trim()) ?? [];
  const key = request.headers["sec-websocket-key"];
  if (url.pathname !== "/v1/sbx035/ws" || !uuidPattern.test(runId) || caseId !== SBX035_CASE_ID ||
    !canaryPattern.test(publicCanary) || request.headers.upgrade?.toLowerCase() !== "websocket" ||
    !connection.includes("upgrade") || request.headers["sec-websocket-version"] !== "13" ||
    typeof key !== "string") return undefined;
  const decoded = Buffer.from(key, "base64");
  if (decoded.length !== 16 || decoded.toString("base64") !== key) return undefined;
  return { runId, caseId, publicCanary };
}

function statusOf(state: RunState | undefined): Sbx035ReceiverStatus {
  if (!state) {
    return {
      configured: false,
      preAccepted: false,
      registered: false,
      secretAccepted: false,
      secretMessageCount: 0,
      rawSecretStored: false,
    };
  }
  return {
    configured: true,
    preAccepted: state.preAccepted,
    ...(state.preOperationId ? { preOperationId: state.preOperationId } : {}),
    registered: state.registered,
    secretAccepted: state.secretAccepted,
    secretMessageCount: state.secretMessageCount,
    ...(state.operationId ? { operationId: state.operationId } : {}),
    ...(state.receiptAt ? { receiptAt: state.receiptAt } : {}),
    rawSecretStored: false,
  };
}

export async function startSbx035Receiver(options: {
  key: string;
  host?: string;
  port: number;
}): Promise<Sbx035Receiver> {
  if (options.key.length < 32 || options.key.length > 512 || /[\0\r\n]/u.test(options.key)) {
    throw new Error("receiver key must contain from 32 through 512 single-line characters");
  }
  if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65_535) throw new Error("receiver port is invalid");
  const host = options.host ?? "127.0.0.1";
  if (host !== "127.0.0.1") throw new Error("receiver must bind only to 127.0.0.1");
  const runs = new Map<string, RunState>();

  const server: Server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
    if (request.method === "GET" && url.pathname === "/healthz") {
      json(response, 200, { ok: true, service: "sbx035-websocket-receiver" });
      return;
    }
    json(response, 404, { ok: false });
  });

  const drop = (state: RunState, code: number, reason: string): void => {
    closeSocket(state.socket, code, reason);
    state.stage = "complete";
  };

  const processFrames = (state: RunState): void => {
    try {
      while (true) {
        const frame = parseMaskedClientFrame(state.buffer);
        if (!frame) return;
        state.buffer = frame.rest;
        if (frame.opcode === 0x8) {
          state.socket.end(serverFrame(0x8, frame.payload.subarray(0, 125)));
          state.stage = "complete";
          return;
        }
        if (frame.opcode === 0x9) {
          state.socket.write(serverFrame(0xa, frame.payload));
          continue;
        }
        if (frame.opcode !== 0x1) throw new Error("only text messages are accepted");
        const message = frame.payload.toString("utf8");
        if (state.stage === "pre") {
          if (message !== state.publicCanary) throw new Error("public canary mismatch");
          state.preOperationId = derivePreOperationId(options.key, state.runId, state.caseId, state.publicCanary);
          state.preAccepted = true;
          state.stage = "secret";
          serverJson(state.socket, { type: "pre-ack", operationId: state.preOperationId });
          continue;
        }
        if (state.stage !== "secret" || !state.registered || !state.secretCommitment || !state.expectedOperationId) {
          throw new Error("secret action was not registered");
        }
        state.secretMessageCount += 1;
        if (state.secretMessageCount !== 1 || !secretPattern.test(message)) throw new Error("secret message was invalid or repeated");
        const actual = deriveSecretCommitment(options.key, state.runId, state.caseId, message);
        const actualBytes = Buffer.from(actual, "hex");
        const expectedBytes = Buffer.from(state.secretCommitment, "hex");
        if (actualBytes.length !== 32 || expectedBytes.length !== 32 || !timingSafeEqual(actualBytes, expectedBytes)) {
          throw new Error("secret commitment mismatch");
        }
        state.secretAccepted = true;
        state.operationId = state.expectedOperationId;
        state.receiptAt = new Date().toISOString();
        state.stage = "complete";
        serverJson(state.socket, { type: "secret-ack", operationId: state.operationId });
      }
    } catch {
      drop(state, 1008, "invalid action");
    }
  };

  server.on("upgrade", (request, socket, head) => {
    const values = validUpgrade(request);
    const key = request.headers["sec-websocket-key"];
    if (!values || typeof key !== "string" || runs.has(values.runId)) {
      socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
      return;
    }
    const accept = createHash("sha1").update(`${key}${websocketGuid}`).digest("base64");
    socket.write([
      "HTTP/1.1 101 Switching Protocols",
      "Upgrade: websocket",
      "Connection: Upgrade",
      `Sec-WebSocket-Accept: ${accept}`,
      "",
      "",
    ].join("\r\n"));
    const state: RunState = {
      ...values,
      socket,
      buffer: Buffer.from(head),
      stage: "pre",
      preAccepted: false,
      registered: false,
      secretAccepted: false,
      secretMessageCount: 0,
    };
    runs.set(values.runId, state);
    socket.on("data", (chunk: Buffer) => {
      if (state.stage === "complete") return;
      if (state.buffer.length + chunk.length > 2_048) {
        drop(state, 1009, "message too large");
        return;
      }
      state.buffer = Buffer.concat([state.buffer, chunk]);
      processFrames(state);
    });
    socket.on("error", () => { state.stage = "complete"; });
    if (state.buffer.length > 0) processFrames(state);
  });

  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => { server.off("listening", onListening); reject(error); };
    const onListening = (): void => { server.off("error", onError); resolve(); };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(options.port, host);
  });

  return {
    origin: `http://${host}:${options.port}`,
    register(runId, caseId, commitment) {
      if (!uuidPattern.test(runId) || caseId !== SBX035_CASE_ID || !commitmentPattern.test(commitment)) {
        throw new Error("receiver registration was invalid");
      }
      const state = runs.get(runId);
      if (!state || !state.preAccepted || state.registered || state.stage !== "secret") {
        throw new Error("receiver registration did not target one ready socket");
      }
      state.secretCommitment = commitment;
      state.expectedOperationId = deriveSecretOperationId(options.key, runId, caseId, commitment);
      state.registered = true;
      return state.expectedOperationId;
    },
    status(runId) {
      return statusOf(runs.get(runId));
    },
    deleteRun(runId) {
      const state = runs.get(runId);
      if (!state) return false;
      delete state.secretCommitment;
      closeSocket(state.socket, 1000, "run complete");
      return runs.delete(runId);
    },
    async close() {
      for (const state of runs.values()) {
        delete state.secretCommitment;
        closeSocket(state.socket, 1001, "receiver stopping");
      }
      runs.clear();
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
        server.closeAllConnections();
      });
    },
  };
}
