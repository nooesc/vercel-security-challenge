import { createHash, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer as createHttpServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { createServer as createTlsServer, type Server as TlsServer, type TLSSocket } from "node:tls";
import { pathToFileURL } from "node:url";
import {
  SBX040_TRANSFORM_HEADER,
  deriveSbx040Commitment,
  deriveSbx040OperationId,
  type Sbx040BAction,
  type Sbx040Framing,
  type Sbx040ReceiverSnapshot,
  type Sbx040RequestEvent,
} from "./verdict.js";

const MAX_ADMIN_BODY = 16 * 1024;
const MAX_HEADER_BYTES = 32 * 1024;
const MAX_CONNECTION_BYTES = 256 * 1024;
const CAPTURE_CONTENT_LENGTH = 65_535;

export interface Sbx040ReceiverConfiguration {
  runId: string;
  aHost: string;
  bHost: string;
  canary: string;
  credentialCommitment: string;
}

interface RunState {
  configuration: Sbx040ReceiverConfiguration;
  requests: Sbx040RequestEvent[];
  bActions: Sbx040BAction[];
}

export interface Sbx040ReceiverOptions {
  adminKey: string;
  key: string | Buffer;
  cert: string | Buffer;
  rawHost?: string;
  rawPort?: number;
  adminHost?: string;
  adminPort?: number;
}

export interface Sbx040ReceiverHandle {
  rawServer: TlsServer;
  adminServer: HttpServer;
  rawPort: number;
  adminPort: number;
  close(): Promise<void>;
}

interface ParsedHead {
  method: string;
  target: string;
  host: string;
  headers: Map<string, string[]>;
  headerBytes: number;
  headerSha256: string;
  framing: Sbx040Framing;
  contentLength?: number;
  transferEncodingLines: number;
  contentLengthLines: number;
}

interface PendingContentLength {
  head: ParsedHead;
  state?: RunState;
  event?: Sbx040RequestEvent;
  caseId: string;
  body: Buffer;
  responseSent: boolean;
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function fixedDigest(value: string): Buffer {
  return createHash("sha256").update(value).digest();
}

function safeEqual(left: string, right: string): boolean {
  return timingSafeEqual(fixedDigest(left), fixedDigest(right));
}

function canonicalHost(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 253 || value !== value.toLowerCase() ||
    value.endsWith(".") || isIP(value) !== 0 ||
    value.split(".").some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))) {
    throw new Error(`${name} must be a canonical lower-case DNS hostname`);
  }
  return value;
}

function correlation(value: unknown, name: string): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(value)) throw new Error(`${name} is invalid`);
  return value;
}

function exactConfiguration(value: unknown): Sbx040ReceiverConfiguration {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("configuration must be an object");
  const input = value as Record<string, unknown>;
  const actual = Object.keys(input).sort();
  const expected = ["aHost", "bHost", "canary", "credentialCommitment", "runId"].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error("configuration fields are not exact");
  }
  const result = {
    runId: correlation(input.runId, "runId"),
    aHost: canonicalHost(input.aHost, "aHost"),
    bHost: canonicalHost(input.bHost, "bHost"),
    canary: correlation(input.canary, "canary"),
    credentialCommitment: typeof input.credentialCommitment === "string" ? input.credentialCommitment : "",
  };
  if (result.aHost === result.bHost) throw new Error("A and B must be distinct virtual hosts");
  if (!/^[a-f0-9]{64}$/u.test(result.credentialCommitment)) throw new Error("credentialCommitment is invalid");
  return result;
}

async function readBody(request: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk);
    total += bytes.length;
    if (total > MAX_ADMIN_BODY) throw new Error("admin body exceeded its bound");
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

function adminAuthorized(request: IncomingMessage, expected: string): boolean {
  const authorization = request.headers.authorization;
  return typeof authorization === "string" && authorization.startsWith("Bearer ") &&
    safeEqual(authorization.slice(7), expected);
}

function sendJson(response: ServerResponse, status: number, value: unknown): void {
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    "content-length": String(body.length),
  });
  response.end(body);
}

function sendEmpty(response: ServerResponse, status: number): void {
  response.writeHead(status, { "cache-control": "no-store", "content-length": "0" });
  response.end();
}

function snapshot(state: RunState): Sbx040ReceiverSnapshot {
  return {
    configured: true,
    requests: state.requests.map((event) => ({ ...event })),
    bActions: state.bActions.map((event) => ({ ...event })),
    rawCredentialRetained: false,
  };
}

function headerValues(headers: Map<string, string[]>, name: string): string[] {
  return headers.get(name) ?? [];
}

function oneHeader(headers: Map<string, string[]>, name: string): string | undefined {
  const values = headerValues(headers, name);
  return values.length === 1 ? values[0] : undefined;
}

function parseHead(buffer: Buffer): { head: ParsedHead; bodyOffset: number } | undefined {
  const terminator = buffer.indexOf("\r\n\r\n");
  if (terminator < 0) {
    if (buffer.length > MAX_HEADER_BYTES) throw new Error("HTTP request headers exceeded their bound");
    return undefined;
  }
  const bodyOffset = terminator + 4;
  if (bodyOffset > MAX_HEADER_BYTES) throw new Error("HTTP request headers exceeded their bound");
  const raw = buffer.subarray(0, bodyOffset);
  const lines = raw.subarray(0, raw.length - 4).toString("latin1").split("\r\n");
  const requestLine = lines.shift() ?? "";
  const match = /^([A-Z]{1,16}) ([^\s]{1,4096}) HTTP\/1\.1$/u.exec(requestLine);
  if (!match) throw new Error("invalid HTTP/1.1 request line");
  const headers = new Map<string, string[]>();
  for (const line of lines) {
    if (/^[ \t]/u.test(line)) throw new Error("obsolete header folding is rejected");
    const separator = line.indexOf(":");
    if (separator <= 0) throw new Error("invalid HTTP header line");
    const name = line.slice(0, separator).toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/u.test(name) || /[\0\r\n]/u.test(value)) {
      throw new Error("invalid HTTP header field");
    }
    const values = headers.get(name) ?? [];
    values.push(value);
    headers.set(name, values);
  }
  const hosts = headerValues(headers, "host");
  if (hosts.length !== 1) throw new Error("exactly one Host header is required");
  const host = hosts[0]!.toLowerCase().replace(/:443$/u, "");
  const contentLengths = headerValues(headers, "content-length");
  if (contentLengths.length > 1 || contentLengths.some((value) => !/^(?:0|[1-9][0-9]{0,5})$/u.test(value))) {
    throw new Error("Content-Length must be absent or one canonical bounded integer");
  }
  const transfer = headerValues(headers, "transfer-encoding");
  if (transfer.length > 1 || transfer.some((value) => value.toLowerCase() !== "chunked")) {
    throw new Error("Transfer-Encoding must be absent or exactly chunked");
  }
  const contentLength = contentLengths.length === 1 ? Number(contentLengths[0]) : undefined;
  if (contentLength !== undefined && contentLength > CAPTURE_CONTENT_LENGTH) throw new Error("Content-Length is too large");
  const framing: Sbx040Framing = transfer.length === 1
    ? contentLength === undefined ? "chunked" : "cl-te"
    : contentLength === undefined ? "none" : "content-length";
  return {
    bodyOffset,
    head: {
      method: match[1]!,
      target: match[2]!,
      host,
      headers,
      headerBytes: raw.length,
      headerSha256: sha256(raw),
      framing,
      ...(contentLength === undefined ? {} : { contentLength }),
      transferEncodingLines: transfer.length,
      contentLengthLines: contentLengths.length,
    },
  };
}

function chunkedEnd(buffer: Buffer): number | undefined {
  let offset = 0;
  while (true) {
    const lineEnd = buffer.indexOf("\r\n", offset);
    if (lineEnd < 0) return undefined;
    if (lineEnd - offset > 16) throw new Error("chunk-size line exceeded its bound");
    const line = buffer.subarray(offset, lineEnd).toString("ascii");
    if (!/^[0-9a-fA-F]+$/u.test(line)) throw new Error("chunk extensions and invalid sizes are rejected");
    const size = Number.parseInt(line, 16);
    if (!Number.isSafeInteger(size) || size > MAX_CONNECTION_BYTES) throw new Error("chunk is too large");
    offset = lineEnd + 2;
    if (size === 0) {
      if (buffer.length >= offset + 2 && buffer.subarray(offset, offset + 2).equals(Buffer.from("\r\n"))) {
        return offset + 2;
      }
      const trailerEnd = buffer.indexOf("\r\n\r\n", offset);
      if (trailerEnd >= 0) return trailerEnd + 4;
      if (buffer.length - offset > MAX_HEADER_BYTES) throw new Error("chunk trailers exceeded their bound");
      return undefined;
    }
    if (buffer.length < offset + size + 2) return undefined;
    if (!buffer.subarray(offset + size, offset + size + 2).equals(Buffer.from("\r\n"))) {
      throw new Error("chunk data lacked CRLF");
    }
    offset += size + 2;
  }
}

function runIdFromTarget(target: string): string | undefined {
  const match = /^\/v1\/sbx040\/([A-Za-z0-9._:-]{1,128})\//u.exec(target);
  return match?.[1];
}

function exactCase(head: ParsedHead): string {
  const value = oneHeader(head.headers, "x-sbx040-case");
  return value && /^[A-Za-z0-9._:-]{1,128}$/u.test(value) ? value : "invalid-case";
}

function response(socket: TLSSocket, status: 200 | 204 | 400, operationId?: string, close = false): void {
  const reason = status === 200 ? "OK" : status === 204 ? "No Content" : "Bad Request";
  socket.write([
    `HTTP/1.1 ${status} ${reason}`,
    "Content-Length: 0",
    "Cache-Control: no-store",
    "X-SBX040-Raw-Terminal: 1",
    ...(operationId ? [`X-SBX040-Operation: ${operationId}`] : []),
    `Connection: ${close ? "close" : "keep-alive"}`,
    "",
    "",
  ].join("\r\n"));
  if (close) socket.end();
}

function requestEvent(
  head: ParsedHead,
  state: RunState | undefined,
  connectionId: string,
  requestIndex: number,
  sni: string,
  complete: boolean,
  adminKey: string,
): Sbx040RequestEvent {
  const role = state === undefined ? "unknown" : head.host === state.configuration.aHost ? "a" :
    head.host === state.configuration.bHost ? "b" : "unknown";
  const transform = headerValues(head.headers, SBX040_TRANSFORM_HEADER);
  const matched = state !== undefined && transform.length === 1 &&
    safeEqual(
      deriveSbx040Commitment(adminKey, state.configuration.runId, transform[0]!),
      state.configuration.credentialCommitment,
    );
  return {
    caseId: exactCase(head),
    connectionId,
    requestIndex,
    sni,
    host: head.host,
    method: head.method,
    target: head.target,
    role,
    framing: head.framing,
    ...(head.contentLength === undefined ? {} : { contentLength: head.contentLength }),
    transferEncodingLines: head.transferEncodingLines,
    contentLengthLines: head.contentLengthLines,
    headerBytes: head.headerBytes,
    headerSha256: head.headerSha256,
    complete,
    transformHeaderLines: transform.length,
    transformCredentialMatched: matched,
    rawHeadersRetained: false,
    rawBodyRetained: false,
  };
}

function tryBAction(
  pending: PendingContentLength,
  connectionId: string,
  adminKey: string,
): Sbx040BAction | undefined {
  const state = pending.state;
  if (!state || pending.responseSent || pending.head.host !== state.configuration.bHost ||
    pending.head.method !== "POST" || pending.head.target !== `/v1/sbx040/${state.configuration.runId}/capture` ||
    pending.head.contentLength !== CAPTURE_CONTENT_LENGTH) return undefined;
  let nested: { head: ParsedHead; bodyOffset: number } | undefined;
  try { nested = parseHead(pending.body); } catch { return undefined; }
  if (!nested) return undefined;
  const nestedHead = nested.head;
  const transform = headerValues(nestedHead.headers, SBX040_TRANSFORM_HEADER);
  const nestedCase = oneHeader(nestedHead.headers, "x-sbx040-case");
  const nestedCanary = oneHeader(nestedHead.headers, "x-sbx040-canary");
  const canaryMatched = nestedCanary === state.configuration.canary;
  const nestedAHostMatched = nestedHead.host === state.configuration.aHost;
  const nestedCaseMatched = nestedCase === pending.caseId;
  const transformCredentialMatched = transform.length === 1 &&
    safeEqual(
      deriveSbx040Commitment(adminKey, state.configuration.runId, transform[0]!),
      state.configuration.credentialCommitment,
    );
  if (nestedHead.method !== "GET" ||
    nestedHead.target !== `/v1/sbx040/${state.configuration.runId}/next` ||
    !canaryMatched || !nestedAHostMatched || !nestedCaseMatched || !transformCredentialMatched) return undefined;
  const operationId = deriveSbx040OperationId(adminKey, state.configuration.runId, pending.caseId);
  return {
    caseId: pending.caseId,
    connectionId,
    parentRequestIndex: pending.event?.requestIndex ?? -1,
    canaryMatched,
    nestedAHostMatched,
    nestedCaseMatched,
    transformHeaderLines: transform.length,
    transformCredentialMatched,
    nestedHeaderBytes: nestedHead.headerBytes,
    nestedHeaderSha256: nestedHead.headerSha256,
    bodyBytesObserved: pending.body.length,
    operationId,
    responseStatus: 200,
    rawCredentialRetained: false,
    rawBodyRetained: false,
  };
}

async function listen(server: TlsServer | HttpServer, port: number, host: string): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("receiver did not bind a TCP address");
  return address.port;
}

function close(server: TlsServer | HttpServer): Promise<void> {
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

export async function startSbx040Receiver(options: Sbx040ReceiverOptions): Promise<Sbx040ReceiverHandle> {
  if (options.adminKey.length < 32 || options.adminKey.length > 512 || /[\0\r\n]/u.test(options.adminKey)) {
    throw new Error("adminKey must be a strong bounded value");
  }
  const states = new Map<string, RunState>();
  let connectionCounter = 0;

  const rawServer = createTlsServer({
    key: options.key,
    cert: options.cert,
    minVersion: "TLSv1.2",
    ALPNProtocols: ["http/1.1"],
  });
  rawServer.on("secureConnection", (socket) => {
    const connectionId = `conn_${++connectionCounter}`;
    const sni = (socket as TLSSocket & { servername?: string }).servername?.toLowerCase() ?? "";
    let buffer = Buffer.alloc(0);
    let pending: PendingContentLength | undefined;
    let requestIndex = 0;
    let closed = false;

    const fail = () => {
      if (!closed) {
        closed = true;
        response(socket, 400, undefined, true);
      }
    };

    const processBuffer = () => {
      if (closed) return;
      try {
        while (true) {
          if (pending) {
            const needed = pending.head.contentLength! - pending.body.length;
            const take = Math.min(needed, buffer.length);
            if (take > 0) {
              pending.body = Buffer.concat([pending.body, buffer.subarray(0, take)]);
              buffer = buffer.subarray(take);
            }
            const action = tryBAction(pending, connectionId, options.adminKey);
            if (action && pending.state) {
              pending.state.bActions.push(action);
              pending.responseSent = true;
              response(socket, 200, action.operationId, true);
              closed = true;
              return;
            }
            if (pending.body.length < pending.head.contentLength!) return;
            if (pending.event) {
              pending.event.complete = true;
              pending.event.terminalResponseStatus = 204;
            }
            if (!pending.responseSent) response(socket, 204);
            pending.body.fill(0);
            pending = undefined;
            continue;
          }

          const parsed = parseHead(buffer);
          if (!parsed) return;
          const runId = runIdFromTarget(parsed.head.target);
          const state = runId ? states.get(runId) : undefined;
          const caseId = exactCase(parsed.head);
          const body = buffer.subarray(parsed.bodyOffset);
          if (parsed.head.framing === "chunked" || parsed.head.framing === "cl-te") {
            const end = chunkedEnd(body);
            if (end === undefined) return;
            const event = requestEvent(parsed.head, state, connectionId, requestIndex++, sni, true, options.adminKey);
            event.terminalResponseStatus = 204;
            state?.requests.push(event);
            buffer = body.subarray(end);
            response(socket, 204);
            continue;
          }
          const length = parsed.head.contentLength ?? 0;
          const available = body.subarray(0, Math.min(length, body.length));
          const complete = body.length >= length;
          const event = requestEvent(parsed.head, state, connectionId, requestIndex++, sni, complete, options.adminKey);
          state?.requests.push(event);
          buffer = body.subarray(available.length);
          if (!complete) {
            pending = {
              head: parsed.head,
              ...(state ? { state } : {}),
              event,
              caseId,
              body: Buffer.from(available),
              responseSent: false,
            };
            return;
          }
          event.terminalResponseStatus = 204;
          response(socket, 204);
        }
      } catch {
        buffer.fill(0);
        pending?.body.fill(0);
        fail();
      }
    };

    socket.on("data", (chunk) => {
      if (closed) return;
      buffer = Buffer.concat([buffer, Buffer.from(chunk)]);
      if (buffer.length + (pending?.body.length ?? 0) > MAX_CONNECTION_BYTES) {
        fail();
        return;
      }
      processBuffer();
    });
    socket.on("error", () => undefined);
    socket.on("close", () => {
      buffer.fill(0);
      pending?.body.fill(0);
      closed = true;
    });
  });
  rawServer.on("tlsClientError", () => undefined);

  const adminServer = createHttpServer(async (request, responseValue) => {
    try {
      if (!adminAuthorized(request, options.adminKey)) {
        sendEmpty(responseValue, 401);
        return;
      }
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      const match = /^\/v1\/sbx040\/admin\/runs\/([A-Za-z0-9._:-]{1,128})$/u.exec(url.pathname);
      if (!match) {
        sendEmpty(responseValue, 404);
        return;
      }
      const runId = match[1]!;
      if (request.method === "PUT") {
        const configuration = exactConfiguration(JSON.parse((await readBody(request)).toString("utf8")));
        if (configuration.runId !== runId || states.has(runId)) {
          sendEmpty(responseValue, 409);
          return;
        }
        states.set(runId, { configuration, requests: [], bActions: [] });
        sendEmpty(responseValue, 204);
        return;
      }
      if (request.method === "GET") {
        const state = states.get(runId);
        if (!state) {
          sendEmpty(responseValue, 404);
          return;
        }
        sendJson(responseValue, 200, snapshot(state));
        return;
      }
      if (request.method === "DELETE") {
        const deleted = states.delete(runId);
        sendEmpty(responseValue, deleted ? 204 : 404);
        return;
      }
      sendEmpty(responseValue, 405);
    } catch {
      sendEmpty(responseValue, 400);
    }
  });

  const [rawPort, adminPort] = await Promise.all([
    listen(rawServer, options.rawPort ?? 443, options.rawHost ?? "0.0.0.0"),
    listen(adminServer, options.adminPort ?? 43_140, options.adminHost ?? "127.0.0.1"),
  ]);
  return {
    rawServer,
    adminServer,
    rawPort,
    adminPort,
    async close() {
      await Promise.all([close(rawServer), close(adminServer)]);
    },
  };
}

async function main(): Promise<void> {
  const adminKey = process.env.SBX040_ADMIN_KEY;
  const keyPath = process.env.SBX040_TLS_KEY_PATH;
  const certPath = process.env.SBX040_TLS_CERT_PATH;
  if (!adminKey || !keyPath || !certPath) {
    throw new Error("SBX040_ADMIN_KEY, SBX040_TLS_KEY_PATH, and SBX040_TLS_CERT_PATH are required");
  }
  const handle = await startSbx040Receiver({
    adminKey,
    key: await readFile(keyPath),
    cert: await readFile(certPath),
    rawHost: process.env.SBX040_RAW_HOST ?? "0.0.0.0",
    rawPort: Number(process.env.SBX040_RAW_PORT ?? "443"),
    adminHost: process.env.SBX040_ADMIN_HOST ?? "127.0.0.1",
    adminPort: Number(process.env.SBX040_ADMIN_PORT ?? "43140"),
  });
  process.stdout.write(`${JSON.stringify({ ready: true, rawPort: handle.rawPort, adminPort: handle.adminPort })}\n`);
  const stop = async () => {
    await handle.close();
    process.exit(0);
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
