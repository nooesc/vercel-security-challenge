import { createHash, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingHttpHeaders, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { appendFile, mkdir, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { AddressInfo } from "node:net";
import type { ObserverEvent } from "./contracts.js";

const DEFAULT_MAX_BODY_BYTES = 64 * 1024;
const CANARY_HEADER = "x-sbx-harness-canary";

interface BodyMetadata {
  bodyLength: number;
  bodySha256: string;
  tooLarge: boolean;
}

export interface ObserverServerOptions {
  adminKey: string;
  dataPath: string;
  host?: string;
  port?: number;
  maxBodyBytes?: number;
}

export interface RunningObserverServer {
  server: Server;
  baseUrl: string;
  host: string;
  port: number;
  close(): Promise<void>;
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  response.end(JSON.stringify(body));
}

function isSensitiveHeader(name: string): boolean {
  const normalized = name.toLowerCase();
  if (normalized === CANARY_HEADER) return false;
  if (
    normalized === "authorization" ||
    normalized === "proxy-authorization" ||
    normalized === "cookie" ||
    normalized === "set-cookie"
  ) {
    return true;
  }
  return /(^|[-_])(auth|authorization|cookie|token|secret|api[-_]?key|key)([-_]|$)/i.test(normalized);
}

function sanitizeHeaders(headers: IncomingHttpHeaders): Record<string, string | string[]> {
  const sanitized: Record<string, string | string[]> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined || isSensitiveHeader(name)) continue;
    sanitized[name.toLowerCase()] = value;
  }
  return sanitized;
}

function sanitizeRawHeaders(rawHeaders: string[]): string[] {
  const sanitized: string[] = [];
  for (let index = 0; index + 1 < rawHeaders.length; index += 2) {
    const name = rawHeaders[index];
    const value = rawHeaders[index + 1];
    if (name === undefined || value === undefined || isSensitiveHeader(name)) continue;
    sanitized.push(name, value);
  }
  return sanitized;
}

function keyMatches(header: string | undefined, adminKey: string): boolean {
  if (!header?.startsWith("Bearer ")) return false;
  const suppliedDigest = createHash("sha256").update(header.slice(7)).digest();
  const expectedDigest = createHash("sha256").update(adminKey).digest();
  return timingSafeEqual(suppliedDigest, expectedDigest);
}

async function readBodyMetadata(request: IncomingMessage, maxBodyBytes: number): Promise<BodyMetadata> {
  const hash = createHash("sha256");
  let bodyLength = 0;
  let tooLarge = false;

  for await (const unknownChunk of request) {
    const chunk = Buffer.isBuffer(unknownChunk) ? unknownChunk : Buffer.from(unknownChunk as string);
    bodyLength += chunk.length;
    hash.update(chunk);
    if (bodyLength > maxBodyBytes) tooLarge = true;
  }

  return {
    bodyLength,
    bodySha256: hash.digest("hex"),
    tooLarge,
  };
}

class JsonlObserverStore {
  private appendQueue: Promise<void> = Promise.resolve();

  constructor(private readonly dataPath: string) {}

  async initialize(): Promise<void> {
    await mkdir(dirname(this.dataPath), { recursive: true, mode: 0o700 });
  }

  async append(event: ObserverEvent): Promise<void> {
    const operation = this.appendQueue.then(async () => {
      await appendFile(this.dataPath, `${JSON.stringify(event)}\n`, {
        encoding: "utf8",
        mode: 0o600,
      });
    });
    this.appendQueue = operation.catch(() => undefined);
    await operation;
  }

  async forRun(runId: string): Promise<ObserverEvent[]> {
    await this.appendQueue;
    let contents: string;
    try {
      contents = await readFile(this.dataPath, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }

    const events: ObserverEvent[] = [];
    for (const line of contents.split("\n")) {
      if (line.length === 0) continue;
      const event = JSON.parse(line) as ObserverEvent;
      if (event.runId === runId) events.push(event);
    }
    return events;
  }
}

function requiredProbeFields(url: URL): Pick<ObserverEvent, "runId" | "testId" | "caseId" | "canary"> | undefined {
  const runId = url.searchParams.get("__sbx_run");
  const testId = url.searchParams.get("__sbx_test");
  const caseId = url.searchParams.get("__sbx_case");
  const canary = url.searchParams.get("__sbx_canary");
  if (!runId || !testId || !caseId || !canary) return undefined;
  return { runId, testId, caseId, canary };
}

function requestUrl(request: IncomingMessage): URL | undefined {
  try {
    return new URL(request.url ?? "/", "http://observer.invalid");
  } catch {
    return undefined;
  }
}

function eventRoute(pathname: string): string | undefined {
  const match = /^\/v1\/runs\/([^/]+)\/events$/.exec(pathname);
  if (!match?.[1]) return undefined;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return undefined;
  }
}

export async function startObserverServer(options: ObserverServerOptions): Promise<RunningObserverServer> {
  if (options.adminKey.length < 24) throw new Error("observer admin key must contain at least 24 characters");
  const maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes <= 0) {
    throw new Error("maxBodyBytes must be a positive integer");
  }

  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 0;
  const store = new JsonlObserverStore(options.dataPath);
  await store.initialize();

  const server = createServer((request, response) => {
    void (async () => {
      const url = requestUrl(request);
      if (!url) {
        sendJson(response, 400, { error: "invalid request URL" });
        return;
      }

      if (request.method === "GET" && url.pathname === "/healthz") {
        sendJson(response, 200, { ok: true });
        return;
      }

      const queriedRunId = request.method === "GET" ? eventRoute(url.pathname) : undefined;
      if (queriedRunId !== undefined) {
        const authorization = Array.isArray(request.headers.authorization)
          ? request.headers.authorization[0]
          : request.headers.authorization;
        if (!keyMatches(authorization, options.adminKey)) {
          sendJson(response, 401, { error: "unauthorized" });
          return;
        }
        sendJson(response, 200, { events: await store.forRun(queriedRunId) });
        return;
      }

      const fields = requiredProbeFields(url);
      if (!fields) {
        sendJson(response, 404, { error: "not found" });
        return;
      }

      const body = await readBodyMetadata(request, maxBodyBytes);
      const event: ObserverEvent = {
        schemaVersion: 1,
        observedAt: new Date().toISOString(),
        ...fields,
        method: request.method ?? "UNKNOWN",
        rawUrl: request.url ?? "/",
        ...(request.headers.host ? { host: request.headers.host } : {}),
        ...(request.socket.remoteAddress ? { remoteAddress: request.socket.remoteAddress } : {}),
        headers: sanitizeHeaders(request.headers),
        rawHeaders: sanitizeRawHeaders(request.rawHeaders),
        bodyLength: body.bodyLength,
        bodySha256: body.bodySha256,
      };
      await store.append(event);
      if (body.tooLarge) {
        sendJson(response, 413, { error: "request body too large" });
        return;
      }
      response.writeHead(204, { "cache-control": "no-store" });
      response.end();
    })().catch(() => {
      if (!response.headersSent) sendJson(response, 500, { error: "internal server error" });
      else response.destroy();
    });
  });

  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = (): void => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, host);
  });

  const address = server.address() as AddressInfo | null;
  if (!address) {
    server.close();
    throw new Error("observer server did not expose a listening address");
  }
  const urlHost = address.family === "IPv6" ? `[${address.address}]` : address.address;

  return {
    server,
    baseUrl: `http://${urlHost}:${address.port}`,
    host: address.address,
    port: address.port,
    close: async () => {
      if (!server.listening) return;
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    },
  };
}
