import "dotenv/config";

import { createHash, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { isIP, type AddressInfo } from "node:net";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import {
  SBX041_TRANSFORM_HEADER,
  deriveSbx041OperationId,
  type Sbx041AEvent,
  type Sbx041BEvent,
  type Sbx041ReceiverSnapshot,
} from "./verdict.js";

const MAX_ADMIN_BODY = 16 * 1024;

export interface Sbx041ReceiverConfiguration {
  runId: string;
  aHost: string;
  bHost: string;
  correlationCanary: string;
  transformHeaderSha256: string;
}

interface RunState {
  configuration: Sbx041ReceiverConfiguration;
  a: Sbx041AEvent[];
  b: Sbx041BEvent[];
}

export interface Sbx041ReceiverOptions {
  adminKey: string;
  aPublicOrigin: string;
  bPublicOrigin: string;
  aPort?: number;
  bPort?: number;
  host?: string;
}

export interface Sbx041ReceiverHandle {
  aServer: Server;
  bServer: Server;
  aPort: number;
  bPort: number;
  close(): Promise<void>;
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function fixedDigest(value: string): Buffer {
  return createHash("sha256").update(value).digest();
}

function adminAuthorized(request: IncomingMessage, expected: string): boolean {
  const authorization = request.headers.authorization;
  return typeof authorization === "string" && authorization.startsWith("Bearer ") &&
    timingSafeEqual(fixedDigest(authorization.slice(7)), fixedDigest(expected));
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

function safeString(value: unknown, name: string, maximum = 512): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[\0\r\n]/u.test(value)) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

function canonicalHost(value: unknown, name: string): string {
  const host = safeString(value, name, 253);
  if (host !== host.toLowerCase() || host.endsWith(".") || isIP(host) !== 0 ||
    host.split(".").some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))) {
    throw new Error(`${name} must be a canonical lower-case hostname`);
  }
  return host;
}

function exactOrigin(raw: string, name: string): URL {
  const origin = new URL(raw);
  if (origin.protocol !== "https:" || raw !== origin.origin || origin.port || origin.username || origin.password ||
    origin.pathname !== "/" || origin.search || origin.hash || origin.hostname !== origin.hostname.toLowerCase() ||
    isIP(origin.hostname) !== 0) throw new Error(`${name} must be an exact lower-case HTTPS origin`);
  return origin;
}

function exactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function validateConfiguration(value: unknown, a: URL, b: URL): Sbx041ReceiverConfiguration {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("configuration must be an object");
  const input = value as Record<string, unknown>;
  if (!exactKeys(input, ["aHost", "bHost", "correlationCanary", "runId", "transformHeaderSha256"])) {
    throw new Error("configuration fields are not exact");
  }
  const result = {
    runId: safeString(input.runId, "runId", 128),
    aHost: canonicalHost(input.aHost, "aHost"),
    bHost: canonicalHost(input.bHost, "bHost"),
    correlationCanary: safeString(input.correlationCanary, "correlationCanary", 128),
    transformHeaderSha256: safeString(input.transformHeaderSha256, "transformHeaderSha256", 64),
  };
  if (!/^[A-Za-z0-9._:-]+$/u.test(result.runId) || !/^[A-Za-z0-9._:-]+$/u.test(result.correlationCanary)) {
    throw new Error("run/canary characters are invalid");
  }
  if (!/^[a-f0-9]{64}$/u.test(result.transformHeaderSha256)) throw new Error("transform commitment is invalid");
  if (result.aHost !== a.hostname || result.bHost !== b.hostname || result.aHost === result.bHost) {
    throw new Error("configuration hosts do not match the owned origins");
  }
  return result;
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk);
    length += bytes.length;
    if (length > MAX_ADMIN_BODY) throw new Error("admin body exceeded its bound");
    chunks.push(bytes);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function rawHeaderValues(request: IncomingMessage, wanted: string): string[] {
  const values: string[] = [];
  for (let index = 0; index + 1 < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === wanted) values.push(request.rawHeaders[index + 1] ?? "");
  }
  return values;
}

function headerEvidence(request: IncomingMessage, expectedSha256: string): {
  lines: number;
  values: number;
  sha?: string;
  matched: boolean;
} {
  const raw = rawHeaderValues(request, SBX041_TRANSFORM_HEADER);
  const normalized = request.headers[SBX041_TRANSFORM_HEADER];
  const values = Array.isArray(normalized) ? normalized : normalized === undefined ? [] : [normalized];
  const digest = raw.length === 1 && values.length === 1 ? sha256(raw[0]!) : undefined;
  return { lines: raw.length, values: values.length, ...(digest ? { sha: digest } : {}), matched: digest === expectedSha256 };
}

function canaryMatched(request: IncomingMessage, expected: string): boolean {
  const raw = rawHeaderValues(request, "x-sbx041-canary");
  return raw.length === 1 && raw[0] === expected;
}

function hostEvidence(request: IncomingMessage, expected: string): { lines: number; values: number; matched: boolean } {
  const raw = rawHeaderValues(request, "host");
  const normalized = request.headers.host;
  const values = typeof normalized === "string" ? [normalized] : [];
  return { lines: raw.length, values: values.length, matched: raw.length === 1 && values.length === 1 && raw[0] === expected };
}

function caseId(request: IncomingMessage): string | undefined {
  const raw = rawHeaderValues(request, "x-sbx041-case");
  return raw.length === 1 && /^[A-Za-z0-9._:-]{1,128}$/u.test(raw[0]!) ? raw[0] : undefined;
}

function runPath(pathname: string, prefix: string): string | undefined {
  if (!pathname.startsWith(prefix)) return undefined;
  const encoded = pathname.slice(prefix.length);
  if (!encoded || encoded.includes("/")) return undefined;
  try {
    const decoded = decodeURIComponent(encoded);
    return /^[A-Za-z0-9._:-]{1,128}$/u.test(decoded) ? decoded : undefined;
  } catch {
    return undefined;
  }
}

function snapshot(state: RunState): Sbx041ReceiverSnapshot {
  return { configured: true, a: [...state.a], b: [...state.b] };
}

export async function startSbx041Receiver(options: Sbx041ReceiverOptions): Promise<Sbx041ReceiverHandle> {
  if (options.adminKey.length < 32) throw new Error("adminKey must contain at least 32 characters");
  const aOrigin = exactOrigin(options.aPublicOrigin, "aPublicOrigin");
  const bOrigin = exactOrigin(options.bPublicOrigin, "bPublicOrigin");
  if (aOrigin.origin === bOrigin.origin) throw new Error("A and B origins must be distinct");
  const states = new Map<string, RunState>();

  const aServer = createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", "http://receiver.invalid");
      if (url.pathname === "/healthz") {
        sendJson(response, 200, {
          ok: true,
          service: "sbx041-a-receiver",
          hostMatched: hostEvidence(request, aOrigin.hostname).matched,
        });
        return;
      }
      const adminRunId = runPath(url.pathname, "/v1/sbx041/admin/runs/");
      if (adminRunId !== undefined) {
        if (!adminAuthorized(request, options.adminKey)) { sendEmpty(response, 401); return; }
        if (request.method === "PUT") {
          const checked = validateConfiguration(await readJson(request), aOrigin, bOrigin);
          if (checked.runId !== adminRunId) throw new Error("configuration runId does not match path");
          states.set(adminRunId, { configuration: checked, a: [], b: [] });
          sendEmpty(response, 204);
          return;
        }
        if (request.method === "GET") {
          const state = states.get(adminRunId);
          if (!state) { sendEmpty(response, 404); return; }
          sendJson(response, 200, snapshot(state));
          return;
        }
        if (request.method === "DELETE") {
          const existed = states.delete(adminRunId);
          sendEmpty(response, existed ? 204 : 404);
          return;
        }
        sendEmpty(response, 405);
        return;
      }

      const controlRunId = runPath(url.pathname, "/v1/sbx041/control/");
      const ticketRunId = runPath(url.pathname, "/v1/sbx041/ticket/");
      const runId = controlRunId ?? ticketRunId;
      if (runId !== undefined) {
        const state = states.get(runId);
        if (!state) { sendEmpty(response, 404); return; }
        const marker = caseId(request);
        const ticketCases = new Set(["fronted-sni-resume-ticket", "fronted-nosni-resume-ticket"]);
        const wantedCase = controlRunId !== undefined ? "normal-a" : marker;
        const wantedKind = controlRunId !== undefined ? "control" as const : "ticket" as const;
        const transform = headerEvidence(request, state.configuration.transformHeaderSha256);
        const host = hostEvidence(request, state.configuration.aHost);
        const acceptedCase = controlRunId !== undefined ? marker === "normal-a" : marker !== undefined && ticketCases.has(marker);
        const accepted = request.method === "GET" && marker === wantedCase && acceptedCase && host.matched &&
          canaryMatched(request, state.configuration.correlationCanary) && transform.matched;
        const operationId = accepted
          ? deriveSbx041OperationId(options.adminKey, runId, wantedCase!, state.configuration.transformHeaderSha256)
          : undefined;
        state.a.push({
          observedAt: new Date().toISOString(),
          caseId: marker ?? "invalid",
          kind: wantedKind,
          method: request.method ?? "",
          requestTarget: request.url ?? "",
          hostHeaderLines: host.lines,
          hostHeaderValues: host.values,
          hostMatched: host.matched,
          canaryMatched: canaryMatched(request, state.configuration.correlationCanary),
          transformHeaderLines: transform.lines,
          transformHeaderValues: transform.values,
          ...(transform.sha ? { transformHeaderSha256: transform.sha } : {}),
          transformCommitmentMatched: transform.matched,
          responseStatus: accepted ? 200 : 401,
          ...(operationId ? { operationId } : {}),
        });
        if (accepted) sendJson(response, 200, { operationId });
        else sendEmpty(response, 401);
        return;
      }
      sendEmpty(response, 404);
    } catch {
      sendEmpty(response, 400);
    }
  });

  const bServer = createServer((request, response) => {
    try {
      const url = new URL(request.url ?? "/", "http://receiver.invalid");
      if (url.pathname === "/healthz") {
        sendJson(response, 200, {
          ok: true,
          service: "sbx041-b-receiver",
          hostMatched: hostEvidence(request, bOrigin.hostname).matched,
        });
        return;
      }
      const directRunId = runPath(url.pathname, "/v1/sbx041/direct/");
      const frontedRunId = runPath(url.pathname, "/v1/sbx041/fronted-control/");
      const actionRunId = runPath(url.pathname, "/v1/sbx041/action/");
      const runId = directRunId ?? frontedRunId ?? actionRunId;
      if (runId === undefined) { sendEmpty(response, 404); return; }
      const state = states.get(runId);
      if (!state) { sendEmpty(response, 404); return; }
      const marker = caseId(request);
      const transform = headerEvidence(request, state.configuration.transformHeaderSha256);
      const host = hostEvidence(request, state.configuration.bHost);
      const isAction = actionRunId !== undefined;
      const isFrontedControl = frontedRunId !== undefined;
      const attackCases = new Set(["fronted-sni-resume-attack", "fronted-nosni-resume-attack"]);
      const accepted = isAction && request.method === "GET" && marker !== undefined && attackCases.has(marker) &&
        host.matched && canaryMatched(request, state.configuration.correlationCanary) && transform.matched;
      const operationId = accepted
        ? deriveSbx041OperationId(options.adminKey, runId, marker!, state.configuration.transformHeaderSha256)
        : undefined;
      const event: Sbx041BEvent = {
        observedAt: new Date().toISOString(),
        caseId: marker ?? "invalid",
        kind: isAction ? "action" : isFrontedControl ? "fronted-control" : "direct",
        method: request.method ?? "",
        requestTarget: request.url ?? "",
        hostHeaderLines: host.lines,
        hostHeaderValues: host.values,
        hostMatched: host.matched,
        canaryMatched: canaryMatched(request, state.configuration.correlationCanary),
        transformHeaderLines: transform.lines,
        transformHeaderValues: transform.values,
        ...(transform.sha ? { transformHeaderSha256: transform.sha } : {}),
        transformCommitmentMatched: transform.matched,
        responseStatus: accepted ? 200 : isAction ? 401 : isFrontedControl ? 409 : 403,
        ...(operationId ? { operationId } : {}),
      };
      state.b.push(event);
      if (accepted) sendJson(response, 200, { operationId });
      else sendEmpty(response, isAction ? 401 : isFrontedControl ? 409 : 403);
    } catch {
      sendEmpty(response, 400);
    }
  });

  const host = options.host ?? "127.0.0.1";
  const aPort = options.aPort ?? 43_141;
  const bPort = options.bPort ?? 43_142;
  await new Promise<void>((resolveListen, reject) => {
    aServer.once("error", reject);
    aServer.listen(aPort, host, () => { aServer.off("error", reject); resolveListen(); });
  });
  try {
    await new Promise<void>((resolveListen, reject) => {
      bServer.once("error", reject);
      bServer.listen(bPort, host, () => { bServer.off("error", reject); resolveListen(); });
    });
  } catch (error) {
    await new Promise<void>((resolveClose) => aServer.close(() => resolveClose()));
    throw error;
  }
  return {
    aServer,
    bServer,
    aPort: (aServer.address() as AddressInfo).port,
    bPort: (bServer.address() as AddressInfo).port,
    async close() {
      await Promise.all([aServer, bServer].map((server) => new Promise<void>((resolveClose, reject) =>
        server.close((error) => error ? reject(error) : resolveClose()))));
    },
  };
}

async function main(): Promise<void> {
  const adminKey = process.env.SBX041_ADMIN_KEY ?? "";
  const handle = await startSbx041Receiver({
    adminKey,
    aPublicOrigin: process.env.SBX041_A_PUBLIC_ORIGIN ?? "",
    bPublicOrigin: process.env.SBX041_B_PUBLIC_ORIGIN ?? "",
    aPort: Number(process.env.SBX041_A_PORT ?? 43_141),
    bPort: Number(process.env.SBX041_B_PORT ?? 43_142),
  });
  process.stdout.write(`${JSON.stringify({ ready: true, aPort: handle.aPort, bPort: handle.bPort })}\n`);
  await new Promise<void>((resolveStop) => {
    const stop = () => resolveStop();
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
  await handle.close();
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
