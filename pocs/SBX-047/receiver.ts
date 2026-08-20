import "dotenv/config";

import { createHash, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { isIP, type AddressInfo } from "node:net";
import { pathToFileURL } from "node:url";
import {
  SBX047_TEST_ID,
  SBX047_TRANSFORM_HEADER,
  deriveSbx047OperationId,
  deriveSbx047Receipt,
  deriveSbx047SecretProof,
  sha256Sbx047,
  type Sbx047ObserverEvent,
  type Sbx047ObserverSnapshot,
  type Sbx047RequestKind,
} from "./verdict.js";

const MAX_ADMIN_BODY_BYTES = 16 * 1024;
const TOKEN = /^[A-Za-z0-9._:-]{1,160}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;

export interface Sbx047ReceiverConfiguration {
  runId: string;
  publicHost: string;
  canary: string;
  transformHeaderSha256: string;
}

interface RunState {
  configuration: Sbx047ReceiverConfiguration;
  stagedSecret?: Buffer;
  events: Sbx047ObserverEvent[];
}

export interface Sbx047ReceiverOptions {
  adminKey: string;
  publicOrigin: string;
  host?: string;
  port?: number;
}

export interface Sbx047ReceiverHandle {
  server: Server;
  port: number;
  close(): Promise<void>;
}

function digest(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

function exactOrigin(raw: string): URL {
  const result = new URL(raw);
  if (result.protocol !== "https:" || raw !== result.origin || result.port !== "" ||
      result.username !== "" || result.password !== "" || result.pathname !== "/" ||
      result.search !== "" || result.hash !== "" || result.hostname !== result.hostname.toLowerCase() ||
      result.hostname.endsWith(".") || isIP(result.hostname) !== 0) {
    throw new Error("SBX-047 public origin must be one exact canonical HTTPS hostname origin");
  }
  return result;
}

function exactKeys(value: object, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function sendJson(response: ServerResponse, status: number, value: unknown): void {
  const body = Buffer.from(JSON.stringify(value), "utf8");
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

function rawHeaderValues(request: IncomingMessage, wanted: string): string[] {
  const values: string[] = [];
  for (let index = 0; index + 1 < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === wanted) {
      values.push(request.rawHeaders[index + 1] ?? "");
    }
  }
  return values;
}

function hostEvidence(request: IncomingMessage, expected: string): {
  lines: number;
  values: number;
  matched: boolean;
} {
  const raw = rawHeaderValues(request, "host");
  const normalized = typeof request.headers.host === "string" ? [request.headers.host] : [];
  return {
    lines: raw.length,
    values: normalized.length,
    matched: raw.length === 1 && normalized.length === 1 && raw[0] === expected,
  };
}

function transformEvidence(request: IncomingMessage, expectedSha256: string): {
  lines: number;
  values: number;
  sha256?: string;
  matched: boolean;
} {
  const raw = rawHeaderValues(request, SBX047_TRANSFORM_HEADER);
  const normalized = request.headers[SBX047_TRANSFORM_HEADER];
  const values = Array.isArray(normalized) ? normalized : normalized === undefined ? [] : [normalized];
  const valueSha256 = raw.length === 1 && values.length === 1
    ? sha256Sbx047(raw[0]!)
    : undefined;
  return {
    lines: raw.length,
    values: values.length,
    ...(valueSha256 === undefined ? {} : { sha256: valueSha256 }),
    matched: valueSha256 === expectedSha256,
  };
}

function localAdminRequest(request: IncomingMessage): boolean {
  const host = request.headers.host ?? "";
  const remote = request.socket.remoteAddress ?? "";
  return /^(?:127\.0\.0\.1|localhost):[0-9]{1,5}$/u.test(host) &&
    (remote === "127.0.0.1" || remote === "::1" || remote === "::ffff:127.0.0.1");
}

function adminAuthorized(request: IncomingMessage, expected: string): boolean {
  const authorization = request.headers.authorization;
  if (!localAdminRequest(request) || typeof authorization !== "string" ||
      !authorization.startsWith("Bearer ")) return false;
  return timingSafeEqual(digest(authorization.slice(7)), digest(expected));
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk);
    length += bytes.length;
    if (length > MAX_ADMIN_BODY_BYTES) throw new Error("SBX-047 admin body exceeded its limit");
    chunks.push(bytes);
  }
  const body = Buffer.concat(chunks, length);
  try {
    return JSON.parse(body.toString("utf8"));
  } finally {
    body.fill(0);
    for (const chunk of chunks) chunk.fill(0);
  }
}

function checkedToken(value: unknown, name: string): string {
  if (typeof value !== "string" || !TOKEN.test(value)) throw new Error(`${name} is invalid`);
  return value;
}

function validateConfiguration(value: unknown, publicHost: string): Sbx047ReceiverConfiguration {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      !exactKeys(value, ["runId", "publicHost", "canary", "transformHeaderSha256"])) {
    throw new Error("SBX-047 receiver configuration fields were not exact");
  }
  const input = value as Record<string, unknown>;
  const configuration = {
    runId: checkedToken(input.runId, "runId"),
    publicHost: checkedToken(input.publicHost, "publicHost"),
    canary: checkedToken(input.canary, "canary"),
    transformHeaderSha256: checkedToken(input.transformHeaderSha256, "transformHeaderSha256"),
  };
  if (configuration.publicHost !== publicHost || !SHA256.test(configuration.transformHeaderSha256)) {
    throw new Error("SBX-047 receiver configuration did not match the owned origin/commitment");
  }
  return configuration;
}

function validateStagedSecret(value: unknown, runId: string): Buffer {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      !exactKeys(value, ["runId", "secret"])) {
    throw new Error("SBX-047 staged-secret fields were not exact");
  }
  const input = value as Record<string, unknown>;
  if (input.runId !== runId || typeof input.secret !== "string" || input.secret.length < 43 ||
      input.secret.length > 256 || !/^[A-Za-z0-9_-]+$/u.test(input.secret)) {
    throw new Error("SBX-047 staged secret was invalid");
  }
  return Buffer.from(input.secret, "utf8");
}

function parseAdminPath(pathname: string): { runId: string; stage: boolean } | undefined {
  const match = /^\/v1\/sbx047\/admin\/runs\/([A-Za-z0-9._:-]{1,160})(\/stage)?$/u.exec(pathname);
  if (!match) return undefined;
  return { runId: match[1]!, stage: match[2] === "/stage" };
}

function parsePublicPath(pathname: string): {
  kind: Sbx047RequestKind;
  runId: string;
  caseId: string;
  canary: string;
} | undefined {
  const match = /^\/v1\/sbx047\/(public|action)\/([A-Za-z0-9._:-]{1,160})\/([A-Za-z0-9._:-]{1,160})\/([A-Za-z0-9._:-]{1,160})$/u.exec(pathname);
  if (!match) return undefined;
  return {
    kind: match[1] as Sbx047RequestKind,
    runId: match[2]!,
    caseId: match[3]!,
    canary: match[4]!,
  };
}

function publicSnapshot(state: RunState): Sbx047ObserverSnapshot {
  return {
    configured: true,
    actionStaged: state.stagedSecret !== undefined,
    events: state.events.map((event) => ({ ...event })),
  };
}

function clearState(state: RunState): void {
  state.stagedSecret?.fill(0);
  state.events.length = 0;
}

export async function startSbx047Receiver(
  options: Sbx047ReceiverOptions,
): Promise<Sbx047ReceiverHandle> {
  if (options.adminKey.length < 43 || options.adminKey.length > 512 || /[\s\0]/u.test(options.adminKey)) {
    throw new Error("SBX-047 admin key must be one bounded 43+ character value");
  }
  const publicOrigin = exactOrigin(options.publicOrigin);
  const states = new Map<string, RunState>();

  const server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", "http://receiver.invalid");
      if (url.search !== "" || url.hash !== "") { sendEmpty(response, 400); return; }
      if (url.pathname === "/healthz") {
        sendJson(response, 200, {
          ok: true,
          service: "sbx047-receiver",
          hostMatched: hostEvidence(request, publicOrigin.hostname).matched,
        });
        return;
      }

      const admin = parseAdminPath(url.pathname);
      if (admin !== undefined) {
        if (!adminAuthorized(request, options.adminKey)) { sendEmpty(response, 401); return; }
        if (!admin.stage && request.method === "PUT") {
          if (states.has(admin.runId)) { sendEmpty(response, 409); return; }
          const configuration = validateConfiguration(await readJson(request), publicOrigin.hostname);
          if (configuration.runId !== admin.runId) throw new Error("run ID did not match admin path");
          states.set(admin.runId, { configuration, events: [] });
          sendEmpty(response, 204);
          return;
        }
        const state = states.get(admin.runId);
        if (state === undefined) { sendEmpty(response, 404); return; }
        if (admin.stage && request.method === "PUT") {
          if (state.stagedSecret !== undefined) { sendEmpty(response, 409); return; }
          state.stagedSecret = validateStagedSecret(await readJson(request), admin.runId);
          sendEmpty(response, 204);
          return;
        }
        if (admin.stage && request.method === "DELETE") {
          const existed = state.stagedSecret !== undefined;
          state.stagedSecret?.fill(0);
          delete state.stagedSecret;
          sendEmpty(response, existed ? 204 : 404);
          return;
        }
        if (!admin.stage && request.method === "GET") {
          sendJson(response, 200, publicSnapshot(state));
          return;
        }
        if (!admin.stage && request.method === "DELETE") {
          clearState(state);
          states.delete(admin.runId);
          sendEmpty(response, 204);
          return;
        }
        sendEmpty(response, 405);
        return;
      }

      const route = parsePublicPath(url.pathname);
      if (route === undefined) { sendEmpty(response, 404); return; }
      const state = states.get(route.runId);
      if (state === undefined) { sendEmpty(response, 404); return; }
      const host = hostEvidence(request, state.configuration.publicHost);
      const transform = transformEvidence(request, state.configuration.transformHeaderSha256);
      const exactRequest = request.method === "GET" && host.matched &&
        route.canary === state.configuration.canary;
      const actionAccepted = exactRequest && route.kind === "action" && transform.matched &&
        state.stagedSecret !== undefined;
      const accepted = exactRequest && (route.kind === "public" || actionAccepted);
      const secretProof = actionAccepted
        ? deriveSbx047SecretProof(
            state.stagedSecret!.toString("utf8"),
            route.runId,
            route.caseId,
            route.canary,
          )
        : undefined;
      const operationId = secretProof === undefined
        ? undefined
        : deriveSbx047OperationId(options.adminKey, route.runId, route.caseId, secretProof);
      const receipt = accepted
        ? deriveSbx047Receipt(
            options.adminKey,
            route.runId,
            route.kind,
            route.caseId,
            route.canary,
            transform.sha256,
          )
        : undefined;
      const event: Sbx047ObserverEvent = {
        sequence: state.events.length + 1,
        observedAt: new Date().toISOString(),
        kind: route.kind,
        caseId: route.caseId,
        method: request.method ?? "",
        requestTarget: request.url ?? "",
        hostHeaderLines: host.lines,
        hostHeaderValues: host.values,
        hostMatched: host.matched,
        canaryMatched: route.canary === state.configuration.canary,
        transformHeaderLines: transform.lines,
        transformHeaderValues: transform.values,
        ...(transform.sha256 === undefined ? {} : { transformHeaderSha256: transform.sha256 }),
        transformCommitmentMatched: transform.matched,
        responseStatus: accepted ? 200 : 401,
        ...(receipt === undefined ? {} : { receipt }),
        ...(operationId === undefined ? {} : { operationId }),
        ...(secretProof === undefined ? {} : { secretProof }),
      };
      state.events.push(event);
      if (!accepted) { sendEmpty(response, 401); return; }
      sendJson(response, 200, {
        receipt,
        operationId: operationId ?? null,
        secretProof: secretProof ?? null,
      });
    } catch {
      sendEmpty(response, 400);
    }
  });

  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 43_147;
  await new Promise<void>((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolveListen();
    });
  });
  return {
    server,
    port: (server.address() as AddressInfo).port,
    async close(): Promise<void> {
      for (const state of states.values()) clearState(state);
      states.clear();
      await new Promise<void>((resolveClose, reject) => {
        server.close((error) => error ? reject(error) : resolveClose());
      });
    },
  };
}

async function main(): Promise<void> {
  const handle = await startSbx047Receiver({
    adminKey: process.env.SBX047_ADMIN_KEY ?? "",
    publicOrigin: process.env.SBX047_PUBLIC_ORIGIN ?? "",
    host: "127.0.0.1",
    port: Number(process.env.SBX047_RECEIVER_PORT ?? 43_147),
  });
  process.stdout.write(`${JSON.stringify({
    ready: true,
    testId: SBX047_TEST_ID,
    host: "127.0.0.1",
    port: handle.port,
  })}\n`);
  await new Promise<void>((resolveStop) => {
    process.once("SIGINT", resolveStop);
    process.once("SIGTERM", resolveStop);
  });
  await handle.close();
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
