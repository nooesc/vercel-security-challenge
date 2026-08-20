import "dotenv/config";

import { createHash, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { isIP, type Socket } from "node:net";
import { TLSSocket } from "node:tls";
import {
  SBX038_TEST_ID,
  SBX038_TRANSFORM_HEADER,
  deriveSbx038OperationId,
  deriveSbx038SecretCommitment,
  deriveSbx038TransformCommitment,
  type Sbx038AConnectEvent,
  type Sbx038AHttpEvent,
  type Sbx038BEvent,
  type Sbx038ReceiverSnapshot,
} from "./verdict.js";

const MAX_ADMIN_BODY = 16 * 1024;
const MAX_SECRET_BODY = 4 * 1024;

export interface Sbx038ReceiverConfiguration {
  runId: string;
  aHost: string;
  bHost: string;
  correlationCanary: string;
  transformHeaderCommitment: string;
}

interface RunState {
  configuration: Sbx038ReceiverConfiguration;
  aHttp: Sbx038AHttpEvent[];
  aConnect: Sbx038AConnectEvent[];
  b: Sbx038BEvent[];
  infrastructureConnect: Sbx038AConnectEvent[];
  unexpected: import("./verdict.js").Sbx038UnexpectedIngressEvent[];
  inFlight: number;
  nextSequence: number;
  secretCommitment?: string;
}

export interface Sbx038ReceiverOptions {
  adminKey: string;
  aPublicOrigin: string;
  bPublicOrigin: string;
  aPort?: number;
  bPort?: number;
  host?: string;
  aTls?: { key: string | Buffer; cert: string | Buffer };
  bTls?: { key: string | Buffer; cert: string | Buffer };
}

export interface Sbx038ReceiverHandle {
  aServer: Server;
  bServer: Server;
  aPort: number;
  bPort: number;
  close(): Promise<void>;
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

function sendEmpty(response: ServerResponse, status: number, extra: Record<string, string> = {}): void {
  response.writeHead(status, { "cache-control": "no-store", "content-length": "0", ...extra });
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

function configuration(value: unknown, a: URL, b: URL): Sbx038ReceiverConfiguration {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("configuration must be an object");
  const input = value as Record<string, unknown>;
  if (!exactKeys(input, ["aHost", "bHost", "correlationCanary", "runId", "transformHeaderCommitment"])) {
    throw new Error("configuration fields are not exact");
  }
  const result = {
    runId: safeString(input.runId, "runId", 128),
    aHost: canonicalHost(input.aHost, "aHost"),
    bHost: canonicalHost(input.bHost, "bHost"),
    correlationCanary: safeString(input.correlationCanary, "correlationCanary", 128),
    transformHeaderCommitment: safeString(input.transformHeaderCommitment, "transformHeaderCommitment", 64),
  };
  if (!/^[A-Za-z0-9._:-]+$/u.test(result.runId) || !/^[A-Za-z0-9._:-]+$/u.test(result.correlationCanary)) {
    throw new Error("run/canary characters are invalid");
  }
  if (!/^[a-f0-9]{64}$/u.test(result.transformHeaderCommitment)) throw new Error("transform commitment is invalid");
  if (result.aHost !== a.hostname || result.bHost !== b.hostname || result.aHost === result.bHost) {
    throw new Error("configuration hosts do not match the owned origins");
  }
  return result;
}

async function readBody(request: IncomingMessage, maximum: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk);
    length += bytes.length;
    if (length > maximum) throw new Error("request body exceeded its bound");
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  return JSON.parse((await readBody(request, MAX_ADMIN_BODY)).toString("utf8"));
}

function headerCounts(request: IncomingMessage, name: string): { lines: number; values: number; value?: string } {
  const entries: string[] = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === name) entries.push(request.rawHeaders[index + 1] ?? "");
  }
  return {
    lines: entries.length,
    values: entries.reduce((total, value) => total + value.split(",").length, 0),
    ...(entries.length === 1 ? { value: entries[0] } : {}),
  };
}

function caseId(request: IncomingMessage): string | undefined {
  const value = request.headers["x-sbx038-case"];
  return typeof value === "string" && /^[A-Za-z0-9._:-]{1,128}$/u.test(value) ? value : undefined;
}

function canary(request: IncomingMessage): string | undefined {
  const value = request.headers["x-sbx038-canary"];
  return typeof value === "string" && /^[A-Za-z0-9._:-]{1,128}$/u.test(value) ? value : undefined;
}

function runHeader(request: IncomingMessage): string | undefined {
  const header = headerCounts(request, "x-sbx038-run");
  return header.lines === 1 && header.values === 1 && header.value !== undefined &&
    /^[A-Za-z0-9._:-]{1,128}$/u.test(header.value) ? header.value : undefined;
}

function hostHeaderMatched(request: IncomingMessage, expected: string): boolean {
  const header = headerCounts(request, "host");
  return header.lines === 1 && header.values === 1 && header.value === expected;
}

function localTlsServername(request: IncomingMessage): string | undefined {
  const socket = request.socket as TLSSocket & { servername?: unknown };
  return socket instanceof TLSSocket && socket.encrypted && typeof socket.servername === "string"
    ? socket.servername
    : undefined;
}

function attributedState(
  states: Map<string, RunState>,
  request: IncomingMessage,
  pathRunId?: string,
): { state: RunState; attribution: "run-header" | "path-run" | "canary" } | undefined {
  const headerRunId = runHeader(request);
  const byHeader = headerRunId ? states.get(headerRunId) : undefined;
  if (byHeader) return { state: byHeader, attribution: "run-header" };
  const byPath = pathRunId ? states.get(pathRunId) : undefined;
  if (byPath) return { state: byPath, attribution: "path-run" };
  const marker = canary(request);
  const matching = marker === undefined ? [] : [...states.values()].filter((state) =>
    state.configuration.correlationCanary === marker);
  return matching.length === 1 ? { state: matching[0]!, attribution: "canary" } : undefined;
}

function recordUnexpected(
  state: RunState,
  role: "a" | "b",
  attribution: "run-header" | "path-run" | "canary",
  reason: import("./verdict.js").Sbx038UnexpectedIngressEvent["reason"],
  request: IncomingMessage,
): void {
  state.unexpected.push({
    sequence: ++state.nextSequence,
    observedAt: new Date().toISOString(),
    role,
    attribution,
    reason,
    method: request.method ?? "",
    ...(caseId(request) ? { caseId: caseId(request)! } : {}),
  });
}

function ingressReason(
  request: IncomingMessage,
  state: RunState,
  pathRunId: string | undefined,
  expectedHost: string,
  expectedCase: (value: string | undefined) => boolean,
  expectedMethod: string,
): import("./verdict.js").Sbx038UnexpectedIngressEvent["reason"] | undefined {
  if (pathRunId !== undefined && pathRunId !== state.configuration.runId) return "wrong-path";
  if (runHeader(request) !== state.configuration.runId) return "wrong-run-header";
  if (!hostHeaderMatched(request, expectedHost)) return "invalid-host";
  if (request.method !== expectedMethod) return "wrong-method";
  if (!expectedCase(caseId(request))) return "wrong-case";
  if (canary(request) !== state.configuration.correlationCanary) return "wrong-canary";
  return undefined;
}

function snapshot(state: RunState): Sbx038ReceiverSnapshot {
  return {
    configured: true,
    nextSequence: state.nextSequence,
    infrastructureConnect: state.infrastructureConnect.map((event) => ({ ...event })),
    aHttp: state.aHttp.map((event) => ({ ...event })),
    aConnect: state.aConnect.map((event) => ({ ...event })),
    b: state.b.map((event) => ({ ...event })),
    unexpected: state.unexpected.map((event) => ({ ...event })),
    secretRegistered: state.secretCommitment !== undefined,
  };
}

function runPath(pathname: string, prefix: string): string | undefined {
  if (!pathname.startsWith(prefix)) return undefined;
  const encoded = pathname.slice(prefix.length);
  if (!encoded || encoded.includes("/")) return undefined;
  try { return decodeURIComponent(encoded); } catch { return undefined; }
}

async function listen(server: Server, port: number, host: string): Promise<number> {
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

function close(server: Server): Promise<void> {
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

export async function startSbx038Receiver(options: Sbx038ReceiverOptions): Promise<Sbx038ReceiverHandle> {
  if (options.adminKey.length < 32 || options.adminKey.length > 512 || /[\0\r\n]/u.test(options.adminKey)) {
    throw new Error("adminKey must be a strong bounded value");
  }
  const aOrigin = exactOrigin(options.aPublicOrigin, "aPublicOrigin");
  const bOrigin = exactOrigin(options.bPublicOrigin, "bPublicOrigin");
  if (aOrigin.origin === bOrigin.origin) throw new Error("A and B origins must be distinct");
  const states = new Map<string, RunState>();

  const aHandler = async (request: IncomingMessage, response: ServerResponse) => {
    try {
      const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "receiver.invalid"}`);
      if (request.method === "GET" && url.pathname === "/healthz") {
        const attributed = attributedState(states, request);
        if (attributed) recordUnexpected(attributed.state, "a", attributed.attribution, "wrong-path", request);
        sendJson(response, 200, { ok: true, service: "sbx038-a-terminal-receiver", connectTerminal: true });
        return;
      }
      const adminRunId = runPath(url.pathname, "/v1/sbx038/admin/runs/");
      if (adminRunId !== undefined) {
        if (!adminAuthorized(request, options.adminKey)) { sendEmpty(response, 401); return; }
        if (request.method === "PUT") {
          const checked = configuration(await readJson(request), aOrigin, bOrigin);
          const canaryInUse = [...states.values()].some((state) =>
            state.configuration.correlationCanary === checked.correlationCanary);
          if (checked.runId !== adminRunId || states.has(adminRunId) || canaryInUse) {
            sendEmpty(response, 409);
            return;
          }
          states.set(adminRunId, {
            configuration: checked,
            infrastructureConnect: [],
            aHttp: [],
            aConnect: [],
            b: [],
            unexpected: [],
            inFlight: 0,
            nextSequence: 0,
          });
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
          const state = states.get(adminRunId);
          if (!state) { sendEmpty(response, 404); return; }
          if (state.inFlight > 0) { sendEmpty(response, 409); return; }
          states.delete(adminRunId);
          sendEmpty(response, 204);
          return;
        }
      }
      const secretRunId = runPath(url.pathname, "/v1/sbx038/admin/secrets/");
      if (secretRunId !== undefined && request.method === "PUT") {
        if (!adminAuthorized(request, options.adminKey)) { sendEmpty(response, 401); return; }
        const state = states.get(secretRunId);
        if (!state || state.secretCommitment !== undefined) { sendEmpty(response, state ? 409 : 404); return; }
        state.inFlight += 1;
        try {
          const body = await readJson(request);
          if (states.get(secretRunId) !== state || state.secretCommitment !== undefined) {
            sendEmpty(response, states.has(secretRunId) ? 409 : 404);
            return;
          }
          if (!body || typeof body !== "object" || Array.isArray(body) ||
            !exactKeys(body as Record<string, unknown>, ["secretCommitment"])) { sendEmpty(response, 400); return; }
          const commitment = (body as Record<string, unknown>).secretCommitment;
          if (typeof commitment !== "string" || !/^[a-f0-9]{64}$/u.test(commitment)) { sendEmpty(response, 400); return; }
          state.secretCommitment = commitment;
          sendJson(response, 200, {
            operationId: deriveSbx038OperationId(
              options.adminKey,
              state.configuration.runId,
              "secret-connect-b",
              commitment,
            ),
          });
        } finally {
          state.inFlight -= 1;
        }
        return;
      }
      const controlRunId = runPath(url.pathname, "/v1/sbx038/control/");
      if (controlRunId !== undefined) {
        const attributed = attributedState(states, request, controlRunId);
        if (!attributed) { sendEmpty(response, 404); return; }
        const { state, attribution } = attributed;
        const wantedCase = caseId(request);
        const reason = ingressReason(
          request,
          state,
          controlRunId,
          state.configuration.aHost,
          (value) => value === "public-normal-a" || value === "secret-normal-a",
          "GET",
        );
        if (reason) { recordUnexpected(state, "a", attribution, reason, request); sendEmpty(response, 400); return; }
        const exactCase = wantedCase!;
        const transform = headerCounts(request, SBX038_TRANSFORM_HEADER);
        const transformCommitment = transform.value === undefined
          ? undefined
          : deriveSbx038TransformCommitment(options.adminKey, state.configuration.runId, transform.value);
        const matched = transform.lines === 1 && transform.values === 1 &&
          transformCommitment === state.configuration.transformHeaderCommitment;
        const operationId = matched
          ? deriveSbx038OperationId(
            options.adminKey,
            state.configuration.runId,
            exactCase,
            state.configuration.correlationCanary,
          )
          : undefined;
        state.aHttp.push({
          sequence: ++state.nextSequence,
          observedAt: new Date().toISOString(),
          caseId: exactCase,
          method: request.method ?? "",
          requestTarget: request.url ?? "",
          transformHeaderLines: transform.lines,
          transformHeaderValues: transform.values,
          ...(transformCommitment ? { transformHeaderCommitment: transformCommitment } : {}),
          transformCommitmentMatched: matched,
          responseStatus: matched ? 200 : 401,
          ...(operationId ? { operationId } : {}),
        });
        if (!operationId) { sendEmpty(response, 401); return; }
        sendJson(response, 200, { operationId });
        return;
      }
      const attributed = attributedState(states, request);
      if (attributed) recordUnexpected(attributed.state, "a", attributed.attribution, "wrong-path", request);
      sendEmpty(response, 404);
    } catch {
      const attributed = attributedState(states, request);
      if (attributed) recordUnexpected(attributed.state, "a", attributed.attribution, "wrong-path", request);
      sendEmpty(response, 400);
    }
  };
  const aServer = options.aTls ? createHttpsServer(options.aTls, aHandler) : createServer(aHandler);

  aServer.on("connect", (request: IncomingMessage, socket: Socket) => {
    const wantedCase = caseId(request);
    const attributed = attributedState(states, request);
    if (attributed) {
      const { state, attribution } = attributed;
      const infrastructureCase = `infrastructure-connect-a-${state.configuration.runId.slice(0, 8)}`;
      const expectedTarget = wantedCase === "public-connect-b" || wantedCase === "secret-connect-b"
        ? `${state.configuration.bHost}:443`
        : `${state.configuration.aHost}:443`;
      const reason = ingressReason(
        request,
        state,
        undefined,
        state.configuration.aHost,
        (value) => value === infrastructureCase || value === "public-connect-a" || value === "secret-connect-a" ||
          value === "public-connect-b" || value === "secret-connect-b",
        "CONNECT",
      ) ?? (request.url === expectedTarget ? undefined : "wrong-path");
      if (reason) {
        recordUnexpected(state, "a", attribution, reason, request);
      } else if (wantedCase) {
      const transform = headerCounts(request, SBX038_TRANSFORM_HEADER);
      const transformCommitment = transform.value === undefined
        ? undefined
        : deriveSbx038TransformCommitment(options.adminKey, state.configuration.runId, transform.value);
      const event: Sbx038AConnectEvent = {
        sequence: ++state.nextSequence,
        observedAt: new Date().toISOString(),
        caseId: wantedCase,
        requestTarget: request.url ?? "",
        ...(typeof request.headers.host === "string" ? { hostHeader: request.headers.host } : {}),
        transformHeaderLines: transform.lines,
        transformHeaderValues: transform.values,
        ...(transformCommitment ? { transformHeaderCommitment: transformCommitment } : {}),
        transformCommitmentMatched: transform.lines === 1 && transform.values === 1 &&
          transformCommitment === state.configuration.transformHeaderCommitment,
        terminalResponseStatus: 405,
        openedOutboundConnection: false,
      };
      if (wantedCase === infrastructureCase) state.infrastructureConnect.push(event);
      else state.aConnect.push(event);
      }
    }
    socket.end([
      "HTTP/1.1 405 Method Not Allowed",
      "Cache-Control: no-store",
      "Content-Length: 0",
      "X-SBX038-Terminal: 1",
      "Connection: close",
      "",
      "",
    ].join("\r\n"));
  });

  const bHandler = async (request: IncomingMessage, response: ServerResponse) => {
    try {
      const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "receiver.invalid"}`);
      if (request.method === "GET" && url.pathname === "/healthz") {
        const attributed = attributedState(states, request);
        if (attributed) recordUnexpected(attributed.state, "b", attributed.attribution, "wrong-path", request);
        sendJson(response, 200, { ok: true, service: "sbx038-b-action-receiver" });
        return;
      }
      const directRunId = runPath(url.pathname, "/v1/sbx038/direct/");
      if (directRunId !== undefined) {
        const attributed = attributedState(states, request, directRunId);
        if (!attributed) { sendEmpty(response, 404); return; }
        const { state, attribution } = attributed;
        const wantedCase = caseId(request);
        const reason = ingressReason(
          request,
          state,
          directRunId,
          state.configuration.bHost,
          (value) => value === "public-direct-b-pre" || value === "public-direct-b-post" ||
            value === "secret-direct-b-pre" || value === "secret-direct-b-post",
          "GET",
        );
        if (reason) { recordUnexpected(state, "b", attribution, reason, request); sendEmpty(response, 400); return; }
        const exactCase = wantedCase!;
        const host = headerCounts(request, "host");
        const tlsSocket = request.socket instanceof TLSSocket && request.socket.encrypted ? request.socket : undefined;
        const tlsServername = localTlsServername(request);
        state.b.push({
          sequence: ++state.nextSequence,
          observedAt: new Date().toISOString(), caseId: exactCase, stage: "direct", method: request.method ?? "",
          requestTarget: request.url ?? "", hostHeaderLines: host.lines, hostHeaderValues: host.values,
          hostHeaderMatched: hostHeaderMatched(request, state.configuration.bHost),
          tlsTerminatedLocally: tlsSocket !== undefined,
          ...(tlsServername ? { tlsServername } : {}),
          canaryMatched: canary(request) === state.configuration.correlationCanary,
          secretCommitmentMatched: false, bodyBytes: 0, rawBodyRetained: false,
        });
        sendEmpty(response, 403);
        return;
      }
      const actionRunId = runPath(url.pathname, "/v1/sbx038/action/");
      if (actionRunId !== undefined) {
        const attributed = attributedState(states, request, actionRunId);
        if (!attributed) { sendEmpty(response, 404); return; }
        const { state, attribution } = attributed;
        const wantedCase = caseId(request);
        const secretStage = wantedCase === "secret-connect-b";
        const expectedMethod = secretStage ? "POST" : "GET";
        const reason = ingressReason(
          request,
          state,
          actionRunId,
          state.configuration.bHost,
          (value) => value === "public-connect-b" || value === "secret-connect-b",
          expectedMethod,
        );
        if (reason) { recordUnexpected(state, "b", attribution, reason, request); sendEmpty(response, 400); return; }
        const exactCase = wantedCase!;
        const markerMatched = true;
        let body: Buffer | undefined;
        state.inFlight += 1;
        try {
          try { body = await readBody(request, MAX_SECRET_BODY); }
          catch {
            if (states.get(state.configuration.runId) !== state) {
              sendEmpty(response, states.has(state.configuration.runId) ? 409 : 404);
              return;
            }
            recordUnexpected(state, "b", attribution, "invalid-body", request);
            sendEmpty(response, 400);
            return;
          }
          if (states.get(state.configuration.runId) !== state) {
            sendEmpty(response, states.has(state.configuration.runId) ? 409 : 404);
            return;
          }
          const bodyCommitment = secretStage
            ? deriveSbx038SecretCommitment(options.adminKey, state.configuration.runId, body)
            : undefined;
          const secretMatched = secretStage && state.secretCommitment !== undefined &&
            body.length >= 16 && bodyCommitment === state.secretCommitment;
          const signal = secretStage ? state.secretCommitment ?? "unregistered" : state.configuration.correlationCanary;
          const accepted = markerMatched && (secretStage ? secretMatched : body.length === 0);
          const operationId = accepted
            ? deriveSbx038OperationId(options.adminKey, state.configuration.runId, exactCase, signal)
            : undefined;
          const host = headerCounts(request, "host");
          const tlsSocket = request.socket instanceof TLSSocket && request.socket.encrypted ? request.socket : undefined;
          const tlsServername = localTlsServername(request);
          state.b.push({
            sequence: ++state.nextSequence,
            observedAt: new Date().toISOString(),
            caseId: exactCase,
            stage: secretStage ? "secret" : "public",
            method: request.method ?? "",
            requestTarget: request.url ?? "",
            hostHeaderLines: host.lines,
            hostHeaderValues: host.values,
            hostHeaderMatched: hostHeaderMatched(request, state.configuration.bHost),
            tlsTerminatedLocally: tlsSocket !== undefined,
            ...(tlsServername ? { tlsServername } : {}),
            canaryMatched: markerMatched,
            secretCommitmentMatched: secretMatched,
            bodyBytes: body.length,
            rawBodyRetained: false,
            ...(operationId ? { operationId } : {}),
          });
          if (!operationId) { sendEmpty(response, 401); return; }
          sendJson(response, 200, { operationId });
        } finally {
          body?.fill(0);
          state.inFlight -= 1;
        }
        return;
      }
      const attributed = attributedState(states, request);
      if (attributed) recordUnexpected(attributed.state, "b", attributed.attribution, "wrong-path", request);
      sendEmpty(response, 404);
    } catch {
      const attributed = attributedState(states, request);
      if (attributed) recordUnexpected(attributed.state, "b", attributed.attribution, "wrong-path", request);
      sendEmpty(response, 400);
    }
  };
  const bServer = options.bTls ? createHttpsServer(options.bTls, bHandler) : createServer(bHandler);

  const host = options.host ?? "127.0.0.1";
  const aPort = await listen(aServer, options.aPort ?? 43_138, host);
  try {
    const bPort = await listen(bServer, options.bPort ?? 43_139, host);
    return {
      aServer,
      bServer,
      aPort,
      bPort,
      async close() { await Promise.all([close(aServer), close(bServer)]); },
    };
  } catch (error) {
    await close(aServer);
    throw error;
  }
}

async function main(): Promise<void> {
  const aKeyPath = process.env.SBX038_A_TLS_KEY_PATH;
  const aCertPath = process.env.SBX038_A_TLS_CERT_PATH;
  const bKeyPath = process.env.SBX038_B_TLS_KEY_PATH;
  const bCertPath = process.env.SBX038_B_TLS_CERT_PATH;
  if ((aKeyPath === undefined) !== (aCertPath === undefined) || (bKeyPath === undefined) !== (bCertPath === undefined)) {
    throw new Error("each TLS role requires both its key and certificate path");
  }
  const [aKey, aCert, bKey, bCert] = await Promise.all([
    aKeyPath ? readFile(aKeyPath) : undefined,
    aCertPath ? readFile(aCertPath) : undefined,
    bKeyPath ? readFile(bKeyPath) : undefined,
    bCertPath ? readFile(bCertPath) : undefined,
  ]);
  const receiver = await startSbx038Receiver({
    adminKey: process.env.SBX038_ADMIN_KEY ?? "",
    aPublicOrigin: process.env.SBX038_A_PUBLIC_ORIGIN ?? "",
    bPublicOrigin: process.env.SBX038_B_PUBLIC_ORIGIN ?? "",
    aPort: Number(process.env.SBX038_A_PORT ?? "43138"),
    bPort: Number(process.env.SBX038_B_PORT ?? "43139"),
    host: process.env.SBX038_LISTEN_HOST ?? "127.0.0.1",
    ...(aKey && aCert ? { aTls: { key: aKey, cert: aCert } } : {}),
    ...(bKey && bCert ? { bTls: { key: bKey, cert: bCert } } : {}),
  });
  process.stdout.write(`${JSON.stringify({ ready: true, aPort: receiver.aPort, bPort: receiver.bPort })}\n`);
  const stop = async () => { await receiver.close(); process.exit(0); };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}

if (process.argv[1]?.endsWith("receiver.ts")) await main();
