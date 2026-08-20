import "dotenv/config";

import { createHash, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { isIP } from "node:net";
import { pathToFileURL } from "node:url";
import {
  CANARY_PATTERN,
  commitmentMatches,
  expectedOperationId,
  isCaseId,
  OPERATION_ID_PATTERN,
  queryForCase,
  RUN_ID_PATTERN,
  SBX049_CASES,
  SBX049_TEST_ID,
  SBX049_TRANSFORM_HEADER,
  type Sbx049CaseId,
} from "./protocol.js";

const MAX_BODY_BYTES = 16_384;
const COMMITMENT_PATTERN = /^[A-Za-z0-9_-]{43}$/u;

export interface Sbx049ReceiverCase {
  caseId: Sbx049CaseId;
  canary: string;
  rawQuery: string;
}

export interface Sbx049ReceiverConfiguration {
  secretCommitment: string;
  cases: Sbx049ReceiverCase[];
}

export interface Sbx049ReceiverEvent {
  ordinal: number;
  observedAt: string;
  caseId: Sbx049CaseId;
  canaryMatched: true;
  queryMatched: true;
  brokered: boolean;
  operationId: string;
}

interface RunState {
  configuration: Sbx049ReceiverConfiguration;
  events: Sbx049ReceiverEvent[];
}

export interface Sbx049ReceiverOptions {
  adminKey: string;
  actionKey: string;
  publicOrigin: string;
  port?: number;
  host?: string;
}

export interface Sbx049ReceiverHandle {
  server: Server;
  port: number;
  close(): Promise<void>;
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function exactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((entry, index) => entry === wanted[index]);
}

function safeOrigin(raw: string): URL {
  const parsed = new URL(raw);
  if (
    parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.port ||
    parsed.pathname !== "/" || parsed.search || parsed.hash || isIP(parsed.hostname) !== 0 ||
    parsed.hostname !== parsed.hostname.toLowerCase()
  ) throw new Error("SBX049_PUBLIC_ORIGIN must be an exact lower-case HTTPS origin");
  return parsed;
}

function digest(value: string): Buffer {
  return createHash("sha256").update(value).digest();
}

function adminAuthorized(request: IncomingMessage, expected: string): boolean {
  const supplied = request.headers.authorization;
  if (typeof supplied !== "string" || !supplied.startsWith("Bearer ")) return false;
  return timingSafeEqual(digest(supplied.slice(7)), digest(expected));
}

function rawHeaderValues(request: IncomingMessage, expectedName: string): string[] {
  const values: string[] = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === expectedName) {
      const value = request.rawHeaders[index + 1];
      if (value !== undefined) values.push(value);
    }
  }
  return values;
}

function sendJson(response: ServerResponse, status: number, value: unknown): void {
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    "content-length": String(body.byteLength),
  });
  response.end(body);
}

function sendEmpty(response: ServerResponse, status: number): void {
  response.writeHead(status, { "cache-control": "no-store", "content-length": "0" });
  response.end();
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk);
    total += bytes.byteLength;
    if (total > MAX_BODY_BYTES) throw new Error("request body exceeded bound");
    chunks.push(bytes);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

export function validateReceiverConfiguration(
  value: unknown,
  runId: string,
): Sbx049ReceiverConfiguration {
  const root = object(value);
  if (!root || !exactKeys(root, ["cases", "secretCommitment"]) ||
      typeof root.secretCommitment !== "string" || !COMMITMENT_PATTERN.test(root.secretCommitment) ||
      !Array.isArray(root.cases) || root.cases.length !== SBX049_CASES.length) {
    throw new Error("invalid SBX-049 receiver configuration");
  }
  const cases = root.cases.map((raw): Sbx049ReceiverCase => {
    const entry = object(raw);
    if (!entry || !exactKeys(entry, ["canary", "caseId", "rawQuery"]) ||
        !isCaseId(entry.caseId) || typeof entry.canary !== "string" ||
        !CANARY_PATTERN.test(entry.canary) || typeof entry.rawQuery !== "string" ||
        entry.rawQuery !== queryForCase(runId, entry.caseId, entry.canary)) {
      throw new Error("invalid SBX-049 receiver case");
    }
    return { caseId: entry.caseId, canary: entry.canary, rawQuery: entry.rawQuery };
  });
  if (new Set(cases.map((entry) => entry.caseId)).size !== SBX049_CASES.length ||
      new Set(cases.map((entry) => entry.canary)).size !== SBX049_CASES.length ||
      !SBX049_CASES.every((caseId) => cases.some((entry) => entry.caseId === caseId))) {
    throw new Error("SBX-049 receiver cases must be exact and unique");
  }
  return { secretCommitment: root.secretCommitment, cases };
}

function snapshot(state: RunState | undefined): Record<string, unknown> {
  return {
    configured: state !== undefined,
    events: state?.events ?? [],
    rawBrokeredSecretRetained: false,
    brokeredSecretDigestRetained: false,
  };
}

export function createSbx049Receiver(options: Sbx049ReceiverOptions): Sbx049ReceiverHandle {
  if (Buffer.byteLength(options.adminKey) < 32 || Buffer.byteLength(options.adminKey) > 256 ||
      Buffer.byteLength(options.actionKey) < 32 || Buffer.byteLength(options.actionKey) > 256 ||
      options.adminKey === options.actionKey || /[\0\r\n]/u.test(options.adminKey + options.actionKey)) {
    throw new Error("SBX-049 receiver keys must be distinct 32+ byte values");
  }
  const origin = safeOrigin(options.publicOrigin);
  const states = new Map<string, RunState>();
  const server = createServer(async (request, response) => {
    try {
      const rawUrl = request.url ?? "";
      const question = rawUrl.indexOf("?");
      const pathname = question === -1 ? rawUrl : rawUrl.slice(0, question);
      const rawQuery = question === -1 ? "" : rawUrl.slice(question + 1);
      if (request.method === "GET" && pathname === "/healthz") {
        sendJson(response, 200, { ok: true, testId: SBX049_TEST_ID });
        return;
      }

      const adminMatch = /^\/v1\/sbx049\/admin\/runs\/([0-9a-f-]{36})$/u.exec(pathname);
      if (adminMatch) {
        if (!adminAuthorized(request, options.adminKey)) {
          sendEmpty(response, 401);
          return;
        }
        const runId = adminMatch[1]!;
        if (!RUN_ID_PATTERN.test(runId) || rawQuery) {
          sendEmpty(response, 400);
          return;
        }
        if (request.method === "PUT") {
          if (states.has(runId)) {
            sendEmpty(response, 409);
            return;
          }
          const configuration = validateReceiverConfiguration(await readJson(request), runId);
          states.set(runId, { configuration, events: [] });
          sendJson(response, 201, snapshot(states.get(runId)));
          return;
        }
        if (request.method === "GET") {
          const state = states.get(runId);
          if (!state) {
            sendEmpty(response, 404);
            return;
          }
          sendJson(response, 200, snapshot(state));
          return;
        }
        if (request.method === "DELETE") {
          if (!states.delete(runId)) {
            sendEmpty(response, 404);
            return;
          }
          sendEmpty(response, 204);
          return;
        }
        sendEmpty(response, 405);
        return;
      }

      if (request.method === "GET" && pathname === "/v1/sbx049/action") {
        if (request.headers.host?.toLowerCase() !== origin.hostname) {
          sendEmpty(response, 421);
          return;
        }
        const search = new URLSearchParams(rawQuery);
        const runId = search.get("run") ?? "";
        const caseId = search.get("case");
        const state = states.get(runId);
        const configuredCase = state?.configuration.cases.find((entry) => entry.caseId === caseId);
        if (!state || !configuredCase || configuredCase.rawQuery !== rawQuery ||
            configuredCase.canary !== search.get("canary") || !isCaseId(caseId)) {
          sendEmpty(response, 404);
          return;
        }
        if (state.events.some((event) => event.caseId === caseId)) {
          sendEmpty(response, 409);
          return;
        }
        const secretValues = rawHeaderValues(request, SBX049_TRANSFORM_HEADER);
        if (secretValues.length > 1) {
          sendEmpty(response, 400);
          return;
        }
        const brokeredSecret = secretValues[0];
        if (brokeredSecret !== undefined &&
            !commitmentMatches(options.actionKey, brokeredSecret, state.configuration.secretCommitment)) {
          sendEmpty(response, 403);
          return;
        }
        const operationId = expectedOperationId(
          options.actionKey,
          origin.hostname,
          runId,
          caseId,
          configuredCase.canary,
          brokeredSecret,
        );
        if (!OPERATION_ID_PATTERN.test(operationId)) throw new Error("operation ID invariant failed");
        const event: Sbx049ReceiverEvent = {
          ordinal: state.events.length + 1,
          observedAt: new Date().toISOString(),
          caseId,
          canaryMatched: true,
          queryMatched: true,
          brokered: brokeredSecret !== undefined,
          operationId,
        };
        state.events.push(event);
        sendJson(response, 200, {
          testId: SBX049_TEST_ID,
          runId,
          caseId,
          canary: configuredCase.canary,
          brokered: event.brokered,
          operationId,
        });
        return;
      }
      sendEmpty(response, 404);
    } catch {
      sendEmpty(response, 400);
    }
  });
  const port = options.port ?? 43149;
  server.listen(port, options.host ?? "127.0.0.1");
  return {
    server,
    get port() {
      const address = server.address();
      return typeof address === "object" && address !== null ? address.port : port;
    },
    close: async () => await new Promise<void>((resolve, reject) =>
      server.close((error) => error ? reject(error) : resolve())),
  };
}

async function main(): Promise<void> {
  const port = Number.parseInt(process.env.SBX049_PORT ?? "43149", 10);
  const handle = createSbx049Receiver({
    adminKey: process.env.SBX049_ADMIN_KEY ?? "",
    actionKey: process.env.SBX049_ACTION_KEY ?? "",
    publicOrigin: process.env.SBX049_PUBLIC_ORIGIN ?? "",
    port,
  });
  await new Promise<void>((resolve, reject) => {
    if (handle.server.listening) resolve();
    else {
      handle.server.once("listening", resolve);
      handle.server.once("error", reject);
    }
  });
  process.stdout.write(`${JSON.stringify({ ready: true, port: handle.port })}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
