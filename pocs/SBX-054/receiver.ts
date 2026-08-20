import "dotenv/config";

import { createHash, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { isIP, type AddressInfo } from "node:net";
import { pathToFileURL } from "node:url";
import {
  deriveSbx054CanaryCommitment,
  deriveSbx054OperationId,
  deriveSbx054Receipt,
  deriveSbx054SecretProof,
  SBX054_CANARY,
  SBX054_CASES,
  SBX054_DIGEST,
  SBX054_TEST_ID,
  SBX054_UUID,
  type Sbx054CaseId,
  type Sbx054ObserverEvent,
  type Sbx054ObserverSnapshot,
  type Sbx054RequestKind,
} from "./verdict.js";

const MAX_ADMIN_BODY = 8_192;
const MAX_SECRET_BODY = 256;
const RECEIVER_TRUST_NAMES = [
  "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF", "OPENSSL_MODULES",
  "SSL_CERT_DIR", "SSL_CERT_FILE",
] as const;

export interface Sbx054ReceiverCase {
  caseId: Sbx054CaseId;
  kind: Sbx054RequestKind;
  canaryCommitment: string;
}

export interface Sbx054ReceiverConfiguration {
  runId: string;
  publicHost: string;
  cases: Sbx054ReceiverCase[];
}

interface RunState {
  configuration: Sbx054ReceiverConfiguration;
  configuredAt: string;
  events: Sbx054ObserverEvent[];
  stagedSecret?: Buffer;
  secretCleared: boolean;
  unexpectedRequests: number;
}

export interface Sbx054ReceiverOptions {
  adminKey: string;
  actionKey: string;
  publicOrigin: string;
  host?: string;
  port?: number;
}

export interface Sbx054ReceiverHandle {
  server: Server;
  host: string;
  port: number;
  close(): Promise<void>;
}

function exactKeys(value: object, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function exactOrigin(raw: string): URL {
  const value = new URL(raw);
  if (raw !== value.origin || value.protocol !== "https:" || value.port !== "" ||
      value.username !== "" || value.password !== "" || value.pathname !== "/" ||
      value.search !== "" || value.hash !== "" || value.hostname !== value.hostname.toLowerCase() ||
      value.hostname.endsWith(".") || isIP(value.hostname) !== 0) {
    throw new Error("SBX-054 public origin must be one exact canonical HTTPS hostname origin");
  }
  return value;
}

function boundedKey(value: string, name: string): string {
  if (Buffer.byteLength(value) < 32 || Buffer.byteLength(value) > 512 || /[\0\r\n\s]/u.test(value)) {
    throw new Error(`${name} must be one bounded non-whitespace key`);
  }
  return value;
}

function digest(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

function equalText(left: string, right: string): boolean {
  return timingSafeEqual(digest(left), digest(right));
}

function rawHeaderValues(request: IncomingMessage, wanted: string): string[] {
  const values: string[] = [];
  for (let index = 0; index + 1 < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === wanted) values.push(request.rawHeaders[index + 1] ?? "");
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
    matched: raw.length === 1 && normalized.length === 1 && raw[0] === expected && normalized[0] === expected,
  };
}

function localAdmin(request: IncomingMessage, adminKey: string): boolean {
  const remote = request.socket.remoteAddress ?? "";
  const host = request.headers.host ?? "";
  const authorization = request.headers.authorization;
  return /^(?:127\.0\.0\.1|localhost):[0-9]{1,5}$/u.test(host) &&
    (remote === "127.0.0.1" || remote === "::1" || remote === "::ffff:127.0.0.1") &&
    typeof authorization === "string" && authorization.startsWith("Bearer ") &&
    equalText(authorization.slice(7), adminKey);
}

function sendJson(response: ServerResponse, status: number, value: unknown): void {
  const body = Buffer.from(JSON.stringify(value), "utf8");
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

async function readBody(request: IncomingMessage, maximum: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for await (const raw of request) {
      const bytes = Buffer.from(raw);
      total += bytes.byteLength;
      if (total > maximum) {
        bytes.fill(0);
        throw new Error("SBX-054 request body exceeded its bound");
      }
      chunks.push(bytes);
    }
    return Buffer.concat(chunks, total);
  } finally {
    for (const chunk of chunks) chunk.fill(0);
  }
}

function receiverRuntime(): Pick<Sbx054ObserverSnapshot,
  "receiverRuntimeTrustExact" | "receiverTrustEnvironmentNames" |
  "receiverNodeOptionsPresent" | "receiverTlsVerificationDisabled"> {
  const names = RECEIVER_TRUST_NAMES.filter((name) => process.env[name] !== undefined).sort();
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0" || names.length > 0 ||
      (process.env.NODE_OPTIONS !== undefined && process.env.NODE_OPTIONS.trim() !== "")) {
    throw new Error("SBX-054 receiver refuses TLS trust overrides or runtime injection");
  }
  return {
    receiverRuntimeTrustExact: true,
    receiverTrustEnvironmentNames: [],
    receiverNodeOptionsPresent: false,
    receiverTlsVerificationDisabled: false,
  };
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

export function validateSbx054ReceiverConfiguration(
  value: unknown,
  publicHost: string,
): Sbx054ReceiverConfiguration {
  const root = object(value);
  if (!root || !exactKeys(root, ["runId", "publicHost", "cases"]) ||
      typeof root.runId !== "string" || !SBX054_UUID.test(root.runId) ||
      root.publicHost !== publicHost || !Array.isArray(root.cases) ||
      root.cases.length !== SBX054_CASES.length) {
    throw new Error("SBX-054 receiver configuration fields were not exact");
  }
  const kinds: Sbx054RequestKind[] = ["public", "public", "public", "secret"];
  const cases = root.cases.map((raw, index): Sbx054ReceiverCase => {
    const entry = object(raw);
    const caseId = SBX054_CASES[index]!;
    const kind = kinds[index]!;
    if (!entry || !exactKeys(entry, ["caseId", "kind", "canaryCommitment"]) ||
        entry.caseId !== caseId || entry.kind !== kind ||
        typeof entry.canaryCommitment !== "string" || !SBX054_DIGEST.test(entry.canaryCommitment)) {
      throw new Error("SBX-054 receiver case was invalid");
    }
    return {
      caseId,
      kind,
      canaryCommitment: entry.canaryCommitment,
    };
  });
  if (new Set(cases.map((entry) => entry.canaryCommitment)).size !== cases.length) {
    throw new Error("SBX-054 receiver canary commitments were not distinct");
  }
  return { runId: root.runId, publicHost, cases } as Sbx054ReceiverConfiguration;
}

function snapshot(state: RunState): Sbx054ObserverSnapshot {
  return {
    configured: true,
    configuredAt: state.configuredAt,
    events: state.events.map((event) => ({ ...event })),
    secretStaged: state.stagedSecret !== undefined,
    secretCleared: state.secretCleared,
    unexpectedRequests: state.unexpectedRequests,
    rawCanaryRetained: false,
    rawSecretRetained: false,
    rawBodyRetained: false,
    secretDigestRetained: false,
    ...receiverRuntime(),
  };
}

function clearState(state: RunState): void {
  state.stagedSecret?.fill(0);
  delete state.stagedSecret;
  state.events.length = 0;
}

function adminPath(pathname: string): { runId: string; secret: boolean } | undefined {
  const match = /^\/v1\/sbx054\/admin\/runs\/([0-9a-f-]{36})(\/secret)?$/u.exec(pathname);
  if (!match || !SBX054_UUID.test(match[1] ?? "")) return undefined;
  return { runId: match[1]!, secret: match[2] === "/secret" };
}

function publicPath(pathname: string): {
  kind: Sbx054RequestKind;
  runId: string;
  caseId: Sbx054CaseId;
  canary: string;
} | undefined {
  const match = /^\/v1\/sbx054\/(public|secret)\/([0-9a-f-]{36})\/([^/]{1,80})\/([^/]{1,80})$/u.exec(pathname);
  if (!match || !SBX054_UUID.test(match[2] ?? "") ||
      !(SBX054_CASES as readonly string[]).includes(match[3] ?? "") || !SBX054_CANARY.test(match[4] ?? "")) {
    return undefined;
  }
  return {
    kind: match[1] as Sbx054RequestKind,
    runId: match[2]!,
    caseId: match[3] as Sbx054CaseId,
    canary: match[4]!,
  };
}

export async function startSbx054Receiver(options: Sbx054ReceiverOptions): Promise<Sbx054ReceiverHandle> {
  const adminKey = boundedKey(options.adminKey, "SBX-054 admin key");
  const actionKey = boundedKey(options.actionKey, "SBX-054 action key");
  const publicOrigin = exactOrigin(options.publicOrigin);
  const runtime = receiverRuntime();
  const states = new Map<string, RunState>();

  const server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", "http://receiver.invalid");
      if (url.search !== "" || url.hash !== "") { sendEmpty(response, 400); return; }
      if (url.pathname === "/healthz") {
        sendJson(response, 200, {
          ok: true,
          testId: SBX054_TEST_ID,
          hostMatched: hostEvidence(request, publicOrigin.hostname).matched,
          ...runtime,
        });
        return;
      }

      const admin = adminPath(url.pathname);
      if (admin !== undefined) {
        if (!localAdmin(request, adminKey)) { sendEmpty(response, 401); return; }
        if (!admin.secret && request.method === "PUT") {
          if (states.has(admin.runId)) { sendEmpty(response, 409); return; }
          const body = await readBody(request, MAX_ADMIN_BODY);
          try {
            const configuration = validateSbx054ReceiverConfiguration(
              JSON.parse(body.toString("utf8")), publicOrigin.hostname,
            );
            if (configuration.runId !== admin.runId) throw new Error("run path did not match configuration");
            states.set(admin.runId, {
              configuration,
              configuredAt: new Date().toISOString(),
              events: [],
              secretCleared: false,
              unexpectedRequests: 0,
            });
            sendEmpty(response, 204);
          } finally {
            body.fill(0);
          }
          return;
        }
        const state = states.get(admin.runId);
        if (state === undefined) { sendEmpty(response, 404); return; }
        if (admin.secret && request.method === "PUT") {
          if (state.stagedSecret !== undefined || state.events.length !== 1 ||
              state.events[0]?.caseId !== "v2-runtime-deny-target") {
            sendEmpty(response, 409);
            return;
          }
          const secret = await readBody(request, MAX_SECRET_BODY);
          if (secret.byteLength < 32) { secret.fill(0); sendEmpty(response, 400); return; }
          state.stagedSecret = Buffer.from(secret);
          secret.fill(0);
          sendEmpty(response, 204);
          return;
        }
        if (admin.secret && request.method === "DELETE") {
          const existed = state.stagedSecret !== undefined;
          state.stagedSecret?.fill(0);
          delete state.stagedSecret;
          state.secretCleared ||= existed;
          sendEmpty(response, existed ? 204 : 404);
          return;
        }
        if (!admin.secret && request.method === "GET") { sendJson(response, 200, snapshot(state)); return; }
        if (!admin.secret && request.method === "DELETE") {
          clearState(state);
          states.delete(admin.runId);
          sendEmpty(response, 204);
          return;
        }
        sendEmpty(response, 405);
        return;
      }

      const route = publicPath(url.pathname);
      if (route === undefined) { sendEmpty(response, 404); return; }
      const state = states.get(route.runId);
      if (state === undefined) { sendEmpty(response, 404); return; }
      const configured = state.configuration.cases.find((entry) => entry.caseId === route.caseId);
      const host = hostEvidence(request, state.configuration.publicHost);
      const body = await readBody(request, route.kind === "secret" ? MAX_SECRET_BODY : 1);
      try {
        const receivedCommitment = deriveSbx054CanaryCommitment(actionKey, route.runId, route.caseId, route.canary);
        const canaryMatched = configured !== undefined && configured.kind === route.kind &&
          receivedCommitment === configured.canaryCommitment;
        const publicExact = route.kind === "public" && request.method === "GET" && body.byteLength === 0;
        const lengths = rawHeaderValues(request, "content-length");
        const types = rawHeaderValues(request, "content-type");
        const secretFraming = route.kind === "secret" && request.method === "POST" &&
          lengths.length === 1 && lengths[0] === String(body.byteLength) && types.length === 1 &&
          types[0] === "application/octet-stream";
        const secretMatched = secretFraming && state.stagedSecret !== undefined &&
          body.byteLength === state.stagedSecret.byteLength && timingSafeEqual(body, state.stagedSecret);
        const accepted = host.matched && canaryMatched && (publicExact || secretMatched);
        const receipt = accepted
          ? deriveSbx054Receipt(actionKey, route.kind, route.runId, route.caseId,
              receivedCommitment, secretMatched)
          : undefined;
        const secretProof = accepted && route.kind === "secret"
          ? deriveSbx054SecretProof(body, route.runId, route.caseId, receivedCommitment)
          : undefined;
        const operationId = secretProof === undefined
          ? undefined
          : deriveSbx054OperationId(actionKey, route.runId, route.caseId, secretProof);
        state.events.push({
          sequence: state.events.length + 1,
          observedAt: new Date().toISOString(),
          kind: route.kind,
          caseId: route.caseId,
          method: request.method ?? "",
          hostHeaderLines: host.lines,
          hostHeaderValues: host.values,
          hostMatched: host.matched,
          pathMatched: canaryMatched,
          canaryCommitment: receivedCommitment,
          bodyLength: body.byteLength,
          secretMatched,
          responseStatus: accepted ? 200 : 401,
          ...(receipt === undefined ? {} : { receipt }),
          ...(secretProof === undefined ? {} : { secretProof }),
          ...(operationId === undefined ? {} : { operationId }),
        });
        if (!accepted) state.unexpectedRequests += 1;
        if (route.kind === "secret") {
          state.stagedSecret?.fill(0);
          delete state.stagedSecret;
          state.secretCleared = true;
        }
        if (!accepted) { sendEmpty(response, 401); return; }
        sendJson(response, 200, {
          receipt,
          secretProof: secretProof ?? null,
          operationId: operationId ?? null,
        });
      } finally {
        body.fill(0);
      }
    } catch {
      sendEmpty(response, 400);
    }
  });

  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 43_154;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  return {
    server,
    host,
    port: (server.address() as AddressInfo).port,
    async close(): Promise<void> {
      for (const state of states.values()) clearState(state);
      states.clear();
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    },
  };
}

async function main(): Promise<void> {
  const handle = await startSbx054Receiver({
    adminKey: process.env.SBX054_ADMIN_KEY ?? "",
    actionKey: process.env.SBX054_ACTION_KEY ?? "",
    publicOrigin: process.env.SBX054_PUBLIC_ORIGIN ?? "",
    port: Number(process.env.SBX054_RECEIVER_PORT ?? "43154"),
  });
  process.stdout.write(`${JSON.stringify({
    ready: true,
    testId: SBX054_TEST_ID,
    host: handle.host,
    port: handle.port,
  })}\n`);
}

const invoked = process.argv[1] ? pathToFileURL(process.argv[1]).href : "";
if (import.meta.url === invoked) {
  main().catch(() => {
    process.stderr.write("SBX-054 receiver failed without emitting raw state\n");
    process.exitCode = 1;
  });
}
