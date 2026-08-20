import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHmac, timingSafeEqual } from "node:crypto";
import { access } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  SBX042_TEST_ID,
  deriveSbx042OperationId,
  type Sbx042ReceiverEvent,
  type Sbx042ReceiverSnapshot,
} from "./verdict.js";

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const casePattern = /^[a-z0-9][a-z0-9-]{0,63}$/u;
const publicPattern = /^pub_[A-Za-z0-9_-]{24}$/u;
const secretPattern = /^[A-Za-z0-9_-]{43}$/u;
const commitmentPattern = /^[a-f0-9]{64}$/u;
const framePrefix = "SBX042|1|";
const maximumBodyBytes = 16 * 1024;

interface ReceiverConfiguration {
  runId: string;
  caseId: string;
  kind: "public" | "secret";
  publicCanary?: string;
  secretCommitment?: string;
  notBefore: number;
  notAfter: number;
}

interface ReceiverState {
  tls13EarlyDataEnabled: true;
  antiReplayEnabled: true;
  completedHandshakes: number;
  noEarlyDataConnections: number;
  earlyDataReadEnds: number;
  resumedSessions: number;
  malformedFrames: number;
  configurations: Map<string, ReceiverConfiguration>;
  events: Sbx042ReceiverEvent[];
}

export interface Sbx042ReceiverOptions {
  adminKey: string;
  adminPort: number;
  opensslBin: string;
  tlsCertPath: string;
  tlsKeyPath: string;
  tlsBindHost: string;
  tlsPort: number;
  publicHostname: string;
  publicIPv4: string;
}

function key(runId: string, caseId: string): string {
  return `${runId}\0${caseId}`;
}

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("expected an object");
  return value as Record<string, unknown>;
}

function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function deriveSecretCommitment(keyValue: string, runId: string, caseId: string, secret: Buffer): string {
  return createHmac("sha256", keyValue).update(`secret\0${runId}\0${caseId}\0`).update(secret).digest("hex");
}

function exactConfiguration(body: Record<string, unknown>, runId: string, caseId: string): ReceiverConfiguration {
  if (!uuidPattern.test(runId) || !casePattern.test(caseId) || body.runId !== runId || body.caseId !== caseId) {
    throw new Error("run or case identity is invalid");
  }
  if (body.kind !== "public" && body.kind !== "secret") throw new Error("kind is invalid");
  if (!Number.isSafeInteger(body.notBefore) || !Number.isSafeInteger(body.notAfter) ||
      Number(body.notAfter) <= Number(body.notBefore) || Number(body.notAfter) - Number(body.notBefore) > 120_000) {
    throw new Error("bounded receipt window is invalid");
  }
  if (body.kind === "public") {
    if (typeof body.publicCanary !== "string" || !publicPattern.test(body.publicCanary) ||
        body.secretCommitment !== undefined) throw new Error("public configuration is invalid");
    return { runId, caseId, kind: "public", publicCanary: body.publicCanary,
      notBefore: Number(body.notBefore), notAfter: Number(body.notAfter) };
  }
  if (typeof body.secretCommitment !== "string" || !commitmentPattern.test(body.secretCommitment) ||
      body.publicCanary !== undefined) throw new Error("secret configuration is invalid");
  return { runId, caseId, kind: "secret", secretCommitment: body.secretCommitment,
    notBefore: Number(body.notBefore), notAfter: Number(body.notAfter) };
}

export function parseSbx042EarlyFrame(line: string): {
  runId: string;
  caseId: string;
  kind: "public" | "secret";
  payload: string;
} | undefined {
  const start = line.indexOf(framePrefix);
  if (start < 0) return undefined;
  const candidate = line.slice(start).trim();
  const parts = candidate.split("|");
  if (parts.length !== 6 || parts[0] !== "SBX042" || parts[1] !== "1") return undefined;
  const [, , runId = "", caseId = "", kindValue = "", payload = ""] = parts;
  if (!uuidPattern.test(runId) || !casePattern.test(caseId) ||
      (kindValue !== "public" && kindValue !== "secret")) return undefined;
  if (kindValue === "public" ? !publicPattern.test(payload) : !secretPattern.test(payload)) return undefined;
  return { runId, caseId, kind: kindValue, payload };
}

export function acceptSbx042EarlyFrame(
  state: ReceiverState,
  adminKey: string,
  line: string,
  now = Date.now(),
): Sbx042ReceiverEvent | undefined {
  const parsed = parseSbx042EarlyFrame(line);
  if (!parsed) {
    if (line.includes(framePrefix)) state.malformedFrames += 1;
    return undefined;
  }
  const configuration = state.configurations.get(key(parsed.runId, parsed.caseId));
  if (!configuration || configuration.kind !== parsed.kind || now < configuration.notBefore ||
      now > configuration.notAfter) {
    state.malformedFrames += 1;
    return undefined;
  }
  let accepted = false;
  let commitmentMatched = false;
  let signal = parsed.payload;
  let payloadBytes = Buffer.byteLength(parsed.payload);
  if (parsed.kind === "public") {
    accepted = configuration.publicCanary !== undefined && safeEqual(configuration.publicCanary, parsed.payload);
  } else {
    const secret = Buffer.from(parsed.payload, "base64url");
    try {
      payloadBytes = secret.length;
      const commitment = deriveSecretCommitment(adminKey, parsed.runId, parsed.caseId, secret);
      commitmentMatched = configuration.secretCommitment !== undefined &&
        safeEqual(configuration.secretCommitment, commitment);
      accepted = secret.length === 32 && commitmentMatched;
      signal = commitment;
    } finally {
      secret.fill(0);
    }
  }
  const event: Sbx042ReceiverEvent = {
    runId: parsed.runId,
    caseId: parsed.caseId,
    kind: parsed.kind,
    observedAt: new Date(now).toISOString(),
    accepted,
    payloadBytes,
    commitmentMatched,
    ...(accepted ? { operationId: deriveSbx042OperationId(adminKey, parsed.runId, parsed.caseId, signal) } : {}),
    rawPayloadRetained: false,
    payloadDigestRetained: false,
  };
  state.events.push(event);
  return event;
}

function snapshot(state: ReceiverState, runId?: string): Sbx042ReceiverSnapshot {
  return {
    configured: runId === undefined || [...state.configurations.values()].some((value) => value.runId === runId),
    tls13EarlyDataEnabled: true,
    antiReplayEnabled: true,
    completedHandshakes: state.completedHandshakes,
    noEarlyDataConnections: state.noEarlyDataConnections,
    earlyDataReadEnds: state.earlyDataReadEnds,
    resumedSessions: state.resumedSessions,
    malformedFrames: state.malformedFrames,
    events: state.events.filter((event) => runId === undefined || event.runId === runId),
  };
}

function count(text: string, pattern: RegExp): number {
  return [...text.matchAll(pattern)].length;
}

function processStdoutLine(state: ReceiverState, adminKey: string, line: string): void {
  state.completedHandshakes += count(line, /CIPHER is TLS_/gu);
  state.noEarlyDataConnections += count(line, /No early data received/gu);
  state.resumedSessions += count(line, /Reused session-id/gu);
  acceptSbx042EarlyFrame(state, adminKey, line);
}

function processStderrLine(state: ReceiverState, line: string): void {
  state.earlyDataReadEnds += count(line, /TLSv1\.3 read end of early data/gu);
}

function attachBoundedLines(
  stream: NodeJS.ReadableStream,
  onLine: (line: string) => void,
): void {
  let pending = "";
  stream.on("data", (chunk: Buffer | string) => {
    pending += Buffer.isBuffer(chunk) ? chunk.toString("utf8") : chunk;
    if (pending.length > 64 * 1024) pending = pending.slice(-16 * 1024);
    while (true) {
      const newline = pending.indexOf("\n");
      if (newline < 0) break;
      const line = pending.slice(0, newline);
      pending = pending.slice(newline + 1);
      onLine(line);
    }
  });
}

async function body(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.length;
    if (size > maximumBodyBytes) throw new Error("request body exceeded its bound");
    chunks.push(bytes);
  }
  return object(JSON.parse(Buffer.concat(chunks).toString("utf8")));
}

function json(response: ServerResponse, status: number, value: unknown): void {
  const encoded = Buffer.from(JSON.stringify(value));
  response.writeHead(status, { "content-type": "application/json", "content-length": encoded.length });
  response.end(encoded);
}

function authorized(request: IncomingMessage, adminKey: string): boolean {
  const value = request.headers.authorization;
  return typeof value === "string" && safeEqual(value, `Bearer ${adminKey}`);
}

function route(pathname: string): { runId: string; caseId?: string } | undefined {
  const match = /^\/v1\/sbx042\/admin\/runs\/([^/]+)(?:\/cases\/([^/]+))?$/u.exec(pathname);
  if (!match?.[1] || !uuidPattern.test(match[1])) return undefined;
  if (match[2] !== undefined && !casePattern.test(match[2])) return undefined;
  return { runId: match[1], ...(match[2] === undefined ? {} : { caseId: match[2] }) };
}

function serverArgs(options: Sbx042ReceiverOptions): string[] {
  return [
    "s_server",
    "-accept", `${options.tlsBindHost}:${options.tlsPort}`,
    "-cert", options.tlsCertPath,
    "-key", options.tlsKeyPath,
    "-tls1_3",
    "-early_data",
    "-max_early_data", "4096",
    "-recv_max_early_data", "4096",
    "-num_tickets", "2",
    "-anti_replay",
    "-state",
  ];
}

export async function startSbx042Receiver(options: Sbx042ReceiverOptions): Promise<{
  child: ChildProcessWithoutNullStreams;
  close: () => Promise<void>;
}> {
  await Promise.all([access(options.tlsCertPath), access(options.tlsKeyPath)]);
  const help = spawnSync(options.opensslBin, ["s_server", "-help"], { encoding: "utf8", timeout: 5_000 });
  const helpText = `${help.stdout ?? ""}${help.stderr ?? ""}`;
  if (help.error || !helpText.includes("-early_data") || !helpText.includes("-max_early_data") ||
      !helpText.includes("-anti_replay")) throw new Error("OpenSSL does not expose required TLS 1.3 early-data controls");
  const state: ReceiverState = {
    tls13EarlyDataEnabled: true,
    antiReplayEnabled: true,
    completedHandshakes: 0,
    noEarlyDataConnections: 0,
    earlyDataReadEnds: 0,
    resumedSessions: 0,
    malformedFrames: 0,
    configurations: new Map(),
    events: [],
  };
  const child = spawn(options.opensslBin, serverArgs(options), { stdio: ["pipe", "pipe", "pipe"] });
  attachBoundedLines(child.stdout, (line) => processStdoutLine(state, options.adminKey, line));
  attachBoundedLines(child.stderr, (line) => processStderrLine(state, line));
  const admin = createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      if (url.pathname === "/healthz" && request.method === "GET") {
        json(response, 200, { ok: true, testId: SBX042_TEST_ID, listener: {
          hostname: options.publicHostname, ipv4: options.publicIPv4, port: options.tlsPort,
        }, tls13EarlyDataEnabled: true, antiReplayEnabled: true, opensslChildRunning: child.exitCode === null });
        return;
      }
      if (!authorized(request, options.adminKey)) { json(response, 401, { error: "unauthorized" }); return; }
      const selected = route(url.pathname);
      if (!selected) { json(response, 404, { error: "not found" }); return; }
      if (request.method === "GET" && selected.caseId === undefined) {
        json(response, 200, snapshot(state, selected.runId));
        return;
      }
      if (request.method === "POST" && selected.caseId !== undefined) {
        const configuration = exactConfiguration(await body(request), selected.runId, selected.caseId);
        const selectedKey = key(selected.runId, selected.caseId);
        if (state.configurations.has(selectedKey)) throw new Error("case is already configured");
        state.configurations.set(selectedKey, configuration);
        json(response, 201, { configured: true });
        return;
      }
      if (request.method === "DELETE" && selected.caseId === undefined) {
        let deleted = false;
        for (const [entryKey, configuration] of state.configurations) {
          if (configuration.runId === selected.runId) { state.configurations.delete(entryKey); deleted = true; }
        }
        const before = state.events.length;
        state.events = state.events.filter((event) => event.runId !== selected.runId);
        json(response, 200, { deleted: deleted || state.events.length !== before });
        return;
      }
      json(response, 405, { error: "method not allowed" });
    } catch (error) {
      json(response, 400, { error: error instanceof Error ? error.message.slice(0, 512) : "request failed" });
    }
  });
  await new Promise<void>((resolveReady, reject) => {
    admin.once("error", reject);
    admin.listen(options.adminPort, "127.0.0.1", () => resolveReady());
  });
  const close = async (): Promise<void> => {
    child.kill("SIGTERM");
    await new Promise<void>((resolveClose) => admin.close(() => resolveClose()));
  };
  return { child, close };
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function port(name: string, fallback: number): number {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value < 1 || value > 65_535) throw new Error(`${name} is invalid`);
  return value;
}

async function main(): Promise<void> {
  const publicHostname = required("SBX042_ENDPOINT_HOSTNAME");
  const publicIPv4 = required("SBX042_PINNED_IPV4");
  if (publicHostname !== publicHostname.toLowerCase() || isIP(publicHostname) !== 0 || isIP(publicIPv4) !== 4) {
    throw new Error("public listener identity is invalid");
  }
  const adminKey = required("SBX042_ADMIN_KEY");
  if (adminKey.length < 32 || /[\0\r\n]/u.test(adminKey)) throw new Error("SBX042_ADMIN_KEY is invalid");
  const receiver = await startSbx042Receiver({
    adminKey,
    adminPort: port("SBX042_ADMIN_PORT", 43142),
    opensslBin: process.env.SBX042_OPENSSL_BIN ?? "openssl",
    tlsCertPath: resolve(required("SBX042_TLS_CERT_PATH")),
    tlsKeyPath: resolve(required("SBX042_TLS_KEY_PATH")),
    tlsBindHost: process.env.SBX042_TLS_BIND_HOST ?? "0.0.0.0",
    tlsPort: port("SBX042_TLS_PORT", 443),
    publicHostname,
    publicIPv4,
  });
  process.stdout.write(`${JSON.stringify({ ready: true, testId: SBX042_TEST_ID })}\n`);
  const stop = () => { void receiver.close().finally(() => process.exit(0)); };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
