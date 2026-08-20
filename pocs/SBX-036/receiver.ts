import "dotenv/config";

import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createTcpServer, isIP, type Server as TcpServer, type Socket } from "node:net";
import { createSecureContext, TLSSocket, type SecureContext } from "node:tls";
import {
  SBX036_SSL_REQUEST_CODE,
  SBX036_SSL_REQUEST_HEX,
  SBX036_TEST_ID,
  deriveSbx036PublicOperationId,
  deriveSbx036SecretOperationId,
  type Sbx036EndpointRole,
  type Sbx036Receipt,
  type Sbx036ReceiverStatus,
} from "./verdict.js";

const sslRequest = Buffer.from(SBX036_SSL_REQUEST_HEX, "hex");
const frameMagic = Buffer.from("SBX036P1", "ascii");
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const casePattern = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const canaryPattern = /^pub_[A-Za-z0-9_-]{24}$/u;
const commitmentPattern = /^[a-f0-9]{64}$/u;
const secretPattern = /^opsec_[A-Za-z0-9_-]{43}$/u;
const dnsPattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const maximumFirstRead = 512;
const maximumStartup = 1_024;
const maximumAdminBody = 16_384;

export interface Sbx036EndpointIdentity {
  hostname: string;
  publicIPv4: string;
  port: number;
}

export interface Sbx036ListenerOptions extends Sbx036EndpointIdentity {
  bindHost: string;
  certificatePath: string;
  privateKeyPath: string;
}

export interface Sbx036ReceiverOptions {
  key: string;
  allowedControl: Sbx036EndpointIdentity;
  denied: Sbx036ListenerOptions;
  adminHost?: "127.0.0.1";
  adminPort?: number;
}

export interface Sbx036RunConfiguration {
  runId: string;
  phase: "public" | "secret";
  testId: typeof SBX036_TEST_ID;
  allowedHostname: string;
  allowedIPv4: string;
  allowedPort: number;
  deniedHostname: string;
  deniedIPv4: string;
  deniedPort: number;
  notBefore: string;
  notAfter: string;
  expectedPublicCanaries: Record<string, string>;
}

interface RunState {
  configuration: Sbx036RunConfiguration;
  receipts: Sbx036Receipt[];
  secretCaseId?: string;
  secretCommitment?: string;
  secretRegistered: boolean;
}

export interface ParsedPreTlsFrame {
  kind: "public" | "secret";
  runId: string;
  caseId: string;
  payload: Buffer;
  byteLength: number;
}

export interface ParsedStartupMessage {
  protocolVersion: number;
  user: string;
  database: string;
  applicationName: {
    runId: string;
    caseId: string;
    publicCanary: string;
  };
  byteLength: number;
}

export interface ConnectionMeta {
  connectionId: string;
  sourceAddress: string;
  sourcePort: number;
  listenerHostname: string;
  listenerIPv4: string;
  listenerPort: number;
  observedAt: string;
}

export interface Sbx036ReceiverHandle {
  configurationEpoch: string;
  adminOrigin: string;
  close(): Promise<void>;
}

function canonicalHostname(value: string, field: string): string {
  if (value !== value.toLowerCase() || !dnsPattern.test(value)) throw new Error(`${field} must be canonical DNS`);
  return value;
}

function canonicalPublicIPv4(value: string, field: string): string {
  if (isIP(value) !== 4 || value.split(".").some((part) => !/^(?:0|[1-9][0-9]{0,2})$/u.test(part))) {
    throw new Error(`${field} must be canonical IPv4`);
  }
  const [a = -1, b = -1] = value.split(".").map(Number);
  if (a <= 0 || a >= 224 || a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127)) {
    throw new Error(`${field} must be public IPv4`);
  }
  return value;
}

function validPort(value: number, field: string): number {
  if (!Number.isInteger(value) || value < 1 || value > 65_535) throw new Error(`${field} is invalid`);
  return value;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], field: string): void {
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  if (actual.length !== sorted.length || actual.some((key, index) => key !== sorted[index])) {
    throw new Error(`${field} fields are not exact`);
  }
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${field} must be an object`);
  return value as Record<string, unknown>;
}

function safeTimestamp(value: unknown, field: string): string {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) throw new Error(`${field} is invalid`);
  return value;
}

function safeSourceAddress(value: string | undefined): string {
  if (!value) return "unknown";
  return value.replace(/[^0-9a-fA-F:.]/gu, "").slice(0, 64) || "unknown";
}

function validWindow(config: Sbx036RunConfiguration, observedAt: string): boolean {
  const start = Date.parse(config.notBefore);
  const end = Date.parse(config.notAfter);
  const observed = Date.parse(observedAt);
  return Number.isFinite(start) && Number.isFinite(end) && Number.isFinite(observed) &&
    end > start && end - start <= 30 * 60_000 && observed >= start && observed <= end;
}

export function parseSbx036PreTlsFrame(input: Buffer): ParsedPreTlsFrame | undefined {
  if (input.length < 13 || input.length > 256 || !input.subarray(0, 8).equals(frameMagic)) return undefined;
  const kindByte = input[8];
  if (kindByte !== 0x50 && kindByte !== 0x53) return undefined;
  const runLength = input[9]!;
  const caseLength = input[10]!;
  const payloadLength = input.readUInt16BE(11);
  if (runLength < 1 || runLength > 64 || caseLength < 1 || caseLength > 63 || payloadLength < 1 || payloadLength > 96) {
    return undefined;
  }
  const total = 13 + runLength + caseLength + payloadLength;
  if (input.length !== total) return undefined;
  const runStart = 13;
  const caseStart = runStart + runLength;
  const payloadStart = caseStart + caseLength;
  const runId = input.subarray(runStart, caseStart).toString("ascii");
  const caseId = input.subarray(caseStart, payloadStart).toString("ascii");
  if (!uuidPattern.test(runId) || !casePattern.test(caseId)) return undefined;
  return {
    kind: kindByte === 0x50 ? "public" : "secret",
    runId,
    caseId,
    payload: Buffer.from(input.subarray(payloadStart)),
    byteLength: total,
  };
}

export function encodeSbx036PreTlsFrame(
  kind: "public" | "secret",
  runId: string,
  caseId: string,
  payload: string,
): Buffer {
  if (!uuidPattern.test(runId) || !casePattern.test(caseId) ||
    (kind === "public" ? !canaryPattern.test(payload) : !secretPattern.test(payload))) {
    throw new Error("pre-TLS frame fields are invalid");
  }
  const run = Buffer.from(runId, "ascii");
  const caseBytes = Buffer.from(caseId, "ascii");
  const payloadBytes = Buffer.from(payload, "ascii");
  const header = Buffer.alloc(13);
  frameMagic.copy(header, 0);
  header[8] = kind === "public" ? 0x50 : 0x53;
  header[9] = run.length;
  header[10] = caseBytes.length;
  header.writeUInt16BE(payloadBytes.length, 11);
  const frame = Buffer.concat([header, run, caseBytes, payloadBytes]);
  if (frame.length > 256) throw new Error("pre-TLS frame exceeded its bound");
  payloadBytes.fill(0);
  return frame;
}

function readCString(buffer: Buffer, cursor: number): { value: string; cursor: number } | undefined {
  const end = buffer.indexOf(0, cursor);
  if (end < cursor) return undefined;
  const bytes = buffer.subarray(cursor, end);
  if (bytes.some((byte) => byte < 0x20 || byte > 0x7e)) return undefined;
  return { value: bytes.toString("ascii"), cursor: end + 1 };
}

export function parseSbx036StartupMessage(input: Buffer): ParsedStartupMessage | undefined {
  if (input.length < 10 || input.length > maximumStartup) return undefined;
  const length = input.readUInt32BE(0);
  const protocolVersion = input.readUInt32BE(4);
  if (length !== input.length || protocolVersion !== 196_608 || input[input.length - 1] !== 0) return undefined;
  const parameters = new Map<string, string>();
  let cursor = 8;
  while (cursor < input.length - 1) {
    const name = readCString(input, cursor);
    if (!name || name.value.length === 0) return undefined;
    const value = readCString(input, name.cursor);
    if (!value || parameters.has(name.value)) return undefined;
    parameters.set(name.value, value.value);
    cursor = value.cursor;
  }
  if (cursor !== input.length - 1 || parameters.size !== 3 || parameters.get("user") !== "sbx036" ||
    parameters.get("database") !== "sbx036") return undefined;
  const application = parameters.get("application_name")?.split("|");
  if (!application || application.length !== 4 || application[0] !== "sbx036") return undefined;
  const [, runId = "", caseId = "", publicCanary = ""] = application;
  if (!uuidPattern.test(runId) || !casePattern.test(caseId) || !canaryPattern.test(publicCanary)) return undefined;
  return {
    protocolVersion,
    user: "sbx036",
    database: "sbx036",
    applicationName: { runId, caseId, publicCanary },
    byteLength: input.length,
  };
}

export function buildSbx036ErrorResponse(operationId: string): Buffer {
  if (!/^pgp_[A-Za-z0-9_-]{43}$/u.test(operationId)) throw new Error("operation ID is invalid");
  const fields = Buffer.concat([
    Buffer.from("SERROR\0C28000\0Msbx036:", "ascii"),
    Buffer.from(operationId, "ascii"),
    Buffer.from("\0\0", "ascii"),
  ]);
  const output = Buffer.alloc(1 + 4 + fields.length);
  output[0] = 0x45;
  output.writeUInt32BE(4 + fields.length, 1);
  fields.copy(output, 5);
  return output;
}

function validateRunConfiguration(
  value: unknown,
  listeners: { allowed: Sbx036EndpointIdentity; denied: Sbx036ListenerOptions },
): Sbx036RunConfiguration {
  const input = record(value, "configuration");
  exactKeys(input, [
    "allowedHostname", "allowedIPv4", "allowedPort", "deniedHostname", "deniedIPv4", "deniedPort",
    "expectedPublicCanaries", "notAfter", "notBefore", "phase", "runId", "testId",
  ], "configuration");
  if (input.testId !== SBX036_TEST_ID || (input.phase !== "public" && input.phase !== "secret")) {
    throw new Error("configuration identity is invalid");
  }
  const runId = typeof input.runId === "string" ? input.runId : "";
  if (!uuidPattern.test(runId)) throw new Error("runId is invalid");
  const publicCanaries = record(input.expectedPublicCanaries, "expectedPublicCanaries");
  if (Object.keys(publicCanaries).length < 1 || Object.keys(publicCanaries).length > 16) {
    throw new Error("expectedPublicCanaries count is invalid");
  }
  const expectedPublicCanaries: Record<string, string> = {};
  for (const [caseId, canary] of Object.entries(publicCanaries)) {
    if (!casePattern.test(caseId) || typeof canary !== "string" || !canaryPattern.test(canary)) {
      throw new Error("expected public discriminator is invalid");
    }
    expectedPublicCanaries[caseId] = canary;
  }
  const notBefore = safeTimestamp(input.notBefore, "notBefore");
  const notAfter = safeTimestamp(input.notAfter, "notAfter");
  const allowedPort = typeof input.allowedPort === "number" ? input.allowedPort : -1;
  const deniedPort = typeof input.deniedPort === "number" ? input.deniedPort : -1;
  if (input.allowedHostname !== listeners.allowed.hostname || input.allowedIPv4 !== listeners.allowed.publicIPv4 ||
    allowedPort !== listeners.allowed.port || input.deniedHostname !== listeners.denied.hostname ||
    input.deniedIPv4 !== listeners.denied.publicIPv4 || deniedPort !== listeners.denied.port) {
    throw new Error("configuration does not bind the exact receiver listeners");
  }
  const output: Sbx036RunConfiguration = {
    runId,
    phase: input.phase,
    testId: SBX036_TEST_ID,
    allowedHostname: listeners.allowed.hostname,
    allowedIPv4: listeners.allowed.publicIPv4,
    allowedPort: listeners.allowed.port,
    deniedHostname: listeners.denied.hostname,
    deniedIPv4: listeners.denied.publicIPv4,
    deniedPort: listeners.denied.port,
    notBefore,
    notAfter,
    expectedPublicCanaries,
  };
  if (!validWindow(output, notBefore) || Date.parse(notAfter) <= Date.parse(notBefore)) {
    throw new Error("configuration observation window is invalid or exceeds 30 minutes");
  }
  return output;
}

export class Sbx036ReceiverLedger {
  readonly configurationEpoch: string;
  readonly #key: string;
  readonly #listeners: { allowed: Sbx036EndpointIdentity; denied: Sbx036ListenerOptions };
  readonly #runs = new Map<string, RunState>();

  constructor(
    key: string,
    listeners: { allowed: Sbx036EndpointIdentity; denied: Sbx036ListenerOptions },
    configurationEpoch = randomUUID(),
  ) {
    if (key.length < 32 || key.length > 512 || /[\0\r\n]/u.test(key)) throw new Error("receiver key is invalid");
    if (!uuidPattern.test(configurationEpoch)) throw new Error("configuration epoch must be a UUID");
    this.#key = key;
    this.#listeners = listeners;
    this.configurationEpoch = configurationEpoch;
  }

  configure(value: unknown): void {
    const configuration = validateRunConfiguration(value, this.#listeners);
    if (this.#runs.has(configuration.runId)) throw new Error("run already configured");
    this.#runs.set(configuration.runId, { configuration, receipts: [], secretRegistered: false });
  }

  registerSecret(runId: string, caseId: string, commitment: string): string {
    const state = this.#runs.get(runId);
    if (!state || state.configuration.phase !== "secret" || state.secretRegistered || !casePattern.test(caseId) ||
      !commitmentPattern.test(commitment) || state.configuration.expectedPublicCanaries[caseId] !== undefined) {
      throw new Error("secret registration is invalid");
    }
    state.secretCaseId = caseId;
    state.secretCommitment = commitment;
    state.secretRegistered = true;
    return deriveSbx036SecretOperationId(this.#key, runId, caseId, commitment);
  }

  observePreTls(
    role: Sbx036EndpointRole,
    input: Buffer,
    meta: ConnectionMeta,
    beforeServerResponse: boolean,
  ): boolean {
    const parsed = parseSbx036PreTlsFrame(input);
    if (!parsed) return false;
    try {
      const state = this.#runs.get(parsed.runId);
      if (!state || !validWindow(state.configuration, meta.observedAt) || role !== "denied" ||
        meta.listenerHostname !== state.configuration.deniedHostname ||
        meta.listenerIPv4 !== state.configuration.deniedIPv4 || meta.listenerPort !== state.configuration.deniedPort ||
        state.receipts.some((receipt) => receipt.caseId === parsed.caseId)) return false;
      let operationId: string;
      if (parsed.kind === "public") {
        const canary = parsed.payload.toString("ascii");
        if (state.configuration.expectedPublicCanaries[parsed.caseId] !== canary || !canaryPattern.test(canary)) return false;
        operationId = deriveSbx036PublicOperationId(this.#key, parsed.runId, parsed.caseId, canary);
      } else {
        if (!state.secretRegistered || state.secretCaseId !== parsed.caseId || !state.secretCommitment ||
          !secretPattern.test(parsed.payload.toString("ascii"))) return false;
        const actualCommitment = createHmac("sha256", this.#key)
          .update(`commit\n${parsed.runId}\n${parsed.caseId}\n`)
          .update(parsed.payload)
          .digest("hex");
        const actual = Buffer.from(actualCommitment, "hex");
        const expected = Buffer.from(state.secretCommitment, "hex");
        const matches = actual.length === 32 && expected.length === 32 && timingSafeEqual(actual, expected);
        actual.fill(0);
        if (!matches) return false;
        operationId = deriveSbx036SecretOperationId(this.#key, parsed.runId, parsed.caseId, state.secretCommitment);
      }
      state.receipts.push({
        role,
        channel: "pre-tls-coalesced",
        runId: parsed.runId,
        caseId: parsed.caseId,
        discriminatorKind: parsed.kind,
        exactSslRequest: true,
        sslRequestLength: 8,
        sslRequestCode: SBX036_SSL_REQUEST_CODE,
        bytesAfterSslRequest: parsed.byteLength,
        observedBeforeServerResponse: beforeServerResponse,
        serverResponseSentBeforeObservation: !beforeServerResponse,
        serverResponseSentAfterObservation: beforeServerResponse,
        operationId,
        rawPayloadStored: false,
        payloadDigestStored: false,
        observedAt: meta.observedAt,
        connectionId: meta.connectionId,
        sourceAddress: meta.sourceAddress,
        sourcePort: meta.sourcePort,
        listenerHostname: meta.listenerHostname,
        listenerIPv4: meta.listenerIPv4,
        listenerPort: meta.listenerPort,
        configurationEpoch: this.configurationEpoch,
        withinConfiguredWindow: true,
      });
      return true;
    } finally {
      parsed.payload.fill(0);
    }
  }

  observeRawControl(input: Buffer, meta: ConnectionMeta): boolean {
    const parsed = parseSbx036PreTlsFrame(input);
    if (!parsed) return false;
    try {
      const state = this.#runs.get(parsed.runId);
      if (!state || parsed.kind !== "public" || !validWindow(state.configuration, meta.observedAt) ||
        meta.listenerHostname !== state.configuration.deniedHostname ||
        meta.listenerIPv4 !== state.configuration.deniedIPv4 || meta.listenerPort !== state.configuration.deniedPort ||
        state.receipts.some((receipt) => receipt.caseId === parsed.caseId)) return false;
      const canary = parsed.payload.toString("ascii");
      if (state.configuration.expectedPublicCanaries[parsed.caseId] !== canary || !canaryPattern.test(canary)) return false;
      const operationId = deriveSbx036PublicOperationId(this.#key, parsed.runId, parsed.caseId, canary);
      state.receipts.push({
        role: "denied",
        channel: "raw-control",
        runId: parsed.runId,
        caseId: parsed.caseId,
        discriminatorKind: "public",
        exactSslRequest: false,
        sslRequestLength: 0,
        sslRequestCode: 0,
        bytesAfterSslRequest: parsed.byteLength,
        observedBeforeServerResponse: true,
        serverResponseSentBeforeObservation: false,
        serverResponseSentAfterObservation: false,
        operationId,
        rawPayloadStored: false,
        payloadDigestStored: false,
        observedAt: meta.observedAt,
        connectionId: meta.connectionId,
        sourceAddress: meta.sourceAddress,
        sourcePort: meta.sourcePort,
        listenerHostname: meta.listenerHostname,
        listenerIPv4: meta.listenerIPv4,
        listenerPort: meta.listenerPort,
        configurationEpoch: this.configurationEpoch,
        withinConfiguredWindow: true,
      });
      return true;
    } finally {
      parsed.payload.fill(0);
    }
  }

  observeTlsStartup(role: Sbx036EndpointRole, input: Buffer, meta: ConnectionMeta): string | undefined {
    const parsed = parseSbx036StartupMessage(input);
    if (!parsed) return undefined;
    const state = this.#runs.get(parsed.applicationName.runId);
    if (!state || !validWindow(state.configuration, meta.observedAt) ||
      state.receipts.some((receipt) => receipt.caseId === parsed.applicationName.caseId)) return undefined;
    const listener = role === "allowed" ? this.#listeners.allowed : this.#listeners.denied;
    if (meta.listenerHostname !== listener.hostname || meta.listenerIPv4 !== listener.publicIPv4 ||
      meta.listenerPort !== listener.port) return undefined;
    const expected = state.configuration.expectedPublicCanaries[parsed.applicationName.caseId];
    if (expected !== parsed.applicationName.publicCanary) return undefined;
    const operationId = deriveSbx036PublicOperationId(
      this.#key,
      parsed.applicationName.runId,
      parsed.applicationName.caseId,
      parsed.applicationName.publicCanary,
    );
    state.receipts.push({
      role,
      channel: "tls-startup",
      runId: parsed.applicationName.runId,
      caseId: parsed.applicationName.caseId,
      discriminatorKind: "public",
      exactSslRequest: true,
      sslRequestLength: 8,
      sslRequestCode: SBX036_SSL_REQUEST_CODE,
      bytesAfterSslRequest: parsed.byteLength,
      observedBeforeServerResponse: false,
      serverResponseSentBeforeObservation: true,
      serverResponseSentAfterObservation: false,
      operationId,
      rawPayloadStored: false,
      payloadDigestStored: false,
      observedAt: meta.observedAt,
      connectionId: meta.connectionId,
      sourceAddress: meta.sourceAddress,
      sourcePort: meta.sourcePort,
      listenerHostname: meta.listenerHostname,
      listenerIPv4: meta.listenerIPv4,
      listenerPort: meta.listenerPort,
      configurationEpoch: this.configurationEpoch,
      withinConfiguredWindow: true,
    });
    return operationId;
  }

  status(runId: string): Sbx036ReceiverStatus {
    const state = this.#runs.get(runId);
    if (!state) {
      return {
        configured: false,
        receipts: [],
        secretRegistered: false,
        rawPayloadStored: false,
        payloadDigestStored: false,
      };
    }
    return {
      configured: true,
      phase: state.configuration.phase,
      receipts: state.receipts.map((receipt) => ({ ...receipt })),
      secretRegistered: state.secretRegistered,
      rawPayloadStored: false,
      payloadDigestStored: false,
    };
  }

  delete(runId: string): boolean {
    const state = this.#runs.get(runId);
    if (state) delete state.secretCommitment;
    return this.#runs.delete(runId);
  }
}

function adminAuthorized(request: IncomingMessage, key: string): boolean {
  const supplied = request.headers.authorization;
  if (typeof supplied !== "string" || !supplied.startsWith("Bearer ")) return false;
  const actual = createHash("sha256").update(supplied.slice(7)).digest();
  const expected = createHash("sha256").update(key).digest();
  return timingSafeEqual(actual, expected);
}

function sendJson(response: ServerResponse, status: number, value: unknown): void {
  const body = Buffer.from(`${JSON.stringify(value)}\n`);
  response.writeHead(status, {
    "cache-control": "no-store, max-age=0",
    "content-length": body.length,
    "content-type": "application/json; charset=utf-8",
    "x-content-type-options": "nosniff",
  });
  response.end(body);
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk);
    length += bytes.length;
    if (length > maximumAdminBody) throw new Error("admin body exceeded its bound");
    chunks.push(bytes);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function runPath(pathname: string, suffix = ""): string | undefined {
  const match = new RegExp(`^/v1/sbx036/admin/runs/([0-9a-f-]{36})${suffix}$`, "u").exec(pathname);
  return match?.[1];
}

async function listen(server: TcpServer | import("node:http").Server, port: number, host: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => { server.off("listening", onListening); reject(error); };
    const onListening = (): void => { server.off("error", onError); resolve(); };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, host);
  });
}

async function closeServer(server: TcpServer | import("node:http").Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
    if ("closeAllConnections" in server && typeof server.closeAllConnections === "function") {
      server.closeAllConnections();
    }
  });
}

function handleSocket(
  socket: Socket,
  role: Sbx036EndpointRole,
  listener: Sbx036ListenerOptions,
  secureContext: SecureContext,
  ledger: Sbx036ReceiverLedger,
): void {
  const connectionId = `conn_${randomBytes(18).toString("base64url")}`;
  const sourceAddress = safeSourceAddress(socket.remoteAddress);
  const sourcePort = socket.remotePort ?? 0;
  let pending = Buffer.alloc(0);
  let serverResponseSent = false;
  let serverResponseFlushed = false;
  let state: "prefix" | "raw" | "post-s" | "tls" = "prefix";
  socket.setTimeout(5_000, () => socket.destroy());

  const meta = (): ConnectionMeta => ({
    connectionId,
    sourceAddress,
    sourcePort,
    listenerHostname: listener.hostname,
    listenerIPv4: listener.publicIPv4,
    listenerPort: listener.port,
    observedAt: new Date().toISOString(),
  });

  const startTls = (extra: Buffer): void => {
    state = "tls";
    socket.removeAllListeners("data");
    socket.pause();
    if (extra.length > 0) socket.unshift(extra);
    const tlsSocket = new TLSSocket(socket, { isServer: true, secureContext });
    let startup = Buffer.alloc(0);
    tlsSocket.setTimeout(5_000, () => tlsSocket.destroy());
    tlsSocket.once("secure", () => {
      if ((tlsSocket as TLSSocket & { servername?: string }).servername !== listener.hostname) {
        tlsSocket.destroy();
        return;
      }
      tlsSocket.on("data", (chunk: Buffer) => {
        if (startup.length + chunk.length > maximumStartup) {
          tlsSocket.destroy();
          return;
        }
        startup = Buffer.concat([startup, chunk]);
        if (startup.length < 4) return;
        const length = startup.readUInt32BE(0);
        if (length < 10 || length > maximumStartup || startup.length < length) return;
        const meta: ConnectionMeta = {
          connectionId,
          sourceAddress,
          sourcePort,
          listenerHostname: listener.hostname,
          listenerIPv4: listener.publicIPv4,
          listenerPort: listener.port,
          observedAt: new Date().toISOString(),
        };
        const operationId = ledger.observeTlsStartup(role, Buffer.from(startup.subarray(0, length)), meta);
        startup.fill(0);
        if (!operationId) {
          tlsSocket.destroy();
          return;
        }
        tlsSocket.end(buildSbx036ErrorResponse(operationId));
      });
    });
    tlsSocket.once("error", () => tlsSocket.destroy());
    tlsSocket.resume();
  };

  const sendServerResponse = (next?: () => void): void => {
    if (serverResponseSent) {
      next?.();
      return;
    }
    serverResponseSent = true;
    socket.write(Buffer.from("S", "ascii"), (error) => {
      if (error) socket.destroy();
      else {
        serverResponseFlushed = true;
        next?.();
      }
    });
  };

  const isTlsPrefix = (value: Buffer): boolean =>
    value.length >= 1 && value[0] === 0x16 &&
    (value.length < 2 || value[1] === 0x03) &&
    (value.length < 3 || (value[2]! >= 0x01 && value[2]! <= 0x04));

  const isFramePrefix = (value: Buffer): boolean => {
    const compared = Math.min(value.length, frameMagic.length);
    return value.subarray(0, compared).equals(frameMagic.subarray(0, compared));
  };

  const completeFrameLength = (value: Buffer): number | undefined => {
    if (value.length < 13 || !isFramePrefix(value)) return undefined;
    const runLength = value[9]!;
    const caseLength = value[10]!;
    const payloadLength = value.readUInt16BE(11);
    const total = 13 + runLength + caseLength + payloadLength;
    return total <= 256 ? total : -1;
  };

  const consumePostS = (): void => {
    if (pending.length > maximumFirstRead) {
      pending.fill(0);
      socket.destroy();
      return;
    }
    if (isTlsPrefix(pending)) {
      const extra = Buffer.from(pending);
      pending.fill(0);
      startTls(extra);
      return;
    }
    if (!isFramePrefix(pending)) {
      pending.fill(0);
      socket.destroy();
      return;
    }
    const expectedLength = completeFrameLength(pending);
    if (expectedLength === -1) {
      pending.fill(0);
      socket.destroy();
      return;
    }
    if (expectedLength === undefined || pending.length < expectedLength) return;
    if (pending.length !== expectedLength) {
      pending.fill(0);
      socket.destroy();
      return;
    }
    const frame = Buffer.from(pending);
    ledger.observePreTls(role, frame, meta(), !serverResponseFlushed);
    pending.fill(0);
    startTls(frame);
  };

  const consumeRawControl = (): void => {
    if (pending.length > maximumFirstRead || !isFramePrefix(pending)) {
      pending.fill(0);
      socket.destroy();
      return;
    }
    const expectedLength = completeFrameLength(pending);
    if (expectedLength === -1) {
      pending.fill(0);
      socket.destroy();
      return;
    }
    if (expectedLength === undefined || pending.length < expectedLength) return;
    if (pending.length !== expectedLength) {
      pending.fill(0);
      socket.destroy();
      return;
    }
    const frame = Buffer.from(pending);
    ledger.observeRawControl(frame, meta());
    frame.fill(0);
    pending.fill(0);
    socket.destroy();
  };

  socket.on("data", (chunk: Buffer) => {
    if (state === "tls") return;
    if (pending.length + chunk.length > maximumFirstRead) {
      socket.destroy();
      return;
    }
    pending = Buffer.concat([pending, chunk]);
    if (state === "raw") {
      consumeRawControl();
      return;
    }
    if (state === "post-s") {
      consumePostS();
      return;
    }
    if (pending.length < 8) return;
    const prefix = Buffer.from(pending.subarray(0, 8));
    const extra = Buffer.from(pending.subarray(8));
    pending.fill(0);
    pending = Buffer.alloc(0);
    const exactPrefix = prefix.equals(sslRequest);
    const rawControlPrefix = prefix.equals(frameMagic);
    prefix.fill(0);
    if (!exactPrefix) {
      if (rawControlPrefix) {
        pending = Buffer.concat([frameMagic, extra]);
        extra.fill(0);
        state = "raw";
        consumeRawControl();
      } else {
        extra.fill(0);
        socket.destroy();
      }
      return;
    }
    if (extra.length === 0) {
      state = "post-s";
      sendServerResponse();
      return;
    }
    const frame = parseSbx036PreTlsFrame(extra);
    if (frame) {
      frame.payload.fill(0);
      ledger.observePreTls(role, extra, meta(), true);
      sendServerResponse(() => startTls(extra));
      return;
    }
    if (isTlsPrefix(extra)) {
      sendServerResponse(() => startTls(extra));
      return;
    }
    if (isFramePrefix(extra)) {
      pending = extra;
      state = "post-s";
      sendServerResponse(() => consumePostS());
      return;
    }
    sendServerResponse(() => startTls(extra));
  });
  socket.once("error", () => socket.destroy());
}

function validateListener(value: Sbx036ListenerOptions, field: string): Sbx036ListenerOptions {
  canonicalHostname(value.hostname, `${field}.hostname`);
  canonicalPublicIPv4(value.publicIPv4, `${field}.publicIPv4`);
  if (isIP(value.bindHost) === 0) throw new Error(`${field}.bindHost must be a local IP literal`);
  validPort(value.port, `${field}.port`);
  if (!value.certificatePath || !value.privateKeyPath) throw new Error(`${field} certificate paths are required`);
  return value;
}

function validateEndpointIdentity(value: Sbx036EndpointIdentity, field: string): Sbx036EndpointIdentity {
  canonicalHostname(value.hostname, `${field}.hostname`);
  canonicalPublicIPv4(value.publicIPv4, `${field}.publicIPv4`);
  validPort(value.port, `${field}.port`);
  return value;
}

export async function startSbx036Receiver(options: Sbx036ReceiverOptions): Promise<Sbx036ReceiverHandle> {
  const allowed = validateEndpointIdentity(options.allowedControl, "allowedControl");
  const denied = validateListener(options.denied, "denied");
  if (allowed.hostname === denied.hostname || allowed.publicIPv4 === denied.publicIPv4) {
    throw new Error("raw pre-TLS proof requires distinct hostnames and distinct public IP:port listener targets");
  }
  const configurationEpoch = randomUUID();
  const ledger = new Sbx036ReceiverLedger(options.key, { allowed, denied }, configurationEpoch);
  const [deniedCertificate, deniedKey] = await Promise.all([
    readFile(denied.certificatePath),
    readFile(denied.privateKeyPath),
  ]);
  const deniedContext = createSecureContext({ cert: deniedCertificate, key: deniedKey, minVersion: "TLSv1.2" });
  const deniedServer = createTcpServer((socket) => handleSocket(socket, "denied", denied, deniedContext, ledger));
  const adminHost = options.adminHost ?? "127.0.0.1";
  const adminPort = options.adminPort ?? 43_136;
  if (adminHost !== "127.0.0.1") throw new Error("admin server must bind only to 127.0.0.1");
  validPort(adminPort, "adminPort");
  const admin = createHttpServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
      if (!adminAuthorized(request, options.key)) return sendJson(response, 401, { error: "unauthorized" });
      if (request.method === "GET" && url.pathname === "/healthz") {
        return sendJson(response, 200, {
          ok: true,
          testId: SBX036_TEST_ID,
          configurationEpoch,
          listeners: {
            allowed: { hostname: allowed.hostname, ipv4: allowed.publicIPv4, port: allowed.port },
            denied: { hostname: denied.hostname, ipv4: denied.publicIPv4, port: denied.port },
          },
        });
      }
      const secretRunId = runPath(url.pathname, "/secret");
      if (secretRunId && request.method === "POST") {
        const body = record(await readJson(request), "secret registration");
        exactKeys(body, ["caseId", "commitment"], "secret registration");
        const operationId = ledger.registerSecret(
          secretRunId,
          typeof body.caseId === "string" ? body.caseId : "",
          typeof body.commitment === "string" ? body.commitment : "",
        );
        return sendJson(response, 201, { registered: true, operationId });
      }
      const runId = runPath(url.pathname);
      if (!runId) return sendJson(response, 404, { error: "not found" });
      if (request.method === "POST") {
        ledger.configure(await readJson(request));
        return sendJson(response, 201, { configured: true, configurationEpoch });
      }
      if (request.method === "GET") return sendJson(response, 200, ledger.status(runId));
      if (request.method === "DELETE") return sendJson(response, ledger.delete(runId) ? 200 : 404, { deleted: true });
      return sendJson(response, 405, { error: "method not allowed" });
    } catch {
      return sendJson(response, 400, { error: "invalid request" });
    }
  });
  try {
    await listen(deniedServer, denied.port, denied.bindHost);
    await listen(admin, adminPort, adminHost);
  } catch (error) {
    await Promise.allSettled([closeServer(deniedServer), closeServer(admin)]);
    throw error;
  }
  return {
    configurationEpoch,
    adminOrigin: `http://${adminHost}:${adminPort}`,
    async close() {
      await Promise.all([closeServer(deniedServer), closeServer(admin)]);
    },
  };
}

async function main(): Promise<void> {
  const required = (name: string): string => {
    const value = process.env[name];
    if (!value) throw new Error(`${name} is required`);
    return value;
  };
  const handle = await startSbx036Receiver({
    key: required("SBX036_ADMIN_KEY"),
    allowedControl: {
      hostname: required("SBX036_ALLOWED_HOSTNAME"),
      publicIPv4: required("SBX036_ALLOWED_IPV4"),
      port: Number(process.env.SBX036_ALLOWED_PORT ?? "443"),
    },
    denied: {
      hostname: required("SBX036_DENIED_HOSTNAME"),
      publicIPv4: required("SBX036_DENIED_IPV4"),
      bindHost: required("SBX036_DENIED_BIND_HOST"),
      port: Number(process.env.SBX036_DENIED_PORT ?? "5432"),
      certificatePath: required("SBX036_DENIED_CERT_PATH"),
      privateKeyPath: required("SBX036_DENIED_KEY_PATH"),
    },
    adminPort: Number(process.env.SBX036_ADMIN_PORT ?? "43136"),
  });
  process.stdout.write(`${JSON.stringify({
    ready: true,
    testId: SBX036_TEST_ID,
    configurationEpoch: handle.configurationEpoch,
    adminOrigin: handle.adminOrigin,
  })}\n`);
  const shutdown = async (): Promise<void> => { await handle.close(); process.exit(0); };
  process.once("SIGINT", () => { void shutdown(); });
  process.once("SIGTERM", () => { void shutdown(); });
}

if (import.meta.url === new URL(process.argv[1] ?? "", "file:").href) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
