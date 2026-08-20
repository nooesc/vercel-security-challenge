import "dotenv/config";

import { createHash, timingSafeEqual } from "node:crypto";
import dgram, { type RemoteInfo } from "node:dgram";
import { createServer as createHttpServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import { createServer as createTcpServer, isIP, type Server as TcpServer, type Socket } from "node:net";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  SBX001_CASES,
  SBX001_DIRECT_TEST_ID,
  SBX001_RECEIVER_WINDOW_MS,
  canonicalDnsName,
  decodeSecretDnsLabel,
  derivePublicDnsOperationId,
  deriveSecretDnsCommitment,
  deriveSecretDnsOperationId,
  equalSecretDnsCommitments,
  parseDnsQuestion,
  publicDnsLabel,
  type Sbx001CaseArm,
  type Sbx001CaseId,
  type Sbx001DnsTransport,
  type Sbx001Receipt,
  type Sbx001ReceiverSnapshot,
  validateNonce,
  validateRunId,
} from "./direct-shared.js";

const MAX_ADMIN_BODY = 16 * 1024;
const MAX_TCP_DNS_BYTES = 512;
const PUBLIC_CASES = [
  SBX001_CASES.outsideUdp,
  SBX001_CASES.outsideTcp,
  SBX001_CASES.allowPublic,
  SBX001_CASES.denyPublic,
] as const;

type PublicCase = typeof PUBLIC_CASES[number];

export interface Sbx001ReceiverConfiguration {
  runId: string;
  testId: typeof SBX001_DIRECT_TEST_ID;
  authoritativeZone: string;
  nameserverHostname: string;
  answerIPv4: string;
  configuredAt: string;
  expiresAt: string;
  observationWindowMs: typeof SBX001_RECEIVER_WINDOW_MS;
  publicLabels: Record<PublicCase, string>;
}

interface ReceiverState {
  configuration: Sbx001ReceiverConfiguration;
  receipts: Map<Sbx001CaseId, Sbx001Receipt>;
  arms: Map<Sbx001CaseId, Sbx001CaseArm>;
  secretCommitment?: string;
  secretNonce?: string;
  secretRegisteredAt?: string;
}

export interface Sbx001ReceiverOptions {
  adminKey: string;
  proofKey: string;
  authoritativeZone: string;
  nameserverHostname: string;
  answerIPv4?: string;
  bindHost?: string;
  dnsPort?: number;
  adminHost?: "127.0.0.1";
  adminPort?: number;
  /** Local-test seam used to force a peer reset after ingress and before the response write. */
  beforeTcpResponse?: (socket: Socket) => void;
}

export interface Sbx001ReceiverHandle {
  udpSocket: dgram.Socket;
  tcpServer: TcpServer;
  adminServer: HttpServer;
  dnsPort: number;
  adminPort: number;
  close(): Promise<void>;
}

function object(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${field} must be an object`);
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[], field: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${field} fields are not exact`);
  }
}

function boundedString(value: unknown, field: string, maximum = 512): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[\0\r\n]/u.test(value)) {
    throw new Error(`${field} is invalid`);
  }
  return value;
}

function ipv4(value: unknown, field: string): string {
  const checked = boundedString(value, field, 15);
  if (isIP(checked) !== 4 || checked.split(".").some((part) => String(Number(part)) !== part || Number(part) > 255)) {
    throw new Error(`${field} must be canonical IPv4`);
  }
  return checked;
}

function port(value: number, field: string, allowZero = false): number {
  const minimum = allowZero ? 0 : 1;
  if (!Number.isInteger(value) || value < minimum || value > 65_535) throw new Error(`${field} is invalid`);
  return value;
}

function strongSecret(value: string, field: string): string {
  if (Buffer.byteLength(value) < 32 || Buffer.byteLength(value) > 256 || /[\0\r\n]/u.test(value)) {
    throw new Error(`${field} must contain 32-256 bytes without control characters`);
  }
  return value;
}

function configuration(
  value: unknown,
  expectedZone: string,
  expectedNameserver: string,
  expectedAnswer: string,
): Sbx001ReceiverConfiguration {
  const input = object(value, "configuration");
  exactKeys(input, [
    "answerIPv4",
    "authoritativeZone",
    "nameserverHostname",
    "observationWindowMs",
    "publicLabels",
    "runId",
    "testId",
  ], "configuration");
  const runId = validateRunId(boundedString(input.runId, "runId", 36));
  if (input.testId !== SBX001_DIRECT_TEST_ID) throw new Error("testId is invalid");
  const authoritativeZone = canonicalDnsName(boundedString(input.authoritativeZone, "authoritativeZone", 253));
  const nameserverHostname = canonicalDnsName(boundedString(input.nameserverHostname, "nameserverHostname", 253));
  const answerIPv4 = ipv4(input.answerIPv4, "answerIPv4");
  if (input.observationWindowMs !== SBX001_RECEIVER_WINDOW_MS) {
    throw new Error("observationWindowMs is not exact");
  }
  if (authoritativeZone !== expectedZone || nameserverHostname !== expectedNameserver || answerIPv4 !== expectedAnswer) {
    throw new Error("configuration does not match receiver identity");
  }
  const configuredAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + SBX001_RECEIVER_WINDOW_MS).toISOString();
  const rawLabels = object(input.publicLabels, "publicLabels");
  exactKeys(rawLabels, PUBLIC_CASES, "publicLabels");
  const publicLabels = Object.fromEntries(PUBLIC_CASES.map((caseId) => {
    const label = boundedString(rawLabels[caseId], `publicLabels.${caseId}`, 63);
    if (label !== publicDnsLabel(caseId, validateNonce(label.slice(1)))) {
      throw new Error(`publicLabels.${caseId} is not exact`);
    }
    return [caseId, label];
  })) as Record<PublicCase, string>;
  if (new Set(Object.values(publicLabels).map((label) => label.slice(1))).size !== PUBLIC_CASES.length) {
    throw new Error("publicLabels must use distinct 128-bit nonces");
  }
  return {
    runId,
    testId: SBX001_DIRECT_TEST_ID,
    authoritativeZone,
    nameserverHostname,
    answerIPv4,
    configuredAt,
    expiresAt,
    observationWindowMs: SBX001_RECEIVER_WINDOW_MS,
    publicLabels,
  };
}

function snapshot(state: ReceiverState | undefined): Sbx001ReceiverSnapshot {
  return {
    configured: state !== undefined,
    ...(state ? { runId: state.configuration.runId } : {}),
    ...(state ? {
      configuredAt: state.configuration.configuredAt,
      expiresAt: state.configuration.expiresAt,
      observationWindowMs: state.configuration.observationWindowMs,
    } : {}),
    receipts: state ? [...state.receipts.values()].map((receipt) => ({ ...receipt })) : [],
    arms: state ? [...state.arms.values()].map((arm) => ({ ...arm })) : [],
    secretRegistered: state?.secretCommitment !== undefined,
    ...(state?.secretRegisteredAt === undefined ? {} : { secretRegisteredAt: state.secretRegisteredAt }),
    rawQueryNamesRetained: false,
    rawSecretsRetained: false,
    rawSecretDigestsRetained: false,
  };
}

function fixedDigest(value: string): Buffer {
  return createHash("sha256").update(value).digest();
}

function adminAuthorized(request: IncomingMessage, adminKey: string): boolean {
  const authorization = request.headers.authorization;
  return typeof authorization === "string" && authorization.startsWith("Bearer ") &&
    timingSafeEqual(fixedDigest(authorization.slice(7)), fixedDigest(adminKey));
}

async function body(request: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for await (const chunk of request) {
      const bytes = Buffer.from(chunk);
      total += bytes.length;
      if (total > MAX_ADMIN_BODY) throw new Error("admin request body exceeded its bound");
      chunks.push(bytes);
    }
    return Buffer.concat(chunks, total);
  } catch (error) {
    for (const chunk of chunks) chunk.fill(0);
    throw error;
  }
}

async function jsonBody(request: IncomingMessage): Promise<unknown> {
  const bytes = await body(request);
  try {
    return JSON.parse(bytes.toString("utf8"));
  } finally {
    bytes.fill(0);
  }
}

function sendJson(response: ServerResponse, status: number, value: unknown): void {
  const bytes = Buffer.from(JSON.stringify(value));
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    "content-length": String(bytes.length),
  });
  response.end(bytes, () => bytes.fill(0));
}

function sendEmpty(response: ServerResponse, status: number): void {
  response.writeHead(status, { "cache-control": "no-store", "content-length": "0" });
  response.end();
}

function runPath(pathname: string, suffix = ""): string | undefined {
  const match = new RegExp(`^/v1/sbx001/admin/runs/([^/]+)${suffix}$`, "u").exec(pathname);
  if (!match?.[1]) return undefined;
  try {
    return validateRunId(decodeURIComponent(match[1]));
  } catch {
    return undefined;
  }
}

function armPath(pathname: string): { runId: string; caseId: Sbx001CaseId } | undefined {
  const match = /^\/v1\/sbx001\/admin\/runs\/([^/]+)\/cases\/([^/]+)\/arm$/u.exec(pathname);
  if (!match?.[1] || !match[2] || !Object.values(SBX001_CASES).includes(match[2] as Sbx001CaseId)) return undefined;
  try {
    return { runId: validateRunId(decodeURIComponent(match[1])), caseId: match[2] as Sbx001CaseId };
  } catch {
    return undefined;
  }
}

function safeSourceAddress(value: string | undefined): string {
  return (value ?? "unknown").replace(/[^0-9a-fA-F:.]/gu, "").slice(0, 64) || "unknown";
}

interface MatchedQuery {
  caseId: Sbx001CaseId;
  kind: "public" | "secret";
  operationId: string;
}

function matchQuery(state: ReceiverState, proofKey: string, queryName: string): MatchedQuery | undefined {
  const { configuration: config } = state;
  if (!withinWindow(state, new Date().toISOString())) return undefined;
  const suffix = `.${config.authoritativeZone}`;
  if (!queryName.endsWith(suffix)) return undefined;
  const label = queryName.slice(0, -suffix.length);
  if (!label || label.includes(".")) return undefined;
  for (const caseId of PUBLIC_CASES) {
    if (label === config.publicLabels[caseId]) {
      const matched = {
        caseId,
        kind: "public" as const,
        operationId: derivePublicDnsOperationId(proofKey, config.runId, caseId, label),
      };
      const arm = state.arms.get(caseId);
      return arm?.operationId === matched.operationId ? matched : undefined;
    }
  }
  if (!state.secretCommitment || !state.secretNonce) return undefined;
  const secret = decodeSecretDnsLabel(label, state.secretNonce);
  if (!secret) return undefined;
  try {
    const observedCommitment = deriveSecretDnsCommitment(proofKey, config.runId, secret);
    if (!equalSecretDnsCommitments(observedCommitment, state.secretCommitment)) return undefined;
    const matched = {
      caseId: SBX001_CASES.denySecret,
      kind: "secret" as const,
      operationId: deriveSecretDnsOperationId(proofKey, config.runId, state.secretCommitment),
    };
    const arm = state.arms.get(SBX001_CASES.denySecret);
    return arm?.operationId === matched.operationId ? matched : undefined;
  } finally {
    secret.fill(0);
  }
}

function withinWindow(state: ReceiverState, observedAt: string): boolean {
  const observed = Date.parse(observedAt);
  return observed >= Date.parse(state.configuration.configuredAt) && observed <= Date.parse(state.configuration.expiresAt);
}

function recordReceipt(
  state: ReceiverState,
  matched: MatchedQuery,
  transport: Sbx001DnsTransport,
  sourceAddress: string,
  sourcePort: number,
  observedAt: string,
): Sbx001Receipt | undefined {
  const arm = state.arms.get(matched.caseId);
  if (!arm || arm.operationId !== matched.operationId) return undefined;
  const existing = state.receipts.get(matched.caseId);
  if (existing) {
    existing.duplicateCount += 1;
    return existing;
  }
  const receipt: Sbx001Receipt = {
    runId: state.configuration.runId,
    caseId: matched.caseId,
    kind: matched.kind,
    transport,
    queryType: "A",
    authoritativeResponseSent: false,
    operationId: matched.operationId,
    armedAt: arm.armedAt,
    observedAt,
    sourceAddress: safeSourceAddress(sourceAddress),
    sourcePort,
    duplicateCount: 0,
    withinConfiguredWindow: withinWindow(state, observedAt),
    rawQueryNameRetained: false,
    rawSecretRetained: false,
    rawSecretDigestRetained: false,
  };
  state.receipts.set(matched.caseId, receipt);
  return receipt;
}

function markAuthoritativeResponseSent(receipt: Sbx001Receipt | undefined): void {
  if (receipt) receipt.authoritativeResponseSent = true;
}

function expectedOperation(state: ReceiverState, proofKey: string, caseId: Sbx001CaseId): string | undefined {
  if (caseId === SBX001_CASES.denySecret) {
    return state.secretCommitment
      ? deriveSecretDnsOperationId(proofKey, state.configuration.runId, state.secretCommitment)
      : undefined;
  }
  return derivePublicDnsOperationId(
    proofKey,
    state.configuration.runId,
    caseId,
    state.configuration.publicLabels[caseId],
  );
}

function armPrerequisitePassed(state: ReceiverState, caseId: Sbx001CaseId): boolean {
  if (caseId === SBX001_CASES.outsideUdp) return true;
  if (caseId === SBX001_CASES.outsideTcp) return state.receipts.has(SBX001_CASES.outsideUdp);
  if (caseId === SBX001_CASES.allowPublic) {
    return state.receipts.has(SBX001_CASES.outsideUdp) && state.receipts.has(SBX001_CASES.outsideTcp);
  }
  if (caseId === SBX001_CASES.denyPublic) return state.receipts.has(SBX001_CASES.allowPublic);
  return state.receipts.has(SBX001_CASES.denyPublic) && state.secretCommitment !== undefined && state.secretNonce !== undefined;
}

function encodeDnsName(value: string): Buffer {
  const canonical = canonicalDnsName(value);
  return Buffer.concat([
    ...canonical.split(".").flatMap((label) => {
      const bytes = Buffer.from(label, "ascii");
      return [Buffer.from([bytes.length]), bytes];
    }),
    Buffer.from([0]),
  ]);
}

function resourceRecord(owner: string, type: number, ttl: number, data: Buffer): Buffer {
  const name = encodeDnsName(owner);
  const fixed = Buffer.alloc(10);
  fixed.writeUInt16BE(type, 0);
  fixed.writeUInt16BE(1, 2);
  fixed.writeUInt32BE(ttl, 4);
  fixed.writeUInt16BE(data.length, 8);
  return Buffer.concat([name, fixed, data]);
}

function soaData(zone: string, nameserver: string): Buffer {
  const rname = canonicalDnsName(`hostmaster.${zone}`);
  const times = Buffer.alloc(20);
  times.writeUInt32BE(1, 0);
  times.writeUInt32BE(300, 4);
  times.writeUInt32BE(60, 8);
  times.writeUInt32BE(86_400, 12);
  times.writeUInt32BE(0, 16);
  return Buffer.concat([encodeDnsName(nameserver), encodeDnsName(rname), times]);
}

function responsePacket(input: {
  query: Buffer;
  authoritative: boolean;
  responseCode: number;
  answers?: Buffer[];
  authorities?: Buffer[];
}): Buffer | undefined {
  const parsed = parseDnsQuestion(input.query);
  if (!parsed) return undefined;
  const answers = input.answers ?? [];
  const authorities = input.authorities ?? [];
  const header = Buffer.alloc(12);
  header.writeUInt16BE(parsed.transactionId, 0);
  header.writeUInt16BE(0x8000 | (input.authoritative ? 0x0400 : 0) |
    (parsed.requestFlags & 0x0100) | (input.responseCode & 0x000f), 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(answers.length, 6);
  header.writeUInt16BE(authorities.length, 8);
  return Buffer.concat([header, input.query.subarray(12, parsed.questionEnd), ...answers, ...authorities]);
}

function authoritativeResponse(input: {
  query: Buffer;
  zone: string;
  nameserver: string;
  answerIPv4: string;
  matched?: MatchedQuery;
}): Buffer | undefined {
  const parsed = parseDnsQuestion(input.query);
  if (!parsed) return undefined;
  const inZone = parsed.queryName === input.zone || parsed.queryName.endsWith(`.${input.zone}`);
  if (!inZone) return responsePacket({ query: input.query, authoritative: false, responseCode: 5 });
  const soa = () => resourceRecord(input.zone, 6, 0, soaData(input.zone, input.nameserver));
  if (parsed.queryName === input.zone && parsed.queryType === 2) {
    return responsePacket({
      query: input.query,
      authoritative: true,
      responseCode: 0,
      answers: [resourceRecord(input.zone, 2, 0, encodeDnsName(input.nameserver))],
    });
  }
  if (parsed.queryName === input.zone && parsed.queryType === 6) {
    return responsePacket({ query: input.query, authoritative: true, responseCode: 0, answers: [soa()] });
  }
  if (input.matched && parsed.queryType === 1) {
    const octets = input.answerIPv4.split(".").map(Number);
    return responsePacket({
      query: input.query,
      authoritative: true,
      responseCode: 0,
      answers: [resourceRecord(parsed.queryName, 1, 0, Buffer.from(octets))],
    });
  }
  if (input.matched) {
    return responsePacket({ query: input.query, authoritative: true, responseCode: 0, authorities: [soa()] });
  }
  if (parsed.queryName === input.zone) {
    return responsePacket({ query: input.query, authoritative: true, responseCode: 0, authorities: [soa()] });
  }
  return responsePacket({ query: input.query, authoritative: true, responseCode: 3, authorities: [soa()] });
}

function processDnsMessage(
  query: Buffer,
  state: ReceiverState | undefined,
  proofKey: string,
  authoritativeZone: string,
  nameserverHostname: string,
  answerIPv4: string,
): { response: Buffer; matched?: MatchedQuery; receiptState?: ReceiverState } | undefined {
  const parsed = parseDnsQuestion(query);
  if (!parsed) return undefined;
  const recognized = state ? matchQuery(state, proofKey, parsed.queryName) : undefined;
  const response = authoritativeResponse({
    query,
    zone: authoritativeZone,
    nameserver: nameserverHostname,
    answerIPv4,
    ...(recognized ? { matched: recognized } : {}),
  });
  const matched = parsed.queryType === 1 ? recognized : undefined;
  return response ? {
    response,
    ...(matched && state ? { matched, receiptState: state } : {}),
  } : undefined;
}

function closeUdp(socket: dgram.Socket): Promise<void> {
  return new Promise((resolve) => socket.close(() => resolve()));
}

function closeServer(server: TcpServer | HttpServer): Promise<void> {
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

async function listenServer(server: TcpServer | HttpServer, portValue: number, host: string): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(portValue, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("server did not bind a TCP address");
  return address.port;
}

async function bindUdp(socket: dgram.Socket, portValue: number, host: string): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    socket.once("error", reject);
    socket.bind(portValue, host, () => {
      socket.off("error", reject);
      resolve();
    });
  });
  const address = socket.address();
  if (typeof address === "string") throw new Error("UDP socket did not bind an IP address");
  return address.port;
}

export async function startSbx001AuthoritativeReceiver(
  options: Sbx001ReceiverOptions,
): Promise<Sbx001ReceiverHandle> {
  const adminKey = strongSecret(options.adminKey, "adminKey");
  const proofKey = strongSecret(options.proofKey, "proofKey");
  const authoritativeZone = canonicalDnsName(options.authoritativeZone, "authoritativeZone");
  const nameserverHostname = canonicalDnsName(options.nameserverHostname, "nameserverHostname");
  const answerIPv4 = ipv4(options.answerIPv4 ?? "192.0.2.1", "answerIPv4");
  const bindHost = options.bindHost ?? "0.0.0.0";
  if (isIP(bindHost) === 0) throw new Error("bindHost must be an IP address");
  const requestedDnsPort = port(options.dnsPort ?? 53, "dnsPort", true);
  const adminHost = options.adminHost ?? "127.0.0.1";
  const requestedAdminPort = port(options.adminPort ?? 43_101, "adminPort", true);
  let state: ReceiverState | undefined;

  const udpSocket = dgram.createSocket(isIP(bindHost) === 6 ? "udp6" : "udp4");
  udpSocket.on("message", (query: Buffer, remote: RemoteInfo) => {
    const result = processDnsMessage(query, state, proofKey, authoritativeZone, nameserverHostname, answerIPv4);
    query.fill(0);
    if (!result) return;
    const receipt = result.matched && result.receiptState
      ? recordReceipt(
        result.receiptState,
        result.matched,
        "udp",
        remote.address,
        remote.port,
        new Date().toISOString(),
      )
      : undefined;
    udpSocket.send(result.response, remote.port, remote.address, (error) => {
      if (!error) markAuthoritativeResponseSent(receipt);
      result.response.fill(0);
    });
  });
  let actualDnsPort: number;
  try {
    actualDnsPort = await bindUdp(udpSocket, requestedDnsPort, bindHost);
  } catch (error) {
    await Promise.allSettled([closeUdp(udpSocket)]);
    throw error;
  }

  const tcpServer = createTcpServer((socket: Socket) => {
    let buffer = Buffer.alloc(0);
    let handled = false;
    socket.setTimeout(5_000, () => socket.destroy());
    socket.on("data", (chunk) => {
      if (handled) return;
      if (buffer.length + chunk.length > MAX_TCP_DNS_BYTES + 2) {
        socket.destroy();
        return;
      }
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length < 2) return;
      const length = buffer.readUInt16BE(0);
      if (length < 17 || length > MAX_TCP_DNS_BYTES) {
        socket.destroy();
        return;
      }
      if (buffer.length < length + 2) return;
      if (buffer.length !== length + 2) {
        socket.destroy();
        return;
      }
      handled = true;
      const query = Buffer.from(buffer.subarray(2));
      buffer.fill(0);
      buffer = Buffer.alloc(0);
      const result = processDnsMessage(query, state, proofKey, authoritativeZone, nameserverHostname, answerIPv4);
      query.fill(0);
      if (!result) {
        socket.destroy();
        return;
      }
      const frame = Buffer.alloc(2 + result.response.length);
      frame.writeUInt16BE(result.response.length, 0);
      result.response.copy(frame, 2);
      result.response.fill(0);
      const receipt = result.matched && result.receiptState
        ? recordReceipt(
          result.receiptState,
          result.matched,
          "tcp",
          socket.remoteAddress ?? "unknown",
          socket.remotePort ?? 0,
          new Date().toISOString(),
        )
        : undefined;
      options.beforeTcpResponse?.(socket);
      if (socket.destroyed) {
        frame.fill(0);
        return;
      }
      socket.end(frame, () => {
        markAuthoritativeResponseSent(receipt);
        frame.fill(0);
      });
    });
  });
  try {
    await listenServer(tcpServer, actualDnsPort, bindHost);
  } catch (error) {
    await Promise.allSettled([closeUdp(udpSocket), closeServer(tcpServer)]);
    throw error;
  }

  const adminServer = createHttpServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", `http://${adminHost}`);
      if (request.method === "GET" && url.pathname === "/healthz") {
        sendJson(response, 200, {
          ok: true,
          service: "sbx001-direct-authoritative",
          udp: true,
          tcp: true,
          rawQueryLogging: false,
        });
        return;
      }
      if (!adminAuthorized(request, adminKey)) {
        sendEmpty(response, 401);
        return;
      }
      const arm = armPath(url.pathname);
      if (arm !== undefined) {
        if (request.method !== "PUT") {
          sendEmpty(response, 405);
          return;
        }
        if (!state || state.configuration.runId !== arm.runId) {
          sendEmpty(response, 404);
          return;
        }
        const parsed = object(await jsonBody(request), "case arm");
        exactKeys(parsed, ["operationId"], "case arm");
        const operationId = boundedString(parsed.operationId, "operationId", 47);
        const wanted = expectedOperation(state, proofKey, arm.caseId);
        if (!withinWindow(state, new Date().toISOString()) || !wanted || operationId !== wanted ||
          !/^dns_[A-Za-z0-9_-]{43}$/u.test(operationId)) {
          sendEmpty(response, 409);
          return;
        }
        const existing = state.arms.get(arm.caseId);
        if (existing) {
          if (existing.operationId !== operationId) {
            sendEmpty(response, 409);
            return;
          }
          sendJson(response, 200, existing);
          return;
        }
        if (!armPrerequisitePassed(state, arm.caseId)) {
          sendEmpty(response, 409);
          return;
        }
        const checked: Sbx001CaseArm = {
          caseId: arm.caseId,
          operationId,
          armedAt: new Date().toISOString(),
        };
        state.arms.set(arm.caseId, checked);
        sendJson(response, 200, checked);
        return;
      }
      const secretRunId = runPath(url.pathname, "/secret");
      if (secretRunId !== undefined) {
        if (request.method !== "PUT") {
          sendEmpty(response, 405);
          return;
        }
        if (!state || state.configuration.runId !== secretRunId) {
          sendEmpty(response, 404);
          return;
        }
        const parsed = object(await jsonBody(request), "secret registration");
        exactKeys(parsed, ["queryNonce", "secretCommitment"], "secret registration");
        const commitment = boundedString(parsed.secretCommitment, "secretCommitment", 47);
        const queryNonce = validateNonce(boundedString(parsed.queryNonce, "queryNonce", 32));
        if (!/^dsc_[A-Za-z0-9_-]{43}$/u.test(commitment)) {
          sendEmpty(response, 400);
          return;
        }
        if (Object.values(state.configuration.publicLabels).some((label) => label.slice(1) === queryNonce)) {
          sendEmpty(response, 409);
          return;
        }
        if (!withinWindow(state, new Date().toISOString()) || !state.receipts.has(SBX001_CASES.denyPublic)) {
          sendEmpty(response, 409);
          return;
        }
        if (state.secretCommitment !== undefined || state.secretNonce !== undefined) {
          if (state.secretCommitment === commitment && state.secretNonce === queryNonce) {
            sendEmpty(response, 204);
            return;
          }
          sendEmpty(response, 409);
          return;
        }
        state.secretCommitment = commitment;
        state.secretNonce = queryNonce;
        state.secretRegisteredAt = new Date().toISOString();
        sendEmpty(response, 204);
        return;
      }
      const runId = runPath(url.pathname);
      if (runId === undefined) {
        sendEmpty(response, 404);
        return;
      }
      if (request.method === "PUT") {
        if (state !== undefined) {
          sendEmpty(response, 409);
          return;
        }
        const checked = configuration(await jsonBody(request), authoritativeZone, nameserverHostname, answerIPv4);
        if (checked.runId !== runId) {
          sendEmpty(response, 409);
          return;
        }
        state = { configuration: checked, receipts: new Map(), arms: new Map() };
        sendEmpty(response, 204);
        return;
      }
      if (request.method === "GET") {
        if (!state || state.configuration.runId !== runId) {
          sendEmpty(response, 404);
          return;
        }
        sendJson(response, 200, snapshot(state));
        return;
      }
      if (request.method === "DELETE") {
        if (!state || state.configuration.runId !== runId) {
          sendEmpty(response, 404);
          return;
        }
        state = undefined;
        sendEmpty(response, 204);
        return;
      }
      sendEmpty(response, 405);
    } catch {
      sendEmpty(response, 400);
    }
  });
  let actualAdminPort: number;
  try {
    actualAdminPort = await listenServer(adminServer, requestedAdminPort, adminHost);
  } catch (error) {
    await Promise.allSettled([closeUdp(udpSocket), closeServer(tcpServer), closeServer(adminServer)]);
    throw error;
  }

  let closed = false;
  return {
    udpSocket,
    tcpServer,
    adminServer,
    dnsPort: actualDnsPort,
    adminPort: actualAdminPort,
    async close(): Promise<void> {
      if (closed) return;
      closed = true;
      state = undefined;
      await Promise.all([closeUdp(udpSocket), closeServer(tcpServer), closeServer(adminServer)]);
    },
  };
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function main(): Promise<void> {
  const receiver = await startSbx001AuthoritativeReceiver({
    adminKey: required("SBX001_ADMIN_KEY"),
    proofKey: required("SBX001_PROOF_KEY"),
    authoritativeZone: required("SBX001_AUTHORITATIVE_ZONE"),
    nameserverHostname: required("SBX001_NAMESERVER_HOSTNAME"),
    answerIPv4: process.env.SBX001_ANSWER_IPV4 ?? "192.0.2.1",
    bindHost: process.env.SBX001_BIND_HOST ?? "0.0.0.0",
    dnsPort: Number(process.env.SBX001_DNS_PORT ?? "53"),
    adminHost: "127.0.0.1",
    adminPort: Number(process.env.SBX001_ADMIN_PORT ?? "43101"),
  });
  process.stdout.write(`${JSON.stringify({
    ready: true,
    service: "sbx001-direct-authoritative",
    dnsPort: receiver.dnsPort,
    adminPort: receiver.adminPort,
    udp: true,
    tcp: true,
    rawQueryLogging: false,
  })}\n`);
  const stop = async () => {
    await receiver.close();
    process.exit(0);
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : "receiver failed"}\n`);
    process.exitCode = 1;
  });
}
