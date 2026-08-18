import { createHash } from "node:crypto";
import { lstat, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import tls from "node:tls";
import { domainToASCII } from "node:url";

const SCOPE_CONFIRMATION = "I_CONTROL_THE_CONFIGURED_ORIGIN";
const MAX_CONFIG_BYTES = 64 * 1024;
const MAX_HEADER_BYTES = 32 * 1024;
const MAX_RESULT_BYTES = 128 * 1024;
const SENSITIVE_KEY = /(?:^|[-_])(?:api[-_]?key|auth(?:orization)?|cookie|credential|password|private[-_]?key|secret|token)(?:$|[-_])/i;
const ALLOWED_KEYS = new Set([
  "caPem",
  "connectHost",
  "connectPort",
  "correlation",
  "httpHost",
  "ioTimeoutMs",
  "maxResponseBytes",
  "rawPath",
  "readinessPath",
  "researcherControlledHosts",
  "resultPath",
  "scopeConfirmation",
  "sniHost",
  "triggerPath",
  "triggerTimeoutMs",
]);

function message(error) {
  const value = error instanceof Error ? error.message : String(error);
  return value.length <= 1024 ? value : `${value.slice(0, 1024)}…`;
}

function output(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function requiredString(value, name, max = 2048) {
  if (typeof value !== "string" || value.length === 0 || value.length > max) {
    throw new Error(`${name} must be a non-empty string of at most ${max} characters`);
  }
  if (value.includes("\r") || value.includes("\n") || value.includes("\0")) {
    throw new Error(`${name} contains a forbidden control character`);
  }
  return value;
}

function normalizeHost(value, name) {
  const raw = requiredString(value, name, 253).toLowerCase();
  if (isIP(raw)) return raw;
  const ascii = domainToASCII(raw);
  if (!ascii || ascii.endsWith(".") || ascii.length > 253) {
    throw new Error(`${name} must be an IP address or canonical DNS hostname`);
  }
  if (ascii.split(".").some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    throw new Error(`${name} must be an IP address or canonical DNS hostname`);
  }
  return ascii;
}

function temporaryPath(value, name) {
  const path = resolve(requiredString(value, name, 4096));
  if (!path.startsWith("/tmp/") || path === "/tmp/") {
    throw new Error(`${name} must resolve to a file below /tmp`);
  }
  return path;
}

function integer(value, fallback, name, minimum, maximum) {
  const result = value ?? fallback;
  if (!Number.isInteger(result) || result < minimum || result > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} through ${maximum}`);
  }
  return result;
}

function parseConfiguration(encoded) {
  if (typeof encoded !== "string" || encoded.length === 0) throw new Error("missing base64url probe configuration");
  const buffer = Buffer.from(encoded, "base64url");
  if (buffer.length > MAX_CONFIG_BYTES) throw new Error("probe configuration is too large");
  const decoded = JSON.parse(buffer.toString("utf8"));
  if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) throw new Error("probe configuration must be an object");
  for (const key of Object.keys(decoded)) {
    if (SENSITIVE_KEY.test(key)) throw new Error(`sensitive configuration field ${key} is not allowed`);
    if (!ALLOWED_KEYS.has(key)) throw new Error(`unknown configuration field ${key}`);
  }
  if (decoded.scopeConfirmation !== SCOPE_CONFIRMATION) {
    throw new Error(`scopeConfirmation must equal ${SCOPE_CONFIRMATION}`);
  }
  if (!Array.isArray(decoded.researcherControlledHosts) || decoded.researcherControlledHosts.length === 0 || decoded.researcherControlledHosts.length > 16) {
    throw new Error("researcherControlledHosts must list from 1 through 16 hosts");
  }
  const controlledHosts = new Set(decoded.researcherControlledHosts.map((value, index) => normalizeHost(value, `researcherControlledHosts[${index}]`)));
  if (controlledHosts.size !== decoded.researcherControlledHosts.length) throw new Error("researcherControlledHosts contains duplicates");
  const connectHost = normalizeHost(decoded.connectHost, "connectHost");
  const sniHost = normalizeHost(decoded.sniHost, "sniHost");
  const httpHost = normalizeHost(decoded.httpHost, "httpHost");
  if (isIP(sniHost)) throw new Error("sniHost must be a DNS hostname");
  for (const host of [connectHost, sniHost, httpHost]) {
    if (!controlledHosts.has(host)) throw new Error(`${host} is outside researcherControlledHosts`);
  }
  if (sniHost !== httpHost) throw new Error("sniHost and httpHost must identify the same controlled origin");
  const connectPort = integer(decoded.connectPort, undefined, "connectPort", 1, 65_535);
  const rawPath = requiredString(decoded.rawPath, "rawPath", 2048);
  if (!rawPath.startsWith("/") || rawPath.startsWith("//") || rawPath.includes("#")) {
    throw new Error("rawPath must be an origin-form path without a fragment");
  }
  const correlation = decoded.correlation;
  if (!correlation || typeof correlation !== "object" || Array.isArray(correlation)) throw new Error("correlation must be an object");
  const checkedCorrelation = {};
  for (const key of ["runId", "testId", "caseId", "canary"]) {
    const value = requiredString(correlation[key], `correlation.${key}`, 128);
    if (!/^[A-Za-z0-9._:-]+$/.test(value)) throw new Error(`correlation.${key} contains unsupported characters`);
    checkedCorrelation[key] = value;
  }
  const caPem = decoded.caPem;
  if (caPem !== undefined && (
    typeof caPem !== "string" || caPem.length === 0 || caPem.length > 32 * 1024 ||
    caPem.includes("\0") || !caPem.includes("-----BEGIN CERTIFICATE-----") || caPem.includes("PRIVATE KEY")
  )) {
    throw new Error("caPem must contain public certificates and must not contain a private key");
  }
  const readinessPath = temporaryPath(decoded.readinessPath, "readinessPath");
  const triggerPath = temporaryPath(decoded.triggerPath, "triggerPath");
  const resultPath = temporaryPath(decoded.resultPath, "resultPath");
  if (new Set([readinessPath, triggerPath, resultPath]).size !== 3) throw new Error("coordination paths must be distinct");
  return {
    connectHost,
    connectPort,
    sniHost,
    httpHost,
    rawPath,
    correlation: checkedCorrelation,
    caPem,
    readinessPath,
    triggerPath,
    resultPath,
    ioTimeoutMs: integer(decoded.ioTimeoutMs, 10_000, "ioTimeoutMs", 100, 30_000),
    triggerTimeoutMs: integer(decoded.triggerTimeoutMs, 60_000, "triggerTimeoutMs", 100, 300_000),
    maxResponseBytes: integer(decoded.maxResponseBytes, 4096, "maxResponseBytes", 1, 16_384),
  };
}

function target(config, phase) {
  const query = new URLSearchParams({
    __sbx_run: config.correlation.runId,
    __sbx_test: config.correlation.testId,
    __sbx_case: config.correlation.caseId,
    __sbx_canary: config.correlation.canary,
    __sbx_phase: phase,
  });
  return `${config.rawPath}${config.rawPath.includes("?") ? "&" : "?"}${query.toString()}`;
}

class Reader {
  constructor(socket) {
    this.iterator = socket[Symbol.asyncIterator]();
    this.buffer = Buffer.alloc(0);
  }
  async pull() {
    const next = await this.iterator.next();
    if (next.done) throw new Error("TLS socket closed before the HTTP response completed");
    this.buffer = Buffer.concat([this.buffer, Buffer.from(next.value)]);
  }
  async through(delimiter, maximum) {
    while (true) {
      const index = this.buffer.indexOf(delimiter);
      if (index !== -1) {
        const value = this.buffer.subarray(0, index);
        this.buffer = this.buffer.subarray(index + delimiter.length);
        return value;
      }
      if (this.buffer.length > maximum) throw new Error("HTTP response headers exceeded their limit");
      await this.pull();
    }
  }
  async exact(length) {
    while (this.buffer.length < length) await this.pull();
    const value = this.buffer.subarray(0, length);
    this.buffer = this.buffer.subarray(length);
    return value;
  }
}

async function readResponse(reader, maximumBody) {
  const block = (await reader.through(Buffer.from("\r\n\r\n"), MAX_HEADER_BYTES)).toString("latin1");
  const lines = block.split("\r\n");
  const status = /^HTTP\/1\.[01] ([1-5][0-9]{2})(?: |$)/.exec(lines.shift() ?? "");
  if (!status) throw new Error("invalid HTTP/1.1 response status line");
  const headers = new Map();
  for (const line of lines) {
    const separator = line.indexOf(":");
    if (separator <= 0) throw new Error("invalid HTTP/1.1 response header");
    const name = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    const values = headers.get(name) ?? [];
    values.push(value);
    headers.set(name, values);
  }
  const statusCode = Number(status[1]);
  let body = Buffer.alloc(0);
  if (statusCode !== 204 && statusCode !== 304) {
    if (headers.has("transfer-encoding")) throw new Error("only Content-Length response framing is accepted");
    const lengths = headers.get("content-length") ?? [];
    if (lengths.length === 0 || new Set(lengths).size !== 1 || !/^[0-9]+$/.test(lengths[0])) {
      throw new Error("response requires one unambiguous Content-Length");
    }
    const length = Number(lengths[0]);
    if (!Number.isSafeInteger(length) || length > maximumBody) throw new Error("HTTP response body exceeds maxResponseBytes");
    body = await reader.exact(length);
  }
  return {
    statusCode,
    connection: headers.get("connection")?.[0],
    keepAlive: headers.get("keep-alive")?.[0],
    bodyLength: body.length,
    bodyBase64: body.toString("base64"),
    bodySha256: createHash("sha256").update(body).digest("hex"),
  };
}

async function writeRequest(socket, host, rawTarget, close) {
  const request = [
    `GET ${rawTarget} HTTP/1.1`,
    `Host: ${host}`,
    "User-Agent: vsc-policy-update-socket-probe/1",
    "Accept: application/json, text/plain;q=0.9, */*;q=0.1",
    `Connection: ${close ? "close" : "keep-alive"}`,
    "",
    "",
  ].join("\r\n");
  await new Promise((resolveWrite, rejectWrite) => {
    socket.write(request, "latin1", (error) => error ? rejectWrite(error) : resolveWrite());
  });
}

async function verifiedConnection(config) {
  let handshakes = 0;
  const socket = tls.connect({
    host: config.connectHost,
    port: config.connectPort,
    servername: config.sniHost,
    ...(config.caPem ? { ca: config.caPem } : {}),
    rejectUnauthorized: true,
    minVersion: "TLSv1.2",
  });
  socket.setTimeout(config.ioTimeoutMs, () => socket.destroy(new Error("TLS socket timed out")));
  socket.on("secureConnect", () => { handshakes += 1; });
  await new Promise((resolveConnect, rejectConnect) => {
    socket.once("secureConnect", resolveConnect);
    socket.once("error", rejectConnect);
  });
  if (!socket.authorized || socket.authorizationError) {
    socket.destroy();
    throw new Error(`TLS verification failed: ${socket.authorizationError ?? "unauthorized"}`);
  }
  socket.disableRenegotiation();
  const peer = socket.getPeerCertificate();
  const tuple = [socket.localAddress, socket.localPort, socket.remoteAddress, socket.remotePort, peer.fingerprint256].join("|");
  return {
    socket,
    handshakes: () => handshakes,
    identity: {
      id: createHash("sha256").update(tuple).digest("hex"),
      localAddress: socket.localAddress,
      localPort: socket.localPort,
      remoteAddress: socket.remoteAddress,
      remotePort: socket.remotePort,
      peerFingerprint256: peer.fingerprint256,
    },
    protocol: socket.getProtocol(),
  };
}

async function waitForTrigger(path, timeoutMs) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const metadata = await lstat(path);
      if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 1024) throw new Error("trigger must be a regular file of at most 1024 bytes");
      return { observedAt: new Date().toISOString(), waitedMs: Date.now() - started };
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 50));
  }
  throw new Error("trigger wait timed out");
}

async function requireFreshCoordinationPaths(config) {
  for (const [name, path] of [
    ["readinessPath", config.readinessPath],
    ["triggerPath", config.triggerPath],
    ["resultPath", config.resultPath],
  ]) {
    try {
      await lstat(path);
      throw new Error(`${name} must not exist before the probe starts`);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  }
}

async function attemptFreshConnection(config) {
  let connection;
  try {
    connection = await verifiedConnection(config);
    const rawTarget = target(config, "post-new");
    await writeRequest(connection.socket, config.httpHost, rawTarget, true);
    const response = await readResponse(new Reader(connection.socket), config.maxResponseBytes);
    return {
      attempted: true,
      connected: true,
      requestSucceeded: true,
      handshakeCount: connection.handshakes(),
      socket: connection.identity,
      rawTarget,
      response,
    };
  } catch (error) {
    return { attempted: true, connected: connection !== undefined, requestSucceeded: false, error: message(error) };
  } finally {
    connection?.socket.destroy();
  }
}

async function run(config) {
  let primary;
  try {
    await requireFreshCoordinationPaths(config);
    primary = await verifiedConnection(config);
    const reader = new Reader(primary.socket);
    const preTarget = target(config, "pre-update");
    await writeRequest(primary.socket, config.httpHost, preTarget, false);
    const preResponse = await readResponse(reader, config.maxResponseBytes);
    if (primary.handshakes() !== 1) throw new Error("unexpected pre-update TLS handshake count");
    primary.socket.setTimeout(0);
    const readiness = {
      schemaVersion: 1,
      ready: true,
      readyAt: new Date().toISOString(),
      primarySocketId: primary.identity.id,
      handshakeCount: 1,
      preStatusCode: preResponse.statusCode,
    };
    await writeFile(config.readinessPath, `${JSON.stringify(readiness)}\n`, { flag: "wx", mode: 0o600 });
    const trigger = await waitForTrigger(config.triggerPath, config.triggerTimeoutMs);
    primary.socket.setTimeout(config.ioTimeoutMs, () => primary.socket.destroy(new Error("TLS socket timed out")));
    const reusedTarget = target(config, "post-reused");
    let reusedPost;
    try {
      await writeRequest(primary.socket, config.httpHost, reusedTarget, true);
      const response = await readResponse(reader, config.maxResponseBytes);
      reusedPost = {
        attempted: true,
        requestSucceeded: true,
        sameSocketAsPreUpdate: true,
        socketId: primary.identity.id,
        handshakeCount: primary.handshakes(),
        rawTarget: reusedTarget,
        response,
      };
    } catch (error) {
      reusedPost = {
        attempted: true,
        requestSucceeded: false,
        sameSocketAsPreUpdate: true,
        socketId: primary.identity.id,
        handshakeCount: primary.handshakes(),
        rawTarget: reusedTarget,
        error: message(error),
      };
    } finally {
      primary.socket.destroy();
    }
    const freshPost = await attemptFreshConnection(config);
    return {
      ok: true,
      schemaVersion: 1,
      primaryTls: {
        authorized: true,
        sniHost: config.sniHost,
        handshakeCount: primary.handshakes(),
        socket: primary.identity,
        protocol: primary.protocol,
      },
      preUpdate: { rawTarget: preTarget, response: preResponse },
      readiness,
      trigger,
      reusedPost,
      freshPost,
    };
  } finally {
    primary?.socket.destroy();
  }
}

let config;
let result;
try {
  config = parseConfiguration(process.argv[2]);
  result = await run(config);
} catch (error) {
  result = { ok: false, schemaVersion: 1, error: message(error) };
}
if (config?.resultPath) {
  try {
    const serialized = `${JSON.stringify(result, null, 2)}\n`;
    if (Buffer.byteLength(serialized) > MAX_RESULT_BYTES) throw new Error("result exceeds its size limit");
    await writeFile(config.resultPath, serialized, { flag: "wx", mode: 0o600 });
  } catch (error) {
    result = { ...result, ok: false, resultWriteError: message(error) };
  }
}
output(result);
