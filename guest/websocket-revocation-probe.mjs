import { createHash, randomBytes } from "node:crypto";
import { lstat, readFile, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import tls from "node:tls";
import { domainToASCII } from "node:url";

const TEST_ID = "SBX-035-POC";
const CASE_ID = "websocket-live-policy-revocation";
const SCOPE = "I_CONTROL_THE_WSS_ORIGIN_AND_AUTHORIZE_ONE_SYNTHETIC_SECRET_SEND";
const SECRET_PATH = "/tmp/sbx-035/operator-secret";
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_CONFIG_BYTES = 16 * 1024;
const MAX_HEADERS = 32 * 1024;
const MAX_SERVER_FRAME = 2 * 1024;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const canaryPattern = /^corr_[A-Za-z0-9_-]{24}$/u;
const preOperationPattern = /^pre_[A-Za-z0-9_-]{43}$/u;
const secretPattern = /^opsec_[A-Za-z0-9_-]{43}$/u;
const secretOperationPattern = /^ws_[A-Za-z0-9_-]{43}$/u;
const allowedKeys = new Set([
  "caseId",
  "connectTimeoutMs",
  "endpointHost",
  "healthPath",
  "ioTimeoutMs",
  "mode",
  "operatorSecretPath",
  "pinnedIPv4",
  "pinnedPort",
  "publicCanary",
  "readinessPath",
  "scopeConfirmation",
  "testId",
  "triggerPath",
  "triggerTimeoutMs",
  "websocketPath",
  "expectedPreOperationId",
  "runId",
]);

function output(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function errorWithCode(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function requiredString(value, name, maximum = 1024) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[\0\r\n]/u.test(value)) {
    throw new Error(`${name} must be a bounded single-line string`);
  }
  return value;
}

function boundedInteger(value, name, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function publicIPv4(value) {
  if (isIP(value) !== 4 || value.split(".").some((part) => !/^(?:0|[1-9][0-9]{0,2})$/u.test(part))) return false;
  const [a = -1, b = -1] = value.split(".").map(Number);
  return a > 0 && a < 224 && a !== 10 && a !== 127 && !(a === 172 && b >= 16 && b <= 31) &&
    !(a === 192 && b === 168) && !(a === 169 && b === 254) && !(a === 100 && b >= 64 && b <= 127) &&
    !(a === 192 && b === 0) && !(a === 198 && (b === 18 || b === 19));
}

function controlledHostname(value) {
  const ascii = domainToASCII(requiredString(value, "endpointHost", 253).toLowerCase());
  if (!ascii || isIP(ascii) || ascii.endsWith(".") || ascii.length > 253 ||
    ascii.split(".").some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))) {
    throw new Error("endpointHost must be a canonical DNS hostname");
  }
  return ascii;
}

function coordinationPath(value, expected, name) {
  const path = requiredString(value, name, 4096);
  if (path !== expected) throw new Error(`${name} must equal ${expected}`);
  return path;
}

export function parseConfiguration(encoded) {
  const input = requiredString(encoded, "configuration", MAX_CONFIG_BYTES * 2);
  const bytes = Buffer.from(input, "base64url");
  if (bytes.length === 0 || bytes.length > MAX_CONFIG_BYTES || bytes.toString("base64url") !== input.replace(/=+$/u, "")) {
    throw new Error("configuration must be canonical bounded base64url");
  }
  const parsed = JSON.parse(bytes.toString("utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("configuration must be an object");
  for (const key of Object.keys(parsed)) if (!allowedKeys.has(key)) throw new Error(`unknown configuration field ${key}`);
  if (parsed.scopeConfirmation !== SCOPE) throw new Error(`scopeConfirmation must equal ${SCOPE}`);
  if (parsed.testId !== TEST_ID || parsed.caseId !== CASE_ID) throw new Error("testId/caseId do not match SBX-035");
  const runId = requiredString(parsed.runId, "runId", 36);
  if (!uuidPattern.test(runId)) throw new Error("runId must be a canonical random UUID");
  const mode = requiredString(parsed.mode, "mode", 16);
  if (!["retained", "fresh-https", "fresh-wss"].includes(mode)) throw new Error("mode is not supported");
  const endpointHost = controlledHostname(parsed.endpointHost);
  const pinnedIPv4 = requiredString(parsed.pinnedIPv4, "pinnedIPv4", 15);
  if (!publicIPv4(pinnedIPv4)) throw new Error("pinnedIPv4 must be a canonical public IPv4 address");
  const publicCanary = requiredString(parsed.publicCanary, "publicCanary", 29);
  if (!canaryPattern.test(publicCanary)) throw new Error("publicCanary has the wrong format");
  const expectedPreOperationId = requiredString(parsed.expectedPreOperationId, "expectedPreOperationId", 47);
  if (!preOperationPattern.test(expectedPreOperationId)) throw new Error("expectedPreOperationId has the wrong format");
  const readinessPath = coordinationPath(parsed.readinessPath, `/tmp/sbx-035/${runId}-ready.json`, "readinessPath");
  const triggerPath = coordinationPath(parsed.triggerPath, `/tmp/sbx-035/${runId}-trigger`, "triggerPath");
  const operatorSecretPath = coordinationPath(parsed.operatorSecretPath, SECRET_PATH, "operatorSecretPath");
  if (parsed.websocketPath !== "/v1/sbx035/ws" || parsed.healthPath !== "/healthz") {
    throw new Error("websocketPath and healthPath must use the fixed owned observer routes");
  }
  return {
    runId,
    mode,
    endpointHost,
    pinnedIPv4,
    pinnedPort: boundedInteger(parsed.pinnedPort, "pinnedPort", 443, 443),
    publicCanary,
    expectedPreOperationId,
    readinessPath,
    triggerPath,
    operatorSecretPath,
    websocketPath: parsed.websocketPath,
    healthPath: parsed.healthPath,
    connectTimeoutMs: boundedInteger(parsed.connectTimeoutMs, "connectTimeoutMs", 250, 4_000),
    ioTimeoutMs: boundedInteger(parsed.ioTimeoutMs, "ioTimeoutMs", 250, 10_000),
    triggerTimeoutMs: boundedInteger(parsed.triggerTimeoutMs, "triggerTimeoutMs", 5_000, 120_000),
  };
}

export function encodeClientTextFrame(message, mask = randomBytes(4)) {
  const payload = Buffer.from(message, "utf8");
  if (payload.length === 0 || payload.length > 125) throw new Error("client text frame must contain 1 through 125 bytes");
  if (!Buffer.isBuffer(mask) || mask.length !== 4) throw new Error("WebSocket mask must contain four bytes");
  const frame = Buffer.alloc(2 + 4 + payload.length);
  frame[0] = 0x81;
  frame[1] = 0x80 | payload.length;
  mask.copy(frame, 2);
  for (let index = 0; index < payload.length; index += 1) frame[6 + index] = payload[index] ^ mask[index % 4];
  return frame;
}

export function parseServerFrame(buffer) {
  if (!Buffer.isBuffer(buffer)) throw new Error("server frame input must be a Buffer");
  if (buffer.length < 2) return undefined;
  const first = buffer[0];
  const second = buffer[1];
  if ((first & 0x70) !== 0 || (first & 0x80) === 0) throw new Error("fragmented or extended WebSocket frames are not accepted");
  if ((second & 0x80) !== 0) throw new Error("server WebSocket frame must not be masked");
  let length = second & 0x7f;
  let offset = 2;
  if (length === 126) {
    if (buffer.length < 4) return undefined;
    length = buffer.readUInt16BE(2);
    offset = 4;
  } else if (length === 127) {
    throw new Error("64-bit WebSocket frames are not accepted");
  }
  if (length > MAX_SERVER_FRAME) throw new Error("server WebSocket frame exceeded its bound");
  if (buffer.length < offset + length) return undefined;
  return {
    opcode: first & 0x0f,
    payload: buffer.subarray(offset, offset + length),
    rest: buffer.subarray(offset + length),
  };
}

class SocketReader {
  constructor(socket) {
    this.socket = socket;
    this.iterator = socket[Symbol.asyncIterator]();
    this.buffer = Buffer.alloc(0);
    this.responseStarted = false;
  }

  async pull(timeoutMs) {
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => {
        const error = errorWithCode("socket read timed out", "VSC_TIMEOUT");
        this.socket.destroy(error);
        reject(error);
      }, timeoutMs);
    });
    try {
      const next = await Promise.race([this.iterator.next(), timeout]);
      if (next.done) throw errorWithCode("socket closed before a complete response", "EOF");
      const chunk = Buffer.from(next.value);
      if (chunk.length > 0) this.responseStarted = true;
      this.buffer = Buffer.concat([this.buffer, chunk]);
    } finally {
      clearTimeout(timer);
    }
  }

  async through(delimiter, maximum, timeoutMs) {
    while (true) {
      const index = this.buffer.indexOf(delimiter);
      if (index !== -1) {
        const value = this.buffer.subarray(0, index);
        this.buffer = this.buffer.subarray(index + delimiter.length);
        return value;
      }
      if (this.buffer.length > maximum) throw new Error("response headers exceeded their bound");
      await this.pull(timeoutMs);
    }
  }

  async serverText(timeoutMs) {
    while (true) {
      const parsed = parseServerFrame(this.buffer);
      if (!parsed) {
        await this.pull(timeoutMs);
        continue;
      }
      this.buffer = parsed.rest;
      if (parsed.opcode === 0x8) throw errorWithCode("server closed the WebSocket", "WS_CLOSE");
      if (parsed.opcode === 0x9) {
        if (parsed.payload.length > 125) throw new Error("ping frame exceeded its bound");
        const pong = Buffer.concat([Buffer.from([0x8a, 0x80 | parsed.payload.length]), randomBytes(4)]);
        for (let index = 0; index < parsed.payload.length; index += 1) {
          pong[6 + index] = parsed.payload[index] ^ pong[2 + (index % 4)];
        }
        await writeSocket(this.socket, pong);
        continue;
      }
      if (parsed.opcode !== 0x1) throw new Error("expected one server text frame");
      return parsed.payload.toString("utf8");
    }
  }
}

function writeSocket(socket, value) {
  return new Promise((resolve, reject) => {
    socket.write(value, (error) => error ? reject(error) : resolve());
  });
}

function websocketTarget(config) {
  const query = new URLSearchParams({
    run: config.runId,
    case: CASE_ID,
    canary: config.publicCanary,
  });
  return `${config.websocketPath}?${query.toString()}`;
}

function websocketRequest(config, key) {
  return [
    `GET ${websocketTarget(config)} HTTP/1.1`,
    `Host: ${config.endpointHost}`,
    "Connection: Upgrade",
    "Upgrade: websocket",
    `Sec-WebSocket-Key: ${key}`,
    "Sec-WebSocket-Version: 13",
    "User-Agent: vsc-sbx035-probe/1",
    "",
    "",
  ].join("\r\n");
}

function healthRequest(config) {
  const query = new URLSearchParams({ run: config.runId, case: CASE_ID, phase: "fresh-https" });
  return [
    `GET ${config.healthPath}?${query.toString()} HTTP/1.1`,
    `Host: ${config.endpointHost}`,
    "Connection: close",
    "User-Agent: vsc-sbx035-probe/1",
    "",
    "",
  ].join("\r\n");
}

function parseHttpHeaders(block) {
  const lines = block.toString("latin1").split("\r\n");
  const status = /^HTTP\/1\.[01] ([1-5][0-9]{2})(?: |$)/u.exec(lines.shift() ?? "");
  if (!status) throw new Error("invalid HTTP response status line");
  const headers = new Map();
  for (const line of lines) {
    const separator = line.indexOf(":");
    if (separator <= 0) throw new Error("invalid HTTP response header");
    const name = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    const values = headers.get(name) ?? [];
    values.push(value);
    headers.set(name, values);
  }
  return { statusCode: Number(status[1]), headers };
}

async function connectTls(config) {
  let tcpConnected = false;
  let tlsEstablished = false;
  let timedOut = false;
  const socket = tls.connect({
    host: config.pinnedIPv4,
    port: config.pinnedPort,
    servername: config.endpointHost,
    rejectUnauthorized: true,
    minVersion: "TLSv1.2",
    ALPNProtocols: ["http/1.1"],
  });
  socket.once("connect", () => { tcpConnected = true; });
  socket.setTimeout(config.connectTimeoutMs, () => {
    timedOut = true;
    socket.destroy(errorWithCode("TLS connect timed out", "VSC_TIMEOUT"));
  });
  try {
    await new Promise((resolve, reject) => {
      socket.once("secureConnect", resolve);
      socket.once("error", reject);
    });
    tlsEstablished = true;
    socket.setTimeout(0);
    if (!socket.authorized || socket.authorizationError) throw new Error("TLS peer certificate was not authorized");
    if (socket.alpnProtocol !== "http/1.1") throw new Error("TLS did not negotiate HTTP/1.1");
    const remoteAddress = socket.remoteAddress?.replace(/^::ffff:/u, "");
    if (remoteAddress !== config.pinnedIPv4 || socket.remotePort !== config.pinnedPort) {
      throw new Error("TLS socket did not use the exact pinned destination");
    }
    socket.disableRenegotiation();
    return { socket, tcpConnected, tlsEstablished, timedOut };
  } catch (error) {
    socket.destroy();
    throw Object.assign(error instanceof Error ? error : new Error(String(error)), {
      probeState: { tcpConnected, tlsEstablished, timedOut },
    });
  }
}

async function upgrade(config) {
  const connection = await connectTls(config);
  const reader = new SocketReader(connection.socket);
  const key = randomBytes(16).toString("base64");
  await writeSocket(connection.socket, websocketRequest(config, key));
  const parsed = parseHttpHeaders(await reader.through(Buffer.from("\r\n\r\n"), MAX_HEADERS, config.ioTimeoutMs));
  const expectedAccept = createHash("sha1").update(`${key}${WS_GUID}`).digest("base64");
  const connectionTokens = (parsed.headers.get("connection") ?? []).join(",").toLowerCase().split(",").map((v) => v.trim());
  const upgradeHeader = parsed.headers.get("upgrade")?.[0]?.toLowerCase();
  const accepts = parsed.headers.get("sec-websocket-accept") ?? [];
  const verified = parsed.statusCode === 101 && upgradeHeader === "websocket" && connectionTokens.includes("upgrade") &&
    accepts.length === 1 && accepts[0] === expectedAccept && !parsed.headers.has("sec-websocket-extensions");
  if (!verified) {
    connection.socket.destroy();
    throw new Error("strict WebSocket 101 validation failed");
  }
  return { ...connection, reader, statusCode: parsed.statusCode, websocketAcceptVerified: true };
}

function parseAck(value, type, pattern) {
  const parsed = JSON.parse(value);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || Object.keys(parsed).sort().join(",") !== "operationId,type" ||
    parsed.type !== type || typeof parsed.operationId !== "string" || !pattern.test(parsed.operationId)) {
    throw new Error(`invalid ${type} receipt`);
  }
  return parsed.operationId;
}

async function waitForTrigger(path, timeoutMs) {
  const started = Date.now();
  while (Date.now() - started <= timeoutMs) {
    try {
      const stat = await lstat(path);
      if (!stat.isFile() || (stat.mode & 0o777) !== 0o600 || stat.size !== 3) throw new Error("trigger file must be a mode-0600 regular file");
      if ((await readFile(path, "utf8")) !== "go\n") throw new Error("trigger file content was invalid");
      return;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw errorWithCode("trigger wait timed out", "VSC_TRIGGER_TIMEOUT");
}

async function readOperatorSecret(path) {
  const stat = await lstat(path);
  if (!stat.isFile() || (stat.mode & 0o777) !== 0o600 || stat.size < 48 || stat.size > 64) {
    throw new Error("operator secret must be a bounded mode-0600 regular file");
  }
  const value = await readFile(path, "utf8");
  if (!secretPattern.test(value)) throw new Error("operator secret has the wrong format");
  return value;
}

function errorCode(error) {
  const code = typeof error?.code === "string" ? error.code : undefined;
  if (code && /^[A-Z][A-Z0-9_]{1,31}$/u.test(code)) return code;
  return "PROBE_ERROR";
}

function retainedBase(config) {
  return {
    schemaVersion: 1,
    mode: "retained",
    runId: config.runId,
    testId: TEST_ID,
    caseId: CASE_ID,
    endpointHost: config.endpointHost,
    pinnedIPv4: config.pinnedIPv4,
    pinnedPort: config.pinnedPort,
    strictCertificateVerification: true,
    operatorSecretFileValidated: false,
    operatorSecretFileMode: 0,
    secretFramesSent: 0,
    rawSecretRetained: false,
    rawConfigurationRetained: false,
    rawFramesRetained: false,
  };
}

async function runRetained(config) {
  const result = retainedBase(config);
  let connection;
  let secret;
  try {
    connection = await upgrade(config);
    Object.assign(result, {
      tcpConnected: connection.tcpConnected,
      tlsEstablished: connection.tlsEstablished,
      websocketStatusCode: connection.statusCode,
      websocketAcceptVerified: connection.websocketAcceptVerified,
    });
    await writeSocket(connection.socket, encodeClientTextFrame(config.publicCanary));
    const preOperationId = parseAck(await connection.reader.serverText(config.ioTimeoutMs), "pre-ack", preOperationPattern);
    if (preOperationId !== config.expectedPreOperationId) throw new Error("pre receipt did not match controller HMAC proof");
    result.preOperationId = preOperationId;
    await writeFile(config.readinessPath, `${JSON.stringify({
      schemaVersion: 1,
      ready: true,
      runId: config.runId,
      testId: TEST_ID,
      caseId: CASE_ID,
      endpointHost: config.endpointHost,
      pinnedIPv4: config.pinnedIPv4,
      pinnedPort: config.pinnedPort,
      tcpConnected: true,
      tlsEstablished: true,
      strictCertificateVerification: true,
      websocketStatusCode: 101,
      websocketAcceptVerified: true,
      preOperationId,
      rawConfigurationRetained: false,
      rawFramesRetained: false,
    })}\n`, { flag: "wx", mode: 0o600 });
    await waitForTrigger(config.triggerPath, config.triggerTimeoutMs);
    secret = await readOperatorSecret(config.operatorSecretPath);
    result.operatorSecretFileValidated = true;
    result.operatorSecretFileMode = 0o600;
    await writeSocket(connection.socket, encodeClientTextFrame(secret));
    result.secretFramesSent = 1;
    secret = undefined;
    result.responseOperationId = parseAck(
      await connection.reader.serverText(config.ioTimeoutMs),
      "secret-ack",
      secretOperationPattern,
    );
    result.ok = true;
  } catch (error) {
    result.ok = false;
    result.errorCode = errorCode(error);
    const state = error?.probeState;
    if (state && typeof state === "object") {
      result.tcpConnected = state.tcpConnected === true;
      result.tlsEstablished = state.tlsEstablished === true;
    }
  } finally {
    secret = undefined;
    connection?.socket.destroy();
  }
  return result;
}

async function runFresh(config) {
  const started = Date.now();
  const result = {
    schemaVersion: 1,
    ok: true,
    mode: config.mode,
    runId: config.runId,
    testId: TEST_ID,
    caseId: CASE_ID,
    endpointHost: config.endpointHost,
    pinnedIPv4: config.pinnedIPv4,
    pinnedPort: config.pinnedPort,
    attemptCount: 1,
    retryCount: 0,
    strictCertificateVerification: true,
    environmentProxyTrust: false,
    tcpConnected: false,
    tlsEstablished: false,
    responseStarted: false,
    receivedResponse: false,
    timedOut: false,
  };
  let socket;
  try {
    const connection = await connectTls(config);
    socket = connection.socket;
    result.tcpConnected = connection.tcpConnected;
    result.tlsEstablished = connection.tlsEstablished;
    const reader = new SocketReader(socket);
    if (config.mode === "fresh-wss") {
      const key = randomBytes(16).toString("base64");
      await writeSocket(socket, websocketRequest(config, key));
    } else {
      await writeSocket(socket, healthRequest(config));
    }
    const response = parseHttpHeaders(await reader.through(Buffer.from("\r\n\r\n"), MAX_HEADERS, config.ioTimeoutMs));
    result.responseStarted = reader.responseStarted;
    result.receivedResponse = true;
    result.statusCode = response.statusCode;
  } catch (error) {
    const state = error?.probeState;
    if (state && typeof state === "object") {
      result.tcpConnected = state.tcpConnected === true;
      result.tlsEstablished = state.tlsEstablished === true;
      result.timedOut = state.timedOut === true;
    }
    result.errorCode = errorCode(error);
    if (result.errorCode === "VSC_TIMEOUT") result.timedOut = true;
  } finally {
    socket?.destroy();
  }
  result.durationMs = Date.now() - started;
  return result;
}

export async function runProbe(config) {
  return config.mode === "retained" ? await runRetained(config) : await runFresh(config);
}

async function main() {
  try {
    const config = parseConfiguration(process.argv[2]);
    if (process.argv[3] === "--plan") {
      output({
        schemaVersion: 1,
        ok: true,
        phase: "plan",
        mode: config.mode,
        runId: config.runId,
        testId: TEST_ID,
        caseId: CASE_ID,
        endpointHost: config.endpointHost,
        pinnedIPv4: config.pinnedIPv4,
        pinnedPort: config.pinnedPort,
        attemptCount: 1,
        retryCount: 0,
        strictCertificateVerification: true,
        environmentProxyTrust: false,
        operatorSecretPath: config.operatorSecretPath,
        rawSecretRetained: false,
        rawConfigurationRetained: false,
        rawFramesRetained: false,
      });
      return;
    }
    if (process.argv.length !== 3) throw new Error("unsupported command-line arguments");
    output(await runProbe(config));
  } catch {
    output({ schemaVersion: 1, ok: false, phase: "configuration", errorCode: "INVALID_CONFIGURATION" });
    process.exitCode = 20;
  }
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) await main();
