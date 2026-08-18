import { createHash } from "node:crypto";
import { domainToASCII } from "node:url";
import { isIP } from "node:net";
import tls from "node:tls";

const SCOPE_CONFIRMATION = "I_CONTROL_ALL_LISTED_HOSTS";
const MAX_CONFIGURATION_BYTES = 64 * 1024;
const MAX_HEADER_BYTES = 32 * 1024;
const SENSITIVE_NAME = /(?:^|[-_])(?:api[-_]?key|auth(?:orization)?|cookie|credential|password|private[-_]?key|secret|token)(?:$|[-_])/i;
const ALLOWED_CONFIGURATION_KEYS = new Set([
  "caPem",
  "connectHost",
  "connectPort",
  "correlation",
  "firstHost",
  "firstPath",
  "maxResponseBytes",
  "researcherControlledHosts",
  "scopeConfirmation",
  "secondHost",
  "secondPath",
  "sniHost",
  "timeoutMs",
]);

function output(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function requiredString(value, name, maximumLength = 2048) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximumLength) {
    throw new Error(`${name} must be a non-empty string of at most ${maximumLength} characters`);
  }
  if (value.includes("\r") || value.includes("\n") || value.includes("\0")) {
    throw new Error(`${name} contains a forbidden control character`);
  }
  return value;
}

function normalizedHost(value, name) {
  const raw = requiredString(value, name, 253).toLowerCase();
  if (isIP(raw)) return raw;
  const ascii = domainToASCII(raw);
  if (!ascii || ascii.length > 253 || ascii.endsWith(".")) {
    throw new Error(`${name} must be an IP address or canonical DNS hostname`);
  }
  const labels = ascii.split(".");
  if (labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    throw new Error(`${name} must be an IP address or canonical DNS hostname`);
  }
  return ascii;
}

function requestPath(value, name) {
  const path = requiredString(value, name, 2048);
  if (!path.startsWith("/") || path.startsWith("//") || path.includes("#")) {
    throw new Error(`${name} must be an origin-form path without a fragment`);
  }
  return path;
}

function appendCorrelation(path, correlation) {
  const parameters = new URLSearchParams({
    __sbx_run: correlation.runId,
    __sbx_test: correlation.testId,
    __sbx_case: correlation.caseId,
    __sbx_canary: correlation.canary,
  });
  return `${path}${path.includes("?") ? "&" : "?"}${parameters.toString()}`;
}

function parseConfiguration(encoded) {
  if (typeof encoded !== "string" || encoded.length === 0) {
    throw new Error("missing base64url probe configuration");
  }
  const decodedBuffer = Buffer.from(encoded, "base64url");
  if (decodedBuffer.length > MAX_CONFIGURATION_BYTES) throw new Error("probe configuration is too large");
  const decoded = JSON.parse(decodedBuffer.toString("utf8"));
  if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) {
    throw new Error("probe configuration must be an object");
  }
  for (const key of Object.keys(decoded)) {
    if (SENSITIVE_NAME.test(key)) throw new Error(`sensitive configuration field ${key} is not allowed`);
    if (!ALLOWED_CONFIGURATION_KEYS.has(key)) throw new Error(`unknown configuration field ${key}`);
  }
  if (decoded.scopeConfirmation !== SCOPE_CONFIRMATION) {
    throw new Error(`scopeConfirmation must equal ${SCOPE_CONFIRMATION}`);
  }
  if (!Array.isArray(decoded.researcherControlledHosts) || decoded.researcherControlledHosts.length < 2) {
    throw new Error("researcherControlledHosts must explicitly list at least two hosts");
  }
  if (decoded.researcherControlledHosts.length > 16) {
    throw new Error("researcherControlledHosts may list at most 16 hosts");
  }
  const controlledHosts = new Set(
    decoded.researcherControlledHosts.map((host, index) =>
      normalizedHost(host, `researcherControlledHosts[${index}]`),
    ),
  );
  if (controlledHosts.size !== decoded.researcherControlledHosts.length) {
    throw new Error("researcherControlledHosts contains duplicates");
  }

  const connectHost = normalizedHost(decoded.connectHost, "connectHost");
  const sniHost = normalizedHost(decoded.sniHost, "sniHost");
  const firstHost = normalizedHost(decoded.firstHost, "firstHost");
  const secondHost = normalizedHost(decoded.secondHost, "secondHost");
  if (isIP(sniHost)) throw new Error("sniHost must be a DNS hostname");
  if (sniHost !== firstHost) throw new Error("sniHost and firstHost must identify origin A");
  if (firstHost === secondHost) throw new Error("firstHost and secondHost must be distinct");
  for (const host of [connectHost, sniHost, firstHost, secondHost]) {
    if (!controlledHosts.has(host)) throw new Error(`${host} is outside researcherControlledHosts`);
  }

  const connectPort = decoded.connectPort;
  if (!Number.isInteger(connectPort) || connectPort < 1 || connectPort > 65535) {
    throw new Error("connectPort must be an integer from 1 through 65535");
  }
  const timeoutMs = decoded.timeoutMs ?? 10_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) {
    throw new Error("timeoutMs must be an integer from 100 through 30000");
  }
  const maxResponseBytes = decoded.maxResponseBytes ?? 4096;
  if (!Number.isInteger(maxResponseBytes) || maxResponseBytes < 1 || maxResponseBytes > 65_536) {
    throw new Error("maxResponseBytes must be an integer from 1 through 65536");
  }
  const caPem = decoded.caPem;
  if (caPem !== undefined) {
    if (
      typeof caPem !== "string" ||
      caPem.length === 0 ||
      caPem.length > 32 * 1024 ||
      caPem.includes("\0") ||
      !caPem.includes("-----BEGIN CERTIFICATE-----") ||
      caPem.includes("PRIVATE KEY")
    ) {
      throw new Error("caPem must contain public certificates and must not contain a private key");
    }
  }
  const correlation = decoded.correlation;
  if (!correlation || typeof correlation !== "object" || Array.isArray(correlation)) {
    throw new Error("correlation must be an object");
  }
  const checkedCorrelation = {};
  for (const name of ["runId", "testId", "caseId", "canary"]) {
    const value = requiredString(correlation[name], `correlation.${name}`, 128);
    if (!/^[A-Za-z0-9._:-]+$/.test(value)) {
      throw new Error(`correlation.${name} contains unsupported characters`);
    }
    checkedCorrelation[name] = value;
  }

  return {
    connectHost,
    connectPort,
    sniHost,
    firstHost,
    secondHost,
    firstTarget: appendCorrelation(requestPath(decoded.firstPath, "firstPath"), checkedCorrelation),
    secondTarget: appendCorrelation(requestPath(decoded.secondPath, "secondPath"), checkedCorrelation),
    caPem,
    timeoutMs,
    maxResponseBytes,
  };
}

class BufferedSocketReader {
  constructor(socket) {
    this.iterator = socket[Symbol.asyncIterator]();
    this.buffer = Buffer.alloc(0);
  }

  async pull() {
    const result = await this.iterator.next();
    if (result.done) throw new Error("TLS socket closed before the HTTP response completed");
    this.buffer = Buffer.concat([this.buffer, Buffer.from(result.value)]);
  }

  async through(delimiter, maximumBytes) {
    while (true) {
      const index = this.buffer.indexOf(delimiter);
      if (index !== -1) {
        const end = index + delimiter.length;
        const value = this.buffer.subarray(0, index);
        this.buffer = this.buffer.subarray(end);
        return value;
      }
      if (this.buffer.length > maximumBytes) throw new Error("HTTP response framing exceeded its limit");
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

function parseHeaderBlock(block) {
  const lines = block.toString("latin1").split("\r\n");
  const statusLine = lines.shift() ?? "";
  const statusMatch = /^HTTP\/1\.[01] ([1-5][0-9]{2})(?: |$)/.exec(statusLine);
  if (!statusMatch) throw new Error("invalid HTTP/1.1 response status line");
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
  return { statusCode: Number(statusMatch[1]), headers };
}

function safeResponseHeaders(headers) {
  const result = {};
  for (const [name, values] of headers) {
    if (SENSITIVE_NAME.test(name) || name === "set-cookie") continue;
    result[name] = values.length === 1 ? values[0] : values;
  }
  return result;
}

async function readChunkedBody(reader, maximumBytes) {
  const chunks = [];
  let length = 0;
  while (true) {
    const sizeLine = (await reader.through(Buffer.from("\r\n"), 1024)).toString("ascii");
    const sizeToken = sizeLine.split(";", 1)[0];
    if (!sizeToken || !/^[0-9a-fA-F]+$/.test(sizeToken)) throw new Error("invalid chunk size");
    const size = Number.parseInt(sizeToken, 16);
    if (!Number.isSafeInteger(size)) throw new Error("invalid chunk size");
    if (size === 0) {
      while ((await reader.through(Buffer.from("\r\n"), MAX_HEADER_BYTES)).length !== 0) {
        // Consume bounded trailers.
      }
      break;
    }
    if (length + size > maximumBytes) throw new Error("HTTP response body exceeds maxResponseBytes");
    chunks.push(await reader.exact(size));
    length += size;
    const terminator = await reader.exact(2);
    if (!terminator.equals(Buffer.from("\r\n"))) throw new Error("invalid chunk terminator");
  }
  return Buffer.concat(chunks);
}

async function readResponse(reader, maximumBytes) {
  while (true) {
    const headerBlock = await reader.through(Buffer.from("\r\n\r\n"), MAX_HEADER_BYTES);
    const { statusCode, headers } = parseHeaderBlock(headerBlock);
    if (statusCode >= 100 && statusCode < 200) continue;
    let body = Buffer.alloc(0);
    if (statusCode !== 204 && statusCode !== 304) {
      const transferEncoding = (headers.get("transfer-encoding") ?? []).join(",").toLowerCase();
      const contentLengths = headers.get("content-length") ?? [];
      if (transferEncoding && contentLengths.length > 0) {
        throw new Error("ambiguous HTTP response framing");
      }
      if (transferEncoding) {
        if (!transferEncoding.split(",").map((value) => value.trim()).includes("chunked")) {
          throw new Error("unsupported HTTP transfer encoding");
        }
        body = await readChunkedBody(reader, maximumBytes);
      } else if (contentLengths.length > 0) {
        if (new Set(contentLengths).size !== 1 || !/^[0-9]+$/.test(contentLengths[0])) {
          throw new Error("invalid Content-Length response framing");
        }
        const length = Number(contentLengths[0]);
        if (!Number.isSafeInteger(length) || length > maximumBytes) {
          throw new Error("HTTP response body exceeds maxResponseBytes");
        }
        body = await reader.exact(length);
      } else {
        throw new Error("keep-alive response lacks explicit body framing");
      }
    }
    return {
      statusCode,
      headers: safeResponseHeaders(headers),
      bodyLength: body.length,
      body: body.toString("utf8"),
      bodySha256: createHash("sha256").update(body).digest("hex"),
    };
  }
}

async function writeRequest(socket, host, target, close) {
  const request = [
    `GET ${target} HTTP/1.1`,
    `Host: ${host}`,
    "User-Agent: vsc-h1-authority-reuse-probe/1",
    "Accept: application/json, text/plain;q=0.9, */*;q=0.1",
    `Connection: ${close ? "close" : "keep-alive"}`,
    "",
    "",
  ].join("\r\n");
  if (!socket.write(request, "latin1")) {
    await new Promise((resolve, reject) => {
      socket.once("drain", resolve);
      socket.once("error", reject);
    });
  }
}

async function connectVerified(config) {
  let handshakeCount = 0;
  const socket = tls.connect({
    host: config.connectHost,
    port: config.connectPort,
    servername: config.sniHost,
    ...(config.caPem ? { ca: config.caPem } : {}),
    rejectUnauthorized: true,
    minVersion: "TLSv1.2",
  });
  socket.setTimeout(config.timeoutMs, () => socket.destroy(new Error("TLS socket timed out")));
  socket.on("secureConnect", () => {
    handshakeCount += 1;
  });
  await new Promise((resolve, reject) => {
    socket.once("secureConnect", resolve);
    socket.once("error", reject);
  });
  if (!socket.authorized || socket.authorizationError) {
    socket.destroy();
    throw new Error(`TLS peer verification failed: ${socket.authorizationError ?? "unauthorized"}`);
  }
  socket.disableRenegotiation();
  const peer = socket.getPeerCertificate();
  const tuple = [
    socket.localAddress,
    socket.localPort,
    socket.remoteAddress,
    socket.remotePort,
    peer.fingerprint256,
  ].join("|");
  return {
    socket,
    handshakeCount: () => handshakeCount,
    identity: {
      id: createHash("sha256").update(tuple).digest("hex"),
      localAddress: socket.localAddress,
      localPort: socket.localPort,
      remoteAddress: socket.remoteAddress,
      remotePort: socket.remotePort,
      peerFingerprint256: peer.fingerprint256,
    },
    protocol: socket.getProtocol(),
    cipher: socket.getCipher().standardName ?? socket.getCipher().name,
  };
}

async function run(config) {
  const connection = await connectVerified(config);
  const reader = new BufferedSocketReader(connection.socket);
  try {
    await writeRequest(connection.socket, config.firstHost, config.firstTarget, false);
    const firstResponse = await readResponse(reader, config.maxResponseBytes);
    await writeRequest(connection.socket, config.secondHost, config.secondTarget, true);
    const secondResponse = await readResponse(reader, config.maxResponseBytes);
    if (connection.handshakeCount() !== 1) throw new Error("unexpected TLS handshake count");
    return {
      ok: true,
      tls: {
        authorized: true,
        sniHost: config.sniHost,
        handshakeCount: 1,
        protocol: connection.protocol,
        cipher: connection.cipher,
        socket: connection.identity,
      },
      requests: [
        { index: 0, host: config.firstHost, rawTarget: config.firstTarget, response: firstResponse },
        { index: 1, host: config.secondHost, rawTarget: config.secondTarget, response: secondResponse },
      ],
    };
  } finally {
    connection.socket.destroy();
  }
}

try {
  output(await run(parseConfiguration(process.argv[2])));
} catch (error) {
  output({ ok: false, error: error instanceof Error ? error.message : String(error) });
}
