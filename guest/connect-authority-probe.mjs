import { readFile, stat } from "node:fs/promises";
import { isIP } from "node:net";
import tls from "node:tls";
import { domainToASCII } from "node:url";

const TEST_ID = "SBX-038-POC";
const SCOPE_CONFIRMATION = "I_CONTROL_BOTH_SBX038_ORIGINS_AND_AUTHORIZE_BOUNDED_CONNECT_AUTHORITY_TESTING";
const MAX_CONFIGURATION_BYTES = 64 * 1024;
const MAX_HEADER_BYTES = 32 * 1024;
const MAX_RESPONSE_BYTES = 16 * 1024;
const SENSITIVE_NAME = /(?:^|[-_])(?:api[-_]?key|auth(?:orization)?|cookie|credential|password|private[-_]?key|secret|token)(?:$|[-_])/iu;
const MODES = new Set(["normal-a", "direct-b", "connect-a", "connect-b-public", "connect-b-secret"]);
const TRUST_ENVIRONMENT_NAMES = [
  "NODE_EXTRA_CA_CERTS",
  "NODE_USE_SYSTEM_CA",
  "OPENSSL_CONF",
  "OPENSSL_MODULES",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
];
const FORBIDDEN_TRUST_ENVIRONMENT_NAMES = ["NODE_OPTIONS", "NODE_TLS_REJECT_UNAUTHORIZED"];
const CONFIGURATION_KEYS = new Set([
  "caseId",
  "correlationCanary",
  "maxResponseBytes",
  "mode",
  "nestedPath",
  "outerHost",
  "outerPath",
  "outerPort",
  "researcherControlledHosts",
  "runId",
  "scopeConfirmation",
  "secretFilePath",
  "targetHost",
  "targetPort",
  "timeoutMs",
]);

function output(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function requiredString(value, name, maximum = 2_048) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[\0\r\n]/u.test(value)) {
    throw new Error(`${name} must be a non-empty bounded string without control characters`);
  }
  return value;
}

function canonicalHost(value, name) {
  const raw = requiredString(value, name, 253).toLowerCase();
  if (isIP(raw) !== 0) throw new Error(`${name} must be a DNS hostname, not an IP literal`);
  const ascii = domainToASCII(raw);
  if (!ascii || ascii !== raw || ascii.endsWith(".") || ascii.length > 253) {
    throw new Error(`${name} must be a canonical lower-case ASCII hostname`);
  }
  if (ascii.split(".").some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))) {
    throw new Error(`${name} is not a canonical hostname`);
  }
  return ascii;
}

function port(value, name) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 65_535) throw new Error(`${name} is invalid`);
  return value;
}

function boundedInteger(value, name, minimum, maximum, fallback) {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < minimum || selected > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} through ${maximum}`);
  }
  return selected;
}

function originPath(value, name) {
  const path = requiredString(value, name, 4_096);
  if (!path.startsWith("/") || path.startsWith("//") || path.includes("#")) {
    throw new Error(`${name} must be an origin-form path`);
  }
  return path;
}

function exactCorrelation(value, name) {
  const text = requiredString(value, name, 128);
  if (!/^[A-Za-z0-9._:-]+$/u.test(text)) throw new Error(`${name} contains unsupported characters`);
  return text;
}

function parseConfiguration(encoded) {
  if (typeof encoded !== "string" || encoded.length === 0) throw new Error("missing base64url probe configuration");
  const decodedBytes = Buffer.from(encoded, "base64url");
  if (decodedBytes.length > MAX_CONFIGURATION_BYTES) throw new Error("probe configuration is too large");
  const decoded = JSON.parse(decodedBytes.toString("utf8"));
  if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) throw new Error("probe configuration must be an object");
  for (const key of Object.keys(decoded)) {
    if (SENSITIVE_NAME.test(key) && key !== "secretFilePath") {
      throw new Error(`sensitive configuration field ${key} is not allowed`);
    }
    if (!CONFIGURATION_KEYS.has(key)) throw new Error(`unknown configuration field ${key}`);
  }
  if (decoded.scopeConfirmation !== SCOPE_CONFIRMATION) {
    throw new Error(`scopeConfirmation must equal ${SCOPE_CONFIRMATION}`);
  }
  if (!MODES.has(decoded.mode)) throw new Error("mode is invalid");
  if (!Array.isArray(decoded.researcherControlledHosts) || decoded.researcherControlledHosts.length !== 2) {
    throw new Error("researcherControlledHosts must contain exactly A and B");
  }
  const controlled = decoded.researcherControlledHosts.map((value, index) =>
    canonicalHost(value, `researcherControlledHosts[${index}]`));
  if (new Set(controlled).size !== 2) throw new Error("A and B must be distinct hosts");

  const outerHost = canonicalHost(decoded.outerHost, "outerHost");
  if (!controlled.includes(outerHost)) throw new Error("outerHost is not researcher-controlled");
  const targetHost = decoded.targetHost === undefined ? undefined : canonicalHost(decoded.targetHost, "targetHost");
  if (targetHost !== undefined && !controlled.includes(targetHost)) throw new Error("targetHost is not researcher-controlled");
  const isConnect = decoded.mode.startsWith("connect-");
  if (isConnect !== (targetHost !== undefined)) throw new Error("targetHost is required only for CONNECT modes");
  const [a, b] = controlled;
  if (decoded.mode === "normal-a" && outerHost !== a) throw new Error("normal-a must connect to A");
  if (decoded.mode === "direct-b" && outerHost !== b) throw new Error("direct-b must connect to B");
  if (isConnect && outerHost !== a) throw new Error("CONNECT outer TLS must terminate at A");
  if (decoded.mode === "connect-a" && targetHost !== a) throw new Error("connect-a must target A");
  if ((decoded.mode === "connect-b-public" || decoded.mode === "connect-b-secret") && targetHost !== b) {
    throw new Error("CONNECT B modes must target B");
  }

  const secretFilePath = decoded.secretFilePath === undefined
    ? undefined
    : requiredString(decoded.secretFilePath, "secretFilePath", 512);
  if (decoded.mode === "connect-b-secret") {
    if (!secretFilePath?.startsWith("/tmp/sbx-038/") || secretFilePath.includes("..")) {
      throw new Error("connect-b-secret requires an exact SBX-038 temporary secret path");
    }
  } else if (secretFilePath !== undefined) {
    throw new Error("secretFilePath is allowed only for connect-b-secret");
  }

  const outerPath = decoded.outerPath === undefined ? undefined : originPath(decoded.outerPath, "outerPath");
  const nestedPath = decoded.nestedPath === undefined ? undefined : originPath(decoded.nestedPath, "nestedPath");
  if ((decoded.mode === "normal-a" || decoded.mode === "direct-b") !== (outerPath !== undefined)) {
    throw new Error("outerPath is required only for non-CONNECT modes");
  }
  if (isConnect !== (nestedPath !== undefined)) throw new Error("nestedPath is required only for CONNECT modes");

  return {
    mode: decoded.mode,
    runId: exactCorrelation(decoded.runId, "runId"),
    caseId: exactCorrelation(decoded.caseId, "caseId"),
    correlationCanary: exactCorrelation(decoded.correlationCanary, "correlationCanary"),
    outerHost,
    outerPort: port(decoded.outerPort, "outerPort"),
    targetHost,
    targetPort: targetHost === undefined ? undefined : port(decoded.targetPort, "targetPort"),
    outerPath,
    nestedPath,
    secretFilePath,
    timeoutMs: boundedInteger(decoded.timeoutMs, "timeoutMs", 250, 15_000, 4_000),
    maxResponseBytes: boundedInteger(decoded.maxResponseBytes, "maxResponseBytes", 1, MAX_RESPONSE_BYTES, 8_192),
  };
}

class SocketReader {
  constructor(socket) {
    this.iterator = socket[Symbol.asyncIterator]();
    this.buffer = Buffer.alloc(0);
  }

  async pull() {
    const result = await this.iterator.next();
    if (result.done) throw new Error("socket closed before response completed");
    this.buffer = Buffer.concat([this.buffer, Buffer.from(result.value)]);
  }

  async through(delimiter, maximum) {
    while (true) {
      const index = this.buffer.indexOf(delimiter);
      if (index >= 0) {
        const value = this.buffer.subarray(0, index);
        this.buffer = this.buffer.subarray(index + delimiter.length);
        return value;
      }
      if (this.buffer.length > maximum) throw new Error("response headers exceeded their bound");
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

function parseHeaders(block) {
  const lines = block.toString("latin1").split("\r\n");
  const statusLine = lines.shift() ?? "";
  const match = /^HTTP\/1\.[01] ([1-5][0-9]{2})(?: |$)/u.exec(statusLine);
  if (!match) throw new Error("invalid HTTP response status line");
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
  return { statusCode: Number(match[1]), headers };
}

async function response(reader, maximumBodyBytes, tunnelResponse = false) {
  let parsed;
  do {
    parsed = parseHeaders(await reader.through(Buffer.from("\r\n\r\n"), MAX_HEADER_BYTES));
  } while (parsed.statusCode >= 100 && parsed.statusCode < 200);
  if (tunnelResponse && parsed.statusCode >= 200 && parsed.statusCode < 300) {
    if (reader.buffer.length !== 0) throw new Error("CONNECT response contained bytes before nested TLS began");
    return { ...parsed, body: Buffer.alloc(0) };
  }
  const lengths = parsed.headers.get("content-length") ?? [];
  const transfer = parsed.headers.get("transfer-encoding") ?? [];
  if (transfer.length !== 0) throw new Error("chunked/transfer-coded responses are not accepted");
  if (lengths.length !== 1 || new Set(lengths).size !== 1 || !/^[0-9]+$/u.test(lengths[0])) {
    throw new Error("response must contain one canonical Content-Length");
  }
  const length = Number(lengths[0]);
  if (!Number.isSafeInteger(length) || length > maximumBodyBytes) throw new Error("response body exceeded its bound");
  return { ...parsed, body: await reader.exact(length) };
}

function tlsIdentity(socket, servername) {
  return {
    servername,
    authorized: socket.authorized === true,
    authorizationError: socket.authorizationError || undefined,
    protocol: socket.getProtocol() ?? undefined,
    remoteAddress: socket.remoteAddress,
    remotePort: socket.remotePort,
  };
}

function connectTls({ host, port: destinationPort, servername, timeoutMs, socket }) {
  return new Promise((resolve, reject) => {
    const connection = tls.connect({
      ...(socket ? { socket } : { host, port: destinationPort }),
      servername,
      rejectUnauthorized: true,
      ALPNProtocols: ["http/1.1"],
    });
    const timer = setTimeout(() => connection.destroy(new Error("TLS connection timed out")), timeoutMs);
    connection.once("secureConnect", () => {
      clearTimeout(timer);
      if (!connection.authorized || connection.alpnProtocol !== "http/1.1") {
        connection.destroy();
        reject(new Error("strict HTTP/1.1 TLS verification failed"));
        return;
      }
      resolve(connection);
    });
    connection.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

function requestBytes(method, path, host, runId, caseId, canary, body = Buffer.alloc(0)) {
  const headers = [
    `${method} ${path} HTTP/1.1`,
    `Host: ${host}`,
    "User-Agent: sbx-038-deterministic-probe/1",
    "Accept: application/json",
    `X-SBX038-Case: ${caseId}`,
    `X-SBX038-Canary: ${canary}`,
    `X-SBX038-Run: ${runId}`,
    `Content-Length: ${body.length}`,
    "Connection: close",
    "",
    "",
  ];
  return Buffer.concat([Buffer.from(headers.join("\r\n"), "latin1"), body]);
}

function connectBytes(targetHost, targetPort, outerHost, runId, caseId, canary) {
  return Buffer.from([
    `CONNECT ${targetHost}:${targetPort} HTTP/1.1`,
    `Host: ${outerHost}`,
    "User-Agent: sbx-038-deterministic-probe/1",
    `X-SBX038-Case: ${caseId}`,
    `X-SBX038-Canary: ${canary}`,
    `X-SBX038-Run: ${runId}`,
    "Proxy-Connection: keep-alive",
    "Connection: keep-alive",
    "",
    "",
  ].join("\r\n"), "latin1");
}

async function writeAll(socket, bytes) {
  await new Promise((resolve, reject) => {
    socket.write(bytes, (error) => error ? reject(error) : resolve());
  });
}

function safeOperation(body) {
  if (body.length === 0) return undefined;
  const parsed = JSON.parse(body.toString("utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("response JSON is invalid");
  return typeof parsed.operationId === "string" && /^cx_[A-Za-z0-9_-]{24,64}$/u.test(parsed.operationId)
    ? parsed.operationId
    : undefined;
}

async function validatedSecret(path) {
  const metadata = await stat(path, { bigint: false });
  if (!metadata.isFile() || (metadata.mode & 0o777) !== 0o600 || metadata.size < 16 || metadata.size > 4_096) {
    throw new Error("operator secret must be a regular mode-0600 file of 16 through 4096 bytes");
  }
  const value = await readFile(path);
  if (value.length !== metadata.size) throw new Error("operator secret changed while being read");
  return value;
}

async function run(config) {
  const started = Date.now();
  const startedAt = new Date().toISOString();
  let outer;
  let nested;
  let secret;
  const evidence = {
    schemaVersion: 1,
    testId: TEST_ID,
    runId: config.runId,
    caseId: config.caseId,
    mode: config.mode,
    outerHost: config.outerHost,
    outerPort: config.outerPort,
    targetHost: config.targetHost,
    targetPort: config.targetPort,
    connectAuthority: config.targetHost ? `${config.targetHost}:${config.targetPort}` : undefined,
    connectHostHeader: config.targetHost ? config.outerHost : undefined,
    connectionAttempts: 1,
    retryCount: 0,
    maximumRequests: config.targetHost ? 2 : 1,
    actualRequests: 0,
    strictCertificateVerification: true,
    environmentProxyTrust: false,
    trustEnvironmentNames: TRUST_ENVIRONMENT_NAMES.filter((name) => Object.hasOwn(process.env, name)).sort(),
    trustEnvironmentScanComplete: true,
    trustOverridesForbidden: FORBIDDEN_TRUST_ENVIRONMENT_NAMES.every((name) => !Object.hasOwn(process.env, name)),
    rawConfigurationRetained: false,
    rawSecretRetained: false,
    secretDigestRetained: false,
    startedAt,
    completedAt: startedAt,
  };
  try {
    outer = await connectTls({
      host: config.outerHost,
      port: config.outerPort,
      servername: config.outerHost,
      timeoutMs: config.timeoutMs,
    });
    evidence.outerTls = tlsIdentity(outer, config.outerHost);
    outer.setTimeout(config.timeoutMs, () => outer.destroy(new Error("outer I/O timed out")));

    if (!config.targetHost) {
      await writeAll(outer, requestBytes(
        "GET", config.outerPath, config.outerHost, config.runId, config.caseId, config.correlationCanary,
      ));
      evidence.actualRequests += 1;
      const parsed = await response(new SocketReader(outer), config.maxResponseBytes);
      evidence.outerResponse = {
        statusCode: parsed.statusCode,
        operationId: safeOperation(parsed.body),
        bodyBytes: parsed.body.length,
        terminalConnectHeader: (parsed.headers.get("x-sbx038-terminal") ?? []).length === 1,
      };
      evidence.ok = parsed.statusCode >= 200 && parsed.statusCode < 300;
      return evidence;
    }

    await writeAll(outer, connectBytes(
      config.targetHost,
      config.targetPort,
      config.outerHost,
      config.runId,
      config.caseId,
      config.correlationCanary,
    ));
    evidence.actualRequests += 1;
    const connectResponse = await response(new SocketReader(outer), config.maxResponseBytes, true);
    evidence.connectResponse = {
      statusCode: connectResponse.statusCode,
      terminalConnectHeader: (connectResponse.headers.get("x-sbx038-terminal") ?? []).length === 1,
      bodyBytes: connectResponse.body.length,
    };
    if (connectResponse.statusCode < 200 || connectResponse.statusCode >= 300) {
      evidence.ok = false;
      evidence.tunnelEstablished = false;
      return evidence;
    }

    evidence.tunnelEstablished = true;
    nested = await connectTls({
      host: config.targetHost,
      port: config.targetPort,
      servername: config.targetHost,
      timeoutMs: config.timeoutMs,
      socket: outer,
    });
    evidence.nestedTls = tlsIdentity(nested, config.targetHost);
    nested.setTimeout(config.timeoutMs, () => nested.destroy(new Error("nested I/O timed out")));
    if (config.mode === "connect-b-secret") {
      secret = await validatedSecret(config.secretFilePath);
      evidence.secretFileValidated = true;
      evidence.secretFileMode = 0o600;
      evidence.secretBytes = secret.length;
    }
    const method = secret ? "POST" : "GET";
    await writeAll(nested, requestBytes(
      method,
      config.nestedPath,
      config.targetHost,
      config.runId,
      config.caseId,
      config.correlationCanary,
      secret ?? Buffer.alloc(0),
    ));
    evidence.actualRequests += 1;
    const nestedResponse = await response(new SocketReader(nested), config.maxResponseBytes);
    evidence.nestedResponse = {
      statusCode: nestedResponse.statusCode,
      operationId: safeOperation(nestedResponse.body),
      bodyBytes: nestedResponse.body.length,
    };
    evidence.ok = nestedResponse.statusCode >= 200 && nestedResponse.statusCode < 300;
    return evidence;
  } catch (error) {
    evidence.ok = false;
    evidence.errorCode = typeof error?.code === "string" ? error.code : undefined;
    evidence.errorErrno = Number.isSafeInteger(error?.errno) ? error.errno : undefined;
    evidence.errorSyscall = typeof error?.syscall === "string" ? error.syscall : undefined;
    evidence.errorMessage = (error instanceof Error ? error.message : String(error)).replace(/[\0\r\n]/gu, " ").slice(0, 512);
    return evidence;
  } finally {
    if (secret) secret.fill(0);
    nested?.destroy();
    outer?.destroy();
    evidence.completedAt = new Date().toISOString();
    evidence.durationMs = Date.now() - started;
  }
}

try {
  output(await run(parseConfiguration(process.argv[2])));
} catch (error) {
  output({
    ok: false,
    error: (error instanceof Error ? error.message : String(error)).replace(/[\0\r\n]/gu, " ").slice(0, 512),
  });
}
