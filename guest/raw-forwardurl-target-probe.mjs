import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { open } from "node:fs/promises";
import { STATUS_CODES } from "node:http";
import { isIP } from "node:net";
import tls from "node:tls";
import { domainToASCII, fileURLToPath } from "node:url";

const SCHEMA_VERSION = 1;
const SCOPE_CONFIRMATION = "researcher-controlled-sbx037-origins-only";
const OPERATOR_SECRET_FILE = "/tmp/sbx-037/operator-secret";
const MAX_CONFIGURATION_BYTES = 32 * 1024;
const MAX_TIMEOUT_MS = 15_000;
const MAX_RESPONSE_HEADER_BYTES = 16 * 1024;
const MAX_RESPONSE_BODY_BYTES = 8 * 1024;
const MAX_REQUEST_BODY_BYTES = 256;
const REQUIRED_CONTROLLER_INTERVAL_MS = 200;
const TARGET_FORMS = new Set(["origin", "absolute", "network-path"]);
const CONNECTION_ROLES = new Set(["a", "p", "b"]);
const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
const SAFE_ID = /^[A-Za-z0-9._:-]+$/u;
const RECEIPT_ID = /^rt37r_[A-Za-z0-9_-]{24}$/u;
const FALLBACK_RECEIPT_ID = /^rt37f_[A-Za-z0-9_-]{24}$/u;
const ROOT_KEYS = new Set([
  "aOrigin",
  "bOrigin",
  "bodyFile",
  "bodySource",
  "caseId",
  "connectionRole",
  "correlationId",
  "expectedOperationId",
  "maxResponseBodyBytes",
  "maxResponseHeaderBytes",
  "pUrl",
  "pinnedDestinationIpv4",
  "publicBody",
  "researcherControlledOrigins",
  "runId",
  "schemaVersion",
  "scopeConfirmation",
  "targetForm",
  "targetPath",
  "testId",
  "timeoutMs",
]);
const EXPLICITLY_FORBIDDEN_KEYS = new Set([
  "agent",
  "ca",
  "caPem",
  "cert",
  "checkServerIdentity",
  "headers",
  "key",
  "maxRedirects",
  "proxy",
  "redirectMode",
  "rejectUnauthorized",
  "retryCount",
  "secureContext",
  "servername",
]);
const RESPONSE_HEADERS = new Set([
  "content-type",
  "x-sbx-harness-canary",
  "x-sbx-operation-id",
  "x-sbx-role",
  "x-sbx037-fallback-receipt",
  "x-sbx037-case",
  "x-sbx037-run",
  "x-sbx037-test",
]);
const INHERITED_PLATFORM_TRUST_ENVIRONMENT_NAMES = Object.freeze([
  "NODE_EXTRA_CA_CERTS",
  "NODE_USE_SYSTEM_CA",
  "OPENSSL_CONF",
  "OPENSSL_MODULES",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
]);

function record(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value;
}

function boundedString(value, name, maximum) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
    throw new Error(`${name} must be a bounded non-empty string`);
  }
  if (/[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(`${name} contains a forbidden control character`);
  }
  return value;
}

function identifier(value, name) {
  const result = boundedString(value, name, 128);
  if (!SAFE_ID.test(result)) throw new Error(`${name} contains unsupported characters`);
  return result;
}

function dnsHostname(value, name) {
  const raw = boundedString(value, name, 253);
  if (isIP(raw)) throw new Error(`${name} must be a DNS hostname`);
  const ascii = domainToASCII(raw).toLowerCase();
  if (!ascii || ascii.length > 253 || ascii.endsWith(".")) {
    throw new Error(`${name} must be a canonical DNS hostname`);
  }
  const labels = ascii.split(".");
  if (labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))) {
    throw new Error(`${name} must be a canonical DNS hostname`);
  }
  return ascii;
}

function httpsOrigin(value, name) {
  const input = boundedString(value, name, 2_048);
  let url;
  try {
    url = new URL(input);
  } catch {
    throw new Error(`${name} must be an HTTPS origin`);
  }
  if (
    url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" ||
    url.search || url.hash
  ) {
    throw new Error(`${name} must be an HTTPS origin without credentials, path, query, or fragment`);
  }
  const hostname = dnsHostname(url.hostname, `${name} hostname`);
  const port = url.port === "" ? 443 : Number(url.port);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`${name} contains an invalid port`);
  }
  const authority = port === 443 ? hostname : `${hostname}:${port}`;
  return { origin: `https://${authority}`, hostname, authority, port };
}

function httpsEndpoint(value, name) {
  const input = boundedString(value, name, 4_096);
  let url;
  try {
    url = new URL(input);
  } catch {
    throw new Error(`${name} must be an HTTPS URL`);
  }
  if (url.protocol !== "https:" || url.username || url.password || url.hash) {
    throw new Error(`${name} must be an HTTPS URL without credentials or a fragment`);
  }
  const hostname = dnsHostname(url.hostname, `${name} hostname`);
  const port = url.port === "" ? 443 : Number(url.port);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`${name} contains an invalid port`);
  }
  const authority = port === 443 ? hostname : `${hostname}:${port}`;
  url.hostname = hostname;
  url.port = port === 443 ? "" : String(port);
  return { url: url.toString(), origin: `https://${authority}`, hostname, authority, port };
}

function originFormPath(value, name) {
  const path = boundedString(value, name, 2_048);
  if (!/^[\x21-\x7e]+$/u.test(path)) {
    throw new Error(`${name} must contain only visible ASCII request-target characters`);
  }
  if (!path.startsWith("/") || path.startsWith("//") || path.includes("#") || path.includes("\\")) {
    throw new Error(`${name} must be a single-slash origin-form path without a fragment or backslash`);
  }
  return path;
}

function publicIpv4(value, name) {
  if (typeof value !== "string" || value.length < 7 || value.length > 15 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(`${name} must be a canonical public IPv4 address`);
  }
  const input = value;
  if (isIP(input) !== 4) throw new Error(`${name} must be a canonical public IPv4 address`);
  const octets = input.split(".").map(Number);
  if (octets.join(".") !== input) throw new Error(`${name} must be a canonical public IPv4 address`);
  const [a, b, c] = octets;
  const reserved =
    a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && (c === 0 || c === 2)) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113);
  if (reserved) throw new Error(`${name} must be a canonical public IPv4 address`);
  return input;
}

function exactInteger(value, name, fallback, minimum, maximum) {
  const candidate = value ?? fallback;
  if (!Number.isInteger(candidate) || candidate < minimum || candidate > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} through ${maximum}`);
  }
  return candidate;
}

function validateEncodedConfiguration(encoded) {
  if (typeof encoded !== "string" || encoded.length === 0 || !/^[A-Za-z0-9_-]+$/u.test(encoded)) {
    throw new Error("missing or malformed base64url probe configuration");
  }
  const bytes = Buffer.from(encoded, "base64url");
  if (bytes.length === 0 || bytes.length > MAX_CONFIGURATION_BYTES) {
    throw new Error("probe configuration size is invalid");
  }
  if (bytes.toString("base64url") !== encoded) {
    throw new Error("probe configuration is not canonical base64url");
  }
  return JSON.parse(bytes.toString("utf8"));
}

export function validateRawTargetProbeConfig(input) {
  const value = record(input, "configuration");
  for (const key of Object.keys(value)) {
    if (EXPLICITLY_FORBIDDEN_KEYS.has(key)) {
      throw new Error(`${key} cannot be configured by this verified-TLS, no-proxy, no-redirect probe`);
    }
    if (!ROOT_KEYS.has(key)) throw new Error(`unknown configuration field ${key}`);
  }
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
    throw new Error("NODE_TLS_REJECT_UNAUTHORIZED=0 is forbidden");
  }
  if (typeof process.env.NODE_OPTIONS === "string" && process.env.NODE_OPTIONS.length > 0) {
    throw new Error("NODE_OPTIONS is forbidden for the standalone verified-TLS probe");
  }
  const runtimeInjectionOption = /^(?:-r|--require|--import|--loader|--experimental-loader|--use-openssl-ca|--use-system-ca|--openssl-config)(?:=|$)/u;
  if (process.execArgv.some((argument) => runtimeInjectionOption.test(argument))) {
    throw new Error("trust-store or runtime-injection Node options are forbidden");
  }
  if (value.schemaVersion !== SCHEMA_VERSION) throw new Error(`schemaVersion must equal ${SCHEMA_VERSION}`);
  if (value.scopeConfirmation !== SCOPE_CONFIRMATION) {
    throw new Error(`scopeConfirmation must equal ${SCOPE_CONFIRMATION}`);
  }

  const a = httpsOrigin(value.aOrigin, "aOrigin");
  const b = httpsOrigin(value.bOrigin, "bOrigin");
  const p = httpsEndpoint(value.pUrl, "pUrl");
  const pinnedDestinationIpv4 = publicIpv4(value.pinnedDestinationIpv4, "pinnedDestinationIpv4");
  if (new Set([a.origin, b.origin, p.origin]).size !== 3) {
    throw new Error("A, B, and P must be three distinct HTTPS origins");
  }
  if (!Array.isArray(value.researcherControlledOrigins) || value.researcherControlledOrigins.length !== 3) {
    throw new Error("researcherControlledOrigins must declare exactly A, B, and P");
  }
  const declared = value.researcherControlledOrigins.map((entry, index) =>
    httpsOrigin(entry, `researcherControlledOrigins[${index}]`).origin,
  );
  if (new Set(declared).size !== 3) {
    throw new Error("researcherControlledOrigins must contain three distinct origins");
  }
  const expectedOrigins = new Set([a.origin, b.origin, p.origin]);
  if (declared.some((origin) => !expectedOrigins.has(origin))) {
    throw new Error("researcherControlledOrigins must exactly match A, B, and P");
  }
  if (typeof value.connectionRole !== "string" || !CONNECTION_ROLES.has(value.connectionRole)) {
    throw new Error("connectionRole must equal a, p, or b");
  }
  const connection = value.connectionRole === "a" ? a : value.connectionRole === "p" ? p : b;

  if (typeof value.targetForm !== "string" || !TARGET_FORMS.has(value.targetForm)) {
    throw new Error("targetForm must equal origin, absolute, or network-path");
  }
  const targetPath = originFormPath(value.targetPath, "targetPath");
  const bodySource = value.bodySource;
  if (bodySource !== "public" && bodySource !== "file") {
    throw new Error("bodySource must equal public or file");
  }
  let publicBody;
  if (bodySource === "public") {
    publicBody = boundedString(value.publicBody, "publicBody", MAX_REQUEST_BODY_BYTES);
    if (!/^[\x20-\x7e]+$/u.test(publicBody)) {
      throw new Error("publicBody must contain only printable ASCII");
    }
    if (value.bodyFile !== undefined) throw new Error("bodyFile is forbidden for a public body");
  } else {
    if (value.targetForm === "origin") {
      throw new Error("file body transmission is allowed only for absolute or network-path attack cases");
    }
    if (value.bodyFile !== OPERATOR_SECRET_FILE) {
      throw new Error(`bodyFile must equal the fixed SBX-037 operator-secret path`);
    }
    if (value.publicBody !== undefined) throw new Error("publicBody is forbidden for a file body");
  }

  const rawRequestTarget = value.targetForm === "origin"
    ? targetPath
    : value.targetForm === "absolute"
      ? `${b.origin}${targetPath}`
      : `//${b.authority}${targetPath}`;
  if (rawRequestTarget.length > 4_096) throw new Error("constructed request target exceeds its limit");
  const expectedOperationId = identifier(value.expectedOperationId, "expectedOperationId");
  if (!RECEIPT_ID.test(expectedOperationId)) {
    throw new Error("expectedOperationId must be an SBX-037 public receipt ID");
  }

  return {
    schemaVersion: SCHEMA_VERSION,
    runId: identifier(value.runId, "runId"),
    testId: identifier(value.testId, "testId"),
    caseId: identifier(value.caseId, "caseId"),
    correlationId: identifier(value.correlationId, "correlationId"),
    expectedOperationId,
    a,
    b,
    p,
    connectionRole: value.connectionRole,
    connection,
    pinnedDestinationIpv4,
    targetForm: value.targetForm,
    targetPath,
    rawRequestTarget,
    bodySource,
    ...(publicBody ? { publicBody } : {}),
    timeoutMs: exactInteger(value.timeoutMs, "timeoutMs", 5_000, 250, MAX_TIMEOUT_MS),
    maxResponseHeaderBytes: exactInteger(
      value.maxResponseHeaderBytes,
      "maxResponseHeaderBytes",
      MAX_RESPONSE_HEADER_BYTES,
      1_024,
      MAX_RESPONSE_HEADER_BYTES,
    ),
    maxResponseBodyBytes: exactInteger(
      value.maxResponseBodyBytes,
      "maxResponseBodyBytes",
      MAX_RESPONSE_BODY_BYTES,
      256,
      MAX_RESPONSE_BODY_BYTES,
    ),
  };
}

function fixedHeaders(config, bodyLength) {
  return [
    ["Host", config.connection.authority],
    ["User-Agent", "vsc-sbx037-raw-forwardurl-target-probe/1"],
    ["Accept", "application/json"],
    ["Content-Type", config.bodySource === "file" ? "application/octet-stream" : "text/plain; charset=utf-8"],
    ["Content-Length", String(bodyLength)],
    ["X-SBX037-Run", config.runId],
    ["X-SBX037-Test", config.testId],
    ["X-SBX037-Case", config.caseId],
    ["X-SBX-Harness-Canary", config.correlationId],
    ["Connection", "close"],
  ];
}

export function buildRawRequest(config, body) {
  if (!Buffer.isBuffer(body) || body.length < 1 || body.length > MAX_REQUEST_BODY_BYTES) {
    throw new Error("request body is missing or invalid");
  }
  if (body.includes(0) || body.includes(10) || body.includes(13)) {
    throw new Error("request body contains a forbidden control character");
  }
  const lines = [`POST ${config.rawRequestTarget} HTTP/1.1`];
  for (const [name, value] of fixedHeaders(config, body.length)) {
    if (!TOKEN.test(name) || typeof value !== "string" || /[\u0000-\u001f\u007f]/u.test(value)) {
      throw new Error("refusing to construct an unsafe HTTP request header");
    }
    lines.push(`${name}: ${value}`);
  }
  lines.push("", "");
  return Buffer.concat([Buffer.from(lines.join("\r\n"), "ascii"), body]);
}

function commonEvidence(config) {
  return {
    schemaVersion: SCHEMA_VERSION,
    runId: config.runId,
    testId: config.testId,
    caseId: config.caseId,
    correlationId: config.correlationId,
    targetForm: config.targetForm,
    connectionRole: config.connectionRole,
    method: "POST",
    bodySource: config.bodySource,
    ...(config.bodySource === "public" ? { requestBodyBytes: Buffer.byteLength(config.publicBody, "ascii") } : {}),
    operatorSecretLoaded: false,
    httpVersion: "1.1",
    tcpHost: config.connection.hostname,
    tcpPort: config.connection.port,
    pinnedDestinationIpv4: config.pinnedDestinationIpv4,
    tlsServername: config.connection.hostname,
    httpHost: config.connection.authority,
    rawRequestTarget: config.rawRequestTarget,
    maximumConnections: 1,
    maximumRequests: 1,
    retryCount: 0,
    redirectsAllowed: false,
    redirectsFollowed: 0,
    connectionReused: false,
    environmentProxyTrust: false,
    tlsTrust: {
      inheritedPlatformTrustEnvironmentNames: INHERITED_PLATFORM_TRUST_ENVIRONMENT_NAMES.filter(
        (name) => typeof process.env[name] === "string" && process.env[name].length > 0,
      ),
      controllerConfigurableCustomTrustAccepted: false,
      rejectUnauthorized: true,
    },
  };
}

export function buildRawTargetProbePlan(input) {
  const config = validateRawTargetProbeConfig(input);
  return {
    ...commonEvidence(config),
    ok: true,
    phase: "plan",
    owned: { aOrigin: config.a.origin, bOrigin: config.b.origin, pUrl: config.p.url },
    connectionRole: config.connectionRole,
    connection: {
      host: config.pinnedDestinationIpv4,
      port: config.connection.port,
      servername: config.connection.hostname,
      httpHost: config.connection.authority,
      rejectUnauthorized: true,
      minimumTlsVersion: "TLSv1.2",
      alpnProtocols: ["http/1.1"],
      freshConnection: true,
      absoluteDeadline: true,
    },
    request: {
      requestLine: `POST ${config.rawRequestTarget} HTTP/1.1`,
      headerNames: fixedHeaders(config, 1).map(([name]) => name.toLowerCase()),
      contentLengthComputedOnlyAtRuntime: config.bodySource === "file",
      rawRequestBytesExposed: false,
      responseBodyExposed: false,
      requiredControllerMinimumIntervalMs: REQUIRED_CONTROLLER_INTERVAL_MS,
      maximumQps: 5,
    },
    responseLimits: { headerBytes: config.maxResponseHeaderBytes, bodyBytes: config.maxResponseBodyBytes },
  };
}

async function readOperatorSecret() {
  let handle;
  let bytes;
  try {
    if (typeof fsConstants.O_NOFOLLOW !== "number") throw new Error("invalid");
    handle = await open(OPERATOR_SECRET_FILE, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const stat = await handle.stat();
    if (!stat.isFile() || (stat.mode & 0o777) !== 0o600 || stat.size < 1 || stat.size > MAX_REQUEST_BODY_BYTES) {
      throw new Error("invalid");
    }
    bytes = Buffer.alloc(MAX_REQUEST_BODY_BYTES + 1);
    const result = await handle.read(bytes, 0, bytes.length, 0);
    if (result.bytesRead !== stat.size || result.bytesRead < 1 || result.bytesRead > MAX_REQUEST_BODY_BYTES) {
      throw new Error("invalid");
    }
    const body = Buffer.from(bytes.subarray(0, result.bytesRead));
    if (body.includes(0) || body.includes(10) || body.includes(13)) throw new Error("invalid");
    return { body, mode: 0o600 };
  } catch {
    throw new Error("operator secret file is missing, unsafe, or invalid");
  } finally {
    bytes?.fill(0);
    await handle?.close().catch(() => {});
  }
}

class BufferedSocketReader {
  constructor(socket) {
    this.iterator = socket[Symbol.asyncIterator]();
    this.buffer = Buffer.alloc(0);
    this.ended = false;
  }

  async pull() {
    if (this.ended) return false;
    const result = await this.iterator.next();
    if (result.done) {
      this.ended = true;
      return false;
    }
    this.buffer = Buffer.concat([this.buffer, Buffer.from(result.value)]);
    return true;
  }

  async through(delimiter, maximumBytes) {
    while (true) {
      const index = this.buffer.indexOf(delimiter);
      if (index !== -1) {
        if (index > maximumBytes) throw new Error("HTTP response headers exceeded their limit");
        const value = this.buffer.subarray(0, index);
        this.buffer = this.buffer.subarray(index + delimiter.length);
        return value;
      }
      if (this.buffer.length > maximumBytes) throw new Error("HTTP response headers exceeded their limit");
      if (!await this.pull()) throw new Error("TLS connection closed before response headers completed");
    }
  }

  async exact(length) {
    while (this.buffer.length < length) {
      if (!await this.pull()) throw new Error("TLS connection closed before the response body completed");
    }
    const value = this.buffer.subarray(0, length);
    this.buffer = this.buffer.subarray(length);
    return value;
  }

  async toEnd(maximumBytes) {
    while (!this.ended) {
      if (this.buffer.length > maximumBytes) throw new Error("HTTP response body exceeded its limit");
      await this.pull();
    }
    if (this.buffer.length > maximumBytes) throw new Error("HTTP response body exceeded its limit");
    const value = this.buffer;
    this.buffer = Buffer.alloc(0);
    return value;
  }
}

function parseHeaderBlock(block) {
  const lines = block.toString("latin1").split("\r\n");
  const rawStatusLine = lines.shift() ?? "";
  if (rawStatusLine.length > 512 || /[^\x20-\x7e]/u.test(rawStatusLine)) {
    throw new Error("invalid HTTP response status line");
  }
  const match = /^(HTTP\/1\.[01]) ([1-5][0-9]{2})(?:[ ]([^\r\n]*))?$/u.exec(rawStatusLine);
  if (!match) throw new Error("invalid HTTP response status line");
  const headers = new Map();
  for (const line of lines) {
    const separator = line.indexOf(":");
    if (separator <= 0) throw new Error("invalid HTTP response header");
    const name = line.slice(0, separator).toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (!TOKEN.test(name) || /[^\x09\x20-\x7e]/u.test(value)) throw new Error("invalid HTTP response header");
    const values = headers.get(name) ?? [];
    values.push(value);
    headers.set(name, values);
  }
  return { rawStatusLine, httpVersion: match[1], statusCode: Number(match[2]), headers };
}

async function readChunkedBody(reader, maximumBytes, maximumHeaderBytes) {
  const chunks = [];
  let length = 0;
  while (true) {
    const sizeLine = (await reader.through(Buffer.from("\r\n"), 1_024)).toString("ascii");
    const token = sizeLine.split(";", 1)[0];
    if (!token || !/^[0-9a-f]+$/iu.test(token)) throw new Error("invalid HTTP chunk size");
    const size = Number.parseInt(token, 16);
    if (!Number.isSafeInteger(size)) throw new Error("invalid HTTP chunk size");
    if (size === 0) {
      let trailerBytes = 0;
      while (true) {
        const trailer = await reader.through(Buffer.from("\r\n"), maximumHeaderBytes - trailerBytes);
        trailerBytes += trailer.length + 2;
        if (trailer.length === 0) break;
        if (trailerBytes > maximumHeaderBytes) throw new Error("HTTP response trailers exceeded their limit");
      }
      break;
    }
    if (length + size > maximumBytes) throw new Error("HTTP response body exceeded its limit");
    chunks.push(await reader.exact(size));
    length += size;
    if (!(await reader.exact(2)).equals(Buffer.from("\r\n"))) throw new Error("invalid HTTP chunk terminator");
  }
  return Buffer.concat(chunks);
}

export function selectedHeaders(headers, config) {
  const result = {};
  for (const [name, values] of headers) {
    if (!RESPONSE_HEADERS.has(name)) continue;
    if (values.length !== 1) continue;
    const value = values[0];
    const exact =
      (name === "content-type" && /^(?:application\/json|text\/plain)(?:;[ -~]{0,128})?$/iu.test(value)) ||
      (name === "x-sbx-operation-id" && value === config.expectedOperationId) ||
      (name === "x-sbx037-run" && value === config.runId) ||
      (name === "x-sbx037-test" && value === config.testId) ||
      (name === "x-sbx037-case" && value === config.caseId) ||
      (name === "x-sbx-harness-canary" && value === config.correlationId) ||
      (name === "x-sbx-role" && ["A", "B", "P"].includes(value)) ||
      (name === "x-sbx037-fallback-receipt" && FALLBACK_RECEIPT_ID.test(value));
    if (exact) result[name] = value;
  }
  return result;
}

export function responseReceipt(body, headers, config) {
  let parsed;
  try {
    parsed = JSON.parse(body.toString("utf8"));
  } catch {
    parsed = undefined;
  }
  const object = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : undefined;
  const bodyOperationId = object?.operationId === config.expectedOperationId ? config.expectedOperationId : undefined;
  const headerValues = headers.get("x-sbx-operation-id") ?? [];
  const headerOperationId = headerValues.length === 1 && headerValues[0] === config.expectedOperationId
    ? config.expectedOperationId
    : undefined;
  const operationIdConflict = Boolean(
    (bodyOperationId && headerOperationId && bodyOperationId !== headerOperationId) || headerValues.length > 1,
  );
  const operationId = operationIdConflict ? undefined : bodyOperationId ?? headerOperationId;
  const fallbackValues = headers.get("x-sbx037-fallback-receipt") ?? [];
  const fallbackReceiptId = fallbackValues.length === 1 && FALLBACK_RECEIPT_ID.test(fallbackValues[0])
    ? fallbackValues[0]
    : undefined;
  const bodyRole = ["A", "B", "P"].includes(object?.role) ? object.role : undefined;
  const headerRoleValues = headers.get("x-sbx-role") ?? [];
  const headerRole = headerRoleValues.length === 1 && ["A", "B", "P"].includes(headerRoleValues[0])
    ? headerRoleValues[0]
    : undefined;
  const roleConflict = Boolean(bodyRole && headerRole && bodyRole !== headerRole) || headerRoleValues.length > 1;
  const role = roleConflict ? undefined : bodyRole ?? headerRole;
  const receipt = {
    jsonObject: object !== undefined,
    ...(operationId ? { operationId } : {}),
    ...(operationIdConflict ? { operationIdConflict: true } : {}),
    ...(fallbackReceiptId ? { fallbackReceiptId } : {}),
    ...(fallbackValues.length > 0 && !fallbackReceiptId ? { fallbackReceiptConflict: true } : {}),
    ...(role ? { role } : {}),
    ...(roleConflict ? { roleConflict: true } : {}),
  };
  if (object?.runId === config.runId) receipt.runId = config.runId;
  if (object?.testId === config.testId) receipt.testId = config.testId;
  if (object?.caseId === config.caseId) receipt.caseId = config.caseId;
  if (object?.correlationId === config.correlationId) receipt.correlationId = config.correlationId;
  if (["A", "B", "P"].includes(object?.receivedBy)) receipt.receivedBy = object.receivedBy;
  for (const name of ["authenticated", "platformTokenVerified", "operatorSecretActionAuthorized"]) {
    if (typeof object?.[name] === "boolean") receipt[name] = object[name];
  }
  return receipt;
}

async function readResponse(reader, config) {
  let informationalResponses = 0;
  while (true) {
    const block = await reader.through(Buffer.from("\r\n\r\n"), config.maxResponseHeaderBytes);
    const parsed = parseHeaderBlock(block);
    if (parsed.statusCode >= 100 && parsed.statusCode < 200) {
      informationalResponses += 1;
      if (informationalResponses > 2) throw new Error("too many informational HTTP responses");
      continue;
    }
    const transferEncoding = (parsed.headers.get("transfer-encoding") ?? []).map((value) => value.toLowerCase());
    const contentLengths = parsed.headers.get("content-length") ?? [];
    if (transferEncoding.length > 0 && contentLengths.length > 0) throw new Error("ambiguous HTTP response framing");
    let body;
    let bodyFraming;
    if (parsed.statusCode === 204 || parsed.statusCode === 304) {
      body = Buffer.alloc(0);
      bodyFraming = "none";
    } else if (transferEncoding.length > 0) {
      if (transferEncoding.length !== 1 || transferEncoding[0] !== "chunked") {
        throw new Error("unsupported HTTP transfer encoding");
      }
      body = await readChunkedBody(reader, config.maxResponseBodyBytes, config.maxResponseHeaderBytes);
      bodyFraming = "chunked";
    } else if (contentLengths.length > 0) {
      if (new Set(contentLengths).size !== 1 || !/^[0-9]+$/u.test(contentLengths[0])) {
        throw new Error("invalid HTTP Content-Length framing");
      }
      const length = Number(contentLengths[0]);
      if (!Number.isSafeInteger(length) || length > config.maxResponseBodyBytes) {
        throw new Error("HTTP response body exceeded its limit");
      }
      body = await reader.exact(length);
      bodyFraming = "content-length";
    } else {
      body = await reader.toEnd(config.maxResponseBodyBytes);
      bodyFraming = "connection-close";
    }
    return {
      ...(parsed.rawStatusLine === `${parsed.httpVersion} ${parsed.statusCode} ${STATUS_CODES[parsed.statusCode] ?? ""}`.trimEnd()
        ? { rawStatusLine: parsed.rawStatusLine, rawStatusLineRetained: true }
        : { statusLine: `${parsed.httpVersion} ${parsed.statusCode}`, rawStatusLineRetained: false }),
      httpVersion: parsed.httpVersion,
      statusCode: parsed.statusCode,
      selectedHeaders: selectedHeaders(parsed.headers, config),
      bodyFraming,
      bodyWithinLimit: true,
      receipt: responseReceipt(body, parsed.headers, config),
    };
  }
}

async function connectVerified(config) {
  const progress = {
    tcpConnected: false,
    tlsEstablished: false,
    pinnedDestinationIpv4: config.pinnedDestinationIpv4,
  };
  const socket = tls.connect({
    host: config.pinnedDestinationIpv4,
    port: config.connection.port,
    servername: config.connection.hostname,
    rejectUnauthorized: true,
    minVersion: "TLSv1.2",
    ALPNProtocols: ["http/1.1"],
  });
  const absoluteDeadline = setTimeout(() => {
    socket.destroy(Object.assign(new Error("probe timed out"), { code: "ETIMEDOUT" }));
  }, config.timeoutMs);
  absoluteDeadline.unref();
  socket.once("connect", () => {
    progress.tcpConnected = true;
    progress.remoteAddress = socket.remoteAddress;
    progress.remotePort = socket.remotePort;
  });
  try {
    await new Promise((resolve, reject) => {
      const onSecure = () => { cleanup(); resolve(); };
      const onError = (error) => { cleanup(); reject(error); };
      const cleanup = () => {
        socket.off("secureConnect", onSecure);
        socket.off("error", onError);
      };
      socket.once("secureConnect", onSecure);
      socket.once("error", onError);
    });
  } catch (error) {
    clearTimeout(absoluteDeadline);
    socket.destroy();
    error.partialTransport = { ...progress };
    throw error;
  }
  progress.tlsEstablished = socket.authorized === true && !socket.authorizationError;
  progress.remoteAddress = socket.remoteAddress;
  progress.remotePort = socket.remotePort;
  if (!socket.authorized || socket.authorizationError) {
    clearTimeout(absoluteDeadline);
    socket.destroy();
    const error = new Error("TLS peer verification failed");
    error.partialTransport = { ...progress };
    throw error;
  }
  if (socket.alpnProtocol !== "http/1.1") {
    clearTimeout(absoluteDeadline);
    socket.destroy();
    const error = new Error("TLS did not negotiate HTTP/1.1");
    error.partialTransport = { ...progress };
    throw error;
  }
  socket.disableRenegotiation();
  const certificate = socket.getPeerCertificate();
  if (!Buffer.isBuffer(certificate.raw) || certificate.raw.length === 0) {
    clearTimeout(absoluteDeadline);
    socket.destroy();
    const error = new Error("TLS peer certificate metadata is unavailable");
    error.partialTransport = { ...progress };
    throw error;
  }
  const cipher = socket.getCipher();
  return {
    socket,
    absoluteDeadline,
    evidence: {
      ...progress,
      authorized: true,
      alpnProtocol: socket.alpnProtocol,
      tlsProtocol: socket.getProtocol() ?? undefined,
      cipher: cipher ? { name: cipher.standardName ?? cipher.name, version: cipher.version } : undefined,
      peerCertificate: {
        sha256: createHash("sha256").update(certificate.raw).digest("hex"),
        validFrom: certificate.valid_from,
        validTo: certificate.valid_to,
      },
    },
  };
}

function safeError(error) {
  return {
    errorCode: typeof error?.code === "string" ? error.code.slice(0, 64) : "UNKNOWN",
    errorMessage: String(error?.message ?? error).replace(/[\u0000-\u001f\u007f]/gu, " ").slice(0, 256),
  };
}

export async function runRawTargetProbe(input) {
  const config = validateRawTargetProbeConfig(input);
  const common = commonEvidence(config);
  const startedAt = Date.now();
  let body;
  let bodyFileMode;
  let requestBytes;
  let connection;
  let partialTransport;
  let actualRequests = 0;
  try {
    if (config.bodySource === "file") {
      const loaded = await readOperatorSecret();
      body = loaded.body;
      bodyFileMode = loaded.mode;
    } else {
      body = Buffer.from(config.publicBody, "ascii");
    }
    requestBytes = buildRawRequest(config, body);
    body.fill(0);
    body = undefined;
    try {
      connection = await connectVerified(config);
    } catch (error) {
      partialTransport = error?.partialTransport;
      throw error;
    }
    const reader = new BufferedSocketReader(connection.socket);
    await new Promise((resolve, reject) => {
      connection.socket.write(requestBytes, (error) => {
        requestBytes.fill(0);
        requestBytes = undefined;
        if (error) reject(error);
        else resolve();
      });
    });
    actualRequests = 1;
    const response = await readResponse(reader, config);
    return {
      ...common,
      ok: true,
      phase: "response",
      syntaxSupported: ![400, 414, 431, 501, 505].includes(response.statusCode),
      operatorSecretLoaded: config.bodySource === "file",
      ...(config.bodySource === "file" ? { bodyFileMode } : {}),
      actualConnections: 1,
      actualRequests,
      responseStatusCode: response.statusCode,
      ...(response.receipt.operationId ? { responseOperationId: response.receipt.operationId } : {}),
      ...(response.receipt.fallbackReceiptId
        ? { responseFallbackReceiptId: response.receipt.fallbackReceiptId }
        : {}),
      ...(response.receipt.role ? { responseRole: response.receipt.role } : {}),
      transport: connection.evidence,
      response,
      durationMs: Date.now() - startedAt,
    };
  } catch (error) {
    return {
      ...common,
      ok: false,
      phase: connection ? "response" : config.bodySource === "file" && body === undefined && requestBytes === undefined
        ? "operator-secret" : "transport",
      operatorSecretLoaded: config.bodySource === "file" && (body !== undefined || requestBytes !== undefined || connection !== undefined),
      actualConnections: connection || partialTransport?.tcpConnected ? 1 : 0,
      actualRequests,
      ...(connection ? { transport: connection.evidence } : partialTransport ? { transport: partialTransport } : {}),
      ...safeError(error),
      durationMs: Date.now() - startedAt,
    };
  } finally {
    body?.fill(0);
    requestBytes?.fill(0);
    if (connection?.absoluteDeadline) clearTimeout(connection.absoluteDeadline);
    connection?.socket.destroy();
  }
}

async function main() {
  const input = validateEncodedConfiguration(process.argv[2]);
  const mode = process.argv[3];
  if (mode !== undefined && mode !== "--plan") throw new Error("only --plan is accepted as an optional mode");
  const result = mode === "--plan" ? buildRawTargetProbePlan(input) : await runRawTargetProbe(input);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => {
    process.stdout.write(`${JSON.stringify({
      schemaVersion: SCHEMA_VERSION,
      ok: false,
      phase: "configuration",
      ...safeError(error),
    })}\n`);
    process.exitCode = 2;
  });
}
