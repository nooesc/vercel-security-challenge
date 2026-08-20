import https from "node:https";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";

const SCOPE_CONFIRMATION = "researcher-controlled-sbx034-origins-only";
const MAX_BODY_BYTES = 8_192;
const MAX_TIMEOUT_MS = 15_000;
const HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;

function record(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value;
}

function text(value, name, maximum = 2_048) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[\0\r\n]/u.test(value)) {
    throw new Error(`${name} must be a bounded non-empty string without control characters`);
  }
  return value;
}

function hostname(value, name) {
  const input = text(value, name, 253);
  if (isIP(input)) return input.toLowerCase();
  if (input.includes(":")) throw new Error(`${name} must not contain a port`);
  const ascii = domainToASCII(input);
  if (!ascii || ascii.length > 253) throw new Error(`${name} is not a valid hostname`);
  return ascii.toLowerCase();
}

export function validateRedirectProbeConfig(input) {
  const value = record(input, "configuration");
  if (value.scopeConfirmation !== SCOPE_CONFIRMATION) {
    throw new Error(`scopeConfirmation must equal ${SCOPE_CONFIRMATION}`);
  }
  if (value.redirectMode !== "manual") throw new Error("redirectMode must equal manual");
  if (value.maxRedirects !== 0) throw new Error("maxRedirects must equal zero");
  if (value.retryCount !== 0) throw new Error("retryCount must equal zero");
  const controlled = Array.isArray(value.researcherControlledHosts)
    ? value.researcherControlledHosts.map((entry, index) => hostname(entry, `researcherControlledHosts[${index}]`))
    : [];
  if (controlled.length < 2 || new Set(controlled).size !== controlled.length) {
    throw new Error("researcherControlledHosts must contain at least two distinct hosts");
  }
  const tlsServername = hostname(value.tlsServername, "tlsServername");
  const httpHost = hostname(value.httpHost, "httpHost");
  if (!controlled.includes(tlsServername) || !controlled.includes(httpHost)) {
    throw new Error("TLS and HTTP identities must be declared researcher-controlled hosts");
  }
  const destinationHost = text(value.destinationHost, "destinationHost", 253);
  const destinationIdentity = isIP(destinationHost)
    ? destinationHost.toLowerCase()
    : hostname(destinationHost, "destinationHost");
  if (!isIP(destinationHost) && !controlled.includes(destinationIdentity)) {
    throw new Error("DNS destinationHost must be researcher-controlled");
  }
  const destinationPort = value.destinationPort ?? 443;
  if (!Number.isInteger(destinationPort) || destinationPort < 1 || destinationPort > 65_535) {
    throw new Error("destinationPort must be an integer from 1 through 65535");
  }
  const path = text(value.path, "path", 4_096);
  if (!path.startsWith("/") || path.startsWith("//") || /\s/u.test(path)) {
    throw new Error("path must be a whitespace-free origin-form request target");
  }
  const headers = record(value.headers ?? {}, "headers");
  const safeHeaders = {};
  for (const [name, headerValue] of Object.entries(headers)) {
    if (!HEADER_NAME.test(name) || name.toLowerCase() === "host") {
      throw new Error(`invalid or reserved header ${name}`);
    }
    safeHeaders[name] = text(headerValue, `headers.${name}`, 2_048);
  }
  const timeoutMs = value.timeoutMs ?? 5_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 250 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new Error(`timeoutMs must be an integer from 250 through ${MAX_TIMEOUT_MS}`);
  }
  return {
    runId: text(value.runId, "runId", 128),
    testId: text(value.testId, "testId", 128),
    caseId: text(value.caseId, "caseId", 128),
    correlationId: text(value.correlationId, "correlationId", 128),
    destinationHost,
    destinationPort,
    tlsServername,
    httpHost,
    path,
    headers: safeHeaders,
    timeoutMs,
    researcherControlledHosts: controlled,
  };
}

export function requestOptions(config) {
  return {
    hostname: config.destinationHost,
    port: config.destinationPort,
    servername: config.tlsServername,
    method: "GET",
    path: config.path,
    headers: { ...config.headers, Host: config.httpHost, Connection: "close" },
    timeout: config.timeoutMs,
    rejectUnauthorized: true,
    agent: false,
  };
}

function safeLocation(value) {
  if (typeof value !== "string" || value.length > 4_096 || /[\0\r\n]/u.test(value)) return undefined;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" ? parsed.toString() : undefined;
  } catch {
    return undefined;
  }
}

export async function runProbe(input) {
  const config = validateRedirectProbeConfig(input);
  const options = requestOptions(config);
  const started = Date.now();
  return await new Promise((resolve) => {
    let settled = false;
    let tcpConnected = false;
    let tlsEstablished = false;
    let remoteAddress;
    let remotePort;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve({
        schemaVersion: 1,
        runId: config.runId,
        testId: config.testId,
        caseId: config.caseId,
        correlationId: config.correlationId,
        requestUrl: new URL(config.path, `https://${config.httpHost}`).toString(),
        method: "GET",
        redirectMode: "manual",
        maxRedirects: 0,
        retryCount: 0,
        maximumRequests: 1,
        actualRequests: 1,
        requestCount: 1,
        redirectsAllowed: false,
        redirectsFollowed: 0,
        environmentProxyTrust: false,
        destinationHost: config.destinationHost,
        tlsServername: config.tlsServername,
        httpHost: config.httpHost,
        tcpConnected,
        tlsEstablished,
        ...(remoteAddress ? { remoteAddress } : {}),
        ...(remotePort ? { remotePort } : {}),
        durationMs: Date.now() - started,
        ...result,
      });
    };
    const request = https.request(options, (response) => {
      const chunks = [];
      let bodyLength = 0;
      let captured = 0;
      response.on("data", (chunk) => {
        const bytes = Buffer.from(chunk);
        bodyLength += bytes.length;
        if (captured < MAX_BODY_BYTES) {
          const part = bytes.subarray(0, MAX_BODY_BYTES - captured);
          chunks.push(part);
          captured += part.length;
        }
      });
      response.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        let responseJson;
        try {
          responseJson = JSON.parse(body);
        } catch {
          responseJson = undefined;
        }
        const location = safeLocation(response.headers.location);
        finish({
          ok: true,
          responseStarted: true,
          statusCode: response.statusCode,
          bodyLength,
          bodyTruncated: bodyLength > captured,
          ...(location ? { location } : {}),
          ...(responseJson && typeof responseJson === "object" && !Array.isArray(responseJson)
            ? {
                responseAuthenticated: responseJson.authenticated === true,
                responseOperationId: typeof responseJson.operationId === "string"
                  ? responseJson.operationId.slice(0, 128)
                  : undefined,
              }
            : {}),
        });
      });
    });
    request.on("socket", (socket) => {
      socket.once("connect", () => {
        tcpConnected = true;
        remoteAddress = socket.remoteAddress;
        remotePort = socket.remotePort;
      });
      socket.once("secureConnect", () => {
        tlsEstablished = socket.authorized === true;
        remoteAddress = socket.remoteAddress;
        remotePort = socket.remotePort;
      });
    });
    request.on("timeout", () => request.destroy(Object.assign(new Error("request timeout"), { code: "ETIMEDOUT" })));
    request.on("error", (error) => finish({
      ok: false,
      responseStarted: false,
      errorCode: typeof error.code === "string" ? error.code : "UNKNOWN",
      errorErrno: typeof error.errno === "number" ? error.errno : undefined,
      errorSyscall: typeof error.syscall === "string" ? error.syscall : undefined,
      errorMessage: String(error.message).replace(/[\0\r\n]/gu, " ").slice(0, 256),
    }));
    request.end();
  });
}

function decodeArgument(argument) {
  if (!argument) throw new Error("missing base64url configuration argument");
  const bytes = Buffer.from(argument, "base64url");
  if (bytes.length === 0 || bytes.length > 32_768) throw new Error("configuration size is invalid");
  return JSON.parse(bytes.toString("utf8"));
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  runProbe(decodeArgument(process.argv[2]))
    .then((result) => process.stdout.write(`${JSON.stringify(result)}\n`))
    .catch((error) => {
      process.stdout.write(`${JSON.stringify({ ok: false, configurationError: String(error.message).slice(0, 256) })}\n`);
      process.exitCode = 2;
    });
}
