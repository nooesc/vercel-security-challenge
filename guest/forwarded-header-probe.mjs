import http from "node:http";
import https from "node:https";
import { isIP } from "node:net";
import { domainToASCII, fileURLToPath } from "node:url";

const SCOPE_CONFIRMATION = "researcher-controlled-endpoints-only";
const HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const FORBIDDEN_RAW_HEADERS = new Set([
  "connection",
  "content-length",
  "host",
  "proxy-authorization",
  "transfer-encoding",
]);

function requireRecord(value, field) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${field} must be an object`);
  }
  return value;
}

function requireString(value, field) {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    throw new Error(`${field} must be a non-empty string without surrounding whitespace`);
  }
  if (/[\0\r\n]/u.test(value)) throw new Error(`${field} contains a forbidden control character`);
  return value;
}

function canonicalHostname(value, field) {
  const hostname = requireString(value, field);
  if (isIP(hostname)) return hostname.toLowerCase();
  const ascii = domainToASCII(hostname);
  if (!ascii || ascii.includes(":")) throw new Error(`${field} must be a valid hostname or IP address`);
  return ascii.toLowerCase();
}

function controlledOrigin(raw, config) {
  const url = new URL(requireString(raw, "baseUrl"));
  if (url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
    throw new Error("baseUrl must be an origin without credentials, path, query, or fragment");
  }
  const localTest =
    config.allowInsecureLoopbackForTesting === true &&
    url.protocol === "http:" &&
    (url.hostname === "127.0.0.1" || url.hostname === "::1");
  if (url.protocol !== "https:" && !localTest) {
    throw new Error("baseUrl must use HTTPS (HTTP is permitted only for explicit loopback tests)");
  }
  return url;
}

export function validateForwardedHeaderProbeConfig(input) {
  const config = requireRecord(input, "configuration");
  if (config.scopeConfirmation !== SCOPE_CONFIRMATION) {
    throw new Error(`scopeConfirmation must equal ${JSON.stringify(SCOPE_CONFIRMATION)}`);
  }
  const baseUrl = controlledOrigin(config.baseUrl, config);
  if (!Array.isArray(config.researcherControlledHosts) || config.researcherControlledHosts.length === 0) {
    throw new Error("researcherControlledHosts must be a non-empty array");
  }
  const controlledHosts = new Set(
    config.researcherControlledHosts.map((entry, index) =>
      canonicalHostname(entry, `researcherControlledHosts[${index}]`),
    ),
  );
  if (!controlledHosts.has(canonicalHostname(baseUrl.hostname, "baseUrl hostname"))) {
    throw new Error("baseUrl hostname is not listed in researcherControlledHosts");
  }

  const rawPath = requireString(config.rawPath, "rawPath");
  if (!rawPath.startsWith("/") || /^\/\//u.test(rawPath) || /[\s#]/u.test(rawPath)) {
    throw new Error("rawPath must be origin-form without whitespace or a fragment");
  }
  if (!Array.isArray(config.rawHeaders)) throw new Error("rawHeaders must be an array");
  if (config.rawHeaders.length > 32) throw new Error("rawHeaders may contain at most 32 fields");
  const rawHeaders = config.rawHeaders.map((entry, index) => {
    if (!Array.isArray(entry) || entry.length !== 2) {
      throw new Error(`rawHeaders[${index}] must be a [name, value] pair`);
    }
    const name = requireString(entry[0], `rawHeaders[${index}][0]`);
    const value = requireString(entry[1], `rawHeaders[${index}][1]`);
    if (!HEADER_NAME.test(name)) throw new Error(`rawHeaders[${index}][0] is not a valid header name`);
    if (FORBIDDEN_RAW_HEADERS.has(name.toLowerCase())) {
      throw new Error(`rawHeaders[${index}] may not set ${name}`);
    }
    return [name, value];
  });

  const timeoutMs = config.timeoutMs ?? 10_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) {
    throw new Error("timeoutMs must be an integer from 100 through 30000");
  }
  return {
    baseUrl,
    runId: requireString(config.runId, "runId"),
    testId: requireString(config.testId, "testId"),
    caseId: requireString(config.caseId, "caseId"),
    rawPath,
    rawHeaders,
    timeoutMs,
    ...(config.connectIp !== undefined
      ? {
          connectIp: (() => {
            const connectIp = canonicalHostname(config.connectIp, "connectIp");
            if (isIP(connectIp) !== 4) throw new Error("connectIp must be an IPv4 address");
            if (
              !Array.isArray(config.researcherControlledIpv4s) ||
              !config.researcherControlledIpv4s.some(
                (entry, index) => canonicalHostname(entry, `researcherControlledIpv4s[${index}]`) === connectIp,
              )
            ) {
              throw new Error("connectIp is not listed in researcherControlledIpv4s");
            }
            return connectIp;
          })(),
        }
      : {}),
  };
}

export function buildRawHeaderList(config) {
  return ["Host", config.baseUrl.host, ...config.rawHeaders.flat()];
}

export async function runForwardedHeaderProbe(config) {
  const client = config.baseUrl.protocol === "https:" ? https : http;
  const startedAt = Date.now();
  return await new Promise((resolve) => {
    let tcpConnected = false;
    let remoteAddress;
    let remotePort;
    let tlsEstablished = false;
    let responseStarted = false;
    const request = client.request(
      {
        protocol: config.baseUrl.protocol,
        hostname: config.connectIp ?? config.baseUrl.hostname,
        port: config.baseUrl.port || undefined,
        method: "GET",
        path: config.rawPath,
        headers: buildRawHeaderList(config),
        timeout: config.timeoutMs,
        ...(config.baseUrl.protocol === "https:"
          ? { rejectUnauthorized: true, servername: config.baseUrl.hostname }
          : {}),
        agent: false,
      },
      (response) => {
        responseStarted = true;
        const chunks = [];
        let bodyLength = 0;
        let capturedLength = 0;
        response.on("data", (chunk) => {
          const buffer = Buffer.from(chunk);
          bodyLength += buffer.length;
          if (capturedLength < 4_096) {
            const captured = buffer.subarray(0, 4_096 - capturedLength);
            chunks.push(captured);
            capturedLength += captured.length;
          }
        });
        response.on("end", () => {
          let parsed = {};
          let responseJsonValid = false;
          try {
            const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            if (typeof value === "object" && value !== null && !Array.isArray(value)) {
              parsed = value;
              responseJsonValid = true;
            }
          } catch {
            // Retain only the parse result, never an arbitrary response body.
          }
          resolve({
            ok: true,
            runId: config.runId,
            testId: config.testId,
            caseId: config.caseId,
            statusCode: response.statusCode,
            bodyLength,
            truncated: capturedLength < bodyLength,
            responseJsonValid,
            ...(typeof parsed.operationId === "string" ? { operationId: parsed.operationId } : {}),
            ...(typeof parsed.authenticated === "boolean" ? { authenticated: parsed.authenticated } : {}),
            ...(typeof parsed.actionAuthorized === "boolean" ? { actionAuthorized: parsed.actionAuthorized } : {}),
            outboundHeaderNames: config.rawHeaders.map(([name]) => name),
            connectIpUsed: config.connectIp,
            tcpConnected,
            ...(remoteAddress !== undefined ? { remoteAddress } : {}),
            ...(remotePort !== undefined ? { remotePort } : {}),
            tlsEstablished,
            responseStarted,
            durationMs: Date.now() - startedAt,
          });
        });
      },
    );
    request.on("socket", (socket) => {
      const captureTcpPeer = () => {
        tcpConnected = true;
        if (typeof socket.remoteAddress === "string") remoteAddress = socket.remoteAddress;
        if (Number.isInteger(socket.remotePort)) remotePort = socket.remotePort;
      };
      if (socket.connecting) socket.once("connect", captureTcpPeer);
      else captureTcpPeer();
      socket.once("secureConnect", () => {
        tlsEstablished = true;
      });
    });
    request.on("timeout", () => {
      const error = new Error("request timed out");
      error.code = "SBX_REQUEST_TIMEOUT";
      request.destroy(error);
    });
    request.on("error", (error) => {
      resolve({
        ok: false,
        runId: config.runId,
        testId: config.testId,
        caseId: config.caseId,
        errorPhase: responseStarted ? "response" : tlsEstablished ? "tls" : "connect",
        errorCode: typeof error?.code === "string" ? error.code : "UNKNOWN",
        ...(typeof error?.errno === "number" ? { errorErrno: error.errno } : {}),
        ...(typeof error?.syscall === "string" ? { errorSyscall: error.syscall } : {}),
        outboundHeaderNames: config.rawHeaders.map(([name]) => name),
        connectIpUsed: config.connectIp,
        tcpConnected,
        ...(remoteAddress !== undefined ? { remoteAddress } : {}),
        ...(remotePort !== undefined ? { remotePort } : {}),
        tlsEstablished,
        responseStarted,
        durationMs: Date.now() - startedAt,
      });
    });
    request.end();
  });
}

async function main() {
  const encoded = process.argv[2];
  if (!encoded) throw new Error("missing base64url forwarded-header probe configuration");
  const input = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  const config = validateForwardedHeaderProbeConfig(input);
  const result = await runForwardedHeaderProbe(config);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => {
    process.stdout.write(`${JSON.stringify({
      ok: false,
      errorPhase: "configuration",
      errorCode: "INVALID_CONFIGURATION",
    })}\n`);
    process.exitCode = 2;
  });
}
