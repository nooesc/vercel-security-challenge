#!/usr/bin/env node

import https from "node:https";
import { pathToFileURL } from "node:url";

const TEST_ID = "SBX-049-POC";
const SCOPE_CONFIRMATION = "researcher-controlled-sbx049-origin-only";
const CASES = new Set(["exact-pair", "key-half", "value-half", "combined-halves"]);
const MAX_BODY_BYTES = 4096;
const TRUST_ENV_NAMES = [
  "NODE_EXTRA_CA_CERTS",
  "NODE_USE_SYSTEM_CA",
  "OPENSSL_CONF",
  "OPENSSL_MODULES",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
];

function exactKeys(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((entry, index) => entry === wanted[index]);
}

function queryForCase(runId, caseId, canary) {
  const query = new URLSearchParams({ run: runId, case: caseId, canary });
  if (caseId === "exact-pair") query.append("role", "privileged");
  if (caseId === "key-half") query.append("role", "user");
  if (caseId === "value-half") query.append("decoy", "privileged");
  if (caseId === "combined-halves") {
    query.append("role", "user");
    query.append("decoy", "privileged");
  }
  return query.toString();
}

function decodeConfiguration(encoded) {
  if (typeof encoded !== "string" || !/^[A-Za-z0-9_-]+$/u.test(encoded)) {
    throw new Error("expected one base64url configuration argument");
  }
  return JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
}

export function validateConfiguration(value) {
  if (!exactKeys(value, ["canary", "caseId", "origin", "runId", "scopeConfirmation", "testId", "timeoutMs", "url"])) {
    throw new Error("configuration fields are not exact");
  }
  if (value.scopeConfirmation !== SCOPE_CONFIRMATION || value.testId !== TEST_ID) {
    throw new Error("scope or test identity mismatch");
  }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value.runId ?? "") ||
      !CASES.has(value.caseId) || !/^c49_[A-Za-z0-9_-]{24}$/u.test(value.canary ?? "")) {
    throw new Error("invalid correlation identity");
  }
  const origin = new URL(value.origin);
  if (origin.protocol !== "https:" || origin.username || origin.password || origin.port ||
      origin.pathname !== "/" || origin.search || origin.hash || origin.hostname !== origin.hostname.toLowerCase()) {
    throw new Error("origin must be an exact lower-case HTTPS origin");
  }
  const url = new URL(value.url);
  const expectedQuery = queryForCase(value.runId, value.caseId, value.canary);
  if (url.origin !== origin.origin || url.pathname !== "/v1/sbx049/action" ||
      url.search !== `?${expectedQuery}` || url.hash) {
    throw new Error("URL is not the exact controlled action URL");
  }
  if (!Number.isInteger(value.timeoutMs) || value.timeoutMs < 1000 || value.timeoutMs > 15000) {
    throw new Error("timeoutMs must be between 1000 and 15000");
  }
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
    throw new Error("NODE_TLS_REJECT_UNAUTHORIZED=0 is forbidden");
  }
  return { origin, url };
}

function boundedResponse(value, configuration) {
  if (!exactKeys(value, ["brokered", "canary", "caseId", "operationId", "runId", "testId"]) ||
      value.testId !== TEST_ID || value.runId !== configuration.runId ||
      value.caseId !== configuration.caseId || value.canary !== configuration.canary ||
      typeof value.brokered !== "boolean" || !/^q49[rs]_[A-Za-z0-9_-]{43}$/u.test(value.operationId ?? "")) {
    return undefined;
  }
  return value;
}

export async function requestOnce(configuration) {
  const { url } = validateConfiguration(configuration);
  const started = Date.now();
  const trustNames = TRUST_ENV_NAMES.filter((name) => process.env[name] !== undefined).sort();
  let tcpConnected = false;
  let tlsEstablished = false;
  let tlsAuthorized = false;

  return await new Promise((resolve) => {
    let settled = false;
    const finish = (fields) => {
      if (settled) return;
      settled = true;
      resolve({
        schemaVersion: 1,
        testId: TEST_ID,
        runId: configuration.runId,
        caseId: configuration.caseId,
        correlationCanary: configuration.canary,
        durationMs: Date.now() - started,
        requestHostname: url.hostname,
        requestServername: url.hostname,
        requestPath: `${url.pathname}${url.search}`,
        connectionAttempts: 1,
        actualConnections: tcpConnected ? 1 : 0,
        actualRequests: 1,
        retries: 0,
        redirectsFollowed: 0,
        rejectUnauthorized: true,
        controllerConfigurableCustomTrustAccepted: false,
        inheritedPlatformTrustEnvironmentNames: trustNames,
        tcpConnected,
        tlsEstablished,
        tlsAuthorized,
        responseBodyRetained: false,
        ...fields,
      });
    };

    const request = https.request({
      protocol: "https:",
      hostname: url.hostname,
      port: 443,
      servername: url.hostname,
      method: "GET",
      path: `${url.pathname}${url.search}`,
      agent: false,
      rejectUnauthorized: true,
      timeout: configuration.timeoutMs,
      headers: {
        accept: "application/json",
        connection: "close",
        "user-agent": "vsc-sbx049/1",
      },
    }, (response) => {
      const chunks = [];
      let length = 0;
      response.on("data", (chunk) => {
        const bytes = Buffer.from(chunk);
        length += bytes.byteLength;
        if (length > MAX_BODY_BYTES) {
          response.destroy(new Error("response body exceeded fixed cap"));
          return;
        }
        chunks.push(bytes);
      });
      response.on("end", () => {
        let parsed;
        try { parsed = boundedResponse(JSON.parse(Buffer.concat(chunks).toString("utf8")), configuration); }
        catch { parsed = undefined; }
        finish({
          ok: response.statusCode === 200 && parsed !== undefined,
          phase: "response",
          responseReceived: true,
          responseStatusCode: response.statusCode,
          responseBodyBytes: length,
          responseShapeValid: parsed !== undefined,
          ...(parsed ? { responseBrokered: parsed.brokered, responseOperationId: parsed.operationId } : {}),
        });
      });
    });
    request.once("socket", (socket) => {
      socket.once("connect", () => { tcpConnected = true; });
      socket.once("secureConnect", () => {
        tlsEstablished = true;
        tlsAuthorized = socket.authorized === true;
      });
    });
    request.once("timeout", () => request.destroy(Object.assign(new Error("request timeout"), { code: "ETIMEDOUT" })));
    request.once("error", (error) => finish({
      ok: false,
      phase: tlsEstablished ? "request" : "transport",
      responseReceived: false,
      responseShapeValid: false,
      errorCode: typeof error.code === "string" ? error.code : "UNKNOWN",
    }));
    request.end();
  });
}

function fail(message) {
  process.stdout.write(`${JSON.stringify({ schemaVersion: 1, ok: false, phase: "configuration", error: message })}\n`);
  process.exitCode = 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const result = await requestOnce(decodeConfiguration(process.argv[2]));
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  }
}
