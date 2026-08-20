import { createHmac, timingSafeEqual } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { open } from "node:fs/promises";
import http from "node:http";
import { isAbsolute, normalize, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const SCHEMA_VERSION = 1;
const TEST_ID = "SBX-046";
const PORT = 3000;
const LISTEN_HOST = "0.0.0.0";
const LOOPBACK_BASE_URL = "http://127.0.0.1:3000";
const CANARY_PATH = "/v1/sbx046/canary";
const MAX_CONFIG_BYTES = 32 * 1024;
const MAX_CASES = 8;
const MAX_RESPONSE_BYTES = 4 * 1024;
const MAX_EVENT_BYTES = 2 * 1024;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SANDBOX_NAME = /^sbx-046-[a-z0-9](?:[a-z0-9-]{0,53}[a-z0-9])?$/u;
const SESSION_ID = /^sbx_[A-Za-z0-9_-]{16,124}$/u;
const SERVICE_INSTANCE_ID = /^svc46_[A-Za-z0-9_-]{24}$/u;
const CASE_ID = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/u;
const CHALLENGE = /^ch46_[A-Za-z0-9_-]{24}$/u;
const OPERATION_ID = /^op46_[A-Za-z0-9_-]{43}$/u;
const SERVICE_KEYS = new Set([
  "cases",
  "eventLogPath",
  "hmacKey",
  "port",
  "runId",
  "sandboxName",
  "schemaVersion",
  "serviceInstanceId",
  "sessionId",
  "testId",
]);
const CASE_KEYS = new Set(["challenge", "operationId"]);
const PROBE_KEYS = new Set([
  "baseUrl",
  "caseId",
  "challenge",
  "expectedOperationId",
  "port",
  "runId",
  "sandboxName",
  "schemaVersion",
  "serviceInstanceId",
  "sessionId",
  "testId",
  "timeoutMs",
]);
const EXPLICITLY_FORBIDDEN_CONFIGURATION_KEYS = new Set([
  "agent",
  "ca",
  "cert",
  "checkServerIdentity",
  "env",
  "headers",
  "hostname",
  "key",
  "maxRedirects",
  "NODE_EXTRA_CA_CERTS",
  "NODE_OPTIONS",
  "NODE_TLS_REJECT_UNAUTHORIZED",
  "proxy",
  "redirect",
  "rejectUnauthorized",
  "retryCount",
  "secureContext",
]);
const RECEIPT_KEYS = [
  "caseId",
  "challenge",
  "ok",
  "operationId",
  "port",
  "requestBodyValidated",
  "runId",
  "sandboxName",
  "schemaVersion",
  "serviceInstanceId",
  "sessionId",
  "testId",
].sort();

function objectRecord(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value;
}

function exactKeys(value, allowed, name) {
  for (const key of Object.keys(value)) {
    if (EXPLICITLY_FORBIDDEN_CONFIGURATION_KEYS.has(key)) {
      throw new Error(`${name} field ${key} is forbidden`);
    }
    if (!allowed.has(key)) throw new Error(`unknown ${name} field ${key}`);
  }
  for (const key of allowed) {
    if (!Object.hasOwn(value, key)) throw new Error(`${name} field ${key} is required`);
  }
}

function exactString(value, name, pattern, maximum = 256) {
  if (
    typeof value !== "string" || value.length === 0 || value.length > maximum ||
    /[\u0000-\u001f\u007f]/u.test(value) || !pattern.test(value)
  ) {
    throw new Error(`${name} has an invalid format`);
  }
  return value;
}

function exactIdentity(value) {
  if (value.schemaVersion !== SCHEMA_VERSION) throw new Error(`schemaVersion must equal ${SCHEMA_VERSION}`);
  if (value.testId !== TEST_ID) throw new Error(`testId must equal ${TEST_ID}`);
  const runId = exactString(value.runId, "runId", UUID_V4, 36);
  const sandboxName = exactString(value.sandboxName, "sandboxName", SANDBOX_NAME, 63);
  const sessionId = exactString(value.sessionId, "sessionId", SESSION_ID, 128);
  if (value.port !== PORT) throw new Error(`port must equal ${PORT}`);
  const serviceInstanceId = exactString(
    value.serviceInstanceId,
    "serviceInstanceId",
    SERVICE_INSTANCE_ID,
    30,
  );
  return { runId, sandboxName, sessionId, port: PORT, serviceInstanceId };
}

function canonicalBase64urlBytes(value, name, minimum, maximum) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new Error(`${name} must be canonical base64url`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length < minimum || bytes.length > maximum || bytes.toString("base64url") !== value) {
    throw new Error(`${name} must decode to ${minimum} through ${maximum} bytes`);
  }
  return bytes;
}

function safeEqual(left, right) {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

function canonicalOperationMessage(value) {
  return JSON.stringify([
    TEST_ID,
    value.runId,
    value.sandboxName,
    value.sessionId,
    PORT,
    value.serviceInstanceId,
    value.caseId,
    value.challenge,
  ]);
}

/**
 * Returns the only keyed receipt accepted by the SBX-046 service.
 * `hmacKey` must be a canonical base64url encoding of 32 through 64 bytes.
 */
export function computeOperationId(input) {
  const value = objectRecord(input, "operation input");
  const identity = exactIdentity({
    ...value,
    schemaVersion: SCHEMA_VERSION,
    testId: TEST_ID,
    port: PORT,
  });
  const caseId = exactString(value.caseId, "caseId", CASE_ID, 64);
  const challenge = exactString(value.challenge, "challenge", CHALLENGE, 29);
  const keyBytes = canonicalBase64urlBytes(value.hmacKey, "hmacKey", 32, 64);
  try {
    return `op46_${createHmac("sha256", keyBytes)
      .update(canonicalOperationMessage({ ...identity, caseId, challenge }), "utf8")
      .digest("base64url")}`;
  } finally {
    keyBytes.fill(0);
  }
}

function normalizedAbsolutePath(value, name) {
  if (
    typeof value !== "string" || value.length === 0 || value.length > 4_096 ||
    /[\u0000\r\n]/u.test(value) || !isAbsolute(value) || normalize(value) !== value
  ) {
    throw new Error(`${name} must be a normalized absolute path`);
  }
  return value;
}

export function validateServiceConfiguration(input) {
  const value = objectRecord(input, "service configuration");
  exactKeys(value, SERVICE_KEYS, "service configuration");
  const identity = exactIdentity(value);
  const hmacKey = exactString(value.hmacKey, "hmacKey", /^[A-Za-z0-9_-]+$/u, 128);
  canonicalBase64urlBytes(hmacKey, "hmacKey", 32, 64).fill(0);
  const eventLogPath = normalizedAbsolutePath(value.eventLogPath, "eventLogPath");
  const rawCases = objectRecord(value.cases, "cases");
  const entries = Object.entries(rawCases);
  if (entries.length === 0 || entries.length > MAX_CASES) {
    throw new Error(`cases must contain 1 through ${MAX_CASES} exact mappings`);
  }
  const cases = Object.create(null);
  const challenges = new Set();
  const operationIds = new Set();
  for (const [rawCaseId, rawMapping] of entries) {
    const caseId = exactString(rawCaseId, "caseId", CASE_ID, 64);
    const mapping = objectRecord(rawMapping, `cases.${caseId}`);
    exactKeys(mapping, CASE_KEYS, `cases.${caseId}`);
    const challenge = exactString(mapping.challenge, `cases.${caseId}.challenge`, CHALLENGE, 29);
    const operationId = exactString(mapping.operationId, `cases.${caseId}.operationId`, OPERATION_ID, 48);
    if (challenges.has(challenge)) throw new Error("case challenges must be unique");
    if (operationIds.has(operationId)) throw new Error("case operation IDs must be unique");
    const expected = computeOperationId({ ...identity, caseId, challenge, hmacKey });
    if (!safeEqual(operationId, expected)) {
      throw new Error(`cases.${caseId}.operationId does not match the keyed identity`);
    }
    challenges.add(challenge);
    operationIds.add(operationId);
    cases[caseId] = Object.freeze({ challenge, operationId });
  }
  return Object.freeze({
    schemaVersion: SCHEMA_VERSION,
    testId: TEST_ID,
    ...identity,
    hmacKey,
    eventLogPath,
    cases: Object.freeze(cases),
  });
}

export function validateProbeConfiguration(input) {
  const value = objectRecord(input, "probe configuration");
  exactKeys(value, PROBE_KEYS, "probe configuration");
  const identity = exactIdentity(value);
  if (value.baseUrl !== LOOPBACK_BASE_URL) {
    throw new Error(`baseUrl must equal ${LOOPBACK_BASE_URL}`);
  }
  const caseId = exactString(value.caseId, "caseId", CASE_ID, 64);
  const challenge = exactString(value.challenge, "challenge", CHALLENGE, 29);
  const expectedOperationId = exactString(
    value.expectedOperationId,
    "expectedOperationId",
    OPERATION_ID,
    48,
  );
  if (!Number.isInteger(value.timeoutMs) || value.timeoutMs < 250 || value.timeoutMs > 5_000) {
    throw new Error("timeoutMs must be an integer from 250 through 5000");
  }
  return Object.freeze({
    schemaVersion: SCHEMA_VERSION,
    testId: TEST_ID,
    ...identity,
    baseUrl: LOOPBACK_BASE_URL,
    caseId,
    challenge,
    expectedOperationId,
    timeoutMs: value.timeoutMs,
  });
}

export function parseEncodedProbeConfiguration(encoded) {
  if (typeof encoded !== "string" || encoded.length === 0 || !/^[A-Za-z0-9_-]+$/u.test(encoded)) {
    throw new Error("probe configuration must be canonical base64url");
  }
  const bytes = Buffer.from(encoded, "base64url");
  if (
    bytes.length === 0 || bytes.length > MAX_CONFIG_BYTES ||
    bytes.toString("base64url") !== encoded
  ) {
    throw new Error("probe configuration must be bounded canonical base64url");
  }
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("probe configuration must contain valid JSON");
  }
  return validateProbeConfiguration(parsed);
}

export async function loadServiceConfiguration(path) {
  const exactPath = normalizedAbsolutePath(path, "service configuration path");
  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  const handle = await open(exactPath, fsConstants.O_RDONLY | noFollow);
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.nlink !== 1 || (metadata.mode & 0o777) !== 0o600) {
      throw new Error("service configuration must be a single-link regular file with exact mode 0600");
    }
    if (metadata.size === 0 || metadata.size > MAX_CONFIG_BYTES) {
      throw new Error("service configuration file size is invalid");
    }
    let parsed;
    try {
      parsed = JSON.parse(await handle.readFile("utf8"));
    } catch {
      throw new Error("service configuration file must contain valid JSON");
    }
    return validateServiceConfiguration(parsed);
  } finally {
    await handle.close();
  }
}

function headerValues(request, name) {
  const values = request.headersDistinct?.[name];
  if (Array.isArray(values)) return values;
  const fallback = request.headers[name];
  return typeof fallback === "string" ? [fallback] : Array.isArray(fallback) ? fallback : [];
}

function exactSingleHeader(request, name) {
  const values = headerValues(request, name);
  if (values.length !== 1 || typeof values[0] !== "string") return undefined;
  return values[0];
}

function responseHeaders(body) {
  return {
    "cache-control": "no-store",
    connection: "close",
    "content-length": String(Buffer.byteLength(body)),
    "content-type": "application/json; charset=utf-8",
    "x-content-type-options": "nosniff",
    "x-sbx046-service": "1",
  };
}

function sendJson(response, statusCode, value) {
  const body = `${JSON.stringify(value)}\n`;
  if (Buffer.byteLength(body) > MAX_RESPONSE_BYTES) throw new Error("response exceeded its fixed bound");
  response.writeHead(statusCode, responseHeaders(body));
  response.end(body);
}

async function readExactBody(request, expectedBytes) {
  const chunks = [];
  let received = 0;
  for await (const chunk of request) {
    received += chunk.length;
    if (received > expectedBytes || received > 128) {
      request.destroy();
      throw new Error("request body exceeded its exact bound");
    }
    chunks.push(Buffer.from(chunk));
  }
  if (received !== expectedBytes) throw new Error("request body length did not match");
  return Buffer.concat(chunks, received);
}

function sanitizedEvent(config, caseId, mapping, observedAt) {
  return {
    schemaVersion: SCHEMA_VERSION,
    testId: TEST_ID,
    runId: config.runId,
    sandboxName: config.sandboxName,
    sessionId: config.sessionId,
    port: PORT,
    serviceInstanceId: config.serviceInstanceId,
    caseId,
    challenge: mapping.challenge,
    operationId: mapping.operationId,
    observedAt,
    method: "POST",
    path: CANARY_PATH,
    requestBodyValidated: true,
    rawHmacKeyRetained: false,
    rawRequestBodyRetained: false,
    derivedDigestRetained: false,
  };
}

async function openEventLog(path) {
  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  const handle = await open(
    path,
    fsConstants.O_WRONLY | fsConstants.O_APPEND | fsConstants.O_CREAT | noFollow,
    0o600,
  );
  const metadata = await handle.stat();
  if (!metadata.isFile() || metadata.nlink !== 1 || (metadata.mode & 0o777) !== 0o600) {
    await handle.close();
    throw new Error("event log must be a single-link regular file with exact mode 0600");
  }
  if (metadata.size !== 0) {
    await handle.close();
    throw new Error("event log must be empty when the service starts");
  }
  return handle;
}

export async function startService(input) {
  const config = validateServiceConfiguration(input);
  const eventHandle = await openEventLog(config.eventLogPath);
  const seenCases = new Set();
  let closing = false;
  const server = http.createServer({
    connectionsCheckingInterval: 1_000,
    headersTimeout: 2_000,
    highWaterMark: 2 * 1024,
    joinDuplicateHeaders: false,
    keepAlive: false,
    requestTimeout: 5_000,
    requireHostHeader: true,
  }, async (request, response) => {
    try {
      response.shouldKeepAlive = false;
      if (closing) return sendJson(response, 503, { ok: false, errorCode: "SERVICE_CLOSING" });
      if (request.method !== "POST" || request.url !== CANARY_PATH) {
        request.resume();
        return sendJson(response, 404, { ok: false, errorCode: "ROUTE_NOT_FOUND" });
      }
      if (
        headerValues(request, "transfer-encoding").length !== 0 ||
        headerValues(request, "expect").length !== 0 ||
        exactSingleHeader(request, "content-type") !== "text/plain; charset=utf-8"
      ) {
        request.resume();
        return sendJson(response, 400, { ok: false, errorCode: "REQUEST_FRAMING_INVALID" });
      }
      const runId = exactSingleHeader(request, "x-sbx046-run");
      const caseId = exactSingleHeader(request, "x-sbx046-case");
      const challenge = exactSingleHeader(request, "x-sbx046-challenge");
      if (!safeEqual(runId ?? "", config.runId) || typeof caseId !== "string") {
        request.resume();
        return sendJson(response, 403, { ok: false, errorCode: "CANARY_IDENTITY_INVALID" });
      }
      const mapping = config.cases[caseId];
      if (!mapping || !safeEqual(challenge ?? "", mapping.challenge) || seenCases.has(caseId)) {
        request.resume();
        return sendJson(response, 403, { ok: false, errorCode: "CANARY_IDENTITY_INVALID" });
      }
      const expectedBody = Buffer.from(`public:${mapping.challenge}`, "utf8");
      if (exactSingleHeader(request, "content-length") !== String(expectedBody.length)) {
        request.resume();
        return sendJson(response, 400, { ok: false, errorCode: "REQUEST_FRAMING_INVALID" });
      }
      const actualBody = await readExactBody(request, expectedBody.length);
      if (actualBody.length !== expectedBody.length || !timingSafeEqual(actualBody, expectedBody)) {
        return sendJson(response, 403, { ok: false, errorCode: "CANARY_BODY_INVALID" });
      }
      seenCases.add(caseId);
      const event = sanitizedEvent(config, caseId, mapping, new Date().toISOString());
      const eventLine = `${JSON.stringify(event)}\n`;
      if (Buffer.byteLength(eventLine) > MAX_EVENT_BYTES) throw new Error("event exceeded its fixed bound");
      await eventHandle.write(eventLine, null, "utf8");
      await eventHandle.sync();
      return sendJson(response, 200, {
        schemaVersion: SCHEMA_VERSION,
        testId: TEST_ID,
        runId: config.runId,
        sandboxName: config.sandboxName,
        sessionId: config.sessionId,
        port: PORT,
        serviceInstanceId: config.serviceInstanceId,
        caseId,
        challenge: mapping.challenge,
        operationId: mapping.operationId,
        requestBodyValidated: true,
        ok: true,
      });
    } catch {
      if (!response.headersSent && !response.destroyed) {
        sendJson(response, 500, { ok: false, errorCode: "SERVICE_ERROR" });
      } else if (!response.destroyed) {
        response.destroy();
      }
    }
  });
  server.maxConnections = 8;
  server.maxRequestsPerSocket = 1;
  server.on("clientError", (_error, socket) => {
    if (!socket.destroyed) {
      socket.end(
        "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nCache-Control: no-store\r\n" +
        "Content-Length: 0\r\nX-SBX046-Service: 1\r\n\r\n",
      );
    }
  });
  try {
    await new Promise((resolve, reject) => {
      const onError = (error) => {
        server.off("listening", onListening);
        reject(error);
      };
      const onListening = () => {
        server.off("error", onError);
        resolve();
      };
      server.once("error", onError);
      server.once("listening", onListening);
      server.listen(PORT, LISTEN_HOST);
    });
  } catch (error) {
    await eventHandle.close();
    throw error;
  }
  let closed = false;
  return {
    config,
    server,
    async close() {
      if (closed) return;
      closed = true;
      closing = true;
      await new Promise((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
        server.closeAllConnections?.();
      });
      await eventHandle.close();
    },
  };
}

function baseProbeEvidence(config) {
  return {
    schemaVersion: SCHEMA_VERSION,
    testId: TEST_ID,
    runId: config.runId,
    sandboxName: config.sandboxName,
    sessionId: config.sessionId,
    port: PORT,
    serviceInstanceId: config.serviceInstanceId,
    caseId: config.caseId,
    challenge: config.challenge,
    expectedOperationId: config.expectedOperationId,
    targetBaseUrl: LOOPBACK_BASE_URL,
    targetPath: CANARY_PATH,
    requestOrigin: LOOPBACK_BASE_URL,
    requestPath: CANARY_PATH,
    method: "POST",
    timeoutMs: config.timeoutMs,
    attemptCount: 1,
    requestAttempts: 1,
    connectionAttempts: 1,
    actualRequests: 0,
    retryCount: 0,
    redirectsFollowed: 0,
    freshConnection: true,
    strictTlsVerification: false,
    proxyConfigurationAccepted: false,
    tlsTrustConfigurationAccepted: false,
    rawConfigurationRetained: false,
    rawRequestBodyRetained: false,
    rawResponseBodyRetained: false,
    tcpConnected: false,
    tlsEstablished: false,
    tlsAuthorized: false,
    responseReceived: false,
    timedOut: false,
    receiptValidated: false,
  };
}

function sanitizedErrorCode(error) {
  const code = typeof error?.code === "string" ? error.code : "PROBE_ERROR";
  return /^[A-Z][A-Z0-9_]{1,31}$/u.test(code) ? code : "PROBE_ERROR";
}

function exactReceipt(value, config) {
  const receipt = objectRecord(value, "service receipt");
  if (Object.keys(receipt).sort().join(",") !== RECEIPT_KEYS.join(",")) {
    throw new Error("service receipt fields were not exact");
  }
  if (
    receipt.schemaVersion !== SCHEMA_VERSION || receipt.testId !== TEST_ID || receipt.ok !== true ||
    receipt.requestBodyValidated !== true || receipt.port !== PORT ||
    receipt.runId !== config.runId || receipt.sandboxName !== config.sandboxName ||
    receipt.sessionId !== config.sessionId || receipt.serviceInstanceId !== config.serviceInstanceId ||
    receipt.caseId !== config.caseId || receipt.challenge !== config.challenge ||
    receipt.operationId !== config.expectedOperationId
  ) {
    throw new Error("service receipt identity did not match the exact probe configuration");
  }
  return receipt;
}

export async function runProbe(input) {
  const config = validateProbeConfiguration(input);
  const evidence = baseProbeEvidence(config);
  const startedAt = process.hrtime.bigint();
  const body = Buffer.from(`public:${config.challenge}`, "utf8");
  let responseBody;
  try {
    const outcome = await new Promise((resolve, reject) => {
      const request = http.request({
        agent: false,
        family: 4,
        headers: {
          "accept-encoding": "identity",
          connection: "close",
          "content-length": String(body.length),
          "content-type": "text/plain; charset=utf-8",
          host: "127.0.0.1:3000",
          "x-sbx046-case": config.caseId,
          "x-sbx046-challenge": config.challenge,
          "x-sbx046-run": config.runId,
        },
        hostname: "127.0.0.1",
        method: "POST",
        path: CANARY_PATH,
        port: PORT,
        protocol: "http:",
        setDefaultHeaders: false,
        timeout: config.timeoutMs,
      }, (response) => {
        evidence.responseReceived = true;
        const chunks = [];
        let bytes = 0;
        response.on("data", (chunk) => {
          bytes += chunk.length;
          if (bytes > MAX_RESPONSE_BYTES) {
            response.destroy(Object.assign(new Error("response body exceeded its bound"), { code: "RESPONSE_TOO_LARGE" }));
            return;
          }
          chunks.push(Buffer.from(chunk));
        });
        response.once("error", reject);
        response.once("end", () => resolve({
          complete: response.complete,
          headers: response.headersDistinct,
          statusCode: response.statusCode,
          body: Buffer.concat(chunks, bytes),
        }));
      });
      request.once("socket", (socket) => {
        socket.once("connect", () => { evidence.tcpConnected = true; });
      });
      request.once("timeout", () => {
        evidence.timedOut = true;
        request.destroy(Object.assign(new Error("probe timed out"), { code: "PROBE_TIMEOUT" }));
      });
      request.once("error", reject);
      request.end(body);
      evidence.actualRequests = 1;
    });
    responseBody = outcome.body;
    evidence.statusCode = outcome.statusCode;
    evidence.responseBytes = responseBody.length;
    const oneResponseHeader = (name) => {
      const values = outcome.headers[name];
      return Array.isArray(values) && values.length === 1 ? values[0] : undefined;
    };
    evidence.serviceHeaderValidated = oneResponseHeader("x-sbx046-service") === "1";
    evidence.cacheControlValidated = oneResponseHeader("cache-control") === "no-store";
    evidence.connectionCloseValidated = oneResponseHeader("connection") === "close";
    evidence.contentTypeValidated = oneResponseHeader("content-type") === "application/json; charset=utf-8";
    evidence.contentLengthValidated = oneResponseHeader("content-length") === String(responseBody.length);
    if (
      outcome.complete !== true || outcome.statusCode !== 200 ||
      !evidence.serviceHeaderValidated || !evidence.cacheControlValidated ||
      !evidence.connectionCloseValidated || !evidence.contentTypeValidated ||
      !evidence.contentLengthValidated || oneResponseHeader("location") !== undefined ||
      oneResponseHeader("content-encoding") !== undefined
    ) {
      throw new Error("service response envelope was not exact");
    }
    let parsed;
    try {
      parsed = JSON.parse(responseBody.toString("utf8"));
    } catch {
      throw new Error("service response was not valid JSON");
    }
    const receipt = exactReceipt(parsed, config);
    evidence.operationId = receipt.operationId;
    evidence.serviceResponse = {
      schemaVersion: receipt.schemaVersion,
      testId: receipt.testId,
      runId: receipt.runId,
      sandboxName: receipt.sandboxName,
      sessionId: receipt.sessionId,
      port: receipt.port,
      serviceInstanceId: receipt.serviceInstanceId,
      caseId: receipt.caseId,
      challenge: receipt.challenge,
      operationId: receipt.operationId,
      requestBodyValidated: receipt.requestBodyValidated,
      ok: receipt.ok,
    };
    evidence.receiptValidated = true;
    evidence.ok = true;
    return evidence;
  } catch (error) {
    evidence.ok = false;
    evidence.errorCode = sanitizedErrorCode(error);
    return evidence;
  } finally {
    evidence.durationMs = Number(process.hrtime.bigint() - startedAt) / 1_000_000;
    if (responseBody) responseBody.fill(0);
    body.fill(0);
  }
}

async function main() {
  const [mode, argument, extra] = process.argv.slice(2);
  if (extra !== undefined || (mode !== "serve" && mode !== "probe") || typeof argument !== "string") {
    throw new Error("usage: published-port-revocation-service.mjs serve <absolute-config-path> | probe <base64url-json>");
  }
  if (mode === "probe") {
    process.stdout.write(`${JSON.stringify(await runProbe(parseEncodedProbeConfiguration(argument)))}\n`);
    return;
  }
  const service = await startService(await loadServiceConfiguration(argument));
  process.stdout.write(`${JSON.stringify({
    schemaVersion: SCHEMA_VERSION,
    testId: TEST_ID,
    mode: "serve",
    ready: true,
    runId: service.config.runId,
    sandboxName: service.config.sandboxName,
    sessionId: service.config.sessionId,
    port: PORT,
    serviceInstanceId: service.config.serviceInstanceId,
    listenHost: LISTEN_HOST,
    eventLogReady: true,
    rawHmacKeyRetained: false,
    rawConfigurationRetained: false,
  })}\n`);
  const stop = async () => {
    await service.close();
    process.exitCode = 0;
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
