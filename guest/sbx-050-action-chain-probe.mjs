import https from "node:https";
import { isIP } from "node:net";
import { pathToFileURL } from "node:url";

const SCOPE = "researcher-controlled-sbx050-origins-only";
const TEST_ID = "SBX-050-POC";
const PUBLIC_TRIGGER = "sbx050-public-forward-control";
const CASE_HEADER = "x-sbx050-case";
const CANARY_HEADER = "x-sbx050-canary";
const RUN_HEADER = "x-sbx050-run";
const TRIGGER_HEADER = "x-sbx050-route-trigger";
const MAX_BODY_BYTES = 8_192;
const MAX_TIMEOUT_MS = 15_000;
const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANARY = /^c50_[A-Za-z0-9_-]{24}$/u;
const SECRET_SHAPE = /(?:s50_[A-Za-z0-9_-]{43}|t50_[A-Za-z0-9_-]{32})/u;
const OPERATION_ID = /^chain50_[A-Za-z0-9_-]{43}$/u;
const CASES = new Set([
  "public-forward-control", "transform-alone-control", "final-plain-pre", "direct-p-pre",
  "arm-without-trigger", "direct-p-post", "final-plain-post",
]);
const TRUST_ENV_NAMES = [
  "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF",
  "OPENSSL_MODULES", "SSL_CERT_DIR", "SSL_CERT_FILE",
];

function record(value, name) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${name} must be an object`);
  return value;
}

function exactKeys(value, wanted) {
  const actual = Object.keys(value).sort();
  const expected = [...wanted].sort();
  return actual.length === expected.length && actual.every((entry, index) => entry === expected[index]);
}

function safeText(value, name, maximum = 2_048) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[\0\r\n]/u.test(value)) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

function expectedPath(runId, caseId, canary) {
  const pathname = caseId === "arm-without-trigger" || caseId === "transform-alone-control"
    ? `/v1/sbx050/arm/${runId}`
    : `/v1/sbx050/request/${runId}/${caseId}`;
  return `${pathname}?${new URLSearchParams({ case: caseId, canary }).toString()}`;
}

function exactOrigin(raw) {
  const parsed = new URL(raw);
  if (raw !== parsed.origin || parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.port ||
      parsed.pathname !== "/" || parsed.search || parsed.hash || isIP(parsed.hostname) !== 0 ||
      parsed.hostname !== parsed.hostname.toLowerCase()) throw new Error("targetOrigin must be one exact public HTTPS origin");
  return parsed;
}

function secretShapeAbsent(value) {
  return !SECRET_SHAPE.test(JSON.stringify(value));
}

export function validateConfiguration(input) {
  const value = record(input, "configuration");
  const keys = [
    "caseId", "correlationCanary", "requestPath", "runId", "scopeConfirmation",
    "sendPublicTrigger", "targetOrigin", "testId", "timeoutMs",
  ];
  if (!exactKeys(value, keys) || value.scopeConfirmation !== SCOPE || value.testId !== TEST_ID ||
      typeof value.runId !== "string" || !RUN_ID.test(value.runId) ||
      typeof value.caseId !== "string" || !CASES.has(value.caseId) ||
      typeof value.correlationCanary !== "string" || !CANARY.test(value.correlationCanary) ||
      typeof value.sendPublicTrigger !== "boolean" ||
      value.sendPublicTrigger !== (value.caseId === "public-forward-control") || !secretShapeAbsent(value)) {
    throw new Error("configuration fields or identities are not exact");
  }
  const origin = exactOrigin(safeText(value.targetOrigin, "targetOrigin"));
  const requestPath = expectedPath(value.runId, value.caseId, value.correlationCanary);
  if (value.requestPath !== requestPath) throw new Error("requestPath is not exact");
  if (!Number.isInteger(value.timeoutMs) || value.timeoutMs < 500 || value.timeoutMs > MAX_TIMEOUT_MS) {
    throw new Error("timeoutMs is invalid");
  }
  return {
    testId: TEST_ID,
    runId: value.runId,
    caseId: value.caseId,
    correlationCanary: value.correlationCanary,
    targetOrigin: origin.origin,
    hostname: origin.hostname,
    requestPath,
    sendPublicTrigger: value.sendPublicTrigger,
    timeoutMs: value.timeoutMs,
  };
}

export function requestOptions(configuration) {
  const headers = {
    Host: configuration.hostname,
    Connection: "close",
    [RUN_HEADER]: configuration.runId,
    [CASE_HEADER]: configuration.caseId,
    [CANARY_HEADER]: configuration.correlationCanary,
    ...(configuration.sendPublicTrigger ? { [TRIGGER_HEADER]: PUBLIC_TRIGGER } : {}),
  };
  if (Object.keys(headers).some((name) => name.toLowerCase() === "x-sbx050-brokered-credential") ||
      (!configuration.sendPublicTrigger && Object.keys(headers).some((name) => name.toLowerCase() === TRIGGER_HEADER))) {
    throw new Error("forbidden attack header reached request options");
  }
  return {
    hostname: configuration.hostname,
    port: 443,
    servername: configuration.hostname,
    method: "GET",
    path: configuration.requestPath,
    headers,
    rejectUnauthorized: true,
    agent: false,
    timeout: configuration.timeoutMs,
  };
}

function inheritedPlatformTrustEnvironmentNames() {
  return TRUST_ENV_NAMES.filter((name) => process.env[name] !== undefined).sort();
}

function environmentContainsSecretShape() {
  return Object.values(process.env).some((value) => typeof value === "string" && SECRET_SHAPE.test(value));
}

function errorFacts(error) {
  const code = typeof error?.code === "string" ? error.code.slice(0, 64) : "ERR_REQUEST";
  const syscall = typeof error?.syscall === "string" ? error.syscall.slice(0, 64) : undefined;
  const errno = typeof error?.errno === "number" && Number.isInteger(error.errno) ? error.errno : undefined;
  const errorClass = code === "EAI_AGAIN" ? "dns-resolution"
    : code === "ECONNRESET" ? "connection-reset"
      : code === "EHOSTUNREACH" || code === "ENETUNREACH" ? "route-unreachable" : undefined;
  return { code, syscall, errno, errorClass };
}

export async function runProbe(input) {
  const configuration = validateConfiguration(input);
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0" || environmentContainsSecretShape()) {
    throw new Error("unsafe guest trust or hidden-material environment");
  }
  const started = Date.now();
  const startedAt = new Date(started).toISOString();
  return await new Promise((resolve) => {
    let settled = false;
    let tcpConnected = false;
    let tlsEstablished = false;
    let tlsAuthorized = false;
    let actualConnections = 0;
    let actualRequests = 0;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve({
        schemaVersion: 1,
        testId: TEST_ID,
        runId: configuration.runId,
        caseId: configuration.caseId,
        correlationCanary: configuration.correlationCanary,
        commandExitCode: 0,
        startedAt,
        completedAt: new Date().toISOString(),
        requestHostname: configuration.hostname,
        requestServername: configuration.hostname,
        requestPath: configuration.requestPath,
        sentCredentialHeader: false,
        sentHiddenTriggerHeader: false,
        sentPublicTriggerHeader: configuration.sendPublicTrigger,
        connectionAttempts: 1,
        actualConnections,
        actualRequests,
        retries: 0,
        redirectsFollowed: 0,
        rejectUnauthorized: true,
        controllerConfigurableCustomTrustAccepted: false,
        inheritedPlatformTrustEnvironmentNames: inheritedPlatformTrustEnvironmentNames(),
        tcpConnected,
        tlsEstablished,
        tlsAuthorized,
        responseBodyRetained: false,
        durationMs: Date.now() - started,
        ...value,
      });
    };
    const request = https.request(requestOptions(configuration), (response) => {
      const chunks = [];
      let received = 0;
      response.on("data", (chunk) => {
        const bytes = Buffer.from(chunk);
        received += bytes.byteLength;
        if (received <= MAX_BODY_BYTES) chunks.push(bytes);
      });
      response.on("end", () => {
        let body;
        try { body = received <= MAX_BODY_BYTES ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : undefined; }
        catch { body = undefined; }
        const parsed = body !== null && typeof body === "object" && !Array.isArray(body) ? body : undefined;
        const responseShapeValid = parsed !== undefined && exactKeys(parsed, [
          "caseId", "credentialMatched", "oidcVerified", "operationId", "role", "schemaVersion", "testId", "triggerMatched",
        ]) && parsed.schemaVersion === 1 && parsed.testId === TEST_ID && parsed.caseId === configuration.caseId &&
          (parsed.role === "A" || parsed.role === "P") && typeof parsed.credentialMatched === "boolean" &&
          typeof parsed.triggerMatched === "boolean" && typeof parsed.oidcVerified === "boolean" &&
          typeof parsed.operationId === "string" && OPERATION_ID.test(parsed.operationId);
        finish({
          ok: response.statusCode === 200 && responseShapeValid,
          phase: "response",
          responseReceived: true,
          responseStatusCode: response.statusCode ?? 0,
          responseShapeValid,
          ...(responseShapeValid ? {
            responseRole: parsed.role,
            responseCredentialMatched: parsed.credentialMatched,
            responseTriggerMatched: parsed.triggerMatched,
            responseOidcVerified: parsed.oidcVerified,
            responseOperationId: parsed.operationId,
          } : {}),
          timedOut: false,
        });
        body = undefined;
      });
    });
    request.once("socket", (socket) => {
      socket.once("connect", () => { tcpConnected = true; actualConnections = 1; });
      socket.once("secureConnect", () => {
        tlsEstablished = true;
        tlsAuthorized = socket.authorized === true;
        actualRequests = 1;
      });
    });
    request.once("timeout", () => request.destroy(Object.assign(new Error("timeout"), { code: "ETIMEDOUT" })));
    request.once("error", (error) => {
      const facts = errorFacts(error);
      finish({
        ok: false,
        phase: facts.code === "ETIMEDOUT" ? "timeout" : "network-error",
        responseReceived: false,
        responseShapeValid: false,
        timedOut: facts.code === "ETIMEDOUT",
        errorCode: facts.code,
        ...(facts.syscall ? { errorSyscall: facts.syscall } : {}),
        ...(facts.errno !== undefined ? { errorErrno: facts.errno } : {}),
        ...(facts.errorClass ? { errorClass: facts.errorClass } : {}),
      });
    });
    request.end();
  });
}

async function cli() {
  const encoded = process.argv[2];
  if (!encoded || process.argv.length !== 3) throw new Error("one encoded configuration is required");
  const decoded = Buffer.from(encoded, "base64url").toString("utf8");
  if (SECRET_SHAPE.test(decoded)) throw new Error("hidden material in guest argv");
  const configuration = JSON.parse(decoded);
  process.stdout.write(`${JSON.stringify(await runProbe(configuration))}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  cli().catch(() => {
    process.stdout.write(`${JSON.stringify({
      schemaVersion: 1, testId: TEST_ID, ok: false, phase: "configuration-error",
      responseBodyRetained: false, rawConfigurationRetained: false,
    })}\n`);
  });
}
