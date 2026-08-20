import https from "node:https";
import { isIP } from "node:net";
import { pathToFileURL } from "node:url";

const SCOPE = "researcher-controlled-sbx058-origins-only";
const TEST_ID = "SBX-058-HEADER-ENTRY-BINDING";
const MATCH_HEADER = "x-sbx058-route";
const DECOY_HEADER = "x-sbx058-decoy";
const RUN_HEADER = "x-sbx058-run";
const CASE_HEADER = "x-sbx058-case";
const CANARY_HEADER = "x-sbx058-canary";
const MATCH_VALUE = "privileged";
const WRONG_VALUE = "ordinary";
const MAX_BODY_BYTES = 8_192;
const MAX_TIMEOUT_MS = 15_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANARY = /^s58_[a-z-]+_[A-Za-z0-9_-]{22}$/u;
const OPERATION = /^s58op_[A-Za-z0-9_-]{43}$/u;
const RECEIPT = /^s58rcpt_[A-Za-z0-9_-]{43}$/u;
const CASES = new Set([
  "direct-p-pre", "exact-pair", "key-half", "value-half", "combined-halves", "direct-p-post",
]);
const EVENT_CASES = new Set(["exact-pair", "key-half", "value-half", "combined-halves"]);
const TRUST_ENV_NAMES = [
  "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF",
  "OPENSSL_MODULES", "SSL_CERT_DIR", "SSL_CERT_FILE",
];

function record(value, name) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value;
}

function exactKeys(value, expected) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((entry, index) => entry === wanted[index]);
}

function exactOrigin(raw) {
  const parsed = new URL(raw);
  if (raw !== parsed.origin || parsed.protocol !== "https:" || parsed.username || parsed.password ||
      parsed.port || parsed.pathname !== "/" || parsed.search || parsed.hash || isIP(parsed.hostname) !== 0 ||
      parsed.hostname !== parsed.hostname.toLowerCase()) {
    throw new Error("targetOrigin must be one canonical public HTTPS origin");
  }
  return parsed;
}

function expectedPath(runId, caseId, canary) {
  const family = EVENT_CASES.has(caseId) ? "request" : "direct";
  return `/v1/sbx058/${family}/${runId}/${caseId}?${new URLSearchParams({ canary }).toString()}`;
}

export function validateConfiguration(input) {
  const value = record(input, "configuration");
  if (!exactKeys(value, [
    "caseId", "correlationCanary", "headerMode", "requestPath", "runId", "scopeConfirmation",
    "targetOrigin", "targetRole", "testId", "timeoutMs",
  ]) || value.scopeConfirmation !== SCOPE || value.testId !== TEST_ID ||
      typeof value.runId !== "string" || !UUID.test(value.runId) ||
      typeof value.caseId !== "string" || !CASES.has(value.caseId) ||
      typeof value.correlationCanary !== "string" || !CANARY.test(value.correlationCanary) ||
      !["none", "exact-pair", "key-half", "value-half", "combined-halves"].includes(value.headerMode) ||
      value.headerMode !== (EVENT_CASES.has(value.caseId) ? value.caseId : "none") ||
      value.targetRole !== (EVENT_CASES.has(value.caseId) ? "A" : "P") ||
      !Number.isInteger(value.timeoutMs) || value.timeoutMs < 500 || value.timeoutMs > MAX_TIMEOUT_MS) {
    throw new Error("configuration fields were not exact");
  }
  const origin = exactOrigin(value.targetOrigin);
  const requestPath = expectedPath(value.runId, value.caseId, value.correlationCanary);
  if (value.requestPath !== requestPath) throw new Error("requestPath was not exact");
  return {
    testId: TEST_ID,
    runId: value.runId,
    caseId: value.caseId,
    correlationCanary: value.correlationCanary,
    headerMode: value.headerMode,
    targetRole: value.targetRole,
    targetOrigin: origin.origin,
    hostname: origin.hostname,
    requestPath,
    timeoutMs: value.timeoutMs,
  };
}

function matcherHeaders(mode) {
  if (mode === "exact-pair") return { [MATCH_HEADER]: MATCH_VALUE };
  if (mode === "key-half") return { [MATCH_HEADER]: WRONG_VALUE };
  if (mode === "value-half") return { [DECOY_HEADER]: MATCH_VALUE };
  if (mode === "combined-halves") {
    return { [MATCH_HEADER]: WRONG_VALUE, [DECOY_HEADER]: MATCH_VALUE };
  }
  return {};
}

export function requestOptions(configuration) {
  const headers = {
    Host: configuration.hostname,
    Connection: "close",
    [RUN_HEADER]: configuration.runId,
    [CASE_HEADER]: configuration.caseId,
    [CANARY_HEADER]: configuration.correlationCanary,
    ...matcherHeaders(configuration.headerMode),
  };
  const lower = Object.keys(headers).map((entry) => entry.toLowerCase());
  if (new Set(lower).size !== lower.length || lower.includes("vercel-sandbox-oidc-token")) {
    throw new Error("forbidden or duplicate header reached request options");
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

function inheritedTrustNames() {
  return TRUST_ENV_NAMES.filter((name) => process.env[name] !== undefined).sort();
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
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0" || process.env.NODE_OPTIONS) {
    throw new Error("unsafe guest trust or runtime override");
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
        targetRole: configuration.targetRole,
        headerMode: configuration.headerMode,
        commandExitCode: 0,
        startedAt,
        completedAt: new Date().toISOString(),
        requestHostname: configuration.hostname,
        requestServername: configuration.hostname,
        requestHostHeader: configuration.hostname,
        requestPath: configuration.requestPath,
        routeHeaderSent: configuration.headerMode === "exact-pair" || configuration.headerMode === "key-half" ||
          configuration.headerMode === "combined-halves",
        decoyHeaderSent: configuration.headerMode === "value-half" || configuration.headerMode === "combined-halves",
        connectionAttempts: 1,
        actualConnections,
        actualRequests,
        retries: 0,
        redirectsFollowed: 0,
        rejectUnauthorized: true,
        controllerConfigurableCustomTrustAccepted: false,
        inheritedPlatformTrustEnvironmentNames: inheritedTrustNames(),
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
        try {
          body = received <= MAX_BODY_BYTES ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : undefined;
        } catch {
          body = undefined;
        }
        const parsed = body !== null && typeof body === "object" && !Array.isArray(body) ? body : undefined;
        const responseShapeValid = parsed !== undefined && exactKeys(parsed, [
          "caseId", "oidcVerified", "operationId", "receipt", "role", "schemaVersion", "testId",
        ]) && parsed.schemaVersion === 1 && parsed.testId === TEST_ID && parsed.caseId === configuration.caseId &&
          (parsed.role === "A" || parsed.role === "P") && typeof parsed.oidcVerified === "boolean" &&
          typeof parsed.operationId === "string" && OPERATION.test(parsed.operationId) &&
          typeof parsed.receipt === "string" && RECEIPT.test(parsed.receipt);
        finish({
          ok: response.statusCode === 200 && responseShapeValid,
          phase: "response",
          responseReceived: true,
          responseStatusCode: response.statusCode ?? 0,
          responseShapeValid,
          ...(responseShapeValid ? {
            responseRole: parsed.role,
            responseOidcVerified: parsed.oidcVerified,
            responseOperationId: parsed.operationId,
            responseReceipt: parsed.receipt,
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
  if (!process.argv[2] || process.argv.length !== 3) throw new Error("one encoded configuration is required");
  const configuration = JSON.parse(Buffer.from(process.argv[2], "base64url").toString("utf8"));
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
