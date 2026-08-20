import https from "node:https";

const SCOPE = "researcher-controlled-sbx048-origin-only";
const TEST_ID = "SBX-048-OIDC-CONTROL-PLANE-CONFUSION";
const CASE_ID = "brokered-control-plane-probe";
const MAX_BODY_BYTES = 8_192;
const MAX_TIMEOUT_MS = 15_000;
const OPERATION_ID = /^oid48_[A-Za-z0-9_-]{24}$/u;
const PLATFORM_TRUST_ENVIRONMENT_NAMES = [
  "NODE_EXTRA_CA_CERTS",
  "NODE_USE_SYSTEM_CA",
  "OPENSSL_CONF",
  "OPENSSL_MODULES",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
];

function inheritedPlatformTrustEnvironmentNames() {
  return PLATFORM_TRUST_ENVIRONMENT_NAMES.filter((name) => process.env[name] !== undefined).sort();
}

function record(value, name) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${name} must be an object`);
  return value;
}

function text(value, name, maximum = 2_048) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[\0\r\n]/u.test(value)) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

export function validateConfiguration(input) {
  const value = record(input, "configuration");
  const expectedKeys = [
    "caseId", "correlationCanary", "expectedMode", "publicOrigin", "runId", "scopeConfirmation", "sourcePath",
    "testId", "timeoutMs",
  ].sort();
  const actualKeys = Object.keys(value).sort();
  if (actualKeys.length !== expectedKeys.length || actualKeys.some((entry, index) => entry !== expectedKeys[index])) {
    throw new Error("configuration fields are not exact");
  }
  if (value.scopeConfirmation !== SCOPE) throw new Error(`scopeConfirmation must equal ${SCOPE}`);
  if (value.testId !== TEST_ID || value.caseId !== CASE_ID) throw new Error("test or case identity mismatch");
  if (value.expectedMode !== "direct" && value.expectedMode !== "forward") throw new Error("expectedMode is invalid");
  const publicOrigin = new URL(text(value.publicOrigin, "publicOrigin"));
  if (
    value.publicOrigin !== publicOrigin.origin || publicOrigin.protocol !== "https:" || publicOrigin.username ||
    publicOrigin.password || publicOrigin.port || publicOrigin.pathname !== "/" || publicOrigin.search || publicOrigin.hash
  ) {
    throw new Error("publicOrigin must be one exact HTTPS origin");
  }
  const runId = text(value.runId, "runId", 64);
  const sourcePath = text(value.sourcePath, "sourcePath", 512);
  if (sourcePath !== `/v1/sbx048/source/${encodeURIComponent(runId)}`) throw new Error("sourcePath is not exact");
  const timeoutMs = value.timeoutMs;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 500 || timeoutMs > MAX_TIMEOUT_MS) throw new Error("timeoutMs is invalid");
  return {
    runId,
    testId: TEST_ID,
    caseId: CASE_ID,
    correlationCanary: text(value.correlationCanary, "correlationCanary", 128),
    expectedMode: value.expectedMode,
    publicOrigin: publicOrigin.origin,
    hostname: publicOrigin.hostname,
    sourcePath,
    timeoutMs,
  };
}

export function requestOptions(configuration) {
  return {
    hostname: configuration.hostname,
    port: 443,
    servername: configuration.hostname,
    method: "GET",
    path: configuration.sourcePath,
    headers: {
      Host: configuration.hostname,
      Connection: "close",
      "x-sbx048-run": configuration.runId,
      "x-sbx048-case": configuration.caseId,
      "x-sbx048-canary": configuration.correlationCanary,
    },
    rejectUnauthorized: true,
    agent: false,
    timeout: configuration.timeoutMs,
  };
}

export async function runProbe(input) {
  const configuration = validateConfiguration(input);
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
    throw new Error("NODE_TLS_REJECT_UNAUTHORIZED=0 is forbidden");
  }
  const startedAt = Date.now();
  return await new Promise((resolve) => {
    let settled = false;
    let tcpConnected = false;
    let tlsEstablished = false;
    let tlsAuthorized = false;
    let remoteAddress;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve({
        schemaVersion: 1,
        testId: TEST_ID,
        runId: configuration.runId,
        caseId: CASE_ID,
        expectedMode: configuration.expectedMode,
        requestCount: 1,
        maximumRequests: 1,
        retryCount: 0,
        redirectsAllowed: false,
        redirectsFollowed: 0,
        environmentProxyTrust: false,
        rejectUnauthorized: true,
        controllerConfigurableCustomTrustAccepted: false,
        inheritedPlatformTrustEnvironmentNames: inheritedPlatformTrustEnvironmentNames(),
        tcpConnected,
        tlsEstablished,
        tlsAuthorized,
        ...(remoteAddress ? { remoteAddress } : {}),
        durationMs: Date.now() - startedAt,
        rawResponseHeadersRetained: false,
        rawResponseBodyRetained: false,
        ...value,
      });
    };
    const request = https.request(requestOptions(configuration), (response) => {
      const chunks = [];
      let length = 0;
      let captured = 0;
      response.on("data", (chunk) => {
        const bytes = Buffer.from(chunk);
        length += bytes.length;
        if (captured < MAX_BODY_BYTES) {
          const part = bytes.subarray(0, MAX_BODY_BYTES - captured);
          chunks.push(part);
          captured += part.length;
        }
      });
      response.on("end", () => {
        let body;
        try {
          body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        } catch {
          body = undefined;
        }
        const operationId = typeof body?.operationId === "string" && OPERATION_ID.test(body.operationId)
          ? body.operationId
          : undefined;
        const directPassed = configuration.expectedMode === "direct" && response.statusCode === 200 &&
          body?.direct === true && operationId !== undefined;
        const forwardPassed = configuration.expectedMode === "forward" && response.statusCode === 202 &&
          body?.authenticated === true && operationId !== undefined &&
          Number.isInteger(body?.controlPlaneReadStatus) &&
          (body?.mutationStatus === null || Number.isInteger(body?.mutationStatus));
        finish({
          ok: directPassed || forwardPassed,
          responseStatus: response.statusCode ?? 0,
          responseBodyLength: length,
          responseTruncated: length > MAX_BODY_BYTES,
          ...(operationId ? { responseOperationId: operationId } : {}),
          ...(configuration.expectedMode === "forward" && Number.isInteger(body?.controlPlaneReadStatus)
            ? { controlPlaneReadStatus: body.controlPlaneReadStatus }
            : {}),
          ...(configuration.expectedMode === "forward" && (body?.mutationStatus === null || Number.isInteger(body?.mutationStatus))
            ? { mutationStatus: body.mutationStatus }
            : {}),
        });
      });
    });
    request.once("socket", (socket) => {
      socket.once("connect", () => {
        tcpConnected = true;
        remoteAddress = socket.remoteAddress;
      });
      socket.once("secureConnect", () => {
        tlsEstablished = true;
        tlsAuthorized = socket.authorized === true;
      });
    });
    request.once("timeout", () => request.destroy(Object.assign(new Error("timeout"), { code: "ETIMEDOUT" })));
    request.once("error", (error) => finish({
      ok: false,
      responseStatus: 0,
      errorCode: typeof error.code === "string" ? error.code.slice(0, 64) : "ERR_REQUEST",
    }));
    request.end();
  });
}

async function cli() {
  const encoded = process.argv[2];
  if (!encoded) throw new Error("one base64url configuration argument is required");
  const configuration = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  process.stdout.write(`${JSON.stringify(await runProbe(configuration))}\n`);
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  cli().catch((error) => {
    process.stdout.write(`${JSON.stringify({
      schemaVersion: 1,
      testId: TEST_ID,
      ok: false,
      errorCode: "ERR_CONFIGURATION",
      errorMessage: String(error instanceof Error ? error.message : error).slice(0, 256),
      rawResponseHeadersRetained: false,
      rawResponseBodyRetained: false,
    })}\n`);
  });
}
