import https from "node:https";
import { isIP } from "node:net";
import { pathToFileURL } from "node:url";

const TEST_ID = "SBX-057-WILDCARD-EMPTY-ISOLATION";
const CASES = new Set(["comparator-a", "comparator-b", "target-a", "target-b"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANARY = /^s57_[a-z-]+_[A-Za-z0-9_-]{22}$/u;
const RECEIPT = /^s57rcpt_[A-Za-z0-9_-]{43}$/u;
const OPERATION = /^s57op_[A-Za-z0-9_-]{43}$/u;
const TRUST_NAMES = [
  "NODE_EXTRA_CA_CERTS",
  "NODE_USE_SYSTEM_CA",
  "OPENSSL_CONF",
  "OPENSSL_MODULES",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
];
const MAX_BODY = 1_024;
const TIMEOUT_MS = 20_000;

function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value : undefined;
}

function exactKeys(value, expected) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

export function validateConfiguration(value) {
  const root = object(value);
  if (!root || !exactKeys(root, ["schemaVersion", "testId", "runId", "caseId", "canary", "origin"]) ||
      root.schemaVersion !== 1 || root.testId !== TEST_ID || typeof root.runId !== "string" ||
      !UUID.test(root.runId) || typeof root.caseId !== "string" || !CASES.has(root.caseId) ||
      typeof root.canary !== "string" || !CANARY.test(root.canary) || typeof root.origin !== "string") {
    throw new Error("SBX-057 probe configuration was not exact");
  }
  const origin = new URL(root.origin);
  if (origin.origin !== root.origin || origin.protocol !== "https:" || origin.port !== "" ||
      origin.username !== "" || origin.password !== "" || origin.pathname !== "/" ||
      origin.search !== "" || origin.hash !== "" || origin.hostname !== origin.hostname.toLowerCase() ||
      origin.hostname.endsWith(".") || !origin.hostname.endsWith(".trycloudflare.com") ||
      isIP(origin.hostname) !== 0) throw new Error("SBX-057 probe origin was not canonical");
  const role = root.caseId.endsWith("-a") ? "A" : "B";
  return { ...root, origin, role };
}

function trustEnvironmentNames(environment) {
  if (environment.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
    throw new Error("SBX-057 refuses NODE_TLS_REJECT_UNAUTHORIZED=0");
  }
  if (environment.NODE_OPTIONS) throw new Error("SBX-057 refuses NODE_OPTIONS");
  if (process.execArgv.length !== 0) throw new Error("SBX-057 refuses runtime execArgv injection");
  return TRUST_NAMES.filter((name) => environment[name] !== undefined).sort();
}

function exactResponse(body, expectedRole, statusCode) {
  const root = object(JSON.parse(body));
  const operationExpected = statusCode === 200;
  const keys = operationExpected ? ["ok", "role", "receipt", "operationId"] : ["ok", "role", "receipt"];
  if (!root || !exactKeys(root, keys) || root.ok !== (statusCode === 200 || statusCode === 202) ||
      root.role !== expectedRole || typeof root.receipt !== "string" || !RECEIPT.test(root.receipt) ||
      (operationExpected && (typeof root.operationId !== "string" || !OPERATION.test(root.operationId))) ||
      (!operationExpected && root.operationId !== undefined)) {
    throw new Error("SBX-057 response body was not exact");
  }
  return {
    responseShapeValid: true,
    responseRole: root.role,
    responseReceipt: root.receipt,
    ...(operationExpected ? { responseOperationId: root.operationId } : {}),
  };
}

export async function requestOnce(configuration, environment = process.env) {
  const config = validateConfiguration(configuration);
  const inheritedPlatformTrustEnvironmentNames = trustEnvironmentNames(environment);
  const pathname = `/v1/sbx057/probe/${config.runId}/${config.caseId}`;
  const startedAt = Date.now();
  let connectionAttempts = 0;
  let actualConnections = 0;
  let actualRequests = 0;
  let tcpConnected = false;
  let tlsEstablished = false;
  let tlsAuthorized = false;
  return await new Promise((resolve) => {
    let settled = false;
    let request;
    const absoluteDeadline = setTimeout(() => {
      request?.destroy(Object.assign(new Error("absolute-timeout"), { code: "ETIMEDOUT" }));
    }, TIMEOUT_MS);
    absoluteDeadline.unref();
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(absoluteDeadline);
      resolve({
        schemaVersion: 1,
        testId: TEST_ID,
        runId: config.runId,
        caseId: config.caseId,
        canary: config.canary,
        ok: value.ok,
        requestHostname: config.origin.hostname,
        requestServername: config.origin.hostname,
        requestHostHeader: config.origin.hostname,
        requestPath: pathname,
        connectionAttempts,
        actualConnections,
        actualRequests,
        retries: 0,
        redirectsFollowed: 0,
        rejectUnauthorized: true,
        controllerConfigurableCustomTrustAccepted: false,
        inheritedPlatformTrustEnvironmentNames,
        tcpConnected,
        tlsEstablished,
        tlsAuthorized,
        responseReceived: value.responseReceived === true,
        ...(value.responseStatusCode === undefined ? {} : { responseStatusCode: value.responseStatusCode }),
        responseShapeValid: value.responseShapeValid === true,
        ...(value.responseRole === undefined ? {} : { responseRole: value.responseRole }),
        ...(value.responseReceipt === undefined ? {} : { responseReceipt: value.responseReceipt }),
        ...(value.responseOperationId === undefined ? {} : { responseOperationId: value.responseOperationId }),
        responseBodyRetained: false,
        durationMs: Date.now() - startedAt,
        ...(value.errorCode === undefined ? {} : { errorCode: value.errorCode }),
      });
    };
    connectionAttempts = 1;
    request = https.request({
      protocol: "https:",
      hostname: config.origin.hostname,
      port: 443,
      servername: config.origin.hostname,
      method: "GET",
      path: pathname,
      headers: {
        host: config.origin.hostname,
        "x-sbx057-run": config.runId,
        "x-sbx057-case": config.caseId,
        "x-sbx057-canary": config.canary,
        connection: "close",
      },
      agent: false,
      rejectUnauthorized: true,
      timeout: TIMEOUT_MS,
    }, (response) => {
      const chunks = [];
      let length = 0;
      response.on("data", (chunk) => {
        const bytes = Buffer.from(chunk);
        length += bytes.length;
        if (length > MAX_BODY) {
          request.destroy(Object.assign(new Error("response-too-large"), { code: "ERESPONSETOOLARGE" }));
          return;
        }
        chunks.push(bytes);
      });
      response.on("end", () => {
        try {
          const statusCode = response.statusCode ?? 0;
          const shape = exactResponse(Buffer.concat(chunks).toString("utf8"), config.role, statusCode);
          finish({ ok: statusCode === 200 || statusCode === 202, responseReceived: true, responseStatusCode: statusCode, ...shape });
        } catch (error) {
          finish({ ok: false, responseReceived: true, responseStatusCode: response.statusCode ?? 0,
            errorCode: error instanceof Error ? error.message : "invalid-response" });
        }
      });
      response.on("aborted", () => finish({ ok: false, responseReceived: true, errorCode: "ERESPONSEABORTED" }));
      response.on("close", () => {
        if (!response.complete) finish({ ok: false, responseReceived: true, errorCode: "ERESPONSEPREMATURECLOSE" });
      });
      response.on("error", (error) => finish({ ok: false, responseReceived: true,
        errorCode: typeof error.code === "string" ? error.code : "ERESPONSE" }));
    });
    request.on("socket", (socket) => {
      actualConnections += 1;
      socket.once("connect", () => { tcpConnected = true; });
      socket.once("secureConnect", () => {
        tlsEstablished = true;
        tlsAuthorized = socket.authorized === true;
      });
    });
    request.on("finish", () => { actualRequests = 1; });
    request.on("timeout", () => request.destroy(Object.assign(new Error("timeout"), { code: "ETIMEDOUT" })));
    request.on("error", (error) => finish({ ok: false, responseReceived: false,
      errorCode: typeof error.code === "string" ? error.code : "EREQUEST" }));
    request.end();
  });
}

async function main() {
  if (process.argv.length !== 3) throw new Error("SBX-057 probe requires one encoded configuration");
  const decoded = JSON.parse(Buffer.from(process.argv[2], "base64url").toString("utf8"));
  const result = await requestOnce(decoded);
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!result.ok) process.exitCode = 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stdout.write(`${JSON.stringify({
      schemaVersion: 1,
      testId: TEST_ID,
      ok: false,
      errorCode: error instanceof Error ? error.message : "probe-failed",
    })}\n`);
    process.exitCode = 1;
  });
}
