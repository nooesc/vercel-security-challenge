#!/usr/bin/env node

import https from "node:https";
import { pathToFileURL } from "node:url";

const SCOPE_CONFIRMATION = "researcher-controlled-sbx044-origins-only";
const TEST_ID = "SBX-044-POC";
const MAX_BODY_BYTES = 4096;
const EXPECTED_HOST_ROLES = new Map([
  ["s44a.one.form-app.app", "allowed"],
  ["s44a.one.two.form-app.app", "denied"],
]);
const TRUST_ENV_NAMES = [
  "NODE_EXTRA_CA_CERTS",
  "NODE_USE_SYSTEM_CA",
  "OPENSSL_CONF",
  "OPENSSL_MODULES",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
];

function fail(message) {
  process.stdout.write(`${JSON.stringify({
    schemaVersion: 1,
    ok: false,
    phase: "configuration",
    error: message,
  })}\n`);
  process.exitCode = 2;
}

function decodeConfiguration(encoded) {
  if (!encoded || !/^[A-Za-z0-9_-]+$/u.test(encoded)) {
    throw new Error("expected one base64url configuration argument");
  }
  const parsed = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("configuration must be an object");
  }
  return parsed;
}

export function validateConfiguration(value) {
  if (value.scopeConfirmation !== SCOPE_CONFIRMATION) {
    throw new Error("scope confirmation mismatch");
  }
  if (value.testId !== TEST_ID) throw new Error("testId mismatch");
  if (!/^[0-9a-f-]{36}$/u.test(value.runId ?? "")) throw new Error("invalid runId");
  if (!/^[a-z0-9-]{1,64}$/u.test(value.caseId ?? "")) throw new Error("invalid caseId");
  if (!/^[A-Za-z0-9_-]{16,128}$/u.test(value.canary ?? "")) throw new Error("invalid canary");
  if (value.expectedRole !== "allowed" && value.expectedRole !== "denied") {
    throw new Error("expectedRole must be allowed or denied");
  }
  if (!Array.isArray(value.researcherControlledHosts) || value.researcherControlledHosts.length !== 2) {
    throw new Error("exactly two researcher-controlled hosts are required");
  }
  const hosts = value.researcherControlledHosts.map((entry) => {
    if (typeof entry !== "string" || entry !== entry.toLowerCase()) {
      throw new Error("controlled hosts must be lowercase strings");
    }
    return entry;
  });
  if (
    new Set(hosts).size !== 2 ||
    hosts.slice().sort().join(",") !== [...EXPECTED_HOST_ROLES.keys()].sort().join(",")
  ) throw new Error("controlled hosts must be the exact fixed SBX-044 A/B pair");
  const url = new URL(value.url);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.port ||
    url.pathname !== "/v1/sbx044/action" ||
    url.hash ||
    !hosts.includes(url.hostname)
  ) {
    throw new Error("url must be the fixed HTTPS action path on a controlled host");
  }
  if (EXPECTED_HOST_ROLES.get(url.hostname) !== value.expectedRole) {
    throw new Error("url hostname and expectedRole do not match the fixed SBX-044 role map");
  }
  if (
    url.searchParams.get("run") !== value.runId ||
    url.searchParams.get("case") !== value.caseId ||
    url.searchParams.get("canary") !== value.canary ||
    [...url.searchParams.keys()].sort().join(",") !== "canary,case,run"
  ) {
    throw new Error("url correlation parameters mismatch");
  }
  if (!Number.isInteger(value.timeoutMs) || value.timeoutMs < 1000 || value.timeoutMs > 15000) {
    throw new Error("timeoutMs must be between 1000 and 15000");
  }
  if (value.headers !== undefined || value.ca !== undefined || value.secureContext !== undefined) {
    throw new Error("controller-supplied headers or TLS trust overrides are forbidden");
  }
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
    throw new Error("NODE_TLS_REJECT_UNAUTHORIZED=0 is forbidden");
  }
  return { url, hosts };
}

function boundedJson(body) {
  let parsed;
  try {
    parsed = JSON.parse(body.toString("utf8"));
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  return parsed;
}

export async function requestOnce(configuration) {
  const { url } = validateConfiguration(configuration);
  const started = Date.now();
  const inheritedPlatformTrustEnvironmentNames = TRUST_ENV_NAMES.filter((name) => process.env[name] !== undefined);
  let tcpConnected = false;
  let tlsEstablished = false;
  let authorized = false;
  let remoteAddress;
  let remotePort;
  let alpnProtocol;
  let peerCertificateFingerprint256;

  return await new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve({
        schemaVersion: 1,
        testId: TEST_ID,
        runId: configuration.runId,
        caseId: configuration.caseId,
        correlationCanary: configuration.canary,
        ok: result.ok,
        phase: result.phase,
        durationMs: Date.now() - started,
        expectedRole: configuration.expectedRole,
        request: {
          hostname: url.hostname,
          port: 443,
          servername: url.hostname,
          method: "GET",
          path: `${url.pathname}${url.search}`,
          connectionAttempts: 1,
          actualConnections: tcpConnected ? 1 : 0,
          actualRequests: result.fields?.responseReceived === true ? 1 : 0,
          retries: 0,
          redirectsFollowed: 0,
        },
        tlsTrust: {
          rejectUnauthorized: true,
          controllerConfigurableCustomTrustAccepted: false,
          inheritedPlatformTrustEnvironmentNames,
        },
        transport: {
          tcpConnected,
          tlsEstablished,
          authorized,
          ...(remoteAddress ? { remoteAddress } : {}),
          ...(typeof remotePort === "number" ? { remotePort } : {}),
          ...(alpnProtocol ? { alpnProtocol } : {}),
          ...(peerCertificateFingerprint256 ? { peerCertificateFingerprint256 } : {}),
        },
        ...result.fields,
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
        "user-agent": "vsc-sbx044/1",
      },
    }, (response) => {
      const chunks = [];
      let length = 0;
      let truncated = false;
      response.on("data", (chunk) => {
        if (truncated) return;
        const bytes = Buffer.from(chunk);
        if (length + bytes.length > MAX_BODY_BYTES) {
          truncated = true;
          response.destroy(new Error("response body exceeded fixed cap"));
          return;
        }
        chunks.push(bytes);
        length += bytes.length;
      });
      response.on("end", () => {
        const parsed = boundedJson(Buffer.concat(chunks));
        finish({
          ok: !truncated,
          phase: "response",
          fields: {
            responseReceived: true,
            responseStatusCode: response.statusCode,
            responseBodyLength: length,
            responseBodyRetained: false,
            responseRole: parsed?.role,
            responseBrokered: parsed?.brokered,
            responseOperationId: parsed?.operationId,
          },
        });
      });
    });

    request.once("socket", (socket) => {
      socket.once("connect", () => { tcpConnected = true; });
      socket.once("secureConnect", () => {
        tlsEstablished = true;
        authorized = socket.authorized === true;
        remoteAddress = socket.remoteAddress;
        remotePort = socket.remotePort;
        alpnProtocol = socket.alpnProtocol || "http/1.1";
        const certificate = socket.getPeerCertificate();
        peerCertificateFingerprint256 = certificate?.fingerprint256;
      });
    });
    request.once("timeout", () => request.destroy(Object.assign(new Error("request timeout"), { code: "ETIMEDOUT" })));
    request.once("error", (error) => {
      finish({
        ok: false,
        phase: tlsEstablished ? "request" : "transport",
        fields: {
          responseReceived: false,
          responseBodyRetained: false,
          errorCode: typeof error.code === "string" ? error.code : "UNKNOWN",
          ...(typeof error.errno === "number" ? { errorErrno: error.errno } : {}),
          ...(typeof error.syscall === "string" ? { errorSyscall: error.syscall } : {}),
          errorMessage: typeof error.message === "string" ? error.message.slice(0, 256) : "request failed",
        },
      });
    });
    request.end();
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let configuration;
  try {
    configuration = decodeConfiguration(process.argv[2]);
    const result = await requestOnce(configuration);
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  }
}
