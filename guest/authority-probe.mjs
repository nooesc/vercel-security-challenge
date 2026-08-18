import https from "node:https";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";

const SCOPE_CONFIRMATION = "researcher-controlled-endpoints-only";
const DEFAULT_EVIDENCE_HEADERS = [
  "x-sbx-observer-event-id",
  "x-sbx-observed-host",
  "x-sbx-observed-vhost",
  "x-sbx-observed-sni",
];
const FORBIDDEN_TLS_OPTIONS = new Set([
  "ca",
  "cert",
  "checkServerIdentity",
  "key",
  "rejectUnauthorized",
]);
const HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const METHOD = HEADER_NAME;

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

function canonicalHost(value, field) {
  const host = requireString(value, field);
  if (isIP(host)) return host.toLowerCase();
  if (host.startsWith("[") && host.endsWith("]") && isIP(host.slice(1, -1)) === 6) {
    return host.slice(1, -1).toLowerCase();
  }
  if (host.includes(":")) throw new Error(`${field} must not include a port`);
  const ascii = domainToASCII(host);
  if (!ascii || ascii.includes(":")) throw new Error(`${field} is not a valid hostname or IP address`);
  return ascii.toLowerCase();
}

function authorityHostname(value, field) {
  const authority = requireString(value, field);
  if (authority.includes("@") || authority.includes("/") || authority.includes("?") || authority.includes("#")) {
    throw new Error(`${field} must contain only a host and optional port`);
  }
  let parsed;
  try {
    parsed = new URL(`https://${authority}/`);
  } catch {
    throw new Error(`${field} is not a valid HTTP authority`);
  }
  if (!parsed.hostname) throw new Error(`${field} is not a valid HTTP authority`);
  return canonicalHost(parsed.hostname, field);
}

function validateHeaderValue(value, field) {
  const values = Array.isArray(value) ? value : [value];
  if (values.length === 0) throw new Error(`${field} must not be an empty array`);
  for (const item of values) requireString(item, field);
  return value;
}

export function validateAuthorityProbeConfig(input) {
  const config = requireRecord(input, "configuration");
  for (const option of FORBIDDEN_TLS_OPTIONS) {
    if (Object.hasOwn(config, option)) {
      throw new Error(`${option} cannot be configured; live TLS verification is mandatory`);
    }
  }

  if (config.scopeConfirmation !== SCOPE_CONFIRMATION) {
    throw new Error(`scopeConfirmation must equal ${JSON.stringify(SCOPE_CONFIRMATION)}`);
  }

  const destinationHost = requireString(config.destinationHost, "destinationHost");
  const destinationIdentity = canonicalHost(destinationHost, "destinationHost");
  const destinationPort = config.destinationPort ?? 443;
  if (!Number.isInteger(destinationPort) || destinationPort < 1 || destinationPort > 65_535) {
    throw new Error("destinationPort must be an integer from 1 through 65535");
  }

  const tlsServername = requireString(config.tlsServername, "tlsServername");
  if (isIP(tlsServername) !== 0) throw new Error("tlsServername must be a DNS hostname, not an IP address");
  const tlsIdentity = canonicalHost(tlsServername, "tlsServername");
  const httpHost = requireString(config.httpHost, "httpHost");
  const httpIdentity = authorityHostname(httpHost, "httpHost");

  const requestTarget = requireString(config.requestTarget, "requestTarget");
  if (!requestTarget.startsWith("/") && !/^https?:\/\//iu.test(requestTarget)) {
    throw new Error("requestTarget must be origin-form or an HTTP(S) absolute-form target");
  }
  if (/\s/u.test(requestTarget)) throw new Error("requestTarget must not contain whitespace");
  let requestTargetIdentity;
  if (/^https?:\/\//iu.test(requestTarget)) {
    let target;
    try {
      target = new URL(requestTarget);
    } catch {
      throw new Error("requestTarget is not a valid HTTP(S) absolute-form target");
    }
    if (target.username || target.password || target.hash) {
      throw new Error("an absolute-form requestTarget must not contain credentials or a fragment");
    }
    requestTargetIdentity = canonicalHost(target.hostname, "requestTarget authority");
  }

  const method = config.method ?? "GET";
  if (typeof method !== "string" || !METHOD.test(method)) throw new Error("method is not a valid HTTP token");

  const headersInput = config.headers ?? {};
  const headers = requireRecord(headersInput, "headers");
  const normalizedHeaders = {};
  for (const [name, value] of Object.entries(headers)) {
    if (!HEADER_NAME.test(name)) throw new Error(`headers.${name} is not a valid header name`);
    if (name.toLowerCase() === "host") {
      throw new Error("headers must not include Host; use the dedicated httpHost field");
    }
    normalizedHeaders[name] = validateHeaderValue(value, `headers.${name}`);
  }

  const timeoutMs = config.timeoutMs ?? 5_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) {
    throw new Error("timeoutMs must be an integer from 100 through 30000");
  }
  const maxResponseBodyBytes = config.maxResponseBodyBytes ?? 4_096;
  if (!Number.isInteger(maxResponseBodyBytes) || maxResponseBodyBytes < 0 || maxResponseBodyBytes > 65_536) {
    throw new Error("maxResponseBodyBytes must be an integer from 0 through 65536");
  }

  if (!Array.isArray(config.researcherControlledHosts) || config.researcherControlledHosts.length === 0) {
    throw new Error("researcherControlledHosts must be a non-empty array");
  }
  const controlledHosts = new Set(
    config.researcherControlledHosts.map((host, index) =>
      canonicalHost(host, `researcherControlledHosts[${index}]`),
    ),
  );
  for (const [field, identity] of [
    ["destinationHost", destinationIdentity],
    ["tlsServername", tlsIdentity],
    ["httpHost", httpIdentity],
    ...(requestTargetIdentity ? [["requestTarget authority", requestTargetIdentity]] : []),
  ]) {
    if (!controlledHosts.has(identity)) {
      throw new Error(`${field} is not listed in researcherControlledHosts`);
    }
  }

  const evidenceHeaderNames = config.evidenceHeaderNames ?? DEFAULT_EVIDENCE_HEADERS;
  if (!Array.isArray(evidenceHeaderNames)) throw new Error("evidenceHeaderNames must be an array");
  const normalizedEvidenceHeaderNames = evidenceHeaderNames.map((name, index) => {
    if (typeof name !== "string" || !HEADER_NAME.test(name)) {
      throw new Error(`evidenceHeaderNames[${index}] is not a valid header name`);
    }
    return name.toLowerCase();
  });

  return {
    runId: requireString(config.runId, "runId"),
    testId: requireString(config.testId, "testId"),
    caseId: requireString(config.caseId, "caseId"),
    destinationHost,
    destinationPort,
    tlsServername,
    httpHost,
    requestTarget,
    method,
    headers: normalizedHeaders,
    timeoutMs,
    maxResponseBodyBytes,
    evidenceHeaderNames: normalizedEvidenceHeaderNames,
  };
}

export function buildAuthorityRequestOptions(config) {
  return {
    hostname: config.destinationHost,
    port: config.destinationPort,
    servername: config.tlsServername,
    method: config.method,
    path: config.requestTarget,
    headers: { ...config.headers, Host: config.httpHost },
    timeout: config.timeoutMs,
    rejectUnauthorized: true,
    agent: false,
  };
}

function plan(config) {
  const options = buildAuthorityRequestOptions(config);
  return {
    ok: true,
    mode: "plan",
    runId: config.runId,
    testId: config.testId,
    caseId: config.caseId,
    requestOptions: {
      hostname: options.hostname,
      port: options.port,
      servername: options.servername,
      method: options.method,
      path: options.path,
      headers: Object.fromEntries(
        Object.keys(options.headers).map((name) => [name, name.toLowerCase() === "host" ? options.headers[name] : "<redacted>"]),
      ),
      timeout: options.timeout,
      rejectUnauthorized: options.rejectUnauthorized,
      agent: options.agent,
    },
  };
}

function selectedHeaders(headers, names) {
  return Object.fromEntries(names.filter((name) => headers[name] !== undefined).map((name) => [name, headers[name]]));
}

function peerCertificateMetadata(socket) {
  const certificate = socket.getPeerCertificate();
  if (!certificate || Object.keys(certificate).length === 0) return undefined;
  return {
    subject: certificate.subject,
    issuer: certificate.issuer,
    validFrom: certificate.valid_from,
    validTo: certificate.valid_to,
    fingerprint256: certificate.fingerprint256,
  };
}

export async function runAuthorityProbe(config) {
  const options = buildAuthorityRequestOptions(config);
  const startedAt = Date.now();
  const transport = {
    destinationHost: config.destinationHost,
    destinationPort: config.destinationPort,
    tlsServername: config.tlsServername,
  };

  return await new Promise((resolve) => {
    const request = https.request(options, (response) => {
      const chunks = [];
      let bodyLength = 0;
      let capturedLength = 0;
      response.on("data", (chunk) => {
        const buffer = Buffer.from(chunk);
        bodyLength += buffer.length;
        const remaining = config.maxResponseBodyBytes - capturedLength;
        if (remaining > 0) {
          const captured = buffer.subarray(0, remaining);
          chunks.push(captured);
          capturedLength += captured.length;
        }
      });
      response.on("end", () => {
        resolve({
          ok: true,
          phase: "response",
          runId: config.runId,
          testId: config.testId,
          caseId: config.caseId,
          authority: {
            destinationHost: config.destinationHost,
            destinationPort: config.destinationPort,
            tlsServername: config.tlsServername,
            httpHost: config.httpHost,
            requestTarget: config.requestTarget,
          },
          transport,
          response: {
            statusCode: response.statusCode,
            statusMessage: response.statusMessage,
            evidenceHeaders: selectedHeaders(response.headers, config.evidenceHeaderNames),
            bodyLength,
            body: Buffer.concat(chunks).toString("utf8"),
            truncated: capturedLength < bodyLength,
          },
          durationMs: Date.now() - startedAt,
        });
      });
    });

    request.on("socket", (socket) => {
      socket.once("lookup", (error, address, family) => {
        transport.lookup = error
          ? { error: error.message }
          : { address, family };
      });
      socket.once("secureConnect", () => {
        const cipher = socket.getCipher();
        transport.tls = {
          authorized: socket.authorized,
          authorizationError: socket.authorizationError ?? undefined,
          alpnProtocol: socket.alpnProtocol || undefined,
          protocol: socket.getProtocol() ?? undefined,
          cipher: cipher ? { name: cipher.name, version: cipher.version } : undefined,
          peerCertificate: peerCertificateMetadata(socket),
        };
        transport.remoteAddress = socket.remoteAddress;
        transport.remotePort = socket.remotePort;
      });
    });
    request.on("timeout", () => request.destroy(new Error("request timed out")));
    request.on("error", (error) => {
      resolve({
        ok: false,
        phase: "request",
        runId: config.runId,
        testId: config.testId,
        caseId: config.caseId,
        authority: {
          destinationHost: config.destinationHost,
          destinationPort: config.destinationPort,
          tlsServername: config.tlsServername,
          httpHost: config.httpHost,
          requestTarget: config.requestTarget,
        },
        transport,
        error: error instanceof Error ? error.message : String(error),
        durationMs: Date.now() - startedAt,
      });
    });
    request.end();
  });
}

async function main() {
  const encoded = process.argv[2];
  if (!encoded) throw new Error("missing base64url authority-probe configuration");
  const decoded = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  const config = validateAuthorityProbeConfig(decoded);
  const result = process.argv[3] === "--plan" ? plan(config) : await runAuthorityProbe(config);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1] && new URL(import.meta.url).pathname === new URL(`file://${process.argv[1]}`).pathname) {
  main().catch((error) => {
    process.stdout.write(`${JSON.stringify({
      ok: false,
      phase: "configuration",
      error: error instanceof Error ? error.message : String(error),
    })}\n`);
    process.exitCode = 2;
  });
}
