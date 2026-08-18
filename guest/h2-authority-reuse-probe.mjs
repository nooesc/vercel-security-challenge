import { randomBytes } from "node:crypto";
import http2 from "node:http2";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { domainToASCII, fileURLToPath } from "node:url";

const SCOPE_CONFIRMATION = "researcher-controlled-endpoints-only";
const HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const METHOD = HEADER_NAME;
const DEFAULT_EVIDENCE_HEADERS = [
  "x-sbx-observer-event-id",
  "x-sbx-observed-authority",
  "x-sbx-observed-vhost",
];
const FORBIDDEN_TLS_OPTIONS = new Set([
  "ca",
  "cert",
  "checkServerIdentity",
  "key",
  "rejectUnauthorized",
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

function parseAuthority(value, field) {
  const authority = requireString(value, field);
  if (authority.includes("@") || authority.includes("/") || authority.includes("?") || authority.includes("#")) {
    throw new Error(`${field} must contain only a host and optional port`);
  }
  let parsed;
  try {
    parsed = new URL(`https://${authority}/`);
  } catch {
    throw new Error(`${field} is not a valid HTTP/2 authority`);
  }
  const host = canonicalHost(parsed.hostname, field);
  const effectivePort = parsed.port ? Number(parsed.port) : 443;
  return { authority, host, identity: `${host}:${effectivePort}` };
}

function validateHeaders(value, field) {
  const headers = requireRecord(value ?? {}, field);
  const normalized = {};
  for (const [name, rawValue] of Object.entries(headers)) {
    if (!HEADER_NAME.test(name) || name.startsWith(":")) {
      throw new Error(`${field}.${name} is not a valid regular HTTP/2 header name`);
    }
    if (name.toLowerCase() === "host") {
      throw new Error(`${field} must not include Host; use the stream authority field`);
    }
    const values = Array.isArray(rawValue) ? rawValue : [rawValue];
    if (values.length === 0) throw new Error(`${field}.${name} must not be an empty array`);
    for (const item of values) requireString(item, `${field}.${name}`);
    normalized[name.toLowerCase()] = rawValue;
  }
  return normalized;
}

export function validateH2AuthorityReuseConfig(input) {
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
  ]) {
    if (!controlledHosts.has(identity)) throw new Error(`${field} is not listed in researcherControlledHosts`);
  }

  if (config.sequence !== "single-stream" && config.sequence !== "a-b-a-reuse") {
    throw new Error("sequence must be single-stream or a-b-a-reuse");
  }
  const expectedStreamCount = config.sequence === "single-stream" ? 1 : 3;
  if (!Array.isArray(config.streams) || config.streams.length !== expectedStreamCount) {
    throw new Error(`${config.sequence} requires exactly ${expectedStreamCount} stream(s)`);
  }
  const streams = config.streams.map((unknownStream, index) => {
    const stream = requireRecord(unknownStream, `streams[${index}]`);
    const parsedAuthority = parseAuthority(stream.authority, `streams[${index}].authority`);
    if (!controlledHosts.has(parsedAuthority.host)) {
      throw new Error(`streams[${index}].authority is not listed in researcherControlledHosts`);
    }
    const path = requireString(stream.path, `streams[${index}].path`);
    if (!path.startsWith("/") || /^\/\//u.test(path) || /\s/u.test(path)) {
      throw new Error(`streams[${index}].path must be an origin-form path without whitespace`);
    }
    const method = stream.method ?? "GET";
    if (typeof method !== "string" || !METHOD.test(method)) {
      throw new Error(`streams[${index}].method is not a valid HTTP token`);
    }
    return {
      id: requireString(stream.id, `streams[${index}].id`),
      authority: parsedAuthority.authority,
      authorityHost: parsedAuthority.host,
      authorityIdentity: parsedAuthority.identity,
      path,
      method,
      headers: validateHeaders(stream.headers, `streams[${index}].headers`),
    };
  });
  if (config.sequence === "a-b-a-reuse") {
    const expectedAIdentity = `${tlsIdentity}:${destinationPort}`;
    if (
      streams[0].authorityIdentity !== expectedAIdentity ||
      streams[2].authorityIdentity !== expectedAIdentity
    ) {
      throw new Error("a-b-a-reuse requires the first and third authorities to match TLS origin A");
    }
    if (streams[1].authorityIdentity === expectedAIdentity) {
      throw new Error("a-b-a-reuse requires a distinct authority B on the second stream");
    }
  }
  if (new Set(streams.map((stream) => stream.id)).size !== streams.length) {
    throw new Error("stream ids must be distinct");
  }

  const timeoutMs = config.timeoutMs ?? 10_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) {
    throw new Error("timeoutMs must be an integer from 100 through 30000");
  }
  const maxResponseBodyBytes = config.maxResponseBodyBytes ?? 4_096;
  if (!Number.isInteger(maxResponseBodyBytes) || maxResponseBodyBytes < 0 || maxResponseBodyBytes > 65_536) {
    throw new Error("maxResponseBodyBytes must be an integer from 0 through 65536");
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
    sequence: config.sequence,
    destinationHost,
    destinationPort,
    tlsServername,
    streams,
    timeoutMs,
    maxResponseBodyBytes,
    evidenceHeaderNames: normalizedEvidenceHeaderNames,
  };
}

function connectOrigin(config) {
  const host = isIP(config.destinationHost) === 6
    ? `[${config.destinationHost.replace(/^\[|\]$/gu, "")}]`
    : config.destinationHost;
  return `https://${host}:${config.destinationPort}`;
}

export function buildH2ConnectionPlan(config) {
  return {
    origin: connectOrigin(config),
    options: {
      servername: config.tlsServername,
      rejectUnauthorized: true,
    },
    streams: config.streams.map((stream) => ({
      id: stream.id,
      headers: {
        ":method": stream.method,
        ":scheme": "https",
        ":authority": stream.authority,
        ":path": stream.path,
        ...stream.headers,
      },
    })),
  };
}

function redactedPlan(config) {
  const connection = buildH2ConnectionPlan(config);
  return {
    ok: true,
    mode: "plan",
    runId: config.runId,
    testId: config.testId,
    caseId: config.caseId,
    sequence: config.sequence,
    connection: {
      origin: connection.origin,
      servername: connection.options.servername,
      rejectUnauthorized: connection.options.rejectUnauthorized,
    },
    streams: connection.streams.map((stream) => ({
      id: stream.id,
      headers: Object.fromEntries(
        Object.entries(stream.headers).map(([name, value]) => [
          name,
          name.startsWith(":") ? value : "<redacted>",
        ]),
      ),
    })),
  };
}

function selectedHeaders(headers, names) {
  return Object.fromEntries(
    names.filter((name) => headers[name] !== undefined).map((name) => [name, headers[name]]),
  );
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

async function runStream(session, streamConfig, config) {
  const startedAt = Date.now();
  let stream;
  try {
    stream = session.request({
      ":method": streamConfig.method,
      ":scheme": "https",
      ":authority": streamConfig.authority,
      ":path": streamConfig.path,
      ...streamConfig.headers,
    });
  } catch (error) {
    return {
      id: streamConfig.id,
      ok: false,
      phase: "open",
      authority: streamConfig.authority,
      path: streamConfig.path,
      error: error instanceof Error ? error.message : String(error),
      errorCode: typeof error?.code === "string" ? error.code : undefined,
      durationMs: Date.now() - startedAt,
    };
  }

  return await new Promise((resolveResult) => {
    let responseHeaders;
    let bodyLength = 0;
    let capturedLength = 0;
    const chunks = [];
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolveResult({
        id: streamConfig.id,
        authority: streamConfig.authority,
        path: streamConfig.path,
        durationMs: Date.now() - startedAt,
        ...result,
      });
    };
    stream.setTimeout(config.timeoutMs, () => stream.close(http2.constants.NGHTTP2_CANCEL));
    stream.on("response", (headers) => {
      responseHeaders = headers;
    });
    stream.on("data", (chunk) => {
      const buffer = Buffer.from(chunk);
      bodyLength += buffer.length;
      const remaining = config.maxResponseBodyBytes - capturedLength;
      if (remaining > 0) {
        const captured = buffer.subarray(0, remaining);
        chunks.push(captured);
        capturedLength += captured.length;
      }
    });
    stream.on("end", () => {
      finish({
        ok: true,
        phase: "response",
        statusCode: responseHeaders?.[":status"],
        evidenceHeaders: selectedHeaders(responseHeaders ?? {}, config.evidenceHeaderNames),
        bodyLength,
        body: Buffer.concat(chunks).toString("utf8"),
        truncated: capturedLength < bodyLength,
        rstCode: stream.rstCode,
      });
    });
    stream.on("aborted", () => finish({ ok: false, phase: "stream", error: "stream aborted" }));
    stream.on("error", (error) => finish({
      ok: false,
      phase: "stream",
      error: error instanceof Error ? error.message : String(error),
      errorCode: typeof error?.code === "string" ? error.code : undefined,
      rstCode: stream.rstCode,
    }));
    stream.on("close", () => finish({
      ok: false,
      phase: "stream",
      error: "stream closed before the response completed",
      rstCode: stream.rstCode,
    }));
    stream.end();
  });
}

async function closeSession(session) {
  if (session.closed || session.destroyed) return;
  await new Promise((resolveClose) => {
    const timeout = setTimeout(() => {
      session.destroy();
      resolveClose();
    }, 1_000);
    session.once("close", () => {
      clearTimeout(timeout);
      resolveClose();
    });
    session.close();
  });
}

export async function runH2AuthorityReuseProbe(config) {
  const startedAt = Date.now();
  const sessionCorrelation = `h2sess_${randomBytes(12).toString("base64url")}`;
  const connection = buildH2ConnectionPlan(config);
  const session = http2.connect(connection.origin, connection.options);
  const goawayEvents = [];
  session.on("goaway", (errorCode, lastStreamID, opaqueData) => {
    goawayEvents.push({
      errorCode,
      lastStreamID,
      opaqueDataBase64: opaqueData?.length ? opaqueData.toString("base64") : undefined,
    });
  });
  session.setTimeout(config.timeoutMs, () => session.destroy(new Error("HTTP/2 session timed out")));

  try {
    await new Promise((resolveConnect, rejectConnect) => {
      session.once("connect", resolveConnect);
      session.once("error", rejectConnect);
    });
    const socket = session.socket;
    if (!socket || socket.alpnProtocol !== "h2") {
      throw new Error(`expected ALPN h2, received ${socket?.alpnProtocol || "none"}`);
    }
    const cipher = socket.getCipher();
    const transport = {
      sessionCorrelation,
      origin: connection.origin,
      destinationHost: config.destinationHost,
      destinationPort: config.destinationPort,
      tlsServername: config.tlsServername,
      remoteAddress: socket.remoteAddress,
      remotePort: socket.remotePort,
      tls: {
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ?? undefined,
        alpnProtocol: socket.alpnProtocol,
        protocol: socket.getProtocol() ?? undefined,
        cipher: cipher ? { name: cipher.name, version: cipher.version } : undefined,
        peerCertificate: peerCertificateMetadata(socket),
      },
    };
    const results = [];
    for (const streamConfig of config.streams) {
      results.push(await runStream(session, streamConfig, config));
    }
    return {
      ok: true,
      phase: "complete",
      runId: config.runId,
      testId: config.testId,
      caseId: config.caseId,
      transport,
      streams: results,
      goawayEvents,
      durationMs: Date.now() - startedAt,
    };
  } catch (error) {
    return {
      ok: false,
      phase: "session",
      runId: config.runId,
      testId: config.testId,
      caseId: config.caseId,
      sessionCorrelation,
      error: error instanceof Error ? error.message : String(error),
      errorCode: typeof error?.code === "string" ? error.code : undefined,
      goawayEvents,
      durationMs: Date.now() - startedAt,
    };
  } finally {
    await closeSession(session);
  }
}

async function main() {
  const encoded = process.argv[2];
  if (!encoded) throw new Error("missing base64url HTTP/2 authority-reuse configuration");
  const decoded = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  const config = validateH2AuthorityReuseConfig(decoded);
  const result = process.argv[3] === "--plan"
    ? redactedPlan(config)
    : await runH2AuthorityReuseProbe(config);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch((error) => {
    process.stdout.write(`${JSON.stringify({
      ok: false,
      phase: "configuration",
      error: error instanceof Error ? error.message : String(error),
    })}\n`);
    process.exitCode = 2;
  });
}
