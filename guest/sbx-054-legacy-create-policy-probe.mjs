import { constants } from "node:fs";
import { open, unlink } from "node:fs/promises";
import https from "node:https";
import { isIP } from "node:net";

const TEST_ID = "SBX-054";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANARY = /^c54_[A-Za-z0-9_-]{43}$/u;
const CASES = new Set([
  "v3-deny-comparator",
  "v2-runtime-deny-target",
  "v3-deny-comparator-post",
  "v2-runtime-secret",
]);
const DIGEST = /^[0-9a-f]{64}$/u;
const MAX_RESPONSE_BYTES = 1_024;
const MAX_SECRET_BYTES = 256;
const INHERITED_PLATFORM_TRUST_ENVIRONMENT_NAMES = Object.freeze([
  "NODE_EXTRA_CA_CERTS",
  "NODE_USE_SYSTEM_CA",
  "SSL_CERT_FILE",
]);
const UNKNOWN_TRUST_ENVIRONMENT_NAMES = Object.freeze([
  "OPENSSL_CONF",
  "OPENSSL_MODULES",
  "SSL_CERT_DIR",
]);

function fail(message) {
  process.stderr.write(`SBX-054 guest input error: ${message}\n`);
  process.exit(2);
}

function exactOrigin(raw) {
  let value;
  try {
    value = new URL(raw);
  } catch {
    fail("origin is not a URL");
  }
  if (raw !== value.origin || value.protocol !== "https:" || value.port !== "" ||
      value.username !== "" || value.password !== "" || value.pathname !== "/" ||
      value.search !== "" || value.hash !== "" || value.hostname !== value.hostname.toLowerCase() ||
      value.hostname.endsWith(".") || isIP(value.hostname) !== 0) {
    fail("origin is not one exact canonical public HTTPS hostname origin");
  }
  return value;
}

function safeError(error) {
  const root = error && typeof error === "object" ? error : {};
  const cause = root.cause && typeof root.cause === "object" ? root.cause : {};
  const safe = (value) => typeof value === "string" && value.length <= 80 ? value : null;
  return {
    name: safe(root.name) ?? "Error",
    code: safe(cause.code) ?? safe(root.code),
    syscall: safe(cause.syscall) ?? safe(root.syscall),
    errno: Number.isSafeInteger(cause.errno) ? cause.errno :
      Number.isSafeInteger(root.errno) ? root.errno : null,
  };
}

function exactResponse(bytes, kind) {
  if (bytes.byteLength > MAX_RESPONSE_BYTES) throw new Error("response exceeded byte ceiling");
  const text = bytes.toString("utf8");
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("response was not JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed) ||
      Object.keys(parsed).sort().join(",") !== "operationId,receipt,secretProof" ||
      typeof parsed.receipt !== "string" || !DIGEST.test(parsed.receipt) ||
      !(parsed.secretProof === null || (typeof parsed.secretProof === "string" && DIGEST.test(parsed.secretProof))) ||
      !(parsed.operationId === null || (typeof parsed.operationId === "string" && DIGEST.test(parsed.operationId))) ||
      (kind === "public" && (parsed.secretProof !== null || parsed.operationId !== null)) ||
      (kind === "secret" && (parsed.secretProof === null || parsed.operationId === null))) {
    throw new Error("response fields were not exact");
  }
  return parsed;
}

async function readAndRemoveSecret(path) {
  const noFollow = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
  const handle = await open(path, constants.O_RDONLY | noFollow);
  try {
    const metadata = await handle.stat();
    const mode = metadata.mode & 0o777;
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || mode !== 0o600 ||
        metadata.size < 32 || metadata.size > MAX_SECRET_BYTES) {
      throw new Error("secret file was not an exact bounded mode-0600 single-link regular file");
    }
    const bytes = await handle.readFile();
    if (bytes.byteLength !== metadata.size) {
      bytes.fill(0);
      throw new Error("secret file changed while reading");
    }
    await unlink(path);
    return { bytes, mode };
  } finally {
    await handle.close();
  }
}

async function oneRequest(url, kind, body) {
  let connectionAttempts = 0;
  let tlsAuthorized = false;
  return await new Promise((resolve) => {
    const request = https.request(url, {
      method: kind === "public" ? "GET" : "POST",
      agent: false,
      rejectUnauthorized: true,
      servername: url.hostname,
      headers: kind === "public" ? {
        "cache-control": "no-store",
      } : {
        "cache-control": "no-store",
        "content-type": "application/octet-stream",
        "content-length": String(body.byteLength),
      },
    });
    const timer = setTimeout(() => request.destroy(Object.assign(new Error("request timeout"), {
      code: "ETIMEDOUT",
      syscall: "connect",
    })), 5_000);
    request.once("socket", (socket) => {
      connectionAttempts += 1;
      socket.once("secureConnect", () => {
        tlsAuthorized = socket.authorized === true;
      });
    });
    request.once("response", (response) => {
      const chunks = [];
      let total = 0;
      response.on("data", (chunk) => {
        const bytes = Buffer.from(chunk);
        total += bytes.byteLength;
        if (total > MAX_RESPONSE_BYTES) {
          bytes.fill(0);
          request.destroy(new Error("response exceeded byte ceiling"));
          return;
        }
        chunks.push(bytes);
      });
      response.once("end", () => {
        clearTimeout(timer);
        const bytes = Buffer.concat(chunks, total);
        try {
          const parsed = exactResponse(bytes, kind);
          resolve({
            connectionAttempts,
            tlsAuthorized,
            receivedResponse: true,
            statusCode: response.statusCode ?? null,
            receipt: parsed.receipt,
            secretProof: parsed.secretProof,
            operationId: parsed.operationId,
            error: null,
          });
        } catch (error) {
          resolve({
            connectionAttempts,
            tlsAuthorized,
            receivedResponse: false,
            statusCode: null,
            receipt: null,
            secretProof: null,
            operationId: null,
            error: safeError(error),
          });
        } finally {
          bytes.fill(0);
          for (const chunk of chunks) chunk.fill(0);
        }
      });
    });
    request.once("error", (error) => {
      clearTimeout(timer);
      resolve({
        connectionAttempts,
        tlsAuthorized: false,
        receivedResponse: false,
        statusCode: null,
        receipt: null,
        secretProof: null,
        operationId: null,
        error: safeError(error),
      });
    });
    if (body !== undefined) request.end(body);
    else request.end();
  });
}

const inheritedPlatformTrustEnvironmentNames = INHERITED_PLATFORM_TRUST_ENVIRONMENT_NAMES.filter(
  (name) => typeof process.env[name] === "string" && process.env[name].length > 0,
);
const unknownTrustEnvironmentNames = UNKNOWN_TRUST_ENVIRONMENT_NAMES.filter(
  (name) => typeof process.env[name] === "string" && process.env[name].length > 0,
);
if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
  fail("NODE_TLS_REJECT_UNAUTHORIZED=0 is forbidden");
}
if (unknownTrustEnvironmentNames.length > 0) {
  fail("an unknown inherited trust environment name was present");
}
if (process.env.NODE_OPTIONS !== undefined && process.env.NODE_OPTIONS.trim() !== "") {
  fail("NODE_OPTIONS is forbidden");
}
const runtimeInjectionOption =
  /^(?:-r|--require|--import|--loader|--experimental-loader|--use-openssl-ca|--use-system-ca|--openssl-config)(?:=|$)/u;
if (process.execArgv.some((argument) => runtimeInjectionOption.test(argument))) {
  fail("trust-store or runtime-injection Node options are forbidden");
}

const [kindRaw, originRaw, runId, caseId, canary, secretPath, ...extra] = process.argv.slice(2);
if ((kindRaw !== "public" && kindRaw !== "secret") || !UUID.test(runId ?? "") ||
    !CASES.has(caseId) || !CANARY.test(canary ?? "") || extra.length !== 0 ||
    (kindRaw === "public" && secretPath !== undefined) ||
    (kindRaw === "secret" && (caseId !== "v2-runtime-secret" || typeof secretPath !== "string" ||
      !secretPath.startsWith("/tmp/sbx-054/") || secretPath.includes("..")))) {
  fail("arguments were not exact");
}
const kind = kindRaw;
const origin = exactOrigin(originRaw);
const url = new URL(`/v1/sbx054/${kind}/${runId}/${caseId}/${canary}`, origin);
let body;
let secretFileMode = null;
let secretFileDeleted = null;
if (kind === "secret") {
  const secret = await readAndRemoveSecret(secretPath);
  body = secret.bytes;
  secretFileMode = secret.mode;
  secretFileDeleted = true;
}

await new Promise((resolve) => setTimeout(resolve, 350));
const started = performance.now();
try {
  const result = await oneRequest(url, kind, body);
  const output = {
    schemaVersion: 1,
    testId: TEST_ID,
    kind,
    caseId,
    requestAttempts: 1,
    connectionAttempts: result.connectionAttempts,
    redirectsFollowed: 0,
    rejectUnauthorized: true,
    controllerConfigurableCustomTrustAccepted: false,
    inheritedPlatformTrustEnvironmentNames,
    nodeOptionsPresent: false,
    tlsAuthorized: result.tlsAuthorized,
    receivedResponse: result.receivedResponse,
    statusCode: result.statusCode,
    durationMs: Math.round(performance.now() - started),
    receipt: result.receipt,
    secretProof: result.secretProof,
    operationId: result.operationId,
    secretFileMode,
    secretFileDeleted,
    error: result.error,
  };
  process.stdout.write(`${JSON.stringify(output)}\n`);
} finally {
  body?.fill(0);
}
