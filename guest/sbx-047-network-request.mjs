import { isIP } from "node:net";

const TOKEN = /^[A-Za-z0-9._:-]{1,160}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const MAXIMUM_RESPONSE_BYTES = 1_024;

if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
  process.stderr.write("SBX-047 guest refused disabled TLS certificate verification\n");
  process.exit(2);
}

function fail(message) {
  process.stderr.write(`SBX-047 guest input error: ${message}\n`);
  process.exit(2);
}

function token(value, name) {
  if (typeof value !== "string" || !TOKEN.test(value)) fail(`${name} is invalid`);
  return value;
}

function exactOrigin(raw) {
  let origin;
  try {
    origin = new URL(raw);
  } catch {
    fail("origin is not a URL");
  }
  if (origin.protocol !== "https:" || raw !== origin.origin || origin.port !== "" ||
      origin.username !== "" || origin.password !== "" || origin.pathname !== "/" ||
      origin.search !== "" || origin.hash !== "" || origin.hostname !== origin.hostname.toLowerCase() ||
      origin.hostname.endsWith(".") || isIP(origin.hostname) !== 0) {
    fail("origin is not one exact canonical HTTPS hostname origin");
  }
  return origin;
}

function nullableDigest(value) {
  return value === null || (typeof value === "string" && SHA256.test(value));
}

function parseResponse(bytes) {
  if (bytes.byteLength > MAXIMUM_RESPONSE_BYTES) throw new Error("response exceeded byte limit");
  if (bytes.byteLength === 0) return { receipt: null, operationId: null, secretProof: null };
  const text = Buffer.from(bytes).toString("utf8");
  const parsed = JSON.parse(text);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed) ||
      Object.keys(parsed).sort().join(",") !== "operationId,receipt,secretProof" ||
      !nullableDigest(parsed.receipt) || !nullableDigest(parsed.operationId) ||
      !nullableDigest(parsed.secretProof)) {
    throw new Error("response JSON was not exact");
  }
  return parsed;
}

function safeError(error) {
  const root = error && typeof error === "object" ? error : {};
  const cause = root.cause && typeof root.cause === "object" ? root.cause : {};
  const name = typeof root.name === "string" && root.name.length <= 80 ? root.name : "Error";
  const code = typeof cause.code === "string" && cause.code.length <= 80
    ? cause.code
    : typeof root.code === "string" && root.code.length <= 80 ? root.code : null;
  const syscall = typeof cause.syscall === "string" && cause.syscall.length <= 80
    ? cause.syscall
    : typeof root.syscall === "string" && root.syscall.length <= 80 ? root.syscall : null;
  const errno = Number.isSafeInteger(cause.errno)
    ? cause.errno
    : Number.isSafeInteger(root.errno) ? root.errno : null;
  return { name, code, syscall, errno };
}

const [kindRaw, originRaw, runRaw, caseRaw, canaryRaw, ...extra] = process.argv.slice(2);
if (extra.length !== 0 || (kindRaw !== "public" && kindRaw !== "action")) fail("arguments are not exact");
const kind = kindRaw;
const origin = exactOrigin(originRaw);
const runId = token(runRaw, "runId");
const caseId = token(caseRaw, "caseId");
const canary = token(canaryRaw, "canary");
const url = new URL(`/v1/sbx047/${kind}/${runId}/${caseId}/${canary}`, origin);
// The controller also paces its control-plane call that starts this command. This fixed
// one-shot delay keeps the ensuing owned-observer request below the same five-per-second bound.
await new Promise((resolve) => setTimeout(resolve, 350));
const started = performance.now();

let output;
try {
  const response = await fetch(url, {
    method: "GET",
    redirect: "error",
    cache: "no-store",
    signal: AbortSignal.timeout(5_000),
  });
  const bytes = await response.arrayBuffer();
  const payload = parseResponse(bytes);
  output = {
    schemaVersion: 1,
    testId: "SBX-047",
    kind,
    caseId,
    receivedResponse: true,
    statusCode: response.status,
    durationMs: Math.round(performance.now() - started),
    receipt: payload.receipt,
    operationId: payload.operationId,
    secretProof: payload.secretProof,
    error: null,
  };
} catch (error) {
  output = {
    schemaVersion: 1,
    testId: "SBX-047",
    kind,
    caseId,
    receivedResponse: false,
    statusCode: null,
    durationMs: Math.round(performance.now() - started),
    receipt: null,
    operationId: null,
    secretProof: null,
    error: safeError(error),
  };
}
process.stdout.write(`${JSON.stringify(output)}\n`);
