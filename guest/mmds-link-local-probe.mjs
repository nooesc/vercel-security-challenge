import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import http from "node:http";
import { TextDecoder } from "node:util";
import {
  DIRECT_SECRET_LEAVES,
  DISCOVERY_NAMESPACE_RULES,
  SECRET_OBJECT_KEYS as SECRET_OBJECT_KEY_LIST,
} from "./mmds-discovery-rules.mjs";

export const MMDS_TARGET = "169.254.169.254";
export const ROOT_INDEX_PATH = "/latest/meta-data/";
export const TOKEN_PATH = "/latest/api/token";
export const IDENTITY_PATH = "/latest/dynamic/instance-identity/document";
export const ROLE_INDEX_PATH = "/latest/meta-data/iam/security-credentials/";
export const CREDENTIAL_PATH_TEMPLATE = "/latest/meta-data/iam/security-credentials/<validated-role>";
export const DISCOVERY_ROOT_PATH = "/";
export const DISCOVERY_NAMESPACE_PATH_TEMPLATE = "/<matched-secret-namespace>/";
export const DISCOVERY_SECRET_PATH_TEMPLATE = "/<matched-secret-namespace?>/<matched-secret-leaf>";
export const TOKEN_TTL_SECONDS = "60";
export const MAXIMUM_REQUEST_COUNT = 8;
export const MMDS_REQUEST_FORMAT_ATTESTATION = Object.freeze({
  token: "imds-default-accept-omitted",
  rootAndDirectoryListings: "imds-default-accept-omitted",
  roleIndex: "imds-default-accept-omitted",
  structuredDocumentsAndSecretLeaf: "application/json",
});

const SCOPE_CONFIRMATION = "I_UNDERSTAND_THIS_TARGETS_ONLY_FIRECRACKER_MMDS";
const ALLOWED_CONFIGURATION_KEYS = new Set([
  "scopeConfirmation", "runId", "testId", "caseId", "target", "timeoutMs",
  "routeTimeoutMs", "interRequestDelayMs", "maxResponseBytes",
]);
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const TOKEN_VALUE = /^[\x21-\x7e]{16,4096}$/u;
const ROLE_NAME = /^[A-Za-z0-9+=,.@_-]{1,64}$/u;
const SAFE_CHILD_KEY = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });
const EXPECTED_CREDENTIAL_KEYS = ["Code", "AccessKeyId", "SecretAccessKey", "Token", "Expiration"];
const SECRET_OBJECT_KEYS = new Set(SECRET_OBJECT_KEY_LIST);
const DISCOVERY_NAMESPACE_ENTRIES = Object.entries(DISCOVERY_NAMESPACE_RULES).map(
  ([name, leaves]) => ({ name, leaves }),
);

function record(value, field) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${field} must be an object`);
  }
  return value;
}

function identifier(value, field) {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    throw new Error(`${field} must be a bounded identifier`);
  }
  return value;
}

function boundedInteger(value, field, minimum, maximum, fallback) {
  const selected = value ?? fallback;
  if (!Number.isInteger(selected) || selected < minimum || selected > maximum) {
    throw new Error(`${field} must be an integer from ${minimum} through ${maximum}`);
  }
  return selected;
}

export function validateMmdsProbeConfig(input) {
  const config = record(input, "configuration");
  for (const key of Object.keys(config)) {
    if (!ALLOWED_CONFIGURATION_KEYS.has(key)) {
      throw new Error(`configuration field ${JSON.stringify(key)} is not allowed`);
    }
  }
  if (config.scopeConfirmation !== SCOPE_CONFIRMATION) {
    throw new Error(`scopeConfirmation must equal ${JSON.stringify(SCOPE_CONFIRMATION)}`);
  }
  if ((config.target ?? MMDS_TARGET) !== MMDS_TARGET) {
    throw new Error(`target is fixed to ${MMDS_TARGET}; arbitrary link-local probing is forbidden`);
  }
  return {
    runId: identifier(config.runId, "runId"),
    testId: identifier(config.testId, "testId"),
    caseId: identifier(config.caseId, "caseId"),
    target: MMDS_TARGET,
    timeoutMs: boundedInteger(config.timeoutMs, "timeoutMs", 100, 10_000, 2_000),
    routeTimeoutMs: boundedInteger(config.routeTimeoutMs, "routeTimeoutMs", 100, 5_000, 1_500),
    interRequestDelayMs: boundedInteger(config.interRequestDelayMs, "interRequestDelayMs", 200, 1_000, 250),
    maxResponseBytes: boundedInteger(config.maxResponseBytes, "maxResponseBytes", 256, 65_536, 16_384),
  };
}

function safeErrorCode(error) {
  const code = typeof error?.code === "string" ? error.code : undefined;
  if (code && /^[A-Z0-9_]{1,64}$/u.test(code)) return code;
  const name = error instanceof Error ? error.name : "Error";
  return /^[A-Za-z][A-Za-z0-9]{0,63}$/u.test(name) ? name : "Error";
}

function safeContentType(headers) {
  const raw = headers?.["content-type"];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === "string" ? value.replace(/[\0\r\n]/gu, "").slice(0, 256) : undefined;
}

function parsedJsonKeyNames(body) {
  if (body.length === 0) return [];
  try {
    const parsed = JSON.parse(UTF8_DECODER.decode(body));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return [];
    return Object.keys(parsed).slice(0, 64).map((key) => key.replace(/[\0\r\n]/gu, "").slice(0, 128));
  } catch {
    return [];
  }
}

export function summarizeMetadataResponse({
  path,
  statusCode,
  headers,
  body,
  suppressDigest = false,
  suppressJsonKeys = false,
}) {
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(body ?? "");
  return {
    path,
    requestSucceeded: true,
    statusCode: Number.isInteger(statusCode) ? statusCode : undefined,
    byteLength: bytes.length,
    contentType: safeContentType(headers),
    sha256: suppressDigest ? undefined : createHash("sha256").update(bytes).digest("hex"),
    parsedJsonKeyNames: suppressDigest || suppressJsonKeys ? [] : parsedJsonKeyNames(bytes),
  };
}

export async function inspectMmdsRoute(config) {
  const startedAt = Date.now();
  return await new Promise((resolve) => {
    execFile("ip", ["-json", "route", "get", MMDS_TARGET], {
      timeout: config.routeTimeoutMs,
      maxBuffer: 16_384,
      encoding: "utf8",
    }, (error, stdout) => {
      const output = typeof stdout === "string" ? stdout : "";
      resolve({
        toolAvailable: error?.code !== "ENOENT",
        routePresent: error === null && output.length > 0,
        exitCode: typeof error?.code === "number" ? error.code : error === null ? 0 : undefined,
        errorCode: error ? safeErrorCode(error) : undefined,
        targetMentioned: output.includes(MMDS_TARGET),
        stdoutSha256: output.length > 0 ? createHash("sha256").update(output).digest("hex") : undefined,
        durationMs: Date.now() - startedAt,
      });
    });
  });
}

function validatedRequestSpec(input) {
  const spec = record(input, "request specification");
  const method = spec.method;
  const path = spec.path;
  const headers = record(spec.headers ?? {}, "request headers");
  const headerNames = Object.keys(headers).map((name) => name.toLowerCase()).sort();
  const tokenHeader = headers["x-aws-ec2-metadata-token"];
  const ttlHeader = headers["x-aws-ec2-metadata-token-ttl-seconds"];

  if (method === "PUT" && path === TOKEN_PATH) {
    if (headerNames.length !== 1 || headerNames[0] !== "x-aws-ec2-metadata-token-ttl-seconds" ||
      ttlHeader !== TOKEN_TTL_SECONDS) {
      throw new Error("the token request requires only the fixed IMDSv2 TTL header");
    }
    return {
      method,
      path,
      headers,
      capturePrivateBody: true,
      suppressDigest: true,
      responseFormat: "imds-default",
    };
  }
  if (method !== "GET") throw new Error("only the fixed token PUT and metadata GETs are allowed");
  if (path === ROOT_INDEX_PATH) {
    if (headerNames.length !== 0) throw new Error("the root control must be unauthenticated");
    return {
      method,
      path,
      headers,
      capturePrivateBody: false,
      suppressDigest: false,
      responseFormat: "imds-default",
    };
  }
  const fixedAuthenticated = path === IDENTITY_PATH || path === ROLE_INDEX_PATH;
  let credentialPath = false;
  if (typeof path === "string" && path.startsWith(ROLE_INDEX_PATH) && path !== ROLE_INDEX_PATH) {
    const segment = path.slice(ROLE_INDEX_PATH.length);
    try {
      const decoded = decodeURIComponent(segment);
      credentialPath = segment.length > 0 && !segment.includes("/") && ROLE_NAME.test(decoded) &&
        encodeURIComponent(decoded) === segment;
    } catch {
      credentialPath = false;
    }
  }
  if (headerNames.length !== 1 || headerNames[0] !== "x-aws-ec2-metadata-token" ||
    typeof tokenHeader !== "string" || !TOKEN_VALUE.test(tokenHeader)) {
    throw new Error("authenticated metadata GET requires only a validated in-memory IMDSv2 token");
  }
  const discoveryKind = spec.discoveryKind;
  let discoveryDirectory = false;
  let discoverySecret = false;
  if (discoveryKind === "directory") {
    discoveryDirectory = path === DISCOVERY_ROOT_PATH || DISCOVERY_NAMESPACE_ENTRIES.some(
      (rule) => path === `/${encodeURIComponent(rule.name)}/`,
    );
  } else if (discoveryKind === "secret") {
    discoverySecret = DIRECT_SECRET_LEAVES.some((leaf) => path === `/${encodeURIComponent(leaf)}`) ||
      DISCOVERY_NAMESPACE_ENTRIES.some((rule) => rule.leaves.some(
        (leaf) => path === `/${encodeURIComponent(rule.name)}/${encodeURIComponent(leaf)}`,
      ));
  } else if (discoveryKind !== undefined) {
    throw new Error("discoveryKind is not recognized");
  }
  if (discoveryKind === "directory" && !discoveryDirectory) {
    throw new Error("discovery directory path is not allowlisted");
  }
  if (discoveryKind === "secret" && !discoverySecret) {
    throw new Error("discovery secret path is not allowlisted");
  }
  if (!fixedAuthenticated && !credentialPath && !discoveryDirectory && !discoverySecret) {
    throw new Error("metadata GET path is not allowlisted");
  }
  return {
    method,
    path,
    headers,
    capturePrivateBody: path === ROLE_INDEX_PATH || credentialPath || discoveryDirectory || discoverySecret,
    // Credential and secret bodies are validated only in guest memory. Even a
    // digest can disclose a low-entropy value, so it must not leave the guest.
    suppressDigest: path === ROLE_INDEX_PATH || credentialPath || discoveryDirectory || discoverySecret,
    suppressJsonKeys: discoveryDirectory || discoverySecret,
    // Firecracker selects IMDS directory output when Accept is absent. Its
    // documented plaintext spelling is `plain/text`, not `text/plain`, so
    // listings deliberately omit the header. Exact leaf/object requests use
    // JSON so scalar and structured proofs can both be validated in memory.
    responseFormat: (fixedAuthenticated && path === IDENTITY_PATH) || credentialPath || discoverySecret
      ? "json"
      : "imds-default",
  };
}

function headersForValidatedSpec(spec) {
  return {
    Host: MMDS_TARGET,
    ...(spec.responseFormat === "json" ? { Accept: "application/json" } : {}),
    Connection: "close",
    ...spec.headers,
  };
}

export function requestHeadersForSpec(specInput) {
  return headersForValidatedSpec(validatedRequestSpec(specInput));
}

export async function requestMmds(specInput, config) {
  const spec = validatedRequestSpec(specInput);
  const startedAt = Date.now();
  return await new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve({ ...value, durationMs: Date.now() - startedAt });
    };
    const request = http.request({
      hostname: MMDS_TARGET,
      port: 80,
      method: spec.method,
      path: spec.path,
      agent: false,
      timeout: config.timeoutMs,
      headers: headersForValidatedSpec(spec),
    }, (response) => {
      const chunks = [];
      let byteLength = 0;
      const wipeChunks = () => {
        for (const chunk of chunks) chunk.fill(0);
        chunks.length = 0;
      };
      response.on("data", (chunk) => {
        const bytes = Buffer.from(chunk);
        byteLength += bytes.length;
        if (byteLength > config.maxResponseBytes) {
          bytes.fill(0);
          response.destroy(Object.assign(new Error("response exceeded the configured byte cap"), {
            code: "RESPONSE_TOO_LARGE",
          }));
          return;
        }
        chunks.push(bytes);
      });
      response.on("end", () => {
        const body = Buffer.concat(chunks);
        const summary = summarizeMetadataResponse({
          path: spec.path,
          statusCode: response.statusCode,
          headers: response.headers,
          body,
          suppressDigest: spec.suppressDigest,
          suppressJsonKeys: spec.suppressJsonKeys,
        });
        finish({ ...summary, privateBody: spec.capturePrivateBody ? Buffer.from(body) : undefined });
        body.fill(0);
        wipeChunks();
      });
      response.on("error", (error) => {
        wipeChunks();
        finish({
          path: spec.path,
          requestSucceeded: false,
          errorCode: safeErrorCode(error),
          byteLength,
        });
      });
    });
    request.on("timeout", () => request.destroy(Object.assign(new Error("request timed out"), {
      code: "ETIMEDOUT",
    })));
    request.on("error", (error) => finish({
      path: spec.path,
      requestSucceeded: false,
      errorCode: safeErrorCode(error),
    }));
    request.end();
  });
}

function normalizeAttempt(raw, { method, path, classification, suppressDigest = false }) {
  const input = raw !== null && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  const suppressSensitiveJsonKeys = classification === "token" || classification === "role-index" ||
    classification === "discovery-root" || classification === "discovery-namespace" ||
    classification === "discovery-secret";
  const keyNames = !suppressSensitiveJsonKeys && Array.isArray(input.parsedJsonKeyNames)
    ? input.parsedJsonKeyNames.filter((key) => typeof key === "string").slice(0, 64)
      .map((key) => key.replace(/[\0\r\n]/gu, "").slice(0, 128))
    : [];
  return {
    classification,
    method,
    path,
    requestSucceeded: input.requestSucceeded === true,
    statusCode: Number.isInteger(input.statusCode) ? input.statusCode : undefined,
    byteLength: Number.isInteger(input.byteLength) && input.byteLength >= 0 ? input.byteLength : undefined,
    contentType: typeof input.contentType === "string"
      ? input.contentType.replace(/[\0\r\n]/gu, "").slice(0, 256)
      : undefined,
    sha256: !suppressDigest && typeof input.sha256 === "string" && SHA256.test(input.sha256)
      ? input.sha256
      : undefined,
    parsedJsonKeyNames: keyNames,
    errorCode: typeof input.errorCode === "string" && /^[A-ZA-Za-z0-9_]{1,64}$/u.test(input.errorCode)
      ? input.errorCode
      : undefined,
    durationMs: Number.isInteger(input.durationMs) && input.durationMs >= 0 ? input.durationMs : undefined,
  };
}

function populatedSuccess(attempt) {
  return attempt?.requestSucceeded === true && Number.isInteger(attempt.statusCode) &&
    attempt.statusCode >= 200 && attempt.statusCode < 300 && Number.isInteger(attempt.byteLength) &&
    attempt.byteLength > 0;
}

function validatedToken(privateBody) {
  if (!Buffer.isBuffer(privateBody) || privateBody.length < 16 || privateBody.length > 4_096) return undefined;
  try {
    const value = UTF8_DECODER.decode(privateBody);
    return TOKEN_VALUE.test(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

function validatedRole(privateBody) {
  if (!Buffer.isBuffer(privateBody) || privateBody.length === 0 || privateBody.length > 128) return undefined;
  try {
    const match = /^([A-Za-z0-9+=,.@_-]{1,64})(?:\r?\n)?$/u.exec(UTF8_DECODER.decode(privateBody));
    return match?.[1] && ROLE_NAME.test(match[1]) ? match[1] : undefined;
  } catch {
    return undefined;
  }
}

function safeContentTypeValue(value) {
  return typeof value === "string" ? value.toLowerCase() : "";
}

function parseTextDirectory(privateBody, contentType) {
  if (!Buffer.isBuffer(privateBody) || privateBody.length === 0 || privateBody.length > 4_096) {
    return { safe: false, reason: "missing-or-oversized-listing", childKeyNames: [] };
  }
  try {
    const text = UTF8_DECODER.decode(privateBody);
    const trimmedStart = text.trimStart();
    if (safeContentTypeValue(contentType).includes("json") || trimmedStart.startsWith("{") ||
      trimmedStart.startsWith("[")) {
      return { safe: false, reason: "json-container-listing", childKeyNames: [] };
    }
    const lines = text.split(/\r?\n/u);
    if (lines.at(-1) === "") lines.pop();
    if (lines.length === 0 || lines.length > 64) {
      return { safe: false, reason: "empty-or-excessive-listing", childKeyNames: [] };
    }
    const childEntries = [];
    const seen = new Set();
    for (const line of lines) {
      const isDirectory = line.endsWith("/");
      const key = isDirectory ? line.slice(0, -1) : line;
      if (!SAFE_CHILD_KEY.test(key) || key === "." || key === ".." || seen.has(key)) {
        return { safe: false, reason: "unsafe-child-key", childKeyNames: [] };
      }
      seen.add(key);
      childEntries.push({ name: key, isDirectory });
    }
    return { safe: true, childEntries, childKeyNames: childEntries.map((entry) => entry.name) };
  } catch {
    return { safe: false, reason: "non-utf8-listing", childKeyNames: [] };
  }
}

function selectDiscoveryTarget(childEntries, namespaceRule) {
  if (!namespaceRule) {
    const directLeaf = DIRECT_SECRET_LEAVES.find((leaf) => childEntries.some(
      (entry) => entry.name === leaf && entry.isDirectory === false,
    ));
    if (directLeaf) return { kind: "secret", leaf: directLeaf };
    const namespace = DISCOVERY_NAMESPACE_ENTRIES.find((rule) => childEntries.some(
      (entry) => entry.name === rule.name && entry.isDirectory === true,
    ));
    return namespace ? { kind: "namespace", namespace } : undefined;
  }
  const leaf = namespaceRule.leaves.find((candidate) => childEntries.some(
    (entry) => entry.name === candidate && entry.isDirectory === false,
  ));
  return leaf ? { kind: "secret", namespace: namespaceRule, leaf } : undefined;
}

function validSecretScalar(value) {
  if (typeof value !== "string" || value.length < 16 || value.length > 4_096 ||
    !/^[\x21-\x7e]+$/u.test(value)) return false;
  const normalized = value.toLowerCase().replace(/[^a-z0-9]+/gu, "");
  if (/(?:notfound|notavailable|notconfigured|notsupported|noprovided|nocredential|nocredentials|notoken|nosecret|none|null|undefined|error|unauthorized|forbidden|missing|redacted|placeholder|changeme|example|testvalue|dummy|disabled|empty)/u.test(normalized)) {
    return false;
  }
  if (new Set(value).size < 10) return false;
  const knownPrefix = /^(?:ddapi_|dduid_|sk-|ghp_|xox[baprs]-)[A-Za-z0-9_-]{16,}$/u.test(value);
  const hexSecret = /^(?=.*[A-Fa-f])(?=.*[0-9])[A-Fa-f0-9]{24,128}$/u.test(value);
  const opaqueSecret = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])[A-Za-z0-9_-]{24,512}$/u.test(value);
  return knownPrefix || hexSecret || opaqueSecret;
}

function parseSecretProof(privateBody, contentType, expectedLeaf) {
  if (!Buffer.isBuffer(privateBody) || privateBody.length === 0 || privateBody.length > 16_384) {
    return { safe: false, reason: "missing-or-oversized-secret" };
  }
  if (!knownLeafName(expectedLeaf)) return { safe: false, reason: "unrecognized-secret-leaf" };
  try {
    const text = UTF8_DECODER.decode(privateBody);
    const trimmed = text.trim();
    if (trimmed.length === 0) return { safe: false, reason: "empty-secret" };
    if (trimmed.startsWith("{") || trimmed.startsWith("\"") ||
      safeContentTypeValue(contentType).includes("json")) {
      const parsed = JSON.parse(trimmed);
      if (typeof parsed === "string") {
        if (!validSecretScalar(parsed)) return { safe: false, reason: "weak-or-placeholder-secret" };
        return { safe: true, proofType: "scalar-text", keyNames: [] };
      }
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        return { safe: false, reason: "non-object-json-secret" };
      }
      const keyNames = Object.keys(parsed);
      if (keyNames.length === 0 || keyNames.length > 64 ||
        keyNames.some((key) => !SAFE_CHILD_KEY.test(key))) {
        return { safe: false, reason: "unsafe-secret-object-keys" };
      }
      const validatedSecretKeys = keyNames.filter(
        (key) => SECRET_OBJECT_KEYS.has(key) && validSecretScalar(parsed[key]),
      );
      if (validatedSecretKeys.length === 0) {
        return { safe: false, reason: "unrecognized-secret-object" };
      }
      return { safe: true, proofType: "secret-object", keyNames: validatedSecretKeys };
    }
    if (trimmed.startsWith("[") || /[\0\r\n]/u.test(trimmed)) {
      return { safe: false, reason: "non-scalar-secret" };
    }
    const normalizedContentType = safeContentTypeValue(contentType);
    if (normalizedContentType && !normalizedContentType.startsWith("text/plain") &&
      !normalizedContentType.startsWith("application/octet-stream")) {
      return { safe: false, reason: "unexpected-scalar-content-type" };
    }
    if (!validSecretScalar(trimmed)) return { safe: false, reason: "weak-or-placeholder-secret" };
    return { safe: true, proofType: "scalar-text", keyNames: [] };
  } catch {
    return { safe: false, reason: "non-utf8-or-invalid-json-secret" };
  }
}

function knownLeafName(value) {
  return DIRECT_SECRET_LEAVES.includes(value) || Object.values(DISCOVERY_NAMESPACE_RULES).some(
    (leaves) => leaves.includes(value),
  );
}

function hasExpectedCredentialStructure(attempt) {
  if (!populatedSuccess(attempt) || !Array.isArray(attempt.parsedJsonKeyNames)) return false;
  const names = new Set(attempt.parsedJsonKeyNames);
  return EXPECTED_CREDENTIAL_KEYS.every((key) => names.has(key));
}

function validCredentialString(value, minimum, maximum) {
  return typeof value === "string" && value.length >= minimum && value.length <= maximum &&
    /^[\x21-\x7e]+$/u.test(value);
}

function validateCredentialDocument(privateBody) {
  if (!Buffer.isBuffer(privateBody) || privateBody.length === 0 || privateBody.length > 16_384) return false;
  try {
    const parsed = JSON.parse(UTF8_DECODER.decode(privateBody));
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) &&
      parsed.Code === "Success" && validCredentialString(parsed.AccessKeyId, 8, 256) &&
      validCredentialString(parsed.SecretAccessKey, 16, 512) && validCredentialString(parsed.Token, 16, 8_192) &&
      typeof parsed.Expiration === "string" && parsed.Expiration.length <= 128 &&
      Number.isFinite(Date.parse(parsed.Expiration));
  } catch {
    return false;
  }
}

function boundedDelay(ms) {
  return ms === 0 ? Promise.resolve() : new Promise((resolve) => setTimeout(resolve, ms));
}

export async function runMmdsProbe(config, {
  requester = requestMmds,
  routeInspector = inspectMmdsRoute,
  sleeper = boundedDelay,
} = {}) {
  const startedAt = new Date().toISOString();
  const routeControlRaw = await routeInspector(config);
  const routeControl = {
    toolAvailable: routeControlRaw?.toolAvailable === true,
    routePresent: routeControlRaw?.routePresent === true,
    exitCode: Number.isInteger(routeControlRaw?.exitCode) ? routeControlRaw.exitCode : undefined,
    errorCode: typeof routeControlRaw?.errorCode === "string" ? routeControlRaw.errorCode.slice(0, 64) : undefined,
    targetMentioned: routeControlRaw?.targetMentioned === true,
    stdoutSha256: typeof routeControlRaw?.stdoutSha256 === "string" && SHA256.test(routeControlRaw.stdoutSha256)
      ? routeControlRaw.stdoutSha256
      : undefined,
    durationMs: Number.isInteger(routeControlRaw?.durationMs) && routeControlRaw.durationMs >= 0
      ? routeControlRaw.durationMs
      : undefined,
  };
  const attempts = [];
  let token;
  let tokenAcquired = false;
  let tokenResponseRejectedUnsafe = false;
  let roleNameValidated = false;
  let roleResponseRejectedUnsafe = false;
  let credentialDocumentRequested = false;
  let credentialValuesValidated = false;
  let credentialProofObserved = false;
  let unexpectedCredentialDocument = false;
  let discoveryStarted = false;
  let discoveryRootListingSafe = false;
  let discoveryNamespaceListingSafe = false;
  let discoveryListingRejectedUnsafe = false;
  let discoverySecretRequested = false;
  let discoverySecretProofType;
  let discoverySecretRejectedUnsafe = false;
  let matchedKnownNamespace;
  let matchedSecretLeaf;

  const request = async (spec, descriptor) => {
    if (attempts.length >= MAXIMUM_REQUEST_COUNT) throw new Error("MMDS request bound exhausted");
    const raw = await requester(spec, config);
    const attempt = normalizeAttempt(raw, descriptor);
    attempts.push(attempt);
    return { raw, attempt };
  };

  await request(
    { method: "GET", path: ROOT_INDEX_PATH, headers: {} },
    { method: "GET", path: ROOT_INDEX_PATH, classification: "root-index" },
  );
  await sleeper(config.interRequestDelayMs);
  const { raw: tokenRaw } = await request(
    {
      method: "PUT",
      path: TOKEN_PATH,
      headers: { "x-aws-ec2-metadata-token-ttl-seconds": TOKEN_TTL_SECONDS },
    },
    { method: "PUT", path: TOKEN_PATH, classification: "token", suppressDigest: true },
  );
  const tokenAttempt = attempts.at(-1);
  if (populatedSuccess(tokenAttempt)) {
    token = validatedToken(tokenRaw?.privateBody);
    tokenAcquired = token !== undefined;
    tokenResponseRejectedUnsafe = !tokenAcquired;
  }
  if (Buffer.isBuffer(tokenRaw?.privateBody)) tokenRaw.privateBody.fill(0);

  if (tokenAcquired) {
    await sleeper(config.interRequestDelayMs);
    await request(
      { method: "GET", path: IDENTITY_PATH, headers: { "x-aws-ec2-metadata-token": token } },
      { method: "GET", path: IDENTITY_PATH, classification: "identity" },
    );
    await sleeper(config.interRequestDelayMs);
    const { raw: roleRaw } = await request(
      { method: "GET", path: ROLE_INDEX_PATH, headers: { "x-aws-ec2-metadata-token": token } },
      { method: "GET", path: ROLE_INDEX_PATH, classification: "role-index", suppressDigest: true },
    );
    const roleAttempt = attempts.at(-1);
    if (populatedSuccess(roleAttempt)) {
      const role = validatedRole(roleRaw?.privateBody);
      roleNameValidated = role !== undefined;
      roleResponseRejectedUnsafe = !roleNameValidated;
      if (role) {
        await sleeper(config.interRequestDelayMs);
        credentialDocumentRequested = true;
        const { raw: credentialRaw, attempt: credentialAttempt } = await request(
          {
            method: "GET",
            path: `${ROLE_INDEX_PATH}${encodeURIComponent(role)}`,
            headers: { "x-aws-ec2-metadata-token": token },
          },
          {
            method: "GET",
            path: CREDENTIAL_PATH_TEMPLATE,
            classification: "credential-document",
            suppressDigest: true,
          },
        );
        credentialValuesValidated = validateCredentialDocument(credentialRaw?.privateBody);
        credentialAttempt.credentialValuesValidated = credentialValuesValidated;
        if (Buffer.isBuffer(credentialRaw?.privateBody)) credentialRaw.privateBody.fill(0);
      }
    }
    if (Buffer.isBuffer(roleRaw?.privateBody)) roleRaw.privateBody.fill(0);

    const credentialAttempt = attempts.find((attempt) => attempt.classification === "credential-document");
    credentialProofObserved = hasExpectedCredentialStructure(credentialAttempt) && credentialValuesValidated;
    unexpectedCredentialDocument = populatedSuccess(credentialAttempt) && !credentialProofObserved;

    if (!credentialProofObserved && !unexpectedCredentialDocument && !roleResponseRejectedUnsafe) {
      discoveryStarted = true;
      await sleeper(config.interRequestDelayMs);
      const { raw: rootRaw, attempt: rootAttempt } = await request(
        {
          method: "GET",
          path: DISCOVERY_ROOT_PATH,
          headers: { "x-aws-ec2-metadata-token": token },
          discoveryKind: "directory",
        },
        { method: "GET", path: DISCOVERY_ROOT_PATH, classification: "discovery-root", suppressDigest: true },
      );
      let rootListing;
      if (populatedSuccess(rootAttempt)) {
        rootListing = parseTextDirectory(rootRaw?.privateBody, rootAttempt.contentType);
        rootAttempt.listingSafe = rootListing.safe;
        rootAttempt.safeChildCount = rootListing.safe ? rootListing.childKeyNames.length : undefined;
        rootAttempt.listingRejectionReason = rootListing.safe ? undefined : rootListing.reason;
        discoveryRootListingSafe = rootListing.safe;
        discoveryListingRejectedUnsafe = !rootListing.safe;
      }
      if (Buffer.isBuffer(rootRaw?.privateBody)) rootRaw.privateBody.fill(0);

      if (rootListing?.safe) {
        let selection = selectDiscoveryTarget(rootListing.childEntries);
        rootAttempt.matchedAllowlistedChildKeyNames = selection
          ? [selection.kind === "namespace" ? selection.namespace.name : selection.leaf]
          : [];
        if (selection?.kind === "namespace") {
          matchedKnownNamespace = selection.namespace.name;
          await sleeper(config.interRequestDelayMs);
          const namespacePath = `/${encodeURIComponent(selection.namespace.name)}/`;
          const { raw: namespaceRaw, attempt: namespaceAttempt } = await request(
            {
              method: "GET",
              path: namespacePath,
              headers: { "x-aws-ec2-metadata-token": token },
              discoveryKind: "directory",
            },
            {
              method: "GET",
              path: DISCOVERY_NAMESPACE_PATH_TEMPLATE,
              classification: "discovery-namespace",
              suppressDigest: true,
            },
          );
          let namespaceListing;
          if (populatedSuccess(namespaceAttempt)) {
            namespaceListing = parseTextDirectory(namespaceRaw?.privateBody, namespaceAttempt.contentType);
            namespaceAttempt.listingSafe = namespaceListing.safe;
            namespaceAttempt.safeChildCount = namespaceListing.safe
              ? namespaceListing.childKeyNames.length
              : undefined;
            namespaceAttempt.listingRejectionReason = namespaceListing.safe
              ? undefined
              : namespaceListing.reason;
            discoveryNamespaceListingSafe = namespaceListing.safe;
            discoveryListingRejectedUnsafe ||= !namespaceListing.safe;
          }
          if (Buffer.isBuffer(namespaceRaw?.privateBody)) namespaceRaw.privateBody.fill(0);
          selection = namespaceListing?.safe
            ? selectDiscoveryTarget(namespaceListing.childEntries, selection.namespace)
            : undefined;
          namespaceAttempt.matchedAllowlistedChildKeyNames = selection?.kind === "secret"
            ? [selection.leaf]
            : [];
        }

        if (selection?.kind === "secret") {
          matchedSecretLeaf = selection.leaf;
          if (selection.namespace) matchedKnownNamespace = selection.namespace.name;
          await sleeper(config.interRequestDelayMs);
          const secretPath = selection.namespace
            ? `/${encodeURIComponent(selection.namespace.name)}/${encodeURIComponent(selection.leaf)}`
            : `/${encodeURIComponent(selection.leaf)}`;
          discoverySecretRequested = true;
          const { raw: secretRaw, attempt: secretAttempt } = await request(
            {
              method: "GET",
              path: secretPath,
              headers: { "x-aws-ec2-metadata-token": token },
              discoveryKind: "secret",
            },
            {
              method: "GET",
              path: DISCOVERY_SECRET_PATH_TEMPLATE,
              classification: "discovery-secret",
              suppressDigest: true,
            },
          );
          if (populatedSuccess(secretAttempt)) {
            const proof = parseSecretProof(secretRaw?.privateBody, secretAttempt.contentType, selection.leaf);
            secretAttempt.secretProofType = proof.safe ? proof.proofType : undefined;
            secretAttempt.secretObjectKeyNames = proof.safe ? proof.keyNames : [];
            secretAttempt.secretRejectedUnsafe = !proof.safe;
            secretAttempt.secretRejectionReason = proof.safe ? undefined : proof.reason;
            discoverySecretProofType = proof.safe ? proof.proofType : undefined;
            discoverySecretRejectedUnsafe = !proof.safe;
          }
          if (Buffer.isBuffer(secretRaw?.privateBody)) secretRaw.privateBody.fill(0);
        }
      }
    }
  }
  token = undefined;

  const credentialAttempt = attempts.find((attempt) => attempt.classification === "credential-document");
  return {
    ok: true,
    mode: "execute",
    runId: config.runId,
    testId: config.testId,
    caseId: config.caseId,
    target: MMDS_TARGET,
    startedAt,
    completedAt: new Date().toISOString(),
    runtime: { nodeVersion: process.version, platform: process.platform, arch: process.arch },
    bounds: {
      sequentialRequestsOnly: true,
      maximumRequestCount: MAXIMUM_REQUEST_COUNT,
      actualRequestCount: attempts.length,
      interRequestDelayMs: config.interRequestDelayMs,
      maximumRequestsPerSecond: 5,
      timeoutMs: config.timeoutMs,
      maxResponseBytes: config.maxResponseBytes,
    },
    bodyRetention: "none",
    tokenRetention: "guest-memory-only-during-flow",
    sensitiveLeafValueOrDigestRetention: "none",
    requestFormatAttestation: MMDS_REQUEST_FORMAT_ATTESTATION,
    routeControl,
    attempts,
    flow: {
      tokenAcquired,
      tokenResponseRejectedUnsafe,
      roleNameValidated,
      roleResponseRejectedUnsafe,
      credentialDocumentRequested,
      credentialValuesValidated,
      credentialProofObserved,
      unexpectedCredentialDocument,
      stoppedAfterCredentialDocument: credentialProofObserved && attempts.at(-1) === credentialAttempt,
      discoveryStarted,
      discoveryRootListingSafe,
      discoveryNamespaceListingSafe,
      discoveryListingRejectedUnsafe,
      matchedKnownNamespace,
      matchedSecretLeaf,
      discoverySecretRequested,
      discoverySecretProofType,
      discoverySecretRejectedUnsafe,
      stoppedAtProof: credentialProofObserved || discoverySecretProofType !== undefined,
    },
  };
}

function plan(config) {
  return {
    ok: true,
    mode: "plan",
    target: MMDS_TARGET,
    port: 80,
    maximumRequestCount: MAXIMUM_REQUEST_COUNT,
    sequentialRequestsOnly: true,
    interRequestDelayMs: config.interRequestDelayMs,
    maximumRequestsPerSecond: 5,
    stopAtCredentialProof: true,
    requestFormatAttestation: MMDS_REQUEST_FORMAT_ATTESTATION,
    flow: [
      { method: "GET", path: ROOT_INDEX_PATH, authentication: "none" },
      { method: "PUT", path: TOKEN_PATH, fixedTtlSeconds: TOKEN_TTL_SECONDS },
      { method: "GET", path: IDENTITY_PATH, authentication: "in-memory-token" },
      { method: "GET", path: ROLE_INDEX_PATH, authentication: "in-memory-token" },
      { method: "GET", path: CREDENTIAL_PATH_TEMPLATE, condition: "one validated role segment" },
      {
        method: "GET",
        path: DISCOVERY_ROOT_PATH,
        responseFormat: "imds-default",
        acceptHeader: "omitted",
        condition: "no prior proof or unsafe response",
      },
      {
        method: "GET",
        path: DISCOVERY_NAMESPACE_PATH_TEMPLATE,
        responseFormat: "imds-default",
        acceptHeader: "omitted",
        condition: "one exact known namespace",
      },
      {
        method: "GET",
        path: DISCOVERY_SECRET_PATH_TEMPLATE,
        responseFormat: "json",
        acceptHeader: "application/json",
        condition: "one exact known secret leaf",
      },
    ],
    responseRetention: ["status", "byteLength", "contentType", "non-secret-control-sha256", "parsedJsonKeyNames"],
    tokenResponseDigestRetained: false,
    roleResponseDigestRetained: false,
    directoryResponseDigestRetained: false,
    credentialOrDiscoveryValueOrDigestRetained: false,
    responseBodiesRetained: false,
    tokenValueRetained: false,
    roleNameRetained: false,
    timeoutMs: config.timeoutMs,
    maxResponseBytes: config.maxResponseBytes,
  };
}

async function main() {
  const encoded = process.argv[2];
  if (!encoded) throw new Error("missing base64url MMDS probe configuration");
  const decoded = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  const config = validateMmdsProbeConfig(decoded);
  const result = process.argv[3] === "--plan" ? plan(config) : await runMmdsProbe(config);
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
