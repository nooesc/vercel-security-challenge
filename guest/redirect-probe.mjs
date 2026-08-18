import http from "node:http";
import https from "node:https";

const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);
const MAX_REDIRECT_LIMIT = 10;
const MAX_RESPONSE_BODY_BYTES = 4096;
const DESTINATION_BOUND_HEADERS = new Set([
  "authorization",
  "cookie",
  "cookie2",
  "host",
  "proxy-authorization",
]);
const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "content-length",
  "keep-alive",
  "proxy-authenticate",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);
const SENSITIVE_HEADER_NAME = /(?:^|[-_])(?:api[-_]?key|auth(?:orization)?|cookie|credential|secret|token)(?:$|[-_])/i;

function fail(message) {
  process.stdout.write(`${JSON.stringify({ ok: false, error: message, hops: [] })}\n`);
}

function assertString(value, name) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${name} must be a non-empty string`);
  }
  return value;
}

function parseConfiguration(encoded) {
  const decoded = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  const baseUrl = new URL(assertString(decoded.baseUrl, "baseUrl"));
  if (baseUrl.protocol !== "http:" && baseUrl.protocol !== "https:") {
    throw new Error("baseUrl protocol must be http: or https:");
  }
  const rawPath = assertString(decoded.rawPath, "rawPath");
  if (!rawPath.startsWith("/")) throw new Error("rawPath must begin with /");

  const maxRedirects = decoded.maxRedirects ?? 5;
  if (!Number.isInteger(maxRedirects) || maxRedirects < 0 || maxRedirects > MAX_REDIRECT_LIMIT) {
    throw new Error(`maxRedirects must be an integer from 0 through ${MAX_REDIRECT_LIMIT}`);
  }

  const timeoutMs = decoded.timeoutMs ?? 5_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) {
    throw new Error("timeoutMs must be an integer from 1 through 60000");
  }

  const headers = {};
  for (const [name, value] of Object.entries(decoded.headers ?? {})) {
    if (typeof value !== "string") throw new Error(`header ${name} must have a string value`);
    headers[name.toLowerCase()] = value;
  }

  const preserveHeaders = new Set();
  for (const rawName of decoded.preserveHeaders ?? []) {
    const name = assertString(rawName, "preserveHeaders entry").toLowerCase();
    if (!(name in headers)) throw new Error(`preserved header ${name} is not configured`);
    if (
      DESTINATION_BOUND_HEADERS.has(name) ||
      HOP_BY_HOP_HEADERS.has(name) ||
      SENSITIVE_HEADER_NAME.test(name)
    ) {
      throw new Error(`refusing to preserve sensitive or connection-specific header ${name}`);
    }
    preserveHeaders.add(name);
  }

  const correlation = decoded.correlation ?? {};
  const correlationParameters = new URLSearchParams({
    __sbx_run: assertString(correlation.runId, "correlation.runId"),
    __sbx_test: assertString(correlation.testId, "correlation.testId"),
    __sbx_case: assertString(correlation.caseId, "correlation.caseId"),
    __sbx_canary: assertString(correlation.canary, "correlation.canary"),
  });

  return {
    baseUrl,
    rawPath,
    method: typeof decoded.method === "string" ? decoded.method.toUpperCase() : "GET",
    headers,
    preserveHeaders,
    correlationParameters,
    maxRedirects,
    timeoutMs,
  };
}

function appendCorrelation(rawTarget, correlationParameters) {
  const fragmentIndex = rawTarget.indexOf("#");
  const withoutFragment = fragmentIndex === -1 ? rawTarget : rawTarget.slice(0, fragmentIndex);
  const separator = withoutFragment.includes("?") ? "&" : "?";
  return `${withoutFragment}${separator}${correlationParameters.toString()}`;
}

function targetFromRedirect(location, previousUrl, correlationParameters) {
  const nextUrl = new URL(location, previousUrl);
  if (nextUrl.protocol !== "http:" && nextUrl.protocol !== "https:") {
    throw new Error(`redirect protocol ${nextUrl.protocol} is not supported`);
  }
  nextUrl.hash = "";
  const rawTarget = appendCorrelation(`${nextUrl.pathname}${nextUrl.search}`, correlationParameters);
  return { url: nextUrl, rawTarget };
}

function redirectedMethod(statusCode, method) {
  if (statusCode === 303 && method !== "HEAD") return "GET";
  if ((statusCode === 301 || statusCode === 302) && method === "POST") return "GET";
  return method;
}

function headersForRedirect(headers, preserveHeaders) {
  return Object.fromEntries(
    Object.entries(headers).filter(([name]) => preserveHeaders.has(name.toLowerCase())),
  );
}

function requestHop({ url, rawTarget, method, headers, timeoutMs }) {
  const client = url.protocol === "https:" ? https : http;
  return new Promise((resolve) => {
    const startedAt = Date.now();
    const request = client.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || undefined,
        method,
        path: rawTarget,
        headers,
        timeout: timeoutMs,
      },
      (response) => {
        let bodyLength = 0;
        let capturedLength = 0;
        const bodyChunks = [];
        response.on("data", (chunk) => {
          const bytes = Buffer.from(chunk);
          bodyLength += bytes.length;
          if (capturedLength < MAX_RESPONSE_BODY_BYTES) {
            const captured = bytes.subarray(0, MAX_RESPONSE_BODY_BYTES - capturedLength);
            bodyChunks.push(captured);
            capturedLength += captured.length;
          }
        });
        response.on("end", () => {
          resolve({
            ok: true,
            statusCode: response.statusCode ?? 0,
            location: response.headers.location,
            bodyLength,
            body: Buffer.concat(bodyChunks).toString("utf8"),
            durationMs: Date.now() - startedAt,
          });
        });
      },
    );
    request.on("timeout", () => request.destroy(new Error("request timed out")));
    request.on("error", (error) => {
      resolve({
        ok: false,
        error: error instanceof Error ? error.message : String(error),
        durationMs: Date.now() - startedAt,
      });
    });
    request.end();
  });
}

async function run(config) {
  let url = new URL(config.baseUrl);
  let rawTarget = appendCorrelation(config.rawPath, config.correlationParameters);
  let method = config.method;
  let headers = config.headers;
  let redirectsFollowed = 0;
  const hops = [];

  while (true) {
    const response = await requestHop({
      url,
      rawTarget,
      method,
      headers,
      timeoutMs: config.timeoutMs,
    });
    const hop = {
      index: hops.length,
      url: `${url.origin}${rawTarget}`,
      origin: url.origin,
      method,
      rawTarget,
      requestHeaderNames: Object.keys(headers).sort(),
      statusCode: response.ok ? response.statusCode : undefined,
      location: response.ok ? response.location : undefined,
      durationMs: response.durationMs,
      error: response.ok ? undefined : response.error,
    };
    hops.push(hop);

    if (!response.ok) {
      return { ok: false, error: response.error, redirectsFollowed, hops };
    }

    if (!REDIRECT_STATUS_CODES.has(response.statusCode) || !response.location) {
      return {
        ok: true,
        redirectsFollowed,
        hops,
        final: {
          url: hop.url,
          statusCode: response.statusCode,
          bodyLength: response.bodyLength,
          body: response.body,
          bodyTruncated: response.bodyLength > MAX_RESPONSE_BODY_BYTES,
        },
      };
    }

    if (redirectsFollowed >= config.maxRedirects) {
      return {
        ok: false,
        error: "redirect limit reached",
        redirectsFollowed,
        hops,
        final: { url: hop.url, statusCode: response.statusCode },
      };
    }

    let next;
    try {
      next = targetFromRedirect(response.location, url, config.correlationParameters);
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error.message : String(error),
        redirectsFollowed,
        hops,
        final: { url: hop.url, statusCode: response.statusCode },
      };
    }

    redirectsFollowed += 1;
    method = redirectedMethod(response.statusCode, method);
    headers = headersForRedirect(config.headers, config.preserveHeaders);
    url = next.url;
    rawTarget = next.rawTarget;
  }
}

const encoded = process.argv[2];
if (!encoded) {
  fail("missing base64url probe configuration");
} else {
  try {
    const result = await run(parseConfiguration(encoded));
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  }
}
