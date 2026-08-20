import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingHttpHeaders, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { appendFile, mkdir, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { AddressInfo } from "node:net";
import { defineSandboxProxy } from "@vercel/sandbox";
import type { ObserverEvent } from "./contracts.js";

const DEFAULT_MAX_BODY_BYTES = 64 * 1024;
const CANARY_HEADER = "x-sbx-harness-canary";
const ACTION_SECRET_HEADER = "x-observer-action-secret";
const REDIRECT_TARGET_HEADER = "x-observer-redirect-target";
const VHOST_HEADER = "x-observer-vhost";
const PROXY_ACTION_URL_HEADER = "x-observer-proxy-action-url";
const PROXY_FAKE_OIDC_SHA256_HEADER = "x-observer-proxy-fake-oidc-sha256";
const PROXY_CASE_HEADER = "x-sbx-forward-case";
const PROXY_RESERVED_METADATA_HEADERS = new Set([
  "vercel-forwarded-host",
  "vercel-forwarded-scheme",
  "vercel-forwarded-port",
  "vercel-forwarded-path",
]);

type AdminResource =
  | "action-config"
  | "actions"
  | "redirect-config"
  | "vhost-config"
  | "vhost-actions"
  | "proxy-config"
  | "proxy-actions";

interface RecordedAction {
  operationId: string;
  authorizedAt: string;
  caseId: string;
  normalizedPath: string;
}

interface ActionConfiguration {
  brokeredSecret: string;
  actions: RecordedAction[];
}

interface VhostConfiguration {
  expectedHost: string;
  expectedSecret?: string;
  actions: RecordedAction[];
}

interface ProxyAuthenticationRecord {
  operationId: string;
  authenticatedAt: string;
  caseId: string;
  authenticated: boolean;
  actionAuthorized: boolean;
  reconstructedUrl?: string;
  proxyMeta?: {
    host: string;
    teamId: string;
    projectId: string;
    sandboxId: string;
    sandboxName: string;
  };
  invalidReasonCode?: "missing-proxy-metadata" | "invalid-proxied-url" | "oidc-verification-failed";
  rawHeaderAudit: ProxyRawHeaderAudit;
}

interface ProxyConfiguration {
  actionUrl: string;
  expectedGuestFakeOidcSha256: string;
  records: ProxyAuthenticationRecord[];
}

interface ProxyRawHeaderField {
  position: number;
  name: string;
  value: string;
}

interface ProxyRawHeaderAudit {
  caseId: string;
  caseHeaderCount: number;
  caseIdMatched: boolean;
  oidcHeaderCount: number;
  oidcValueCount: number;
  guestFakeOidcObserved: boolean;
  intermediaryOrderTrusted: false;
  forwardedFields: ProxyRawHeaderField[];
}

interface BodyMetadata {
  bodyLength: number;
  bodySha256: string;
  tooLarge: boolean;
}

export interface ObserverServerOptions {
  adminKey: string;
  dataPath: string;
  host?: string;
  port?: number;
  maxBodyBytes?: number;
}

export interface RunningObserverServer {
  server: Server;
  baseUrl: string;
  host: string;
  port: number;
  close(): Promise<void>;
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  response.end(JSON.stringify(body));
}

function isSensitiveHeader(name: string): boolean {
  const normalized = name.toLowerCase();
  if (normalized === CANARY_HEADER) return false;
  if (
    normalized === "authorization" ||
    normalized === "proxy-authorization" ||
    normalized === "cookie" ||
    normalized === "set-cookie"
  ) {
    return true;
  }
  return /(^|[-_])(auth|authorization|cookie|token|secret|api[-_]?key|key)([-_]|$)/i.test(normalized);
}

function sanitizeHeaders(headers: IncomingHttpHeaders): Record<string, string | string[]> {
  const sanitized: Record<string, string | string[]> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined || isSensitiveHeader(name)) continue;
    sanitized[name.toLowerCase()] = value;
  }
  return sanitized;
}

function sanitizeRawHeaders(rawHeaders: string[]): string[] {
  const sanitized: string[] = [];
  for (let index = 0; index + 1 < rawHeaders.length; index += 2) {
    const name = rawHeaders[index];
    const value = rawHeaders[index + 1];
    if (name === undefined || value === undefined || isSensitiveHeader(name)) continue;
    sanitized.push(name, value);
  }
  return sanitized;
}

function keyMatches(header: string | undefined, adminKey: string): boolean {
  if (!header?.startsWith("Bearer ")) return false;
  const suppliedDigest = createHash("sha256").update(header.slice(7)).digest();
  const expectedDigest = createHash("sha256").update(adminKey).digest();
  return timingSafeEqual(suppliedDigest, expectedDigest);
}

function singleHeader(headers: IncomingHttpHeaders, name: string): string | undefined {
  const value = headers[name];
  return Array.isArray(value) ? value[0] : value;
}

function secretMatches(supplied: string | undefined, expected: string): boolean {
  if (!supplied) return false;
  const suppliedDigest = createHash("sha256").update(supplied).digest();
  const expectedDigest = createHash("sha256").update(expected).digest();
  return timingSafeEqual(suppliedDigest, expectedDigest);
}

async function readBodyMetadata(request: IncomingMessage, maxBodyBytes: number): Promise<BodyMetadata> {
  const hash = createHash("sha256");
  let bodyLength = 0;
  let tooLarge = false;

  for await (const unknownChunk of request) {
    const chunk = Buffer.isBuffer(unknownChunk) ? unknownChunk : Buffer.from(unknownChunk as string);
    bodyLength += chunk.length;
    hash.update(chunk);
    if (bodyLength > maxBodyBytes) tooLarge = true;
  }

  return {
    bodyLength,
    bodySha256: hash.digest("hex"),
    tooLarge,
  };
}

class JsonlObserverStore {
  private appendQueue: Promise<void> = Promise.resolve();

  constructor(private readonly dataPath: string) {}

  async initialize(): Promise<void> {
    await mkdir(dirname(this.dataPath), { recursive: true, mode: 0o700 });
  }

  async append(event: ObserverEvent): Promise<void> {
    const operation = this.appendQueue.then(async () => {
      await appendFile(this.dataPath, `${JSON.stringify(event)}\n`, {
        encoding: "utf8",
        mode: 0o600,
      });
    });
    this.appendQueue = operation.catch(() => undefined);
    await operation;
  }

  async forRun(runId: string): Promise<ObserverEvent[]> {
    await this.appendQueue;
    let contents: string;
    try {
      contents = await readFile(this.dataPath, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }

    const events: ObserverEvent[] = [];
    for (const line of contents.split("\n")) {
      if (line.length === 0) continue;
      const event = JSON.parse(line) as ObserverEvent;
      if (event.runId === runId) events.push(event);
    }
    return events;
  }
}

function requiredProbeFields(url: URL): Pick<ObserverEvent, "runId" | "testId" | "caseId" | "canary"> | undefined {
  const runId = url.searchParams.get("__sbx_run");
  const testId = url.searchParams.get("__sbx_test");
  const caseId = url.searchParams.get("__sbx_case");
  const canary = url.searchParams.get("__sbx_canary");
  if (!runId || !testId || !caseId || !canary) return undefined;
  return { runId, testId, caseId, canary };
}

function requestUrl(request: IncomingMessage): URL | undefined {
  try {
    return new URL(request.url ?? "/", "http://observer.invalid");
  } catch {
    return undefined;
  }
}

function eventRoute(pathname: string): string | undefined {
  const match = /^\/v1\/runs\/([^/]+)\/events$/.exec(pathname);
  if (!match?.[1]) return undefined;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return undefined;
  }
}

function adminRoute(pathname: string): { runId: string; resource: AdminResource } | undefined {
  const match = /^\/v1\/runs\/([^/]+)\/(action-config|actions|redirect-config|vhost-config|vhost-actions|proxy-config|proxy-actions)$/.exec(pathname);
  if (!match?.[1] || !match[2]) return undefined;
  try {
    return {
      runId: decodeURIComponent(match[1]),
      resource: match[2] as AdminResource,
    };
  } catch {
    return undefined;
  }
}

function forwardProxyRun(pathname: string): string | undefined {
  const match = /^\/v1\/proxy\/([^/]+)\/forward(?:\/.*)?$/.exec(pathname);
  if (!match?.[1]) return undefined;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return undefined;
  }
}

function outsideActionRun(pathname: string): string | undefined {
  const match = /^\/v1\/probe\/([^/]+)\/outside$/.exec(pathname);
  if (!match?.[1]) return undefined;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return undefined;
  }
}

function redirectRun(pathname: string): string | undefined {
  const match = /^\/v1\/probe\/([^/]+)\/redirect$/.exec(pathname);
  if (!match?.[1]) return undefined;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return undefined;
  }
}

function vhostActionRun(pathname: string): string | undefined {
  const match = /^\/v1\/probe\/([^/]+)\/vhost-action$/.exec(pathname);
  if (!match?.[1]) return undefined;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return undefined;
  }
}

function validRedirectTarget(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  try {
    const target = new URL(raw);
    if (target.protocol !== "https:" || target.username || target.password || target.hash) return undefined;
    return target.toString();
  } catch {
    return undefined;
  }
}

function validProxyActionUrl(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  try {
    const target = new URL(raw);
    if (
      target.protocol !== "https:" ||
      target.username ||
      target.password ||
      target.search ||
      target.hash
    ) {
      return undefined;
    }
    return target.toString();
  } catch {
    return undefined;
  }
}

function requestHeaders(request: IncomingMessage): Headers {
  const headers = new Headers();
  for (let index = 0; index + 1 < request.rawHeaders.length; index += 2) {
    const name = request.rawHeaders[index];
    const value = request.rawHeaders[index + 1];
    if (name === undefined || value === undefined) continue;
    const normalized = name.toLowerCase();
    if (normalized === "connection" || normalized === "content-length" || normalized === "transfer-encoding") {
      continue;
    }
    headers.append(name, value);
  }
  return headers;
}

function proxyInvalidReasonCode(
  error: Error,
): NonNullable<ProxyAuthenticationRecord["invalidReasonCode"]> {
  if (error.message === "Missing required proxy headers") return "missing-proxy-metadata";
  if (error.message === "Invalid proxied request URL") return "invalid-proxied-url";
  return "oidc-verification-failed";
}

function proxyRawHeaderAudit(
  rawHeaders: string[],
  caseId: string,
  expectedGuestFakeOidcSha256: string,
): ProxyRawHeaderAudit {
  const forwardedFields: ProxyRawHeaderField[] = [];
  let caseHeaderCount = 0;
  let caseIdMatched = false;
  let oidcHeaderCount = 0;
  let oidcValueCount = 0;
  let guestFakeOidcObserved = false;

  for (let index = 0; index + 1 < rawHeaders.length; index += 2) {
    const rawName = rawHeaders[index];
    const rawValue = rawHeaders[index + 1];
    if (rawName === undefined || rawValue === undefined) continue;
    const name = rawName.toLowerCase();
    if (name === PROXY_CASE_HEADER) {
      caseHeaderCount += 1;
      if (rawValue === caseId) caseIdMatched = true;
      continue;
    }
    if (name === "vercel-sandbox-oidc-token") {
      oidcHeaderCount += 1;
      const values = rawValue.split(/,\s*/u).filter(Boolean);
      oidcValueCount += values.length;
      if (
        values.some((value) =>
          createHash("sha256").update(value).digest("hex") === expectedGuestFakeOidcSha256
        )
      ) {
        guestFakeOidcObserved = true;
      }
      continue;
    }
    if (PROXY_RESERVED_METADATA_HEADERS.has(name) && forwardedFields.length < 32) {
      forwardedFields.push({
        position: index / 2,
        name,
        value: rawValue.slice(0, 2_048),
      });
    }
  }

  return {
    caseId,
    caseHeaderCount,
    caseIdMatched,
    oidcHeaderCount,
    oidcValueCount,
    guestFakeOidcObserved,
    // Cloudflare Quick Tunnels may normalize duplicates before this application hop.
    intermediaryOrderTrusted: false,
    forwardedFields,
  };
}

async function sendFetchResponse(response: ServerResponse, fetchResponse: Response): Promise<void> {
  const body = Buffer.from(await fetchResponse.arrayBuffer());
  const headers: Record<string, string> = {};
  fetchResponse.headers.forEach((value, name) => {
    headers[name] = value;
  });
  response.writeHead(fetchResponse.status, headers);
  response.end(body);
}

function normalizedHostname(raw: string | undefined): string | undefined {
  if (!raw || raw.includes("@") || raw.includes("/") || raw.includes("?") || raw.includes("#")) return undefined;
  try {
    const parsed = new URL(`https://${raw}/`);
    return parsed.hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

export async function startObserverServer(options: ObserverServerOptions): Promise<RunningObserverServer> {
  if (options.adminKey.length < 24) throw new Error("observer admin key must contain at least 24 characters");
  const maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes <= 0) {
    throw new Error("maxBodyBytes must be a positive integer");
  }

  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 0;
  const store = new JsonlObserverStore(options.dataPath);
  const actionConfigurations = new Map<string, ActionConfiguration>();
  const redirectConfigurations = new Map<string, string>();
  const vhostConfigurations = new Map<string, VhostConfiguration>();
  const proxyConfigurations = new Map<string, ProxyConfiguration>();
  await store.initialize();

  const server = createServer((request, response) => {
    void (async () => {
      const url = requestUrl(request);
      if (!url) {
        sendJson(response, 400, { error: "invalid request URL" });
        return;
      }

      if (request.method === "GET" && url.pathname === "/healthz") {
        sendJson(response, 200, { ok: true });
        return;
      }

      const admin = adminRoute(url.pathname);
      if (admin) {
        const authorization = singleHeader(request.headers, "authorization");
        if (!keyMatches(authorization, options.adminKey)) {
          sendJson(response, 401, { error: "unauthorized" });
          return;
        }
        if (request.method === "POST" && admin.resource === "action-config") {
          const brokeredSecret = singleHeader(request.headers, ACTION_SECRET_HEADER);
          if (!brokeredSecret || brokeredSecret.length < 24) {
            sendJson(response, 400, { error: `${ACTION_SECRET_HEADER} must contain at least 24 characters` });
            return;
          }
          actionConfigurations.set(admin.runId, { brokeredSecret, actions: [] });
          sendJson(response, 201, { configured: true });
          return;
        }
        if (request.method === "GET" && admin.resource === "actions") {
          sendJson(response, 200, {
            actions: actionConfigurations.get(admin.runId)?.actions ?? [],
          });
          return;
        }
        if (request.method === "DELETE" && admin.resource === "action-config") {
          actionConfigurations.delete(admin.runId);
          response.writeHead(204, { "cache-control": "no-store" });
          response.end();
          return;
        }
        if (request.method === "POST" && admin.resource === "redirect-config") {
          const target = validRedirectTarget(singleHeader(request.headers, REDIRECT_TARGET_HEADER));
          if (!target) {
            sendJson(response, 400, { error: `${REDIRECT_TARGET_HEADER} must be an absolute HTTPS URL without credentials or a fragment` });
            return;
          }
          redirectConfigurations.set(admin.runId, target);
          sendJson(response, 201, { configured: true });
          return;
        }
        if (request.method === "DELETE" && admin.resource === "redirect-config") {
          redirectConfigurations.delete(admin.runId);
          response.writeHead(204, { "cache-control": "no-store" });
          response.end();
          return;
        }
        if (request.method === "POST" && admin.resource === "vhost-config") {
          const expectedHost = normalizedHostname(singleHeader(request.headers, VHOST_HEADER));
          if (!expectedHost) {
            sendJson(response, 400, { error: `${VHOST_HEADER} must be a valid hostname or host:port authority` });
            return;
          }
          const expectedSecret = singleHeader(request.headers, ACTION_SECRET_HEADER);
          if (expectedSecret !== undefined && expectedSecret.length < 24) {
            sendJson(response, 400, { error: `${ACTION_SECRET_HEADER} must contain at least 24 characters when supplied` });
            return;
          }
          vhostConfigurations.set(admin.runId, {
            expectedHost,
            ...(expectedSecret ? { expectedSecret } : {}),
            actions: [],
          });
          sendJson(response, 201, { configured: true });
          return;
        }
        if (request.method === "GET" && admin.resource === "vhost-actions") {
          sendJson(response, 200, { actions: vhostConfigurations.get(admin.runId)?.actions ?? [] });
          return;
        }
        if (request.method === "DELETE" && admin.resource === "vhost-config") {
          vhostConfigurations.delete(admin.runId);
          response.writeHead(204, { "cache-control": "no-store" });
          response.end();
          return;
        }
        if (request.method === "POST" && admin.resource === "proxy-config") {
          const actionUrl = validProxyActionUrl(singleHeader(request.headers, PROXY_ACTION_URL_HEADER));
          const expectedGuestFakeOidcSha256 = singleHeader(
            request.headers,
            PROXY_FAKE_OIDC_SHA256_HEADER,
          );
          if (!actionUrl || !/^[a-f0-9]{64}$/u.test(expectedGuestFakeOidcSha256 ?? "")) {
            sendJson(response, 400, {
              error: `${PROXY_ACTION_URL_HEADER} and ${PROXY_FAKE_OIDC_SHA256_HEADER} are required`,
            });
            return;
          }
          proxyConfigurations.set(admin.runId, {
            actionUrl,
            expectedGuestFakeOidcSha256: expectedGuestFakeOidcSha256!,
            records: [],
          });
          sendJson(response, 201, { configured: true });
          return;
        }
        if (request.method === "GET" && admin.resource === "proxy-config") {
          const configuration = proxyConfigurations.get(admin.runId);
          sendJson(response, 200, {
            configured: configuration !== undefined,
            ...(configuration ? { actionUrl: configuration.actionUrl } : {}),
          });
          return;
        }
        if (request.method === "GET" && admin.resource === "proxy-actions") {
          sendJson(response, 200, { records: proxyConfigurations.get(admin.runId)?.records ?? [] });
          return;
        }
        if (request.method === "DELETE" && admin.resource === "proxy-config") {
          proxyConfigurations.delete(admin.runId);
          response.writeHead(204, { "cache-control": "no-store" });
          response.end();
          return;
        }
        sendJson(response, 405, { error: "method not allowed" });
        return;
      }

      const queriedRunId = request.method === "GET" ? eventRoute(url.pathname) : undefined;
      if (queriedRunId !== undefined) {
        const authorization = singleHeader(request.headers, "authorization");
        if (!keyMatches(authorization, options.adminKey)) {
          sendJson(response, 401, { error: "unauthorized" });
          return;
        }
        sendJson(response, 200, { events: await store.forRun(queriedRunId) });
        return;
      }

      const proxyRunId = request.method === "GET" ? forwardProxyRun(url.pathname) : undefined;
      if (proxyRunId !== undefined) {
        const configuration = proxyConfigurations.get(proxyRunId);
        if (!configuration) {
          sendJson(response, 404, { error: "proxy not configured" });
          return;
        }
        const caseId = singleHeader(request.headers, PROXY_CASE_HEADER);
        const canary = singleHeader(request.headers, CANARY_HEADER);
        if (!caseId || !canary) {
          sendJson(response, 400, { error: "missing proxy correlation headers" });
          return;
        }
        const rawHeaderAudit = proxyRawHeaderAudit(
          request.rawHeaders,
          caseId,
          configuration.expectedGuestFakeOidcSha256,
        );
        const body = await readBodyMetadata(request, maxBodyBytes);
        const event: ObserverEvent = {
          schemaVersion: 1,
          observedAt: new Date().toISOString(),
          runId: proxyRunId,
          testId: "SBX-023-POC",
          caseId,
          canary,
          method: "GET",
          rawUrl: request.url ?? "/",
          normalizedPath: url.pathname,
          ...(request.headers.host ? { host: request.headers.host } : {}),
          ...(request.socket.remoteAddress ? { remoteAddress: request.socket.remoteAddress } : {}),
          headers: sanitizeHeaders(request.headers),
          rawHeaders: sanitizeRawHeaders(request.rawHeaders),
          bodyLength: body.bodyLength,
          bodySha256: body.bodySha256,
        };
        await store.append(event);
        if (body.tooLarge) {
          sendJson(response, 413, { error: "request body too large" });
          return;
        }

        const host = singleHeader(request.headers, "host");
        if (!host || host.includes("/") || host.includes("@")) {
          sendJson(response, 400, { error: "invalid proxy Host header" });
          return;
        }
        let publicRequestUrl: URL;
        try {
          publicRequestUrl = new URL(request.url ?? "/", `https://${host}`);
        } catch {
          sendJson(response, 400, { error: "invalid proxy request URL" });
          return;
        }

        const proxyHandler = defineSandboxProxy(
          async (proxiedRequest, meta) => {
            const reconstructed = new URL(proxiedRequest.url);
            const expected = new URL(configuration.actionUrl);
            const actionAuthorized =
              reconstructed.origin === expected.origin &&
              reconstructed.pathname === expected.pathname;
            const operationId = `proxy_${randomBytes(18).toString("base64url")}`;
            configuration.records.push({
              operationId,
              authenticatedAt: new Date().toISOString(),
              caseId,
              authenticated: true,
              actionAuthorized,
              reconstructedUrl: reconstructed.toString(),
              proxyMeta: meta,
              rawHeaderAudit,
            });
            return Response.json(
              { authenticated: true, actionAuthorized, operationId },
              { status: actionAuthorized ? 200 : 202 },
            );
          },
          async (_proxiedRequest, error) => {
            const operationId = `proxy_${randomBytes(18).toString("base64url")}`;
            configuration.records.push({
              operationId,
              authenticatedAt: new Date().toISOString(),
              caseId,
              authenticated: false,
              actionAuthorized: false,
              invalidReasonCode: proxyInvalidReasonCode(error),
              rawHeaderAudit,
            });
            return Response.json(
              { authenticated: false, actionAuthorized: false, operationId },
              { status: 403 },
            );
          },
        );
        await sendFetchResponse(
          response,
          await proxyHandler(new Request(publicRequestUrl, {
            method: "GET",
            headers: requestHeaders(request),
          })),
        );
        return;
      }

      const fields = requiredProbeFields(url);
      if (!fields) {
        sendJson(response, 404, { error: "not found" });
        return;
      }

      const body = await readBodyMetadata(request, maxBodyBytes);
      const event: ObserverEvent = {
        schemaVersion: 1,
        observedAt: new Date().toISOString(),
        ...fields,
        method: request.method ?? "UNKNOWN",
        rawUrl: request.url ?? "/",
        normalizedPath: url.pathname,
        ...(request.headers.host ? { host: request.headers.host } : {}),
        ...(request.socket.remoteAddress ? { remoteAddress: request.socket.remoteAddress } : {}),
        headers: sanitizeHeaders(request.headers),
        rawHeaders: sanitizeRawHeaders(request.rawHeaders),
        bodyLength: body.bodyLength,
        bodySha256: body.bodySha256,
      };
      await store.append(event);
      if (body.tooLarge) {
        sendJson(response, 413, { error: "request body too large" });
        return;
      }
      const outsideRunId = outsideActionRun(event.normalizedPath);
      if (outsideRunId !== undefined && outsideRunId === fields.runId) {
        const actionConfiguration = actionConfigurations.get(outsideRunId);
        const suppliedSecret = singleHeader(request.headers, CANARY_HEADER);
        if (!actionConfiguration || !secretMatches(suppliedSecret, actionConfiguration.brokeredSecret)) {
          sendJson(response, 401, {
            authorized: false,
            normalizedPath: event.normalizedPath,
          });
          return;
        }
        const action: RecordedAction = {
          operationId: `op_${randomBytes(18).toString("base64url")}`,
          authorizedAt: new Date().toISOString(),
          caseId: fields.caseId,
          normalizedPath: event.normalizedPath,
        };
        actionConfiguration.actions.push(action);
        sendJson(response, 200, {
          authorized: true,
          operationId: action.operationId,
          normalizedPath: event.normalizedPath,
        });
        return;
      }
      const configuredRedirectRun = redirectRun(event.normalizedPath);
      if (configuredRedirectRun !== undefined && configuredRedirectRun === fields.runId) {
        const target = redirectConfigurations.get(configuredRedirectRun);
        if (!target) {
          sendJson(response, 404, { error: "redirect not configured" });
          return;
        }
        response.writeHead(302, {
          "cache-control": "no-store",
          location: target,
        });
        response.end();
        return;
      }
      const configuredVhostRun = vhostActionRun(event.normalizedPath);
      if (configuredVhostRun !== undefined && configuredVhostRun === fields.runId) {
        const configuration = vhostConfigurations.get(configuredVhostRun);
        const observedHost = normalizedHostname(request.headers.host);
        if (!configuration || observedHost !== configuration.expectedHost) {
          sendJson(response, 421, {
            selected: false,
            normalizedPath: event.normalizedPath,
          });
          return;
        }
        if (
          configuration.expectedSecret !== undefined &&
          !secretMatches(singleHeader(request.headers, CANARY_HEADER), configuration.expectedSecret)
        ) {
          sendJson(response, 401, {
            selected: true,
            authorized: false,
            normalizedPath: event.normalizedPath,
          });
          return;
        }
        const action: RecordedAction = {
          operationId: `vhost_${randomBytes(18).toString("base64url")}`,
          authorizedAt: new Date().toISOString(),
          caseId: fields.caseId,
          normalizedPath: event.normalizedPath,
        };
        configuration.actions.push(action);
        sendJson(response, 200, {
          selected: true,
          authorized: true,
          operationId: action.operationId,
          normalizedPath: event.normalizedPath,
        });
        return;
      }
      if (/^\/v1\/probe\/[^/]+\/policy-update(?:-multi)?$/.test(event.normalizedPath)) {
        response.writeHead(204, {
          "cache-control": "no-store",
          "content-length": "0",
          connection: "keep-alive",
          "keep-alive": "timeout=60",
        });
        response.end();
        return;
      }
      response.writeHead(204, { "cache-control": "no-store" });
      response.end();
    })().catch(() => {
      if (!response.headersSent) sendJson(response, 500, { error: "internal server error" });
      else response.destroy();
    });
  });

  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = (): void => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, host);
  });

  const address = server.address() as AddressInfo | null;
  if (!address) {
    server.close();
    throw new Error("observer server did not expose a listening address");
  }
  const urlHost = address.family === "IPv6" ? `[${address.address}]` : address.address;

  return {
    server,
    baseUrl: `http://${urlHost}:${address.port}`,
    host: address.address,
    port: address.port,
    close: async () => {
      if (!server.listening) return;
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    },
  };
}
