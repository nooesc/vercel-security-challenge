import "dotenv/config";

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { isIP } from "node:net";
import { defineSandboxProxy } from "@vercel/sandbox";
import { createRemoteJWKSet, decodeProtectedHeader, decodeJwt, jwtVerify, type JWTPayload } from "jose";

const TEST_ID = "SBX-034-POC";
const CASE_HEADER = "x-sbx034-case";
const CANARY_HEADER = "x-sbx-harness-canary";
const OIDC_HEADER = "vercel-sandbox-oidc-token";
const MAX_BODY_BYTES = 16_384;
const OPERATION_ID = /^redir_[A-Za-z0-9_-]{24}$/u;

export interface ReceiverConfiguration {
  runId: string;
  originalHost: string;
  forwardAudience: string;
  redirectUrl: string;
  expectedTeamId: string;
  expectedProjectId: string;
  expectedSandboxId: string;
  expectedSandboxName: string;
  correlationCanary: string;
}

export interface ARecord {
  observedAt: string;
  runId: string;
  testId: string;
  caseId: string;
  correlationId: string;
  requestUrl: string;
  authenticated: boolean;
  identityMatched: boolean;
  oidcHeaderCount: number;
  oidcValueCount: number;
  responseStatus: number;
  location?: string;
  operationId: string;
}

export interface IndependentOidcVerification {
  tokenOrdinal: number;
  verifier: "observer-b-independent-jose";
  signatureVerified: boolean;
  algorithm: string;
  issuer: string;
  jwksUrl: string;
  audience: string;
  temporalClaimsVerified: boolean;
  identity: {
    teamId: string;
    projectId: string;
    sandboxId: string;
    sessionId: string;
    sandboxName: string;
  };
  rawTokenRetained: false;
  verificationError?: string;
}

export interface BRecord {
  observedAt: string;
  runId: string;
  testId: string;
  caseId: string;
  correlationId: string;
  requestUrl: string;
  attributableToSourceRedirect: boolean;
  oidcHeaderCount: number;
  oidcValueCount: number;
  tokenVerified: boolean;
  algorithmRs256: boolean;
  issuerVerified: boolean;
  audienceVerified: boolean;
  exactClaimsVerified: boolean;
  teamId?: string;
  projectId?: string;
  sandboxId?: string;
  sandboxName?: string;
  oidcVerifications: IndependentOidcVerification[];
  operationId: string;
  responseStatus: number;
}

export interface DirectRecord {
  observedAt: string;
  caseId: string;
  canaryMatched: boolean;
  method: string;
  host?: string;
}

interface RunState {
  configuration: ReceiverConfiguration;
  aRecords: ARecord[];
  bRecords: BRecord[];
  directRecords: DirectRecord[];
}

interface ReceiverOptions {
  adminKey: string;
  aPublicOrigin: string;
  bPublicOrigin: string;
  aPort?: number;
  bPort?: number;
  host?: string;
}

interface ReceiverHandle {
  aServer: Server;
  bServer: Server;
  aPort: number;
  bPort: number;
  close(): Promise<void>;
}

const jwks = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function digest(value: string): Buffer {
  return createHash("sha256").update(value).digest();
}

function adminAuthorized(request: IncomingMessage, expectedKey: string): boolean {
  const supplied = request.headers.authorization;
  if (typeof supplied !== "string" || !supplied.startsWith("Bearer ")) return false;
  return timingSafeEqual(digest(supplied.slice(7)), digest(expectedKey));
}

function sendJson(response: ServerResponse, status: number, value: unknown): void {
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    "content-length": String(body.length),
  });
  response.end(body);
}

function sendEmpty(response: ServerResponse, status: number): void {
  response.writeHead(status, { "cache-control": "no-store", "content-length": "0" });
  response.end();
}

function safeOrigin(raw: string, name: string): URL {
  const parsed = new URL(raw);
  if (
    parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash ||
    parsed.pathname !== "/" || parsed.port || isIP(parsed.hostname) !== 0 || parsed.hostname !== parsed.hostname.toLowerCase()
  ) {
    throw new Error(`${name} must be an exact lower-case HTTPS origin without credentials, path, port, query, or fragment`);
  }
  return parsed;
}

function safeString(value: unknown, name: string, maximum = 512): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[\0\r\n]/u.test(value)) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

function validateConfiguration(value: unknown, aOrigin: URL, bOrigin: URL): ReceiverConfiguration {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("configuration must be an object");
  const input = value as Record<string, unknown>;
  const expectedKeys = [
    "correlationCanary", "expectedProjectId", "expectedSandboxId", "expectedSandboxName", "expectedTeamId",
    "forwardAudience", "originalHost", "redirectUrl", "runId",
  ].sort();
  const actualKeys = Object.keys(input).sort();
  if (actualKeys.length !== expectedKeys.length || actualKeys.some((key, index) => key !== expectedKeys[index])) {
    throw new Error("configuration fields are not exact");
  }
  const runId = safeString(input.runId, "runId", 128);
  const originalHost = safeString(input.originalHost, "originalHost", 253).toLowerCase();
  if (originalHost.includes(":")) throw new Error("originalHost must not contain a port");
  const forwardAudience = new URL(safeString(input.forwardAudience, "forwardAudience", 2_048));
  const redirectUrl = new URL(safeString(input.redirectUrl, "redirectUrl", 2_048));
  const expectedForward = new URL(`/v1/sbx034/forward/${encodeURIComponent(runId)}`, aOrigin);
  const expectedRedirect = new URL(`/v1/sbx034/target/${encodeURIComponent(runId)}`, bOrigin);
  if (forwardAudience.toString() !== expectedForward.toString()) throw new Error("forwardAudience is not the exact A receiver URL");
  if (redirectUrl.origin !== expectedRedirect.origin || redirectUrl.pathname !== expectedRedirect.pathname) {
    throw new Error("redirectUrl is not the exact B target path");
  }
  if (
    redirectUrl.searchParams.get("run") !== runId ||
    redirectUrl.searchParams.get("case") !== "redirect-attack" ||
    !redirectUrl.searchParams.get("canary")
  ) {
    throw new Error("redirectUrl correlation fields are invalid");
  }
  const correlationCanary = safeString(input.correlationCanary, "correlationCanary", 128);
  if (redirectUrl.searchParams.get("canary") !== correlationCanary) throw new Error("redirect canary mismatch");
  return {
    runId,
    originalHost,
    forwardAudience: forwardAudience.toString(),
    redirectUrl: redirectUrl.toString(),
    expectedTeamId: safeString(input.expectedTeamId, "expectedTeamId", 128),
    expectedProjectId: safeString(input.expectedProjectId, "expectedProjectId", 128),
    expectedSandboxId: safeString(input.expectedSandboxId, "expectedSandboxId", 128),
    expectedSandboxName: safeString(input.expectedSandboxName, "expectedSandboxName", 256),
    correlationCanary,
  };
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk);
    length += bytes.length;
    if (length > MAX_BODY_BYTES) throw new Error("request body too large");
    chunks.push(bytes);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function rawHeaderCount(request: IncomingMessage, name: string): { lines: number; values: number } {
  let lines = 0;
  let values = 0;
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === name) {
      lines += 1;
      values += request.rawHeaders[index + 1]?.split(",").length ?? 0;
    }
  }
  return { lines, values };
}

function requestHeaders(request: IncomingMessage): Headers {
  const headers = new Headers();
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    const name = request.rawHeaders[index];
    const value = request.rawHeaders[index + 1];
    if (name && value && name.toLowerCase() !== "connection") headers.append(name, value);
  }
  return headers;
}

function operationId(): string {
  const value = `redir_${randomBytes(18).toString("base64url")}`;
  if (!OPERATION_ID.test(value)) throw new Error("operation id invariant failed");
  return value;
}

function exactMeta(meta: { host: string; teamId: string; projectId: string; sandboxId: string; sandboxName: string }, config: ReceiverConfiguration): boolean {
  return meta.host.toLowerCase() === config.originalHost && meta.teamId === config.expectedTeamId &&
    meta.projectId === config.expectedProjectId && meta.sandboxId === config.expectedSandboxId &&
    meta.sandboxName === config.expectedSandboxName;
}

async function sendWebResponse(target: ServerResponse, source: Response): Promise<void> {
  const body = Buffer.from(await source.arrayBuffer());
  if (body.length > MAX_BODY_BYTES) throw new Error("generated response exceeded bound");
  const headers: Record<string, string> = {};
  source.headers.forEach((value, name) => { headers[name] = value; });
  headers["cache-control"] = "no-store";
  headers["content-length"] = String(body.length);
  target.writeHead(source.status, headers);
  target.end(body);
}

function claim(payload: JWTPayload, name: string): string | undefined {
  const value = payload[name];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function exactAudienceClaim(actual: JWTPayload["aud"], expected: string): boolean {
  return actual === expected || (Array.isArray(actual) && actual.length === 1 && actual[0] === expected);
}

function getJwks(issuer: string): ReturnType<typeof createRemoteJWKSet> {
  const existing = jwks.get(issuer);
  if (existing) return existing;
  const created = createRemoteJWKSet(new URL(`${issuer.replace(/\/$/u, "")}/.well-known/jwks`), {
    timeoutDuration: 5_000,
    cooldownDuration: 30_000,
  });
  jwks.set(issuer, created);
  return created;
}

async function verifyAtB(token: string, config: ReceiverConfiguration): Promise<{
  tokenVerified: boolean;
  algorithmRs256: boolean;
  issuerVerified: boolean;
  audienceVerified: boolean;
  exactClaimsVerified: boolean;
  teamId?: string;
  projectId?: string;
  sandboxId?: string;
  sandboxName?: string;
  oidcVerifications: IndependentOidcVerification[];
}> {
  let algorithmRs256 = false;
  let issuerVerified = false;
  try {
    algorithmRs256 = decodeProtectedHeader(token).alg === "RS256";
    if (!algorithmRs256) throw new Error("unexpected JWT algorithm");
    const decoded = decodeJwt(token);
    if (typeof decoded.iss !== "string") throw new Error("missing issuer");
    const issuerUrl = new URL(decoded.iss);
    issuerVerified = issuerUrl.protocol === "https:" && issuerUrl.hostname === "oidc.vercel.com";
    if (!issuerVerified) throw new Error("unexpected issuer");
    const { payload } = await jwtVerify(token, getJwks(decoded.iss), {
      algorithms: ["RS256"],
      issuer: decoded.iss,
      audience: config.forwardAudience,
      clockTolerance: 60,
    });
    const audienceVerified = exactAudienceClaim(payload.aud, config.forwardAudience);
    const teamId = claim(payload, "team_id");
    const projectId = claim(payload, "project_id");
    const sandboxId = claim(payload, "sandbox_id");
    const sandboxName = claim(payload, "sandbox_name") ?? sandboxId;
    const now = Math.floor(Date.now() / 1_000);
    const temporalClaimsVerified = typeof payload.iat === "number" && typeof payload.exp === "number" &&
      payload.exp > payload.iat && payload.iat <= now + 60 && payload.exp >= now - 60;
    const exactClaimsVerified = audienceVerified && teamId === config.expectedTeamId && projectId === config.expectedProjectId &&
      sandboxId === config.expectedSandboxId && sandboxName === config.expectedSandboxName;
    const verification: IndependentOidcVerification = {
      tokenOrdinal: 1,
      verifier: "observer-b-independent-jose",
      signatureVerified: true,
      algorithm: "RS256",
      issuer: decoded.iss,
      jwksUrl: `${decoded.iss.replace(/\/$/u, "")}/.well-known/jwks`,
      audience: audienceVerified ? config.forwardAudience : "non-exact-audience",
      temporalClaimsVerified,
      identity: {
        teamId: teamId ?? "missing",
        projectId: projectId ?? "missing",
        sandboxId: sandboxId ?? "missing",
        sessionId: sandboxId ?? "missing",
        sandboxName: sandboxName ?? "missing",
      },
      rawTokenRetained: false,
      ...(!audienceVerified
        ? { verificationError: "non-exact-audience" }
        : !exactClaimsVerified
          ? { verificationError: "exact-identity-mismatch" }
        : !temporalClaimsVerified
          ? { verificationError: "required-temporal-claims-missing-or-invalid" }
          : {}),
    };
    return {
      tokenVerified: exactClaimsVerified && temporalClaimsVerified,
      algorithmRs256,
      issuerVerified,
      audienceVerified,
      exactClaimsVerified,
      oidcVerifications: [verification],
      ...(teamId ? { teamId } : {}),
      ...(projectId ? { projectId } : {}),
      ...(sandboxId ? { sandboxId } : {}),
      ...(sandboxName ? { sandboxName } : {}),
    };
  } catch {
    return {
      tokenVerified: false,
      algorithmRs256,
      issuerVerified,
      audienceVerified: false,
      exactClaimsVerified: false,
      oidcVerifications: [],
    };
  }
}

function runIdFromPath(pathname: string, prefix: string): string | undefined {
  if (!pathname.startsWith(prefix)) return undefined;
  const value = pathname.slice(prefix.length).split("/")[0];
  if (!value) return undefined;
  try { return decodeURIComponent(value); } catch { return undefined; }
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

export async function createSbx034Receiver(options: ReceiverOptions): Promise<ReceiverHandle> {
  if (options.adminKey.length < 32 || /[\0\r\n]/u.test(options.adminKey)) throw new Error("adminKey must be at least 32 safe characters");
  const aOrigin = safeOrigin(options.aPublicOrigin, "aPublicOrigin");
  const bOrigin = safeOrigin(options.bPublicOrigin, "bPublicOrigin");
  if (aOrigin.origin === bOrigin.origin) throw new Error("A and B origins must be distinct");
  const states = new Map<string, RunState>();

  const aServer = createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", aOrigin);
      if (request.method === "GET" && url.pathname === "/healthz") return sendJson(response, 200, { ok: true, role: "A" });
      const adminRunId = runIdFromPath(url.pathname, "/v1/sbx034/admin/runs/");
      if (adminRunId && url.pathname === `/v1/sbx034/admin/runs/${encodeURIComponent(adminRunId)}`) {
        if (!adminAuthorized(request, options.adminKey)) return sendJson(response, 401, { error: "unauthorized" });
        if (request.method === "POST") {
          if (states.has(adminRunId)) return sendJson(response, 409, { error: "already configured" });
          const configuration = validateConfiguration(await readJson(request), aOrigin, bOrigin);
          if (configuration.runId !== adminRunId) return sendJson(response, 400, { error: "run mismatch" });
          states.set(adminRunId, { configuration, aRecords: [], bRecords: [], directRecords: [] });
          return sendJson(response, 201, { configured: true });
        }
        if (request.method === "GET") {
          const state = states.get(adminRunId);
          return state
            ? sendJson(response, 200, { configured: true, aRecords: state.aRecords, bRecords: state.bRecords, directRecords: state.directRecords })
            : sendJson(response, 404, { configured: false });
        }
        if (request.method === "DELETE") {
          const deleted = states.delete(adminRunId);
          return sendJson(response, deleted ? 200 : 404, { deleted });
        }
        return sendJson(response, 405, { error: "method not allowed" });
      }

      const runId = runIdFromPath(url.pathname, "/v1/sbx034/forward/");
      const state = runId ? states.get(runId) : undefined;
      if (!runId || !state || request.method !== "GET") return sendJson(response, 404, { error: "not found" });
      const caseId = request.headers[CASE_HEADER];
      const canary = request.headers[CANARY_HEADER];
      if (typeof caseId !== "string" || typeof canary !== "string" || canary !== state.configuration.correlationCanary) {
        return sendJson(response, 400, { error: "invalid correlation" });
      }
      const oidcCounts = rawHeaderCount(request, OIDC_HEADER);
      const publicRequest = new Request(new URL(request.url ?? "/", aOrigin), {
        method: "GET",
        headers: requestHeaders(request),
      });
      const handler = defineSandboxProxy(
        async (_proxiedRequest, meta) => {
          const identityMatched = exactMeta(meta, state.configuration);
          const id = operationId();
          const redirect = caseId === "redirect-attack";
          const status = identityMatched ? (redirect ? 307 : 202) : 403;
          state.aRecords.push({
            observedAt: new Date().toISOString(), runId, testId: TEST_ID, caseId,
            correlationId: canary, requestUrl: publicRequest.url,
            authenticated: true, identityMatched,
            oidcHeaderCount: oidcCounts.lines, oidcValueCount: oidcCounts.values,
            responseStatus: status, ...(redirect ? { location: state.configuration.redirectUrl } : {}), operationId: id,
          });
          if (!identityMatched) return Response.json({ authenticated: false, operationId: id }, { status });
          if (redirect) {
            return new Response(null, { status: 307, headers: { Location: state.configuration.redirectUrl, "Cache-Control": "no-store" } });
          }
          return Response.json({ authenticated: true, operationId: id }, { status: 202 });
        },
        async () => {
          const id = operationId();
          state.aRecords.push({
            observedAt: new Date().toISOString(), runId, testId: TEST_ID, caseId,
            correlationId: canary, requestUrl: publicRequest.url,
            authenticated: false, identityMatched: false,
            oidcHeaderCount: oidcCounts.lines, oidcValueCount: oidcCounts.values,
            responseStatus: 403, operationId: id,
          });
          return Response.json({ authenticated: false, operationId: id }, { status: 403 });
        },
      );
      await sendWebResponse(response, await handler(publicRequest));
    } catch {
      if (!response.headersSent) sendJson(response, 500, { error: "receiver error" });
      else response.destroy();
    }
  });

  const bServer = createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", bOrigin);
      if (request.method === "GET" && url.pathname === "/healthz") return sendJson(response, 200, { ok: true, role: "B" });
      const directRunId = runIdFromPath(url.pathname, "/v1/sbx034/direct/");
      if (directRunId && request.method === "GET") {
        const state = states.get(directRunId);
        if (!state) return sendJson(response, 404, { error: "not configured" });
        const caseId = url.searchParams.get("case") ?? "missing";
        state.directRecords.push({
          observedAt: new Date().toISOString(), caseId,
          canaryMatched: url.searchParams.get("canary") === state.configuration.correlationCanary,
          method: "GET", ...(request.headers.host ? { host: request.headers.host } : {}),
        });
        return sendEmpty(response, 204);
      }
      const runId = runIdFromPath(url.pathname, "/v1/sbx034/target/");
      const state = runId ? states.get(runId) : undefined;
      if (!runId || !state || request.method !== "GET") return sendJson(response, 404, { error: "not found" });
      const caseId = url.searchParams.get("case") ?? "missing";
      const correlated = url.searchParams.get("run") === runId && caseId === "redirect-attack" &&
        url.searchParams.get("canary") === state.configuration.correlationCanary;
      const counts = rawHeaderCount(request, OIDC_HEADER);
      const token = counts.lines === 1 && counts.values === 1 && typeof request.headers[OIDC_HEADER] === "string"
        ? request.headers[OIDC_HEADER]
        : undefined;
      const verified = token && correlated
        ? await verifyAtB(token, state.configuration)
        : {
            tokenVerified: false, algorithmRs256: false, issuerVerified: false,
            audienceVerified: false, exactClaimsVerified: false, oidcVerifications: [],
          };
      const id = operationId();
      const status = verified.tokenVerified ? 200 : 401;
      state.bRecords.push({
        observedAt: new Date().toISOString(), runId, testId: TEST_ID, caseId,
        correlationId: url.searchParams.get("canary") ?? "missing",
        requestUrl: url.toString(), attributableToSourceRedirect: correlated,
        oidcHeaderCount: counts.lines, oidcValueCount: counts.values,
        ...verified, operationId: id, responseStatus: status,
      });
      return sendJson(response, status, { received: true, tokenVerified: verified.tokenVerified, operationId: id });
    } catch {
      if (!response.headersSent) sendJson(response, 500, { error: "receiver error" });
      else response.destroy();
    }
  });

  const listen = async (server: Server, port: number): Promise<number> => {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, options.host ?? "127.0.0.1", () => { server.off("error", reject); resolve(); });
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("receiver did not bind a TCP address");
    return address.port;
  };
  const aPort = await listen(aServer, options.aPort ?? 0);
  let bPort: number;
  try { bPort = await listen(bServer, options.bPort ?? 0); } catch (error) { await closeServer(aServer); throw error; }
  return {
    aServer, bServer, aPort, bPort,
    async close() { await Promise.all([closeServer(aServer), closeServer(bServer)]); },
  };
}

async function cli(): Promise<void> {
  const adminKey = process.env.SBX034_ADMIN_KEY;
  const aPublicOrigin = process.env.SBX034_A_PUBLIC_ORIGIN;
  const bPublicOrigin = process.env.SBX034_B_PUBLIC_ORIGIN;
  if (!adminKey || !aPublicOrigin || !bPublicOrigin) {
    throw new Error("SBX034_ADMIN_KEY, SBX034_A_PUBLIC_ORIGIN, and SBX034_B_PUBLIC_ORIGIN are required");
  }
  const receiver = await createSbx034Receiver({
    adminKey, aPublicOrigin, bPublicOrigin,
    aPort: Number(process.env.SBX034_A_PORT ?? "43134"),
    bPort: Number(process.env.SBX034_B_PORT ?? "43135"),
    host: process.env.SBX034_LISTEN_HOST ?? "127.0.0.1",
  });
  process.stdout.write(`${JSON.stringify({ ready: true, aPort: receiver.aPort, bPort: receiver.bPort })}\n`);
  const shutdown = async () => { await receiver.close(); process.exit(0); };
  process.once("SIGINT", () => void shutdown());
  process.once("SIGTERM", () => void shutdown());
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  cli().catch((error) => {
    process.stderr.write(`${String(error instanceof Error ? error.message : error).slice(0, 512)}\n`);
    process.exitCode = 1;
  });
}
