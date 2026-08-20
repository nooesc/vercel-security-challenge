import "dotenv/config";

import { createHash, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { isIP } from "node:net";
import { pathToFileURL } from "node:url";
import { defineSandboxProxy } from "@vercel/sandbox";
import { createRemoteJWKSet, decodeJwt, decodeProtectedHeader, jwtVerify, type JWTPayload } from "jose";
import {
  SBX058_CANARY,
  SBX058_CANARY_HEADER,
  SBX058_CASE_HEADER,
  SBX058_DECOY_HEADER,
  SBX058_EVENT_CASES,
  SBX058_MATCH_HEADER,
  SBX058_MATCH_VALUE,
  SBX058_OIDC_HEADER,
  SBX058_RUN_HEADER,
  SBX058_TEST_ID,
  SBX058_UUID,
  SBX058_WRONG_VALUE,
  expectedOperationId,
  expectedReceipt,
  isSbx058EventCaseId,
  proxyAudience,
  requestPath,
  type Sbx058EventCaseId,
  type Sbx058Role,
} from "./protocol.js";

const MAX_BODY_BYTES = 16_384;
const FORWARDED_HOST = "vercel-forwarded-host";
const FORWARDED_SCHEME = "vercel-forwarded-scheme";
const FORWARDED_PORT = "vercel-forwarded-port";
const FORWARDED_PATH = "vercel-forwarded-path";
const TRUST_ENVIRONMENT_NAMES = [
  "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF",
  "OPENSSL_MODULES", "SSL_CERT_DIR", "SSL_CERT_FILE",
] as const;

export interface Sbx058ReceiverCase {
  caseId: Sbx058EventCaseId;
  canary: string;
  requestPath: string;
}

export interface Sbx058ReceiverConfiguration {
  runId: string;
  aHostname: string;
  forwardAudience: string;
  expectedTeamId: string;
  expectedProjectId: string;
  expectedSessionId: string;
  expectedSandboxName: string;
  cases: Sbx058ReceiverCase[];
}

export interface Sbx058OidcFacts {
  oidcHeaderLines: number;
  oidcHeaderValues: number;
  oidcOfficialVerified: boolean;
  oidcIndependentRs256Verified: boolean;
  oidcAudienceMatched: boolean;
  oidcSourceMatched: boolean;
  oidcIssuerVerified: boolean;
  oidcTemporalVerified: boolean;
  oidcIssuer?: string;
  oidcAudience?: string;
  oidcTeamId?: string;
  oidcProjectId?: string;
  oidcSessionId?: string;
  oidcSandboxName?: string;
}

export interface Sbx058ReceiverEvent extends Sbx058OidcFacts {
  ordinal: number;
  observedAt: string;
  caseId: Sbx058EventCaseId;
  role: Sbx058Role;
  method: "GET";
  hostMatched: true;
  pathMatched: true;
  correlationHeadersExact: true;
  forwardedMetadataExact: boolean;
  routeHeaderLines: number;
  routeHeaderValues: number;
  decoyHeaderLines: number;
  decoyHeaderValues: number;
  routeValueMatched: boolean;
  decoyValueMatched: boolean;
  operationId: string;
  receipt: string;
}

export interface Sbx058ReceiverSnapshot {
  configured: true;
  configuredAt: string;
  snapshotAt: string;
  emptyReadAt?: string;
  events: Sbx058ReceiverEvent[];
  unexpectedARequests: number;
  unexpectedPRequests: number;
  unattributedRequests: number;
  rawOidcTokenRetained: false;
  oidcTokenDigestRetained: false;
  receiverRuntimeTrustExact: true;
  receiverRuntimeTrustEnvironmentNames: string[];
  receiverNodeOptionsPresent: false;
  receiverTlsVerificationDisabled: false;
}

interface RunState {
  configuration: Sbx058ReceiverConfiguration;
  configuredAt: string;
  emptyReadAt?: string;
  events: Sbx058ReceiverEvent[];
  unexpectedARequests: number;
  unexpectedPRequests: number;
  unattributedRequests: number;
}

interface IndependentOidcResult {
  verified: boolean;
  rs256: boolean;
  audienceMatched: boolean;
  issuerVerified: boolean;
  temporalVerified: boolean;
  issuer?: string;
  audience?: string;
  teamId?: string;
  projectId?: string;
  sessionId?: string;
  sandboxName?: string;
}

export interface Sbx058ReceiverOptions {
  adminKey: string;
  actionKey: string;
  aPublicOrigin: string;
  pPublicOrigin: string;
  aPort?: number;
  pPort?: number;
  host?: string;
}

export interface Sbx058ReceiverHandle {
  aServer: Server;
  pServer: Server;
  aPort: number;
  pPort: number;
  close(): Promise<void>;
}

export interface Sbx058ForwardedMetadata {
  host: string[];
  scheme: string[];
  port: string[];
  path: string[];
}

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((entry, index) => entry === wanted[index]);
}

function canonicalOrigin(raw: string, label: string): URL {
  const value = new URL(raw);
  if (raw !== value.origin || value.protocol !== "https:" || value.username || value.password || value.port ||
      value.pathname !== "/" || value.search || value.hash || isIP(value.hostname) !== 0 ||
      value.hostname !== value.hostname.toLowerCase()) throw new Error(`${label} was not a canonical HTTPS origin`);
  return value;
}

function digest(value: string): Buffer {
  return createHash("sha256").update(value).digest();
}

function adminAuthorized(request: IncomingMessage, expected: string): boolean {
  const supplied = request.headers.authorization;
  if (typeof supplied !== "string" || !supplied.startsWith("Bearer ")) return false;
  return timingSafeEqual(digest(supplied.slice(7)), digest(expected));
}

function rawHeaderLines(request: IncomingMessage, name: string): string[] {
  const values: string[] = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === name) {
      const value = request.rawHeaders[index + 1];
      if (value !== undefined) values.push(value);
    }
  }
  return values;
}

function semanticValues(lines: readonly string[]): string[] {
  return lines.flatMap((line) => line.split(",").map((entry) => entry.trim()));
}

function headerSummary(request: IncomingMessage, name: string): { lines: string[]; values: string[] } {
  const lines = rawHeaderLines(request, name);
  return { lines, values: semanticValues(lines) };
}

function correlationAbsent(request: IncomingMessage): boolean {
  return rawHeaderLines(request, SBX058_RUN_HEADER).length === 0 &&
    rawHeaderLines(request, SBX058_CASE_HEADER).length === 0 &&
    rawHeaderLines(request, SBX058_CANARY_HEADER).length === 0;
}

function forwardedMetadataAbsent(request: IncomingMessage): boolean {
  return [FORWARDED_HOST, FORWARDED_SCHEME, FORWARDED_PORT, FORWARDED_PATH]
    .every((name) => rawHeaderLines(request, name).length === 0);
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

function sendJson(response: ServerResponse, status: number, value: unknown): void {
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    "content-length": String(body.byteLength),
  });
  response.end(body);
}

function sendEmpty(response: ServerResponse, status: number): void {
  response.writeHead(status, { "cache-control": "no-store", "content-length": "0" });
  response.end();
}

async function sendWebResponse(target: ServerResponse, source: Response): Promise<void> {
  const body = Buffer.from(await source.arrayBuffer());
  if (body.byteLength > MAX_BODY_BYTES) throw new Error("proxy response exceeded bound");
  const headers: Record<string, string> = {};
  source.headers.forEach((value, name) => { headers[name] = value; });
  headers["cache-control"] = "no-store";
  headers["content-length"] = String(body.byteLength);
  target.writeHead(source.status, headers);
  target.end(body);
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk);
    total += bytes.byteLength;
    if (total > MAX_BODY_BYTES) throw new Error("admin body exceeded bound");
    chunks.push(bytes);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function safeString(value: unknown, maximum: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[\0\r\n]/u.test(value)) {
    throw new Error("receiver identity string was invalid");
  }
  return value;
}

export function receiverRuntimeAttestation(environment: NodeJS.ProcessEnv = process.env): {
  receiverRuntimeTrustExact: true;
  receiverRuntimeTrustEnvironmentNames: string[];
  receiverNodeOptionsPresent: false;
  receiverTlsVerificationDisabled: false;
} {
  const names = TRUST_ENVIRONMENT_NAMES.filter((name) => environment[name] !== undefined).sort();
  if (names.length > 0 || environment.NODE_TLS_REJECT_UNAUTHORIZED === "0" || environment.NODE_OPTIONS) {
    throw new Error("SBX-058 receiver refuses TLS trust or runtime injection overrides");
  }
  return {
    receiverRuntimeTrustExact: true,
    receiverRuntimeTrustEnvironmentNames: [],
    receiverNodeOptionsPresent: false,
    receiverTlsVerificationDisabled: false,
  };
}

export function validateReceiverConfiguration(
  value: unknown,
  runId: string,
  aOrigin: URL,
  pOrigin: URL,
): Sbx058ReceiverConfiguration {
  const root = object(value);
  if (!root || !exactKeys(root, [
    "aHostname", "cases", "expectedProjectId", "expectedSandboxName", "expectedSessionId",
    "expectedTeamId", "forwardAudience", "runId",
  ]) || root.runId !== runId || root.aHostname !== aOrigin.hostname ||
      root.forwardAudience !== proxyAudience(pOrigin, runId) || !Array.isArray(root.cases) ||
      root.cases.length !== SBX058_EVENT_CASES.length) {
    throw new Error("SBX-058 receiver configuration was not exact");
  }
  const cases = root.cases.map((raw): Sbx058ReceiverCase => {
    const entry = object(raw);
    if (!entry || !exactKeys(entry, ["canary", "caseId", "requestPath"]) ||
        !isSbx058EventCaseId(entry.caseId) || typeof entry.canary !== "string" ||
        !SBX058_CANARY.test(entry.canary) || entry.requestPath !== requestPath(runId, entry.caseId, entry.canary)) {
      throw new Error("SBX-058 receiver case was invalid");
    }
    return { caseId: entry.caseId, canary: entry.canary, requestPath: entry.requestPath as string };
  });
  if (!SBX058_EVENT_CASES.every((caseId, index) => cases[index]?.caseId === caseId) ||
      new Set(cases.map((entry) => entry.canary)).size !== cases.length) {
    throw new Error("SBX-058 receiver cases were not ordered and unique");
  }
  return {
    runId,
    aHostname: aOrigin.hostname,
    forwardAudience: proxyAudience(pOrigin, runId),
    expectedTeamId: safeString(root.expectedTeamId, 128),
    expectedProjectId: safeString(root.expectedProjectId, 128),
    expectedSessionId: safeString(root.expectedSessionId, 128),
    expectedSandboxName: safeString(root.expectedSandboxName, 256),
    cases,
  };
}

function snapshot(state: RunState, runtime: ReturnType<typeof receiverRuntimeAttestation>): Sbx058ReceiverSnapshot {
  return {
    configured: true,
    configuredAt: state.configuredAt,
    snapshotAt: new Date().toISOString(),
    ...(state.emptyReadAt ? { emptyReadAt: state.emptyReadAt } : {}),
    events: state.events,
    unexpectedARequests: state.unexpectedARequests,
    unexpectedPRequests: state.unexpectedPRequests,
    unattributedRequests: state.unattributedRequests,
    rawOidcTokenRetained: false,
    oidcTokenDigestRetained: false,
    ...runtime,
  };
}

function claim(payload: JWTPayload, name: string): string | undefined {
  const value = payload[name];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function exactAudience(actual: JWTPayload["aud"], expected: string): boolean {
  return actual === expected || (Array.isArray(actual) && actual.length === 1 && actual[0] === expected);
}

function jwks(issuer: string): ReturnType<typeof createRemoteJWKSet> {
  const existing = jwksCache.get(issuer);
  if (existing) return existing;
  const created = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks`), {
    timeoutDuration: 5_000,
    cooldownDuration: 30_000,
  });
  jwksCache.set(issuer, created);
  return created;
}

async function independentlyVerifyOidc(
  token: string,
  config: Sbx058ReceiverConfiguration,
): Promise<IndependentOidcResult> {
  let rs256 = false;
  let issuerVerified = false;
  try {
    rs256 = decodeProtectedHeader(token).alg === "RS256";
    if (!rs256) throw new Error("non-RS256 OIDC token");
    const decoded = decodeJwt(token);
    if (typeof decoded.iss !== "string") throw new Error("missing issuer");
    const issuer = new URL(decoded.iss);
    issuerVerified = issuer.protocol === "https:" && issuer.hostname === "oidc.vercel.com" &&
      !issuer.username && !issuer.password && !issuer.port && !issuer.search && !issuer.hash &&
      issuer.pathname === `/${config.expectedTeamId}`;
    if (!issuerVerified) throw new Error("issuer mismatch");
    const { payload } = await jwtVerify(token, jwks(decoded.iss), {
      algorithms: ["RS256"],
      issuer: decoded.iss,
      audience: config.forwardAudience,
      clockTolerance: 60,
    });
    const teamId = claim(payload, "team_id");
    const projectId = claim(payload, "project_id");
    const sessionId = claim(payload, "sandbox_id");
    const sandboxName = claim(payload, "sandbox_name") ?? sessionId;
    const audienceMatched = exactAudience(payload.aud, config.forwardAudience);
    const now = Math.floor(Date.now() / 1_000);
    const temporalVerified = typeof payload.iat === "number" && typeof payload.exp === "number" &&
      payload.exp > payload.iat && payload.iat <= now + 60 && payload.exp >= now - 60;
    const sourceMatched = teamId === config.expectedTeamId && projectId === config.expectedProjectId &&
      sessionId === config.expectedSessionId && sandboxName === config.expectedSandboxName;
    return {
      verified: rs256 && issuerVerified && audienceMatched && temporalVerified && sourceMatched,
      rs256,
      audienceMatched,
      issuerVerified,
      temporalVerified,
      issuer: decoded.iss,
      audience: audienceMatched ? config.forwardAudience : "non-exact-audience",
      ...(teamId ? { teamId } : {}),
      ...(projectId ? { projectId } : {}),
      ...(sessionId ? { sessionId } : {}),
      ...(sandboxName ? { sandboxName } : {}),
    };
  } catch {
    return { verified: false, rs256, audienceMatched: false, issuerVerified, temporalVerified: false };
  }
}

function exactCorrelation(
  request: IncomingMessage,
  state: RunState,
): { caseId: Sbx058EventCaseId; configured: Sbx058ReceiverCase } | undefined {
  const run = headerSummary(request, SBX058_RUN_HEADER);
  const caseHeader = headerSummary(request, SBX058_CASE_HEADER);
  const canary = headerSummary(request, SBX058_CANARY_HEADER);
  if (run.lines.length !== 1 || run.values.length !== 1 || run.values[0] !== state.configuration.runId ||
      caseHeader.lines.length !== 1 || caseHeader.values.length !== 1 ||
      canary.lines.length !== 1 || canary.values.length !== 1 ||
      !isSbx058EventCaseId(caseHeader.values[0])) return;
  const configured = state.configuration.cases.find((entry) => entry.caseId === caseHeader.values[0]);
  if (!configured || configured.canary !== canary.values[0]) return;
  return { caseId: caseHeader.values[0], configured };
}

function stateFromEvidence(request: IncomingMessage, url: URL, states: Map<string, RunState>): RunState | undefined {
  const candidates = new Set<RunState>();
  for (const value of semanticValues(rawHeaderLines(request, SBX058_RUN_HEADER))) {
    if (SBX058_UUID.test(value)) {
      const state = states.get(value);
      if (state) candidates.add(state);
    }
  }
  for (const segment of url.pathname.split("/")) {
    if (SBX058_UUID.test(segment)) {
      const state = states.get(segment);
      if (state) candidates.add(state);
    }
  }
  return candidates.size === 1 ? candidates.values().next().value : undefined;
}

function expectedHeaders(caseId: Sbx058EventCaseId): {
  routeLines: number;
  routeValues: number;
  decoyLines: number;
  decoyValues: number;
  routeMatched: boolean;
  decoyMatched: boolean;
} {
  return {
    routeLines: caseId === "value-half" ? 0 : 1,
    routeValues: caseId === "value-half" ? 0 : 1,
    decoyLines: caseId === "value-half" || caseId === "combined-halves" ? 1 : 0,
    decoyValues: caseId === "value-half" || caseId === "combined-halves" ? 1 : 0,
    routeMatched: caseId === "exact-pair",
    decoyMatched: caseId === "value-half" || caseId === "combined-halves",
  };
}

function appendEvent(
  state: RunState,
  request: IncomingMessage,
  caseId: Sbx058EventCaseId,
  role: Sbx058Role,
  forwardedMetadataExact: boolean,
  oidc: IndependentOidcResult,
  official: boolean,
  sourceMatched: boolean,
  adminKey: string,
  actionKey: string,
): Sbx058ReceiverEvent | undefined {
  if (SBX058_EVENT_CASES[state.events.length] !== caseId || state.events.some((event) => event.caseId === caseId)) {
    state.unattributedRequests += 1;
    return;
  }
  const route = headerSummary(request, SBX058_MATCH_HEADER);
  const decoy = headerSummary(request, SBX058_DECOY_HEADER);
  const wanted = expectedHeaders(caseId);
  const routeValueMatched = route.values.length === 1 && route.values[0] === SBX058_MATCH_VALUE;
  const decoyValueMatched = decoy.values.length === 1 && decoy.values[0] === SBX058_MATCH_VALUE;
  if (route.lines.length !== wanted.routeLines || route.values.length !== wanted.routeValues ||
      decoy.lines.length !== wanted.decoyLines || decoy.values.length !== wanted.decoyValues ||
      routeValueMatched !== wanted.routeMatched || decoyValueMatched !== wanted.decoyMatched ||
      (route.values.length === 1 && !routeValueMatched && route.values[0] !== SBX058_WRONG_VALUE)) {
    state.unattributedRequests += 1;
    return;
  }
  const oidcVerified = official && oidc.verified && sourceMatched;
  const operationId = expectedOperationId(
    actionKey,
    state.configuration.runId,
    caseId,
    state.configuration.cases.find((entry) => entry.caseId === caseId)!.canary,
    role,
    route.lines.length,
    decoy.lines.length,
    routeValueMatched,
    decoyValueMatched,
    oidcVerified,
  );
  const ordinal = state.events.length + 1;
  const oidcLines = headerSummary(request, SBX058_OIDC_HEADER);
  const event: Sbx058ReceiverEvent = {
    ordinal,
    observedAt: new Date().toISOString(),
    caseId,
    role,
    method: "GET",
    hostMatched: true,
    pathMatched: true,
    correlationHeadersExact: true,
    forwardedMetadataExact,
    routeHeaderLines: route.lines.length,
    routeHeaderValues: route.values.length,
    decoyHeaderLines: decoy.lines.length,
    decoyHeaderValues: decoy.values.length,
    routeValueMatched,
    decoyValueMatched,
    oidcHeaderLines: oidcLines.lines.length,
    oidcHeaderValues: oidcLines.values.length,
    oidcOfficialVerified: official,
    oidcIndependentRs256Verified: oidc.verified,
    oidcAudienceMatched: oidc.audienceMatched,
    oidcSourceMatched: sourceMatched,
    oidcIssuerVerified: oidc.issuerVerified,
    oidcTemporalVerified: oidc.temporalVerified,
    ...(oidc.issuer ? { oidcIssuer: oidc.issuer } : {}),
    ...(oidc.audience ? { oidcAudience: oidc.audience } : {}),
    ...(oidc.teamId ? { oidcTeamId: oidc.teamId } : {}),
    ...(oidc.projectId ? { oidcProjectId: oidc.projectId } : {}),
    ...(oidc.sessionId ? { oidcSessionId: oidc.sessionId } : {}),
    ...(oidc.sandboxName ? { oidcSandboxName: oidc.sandboxName } : {}),
    operationId,
    receipt: expectedReceipt(
      adminKey,
      state.configuration.runId,
      ordinal,
      caseId,
      state.configuration.cases.find((entry) => entry.caseId === caseId)!.canary,
      role,
      operationId,
    ),
  };
  state.events.push(event);
  return event;
}

function eventResponse(event: Sbx058ReceiverEvent): Record<string, unknown> {
  return {
    schemaVersion: 1,
    testId: SBX058_TEST_ID,
    caseId: event.caseId,
    role: event.role,
    oidcVerified: event.oidcOfficialVerified && event.oidcIndependentRs256Verified &&
      event.oidcAudienceMatched && event.oidcSourceMatched,
    operationId: event.operationId,
    receipt: event.receipt,
  };
}

function runIdFromAdminPath(pathname: string): string | undefined {
  return /^\/v1\/sbx058\/admin\/runs\/([0-9a-f-]{36})$/u.exec(pathname)?.[1];
}

export function exactProxyAttribution(
  proxiedRequest: Request,
  metaHost: string,
  forwarded: Sbx058ForwardedMetadata,
  configured: Sbx058ReceiverCase,
  config: Sbx058ReceiverConfiguration,
): boolean {
  try {
    const original = new URL(proxiedRequest.url);
    const audience = new URL(config.forwardAudience);
    return metaHost === audience.host && proxiedRequest.method === "GET" &&
      original.protocol === "https:" && original.hostname === config.aHostname && !original.port &&
      `${original.pathname}${original.search}` === configured.requestPath &&
      proxiedRequest.headers.get("host") === config.aHostname &&
      forwarded.host.length === 1 && forwarded.host[0] === config.aHostname &&
      forwarded.scheme.length === 1 && forwarded.scheme[0] === "https" &&
      forwarded.port.length === 1 && forwarded.port[0] === "443" &&
      forwarded.path.length === 1 && forwarded.path[0] === configured.requestPath;
  } catch {
    return false;
  }
}

async function listen(server: Server, host: string, port: number): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => { server.off("error", reject); resolve(); });
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("receiver did not bind TCP");
  return address.port;
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

export async function createSbx058Receiver(options: Sbx058ReceiverOptions): Promise<Sbx058ReceiverHandle> {
  const runtime = receiverRuntimeAttestation();
  if (Buffer.byteLength(options.adminKey) < 32 || Buffer.byteLength(options.actionKey) < 32 ||
      options.adminKey === options.actionKey || /[\0\r\n]/u.test(options.adminKey + options.actionKey)) {
    throw new Error("SBX-058 receiver keys were invalid");
  }
  const aOrigin = canonicalOrigin(options.aPublicOrigin, "A origin");
  const pOrigin = canonicalOrigin(options.pPublicOrigin, "P origin");
  if (aOrigin.origin === pOrigin.origin) throw new Error("SBX-058 A/P origins must differ");
  const states = new Map<string, RunState>();

  const aServer = createServer(async (request, response) => {
    let attributed: RunState | undefined;
    let countable = false;
    try {
      const url = new URL(request.url ?? "/", aOrigin);
      if (request.method === "GET" && url.pathname === "/healthz" && !url.search && correlationAbsent(request)) {
        return sendJson(response, 200, { ok: true, testId: SBX058_TEST_ID, role: "A" });
      }
      const adminRun = runIdFromAdminPath(url.pathname);
      if (adminRun && !url.search && correlationAbsent(request)) {
        if (!adminAuthorized(request, options.adminKey)) return sendEmpty(response, 401);
        if (!SBX058_UUID.test(adminRun)) return sendEmpty(response, 400);
        if (request.method === "PUT") {
          if (states.has(adminRun) || states.size !== 0) return sendEmpty(response, 409);
          const configuration = validateReceiverConfiguration(await readJson(request), adminRun, aOrigin, pOrigin);
          const state: RunState = {
            configuration,
            configuredAt: new Date().toISOString(),
            events: [],
            unexpectedARequests: 0,
            unexpectedPRequests: 0,
            unattributedRequests: 0,
          };
          states.set(adminRun, state);
          return sendJson(response, 201, snapshot(state, runtime));
        }
        const state = states.get(adminRun);
        if (request.method === "GET") {
          if (!state) return sendEmpty(response, 404);
          if (state.events.length === 0 && !state.emptyReadAt) state.emptyReadAt = new Date().toISOString();
          return sendJson(response, 200, snapshot(state, runtime));
        }
        if (request.method === "DELETE") return sendEmpty(response, states.delete(adminRun) ? 204 : 404);
        return sendEmpty(response, 405);
      }
      countable = true;
      attributed = stateFromEvidence(request, url, states);
      if (!attributed) {
        const active = states.size === 1 ? states.values().next().value : undefined;
        if (active) active.unattributedRequests += 1;
        return sendEmpty(response, 404);
      }
      if (request.method !== "GET") {
        attributed.unexpectedARequests += 1;
        return sendEmpty(response, 405);
      }
      const correlation = exactCorrelation(request, attributed);
      if (!correlation || `${url.pathname}${url.search}` !== correlation.configured.requestPath ||
          request.headers.host !== aOrigin.hostname || !forwardedMetadataAbsent(request)) {
        attributed.unexpectedARequests += 1;
        return sendEmpty(response, 400);
      }
      const oidc = headerSummary(request, SBX058_OIDC_HEADER);
      if (oidc.lines.length !== 0 || oidc.values.length !== 0) {
        attributed.unexpectedARequests += 1;
        return sendEmpty(response, 400);
      }
      const event = appendEvent(
        attributed,
        request,
        correlation.caseId,
        "A",
        false,
        { verified: false, rs256: false, audienceMatched: false, issuerVerified: false, temporalVerified: false },
        false,
        false,
        options.adminKey,
        options.actionKey,
      );
      if (!event) return sendEmpty(response, 409);
      return sendJson(response, 200, eventResponse(event));
    } catch {
      if (countable && attributed) attributed.unexpectedARequests += 1;
      if (!response.headersSent) sendEmpty(response, 400); else response.destroy();
    }
  });

  const pServer = createServer(async (request, response) => {
    let rawToken: string | undefined;
    let attributed: RunState | undefined;
    let countable = false;
    try {
      const url = new URL(request.url ?? "/", pOrigin);
      if (request.method === "GET" && url.pathname === "/healthz" && !url.search && correlationAbsent(request)) {
        return sendJson(response, 200, { ok: true, testId: SBX058_TEST_ID, role: "P" });
      }
      countable = true;
      attributed = stateFromEvidence(request, url, states);
      if (!attributed) {
        const active = states.size === 1 ? states.values().next().value : undefined;
        if (active) active.unattributedRequests += 1;
        return sendEmpty(response, 404);
      }
      if (request.method !== "GET") {
        attributed.unexpectedPRequests += 1;
        return sendEmpty(response, 405);
      }
      const correlation = exactCorrelation(request, attributed);
      const proxyMatch = /^\/v1\/sbx058\/proxy\/([0-9a-f-]{36})(?:\/|$)/u.exec(url.pathname);
      if (!correlation || !proxyMatch || proxyMatch[1] !== attributed.configuration.runId) {
        attributed.unexpectedPRequests += 1;
        return sendEmpty(response, 400);
      }
      const oidc = headerSummary(request, SBX058_OIDC_HEADER);
      rawToken = oidc.lines.length === 1 && oidc.values.length === 1 ? oidc.values[0] : undefined;
      const independent = rawToken
        ? await independentlyVerifyOidc(rawToken, attributed.configuration)
        : { verified: false, rs256: false, audienceMatched: false, issuerVerified: false, temporalVerified: false };
      const forwarded: Sbx058ForwardedMetadata = {
        host: semanticValues(rawHeaderLines(request, FORWARDED_HOST)),
        scheme: semanticValues(rawHeaderLines(request, FORWARDED_SCHEME)),
        port: semanticValues(rawHeaderLines(request, FORWARDED_PORT)),
        path: rawHeaderLines(request, FORWARDED_PATH),
      };
      const publicRequest = new Request(url, { method: "GET", headers: requestHeaders(request) });
      const handler = defineSandboxProxy(
        async (proxiedRequest, meta) => {
          const sourceMatched = meta.host === new URL(attributed!.configuration.forwardAudience).host &&
            meta.teamId === attributed!.configuration.expectedTeamId &&
            meta.projectId === attributed!.configuration.expectedProjectId &&
            meta.sandboxId === attributed!.configuration.expectedSessionId &&
            meta.sandboxName === attributed!.configuration.expectedSandboxName;
          const proxyExact = exactProxyAttribution(
            proxiedRequest,
            meta.host,
            forwarded,
            correlation.configured,
            attributed!.configuration,
          );
          if (!proxyExact) {
            attributed!.unexpectedPRequests += 1;
            return new Response(null, { status: 409 });
          }
          const event = appendEvent(
            attributed!,
            request,
            correlation.caseId,
            "P",
            true,
            independent,
            true,
            sourceMatched,
            options.adminKey,
            options.actionKey,
          );
          if (!event) return new Response(null, { status: 409 });
          return Response.json(eventResponse(event), {
            status: independent.verified && sourceMatched ? 200 : 403,
          });
        },
        async () => {
          attributed!.unattributedRequests += 1;
          return new Response(null, { status: 403 });
        },
      );
      await sendWebResponse(response, await handler(publicRequest));
    } catch {
      if (countable && attributed) attributed.unexpectedPRequests += 1;
      if (!response.headersSent) sendEmpty(response, 400); else response.destroy();
    } finally {
      rawToken = undefined;
    }
  });

  const host = options.host ?? "127.0.0.1";
  const aPort = await listen(aServer, host, options.aPort ?? 43160);
  let pPort: number;
  try {
    pPort = await listen(pServer, host, options.pPort ?? 43161);
  } catch (error) {
    await closeServer(aServer);
    throw error;
  }
  return {
    aServer,
    pServer,
    aPort,
    pPort,
    async close() { await Promise.all([closeServer(aServer), closeServer(pServer)]); },
  };
}

async function main(): Promise<void> {
  const handle = await createSbx058Receiver({
    adminKey: process.env.SBX058_ADMIN_KEY ?? "",
    actionKey: process.env.SBX058_ACTION_KEY ?? "",
    aPublicOrigin: process.env.SBX058_A_PUBLIC_ORIGIN ?? "",
    pPublicOrigin: process.env.SBX058_P_PUBLIC_ORIGIN ?? "",
    aPort: Number.parseInt(process.env.SBX058_A_PORT ?? "43160", 10),
    pPort: Number.parseInt(process.env.SBX058_P_PORT ?? "43161", 10),
    host: process.env.SBX058_LISTEN_HOST ?? "127.0.0.1",
  });
  process.stdout.write(`${JSON.stringify({ ready: true, aPort: handle.aPort, pPort: handle.pPort })}\n`);
  const shutdown = async (): Promise<void> => { await handle.close(); process.exit(0); };
  process.once("SIGINT", () => void shutdown());
  process.once("SIGTERM", () => void shutdown());
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
