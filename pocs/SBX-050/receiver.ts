import "dotenv/config";

import { createHash, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { isIP } from "node:net";
import { pathToFileURL } from "node:url";
import { defineSandboxProxy } from "@vercel/sandbox";
import { createRemoteJWKSet, decodeJwt, decodeProtectedHeader, jwtVerify, type JWTPayload } from "jose";
import {
  CANARY_PATTERN,
  COMMITMENT_PATTERN,
  commitmentMatches,
  expectedOperationId,
  isEventCaseId,
  proxyAudience,
  requestPath,
  RUN_ID_PATTERN,
  SBX050_CANARY_HEADER,
  SBX050_CASE_HEADER,
  SBX050_CREDENTIAL_HEADER,
  SBX050_EVENT_CASES,
  SBX050_OIDC_HEADER,
  SBX050_RUN_HEADER,
  SBX050_TEST_ID,
  SBX050_TRIGGER_HEADER,
  type Sbx050EventCaseId,
  type Sbx050Role,
} from "./protocol.js";
import type { Sbx050LedgerEvent } from "./verdict.js";

const MAX_BODY_BYTES = 16_384;
const FORWARDED_HOST_HEADER = "vercel-forwarded-host";
const FORWARDED_SCHEME_HEADER = "vercel-forwarded-scheme";
const FORWARDED_PORT_HEADER = "vercel-forwarded-port";
const FORWARDED_PATH_HEADER = "vercel-forwarded-path";
const RECEIVER_TRUST_ENVIRONMENT_NAMES = [
  "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF",
  "OPENSSL_MODULES", "SSL_CERT_DIR", "SSL_CERT_FILE",
] as const;

export interface Sbx050ReceiverCase {
  caseId: Sbx050EventCaseId;
  canary: string;
  requestPath: string;
}

export interface Sbx050ReceiverConfiguration {
  runId: string;
  aHostname: string;
  forwardAudience: string;
  expectedTeamId: string;
  expectedProjectId: string;
  expectedSessionId: string;
  expectedSandboxName: string;
  credentialCommitment: string;
  hiddenTriggerCommitment: string;
  cases: Sbx050ReceiverCase[];
}

interface RunState {
  configuration: Sbx050ReceiverConfiguration;
  configuredAt: string;
  emptyReadAt?: string;
  events: Sbx050LedgerEvent[];
  unexpectedARequests: number;
  unexpectedPRequests: number;
  unattributedRequests: number;
}

export interface Sbx050ReceiverRuntimeAttestation {
  receiverRuntimeTrustExact: true;
  receiverRuntimeTrustEnvironmentNames: string[];
  receiverNodeOptionsPresent: false;
  receiverTlsVerificationDisabled: false;
}

export interface Sbx050ReceiverOptions {
  adminKey: string;
  actionKey: string;
  aPublicOrigin: string;
  pPublicOrigin: string;
  aPort?: number;
  pPort?: number;
  host?: string;
}

export interface Sbx050ReceiverHandle {
  aServer: Server;
  pServer: Server;
  aPort: number;
  pPort: number;
  close(): Promise<void>;
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

export interface Sbx050ForwardedMetadata {
  host: string[];
  scheme: string[];
  port: string[];
  path: string[];
}

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

export function receiverRuntimeAttestation(
  environment: NodeJS.ProcessEnv = process.env,
): Sbx050ReceiverRuntimeAttestation {
  const names = RECEIVER_TRUST_ENVIRONMENT_NAMES.filter((name) => environment[name] !== undefined).sort();
  if (environment.NODE_TLS_REJECT_UNAUTHORIZED === "0" ||
      (environment.NODE_OPTIONS !== undefined && environment.NODE_OPTIONS.trim() !== "") || names.length > 0) {
    throw new Error("SBX-050 receiver refuses TLS trust overrides or runtime injection");
  }
  return {
    receiverRuntimeTrustExact: true,
    receiverRuntimeTrustEnvironmentNames: [],
    receiverNodeOptionsPresent: false,
    receiverTlsVerificationDisabled: false,
  };
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function exactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((entry, index) => entry === wanted[index]);
}

function safeOrigin(raw: string, name: string): URL {
  const parsed = new URL(raw);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.port ||
      parsed.pathname !== "/" || parsed.search || parsed.hash || isIP(parsed.hostname) !== 0 ||
      parsed.hostname !== parsed.hostname.toLowerCase()) {
    throw new Error(`${name} must be an exact lower-case public HTTPS origin`);
  }
  return parsed;
}

function digest(value: string): Buffer {
  return createHash("sha256").update(value).digest();
}

function adminAuthorized(request: IncomingMessage, expected: string): boolean {
  const supplied = request.headers.authorization;
  if (typeof supplied !== "string" || !supplied.startsWith("Bearer ")) return false;
  return timingSafeEqual(digest(supplied.slice(7)), digest(expected));
}

function rawHeaderValues(request: IncomingMessage, name: string): string[] {
  const values: string[] = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === name) {
      const value = request.rawHeaders[index + 1];
      if (value !== undefined) values.push(value);
    }
  }
  return values;
}

function rawHeaderCount(request: IncomingMessage, name: string): number {
  let count = 0;
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === name) count += 1;
  }
  return count;
}

function correlationHeadersAbsent(request: IncomingMessage): boolean {
  return rawHeaderCount(request, SBX050_RUN_HEADER) === 0 &&
    rawHeaderCount(request, SBX050_CASE_HEADER) === 0 &&
    rawHeaderCount(request, SBX050_CANARY_HEADER) === 0;
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
  if (body.byteLength > MAX_BODY_BYTES) throw new Error("generated response exceeded bound");
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
    if (total > MAX_BODY_BYTES) throw new Error("request body exceeded bound");
    chunks.push(bytes);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function safeString(value: unknown, maximum = 2_048): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[\0\r\n]/u.test(value)) {
    throw new Error("invalid receiver string");
  }
  return value;
}

export function validateReceiverConfiguration(
  value: unknown,
  runId: string,
  aOrigin: URL,
  pOrigin: URL,
): Sbx050ReceiverConfiguration {
  const root = object(value);
  const keys = [
    "aHostname", "cases", "credentialCommitment", "expectedProjectId", "expectedSandboxName",
    "expectedSessionId", "expectedTeamId", "forwardAudience", "hiddenTriggerCommitment", "runId",
  ];
  if (!root || !exactKeys(root, keys) || root.runId !== runId || root.aHostname !== aOrigin.hostname ||
      root.forwardAudience !== proxyAudience(pOrigin, runId) ||
      typeof root.credentialCommitment !== "string" || !COMMITMENT_PATTERN.test(root.credentialCommitment) ||
      typeof root.hiddenTriggerCommitment !== "string" || !COMMITMENT_PATTERN.test(root.hiddenTriggerCommitment) ||
      !Array.isArray(root.cases) || root.cases.length !== SBX050_EVENT_CASES.length) {
    throw new Error("invalid SBX-050 receiver configuration");
  }
  const cases = root.cases.map((raw): Sbx050ReceiverCase => {
    const entry = object(raw);
    if (!entry || !exactKeys(entry, ["canary", "caseId", "requestPath"]) ||
        !isEventCaseId(entry.caseId) || typeof entry.canary !== "string" ||
        !CANARY_PATTERN.test(entry.canary) || entry.requestPath !== requestPath(runId, entry.caseId, entry.canary)) {
      throw new Error("invalid SBX-050 receiver case");
    }
    return { caseId: entry.caseId, canary: entry.canary, requestPath: entry.requestPath as string };
  });
  if (!SBX050_EVENT_CASES.every((caseId, index) => cases[index]?.caseId === caseId) ||
      new Set(cases.map((entry) => entry.canary)).size !== cases.length) {
    throw new Error("SBX-050 receiver cases are not exact, ordered, and unique");
  }
  return {
    runId,
    aHostname: aOrigin.hostname,
    forwardAudience: proxyAudience(pOrigin, runId),
    expectedTeamId: safeString(root.expectedTeamId, 128),
    expectedProjectId: safeString(root.expectedProjectId, 128),
    expectedSessionId: safeString(root.expectedSessionId, 128),
    expectedSandboxName: safeString(root.expectedSandboxName, 256),
    credentialCommitment: root.credentialCommitment,
    hiddenTriggerCommitment: root.hiddenTriggerCommitment,
    cases,
  };
}

function snapshot(state: RunState, runtime: Sbx050ReceiverRuntimeAttestation): Record<string, unknown> {
  return {
    configured: true,
    configuredAt: state.configuredAt,
    ...(state.emptyReadAt ? { emptyReadAt: state.emptyReadAt } : {}),
    events: state.events,
    unexpectedARequests: state.unexpectedARequests,
    unexpectedPRequests: state.unexpectedPRequests,
    unattributedRequests: state.unattributedRequests,
    rawCredentialRetained: false,
    credentialDigestRetained: false,
    rawHiddenTriggerRetained: false,
    hiddenTriggerDigestRetained: false,
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

function getJwks(issuer: string): ReturnType<typeof createRemoteJWKSet> {
  const existing = jwksCache.get(issuer);
  if (existing) return existing;
  const created = createRemoteJWKSet(new URL(`${issuer.replace(/\/$/u, "")}/.well-known/jwks`), {
    timeoutDuration: 5_000,
    cooldownDuration: 30_000,
  });
  jwksCache.set(issuer, created);
  return created;
}

async function independentlyVerifyOidc(
  token: string,
  config: Sbx050ReceiverConfiguration,
): Promise<IndependentOidcResult> {
  let rs256 = false;
  let issuerVerified = false;
  try {
    rs256 = decodeProtectedHeader(token).alg === "RS256";
    if (!rs256) throw new Error("non-RS256 token");
    const decoded = decodeJwt(token);
    if (typeof decoded.iss !== "string") throw new Error("missing issuer");
    const issuerUrl = new URL(decoded.iss);
    issuerVerified = issuerUrl.protocol === "https:" && issuerUrl.hostname === "oidc.vercel.com" &&
      !issuerUrl.username && !issuerUrl.password && !issuerUrl.port && !issuerUrl.search && !issuerUrl.hash &&
      issuerUrl.pathname === `/${config.expectedTeamId}`;
    if (!issuerVerified) throw new Error("invalid issuer");
    const { payload } = await jwtVerify(token, getJwks(decoded.iss), {
      algorithms: ["RS256"], issuer: decoded.iss, audience: config.forwardAudience, clockTolerance: 60,
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
      rs256, audienceMatched, issuerVerified, temporalVerified,
      issuer: decoded.iss,
      audience: audienceMatched ? config.forwardAudience : "non-exact-audience",
      ...(teamId ? { teamId } : {}), ...(projectId ? { projectId } : {}),
      ...(sessionId ? { sessionId } : {}), ...(sandboxName ? { sandboxName } : {}),
    };
  } catch {
    return { verified: false, rs256, audienceMatched: false, issuerVerified, temporalVerified: false };
  }
}

function exactOriginalRequest(
  url: URL,
  caseId: Sbx050EventCaseId,
  config: Sbx050ReceiverConfiguration,
): boolean {
  const configured = config.cases.find((entry) => entry.caseId === caseId);
  return configured !== undefined && url.hostname === config.aHostname && `${url.pathname}${url.search}` === configured.requestPath;
}

export function exactProxyAttribution(
  proxiedRequest: Request,
  metaHost: string,
  forwarded: Sbx050ForwardedMetadata,
  caseId: Sbx050EventCaseId,
  config: Sbx050ReceiverConfiguration,
): boolean {
  const configured = config.cases.find((entry) => entry.caseId === caseId);
  if (!configured) return false;
  let proxiedUrl: URL;
  let audience: URL;
  try {
    proxiedUrl = new URL(proxiedRequest.url);
    audience = new URL(config.forwardAudience);
  } catch {
    return false;
  }
  return metaHost === audience.host && proxiedRequest.method === "GET" &&
    proxiedUrl.protocol === "https:" && proxiedUrl.hostname === config.aHostname && !proxiedUrl.port &&
    `${proxiedUrl.pathname}${proxiedUrl.search}` === configured.requestPath &&
    proxiedRequest.headers.get("host") === config.aHostname &&
    forwarded.host.length === 1 && forwarded.host[0] === config.aHostname &&
    forwarded.scheme.length === 1 && forwarded.scheme[0] === "https" &&
    forwarded.port.length === 1 && forwarded.port[0] === "443" &&
    forwarded.path.length === 1 && forwarded.path[0] === configured.requestPath;
}

function exactCorrelation(
  request: IncomingMessage,
  state: RunState,
): { caseId: Sbx050EventCaseId; configured: Sbx050ReceiverCase } | undefined {
  const runValues = rawHeaderValues(request, SBX050_RUN_HEADER);
  const caseValues = rawHeaderValues(request, SBX050_CASE_HEADER);
  const canaryValues = rawHeaderValues(request, SBX050_CANARY_HEADER);
  if (runValues.length !== 1 || runValues[0] !== state.configuration.runId ||
      caseValues.length !== 1 || canaryValues.length !== 1 || !isEventCaseId(caseValues[0])) return;
  const configured = state.configuration.cases.find((entry) => entry.caseId === caseValues[0]);
  if (!configured || configured.canary !== canaryValues[0]) return;
  return { caseId: caseValues[0], configured };
}

function stateFromRequestEvidence(
  request: IncomingMessage,
  url: URL,
  states: Map<string, RunState>,
): RunState | undefined {
  const runValues = rawHeaderValues(request, SBX050_RUN_HEADER);
  if (runValues.length === 1 && RUN_ID_PATTERN.test(runValues[0]!)) {
    const exact = states.get(runValues[0]!);
    if (exact) return exact;
  }
  const candidates = new Set<RunState>();
  for (const value of runValues) {
    if (RUN_ID_PATTERN.test(value)) {
      const state = states.get(value);
      if (state) candidates.add(state);
    }
  }
  for (const segment of url.pathname.split("/")) {
    if (RUN_ID_PATTERN.test(segment)) {
      const state = states.get(segment);
      if (state) candidates.add(state);
    }
  }
  return candidates.values().next().value;
}

function stateFromExactRunHeader(request: IncomingMessage, states: Map<string, RunState>): RunState | undefined {
  const values = rawHeaderValues(request, SBX050_RUN_HEADER);
  return values.length === 1 && RUN_ID_PATTERN.test(values[0]!) ? states.get(values[0]!) : undefined;
}

function appendEvent(
  state: RunState,
  request: IncomingMessage,
  caseId: Sbx050EventCaseId,
  role: Sbx050Role,
  originalRequestMatched: boolean,
  oidc: {
    headerCount: number;
    official: boolean;
    independent: IndependentOidcResult;
    sourceMatched: boolean;
  },
  actionKey: string,
  terminalHostname: string,
): Sbx050LedgerEvent | undefined {
  if (!originalRequestMatched || SBX050_EVENT_CASES[state.events.length] !== caseId ||
      state.events.some((event) => event.caseId === caseId)) {
    state.unattributedRequests += 1;
    return;
  }
  const credentialValues = rawHeaderValues(request, SBX050_CREDENTIAL_HEADER);
  const triggerValues = rawHeaderValues(request, SBX050_TRIGGER_HEADER);
  const credentialMatched = credentialValues.length === 1 && commitmentMatches(
    actionKey, "credential", credentialValues[0]!, state.configuration.credentialCommitment,
  );
  const triggerMatched = triggerValues.length === 1 && commitmentMatches(
    actionKey, "trigger", triggerValues[0]!, state.configuration.hiddenTriggerCommitment,
  );
  const configured = state.configuration.cases.find((entry) => entry.caseId === caseId);
  if (!configured) return;
  const event: Sbx050LedgerEvent = {
    ordinal: state.events.length + 1,
    observedAt: new Date().toISOString(),
    caseId,
    role,
    canaryMatched: true,
    originalRequestMatched: true,
    credentialHeaderCount: credentialValues.length,
    triggerHeaderCount: triggerValues.length,
    credentialMatched,
    triggerMatched,
    oidcHeaderCount: oidc.headerCount,
    oidcOfficialVerified: oidc.official,
    oidcIndependentRs256Verified: oidc.independent.verified,
    oidcAudienceMatched: oidc.independent.audienceMatched,
    oidcSourceMatched: oidc.sourceMatched,
    oidcIssuerVerified: oidc.independent.issuerVerified,
    oidcTemporalVerified: oidc.independent.temporalVerified,
    ...(oidc.independent.issuer ? { oidcIssuer: oidc.independent.issuer } : {}),
    ...(oidc.independent.audience ? { oidcAudience: oidc.independent.audience } : {}),
    ...(oidc.independent.teamId ? { oidcTeamId: oidc.independent.teamId } : {}),
    ...(oidc.independent.projectId ? { oidcProjectId: oidc.independent.projectId } : {}),
    ...(oidc.independent.sessionId ? { oidcSessionId: oidc.independent.sessionId } : {}),
    ...(oidc.independent.sandboxName ? { oidcSandboxName: oidc.independent.sandboxName } : {}),
    operationId: expectedOperationId(
      actionKey, terminalHostname, state.configuration.runId, caseId, configured.canary,
      role, credentialMatched, triggerMatched,
      oidc.official && oidc.independent.verified && oidc.sourceMatched,
    ),
  };
  state.events.push(event);
  return event;
}

function eventResponse(event: Sbx050LedgerEvent): Record<string, unknown> {
  const oidcVerified = event.oidcOfficialVerified && event.oidcIndependentRs256Verified &&
    event.oidcAudienceMatched && event.oidcSourceMatched;
  return {
    schemaVersion: 1,
    testId: SBX050_TEST_ID,
    caseId: event.caseId,
    role: event.role,
    credentialMatched: event.credentialMatched,
    triggerMatched: event.triggerMatched,
    oidcVerified,
    operationId: event.operationId,
  };
}

function runIdFromAdminPath(pathname: string): string | undefined {
  const match = /^\/v1\/sbx050\/admin\/runs\/([0-9a-f-]{36})$/u.exec(pathname);
  return match?.[1];
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
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

export async function createSbx050Receiver(options: Sbx050ReceiverOptions): Promise<Sbx050ReceiverHandle> {
  const runtimeAttestation = receiverRuntimeAttestation();
  if (Buffer.byteLength(options.adminKey) < 32 || Buffer.byteLength(options.actionKey) < 32 ||
      options.adminKey === options.actionKey || /[\0\r\n]/u.test(options.adminKey + options.actionKey)) {
    throw new Error("SBX-050 receiver keys must be distinct safe 32+ byte values");
  }
  const aOrigin = safeOrigin(options.aPublicOrigin, "SBX050_A_PUBLIC_ORIGIN");
  const pOrigin = safeOrigin(options.pPublicOrigin, "SBX050_P_PUBLIC_ORIGIN");
  if (aOrigin.origin === pOrigin.origin) throw new Error("SBX-050 A and P origins must be distinct");
  const states = new Map<string, RunState>();

  const aServer = createServer(async (request, response) => {
    let attributedState: RunState | undefined;
    let countableIngress = false;
    try {
      const url = new URL(request.url ?? "/", aOrigin);
      if (request.method === "GET" && url.pathname === "/healthz" && !url.search &&
          correlationHeadersAbsent(request)) {
        sendJson(response, 200, { ok: true, testId: SBX050_TEST_ID, role: "A" });
        return;
      }
      const adminRunId = runIdFromAdminPath(url.pathname);
      if (adminRunId && !url.search && correlationHeadersAbsent(request)) {
        if (!adminAuthorized(request, options.adminKey)) return sendEmpty(response, 401);
        if (!RUN_ID_PATTERN.test(adminRunId)) return sendEmpty(response, 400);
        if (request.method === "PUT") {
          if (states.has(adminRunId)) return sendEmpty(response, 409);
          const configuration = validateReceiverConfiguration(await readJson(request), adminRunId, aOrigin, pOrigin);
          const state: RunState = {
            configuration, configuredAt: new Date().toISOString(), events: [],
            unexpectedARequests: 0, unexpectedPRequests: 0, unattributedRequests: 0,
          };
          states.set(adminRunId, state);
          sendJson(response, 201, snapshot(state, runtimeAttestation));
          return;
        }
        const state = states.get(adminRunId);
        if (request.method === "GET") {
          if (!state) return sendEmpty(response, 404);
          if (state.events.length === 0 && !state.emptyReadAt) state.emptyReadAt = new Date().toISOString();
          sendJson(response, 200, snapshot(state, runtimeAttestation));
          return;
        }
        if (request.method === "DELETE") {
          sendEmpty(response, states.delete(adminRunId) ? 204 : 404);
          return;
        }
        return sendEmpty(response, 405);
      }

      countableIngress = true;
      const state = stateFromRequestEvidence(request, url, states);
      if (!state) return sendEmpty(response, 404);
      attributedState = state;
      if (request.method !== "GET") {
        state.unexpectedARequests += 1;
        return sendEmpty(response, 405);
      }
      const correlation = exactCorrelation(request, state);
      if (!correlation || `${url.pathname}${url.search}` !== correlation.configured.requestPath) {
        state.unexpectedARequests += 1;
        return sendEmpty(response, 400);
      }
      const event = appendEvent(
        state, request, correlation.caseId, "A", true,
        {
          headerCount: rawHeaderCount(request, SBX050_OIDC_HEADER), official: false,
          independent: {
            verified: false, rs256: false, audienceMatched: false,
            issuerVerified: false, temporalVerified: false,
          },
          sourceMatched: false,
        },
        options.actionKey, aOrigin.hostname,
      );
      if (!event) return sendEmpty(response, 409);
      sendJson(response, 200, eventResponse(event));
    } catch {
      const state = countableIngress
        ? attributedState ?? stateFromExactRunHeader(request, states)
        : undefined;
      if (state) state.unexpectedARequests += 1;
      if (!response.headersSent) sendEmpty(response, 400); else response.destroy();
    }
  });

  const pServer = createServer(async (request, response) => {
    let rawToken: string | undefined;
    let attributedState: RunState | undefined;
    let countableIngress = false;
    try {
      const url = new URL(request.url ?? "/", pOrigin);
      if (request.method === "GET" && url.pathname === "/healthz" && !url.search &&
          correlationHeadersAbsent(request)) {
        sendJson(response, 200, { ok: true, testId: SBX050_TEST_ID, role: "P" });
        return;
      }
      countableIngress = true;
      const proxyMatch = /^\/v1\/sbx050\/proxy\/([0-9a-f-]{36})(?:\/|$)/u.exec(url.pathname);
      const state = stateFromRequestEvidence(request, url, states);
      if (!state) return sendEmpty(response, 404);
      attributedState = state;
      if (request.method !== "GET") {
        state.unexpectedPRequests += 1;
        return sendEmpty(response, 405);
      }
      const correlation = exactCorrelation(request, state);
      if (!correlation) {
        state.unexpectedPRequests += 1;
        return sendEmpty(response, 400);
      }
      if (!proxyMatch || proxyMatch[1] !== state.configuration.runId) {
        state.unexpectedPRequests += 1;
        return sendEmpty(response, 404);
      }
      const oidcValues = rawHeaderValues(request, SBX050_OIDC_HEADER);
      const forwarded: Sbx050ForwardedMetadata = {
        host: rawHeaderValues(request, FORWARDED_HOST_HEADER),
        scheme: rawHeaderValues(request, FORWARDED_SCHEME_HEADER),
        port: rawHeaderValues(request, FORWARDED_PORT_HEADER),
        path: rawHeaderValues(request, FORWARDED_PATH_HEADER),
      };
      rawToken = oidcValues.length === 1 ? oidcValues[0] : undefined;
      const independent = rawToken
        ? await independentlyVerifyOidc(rawToken, state.configuration)
        : { verified: false, rs256: false, audienceMatched: false, issuerVerified: false, temporalVerified: false };
      const publicRequest = new Request(url, { method: "GET", headers: requestHeaders(request) });
      const handler = defineSandboxProxy(
        async (proxiedRequest, meta) => {
          const originalUrl = new URL(proxiedRequest.url);
          const proxyHostMatched = meta.host === new URL(state.configuration.forwardAudience).host;
          const sourceMatched = proxyHostMatched &&
            meta.teamId === state.configuration.expectedTeamId && meta.projectId === state.configuration.expectedProjectId &&
            meta.sandboxId === state.configuration.expectedSessionId && meta.sandboxName === state.configuration.expectedSandboxName;
          const originalMatched = exactOriginalRequest(originalUrl, correlation.caseId, state.configuration) &&
            exactProxyAttribution(proxiedRequest, meta.host, forwarded, correlation.caseId, state.configuration);
          const event = appendEvent(
            state, request, correlation.caseId, "P", originalMatched,
            { headerCount: oidcValues.length, official: true, independent, sourceMatched },
            options.actionKey, pOrigin.hostname,
          );
          if (!event || !originalMatched) return new Response(null, { status: 409 });
          const verified = independent.verified && sourceMatched;
          return Response.json(eventResponse(event), { status: verified ? 200 : 403 });
        },
        async () => {
          state.unattributedRequests += 1;
          return new Response(null, { status: 403 });
        },
      );
      await sendWebResponse(response, await handler(publicRequest));
    } catch {
      const state = countableIngress
        ? attributedState ?? stateFromExactRunHeader(request, states)
        : undefined;
      if (state) state.unexpectedPRequests += 1;
      if (!response.headersSent) sendEmpty(response, 400); else response.destroy();
    } finally {
      rawToken = undefined;
    }
  });

  const host = options.host ?? "127.0.0.1";
  const aPort = await listen(aServer, host, options.aPort ?? 43150);
  let pPort: number;
  try { pPort = await listen(pServer, host, options.pPort ?? 43151); }
  catch (error) { await closeServer(aServer); throw error; }
  return {
    aServer, pServer, aPort, pPort,
    async close() { await Promise.all([closeServer(aServer), closeServer(pServer)]); },
  };
}

async function main(): Promise<void> {
  const handle = await createSbx050Receiver({
    adminKey: process.env.SBX050_ADMIN_KEY ?? "",
    actionKey: process.env.SBX050_ACTION_KEY ?? "",
    aPublicOrigin: process.env.SBX050_A_PUBLIC_ORIGIN ?? "",
    pPublicOrigin: process.env.SBX050_P_PUBLIC_ORIGIN ?? "",
    aPort: Number.parseInt(process.env.SBX050_A_PORT ?? "43150", 10),
    pPort: Number.parseInt(process.env.SBX050_P_PORT ?? "43151", 10),
    host: process.env.SBX050_LISTEN_HOST ?? "127.0.0.1",
  });
  process.stdout.write(`${JSON.stringify({ ready: true, aPort: handle.aPort, pPort: handle.pPort })}\n`);
  const shutdown = async (): Promise<void> => { await handle.close(); process.exit(0); };
  process.once("SIGINT", () => void shutdown());
  process.once("SIGTERM", () => void shutdown());
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
