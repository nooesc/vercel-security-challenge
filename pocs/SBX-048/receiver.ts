import "dotenv/config";

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { isIP } from "node:net";
import {
  createRemoteJWKSet,
  decodeJwt,
  decodeProtectedHeader,
  jwtVerify,
  type JWTPayload,
} from "jose";
import {
  exactDenyAll,
  exactRawForwardPolicy,
  SBX048_TEST_ID,
  type Sbx048ControlPlaneAttempt,
  type Sbx048OidcEvidence,
  type Sbx048ReceiverRecord,
} from "./verdict.js";

const OIDC_HEADER = "vercel-sandbox-oidc-token";
const FORWARDED_HOST = "vercel-forwarded-host";
const FORWARDED_SCHEME = "vercel-forwarded-scheme";
const FORWARDED_PORT = "vercel-forwarded-port";
const FORWARDED_PATH = "vercel-forwarded-path";
const RUN_HEADER = "x-sbx048-run";
const CASE_HEADER = "x-sbx048-case";
const CANARY_HEADER = "x-sbx048-canary";
const FORWARD_CASE = "brokered-control-plane-probe";
const MAX_BODY_BYTES = 65_536;
const MAX_STATES = 4;
const CONTROL_PLANE_BASE = "https://vercel.com/api";
const MINIMUM_CONTROL_PLANE_SPACING_MS = 250;
const OPERATION_ID = /^oid48_[A-Za-z0-9_-]{24}$/u;
const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const LOCAL_TLS_TRUST_ENVIRONMENT_NAMES = [
  "NODE_EXTRA_CA_CERTS",
  "NODE_USE_SYSTEM_CA",
  "OPENSSL_CONF",
  "OPENSSL_MODULES",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
] as const;

export interface ReceiverConfiguration {
  runId: string;
  publicOrigin: string;
  forwardAudience: string;
  wrongAudience: string;
  sourceHostname: string;
  sourcePath: string;
  expectedTeamId: string;
  expectedProjectId: string;
  expectedSandboxId: string;
  expectedSandboxName: string;
  correlationCanary: string;
  mutationEnabled: boolean;
}

export interface ReceiverReadback {
  configured: boolean;
  configuration?: ReceiverConfiguration;
  fakeControl?: Sbx048ControlPlaneAttempt;
  directRecords: Array<{
    observedAt: string;
    operationId: string;
    correlationExact: boolean;
    oidcHeaderLines: number;
    oidcHeaderValues: number;
  }>;
  records: Sbx048ReceiverRecord[];
}

interface RunState {
  configuration: ReceiverConfiguration;
  fakeControlClaimed: boolean;
  brokeredRequestClaimed: boolean;
  fakeControl?: Sbx048ControlPlaneAttempt;
  directRecords: ReceiverReadback["directRecords"];
  records: Sbx048ReceiverRecord[];
}

interface VerificationResult {
  accepted: boolean;
  evidence?: Sbx048OidcEvidence;
}

interface ReceiverOptions {
  adminKey: string;
  publicOrigin: string;
  port?: number;
  host?: string;
  fetchImpl?: typeof fetch;
  verifyImpl?: (token: string, configuration: ReceiverConfiguration) => Promise<VerificationResult>;
}

export interface ReceiverHandle {
  server: Server;
  port: number;
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

function safeOrigin(raw: string, name: string): URL {
  const parsed = new URL(raw);
  if (
    raw !== parsed.origin || parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.port ||
    parsed.pathname !== "/" || parsed.search || parsed.hash || isIP(parsed.hostname) !== 0 ||
    parsed.hostname !== parsed.hostname.toLowerCase()
  ) {
    throw new Error(`${name} must be an exact lower-case public HTTPS origin`);
  }
  return parsed;
}

function safeString(value: unknown, name: string, maximum = 2_048): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[\0\r\n]/u.test(value)) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((entry, index) => entry === wanted[index]);
}

export function validateConfiguration(value: unknown, receiverOrigin: URL): ReceiverConfiguration {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("configuration must be an object");
  }
  const input = value as Record<string, unknown>;
  const keys = [
    "correlationCanary", "expectedProjectId", "expectedSandboxId", "expectedSandboxName", "expectedTeamId",
    "forwardAudience", "mutationEnabled", "publicOrigin", "runId", "sourceHostname", "sourcePath",
    "wrongAudience",
  ];
  if (!exactKeys(input, keys)) throw new Error("configuration fields are not exact");
  const runId = safeString(input.runId, "runId", 64);
  if (!RUN_ID.test(runId)) throw new Error("runId must be a canonical UUIDv4");
  const publicOrigin = safeOrigin(safeString(input.publicOrigin, "publicOrigin"), "publicOrigin");
  if (publicOrigin.origin !== receiverOrigin.origin) throw new Error("publicOrigin does not match receiver origin");
  const forwardAudience = new URL(safeString(input.forwardAudience, "forwardAudience"));
  const wrongAudience = new URL(safeString(input.wrongAudience, "wrongAudience"));
  const expectedForward = new URL(`/v1/sbx048/forward/${encodeURIComponent(runId)}`, receiverOrigin);
  const expectedWrong = new URL(`/v1/sbx048/wrong-audience/${encodeURIComponent(runId)}`, receiverOrigin);
  if (forwardAudience.toString() !== expectedForward.toString()) throw new Error("forwardAudience is not exact");
  if (wrongAudience.toString() !== expectedWrong.toString()) throw new Error("wrongAudience is not exact");
  const sourceHostname = safeString(input.sourceHostname, "sourceHostname", 253).toLowerCase();
  if (sourceHostname !== receiverOrigin.hostname) throw new Error("sourceHostname must equal the owned receiver hostname");
  const sourcePath = safeString(input.sourcePath, "sourcePath", 512);
  if (sourcePath !== `/v1/sbx048/source/${encodeURIComponent(runId)}`) throw new Error("sourcePath is not exact");
  if (input.mutationEnabled !== true) throw new Error("mutationEnabled must be explicitly true");
  return {
    runId,
    publicOrigin: publicOrigin.origin,
    forwardAudience: forwardAudience.toString(),
    wrongAudience: wrongAudience.toString(),
    sourceHostname,
    sourcePath,
    expectedTeamId: safeString(input.expectedTeamId, "expectedTeamId", 128),
    expectedProjectId: safeString(input.expectedProjectId, "expectedProjectId", 128),
    expectedSandboxId: safeString(input.expectedSandboxId, "expectedSandboxId", 128),
    expectedSandboxName: safeString(input.expectedSandboxName, "expectedSandboxName", 256),
    correlationCanary: safeString(input.correlationCanary, "correlationCanary", 128),
    mutationEnabled: true,
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

async function boundedJson(response: Response): Promise<unknown> {
  if (!response.body) return undefined;
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let length = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      length += part.value.length;
      if (length > MAX_BODY_BYTES) throw new Error("control-plane response exceeded byte bound");
      chunks.push(Buffer.from(part.value));
    }
  } finally {
    reader.releaseLock();
  }
  if (length === 0) return undefined;
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

async function discardBody(response: Response): Promise<void> {
  if (response.body) await response.body.cancel().catch(() => undefined);
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

function claim(payload: JWTPayload, name: string): string | undefined {
  const value = payload[name];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function exactAudience(actual: JWTPayload["aud"], expected: string): boolean {
  return actual === expected || (Array.isArray(actual) && actual.length === 1 && actual[0] === expected);
}

function exactIssuer(raw: unknown, expectedTeamId: string): string {
  const issuer = safeString(raw, "OIDC issuer", 512);
  const parsed = new URL(issuer);
  if (
    parsed.protocol !== "https:" || parsed.hostname !== "oidc.vercel.com" || parsed.username || parsed.password ||
    parsed.port || parsed.search || parsed.hash || parsed.pathname !== `/${expectedTeamId}`
  ) {
    throw new Error("OIDC issuer is not the exact expected team issuer");
  }
  return issuer;
}

function getJwks(issuer: string): ReturnType<typeof createRemoteJWKSet> {
  const existing = jwks.get(issuer);
  if (existing) return existing;
  const created = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks`), {
    timeoutDuration: 5_000,
    cooldownDuration: 30_000,
  });
  jwks.set(issuer, created);
  return created;
}

export async function verifyBrokeredToken(
  token: string,
  configuration: ReceiverConfiguration,
): Promise<VerificationResult> {
  try {
    if (decodeProtectedHeader(token).alg !== "RS256") return { accepted: false };
    const issuer = exactIssuer(decodeJwt(token).iss, configuration.expectedTeamId);
    const keySet = getJwks(issuer);
    const { payload } = await jwtVerify(token, keySet, {
      algorithms: ["RS256"],
      issuer,
      audience: configuration.forwardAudience,
      clockTolerance: 60,
    });
    const audienceVerified = exactAudience(payload.aud, configuration.forwardAudience);
    const now = Math.floor(Date.now() / 1_000);
    const temporalClaimsVerified = typeof payload.iat === "number" && typeof payload.exp === "number" &&
      payload.iat <= now + 60 && payload.exp >= now - 60 && payload.exp > payload.iat;
    const teamId = claim(payload, "team_id") ?? "missing";
    const projectId = claim(payload, "project_id") ?? "missing";
    const sandboxId = claim(payload, "sandbox_id") ?? "missing";
    const sandboxName = claim(payload, "sandbox_name") ?? sandboxId;
    const exactSourceIdentityVerified = teamId === configuration.expectedTeamId &&
      projectId === configuration.expectedProjectId && sandboxId === configuration.expectedSandboxId &&
      sandboxName === configuration.expectedSandboxName;
    let wrongAudienceRejected = false;
    try {
      await jwtVerify(token, keySet, {
        algorithms: ["RS256"],
        issuer,
        audience: configuration.wrongAudience,
        clockTolerance: 60,
      });
    } catch (error) {
      const candidate = error as { code?: unknown; claim?: unknown };
      wrongAudienceRejected = candidate.code === "ERR_JWT_CLAIM_VALIDATION_FAILED" && candidate.claim === "aud";
    }
    const evidence: Sbx048OidcEvidence = {
      verifier: "independent-jose",
      signatureVerified: true,
      algorithmRs256: true,
      issuerVerified: true,
      audienceVerified,
      temporalClaimsVerified,
      exactSourceIdentityVerified,
      wrongAudienceRejected,
      issuer,
      audience: audienceVerified ? configuration.forwardAudience : "non-exact-audience",
      identity: { teamId, projectId, sandboxId, sandboxName },
      ownerIdClaimPresent: claim(payload, "owner_id") !== undefined,
      teamIdClaimPresent: claim(payload, "team_id") !== undefined,
      rawTokenRetained: false,
      rawTokenDigestRetained: false,
    };
    return {
      accepted: audienceVerified && temporalClaimsVerified && exactSourceIdentityVerified && wrongAudienceRejected,
      evidence,
    };
  } catch {
    return { accepted: false };
  }
}

function sessionPath(configuration: ReceiverConfiguration, verifiedTeamId: string): string {
  if (verifiedTeamId !== configuration.expectedTeamId) throw new Error("verified team claim does not match owned scope");
  const path = `/v2/sandboxes/sessions/${encodeURIComponent(configuration.expectedSandboxId)}`;
  const query = new URLSearchParams({ teamId: verifiedTeamId });
  return `${path}?${query.toString()}`;
}

function attemptBase(
  kind: Sbx048ControlPlaneAttempt["kind"],
  method: Sbx048ControlPlaneAttempt["method"],
  statusCode: number,
): Sbx048ControlPlaneAttempt {
  return {
    kind,
    method,
    endpointFamily: method === "GET"
      ? "/v2/sandboxes/sessions/:sessionId"
      : "/v2/sandboxes/sessions/:sessionId/network-policy",
    requestCount: 1,
    statusCode,
    responseBodyRetained: false,
    responseHeadersRetained: false,
    rawTokenRetained: false,
    rawTokenDigestRetained: false,
  };
}

export async function controlPlaneRead(
  fetchImpl: typeof fetch,
  token: string,
  configuration: ReceiverConfiguration,
  kind: "fake-token-read" | "brokered-token-read",
  verifiedTeamId = configuration.expectedTeamId,
): Promise<Sbx048ControlPlaneAttempt> {
  try {
    const response = await fetchImpl(`${CONTROL_PLANE_BASE}${sessionPath(configuration, verifiedTeamId)}`, {
      method: "GET",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${token}`,
        "user-agent": "vercel-sandbox-security-research/sbx-048",
      },
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
    });
    const base = attemptBase(kind, "GET", response.status);
    if (response.status !== 200) {
      await discardBody(response);
      return base;
    }
    const payload = await boundedJson(response);
    const root = payload !== null && typeof payload === "object" && !Array.isArray(payload)
      ? payload as Record<string, unknown>
      : undefined;
    const session = root?.session !== null && typeof root?.session === "object" && !Array.isArray(root.session)
      ? root.session as Record<string, unknown>
      : undefined;
    return {
      ...base,
      exactSession: session?.id === configuration.expectedSandboxId,
      exactPolicy: exactRawForwardPolicy(session?.networkPolicy, configuration.sourceHostname, configuration.forwardAudience),
      ...(exactRawForwardPolicy(session?.networkPolicy, configuration.sourceHostname, configuration.forwardAudience)
        ? { policyShape: "legacy-raw-custom" as const }
        : {}),
    };
  } catch {
    return { ...attemptBase(kind, "GET", 0), transportError: true };
  }
}

export async function controlPlaneMutation(
  fetchImpl: typeof fetch,
  token: string,
  configuration: ReceiverConfiguration,
  verifiedTeamId = configuration.expectedTeamId,
): Promise<Sbx048ControlPlaneAttempt> {
  try {
    if (verifiedTeamId !== configuration.expectedTeamId) throw new Error("verified team claim does not match owned scope");
    const path = `/v2/sandboxes/sessions/${encodeURIComponent(configuration.expectedSandboxId)}/network-policy`;
    const query = new URLSearchParams({ teamId: verifiedTeamId });
    const response = await fetchImpl(`${CONTROL_PLANE_BASE}${path}?${query.toString()}`, {
      method: "POST",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        "user-agent": "vercel-sandbox-security-research/sbx-048",
      },
      body: JSON.stringify({ mode: "deny-all" }),
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
    });
    const base = attemptBase("brokered-token-policy-mutation", "POST", response.status);
    if (response.status !== 200) {
      await discardBody(response);
      return base;
    }
    const payload = await boundedJson(response);
    const root = payload !== null && typeof payload === "object" && !Array.isArray(payload)
      ? payload as Record<string, unknown>
      : undefined;
    const session = root?.session !== null && typeof root?.session === "object" && !Array.isArray(root.session)
      ? root.session as Record<string, unknown>
      : undefined;
    return {
      ...base,
      exactSession: session?.id === configuration.expectedSandboxId,
      exactPolicy: exactDenyAll(session?.networkPolicy),
      ...(exactDenyAll(session?.networkPolicy) ? { policyShape: "literal-mode" as const } : {}),
    };
  } catch {
    return { ...attemptBase("brokered-token-policy-mutation", "POST", 0), transportError: true };
  }
}

function runIdFromPath(pathname: string, prefix: string): string | undefined {
  if (!pathname.startsWith(prefix)) return undefined;
  const encoded = pathname.slice(prefix.length).split("/")[0];
  if (!encoded) return undefined;
  try {
    const value = decodeURIComponent(encoded);
    return RUN_ID.test(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

function operationId(): string {
  const id = `oid48_${randomBytes(18).toString("base64url")}`;
  if (!OPERATION_ID.test(id)) throw new Error("operation ID invariant failed");
  return id;
}

function forwardedMetadataExact(request: IncomingMessage, configuration: ReceiverConfiguration): boolean {
  return request.headers[FORWARDED_HOST] === configuration.sourceHostname &&
    request.headers[FORWARDED_SCHEME] === "https" && request.headers[FORWARDED_PORT] === "443" &&
    request.headers[FORWARDED_PATH] === configuration.sourcePath;
}

function correlationExact(request: IncomingMessage, configuration: ReceiverConfiguration): boolean {
  return request.headers[RUN_HEADER] === configuration.runId &&
    request.headers[CASE_HEADER] === FORWARD_CASE &&
    request.headers[CANARY_HEADER] === configuration.correlationCanary;
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

export function requireStrictReceiverTlsEnvironment(environment: NodeJS.ProcessEnv = process.env): void {
  if (environment.NODE_TLS_REJECT_UNAUTHORIZED === "0" ||
      (environment.NODE_OPTIONS !== undefined && environment.NODE_OPTIONS.trim() !== "") ||
      LOCAL_TLS_TRUST_ENVIRONMENT_NAMES.some((name) => environment[name] !== undefined)) {
    throw new Error("SBX-048 receiver refuses local TLS trust overrides or runtime injection");
  }
}

export async function createSbx048Receiver(options: ReceiverOptions): Promise<ReceiverHandle> {
  requireStrictReceiverTlsEnvironment();
  if (Buffer.byteLength(options.adminKey) < 32 || Buffer.byteLength(options.adminKey) > 256 || /[\0\r\n]/u.test(options.adminKey)) {
    throw new Error("adminKey must contain 32-256 safe bytes");
  }
  const origin = safeOrigin(options.publicOrigin, "publicOrigin");
  const rawFetch = options.fetchImpl ?? fetch;
  let nextControlPlaneRequestAt = 0;
  const fetchImpl = (async (input: string | URL | globalThis.Request, init?: RequestInit): Promise<Response> => {
    const wait = Math.max(0, nextControlPlaneRequestAt - Date.now());
    if (wait > 0) await new Promise<void>((resolve) => globalThis.setTimeout(resolve, wait));
    nextControlPlaneRequestAt = Date.now() + MINIMUM_CONTROL_PLANE_SPACING_MS;
    return rawFetch(input, init);
  }) as typeof fetch;
  const verifyImpl = options.verifyImpl ?? verifyBrokeredToken;
  const states = new Map<string, RunState>();

  const server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", origin);
      if (request.method === "GET" && url.pathname === "/healthz") {
        return sendJson(response, 200, { ok: true, role: "SBX-048-P" });
      }

      const adminRunId = runIdFromPath(url.pathname, "/v1/sbx048/admin/runs/");
      const adminBase = adminRunId ? `/v1/sbx048/admin/runs/${encodeURIComponent(adminRunId)}` : undefined;
      if (adminRunId && adminBase && (url.pathname === adminBase || url.pathname === `${adminBase}/fake-control`)) {
        if (!adminAuthorized(request, options.adminKey)) return sendJson(response, 401, { error: "unauthorized" });
        if (request.method === "POST" && url.pathname === adminBase) {
          if (states.size >= MAX_STATES) return sendJson(response, 429, { error: "state limit reached" });
          if (states.has(adminRunId)) return sendJson(response, 409, { error: "already configured" });
          const configuration = validateConfiguration(await readJson(request), origin);
          if (configuration.runId !== adminRunId) return sendJson(response, 400, { error: "run mismatch" });
          states.set(adminRunId, {
            configuration,
            fakeControlClaimed: false,
            brokeredRequestClaimed: false,
            directRecords: [],
            records: [],
          });
          return sendJson(response, 201, { configured: true });
        }
        const state = states.get(adminRunId);
        if (request.method === "POST" && url.pathname === `${adminBase}/fake-control`) {
          if (!state) return sendJson(response, 404, { error: "not configured" });
          if (state.fakeControlClaimed) return sendJson(response, 409, { error: "fake control already performed" });
          state.fakeControlClaimed = true;
          state.fakeControl = await controlPlaneRead(
            fetchImpl,
            `sbx048-invalid-control-${adminRunId}`,
            state.configuration,
            "fake-token-read",
          );
          return sendJson(response, 200, { completed: true, attempt: state.fakeControl });
        }
        if (request.method === "GET" && url.pathname === adminBase) {
          return state
            ? sendJson(response, 200, {
                configured: true,
                configuration: state.configuration,
                ...(state.fakeControl ? { fakeControl: state.fakeControl } : {}),
                directRecords: state.directRecords,
                records: state.records,
              })
            : sendJson(response, 404, { configured: false });
        }
        if (request.method === "DELETE" && url.pathname === adminBase) {
          const deleted = states.delete(adminRunId);
          return sendJson(response, deleted ? 200 : 404, { deleted });
        }
        return sendJson(response, 405, { error: "method not allowed" });
      }

      const directRunId = runIdFromPath(url.pathname, "/v1/sbx048/source/");
      if (directRunId && url.pathname === `/v1/sbx048/source/${encodeURIComponent(directRunId)}` && request.method === "GET") {
        const state = states.get(directRunId);
        if (!state) return sendJson(response, 404, { error: "not configured" });
        const counts = rawHeaderCount(request, OIDC_HEADER);
        const correlated = correlationExact(request, state.configuration);
        if (!correlated || counts.lines !== 0 || counts.values !== 0) {
          return sendJson(response, 400, { error: "direct control mismatch" });
        }
        const id = operationId();
        state.directRecords.push({
          observedAt: new Date().toISOString(),
          operationId: id,
          correlationExact: correlated,
          oidcHeaderLines: counts.lines,
          oidcHeaderValues: counts.values,
        });
        return sendJson(response, 200, { direct: true, operationId: id });
      }

      const runId = runIdFromPath(url.pathname, "/v1/sbx048/forward/");
      const state = runId ? states.get(runId) : undefined;
      if (!runId || !state || request.method !== "GET") return sendJson(response, 404, { error: "not found" });
      if (state.brokeredRequestClaimed) return sendJson(response, 409, { error: "one brokered request already processed" });
      if (!state.fakeControl || (state.fakeControl.statusCode !== 401 && state.fakeControl.statusCode !== 403)) {
        return sendJson(response, 412, { error: "fake-token rejection control missing" });
      }
      const counts = rawHeaderCount(request, OIDC_HEADER);
      const token = counts.lines === 1 && counts.values === 1 && typeof request.headers[OIDC_HEADER] === "string"
        ? request.headers[OIDC_HEADER]
        : undefined;
      const metadataExact = forwardedMetadataExact(request, state.configuration);
      const correlation = correlationExact(request, state.configuration);
      if (token && metadataExact && correlation) state.brokeredRequestClaimed = true;
      const verified = token && metadataExact && correlation
        ? await verifyImpl(token, state.configuration)
        : { accepted: false };
      if (!token || !verified.accepted || !verified.evidence) {
        return sendJson(response, 403, { authenticated: false, operationId: operationId() });
      }

      const brokeredRead = await controlPlaneRead(
        fetchImpl,
        token,
        state.configuration,
        "brokered-token-read",
        verified.evidence.identity.teamId,
      );
      const exactRead = brokeredRead.statusCode === 200 && brokeredRead.exactSession === true &&
        brokeredRead.exactPolicy === true && brokeredRead.policyShape === "legacy-raw-custom";
      const brokeredMutation = exactRead && state.configuration.mutationEnabled
        ? await controlPlaneMutation(fetchImpl, token, state.configuration, verified.evidence.identity.teamId)
        : undefined;
      const id = operationId();
      const record: Sbx048ReceiverRecord = {
        schemaVersion: 1,
        testId: SBX048_TEST_ID,
        runId,
        observedAt: new Date().toISOString(),
        requestAttributed: true,
        oidcHeaderLines: counts.lines,
        oidcHeaderValues: counts.values,
        forwardedMetadataExact: metadataExact,
        correlationExact: correlation,
        oidc: verified.evidence,
        fakeControl: state.fakeControl,
        brokeredRead,
        ...(brokeredMutation ? { brokeredMutation } : {}),
        mutationAttemptedOnlyAfterExactRead: brokeredMutation !== undefined && exactRead,
        controlPlaneRequestCounts: {
          fakeToken: 1,
          brokeredRead: 1,
          brokeredMutation: brokeredMutation ? 1 : 0,
          total: brokeredMutation ? 3 : 2,
        },
        responseOperationId: id,
        rawRequestHeadersRetained: false,
        rawTokenRetained: false,
        rawTokenDigestRetained: false,
      };
      state.records.push(record);
      return sendJson(response, 202, {
        authenticated: true,
        operationId: id,
        controlPlaneReadStatus: brokeredRead.statusCode,
        mutationStatus: brokeredMutation?.statusCode ?? null,
      });
    } catch {
      if (!response.headersSent) sendJson(response, 500, { error: "receiver error" });
      else response.destroy();
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 0, options.host ?? "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("receiver did not bind a TCP port");
  return { server, port: address.port, close: async () => closeServer(server) };
}

async function cli(): Promise<void> {
  const adminKey = process.env.SBX048_ADMIN_KEY;
  const publicOrigin = process.env.SBX048_PUBLIC_ORIGIN;
  if (!adminKey || !publicOrigin) throw new Error("SBX048_ADMIN_KEY and SBX048_PUBLIC_ORIGIN are required");
  const receiver = await createSbx048Receiver({
    adminKey,
    publicOrigin,
    port: Number(process.env.SBX048_PORT ?? "43148"),
    host: process.env.SBX048_LISTEN_HOST ?? "127.0.0.1",
  });
  process.stdout.write(`${JSON.stringify({ ready: true, port: receiver.port })}\n`);
  const shutdown = async (): Promise<void> => {
    await receiver.close();
    process.exit(0);
  };
  process.once("SIGINT", () => void shutdown());
  process.once("SIGTERM", () => void shutdown());
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  cli().catch((error) => {
    process.stderr.write(`${String(error instanceof Error ? error.message : error).slice(0, 512)}\n`);
    process.exitCode = 1;
  });
}
