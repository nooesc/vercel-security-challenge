import "dotenv/config";

import { randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { APIError, Sandbox } from "@vercel/sandbox";
import { verifyEligibleAliasToken, type EligibleAliasIdentityProof } from "../eligible-alias-identity.js";
import {
  exactSbx051BaseWebSocketUrl,
  runSbx051InteractiveAttempt,
  SBX051_WS_VERSION,
  type Sbx051AttemptPurpose,
  type Sbx051InteractiveAttempt,
  type Sbx051Role,
} from "./protocol.js";
import {
  SBX051_ALIAS,
  SBX051_PROJECT,
  SBX051_TEAM,
  SBX051_TEST_ID,
  acquireSbx051Lock,
  createSbx051Journal,
  loadSbx051Config,
  readSbx051Journal,
  removeSbx051Journal,
  sbx051ArtifactPath,
  sbx051RecoveryArtifactPath,
  writeSbx051Journal,
  writeSbx051PrivateJson,
  writeSbx051PrivateJsonNoClobber,
  type Sbx051Config,
  type Sbx051HeldLock,
  type Sbx051Journal,
  type Sbx051JournalResource,
} from "./safety.js";
import {
  assessSbx051,
  assertSbx051EvidenceHasNoRawCapabilities,
  exactSbx051ReadbackPair,
  type Sbx051Assessment,
  type Sbx051AssessmentInput,
  type Sbx051Chronology,
  type Sbx051ChronologyStep,
  type Sbx051CleanupResource,
  type Sbx051CredentialIssuance,
  type Sbx051SandboxReadback,
} from "./verdict.js";

const SDK_VERSION = "3.0.0";
const CLI_VERSION = "4.0.0";
const SESSION_TIMEOUT_MS = 240_000;
const CONTROL_TIMEOUT_MS = 30_000;
const WEBSOCKET_TIMEOUT_MS = 10_000;
const EXTERNAL_INTERVAL_MS = 250;
const MAX_EXTERNAL_REQUESTS = 100;
export const SBX051_KNOWN_SESSION_ABSENCE_DELAY_MS = 750 as const;
export const SBX051_UNKNOWN_SESSION_ABSENCE_DELAY_MS = 2_000 as const;

type ExternalOperation =
  | "identity-user"
  | "identity-team"
  | "identity-project"
  | `create-${Sbx051Role}`
  | `get-${Sbx051Role}`
  | `list-${Sbx051Role}`
  | `fs-write-${Sbx051Role}`
  | `fs-read-${Sbx051Role}`
  | `fs-cross-absence-${Sbx051Role}`
  | `stat-${Sbx051Role}`
  | `interactive-${Sbx051Role}`
  | `stop-${Sbx051Role}`
  | `delete-${Sbx051Role}`
  | `websocket-${Sbx051AttemptPurpose}`;

export interface Sbx051ExternalAuditRecord {
  sequence: number;
  operation: ExternalOperation;
  method: string;
  startedAt: string;
  completedAt?: string;
  status?: number;
}

export interface Sbx051RequestGate {
  fetch: typeof fetch;
  registerSession(role: Sbx051Role, sessionId: string): void;
  reserveWebSocket(purpose: Sbx051AttemptPurpose): Promise<Sbx051ExternalAuditRecord>;
  completeWebSocket(record: Sbx051ExternalAuditRecord): void;
  summary(): {
    count: number;
    records: Sbx051ExternalAuditRecord[];
    allAllowlisted: boolean;
    contiguous: boolean;
    completed: boolean;
    withinRateLimit: boolean;
    minimumStartIntervalMs?: number;
    rawInteractiveCredentialRequests: number;
    websocketConnections: number;
    unexpectedRequests: number;
  };
}

interface TransientCredential {
  role: Sbx051Role;
  baseUrl: string;
  token: string;
  evidence: Sbx051CredentialIssuance;
}

interface ResourceRuntime {
  plan: Sbx051JournalResource;
  sandbox?: Sandbox;
  marker?: Buffer;
}

export interface CleanupEvidence {
  passed: boolean;
  journalRemoved: boolean;
  lockReleased: boolean;
  resources: Sbx051CleanupResource[];
}

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

function exactTags(actual: Record<string, string> | undefined, expected: Record<string, string>): boolean {
  return actual !== undefined && exactKeys(actual, Object.keys(expected)) &&
    Object.entries(expected).every(([key, value]) => actual[key] === value);
}

function exactQuery(url: URL, expected: Record<string, string>): boolean {
  const entries = [...url.searchParams.entries()];
  const keys = Object.keys(expected);
  return entries.length === keys.length && keys.every((key) =>
    url.searchParams.getAll(key).length === 1 && url.searchParams.get(key) === expected[key]);
}

function requestUrl(input: string | URL | Request): URL {
  return new URL(input instanceof Request ? input.url : input.toString());
}

function requestMethod(input: string | URL | Request, init?: RequestInit): string {
  return (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
}

function requestHeaders(input: string | URL | Request, init?: RequestInit): Headers {
  return new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
}

function parseJsonBody(init?: RequestInit): Record<string, unknown> | undefined {
  if (typeof init?.body !== "string") return undefined;
  try {
    return object(JSON.parse(init.body));
  } catch {
    return undefined;
  }
}

function roleForPlan(
  plans: readonly [Sbx051JournalResource, Sbx051JournalResource],
  name: string,
): Sbx051Role | undefined {
  return plans.find((plan) => plan.name === name)?.role;
}

export function createSbx051RequestGate(
  rawFetch: typeof fetch,
  token: string,
  plans: readonly [Sbx051JournalResource, Sbx051JournalResource],
  options: {
    now?: () => number;
    wait?: (milliseconds: number) => Promise<void>;
  } = {},
): Sbx051RequestGate {
  const now = options.now ?? Date.now;
  const wait = options.wait ?? ((milliseconds: number) => delay(milliseconds));
  const records: Sbx051ExternalAuditRecord[] = [];
  const sessions = new Map<string, Sbx051Role>();
  let unexpectedRequests = 0;
  let lastStart = Number.NEGATIVE_INFINITY;
  let queue = Promise.resolve();

  const reserve = async (operation: ExternalOperation, method: string): Promise<Sbx051ExternalAuditRecord> => {
    if (records.length >= MAX_EXTERNAL_REQUESTS) {
      throw new Error("SBX-051 exceeded its fixed external request budget");
    }
    let release!: () => void;
    const previous = queue;
    queue = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    try {
      const remaining = EXTERNAL_INTERVAL_MS - (now() - lastStart);
      if (remaining > 0) await wait(remaining);
      lastStart = now();
      const record: Sbx051ExternalAuditRecord = {
        sequence: records.length + 1,
        operation,
        method,
        startedAt: new Date(lastStart).toISOString(),
      };
      records.push(record);
      return record;
    } finally {
      release();
    }
  };

  const roleFromSessionPath = (pathname: string): Sbx051Role | undefined => {
    const match = /^\/api\/v2\/sandboxes\/sessions\/([^/]+)(?:\/|$)/u.exec(pathname);
    return match?.[1] === undefined ? undefined : sessions.get(decodeURIComponent(match[1]));
  };

  const classify = (
    input: string | URL | Request,
    init?: RequestInit,
  ): ExternalOperation => {
    const url = requestUrl(input);
    const method = requestMethod(input, init);
    if (url.protocol !== "https:" || url.username !== "" || url.password !== "" || url.hash !== "") {
      throw new Error("SBX-051 request gate rejected unsafe URL components");
    }
    const headers = requestHeaders(input, init);
    if (headers.get("authorization") !== `Bearer ${token}`) {
      throw new Error("SBX-051 request gate rejected a missing or mismatched owner authorization header");
    }
    if (url.origin === "https://api.vercel.com" && method === "GET") {
      if (url.pathname === "/v2/user" && exactQuery(url, {})) return "identity-user";
      if (url.pathname === `/v2/teams/${SBX051_TEAM}` && exactQuery(url, {})) return "identity-team";
      if (url.pathname === `/v9/projects/${SBX051_PROJECT}` &&
          exactQuery(url, { teamId: SBX051_TEAM })) return "identity-project";
      throw new Error("SBX-051 request gate rejected a nonexact identity request");
    }
    if (url.origin !== "https://vercel.com") {
      throw new Error("SBX-051 request gate rejected a non-Vercel origin");
    }
    if (method === "POST" && url.pathname === "/api/v3/sandboxes" &&
        exactQuery(url, { teamId: SBX051_TEAM })) {
      const body = parseJsonBody(init);
      const role = typeof body?.name === "string" ? roleForPlan(plans, body.name) : undefined;
      const plan = role === undefined ? undefined : plans.find((entry) => entry.role === role);
      if (body === undefined || role === undefined || plan === undefined ||
          !exactKeys(body, ["projectId", "ports", "timeout", "resources", "name", "persistent",
            "networkPolicy", "tags", "__interactive"]) || body.projectId !== SBX051_PROJECT ||
          body.name !== plan.name || body.persistent !== false || body.timeout !== SESSION_TIMEOUT_MS ||
          body.__interactive !== true || !Array.isArray(body.ports) || body.ports.length !== 0 ||
          !exactKeys(object(body.resources) ?? {}, ["vcpus"]) || object(body.resources)?.vcpus !== 2 ||
          !exactKeys(object(body.networkPolicy) ?? {}, ["mode"]) ||
          object(body.networkPolicy)?.mode !== "deny-all" || !exactTags(
            object(body.tags) as Record<string, string> | undefined,
            plan.tags,
          )) {
        throw new Error("SBX-051 request gate rejected a nonexact sandbox create");
      }
      return `create-${role}`;
    }
    if (method === "GET" && url.pathname === "/api/v2/sandboxes") {
      const namePrefix = url.searchParams.get("namePrefix");
      const role = namePrefix === null ? undefined : roleForPlan(plans, namePrefix);
      if (role === undefined || !exactQuery(url, {
        teamId: SBX051_TEAM,
        project: SBX051_PROJECT,
        limit: "10",
        sortBy: "name",
        sortOrder: "asc",
        namePrefix: namePrefix!,
      })) throw new Error("SBX-051 request gate rejected a nonexact cleanup list");
      return `list-${role}`;
    }
    const named = /^\/api\/v2\/sandboxes\/(?!sessions(?:\/|$))([^/]+)$/u.exec(url.pathname);
    if (named?.[1] !== undefined) {
      const decoded = decodeURIComponent(named[1]);
      const role = roleForPlan(plans, decoded);
      if (role === undefined) throw new Error("SBX-051 request gate rejected a foreign sandbox name");
      if (method === "GET" && exactQuery(url, {
        teamId: SBX051_TEAM,
        projectId: SBX051_PROJECT,
        __interactive: "true",
        resume: "false",
      })) return `get-${role}`;
      if (method === "DELETE" && exactQuery(url, {
        teamId: SBX051_TEAM,
        projectId: SBX051_PROJECT,
      })) return `delete-${role}`;
      throw new Error("SBX-051 request gate rejected a nonexact named-sandbox request");
    }
    const role = roleFromSessionPath(url.pathname);
    if (role === undefined || !exactQuery(url, { teamId: SBX051_TEAM })) {
      throw new Error("SBX-051 request gate rejected an unknown session or query");
    }
    const suffix = url.pathname.replace(/^\/api\/v2\/sandboxes\/sessions\/[^/]+/u, "");
    if (method === "POST" && suffix === "/fs/write") return `fs-write-${role}`;
    if (method === "POST" && suffix === "/fs/read") {
      const body = parseJsonBody(init);
      const plan = plans.find((entry) => entry.role === role)!;
      const other = plans.find((entry) => entry.role !== role)!;
      if (body === undefined || !exactKeys(body, ["path"]) ||
          (body.path !== plan.markerPath && body.path !== other.markerPath)) {
        throw new Error("SBX-051 request gate rejected a nonexact owner marker read");
      }
      return body.path === plan.markerPath ? `fs-read-${role}` : `fs-cross-absence-${role}`;
    }
    if (method === "POST" && suffix === "/cmd") {
      const body = parseJsonBody(init);
      const plan = plans.find((entry) => entry.role === role)!;
      if (body === undefined || body.command !== "stat" || !Array.isArray(body.args) ||
          body.args.length !== 3 || body.args[0] !== "-c" ||
          body.args[1] !== "%s|%f|%u|%g|%X|%Y|%Z|%W|%h|%i|%d|%B|%b" ||
          body.args[2] !== plan.markerPath || body.wait !== true ||
          body.logs !== true || body.sudo !== false || !exactKeys(object(body.env) ?? {}, [])) {
        throw new Error("SBX-051 request gate rejected a nonexact owner marker stat");
      }
      return `stat-${role}`;
    }
    if (method === "POST" && suffix === "/interactive") {
      const body = parseJsonBody(init);
      if (body === undefined || !exactKeys(body, [])) {
        throw new Error("SBX-051 request gate rejected a nonempty interactive request");
      }
      return `interactive-${role}`;
    }
    if (method === "POST" && suffix === "/stop") return `stop-${role}`;
    throw new Error("SBX-051 request gate rejected a non-allowlisted Sandbox operation");
  };

  const gatedFetch = (async (input: string | URL | Request, init?: RequestInit) => {
    let operation: ExternalOperation;
    try {
      operation = classify(input, init);
    } catch (error) {
      unexpectedRequests += 1;
      throw error;
    }
    const record = await reserve(operation, requestMethod(input, init));
    try {
      const response = await rawFetch(input, { ...init, redirect: "error" });
      record.status = response.status;
      record.completedAt = new Date(now()).toISOString();
      if (response.status === 429 || response.status >= 500) {
        await response.body?.cancel().catch(() => undefined);
        throw new DOMException("SBX-051 single-attempt fetch stopped on a retryable response", "AbortError");
      }
      return response;
    } catch (error) {
      record.completedAt ??= new Date(now()).toISOString();
      if (error instanceof DOMException && error.name === "AbortError") throw error;
      throw new DOMException("SBX-051 single-attempt fetch failed without retry", "AbortError");
    }
  }) as typeof fetch;

  return {
    fetch: gatedFetch,
    registerSession(role, sessionId): void {
      if (!/^sbx_[A-Za-z0-9_-]{8,192}$/u.test(sessionId)) {
        throw new Error("SBX-051 refused a malformed session ID");
      }
      const existing = sessions.get(sessionId);
      if (existing !== undefined && existing !== role) {
        throw new Error("SBX-051 refused one session ID assigned to both roles");
      }
      for (const [otherId, otherRole] of sessions) {
        if (otherRole === role && otherId !== sessionId) {
          throw new Error("SBX-051 refused session drift for one role");
        }
      }
      sessions.set(sessionId, role);
    },
    reserveWebSocket: (purpose) => reserve(`websocket-${purpose}`, "GET"),
    completeWebSocket(record): void {
      if (!record.operation.startsWith("websocket-") || record.completedAt !== undefined) {
        throw new Error("SBX-051 refused an invalid WebSocket audit completion");
      }
      record.completedAt = new Date(now()).toISOString();
    },
    summary() {
      const starts = records.map((record) => Date.parse(record.startedAt));
      const intervals = starts.slice(1).map((start, index) => start - starts[index]!);
      const minimum = intervals.length === 0 ? undefined : Math.min(...intervals);
      return {
        count: records.length,
        records: records.map((record) => ({ ...record })),
        allAllowlisted: unexpectedRequests === 0,
        contiguous: records.every((record, index) => record.sequence === index + 1),
        completed: records.every((record) => record.completedAt !== undefined),
        withinRateLimit: minimum === undefined || minimum >= EXTERNAL_INTERVAL_MS - 2,
        ...(minimum === undefined ? {} : { minimumStartIntervalMs: minimum }),
        rawInteractiveCredentialRequests: records.filter((record) =>
          record.operation === "interactive-A" || record.operation === "interactive-B").length,
        websocketConnections: records.filter((record) => record.operation.startsWith("websocket-")).length,
        unexpectedRequests,
      };
    },
  };
}

function credentials(config: Sbx051Config, gate: Sbx051RequestGate) {
  return { token: config.token, teamId: config.teamId, projectId: config.projectId, fetch: gate.fetch };
}

function resource(journal: Sbx051Journal, role: Sbx051Role): Sbx051JournalResource {
  const result = journal.resources.find((entry) => entry.role === role);
  if (result === undefined) throw new Error(`SBX-051 journal lacks role ${role}`);
  return result;
}

function createParams(
  config: Sbx051Config,
  gate: Sbx051RequestGate,
  plan: Sbx051JournalResource,
): Parameters<typeof Sandbox.create>[0] {
  return {
    ...credentials(config, gate),
    name: plan.name,
    persistent: false,
    timeout: SESSION_TIMEOUT_MS,
    resources: { vcpus: 2 },
    ports: [],
    networkPolicy: "deny-all",
    tags: plan.tags,
    __interactive: true,
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  };
}

function getParams(
  config: Sbx051Config,
  gate: Sbx051RequestGate,
  plan: Sbx051JournalResource,
): Parameters<typeof Sandbox.get>[0] {
  return {
    ...credentials(config, gate),
    name: plan.name,
    resume: false,
    __interactive: true,
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  };
}

function exactInteractiveRoute(sandbox: Sandbox): boolean {
  const port = sandbox.interactivePort;
  if (!Number.isSafeInteger(port) || port === undefined || port < 1 || port > 65_535 ||
      sandbox.currentSession().interactivePort !== port || sandbox.routes.length !== 1) return false;
  const route = sandbox.routes[0]!;
  let url: URL;
  try {
    url = new URL(route.url);
  } catch {
    return false;
  }
  return route.port === port && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(route.subdomain) &&
    url.protocol === "https:" && url.username === "" && url.password === "" && url.port === "" &&
    url.search === "" && url.hash === "" && url.pathname === "/" &&
    url.hostname === `${route.subdomain}.vercel.run` &&
    (route.url === url.origin || route.url === `${url.origin}/`);
}

function exactCreatedSandbox(sandbox: Sandbox, plan: Sbx051JournalResource): boolean {
  return sandbox.name === plan.name && exactTags(sandbox.tags, plan.tags) && !sandbox.persistent &&
    sandbox.status === "running" && sandbox.networkPolicy === "deny-all" &&
    sandbox.currentSession().networkPolicy === "deny-all" && exactInteractiveRoute(sandbox);
}

async function ownerMarkerProof(
  sandbox: Sandbox,
  plan: Sbx051JournalResource,
  otherPlan: Sbx051JournalResource,
  marker: Buffer,
): Promise<{ exact: boolean; mode0600: boolean; otherMarkerAbsent: boolean }> {
  const readback = await sandbox.currentSession().readFileToBuffer(
    { path: plan.markerPath },
    { signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) },
  );
  let exact = false;
  try {
    exact = readback !== null && readback.length === marker.length && readback.equals(marker);
  } finally {
    readback?.fill(0);
  }
  const stat = await sandbox.fs.lstat(plan.markerPath, {
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  });
  const crossRead = await sandbox.currentSession().readFileToBuffer(
    { path: otherPlan.markerPath },
    { signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) },
  );
  const otherMarkerAbsent = crossRead === null;
  crossRead?.fill(0);
  return {
    exact,
    mode0600: stat.isFile() && stat.size === marker.length && (stat.mode & 0o777) === 0o600,
    otherMarkerAbsent,
  };
}

async function readbackSandbox(
  config: Sbx051Config,
  gate: Sbx051RequestGate,
  active: Sandbox,
  plan: Sbx051JournalResource,
  otherPlan: Sbx051JournalResource,
  marker: Buffer,
): Promise<Sbx051SandboxReadback> {
  const independent = await Sandbox.get(getParams(config, gate, plan));
  gate.registerSession(plan.role, independent.currentSession().sessionId);
  const markerProof = await ownerMarkerProof(independent, plan, otherPlan, marker);
  return {
    role: plan.role,
    name: active.name,
    markerPath: plan.markerPath,
    otherMarkerPath: otherPlan.markerPath,
    otherMarkerAbsent: markerProof.otherMarkerAbsent,
    activeSessionId: active.currentSession().sessionId,
    independentSessionId: independent.currentSession().sessionId,
    activeStatus: active.status,
    independentStatus: independent.status,
    exactName: active.name === plan.name && independent.name === plan.name,
    exactTags: exactTags(active.tags, plan.tags),
    independentTags: exactTags(independent.tags, plan.tags),
    nonpersistent: !active.persistent,
    independentNonpersistent: !independent.persistent,
    sandboxDenyAll: active.networkPolicy === "deny-all",
    sessionDenyAll: active.currentSession().networkPolicy === "deny-all",
    independentSandboxDenyAll: independent.networkPolicy === "deny-all",
    independentSessionDenyAll: independent.currentSession().networkPolicy === "deny-all",
    interactivePort: active.interactivePort ?? null,
    independentInteractivePort: independent.interactivePort ?? null,
    exactSingleInteractiveRoute: exactInteractiveRoute(active),
    independentRouteCount: independent.routes.length,
    ownerMarkerExact: markerProof.exact,
    markerMode0600: markerProof.mode0600,
    markerLength: marker.length,
    rawMarkerRetained: false,
    rawMarkerDigestRetained: false,
  };
}

async function boundedJson(response: Response, maximum = 32 * 1024): Promise<unknown> {
  if (response.body === null) throw new Error("SBX-051 response lacked a body");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      if (next.value.byteLength > maximum - total) {
        await reader.cancel().catch(() => undefined);
        throw new Error("SBX-051 response exceeded its byte limit");
      }
      const copy = new Uint8Array(next.value);
      chunks.push(copy);
      total += copy.byteLength;
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
      chunk.fill(0);
    }
    try {
      return JSON.parse(Buffer.from(bytes).toString("utf8"));
    } finally {
      bytes.fill(0);
    }
  } finally {
    reader.releaseLock();
    for (const chunk of chunks) chunk.fill(0);
  }
}

async function issueInteractiveCredential(
  config: Sbx051Config,
  gate: Sbx051RequestGate,
  role: Sbx051Role,
  sessionId: string,
  purpose: Sbx051CredentialIssuance["purpose"],
): Promise<TransientCredential> {
  const url = new URL(`/api/v2/sandboxes/sessions/${encodeURIComponent(sessionId)}/interactive`,
    "https://vercel.com");
  url.searchParams.set("teamId", config.teamId);
  const response = await gate.fetch(url, {
    method: "POST",
    headers: {
      authorization: `Bearer ${config.token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({}),
    redirect: "error",
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  });
  if (response.status !== 200 || response.redirected ||
      !response.headers.get("content-type")?.toLowerCase().includes("application/json")) {
    await response.body?.cancel().catch(() => undefined);
    throw new Error("SBX-051 interactive credential issuance was not an exact JSON 200");
  }
  const parsed = object(await boundedJson(response));
  if (parsed === undefined || !exactKeys(parsed, ["url", "token"]) ||
      typeof parsed.url !== "string" || typeof parsed.token !== "string") {
    throw new Error("SBX-051 interactive credential response shape was not exact");
  }
  const canonicalWssUrl = exactSbx051BaseWebSocketUrl(parsed.url);
  const tokenStructurallyValid = parsed.token.length >= 16 && parsed.token.length <= 8_192 &&
    !/[\s\0]/u.test(parsed.token);
  if (!canonicalWssUrl || !tokenStructurallyValid) {
    throw new Error("SBX-051 interactive credential fields were not canonical");
  }
  return {
    role,
    baseUrl: parsed.url,
    token: parsed.token,
    evidence: {
      purpose,
      sourceRole: role,
      exactSourceSession: true,
      method: "POST",
      endpointFamily: "/v2/sandboxes/sessions/:sessionId/interactive",
      requestCount: 1,
      retryCount: 0,
      statusCode: 200,
      exactResponseShape: true,
      canonicalWssUrl,
      tokenStructurallyValid,
      responseBodyRetained: false,
      responseHeadersRetained: false,
      rawUrlRetained: false,
      queryBearingUrlRetained: false,
      rawTokenRetained: false,
      rawTokenDigestRetained: false,
    },
  };
}

async function interactiveAttempt(
  gate: Sbx051RequestGate,
  input: Parameters<typeof runSbx051InteractiveAttempt>[0],
  tokenUseCounts: Map<string, number>,
): Promise<Sbx051InteractiveAttempt> {
  if (input.token !== undefined) {
    tokenUseCounts.set(input.token, (tokenUseCounts.get(input.token) ?? 0) + 1);
  }
  const audit = await gate.reserveWebSocket(input.purpose);
  try {
    return await runSbx051InteractiveAttempt({ ...input, timeoutMs: WEBSOCKET_TIMEOUT_MS });
  } finally {
    gate.completeWebSocket(audit);
  }
}

function isNotFound(error: unknown): boolean {
  return error instanceof APIError && (error.response.status === 404 || error.response.status === 410);
}

function safeFailure(error: unknown): Sbx051CleanupResource["errors"][number] {
  if (error instanceof APIError) {
    const root = object(error.json);
    const nested = object(root?.error);
    const code = typeof nested?.code === "string" && nested.code.length <= 128
      ? nested.code
      : undefined;
    return { kind: "api", status: error.response.status, ...(code === undefined ? {} : { code }) };
  }
  return { kind: "other", message: "sanitized local controller failure" };
}

async function exactList(
  config: Sbx051Config,
  gate: Sbx051RequestGate,
  plan: Sbx051JournalResource,
) {
  const page = await Sandbox.list({
    ...credentials(config, gate),
    namePrefix: plan.name,
    limit: 10,
    sortBy: "name",
    sortOrder: "asc",
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  });
  if (page.pagination.next !== null) throw new Error("SBX-051 exact cleanup list required pagination");
  return page.sandboxes.filter((entry) => entry.name === plan.name);
}

async function exactNamedGet(
  config: Sbx051Config,
  gate: Sbx051RequestGate,
  plan: Sbx051JournalResource,
): Promise<Sandbox | undefined> {
  try {
    return await Sandbox.get(getParams(config, gate, plan));
  } catch (error) {
    if (isNotFound(error)) return undefined;
    throw error;
  }
}

function validateCleanupHandle(
  gate: Sbx051RequestGate,
  plan: Sbx051JournalResource,
  handle: Sandbox,
): string {
  const sessionId = handle.currentSession().sessionId;
  gate.registerSession(plan.role, sessionId);
  if (handle.name !== plan.name || !exactTags(handle.tags, plan.tags) || handle.persistent ||
      (plan.sessionId !== undefined && sessionId !== plan.sessionId)) {
    throw new Error("SBX-051 refused cleanup without exact handle provenance");
  }
  return sessionId;
}

async function stopAndDeleteCleanupHandle(
  handle: Sandbox,
  result: Sbx051CleanupResource,
): Promise<void> {
  result.exactProvenance = true;
  result.stopAttempted = true;
  try {
    await handle.stop({ signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
    result.stopped = true;
  } catch (error) {
    if (isNotFound(error)) result.stopped = true;
    else throw error;
  }
  result.deleteAttempted = true;
  try {
    await handle.delete({ signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
    result.deleted = true;
  } catch (error) {
    if (isNotFound(error)) result.deleted = true;
    else throw error;
  }
}

async function exactNamedAndPrefixAbsent(
  config: Sbx051Config,
  gate: Sbx051RequestGate,
  plan: Sbx051JournalResource,
): Promise<boolean> {
  const named = await exactNamedGet(config, gate, plan);
  if (named !== undefined) return false;
  return (await exactList(config, gate, plan)).length === 0;
}

export async function cleanupSbx051Resource(
  config: Sbx051Config,
  gate: Sbx051RequestGate,
  journal: Sbx051Journal,
  plan: Sbx051JournalResource,
  wait: (milliseconds: number) => Promise<unknown> = delay,
): Promise<Sbx051CleanupResource> {
  const result: Sbx051CleanupResource = {
    role: plan.role,
    attempted: plan.createAttempted,
    sessionIdKnownAtCleanup: plan.sessionId !== undefined,
    exactProvenance: !plan.createAttempted,
    stopAttempted: false,
    stopped: !plan.createAttempted,
    deleteAttempted: false,
    deleted: !plan.createAttempted,
    firstAbsence: !plan.createAttempted,
    secondAbsence: !plan.createAttempted,
    namedAbsenceChecks: 0,
    absenceDelayMs: 0,
    errors: [],
  };
  if (!plan.createAttempted) return result;
  try {
    const matches = await exactList(config, gate, plan);
    if (matches.length > 1) throw new Error("SBX-051 found duplicate exact cleanup names");
    let handle: Sandbox | undefined;
    if (matches.length === 1) {
      const match = matches[0]!;
      if (!exactTags(match.tags, plan.tags) || match.persistent ||
          (plan.sessionId !== undefined && match.currentSessionId !== plan.sessionId)) {
        throw new Error("SBX-051 refused cleanup without exact list provenance");
      }
      handle = await exactNamedGet(config, gate, plan);
      if (handle === undefined) throw new Error("SBX-051 exact cleanup handle vanished after list");
    } else {
      if (plan.sessionId === undefined) {
        await wait(SBX051_UNKNOWN_SESSION_ABSENCE_DELAY_MS);
      }
      handle = await exactNamedGet(config, gate, plan);
    }
    if (handle !== undefined) {
      const validatedSessionId = validateCleanupHandle(gate, plan, handle);
      if (plan.sessionId === undefined) {
        plan.sessionId = validatedSessionId;
        await writeSbx051Journal(journal);
        result.sessionIdKnownAtCleanup = true;
      }
      await stopAndDeleteCleanupHandle(handle, result);
    } else if (plan.sessionId !== undefined) {
      result.exactProvenance = true;
      result.stopped = true;
      result.deleted = true;
    }
    const absenceDelay = plan.sessionId === undefined
      ? SBX051_UNKNOWN_SESSION_ABSENCE_DELAY_MS
      : SBX051_KNOWN_SESSION_ABSENCE_DELAY_MS;
    result.absenceDelayMs = absenceDelay;
    result.firstAbsence = await exactNamedAndPrefixAbsent(config, gate, plan);
    await wait(absenceDelay);
    result.secondAbsence = await exactNamedAndPrefixAbsent(config, gate, plan);
    if (!result.firstAbsence || !result.secondAbsence) {
      throw new Error("SBX-051 could not confirm exact sandbox absence twice");
    }
    result.namedAbsenceChecks = 2;
    if (plan.sessionId === undefined) {
      throw new Error(
        "SBX-051 cannot resolve a response-lost create without a captured or validated session",
      );
    }
  } catch (error) {
    result.errors.push(safeFailure(error));
  }
  return result;
}

async function cleanupAll(
  config: Sbx051Config,
  gate: Sbx051RequestGate,
  journal: Sbx051Journal,
): Promise<CleanupEvidence> {
  const resources: Sbx051CleanupResource[] = [];
  for (const role of ["B", "A"] as const) {
    resources.push(await cleanupSbx051Resource(config, gate, journal, resource(journal, role)));
  }
  return {
    passed: resources.every((entry) => entry.errors.length === 0 && entry.exactProvenance &&
      entry.stopped && entry.deleted && entry.firstAbsence && entry.secondAbsence &&
      (!entry.attempted || (entry.namedAbsenceChecks === 2 && entry.absenceDelayMs >= 750))),
    journalRemoved: false,
    lockReleased: false,
    resources,
  };
}

async function installedWireAudit(): Promise<boolean> {
  const [sdkPackage, cliPackage, wsPackage, apiSource, cliSource, createSource] = await Promise.all([
    readFile(new URL("../../node_modules/@vercel/sandbox/package.json", import.meta.url), "utf8"),
    readFile(new URL("../../targets/vercel-sandbox/packages/sandbox/package.json", import.meta.url), "utf8"),
    readFile(new URL("../../infra/h3-action-worker/node_modules/ws/package.json", import.meta.url), "utf8"),
    readFile(new URL("../../node_modules/@vercel/sandbox/dist/api-client/api-client.js", import.meta.url), "utf8"),
    readFile(new URL(
      "../../targets/vercel-sandbox/packages/sandbox/src/interactive-shell/interactive-shell.ts",
      import.meta.url,
    ), "utf8"),
    readFile(new URL("../../targets/vercel-sandbox/packages/sandbox/src/commands/create.ts", import.meta.url), "utf8"),
  ]);
  const sdk = JSON.parse(sdkPackage) as { version?: unknown };
  const cli = JSON.parse(cliPackage) as {
    version?: unknown;
    dependencies?: Record<string, string>;
  };
  const ws = JSON.parse(wsPackage) as { version?: unknown };
  const passed = sdk.version === SDK_VERSION && cli.version === CLI_VERSION &&
    cli.dependencies?.ws === "^8.21.0" &&
    ws.version === SBX051_WS_VERSION &&
    apiSource.includes("`/v2/sandboxes/sessions/${params.sessionId}/interactive`") &&
    apiSource.includes("body: JSON.stringify({})") &&
    cliSource.includes('import { WebSocket } from "ws";') &&
    cliSource.includes("const client = new WebSocket(`${url}?token=${encodeURIComponent(token)}`);") &&
    cliSource.includes('type: "start"') && cliSource.includes("if (isBinary)") &&
    createSource.match(/__interactive:\s*true/gu)?.length === 2;
  if (!passed) throw new Error("SBX-051 installed interactive wire audit drifted");
  return true;
}

async function markCreateAttempt(journal: Sbx051Journal, plan: Sbx051JournalResource): Promise<void> {
  if (plan.createAttempted) throw new Error(`SBX-051 role ${plan.role} create may be attempted once`);
  plan.createAttempted = true;
  await writeSbx051Journal(journal);
}

function distinctStrings(values: readonly string[]): boolean {
  return new Set(values).size === values.length;
}

async function timedStep<T>(
  steps: Sbx051ChronologyStep[],
  stage: Sbx051ChronologyStep["stage"],
  action: () => Promise<T>,
): Promise<T> {
  const startedAt = new Date().toISOString();
  const result = await action();
  const completedAt = new Date().toISOString();
  steps.push({ stage, startedAt, completedAt });
  return result;
}

const BINDING_OPERATION_ORDER: ExternalOperation[] = [
  "interactive-A",
  "interactive-B",
  "websocket-missing-token-negative",
  "websocket-random-token-negative",
  "websocket-a-owner-control",
  "websocket-b-owner-control",
  "interactive-A",
  "interactive-B",
  "websocket-a-token-b-attack",
];

function exactBindingOperationOrder(
  records: readonly Sbx051ExternalAuditRecord[],
  targetValidation: boolean,
): boolean {
  const operations = records.map((record) => record.operation).filter((operation) =>
    operation.startsWith("interactive-") || operation.startsWith("websocket-"));
  const expected = [
    ...BINDING_OPERATION_ORDER,
    ...(targetValidation ? ["websocket-b-target-validation" as const] : []),
  ];
  return operations.length === expected.length &&
    operations.every((operation, index) => operation === expected[index]);
}

function exactAttackHttpRejectionForValidation(attempt: Sbx051InteractiveAttempt): boolean {
  return attempt.purpose === "a-token-b-attack" && attempt.urlRole === "B" &&
    attempt.tokenSource === "A" && attempt.urlCredentialPurpose === "b-attack-target" &&
    attempt.tokenCredentialPurpose === "a-attack" && attempt.requestCount === 1 &&
    attempt.retryCount === 0 && attempt.webSocketClient === `ws@${SBX051_WS_VERSION}` &&
    attempt.handshakeResponseBodyRetained === false &&
    attempt.handshakeResponseHeadersRetained === false &&
    !attempt.opened && !attempt.openedExactIssuedUrl && attempt.startMessageExpected &&
    attempt.unexpectedResponseObserved &&
    (attempt.handshakeStatusCode === 401 || attempt.handshakeStatusCode === 403) &&
    attempt.startMessagesSent === 0 && attempt.binaryFrames === 0 &&
    attempt.textControlFrames === 0 && attempt.outputBytes === 0 && attempt.exitCode === null &&
    attempt.terminal === "http-response-before-open";
}

function roleUrlsDistinct(credentialsList: readonly TransientCredential[]): boolean {
  const a = credentialsList.filter((entry) => entry.role === "A").map((entry) => entry.baseUrl);
  const b = credentialsList.filter((entry) => entry.role === "B").map((entry) => entry.baseUrl);
  return a.length > 0 && b.length > 0 && a.every((left) => b.every((right) => left !== right));
}

export async function finalizeSbx051LocalCleanup(
  cleanup: CleanupEvidence,
  lock: Pick<Sbx051HeldLock, "release" | "isReleased">,
  removeJournal: () => Promise<void>,
): Promise<void> {
  if (!cleanup.passed) return;
  try {
    await lock.release();
    cleanup.lockReleased = lock.isReleased();
    if (!cleanup.lockReleased) {
      throw new Error("SBX-051 lock release did not prove close and unlink");
    }
    await removeJournal();
    cleanup.journalRemoved = true;
  } catch {
    cleanup.passed = false;
  }
  cleanup.passed &&= cleanup.journalRemoved && cleanup.lockReleased;
}

async function finalizeCleanup(
  cleanup: CleanupEvidence,
  journal: Sbx051Journal,
  lock: Sbx051HeldLock,
): Promise<void> {
  await finalizeSbx051LocalCleanup(
    cleanup,
    lock,
    () => removeSbx051Journal(journal.runId),
  );
}

async function runRecovery(
  config: Sbx051Config,
  journal: Sbx051Journal,
  lock: Sbx051HeldLock,
  gate: Sbx051RequestGate,
): Promise<void> {
  const recoveryAttemptId = randomUUID();
  const recoveryArtifactPath = sbx051RecoveryArtifactPath(journal.runId, recoveryAttemptId);
  const identity = await verifyEligibleAliasToken({
    token: config.token,
    expectedEmail: config.expectedAlias,
    expectedTeamId: config.teamId,
    expectedProjectId: config.projectId,
    manualEmailConfirmation: config.manualAliasConfirmation,
    fetchImpl: gate.fetch,
  });
  const cleanup = await cleanupAll(config, gate, journal);
  await finalizeCleanup(cleanup, journal, lock);
  const artifact = {
    schemaVersion: 1,
    testId: SBX051_TEST_ID,
    runId: journal.runId,
    recoveryAttemptId,
    mode: "cleanup-only",
    scopeAndAliasPassed: identity.email === SBX051_ALIAS && identity.teamId === SBX051_TEAM &&
      identity.projectId === SBX051_PROJECT,
    interactiveCredentialsIssued: 0,
    websocketConnections: 0,
    cleanup,
    requestAudit: gate.summary(),
    retention: {
      rawMarkers: false,
      rawMarkerDigests: false,
      rawInteractiveTokens: false,
      rawInteractiveTokenDigests: false,
      queryBearingUrls: false,
      commandOutput: false,
      websocketErrors: false,
    },
  };
  assertSbx051EvidenceHasNoRawCapabilities(artifact, [config.token]);
  await writeSbx051PrivateJsonNoClobber(recoveryArtifactPath, artifact);
  console.log(JSON.stringify({
    testId: SBX051_TEST_ID,
    runId: journal.runId,
    mode: "cleanup-only",
    cleanupPassed: cleanup.passed,
    artifactPath: recoveryArtifactPath,
  }, null, 2));
  process.exitCode = cleanup.passed ? 0 : 1;
}

function incompleteAssessment(summary: string): Sbx051Assessment {
  return {
    verdict: "indeterminate",
    candidate: false,
    controlsPassed: false,
    maximumDemonstratedImpact: "none",
    reportability: "none",
    summary,
  };
}

export async function main(): Promise<void> {
  const config = loadSbx051Config();
  let journal = config.recoveryRunId === undefined
    ? createSbx051Journal()
    : await readSbx051Journal(config.recoveryRunId);
  const lock = await acquireSbx051Lock(journal.runId, config.recoveryRunId !== undefined);
  const gate = createSbx051RequestGate(fetch, config.token, journal.resources);
  if (config.recoveryRunId !== undefined) {
    await runRecovery(config, journal, lock, gate);
    return;
  }
  try {
    await writeSbx051Journal(journal);
  } catch (error) {
    await lock.release();
    throw error;
  }

  const a: ResourceRuntime = { plan: resource(journal, "A") };
  const b: ResourceRuntime = { plan: resource(journal, "B") };
  let identity: EligibleAliasIdentityProof | undefined;
  let wireAuditPassed = false;
  let preReadbacks: [Sbx051SandboxReadback, Sbx051SandboxReadback] | undefined;
  let postReadbacks: [Sbx051SandboxReadback, Sbx051SandboxReadback] | undefined;
  const credentialsList: TransientCredential[] = [];
  const attempts: Sbx051InteractiveAttempt[] = [];
  const tokenUseCounts = new Map<string, number>();
  const chronologySteps: Sbx051ChronologyStep[] = [];
  let preReadbacksCompletedAt: string | undefined;
  let postReadbacksStartedAt: string | undefined;
  let postReadbacksCompletedAt: string | undefined;
  let cleanupStartedAt: string | undefined;
  let cleanupCompletedAt: string | undefined;
  const forbidden: string[] = [config.token];
  let failureStage: string | undefined;
  let cleanup: CleanupEvidence;

  try {
    wireAuditPassed = await installedWireAudit();
    identity = await verifyEligibleAliasToken({
      token: config.token,
      expectedEmail: config.expectedAlias,
      expectedTeamId: config.teamId,
      expectedProjectId: config.projectId,
      manualEmailConfirmation: config.manualAliasConfirmation,
      fetchImpl: gate.fetch,
    });

    for (const runtime of [a, b]) {
      await markCreateAttempt(journal, runtime.plan);
      runtime.sandbox = await Sandbox.create(createParams(config, gate, runtime.plan));
      if (!exactCreatedSandbox(runtime.sandbox, runtime.plan)) {
        throw new Error("SBX-051 fresh sandbox response failed exact interactive provenance");
      }
      const sessionId = runtime.sandbox.currentSession().sessionId;
      gate.registerSession(runtime.plan.role, sessionId);
      runtime.plan.sessionId = sessionId;
      await writeSbx051Journal(journal);
      runtime.marker = Buffer.from(randomBytes(32).toString("base64url"), "utf8");
      forbidden.push(runtime.marker.toString("utf8"));
      await runtime.sandbox.currentSession().writeFiles(
        [{ path: runtime.plan.markerPath, content: runtime.marker, mode: 0o600 }],
        { signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) },
      );
    }
    if (!a.sandbox || !b.sandbox || !a.marker || !b.marker ||
        a.sandbox.currentSession().sessionId === b.sandbox.currentSession().sessionId ||
        a.marker.equals(b.marker)) {
      throw new Error("SBX-051 fixtures were not distinct");
    }

    preReadbacks = [
      await readbackSandbox(config, gate, a.sandbox, a.plan, b.plan, a.marker),
      await readbackSandbox(config, gate, b.sandbox, b.plan, a.plan, b.marker),
    ];
    if (!exactSbx051ReadbackPair(preReadbacks)) {
      throw new Error("SBX-051 pre-attack readback pair failed exact provenance");
    }
    preReadbacksCompletedAt = new Date().toISOString();

    const aControl = await timedStep(chronologySteps, "issue-a-owner-control", () =>
      issueInteractiveCredential(config, gate, "A", a.plan.sessionId!, "a-owner-control"));
    const bControl = await timedStep(chronologySteps, "issue-b-owner-control", () =>
      issueInteractiveCredential(config, gate, "B", b.plan.sessionId!, "b-owner-control"));
    credentialsList.push(aControl, bControl);
    forbidden.push(aControl.token, bControl.token);

    attempts.push(await timedStep(chronologySteps, "missing-token-negative", () =>
      interactiveAttempt(gate, {
      purpose: "missing-token-negative",
      urlRole: "B",
      tokenSource: "none",
      urlCredentialPurpose: "b-owner-control",
      tokenCredentialPurpose: "none",
      baseUrl: bControl.baseUrl,
      }, tokenUseCounts)));
    let randomInvalidToken = `invalid_${randomBytes(32).toString("base64url")}`;
    while (randomInvalidToken === aControl.token || randomInvalidToken === bControl.token) {
      randomInvalidToken = `invalid_${randomBytes(32).toString("base64url")}`;
    }
    forbidden.push(randomInvalidToken);
    attempts.push(await timedStep(chronologySteps, "random-token-negative", () =>
      interactiveAttempt(gate, {
      purpose: "random-token-negative",
      urlRole: "B",
      tokenSource: "random",
      urlCredentialPurpose: "b-owner-control",
      tokenCredentialPurpose: "random",
      baseUrl: bControl.baseUrl,
      token: randomInvalidToken,
      }, tokenUseCounts)));
    attempts.push(await timedStep(chronologySteps, "a-owner-control", () =>
      interactiveAttempt(gate, {
      purpose: "a-owner-control",
      urlRole: "A",
      tokenSource: "A",
      urlCredentialPurpose: "a-owner-control",
      tokenCredentialPurpose: "a-owner-control",
      baseUrl: aControl.baseUrl,
      token: aControl.token,
      markerPath: a.plan.markerPath,
      expectedMarker: a.marker!,
      unexpectedMarker: b.marker!,
      }, tokenUseCounts)));
    attempts.push(await timedStep(chronologySteps, "b-owner-control", () =>
      interactiveAttempt(gate, {
      purpose: "b-owner-control",
      urlRole: "B",
      tokenSource: "B",
      urlCredentialPurpose: "b-owner-control",
      tokenCredentialPurpose: "b-owner-control",
      baseUrl: bControl.baseUrl,
      token: bControl.token,
      markerPath: b.plan.markerPath,
      expectedMarker: b.marker!,
      unexpectedMarker: a.marker!,
      }, tokenUseCounts)));

    const aAttack = await timedStep(chronologySteps, "issue-a-attack", () =>
      issueInteractiveCredential(config, gate, "A", a.plan.sessionId!, "a-attack"));
    const bTarget = await timedStep(chronologySteps, "issue-b-attack-target", () =>
      issueInteractiveCredential(config, gate, "B", b.plan.sessionId!, "b-attack-target"));
    credentialsList.push(aAttack, bTarget);
    forbidden.push(aAttack.token, bTarget.token);
    if (!distinctStrings(credentialsList.map((entry) => entry.token)) ||
        !roleUrlsDistinct(credentialsList)) {
      throw new Error("SBX-051 returned non-distinct credentials or inseparable A/B URL bindings");
    }
    const attackAttempt = await timedStep(chronologySteps, "a-token-b-attack", () =>
      interactiveAttempt(gate, {
      purpose: "a-token-b-attack",
      urlRole: "B",
      tokenSource: "A",
      urlCredentialPurpose: "b-attack-target",
      tokenCredentialPurpose: "a-attack",
      baseUrl: bTarget.baseUrl,
      token: aAttack.token,
      markerPath: b.plan.markerPath,
      expectedMarker: b.marker!,
      unexpectedMarker: a.marker!,
      }, tokenUseCounts));
    attempts.push(attackAttempt);
    if (exactAttackHttpRejectionForValidation(attackAttempt)) {
      attempts.push(await timedStep(chronologySteps, "b-target-validation", () =>
        interactiveAttempt(gate, {
        purpose: "b-target-validation",
        urlRole: "B",
        tokenSource: "B",
        urlCredentialPurpose: "b-attack-target",
        tokenCredentialPurpose: "b-attack-target",
        baseUrl: bTarget.baseUrl,
        token: bTarget.token,
        markerPath: b.plan.markerPath,
        expectedMarker: b.marker!,
        unexpectedMarker: a.marker!,
        }, tokenUseCounts)));
    }

    postReadbacksStartedAt = new Date().toISOString();
    postReadbacks = [
      await readbackSandbox(config, gate, a.sandbox, a.plan, b.plan, a.marker),
      await readbackSandbox(config, gate, b.sandbox, b.plan, a.plan, b.marker),
    ];
    postReadbacksCompletedAt = new Date().toISOString();
  } catch {
    failureStage = "sanitized bounded experiment failure";
  } finally {
    cleanupStartedAt = new Date().toISOString();
    cleanup = await cleanupAll(config, gate, journal);
    await finalizeCleanup(cleanup, journal, lock);
    cleanupCompletedAt = new Date().toISOString();
  }

  const scopeAndAliasPassed = identity?.email === SBX051_ALIAS && identity.teamId === SBX051_TEAM &&
    identity.projectId === SBX051_PROJECT;
  const requestAudit = gate.summary();
  const bindingOperations = requestAudit.records.map((record) => record.operation).filter((operation) =>
    operation.startsWith("interactive-") || operation.startsWith("websocket-"));
  const aAttackCredential = credentialsList.find((entry) => entry.evidence.purpose === "a-attack");
  const bTargetCredential = credentialsList.find((entry) => entry.evidence.purpose === "b-attack-target");
  const targetValidation = attempts.length === 6;
  const aAttackTokenUses = aAttackCredential === undefined
    ? -1
    : tokenUseCounts.get(aAttackCredential.token) ?? 0;
  const bTargetTokenUses = bTargetCredential === undefined
    ? -1
    : tokenUseCounts.get(bTargetCredential.token) ?? 0;
  let assessment: Sbx051Assessment;
  if (preReadbacks !== undefined && postReadbacks !== undefined &&
      credentialsList.length === 4 && (attempts.length === 5 || targetValidation) &&
      preReadbacksCompletedAt !== undefined && postReadbacksStartedAt !== undefined &&
      postReadbacksCompletedAt !== undefined && cleanupStartedAt !== undefined &&
      cleanupCompletedAt !== undefined && aAttackCredential !== undefined &&
      bTargetCredential !== undefined && aAttackTokenUses === 1 &&
      (bTargetTokenUses === 0 || bTargetTokenUses === 1)) {
    const chronology: Sbx051Chronology = {
      preReadbacksCompletedAt,
      steps: chronologySteps,
      postReadbacksStartedAt,
      postReadbacksCompletedAt,
      cleanupStartedAt,
      cleanupCompletedAt,
    };
    const input: Sbx051AssessmentInput = {
      schemaVersion: 1,
      testId: SBX051_TEST_ID,
      scopeAndAliasPassed,
      installedWireAuditPassed: wireAuditPassed,
      distinctSandboxNames: a.plan.name !== b.plan.name,
      distinctSessionIds: a.plan.sessionId !== undefined && b.plan.sessionId !== undefined &&
        a.plan.sessionId !== b.plan.sessionId,
      distinctMarkerPaths: a.plan.markerPath !== b.plan.markerPath,
      distinctMarkerValues: a.marker !== undefined && b.marker !== undefined && !a.marker.equals(b.marker),
      distinctReturnedUrlBindings: roleUrlsDistinct(credentialsList),
      allIssuedTokensDistinct: distinctStrings(credentialsList.map((entry) => entry.token)),
      attackTokenIssuedFreshAndUsedOnce: exactBindingOperationOrder(
        requestAudit.records,
        targetValidation,
      ) && aAttackTokenUses === 1,
      bTargetTokenUseCount: bTargetTokenUses,
      chronology,
      preAttackReadbacks: preReadbacks,
      postAttackReadbacks: postReadbacks,
      issuances: credentialsList.map((entry) => entry.evidence),
      attempts,
      requestAudit: {
        allAllowlisted: requestAudit.allAllowlisted,
        contiguous: requestAudit.contiguous,
        completed: requestAudit.completed,
        withinRateLimit: requestAudit.withinRateLimit,
        rawInteractiveCredentialRequests: requestAudit.rawInteractiveCredentialRequests,
        websocketConnections: requestAudit.websocketConnections,
        unexpectedRequests: requestAudit.unexpectedRequests,
        bindingOperations,
      },
      cleanup: { passed: cleanup.passed, resources: cleanup.resources },
      rawMarkersRetained: false,
      rawMarkerDigestsRetained: false,
      rawInteractiveTokensRetained: false,
      rawInteractiveTokenDigestsRetained: false,
      queryBearingUrlsRetained: false,
      commandOutputRetained: false,
      websocketErrorsRetained: false,
    };
    assessment = assessSbx051(input);
  } else {
    assessment = incompleteAssessment(
      failureStage ?? "The bounded experiment did not produce one complete exact evidence matrix.",
    );
  }

  const artifact = {
    schemaVersion: 1,
    testId: SBX051_TEST_ID,
    runId: journal.runId,
    startedAt: journal.startedAt,
    completedAt: new Date().toISOString(),
    runtime: {
      sandboxSdk: `@vercel/sandbox@${SDK_VERSION}`,
      auditedCliSource: `@vercel/sandbox-cli@${CLI_VERSION}`,
      controllerNode: process.version,
      interactiveTransport: `ws@${SBX051_WS_VERSION}`,
    },
    account: {
      alias: SBX051_ALIAS,
      teamId: SBX051_TEAM,
      projectId: SBX051_PROJECT,
      identityMethod: identity?.method ?? "not-verified",
    },
    fixture: {
      resources: journal.resources.map((entry) => ({
        role: entry.role,
        name: entry.name,
        markerPath: entry.markerPath,
        sessionId: entry.sessionId,
        markerLength: entry.role === "A" ? a.marker?.length : b.marker?.length,
        markerRequestedMode: "0600",
      })),
      preAttackReadbacks: preReadbacks,
      postAttackReadbacks: postReadbacks,
    },
    credentialIssuances: credentialsList.map((entry) => entry.evidence),
    attempts,
    chronology: {
      preReadbacksCompletedAt,
      steps: chronologySteps,
      postReadbacksStartedAt,
      postReadbacksCompletedAt,
      cleanupStartedAt,
      cleanupCompletedAt,
    },
    requestAudit,
    assessment,
    cleanup,
    failure: failureStage,
    retention: {
      rawMarkers: false,
      rawMarkerDigests: false,
      rawInteractiveTokens: false,
      rawInteractiveTokenDigests: false,
      queryBearingUrls: false,
      commandOutput: false,
      websocketErrors: false,
    },
    evidencePath: sbx051ArtifactPath(journal.runId),
  };
  assertSbx051EvidenceHasNoRawCapabilities(artifact, forbidden);
  await writeSbx051PrivateJson(sbx051ArtifactPath(journal.runId), artifact);
  a.marker?.fill(0);
  b.marker?.fill(0);
  console.log(JSON.stringify({
    schemaVersion: 1,
    testId: SBX051_TEST_ID,
    runId: journal.runId,
    assessment,
    cleanup,
    evidencePath: sbx051ArtifactPath(journal.runId),
  }, null, 2));
  process.exitCode = assessment.verdict === "candidate" ? 2 : assessment.verdict === "pass" ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error: unknown) => {
    console.error(JSON.stringify({
      testId: SBX051_TEST_ID,
      outcome: "error",
      error: error instanceof Error ? error.name : "unknown",
    }));
    process.exitCode = 1;
  });
}
