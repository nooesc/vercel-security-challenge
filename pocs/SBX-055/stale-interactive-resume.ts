import "dotenv/config";

import { randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { APIError, Sandbox, Snapshot } from "@vercel/sandbox";
import { verifyEligibleAliasToken, type EligibleAliasIdentityProof } from "../eligible-alias-identity.js";
import {
  SBX055_WS_VERSION,
  exactSbx055BaseWebSocketUrl,
  runSbx055InteractiveAttempt,
  type Sbx055AttemptPurpose,
  type Sbx055InteractiveAttempt,
  type Sbx055Role,
  type Sbx055RunAttemptInput,
} from "./protocol.js";
import {
  SBX055_ALIAS,
  SBX055_PROJECT,
  SBX055_SANDBOX_TIMEOUT_MS,
  SBX055_SNAPSHOT_EXPIRATION_MS,
  SBX055_TEAM,
  SBX055_TEST_ID,
  acquireSbx055Lock,
  acquireSbx055RecoveryLock,
  createSbx055Journal,
  dispatchSbx055Recovery,
  loadSbx055Config,
  persistSbx055Journal,
  readSbx055Journal,
  releaseSbx055LockAndJournal,
  safeSbx055Error,
  sbx055ArtifactPath,
  sbx055RecoveryArtifactPath,
  writeSbx055PrivateArtifact,
  zeroExternalStateJournal,
  type Sbx055Config,
  type Sbx055HeldLock,
  type Sbx055RecoveryJournal,
  type Sbx055RecoveryDispatchOutcome,
} from "./safety.js";
import {
  assessSbx055,
  assertSbx055EvidenceHasNoRawCapabilities,
  type Sbx055Assessment,
  type Sbx055AssessmentInput,
  type Sbx055ChronologyStage,
  type Sbx055ChronologyStep,
  type Sbx055CleanupProof,
  type Sbx055CredentialIssuance,
  type Sbx055SandboxReadback,
  type Sbx055SnapshotCleanup,
} from "./verdict.js";

const SDK_VERSION = "3.0.0";
const CONTROL_TIMEOUT_MS = 30_000;
const WEBSOCKET_TIMEOUT_MS = 10_000;
const MINIMUM_REQUEST_INTERVAL_MS = 250;
const MAXIMUM_EXTERNAL_REQUESTS = 100;
const ABSENCE_DELAY_MS = 750;

type ExternalOperation =
  | "identity-user" | "identity-team" | "identity-project" | "create"
  | "get-no-resume" | "get-resume" | "list-sandbox" | "write-file" | "read-file"
  | "stat-file" | "issue-interactive" | "stop-session" | "delete-sandbox"
  | "list-snapshots" | "get-snapshot" | "delete-snapshot"
  | `websocket-${Sbx055AttemptPurpose}`;

export interface Sbx055ExternalAuditRecord {
  sequence: number;
  operation: ExternalOperation;
  method: string;
  startedAt: string;
  completedAt?: string;
  status?: number;
}

export interface Sbx055RequestGate {
  fetch: typeof fetch;
  registerSession(role: Sbx055Role, sessionId: string): void;
  registerSnapshot(snapshotId: string): void;
  reserveWebSocket(purpose: Sbx055AttemptPurpose): Promise<Sbx055ExternalAuditRecord>;
  completeWebSocket(record: Sbx055ExternalAuditRecord): void;
  summary(): {
    count: number;
    records: Sbx055ExternalAuditRecord[];
    allAllowlisted: boolean;
    contiguous: boolean;
    completed: boolean;
    withinRateLimit: boolean;
    minimumStartIntervalMs?: number;
    interactiveCredentialRequests: number;
    websocketConnections: number;
    unexpectedRequests: number;
  };
}

interface TransientCredential {
  role: Sbx055Role;
  baseUrl: string;
  token: string;
  evidence: Sbx055CredentialIssuance;
}

interface MarkerState {
  m1: Buffer;
  m2: Buffer;
  s1WrittenAfterCreate: boolean;
  s1Mode0600: boolean;
  s1LocalReadExactBeforeStop: boolean;
  s2AbsentBeforeStop: boolean;
  s1PersistedAfterResume: boolean;
  s1Mode0600AfterResume: boolean;
  s1LocalReadExactAfterResume: boolean;
  s2WrittenOnlyAfterResume: boolean;
  s2Mode0600: boolean;
  s2LocalReadExactAfterResume: boolean;
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
  return entries.length === Object.keys(expected).length && Object.entries(expected).every(([key, value]) =>
    url.searchParams.getAll(key).length === 1 && url.searchParams.get(key) === value);
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

export function createSbx055RequestGate(
  rawFetch: typeof fetch,
  token: string,
  journal: Sbx055RecoveryJournal,
  options: { now?: () => number; wait?: (milliseconds: number) => Promise<void> } = {},
): Sbx055RequestGate {
  const now = options.now ?? Date.now;
  const wait = options.wait ?? ((milliseconds: number) => delay(milliseconds));
  const sessions = new Map<string, Sbx055Role>();
  const snapshots = new Set<string>();
  const records: Sbx055ExternalAuditRecord[] = [];
  let unexpectedRequests = 0;
  let lastStart = Number.NEGATIVE_INFINITY;
  let queue = Promise.resolve();

  const reserve = async (operation: ExternalOperation, method: string): Promise<Sbx055ExternalAuditRecord> => {
    if (records.length >= MAXIMUM_EXTERNAL_REQUESTS) {
      throw new Error("SBX-055 exceeded its fixed external request budget");
    }
    let release!: () => void;
    const previous = queue;
    queue = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    try {
      const remaining = MINIMUM_REQUEST_INTERVAL_MS - (now() - lastStart);
      if (remaining > 0) await wait(remaining);
      lastStart = now();
      const record: Sbx055ExternalAuditRecord = {
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

  const classify = (input: string | URL | Request, init?: RequestInit): ExternalOperation => {
    const url = requestUrl(input);
    const method = requestMethod(input, init);
    const headers = requestHeaders(input, init);
    if (url.protocol !== "https:" || url.username || url.password || url.hash ||
        headers.get("authorization") !== `Bearer ${token}`) {
      throw new Error("SBX-055 request gate rejected URL or owner authorization");
    }
    if (url.origin === "https://api.vercel.com" && method === "GET") {
      if (url.pathname === "/v2/user" && exactQuery(url, {})) return "identity-user";
      if (url.pathname === `/v2/teams/${SBX055_TEAM}` && exactQuery(url, {})) return "identity-team";
      if (url.pathname === `/v9/projects/${SBX055_PROJECT}` &&
          exactQuery(url, { teamId: SBX055_TEAM })) return "identity-project";
      throw new Error("SBX-055 request gate rejected a nonexact identity request");
    }
    if (url.origin !== "https://vercel.com") {
      throw new Error("SBX-055 request gate rejected a foreign origin");
    }
    if (method === "POST" && url.pathname === "/api/v3/sandboxes" &&
        exactQuery(url, { teamId: SBX055_TEAM })) {
      const body = parseJsonBody(init);
      if (body === undefined || !exactKeys(body, ["projectId", "ports", "timeout", "resources",
        "name", "persistent", "networkPolicy", "tags", "snapshotExpiration", "__interactive"]) ||
        body.projectId !== SBX055_PROJECT || body.name !== journal.sandboxName ||
        body.persistent !== true || body.timeout !== SBX055_SANDBOX_TIMEOUT_MS ||
        body.snapshotExpiration !== SBX055_SNAPSHOT_EXPIRATION_MS || body.__interactive !== true ||
        !Array.isArray(body.ports) || body.ports.length !== 0 ||
        !exactKeys(object(body.resources) ?? {}, ["vcpus"]) || object(body.resources)?.vcpus !== 2 ||
        !exactKeys(object(body.networkPolicy) ?? {}, ["mode"]) ||
        object(body.networkPolicy)?.mode !== "deny-all" ||
        !exactTags(object(body.tags) as Record<string, string> | undefined, journal.tags)) {
        throw new Error("SBX-055 request gate rejected a nonexact persistent create");
      }
      return "create";
    }
    if (method === "GET" && url.pathname === "/api/v2/sandboxes" && exactQuery(url, {
      teamId: SBX055_TEAM, project: SBX055_PROJECT, limit: "10", sortBy: "name",
      sortOrder: "asc", namePrefix: journal.sandboxName,
    })) return "list-sandbox";
    const named = /^\/api\/v2\/sandboxes\/(?!sessions(?:\/|$)|snapshots(?:\/|$))([^/]+)$/u.exec(url.pathname);
    if (named?.[1] !== undefined && decodeURIComponent(named[1]) === journal.sandboxName) {
      if (method === "GET" && exactQuery(url, {
        teamId: SBX055_TEAM, projectId: SBX055_PROJECT, __interactive: "true", resume: "false",
      })) return "get-no-resume";
      if (method === "GET" && exactQuery(url, {
        teamId: SBX055_TEAM, projectId: SBX055_PROJECT, __interactive: "true", resume: "true",
      })) return "get-resume";
      if (method === "DELETE" && exactQuery(url, {
        teamId: SBX055_TEAM, projectId: SBX055_PROJECT,
      })) return "delete-sandbox";
      throw new Error("SBX-055 request gate rejected a nonexact named-sandbox request");
    }
    if (url.pathname === "/api/v2/sandboxes/snapshots" && method === "GET" && exactQuery(url, {
      teamId: SBX055_TEAM, project: SBX055_PROJECT, name: journal.sandboxName,
      limit: "10", sortOrder: "asc",
    })) return "list-snapshots";
    const snapshot = /^\/api\/v2\/sandboxes\/snapshots\/([^/]+)$/u.exec(url.pathname)?.[1];
    if (snapshot !== undefined && snapshots.has(decodeURIComponent(snapshot)) &&
        exactQuery(url, { teamId: SBX055_TEAM })) {
      if (method === "GET") return "get-snapshot";
      if (method === "DELETE") return "delete-snapshot";
    }
    const sessionMatch = /^\/api\/v2\/sandboxes\/sessions\/([^/]+)(?:\/(.*))?$/u.exec(url.pathname);
    const sessionId = sessionMatch?.[1] === undefined ? undefined : decodeURIComponent(sessionMatch[1]);
    const suffix = sessionMatch?.[2] ?? "";
    if (sessionId !== undefined && sessions.has(sessionId) && exactQuery(url, { teamId: SBX055_TEAM })) {
      if (method === "POST" && suffix === "fs/write" &&
          headers.get("content-type") === "application/gzip" && headers.get("x-cwd") === "/") {
        return "write-file";
      }
      if (method === "POST" && suffix === "fs/read") {
        const body = parseJsonBody(init);
        if (body === undefined || !exactKeys(body, ["path"]) ||
            (body.path !== journal.marker1Path && body.path !== journal.marker2Path)) {
          throw new Error("SBX-055 request gate rejected a nonexact marker read");
        }
        return "read-file";
      }
      if (method === "POST" && suffix === "cmd") {
        const body = parseJsonBody(init);
        if (body === undefined || body.command !== "stat" || !Array.isArray(body.args) ||
            body.args.length !== 3 || body.args[0] !== "-c" ||
            body.args[1] !== "%s|%f|%u|%g|%X|%Y|%Z|%W|%h|%i|%d|%B|%b" ||
            (body.args[2] !== journal.marker1Path && body.args[2] !== journal.marker2Path) ||
            body.wait !== true || body.logs !== true || body.sudo !== false ||
            !exactKeys(object(body.env) ?? {}, [])) {
          throw new Error("SBX-055 request gate rejected a nonexact marker stat");
        }
        return "stat-file";
      }
      if (method === "POST" && suffix === "interactive" && exactKeys(parseJsonBody(init) ?? {}, [])) {
        return "issue-interactive";
      }
      if (method === "POST" && suffix === "stop") return "stop-session";
    }
    throw new Error("SBX-055 request gate rejected a non-allowlisted Sandbox operation");
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
        throw new DOMException("SBX-055 stopped on a retryable response", "AbortError");
      }
      return response;
    } catch (error) {
      record.completedAt ??= new Date(now()).toISOString();
      if (error instanceof DOMException && error.name === "AbortError") throw error;
      throw new DOMException("SBX-055 single-attempt fetch failed without retry", "AbortError");
    }
  }) as typeof fetch;

  return {
    fetch: gatedFetch,
    registerSession(role, sessionId): void {
      if (!/^sbx_[A-Za-z0-9_-]{8,192}$/u.test(sessionId)) throw new Error("SBX-055 malformed session ID");
      const existing = sessions.get(sessionId);
      if (existing !== undefined && existing !== role) throw new Error("SBX-055 session role collision");
      for (const [other, otherRole] of sessions) {
        if (otherRole === role && other !== sessionId) throw new Error("SBX-055 session drift for one role");
      }
      sessions.set(sessionId, role);
    },
    registerSnapshot(snapshotId): void {
      if (!/^snap_[A-Za-z0-9_-]{8,192}$/u.test(snapshotId)) throw new Error("SBX-055 malformed snapshot ID");
      snapshots.add(snapshotId);
    },
    reserveWebSocket: (purpose) => reserve(`websocket-${purpose}`, "GET"),
    completeWebSocket(record): void {
      if (!record.operation.startsWith("websocket-") || record.completedAt !== undefined) {
        throw new Error("SBX-055 invalid WebSocket audit completion");
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
        withinRateLimit: minimum === undefined || minimum >= MINIMUM_REQUEST_INTERVAL_MS - 2,
        ...(minimum === undefined ? {} : { minimumStartIntervalMs: minimum }),
        interactiveCredentialRequests: records.filter((record) =>
          record.operation === "issue-interactive").length,
        websocketConnections: records.filter((record) => record.operation.startsWith("websocket-")).length,
        unexpectedRequests,
      };
    },
  };
}

function credentials(config: Sbx055Config, gate: Sbx055RequestGate) {
  return { token: config.token, teamId: config.teamId, projectId: config.projectId, fetch: gate.fetch };
}

function createParams(config: Sbx055Config, gate: Sbx055RequestGate, journal: Sbx055RecoveryJournal):
Parameters<typeof Sandbox.create>[0] {
  return {
    ...credentials(config, gate),
    name: journal.sandboxName,
    persistent: true,
    timeout: SBX055_SANDBOX_TIMEOUT_MS,
    snapshotExpiration: SBX055_SNAPSHOT_EXPIRATION_MS,
    resources: { vcpus: 2 },
    ports: [],
    networkPolicy: "deny-all",
    tags: journal.tags,
    __interactive: true,
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  };
}

function getParams(config: Sbx055Config, gate: Sbx055RequestGate, journal: Sbx055RecoveryJournal,
  resume: boolean): Parameters<typeof Sandbox.get>[0] {
  return {
    ...credentials(config, gate),
    name: journal.sandboxName,
    resume,
    __interactive: true,
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  };
}

function exactInteractiveRoute(sandbox: Sandbox): boolean {
  const port = sandbox.interactivePort;
  if (port === undefined || !Number.isSafeInteger(port) || port < 1 || port > 65_535 ||
      sandbox.currentSession().interactivePort !== port || sandbox.routes.length !== 1) return false;
  const route = sandbox.routes[0]!;
  let url: URL;
  try { url = new URL(route.url); } catch { return false; }
  return route.port === port && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(route.subdomain) &&
    url.protocol === "https:" && !url.username && !url.password && !url.port && !url.search && !url.hash &&
    url.pathname === "/" && url.hostname === `${route.subdomain}.vercel.run` &&
    (route.url === url.origin || route.url === `${url.origin}/`);
}

function exactSandboxBase(sandbox: Sandbox, journal: Sbx055RecoveryJournal): boolean {
  return sandbox.name === journal.sandboxName && exactTags(sandbox.tags, journal.tags) && sandbox.persistent &&
    sandbox.timeout === SBX055_SANDBOX_TIMEOUT_MS && sandbox.status === "running" &&
    sandbox.networkPolicy === "deny-all" && sandbox.currentSession().networkPolicy === "deny-all" &&
    exactInteractiveRoute(sandbox);
}

async function exactSandboxList(config: Sbx055Config, gate: Sbx055RequestGate,
  journal: Sbx055RecoveryJournal) {
  const page = await Sandbox.list({ ...credentials(config, gate), namePrefix: journal.sandboxName,
    limit: 10, sortBy: "name", sortOrder: "asc", signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
  return { matches: page.sandboxes.filter((entry) => entry.name === journal.sandboxName),
    paginationComplete: page.pagination.next === null };
}

async function sandboxReadback(
  stage: Sbx055SandboxReadback["stage"], role: Sbx055Role, active: Sandbox,
  config: Sbx055Config, gate: Sbx055RequestGate, journal: Sbx055RecoveryJournal,
): Promise<Sbx055SandboxReadback> {
  const independent = await Sandbox.get(getParams(config, gate, journal, false));
  const expectedSessionId = active.currentSession().sessionId;
  gate.registerSession(role, independent.currentSession().sessionId);
  const listed = await exactSandboxList(config, gate, journal);
  const item = listed.matches.length === 1 ? listed.matches[0] : undefined;
  return {
    stage,
    role,
    name: active.name,
    independentName: independent.name,
    listedName: item?.name ?? "",
    activeSessionId: expectedSessionId,
    independentSessionId: independent.currentSession().sessionId,
    listedSessionId: item?.currentSessionId ?? "",
    activeStatus: active.status,
    independentStatus: independent.status,
    listedStatus: item?.status ?? "",
    activeTagsExact: exactTags(active.tags, journal.tags),
    independentTagsExact: exactTags(independent.tags, journal.tags),
    listedTagsExact: exactTags(item?.tags, journal.tags),
    activePersistent: active.persistent,
    independentPersistent: independent.persistent,
    listedPersistent: item?.persistent ?? false,
    activeTimeoutMs: active.timeout ?? -1,
    independentTimeoutMs: independent.timeout ?? -1,
    listedTimeoutMs: item?.timeout ?? -1,
    activeDenyAll: active.networkPolicy === "deny-all",
    activeSessionDenyAll: active.currentSession().networkPolicy === "deny-all",
    independentDenyAll: independent.networkPolicy === "deny-all",
    independentSessionDenyAll: independent.currentSession().networkPolicy === "deny-all",
    listedDenyAll: object(item?.networkPolicy)?.mode === "deny-all",
    activeInteractivePort: active.interactivePort ?? null,
    independentInteractivePort: independent.interactivePort ?? null,
    activeExactSingleInteractiveRoute: exactInteractiveRoute(active),
    independentRouteCount: independent.routes.length,
    sourceSnapshotId: active.sourceSnapshotId ?? null,
    independentSourceSnapshotId: independent.sourceSnapshotId ?? null,
    exactOneListedSandbox: listed.matches.length === 1,
    listPaginationComplete: listed.paginationComplete,
    independentResumeFalse: true,
    listQueryExactNamePrefix: true,
  };
}

async function readMarker(
  sandbox: Sandbox,
  path: string,
  expected: Buffer,
): Promise<{ exact: boolean; mode0600: boolean }> {
  const returned = await sandbox.currentSession().readFileToBuffer(
    { path }, { signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) },
  );
  let exact = false;
  try {
    exact = returned !== null && returned.length === expected.length && returned.equals(expected);
  } finally {
    returned?.fill(0);
  }
  const stat = await sandbox.fs.lstat(path, { signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
  return { exact, mode0600: stat.isFile() && stat.size === expected.length && (stat.mode & 0o777) === 0o600 };
}

async function markerAbsent(sandbox: Sandbox, path: string): Promise<boolean> {
  const returned = await sandbox.currentSession().readFileToBuffer(
    { path }, { signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) },
  );
  const absent = returned === null;
  returned?.fill(0);
  return absent;
}

async function boundedJson(response: Response, maximum = 32 * 1024): Promise<unknown> {
  if (response.body === null) throw new Error("SBX-055 response lacked a body");
  const reader = response.body.getReader();
  const retained = new Uint8Array(maximum + 1);
  let total = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      if (next.value.byteLength > maximum - total) {
        await reader.cancel().catch(() => undefined);
        throw new Error("SBX-055 response exceeded its byte limit");
      }
      retained.set(next.value, total);
      total += next.value.byteLength;
    }
    return JSON.parse(Buffer.from(retained.subarray(0, total)).toString("utf8"));
  } finally {
    retained.fill(0);
    reader.releaseLock();
  }
}

async function issueInteractiveCredential(
  config: Sbx055Config,
  gate: Sbx055RequestGate,
  role: Sbx055Role,
  sessionId: string,
  purpose: Sbx055CredentialIssuance["purpose"],
): Promise<TransientCredential> {
  const url = new URL(`/api/v2/sandboxes/sessions/${encodeURIComponent(sessionId)}/interactive`,
    "https://vercel.com");
  url.searchParams.set("teamId", config.teamId);
  const response = await gate.fetch(url, {
    method: "POST",
    headers: { authorization: `Bearer ${config.token}`, "content-type": "application/json" },
    body: JSON.stringify({}),
    redirect: "error",
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  });
  if (response.status !== 200 || response.redirected ||
      !response.headers.get("content-type")?.toLowerCase().includes("application/json")) {
    await response.body?.cancel().catch(() => undefined);
    throw new Error("SBX-055 interactive credential issuance was not an exact JSON 200");
  }
  const parsed = object(await boundedJson(response));
  if (parsed === undefined || !exactKeys(parsed, ["url", "token"]) ||
      typeof parsed.url !== "string" || typeof parsed.token !== "string") {
    throw new Error("SBX-055 interactive credential response shape was not exact");
  }
  const canonicalWssUrl = exactSbx055BaseWebSocketUrl(parsed.url);
  const tokenStructurallyValid = parsed.token.length >= 16 && parsed.token.length <= 8_192 &&
    !/[\s\0]/u.test(parsed.token);
  if (!canonicalWssUrl || !tokenStructurallyValid) {
    throw new Error("SBX-055 interactive credential fields were not canonical");
  }
  return {
    role,
    baseUrl: parsed.url,
    token: parsed.token,
    evidence: {
      purpose,
      sourceRole: role,
      sourceSessionId: sessionId,
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
      rawUrlDigestRetained: false,
      queryBearingUrlRetained: false,
      rawTokenRetained: false,
      rawTokenDigestRetained: false,
    },
  };
}

async function interactiveAttempt(
  gate: Sbx055RequestGate,
  input: Sbx055RunAttemptInput,
  tokenUses: Map<string, number>,
): Promise<Sbx055InteractiveAttempt> {
  if (input.token !== undefined) tokenUses.set(input.token, (tokenUses.get(input.token) ?? 0) + 1);
  const audit = await gate.reserveWebSocket(input.purpose);
  try {
    return await runSbx055InteractiveAttempt({ ...input, timeoutMs: WEBSOCKET_TIMEOUT_MS });
  } finally {
    gate.completeWebSocket(audit);
  }
}

function exactAuthRejection(value: Sbx055InteractiveAttempt): boolean {
  return value.purpose === "stale-s1-token-on-s2" && value.issuedUrlRole === "S1" &&
    value.tokenSourceSession === "S1" && value.expectedRuntimeRole === "S2" &&
    value.urlCredentialPurpose === "s1-fresh-stale" &&
    value.tokenCredentialPurpose === "s1-fresh-stale" && value.statusCategory === "auth-rejected" &&
    value.requestCount === 1 && value.retryCount === 0 && value.webSocketClient === `ws@${SBX055_WS_VERSION}` &&
    value.handshakeResponseBodyRetained === false && value.handshakeResponseHeadersRetained === false &&
    value.unexpectedResponseObserved && (value.handshakeStatusCode === 401 || value.handshakeStatusCode === 403) &&
    !value.opened && !value.authenticated && !value.openedExactIssuedUrl && !value.protocolValid &&
    !value.emptyNegotiatedProtocol && !value.emptyNegotiatedExtensions && value.startMessageExpected &&
    value.startMessagesSent === 0 && !value.exactStartMessage && value.binaryFrames === 0 &&
    value.textControlFrames === 0 && value.outputBytes === 0 && value.exitCode === null &&
    !value.markerMatched && !value.crossMarkerAbsent && value.terminal === "http-response-before-open" &&
    value.rawOutputRetained === false && value.rawMarkerRetained === false &&
    value.rawTokenRetained === false && value.rawTokenDigestRetained === false &&
    value.queryBearingUrlRetained === false;
}

export function shouldMintSbx055S2Credential(value: Sbx055InteractiveAttempt): boolean {
  return exactAuthRejection(value);
}

function exactReadbackBarrier(
  value: Sbx055SandboxReadback,
  role: Sbx055Role,
  stage: Sbx055SandboxReadback["stage"],
  journal: Pick<Sbx055RecoveryJournal, "sandboxName" | "session1Id" | "session2Id" | "snapshotId">,
): boolean {
  const sessionId = role === "S1" ? journal.session1Id : journal.session2Id;
  const sourceSnapshotId = role === "S1" ? null : journal.snapshotId ?? null;
  return sessionId !== undefined && value.stage === stage && value.role === role &&
    value.name === journal.sandboxName && value.independentName === journal.sandboxName &&
    value.listedName === journal.sandboxName && value.activeSessionId === sessionId &&
    value.independentSessionId === sessionId && value.listedSessionId === sessionId &&
    value.activeStatus === "running" && value.independentStatus === "running" &&
    value.listedStatus === "running" && value.activeTagsExact && value.independentTagsExact &&
    value.listedTagsExact && value.activePersistent && value.independentPersistent &&
    value.listedPersistent && value.activeTimeoutMs === SBX055_SANDBOX_TIMEOUT_MS &&
    value.independentTimeoutMs === SBX055_SANDBOX_TIMEOUT_MS &&
    value.listedTimeoutMs === SBX055_SANDBOX_TIMEOUT_MS && value.activeDenyAll &&
    value.activeSessionDenyAll && value.independentDenyAll && value.independentSessionDenyAll &&
    value.listedDenyAll && value.activeInteractivePort !== null &&
    Number.isSafeInteger(value.activeInteractivePort) && value.activeInteractivePort >= 1 &&
    value.activeInteractivePort <= 65_535 && value.independentInteractivePort === value.activeInteractivePort &&
    value.activeExactSingleInteractiveRoute && value.independentRouteCount === 0 &&
    value.sourceSnapshotId === sourceSnapshotId && value.independentSourceSnapshotId === sourceSnapshotId &&
    value.independentResumeFalse && value.listQueryExactNamePrefix && value.exactOneListedSandbox &&
    value.listPaginationComplete;
}

function exactNegativeControl(
  value: Sbx055InteractiveAttempt | undefined,
  purpose: "missing-token-negative" | "random-token-negative",
): boolean {
  const source = purpose === "missing-token-negative" ? "none" : "random";
  return value !== undefined && value.purpose === purpose && value.issuedUrlRole === "S1" &&
    value.tokenSourceSession === source && value.expectedRuntimeRole === "none" &&
    value.urlCredentialPurpose === "s1-owner-control" && value.tokenCredentialPurpose === source &&
    value.requestCount === 1 && value.retryCount === 0 && value.webSocketClient === `ws@${SBX055_WS_VERSION}` &&
    value.statusCategory === "auth-rejected" && value.handshakeResponseBodyRetained === false &&
    value.handshakeResponseHeadersRetained === false &&
    value.unexpectedResponseObserved && (value.handshakeStatusCode === 401 || value.handshakeStatusCode === 403) &&
    !value.opened && !value.authenticated && !value.openedExactIssuedUrl && !value.protocolValid &&
    !value.emptyNegotiatedProtocol && !value.emptyNegotiatedExtensions && !value.startMessageExpected &&
    value.startMessagesSent === 0 && value.exactStartMessage && value.binaryFrames === 0 &&
    value.textControlFrames === 0 && value.outputBytes === 0 && value.exitCode === null &&
    !value.markerMatched && !value.crossMarkerAbsent && value.terminal === "http-response-before-open" &&
    value.rawOutputRetained === false && value.rawMarkerRetained === false &&
    value.rawTokenRetained === false && value.rawTokenDigestRetained === false &&
    value.queryBearingUrlRetained === false;
}

function exactOwnerControl(
  value: Sbx055InteractiveAttempt | undefined,
  role: Sbx055Role,
  purpose: "s1-owner-control" | "s2-owner-control",
  markerLength: number,
): boolean {
  return value !== undefined && value.purpose === purpose && value.issuedUrlRole === role &&
    value.tokenSourceSession === role && value.expectedRuntimeRole === role &&
    value.urlCredentialPurpose === purpose && value.tokenCredentialPurpose === purpose &&
    value.requestCount === 1 && value.retryCount === 0 && value.webSocketClient === `ws@${SBX055_WS_VERSION}` &&
    value.statusCategory === "websocket-opened" && value.handshakeResponseBodyRetained === false &&
    value.handshakeResponseHeadersRetained === false &&
    value.opened && value.authenticated && value.openedExactIssuedUrl && value.protocolValid &&
    !value.unexpectedResponseObserved && value.handshakeStatusCode === null &&
    value.emptyNegotiatedProtocol && value.emptyNegotiatedExtensions && value.startMessageExpected &&
    value.startMessagesSent === 1 && value.exactStartMessage &&
    value.binaryFrames === 1 && value.textControlFrames === 1 && value.outputBytes === markerLength &&
    value.markerMatched && value.crossMarkerAbsent && value.exitCode === 0 &&
    value.terminal === "closed-after-exit" && value.rawOutputRetained === false &&
    value.rawMarkerRetained === false && value.rawTokenRetained === false &&
    value.rawTokenDigestRetained === false && value.queryBearingUrlRetained === false;
}

export interface Sbx055S1BarrierInput {
  journal: Pick<Sbx055RecoveryJournal, "sandboxName" | "session1Id" | "session2Id" | "snapshotId">;
  readback: Sbx055SandboxReadback;
  m1WrittenAfterCreate: boolean;
  m1Mode0600: boolean;
  m1ReadExact: boolean;
  m2Absent: boolean;
  marker1Length: number;
  attempts: readonly Sbx055InteractiveAttempt[];
}

export function exactSbx055S1Barrier(input: Sbx055S1BarrierInput): boolean {
  return exactReadbackBarrier(input.readback, "S1", "s1-pre-stop", input.journal) &&
    input.m1WrittenAfterCreate && input.m1Mode0600 && input.m1ReadExact && input.m2Absent &&
    input.attempts.length === 3 && exactNegativeControl(input.attempts[0], "missing-token-negative") &&
    exactNegativeControl(input.attempts[1], "random-token-negative") &&
    exactOwnerControl(input.attempts[2], "S1", "s1-owner-control", input.marker1Length);
}

export interface Sbx055S2BarrierInput {
  journal: Pick<Sbx055RecoveryJournal, "sandboxName" | "session1Id" | "session2Id" | "snapshotId">;
  readback: Sbx055SandboxReadback;
  m1Persisted: boolean;
  m1Mode0600: boolean;
  m1ReadExact: boolean;
  m2WrittenAfterResume: boolean;
  m2Mode0600: boolean;
  m2ReadExact: boolean;
}

export function exactSbx055S2Barrier(input: Sbx055S2BarrierInput): boolean {
  return exactReadbackBarrier(input.readback, "S2", "s2-pre-attempt", input.journal) &&
    input.m1Persisted && input.m1Mode0600 && input.m1ReadExact && input.m2WrittenAfterResume &&
    input.m2Mode0600 && input.m2ReadExact;
}

function isNotFound(error: unknown): boolean {
  return error instanceof APIError && (error.response.status === 404 || error.response.status === 410);
}

function safeCleanupError(error: unknown): { kind: "api" | "other"; status?: number; code?: string; message?: string } {
  if (error instanceof APIError) {
    const nested = object(object(error.json)?.error);
    const code = typeof nested?.code === "string" && nested.code.length <= 128 ? nested.code : undefined;
    return { kind: "api", status: error.response.status, ...(code === undefined ? {} : { code }) };
  }
  return { kind: "other", message: "sanitized local controller failure" };
}

async function namedGet(
  config: Sbx055Config, gate: Sbx055RequestGate, journal: Sbx055RecoveryJournal,
): Promise<Sandbox | undefined> {
  try {
    return await Sandbox.get(getParams(config, gate, journal, false));
  } catch (error) {
    if (isNotFound(error)) return undefined;
    throw error;
  }
}

async function exactSandboxAbsent(
  config: Sbx055Config, gate: Sbx055RequestGate, journal: Sbx055RecoveryJournal,
): Promise<boolean> {
  if (await namedGet(config, gate, journal) !== undefined) return false;
  const listed = await exactSandboxList(config, gate, journal);
  return listed.paginationComplete && listed.matches.length === 0;
}

async function snapshotAbsent(
  config: Sbx055Config, gate: Sbx055RequestGate, snapshotId: string,
): Promise<boolean> {
  try {
    await Snapshot.get({ ...credentials(config, gate), snapshotId,
      signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
    return false;
  } catch (error) {
    if (isNotFound(error)) return true;
    throw error;
  }
}

async function enumerateSnapshots(
  config: Sbx055Config, gate: Sbx055RequestGate, journal: Sbx055RecoveryJournal,
) {
  const page = await Snapshot.list({ ...credentials(config, gate), name: journal.sandboxName,
    limit: 10, sortOrder: "asc", signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
  if (page.pagination.next !== null) throw new Error("SBX-055 snapshot cleanup required a single page");
  for (const snapshot of page.snapshots) gate.registerSnapshot(snapshot.id);
  return page.snapshots;
}

export function planSbx055SnapshotCleanup(
  knownSnapshotIds: readonly string[],
  enumeratedSnapshotIds: readonly string[],
): { allSnapshotIds: string[]; missingKnownIds: string[] } {
  const canonical = /^snap_[A-Za-z0-9_-]{8,192}$/u;
  if ([...knownSnapshotIds, ...enumeratedSnapshotIds].some((id) => !canonical.test(id)) ||
      new Set(knownSnapshotIds).size !== knownSnapshotIds.length ||
      new Set(enumeratedSnapshotIds).size !== enumeratedSnapshotIds.length) {
    throw new Error("SBX-055 refused malformed or duplicate snapshot cleanup IDs");
  }
  const enumerated = new Set(enumeratedSnapshotIds);
  return {
    allSnapshotIds: [...new Set([...knownSnapshotIds, ...enumeratedSnapshotIds])],
    missingKnownIds: knownSnapshotIds.filter((id) => !enumerated.has(id)),
  };
}

export interface Sbx055CleanupHandleProjection {
  name: string;
  tags: Record<string, string>;
  persistent: boolean;
  sessionId: string;
  sourceSnapshotId: string | null;
  status: string;
}

export function exactSbx055UnresolvedResumeHandle(
  journal: Pick<Sbx055RecoveryJournal,
    "sandboxName" | "tags" | "persistent" | "resumeAttempted" | "session1Id" | "session2Id" | "snapshotId">,
  observed: Sbx055CleanupHandleProjection,
): boolean {
  return journal.resumeAttempted && journal.session2Id === undefined &&
    journal.session1Id !== undefined && journal.snapshotId !== undefined &&
    observed.name === journal.sandboxName && exactTags(observed.tags, journal.tags) &&
    observed.persistent === journal.persistent && observed.sessionId !== journal.session1Id &&
    observed.sourceSnapshotId === journal.snapshotId;
}

export function shouldIssueSbx055CleanupStop(
  journal: Pick<Sbx055RecoveryJournal,
    "stopAttempted" | "stopped" | "resumeAttempted" | "session2Id" |
    "cleanupStopAttempted" | "cleanupStopped">,
  observedStatus: string,
): boolean {
  return observedStatus === "running" && !journal.cleanupStopAttempted &&
    !(journal.stopAttempted && !journal.stopped) &&
    !(journal.resumeAttempted && journal.session2Id === undefined);
}

export function exactSbx055RecoveredStopSnapshotId(
  sessionId: string,
  snapshots: readonly { id: string; sourceSessionId: string; status: string }[],
): string | undefined {
  const exact = snapshots.filter((entry) => entry.sourceSessionId === sessionId &&
    entry.status === "created" && /^snap_[A-Za-z0-9_-]{8,192}$/u.test(entry.id));
  return exact.length === 1 ? exact[0]!.id : undefined;
}

export function exactSbx055SnapshotDelete404Checkpoint(
  journal: Pick<Sbx055RecoveryJournal,
    "snapshotsObserved" | "snapshotDeleteIntents" | "snapshotsDeleted">,
  snapshotId: string,
): "unattempted" | "intent-recorded" | "completed" {
  if (!journal.snapshotsObserved.includes(snapshotId) ||
      !/^snap_[A-Za-z0-9_-]{8,192}$/u.test(snapshotId)) return "unattempted";
  if (journal.snapshotsDeleted.includes(snapshotId)) return "completed";
  return journal.snapshotDeleteIntents.includes(snapshotId) ? "intent-recorded" : "unattempted";
}

async function cleanupSbx055(
  config: Sbx055Config,
  gate: Sbx055RequestGate,
  journal: Sbx055RecoveryJournal,
  lock: Sbx055HeldLock,
  knownHandle?: Sandbox,
): Promise<Sbx055CleanupProof> {
  const sandboxResult: Sbx055CleanupProof["sandbox"] = {
    attempted: journal.createAttemptedAt !== undefined,
    exactProvenance: false,
    s2SessionIdKnown: journal.session2Id !== undefined,
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    firstAbsence: false,
    secondAbsence: false,
    thirdAbsence: false,
    namedAbsenceChecks: 0,
    prefixListAbsent: false,
    errors: [],
  };
  const snapshotResults: Sbx055SnapshotCleanup[] = [];
  let enumerationComplete = false;
  let snapshotListPaginationComplete = false;
  let observedSnapshotCount = 0;
  let unexpectedSnapshots = 0;
  let unresolvedS1Stop = false;
  let unresolvedCleanupStop = false;
  let cleanupStopSessionId: string | undefined;
  journal.phase = "cleanup";
  await persistSbx055Journal(lock, journal);
  try {
    let handle = knownHandle;
    if (handle === undefined) handle = await namedGet(config, gate, journal);
    if (handle !== undefined) {
      const sessionId = handle.currentSession().sessionId;
      if (journal.session1Id === undefined && journal.session2Id === undefined &&
          handle.name === journal.sandboxName && exactTags(handle.tags, journal.tags) && handle.persistent) {
        journal.session1Id = sessionId;
        await persistSbx055Journal(lock, journal);
      }
      if (journal.resumeAttempted && journal.session2Id === undefined &&
          exactSbx055UnresolvedResumeHandle(journal, {
            name: handle.name,
            tags: handle.tags ?? {},
            persistent: handle.persistent,
            sessionId,
            sourceSnapshotId: handle.sourceSnapshotId ?? null,
            status: handle.status,
          })) {
        journal.session2Id = sessionId;
        await persistSbx055Journal(lock, journal);
        sandboxResult.s2SessionIdKnown = true;
      }
      if (journal.resumeAttempted && journal.session2Id === undefined) {
        throw new Error("SBX-055 unresolved resume lacked one exact distinct S2 handle; state retained");
      }
      const exactKnownSession = sessionId === journal.session2Id ||
        (!journal.resumeAttempted && journal.session2Id === undefined && sessionId === journal.session1Id);
      if (handle.name !== journal.sandboxName || !exactTags(handle.tags, journal.tags) ||
          !handle.persistent || !exactKnownSession) {
        throw new Error("SBX-055 refused cleanup without exact named/session/tag provenance");
      }
      gate.registerSession(journal.session2Id === sessionId ? "S2" : "S1", sessionId);
      sandboxResult.exactProvenance = true;
      sandboxResult.stopAttempted = true;
      if (journal.stopAttempted && !journal.stopped) {
        if (sessionId !== journal.session1Id || handle.status !== "stopped") {
          throw new Error("SBX-055 unresolved S1 stop was not freshly observed stopped; stop not reissued");
        }
        unresolvedS1Stop = true;
      } else if (journal.cleanupStopAttempted && !journal.cleanupStopped) {
        if (handle.status !== "stopped") {
          throw new Error("SBX-055 unresolved cleanup stop was not freshly observed stopped; stop not reissued");
        }
        unresolvedCleanupStop = true;
        cleanupStopSessionId = sessionId;
      } else if (shouldIssueSbx055CleanupStop(journal, handle.status)) {
        journal.cleanupStopAttempted = true;
        await persistSbx055Journal(lock, journal);
        const stopped = await handle.stop({ signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
        if (stopped.status !== "stopped") throw new Error("SBX-055 cleanup stop was not exact");
        if (stopped.snapshot === undefined || stopped.snapshot.status !== "created" ||
            stopped.snapshot.sourceSessionId !== sessionId ||
            !/^snap_[A-Za-z0-9_-]{8,192}$/u.test(stopped.snapshot.id)) {
          throw new Error("SBX-055 cleanup snapshot provenance was not exact");
        }
        gate.registerSnapshot(stopped.snapshot.id);
        if (!journal.snapshotsObserved.includes(stopped.snapshot.id)) {
          journal.snapshotsObserved.push(stopped.snapshot.id);
        }
        journal.cleanupStopped = true;
        // Persist the authoritative cleanup-stop result before any subsequent
        // cleanup operation can make its list visibility race relevant.
        await persistSbx055Journal(lock, journal);
        sandboxResult.stopped = true;
      } else if (handle.status === "stopped" &&
          (!journal.cleanupStopAttempted || journal.cleanupStopped)) {
        sandboxResult.stopped = true;
      } else {
        throw new Error("SBX-055 cleanup handle state could not safely settle without a repeated stop");
      }
    } else if (journal.session1Id !== undefined || journal.session2Id !== undefined) {
      if ((journal.resumeAttempted && journal.session2Id === undefined) ||
          (journal.stopAttempted && !journal.stopped) ||
          (journal.cleanupStopAttempted && !journal.cleanupStopped) || !journal.deleteAttempted) {
        throw new Error("SBX-055 missing handle left lifecycle state unresolved; state retained");
      }
      sandboxResult.exactProvenance = true;
      sandboxResult.stopAttempted = journal.cleanupStopAttempted;
      sandboxResult.stopped = journal.cleanupStopped || journal.stopped;
    } else {
      throw new Error("SBX-055 cannot resolve a response-lost create without an exact handle");
    }

    const snapshots = await enumerateSnapshots(config, gate, journal);
    enumerationComplete = true;
    snapshotListPaginationComplete = true;
    if (unresolvedS1Stop || (journal.stopAttempted && journal.snapshotId === undefined)) {
      if (journal.session1Id === undefined) {
        throw new Error("SBX-055 response-lost S1 stop lacked its session ID");
      }
      const recoveredS1Id = exactSbx055RecoveredStopSnapshotId(journal.session1Id, snapshots);
      if (recoveredS1Id === undefined) {
        throw new Error("SBX-055 response-lost S1 stop lacks one authoritative snapshot");
      }
      journal.snapshotId = recoveredS1Id;
      if (!journal.snapshotsObserved.includes(recoveredS1Id)) {
        journal.snapshotsObserved.push(recoveredS1Id);
      }
      journal.stopped = true;
      sandboxResult.stopped = true;
      await persistSbx055Journal(lock, journal);
    }
    if (unresolvedCleanupStop) {
      if (cleanupStopSessionId === undefined) {
        throw new Error("SBX-055 response-lost cleanup stop lacked its session ID");
      }
      const recoveredCleanupId = exactSbx055RecoveredStopSnapshotId(cleanupStopSessionId, snapshots);
      if (recoveredCleanupId === undefined || recoveredCleanupId === journal.snapshotId) {
        throw new Error("SBX-055 response-lost cleanup stop lacks one authoritative new snapshot");
      }
      if (!journal.snapshotsObserved.includes(recoveredCleanupId)) {
        journal.snapshotsObserved.push(recoveredCleanupId);
      }
      journal.cleanupStopped = true;
      sandboxResult.stopped = true;
      await persistSbx055Journal(lock, journal);
    }
    if (journal.cleanupStopAttempted && journal.session2Id !== undefined) {
      const knownS2Snapshot = snapshots.some((entry) =>
        entry.sourceSessionId === journal.session2Id && entry.status === "created") ||
        journal.snapshotsObserved.some((id) => id !== journal.snapshotId);
      if (!knownS2Snapshot) {
        throw new Error("SBX-055 response-lost S2 cleanup stop lacks an authoritative snapshot");
      }
    }
    const snapshotPlan = planSbx055SnapshotCleanup(
      journal.snapshotsObserved,
      snapshots.map((entry) => entry.id),
    );
    observedSnapshotCount = snapshotPlan.allSnapshotIds.length;
    for (const snapshot of snapshots) {
      if (!journal.snapshotsObserved.includes(snapshot.id)) journal.snapshotsObserved.push(snapshot.id);
    }
    for (const snapshotId of snapshotPlan.allSnapshotIds) gate.registerSnapshot(snapshotId);
    await persistSbx055Journal(lock, journal);

    sandboxResult.deleteAttempted = true;
    journal.deleteAttempted = true;
    await persistSbx055Journal(lock, journal);
    if (handle !== undefined) {
      try { await handle.delete({ signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) }); }
      catch (error) { if (!isNotFound(error)) throw error; }
    }
    sandboxResult.deleted = true;
    journal.deleted = true;
    await persistSbx055Journal(lock, journal);
    const sandboxAbsences: boolean[] = [];
    for (let index = 0; index < 3; index += 1) {
      if (index > 0) await delay(ABSENCE_DELAY_MS);
      sandboxAbsences.push(await exactSandboxAbsent(config, gate, journal));
    }
    [sandboxResult.firstAbsence, sandboxResult.secondAbsence, sandboxResult.thirdAbsence] =
      sandboxAbsences as [boolean, boolean, boolean];
    sandboxResult.namedAbsenceChecks = sandboxAbsences.filter(Boolean).length;
    sandboxResult.prefixListAbsent = sandboxAbsences.every(Boolean);
    journal.sandboxAbsenceChecks = sandboxAbsences.filter(Boolean).length;
    journal.prefixListAbsent = sandboxResult.prefixListAbsent;
    if (!sandboxResult.prefixListAbsent) throw new Error("SBX-055 sandbox absence proof failed");

    const listedSnapshots = new Map(snapshots.map((entry) => [entry.id, entry]));
    for (const snapshotId of snapshotPlan.allSnapshotIds) {
      const listed = listedSnapshots.get(snapshotId);
      const inferredSourceSessionId = listed?.sourceSessionId ??
        (snapshotId === journal.snapshotId ? journal.session1Id : journal.session2Id);
      const sourceRole: Sbx055Role | undefined = inferredSourceSessionId === journal.session1Id ? "S1"
        : inferredSourceSessionId === journal.session2Id ? "S2" : undefined;
      const result: Sbx055SnapshotCleanup = {
        snapshotId,
        sourceRole: sourceRole ?? "S1",
        sourceSessionId: inferredSourceSessionId ?? "",
        exactProvenance: sourceRole !== undefined && (listed === undefined || listed.status === "created"),
        deleteAttempted: false,
        deleted: false,
        firstAbsence: false,
        secondAbsence: false,
        absenceChecks: 0,
        errors: [],
      };
      if (!result.exactProvenance) unexpectedSnapshots += 1;
      try {
        if (!result.exactProvenance) throw new Error("SBX-055 unexpected snapshot provenance");
        let snapshot: Snapshot | undefined;
        try {
          snapshot = await Snapshot.get({ ...credentials(config, gate), snapshotId,
            signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
        } catch (error) {
          if (!isNotFound(error)) throw error;
          if (exactSbx055SnapshotDelete404Checkpoint(journal, snapshotId) === "unattempted") {
            throw new Error("SBX-055 known snapshot was not yet observable; cleanup state retained");
          }
        }
        if (snapshot !== undefined) {
          if (snapshot.sourceSessionId !== inferredSourceSessionId || snapshot.status !== "created") {
            throw new Error("SBX-055 snapshot GET provenance drifted");
          }
          if (!journal.snapshotDeleteIntents.includes(snapshotId)) {
            journal.snapshotDeleteIntents.push(snapshotId);
            await persistSbx055Journal(lock, journal);
          }
          result.deleteAttempted = true;
          try {
            await snapshot.delete({ signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
          } catch (error) {
            if (!isNotFound(error)) throw error;
          }
          result.deleted = true;
        } else {
          result.deleteAttempted = true;
          result.deleted = true;
        }
        if (!journal.snapshotsDeleted.includes(snapshotId)) {
          journal.snapshotsDeleted.push(snapshotId);
          // Checkpoint exact delete completion immediately. A crash after the
          // remote DELETE can then accept only this intent-bound ID's exact 404.
          await persistSbx055Journal(lock, journal);
        }
        result.firstAbsence = await snapshotAbsent(config, gate, snapshotId);
        result.absenceChecks += Number(result.firstAbsence);
        await delay(ABSENCE_DELAY_MS);
        result.secondAbsence = await snapshotAbsent(config, gate, snapshotId);
        result.absenceChecks += Number(result.secondAbsence);
        if (!result.firstAbsence || !result.secondAbsence) throw new Error("SBX-055 snapshot absence failed");
      } catch (error) {
        result.errors.push(safeCleanupError(error));
      }
      snapshotResults.push(result);
    }
    journal.snapshotAbsenceChecks = snapshotResults.reduce((count, value) =>
      count + Number(value.firstAbsence) + Number(value.secondAbsence), 0);
    await persistSbx055Journal(lock, journal);
  } catch (error) {
    sandboxResult.errors.push(safeCleanupError(error));
  }
  const remotePassed = sandboxResult.exactProvenance && sandboxResult.stopped && sandboxResult.deleted &&
    sandboxResult.firstAbsence && sandboxResult.secondAbsence && sandboxResult.thirdAbsence &&
    sandboxResult.namedAbsenceChecks === 3 && sandboxResult.prefixListAbsent &&
    sandboxResult.errors.length === 0 && enumerationComplete &&
    snapshotListPaginationComplete && observedSnapshotCount >= 1 && observedSnapshotCount <= 8 &&
    unexpectedSnapshots === 0 && snapshotResults.length === observedSnapshotCount &&
    snapshotResults.every((entry) => entry.exactProvenance && entry.deleteAttempted && entry.deleted &&
      entry.firstAbsence && entry.secondAbsence && entry.absenceChecks === 2 && entry.errors.length === 0);
  const cleanup: Sbx055CleanupProof = {
    passed: false,
    sandbox: sandboxResult,
    snapshotEnumerationComplete: enumerationComplete,
    snapshotListPaginationComplete,
    observedSnapshotCount,
    unexpectedSnapshots,
    snapshots: snapshotResults,
    journalRemoved: false,
    liveLockReleased: false,
  };
  if (remotePassed) {
    try {
      journal.completed = true;
      journal.phase = "complete";
      await persistSbx055Journal(lock, journal);
      await releaseSbx055LockAndJournal(lock);
      cleanup.liveLockReleased = lock.liveLock.isReleased();
      cleanup.journalRemoved = cleanup.liveLockReleased;
      cleanup.passed = cleanup.liveLockReleased && cleanup.journalRemoved;
    } catch (error) {
      cleanup.sandbox.errors.push(safeCleanupError(error));
    }
  }
  return cleanup;
}

export async function auditSbx055InstalledWire(): Promise<boolean> {
  const [sdkPackage, wsPackage, apiSource, sandboxSource, privateSource] = await Promise.all([
    readFile(new URL("../../node_modules/@vercel/sandbox/package.json", import.meta.url), "utf8"),
    readFile(new URL("../../infra/h3-action-worker/node_modules/ws/package.json", import.meta.url), "utf8"),
    readFile(new URL("../../node_modules/@vercel/sandbox/dist/api-client/api-client.js", import.meta.url), "utf8"),
    readFile(new URL("../../node_modules/@vercel/sandbox/dist/sandbox.js", import.meta.url), "utf8"),
    readFile(new URL("../../node_modules/@vercel/sandbox/dist/utils/types.js", import.meta.url), "utf8"),
  ]);
  const sdk = JSON.parse(sdkPackage) as { version?: unknown };
  const ws = JSON.parse(wsPackage) as { version?: unknown };
  const passed = sdk.version === SDK_VERSION && ws.version === SBX055_WS_VERSION &&
    apiSource.includes("`/v2/sandboxes/sessions/${params.sessionId}/interactive`") &&
    apiSource.includes("body: JSON.stringify({})") &&
    apiSource.includes("`/v2/sandboxes/sessions/${params.sessionId}/stop`") &&
    apiSource.includes("snapshotExpiration: params.snapshotExpiration") &&
    sandboxSource.includes("resume: params.resume") && sandboxSource.includes("if (response.json.resumed") &&
    privateSource.includes('k.startsWith("__")');
  if (!passed) throw new Error("SBX-055 installed SDK/WebSocket lifecycle wire audit drifted");
  return true;
}

function chronologyRecorder(steps: Sbx055ChronologyStep[]) {
  let previous = Date.now() - 1;
  const stamp = (): string => {
    const next = Math.max(Date.now(), previous + 1);
    previous = next;
    return new Date(next).toISOString();
  };
  return async <T>(stage: Sbx055ChronologyStage, action: () => Promise<T>): Promise<T> => {
    const startedAt = stamp();
    const result = await action();
    const completedAt = stamp();
    steps.push({ stage, startedAt, completedAt });
    return result;
  };
}

function incompleteAssessment(summary: string): Sbx055Assessment {
  return {
    verdict: "indeterminate",
    candidate: false,
    controlsPassed: false,
    maximumDemonstratedImpact: "none",
    maximumSeverity: "none",
    reportability: "none",
    summary,
  };
}

async function releaseZeroExternalState(lock: Sbx055HeldLock): Promise<Sbx055CleanupProof> {
  await releaseSbx055LockAndJournal(lock);
  return {
    passed: false,
    sandbox: {
      attempted: false,
      exactProvenance: true,
      s2SessionIdKnown: false,
      stopAttempted: false,
      stopped: false,
      deleteAttempted: false,
      deleted: false,
      firstAbsence: false,
      secondAbsence: false,
      thirdAbsence: false,
      namedAbsenceChecks: 0,
      prefixListAbsent: false,
      errors: [],
    },
    snapshotEnumerationComplete: false,
    snapshotListPaginationComplete: false,
    observedSnapshotCount: 0,
    unexpectedSnapshots: 0,
    snapshots: [],
    journalRemoved: lock.liveLock.isReleased(),
    liveLockReleased: lock.liveLock.isReleased(),
  };
}

async function runRecovery(
  config: Sbx055Config,
  journal: Sbx055RecoveryJournal,
  lock: Sbx055HeldLock,
): Promise<void> {
  const attemptId = randomUUID();
  const artifactPath = sbx055RecoveryArtifactPath(journal.runId, attemptId);
  if (zeroExternalStateJournal(journal)) {
    await releaseSbx055LockAndJournal(lock);
    const artifact = {
      schemaVersion: 1,
      testId: SBX055_TEST_ID,
      runId: journal.runId,
      recoveryAttemptId: attemptId,
      recoveryOnly: true,
      mode: "cleanup-only",
      outcome: "zero-external-state-released",
      externalRequests: 0,
      cleanupAttempted: false,
      journalRemoved: true,
      liveLockReleased: lock.liveLock.isReleased(),
      retention: {
        rawMarkers: false, rawMarkerDigests: false, rawInteractiveTokens: false,
        rawInteractiveTokenDigests: false, rawInteractiveUrls: false,
        rawInteractiveUrlDigests: false, commandOutput: false, commandOutputDigests: false,
      },
    };
    assertSbx055EvidenceHasNoRawCapabilities(artifact, [config.token]);
    await writeSbx055PrivateArtifact(artifactPath, artifact);
    return;
  }
  const gate = createSbx055RequestGate(fetch, config.token, journal);
  const forbidden = [config.token];
  let identity: EligibleAliasIdentityProof | undefined;
  let cleanup: Sbx055CleanupProof | undefined;
  let failure: string | undefined;
  try {
    identity = await verifyEligibleAliasToken({
      token: config.token,
      expectedEmail: config.expectedAlias,
      expectedTeamId: config.teamId,
      expectedProjectId: config.projectId,
      manualEmailConfirmation: config.manualAliasConfirmation,
      fetchImpl: gate.fetch,
    });
    cleanup = await cleanupSbx055(config, gate, journal, lock);
  } catch (error) {
    failure = safeSbx055Error(error, forbidden);
  }
  const artifact = {
    schemaVersion: 1,
    testId: SBX055_TEST_ID,
    runId: journal.runId,
    recoveryAttemptId: attemptId,
    recoveryOnly: true,
    mode: "cleanup-only",
    outcome: cleanup?.passed === true ? "cleanup-complete" : "cleanup-incomplete",
    scopeAndAliasPassed: identity?.email === SBX055_ALIAS && identity.teamId === SBX055_TEAM &&
      identity.projectId === SBX055_PROJECT,
    cleanup,
    failure,
    requestAudit: gate.summary(),
    retention: {
      rawMarkers: false, rawMarkerDigests: false, rawInteractiveTokens: false,
      rawInteractiveTokenDigests: false, rawInteractiveUrls: false,
      rawInteractiveUrlDigests: false, commandOutput: false, commandOutputDigests: false,
    },
  };
  assertSbx055EvidenceHasNoRawCapabilities(artifact, forbidden);
  await writeSbx055PrivateArtifact(artifactPath, artifact);
  process.exitCode = cleanup?.passed === true ? 0 : 1;
}

export async function writeSbx055LocalRecoveryCompletion(
  config: Sbx055Config,
  runId: string,
  outcome: Exclude<Sbx055RecoveryDispatchOutcome, "continue-journal-recovery">,
  suppliedAttemptId?: string,
): Promise<{ artifactPath: string; evidence: Record<string, unknown> }> {
  const attemptId = suppliedAttemptId ?? randomUUID();
  const artifactPath = sbx055RecoveryArtifactPath(runId, attemptId);
  const evidence = {
    schemaVersion: 1,
    testId: SBX055_TEST_ID,
    runId,
    recoveryAttemptId: attemptId,
    recoveryOnly: true,
    mode: "cleanup-only",
    outcome,
    externalRequests: 0,
    cleanupAttempted: false,
    journalRemoved: true,
    liveLockReleased: true,
    retention: {
      rawMarkers: false,
      rawMarkerDigests: false,
      rawInteractiveTokens: false,
      rawInteractiveTokenDigests: false,
      rawInteractiveUrls: false,
      rawInteractiveUrlDigests: false,
      commandOutput: false,
      commandOutputDigests: false,
    },
  };
  assertSbx055EvidenceHasNoRawCapabilities(evidence, [config.token]);
  await writeSbx055PrivateArtifact(artifactPath, evidence);
  return { artifactPath, evidence };
}

export async function main(): Promise<void> {
  const config = loadSbx055Config();
  if (config.recoveryRunId !== undefined) {
    const dispatch = await dispatchSbx055Recovery(config.recoveryRunId);
    if (dispatch !== "continue-journal-recovery") {
      await writeSbx055LocalRecoveryCompletion(config, config.recoveryRunId, dispatch);
      return;
    }
    const lock = await acquireSbx055RecoveryLock(config.recoveryRunId);
    const journal = await readSbx055Journal(config.recoveryRunId);
    await runRecovery(config, journal, lock);
    return;
  }

  const journal = createSbx055Journal();
  const lock = await acquireSbx055Lock(journal);
  const gate = createSbx055RequestGate(fetch, config.token, journal);
  const chronology: Sbx055ChronologyStep[] = [];
  const timed = chronologyRecorder(chronology);
  const markerState: MarkerState = {
    m1: Buffer.from(randomBytes(32).toString("base64url"), "utf8"),
    m2: Buffer.from(randomBytes(32).toString("base64url"), "utf8"),
    s1WrittenAfterCreate: false, s1Mode0600: false, s1LocalReadExactBeforeStop: false,
    s2AbsentBeforeStop: false, s1PersistedAfterResume: false, s1Mode0600AfterResume: false,
    s1LocalReadExactAfterResume: false, s2WrittenOnlyAfterResume: false, s2Mode0600: false,
    s2LocalReadExactAfterResume: false,
  };
  const forbidden = [config.token, markerState.m1.toString("utf8"), markerState.m2.toString("utf8")];
  const issuances: TransientCredential[] = [];
  const attempts: Sbx055InteractiveAttempt[] = [];
  const tokenUses = new Map<string, number>();
  const readbacks: Sbx055SandboxReadback[] = [];
  let identity: EligibleAliasIdentityProof | undefined;
  let wireAuditPassed = false;
  let sandbox: Sandbox | undefined;
  let snapshot: { id: string; sourceSessionId: string; status: "created" | "failed" | "deleted" } | undefined;
  let s1Owner: TransientCredential | undefined;
  let stale: TransientCredential | undefined;
  let s2Owner: TransientCredential | undefined;
  let staleUnusedBeforeAttack = false;
  let stalePairUsedUnchanged = false;
  let cleanup: Sbx055CleanupProof | undefined;
  let failure: string | undefined;

  try {
    wireAuditPassed = await auditSbx055InstalledWire();
    identity = await verifyEligibleAliasToken({
      token: config.token,
      expectedEmail: config.expectedAlias,
      expectedTeamId: config.teamId,
      expectedProjectId: config.projectId,
      manualEmailConfirmation: config.manualAliasConfirmation,
      fetchImpl: gate.fetch,
    });

    journal.createAttemptedAt = new Date().toISOString();
    await persistSbx055Journal(lock, journal);
    sandbox = await Sandbox.create(createParams(config, gate, journal));
    journal.createRequestSettledAt = new Date().toISOString();
    if (!exactSandboxBase(sandbox, journal) || sandbox.sourceSnapshotId !== undefined) {
      throw new Error("SBX-055 S1 create response failed exact persistent provenance");
    }
    journal.session1Id = sandbox.currentSession().sessionId;
    gate.registerSession("S1", journal.session1Id);
    journal.phase = "s1-running";
    await persistSbx055Journal(lock, journal);

    readbacks.push(await timed("s1-readbacks", () =>
      sandboxReadback("s1-pre-stop", "S1", sandbox!, config, gate, journal)));

    await timed("write-read-m1", async () => {
      const before = sandbox!.currentSession().sessionId;
      await sandbox!.currentSession().writeFiles([
        { path: journal.marker1Path, content: markerState.m1, mode: 0o600 },
      ], { signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
      markerState.s1WrittenAfterCreate = before === journal.session1Id &&
        sandbox!.currentSession().sessionId === journal.session1Id;
      const proof = await readMarker(sandbox!, journal.marker1Path, markerState.m1);
      markerState.s1Mode0600 = proof.mode0600;
      markerState.s1LocalReadExactBeforeStop = proof.exact;
    });
    journal.phase = "s1-fixtures-ready";
    await persistSbx055Journal(lock, journal);

    s1Owner = await timed("issue-s1-owner-control", () =>
      issueInteractiveCredential(config, gate, "S1", journal.session1Id!, "s1-owner-control"));
    issuances.push(s1Owner);
    forbidden.push(s1Owner.token, s1Owner.baseUrl);
    attempts.push(await timed("missing-token-negative", () => interactiveAttempt(gate, {
      purpose: "missing-token-negative", issuedUrlRole: "S1", tokenSourceSession: "none",
      expectedRuntimeRole: "none", urlCredentialPurpose: "s1-owner-control",
      tokenCredentialPurpose: "none", baseUrl: s1Owner!.baseUrl,
    }, tokenUses)));
    let invalidToken = `invalid_${randomBytes(32).toString("base64url")}`;
    while (invalidToken === s1Owner.token) invalidToken = `invalid_${randomBytes(32).toString("base64url")}`;
    forbidden.push(invalidToken);
    attempts.push(await timed("random-token-negative", () => interactiveAttempt(gate, {
      purpose: "random-token-negative", issuedUrlRole: "S1", tokenSourceSession: "random",
      expectedRuntimeRole: "none", urlCredentialPurpose: "s1-owner-control",
      tokenCredentialPurpose: "random", baseUrl: s1Owner!.baseUrl, token: invalidToken,
    }, tokenUses)));
    attempts.push(await timed("s1-owner-control", () => interactiveAttempt(gate, {
      purpose: "s1-owner-control", issuedUrlRole: "S1", tokenSourceSession: "S1",
      expectedRuntimeRole: "S1", urlCredentialPurpose: "s1-owner-control",
      tokenCredentialPurpose: "s1-owner-control", baseUrl: s1Owner!.baseUrl, token: s1Owner!.token,
      markerPath: journal.marker1Path, expectedMarker: markerState.m1, crossMarker: markerState.m2,
    }, tokenUses)));

    await timed("m2-absence-before-stop", async () => {
      markerState.s2AbsentBeforeStop = await markerAbsent(sandbox!, journal.marker2Path) &&
        sandbox!.currentSession().sessionId === journal.session1Id;
    });
    if (!exactSbx055S1Barrier({
      journal,
      readback: readbacks[0]!,
      m1WrittenAfterCreate: markerState.s1WrittenAfterCreate,
      m1Mode0600: markerState.s1Mode0600,
      m1ReadExact: markerState.s1LocalReadExactBeforeStop,
      m2Absent: markerState.s2AbsentBeforeStop,
      marker1Length: markerState.m1.length,
      attempts,
    })) throw new Error("SBX-055 refused to mint stale T1 after an inexact S1 control barrier");
    stale = await timed("issue-s1-fresh-stale", () =>
      issueInteractiveCredential(config, gate, "S1", journal.session1Id!, "s1-fresh-stale"));
    issuances.push(stale);
    forbidden.push(stale.token, stale.baseUrl);
    if (stale.token === s1Owner.token) throw new Error("SBX-055 interactive tokens were not distinct");
    staleUnusedBeforeAttack = (tokenUses.get(stale.token) ?? 0) === 0;
    journal.phase = "stale-token-issued";
    await persistSbx055Journal(lock, journal);

    journal.stopAttempted = true;
    await persistSbx055Journal(lock, journal);
    const stopped = await timed("stop-s1", () =>
      sandbox!.stop({ signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) }));
    if (stopped.status !== "stopped" || stopped.snapshot === undefined) {
      throw new Error("SBX-055 persistent S1 stop did not return a created snapshot");
    }
    snapshot = await timed("snapshot-created", async () => {
      if (stopped.snapshot!.status !== "created" ||
          stopped.snapshot!.sourceSessionId !== journal.session1Id ||
          !/^snap_[A-Za-z0-9_-]{8,192}$/u.test(stopped.snapshot!.id)) {
        throw new Error("SBX-055 S1 snapshot provenance was not exact");
      }
      return { id: stopped.snapshot!.id, sourceSessionId: stopped.snapshot!.sourceSessionId,
        status: stopped.snapshot!.status };
    });
    gate.registerSnapshot(snapshot.id);
    journal.stopped = true;
    journal.snapshotId = snapshot.id;
    if (!journal.snapshotsObserved.includes(snapshot.id)) journal.snapshotsObserved.push(snapshot.id);
    journal.phase = "s1-stopped";
    await persistSbx055Journal(lock, journal);

    journal.resumeAttempted = true;
    await persistSbx055Journal(lock, journal);
    sandbox = await timed("resume-s2", () => Sandbox.get(getParams(config, gate, journal, true)));
    const s2Id = sandbox.currentSession().sessionId;
    if (!exactSandboxBase(sandbox, journal) || s2Id === journal.session1Id ||
        sandbox.sourceSnapshotId !== snapshot.id) {
      throw new Error("SBX-055 S2 resume response failed exact snapshot/session provenance");
    }
    gate.registerSession("S2", s2Id);
    journal.session2Id = s2Id;
    journal.phase = "s2-running";
    await persistSbx055Journal(lock, journal);

    readbacks.push(await timed("s2-pre-readbacks", () =>
      sandboxReadback("s2-pre-attempt", "S2", sandbox!, config, gate, journal)));
    await timed("verify-m1-persisted", async () => {
      const proof = await readMarker(sandbox!, journal.marker1Path, markerState.m1);
      markerState.s1PersistedAfterResume = proof.exact;
      markerState.s1Mode0600AfterResume = proof.mode0600;
      markerState.s1LocalReadExactAfterResume = proof.exact && sandbox!.currentSession().sessionId === s2Id;
    });
    await timed("write-read-m2", async () => {
      const before = sandbox!.currentSession().sessionId;
      await sandbox!.currentSession().writeFiles([
        { path: journal.marker2Path, content: markerState.m2, mode: 0o600 },
      ], { signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
      markerState.s2WrittenOnlyAfterResume = before === s2Id && sandbox!.currentSession().sessionId === s2Id;
      const proof = await readMarker(sandbox!, journal.marker2Path, markerState.m2);
      markerState.s2Mode0600 = proof.mode0600;
      markerState.s2LocalReadExactAfterResume = proof.exact;
    });
    if (!exactSbx055S2Barrier({
      journal,
      readback: readbacks[1]!,
      m1Persisted: markerState.s1PersistedAfterResume,
      m1Mode0600: markerState.s1Mode0600AfterResume,
      m1ReadExact: markerState.s1LocalReadExactAfterResume,
      m2WrittenAfterResume: markerState.s2WrittenOnlyAfterResume,
      m2Mode0600: markerState.s2Mode0600,
      m2ReadExact: markerState.s2LocalReadExactAfterResume,
    })) throw new Error("SBX-055 refused the stale-token attempt after an inexact S2 control barrier");

    const staleBaseUrl = stale.baseUrl;
    const staleToken = stale.token;
    const staleAttempt = await timed("stale-s1-token-on-s2", () => interactiveAttempt(gate, {
      purpose: "stale-s1-token-on-s2", issuedUrlRole: "S1", tokenSourceSession: "S1",
      expectedRuntimeRole: "S2", urlCredentialPurpose: "s1-fresh-stale",
      tokenCredentialPurpose: "s1-fresh-stale", baseUrl: staleBaseUrl, token: staleToken,
      markerPath: journal.marker2Path, expectedMarker: markerState.m2, crossMarker: markerState.m1,
    }, tokenUses));
    stalePairUsedUnchanged = stale.baseUrl === staleBaseUrl && stale.token === staleToken;
    attempts.push(staleAttempt);
    if (exactAuthRejection(staleAttempt)) {
      s2Owner = await timed("issue-s2-owner-control", () =>
        issueInteractiveCredential(config, gate, "S2", s2Id, "s2-owner-control"));
      issuances.push(s2Owner);
      forbidden.push(s2Owner.token, s2Owner.baseUrl);
      if (issuances.some((entry) => entry !== s2Owner && entry.token === s2Owner!.token)) {
        throw new Error("SBX-055 returned a repeated interactive token");
      }
      const s2Control = await timed("s2-owner-control", () => interactiveAttempt(gate, {
        purpose: "s2-owner-control", issuedUrlRole: "S2", tokenSourceSession: "S2",
        expectedRuntimeRole: "S2", urlCredentialPurpose: "s2-owner-control",
        tokenCredentialPurpose: "s2-owner-control", baseUrl: s2Owner!.baseUrl, token: s2Owner!.token,
        markerPath: journal.marker2Path, expectedMarker: markerState.m2, crossMarker: markerState.m1,
      }, tokenUses));
      attempts.push(s2Control);
      if (!exactOwnerControl(s2Control, "S2", "s2-owner-control", markerState.m2.length)) {
        throw new Error("SBX-055 rejected an inexact fresh S2 owner control");
      }
    }
    journal.phase = "attack-complete";
    await persistSbx055Journal(lock, journal);
    readbacks.push(await timed("s2-post-readbacks", () =>
      sandboxReadback("s2-post-attempt", "S2", sandbox!, config, gate, journal)));
  } catch (error) {
    failure = safeSbx055Error(error, forbidden);
  } finally {
    cleanup = await timed("cleanup", () => zeroExternalStateJournal(journal)
      ? releaseZeroExternalState(lock)
      : cleanupSbx055(config, gate, journal, lock, sandbox));
  }

  const scopeAndAliasPassed = identity?.email === SBX055_ALIAS && identity.teamId === SBX055_TEAM &&
    identity.projectId === SBX055_PROJECT;
  const requestAudit = gate.summary();
  let assessment = incompleteAssessment(failure ?? "The exact lifecycle matrix was incomplete.");
  if (journal.session1Id !== undefined && journal.session2Id !== undefined && snapshot !== undefined &&
      readbacks.length === 3 && s1Owner !== undefined && stale !== undefined && cleanup !== undefined &&
      (issuances.length === 2 || issuances.length === 3) &&
      (attempts.length === 4 || attempts.length === 5)) {
    const input: Sbx055AssessmentInput = {
      schemaVersion: 1,
      testId: SBX055_TEST_ID,
      runId: journal.runId,
      sandboxName: journal.sandboxName,
      scopeAndAliasPassed,
      installedWireAuditPassed: wireAuditPassed,
      sameOwnerOnly: true,
      expectedTimeoutMs: SBX055_SANDBOX_TIMEOUT_MS,
      lifecycle: {
        sandboxName: journal.sandboxName,
        s1SessionId: journal.session1Id,
        stopAttempted: journal.stopAttempted,
        stopped: journal.stopped,
        snapshotCaptured: true,
        snapshotId: snapshot.id,
        snapshotSourceSessionId: snapshot.sourceSessionId,
        snapshotStatus: snapshot.status,
        resumeAttempted: journal.resumeAttempted,
        resumedFromExactSnapshot: readbacks[1]!.sourceSnapshotId === snapshot.id,
        resumeResponseExact: readbacks[1]!.activeSessionId === journal.session2Id,
        sameNameResumed: readbacks[1]!.name === journal.sandboxName,
        s2SessionId: journal.session2Id,
        distinctSessionIds: journal.session1Id !== journal.session2Id,
      },
      markers: {
        s1Path: journal.marker1Path,
        s2Path: journal.marker2Path,
        s1FixtureSessionId: journal.session1Id,
        s2FixtureSessionId: journal.session2Id,
        s1Length: markerState.m1.length,
        s2Length: markerState.m2.length,
        distinctMarkerValues: !markerState.m1.equals(markerState.m2),
        s1FixedCommandShape: true,
        s1SessionUnchanged: markerState.s1WrittenAfterCreate,
        s1WrittenAfterCreate: markerState.s1WrittenAfterCreate,
        s1Mode0600: markerState.s1Mode0600,
        s1LocalReadExactBeforeStop: markerState.s1LocalReadExactBeforeStop,
        s2AbsentBeforeStop: markerState.s2AbsentBeforeStop,
        s1PersistedAfterResume: markerState.s1PersistedAfterResume,
        s1Mode0600AfterResume: markerState.s1Mode0600AfterResume,
        s1LocalReadExactAfterResume: markerState.s1LocalReadExactAfterResume,
        s2FixedCommandShape: true,
        s2SessionUnchanged: markerState.s2WrittenOnlyAfterResume,
        s2WrittenOnlyAfterResume: markerState.s2WrittenOnlyAfterResume,
        s2Mode0600: markerState.s2Mode0600,
        s2LocalReadExactAfterResume: markerState.s2LocalReadExactAfterResume,
        rawMarkersRetained: false,
        rawMarkerDigestsRetained: false,
      },
      readbacks: readbacks as [Sbx055SandboxReadback, Sbx055SandboxReadback, Sbx055SandboxReadback],
      issuances: issuances.map((entry) => entry.evidence),
      attempts,
      chronology,
      allIssuedTokensDistinct: new Set(issuances.map((entry) => entry.token)).size === issuances.length,
      staleTokenUnusedBeforeAttack: staleUnusedBeforeAttack,
      staleCredentialPairUsedUnchanged: stalePairUsedUnchanged,
      s1OwnerTokenUseCount: (tokenUses.get(s1Owner.token) ?? 0) as 1,
      staleTokenUseCount: (tokenUses.get(stale.token) ?? 0) as 1,
      s2OwnerTokenUseCount: (s2Owner === undefined ? 0 : tokenUses.get(s2Owner.token) ?? 0) as 0 | 1,
      requestAudit: {
        allAllowlisted: requestAudit.allAllowlisted,
        contiguous: requestAudit.contiguous,
        completed: requestAudit.completed,
        withinRateLimit: requestAudit.withinRateLimit,
        interactiveCredentialRequests: requestAudit.interactiveCredentialRequests,
        websocketConnections: requestAudit.websocketConnections,
        unexpectedRequests: requestAudit.unexpectedRequests,
      },
      cleanup,
      rawInteractiveTokensRetained: false,
      rawInteractiveTokenDigestsRetained: false,
      rawInteractiveUrlsRetained: false,
      rawInteractiveUrlDigestsRetained: false,
      queryBearingUrlsRetained: false,
      commandOutputRetained: false,
      commandOutputDigestsRetained: false,
      websocketErrorsRetained: false,
    };
    assessment = assessSbx055(input);
  }

  const artifact = {
    schemaVersion: 1,
    testId: SBX055_TEST_ID,
    runId: journal.runId,
    recoveryOnly: false,
    startedAt: journal.startedAt,
    completedAt: new Date().toISOString(),
    runtime: { sandboxSdk: `@vercel/sandbox@${SDK_VERSION}`, webSocket: `ws@${SBX055_WS_VERSION}` },
    identity: { alias: SBX055_ALIAS, teamId: SBX055_TEAM, projectId: SBX055_PROJECT,
      method: identity?.method ?? "not-verified" },
    lifecycle: { sandboxName: journal.sandboxName, session1Id: journal.session1Id,
      session2Id: journal.session2Id, snapshotId: journal.snapshotId,
      snapshotSourceSessionId: snapshot?.sourceSessionId, snapshotStatus: snapshot?.status,
      stopAttempted: journal.stopAttempted, stopped: journal.stopped,
      resumeAttempted: journal.resumeAttempted },
    fixture: { marker1Path: journal.marker1Path, marker2Path: journal.marker2Path,
      marker1Length: markerState.m1.length, marker2Length: markerState.m2.length,
      requestedMode: "0600", markerProof: {
        distinctMarkerValues: !markerState.m1.equals(markerState.m2),
        s1WrittenAfterCreate: markerState.s1WrittenAfterCreate,
        s1Mode0600: markerState.s1Mode0600,
        s1LocalReadExactBeforeStop: markerState.s1LocalReadExactBeforeStop,
        s2AbsentBeforeStop: markerState.s2AbsentBeforeStop,
        s1PersistedAfterResume: markerState.s1PersistedAfterResume,
        s1Mode0600AfterResume: markerState.s1Mode0600AfterResume,
        s1LocalReadExactAfterResume: markerState.s1LocalReadExactAfterResume,
        s2WrittenOnlyAfterResume: markerState.s2WrittenOnlyAfterResume,
        s2Mode0600: markerState.s2Mode0600,
        s2LocalReadExactAfterResume: markerState.s2LocalReadExactAfterResume,
      }, readbacks },
    issuances: issuances.map((entry) => entry.evidence),
    attempts,
    capabilityUseProof: {
      s1OwnerTokenUseCount: s1Owner === undefined ? 0 : tokenUses.get(s1Owner.token) ?? 0,
      staleTokenUnusedBeforeAttack: staleUnusedBeforeAttack,
      staleTokenUseCount: stale === undefined ? 0 : tokenUses.get(stale.token) ?? 0,
      staleCredentialPairUsedUnchanged: stalePairUsedUnchanged,
      s2OwnerTokenUseCount: s2Owner === undefined ? 0 : tokenUses.get(s2Owner.token) ?? 0,
    },
    chronology,
    requestAudit,
    assessment,
    cleanup,
    failure,
    retention: {
      rawMarkers: false, rawMarkerDigests: false, rawInteractiveTokens: false,
      rawInteractiveTokenDigests: false, rawInteractiveUrls: false,
      rawInteractiveUrlDigests: false, queryBearingUrls: false, commandOutput: false,
      commandOutputDigests: false, websocketErrors: false,
    },
  };
  assertSbx055EvidenceHasNoRawCapabilities(artifact, forbidden);
  await writeSbx055PrivateArtifact(sbx055ArtifactPath(journal.runId), artifact);
  markerState.m1.fill(0);
  markerState.m2.fill(0);
  console.log(JSON.stringify({ testId: SBX055_TEST_ID, runId: journal.runId, assessment,
    cleanup, artifactPath: sbx055ArtifactPath(journal.runId) }, null, 2));
  process.exitCode = assessment.verdict === "candidate" ? 2 : assessment.verdict === "pass" ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error: unknown) => {
    console.error(JSON.stringify({ testId: SBX055_TEST_ID, outcome: "error",
      error: error instanceof Error ? error.name : "unknown" }));
    process.exitCode = 1;
  });
}
