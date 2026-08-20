import "dotenv/config";

import { createHash, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import {
  APIError,
  Sandbox,
  type NetworkPolicy,
} from "@vercel/sandbox";
import { verifyEligibleAliasToken } from "../eligible-alias-identity.js";
import {
  SBX047_ELIGIBLE_ALIAS,
  SBX047_ELIGIBLE_PROJECT,
  SBX047_ELIGIBLE_TEAM,
  acquireSbx047Lock,
  createSbx047Journal,
  loadSbx047Config,
  readSbx047Journal,
  removeSbx047Journal,
  sbx047ArtifactPath,
  writeSbx047Journal,
  writeSbx047PrivateJson,
  type Sbx047ExplicitConfig,
  type Sbx047JournalResource,
  type Sbx047RecoveryJournal,
  type Sbx047ResourceRole,
} from "./safety.js";
import {
  SBX047_TEST_ID,
  SBX047_TRANSFORM_HEADER,
  assessSbx047,
  assertSbx047EvidenceHasNoRawSecrets,
  deriveSbx047OperationId,
  deriveSbx047Receipt,
  deriveSbx047SecretProof,
  parseSbx047GuestResult,
  parseSbx047ObserverSnapshot,
  sha256Sbx047,
  type Sbx047Assessment,
  type Sbx047GuestResult,
  type Sbx047ObserverEvent,
  type Sbx047ObserverSnapshot,
  type Sbx047RequestKind,
} from "./verdict.js";

const SDK_VERSION = "3.0.0";
const SESSION_TIMEOUT_MS = 180_000;
const CONTROL_TIMEOUT_MS = 30_000;
const COMMAND_TIMEOUT_MS = 12_000;
const EXTERNAL_INTERVAL_MS = 250;
const MAX_EXTERNAL_REQUESTS = 120;
const REMOTE_GUEST_PATH = "/tmp/sbx-047/network-request.mjs";
export const SBX047_GUEST_SHA256 =
  "003b471a2f872969677879c0173d0950a9587621c29380e1df34643b3aa0c5f2";

const SOURCE_PUBLIC_CASE = "source-public-control";
const SOURCE_ACTION_CASE = "source-protected-control";
const INHERITANCE_PUBLIC_CASE = "inheritance-public-control";
const TARGET_PUBLIC_CASE = "target-deny-all-public";
const TARGET_ACTION_CASE = "target-deny-all-protected";

interface ExternalAuditRecord {
  sequence: number;
  startedAt: string;
  completedAt?: string;
  class: "vercel-control" | "identity" | "observer-health" | "guest-request";
  method: string;
  pathname: string;
  status?: number;
}

interface ExternalGate {
  fetch: typeof fetch;
  reserveGuest(pathname: string): Promise<ExternalAuditRecord>;
  completeGuest(record: ExternalAuditRecord): void;
  summary(): {
    count: number;
    contiguous: boolean;
    completed: boolean;
    withinRateLimit: boolean;
    minimumStartIntervalMs?: number;
    records: ExternalAuditRecord[];
  };
}

interface PolicyReadback {
  role: Sbx047ResourceRole;
  name: string;
  sessionId: string;
  independentSessionId: string;
  status: string;
  independentStatus: string;
  exactName: boolean;
  exactTags: boolean;
  independentTags: boolean;
  exactPersistence: boolean;
  exactRoutes: boolean;
  independentRoutes: boolean;
  sandboxPolicy: "source-transform" | "deny-all" | "other";
  currentSessionPolicy: "source-transform" | "deny-all" | "other";
  independentSandboxPolicy: "source-transform" | "deny-all" | "other";
  independentCurrentSessionPolicy: "source-transform" | "deny-all" | "other";
  sourceSnapshotId?: string;
  independentSourceSnapshotId?: string;
}

interface GuestExecution {
  result: Sbx047GuestResult;
  sessionId: string;
  sessionIdUnchanged: boolean;
}

interface SafeFailure {
  kind: "api" | "other";
  status?: number;
  code?: string;
  message?: string;
}

interface CleanupRecord {
  role: Sbx047ResourceRole;
  name: string;
  attempted: boolean;
  exactProvenance: boolean;
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  firstAbsence: boolean;
  secondAbsence: boolean;
  errors: SafeFailure[];
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function exactKeys(value: object, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function exactTags(actual: Record<string, string> | undefined, expected: Record<string, string>): boolean {
  if (actual === undefined) return false;
  return exactKeys(actual, Object.keys(expected)) &&
    Object.entries(expected).every(([key, value]) => actual[key] === value);
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

export function sbx047SourcePolicy(hostname: string, credential: string): NetworkPolicy {
  return {
    allow: {
      [hostname]: [{ transform: [{ headers: { [SBX047_TRANSFORM_HEADER]: credential } }] }],
    },
  };
}

export function sbx047TargetForkOverride(): { networkPolicy: "deny-all" } {
  return { networkPolicy: "deny-all" };
}

export function sbx047InheritanceForkOverride(): Record<string, never> {
  return {};
}

export function exactSbx047SourcePolicy(
  value: unknown,
  hostname: string,
  credential: string,
): boolean {
  const policy = object(value);
  if (policy === undefined || !exactKeys(policy, ["allow"])) return false;
  const allow = object(policy.allow);
  if (allow === undefined || !exactKeys(allow, [hostname]) || !Array.isArray(allow[hostname]) ||
      allow[hostname].length !== 1) return false;
  const rule = object(allow[hostname][0]);
  if (rule === undefined || !exactKeys(rule, ["transform"]) || !Array.isArray(rule.transform) ||
      rule.transform.length !== 1) return false;
  const transform = object(rule.transform[0]);
  const headers = object(transform?.headers);
  return transform !== undefined && headers !== undefined && exactKeys(transform, ["headers"]) &&
    exactKeys(headers, [SBX047_TRANSFORM_HEADER]) &&
    headers[SBX047_TRANSFORM_HEADER] === credential;
}

export function exactSbx047SourceSandboxProjection(
  value: unknown,
  hostname: string,
): boolean {
  const policy = object(value);
  return policy !== undefined && exactKeys(policy, ["allow"]) &&
    Array.isArray(policy.allow) && policy.allow.length === 1 && policy.allow[0] === hostname;
}

export function exactSbx047DenyAll(value: unknown): value is "deny-all" {
  return value === "deny-all";
}

function policyClass(
  value: unknown,
  hostname: string,
  credential: string,
  allowSandboxProjection = false,
):
"source-transform" | "deny-all" | "other" {
  return (exactSbx047SourcePolicy(value, hostname, credential) ||
    exactSbx047SourcePolicy(value, hostname, "<redacted>") ||
    (allowSandboxProjection && exactSbx047SourceSandboxProjection(value, hostname)))
    ? "source-transform"
    : exactSbx047DenyAll(value) ? "deny-all" : "other";
}

function requestUrl(input: string | URL | Request): URL {
  return new URL(input instanceof Request ? input.url : input.toString());
}

export function createSbx047ExternalGate(
  publicOrigin: URL,
  rawFetch: typeof fetch = globalThis.fetch,
  now: () => number = Date.now,
  wait: (milliseconds: number) => Promise<void> = async (milliseconds) => {
    await delay(milliseconds);
  },
): ExternalGate {
  const records: ExternalAuditRecord[] = [];
  let lastStart = 0;
  let queue = Promise.resolve();

  const reserve = async (
    requestClass: ExternalAuditRecord["class"],
    method: string,
    pathname: string,
  ): Promise<ExternalAuditRecord> => {
    if (records.length >= MAX_EXTERNAL_REQUESTS) {
      throw new Error("SBX-047 exceeded its fixed external request budget");
    }
    let release!: () => void;
    const previous = queue;
    queue = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    try {
      const remaining = EXTERNAL_INTERVAL_MS - (now() - lastStart);
      if (remaining > 0) await wait(remaining);
      lastStart = now();
      const record: ExternalAuditRecord = {
        sequence: records.length + 1,
        startedAt: new Date(lastStart).toISOString(),
        class: requestClass,
        method: method.toUpperCase(),
        pathname,
      };
      records.push(record);
      return record;
    } finally {
      release();
    }
  };

  const gatedFetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = requestUrl(input);
    const method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
    let requestClass: ExternalAuditRecord["class"];
    if (url.origin === "https://vercel.com" && /^\/api\/v[23]\/sandboxes(?:\/|$)/u.test(url.pathname)) {
      if (url.searchParams.get("teamId") !== SBX047_ELIGIBLE_TEAM ||
          (url.searchParams.has("projectId") &&
            url.searchParams.get("projectId") !== SBX047_ELIGIBLE_PROJECT) ||
          (url.searchParams.has("project") &&
            url.searchParams.get("project") !== SBX047_ELIGIBLE_PROJECT)) {
        throw new Error("SBX-047 gate rejected a Sandbox request outside the exact team/project");
      }
      const rootCollection = /^\/api\/v[23]\/sandboxes$/u.test(url.pathname);
      if (rootCollection && method === "POST") {
        let requestBody: unknown;
        try {
          requestBody = JSON.parse(String(init?.body));
        } catch {
          throw new Error("SBX-047 gate rejected an unparseable Sandbox create body");
        }
        if (object(requestBody)?.projectId !== SBX047_ELIGIBLE_PROJECT) {
          throw new Error("SBX-047 gate rejected a Sandbox create outside the exact project");
        }
      } else if (rootCollection && method === "GET") {
        if (url.searchParams.get("project") !== SBX047_ELIGIBLE_PROJECT) {
          throw new Error("SBX-047 gate rejected a Sandbox list outside the exact project");
        }
      } else if (/\/fork$/u.test(url.pathname) ||
          /^\/api\/v2\/sandboxes\/(?!sessions(?:\/|$)|snapshots(?:\/|$))[^/]+$/u.test(url.pathname)) {
        if (url.searchParams.get("projectId") !== SBX047_ELIGIBLE_PROJECT) {
          throw new Error("SBX-047 gate rejected a named Sandbox operation outside the exact project");
        }
      }
      requestClass = "vercel-control";
    } else if (url.origin === "https://api.vercel.com" && (
      url.pathname === "/v2/user" ||
      url.pathname === `/v2/teams/${SBX047_ELIGIBLE_TEAM}` ||
      url.pathname === `/v9/projects/${SBX047_ELIGIBLE_PROJECT}`
    )) {
      if (url.pathname.includes("/projects/") &&
          url.searchParams.get("teamId") !== SBX047_ELIGIBLE_TEAM) {
        throw new Error("SBX-047 gate rejected an identity project request outside the team");
      }
      requestClass = "identity";
    } else if (url.origin === publicOrigin.origin && url.pathname === "/healthz" &&
        url.search === "" && method === "GET") {
      requestClass = "observer-health";
    } else {
      throw new Error("SBX-047 gate rejected a non-allowlisted external URL");
    }
    if (url.protocol !== "https:" || url.username !== "" || url.password !== "" || url.hash !== "") {
      throw new Error("SBX-047 gate rejected unsafe URL components");
    }
    const record = await reserve(requestClass, method, url.pathname);
    try {
      const response = await rawFetch(input, { ...init, redirect: "error" });
      record.status = response.status;
      record.completedAt = new Date(now()).toISOString();
      return response;
    } catch (error) {
      record.completedAt = new Date(now()).toISOString();
      throw error;
    }
  }) as typeof fetch;

  return {
    fetch: gatedFetch,
    reserveGuest: (pathname) => reserve("guest-request", "GET", pathname),
    completeGuest(record): void { record.completedAt = new Date(now()).toISOString(); },
    summary() {
      const starts = records.map((record) => Date.parse(record.startedAt));
      const intervals = starts.slice(1).map((start, index) => start - starts[index]!);
      const minimum = intervals.length === 0 ? undefined : Math.min(...intervals);
      return {
        count: records.length,
        contiguous: records.every((record, index) => record.sequence === index + 1),
        completed: records.every((record) => record.completedAt !== undefined),
        withinRateLimit: minimum === undefined || minimum >= EXTERNAL_INTERVAL_MS - 2,
        ...(minimum === undefined ? {} : { minimumStartIntervalMs: minimum }),
        records: records.map((record) => ({ ...record })),
      };
    },
  };
}

function sandboxCredentials(config: Sbx047ExplicitConfig, gatedFetch: typeof fetch) {
  return {
    token: config.token,
    teamId: config.teamId,
    projectId: config.projectId,
    fetch: gatedFetch,
  };
}

function resource(journal: Sbx047RecoveryJournal, role: Sbx047ResourceRole): Sbx047JournalResource {
  const match = journal.resources.find((entry) => entry.role === role);
  if (match === undefined) throw new Error(`SBX-047 journal lacks ${role}`);
  return match;
}

function sourceCreateParams(
  config: Sbx047ExplicitConfig,
  gatedFetch: typeof fetch,
  plan: Sbx047JournalResource,
  policy: NetworkPolicy,
): Parameters<typeof Sandbox.create>[0] {
  return {
    ...sandboxCredentials(config, gatedFetch),
    name: plan.name,
    persistent: false,
    timeout: SESSION_TIMEOUT_MS,
    ports: [],
    networkPolicy: policy,
    tags: plan.tags,
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  };
}

export function inheritanceForkParams(
  config: Pick<Sbx047ExplicitConfig, "token" | "teamId" | "projectId">,
  gatedFetch: typeof fetch,
  sourceName: string,
  plan: Pick<Sbx047JournalResource, "name" | "tags">,
): Parameters<typeof Sandbox.fork>[0] {
  return {
    ...config,
    fetch: gatedFetch,
    sourceSandbox: sourceName,
    name: plan.name,
    persistent: false,
    timeout: SESSION_TIMEOUT_MS,
    ports: [],
    tags: plan.tags,
    ...sbx047InheritanceForkOverride(),
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  };
}

export function targetForkParams(
  config: Pick<Sbx047ExplicitConfig, "token" | "teamId" | "projectId">,
  gatedFetch: typeof fetch,
  sourceName: string,
  plan: Pick<Sbx047JournalResource, "name" | "tags">,
): Parameters<typeof Sandbox.fork>[0] {
  return {
    ...config,
    fetch: gatedFetch,
    sourceSandbox: sourceName,
    name: plan.name,
    persistent: false,
    timeout: SESSION_TIMEOUT_MS,
    ports: [],
    tags: plan.tags,
    ...sbx047TargetForkOverride(),
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  };
}

function expectedPolicy(
  role: Sbx047ResourceRole,
  value: unknown,
  hostname: string,
  credential: string,
): boolean {
  return role === "target"
    ? exactSbx047DenyAll(value)
    : exactSbx047SourcePolicy(value, hostname, credential) ||
      exactSbx047SourcePolicy(value, hostname, "<redacted>");
}

function exactCreateResponse(
  sandbox: Sandbox,
  plan: Sbx047JournalResource,
  hostname: string,
  credential: string,
): boolean {
  const sandboxPolicyExact = plan.role === "target"
    ? exactSbx047DenyAll(sandbox.networkPolicy)
    : exactSbx047SourcePolicy(sandbox.networkPolicy, hostname, credential) ||
      exactSbx047SourcePolicy(sandbox.networkPolicy, hostname, "<redacted>") ||
      exactSbx047SourceSandboxProjection(sandbox.networkPolicy, hostname);
  return sandbox.name === plan.name && exactTags(sandbox.tags, plan.tags) &&
    sandbox.persistent === false && sandbox.status === "running" && sandbox.routes.length === 0 &&
    sandboxPolicyExact &&
    expectedPolicy(plan.role, sandbox.currentSession().networkPolicy, hostname, credential);
}

async function readbackPolicy(
  config: Sbx047ExplicitConfig,
  gatedFetch: typeof fetch,
  active: Sandbox,
  plan: Sbx047JournalResource,
  hostname: string,
  credential: string,
): Promise<PolicyReadback> {
  const independent = await Sandbox.get({
    ...sandboxCredentials(config, gatedFetch),
    name: plan.name,
    resume: false,
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  });
  return {
    role: plan.role,
    name: active.name,
    sessionId: active.currentSession().sessionId,
    independentSessionId: independent.currentSession().sessionId,
    status: active.status,
    independentStatus: independent.status,
    exactName: active.name === plan.name && independent.name === plan.name,
    exactTags: exactTags(active.tags, plan.tags),
    independentTags: exactTags(independent.tags, plan.tags),
    exactPersistence: !active.persistent && !independent.persistent,
    exactRoutes: active.routes.length === 0,
    independentRoutes: independent.routes.length === 0,
    sandboxPolicy: policyClass(active.networkPolicy, hostname, credential, true),
    currentSessionPolicy: policyClass(active.currentSession().networkPolicy, hostname, credential),
    independentSandboxPolicy: policyClass(independent.networkPolicy, hostname, credential, true),
    independentCurrentSessionPolicy: policyClass(
      independent.currentSession().networkPolicy,
      hostname,
      credential,
    ),
    ...(active.sourceSnapshotId === undefined ? {} : { sourceSnapshotId: active.sourceSnapshotId }),
    ...(independent.sourceSnapshotId === undefined
      ? {}
      : { independentSourceSnapshotId: independent.sourceSnapshotId }),
  };
}

function readbackExact(readback: PolicyReadback): boolean {
  const expected = readback.role === "target" ? "deny-all" : "source-transform";
  return readback.exactName && readback.exactTags && readback.independentTags &&
    readback.exactPersistence && readback.exactRoutes && readback.independentRoutes &&
    readback.sessionId === readback.independentSessionId && readback.status === "running" &&
    readback.independentStatus === "running" && readback.sandboxPolicy === expected &&
    readback.currentSessionPolicy === expected && readback.independentSandboxPolicy === expected &&
    readback.independentCurrentSessionPolicy === expected;
}

export function fixedSbx047GuestCommand(
  publicOrigin: string,
  runId: string,
  kind: Sbx047RequestKind,
  caseId: string,
  canary: string,
) {
  return {
    cmd: "node" as const,
    args: [REMOTE_GUEST_PATH, kind, publicOrigin, runId, caseId, canary],
    timeoutMs: COMMAND_TIMEOUT_MS,
  };
}

async function writeFixedGuest(sandbox: Sandbox, guestSource: string): Promise<void> {
  await sandbox.currentSession().writeFiles(
    [{ path: REMOTE_GUEST_PATH, content: guestSource, mode: 0o700 }],
    { signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) },
  );
}

async function runGuest(
  sandbox: Sandbox,
  gate: ExternalGate,
  config: Sbx047ExplicitConfig,
  runId: string,
  kind: Sbx047RequestKind,
  caseId: string,
  canary: string,
  forbidden: readonly string[],
): Promise<GuestExecution> {
  const session = sandbox.currentSession();
  const sessionId = session.sessionId;
  const pathname = `/v1/sbx047/${kind}/${runId}/${caseId}/${canary}`;
  const guestAudit = await gate.reserveGuest(pathname);
  try {
    const command = await session.runCommand({
      ...fixedSbx047GuestCommand(config.publicOrigin.origin, runId, kind, caseId, canary),
      signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
    });
    const [stdout, stderr] = await Promise.all([command.stdout(), command.stderr()]);
    if (forbidden.some((secret) => secret.length > 0 &&
        (stdout.includes(secret) || stderr.includes(secret)))) {
      throw new Error("SBX-047 guest output contained raw controller-only material");
    }
    return {
      result: parseSbx047GuestResult(stdout, stderr, command.exitCode, kind, caseId),
      sessionId,
      sessionIdUnchanged: sandbox.currentSession().sessionId === sessionId,
    };
  } finally {
    gate.completeGuest(guestAudit);
  }
}

async function boundedJson(response: Response, maximum = 128 * 1024): Promise<unknown> {
  const bytes = Buffer.from(await response.arrayBuffer());
  try {
    if (bytes.length > maximum) throw new Error("SBX-047 response exceeded its byte limit");
    return JSON.parse(bytes.toString("utf8"));
  } finally {
    bytes.fill(0);
  }
}

function adminUrl(config: Sbx047ExplicitConfig, runId: string, stage = false): URL {
  return new URL(`/v1/sbx047/admin/runs/${runId}${stage ? "/stage" : ""}`, config.adminOrigin);
}

async function adminRequest(
  config: Sbx047ExplicitConfig,
  runId: string,
  method: "GET" | "PUT" | "DELETE",
  stage: boolean,
  body?: unknown,
): Promise<Response> {
  return fetch(adminUrl(config, runId, stage), {
    method,
    headers: {
      authorization: `Bearer ${config.adminKey}`,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    redirect: "error",
    signal: AbortSignal.timeout(5_000),
  });
}

async function observerSnapshot(
  config: Sbx047ExplicitConfig,
  runId: string,
): Promise<Sbx047ObserverSnapshot> {
  const response = await adminRequest(config, runId, "GET", false);
  if (response.status !== 200) throw new Error(`SBX-047 observer snapshot returned ${response.status}`);
  return parseSbx047ObserverSnapshot(await boundedJson(response));
}

async function configureObserver(
  config: Sbx047ExplicitConfig,
  runId: string,
  canary: string,
  transformHeaderSha256: string,
): Promise<void> {
  const response = await adminRequest(config, runId, "PUT", false, {
    runId,
    publicHost: config.publicOrigin.hostname,
    canary,
    transformHeaderSha256,
  });
  if (response.status !== 204) throw new Error(`SBX-047 observer configuration returned ${response.status}`);
}

async function stageSecret(
  config: Sbx047ExplicitConfig,
  runId: string,
  secret: string,
): Promise<void> {
  const response = await adminRequest(config, runId, "PUT", true, { runId, secret });
  if (response.status !== 204) throw new Error(`SBX-047 observer secret staging returned ${response.status}`);
}

async function unstageSecret(config: Sbx047ExplicitConfig, runId: string): Promise<void> {
  const response = await adminRequest(config, runId, "DELETE", true);
  if (response.status !== 204) throw new Error(`SBX-047 observer secret deletion returned ${response.status}`);
}

async function deleteObserverConfiguration(
  config: Sbx047ExplicitConfig,
  runId: string,
): Promise<{ deleteAttempted: true; deleted: boolean; absenceConfirmed: boolean; error?: SafeFailure }> {
  try {
    const response = await adminRequest(config, runId, "DELETE", false);
    const deleted = response.status === 204 || response.status === 404;
    const confirmation = await adminRequest(config, runId, "GET", false);
    return {
      deleteAttempted: true,
      deleted,
      absenceConfirmed: confirmation.status === 404,
    };
  } catch (error) {
    return {
      deleteAttempted: true,
      deleted: false,
      absenceConfirmed: false,
      error: safeFailure(error, [config.token, config.adminKey]),
    };
  }
}

async function observerHealth(config: Sbx047ExplicitConfig, gatedFetch: typeof fetch): Promise<boolean> {
  const response = await gatedFetch(new URL("/healthz", config.publicOrigin), {
    method: "GET",
    signal: AbortSignal.timeout(5_000),
  });
  if (response.status !== 200) return false;
  const parsed = await boundedJson(response, 4_096);
  return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) &&
    exactKeys(parsed, ["ok", "service", "hostMatched"]) &&
    (parsed as Record<string, unknown>).ok === true &&
    (parsed as Record<string, unknown>).service === "sbx047-receiver" &&
    (parsed as Record<string, unknown>).hostMatched === true;
}

function exactControlEvent(
  event: Sbx047ObserverEvent | undefined,
  sequence: number,
  kind: Sbx047RequestKind,
  caseId: string,
  transformSha: string,
  receipt: string,
  operationId?: string,
  secretProof?: string,
): boolean {
  return event !== undefined && event.sequence === sequence && event.kind === kind &&
    event.caseId === caseId && event.method === "GET" && event.hostHeaderLines === 1 &&
    event.hostHeaderValues === 1 && event.hostMatched && event.canaryMatched &&
    event.transformHeaderLines === 1 && event.transformHeaderValues === 1 &&
    event.transformHeaderSha256 === transformSha && event.transformCommitmentMatched &&
    event.responseStatus === 200 && event.receipt === receipt &&
    event.operationId === operationId && event.secretProof === secretProof;
}

function exactGuestSuccess(
  result: Sbx047GuestResult,
  receipt: string,
  operationId: string | null,
  secretProof: string | null,
): boolean {
  return result.receivedResponse && result.statusCode === 200 && result.receipt === receipt &&
    result.operationId === operationId && result.secretProof === secretProof && result.error === null;
}

function apiCode(error: APIError<unknown>): string | undefined {
  const root = object(error.json);
  const nested = object(root?.error);
  const code = nested?.code;
  return typeof code === "string" && code.length <= 128 ? code : undefined;
}

function notFound(error: unknown): boolean {
  return error instanceof APIError && (error.response.status === 404 || error.response.status === 410);
}

function safeFailure(error: unknown, forbidden: readonly string[]): SafeFailure {
  if (error instanceof APIError) {
    const code = apiCode(error);
    return {
      kind: "api",
      status: error.response.status,
      ...(code === undefined ? {} : { code }),
    };
  }
  let message = error instanceof Error ? error.message : String(error);
  for (const secret of forbidden) {
    if (secret.length > 0) message = message.split(secret).join("[REDACTED]");
  }
  return { kind: "other", message: message.slice(0, 512) };
}

async function exactList(
  config: Sbx047ExplicitConfig,
  gatedFetch: typeof fetch,
  plan: Sbx047JournalResource,
) {
  const page = await Sandbox.list({
    ...sandboxCredentials(config, gatedFetch),
    namePrefix: plan.name,
    sortBy: "name",
    sortOrder: "asc",
    limit: 10,
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  });
  if (page.pagination.next !== null) throw new Error("SBX-047 exact cleanup list required pagination");
  return page.sandboxes.filter((item) => item.name === plan.name);
}

async function cleanupOne(
  config: Sbx047ExplicitConfig,
  gatedFetch: typeof fetch,
  plan: Sbx047JournalResource,
  forbidden: readonly string[],
): Promise<CleanupRecord> {
  const record: CleanupRecord = {
    role: plan.role,
    name: plan.name,
    attempted: plan.createAttempted,
    exactProvenance: !plan.createAttempted,
    stopAttempted: false,
    stopped: !plan.createAttempted,
    deleteAttempted: false,
    deleted: !plan.createAttempted,
    firstAbsence: !plan.createAttempted,
    secondAbsence: !plan.createAttempted,
    errors: [],
  };
  if (!plan.createAttempted) return record;
  try {
    const matches = await exactList(config, gatedFetch, plan);
    if (matches.length > 1) throw new Error(`SBX-047 found multiple exact ${plan.role} names`);
    if (matches.length === 1) {
      const item = matches[0]!;
      if (!exactTags(item.tags, plan.tags) || item.persistent ||
          (plan.sessionId !== undefined && item.currentSessionId !== plan.sessionId)) {
        throw new Error(`SBX-047 refused cleanup of an unattributable ${plan.role}`);
      }
      const handle = await Sandbox.get({
        ...sandboxCredentials(config, gatedFetch),
        name: plan.name,
        resume: false,
        signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
      });
      if (handle.name !== plan.name || !exactTags(handle.tags, plan.tags) || handle.persistent ||
          (plan.sessionId !== undefined && handle.currentSession().sessionId !== plan.sessionId)) {
        throw new Error(`SBX-047 cleanup handle failed exact ${plan.role} provenance`);
      }
      record.exactProvenance = true;
      record.stopAttempted = true;
      try {
        await handle.stop({ signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
        record.stopped = true;
      } catch (error) {
        if (notFound(error)) record.stopped = true;
        else throw error;
      }
      record.deleteAttempted = true;
      try {
        await handle.delete({ signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
        record.deleted = true;
      } catch (error) {
        if (notFound(error)) record.deleted = true;
        else throw error;
      }
    } else {
      record.exactProvenance = true;
      record.stopped = true;
      record.deleted = true;
    }
    record.firstAbsence = (await exactList(config, gatedFetch, plan)).length === 0;
    await delay(750);
    record.secondAbsence = (await exactList(config, gatedFetch, plan)).length === 0;
    if (!record.firstAbsence || !record.secondAbsence) {
      throw new Error(`SBX-047 could not confirm ${plan.role} absence twice`);
    }
  } catch (error) {
    record.errors.push(safeFailure(error, forbidden));
  }
  return record;
}

async function cleanupAll(
  config: Sbx047ExplicitConfig,
  gatedFetch: typeof fetch,
  journal: Sbx047RecoveryJournal,
  forbidden: readonly string[],
): Promise<{ passed: boolean; resources: CleanupRecord[] }> {
  const resources: CleanupRecord[] = [];
  for (const role of ["target", "inheritance", "source"] as const) {
    resources.push(await cleanupOne(config, gatedFetch, resource(journal, role), forbidden));
  }
  return {
    passed: resources.every((item) => item.errors.length === 0 && item.exactProvenance &&
      item.stopped && item.deleted && item.firstAbsence && item.secondAbsence),
    resources,
  };
}

async function installedSdkAudit(): Promise<void> {
  const metadata = JSON.parse(await readFile(
    new URL("../../node_modules/@vercel/sandbox/package.json", import.meta.url),
    "utf8",
  )) as { version?: unknown };
  if (metadata.version !== SDK_VERSION) {
    throw new Error("SBX-047 requires a fresh SDK serialization audit for this installed version");
  }
}

async function markCreateAttempt(
  journal: Sbx047RecoveryJournal,
  plan: Sbx047JournalResource,
): Promise<void> {
  if (plan.createAttempted) throw new Error(`SBX-047 ${plan.role} create may be attempted once`);
  plan.createAttempted = true;
  await writeSbx047Journal(journal);
}

async function registerSession(
  journal: Sbx047RecoveryJournal,
  plan: Sbx047JournalResource,
  sandbox: Sandbox,
  hostname: string,
  credential: string,
): Promise<void> {
  if (!exactCreateResponse(sandbox, plan, hostname, credential)) {
    throw new Error(`SBX-047 ${plan.role} create/fork response failed exact validation`);
  }
  plan.sessionId = sandbox.currentSession().sessionId;
  await writeSbx047Journal(journal);
}

async function runRecovery(
  config: Sbx047ExplicitConfig,
  journal: Sbx047RecoveryJournal,
  gate: ExternalGate,
): Promise<void> {
  const forbidden = [config.token, config.adminKey];
  const identity = await verifyEligibleAliasToken({
    token: config.token,
    expectedEmail: config.expectedAlias,
    expectedTeamId: config.teamId,
    expectedProjectId: config.projectId,
    manualEmailConfirmation: config.expectedAlias,
    fetchImpl: gate.fetch,
  });
  const cleanup = await cleanupAll(config, gate.fetch, journal, forbidden);
  const observerCleanup = await deleteObserverConfiguration(config, journal.runId);
  const audit = gate.summary();
  const passed = cleanup.passed && observerCleanup.deleted && observerCleanup.absenceConfirmed &&
    audit.contiguous && audit.completed && audit.withinRateLimit;
  const artifact = {
    schemaVersion: 1,
    visibility: "private",
    testId: SBX047_TEST_ID,
    mode: "recovery",
    runId: journal.runId,
    identity,
    cleanup,
    observerCleanup,
    requestAudit: audit,
    passed,
    rawSecretsRetained: false,
  };
  assertSbx047EvidenceHasNoRawSecrets(artifact, forbidden);
  await writeSbx047PrivateJson(sbx047ArtifactPath(journal.runId), artifact);
  if (passed) await removeSbx047Journal(journal.runId);
  process.stdout.write(`${JSON.stringify({
    testId: SBX047_TEST_ID,
    runId: journal.runId,
    mode: "recovery",
    cleanupPassed: passed,
    evidencePath: sbx047ArtifactPath(journal.runId),
  })}\n`);
  if (!passed) process.exitCode = 1;
}

async function runNormal(
  config: Sbx047ExplicitConfig,
  journal: Sbx047RecoveryJournal,
  gate: ExternalGate,
  guestSource: string,
): Promise<void> {
  const runId = journal.runId;
  let transformCredential = `s47_${randomBytes(32).toString("base64url")}`;
  let sourceProtectedSecret = `s47_${randomBytes(32).toString("base64url")}`;
  let targetProtectedSecret = "";
  const canary = `c47_${randomBytes(24).toString("hex")}`;
  const transformSha = sha256Sbx047(transformCredential);
  const forbidden = [config.token, config.adminKey, transformCredential, sourceProtectedSecret];
  const sourcePlan = resource(journal, "source");
  const inheritancePlan = resource(journal, "inheritance");
  const targetPlan = resource(journal, "target");
  const sourcePolicy = sbx047SourcePolicy(config.publicOrigin.hostname, transformCredential);

  let identity: Awaited<ReturnType<typeof verifyEligibleAliasToken>> | undefined;
  let observerConfigured = false;
  let observerPreflightPassed = false;
  let observerPostflightPassed = false;
  let sourceInitial: PolicyReadback | undefined;
  let sourceFinal: PolicyReadback | undefined;
  let inheritanceInitial: PolicyReadback | undefined;
  let inheritanceFinal: PolicyReadback | undefined;
  let targetInitial: PolicyReadback | undefined;
  let targetFinal: PolicyReadback | undefined;
  let sourcePublic: GuestExecution | undefined;
  let sourceAction: GuestExecution | undefined;
  let inheritancePublic: GuestExecution | undefined;
  let targetPublic: GuestExecution | undefined;
  let targetAction: GuestExecution | undefined;
  let finalSnapshot: Sbx047ObserverSnapshot | undefined;
  let actionStagedAfterPublicSignal = false;
  let targetPublicReceipt = deriveSbx047Receipt(
    config.adminKey, runId, "public", TARGET_PUBLIC_CASE, canary, undefined,
  );
  let targetActionReceipt: string | undefined;
  let targetOperationId: string | undefined;
  let targetSecretProof: string | undefined;
  let sourcePublicControlPassed = false;
  let sourceActionControlPassed = false;
  let inheritancePublicControlPassed = false;
  let targetForkResponseDenyAll = false;
  let assessment: Sbx047Assessment | undefined;
  let setupFailure: SafeFailure | undefined;
  const startedAt = new Date().toISOString();

  try {
    identity = await verifyEligibleAliasToken({
      token: config.token,
      expectedEmail: config.expectedAlias,
      expectedTeamId: config.teamId,
      expectedProjectId: config.projectId,
      manualEmailConfirmation: config.expectedAlias,
      fetchImpl: gate.fetch,
    });
    await configureObserver(config, runId, canary, transformSha);
    observerConfigured = true;
    observerPreflightPassed = await observerHealth(config, gate.fetch);
    if (!observerPreflightPassed) throw new Error("SBX-047 observer public preflight failed");

    await markCreateAttempt(journal, sourcePlan);
    const source = await Sandbox.create(sourceCreateParams(config, gate.fetch, sourcePlan, sourcePolicy));
    await registerSession(journal, sourcePlan, source, config.publicOrigin.hostname, transformCredential);
    sourceInitial = await readbackPolicy(
      config, gate.fetch, source, sourcePlan, config.publicOrigin.hostname, transformCredential,
    );
    if (!readbackExact(sourceInitial)) throw new Error("SBX-047 source policy readback failed");
    await writeFixedGuest(source, guestSource);
    sourcePublic = await runGuest(
      source, gate, config, runId, "public", SOURCE_PUBLIC_CASE, canary, forbidden,
    );
    const sourcePublicReceipt = deriveSbx047Receipt(
      config.adminKey, runId, "public", SOURCE_PUBLIC_CASE, canary, transformSha,
    );
    let snapshot = await observerSnapshot(config, runId);
    sourcePublicControlPassed = snapshot.events.length === 1 && !snapshot.actionStaged &&
      sourcePublic.sessionId === sourceInitial.sessionId && sourcePublic.sessionIdUnchanged &&
      exactGuestSuccess(sourcePublic.result, sourcePublicReceipt, null, null) &&
      exactControlEvent(
        snapshot.events[0], 1, "public", SOURCE_PUBLIC_CASE, transformSha, sourcePublicReceipt,
      );
    if (!sourcePublicControlPassed) throw new Error("SBX-047 source transformed public control failed");

    await stageSecret(config, runId, sourceProtectedSecret);
    sourceAction = await runGuest(
      source, gate, config, runId, "action", SOURCE_ACTION_CASE, canary, forbidden,
    );
    const sourceSecretProof = deriveSbx047SecretProof(
      sourceProtectedSecret, runId, SOURCE_ACTION_CASE, canary,
    );
    const sourceOperationId = deriveSbx047OperationId(
      config.adminKey, runId, SOURCE_ACTION_CASE, sourceSecretProof,
    );
    const sourceActionReceipt = deriveSbx047Receipt(
      config.adminKey, runId, "action", SOURCE_ACTION_CASE, canary, transformSha,
    );
    snapshot = await observerSnapshot(config, runId);
    sourceActionControlPassed = snapshot.events.length === 2 && snapshot.actionStaged &&
      sourceAction.sessionId === sourceInitial.sessionId && sourceAction.sessionIdUnchanged &&
      exactGuestSuccess(sourceAction.result, sourceActionReceipt, sourceOperationId, sourceSecretProof) &&
      exactControlEvent(
        snapshot.events[1], 2, "action", SOURCE_ACTION_CASE, transformSha, sourceActionReceipt,
        sourceOperationId, sourceSecretProof,
      );
    if (!sourceActionControlPassed) throw new Error("SBX-047 source nonreflecting protected control failed");
    await unstageSecret(config, runId);
    snapshot = await observerSnapshot(config, runId);
    if (snapshot.actionStaged || snapshot.events.length !== 2) {
      throw new Error("SBX-047 source protected secret was not removed exactly");
    }

    await markCreateAttempt(journal, inheritancePlan);
    const inheritance = await Sandbox.fork(inheritanceForkParams(
      config, gate.fetch, sourcePlan.name, inheritancePlan,
    ));
    await registerSession(
      journal, inheritancePlan, inheritance, config.publicOrigin.hostname, transformCredential,
    );
    inheritanceInitial = await readbackPolicy(
      config, gate.fetch, inheritance, inheritancePlan, config.publicOrigin.hostname,
      transformCredential,
    );
    if (!readbackExact(inheritanceInitial) || inheritanceInitial.sessionId === sourceInitial.sessionId) {
      throw new Error("SBX-047 omitted-policy inheritance fork control failed exact readback");
    }
    await writeFixedGuest(inheritance, guestSource);
    inheritancePublic = await runGuest(
      inheritance, gate, config, runId, "public", INHERITANCE_PUBLIC_CASE, canary, forbidden,
    );
    const inheritanceReceipt = deriveSbx047Receipt(
      config.adminKey, runId, "public", INHERITANCE_PUBLIC_CASE, canary, transformSha,
    );
    snapshot = await observerSnapshot(config, runId);
    inheritancePublicControlPassed = snapshot.events.length === 3 && !snapshot.actionStaged &&
      inheritancePublic.sessionId === inheritanceInitial.sessionId &&
      inheritancePublic.sessionIdUnchanged &&
      exactGuestSuccess(inheritancePublic.result, inheritanceReceipt, null, null) &&
      exactControlEvent(
        snapshot.events[2], 3, "public", INHERITANCE_PUBLIC_CASE, transformSha,
        inheritanceReceipt,
      );
    if (!inheritancePublicControlPassed) {
      throw new Error("SBX-047 omitted-policy inheritance request control failed");
    }

    await markCreateAttempt(journal, targetPlan);
    const target = await Sandbox.fork(targetForkParams(config, gate.fetch, sourcePlan.name, targetPlan));
    targetForkResponseDenyAll = exactCreateResponse(
      target, targetPlan, config.publicOrigin.hostname, transformCredential,
    ) && exactSbx047DenyAll(target.networkPolicy) &&
      exactSbx047DenyAll(target.currentSession().networkPolicy);
    await registerSession(journal, targetPlan, target, config.publicOrigin.hostname, transformCredential);
    targetInitial = await readbackPolicy(
      config, gate.fetch, target, targetPlan, config.publicOrigin.hostname, transformCredential,
    );
    if (!targetForkResponseDenyAll || !readbackExact(targetInitial) ||
        targetInitial.sessionId === sourceInitial.sessionId ||
        targetInitial.sessionId === inheritanceInitial.sessionId) {
      throw new Error("SBX-047 explicit deny-all target fork failed exact response/readback");
    }
    await writeFixedGuest(target, guestSource);
    targetPublic = await runGuest(
      target, gate, config, runId, "public", TARGET_PUBLIC_CASE, canary, forbidden,
    );
    snapshot = await observerSnapshot(config, runId);
    const targetPublicEvent = snapshot.events.length === 4 ? snapshot.events[3] : undefined;
    if (targetPublicEvent?.caseId === TARGET_PUBLIC_CASE && targetPublicEvent.kind === "public" &&
        targetPublicEvent.receipt !== undefined) {
      targetPublicReceipt = deriveSbx047Receipt(
        config.adminKey,
        runId,
        "public",
        TARGET_PUBLIC_CASE,
        canary,
        targetPublicEvent.transformHeaderSha256,
      );
    }
    const exactPublicSignal = targetPublicEvent !== undefined &&
      targetPublicEvent.sequence === 4 && targetPublicEvent.receipt === targetPublicReceipt &&
      targetPublicEvent.method === "GET" && targetPublicEvent.hostMatched &&
      targetPublicEvent.canaryMatched && targetPublicEvent.responseStatus === 200 &&
      exactGuestSuccess(targetPublic.result, targetPublicReceipt, null, null);

    if (exactPublicSignal && targetPublicEvent.transformCommitmentMatched &&
        targetPublicEvent.transformHeaderSha256 === transformSha) {
      targetProtectedSecret = `s47_${randomBytes(32).toString("base64url")}`;
      forbidden.push(targetProtectedSecret);
      await stageSecret(config, runId, targetProtectedSecret);
      actionStagedAfterPublicSignal = true;
      targetSecretProof = deriveSbx047SecretProof(
        targetProtectedSecret, runId, TARGET_ACTION_CASE, canary,
      );
      targetOperationId = deriveSbx047OperationId(
        config.adminKey, runId, TARGET_ACTION_CASE, targetSecretProof,
      );
      targetActionReceipt = deriveSbx047Receipt(
        config.adminKey, runId, "action", TARGET_ACTION_CASE, canary, transformSha,
      );
      targetAction = await runGuest(
        target, gate, config, runId, "action", TARGET_ACTION_CASE, canary, forbidden,
      );
    }
    finalSnapshot = await observerSnapshot(config, runId);
    targetFinal = await readbackPolicy(
      config, gate.fetch, target, targetPlan, config.publicOrigin.hostname, transformCredential,
    );
    sourceFinal = await readbackPolicy(
      config, gate.fetch, source, sourcePlan, config.publicOrigin.hostname, transformCredential,
    );
    inheritanceFinal = await readbackPolicy(
      config, gate.fetch, inheritance, inheritancePlan, config.publicOrigin.hostname,
      transformCredential,
    );
    observerPostflightPassed = await observerHealth(config, gate.fetch);
    const audit = gate.summary();
    const distinctNames = new Set(journal.resources.map((entry) => entry.name)).size === 3;
    const sessions = [sourceInitial.sessionId, inheritanceInitial.sessionId, targetInitial.sessionId];
    const distinctSessions = new Set(sessions).size === 3;
    assessment = assessSbx047({
      controls: {
        exactEligibleAlias: identity.email === SBX047_ELIGIBLE_ALIAS &&
          identity.teamId === SBX047_ELIGIBLE_TEAM && identity.projectId === SBX047_ELIGIBLE_PROJECT,
        sdk300ForkOverrideSerialized: true,
        sourcePolicyReadbacksExact: readbackExact(sourceInitial) && readbackExact(sourceFinal) &&
          sourceInitial.sessionId === sourceFinal.sessionId,
        sourcePublicControlPassed,
        sourceNonreflectingActionPassed: sourceActionControlPassed,
        inheritancePolicyReadbacksExact: readbackExact(inheritanceInitial) &&
          readbackExact(inheritanceFinal) &&
          inheritanceInitial.sessionId === inheritanceFinal.sessionId,
        inheritancePublicControlPassed,
        targetForkResponseDenyAll,
        targetActiveDenyAll: readbackExact(targetInitial) && readbackExact(targetFinal) &&
          targetInitial.sandboxPolicy === "deny-all" && targetFinal.sandboxPolicy === "deny-all",
        targetIndependentDenyAll: targetInitial.independentSandboxPolicy === "deny-all" &&
          targetFinal.independentSandboxPolicy === "deny-all",
        targetCurrentSessionDenyAll: targetInitial.currentSessionPolicy === "deny-all" &&
          targetFinal.currentSessionPolicy === "deny-all",
        targetIndependentCurrentSessionDenyAll:
          targetInitial.independentCurrentSessionPolicy === "deny-all" &&
          targetFinal.independentCurrentSessionPolicy === "deny-all",
        exactDistinctNamesAndSessions: distinctNames && distinctSessions &&
          targetInitial.sessionId === targetFinal.sessionId,
        fixedGuestProgram: sha256(guestSource) === SBX047_GUEST_SHA256,
        guestSessionAttributionPassed: sourcePublic.sessionIdUnchanged &&
          sourceAction.sessionIdUnchanged && inheritancePublic.sessionIdUnchanged &&
          targetPublic.sessionIdUnchanged &&
          (targetAction === undefined || targetAction.sessionIdUnchanged),
        observerPreflightPassed,
        observerPostflightPassed,
        sequentialNoRetrySchedule: audit.contiguous && audit.completed && audit.withinRateLimit,
      },
      expected: {
        runId,
        sourcePublicCaseId: SOURCE_PUBLIC_CASE,
        sourceActionCaseId: SOURCE_ACTION_CASE,
        inheritancePublicCaseId: INHERITANCE_PUBLIC_CASE,
        publicCaseId: TARGET_PUBLIC_CASE,
        actionCaseId: TARGET_ACTION_CASE,
        canary,
        publicReceipt: targetPublicReceipt,
        ...(targetActionReceipt === undefined ? {} : { actionReceipt: targetActionReceipt }),
        ...(targetOperationId === undefined ? {} : { operationId: targetOperationId }),
        ...(targetSecretProof === undefined ? {} : { secretProof: targetSecretProof }),
        transformHeaderSha256: transformSha,
      },
      targetPublic: targetPublic.result,
      ...(targetAction === undefined ? {} : { targetAction: targetAction.result }),
      observerEvents: finalSnapshot.events,
      actionStagedAfterPublicSignal,
    });
  } catch (error) {
    setupFailure = safeFailure(error, forbidden);
    try {
      finalSnapshot = observerConfigured ? await observerSnapshot(config, runId) : undefined;
    } catch {
      // The setup failure already records the primary bounded diagnostic.
    }
  }

  const cleanup = await cleanupAll(config, gate.fetch, journal, forbidden);
  const observerCleanup = await deleteObserverConfiguration(config, runId);
  const requestAudit = gate.summary();
  const cleanupPassed = cleanup.passed && observerCleanup.deleted &&
    observerCleanup.absenceConfirmed;
  const finalVerdict = cleanupPassed
    ? assessment?.verdict ?? "indeterminate"
    : "error";
  const artifact = {
    schemaVersion: 1,
    visibility: "private",
    testId: SBX047_TEST_ID,
    mode: "normal",
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    hypothesis: "explicit fork networkPolicy deny-all must replace the copied source transform policy",
    distinctFrom: ["SBX-025 lifecycle resume policy restore", "SBX-045 fork environment override"],
    sdkAudit: {
      installedVersion: SDK_VERSION,
      endpoint: "/v2/sandboxes/:source/fork",
      explicitDenyAllSerializedAsExactApiModeObjectOffline: true,
      inheritanceControlOmitsNetworkPolicyOffline: true,
      serverBoundaryRequiredForCandidate: true,
    },
    identity,
    resources: journal.resources.map((entry) => ({
      role: entry.role,
      name: entry.name,
      tags: entry.tags,
      sessionId: entry.sessionId,
    })),
    controls: {
      observerPreflightPassed,
      observerPostflightPassed,
      sourceInitial,
      sourceFinal,
      sourcePublicControlPassed,
      sourceActionControlPassed,
      inheritanceInitial,
      inheritanceFinal,
      inheritancePublicControlPassed,
      targetForkResponseDenyAll,
      targetInitial,
      targetFinal,
      fixedGuestProgramSha256: sha256(guestSource),
      rawGuestOutputRetained: false,
      rawPolicyCredentialRetained: false,
      targetSecretGeneratedOnlyAfterExactPublicSignal: targetProtectedSecret === "" ||
        actionStagedAfterPublicSignal,
    },
    attempts: {
      sourcePublic: sourcePublic?.result,
      sourceAction: sourceAction?.result,
      inheritancePublic: inheritancePublic?.result,
      targetPublic: targetPublic?.result,
      targetAction: targetAction?.result,
    },
    observer: finalSnapshot,
    stagedProtectedSecret: {
      targetStageOccurred: actionStagedAfterPublicSignal,
      rawSecretRetained: false,
      secretProof: targetSecretProof,
      operationId: targetOperationId,
    },
    assessment,
    setupFailure,
    cleanup,
    observerCleanup,
    requestAudit,
    cleanupPassed,
    verdict: finalVerdict,
    candidate: finalVerdict === "candidate",
    severity: finalVerdict === "candidate" ? assessment?.severity : "none",
    rawSecretsRetained: false,
    rawCommandOutputRetained: false,
  };
  assertSbx047EvidenceHasNoRawSecrets(artifact, forbidden);
  await writeSbx047PrivateJson(sbx047ArtifactPath(runId), artifact);
  if (cleanupPassed) await removeSbx047Journal(runId);

  transformCredential = "";
  sourceProtectedSecret = "";
  targetProtectedSecret = "";
  forbidden.fill("");
  process.stdout.write(`${JSON.stringify({
    schemaVersion: 1,
    testId: SBX047_TEST_ID,
    runId,
    outcome: finalVerdict,
    candidate: finalVerdict === "candidate",
    severity: finalVerdict === "candidate" ? assessment?.severity : "none",
    cleanupPassed,
    evidencePath: sbx047ArtifactPath(runId),
  })}\n`);
  if (finalVerdict === "candidate") process.exitCode = 10;
  else if (finalVerdict !== "pass") process.exitCode = 1;
}

async function main(): Promise<void> {
  const config = loadSbx047Config();
  await installedSdkAudit();
  const guestSource = await readFile(
    new URL("../../guest/sbx-047-network-request.mjs", import.meta.url),
    "utf8",
  );
  if (sha256(guestSource) !== SBX047_GUEST_SHA256) {
    throw new Error("SBX-047 fixed guest source digest did not match the reviewed program");
  }
  const journal = config.recoveryRunId === undefined
    ? createSbx047Journal()
    : await readSbx047Journal(config.recoveryRunId);
  const lock = await acquireSbx047Lock(journal.runId, config.recoveryRunId !== undefined);
  const gate = createSbx047ExternalGate(config.publicOrigin);
  try {
    if (config.recoveryRunId !== undefined) await runRecovery(config, journal, gate);
    else {
      await writeSbx047Journal(journal);
      await runNormal(config, journal, gate, guestSource);
    }
  } finally {
    await lock.release();
  }
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
