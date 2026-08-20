import "dotenv/config";

import {
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  mkdir,
  open,
  readFile,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { APIError, Sandbox, type Command } from "@vercel/sandbox";
import { verifyEligibleAliasToken, type EligibleAliasIdentityProof } from "../eligible-alias-identity.js";
import {
  assessSbx046,
  assertSbx046EvidenceExcludesRawValues,
  type Sbx046AssessmentInput,
  type Sbx046CreationEvidence,
  type Sbx046LedgerEvidence,
  type Sbx046LedgerEvent as VerdictLedgerEvent,
  type Sbx046ProbeEvidence as VerdictProbeEvidence,
  type Sbx046ReadbackPair as VerdictReadbackPair,
  type Sbx046RouteData as VerdictRouteData,
  type Sbx046ServiceResponseEvidence,
  type Sbx046StorageEvidence,
  type Sbx046UpdateEvidence,
} from "./verdict.js";

export const SBX046_TEST_ID = "SBX-046" as const;
export const SBX046_PORT = 3_000 as const;
export const SBX046_ALIAS_EMAIL = "swve@wearehackerone.com" as const;
export const SBX046_TEAM_ID = "team_n98ERpVwV7HqmWRudAyK8sXQ" as const;
export const SBX046_PROJECT_ID = "prj_CyyVykdN06Nrkla6KidZcecLgbCa" as const;
export const SBX046_SCOPE_CONFIRMATION =
  "I_OWN_THIS_ALIAS_SCOPE_AND_AUTHORIZE_ONE_PUBLISHED_PORT_REVOCATION_TEST" as const;
export const SBX046_LIVE_LOCK = "SBX-046-live-active.lock" as const;

const REMOTE_DIRECTORY = "/tmp/sbx-046";
const REMOTE_SERVICE_PATH = `${REMOTE_DIRECTORY}/published-port-revocation-service.mjs`;
const REMOTE_CONFIG_PATH = `${REMOTE_DIRECTORY}/service-config.json`;
const REMOTE_EVENT_LOG_PATH = `${REMOTE_DIRECTORY}/events.jsonl`;
const CONTROL_PLANE_TIMEOUT_MS = 30_000;
const EXTERNAL_TIMEOUT_MS = 5_000;
const MAXIMUM_RESPONSE_BYTES = 4_096;
const MAXIMUM_GUEST_OUTPUT_BYTES = 16_384;
const MAXIMUM_EVENT_LOG_BYTES = 64 * 1024;
const POST_UPDATE_OFFSETS_MS = [5_000, 30_000, 90_000] as const;
const REPOSITORY_ROOT = fileURLToPath(new URL("../../", import.meta.url));
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SANDBOX_NAME = /^sbx-046-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SESSION_ID = /^sbx_[A-Za-z0-9_-]{16,124}$/u;
const SUBDOMAIN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const CHALLENGE = /^ch46_[A-Za-z0-9_-]{24}$/u;
const SERVICE_INSTANCE = /^svc46_[A-Za-z0-9_-]{24}$/u;
const OPERATION_ID = /^op46_[A-Za-z0-9_-]{43}$/u;
const HMAC_KEY = /^[A-Za-z0-9_-]{43,86}$/u;

export type Sbx046CaseId =
  | "local-pre"
  | "external-pre"
  | "local-post-readback"
  | "external-post-5s"
  | "external-post-30s"
  | "external-post-90s"
  | "local-post-final";

export const SBX046_CASES = [
  "local-pre",
  "external-pre",
  "local-post-readback",
  "external-post-5s",
  "external-post-30s",
  "external-post-90s",
  "local-post-final",
] as const satisfies readonly Sbx046CaseId[];

export interface Sbx046Credentials {
  token: string;
  teamId: typeof SBX046_TEAM_ID;
  projectId: typeof SBX046_PROJECT_ID;
}

export interface Sbx046Route {
  url: string;
  subdomain: string;
  port: number;
}

export interface Sbx046DomainObservation {
  returned: boolean;
  value?: string | undefined;
  threw: boolean;
  errorClass?: string | undefined;
}

export interface Sbx046RouteReadback {
  stage: "initial" | "post-update" | "final";
  expectedName: string;
  expectedSessionId: string;
  activeName: string;
  independentName: string;
  activeSessionId: string;
  independentSessionId: string;
  activePersistent: boolean;
  independentPersistent: boolean;
  activeStatus: string;
  independentStatus: string;
  activeTags: Record<string, string> | undefined;
  independentTags: Record<string, string> | undefined;
  activeRoutes: Sbx046Route[];
  independentRoutes: Sbx046Route[];
  activeDomain: Sbx046DomainObservation;
  independentDomain: Sbx046DomainObservation;
  savedOrigin?: string | undefined;
}

export interface Sbx046CaseMaterial {
  challenge: string;
  operationId: string;
}

export interface Sbx046ExternalProbeEvidence {
  schemaVersion: 1;
  testId: typeof SBX046_TEST_ID;
  runId: string;
  sandboxName: string;
  sessionId: string;
  serviceInstanceId: string;
  caseId: Sbx046CaseId;
  challenge: string;
  expectedOperationId: string;
  startedAt: string;
  completedAt: string;
  requestOrigin: string;
  requestPath: string;
  method: "POST";
  attempts: 1;
  requests: 1;
  retries: 0;
  redirectsFollowed: 0;
  agentDisabled: true;
  rejectUnauthorized: true;
  tcpConnected: boolean;
  tlsEstablished: boolean;
  tlsAuthorized: boolean;
  responseReceived: boolean;
  responseBytes: number;
  responseStatusCode?: number | undefined;
  responseServiceHeader?: string | undefined;
  responseOperationId?: string | undefined;
  responseExact: boolean;
  serviceHeaderValidated: boolean;
  cacheControlValidated: boolean;
  connectionCloseValidated: boolean;
  contentTypeValidated: boolean;
  contentLengthValidated: boolean;
  serviceResponse?: Sbx046ServiceResponseEvidence | undefined;
  remoteAddress?: string | undefined;
  remotePort?: number | undefined;
  errorCode?: string | undefined;
  errorErrno?: number | undefined;
  errorSyscall?: string | undefined;
  timedOut: boolean;
  durationMs: number;
  rawResponseRetained: false;
}

export interface Sbx046RecoveryJournal {
  schemaVersion: 1;
  testId: typeof SBX046_TEST_ID;
  runId: string;
  sandboxName: string;
  tags: Record<string, string>;
  persistent: false;
  startedAt: string;
  createAttemptedAt?: string | undefined;
  createdAt?: string | undefined;
  initialSessionId?: string | undefined;
  knownSessionIds: string[];
  keyStaged: boolean;
  keyOverwritten: boolean;
  keyDeleted: boolean;
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  absenceChecks: number;
  listAbsenceConfirmed: boolean;
  completed: boolean;
}

export interface Sbx046CleanupEvidence {
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  absenceChecks: number;
  exactNameAbsent: boolean;
  prefixListAbsent: boolean;
  guestConfigDeleted: boolean;
  guestLedgerDeleted: boolean;
  keyOverwritten: boolean;
  keyDeleted: boolean;
  liveLockReleased: boolean;
  errors: string[];
}

interface SandboxReadbackLike {
  name: string;
  persistent: boolean;
  status: string;
  tags?: Record<string, string> | undefined;
  routes: Array<{ url: string; subdomain: string; port: number }>;
  currentSession(): { sessionId: string };
  domain(port: number): string;
}

export interface ExternalProbeRequestInput {
  origin: string;
  runId: string;
  sandboxName: string;
  sessionId: string;
  serviceInstanceId: string;
  caseId: Sbx046CaseId;
  challenge: string;
  expectedOperationId: string;
  timeoutMs?: number | undefined;
}

interface RawExternalResponse {
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function text(value: unknown, maximum = 1_024): string | undefined {
  return typeof value === "string" && value.length <= maximum ? value : undefined;
}

function finiteNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((entry, index) => entry === wanted[index]);
}

function safeError(error: unknown, forbidden: readonly string[]): string {
  let value = error instanceof Error ? error.message : String(error);
  for (const secret of forbidden) {
    if (secret.length > 0) value = value.split(secret).join("[REDACTED]");
  }
  return value.replace(/[\0\r\n]/gu, " ").slice(0, 1_000);
}

function exactString(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  return timingSafeEqual(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function domainObservation(handle: SandboxReadbackLike): Sbx046DomainObservation {
  try {
    return { returned: true, value: handle.domain(SBX046_PORT), threw: false };
  } catch (error) {
    return {
      returned: false,
      threw: true,
      errorClass: error instanceof Error ? error.constructor.name.slice(0, 80) : "unknown",
    };
  }
}

function copyRoutes(routes: SandboxReadbackLike["routes"]): Sbx046Route[] {
  return routes.map((route) => ({ url: route.url, subdomain: route.subdomain, port: route.port }));
}

export function explicitCredentials(environment: NodeJS.ProcessEnv = process.env): Sbx046Credentials {
  const token = required(environment, "VERCEL_TOKEN");
  if (environment.VERCEL_TEAM_ID !== SBX046_TEAM_ID || environment.VERCEL_PROJECT_ID !== SBX046_PROJECT_ID) {
    throw new Error("SBX-046 requires the exact verified HackerOne-alias team and project");
  }
  return { token, teamId: SBX046_TEAM_ID, projectId: SBX046_PROJECT_ID };
}

export function requireScopeConfirmation(environment: NodeJS.ProcessEnv = process.env): void {
  if (environment.SBX046_SCOPE_CONFIRMATION !== SBX046_SCOPE_CONFIRMATION) {
    throw new Error(`SBX046_SCOPE_CONFIRMATION must equal ${SBX046_SCOPE_CONFIRMATION}`);
  }
}

export function requireStrictControllerTlsEnvironment(environment: NodeJS.ProcessEnv = process.env): void {
  const forbidden = [
    "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF", "OPENSSL_MODULES", "SSL_CERT_DIR", "SSL_CERT_FILE",
  ];
  if (environment.NODE_TLS_REJECT_UNAUTHORIZED === "0" ||
      (environment.NODE_OPTIONS !== undefined && environment.NODE_OPTIONS.trim() !== "") ||
      forbidden.some((name) => environment[name] !== undefined)) {
    throw new Error("SBX-046 refuses controller TLS trust overrides or runtime injection");
  }
}

export function buildSandboxName(runId: string): string {
  if (!UUID_V4.test(runId)) throw new Error("SBX-046 run ID must be a canonical UUIDv4");
  return `sbx-046-${runId}`;
}

export function exactTags(actual: Record<string, string> | undefined, expected: Record<string, string>): boolean {
  if (!actual) return false;
  const actualKeys = Object.keys(actual).sort();
  const expectedKeys = Object.keys(expected).sort();
  return actualKeys.length === expectedKeys.length &&
    actualKeys.every((key, index) => key === expectedKeys[index] && actual[key] === expected[key]);
}

export function canonicalRouteOrigin(route: Sbx046Route): string | undefined {
  if (route.port !== SBX046_PORT || !SUBDOMAIN.test(route.subdomain)) return undefined;
  const expected = `https://${route.subdomain}.vercel.run`;
  if (route.url !== expected) return undefined;
  try {
    const parsed = new URL(route.url);
    if (parsed.protocol !== "https:" || parsed.hostname !== `${route.subdomain}.vercel.run` ||
        parsed.port || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) {
      return undefined;
    }
  } catch {
    return undefined;
  }
  return expected;
}

export function captureRouteReadback(input: {
  stage: Sbx046RouteReadback["stage"];
  expectedName: string;
  expectedSessionId: string;
  expectedTags: Record<string, string>;
  active: SandboxReadbackLike;
  independent: SandboxReadbackLike;
  savedOrigin?: string | undefined;
}): Sbx046RouteReadback {
  return {
    stage: input.stage,
    expectedName: input.expectedName,
    expectedSessionId: input.expectedSessionId,
    activeName: input.active.name,
    independentName: input.independent.name,
    activeSessionId: input.active.currentSession().sessionId,
    independentSessionId: input.independent.currentSession().sessionId,
    activePersistent: input.active.persistent,
    independentPersistent: input.independent.persistent,
    activeStatus: input.active.status,
    independentStatus: input.independent.status,
    activeTags: input.active.tags,
    independentTags: input.independent.tags,
    activeRoutes: copyRoutes(input.active.routes),
    independentRoutes: copyRoutes(input.independent.routes),
    activeDomain: domainObservation(input.active),
    independentDomain: domainObservation(input.independent),
    ...(input.savedOrigin === undefined ? {} : { savedOrigin: input.savedOrigin }),
  };
}

function identityExact(proof: Sbx046RouteReadback, tags: Record<string, string>): boolean {
  return proof.activeName === proof.expectedName && proof.independentName === proof.expectedName &&
    proof.activeSessionId === proof.expectedSessionId && proof.independentSessionId === proof.expectedSessionId &&
    proof.activePersistent === false && proof.independentPersistent === false &&
    proof.activeStatus === "running" && proof.independentStatus === "running" &&
    exactTags(proof.activeTags, tags) && exactTags(proof.independentTags, tags);
}

export function exactInitialRouteReadback(
  proof: Sbx046RouteReadback,
  tags: Record<string, string>,
): proof is Sbx046RouteReadback & { savedOrigin: string } {
  if (proof.stage !== "initial" || !identityExact(proof, tags) || proof.activeRoutes.length !== 1 ||
      proof.independentRoutes.length !== 1) return false;
  const activeOrigin = canonicalRouteOrigin(proof.activeRoutes[0]!);
  const independentOrigin = canonicalRouteOrigin(proof.independentRoutes[0]!);
  return activeOrigin !== undefined && activeOrigin === independentOrigin && proof.savedOrigin === activeOrigin &&
    proof.activeDomain.returned && !proof.activeDomain.threw && proof.activeDomain.value === activeOrigin &&
    proof.independentDomain.returned && !proof.independentDomain.threw &&
    proof.independentDomain.value === activeOrigin;
}

export function exactClearedRouteReadback(
  proof: Sbx046RouteReadback,
  tags: Record<string, string>,
  savedOrigin: string,
): boolean {
  return (proof.stage === "post-update" || proof.stage === "final") && identityExact(proof, tags) &&
    proof.savedOrigin === savedOrigin && proof.activeRoutes.length === 0 && proof.independentRoutes.length === 0 &&
    proof.activeDomain.threw && !proof.activeDomain.returned && proof.activeDomain.value === undefined &&
    proof.independentDomain.threw && !proof.independentDomain.returned && proof.independentDomain.value === undefined;
}

export function buildPortRemovalUpdate(): { ports: number[] } {
  return { ports: [] };
}

export function deriveOperationId(input: {
  hmacKey: string;
  runId: string;
  sandboxName: string;
  sessionId: string;
  serviceInstanceId: string;
  caseId: Sbx046CaseId;
  challenge: string;
}): string {
  if (!HMAC_KEY.test(input.hmacKey)) throw new Error("SBX-046 HMAC key is not canonical base64url");
  const decoded = Buffer.from(input.hmacKey, "base64url");
  if (decoded.length < 32 || decoded.length > 64 || decoded.toString("base64url") !== input.hmacKey) {
    throw new Error("SBX-046 HMAC key must canonically encode 32-64 bytes");
  }
  const message = JSON.stringify([
    SBX046_TEST_ID,
    input.runId,
    input.sandboxName,
    input.sessionId,
    SBX046_PORT,
    input.serviceInstanceId,
    input.caseId,
    input.challenge,
  ]);
  try {
    return `op46_${createHmac("sha256", decoded).update(message).digest("base64url")}`;
  } finally {
    decoded.fill(0);
  }
}

export function buildCaseMaterial(input: {
  hmacKey: string;
  runId: string;
  sandboxName: string;
  sessionId: string;
  serviceInstanceId: string;
  randomBytesImpl?: typeof randomBytes | undefined;
}): Record<Sbx046CaseId, Sbx046CaseMaterial> {
  const random = input.randomBytesImpl ?? randomBytes;
  const entries = SBX046_CASES.map((caseId): [Sbx046CaseId, Sbx046CaseMaterial] => {
    const challenge = `ch46_${random(18).toString("base64url")}`;
    return [caseId, {
      challenge,
      operationId: deriveOperationId({ ...input, caseId, challenge }),
    }];
  });
  const output = Object.fromEntries(entries) as Record<Sbx046CaseId, Sbx046CaseMaterial>;
  const challenges = Object.values(output).map((item) => item.challenge);
  const operations = Object.values(output).map((item) => item.operationId);
  if (challenges.some((value) => !CHALLENGE.test(value)) || operations.some((value) => !OPERATION_ID.test(value)) ||
      new Set(challenges).size !== challenges.length || new Set(operations).size !== operations.length) {
    throw new Error("SBX-046 case material was noncanonical or nonunique");
  }
  return output;
}

export function buildServiceConfiguration(input: {
  hmacKey: string;
  runId: string;
  sandboxName: string;
  sessionId: string;
  serviceInstanceId: string;
  cases: Record<Sbx046CaseId, Sbx046CaseMaterial>;
}): Record<string, unknown> {
  return {
    schemaVersion: 1,
    testId: SBX046_TEST_ID,
    runId: input.runId,
    sandboxName: input.sandboxName,
    sessionId: input.sessionId,
    port: SBX046_PORT,
    serviceInstanceId: input.serviceInstanceId,
    hmacKey: input.hmacKey,
    eventLogPath: REMOTE_EVENT_LOG_PATH,
    cases: input.cases,
  };
}

export function buildLocalProbeConfiguration(input: {
  runId: string;
  sandboxName: string;
  sessionId: string;
  serviceInstanceId: string;
  caseId: Sbx046CaseId;
  material: Sbx046CaseMaterial;
}): Record<string, unknown> {
  return {
    schemaVersion: 1,
    testId: SBX046_TEST_ID,
    runId: input.runId,
    sandboxName: input.sandboxName,
    sessionId: input.sessionId,
    port: SBX046_PORT,
    serviceInstanceId: input.serviceInstanceId,
    baseUrl: `http://127.0.0.1:${SBX046_PORT}`,
    caseId: input.caseId,
    challenge: input.material.challenge,
    expectedOperationId: input.material.operationId,
    timeoutMs: 3_000,
  };
}

function expectedExternalBody(input: ExternalProbeRequestInput): Record<string, unknown> {
  return {
    schemaVersion: 1,
    testId: SBX046_TEST_ID,
    runId: input.runId,
    sandboxName: input.sandboxName,
    sessionId: input.sessionId,
    port: SBX046_PORT,
    serviceInstanceId: input.serviceInstanceId,
    caseId: input.caseId,
    challenge: input.challenge,
    operationId: input.expectedOperationId,
    requestBodyValidated: true,
    ok: true,
  };
}

function singleHeader(headers: RawExternalResponse["headers"], name: string): string | undefined {
  const value = headers[name];
  return typeof value === "string" ? value : Array.isArray(value) && value.length === 1 ? value[0] : undefined;
}

export function exactExternalResponse(input: ExternalProbeRequestInput, response: RawExternalResponse): {
  serviceHeader?: string | undefined;
  operationId?: string | undefined;
  cacheControlValidated: boolean;
  connectionCloseValidated: boolean;
  contentTypeValidated: boolean;
  contentLengthValidated: boolean;
  serviceResponse?: Sbx046ServiceResponseEvidence | undefined;
  exact: boolean;
} {
  const serviceHeader = singleHeader(response.headers, "x-sbx046-service");
  let parsed: unknown;
  try {
    parsed = JSON.parse(response.body.toString("utf8"));
  } catch {
    parsed = undefined;
  }
  const body = object(parsed);
  const expected = expectedExternalBody(input);
  const exactBody = body !== undefined && exactKeys(body, Object.keys(expected)) &&
    Object.entries(expected).every(([key, value]) => body[key] === value) &&
    response.body.toString("utf8") === `${JSON.stringify(expected)}\n`;
  const exact = response.statusCode === 200 && serviceHeader === "1" &&
    response.headers.location === undefined && response.headers["content-encoding"] === undefined && exactBody;
  const cacheControlValidated = singleHeader(response.headers, "cache-control") === "no-store";
  const connectionCloseValidated = singleHeader(response.headers, "connection") === "close";
  const contentTypeValidated = singleHeader(response.headers, "content-type") === "application/json; charset=utf-8";
  const contentLengthValidated = singleHeader(response.headers, "content-length") === String(response.body.length);
  return {
    ...(serviceHeader === undefined ? {} : { serviceHeader }),
    ...(body && typeof body.operationId === "string" ? { operationId: body.operationId } : {}),
    cacheControlValidated,
    connectionCloseValidated,
    contentTypeValidated,
    contentLengthValidated,
    ...(exact ? { serviceResponse: body as unknown as Sbx046ServiceResponseEvidence } : {}),
    exact: exact && cacheControlValidated && connectionCloseValidated && contentTypeValidated && contentLengthValidated,
  };
}

function canonicalSavedOrigin(value: string): URL {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.port || url.username || url.password || url.pathname !== "/" ||
      url.search || url.hash || !url.hostname.endsWith(".vercel.run")) {
    throw new Error("SBX-046 saved route must be a bare HTTPS *.vercel.run origin");
  }
  const subdomain = url.hostname.slice(0, -".vercel.run".length);
  if (!SUBDOMAIN.test(subdomain) || value !== `https://${subdomain}.vercel.run`) {
    throw new Error("SBX-046 saved route was not canonical");
  }
  return url;
}

export function conclusiveTerminalRouteDenial(probe: Sbx046ExternalProbeEvidence): boolean {
  let canonicalOrigin = false;
  try {
    canonicalSavedOrigin(probe.requestOrigin);
    canonicalOrigin = true;
  } catch {
    canonicalOrigin = false;
  }
  const invariant = probe.schemaVersion === 1 && probe.testId === SBX046_TEST_ID && canonicalOrigin &&
    probe.requestPath === "/v1/sbx046/canary" && probe.method === "POST" && !probe.rawResponseRetained &&
    probe.attempts === 1 && probe.requests === 1 && probe.retries === 0 && probe.redirectsFollowed === 0 &&
    probe.agentDisabled && probe.rejectUnauthorized && !probe.responseExact;
  if (!invariant) return false;
  const dnsWithdrawn = !probe.responseReceived && !probe.tcpConnected && !probe.tlsEstablished &&
    !probe.tlsAuthorized && !probe.timedOut && probe.errorCode === "ENOTFOUND" &&
    probe.errorSyscall === "getaddrinfo";
  const terminalEdgeStatus = probe.responseReceived && probe.tcpConnected && probe.tlsEstablished &&
    probe.tlsAuthorized && probe.responseServiceHeader === undefined && probe.responseOperationId === undefined &&
    probe.responseStatusCode !== undefined && [404, 410, 421].includes(probe.responseStatusCode);
  return dnsWithdrawn || terminalEdgeStatus;
}

export function recoverableSandboxIdentity(input: {
  expectedName: string;
  expectedTags: Record<string, string>;
  expectedPersistent: false;
  createAttemptedAt: string;
  candidate: {
    name: string;
    tags?: Record<string, string> | undefined;
    persistent: boolean;
    createdAt: number;
  };
  nowMs?: number | undefined;
}): boolean {
  const attempted = Date.parse(input.createAttemptedAt);
  const now = input.nowMs ?? Date.now();
  return Number.isFinite(attempted) && input.candidate.name === input.expectedName &&
    input.candidate.persistent === input.expectedPersistent && exactTags(input.candidate.tags, input.expectedTags) &&
    input.candidate.createdAt >= attempted - 5_000 && input.candidate.createdAt <= now + 5_000 &&
    input.candidate.createdAt <= attempted + 5 * 60_000;
}

export function newRecoveryJournal(input: {
  runId: string;
  sandboxName: string;
  tags: Record<string, string>;
  startedAt: string;
}): Sbx046RecoveryJournal {
  if (!UUID_V4.test(input.runId) || !SANDBOX_NAME.test(input.sandboxName) ||
      input.sandboxName !== buildSandboxName(input.runId)) {
    throw new Error("SBX-046 recovery journal identity was invalid");
  }
  return {
    schemaVersion: 1,
    testId: SBX046_TEST_ID,
    runId: input.runId,
    sandboxName: input.sandboxName,
    tags: { ...input.tags },
    persistent: false,
    startedAt: input.startedAt,
    knownSessionIds: [],
    keyStaged: false,
    keyOverwritten: false,
    keyDeleted: false,
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    absenceChecks: 0,
    listAbsenceConfirmed: false,
    completed: false,
  };
}

export function evidenceExcludesSecrets(value: unknown, forbidden: readonly string[]): boolean {
  const serialized = JSON.stringify(value);
  return forbidden.every((secret) => secret.length === 0 || !serialized.includes(secret));
}

export function safeToReleaseSbx046Lock(journal: Sbx046RecoveryJournal): boolean {
  return journal.createAttemptedAt === undefined || journal.completed;
}

export async function performExternalProbe(
  input: ExternalProbeRequestInput,
  requestImpl: typeof httpsRequest = httpsRequest,
): Promise<Sbx046ExternalProbeEvidence> {
  const origin = canonicalSavedOrigin(input.origin);
  const requestPath = "/v1/sbx046/canary";
  const body = Buffer.from(`public:${input.challenge}`, "utf8");
  const timeoutMs = input.timeoutMs ?? EXTERNAL_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 250 || timeoutMs > EXTERNAL_TIMEOUT_MS) {
    throw new Error("SBX-046 external probe timeout must be an integer from 250 through 5000ms");
  }
  const started = Date.now();
  const startedAt = new Date(started).toISOString();
  let tcpConnected = false;
  let tlsEstablished = false;
  let tlsAuthorized = false;
  let remoteAddress: string | undefined;
  let remotePort: number | undefined;
  let timedOut = false;
  let responseStarted = false;
  let observedResponseBytes = 0;

  return await new Promise((resolveProbe) => {
    let settled = false;
    let absoluteDeadline: NodeJS.Timeout | undefined;
    const settle = (partial: Partial<Sbx046ExternalProbeEvidence>): boolean => {
      if (settled) return false;
      settled = true;
      if (absoluteDeadline !== undefined) clearTimeout(absoluteDeadline);
      resolveProbe({
        schemaVersion: 1,
        testId: SBX046_TEST_ID,
        runId: input.runId,
        sandboxName: input.sandboxName,
        sessionId: input.sessionId,
        serviceInstanceId: input.serviceInstanceId,
        caseId: input.caseId,
        challenge: input.challenge,
        expectedOperationId: input.expectedOperationId,
        startedAt,
        completedAt: new Date().toISOString(),
        requestOrigin: input.origin,
        requestPath,
        method: "POST",
        attempts: 1,
        requests: 1,
        retries: 0,
        redirectsFollowed: 0,
        agentDisabled: true,
        rejectUnauthorized: true,
        tcpConnected,
        tlsEstablished,
        tlsAuthorized,
        responseReceived: responseStarted,
        responseBytes: observedResponseBytes,
        responseExact: false,
        serviceHeaderValidated: false,
        cacheControlValidated: false,
        connectionCloseValidated: false,
        contentTypeValidated: false,
        contentLengthValidated: false,
        ...(remoteAddress === undefined ? {} : { remoteAddress }),
        ...(remotePort === undefined ? {} : { remotePort }),
        timedOut,
        durationMs: Date.now() - started,
        rawResponseRetained: false,
        ...partial,
      });
      return true;
    };
    const request = requestImpl({
      protocol: "https:",
      hostname: origin.hostname,
      port: 443,
      method: "POST",
      path: requestPath,
      agent: false,
      rejectUnauthorized: true,
      headers: {
        "accept-encoding": "identity",
        "cache-control": "no-store",
        connection: "close",
        "content-type": "text/plain; charset=utf-8",
        "content-length": String(body.length),
        host: origin.host,
        "x-sbx046-run": input.runId,
        "x-sbx046-case": input.caseId,
        "x-sbx046-challenge": input.challenge,
      },
      setDefaultHeaders: false,
    }, (response) => {
      responseStarted = true;
      const chunks: Buffer[] = [];
      let responseEnded = false;
      const settleResponseFailure = (inputError: {
        code: string;
        errno?: number | undefined;
        syscall: string;
      }): void => {
        const won = settle({
          responseReceived: true,
          responseBytes: observedResponseBytes,
          errorCode: inputError.code.slice(0, 64),
          ...(inputError.errno === undefined ? {} : { errorErrno: inputError.errno }),
          errorSyscall: inputError.syscall.slice(0, 64),
        });
        if (won) request.destroy();
      };
      response.once("error", (error: NodeJS.ErrnoException) => {
        settleResponseFailure({
          code: typeof error.code === "string" ? error.code : "ERR_RESPONSE_STREAM",
          ...(typeof error.errno === "number" ? { errno: error.errno } : {}),
          syscall: typeof error.syscall === "string" ? error.syscall : "response",
        });
      });
      response.once("aborted", () => {
        settleResponseFailure({ code: "ERR_RESPONSE_ABORTED", syscall: "response" });
      });
      response.once("close", () => {
        if (!responseEnded) {
          settleResponseFailure({ code: "ERR_RESPONSE_PREMATURE_CLOSE", syscall: "response" });
        }
      });
      response.on("data", (chunk: Buffer | string) => {
        if (settled) return;
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        observedResponseBytes = Math.min(
          MAXIMUM_RESPONSE_BYTES + 1,
          observedResponseBytes + buffer.length,
        );
        if (observedResponseBytes > MAXIMUM_RESPONSE_BYTES) {
          settleResponseFailure({ code: "EMSGSIZE", syscall: "response" });
          response.destroy();
          return;
        }
        chunks.push(buffer);
      });
      response.on("end", () => {
        responseEnded = true;
        const raw: RawExternalResponse = {
          statusCode: response.statusCode ?? -1,
          headers: response.headers,
          body: Buffer.concat(chunks),
        };
        const exact = exactExternalResponse(input, raw);
        settle({
          responseReceived: true,
          responseBytes: observedResponseBytes,
          responseStatusCode: raw.statusCode,
          ...(exact.serviceHeader === undefined ? {} : { responseServiceHeader: exact.serviceHeader }),
          ...(exact.operationId === undefined ? {} : { responseOperationId: exact.operationId }),
          responseExact: exact.exact,
          serviceHeaderValidated: exact.serviceHeader === "1",
          cacheControlValidated: exact.cacheControlValidated,
          connectionCloseValidated: exact.connectionCloseValidated,
          contentTypeValidated: exact.contentTypeValidated,
          contentLengthValidated: exact.contentLengthValidated,
          ...(exact.serviceResponse === undefined ? {} : { serviceResponse: exact.serviceResponse }),
        });
      });
    });
    request.on("socket", (socket) => {
      socket.once("connect", () => {
        tcpConnected = true;
        remoteAddress = socket.remoteAddress;
        remotePort = socket.remotePort;
      });
      socket.once("secureConnect", () => {
        tlsEstablished = true;
        const tlsSocket = socket as typeof socket & { authorized?: boolean };
        tlsAuthorized = tlsSocket.authorized === true;
      });
    });
    request.once("error", (error: NodeJS.ErrnoException) => {
      settle({
        errorCode: typeof error.code === "string" ? error.code.slice(0, 64) : "UNKNOWN",
        ...(typeof error.errno === "number" ? { errorErrno: error.errno } : {}),
        ...(typeof error.syscall === "string" ? { errorSyscall: error.syscall.slice(0, 64) } : {}),
      });
    });
    absoluteDeadline = setTimeout(() => {
      timedOut = true;
      const won = settle({ errorCode: "ETIMEDOUT", errorSyscall: "request" });
      if (won) request.destroy();
    }, timeoutMs);
    request.end(body);
  });
}

export interface Sbx046LiveLock {
  handle: FileHandle;
  lockPath: string;
  journalPath: string;
  lockMode: number;
}

export async function acquireSbx046LiveLock(
  artifactsDirectory: string,
  journal: Sbx046RecoveryJournal,
): Promise<Sbx046LiveLock> {
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const lockPath = resolve(artifactsDirectory, SBX046_LIVE_LOCK);
  const journalPath = resolve(artifactsDirectory, `SBX-046-${journal.runId}-recovery.json`);
  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  const handle = await open(
    lockPath,
    fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | noFollow,
    0o600,
  );
  try {
    await handle.chmod(0o600);
    const metadata = await handle.stat();
    const lockMode = metadata.mode & 0o777;
    if (!metadata.isFile() || metadata.nlink !== 1 || lockMode !== 0o600) {
      throw new Error("SBX-046 live lock was not an exact mode-0600 single-link regular file");
    }
    await handle.writeFile(`${JSON.stringify({
      schemaVersion: 1,
      testId: SBX046_TEST_ID,
      runId: journal.runId,
      sandboxName: journal.sandboxName,
      startedAt: journal.startedAt,
      recoveryJournal: journalPath,
    })}\n`, "utf8");
    await handle.sync();
    await writePrivateJsonExclusive(journalPath, journal);
    return { handle, lockPath, journalPath, lockMode };
  } catch (error) {
    await handle.close().catch(() => undefined);
    await unlink(lockPath).catch(() => undefined);
    await unlink(journalPath).catch(() => undefined);
    throw error;
  }
}

async function writePrivateJsonExclusive(path: string, value: unknown): Promise<void> {
  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  const handle = await open(
    path,
    fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | noFollow,
    0o600,
  );
  try {
    await handle.chmod(0o600);
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    await handle.sync();
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.nlink !== 1 || (metadata.mode & 0o777) !== 0o600) {
      throw new Error(`${path} was not persisted as an exact mode-0600 single-link regular file`);
    }
  } finally {
    await handle.close();
  }
}

export async function persistSbx046RecoveryJournal(
  journalPath: string,
  journal: Sbx046RecoveryJournal,
): Promise<void> {
  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  const handle = await open(journalPath, fsConstants.O_WRONLY | fsConstants.O_TRUNC | noFollow);
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.nlink !== 1 || (metadata.mode & 0o777) !== 0o600) {
      throw new Error("SBX-046 recovery journal lost its exact mode-0600 regular-file invariant");
    }
    await handle.writeFile(`${JSON.stringify(journal, null, 2)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export async function releaseSbx046LiveLock(lock: Sbx046LiveLock): Promise<void> {
  await lock.handle.close();
  await unlink(lock.lockPath);
}

function isNotFound(error: unknown): boolean {
  return error instanceof APIError && error.response.status === 404;
}

function sandboxCredentials(credentials: Sbx046Credentials): Pick<Sbx046Credentials, "token" | "teamId" | "projectId"> {
  return credentials;
}

function routeData(value: readonly { url: string; subdomain: string; port: number }[]): VerdictRouteData[] {
  return value.map((route) => ({ url: route.url, subdomain: route.subdomain, port: route.port }));
}

function readbackRecord(
  stage: VerdictReadbackPair["active"]["stage"],
  source: VerdictReadbackPair["active"]["source"],
  handle: Sandbox,
): VerdictReadbackPair["active"] {
  let domainValue: string | null = null;
  let domainLookupThrew = false;
  try {
    domainValue = handle.domain(SBX046_PORT);
  } catch {
    domainLookupThrew = true;
  }
  return {
    stage,
    source,
    observedAt: new Date().toISOString(),
    sandboxName: handle.name,
    sessionId: handle.currentSession().sessionId,
    persistent: handle.persistent,
    status: handle.status,
    tags: { ...(handle.tags ?? {}) },
    routes: routeData(handle.routes),
    domainPort: SBX046_PORT,
    domainValue,
    domainLookupThrew,
  };
}

async function captureVerdictReadbacks(
  stage: VerdictReadbackPair["active"]["stage"],
  sandbox: Sandbox,
  credentials: Sbx046Credentials,
): Promise<{ pair: VerdictReadbackPair; denyAllPassed: boolean }> {
  const active = readbackRecord(stage, "active", sandbox);
  const activeDenyAllPassed = sandbox.networkPolicy === "deny-all" &&
    sandbox.currentSession().networkPolicy === "deny-all";
  const independent = await Sandbox.get({
    name: sandbox.name,
    resume: false,
    ...sandboxCredentials(credentials),
    signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
  });
  return {
    pair: {
      active,
      independent: readbackRecord(stage, "independent", independent),
    },
    denyAllPassed: activeDenyAllPassed && independent.networkPolicy === "deny-all" &&
      independent.currentSession().networkPolicy === "deny-all",
  };
}

function exactVerdictReadbackPair(
  pair: VerdictReadbackPair,
  stage: VerdictReadbackPair["active"]["stage"],
  expected: {
    sandboxName: string;
    sessionId: string;
    tags: Record<string, string>;
    route: VerdictRouteData;
  },
): boolean {
  return ([pair.active, pair.independent] as const).every((readback, index) => {
    const expectedSource = index === 0 ? "active" : "independent";
    const identity = readback.stage === stage && readback.source === expectedSource &&
      readback.sandboxName === expected.sandboxName && readback.sessionId === expected.sessionId &&
      readback.persistent === false && readback.status === "running" && exactTags(readback.tags, expected.tags) &&
      readback.domainPort === SBX046_PORT;
    if (!identity) return false;
    if (stage === "initial") {
      return readback.routes.length === 1 && readback.routes[0]?.url === expected.route.url &&
        readback.routes[0].subdomain === expected.route.subdomain && readback.routes[0].port === expected.route.port &&
        !readback.domainLookupThrew && readback.domainValue === expected.route.url;
    }
    return readback.routes.length === 0 && readback.domainLookupThrew && readback.domainValue === null;
  });
}

function externalVerdictProbe(
  raw: Sbx046ExternalProbeEvidence,
  revocationAcknowledgedAt?: string,
): VerdictProbeEvidence {
  const elapsed = revocationAcknowledgedAt === undefined
    ? null
    : Date.parse(raw.startedAt) - Date.parse(revocationAcknowledgedAt);
  const error = raw.errorCode === undefined
    ? undefined
    : {
        code: raw.errorCode,
        syscall: raw.errorSyscall ?? "unknown",
        ...(raw.errorErrno === undefined ? {} : { errno: raw.errorErrno }),
      };
  return {
    schemaVersion: 1,
    testId: SBX046_TEST_ID,
    runId: raw.runId,
    caseId: raw.caseId,
    origin: "saved-public-route",
    sandboxName: raw.sandboxName,
    sessionId: raw.sessionId,
    port: SBX046_PORT,
    serviceInstanceId: raw.serviceInstanceId,
    challenge: raw.challenge,
    expectedOperationId: raw.expectedOperationId,
    requestMethod: "POST",
    requestPath: raw.requestPath,
    requestOrigin: raw.requestOrigin,
    startedAt: raw.startedAt,
    completedAt: raw.completedAt,
    elapsedSinceRevocationAckMs: elapsed,
    requestAttempts: raw.attempts,
    connectionAttempts: raw.attempts,
    actualRequests: raw.requests,
    retries: raw.retries,
    redirectsFollowed: raw.redirectsFollowed,
    freshConnection: raw.agentDisabled,
    strictTlsVerification: raw.rejectUnauthorized,
    proxyConfigurationAccepted: false,
    tlsTrustConfigurationAccepted: false,
    rawConfigurationRetained: false,
    tcpConnected: raw.tcpConnected,
    tlsEstablished: raw.tlsEstablished,
    tlsAuthorized: raw.tlsAuthorized,
    responseReceived: raw.responseReceived,
    ...(raw.responseStatusCode === undefined ? {} : { responseStatusCode: raw.responseStatusCode }),
    ...(raw.responseReceived ? { responseBytes: raw.responseBytes } : {}),
    serviceHeaderValidated: raw.serviceHeaderValidated,
    cacheControlValidated: raw.cacheControlValidated,
    connectionCloseValidated: raw.connectionCloseValidated,
    contentTypeValidated: raw.contentTypeValidated,
    contentLengthValidated: raw.contentLengthValidated,
    ...(raw.serviceResponse === undefined ? {} : { serviceResponse: raw.serviceResponse }),
    timedOut: raw.timedOut,
    ...(error === undefined ? {} : { error }),
    durationMs: raw.durationMs,
    rawRequestBodyRetained: false,
    rawResponseBodyRetained: false,
  };
}

export function parseSbx046Ledger(raw: Buffer): Sbx046LedgerEvidence {
  if (raw.length === 0 || raw.length > MAXIMUM_EVENT_LOG_BYTES) {
    throw new Error("SBX-046 guest ledger was empty or exceeded its fixed bound");
  }
  const serialized = raw.toString("utf8");
  if (!serialized.endsWith("\n")) throw new Error("SBX-046 guest ledger lacked a final line terminator");
  const lines = serialized.slice(0, -1).split("\n");
  const expectedKeys = [
    "caseId", "challenge", "derivedDigestRetained", "method", "observedAt", "operationId", "path",
    "port", "rawHmacKeyRetained", "rawRequestBodyRetained", "requestBodyValidated", "runId",
    "sandboxName", "schemaVersion", "serviceInstanceId", "sessionId", "testId",
  ];
  const events = lines.map((line): VerdictLedgerEvent => {
    if (Buffer.byteLength(line, "utf8") > 2_048) throw new Error("SBX-046 guest ledger event exceeded its bound");
    let parsed: unknown;
    try { parsed = JSON.parse(line); } catch { throw new Error("SBX-046 guest ledger contained invalid JSON"); }
    const value = object(parsed);
    if (!value || !exactKeys(value, expectedKeys) || value.schemaVersion !== 1 || value.testId !== SBX046_TEST_ID ||
        !UUID_V4.test(text(value.runId, 36) ?? "") || !SANDBOX_NAME.test(text(value.sandboxName, 63) ?? "") ||
        !SESSION_ID.test(text(value.sessionId, 128) ?? "") || value.port !== SBX046_PORT ||
        !SERVICE_INSTANCE.test(text(value.serviceInstanceId, 30) ?? "") ||
        !SBX046_CASES.includes(value.caseId as Sbx046CaseId) || !CHALLENGE.test(text(value.challenge, 29) ?? "") ||
        !OPERATION_ID.test(text(value.operationId, 48) ?? "") ||
        typeof value.observedAt !== "string" || Number.isNaN(Date.parse(value.observedAt)) ||
        value.method !== "POST" || value.path !== "/v1/sbx046/canary" || value.requestBodyValidated !== true ||
        value.rawHmacKeyRetained !== false || value.rawRequestBodyRetained !== false ||
        value.derivedDigestRetained !== false) {
      throw new Error("SBX-046 guest ledger event had a noncanonical shape or value");
    }
    return value as unknown as VerdictLedgerEvent;
  });
  if (new Set(events.map((event) => event.caseId)).size !== events.length) {
    throw new Error("SBX-046 guest ledger contained a duplicate case event");
  }
  raw.fill(0);
  return {
    configured: true,
    events,
    rawHmacKeyRetained: false,
    hmacKeyDigestRetained: false,
    rawLogRetained: false,
  };
}

async function waitUntilOffset(acknowledgedAtMs: number, offsetMs: number): Promise<void> {
  const remaining = acknowledgedAtMs + offsetMs - Date.now();
  if (remaining > 0) {
    await delay(remaining, undefined, { signal: AbortSignal.timeout(remaining + 2_000) });
  }
}

async function readOneReadinessLine(command: Command): Promise<unknown> {
  const stream = command.logs({ signal: AbortSignal.timeout(10_000) });
  let stdout = "";
  let stderr = "";
  try {
    for await (const log of stream) {
      if (log.stream === "stdout") stdout += log.data;
      else stderr += log.data;
      if (Buffer.byteLength(stdout) > 4_096 || Buffer.byteLength(stderr) > 4_096) {
        throw new Error("SBX-046 service readiness output exceeded its bound");
      }
      if (stdout.includes("\n")) break;
    }
  } finally {
    stream.close();
  }
  if (stderr !== "" || !stdout.endsWith("\n") || stdout.indexOf("\n") !== stdout.length - 1) {
    throw new Error("SBX-046 service did not emit exactly one clean readiness line");
  }
  return JSON.parse(stdout.slice(0, -1));
}

function exactReadiness(value: unknown, expected: {
  runId: string;
  sandboxName: string;
  sessionId: string;
  serviceInstanceId: string;
}): boolean {
  const record = object(value);
  return record !== undefined && exactKeys(record, [
    "eventLogReady", "listenHost", "mode", "port", "rawConfigurationRetained", "rawHmacKeyRetained",
    "ready", "runId", "sandboxName", "schemaVersion", "serviceInstanceId", "sessionId", "testId",
  ]) && record.schemaVersion === 1 && record.testId === SBX046_TEST_ID && record.mode === "serve" &&
    record.ready === true && record.runId === expected.runId && record.sandboxName === expected.sandboxName &&
    record.sessionId === expected.sessionId && record.port === SBX046_PORT &&
    record.serviceInstanceId === expected.serviceInstanceId && record.listenHost === "0.0.0.0" &&
    record.eventLogReady === true && record.rawHmacKeyRetained === false && record.rawConfigurationRetained === false;
}

export function sanitizeLocalProbeEvidence(input: {
  value: unknown;
  commandExitCode: number;
  stdoutBytes: number;
  stderrBytes: number;
  startedAt: string;
  completedAt: string;
  elapsedSinceRevocationAckMs: number | null;
}): VerdictProbeEvidence {
  const value = object(input.value);
  const serviceResponse = object(value?.serviceResponse);
  const successKeys = [
    "actualRequests", "attemptCount", "cacheControlValidated", "caseId", "challenge", "connectionAttempts",
    "connectionCloseValidated", "contentLengthValidated", "contentTypeValidated", "durationMs", "expectedOperationId",
    "freshConnection", "method", "ok", "operationId", "port", "proxyConfigurationAccepted",
    "rawConfigurationRetained", "rawRequestBodyRetained", "rawResponseBodyRetained", "receiptValidated",
    "redirectsFollowed", "requestAttempts", "requestOrigin", "requestPath", "responseBytes", "responseReceived",
    "retryCount", "runId", "sandboxName", "schemaVersion", "serviceHeaderValidated", "serviceInstanceId",
    "serviceResponse", "sessionId", "statusCode", "strictTlsVerification", "targetBaseUrl", "targetPath", "tcpConnected",
    "testId", "timedOut", "timeoutMs", "tlsAuthorized", "tlsEstablished", "tlsTrustConfigurationAccepted",
  ];
  const requiredBooleans = [
    "cacheControlValidated", "connectionCloseValidated", "contentLengthValidated", "contentTypeValidated",
    "freshConnection", "ok", "proxyConfigurationAccepted", "rawConfigurationRetained", "rawRequestBodyRetained",
    "rawResponseBodyRetained", "receiptValidated", "responseReceived", "serviceHeaderValidated",
    "strictTlsVerification", "tcpConnected", "timedOut", "tlsAuthorized", "tlsEstablished",
    "tlsTrustConfigurationAccepted",
  ];
  const requiredNumbers = [
    "actualRequests", "attemptCount", "connectionAttempts", "durationMs", "port", "redirectsFollowed",
    "requestAttempts", "responseBytes", "retryCount", "statusCode", "timeoutMs",
  ];
  if (!value || !exactKeys(value, successKeys) || value.schemaVersion !== 1 || value.testId !== SBX046_TEST_ID ||
      typeof value.runId !== "string" || typeof value.caseId !== "string" ||
      !SBX046_CASES.includes(value.caseId as Sbx046CaseId) || value.method !== "POST" ||
      value.requestPath !== "/v1/sbx046/canary" || value.requestOrigin !== `http://127.0.0.1:${SBX046_PORT}` ||
      value.targetPath !== "/v1/sbx046/canary" || value.targetBaseUrl !== `http://127.0.0.1:${SBX046_PORT}` ||
      value.operationId !== value.expectedOperationId || value.receiptValidated !== true || value.ok !== true ||
      requiredBooleans.some((name) => typeof value[name] !== "boolean") ||
      requiredNumbers.some((name) => finiteNumber(value[name]) === undefined) || input.commandExitCode !== 0 ||
      input.stdoutBytes <= 0 || input.stdoutBytes > MAXIMUM_GUEST_OUTPUT_BYTES || input.stderrBytes !== 0) {
    throw new Error("SBX-046 local probe output lacked its exact identity");
  }
  if (serviceResponse && !exactKeys(serviceResponse, [
    "caseId", "challenge", "ok", "operationId", "port", "requestBodyValidated", "runId", "sandboxName",
    "schemaVersion", "serviceInstanceId", "sessionId", "testId",
  ])) throw new Error("SBX-046 local probe service response fields were not exact");
  const optionalError = text(value.errorCode, 64);
  return {
    schemaVersion: 1,
    testId: SBX046_TEST_ID,
    runId: value.runId,
    caseId: value.caseId as Sbx046CaseId,
    origin: "loopback",
    sandboxName: text(value.sandboxName, 63) ?? "invalid",
    sessionId: text(value.sessionId, 128) ?? "invalid",
    port: finiteNumber(value.port) ?? -1,
    serviceInstanceId: text(value.serviceInstanceId, 30) ?? "invalid",
    challenge: text(value.challenge, 29) ?? "invalid",
    expectedOperationId: text(value.expectedOperationId, 48) ?? "invalid",
    requestMethod: value.method === "POST" ? "POST" : "POST",
    requestPath: text(value.requestPath, 128) ?? "invalid",
    requestOrigin: text(value.requestOrigin, 128) ?? "invalid",
    startedAt: input.startedAt,
    completedAt: input.completedAt,
    elapsedSinceRevocationAckMs: input.elapsedSinceRevocationAckMs,
    requestAttempts: finiteNumber(value.requestAttempts) ?? -1,
    connectionAttempts: finiteNumber(value.connectionAttempts) ?? -1,
    actualRequests: finiteNumber(value.actualRequests) ?? -1,
    retries: finiteNumber(value.retryCount) ?? -1,
    redirectsFollowed: finiteNumber(value.redirectsFollowed) ?? -1,
    freshConnection: value.freshConnection === true,
    strictTlsVerification: value.strictTlsVerification === true,
    proxyConfigurationAccepted: value.proxyConfigurationAccepted === true,
    tlsTrustConfigurationAccepted: value.tlsTrustConfigurationAccepted === true,
    rawConfigurationRetained: value.rawConfigurationRetained === true,
    tcpConnected: value.tcpConnected === true,
    tlsEstablished: value.tlsEstablished === true,
    tlsAuthorized: value.tlsAuthorized === true,
    responseReceived: value.responseReceived === true,
    ...(finiteNumber(value.statusCode) === undefined ? {} : { responseStatusCode: finiteNumber(value.statusCode)! }),
    ...(finiteNumber(value.responseBytes) === undefined ? {} : { responseBytes: finiteNumber(value.responseBytes)! }),
    ...(typeof value.serviceHeaderValidated === "boolean"
      ? { serviceHeaderValidated: value.serviceHeaderValidated }
      : {}),
    ...(typeof value.cacheControlValidated === "boolean"
      ? { cacheControlValidated: value.cacheControlValidated }
      : {}),
    ...(typeof value.connectionCloseValidated === "boolean"
      ? { connectionCloseValidated: value.connectionCloseValidated }
      : {}),
    ...(typeof value.contentTypeValidated === "boolean"
      ? { contentTypeValidated: value.contentTypeValidated }
      : {}),
    ...(typeof value.contentLengthValidated === "boolean"
      ? { contentLengthValidated: value.contentLengthValidated }
      : {}),
    ...(serviceResponse === undefined ? {} : {
      serviceResponse: serviceResponse as unknown as Sbx046ServiceResponseEvidence,
    }),
    timedOut: value.timedOut === true,
    ...(optionalError === undefined ? {} : { error: { code: optionalError, syscall: "loopback" } }),
    durationMs: finiteNumber(value.durationMs) ?? -1,
    rawRequestBodyRetained: value.rawRequestBodyRetained === true,
    rawResponseBodyRetained: value.rawResponseBodyRetained === true,
  };
}

function localProbeSelfExact(
  probe: VerdictProbeEvidence,
  expected: {
    runId: string;
    sandboxName: string;
    sessionId: string;
    serviceInstanceId: string;
    caseId: Sbx046CaseId;
    material: Sbx046CaseMaterial;
  },
): boolean {
  const response = probe.serviceResponse;
  return probe.schemaVersion === 1 && probe.testId === SBX046_TEST_ID && probe.runId === expected.runId &&
    probe.caseId === expected.caseId && probe.origin === "loopback" && probe.sandboxName === expected.sandboxName &&
    probe.sessionId === expected.sessionId && probe.port === SBX046_PORT &&
    probe.serviceInstanceId === expected.serviceInstanceId && probe.challenge === expected.material.challenge &&
    probe.expectedOperationId === expected.material.operationId && probe.requestMethod === "POST" &&
    probe.requestPath === "/v1/sbx046/canary" && probe.requestOrigin === `http://127.0.0.1:${SBX046_PORT}` &&
    probe.requestAttempts === 1 && probe.connectionAttempts === 1 && probe.actualRequests === 1 &&
    probe.retries === 0 && probe.redirectsFollowed === 0 && probe.freshConnection &&
    !probe.strictTlsVerification && !probe.proxyConfigurationAccepted && !probe.tlsTrustConfigurationAccepted &&
    !probe.rawConfigurationRetained && probe.tcpConnected && !probe.tlsEstablished && !probe.tlsAuthorized &&
    probe.responseReceived && probe.responseStatusCode === 200 && probe.responseBytes !== undefined &&
    probe.responseBytes > 0 && probe.responseBytes <= MAXIMUM_RESPONSE_BYTES &&
    probe.serviceHeaderValidated === true && probe.cacheControlValidated === true &&
    probe.connectionCloseValidated === true && probe.contentTypeValidated === true &&
    probe.contentLengthValidated === true && !probe.timedOut && probe.error === undefined &&
    Number.isFinite(probe.durationMs) && probe.durationMs >= 0 && probe.durationMs <= 10_000 &&
    !probe.rawRequestBodyRetained && !probe.rawResponseBodyRetained && response !== undefined &&
    response.schemaVersion === 1 && response.testId === SBX046_TEST_ID && response.runId === expected.runId &&
    response.caseId === expected.caseId && response.sandboxName === expected.sandboxName &&
    response.sessionId === expected.sessionId && response.port === SBX046_PORT &&
    response.serviceInstanceId === expected.serviceInstanceId && response.challenge === expected.material.challenge &&
    response.operationId === expected.material.operationId && response.requestBodyValidated && response.ok;
}

async function runLocalProbe(input: {
  sandbox: Sandbox;
  runId: string;
  sandboxName: string;
  sessionId: string;
  serviceInstanceId: string;
  caseId: Sbx046CaseId;
  material: Sbx046CaseMaterial;
  revocationAcknowledgedAt?: string | undefined;
  forbidden: readonly string[];
}): Promise<VerdictProbeEvidence> {
  const configuration = buildLocalProbeConfiguration(input);
  const serialized = JSON.stringify(configuration);
  if (!evidenceExcludesSecrets(serialized, input.forbidden)) {
    throw new Error("SBX-046 local probe configuration contained controller-only material");
  }
  const startedAt = new Date().toISOString();
  const finished = await input.sandbox.currentSession().runCommand({
    cmd: "node",
    args: [REMOTE_SERVICE_PATH, "probe", Buffer.from(serialized).toString("base64url")],
    timeoutMs: 10_000,
    signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
  });
  const completedAt = new Date().toISOString();
  const [stdout, stderr] = await Promise.all([finished.stdout(), finished.stderr()]);
  if (Buffer.byteLength(stdout) > MAXIMUM_GUEST_OUTPUT_BYTES || Buffer.byteLength(stderr) > MAXIMUM_GUEST_OUTPUT_BYTES ||
      !evidenceExcludesSecrets({ stdout, stderr }, input.forbidden)) {
    throw new Error("SBX-046 local probe output exceeded bounds or retained controller-only material");
  }
  if (stderr !== "" || !stdout.endsWith("\n") || stdout.indexOf("\n") !== stdout.length - 1) {
    throw new Error("SBX-046 local probe did not return one clean JSON line");
  }
  const elapsed = input.revocationAcknowledgedAt === undefined
    ? null
    : Date.parse(startedAt) - Date.parse(input.revocationAcknowledgedAt);
  const probe = sanitizeLocalProbeEvidence({
    value: JSON.parse(stdout.slice(0, -1)),
    commandExitCode: finished.exitCode,
    stdoutBytes: Buffer.byteLength(stdout),
    stderrBytes: Buffer.byteLength(stderr),
    startedAt,
    completedAt,
    elapsedSinceRevocationAckMs: elapsed,
  });
  if (finished.exitCode !== 0 || !localProbeSelfExact(probe, input)) {
    throw new Error(`SBX-046 ${input.caseId} loopback control was not exact`);
  }
  return probe;
}

async function listPrefixSandboxes(
  credentials: Sbx046Credentials,
  sandboxName: string,
): Promise<Awaited<ReturnType<typeof Sandbox.list>>["sandboxes"]> {
  const page = await Sandbox.list({
    namePrefix: sandboxName,
    sortBy: "name",
    sortOrder: "asc",
    limit: 10,
    ...sandboxCredentials(credentials),
    signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
  });
  if (page.pagination.next !== null) throw new Error("SBX-046 prefix lookup unexpectedly required pagination");
  return page.sandboxes;
}

async function terminateService(
  command: Command | undefined,
  errors: string[],
  forbidden: readonly string[],
): Promise<boolean> {
  if (!command) return true;
  try {
    await command.kill("SIGTERM", { abortSignal: AbortSignal.timeout(5_000) });
    const finished = await command.wait({ signal: AbortSignal.timeout(10_000) });
    if (finished.exitCode !== 0) {
      errors.push(`service exited ${finished.exitCode} after SIGTERM`);
      return false;
    }
    return true;
  } catch (error) {
    errors.push(`service termination: ${safeError(error, forbidden)}`);
    return false;
  }
}

async function eraseGuestMaterial(
  sandbox: Sandbox | undefined,
  journal: Sbx046RecoveryJournal,
  persist: () => Promise<void>,
  cleanup: Sbx046CleanupEvidence,
  forbidden: readonly string[],
): Promise<void> {
  if (!sandbox || !journal.keyStaged) return;
  try {
    await sandbox.writeFiles([{
      path: REMOTE_CONFIG_PATH,
      content: Buffer.alloc(4_096, 0),
      mode: 0o600,
    }], { signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS) });
    journal.keyOverwritten = true;
    cleanup.keyOverwritten = true;
    await persist();
  } catch (error) {
    cleanup.errors.push(`guest key overwrite: ${safeError(error, forbidden)}`);
  }
  try {
    const finished = await sandbox.currentSession().runCommand({
      cmd: "rm",
      args: ["--", REMOTE_CONFIG_PATH, REMOTE_EVENT_LOG_PATH],
      timeoutMs: 10_000,
      signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
    });
    const [stdout, stderr] = await Promise.all([finished.stdout(), finished.stderr()]);
    if (finished.exitCode !== 0 || stdout !== "" || stderr !== "") {
      throw new Error(`rm returned exit=${finished.exitCode}`);
    }
    const [config, ledger] = await Promise.all([
      sandbox.readFileToBuffer({ path: REMOTE_CONFIG_PATH }, { signal: AbortSignal.timeout(5_000) }),
      sandbox.readFileToBuffer({ path: REMOTE_EVENT_LOG_PATH }, { signal: AbortSignal.timeout(5_000) }),
    ]);
    cleanup.guestConfigDeleted = config === null;
    cleanup.guestLedgerDeleted = ledger === null;
    if (!cleanup.guestConfigDeleted || !cleanup.guestLedgerDeleted) {
      throw new Error("guest config or ledger remained readable after deletion");
    }
    journal.keyDeleted = true;
    cleanup.keyDeleted = true;
    await persist();
  } catch (error) {
    cleanup.errors.push(`guest material deletion: ${safeError(error, forbidden)}`);
  }
}

async function cleanupNamedSandbox(input: {
  sandbox: Sandbox | undefined;
  credentials: Sbx046Credentials;
  journal: Sbx046RecoveryJournal;
  persist: () => Promise<void>;
  cleanup: Sbx046CleanupEvidence;
  forbidden: readonly string[];
}): Promise<void> {
  if (input.journal.createAttemptedAt === undefined) {
    input.cleanup.exactNameAbsent = true;
    input.cleanup.prefixListAbsent = true;
    return;
  }
  let handle = input.sandbox;
  try {
    if (!handle && input.journal.createAttemptedAt !== undefined) {
      const matches = (await listPrefixSandboxes(input.credentials, input.journal.sandboxName))
        .filter((candidate) => candidate.name === input.journal.sandboxName);
      if (matches.length > 1) throw new Error("multiple exact-name sandboxes found during recovery");
      const match = matches[0];
      if (match) {
        if (!recoverableSandboxIdentity({
          expectedName: input.journal.sandboxName,
          expectedTags: input.journal.tags,
          expectedPersistent: false,
          createAttemptedAt: input.journal.createAttemptedAt,
          candidate: match,
        })) throw new Error("recovery candidate failed exact provenance validation");
        if (input.journal.knownSessionIds.length > 0 &&
            !input.journal.knownSessionIds.includes(match.currentSessionId)) {
          throw new Error("recovery candidate session was not previously committed");
        }
        handle = await Sandbox.get({
          name: input.journal.sandboxName,
          resume: false,
          ...sandboxCredentials(input.credentials),
          signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
        });
      }
    }
    if (handle) {
      const sessionId = handle.currentSession().sessionId;
      const provenance = handle.name === input.journal.sandboxName && handle.persistent === false &&
        exactTags(handle.tags, input.journal.tags) &&
        (input.journal.knownSessionIds.length === 0 || input.journal.knownSessionIds.includes(sessionId));
      if (!provenance) throw new Error("cleanup handle failed exact name/tag/persistence/session provenance");
      input.cleanup.stopAttempted = true;
      input.journal.stopAttempted = true;
      await input.persist();
      if (handle.status !== "stopped") {
        const stopped = await handle.stop({ signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS) });
        if (stopped.id !== sessionId || stopped.status !== "stopped") {
          throw new Error("stop response did not identify the exact committed session");
        }
      }
      input.cleanup.stopped = true;
      input.journal.stopped = true;
      await input.persist();
      input.cleanup.deleteAttempted = true;
      input.journal.deleteAttempted = true;
      await input.persist();
      await handle.delete({ signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS) });
      input.cleanup.deleted = true;
      input.journal.deleted = true;
      await input.persist();
    }
  } catch (error) {
    input.cleanup.errors.push(`sandbox cleanup: ${safeError(error, input.forbidden)}`);
  }

  for (let attempt = 0; attempt < 3; attempt += 1) {
    if (attempt > 0) await delay(750);
    try {
      await Sandbox.get({
        name: input.journal.sandboxName,
        resume: false,
        ...sandboxCredentials(input.credentials),
        signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
      });
      input.cleanup.errors.push(`absence check ${attempt + 1} still found the exact sandbox`);
    } catch (error) {
      if (isNotFound(error)) {
        input.cleanup.absenceChecks += 1;
        input.journal.absenceChecks += 1;
      } else {
        input.cleanup.errors.push(`absence check ${attempt + 1}: ${safeError(error, input.forbidden)}`);
      }
    }
  }
  try {
    const remaining = await listPrefixSandboxes(input.credentials, input.journal.sandboxName);
    input.cleanup.prefixListAbsent = remaining.every((candidate) =>
      candidate.name !== input.journal.sandboxName && !candidate.name.startsWith(input.journal.sandboxName));
    input.journal.listAbsenceConfirmed = input.cleanup.prefixListAbsent;
    if (!input.cleanup.prefixListAbsent) input.cleanup.errors.push("sandbox name prefix remained after deletion");
  } catch (error) {
    input.cleanup.errors.push(`prefix absence: ${safeError(error, input.forbidden)}`);
  }
  input.cleanup.exactNameAbsent = input.cleanup.absenceChecks >= 3;
  await input.persist().catch((error) => {
    input.cleanup.errors.push(`final recovery journal: ${safeError(error, input.forbidden)}`);
  });
}

function emptyReadbackPair(
  stage: VerdictReadbackPair["active"]["stage"],
  expected: { sandboxName: string; sessionId: string; tags: Record<string, string> },
  observedAt: string,
): VerdictReadbackPair {
  const record = (source: "active" | "independent"): VerdictReadbackPair["active"] => ({
    stage,
    source,
    observedAt,
    sandboxName: expected.sandboxName,
    sessionId: expected.sessionId,
    persistent: false,
    status: "missing",
    tags: expected.tags,
    routes: [],
    domainPort: SBX046_PORT,
    domainValue: null,
    domainLookupThrew: false,
  });
  return { active: record("active"), independent: record("independent") };
}

function emptyProbe(
  caseId: Sbx046CaseId,
  expected: {
    runId: string;
    sandboxName: string;
    sessionId: string;
    serviceInstanceId: string;
    material: Sbx046CaseMaterial;
  },
  observedAt: string,
): VerdictProbeEvidence {
  const local = caseId.startsWith("local-");
  return {
    schemaVersion: 1,
    testId: SBX046_TEST_ID,
    runId: expected.runId,
    caseId,
    origin: local ? "loopback" : "saved-public-route",
    sandboxName: expected.sandboxName,
    sessionId: expected.sessionId,
    port: SBX046_PORT,
    serviceInstanceId: expected.serviceInstanceId,
    challenge: expected.material.challenge,
    expectedOperationId: expected.material.operationId,
    requestMethod: "POST",
    requestPath: "/v1/sbx046/canary",
    requestOrigin: local ? `http://127.0.0.1:${SBX046_PORT}` : "https://missing.vercel.run",
    startedAt: observedAt,
    completedAt: observedAt,
    elapsedSinceRevocationAckMs: null,
    requestAttempts: 0,
    connectionAttempts: 0,
    actualRequests: 0,
    retries: 0,
    redirectsFollowed: 0,
    freshConnection: false,
    strictTlsVerification: !local,
    proxyConfigurationAccepted: false,
    tlsTrustConfigurationAccepted: false,
    rawConfigurationRetained: false,
    tcpConnected: false,
    tlsEstablished: false,
    tlsAuthorized: false,
    responseReceived: false,
    timedOut: false,
    durationMs: 0,
    rawRequestBodyRetained: false,
    rawResponseBodyRetained: false,
  };
}

function exactLedgerJoin(
  ledger: Sbx046LedgerEvidence,
  probe: VerdictProbeEvidence,
  caseId: Sbx046CaseId,
): boolean {
  const events = ledger.events.filter((event) => event.caseId === caseId);
  const event = events[0];
  return events.length === 1 && event !== undefined && event.schemaVersion === 1 &&
    event.testId === SBX046_TEST_ID && event.runId === probe.runId && event.sandboxName === probe.sandboxName &&
    event.sessionId === probe.sessionId && event.port === SBX046_PORT &&
    event.serviceInstanceId === probe.serviceInstanceId && event.challenge === probe.challenge &&
    event.operationId === probe.expectedOperationId && event.method === "POST" &&
    event.path === "/v1/sbx046/canary" && event.requestBodyValidated && !event.rawHmacKeyRetained &&
    !event.rawRequestBodyRetained && !event.derivedDigestRetained;
}

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  requireScopeConfirmation();
  requireStrictControllerTlsEnvironment();
  const credentials = explicitCredentials();
  const runId = randomUUID();
  const sandboxName = buildSandboxName(runId);
  const tags = { harness: "vsc", test: SBX046_TEST_ID, run: runId };
  const artifactsDirectory = resolve(REPOSITORY_ROOT, "artifacts");
  const artifactPath = resolve(artifactsDirectory, `SBX-046-${runId}-private.json`);
  const journal = newRecoveryJournal({ runId, sandboxName, tags, startedAt });
  const hmacKey = randomBytes(32).toString("base64url");
  const serviceInstanceId = `svc46_${randomBytes(18).toString("base64url")}`;
  if (!SERVICE_INSTANCE.test(serviceInstanceId)) throw new Error("SBX-046 service instance ID was invalid");
  const forbidden = [credentials.token, hmacKey];
  const placeholderSessionId = "sbx_00000000000000000000";
  let sessionId = placeholderSessionId;
  let cases = buildCaseMaterial({ hmacKey, runId, sandboxName, sessionId, serviceInstanceId });
  let expectedRoute: VerdictRouteData = {
    url: "https://missing.vercel.run",
    subdomain: "missing",
    port: SBX046_PORT,
  };
  let expected = {
    runId,
    sandboxName,
    sessionId,
    tags,
    route: expectedRoute,
    serviceInstanceId,
    challenges: Object.fromEntries(SBX046_CASES.map((caseId) => [caseId, cases[caseId].challenge])) as
      Record<Sbx046CaseId, string>,
    operationIds: Object.fromEntries(SBX046_CASES.map((caseId) => [caseId, cases[caseId].operationId])) as
      Record<Sbx046CaseId, string>,
  };
  let probes = Object.fromEntries(SBX046_CASES.map((caseId) => [
    caseId,
    emptyProbe(caseId, { runId, sandboxName, sessionId, serviceInstanceId, material: cases[caseId] }, startedAt),
  ])) as Record<Sbx046CaseId, VerdictProbeEvidence>;
  let creation: Sbx046CreationEvidence = {
    attempts: 0,
    requestedAt: startedAt,
    createdAt: startedAt,
    completedAt: startedAt,
    sandboxName,
    sessionId,
    persistent: false,
    status: "missing",
    tags,
    routes: [],
    sourceSnapshotId: null,
  };
  let initialReadbacks = emptyReadbackPair("initial", { sandboxName, sessionId, tags }, startedAt);
  let postUpdateReadbacks = emptyReadbackPair("post-update", { sandboxName, sessionId, tags }, startedAt);
  let finalReadbacks = emptyReadbackPair("final", { sandboxName, sessionId, tags }, startedAt);
  let update: Sbx046UpdateEvidence = {
    method: "Sandbox.update",
    attempts: 0,
    requestedPorts: [],
    requestedAt: startedAt,
    acknowledgedAt: startedAt,
    acknowledged: false,
    sandboxName,
    sessionIdBefore: sessionId,
    sessionIdAfter: sessionId,
    responseRoutes: [],
  };
  let ledger: Sbx046LedgerEvidence = {
    configured: false,
    events: [],
    rawHmacKeyRetained: false,
    hmacKeyDigestRetained: false,
    rawLogRetained: false,
  };
  const cleanup: Sbx046CleanupEvidence = {
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    absenceChecks: 0,
    exactNameAbsent: false,
    prefixListAbsent: false,
    guestConfigDeleted: false,
    guestLedgerDeleted: false,
    keyOverwritten: false,
    keyDeleted: false,
    liveLockReleased: false,
    errors: [],
  };
  const storage: Sbx046StorageEvidence = {
    guestConfigMode: -1,
    guestLedgerMode: -1,
    artifactMode: -1,
    liveLockMode: -1,
    liveLockReleased: false,
    rawHmacKeyRetained: false,
    hmacKeyDigestRetained: false,
    rawRequestBodyRetained: false,
    rawResponseBodyRetained: false,
  };
  let identityProof: EligibleAliasIdentityProof | undefined;
  let identityAndScopePassed = false;
  let executionError: string | undefined;
  let sandbox: Sandbox | undefined;
  let serviceCommand: Command | undefined;
  let serviceLaunchAttempted = false;
  let lock: Sbx046LiveLock | undefined;
  let guestSource = "";
  const policyReadbacks = { initial: false, postUpdate: false, final: false };

  const persist = async (): Promise<void> => {
    if (!lock) return;
    await persistSbx046RecoveryJournal(lock.journalPath, journal);
  };

  const readLedger = async (): Promise<Sbx046LedgerEvidence> => {
    if (!sandbox) throw new Error("SBX-046 sandbox was unavailable for ledger readback");
    const raw = await sandbox.readFileToBuffer(
      { path: REMOTE_EVENT_LOG_PATH },
      { signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS) },
    );
    if (!raw) throw new Error("SBX-046 guest ledger was absent");
    return parseSbx046Ledger(raw);
  };

  try {
    lock = await acquireSbx046LiveLock(artifactsDirectory, journal);
    storage.liveLockMode = lock.lockMode;
    identityProof = await verifyEligibleAliasToken({
      token: credentials.token,
      expectedEmail: SBX046_ALIAS_EMAIL,
      expectedTeamId: SBX046_TEAM_ID,
      expectedProjectId: SBX046_PROJECT_ID,
      manualEmailConfirmation: process.env.SBX046_ALIAS_EMAIL_CONFIRMATION,
    });
    const preexisting = await listPrefixSandboxes(credentials, sandboxName);
    if (preexisting.some((candidate) => candidate.name.startsWith(sandboxName))) {
      throw new Error("SBX-046 exact full-UUID sandbox name was not fresh");
    }
    identityAndScopePassed = true;

    guestSource = await readFile(resolve(REPOSITORY_ROOT, "guest/published-port-revocation-service.mjs"), "utf8");
    if (!evidenceExcludesSecrets(guestSource, forbidden)) {
      throw new Error("SBX-046 guest source contained controller-only material");
    }
    journal.createAttemptedAt = new Date().toISOString();
    await persist();
    creation.attempts = 1;
    creation.requestedAt = journal.createAttemptedAt;
    sandbox = await Sandbox.create({
      name: sandboxName,
      persistent: false,
      timeout: 240_000,
      resources: { vcpus: 2 },
      ports: [SBX046_PORT],
      networkPolicy: "deny-all",
      tags,
      ...sandboxCredentials(credentials),
      signal: AbortSignal.timeout(45_000),
    });
    const createdCompletedAt = new Date().toISOString();
    const createdSession = sandbox.currentSession();
    sessionId = createdSession.sessionId;
    if (!SESSION_ID.test(sessionId) || sandbox.name !== sandboxName || sandbox.persistent !== false ||
        sandbox.status !== "running" || !exactTags(sandbox.tags, tags) || sandbox.networkPolicy !== "deny-all" ||
        createdSession.networkPolicy !== "deny-all" || sandbox.routes.length !== 1 ||
        !recoverableSandboxIdentity({
          expectedName: sandboxName,
          expectedTags: tags,
          expectedPersistent: false,
          createAttemptedAt: journal.createAttemptedAt,
          candidate: { name: sandbox.name, tags: sandbox.tags, persistent: sandbox.persistent,
            createdAt: sandbox.createdAt.getTime() },
        })) throw new Error("SBX-046 create response failed exact provenance or one-route validation");
    const canonicalOrigin = canonicalRouteOrigin(sandbox.routes[0]!);
    if (!canonicalOrigin) throw new Error("SBX-046 create response route was not canonical");
    expectedRoute = routeData(sandbox.routes)[0]!;
    journal.createdAt = sandbox.createdAt.toISOString();
    journal.initialSessionId = sessionId;
    journal.knownSessionIds.push(sessionId);
    await persist();

    cases = buildCaseMaterial({ hmacKey, runId, sandboxName, sessionId, serviceInstanceId });
    expected = {
      runId,
      sandboxName,
      sessionId,
      tags,
      route: expectedRoute,
      serviceInstanceId,
      challenges: Object.fromEntries(SBX046_CASES.map((caseId) => [caseId, cases[caseId].challenge])) as
        Record<Sbx046CaseId, string>,
      operationIds: Object.fromEntries(SBX046_CASES.map((caseId) => [caseId, cases[caseId].operationId])) as
        Record<Sbx046CaseId, string>,
    };
    probes = Object.fromEntries(SBX046_CASES.map((caseId) => [
      caseId,
      emptyProbe(caseId, { runId, sandboxName, sessionId, serviceInstanceId, material: cases[caseId] }, startedAt),
    ])) as Record<Sbx046CaseId, VerdictProbeEvidence>;
    creation = {
      attempts: 1,
      requestedAt: journal.createAttemptedAt,
      createdAt: sandbox.createdAt.toISOString(),
      completedAt: createdCompletedAt,
      sandboxName: sandbox.name,
      sessionId,
      persistent: sandbox.persistent,
      status: sandbox.status,
      tags: { ...(sandbox.tags ?? {}) },
      routes: routeData(sandbox.routes),
      sourceSnapshotId: createdSession.sourceSnapshotId ?? null,
    };

    const initial = await captureVerdictReadbacks("initial", sandbox, credentials);
    initialReadbacks = initial.pair;
    policyReadbacks.initial = initial.denyAllPassed;
    if (!initial.denyAllPassed || !exactVerdictReadbackPair(initial.pair, "initial", expected)) {
      throw new Error("SBX-046 initial active/independent one-route same-session readback failed");
    }

    const serviceConfiguration = buildServiceConfiguration({
      hmacKey,
      runId,
      sandboxName,
      sessionId,
      serviceInstanceId,
      cases,
    });
    await sandbox.mkDir(REMOTE_DIRECTORY, { signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS) });
    await sandbox.writeFiles([
      { path: REMOTE_SERVICE_PATH, content: guestSource, mode: 0o700 },
      { path: REMOTE_CONFIG_PATH, content: `${JSON.stringify(serviceConfiguration)}\n`, mode: 0o600 },
    ], { signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS) });
    journal.keyStaged = true;
    await persist();
    serviceLaunchAttempted = true;
    serviceCommand = await sandbox.currentSession().runCommand({
      cmd: "node",
      args: [REMOTE_SERVICE_PATH, "serve", REMOTE_CONFIG_PATH],
      detached: true,
      timeoutMs: 180_000,
      signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
    });
    const readiness = await readOneReadinessLine(serviceCommand);
    if (!exactReadiness(readiness, { runId, sandboxName, sessionId, serviceInstanceId })) {
      throw new Error("SBX-046 detached service readiness was not exact");
    }
    const statCommand = await sandbox.currentSession().runCommand({
      cmd: "stat",
      args: ["--format=%a", "--", REMOTE_CONFIG_PATH, REMOTE_EVENT_LOG_PATH],
      timeoutMs: 10_000,
      signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
    });
    const [statStdout, statStderr] = await Promise.all([statCommand.stdout(), statCommand.stderr()]);
    if (statCommand.exitCode !== 0 || statStderr !== "" || statStdout !== "600\n600\n") {
      throw new Error("SBX-046 guest config/event ledger were not exact mode 0600");
    }
    storage.guestConfigMode = 0o600;
    storage.guestLedgerMode = 0o600;

    probes["local-pre"] = await runLocalProbe({
      sandbox, runId, sandboxName, sessionId, serviceInstanceId,
      caseId: "local-pre", material: cases["local-pre"], forbidden,
    });
    const externalPreRaw = await performExternalProbe({
      origin: canonicalOrigin, runId, sandboxName, sessionId, serviceInstanceId,
      caseId: "external-pre", challenge: cases["external-pre"].challenge,
      expectedOperationId: cases["external-pre"].operationId,
    });
    probes["external-pre"] = externalVerdictProbe(externalPreRaw);
    if (!externalPreRaw.responseExact || !externalPreRaw.tcpConnected || !externalPreRaw.tlsEstablished ||
        !externalPreRaw.tlsAuthorized || !externalPreRaw.responseReceived || externalPreRaw.timedOut) {
      throw new Error("SBX-046 initial saved-route strict-TLS keyed control failed");
    }
    const preLedger = await readLedger();
    if (preLedger.events.length !== 2 || !exactLedgerJoin(preLedger, probes["local-pre"], "local-pre") ||
        !exactLedgerJoin(preLedger, probes["external-pre"], "external-pre")) {
      throw new Error("SBX-046 initial loopback/public controls lacked exact single guest events");
    }

    const updateRequestedAt = new Date().toISOString();
    const sessionIdBefore = sandbox.currentSession().sessionId;
    await sandbox.update({ ports: [] }, { signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS) });
    const updateAcknowledgedAt = new Date().toISOString();
    const sessionIdAfter = sandbox.currentSession().sessionId;
    update = {
      method: "Sandbox.update",
      attempts: 1,
      requestedPorts: [],
      requestedAt: updateRequestedAt,
      acknowledgedAt: updateAcknowledgedAt,
      acknowledged: true,
      sandboxName: sandbox.name,
      sessionIdBefore,
      sessionIdAfter,
      responseRoutes: routeData(sandbox.routes),
    };
    if (sessionIdBefore !== sessionId || sessionIdAfter !== sessionId || update.responseRoutes.length !== 0) {
      throw new Error("SBX-046 literal ports=[] update changed session or returned a route");
    }
    const post = await captureVerdictReadbacks("post-update", sandbox, credentials);
    postUpdateReadbacks = post.pair;
    policyReadbacks.postUpdate = post.denyAllPassed;
    if (!post.denyAllPassed || !exactVerdictReadbackPair(post.pair, "post-update", expected)) {
      throw new Error("SBX-046 post-update active/independent empty-route readback failed");
    }
    probes["local-post-readback"] = await runLocalProbe({
      sandbox, runId, sandboxName, sessionId, serviceInstanceId,
      caseId: "local-post-readback", material: cases["local-post-readback"],
      revocationAcknowledgedAt: updateAcknowledgedAt, forbidden,
    });

    const updateAcknowledgedAtMs = Date.parse(updateAcknowledgedAt);
    for (const [caseId, offset] of [
      ["external-post-5s", POST_UPDATE_OFFSETS_MS[0]],
      ["external-post-30s", POST_UPDATE_OFFSETS_MS[1]],
      ["external-post-90s", POST_UPDATE_OFFSETS_MS[2]],
    ] as const) {
      await waitUntilOffset(updateAcknowledgedAtMs, offset);
      const raw = await performExternalProbe({
        origin: canonicalOrigin,
        runId,
        sandboxName,
        sessionId,
        serviceInstanceId,
        caseId,
        challenge: cases[caseId].challenge,
        expectedOperationId: cases[caseId].operationId,
      });
      probes[caseId] = externalVerdictProbe(raw, updateAcknowledgedAt);
    }

    const final = await captureVerdictReadbacks("final", sandbox, credentials);
    finalReadbacks = final.pair;
    policyReadbacks.final = final.denyAllPassed;
    if (!final.denyAllPassed || !exactVerdictReadbackPair(final.pair, "final", expected)) {
      throw new Error("SBX-046 final active/independent empty-route readback failed");
    }
    probes["local-post-final"] = await runLocalProbe({
      sandbox, runId, sandboxName, sessionId, serviceInstanceId,
      caseId: "local-post-final", material: cases["local-post-final"],
      revocationAcknowledgedAt: updateAcknowledgedAt, forbidden,
    });
    ledger = await readLedger();
  } catch (error) {
    executionError = safeError(error, forbidden);
    if (sandbox && journal.keyStaged && ledger.events.length === 0) {
      try { ledger = await readLedger(); } catch { /* executionError already makes the run non-candidate */ }
    }
  } finally {
    const serviceTerminated = serviceCommand
      ? await terminateService(serviceCommand, cleanup.errors, forbidden)
      : !serviceLaunchAttempted;
    if (serviceTerminated) {
      await eraseGuestMaterial(sandbox, journal, persist, cleanup, forbidden);
    } else if (journal.keyStaged) {
      cleanup.errors.push("guest material retained because service termination was not proven");
    }
    await cleanupNamedSandbox({ sandbox, credentials, journal, persist, cleanup, forbidden });
    journal.completed = cleanup.stopped && cleanup.deleted && cleanup.absenceChecks >= 3 &&
      cleanup.prefixListAbsent && cleanup.guestConfigDeleted && cleanup.guestLedgerDeleted &&
      cleanup.errors.length === 0;
    try {
      await persist();
    } catch (error) {
      journal.completed = false;
      cleanup.errors.push(`journal completion: ${safeError(error, forbidden)}`);
    }
    if (lock && safeToReleaseSbx046Lock(journal)) {
      try {
        await releaseSbx046LiveLock(lock);
        cleanup.liveLockReleased = true;
        storage.liveLockReleased = true;
      } catch (error) {
        cleanup.errors.push(`live lock release: ${safeError(error, forbidden)}`);
      }
    }
  }

  const verdictCleanup = {
    stopAttempted: cleanup.stopAttempted,
    stopped: cleanup.stopped,
    deleteAttempted: cleanup.deleteAttempted,
    deleted: cleanup.deleted,
    absenceChecks: cleanup.absenceChecks,
    exactNameAbsent: cleanup.exactNameAbsent,
    prefixListAbsent: cleanup.prefixListAbsent,
    guestConfigDeleted: cleanup.guestConfigDeleted,
    guestLedgerDeleted: cleanup.guestLedgerDeleted,
    errors: cleanup.errors,
  };
  const assessmentInput: Sbx046AssessmentInput = {
    ...(executionError === undefined ? {} : { executionError }),
    identityAndScopePassed,
    expected,
    creation,
    initialReadbacks,
    update,
    postUpdateReadbacks,
    finalReadbacks,
    probes,
    ledger,
    cleanup: verdictCleanup,
    storage,
  };

  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  const artifact = await open(
    artifactPath,
    fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | noFollow,
    0o600,
  );
  let assessment;
  try {
    await artifact.chmod(0o600);
    const metadata = await artifact.stat();
    storage.artifactMode = metadata.mode & 0o777;
    if (!metadata.isFile() || metadata.nlink !== 1 || storage.artifactMode !== 0o600) {
      throw new Error("SBX-046 artifact was not an exact mode-0600 single-link regular file");
    }
    assessment = assessSbx046(assessmentInput);
    const evidence = {
      schemaVersion: 1,
      visibility: "private",
      testId: SBX046_TEST_ID,
      refinedHypothesis: "named sandbox published-port route revocation after ports=[]",
      runId,
      startedAt,
      completedAt: new Date().toISOString(),
      runtime: { sandboxSdk: "@vercel/sandbox@3.0.0", controllerNode: process.version },
      account: {
        aliasEmail: SBX046_ALIAS_EMAIL,
        teamId: SBX046_TEAM_ID,
        projectId: SBX046_PROJECT_ID,
        identityVerificationMethod: identityProof?.method ?? "not-verified",
      },
      assessment,
      assessmentInput,
      policyReadbacks,
      cleanupDetail: cleanup,
      recovery: {
        journalCompleted: journal.completed,
        fullUuidSandboxName: sandboxName,
        knownSessionIds: journal.knownSessionIds,
        rawJournalRetainedInArtifact: false,
      },
      bounds: {
        sandboxesCreatedMaximum: 1,
        publicRequestsMaximum: 4,
        publicRequestsSequential: true,
        publicRetries: 0,
        redirectsFollowed: 0,
        postUpdateAbsoluteOffsetsMs: POST_UPDATE_OFFSETS_MS,
      },
      retention: {
        rawVercelToken: false,
        rawHmacKey: false,
        hmacKeyDigest: false,
        rawRequestBodies: false,
        rawResponseBodies: false,
        guestRawLog: false,
        keyedOperationIdsOnly: true,
      },
      ...(executionError === undefined ? {} : { executionError }),
    };
    assertSbx046EvidenceExcludesRawValues(evidence, forbidden);
    if (!evidenceExcludesSecrets(evidence, forbidden)) {
      throw new Error("SBX-046 private evidence retained controller-only material");
    }
    await artifact.writeFile(`${JSON.stringify(evidence, null, 2)}\n`, "utf8");
    await artifact.sync();
  } catch (error) {
    await artifact.close().catch(() => undefined);
    await unlink(artifactPath).catch(() => undefined);
    throw error;
  }
  await artifact.close();
  if (lock && storage.liveLockReleased) await unlink(lock.journalPath);
  process.stdout.write(`${JSON.stringify({
    testId: SBX046_TEST_ID,
    runId,
    verdict: assessment.verdict,
    severity: assessment.severity,
    candidate: assessment.candidate,
    summary: assessment.summary,
    cleanupPassed: verdictCleanup.stopped && verdictCleanup.deleted && verdictCleanup.absenceChecks >= 3 &&
      verdictCleanup.exactNameAbsent && verdictCleanup.prefixListAbsent && verdictCleanup.guestConfigDeleted &&
      verdictCleanup.guestLedgerDeleted && verdictCleanup.errors.length === 0 && storage.liveLockReleased,
    artifactPath,
  }, null, 2)}\n`);
  process.exitCode = assessment.verdict === "pass" ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
