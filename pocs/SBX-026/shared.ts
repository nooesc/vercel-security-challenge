import { randomBytes } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import {
  lstat,
  link,
  mkdir,
  open,
  rename,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import { dirname, isAbsolute } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { APIError } from "@vercel/sandbox";

export const SCOPE_CONFIRMATION = "I_OWN_BOTH_DISTINCT_PROGRAM_ELIGIBLE_VERCEL_ACCOUNTS";
export const OWNERSHIP_CONFIRMATION =
  "I_PERSONALLY_OWN_AND_VERIFIED_BOTH_DISTINCT_VERCEL_ACCOUNTS";
export const NO_CROSS_MEMBERSHIP_CONFIRMATION =
  "I_VERIFIED_NEITHER_ACCOUNT_IS_A_MEMBER_OF_THE_OTHER_ACCOUNT_TEAM";
export const MINIMUM_VERCEL_REQUEST_INTERVAL_MS = 250;
export const CONTROL_PLANE_TIMEOUT_MS = 30_000;
export const MAXIMUM_CONTROL_RESPONSE_BYTES = 4_096;

export type AccountRole = "attacker" | "victim";

export interface ExplicitAccountCredentials {
  role: AccountRole;
  token: string;
  teamId: string;
  projectId: string;
  expectedEmail: string;
}

export interface ApiFailure {
  kind: "api" | "other";
  status?: number;
  code?: string;
}

export interface RequestAuditRecord {
  sequence: number;
  startedAt: string;
  completedAt?: string;
  method: string;
  origin: "vercel-sandbox-control-plane" | "vercel-identity";
  pathname: string;
  status?: number;
}

export interface VerifiedAccountIdentity {
  email: string;
  userId: string;
  exactMatch: true;
}

type Environment = Readonly<Record<string, string | undefined>>;

function required(environment: Environment, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function accountPrefix(role: AccountRole): "ATTACKER" | "VICTIM" {
  return role === "attacker" ? "ATTACKER" : "VICTIM";
}

function canonicalAliasEmail(value: string, field: string): string {
  const canonical = value.toLowerCase();
  if (
    canonical !== value || canonical.length > 254 ||
    !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@wearehackerone\.com$/u.test(canonical)
  ) {
    throw new Error(`${field} must be a canonical HackerOne alias email`);
  }
  return canonical;
}

export function loadAccountCredentials(
  role: AccountRole,
  environment: Environment = process.env,
): ExplicitAccountCredentials {
  const prefix = accountPrefix(role);
  const token = required(environment, `SBX026_${prefix}_TOKEN`);
  const teamId = required(environment, `SBX026_${prefix}_TEAM_ID`);
  const projectId = required(environment, `SBX026_${prefix}_PROJECT_ID`);
  const expectedEmail = canonicalAliasEmail(
    required(environment, `SBX026_${prefix}_EMAIL`),
    `SBX026_${prefix}_EMAIL`,
  );

  if (!/^team_[A-Za-z0-9]+$/u.test(teamId)) {
    throw new Error(`SBX026_${prefix}_TEAM_ID must be an exact team_ identifier`);
  }
  if (!/^prj_[A-Za-z0-9]+$/u.test(projectId)) {
    throw new Error(`SBX026_${prefix}_PROJECT_ID must be an exact prj_ identifier`);
  }
  if (token.length < 20 || token.length > 4_096 || /[\0\r\n]/u.test(token)) {
    throw new Error(`SBX026_${prefix}_TOKEN is malformed`);
  }

  return { role, token, teamId, projectId, expectedEmail };
}

export function loadTwoOwnedAccounts(
  environment: Environment = process.env,
): { attacker: ExplicitAccountCredentials; victim: ExplicitAccountCredentials } {
  if (required(environment, "SBX026_SCOPE_CONFIRMATION") !== SCOPE_CONFIRMATION) {
    throw new Error(`SBX026_SCOPE_CONFIRMATION must equal ${SCOPE_CONFIRMATION}`);
  }
  if (required(environment, "SBX026_OWNERSHIP_CONFIRMATION") !== OWNERSHIP_CONFIRMATION) {
    throw new Error(`SBX026_OWNERSHIP_CONFIRMATION must equal ${OWNERSHIP_CONFIRMATION}`);
  }
  if (
    required(environment, "SBX026_NO_CROSS_MEMBERSHIP_CONFIRMATION") !==
      NO_CROSS_MEMBERSHIP_CONFIRMATION
  ) {
    throw new Error(
      `SBX026_NO_CROSS_MEMBERSHIP_CONFIRMATION must equal ${NO_CROSS_MEMBERSHIP_CONFIRMATION}`,
    );
  }

  const attacker = loadAccountCredentials("attacker", environment);
  const victim = loadAccountCredentials("victim", environment);
  if (attacker.token === victim.token) throw new Error("attacker and victim tokens must be different");
  if (attacker.teamId === victim.teamId) throw new Error("attacker and victim team IDs must be different");
  if (attacker.projectId === victim.projectId) {
    throw new Error("attacker and victim project IDs must be different");
  }
  if (attacker.expectedEmail === victim.expectedEmail) {
    throw new Error("attacker and victim HackerOne alias emails must be different");
  }
  return { attacker, victim };
}

export class VercelRequestGate {
  private nextStartAt = 0;
  private sequence = 0;
  private reservation: Promise<void> = Promise.resolve();
  readonly records: RequestAuditRecord[] = [];

  async beforeRequest(
    input: Omit<RequestAuditRecord, "sequence" | "startedAt" | "completedAt" | "status">,
  ): Promise<RequestAuditRecord> {
    const previous = this.reservation;
    let release!: () => void;
    this.reservation = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      const waitMs = Math.max(0, this.nextStartAt - Date.now());
      if (waitMs > 0) {
        await delay(waitMs, undefined, { signal: AbortSignal.timeout(waitMs + 2_000) });
      }
      const startedAtMs = Date.now();
      this.nextStartAt = startedAtMs + MINIMUM_VERCEL_REQUEST_INTERVAL_MS;
      const record: RequestAuditRecord = {
        sequence: ++this.sequence,
        startedAt: new Date(startedAtMs).toISOString(),
        ...input,
      };
      this.records.push(record);
      return record;
    } finally {
      release();
    }
  }
}

function requestUrl(input: Parameters<typeof fetch>[0]): URL {
  if (input instanceof URL) return new URL(input.href);
  if (typeof input === "string") return new URL(input);
  return new URL(input.url);
}

function combinedHeaders(
  input: Parameters<typeof fetch>[0],
  init: Parameters<typeof fetch>[1],
): Headers {
  const headers = new Headers(input instanceof Request ? input.headers : undefined);
  new Headers(init?.headers).forEach((value, name) => headers.set(name, value));
  return headers;
}

function classifyUrl(url: URL, expectedTeamId: string): RequestAuditRecord["origin"] {
  if (
    url.origin === "https://api.vercel.com" && url.pathname === "/v2/user" &&
    url.search === "" && url.hash === ""
  ) {
    return "vercel-identity";
  }
  if (
    url.origin !== "https://vercel.com" ||
    (!url.pathname.startsWith("/api/v2/sandboxes") && !url.pathname.startsWith("/api/v3/sandboxes")) ||
    url.hash !== ""
  ) {
    throw new Error("controlled fetch refused a non-Sandbox Vercel endpoint");
  }
  const teamValues = url.searchParams.getAll("teamId");
  if (teamValues.length !== 1 || teamValues[0] !== expectedTeamId) {
    throw new Error("controlled fetch refused a missing, duplicate, or mismatched teamId");
  }
  return "vercel-sandbox-control-plane";
}

export function createAccountFetch(
  account: ExplicitAccountCredentials,
  gate: VercelRequestGate,
  baseFetch: typeof fetch = globalThis.fetch,
): typeof fetch {
  return (async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
    const url = requestUrl(input);
    const origin = classifyUrl(url, account.teamId);
    const headers = combinedHeaders(input, init);
    if (headers.get("authorization") !== `Bearer ${account.token}`) {
      throw new Error("controlled fetch refused missing or mismatched account authorization");
    }
    const method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
    const audit = await gate.beforeRequest({ method, origin, pathname: url.pathname });
    try {
      const response = await baseFetch(input, {
        ...init,
        redirect: "error",
        credentials: "omit",
        referrerPolicy: "no-referrer",
      });
      audit.status = response.status;
      audit.completedAt = new Date().toISOString();
      return response;
    } catch (error) {
      audit.completedAt = new Date().toISOString();
      throw error;
    }
  }) as typeof fetch;
}

export async function readBoundedResponse(
  response: Response,
  maximumBytes = MAXIMUM_CONTROL_RESPONSE_BYTES,
): Promise<Buffer> {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 0 || maximumBytes > 65_536) {
    throw new Error("invalid bounded response limit");
  }
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      const chunk = Buffer.from(item.value);
      total += chunk.length;
      if (total > maximumBytes) {
        await reader.cancel("bounded response exceeded fixed maximum").catch(() => undefined);
        chunk.fill(0);
        for (const retained of chunks) retained.fill(0);
        throw new Error(`bounded response exceeded ${maximumBytes} bytes`);
      }
      chunks.push(chunk);
    }
    const output = Buffer.concat(chunks, total);
    for (const retained of chunks) retained.fill(0);
    return output;
  } catch (error) {
    for (const retained of chunks) retained.fill(0);
    throw error;
  } finally {
    reader.releaseLock();
  }
}

function failureCode(value: unknown): string | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const error = (value as { error?: unknown }).error;
  if (error === null || typeof error !== "object" || Array.isArray(error)) return undefined;
  const code = (error as { code?: unknown }).code;
  return typeof code === "string" ? code.slice(0, 128) : undefined;
}

export async function apiFailureFromResponse(response: Response): Promise<ApiFailure> {
  const body = await readBoundedResponse(response);
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString("utf8") || "{}");
  } catch {
    parsed = undefined;
  } finally {
    body.fill(0);
  }
  const code = failureCode(parsed);
  return { kind: "api", status: response.status, ...(code ? { code } : {}) };
}

export function apiFailureFromError(error: unknown): ApiFailure {
  if (!(error instanceof APIError)) return { kind: "other" };
  const code = failureCode(error.json);
  return {
    kind: "api",
    status: error.response.status,
    ...(code ? { code } : {}),
  };
}

export function conclusiveAuthorizationRejection(failure: ApiFailure): boolean {
  if (failure.kind !== "api" || failure.status === undefined) return false;
  if ([403, 404].includes(failure.status)) return true;
  return failure.status === 422 &&
    ["forbidden", "not_found", "snapshot_not_found"].includes(failure.code ?? "");
}

export async function verifyAccountIdentity(
  account: ExplicitAccountCredentials,
  accountFetch: typeof fetch,
): Promise<VerifiedAccountIdentity> {
  const response = await accountFetch("https://api.vercel.com/v2/user", {
    method: "GET",
    headers: { Authorization: `Bearer ${account.token}`, Accept: "application/json" },
    signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
  });
  if (!response.ok) {
    const failure = await apiFailureFromResponse(response);
    throw new Error(`could not verify ${account.role} Vercel identity (${failure.status ?? "unknown"})`);
  }
  const body = await readBoundedResponse(response);
  let email: unknown;
  let userId: unknown;
  try {
    const payload = JSON.parse(body.toString("utf8")) as { user?: { id?: unknown; email?: unknown } };
    userId = payload.user?.id;
    email = payload.user?.email;
  } finally {
    body.fill(0);
  }
  if (email !== account.expectedEmail) {
    throw new Error(`${account.role} token email did not match its exact expected HackerOne alias`);
  }
  if (typeof userId !== "string" || userId.length < 1 || userId.length > 256 || /[\0\r\n]/u.test(userId)) {
    throw new Error(`${account.role} identity response did not contain a bounded user ID`);
  }
  return { email: account.expectedEmail, userId, exactMatch: true };
}

export function assertDistinctVerifiedIdentities(
  attacker: VerifiedAccountIdentity,
  victim: VerifiedAccountIdentity,
): true {
  if (!attacker.exactMatch || !victim.exactMatch) {
    throw new Error("both account identity checks must match their expected aliases");
  }
  if (attacker.email === victim.email || attacker.userId === victim.userId) {
    throw new Error("attacker and victim tokens must resolve to distinct Vercel users");
  }
  return true;
}

export function sandboxControlPlaneUrl(
  account: ExplicitAccountCredentials,
  path: string,
  query: Readonly<{ projectId?: string }> = {},
): URL {
  if (
    (!path.startsWith("/v2/sandboxes") && !path.startsWith("/v3/sandboxes")) ||
    path.includes("?") || path.includes("#")
  ) {
    throw new Error("path must be one exact Sandbox control-plane path without a query or fragment");
  }
  const queryKeys = Object.keys(query);
  if (queryKeys.some((key) => key !== "projectId")) {
    throw new Error("only an exact projectId query is supported by the bounded harness");
  }
  const url = new URL(`/api${path}`, "https://vercel.com");
  url.searchParams.set("teamId", account.teamId);
  if (query.projectId !== undefined) {
    if (!/^prj_[A-Za-z0-9]+$/u.test(query.projectId)) {
      throw new Error("projectId query must be an exact prj_ identifier");
    }
    url.searchParams.set("projectId", query.projectId);
  }
  return url;
}

export async function oneShotSandboxRequest(
  account: ExplicitAccountCredentials,
  accountFetch: typeof fetch,
  path: string,
  init: RequestInit,
  query: Readonly<{ projectId?: string }> = {},
): Promise<Response> {
  if (init.signal === undefined) throw new Error("one-shot requests require an AbortSignal");
  const url = sandboxControlPlaneUrl(account, path, query);
  const headers = new Headers(init.headers);
  headers.set("authorization", `Bearer ${account.token}`);
  if (!headers.has("accept")) headers.set("accept", "application/json");
  return accountFetch(url, {
    ...init,
    headers,
  });
}

export const SBX026_LIVE_LOCK_FILENAME = "SBX-026-live-active.lock";
export const SBX026_LIVE_LOCK_PATH = fileURLToPath(
  new URL(`../../artifacts/${SBX026_LIVE_LOCK_FILENAME}`, import.meta.url),
);

export type Sbx026LiveScope = "snapshot" | "fork" | "session-command";
export type Sbx026LiveMode = "normal" | "cleanup-only";

export interface Sbx026LiveLockMetadata {
  schemaVersion: 1;
  testId: "SBX-026";
  scope: Sbx026LiveScope;
  runId: string;
  pid: number;
  lease: string;
  createdAt: string;
  mode: Sbx026LiveMode;
  lane?: string;
}

export interface AcquireSbx026LiveLockOptions {
  scope: Sbx026LiveScope;
  runId: string;
  mode: Sbx026LiveMode;
  lane?: string;
}

export type Sbx026LiveLockTestMutation =
  | "transaction-created"
  | "recovery-guard-created"
  | "stale-recovery-guard-claimed"
  | "recovery-guard-replaced"
  | "stale-recovery-guard-removed"
  | "transaction-replacement-created"
  | "transaction-replaced"
  | "recovery-guard-removed"
  | "canonical-replacement-created"
  | "canonical-replaced"
  | "transaction-removed"
  | "release-transaction-created"
  | "release-canonical-claimed"
  | "release-canonical-removed"
  | "release-transaction-removed";

export interface Sbx026LiveLock {
  readonly path: string;
  readonly metadata: Readonly<Sbx026LiveLockMetadata>;
  readonly reclaimed: boolean;
  release(): Promise<void>;
}

const SBX026_LIVE_LOCK_SCHEMA_VERSION = 1;
const MAXIMUM_LIVE_LOCK_BYTES = 4_096;
const CANONICAL_UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANONICAL_LANE_PATTERN = /^[a-z][a-z0-9-]{0,63}$/u;
const LEASE_PATTERN = /^[A-Za-z0-9_-]{43}$/u;

type LockMutationHook = (mutation: Sbx026LiveLockTestMutation) => void | Promise<void>;

interface FileIdentity {
  device: bigint;
  inode: bigint;
}

interface OpenedSecureFile<T> extends FileIdentity {
  handle: FileHandle;
  metadata: T;
}

type OpenedLiveLock = OpenedSecureFile<Sbx026LiveLockMetadata>;

interface TransactionMetadata {
  schemaVersion: 1;
  testId: "SBX-026";
  kind: "live-lock-transaction";
  scope: Sbx026LiveScope;
  runId: string;
  pid: number;
  lease: string;
  createdAt: string;
  mode: Sbx026LiveMode;
  operation: "acquire" | "release";
  targetLease?: string;
  lane?: string;
}

interface RecoveryGuardMetadata {
  schemaVersion: 1;
  testId: "SBX-026";
  kind: "live-lock-transaction-recovery";
  scope: Sbx026LiveScope;
  runId: string;
  pid: number;
  lease: string;
  createdAt: string;
  mode: "cleanup-only";
  targetTransactionLease: string;
  lane?: string;
}

interface HeldTransaction extends OpenedSecureFile<TransactionMetadata> {
  path: string;
  reclaimed: boolean;
}

function filesystemErrorCode(error: unknown): string | undefined {
  return error !== null && typeof error === "object" && "code" in error &&
      typeof (error as { code?: unknown }).code === "string"
    ? (error as { code: string }).code
    : undefined;
}

function currentUserId(): bigint {
  if (typeof process.getuid !== "function") {
    throw new Error("SBX-026 live locking requires a POSIX process user ID");
  }
  return BigInt(process.getuid());
}

function noFollowFlag(): number {
  if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0) {
    throw new Error("SBX-026 live locking requires O_NOFOLLOW support");
  }
  return constants.O_NOFOLLOW;
}

function validateRunId(runId: string): void {
  if (!CANONICAL_UUID_PATTERN.test(runId)) {
    throw new Error("SBX-026 live-lock runId must be one lowercase canonical UUID");
  }
}

function validateLane(lane: string | undefined): void {
  if (lane !== undefined && !CANONICAL_LANE_PATTERN.test(lane)) {
    throw new Error("SBX-026 live-lock lane must be one exact canonical lane name");
  }
}

function validateAcquireOptions(options: AcquireSbx026LiveLockOptions): void {
  if (!(["snapshot", "fork", "session-command"] as const).includes(options.scope)) {
    throw new Error("SBX-026 live-lock scope must be snapshot, fork, or session-command");
  }
  if (options.mode !== "normal" && options.mode !== "cleanup-only") {
    throw new Error("SBX-026 live-lock mode must be normal or cleanup-only");
  }
  validateRunId(options.runId);
  validateLane(options.lane);
}

function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || value.length !== 24) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function exactObjectKeys(
  candidate: object,
  required: readonly string[],
  optional: readonly string[],
): boolean {
  const actual = Object.keys(candidate);
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.prototype.hasOwnProperty.call(candidate, key)) &&
    actual.every((key) => allowed.has(key)) &&
    actual.length === required.length + optional.filter((key) =>
      Object.prototype.hasOwnProperty.call(candidate, key)).length;
}

function parseLiveLockMetadata(value: unknown): Sbx026LiveLockMetadata {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("SBX-026 live-lock metadata must be one bounded JSON object");
  }
  const candidate = value as Partial<Record<keyof Sbx026LiveLockMetadata, unknown>>;
  if (!exactObjectKeys(candidate, [
    "schemaVersion", "testId", "scope", "runId", "pid", "lease", "createdAt", "mode",
  ], ["lane"])) {
    throw new Error("SBX-026 live-lock metadata has unexpected or missing fields");
  }
  const lanePresent = Object.prototype.hasOwnProperty.call(candidate, "lane");
  if (
    candidate.schemaVersion !== SBX026_LIVE_LOCK_SCHEMA_VERSION ||
    candidate.testId !== "SBX-026" ||
    (candidate.scope !== "snapshot" && candidate.scope !== "fork" &&
      candidate.scope !== "session-command") ||
    typeof candidate.runId !== "string" || !CANONICAL_UUID_PATTERN.test(candidate.runId) ||
    typeof candidate.pid !== "number" || !Number.isSafeInteger(candidate.pid) || candidate.pid <= 0 ||
    typeof candidate.lease !== "string" || !LEASE_PATTERN.test(candidate.lease) ||
    !isCanonicalTimestamp(candidate.createdAt) ||
    (candidate.mode !== "normal" && candidate.mode !== "cleanup-only") ||
    (lanePresent && (typeof candidate.lane !== "string" ||
      !CANONICAL_LANE_PATTERN.test(candidate.lane)))
  ) {
    throw new Error("SBX-026 live-lock metadata is invalid");
  }
  return candidate as unknown as Sbx026LiveLockMetadata;
}

function validCommonMetadata(candidate: {
  schemaVersion?: unknown;
  testId?: unknown;
  scope?: unknown;
  runId?: unknown;
  pid?: unknown;
  lease?: unknown;
  createdAt?: unknown;
  lane?: unknown;
}, lanePresent: boolean): boolean {
  return candidate.schemaVersion === SBX026_LIVE_LOCK_SCHEMA_VERSION &&
    candidate.testId === "SBX-026" &&
    (candidate.scope === "snapshot" || candidate.scope === "fork" ||
      candidate.scope === "session-command") &&
    typeof candidate.runId === "string" && CANONICAL_UUID_PATTERN.test(candidate.runId) &&
    typeof candidate.pid === "number" && Number.isSafeInteger(candidate.pid) && candidate.pid > 0 &&
    typeof candidate.lease === "string" && LEASE_PATTERN.test(candidate.lease) &&
    isCanonicalTimestamp(candidate.createdAt) &&
    (!lanePresent || (typeof candidate.lane === "string" &&
      CANONICAL_LANE_PATTERN.test(candidate.lane)));
}

function parseTransactionMetadata(value: unknown): TransactionMetadata {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("SBX-026 transaction sentinel metadata must be one bounded JSON object");
  }
  const candidate = value as Partial<Record<keyof TransactionMetadata, unknown>>;
  if (!exactObjectKeys(candidate, [
    "schemaVersion", "testId", "kind", "scope", "runId", "pid", "lease", "createdAt",
    "mode", "operation",
  ], ["lane", "targetLease"])) {
    throw new Error("SBX-026 transaction sentinel has unexpected or missing fields");
  }
  const lanePresent = Object.prototype.hasOwnProperty.call(candidate, "lane");
  const targetPresent = Object.prototype.hasOwnProperty.call(candidate, "targetLease");
  if (
    !validCommonMetadata(candidate, lanePresent) ||
    candidate.kind !== "live-lock-transaction" ||
    (candidate.mode !== "normal" && candidate.mode !== "cleanup-only") ||
    (candidate.operation !== "acquire" && candidate.operation !== "release") ||
    (targetPresent && (typeof candidate.targetLease !== "string" ||
      !LEASE_PATTERN.test(candidate.targetLease))) ||
    (candidate.operation === "release") !== targetPresent
  ) {
    throw new Error("SBX-026 transaction sentinel metadata is invalid");
  }
  return candidate as unknown as TransactionMetadata;
}

function parseRecoveryGuardMetadata(value: unknown): RecoveryGuardMetadata {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("SBX-026 recovery guard metadata must be one bounded JSON object");
  }
  const candidate = value as Partial<Record<keyof RecoveryGuardMetadata, unknown>>;
  if (!exactObjectKeys(candidate, [
    "schemaVersion", "testId", "kind", "scope", "runId", "pid", "lease", "createdAt",
    "mode", "targetTransactionLease",
  ], ["lane"])) {
    throw new Error("SBX-026 recovery guard has unexpected or missing fields");
  }
  const lanePresent = Object.prototype.hasOwnProperty.call(candidate, "lane");
  if (
    !validCommonMetadata(candidate, lanePresent) ||
    candidate.kind !== "live-lock-transaction-recovery" ||
    candidate.mode !== "cleanup-only" ||
    typeof candidate.targetTransactionLease !== "string" ||
    !LEASE_PATTERN.test(candidate.targetTransactionLease)
  ) {
    throw new Error("SBX-026 recovery guard metadata is invalid");
  }
  return candidate as unknown as RecoveryGuardMetadata;
}

async function readBoundedJson(handle: FileHandle): Promise<unknown> {
  const retained = Buffer.allocUnsafe(MAXIMUM_LIVE_LOCK_BYTES + 1);
  let total = 0;
  try {
    while (total < retained.length) {
      const result = await handle.read(retained, total, retained.length - total, total);
      if (result.bytesRead === 0) break;
      total += result.bytesRead;
    }
    if (total === 0 || total > MAXIMUM_LIVE_LOCK_BYTES) {
      throw new Error("SBX-026 live-lock metadata exceeded its fixed byte bound");
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(retained.subarray(0, total).toString("utf8"));
    } catch {
      throw new Error("SBX-026 live-lock metadata is not valid JSON");
    }
    return parsed;
  } finally {
    retained.fill(0);
  }
}

async function readBoundedLockMetadata(handle: FileHandle): Promise<Sbx026LiveLockMetadata> {
  return parseLiveLockMetadata(await readBoundedJson(handle));
}

function assertSecureRegularFile(
  metadata: BigIntStats,
  description: string,
): void {
  if (!metadata.isFile()) throw new Error(`${description} must be a regular file`);
  if ((metadata.mode & 0o777n) !== 0o600n) {
    throw new Error(`${description} must have exact mode 0600`);
  }
  if (metadata.uid !== currentUserId()) {
    throw new Error(`${description} must be owned by the current process user`);
  }
}

function sameIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return left.device === right.device && left.inode === right.inode;
}

function sameMetadata(
  left: Readonly<Sbx026LiveLockMetadata>,
  right: Readonly<Sbx026LiveLockMetadata>,
): boolean {
  return left.schemaVersion === right.schemaVersion && left.testId === right.testId &&
    left.scope === right.scope && left.runId === right.runId && left.pid === right.pid &&
    left.lease === right.lease && left.createdAt === right.createdAt && left.mode === right.mode &&
    left.lane === right.lane;
}

function sameTransactionMetadata(
  left: Readonly<TransactionMetadata>,
  right: Readonly<TransactionMetadata>,
): boolean {
  return left.schemaVersion === right.schemaVersion && left.testId === right.testId &&
    left.kind === right.kind && left.scope === right.scope && left.runId === right.runId &&
    left.pid === right.pid && left.lease === right.lease && left.createdAt === right.createdAt &&
    left.mode === right.mode && left.operation === right.operation &&
    left.targetLease === right.targetLease && left.lane === right.lane;
}

function sameRecoveryGuardMetadata(
  left: Readonly<RecoveryGuardMetadata>,
  right: Readonly<RecoveryGuardMetadata>,
): boolean {
  return left.schemaVersion === right.schemaVersion && left.testId === right.testId &&
    left.kind === right.kind && left.scope === right.scope && left.runId === right.runId &&
    left.pid === right.pid && left.lease === right.lease && left.createdAt === right.createdAt &&
    left.mode === right.mode && left.targetTransactionLease === right.targetTransactionLease &&
    left.lane === right.lane;
}

async function assertSecureLockDirectory(path: string): Promise<void> {
  const parent = dirname(path);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const metadata = await lstat(parent, { bigint: true });
  if (
    !metadata.isDirectory() || metadata.uid !== currentUserId() ||
    (metadata.mode & 0o777n) !== 0o700n
  ) {
    throw new Error("SBX-026 live-lock directory must be current-user-owned with exact mode 0700");
  }
}

async function openSecureMetadataFile<T>(
  path: string,
  description: string,
  parse: (value: unknown) => T,
): Promise<OpenedSecureFile<T>> {
  const pathBefore = await lstat(path, { bigint: true });
  assertSecureRegularFile(pathBefore, "SBX-026 live-lock path");
  const handle = await open(path, constants.O_RDONLY | noFollowFlag());
  try {
    const held = await handle.stat({ bigint: true });
    assertSecureRegularFile(held, "SBX-026 live-lock file");
    const identity = { device: held.dev, inode: held.ino };
    if (!sameIdentity(identity, { device: pathBefore.dev, inode: pathBefore.ino })) {
      throw new Error("SBX-026 live-lock path changed while it was opened");
    }
    const metadata = parse(await readBoundedJson(handle));
    const pathAfter = await lstat(path, { bigint: true });
    assertSecureRegularFile(pathAfter, "SBX-026 live-lock path");
    if (!sameIdentity(identity, { device: pathAfter.dev, inode: pathAfter.ino })) {
      throw new Error("SBX-026 live-lock path changed while it was inspected");
    }
    return { handle, metadata, ...identity };
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw error;
  }
}

async function openExistingLiveLock(path: string): Promise<OpenedLiveLock> {
  return openSecureMetadataFile(path, "SBX-026 live-lock", parseLiveLockMetadata);
}

async function openExistingTransaction(path: string): Promise<OpenedSecureFile<TransactionMetadata>> {
  return openSecureMetadataFile(
    path,
    "SBX-026 transaction sentinel",
    parseTransactionMetadata,
  );
}

async function openExistingRecoveryGuard(
  path: string,
): Promise<OpenedSecureFile<RecoveryGuardMetadata>> {
  return openSecureMetadataFile(path, "SBX-026 recovery guard", parseRecoveryGuardMetadata);
}

function metadataFor(options: AcquireSbx026LiveLockOptions): Sbx026LiveLockMetadata {
  return {
    schemaVersion: 1,
    testId: "SBX-026",
    scope: options.scope,
    runId: options.runId,
    pid: process.pid,
    lease: randomBytes(32).toString("base64url"),
    createdAt: new Date().toISOString(),
    mode: options.mode,
    ...(options.lane === undefined ? {} : { lane: options.lane }),
  };
}

async function restoreClaimWithoutReplacement(claimPath: string, path: string): Promise<boolean> {
  try {
    await link(claimPath, path);
  } catch (error) {
    if (filesystemErrorCode(error) === "EEXIST") return false;
    throw error;
  }
  await unlink(claimPath);
  return true;
}

async function removeExactMetadataClaim<T>(
  claimPath: string,
  expectedIdentity: FileIdentity,
  expectedMetadata: Readonly<T>,
  description: string,
  parse: (value: unknown) => T,
  equal: (left: Readonly<T>, right: Readonly<T>) => boolean,
): Promise<void> {
  const claim = await openSecureMetadataFile(claimPath, description, parse);
  try {
    if (!sameIdentity(claim, expectedIdentity) || !equal(claim.metadata, expectedMetadata)) {
      throw new Error("SBX-026 live-lock claim ownership changed; refusing removal");
    }
  } finally {
    await claim.handle.close();
  }
  const current = await lstat(claimPath, { bigint: true });
  assertSecureRegularFile(current, "SBX-026 live-lock claim");
  if (!sameIdentity({ device: current.dev, inode: current.ino }, expectedIdentity)) {
    throw new Error("SBX-026 live-lock claim changed before removal");
  }
  await unlink(claimPath);
}

async function createSecureMetadataFile<T>(
  path: string,
  metadata: T,
  description: string,
  parse: (value: unknown) => T,
  equal: (left: Readonly<T>, right: Readonly<T>) => boolean,
): Promise<OpenedSecureFile<T>> {
  const handle = await open(
    path,
    constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | noFollowFlag(),
    0o600,
  );
  let identity: FileIdentity | undefined;
  try {
    const opened = await handle.stat({ bigint: true });
    identity = { device: opened.dev, inode: opened.ino };
    await handle.chmod(0o600);
    const encoded = Buffer.from(`${JSON.stringify(metadata)}\n`, "utf8");
    try {
      if (encoded.length > MAXIMUM_LIVE_LOCK_BYTES) {
        throw new Error(`${description} metadata exceeded its fixed byte bound`);
      }
      await handle.write(encoded, 0, encoded.length, 0);
      await handle.truncate(encoded.length);
      await handle.sync();
    } finally {
      encoded.fill(0);
    }
    const held = await handle.stat({ bigint: true });
    assertSecureRegularFile(held, `${description} file`);
    identity = { device: held.dev, inode: held.ino };
    const current = await lstat(path, { bigint: true });
    assertSecureRegularFile(current, `${description} path`);
    if (!sameIdentity(identity, { device: current.dev, inode: current.ino })) {
      throw new Error(`${description} path changed during creation`);
    }
    const verified = parse(await readBoundedJson(handle));
    if (!equal(verified, metadata)) {
      throw new Error(`${description} metadata changed during creation`);
    }
    return { handle, metadata, ...identity };
  } catch (error) {
    await handle.close().catch(() => undefined);
    if (identity) {
      try {
        const current = await lstat(path, { bigint: true });
        if (sameIdentity(identity, { device: current.dev, inode: current.ino })) await unlink(path);
      } catch {
        // Fail closed: never remove a path whose inode cannot still be proven.
      }
    }
    throw error;
  }
}

function ownerProcessState(pid: number): "live" | "dead" | "uncertain" {
  try {
    process.kill(pid, 0);
    return "live";
  } catch (error) {
    if (filesystemErrorCode(error) === "ESRCH") return "dead";
    return "uncertain";
  }
}

function transactionPath(path: string): string {
  return `${path}.transaction`;
}

function recoveryGuardPath(path: string): string {
  return `${path}.transaction-recovery`;
}

function exactScope(
  metadata: Readonly<{ scope: Sbx026LiveScope; runId: string; lane?: string }>,
  options: AcquireSbx026LiveLockOptions,
): boolean {
  return metadata.scope === options.scope && metadata.runId === options.runId &&
    metadata.lane === options.lane;
}

function transactionFor(
  options: AcquireSbx026LiveLockOptions,
  operation: "acquire" | "release",
  targetLease?: string,
): TransactionMetadata {
  return {
    schemaVersion: 1,
    testId: "SBX-026",
    kind: "live-lock-transaction",
    scope: options.scope,
    runId: options.runId,
    pid: process.pid,
    lease: randomBytes(32).toString("base64url"),
    createdAt: new Date().toISOString(),
    mode: options.mode,
    operation,
    ...(targetLease === undefined ? {} : { targetLease }),
    ...(options.lane === undefined ? {} : { lane: options.lane }),
  };
}

function recoveryGuardFor(
  options: AcquireSbx026LiveLockOptions,
  targetTransactionLease: string,
): RecoveryGuardMetadata {
  return {
    schemaVersion: 1,
    testId: "SBX-026",
    kind: "live-lock-transaction-recovery",
    scope: options.scope,
    runId: options.runId,
    pid: process.pid,
    lease: randomBytes(32).toString("base64url"),
    createdAt: new Date().toISOString(),
    mode: "cleanup-only",
    targetTransactionLease,
    ...(options.lane === undefined ? {} : { lane: options.lane }),
  };
}

async function fireMutation(
  hook: LockMutationHook | undefined,
  mutation: Sbx026LiveLockTestMutation,
): Promise<void> {
  await hook?.(mutation);
}

async function removeOwnedMetadataFile<T>(
  path: string,
  opened: OpenedSecureFile<T>,
  description: string,
  parse: (value: unknown) => T,
  equal: (left: Readonly<T>, right: Readonly<T>) => boolean,
  hook: LockMutationHook | undefined,
  mutation: Sbx026LiveLockTestMutation,
  restoreOnPostRenameFailure = true,
): Promise<void> {
  const held = await opened.handle.stat({ bigint: true });
  assertSecureRegularFile(held, `${description} held file`);
  if (!sameIdentity({ device: held.dev, inode: held.ino }, opened)) {
    throw new Error(`${description} held inode changed`);
  }
  const heldMetadata = parse(await readBoundedJson(opened.handle));
  if (!equal(heldMetadata, opened.metadata)) throw new Error(`${description} held lease changed`);
  const current = await openSecureMetadataFile(path, description, parse);
  try {
    if (!sameIdentity(current, opened) || !equal(current.metadata, opened.metadata)) {
      throw new Error(`${description} path was replaced; refusing removal`);
    }
  } finally {
    await current.handle.close();
  }
  const claimPath = `${path}.remove-${process.pid}-${randomBytes(32).toString("hex")}`;
  let renamed = false;
  try {
    await rename(path, claimPath);
    renamed = true;
    await fireMutation(hook, mutation);
    await removeExactMetadataClaim(
      claimPath,
      opened,
      opened.metadata,
      description,
      parse,
      equal,
    );
  } catch (error) {
    if (renamed && restoreOnPostRenameFailure) {
      await restoreClaimWithoutReplacement(claimPath, path);
    }
    throw error;
  } finally {
    await opened.handle.close().catch(() => undefined);
  }
}

async function createRecoveryGuard(
  path: string,
  options: AcquireSbx026LiveLockOptions,
  targetLease: string,
  hook: LockMutationHook | undefined,
  mutation: Sbx026LiveLockTestMutation,
): Promise<OpenedSecureFile<RecoveryGuardMetadata>> {
  const metadata = recoveryGuardFor(options, targetLease);
  const opened = await createSecureMetadataFile(
    path,
    metadata,
    "SBX-026 recovery guard",
    parseRecoveryGuardMetadata,
    sameRecoveryGuardMetadata,
  );
  await fireMutation(hook, mutation);
  return opened;
}

async function acquireRecoveryGuard(
  lockPath: string,
  options: AcquireSbx026LiveLockOptions,
  target: TransactionMetadata,
  hook: LockMutationHook | undefined,
): Promise<OpenedSecureFile<RecoveryGuardMetadata>> {
  const guardPath = recoveryGuardPath(lockPath);
  try {
    return await createRecoveryGuard(
      guardPath,
      options,
      target.lease,
      hook,
      "recovery-guard-created",
    );
  } catch (error) {
    if (filesystemErrorCode(error) !== "EEXIST") throw error;
  }

  const stale = await openExistingRecoveryGuard(guardPath);
  const staleIdentity = { device: stale.device, inode: stale.inode };
  const staleMetadata = stale.metadata;
  await stale.handle.close();
  if (!exactScope(staleMetadata, options)) {
    throw new Error("cleanup-only mode refused a non-matching transaction recovery guard");
  }
  const state = ownerProcessState(staleMetadata.pid);
  if (state === "live") throw new Error("transaction recovery guard owner PID is live");
  if (state !== "dead") throw new Error("transaction recovery guard PID liveness is uncertain");

  const staleClaim = `${guardPath}.stale-${process.pid}-${randomBytes(32).toString("hex")}`;
  await rename(guardPath, staleClaim);
  await fireMutation(hook, "stale-recovery-guard-claimed");
  try {
    const claimed = await openExistingRecoveryGuard(staleClaim);
    try {
      if (!sameIdentity(claimed, staleIdentity) ||
          !sameRecoveryGuardMetadata(claimed.metadata, staleMetadata)) {
        throw new Error("transaction recovery guard changed during its atomic claim");
      }
    } finally {
      await claimed.handle.close();
    }
  } catch (error) {
    await restoreClaimWithoutReplacement(staleClaim, guardPath);
    throw error;
  }

  let replacement: OpenedSecureFile<RecoveryGuardMetadata>;
  try {
    replacement = await createRecoveryGuard(
      guardPath,
      options,
      target.lease,
      hook,
      "recovery-guard-replaced",
    );
  } catch (error) {
    await restoreClaimWithoutReplacement(staleClaim, guardPath);
    throw error;
  }
  try {
    await removeExactMetadataClaim(
      staleClaim,
      staleIdentity,
      staleMetadata,
      "SBX-026 stale recovery guard",
      parseRecoveryGuardMetadata,
      sameRecoveryGuardMetadata,
    );
    await fireMutation(hook, "stale-recovery-guard-removed");
    return replacement;
  } catch (error) {
    await replacement.handle.close().catch(() => undefined);
    throw error;
  }
}

async function createTransaction(
  path: string,
  metadata: TransactionMetadata,
  hook: LockMutationHook | undefined,
  mutation: Sbx026LiveLockTestMutation,
): Promise<HeldTransaction> {
  const opened = await createSecureMetadataFile(
    path,
    metadata,
    "SBX-026 transaction sentinel",
    parseTransactionMetadata,
    sameTransactionMetadata,
  );
  await fireMutation(hook, mutation);
  return { path, reclaimed: false, ...opened };
}

async function acquireTransaction(
  lockPath: string,
  options: AcquireSbx026LiveLockOptions,
  operation: "acquire" | "release",
  targetLease: string | undefined,
  hook: LockMutationHook | undefined,
): Promise<HeldTransaction> {
  const path = transactionPath(lockPath);
  const metadata = transactionFor(options, operation, targetLease);
  try {
    return await createTransaction(
      path,
      metadata,
      hook,
      operation === "release" ? "release-transaction-created" : "transaction-created",
    );
  } catch (error) {
    if (filesystemErrorCode(error) !== "EEXIST") throw error;
  }
  if (options.mode === "normal" || operation === "release") {
    throw new Error("refused SBX-026 operation because its global transaction sentinel exists");
  }

  const stale = await openExistingTransaction(path);
  const staleIdentity = { device: stale.device, inode: stale.inode };
  const staleMetadata = stale.metadata;
  if (!exactScope(staleMetadata, options)) {
    await stale.handle.close();
    throw new Error("cleanup-only mode refused a non-matching transaction scope, lane, or runId");
  }
  const state = ownerProcessState(staleMetadata.pid);
  if (state === "live") {
    await stale.handle.close();
    throw new Error("cleanup-only mode refused a transaction whose owner PID is live");
  }
  if (state !== "dead") {
    await stale.handle.close();
    throw new Error("cleanup-only mode refused uncertain transaction-owner liveness");
  }

  const guard = await acquireRecoveryGuard(lockPath, options, staleMetadata, hook);
  try {
    const current = await openExistingTransaction(path);
    try {
      if (!sameIdentity(current, staleIdentity) ||
          !sameTransactionMetadata(current.metadata, staleMetadata) ||
          ownerProcessState(current.metadata.pid) !== "dead") {
        throw new Error("stale transaction changed or became live during guarded recovery");
      }
    } finally {
      await current.handle.close();
    }

    const replacementPath = `${path}.next-${process.pid}-${metadata.lease}`;
    const replacement = await createSecureMetadataFile(
      replacementPath,
      metadata,
      "SBX-026 replacement transaction sentinel",
      parseTransactionMetadata,
      sameTransactionMetadata,
    );
    await fireMutation(hook, "transaction-replacement-created");
    await rename(replacementPath, path);
    await fireMutation(hook, "transaction-replaced");
    const verified = await openExistingTransaction(path);
    try {
      if (!sameIdentity(verified, replacement) ||
          !sameTransactionMetadata(verified.metadata, metadata)) {
        throw new Error("replacement transaction sentinel lost atomic ownership");
      }
    } finally {
      await verified.handle.close();
    }
    await stale.handle.close();
    await removeOwnedMetadataFile(
      recoveryGuardPath(lockPath),
      guard,
      "SBX-026 recovery guard",
      parseRecoveryGuardMetadata,
      sameRecoveryGuardMetadata,
      hook,
      "recovery-guard-removed",
    );
    return { path, reclaimed: true, ...replacement };
  } catch (error) {
    await stale.handle.close().catch(() => undefined);
    await guard.handle.close().catch(() => undefined);
    throw error;
  }
}

async function finishTransaction(
  transaction: HeldTransaction,
  hook: LockMutationHook | undefined,
  mutation: "transaction-removed" | "release-transaction-removed",
): Promise<void> {
  try {
    await removeOwnedMetadataFile(
      transaction.path,
      transaction,
      "SBX-026 transaction sentinel",
      parseTransactionMetadata,
      sameTransactionMetadata,
      hook,
      mutation,
      mutation !== "release-transaction-removed",
    );
  } catch (error) {
    if (mutation === "release-transaction-removed") {
      try {
        await lstat(transaction.path, { bigint: true });
      } catch (pathError) {
        if (filesystemErrorCode(pathError) === "ENOENT") {
          await transaction.handle.close().catch(() => undefined);
          return;
        }
      }
    }
    throw error;
  }
}

async function openOptionalLiveLock(path: string): Promise<OpenedLiveLock | undefined> {
  try {
    return await openExistingLiveLock(path);
  } catch (error) {
    if (filesystemErrorCode(error) === "ENOENT") return undefined;
    throw error;
  }
}

function assertDeadExactLiveLock(
  metadata: Sbx026LiveLockMetadata,
  options: AcquireSbx026LiveLockOptions,
): void {
  if (!exactScope(metadata, options)) {
    throw new Error("cleanup-only mode refused a non-matching SBX-026 scope, lane, or runId");
  }
  const state = ownerProcessState(metadata.pid);
  if (state === "live") throw new Error("cleanup-only mode refused because owner PID is live");
  if (state !== "dead") throw new Error("cleanup-only mode refused uncertain owner PID liveness");
}

class HeldSbx026LiveLock implements Sbx026LiveLock {
  private closed = false;

  constructor(
    readonly path: string,
    readonly metadata: Readonly<Sbx026LiveLockMetadata>,
    readonly reclaimed: boolean,
    private readonly handle: FileHandle,
    private readonly identity: FileIdentity,
    private readonly hook?: LockMutationHook,
  ) {}

  /**
   * Release is linearized only when the fixed transaction sentinel is atomically renamed away,
   * after the canonical live lock has been removed. Before that point, a failure retains the
   * sentinel (and restores a claimed canonical lock when possible), so every fresh acquisition
   * still refuses. After that rename, release is committed even if best-effort claim cleanup fails.
   */
  async release(): Promise<void> {
    if (this.closed) throw new Error("SBX-026 live lock is already closed");
    const options: AcquireSbx026LiveLockOptions = {
      scope: this.metadata.scope,
      runId: this.metadata.runId,
      mode: this.metadata.mode,
      ...(this.metadata.lane === undefined ? {} : { lane: this.metadata.lane }),
    };
    let transaction: HeldTransaction | undefined;
    let canonicalClaim: string | undefined;
    let canonicalRemoved = false;
    try {
      transaction = await acquireTransaction(
        this.path,
        options,
        "release",
        this.metadata.lease,
        this.hook,
      );
      const held = await this.handle.stat({ bigint: true });
      assertSecureRegularFile(held, "held SBX-026 live-lock file");
      if (!sameIdentity({ device: held.dev, inode: held.ino }, this.identity) ||
          !sameMetadata(await readBoundedLockMetadata(this.handle), this.metadata)) {
        throw new Error("held SBX-026 live-lock identity or lease changed");
      }
      const current = await openExistingLiveLock(this.path);
      try {
        if (!sameIdentity(current, this.identity) || !sameMetadata(current.metadata, this.metadata)) {
          throw new Error("SBX-026 live-lock path was replaced; refusing release");
        }
      } finally {
        await current.handle.close();
      }

      canonicalClaim = `${this.path}.release-${process.pid}-${randomBytes(32).toString("hex")}`;
      await rename(this.path, canonicalClaim);
      await fireMutation(this.hook, "release-canonical-claimed");
      await removeExactMetadataClaim(
        canonicalClaim,
        this.identity,
        this.metadata,
        "SBX-026 released live-lock claim",
        parseLiveLockMetadata,
        sameMetadata,
      );
      canonicalClaim = undefined;
      canonicalRemoved = true;
      await fireMutation(this.hook, "release-canonical-removed");
      await finishTransaction(transaction, this.hook, "release-transaction-removed");
      transaction = undefined;
    } catch (error) {
      if (canonicalClaim !== undefined) {
        await restoreClaimWithoutReplacement(canonicalClaim, this.path).catch(() => false);
      } else if (transaction !== undefined && !canonicalRemoved) {
        try {
          await finishTransaction(transaction, undefined, "release-transaction-removed");
          transaction = undefined;
        } catch {
          // The canonical lock still exists, and the transaction sentinel is retained if possible.
        }
      } else if (transaction !== undefined) {
        try {
          await finishTransaction(transaction, undefined, "release-transaction-removed");
          transaction = undefined;
          return;
        } catch {
          // The canonical lock is gone, but the fixed sentinel remains: report failure fail-closed.
        }
      }
      throw error;
    } finally {
      this.closed = true;
      await this.handle.close().catch(() => undefined);
      await transaction?.handle.close().catch(() => undefined);
    }
  }
}

async function acquireSbx026LiveLockAtPath(
  path: string,
  options: AcquireSbx026LiveLockOptions,
  hook?: LockMutationHook,
): Promise<Sbx026LiveLock> {
  validateAcquireOptions(options);
  if (!isAbsolute(path)) throw new Error("SBX-026 live-lock path must be absolute");
  await assertSecureLockDirectory(path);
  const transaction = await acquireTransaction(path, options, "acquire", undefined, hook);
  let existing: OpenedLiveLock | undefined;
  let replacement: OpenedSecureFile<Sbx026LiveLockMetadata> | undefined;
  let canonicalReplaced = false;
  try {
    existing = await openOptionalLiveLock(path);
    if (options.mode === "normal") {
      if (existing !== undefined) {
        throw new Error("refused normal SBX-026 run because the shared live lock already exists");
      }
    } else if (existing !== undefined) {
      assertDeadExactLiveLock(existing.metadata, options);
    } else if (!transaction.reclaimed) {
      throw new Error("cleanup-only mode requires an existing exact-scope lock or stale transaction");
    }

    const metadata = metadataFor(options);
    const replacementPath = `${path}.next-${process.pid}-${metadata.lease}`;
    replacement = await createSecureMetadataFile(
      replacementPath,
      metadata,
      "SBX-026 replacement live-lock",
      parseLiveLockMetadata,
      sameMetadata,
    );
    await fireMutation(hook, "canonical-replacement-created");
    await rename(replacementPath, path);
    canonicalReplaced = true;
    await fireMutation(hook, "canonical-replaced");
    const verified = await openExistingLiveLock(path);
    try {
      if (!sameIdentity(verified, replacement) || !sameMetadata(verified.metadata, metadata)) {
        throw new Error("replacement SBX-026 live lock lost atomic ownership");
      }
    } finally {
      await verified.handle.close();
    }
    await existing?.handle.close();
    existing = undefined;
    await finishTransaction(transaction, hook, "transaction-removed");
    return new HeldSbx026LiveLock(
      path,
      metadata,
      options.mode === "cleanup-only",
      replacement.handle,
      replacement,
      hook,
    );
  } catch (error) {
    await existing?.handle.close().catch(() => undefined);
    await replacement?.handle.close().catch(() => undefined);
    if (!canonicalReplaced) {
      await finishTransaction(transaction, undefined, "transaction-removed").catch(() => undefined);
    } else {
      await transaction.handle.close().catch(() => undefined);
    }
    throw error;
  }
}

/**
 * Acquires the single repository-global SBX-026 live lock.
 *
 * This relies on local POSIX filesystem semantics: O_EXCL/O_NOFOLLOW, stable dev/inode values,
 * atomic same-directory rename, non-replacing hard links, and kill(pid, 0) returning ESRCH only
 * for a dead local process. Network filesystems whose locking or inode semantics differ are
 * intentionally unsupported.
 */
export async function acquireSbx026LiveLock(
  options: AcquireSbx026LiveLockOptions,
): Promise<Sbx026LiveLock> {
  return acquireSbx026LiveLockAtPath(SBX026_LIVE_LOCK_PATH, options);
}

/** Unit-test seam. Production controllers must call acquireSbx026LiveLock(). */
export async function acquireSbx026LiveLockAtPathForTest(
  path: string,
  options: AcquireSbx026LiveLockOptions,
  mutationHook?: (mutation: Sbx026LiveLockTestMutation) => void | Promise<void>,
): Promise<Sbx026LiveLock> {
  return acquireSbx026LiveLockAtPath(path, options, mutationHook);
}
