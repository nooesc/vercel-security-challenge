import "dotenv/config";

import { createHash, randomBytes, randomUUID } from "node:crypto";
import dgram from "node:dgram";
import { Resolver } from "node:dns/promises";
import { readFile } from "node:fs/promises";
import { isIP, createConnection } from "node:net";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { APIError, Sandbox } from "@vercel/sandbox";
import {
  verifyEligibleAliasToken,
  type EligibleAliasIdentityProof,
} from "../eligible-alias-identity.js";
import {
  SBX001_CASES,
  SBX001_DIRECT_SCOPE_CONFIRMATION,
  SBX001_DIRECT_TEST_ID,
  SBX001_MIN_DNS_INTERVAL_MS,
  SBX001_RECEIPT_OBSERVATION_MS,
  SBX001_RECEIVER_WINDOW_MS,
  SBX001_SECRET_BYTES,
  SBX001_SECRET_FILE,
  assessSbx001Direct,
  buildDnsAQueryDirect,
  canonicalDnsName,
  derivePublicDnsOperationId,
  deriveSecretDnsCommitment,
  deriveSecretDnsOperationId,
  exactPolicyReadback,
  publicDnsLabel,
  publicDnsName,
  validateAuthoritativeAResponse,
  type Sbx001CleanupEvidence,
  type Sbx001CaseArm,
  type Sbx001CaseId,
  type Sbx001ControllerArmEvidence,
  type Sbx001ReceiptObservationEvidence,
  type Sbx001DnsTransport,
  type Sbx001GuestDnsEvidence,
  type Sbx001GuestHttpsEvidence,
  type Sbx001PolicyReadback,
  type Sbx001ReceiverSnapshot,
} from "./direct-shared.js";
import {
  SBX001_DIRECT_SANDBOX_TIMEOUT_MS,
  acquireSbx001DirectRecoveryState,
  acquireSbx001DirectState,
  createSbx001DirectJournal,
  persistSbx001DirectJournal,
  readSbx001DirectFinalizationReceipt,
  readSbx001DirectJournal,
  readSbx001DirectPendingArtifact,
  releaseSbx001DirectState,
  resumeSbx001DirectInterruptedFinalization,
  sbx001DirectArtifactPath,
  sbx001DirectFinalizationReceiptPath,
  sbx001DirectCreateSettlementReached,
  sbx001DirectRecoveryArtifactPath,
  writeSbx001DirectFinalizationReceipt,
  writeSbx001DirectPrivateArtifact,
  type Sbx001DirectFinalizationReceipt,
  type Sbx001DirectHeldState,
  type Sbx001DirectRecoveryJournal,
} from "./direct-safety.js";

const ELIGIBLE_ALIAS_EMAIL = "swve@wearehackerone.com";
const ELIGIBLE_TEAM_ID = "team_n98ERpVwV7HqmWRudAyK8sXQ";
const ELIGIBLE_PROJECT_ID = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
const OWNED_ZONE_SUFFIX = ".form-app.app";
const OWNED_HTTPS_CONTROL_ORIGIN = "https://vsc-h3-action-swve.cyrus-206.workers.dev";
const REMOTE_PROBE = "/tmp/sbx-001/dns-authoritative-probe.mjs";
const CONTROL_TIMEOUT_MS = 30_000;
const DNS_TIMEOUT_MS = 2_500;
const RECEIPT_POLL_INTERVAL_MS = 250;
const MAX_ADMIN_RESPONSE = 256 * 1024;
const OPERATION_ID_PATTERN = /^dns_[A-Za-z0-9_-]{43}$/u;
const SANDBOX_SESSION_ID_PATTERN = /^sbx_[A-Za-z0-9_-]{8,192}$/u;
const LATE_CREATE_RECOVERY_CHECKS = 16;
const LATE_CREATE_RECOVERY_INTERVAL_MS = 2_000;
const RESOURCE_ABSENCE_CHECKS = 3;
const RESOURCE_ABSENCE_INTERVAL_MS = 500;

export function sbx001SandboxPrefixListOptions(namePrefix: string): {
  namePrefix: string;
  limit: 10;
  sortBy: "name";
  sortOrder: "asc";
} {
  return { namePrefix, limit: 10, sortBy: "name", sortOrder: "asc" };
}

interface Credentials {
  token: string;
  teamId: string;
  projectId: string;
}

interface CommandEvidence {
  commandId: string;
  exitCode: number;
  startedAt: string;
  completedAt: string;
  durationMs?: number;
  stdoutRetained: false;
  stderrRetained: false;
}

interface DirectDnsPreflight {
  transport: Sbx001DnsTransport;
  attempted: boolean;
  retryCount: 0;
  responseReceived: boolean;
  authoritativeResponseValidated: boolean;
  timedOut: boolean;
  errorCode?: string;
}

class RateGate {
  private lastStartedAt = 0;
  private queued: Promise<void> = Promise.resolve();

  constructor(private readonly intervalMs: number) {}

  before(): Promise<void> {
    const next = this.queued.then(async () => {
      const remaining = this.intervalMs - (Date.now() - this.lastStartedAt);
      if (remaining > 0) await delay(remaining);
      this.lastStartedAt = Date.now();
    });
    this.queued = next.catch(() => undefined);
    return next;
  }
}

export async function pollForLateSbx001Resource<T>(input: {
  checks: number;
  intervalMs: number;
  lookup(): Promise<T | undefined>;
  wait?: (milliseconds: number) => Promise<void>;
  now?: () => number;
}): Promise<{ resource?: T; checks: number; observationMs: number }> {
  if (!Number.isInteger(input.checks) || input.checks < 1 || input.checks > 64 ||
    !Number.isInteger(input.intervalMs) || input.intervalMs < 0 || input.intervalMs > 10_000) {
    throw new Error("late-resource polling bounds are invalid");
  }
  const wait = input.wait ?? (async (milliseconds: number) => { await delay(milliseconds); });
  const now = input.now ?? Date.now;
  const startedAt = now();
  for (let index = 0; index < input.checks; index += 1) {
    if (index > 0) await wait(input.intervalMs);
    const resource = await input.lookup();
    if (resource !== undefined) return { resource, checks: index + 1, observationMs: now() - startedAt };
  }
  return { checks: input.checks, observationMs: now() - startedAt };
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function strongSecret(value: string, field: string): string {
  if (Buffer.byteLength(value) < 32 || Buffer.byteLength(value) > 256 || /[\0\r\n]/u.test(value)) {
    throw new Error(`${field} must contain 32-256 bytes without control characters`);
  }
  return value;
}

function freshQueryNonce(excluded: ReadonlySet<string>): string {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const nonce = randomBytes(16).toString("hex");
    if (!excluded.has(nonce)) return nonce;
  }
  throw new Error("failed to generate a distinct 128-bit query nonce");
}

function publicIPv4(value: string, field: string): string {
  if (isIP(value) !== 4 || value.split(".").some((part) => String(Number(part)) !== part || Number(part) > 255)) {
    throw new Error(`${field} must be canonical IPv4`);
  }
  const [a = -1, b = -1] = value.split(".").map(Number);
  if (a <= 0 || a >= 224 || a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127)) {
    throw new Error(`${field} must be a public IPv4 address`);
  }
  return value;
}

function loopbackAdminOrigin(value: string): string {
  const parsed = new URL(value);
  if (parsed.protocol !== "http:" || parsed.hostname !== "127.0.0.1" || !parsed.port || value !== parsed.origin ||
    parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) {
    throw new Error("SBX001_ADMIN_ORIGIN must be an exact loopback HTTP origin reached through an owned SSH forward");
  }
  return parsed.origin;
}

function ownedHttpsOrigin(value: string): string {
  const parsed = new URL(value);
  if (value !== OWNED_HTTPS_CONTROL_ORIGIN || parsed.protocol !== "https:" || value !== parsed.origin) {
    throw new Error("SBX001_HTTPS_CONTROL_ORIGIN must be the exact existing researcher-owned control Worker");
  }
  return value;
}

function credentials(environment: NodeJS.ProcessEnv): Credentials {
  const token = required(environment, "VERCEL_TOKEN");
  const teamId = required(environment, "VERCEL_TEAM_ID");
  const projectId = required(environment, "VERCEL_PROJECT_ID");
  if (teamId !== ELIGIBLE_TEAM_ID || projectId !== ELIGIBLE_PROJECT_ID) {
    throw new Error("SBX-001 must use the exact eligible HackerOne-alias team and project");
  }
  return { token, teamId, projectId };
}

function signal(timeoutMs = CONTROL_TIMEOUT_MS): AbortSignal {
  return AbortSignal.timeout(timeoutMs);
}

function safeError(error: unknown, forbidden: string[]): string {
  let text = error instanceof Error ? error.message : String(error);
  for (const value of forbidden) if (value) text = text.split(value).join("[REDACTED]");
  return text.replace(/[\0\r\n]/gu, " ").slice(0, 1_000);
}

function isNotFound(error: unknown): boolean {
  return error instanceof APIError && error.response.status === 404;
}

async function verifyAlias(
  token: string,
  manualEmailConfirmation: string | undefined,
  gate: RateGate,
): Promise<EligibleAliasIdentityProof> {
  const gatedFetch: typeof fetch = async (input, init) => {
    await gate.before();
    return await fetch(input, init);
  };
  return await verifyEligibleAliasToken({
    token,
    expectedEmail: ELIGIBLE_ALIAS_EMAIL,
    expectedTeamId: ELIGIBLE_TEAM_ID,
    expectedProjectId: ELIGIBLE_PROJECT_ID,
    ...(manualEmailConfirmation === undefined ? {} : { manualEmailConfirmation }),
    fetchImpl: gatedFetch,
  });
}

async function readBoundedJson(response: Response): Promise<unknown> {
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > MAX_ADMIN_RESPONSE) throw new Error("admin response exceeded its bound");
  const bytes = Buffer.from(await response.arrayBuffer());
  try {
    if (bytes.length > MAX_ADMIN_RESPONSE) throw new Error("admin response exceeded its bound");
    return bytes.length === 0 ? undefined : JSON.parse(bytes.toString("utf8"));
  } finally {
    bytes.fill(0);
  }
}

async function adminRequestWithStatus(input: {
  origin: string;
  adminKey: string;
  path: string;
  method: "GET" | "PUT" | "DELETE";
  expectedStatus: number | readonly number[];
  body?: unknown;
}): Promise<{ status: number; value: unknown }> {
  const response = await fetch(new URL(input.path, input.origin), {
    method: input.method,
    headers: {
      authorization: `Bearer ${input.adminKey}`,
      ...(input.body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(input.body === undefined ? {} : { body: JSON.stringify(input.body) }),
    signal: signal(10_000),
  });
  const parsed = await readBoundedJson(response);
  const expected = Array.isArray(input.expectedStatus) ? input.expectedStatus : [input.expectedStatus];
  if (!expected.includes(response.status)) {
    throw new Error(`receiver ${input.method} ${input.path} returned ${response.status}`);
  }
  return { status: response.status, value: parsed };
}

async function adminRequest(input: Parameters<typeof adminRequestWithStatus>[0]): Promise<unknown> {
  return (await adminRequestWithStatus(input)).value;
}

function exactObjectKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => allowed.has(key));
}

function exactStringRecord(actual: unknown, expected: Record<string, string>): boolean {
  if (actual === null || typeof actual !== "object" || Array.isArray(actual)) return false;
  const value = actual as Record<string, unknown>;
  const keys = Object.keys(expected);
  return Object.keys(value).length === keys.length && keys.every((key) => value[key] === expected[key]);
}

interface Sbx001RecoveredSandboxHandle {
  name: string;
  persistent: boolean;
  tags: unknown;
  currentSession(): { sessionId: unknown };
}

export type Sbx001RecoveredHandleMatch =
  | { matched: true; sessionId: string }
  | { matched: false };

/**
 * The single recovery-handle provenance predicate. The session is sampled
 * exactly once so attribution cannot validate one session and journal another.
 */
export function matchExactSbx001RecoveredHandle(input: {
  resource: Sbx001RecoveredSandboxHandle;
  sandboxName: string;
  sandboxTags: Record<string, string>;
  journaledSessionId?: string;
}): Sbx001RecoveredHandleMatch {
  let sessionId: unknown;
  try {
    sessionId = input.resource.currentSession().sessionId;
  } catch {
    return { matched: false };
  }
  if (input.resource.name !== input.sandboxName || input.resource.persistent !== false ||
      !exactStringRecord(input.resource.tags, input.sandboxTags) || typeof sessionId !== "string" ||
      !SANDBOX_SESSION_ID_PATTERN.test(sessionId) ||
      (input.journaledSessionId !== undefined && sessionId !== input.journaledSessionId)) {
    return { matched: false };
  }
  return { matched: true, sessionId };
}

/** Persist exact attribution before returning a handle that cleanup may mutate. */
export async function attributeSbx001RecoveredHandle<T extends Sbx001RecoveredSandboxHandle>(input: {
  resource: T;
  sandboxName: string;
  sandboxTags: Record<string, string>;
  journal: Sbx001DirectRecoveryJournal;
  persist(): Promise<void>;
}): Promise<T> {
  const match = matchExactSbx001RecoveredHandle({
    resource: input.resource,
    sandboxName: input.sandboxName,
    sandboxTags: input.sandboxTags,
    ...(input.journal.sessionId === undefined ? {} : { journaledSessionId: input.journal.sessionId }),
  });
  if (!match.matched) throw new Error("orphan recovery found a sandbox with non-exact provenance or session");
  const priorSessionId = input.journal.sessionId;
  const priorAttributed = input.journal.sandboxAttributed;
  input.journal.sessionId = match.sessionId;
  input.journal.sandboxAttributed = true;
  try {
    await input.persist();
  } catch (error) {
    if (priorSessionId === undefined) delete input.journal.sessionId;
    else input.journal.sessionId = priorSessionId;
    input.journal.sandboxAttributed = priorAttributed;
    throw error;
  }
  return input.resource;
}

function canonicalTimestamp(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}

export function sanitizeSbx001ReceiverSnapshot(value: unknown, runId: string): Sbx001ReceiverSnapshot {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("receiver snapshot is invalid");
  const snapshot = value as Record<string, unknown>;
  if (!exactObjectKeys(snapshot, [
    "arms", "configured", "configuredAt", "expiresAt", "observationWindowMs", "rawQueryNamesRetained",
    "rawSecretDigestsRetained", "rawSecretsRetained", "receipts", "runId", "secretRegistered",
  ], ["secretRegisteredAt"]) || snapshot.configured !== true || snapshot.runId !== runId ||
    !canonicalTimestamp(snapshot.configuredAt) || !canonicalTimestamp(snapshot.expiresAt) ||
    Date.parse(snapshot.expiresAt) - Date.parse(snapshot.configuredAt) !== SBX001_RECEIVER_WINDOW_MS ||
    snapshot.observationWindowMs !== SBX001_RECEIVER_WINDOW_MS || !Array.isArray(snapshot.receipts) ||
    !Array.isArray(snapshot.arms) || typeof snapshot.secretRegistered !== "boolean" ||
    snapshot.rawQueryNamesRetained !== false || snapshot.rawSecretsRetained !== false ||
    snapshot.rawSecretDigestsRetained !== false ||
    (snapshot.secretRegistered === true ? !canonicalTimestamp(snapshot.secretRegisteredAt) :
      snapshot.secretRegisteredAt !== undefined)) {
    throw new Error("receiver snapshot failed exact identity, window, or retention checks");
  }

  const caseIds = new Set<string>(Object.values(SBX001_CASES));
  const arms: Sbx001CaseArm[] = [];
  const armsByCase = new Map<Sbx001CaseId, Sbx001CaseArm>();
  for (const entry of snapshot.arms) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new Error("receiver arm is invalid");
    const arm = entry as Record<string, unknown>;
    if (!exactObjectKeys(arm, ["armedAt", "caseId", "operationId"]) ||
      typeof arm.caseId !== "string" || !caseIds.has(arm.caseId) || !canonicalTimestamp(arm.armedAt) ||
      typeof arm.operationId !== "string" || !OPERATION_ID_PATTERN.test(arm.operationId) ||
      armsByCase.has(arm.caseId as Sbx001CaseId) || Date.parse(arm.armedAt) < Date.parse(snapshot.configuredAt) ||
      Date.parse(arm.armedAt) > Date.parse(snapshot.expiresAt)) {
      throw new Error("receiver arm failed exact validation");
    }
    const checked = { caseId: arm.caseId as Sbx001CaseId, armedAt: arm.armedAt, operationId: arm.operationId };
    arms.push(checked);
    armsByCase.set(checked.caseId, checked);
  }

  const receipts: Sbx001ReceiverSnapshot["receipts"] = [];
  const receiptCases = new Set<Sbx001CaseId>();
  for (const entry of snapshot.receipts) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new Error("receiver receipt is invalid");
    const receipt = entry as Record<string, unknown>;
    if (!exactObjectKeys(receipt, [
      "armedAt", "authoritativeResponseSent", "caseId", "duplicateCount", "kind", "observedAt", "operationId",
      "queryType", "rawQueryNameRetained", "rawSecretDigestRetained", "rawSecretRetained", "runId",
      "sourceAddress", "sourcePort", "transport", "withinConfiguredWindow",
    ]) || receipt.runId !== runId || typeof receipt.caseId !== "string" || !caseIds.has(receipt.caseId) ||
      receiptCases.has(receipt.caseId as Sbx001CaseId) || !canonicalTimestamp(receipt.armedAt) ||
      !canonicalTimestamp(receipt.observedAt) || Date.parse(receipt.observedAt) < Date.parse(receipt.armedAt) ||
      typeof receipt.operationId !== "string" || !OPERATION_ID_PATTERN.test(receipt.operationId) ||
      receipt.kind !== (receipt.caseId === SBX001_CASES.denySecret ? "secret" : "public") ||
      (receipt.caseId === SBX001_CASES.outsideUdp ? receipt.transport !== "udp" :
        receipt.caseId === SBX001_CASES.outsideTcp ? receipt.transport !== "tcp" :
          receipt.transport !== "udp" && receipt.transport !== "tcp") ||
      receipt.queryType !== "A" || typeof receipt.authoritativeResponseSent !== "boolean" ||
      typeof receipt.sourceAddress !== "string" || isIP(receipt.sourceAddress) === 0 ||
      !Number.isInteger(receipt.sourcePort) || Number(receipt.sourcePort) < 0 || Number(receipt.sourcePort) > 65_535 ||
      !Number.isInteger(receipt.duplicateCount) || Number(receipt.duplicateCount) < 0 ||
      receipt.withinConfiguredWindow !== true || receipt.rawQueryNameRetained !== false ||
      receipt.rawSecretRetained !== false || receipt.rawSecretDigestRetained !== false) {
      throw new Error("receiver receipt failed exact validation");
    }
    const caseId = receipt.caseId as Sbx001CaseId;
    const arm = armsByCase.get(caseId);
    if (!arm || arm.armedAt !== receipt.armedAt || arm.operationId !== receipt.operationId) {
      throw new Error("receiver receipt does not match its exact case arm");
    }
    receiptCases.add(caseId);
    receipts.push({
      runId,
      caseId,
      kind: receipt.kind as "public" | "secret",
      transport: receipt.transport as Sbx001DnsTransport,
      queryType: "A",
      authoritativeResponseSent: receipt.authoritativeResponseSent,
      operationId: receipt.operationId,
      armedAt: receipt.armedAt,
      observedAt: receipt.observedAt,
      sourceAddress: receipt.sourceAddress,
      sourcePort: receipt.sourcePort as number,
      duplicateCount: receipt.duplicateCount as number,
      withinConfiguredWindow: true,
      rawQueryNameRetained: false,
      rawSecretRetained: false,
      rawSecretDigestRetained: false,
    });
  }
  return {
    configured: true,
    runId,
    configuredAt: snapshot.configuredAt,
    expiresAt: snapshot.expiresAt,
    observationWindowMs: SBX001_RECEIVER_WINDOW_MS,
    receipts,
    arms,
    secretRegistered: snapshot.secretRegistered,
    ...(snapshot.secretRegisteredAt === undefined ? {} : { secretRegisteredAt: snapshot.secretRegisteredAt as string }),
    rawQueryNamesRetained: false,
    rawSecretsRetained: false,
    rawSecretDigestsRetained: false,
  };
}

/**
 * Boundary attribution is the exact pre-response ingress receipt. A response
 * write is still retained as a separate outcome, but is not required for a
 * deny-all boundary candidate. Conversely, a kernel-accepted guest datagram
 * without exact authoritative ingress can never be a clean negative.
 */
export function assessSbx001DirectWithIngress(
  input: Parameters<typeof assessSbx001Direct>[0],
): ReturnType<typeof assessSbx001Direct> {
  const denyIngress = input.receiver.receipts.filter((receipt) =>
    receipt.caseId === SBX001_CASES.denyPublic || receipt.caseId === SBX001_CASES.denySecret);
  const assessed = assessSbx001Direct({
    ...input,
    receiver: {
      ...input.receiver,
      receipts: input.receiver.receipts.map((receipt) =>
        receipt.caseId === SBX001_CASES.denyPublic || receipt.caseId === SBX001_CASES.denySecret
          ? { ...receipt, authoritativeResponseSent: true }
          : receipt),
    },
  });
  if (assessed.verdict === "pass" &&
      (input.denyDns.datagramAcceptedByKernel || denyIngress.length !== 0)) {
    return {
      verdict: "indeterminate",
      candidate: false,
      severity: "unknown",
      controlsPassed: assessed.controlsPassed,
      secretPhaseAuthorized: false,
      summary: denyIngress.length === 0
        ? "The guest datagram was accepted by the kernel, but no exact final authoritative ingress was retained."
        : "An exact deny-all ingress existed, so a clean negative was forbidden even though its response write failed.",
    };
  }
  return assessed;
}

async function getReceiverSnapshot(origin: string, adminKey: string, runId: string): Promise<Sbx001ReceiverSnapshot> {
  return sanitizeSbx001ReceiverSnapshot(await adminRequest({
    origin,
    adminKey,
    path: `/v1/sbx001/admin/runs/${runId}`,
    method: "GET",
    expectedStatus: 200,
  }), runId);
}

export function requireSbx001FinalReceiverSnapshot(input: {
  status: number;
  value: unknown;
  runId: string;
  receiverConfigured: boolean;
}): Sbx001ReceiverSnapshot | undefined {
  if (input.status === 200) return sanitizeSbx001ReceiverSnapshot(input.value, input.runId);
  if (input.status === 404 && !input.receiverConfigured) return undefined;
  if (input.status === 404) throw new Error("configured receiver lacked its required final snapshot");
  throw new Error(`final receiver snapshot returned unexpected status ${input.status}`);
}

interface Sbx001ReceiverCleanupResult {
  receiverAlreadyAbsent: boolean;
  receiverDeleteAttempted: boolean;
  receiverDeleted: boolean;
  receiverAbsenceChecks: number;
  receiverAbsenceConfirmed: boolean;
  errors: string[];
  finalReceiverSnapshot?: Sbx001ReceiverSnapshot;
}

/**
 * Receiver cleanup is fail-closed around the durable final snapshot. In
 * particular, neither DELETE intent nor DELETE itself is exposed until a
 * configured receiver's sanitized snapshot is present in the journal and the
 * journal persistence has completed.
 */
export async function cleanupSbx001Receiver(input: {
  receiverConfigureAttempted: boolean;
  runId: string;
  journal: Sbx001DirectRecoveryJournal;
  forbidden: string[];
  readFinal(): Promise<{ status: number; value: unknown }>;
  persist(): Promise<void>;
  deleteReceiver(): Promise<{ status: number }>;
  checkAbsent(): Promise<void>;
  wait?: (milliseconds: number) => Promise<void>;
}): Promise<Sbx001ReceiverCleanupResult> {
  const result: Sbx001ReceiverCleanupResult = {
    receiverAlreadyAbsent: false,
    receiverDeleteAttempted: false,
    receiverDeleted: false,
    receiverAbsenceChecks: 0,
    receiverAbsenceConfirmed: false,
    errors: [],
  };
  if (!input.receiverConfigureAttempted) return result;

  let finalReceiverSnapshot: Sbx001ReceiverSnapshot | undefined;
  try {
    const finalRead = await input.readFinal();
    if (finalRead.status === 404 && input.journal.receiverConfigured &&
        input.journal.finalReceiverSnapshotCaptured && input.journal.finalReceiverSnapshot !== undefined) {
      finalReceiverSnapshot = sanitizeSbx001ReceiverSnapshot(
        input.journal.finalReceiverSnapshot,
        input.runId,
      );
    } else {
      finalReceiverSnapshot = requireSbx001FinalReceiverSnapshot({
        status: finalRead.status,
        value: finalRead.value,
        runId: input.runId,
        receiverConfigured: input.journal.receiverConfigured,
      });
      if (finalReceiverSnapshot) {
        const priorSnapshot = input.journal.finalReceiverSnapshot;
        const priorCaptured = input.journal.finalReceiverSnapshotCaptured;
        input.journal.finalReceiverSnapshot = finalReceiverSnapshot;
        input.journal.finalReceiverSnapshotCaptured = true;
        try {
          await input.persist();
        } catch (error) {
          if (priorSnapshot === undefined) delete input.journal.finalReceiverSnapshot;
          else input.journal.finalReceiverSnapshot = priorSnapshot;
          input.journal.finalReceiverSnapshotCaptured = priorCaptured;
          throw error;
        }
      } else {
        result.receiverAlreadyAbsent = true;
      }
    }
  } catch (error) {
    result.errors.push(`final receiver snapshot: ${safeError(error, input.forbidden)}`);
    return result;
  }

  let receiverDeleteError: unknown;
  if (!result.receiverAlreadyAbsent) {
    const priorDeleteAttempted = input.journal.receiverDeleteAttempted;
    result.receiverDeleteAttempted = true;
    input.journal.receiverDeleteAttempted = true;
    try {
      await input.persist();
    } catch (error) {
      result.receiverDeleteAttempted = false;
      input.journal.receiverDeleteAttempted = priorDeleteAttempted;
      result.errors.push(`receiver delete intent: ${safeError(error, input.forbidden)}`);
      return { ...result, ...(finalReceiverSnapshot ? { finalReceiverSnapshot } : {}) };
    }
    try {
      const deletion = await input.deleteReceiver();
      result.receiverDeleted = deletion.status === 204;
      result.receiverAlreadyAbsent = deletion.status === 404;
      if (!result.receiverDeleted && !result.receiverAlreadyAbsent) {
        throw new Error(`receiver DELETE returned ${deletion.status}`);
      }
      input.journal.receiverDeleted = true;
      await input.persist();
    } catch (error) {
      receiverDeleteError = error;
    }
  }

  const wait = input.wait ?? (async (milliseconds: number) => { await delay(milliseconds); });
  for (let index = 0; index < RESOURCE_ABSENCE_CHECKS; index += 1) {
    if (index > 0) await wait(RESOURCE_ABSENCE_INTERVAL_MS);
    try {
      await input.checkAbsent();
      result.receiverAbsenceChecks += 1;
    } catch (error) {
      result.errors.push(`receiver absence check: ${safeError(error, input.forbidden)}`);
      break;
    }
  }
  result.receiverAbsenceConfirmed = result.receiverAbsenceChecks === RESOURCE_ABSENCE_CHECKS;
  input.journal.receiverAbsenceChecks = result.receiverAbsenceChecks;
  try {
    await input.persist();
  } catch (error) {
    result.errors.push(`receiver absence checkpoint: ${safeError(error, input.forbidden)}`);
  }
  if (result.receiverAbsenceConfirmed && receiverDeleteError !== undefined) result.receiverAlreadyAbsent = true;
  if (!result.receiverAbsenceConfirmed && receiverDeleteError !== undefined) {
    result.errors.push(`receiver delete: ${safeError(receiverDeleteError, input.forbidden)}`);
  }
  return { ...result, ...(finalReceiverSnapshot ? { finalReceiverSnapshot } : {}) };
}

function receiverArm(value: unknown, caseId: Sbx001CaseId, operationId: string): Sbx001CaseArm {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("receiver case arm is invalid");
  const arm = value as Record<string, unknown>;
  if (Object.keys(arm).sort().join("\0") !== ["armedAt", "caseId", "operationId"].sort().join("\0") ||
    arm.caseId !== caseId || arm.operationId !== operationId || typeof arm.armedAt !== "string" ||
    !Number.isFinite(Date.parse(arm.armedAt))) {
    throw new Error("receiver case arm failed exact validation");
  }
  return { caseId, operationId, armedAt: new Date(arm.armedAt).toISOString() };
}

async function armReceiverCase(input: {
  origin: string;
  adminKey: string;
  runId: string;
  caseId: Sbx001CaseId;
  operationId: string;
}): Promise<Sbx001ControllerArmEvidence> {
  const requestedAt = new Date().toISOString();
  const arm = receiverArm(await adminRequest({
    origin: input.origin,
    adminKey: input.adminKey,
    path: `/v1/sbx001/admin/runs/${input.runId}/cases/${input.caseId}/arm`,
    method: "PUT",
    expectedStatus: 200,
    body: { operationId: input.operationId },
  }), input.caseId, input.operationId);
  return { ...arm, requestedAt, acknowledgedAt: new Date().toISOString() };
}

async function observeReceiverReceipt(input: {
  origin: string;
  adminKey: string;
  runId: string;
  caseId: Sbx001CaseId;
  operationId: string;
}): Promise<{
  snapshot: Sbx001ReceiverSnapshot;
  receiptObserved: boolean;
  observation: Sbx001ReceiptObservationEvidence;
}> {
  const startedAt = new Date().toISOString();
  const deadline = Date.now() + SBX001_RECEIPT_OBSERVATION_MS;
  let pollCount = 0;
  let snapshot = await getReceiverSnapshot(input.origin, input.adminKey, input.runId);
  while (true) {
    pollCount += 1;
    const receiptObserved = snapshot.receipts.some((receipt) => receipt.caseId === input.caseId &&
      receipt.operationId === input.operationId && receipt.armedAt === snapshot.arms.find((arm) =>
        arm.caseId === input.caseId && arm.operationId === input.operationId)?.armedAt);
    if (receiptObserved || Date.now() >= deadline) return {
      snapshot,
      receiptObserved,
      observation: {
        caseId: input.caseId,
        operationId: input.operationId,
        startedAt,
        completedAt: new Date().toISOString(),
        maximumWindowMs: SBX001_RECEIPT_OBSERVATION_MS,
        pollCount,
        receiptObserved,
      },
    };
    await delay(Math.min(RECEIPT_POLL_INTERVAL_MS, Math.max(1, deadline - Date.now())));
    snapshot = await getReceiverSnapshot(input.origin, input.adminKey, input.runId);
  }
}

async function delegationPreflight(zone: string, nameserver: string, expectedIPv4: string): Promise<{
  nameservers: string[];
  nameserverIPv4: string[];
  nameserverIPv6: string[];
  nameserverCname: string[];
  passed: boolean;
}> {
  const resolver = new Resolver();
  const timer = globalThis.setTimeout(() => resolver.cancel(), 10_000);
  try {
    const optional = async (lookup: () => Promise<string[]>): Promise<string[]> => {
      try {
        return await lookup();
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === "ENODATA" || code === "ENOTFOUND") return [];
        throw error;
      }
    };
    const nameservers = [...new Set((await resolver.resolveNs(zone)).map((value) => value.toLowerCase().replace(/\.$/u, "")))].sort();
    const nameserverIPv4 = [...new Set(await resolver.resolve4(nameserver))].sort();
    const nameserverIPv6 = [...new Set(await optional(() => resolver.resolve6(nameserver)))].sort();
    const nameserverCname = [...new Set((await optional(() => resolver.resolveCname(nameserver)))
      .map((value) => value.toLowerCase().replace(/\.$/u, "")))].sort();
    return {
      nameservers,
      nameserverIPv4,
      nameserverIPv6,
      nameserverCname,
      passed: exactDelegationSets({ nameservers, nameserverIPv4, nameserverIPv6, nameserverCname },
        { nameserver, expectedIPv4 }),
    };
  } finally {
    globalThis.clearTimeout(timer);
  }
}

export function exactDelegationSets(
  observed: { nameservers: string[]; nameserverIPv4: string[]; nameserverIPv6: string[]; nameserverCname: string[] },
  expected: { nameserver: string; expectedIPv4: string },
): boolean {
  return observed.nameservers.length === 1 && observed.nameservers[0] === expected.nameserver &&
    observed.nameserverIPv4.length === 1 && observed.nameserverIPv4[0] === expected.expectedIPv4 &&
    observed.nameserverIPv6.length === 0 && observed.nameserverCname.length === 0;
}

async function outsideHttpsPreflight(origin: string): Promise<{ statusCode?: number; passed: boolean }> {
  const response = await fetch(new URL("/healthz", origin), { redirect: "error", signal: signal(8_000) });
  const statusCode = response.status;
  await response.body?.cancel();
  return { statusCode, passed: statusCode === 200 };
}

async function directUdpQuery(
  ipv4: string,
  port: number,
  queryName: string,
  gate: RateGate,
): Promise<DirectDnsPreflight> {
  await gate.before();
  const transactionId = randomBytes(2).readUInt16BE(0);
  const packet = buildDnsAQueryDirect(queryName, transactionId);
  const socket = dgram.createSocket("udp4");
  let timer: NodeJS.Timeout | undefined;
  try {
    return await new Promise((resolvePromise) => {
      let finished = false;
      const finish = (value: Omit<DirectDnsPreflight, "transport" | "attempted" | "retryCount">) => {
        if (finished) return;
        finished = true;
        if (timer) clearTimeout(timer);
        socket.close();
        resolvePromise({ transport: "udp", attempted: true, retryCount: 0, ...value });
      };
      socket.once("message", (response) => finish({
        responseReceived: true,
        authoritativeResponseValidated: validateAuthoritativeAResponse(response, transactionId),
        timedOut: false,
      }));
      socket.once("error", (error) => finish({
        responseReceived: false,
        authoritativeResponseValidated: false,
        timedOut: false,
        errorCode: typeof (error as NodeJS.ErrnoException).code === "string"
          ? (error as NodeJS.ErrnoException).code!.slice(0, 64)
          : "UDP_ERROR",
      }));
      timer = setTimeout(() => finish({
        responseReceived: false,
        authoritativeResponseValidated: false,
        timedOut: true,
        errorCode: "ETIMEDOUT",
      }), DNS_TIMEOUT_MS);
      socket.send(packet, port, ipv4, (error) => {
        if (error) finish({
          responseReceived: false,
          authoritativeResponseValidated: false,
          timedOut: false,
          errorCode: typeof (error as NodeJS.ErrnoException).code === "string"
            ? (error as NodeJS.ErrnoException).code!.slice(0, 64)
            : "UDP_SEND_ERROR",
        });
      });
    });
  } finally {
    packet.fill(0);
  }
}

async function directTcpQuery(
  ipv4: string,
  port: number,
  queryName: string,
  gate: RateGate,
): Promise<DirectDnsPreflight> {
  await gate.before();
  const transactionId = randomBytes(2).readUInt16BE(0);
  const query = buildDnsAQueryDirect(queryName, transactionId);
  const frame = Buffer.alloc(query.length + 2);
  frame.writeUInt16BE(query.length, 0);
  query.copy(frame, 2);
  query.fill(0);
  return await new Promise((resolvePromise) => {
    let finished = false;
    let received = Buffer.alloc(0);
    const socket = createConnection({ host: ipv4, port, timeout: DNS_TIMEOUT_MS });
    const finish = (value: Omit<DirectDnsPreflight, "transport" | "attempted" | "retryCount">) => {
      if (finished) return;
      finished = true;
      socket.destroy();
      frame.fill(0);
      received.fill(0);
      resolvePromise({ transport: "tcp", attempted: true, retryCount: 0, ...value });
    };
    socket.once("connect", () => socket.write(frame));
    socket.on("data", (chunk) => {
      if (received.length + chunk.length > 514) {
        finish({ responseReceived: false, authoritativeResponseValidated: false, timedOut: false, errorCode: "OVERSIZED" });
        return;
      }
      received = Buffer.concat([received, chunk]);
      if (received.length < 2) return;
      const length = received.readUInt16BE(0);
      if (length > 512 || received.length < length + 2) return;
      if (received.length !== length + 2) {
        finish({ responseReceived: false, authoritativeResponseValidated: false, timedOut: false, errorCode: "FRAMING" });
        return;
      }
      finish({
        responseReceived: true,
        authoritativeResponseValidated: validateAuthoritativeAResponse(received.subarray(2), transactionId),
        timedOut: false,
      });
    });
    socket.once("timeout", () => finish({
      responseReceived: false,
      authoritativeResponseValidated: false,
      timedOut: true,
      errorCode: "ETIMEDOUT",
    }));
    socket.once("error", (error) => finish({
      responseReceived: false,
      authoritativeResponseValidated: false,
      timedOut: false,
      errorCode: typeof (error as NodeJS.ErrnoException).code === "string"
        ? (error as NodeJS.ErrnoException).code!.slice(0, 64)
        : "TCP_ERROR",
    }));
  });
}

async function policyReadback(
  sandbox: Sandbox,
  sandboxName: string,
  sessionId: string,
  creds: Credentials,
  expected: "allow-all" | "deny-all",
  gate: RateGate,
): Promise<Sbx001PolicyReadback> {
  await gate.before();
  const independent = await Sandbox.get({ name: sandboxName, resume: false, ...creds, signal: signal() });
  const activeSession = sandbox.currentSession();
  const independentSession = independent.currentSession();
  return exactPolicyReadback({
    observedAt: new Date().toISOString(),
    originalSessionId: sessionId,
    activeSessionId: activeSession.sessionId,
    independentSessionId: independentSession.sessionId,
    activeSandboxPolicy: sandbox.networkPolicy,
    activeSessionPolicy: activeSession.networkPolicy,
    independentSandboxPolicy: independent.networkPolicy,
    independentSessionPolicy: independentSession.networkPolicy,
  }, expected);
}

function emptyPolicy(): Sbx001PolicyReadback {
  return {
    observedAt: new Date(0).toISOString(),
    originalSessionId: "",
    activeSessionId: "",
    independentSessionId: "",
    activeSandboxPolicy: undefined,
    activeSessionPolicy: undefined,
    independentSandboxPolicy: undefined,
    independentSessionPolicy: undefined,
    exact: false,
    sameSession: false,
    passed: false,
  };
}

function emptyDns(caseId: "allow-public" | "deny-public" | "deny-secret", runId: string): Sbx001GuestDnsEvidence {
  return {
    schemaVersion: 1,
    ok: false,
    mode: "dns",
    runId,
    testId: SBX001_DIRECT_TEST_ID,
    guestNodeVersion: "invalid",
    caseId,
    queryType: "A",
    queryAttempts: 1,
    retryCount: 0,
    resolverFamily: 4,
    resolverPort: 53,
    sendInvoked: false,
    datagramAcceptedByKernel: false,
    responseReceived: false,
    timedOut: false,
    secretFileValidated: false,
    secretEncodedInOneLabel: false,
    rawQueryNameRetained: false,
    rawSecretRetained: false,
    rawSecretDigestRetained: false,
  };
}

function emptyHttps(caseId: "allow-https" | "deny-https", runId: string, origin: string): Sbx001GuestHttpsEvidence {
  return {
    schemaVersion: 1,
    ok: false,
    mode: "https",
    runId,
    testId: SBX001_DIRECT_TEST_ID,
    guestNodeVersion: "invalid",
    caseId,
    origin,
    path: "/healthz",
    connectionAttempts: 1,
    retryCount: 0,
    responseBodiesRetained: false,
    durationMs: 0,
    receivedResponse: false,
    timedOut: false,
  };
}

function exactEvidenceKeys(
  input: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[],
): boolean {
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(input, key)) && Object.keys(input).every((key) => allowed.has(key));
}

export function sanitizeSbx001DnsEvidence(
  value: unknown,
  expectedCase: Sbx001GuestDnsEvidence["caseId"],
  runId: string,
): Sbx001GuestDnsEvidence {
  const fallback = emptyDns(expectedCase, runId);
  if (!value || typeof value !== "object" || Array.isArray(value)) return fallback;
  const input = value as Record<string, unknown>;
  const required = [
    "caseId", "datagramAcceptedByKernel", "guestNodeVersion", "mode", "ok", "queryAttempts", "queryType",
    "rawQueryNameRetained", "rawSecretDigestRetained", "rawSecretRetained", "resolverFamily", "resolverPort",
    "responseReceived", "retryCount", "runId", "schemaVersion", "secretEncodedInOneLabel", "secretFileValidated",
    "sendInvoked", "testId", "timedOut",
  ] as const;
  const optional = ["errorCode", "responseCode", "secretBytes", "secretFileMode", "transactionIdMatched"] as const;
  const errorCodePassed = input.errorCode === undefined ||
    (typeof input.errorCode === "string" && /^[A-Za-z][A-Za-z0-9_]{0,63}$/u.test(input.errorCode));
  const responseCodePassed = input.responseCode === undefined ||
    (Number.isInteger(input.responseCode) && Number(input.responseCode) >= 0 && Number(input.responseCode) <= 15);
  const transactionPassed = input.transactionIdMatched === undefined || typeof input.transactionIdMatched === "boolean";
  const secretFieldsPassed = expectedCase === SBX001_CASES.denySecret
    ? Number.isInteger(input.secretFileMode) && Number.isInteger(input.secretBytes)
    : input.secretFileMode === undefined && input.secretBytes === undefined;
  if (!exactEvidenceKeys(input, required, optional) || input.schemaVersion !== 1 || input.ok !== true ||
    input.mode !== "dns" || input.runId !== runId || input.testId !== SBX001_DIRECT_TEST_ID ||
    input.caseId !== expectedCase || input.queryType !== "A" || input.queryAttempts !== 1 || input.retryCount !== 0 ||
    (input.resolverFamily !== 4 && input.resolverFamily !== 6) || input.resolverPort !== 53 ||
    typeof input.guestNodeVersion !== "string" || !/^v\d+\.\d+\.\d+(?:[-+].*)?$/u.test(input.guestNodeVersion) ||
    typeof input.sendInvoked !== "boolean" || typeof input.datagramAcceptedByKernel !== "boolean" ||
    typeof input.responseReceived !== "boolean" || typeof input.timedOut !== "boolean" ||
    typeof input.secretFileValidated !== "boolean" || typeof input.secretEncodedInOneLabel !== "boolean" ||
    input.rawQueryNameRetained !== false || input.rawSecretRetained !== false ||
    input.rawSecretDigestRetained !== false || !errorCodePassed || !responseCodePassed || !transactionPassed ||
    !secretFieldsPassed) return fallback;
  return {
    schemaVersion: 1,
    ok: true,
    mode: "dns",
    runId,
    testId: SBX001_DIRECT_TEST_ID,
    guestNodeVersion: input.guestNodeVersion,
    caseId: expectedCase,
    queryType: "A",
    queryAttempts: 1,
    retryCount: 0,
    resolverFamily: input.resolverFamily,
    resolverPort: 53,
    sendInvoked: input.sendInvoked,
    datagramAcceptedByKernel: input.datagramAcceptedByKernel,
    responseReceived: input.responseReceived,
    timedOut: input.timedOut,
    ...(input.transactionIdMatched === undefined ? {} : { transactionIdMatched: input.transactionIdMatched as boolean }),
    ...(input.responseCode === undefined ? {} : { responseCode: input.responseCode as number }),
    secretFileValidated: input.secretFileValidated,
    ...(input.secretFileMode === undefined ? {} : { secretFileMode: input.secretFileMode as number }),
    ...(input.secretBytes === undefined ? {} : { secretBytes: input.secretBytes as number }),
    secretEncodedInOneLabel: input.secretEncodedInOneLabel,
    rawQueryNameRetained: false,
    rawSecretRetained: false,
    rawSecretDigestRetained: false,
    ...(input.errorCode === undefined ? {} : { errorCode: input.errorCode as string }),
  };
}

export function sanitizeSbx001HttpsEvidence(
  value: unknown,
  expectedCase: Sbx001GuestHttpsEvidence["caseId"],
  runId: string,
  origin: string,
): Sbx001GuestHttpsEvidence {
  const fallback = emptyHttps(expectedCase, runId, origin);
  if (!value || typeof value !== "object" || Array.isArray(value)) return fallback;
  const input = value as Record<string, unknown>;
  const required = [
    "caseId", "connectionAttempts", "durationMs", "guestNodeVersion", "mode", "ok", "origin", "path",
    "receivedResponse", "responseBodiesRetained", "retryCount", "runId", "schemaVersion", "testId", "timedOut",
  ] as const;
  const optional = ["errorCode", "statusCode"] as const;
  if (!exactEvidenceKeys(input, required, optional) || input.schemaVersion !== 1 || input.ok !== true ||
    input.mode !== "https" || input.runId !== runId || input.testId !== SBX001_DIRECT_TEST_ID ||
    input.caseId !== expectedCase || input.origin !== origin || input.path !== "/healthz" ||
    input.connectionAttempts !== 1 || input.retryCount !== 0 || input.responseBodiesRetained !== false ||
    typeof input.guestNodeVersion !== "string" || !/^v\d+\.\d+\.\d+(?:[-+].*)?$/u.test(input.guestNodeVersion) ||
    typeof input.receivedResponse !== "boolean" || typeof input.timedOut !== "boolean" ||
    !Number.isInteger(input.durationMs) || Number(input.durationMs) < 0 || Number(input.durationMs) > 10_000 ||
    (input.statusCode !== undefined && (!Number.isInteger(input.statusCode) || Number(input.statusCode) < 100 ||
      Number(input.statusCode) > 599)) ||
    (input.errorCode !== undefined && (typeof input.errorCode !== "string" ||
      !/^[A-Za-z][A-Za-z0-9_]{0,63}$/u.test(input.errorCode)))) return fallback;
  return {
    schemaVersion: 1,
    ok: true,
    mode: "https",
    runId,
    testId: SBX001_DIRECT_TEST_ID,
    guestNodeVersion: input.guestNodeVersion,
    caseId: expectedCase,
    origin,
    path: "/healthz",
    connectionAttempts: 1,
    retryCount: 0,
    responseBodiesRetained: false,
    durationMs: input.durationMs as number,
    receivedResponse: input.receivedResponse,
    ...(input.statusCode === undefined ? {} : { statusCode: input.statusCode as number }),
    timedOut: input.timedOut,
    ...(input.errorCode === undefined ? {} : { errorCode: input.errorCode as string }),
  };
}

async function runGuest<T extends Sbx001GuestDnsEvidence | Sbx001GuestHttpsEvidence>(input: {
  sandbox: Sandbox;
  gate: RateGate;
  configuration: Record<string, unknown>;
  sanitize(value: unknown): T;
}): Promise<{ result: T; command: CommandEvidence }> {
  const encoded = Buffer.from(JSON.stringify(input.configuration)).toString("base64url");
  await input.gate.before();
  const startedAt = new Date().toISOString();
  const handle = await input.sandbox.runCommand({
    cmd: "node",
    args: [REMOTE_PROBE, encoded],
    timeoutMs: 10_000,
    signal: signal(25_000),
  });
  const [stdout, stderr] = await Promise.all([handle.stdout({ signal: signal() }), handle.stderr({ signal: signal() })]);
  if (Buffer.byteLength(stdout) > 16_384 || Buffer.byteLength(stderr) > 8_192) {
    throw new Error("guest command output exceeded its fixed bound");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    parsed = undefined;
  }
  return {
    result: input.sanitize(parsed),
    command: {
      commandId: handle.cmdId,
      exitCode: handle.exitCode,
      startedAt,
      completedAt: new Date().toISOString(),
      ...(handle.durationMs !== undefined ? { durationMs: handle.durationMs } : {}),
      stdoutRetained: false,
      stderrRetained: false,
    },
  };
}

async function cleanupSandbox(input: {
  sandbox?: Sandbox;
  createAttempted: boolean;
  sandboxName: string;
  sandboxTags: Record<string, string>;
  credentials: Credentials;
  gate: RateGate;
  adminOrigin: string;
  adminKey: string;
  runId: string;
  receiverConfigureAttempted: boolean;
  forbidden: string[];
  journal: Sbx001DirectRecoveryJournal;
  held: Sbx001DirectHeldState;
  allowSettledUnknownAbsence: boolean;
}): Promise<{ cleanup: Sbx001CleanupEvidence; finalReceiverSnapshot?: Sbx001ReceiverSnapshot }> {
  let sandbox = input.sandbox;
  let finalReceiverSnapshot: Sbx001ReceiverSnapshot | undefined;
  const persist = async (): Promise<void> => persistSbx001DirectJournal(input.held, input.journal);
  const cleanup: Sbx001CleanupEvidence = {
    sandboxCreateAttempted: input.createAttempted,
    sandboxRecovered: false,
    sandboxAlreadyAbsent: false,
    sandboxRecoveryChecks: 0,
    sandboxRecoveryObservationMs: 0,
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    absenceChecks: 0,
    absenceConfirmed: false,
    receiverConfigureAttempted: input.receiverConfigureAttempted,
    receiverAlreadyAbsent: false,
    receiverDeleteAttempted: false,
    receiverDeleted: false,
    receiverAbsenceChecks: 0,
    receiverAbsenceConfirmed: false,
    errors: [],
  };
  if (!sandbox && input.createAttempted) {
    try {
      await input.gate.before();
      try {
        const recovered = await Sandbox.get({
          name: input.sandboxName,
          resume: false,
          ...input.credentials,
          signal: signal(),
        });
        sandbox = await attributeSbx001RecoveredHandle({
          resource: recovered,
          sandboxName: input.sandboxName,
          sandboxTags: input.sandboxTags,
          journal: input.journal,
          persist,
        });
        cleanup.sandboxRecovered = true;
      } catch (error) {
        if (!isNotFound(error)) throw error;
        if (input.journal.sessionId === undefined &&
            (!input.allowSettledUnknownAbsence || !sbx001DirectCreateSettlementReached(input.journal))) {
          throw new Error("response-lost Sandbox creation remains inside the terminal/expiry settlement horizon");
        }
        const recovery = await pollForLateSbx001Resource({
          checks: LATE_CREATE_RECOVERY_CHECKS,
          intervalMs: LATE_CREATE_RECOVERY_INTERVAL_MS,
          lookup: async () => {
            try {
              await input.gate.before();
              return await Sandbox.get({
                name: input.sandboxName,
                resume: false,
                ...input.credentials,
                signal: signal(),
              });
            } catch (lateError) {
              if (isNotFound(lateError)) return undefined;
              throw lateError;
            }
          },
        });
        cleanup.sandboxRecoveryChecks = recovery.checks;
        cleanup.sandboxRecoveryObservationMs = recovery.observationMs;
        if (recovery.resource) {
          sandbox = await attributeSbx001RecoveredHandle({
            resource: recovery.resource,
            sandboxName: input.sandboxName,
            sandboxTags: input.sandboxTags,
            journal: input.journal,
            persist,
          });
          cleanup.sandboxRecovered = true;
        } else {
          await input.gate.before();
          const paginator = await Sandbox.list({
            ...sbx001SandboxPrefixListOptions(input.sandboxName),
            ...input.credentials,
            signal: signal(),
          });
          const items = await paginator.toArray();
          input.journal.sandboxPrefixAbsent = items.length === 0;
          await persist();
          if (!input.journal.sandboxPrefixAbsent) throw new Error("sandbox prefix remained present after settlement");
          cleanup.sandboxAlreadyAbsent = true;
          cleanup.absenceConfirmed = recovery.observationMs >= 29_500;
        }
      }
    } catch (error) {
      cleanup.errors.push(`orphan recovery: ${safeError(error, input.forbidden)}`);
    }
  }
  if (sandbox) {
    let stopError: unknown;
    let deleteError: unknown;
    cleanup.stopAttempted = true;
    input.journal.stopAttempted = true;
    await persist();
    try {
      await input.gate.before();
      await sandbox.stop({ signal: signal() });
      cleanup.stopped = true;
      input.journal.stopped = true;
      await persist();
    } catch (error) {
      stopError = error;
    }
    cleanup.deleteAttempted = true;
    input.journal.deleteAttempted = true;
    await persist();
    try {
      await input.gate.before();
      await sandbox.delete({ signal: signal() });
      cleanup.deleted = true;
      input.journal.deleted = true;
      await persist();
    } catch (error) {
      deleteError = error;
    }
    cleanup.absenceChecks = 0;
    for (let index = 0; index < RESOURCE_ABSENCE_CHECKS; index += 1) {
      if (index > 0) await delay(RESOURCE_ABSENCE_INTERVAL_MS);
      try {
        await input.gate.before();
        await Sandbox.get({ name: input.sandboxName, resume: false, ...input.credentials, signal: signal() });
      } catch (error) {
        if (isNotFound(error)) cleanup.absenceChecks += 1;
        else {
          cleanup.errors.push(`absence check: ${safeError(error, input.forbidden)}`);
          break;
        }
      }
    }
    cleanup.absenceConfirmed = cleanup.absenceChecks === RESOURCE_ABSENCE_CHECKS;
    input.journal.sandboxAbsenceChecks = cleanup.absenceChecks;
    if (cleanup.absenceConfirmed) {
      await input.gate.before();
      const paginator = await Sandbox.list({
        ...sbx001SandboxPrefixListOptions(input.sandboxName),
        ...input.credentials,
        signal: signal(),
      });
      input.journal.sandboxPrefixAbsent = (await paginator.toArray()).length === 0;
      cleanup.absenceConfirmed &&= input.journal.sandboxPrefixAbsent;
    }
    await persist();
    if (cleanup.absenceConfirmed) cleanup.deleted = true;
    else {
      if (stopError !== undefined) cleanup.errors.push(`stop: ${safeError(stopError, input.forbidden)}`);
      if (deleteError !== undefined) cleanup.errors.push(`delete: ${safeError(deleteError, input.forbidden)}`);
      if (stopError === undefined && deleteError === undefined) cleanup.errors.push("sandbox remained present after delete");
    }
  }
  if (input.receiverConfigureAttempted) {
    const receiverCleanup = await cleanupSbx001Receiver({
      receiverConfigureAttempted: input.receiverConfigureAttempted,
      runId: input.runId,
      journal: input.journal,
      forbidden: input.forbidden,
      persist,
      readFinal: async () => await adminRequestWithStatus({
        origin: input.adminOrigin,
        adminKey: input.adminKey,
        path: `/v1/sbx001/admin/runs/${input.runId}`,
        method: "GET",
        expectedStatus: [200, 404],
      }),
      deleteReceiver: async () => await adminRequestWithStatus({
        origin: input.adminOrigin,
        adminKey: input.adminKey,
        path: `/v1/sbx001/admin/runs/${input.runId}`,
        method: "DELETE",
        expectedStatus: [204, 404],
      }),
      checkAbsent: async () => {
        await adminRequest({
          origin: input.adminOrigin,
          adminKey: input.adminKey,
          path: `/v1/sbx001/admin/runs/${input.runId}`,
          method: "GET",
          expectedStatus: 404,
        });
      },
    });
    cleanup.receiverAlreadyAbsent = receiverCleanup.receiverAlreadyAbsent;
    cleanup.receiverDeleteAttempted = receiverCleanup.receiverDeleteAttempted;
    cleanup.receiverDeleted = receiverCleanup.receiverDeleted;
    cleanup.receiverAbsenceChecks = receiverCleanup.receiverAbsenceChecks;
    cleanup.receiverAbsenceConfirmed = receiverCleanup.receiverAbsenceConfirmed;
    cleanup.errors.push(...receiverCleanup.errors);
    finalReceiverSnapshot = receiverCleanup.finalReceiverSnapshot;
  }
  return { cleanup, ...(finalReceiverSnapshot ? { finalReceiverSnapshot } : {}) };
}

function cleanupComplete(
  cleanup: Sbx001CleanupEvidence,
  journal: Sbx001DirectRecoveryJournal,
): boolean {
  const sandboxSafe = !cleanup.sandboxCreateAttempted ||
    (cleanup.sandboxAlreadyAbsent && cleanup.sandboxRecoveryChecks === LATE_CREATE_RECOVERY_CHECKS &&
      cleanup.sandboxRecoveryObservationMs >= 29_500 && cleanup.absenceConfirmed &&
      journal.sandboxPrefixAbsent) ||
    (cleanup.stopAttempted && cleanup.deleteAttempted && cleanup.deleted && cleanup.absenceChecks === 3 &&
      cleanup.absenceConfirmed && journal.sandboxPrefixAbsent);
  const receiverSafe = !cleanup.receiverConfigureAttempted ||
    (cleanup.receiverAbsenceChecks === 3 && cleanup.receiverAbsenceConfirmed &&
      (cleanup.receiverAlreadyAbsent || (cleanup.receiverDeleteAttempted && cleanup.receiverDeleted)) &&
      (!journal.receiverConfigured || journal.finalReceiverSnapshotCaptured));
  return cleanup.errors.length === 0 && sandboxSafe && receiverSafe;
}

export function assessSbx001DirectAfterFinalReceiver(input: {
  assessmentInput: Parameters<typeof assessSbx001DirectWithIngress>[0];
  receiverConfigured: boolean;
  finalReceiverSnapshotCaptured: boolean;
  assess?: typeof assessSbx001DirectWithIngress;
}): ReturnType<typeof assessSbx001DirectWithIngress> {
  if (input.receiverConfigured && !input.finalReceiverSnapshotCaptured) {
    return {
      verdict: "error",
      candidate: false,
      severity: "unknown",
      controlsPassed: false,
      secretPhaseAuthorized: false,
      summary: "The configured receiver lacked a valid required final snapshot; older snapshots were not assessed.",
    };
  }
  return (input.assess ?? assessSbx001DirectWithIngress)(input.assessmentInput);
}

export function sbx001DirectRecoveryNeedsExternalCleanup(journal: Sbx001DirectRecoveryJournal): boolean {
  return journal.receiverConfigureAttemptedAt !== undefined || journal.createAttemptedAt !== undefined;
}

export function validateSbx001PendingExperimentArtifact(
  value: unknown,
  runId: string,
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("SBX-001 pending experiment artifact was invalid");
  }
  const artifact = value as Record<string, unknown>;
  if (!exactObjectKeys(artifact, [
    "schemaVersion", "visibility", "testId", "runId", "startedAt", "completedAt", "runtime", "assessment",
    "scope", "outsidePreflight", "sandbox", "policy", "guest", "commands", "receiver", "controllerArms",
    "receiverObservations", "expectedOperations", "secretGate", "requestBounds", "cleanup", "durableSafety",
    "reportability", "retention",
  ], ["executionError"])) {
    throw new Error("SBX-001 pending experiment artifact fields were not exact");
  }
  const assessment = artifact.assessment as Record<string, unknown> | undefined;
  const cleanup = artifact.cleanup as Record<string, unknown> | undefined;
  const durableSafety = artifact.durableSafety as Record<string, unknown> | undefined;
  const reportability = artifact.reportability as Record<string, unknown> | undefined;
  const retention = artifact.retention as Record<string, unknown> | undefined;
  const receiver = artifact.receiver as Record<string, unknown> | undefined;
  const allowedVerdicts = new Set(["candidate-high", "candidate-medium", "pass", "indeterminate", "error"]);
  const candidateVerdicts = new Set(["candidate-high", "candidate-medium"]);
  const expectedSeverity = new Map<string, string>([
    ["candidate-high", "high"],
    ["candidate-medium", "medium"],
    ["pass", "none"],
    ["indeterminate", "unknown"],
    ["error", "unknown"],
  ]);
  if (artifact.schemaVersion !== 1 || artifact.visibility !== "private" ||
      artifact.testId !== SBX001_DIRECT_TEST_ID || artifact.runId !== runId ||
      !canonicalTimestamp(artifact.startedAt) || !canonicalTimestamp(artifact.completedAt) ||
      Date.parse(artifact.completedAt) < Date.parse(artifact.startedAt) ||
      !assessment || !exactObjectKeys(assessment, [
        "verdict", "candidate", "severity", "controlsPassed", "secretPhaseAuthorized", "summary",
      ]) || typeof assessment.verdict !== "string" || !allowedVerdicts.has(assessment.verdict) ||
      typeof assessment.candidate !== "boolean" ||
      assessment.candidate !== candidateVerdicts.has(assessment.verdict) ||
      assessment.severity !== expectedSeverity.get(assessment.verdict) ||
      typeof assessment.controlsPassed !== "boolean" || typeof assessment.secretPhaseAuthorized !== "boolean" ||
      typeof assessment.summary !== "string" ||
      !cleanup || !exactObjectKeys(cleanup, [
        "sandboxCreateAttempted", "sandboxRecovered", "sandboxAlreadyAbsent", "sandboxRecoveryChecks",
        "sandboxRecoveryObservationMs", "stopAttempted", "stopped", "deleteAttempted", "deleted",
        "absenceChecks", "absenceConfirmed", "receiverConfigureAttempted", "receiverAlreadyAbsent",
        "receiverDeleteAttempted", "receiverDeleted", "receiverAbsenceChecks", "receiverAbsenceConfirmed", "errors",
      ]) || !Array.isArray(cleanup.errors) || cleanup.errors.length !== 0 ||
      !durableSafety || !exactObjectKeys(durableSafety, [
        "liveLockMode", "recoveryJournalMode", "finalReceiverSnapshotCaptured", "exactCleanupComplete",
        "artifactFsyncedBeforeJournalAndLockRelease", "localFinalizationPendingAtArtifactWrite",
      ]) || durableSafety.liveLockMode !== 0o600 || durableSafety.recoveryJournalMode !== 0o600 ||
      typeof durableSafety.finalReceiverSnapshotCaptured !== "boolean" ||
      durableSafety.exactCleanupComplete !== true ||
      durableSafety.artifactFsyncedBeforeJournalAndLockRelease !== true ||
      durableSafety.localFinalizationPendingAtArtifactWrite !== true ||
      !reportability || !exactObjectKeys(reportability, ["requiresFinalizationReceipt", "reportable"]) ||
      reportability.requiresFinalizationReceipt !== true || reportability.reportable !== false ||
      !retention || !exactObjectKeys(retention, [
        "rawQueryName", "rawOperatorSecret", "rawSecretDigest", "rawGuestConfiguration", "rawCommandOutput",
      ]) || retention.rawQueryName !== false || retention.rawOperatorSecret !== false ||
      retention.rawSecretDigest !== false || retention.rawGuestConfiguration !== false ||
      retention.rawCommandOutput !== false || !receiver || receiver.rawQueryNamesRetained !== false ||
      receiver.rawSecretsRetained !== false || receiver.rawSecretDigestsRetained !== false ||
      (artifact.executionError !== undefined && typeof artifact.executionError !== "string")) {
    throw new Error("SBX-001 pending experiment artifact failed exact finalization validation");
  }
  if (receiver.configured === true) sanitizeSbx001ReceiverSnapshot(receiver, runId);
  const cleanupBooleans = [
    "sandboxCreateAttempted", "sandboxRecovered", "sandboxAlreadyAbsent", "stopAttempted", "stopped",
    "deleteAttempted", "deleted", "absenceConfirmed", "receiverConfigureAttempted", "receiverAlreadyAbsent",
    "receiverDeleteAttempted", "receiverDeleted", "receiverAbsenceConfirmed",
  ];
  const cleanupCounts = [
    "sandboxRecoveryChecks", "sandboxRecoveryObservationMs", "absenceChecks", "receiverAbsenceChecks",
  ];
  const sandboxCleanupSafe = cleanup.sandboxCreateAttempted === false ||
    (cleanup.sandboxAlreadyAbsent === true && cleanup.sandboxRecoveryChecks === LATE_CREATE_RECOVERY_CHECKS &&
      typeof cleanup.sandboxRecoveryObservationMs === "number" && cleanup.sandboxRecoveryObservationMs >= 29_500 &&
      cleanup.absenceChecks === 0 && cleanup.absenceConfirmed === true) ||
    (cleanup.stopAttempted === true && cleanup.deleteAttempted === true && cleanup.deleted === true &&
      cleanup.absenceChecks === RESOURCE_ABSENCE_CHECKS && cleanup.absenceConfirmed === true);
  const receiverCleanupSafe = cleanup.receiverConfigureAttempted === false ||
    (cleanup.receiverAbsenceChecks === RESOURCE_ABSENCE_CHECKS && cleanup.receiverAbsenceConfirmed === true &&
      (cleanup.receiverAlreadyAbsent === true ||
        (cleanup.receiverDeleteAttempted === true && cleanup.receiverDeleted === true)));
  if (!cleanupBooleans.every((key) => typeof cleanup[key] === "boolean") ||
      !cleanupCounts.every((key) => Number.isInteger(cleanup[key]) && Number(cleanup[key]) >= 0) ||
      !sandboxCleanupSafe || !receiverCleanupSafe ||
      (receiver.configured === true && durableSafety.finalReceiverSnapshotCaptured !== true)) {
    throw new Error("SBX-001 pending experiment artifact cleanup proof was not exact");
  }
  const serialized = JSON.stringify(artifact);
  if (/"(?:queryName|secretSha256|rawSecret|secretBase32)"\s*:/u.test(serialized)) {
    throw new Error("SBX-001 pending experiment artifact retained forbidden sensitive material");
  }
  return artifact;
}

export async function releaseAndWriteSbx001FinalizationReceipt(input: {
  release(): Promise<void>;
  writeReceipt(): Promise<void>;
  afterRelease?: () => void | Promise<void>;
  afterReceipt?: () => void | Promise<void>;
}): Promise<void> {
  await input.release();
  await input.afterRelease?.();
  await input.writeReceipt();
  await input.afterReceipt?.();
}

export async function completeSbx001PendingFinalization<T>(input: {
  runId: string;
  readReceipt(): Promise<T | undefined>;
  retainedJournalExists(): Promise<boolean>;
  readPendingArtifact(): Promise<unknown | undefined>;
  writeReceipt(): Promise<T>;
}): Promise<{ outcome: "already-finalized" | "receipt-created"; receipt: T } | undefined> {
  const existing = await input.readReceipt();
  if (existing !== undefined) return { outcome: "already-finalized", receipt: existing };
  if (await input.retainedJournalExists()) return undefined;
  const pending = await input.readPendingArtifact();
  if (pending === undefined) return undefined;
  validateSbx001PendingExperimentArtifact(pending, input.runId);
  try {
    return { outcome: "receipt-created", receipt: await input.writeReceipt() };
  } catch (error) {
    const raced = await input.readReceipt();
    if (raced !== undefined) return { outcome: "already-finalized", receipt: raced };
    throw error;
  }
}

function sbx001FinalizationReceipt(runId: string, finalizedAt = new Date().toISOString()): Sbx001DirectFinalizationReceipt {
  return {
    schemaVersion: 1,
    testId: SBX001_DIRECT_TEST_ID,
    kind: "finalization-receipt",
    runId,
    artifactPath: sbx001DirectArtifactPath(runId),
    finalizedAt,
    artifactWritten: true,
    journalRemoved: true,
    lockReleased: true,
    rawQueryNamesRetained: false,
    rawSecretsRetained: false,
    rawSecretDigestsRetained: false,
  };
}

async function completeLocalSbx001PendingFinalization(runId: string): Promise<{
  outcome: "already-finalized" | "receipt-created";
  receipt: Sbx001DirectFinalizationReceipt;
} | undefined> {
  return await completeSbx001PendingFinalization({
    runId,
    readReceipt: async () => await readSbx001DirectFinalizationReceipt(runId),
    retainedJournalExists: async () => {
      try {
        await readSbx001DirectJournal(runId);
        return true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
        throw error;
      }
    },
    readPendingArtifact: async () => await readSbx001DirectPendingArtifact(runId),
    writeReceipt: async () => {
      const receipt = sbx001FinalizationReceipt(runId);
      await writeSbx001DirectFinalizationReceipt(receipt);
      return receipt;
    },
  });
}

export async function runCleanupOnlyRecovery(environment: NodeJS.ProcessEnv, runId: string): Promise<void> {
  const interruptedFinalizationCompleted = await resumeSbx001DirectInterruptedFinalization(runId);
  const localFinalization = await completeLocalSbx001PendingFinalization(runId);
  if (localFinalization) {
    process.stdout.write(`${JSON.stringify({
      testId: SBX001_DIRECT_TEST_ID,
      runId,
      recoveryOnly: true,
      mode: "cleanup-only",
      outcome: localFinalization.outcome,
      externalRequests: 0,
      artifactPath: localFinalization.receipt.artifactPath,
      finalizationReceiptPath: sbx001DirectFinalizationReceiptPath(runId),
      localStateReleased: true,
      reportable: true,
    }, null, 2)}\n`);
    return;
  }
  if (interruptedFinalizationCompleted) {
    process.stdout.write(`${JSON.stringify({
      testId: SBX001_DIRECT_TEST_ID,
      runId,
      mode: "cleanup-only",
      outcome: "interrupted-finalization-completed",
    }, null, 2)}\n`);
    return;
  }
  const held = await acquireSbx001DirectRecoveryState(runId);
  const journal = await readSbx001DirectJournal(runId);
  const recoveryAttemptId = randomUUID();
  if (!sbx001DirectRecoveryNeedsExternalCleanup(journal)) {
    const cleanup: Sbx001CleanupEvidence = {
      sandboxCreateAttempted: false,
      sandboxRecovered: false,
      sandboxAlreadyAbsent: false,
      sandboxRecoveryChecks: 0,
      sandboxRecoveryObservationMs: 0,
      stopAttempted: false,
      stopped: false,
      deleteAttempted: false,
      deleted: false,
      absenceChecks: 0,
      absenceConfirmed: false,
      receiverConfigureAttempted: false,
      receiverAlreadyAbsent: false,
      receiverDeleteAttempted: false,
      receiverDeleted: false,
      receiverAbsenceChecks: 0,
      receiverAbsenceConfirmed: false,
      errors: [],
    };
    const artifact = {
      schemaVersion: 1,
      visibility: "private",
      testId: SBX001_DIRECT_TEST_ID,
      runId,
      recoveryAttemptId,
      recoveryOnly: true,
      mode: "cleanup-only",
      outcome: "cleanup-complete",
      settledLocallyWithoutExternalState: true,
      cleanup,
      finalReceiverSnapshot: null,
      journal: {
        createAttempted: false,
        sandboxAttributed: false,
        finalReceiverSnapshotCaptured: false,
        rawQueryNamesRetained: false,
        rawSecretsRetained: false,
        rawSecretDigestsRetained: false,
      },
    };
    const path = sbx001DirectRecoveryArtifactPath(runId, recoveryAttemptId);
    journal.artifactWriteAttemptedAt = new Date().toISOString();
    await persistSbx001DirectJournal(held, journal);
    await writeSbx001DirectPrivateArtifact(path, artifact);
    journal.artifactWritten = true;
    journal.completed = true;
    await persistSbx001DirectJournal(held, journal);
    await releaseSbx001DirectState(held);
    process.stdout.write(`${JSON.stringify({
      testId: SBX001_DIRECT_TEST_ID,
      runId,
      recoveryOnly: true,
      mode: "cleanup-only",
      outcome: artifact.outcome,
      artifactPath: path,
    }, null, 2)}\n`);
    return;
  }

  let creds: Credentials;
  let adminKey: string;
  let adminOrigin: string;
  try {
    creds = credentials(environment);
    adminKey = strongSecret(required(environment, "SBX001_ADMIN_KEY"), "SBX001_ADMIN_KEY");
    adminOrigin = loopbackAdminOrigin(required(environment, "SBX001_ADMIN_ORIGIN"));
  } catch (error) {
    await held.liveLock.closeRetainingState();
    throw error;
  }
  const forbidden = [creds.token, adminKey];
  const gate = new RateGate(SBX001_MIN_DNS_INTERVAL_MS);
  const pendingExperimentAwaitedRelease = journal.completed && journal.artifactWritten;
  let cleanup: Sbx001CleanupEvidence | undefined;
  let finalReceiverSnapshot: Sbx001ReceiverSnapshot | undefined;
  let cleanupPassed = false;
  let executionError: string | undefined;
  try {
    await verifyAlias(creds.token, environment.SBX001_ALIAS_EMAIL_CONFIRMATION, gate);
    const result = await cleanupSandbox({
      createAttempted: journal.createAttemptedAt !== undefined,
      sandboxName: journal.sandboxName,
      sandboxTags: journal.tags,
      credentials: creds,
      gate,
      adminOrigin,
      adminKey,
      runId,
      receiverConfigureAttempted: journal.receiverConfigureAttemptedAt !== undefined,
      forbidden,
      journal,
      held,
      allowSettledUnknownAbsence: true,
    });
    cleanup = result.cleanup;
    finalReceiverSnapshot = result.finalReceiverSnapshot;
    cleanupPassed = cleanupComplete(cleanup, journal);
    if (!cleanupPassed) throw new Error("SBX-001 direct cleanup-only recovery remains uncertain");
  } catch (error) {
    executionError = safeError(error, forbidden);
    cleanup ??= {
      sandboxCreateAttempted: journal.createAttemptedAt !== undefined,
      sandboxRecovered: false,
      sandboxAlreadyAbsent: false,
      sandboxRecoveryChecks: 0,
      sandboxRecoveryObservationMs: 0,
      stopAttempted: false,
      stopped: false,
      deleteAttempted: false,
      deleted: false,
      absenceChecks: 0,
      absenceConfirmed: false,
      receiverConfigureAttempted: journal.receiverConfigureAttemptedAt !== undefined,
      receiverAlreadyAbsent: false,
      receiverDeleteAttempted: false,
      receiverDeleted: false,
      receiverAbsenceChecks: 0,
      receiverAbsenceConfirmed: false,
      errors: [executionError],
    };
  }
  if (!cleanup) throw new Error("SBX-001 direct recovery cleanup evidence was not initialized");
  const artifact = {
    schemaVersion: 1,
    visibility: "private",
    testId: SBX001_DIRECT_TEST_ID,
    runId,
    recoveryAttemptId,
    recoveryOnly: true,
    mode: "cleanup-only",
    outcome: cleanupPassed ? "cleanup-complete" : "cleanup-incomplete",
    cleanup,
    finalReceiverSnapshot: finalReceiverSnapshot ?? null,
    journal: {
      createAttempted: journal.createAttemptedAt !== undefined,
      sandboxAttributed: journal.sandboxAttributed,
      finalReceiverSnapshotCaptured: journal.finalReceiverSnapshotCaptured,
      rawQueryNamesRetained: false,
      rawSecretsRetained: false,
      rawSecretDigestsRetained: false,
    },
    ...(executionError ? { executionError } : {}),
  };
  const path = sbx001DirectRecoveryArtifactPath(runId, recoveryAttemptId);
  journal.artifactWriteAttemptedAt = new Date().toISOString();
  await persistSbx001DirectJournal(held, journal);
  await writeSbx001DirectPrivateArtifact(path, artifact);
  let pendingFinalization: Awaited<ReturnType<typeof completeLocalSbx001PendingFinalization>>;
  if (cleanupPassed) {
    journal.artifactWritten = true;
    journal.completed = true;
    await persistSbx001DirectJournal(held, journal);
    await releaseSbx001DirectState(held);
    if (pendingExperimentAwaitedRelease) {
      pendingFinalization = await completeLocalSbx001PendingFinalization(runId);
      if (pendingFinalization === undefined) {
        throw new Error("SBX-001 released pending experiment lacked its finalization receipt transition");
      }
    }
  } else {
    await held.liveLock.closeRetainingState();
  }
  process.stdout.write(`${JSON.stringify({
    testId: SBX001_DIRECT_TEST_ID,
    runId,
    mode: "cleanup-only",
    outcome: artifact.outcome,
    artifactPath: path,
    ...(pendingFinalization ? {
      pendingExperimentOutcome: pendingFinalization.outcome,
      finalizationReceiptPath: sbx001DirectFinalizationReceiptPath(runId),
      reportable: true,
    } : {}),
  }, null, 2)}\n`);
  if (!cleanupPassed) process.exitCode = 1;
}

async function main(): Promise<void> {
  const environment = process.env;
  if (environment.SBX001_SCOPE_CONFIRMATION !== SBX001_DIRECT_SCOPE_CONFIRMATION) {
    throw new Error(`SBX001_SCOPE_CONFIRMATION must equal ${SBX001_DIRECT_SCOPE_CONFIRMATION}`);
  }
  if (environment.SBX001_RECOVERY_RUN_ID !== undefined) {
    await runCleanupOnlyRecovery(environment, environment.SBX001_RECOVERY_RUN_ID);
    return;
  }
  const creds = credentials(environment);
  const adminKey = strongSecret(required(environment, "SBX001_ADMIN_KEY"), "SBX001_ADMIN_KEY");
  const proofKey = strongSecret(required(environment, "SBX001_PROOF_KEY"), "SBX001_PROOF_KEY");
  const adminOrigin = loopbackAdminOrigin(required(environment, "SBX001_ADMIN_ORIGIN"));
  const authoritativeZone = canonicalDnsName(required(environment, "SBX001_AUTHORITATIVE_ZONE"), "authoritative zone");
  if (!authoritativeZone.endsWith(OWNED_ZONE_SUFFIX)) throw new Error("authoritative zone must be under the owned form-app.app zone");
  const nameserverHostname = canonicalDnsName(required(environment, "SBX001_NAMESERVER_HOSTNAME"), "nameserver hostname");
  if (!nameserverHostname.endsWith(OWNED_ZONE_SUFFIX)) throw new Error("nameserver hostname must be under the owned form-app.app zone");
  const authoritativeIPv4 = publicIPv4(required(environment, "SBX001_AUTHORITATIVE_IPV4"), "authoritative IPv4");
  const httpsControlOrigin = ownedHttpsOrigin(required(environment, "SBX001_HTTPS_CONTROL_ORIGIN"));
  const journal = createSbx001DirectJournal();
  const runId = journal.runId;
  const usedQueryNonces = new Set<string>();
  const nextQueryNonce = (): string => {
    const nonce = freshQueryNonce(usedQueryNonces);
    usedQueryNonces.add(nonce);
    return nonce;
  };
  const publicNonces = {
    [SBX001_CASES.outsideUdp]: nextQueryNonce(),
    [SBX001_CASES.outsideTcp]: nextQueryNonce(),
    [SBX001_CASES.allowPublic]: nextQueryNonce(),
    [SBX001_CASES.denyPublic]: nextQueryNonce(),
  } as const;
  const sandboxName = journal.sandboxName;
  const sandboxTags = journal.tags;
  const controllerGate = new RateGate(SBX001_MIN_DNS_INTERVAL_MS);
  const dnsGate = new RateGate(SBX001_MIN_DNS_INTERVAL_MS);
  const forbidden = [creds.token, adminKey, proofKey, ...Object.values(publicNonces)];
  const held = await acquireSbx001DirectState(journal);
  const persist = async (): Promise<void> => persistSbx001DirectJournal(held, journal);

  const publicLabels = {
    [SBX001_CASES.outsideUdp]: publicDnsLabel(SBX001_CASES.outsideUdp, publicNonces[SBX001_CASES.outsideUdp]),
    [SBX001_CASES.outsideTcp]: publicDnsLabel(SBX001_CASES.outsideTcp, publicNonces[SBX001_CASES.outsideTcp]),
    [SBX001_CASES.allowPublic]: publicDnsLabel(SBX001_CASES.allowPublic, publicNonces[SBX001_CASES.allowPublic]),
    [SBX001_CASES.denyPublic]: publicDnsLabel(SBX001_CASES.denyPublic, publicNonces[SBX001_CASES.denyPublic]),
  };
  forbidden.push(...Object.values(publicLabels));
  const expectedOperations = {
    [SBX001_CASES.outsideUdp]: derivePublicDnsOperationId(proofKey, runId, SBX001_CASES.outsideUdp, publicLabels[SBX001_CASES.outsideUdp]),
    [SBX001_CASES.outsideTcp]: derivePublicDnsOperationId(proofKey, runId, SBX001_CASES.outsideTcp, publicLabels[SBX001_CASES.outsideTcp]),
    [SBX001_CASES.allowPublic]: derivePublicDnsOperationId(proofKey, runId, SBX001_CASES.allowPublic, publicLabels[SBX001_CASES.allowPublic]),
    [SBX001_CASES.denyPublic]: derivePublicDnsOperationId(proofKey, runId, SBX001_CASES.denyPublic, publicLabels[SBX001_CASES.denyPublic]),
    [SBX001_CASES.denySecret]: "dns_" + "A".repeat(43),
  };
  const startedAt = new Date().toISOString();
  let sandbox: Sandbox | undefined;
  let createAttempted = false;
  let receiverConfigureAttempted = false;
  let identityProof: EligibleAliasIdentityProof | undefined;
  let receiver: Sbx001ReceiverSnapshot = {
    configured: false,
    receipts: [],
    arms: [],
    secretRegistered: false,
    rawQueryNamesRetained: false,
    rawSecretsRetained: false,
    rawSecretDigestsRetained: false,
  };
  let identityAndScopePassed = false;
  let delegation = {
    nameservers: [] as string[],
    nameserverIPv4: [] as string[],
    nameserverIPv6: [] as string[],
    nameserverCname: [] as string[],
    passed: false,
  };
  let outsideHttps = { passed: false } as { statusCode?: number; passed: boolean };
  let outsideUdp: DirectDnsPreflight = {
    transport: "udp", attempted: false, retryCount: 0, responseReceived: false,
    authoritativeResponseValidated: false, timedOut: false,
  };
  let outsideTcp: DirectDnsPreflight = {
    transport: "tcp", attempted: false, retryCount: 0, responseReceived: false,
    authoritativeResponseValidated: false, timedOut: false,
  };
  let allowReadback = emptyPolicy();
  let denyReadback = emptyPolicy();
  let denyPostReadback = emptyPolicy();
  let allowHttps = emptyHttps("allow-https", runId, httpsControlOrigin);
  let denyHttps = emptyHttps("deny-https", runId, httpsControlOrigin);
  let allowDns = emptyDns("allow-public", runId);
  let denyDns = emptyDns("deny-public", runId);
  let secretDns: Sbx001GuestDnsEvidence | undefined;
  const commands: Record<string, CommandEvidence> = {};
  const receiverObservations: Partial<Record<Sbx001CaseId, Sbx001ReceiptObservationEvidence>> = {};
  const controllerArms: Partial<Record<Sbx001CaseId, Sbx001ControllerArmEvidence>> = {};
  let denyPublicReceiptObservedAt: string | undefined;
  let denyPublicReceiptFetchedAt: string | undefined;
  let secretCreatedAt: string | undefined;
  let secretRegisteredAt: string | undefined;
  let secretWrittenAt: string | undefined;
  let secretAttempted = false;
  let guestDnsProbeInvocations = 0;
  let secretStagedBeforePublicSignal = false;
  let secretCommitment: string | undefined;
  let secretNonce: string | undefined;
  let guestProbeSha256: string | undefined;
  let sandboxProvenance: {
    name: string;
    sessionId: string;
    sessionCreatedAt: string;
    sandboxCreatedAt: string;
    region?: string;
    runtime?: string;
    image?: string;
    persistent: boolean;
  } | undefined;
  let executionError: string | undefined;
  let finalReceiverSnapshotCaptured = false;
  let localStateReleased = false;
  let finalizationReceiptWritten = false;
  let cleanup: Sbx001CleanupEvidence = {
    sandboxCreateAttempted: false,
    sandboxRecovered: false,
    sandboxAlreadyAbsent: false,
    sandboxRecoveryChecks: 0,
    sandboxRecoveryObservationMs: 0,
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    absenceChecks: 0,
    absenceConfirmed: false,
    receiverConfigureAttempted: false,
    receiverAlreadyAbsent: false,
    receiverDeleteAttempted: false,
    receiverDeleted: false,
    receiverAbsenceChecks: 0,
    receiverAbsenceConfirmed: false,
    errors: [],
  };

  try {
    identityProof = await verifyAlias(creds.token, environment.SBX001_ALIAS_EMAIL_CONFIRMATION, controllerGate);
    identityAndScopePassed = identityProof.email === ELIGIBLE_ALIAS_EMAIL && identityProof.teamId === creds.teamId &&
      identityProof.projectId === creds.projectId;
    const health = await fetch(new URL("/healthz", adminOrigin), { signal: signal(5_000) });
    if (health.status !== 200) throw new Error(`receiver health returned ${health.status}`);
    await health.body?.cancel();
    journal.receiverConfigureAttemptedAt = new Date().toISOString();
    await persist();
    receiverConfigureAttempted = true;
    await adminRequest({
      origin: adminOrigin,
      adminKey,
      path: `/v1/sbx001/admin/runs/${runId}`,
      method: "PUT",
      expectedStatus: 204,
      body: {
        runId,
        testId: SBX001_DIRECT_TEST_ID,
        authoritativeZone,
        nameserverHostname,
        answerIPv4: "192.0.2.1",
        observationWindowMs: SBX001_RECEIVER_WINDOW_MS,
        publicLabels,
      },
    });
    journal.receiverConfigured = true;
    await persist();

    delegation = await delegationPreflight(authoritativeZone, nameserverHostname, authoritativeIPv4);
    if (!delegation.passed) throw new Error("owned authoritative-zone NS/A delegation preflight failed");
    outsideHttps = await outsideHttpsPreflight(httpsControlOrigin);
    if (!outsideHttps.passed) throw new Error("owned HTTPS control outside preflight failed");
    controllerArms[SBX001_CASES.outsideUdp] = await armReceiverCase({
      origin: adminOrigin,
      adminKey,
      runId,
      caseId: SBX001_CASES.outsideUdp,
      operationId: expectedOperations[SBX001_CASES.outsideUdp],
    });
    outsideUdp = await directUdpQuery(
      authoritativeIPv4,
      53,
      publicDnsName(SBX001_CASES.outsideUdp, publicNonces[SBX001_CASES.outsideUdp], authoritativeZone),
      dnsGate,
    );
    const outsideUdpObservation = await observeReceiverReceipt({
      origin: adminOrigin,
      adminKey,
      runId,
      caseId: SBX001_CASES.outsideUdp,
      operationId: expectedOperations[SBX001_CASES.outsideUdp],
    });
    receiverObservations[SBX001_CASES.outsideUdp] = outsideUdpObservation.observation;
    receiver = outsideUdpObservation.snapshot;
    if (!outsideUdp.authoritativeResponseValidated || !outsideUdpObservation.receiptObserved) {
      throw new Error("direct authoritative UDP outside preflight failed");
    }
    controllerArms[SBX001_CASES.outsideTcp] = await armReceiverCase({
      origin: adminOrigin,
      adminKey,
      runId,
      caseId: SBX001_CASES.outsideTcp,
      operationId: expectedOperations[SBX001_CASES.outsideTcp],
    });
    outsideTcp = await directTcpQuery(
      authoritativeIPv4,
      53,
      publicDnsName(SBX001_CASES.outsideTcp, publicNonces[SBX001_CASES.outsideTcp], authoritativeZone),
      dnsGate,
    );
    const outsideTcpObservation = await observeReceiverReceipt({
      origin: adminOrigin,
      adminKey,
      runId,
      caseId: SBX001_CASES.outsideTcp,
      operationId: expectedOperations[SBX001_CASES.outsideTcp],
    });
    receiverObservations[SBX001_CASES.outsideTcp] = outsideTcpObservation.observation;
    receiver = outsideTcpObservation.snapshot;
    if (!outsideTcp.authoritativeResponseValidated || !outsideTcpObservation.receiptObserved) {
      throw new Error("direct authoritative TCP outside preflight failed");
    }

    const probeSource = await readFile(resolve("guest/dns-authoritative-probe.mjs"), "utf8");
    guestProbeSha256 = createHash("sha256").update(probeSource).digest("hex");
    if (forbidden.some((value) => probeSource.includes(value))) throw new Error("guest source contains controller-only material");
    await controllerGate.before();
    journal.createAttemptedAt = new Date().toISOString();
    await persist();
    createAttempted = true;
    try {
      sandbox = await Sandbox.create({
        name: sandboxName,
        persistent: false,
        timeout: SBX001_DIRECT_SANDBOX_TIMEOUT_MS,
        networkPolicy: "allow-all",
        tags: sandboxTags,
        ...creds,
        signal: signal(45_000),
      });
    } finally {
      journal.createRequestSettledAt = new Date().toISOString();
      await persist();
    }
    const sessionId = sandbox.currentSession().sessionId;
    const createdSession = sandbox.currentSession();
    sandboxProvenance = {
      name: sandbox.name,
      sessionId,
      sessionCreatedAt: createdSession.createdAt.toISOString(),
      sandboxCreatedAt: sandbox.createdAt.toISOString(),
      ...(sandbox.region === undefined ? {} : { region: sandbox.region }),
      ...(sandbox.runtime === undefined ? {} : { runtime: sandbox.runtime }),
      ...(sandbox.image === undefined ? {} : { image: sandbox.image }),
      persistent: sandbox.persistent,
    };
    journal.sessionId = sessionId;
    journal.sandboxAttributed = /^sbx_[A-Za-z0-9_-]{8,192}$/u.test(sessionId) && sandbox.name === sandboxName &&
      sandbox.persistent === false && exactStringRecord(sandbox.tags, sandboxTags);
    await persist();
    if (!journal.sandboxAttributed) throw new Error("created Sandbox provenance was not exact");
    await controllerGate.before();
    await sandbox.writeFiles([{ path: REMOTE_PROBE, content: probeSource, mode: 0o700 }], { signal: signal() });
    allowReadback = await policyReadback(sandbox, sandboxName, sessionId, creds, "allow-all", controllerGate);
    if (!allowReadback.passed) throw new Error("allow-all lacked exact active and independent same-session readback");

    const common = {
      scopeConfirmation: SBX001_DIRECT_SCOPE_CONFIRMATION,
      runId,
      testId: SBX001_DIRECT_TEST_ID,
    };
    const allowHttpsCapture = await runGuest({
      sandbox,
      gate: controllerGate,
      configuration: { ...common, mode: "https", caseId: "allow-https", endpointOrigin: httpsControlOrigin, timeoutMs: 3_000 },
      sanitize: (value) => sanitizeSbx001HttpsEvidence(value, "allow-https", runId, httpsControlOrigin),
    });
    allowHttps = allowHttpsCapture.result;
    commands.allowHttps = allowHttpsCapture.command;
    if (!(allowHttps.ok && allowHttps.receivedResponse && allowHttps.statusCode === 200)) {
      throw new Error("allow-all ordinary HTTPS control failed");
    }
    controllerArms[SBX001_CASES.allowPublic] = await armReceiverCase({
      origin: adminOrigin,
      adminKey,
      runId,
      caseId: SBX001_CASES.allowPublic,
      operationId: expectedOperations[SBX001_CASES.allowPublic],
    });
    guestDnsProbeInvocations += 1;
    const allowDnsCapture = await runGuest({
      sandbox,
      gate: controllerGate,
      configuration: {
        ...common,
        mode: "dns",
        caseId: SBX001_CASES.allowPublic,
        authoritativeZone,
        queryNonce: publicNonces[SBX001_CASES.allowPublic],
        timeoutMs: DNS_TIMEOUT_MS,
      },
      sanitize: (value) => sanitizeSbx001DnsEvidence(value, SBX001_CASES.allowPublic, runId),
    });
    allowDns = allowDnsCapture.result;
    commands.allowDns = allowDnsCapture.command;
    if (allowDnsCapture.command.exitCode !== 0 || !allowDns.sendInvoked || !allowDns.datagramAcceptedByKernel) {
      throw new Error("allow-all one-shot DNS command did not complete its exact local attempt");
    }
    const allowObservation = await observeReceiverReceipt({
      origin: adminOrigin,
      adminKey,
      runId,
      caseId: SBX001_CASES.allowPublic,
      operationId: expectedOperations[SBX001_CASES.allowPublic],
    });
    receiverObservations[SBX001_CASES.allowPublic] = allowObservation.observation;
    receiver = allowObservation.snapshot;
    if (!allowObservation.receiptObserved) {
      throw new Error("allow-all public query was not observed by the authoritative receiver");
    }

    await controllerGate.before();
    await sandbox.update({ networkPolicy: "deny-all" }, { signal: signal() });
    denyReadback = await policyReadback(sandbox, sandboxName, sessionId, creds, "deny-all", controllerGate);
    if (!denyReadback.passed) throw new Error("deny-all lacked exact active and independent same-session readback");
    const denyHttpsCapture = await runGuest({
      sandbox,
      gate: controllerGate,
      configuration: { ...common, mode: "https", caseId: "deny-https", endpointOrigin: httpsControlOrigin, timeoutMs: 3_000 },
      sanitize: (value) => sanitizeSbx001HttpsEvidence(value, "deny-https", runId, httpsControlOrigin),
    });
    denyHttps = denyHttpsCapture.result;
    commands.denyHttps = denyHttpsCapture.command;
    if (!(denyHttps.ok && !denyHttps.receivedResponse && !denyHttps.timedOut &&
      (denyHttps.errorCode === "EAI_AGAIN" || denyHttps.errorCode === "EHOSTUNREACH"))) {
      throw new Error("ordinary public HTTPS was not actively blocked under deny-all");
    }
    controllerArms[SBX001_CASES.denyPublic] = await armReceiverCase({
      origin: adminOrigin,
      adminKey,
      runId,
      caseId: SBX001_CASES.denyPublic,
      operationId: expectedOperations[SBX001_CASES.denyPublic],
    });
    guestDnsProbeInvocations += 1;
    const denyDnsCapture = await runGuest({
      sandbox,
      gate: controllerGate,
      configuration: {
        ...common,
        mode: "dns",
        caseId: SBX001_CASES.denyPublic,
        authoritativeZone,
        queryNonce: publicNonces[SBX001_CASES.denyPublic],
        timeoutMs: DNS_TIMEOUT_MS,
      },
      sanitize: (value) => sanitizeSbx001DnsEvidence(value, SBX001_CASES.denyPublic, runId),
    });
    denyDns = denyDnsCapture.result;
    commands.denyDns = denyDnsCapture.command;
    const denyDnsActiveLocalBlock = !denyDns.datagramAcceptedByKernel && !denyDns.responseReceived && !denyDns.timedOut &&
      denyDns.errorCode !== undefined && ["EACCES", "EHOSTUNREACH", "ENETUNREACH", "EPERM"].includes(denyDns.errorCode);
    if (denyDnsCapture.command.exitCode !== 0 || !denyDns.sendInvoked ||
      (!denyDns.datagramAcceptedByKernel && !denyDnsActiveLocalBlock)) {
      throw new Error("deny-all one-shot public DNS command did not complete its exact local attempt");
    }
    const denyObservation = await observeReceiverReceipt({
      origin: adminOrigin,
      adminKey,
      runId,
      caseId: SBX001_CASES.denyPublic,
      operationId: expectedOperations[SBX001_CASES.denyPublic],
    });
    receiverObservations[SBX001_CASES.denyPublic] = denyObservation.observation;
    receiver = denyObservation.snapshot;
    const denyReceipt = receiver.receipts.find((receipt) => receipt.caseId === SBX001_CASES.denyPublic &&
      receipt.operationId === expectedOperations[SBX001_CASES.denyPublic]);
    if (denyReceipt) {
      denyPublicReceiptObservedAt = denyReceipt.observedAt;
      denyPublicReceiptFetchedAt = denyObservation.observation.completedAt;
      const rawSecret = randomBytes(SBX001_SECRET_BYTES);
      const readbackSecret = Buffer.from(rawSecret);
      secretCreatedAt = new Date().toISOString();
      secretStagedBeforePublicSignal = Date.parse(secretCreatedAt) < Date.parse(denyPublicReceiptFetchedAt);
      secretCommitment = deriveSecretDnsCommitment(proofKey, runId, rawSecret);
      secretNonce = nextQueryNonce();
      forbidden.push(secretNonce);
      expectedOperations[SBX001_CASES.denySecret] = deriveSecretDnsOperationId(proofKey, runId, secretCommitment);
      try {
        await adminRequest({
          origin: adminOrigin,
          adminKey,
          path: `/v1/sbx001/admin/runs/${runId}/secret`,
          method: "PUT",
          expectedStatus: 204,
          body: { secretCommitment, queryNonce: secretNonce },
        });
        secretRegisteredAt = new Date().toISOString();
        await controllerGate.before();
        await sandbox.writeFiles([{ path: SBX001_SECRET_FILE, content: rawSecret, mode: 0o600 }], { signal: signal() });
        secretWrittenAt = new Date().toISOString();
        await controllerGate.before();
        const readback = await sandbox.readFileToBuffer({ path: SBX001_SECRET_FILE }, { signal: signal() });
        const exactReadback = readback !== null && readback.equals(readbackSecret);
        readback?.fill(0);
        if (!exactReadback) throw new Error("mode-0600 operator-secret write/readback failed");
        controllerArms[SBX001_CASES.denySecret] = await armReceiverCase({
          origin: adminOrigin,
          adminKey,
          runId,
          caseId: SBX001_CASES.denySecret,
          operationId: expectedOperations[SBX001_CASES.denySecret],
        });
      } finally {
        rawSecret.fill(0);
        readbackSecret.fill(0);
      }
      secretAttempted = true;
      guestDnsProbeInvocations += 1;
      const secretDnsCapture = await runGuest({
        sandbox,
        gate: controllerGate,
        configuration: {
          ...common,
          mode: "dns",
          caseId: SBX001_CASES.denySecret,
          authoritativeZone,
          queryNonce: secretNonce,
          timeoutMs: DNS_TIMEOUT_MS,
          secretFilePath: SBX001_SECRET_FILE,
        },
        sanitize: (value) => sanitizeSbx001DnsEvidence(value, SBX001_CASES.denySecret, runId),
      });
      secretDns = secretDnsCapture.result;
      commands.secretDns = secretDnsCapture.command;
      const secretObservation = await observeReceiverReceipt({
        origin: adminOrigin,
        adminKey,
        runId,
        caseId: SBX001_CASES.denySecret,
        operationId: expectedOperations[SBX001_CASES.denySecret],
      });
      receiverObservations[SBX001_CASES.denySecret] = secretObservation.observation;
      receiver = secretObservation.snapshot;
    }
    denyPostReadback = await policyReadback(sandbox, sandboxName, sessionId, creds, "deny-all", controllerGate);
    if (!denyPostReadback.passed) throw new Error("post-query deny-all same-session readback failed");
  } catch (error) {
    executionError = safeError(error, forbidden);
  } finally {
    try {
      const cleanupResult = await cleanupSandbox({
        ...(sandbox ? { sandbox } : {}),
        createAttempted,
        sandboxName,
        sandboxTags,
        credentials: creds,
        gate: controllerGate,
        adminOrigin,
        adminKey,
        runId,
        receiverConfigureAttempted,
        forbidden,
        journal,
        held,
        allowSettledUnknownAbsence: false,
      });
      cleanup = cleanupResult.cleanup;
      if (cleanupResult.finalReceiverSnapshot) {
        receiver = cleanupResult.finalReceiverSnapshot;
        finalReceiverSnapshotCaptured = true;
      }
    } catch (error) {
      executionError ??= safeError(error, forbidden);
      cleanup.errors.push(`durable cleanup: ${safeError(error, forbidden)}`);
    }
  }

  const assessmentInput: Parameters<typeof assessSbx001DirectWithIngress>[0] = {
    runId,
    authoritativeZone,
    httpsControlOrigin,
    identityAndScopePassed,
    delegationPreflightPassed: delegation.passed,
    outsideHttpsPassed: outsideHttps.passed,
    outsideUdpPassed: outsideUdp.authoritativeResponseValidated,
    outsideTcpPassed: outsideTcp.authoritativeResponseValidated,
    allowReadback,
    allowHttps,
    allowDns,
    denyReadback,
    denyPostReadback,
    denyHttps,
    denyDns,
    ...(secretDns ? { secretDns } : {}),
    receiver,
    controllerArms,
    receiverObservations,
    expectedOperations,
    ...(denyPublicReceiptObservedAt ? { denyPublicReceiptObservedAt } : {}),
    ...(denyPublicReceiptFetchedAt ? { denyPublicReceiptFetchedAt } : {}),
    ...(secretCreatedAt ? { secretCreatedAt } : {}),
    ...(secretRegisteredAt ? { secretRegisteredAt } : {}),
    ...(secretWrittenAt ? { secretWrittenAt } : {}),
    secretAttempted,
    secretStagedBeforePublicSignal,
    cleanup,
    retention: {
      rawQueryName: false,
      rawOperatorSecret: false,
      rawSecretDigest: false,
      rawGuestConfiguration: false,
      rawCommandOutput: false,
    },
    ...(executionError ? { executionError: true } : {}),
  };
  const assessment = assessSbx001DirectAfterFinalReceiver({
    assessmentInput,
    receiverConfigured: journal.receiverConfigured,
    finalReceiverSnapshotCaptured,
  });
  let sandboxSdkVersion = "unavailable";
  try {
    const sdkPackage = JSON.parse(await readFile(resolve("node_modules/@vercel/sandbox/package.json"), "utf8")) as {
      version?: unknown;
    };
    if (typeof sdkPackage.version === "string" && /^\d+\.\d+\.\d+(?:[-+].*)?$/u.test(sdkPackage.version)) {
      sandboxSdkVersion = sdkPackage.version;
    }
  } catch {
    // Candidate evidence remains explicit about unavailable local package provenance.
  }
  const exactCleanupComplete = cleanupComplete(cleanup, journal);
  const evidence = {
    schemaVersion: 1,
    visibility: "private",
    testId: SBX001_DIRECT_TEST_ID,
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    runtime: {
      controllerNode: process.version,
      sandboxSdk: sandboxSdkVersion,
      guestProbeSha256: guestProbeSha256 ?? "unavailable",
      requestedImage: "vercel/sandbox/universal:latest (SDK default)",
    },
    assessment,
    scope: {
      identityProof: identityProof ?? null,
      teamId: creds.teamId,
      projectId: creds.projectId,
      authoritativeZone,
      authoritativeIPv4,
      nameserverHostname,
      httpsControlOrigin,
      manualScopeConfirmationPassed: true,
      identityPassed: identityAndScopePassed,
      dnsDelegationControlPassed: delegation.passed,
      httpsEndpointControlPassed: outsideHttps.passed,
      receiverAdminWasLoopbackForward: true,
    },
    outsidePreflight: { delegation, https: outsideHttps, udp: outsideUdp, tcp: outsideTcp },
    sandbox: sandboxProvenance ?? { name: sandboxName },
    policy: { allowReadback, denyReadback, denyPostReadback },
    guest: { allowHttps, allowDns, denyHttps, denyDns, ...(secretDns ? { secretDns } : {}) },
    commands,
    receiver,
    controllerArms,
    receiverObservations,
    expectedOperations,
    secretGate: {
      publicReceiptObserved: denyPublicReceiptObservedAt !== undefined,
      denyPublicReceiptObservedAt,
      denyPublicReceiptFetchedAt,
      secretCreatedAt,
      secretRegisteredAt,
      secretWrittenAt,
      secretAttempted,
      secretStagedBeforePublicSignal,
      secretCommitment,
      secretQueryNoncePersisted: false,
      rawSecretPersisted: false,
      rawSecretDigestPersisted: false,
      rawSecretQueryNamePersisted: false,
    },
    requestBounds: {
      maximumGuestDnsProbeInvocations: 3,
      actualGuestDnsProbeInvocations: guestDnsProbeInvocations,
      maximumControllerDirectDnsQueries: 2,
      actualControllerDirectDnsQueries: Number(outsideUdp.attempted) + Number(outsideTcp.attempted),
      guestDnsRetries: 0,
      minimumDnsIntervalMs: SBX001_MIN_DNS_INTERVAL_MS,
      maximumQueriesPerSecond: 4,
      receiverObservationWindowMs: SBX001_RECEIPT_OBSERVATION_MS,
      receiverPollingIntervalMs: RECEIPT_POLL_INTERVAL_MS,
    },
    cleanup,
    durableSafety: {
      liveLockMode: held.lockMode,
      recoveryJournalMode: held.journalMode,
      finalReceiverSnapshotCaptured,
      exactCleanupComplete,
      artifactFsyncedBeforeJournalAndLockRelease: true,
      localFinalizationPendingAtArtifactWrite: true,
    },
    reportability: {
      requiresFinalizationReceipt: true,
      reportable: false,
    },
    retention: {
      rawQueryName: false,
      rawOperatorSecret: false,
      rawSecretDigest: false,
      rawGuestConfiguration: false,
      rawCommandOutput: false,
    },
    ...(executionError ? { executionError } : {}),
  };
  const serialized = `${JSON.stringify(evidence, null, 2)}\n`;
  if (forbidden.some((value) => value && serialized.includes(value)) ||
    /"(?:queryName|secretSha256|rawSecret|secretBase32)"\s*:/u.test(serialized)) {
    throw new Error("refusing to persist a credential, raw query name, raw secret, or raw secret digest");
  }
  const evidencePath = sbx001DirectArtifactPath(runId);
  journal.artifactWriteAttemptedAt = new Date().toISOString();
  await persist();
  await writeSbx001DirectPrivateArtifact(evidencePath, JSON.parse(serialized));
  journal.artifactWritten = true;
  journal.completed = exactCleanupComplete;
  await persist();
  const finalizationReceiptPath = sbx001DirectFinalizationReceiptPath(runId);
  try {
    if (exactCleanupComplete) {
      await releaseAndWriteSbx001FinalizationReceipt({
        release: async () => {
          await releaseSbx001DirectState(held);
          localStateReleased = true;
        },
        writeReceipt: async () => {
          const finalized = await completeLocalSbx001PendingFinalization(runId);
          if (finalized === undefined) {
            throw new Error("SBX-001 pending experiment artifact disappeared before receipt");
          }
          finalizationReceiptWritten = true;
        },
      });
    } else {
      await held.liveLock.closeRetainingState();
    }
  } catch (error) {
    if (!localStateReleased) await held.liveLock.closeRetainingState().catch(() => undefined);
    process.stderr.write(localStateReleased
      ? `SBX-001 direct immutable artifact remains pending its finalization receipt: ${safeError(error, forbidden)}\n`
      : `SBX-001 direct finalization retained recovery state: ${safeError(error, forbidden)}\n`);
    process.exitCode = 1;
  }
  const reportable = localStateReleased && finalizationReceiptWritten;
  const outputAssessment = reportable ? assessment : {
    verdict: "indeterminate" as const,
    candidate: false,
    severity: "unknown" as const,
    controlsPassed: false,
    secretPhaseAuthorized: false,
    summary: "The immutable experiment artifact is pending its local finalization receipt.",
  };
  process.stdout.write(`${JSON.stringify({
    testId: SBX001_DIRECT_TEST_ID,
    runId,
    assessment: outputAssessment,
    sandbox: evidence.sandbox,
    cleanup,
    localStateReleased,
    finalizationReceiptWritten,
    finalizationReceiptPath,
    reportable,
    candidateReportable: assessment.candidate && reportable,
    evidencePath,
  }, null, 2)}\n`);
  if (assessment.verdict === "error" || assessment.verdict === "indeterminate" || !localStateReleased ||
      !finalizationReceiptWritten) {
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : "SBX-001 direct run failed"}\n`);
    process.exitCode = 1;
  });
}
