import "dotenv/config";

import { randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { APIError, Sandbox, type Session } from "@vercel/sandbox";
import { verifyEligibleAliasToken } from "../eligible-alias-identity.js";
import {
  acquireSbx052Lock,
  acquireSbx052RecoveryLock,
  createSettlementReached,
  createSbx052Journal,
  loadSbx052Config,
  persistSbx052Journal,
  readSbx052Journal,
  releaseSbx052LockAndJournal,
  resumeSbx052InterruptedFinalization,
  safeSbx052Error,
  sbx052ArtifactPath,
  sbx052RecoveryArtifactPath,
  type Sbx052Config,
  type Sbx052HeldLock,
  type Sbx052RecoveryJournal,
  SBX052_CREATE_REQUEST_TIMEOUT_MS,
  SBX052_SANDBOX_TIMEOUT_MS,
  SBX052_UUID,
  writeSbx052PrivateArtifact,
} from "./safety.js";
import {
  assessSbx052,
  assertSbx052EvidenceExcludesRawValues,
  buildSbx052NamespaceEvidence,
  type Sbx052AssessmentInput,
  type Sbx052CleanupEvidence,
  type Sbx052NamespaceEvidence,
  type Sbx052OperationCase,
  type Sbx052OperationEvidence,
  type Sbx052RawGuestObservation,
  type Sbx052ReadbackEvidence,
  type Sbx052SandboxEvidence,
  type Sbx052StorageEvidence,
  SBX052_ALIAS_EMAIL,
  SBX052_BOOT_ID_PATH,
  SBX052_PROJECT_ID,
  SBX052_TEAM_ID,
  SBX052_TEST_ID,
} from "./verdict.js";

const REPOSITORY_ROOT = fileURLToPath(new URL("../../", import.meta.url));
const GUEST_SOURCE_PATH = resolve(REPOSITORY_ROOT, "guest/sbx-052-fs-namespace-probe.mjs");
const CONTROL_TIMEOUT_MS = 30_000;
const MAX_FILE_BYTES = 128;
const MAX_GUEST_OUTPUT_BYTES = 4_096;
const SESSION_ID = /^sbx_[A-Za-z0-9_-]{8,192}$/u;
const BOOT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANARY = /^can52_[A-Za-z0-9_-]{32}$/u;

interface GuestSetupResponse {
  schemaVersion: 1;
  testId: typeof SBX052_TEST_ID;
  operation: "setup";
  runId: string;
  ready: true;
  directoryMode: number;
  ownedMode: number;
  ownedRelativeLink: true;
  procAbsoluteLink: true;
}

interface GuestObserveResponse extends Sbx052RawGuestObservation {
  schemaVersion: 1;
  testId: typeof SBX052_TEST_ID;
  operation: "observe";
  runId: string;
}

interface GuestCleanupResponse {
  schemaVersion: 1;
  testId: typeof SBX052_TEST_ID;
  operation: "cleanup";
  runId: string;
  directoryRemoved: true;
  probeRemoved: true;
}

interface GuestRun<T> {
  parsed: T;
  operation: Sbx052OperationEvidence;
  rawStdout: string;
  rawStderr: string;
}

interface ApiReadRun {
  bytes: Buffer;
  operation: Sbx052OperationEvidence;
}

interface SandboxListItem {
  name: string;
  persistent: boolean;
  status: string;
  currentSessionId: string;
  createdAt: number;
  tags?: Record<string, string>;
}

export interface Sbx052CleanupSandboxInput {
  sandbox?: Sandbox;
  config: Sbx052Config;
  journal: Sbx052RecoveryJournal;
  lock: Sbx052HeldLock;
  cleanup: Sbx052CleanupEvidence;
  allowSettledUnknownAbsence: boolean;
  forbidden: string[];
}

export interface Sbx052RecoveryRuntime {
  newAttemptId(): string;
  resumeInterruptedFinalization(runId: string): Promise<boolean>;
  acquireLock(runId: string): Promise<Sbx052HeldLock>;
  readJournal(runId: string): Promise<Sbx052RecoveryJournal>;
  verifyIdentity(config: Sbx052Config): Promise<void>;
  cleanupSandbox(input: Sbx052CleanupSandboxInput): Promise<void>;
  persistJournal(lock: Sbx052HeldLock, journal: Sbx052RecoveryJournal): Promise<void>;
  releaseLockAndJournal(lock: Sbx052HeldLock): Promise<void>;
  closeRetainingState(lock: Sbx052HeldLock): Promise<void>;
  writeArtifact(path: string, value: unknown): Promise<number>;
}

export interface Sbx052ExperimentRunResult {
  runId: string;
  recoveryOnly: false;
  mode: "experiment";
  assessment: ReturnType<typeof assessSbx052>;
  evidencePath: string;
  cleanup: Sbx052CleanupEvidence;
}

export interface Sbx052RecoveryRunResult {
  runId: string;
  recoveryAttemptId: string;
  recoveryOnly: true;
  mode: "cleanup-only";
  outcome: "cleanup-complete" | "cleanup-incomplete";
  recoveryPath: "pre-create-local-only" | "post-create-cleanup" |
    "interrupted-finalization-local-only" | "unknown";
  zeroExternalStateProved: boolean;
  interruptedFinalizationProved: boolean;
  identityVerificationAttempted: boolean;
  externalCleanupPathEntered: boolean;
  failure?: string;
  evidencePath: string;
  cleanup: Sbx052CleanupEvidence;
}

export type Sbx052RunResult = Sbx052ExperimentRunResult | Sbx052RecoveryRunResult;

function credentials(config: Sbx052Config) {
  return { token: config.token, teamId: config.teamId, projectId: config.projectId };
}

function exactRecord(actual: Record<string, string> | undefined, expected: Record<string, string>): boolean {
  if (actual === undefined) return false;
  const keys = Object.keys(expected);
  return Object.keys(actual).length === keys.length && keys.every((key) => actual[key] === expected[key]);
}

function isNotFound(error: unknown): boolean {
  return error instanceof APIError && error.response.status === 404;
}

function remotePaths(runId: string) {
  const directory = `/tmp/sbx-052-${runId}`;
  return {
    directory,
    probe: `/tmp/sbx-052-probe-${runId}.mjs`,
    owned: `${directory}/owned.txt`,
    ownedLink: `${directory}/owned-link`,
    procLink: `${directory}/proc-link`,
  };
}

function exactObjectKeys(value: object, expected: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === expected.length && expected.every((key) =>
    Object.prototype.hasOwnProperty.call(value, key));
}

function parseSingleJsonLine(raw: string): Record<string, unknown> {
  if (Buffer.byteLength(raw) < 2 || Buffer.byteLength(raw) > MAX_GUEST_OUTPUT_BYTES ||
      !raw.endsWith("\n") || raw.slice(0, -1).includes("\n")) {
    throw new Error("SBX-052 guest output was not one bounded JSON line");
  }
  const parsed = JSON.parse(raw.slice(0, -1));
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("SBX-052 guest output was not an object");
  }
  return parsed as Record<string, unknown>;
}

export function parseSbx052Setup(raw: string, runId: string): GuestSetupResponse {
  const value = parseSingleJsonLine(raw);
  if (!exactObjectKeys(value, ["schemaVersion", "testId", "operation", "runId", "ready",
    "directoryMode", "ownedMode", "ownedRelativeLink", "procAbsoluteLink"]) ||
      value.schemaVersion !== 1 || value.testId !== SBX052_TEST_ID || value.operation !== "setup" ||
      value.runId !== runId || value.ready !== true || value.directoryMode !== 0o700 ||
      value.ownedMode !== 0o600 || value.ownedRelativeLink !== true || value.procAbsoluteLink !== true) {
    throw new Error("SBX-052 guest setup response was not exact");
  }
  return value as unknown as GuestSetupResponse;
}

export function parseSbx052Observation(raw: string, runId: string): GuestObserveResponse {
  const value = parseSingleJsonLine(raw);
  if (!exactObjectKeys(value, ["schemaVersion", "testId", "operation", "runId", "directBootId",
    "linkedBootId", "directBytes", "linkedBytes", "ownedLinkTarget", "procLinkTarget"]) ||
      value.schemaVersion !== 1 || value.testId !== SBX052_TEST_ID || value.operation !== "observe" ||
      value.runId !== runId || typeof value.directBootId !== "string" || !BOOT_ID.test(value.directBootId) ||
      typeof value.linkedBootId !== "string" || !BOOT_ID.test(value.linkedBootId) ||
      value.directBytes !== 37 || value.linkedBytes !== 37 || value.ownedLinkTarget !== "owned.txt" ||
      value.procLinkTarget !== SBX052_BOOT_ID_PATH) {
    throw new Error("SBX-052 guest observation response was not exact");
  }
  return value as unknown as GuestObserveResponse;
}

export function parseSbx052Cleanup(raw: string, runId: string): GuestCleanupResponse {
  const value = parseSingleJsonLine(raw);
  if (!exactObjectKeys(value, ["schemaVersion", "testId", "operation", "runId",
    "directoryRemoved", "probeRemoved"]) || value.schemaVersion !== 1 ||
      value.testId !== SBX052_TEST_ID || value.operation !== "cleanup" || value.runId !== runId ||
      value.directoryRemoved !== true || value.probeRemoved !== true) {
    throw new Error("SBX-052 guest cleanup response was not exact");
  }
  return value as unknown as GuestCleanupResponse;
}

async function runGuest<T>(input: {
  sandbox: Sandbox;
  probePath: string;
  runId: string;
  operationName: "setup" | "observe" | "cleanup";
  args?: string[];
  ordinal: number;
  caseId: Sbx052OperationCase;
  parse(raw: string, runId: string): T;
}): Promise<GuestRun<T>> {
  const startedAt = new Date().toISOString();
  const command = await input.sandbox.currentSession().runCommand({
    cmd: "node",
    args: [input.probePath, input.operationName, input.runId, ...(input.args ?? [])],
    timeoutMs: 15_000,
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  });
  const [stdout, stderr] = await Promise.all([command.stdout(), command.stderr()]);
  const completedAt = new Date().toISOString();
  if (Buffer.byteLength(stdout) > MAX_GUEST_OUTPUT_BYTES ||
      Buffer.byteLength(stderr) > MAX_GUEST_OUTPUT_BYTES || command.exitCode !== 0 || stderr !== "") {
    throw new Error(`SBX-052 guest ${input.operationName} command failed without retaining output`);
  }
  return {
    parsed: input.parse(stdout, input.runId),
    rawStdout: stdout,
    rawStderr: stderr,
    operation: {
      ordinal: input.ordinal,
      caseId: input.caseId,
      channel: "guest-command",
      pathClass: "none",
      startedAt,
      completedAt,
      sdkInvocations: 1,
      transportAttemptsObserved: false,
      found: true,
      returnedBytes: Buffer.byteLength(stdout),
      rawOutputRetained: false,
    },
  };
}

export async function readBoundedSessionFile(input: {
  session: Session;
  path: string;
  ordinal: number;
  caseId: Extract<Sbx052OperationCase,
    "owned-direct" | "owned-symlink" | "proc-direct" | "proc-symlink">;
  pathClass: Sbx052OperationEvidence["pathClass"];
}): Promise<ApiReadRun> {
  const startedAt = new Date().toISOString();
  const stream = await input.session.readFile(
    { path: input.path },
    { signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) },
  );
  if (stream === null) throw new Error(`SBX-052 ${input.caseId} target was absent`);
  const chunks: Buffer[] = [];
  let total = 0;
  const readable = stream as NodeJS.ReadableStream & AsyncIterable<Uint8Array> & { destroy?: () => void };
  try {
    for await (const raw of readable) {
      const chunk = Buffer.from(raw);
      total += chunk.length;
      if (total > MAX_FILE_BYTES) throw new Error(`SBX-052 ${input.caseId} exceeded the byte ceiling`);
      chunks.push(chunk);
    }
  } finally {
    readable.destroy?.();
  }
  const completedAt = new Date().toISOString();
  if (total < 1) throw new Error(`SBX-052 ${input.caseId} returned an empty file`);
  return {
    bytes: Buffer.concat(chunks, total),
    operation: {
      ordinal: input.ordinal,
      caseId: input.caseId,
      channel: "Session.readFile",
      pathClass: input.pathClass,
      startedAt,
      completedAt,
      sdkInvocations: 1,
      transportAttemptsObserved: false,
      found: true,
      returnedBytes: total,
      rawOutputRetained: false,
    },
  };
}

function policyLabel(sandbox: Sandbox): string {
  return sandbox.networkPolicy === "deny-all" && sandbox.currentSession().networkPolicy === "deny-all"
    ? "deny-all"
    : "other";
}

function readback(stage: "initial" | "final", source: "active" | "independent", sandbox: Sandbox): Sbx052ReadbackEvidence {
  return {
    stage,
    source,
    observedAt: new Date().toISOString(),
    name: sandbox.name,
    sessionId: sandbox.currentSession().sessionId,
    persistent: sandbox.persistent,
    status: sandbox.status,
    networkPolicy: policyLabel(sandbox),
    routesCount: sandbox.routes.length,
    sandboxTimeoutMs: sandbox.timeout ?? null,
    sessionTimeoutMs: sandbox.currentSession().timeout,
    tags: { ...(sandbox.tags ?? {}) },
  };
}

async function captureReadbacks(
  stage: "initial" | "final",
  sandbox: Sandbox,
  config: Sbx052Config,
): Promise<[Sbx052ReadbackEvidence, Sbx052ReadbackEvidence]> {
  const active = readback(stage, "active", sandbox);
  const independent = await Sandbox.get({
    name: sandbox.name,
    resume: false,
    ...credentials(config),
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  });
  return [active, readback(stage, "independent", independent)];
}

async function listNamed(config: Sbx052Config, name: string): Promise<SandboxListItem[]> {
  const page = await Sandbox.list({
    namePrefix: name,
    limit: 10,
    sortBy: "name",
    sortOrder: "asc",
    ...credentials(config),
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  });
  if (page.pagination.next !== null) throw new Error("SBX-052 exact-name lookup unexpectedly paginated");
  return page.sandboxes as SandboxListItem[];
}

function recoverableListItem(item: SandboxListItem, journal: Sbx052RecoveryJournal): boolean {
  if (journal.createAttemptedAt === undefined) return false;
  const created = item.createdAt;
  const attempted = Date.parse(journal.createAttemptedAt);
  return item.name === journal.sandboxName && item.persistent === false &&
    exactRecord(item.tags, journal.tags) && created >= attempted - 5_000 &&
    created <= Date.now() + 5_000 &&
    (journal.sessionId === undefined || item.currentSessionId === journal.sessionId);
}

async function cleanupSandbox(input: Sbx052CleanupSandboxInput): Promise<void> {
  let handle = input.sandbox;
  if (input.journal.createAttemptedAt === undefined) {
    input.cleanup.exactNameAbsent = true;
    input.cleanup.prefixListAbsent = true;
    return;
  }
  if (!handle) {
    const matches = (await listNamed(input.config, input.journal.sandboxName))
      .filter((item) => item.name === input.journal.sandboxName);
    if (matches.length > 1) throw new Error("SBX-052 recovery found multiple exact-name sandboxes");
    const match = matches[0];
    if (match !== undefined) {
      if (!recoverableListItem(match, input.journal)) {
        throw new Error("SBX-052 recovery candidate failed exact provenance");
      }
      handle = await Sandbox.get({
        name: input.journal.sandboxName,
        resume: false,
        ...credentials(input.config),
        signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
      });
    } else {
      const exactDeleteAlreadyCommitted = input.journal.stopped && input.journal.deleted;
      const settled = input.allowSettledUnknownAbsence && createSettlementReached(input.journal);
      if (!exactDeleteAlreadyCommitted && !settled) {
        input.cleanup.unknownCreate = input.journal.sessionId === undefined;
        throw new Error("SBX-052 absent create outcome is not settled; lock and journal must remain");
      }
      input.cleanup.stopped = true;
      input.cleanup.deleted = true;
      input.journal.stopped = true;
      input.journal.deleted = true;
    }
  }
  if (handle) {
    const sessionId = handle.currentSession().sessionId;
    if (handle.name !== input.journal.sandboxName || handle.persistent !== false ||
        !exactRecord(handle.tags, input.journal.tags) ||
        (input.journal.sessionId !== undefined && sessionId !== input.journal.sessionId)) {
      throw new Error("SBX-052 cleanup handle failed exact provenance");
    }
    input.cleanup.stopAttempted = true;
    input.journal.stopAttempted = true;
    await persistSbx052Journal(input.lock, input.journal);
    if (handle.status !== "stopped") {
      const stopped = await handle.stop({ signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
      if (stopped.id !== sessionId || stopped.status !== "stopped") {
        throw new Error("SBX-052 stop response did not identify the exact session");
      }
    }
    input.cleanup.stopped = true;
    input.journal.stopped = true;
    await persistSbx052Journal(input.lock, input.journal);
    input.cleanup.deleteAttempted = true;
    input.journal.deleteAttempted = true;
    await persistSbx052Journal(input.lock, input.journal);
    await handle.delete({ signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
    input.cleanup.deleted = true;
    input.journal.deleted = true;
    await persistSbx052Journal(input.lock, input.journal);
  }
  for (let attempt = 0; attempt < 3; attempt += 1) {
    if (attempt > 0) await delay(1_000);
    try {
      await Sandbox.get({
        name: input.journal.sandboxName,
        resume: false,
        ...credentials(input.config),
        signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
      });
      input.cleanup.errors.push(`absence check ${attempt + 1} still found the sandbox`);
    } catch (error) {
      if (isNotFound(error)) {
        input.cleanup.absenceChecks += 1;
        input.journal.absenceChecks += 1;
      } else {
        input.cleanup.errors.push(`absence check ${attempt + 1}: ${safeSbx052Error(error, input.forbidden)}`);
      }
    }
  }
  const remaining = await listNamed(input.config, input.journal.sandboxName);
  input.cleanup.exactNameAbsent = input.cleanup.absenceChecks >= 3;
  input.cleanup.prefixListAbsent = remaining.every((item) =>
    item.name !== input.journal.sandboxName && !item.name.startsWith(input.journal.sandboxName));
  input.journal.prefixListAbsent = input.cleanup.prefixListAbsent;
  if (!input.cleanup.prefixListAbsent) input.cleanup.errors.push("sandbox name prefix remained after cleanup");
  await persistSbx052Journal(input.lock, input.journal);
}

function emptyNamespace(): Sbx052NamespaceEvidence {
  return {
    guestObservationCount: 0,
    guestDirectFormatsValid: false,
    guestLinkedFormatsValid: false,
    guestDirectEqualsLinkedEveryTime: false,
    guestBootIdStableAcrossBrackets: false,
    guestBootBytes: [],
    ownedDirectMatched: false,
    ownedSymlinkMatched: false,
    ownedDirectEqualsSymlink: false,
    ownedDirectBytes: 0,
    ownedSymlinkBytes: 0,
    apiDirectProcFormatValid: false,
    apiSymlinkProcFormatValid: false,
    apiDirectProcBytes: 0,
    apiSymlinkProcBytes: 0,
    apiDirectEqualsSymlink: false,
    apiDirectEqualsStableGuest: false,
    apiSymlinkEqualsStableGuest: false,
    apiPairDiffersFromStableGuest: false,
    rawBootIdsRetained: false,
    bootIdDigestsRetained: false,
    rawCanaryRetained: false,
    canaryDigestRetained: false,
  };
}

function emptyCleanup(): Sbx052CleanupEvidence {
  return {
    guestCleanupAttempted: false,
    guestDirectoryRemoved: false,
    guestProbeRemoved: false,
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    absenceChecks: 0,
    exactNameAbsent: false,
    prefixListAbsent: false,
    unknownCreate: false,
    liveLockReleased: false,
    recoveryJournalDeleted: false,
    completedAt: new Date().toISOString(),
    errors: [],
  };
}

function sandboxEvidence(sandbox: Sandbox): Sbx052SandboxEvidence {
  return {
    name: sandbox.name,
    sessionId: sandbox.currentSession().sessionId,
    persistent: sandbox.persistent,
    status: sandbox.status,
    networkPolicy: policyLabel(sandbox),
    routesCount: sandbox.routes.length,
    createdAt: sandbox.createdAt.toISOString(),
    sandboxTimeoutMs: sandbox.timeout ?? null,
    sessionTimeoutMs: sandbox.currentSession().timeout,
    tags: { ...(sandbox.tags ?? {}) },
  };
}

export async function runSbx052(config: Sbx052Config): Promise<Sbx052RunResult> {
  if (config.recoveryRunId !== undefined) return runSbx052Recovery(config, config.recoveryRunId);
  const journal = createSbx052Journal();
  const runId = journal.runId;
  const paths = remotePaths(runId);
  const canary = `can52_${randomBytes(24).toString("base64url")}`;
  if (!CANARY.test(canary)) throw new Error("SBX-052 generated canary was not canonical");
  const canaryBytes = Buffer.from(`${canary}\n`, "utf8");
  const forbidden = [config.token, canary];
  const cleanup = emptyCleanup();
  const storage: Sbx052StorageEvidence = {
    artifactMode: 0o600,
    liveLockMode: 0,
    recoveryJournalMode: 0,
    rawBootIdsRetained: false,
    bootIdDigestsRetained: false,
    rawCanaryRetained: false,
    canaryDigestRetained: false,
    guestStdoutRetained: false,
    guestStderrRetained: false,
    apiResponseBodiesRetained: false,
  };
  let lock: Sbx052HeldLock | undefined;
  let sandbox: Sandbox | undefined;
  let identity: Awaited<ReturnType<typeof verifyEligibleAliasToken>> | undefined;
  let identityAndScopePassed = false;
  let executionError: string | undefined;
  let sandboxRecord: Sbx052SandboxEvidence = {
    name: journal.sandboxName,
    sessionId: "sbx_unavailable",
    persistent: false,
    status: "missing",
    networkPolicy: "other",
    routesCount: 0,
    createdAt: journal.startedAt,
    sandboxTimeoutMs: null,
    sessionTimeoutMs: 0,
    tags: journal.tags,
  };
  const readbacks: Sbx052ReadbackEvidence[] = [];
  const operations: Sbx052OperationEvidence[] = [];
  let namespace = emptyNamespace();
  const rawForbidden: string[] = [];

  const persist = async (): Promise<void> => {
    if (lock) await persistSbx052Journal(lock, journal);
  };

  try {
    lock = await acquireSbx052Lock(journal);
    storage.liveLockMode = lock.lockMode;
    storage.recoveryJournalMode = lock.journalMode;
    identity = await verifyEligibleAliasToken({
      token: config.token,
      expectedEmail: SBX052_ALIAS_EMAIL,
      expectedTeamId: SBX052_TEAM_ID,
      expectedProjectId: SBX052_PROJECT_ID,
      manualEmailConfirmation: config.expectedAlias,
    });
    const preexisting = await listNamed(config, journal.sandboxName);
    if (preexisting.some((item) => item.name.startsWith(journal.sandboxName))) {
      throw new Error("SBX-052 full-UUID sandbox name was not fresh");
    }
    identityAndScopePassed = true;
    const guestSource = await readFile(GUEST_SOURCE_PATH, "utf8");
    if (!guestSource.includes("/proc/sys/kernel/random/boot_id") ||
        /node:(?:http|https|net|tls|dgram)|\bfetch\s*\(/u.test(guestSource)) {
      throw new Error("SBX-052 guest source failed its local-only source gate");
    }
    journal.createAttemptedAt = new Date().toISOString();
    await persist();
    sandbox = await Sandbox.create({
      name: journal.sandboxName,
      persistent: false,
      timeout: SBX052_SANDBOX_TIMEOUT_MS,
      resources: { vcpus: 2 },
      ports: [],
      networkPolicy: "deny-all",
      tags: journal.tags,
      ...credentials(config),
      signal: AbortSignal.timeout(SBX052_CREATE_REQUEST_TIMEOUT_MS),
    });
    const sessionId = sandbox.currentSession().sessionId;
    if (!SESSION_ID.test(sessionId) || sandbox.name !== journal.sandboxName || sandbox.persistent !== false ||
        sandbox.status !== "running" || policyLabel(sandbox) !== "deny-all" || sandbox.routes.length !== 0 ||
        sandbox.timeout !== SBX052_SANDBOX_TIMEOUT_MS ||
        sandbox.currentSession().timeout !== SBX052_SANDBOX_TIMEOUT_MS ||
        !exactRecord(sandbox.tags, journal.tags)) {
      throw new Error("SBX-052 create response failed exact provenance or deny-all validation");
    }
    journal.sessionId = sessionId;
    await persist();
    sandboxRecord = sandboxEvidence(sandbox);
    readbacks.push(...await captureReadbacks("initial", sandbox, config));
    await sandbox.writeFiles([{ path: paths.probe, content: guestSource, mode: 0o700 }], {
      signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
    });
    journal.guestProbeStaged = true;
    await persist();

    const setup = await runGuest({
      sandbox, probePath: paths.probe, runId, operationName: "setup", args: [canary],
      ordinal: 1, caseId: "guest-setup", parse: parseSbx052Setup,
    });
    operations.push(setup.operation);
    const before = await runGuest({
      sandbox, probePath: paths.probe, runId, operationName: "observe",
      ordinal: 2, caseId: "guest-before", parse: parseSbx052Observation,
    });
    operations.push(before.operation);
    rawForbidden.push(before.parsed.directBootId, before.parsed.linkedBootId);

    const ownedDirect = await readBoundedSessionFile({
      session: sandbox.currentSession(), path: paths.owned, ordinal: 3,
      caseId: "owned-direct", pathClass: "owned-file",
    });
    operations.push(ownedDirect.operation);
    const ownedSymlink = await readBoundedSessionFile({
      session: sandbox.currentSession(), path: paths.ownedLink, ordinal: 4,
      caseId: "owned-symlink", pathClass: "owned-relative-symlink",
    });
    operations.push(ownedSymlink.operation);
    const procDirect = await readBoundedSessionFile({
      session: sandbox.currentSession(), path: SBX052_BOOT_ID_PATH, ordinal: 5,
      caseId: "proc-direct", pathClass: "proc-direct",
    });
    operations.push(procDirect.operation);
    rawForbidden.push(procDirect.bytes.toString("utf8").trim());

    const middle = await runGuest({
      sandbox, probePath: paths.probe, runId, operationName: "observe",
      ordinal: 6, caseId: "guest-middle", parse: parseSbx052Observation,
    });
    operations.push(middle.operation);
    rawForbidden.push(middle.parsed.directBootId, middle.parsed.linkedBootId);
    const procSymlink = await readBoundedSessionFile({
      session: sandbox.currentSession(), path: paths.procLink, ordinal: 7,
      caseId: "proc-symlink", pathClass: "proc-absolute-symlink",
    });
    operations.push(procSymlink.operation);
    rawForbidden.push(procSymlink.bytes.toString("utf8").trim());
    const after = await runGuest({
      sandbox, probePath: paths.probe, runId, operationName: "observe",
      ordinal: 8, caseId: "guest-after", parse: parseSbx052Observation,
    });
    operations.push(after.operation);
    rawForbidden.push(after.parsed.directBootId, after.parsed.linkedBootId);

    namespace = buildSbx052NamespaceEvidence({
      guest: [before.parsed, middle.parsed, after.parsed],
      ownedDirect: ownedDirect.bytes,
      ownedSymlink: ownedSymlink.bytes,
      expectedCanary: canaryBytes,
      apiDirectProc: procDirect.bytes,
      apiSymlinkProc: procSymlink.bytes,
    });
    readbacks.push(...await captureReadbacks("final", sandbox, config));
  } catch (error) {
    executionError = safeSbx052Error(error, [...forbidden, ...rawForbidden]);
  } finally {
    if (sandbox && journal.guestProbeStaged) {
      cleanup.guestCleanupAttempted = true;
      try {
        const guestCleanup = await runGuest({
          sandbox, probePath: paths.probe, runId, operationName: "cleanup",
          ordinal: 9, caseId: "guest-cleanup", parse: parseSbx052Cleanup,
        });
        operations.push(guestCleanup.operation);
        cleanup.guestDirectoryRemoved = guestCleanup.parsed.directoryRemoved;
        cleanup.guestProbeRemoved = guestCleanup.parsed.probeRemoved;
        journal.guestMaterialRemoved = true;
        await persist();
      } catch (error) {
        cleanup.errors.push(`guest cleanup: ${safeSbx052Error(error, [...forbidden, ...rawForbidden])}`);
      }
    }
    if (lock) {
      try {
        await cleanupSandbox({
          ...(sandbox === undefined ? {} : { sandbox }),
          config, journal, lock, cleanup, allowSettledUnknownAbsence: false,
          forbidden: [...forbidden, ...rawForbidden],
        });
      } catch (error) {
        cleanup.errors.push(`sandbox cleanup: ${safeSbx052Error(error, [...forbidden, ...rawForbidden])}`);
      }
      journal.completed = journal.createAttemptedAt === undefined
        ? cleanup.errors.length === 0
        : cleanup.stopped && cleanup.deleted && cleanup.absenceChecks >= 3 &&
          cleanup.prefixListAbsent && !cleanup.unknownCreate &&
          (!journal.guestProbeStaged || journal.guestMaterialRemoved) && cleanup.errors.length === 0;
      await persist().catch((error) => {
        journal.completed = false;
        cleanup.errors.push(`journal finalization: ${safeSbx052Error(error, forbidden)}`);
      });
      if (journal.completed) {
        try {
          await releaseSbx052LockAndJournal(lock);
          cleanup.liveLockReleased = true;
          cleanup.recoveryJournalDeleted = true;
        } catch (error) {
          cleanup.errors.push(`lock release: ${safeSbx052Error(error, forbidden)}`);
        }
      }
    }
    cleanup.completedAt = new Date().toISOString();
  }

  const expected = {
    runId,
    sandboxName: journal.sandboxName,
    sessionId: journal.sessionId ?? "sbx_unavailable",
    tags: journal.tags,
  };
  const input: Sbx052AssessmentInput = {
    ...(executionError === undefined ? {} : { executionError }),
    identityAndScopePassed,
    ...(identity === undefined ? {} : { identity }),
    expected,
    sandbox: sandboxRecord,
    readbacks,
    operations,
    namespace,
    cleanup,
    storage,
  };
  const assessment = assessSbx052(input);
  const artifact = {
    schemaVersion: 1,
    testId: SBX052_TEST_ID,
    runId,
    recoveryOnly: false,
    mode: "experiment" as const,
    assessment,
    evidence: input,
    retention: {
      rawBootIds: false,
      bootIdDigests: false,
      rawCanary: false,
      canaryDigest: false,
      guestOutput: false,
      apiResponseBodies: false,
      token: false,
    },
  };
  assertSbx052EvidenceExcludesRawValues(artifact, [...forbidden, ...rawForbidden]);
  const evidencePath = sbx052ArtifactPath(runId);
  const artifactMode = await writeSbx052PrivateArtifact(evidencePath, artifact);
  if (artifactMode !== 0o600) throw new Error("SBX-052 artifact mode changed after persistence");
  return { runId, recoveryOnly: false, mode: "experiment", assessment, evidencePath, cleanup };
}

export async function runSbx052Recovery(
  config: Sbx052Config,
  runId: string,
  overrides: Partial<Sbx052RecoveryRuntime> = {},
): Promise<Sbx052RecoveryRunResult> {
  const runtime: Sbx052RecoveryRuntime = {
    newAttemptId: randomUUID,
    resumeInterruptedFinalization: resumeSbx052InterruptedFinalization,
    acquireLock: acquireSbx052RecoveryLock,
    readJournal: readSbx052Journal,
    verifyIdentity: async (recoveryConfig) => {
      await verifyEligibleAliasToken({
        token: recoveryConfig.token,
        expectedEmail: SBX052_ALIAS_EMAIL,
        expectedTeamId: SBX052_TEAM_ID,
        expectedProjectId: SBX052_PROJECT_ID,
        manualEmailConfirmation: recoveryConfig.expectedAlias,
      });
    },
    cleanupSandbox,
    persistJournal: persistSbx052Journal,
    releaseLockAndJournal: releaseSbx052LockAndJournal,
    closeRetainingState: async (recoveryLock) => recoveryLock.liveLock.closeRetainingState(),
    writeArtifact: writeSbx052PrivateArtifact,
    ...overrides,
  };
  const recoveryAttemptId = runtime.newAttemptId();
  if (!SBX052_UUID.test(recoveryAttemptId)) {
    throw new Error("SBX-052 recovery attempt ID was not a canonical UUIDv4");
  }
  const cleanup = emptyCleanup();
  const forbidden = [config.token];
  let lock: Sbx052HeldLock | undefined;
  let journal: Sbx052RecoveryJournal | undefined;
  let executionError: string | undefined;
  let identityAndScopePassed = false;
  let identityVerificationAttempted = false;
  let externalCleanupPathEntered = false;
  let recoveryStateProved = false;
  let recoveryPath: Sbx052RecoveryRunResult["recoveryPath"] = "unknown";
  try {
    if (await runtime.resumeInterruptedFinalization(runId)) {
      recoveryPath = "interrupted-finalization-local-only";
      recoveryStateProved = true;
      cleanup.exactNameAbsent = true;
      cleanup.prefixListAbsent = true;
      cleanup.liveLockReleased = true;
      cleanup.recoveryJournalDeleted = true;
    } else {
      lock = await runtime.acquireLock(runId);
      journal = await runtime.readJournal(runId);
      if (journal.createAttemptedAt === undefined) {
        recoveryPath = "pre-create-local-only";
        await runtime.cleanupSandbox({
          config, journal, lock, cleanup, allowSettledUnknownAbsence: true, forbidden,
        });
        recoveryStateProved = journal.sessionId === undefined && !journal.guestProbeStaged &&
          !journal.guestMaterialRemoved && !journal.stopAttempted && !journal.stopped &&
          !journal.deleteAttempted && !journal.deleted && journal.absenceChecks === 0 &&
          !journal.prefixListAbsent && !identityVerificationAttempted &&
          !externalCleanupPathEntered && !cleanup.guestCleanupAttempted &&
          !cleanup.guestDirectoryRemoved && !cleanup.guestProbeRemoved && !cleanup.stopAttempted &&
          !cleanup.stopped && !cleanup.deleteAttempted && !cleanup.deleted &&
          cleanup.absenceChecks === 0 && cleanup.exactNameAbsent && cleanup.prefixListAbsent &&
          !cleanup.unknownCreate && cleanup.errors.length === 0;
      } else {
        recoveryPath = "post-create-cleanup";
        identityVerificationAttempted = true;
        await runtime.verifyIdentity(config);
        identityAndScopePassed = true;
        externalCleanupPathEntered = true;
        await runtime.cleanupSandbox({
          config, journal, lock, cleanup, allowSettledUnknownAbsence: true, forbidden,
        });
        recoveryStateProved = cleanup.stopped && cleanup.deleted && cleanup.absenceChecks >= 3 &&
          cleanup.exactNameAbsent && cleanup.prefixListAbsent && !cleanup.unknownCreate &&
          cleanup.errors.length === 0;
      }
      journal.completed = recoveryStateProved;
      await runtime.persistJournal(lock, journal);
      if (!journal.completed) throw new Error("SBX-052 recovery did not prove exact cleanup");
      await runtime.releaseLockAndJournal(lock);
      cleanup.liveLockReleased = true;
      cleanup.recoveryJournalDeleted = true;
    }
  } catch (error) {
    executionError = safeSbx052Error(error, forbidden);
    if (lock !== undefined) {
      try {
        await runtime.closeRetainingState(lock);
      } catch (retentionError) {
        executionError = safeSbx052Error(new Error(
          `${executionError}; retained-lock descriptor close failed: ${safeSbx052Error(retentionError, forbidden)}`,
        ), forbidden);
      }
    }
  }
  cleanup.completedAt = new Date().toISOString();
  const preCreateLocalSuccess = recoveryPath === "pre-create-local-only" &&
    recoveryStateProved && !identityVerificationAttempted && !externalCleanupPathEntered;
  const postCreateCleanupSuccess = recoveryPath === "post-create-cleanup" &&
    recoveryStateProved && identityVerificationAttempted && identityAndScopePassed &&
    externalCleanupPathEntered;
  const interruptedFinalizationSuccess = recoveryPath === "interrupted-finalization-local-only" &&
    recoveryStateProved && !identityVerificationAttempted && !externalCleanupPathEntered;
  const cleanupComplete = executionError === undefined &&
    (preCreateLocalSuccess || postCreateCleanupSuccess || interruptedFinalizationSuccess) &&
    cleanup.liveLockReleased && cleanup.recoveryJournalDeleted;
  if (!cleanupComplete && executionError === undefined) {
    executionError = "SBX-052 recovery evidence did not prove exact cleanup";
  }
  const outcome = cleanupComplete ? "cleanup-complete" as const : "cleanup-incomplete" as const;
  const artifact = {
    schemaVersion: 1,
    testId: SBX052_TEST_ID,
    runId,
    recoveryAttemptId,
    recoveryOnly: true,
    mode: "cleanup-only" as const,
    outcome,
    recoveryPath,
    zeroExternalStateProved: preCreateLocalSuccess,
    interruptedFinalizationProved: interruptedFinalizationSuccess,
    identityVerificationAttempted,
    externalCleanupPathEntered,
    identityAndScopePassed,
    ...(executionError === undefined ? {} : { failure: executionError }),
    cleanup,
    retention: { experimentEvidenceOverwritten: false, rawValues: false, token: false },
  };
  assertSbx052EvidenceExcludesRawValues(artifact, forbidden);
  const evidencePath = sbx052RecoveryArtifactPath(runId, recoveryAttemptId);
  const artifactMode = await runtime.writeArtifact(evidencePath, artifact);
  if (artifactMode !== 0o600) throw new Error("SBX-052 recovery artifact mode changed after persistence");
  return {
    runId,
    recoveryAttemptId,
    recoveryOnly: true,
    mode: "cleanup-only",
    outcome,
    recoveryPath,
    zeroExternalStateProved: preCreateLocalSuccess,
    interruptedFinalizationProved: interruptedFinalizationSuccess,
    identityVerificationAttempted,
    externalCleanupPathEntered,
    ...(executionError === undefined ? {} : { failure: executionError }),
    evidencePath,
    cleanup,
  };
}

export async function main(): Promise<void> {
  const config = loadSbx052Config();
  const result = await runSbx052(config);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (result.mode === "experiment") {
    if (result.assessment.verdict !== "pass") process.exitCode = 2;
  } else if (result.outcome !== "cleanup-complete") {
    process.exitCode = 2;
  }
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : "";
if (import.meta.url === invokedPath) {
  main().catch((error) => {
    process.stderr.write(`SBX-052 failed: ${safeSbx052Error(error)}\n`);
    process.exitCode = 1;
  });
}
