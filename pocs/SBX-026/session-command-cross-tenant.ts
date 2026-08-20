import "dotenv/config";

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { Sandbox } from "@vercel/sandbox";
import {
  CONTROL_PLANE_TIMEOUT_MS,
  MINIMUM_VERCEL_REQUEST_INTERVAL_MS,
  SBX026_LIVE_LOCK_FILENAME,
  acquireSbx026LiveLock,
  apiFailureFromError,
  apiFailureFromResponse,
  assertDistinctVerifiedIdentities,
  conclusiveAuthorizationRejection,
  createAccountFetch,
  loadTwoOwnedAccounts,
  oneShotSandboxRequest,
  readBoundedResponse,
  verifyAccountIdentity,
  VercelRequestGate,
  type AcquireSbx026LiveLockOptions,
  type ApiFailure,
  type ExplicitAccountCredentials,
  type RequestAuditRecord,
  type Sbx026LiveLock,
} from "./shared.js";
import {
  assessSessionCommandAuthorization,
  type SessionCommandAssessment,
  type SessionCommandLane,
} from "./session-command-verdict.js";

export const SESSION_COMMAND_CONFIRMATION =
  "I_CONFIRM_EXACTLY_ONE_BOUNDED_CROSS_ACCOUNT_SESSION_OR_COMMAND_REQUEST";

const TEST_ID = "SBX-026";
const SETUP_TIMEOUT_MS = 120_000;
const SANDBOX_TIMEOUT_MS = 180_000;
const COMMAND_TIMEOUT_MS = 5_000;
const MAXIMUM_COMMAND_RESPONSE_BYTES = 8_192;
export const ABSENCE_CONFIRMATION_DELAY_MS = 1_000;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

interface RequestCounters {
  attackerOwnerControlRequests: number;
  attackerOwnerControlTransportCalls: number;
  victimOwnerControlRequests: number;
  victimOwnerControlTransportCalls: number;
  foreignRequests: number;
  foreignTransportCalls: number;
  crossKnownPathReads: number;
  deferredCrossOperations: number;
}

interface SanitizedAttempt {
  status?: number;
  contentType?: string;
  responseBytes?: number;
  failure?: ApiFailure;
  httpSucceeded: boolean;
  exactMarkerConfirmed: boolean;
}

interface CommandParseSummary {
  exact: boolean;
  lineCount: number;
  stdoutBytes: number;
  stderrBytes: number;
  finalExitCode?: number;
  sessionIdMatched: boolean;
  commandShapeMatched: boolean;
}

interface CleanupError {
  stage: string;
  kind: "api" | "other" | "provenance";
  status?: number;
  code?: string;
}

interface CleanupTarget {
  name: string;
  expectedTags: Record<string, string>;
  owner: ExplicitAccountCredentials;
  ownerFetch: typeof fetch;
  enforceCreationWindow: boolean;
  creationWindowStartedAtMs: number;
  createAttempted: boolean;
  handle?: Sandbox;
  recovered: boolean;
  provenancePassed: boolean;
  stopAttempted: boolean;
  stopAccepted: boolean;
  deleteAttempted: boolean;
  deleteAccepted: boolean;
  absenceChecked: boolean;
  absenceConfirmed: boolean;
  absenceConfirmationAttempts: number;
  absenceConfirmationDelayMs?: number;
  errors: CleanupError[];
}

interface QpsAudit {
  requestCount: number;
  minimumObservedIntervalMs?: number;
  maximumObservedStartsPerSecond?: number;
  passed: boolean;
}

export type FixtureRole = "attacker" | "victim";

export interface FixtureMetadata {
  role: FixtureRole;
  name: string;
  tags: Record<string, string>;
  knownPath: string;
}

export interface FixturePlan extends FixtureMetadata {
  marker: string;
}

export interface AuthorizationOperation {
  phase: "attacker-owner-control" | "victim-owner-control" | "foreign";
  actor: FixtureRole;
  target: FixtureRole;
  lane: SessionCommandLane;
  sessionId: string;
  marker: string;
  knownPath: string;
}

export interface AuthorizationSequenceResult {
  attackerOwnerControlPassed: boolean;
  victimOwnerControlPassed: boolean;
  foreignDispatched: boolean;
}

export interface CleanupOnlySequenceResult extends AuthorizationSequenceResult {
  attackerRecoveryPassed: boolean;
  victimRecoveryPassed: boolean;
}

type AuthorizationOrchestrationInput =
  | { cleanupOnly: true }
  | {
      cleanupOnly: false;
      lane: SessionCommandLane;
      attacker: FixturePlan & { sessionId: string };
      victim: FixturePlan & { sessionId: string };
    };

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function exactContentType(response: Response, expected: string): boolean {
  return (response.headers.get("content-type") ?? "")
    .split(";", 1)[0]
    ?.trim().toLowerCase() === expected;
}

function sdkCredentials(account: ExplicitAccountCredentials): {
  token: string;
  teamId: string;
  projectId: string;
} {
  return { token: account.token, teamId: account.teamId, projectId: account.projectId };
}

export function parseSessionCommandLane(argv: readonly string[]): SessionCommandLane {
  if (argv.includes("--all")) throw new Error("--all is forbidden; select exactly one lane");
  if (argv.length !== 1) {
    throw new Error("supply exactly one --lane=session-read or --lane=command-run argument");
  }
  if (argv[0] === "--lane=session-read") return "session-read";
  if (argv[0] === "--lane=command-run") return "command-run";
  throw new Error("lane must be exactly session-read or command-run");
}

export function resolveRunMode(
  environment: Readonly<Record<string, string | undefined>>,
): { runId: string; cleanupOnly: boolean } {
  const supplied = environment.SBX026_RUN_ID;
  const value = supplied ?? randomUUID();
  if (!UUID_PATTERN.test(value)) {
    throw new Error("SBX026_RUN_ID, when supplied for recovery, must be one canonical UUID");
  }
  return { runId: value, cleanupOnly: supplied !== undefined };
}

export function sessionCommandLiveLockOptions(
  lane: SessionCommandLane,
  runId: string,
  cleanupOnly: boolean,
): AcquireSbx026LiveLockOptions {
  if (!UUID_PATTERN.test(runId)) {
    throw new Error("session-command live-lock run ID must be one canonical UUID");
  }
  return {
    scope: "session-command",
    lane,
    runId,
    mode: cleanupOnly ? "cleanup-only" : "normal",
  };
}

export function pendingSessionCommandAssessment(): SessionCommandAssessment {
  return {
    verdict: "indeterminate",
    summary: "Final verdict withheld until the exact shared SBX-026 live lock is released.",
    outcomeSignalsMutuallyExclusive: false,
    outcomeSignalsConsistent: false,
    safetyInvariantsPassed: false,
  };
}

export function releaseNeutralSessionCommandEvidenceState(
  mode: "test" | "cleanup-only",
): Record<string, unknown> {
  return {
    ...(mode === "test"
      ? { assessment: pendingSessionCommandAssessment() }
      : { outcome: "pending-live-lock-release" }),
    finalization: {
      status: "pending-recovery-or-live-lock-release",
      effectiveVerdict: "indeterminate",
      candidate: false,
      finalAssessmentRetained: false,
      liveLockReleased: false,
    },
  };
}

function isReleaseNeutralSessionCommandEvidence(
  evidence: Readonly<Record<string, unknown>>,
  mode: "test" | "cleanup-only",
): boolean {
  const finalization = evidence.finalization;
  if (finalization === null || typeof finalization !== "object" || Array.isArray(finalization)) {
    return false;
  }
  const state = finalization as Record<string, unknown>;
  if (
    state.status !== "pending-recovery-or-live-lock-release" ||
    state.effectiveVerdict !== "indeterminate" || state.candidate !== false ||
    state.finalAssessmentRetained !== false || state.liveLockReleased !== false
  ) {
    return false;
  }
  if (mode === "cleanup-only") return evidence.outcome === "pending-live-lock-release";
  const assessment = evidence.assessment;
  return assessment !== null && typeof assessment === "object" && !Array.isArray(assessment) &&
    (assessment as { verdict?: unknown }).verdict === "indeterminate";
}

export async function finalizeSessionCommandAfterLiveLockRelease(
  mode: "test" | "cleanup-only",
  pendingEvidence: Readonly<Record<string, unknown>>,
  evidencePath: string,
  liveLock: Pick<Sbx026LiveLock, "release">,
  releaseEligible: boolean,
  constructFinalResult: () => Readonly<Record<string, unknown>>,
  emitFinalResult: (result: Readonly<Record<string, unknown>>) => void,
  finalizedAt = new Date().toISOString(),
): Promise<Readonly<Record<string, unknown>> | undefined> {
  if (!isReleaseNeutralSessionCommandEvidence(pendingEvidence, mode)) {
    throw new Error("refused to finalize non-neutral session-command evidence");
  }
  if (!releaseEligible) return undefined;

  // The durable record is already neutral. Construct and emit no effective
  // outcome until the exact shared lock has successfully released.
  await liveLock.release();
  const result = {
    ...constructFinalResult(),
    completedAt: finalizedAt,
    evidencePath,
    finalization: {
      status: "complete",
      liveLockReleasedBeforeVerdict: true,
      durableEvidenceRemainsReleaseNeutral: true,
    },
  };
  emitFinalResult(result);
  return result;
}

export function deterministicFixtureMetadata(
  lane: SessionCommandLane,
  runId: string,
): { attacker: FixtureMetadata; victim: FixtureMetadata } {
  if (!UUID_PATTERN.test(runId)) throw new Error("fixture run ID must be one canonical UUID");
  const compactRunId = runId.replaceAll("-", "");
  const laneName = lane === "session-read" ? "read" : "cmd";
  const baseTags = { test: TEST_ID, packet: "session-command", run: runId, lane };
  return {
    attacker: {
      role: "attacker",
      name: `sbx-026-sc-attacker-${laneName}-${compactRunId}`,
      tags: { ...baseTags, owner: "attacker" },
      knownPath: `/vercel/sandbox/.sbx-026-attacker-${compactRunId}.marker`,
    },
    victim: {
      role: "victim",
      name: `sbx-026-sc-victim-${laneName}-${compactRunId}`,
      tags: { ...baseTags, owner: "victim" },
      knownPath: `/vercel/sandbox/.sbx-026-victim-${compactRunId}.marker`,
    },
  };
}

function validateMarker(marker: string, role: FixtureRole): void {
  const bytes = Buffer.byteLength(marker);
  if (bytes < 16 || bytes > 512 || /[\0\r\n]/u.test(marker)) {
    throw new Error(`${role} marker must be bounded and single-line`);
  }
}

export function createFixturePlans(
  lane: SessionCommandLane,
  runId: string,
  attackerMarker: string,
  victimMarker: string,
): { attacker: FixturePlan; victim: FixturePlan } {
  validateMarker(attackerMarker, "attacker");
  validateMarker(victimMarker, "victim");
  if (attackerMarker === victimMarker) throw new Error("owner markers must be distinct");
  const metadata = deterministicFixtureMetadata(lane, runId);
  if (metadata.attacker.knownPath === metadata.victim.knownPath) {
    throw new Error("owner known paths must be distinct");
  }
  return {
    attacker: { ...metadata.attacker, marker: attackerMarker },
    victim: { ...metadata.victim, marker: victimMarker },
  };
}

function boundedSessionId(value: string): boolean {
  return value.length <= 256 && /^sbx_[A-Za-z0-9_-]{8,252}$/u.test(value);
}

export function assertDistinctBoundedSessionIds(attacker: string, victim: string): true {
  if (!boundedSessionId(attacker) || !boundedSessionId(victim)) {
    throw new Error("both fixture session IDs must have the bounded sbx_ identifier shape");
  }
  if (attacker === victim) throw new Error("attacker and victim session IDs must be distinct");
  return true;
}

export async function orchestrateAuthorizationRequests(
  input: AuthorizationOrchestrationInput,
  dispatch: (operation: AuthorizationOperation) => Promise<{ exactMarkerConfirmed: boolean }>,
): Promise<AuthorizationSequenceResult> {
  if (input.cleanupOnly) {
    return {
      attackerOwnerControlPassed: false,
      victimOwnerControlPassed: false,
      foreignDispatched: false,
    };
  }
  assertDistinctBoundedSessionIds(input.attacker.sessionId, input.victim.sessionId);
  if (input.attacker.role !== "attacker" || input.victim.role !== "victim") {
    throw new Error("fixture roles must remain attacker and victim");
  }
  if (input.attacker.marker === input.victim.marker) throw new Error("owner markers must be distinct");
  if (input.attacker.knownPath === input.victim.knownPath) {
    throw new Error("owner known paths must be distinct");
  }

  const attackerControl = await dispatch({
    phase: "attacker-owner-control",
    actor: "attacker",
    target: "attacker",
    lane: input.lane,
    sessionId: input.attacker.sessionId,
    marker: input.attacker.marker,
    knownPath: input.attacker.knownPath,
  });
  if (!attackerControl.exactMarkerConfirmed) {
    return {
      attackerOwnerControlPassed: false,
      victimOwnerControlPassed: false,
      foreignDispatched: false,
    };
  }

  const victimControl = await dispatch({
    phase: "victim-owner-control",
    actor: "victim",
    target: "victim",
    lane: input.lane,
    sessionId: input.victim.sessionId,
    marker: input.victim.marker,
    knownPath: input.victim.knownPath,
  });
  if (!victimControl.exactMarkerConfirmed) {
    return {
      attackerOwnerControlPassed: true,
      victimOwnerControlPassed: false,
      foreignDispatched: false,
    };
  }

  await dispatch({
    phase: "foreign",
    actor: "attacker",
    target: "victim",
    lane: input.lane,
    sessionId: input.victim.sessionId,
    marker: input.victim.marker,
    knownPath: input.victim.knownPath,
  });
  return {
    attackerOwnerControlPassed: true,
    victimOwnerControlPassed: true,
    foreignDispatched: true,
  };
}

export async function orchestrateCleanupOnlyRecovery(
  recoverAttacker: () => Promise<boolean>,
  recoverVictim: () => Promise<boolean>,
  forbiddenDispatch: (
    operation: AuthorizationOperation,
  ) => Promise<{ exactMarkerConfirmed: boolean }>,
): Promise<CleanupOnlySequenceResult> {
  const attackerRecoveryPassed = await recoverAttacker();
  const victimRecoveryPassed = await recoverVictim();
  const sequence = await orchestrateAuthorizationRequests(
    { cleanupOnly: true },
    forbiddenDispatch,
  );
  return { ...sequence, attackerRecoveryPassed, victimRecoveryPassed };
}

function exactTags(left: Record<string, string> | undefined, right: Record<string, string>): boolean {
  if (!left) return false;
  const leftEntries = Object.entries(left).sort(([a], [b]) => a.localeCompare(b));
  const rightEntries = Object.entries(right).sort(([a], [b]) => a.localeCompare(b));
  return JSON.stringify(leftEntries) === JSON.stringify(rightEntries);
}

function cleanupError(stage: string, error: unknown): CleanupError {
  const failure = apiFailureFromError(error);
  return {
    stage,
    kind: failure.kind,
    ...(failure.status !== undefined ? { status: failure.status } : {}),
    ...(failure.code !== undefined ? { code: failure.code } : {}),
  };
}

function validateOwnedSandbox(target: CleanupTarget, sandbox: Sandbox): boolean {
  const createdAtMs = sandbox.createdAt.getTime();
  const inCreationWindow = !target.enforceCreationWindow ||
    (createdAtMs >= target.creationWindowStartedAtMs - 5_000 && createdAtMs <= Date.now() + 5_000);
  return sandbox.name === target.name && exactTags(sandbox.tags, target.expectedTags) &&
    sandbox.persistent === false && sandbox.networkPolicy === "deny-all" && inCreationWindow;
}

async function ownerGet(target: CleanupTarget): Promise<Sandbox> {
  return Sandbox.get({
    ...sdkCredentials(target.owner),
    fetch: target.ownerFetch,
    name: target.name,
    resume: false,
    signal: AbortSignal.timeout(SETUP_TIMEOUT_MS),
  });
}

async function boundedAbsenceDelay(milliseconds: number): Promise<void> {
  await delay(milliseconds, undefined, {
    signal: AbortSignal.timeout(milliseconds + 2_000),
  });
}

export async function confirmTwoAbsences(
  probe: () => Promise<boolean>,
  wait: (milliseconds: number) => Promise<void> = boundedAbsenceDelay,
  firstAlreadyConfirmed = false,
): Promise<{ confirmed: boolean; attempts: number; delayMs?: number }> {
  let attempts = firstAlreadyConfirmed ? 1 : 0;
  let first = true;
  if (!firstAlreadyConfirmed) {
    first = await probe();
    attempts = 1;
  }
  if (!first) return { confirmed: false, attempts };
  await wait(ABSENCE_CONFIRMATION_DELAY_MS);
  const second = await probe();
  attempts += 1;
  return {
    confirmed: second,
    attempts,
    delayMs: ABSENCE_CONFIRMATION_DELAY_MS,
  };
}

async function confirmTargetAbsence(
  target: CleanupTarget,
  firstAlreadyConfirmed = false,
): Promise<void> {
  const errorsBefore = target.errors.length;
  let result: Awaited<ReturnType<typeof confirmTwoAbsences>>;
  try {
    result = await confirmTwoAbsences(async () => {
      try {
        await ownerGet(target);
        return false;
      } catch (error) {
        const failure = apiFailureFromError(error);
        if (failure.kind === "api" && failure.status === 404) return true;
        target.errors.push(cleanupError("absence", error));
        return false;
      }
    }, boundedAbsenceDelay, firstAlreadyConfirmed);
  } catch (error) {
    target.errors.push(cleanupError("absence-delay", error));
    target.absenceConfirmationAttempts += 1;
    target.absenceChecked = true;
    target.absenceConfirmed = false;
    return;
  }
  target.absenceConfirmationAttempts += result.attempts;
  if (result.delayMs !== undefined) target.absenceConfirmationDelayMs = result.delayMs;
  target.absenceChecked = result.attempts > 0;
  target.absenceConfirmed = result.confirmed;
  if (!result.confirmed && target.errors.length === errorsBefore) {
    target.errors.push({ stage: "absence", kind: "provenance" });
  }
}

async function cleanupOwnedSandbox(target: CleanupTarget): Promise<void> {
  if (!target.handle && !target.createAttempted) return;
  if (!target.handle && target.createAttempted) {
    try {
      const recovered = await ownerGet(target);
      if (!validateOwnedSandbox(target, recovered)) {
        target.errors.push({ stage: "recover", kind: "provenance" });
      } else {
        target.handle = recovered;
        target.recovered = true;
        target.provenancePassed = true;
      }
    } catch (error) {
      const failure = apiFailureFromError(error);
      if (failure.kind === "api" && failure.status === 404) {
        await confirmTargetAbsence(target, true);
        return;
      }
      target.errors.push(cleanupError("recover", error));
    }
  }

  const sandbox = target.handle;
  if (sandbox) {
    if (!validateOwnedSandbox(target, sandbox)) {
      target.errors.push({ stage: "pre-cleanup", kind: "provenance" });
    } else {
      target.provenancePassed = true;
      target.stopAttempted = true;
      try {
        await sandbox.stop({ signal: AbortSignal.timeout(SETUP_TIMEOUT_MS) });
        target.stopAccepted = true;
      } catch (error) {
        const failure = apiFailureFromError(error);
        if (failure.kind === "api" && (failure.status === 404 || failure.status === 410)) {
          target.stopAccepted = true;
        } else {
          target.errors.push(cleanupError("stop", error));
        }
      }

      target.deleteAttempted = true;
      try {
        await sandbox.delete({ signal: AbortSignal.timeout(SETUP_TIMEOUT_MS) });
        target.deleteAccepted = true;
      } catch (error) {
        const failure = apiFailureFromError(error);
        if (failure.kind === "api" && failure.status === 404) {
          target.deleteAccepted = true;
        } else {
          target.errors.push(cleanupError("delete", error));
        }
      }
    }
  }

  await confirmTargetAbsence(target);
}

function cleanupPassed(target: CleanupTarget): boolean {
  if (!target.handle && !target.createAttempted) return target.errors.length === 0;
  if (target.errors.length > 0 || !target.absenceChecked || !target.absenceConfirmed) return false;
  if (target.handle && !target.provenancePassed) return false;
  return !target.handle || (target.stopAccepted && target.deleteAccepted);
}

async function recoverOwnedOrConfirmAbsent(target: CleanupTarget): Promise<void> {
  try {
    const orphan = await ownerGet(target);
    if (!validateOwnedSandbox(target, orphan)) {
      target.errors.push({ stage: "preflight", kind: "provenance" });
      return;
    }
    target.handle = orphan;
    target.recovered = true;
    target.provenancePassed = true;
    await cleanupOwnedSandbox(target);
  } catch (error) {
    const failure = apiFailureFromError(error);
    if (failure.kind === "api" && failure.status === 404) {
      await confirmTargetAbsence(target, true);
    } else {
      target.errors.push(cleanupError("preflight", error));
    }
  }
}

function newCleanupTarget(
  name: string,
  expectedTags: Record<string, string>,
  owner: ExplicitAccountCredentials,
  ownerFetch: typeof fetch,
  creationWindowStartedAtMs: number,
  enforceCreationWindow: boolean,
): CleanupTarget {
  return {
    name,
    expectedTags,
    owner,
    ownerFetch,
    enforceCreationWindow,
    creationWindowStartedAtMs,
    createAttempted: false,
    recovered: false,
    provenancePassed: false,
    stopAttempted: false,
    stopAccepted: false,
    deleteAttempted: false,
    deleteAccepted: false,
    absenceChecked: false,
    absenceConfirmed: false,
    absenceConfirmationAttempts: 0,
    errors: [],
  };
}

function commandShape(
  value: unknown,
  expectedSessionId: string,
  marker: string,
): value is { id: string; sessionId: string; exitCode: number | null } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const command = value as Record<string, unknown>;
  return typeof command.id === "string" && command.id.length > 0 && command.id.length <= 256 &&
    command.sessionId === expectedSessionId && command.name === "printf" &&
    Array.isArray(command.args) && command.args.length === 2 &&
    command.args[0] === "%s" && command.args[1] === marker &&
    command.cwd === "/vercel/sandbox" &&
    (command.exitCode === null || Number.isSafeInteger(command.exitCode));
}

export function parseCommandResponse(
  body: Uint8Array,
  expectedSessionId: string,
  marker: string,
): CommandParseSummary {
  let parsedLines: unknown[];
  try {
    const view = Buffer.isBuffer(body)
      ? body
      : Buffer.from(body.buffer, body.byteOffset, body.byteLength);
    const text = view.toString("utf8");
    const lines = text.split("\n").filter((line) => line.length > 0);
    if (lines.length < 2 || lines.length > 16) {
      return {
        exact: false,
        lineCount: lines.length,
        stdoutBytes: 0,
        stderrBytes: 0,
        sessionIdMatched: false,
        commandShapeMatched: false,
      };
    }
    parsedLines = lines.map((line) => JSON.parse(line) as unknown);
  } catch {
    return {
      exact: false,
      lineCount: 0,
      stdoutBytes: 0,
      stderrBytes: 0,
      sessionIdMatched: false,
      commandShapeMatched: false,
    };
  }

  const firstEnvelope = parsedLines[0];
  const finalEnvelope = parsedLines.at(-1);
  const firstCommand = firstEnvelope !== null && typeof firstEnvelope === "object" &&
      !Array.isArray(firstEnvelope)
    ? (firstEnvelope as { command?: unknown }).command
    : undefined;
  const finalCommand = finalEnvelope !== null && typeof finalEnvelope === "object" &&
      !Array.isArray(finalEnvelope)
    ? (finalEnvelope as { command?: unknown }).command
    : undefined;
  const firstMatched = commandShape(firstCommand, expectedSessionId, marker);
  const finalMatched = commandShape(finalCommand, expectedSessionId, marker);
  let stdout = "";
  let stderr = "";
  let invalidLog = false;
  for (const line of parsedLines.slice(1, -1)) {
    if (line === null || typeof line !== "object" || Array.isArray(line)) {
      invalidLog = true;
      continue;
    }
    const log = line as { stream?: unknown; data?: unknown };
    if (log.stream === "stdout" && typeof log.data === "string") stdout += log.data;
    else if (log.stream === "stderr" && typeof log.data === "string") stderr += log.data;
    else invalidLog = true;
  }
  const finalExitCode = finalMatched ? finalCommand.exitCode : undefined;
  const sameCommand = firstMatched && finalMatched && firstCommand.id === finalCommand.id &&
    firstCommand.exitCode === null;
  const sessionIdMatched = firstMatched && finalMatched;
  const commandShapeMatched = sameCommand;
  return {
    exact: commandShapeMatched && !invalidLog && finalExitCode === 0 &&
      stdout === marker && stderr === "",
    lineCount: parsedLines.length,
    stdoutBytes: Buffer.byteLength(stdout),
    stderrBytes: Buffer.byteLength(stderr),
    ...(typeof finalExitCode === "number" ? { finalExitCode } : {}),
    sessionIdMatched,
    commandShapeMatched,
  };
}

async function fileReadAttempt(
  account: ExplicitAccountCredentials,
  accountFetch: typeof fetch,
  sessionId: string,
  path: string,
  marker: string,
): Promise<SanitizedAttempt> {
  const expectedMarker = Buffer.from(marker, "utf8");
  try {
    const response = await oneShotSandboxRequest(
      account,
      accountFetch,
      `/v2/sandboxes/sessions/${encodeURIComponent(sessionId)}/fs/read`,
      {
        method: "POST",
        headers: { "content-type": "application/json", Accept: "application/octet-stream" },
        body: JSON.stringify({ path }),
        signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
      },
    );
    const contentType = response.headers.get("content-type") ?? "";
    if (!response.ok) {
      const failure = await apiFailureFromResponse(response);
      return { status: response.status, contentType, failure, httpSucceeded: false, exactMarkerConfirmed: false };
    }
    const body = await readBoundedResponse(response);
    try {
      return {
        status: response.status,
        contentType,
        responseBytes: body.length,
        httpSucceeded: true,
        exactMarkerConfirmed: response.status === 200 &&
          exactContentType(response, "application/octet-stream") && body.equals(expectedMarker),
      };
    } finally {
      body.fill(0);
    }
  } catch (error) {
    const failure = apiFailureFromError(error);
    return { failure, httpSucceeded: false, exactMarkerConfirmed: false };
  } finally {
    expectedMarker.fill(0);
  }
}

async function commandRunAttempt(
  account: ExplicitAccountCredentials,
  accountFetch: typeof fetch,
  sessionId: string,
  marker: string,
): Promise<SanitizedAttempt & { command?: CommandParseSummary }> {
  try {
    const response = await oneShotSandboxRequest(
      account,
      accountFetch,
      `/v2/sandboxes/sessions/${encodeURIComponent(sessionId)}/cmd`,
      {
        method: "POST",
        headers: { "content-type": "application/json", Accept: "application/x-ndjson" },
        body: JSON.stringify(commandRequestPayload(marker)),
        signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
      },
    );
    const contentType = response.headers.get("content-type") ?? "";
    if (!response.ok) {
      const failure = await apiFailureFromResponse(response);
      return { status: response.status, contentType, failure, httpSucceeded: false, exactMarkerConfirmed: false };
    }
    const body = await readBoundedResponse(response, MAXIMUM_COMMAND_RESPONSE_BYTES);
    try {
      const command = exactContentType(response, "application/x-ndjson")
        ? parseCommandResponse(body, sessionId, marker)
        : undefined;
      return {
        status: response.status,
        contentType,
        responseBytes: body.length,
        httpSucceeded: true,
        exactMarkerConfirmed: response.status === 200 && command?.exact === true,
        ...(command ? { command } : {}),
      };
    } finally {
      body.fill(0);
    }
  } catch (error) {
    const failure = apiFailureFromError(error);
    return { failure, httpSucceeded: false, exactMarkerConfirmed: false };
  }
}

export function commandRequestPayload(marker: string): {
  command: "printf";
  args: ["%s", string];
  cwd: "/vercel/sandbox";
  env: Record<string, never>;
  sudo: false;
  wait: true;
  logs: true;
  timeout: number;
} {
  return {
    command: "printf",
    args: ["%s", marker],
    cwd: "/vercel/sandbox",
    env: {},
    sudo: false,
    wait: true,
    logs: true,
    timeout: COMMAND_TIMEOUT_MS,
  };
}

function qpsAudit(records: readonly RequestAuditRecord[]): QpsAudit {
  const starts = records.map((record) => Date.parse(record.startedAt));
  const intervals = starts.slice(1).map((startedAt, index) => startedAt - starts[index]!);
  const minimumObservedIntervalMs = intervals.length > 0 ? Math.min(...intervals) : undefined;
  const maximumObservedStartsPerSecond = minimumObservedIntervalMs === undefined
    ? 0
    : 1_000 / minimumObservedIntervalMs;
  return {
    requestCount: records.length,
    ...(minimumObservedIntervalMs !== undefined ? { minimumObservedIntervalMs } : {}),
    ...(maximumObservedStartsPerSecond !== undefined ? { maximumObservedStartsPerSecond } : {}),
    passed: intervals.every((interval) => interval >= MINIMUM_VERCEL_REQUEST_INTERVAL_MS) &&
      maximumObservedStartsPerSecond <= 4,
  };
}

export function conclusiveSessionCommandRejection(failure: ApiFailure): boolean {
  if (!conclusiveAuthorizationRejection(failure)) return false;
  return !(failure.status === 422 && failure.code === "snapshot_not_found");
}

function cleanupEvidence(target: CleanupTarget): Record<string, unknown> {
  return {
    createAttempted: target.createAttempted,
    recovered: target.recovered,
    provenancePassed: target.provenancePassed,
    stopAttempted: target.stopAttempted,
    stopAccepted: target.stopAccepted,
    deleteAttempted: target.deleteAttempted,
    deleteAccepted: target.deleteAccepted,
    absenceChecked: target.absenceChecked,
    absenceConfirmed: target.absenceConfirmed,
    absenceConfirmationAttempts: target.absenceConfirmationAttempts,
    absenceConfirmationDelayMs: target.absenceConfirmationDelayMs,
    errors: target.errors,
  };
}

function emptyRequestCounters(): RequestCounters {
  return {
    attackerOwnerControlRequests: 0,
    attackerOwnerControlTransportCalls: 0,
    victimOwnerControlRequests: 0,
    victimOwnerControlTransportCalls: 0,
    foreignRequests: 0,
    foreignTransportCalls: 0,
    crossKnownPathReads: 0,
    deferredCrossOperations: 0,
  };
}

async function writePrivateEvidence(
  lane: SessionCommandLane,
  runId: string,
  cleanupOnly: boolean,
  evidence: unknown,
  forbiddenMarkers: readonly string[] = [],
): Promise<string> {
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "artifacts");
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const suffix = cleanupOnly
    ? `cleanup-only-${lane}-${runId}-${randomUUID()}`
    : `${lane}-${runId}`;
  const evidencePath = resolve(
    artifactsDirectory,
    `SBX-026-session-command-${suffix}-private.json`,
  );
  const serializedEvidence = `${JSON.stringify(evidence, null, 2)}\n`;
  if (forbiddenMarkers.some((marker) => serializedEvidence.includes(marker))) {
    throw new Error("refused to retain a raw marker in session-command evidence");
  }
  await writeFile(evidencePath, serializedEvidence, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
    flush: true,
  });
  return evidencePath;
}

async function run(): Promise<void> {
  const lane = parseSessionCommandLane(process.argv.slice(2));
  if (process.env.SBX026_SESSION_COMMAND_CONFIRMATION !== SESSION_COMMAND_CONFIRMATION) {
    throw new Error(
      `SBX026_SESSION_COMMAND_CONFIRMATION must equal ${SESSION_COMMAND_CONFIRMATION}`,
    );
  }
  const accounts = loadTwoOwnedAccounts();
  const { runId, cleanupOnly } = resolveRunMode(process.env);
  const startedAtMs = Date.now();
  const startedAt = new Date(startedAtMs).toISOString();
  const metadata = deterministicFixtureMetadata(lane, runId);
  const gate = new VercelRequestGate();
  const attackerFetch = createAccountFetch(accounts.attacker, gate);
  const victimFetch = createAccountFetch(accounts.victim, gate);
  const counters = emptyRequestCounters();
  const attackerPreflight = newCleanupTarget(
    metadata.attacker.name,
    metadata.attacker.tags,
    accounts.attacker,
    attackerFetch,
    0,
    false,
  );
  const victimPreflight = newCleanupTarget(
    metadata.victim.name,
    metadata.victim.tags,
    accounts.victim,
    victimFetch,
    0,
    false,
  );
  console.log(JSON.stringify({
    testId: TEST_ID,
    lane,
    runId,
    phase: cleanupOnly ? "cleanup-only" : "starting-disabled-lane",
  }));

  // The shared helper fixes one repository-global path. Neither cwd nor
  // HARNESS_ARTIFACTS_DIR can create an independent live-request lock domain.
  const liveLock = await acquireSbx026LiveLock(
    sessionCommandLiveLockOptions(lane, runId, cleanupOnly),
  );
  const attackerIdentity = await verifyAccountIdentity(accounts.attacker, attackerFetch);
  const victimIdentity = await verifyAccountIdentity(accounts.victim, victimFetch);
  const exactIdentitiesVerified = assertDistinctVerifiedIdentities(
    attackerIdentity,
    victimIdentity,
  );
  const identitiesDistinct = true;

  if (cleanupOnly) {
    let unexpectedDispatches = 0;
    const sequence = await orchestrateCleanupOnlyRecovery(
      async () => {
        await recoverOwnedOrConfirmAbsent(attackerPreflight);
        return cleanupPassed(attackerPreflight) && attackerPreflight.absenceConfirmed &&
          attackerPreflight.absenceConfirmationAttempts >= 2;
      },
      async () => {
        await recoverOwnedOrConfirmAbsent(victimPreflight);
        return cleanupPassed(victimPreflight) && victimPreflight.absenceConfirmed &&
          victimPreflight.absenceConfirmationAttempts >= 2;
      },
      async () => {
        unexpectedDispatches += 1;
        return { exactMarkerConfirmed: false };
      },
    );
    const qps = qpsAudit(gate.records);
    const cleanupComplete = sequence.attackerRecoveryPassed &&
      sequence.victimRecoveryPassed && qps.passed &&
      unexpectedDispatches === 0 && !sequence.foreignDispatched;
    const evidence = {
      schemaVersion: 2,
      testId: TEST_ID,
      packet: "session-command-authorization",
      mode: "cleanup-only",
      lane,
      runId,
      suppliedRunIdForcedCleanupOnly: true,
      completedUuidReplayPrevented: true,
      ...releaseNeutralSessionCommandEvidenceState("cleanup-only"),
      liveLock: {
        filename: SBX026_LIVE_LOCK_FILENAME,
        fixedRepoPath: true,
        scope: liveLock.metadata.scope,
        lane: liveLock.metadata.lane,
        runId: liveLock.metadata.runId,
        mode: liveLock.metadata.mode,
        reclaimed: liveLock.reclaimed,
        heldThroughEvidenceWrite: true,
        releasedAfterEvidenceWrite: false,
      },
      startedAt,
      pendingEvidenceWrittenAt: new Date().toISOString(),
      prerequisites: {
        exactAliasIdentitiesVerified: exactIdentitiesVerified,
        distinctEmails: attackerIdentity.email !== victimIdentity.email,
        distinctUserIds: attackerIdentity.userId !== victimIdentity.userId,
        attackerEmailSha256: sha256(attackerIdentity.email),
        victimEmailSha256: sha256(victimIdentity.email),
        attackerUserIdSha256: sha256(attackerIdentity.userId),
        victimUserIdSha256: sha256(victimIdentity.userId),
      },
      deterministicFixtures: {
        attacker: { name: metadata.attacker.name, tags: metadata.attacker.tags },
        victim: { name: metadata.victim.name, tags: metadata.victim.tags },
      },
      orchestration: { ...sequence, unexpectedDispatches },
      controls: { dispatched: 0 },
      foreign: { requestAttempted: false, transportCalls: 0 },
      counters,
      requestRateAudit: {
        ...qps,
        requiredMinimumIntervalMs: MINIMUM_VERCEL_REQUEST_INTERVAL_MS,
        records: gate.records,
      },
      cleanup: {
        attacker: cleanupEvidence(attackerPreflight),
        victim: cleanupEvidence(victimPreflight),
        passed: cleanupComplete,
      },
    };
    const evidencePath = await writePrivateEvidence(lane, runId, true, evidence);
    const finalResult = await finalizeSessionCommandAfterLiveLockRelease(
      "cleanup-only",
      evidence,
      evidencePath,
      liveLock,
      exactIdentitiesVerified && identitiesDistinct && cleanupComplete,
      () => ({
        testId: TEST_ID,
        lane,
        runId,
        mode: "cleanup-only",
        outcome: "cleanup-complete",
        foreignRequests: 0,
      }),
      (result) => console.log(JSON.stringify(result, null, 2)),
    );
    if (finalResult === undefined) process.exitCode = 1;
    return;
  }

  const attackerMarkerBuffer = Buffer.from(
    `sbx026_attacker_${runId}_${randomBytes(24).toString("base64url")}`,
    "utf8",
  );
  const victimMarkerBuffer = Buffer.from(
    `sbx026_victim_${runId}_${randomBytes(24).toString("base64url")}`,
    "utf8",
  );
  const attackerMarker = attackerMarkerBuffer.toString("utf8");
  const victimMarker = victimMarkerBuffer.toString("utf8");
  const plans = createFixturePlans(lane, runId, attackerMarker, victimMarker);
  const attackerTarget = newCleanupTarget(
    plans.attacker.name,
    plans.attacker.tags,
    accounts.attacker,
    attackerFetch,
    startedAtMs,
    true,
  );
  const victimTarget = newCleanupTarget(
    plans.victim.name,
    plans.victim.tags,
    accounts.victim,
    victimFetch,
    startedAtMs,
    true,
  );

  let setupError: string | undefined;
  let attackerSessionId: string | undefined;
  let victimSessionId: string | undefined;
  let attackerOwnerControlPassed = false;
  let victimOwnerControlPassed = false;
  let attackerControlAttempt: (SanitizedAttempt & { command?: CommandParseSummary }) | undefined;
  let victimControlAttempt: (SanitizedAttempt & { command?: CommandParseSummary }) | undefined;
  let foreignAttempt: (SanitizedAttempt & { command?: CommandParseSummary }) | undefined;
  let attackerControlAuditSequence: number | undefined;
  let victimControlAuditSequence: number | undefined;
  let foreignAuditSequence: number | undefined;
  let foreignBindingPassed = false;
  let sameAccountControlImmediatelyPrecededCross = false;
  let operationConstraintsPassed = true;

  try {
    attackerTarget.createAttempted = true;
    const attackerSandbox = await Sandbox.create({
      ...sdkCredentials(accounts.attacker),
      fetch: attackerFetch,
      name: plans.attacker.name,
      persistent: false,
      timeout: SANDBOX_TIMEOUT_MS,
      networkPolicy: "deny-all",
      tags: plans.attacker.tags,
      signal: AbortSignal.timeout(SETUP_TIMEOUT_MS),
    });
    attackerTarget.handle = attackerSandbox;
    attackerTarget.provenancePassed = validateOwnedSandbox(attackerTarget, attackerSandbox);
    if (!attackerTarget.provenancePassed) throw new Error("created-attacker-provenance-failed");
    attackerSessionId = attackerSandbox.currentSession().sessionId;

    victimTarget.createAttempted = true;
    const victimSandbox = await Sandbox.create({
      ...sdkCredentials(accounts.victim),
      fetch: victimFetch,
      name: plans.victim.name,
      persistent: false,
      timeout: SANDBOX_TIMEOUT_MS,
      networkPolicy: "deny-all",
      tags: plans.victim.tags,
      signal: AbortSignal.timeout(SETUP_TIMEOUT_MS),
    });
    victimTarget.handle = victimSandbox;
    victimTarget.provenancePassed = validateOwnedSandbox(victimTarget, victimSandbox);
    if (!victimTarget.provenancePassed) throw new Error("created-victim-provenance-failed");
    victimSessionId = victimSandbox.currentSession().sessionId;
    assertDistinctBoundedSessionIds(attackerSessionId, victimSessionId);

    if (lane === "session-read") {
      await attackerSandbox.writeFiles(
        [{ path: plans.attacker.knownPath, content: attackerMarkerBuffer, mode: 0o600 }],
        { signal: AbortSignal.timeout(SETUP_TIMEOUT_MS) },
      );
      await victimSandbox.writeFiles(
        [{ path: plans.victim.knownPath, content: victimMarkerBuffer, mode: 0o600 }],
        { signal: AbortSignal.timeout(SETUP_TIMEOUT_MS) },
      );
    }

    const sequence = await orchestrateAuthorizationRequests({
      cleanupOnly: false,
      lane,
      attacker: { ...plans.attacker, sessionId: attackerSessionId },
      victim: { ...plans.victim, sessionId: victimSessionId },
    }, async (operation) => {
      const account = operation.actor === "attacker" ? accounts.attacker : accounts.victim;
      const accountFetch = operation.actor === "attacker" ? attackerFetch : victimFetch;
      const auditStart = gate.records.length;
      if (operation.phase === "attacker-owner-control") {
        counters.attackerOwnerControlRequests += 1;
      } else if (operation.phase === "victim-owner-control") {
        counters.victimOwnerControlRequests += 1;
      } else {
        counters.foreignRequests += 1;
        if (lane === "session-read") counters.crossKnownPathReads += 1;
        foreignBindingPassed = operation.actor === "attacker" && operation.target === "victim" &&
          operation.sessionId === victimSessionId && operation.marker === victimMarker &&
          operation.knownPath === plans.victim.knownPath;
        if (!foreignBindingPassed) throw new Error("foreign operation lost its victim binding");
      }
      const attempt = operation.lane === "session-read"
        ? await fileReadAttempt(
            account,
            accountFetch,
            operation.sessionId,
            operation.knownPath,
            operation.marker,
          )
        : await commandRunAttempt(
            account,
            accountFetch,
            operation.sessionId,
            operation.marker,
          );
      const auditRecords = gate.records.slice(auditStart);
      const auditSequence = auditRecords.length === 1 ? auditRecords[0]?.sequence : undefined;
      if (operation.phase === "attacker-owner-control") {
        attackerControlAttempt = attempt;
        attackerControlAuditSequence = auditSequence;
        counters.attackerOwnerControlTransportCalls = auditRecords.length;
      } else if (operation.phase === "victim-owner-control") {
        victimControlAttempt = attempt;
        victimControlAuditSequence = auditSequence;
        counters.victimOwnerControlTransportCalls = auditRecords.length;
      } else {
        foreignAttempt = attempt;
        foreignAuditSequence = auditSequence;
        counters.foreignTransportCalls = auditRecords.length;
      }
      return {
        exactMarkerConfirmed: attempt.httpSucceeded && attempt.exactMarkerConfirmed &&
          auditRecords.length === 1,
      };
    });
    attackerOwnerControlPassed = sequence.attackerOwnerControlPassed;
    victimOwnerControlPassed = sequence.victimOwnerControlPassed;
    sameAccountControlImmediatelyPrecededCross = sequence.foreignDispatched &&
      victimControlAuditSequence !== undefined &&
      foreignAuditSequence === victimControlAuditSequence + 1;
    operationConstraintsPassed = sequence.foreignDispatched
      ? lane === "session-read"
        ? foreignBindingPassed && counters.foreignTransportCalls === 1 &&
          counters.crossKnownPathReads === 1 &&
          counters.deferredCrossOperations === 0
        : foreignBindingPassed && counters.foreignTransportCalls === 1 &&
          counters.crossKnownPathReads === 0 &&
          counters.deferredCrossOperations === 0
      : true;
  } catch {
    setupError = "prerequisite-or-owned-target-setup-failed";
  } finally {
    try {
      await cleanupOwnedSandbox(victimTarget);
    } finally {
      try {
        await cleanupOwnedSandbox(attackerTarget);
      } finally {
        attackerMarkerBuffer.fill(0);
        victimMarkerBuffer.fill(0);
      }
    }
  }

  const qps = qpsAudit(gate.records);
  const foreignRejected = foreignAttempt !== undefined && !foreignAttempt.httpSucceeded &&
    foreignAttempt.status !== undefined;
  const foreignSucceeded = foreignAttempt?.httpSucceeded === true;
  const foreignRejectionConclusive = foreignAttempt?.failure !== undefined &&
    conclusiveSessionCommandRejection(foreignAttempt.failure);
  const allCleanupPassed = cleanupPassed(attackerTarget) && cleanupPassed(victimTarget);
  const exactCleanupAndAbsencePassed = allCleanupPassed &&
    attackerTarget.absenceConfirmed && attackerTarget.absenceConfirmationAttempts >= 2 &&
    victimTarget.absenceConfirmed && victimTarget.absenceConfirmationAttempts >= 2;
  const assessmentInput = {
    lane,
    ...(setupError !== undefined ? { setupError } : {}),
    cleanupPassed: exactCleanupAndAbsencePassed,
    exactIdentitiesVerified,
    identitiesDistinct,
    attackerOwnerControlPassed,
    victimOwnerControlPassed,
    sameAccountControlRequestCount:
      counters.attackerOwnerControlRequests + counters.victimOwnerControlRequests,
    sameAccountControlImmediatelyPrecededCross,
    operationConstraintsPassed,
    foreignRequestAttempted: counters.foreignRequests === 1,
    foreignRequestCount: counters.foreignRequests,
    crossKnownPathReadCount: counters.crossKnownPathReads,
    deferredCrossOperationCount: counters.deferredCrossOperations,
    foreignRejected,
    foreignRejectionConclusive,
    foreignSucceeded,
    exactMarkerConfirmed: foreignAttempt?.exactMarkerConfirmed === true,
    qpsAuditPassed: qps.passed,
    rawMarkerOrBodyRetained: false,
  };
  const evidence = {
    schemaVersion: 2,
    testId: TEST_ID,
    packet: "session-command-authorization",
    lane,
    runId,
    mode: "test",
    runIdWasRandomlyGenerated: true,
    ...releaseNeutralSessionCommandEvidenceState("test"),
    liveLock: {
      filename: SBX026_LIVE_LOCK_FILENAME,
      fixedRepoPath: true,
      scope: liveLock.metadata.scope,
      lane: liveLock.metadata.lane,
      runId: liveLock.metadata.runId,
      mode: liveLock.metadata.mode,
      reclaimed: liveLock.reclaimed,
      heldThroughEvidenceWrite: true,
      releasedAfterEvidenceWrite: false,
    },
    startedAt,
    pendingEvidenceWrittenAt: new Date().toISOString(),
    prerequisites: {
      exactAliasIdentitiesVerified: exactIdentitiesVerified,
      distinctEmails: attackerIdentity !== undefined && victimIdentity !== undefined &&
        attackerIdentity.email !== victimIdentity.email,
      distinctUserIds: attackerIdentity !== undefined && victimIdentity !== undefined &&
        attackerIdentity.userId !== victimIdentity.userId,
      attackerEmailSha256: sha256(attackerIdentity.email),
      victimEmailSha256: sha256(victimIdentity.email),
      attackerUserIdSha256: sha256(attackerIdentity.userId),
      victimUserIdSha256: sha256(victimIdentity.userId),
      scopeConfirmationPassed: true,
      ownershipConfirmationPassed: true,
      noCrossMembershipConfirmationPassed: true,
      laneConfirmationPassed: true,
    },
    ownedFixtures: {
      attacker: {
        name: plans.attacker.name,
        sessionId: attackerSessionId,
        teamIdSha256: sha256(accounts.attacker.teamId),
        projectIdSha256: sha256(accounts.attacker.projectId),
        persistent: false,
        networkPolicy: "deny-all",
        tags: plans.attacker.tags,
        ...(lane === "session-read" ? { knownPath: plans.attacker.knownPath } : {}),
      },
      victim: {
        name: plans.victim.name,
        sessionId: victimSessionId,
        teamIdSha256: sha256(accounts.victim.teamId),
        projectIdSha256: sha256(accounts.victim.projectId),
        persistent: false,
        networkPolicy: "deny-all",
        tags: plans.victim.tags,
        ...(lane === "session-read" ? { knownPath: plans.victim.knownPath } : {}),
      },
    },
    markers: {
      distinct: attackerMarker !== victimMarker,
      attacker: {
        sha256: sha256(attackerMarker),
        bytes: Buffer.byteLength(attackerMarker),
      },
      victim: {
        sha256: sha256(victimMarker),
        bytes: Buffer.byteLength(victimMarker),
      },
      rawMarkersRetained: false,
    },
    controls: {
      passed: attackerOwnerControlPassed && victimOwnerControlPassed,
      immediatelyPrecededCross: sameAccountControlImmediatelyPrecededCross,
      attackerOwner: {
        passed: attackerOwnerControlPassed,
        auditSequence: attackerControlAuditSequence,
        attempt: attackerControlAttempt,
      },
      victimOwner: {
        passed: victimOwnerControlPassed,
        auditSequence: victimControlAuditSequence,
        attempt: victimControlAttempt,
      },
    },
    foreign: {
      auditSequence: foreignAuditSequence,
      actor: "attacker",
      target: "victim",
      victimBindingPassed: foreignBindingPassed,
      expectedVictimMarkerSha256: sha256(victimMarker),
      ...(lane === "session-read" ? { expectedVictimKnownPath: plans.victim.knownPath } : {}),
      requesterTeamIdSha256: sha256(accounts.attacker.teamId),
      targetTeamIdSha256: sha256(accounts.victim.teamId),
      requestImplementation: "shared oneShotSandboxRequest over account-scoped fetch; no SDK retry wrapper",
      rejected: foreignRejected,
      rejectionConclusive: foreignRejectionConclusive,
      succeeded: foreignSucceeded,
      exactMarkerConfirmed: foreignAttempt?.exactMarkerConfirmed === true,
      attempt: foreignAttempt,
    },
    counters,
    constraints: {
      oneLaneOnly: true,
      rawForeignRequestNoRetry: true,
      oneKnownPathReadMaximum: counters.crossKnownPathReads <= 1,
      commandExecutable: lane === "command-run" ? "printf" : undefined,
      commandUsedShell: false,
      commandFilesystemWrite: false,
      interactiveDeferred: true,
      crossAccountStopKillMutationDeferred: true,
      rawRequestBodyRetained: false,
      rawResponseBodyRetained: false,
    },
    requestRateAudit: {
      ...qps,
      requiredMinimumIntervalMs: MINIMUM_VERCEL_REQUEST_INTERVAL_MS,
      records: gate.records,
    },
    cleanup: {
      ownerTargets: {
        attacker: cleanupEvidence(attackerTarget),
        victim: cleanupEvidence(victimTarget),
      },
      passed: exactCleanupAndAbsencePassed,
    },
  };
  const evidencePath = await writePrivateEvidence(
    lane,
    runId,
    false,
    evidence,
    [attackerMarker, victimMarker],
  );
  const finalResult = await finalizeSessionCommandAfterLiveLockRelease(
    "test",
    evidence,
    evidencePath,
    liveLock,
    exactIdentitiesVerified && identitiesDistinct && exactCleanupAndAbsencePassed,
    () => {
      const assessment = assessSessionCommandAuthorization(assessmentInput);
      return {
        testId: TEST_ID,
        lane,
        runId,
        verdict: assessment.verdict,
        summary: assessment.summary,
        counters,
        cleanupPassed: exactCleanupAndAbsencePassed,
      };
    },
    (result) => console.log(JSON.stringify(result, null, 2)),
  );
  if (finalResult === undefined) process.exitCode = 1;
}

const directEntry = process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (directEntry) {
  run().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : "session-command harness failed");
    process.exitCode = 1;
  });
}
