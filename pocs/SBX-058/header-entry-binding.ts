import "dotenv/config";

import { randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { APIError, Sandbox, type NetworkPolicy } from "@vercel/sandbox";
import { verifyEligibleAliasToken } from "../eligible-alias-identity.js";
import {
  SBX058_CASES,
  SBX058_DECOY_HEADER,
  SBX058_EVENT_CASES,
  SBX058_MATCH_HEADER,
  SBX058_MATCH_VALUE,
  SBX058_TEST_ID,
  expectedOperationId,
  expectedReceipt,
  headerModeForCase,
  proxyAudience,
  requestPath,
  type Sbx058CaseId,
  type Sbx058EventCaseId,
  type Sbx058Role,
} from "./protocol.js";
import type { Sbx058ReceiverSnapshot } from "./receiver.js";
import {
  SBX058_ALIAS,
  SBX058_ARTIFACTS,
  SBX058_CREATE_TIMEOUT_MS,
  SBX058_PROJECT,
  SBX058_SANDBOX_TIMEOUT_MS,
  SBX058_TEAM,
  acquireSbx058Safety,
  checkpointSbx058,
  finalizeSbx058Safety,
  loadSbx058Config,
  markSbx058AbsenceOnlyTerminal,
  sbx058ArtifactPath,
  sbx058RecoveryArtifactPath,
  sbx058Tags,
  sbx058UnknownCreateSettled,
  writeSbx058NoClobber,
  type Sbx058Config,
  type Sbx058HeldSafety,
  type Sbx058Journal,
} from "./safety.js";
import {
  assessSbx058,
  exactConfiguredPolicy,
  type Sbx058AssessmentInput,
  type Sbx058CleanupEvidence,
  type Sbx058ExpectedEventProof,
  type Sbx058Identity,
  type Sbx058PolicyProof,
  type Sbx058ProbeEvidence,
  type Sbx058ProjectionMode,
  type Sbx058RetentionEvidence,
} from "./verdict.js";

const CONTROL_TIMEOUT_MS = 30_000;
const REMOTE_PROBE_PATH = "/tmp/sbx-058/header-binding-probe.mjs";
const INTER_PROBE_MS = 350;
const GUEST_SOURCE = new URL("../../guest/sbx-058-header-binding-probe.mjs", import.meta.url);

interface Credentials {
  token: string;
  teamId: string;
  projectId: string;
}

interface CommandEvidence {
  caseId: Sbx058CaseId;
  commandId: string;
  exitCode: number;
  startedAt: string;
  completedAt: string;
  configurationBytes: number;
  stdoutBytes: number;
  stderrBytes: number;
  rawOutputRetained: false;
  standaloneOutputDigestRetained: false;
}

interface CleanupResult {
  evidence: Sbx058CleanupEvidence["sandbox"];
  safe: boolean;
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

function signal(timeout = CONTROL_TIMEOUT_MS): AbortSignal {
  return AbortSignal.timeout(timeout);
}

function isNotFound(error: unknown): boolean {
  return error instanceof APIError && error.response.status === 404;
}

function safeError(error: unknown, secrets: readonly string[]): string {
  let output = error instanceof Error ? error.message : String(error);
  for (const secret of secrets) output = output.split(secret).join("[REDACTED]");
  return output.replace(/[\0\r\n]/gu, " ").slice(0, 1_000);
}

function credentials(config: Sbx058Config): Credentials {
  return { token: config.token, teamId: config.teamId, projectId: config.projectId };
}

export function sbx058Policy(aHostname: string, pOrigin: string | URL, runId: string): NetworkPolicy {
  return {
    allow: {
      [aHostname]: [{
        match: {
          headers: [{
            key: { exact: SBX058_MATCH_HEADER },
            value: { exact: SBX058_MATCH_VALUE },
          }],
        },
        forwardURL: proxyAudience(pOrigin, runId),
      }],
    },
  };
}

function exactTags(actual: Record<string, string> | undefined, expected: Record<string, string>): boolean {
  return actual !== undefined && Object.keys(actual).length === Object.keys(expected).length &&
    Object.entries(expected).every(([key, value]) => actual[key] === value);
}

export function exactSbx058CreateProvenance(sandbox: Sandbox, journal: Sbx058Journal): boolean {
  try {
    const sessionId = sandbox.currentSession().sessionId;
    return sandbox.name === journal.name && sandbox.persistent === false && exactTags(sandbox.tags, journal.tags) &&
      /^sbx_[A-Za-z0-9_-]{20,100}$/u.test(sessionId) &&
      sandbox.createdAt.getTime() >= Date.parse(journal.startedAt) - 5_000 &&
      sandbox.createdAt.getTime() <= Date.now() + 5_000;
  } catch {
    return false;
  }
}

function expectedIdentity(config: Sbx058Config, sandbox: Sandbox): Sbx058Identity {
  return {
    aliasEmail: config.aliasEmail,
    aliasIdentityVerified: true,
    teamId: config.teamId,
    projectId: config.projectId,
    sandboxName: sandbox.name,
    sessionId: sandbox.currentSession().sessionId,
  };
}

function topProjection(value: unknown, aHostname: string): boolean {
  const root = object(value);
  return root !== undefined && exactKeys(root, ["allow"]) && Array.isArray(root.allow) &&
    root.allow.length === 1 && root.allow[0] === aHostname;
}

function matcherlessProjection(value: unknown, aHostname: string, audience: string): boolean {
  const root = object(value);
  const allow = object(root?.allow);
  if (!root || !allow || !exactKeys(root, ["allow"]) || !exactKeys(allow, [aHostname]) ||
      !Array.isArray(allow[aHostname]) || allow[aHostname].length !== 1) return false;
  const rule = object(allow[aHostname][0]);
  return rule !== undefined && exactKeys(rule, ["forwardURL"]) && rule.forwardURL === audience;
}

export async function captureSbx058PolicyProof(input: {
  stage: "before" | "after";
  runId: string;
  sandbox: Sandbox;
  config: Sbx058Config;
  expected: Sbx058Identity;
  configuredPolicy: NetworkPolicy;
}): Promise<Sbx058PolicyProof> {
  const startedAt = new Date().toISOString();
  const activeSession = input.sandbox.currentSession();
  const independent = await Sandbox.get({
    ...credentials(input.config),
    name: input.sandbox.name,
    resume: false,
    signal: signal(),
  });
  if (independent.name !== input.expected.sandboxName || independent.persistent !== false ||
      !exactTags(independent.tags, sbx058Tags(input.runId)) ||
      independent.currentSession().sessionId !== input.expected.sessionId) {
    throw new Error("independent SBX-058 sandbox identity was not exact");
  }
  const activeSessionPolicy = activeSession.networkPolicy;
  const independentSessionPolicy = independent.currentSession().networkPolicy;
  const aHostname = input.config.aOrigin.hostname;
  const audience = proxyAudience(input.config.pOrigin, input.runId);
  const exactMatchers = exactConfiguredPolicy(activeSessionPolicy, aHostname, audience) &&
    exactConfiguredPolicy(independentSessionPolicy, aHostname, audience);
  const matcherless = matcherlessProjection(activeSessionPolicy, aHostname, audience) &&
    matcherlessProjection(independentSessionPolicy, aHostname, audience);
  const projectionMode: Sbx058ProjectionMode = exactMatchers ? "exact-matchers"
    : matcherless ? "matcherless"
      : (() => { throw new Error("SBX-058 session policy projection was unexpected"); })();
  if (!topProjection(input.sandbox.networkPolicy, aHostname) ||
      !topProjection(independent.networkPolicy, aHostname) ||
      JSON.stringify(input.configuredPolicy) !== JSON.stringify(sbx058Policy(
        aHostname, input.config.pOrigin, input.runId,
      ))) throw new Error("SBX-058 configured or sandbox policy projection was unexpected");
  return {
    stage: input.stage,
    startedAt,
    completedAt: new Date().toISOString(),
    expectedSessionId: input.expected.sessionId,
    activeSessionId: activeSession.sessionId,
    independentSessionId: independent.currentSession().sessionId,
    activeSandboxPolicy: input.sandbox.networkPolicy,
    activeSessionPolicy,
    independentSandboxPolicy: independent.networkPolicy,
    independentSessionPolicy,
    configuredPolicyComparedExactlyInMemory: true,
    projectionMode,
    identity: input.expected,
    containsControllerSecrets: false,
  };
}

function number(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function string(value: unknown, maximum = 4_096): string | undefined {
  return typeof value === "string" && value.length <= maximum ? value : undefined;
}

export function sanitizeSbx058Probe(
  value: unknown,
  commandExitCode: number,
  identity: Sbx058Identity,
): Sbx058ProbeEvidence {
  const root = object(value) ?? {};
  const trustNames = Array.isArray(root.inheritedPlatformTrustEnvironmentNames)
    ? root.inheritedPlatformTrustEnvironmentNames.filter((entry): entry is string => typeof entry === "string")
    : [];
  const output: Sbx058ProbeEvidence = {
    schemaVersion: number(root.schemaVersion) ?? -1,
    testId: string(root.testId, 64) ?? "missing",
    runId: string(root.runId, 128) ?? "missing",
    caseId: string(root.caseId, 64) ?? "missing",
    correlationCanary: string(root.correlationCanary, 128) ?? "missing",
    targetRole: string(root.targetRole, 8) ?? "missing",
    headerMode: string(root.headerMode, 32) ?? "missing",
    commandExitCode,
    startedAt: string(root.startedAt, 64) ?? "missing",
    completedAt: string(root.completedAt, 64) ?? "missing",
    ok: root.ok === true,
    phase: string(root.phase, 64) ?? "missing",
    requestHostname: string(root.requestHostname, 256) ?? "missing",
    requestServername: string(root.requestServername, 256) ?? "missing",
    requestHostHeader: string(root.requestHostHeader, 256) ?? "missing",
    requestPath: string(root.requestPath, 4_096) ?? "missing",
    routeHeaderSent: root.routeHeaderSent === true,
    decoyHeaderSent: root.decoyHeaderSent === true,
    connectionAttempts: number(root.connectionAttempts) ?? -1,
    actualConnections: number(root.actualConnections) ?? -1,
    actualRequests: number(root.actualRequests) ?? -1,
    retries: number(root.retries) ?? -1,
    redirectsFollowed: number(root.redirectsFollowed) ?? -1,
    rejectUnauthorized: root.rejectUnauthorized === true,
    controllerConfigurableCustomTrustAccepted: root.controllerConfigurableCustomTrustAccepted === true,
    inheritedPlatformTrustEnvironmentNames: trustNames,
    tcpConnected: root.tcpConnected === true,
    tlsEstablished: root.tlsEstablished === true,
    tlsAuthorized: root.tlsAuthorized === true,
    responseReceived: root.responseReceived === true,
    ...(number(root.responseStatusCode) !== undefined ? { responseStatusCode: number(root.responseStatusCode)! } : {}),
    responseShapeValid: root.responseShapeValid === true,
    ...(string(root.responseRole, 8) ? { responseRole: string(root.responseRole, 8)! } : {}),
    ...(typeof root.responseOidcVerified === "boolean" ? { responseOidcVerified: root.responseOidcVerified } : {}),
    ...(string(root.responseOperationId, 128) ? { responseOperationId: string(root.responseOperationId, 128)! } : {}),
    ...(string(root.responseReceipt, 128) ? { responseReceipt: string(root.responseReceipt, 128)! } : {}),
    responseBodyRetained: root.responseBodyRetained === true,
    timedOut: root.timedOut === true,
    durationMs: number(root.durationMs) ?? -1,
    ...(string(root.errorCode, 64) ? { errorCode: string(root.errorCode, 64)! } : {}),
    ...(string(root.errorSyscall, 64) ? { errorSyscall: string(root.errorSyscall, 64)! } : {}),
    ...(number(root.errorErrno) !== undefined ? { errorErrno: number(root.errorErrno)! } : {}),
    ...(root.errorClass === "dns-resolution" || root.errorClass === "connection-reset" ||
      root.errorClass === "route-unreachable" ? { errorClass: root.errorClass } : {}),
    controllerIdentity: identity,
  };
  return output;
}

function emptyProbe(
  runId: string,
  caseId: Sbx058CaseId,
  canary: string,
  identity: Sbx058Identity,
  config: Sbx058Config,
): Sbx058ProbeEvidence {
  const target = caseId.startsWith("direct-p-") ? config.pOrigin : config.aOrigin;
  return {
    schemaVersion: -1,
    testId: "missing",
    runId,
    caseId,
    correlationCanary: canary,
    targetRole: caseId.startsWith("direct-p-") ? "P" : "A",
    headerMode: headerModeForCase(caseId),
    commandExitCode: -1,
    startedAt: new Date(0).toISOString(),
    completedAt: new Date(0).toISOString(),
    ok: false,
    phase: "missing",
    requestHostname: target.hostname,
    requestServername: target.hostname,
    requestHostHeader: target.hostname,
    requestPath: requestPath(runId, caseId, canary),
    routeHeaderSent: false,
    decoyHeaderSent: false,
    connectionAttempts: 0,
    actualConnections: 0,
    actualRequests: 0,
    retries: 0,
    redirectsFollowed: 0,
    rejectUnauthorized: true,
    controllerConfigurableCustomTrustAccepted: false,
    inheritedPlatformTrustEnvironmentNames: [],
    tcpConnected: false,
    tlsEstablished: false,
    tlsAuthorized: false,
    responseReceived: false,
    responseShapeValid: false,
    responseBodyRetained: false,
    timedOut: false,
    durationMs: -1,
    controllerIdentity: identity,
  };
}

async function adminRequest(
  config: Sbx058Config,
  runId: string,
  method: "GET" | "PUT" | "DELETE",
  body?: unknown,
): Promise<Response> {
  return await fetch(new URL(`/v1/sbx058/admin/runs/${runId}`, config.adminOrigin), {
    method,
    headers: {
      authorization: `Bearer ${config.adminKey}`,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    redirect: "error",
    signal: signal(10_000),
  });
}

async function ledgerSnapshot(config: Sbx058Config, runId: string): Promise<Sbx058ReceiverSnapshot> {
  const response = await adminRequest(config, runId, "GET");
  if (response.status !== 200) throw new Error(`SBX-058 ledger read returned ${response.status}`);
  const value: unknown = await response.json();
  const root = object(value);
  if (!root || root.configured !== true || !Array.isArray(root.events) ||
      typeof root.snapshotAt !== "string" ||
      typeof root.unexpectedARequests !== "number" || typeof root.unexpectedPRequests !== "number" ||
      typeof root.unattributedRequests !== "number" || root.rawOidcTokenRetained !== false ||
      root.oidcTokenDigestRetained !== false) throw new Error("SBX-058 ledger snapshot was invalid");
  return value as Sbx058ReceiverSnapshot;
}

async function sandboxByName(config: Sbx058Config, name: string): Promise<Sandbox | undefined> {
  try {
    return await Sandbox.get({ ...credentials(config), name, resume: false, signal: signal() });
  } catch (error) {
    if (isNotFound(error)) return;
    throw error;
  }
}

export function sbx058PrefixListOptions(name: string): {
  namePrefix: string;
  limit: 10;
  sortBy: "name";
  sortOrder: "asc";
} {
  return { namePrefix: name, limit: 10, sortBy: "name", sortOrder: "asc" };
}

async function prefixAbsent(config: Sbx058Config, name: string): Promise<boolean> {
  const page = await Sandbox.list({
    ...credentials(config),
    ...sbx058PrefixListOptions(name),
    signal: signal(),
  });
  return (await page.toArray()).length === 0;
}

export async function cleanupSbx058Sandbox(input: {
  config: Sbx058Config;
  held: Sbx058HeldSafety;
  sandbox?: Sandbox | undefined;
  secrets: readonly string[];
}): Promise<CleanupResult> {
  const journal = input.held.journal;
  const evidence: Sbx058CleanupEvidence["sandbox"] = {
    exactProvenance: false,
    absenceOnlyValidated: journal.absenceOnlyValidated,
    stopAttempted: journal.stopAttempted,
    stopped: journal.stopped,
    deleteAttempted: journal.deleteAttempted,
    deleted: journal.deleted,
    absenceChecks: journal.absenceChecks,
    prefixAbsent: journal.prefixAbsent,
    errors: [],
  };
  if (journal.createAttemptedAt === undefined) {
    journal.zeroExternalStateConfirmed = true;
    await checkpointSbx058(input.held);
    return { evidence, safe: true };
  }
  if (journal.deleted && journal.absenceChecks >= 3 && journal.prefixAbsent) {
    return {
      evidence: {
        ...evidence,
        exactProvenance: journal.provenanceValidated,
        absenceOnlyValidated: journal.absenceOnlyValidated,
        stopped: journal.stopped || journal.deleted,
        deleted: true,
        absenceChecks: journal.absenceChecks,
        prefixAbsent: true,
      },
      safe: true,
    };
  }
  let sandbox = input.sandbox;
  try {
    sandbox ??= await sandboxByName(input.config, journal.name);
    if (!sandbox && journal.sessionId === undefined) {
      if (!sbx058UnknownCreateSettled(journal)) {
        evidence.errors.push("create-settlement-uncertain");
        return { evidence, safe: false };
      }
      for (let check = journal.absenceChecks + 1; check <= 3; check += 1) {
        if (check > 1) await delay(check === 2 ? 1_500 : 3_000);
        if (await sandboxByName(input.config, journal.name)) {
          evidence.errors.push("late-create-visible");
          return { evidence, safe: false };
        }
        journal.absenceChecks = check;
        await checkpointSbx058(input.held);
      }
      journal.prefixAbsent = await prefixAbsent(input.config, journal.name);
      if (!journal.prefixAbsent) {
        evidence.errors.push("late-create-prefix-visible");
        return { evidence, safe: false };
      }
      markSbx058AbsenceOnlyTerminal(journal);
      await checkpointSbx058(input.held);
      return {
        evidence: {
          ...evidence,
          absenceOnlyValidated: true,
          deleted: true,
          absenceChecks: 3,
          prefixAbsent: true,
        },
        safe: true,
      };
    }
    if (!sandbox && journal.sessionId !== undefined && journal.provenanceValidated) {
      for (let check = journal.absenceChecks + 1; check <= 3; check += 1) {
        if (check > 1) await delay(check === 2 ? 750 : 1_500);
        if (await sandboxByName(input.config, journal.name)) {
          evidence.errors.push("resource-reappeared-after-delete-attempt");
          return { evidence, safe: false };
        }
        journal.absenceChecks = check;
        await checkpointSbx058(input.held);
      }
      journal.prefixAbsent = await prefixAbsent(input.config, journal.name);
      if (!journal.prefixAbsent) {
        evidence.errors.push("resource-prefix-still-visible");
        return { evidence, safe: false };
      }
      markSbx058AbsenceOnlyTerminal(journal);
      await checkpointSbx058(input.held);
      return {
        evidence: {
          ...evidence,
          exactProvenance: true,
          absenceOnlyValidated: true,
          stopped: journal.stopped,
          deleted: true,
          absenceChecks: 3,
          prefixAbsent: true,
        },
        safe: true,
      };
    }
    if (!sandbox || !exactSbx058CreateProvenance(sandbox, journal)) {
      evidence.errors.push("cleanup-provenance-mismatch");
      return { evidence, safe: false };
    }
    const sessionId = sandbox.currentSession().sessionId;
    if (journal.sessionId && journal.sessionId !== sessionId) {
      evidence.errors.push("cleanup-session-mismatch");
      return { evidence, safe: false };
    }
    journal.sessionId ??= sessionId;
    journal.provenanceValidated = true;
    evidence.exactProvenance = true;
    await checkpointSbx058(input.held);
    try { await sandbox.updateNetworkPolicy("deny-all", { signal: signal() }); }
    catch (error) { evidence.errors.push(`deny-all: ${safeError(error, input.secrets)}`); }
    journal.stopAttempted = true;
    evidence.stopAttempted = true;
    await checkpointSbx058(input.held);
    try {
      await sandbox.stop({ signal: signal() });
      journal.stopped = true;
      evidence.stopped = true;
      await checkpointSbx058(input.held);
    } catch (error) {
      evidence.errors.push(`stop: ${safeError(error, input.secrets)}`);
    }
    journal.deleteAttempted = true;
    evidence.deleteAttempted = true;
    await checkpointSbx058(input.held);
    let deleteErrored = false;
    try { await sandbox.delete({ signal: signal() }); }
    catch (error) {
      deleteErrored = true;
      evidence.errors.push(`delete: ${safeError(error, input.secrets)}`);
    }
    for (let check = journal.absenceChecks + 1; check <= 3; check += 1) {
      if (check > 1) await delay(check === 2 ? 750 : 1_500);
      if (await sandboxByName(input.config, journal.name)) {
        evidence.errors.push("resource-still-visible");
        return { evidence, safe: false };
      }
      journal.absenceChecks = check;
      evidence.absenceChecks = check;
      await checkpointSbx058(input.held);
    }
    journal.prefixAbsent = await prefixAbsent(input.config, journal.name);
    evidence.prefixAbsent = journal.prefixAbsent;
    if (!journal.prefixAbsent) evidence.errors.push("resource-prefix-still-visible");
    if (deleteErrored && journal.stopped && sandbox.persistent === false &&
        journal.prefixAbsent && journal.absenceChecks >= 3) {
      markSbx058AbsenceOnlyTerminal(journal);
    } else {
      journal.deleted = journal.prefixAbsent && journal.absenceChecks >= 3;
    }
    evidence.absenceOnlyValidated = journal.absenceOnlyValidated;
    evidence.deleted = journal.deleted;
    await checkpointSbx058(input.held);
  } catch (error) {
    evidence.errors.push(safeError(error, input.secrets));
  }
  const errorsExact = evidence.errors.length === 0 ||
    (evidence.absenceOnlyValidated && evidence.errors.length === 1 &&
      evidence.errors[0]?.startsWith("delete: ") === true);
  return {
    evidence,
    safe: evidence.exactProvenance && evidence.stopAttempted && evidence.stopped && evidence.deleteAttempted &&
      evidence.deleted && evidence.absenceChecks >= 3 && evidence.prefixAbsent && errorsExact,
  };
}

async function cleanupReceiver(
  config: Sbx058Config,
  held: Sbx058HeldSafety,
  secrets: readonly string[],
): Promise<Sbx058CleanupEvidence["receiver"]> {
  const result: Sbx058CleanupEvidence["receiver"] = {
    deleteAttempted: held.journal.receiverConfigureAttempted,
    deleted: false,
    absenceChecks: 0,
    errors: [],
  };
  if (!held.journal.receiverConfigureAttempted) {
    held.journal.receiverDeleted = true;
    await checkpointSbx058(held);
    return { ...result, deleted: true };
  }
  try {
    const deleted = await adminRequest(config, held.runId, "DELETE");
    result.deleted = deleted.status === 204 || deleted.status === 404;
    if (!result.deleted) result.errors.push(`receiver delete returned ${deleted.status}`);
    for (let check = 1; check <= 2; check += 1) {
      const absent = await adminRequest(config, held.runId, "GET");
      if (absent.status !== 404) {
        result.errors.push(`receiver absence returned ${absent.status}`);
        break;
      }
      result.absenceChecks = check;
    }
    held.journal.receiverDeleted = result.deleted && result.absenceChecks >= 2 && result.errors.length === 0;
    await checkpointSbx058(held);
  } catch (error) {
    result.errors.push(safeError(error, secrets));
  }
  return result;
}

function expectedProofs(
  config: Sbx058Config,
  runId: string,
  canaries: Record<Sbx058CaseId, string>,
): Record<Sbx058EventCaseId, Partial<Record<Sbx058Role, Sbx058ExpectedEventProof>>> {
  const header = (caseId: Sbx058EventCaseId): {
    route: number; decoy: number; routeMatched: boolean; decoyMatched: boolean;
  } => ({
    route: caseId === "value-half" ? 0 : 1,
    decoy: caseId === "value-half" || caseId === "combined-halves" ? 1 : 0,
    routeMatched: caseId === "exact-pair",
    decoyMatched: caseId === "value-half" || caseId === "combined-halves",
  });
  const proof = (caseId: Sbx058EventCaseId, role: Sbx058Role): Sbx058ExpectedEventProof => {
    const facts = header(caseId);
    const operationId = expectedOperationId(
      config.actionKey, runId, caseId, canaries[caseId], role,
      facts.route, facts.decoy, facts.routeMatched, facts.decoyMatched, role === "P",
    );
    return {
      operationId,
      receipt: expectedReceipt(
        config.adminKey, runId, SBX058_EVENT_CASES.indexOf(caseId) + 1,
        caseId, canaries[caseId], role, operationId,
      ),
    };
  };
  return {
    "exact-pair": { P: proof("exact-pair", "P") },
    "key-half": { A: proof("key-half", "A") },
    "value-half": { A: proof("value-half", "A") },
    "combined-halves": { A: proof("combined-halves", "A"), P: proof("combined-halves", "P") },
  };
}

function guestConfiguration(
  config: Sbx058Config,
  runId: string,
  caseId: Sbx058CaseId,
  canary: string,
): Record<string, unknown> {
  const target = caseId.startsWith("direct-p-") ? config.pOrigin : config.aOrigin;
  return {
    scopeConfirmation: "researcher-controlled-sbx058-origins-only",
    testId: SBX058_TEST_ID,
    runId,
    caseId,
    correlationCanary: canary,
    headerMode: headerModeForCase(caseId),
    targetRole: caseId.startsWith("direct-p-") ? "P" : "A",
    targetOrigin: target.origin,
    requestPath: requestPath(runId, caseId, canary),
    timeoutMs: caseId.startsWith("direct-p-") ? 4_000 : 8_000,
  };
}

async function runGuestProbe(input: {
  sandbox: Sandbox;
  config: Sbx058Config;
  runId: string;
  caseId: Sbx058CaseId;
  canary: string;
  identity: Sbx058Identity;
  guestSource: string;
  secrets: readonly string[];
}): Promise<{ probe: Sbx058ProbeEvidence; command: CommandEvidence }> {
  const configuration = guestConfiguration(input.config, input.runId, input.caseId, input.canary);
  const serialized = JSON.stringify(configuration);
  if (input.secrets.some((secret) => serialized.includes(secret)) || serialized.includes("vercel-sandbox-oidc-token")) {
    throw new Error("SBX-058 guest configuration contained controller-only material");
  }
  const encoded = Buffer.from(serialized).toString("base64url");
  if (input.secrets.some((secret) => encoded.includes(secret))) throw new Error("SBX-058 guest argv contained a secret");
  const startedAt = new Date().toISOString();
  const command = await input.sandbox.runCommand({
    cmd: "node",
    args: [REMOTE_PROBE_PATH, encoded],
    timeoutMs: 20_000,
    signal: signal(),
  });
  const [stdout, stderr] = await Promise.all([
    command.stdout({ signal: signal() }),
    command.stderr({ signal: signal() }),
  ]);
  if (Buffer.byteLength(stdout) > 64_000 || Buffer.byteLength(stderr) > 16_000 ||
      input.secrets.some((secret) => stdout.includes(secret) || stderr.includes(secret))) {
    throw new Error(`${input.caseId} guest output violated retention bounds`);
  }
  let parsed: unknown;
  try { parsed = JSON.parse(stdout); }
  catch { throw new Error(`${input.caseId} guest output was not JSON`); }
  return {
    probe: sanitizeSbx058Probe(parsed, command.exitCode, input.identity),
    command: {
      caseId: input.caseId,
      commandId: command.cmdId,
      exitCode: command.exitCode,
      startedAt,
      completedAt: new Date().toISOString(),
      configurationBytes: Buffer.byteLength(serialized),
      stdoutBytes: Buffer.byteLength(stdout),
      stderrBytes: Buffer.byteLength(stderr),
      rawOutputRetained: false,
      standaloneOutputDigestRetained: false,
    },
  };
}

async function scanGuestEnvironment(sandbox: Sandbox, secrets: readonly string[]): Promise<void> {
  const command = await sandbox.runCommand({
    cmd: "node",
    args: ["-e", "process.stdout.write(JSON.stringify(Object.values(process.env)))"],
    timeoutMs: 10_000,
    signal: signal(),
  });
  const [stdout, stderr] = await Promise.all([
    command.stdout({ signal: signal() }),
    command.stderr({ signal: signal() }),
  ]);
  if (command.exitCode !== 0 || Buffer.byteLength(stdout) > 64_000 || Buffer.byteLength(stderr) > 8_192 ||
      secrets.some((secret) => stdout.includes(secret) || stderr.includes(secret))) {
    throw new Error("SBX-058 guest environment scan was incomplete or found controller-only material");
  }
  let values: unknown;
  try { values = JSON.parse(stdout); }
  catch { throw new Error("SBX-058 guest environment scan was not bounded JSON"); }
  if (!Array.isArray(values) || values.some((value) => typeof value !== "string" || value.length > 16_384)) {
    throw new Error("SBX-058 guest environment scan shape was invalid");
  }
  values = undefined;
}

function missingIdentity(runId: string): Sbx058Identity {
  return {
    aliasEmail: SBX058_ALIAS,
    aliasIdentityVerified: false,
    teamId: SBX058_TEAM,
    projectId: SBX058_PROJECT,
    sandboxName: `sbx-058-${runId}`,
    sessionId: "missing",
  };
}

function missingPolicy(stage: "before" | "after", identity: Sbx058Identity): Sbx058PolicyProof {
  return {
    stage,
    startedAt: new Date(0).toISOString(),
    completedAt: new Date(0).toISOString(),
    expectedSessionId: identity.sessionId,
    activeSessionId: "missing",
    independentSessionId: "missing",
    activeSandboxPolicy: null,
    activeSessionPolicy: null,
    independentSandboxPolicy: null,
    independentSessionPolicy: null,
    configuredPolicyComparedExactlyInMemory: true,
    projectionMode: "matcherless",
    identity,
    containsControllerSecrets: false,
  };
}

async function runRecovery(config: Sbx058Config, runId: string): Promise<void> {
  const attemptId = randomUUID();
  const artifactPath = sbx058RecoveryArtifactPath(runId, attemptId);
  let held: Sbx058HeldSafety | undefined;
  let result: Record<string, unknown>;
  try {
    held = await acquireSbx058Safety("cleanup-only", runId);
    const secrets = [config.token, config.adminKey, config.actionKey];
    if (held.journal.completed) {
      const local = await finalizeSbx058Safety(held);
      result = {
        schemaVersion: 1,
        testId: SBX058_TEST_ID,
        recoveryOnly: true,
        runId,
        attemptId,
        outcome: "cleanup-complete",
        completedJournalFinalized: true,
        local,
        experimentVerdictEmitted: false,
      };
      await writeSbx058NoClobber(artifactPath, result);
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      process.exitCode = 0;
      return;
    }
    const sandboxCleanup = await cleanupSbx058Sandbox({ config, held, secrets });
    const receiverCleanup = await cleanupReceiver(config, held, secrets);
    const safe = sandboxCleanup.safe && receiverCleanup.deleted && receiverCleanup.errors.length === 0;
    if (safe) {
      held.journal.completed = true;
      await checkpointSbx058(held);
      const local = await finalizeSbx058Safety(held);
      result = {
        schemaVersion: 1,
        testId: SBX058_TEST_ID,
        recoveryOnly: true,
        runId,
        attemptId,
        outcome: "cleanup-complete",
        sandboxCleanup: sandboxCleanup.evidence,
        receiverCleanup,
        local,
        experimentVerdictEmitted: false,
      };
    } else {
      result = {
        schemaVersion: 1,
        testId: SBX058_TEST_ID,
        recoveryOnly: true,
        runId,
        attemptId,
        outcome: "cleanup-indeterminate",
        sandboxCleanup: sandboxCleanup.evidence,
        receiverCleanup,
        journalRetained: true,
        liveLockRetainedForRecovery: true,
        experimentVerdictEmitted: false,
      };
    }
  } catch (error) {
    result = {
      schemaVersion: 1,
      testId: SBX058_TEST_ID,
      recoveryOnly: true,
      runId,
      attemptId,
      outcome: "cleanup-error",
      error: safeError(error, [config.token, config.adminKey, config.actionKey]),
      experimentVerdictEmitted: false,
    };
  }
  const serialized = JSON.stringify(result);
  if ([config.token, config.adminKey, config.actionKey].some((secret) => serialized.includes(secret))) {
    throw new Error("SBX-058 recovery artifact contained a secret");
  }
  await writeSbx058NoClobber(artifactPath, result);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode = result.outcome === "cleanup-complete" ? 0 : 2;
}

async function main(): Promise<void> {
  const config = loadSbx058Config();
  if (config.recoveryRunId) return await runRecovery(config, config.recoveryRunId);
  const held = await acquireSbx058Safety("normal");
  const runId = held.runId;
  const startedAt = new Date().toISOString();
  const artifactPath = sbx058ArtifactPath(runId);
  const canaries = Object.fromEntries(SBX058_CASES.map((caseId) => [
    caseId,
    `s58_${caseId}_${randomBytes(16).toString("base64url")}`,
  ])) as Record<Sbx058CaseId, string>;
  const proofs = expectedProofs(config, runId, canaries);
  const secrets = [config.token, config.adminKey, config.actionKey];
  const policy = sbx058Policy(config.aOrigin.hostname, config.pOrigin, runId);
  const guestSource = await readFile(GUEST_SOURCE, "utf8");
  if (secrets.some((secret) => guestSource.includes(secret))) throw new Error("guest source contained a secret");
  let sandbox: Sandbox | undefined;
  let identity = missingIdentity(runId);
  let observedIdentity = missingIdentity(runId);
  let identityMethod: string | undefined;
  let policyBefore = missingPolicy("before", identity);
  let policyAfter = missingPolicy("after", identity);
  let ledger: Sbx058ReceiverSnapshot = {
    configured: true,
    configuredAt: new Date(0).toISOString(),
    snapshotAt: new Date(0).toISOString(),
    events: [],
    unexpectedARequests: 0,
    unexpectedPRequests: 0,
    unattributedRequests: 0,
    rawOidcTokenRetained: false,
    oidcTokenDigestRetained: false,
    receiverRuntimeTrustExact: true,
    receiverRuntimeTrustEnvironmentNames: [],
    receiverNodeOptionsPresent: false,
    receiverTlsVerificationDisabled: false,
  };
  const probes = Object.fromEntries(SBX058_CASES.map((caseId) => [
    caseId,
    emptyProbe(runId, caseId, canaries[caseId], identity, config),
  ])) as Record<Sbx058CaseId, Sbx058ProbeEvidence>;
  const commands: CommandEvidence[] = [];
  let controllerError: string | undefined;
  let sandboxCleanup: Sbx058CleanupEvidence["sandbox"] = {
    exactProvenance: false,
    absenceOnlyValidated: false,
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    absenceChecks: 0,
    prefixAbsent: false,
    errors: [],
  };
  let receiverCleanup: Sbx058CleanupEvidence["receiver"] = {
    deleteAttempted: false,
    deleted: false,
    absenceChecks: 0,
    errors: [],
  };
  let cleanupStartedAt = new Date(0).toISOString();
  let sandboxCompletedAt = new Date(0).toISOString();
  let cleanupCompletedAt = new Date(0).toISOString();
  let journalRemoved = false;
  let liveLockRemoved = false;
  let guestEnvironmentScanned = false;

  try {
    const verified = await verifyEligibleAliasToken({
      token: config.token,
      expectedEmail: config.aliasEmail,
      expectedTeamId: config.teamId,
      expectedProjectId: config.projectId,
      manualEmailConfirmation: process.env.SBX058_ALIAS_EMAIL_CONFIRMATION,
    });
    identityMethod = verified.method;
    held.journal.createAttemptedAt = new Date().toISOString();
    await checkpointSbx058(held);
    sandbox = await Sandbox.create({
      name: held.journal.name,
      persistent: false,
      timeout: SBX058_SANDBOX_TIMEOUT_MS,
      resources: { vcpus: 2 },
      ports: [],
      networkPolicy: policy,
      tags: held.journal.tags,
      ...credentials(config),
      signal: signal(SBX058_CREATE_TIMEOUT_MS),
    });
    if (!exactSbx058CreateProvenance(sandbox, held.journal)) {
      throw new Error("SBX-058 create response provenance was invalid");
    }
    held.journal.createSettledAt = new Date().toISOString();
    held.journal.sessionId = sandbox.currentSession().sessionId;
    held.journal.provenanceValidated = true;
    await checkpointSbx058(held);
    identity = expectedIdentity(config, sandbox);
    observedIdentity = { ...identity };
    for (const caseId of SBX058_CASES) probes[caseId].controllerIdentity = identity;
    held.journal.receiverConfigureAttempted = true;
    await checkpointSbx058(held);
    const configured = await adminRequest(config, runId, "PUT", {
      runId,
      aHostname: config.aOrigin.hostname,
      forwardAudience: proxyAudience(config.pOrigin, runId),
      expectedTeamId: config.teamId,
      expectedProjectId: config.projectId,
      expectedSessionId: identity.sessionId,
      expectedSandboxName: identity.sandboxName,
      cases: SBX058_EVENT_CASES.map((caseId) => ({
        caseId,
        canary: canaries[caseId],
        requestPath: requestPath(runId, caseId, canaries[caseId]),
      })),
    });
    if (configured.status !== 201) throw new Error(`SBX-058 receiver configuration returned ${configured.status}`);
    held.journal.receiverConfigured = true;
    await checkpointSbx058(held);
    ledger = await ledgerSnapshot(config, runId);
    if (ledger.events.length !== 0 || !ledger.emptyReadAt) throw new Error("SBX-058 receiver did not start empty");
    policyBefore = await captureSbx058PolicyProof({ stage: "before", runId, sandbox, config, expected: identity, configuredPolicy: policy });
    await sandbox.writeFiles([{ path: REMOTE_PROBE_PATH, content: guestSource, mode: 0o700 }], { signal: signal() });
    await scanGuestEnvironment(sandbox, secrets);
    guestEnvironmentScanned = true;

    let expectedEvents = 0;
    for (const caseId of SBX058_CASES) {
      const result = await runGuestProbe({
        sandbox,
        config,
        runId,
        caseId,
        canary: canaries[caseId],
        identity,
        guestSource,
        secrets,
      });
      probes[caseId] = result.probe;
      commands.push(result.command);
      if (SBX058_EVENT_CASES.includes(caseId as Sbx058EventCaseId)) expectedEvents += 1;
      await delay(INTER_PROBE_MS);
      ledger = await ledgerSnapshot(config, runId);
      if (ledger.events.length !== expectedEvents) throw new Error(`${caseId} produced unexpected receiver accounting`);
      if (caseId === "direct-p-pre" || caseId === "direct-p-post") {
        if (result.probe.ok || result.probe.responseReceived) throw new Error(`${caseId} direct-P barrier failed`);
      } else if (caseId === "exact-pair") {
        if (!result.probe.ok || result.probe.responseRole !== "P" || result.probe.responseOidcVerified !== true) {
          throw new Error("exact-pair positive control failed");
        }
      } else if (caseId === "key-half" || caseId === "value-half") {
        if (!result.probe.ok || result.probe.responseRole !== "A" || result.probe.responseOidcVerified !== false) {
          throw new Error(`${caseId} isolated-half control failed`);
        }
      }
      await delay(INTER_PROBE_MS);
    }
    policyAfter = await captureSbx058PolicyProof({ stage: "after", runId, sandbox, config, expected: identity, configuredPolicy: policy });
    ledger = await ledgerSnapshot(config, runId);
  } catch (error) {
    controllerError = safeError(error, secrets);
  } finally {
    cleanupStartedAt = new Date().toISOString();
    const sandboxResult = await cleanupSbx058Sandbox({ config, held, sandbox, secrets });
    sandboxCleanup = sandboxResult.evidence;
    sandboxCompletedAt = new Date().toISOString();
    if (sandboxResult.safe && held.journal.receiverConfigured) {
      try {
        ledger = await ledgerSnapshot(config, runId);
      } catch (error) {
        controllerError ??= `final receiver snapshot: ${safeError(error, secrets)}`;
      }
    }
    receiverCleanup = await cleanupReceiver(config, held, secrets);
    cleanupCompletedAt = new Date().toISOString();
    const cleanupSafe = sandboxResult.safe && receiverCleanup.deleted && receiverCleanup.absenceChecks >= 2 &&
      receiverCleanup.errors.length === 0;
    if (cleanupSafe) {
      held.journal.completed = true;
      await checkpointSbx058(held);
      const local = await finalizeSbx058Safety(held);
      journalRemoved = local.journalRemoved;
      liveLockRemoved = local.liveLockRemoved;
    } else {
      controllerError ??= "strict cleanup remained uncertain; journal and live lock were retained";
    }
  }

  const cleanup: Sbx058CleanupEvidence = {
    startedAt: cleanupStartedAt,
    sandboxCompletedAt,
    completedAt: cleanupCompletedAt,
    sandbox: sandboxCleanup,
    receiver: receiverCleanup,
    journalCompleted: held.journal.completed,
    journalRemoved,
    liveLockRemoved,
  };
  const retention: Sbx058RetentionEvidence = {
    guestSourceScanned: true,
    guestConfigurationScanned: true,
    guestArgvScanned: true,
    guestEnvironmentScanned,
    guestStagedFilesScanned: true,
    guestStdoutScanned: true,
    guestResultsScanned: true,
    controllerArtifactScanned: true,
    adminKeyAbsent: true,
    actionKeyAbsent: true,
    vercelTokenAbsent: true,
    rawOidcTokenRetained: false,
    oidcTokenDigestRetained: false,
    rawGuestOutputRetained: false,
    standaloneGuestOutputDigestRetained: false,
    artifactMode: 0o600,
    journalMode: held.journalMode,
    lockMode: held.lockMode,
  };
  const assessmentInput: Sbx058AssessmentInput = {
    ...(controllerError ? { controllerError } : {}),
    runId,
    aOrigin: config.aOrigin.origin,
    pOrigin: config.pOrigin.origin,
    canaries,
    expectedIdentity: identity,
    observedIdentity,
    expectedEvents: proofs,
    policyBefore,
    policyAfter,
    probes,
    ledger,
    cleanup,
    retention,
  };
  const assessment = assessSbx058(assessmentInput);
  const evidence = {
    schemaVersion: 1,
    testId: SBX058_TEST_ID,
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    identity: { ...observedIdentity, verificationMethod: identityMethod ?? "missing" },
    origins: { A: config.aOrigin.origin, P: config.pOrigin.origin },
    policy: {
      matcher: { headerName: SBX058_MATCH_HEADER, exactValue: SBX058_MATCH_VALUE },
      decoyHeaderName: SBX058_DECOY_HEADER,
      forwardAudience: proxyAudience(config.pOrigin, runId),
    },
    canaries,
    expectedEvents: proofs,
    policyProofs: { before: policyBefore, after: policyAfter },
    probes,
    commands,
    receiverLedger: ledger,
    cleanup,
    retention,
    assessment,
    recoveryOnly: false,
    evidencePath: artifactPath,
  };
  const serialized = `${JSON.stringify(evidence, null, 2)}\n`;
  if (secrets.some((secret) => serialized.includes(secret))) {
    throw new Error("SBX-058 evidence contained controller-only material");
  }
  await writeSbx058NoClobber(artifactPath, evidence);
  process.stdout.write(serialized);
  process.exitCode = assessment.outcome === "candidate-high" || assessment.outcome === "pass" ? 0 : 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}

export { main as runSbx058 };
