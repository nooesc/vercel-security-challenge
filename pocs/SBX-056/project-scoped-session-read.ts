import "dotenv/config";

import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { APIError, Sandbox } from "@vercel/sandbox";
import {
  acquireSbx056Safety,
  acquireSbx056RecoverySafety,
  closeSbx056RetainingState,
  createSbx056Journal,
  finalizeSbx056Safety,
  persistSbx056Journal,
  sbx056FixedPath,
  sbx056RecoveryArtifactPath,
  sbx056UnknownCreateSettled,
  type Sbx056HeldSafety,
  type Sbx056Journal,
  type Sbx056Role,
  type Sbx056TargetJournal,
  SBX056_CREATE_TIMEOUT_MS,
  SBX056_SANDBOX_TIMEOUT_MS,
  SBX056_UUID,
} from "./safety.js";
import {
  assessSbx056,
  assertSbx056EvidenceExcludesRawValues,
  type Sbx056AssessmentInput,
  type Sbx056Attempt,
  type Sbx056AuthorityProof,
  type Sbx056CleanupProof,
  type Sbx056ProvenanceProof,
  SBX056_TEST_ID,
} from "./verdict.js";

export const SBX056_SCOPE_CONFIRMATION =
  "I_RECHECKED_SBX056_SCOPE_AND_OWN_BOTH_PROJECTS_AND_THE_PROJECT_SCOPED_TOKEN" as const;
export const SBX056_ALIAS = "swve@wearehackerone.com" as const;
const API = "https://api.vercel.com";
const SDK_API = "https://vercel.com";
const CONTROL_TIMEOUT_MS = 30_000;
const MAX_RESPONSE_BYTES = 4_096;
const MIN_REQUEST_INTERVAL_MS = 300;
const PROJECT = /^prj_[A-Za-z0-9]{8,128}$/u;
const TEAM = /^team_[A-Za-z0-9]{8,128}$/u;
const SESSION = /^sbx_[A-Za-z0-9_-]{20,192}$/u;

export interface Sbx056Config {
  ownerToken: string;
  scopedToken?: string;
  teamId: string;
  controlProjectId: string;
  victimProjectId: string;
  expectedAlias: typeof SBX056_ALIAS;
  recoveryRunId?: string;
}

export interface Sbx056RequestRecord {
  ordinal: number;
  startedAt: string;
  method: string;
  pathname: string;
  actor: "owner" | "project-scoped";
}

export class Sbx056RequestGate {
  readonly records: Sbx056RequestRecord[] = [];
  #lastStart = 0;
  #queue: Promise<void> = Promise.resolve();
  constructor(
    private readonly ownerToken: string,
    private readonly scopedToken: string | undefined,
    private readonly teamId: string,
    private readonly fetcher: typeof fetch = fetch,
    private readonly minimumIntervalMs: number = MIN_REQUEST_INTERVAL_MS,
  ) {
    if (!Number.isInteger(minimumIntervalMs) || minimumIntervalMs < 0 ||
        minimumIntervalMs > MIN_REQUEST_INTERVAL_MS) {
      throw new Error("SBX-056 request interval override was invalid");
    }
  }

  readonly fetch: typeof fetch = async (input, init) => {
    let release!: () => void;
    const prior = this.#queue;
    this.#queue = new Promise<void>((resolve) => { release = resolve; });
    await prior;
    try {
      const url = new URL(input instanceof Request ? input.url : input.toString());
      const rawApi = url.origin === API && /^\/v(?:2|9)\//u.test(url.pathname);
      const sdkApi = url.origin === SDK_API && url.pathname.startsWith("/api/");
      if (!rawApi && !sdkApi) {
        throw new Error(`SBX-056 refused a non-Vercel API origin (${url.origin})`);
      }
      const headers = new Headers(input instanceof Request ? input.headers : init?.headers);
      const authorization = headers.get("authorization");
      const owner = authorization === `Bearer ${this.ownerToken}`;
      const scoped = this.scopedToken !== undefined && authorization === `Bearer ${this.scopedToken}`;
      if (!owner && !scoped) throw new Error("SBX-056 refused an unrecognized bearer token");
      const queryTeam = url.searchParams.get("teamId");
      if (queryTeam !== null && queryTeam !== this.teamId) {
        throw new Error("SBX-056 refused a different team query");
      }
      const wait = this.#lastStart + this.minimumIntervalMs - Date.now();
      if (wait > 0) await delay(wait);
      this.#lastStart = Date.now();
      this.records.push({
        ordinal: this.records.length + 1,
        startedAt: new Date(this.#lastStart).toISOString(),
        method: (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase(),
        pathname: url.pathname,
        actor: owner ? "owner" : "project-scoped",
      });
      return await this.fetcher(input, init);
    } finally { release(); }
  };
}

function required(environment: Readonly<Record<string, string | undefined>>, name: string): string {
  const value = environment[name];
  if (value === undefined || value.trim() !== value || value.length < 1) {
    throw new Error(`${name} must be one explicit nonempty value`);
  }
  return value;
}

function boundedToken(value: string, name: string): string {
  if (value.length < 20 || value.length > 4_096 || /[\s\0\u007f]/u.test(value)) {
    throw new Error(`${name} was not one bounded opaque token`);
  }
  return value;
}

export function loadSbx056Config(
  environment: Readonly<Record<string, string | undefined>> = process.env,
): Sbx056Config {
  if (required(environment, "SBX056_SCOPE_CONFIRMATION") !== SBX056_SCOPE_CONFIRMATION) {
    throw new Error("SBX056_SCOPE_CONFIRMATION did not exactly match the bounded scope statement");
  }
  const expectedAlias = required(environment, "SBX056_EXPECTED_ALIAS");
  const aliasConfirmation = required(environment, "SBX056_ALIAS_EMAIL_CONFIRMATION");
  if (expectedAlias !== SBX056_ALIAS || aliasConfirmation !== SBX056_ALIAS) {
    throw new Error("SBX-056 requires the exact eligible HackerOne alias confirmation");
  }
  const teamId = required(environment, "VERCEL_TEAM_ID");
  const controlProjectId = required(environment, "SBX056_CONTROL_PROJECT_ID");
  const victimProjectId = required(environment, "SBX056_VICTIM_PROJECT_ID");
  if (!TEAM.test(teamId) || !PROJECT.test(controlProjectId) || !PROJECT.test(victimProjectId) ||
      controlProjectId === victimProjectId) throw new Error("SBX-056 team/project identifiers were invalid");
  const ownerToken = boundedToken(required(environment, "SBX056_OWNER_TOKEN"), "SBX056_OWNER_TOKEN");
  const recoveryRunId = environment.SBX056_RECOVERY_RUN_ID;
  if (recoveryRunId !== undefined && !SBX056_UUID.test(recoveryRunId)) {
    throw new Error("SBX056_RECOVERY_RUN_ID must be one canonical UUIDv4");
  }
  if (recoveryRunId !== undefined) {
    return { ownerToken, teamId, controlProjectId, victimProjectId,
      expectedAlias: SBX056_ALIAS, recoveryRunId };
  }
  const scopedToken = boundedToken(required(environment, "SBX056_PROJECT_SCOPED_TOKEN"),
    "SBX056_PROJECT_SCOPED_TOKEN");
  if (scopedToken === ownerToken) throw new Error("SBX-056 owner and project-scoped tokens must differ");
  return { ownerToken, scopedToken, teamId, controlProjectId, victimProjectId,
    expectedAlias: SBX056_ALIAS };
}

async function boundedBody(response: Response): Promise<Buffer> {
  if (response.body === null) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      total += chunk.value.length;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error("SBX-056 response exceeded its fixed byte ceiling");
      }
      chunks.push(chunk.value);
    }
    return Buffer.concat(chunks, total);
  } finally { reader.releaseLock(); }
}

function exactIdBody(body: Buffer, key: "id" | "email", expected: string): boolean {
  try {
    const parsed = JSON.parse(body.toString("utf8")) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return false;
    const record = parsed as Record<string, unknown>;
    if (record[key] === expected) return true;
    const user = record.user;
    return user !== null && typeof user === "object" && !Array.isArray(user) &&
      (user as Record<string, unknown>)[key] === expected;
  } catch { return false; }
}

async function exactIdentityRead(
  gate: Sbx056RequestGate,
  token: string,
  path: string,
  key: "id" | "email",
  expected: string,
): Promise<boolean> {
  const response = await gate.fetch(`${API}${path}`, {
    headers: { authorization: `Bearer ${token}`, accept: "application/json" },
    redirect: "error",
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  });
  const body = await boundedBody(response);
  try {
    return response.status === 200 &&
      (response.headers.get("content-type") ?? "").toLowerCase().startsWith("application/json") &&
      exactIdBody(body, key, expected);
  } finally { body.fill(0); }
}

async function boundedAuthorizationDenial(response: Response): Promise<boolean> {
  if (response.status !== 403 && response.status !== 404) return false;
  if (!(response.headers.get("content-type") ?? "").toLowerCase().startsWith("application/json")) {
    return false;
  }
  const body = await boundedBody(response);
  try {
    if (body.length < 2) return false;
    const value = JSON.parse(body.toString("utf8")) as unknown;
    return value !== null && typeof value === "object" && !Array.isArray(value);
  } catch { return false; } finally { body.fill(0); }
}

export async function verifySbx056Authority(
  config: Sbx056Config & { scopedToken: string },
  gate: Sbx056RequestGate,
): Promise<Sbx056AuthorityProof> {
  const ownerAliasExact = await exactIdentityRead(gate, config.ownerToken, "/v2/user", "email",
    config.expectedAlias);
  const ownerTeamExact = await exactIdentityRead(gate, config.ownerToken,
    `/v2/teams/${config.teamId}`, "id", config.teamId);
  const ownerControlProjectExact = await exactIdentityRead(gate, config.ownerToken,
    `/v9/projects/${config.controlProjectId}?teamId=${config.teamId}`, "id", config.controlProjectId);
  const ownerVictimProjectExact = await exactIdentityRead(gate, config.ownerToken,
    `/v9/projects/${config.victimProjectId}?teamId=${config.teamId}`, "id", config.victimProjectId);
  const scopedControlProjectExact = await exactIdentityRead(gate, config.scopedToken,
    `/v9/projects/${config.controlProjectId}?teamId=${config.teamId}`, "id", config.controlProjectId);
  const denied = await gate.fetch(
    `${API}/v9/projects/${config.victimProjectId}?teamId=${config.teamId}`,
    { headers: { authorization: `Bearer ${config.scopedToken}`, accept: "application/json" },
      redirect: "error", signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) },
  );
  const scopedVictimProjectDenied = await boundedAuthorizationDenial(denied);
  return {
    ownerAliasExact,
    ownerTeamExact,
    ownerControlProjectExact,
    ownerVictimProjectExact,
    scopedControlProjectExact,
    scopedVictimProjectDenied,
    scopedVictimProjectStatus: scopedVictimProjectDenied &&
        (denied.status === 403 || denied.status === 404) ? denied.status : null,
    scopedTokenProjectRestrictionManuallyConfirmed: true,
    ownerAndScopedTokensDistinct: config.ownerToken !== config.scopedToken,
  };
}

function ownerCredentials(config: Sbx056Config, projectId: string, gate: Sbx056RequestGate) {
  return { token: config.ownerToken, teamId: config.teamId, projectId, fetch: gate.fetch };
}

export function sbx056CreateParameters(
  config: Sbx056Config,
  target: Sbx056TargetJournal,
  gate: Sbx056RequestGate,
) {
  return {
    ...ownerCredentials(config, target.projectId, gate),
    name: target.name,
    tags: target.tags,
    persistent: false as const,
    timeout: SBX056_SANDBOX_TIMEOUT_MS,
    ports: [] as number[],
    networkPolicy: "deny-all" as const,
    signal: AbortSignal.timeout(SBX056_CREATE_TIMEOUT_MS),
  };
}

function exactTags(actual: Record<string, string> | undefined, expected: Record<string, string>): boolean {
  if (actual === undefined) return false;
  const keys = Object.keys(expected);
  return Object.keys(actual).length === keys.length && keys.every((key) => actual[key] === expected[key]);
}

export function exactSbx056Handle(sandbox: Sandbox, target: Sbx056TargetJournal): boolean {
  let sessionId: string;
  try { sessionId = sandbox.currentSession().sessionId; } catch { return false; }
  return sandbox.name === target.name && sandbox.persistent === false &&
    exactTags(sandbox.tags, target.tags) && SESSION.test(sessionId) &&
    sandbox.currentSession().sessionId === sessionId && sandbox.networkPolicy === "deny-all" &&
    sandbox.currentSession().networkPolicy === "deny-all" && sandbox.routes.length === 0;
}

async function createExactSandbox(input: {
  config: Sbx056Config;
  gate: Sbx056RequestGate;
  held: Sbx056HeldSafety;
  journal: Sbx056Journal;
  target: Sbx056TargetJournal;
}): Promise<Sandbox> {
  input.target.createAttemptedAt = new Date().toISOString();
  await persistSbx056Journal(input.held, input.journal);
  let sandbox: Sandbox;
  try {
    sandbox = await Sandbox.create(sbx056CreateParameters(input.config, input.target, input.gate));
  } finally {
    input.target.createSettledAt = new Date().toISOString();
    await persistSbx056Journal(input.held, input.journal);
  }
  if (!exactSbx056Handle(sandbox, input.target)) throw new Error("SBX-056 create handle failed provenance");
  const independent = await Sandbox.get({
    ...ownerCredentials(input.config, input.target.projectId, input.gate),
    name: input.target.name,
    resume: false,
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  });
  if (!exactSbx056Handle(independent, input.target) ||
      independent.currentSession().sessionId !== sandbox.currentSession().sessionId) {
    throw new Error("SBX-056 independent readback failed provenance");
  }
  input.target.sessionId = sandbox.currentSession().sessionId;
  input.target.provenanceValidated = true;
  await persistSbx056Journal(input.held, input.journal);
  return sandbox;
}

function contentType(response: Response): Sbx056Attempt["contentType"] {
  const value = (response.headers.get("content-type") ?? "").split(";", 1)[0]?.trim().toLowerCase();
  if (!value) return null;
  if (value === "application/octet-stream") return value;
  if (value === "application/json") return value;
  return "other";
}

function exactBytes(left: Buffer, right: Buffer): boolean {
  return left.length === right.length && left.length > 0 && timingSafeEqual(left, right);
}

function authErrorBody(body: Buffer): boolean {
  if (body.length < 2) return false;
  try {
    const value = JSON.parse(body.toString("utf8")) as unknown;
    return value !== null && typeof value === "object" && !Array.isArray(value);
  } catch { return false; }
}

export async function oneSbx056Read(input: {
  gate: Sbx056RequestGate;
  token: string;
  teamId: string;
  sessionId: string;
  path: string;
  expected: Buffer;
  phase: Sbx056Attempt["phase"];
  actor: Sbx056Attempt["actor"];
  target: Sbx056Attempt["target"];
}): Promise<Sbx056Attempt> {
  if (!SESSION.test(input.sessionId) || !input.path.startsWith("/vercel/sandbox/.sbx-056-")) {
    throw new Error("SBX-056 refused a noncanonical direct read target");
  }
  const startedAt = new Date().toISOString();
  const url = new URL(
    `${SDK_API}/api/v2/sandboxes/sessions/${encodeURIComponent(input.sessionId)}/fs/read`,
  );
  url.searchParams.set("teamId", input.teamId);
  try {
    const response = await input.gate.fetch(url, {
      method: "POST",
      headers: {
        authorization: `Bearer ${input.token}`,
        accept: "application/octet-stream",
        "content-type": "application/json",
      },
      body: JSON.stringify({ path: input.path }),
      redirect: "error",
      signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
    });
    const body = await boundedBody(response);
    try {
      return {
        phase: input.phase,
        actor: input.actor,
        target: input.target,
        startedAt,
        completedAt: new Date().toISOString(),
        method: "POST",
        routeShapeExact: true,
        teamQueryExact: true,
        projectIdentifierSent: false,
        redirectMode: "error",
        transportCalls: 1,
        status: response.status,
        contentType: contentType(response),
        responseBytes: body.length,
        exactExpectedMarker: response.status === 200 &&
          contentType(response) === "application/octet-stream" && exactBytes(body, input.expected),
        boundedAuthError: (response.status === 403 || response.status === 404) && authErrorBody(body),
        transportError: false,
      };
    } finally { body.fill(0); }
  } catch {
    return {
      phase: input.phase,
      actor: input.actor,
      target: input.target,
      startedAt,
      completedAt: new Date().toISOString(),
      method: "POST",
      routeShapeExact: true,
      teamQueryExact: true,
      projectIdentifierSent: false,
      redirectMode: "error",
      transportCalls: 1,
      status: null,
      contentType: null,
      responseBytes: 0,
      exactExpectedMarker: false,
      boundedAuthError: false,
      transportError: true,
    };
  }
}

export function sbx056CrossDispatchGate(input: {
  authority: Sbx056AuthorityProof;
  control: Sbx056Attempt;
  victimOwner: Sbx056Attempt;
  controlTarget: Sbx056TargetJournal;
  victimTarget: Sbx056TargetJournal;
}): boolean {
  const exactSuccessfulRead = (attempt: Sbx056Attempt): boolean =>
    attempt.method === "POST" && attempt.routeShapeExact && attempt.teamQueryExact &&
    attempt.projectIdentifierSent === false && attempt.redirectMode === "error" &&
    attempt.transportCalls === 1 && attempt.status === 200 &&
    attempt.contentType === "application/octet-stream" && attempt.responseBytes > 0 &&
    attempt.responseBytes <= MAX_RESPONSE_BYTES && attempt.exactExpectedMarker &&
    !attempt.boundedAuthError && !attempt.transportError;
  const authority = input.authority.ownerAliasExact && input.authority.ownerTeamExact &&
    input.authority.ownerControlProjectExact && input.authority.ownerVictimProjectExact &&
    input.authority.scopedControlProjectExact && input.authority.scopedVictimProjectDenied &&
    (input.authority.scopedVictimProjectStatus === 403 ||
      input.authority.scopedVictimProjectStatus === 404) &&
    input.authority.scopedTokenProjectRestrictionManuallyConfirmed &&
    input.authority.ownerAndScopedTokensDistinct;
  return authority && input.control.phase === "public-control" &&
    input.control.actor === "project-scoped" && input.control.target === "control" &&
    exactSuccessfulRead(input.control) && input.victimOwner.phase === "owner-victim-control" &&
    input.victimOwner.actor === "owner" && input.victimOwner.target === "victim" &&
    exactSuccessfulRead(input.victimOwner) && input.controlTarget.provenanceValidated &&
    input.victimTarget.provenanceValidated && input.controlTarget.projectId !== input.victimTarget.projectId &&
    input.controlTarget.sessionId !== input.victimTarget.sessionId;
}

function isNotFound(error: unknown): boolean {
  return error instanceof APIError && error.response.status === 404;
}

async function exactPrefixAbsent(
  config: Sbx056Config,
  gate: Sbx056RequestGate,
  target: Sbx056TargetJournal,
): Promise<boolean> {
  const page = await Sandbox.list({
    ...ownerCredentials(config, target.projectId, gate),
    namePrefix: target.name,
    limit: 10,
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  });
  const all = await page.toArray();
  return all.length === 0;
}

async function cleanupTarget(input: {
  config: Sbx056Config;
  gate: Sbx056RequestGate;
  held: Sbx056HeldSafety;
  journal: Sbx056Journal;
  target: Sbx056TargetJournal;
  sandbox?: Sandbox;
}): Promise<boolean> {
  if (input.target.createAttemptedAt === undefined) {
    input.target.zeroExternalStateConfirmed = true;
    await persistSbx056Journal(input.held, input.journal);
    return true;
  }
  let sandbox = input.sandbox;
  if (sandbox === undefined) {
    try {
      const recovered = await Sandbox.get({
        ...ownerCredentials(input.config, input.target.projectId, input.gate),
        name: input.target.name,
        resume: false,
        signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
      });
      if (!exactSbx056Handle(recovered, input.target)) return false;
      if (input.target.sessionId !== undefined &&
          recovered.currentSession().sessionId !== input.target.sessionId) return false;
      input.target.sessionId ??= recovered.currentSession().sessionId;
      input.target.provenanceValidated = true;
      await persistSbx056Journal(input.held, input.journal);
      sandbox = recovered;
    } catch (error) {
      if (!isNotFound(error)) return false;
      const knownExactTarget = input.target.provenanceValidated && input.target.sessionId !== undefined;
      if (!knownExactTarget && (input.target.sessionId !== undefined ||
          !sbx056UnknownCreateSettled(input.target))) return false;
    }
  }
  if (sandbox !== undefined) {
    if (!exactSbx056Handle(sandbox, input.target) || !input.target.provenanceValidated) return false;
    input.target.stopAttempted = true;
    await persistSbx056Journal(input.held, input.journal);
    try {
      if (sandbox.status === "running" || sandbox.status === "pending") {
        await sandbox.stop({ signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
      }
      input.target.stopped = true;
      await persistSbx056Journal(input.held, input.journal);
      input.target.deleteAttempted = true;
      await persistSbx056Journal(input.held, input.journal);
      try { await sandbox.delete({ signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) }); }
      catch (error) { if (!isNotFound(error)) throw error; }
      input.target.deleted = true;
      await persistSbx056Journal(input.held, input.journal);
    } catch (error) {
      if (!isNotFound(error)) throw error;
      sandbox = undefined;
    }
  }
  for (let index = input.target.exactNameAbsenceChecks; index < 2; index += 1) {
    try {
      await Sandbox.get({
        ...ownerCredentials(input.config, input.target.projectId, input.gate),
        name: input.target.name,
        resume: false,
        signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
      });
      return false;
    } catch (error) {
      if (!isNotFound(error)) return false;
      input.target.exactNameAbsenceChecks += 1;
      await persistSbx056Journal(input.held, input.journal);
    }
    if (index === 0) await delay(1_000);
  }
  input.target.prefixAbsent = await exactPrefixAbsent(input.config, input.gate, input.target);
  if (sandbox === undefined && input.target.exactNameAbsenceChecks >= 2 && input.target.prefixAbsent &&
      ((input.target.provenanceValidated && input.target.sessionId !== undefined) ||
        (input.target.sessionId === undefined && sbx056UnknownCreateSettled(input.target)))) {
    input.target.absenceResolvedWithoutHandle = true;
  }
  await persistSbx056Journal(input.held, input.journal);
  return input.target.exactNameAbsenceChecks >= 2 && input.target.prefixAbsent &&
    (input.target.absenceResolvedWithoutHandle || (input.target.provenanceValidated &&
      input.target.stopped && input.target.deleted));
}

function emptyAttempt(
  phase: Sbx056Attempt["phase"],
  actor: Sbx056Attempt["actor"],
  target: Sbx056Attempt["target"],
): Sbx056Attempt {
  const at = new Date().toISOString();
  return { phase, actor, target, startedAt: at, completedAt: at, method: "POST",
    routeShapeExact: false, teamQueryExact: false, projectIdentifierSent: false,
    redirectMode: "error", transportCalls: 1, status: null, contentType: null,
    responseBytes: 0, exactExpectedMarker: false, boundedAuthError: false, transportError: true };
}

function cleanupProof(journal: Sbx056Journal, liveLockReleased: boolean): Sbx056CleanupProof {
  const [control, victim] = journal.targets;
  return {
    controlStopped: control.stopped,
    controlDeleted: control.deleted,
    controlExactNameAbsent: control.exactNameAbsenceChecks >= 2,
    controlPrefixAbsent: control.prefixAbsent,
    victimStopped: victim.stopped,
    victimDeleted: victim.deleted,
    victimExactNameAbsent: victim.exactNameAbsenceChecks >= 2,
    victimPrefixAbsent: victim.prefixAbsent,
    journalCompleted: journal.completed,
    liveLockReleased,
  };
}

function minimumInterval(records: readonly Sbx056RequestRecord[]): boolean {
  return records.slice(1).every((record, index) =>
    Date.parse(record.startedAt) - Date.parse(records[index]!.startedAt) >= MIN_REQUEST_INTERVAL_MS);
}

function chronology(attempts: readonly Sbx056Attempt[]): boolean {
  return attempts.every((attempt, index) => index === 0 ||
    Date.parse(attempt.startedAt) >= Date.parse(attempts[index - 1]!.completedAt));
}

function provenance(
  journal: Sbx056Journal,
  config: Sbx056Config,
  publicAt: string,
  victimAt: string,
): Sbx056ProvenanceProof {
  const [control, victim] = journal.targets;
  return {
    controlCreatedByOwner: control.provenanceValidated,
    victimCreatedByOwner: victim.provenanceValidated,
    controlProjectExact: control.provenanceValidated && control.projectId === config.controlProjectId,
    victimProjectExact: victim.provenanceValidated && victim.projectId === config.victimProjectId,
    projectsDistinct: control.projectId !== victim.projectId,
    sessionsDistinct: control.sessionId !== undefined && victim.sessionId !== undefined &&
      control.sessionId !== victim.sessionId,
    namesAndTagsExact: control.provenanceValidated && victim.provenanceValidated,
    nonpersistent: control.provenanceValidated && victim.provenanceValidated,
    denyAll: control.provenanceValidated && victim.provenanceValidated,
    zeroRoutes: control.provenanceValidated && victim.provenanceValidated,
    fixedPathsExact: sbx056FixedPath(journal.runId, "control").includes(journal.runId.replaceAll("-", "")) &&
      sbx056FixedPath(journal.runId, "victim").includes(journal.runId.replaceAll("-", "")),
    publicMarkerWrittenBeforeVictimMarker: Date.parse(publicAt) < Date.parse(victimAt),
    victimMarkerStagedAfterPublicControl: journal.publicControlPassed && journal.victimMarkerStaged,
  };
}

function assessmentInput(input: {
  config: Sbx056Config;
  journal: Sbx056Journal;
  authority: Sbx056AuthorityProof;
  publicControl: Sbx056Attempt;
  ownerVictim: Sbx056Attempt;
  cross: Sbx056Attempt;
  crossGate: boolean;
  gate: Sbx056RequestGate;
  publicMarkerWrittenAt: string;
  victimMarkerWrittenAt: string;
  liveLockReleased: boolean;
}): Sbx056AssessmentInput {
  const attempts = [input.publicControl, input.ownerVictim, input.cross];
  return {
    runIdCanonical: SBX056_UUID.test(input.journal.runId),
    sameEligibleTeam: true,
    controlProjectId: input.config.controlProjectId,
    victimProjectId: input.config.victimProjectId,
    authority: input.authority,
    provenance: provenance(input.journal, input.config, input.publicMarkerWrittenAt,
      input.victimMarkerWrittenAt),
    publicControl: input.publicControl,
    ownerVictimControl: input.ownerVictim,
    crossProject: input.cross,
    crossDispatchGatePassed: input.crossGate,
    exactlyThreeReadRequests: input.gate.records.filter((record) =>
      record.pathname.endsWith("/fs/read")).length === 3,
    minimumRequestIntervalPassed: minimumInterval(input.gate.records),
    chronologyExact: chronology(attempts),
    rawTokensOrMarkersRetained: false,
    cleanup: cleanupProof(input.journal, input.liveLockReleased),
  };
}

async function runExperiment(config: Sbx056Config & { scopedToken: string }): Promise<number> {
  const journal = createSbx056Journal(config.controlProjectId, config.victimProjectId);
  process.stderr.write(`SBX-056 recovery run ID: ${journal.runId}\n`);
  const held = await acquireSbx056Safety(journal);
  const gate = new Sbx056RequestGate(config.ownerToken, config.scopedToken, config.teamId);
  const publicMarkerRaw = `SBX056-PUBLIC-${journal.runId}\n`;
  const victimMarkerRaw = `SBX056-VICTIM-${randomBytes(32).toString("base64url")}\n`;
  const publicMarker = Buffer.from(publicMarkerRaw, "utf8");
  const victimMarker = Buffer.from(victimMarkerRaw, "utf8");
  let controlSandbox: Sandbox | undefined;
  let victimSandbox: Sandbox | undefined;
  let authority: Sbx056AuthorityProof = {
    ownerAliasExact: false, ownerTeamExact: false, ownerControlProjectExact: false,
    ownerVictimProjectExact: false, scopedControlProjectExact: false,
    scopedVictimProjectDenied: false, scopedVictimProjectStatus: null,
    scopedTokenProjectRestrictionManuallyConfirmed: false,
    ownerAndScopedTokensDistinct: false,
  };
  let publicControl = emptyAttempt("public-control", "project-scoped", "control");
  let ownerVictim = emptyAttempt("owner-victim-control", "owner", "victim");
  let cross = emptyAttempt("cross-project", "project-scoped", "victim");
  let crossGate = false;
  let publicMarkerWrittenAt = journal.startedAt;
  let victimMarkerWrittenAt = journal.startedAt;
  let failure: string | undefined;
  try {
    authority = await verifySbx056Authority(config, gate);
    journal.ownerAuthorityPassed = authority.ownerAliasExact && authority.ownerTeamExact &&
      authority.ownerControlProjectExact && authority.ownerVictimProjectExact;
    journal.scopedAuthorityPassed = authority.scopedControlProjectExact &&
      authority.scopedVictimProjectDenied && authority.scopedTokenProjectRestrictionManuallyConfirmed &&
      authority.ownerAndScopedTokensDistinct;
    if (!journal.ownerAuthorityPassed || !journal.scopedAuthorityPassed) {
      throw new Error("SBX-056 authority proof failed before Sandbox creation");
    }
    await persistSbx056Journal(held, journal);
    controlSandbox = await createExactSandbox({ config, gate, held, journal,
      target: journal.targets[0] });
    await controlSandbox.writeFiles([{ path: sbx056FixedPath(journal.runId, "control"),
      content: publicMarker, mode: 0o644 }], { signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
    publicMarkerWrittenAt = new Date().toISOString();
    publicControl = await oneSbx056Read({ gate, token: config.scopedToken, teamId: config.teamId,
      sessionId: journal.targets[0].sessionId!, path: sbx056FixedPath(journal.runId, "control"),
      expected: publicMarker, phase: "public-control", actor: "project-scoped", target: "control" });
    if (!publicControl.exactExpectedMarker) throw new Error("SBX-056 public scoped-token control failed");
    journal.publicControlPassed = true;
    await persistSbx056Journal(held, journal);
    victimSandbox = await createExactSandbox({ config, gate, held, journal,
      target: journal.targets[1] });
    await victimSandbox.writeFiles([{ path: sbx056FixedPath(journal.runId, "victim"),
      content: victimMarker, mode: 0o600 }], { signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
    victimMarkerWrittenAt = new Date().toISOString();
    journal.victimMarkerStaged = true;
    await persistSbx056Journal(held, journal);
    ownerVictim = await oneSbx056Read({ gate, token: config.ownerToken, teamId: config.teamId,
      sessionId: journal.targets[1].sessionId!, path: sbx056FixedPath(journal.runId, "victim"),
      expected: victimMarker, phase: "owner-victim-control", actor: "owner", target: "victim" });
    crossGate = sbx056CrossDispatchGate({ authority, control: publicControl, victimOwner: ownerVictim,
      controlTarget: journal.targets[0], victimTarget: journal.targets[1] });
    if (!crossGate) throw new Error("SBX-056 cross-project dispatch gate failed");
    journal.crossReadDispatched = true;
    await persistSbx056Journal(held, journal);
    cross = await oneSbx056Read({ gate, token: config.scopedToken, teamId: config.teamId,
      sessionId: journal.targets[1].sessionId!, path: sbx056FixedPath(journal.runId, "victim"),
      expected: victimMarker, phase: "cross-project", actor: "project-scoped", target: "victim" });
  } catch (error) {
    failure = error instanceof Error ? error.message.slice(0, 240) : "unknown controller error";
  } finally {
    victimMarker.fill(0);
    publicMarker.fill(0);
  }
  const victimClean = await cleanupTarget({ config, gate, held, journal,
    target: journal.targets[1], ...(victimSandbox ? { sandbox: victimSandbox } : {}) }).catch(() => false);
  const controlClean = await cleanupTarget({ config, gate, held, journal,
    target: journal.targets[0], ...(controlSandbox ? { sandbox: controlSandbox } : {}) }).catch(() => false);
  if (!victimClean || !controlClean) {
    await closeSbx056RetainingState(held);
    throw new Error(`SBX-056 cleanup incomplete; lock+journal retained for ${journal.runId}`);
  }
  journal.completed = true;
  await persistSbx056Journal(held, journal);
  const pendingInput = assessmentInput({ config, journal, authority, publicControl,
    ownerVictim, cross, crossGate, gate, publicMarkerWrittenAt, victimMarkerWrittenAt,
    liveLockReleased: false });
  const finalInput = { ...pendingInput, cleanup: cleanupProof(journal, true) };
  const assessment = assessSbx056(finalInput);
  const checkpoint = { schemaVersion: 1, testId: SBX056_TEST_ID, runId: journal.runId,
    mode: "experiment", state: "cleanup-complete-lock-held", assessment: assessSbx056(pendingInput),
    failure: failure ?? null, rawTokensOrMarkersRetained: false };
  const artifact = { schemaVersion: 1, testId: SBX056_TEST_ID, runId: journal.runId,
    mode: "experiment", assessment, authority, provenance: finalInput.provenance,
    fixtures: journal.targets.map((target) => ({ role: target.role, name: target.name,
      projectId: target.projectId, sessionId: target.sessionId ?? null, tags: target.tags,
      persistent: false, networkPolicy: "deny-all", routesCount: 0 })),
    attempts: [publicControl, ownerVictim, cross], requestCount: gate.records.length,
    cleanup: finalInput.cleanup, failure: failure ?? null, rawTokensOrMarkersRetained: false };
  assertSbx056EvidenceExcludesRawValues(artifact,
    [config.ownerToken, config.scopedToken, publicMarkerRaw, victimMarkerRaw]);
  await finalizeSbx056Safety({ held, journal, checkpoint, finalArtifact: artifact });
  process.stdout.write(`${JSON.stringify(artifact)}\n`);
  return assessment.candidate ? 2 : assessment.verdict === "pass" ? 0 : 1;
}

async function runRecovery(config: Sbx056Config & { recoveryRunId: string }): Promise<number> {
  const recovered = await acquireSbx056RecoverySafety(config.recoveryRunId,
    config.controlProjectId, config.victimProjectId);
  const { held, journal } = recovered;
  if (journal.completed) {
    const recoveryAttemptId = randomUUID();
    const artifact = { schemaVersion: 1, testId: SBX056_TEST_ID, runId: journal.runId,
      mode: "cleanup-finalization-only",
      outcome: recovered.preJournalZeroStateRecovered
        ? "pre-journal-zero-state-recovered"
        : "durable-cleanup-already-complete",
      experimentVerdict: null, cleanup: cleanupProof(journal, true),
      rawTokensOrMarkersRetained: false };
    assertSbx056EvidenceExcludesRawValues(artifact, [config.ownerToken]);
    await finalizeSbx056Safety({ held, journal,
      checkpoint: { ...artifact, cleanup: cleanupProof(journal, false) }, finalArtifact: artifact,
      artifactPath: sbx056RecoveryArtifactPath(journal.runId, recoveryAttemptId) });
    process.stdout.write(`${JSON.stringify(artifact)}\n`);
    return 0;
  }
  const gate = new Sbx056RequestGate(config.ownerToken, undefined, config.teamId);
  const ownerAliasExact = await exactIdentityRead(gate, config.ownerToken, "/v2/user", "email",
    config.expectedAlias);
  const projectsExact = await exactIdentityRead(gate, config.ownerToken,
    `/v9/projects/${config.controlProjectId}?teamId=${config.teamId}`, "id", config.controlProjectId) &&
    await exactIdentityRead(gate, config.ownerToken,
      `/v9/projects/${config.victimProjectId}?teamId=${config.teamId}`, "id", config.victimProjectId);
  if (!ownerAliasExact || !projectsExact) {
    await closeSbx056RetainingState(held);
    throw new Error("SBX-056 recovery owner authority failed; lock+journal retained");
  }
  const victimClean = await cleanupTarget({ config, gate, held, journal,
    target: journal.targets[1] }).catch(() => false);
  const controlClean = await cleanupTarget({ config, gate, held, journal,
    target: journal.targets[0] }).catch(() => false);
  if (!victimClean || !controlClean) {
    await closeSbx056RetainingState(held);
    throw new Error("SBX-056 recovery remains incomplete; lock+journal retained");
  }
  journal.completed = true;
  await persistSbx056Journal(held, journal);
  const artifact = { schemaVersion: 1, testId: SBX056_TEST_ID, runId: journal.runId,
    mode: "cleanup-only", outcome: "cleanup-recovered", experimentVerdict: null,
    cleanup: cleanupProof(journal, true), rawTokensOrMarkersRetained: false };
  assertSbx056EvidenceExcludesRawValues(artifact, [config.ownerToken]);
  const recoveryAttemptId = randomUUID();
  await finalizeSbx056Safety({ held, journal,
    checkpoint: { ...artifact, cleanup: cleanupProof(journal, false) }, finalArtifact: artifact,
    artifactPath: sbx056RecoveryArtifactPath(journal.runId, recoveryAttemptId) });
  process.stdout.write(`${JSON.stringify(artifact)}\n`);
  return 0;
}

export async function main(environment: Readonly<Record<string, string | undefined>> = process.env): Promise<number> {
  const config = loadSbx056Config(environment);
  if (config.recoveryRunId !== undefined) return runRecovery({ ...config, recoveryRunId: config.recoveryRunId });
  if (config.scopedToken === undefined) throw new Error("SBX-056 normal run requires a project-scoped token");
  return runExperiment({ ...config, scopedToken: config.scopedToken });
}

const invoked = process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invoked) {
  main().then((code) => { process.exitCode = code; }).catch((error: unknown) => {
    process.stderr.write(`SBX-056 failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
