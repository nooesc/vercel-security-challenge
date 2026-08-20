import "dotenv/config";

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Resolver } from "node:dns/promises";
import { mkdir, open, readFile, unlink, writeFile, type FileHandle } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { APIError, Sandbox, type NetworkPolicy } from "@vercel/sandbox";
import type { ARecord, BRecord, DirectRecord, ReceiverConfiguration } from "./receiver.js";
import { assessSbx034, type Sbx034AssessmentInput } from "./verdict.js";

const TEST_ID = "SBX-034-POC";
const REMOTE_PROBE_PATH = "/tmp/sbx-034/forwardurl-redirect-probe.mjs";
const SCOPE_CONFIRMATION = "I_CONTROL_BOTH_SBX034_ORIGINS_AND_AUTHORIZE_BOUNDED_FORWARDURL_REDIRECT_TESTING";
const ALIAS_EMAIL = "swve@wearehackerone.com";
const TEAM_ID = "team_n98ERpVwV7HqmWRudAyK8sXQ";
const PROJECT_ID = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
const CASE_HEADER = "x-sbx034-case";
const CANARY_HEADER = "x-sbx-harness-canary";
const CONTROL_TIMEOUT_MS = 30_000;
const POLICY_SETTLE_MS = 1_500;
const INTER_REQUEST_MS = 500;
const MAX_GUEST_REQUESTS = 5;
const MAX_RESET_MS = 2_000;
const OPERATION_ID = /^redir_[A-Za-z0-9_-]{24}$/u;

type CaseId =
  | "direct-b-allow"
  | "redirect-attack-direct-b-pre"
  | "baseline-forward"
  | "redirect-attack"
  | "redirect-attack-direct-b-post";

interface GuestResult {
  schemaVersion?: number;
  runId?: string;
  testId?: string;
  caseId?: string;
  correlationId?: string;
  requestUrl?: string;
  method?: string;
  redirectMode?: string;
  maxRedirects?: number;
  retryCount?: number;
  requestCount?: number;
  maximumRequests?: number;
  actualRequests?: number;
  redirectsAllowed?: boolean;
  redirectsFollowed?: number;
  environmentProxyTrust?: boolean;
  destinationHost?: string;
  tlsServername?: string;
  httpHost?: string;
  tcpConnected?: boolean;
  tlsEstablished?: boolean;
  remoteAddress?: string;
  remotePort?: number;
  durationMs?: number;
  ok?: boolean;
  responseStarted?: boolean;
  statusCode?: number;
  bodyLength?: number;
  bodyTruncated?: boolean;
  location?: string;
  responseAuthenticated?: boolean;
  responseOperationId?: string;
  errorCode?: string;
  errorErrno?: number;
  errorSyscall?: string;
  errorMessage?: string;
}

interface CommandRecord {
  commandId: string;
  exitCode: number;
  stdoutBytes: number;
  stdoutSha256: string;
  stderrBytes: number;
  stderrSha256: string;
}

interface GuestCaseRecord {
  caseId: CaseId;
  configurationSha256: string;
  command: CommandRecord;
  result?: GuestResult;
}

interface PolicyProof {
  stage: "initial" | "pre-attack" | "post-attack";
  activeSandboxPolicy: NetworkPolicy | undefined;
  activeSessionPolicy: NetworkPolicy | undefined;
  independentSandboxPolicy: NetworkPolicy | undefined;
  independentSessionPolicy: NetworkPolicy | undefined;
  initialSessionId: string;
  activeSessionId: string;
  independentSessionId: string;
  exact: boolean;
  sameSession: boolean;
  passed: boolean;
}

interface ReceiverReadback {
  configured: boolean;
  aRecords: ARecord[];
  bRecords: BRecord[];
  directRecords: DirectRecord[];
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function signal(timeout = CONTROL_TIMEOUT_MS): AbortSignal {
  return AbortSignal.timeout(timeout);
}

function safeError(error: unknown, secrets: string[]): string {
  let message = error instanceof Error ? error.message : String(error);
  for (const secret of secrets) if (secret) message = message.split(secret).join("[REDACTED]");
  return message.replace(/[\0\r\n]/gu, " ").slice(0, 1_000);
}

function exactOrigin(raw: string, name: string): URL {
  const parsed = new URL(raw);
  if (
    raw !== parsed.origin || parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.port ||
    parsed.pathname !== "/" || parsed.search || parsed.hash || isIP(parsed.hostname) !== 0 ||
    parsed.hostname !== parsed.hostname.toLowerCase()
  ) {
    throw new Error(`${name} must be an exact lower-case HTTPS origin`);
  }
  return parsed;
}

export function controlledOrigins(environment: NodeJS.ProcessEnv = process.env): { a: URL; b: URL } {
  if (environment.SBX034_SCOPE_CONFIRMATION !== SCOPE_CONFIRMATION) {
    throw new Error(`SBX034_SCOPE_CONFIRMATION must equal ${SCOPE_CONFIRMATION}`);
  }
  const a = exactOrigin(environment.SBX034_A_PUBLIC_ORIGIN ?? "", "SBX034_A_PUBLIC_ORIGIN");
  const b = exactOrigin(environment.SBX034_B_PUBLIC_ORIGIN ?? "", "SBX034_B_PUBLIC_ORIGIN");
  if (a.origin === b.origin) throw new Error("SBX-034 requires two distinct owned HTTPS origins");
  return { a, b };
}

export function explicitCredentials(environment: NodeJS.ProcessEnv = process.env): { token: string; teamId: string; projectId: string } {
  const token = environment.VERCEL_TOKEN;
  if (!token || environment.VERCEL_TEAM_ID !== TEAM_ID || environment.VERCEL_PROJECT_ID !== PROJECT_ID) {
    throw new Error("SBX-034 requires explicit credentials for the verified HackerOne-alias team and project");
  }
  return { token, teamId: TEAM_ID, projectId: PROJECT_ID };
}

async function verifyAlias(token: string): Promise<void> {
  const response = await fetch("https://api.vercel.com/v2/user", {
    headers: { Authorization: `Bearer ${token}` }, signal: signal(10_000),
  });
  if (!response.ok) throw new Error(`Vercel alias verification returned ${response.status}`);
  const payload = await response.json() as { user?: { email?: unknown } };
  if (payload.user?.email !== ALIAS_EMAIL) throw new Error("Vercel token is not authenticated as the required HackerOne alias");
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function exactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return actual.length === sorted.length && actual.every((key, index) => key === sorted[index]);
}

export function exactAllowPolicy(value: unknown, hosts: string[]): boolean {
  const policy = object(value);
  if (!policy || !exactKeys(policy, ["allow"]) || !Array.isArray(policy.allow)) return false;
  const allow = policy.allow;
  return allow.length === hosts.length && new Set(allow).size === hosts.length &&
    hosts.every((host) => allow.includes(host));
}

export function exactForwardPolicy(value: unknown, hostname: string, forwardUrl: string): boolean {
  const policy = object(value);
  const allow = object(policy?.allow);
  if (!policy || !allow || !exactKeys(policy, ["allow"]) || !exactKeys(allow, [hostname])) return false;
  const rules = allow[hostname];
  if (!Array.isArray(rules) || rules.length !== 1) return false;
  const rule = object(rules[0]);
  return rule !== undefined && exactKeys(rule, ["forwardURL"]) && rule.forwardURL === forwardUrl;
}

export function exactForwardProjection(value: unknown, hostname: string): boolean {
  const policy = object(value);
  return policy !== undefined && exactKeys(policy, ["allow"]) && Array.isArray(policy.allow) &&
    policy.allow.length === 1 && policy.allow[0] === hostname;
}

function publicIpv4(address: string): boolean {
  if (isIP(address) !== 4) return false;
  const [a = -1, b = -1] = address.split(".").map(Number);
  return a > 0 && a < 224 && a !== 10 && a !== 127 && !(a === 172 && b >= 16 && b <= 31) &&
    !(a === 192 && b === 168) && !(a === 169 && b === 254) && !(a === 100 && b >= 64 && b <= 127);
}

async function resolveIpv4(hostname: string): Promise<string[]> {
  const resolver = new Resolver();
  const deadline = globalThis.setTimeout(() => resolver.cancel(), 10_000);
  try {
    const answers = await resolver.resolve4(hostname);
    const unique = [...new Set(answers.filter(publicIpv4))].sort();
    if (unique.length === 0) throw new Error(`${hostname} has no public IPv4 address`);
    return unique;
  } finally { globalThis.clearTimeout(deadline); }
}

function isNotFound(error: unknown): boolean {
  return error instanceof APIError && error.response.status === 404;
}

function recoverable(createdAt: Date, startedAt: string, tags: Record<string, string> | undefined, expected: Record<string, string>): boolean {
  const timestamp = createdAt.getTime();
  return timestamp >= Date.parse(startedAt) - 5_000 && timestamp <= Date.now() + 5_000 &&
    tags?.harness === expected.harness && tags.test === expected.test && tags.run === expected.run;
}

function sanitizeGuest(value: unknown): GuestResult | undefined {
  const input = object(value);
  if (!input) return undefined;
  const output: GuestResult = {};
  for (const key of ["schemaVersion", "maxRedirects", "retryCount", "requestCount", "maximumRequests", "actualRequests", "redirectsFollowed", "remotePort", "durationMs", "statusCode", "bodyLength", "errorErrno"] as const) {
    if (typeof input[key] === "number" && Number.isFinite(input[key])) output[key] = input[key] as never;
  }
  for (const key of ["runId", "testId", "caseId", "correlationId", "requestUrl", "method", "redirectMode", "destinationHost", "tlsServername", "httpHost", "remoteAddress", "location", "responseOperationId", "errorCode", "errorSyscall", "errorMessage"] as const) {
    if (typeof input[key] === "string" && input[key].length <= 4_096) output[key] = input[key] as never;
  }
  for (const key of ["tcpConnected", "tlsEstablished", "ok", "responseStarted", "bodyTruncated", "responseAuthenticated", "redirectsAllowed", "environmentProxyTrust"] as const) {
    if (typeof input[key] === "boolean") output[key] = input[key] as never;
  }
  return output;
}

async function adminRequest(a: URL, key: string, runId: string, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);
  headers.set("authorization", `Bearer ${key}`);
  if (init?.body) headers.set("content-type", "application/json");
  return fetch(new URL(`/v1/sbx034/admin/runs/${encodeURIComponent(runId)}`, a), {
    ...init, headers, signal: signal(10_000),
  });
}

async function receiverReadback(a: URL, key: string, runId: string): Promise<ReceiverReadback> {
  const response = await adminRequest(a, key, runId);
  if (response.status === 404) return { configured: false, aRecords: [], bRecords: [], directRecords: [] };
  if (!response.ok) throw new Error(`receiver readback returned ${response.status}`);
  const value = await response.json() as ReceiverReadback;
  if (!Array.isArray(value.aRecords) || !Array.isArray(value.bRecords) || !Array.isArray(value.directRecords)) {
    throw new Error("receiver returned invalid record arrays");
  }
  return { configured: value.configured === true, aRecords: value.aRecords, bRecords: value.bRecords, directRecords: value.directRecords };
}

async function health(origin: URL): Promise<boolean> {
  const response = await fetch(new URL("/healthz", origin), { signal: signal(10_000) });
  const body = await response.json() as { ok?: unknown };
  return response.ok && body.ok === true;
}

async function captureCommand(sandbox: Sandbox, configuration: unknown, secrets: string[]): Promise<{ command: CommandRecord; result?: GuestResult }> {
  const serialized = JSON.stringify(configuration);
  if (secrets.some((secret) => serialized.includes(secret))) throw new Error("guest configuration contains controller credentials");
  const command = await sandbox.runCommand({
    cmd: "node", args: [REMOTE_PROBE_PATH, Buffer.from(serialized).toString("base64url")], timeoutMs: 20_000,
    signal: signal(),
  });
  const [stdout, stderr] = await Promise.all([command.stdout({ signal: signal() }), command.stderr({ signal: signal() })]);
  if (Buffer.byteLength(stdout) > 64_000 || Buffer.byteLength(stderr) > 16_000) throw new Error("guest output exceeded evidence bounds");
  if (secrets.some((secret) => stdout.includes(secret) || stderr.includes(secret))) throw new Error("guest output contains controller credentials");
  let parsed: unknown;
  try { parsed = JSON.parse(stdout); } catch { throw new Error("guest did not emit structured JSON"); }
  const result = sanitizeGuest(parsed);
  return {
    command: {
      commandId: command.cmdId, exitCode: command.exitCode,
      stdoutBytes: Buffer.byteLength(stdout), stdoutSha256: sha256(stdout),
      stderrBytes: Buffer.byteLength(stderr), stderrSha256: sha256(stderr),
    },
    ...(result ? { result } : {}),
  };
}

export function conclusiveDirectReachability(result: GuestResult | undefined, pinnedIp: string, commandExit: number, records: DirectRecord[], caseId: string): boolean {
  return commandExit === 0 && result?.runId !== undefined && result.caseId === caseId && result.ok === true &&
    result.redirectMode === "manual" && result.requestCount === 1 && result.redirectsFollowed === 0 &&
    result.tcpConnected === true && result.tlsEstablished === true && result.remoteAddress === pinnedIp &&
    result.remotePort === 443 && result.statusCode === 204 && result.bodyLength === 0 &&
    records.filter((entry) => entry.caseId === caseId && entry.canaryMatched && entry.method === "GET").length === 1;
}

export function conclusiveDirectBlock(result: GuestResult | undefined, pinnedIp: string, commandExit: number, records: DirectRecord[], caseId: string): boolean {
  const permittedErrno = result?.errorErrno === undefined || result.errorErrno === -104;
  const permittedSyscall = result?.errorSyscall === undefined || result.errorSyscall === "connect" || result.errorSyscall === "read";
  return commandExit === 0 && result?.caseId === caseId && result.ok === false && result.redirectMode === "manual" &&
    result.requestCount === 1 && result.redirectsFollowed === 0 && result.tcpConnected === true &&
    result.remoteAddress === pinnedIp && result.remotePort === 443 && result.tlsEstablished === false &&
    result.responseStarted === false && result.errorCode === "ECONNRESET" && permittedErrno && permittedSyscall &&
    typeof result.durationMs === "number" && result.durationMs <= MAX_RESET_MS &&
    records.filter((entry) => entry.caseId === caseId).length === 0;
}

async function acquireLock(path: string): Promise<FileHandle> {
  await mkdir(resolve(path, ".."), { recursive: true, mode: 0o700 });
  return open(path, "wx", 0o600);
}

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  const lockPath = resolve(artifactsDirectory, "SBX-034-live-active.lock");
  const { a, b } = controlledOrigins();
  const adminKey = required("SBX034_ADMIN_KEY");
  const credentials = explicitCredentials();
  const secrets = [adminKey, credentials.token];
  const runId = randomUUID();
  const sandboxName = `sbx-034-poc-${runId.replaceAll("-", "")}`;
  const sandboxTags = { harness: "vsc", test: TEST_ID, run: runId };
  const canary = `corr_${randomBytes(18).toString("base64url")}`;
  const forwardAudience = new URL(`/v1/sbx034/forward/${encodeURIComponent(runId)}`, a).toString();
  const redirectUrl = new URL(`/v1/sbx034/target/${encodeURIComponent(runId)}`, b);
  redirectUrl.search = new URLSearchParams({ run: runId, case: "redirect-attack", canary }).toString();
  const initialPolicy = { allow: [a.hostname, b.hostname] } satisfies NetworkPolicy;
  const finalPolicy = { allow: { [a.hostname]: [{ forwardURL: forwardAudience }] } } satisfies NetworkPolicy;
  const cleanup = {
    orphanRecoveryAttempted: false, recovered: false, stopAttempted: false, stopped: false,
    deleteAttempted: false, deleted: false, deletionAbsenceConfirmed: false,
    receiverDeleteAttempted: false, receiverDeleted: false, receiverAbsent: false,
    lockReleased: false, errors: [] as string[],
  };
  let sandbox: Sandbox | undefined;
  let createAttempted = false;
  let receiverConfigured = false;
  let sessionId: string | undefined;
  let receiver: ReceiverReadback = { configured: false, aRecords: [], bRecords: [], directRecords: [] };
  let executionError: string | undefined;
  let attempts = 0;
  const guestCases: GuestCaseRecord[] = [];
  const policyProofs: PolicyProof[] = [];
  let bAddresses: string[] = [];
  let pinnedB = "missing";
  let liveLock: FileHandle | undefined;

  const proof = async (stage: PolicyProof["stage"]): Promise<PolicyProof> => {
    if (!sandbox || !sessionId) throw new Error("policy proof requires active sandbox identity");
    const activeSession = sandbox.currentSession();
    const independent = await Sandbox.get({ name: sandboxName, resume: false, signal: signal(), ...credentials });
    const independentSession = independent.currentSession();
    const initial = stage === "initial";
    const exact = initial
      ? exactAllowPolicy(sandbox.networkPolicy, initialPolicy.allow) && exactAllowPolicy(independent.networkPolicy, initialPolicy.allow) &&
        exactAllowPolicy(activeSession.networkPolicy, initialPolicy.allow) && exactAllowPolicy(independentSession.networkPolicy, initialPolicy.allow)
      : exactForwardProjection(sandbox.networkPolicy, a.hostname) && exactForwardProjection(independent.networkPolicy, a.hostname) &&
        exactForwardPolicy(activeSession.networkPolicy, a.hostname, forwardAudience) &&
        exactForwardPolicy(independentSession.networkPolicy, a.hostname, forwardAudience);
    const sameSession = activeSession.sessionId === sessionId && independentSession.sessionId === sessionId;
    return {
      stage, activeSandboxPolicy: sandbox.networkPolicy, activeSessionPolicy: activeSession.networkPolicy,
      independentSandboxPolicy: independent.networkPolicy, independentSessionPolicy: independentSession.networkPolicy,
      initialSessionId: sessionId, activeSessionId: activeSession.sessionId,
      independentSessionId: independentSession.sessionId, exact, sameSession, passed: exact && sameSession,
    };
  };

  const runCase = async (caseId: CaseId, direct: boolean): Promise<GuestCaseRecord> => {
    if (!sandbox) throw new Error("sandbox unavailable");
    if (attempts >= MAX_GUEST_REQUESTS) throw new Error("fixed five-request bound exhausted");
    const destination = direct ? b : a;
    const path = direct
      ? `/v1/sbx034/direct/${encodeURIComponent(runId)}?${new URLSearchParams({ case: caseId, canary })}`
      : `/v1/sbx034/original/${encodeURIComponent(runId)}/${caseId}`;
    const configuration = {
      scopeConfirmation: "researcher-controlled-sbx034-origins-only",
      redirectMode: "manual", maxRedirects: 0, retryCount: 0,
      researcherControlledHosts: [a.hostname, b.hostname], runId, testId: TEST_ID, caseId,
      correlationId: canary,
      destinationHost: direct ? pinnedB : destination.hostname, destinationPort: 443,
      tlsServername: destination.hostname, httpHost: destination.hostname, path,
      headers: { [CASE_HEADER]: caseId, [CANARY_HEADER]: canary }, timeoutMs: 8_000,
    };
    attempts += 1;
    const captured = await captureCommand(sandbox, configuration, secrets);
    const entry: GuestCaseRecord = {
      caseId, configurationSha256: sha256(JSON.stringify(configuration)), command: captured.command,
      ...(captured.result ? { result: captured.result } : {}),
    };
    guestCases.push(entry);
    await delay(INTER_REQUEST_MS, undefined, { signal: signal(2_000) });
    return entry;
  };

  try {
    liveLock = await acquireLock(lockPath);
    await verifyAlias(credentials.token);
    if (!(await health(a)) || !(await health(b))) throw new Error("both owned receiver roles must be healthy");
    const absent = await receiverReadback(a, adminKey, runId);
    if (absent.configured) throw new Error("fresh receiver run id was unexpectedly configured");
    bAddresses = await resolveIpv4(b.hostname);
    pinnedB = bAddresses[0]!;

    createAttempted = true;
    sandbox = await Sandbox.create({
      name: sandboxName, persistent: false, timeout: 480_000, resources: { vcpus: 2 },
      networkPolicy: initialPolicy, tags: sandboxTags, signal: signal(), ...credentials,
    });
    sessionId = sandbox.currentSession().sessionId;
    if (sandbox.name !== sandboxName || sandbox.tags?.run !== runId || sandbox.tags.test !== TEST_ID) {
      throw new Error("created sandbox identity did not match the exact run");
    }
    const configuration: ReceiverConfiguration = {
      runId, originalHost: a.hostname, forwardAudience, redirectUrl: redirectUrl.toString(),
      expectedTeamId: TEAM_ID, expectedProjectId: PROJECT_ID,
      expectedSandboxId: sessionId, expectedSandboxName: sandboxName, correlationCanary: canary,
    };
    const registered = await adminRequest(a, adminKey, runId, { method: "POST", body: JSON.stringify(configuration) });
    if (registered.status !== 201) throw new Error(`receiver registration returned ${registered.status}`);
    receiverConfigured = true;
    receiver = await receiverReadback(a, adminKey, runId);
    if (!receiver.configured) throw new Error("receiver registration did not read back");

    const source = await readFile(resolve("guest/forwardurl-redirect-probe.mjs"), "utf8");
    if (secrets.some((secret) => source.includes(secret))) throw new Error("guest probe source contains controller credentials");
    await sandbox.writeFiles([{ path: REMOTE_PROBE_PATH, content: source, mode: 0o700 }], { signal: signal() });
    policyProofs.push(await proof("initial"));
    if (!policyProofs.at(-1)?.passed) throw new Error("initial policy/session proof failed");

    const allow = await runCase("direct-b-allow", true);
    receiver = await receiverReadback(a, adminKey, runId);
    if (!conclusiveDirectReachability(allow.result, pinnedB, allow.command.exitCode, receiver.directRecords, allow.caseId)) {
      throw new Error("temporary-policy direct B reachability control failed");
    }

    await sandbox.update({ networkPolicy: finalPolicy }, { signal: signal() });
    await delay(POLICY_SETTLE_MS, undefined, { signal: signal(3_000) });
    policyProofs.push(await proof("pre-attack"));
    if (!policyProofs.at(-1)?.passed) throw new Error("pre-attack final policy/session proof failed");

    const pre = await runCase("redirect-attack-direct-b-pre", true);
    receiver = await receiverReadback(a, adminKey, runId);
    if (!conclusiveDirectBlock(pre.result, pinnedB, pre.command.exitCode, receiver.directRecords, pre.caseId)) {
      throw new Error("pre-attack direct B block was not conclusive");
    }

    const baseline = await runCase("baseline-forward", false);
    receiver = await receiverReadback(a, adminKey, runId);
    const baselineRecords = receiver.aRecords.filter((entry) => entry.caseId === "baseline-forward");
    if (
      baseline.result?.ok !== true || baseline.result.statusCode !== 202 || baseline.result.redirectsFollowed !== 0 ||
      baselineRecords.length !== 1 || baselineRecords[0]?.authenticated !== true ||
      baselineRecords[0].identityMatched !== true || baselineRecords[0].oidcHeaderCount !== 1 ||
      baselineRecords[0].oidcValueCount !== 1 || baseline.result.responseOperationId !== baselineRecords[0].operationId
    ) {
      throw new Error("authenticated baseline forwardURL control failed");
    }

    await runCase("redirect-attack", false);
    await delay(750, undefined, { signal: signal(2_000) });
    receiver = await receiverReadback(a, adminKey, runId);
    policyProofs.push(await proof("post-attack"));
    const post = await runCase("redirect-attack-direct-b-post", true);
    await delay(750, undefined, { signal: signal(2_000) });
    receiver = await receiverReadback(a, adminKey, runId);
    if (!conclusiveDirectBlock(post.result, pinnedB, post.command.exitCode, receiver.directRecords, post.caseId)) {
      throw new Error("post-attack direct B block was not conclusive");
    }
  } catch (error) {
    executionError = safeError(error, secrets);
  } finally {
    if (!sandbox && createAttempted) {
      cleanup.orphanRecoveryAttempted = true;
      try {
        const recovered = await Sandbox.get({ name: sandboxName, resume: false, signal: signal(), ...credentials });
        if (recoverable(recovered.createdAt, startedAt, recovered.tags, sandboxTags)) {
          sandbox = recovered; cleanup.recovered = true;
        } else cleanup.errors.push("orphan recovery found a nonmatching sandbox and left it untouched");
      } catch (error) {
        if (!isNotFound(error)) cleanup.errors.push(`orphan recovery: ${safeError(error, secrets)}`);
      }
    }
    if (sandbox) {
      cleanup.stopAttempted = true;
      try { await sandbox.stop({ signal: signal() }); cleanup.stopped = true; }
      catch (error) { cleanup.errors.push(`stop: ${safeError(error, secrets)}`); }
      cleanup.deleteAttempted = true;
      try { await sandbox.delete({ signal: signal() }); cleanup.deleted = true; }
      catch (error) { cleanup.errors.push(`delete: ${safeError(error, secrets)}`); }
      if (cleanup.deleted) {
        let absent = 0;
        for (let attempt = 0; attempt < 3; attempt += 1) {
          if (attempt) await delay(750, undefined, { signal: signal(2_000) });
          try { await Sandbox.get({ name: sandboxName, resume: false, signal: signal(), ...credentials }); }
          catch (error) { if (isNotFound(error)) absent += 1; else cleanup.errors.push(`absence check: ${safeError(error, secrets)}`); }
        }
        cleanup.deletionAbsenceConfirmed = absent === 3;
        if (!cleanup.deletionAbsenceConfirmed) cleanup.errors.push("sandbox deletion was not confirmed absent three times");
      }
    }
    if (receiverConfigured) {
      cleanup.receiverDeleteAttempted = true;
      try {
        const deletion = await adminRequest(a, adminKey, runId, { method: "DELETE" });
        cleanup.receiverDeleted = deletion.status === 200;
        cleanup.receiverAbsent = !(await receiverReadback(a, adminKey, runId)).configured;
        if (!cleanup.receiverDeleted || !cleanup.receiverAbsent) cleanup.errors.push("receiver configuration cleanup failed");
      } catch (error) { cleanup.errors.push(`receiver cleanup: ${safeError(error, secrets)}`); }
    }
    if (liveLock) {
      try { await liveLock.close(); await unlink(lockPath); cleanup.lockReleased = true; }
      catch (error) { cleanup.errors.push(`live lock cleanup: ${safeError(error, secrets)}`); }
    }
  }

  const byCase = (caseId: CaseId): GuestCaseRecord | undefined => guestCases.find((entry) => entry.caseId === caseId);
  const attackCase = byCase("redirect-attack");
  const attackGuest = byCase("redirect-attack")?.result;
  const attackA = receiver.aRecords.filter((entry) => entry.caseId === "redirect-attack");
  const attackB = receiver.bRecords.filter((entry) => entry.caseId === "redirect-attack");
  const preCase = byCase("redirect-attack-direct-b-pre");
  const postCase = byCase("redirect-attack-direct-b-post");
  const guestAttackPath = `/v1/sbx034/original/${encodeURIComponent(runId)}/redirect-attack`;
  const guestAttackUrl = new URL(guestAttackPath, a).toString();
  const sourceRequestUrl = new URL(`${new URL(forwardAudience).pathname}${guestAttackPath}`, a).toString();
  const expectedOperationId = attackGuest?.responseOperationId && OPERATION_ID.test(attackGuest.responseOperationId)
    ? attackGuest.responseOperationId
    : "no-destination-operation";
  const expected = {
    runId,
    testId: TEST_ID,
    caseId: "redirect-attack",
    correlationId: canary,
    guestRequestUrl: guestAttackUrl,
    forwardObserverUrl: sourceRequestUrl,
    redirectTargetUrl: redirectUrl.toString(),
    oidcAudience: forwardAudience,
    operationId: expectedOperationId,
    identity: {
      teamId: TEAM_ID,
      projectId: PROJECT_ID,
      sandboxId: sessionId ?? "missing-sandbox-id",
      sessionId: sessionId ?? "missing-session-id",
      sandboxName,
    },
  };
  const input: Sbx034AssessmentInput = {
    ...(executionError ? { executionError: true } : {}),
    cleanupPassed: cleanup.stopped && cleanup.deleted && cleanup.deletionAbsenceConfirmed &&
      cleanup.receiverDeleted && cleanup.receiverAbsent && cleanup.lockReleased,
    identityAndScopePassed: sessionId !== undefined && credentials.teamId === TEAM_ID &&
      credentials.projectId === PROJECT_ID,
    forwardPolicyConfiguredExactly: exactForwardPolicy(finalPolicy, a.hostname, forwardAudience),
    initialPolicyReadbackPassed: policyProofs.find((entry) => entry.stage === "initial")?.passed === true,
    finalPolicyReadbackPassed: policyProofs.find((entry) => entry.stage === "pre-attack")?.passed === true &&
      policyProofs.find((entry) => entry.stage === "post-attack")?.passed === true,
    sameSessionPassed: policyProofs.length === 3 && policyProofs.every((entry) => entry.sameSession),
    sourceRedirectConfiguredExactly: redirectUrl.toString() === attackA[0]?.location,
    expected,
    guest: {
      commandExitCode: attackCase?.command.exitCode ?? -1,
      ok: attackGuest?.ok === true,
      runId: attackGuest?.runId ?? "missing",
      testId: attackGuest?.testId ?? "missing",
      caseId: attackGuest?.caseId ?? "missing",
      correlationId: attackGuest?.correlationId ?? "missing",
      requestUrl: attackGuest?.requestUrl ?? "https://invalid.invalid/",
      method: attackGuest?.method ?? "missing",
      maximumRequests: attackGuest?.maximumRequests ?? -1,
      actualRequests: attackGuest?.actualRequests ?? -1,
      retryCount: attackGuest?.retryCount ?? -1,
      redirectMode: attackGuest?.redirectMode ?? "missing",
      redirectsAllowed: attackGuest?.redirectsAllowed ?? true,
      redirectsFollowed: attackGuest?.redirectsFollowed ?? -1,
      environmentProxyTrust: attackGuest?.environmentProxyTrust ?? true,
      ...(attackGuest?.responseOperationId ? { responseOperationId: attackGuest.responseOperationId } : {}),
    },
    directBPre: {
      caseId: "redirect-attack-direct-b-pre",
      maximumRequests: preCase?.result?.maximumRequests ?? -1,
      actualRequests: preCase?.result?.actualRequests ?? -1,
      retryCount: preCase?.result?.retryCount ?? -1,
      redirectsAllowed: preCase?.result?.redirectsAllowed ?? true,
      samePinnedDestination: preCase?.result?.remoteAddress === pinnedB && preCase?.result?.remotePort === 443,
      conclusiveFirewallBlock: conclusiveDirectBlock(
        preCase?.result, pinnedB, preCase?.command.exitCode ?? -1,
        receiver.directRecords, "redirect-attack-direct-b-pre",
      ),
      destinationObserverEventCount: receiver.directRecords.filter((entry) =>
        entry.caseId === "redirect-attack-direct-b-pre"
      ).length,
    },
    directBPost: {
      caseId: "redirect-attack-direct-b-post",
      maximumRequests: postCase?.result?.maximumRequests ?? -1,
      actualRequests: postCase?.result?.actualRequests ?? -1,
      retryCount: postCase?.result?.retryCount ?? -1,
      redirectsAllowed: postCase?.result?.redirectsAllowed ?? true,
      samePinnedDestination: postCase?.result?.remoteAddress === pinnedB && postCase?.result?.remotePort === 443,
      conclusiveFirewallBlock: conclusiveDirectBlock(
        postCase?.result, pinnedB, postCase?.command.exitCode ?? -1,
        receiver.directRecords, "redirect-attack-direct-b-post",
      ),
      destinationObserverEventCount: receiver.directRecords.filter((entry) =>
        entry.caseId === "redirect-attack-direct-b-post"
      ).length,
    },
    source: {
      eventCount: attackA.length,
      ...(attackA[0]
        ? {
            event: {
              runId: attackA[0].runId,
              testId: attackA[0].testId,
              caseId: attackA[0].caseId,
              correlationId: attackA[0].correlationId,
              requestUrl: attackA[0].requestUrl,
              redirectStatusCode: attackA[0].responseStatus,
              location: attackA[0].location ?? "https://invalid.invalid/",
            },
          }
        : {}),
    },
    destination: {
      eventCount: attackB.length,
      ...(attackB[0]
        ? {
            event: {
              runId: attackB[0].runId,
              testId: attackB[0].testId,
              caseId: attackB[0].caseId,
              correlationId: attackB[0].correlationId,
              requestUrl: attackB[0].requestUrl,
              operationId: attackB[0].operationId,
              attributableToSourceRedirect: attackB[0].attributableToSourceRedirect,
              oidcHeaderCount: attackB[0].oidcHeaderCount,
              oidcValueCount: attackB[0].oidcValueCount,
              oidcVerifications: attackB[0].oidcVerifications,
            },
          }
        : {}),
    },
  };
  const assessment = assessSbx034(input);
  const evidence = {
    schemaVersion: 1, visibility: "private", testId: TEST_ID, runId, startedAt, completedAt: new Date().toISOString(),
    scope: "one verified HackerOne-alias Vercel account, one sandbox, and two researcher-owned HTTPS origins",
    runtime: { sandboxSdk: "@vercel/sandbox@3.0.0", controllerNode: process.version },
    account: { email: ALIAS_EMAIL, teamId: TEAM_ID, projectId: PROJECT_ID },
    origins: { a: a.origin, b: b.origin, bAddresses, pinnedB },
    sandbox: sessionId ? { name: sandboxName, sessionId } : undefined,
    policy: { initialPolicy, finalPolicy, forwardAudience, proofs: policyProofs },
    bounds: { attempts, maximum: MAX_GUEST_REQUESTS, sequential: true, retries: 0, redirectsFollowedByGuest: 0, minimumDelayMs: INTER_REQUEST_MS },
    guestCases, receiverRecords: receiver,
    tokenHandling: {
      rawPlatformTokenStoredLoggedOrReturned: false,
      platformTokenDigestStored: false,
      independentBVerificationRetainedAsBooleansAndExactClaimsOnly: true,
      controllerCredentialsEnteredGuest: false,
    },
    correlationCanarySha256: sha256(canary), assessmentInput: input, assessment, cleanup,
    ...(executionError ? { executionError } : {}),
  };
  const serialized = `${JSON.stringify(evidence, null, 2)}\n`;
  if (secrets.some((secret) => serialized.includes(secret))) throw new Error("refusing to store controller credentials");
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const artifactPath = resolve(artifactsDirectory, `SBX-034-${runId}-private.json`);
  await writeFile(artifactPath, serialized, { encoding: "utf8", mode: 0o600, flag: "wx" });
  process.stdout.write(`${JSON.stringify({
    testId: TEST_ID, runId, verdict: assessment.verdict, severity: assessment.severity,
    summary: assessment.summary, guestRequestAttempts: attempts, artifactPath,
  }, null, 2)}\n`);
  process.exitCode = assessment.verdict === "pass" ? 0 : 1;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  main().catch((error) => {
    process.stderr.write(`${String(error instanceof Error ? error.message : error).slice(0, 1_000)}\n`);
    process.exitCode = 1;
  });
}
