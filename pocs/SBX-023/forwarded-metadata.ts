import "dotenv/config";

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Resolver } from "node:dns/promises";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { APIError, Sandbox, type NetworkPolicy } from "@vercel/sandbox";
import { HttpObserverClient } from "../../src/observer-client.js";
import type { ObserverEvent } from "../../src/contracts.js";
import {
  assessSbx023,
  rawAuditContainsUniqueValues,
  type AttackAttributionClass,
  type GuestCaseAssessment,
  type ProxyAuthenticationRecord,
  type ProxyIdentity,
  type ProxyRawHeaderAudit,
} from "./verdict.js";

const remoteProbePath = "/tmp/sbx-023/forwarded-header-probe.mjs";
const testId = "SBX-023-POC";
const scopeConfirmation = "I_CONTROL_BOTH_PINNED_TRYCLOUDFLARE_ORIGINS_AND_AUTHORIZE_BOUNDED_FORWARDING_TESTING";
const eligibleAliasEmail = "swve@wearehackerone.com";
const eligibleTeamId = "team_n98ERpVwV7HqmWRudAyK8sXQ";
const eligibleProjectId = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
const canaryHeader = "x-sbx-harness-canary";
const caseHeader = "x-sbx-forward-case";
const minimumInterRequestDelayMs = 500;
const policySettleDelayMs = 1_500;
const controlPlaneTimeoutMs = 30_000;
const maximumEndpointRequests = 16;
const maximumConclusiveResetDurationMs = 2_000;
const operationIdPattern = /^proxy_[A-Za-z0-9_-]{24}$/u;
const safeHeaderNamePattern = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;

type CaseId =
  | "direct-b-allow-control"
  | "direct-b-pre-negative"
  | "baseline-forward"
  | "spoof-host"
  | "spoof-path"
  | "spoof-scheme"
  | "spoof-port"
  | "spoof-oidc"
  | "full-forge"
  | "duplicate-host-b-a"
  | "duplicate-host-a-b"
  | "duplicate-path-action-source"
  | "duplicate-path-source-action"
  | "case-variant-full-forge"
  | "full-forge-a-port"
  | "direct-b-post-negative";

interface GuestProbeResult {
  ok?: boolean;
  runId?: string;
  testId?: string;
  caseId?: string;
  statusCode?: number;
  bodyLength?: number;
  truncated?: boolean;
  responseJsonValid?: boolean;
  operationId?: string;
  authenticated?: boolean;
  actionAuthorized?: boolean;
  outboundHeaderNames?: string[];
  connectIpUsed?: string;
  tcpConnected?: boolean;
  remoteAddress?: string;
  remotePort?: number;
  tlsEstablished?: boolean;
  responseStarted?: boolean;
  errorPhase?: string;
  errorCode?: string;
  errorErrno?: number;
  errorSyscall?: string;
  durationMs?: number;
}

interface CommandRecord {
  commandId: string;
  exitCode: number;
  durationMs?: number;
  stdoutByteLength: number;
  stdoutSha256: string;
  stderrByteLength: number;
  stderrSha256: string;
}

interface GuestCaseRecord {
  caseId: CaseId;
  description: string;
  command: CommandRecord;
  configurationSha256: string;
  headerPlan: Array<{ name: string; value?: string; valueSha256?: string }>;
  result?: GuestProbeResult;
}

interface CaseDefinition {
  caseId: CaseId;
  description: string;
  destination: URL;
  rawPath: string;
  reservedHeaders: Array<[string, string]>;
  attributionClass?: AttackAttributionClass;
  causalGuestFields?: Array<{ name: string; value: string }>;
  connectIp?: string;
  directControl?: "allow-positive" | "deny-reset";
}

interface PolicyProof {
  stage: "initial-allow" | "pre-attack" | "post-attack";
  activeSandboxPolicy: NetworkPolicy | undefined;
  activeSessionPolicy: NetworkPolicy | undefined;
  independentSandboxPolicy: NetworkPolicy | undefined;
  independentSessionPolicy: NetworkPolicy | undefined;
  initialSessionId: string;
  activeSessionId: string;
  independentSessionId: string;
  sandboxProjectionPassed: boolean;
  fullSessionPolicyPassed: boolean;
  sameSessionPassed: boolean;
  passed: boolean;
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function controlSignal(timeoutMs = controlPlaneTimeoutMs): AbortSignal {
  return AbortSignal.timeout(timeoutMs);
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function safeText(value: unknown, maximum = 256): string | undefined {
  return typeof value === "string"
    ? value.replace(/[\0\r\n]/gu, " ").slice(0, maximum)
    : undefined;
}

function numeric(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function exactBoolean(value: unknown): boolean | undefined {
  return value === true ? true : value === false ? false : undefined;
}

function redact(value: string, secrets: string[]): string {
  return secrets.reduce(
    (output, secret) => secret.length === 0 ? output : output.split(secret).join("[REDACTED]"),
    value,
  );
}

function safeError(error: unknown, secrets: string[]): string {
  return redact(error instanceof Error ? error.message : String(error), secrets)
    .replace(/[\0\r\n]/gu, " ")
    .slice(0, 1_000);
}

function isNotFound(error: unknown): boolean {
  return error instanceof APIError && error.response.status === 404;
}

export function recoverableSandboxIdentity(input: {
  createdAtMs: number;
  startedAtMs: number;
  nowMs: number;
  tags: Record<string, string> | undefined;
  expectedTags: Record<string, string>;
}): boolean {
  return Number.isFinite(input.createdAtMs) && input.createdAtMs >= input.startedAtMs - 5_000 &&
    input.createdAtMs <= input.nowMs + 5_000 &&
    input.tags?.harness === input.expectedTags.harness &&
    input.tags?.test === input.expectedTags.test && input.tags?.run === input.expectedTags.run;
}

export function exitCodeForVerdict(verdict: "pass" | "candidate" | "indeterminate" | "error"): number {
  return verdict === "pass" ? 0 : 1;
}

export function explicitCredentials(
  environment: NodeJS.ProcessEnv = process.env,
): { token: string; teamId: string; projectId: string } {
  const token = environment.VERCEL_TOKEN;
  const teamId = environment.VERCEL_TEAM_ID;
  const projectId = environment.VERCEL_PROJECT_ID;
  if (!token || !teamId || !projectId) {
    throw new Error("VERCEL_TOKEN, VERCEL_TEAM_ID, and VERCEL_PROJECT_ID are required");
  }
  if (teamId !== eligibleTeamId || projectId !== eligibleProjectId) {
    throw new Error("SBX-023 must use the verified HackerOne-alias Vercel team and project");
  }
  return { token, teamId, projectId };
}

async function verifyAliasIdentity(token: string): Promise<{ email: string; method: string }> {
  const response = await fetch("https://api.vercel.com/v2/user", {
    headers: { Authorization: `Bearer ${token}` },
    signal: controlSignal(10_000),
  });
  if (response.ok) {
    const payload = await response.json() as { user?: { email?: unknown } };
    if (payload.user?.email !== eligibleAliasEmail) {
      throw new Error("Vercel token is not authenticated as the required HackerOne alias");
    }
    return { email: eligibleAliasEmail, method: "v2-user-email" };
  }
  if (response.status !== 401 && response.status !== 403) {
    throw new Error(`could not verify Vercel token identity (${response.status})`);
  }
  if (process.env.SBX023_ALIAS_EMAIL_CONFIRMATION !== eligibleAliasEmail) {
    throw new Error("scoped Sandbox token requires the exact manual HackerOne alias confirmation");
  }
  const headers = { Authorization: `Bearer ${token}` };
  const [teamResponse, projectResponse] = await Promise.all([
    fetch(`https://api.vercel.com/v2/teams/${eligibleTeamId}`, { headers, signal: controlSignal(10_000) }),
    fetch(`https://api.vercel.com/v9/projects/${eligibleProjectId}?teamId=${eligibleTeamId}`, {
      headers,
      signal: controlSignal(10_000),
    }),
  ]);
  if (!teamResponse.ok || !projectResponse.ok) {
    throw new Error(`scoped Vercel identity proof failed (team=${teamResponse.status}, project=${projectResponse.status})`);
  }
  const team = await teamResponse.json() as { id?: unknown };
  const project = await projectResponse.json() as { id?: unknown };
  if (team.id !== eligibleTeamId || project.id !== eligibleProjectId) {
    throw new Error("scoped Vercel identity proof returned the wrong team or project");
  }
  return { email: eligibleAliasEmail, method: "manual-alias-confirmation-plus-exact-team-project-api" };
}

function exactPinnedOrigin(raw: string): URL {
  const value = new URL(raw);
  if (
    raw !== value.origin || value.protocol !== "https:" || value.port !== "" ||
    value.pathname !== "/" ||
    value.username || value.password || value.search || value.hash ||
    !value.hostname.endsWith(".trycloudflare.com") || value.hostname !== value.hostname.toLowerCase()
  ) {
    throw new Error("SBX-023 observer origin did not match the exact owned Quick Tunnel hard-pin");
  }
  return value;
}

export function controlledOrigins(
  environment: NodeJS.ProcessEnv = process.env,
): { observerA: URL; observerB: URL } {
  if (required(environment, "SBX023_SCOPE_CONFIRMATION") !== scopeConfirmation) {
    throw new Error(`SBX023_SCOPE_CONFIRMATION must equal ${scopeConfirmation}`);
  }
  const observerA = exactPinnedOrigin(required(environment, "SBX023_A_PUBLIC_ORIGIN"));
  const observerB = exactPinnedOrigin(required(environment, "SBX023_B_PUBLIC_ORIGIN"));
  if (observerA.hostname === observerB.hostname) throw new Error("SBX-023 observer hard-pins must be distinct");
  return { observerA, observerB };
}

function publicIPv4(value: string): boolean {
  if (isIP(value) !== 4) return false;
  const [a = -1, b = -1] = value.split(".").map(Number);
  if (a <= 0 || a >= 224 || a === 127) return false;
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return false;
  if ((a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127)) return false;
  if ((a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19))) return false;
  return true;
}

async function resolvePublicIPv4(hostname: string): Promise<Array<{ address: string; ttl: number }>> {
  const resolver = new Resolver();
  const deadline = globalThis.setTimeout(() => resolver.cancel(), 10_000);
  let resolved: Array<{ address: string; ttl: number }>;
  try {
    resolved = await resolver.resolve4(hostname, { ttl: true });
  } finally {
    globalThis.clearTimeout(deadline);
  }
  const answers = resolved.filter((answer, index, all) =>
    publicIPv4(answer.address) && all.findIndex((candidate) => candidate.address === answer.address) === index
  ).sort((left, right) => left.address.localeCompare(right.address));
  if (answers.length === 0) throw new Error(`${hostname} did not resolve to a public IPv4 address`);
  return answers;
}

function port(origin: URL): string {
  return origin.port || "443";
}

function directProbePath(runId: string, caseId: CaseId, canary: string): string {
  const query = new URLSearchParams({
    __sbx_run: runId,
    __sbx_test: testId,
    __sbx_case: caseId,
    __sbx_canary: canary,
  });
  return `/v1/probe/${encodeURIComponent(runId)}/direct-b?${query}`;
}

function probeMetadata(runId: string, caseId: string, canary: string): Array<[string, string]> {
  return [
    [caseHeader, caseId],
    [canaryHeader, canary],
    ["x-sbx-forward-run", runId],
  ];
}

function exactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

export function exactForwardPolicy(value: unknown, hostname: string, forwardUrl: string): boolean {
  const policy = record(value);
  const allow = record(policy?.allow);
  if (!policy || !allow || !exactKeys(policy, ["allow"]) || !exactKeys(allow, [hostname])) return false;
  const rules = allow[hostname];
  if (!Array.isArray(rules) || rules.length !== 1) return false;
  const rule = record(rules[0]);
  return rule !== undefined && exactKeys(rule, ["forwardURL"]) && rule.forwardURL === forwardUrl;
}

export function exactSandboxForwardProjection(value: unknown, hostname: string): boolean {
  const policy = record(value);
  return policy !== undefined && exactKeys(policy, ["allow"]) && Array.isArray(policy.allow) &&
    policy.allow.length === 1 && policy.allow[0] === hostname;
}

export function exactAllowHostsPolicy(value: unknown, hostnames: string[]): boolean {
  const policy = record(value);
  if (!policy || !exactKeys(policy, ["allow"]) || !Array.isArray(policy.allow)) return false;
  const actual = policy.allow;
  const expected = new Set(hostnames);
  return expected.size === hostnames.length && actual.length === hostnames.length &&
    actual.every((hostname) => typeof hostname === "string" && expected.has(hostname)) &&
    new Set(actual).size === actual.length;
}

export function attackDefinitions(
  observerA: URL,
  observerB: URL,
  sourcePath: string,
  actionPath: string,
  guestFakeOidc: string,
): CaseDefinition[] {
  const aPort = port(observerA);
  const bPort = port(observerB);
  const uniqueHost = [{ name: "vercel-forwarded-host", value: observerB.host }];
  return [
    {
      caseId: "spoof-host",
      description: "guest sends the real A action suffix while supplying B in vercel-forwarded-host",
      destination: observerA,
      rawPath: actionPath,
      reservedHeaders: [["vercel-forwarded-host", observerB.host]],
      attributionClass: "unique-metadata",
      causalGuestFields: uniqueHost,
    },
    {
      caseId: "spoof-path",
      description: "fail-closed control: guest supplies the action path while the real A path is the source path",
      destination: observerA,
      rawPath: sourcePath,
      reservedHeaders: [["vercel-forwarded-path", actionPath]],
      attributionClass: "oidc-only",
    },
    {
      caseId: "spoof-scheme",
      description: "guest supplies a conflicting forwarded scheme on the real A action suffix",
      destination: observerA,
      rawPath: actionPath,
      reservedHeaders: [["vercel-forwarded-scheme", "http"]],
      attributionClass: "oidc-only",
    },
    {
      caseId: "spoof-port",
      description: "guest supplies B's forwarded port on the real A action suffix",
      destination: observerA,
      rawPath: actionPath,
      reservedHeaders: [["vercel-forwarded-port", bPort]],
      attributionClass: "oidc-only",
    },
    {
      caseId: "spoof-oidc",
      description: "fail-closed control: guest supplies a fake vercel-sandbox-oidc-token",
      destination: observerA,
      rawPath: sourcePath,
      reservedHeaders: [["vercel-sandbox-oidc-token", guestFakeOidc]],
      attributionClass: "oidc-only",
    },
    {
      caseId: "full-forge",
      description: "guest sends the real A action suffix and supplies B authority metadata without overriding path or OIDC",
      destination: observerA,
      rawPath: actionPath,
      reservedHeaders: [
        ["vercel-forwarded-host", observerB.host],
        ["vercel-forwarded-scheme", "https"],
        ["vercel-forwarded-port", bPort],
      ],
      attributionClass: "unique-metadata",
      causalGuestFields: uniqueHost,
    },
    {
      caseId: "duplicate-host-b-a",
      description: "duplicate host fields, B first and A last, on the real A action suffix",
      destination: observerA,
      rawPath: actionPath,
      reservedHeaders: [
        ["Vercel-Forwarded-Host", observerB.host],
        ["vercel-forwarded-host", observerA.host],
      ],
      attributionClass: "duplicate-order-only",
    },
    {
      caseId: "duplicate-host-a-b",
      description: "duplicate host fields, A first and B last, on the real A action suffix",
      destination: observerA,
      rawPath: actionPath,
      reservedHeaders: [
        ["Vercel-Forwarded-Host", observerA.host],
        ["vercel-forwarded-host", observerB.host],
      ],
      attributionClass: "duplicate-order-only",
    },
    {
      caseId: "duplicate-path-action-source",
      description: "fail-closed duplicate path fields, action first and source last",
      destination: observerA,
      rawPath: sourcePath,
      reservedHeaders: [
        ["VERCEL-FORWARDED-PATH", actionPath],
        ["vercel-forwarded-path", sourcePath],
      ],
      attributionClass: "duplicate-order-only",
    },
    {
      caseId: "duplicate-path-source-action",
      description: "fail-closed duplicate path fields, source first and action last",
      destination: observerA,
      rawPath: sourcePath,
      reservedHeaders: [
        ["VERCEL-FORWARDED-PATH", sourcePath],
        ["vercel-forwarded-path", actionPath],
      ],
      attributionClass: "duplicate-order-only",
    },
    {
      caseId: "case-variant-full-forge",
      description: "uppercase B authority metadata on the real A action suffix",
      destination: observerA,
      rawPath: actionPath,
      reservedHeaders: [
        ["VERCEL-FORWARDED-HOST", observerB.host],
        ["VERCEL-FORWARDED-SCHEME", "https"],
        ["VERCEL-FORWARDED-PORT", bPort],
      ],
      attributionClass: "unique-metadata",
      causalGuestFields: uniqueHost,
    },
    {
      caseId: "full-forge-a-port",
      description: "B authority with A's forwarded port on the real A action suffix",
      destination: observerA,
      rawPath: actionPath,
      reservedHeaders: [
        ["vercel-forwarded-host", observerB.host],
        ["vercel-forwarded-scheme", "https"],
        ["vercel-forwarded-port", aPort],
      ],
      attributionClass: "unique-metadata",
      causalGuestFields: uniqueHost,
    },
  ];
}

export function baselineDefinition(observerA: URL, actionPath: string): CaseDefinition {
  return {
    caseId: "baseline-forward",
    description: "same action-suffix request to A must authenticate at B and reconstruct exact A URL",
    destination: observerA,
    rawPath: actionPath,
    reservedHeaders: [],
  };
}

function sanitizeGuestResult(value: unknown): GuestProbeResult | undefined {
  const input = record(value);
  if (!input) return undefined;
  const headerNames = Array.isArray(input.outboundHeaderNames) && input.outboundHeaderNames.length <= 32 &&
      input.outboundHeaderNames.every((name) => typeof name === "string" && safeHeaderNamePattern.test(name))
    ? input.outboundHeaderNames as string[]
    : undefined;
  const operationId = typeof input.operationId === "string" && operationIdPattern.test(input.operationId)
    ? input.operationId
    : undefined;
  return {
    ...(exactBoolean(input.ok) !== undefined ? { ok: exactBoolean(input.ok) } : {}),
    ...(safeText(input.runId, 128) ? { runId: safeText(input.runId, 128) } : {}),
    ...(safeText(input.testId, 128) ? { testId: safeText(input.testId, 128) } : {}),
    ...(safeText(input.caseId, 128) ? { caseId: safeText(input.caseId, 128) } : {}),
    ...(numeric(input.statusCode) !== undefined ? { statusCode: numeric(input.statusCode) } : {}),
    ...(numeric(input.bodyLength) !== undefined ? { bodyLength: numeric(input.bodyLength) } : {}),
    ...(exactBoolean(input.truncated) !== undefined ? { truncated: exactBoolean(input.truncated) } : {}),
    ...(exactBoolean(input.responseJsonValid) !== undefined
      ? { responseJsonValid: exactBoolean(input.responseJsonValid) }
      : {}),
    ...(operationId ? { operationId } : {}),
    ...(exactBoolean(input.authenticated) !== undefined ? { authenticated: exactBoolean(input.authenticated) } : {}),
    ...(exactBoolean(input.actionAuthorized) !== undefined
      ? { actionAuthorized: exactBoolean(input.actionAuthorized) }
      : {}),
    ...(headerNames ? { outboundHeaderNames: headerNames } : {}),
    ...(safeText(input.connectIpUsed, 64) ? { connectIpUsed: safeText(input.connectIpUsed, 64) } : {}),
    ...(exactBoolean(input.tcpConnected) !== undefined
      ? { tcpConnected: exactBoolean(input.tcpConnected) }
      : {}),
    ...(safeText(input.remoteAddress, 64) ? { remoteAddress: safeText(input.remoteAddress, 64) } : {}),
    ...(numeric(input.remotePort) !== undefined ? { remotePort: numeric(input.remotePort) } : {}),
    ...(exactBoolean(input.tlsEstablished) !== undefined
      ? { tlsEstablished: exactBoolean(input.tlsEstablished) }
      : {}),
    ...(exactBoolean(input.responseStarted) !== undefined
      ? { responseStarted: exactBoolean(input.responseStarted) }
      : {}),
    ...(safeText(input.errorPhase, 32) ? { errorPhase: safeText(input.errorPhase, 32) } : {}),
    ...(safeText(input.errorCode, 64) ? { errorCode: safeText(input.errorCode, 64) } : {}),
    ...(numeric(input.errorErrno) !== undefined ? { errorErrno: numeric(input.errorErrno) } : {}),
    ...(safeText(input.errorSyscall, 64) ? { errorSyscall: safeText(input.errorSyscall, 64) } : {}),
    ...(numeric(input.durationMs) !== undefined ? { durationMs: numeric(input.durationMs) } : {}),
  } as GuestProbeResult;
}

function sanitizeRawHeaderAudit(value: unknown): ProxyRawHeaderAudit | undefined {
  const input = record(value);
  if (!input || !Array.isArray(input.forwardedFields) || input.forwardedFields.length > 32) return undefined;
  const forwardedFields = input.forwardedFields.map((value) => {
    const field = record(value);
    if (!field) return undefined;
    const position = numeric(field.position);
    const name = safeText(field.name, 128);
    const headerValue = safeText(field.value, 2_048);
    if (position === undefined || !Number.isInteger(position) || !name || !headerValue) return undefined;
    return { position, name: name.toLowerCase(), value: headerValue };
  });
  if (forwardedFields.some((field) => field === undefined)) return undefined;
  const caseId = safeText(input.caseId, 128);
  const caseHeaderCount = numeric(input.caseHeaderCount);
  const oidcHeaderCount = numeric(input.oidcHeaderCount);
  const oidcValueCount = numeric(input.oidcValueCount);
  if (!caseId || caseHeaderCount === undefined || oidcHeaderCount === undefined || oidcValueCount === undefined) {
    return undefined;
  }
  return {
    caseId,
    caseHeaderCount,
    caseIdMatched: input.caseIdMatched === true,
    oidcHeaderCount,
    oidcValueCount,
    guestFakeOidcObserved: input.guestFakeOidcObserved === true,
    intermediaryOrderTrusted: input.intermediaryOrderTrusted === true,
    forwardedFields: forwardedFields as ProxyRawHeaderAudit["forwardedFields"],
  } as ProxyRawHeaderAudit;
}

function sanitizeProxyRecord(value: unknown): ProxyAuthenticationRecord | undefined {
  const input = record(value);
  if (!input) return undefined;
  const operationId = typeof input.operationId === "string" && operationIdPattern.test(input.operationId)
    ? input.operationId
    : undefined;
  const caseId = safeText(input.caseId, 128);
  const rawHeaderAudit = sanitizeRawHeaderAudit(input.rawHeaderAudit);
  if (!operationId || !caseId || !rawHeaderAudit) return undefined;
  const proxyMeta = record(input.proxyMeta);
  const identity = proxyMeta && ["host", "teamId", "projectId", "sandboxId", "sandboxName"].every(
      (key) => typeof proxyMeta[key] === "string",
    )
    ? {
        host: safeText(proxyMeta.host, 256)!,
        teamId: safeText(proxyMeta.teamId, 128)!,
        projectId: safeText(proxyMeta.projectId, 128)!,
        sandboxId: safeText(proxyMeta.sandboxId, 128)!,
        sandboxName: safeText(proxyMeta.sandboxName, 256)!,
      }
    : undefined;
  return {
    operationId,
    caseId,
    authenticated: input.authenticated === true,
    actionAuthorized: input.actionAuthorized === true,
    ...(safeText(input.reconstructedUrl, 2_048)
      ? { reconstructedUrl: safeText(input.reconstructedUrl, 2_048) }
      : {}),
    ...(identity ? { proxyMeta: identity } : {}),
    ...(safeText(input.invalidReasonCode, 64)
      ? { invalidReasonCode: safeText(input.invalidReasonCode, 64) }
      : {}),
    rawHeaderAudit,
  } as ProxyAuthenticationRecord;
}

async function observerAdminRequest(
  origin: URL,
  adminKey: string,
  runId: string,
  resource: "proxy-config" | "proxy-actions",
  init?: RequestInit,
): Promise<Response> {
  const headers = new Headers(init?.headers);
  headers.set("authorization", `Bearer ${adminKey}`);
  return fetch(new URL(`/v1/runs/${encodeURIComponent(runId)}/${resource}`, origin), {
    ...init,
    headers,
    signal: controlSignal(10_000),
  });
}

async function proxyRecords(origin: URL, adminKey: string, runId: string): Promise<ProxyAuthenticationRecord[]> {
  const response = await observerAdminRequest(origin, adminKey, runId, "proxy-actions");
  if (!response.ok) throw new Error(`observer proxy action query returned ${response.status}`);
  const body = await response.json() as { records?: unknown[] };
  if (!Array.isArray(body.records)) throw new Error("observer returned invalid proxy records");
  const sanitized = body.records.map(sanitizeProxyRecord);
  if (sanitized.some((entry) => entry === undefined)) throw new Error("observer returned an unsafe proxy record");
  return sanitized as ProxyAuthenticationRecord[];
}

async function proxyConfigReadback(
  origin: URL,
  adminKey: string,
  runId: string,
): Promise<{ configured: boolean; actionUrl?: string }> {
  const response = await observerAdminRequest(origin, adminKey, runId, "proxy-config");
  if (!response.ok) throw new Error(`observer proxy config query returned ${response.status}`);
  const body = await response.json() as { configured?: unknown; actionUrl?: unknown };
  return {
    configured: body.configured === true,
    ...(typeof body.actionUrl === "string" ? { actionUrl: body.actionUrl } : {}),
  };
}

function headerPlan(headers: Array<[string, string]>): GuestCaseRecord["headerPlan"] {
  return headers.map(([name, value]) =>
    name.toLowerCase() === "vercel-sandbox-oidc-token"
      ? { name, valueSha256: sha256(value) }
      : { name, value }
  );
}

function exactEventCount(
  events: ObserverEvent[],
  runId: string,
  caseId: string,
  canary: string,
): number {
  return events.filter((event) =>
    event.runId === runId && event.testId === testId && event.caseId === caseId && event.canary === canary
  ).length;
}

export function conclusiveDirectBReachability(
  result: GuestProbeResult | undefined,
  pinnedIPv4: string,
  expectedPort: number,
  exactObserverEvent: boolean,
  recordCount: number,
  commandExitCode: number | undefined,
): boolean {
  return commandExitCode === 0 && result?.ok === true && result.connectIpUsed === pinnedIPv4 &&
    result.tcpConnected === true &&
    result.remoteAddress === pinnedIPv4 && result.remotePort === expectedPort && result.tlsEstablished === true &&
    result.responseStarted === true && result.statusCode === 204 && result.bodyLength === 0 &&
    result.responseJsonValid === false && exactObserverEvent && recordCount === 0;
}

export function conclusiveDirectBReset(
  result: GuestProbeResult | undefined,
  pinnedIPv4: string,
  expectedPort: number,
  observerEventCount: number,
  recordCount: number,
  commandExitCode: number | undefined,
): boolean {
  const permittedErrno = result?.errorErrno === undefined || result.errorErrno === -104;
  const permittedSyscall = result?.errorSyscall === undefined ||
    result.errorSyscall === "connect" || result.errorSyscall === "read";
  return commandExitCode === 0 && result?.ok === false && result.connectIpUsed === pinnedIPv4 &&
    result.tcpConnected === true &&
    result.remoteAddress === pinnedIPv4 && result.remotePort === expectedPort && result.errorPhase === "connect" &&
    result.errorCode === "ECONNRESET" && typeof result.durationMs === "number" && result.durationMs >= 0 &&
    result.durationMs <= maximumConclusiveResetDurationMs && permittedErrno && permittedSyscall &&
    result.tlsEstablished === false && result.responseStarted === false && result.statusCode === undefined &&
    observerEventCount === 0 && recordCount === 0;
}

function toAssessment(
  guestRecord: GuestCaseRecord | undefined,
  events: ObserverEvent[],
  records: ProxyAuthenticationRecord[],
  runId: string,
  canary: string,
  definition?: CaseDefinition,
): GuestCaseAssessment {
  const caseId = definition?.caseId ?? guestRecord?.caseId ?? "missing";
  const caseRecords = records.filter((entry) => entry.caseId === caseId);
  const caseEvents = events.filter((event) =>
    event.runId === runId && event.testId === testId && event.caseId === caseId
  );
  const observerEventCount = exactEventCount(caseEvents, runId, caseId, canary);
  const result = guestRecord?.result;
  const resultIdentityValid = result?.runId === runId && result.testId === testId && result.caseId === caseId;
  const expectedPort = Number(port(definition?.destination ?? new URL("https://invalid.example")));
  const expectedPath = definition ? new URL(definition.rawPath, definition.destination).pathname : undefined;
  const exactDirectObserverEvent = definition !== undefined && caseEvents.length === 1 &&
    caseEvents[0]?.canary === canary && caseEvents[0].method === "GET" &&
    caseEvents[0].rawUrl === definition.rawPath && caseEvents[0].normalizedPath === expectedPath &&
    caseEvents[0].host === definition.destination.host && caseEvents[0].bodyLength === 0;
  const rawAttackEvidenceValid = definition?.attributionClass === "unique-metadata" &&
    definition.causalGuestFields !== undefined && caseRecords.some((entry) =>
      rawAuditContainsUniqueValues(entry.rawHeaderAudit, caseId, definition.causalGuestFields!)
    );
  return {
    caseId,
    guestOk: result?.ok === true,
    ...(result?.statusCode !== undefined ? { statusCode: result.statusCode } : {}),
    ...(result?.operationId ? { responseOperationId: result.operationId } : {}),
    ...(result?.authenticated !== undefined ? { responseAuthenticated: result.authenticated } : {}),
    ...(result?.actionAuthorized !== undefined ? { responseActionAuthorized: result.actionAuthorized } : {}),
    observerEventCount,
    records: caseRecords,
    ...(definition?.connectIp && definition.directControl === "allow-positive"
      ? {
          conclusiveDirectReachability: resultIdentityValid && conclusiveDirectBReachability(
            result,
            definition.connectIp,
            expectedPort,
            exactDirectObserverEvent,
            caseRecords.length,
            guestRecord?.command.exitCode,
          ),
        }
      : {}),
    ...(definition?.connectIp && definition.directControl === "deny-reset"
      ? {
          conclusiveFirewallBlock: resultIdentityValid && conclusiveDirectBReset(
            result,
            definition.connectIp,
            expectedPort,
            caseEvents.length,
            caseRecords.length,
            guestRecord?.command.exitCode,
          ),
        }
      : {}),
    ...(definition?.attributionClass ? { attackAttributionClass: definition.attributionClass } : {}),
    ...(definition?.attributionClass ? { rawAttackEvidenceValid } : {}),
  };
}

function baselineAuditValid(
  assessment: GuestCaseAssessment,
  observerA: URL,
  sourcePath: string,
): boolean {
  if (assessment.records.length !== 1) return false;
  const audit = assessment.records[0]?.rawHeaderAudit;
  if (
    !audit || audit.caseId !== "baseline-forward" || audit.caseHeaderCount !== 1 || !audit.caseIdMatched ||
    audit.oidcHeaderCount !== 1 || audit.oidcValueCount !== 1 || audit.guestFakeOidcObserved
  ) {
    return false;
  }
  const expected = new Map([
    ["vercel-forwarded-host", observerA.host],
    ["vercel-forwarded-scheme", "https"],
    ["vercel-forwarded-port", port(observerA)],
    ["vercel-forwarded-path", sourcePath],
  ]);
  return audit.forwardedFields.length === expected.size && [...expected].every(([name, value]) =>
    audit.forwardedFields.filter((field) => field.name === name && field.value === value).length === 1
  );
}

async function captureCommand(
  sandbox: Sandbox,
  configuration: string,
  argumentSecrets: string[],
  outputSecrets: string[],
): Promise<{ command: CommandRecord; result?: GuestProbeResult }> {
  const encoded = Buffer.from(configuration).toString("base64url");
  if (argumentSecrets.some((secret) => secret && encoded.includes(secret))) {
    throw new Error("guest command arguments contain controller-only material");
  }
  const command = await sandbox.runCommand({
    cmd: "node",
    args: [remoteProbePath, encoded],
    timeoutMs: 15_000,
    signal: controlSignal(30_000),
  });
  const outputSignal = controlSignal();
  const [stdout, stderr] = await Promise.all([
    command.stdout({ signal: outputSignal }),
    command.stderr({ signal: outputSignal }),
  ]);
  if (Buffer.byteLength(stdout) > 64_000 || Buffer.byteLength(stderr) > 16_000) {
    throw new Error("guest command output exceeded the fixed evidence bound");
  }
  if (outputSecrets.some((secret) => secret && (stdout.includes(secret) || stderr.includes(secret)))) {
    throw new Error("guest command output contained controller-only material");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error("guest probe did not emit valid structured JSON");
  }
  const sanitizedResult = sanitizeGuestResult(parsed);
  return {
    command: {
      commandId: command.cmdId,
      exitCode: command.exitCode,
      ...(command.durationMs !== undefined ? { durationMs: command.durationMs } : {}),
      stdoutByteLength: Buffer.byteLength(stdout),
      stdoutSha256: sha256(stdout),
      stderrByteLength: Buffer.byteLength(stderr),
      stderrSha256: sha256(stderr),
    },
    ...(sanitizedResult ? { result: sanitizedResult } : {}),
  };
}

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  const { observerA, observerB } = controlledOrigins();
  const observerAdminKey = required(process.env, "OBSERVER_ADMIN_KEY");
  const credentials = explicitCredentials();
  const verifiedAlias = await verifyAliasIdentity(credentials.token);
  const controllerOnlySecrets = [observerAdminKey, credentials.token];
  const clients = [
    new HttpObserverClient(observerA.origin, observerAdminKey),
    new HttpObserverClient(observerB.origin, observerAdminKey),
  ];
  await Promise.all(clients.map((client) => client.health()));
  const ownershipProofRunId = `ownership-${randomUUID()}`;
  const ownershipResults = await Promise.all(clients.map((client) => client.events(ownershipProofRunId)));
  const endpointOwnershipProofPassed = ownershipResults.every((events) => events.length === 0);
  if (!endpointOwnershipProofPassed) throw new Error("admin-authenticated ownership proof was not empty on both hard-pinned origins");

  const dnsStartedAt = new Date().toISOString();
  const [observerAAnswers, observerBAnswers] = await Promise.all([
    resolvePublicIPv4(observerA.hostname),
    resolvePublicIPv4(observerB.hostname),
  ]);
  const dnsCompletedAt = new Date().toISOString();
  const pinnedBIPv4 = observerBAnswers[0]!.address;
  const runId = randomUUID();
  const sandboxName = `sbx-023-poc-${runId.replaceAll("-", "")}`;
  const sandboxTags = { harness: "vsc", test: "SBX-023", run: runId };
  const correlationCanary = `corr_${randomBytes(18).toString("base64url")}`;
  const guestFakeOidc = `guest_fake_oidc_${randomBytes(18).toString("base64url")}`;
  const evidenceSecrets = [...controllerOnlySecrets, guestFakeOidc];
  const sourcePath = `/v1/probe/${encodeURIComponent(runId)}/forward-source`;
  const actionPath = `/v1/probe/${encodeURIComponent(runId)}/forwarded-action`;
  const expectedBaselineUrl = new URL(actionPath, observerA).toString();
  const expectedActionUrl = new URL(actionPath, observerB).toString();
  const forwardUrl = new URL(`/v1/proxy/${encodeURIComponent(runId)}/forward`, observerB).toString();
  const initialPolicy = {
    allow: [observerA.hostname, observerB.hostname],
  } satisfies NetworkPolicy;
  const finalPolicy = {
    allow: { [observerA.hostname]: [{ forwardURL: forwardUrl }] },
  } satisfies NetworkPolicy;
  const attacks = attackDefinitions(observerA, observerB, sourcePath, actionPath, guestFakeOidc);
  const positiveDirect: CaseDefinition = {
    caseId: "direct-b-allow-control",
    description: "temporary explicit A+B policy must reach exact pinned B IPv4 over TCP, TLS, and HTTP",
    destination: observerB,
    rawPath: directProbePath(runId, "direct-b-allow-control", correlationCanary),
    reservedHeaders: [],
    connectIp: pinnedBIPv4,
    directControl: "allow-positive",
  };
  const preDirect: CaseDefinition = {
    caseId: "direct-b-pre-negative",
    description: "same pinned B IPv4 must reset after TCP but before TLS under the final A-forward policy",
    destination: observerB,
    rawPath: directProbePath(runId, "direct-b-pre-negative", correlationCanary),
    reservedHeaders: [],
    connectIp: pinnedBIPv4,
    directControl: "deny-reset",
  };
  const baseline = baselineDefinition(observerA, actionPath);
  const postDirect: CaseDefinition = {
    caseId: "direct-b-post-negative",
    description: "same pinned B IPv4 must still reset after TCP but before TLS under the final A-forward policy",
    destination: observerB,
    rawPath: directProbePath(runId, "direct-b-post-negative", correlationCanary),
    reservedHeaders: [],
    connectIp: pinnedBIPv4,
    directControl: "deny-reset",
  };
  const plannedCases = [positiveDirect, preDirect, baseline, ...attacks, postDirect];
  if (plannedCases.length !== maximumEndpointRequests) throw new Error("fixed SBX-023 request matrix changed unexpectedly");

  const cleanup = {
    orphanRecoveryAttempted: false,
    recoveredHandle: false,
    orphanAbsenceConfirmed: false,
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    deletionAbsenceCheckAttempted: false,
    deletionAbsenceConfirmed: false,
    observerProxyDeleteAttempted: false,
    observerProxyDeleted: false,
    observerProxyAbsenceConfirmed: false,
    errors: [] as string[],
  };
  const guestCases: GuestCaseRecord[] = [];
  const policyProofs: PolicyProof[] = [];
  let endpointRequestAttempts = 0;
  let sandbox: Sandbox | undefined;
  let createAttempted = false;
  let observerConfigAttempted = false;
  let initialSessionId: string | undefined;
  let sandboxIdentity: (ProxyIdentity & {
    sessionCreatedAt: string;
    sessionRequestedAt: string;
    region: string;
  }) | undefined;
  let observerEvents: ObserverEvent[] = [];
  let proxyActionRecords: ProxyAuthenticationRecord[] = [];
  let executionError: string | undefined;
  let finalPolicyUpdateAcknowledged = false;
  let finalPolicyUpdateStartedAt: string | undefined;
  let finalPolicyUpdateCompletedAt: string | undefined;

  async function policyProof(stage: PolicyProof["stage"]): Promise<PolicyProof> {
    if (!sandbox || !initialSessionId) throw new Error(`${stage} policy proof has no active sandbox`);
    const activeSession = sandbox.currentSession();
    const independent = await Sandbox.get({
      name: sandboxName,
      resume: false,
      signal: controlSignal(),
      ...credentials,
    });
    const independentSession = independent.currentSession();
    const initialStage = stage === "initial-allow";
    const sandboxProjectionPassed = initialStage
      ? exactAllowHostsPolicy(sandbox.networkPolicy, initialPolicy.allow) &&
        exactAllowHostsPolicy(independent.networkPolicy, initialPolicy.allow)
      : exactSandboxForwardProjection(sandbox.networkPolicy, observerA.hostname) &&
        exactSandboxForwardProjection(independent.networkPolicy, observerA.hostname);
    const fullSessionPolicyPassed = initialStage
      ? exactAllowHostsPolicy(activeSession.networkPolicy, initialPolicy.allow) &&
        exactAllowHostsPolicy(independentSession.networkPolicy, initialPolicy.allow)
      : exactForwardPolicy(activeSession.networkPolicy, observerA.hostname, forwardUrl) &&
        exactForwardPolicy(independentSession.networkPolicy, observerA.hostname, forwardUrl);
    const sameSessionPassed = activeSession.sessionId === initialSessionId &&
      independentSession.sessionId === initialSessionId;
    return {
      stage,
      activeSandboxPolicy: sandbox.networkPolicy,
      activeSessionPolicy: activeSession.networkPolicy,
      independentSandboxPolicy: independent.networkPolicy,
      independentSessionPolicy: independentSession.networkPolicy,
      initialSessionId,
      activeSessionId: activeSession.sessionId,
      independentSessionId: independentSession.sessionId,
      sandboxProjectionPassed,
      fullSessionPolicyPassed,
      sameSessionPassed,
      passed: sandboxProjectionPassed && fullSessionPolicyPassed && sameSessionPassed,
    };
  }

  async function runCase(definition: CaseDefinition): Promise<GuestCaseRecord> {
    if (!sandbox) throw new Error("sandbox is not available");
    if (endpointRequestAttempts >= maximumEndpointRequests) throw new Error("fixed endpoint request bound exhausted");
    const rawHeaders = [
      ...probeMetadata(runId, definition.caseId, correlationCanary),
      ...definition.reservedHeaders,
    ];
    const configuration = {
      scopeConfirmation: "researcher-controlled-endpoints-only",
      researcherControlledHosts: [observerA.hostname, observerB.hostname],
      researcherControlledIpv4s: observerBAnswers.map((answer) => answer.address),
      baseUrl: definition.destination.origin,
      runId,
      testId,
      caseId: definition.caseId,
      rawPath: definition.rawPath,
      rawHeaders,
      ...(definition.connectIp ? { connectIp: definition.connectIp } : {}),
      timeoutMs: 8_000,
    };
    const serialized = JSON.stringify(configuration);
    if (controllerOnlySecrets.some((secret) => secret && serialized.includes(secret))) {
      throw new Error(`${definition.caseId} guest configuration contains controller-only material`);
    }
    endpointRequestAttempts += 1;
    const captured = await captureCommand(sandbox, serialized, controllerOnlySecrets, evidenceSecrets);
    const result: GuestCaseRecord = {
      caseId: definition.caseId,
      description: definition.description,
      command: captured.command,
      configurationSha256: sha256(serialized),
      headerPlan: headerPlan(rawHeaders),
      ...(captured.result ? { result: captured.result } : {}),
    };
    guestCases.push(result);
    await delay(minimumInterRequestDelayMs, undefined, { signal: controlSignal(2_000) });
    return result;
  }

  try {
    observerConfigAttempted = true;
    const registration = await observerAdminRequest(observerB, observerAdminKey, runId, "proxy-config", {
      method: "POST",
      headers: {
        "x-observer-proxy-action-url": expectedActionUrl,
        "x-observer-proxy-fake-oidc-sha256": sha256(guestFakeOidc),
      },
    });
    if (registration.status !== 201) throw new Error(`observer proxy registration returned ${registration.status}`);
    const registered = await proxyConfigReadback(observerB, observerAdminKey, runId);
    if (!registered.configured || registered.actionUrl !== expectedActionUrl) {
      throw new Error("observer proxy configuration did not read back exactly");
    }

    createAttempted = true;
    sandbox = await Sandbox.create({
      name: sandboxName,
      persistent: false,
      timeout: 480_000,
      resources: { vcpus: 2 },
      networkPolicy: initialPolicy,
      tags: sandboxTags,
      signal: controlSignal(),
      ...credentials,
    });
    const session = sandbox.currentSession();
    initialSessionId = session.sessionId;
    if (
      sandbox.name !== sandboxName || sandbox.tags?.harness !== sandboxTags.harness ||
      sandbox.tags?.test !== sandboxTags.test || sandbox.tags?.run !== sandboxTags.run
    ) {
      throw new Error("created sandbox identity did not match exact name and tags");
    }
    sandboxIdentity = {
      host: observerB.host,
      teamId: eligibleTeamId,
      projectId: eligibleProjectId,
      sandboxId: session.sessionId,
      sandboxName: sandbox.name,
      sessionCreatedAt: session.createdAt.toISOString(),
      sessionRequestedAt: session.requestedAt.toISOString(),
      region: session.region,
    };
    policyProofs.push(await policyProof("initial-allow"));

    const probeSource = await readFile(resolve("guest/forwarded-header-probe.mjs"), "utf8");
    if (controllerOnlySecrets.some((secret) => secret && probeSource.includes(secret))) {
      throw new Error("guest probe source contains controller-only material");
    }
    await sandbox.writeFiles([{ path: remoteProbePath, content: probeSource, mode: 0o700 }], {
      signal: controlSignal(),
    });

    if (policyProofs[0]?.passed) {
      const positive = await runCase(positiveDirect);
      await delay(500, undefined, { signal: controlSignal(2_000) });
      const [positiveEvents, positiveRecords] = await Promise.all([
        clients[1]!.events(runId),
        proxyRecords(observerB, observerAdminKey, runId),
      ]);
      const positiveAssessment = toAssessment(
        positive,
        positiveEvents,
        positiveRecords,
        runId,
        correlationCanary,
        positiveDirect,
      );
      if (positiveAssessment.conclusiveDirectReachability) {
        finalPolicyUpdateStartedAt = new Date().toISOString();
        await sandbox.update({ networkPolicy: finalPolicy }, { signal: controlSignal() });
        finalPolicyUpdateCompletedAt = new Date().toISOString();
        finalPolicyUpdateAcknowledged = sandbox.currentSession().sessionId === initialSessionId;
        await delay(policySettleDelayMs, undefined, { signal: controlSignal(policySettleDelayMs + 1_000) });
        policyProofs.push(await policyProof("pre-attack"));

        if (policyProofs.find((proof) => proof.stage === "pre-attack")?.passed) {
          const pre = await runCase(preDirect);
          await delay(500, undefined, { signal: controlSignal(2_000) });
          const [preEvents, preRecords] = await Promise.all([
            clients[1]!.events(runId),
            proxyRecords(observerB, observerAdminKey, runId),
          ]);
          const preAssessment = toAssessment(pre, preEvents, preRecords, runId, correlationCanary, preDirect);
          if (preAssessment.conclusiveFirewallBlock) {
            const baselineRecord = await runCase(baseline);
            await delay(500, undefined, { signal: controlSignal(2_000) });
            const [baselineEvents, baselineRecords] = await Promise.all([
              clients[1]!.events(runId),
              proxyRecords(observerB, observerAdminKey, runId),
            ]);
            const baselineAssessment = toAssessment(
              baselineRecord,
              baselineEvents,
              baselineRecords,
              runId,
              correlationCanary,
              baseline,
            );
            if (
              baselineAssessment.guestOk && baselineAssessment.statusCode === 202 &&
              baselineAssessment.records.some((entry) => entry.authenticated && !entry.actionAuthorized)
            ) {
              for (const definition of attacks) {
                await runCase(definition);
                const earlyRecords = await proxyRecords(observerB, observerAdminKey, runId);
                if (earlyRecords.some((entry) => entry.caseId === definition.caseId && entry.actionAuthorized)) break;
              }
            }
          }
        }
      }
    }

    if (finalPolicyUpdateAcknowledged) {
      policyProofs.push(await policyProof("post-attack"));
      await runCase(postDirect);
      await delay(1_000, undefined, { signal: controlSignal(3_000) });
    }
    [observerEvents, proxyActionRecords] = await Promise.all([
      clients[1]!.events(runId),
      proxyRecords(observerB, observerAdminKey, runId),
    ]);
  } catch (error) {
    executionError = safeError(error, evidenceSecrets);
  } finally {
    if (!sandbox && createAttempted) {
      cleanup.orphanRecoveryAttempted = true;
      let notFoundCount = 0;
      for (let attempt = 0; attempt < 3 && !sandbox; attempt += 1) {
        if (attempt > 0) await delay(1_000, undefined, { signal: controlSignal(3_000) });
        try {
          const recovered = await Sandbox.get({
            name: sandboxName,
            resume: false,
            signal: controlSignal(),
            ...credentials,
          });
          if (!recoverableSandboxIdentity({
            createdAtMs: recovered.createdAt.getTime(),
            startedAtMs: Date.parse(startedAt),
            nowMs: Date.now(),
            tags: recovered.tags,
            expectedTags: sandboxTags,
          })) {
            cleanup.errors.push("orphan recovery found a sandbox without the exact run identity; left untouched");
            break;
          }
          sandbox = recovered;
          cleanup.recoveredHandle = true;
        } catch (error) {
          if (isNotFound(error)) notFoundCount += 1;
          else {
            cleanup.errors.push(`orphan recovery: ${safeError(error, evidenceSecrets)}`);
            break;
          }
        }
      }
      cleanup.orphanAbsenceConfirmed = !sandbox && notFoundCount === 3;
      if (!sandbox && !cleanup.orphanAbsenceConfirmed && cleanup.errors.length === 0) {
        cleanup.errors.push("ambiguous create did not yield three independent absence confirmations");
      }
    }
    if (sandbox) {
      cleanup.stopAttempted = true;
      try {
        await sandbox.stop({ signal: controlSignal() });
        cleanup.stopped = true;
      } catch (error) {
        cleanup.errors.push(`stop: ${safeError(error, evidenceSecrets)}`);
      }
      cleanup.deleteAttempted = true;
      try {
        await sandbox.delete({ signal: controlSignal() });
        cleanup.deleted = true;
      } catch (error) {
        cleanup.errors.push(`delete: ${safeError(error, evidenceSecrets)}`);
      }
      if (cleanup.deleted) {
        cleanup.deletionAbsenceCheckAttempted = true;
        let notFoundCount = 0;
        for (let attempt = 0; attempt < 3; attempt += 1) {
          if (attempt > 0) await delay(1_000, undefined, { signal: controlSignal(3_000) });
          try {
            await Sandbox.get({
              name: sandboxName,
              resume: false,
              signal: controlSignal(),
              ...credentials,
            });
          } catch (error) {
            if (isNotFound(error)) notFoundCount += 1;
            else {
              cleanup.errors.push(`deletion absence check: ${safeError(error, evidenceSecrets)}`);
              break;
            }
          }
        }
        cleanup.deletionAbsenceConfirmed = notFoundCount === 3;
        if (!cleanup.deletionAbsenceConfirmed && cleanup.errors.length === 0) {
          cleanup.errors.push("deleted sandbox remained discoverable during independent absence checks");
        }
      }
    }
    if (observerConfigAttempted) {
      cleanup.observerProxyDeleteAttempted = true;
      try {
        const deletion = await observerAdminRequest(observerB, observerAdminKey, runId, "proxy-config", {
          method: "DELETE",
        });
        cleanup.observerProxyDeleted = deletion.status === 204;
        const readback = await proxyConfigReadback(observerB, observerAdminKey, runId);
        cleanup.observerProxyAbsenceConfirmed = !readback.configured;
        if (!cleanup.observerProxyDeleted || !cleanup.observerProxyAbsenceConfirmed) {
          cleanup.errors.push("observer proxy configuration deletion did not read back absent");
        }
      } catch (error) {
        cleanup.errors.push(`observer proxy delete: ${safeError(error, evidenceSecrets)}`);
      }
    }
  }

  const recordFor = (caseId: CaseId): GuestCaseRecord | undefined =>
    guestCases.find((entry) => entry.caseId === caseId);
  const positiveDirectAssessment = toAssessment(
    recordFor(positiveDirect.caseId),
    observerEvents,
    proxyActionRecords,
    runId,
    correlationCanary,
    positiveDirect,
  );
  const preDirectAssessment = toAssessment(
    recordFor(preDirect.caseId),
    observerEvents,
    proxyActionRecords,
    runId,
    correlationCanary,
    preDirect,
  );
  const postDirectAssessment = toAssessment(
    recordFor(postDirect.caseId),
    observerEvents,
    proxyActionRecords,
    runId,
    correlationCanary,
    postDirect,
  );
  const baselineAssessment = toAssessment(
    recordFor(baseline.caseId),
    observerEvents,
    proxyActionRecords,
    runId,
    correlationCanary,
    baseline,
  );
  const attackAssessments = attacks
    .filter((definition) => recordFor(definition.caseId) !== undefined)
    .map((definition) => toAssessment(
      recordFor(definition.caseId),
      observerEvents,
      proxyActionRecords,
      runId,
      correlationCanary,
      definition,
    ));
  const baselineEvent = observerEvents.find((event) =>
    event.runId === runId && event.testId === testId && event.caseId === baseline.caseId &&
    event.canary === correlationCanary
  );
  const baselineRawMetadataValid = baselineAuditValid(baselineAssessment, observerA, actionPath) &&
    baselineEvent?.headers["vercel-forwarded-host"] === observerA.host &&
    baselineEvent.headers["vercel-forwarded-scheme"] === "https" &&
    baselineEvent.headers["vercel-forwarded-port"] === port(observerA) &&
    baselineEvent.headers["vercel-forwarded-path"] === actionPath;
  const expectedIdentity: ProxyIdentity = sandboxIdentity ?? {
    host: observerB.host,
    teamId: eligibleTeamId,
    projectId: eligibleProjectId,
    sandboxId: "missing",
    sandboxName: "missing",
  };
  const initialPolicyProofPassed = policyProofs.find((proof) => proof.stage === "initial-allow")?.passed === true;
  const prePolicyProofPassed = policyProofs.find((proof) => proof.stage === "pre-attack")?.passed === true;
  const postPolicyProofPassed = policyProofs.find((proof) => proof.stage === "post-attack")?.passed === true;
  const allAttacksExecuted = attacks.every((definition) => recordFor(definition.caseId) !== undefined);
  const assessment = assessSbx023({
    ...(executionError ? { executionError } : {}),
    cleanupErrors: cleanup.errors,
    initialPolicyProofPassed,
    finalPolicyUpdateAcknowledged,
    prePolicyProofPassed,
    postPolicyProofPassed,
    positiveDirectB: positiveDirectAssessment,
    preDirectB: preDirectAssessment,
    postDirectB: postDirectAssessment,
    baseline: baselineAssessment,
    attacks: attackAssessments,
    allAttacksExecuted,
    baselineRawMetadataValid,
    expectedBaselineUrl,
    expectedActionUrl,
    expectedIdentity,
  });
  const evidence = {
    schemaVersion: 3,
    visibility: "private",
    testId: "SBX-023",
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    scope: "one exact eligible Vercel account/project, one owned sandbox, and two exact owned Quick Tunnel origins",
    runtime: {
      sandboxSdk: "@vercel/sandbox@3.0.0",
      controllerNode: process.version,
      proxyAuthentication: "official @vercel/sandbox defineSandboxProxy helper",
    },
    credentialContext: {
      mode: verifiedAlias.method,
      email: verifiedAlias.email,
      teamId: credentials.teamId,
      projectId: credentials.projectId,
    },
    endpointOwnership: {
      scopeConfirmation,
      adminAuthenticatedOnBothOrigins: endpointOwnershipProofPassed,
      observerAOrigin: observerA.origin,
      observerBOrigin: observerB.origin,
      hardPinned: true,
      intermediary: "Cloudflare Quick Tunnel; duplicate header order is not independently trusted",
      dns: {
        startedAt: dnsStartedAt,
        completedAt: dnsCompletedAt,
        observerAAnswers,
        observerBAnswers,
        pinnedBIPv4,
      },
    },
    requestBounds: {
      endpointRequestAttempts,
      retainedProbeResults: guestCases.length,
      maximumEndpointRequests,
      sequential: true,
      retryCount: 0,
      redirectsAllowed: false,
      minimumInterRequestDelayMs,
      maximumRequestRatePerSecond: 1_000 / minimumInterRequestDelayMs,
    },
    sandbox: sandboxIdentity,
    policy: {
      initialConfigured: initialPolicy,
      finalConfigured: finalPolicy,
      forwardUrl,
      transition: {
        updateStartedAt: finalPolicyUpdateStartedAt,
        updateCompletedAt: finalPolicyUpdateCompletedAt,
        acknowledgedOnOriginalSession: finalPolicyUpdateAcknowledged,
        settleDelayMs: policySettleDelayMs,
      },
      proofs: policyProofs,
    },
    expectedBaselineUrl,
    expectedActionUrl,
    guestMaterialGuards: {
      observerAdminKeyEnteredGuestSourceConfigurationArgumentsOrOutput: false,
      vercelCredentialEnteredGuestSourceConfigurationArgumentsOrOutput: false,
      rawGuestFakeOidcRetained: false,
      guestFakeOidcSha256: sha256(guestFakeOidc),
      platformOidcTokenRetrievedOrStored: false,
      rawHttpResponseRetained: false,
      structuredResponseFieldsRetainedOnly: true,
      serializedSecretGuardPassed: true,
    },
    correlationCanarySha256: sha256(correlationCanary),
    baselineRawMetadataValid,
    casesPlanned: plannedCases.map((entry) => ({
      caseId: entry.caseId,
      description: entry.description,
      attributionClass: entry.attributionClass,
    })),
    guestCases,
    observerEvents,
    proxyAuthenticationRecords: proxyActionRecords,
    controls: {
      initialPolicyProofPassed,
      finalPolicyUpdateAcknowledged,
      prePolicyProofPassed,
      postPolicyProofPassed,
      directBReachabilityConclusive: positiveDirectAssessment.conclusiveDirectReachability === true,
      preDirectBConclusive: preDirectAssessment.conclusiveFirewallBlock === true,
      postDirectBConclusive: postDirectAssessment.conclusiveFirewallBlock === true,
      allAttacksExecuted,
    },
    assessment,
    cleanup,
    ...(executionError ? { executionError } : {}),
  };
  const serializedEvidence = `${JSON.stringify(evidence, null, 2)}\n`;
  if (evidenceSecrets.some((secret) => secret && serializedEvidence.includes(secret))) {
    throw new Error("refusing to write SBX-023 evidence containing controller-only material");
  }
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const artifactPath = resolve(artifactsDirectory, `SBX-023-${runId}-private.json`);
  await writeFile(artifactPath, serializedEvidence, { encoding: "utf8", mode: 0o600, flag: "wx" });
  process.stdout.write(`${JSON.stringify({
    testId: "SBX-023",
    runId,
    verdict: assessment.verdict,
    candidate: assessment.candidate,
    controlsPassed: assessment.controlsPassed,
    summary: assessment.summary,
    endpointRequestAttempts,
    sandbox: sandboxIdentity,
    candidateCaseId: assessment.candidateCaseId,
    candidateOperationId: assessment.candidateOperationId,
    artifactPath,
    cleanup,
    ...(executionError ? { executionError } : {}),
  }, null, 2)}\n`);
  process.exitCode = exitCodeForVerdict(assessment.verdict);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
