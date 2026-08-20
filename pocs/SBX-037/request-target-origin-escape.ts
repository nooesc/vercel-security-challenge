import "dotenv/config";

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Resolver } from "node:dns/promises";
import { mkdir, open, readFile, unlink, writeFile, type FileHandle } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { APIError, Sandbox, type NetworkPolicy } from "@vercel/sandbox";
import {
  actionOperationId,
  type ARecord,
  type BRecord,
  type DirectRecord,
  type IndependentOidcVerification,
  type IngressFallbackRecord,
  type OperatorSecretAction,
  type PRecord,
  type PSyntaxRecord,
  type ReceiverConfiguration,
} from "./receiver.js";
import {
  SBX037_ALIAS_EMAIL,
  SBX037_PROJECT_ID,
  SBX037_TEAM_ID,
  assessSbx037,
  type Sbx037AssessmentInput,
  type Sbx037AttackCaseEvidence,
  type Sbx037DestinationBEvent,
  type Sbx037ExpectedAttackCase,
  type Sbx037ExpectedEvidence,
  type Sbx037ExpectedSyntaxControl,
  type Sbx037GuestRawRequestEvidence,
  type Sbx037PlatformOidcVerification,
  type Sbx037PSyntaxControlEvidence,
  type Sbx037SanitizedFallbackEvent,
  type Sbx037SyntaxAEvent,
  type Sbx037SyntaxControlEvidence,
  type Sbx037SyntaxPEvent,
  type Sbx037TerminalPEvent,
} from "./verdict.js";

const TEST_ID = "SBX-037-POC" as const;
const SCOPE_CONFIRMATION = "researcher-controlled-sbx037-origins-only" as const;
const REMOTE_PROBE_PATH = "/tmp/sbx-037-raw-target-probe.mjs";
const REMOTE_SECRET_PATH = "/tmp/sbx-037/operator-secret";
const SDK_TIMEOUT_MS = 20_000;
const PROBE_TIMEOUT_MS = 8_000;
const POLICY_SETTLE_MS = 1_500;
const INTER_REQUEST_MS = 300;
const MAX_GUEST_REQUESTS = 10;
const MAX_BLOCK_MS = 2_000;
const RECEIPT_ID = /^rt37r_[A-Za-z0-9_-]{24}$/u;
const INHERITED_PLATFORM_TRUST_ENVIRONMENT_NAMES = [
  "NODE_EXTRA_CA_CERTS",
  "NODE_USE_SYSTEM_CA",
  "OPENSSL_CONF",
  "OPENSSL_MODULES",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
] as const;
const INHERITED_PLATFORM_TRUST_ENVIRONMENT_NAME_SET = new Set<string>(
  INHERITED_PLATFORM_TRUST_ENVIRONMENT_NAMES,
);

type CaseId =
  | "direct-b-allow"
  | "absolute-syntax-control"
  | "network-path-syntax-control"
  | "absolute-p-syntax-control"
  | "network-p-syntax-control"
  | "direct-b-pre"
  | "origin-form-terminal"
  | "absolute-target-attack"
  | "network-path-target-attack"
  | "direct-b-post";

type ProbeForm = "origin" | "absolute" | "network-path";
type BodySource = "public" | "file";

interface ProbeTransport {
  tcpConnected?: boolean;
  remoteAddress?: string;
  remotePort?: number;
  tlsEstablished?: boolean;
  authorized?: boolean;
  alpnProtocol?: string;
  tlsProtocol?: string;
  peerCertificate?: { sha256?: string; validFrom?: string; validTo?: string };
}

interface ProbeTlsTrust {
  inheritedPlatformTrustEnvironmentNames?: unknown;
  controllerConfigurableCustomTrustAccepted?: boolean;
  rejectUnauthorized?: boolean;
}

interface GuestProbeResult {
  schemaVersion?: number;
  ok?: boolean;
  phase?: string;
  runId?: string;
  testId?: string;
  caseId?: string;
  correlationId?: string;
  targetForm?: ProbeForm;
  connectionRole?: "a" | "p" | "b";
  syntaxSupported?: boolean;
  method?: string;
  bodySource?: BodySource;
  requestBodyBytes?: number;
  operatorSecretLoaded?: boolean;
  bodyFileMode?: number;
  httpVersion?: string;
  tcpHost?: string;
  tcpPort?: number;
  tlsServername?: string;
  httpHost?: string;
  rawRequestTarget?: string;
  pinnedDestinationIpv4?: string;
  maximumConnections?: number;
  actualConnections?: number;
  maximumRequests?: number;
  actualRequests?: number;
  retryCount?: number;
  redirectsAllowed?: boolean;
  redirectsFollowed?: number;
  connectionReused?: boolean;
  environmentProxyTrust?: boolean;
  tlsTrust?: ProbeTlsTrust;
  responseStatusCode?: number;
  responseOperationId?: string;
  responseFallbackReceiptId?: string;
  responseRole?: "A" | "P" | "B";
  durationMs?: number;
  errorCode?: string;
  errorMessage?: string;
  transport?: ProbeTransport;
  [key: string]: unknown;
}

interface CommandEvidence {
  commandId: string;
  exitCode: number;
  stdoutBytes: number;
  stdoutSha256: string;
  stderrBytes: number;
  stderrSha256: string;
}

interface GuestCaseEvidence {
  caseId: CaseId;
  configurationSha256: string;
  command: CommandEvidence;
  result?: GuestProbeResult;
}

function exactInheritedPlatformTrustEnvironmentNames(value: unknown): value is string[] {
  if (!Array.isArray(value) || value.length > INHERITED_PLATFORM_TRUST_ENVIRONMENT_NAMES.length ||
    !value.every((name): name is string =>
      typeof name === "string" && INHERITED_PLATFORM_TRUST_ENVIRONMENT_NAME_SET.has(name))) return false;
  return new Set(value).size === value.length &&
    value.every((name, index) => name === [...value].sort()[index]);
}

function sanitizeInheritedPlatformTrustEnvironmentNames(value: unknown): string[] {
  return exactInheritedPlatformTrustEnvironmentNames(value)
    ? [...value]
    : ["INVALID_INHERITED_PLATFORM_TRUST_ENVIRONMENT_ATTESTATION"];
}

function observedInheritedPlatformTrustEnvironmentNames(cases: GuestCaseEvidence[]): string[] {
  const observed = new Set<string>();
  for (const entry of cases) {
    const names = entry.result?.tlsTrust?.inheritedPlatformTrustEnvironmentNames;
    if (exactInheritedPlatformTrustEnvironmentNames(names)) {
      for (const name of names) observed.add(name);
    }
  }
  return [...observed].sort();
}

interface PolicyProof {
  stage: "initial" | "pre-attack" | "post-attack";
  activeSandboxPolicy: unknown;
  activeSessionPolicy: unknown;
  independentSandboxPolicy: unknown;
  independentSessionPolicy: unknown;
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
  pSyntaxRecords: PSyntaxRecord[];
  pRecords: PRecord[];
  bRecords: BRecord[];
  directRecords: DirectRecord[];
  fallbackRecords: IngressFallbackRecord[];
  terminalInvariant: {
    redirectsIssued: number;
    locationHeadersIssued: number;
    applicationFetches: number;
    applicationProxyAttempts: number;
    rawOidcTokensRetained: boolean;
    rawRequestBodiesRetained: boolean;
  };
}

interface CleanupEvidence {
  orphanRecoveryAttempted: boolean;
  recovered: boolean;
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  sandboxAbsenceChecks: number;
  receiverDeleteAttempted: boolean;
  receiverDeleted: boolean;
  receiverAbsent: boolean;
  liveLockReleased: boolean;
  errors: string[];
}

class IndeterminateControlError extends Error {}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function signal(timeoutMs = SDK_TIMEOUT_MS): AbortSignal {
  return AbortSignal.timeout(timeoutMs);
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function exactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
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

export function controlledOrigins(environment: NodeJS.ProcessEnv = process.env): { a: URL; p: URL; b: URL } {
  if (environment.SBX037_SCOPE_CONFIRMATION !== SCOPE_CONFIRMATION) {
    throw new Error(`SBX037_SCOPE_CONFIRMATION must equal ${SCOPE_CONFIRMATION}`);
  }
  const a = exactOrigin(environment.SBX037_A_PUBLIC_ORIGIN ?? "", "SBX037_A_PUBLIC_ORIGIN");
  const p = exactOrigin(environment.SBX037_P_PUBLIC_ORIGIN ?? "", "SBX037_P_PUBLIC_ORIGIN");
  const b = exactOrigin(environment.SBX037_B_PUBLIC_ORIGIN ?? "", "SBX037_B_PUBLIC_ORIGIN");
  if (new Set([a.origin, p.origin, b.origin]).size !== 3) {
    throw new Error("SBX-037 requires three distinct researcher-owned HTTPS origins");
  }
  return { a, p, b };
}

export function explicitCredentials(environment: NodeJS.ProcessEnv = process.env): {
  token: string;
  teamId: typeof SBX037_TEAM_ID;
  projectId: typeof SBX037_PROJECT_ID;
} {
  const token = environment.VERCEL_TOKEN;
  if (!token || environment.VERCEL_TEAM_ID !== SBX037_TEAM_ID || environment.VERCEL_PROJECT_ID !== SBX037_PROJECT_ID) {
    throw new Error("SBX-037 requires explicit credentials for the verified HackerOne-alias team and project");
  }
  return { token, teamId: SBX037_TEAM_ID, projectId: SBX037_PROJECT_ID };
}

export function buildProbeConfiguration(input: {
  a: URL;
  p: URL;
  b: URL;
  forwardAudience: string;
  connectionRole: "a" | "p" | "b";
  pinnedDestinationIpv4: string;
  expectedOperationId: string;
  runId: string;
  caseId: CaseId;
  correlationId: string;
  targetForm: ProbeForm;
  targetPath: string;
  bodySource: BodySource;
}): object {
  const publicBody = `public:${input.correlationId}`;
  return {
    schemaVersion: 1,
    scopeConfirmation: SCOPE_CONFIRMATION,
    researcherControlledOrigins: [input.a.origin, input.p.origin, input.b.origin],
    aOrigin: input.a.origin,
    bOrigin: input.b.origin,
    pUrl: input.forwardAudience,
    connectionRole: input.connectionRole,
    pinnedDestinationIpv4: input.pinnedDestinationIpv4,
    expectedOperationId: input.expectedOperationId,
    runId: input.runId,
    testId: TEST_ID,
    caseId: input.caseId,
    correlationId: input.correlationId,
    targetForm: input.targetForm,
    targetPath: input.targetPath,
    bodySource: input.bodySource,
    ...(input.bodySource === "public" ? { publicBody } : { bodyFile: REMOTE_SECRET_PATH }),
    timeoutMs: PROBE_TIMEOUT_MS,
    maxResponseHeaderBytes: 16_384,
    maxResponseBodyBytes: 8_192,
  };
}

export interface AliasIdentityVerification {
  email: typeof SBX037_ALIAS_EMAIL;
  method: "v2-user-email" | "manual-alias-confirmation-plus-exact-team-project-api";
}

export type IdentityFetch = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

export async function verifyAliasIdentity(
  token: string,
  environment: NodeJS.ProcessEnv = process.env,
  fetchImpl: IdentityFetch = fetch,
): Promise<AliasIdentityVerification> {
  const response = await fetchImpl("https://api.vercel.com/v2/user", {
    headers: { Authorization: `Bearer ${token}`, Connection: "close" },
    redirect: "error",
    signal: signal(10_000),
  });
  if (response.ok) {
    const payload = await response.json() as { user?: { email?: unknown } };
    if (payload.user?.email !== SBX037_ALIAS_EMAIL) {
      throw new Error("Vercel token is not authenticated as the required HackerOne alias");
    }
    return { email: SBX037_ALIAS_EMAIL, method: "v2-user-email" };
  }

  if (response.status !== 401 && response.status !== 403) {
    throw new Error(`Vercel alias verification returned ${response.status}`);
  }
  if (environment.SBX037_ALIAS_EMAIL_CONFIRMATION !== SBX037_ALIAS_EMAIL) {
    throw new Error("scoped Sandbox token requires the exact manual HackerOne alias confirmation");
  }

  const headers = { Authorization: `Bearer ${token}`, Connection: "close" };
  const teamResponse = await fetchImpl(`https://api.vercel.com/v2/teams/${SBX037_TEAM_ID}`, {
    headers,
    redirect: "error",
    signal: signal(10_000),
  });
  if (!teamResponse.ok) {
    throw new Error(`scoped Vercel identity proof failed for the exact team (${teamResponse.status})`);
  }
  const team = await teamResponse.json() as { id?: unknown };
  if (team.id !== SBX037_TEAM_ID) {
    throw new Error("scoped Vercel identity proof returned the wrong team");
  }

  const projectResponse = await fetchImpl(
    `https://api.vercel.com/v9/projects/${SBX037_PROJECT_ID}?teamId=${SBX037_TEAM_ID}`,
    { headers, redirect: "error", signal: signal(10_000) },
  );
  if (!projectResponse.ok) {
    throw new Error(`scoped Vercel identity proof failed for the exact project (${projectResponse.status})`);
  }
  const project = await projectResponse.json() as { id?: unknown };
  if (project.id !== SBX037_PROJECT_ID) {
    throw new Error("scoped Vercel identity proof returned the wrong project");
  }

  return {
    email: SBX037_ALIAS_EMAIL,
    method: "manual-alias-confirmation-plus-exact-team-project-api",
  };
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

function publicIpv4(value: string): boolean {
  if (isIP(value) !== 4) return false;
  const [a = -1, b = -1] = value.split(".").map(Number);
  return a > 0 && a < 224 && a !== 10 && a !== 127 && !(a === 172 && b >= 16 && b <= 31) &&
    !(a === 192 && b === 168) && !(a === 169 && b === 254) && !(a === 100 && b >= 64 && b <= 127);
}

async function resolvePublicIpv4(hostname: string): Promise<string[]> {
  const resolver = new Resolver();
  const deadline = globalThis.setTimeout(() => resolver.cancel(), 10_000);
  try {
    const answers = await resolver.resolve4(hostname);
    const unique = [...new Set(answers.filter(publicIpv4))].sort();
    if (unique.length === 0) throw new Error(`${hostname} has no public IPv4 address`);
    return unique;
  } finally {
    globalThis.clearTimeout(deadline);
  }
}

function receiptOperationId(): string {
  const id = `rt37r_${randomBytes(18).toString("base64url")}`;
  if (!RECEIPT_ID.test(id)) throw new Error("receipt operation ID invariant failed");
  return id;
}

function safeError(error: unknown, secrets: string[]): string {
  let value = String(error instanceof Error ? error.message : error).replace(/[\0\r\n]/gu, " ").slice(0, 512);
  for (const secret of secrets) value = value.replaceAll(secret, "[redacted]");
  return value;
}

function isNotFound(error: unknown): boolean {
  return error instanceof APIError && error.response.status === 404;
}

export function recoverableSandboxIdentity(input: {
  createdAt: Date;
  startedAt: string;
  tags: Record<string, string> | undefined;
  expectedTags: Record<string, string>;
}): boolean {
  const timestamp = input.createdAt.getTime();
  const tags = input.tags;
  if (!tags) return false;
  return timestamp >= Date.parse(input.startedAt) - 5_000 && timestamp <= Date.now() + 5_000 &&
    tags.harness === input.expectedTags.harness && tags.test === input.expectedTags.test &&
    tags.run === input.expectedTags.run;
}

async function health(origin: URL): Promise<boolean> {
  const response = await fetch(new URL("/healthz", origin), {
    headers: { Connection: "close" },
    redirect: "error",
    signal: signal(10_000),
  });
  const body = await response.json() as { ok?: unknown };
  return response.ok && body.ok === true;
}

async function adminRequest(p: URL, adminKey: string, runId: string, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);
  headers.set("authorization", `Bearer ${adminKey}`);
  headers.set("connection", "close");
  if (init?.body) headers.set("content-type", "application/json");
  return fetch(new URL(`/v1/sbx037/admin/runs/${encodeURIComponent(runId)}`, p), {
    ...init,
    headers,
    redirect: "error",
    signal: signal(10_000),
  });
}

function emptyReceiverReadback(): ReceiverReadback {
  return {
    configured: false,
    aRecords: [],
    pSyntaxRecords: [],
    pRecords: [],
    bRecords: [],
    directRecords: [],
    fallbackRecords: [],
    terminalInvariant: {
      redirectsIssued: 0,
      locationHeadersIssued: 0,
      applicationFetches: 0,
      applicationProxyAttempts: 0,
      rawOidcTokensRetained: false,
      rawRequestBodiesRetained: false,
    },
  };
}

async function receiverReadback(p: URL, adminKey: string, runId: string): Promise<ReceiverReadback> {
  const response = await adminRequest(p, adminKey, runId);
  if (response.status === 404) return emptyReceiverReadback();
  if (!response.ok) throw new Error(`receiver readback returned ${response.status}`);
  const value = await response.json() as ReceiverReadback;
  if (!Array.isArray(value.aRecords) || !Array.isArray(value.pSyntaxRecords) || !Array.isArray(value.pRecords) ||
      !Array.isArray(value.bRecords) || !Array.isArray(value.directRecords) ||
      !Array.isArray(value.fallbackRecords) || !value.terminalInvariant) {
    throw new Error("receiver readback shape was invalid");
  }
  return value;
}

function guestResult(value: unknown): GuestProbeResult | undefined {
  const input = object(value);
  if (!input) return undefined;
  return input as GuestProbeResult;
}

async function captureCommand(
  sandbox: Sandbox,
  configuration: unknown,
  secrets: string[],
): Promise<{ command: CommandEvidence; result?: GuestProbeResult }> {
  const serialized = JSON.stringify(configuration);
  if (secrets.some((secret) => serialized.includes(secret))) {
    throw new Error("guest configuration contains a controller credential or raw operator secret");
  }
  const command = await sandbox.runCommand({
    cmd: "node",
    args: [REMOTE_PROBE_PATH, Buffer.from(serialized).toString("base64url")],
    timeoutMs: 20_000,
    signal: signal(),
  });
  const [stdout, stderr] = await Promise.all([
    command.stdout({ signal: signal() }),
    command.stderr({ signal: signal() }),
  ]);
  if (Buffer.byteLength(stdout) > 64_000 || Buffer.byteLength(stderr) > 16_000) {
    throw new Error("guest output exceeded evidence bounds");
  }
  if (secrets.some((secret) => stdout.includes(secret) || stderr.includes(secret))) {
    throw new Error("guest output contains a controller credential or raw operator secret");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error("guest did not emit structured JSON");
  }
  const result = guestResult(parsed);
  return {
    command: {
      commandId: command.cmdId,
      exitCode: command.exitCode,
      stdoutBytes: Buffer.byteLength(stdout),
      stdoutSha256: sha256(stdout),
      stderrBytes: Buffer.byteLength(stderr),
      stderrSha256: sha256(stderr),
    },
    ...(result ? { result } : {}),
  };
}

function exactVerifiedTransport(result: GuestProbeResult | undefined, pinnedIp: string): boolean {
  return result?.tlsTrust?.controllerConfigurableCustomTrustAccepted === false &&
    exactInheritedPlatformTrustEnvironmentNames(result.tlsTrust.inheritedPlatformTrustEnvironmentNames) &&
    result.tlsTrust.rejectUnauthorized === true &&
    result.transport?.tcpConnected === true && result.transport.tlsEstablished === true &&
    result.transport.authorized === true && result.transport.remoteAddress === pinnedIp &&
    result.transport.remotePort === 443 && result.transport.alpnProtocol === "http/1.1";
}

export function conclusiveDirectReachability(
  result: GuestProbeResult | undefined,
  commandExitCode: number,
  pinnedIp: string,
  operationId: string,
  eventCount: number,
): boolean {
  return commandExitCode === 0 && result?.ok === true && result.actualConnections === 1 &&
    result.actualRequests === 1 && result.responseStatusCode === 202 &&
    result.responseOperationId === operationId && result.responseRole === "B" &&
    result.responseFallbackReceiptId === undefined && exactVerifiedTransport(result, pinnedIp) && eventCount === 1;
}

export function conclusiveDirectBlock(
  result: GuestProbeResult | undefined,
  commandExitCode: number,
  pinnedIp: string,
  eventCount: number,
): boolean {
  if (commandExitCode !== 0 || result?.ok !== false || result.actualRequests !== 0 ||
    result.tlsTrust?.controllerConfigurableCustomTrustAccepted !== false ||
    !exactInheritedPlatformTrustEnvironmentNames(result.tlsTrust.inheritedPlatformTrustEnvironmentNames) ||
    result.tlsTrust.rejectUnauthorized !== true ||
    result.pinnedDestinationIpv4 !== pinnedIp || typeof result.durationMs !== "number" ||
    result.durationMs < 0 || result.durationMs > MAX_BLOCK_MS || eventCount !== 0) return false;
  const preConnectDeny = ["EHOSTUNREACH", "ENETUNREACH"].includes(result.errorCode ?? "") &&
    result.actualConnections === 0 && result.transport?.tcpConnected !== true &&
    result.transport?.tlsEstablished !== true && result.transport?.remoteAddress === undefined;
  const connectedReset = result.errorCode === "ECONNRESET" && result.actualConnections === 1 &&
    result.transport?.tcpConnected === true && result.transport.tlsEstablished === false &&
    result.transport.remoteAddress === pinnedIp && result.transport.remotePort === 443;
  return preConnectDeny || connectedReset;
}

export function conclusiveSyntaxControl(input: {
  result: GuestProbeResult | undefined;
  commandExitCode: number;
  pinnedIp: string;
  runId: string;
  caseId: "absolute-syntax-control" | "network-path-syntax-control";
  correlationId: string;
  targetForm: "absolute" | "network-path";
  rawRequestTarget: string;
  operationId: string;
  publicBodyBytes: number;
  aRecords: ARecord[];
  bEventCount: number;
  pEventCount: number;
}): boolean {
  const event = input.aRecords[0];
  return input.commandExitCode === 0 && input.result?.ok === true && input.result.syntaxSupported === true &&
    input.result.runId === input.runId && input.result.testId === TEST_ID && input.result.caseId === input.caseId &&
    input.result.correlationId === input.correlationId && input.result.targetForm === input.targetForm &&
    input.result.rawRequestTarget === input.rawRequestTarget && input.result.responseStatusCode === 202 &&
    input.result.responseOperationId === input.operationId && input.result.responseRole === "A" &&
    input.result.responseFallbackReceiptId === undefined && input.result.actualConnections === 1 &&
    input.result.actualRequests === 1 && exactVerifiedTransport(input.result, input.pinnedIp) &&
    input.aRecords.length === 1 && event !== undefined && event.runId === input.runId &&
    event.testId === TEST_ID && event.caseId === input.caseId && event.correlationId === input.correlationId &&
    event.correlationMatched === true && event.method === "POST" && event.rawTarget === input.rawRequestTarget &&
    event.targetForm === input.targetForm && event.exactSyntaxTarget === true && event.publicBodyMatched === true &&
    event.bodyLength === input.publicBodyBytes && event.oidcHeaderCount === 0 &&
    event.operationId === input.operationId && event.terminalResponse === true && event.responseStatus === 202 &&
    input.bEventCount === 0 && input.pEventCount === 0;
}

export function conclusiveUnsupportedSyntaxControl(input: {
  result: GuestProbeResult | undefined;
  commandExitCode: number;
  pinnedIp: string;
  runId: string;
  caseId: "absolute-syntax-control" | "network-path-syntax-control";
  correlationId: string;
  targetForm: "absolute" | "network-path";
  rawRequestTarget: string;
  normalizedAPath: string;
  publicBodyBytes: number;
  aRecords: ARecord[];
  bEventCount: number;
  pEventCount: number;
  pSyntaxEventCount: number;
  directEventCount: number;
}): boolean {
  const event = input.aRecords[0];
  return input.commandExitCode === 0 && input.result?.ok === true && input.result.syntaxSupported === false &&
    input.result.runId === input.runId && input.result.testId === TEST_ID && input.result.caseId === input.caseId &&
    input.result.correlationId === input.correlationId && input.result.targetForm === input.targetForm &&
    input.result.connectionRole === "a" && input.result.method === "POST" && input.result.bodySource === "public" &&
    input.result.operatorSecretLoaded === false && input.result.requestBodyBytes === input.publicBodyBytes &&
    input.result.rawRequestTarget === input.rawRequestTarget && input.result.responseStatusCode === 400 &&
    input.result.responseOperationId === undefined && input.result.httpVersion === "1.1" &&
    input.result.responseRole === "A" && input.result.responseFallbackReceiptId === undefined &&
    input.result.maximumConnections === 1 && input.result.actualConnections === 1 &&
    input.result.maximumRequests === 1 && input.result.actualRequests === 1 && input.result.retryCount === 0 &&
    input.result.redirectsAllowed === false && input.result.redirectsFollowed === 0 &&
    input.result.connectionReused === false && input.result.environmentProxyTrust === false &&
    input.result.pinnedDestinationIpv4 === input.pinnedIp && exactVerifiedTransport(input.result, input.pinnedIp) &&
    input.aRecords.length === 1 && event !== undefined && event.runId === input.runId &&
    event.testId === TEST_ID && event.caseId === input.caseId && event.correlationId === input.correlationId &&
    event.correlationMatched === true && event.method === "POST" && event.rawTarget === input.normalizedAPath &&
    event.targetForm === "other" && event.exactSyntaxTarget === false && event.publicBodyMatched === true &&
    event.bodyLength === input.publicBodyBytes && event.oidcHeaderCount === 0 && event.operationId === undefined &&
    event.terminalResponse === true && event.responseStatus === 400 && input.bEventCount === 0 &&
    input.pEventCount === 0 && input.pSyntaxEventCount === 0 && input.directEventCount === 0;
}

export function conclusivePSyntaxControl(input: {
  result: GuestProbeResult | undefined;
  commandExitCode: number;
  pinnedIp: string;
  runId: string;
  caseId: "absolute-p-syntax-control" | "network-p-syntax-control";
  correlationId: string;
  targetForm: "absolute" | "network-path";
  rawRequestTarget: string;
  operationId: string;
  publicBodyBytes: number;
  pSyntaxRecords: PSyntaxRecord[];
  aEventCount: number;
  bEventCount: number;
  forwardedPEventCount: number;
}): boolean {
  const event = input.pSyntaxRecords[0];
  return input.commandExitCode === 0 && input.result?.ok === true && input.result.syntaxSupported === true &&
    input.result.runId === input.runId && input.result.testId === TEST_ID && input.result.caseId === input.caseId &&
    input.result.correlationId === input.correlationId && input.result.targetForm === input.targetForm &&
    input.result.rawRequestTarget === input.rawRequestTarget && input.result.responseStatusCode === 202 &&
    input.result.responseOperationId === input.operationId && input.result.responseRole === "P" &&
    input.result.responseFallbackReceiptId === undefined && input.result.actualConnections === 1 &&
    input.result.actualRequests === 1 && exactVerifiedTransport(input.result, input.pinnedIp) &&
    input.pSyntaxRecords.length === 1 && event !== undefined && event.runId === input.runId &&
    event.testId === TEST_ID && event.caseId === input.caseId && event.correlationId === input.correlationId &&
    event.correlationMatched === true && event.method === "POST" && event.rawTarget === input.rawRequestTarget &&
    event.targetForm === input.targetForm && event.exactSyntaxTarget === true && event.hostMatched === true &&
    event.publicBodyMatched === true &&
    event.bodyLength === input.publicBodyBytes && event.oidcHeaderCount === 0 &&
    event.forwardedMetadataAbsent === true && event.operationId === input.operationId &&
    event.terminalResponse === true && event.redirectAttempted === false && event.fetchAttempted === false &&
    event.proxyAttempted === false && event.locationHeaderPresent === false && event.responseStatus === 202 &&
    input.aEventCount === 0 && input.bEventCount === 0 && input.forwardedPEventCount === 0;
}

export function conclusiveOriginTerminalControl(input: {
  result: GuestProbeResult | undefined;
  commandExitCode: number;
  pinnedIp: string;
  operationId: string;
  pRecords: Array<{ operationId?: string; tokenVerified: boolean }>;
  originCaseAEventCount: number;
  originCaseBEventCount: number;
}): boolean {
  const event = input.pRecords[0];
  return input.commandExitCode === 0 && input.result?.ok === true &&
    input.result.responseStatusCode === 202 && input.result.responseOperationId === input.operationId &&
    input.result.responseRole === "P" && input.result.responseFallbackReceiptId === undefined &&
    exactVerifiedTransport(input.result, input.pinnedIp) && input.pRecords.length === 1 &&
    event?.tokenVerified === true && event.operationId === input.operationId &&
    input.originCaseAEventCount === 0 && input.originCaseBEventCount === 0;
}

function oidcVerification(
  value: IndependentOidcVerification,
): Sbx037PlatformOidcVerification {
  return {
    tokenOrdinal: value.tokenOrdinal,
    verifier: value.verifier,
    signatureVerified: value.signatureVerified,
    algorithm: value.algorithm,
    issuer: value.issuer,
    jwksUrl: value.jwksUrl,
    audience: value.audience,
    temporalClaimsVerified: value.temporalClaimsVerified,
    identity: value.identity,
    rawTokenRetained: value.rawTokenRetained,
    ...(value.verificationError ? { verificationError: value.verificationError } : {}),
  };
}

function pEvent(value: PRecord | undefined): Sbx037TerminalPEvent | undefined {
  if (!value?.operationId) return undefined;
  return {
    runId: value.runId,
    testId: value.testId,
    caseId: value.caseId,
    correlationId: value.correlationId,
    requestUrl: value.requestUrl,
    operationId: value.operationId,
    terminalResponse: value.terminalResponse,
    forwardedMetadataValid: value.forwardedMetadataValid,
    responseStatusCode: value.responseStatus,
    oidcHeaderCount: value.oidcHeaderCount,
    oidcValueCount: value.oidcValueCount,
    oidcVerifications: value.oidcVerifications.map(oidcVerification),
  };
}

function syntaxAEvent(value: ARecord | undefined): Sbx037SyntaxAEvent | undefined {
  if (!value) return undefined;
  return {
    runId: value.runId,
    testId: value.testId,
    caseId: value.caseId,
    correlationId: value.correlationId,
    correlationMatched: value.correlationMatched,
    method: value.method,
    rawRequestTarget: value.rawTarget,
    targetForm: value.targetForm,
    exactSyntaxTarget: value.exactSyntaxTarget,
    publicBodyMatched: value.publicBodyMatched,
    bodyLength: value.bodyLength ?? -1,
    oidcHeaderCount: value.oidcHeaderCount,
    ...(value.operationId ? { operationId: value.operationId } : {}),
    terminalResponse: value.terminalResponse,
    responseStatusCode: value.responseStatus,
  };
}

function syntaxPEvent(value: PSyntaxRecord | undefined): Sbx037SyntaxPEvent | undefined {
  if (!value?.operationId) return undefined;
  return {
    runId: value.runId,
    testId: value.testId,
    caseId: value.caseId,
    correlationId: value.correlationId,
    correlationMatched: value.correlationMatched,
    method: value.method,
    rawRequestTarget: value.rawTarget,
    targetForm: value.targetForm,
    exactSyntaxTarget: value.exactSyntaxTarget,
    hostMatched: value.hostMatched,
    publicBodyMatched: value.publicBodyMatched,
    bodyLength: value.bodyLength,
    oidcHeaderCount: value.oidcHeaderCount,
    forwardedMetadataAbsent: value.forwardedMetadataAbsent,
    operationId: value.operationId,
    terminalResponse: value.terminalResponse,
    redirectAttempted: value.redirectAttempted,
    fetchAttempted: value.fetchAttempted,
    proxyAttempted: value.proxyAttempted,
    locationHeaderPresent: value.locationHeaderPresent,
    responseStatusCode: value.responseStatus,
  };
}

function secretAction(value: OperatorSecretAction): Sbx037DestinationBEvent["operatorSecretActions"][number] {
  return { ...value };
}

function bEvent(value: BRecord | undefined): Sbx037DestinationBEvent | undefined {
  if (!value?.operationId) return undefined;
  return {
    runId: value.runId,
    testId: value.testId,
    caseId: value.caseId,
    correlationId: value.correlationId,
    requestUrl: value.requestUrl,
    operationId: value.operationId,
    correlationMatched: value.correlationMatched,
    responseStatusCode: value.responseStatus,
    oidcHeaderCount: value.oidcHeaderCount,
    oidcValueCount: value.oidcValueCount,
    oidcVerifications: value.oidcVerifications.map(oidcVerification),
    operatorSecretActions: value.operatorSecretActions.map(secretAction),
  };
}

function guestEvidence(
  record: GuestCaseEvidence | undefined,
  expected: {
    runId: string;
    correlationId: string;
    caseId: string;
    targetForm: ProbeForm;
    rawRequestTarget: string;
    bodySource: BodySource;
    publicBodyBytes?: number;
  },
  a: URL,
): Sbx037GuestRawRequestEvidence {
  const value = record?.result;
  return {
    commandExitCode: record?.command.exitCode ?? -1,
    ok: value?.ok === true,
    runId: value?.runId ?? "missing",
    testId: value?.testId ?? "missing",
    caseId: value?.caseId ?? "missing",
    correlationId: value?.correlationId ?? "missing",
    targetForm: value?.targetForm ?? "missing",
    connectionRole: value?.connectionRole ?? "missing",
    syntaxSupported: typeof value?.syntaxSupported === "boolean" ? value.syntaxSupported : "missing",
    method: value?.method ?? "missing",
    bodySource: value?.bodySource ?? "missing",
    ...(expected.bodySource === "public" ? { requestBodyBytes: value?.requestBodyBytes ?? -1 } : {}),
    operatorSecretLoaded: value?.operatorSecretLoaded === true,
    ...(typeof value?.bodyFileMode === "number" ? { bodyFileMode: value.bodyFileMode } : {}),
    httpVersion: value?.httpVersion ?? "missing",
    tcpHost: value?.tcpHost ?? "missing",
    tcpPort: value?.tcpPort ?? -1,
    tlsServername: value?.tlsServername ?? "missing",
    httpHost: value?.httpHost ?? "missing",
    rawRequestTarget: value?.rawRequestTarget ?? "missing",
    maximumConnections: value?.maximumConnections ?? -1,
    actualConnections: value?.actualConnections ?? -1,
    maximumRequests: value?.maximumRequests ?? -1,
    actualRequests: value?.actualRequests ?? -1,
    retryCount: value?.retryCount ?? -1,
    redirectsAllowed: value?.redirectsAllowed ?? true,
    redirectsFollowed: value?.redirectsFollowed ?? -1,
    connectionReused: value?.connectionReused ?? true,
    environmentProxyTrust: value?.environmentProxyTrust ?? true,
    tlsTrust: {
      inheritedPlatformTrustEnvironmentNames: sanitizeInheritedPlatformTrustEnvironmentNames(
        value?.tlsTrust?.inheritedPlatformTrustEnvironmentNames,
      ),
      controllerConfigurableCustomTrustAccepted:
        value?.tlsTrust?.controllerConfigurableCustomTrustAccepted !== false,
      rejectUnauthorized: value?.tlsTrust?.rejectUnauthorized === true,
    },
    pinnedDestinationIpv4: value?.pinnedDestinationIpv4 ?? "missing",
    transportTcpConnected: value?.transport?.tcpConnected === true,
    transportTlsEstablished: value?.transport?.tlsEstablished === true,
    transportAuthorized: value?.transport?.authorized === true,
    transportRemoteAddress: value?.transport?.remoteAddress ?? "missing",
    transportRemotePort: value?.transport?.remotePort ?? -1,
    transportAlpnProtocol: value?.transport?.alpnProtocol ?? "missing",
    ...(typeof value?.responseStatusCode === "number" ? { responseStatusCode: value.responseStatusCode } : {}),
    ...(value?.responseOperationId ? { responseOperationId: value.responseOperationId } : {}),
    ...(value?.responseFallbackReceiptId
      ? { responseFallbackReceiptId: value.responseFallbackReceiptId }
      : {}),
    ...(value?.responseRole ? { responseRole: value.responseRole } : {}),
  };
}

export function fallbackEvent(value: IngressFallbackRecord | undefined): Sbx037SanitizedFallbackEvent | undefined {
  if (!value) return undefined;
  return {
    observedAt: value.observedAt,
    role: value.role,
    reason: value.reason,
    runId: value.runId,
    testId: value.testId,
    caseId: value.caseId,
    correlationId: value.correlationId,
    correlationMatched: value.correlationMatched,
    method: value.method,
    requestTarget: value.requestTarget,
    host: value.host,
    ...(typeof value.bodyLength === "number" ? { bodyLength: value.bodyLength } : {}),
    forwardedHeaderCounts: {
      host: { ...value.forwardedHeaderCounts.host },
      scheme: { ...value.forwardedHeaderCounts.scheme },
      port: { ...value.forwardedHeaderCounts.port },
      path: { ...value.forwardedHeaderCounts.path },
    },
    oidcHeaderCount: value.oidcHeaderCount,
    oidcValueCount: value.oidcValueCount,
    tokenVerified: value.tokenVerified,
    algorithmRs256: value.algorithmRs256,
    issuerVerified: value.issuerVerified,
    audienceVerified: value.audienceVerified,
    temporalClaimsVerified: value.temporalClaimsVerified,
    exactClaimsVerified: value.exactClaimsVerified,
    oidcVerifications: value.oidcVerifications.map((verification) => ({ ...verification })),
    operatorSecretBodyPresent: value.operatorSecretBodyPresent,
    operatorSecretActionAttempted: value.operatorSecretActionAttempted,
    operatorSecretActionAuthorized: value.operatorSecretActionAuthorized,
    ...(value.actionOperationId ? { actionOperationId: value.actionOperationId } : {}),
    operatorSecretActions: value.operatorSecretActions.map(secretAction),
    receiptId: value.receiptId,
    rawOidcTokenRetained: value.rawOidcTokenRetained,
    rawRequestBodyRetained: value.rawRequestBodyRetained,
    rawOperatorSecretRetained: value.rawOperatorSecretRetained,
    rawOperatorSecretReflected: value.rawOperatorSecretReflected,
    responseBodyContainedSecret: value.responseBodyContainedSecret,
    derivedSecretDigestRetained: value.derivedSecretDigestRetained,
    terminalResponse: value.terminalResponse,
    redirectAttempted: value.redirectAttempted,
    fetchAttempted: value.fetchAttempted,
    proxyAttempted: value.proxyAttempted,
    locationHeaderPresent: value.locationHeaderPresent,
    responseStatus: value.responseStatus,
  };
}

async function acquireLock(path: string): Promise<FileHandle> {
  await mkdir(resolve(path, ".."), { recursive: true, mode: 0o700 });
  return open(path, "wx", 0o600);
}

export function exitCodeForVerdict(verdict: string): number {
  return verdict === "pass" ? 0 : 1;
}

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  const lockPath = resolve(artifactsDirectory, "SBX-037-live-active.lock");
  const { a, p, b } = controlledOrigins();
  const credentials = explicitCredentials();
  const adminKey = required(process.env, "SBX037_ADMIN_KEY");
  const actionKey = required(process.env, "SBX037_ACTION_KEY");
  if (adminKey === actionKey || Buffer.byteLength(adminKey) < 32 || Buffer.byteLength(actionKey) < 32) {
    throw new Error("SBX037_ADMIN_KEY and SBX037_ACTION_KEY must be distinct and at least 32 bytes each");
  }
  const runId = randomUUID();
  const sandboxName = `sbx-037-poc-${runId.replaceAll("-", "")}`;
  const sandboxTags = { harness: "vsc", test: TEST_ID, run: runId };
  const correlations = {
    directBAllow: `c37_${randomBytes(18).toString("base64url")}`,
    directBPre: `c37_${randomBytes(18).toString("base64url")}`,
    directBPost: `c37_${randomBytes(18).toString("base64url")}`,
    originFormTerminal: `c37_${randomBytes(18).toString("base64url")}`,
    absoluteSyntaxControl: `c37_${randomBytes(18).toString("base64url")}`,
    networkPathSyntaxControl: `c37_${randomBytes(18).toString("base64url")}`,
    absolutePSyntaxControl: `c37_${randomBytes(18).toString("base64url")}`,
    networkPSyntaxControl: `c37_${randomBytes(18).toString("base64url")}`,
    absoluteTargetAttack: `c37_${randomBytes(18).toString("base64url")}`,
    networkPathTargetAttack: `c37_${randomBytes(18).toString("base64url")}`,
  };
  if (new Set(Object.values(correlations)).size !== Object.keys(correlations).length) {
    throw new Error("case correlation invariant failed");
  }
  const operatorSecret = `opsec_${randomBytes(32).toString("base64url")}`;
  const publicOperationIds = {
    initialB: receiptOperationId(),
    directPre: receiptOperationId(),
    directPost: receiptOperationId(),
    origin: receiptOperationId(),
    absoluteSyntax: receiptOperationId(),
    networkSyntax: receiptOperationId(),
    absolutePSyntax: receiptOperationId(),
    networkPSyntax: receiptOperationId(),
    absolute: receiptOperationId(),
    network: receiptOperationId(),
  };
  const actionOperationIds = {
    absolute: actionOperationId(actionKey, runId, "absolute-target-attack", operatorSecret),
    network: actionOperationId(actionKey, runId, "network-path-target-attack", operatorSecret),
  };
  if (new Set([...Object.values(publicOperationIds), ...Object.values(actionOperationIds)]).size !== 12) {
    throw new Error("operation ID uniqueness invariant failed");
  }
  const forwardAudience = new URL(`/v1/sbx037/forward/${encodeURIComponent(runId)}`, p).toString();
  const directBUrl = new URL(`/v1/sbx037/direct/${encodeURIComponent(runId)}`, b).toString();
  const originPath = `/v1/sbx037/origin/${encodeURIComponent(runId)}`;
  const originAUrl = new URL(originPath, a).toString();
  const collectPath = `/v1/sbx037/collect/${encodeURIComponent(runId)}`;
  const bCollectUrl = new URL(collectPath, b).toString();
  const networkRawTarget = `//${b.host}${collectPath}`;
  const initialPolicy = { allow: [a.hostname, p.hostname, b.hostname] } satisfies NetworkPolicy;
  const finalPolicy = { allow: { [a.hostname]: [{ forwardURL: forwardAudience }] } } satisfies NetworkPolicy;
  const secrets = [credentials.token, adminKey, actionKey, operatorSecret];
  const cleanup: CleanupEvidence = {
    orphanRecoveryAttempted: false,
    recovered: false,
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    sandboxAbsenceChecks: 0,
    receiverDeleteAttempted: false,
    receiverDeleted: false,
    receiverAbsent: false,
    liveLockReleased: false,
    errors: [],
  };
  let sandbox: Sandbox | undefined;
  let aliasVerification: AliasIdentityVerification | undefined;
  let createAttempted = false;
  let receiverConfigured = false;
  let sessionId: string | undefined;
  let liveLock: FileHandle | undefined;
  let executionError: string | undefined;
  let controlFailure: string | undefined;
  let receiver = emptyReceiverReadback();
  let attempts = 0;
  let aAddresses: string[] = [];
  let pAddresses: string[] = [];
  let bAddresses: string[] = [];
  let pinnedA = "missing";
  let pinnedP = "missing";
  let pinnedB = "missing";
  const guestCases: GuestCaseEvidence[] = [];
  const policyProofs: PolicyProof[] = [];
  const syntaxEligibility: Record<"absolute" | "network-path", "unknown" | "supported" | "unsupported"> = {
    absolute: "unknown",
    "network-path": "unknown",
  };

  const policyProof = async (stage: PolicyProof["stage"]): Promise<PolicyProof> => {
    if (!sandbox || !sessionId) throw new Error("policy proof requires an active sandbox identity");
    const activeSession = sandbox.currentSession();
    const independent = await Sandbox.get({ name: sandboxName, resume: false, signal: signal(), ...credentials });
    const independentSession = independent.currentSession();
    const initial = stage === "initial";
    const exact = initial
      ? exactAllowPolicy(sandbox.networkPolicy, initialPolicy.allow) &&
        exactAllowPolicy(activeSession.networkPolicy, initialPolicy.allow) &&
        exactAllowPolicy(independent.networkPolicy, initialPolicy.allow) &&
        exactAllowPolicy(independentSession.networkPolicy, initialPolicy.allow)
      : exactForwardProjection(sandbox.networkPolicy, a.hostname) &&
        exactForwardProjection(independent.networkPolicy, a.hostname) &&
        exactForwardPolicy(activeSession.networkPolicy, a.hostname, forwardAudience) &&
        exactForwardPolicy(independentSession.networkPolicy, a.hostname, forwardAudience);
    const sameSession = activeSession.sessionId === sessionId && independentSession.sessionId === sessionId;
    return {
      stage,
      activeSandboxPolicy: sandbox.networkPolicy,
      activeSessionPolicy: activeSession.networkPolicy,
      independentSandboxPolicy: independent.networkPolicy,
      independentSessionPolicy: independentSession.networkPolicy,
      initialSessionId: sessionId,
      activeSessionId: activeSession.sessionId,
      independentSessionId: independentSession.sessionId,
      exact,
      sameSession,
      passed: exact && sameSession,
    };
  };

  const runCase = async (input: {
    caseId: CaseId;
    correlationId: string;
    connectionRole: "a" | "p" | "b";
    pinnedDestinationIpv4: string;
    expectedOperationId: string;
    targetForm: ProbeForm;
    targetPath: string;
    bodySource: BodySource;
  }): Promise<GuestCaseEvidence> => {
    if (!sandbox) throw new Error("sandbox is unavailable");
    if (attempts >= MAX_GUEST_REQUESTS) throw new Error("fixed ten-request bound exhausted");
    const configuration = buildProbeConfiguration({
      a,
      p,
      b,
      forwardAudience,
      connectionRole: input.connectionRole,
      pinnedDestinationIpv4: input.pinnedDestinationIpv4,
      expectedOperationId: input.expectedOperationId,
      runId,
      caseId: input.caseId,
      correlationId: input.correlationId,
      targetForm: input.targetForm,
      targetPath: input.targetPath,
      bodySource: input.bodySource,
    });
    attempts += 1;
    const captured = await captureCommand(sandbox, configuration, secrets);
    const record: GuestCaseEvidence = {
      caseId: input.caseId,
      configurationSha256: sha256(JSON.stringify(configuration)),
      command: captured.command,
      ...(captured.result ? { result: captured.result } : {}),
    };
    guestCases.push(record);
    await delay(INTER_REQUEST_MS, undefined, { signal: signal(2_000) });
    return record;
  };

  try {
    liveLock = await acquireLock(lockPath);
    aliasVerification = await verifyAliasIdentity(credentials.token);
    for (const origin of [a, p, b]) {
      if (!(await health(origin))) throw new Error(`${origin.hostname} receiver health check failed`);
      await delay(INTER_REQUEST_MS, undefined, { signal: signal(2_000) });
    }
    if ((await receiverReadback(p, adminKey, runId)).configured) {
      throw new Error("fresh receiver run ID was unexpectedly configured");
    }
    aAddresses = await resolvePublicIpv4(a.hostname);
    pAddresses = await resolvePublicIpv4(p.hostname);
    bAddresses = await resolvePublicIpv4(b.hostname);
    pinnedA = aAddresses[0]!;
    pinnedP = pAddresses[0]!;
    pinnedB = bAddresses[0]!;

    createAttempted = true;
    sandbox = await Sandbox.create({
      name: sandboxName,
      persistent: false,
      timeout: 480_000,
      resources: { vcpus: 2 },
      networkPolicy: initialPolicy,
      tags: sandboxTags,
      signal: signal(),
      ...credentials,
    });
    sessionId = sandbox.currentSession().sessionId;
    if (sandbox.name !== sandboxName || sandbox.tags?.run !== runId || sandbox.tags.test !== TEST_ID) {
      throw new Error("created sandbox identity did not match the exact run");
    }
    const receiverConfiguration = {
      runId,
      aOrigin: a.origin,
      pOrigin: p.origin,
      bOrigin: b.origin,
      forwardAudience,
      expectedTeamId: SBX037_TEAM_ID,
      expectedProjectId: SBX037_PROJECT_ID,
      expectedSandboxId: sessionId,
      expectedSandboxName: sandboxName,
      caseCorrelations: correlations,
      initialBOperationId: publicOperationIds.initialB,
      originOperationId: publicOperationIds.origin,
      syntaxOperationIds: {
        absoluteSyntaxControl: publicOperationIds.absoluteSyntax,
        networkPathSyntaxControl: publicOperationIds.networkSyntax,
        absolutePSyntaxControl: publicOperationIds.absolutePSyntax,
        networkPSyntaxControl: publicOperationIds.networkPSyntax,
      },
      caseOperationIds: {
        absoluteTargetAttack: publicOperationIds.absolute,
        networkPathTargetAttack: publicOperationIds.network,
      },
      expectedActionOperationIds: {
        absoluteTargetAttack: actionOperationIds.absolute,
        networkPathTargetAttack: actionOperationIds.network,
      },
    } satisfies ReceiverConfiguration;
    const registration = await adminRequest(p, adminKey, runId, {
      method: "POST",
      body: JSON.stringify(receiverConfiguration),
    });
    if (registration.status !== 201) throw new Error(`receiver registration returned ${registration.status}`);
    receiverConfigured = true;
    receiver = await receiverReadback(p, adminKey, runId);
    if (!receiver.configured) throw new Error("receiver registration did not read back");

    const probeSource = await readFile(resolve("guest/raw-forwardurl-target-probe.mjs"), "utf8");
    if (secrets.some((secret) => probeSource.includes(secret))) {
      throw new Error("guest probe source contains a controller credential or operator secret");
    }
    await sandbox.writeFiles([
      { path: REMOTE_PROBE_PATH, content: probeSource, mode: 0o700 },
    ], { signal: signal() });

    const initialProof = await policyProof("initial");
    policyProofs.push(initialProof);
    if (!initialProof.passed) throw new IndeterminateControlError("initial A+P+B policy/session proof failed");

    const directAllow = await runCase({
      caseId: "direct-b-allow",
      correlationId: correlations.directBAllow,
      connectionRole: "b",
      pinnedDestinationIpv4: pinnedB,
      expectedOperationId: publicOperationIds.initialB,
      targetForm: "origin",
      targetPath: new URL(directBUrl).pathname,
      bodySource: "public",
    });
    receiver = await receiverReadback(p, adminKey, runId);
    const initialEvents = receiver.directRecords.filter((entry) => entry.caseId === "direct-b-allow");
    if (!conclusiveDirectReachability(
      directAllow.result,
      directAllow.command.exitCode,
      pinnedB,
      publicOperationIds.initialB,
      initialEvents.length,
    )) {
      throw new IndeterminateControlError("initial direct-B allow control failed");
    }

    const absoluteSyntax = await runCase({
      caseId: "absolute-syntax-control",
      correlationId: correlations.absoluteSyntaxControl,
      connectionRole: "a",
      pinnedDestinationIpv4: pinnedA,
      expectedOperationId: publicOperationIds.absoluteSyntax,
      targetForm: "absolute",
      targetPath: collectPath,
      bodySource: "public",
    });
    const networkSyntax = await runCase({
      caseId: "network-path-syntax-control",
      correlationId: correlations.networkPathSyntaxControl,
      connectionRole: "a",
      pinnedDestinationIpv4: pinnedA,
      expectedOperationId: publicOperationIds.networkSyntax,
      targetForm: "network-path",
      targetPath: collectPath,
      bodySource: "public",
    });
    receiver = await receiverReadback(p, adminKey, runId);
    const aSyntaxRuns = [
      {
        record: absoluteSyntax,
        caseId: "absolute-syntax-control" as const,
        correlationId: correlations.absoluteSyntaxControl,
        targetForm: "absolute" as const,
        rawRequestTarget: bCollectUrl,
        operationId: publicOperationIds.absoluteSyntax,
      },
      {
        record: networkSyntax,
        caseId: "network-path-syntax-control" as const,
        correlationId: correlations.networkPathSyntaxControl,
        targetForm: "network-path" as const,
        rawRequestTarget: networkRawTarget,
        operationId: publicOperationIds.networkSyntax,
      },
    ];
    for (const syntax of aSyntaxRuns) {
      const publicBodyBytes = Buffer.byteLength(`public:${syntax.correlationId}`);
      const aRecords = receiver.aRecords.filter((entry) => entry.caseId === syntax.caseId);
      const bEventCount = receiver.bRecords.filter((entry) => entry.caseId === syntax.caseId).length;
      const pEventCount = receiver.pRecords.filter((entry) => entry.caseId === syntax.caseId).length;
      const supported = conclusiveSyntaxControl({
        result: syntax.record.result,
        commandExitCode: syntax.record.command.exitCode,
        pinnedIp: pinnedA,
        runId,
        caseId: syntax.caseId,
        correlationId: syntax.correlationId,
        targetForm: syntax.targetForm,
        rawRequestTarget: syntax.rawRequestTarget,
        operationId: syntax.operationId,
        publicBodyBytes,
        aRecords,
        bEventCount,
        pEventCount,
      });
      const unsupported = conclusiveUnsupportedSyntaxControl({
        result: syntax.record.result,
        commandExitCode: syntax.record.command.exitCode,
        pinnedIp: pinnedA,
        runId,
        caseId: syntax.caseId,
        correlationId: syntax.correlationId,
        targetForm: syntax.targetForm,
        rawRequestTarget: syntax.rawRequestTarget,
        normalizedAPath: collectPath,
        publicBodyBytes,
        aRecords,
        bEventCount,
        pEventCount,
        pSyntaxEventCount: receiver.pSyntaxRecords.filter((entry) => entry.caseId === syntax.caseId).length,
        directEventCount: receiver.directRecords.filter((entry) => entry.caseId === syntax.caseId).length,
      });
      if (supported === unsupported) {
        throw new IndeterminateControlError(`${syntax.caseId} was neither one exact supported form nor one exact A-ingress normalization rejection`);
      }
      syntaxEligibility[syntax.targetForm] = supported ? "supported" : "unsupported";
    }
    if (!Object.values(syntaxEligibility).includes("supported")) {
      throw new IndeterminateControlError("no raw request-target form passed the exact public A syntax control");
    }

    const pSyntaxDefinitions = [
      {
        caseId: "absolute-p-syntax-control" as const,
        correlationId: correlations.absolutePSyntaxControl,
        targetForm: "absolute" as const,
        rawRequestTarget: bCollectUrl,
        operationId: publicOperationIds.absolutePSyntax,
      },
      {
        caseId: "network-p-syntax-control" as const,
        correlationId: correlations.networkPSyntaxControl,
        targetForm: "network-path" as const,
        rawRequestTarget: networkRawTarget,
        operationId: publicOperationIds.networkPSyntax,
      },
    ].filter((syntax) => syntaxEligibility[syntax.targetForm] === "supported");
    const pSyntaxRuns = [];
    for (const syntax of pSyntaxDefinitions) {
      const record = await runCase({
        caseId: syntax.caseId,
        correlationId: syntax.correlationId,
        connectionRole: "p",
        pinnedDestinationIpv4: pinnedP,
        expectedOperationId: syntax.operationId,
        targetForm: syntax.targetForm,
        targetPath: collectPath,
        bodySource: "public",
      });
      pSyntaxRuns.push({ ...syntax, record });
    }
    receiver = await receiverReadback(p, adminKey, runId);
    for (const syntax of pSyntaxRuns) {
      if (!conclusivePSyntaxControl({
        result: syntax.record.result,
        commandExitCode: syntax.record.command.exitCode,
        pinnedIp: pinnedP,
        runId,
        caseId: syntax.caseId,
        correlationId: syntax.correlationId,
        targetForm: syntax.targetForm,
        rawRequestTarget: syntax.rawRequestTarget,
        operationId: syntax.operationId,
        publicBodyBytes: Buffer.byteLength(`public:${syntax.correlationId}`),
        pSyntaxRecords: receiver.pSyntaxRecords.filter((entry) => entry.caseId === syntax.caseId),
        aEventCount: receiver.aRecords.filter((entry) => entry.caseId === syntax.caseId).length,
        bEventCount: receiver.bRecords.filter((entry) => entry.caseId === syntax.caseId).length,
        forwardedPEventCount: receiver.pRecords.filter((entry) => entry.caseId === syntax.caseId).length,
      })) {
        throw new IndeterminateControlError(`${syntax.caseId} did not terminate exactly at P with zero OIDC/A/B events`);
      }
    }

    await sandbox.update({ networkPolicy: finalPolicy }, { signal: signal() });
    await delay(POLICY_SETTLE_MS, undefined, { signal: signal(3_000) });
    const preProof = await policyProof("pre-attack");
    policyProofs.push(preProof);
    if (!preProof.passed) throw new IndeterminateControlError("pre-attack A-to-P policy/session proof failed");

    const directPre = await runCase({
      caseId: "direct-b-pre",
      correlationId: correlations.directBPre,
      connectionRole: "b",
      pinnedDestinationIpv4: pinnedB,
      expectedOperationId: publicOperationIds.directPre,
      targetForm: "origin",
      targetPath: new URL(directBUrl).pathname,
      bodySource: "public",
    });
    receiver = await receiverReadback(p, adminKey, runId);
    if (!conclusiveDirectBlock(
      directPre.result,
      directPre.command.exitCode,
      pinnedB,
      receiver.directRecords.filter((entry) => entry.caseId === "direct-b-pre").length,
    )) {
      throw new IndeterminateControlError("pre-attack direct-B block was not conclusive");
    }

    const origin = await runCase({
      caseId: "origin-form-terminal",
      correlationId: correlations.originFormTerminal,
      connectionRole: "a",
      pinnedDestinationIpv4: pinnedA,
      expectedOperationId: publicOperationIds.origin,
      targetForm: "origin",
      targetPath: originPath,
      bodySource: "public",
    });
    receiver = await receiverReadback(p, adminKey, runId);
    const originRecords = receiver.pRecords.filter((entry) => entry.caseId === "origin-form-terminal");
    if (!conclusiveOriginTerminalControl({
      result: origin.result,
      commandExitCode: origin.command.exitCode,
      pinnedIp: pinnedA,
      operationId: publicOperationIds.origin,
      pRecords: originRecords,
      originCaseAEventCount: receiver.aRecords.filter((entry) => entry.caseId === "origin-form-terminal").length,
      originCaseBEventCount: receiver.bRecords.filter((entry) => entry.caseId === "origin-form-terminal").length,
    })) {
      throw new IndeterminateControlError("origin-form A-to-P terminal OIDC control failed");
    }

    await sandbox.writeFiles([
      { path: REMOTE_SECRET_PATH, content: operatorSecret, mode: 0o600 },
    ], { signal: signal() });

    const attackDefinitions = [
      {
        caseId: "absolute-target-attack" as const,
        correlationId: correlations.absoluteTargetAttack,
        targetForm: "absolute" as const,
        operationId: publicOperationIds.absolute,
      },
      {
        caseId: "network-path-target-attack" as const,
        correlationId: correlations.networkPathTargetAttack,
        targetForm: "network-path" as const,
        operationId: publicOperationIds.network,
      },
    ].filter((attack) => syntaxEligibility[attack.targetForm] === "supported");
    for (const attack of attackDefinitions) {
      await runCase({
        caseId: attack.caseId,
        correlationId: attack.correlationId,
        connectionRole: "a",
        pinnedDestinationIpv4: pinnedA,
        expectedOperationId: attack.operationId,
        targetForm: attack.targetForm,
        targetPath: collectPath,
        bodySource: "file",
      });
    }
    receiver = await receiverReadback(p, adminKey, runId);

    const postProof = await policyProof("post-attack");
    policyProofs.push(postProof);
    if (!postProof.passed) throw new IndeterminateControlError("post-attack A-to-P policy/session proof failed");

    const directPost = await runCase({
      caseId: "direct-b-post",
      correlationId: correlations.directBPost,
      connectionRole: "b",
      pinnedDestinationIpv4: pinnedB,
      expectedOperationId: publicOperationIds.directPost,
      targetForm: "origin",
      targetPath: new URL(directBUrl).pathname,
      bodySource: "public",
    });
    receiver = await receiverReadback(p, adminKey, runId);
    if (!conclusiveDirectBlock(
      directPost.result,
      directPost.command.exitCode,
      pinnedB,
      receiver.directRecords.filter((entry) => entry.caseId === "direct-b-post").length,
    )) {
      throw new IndeterminateControlError("post-attack direct-B block was not conclusive");
    }
  } catch (error) {
    if (error instanceof IndeterminateControlError) controlFailure = safeError(error, secrets);
    else executionError = safeError(error, secrets);
  } finally {
    if (!sandbox && createAttempted) {
      cleanup.orphanRecoveryAttempted = true;
      try {
        const recovered = await Sandbox.get({ name: sandboxName, resume: false, signal: signal(), ...credentials });
        if (recoverableSandboxIdentity({
          createdAt: recovered.createdAt,
          startedAt,
          tags: recovered.tags,
          expectedTags: sandboxTags,
        })) {
          sandbox = recovered;
          cleanup.recovered = true;
        } else {
          cleanup.errors.push("orphan recovery found a nonmatching sandbox and left it untouched");
        }
      } catch (error) {
        if (!isNotFound(error)) cleanup.errors.push(`orphan recovery: ${safeError(error, secrets)}`);
      }
    }
    if (sandbox) {
      cleanup.stopAttempted = true;
      try {
        await sandbox.stop({ signal: signal() });
        cleanup.stopped = true;
      } catch (error) {
        cleanup.errors.push(`stop: ${safeError(error, secrets)}`);
      }
      cleanup.deleteAttempted = true;
      try {
        await sandbox.delete({ signal: signal() });
        cleanup.deleted = true;
      } catch (error) {
        cleanup.errors.push(`delete: ${safeError(error, secrets)}`);
      }
      if (cleanup.deleted) {
        for (let attempt = 0; attempt < 3; attempt += 1) {
          if (attempt > 0) await delay(750, undefined, { signal: signal(2_000) });
          try {
            await Sandbox.get({ name: sandboxName, resume: false, signal: signal(), ...credentials });
          } catch (error) {
            if (isNotFound(error)) cleanup.sandboxAbsenceChecks += 1;
            else cleanup.errors.push(`absence check: ${safeError(error, secrets)}`);
          }
        }
        if (cleanup.sandboxAbsenceChecks !== 3) {
          cleanup.errors.push("sandbox deletion was not confirmed absent three times");
        }
      }
    }
    if (receiverConfigured) {
      cleanup.receiverDeleteAttempted = true;
      try {
        const deletion = await adminRequest(p, adminKey, runId, { method: "DELETE" });
        cleanup.receiverDeleted = deletion.status === 200;
        cleanup.receiverAbsent = !(await receiverReadback(p, adminKey, runId)).configured;
        if (!cleanup.receiverDeleted || !cleanup.receiverAbsent) {
          cleanup.errors.push("receiver state cleanup failed");
        }
      } catch (error) {
        cleanup.errors.push(`receiver cleanup: ${safeError(error, secrets)}`);
      }
    }
    if (liveLock) {
      try {
        await liveLock.close();
        await unlink(lockPath);
        cleanup.liveLockReleased = true;
      } catch (error) {
        cleanup.errors.push(`live lock cleanup: ${safeError(error, secrets)}`);
      }
    }
  }

  const byCase = (caseId: CaseId): GuestCaseEvidence | undefined => guestCases.find((entry) => entry.caseId === caseId);
  const expectedAttacks: Sbx037ExpectedAttackCase[] = ([
    {
      caseId: "absolute-target-attack",
      correlationId: correlations.absoluteTargetAttack,
      targetForm: "absolute",
      rawRequestTarget: bCollectUrl,
      pTerminalUrl: `${forwardAudience}${collectPath}`,
      bCollectUrl,
      operationId: publicOperationIds.absolute,
      actionOperationId: actionOperationIds.absolute,
      terminalStatusCode: 202,
      method: "POST",
      bodySource: "file",
      bodyFileMode: 0o600,
    },
    {
      caseId: "network-path-target-attack",
      correlationId: correlations.networkPathTargetAttack,
      targetForm: "network-path",
      rawRequestTarget: networkRawTarget,
      pTerminalUrl: `${forwardAudience}${collectPath}`,
      bCollectUrl,
      operationId: publicOperationIds.network,
      actionOperationId: actionOperationIds.network,
      terminalStatusCode: 202,
      method: "POST",
      bodySource: "file",
      bodyFileMode: 0o600,
    },
  ] satisfies Sbx037ExpectedAttackCase[]).filter((attack) => syntaxEligibility[attack.targetForm] === "supported");
  const expectedSyntaxControls: Sbx037ExpectedSyntaxControl[] = [
    {
      caseId: "absolute-syntax-control",
      correlationId: correlations.absoluteSyntaxControl,
      targetForm: "absolute",
      rawRequestTarget: bCollectUrl,
      bCollectUrl,
      operationId: publicOperationIds.absoluteSyntax,
      syntaxSupported: syntaxEligibility.absolute === "supported",
      terminalStatusCode: syntaxEligibility.absolute === "supported" ? 202 : 400,
      method: "POST",
      bodySource: "public",
      requestBodyBytes: Buffer.byteLength(`public:${correlations.absoluteSyntaxControl}`),
    },
    {
      caseId: "network-path-syntax-control",
      correlationId: correlations.networkPathSyntaxControl,
      targetForm: "network-path",
      rawRequestTarget: networkRawTarget,
      bCollectUrl,
      operationId: publicOperationIds.networkSyntax,
      syntaxSupported: syntaxEligibility["network-path"] === "supported",
      terminalStatusCode: syntaxEligibility["network-path"] === "supported" ? 202 : 400,
      method: "POST",
      bodySource: "public",
      requestBodyBytes: Buffer.byteLength(`public:${correlations.networkPathSyntaxControl}`),
    },
  ];
  const expectedPSyntaxControls: Sbx037ExpectedSyntaxControl[] = ([
    {
      caseId: "absolute-p-syntax-control",
      correlationId: correlations.absolutePSyntaxControl,
      targetForm: "absolute",
      rawRequestTarget: bCollectUrl,
      bCollectUrl,
      operationId: publicOperationIds.absolutePSyntax,
      syntaxSupported: true,
      terminalStatusCode: 202,
      method: "POST",
      bodySource: "public",
      requestBodyBytes: Buffer.byteLength(`public:${correlations.absolutePSyntaxControl}`),
    },
    {
      caseId: "network-p-syntax-control",
      correlationId: correlations.networkPSyntaxControl,
      targetForm: "network-path",
      rawRequestTarget: networkRawTarget,
      bCollectUrl,
      operationId: publicOperationIds.networkPSyntax,
      syntaxSupported: true,
      terminalStatusCode: 202,
      method: "POST",
      bodySource: "public",
      requestBodyBytes: Buffer.byteLength(`public:${correlations.networkPSyntaxControl}`),
    },
  ] satisfies Sbx037ExpectedSyntaxControl[]).filter((control) =>
    syntaxEligibility[control.targetForm] === "supported");
  const expected: Sbx037ExpectedEvidence = {
    runId,
    testId: TEST_ID,
    aliasEmail: SBX037_ALIAS_EMAIL,
    identity: {
      teamId: SBX037_TEAM_ID,
      projectId: SBX037_PROJECT_ID,
      sandboxId: sessionId ?? "missing-sandbox-id",
      sessionId: sessionId ?? "missing-session-id",
      sandboxName,
    },
    aOrigin: a.origin,
    pOrigin: p.origin,
    bOrigin: b.origin,
    pinnedAIpv4: pinnedA,
    pinnedPIpv4: pinnedP,
    pinnedBIpv4: pinnedB,
    forwardAudienceP: forwardAudience,
    initialBAllow: {
      caseId: "direct-b-allow",
      correlationId: correlations.directBAllow,
      requestUrl: directBUrl,
      operationId: publicOperationIds.initialB,
      statusCode: 202,
    },
    directBPre: { caseId: "direct-b-pre", correlationId: correlations.directBPre, requestUrl: directBUrl },
    directBPost: { caseId: "direct-b-post", correlationId: correlations.directBPost, requestUrl: directBUrl },
    originControl: {
      caseId: "origin-form-terminal",
      correlationId: correlations.originFormTerminal,
      aRequestUrl: originAUrl,
      rawRequestTarget: originPath,
      pTerminalUrl: `${forwardAudience}${originPath}`,
      operationId: publicOperationIds.origin,
      terminalStatusCode: 202,
      method: "POST",
      bodySource: "public",
      requestBodyBytes: Buffer.byteLength(`public:${correlations.originFormTerminal}`),
    },
    syntaxControls: expectedSyntaxControls,
    pSyntaxControls: expectedPSyntaxControls,
    attacks: expectedAttacks,
  };

  const initialCase = byCase("direct-b-allow");
  const preCase = byCase("direct-b-pre");
  const postCase = byCase("direct-b-post");
  const originCase = byCase("origin-form-terminal");
  const initialEvents = receiver.directRecords.filter((entry) => entry.caseId === "direct-b-allow");
  const preEvents = receiver.directRecords.filter((entry) => entry.caseId === "direct-b-pre");
  const postEvents = receiver.directRecords.filter((entry) => entry.caseId === "direct-b-post");
  const originRecords = receiver.pRecords.filter((entry) => entry.caseId === "origin-form-terminal");

  const attacks: Sbx037AttackCaseEvidence[] = expectedAttacks.map((wanted) => {
    const record = byCase(wanted.caseId as CaseId);
    const pRecords = receiver.pRecords.filter((entry) => entry.caseId === wanted.caseId);
    const bRecords = receiver.bRecords.filter((entry) => entry.caseId === wanted.caseId);
    const fallbackRecords = receiver.fallbackRecords.filter((entry) => entry.caseId === wanted.caseId);
    const mappedP = pEvent(pRecords[0]);
    const mappedB = bEvent(bRecords[0]);
    const mappedFallback = fallbackEvent(fallbackRecords[0]);
    return {
      caseId: wanted.caseId,
      targetForm: wanted.targetForm,
      guest: guestEvidence(record, {
        runId,
        correlationId: wanted.correlationId,
        caseId: wanted.caseId,
        targetForm: wanted.targetForm,
        rawRequestTarget: wanted.rawRequestTarget,
        bodySource: "file",
      }, a),
      p: { eventCount: pRecords.length, ...(mappedP ? { event: mappedP } : {}) },
      b: { eventCount: bRecords.length, ...(mappedB ? { event: mappedB } : {}) },
      fallback: {
        eventCount: fallbackRecords.length,
        ...(mappedFallback ? { event: mappedFallback } : {}),
      },
    };
  });
  const syntaxControls: Sbx037SyntaxControlEvidence[] = expectedSyntaxControls.map((wanted) => {
    const record = byCase(wanted.caseId as CaseId);
    const aRecords = receiver.aRecords.filter((entry) => entry.caseId === wanted.caseId);
    const mappedA = syntaxAEvent(aRecords[0]);
    return {
      caseId: wanted.caseId,
      targetForm: wanted.targetForm,
      guest: guestEvidence(record, {
        runId,
        correlationId: wanted.correlationId,
        caseId: wanted.caseId,
        targetForm: wanted.targetForm,
        rawRequestTarget: wanted.rawRequestTarget,
        bodySource: "public",
        publicBodyBytes: wanted.requestBodyBytes,
      }, a),
      a: { eventCount: aRecords.length, ...(mappedA ? { event: mappedA } : {}) },
      bEventCount: receiver.bRecords.filter((entry) => entry.caseId === wanted.caseId).length,
    };
  });
  const pSyntaxControls: Sbx037PSyntaxControlEvidence[] = expectedPSyntaxControls.map((wanted) => {
    const record = byCase(wanted.caseId as CaseId);
    const pSyntaxRecords = receiver.pSyntaxRecords.filter((entry) => entry.caseId === wanted.caseId);
    const mappedP = syntaxPEvent(pSyntaxRecords[0]);
    return {
      caseId: wanted.caseId,
      targetForm: wanted.targetForm,
      guest: guestEvidence(record, {
        runId,
        correlationId: wanted.correlationId,
        caseId: wanted.caseId,
        targetForm: wanted.targetForm,
        rawRequestTarget: wanted.rawRequestTarget,
        bodySource: "public",
        publicBodyBytes: wanted.requestBodyBytes,
      }, p),
      p: { eventCount: pSyntaxRecords.length, ...(mappedP ? { event: mappedP } : {}) },
      bEventCount: receiver.bRecords.filter((entry) => entry.caseId === wanted.caseId).length,
    };
  });
  const preProof = policyProofs.find((entry) => entry.stage === "pre-attack");
  const postProof = policyProofs.find((entry) => entry.stage === "post-attack");
  const initialEvent = initialEvents[0];
  const assessmentInput: Sbx037AssessmentInput = {
    ...(executionError ? { executionError: true } : {}),
    expected,
    scope: {
      authenticatedAliasEmail: aliasVerification?.email ?? "unverified",
      authenticatedTeamId: credentials.teamId,
      authenticatedProjectId: credentials.projectId,
      scopeConfirmation: SCOPE_CONFIRMATION,
      ownedOrigins: [a.origin, p.origin, b.origin],
      unownedEndpointCount: 0,
    },
    policyPre: {
      stage: "pre-attack",
      activeSessionId: preProof?.activeSessionId ?? "missing",
      independentSessionId: preProof?.independentSessionId ?? "missing",
      activePolicy: preProof?.activeSessionPolicy,
      independentPolicy: preProof?.independentSessionPolicy,
    },
    policyPost: {
      stage: "post-attack",
      activeSessionId: postProof?.activeSessionId ?? "missing",
      independentSessionId: postProof?.independentSessionId ?? "missing",
      activePolicy: postProof?.activeSessionPolicy,
      independentPolicy: postProof?.independentSessionPolicy,
    },
    initialBAllow: {
      caseId: "direct-b-allow",
      correlationId: correlations.directBAllow,
      requestUrl: directBUrl,
      maximumConnections: 1,
      actualConnections: initialCase?.result?.actualConnections ?? -1,
      maximumRequests: 1,
      actualRequests: initialCase?.result?.actualRequests ?? -1,
      retryCount: initialCase?.result?.retryCount ?? -1,
      redirectsAllowed: initialCase?.result?.redirectsAllowed ?? true,
      redirectsFollowed: initialCase?.result?.redirectsFollowed ?? -1,
      connectionReused: initialCase?.result?.connectionReused ?? true,
      commandExitCode: initialCase?.command.exitCode ?? -1,
      conclusiveReachability: conclusiveDirectReachability(
        initialCase?.result,
        initialCase?.command.exitCode ?? -1,
        pinnedB,
        publicOperationIds.initialB,
        initialEvents.length,
      ),
      ...(typeof initialCase?.result?.responseStatusCode === "number"
        ? { responseStatusCode: initialCase.result.responseStatusCode }
        : {}),
      ...(initialCase?.result?.responseOperationId
        ? { responseOperationId: initialCase.result.responseOperationId }
        : {}),
      ...(initialCase?.result?.responseRole === "B" ? { responseRole: "B" as const } : {}),
      destinationObserverEventCount: initialEvents.length,
      ...(initialEvent?.operationId && initialEvent.requestUrl
        ? {
            destinationObserverEvent: {
              runId: initialEvent.runId,
              testId: initialEvent.testId,
              caseId: initialEvent.caseId,
              correlationId: initialEvent.correlationId,
              requestUrl: initialEvent.requestUrl,
              operationId: initialEvent.operationId,
            },
          }
        : {}),
    },
    directBPre: {
      caseId: "direct-b-pre",
      correlationId: correlations.directBPre,
      requestUrl: directBUrl,
      maximumConnections: 1,
      actualConnections: preCase?.result?.actualConnections ?? -1,
      maximumRequests: 1,
      actualRequests: preCase?.result?.actualRequests ?? -1,
      commandExitCode: preCase?.command.exitCode ?? -1,
      retryCount: preCase?.result?.retryCount ?? -1,
      redirectsAllowed: preCase?.result?.redirectsAllowed ?? true,
      connectionReused: preCase?.result?.connectionReused ?? true,
      configuredPinnedDestinationIpv4: preCase?.result?.pinnedDestinationIpv4 ?? "missing",
      tcpConnected: preCase?.result?.transport?.tcpConnected === true,
      tlsEstablished: preCase?.result?.transport?.tlsEstablished === true,
      ...(preCase?.result?.transport?.remoteAddress
        ? { observedRemoteAddress: preCase.result.transport.remoteAddress }
        : {}),
      errorCode: preCase?.result?.errorCode ?? "missing",
      durationMs: preCase?.result?.durationMs ?? -1,
      samePinnedDestination: preCase?.result?.pinnedDestinationIpv4 === pinnedB &&
        (preCase.result.transport?.remoteAddress === undefined || preCase.result.transport.remoteAddress === pinnedB),
      conclusiveFirewallBlock: conclusiveDirectBlock(
        preCase?.result,
        preCase?.command.exitCode ?? -1,
        pinnedB,
        preEvents.length,
      ),
      destinationObserverEventCount: preEvents.length,
    },
    directBPost: {
      caseId: "direct-b-post",
      correlationId: correlations.directBPost,
      requestUrl: directBUrl,
      maximumConnections: 1,
      actualConnections: postCase?.result?.actualConnections ?? -1,
      maximumRequests: 1,
      actualRequests: postCase?.result?.actualRequests ?? -1,
      commandExitCode: postCase?.command.exitCode ?? -1,
      retryCount: postCase?.result?.retryCount ?? -1,
      redirectsAllowed: postCase?.result?.redirectsAllowed ?? true,
      connectionReused: postCase?.result?.connectionReused ?? true,
      configuredPinnedDestinationIpv4: postCase?.result?.pinnedDestinationIpv4 ?? "missing",
      tcpConnected: postCase?.result?.transport?.tcpConnected === true,
      tlsEstablished: postCase?.result?.transport?.tlsEstablished === true,
      ...(postCase?.result?.transport?.remoteAddress
        ? { observedRemoteAddress: postCase.result.transport.remoteAddress }
        : {}),
      errorCode: postCase?.result?.errorCode ?? "missing",
      durationMs: postCase?.result?.durationMs ?? -1,
      samePinnedDestination: postCase?.result?.pinnedDestinationIpv4 === pinnedB &&
        (postCase.result.transport?.remoteAddress === undefined || postCase.result.transport.remoteAddress === pinnedB),
      conclusiveFirewallBlock: conclusiveDirectBlock(
        postCase?.result,
        postCase?.command.exitCode ?? -1,
        pinnedB,
        postEvents.length,
      ),
      destinationObserverEventCount: postEvents.length,
    },
    originGuest: guestEvidence(originCase, {
      runId,
      correlationId: correlations.originFormTerminal,
      caseId: "origin-form-terminal",
      targetForm: "origin",
      rawRequestTarget: originPath,
      bodySource: "public",
      publicBodyBytes: Buffer.byteLength(`public:${correlations.originFormTerminal}`),
    }, a),
    originP: {
      eventCount: originRecords.length,
      ...(pEvent(originRecords[0]) ? { event: pEvent(originRecords[0])! } : {}),
    },
    sourceBehavior: {
      redirectsIssued: receiver.terminalInvariant.redirectsIssued,
      outboundFetches: receiver.terminalInvariant.applicationFetches,
      proxiedRequests: receiver.terminalInvariant.applicationProxyAttempts,
    },
    syntaxControls,
    pSyntaxControls,
    attacks,
    unexpectedPEventCount: receiver.aRecords.filter((entry) =>
      !["absolute-syntax-control", "network-path-syntax-control"].includes(entry.caseId)
    ).length + receiver.pRecords.filter((entry) =>
      !["origin-form-terminal", ...expectedAttacks.map((attack) => attack.caseId)].includes(entry.caseId)
    ).length + receiver.pSyntaxRecords.filter((entry) =>
      !expectedPSyntaxControls.map((control) => control.caseId).includes(entry.caseId)
    ).length,
    unexpectedBEventCount: receiver.bRecords.filter((entry) =>
      !expectedAttacks.map((attack) => attack.caseId).includes(entry.caseId)
    ).length,
    unexpectedFallbackEventCount: receiver.fallbackRecords.filter((entry) =>
      !expectedAttacks.map((attack) => attack.caseId).includes(entry.caseId)
    ).length,
    cleanup: {
      stopAttempted: cleanup.stopAttempted,
      stopped: cleanup.stopped,
      deleteAttempted: cleanup.deleteAttempted,
      deleted: cleanup.deleted,
      sandboxAbsenceChecks: cleanup.sandboxAbsenceChecks,
      receiverDeleteAttempted: cleanup.receiverDeleteAttempted,
      receiverDeleted: cleanup.receiverDeleted,
      receiverAbsent: cleanup.receiverAbsent,
      liveLockReleased: cleanup.liveLockReleased,
      errors: cleanup.errors,
    },
    evidenceStorage: {
      fileMode: 0o600,
      rawTokensAbsent: true,
      rawOperatorSecretsAbsent: true,
      controllerCredentialsAbsent: true,
      controllerConfiguredCustomTrustAbsent: true,
      strictTlsVerificationRequired: true,
      inheritedPlatformTrustEnvironmentNamesObserved: observedInheritedPlatformTrustEnvironmentNames(guestCases),
    },
  };
  const assessment = assessSbx037(assessmentInput);
  const evidence = {
    schemaVersion: 2,
    visibility: "private",
    diagnosticInstrumentation: {
      receiverRoleHeaderOnEveryResponse: true,
      correlatedEarlyIngressFallbackRecords: true,
      guestFallbackReceiptJoinRequired: true,
      maximumFallbackRecordsPerRun: 16,
    },
    testId: TEST_ID,
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    scope: "one verified HackerOne-alias account, one sandbox, and three researcher-owned HTTPS origins",
    runtime: { sandboxSdk: "@vercel/sandbox@3.0.0", controllerNode: process.version },
    account: {
      email: aliasVerification?.email ?? "unverified",
      verificationMethod: aliasVerification?.method ?? "unverified",
      teamId: SBX037_TEAM_ID,
      projectId: SBX037_PROJECT_ID,
    },
    origins: { a: a.origin, p: p.origin, b: b.origin, aAddresses, pAddresses, bAddresses, pinnedA, pinnedP, pinnedB },
    sandbox: sessionId ? { name: sandboxName, sessionId } : undefined,
    policy: { initialPolicy, finalPolicy, forwardAudience, proofs: policyProofs },
    bounds: {
      attempts,
      maximum: MAX_GUEST_REQUESTS,
      sequential: true,
      retries: 0,
      redirects: 0,
      minimumDelayMs: INTER_REQUEST_MS,
      maximumQps: 5,
      freshConnectionPerAttempt: true,
    },
    guestCases,
    receiverRecords: receiver,
    retention: {
      rawPlatformTokenStoredLoggedOrReturned: false,
      platformTokenDigestStored: false,
      rawOperatorSecretStoredLoggedOrReturned: false,
      standaloneOperatorSecretDigestStored: false,
      necessaryKeyedActionOperationIdsOnly: actionOperationIds,
      controllerCredentialsEnteredGuest: false,
      controllerConfiguredCustomTrust: false,
      strictTlsRejectUnauthorized: true,
      inheritedPlatformTrustEnvironmentNamesObserved: observedInheritedPlatformTrustEnvironmentNames(guestCases),
      fileSecretEnteredGuestConfiguration: false,
    },
    assessmentInput,
    assessment,
    cleanup,
    ...(controlFailure ? { controlFailure } : {}),
    ...(executionError ? { executionError } : {}),
  };
  const serialized = `${JSON.stringify(evidence, null, 2)}\n`;
  if (secrets.some((secret) => serialized.includes(secret))) {
    throw new Error("refusing to persist a controller credential or raw operator secret");
  }
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const artifactPath = resolve(artifactsDirectory, `SBX-037-${runId}-private.json`);
  await writeFile(artifactPath, serialized, { encoding: "utf8", mode: 0o600, flag: "wx" });
  process.stdout.write(`${JSON.stringify({
    testId: TEST_ID,
    runId,
    verdict: assessment.verdict,
    severity: assessment.severity,
    summary: assessment.summary,
    guestRequestAttempts: attempts,
    cleanupPassed: cleanup.errors.length === 0,
    artifactPath,
  }, null, 2)}\n`);
  process.exitCode = exitCodeForVerdict(assessment.verdict);
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  main().catch((error) => {
    process.stderr.write(`${String(error instanceof Error ? error.message : error).slice(0, 1_000)}\n`);
    process.exitCode = 1;
  });
}
