import "dotenv/config";

import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { Resolver } from "node:dns/promises";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { APIError, Sandbox, type NetworkPolicy } from "@vercel/sandbox";
import {
  assessSbx033,
  authenticatedNativeIpOperationSuccess,
  conclusiveNativeIpFirewallBlock,
  exactDenyAllPolicy,
  type AddressFamily,
  type CanarySource,
  type NativeIpProbeExpectation,
  type NativeIpProbeRecord,
  type SanitizedNativeIpProbeResult,
} from "./verdict.js";

const testId = "SBX-033-POC";
const scopeConfirmation = "I_CONTROL_THE_ENDPOINT_AND_AUTHORIZE_BOUNDED_NATIVE_IPV6_DENY_TESTING";
const remoteProbePath = "/tmp/sbx-033/native-ipv6-deny-probe.py";
const remoteOperatorSecretPath = "/tmp/sbx-033/operator-secret";
const eligibleAliasEmail = "swve@wearehackerone.com";
const eligibleTeamId = "team_n98ERpVwV7HqmWRudAyK8sXQ";
const eligibleProjectId = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
const minimumRequestIntervalMs = 300;
const controlPlaneTimeoutMs = 30_000;
const endpointRequestLimit = 5;
const operationIdPattern = /^h3_[A-Za-z0-9_-]{43}$/u;
const sha256Pattern = /^[a-f0-9]{64}$/u;
const dnsNamePattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const casePlan = {
  "allow-v4-control": { family: "ipv4", source: "controller-public-canary" },
  "allow-v6-control": { family: "ipv6", source: "controller-public-canary" },
  "deny-v4-control": { family: "ipv4", source: "controller-public-canary" },
  "deny-v6-public": { family: "ipv6", source: "controller-public-canary" },
  "deny-v6-secret-target": { family: "ipv6", source: "operator-secret-file" },
} as const satisfies Record<string, { family: AddressFamily; source: CanarySource }>;

type CaseId = keyof typeof casePlan;
type SandboxRole = "allow" | "deny";

interface DnsAnswer {
  address: string;
  ttl: number;
}

interface EndpointDetails {
  url: URL;
  resolvedA: DnsAnswer[];
  resolvedAAAA: DnsAnswer[];
  pinnedIPv4: string;
  pinnedIPv6: string;
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

interface EvidenceProbeRecord extends NativeIpProbeRecord {
  configurationSha256: string;
  command: CommandRecord;
}

interface RequestCounters {
  vercelAttempts: number;
  dnsAttempts: number;
  endpointAttempts: number;
}

interface CleanupRecord {
  role: SandboxRole;
  name: string;
  createAttempted: boolean;
  orphanRecoveryAttempted: boolean;
  recoveredHandle: boolean;
  orphanAbsenceConfirmed: boolean;
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  deletionAbsenceChecksAttempted: number;
  deletionAbsenceChecksPassed: number;
  deletionAbsenceConfirmed: boolean;
  errors: string[];
}

interface SandboxFixture {
  role: SandboxRole;
  name: string;
  tags: Record<string, string>;
  expectedPolicy: NetworkPolicy;
  startedAtMs: number;
  createAttempted: boolean;
  sandbox?: Sandbox;
  sessionId?: string;
  identity?: Record<string, unknown>;
  cleanup: CleanupRecord;
}

class IndeterminateError extends Error {}

class RateGate {
  private lastStartedAt = 0;

  async beforeRequest(): Promise<void> {
    const remaining = minimumRequestIntervalMs - (Date.now() - this.lastStartedAt);
    if (remaining > 0) {
      await delay(remaining, undefined, { signal: AbortSignal.timeout(2_000) });
    }
    this.lastStartedAt = Date.now();
  }
}

function signal(timeoutMs = controlPlaneTimeoutMs): AbortSignal {
  return AbortSignal.timeout(timeoutMs);
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function safeText(value: unknown, maximum = 256): string | undefined {
  return typeof value === "string" ? value.replace(/[\0\r\n]/gu, " ").slice(0, maximum) : undefined;
}

function numeric(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function exactBoolean(value: unknown): boolean | undefined {
  return value === true ? true : value === false ? false : undefined;
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function redact(value: string, secrets: readonly string[]): string {
  return secrets.reduce(
    (output, secret) => secret.length === 0 ? output : output.split(secret).join("[REDACTED]"),
    value,
  );
}

function safeError(error: unknown, secrets: readonly string[]): string {
  return redact(error instanceof Error ? error.message : String(error), secrets)
    .replace(/[\0\r\n]/gu, " ")
    .slice(0, 1_000);
}

function isNotFound(error: unknown): boolean {
  return error instanceof APIError && error.response.status === 404;
}

function canonicalIpv6(value: string): string | undefined {
  if (isIP(value) !== 6 || value !== value.toLowerCase() || value.includes("%")) return undefined;
  try {
    const host = new URL(`http://[${value}]/`).hostname;
    return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : undefined;
  } catch {
    return undefined;
  }
}

export function publicIPv4(value: string): boolean {
  if (isIP(value) !== 4 || value.split(".").some((part) => String(Number(part)) !== part)) return false;
  const [a = -1, b = -1, c = -1] = value.split(".").map(Number);
  if (a <= 0 || a >= 224 || a === 127) return false;
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return false;
  if ((a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127)) return false;
  if ((a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19))) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}

export function publicNativeIPv6(value: string): boolean {
  const canonical = canonicalIpv6(value);
  if (canonical !== value || value.startsWith("::ffff:")) return false;
  const expandedPrefix = Number.parseInt(value.split(":", 1)[0] ?? "", 16);
  if (!Number.isInteger(expandedPrefix)) return false;
  if (value === "::" || value === "::1" || (expandedPrefix & 0xfe00) === 0xfc00) return false;
  if ((expandedPrefix & 0xffc0) === 0xfe80 || (expandedPrefix & 0xff00) === 0xff00) return false;
  if (value.startsWith("2001:db8:") || value === "2001:db8::") return false;
  if (value.startsWith("2001:0:") || value.startsWith("2001::") || value.startsWith("64:ff9b:")) return false;
  return (expandedPrefix & 0xe000) === 0x2000;
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
    throw new Error("SBX-033 must use the verified HackerOne-alias Vercel team and project");
  }
  return { token, teamId, projectId };
}

export function controlledEndpointConfig(environment: NodeJS.ProcessEnv = process.env): {
  url: URL;
  pinnedIPv4: string;
  pinnedIPv6: string;
} {
  if (environment.SBX033_SCOPE_CONFIRMATION !== scopeConfirmation) {
    throw new Error(`SBX033_SCOPE_CONFIRMATION must equal ${scopeConfirmation}`);
  }
  const rawEndpoint = required(environment, "SBX033_ENDPOINT_URL");
  const endpoint = new URL(rawEndpoint);
  if (
    endpoint.protocol !== "https:" || endpoint.username || endpoint.password || endpoint.search || endpoint.hash ||
    endpoint.port !== "" || endpoint.pathname !== "/v1/h3-action" || isIP(endpoint.hostname) !== 0 ||
    endpoint.hostname !== endpoint.hostname.toLowerCase() || !dnsNamePattern.test(endpoint.hostname) ||
    rawEndpoint !== `https://${endpoint.hostname}/v1/h3-action` ||
    endpoint.href !== `https://${endpoint.hostname}/v1/h3-action`
  ) {
    throw new Error("SBX033_ENDPOINT_URL must be one canonical researcher-owned HTTPS /v1/h3-action URL on port 443");
  }
  const pinnedIPv4 = required(environment, "SBX033_PINNED_IPV4");
  const pinnedIPv6 = required(environment, "SBX033_PINNED_IPV6");
  if (!publicIPv4(pinnedIPv4)) throw new Error("SBX033_PINNED_IPV4 must be canonical public IPv4 text");
  if (!publicNativeIPv6(pinnedIPv6)) {
    throw new Error("SBX033_PINNED_IPV6 must be canonical global native IPv6 text");
  }
  return { url: endpoint, pinnedIPv4, pinnedIPv6 };
}

export function expectedOperationId(key: string, runId: string, caseId: string, canary: string): string {
  return `h3_${createHmac("sha256", key).update(`${runId}\n${caseId}\n${canary}`).digest("base64url")}`;
}

export function buildProbeConfiguration(input: {
  endpointUrl: string;
  pinnedAddress: string;
  runId: string;
  caseId: CaseId;
  publicCanary?: string;
}): Record<string, unknown> {
  const definition = casePlan[input.caseId];
  if (definition.source === "controller-public-canary") {
    if (!input.publicCanary || !/^[A-Za-z0-9_-]{24,128}$/u.test(input.publicCanary)) {
      throw new Error("public-control probes require one bounded public canary");
    }
  } else if (input.publicCanary !== undefined) {
    throw new Error("the file-secret target cannot receive a canary in guest configuration");
  }
  const familyAddressValid = definition.family === "ipv4"
    ? publicIPv4(input.pinnedAddress)
    : publicNativeIPv6(input.pinnedAddress);
  if (!familyAddressValid) throw new Error("pinnedAddress does not match the fixed public address family");
  return {
    scopeConfirmation,
    endpointUrl: input.endpointUrl,
    pinnedAddress: input.pinnedAddress,
    addressFamily: definition.family,
    runId: input.runId,
    testId,
    caseId: input.caseId,
    canarySource: definition.source,
    ...(input.publicCanary ? { publicCanary: input.publicCanary } : { operatorSecretPath: remoteOperatorSecretPath }),
    connectTimeoutSeconds: 8,
    ioTimeoutSeconds: 8,
    maxResponseBytes: 1_024,
  };
}

export function sanitizeGuestResult(value: unknown): SanitizedNativeIpProbeResult | undefined {
  const input = record(value);
  if (!input) return undefined;
  const response = record(input.response);
  const operationId = typeof input.operationId === "string" && operationIdPattern.test(input.operationId)
    ? input.operationId
    : undefined;
  const certificateDigest = typeof input.peerCertificateSha256 === "string" &&
      sha256Pattern.test(input.peerCertificateSha256)
    ? input.peerCertificateSha256
    : undefined;
  const result = {
    ok: exactBoolean(input.ok),
    phase: safeText(input.phase, 64),
    runId: safeText(input.runId, 128),
    testId: safeText(input.testId, 128),
    caseId: safeText(input.caseId, 128),
    addressFamily: input.addressFamily === "ipv4" || input.addressFamily === "ipv6"
      ? input.addressFamily
      : undefined,
    canarySource: input.canarySource === "controller-public-canary" || input.canarySource === "operator-secret-file"
      ? input.canarySource
      : undefined,
    endpointHostname: safeText(input.endpointHostname, 253),
    pinnedAddress: safeText(input.pinnedAddress, 64),
    pinnedPort: numeric(input.pinnedPort),
    attemptNumber: numeric(input.attemptNumber),
    maximumRequests: numeric(input.maximumRequests),
    retryCount: numeric(input.retryCount),
    redirectsAllowed: exactBoolean(input.redirectsAllowed),
    freshConnectionRequired: exactBoolean(input.freshConnectionRequired),
    environmentProxyTrust: exactBoolean(input.environmentProxyTrust),
    strictCertificateVerification: exactBoolean(input.strictCertificateVerification),
    hostnameVerificationRequired: exactBoolean(input.hostnameVerificationRequired),
    certificateVerified: exactBoolean(input.certificateVerified),
    hostnameVerified: exactBoolean(input.hostnameVerified),
    selectedAlpn: safeText(input.selectedAlpn, 32),
    tlsVersion: safeText(input.tlsVersion, 32),
    cipherSuite: safeText(input.cipherSuite, 128),
    peerCertificateSha256: certificateDigest,
    peerAddress: safeText(input.peerAddress, 64),
    peerAddressFamily: input.peerAddressFamily === "ipv4" || input.peerAddressFamily === "ipv6"
      ? input.peerAddressFamily
      : undefined,
    peerPort: numeric(input.peerPort),
    nativeIpv6: exactBoolean(input.nativeIpv6),
    secretFileValidated: exactBoolean(input.secretFileValidated),
    secretFileMode: input.secretFileMode === "0600" ? "0600" : undefined,
    secretByteLength: numeric(input.secretByteLength),
    operationId,
    authorized: exactBoolean(input.authorized),
    operationIdShapeValid: exactBoolean(input.operationIdShapeValid),
    ...(response ? {
      response: {
        statusCode: numeric(response.statusCode),
        contentType: safeText(response.contentType, 128),
        cacheControl: safeText(response.cacheControl, 256),
        bodyByteLength: numeric(response.bodyByteLength),
        bodyContainsCanary: exactBoolean(response.bodyContainsCanary),
        rawBodyRetained: exactBoolean(response.rawBodyRetained),
      },
    } : {}),
    errorType: safeText(input.errorType, 96),
    errorErrno: numeric(input.errorErrno),
    errorSyscall: safeText(input.errorSyscall, 32),
    timeout: exactBoolean(input.timeout),
    responseStatusCode: numeric(input.responseStatusCode),
  } as SanitizedNativeIpProbeResult;
  return result;
}

async function vercelRequest<T>(
  gate: RateGate,
  counters: RequestCounters,
  operation: () => Promise<T>,
): Promise<T> {
  await gate.beforeRequest();
  counters.vercelAttempts += 1;
  return await operation();
}

async function verifyAliasIdentity(
  token: string,
  gate: RateGate,
  counters: RequestCounters,
): Promise<string> {
  const response = await vercelRequest(gate, counters, async () => await fetch("https://api.vercel.com/v2/user", {
    headers: { Authorization: `Bearer ${token}` },
    signal: signal(10_000),
  }));
  if (!response.ok) throw new Error(`could not verify Vercel token identity (${response.status})`);
  const payload = await response.json() as { user?: { email?: unknown } };
  if (payload.user?.email !== eligibleAliasEmail) {
    throw new Error("Vercel token is not authenticated as the required HackerOne alias");
  }
  return payload.user.email;
}

function hmacKey(environment: NodeJS.ProcessEnv = process.env): string {
  const key = required(environment, "H3_ACTION_KEY");
  const byteLength = Buffer.byteLength(key);
  if (byteLength < 32 || byteLength > 256 || /[\0\r\n]/u.test(key)) {
    throw new Error("H3_ACTION_KEY must contain 32-256 bytes without control characters");
  }
  return key;
}

async function resolveFamily(
  hostname: string,
  family: AddressFamily,
  counters: RequestCounters,
): Promise<DnsAnswer[]> {
  const resolver = new Resolver();
  const deadline = globalThis.setTimeout(() => resolver.cancel(), 10_000);
  try {
    counters.dnsAttempts += 1;
    const answers = family === "ipv4"
      ? await resolver.resolve4(hostname, { ttl: true })
      : await resolver.resolve6(hostname, { ttl: true });
    return answers
      .filter((answer, index, all) => {
        const valid = family === "ipv4" ? publicIPv4(answer.address) : publicNativeIPv6(answer.address);
        return valid && all.findIndex((candidate) => candidate.address === answer.address) === index;
      })
      .sort((left, right) => left.address.localeCompare(right.address));
  } finally {
    globalThis.clearTimeout(deadline);
  }
}

async function snapshotEndpoint(
  input: ReturnType<typeof controlledEndpointConfig>,
  counters: RequestCounters,
): Promise<EndpointDetails> {
  const resolvedA = await resolveFamily(input.url.hostname, "ipv4", counters);
  const resolvedAAAA = await resolveFamily(input.url.hostname, "ipv6", counters);
  if (!resolvedA.some(({ address }) => address === input.pinnedIPv4)) {
    throw new Error("SBX033_PINNED_IPV4 is not present in the current bounded A snapshot");
  }
  if (!resolvedAAAA.some(({ address }) => address === input.pinnedIPv6)) {
    throw new Error("SBX033_PINNED_IPV6 is not present in the current bounded AAAA snapshot");
  }
  return { ...input, resolvedA, resolvedAAAA };
}

async function captureCommand(
  sandbox: Sandbox,
  gate: RateGate,
  counters: RequestCounters,
  params: Parameters<Sandbox["runCommand"]>[0] & { cmd: string },
  secrets: readonly string[],
  endpointDispatch: boolean,
): Promise<{ record: CommandRecord; stdout: string; stderr: string }> {
  const serializedParameters = JSON.stringify(params);
  if (secrets.some((secret) => secret && serializedParameters.includes(secret))) {
    throw new Error("guest command arguments or environment contained controller-only material");
  }
  if (endpointDispatch) {
    if (counters.endpointAttempts >= endpointRequestLimit) throw new Error("endpoint request limit exhausted");
    counters.endpointAttempts += 1;
  }
  const commandApiTimeoutMs = Math.min(Math.max((params.timeoutMs ?? 15_000) + 15_000, 30_000), 60_000);
  const command = await vercelRequest(gate, counters, async () => await sandbox.runCommand({
    ...params,
    signal: params.signal ?? signal(commandApiTimeoutMs),
  }));
  const stdout = await vercelRequest(gate, counters, async () => await command.stdout({ signal: signal() }));
  const stderr = await vercelRequest(gate, counters, async () => await command.stderr({ signal: signal() }));
  if (Buffer.byteLength(stdout) > 32_000 || Buffer.byteLength(stderr) > 8_000) {
    throw new Error("guest command output exceeded its evidence bound");
  }
  if (secrets.some((secret) => secret && (stdout.includes(secret) || stderr.includes(secret)))) {
    throw new Error("guest command output contained controller-only material");
  }
  return {
    record: {
      commandId: command.cmdId,
      exitCode: command.exitCode,
      ...(command.durationMs !== undefined ? { durationMs: command.durationMs } : {}),
      stdoutByteLength: Buffer.byteLength(stdout),
      stdoutSha256: sha256(stdout),
      stderrByteLength: Buffer.byteLength(stderr),
      stderrSha256: sha256(stderr),
    },
    stdout,
    stderr,
  };
}

function newFixture(role: SandboxRole, runId: string, expectedPolicy: NetworkPolicy): SandboxFixture {
  const name = `sbx-033-${role}-${runId}`;
  return {
    role,
    name,
    tags: { harness: "vsc", test: "SBX-033", run: runId, role },
    expectedPolicy,
    startedAtMs: Date.now(),
    createAttempted: false,
    cleanup: {
      role,
      name,
      createAttempted: false,
      orphanRecoveryAttempted: false,
      recoveredHandle: false,
      orphanAbsenceConfirmed: false,
      stopAttempted: false,
      stopped: false,
      deleteAttempted: false,
      deleted: false,
      deletionAbsenceChecksAttempted: 0,
      deletionAbsenceChecksPassed: 0,
      deletionAbsenceConfirmed: false,
      errors: [],
    },
  };
}

function exactFixtureIdentity(fixture: SandboxFixture, sandbox: Sandbox): boolean {
  const createdAt = sandbox.createdAt.getTime();
  return sandbox.name === fixture.name && sandbox.persistent === false &&
    JSON.stringify(sandbox.networkPolicy) === JSON.stringify(fixture.expectedPolicy) &&
    Number.isFinite(createdAt) && createdAt >= fixture.startedAtMs - 5_000 && createdAt <= Date.now() + 5_000 &&
    sandbox.tags?.harness === fixture.tags.harness && sandbox.tags?.test === fixture.tags.test &&
    sandbox.tags?.run === fixture.tags.run && sandbox.tags?.role === fixture.tags.role;
}

async function createFixture(
  fixture: SandboxFixture,
  credentials: ReturnType<typeof explicitCredentials>,
  gate: RateGate,
  counters: RequestCounters,
): Promise<Sandbox> {
  fixture.startedAtMs = Date.now();
  fixture.createAttempted = true;
  fixture.cleanup.createAttempted = true;
  const sandbox = await vercelRequest(gate, counters, async () => await Sandbox.create({
    name: fixture.name,
    persistent: false,
    timeout: 300_000,
    networkPolicy: fixture.expectedPolicy,
    tags: fixture.tags,
    signal: signal(45_000),
    ...credentials,
  }));
  fixture.sandbox = sandbox;
  const session = sandbox.currentSession();
  fixture.sessionId = session.sessionId;
  fixture.identity = {
    name: sandbox.name,
    createdAt: sandbox.createdAt.toISOString(),
    sessionId: session.sessionId,
    sessionCreatedAt: session.createdAt.toISOString(),
    sessionRequestedAt: session.requestedAt.toISOString(),
    region: session.region,
    persistent: sandbox.persistent,
    sandboxPolicy: sandbox.networkPolicy,
    sessionPolicy: session.networkPolicy,
    tags: sandbox.tags,
  };
  if (!exactFixtureIdentity(fixture, sandbox) ||
      JSON.stringify(session.networkPolicy) !== JSON.stringify(fixture.expectedPolicy)) {
    throw new IndeterminateError(`${fixture.role} fixture identity or initial policy was not exact`);
  }
  return sandbox;
}

async function exactSameSessionReadback(
  fixture: SandboxFixture,
  credentials: ReturnType<typeof explicitCredentials>,
  gate: RateGate,
  counters: RequestCounters,
): Promise<Record<string, unknown>> {
  const sandbox = fixture.sandbox;
  if (!sandbox || !fixture.sessionId) throw new Error(`${fixture.role} fixture is not active`);
  const activeSession = sandbox.currentSession();
  const independent = await vercelRequest(gate, counters, async () => await Sandbox.get({
    name: fixture.name,
    resume: false,
    signal: signal(),
    ...credentials,
  }));
  const independentSession = independent.currentSession();
  const expected = JSON.stringify(fixture.expectedPolicy);
  const passed = activeSession.sessionId === fixture.sessionId &&
    independentSession.sessionId === fixture.sessionId &&
    JSON.stringify(sandbox.networkPolicy) === expected &&
    JSON.stringify(activeSession.networkPolicy) === expected &&
    JSON.stringify(independent.networkPolicy) === expected &&
    JSON.stringify(independentSession.networkPolicy) === expected;
  return {
    passed,
    expectedPolicy: fixture.expectedPolicy,
    originalSessionId: fixture.sessionId,
    activeSessionId: activeSession.sessionId,
    independentSessionId: independentSession.sessionId,
    activeSandboxPolicy: sandbox.networkPolicy,
    activeSessionPolicy: activeSession.networkPolicy,
    independentSandboxPolicy: independent.networkPolicy,
    independentSessionPolicy: independentSession.networkPolicy,
  };
}

async function cleanupFixture(
  fixture: SandboxFixture,
  credentials: ReturnType<typeof explicitCredentials>,
  gate: RateGate,
  counters: RequestCounters,
  secrets: readonly string[],
): Promise<void> {
  const cleanup = fixture.cleanup;
  if (!fixture.sandbox && fixture.createAttempted) {
    cleanup.orphanRecoveryAttempted = true;
    let absent = 0;
    for (let attempt = 0; attempt < 3 && !fixture.sandbox; attempt += 1) {
      if (attempt > 0) await delay(1_000, undefined, { signal: signal(3_000) });
      try {
        const recovered = await vercelRequest(gate, counters, async () => await Sandbox.get({
          name: fixture.name,
          resume: false,
          signal: signal(),
          ...credentials,
        }));
        if (!exactFixtureIdentity(fixture, recovered)) {
          cleanup.errors.push("orphan recovery found a resource without the exact full-UUID identity; left untouched");
          break;
        }
        fixture.sandbox = recovered;
        fixture.sessionId = recovered.currentSession().sessionId;
        cleanup.recoveredHandle = true;
      } catch (error) {
        if (isNotFound(error)) absent += 1;
        else {
          cleanup.errors.push(`orphan recovery: ${safeError(error, secrets)}`);
          break;
        }
      }
    }
    cleanup.orphanAbsenceConfirmed = !fixture.sandbox && absent === 3;
  }
  const sandbox = fixture.sandbox;
  if (!sandbox) return;
  cleanup.stopAttempted = true;
  try {
    await vercelRequest(gate, counters, async () => await sandbox.stop({ signal: signal() }));
    cleanup.stopped = true;
  } catch (error) {
    cleanup.errors.push(`stop: ${safeError(error, secrets)}`);
  }
  cleanup.deleteAttempted = true;
  try {
    await vercelRequest(gate, counters, async () => await sandbox.delete({ signal: signal() }));
    cleanup.deleted = true;
  } catch (error) {
    cleanup.errors.push(`delete: ${safeError(error, secrets)}`);
  }
  if (!cleanup.deleted) return;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    if (attempt > 0) await delay(1_000, undefined, { signal: signal(3_000) });
    cleanup.deletionAbsenceChecksAttempted += 1;
    try {
      await vercelRequest(gate, counters, async () => await Sandbox.get({
        name: fixture.name,
        resume: false,
        signal: signal(),
        ...credentials,
      }));
    } catch (error) {
      if (isNotFound(error)) cleanup.deletionAbsenceChecksPassed += 1;
      else {
        cleanup.errors.push(`deletion absence check: ${safeError(error, secrets)}`);
        break;
      }
    }
  }
  cleanup.deletionAbsenceConfirmed = cleanup.deletionAbsenceChecksAttempted === 3 &&
    cleanup.deletionAbsenceChecksPassed === 3;
  if (!cleanup.deletionAbsenceConfirmed && cleanup.errors.length === 0) {
    cleanup.errors.push("deleted sandbox remained discoverable during three independent absence checks");
  }
}

function cleanupPassed(fixture: SandboxFixture): boolean {
  if (!fixture.createAttempted) return true;
  const cleanup = fixture.cleanup;
  return cleanup.errors.length === 0 && (
    (fixture.sandbox !== undefined && cleanup.stopped && cleanup.deleted && cleanup.deletionAbsenceConfirmed) ||
    (fixture.sandbox === undefined && cleanup.orphanAbsenceConfirmed)
  );
}

export async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  const runId = randomUUID();
  const gate = new RateGate();
  const counters: RequestCounters = { vercelAttempts: 0, dnsAttempts: 0, endpointAttempts: 0 };
  const credentials = explicitCredentials();
  const controllerHmacKey = hmacKey();
  const endpointInput = controlledEndpointConfig();
  const controllerSecrets: string[] = [credentials.token, controllerHmacKey];
  const guestSource = await readFile(resolve("guest/native-ipv6-deny-probe.py"), "utf8");
  if (controllerSecrets.some((secret) => guestSource.includes(secret))) {
    throw new Error("guest source unexpectedly contained controller-only material");
  }

  const allowFixture = newFixture("allow", runId, "allow-all");
  const denyFixture = newFixture("deny", runId, "deny-all");
  const probes: EvidenceProbeRecord[] = [];
  const policyReadbacks: Record<string, unknown>[] = [];
  const publicCanaries: Partial<Record<CaseId, string>> = {
    "allow-v4-control": `public_${randomBytes(18).toString("base64url")}`,
    "allow-v6-control": `public_${randomBytes(18).toString("base64url")}`,
    "deny-v4-control": `public_${randomBytes(18).toString("base64url")}`,
    "deny-v6-public": `public_${randomBytes(18).toString("base64url")}`,
  };
  const operatorSecretSetup: Record<string, unknown> = {
    path: remoteOperatorSecretPath,
    expectedMode: "0600",
    generatedOnlyAfterPublicIpv6Success: false,
    writeAttempted: false,
    written: false,
    metadataVerified: false,
    exactContentMatched: false,
    rawSecretRetainedInOutputOrArtifact: false,
    standaloneSecretDigestRetainedInOutputOrArtifact: false,
  };

  let verifiedAliasEmail: string | undefined;
  let endpoint: EndpointDetails | undefined;
  let dnsStartedAt: string | undefined;
  let dnsCompletedAt: string | undefined;
  let identityAndScopePassed = false;
  let dnsSnapshotPassed = false;
  let allowSandboxCreated = false;
  let allowIpv4Succeeded = false;
  let allowNativeIpv6Succeeded = false;
  let denySandboxCreated = false;
  let denyPolicyReadbackPassed = false;
  let denyIpv4Blocked = false;
  let denyIpv4UnexpectedlySucceeded = false;
  let denyIpv6PublicBlocked = false;
  let denyIpv6PublicSucceeded = false;
  let secretTargetAttempted = false;
  let secretFilePrepared = false;
  let denyIpv6SecretSucceeded = false;
  let denyIpv6SecretBlocked = false;
  let postTargetReadbackPassed = false;
  let executionError: string | undefined;
  let executionIndeterminate = false;
  let operatorSecret: string | undefined;

  async function writeGuest(fixture: SandboxFixture): Promise<void> {
    if (!fixture.sandbox) throw new Error(`${fixture.role} sandbox is unavailable`);
    await vercelRequest(gate, counters, async () => await fixture.sandbox!.writeFiles([
      { path: remoteProbePath, content: guestSource, mode: 0o700 },
    ], { signal: signal() }));
  }

  async function runProbe(fixture: SandboxFixture, caseId: CaseId): Promise<EvidenceProbeRecord> {
    if (!fixture.sandbox || !endpoint) throw new Error("probe fixture or endpoint snapshot is unavailable");
    const definition = casePlan[caseId];
    const publicCanary = definition.source === "controller-public-canary" ? publicCanaries[caseId] : undefined;
    const pinnedAddress = definition.family === "ipv4" ? endpoint.pinnedIPv4 : endpoint.pinnedIPv6;
    const configuration = buildProbeConfiguration({
      endpointUrl: endpoint.url.href,
      pinnedAddress,
      runId,
      caseId,
      ...(publicCanary ? { publicCanary } : {}),
    });
    const serialized = JSON.stringify(configuration);
    if (controllerSecrets.some((secret) => serialized.includes(secret))) {
      throw new Error(`${caseId} guest configuration contained controller-only material`);
    }
    const requestCanary = definition.source === "operator-secret-file" ? operatorSecret : publicCanary;
    if (!requestCanary) throw new Error(`${caseId} has no gated canary source`);
    const captured = await captureCommand(
      fixture.sandbox,
      gate,
      counters,
      {
        cmd: "python3",
        args: [remoteProbePath, Buffer.from(serialized).toString("base64url")],
        env: { HTTP_PROXY: "", HTTPS_PROXY: "", ALL_PROXY: "", NO_PROXY: "*" },
        timeoutMs: 20_000,
      },
      controllerSecrets,
      true,
    );
    let decoded: unknown;
    try {
      decoded = JSON.parse(captured.stdout);
    } catch {
      throw new IndeterminateError(`${caseId} emitted invalid JSON`);
    }
    const result = sanitizeGuestResult(decoded);
    const probe: EvidenceProbeRecord = {
      caseId,
      addressFamily: definition.family,
      canarySource: definition.source,
      configurationSha256: sha256(serialized),
      expectedOperationId: expectedOperationId(controllerHmacKey, runId, caseId, requestCanary),
      commandExitCode: captured.record.exitCode,
      command: captured.record,
      ...(result ? { result } : {}),
    };
    probes.push(probe);
    return probe;
  }

  function expectation(caseId: CaseId): NativeIpProbeExpectation {
    if (!endpoint) throw new Error("endpoint snapshot is unavailable");
    const definition = casePlan[caseId];
    return {
      runId,
      testId,
      caseId,
      addressFamily: definition.family,
      canarySource: definition.source,
      endpointHostname: endpoint.url.hostname,
      pinnedAddress: definition.family === "ipv4" ? endpoint.pinnedIPv4 : endpoint.pinnedIPv6,
    };
  }

  try {
    verifiedAliasEmail = await verifyAliasIdentity(credentials.token, gate, counters);
    identityAndScopePassed = true;
    dnsStartedAt = new Date().toISOString();
    endpoint = await snapshotEndpoint(endpointInput, counters);
    dnsCompletedAt = new Date().toISOString();
    dnsSnapshotPassed = true;

    try {
      await createFixture(allowFixture, credentials, gate, counters);
      allowSandboxCreated = true;
      const allowReadback = await exactSameSessionReadback(allowFixture, credentials, gate, counters);
      policyReadbacks.push({ stage: "allow-all-pre-controls", at: new Date().toISOString(), ...allowReadback });
      if (allowReadback.passed !== true) {
        throw new IndeterminateError("allow-all active and independent same-session readback failed");
      }
      await writeGuest(allowFixture);
      const allowV4 = await runProbe(allowFixture, "allow-v4-control");
      allowIpv4Succeeded = authenticatedNativeIpOperationSuccess(allowV4, expectation("allow-v4-control"));
      if (!allowIpv4Succeeded) throw new IndeterminateError("allow-all fixed IPv4 TLS/HMAC control failed");
      const allowV6 = await runProbe(allowFixture, "allow-v6-control");
      allowNativeIpv6Succeeded = authenticatedNativeIpOperationSuccess(allowV6, expectation("allow-v6-control"));
      if (!allowNativeIpv6Succeeded) {
        throw new IndeterminateError("allow-all fixed native IPv6 TLS/HMAC control was unavailable");
      }
    } finally {
      await cleanupFixture(allowFixture, credentials, gate, counters, controllerSecrets);
    }
    if (!cleanupPassed(allowFixture)) throw new Error("allow-all fixture cleanup failed");

    try {
      await createFixture(denyFixture, credentials, gate, counters);
      denySandboxCreated = true;
      const denyReadback = await exactSameSessionReadback(denyFixture, credentials, gate, counters);
      denyPolicyReadbackPassed = denyReadback.passed === true &&
        exactDenyAllPolicy(denyReadback.activeSandboxPolicy) &&
        exactDenyAllPolicy(denyReadback.independentSandboxPolicy);
      policyReadbacks.push({ stage: "deny-all-pre-probes", at: new Date().toISOString(), ...denyReadback });
      if (!denyPolicyReadbackPassed) {
        throw new IndeterminateError("literal deny-all active and independent same-session readback failed");
      }
      await writeGuest(denyFixture);
      const denyV4 = await runProbe(denyFixture, "deny-v4-control");
      denyIpv4Blocked = conclusiveNativeIpFirewallBlock(denyV4, expectation("deny-v4-control"));
      denyIpv4UnexpectedlySucceeded = authenticatedNativeIpOperationSuccess(
        denyV4,
        expectation("deny-v4-control"),
      );
      if (!denyIpv4Blocked || denyIpv4UnexpectedlySucceeded) {
        throw new IndeterminateError("deny-all fixed IPv4 discriminator was not one conclusive block");
      }

      const denyV6Public = await runProbe(denyFixture, "deny-v6-public");
      denyIpv6PublicBlocked = conclusiveNativeIpFirewallBlock(denyV6Public, expectation("deny-v6-public"));
      denyIpv6PublicSucceeded = authenticatedNativeIpOperationSuccess(
        denyV6Public,
        expectation("deny-v6-public"),
      );

      if (denyIpv6PublicSucceeded && !denyIpv6PublicBlocked) {
        operatorSecret = randomBytes(32).toString("base64url");
        controllerSecrets.push(operatorSecret);
        operatorSecretSetup.generatedOnlyAfterPublicIpv6Success = true;
        operatorSecretSetup.writeAttempted = true;
        await vercelRequest(gate, counters, async () => await denyFixture.sandbox!.writeFiles([
          { path: remoteOperatorSecretPath, content: operatorSecret!, mode: 0o600 },
        ], { signal: signal() }));
        operatorSecretSetup.written = true;
        const verification = await captureCommand(
          denyFixture.sandbox!,
          gate,
          counters,
          {
            cmd: "python3",
            args: [
              "-c",
              `import os,stat; p=${JSON.stringify(remoteOperatorSecretPath)}; fd=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)); s=os.fstat(fd); d=os.read(fd,129); os.close(fd); assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o600 and len(d)==s.st_size and 24<=len(d)<=128; print('OK')`,
            ],
            timeoutMs: 10_000,
          },
          controllerSecrets,
          false,
        );
        operatorSecretSetup.verificationCommand = verification.record;
        const observed = await vercelRequest(gate, counters, async () => await denyFixture.sandbox!.readFileToBuffer(
          { path: remoteOperatorSecretPath },
          { signal: signal() },
        ));
        const expected = Buffer.from(operatorSecret, "ascii");
        const exactContentMatched = observed !== null && observed.equals(expected);
        observed?.fill(0);
        expected.fill(0);
        operatorSecretSetup.metadataVerified = verification.record.exitCode === 0 &&
          verification.stdout.trim() === "OK";
        operatorSecretSetup.exactContentMatched = exactContentMatched;
        secretFilePrepared = operatorSecretSetup.metadataVerified === true && exactContentMatched;
        if (!secretFilePrepared) throw new IndeterminateError("gated mode-0600 operator secret setup failed");
        secretTargetAttempted = true;
        const denySecret = await runProbe(denyFixture, "deny-v6-secret-target");
        denyIpv6SecretSucceeded = authenticatedNativeIpOperationSuccess(
          denySecret,
          expectation("deny-v6-secret-target"),
        );
        denyIpv6SecretBlocked = conclusiveNativeIpFirewallBlock(
          denySecret,
          expectation("deny-v6-secret-target"),
        );
      }

      const postReadback = await exactSameSessionReadback(denyFixture, credentials, gate, counters);
      postTargetReadbackPassed = postReadback.passed === true &&
        exactDenyAllPolicy(postReadback.activeSandboxPolicy) &&
        exactDenyAllPolicy(postReadback.independentSandboxPolicy);
      policyReadbacks.push({ stage: "deny-all-post-target", at: new Date().toISOString(), ...postReadback });
      if (!postTargetReadbackPassed) {
        throw new IndeterminateError("post-target literal deny-all same-session readback failed");
      }
      if (!denyIpv6PublicBlocked && !denyIpv6PublicSucceeded) {
        throw new IndeterminateError("deny-all native IPv6 public result was not one conclusive block or authenticated success");
      }
    } finally {
      await cleanupFixture(denyFixture, credentials, gate, counters, controllerSecrets);
    }
    if (!cleanupPassed(denyFixture)) throw new Error("deny-all fixture cleanup failed");
  } catch (error) {
    executionError = safeError(error, controllerSecrets);
    executionIndeterminate = error instanceof IndeterminateError;
  } finally {
    if (allowFixture.createAttempted && !cleanupPassed(allowFixture) &&
        !allowFixture.cleanup.stopAttempted && !allowFixture.cleanup.orphanRecoveryAttempted) {
      await cleanupFixture(allowFixture, credentials, gate, counters, controllerSecrets);
    }
    if (denyFixture.createAttempted && !cleanupPassed(denyFixture) &&
        !denyFixture.cleanup.stopAttempted && !denyFixture.cleanup.orphanRecoveryAttempted) {
      await cleanupFixture(denyFixture, credentials, gate, counters, controllerSecrets);
    }
  }

  const allCleanupPassed = cleanupPassed(allowFixture) && cleanupPassed(denyFixture);
  const assessment = assessSbx033({
    identityAndScopePassed,
    dnsSnapshotPassed,
    allowSandboxCreated,
    allowIpv4Succeeded,
    allowNativeIpv6Succeeded,
    denySandboxCreated,
    denyPolicyReadbackPassed,
    denyIpv4Blocked,
    denyIpv4UnexpectedlySucceeded,
    denyIpv6PublicBlocked,
    denyIpv6PublicSucceeded,
    secretTargetAttempted,
    secretFilePrepared,
    denyIpv6SecretSucceeded,
    denyIpv6SecretBlocked,
    postTargetReadbackPassed,
    cleanupPassed: allCleanupPassed,
    ...(executionError && !executionIndeterminate ? { executionError: true } : {}),
  });
  const evidence = {
    schemaVersion: 2,
    visibility: "private",
    testId: "SBX-033",
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    scope: "two fresh researcher-owned Vercel sandboxes and one explicitly confirmed researcher-owned dual-stack HTTPS endpoint",
    hypothesis: "literal deny-all may fail to intercept a fixed native IPv6 TCP/TLS path while intercepting the equivalent fixed IPv4 path",
    credentialContext: {
      mode: "explicit-alias-verified",
      email: verifiedAliasEmail,
      teamId: credentials.teamId,
      projectId: credentials.projectId,
      identityEndpoint: "/v2/user",
    },
    dnsSnapshot: endpoint ? {
      startedAt: dnsStartedAt,
      completedAt: dnsCompletedAt,
      hostname: endpoint.url.hostname,
      path: endpoint.url.pathname,
      resolvedA: endpoint.resolvedA,
      resolvedAAAA: endpoint.resolvedAAAA,
      selectedIPv4: endpoint.pinnedIPv4,
      selectedNativeIPv6: endpoint.pinnedIPv6,
      suppliedPinsPresentInCurrentSnapshot: dnsSnapshotPassed,
    } : undefined,
    requestBounds: {
      vercelAttempts: counters.vercelAttempts,
      dnsAttempts: counters.dnsAttempts,
      endpointAttempts: counters.endpointAttempts,
      maximumEndpointRequests: endpointRequestLimit,
      sequential: true,
      retries: 0,
      redirects: 0,
      minimumRequestIntervalMs,
      maximumRequestRatePerSecond: 1_000 / minimumRequestIntervalMs,
      connectTimeoutSeconds: 8,
      ioTimeoutSeconds: 8,
      dnsTimeoutSeconds: 10,
    },
    fixtures: {
      allow: allowFixture.identity,
      deny: denyFixture.identity,
    },
    policy: {
      allowRequested: "allow-all" satisfies NetworkPolicy,
      denyRequested: "deny-all" satisfies NetworkPolicy,
      readbacks: policyReadbacks,
    },
    operatorSecretSetup,
    probes,
    controls: {
      identityAndScopePassed,
      dnsSnapshotPassed,
      allowSandboxCreated,
      allowIpv4Succeeded,
      allowNativeIpv6Succeeded,
      denySandboxCreated,
      denyPolicyReadbackPassed,
      denyIpv4Blocked,
      denyIpv4UnexpectedlySucceeded,
      denyIpv6PublicBlocked,
      denyIpv6PublicSucceeded,
      secretTargetAttempted,
      secretFilePrepared,
      denyIpv6SecretSucceeded,
      denyIpv6SecretBlocked,
      postTargetReadbackPassed,
    },
    secretGuards: {
      hmacKeyEnteredGuestSourceConfigurationArgumentsOutputOrArtifact: false,
      vercelTokenEnteredGuestSourceConfigurationArgumentsOutputOrArtifact: false,
      rawOperatorSecretEnteredGuestSourceConfigurationArgumentsOutputOrArtifact: false,
      standaloneReversibleOperatorSecretDigestRetained: false,
      keyedActionReceiptRetained: true,
      rawResponseBodyRetained: false,
    },
    cleanup: {
      allow: allowFixture.cleanup,
      deny: denyFixture.cleanup,
      passed: allCleanupPassed,
    },
    assessment,
    ...(executionError ? { executionError } : {}),
  };
  const serializedEvidence = `${JSON.stringify(evidence, null, 2)}\n`;
  if (controllerSecrets.some((secret) => secret && serializedEvidence.includes(secret))) {
    throw new Error("refusing to write evidence containing controller-only material");
  }
  await mkdir(resolve("artifacts"), { recursive: true, mode: 0o700 });
  const privateEvidencePath = resolve("artifacts", `SBX-033-${runId}-private.json`);
  await writeFile(privateEvidencePath, serializedEvidence, { encoding: "utf8", mode: 0o600, flag: "wx" });
  process.stdout.write(`${JSON.stringify({
    testId: "SBX-033",
    runId,
    verdict: assessment.verdict,
    candidate: assessment.candidate,
    nativeIpv6Available: assessment.nativeIpv6Available,
    controlsPassed: assessment.controlsPassed,
    endpointRequestAttempts: counters.endpointAttempts,
    cleanupPassed: allCleanupPassed,
    privateEvidencePath,
    ...(executionError ? { executionError } : {}),
  }, null, 2)}\n`);
  if (assessment.verdict !== "pass") process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
