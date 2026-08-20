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
  assessSbx032,
  authenticatedTlsOperationSuccess,
  conclusiveTlsFirewallBlock,
  exactSingleHostAllowPolicy,
  type SanitizedTlsProbeResult,
  type TlsProbeRecord,
  type TlsTransmissionMode,
} from "./verdict.js";

const testId = "SBX-032-POC";
const scopeConfirmation = "I_CONTROL_BOTH_ENDPOINTS_AND_AUTHORIZE_BOUNDED_TLS_REASSEMBLY_TESTING";
const remoteProbePath = "/tmp/sbx-032/tls-record-reassembly-probe.py";
const remoteOperatorSecretPath = "/tmp/sbx-032/operator-secret";
const minimumEndpointRequestIntervalMs = 300;
const policySettleDelayMs = 1_500;
const controlPlaneTimeoutMs = 30_000;
const eligibleAliasEmail = "swve@wearehackerone.com";
const eligibleTeamId = "team_n98ERpVwV7HqmWRudAyK8sXQ";
const eligibleProjectId = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
const allowedEndpointHostname = "vsc-tls-allow-swve.cyrus-206.workers.dev";
const deniedEndpointHostname = "vsc-tls-deny-swve.cyrus-206.workers.dev";
const operationIdPattern = /^h3_[A-Za-z0-9_-]{43}$/u;
const sha256Pattern = /^[a-f0-9]{64}$/u;
const dnsNamePattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;

type EndpointRole = "allowed" | "denied";
type CanarySource = "controller-public-canary" | "operator-secret-file";
type CaseId =
  | "allow-normal-b-control"
  | "allow-tcp-segmented-b-control"
  | "allow-record-fragmented-b-control"
  | "restricted-normal-a-control"
  | "restricted-record-fragmented-a-control"
  | "restricted-normal-b-negative"
  | "restricted-record-fragmented-b-target"
  | "restricted-record-fragmented-b-public-negative"
  | "restricted-normal-b-post-negative";

interface EndpointDetails {
  url: URL;
  answers: Array<{ address: string; ttl: number }>;
  pinnedIPv4: string;
}

interface CaseDefinition {
  caseId: CaseId;
  endpointRole: EndpointRole;
  transmissionMode: TlsTransmissionMode;
  canarySource: CanarySource;
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

interface EvidenceProbeRecord extends TlsProbeRecord {
  canarySource: CanarySource;
  configurationSha256: string;
  publicCanarySha256?: string;
  command: CommandRecord;
}

class IndeterminateError extends Error {}

class EndpointRateGate {
  private lastEndpointRequestStartedAt = 0;

  async beforeEndpointRequest(): Promise<void> {
    const remaining = minimumEndpointRequestIntervalMs - (Date.now() - this.lastEndpointRequestStartedAt);
    if (remaining > 0) await delay(remaining, undefined, { signal: AbortSignal.timeout(2_000) });
    this.lastEndpointRequestStartedAt = Date.now();
  }
}

function controlSignal(timeoutMs = controlPlaneTimeoutMs): AbortSignal {
  return AbortSignal.timeout(timeoutMs);
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
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

function numberArray(value: unknown, maximumItems: number): number[] | undefined {
  if (!Array.isArray(value) || value.length > maximumItems || !value.every((item) => Number.isInteger(item))) {
    return undefined;
  }
  return value as number[];
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

function canonicalDnsName(value: string, field: string): string {
  const canonical = value.toLowerCase();
  if (value !== canonical || !dnsNamePattern.test(canonical)) {
    throw new Error(`${field} must be a lowercase canonical DNS hostname`);
  }
  return canonical;
}

function controlledEndpoint(name: string, expectedHostname: string): URL {
  const endpoint = new URL(required(name));
  if (
    endpoint.protocol !== "https:" || endpoint.username || endpoint.password || endpoint.search || endpoint.hash ||
    endpoint.port !== "" || endpoint.pathname !== "/v1/h3-action" || isIP(endpoint.hostname) !== 0 ||
    endpoint.hostname !== expectedHostname
  ) {
    throw new Error(
      `${name} must be a researcher-owned HTTPS URL on port 443 at /v1/h3-action with no credentials, query, or fragment`,
    );
  }
  canonicalDnsName(endpoint.hostname, `${name} hostname`);
  if (endpoint.href !== `https://${endpoint.hostname}/v1/h3-action`) {
    throw new Error(`${name} must use canonical URL form`);
  }
  return endpoint;
}

function controlledEndpoints(): { allowed: URL; denied: URL } {
  if (required("SBX032_SCOPE_CONFIRMATION") !== scopeConfirmation) {
    throw new Error(`SBX032_SCOPE_CONFIRMATION must equal ${scopeConfirmation}`);
  }
  const allowed = controlledEndpoint("SBX032_ALLOWED_ENDPOINT_URL", allowedEndpointHostname);
  const denied = controlledEndpoint("SBX032_DENIED_ENDPOINT_URL", deniedEndpointHostname);
  if (allowed.hostname === denied.hostname) {
    throw new Error("SBX032 allowed and denied endpoint hostnames must be distinct");
  }
  return { allowed, denied };
}

function hmacKey(): string {
  const key = required("H3_ACTION_KEY");
  if (Buffer.byteLength(key) < 32 || Buffer.byteLength(key) > 256 || /[\0\r\n]/u.test(key)) {
    throw new Error("H3_ACTION_KEY must contain 32-256 bytes without control characters");
  }
  return key;
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
    throw new Error("SBX-032 must use the verified HackerOne-alias Vercel team and project");
  }
  return { token, teamId, projectId };
}

async function verifyAliasIdentity(token: string): Promise<string> {
  const response = await fetch("https://api.vercel.com/v2/user", {
    headers: { Authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error(`could not verify Vercel token identity (${response.status})`);
  const payload = await response.json() as { user?: { email?: unknown } };
  if (payload.user?.email !== eligibleAliasEmail) {
    throw new Error("Vercel token is not authenticated as the required HackerOne alias");
  }
  return payload.user.email;
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

async function resolveEndpoint(url: URL): Promise<EndpointDetails> {
  const resolver = new Resolver();
  const deadline = globalThis.setTimeout(() => resolver.cancel(), 10_000);
  let resolved: Array<{ address: string; ttl: number }>;
  try {
    resolved = await resolver.resolve4(url.hostname, { ttl: true });
  } finally {
    globalThis.clearTimeout(deadline);
  }
  const answers = resolved.filter((answer, index, all) =>
    publicIPv4(answer.address) && all.findIndex((candidate) => candidate.address === answer.address) === index
  ).sort((left, right) => left.address.localeCompare(right.address));
  if (answers.length === 0) throw new Error(`${url.hostname} did not resolve to a public IPv4 address`);
  return { url, answers, pinnedIPv4: answers[0]!.address };
}

export function expectedOperationId(key: string, runId: string, caseId: string, canary: string): string {
  return `h3_${createHmac("sha256", key).update(`${runId}\n${caseId}\n${canary}`).digest("base64url")}`;
}

export function buildProbeConfiguration(input: {
  allowedEndpointUrl: string;
  allowedPinnedIPv4: string;
  deniedEndpointUrl: string;
  deniedPinnedIPv4: string;
  runId: string;
  caseId: CaseId;
  transmissionMode: TlsTransmissionMode;
  publicCanary?: string;
}): Record<string, unknown> {
  const definition = caseDefinitions.find((candidate) => candidate.caseId === input.caseId);
  if (!definition || definition.transmissionMode !== input.transmissionMode) {
    throw new Error("caseId and transmissionMode must match the fixed SBX-032 matrix");
  }
  if (definition.canarySource === "operator-secret-file" && input.publicCanary !== undefined) {
    throw new Error("the target case cannot receive a public canary");
  }
  if (
    definition.canarySource === "controller-public-canary" &&
    (!input.publicCanary || !/^[A-Za-z0-9_-]{16,128}$/u.test(input.publicCanary))
  ) {
    throw new Error("control cases require one bounded public canary");
  }
  return {
    scopeConfirmation,
    allowedEndpointUrl: input.allowedEndpointUrl,
    allowedPinnedIPv4: input.allowedPinnedIPv4,
    deniedEndpointUrl: input.deniedEndpointUrl,
    deniedPinnedIPv4: input.deniedPinnedIPv4,
    runId: input.runId,
    testId,
    caseId: input.caseId,
    transmissionMode: input.transmissionMode,
    ...(input.publicCanary ? { publicCanary: input.publicCanary } : {}),
    timeoutSeconds: 8,
    maxResponseBytes: 1_024,
  };
}

function sanitizeGuestResult(value: unknown): SanitizedTlsProbeResult | undefined {
  const input = record(value);
  if (!input) return undefined;
  const response = record(input.response);
  const hello = record(input.clientHello);
  const operationId = typeof input.operationId === "string" && operationIdPattern.test(input.operationId)
    ? input.operationId
    : undefined;
  const sha = (candidate: unknown): string | undefined =>
    typeof candidate === "string" && sha256Pattern.test(candidate) ? candidate : undefined;
  return {
    ok: exactBoolean(input.ok),
    phase: safeText(input.phase, 64),
    runId: safeText(input.runId, 128),
    testId: safeText(input.testId, 128),
    caseId: safeText(input.caseId, 128),
    endpointRole: input.endpointRole === "allowed" || input.endpointRole === "denied"
      ? input.endpointRole
      : undefined,
    transmissionMode: input.transmissionMode === "normal" || input.transmissionMode === "tcp-segmented" ||
      input.transmissionMode === "record-fragmented" ? input.transmissionMode : undefined,
    canarySource: input.canarySource === "controller-public-canary" || input.canarySource === "operator-secret-file"
      ? input.canarySource
      : undefined,
    endpointHostname: safeText(input.endpointHostname, 253),
    pinnedIPv4: safeText(input.pinnedIPv4, 64),
    pinnedPort: numeric(input.pinnedPort),
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
    peerCertificateSha256: sha(input.peerCertificateSha256),
    peerIPv4: safeText(input.peerIPv4, 64),
    peerPort: numeric(input.peerPort),
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
    ...(hello ? {
      clientHello: {
        source: hello.source === "python-sslobject-memorybio" ? hello.source : undefined,
        outerSni: safeText(hello.outerSni, 253),
        originalRecordCount: numeric(hello.originalRecordCount),
        transmittedRecordCount: numeric(hello.transmittedRecordCount),
        originalFirstFlightSha256: sha(hello.originalFirstFlightSha256),
        transmittedFirstFlightSha256: sha(hello.transmittedFirstFlightSha256),
        clientHelloPayloadSha256: sha(hello.clientHelloPayloadSha256),
        reassembledClientHelloPayloadSha256: sha(hello.reassembledClientHelloPayloadSha256),
        reassemblyMatchesOriginal: exactBoolean(hello.reassemblyMatchesOriginal),
        splitLocation: hello.splitLocation === "server_name.hostname" ? hello.splitLocation : undefined,
        sniHostnameByteLength: numeric(hello.sniHostnameByteLength),
        sniHostnameStartOffsetInRecordPayload: numeric(hello.sniHostnameStartOffsetInRecordPayload),
        sniHostnameEndOffsetInRecordPayload: numeric(hello.sniHostnameEndOffsetInRecordPayload),
        splitOffsetInRecordPayload: numeric(hello.splitOffsetInRecordPayload),
        originalRecordPayloadLength: numeric(hello.originalRecordPayloadLength),
        fragmentPayloadLengths: numberArray(hello.fragmentPayloadLengths, 2),
        initialSocketWriteCount: numeric(hello.initialSocketWriteCount),
        rawClientHelloRetained: exactBoolean(hello.rawClientHelloRetained),
      },
    } : {}),
    errorType: safeText(input.errorType, 96),
    errorErrno: numeric(input.errorErrno),
    timeout: exactBoolean(input.timeout),
    responseStatusCode: numeric(input.responseStatusCode),
  };
}

async function captureCommand(
  sandbox: Sandbox,
  params: Parameters<Sandbox["runCommand"]>[0] & { cmd: string },
  secrets: string[],
): Promise<{ record: CommandRecord; stdout: string; stderr: string }> {
  const serializedParameters = JSON.stringify(params);
  if (secrets.some((secret) => secret && serializedParameters.includes(secret))) {
    throw new Error("guest command arguments or environment contained controller-only material");
  }
  const commandApiTimeoutMs = Math.min(Math.max((params.timeoutMs ?? 15_000) + 15_000, 30_000), 90_000);
  const command = await sandbox.runCommand({
    ...params,
    signal: params.signal ?? controlSignal(commandApiTimeoutMs),
  });
  const outputSignal = controlSignal();
  const [stdout, stderr] = await Promise.all([
    command.stdout({ signal: outputSignal }),
    command.stderr({ signal: outputSignal }),
  ]);
  if (Buffer.byteLength(stdout) > 64_000 || Buffer.byteLength(stderr) > 16_000) {
    throw new Error("guest command output exceeded the fixed evidence bound");
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

const caseDefinitions: readonly CaseDefinition[] = [
  {
    caseId: "allow-normal-b-control",
    endpointRole: "denied",
    transmissionMode: "normal",
    canarySource: "controller-public-canary",
  },
  {
    caseId: "allow-tcp-segmented-b-control",
    endpointRole: "denied",
    transmissionMode: "tcp-segmented",
    canarySource: "controller-public-canary",
  },
  {
    caseId: "allow-record-fragmented-b-control",
    endpointRole: "denied",
    transmissionMode: "record-fragmented",
    canarySource: "controller-public-canary",
  },
  {
    caseId: "restricted-normal-a-control",
    endpointRole: "allowed",
    transmissionMode: "normal",
    canarySource: "controller-public-canary",
  },
  {
    caseId: "restricted-normal-b-negative",
    endpointRole: "denied",
    transmissionMode: "normal",
    canarySource: "controller-public-canary",
  },
  {
    caseId: "restricted-record-fragmented-a-control",
    endpointRole: "allowed",
    transmissionMode: "record-fragmented",
    canarySource: "controller-public-canary",
  },
  {
    caseId: "restricted-record-fragmented-b-target",
    endpointRole: "denied",
    transmissionMode: "record-fragmented",
    canarySource: "operator-secret-file",
  },
  {
    caseId: "restricted-record-fragmented-b-public-negative",
    endpointRole: "denied",
    transmissionMode: "record-fragmented",
    canarySource: "controller-public-canary",
  },
  {
    caseId: "restricted-normal-b-post-negative",
    endpointRole: "denied",
    transmissionMode: "normal",
    canarySource: "controller-public-canary",
  },
] as const;

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  const endpoints = controlledEndpoints();
  const controllerHmacKey = hmacKey();
  const credentials = explicitCredentials();
  const verifiedAliasEmail = await verifyAliasIdentity(credentials.token);
  const operatorSecret = randomBytes(32).toString("base64url");
  const controllerSecrets = [controllerHmacKey, operatorSecret, process.env.VERCEL_TOKEN ?? ""].filter(Boolean);
  const dnsStartedAt = new Date().toISOString();
  const [allowed, denied] = await Promise.all([
    resolveEndpoint(endpoints.allowed),
    resolveEndpoint(endpoints.denied),
  ]);
  const dnsCompletedAt = new Date().toISOString();
  const runId = randomUUID();
  const sandboxName = `sbx-032-poc-${runId.replaceAll("-", "")}`;
  const sandboxTags = { harness: "vsc", test: "SBX-032", run: runId };
  const publicCanaries = Object.fromEntries(
    caseDefinitions.filter((definition) => definition.canarySource === "controller-public-canary")
      .map((definition) => [definition.caseId, `public_${randomBytes(18).toString("base64url")}`]),
  ) as Partial<Record<CaseId, string>>;
  const guestSource = await readFile(resolve("guest/tls-record-reassembly-probe.py"), "utf8");
  if (controllerSecrets.some((secret) => guestSource.includes(secret))) {
    throw new Error("guest source unexpectedly contained controller-only material");
  }

  const endpointGate = new EndpointRateGate();
  const probes: EvidenceProbeRecord[] = [];
  let endpointRequestAttempts = 0;
  const policyTransitions: Record<string, unknown>[] = [];
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
    errors: [] as string[],
  };
  const operatorSecretSetup: Record<string, unknown> = {
    path: remoteOperatorSecretPath,
    expectedMode: "0600",
    writtenBeforeRestriction: false,
    verifiedBeforeRestriction: false,
  };
  let sandbox: Sandbox | undefined;
  let createAttempted = false;
  let originalSessionId: string | undefined;
  let sandboxIdentity: Record<string, unknown> | undefined;
  let executionError: string | undefined;
  let executionIndeterminate = false;
  let setupPassed = false;
  let allowNormalDeniedControlPassed = false;
  let allowTcpSegmentedDeniedControlPassed = false;
  let allowRecordFragmentedDeniedControlPassed = false;
  let restrictedUpdateAcknowledged = false;
  let restrictedReadbackPassed = false;
  let postTargetReadbackPassed = false;
  let allowedNormalControlPassed = false;
  let allowedRecordFragmentedControlPassed = false;
  let allowedRecordFragmentedControlBlocked = false;
  let restrictedNormalDeniedPreBlocked = false;
  let restrictedNormalDeniedPostBlocked = false;
  let restrictedRecordFragmentedPublicDeniedBlocked = false;
  let restrictedRecordFragmentedDeniedSucceeded = false;
  let restrictedRecordFragmentedDeniedBlocked = false;

  function endpointFor(role: EndpointRole): EndpointDetails {
    return role === "allowed" ? allowed : denied;
  }

  async function runProbe(definition: CaseDefinition): Promise<EvidenceProbeRecord> {
    if (!sandbox) throw new Error("sandbox is not available");
    const publicCanary = publicCanaries[definition.caseId];
    const configuration = buildProbeConfiguration({
      allowedEndpointUrl: allowed.url.href,
      allowedPinnedIPv4: allowed.pinnedIPv4,
      deniedEndpointUrl: denied.url.href,
      deniedPinnedIPv4: denied.pinnedIPv4,
      runId,
      caseId: definition.caseId,
      transmissionMode: definition.transmissionMode,
      ...(publicCanary ? { publicCanary } : {}),
    });
    const serialized = JSON.stringify(configuration);
    if (controllerSecrets.some((secret) => serialized.includes(secret))) {
      throw new Error(`${definition.caseId} guest configuration contained controller-only material`);
    }
    const requestCanary = definition.canarySource === "operator-secret-file" ? operatorSecret : publicCanary;
    if (!requestCanary) throw new Error(`${definition.caseId} has no request canary source`);
    await endpointGate.beforeEndpointRequest();
    endpointRequestAttempts += 1;
    const captured = await captureCommand(
      sandbox,
      {
        cmd: "python3",
        args: [remoteProbePath, Buffer.from(serialized).toString("base64url")],
        env: { HTTP_PROXY: "", HTTPS_PROXY: "", ALL_PROXY: "", NO_PROXY: "*" },
        timeoutMs: 20_000,
      },
      controllerSecrets,
    );
    let decoded: unknown;
    try {
      decoded = JSON.parse(captured.stdout);
    } catch {
      throw new Error(`${definition.caseId} guest probe emitted invalid JSON`);
    }
    const result = sanitizeGuestResult(decoded);
    const probe: EvidenceProbeRecord = {
      caseId: definition.caseId,
      endpointRole: definition.endpointRole,
      transmissionMode: definition.transmissionMode,
      canarySource: definition.canarySource,
      configurationSha256: sha256(serialized),
      ...(publicCanary ? { publicCanarySha256: sha256(publicCanary) } : {}),
      expectedOperationId: expectedOperationId(
        controllerHmacKey, runId, definition.caseId, requestCanary,
      ),
      commandExitCode: captured.record.exitCode,
      command: captured.record,
      ...(result ? { result } : {}),
    };
    probes.push(probe);
    return probe;
  }

  function success(probe: EvidenceProbeRecord): boolean {
    const endpoint = endpointFor(probe.endpointRole);
    return authenticatedTlsOperationSuccess(probe, {
      runId,
      testId,
      caseId: probe.caseId,
      endpointRole: probe.endpointRole,
      transmissionMode: probe.transmissionMode,
      endpointHostname: endpoint.url.hostname,
      pinnedIPv4: endpoint.pinnedIPv4,
    });
  }

  try {
    createAttempted = true;
    sandbox = await Sandbox.create({
      name: sandboxName,
      persistent: false,
      timeout: 300_000,
      networkPolicy: "allow-all",
      tags: sandboxTags,
      signal: controlSignal(45_000),
      ...credentials,
    });
    const session = sandbox.currentSession();
    originalSessionId = session.sessionId;
    sandboxIdentity = {
      name: sandbox.name,
      sessionId: session.sessionId,
      sessionCreatedAt: session.createdAt.toISOString(),
      sessionRequestedAt: session.requestedAt.toISOString(),
      region: session.region,
      persistent: sandbox.persistent,
      initialNetworkPolicy: sandbox.networkPolicy,
      initialSessionNetworkPolicy: session.networkPolicy,
    };
    if (
      sandbox.persistent !== false || sandbox.networkPolicy !== "allow-all" ||
      session.networkPolicy !== "allow-all"
    ) {
      throw new IndeterminateError("fresh nonpersistent sandbox did not report literal allow-all");
    }

    await sandbox.writeFiles([
      { path: remoteProbePath, content: guestSource, mode: 0o700 },
      { path: remoteOperatorSecretPath, content: operatorSecret, mode: 0o600 },
    ], { signal: controlSignal() });
    operatorSecretSetup.writtenBeforeRestriction = true;
    const secretVerification = await captureCommand(
      sandbox,
      {
        cmd: "python3",
        args: [
          "-c",
          `import os,stat; p=${JSON.stringify(remoteOperatorSecretPath)}; fd=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)); s=os.fstat(fd); d=os.read(fd,129); os.close(fd); assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o600 and len(d)==s.st_size and 16<=len(d)<=128; print('OK')`,
        ],
        timeoutMs: 10_000,
      },
      controllerSecrets,
    );
    operatorSecretSetup.verificationCommand = secretVerification.record;
    operatorSecretSetup.observedMode = "0600";
    const observedSecret = await sandbox.readFileToBuffer(
      { path: remoteOperatorSecretPath },
      { signal: controlSignal() },
    );
    const expectedSecret = Buffer.from(operatorSecret, "ascii");
    const exactSecretContentMatched = observedSecret !== null && observedSecret.equals(expectedSecret);
    observedSecret?.fill(0);
    expectedSecret.fill(0);
    operatorSecretSetup.exactContentMatched = exactSecretContentMatched;
    operatorSecretSetup.verifiedBeforeRestriction = secretVerification.record.exitCode === 0 &&
      secretVerification.stdout.trim() === "OK" && exactSecretContentMatched;
    if (!operatorSecretSetup.verifiedBeforeRestriction) {
      throw new IndeterminateError("fresh synthetic operator-secret file verification failed");
    }
    setupPassed = true;

    const allowNormal = await runProbe(caseDefinitions[0]!);
    allowNormalDeniedControlPassed = success(allowNormal);
    if (!allowNormalDeniedControlPassed) {
      throw new IndeterminateError("allow-all ordinary denied-host control failed");
    }

    const allowTcpSegmented = await runProbe(caseDefinitions[1]!);
    allowTcpSegmentedDeniedControlPassed = success(allowTcpSegmented);
    if (!allowTcpSegmentedDeniedControlPassed) {
      throw new IndeterminateError("allow-all TCP-write-segmented ClientHello control failed");
    }

    const allowRecordFragmented = await runProbe(caseDefinitions[2]!);
    allowRecordFragmentedDeniedControlPassed = success(allowRecordFragmented);
    if (!allowRecordFragmentedDeniedControlPassed) {
      throw new IndeterminateError("allow-all standards-valid TLS-record fragmentation control failed");
    }

    const restrictedPolicy = { allow: [allowed.url.hostname] } satisfies NetworkPolicy;
    const updateStartedAt = new Date().toISOString();
    await sandbox.update({ networkPolicy: restrictedPolicy }, { signal: controlSignal() });
    const activeSession = sandbox.currentSession();
    restrictedUpdateAcknowledged = activeSession.sessionId === originalSessionId &&
      exactSingleHostAllowPolicy(activeSession.networkPolicy, allowed.url.hostname) &&
      exactSingleHostAllowPolicy(sandbox.networkPolicy, allowed.url.hostname);
    const independentReadback = await Sandbox.get({
      name: sandbox.name,
      resume: false,
      signal: controlSignal(),
      ...credentials,
    });
    const independentSession = independentReadback.currentSession();
    restrictedReadbackPassed = independentSession.sessionId === originalSessionId &&
      exactSingleHostAllowPolicy(independentSession.networkPolicy, allowed.url.hostname) &&
      exactSingleHostAllowPolicy(independentReadback.networkPolicy, allowed.url.hostname);
    await delay(policySettleDelayMs, undefined, { signal: controlSignal(policySettleDelayMs + 2_000) });
    policyTransitions.push({
      stage: "allow-all-to-exact-single-owned-host",
      startedAt: updateStartedAt,
      completedAt: new Date().toISOString(),
      settleDelayMs: policySettleDelayMs,
      requestedPolicy: restrictedPolicy,
      originalSessionId,
      activeHandleSessionId: activeSession.sessionId,
      activeHandleSessionPolicyReadback: activeSession.networkPolicy,
      activeHandleSandboxPolicyReadback: sandbox.networkPolicy,
      independentSessionId: independentSession.sessionId,
      independentSessionPolicyReadback: independentSession.networkPolicy,
      independentSandboxPolicyReadback: independentReadback.networkPolicy,
      updateAcknowledged: restrictedUpdateAcknowledged,
      independentReadbackPassed: restrictedReadbackPassed,
    });
    if (!restrictedUpdateAcknowledged || !restrictedReadbackPassed) {
      throw new IndeterminateError("exact single-host policy update or independent readback failed");
    }

    const allowedNormal = await runProbe(caseDefinitions[3]!);
    allowedNormalControlPassed = success(allowedNormal);
    if (!allowedNormalControlPassed) {
      throw new IndeterminateError("allowed-host ordinary TLS control failed");
    }

    const restrictedNormal = await runProbe(caseDefinitions[4]!);
    restrictedNormalDeniedPreBlocked = conclusiveTlsFirewallBlock(restrictedNormal, {
      runId,
      testId,
      caseId: restrictedNormal.caseId,
      endpointHostname: denied.url.hostname,
      pinnedIPv4: denied.pinnedIPv4,
      transmissionMode: restrictedNormal.transmissionMode,
    });
    if (!restrictedNormalDeniedPreBlocked) {
      throw new IndeterminateError("ordinary denied-host TLS was not conclusively blocked");
    }

    const allowedFragmented = await runProbe(caseDefinitions[5]!);
    allowedRecordFragmentedControlPassed = success(allowedFragmented);
    if (!allowedRecordFragmentedControlPassed) {
      allowedRecordFragmentedControlBlocked = conclusiveTlsFirewallBlock(allowedFragmented, {
        runId,
        testId,
        caseId: allowedFragmented.caseId,
        endpointRole: "allowed",
        endpointHostname: allowed.url.hostname,
        pinnedIPv4: allowed.pinnedIPv4,
        transmissionMode: allowedFragmented.transmissionMode,
      });
      if (!allowedRecordFragmentedControlBlocked) {
        throw new IndeterminateError("allowed-host TLS-record fragmentation result was inconclusive");
      }
      const publicFragmentedDenied = await runProbe(caseDefinitions[7]!);
      restrictedRecordFragmentedPublicDeniedBlocked = conclusiveTlsFirewallBlock(publicFragmentedDenied, {
        runId,
        testId,
        caseId: publicFragmentedDenied.caseId,
        endpointHostname: denied.url.hostname,
        pinnedIPv4: denied.pinnedIPv4,
        transmissionMode: publicFragmentedDenied.transmissionMode,
      });
      if (!restrictedRecordFragmentedPublicDeniedBlocked) {
        throw new IndeterminateError("public-canary fragmented denied-host result was not conclusively blocked");
      }
    } else {
      const restrictedFragmented = await runProbe(caseDefinitions[6]!);
      restrictedRecordFragmentedDeniedSucceeded = success(restrictedFragmented);
      restrictedRecordFragmentedDeniedBlocked = !restrictedRecordFragmentedDeniedSucceeded &&
        conclusiveTlsFirewallBlock(restrictedFragmented, {
          runId,
          testId,
          caseId: restrictedFragmented.caseId,
          endpointHostname: denied.url.hostname,
          pinnedIPv4: denied.pinnedIPv4,
          transmissionMode: restrictedFragmented.transmissionMode,
        });
    }

    const postTargetReadbackStartedAt = new Date().toISOString();
    const postActiveSession = sandbox.currentSession();
    const postIndependentReadback = await Sandbox.get({
      name: sandbox.name,
      resume: false,
      signal: controlSignal(),
      ...credentials,
    });
    const postIndependentSession = postIndependentReadback.currentSession();
    postTargetReadbackPassed = postActiveSession.sessionId === originalSessionId &&
      postIndependentSession.sessionId === originalSessionId &&
      exactSingleHostAllowPolicy(postActiveSession.networkPolicy, allowed.url.hostname) &&
      exactSingleHostAllowPolicy(sandbox.networkPolicy, allowed.url.hostname) &&
      exactSingleHostAllowPolicy(postIndependentSession.networkPolicy, allowed.url.hostname) &&
      exactSingleHostAllowPolicy(postIndependentReadback.networkPolicy, allowed.url.hostname);
    policyTransitions.push({
      stage: "post-target-same-session-policy-barrier",
      startedAt: postTargetReadbackStartedAt,
      completedAt: new Date().toISOString(),
      originalSessionId,
      activeSessionId: postActiveSession.sessionId,
      independentSessionId: postIndependentSession.sessionId,
      activeSessionPolicyReadback: postActiveSession.networkPolicy,
      activeSandboxPolicyReadback: sandbox.networkPolicy,
      independentSessionPolicyReadback: postIndependentSession.networkPolicy,
      independentSandboxPolicyReadback: postIndependentReadback.networkPolicy,
      postTargetReadbackPassed,
    });
    if (!postTargetReadbackPassed) {
      throw new IndeterminateError("post-target exact policy or same-session readback failed");
    }

    const restrictedNormalPost = await runProbe(caseDefinitions[8]!);
    restrictedNormalDeniedPostBlocked = conclusiveTlsFirewallBlock(restrictedNormalPost, {
      runId,
      testId,
      caseId: restrictedNormalPost.caseId,
      endpointHostname: denied.url.hostname,
      pinnedIPv4: denied.pinnedIPv4,
      transmissionMode: restrictedNormalPost.transmissionMode,
    });
    if (!restrictedNormalDeniedPostBlocked) {
      throw new IndeterminateError("post-target ordinary denied-host TLS was not conclusively blocked");
    }
  } catch (error) {
    executionError = safeError(error, controllerSecrets);
    executionIndeterminate = error instanceof IndeterminateError;
  } finally {
    if (!sandbox && createAttempted) {
      cleanup.orphanRecoveryAttempted = true;
      let notFoundCount = 0;
      for (let attempt = 0; attempt < 3 && !sandbox; attempt += 1) {
        if (attempt > 0) {
          await delay(1_000, undefined, { signal: controlSignal(3_000) });
        }
        try {
          const recovered = await Sandbox.get({
            name: sandboxName,
            resume: false,
            signal: controlSignal(),
            ...credentials,
          });
          const createdAt = recovered.createdAt.getTime();
          const creationWindowValid = Number.isFinite(createdAt) &&
            createdAt >= Date.parse(startedAt) - 5_000 && createdAt <= Date.now() + 5_000;
          const tagsValid = recovered.tags?.harness === sandboxTags.harness &&
            recovered.tags?.test === sandboxTags.test && recovered.tags?.run === sandboxTags.run;
          if (!creationWindowValid || !tagsValid) {
            cleanup.errors.push("orphan recovery found a sandbox without the exact run identity; left untouched");
            break;
          }
          sandbox = recovered;
          cleanup.recoveredHandle = true;
        } catch (error) {
          if (isNotFound(error)) {
            notFoundCount += 1;
          } else {
            cleanup.errors.push(`orphan recovery: ${safeError(error, controllerSecrets)}`);
            break;
          }
        }
      }
      cleanup.orphanAbsenceConfirmed = !sandbox && notFoundCount === 3;
    }
    if (sandbox) {
      cleanup.stopAttempted = true;
      try {
        await sandbox.stop({ signal: controlSignal() });
        cleanup.stopped = true;
      } catch (error) {
        cleanup.errors.push(`stop: ${safeError(error, controllerSecrets)}`);
      }
      cleanup.deleteAttempted = true;
      try {
        await sandbox.delete({ signal: controlSignal() });
        cleanup.deleted = true;
      } catch (error) {
        cleanup.errors.push(`delete: ${safeError(error, controllerSecrets)}`);
      }
      if (cleanup.deleted) {
        cleanup.deletionAbsenceCheckAttempted = true;
        let notFoundCount = 0;
        for (let attempt = 0; attempt < 3; attempt += 1) {
          if (attempt > 0) {
            await delay(1_000, undefined, { signal: controlSignal(3_000) });
          }
          try {
            await Sandbox.get({
              name: sandboxName,
              resume: false,
              signal: controlSignal(),
              ...credentials,
            });
          } catch (error) {
            if (isNotFound(error)) {
              notFoundCount += 1;
            } else {
              cleanup.errors.push(`deletion absence check: ${safeError(error, controllerSecrets)}`);
              break;
            }
          }
        }
        cleanup.deletionAbsenceConfirmed = notFoundCount === 3;
        if (!cleanup.deletionAbsenceConfirmed && cleanup.errors.length === 0) {
          cleanup.errors.push("deleted sandbox remained discoverable during the independent absence checks");
        }
      }
    }
  }

  const cleanupPassed = !createAttempted || (
    cleanup.errors.length === 0 && (
      (sandbox !== undefined && cleanup.stopped && cleanup.deleted && cleanup.deletionAbsenceConfirmed) ||
      (sandbox === undefined && cleanup.orphanAbsenceConfirmed)
    )
  );
  const assessment = assessSbx032({
    setupPassed,
    allowNormalDeniedControlPassed,
    allowTcpSegmentedDeniedControlPassed,
    allowRecordFragmentedDeniedControlPassed,
    restrictedUpdateAcknowledged,
    restrictedReadbackPassed,
    postTargetReadbackPassed,
    allowedNormalControlPassed,
    allowedRecordFragmentedControlPassed,
    allowedRecordFragmentedControlBlocked,
    restrictedNormalDeniedPreBlocked,
    restrictedNormalDeniedPostBlocked,
    restrictedRecordFragmentedPublicDeniedBlocked,
    restrictedRecordFragmentedDeniedSucceeded,
    restrictedRecordFragmentedDeniedBlocked,
    cleanupPassed,
    ...(executionError && !executionIndeterminate ? { executionError: true } : {}),
  });
  const evidence = {
    schemaVersion: 2,
    visibility: "private",
    testId: "SBX-032",
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    scope: "one researcher-owned Vercel sandbox and two distinct researcher-owned HTTPS action hostnames",
    hypothesis: "the host firewall may parse SNI only within one TLS record rather than reassembling a standards-valid fragmented ClientHello",
    requestBounds: {
      endpointRequestAttempts,
      retainedProbeResults: probes.length,
      maximumEndpointRequests: 8,
      sequential: true,
      retryCount: 0,
      redirectsAllowed: false,
      minimumEndpointRequestIntervalMs,
      maximumRequestRatePerSecond: 1_000 / minimumEndpointRequestIntervalMs,
    },
    endpoints: {
      resolvedAt: { startedAt: dnsStartedAt, completedAt: dnsCompletedAt },
      allowed: {
        origin: allowed.url.origin,
        path: allowed.url.pathname,
        pinnedIPv4: allowed.pinnedIPv4,
        resolvedARecords: allowed.answers,
      },
      denied: {
        origin: denied.url.origin,
        path: denied.url.pathname,
        pinnedIPv4: denied.pinnedIPv4,
        resolvedARecords: denied.answers,
      },
      contract: "{authorized:true,operationId:h3_+base64url(HMAC-SHA256(H3_ACTION_KEY,runId\\ncaseId\\ncanary))}",
    },
    credentialContext: {
      mode: "explicit-alias-verified",
      email: verifiedAliasEmail,
      teamId: credentials.teamId,
      projectId: credentials.projectId,
    },
    sandbox: sandboxIdentity,
    operatorSecretSetup,
    policy: {
      initial: "allow-all" satisfies NetworkPolicy,
      tightened: { allow: [allowed.url.hostname] } satisfies NetworkPolicy,
      transitions: policyTransitions,
    },
    guestMaterialGuards: {
      hmacKeyEnteredGuestSourceConfigurationArgumentsOrOutput: false,
      rawOperatorSecretEnteredGuestSourceConfigurationArgumentsOutputOrArtifact: false,
      keyedReceiptProofRetained: true,
      vercelTokenEnteredGuestSourceConfigurationArgumentsOrOutput: false,
      rawClientHelloRetained: false,
      rawHttpResponseRetained: false,
    },
    probes,
    controls: {
      setupPassed,
      allowNormalDeniedControlPassed,
      allowTcpSegmentedDeniedControlPassed,
      allowRecordFragmentedDeniedControlPassed,
      restrictedUpdateAcknowledged,
      restrictedReadbackPassed,
      postTargetReadbackPassed,
      allowedNormalControlPassed,
      allowedRecordFragmentedControlPassed,
      allowedRecordFragmentedControlBlocked,
      restrictedNormalDeniedPreBlocked,
      restrictedNormalDeniedPostBlocked,
      restrictedRecordFragmentedPublicDeniedBlocked,
      restrictedRecordFragmentedDeniedSucceeded,
      restrictedRecordFragmentedDeniedBlocked,
    },
    cleanup,
    assessment,
    ...(executionError ? { executionError } : {}),
  };
  const serializedEvidence = `${JSON.stringify(evidence, null, 2)}\n`;
  if (controllerSecrets.some((secret) => secret && serializedEvidence.includes(secret))) {
    throw new Error("refusing to write evidence containing controller-only material");
  }
  await mkdir(resolve("artifacts"), { recursive: true, mode: 0o700 });
  const privateEvidencePath = resolve("artifacts", `SBX-032-${runId}-private.json`);
  await writeFile(privateEvidencePath, serializedEvidence, { encoding: "utf8", mode: 0o600, flag: "wx" });
  process.stdout.write(`${JSON.stringify({
    testId: "SBX-032",
    runId,
    verdict: assessment.verdict,
    candidate: assessment.candidate,
    controlsPassed: assessment.controlsPassed,
    endpointRequestAttempts,
    cleanup,
    privateEvidencePath,
    ...(executionError ? { executionError } : {}),
  }, null, 2)}\n`);
  if (assessment.verdict !== "pass") process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
