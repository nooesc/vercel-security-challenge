import "dotenv/config";

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdir, open, readFile, unlink, writeFile, type FileHandle } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { APIError, Sandbox, type NetworkPolicy } from "@vercel/sandbox";
import type { Sbx048GuestConfiguration, Sbx048GuestResult } from "../../guest/sbx-048-forward-probe.mjs";
import { verifyEligibleAliasToken, type EligibleAliasIdentityProof } from "../eligible-alias-identity.js";
import {
  assessSbx048,
  assertNoTokenMaterial,
  exactDenyAll,
  exactForwardPolicy,
  exactForwardSandboxProjection,
  exactRawForwardPolicy,
  SBX048_TEST_ID,
  type Sbx048Assessment,
  type Sbx048ControlPlaneAttempt,
  type Sbx048ReceiverRecord,
} from "./verdict.js";
import type { ReceiverConfiguration, ReceiverReadback } from "./receiver.js";

const SCOPE_CONFIRMATION = "I_CONTROL_SBX048_PROXY_ORIGIN_AND_AUTHORIZE_ONE_BOUNDED_OIDC_CONTROL_PLANE_TEST";
const ALIAS_EMAIL = "swve@wearehackerone.com";
const TEAM_ID = "team_n98ERpVwV7HqmWRudAyK8sXQ";
const PROJECT_ID = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
const GUEST_SCOPE = "researcher-controlled-sbx048-origin-only";
const CASE_ID = "brokered-control-plane-probe";
const REMOTE_GUEST_PATH = "/tmp/sbx-048/forward-probe.mjs";
const CONTROL_TIMEOUT_MS = 30_000;
const MINIMUM_VERCEL_SPACING_MS = 250;
const MAX_RESPONSE_BYTES = 65_536;
const OPERATION_ID = /^oid48_[A-Za-z0-9_-]{24}$/u;
const PLATFORM_TRUST_ENVIRONMENT_NAMES = new Set([
  "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF", "OPENSSL_MODULES", "SSL_CERT_DIR", "SSL_CERT_FILE",
]);
const LOCAL_TLS_TRUST_ENVIRONMENT_NAMES = [
  "NODE_EXTRA_CA_CERTS",
  "NODE_USE_SYSTEM_CA",
  "OPENSSL_CONF",
  "OPENSSL_MODULES",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
] as const;

interface ExplicitConfig {
  token: string;
  teamId: typeof TEAM_ID;
  projectId: typeof PROJECT_ID;
  adminKey: string;
  publicOrigin: URL;
  manualAliasConfirmation?: string;
}

interface RequestAudit {
  ordinal: number;
  startedAt: string;
  method: string;
  origin: string;
  endpointFamily: string;
  statusCode?: number;
  completedAt?: string;
}

interface OwnerRead {
  method: "GET";
  endpointFamily: "/v2/sandboxes/sessions/:sessionId";
  requestCount: 1;
  statusCode: number;
  exactSession: boolean;
  exactPolicy: boolean;
  policyShape?: "legacy-raw-custom" | "literal-mode";
  responseBodyRetained: false;
  responseHeadersRetained: false;
}

interface CommandEvidence {
  expectedMode: "direct" | "forward";
  commandId: string;
  exitCode: number;
  stdoutBytes: number;
  stdoutSha256: string;
  stderrBytes: number;
  stderrSha256: string;
  result?: Sbx048GuestResult;
}

interface CleanupEvidence {
  policyRestoreRequired: boolean;
  policyRestoreAttempted: boolean;
  policyRestored: boolean;
  orphanRecoveryAttempted: boolean;
  recovered: boolean;
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  deletionAbsenceConfirmed: boolean;
  receiverDeleteAttempted: boolean;
  receiverDeleted: boolean;
  receiverAbsent: boolean;
  lockReleased: boolean;
  errors: string[];
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function exactOrigin(raw: string, name: string): URL {
  const parsed = new URL(raw);
  if (
    raw !== parsed.origin || parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.port ||
    parsed.pathname !== "/" || parsed.search || parsed.hash || isIP(parsed.hostname) !== 0 ||
    parsed.hostname !== parsed.hostname.toLowerCase()
  ) {
    throw new Error(`${name} must be an exact lower-case public HTTPS origin`);
  }
  return parsed;
}

export function explicitConfiguration(environment: NodeJS.ProcessEnv = process.env): ExplicitConfig {
  requireStrictControllerTlsEnvironment(environment);
  if (environment.SBX048_SCOPE_CONFIRMATION !== SCOPE_CONFIRMATION) {
    throw new Error(`SBX048_SCOPE_CONFIRMATION must equal ${SCOPE_CONFIRMATION}`);
  }
  if (environment.VERCEL_TEAM_ID !== TEAM_ID || environment.VERCEL_PROJECT_ID !== PROJECT_ID) {
    throw new Error("SBX-048 requires the exact verified HackerOne-alias team and project");
  }
  const token = required(environment, "VERCEL_TOKEN");
  if (token.split(".").length === 3) {
    throw new Error("SBX-048 requires an opaque PAT so SDK OIDC refresh cannot add hidden requests");
  }
  const adminKey = required(environment, "SBX048_ADMIN_KEY");
  if (Buffer.byteLength(adminKey) < 32 || Buffer.byteLength(adminKey) > 256 || /[\0\r\n]/u.test(adminKey)) {
    throw new Error("SBX048_ADMIN_KEY must contain 32-256 safe bytes");
  }
  const manualAliasConfirmation = environment.SBX048_ALIAS_EMAIL_CONFIRMATION;
  return {
    token,
    teamId: TEAM_ID,
    projectId: PROJECT_ID,
    adminKey,
    publicOrigin: exactOrigin(required(environment, "SBX048_PUBLIC_ORIGIN"), "SBX048_PUBLIC_ORIGIN"),
    ...(manualAliasConfirmation ? { manualAliasConfirmation } : {}),
  };
}

export function requireStrictControllerTlsEnvironment(environment: NodeJS.ProcessEnv = process.env): void {
  if (environment.NODE_TLS_REJECT_UNAUTHORIZED === "0" ||
      (environment.NODE_OPTIONS !== undefined && environment.NODE_OPTIONS.trim() !== "") ||
      LOCAL_TLS_TRUST_ENVIRONMENT_NAMES.some((name) => environment[name] !== undefined)) {
    throw new Error("SBX-048 controller refuses local TLS trust overrides or runtime injection");
  }
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function safeError(error: unknown, secrets: readonly string[]): string {
  let output = error instanceof Error ? error.message : String(error);
  for (const secret of secrets) if (secret) output = output.split(secret).join("[REDACTED]");
  return output.replace(/[\0\r\n]/gu, " ").slice(0, 1_000);
}

function endpointFamily(url: URL): string {
  return url.pathname
    .replace(/\/sessions\/[^/]+/u, "/sessions/:sessionId")
    .replace(/\/sandboxes\/[^/]+/u, "/sandboxes/:name");
}

export function createVercelRequestGate(rawFetch: typeof fetch = fetch): {
  fetch: typeof fetch;
  records: RequestAudit[];
} {
  const records: RequestAudit[] = [];
  let queue = Promise.resolve();
  let lastStartedAt = 0;
  const gated = (async (input: string | URL | globalThis.Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(input instanceof Request ? input.url : input.toString());
    const allowedSandbox = url.origin === "https://vercel.com" &&
      (/^\/api\/v[23]\/sandboxes(?:\/|$)/u.test(url.pathname));
    const allowedIdentity = url.origin === "https://api.vercel.com" &&
      (url.pathname === "/v2/user" || url.pathname === `/v2/teams/${TEAM_ID}` ||
        url.pathname === `/v9/projects/${PROJECT_ID}`);
    if (!allowedSandbox && !allowedIdentity) throw new Error(`SBX-048 request gate rejected ${url.origin}${url.pathname}`);
    if (url.searchParams.has("teamId") && url.searchParams.get("teamId") !== TEAM_ID) {
      throw new Error("SBX-048 request gate rejected a non-owned team query");
    }
    const method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
    const startTurn = queue.then(async () => {
      const wait = Math.max(0, lastStartedAt + MINIMUM_VERCEL_SPACING_MS - Date.now());
      if (wait > 0) await new Promise<void>((resolve) => globalThis.setTimeout(resolve, wait));
      lastStartedAt = Date.now();
    });
    queue = startTurn.catch(() => undefined);
    await startTurn;
    const record: RequestAudit = {
      ordinal: records.length + 1,
      startedAt: new Date().toISOString(),
      method,
      origin: url.origin,
      endpointFamily: endpointFamily(url),
    };
    records.push(record);
    const response = await rawFetch(input, { ...init, redirect: "error" });
    record.statusCode = response.status;
    record.completedAt = new Date().toISOString();
    return response;
  }) as typeof fetch;
  return { fetch: gated, records };
}

async function boundedJson(response: Response): Promise<unknown> {
  const reader = response.body?.getReader();
  if (!reader) return undefined;
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      const chunk = Buffer.from(item.value);
      total += chunk.length;
      if (total > MAX_RESPONSE_BYTES) {
        chunk.fill(0);
        for (const retained of chunks) retained.fill(0);
        await reader.cancel().catch(() => undefined);
        throw new Error("SBX-048 response exceeded its fixed byte limit");
      }
      chunks.push(chunk);
    }
    const joined = Buffer.concat(chunks, total);
    let parsed: unknown;
    try {
      parsed = total === 0 ? undefined : JSON.parse(joined.toString("utf8"));
    } finally {
      joined.fill(0);
      for (const retained of chunks) retained.fill(0);
    }
    return parsed;
  } finally {
    reader.releaseLock();
  }
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

async function ownerRead(
  gatedFetch: typeof fetch,
  token: string,
  sessionId: string,
  expected: { kind: "forward"; hostname: string; forwardAudience: string } | { kind: "deny-all" },
): Promise<OwnerRead> {
  const query = new URLSearchParams({ teamId: TEAM_ID });
  const response = await gatedFetch(
    `https://vercel.com/api/v2/sandboxes/sessions/${encodeURIComponent(sessionId)}?${query.toString()}`,
    {
      method: "GET",
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
      signal: AbortSignal.timeout(10_000),
    },
  );
  const base = {
    method: "GET" as const,
    endpointFamily: "/v2/sandboxes/sessions/:sessionId" as const,
    requestCount: 1 as const,
    statusCode: response.status,
    exactSession: false,
    exactPolicy: false,
    responseBodyRetained: false as const,
    responseHeadersRetained: false as const,
  };
  if (!response.ok) {
    if (response.body) await response.body.cancel().catch(() => undefined);
    return base;
  }
  const payload = object(await boundedJson(response));
  const session = object(payload?.session);
  const forward = expected.kind === "forward" &&
    exactRawForwardPolicy(session?.networkPolicy, expected.hostname, expected.forwardAudience);
  const deny = expected.kind === "deny-all" && exactDenyAll(session?.networkPolicy);
  return {
    ...base,
    exactSession: session?.id === sessionId,
    exactPolicy: forward || deny,
    ...(forward ? { policyShape: "legacy-raw-custom" as const } : deny ? { policyShape: "literal-mode" as const } : {}),
  };
}

async function adminRequest(
  config: ExplicitConfig,
  runId: string,
  suffix = "",
  init?: RequestInit,
): Promise<Response> {
  const headers = new Headers(init?.headers);
  headers.set("authorization", `Bearer ${config.adminKey}`);
  if (init?.body) headers.set("content-type", "application/json");
  return fetch(new URL(`/v1/sbx048/admin/runs/${encodeURIComponent(runId)}${suffix}`, config.publicOrigin), {
    ...init,
    headers,
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
}

async function receiverReadback(config: ExplicitConfig, runId: string): Promise<ReceiverReadback> {
  const response = await adminRequest(config, runId);
  if (response.status === 404) return { configured: false, directRecords: [], records: [] };
  if (!response.ok) throw new Error(`receiver readback returned ${response.status}`);
  const payload = object(await boundedJson(response));
  if (!payload || !Array.isArray(payload.directRecords) || !Array.isArray(payload.records)) {
    throw new Error("receiver readback schema was invalid");
  }
  return payload as unknown as ReceiverReadback;
}

async function health(origin: URL): Promise<boolean> {
  const response = await fetch(new URL("/healthz", origin), {
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  const payload = object(await boundedJson(response));
  return response.status === 200 && payload?.ok === true && payload.role === "SBX-048-P";
}

function exactReceiverConfiguration(actual: ReceiverConfiguration | undefined, expected: ReceiverConfiguration): boolean {
  return actual !== undefined && JSON.stringify(actual) === JSON.stringify(expected);
}

function sanitizeGuest(value: unknown): Sbx048GuestResult | undefined {
  const input = object(value);
  if (!input) return undefined;
  const output: Record<string, unknown> = {};
  for (const key of [
    "schemaVersion", "requestCount", "maximumRequests", "retryCount", "redirectsFollowed", "durationMs",
    "responseStatus", "responseBodyLength", "controlPlaneReadStatus", "mutationStatus",
  ]) {
    if (typeof input[key] === "number" || (key === "mutationStatus" && input[key] === null)) output[key] = input[key];
  }
  for (const key of ["testId", "runId", "caseId", "expectedMode", "remoteAddress", "responseOperationId", "errorCode"]) {
    if (typeof input[key] === "string" && input[key].length <= 512) output[key] = input[key];
  }
  for (const key of [
    "redirectsAllowed", "environmentProxyTrust", "rejectUnauthorized", "tcpConnected", "tlsEstablished",
    "tlsAuthorized", "controllerConfigurableCustomTrustAccepted", "rawResponseHeadersRetained", "rawResponseBodyRetained",
    "ok", "responseTruncated",
  ]) {
    if (typeof input[key] === "boolean") output[key] = input[key];
  }
  if (Array.isArray(input.inheritedPlatformTrustEnvironmentNames) &&
      input.inheritedPlatformTrustEnvironmentNames.every((entry) => typeof entry === "string")) {
    output.inheritedPlatformTrustEnvironmentNames = [...input.inheritedPlatformTrustEnvironmentNames];
  }
  return output as unknown as Sbx048GuestResult;
}

async function captureGuest(
  sandbox: Sandbox,
  configuration: Sbx048GuestConfiguration,
  secrets: readonly string[],
): Promise<CommandEvidence> {
  const serialized = JSON.stringify(configuration);
  if (secrets.some((secret) => serialized.includes(secret))) throw new Error("guest configuration contains controller secrets");
  const command = await sandbox.runCommand({
    cmd: "node",
    args: [REMOTE_GUEST_PATH, Buffer.from(serialized).toString("base64url")],
    timeoutMs: 20_000,
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  });
  const [stdout, stderr] = await Promise.all([
    command.stdout({ signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) }),
    command.stderr({ signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) }),
  ]);
  if (Buffer.byteLength(stdout) > 32_768 || Buffer.byteLength(stderr) > 8_192) throw new Error("guest output exceeded bounds");
  if (secrets.some((secret) => stdout.includes(secret) || stderr.includes(secret))) throw new Error("guest output contains a controller secret");
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout.trimEnd());
  } catch {
    parsed = undefined;
  }
  return {
    expectedMode: configuration.expectedMode,
    commandId: command.cmdId,
    exitCode: command.exitCode,
    stdoutBytes: Buffer.byteLength(stdout),
    stdoutSha256: sha256(stdout),
    stderrBytes: Buffer.byteLength(stderr),
    stderrSha256: sha256(stderr),
    ...(sanitizeGuest(parsed) ? { result: sanitizeGuest(parsed)! } : {}),
  };
}

function exactGuestBase(result: Sbx048GuestResult | undefined, runId: string, mode: "direct" | "forward"): boolean {
  const trustNames = result?.inheritedPlatformTrustEnvironmentNames;
  const exactTrustNames = Array.isArray(trustNames) && new Set(trustNames).size === trustNames.length &&
    trustNames.every((name) => PLATFORM_TRUST_ENVIRONMENT_NAMES.has(name)) &&
    trustNames.every((name, index) => index === 0 || trustNames[index - 1]! < name);
  return result?.schemaVersion === 1 && result.testId === SBX048_TEST_ID && result.runId === runId &&
    result.caseId === CASE_ID && result.expectedMode === mode && result.requestCount === 1 &&
    result.maximumRequests === 1 && result.retryCount === 0 && result.redirectsAllowed === false &&
    result.redirectsFollowed === 0 && result.environmentProxyTrust === false && result.rejectUnauthorized === true &&
    result.controllerConfigurableCustomTrustAccepted === false && exactTrustNames &&
    result.tcpConnected === true && result.tlsEstablished === true && result.tlsAuthorized === true &&
    result.rawResponseHeadersRetained === false && result.rawResponseBodyRetained === false && result.ok === true &&
    typeof result.responseOperationId === "string" && OPERATION_ID.test(result.responseOperationId);
}

function isNotFound(error: unknown): boolean {
  return error instanceof APIError && error.response.status === 404;
}

async function acquireLock(path: string): Promise<FileHandle> {
  await mkdir(resolve(path, ".."), { recursive: true, mode: 0o700 });
  return open(path, "wx", 0o600);
}

async function writePrivateJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" });
}

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  const config = explicitConfiguration();
  const secrets = [config.token, config.adminKey];
  const runId = randomUUID();
  const sandboxName = `sbx-048-poc-${runId.replaceAll("-", "")}`;
  const tags = { harness: "vsc", test: "SBX-048", run: runId };
  const sourcePath = `/v1/sbx048/source/${encodeURIComponent(runId)}`;
  const forwardAudience = new URL(`/v1/sbx048/forward/${encodeURIComponent(runId)}`, config.publicOrigin).toString();
  const wrongAudience = new URL(`/v1/sbx048/wrong-audience/${encodeURIComponent(runId)}`, config.publicOrigin).toString();
  const canary = `c48_${randomBytes(18).toString("base64url")}`;
  const initialPolicy = { allow: [config.publicOrigin.hostname] } satisfies NetworkPolicy;
  const finalPolicy = {
    allow: { [config.publicOrigin.hostname]: [{ forwardURL: forwardAudience }] },
  } satisfies NetworkPolicy;
  const receiverConfiguration: ReceiverConfiguration = {
    runId,
    publicOrigin: config.publicOrigin.origin,
    forwardAudience,
    wrongAudience,
    sourceHostname: config.publicOrigin.hostname,
    sourcePath,
    expectedTeamId: TEAM_ID,
    expectedProjectId: PROJECT_ID,
    expectedSandboxId: "pending",
    expectedSandboxName: sandboxName,
    correlationCanary: canary,
    mutationEnabled: true,
  };
  const guestBase = {
    scopeConfirmation: GUEST_SCOPE,
    runId,
    testId: SBX048_TEST_ID,
    caseId: CASE_ID,
    correlationCanary: canary,
    publicOrigin: config.publicOrigin.origin,
    sourcePath,
    timeoutMs: 10_000,
  } as const;
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  const lockPath = resolve(artifactsDirectory, "SBX-048-live-active.lock");
  const evidencePath = resolve(artifactsDirectory, `SBX-048-${runId}-private.json`);
  const requestGate = createVercelRequestGate();
  const credentials = { token: config.token, teamId: TEAM_ID, projectId: PROJECT_ID, fetch: requestGate.fetch };
  const cleanup: CleanupEvidence = {
    policyRestoreRequired: false,
    policyRestoreAttempted: false,
    policyRestored: false,
    orphanRecoveryAttempted: false,
    recovered: false,
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    deletionAbsenceConfirmed: false,
    receiverDeleteAttempted: false,
    receiverDeleted: false,
    receiverAbsent: false,
    lockReleased: false,
    errors: [],
  };
  let liveLock: FileHandle | undefined;
  let sandbox: Sandbox | undefined;
  let createAttempted = false;
  let receiverConfigured = false;
  let identity: EligibleAliasIdentityProof | undefined;
  let sessionId: string | undefined;
  let directCommand: CommandEvidence | undefined;
  let forwardCommand: CommandEvidence | undefined;
  let ownerReadBefore: OwnerRead | undefined;
  let ownerReadAfter: OwnerRead | undefined;
  let ownerReadFinal: OwnerRead | undefined;
  let receiverRead: ReceiverReadback = { configured: false, directRecords: [], records: [] };
  let ownerObservedDenyAllAfterMutation = false;
  let ownerFinalOriginalPolicy = false;
  let sandboxFreshAndExact = false;
  let receiverConfigurationWasExact = false;
  let sdkForwardPolicyBeforeExact = false;
  let executionError: string | undefined;

  try {
    liveLock = await acquireLock(lockPath);
    identity = await verifyEligibleAliasToken({
      token: config.token,
      expectedEmail: ALIAS_EMAIL,
      expectedTeamId: TEAM_ID,
      expectedProjectId: PROJECT_ID,
      manualEmailConfirmation: config.manualAliasConfirmation,
      fetchImpl: requestGate.fetch,
    });
    if (!(await health(config.publicOrigin))) throw new Error("owned SBX-048 receiver health check failed");
    if ((await receiverReadback(config, runId)).configured) throw new Error("fresh receiver run ID already existed");

    createAttempted = true;
    sandbox = await Sandbox.create({
      ...credentials,
      name: sandboxName,
      persistent: false,
      timeout: 480_000,
      resources: { vcpus: 2 },
      ports: [],
      networkPolicy: initialPolicy,
      tags,
      signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
    });
    sessionId = sandbox.currentSession().sessionId;
    receiverConfiguration.expectedSandboxId = sessionId;
    if (sandbox.name !== sandboxName || sandbox.currentSession().sessionId !== sessionId || sandbox.tags?.run !== runId) {
      throw new Error("fresh sandbox identity did not match the exact run");
    }
    sandboxFreshAndExact = true;

    const registration = await adminRequest(config, runId, "", {
      method: "POST",
      body: JSON.stringify(receiverConfiguration),
    });
    if (registration.status !== 201) throw new Error(`receiver registration returned ${registration.status}`);
    if (registration.body) await registration.body.cancel().catch(() => undefined);
    receiverConfigured = true;
    receiverRead = await receiverReadback(config, runId);
    if (!receiverRead.configured || !exactReceiverConfiguration(receiverRead.configuration, receiverConfiguration)) {
      throw new Error("receiver registration did not read back exactly");
    }
    receiverConfigurationWasExact = true;

    const guestSource = await readFile(resolve("guest/sbx-048-forward-probe.mjs"), "utf8");
    if (secrets.some((secret) => guestSource.includes(secret))) throw new Error("guest source contains controller credentials");
    await sandbox.writeFiles([{ path: REMOTE_GUEST_PATH, content: guestSource, mode: 0o700 }], {
      signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
    });
    directCommand = await captureGuest(sandbox, { ...guestBase, expectedMode: "direct" }, secrets);
    receiverRead = await receiverReadback(config, runId);
    const directRecord = receiverRead.directRecords[0];
    if (
      receiverRead.directRecords.length !== 1 || !directRecord || !exactGuestBase(directCommand.result, runId, "direct") ||
      directCommand.result?.responseStatus !== 200 || directCommand.result.responseOperationId !== directRecord.operationId ||
      directRecord.correlationExact !== true || directRecord.oidcHeaderLines !== 0 || directRecord.oidcHeaderValues !== 0
    ) {
      throw new Error("owned-origin direct reachability control failed");
    }

    await sandbox.update({ networkPolicy: finalPolicy }, { signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
    cleanup.policyRestoreRequired = true;
    const independentBefore = await Sandbox.get({
      ...credentials,
      name: sandboxName,
      resume: false,
      signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
    });
    if (
      independentBefore.currentSession().sessionId !== sessionId ||
      !exactForwardSandboxProjection(independentBefore.networkPolicy, config.publicOrigin.hostname) ||
      !exactForwardPolicy(independentBefore.currentSession().networkPolicy, config.publicOrigin.hostname, forwardAudience)
    ) {
      throw new Error("exact forward policy did not read back before the OIDC probe");
    }
    sdkForwardPolicyBeforeExact = true;
    ownerReadBefore = await ownerRead(requestGate.fetch, config.token, sessionId, {
      kind: "forward",
      hostname: config.publicOrigin.hostname,
      forwardAudience,
    });
    if (ownerReadBefore.statusCode !== 200 || !ownerReadBefore.exactSession || !ownerReadBefore.exactPolicy) {
      throw new Error("owner token failed the exact same-route pre-probe read control");
    }

    const fakeResponse = await adminRequest(config, runId, "/fake-control", { method: "POST" });
    if (!fakeResponse.ok) throw new Error(`fake-token control returned ${fakeResponse.status}`);
    if (fakeResponse.body) await fakeResponse.body.cancel().catch(() => undefined);
    receiverRead = await receiverReadback(config, runId);
    if (!receiverRead.fakeControl ||
        (receiverRead.fakeControl.statusCode !== 401 && receiverRead.fakeControl.statusCode !== 403)) {
      throw new Error("fake token was not conclusively rejected by the same control-plane route");
    }

    forwardCommand = await captureGuest(sandbox, { ...guestBase, expectedMode: "forward" }, secrets);
    await new Promise<void>((resolve) => globalThis.setTimeout(resolve, 350));
    receiverRead = await receiverReadback(config, runId);
    const record = receiverRead.records.length === 1 ? receiverRead.records[0] : undefined;
    if (!record || !exactGuestBase(forwardCommand.result, runId, "forward") ||
        forwardCommand.result?.responseStatus !== 202 || forwardCommand.result.responseOperationId !== record.responseOperationId) {
      throw new Error("one exact brokered request was not joined to the receiver record");
    }

    const mutationSucceeded = record.brokeredMutation?.statusCode === 200 &&
      record.brokeredMutation.exactSession === true && record.brokeredMutation.exactPolicy === true;
    ownerReadAfter = await ownerRead(
      requestGate.fetch,
      config.token,
      sessionId,
      mutationSucceeded
        ? { kind: "deny-all" }
        : { kind: "forward", hostname: config.publicOrigin.hostname, forwardAudience },
    );
    const independentAfter = await Sandbox.get({
      ...credentials,
      name: sandboxName,
      resume: false,
      signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
    });
    ownerObservedDenyAllAfterMutation = mutationSucceeded && ownerReadAfter.statusCode === 200 &&
      ownerReadAfter.exactSession && ownerReadAfter.exactPolicy &&
      independentAfter.currentSession().sessionId === sessionId && independentAfter.currentSession().networkPolicy === "deny-all" &&
      exactForwardSandboxProjection(independentAfter.networkPolicy, config.publicOrigin.hostname);

    cleanup.policyRestoreAttempted = true;
    if (sandbox.currentSession().sessionId !== sessionId) throw new Error("pinned source session changed before restoration");
    await sandbox.currentSession().update({ networkPolicy: finalPolicy }, {
      signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
    });
    ownerReadFinal = await ownerRead(requestGate.fetch, config.token, sessionId, {
      kind: "forward",
      hostname: config.publicOrigin.hostname,
      forwardAudience,
    });
    const independentFinal = await Sandbox.get({
      ...credentials,
      name: sandboxName,
      resume: false,
      signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
    });
    ownerFinalOriginalPolicy = ownerReadFinal.statusCode === 200 && ownerReadFinal.exactSession &&
      ownerReadFinal.exactPolicy && independentFinal.currentSession().sessionId === sessionId &&
      exactForwardSandboxProjection(independentFinal.networkPolicy, config.publicOrigin.hostname) &&
      exactForwardPolicy(independentFinal.currentSession().networkPolicy, config.publicOrigin.hostname, forwardAudience);
    cleanup.policyRestored = ownerFinalOriginalPolicy;
    if (!ownerFinalOriginalPolicy) throw new Error("owner token did not restore and verify the exact original policy");
  } catch (error) {
    executionError = safeError(error, secrets);
  } finally {
    if (!sandbox && createAttempted) {
      cleanup.orphanRecoveryAttempted = true;
      try {
        const recovered = await Sandbox.get({
          ...credentials,
          name: sandboxName,
          resume: false,
          signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
        });
        if (recovered.name === sandboxName && recovered.tags?.run === runId && recovered.tags.test === "SBX-048") {
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
      if (cleanup.policyRestoreRequired && !cleanup.policyRestored) {
        cleanup.policyRestoreAttempted = true;
        try {
          if (!sessionId || sandbox.currentSession().sessionId !== sessionId) {
            throw new Error("pinned source session is unavailable for fail-safe restoration");
          }
          await sandbox.currentSession().update({ networkPolicy: finalPolicy }, {
            signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
          });
          ownerReadFinal = await ownerRead(requestGate.fetch, config.token, sessionId, {
            kind: "forward",
            hostname: config.publicOrigin.hostname,
            forwardAudience,
          });
          const independentRestored = await Sandbox.get({
            ...credentials,
            name: sandboxName,
            resume: false,
            signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
          });
          cleanup.policyRestored = ownerReadFinal.statusCode === 200 && ownerReadFinal.exactSession &&
            ownerReadFinal.exactPolicy && independentRestored.currentSession().sessionId === sessionId &&
            exactForwardSandboxProjection(independentRestored.networkPolicy, config.publicOrigin.hostname) &&
            exactForwardPolicy(
              independentRestored.currentSession().networkPolicy,
              config.publicOrigin.hostname,
              forwardAudience,
            );
          ownerFinalOriginalPolicy = cleanup.policyRestored;
          if (!cleanup.policyRestored) cleanup.errors.push("fail-safe policy restoration did not read back exactly");
        } catch (error) {
          cleanup.errors.push(`policy restoration: ${safeError(error, secrets)}`);
        }
      }
      cleanup.stopAttempted = true;
      try {
        await sandbox.stop({ signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
        cleanup.stopped = true;
      } catch (error) {
        cleanup.errors.push(`stop: ${safeError(error, secrets)}`);
      }
      cleanup.deleteAttempted = true;
      try {
        await sandbox.delete({ signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
        cleanup.deleted = true;
      } catch (error) {
        cleanup.errors.push(`delete: ${safeError(error, secrets)}`);
      }
      if (cleanup.deleted) {
        let absent = 0;
        for (let index = 0; index < 2; index += 1) {
          if (index > 0) await new Promise<void>((resolve) => globalThis.setTimeout(resolve, 500));
          try {
            await Sandbox.get({
              ...credentials,
              name: sandboxName,
              resume: false,
              signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
            });
          } catch (error) {
            if (isNotFound(error)) absent += 1;
            else cleanup.errors.push(`absence check: ${safeError(error, secrets)}`);
          }
        }
        cleanup.deletionAbsenceConfirmed = absent === 2;
      }
    }
    if (receiverConfigured) {
      cleanup.receiverDeleteAttempted = true;
      try {
        const response = await adminRequest(config, runId, "", { method: "DELETE" });
        cleanup.receiverDeleted = response.status === 200;
        if (response.body) await response.body.cancel().catch(() => undefined);
        cleanup.receiverAbsent = !(await receiverReadback(config, runId)).configured;
      } catch (error) {
        cleanup.errors.push(`receiver cleanup: ${safeError(error, secrets)}`);
      }
    }
    if (liveLock) {
      try {
        await liveLock.close();
        await unlink(lockPath);
        cleanup.lockReleased = true;
      } catch (error) {
        cleanup.errors.push(`lock cleanup: ${safeError(error, secrets)}`);
      }
    }
  }

  const record: Sbx048ReceiverRecord | undefined = receiverRead.records.length === 1
    ? receiverRead.records[0]
    : undefined;
  const cleanupPassed = (!cleanup.policyRestoreRequired || cleanup.policyRestored) &&
    cleanup.stopped && cleanup.deleted && cleanup.deletionAbsenceConfirmed &&
    cleanup.receiverDeleted && cleanup.receiverAbsent && cleanup.lockReleased && cleanup.errors.length === 0;
  const directRecord = receiverRead.directRecords.length === 1 ? receiverRead.directRecords[0] : undefined;
  const assessment: Sbx048Assessment = assessSbx048({
    scopeAndAliasPassed: identity?.email === ALIAS_EMAIL && identity.teamId === TEAM_ID && identity.projectId === PROJECT_ID,
    sandboxFreshAndExact,
    directOwnedOriginControlPassed: directRecord !== undefined && exactGuestBase(directCommand?.result, runId, "direct") &&
      directCommand?.result?.responseOperationId === directRecord.operationId,
    forwardPolicyReadbackBefore: sdkForwardPolicyBeforeExact && ownerReadBefore?.statusCode === 200 &&
      ownerReadBefore.exactSession && ownerReadBefore.exactPolicy,
    ownerTokenSameRouteReadPassed: ownerReadBefore?.statusCode === 200 && ownerReadBefore.exactSession && ownerReadBefore.exactPolicy,
    receiverConfigurationExact: receiverConfigurationWasExact,
    guestRequestCount: forwardCommand?.result?.requestCount ?? 0,
    guestResponseMatchedRecord: record !== undefined && forwardCommand?.result?.responseOperationId === record.responseOperationId,
    ...(record ? { record } : {}),
    ownerObservedDenyAllAfterMutation,
    ownerFinalOriginalPolicy,
    cleanupPassed,
  });
  const evidence = {
    schemaVersion: 1,
    testId: SBX048_TEST_ID,
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    scope: {
      aliasEmail: ALIAS_EMAIL,
      teamId: TEAM_ID,
      projectId: PROJECT_ID,
      oneOwnedSandbox: true,
      oneOwnedProxyOrigin: config.publicOrigin.origin,
    },
    sandbox: { name: sandboxName, sessionId: sessionId ?? "missing" },
    identity,
    forwardAudience,
    wrongAudience,
    ownerReadBefore,
    ownerReadAfter,
    ownerReadFinal,
    directCommand,
    forwardCommand,
    receiver: {
      configured: receiverConfigured,
      fakeControl: receiverRead.fakeControl,
      directRecords: receiverRead.directRecords,
      records: receiverRead.records,
    },
    requestAudit: requestGate.records,
    assessment,
    ...(executionError ? { executionError } : {}),
    cleanup,
    retention: {
      rawProxyOidcToken: false,
      rawProxyOidcTokenDigest: false,
      rawOwnerToken: false,
      rawControlPlaneBodies: false,
      rawGuestOutput: false,
    },
    evidencePath,
  };
  assertNoTokenMaterial(evidence, secrets);
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  await writePrivateJson(evidencePath, evidence);
  process.stdout.write(`${JSON.stringify({
    testId: SBX048_TEST_ID,
    runId,
    assessment,
    cleanup,
    evidencePath,
  }, null, 2)}\n`);
  if (assessment.verdict === "candidate") process.exitCode = 2;
  else if (assessment.verdict === "indeterminate" || !cleanupPassed) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  main().catch((error) => {
    process.stderr.write(`${String(error instanceof Error ? error.message : error).slice(0, 512)}\n`);
    process.exitCode = 1;
  });
}
