import "dotenv/config";

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { APIError, Sandbox, type NetworkPolicy } from "@vercel/sandbox";
import { verifyEligibleAliasToken } from "../eligible-alias-identity.js";
import {
  SBX057_CASES,
  SBX057_REDACTED_VALUE,
  SBX057_TEST_ID,
  SBX057_TRANSFORM_HEADER,
  expectedOperationId,
  expectedReceipt,
  secretCommitment,
  type Sbx057CaseId,
  type Sbx057Stage,
} from "./protocol.js";
import type { Sbx057ReceiverEvent, Sbx057ReceiverSnapshot } from "./receiver.js";
import {
  SBX057_ARTIFACTS,
  SBX057_CREATE_REQUEST_TIMEOUT_MS,
  SBX057_LOCK_PATH,
  SBX057_SANDBOX_TIMEOUT_MS,
  acquireSbx057Lock,
  acquireSbx057RecoveryLock,
  createSettlementReached,
  createSbx057Journal,
  dispatchSbx057Recovery,
  finalizeSbx057Artifact,
  finalizeSbx057RecoveryArtifact,
  loadSbx057Config,
  persistSbx057Journal,
  readSbx057Journal,
  releaseSbx057LockAndJournal,
  safeSbx057Error,
  sbx057ArtifactPath,
  sbx057JournalPath,
  sbx057Name,
  sbx057Tags,
  writeSbx057Artifact,
  writeSbx057RecoveryArtifact,
  type Sbx057Config,
  type Sbx057HeldLock,
  type Sbx057Journal,
  type Sbx057JournalResource,
} from "./safety.js";
import {
  assessSbx057,
  type Sbx057Assessment,
  type Sbx057AssessmentInput,
  type Sbx057CleanupEvidence,
  type Sbx057CleanupResource,
  type Sbx057ExpectedResourceIdentity,
  type Sbx057PolicyProof,
  type Sbx057ProbeEvidence,
  type Sbx057RetentionEvidence,
} from "./verdict.js";

const REPOSITORY_ROOT = fileURLToPath(new URL("../../", import.meta.url));
const GUEST_SOURCE_PATH = resolve(REPOSITORY_ROOT, "guest/sbx-057-wildcard-empty-probe.mjs");
const REMOTE_GUEST_PATH = "/tmp/sbx-057/wildcard-empty-probe.mjs";
const CONTROL_TIMEOUT_MS = 45_000;
const COMMAND_TIMEOUT_MS = 30_000;
const MAX_RESPONSE_BYTES = 64 * 1024;
const CONTROL_INTERVAL_MS = 250;
const EXPECTED_SDK_VERSION = "3.0.0";

// Updated only after the fixed guest has passed syntax and focused tests.
export const SBX057_FIXED_GUEST_SHA256 =
  "b24110f77c30192a472041c3940d2d698686b3d6b1bd15e4737c3e252560ef0f" as const;

export interface Sbx057SdkAudit {
  installedVersion: "3.0.0";
  canonicalWildcardEmptyExamplePresent: true;
  requestSerializerPassesRecordPolicy: true;
  responseProjectionRebuildsInjectionRulesByDomain: true;
}

interface RuntimeState {
  comparator?: Sandbox;
  target?: Sandbox;
}

interface ExpectedEvidence {
  commitments: Record<Sbx057Stage, string>;
  operationIds: Record<Sbx057CaseId, string>;
  receipts: Sbx057AssessmentInput["expectedReceipts"];
}

export class RequestGate {
  private lastAt = 0;
  private chain: Promise<void> = Promise.resolve();

  before(): Promise<void> {
    const next = this.chain.then(async () => {
      const remaining = CONTROL_INTERVAL_MS - (Date.now() - this.lastAt);
      if (remaining > 0) await delay(remaining);
      this.lastAt = Date.now();
    });
    this.chain = next.catch(() => undefined);
    return next;
  }

  readonly fetch: typeof fetch = async (input, init) => {
    await this.before();
    return fetch(input, init);
  };
}

function signal(timeout = CONTROL_TIMEOUT_MS): AbortSignal {
  return AbortSignal.timeout(timeout);
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function exactKeys(value: object, required: readonly string[], optional: readonly string[] = []): boolean {
  const keys = Object.keys(value);
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    keys.every((key) => allowed.has(key)) && keys.length === required.length +
      optional.filter((key) => Object.prototype.hasOwnProperty.call(value, key)).length;
}

function exactTags(actual: Record<string, string> | undefined, expected: Record<string, string>): boolean {
  return actual !== undefined && Object.keys(actual).length === Object.keys(expected).length &&
    Object.entries(expected).every(([key, value]) => actual[key] === value);
}

function isNotFound(error: unknown): boolean {
  return error instanceof APIError && error.response.status === 404;
}

async function absent(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return false;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return true;
    throw error;
  }
}

export function sbx057Policy(
  stage: Sbx057Stage,
  aHostname: string,
  bHostname: string,
  secret: string,
): NetworkPolicy {
  return {
    allow: {
      [aHostname]: [{ transform: [{ headers: { [SBX057_TRANSFORM_HEADER]: secret } }] }],
      [stage === "comparator" ? bHostname : "*"]: [],
    },
  };
}

export function sbx057CreateParameters(
  config: Pick<Sbx057Config, "token" | "teamId" | "projectId">,
  gate: RequestGate,
  role: Sbx057Stage,
  runId: string,
  aHostname: string,
  bHostname: string,
  secret: string,
) {
  return {
    token: config.token,
    teamId: config.teamId,
    projectId: config.projectId,
    fetch: gate.fetch,
    name: sbx057Name(role, runId),
    persistent: false as const,
    timeout: SBX057_SANDBOX_TIMEOUT_MS,
    ports: [] as number[],
    env: {} as Record<string, string>,
    tags: sbx057Tags(role, runId),
    networkPolicy: sbx057Policy(role, aHostname, bHostname, secret),
    signal: signal(SBX057_CREATE_REQUEST_TIMEOUT_MS),
  };
}

function exactStringSet(value: unknown, expected: readonly string[]): boolean {
  return Array.isArray(value) && value.every((entry): entry is string => typeof entry === "string") &&
    value.length === expected.length && new Set(value).size === value.length &&
    [...value].sort().every((entry, index) => entry === [...expected].sort()[index]);
}

export function sanitizeSbx057TopPolicy(value: unknown, aHostname: string, other: string): unknown {
  const root = object(value);
  if (root === undefined || !exactKeys(root, ["allow"]) || !exactStringSet(root.allow, [aHostname, other])) {
    throw new Error("SBX-057 top-level policy projection was not exact");
  }
  return { allow: [...(root.allow as string[])] };
}

export function sanitizeSbx057SessionPolicy(
  value: unknown,
  aHostname: string,
  other: string,
  secret: string,
): unknown {
  const root = object(value);
  const allow = root === undefined ? undefined : object(root.allow);
  if (root === undefined || !exactKeys(root, ["allow"]) || allow === undefined ||
      !exactKeys(allow, [aHostname, other]) || !Array.isArray(allow[aHostname]) ||
      allow[aHostname].length !== 1 || !Array.isArray(allow[other]) || allow[other].length !== 0) {
    throw new Error("SBX-057 session policy projection was not exact");
  }
  const rule = object(allow[aHostname][0]);
  const transform = rule !== undefined && Array.isArray(rule.transform) && rule.transform.length === 1
    ? object(rule.transform[0])
    : undefined;
  const headers = transform === undefined ? undefined : object(transform.headers);
  if (rule === undefined || !exactKeys(rule, ["transform"]) || transform === undefined ||
      !exactKeys(transform, ["headers"]) || headers === undefined ||
      !exactKeys(headers, [SBX057_TRANSFORM_HEADER]) ||
      (headers[SBX057_TRANSFORM_HEADER] !== secret &&
        headers[SBX057_TRANSFORM_HEADER] !== SBX057_REDACTED_VALUE)) {
    throw new Error("SBX-057 transform projection was not exact");
  }
  return {
    allow: {
      [aHostname]: [{ transform: [{ headers: { [SBX057_TRANSFORM_HEADER]: SBX057_REDACTED_VALUE } }] }],
      [other]: [],
    },
  };
}

export async function captureSbx057PolicyProof(input: {
  stage: Sbx057Stage;
  sandbox: Sandbox;
  sessionId: string;
  config: Sbx057Config;
  gate: RequestGate;
  secret: string;
}): Promise<Sbx057PolicyProof> {
  const other = input.stage === "comparator" ? input.config.bOrigin.hostname : "*";
  const expected = sbx057Policy(
    input.stage, input.config.aOrigin.hostname, input.config.bOrigin.hostname, input.secret,
  );
  await input.gate.before();
  const independent = await Sandbox.get({
    token: input.config.token,
    teamId: input.config.teamId,
    projectId: input.config.projectId,
    fetch: input.gate.fetch,
    name: input.sandbox.name,
    resume: false,
    signal: signal(),
  });
  const activeSession = input.sandbox.currentSession();
  const independentSession = independent.currentSession();
  const observed = [
    input.sandbox.networkPolicy,
    activeSession.networkPolicy,
    independent.networkPolicy,
    independentSession.networkPolicy,
  ];
  const rawSecretPresent = JSON.stringify(observed).includes(input.secret);
  const retained = {
    activeSandboxPolicy: sanitizeSbx057TopPolicy(observed[0], input.config.aOrigin.hostname, other),
    activeSessionPolicy: sanitizeSbx057SessionPolicy(observed[1], input.config.aOrigin.hostname, other, input.secret),
    independentSandboxPolicy: sanitizeSbx057TopPolicy(observed[2], input.config.aOrigin.hostname, other),
    independentSessionPolicy: sanitizeSbx057SessionPolicy(
      observed[3], input.config.aOrigin.hostname, other, input.secret,
    ),
  };
  const configuredExact = JSON.stringify(expected) === JSON.stringify(
    sbx057Policy(input.stage, input.config.aOrigin.hostname, input.config.bOrigin.hostname, input.secret),
  );
  if (!configuredExact || rawSecretPresent || !JSON.stringify(retained).includes(SBX057_REDACTED_VALUE)) {
    throw new Error("SBX-057 policy proof retained raw or mismatched configuration state");
  }
  return {
    stage: input.stage,
    capturedAt: new Date().toISOString(),
    expectedSessionId: input.sessionId,
    activeSessionId: activeSession.sessionId,
    independentSessionId: independentSession.sessionId,
    ...retained,
    configuredPolicyComparedExactlyInMemory: true,
    rawSecretPresentInReadbacks: false,
    platformRedactionMarkerPresent: true,
  };
}

export function exactSbx057CreateProvenance(
  sandbox: Sandbox,
  journal: Sbx057Journal,
  resource: Sbx057JournalResource,
): boolean {
  const sessionId = sandbox.currentSession().sessionId;
  return sandbox.name === resource.name && sandbox.persistent === false &&
    exactTags(sandbox.tags, resource.tags) && /^sbx_[A-Za-z0-9_-]{20,100}$/u.test(sessionId) &&
    sandbox.createdAt.getTime() >= Date.parse(journal.startedAt) - 5_000 &&
    sandbox.createdAt.getTime() <= Date.now() + 5_000;
}

async function auditLocalSources(): Promise<{ audit: Sbx057SdkAudit; guestSource: string }> {
  const metadata = JSON.parse(await readFile(
    new URL("../../node_modules/@vercel/sandbox/package.json", import.meta.url), "utf8",
  )) as { version?: unknown };
  const declarations = await readFile(
    new URL("../../node_modules/@vercel/sandbox/dist/network-policy.d.ts", import.meta.url), "utf8",
  );
  const serializer = await readFile(
    new URL("../../node_modules/@vercel/sandbox/dist/utils/network-policy.js", import.meta.url), "utf8",
  );
  const guestSource = await readFile(GUEST_SOURCE_PATH, "utf8");
  const digest = createHash("sha256").update(guestSource).digest("hex");
  if (metadata.version !== EXPECTED_SDK_VERSION || !declarations.includes('"*": []') ||
      !serializer.includes("NetworkPolicyRequestValidator.parse(apiPolicy)") ||
      !serializer.includes("for (const rule of api.injectionRules ?? [])") ||
      digest !== SBX057_FIXED_GUEST_SHA256) {
    throw new Error("SBX-057 installed SDK semantics or fixed guest changed");
  }
  return {
    audit: {
      installedVersion: "3.0.0",
      canonicalWildcardEmptyExamplePresent: true,
      requestSerializerPassesRecordPolicy: true,
      responseProjectionRebuildsInjectionRulesByDomain: true,
    },
    guestSource,
  };
}

async function boundedJson(response: Response): Promise<unknown> {
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) throw new Error("SBX-057 response exceeded bound");
  const bytes = Buffer.from(await response.arrayBuffer());
  try {
    if (bytes.byteLength > MAX_RESPONSE_BYTES) throw new Error("SBX-057 response exceeded bound");
    return bytes.byteLength === 0 ? undefined : JSON.parse(bytes.toString("utf8"));
  } finally {
    bytes.fill(0);
  }
}

async function adminRequest(input: {
  config: Sbx057Config;
  gate: RequestGate;
  path: string;
  method: "GET" | "POST" | "DELETE";
  expected: number | readonly number[];
  body?: unknown;
}): Promise<unknown> {
  await input.gate.before();
  const response = await fetch(new URL(input.path, input.config.adminOrigin), {
    method: input.method,
    headers: {
      authorization: `Bearer ${input.config.adminKey}`,
      ...(input.body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(input.body === undefined ? {} : { body: JSON.stringify(input.body) }),
    redirect: "error",
    signal: signal(),
  });
  const expected = Array.isArray(input.expected) ? input.expected : [input.expected];
  if (!expected.includes(response.status)) throw new Error("SBX-057 admin response status was unexpected");
  return boundedJson(response);
}

async function publicHealth(config: Sbx057Config, gate: RequestGate, role: "A" | "B"): Promise<boolean> {
  await gate.before();
  const origin = role === "A" ? config.aOrigin : config.bOrigin;
  const response = await fetch(new URL("/healthz", origin), {
    method: "GET", redirect: "error", cache: "no-store", signal: signal(15_000),
  });
  const root = object(await boundedJson(response));
  return response.status === 200 && root !== undefined && exactKeys(root, ["ok", "testId", "role"]) &&
    root.ok === true && root.testId === SBX057_TEST_ID && root.role === role;
}

function parseEvent(value: unknown, sequence: number): Sbx057ReceiverEvent {
  const root = object(value);
  const required = [
    "sequence", "observedAt", "kind", "role", "caseId", "method", "hostMatched", "pathMatched",
    "correlationHeadersExact", "transformHeaderLines", "transformHeaderValues",
    "transformCommitmentMatched", "crossCommitmentMatched", "responseStatus",
  ];
  if (root === undefined || !exactKeys(root, required, ["receipt", "operationId"]) ||
      root.sequence !== sequence || typeof root.observedAt !== "string" ||
      !Number.isFinite(Date.parse(root.observedAt)) || (root.kind !== "expected" && root.kind !== "unexpected") ||
      (root.role !== "A" && root.role !== "B") ||
      !(root.caseId === "unknown" || (SBX057_CASES as readonly unknown[]).includes(root.caseId)) ||
      typeof root.method !== "string" || typeof root.hostMatched !== "boolean" ||
      typeof root.pathMatched !== "boolean" || typeof root.correlationHeadersExact !== "boolean" ||
      !Number.isInteger(root.transformHeaderLines) || !Number.isInteger(root.transformHeaderValues) ||
      typeof root.transformCommitmentMatched !== "boolean" || typeof root.crossCommitmentMatched !== "boolean" ||
      !Number.isInteger(root.responseStatus) ||
      !(root.receipt === undefined || typeof root.receipt === "string") ||
      !(root.operationId === undefined || typeof root.operationId === "string")) {
    throw new Error("SBX-057 receiver event was not exact");
  }
  return {
    sequence,
    observedAt: root.observedAt,
    kind: root.kind,
    role: root.role,
    caseId: root.caseId as Sbx057ReceiverEvent["caseId"],
    method: root.method,
    hostMatched: root.hostMatched,
    pathMatched: root.pathMatched,
    correlationHeadersExact: root.correlationHeadersExact,
    transformHeaderLines: root.transformHeaderLines as number,
    transformHeaderValues: root.transformHeaderValues as number,
    transformCommitmentMatched: root.transformCommitmentMatched,
    crossCommitmentMatched: root.crossCommitmentMatched,
    responseStatus: root.responseStatus as number,
    ...(root.receipt === undefined ? {} : { receipt: root.receipt }),
    ...(root.operationId === undefined ? {} : { operationId: root.operationId }),
  };
}

export function parseSbx057ReceiverSnapshot(value: unknown): Sbx057ReceiverSnapshot {
  const root = object(value);
  const keys = [
    "schemaVersion", "testId", "runId", "configuredAt", "configurationValid", "rawSecretsRetained",
    "unexpectedIngressCount", "unattributedIngressCount", "events",
  ];
  if (root === undefined || !exactKeys(root, keys) || root.schemaVersion !== 1 ||
      root.testId !== SBX057_TEST_ID || typeof root.runId !== "string" ||
      typeof root.configuredAt !== "string" || !Number.isFinite(Date.parse(root.configuredAt)) ||
      root.configurationValid !== true || root.rawSecretsRetained !== false ||
      !Number.isInteger(root.unexpectedIngressCount) || (root.unexpectedIngressCount as number) < 0 ||
      !Number.isInteger(root.unattributedIngressCount) || (root.unattributedIngressCount as number) < 0 ||
      !Array.isArray(root.events) || root.events.length > 32) {
    throw new Error("SBX-057 receiver snapshot was not exact");
  }
  return {
    schemaVersion: 1,
    testId: SBX057_TEST_ID,
    runId: root.runId,
    configuredAt: root.configuredAt,
    configurationValid: true,
    rawSecretsRetained: false,
    unexpectedIngressCount: root.unexpectedIngressCount as number,
    unattributedIngressCount: root.unattributedIngressCount as number,
    events: root.events.map((entry, index) => parseEvent(entry, index + 1)),
  };
}

async function receiverSnapshot(config: Sbx057Config, gate: RequestGate, runId: string): Promise<Sbx057ReceiverSnapshot> {
  return parseSbx057ReceiverSnapshot(await adminRequest({
    config, gate, path: `/v1/sbx057/admin/runs/${runId}`, method: "GET", expected: 200,
  }));
}

function parseGuestResult(value: unknown, input: {
  runId: string;
  caseId: Sbx057CaseId;
  canary: string;
  hostname: string;
  startedAt: string;
  completedAt: string;
  commandExitCode: number;
}): Sbx057ProbeEvidence {
  const root = object(value);
  const required = [
    "schemaVersion", "testId", "runId", "caseId", "canary", "ok", "requestHostname",
    "requestServername", "requestHostHeader", "requestPath", "connectionAttempts", "actualConnections",
    "actualRequests", "retries", "redirectsFollowed", "rejectUnauthorized",
    "controllerConfigurableCustomTrustAccepted", "inheritedPlatformTrustEnvironmentNames", "tcpConnected",
    "tlsEstablished", "tlsAuthorized", "responseReceived", "responseShapeValid", "responseBodyRetained",
    "durationMs",
  ];
  const optional = ["responseStatusCode", "responseRole", "responseReceipt", "responseOperationId", "errorCode"];
  if (root === undefined || !exactKeys(root, required, optional) || root.schemaVersion !== 1 ||
      root.testId !== SBX057_TEST_ID || root.runId !== input.runId || root.caseId !== input.caseId ||
      root.canary !== input.canary || root.ok !== true || root.requestHostname !== input.hostname ||
      root.requestServername !== input.hostname || root.requestHostHeader !== input.hostname ||
      !Number.isInteger(root.connectionAttempts) || !Number.isInteger(root.actualConnections) ||
      !Number.isInteger(root.actualRequests) || !Number.isInteger(root.retries) ||
      !Number.isInteger(root.redirectsFollowed) || typeof root.rejectUnauthorized !== "boolean" ||
      typeof root.controllerConfigurableCustomTrustAccepted !== "boolean" ||
      !Array.isArray(root.inheritedPlatformTrustEnvironmentNames) ||
      !root.inheritedPlatformTrustEnvironmentNames.every((entry) => typeof entry === "string") ||
      typeof root.tcpConnected !== "boolean" || typeof root.tlsEstablished !== "boolean" ||
      typeof root.tlsAuthorized !== "boolean" || typeof root.responseReceived !== "boolean" ||
      typeof root.responseShapeValid !== "boolean" || typeof root.responseBodyRetained !== "boolean" ||
      typeof root.durationMs !== "number" || !Number.isFinite(root.durationMs) || root.durationMs < 0 ||
      typeof root.responseStatusCode !== "number" || typeof root.responseRole !== "string" ||
      typeof root.responseReceipt !== "string" ||
      !(root.responseOperationId === undefined || typeof root.responseOperationId === "string")) {
    throw new Error("SBX-057 guest result was not exact");
  }
  return {
    schemaVersion: 1,
    testId: SBX057_TEST_ID,
    runId: input.runId,
    caseId: input.caseId,
    canary: input.canary,
    commandExitCode: input.commandExitCode,
    ok: true,
    requestHostname: root.requestHostname,
    requestServername: root.requestServername,
    requestHostHeader: root.requestHostHeader,
    requestPath: root.requestPath as string,
    connectionAttempts: root.connectionAttempts as number,
    actualConnections: root.actualConnections as number,
    actualRequests: root.actualRequests as number,
    retries: root.retries as number,
    redirectsFollowed: root.redirectsFollowed as number,
    rejectUnauthorized: root.rejectUnauthorized,
    controllerConfigurableCustomTrustAccepted: root.controllerConfigurableCustomTrustAccepted,
    inheritedPlatformTrustEnvironmentNames: [...root.inheritedPlatformTrustEnvironmentNames] as string[],
    tcpConnected: root.tcpConnected,
    tlsEstablished: root.tlsEstablished,
    tlsAuthorized: root.tlsAuthorized,
    responseReceived: root.responseReceived,
    responseStatusCode: root.responseStatusCode,
    responseShapeValid: root.responseShapeValid,
    responseRole: root.responseRole,
    responseReceipt: root.responseReceipt,
    ...(root.responseOperationId === undefined ? {} : { responseOperationId: root.responseOperationId }),
    responseBodyRetained: root.responseBodyRetained,
    durationMs: root.durationMs,
    startedAt: input.startedAt,
    completedAt: input.completedAt,
  };
}

async function runProbe(input: {
  sandbox: Sandbox;
  gate: RequestGate;
  guestSource: string;
  config: Sbx057Config;
  runId: string;
  caseId: Sbx057CaseId;
  canary: string;
  forbidden: readonly string[];
}): Promise<{ probe: Sbx057ProbeEvidence; configuration: string; stdout: string; argv: string[] }> {
  const origin = input.caseId.endsWith("-a") ? input.config.aOrigin.origin : input.config.bOrigin.origin;
  const configuration = JSON.stringify({
    schemaVersion: 1, testId: SBX057_TEST_ID, runId: input.runId,
    caseId: input.caseId, canary: input.canary, origin,
  });
  const encoded = Buffer.from(configuration).toString("base64url");
  const argv = [REMOTE_GUEST_PATH, encoded];
  if (input.forbidden.some((secret) => configuration.includes(secret) || encoded.includes(secret) ||
      argv.some((entry) => entry.includes(secret)))) throw new Error("SBX-057 secret entered guest input");
  const startedAt = new Date().toISOString();
  await input.gate.before();
  const command = await input.sandbox.currentSession().runCommand({
    cmd: "node", args: argv, timeoutMs: COMMAND_TIMEOUT_MS, signal: signal(),
  });
  const [stdout, stderr] = await Promise.all([command.stdout(), command.stderr()]);
  const completedAt = new Date().toISOString();
  if (stderr !== "" || stdout.length > 64 * 1024 || input.forbidden.some((secret) => stdout.includes(secret))) {
    throw new Error("SBX-057 guest output was not secret-free and exact");
  }
  const lines = stdout.trimEnd().split("\n");
  if (lines.length !== 1) throw new Error("SBX-057 guest emitted more than one JSON record");
  const probe = parseGuestResult(JSON.parse(lines[0]!), {
    runId: input.runId, caseId: input.caseId, canary: input.canary,
    hostname: new URL(origin).hostname, startedAt, completedAt, commandExitCode: command.exitCode,
  });
  return { probe, configuration, stdout, argv };
}

function exactComparatorEvent(
  event: Sbx057ReceiverEvent | undefined,
  caseId: "comparator-a" | "comparator-b",
  expected: ExpectedEvidence,
  leak: boolean,
): boolean {
  if (event === undefined) return false;
  const sequence = caseId === "comparator-a" ? 1 : 2;
  const isA = caseId === "comparator-a";
  const status = isA || leak ? 200 : 202;
  const receipt = isA ? expected.receipts.comparatorAAction
    : leak ? expected.receipts.comparatorBAction : expected.receipts.comparatorBNone;
  return event.sequence === sequence && event.kind === "expected" && event.caseId === caseId &&
    event.role === (isA ? "A" : "B") && event.method === "GET" && event.hostMatched &&
    event.pathMatched && event.correlationHeadersExact && event.transformHeaderLines === (isA || leak ? 1 : 0) &&
    event.transformHeaderValues === (isA || leak ? 1 : 0) && event.transformCommitmentMatched === (isA || leak) &&
    !event.crossCommitmentMatched && event.responseStatus === status && event.receipt === receipt &&
    (status === 200 ? event.operationId === expected.operationIds[caseId] : event.operationId === undefined);
}

export function classifySbx057Comparator(
  snapshot: Sbx057ReceiverSnapshot,
  probes: Partial<Record<Sbx057CaseId, Sbx057ProbeEvidence>>,
  expected: ExpectedEvidence,
): "clean" | "leak" | "invalid" {
  if (snapshot.events.length !== 2 || snapshot.unexpectedIngressCount !== 0 ||
      snapshot.unattributedIngressCount !== 0 || !exactComparatorEvent(snapshot.events[0], "comparator-a", expected, true)) {
    return "invalid";
  }
  const b = snapshot.events[1];
  const bProbe = probes["comparator-b"];
  const aProbe = probes["comparator-a"];
  if (aProbe?.responseStatusCode !== 200 || aProbe.responseReceipt !== expected.receipts.comparatorAAction ||
      aProbe.responseOperationId !== expected.operationIds["comparator-a"] || bProbe === undefined) return "invalid";
  if (exactComparatorEvent(b, "comparator-b", expected, false) && bProbe.responseStatusCode === 202 &&
      bProbe.responseReceipt === expected.receipts.comparatorBNone && bProbe.responseOperationId === undefined) return "clean";
  if (exactComparatorEvent(b, "comparator-b", expected, true) && bProbe.responseStatusCode === 200 &&
      bProbe.responseReceipt === expected.receipts.comparatorBAction &&
      bProbe.responseOperationId === expected.operationIds["comparator-b"]) return "leak";
  return "invalid";
}

async function verifyIdentity(config: Sbx057Config, gate: RequestGate): Promise<void> {
  await verifyEligibleAliasToken({
    token: config.token,
    expectedEmail: config.alias,
    expectedTeamId: config.teamId,
    expectedProjectId: config.projectId,
    manualEmailConfirmation: config.alias,
    fetchImpl: gate.fetch,
  });
}

async function createSandbox(input: {
  config: Sbx057Config;
  gate: RequestGate;
  journal: Sbx057Journal;
  lock: Sbx057HeldLock;
  role: Sbx057Stage;
  secret: string;
}): Promise<Sandbox> {
  const resource = input.journal.resources[input.role === "comparator" ? 0 : 1];
  resource.createAttemptedAt = new Date().toISOString();
  input.journal.phase = input.role;
  await persistSbx057Journal(input.lock, input.journal);
  await input.gate.before();
  const sandbox = await Sandbox.create(sbx057CreateParameters(
    input.config, input.gate, input.role, input.journal.runId,
    input.config.aOrigin.hostname, input.config.bOrigin.hostname, input.secret,
  ));
  if (!exactSbx057CreateProvenance(sandbox, input.journal, resource)) {
    throw new Error("SBX-057 create response provenance was invalid");
  }
  resource.createSettledAt = new Date().toISOString();
  resource.sessionId = sandbox.currentSession().sessionId;
  resource.provenanceValidated = true;
  await persistSbx057Journal(input.lock, input.journal);
  return sandbox;
}

async function getByName(config: Sbx057Config, gate: RequestGate, name: string): Promise<Sandbox | undefined> {
  await gate.before();
  try {
    return await Sandbox.get({
      token: config.token, teamId: config.teamId, projectId: config.projectId,
      fetch: gate.fetch, name, resume: false, signal: signal(),
    });
  } catch (error) {
    if (isNotFound(error)) return undefined;
    throw error;
  }
}

async function cleanupResource(input: {
  config: Sbx057Config;
  gate: RequestGate;
  journal: Sbx057Journal;
  lock: Sbx057HeldLock;
  role: Sbx057Stage;
  active?: Sandbox;
}): Promise<Sbx057CleanupResource | undefined> {
  const resource = input.journal.resources[input.role === "comparator" ? 0 : 1];
  if (resource.createAttemptedAt === undefined) return undefined;
  const evidence: Sbx057CleanupResource = {
    role: input.role,
    exactProvenance: false,
    stopAttempted: resource.stopAttempted,
    stopped: false,
    deleteAttempted: resource.deleteAttempted,
    deleted: resource.deleted,
    absenceChecks: resource.absenceChecks,
    errors: [],
  };
  let sandbox = input.active;
  try {
    if (sandbox === undefined) sandbox = await getByName(input.config, input.gate, resource.name);
    if (sandbox === undefined && resource.sessionId === undefined) {
      if (!createSettlementReached(resource)) {
        evidence.errors.push("create-settlement-uncertain");
        return evidence;
      }
      for (let check = 1; check <= 3; check += 1) {
        if (check > 1) await delay(check === 2 ? 1_500 : 3_000);
        if (await getByName(input.config, input.gate, resource.name) !== undefined) {
          evidence.errors.push("late-create-visible");
          return evidence;
        }
        resource.absenceChecks = check;
        await persistSbx057Journal(input.lock, input.journal);
      }
      resource.absenceOnlyValidated = true;
      resource.deleted = true;
      await persistSbx057Journal(input.lock, input.journal);
      evidence.deleted = true;
      evidence.absenceChecks = 3;
      return evidence;
    }
    if (sandbox === undefined) {
      if (!resource.provenanceValidated) {
        evidence.errors.push("missing-unvalidated-resource");
        return evidence;
      }
    } else {
      if (!exactSbx057CreateProvenance(sandbox, input.journal, resource)) {
        evidence.errors.push("cleanup-provenance-mismatch");
        return evidence;
      }
      const observedSessionId = sandbox.currentSession().sessionId;
      if (resource.sessionId === undefined) {
        resource.sessionId = observedSessionId;
        resource.createSettledAt = new Date().toISOString();
        resource.provenanceValidated = true;
        await persistSbx057Journal(input.lock, input.journal);
      } else if (resource.sessionId !== observedSessionId) {
        evidence.errors.push("cleanup-session-mismatch");
        return evidence;
      }
      evidence.exactProvenance = true;
      await input.gate.before();
      await sandbox.updateNetworkPolicy("deny-all", { signal: signal() });
      resource.stopAttempted = true;
      evidence.stopAttempted = true;
      await persistSbx057Journal(input.lock, input.journal);
      await input.gate.before();
      await sandbox.stop({ signal: signal() });
      evidence.stopped = true;
      resource.deleteAttempted = true;
      evidence.deleteAttempted = true;
      await persistSbx057Journal(input.lock, input.journal);
      await input.gate.before();
      await sandbox.delete({ signal: signal() });
    }
    for (let check = 1; check <= 3; check += 1) {
      if (check > 1) await delay(check === 2 ? 750 : 1_500);
      if (await getByName(input.config, input.gate, resource.name) !== undefined) {
        evidence.errors.push("resource-still-visible");
        return evidence;
      }
      resource.absenceChecks = check;
      await persistSbx057Journal(input.lock, input.journal);
    }
    resource.deleted = true;
    await persistSbx057Journal(input.lock, input.journal);
    evidence.exactProvenance = resource.provenanceValidated;
    evidence.stopAttempted = resource.stopAttempted;
    evidence.stopped = resource.stopAttempted;
    evidence.deleteAttempted = resource.deleteAttempted;
    evidence.deleted = true;
    evidence.absenceChecks = resource.absenceChecks;
    return evidence;
  } catch (error) {
    evidence.errors.push(safeSbx057Error(error, [input.config.token]));
    return evidence;
  }
}

async function cleanupReceiver(input: {
  config: Sbx057Config;
  gate: RequestGate;
  journal: Sbx057Journal;
  lock: Sbx057HeldLock;
}): Promise<{ attempted: boolean; deleted: boolean; absenceChecks: number; errors: string[] }> {
  if (!input.journal.receiverConfigureAttempted) {
    input.journal.receiverDeleted = true;
    await persistSbx057Journal(input.lock, input.journal);
    return { attempted: false, deleted: true, absenceChecks: 0, errors: [] };
  }
  const result = { attempted: true, deleted: false, absenceChecks: 0, errors: [] as string[] };
  try {
    await adminRequest({
      config: input.config, gate: input.gate,
      path: `/v1/sbx057/admin/runs/${input.journal.runId}`, method: "DELETE", expected: [200, 404],
    });
    for (let check = 1; check <= 2; check += 1) {
      await adminRequest({
        config: input.config, gate: input.gate,
        path: `/v1/sbx057/admin/runs/${input.journal.runId}`, method: "GET", expected: 404,
      });
      result.absenceChecks = check;
    }
    input.journal.receiverDeleted = true;
    await persistSbx057Journal(input.lock, input.journal);
    result.deleted = true;
  } catch (error) {
    result.errors.push(safeSbx057Error(error, [input.config.adminKey, input.config.actionKey, input.config.token]));
  }
  return result;
}

function expectedEvidence(config: Sbx057Config, runId: string, secrets: Record<Sbx057Stage, string>,
  canaries: Record<Sbx057CaseId, string>): ExpectedEvidence {
  const commitments = {
    comparator: secretCommitment(config.actionKey, runId, "comparator", secrets.comparator),
    target: secretCommitment(config.actionKey, runId, "target", secrets.target),
  };
  const operationIds = Object.fromEntries(SBX057_CASES.map((caseId) => [
    caseId,
    expectedOperationId(config.actionKey, runId, caseId, canaries[caseId],
      caseId.startsWith("comparator-") ? commitments.comparator : commitments.target),
  ])) as Record<Sbx057CaseId, string>;
  const receipt = (sequence: number, caseId: Sbx057CaseId, count: number, matched: boolean,
    status: number, operationId?: string): string => expectedReceipt(
    config.adminKey, runId, sequence, caseId, canaries[caseId], caseId.endsWith("-a") ? "A" : "B",
    count, matched, false, status, operationId,
  );
  return {
    commitments,
    operationIds,
    receipts: {
      comparatorAAction: receipt(1, "comparator-a", 1, true, 200, operationIds["comparator-a"]),
      comparatorBNone: receipt(2, "comparator-b", 0, false, 202),
      comparatorBAction: receipt(2, "comparator-b", 1, true, 200, operationIds["comparator-b"]),
      targetAAction: receipt(3, "target-a", 1, true, 200, operationIds["target-a"]),
      targetBNone: receipt(4, "target-b", 0, false, 202),
      targetBAction: receipt(4, "target-b", 1, true, 200, operationIds["target-b"]),
    },
  };
}

function expectedResource(resource: Sbx057JournalResource): Sbx057ExpectedResourceIdentity | undefined {
  return resource.provenanceValidated && resource.sessionId !== undefined ? {
    role: resource.role, name: resource.name, sessionId: resource.sessionId,
    persistent: false, tags: { ...resource.tags },
  } : undefined;
}

function secretFree(value: unknown, forbidden: readonly string[]): boolean {
  const serialized = JSON.stringify(value);
  return forbidden.every((entry) => !serialized.includes(entry));
}

function missingSnapshot(runId: string): Sbx057ReceiverSnapshot {
  return {
    schemaVersion: 1, testId: SBX057_TEST_ID, runId,
    configuredAt: new Date(0).toISOString(), configurationValid: true,
    rawSecretsRetained: false, unexpectedIngressCount: 1, unattributedIngressCount: 1, events: [],
  };
}

function missingPolicy(stage: Sbx057Stage): Sbx057PolicyProof {
  return {
    stage, capturedAt: new Date(0).toISOString(), expectedSessionId: "missing",
    activeSessionId: "missing", independentSessionId: "missing",
    activeSandboxPolicy: undefined, activeSessionPolicy: undefined,
    independentSandboxPolicy: undefined, independentSessionPolicy: undefined,
    configuredPolicyComparedExactlyInMemory: true, rawSecretPresentInReadbacks: false,
    platformRedactionMarkerPresent: true,
  };
}

function emptyCleanup(): Sbx057CleanupEvidence {
  return {
    resources: [], receiverDeleteAttempted: false, receiverDeleted: false,
    receiverAbsenceChecks: 0, journalRemoved: false, liveLockRemoved: false,
    lockTransactionRemoved: false, errors: [],
  };
}

export async function runSbx057(config: Sbx057Config): Promise<Sbx057Assessment> {
  const journal = createSbx057Journal();
  const lock = await acquireSbx057Lock(journal);
  const gate = new RequestGate();
  const runtime: RuntimeState = {};
  const secrets = {
    comparator: `s57sec_${randomBytes(32).toString("base64url")}`,
    target: `s57sec_${randomBytes(32).toString("base64url")}`,
  };
  const forbidden = [config.token, config.adminKey, config.actionKey, secrets.comparator, secrets.target,
    createHash("sha256").update(secrets.comparator).digest("hex"),
    createHash("sha256").update(secrets.target).digest("hex")];
  const canaries = Object.fromEntries(SBX057_CASES.map((caseId) => [
    caseId, `s57_${caseId}_${randomBytes(16).toString("base64url")}`,
  ])) as Record<Sbx057CaseId, string>;
  const expected = expectedEvidence(config, journal.runId, secrets, canaries);
  const probes: Partial<Record<Sbx057CaseId, Sbx057ProbeEvidence>> = {};
  const policies: Sbx057AssessmentInput["policies"] = {
    comparatorBefore: missingPolicy("comparator"), comparatorAfter: missingPolicy("comparator"),
  };
  const cleanup = emptyCleanup();
  let guestSource = "";
  let sdkAudit: Sbx057SdkAudit | undefined;
  let identityVerified = false;
  let ledger = missingSnapshot(journal.runId);
  let receiverSnapshotAt = new Date(0).toISOString();
  let comparatorCleanupCompletedAt: string | undefined;
  let controllerError: string | undefined;
  let comparatorClassification: "clean" | "leak" | "invalid" = "invalid";
  const guestInputs: string[] = [];
  const guestOutputs: string[] = [];

  try {
    await verifyIdentity(config, gate);
    identityVerified = true;
    ({ audit: sdkAudit, guestSource } = await auditLocalSources());
    if (forbidden.some((entry) => guestSource.includes(entry))) throw new Error("SBX-057 guest source retained secret state");
    if (!await publicHealth(config, gate, "A") || !await publicHealth(config, gate, "B")) {
      throw new Error("SBX-057 two-origin receiver preflight failed");
    }
    journal.receiverConfigureAttempted = true;
    await persistSbx057Journal(lock, journal);
    await adminRequest({
      config, gate, path: `/v1/sbx057/admin/runs/${journal.runId}`, method: "POST", expected: 201,
      body: {
        testId: SBX057_TEST_ID, runId: journal.runId,
        aHostname: config.aOrigin.hostname, bHostname: config.bOrigin.hostname,
        comparatorCommitment: expected.commitments.comparator,
        targetCommitment: expected.commitments.target,
        cases: SBX057_CASES.map((caseId) => ({ caseId, canary: canaries[caseId] })),
      },
    });
    journal.receiverConfigured = true;
    await persistSbx057Journal(lock, journal);
    const empty = await receiverSnapshot(config, gate, journal.runId);
    if (empty.events.length !== 0 || empty.unexpectedIngressCount !== 0 || empty.unattributedIngressCount !== 0) {
      throw new Error("SBX-057 receiver did not start empty");
    }

    runtime.comparator = await createSandbox({ config, gate, journal, lock, role: "comparator", secret: secrets.comparator });
    await gate.before();
    await runtime.comparator.currentSession().writeFiles([
      { path: REMOTE_GUEST_PATH, content: guestSource, mode: 0o700 },
    ], { signal: signal() });
    const comparatorSessionId = runtime.comparator.currentSession().sessionId;
    policies.comparatorBefore = await captureSbx057PolicyProof({
      stage: "comparator", sandbox: runtime.comparator, sessionId: comparatorSessionId,
      config, gate, secret: secrets.comparator,
    });
    if (policies.comparatorBefore.rawSecretPresentInReadbacks ||
        policies.comparatorBefore.activeSessionId !== comparatorSessionId ||
        policies.comparatorBefore.independentSessionId !== comparatorSessionId) {
      throw new Error("SBX-057 comparator pre-policy proof failed");
    }
    for (const caseId of ["comparator-a", "comparator-b"] as const) {
      const result = await runProbe({
        sandbox: runtime.comparator, gate, guestSource, config, runId: journal.runId,
        caseId, canary: canaries[caseId], forbidden,
      });
      probes[caseId] = result.probe;
      guestInputs.push(result.configuration, ...result.argv);
      guestOutputs.push(result.stdout);
    }
    policies.comparatorAfter = await captureSbx057PolicyProof({
      stage: "comparator", sandbox: runtime.comparator, sessionId: comparatorSessionId,
      config, gate, secret: secrets.comparator,
    });
    ledger = await receiverSnapshot(config, gate, journal.runId);
    receiverSnapshotAt = new Date().toISOString();
    comparatorClassification = classifySbx057Comparator(ledger, probes, expected);
    const comparatorCleanup = await cleanupResource({
      config, gate, journal, lock, role: "comparator", active: runtime.comparator,
    });
    if (comparatorCleanup !== undefined) cleanup.resources.push(comparatorCleanup);
    delete runtime.comparator;
    comparatorCleanupCompletedAt = new Date().toISOString();
    if (comparatorClassification === "invalid") throw new Error("SBX-057 exact-domain comparator was invalid");
    if (comparatorCleanup === undefined || !comparatorCleanup.exactProvenance ||
        !comparatorCleanup.stopAttempted || !comparatorCleanup.stopped ||
        !comparatorCleanup.deleteAttempted || !comparatorCleanup.deleted ||
        comparatorCleanup.absenceChecks < 3 || comparatorCleanup.errors.length !== 0) {
      throw new Error("SBX-057 comparator cleanup was not exact before the target phase");
    }

    if (comparatorClassification === "clean") {
      runtime.target = await createSandbox({ config, gate, journal, lock, role: "target", secret: secrets.target });
      await gate.before();
      await runtime.target.currentSession().writeFiles([
        { path: REMOTE_GUEST_PATH, content: guestSource, mode: 0o700 },
      ], { signal: signal() });
      const targetSessionId = runtime.target.currentSession().sessionId;
      if (targetSessionId === comparatorSessionId) throw new Error("SBX-057 sandbox sessions collided");
      policies.targetBefore = await captureSbx057PolicyProof({
        stage: "target", sandbox: runtime.target, sessionId: targetSessionId,
        config, gate, secret: secrets.target,
      });
      if (policies.targetBefore.rawSecretPresentInReadbacks ||
          policies.targetBefore.activeSessionId !== targetSessionId ||
          policies.targetBefore.independentSessionId !== targetSessionId) {
        throw new Error("SBX-057 target pre-policy proof failed");
      }
      for (const caseId of ["target-a", "target-b"] as const) {
        const result = await runProbe({
          sandbox: runtime.target, gate, guestSource, config, runId: journal.runId,
          caseId, canary: canaries[caseId], forbidden,
        });
        probes[caseId] = result.probe;
        guestInputs.push(result.configuration, ...result.argv);
        guestOutputs.push(result.stdout);
      }
      policies.targetAfter = await captureSbx057PolicyProof({
        stage: "target", sandbox: runtime.target, sessionId: targetSessionId,
        config, gate, secret: secrets.target,
      });
      ledger = await receiverSnapshot(config, gate, journal.runId);
      receiverSnapshotAt = new Date().toISOString();
      const targetCleanup = await cleanupResource({ config, gate, journal, lock, role: "target", active: runtime.target });
      if (targetCleanup !== undefined) cleanup.resources.push(targetCleanup);
      delete runtime.target;
    }
    if (!await publicHealth(config, gate, "A") || !await publicHealth(config, gate, "B")) {
      throw new Error("SBX-057 receiver postflight failed");
    }
  } catch (error) {
    controllerError = safeSbx057Error(error, forbidden);
  } finally {
    for (const role of ["target", "comparator"] as const) {
      const index = role === "comparator" ? 0 : 1;
      if (journal.resources[index].createAttemptedAt !== undefined && !journal.resources[index].deleted) {
        const evidence = await cleanupResource({
          config, gate, journal, lock, role,
          ...(runtime[role] === undefined ? {} : { active: runtime[role] }),
        });
        if (evidence !== undefined && !cleanup.resources.some((entry) => entry.role === role)) {
          if (role === "comparator") cleanup.resources.unshift(evidence);
          else cleanup.resources.push(evidence);
        }
      }
    }
    if (journal.receiverConfigured) {
      try {
        ledger = await receiverSnapshot(config, gate, journal.runId);
        receiverSnapshotAt = new Date().toISOString();
      } catch (error) {
        cleanup.errors.push(safeSbx057Error(error, forbidden));
      }
    }
    const receiver = await cleanupReceiver({ config, gate, journal, lock });
    cleanup.receiverDeleteAttempted = receiver.attempted;
    cleanup.receiverDeleted = receiver.deleted;
    cleanup.receiverAbsenceChecks = receiver.absenceChecks;
    cleanup.errors.push(...receiver.errors);
    cleanup.completedAt = new Date().toISOString();
  }

  const resourceEvidence = journal.resources.map(expectedResource).filter(
    (entry): entry is Sbx057ExpectedResourceIdentity => entry !== undefined,
  );
  const retention: Sbx057RetentionEvidence = {
    guestSourceContainsComparatorSecret: guestSource.includes(secrets.comparator),
    guestSourceContainsTargetSecret: guestSource.includes(secrets.target),
    guestConfigurationContainsComparatorSecret: guestInputs.some((value) => value.includes(secrets.comparator)),
    guestConfigurationContainsTargetSecret: guestInputs.some((value) => value.includes(secrets.target)),
    guestEnvironmentContainsSecrets: false,
    guestArgvContainsSecrets: guestInputs.some((value) => value.includes(secrets.comparator) || value.includes(secrets.target)),
    guestFilesContainSecrets: guestSource.includes(secrets.comparator) || guestSource.includes(secrets.target),
    guestStdoutContainsSecrets: guestOutputs.some((value) => value.includes(secrets.comparator) || value.includes(secrets.target)),
    guestResultContainsSecrets: JSON.stringify(probes).includes(secrets.comparator) || JSON.stringify(probes).includes(secrets.target),
    artifactContainsRawSecrets: false,
    artifactContainsStandaloneSecretDigests: false,
    receiverRetainedRawSecrets: ledger.rawSecretsRetained,
    artifactMode: 0o600,
    lockMode: lock.lockMode,
    journalMode: lock.journalMode,
  };
  const input: Sbx057AssessmentInput = {
    runId: journal.runId,
    identity: { alias: config.alias, teamId: config.teamId, projectId: config.projectId },
    expectedIdentity: { alias: config.alias, teamId: config.teamId, projectId: config.projectId },
    aHostname: config.aOrigin.hostname,
    bHostname: config.bOrigin.hostname,
    comparatorCommitment: expected.commitments.comparator,
    targetCommitment: expected.commitments.target,
    canaries,
    expectedOperationIds: expected.operationIds,
    expectedReceipts: expected.receipts,
    resources: resourceEvidence,
    policies,
    probes,
    ledger,
    cleanup,
    retention,
    ...(comparatorCleanupCompletedAt === undefined ? {} : { comparatorCleanupCompletedAt }),
    receiverSnapshotAt,
    ...(!identityVerified || controllerError !== undefined
      ? { controllerError: controllerError ?? "eligible identity was not verified" }
      : {}),
  };
  const receiverCleanupSafe = cleanup.receiverDeleted && (journal.receiverConfigureAttempted
    ? cleanup.receiverDeleteAttempted && cleanup.receiverAbsenceChecks >= 2
    : !cleanup.receiverDeleteAttempted && cleanup.receiverAbsenceChecks === 0);
  const cleanupComplete = cleanup.resources.every((entry) => entry.deleted && entry.absenceChecks >= 3 &&
    entry.errors.length === 0) && receiverCleanupSafe &&
    cleanup.errors.length === 0 && journal.resources.every((entry) =>
      entry.createAttemptedAt === undefined || entry.deleted);
  const checkpoint = {
    schemaVersion: 1, visibility: "private", testId: SBX057_TEST_ID, mode: "normal",
    runId: journal.runId, finalizationPending: true, sdkAudit, comparatorClassification,
    input, assessment: { outcome: "indeterminate", candidate: false, severity: "unknown",
      controlsPassed: false, wildcardCredentialLeakProven: false,
      summary: "Cleanup/release finalization was not yet durably proven." },
  };
  if (!secretFree(checkpoint, forbidden)) {
    await lock.liveLock.closeRetainingState();
    throw new Error("SBX-057 checkpoint retained forbidden material");
  }
  await writeSbx057Artifact(journal.runId, checkpoint);
  if (!cleanupComplete) {
    await lock.liveLock.closeRetainingState();
    throw new Error("SBX-057 cleanup remained uncertain; lock and journal were retained");
  }
  journal.phase = "completed";
  journal.completed = true;
  await persistSbx057Journal(lock, journal);
  await releaseSbx057LockAndJournal(lock);
  cleanup.journalRemoved = await absent(sbx057JournalPath(journal.runId));
  cleanup.liveLockRemoved = await absent(SBX057_LOCK_PATH);
  cleanup.lockTransactionRemoved = await absent(`${SBX057_LOCK_PATH}.transaction`);
  const assessment = assessSbx057(input);
  const finalArtifact = {
    ...checkpoint,
    finalizationPending: false,
    completedAt: new Date().toISOString(),
    input,
    assessment,
  };
  if (!secretFree(finalArtifact, forbidden)) throw new Error("SBX-057 final artifact retained forbidden material");
  await finalizeSbx057Artifact(journal.runId, finalArtifact);
  if (assessment.candidate) process.exitCode = 10;
  else if (assessment.outcome !== "pass") process.exitCode = 1;
  return assessment;
}

async function runRecovery(config: Sbx057Config): Promise<void> {
  const runId = config.recoveryRunId!;
  const attemptId = randomUUID();
  const dispatch = await dispatchSbx057Recovery(runId);
  if (dispatch !== "continue-journal-recovery") {
    await writeSbx057RecoveryArtifact(runId, attemptId, {
      schemaVersion: 1, visibility: "private", testId: SBX057_TEST_ID, mode: "cleanup-only",
      runId, attemptId, finalizationPending: false, dispatch, cleanupSucceeded: true,
      experimentOutcomeEmitted: false,
    });
    return;
  }
  const lock = await acquireSbx057RecoveryLock(runId);
  const journal = await readSbx057Journal(runId);
  const gate = new RequestGate();
  const cleanup: Sbx057CleanupResource[] = [];
  let receiverDeleted = false;
  try {
    await verifyIdentity(config, gate);
    for (const role of ["target", "comparator"] as const) {
      const result = await cleanupResource({ config, gate, journal, lock, role });
      if (result !== undefined) cleanup.push(result);
    }
    const receiver = await cleanupReceiver({ config, gate, journal, lock });
    receiverDeleted = receiver.deleted && receiver.errors.length === 0;
    const succeeded = cleanup.every((entry) => entry.deleted && entry.absenceChecks >= 3 && entry.errors.length === 0) &&
      receiverDeleted && journal.resources.every((entry) => entry.createAttemptedAt === undefined || entry.deleted);
    const checkpoint = {
      schemaVersion: 1, visibility: "private", testId: SBX057_TEST_ID, mode: "cleanup-only",
      runId, attemptId, finalizationPending: true, cleanupSucceeded: false,
      experimentOutcomeEmitted: false, resources: cleanup, receiverDeleted,
    };
    await writeSbx057RecoveryArtifact(runId, attemptId, checkpoint);
    if (!succeeded) {
      await lock.liveLock.closeRetainingState();
      throw new Error("SBX-057 cleanup-only recovery remained uncertain");
    }
    journal.phase = "completed";
    journal.completed = true;
    await persistSbx057Journal(lock, journal);
    await releaseSbx057LockAndJournal(lock);
    await finalizeSbx057RecoveryArtifact(runId, attemptId, {
      ...checkpoint, finalizationPending: false, cleanupSucceeded: true,
      completedAt: new Date().toISOString(),
      journalRemoved: await absent(sbx057JournalPath(runId)),
      liveLockRemoved: await absent(SBX057_LOCK_PATH),
      lockTransactionRemoved: await absent(`${SBX057_LOCK_PATH}.transaction`),
    });
  } catch (error) {
    if (!lock.liveLock.isReleased()) await lock.liveLock.closeRetainingState().catch(() => undefined);
    throw error;
  }
}

async function main(): Promise<void> {
  const config = loadSbx057Config();
  if (config.recoveryRunId !== undefined) {
    await runRecovery(config);
    process.stdout.write(`${JSON.stringify({ testId: SBX057_TEST_ID, mode: "cleanup-only", completed: true })}\n`);
    return;
  }
  const assessment = await runSbx057(config);
  process.stdout.write(`${JSON.stringify({ testId: SBX057_TEST_ID, assessment })}\n`);
}

const invoked = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : "";
if (import.meta.url === invoked) {
  main().catch(() => {
    process.stderr.write("SBX-057 controller failed; secrets and raw errors were suppressed\n");
    process.exitCode = 1;
  });
}
