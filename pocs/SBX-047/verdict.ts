import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export const SBX047_TEST_ID = "SBX-047" as const;
export const SBX047_TRANSFORM_HEADER = "x-sbx047-brokered-credential" as const;

const SHA256 = /^[a-f0-9]{64}$/u;
const TOKEN = /^[A-Za-z0-9._:-]{1,160}$/u;
const MAX_GUEST_STDOUT_BYTES = 2_048;

export type Sbx047RequestKind = "public" | "action";

export interface Sbx047GuestError {
  name: string;
  code: string | null;
  syscall: string | null;
  errno: number | null;
}

export interface Sbx047GuestResult {
  schemaVersion: 1;
  testId: typeof SBX047_TEST_ID;
  kind: Sbx047RequestKind;
  caseId: string;
  receivedResponse: boolean;
  statusCode: number | null;
  durationMs: number;
  receipt: string | null;
  operationId: string | null;
  secretProof: string | null;
  error: Sbx047GuestError | null;
}

export interface Sbx047ObserverEvent {
  sequence: number;
  observedAt: string;
  kind: Sbx047RequestKind;
  caseId: string;
  method: string;
  requestTarget: string;
  hostHeaderLines: number;
  hostHeaderValues: number;
  hostMatched: boolean;
  canaryMatched: boolean;
  transformHeaderLines: number;
  transformHeaderValues: number;
  transformHeaderSha256?: string;
  transformCommitmentMatched: boolean;
  responseStatus: number;
  receipt?: string;
  operationId?: string;
  secretProof?: string;
}

export interface Sbx047ObserverSnapshot {
  configured: true;
  actionStaged: boolean;
  events: Sbx047ObserverEvent[];
}

export interface Sbx047AssessmentInput {
  controls: {
    exactEligibleAlias: boolean;
    sdk300ForkOverrideSerialized: boolean;
    sourcePolicyReadbacksExact: boolean;
    sourcePublicControlPassed: boolean;
    sourceNonreflectingActionPassed: boolean;
    inheritancePolicyReadbacksExact: boolean;
    inheritancePublicControlPassed: boolean;
    targetForkResponseDenyAll: boolean;
    targetActiveDenyAll: boolean;
    targetIndependentDenyAll: boolean;
    targetCurrentSessionDenyAll: boolean;
    targetIndependentCurrentSessionDenyAll: boolean;
    exactDistinctNamesAndSessions: boolean;
    fixedGuestProgram: boolean;
    guestSessionAttributionPassed: boolean;
    observerPreflightPassed: boolean;
    observerPostflightPassed: boolean;
    sequentialNoRetrySchedule: boolean;
  };
  expected: {
    runId: string;
    sourcePublicCaseId: string;
    sourceActionCaseId: string;
    inheritancePublicCaseId: string;
    publicCaseId: string;
    actionCaseId: string;
    canary: string;
    publicReceipt: string;
    actionReceipt?: string;
    operationId?: string;
    secretProof?: string;
    transformHeaderSha256: string;
  };
  targetPublic: Sbx047GuestResult;
  targetAction?: Sbx047GuestResult;
  observerEvents: Sbx047ObserverEvent[];
  actionStagedAfterPublicSignal: boolean;
}

export interface Sbx047Assessment {
  verdict: "candidate" | "pass" | "indeterminate";
  candidate: boolean;
  severity: "high" | "medium" | "none" | "unknown";
  publicBoundaryReached: boolean;
  protectedActionExecuted: boolean;
  summary: string;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function hmac(key: string, fields: readonly string[]): string {
  const value = fields.map((field) => `${Buffer.byteLength(field, "utf8")}:${field}`).join("|");
  return createHmac("sha256", key).update(value, "utf8").digest("hex");
}

export function deriveSbx047Receipt(
  adminKey: string,
  runId: string,
  kind: Sbx047RequestKind,
  caseId: string,
  canary: string,
  transformHeaderSha256: string | undefined,
): string {
  return hmac(adminKey, [SBX047_TEST_ID, "receipt", runId, kind, caseId, canary,
    transformHeaderSha256 ?? "absent"]);
}

export function deriveSbx047SecretProof(
  stagedSecret: string,
  runId: string,
  caseId: string,
  canary: string,
): string {
  return hmac(stagedSecret, [SBX047_TEST_ID, "protected-file", runId, caseId, canary]);
}

export function deriveSbx047OperationId(
  adminKey: string,
  runId: string,
  caseId: string,
  secretProof: string,
): string {
  return hmac(adminKey, [SBX047_TEST_ID, "operation", runId, caseId, secretProof]);
}

function exactKeys(value: object, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function validNullableDigest(value: unknown): value is string | null {
  return value === null || (typeof value === "string" && SHA256.test(value));
}

export function parseSbx047GuestResult(
  stdout: string,
  stderr: string,
  exitCode: number,
  expectedKind: Sbx047RequestKind,
  expectedCaseId: string,
): Sbx047GuestResult {
  if (exitCode !== 0) throw new Error("SBX-047 guest command exited nonzero");
  if (stderr !== "") throw new Error("SBX-047 guest command emitted stderr");
  if (Buffer.byteLength(stdout, "utf8") > MAX_GUEST_STDOUT_BYTES || !stdout.endsWith("\n") ||
      stdout.indexOf("\n") !== stdout.length - 1) {
    throw new Error("SBX-047 guest output must be one bounded JSON line");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout.slice(0, -1));
  } catch {
    throw new Error("SBX-047 guest output was not valid JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed) ||
      !exactKeys(parsed, ["schemaVersion", "testId", "kind", "caseId", "receivedResponse",
        "statusCode", "durationMs", "receipt", "operationId", "secretProof", "error"])) {
    throw new Error("SBX-047 guest output fields were not exact");
  }
  const value = parsed as Record<string, unknown>;
  if (value.schemaVersion !== 1 || value.testId !== SBX047_TEST_ID ||
      value.kind !== expectedKind || value.caseId !== expectedCaseId ||
      !TOKEN.test(expectedCaseId) || typeof value.receivedResponse !== "boolean" ||
      typeof value.durationMs !== "number" || !Number.isSafeInteger(value.durationMs) ||
      value.durationMs < 0 || value.durationMs > 20_000 ||
      !validNullableDigest(value.receipt) || !validNullableDigest(value.operationId) ||
      !validNullableDigest(value.secretProof)) {
    throw new Error("SBX-047 guest output was invalid");
  }
  if (value.receivedResponse) {
    if (typeof value.statusCode !== "number" || !Number.isSafeInteger(value.statusCode) ||
        value.statusCode < 100 || value.statusCode > 599 || value.error !== null) {
      throw new Error("SBX-047 response result was internally inconsistent");
    }
  } else {
    if (value.statusCode !== null || value.receipt !== null || value.operationId !== null ||
        value.secretProof !== null || value.error === null || typeof value.error !== "object" ||
        Array.isArray(value.error) || !exactKeys(value.error,
          ["name", "code", "syscall", "errno"])) {
      throw new Error("SBX-047 blocked result was internally inconsistent");
    }
    const error = value.error as Record<string, unknown>;
    if (typeof error.name !== "string" || error.name.length < 1 || error.name.length > 80 ||
        !(error.code === null || (typeof error.code === "string" && error.code.length <= 80)) ||
        !(error.syscall === null || (typeof error.syscall === "string" && error.syscall.length <= 80)) ||
        !(error.errno === null || (typeof error.errno === "number" && Number.isSafeInteger(error.errno)))) {
      throw new Error("SBX-047 guest error metadata was invalid");
    }
  }
  return value as unknown as Sbx047GuestResult;
}

function canonicalTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || value.length !== 24) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function nonnegativeInteger(value: unknown, maximum = 1_000_000): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

function parseObserverEvent(value: unknown): Sbx047ObserverEvent {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("SBX-047 observer event was not an object");
  }
  const event = value as Record<string, unknown>;
  const required = ["sequence", "observedAt", "kind", "caseId", "method", "requestTarget",
    "hostHeaderLines", "hostHeaderValues", "hostMatched", "canaryMatched",
    "transformHeaderLines", "transformHeaderValues", "transformCommitmentMatched",
    "responseStatus"];
  const optional = ["transformHeaderSha256", "receipt", "operationId", "secretProof"];
  const actual = Object.keys(event);
  if (!required.every((key) => Object.prototype.hasOwnProperty.call(event, key)) ||
      actual.some((key) => !required.includes(key) && !optional.includes(key)) ||
      actual.length !== required.length + optional.filter((key) =>
        Object.prototype.hasOwnProperty.call(event, key)).length) {
    throw new Error("SBX-047 observer event fields were not exact");
  }
  if (!nonnegativeInteger(event.sequence) || event.sequence < 1 ||
      !canonicalTimestamp(event.observedAt) ||
      (event.kind !== "public" && event.kind !== "action") ||
      typeof event.caseId !== "string" || !TOKEN.test(event.caseId) ||
      typeof event.method !== "string" || event.method.length > 16 ||
      typeof event.requestTarget !== "string" || event.requestTarget.length > 1_024 ||
      !nonnegativeInteger(event.hostHeaderLines, 16) ||
      !nonnegativeInteger(event.hostHeaderValues, 16) ||
      typeof event.hostMatched !== "boolean" || typeof event.canaryMatched !== "boolean" ||
      !nonnegativeInteger(event.transformHeaderLines, 16) ||
      !nonnegativeInteger(event.transformHeaderValues, 16) ||
      typeof event.transformCommitmentMatched !== "boolean" ||
      !nonnegativeInteger(event.responseStatus, 599) || event.responseStatus < 100 ||
      !(event.transformHeaderSha256 === undefined ||
        (typeof event.transformHeaderSha256 === "string" && SHA256.test(event.transformHeaderSha256))) ||
      !(event.receipt === undefined || (typeof event.receipt === "string" && SHA256.test(event.receipt))) ||
      !(event.operationId === undefined ||
        (typeof event.operationId === "string" && SHA256.test(event.operationId))) ||
      !(event.secretProof === undefined ||
        (typeof event.secretProof === "string" && SHA256.test(event.secretProof)))) {
    throw new Error("SBX-047 observer event was invalid");
  }
  return event as unknown as Sbx047ObserverEvent;
}

export function parseSbx047ObserverSnapshot(value: unknown): Sbx047ObserverSnapshot {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      !exactKeys(value, ["configured", "actionStaged", "events"])) {
    throw new Error("SBX-047 observer snapshot fields were not exact");
  }
  const snapshot = value as Record<string, unknown>;
  if (snapshot.configured !== true || typeof snapshot.actionStaged !== "boolean" ||
      !Array.isArray(snapshot.events) || snapshot.events.length > 16) {
    throw new Error("SBX-047 observer snapshot was invalid");
  }
  const events = snapshot.events.map(parseObserverEvent);
  if (events.some((event, index) => event.sequence !== index + 1)) {
    throw new Error("SBX-047 observer event sequence was not contiguous");
  }
  return { configured: true, actionStaged: snapshot.actionStaged, events };
}

function equalDigest(left: string | null | undefined, right: string | undefined): boolean {
  if (left === null || left === undefined || right === undefined ||
      left.length !== right.length || !SHA256.test(left) || !SHA256.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "ascii"), Buffer.from(right, "ascii"));
}

function exactTargetEvent(
  event: Sbx047ObserverEvent,
  kind: Sbx047RequestKind,
  caseId: string,
  expected: Sbx047AssessmentInput["expected"],
): boolean {
  const receipt = kind === "public" ? expected.publicReceipt : expected.actionReceipt;
  return event.kind === kind && event.caseId === caseId && event.method === "GET" &&
    event.hostHeaderLines === 1 && event.hostHeaderValues === 1 && event.hostMatched &&
    event.canaryMatched && event.responseStatus === 200 && equalDigest(event.receipt, receipt);
}

function exactPublicGuest(
  result: Sbx047GuestResult,
  expected: Sbx047AssessmentInput["expected"],
): boolean {
  return result.kind === "public" && result.caseId === expected.publicCaseId &&
    result.receivedResponse && result.statusCode === 200 &&
    equalDigest(result.receipt, expected.publicReceipt) && result.operationId === null &&
    result.secretProof === null;
}

function exactActionGuest(
  result: Sbx047GuestResult | undefined,
  expected: Sbx047AssessmentInput["expected"],
): boolean {
  return result !== undefined && result.kind === "action" && result.caseId === expected.actionCaseId &&
    result.receivedResponse && result.statusCode === 200 &&
    equalDigest(result.receipt, expected.actionReceipt) &&
    equalDigest(result.operationId, expected.operationId) &&
    equalDigest(result.secretProof, expected.secretProof);
}

function exactAttributablePreconnectBlock(result: Sbx047GuestResult): boolean {
  if (result.receivedResponse || result.error === null || result.durationMs > 5_000) return false;
  const { code, syscall, errno } = result.error;
  return (code === "EAI_AGAIN" && syscall === "getaddrinfo" && errno === -3001) ||
    (code === "ENETUNREACH" && syscall === "connect" && (errno === -101 || errno === 101)) ||
    (code === "EHOSTUNREACH" && syscall === "connect" && (errno === -113 || errno === 113));
}

function controlsPassed(input: Sbx047AssessmentInput): boolean {
  return Object.values(input.controls).every((value) => value === true) &&
    TOKEN.test(input.expected.runId) && TOKEN.test(input.expected.sourcePublicCaseId) &&
    TOKEN.test(input.expected.sourceActionCaseId) &&
    TOKEN.test(input.expected.inheritancePublicCaseId) &&
    TOKEN.test(input.expected.publicCaseId) && TOKEN.test(input.expected.actionCaseId) &&
    TOKEN.test(input.expected.canary) &&
    SHA256.test(input.expected.publicReceipt) && SHA256.test(input.expected.transformHeaderSha256);
}

function exactControlEventShape(
  event: Sbx047ObserverEvent | undefined,
  sequence: number,
  kind: Sbx047RequestKind,
  caseId: string,
  transformSha256: string,
): boolean {
  return event !== undefined && event.sequence === sequence && event.kind === kind &&
    event.caseId === caseId && event.method === "GET" && event.hostHeaderLines === 1 &&
    event.hostHeaderValues === 1 && event.hostMatched && event.canaryMatched &&
    event.transformHeaderLines === 1 && event.transformHeaderValues === 1 &&
    event.transformHeaderSha256 === transformSha256 && event.transformCommitmentMatched &&
    event.responseStatus === 200 && typeof event.receipt === "string" && SHA256.test(event.receipt) &&
    (kind === "public"
      ? event.operationId === undefined && event.secretProof === undefined
      : typeof event.operationId === "string" && SHA256.test(event.operationId) &&
        typeof event.secretProof === "string" && SHA256.test(event.secretProof));
}

export function assessSbx047(input: Sbx047AssessmentInput): Sbx047Assessment {
  if (!controlsPassed(input)) {
    return {
      verdict: "indeterminate",
      candidate: false,
      severity: "unknown",
      publicBoundaryReached: false,
      protectedActionExecuted: false,
      summary: "A required identity, SDK, lifecycle, policy, observer, or source/inheritance control failed.",
    };
  }

  const baseControlsExact = exactControlEventShape(
    input.observerEvents[0], 1, "public", input.expected.sourcePublicCaseId,
    input.expected.transformHeaderSha256,
  ) && exactControlEventShape(
    input.observerEvents[1], 2, "action", input.expected.sourceActionCaseId,
    input.expected.transformHeaderSha256,
  ) && exactControlEventShape(
    input.observerEvents[2], 3, "public", input.expected.inheritancePublicCaseId,
    input.expected.transformHeaderSha256,
  );
  const allowedCases = new Set([
    input.expected.sourcePublicCaseId,
    input.expected.sourceActionCaseId,
    input.expected.inheritancePublicCaseId,
    input.expected.publicCaseId,
    input.expected.actionCaseId,
  ]);
  const eventAccountingValid = baseControlsExact && input.observerEvents.every((event, index) =>
    event.sequence === index + 1 && allowedCases.has(event.caseId));
  if (!eventAccountingValid) {
    return {
      verdict: "indeterminate",
      candidate: false,
      severity: "unknown",
      publicBoundaryReached: false,
      protectedActionExecuted: false,
      summary: "Observer accounting contained a missing, duplicated, reordered, or unexpected control/case event.",
    };
  }

  const publicEvents = input.observerEvents.filter((event) =>
    event.kind === "public" && event.caseId === input.expected.publicCaseId);
  const actionEvents = input.observerEvents.filter((event) =>
    event.kind === "action" && event.caseId === input.expected.actionCaseId);
  const publicReached = publicEvents.length === 1 &&
    exactTargetEvent(publicEvents[0]!, "public", input.expected.publicCaseId, input.expected) &&
    exactPublicGuest(input.targetPublic, input.expected);

  if (!publicReached) {
    const noTargetEvents = input.observerEvents.length === 3 && publicEvents.length === 0 &&
      actionEvents.length === 0;
    if (noTargetEvents && !input.actionStagedAfterPublicSignal && input.targetAction === undefined &&
        exactAttributablePreconnectBlock(input.targetPublic)) {
      return {
        verdict: "pass",
        candidate: false,
        severity: "none",
        publicBoundaryReached: false,
        protectedActionExecuted: false,
        summary: "The exact deny-all target was blocked before connect and produced no attributable observer event.",
      };
    }
    return {
      verdict: "indeterminate",
      candidate: false,
      severity: "unknown",
      publicBoundaryReached: false,
      protectedActionExecuted: false,
      summary: "The target produced neither an exact attributable public signal nor a clean pre-connect block.",
    };
  }

  if (input.observerEvents[3] !== publicEvents[0] || publicEvents[0]!.sequence !== 4) {
    return {
      verdict: "indeterminate",
      candidate: false,
      severity: "unknown",
      publicBoundaryReached: true,
      protectedActionExecuted: false,
      summary: "The target public signal was not the single next attributable observer event.",
    };
  }

  const actionExpectedFieldsPresent = input.expected.actionReceipt !== undefined &&
    input.expected.operationId !== undefined && input.expected.secretProof !== undefined;
  const actionExecuted = input.actionStagedAfterPublicSignal && actionExpectedFieldsPresent &&
    input.observerEvents.length === 5 && actionEvents.length === 1 &&
    input.observerEvents[4] === actionEvents[0] && actionEvents[0]!.sequence === 5 &&
    exactTargetEvent(actionEvents[0]!, "action", input.expected.actionCaseId, input.expected) &&
    actionEvents[0]!.transformHeaderLines === 1 && actionEvents[0]!.transformHeaderValues === 1 &&
    actionEvents[0]!.transformHeaderSha256 === input.expected.transformHeaderSha256 &&
    actionEvents[0]!.transformCommitmentMatched &&
    equalDigest(actionEvents[0]!.operationId, input.expected.operationId) &&
    equalDigest(actionEvents[0]!.secretProof, input.expected.secretProof) &&
    exactActionGuest(input.targetAction, input.expected);

  if (actionExecuted) {
    return {
      verdict: "candidate",
      candidate: true,
      severity: "high",
      publicBoundaryReached: true,
      protectedActionExecuted: true,
      summary: "The exact deny-all fork reached the owned origin and used the stale source-only transform credential to execute a freshly staged protected action.",
    };
  }
  if (input.actionStagedAfterPublicSignal || input.targetAction !== undefined ||
      actionEvents.length !== 0 || input.observerEvents.length !== 4) {
    return {
      verdict: "indeterminate",
      candidate: false,
      severity: "unknown",
      publicBoundaryReached: true,
      protectedActionExecuted: false,
      summary: "The public bypass was exact, but protected-action staging, response, or event accounting was inconsistent.",
    };
  }
  return {
    verdict: "candidate",
    candidate: true,
    severity: "medium",
    publicBoundaryReached: true,
    protectedActionExecuted: false,
    summary: "The exact deny-all fork reached the owned public observer; no independently verified protected action is claimed.",
  };
}

export function sha256Sbx047(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

export function assertSbx047EvidenceHasNoRawSecrets(
  evidence: unknown,
  forbidden: readonly string[],
): void {
  const serialized = JSON.stringify(evidence);
  for (const secret of forbidden) {
    if (secret.length > 0 && serialized.includes(secret)) {
      throw new Error("SBX-047 evidence contained raw controller-only material");
    }
  }
}
