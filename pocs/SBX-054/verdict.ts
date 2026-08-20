import { createHmac, timingSafeEqual } from "node:crypto";

export const SBX054_TEST_ID = "SBX-054" as const;
export const SBX054_RUNTIME = "node24" as const;
export const SBX054_CASES = [
  "v3-deny-comparator",
  "v2-runtime-deny-target",
  "v3-deny-comparator-post",
  "v2-runtime-secret",
] as const;

export const SBX054_INHERITED_PLATFORM_TRUST_ENVIRONMENT_NAMES = [
  "NODE_EXTRA_CA_CERTS",
  "NODE_USE_SYSTEM_CA",
  "SSL_CERT_FILE",
] as const;

export type Sbx054CaseId = (typeof SBX054_CASES)[number];
export type Sbx054RequestKind = "public" | "secret";

export const SBX054_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
export const SBX054_CANARY = /^c54_[A-Za-z0-9_-]{43}$/u;
export const SBX054_DIGEST = /^[0-9a-f]{64}$/u;

export interface Sbx054ErrorTuple {
  name: string;
  code: string | null;
  syscall: string | null;
  errno: number | null;
}

export interface Sbx054GuestResult {
  schemaVersion: 1;
  testId: typeof SBX054_TEST_ID;
  kind: Sbx054RequestKind;
  caseId: Sbx054CaseId;
  requestAttempts: 1;
  connectionAttempts: 1;
  redirectsFollowed: 0;
  rejectUnauthorized: true;
  controllerConfigurableCustomTrustAccepted: false;
  inheritedPlatformTrustEnvironmentNames: string[];
  nodeOptionsPresent: false;
  tlsAuthorized: boolean;
  receivedResponse: boolean;
  statusCode: number | null;
  durationMs: number;
  receipt: string | null;
  secretProof: string | null;
  operationId: string | null;
  secretFileMode: number | null;
  secretFileDeleted: boolean | null;
  error: Sbx054ErrorTuple | null;
}

export interface Sbx054ObserverEvent {
  sequence: number;
  observedAt: string;
  kind: Sbx054RequestKind;
  caseId: Sbx054CaseId;
  method: string;
  hostHeaderLines: number;
  hostHeaderValues: number;
  hostMatched: boolean;
  pathMatched: boolean;
  canaryCommitment: string;
  bodyLength: number;
  secretMatched: boolean;
  responseStatus: number;
  receipt?: string;
  secretProof?: string;
  operationId?: string;
}

export interface Sbx054ObserverSnapshot {
  configured: boolean;
  configuredAt: string;
  events: Sbx054ObserverEvent[];
  secretStaged: boolean;
  secretCleared: boolean;
  unexpectedRequests: number;
  rawCanaryRetained: false;
  rawSecretRetained: false;
  rawBodyRetained: false;
  secretDigestRetained: false;
  receiverRuntimeTrustExact: true;
  receiverTrustEnvironmentNames: string[];
  receiverNodeOptionsPresent: false;
  receiverTlsVerificationDisabled: false;
}

export interface Sbx054Controls {
  exactEligibleIdentity: boolean;
  sdkVersionPinned: boolean;
  sdkRouteBranchExact: boolean;
  sameDenyAllWirePolicy: boolean;
  comparatorCreatedOnV3: boolean;
  targetCreatedOnV2: boolean;
  exactDistinctNamesAndSessions: boolean;
  comparatorPreReadbackExact: boolean;
  comparatorPostReadbackExact: boolean;
  comparatorPostTargetPreReadbackExact: boolean;
  comparatorFinalReadbackExact: boolean;
  targetPreReadbackExact: boolean;
  targetPostPublicReadbackExact: boolean;
  targetFinalReadbackExact: boolean;
  fixedGuestDigestMatched: boolean;
  receiverPreflightPassed: boolean;
  receiverPostflightPassed: boolean;
  emptyLedgerBeforeRequests: boolean;
  postComparatorCompletedBeforeImpact: boolean;
  sequentialNoRetrySchedule: boolean;
  cleanupSucceeded: boolean;
}

export interface Sbx054ExpectedProofs {
  runId: string;
  comparatorCanaryCommitment: string;
  targetCanaryCommitment: string;
  postComparatorCanaryCommitment: string;
  secretCanaryCommitment: string;
  targetPublicReceipt: string;
  targetSecretReceipt?: string;
  targetSecretProof?: string;
  targetOperationId?: string;
}

export interface Sbx054AssessmentInput {
  controls: Sbx054Controls;
  expected: Sbx054ExpectedProofs;
  comparator: Sbx054GuestResult;
  postComparator: Sbx054GuestResult;
  targetPublic: Sbx054GuestResult;
  targetSecret?: Sbx054GuestResult;
  observer: Sbx054ObserverSnapshot;
  impactAttempted: boolean;
  secretGeneratedAfterPublicSignal: boolean;
  secretFileWrittenAfterPublicSignal: boolean;
  secretFileRequestedMode?: number;
}

export interface Sbx054Assessment {
  verdict: "pass" | "candidate-medium" | "candidate-high" | "indeterminate";
  candidate: boolean;
  severity: "none" | "medium" | "high" | "unknown";
  v2PublicBoundaryReached: boolean;
  fileBackedSecretExfiltrated: boolean;
  summary: string;
}

const GUEST_KEYS = [
  "schemaVersion", "testId", "kind", "caseId", "requestAttempts", "connectionAttempts",
  "redirectsFollowed", "rejectUnauthorized", "controllerConfigurableCustomTrustAccepted",
  "inheritedPlatformTrustEnvironmentNames",
  "nodeOptionsPresent", "tlsAuthorized", "receivedResponse", "statusCode", "durationMs",
  "receipt", "secretProof", "operationId", "secretFileMode", "secretFileDeleted", "error",
] as const;
const ERROR_KEYS = ["name", "code", "syscall", "errno"] as const;

function exactKeys(value: object, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function isTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || value.length !== 24) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function isCase(value: unknown): value is Sbx054CaseId {
  return typeof value === "string" && (SBX054_CASES as readonly string[]).includes(value);
}

function nullableDigest(value: unknown): value is string | null {
  return value === null || (typeof value === "string" && SBX054_DIGEST.test(value));
}

function exactInheritedPlatformTrustEnvironmentNames(value: unknown): value is string[] {
  const allowed = new Set<string>(SBX054_INHERITED_PLATFORM_TRUST_ENVIRONMENT_NAMES);
  if (!Array.isArray(value) || value.length > allowed.size ||
      !value.every((name): name is string => typeof name === "string" && allowed.has(name))) return false;
  const sorted = [...value].sort();
  return new Set(value).size === value.length && value.every((name, index) => name === sorted[index]);
}

export function sbx054DigestEqual(left: string | null | undefined, right: string | undefined): boolean {
  if (left === null || left === undefined || right === undefined ||
      !SBX054_DIGEST.test(left) || !SBX054_DIGEST.test(right) || left.length !== right.length) {
    return false;
  }
  return timingSafeEqual(Buffer.from(left, "ascii"), Buffer.from(right, "ascii"));
}

function operationMessage(
  kind: Sbx054RequestKind,
  runId: string,
  caseId: Sbx054CaseId,
  canaryCommitment: string,
  suffix: string,
): string {
  return ["v1", SBX054_TEST_ID, kind, runId, caseId, canaryCommitment, suffix].join("\n");
}

function checkedKey(key: string | Buffer): string | Buffer {
  if (Buffer.byteLength(key) < 32 || Buffer.byteLength(key) > 512) {
    throw new Error("SBX-054 HMAC key length was invalid");
  }
  return key;
}

export function deriveSbx054CanaryCommitment(
  actionKey: string | Buffer,
  runId: string,
  caseId: Sbx054CaseId,
  canary: string,
): string {
  if (!SBX054_UUID.test(runId) || !isCase(caseId) || !SBX054_CANARY.test(canary)) {
    throw new Error("SBX-054 canary material was invalid");
  }
  return createHmac("sha256", checkedKey(actionKey))
    .update(operationMessage("public", runId, caseId, "canary", canary), "utf8")
    .digest("hex");
}

export function deriveSbx054Receipt(
  actionKey: string | Buffer,
  kind: Sbx054RequestKind,
  runId: string,
  caseId: Sbx054CaseId,
  canaryCommitment: string,
  secretMatched: boolean,
): string {
  if (!SBX054_UUID.test(runId) || !isCase(caseId) || !SBX054_DIGEST.test(canaryCommitment)) {
    throw new Error("SBX-054 receipt material was invalid");
  }
  return createHmac("sha256", checkedKey(actionKey))
    .update(operationMessage(
      kind,
      runId,
      caseId,
      canaryCommitment,
      secretMatched ? "exact-secret" : "public-canary",
    ), "utf8")
    .digest("hex");
}

export function deriveSbx054SecretProof(
  secret: Buffer,
  runId: string,
  caseId: Sbx054CaseId,
  canaryCommitment: string,
): string {
  if (secret.byteLength < 32 || secret.byteLength > 256 || !SBX054_UUID.test(runId) ||
      !isCase(caseId) || !SBX054_DIGEST.test(canaryCommitment)) {
    throw new Error("SBX-054 secret proof material was invalid");
  }
  return createHmac("sha256", secret)
    .update(operationMessage("secret", runId, caseId, canaryCommitment, "file-backed"), "utf8")
    .digest("hex");
}

export function deriveSbx054OperationId(
  actionKey: string | Buffer,
  runId: string,
  caseId: Sbx054CaseId,
  secretProof: string,
): string {
  if (!SBX054_UUID.test(runId) || !isCase(caseId) || !SBX054_DIGEST.test(secretProof)) {
    throw new Error("SBX-054 operation material was invalid");
  }
  return createHmac("sha256", checkedKey(actionKey))
    .update(operationMessage("secret", runId, caseId, secretProof, "accepted-once"), "utf8")
    .digest("hex");
}

function parseError(value: unknown): Sbx054ErrorTuple | null {
  if (value === null) return null;
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      !exactKeys(value, ERROR_KEYS)) throw new Error("SBX-054 guest error fields were not exact");
  const error = value as Record<string, unknown>;
  if (typeof error.name !== "string" || error.name.length < 1 || error.name.length > 80 ||
      !(error.code === null || (typeof error.code === "string" && error.code.length <= 80)) ||
      !(error.syscall === null || (typeof error.syscall === "string" && error.syscall.length <= 80)) ||
      !(error.errno === null || (typeof error.errno === "number" && Number.isSafeInteger(error.errno)))) {
    throw new Error("SBX-054 guest error tuple was invalid");
  }
  return error as unknown as Sbx054ErrorTuple;
}

export function parseSbx054Guest(stdout: string, stderr: string, exitCode: number): Sbx054GuestResult {
  if (exitCode !== 0 || stderr !== "" || Buffer.byteLength(stdout, "utf8") > 8_192 ||
      !stdout.endsWith("\n") || stdout.indexOf("\n") !== stdout.length - 1) {
    throw new Error("SBX-054 guest output was not one bounded successful JSON line");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout.slice(0, -1));
  } catch {
    throw new Error("SBX-054 guest output was not JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed) ||
      !exactKeys(parsed, GUEST_KEYS)) throw new Error("SBX-054 guest fields were not exact");
  const value = parsed as Record<string, unknown>;
  const kind = value.kind;
  const caseId = value.caseId;
  if (value.schemaVersion !== 1 || value.testId !== SBX054_TEST_ID ||
      (kind !== "public" && kind !== "secret") || !isCase(caseId) ||
      value.requestAttempts !== 1 || value.connectionAttempts !== 1 ||
      value.redirectsFollowed !== 0 || value.rejectUnauthorized !== true ||
      value.controllerConfigurableCustomTrustAccepted !== false ||
      !exactInheritedPlatformTrustEnvironmentNames(value.inheritedPlatformTrustEnvironmentNames) ||
      value.nodeOptionsPresent !== false ||
      typeof value.tlsAuthorized !== "boolean" || typeof value.receivedResponse !== "boolean" ||
      !(value.statusCode === null || (typeof value.statusCode === "number" &&
        Number.isSafeInteger(value.statusCode) && value.statusCode >= 100 && value.statusCode <= 599)) ||
      typeof value.durationMs !== "number" || !Number.isSafeInteger(value.durationMs) ||
      value.durationMs < 0 || value.durationMs > 6_000 || !nullableDigest(value.receipt) ||
      !nullableDigest(value.secretProof) || !nullableDigest(value.operationId) ||
      !(value.secretFileMode === null || value.secretFileMode === 0o600) ||
      !(value.secretFileDeleted === null || typeof value.secretFileDeleted === "boolean")) {
    throw new Error("SBX-054 guest result was invalid");
  }
  const error = parseError(value.error);
  const publicShape = kind === "public" && value.secretFileMode === null &&
    value.secretFileDeleted === null && value.secretProof === null && value.operationId === null;
  const secretShape = kind === "secret" && value.secretFileMode === 0o600 &&
    value.secretFileDeleted === true;
  const responseShape = value.receivedResponse
    ? value.statusCode !== null && error === null
    : value.statusCode === null && value.receipt === null && value.secretProof === null &&
      value.operationId === null && value.tlsAuthorized === false && error !== null;
  if ((!publicShape && !secretShape) || !responseShape ||
      (value.receipt !== null && value.statusCode !== 200) ||
      ((value.secretProof !== null || value.operationId !== null) && kind !== "secret")) {
    throw new Error("SBX-054 guest result relationships were invalid");
  }
  return { ...value, error } as unknown as Sbx054GuestResult;
}

export function isSbx054PreconnectBlock(result: Sbx054GuestResult): boolean {
  if (result.receivedResponse || result.error === null || result.durationMs > 5_000) return false;
  const { code, syscall, errno } = result.error;
  return (code === "EAI_AGAIN" && syscall === "getaddrinfo" && errno === -3001) ||
    (code === "ENETUNREACH" && syscall === "connect" && (errno === -101 || errno === 101)) ||
    (code === "EHOSTUNREACH" && syscall === "connect" && (errno === -113 || errno === 113));
}

export function isSbx054ExactEnotfoundDnsDenial(result: Sbx054GuestResult): boolean {
  return result.kind === "public" && result.requestAttempts === 1 && result.connectionAttempts === 1 &&
    result.redirectsFollowed === 0 && result.rejectUnauthorized === true &&
    result.controllerConfigurableCustomTrustAccepted === false && result.nodeOptionsPresent === false &&
    result.tlsAuthorized === false && !result.receivedResponse && result.statusCode === null &&
    result.receipt === null && result.secretProof === null && result.operationId === null &&
    result.secretFileMode === null && result.secretFileDeleted === null && result.error !== null &&
    result.durationMs <= 5_000 &&
    result.error.code === "ENOTFOUND" && result.error.syscall === "getaddrinfo" &&
    result.error.errno === -3008;
}

export function sameSbx054BlockTuple(left: Sbx054GuestResult, right: Sbx054GuestResult): boolean {
  return left.error !== null && right.error !== null && left.error.code === right.error.code &&
    left.error.syscall === right.error.syscall && left.error.errno === right.error.errno;
}

function runtimeSpecificDnsDenialPair(
  comparator: Sbx054GuestResult,
  target: Sbx054GuestResult,
): boolean {
  return comparator.error?.code === "EAI_AGAIN" && comparator.error.syscall === "getaddrinfo" &&
    comparator.error.errno === -3001 && isSbx054ExactEnotfoundDnsDenial(target);
}

function compatibleNoncandidateDenial(
  comparator: Sbx054GuestResult,
  target: Sbx054GuestResult,
): boolean {
  return (isSbx054PreconnectBlock(target) && sameSbx054BlockTuple(comparator, target)) ||
    runtimeSpecificDnsDenialPair(comparator, target);
}

function allControls(input: Sbx054AssessmentInput): boolean {
  return Object.values(input.controls).every((value) => value === true) &&
    SBX054_UUID.test(input.expected.runId) &&
    SBX054_DIGEST.test(input.expected.comparatorCanaryCommitment) &&
    SBX054_DIGEST.test(input.expected.targetCanaryCommitment) &&
    SBX054_DIGEST.test(input.expected.postComparatorCanaryCommitment) &&
    SBX054_DIGEST.test(input.expected.secretCanaryCommitment) &&
    SBX054_DIGEST.test(input.expected.targetPublicReceipt) &&
    input.observer.configured && isTimestamp(input.observer.configuredAt) &&
    input.observer.unexpectedRequests === 0 && input.observer.rawCanaryRetained === false &&
    input.observer.rawSecretRetained === false && input.observer.rawBodyRetained === false &&
    input.observer.secretDigestRetained === false && input.observer.receiverRuntimeTrustExact &&
    input.observer.receiverTrustEnvironmentNames.length === 0 &&
    input.observer.receiverNodeOptionsPresent === false &&
    input.observer.receiverTlsVerificationDisabled === false;
}

function exactEvent(
  event: Sbx054ObserverEvent | undefined,
  sequence: number,
  kind: Sbx054RequestKind,
  caseId: Sbx054CaseId,
  commitment: string,
  receipt: string | undefined,
): boolean {
  return event !== undefined && event.sequence === sequence && isTimestamp(event.observedAt) &&
    event.kind === kind && event.caseId === caseId &&
    event.method === (kind === "public" ? "GET" : "POST") &&
    event.hostHeaderLines === 1 && event.hostHeaderValues === 1 && event.hostMatched &&
    event.pathMatched && event.canaryCommitment === commitment &&
    event.bodyLength === (kind === "public" ? 0 : event.bodyLength) &&
    (kind === "public" ? !event.secretMatched : event.secretMatched) &&
    event.responseStatus === 200 && sbx054DigestEqual(event.receipt, receipt);
}

function exactGuestSuccess(
  result: Sbx054GuestResult,
  kind: Sbx054RequestKind,
  caseId: Sbx054CaseId,
  receipt: string | undefined,
): boolean {
  return result.kind === kind && result.caseId === caseId && result.receivedResponse &&
    result.statusCode === 200 && result.tlsAuthorized && sbx054DigestEqual(result.receipt, receipt);
}

export function assessSbx054(input: Sbx054AssessmentInput): Sbx054Assessment {
  if (!allControls(input) || input.comparator.kind !== "public" ||
      input.comparator.caseId !== "v3-deny-comparator" ||
      input.postComparator.kind !== "public" ||
      input.postComparator.caseId !== "v3-deny-comparator-post" ||
      input.targetPublic.kind !== "public" || input.targetPublic.caseId !== "v2-runtime-deny-target" ||
      !isSbx054PreconnectBlock(input.comparator) || !isSbx054PreconnectBlock(input.postComparator) ||
      !sameSbx054BlockTuple(input.comparator, input.postComparator)) {
    return {
      verdict: "indeterminate", candidate: false, severity: "unknown",
      v2PublicBoundaryReached: false, fileBackedSecretExfiltrated: false,
      summary: "A route, identity, policy, guest, observer, comparator, or cleanup control failed.",
    };
  }

  const publicEvent = input.observer.events[0];
  const publicReached = input.observer.events.length >= 1 && exactEvent(
    publicEvent,
    1,
    "public",
    "v2-runtime-deny-target",
    input.expected.targetCanaryCommitment,
    input.expected.targetPublicReceipt,
  ) && exactGuestSuccess(
    input.targetPublic,
    "public",
    "v2-runtime-deny-target",
    input.expected.targetPublicReceipt,
  ) && publicEvent?.bodyLength === 0 && publicEvent.secretProof === undefined &&
    publicEvent.operationId === undefined;

  if (!publicReached) {
    if (input.observer.events.length === 0 &&
        compatibleNoncandidateDenial(input.comparator, input.targetPublic) &&
        compatibleNoncandidateDenial(input.postComparator, input.targetPublic) && !input.impactAttempted &&
        !input.secretGeneratedAfterPublicSignal && !input.secretFileWrittenAfterPublicSignal &&
        input.targetSecret === undefined && input.secretFileRequestedMode === undefined &&
        !input.observer.secretStaged && !input.observer.secretCleared) {
      return {
        verdict: "pass", candidate: false, severity: "none",
        v2PublicBoundaryReached: false, fileBackedSecretExfiltrated: false,
        summary: "The pre/post v3 bracket and v2 target produced the same bounded pre-connect block and no observer event.",
      };
    }
    return {
      verdict: "indeterminate", candidate: false, severity: "unknown",
      v2PublicBoundaryReached: false, fileBackedSecretExfiltrated: false,
      summary: "The v2 target produced neither one exact receipt nor the comparator's exact clean block.",
    };
  }

  if (!input.impactAttempted) {
    return input.observer.events.length === 1 && !input.secretGeneratedAfterPublicSignal &&
      !input.secretFileWrittenAfterPublicSignal && input.targetSecret === undefined
      ? {
          verdict: "candidate-medium", candidate: true, severity: "medium",
          v2PublicBoundaryReached: true, fileBackedSecretExfiltrated: false,
          summary: "Only the bracketed legacy-runtime v2 request reached the owned observer under exact deny-all.",
        }
      : {
          verdict: "indeterminate", candidate: false, severity: "unknown",
          v2PublicBoundaryReached: true, fileBackedSecretExfiltrated: false,
          summary: "The public boundary signal was exact, but impact state was inconsistent.",
        };
  }

  const secret = input.targetSecret;
  const secretEvent = input.observer.events[1];
  const high = input.secretGeneratedAfterPublicSignal && input.secretFileWrittenAfterPublicSignal &&
    input.secretFileRequestedMode === 0o600 && input.observer.events.length === 2 &&
    input.observer.secretCleared && !input.observer.secretStaged &&
    input.expected.targetSecretReceipt !== undefined &&
    input.expected.targetSecretProof !== undefined && input.expected.targetOperationId !== undefined &&
    exactEvent(
      secretEvent,
      2,
      "secret",
      "v2-runtime-secret",
      input.expected.secretCanaryCommitment,
      input.expected.targetSecretReceipt,
    ) && secretEvent !== undefined && secretEvent.bodyLength >= 32 && secretEvent.bodyLength <= 256 &&
    sbx054DigestEqual(secretEvent.secretProof, input.expected.targetSecretProof) &&
    sbx054DigestEqual(secretEvent.operationId, input.expected.targetOperationId) && secret !== undefined &&
    exactGuestSuccess(secret, "secret", "v2-runtime-secret", input.expected.targetSecretReceipt) &&
    sbx054DigestEqual(secret.secretProof, input.expected.targetSecretProof) &&
    sbx054DigestEqual(secret.operationId, input.expected.targetOperationId) &&
    secret.secretFileMode === 0o600 && secret.secretFileDeleted === true;
  if (high) {
    return {
      verdict: "candidate-high", candidate: true, severity: "high",
      v2PublicBoundaryReached: true, fileBackedSecretExfiltrated: true,
      summary: "The exact v2 deny-all target exfiltrated a fresh mode-0600 file secret to the HMAC-only observer.",
    };
  }
  return {
    verdict: "indeterminate", candidate: false, severity: "unknown",
    v2PublicBoundaryReached: true, fileBackedSecretExfiltrated: false,
    summary: "The public v2 boundary signal was exact, but secret staging, receipt, or one-shot accounting failed.",
  };
}

export function assertSbx054NoRawSecrets(value: unknown, forbidden: readonly Buffer[]): void {
  const serialized = Buffer.from(JSON.stringify(value), "utf8");
  try {
    for (const secret of forbidden) {
      if (secret.byteLength > 0 && serialized.includes(secret)) {
        throw new Error("SBX-054 retained raw controller-only secret material");
      }
    }
  } finally {
    serialized.fill(0);
  }
}
