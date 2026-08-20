import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export const TEST_ID = "SBX-001";
export const TEST_ID_POC = "SBX-001-POC";
export const ZONE_NAME = "form-app.app";
export const ZONE_ID = "4b7531c4f69e05b6ceb150fad5fd909b";
export const CLOUDFLARE_ACCOUNT_ID = "20674b6202a2160e3e275d18ae884820";
export const ELIGIBLE_ALIAS_EMAIL = "swve@wearehackerone.com";
export const ELIGIBLE_TEAM_ID = "team_n98ERpVwV7HqmWRudAyK8sXQ";
export const ELIGIBLE_PROJECT_ID = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
export const QUERY_NONCE_PATTERN = /^[a-f0-9]{32}$/u;
export const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
export const OPERATION_ID_PATTERN = /^dns_[A-Za-z0-9_-]{43}$/u;
export const GATE_PATTERN = /^gate_[A-Za-z0-9_-]{43}$/u;
export const ANALYTICS_ROW_LIMIT = 1_000;
export const ANALYTICS_POLL_GUIDANCE_MS = 60 * 60 * 1_000;
export const EVENT_BRACKET_SKEW_MS = 2 * 60 * 1_000;

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE32_REVERSE = new Map(
  [...BASE32_ALPHABET].map((character, index) => [character, index] as const),
);

export type RunStage = "allow-control" | "deny-control" | "deny-secret";
export type VerificationOutcome =
  | "allow-observed"
  | "signal-medium"
  | "candidate-high"
  | "no-candidate-observed"
  | "indeterminate"
  | "error";

export interface CloudflareDnsRow {
  datetime?: unknown;
  queryName?: unknown;
  queryType?: unknown;
  responseCode?: unknown;
  sampleInterval?: unknown;
}

export interface QueryBracket {
  sendStartedAt: string;
  sendCompletedAt: string;
}

export interface SanitizedDnsObservation {
  datetime: string;
  queryNameSha256: string;
  operationId: string;
  queryType: "A";
  responseCode?: string;
  sampleInterval?: number;
  recoveredSecretMatches?: boolean;
}

export interface PositiveAnalysis {
  sourceRowCount: number;
  exactObservationCount: number;
  observations: SanitizedDnsObservation[];
  observed: boolean;
  ambiguous: boolean;
  ambiguityReasons: string[];
}

export interface StageAssessment {
  outcome: VerificationOutcome;
  candidate: boolean;
  secretPhaseAuthorized: boolean;
  maximumDemonstratedImpact: "high" | "medium" | "none" | "unknown";
  summary: string;
}

export function sha256Bytes(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function base32Encode(value: Uint8Array): string {
  let accumulator = 0;
  let availableBits = 0;
  let output = "";
  for (const byte of value) {
    accumulator = (accumulator << 8) | byte;
    availableBits += 8;
    while (availableBits >= 5) {
      availableBits -= 5;
      output += BASE32_ALPHABET[(accumulator >>> availableBits) & 31];
      accumulator &= (1 << availableBits) - 1;
    }
  }
  if (availableBits > 0) output += BASE32_ALPHABET[(accumulator << (5 - availableBits)) & 31];
  return output;
}

export function base32DecodeStrict(encoded: string): Buffer {
  if (!/^[A-Z2-7]{1,63}$/u.test(encoded)) throw new Error("invalid unpadded base32 value");
  let accumulator = 0;
  let availableBits = 0;
  const bytes: number[] = [];
  for (const character of encoded) {
    const decoded = BASE32_REVERSE.get(character);
    if (decoded === undefined) throw new Error("invalid unpadded base32 character");
    accumulator = (accumulator << 5) | decoded;
    availableBits += 5;
    while (availableBits >= 8) {
      availableBits -= 8;
      bytes.push((accumulator >>> availableBits) & 0xff);
      accumulator &= (1 << availableBits) - 1;
    }
  }
  if (availableBits > 0 && accumulator !== 0) throw new Error("non-zero base32 padding bits");
  const output = Buffer.from(bytes);
  if (base32Encode(output) !== encoded) {
    output.fill(0);
    throw new Error("non-canonical unpadded base32 value");
  }
  return output;
}

export function xorBytes(left: Uint8Array, right: Uint8Array): Buffer {
  if (left.byteLength !== right.byteLength || left.byteLength === 0) throw new Error("XOR operands must have equal non-zero lengths");
  const output = Buffer.alloc(left.byteLength);
  for (let index = 0; index < left.byteLength; index += 1) {
    output[index] = left[index]! ^ right[index]!;
  }
  return output;
}

function validateProofKey(key: string): void {
  if (Buffer.byteLength(key) < 32 || Buffer.byteLength(key) > 256 || /[\0\r\n]/u.test(key)) {
    throw new Error("SBX001_PROOF_KEY must contain 32-256 bytes without control characters");
  }
}

function validateDnsName(value: string): string {
  if (value !== value.toLowerCase() || value.endsWith(".") || value.length === 0 || value.length > 253 ||
    !/^[a-z0-9.-]+$/u.test(value)) {
    throw new Error("DNS name must be lowercase without a trailing dot");
  }
  const labels = value.split(".");
  if (labels.some((label) => label.length === 0 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label))) {
    throw new Error("invalid DNS label");
  }
  return value;
}

export function querySuffix(queryNonce: string): string {
  if (!QUERY_NONCE_PATTERN.test(queryNonce)) throw new Error("invalid query nonce");
  return `${queryNonce}.sbx001.${ZONE_NAME}`;
}

export function publicQueryName(stage: "allow-control" | "deny-control", queryNonce: string): string {
  return validateDnsName(`${stage === "allow-control" ? "a" : "d"}${querySuffix(queryNonce)}`);
}

export function expectedOperationId(
  key: string,
  runId: string,
  stage: RunStage,
  proofMaterialSha256: string,
): string {
  validateProofKey(key);
  if (!SHA256_PATTERN.test(proofMaterialSha256)) throw new Error("proof material must be a SHA-256 digest");
  const message = [TEST_ID, "receipt", runId, stage, proofMaterialSha256].join("\n");
  return `dns_${createHmac("sha256", key).update(message).digest("base64url")}`;
}

export function gateAuthorization(
  key: string,
  stage: "allow-control" | "deny-control",
  runId: string,
  outcome: "allow-observed" | "signal-medium",
  operationId: string,
): string {
  validateProofKey(key);
  if (!OPERATION_ID_PATTERN.test(operationId)) throw new Error("invalid gate operation ID");
  const message = [TEST_ID, "gate", stage, runId, outcome, operationId].join("\n");
  return `gate_${createHmac("sha256", key).update(message).digest("base64url")}`;
}

function safeEqualHex(left: string, right: string): boolean {
  if (!SHA256_PATTERN.test(left) || !SHA256_PATTERN.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function safeResponseCode(value: unknown): string | undefined {
  if (typeof value === "string" && /^[A-Za-z0-9_-]{1,32}$/u.test(value)) return value;
  if (typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 65_535) return String(value);
  return undefined;
}

function safeSampleInterval(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value >= 1 && value <= 1_000_000
    ? value
    : undefined;
}

function eventInBracket(datetime: string, bracket: QueryBracket): boolean {
  const eventTime = Date.parse(datetime);
  const start = Date.parse(bracket.sendStartedAt) - EVENT_BRACKET_SKEW_MS;
  const end = Date.parse(bracket.sendCompletedAt) + EVENT_BRACKET_SKEW_MS;
  return Number.isFinite(eventTime) && Number.isFinite(start) && Number.isFinite(end) && eventTime >= start && eventTime <= end;
}

function sanitizedObservation(
  row: CloudflareDnsRow,
  queryNameSha256: string,
  operationId: string,
  extra: Partial<Pick<SanitizedDnsObservation, "recoveredSecretMatches">> = {},
): SanitizedDnsObservation {
  const responseCode = safeResponseCode(row.responseCode);
  const sampleInterval = safeSampleInterval(row.sampleInterval);
  return {
    datetime: new Date(row.datetime as string).toISOString(),
    queryNameSha256,
    operationId,
    queryType: "A",
    ...(responseCode ? { responseCode } : {}),
    ...(sampleInterval !== undefined ? { sampleInterval } : {}),
    ...extra,
  };
}

export function analyzeExactPositiveRows(input: {
  rows: readonly CloudflareDnsRow[];
  expectedQueryName: string;
  expectedQueryNameSha256: string;
  expectedOperationId: string;
  runId: string;
  stage: "allow-control" | "deny-control";
  proofKey: string;
  bracket: QueryBracket;
  rowLimit?: number;
}): PositiveAnalysis {
  const expectedQueryName = validateDnsName(input.expectedQueryName);
  if (!safeEqualHex(sha256Bytes(expectedQueryName), input.expectedQueryNameSha256)) {
    throw new Error("expected public query-name digest mismatch");
  }
  if (expectedOperationId(input.proofKey, input.runId, input.stage, input.expectedQueryNameSha256) !== input.expectedOperationId) {
    throw new Error("expected public operation ID mismatch");
  }
  const observations: SanitizedDnsObservation[] = [];
  const ambiguityReasons: string[] = [];
  for (const row of input.rows) {
    if (row.queryName !== expectedQueryName) {
      ambiguityReasons.push("exact-filter-returned-different-query-name");
      continue;
    }
    if (row.queryType !== "A" || typeof row.datetime !== "string" || !eventInBracket(row.datetime, input.bracket)) {
      ambiguityReasons.push("exact-row-failed-type-or-event-bracket");
      continue;
    }
    observations.push(sanitizedObservation(row, input.expectedQueryNameSha256, input.expectedOperationId));
  }
  const rowLimit = input.rowLimit ?? ANALYTICS_ROW_LIMIT;
  if (input.rows.length >= rowLimit) ambiguityReasons.push("analytics-row-limit-reached");
  return {
    sourceRowCount: input.rows.length,
    exactObservationCount: observations.length,
    observations,
    observed: observations.length > 0,
    ambiguous: ambiguityReasons.length > 0,
    ambiguityReasons: [...new Set(ambiguityReasons)].sort(),
  };
}

export function analyzeSecretPositiveRows(input: {
  rows: readonly CloudflareDnsRow[];
  queryNonce: string;
  expectedQueryNameSha256: string;
  expectedSecret: Uint8Array;
  oneTimePad: Uint8Array;
  expectedOperationId: string;
  runId: string;
  proofKey: string;
  bracket: QueryBracket;
  rowLimit?: number;
}): PositiveAnalysis {
  if (!QUERY_NONCE_PATTERN.test(input.queryNonce)) throw new Error("invalid secret query nonce");
  if (!SHA256_PATTERN.test(input.expectedQueryNameSha256)) throw new Error("invalid secret query-name digest");
  if (input.expectedSecret.byteLength !== 16 || input.oneTimePad.byteLength !== 16) {
    throw new Error("secret and one-time pad must each contain exactly 16 bytes");
  }
  if (expectedOperationId(input.proofKey, input.runId, "deny-secret", input.expectedQueryNameSha256) !== input.expectedOperationId) {
    throw new Error("expected secret operation ID mismatch");
  }
  const suffix = querySuffix(input.queryNonce);
  const observations: SanitizedDnsObservation[] = [];
  const ambiguityReasons: string[] = [];
  for (const row of input.rows) {
    if (typeof row.queryName !== "string") continue;
    const rawQueryName = row.queryName;
    if (!rawQueryName.endsWith(suffix)) continue;
    let queryName: string;
    try {
      queryName = validateDnsName(rawQueryName);
    } catch {
      ambiguityReasons.push("run-suffix-row-was-not-canonical-lowercase");
      continue;
    }
    if (row.queryType !== "A" || typeof row.datetime !== "string" || !eventInBracket(row.datetime, input.bracket)) {
      ambiguityReasons.push("secret-row-failed-type-or-event-bracket");
      continue;
    }
    const encodedCiphertext = queryName.slice(0, -suffix.length);
    if (!/^s[a-z2-7]{26}$/u.test(encodedCiphertext)) {
      ambiguityReasons.push("run-suffix-row-had-unexpected-shape");
      continue;
    }
    let ciphertext: Buffer | undefined;
    let recovered: Buffer | undefined;
    try {
      ciphertext = base32DecodeStrict(encodedCiphertext.slice(1).toUpperCase());
      if (ciphertext.byteLength !== 16) {
        ambiguityReasons.push("ciphertext-length-mismatch");
        continue;
      }
      const queryNameSha256 = sha256Bytes(queryName);
      if (!safeEqualHex(queryNameSha256, input.expectedQueryNameSha256)) {
        ambiguityReasons.push("query-name-digest-mismatch");
        continue;
      }
      recovered = xorBytes(ciphertext, input.oneTimePad);
      const recoveredSecretMatches = timingSafeEqual(recovered, input.expectedSecret);
      if (!recoveredSecretMatches) {
        ambiguityReasons.push("recovered-secret-mismatch");
        continue;
      }
      observations.push(sanitizedObservation(
        row,
        queryNameSha256,
        input.expectedOperationId,
        { recoveredSecretMatches },
      ));
    } catch {
      ambiguityReasons.push("secret-row-decode-failed");
    } finally {
      ciphertext?.fill(0);
      recovered?.fill(0);
    }
  }
  const rowLimit = input.rowLimit ?? ANALYTICS_ROW_LIMIT;
  if (input.rows.length >= rowLimit) ambiguityReasons.push("analytics-row-limit-reached");
  return {
    sourceRowCount: input.rows.length,
    exactObservationCount: observations.length,
    observations,
    observed: observations.length > 0,
    ambiguous: ambiguityReasons.length > 0,
    ambiguityReasons: [...new Set(ambiguityReasons)].sort(),
  };
}

export function historicalSuffixCollisionCount(rows: readonly CloudflareDnsRow[], queryNonce: string): number {
  const suffix = querySuffix(queryNonce);
  let matches = 0;
  for (const row of rows) {
    if (typeof row.queryName === "string" && row.queryName === row.queryName.toLowerCase() &&
      !row.queryName.endsWith(".") && row.queryName.endsWith(suffix)) {
      matches += 1;
    }
  }
  return matches;
}

export function assessStage(input: {
  stage: RunStage;
  runReadyForVerification: boolean;
  cleanupPassed: boolean;
  analysis?: PositiveAnalysis;
  executionError?: boolean;
}): StageAssessment {
  if (input.executionError || !input.cleanupPassed) {
    return {
      outcome: "error",
      candidate: false,
      secretPhaseAuthorized: false,
      maximumDemonstratedImpact: "unknown",
      summary: "The run packet or owned-sandbox cleanup failed; analytics cannot be interpreted as boundary evidence.",
    };
  }
  if (!input.runReadyForVerification || !input.analysis) {
    return {
      outcome: "indeterminate",
      candidate: false,
      secretPhaseAuthorized: false,
      maximumDemonstratedImpact: "unknown",
      summary: "The run packet did not complete every policy, pre-send, and one-shot-query prerequisite.",
    };
  }
  if (input.analysis.ambiguous) {
    return {
      outcome: "indeterminate",
      candidate: false,
      secretPhaseAuthorized: false,
      maximumDemonstratedImpact: "unknown",
      summary: "Returned DNS analytics rows failed exact query, A-record, event-bracket, or bounded-result checks.",
    };
  }
  if (!input.analysis.observed) {
    return {
      outcome: "no-candidate-observed",
      candidate: false,
      secretPhaseAuthorized: false,
      maximumDemonstratedImpact: "unknown",
      summary: "No exact positive analytics row is currently visible; adaptive-data absence is never classified as a pass.",
    };
  }
  if (input.stage === "allow-control") {
    return {
      outcome: "allow-observed",
      candidate: false,
      secretPhaseAuthorized: false,
      maximumDemonstratedImpact: "none",
      summary: "The exact allow-all A-query control is visible and may authorize the deny-control stage.",
    };
  }
  if (input.stage === "deny-control") {
    return {
      outcome: "signal-medium",
      candidate: false,
      secretPhaseAuthorized: true,
      maximumDemonstratedImpact: "medium",
      summary: "The exact public A query is visible from a literal deny-all sandbox; one gated secret phase is authorized.",
    };
  }
  return {
    outcome: "candidate-high",
    candidate: true,
    secretPhaseAuthorized: false,
    maximumDemonstratedImpact: "high",
    summary: "The exact ciphertext DNS row recovered the fresh file secret under literal deny-all without persisting plaintext, pad, or query name.",
  };
}
