import { createHmac, timingSafeEqual } from "node:crypto";

export const SBX057_TEST_ID = "SBX-057-WILDCARD-EMPTY-ISOLATION" as const;
export const SBX057_TRANSFORM_HEADER = "x-sbx057-brokered-credential" as const;
export const SBX057_RUN_HEADER = "x-sbx057-run" as const;
export const SBX057_CASE_HEADER = "x-sbx057-case" as const;
export const SBX057_CANARY_HEADER = "x-sbx057-canary" as const;
export const SBX057_REDACTED_VALUE = "<redacted>" as const;

export const SBX057_CASES = [
  "comparator-a",
  "comparator-b",
  "target-a",
  "target-b",
] as const;

export type Sbx057CaseId = typeof SBX057_CASES[number];
export type Sbx057Stage = "comparator" | "target";
export type Sbx057Role = "A" | "B";

export const SBX057_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
export const SBX057_CANARY = /^s57_[a-z-]+_[A-Za-z0-9_-]{22}$/u;
export const SBX057_OPERATION = /^s57op_[A-Za-z0-9_-]{43}$/u;
export const SBX057_RECEIPT = /^s57rcpt_[A-Za-z0-9_-]{43}$/u;
export const SBX057_COMMITMENT = /^s57h_[A-Za-z0-9_-]{43}$/u;

function hmac(key: string, domain: string, fields: readonly string[]): string {
  const value = [domain, ...fields].map((entry) => `${Buffer.byteLength(entry)}:${entry}`).join("|");
  return createHmac("sha256", key).update(value).digest("base64url");
}

export function stageForCase(caseId: Sbx057CaseId): Sbx057Stage {
  return caseId.startsWith("comparator-") ? "comparator" : "target";
}

export function roleForCase(caseId: Sbx057CaseId): Sbx057Role {
  return caseId.endsWith("-a") ? "A" : "B";
}

export function casePath(runId: string, caseId: Sbx057CaseId): string {
  if (!SBX057_UUID.test(runId)) throw new Error("SBX-057 path requires a canonical UUIDv4");
  return `/v1/sbx057/probe/${runId}/${caseId}`;
}

export function secretCommitment(
  actionKey: string,
  runId: string,
  stage: Sbx057Stage,
  secret: string,
): string {
  return `s57h_${hmac(actionKey, "sbx057-secret-v1", [runId, stage, secret])}`;
}

export function expectedOperationId(
  actionKey: string,
  runId: string,
  caseId: Sbx057CaseId,
  canary: string,
  commitment: string,
): string {
  return `s57op_${hmac(actionKey, "sbx057-operation-v1", [runId, caseId, canary, commitment])}`;
}

export function expectedReceipt(
  adminKey: string,
  runId: string,
  sequence: number,
  caseId: Sbx057CaseId,
  canary: string,
  role: Sbx057Role,
  headerCount: number,
  commitmentMatched: boolean,
  crossCommitmentMatched: boolean,
  status: number,
  operationId?: string,
): string {
  return `s57rcpt_${hmac(adminKey, "sbx057-receipt-v1", [
    runId,
    String(sequence),
    caseId,
    canary,
    role,
    String(headerCount),
    String(commitmentMatched),
    String(crossCommitmentMatched),
    String(status),
    operationId ?? "",
  ])}`;
}

export function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function isSbx057CaseId(value: unknown): value is Sbx057CaseId {
  return typeof value === "string" && (SBX057_CASES as readonly string[]).includes(value);
}
