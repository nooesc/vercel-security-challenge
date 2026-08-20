import { createHmac, timingSafeEqual } from "node:crypto";

export const SBX058_TEST_ID = "SBX-058-HEADER-ENTRY-BINDING" as const;
export const SBX058_MATCH_HEADER = "x-sbx058-route" as const;
export const SBX058_DECOY_HEADER = "x-sbx058-decoy" as const;
export const SBX058_RUN_HEADER = "x-sbx058-run" as const;
export const SBX058_CASE_HEADER = "x-sbx058-case" as const;
export const SBX058_CANARY_HEADER = "x-sbx058-canary" as const;
export const SBX058_OIDC_HEADER = "vercel-sandbox-oidc-token" as const;
export const SBX058_MATCH_VALUE = "privileged" as const;
export const SBX058_WRONG_VALUE = "ordinary" as const;

export const SBX058_CASES = [
  "direct-p-pre",
  "exact-pair",
  "key-half",
  "value-half",
  "combined-halves",
  "direct-p-post",
] as const;

export const SBX058_EVENT_CASES = [
  "exact-pair",
  "key-half",
  "value-half",
  "combined-halves",
] as const;

export type Sbx058CaseId = typeof SBX058_CASES[number];
export type Sbx058EventCaseId = typeof SBX058_EVENT_CASES[number];
export type Sbx058Role = "A" | "P";
export type Sbx058HeaderMode = "exact-pair" | "key-half" | "value-half" | "combined-halves" | "none";

export const SBX058_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
export const SBX058_CANARY = /^s58_[a-z-]+_[A-Za-z0-9_-]{22}$/u;
export const SBX058_OPERATION = /^s58op_[A-Za-z0-9_-]{43}$/u;
export const SBX058_RECEIPT = /^s58rcpt_[A-Za-z0-9_-]{43}$/u;

function keyed(key: string, domain: string, fields: readonly string[]): string {
  if (Buffer.byteLength(key) < 32 || Buffer.byteLength(key) > 256) {
    throw new Error("SBX-058 key length was invalid");
  }
  const framed = [domain, ...fields].map((value) => `${Buffer.byteLength(value)}:${value}`).join("|");
  return createHmac("sha256", key).update(framed).digest("base64url");
}

export function isSbx058CaseId(value: unknown): value is Sbx058CaseId {
  return typeof value === "string" && (SBX058_CASES as readonly string[]).includes(value);
}

export function isSbx058EventCaseId(value: unknown): value is Sbx058EventCaseId {
  return typeof value === "string" && (SBX058_EVENT_CASES as readonly string[]).includes(value);
}

export function headerModeForCase(caseId: Sbx058CaseId): Sbx058HeaderMode {
  return isSbx058EventCaseId(caseId) ? caseId : "none";
}

export function requestPath(runId: string, caseId: Sbx058CaseId, canary: string): string {
  if (!SBX058_UUID.test(runId) || !SBX058_CANARY.test(canary)) {
    throw new Error("SBX-058 request identity was invalid");
  }
  const family = isSbx058EventCaseId(caseId) ? "request" : "direct";
  return `/v1/sbx058/${family}/${runId}/${caseId}?${new URLSearchParams({ canary }).toString()}`;
}

export function proxyAudience(origin: string | URL, runId: string): string {
  if (!SBX058_UUID.test(runId)) throw new Error("SBX-058 run ID was invalid");
  return new URL(`/v1/sbx058/proxy/${runId}`, origin).toString();
}

export function expectedOperationId(
  actionKey: string,
  runId: string,
  caseId: Sbx058EventCaseId,
  canary: string,
  role: Sbx058Role,
  routeHeaderCount: number,
  decoyHeaderCount: number,
  routeValueMatched: boolean,
  decoyValueMatched: boolean,
  oidcVerified: boolean,
): string {
  if (!SBX058_UUID.test(runId) || !SBX058_CANARY.test(canary) ||
      !Number.isSafeInteger(routeHeaderCount) || routeHeaderCount < 0 || routeHeaderCount > 2 ||
      !Number.isSafeInteger(decoyHeaderCount) || decoyHeaderCount < 0 || decoyHeaderCount > 2) {
    throw new Error("SBX-058 operation material was invalid");
  }
  return `s58op_${keyed(actionKey, "sbx058-operation-v1", [
    runId, caseId, canary, role, String(routeHeaderCount), String(decoyHeaderCount),
    String(routeValueMatched), String(decoyValueMatched), String(oidcVerified),
  ])}`;
}

export function expectedReceipt(
  adminKey: string,
  runId: string,
  ordinal: number,
  caseId: Sbx058EventCaseId,
  canary: string,
  role: Sbx058Role,
  operationId: string,
): string {
  if (!Number.isSafeInteger(ordinal) || ordinal < 1 || ordinal > SBX058_EVENT_CASES.length ||
      !SBX058_OPERATION.test(operationId)) throw new Error("SBX-058 receipt material was invalid");
  return `s58rcpt_${keyed(adminKey, "sbx058-receipt-v1", [
    runId, String(ordinal), caseId, canary, role, operationId,
  ])}`;
}

export function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}
