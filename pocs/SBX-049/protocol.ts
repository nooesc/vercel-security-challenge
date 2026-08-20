import { createHmac, timingSafeEqual } from "node:crypto";

export const SBX049_TEST_ID = "SBX-049-POC" as const;
export const SBX049_TRANSFORM_HEADER = "x-sbx049-brokered-secret" as const;
export const SBX049_REDACTED_VALUE = "<redacted>" as const;

export const SBX049_CASES = [
  "exact-pair",
  "key-half",
  "value-half",
  "combined-halves",
] as const;

export type Sbx049CaseId = (typeof SBX049_CASES)[number];

export const RUN_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
export const CANARY_PATTERN = /^c49_[A-Za-z0-9_-]{24}$/u;
export const SECRET_PATTERN = /^s49_[A-Za-z0-9_-]{43}$/u;
export const OPERATION_ID_PATTERN = /^q49[rs]_[A-Za-z0-9_-]{43}$/u;

export function isCaseId(value: unknown): value is Sbx049CaseId {
  return typeof value === "string" && (SBX049_CASES as readonly string[]).includes(value);
}

export function queryForCase(runId: string, caseId: Sbx049CaseId, canary: string): string {
  if (!RUN_ID_PATTERN.test(runId)) throw new Error("invalid SBX-049 run ID");
  if (!CANARY_PATTERN.test(canary)) throw new Error("invalid SBX-049 correlation canary");
  const query = new URLSearchParams({ run: runId, case: caseId, canary });
  switch (caseId) {
    case "exact-pair":
      query.append("role", "privileged");
      break;
    case "key-half":
      query.append("role", "user");
      break;
    case "value-half":
      query.append("decoy", "privileged");
      break;
    case "combined-halves":
      query.append("role", "user");
      query.append("decoy", "privileged");
      break;
  }
  return query.toString();
}

function operationMessage(
  hostname: string,
  runId: string,
  caseId: Sbx049CaseId,
  canary: string,
  brokeredSecret?: string,
): string {
  const prefix = `v1\n${SBX049_TEST_ID}\n${hostname}\n${runId}\n${caseId}\n${canary}`;
  return brokeredSecret === undefined
    ? `${prefix}\nreach`
    : `${prefix}\nsecret\n${brokeredSecret}`;
}

export function expectedOperationId(
  actionKey: string,
  hostname: string,
  runId: string,
  caseId: Sbx049CaseId,
  canary: string,
  brokeredSecret?: string,
): string {
  if (Buffer.byteLength(actionKey) < 32) throw new Error("SBX-049 action key is too short");
  if (!RUN_ID_PATTERN.test(runId) || !CANARY_PATTERN.test(canary)) {
    throw new Error("invalid SBX-049 operation identity");
  }
  if (brokeredSecret !== undefined && !SECRET_PATTERN.test(brokeredSecret)) {
    throw new Error("invalid SBX-049 brokered secret");
  }
  const prefix = brokeredSecret === undefined ? "q49r" : "q49s";
  const digest = createHmac("sha256", actionKey)
    .update(operationMessage(hostname, runId, caseId, canary, brokeredSecret))
    .digest("base64url");
  return `${prefix}_${digest}`;
}

export function secretCommitment(actionKey: string, brokeredSecret: string): string {
  if (Buffer.byteLength(actionKey) < 32 || !SECRET_PATTERN.test(brokeredSecret)) {
    throw new Error("invalid SBX-049 commitment material");
  }
  return createHmac("sha256", actionKey)
    .update(`v1\n${SBX049_TEST_ID}\ncommit\n${brokeredSecret}`)
    .digest("base64url");
}

export function commitmentMatches(
  actionKey: string,
  brokeredSecret: string,
  commitment: string,
): boolean {
  if (!SECRET_PATTERN.test(brokeredSecret) || !/^[A-Za-z0-9_-]{43}$/u.test(commitment)) {
    return false;
  }
  const actual = Buffer.from(secretCommitment(actionKey, brokeredSecret));
  const expected = Buffer.from(commitment);
  return actual.byteLength === expected.byteLength && timingSafeEqual(actual, expected);
}
