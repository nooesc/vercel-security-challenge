import { createHmac, timingSafeEqual } from "node:crypto";

export const SBX050_TEST_ID = "SBX-050-POC" as const;
export const SBX050_CREDENTIAL_HEADER = "x-sbx050-brokered-credential" as const;
export const SBX050_TRIGGER_HEADER = "x-sbx050-route-trigger" as const;
export const SBX050_CASE_HEADER = "x-sbx050-case" as const;
export const SBX050_CANARY_HEADER = "x-sbx050-canary" as const;
export const SBX050_RUN_HEADER = "x-sbx050-run" as const;
export const SBX050_OIDC_HEADER = "vercel-sandbox-oidc-token" as const;
export const SBX050_REDACTED_VALUE = "<redacted>" as const;
export const SBX050_TRIGGER_MARKER = "<trigger>" as const;
export const SBX050_PUBLIC_TRIGGER = "sbx050-public-forward-control" as const;

export const SBX050_CASES = [
  "public-forward-control",
  "transform-alone-control",
  "final-plain-pre",
  "direct-p-pre",
  "arm-without-trigger",
  "direct-p-post",
  "final-plain-post",
] as const;

export const SBX050_EVENT_CASES = [
  "public-forward-control",
  "transform-alone-control",
  "final-plain-pre",
  "arm-without-trigger",
  "final-plain-post",
] as const;

export type Sbx050CaseId = (typeof SBX050_CASES)[number];
export type Sbx050EventCaseId = (typeof SBX050_EVENT_CASES)[number];
export type Sbx050Role = "A" | "P";

export const RUN_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
export const CANARY_PATTERN = /^c50_[A-Za-z0-9_-]{24}$/u;
export const CREDENTIAL_PATTERN = /^s50_[A-Za-z0-9_-]{43}$/u;
export const TRIGGER_PATTERN = /^t50_[A-Za-z0-9_-]{32}$/u;
export const COMMITMENT_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
export const OPERATION_ID_PATTERN = /^chain50_[A-Za-z0-9_-]{43}$/u;

export function isCaseId(value: unknown): value is Sbx050CaseId {
  return typeof value === "string" && (SBX050_CASES as readonly string[]).includes(value);
}

export function isEventCaseId(value: unknown): value is Sbx050EventCaseId {
  return typeof value === "string" && (SBX050_EVENT_CASES as readonly string[]).includes(value);
}

export function requestPath(runId: string, caseId: Sbx050CaseId, canary: string): string {
  if (!RUN_ID_PATTERN.test(runId) || !CANARY_PATTERN.test(canary)) {
    throw new Error("invalid SBX-050 request identity");
  }
  const pathname = caseId === "arm-without-trigger" || caseId === "transform-alone-control"
    ? `/v1/sbx050/arm/${runId}`
    : `/v1/sbx050/request/${runId}/${caseId}`;
  return `${pathname}?${new URLSearchParams({ case: caseId, canary }).toString()}`;
}

export function armPath(runId: string): string {
  if (!RUN_ID_PATTERN.test(runId)) throw new Error("invalid SBX-050 run ID");
  return `/v1/sbx050/arm/${runId}`;
}

export function proxyAudience(origin: string | URL, runId: string): string {
  if (!RUN_ID_PATTERN.test(runId)) throw new Error("invalid SBX-050 run ID");
  return new URL(`/v1/sbx050/proxy/${runId}`, origin).toString();
}

function operationMessage(
  hostname: string,
  runId: string,
  caseId: Sbx050CaseId,
  canary: string,
  role: Sbx050Role,
  credentialMatched: boolean,
  triggerMatched: boolean,
  oidcVerified: boolean,
): string {
  return [
    "v1", SBX050_TEST_ID, hostname, runId, caseId, canary, role,
    credentialMatched ? "credential" : "no-credential",
    triggerMatched ? "trigger" : "no-trigger",
    oidcVerified ? "oidc" : "no-oidc",
  ].join("\n");
}

export function expectedOperationId(
  actionKey: string,
  hostname: string,
  runId: string,
  caseId: Sbx050CaseId,
  canary: string,
  role: Sbx050Role,
  credentialMatched: boolean,
  triggerMatched: boolean,
  oidcVerified: boolean,
): string {
  if (Buffer.byteLength(actionKey) < 32 || !RUN_ID_PATTERN.test(runId) || !CANARY_PATTERN.test(canary)) {
    throw new Error("invalid SBX-050 operation material");
  }
  const digest = createHmac("sha256", actionKey)
    .update(operationMessage(
      hostname, runId, caseId, canary, role,
      credentialMatched, triggerMatched, oidcVerified,
    ))
    .digest("base64url");
  return `chain50_${digest}`;
}

function commitmentMessage(kind: "credential" | "trigger", value: string): string {
  return `v1\n${SBX050_TEST_ID}\n${kind}\n${value}`;
}

export function valueCommitment(
  actionKey: string,
  kind: "credential" | "trigger",
  value: string,
): string {
  const valid = kind === "credential" ? CREDENTIAL_PATTERN.test(value) : TRIGGER_PATTERN.test(value);
  if (Buffer.byteLength(actionKey) < 32 || !valid) throw new Error("invalid SBX-050 commitment material");
  return createHmac("sha256", actionKey).update(commitmentMessage(kind, value)).digest("base64url");
}

export function commitmentMatches(
  actionKey: string,
  kind: "credential" | "trigger",
  value: string,
  commitment: string,
): boolean {
  const valid = kind === "credential" ? CREDENTIAL_PATTERN.test(value) : TRIGGER_PATTERN.test(value);
  if (!valid || !COMMITMENT_PATTERN.test(commitment)) return false;
  const actual = Buffer.from(valueCommitment(actionKey, kind, value));
  const expected = Buffer.from(commitment);
  return actual.byteLength === expected.byteLength && timingSafeEqual(actual, expected);
}
