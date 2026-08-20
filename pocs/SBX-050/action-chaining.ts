import "dotenv/config";

import { randomBytes, randomUUID } from "node:crypto";
import { mkdir, open, readFile, unlink, type FileHandle } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { APIError, Sandbox, type NetworkPolicy } from "@vercel/sandbox";
import { verifyEligibleAliasToken } from "../eligible-alias-identity.js";
import {
  expectedOperationId,
  proxyAudience,
  requestPath,
  RUN_ID_PATTERN,
  SBX050_CASES,
  SBX050_CASE_HEADER,
  SBX050_CANARY_HEADER,
  SBX050_CREDENTIAL_HEADER,
  SBX050_EVENT_CASES,
  SBX050_OIDC_HEADER,
  SBX050_PUBLIC_TRIGGER,
  SBX050_REDACTED_VALUE,
  SBX050_TEST_ID,
  SBX050_TRIGGER_HEADER,
  SBX050_TRIGGER_MARKER,
  valueCommitment,
  type Sbx050CaseId,
  type Sbx050EventCaseId,
} from "./protocol.js";
import {
  assessSbx050,
  exactDirectBlockProbe,
  SBX050_SEMANTICS_QUESTION,
  type Sbx050AssessmentInput,
  type Sbx050Assessment,
  type Sbx050CleanupEvidence,
  type Sbx050LedgerEvidence,
  type Sbx050LedgerEvent,
  type Sbx050ExpectedIdentity,
  type Sbx050LocalStateEvidence,
  type Sbx050PolicyProof,
  type Sbx050PolicyProjectionMode,
  type Sbx050PolicyReadbackCode,
  type Sbx050PolicyReadbackDiagnostic,
  type Sbx050PolicyStage,
  type Sbx050ProbeEvidence,
  type Sbx050RetentionEvidence,
} from "./verdict.js";

const SCOPE_CONFIRMATION =
  "I_CONTROL_BOTH_SBX050_ORIGINS_AND_AUTHORIZE_BOUNDED_ACTION_CHAINING_TESTING";
const ALIAS_EMAIL = "swve@wearehackerone.com";
const TEAM_ID = "team_n98ERpVwV7HqmWRudAyK8sXQ";
const PROJECT_ID = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
const REMOTE_GUEST_PATH = "/tmp/sbx-050/action-chain-probe.mjs";
const GUEST_SOURCE_PATH = resolve("guest/sbx-050-action-chain-probe.mjs");
const CONTROL_TIMEOUT_MS = 30_000;
const COMMAND_TIMEOUT_MS = 20_000;
const INTER_REQUEST_MS = 350;
const MAX_STDOUT_BYTES = 64 * 1024;
const MAX_STDERR_BYTES = 16 * 1024;
const PLATFORM_REDACTION = "<redacted>";
const RECOVERY_DISCOVERY_DELAYS_MS = [0, 750, 1_500, 3_000] as const;
const POST_DELETE_ABSENCE_DELAYS_MS = [0, 750, 1_500] as const;
const SBX050_SESSION_ID = /^sbx_[A-Za-z0-9_-]{20,100}$/u;
const TRUST_ENVIRONMENT_NAMES = [
  "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF",
  "OPENSSL_MODULES", "SSL_CERT_DIR", "SSL_CERT_FILE",
] as const;

type ExactPhase = Exclude<Sbx050PolicyStage, "final-after">;

export interface Sbx050ExplicitConfiguration {
  token: string;
  teamId: typeof TEAM_ID;
  projectId: typeof PROJECT_ID;
  adminKey: string;
  actionKey: string;
  aOrigin: URL;
  pOrigin: URL;
  manualAliasConfirmation?: string;
}

interface CommandRecord {
  caseId: Sbx050CaseId;
  commandId: string;
  exitCode: number;
  startedAt: string;
  completedAt: string;
  stdoutBytes: number;
  stderrBytes: number;
}

interface PhasePolicyProof extends Sbx050PolicyProof {
  inMemoryReadbackExact: true;
  serverRedactionObserved: boolean;
}

interface RecoveryJournalRecord {
  schemaVersion: 1;
  testId: typeof SBX050_TEST_ID;
  runId: string;
  sandboxName: string;
  teamId: string;
  projectId: string;
  tags: Record<string, string>;
  state: "prepared" | "sandbox-create-requested" | "sandbox-create-confirmed" |
    "receiver-configure-requested" | "receiver-configured" | "cleanup-started" |
    "cleanup-confirmed" | "cleanup-uncertain";
  updatedAt: string;
  containsSecrets: false;
}

const POLICY_READBACK_CODES = new Set<Sbx050PolicyReadbackCode>([
  "not-observed", "exact-top-host-list", "exact-public-forward", "exact-transform-alone",
  "exact-final-matchers", "exact-final-matcherless-redacted", "unexpected",
]);
const POLICY_PROJECTION_MODES = new Set<Sbx050PolicyReadbackDiagnostic["projectionMode"]>([
  "not-final", "exact-matchers", "matcherless-redacted", "undetermined",
]);

function closedPolicyReadbackDiagnostic(
  value: Sbx050PolicyReadbackDiagnostic,
): Sbx050PolicyReadbackDiagnostic {
  if (!(["public-forward", "transform-alone", "final-before", "final-after"] as const).includes(value.stage) ||
      !POLICY_READBACK_CODES.has(value.configuredPolicy) ||
      !POLICY_READBACK_CODES.has(value.activeSandboxPolicy) ||
      !POLICY_READBACK_CODES.has(value.activeSessionPolicy) ||
      !POLICY_READBACK_CODES.has(value.independentSandboxPolicy) ||
      !POLICY_READBACK_CODES.has(value.independentSessionPolicy) ||
      !(value.activeIdentity === "not-observed" || value.activeIdentity === "exact" ||
        value.activeIdentity === "unexpected") ||
      !(value.independentIdentity === "not-observed" || value.independentIdentity === "exact" ||
        value.independentIdentity === "unexpected") ||
      !POLICY_PROJECTION_MODES.has(value.projectionMode) || typeof value.continuationAllowed !== "boolean" ||
      value.containsSecrets !== false) {
    throw new Error("SBX-050 policy readback diagnostic escaped its closed vocabulary");
  }
  return {
    stage: value.stage,
    configuredPolicy: value.configuredPolicy,
    activeSandboxPolicy: value.activeSandboxPolicy,
    activeSessionPolicy: value.activeSessionPolicy,
    independentSandboxPolicy: value.independentSandboxPolicy,
    independentSessionPolicy: value.independentSessionPolicy,
    activeIdentity: value.activeIdentity,
    independentIdentity: value.independentIdentity,
    projectionMode: value.projectionMode,
    continuationAllowed: value.continuationAllowed,
    containsSecrets: false,
  };
}

export function policyReadbackCheckpoint(
  runId: string,
  diagnostics: Partial<Record<Sbx050PolicyStage, Sbx050PolicyReadbackDiagnostic>>,
): Record<string, unknown> {
  if (!RUN_ID_PATTERN.test(runId)) throw new Error("SBX-050 diagnostic checkpoint run ID was not canonical");
  const retained = Object.fromEntries(([
    "public-forward", "transform-alone", "final-before", "final-after",
  ] as const).flatMap((stage) => diagnostics[stage]
    ? [[stage, closedPolicyReadbackDiagnostic(diagnostics[stage]!)] as const] : []));
  return {
    schemaVersion: 1,
    visibility: "private",
    testId: SBX050_TEST_ID,
    runId,
    kind: "policy-readback-checkpoint",
    policyReadbackDiagnostics: retained,
    containsSecrets: false,
  };
}

async function writePolicyReadbackCheckpoint(
  handle: FileHandle,
  runId: string,
  diagnostics: Partial<Record<Sbx050PolicyStage, Sbx050PolicyReadbackDiagnostic>>,
): Promise<void> {
  const serialized = `${JSON.stringify(policyReadbackCheckpoint(runId, diagnostics), null, 2)}\n`;
  await handle.truncate(0);
  await handle.write(serialized, 0, "utf8");
  await handle.sync();
}

async function writeRecoveryJournal(
  handle: FileHandle,
  record: Omit<RecoveryJournalRecord, "schemaVersion" | "testId" | "updatedAt" | "containsSecrets">,
): Promise<void> {
  const serialized = `${JSON.stringify({
    schemaVersion: 1,
    testId: SBX050_TEST_ID,
    ...record,
    updatedAt: new Date().toISOString(),
    containsSecrets: false,
  } satisfies RecoveryJournalRecord)}\n`;
  await handle.truncate(0);
  await handle.write(serialized, 0, "utf8");
  await handle.sync();
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
  ) throw new Error(`${name} must be an exact lower-case public HTTPS origin`);
  return parsed;
}

export function explicitConfiguration(
  environment: NodeJS.ProcessEnv = process.env,
): Sbx050ExplicitConfiguration {
  if (environment.SBX050_SCOPE_CONFIRMATION !== SCOPE_CONFIRMATION) {
    throw new Error(`SBX050_SCOPE_CONFIRMATION must equal ${SCOPE_CONFIRMATION}`);
  }
  if (environment.SBX050_ALIAS_EMAIL_CONFIRMATION !== ALIAS_EMAIL ||
      environment.VERCEL_TEAM_ID !== TEAM_ID || environment.VERCEL_PROJECT_ID !== PROJECT_ID) {
    throw new Error("SBX-050 requires the exact eligible HackerOne-alias identity, team, and project");
  }
  if (environment.NODE_TLS_REJECT_UNAUTHORIZED === "0" ||
      (environment.NODE_OPTIONS !== undefined && environment.NODE_OPTIONS.trim() !== "") ||
      TRUST_ENVIRONMENT_NAMES.some((name) => environment[name] !== undefined)) {
    throw new Error("SBX-050 refuses controller TLS trust overrides or runtime injection");
  }
  const token = required(environment, "VERCEL_TOKEN");
  if (token.split(".").length === 3) {
    throw new Error("SBX-050 requires an opaque PAT so SDK OIDC refresh cannot add hidden requests");
  }
  const adminKey = required(environment, "SBX050_ADMIN_KEY");
  const actionKey = required(environment, "SBX050_ACTION_KEY");
  if (Buffer.byteLength(adminKey) < 32 || Buffer.byteLength(adminKey) > 256 ||
      Buffer.byteLength(actionKey) < 32 || Buffer.byteLength(actionKey) > 256 ||
      adminKey === actionKey || /[\0\r\n]/u.test(adminKey + actionKey)) {
    throw new Error("SBX-050 keys must be distinct 32-256 byte values without line breaks");
  }
  const aOrigin = exactOrigin(required(environment, "SBX050_A_PUBLIC_ORIGIN"), "SBX050_A_PUBLIC_ORIGIN");
  const pOrigin = exactOrigin(required(environment, "SBX050_P_PUBLIC_ORIGIN"), "SBX050_P_PUBLIC_ORIGIN");
  if (aOrigin.origin === pOrigin.origin || aOrigin.hostname === pOrigin.hostname) {
    throw new Error("SBX-050 A and P must be distinct researcher-controlled origins");
  }
  return {
    token,
    teamId: TEAM_ID,
    projectId: PROJECT_ID,
    adminKey,
    actionKey,
    aOrigin,
    pOrigin,
    manualAliasConfirmation: ALIAS_EMAIL,
  };
}

export function publicForwardPolicy(aHostname: string, pOrigin: URL, runId: string): NetworkPolicy {
  return {
    allow: {
      [aHostname]: [{
        match: {
          headers: [{
            key: { exact: SBX050_TRIGGER_HEADER },
            value: { exact: SBX050_PUBLIC_TRIGGER },
          }],
        },
        forwardURL: proxyAudience(pOrigin, runId),
      }],
    },
  };
}

export function transformAlonePolicy(
  aHostname: string,
  runId: string,
  credential: string,
  hiddenTrigger: string,
): NetworkPolicy {
  return {
    allow: {
      [aHostname]: [{
        match: { path: { exact: `/v1/sbx050/arm/${runId}` } },
        transform: [{ headers: {
          [SBX050_CREDENTIAL_HEADER]: credential,
          [SBX050_TRIGGER_HEADER]: hiddenTrigger,
        } }],
      }],
    },
  };
}

export function finalChainingPolicy(
  aHostname: string,
  pOrigin: URL,
  runId: string,
  credential: string,
  hiddenTrigger: string,
): NetworkPolicy {
  const transform = transformAlonePolicy(aHostname, runId, credential, hiddenTrigger);
  const allow = transform !== "allow-all" && transform !== "deny-all" && !Array.isArray(transform.allow)
    ? transform.allow?.[aHostname] : undefined;
  if (!allow) throw new Error("SBX-050 internal policy construction failed");
  return {
    allow: {
      [aHostname]: [
        ...allow,
        {
          match: {
            headers: [{
              key: { exact: SBX050_TRIGGER_HEADER },
              value: { exact: hiddenTrigger },
            }],
          },
          forwardURL: proxyAudience(pOrigin, runId),
        },
      ],
    },
  };
}

export async function updatePhasePolicy(sandbox: Sandbox, networkPolicy: NetworkPolicy): Promise<void> {
  const sessionId = sandbox.currentSession().sessionId;
  await sandbox.update({ networkPolicy }, { signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
  if (sandbox.currentSession().sessionId !== sessionId) {
    throw new Error("SBX-050 phase update changed the pinned session identity");
  }
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((entry, index) => entry === wanted[index]);
}

function exactMatcher(value: unknown, expected: string): boolean {
  const matcher = object(value);
  return matcher !== undefined && exactKeys(matcher, ["exact"]) && matcher.exact === expected;
}

function exactTopProjection(value: unknown, hostname: string): boolean {
  const root = object(value);
  return root !== undefined && exactKeys(root, ["allow"]) && Array.isArray(root.allow) &&
    root.allow.length === 1 && root.allow[0] === hostname;
}

function fullRules(value: unknown, hostname: string): unknown[] | undefined {
  const root = object(value);
  const allow = object(root?.allow);
  if (!root || !allow || !exactKeys(root, ["allow"]) || !exactKeys(allow, [hostname])) return;
  const rules = allow[hostname];
  return Array.isArray(rules) ? rules : undefined;
}

function secretOrRedacted(value: unknown, secret: string): boolean {
  return value === secret || value === PLATFORM_REDACTION;
}

function exactObservedTransformRule(
  value: unknown,
  runId: string,
  credential: string,
  hiddenTrigger: string,
  matcherMayBeOmitted = false,
): boolean {
  const rule = object(value);
  const match = object(rule?.match);
  const transform = Array.isArray(rule?.transform) ? rule.transform : undefined;
  const entry = transform?.length === 1 ? object(transform[0]) : undefined;
  const headers = object(entry?.headers);
  const matcherExact = match !== undefined && exactKeys(match, ["path"]) &&
    exactMatcher(match.path, `/v1/sbx050/arm/${runId}`);
  return rule !== undefined &&
    (exactKeys(rule, ["match", "transform"]) || (matcherMayBeOmitted && exactKeys(rule, ["transform"]))) &&
    (matcherExact || (matcherMayBeOmitted && match === undefined)) &&
    entry !== undefined && exactKeys(entry, ["headers"]) && headers !== undefined &&
    exactKeys(headers, [SBX050_CREDENTIAL_HEADER, SBX050_TRIGGER_HEADER]) &&
    secretOrRedacted(headers[SBX050_CREDENTIAL_HEADER], credential) &&
    secretOrRedacted(headers[SBX050_TRIGGER_HEADER], hiddenTrigger);
}

function exactObservedForwardRule(
  value: unknown,
  audience: string,
  trigger: string,
  matcherMayBeOmitted = false,
): boolean {
  const rule = object(value);
  const match = object(rule?.match);
  const headers = match?.headers;
  const entry = Array.isArray(headers) && headers.length === 1 ? object(headers[0]) : undefined;
  const matcherExact = match !== undefined && exactKeys(match, ["headers"]) &&
    entry !== undefined && exactKeys(entry, ["key", "value"]) &&
    exactMatcher(entry.key, SBX050_TRIGGER_HEADER) &&
    exactMatcher(entry.value, trigger);
  return rule !== undefined &&
    (exactKeys(rule, ["forwardURL", "match"]) || (matcherMayBeOmitted && exactKeys(rule, ["forwardURL"]))) &&
    rule.forwardURL === audience && (matcherExact || (matcherMayBeOmitted && match === undefined));
}

export function exactObservedPhasePolicy(
  stage: ExactPhase,
  value: unknown,
  aHostname: string,
  pOrigin: URL,
  runId: string,
  credential: string,
  hiddenTrigger: string,
): boolean {
  const rules = fullRules(value, aHostname);
  if (!rules) return false;
  if (stage === "public-forward") {
    return rules.length === 1 && exactObservedForwardRule(
      rules[0], proxyAudience(pOrigin, runId), SBX050_PUBLIC_TRIGGER, true,
    );
  }
  if (stage === "transform-alone") {
    return rules.length === 1 && exactObservedTransformRule(
      rules[0], runId, credential, hiddenTrigger, true,
    );
  }
  return rules.length === 2 && exactObservedTransformRule(rules[0], runId, credential, hiddenTrigger) &&
    exactObservedForwardRule(rules[1], proxyAudience(pOrigin, runId), hiddenTrigger);
}

function exactConfiguredTransformRule(
  value: unknown,
  runId: string,
  credential: string,
  hiddenTrigger: string,
): boolean {
  if (!exactObservedTransformRule(value, runId, credential, hiddenTrigger)) return false;
  const rule = object(value);
  const transform = Array.isArray(rule?.transform) ? object(rule.transform[0]) : undefined;
  const headers = object(transform?.headers);
  return headers?.[SBX050_CREDENTIAL_HEADER] === credential &&
    headers[SBX050_TRIGGER_HEADER] === hiddenTrigger;
}

function exactConfiguredPhasePolicy(
  stage: ExactPhase,
  value: unknown,
  aHostname: string,
  pOrigin: URL,
  runId: string,
  credential: string,
  hiddenTrigger: string,
): boolean {
  const rules = fullRules(value, aHostname);
  if (!rules) return false;
  if (stage === "public-forward") {
    return rules.length === 1 && exactObservedForwardRule(
      rules[0], proxyAudience(pOrigin, runId), SBX050_PUBLIC_TRIGGER,
    );
  }
  if (stage === "transform-alone") {
    return rules.length === 1 && exactConfiguredTransformRule(
      rules[0], runId, credential, hiddenTrigger,
    );
  }
  return rules.length === 2 &&
    exactConfiguredTransformRule(rules[0], runId, credential, hiddenTrigger) &&
    exactObservedForwardRule(rules[1], proxyAudience(pOrigin, runId), hiddenTrigger);
}

export function exactMatcherlessRedactedFinalPolicy(
  value: unknown,
  aHostname: string,
  pOrigin: URL,
  runId: string,
): boolean {
  const rules = fullRules(value, aHostname);
  const transformRule = object(rules?.[0]);
  const transform = Array.isArray(transformRule?.transform) && transformRule.transform.length === 1
    ? object(transformRule.transform[0]) : undefined;
  const headers = object(transform?.headers);
  const forwardRule = object(rules?.[1]);
  return rules?.length === 2 && transformRule !== undefined && transform !== undefined &&
    headers !== undefined && forwardRule !== undefined &&
    exactKeys(transformRule, ["transform"]) && exactKeys(transform, ["headers"]) &&
    exactKeys(headers, [SBX050_CREDENTIAL_HEADER, SBX050_TRIGGER_HEADER]) &&
    headers[SBX050_CREDENTIAL_HEADER] === PLATFORM_REDACTION &&
    headers[SBX050_TRIGGER_HEADER] === PLATFORM_REDACTION &&
    exactKeys(forwardRule, ["forwardURL"]) &&
    forwardRule.forwardURL === proxyAudience(pOrigin, runId);
}

export function classifyPolicyReadback(
  stage: ExactPhase,
  value: unknown,
  aHostname: string,
  pOrigin: URL,
  runId: string,
  credential: string,
  hiddenTrigger: string,
): Sbx050PolicyReadbackCode {
  if (exactTopProjection(value, aHostname)) return "exact-top-host-list";
  if (stage === "final-before") {
    if (exactObservedPhasePolicy(
      stage, value, aHostname, pOrigin, runId, credential, hiddenTrigger,
    )) return "exact-final-matchers";
    if (exactMatcherlessRedactedFinalPolicy(value, aHostname, pOrigin, runId)) {
      return "exact-final-matcherless-redacted";
    }
    return "unexpected";
  }
  if (exactObservedPhasePolicy(
    stage, value, aHostname, pOrigin, runId, credential, hiddenTrigger,
  )) return stage === "public-forward" ? "exact-public-forward" : "exact-transform-alone";
  return "unexpected";
}

export interface Sbx050PolicyReadbackObservation {
  stage: Sbx050PolicyStage;
  initialSessionId: string;
  expectedIdentity: Sbx050ExpectedIdentity;
  configuredPolicy: unknown;
  activeSandboxName: string;
  activeSandboxPolicy: unknown;
  activeSessionId: string;
  activeSessionPolicy: unknown;
  independentSandboxName: string;
  independentSandboxPolicy: unknown;
  independentSessionId: string;
  independentSessionPolicy: unknown;
  aHostname: string;
  pOrigin: URL;
  runId: string;
  credential: string;
  hiddenTrigger: string;
}

export function diagnosePolicyReadbacks(
  observation: Sbx050PolicyReadbackObservation,
): Sbx050PolicyReadbackDiagnostic {
  const normalizedStage: ExactPhase = observation.stage === "final-after" ? "final-before" : observation.stage;
  const classify = (value: unknown): Sbx050PolicyReadbackCode => classifyPolicyReadback(
    normalizedStage,
    value,
    observation.aHostname,
    observation.pOrigin,
    observation.runId,
    observation.credential,
    observation.hiddenTrigger,
  );
  const configuredPolicy: Sbx050PolicyReadbackCode = exactConfiguredPhasePolicy(
    normalizedStage,
    observation.configuredPolicy,
    observation.aHostname,
    observation.pOrigin,
    observation.runId,
    observation.credential,
    observation.hiddenTrigger,
  ) ? normalizedStage === "public-forward"
      ? "exact-public-forward"
      : normalizedStage === "transform-alone"
        ? "exact-transform-alone"
        : "exact-final-matchers"
    : "unexpected";
  const activeSandboxPolicy = classify(observation.activeSandboxPolicy);
  const activeSessionPolicy = classify(observation.activeSessionPolicy);
  const independentSandboxPolicy = classify(observation.independentSandboxPolicy);
  const independentSessionPolicy = classify(observation.independentSessionPolicy);
  const expectedIdentityExact = observation.expectedIdentity.aliasEmail === ALIAS_EMAIL &&
    observation.expectedIdentity.aliasIdentityVerified && observation.expectedIdentity.teamId === TEAM_ID &&
    observation.expectedIdentity.projectId === PROJECT_ID &&
    observation.expectedIdentity.sandboxName === observation.activeSandboxName &&
    observation.expectedIdentity.sessionId === observation.initialSessionId &&
    SBX050_SESSION_ID.test(observation.initialSessionId);
  const activeIdentity = expectedIdentityExact && observation.activeSessionId === observation.initialSessionId
    ? "exact" as const : "unexpected" as const;
  const independentIdentity = expectedIdentityExact &&
    observation.independentSandboxName === observation.expectedIdentity.sandboxName &&
    observation.independentSessionId === observation.initialSessionId
    ? "exact" as const : "unexpected" as const;
  let projectionMode: Sbx050PolicyReadbackDiagnostic["projectionMode"] = "not-final";
  if (normalizedStage === "final-before") {
    projectionMode = activeSessionPolicy === "exact-final-matchers" &&
      independentSessionPolicy === "exact-final-matchers"
      ? "exact-matchers"
      : activeSessionPolicy === "exact-final-matcherless-redacted" &&
          independentSessionPolicy === "exact-final-matcherless-redacted"
        ? "matcherless-redacted"
        : "undetermined";
  }
  const expectedStageCode: Sbx050PolicyReadbackCode = normalizedStage === "public-forward"
    ? "exact-public-forward"
    : normalizedStage === "transform-alone"
      ? "exact-transform-alone"
      : "exact-final-matchers";
  const nonFinalReadbacksExact = (activeSandboxPolicy === "exact-top-host-list" ||
      activeSandboxPolicy === expectedStageCode) && activeSessionPolicy === expectedStageCode &&
    (independentSandboxPolicy === "exact-top-host-list" || independentSandboxPolicy === expectedStageCode) &&
    independentSessionPolicy === expectedStageCode;
  const finalReadbacksExact = activeSandboxPolicy === "exact-top-host-list" &&
    independentSandboxPolicy === "exact-top-host-list" && projectionMode !== "undetermined";
  return {
    stage: observation.stage,
    configuredPolicy,
    activeSandboxPolicy,
    activeSessionPolicy,
    independentSandboxPolicy,
    independentSessionPolicy,
    activeIdentity,
    independentIdentity,
    projectionMode,
    continuationAllowed: configuredPolicy === expectedStageCode && activeIdentity === "exact" &&
      independentIdentity === "exact" && (normalizedStage === "final-before"
        ? finalReadbacksExact : nonFinalReadbacksExact),
    containsSecrets: false,
  };
}

export function missingPolicyReadbackDiagnostic(
  stage: Sbx050PolicyStage,
): Sbx050PolicyReadbackDiagnostic {
  return {
    stage,
    configuredPolicy: "not-observed",
    activeSandboxPolicy: "not-observed",
    activeSessionPolicy: "not-observed",
    independentSandboxPolicy: "not-observed",
    independentSessionPolicy: "not-observed",
    activeIdentity: "not-observed",
    independentIdentity: "not-observed",
    projectionMode: "undetermined",
    continuationAllowed: false,
    containsSecrets: false,
  };
}

export function sanitizeObservedPolicy(
  stage: ExactPhase,
  value: unknown,
  aHostname: string,
  credential: string,
  hiddenTrigger: string,
): unknown {
  const clone = structuredClone(value);
  const rules = fullRules(clone, aHostname);
  if (!rules) return clone;
  for (const [index, rawRule] of rules.entries()) {
    const rule = object(rawRule);
    if (!rule) continue;
    const transforms = Array.isArray(rule.transform) ? rule.transform : [];
    for (const rawTransform of transforms) {
      const headers = object(object(rawTransform)?.headers);
      if (!headers) continue;
      if (headers[SBX050_CREDENTIAL_HEADER] === credential ||
          headers[SBX050_CREDENTIAL_HEADER] === PLATFORM_REDACTION) {
        headers[SBX050_CREDENTIAL_HEADER] = SBX050_REDACTED_VALUE;
      }
      if (headers[SBX050_TRIGGER_HEADER] === hiddenTrigger ||
          headers[SBX050_TRIGGER_HEADER] === PLATFORM_REDACTION) {
        headers[SBX050_TRIGGER_HEADER] = SBX050_REDACTED_VALUE;
      }
    }
    if (stage === "final-before" && index === 1) {
      const match = object(rule.match);
      const header = Array.isArray(match?.headers) ? object(match.headers[0]) : undefined;
      const matcher = object(header?.value);
      if (matcher && (matcher.exact === hiddenTrigger || matcher.exact === PLATFORM_REDACTION)) {
        matcher.exact = SBX050_TRIGGER_MARKER;
      }
    }
  }
  return clone;
}

function safeError(error: unknown, secrets: readonly string[]): string {
  let message = error instanceof Error ? error.message : String(error);
  for (const secret of secrets) if (secret) message = message.split(secret).join("[REDACTED]");
  return message.replace(/[\0\r\n]/gu, " ").slice(0, 1_000);
}

async function nextInstant(after: string): Promise<string> {
  const threshold = Date.parse(after);
  while (Date.now() <= threshold) await delay(1);
  return new Date().toISOString();
}

function isNotFound(error: unknown): boolean {
  return error instanceof APIError && (error.response.status === 404 || error.response.status === 410);
}

async function boundedJson(response: Response, maximum = 128 * 1024): Promise<unknown> {
  const bytes = Buffer.from(await response.arrayBuffer());
  try {
    if (bytes.byteLength > maximum) throw new Error("SBX-050 response exceeded its fixed byte limit");
    return bytes.byteLength === 0 ? undefined : JSON.parse(bytes.toString("utf8"));
  } finally {
    bytes.fill(0);
  }
}

async function adminRequest(
  config: Sbx050ExplicitConfiguration,
  runId: string,
  init: RequestInit = {},
): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set("authorization", `Bearer ${config.adminKey}`);
  if (init.body !== undefined) headers.set("content-type", "application/json");
  return fetch(new URL(`/v1/sbx050/admin/runs/${encodeURIComponent(runId)}`, config.aOrigin), {
    ...init,
    headers,
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
}

function string(value: unknown, maximum = 4_096): string | undefined {
  return typeof value === "string" && value.length <= maximum ? value : undefined;
}

function number(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function parseLedgerEvent(value: unknown): Sbx050LedgerEvent {
  const event = object(value);
  const requiredKeys = [
    "canaryMatched", "caseId", "credentialHeaderCount", "credentialMatched", "oidcAudienceMatched",
    "oidcHeaderCount", "oidcIndependentRs256Verified", "oidcOfficialVerified", "oidcSourceMatched",
    "oidcIssuerVerified", "oidcTemporalVerified", "observedAt", "operationId", "ordinal",
    "originalRequestMatched", "role", "triggerHeaderCount", "triggerMatched",
  ];
  const optionalKeys = [
    "oidcIssuer", "oidcAudience", "oidcTeamId", "oidcProjectId", "oidcSessionId", "oidcSandboxName",
  ];
  if (!event || requiredKeys.some((key) => !(key in event)) ||
      Object.keys(event).some((key) => !requiredKeys.includes(key) && !optionalKeys.includes(key)) ||
      !SBX050_EVENT_CASES.includes(event.caseId as Sbx050EventCaseId) ||
      (event.role !== "A" && event.role !== "P") || event.canaryMatched !== true ||
      event.originalRequestMatched !== true || typeof event.credentialMatched !== "boolean" ||
      typeof event.triggerMatched !== "boolean" || typeof event.oidcOfficialVerified !== "boolean" ||
      typeof event.oidcIndependentRs256Verified !== "boolean" || typeof event.oidcAudienceMatched !== "boolean" ||
      typeof event.oidcSourceMatched !== "boolean" || typeof event.oidcIssuerVerified !== "boolean" ||
      typeof event.oidcTemporalVerified !== "boolean" || !Number.isInteger(event.ordinal) ||
      !Number.isInteger(event.credentialHeaderCount) || !Number.isInteger(event.triggerHeaderCount) ||
      !Number.isInteger(event.oidcHeaderCount) || typeof event.observedAt !== "string" ||
      typeof event.operationId !== "string" || optionalKeys.some((key) => key in event && typeof event[key] !== "string")) {
    throw new Error("SBX-050 ledger event shape was invalid");
  }
  return event as unknown as Sbx050LedgerEvent;
}

async function ledgerSnapshot(
  config: Sbx050ExplicitConfiguration,
  runId: string,
): Promise<Sbx050LedgerEvidence> {
  const response = await adminRequest(config, runId);
  if (response.status !== 200) throw new Error(`SBX-050 ledger readback returned ${response.status}`);
  const root = object(await boundedJson(response));
  if (!root || !exactKeys(root, [
    "configured", "configuredAt", "credentialDigestRetained", "emptyReadAt", "events", "hiddenTriggerDigestRetained",
    "rawCredentialRetained", "rawHiddenTriggerRetained", "rawOidcTokenRetained", "oidcTokenDigestRetained",
    "receiverNodeOptionsPresent", "receiverRuntimeTrustEnvironmentNames", "receiverRuntimeTrustExact",
    "receiverTlsVerificationDisabled",
    "unattributedRequests", "unexpectedARequests", "unexpectedPRequests",
  ]) || root.configured !== true || typeof root.configuredAt !== "string" || typeof root.emptyReadAt !== "string" ||
      !Array.isArray(root.events) || root.rawCredentialRetained !== false ||
      root.credentialDigestRetained !== false || root.rawHiddenTriggerRetained !== false ||
      root.hiddenTriggerDigestRetained !== false || root.rawOidcTokenRetained !== false ||
      root.oidcTokenDigestRetained !== false || root.receiverRuntimeTrustExact !== true ||
      !Array.isArray(root.receiverRuntimeTrustEnvironmentNames) || root.receiverRuntimeTrustEnvironmentNames.length !== 0 ||
      root.receiverNodeOptionsPresent !== false || root.receiverTlsVerificationDisabled !== false ||
      !Number.isInteger(root.unexpectedARequests) ||
      !Number.isInteger(root.unexpectedPRequests) || !Number.isInteger(root.unattributedRequests)) {
    throw new Error("SBX-050 ledger readback shape was invalid");
  }
  return {
    configured: true,
    configuredAt: root.configuredAt,
    emptyReadAt: root.emptyReadAt,
    events: root.events.map(parseLedgerEvent),
    unexpectedARequests: root.unexpectedARequests as number,
    unexpectedPRequests: root.unexpectedPRequests as number,
    unattributedRequests: root.unattributedRequests as number,
    rawCredentialRetained: false,
    credentialDigestRetained: false,
    rawHiddenTriggerRetained: false,
    hiddenTriggerDigestRetained: false,
    rawOidcTokenRetained: false,
    oidcTokenDigestRetained: false,
    receiverRuntimeTrustExact: true,
    receiverRuntimeTrustEnvironmentNames: [],
    receiverNodeOptionsPresent: false,
    receiverTlsVerificationDisabled: false,
  };
}

async function health(origin: URL, role: "A" | "P"): Promise<boolean> {
  const response = await fetch(new URL("/healthz", origin), {
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  const payload = object(await boundedJson(response, 4_096));
  return response.status === 200 && payload?.ok === true && payload.role === role;
}

async function policyProof(
  stage: Sbx050PolicyStage,
  sandbox: Sandbox,
  initialSessionId: string,
  config: Sbx050ExplicitConfiguration,
  runId: string,
  credential: string,
  hiddenTrigger: string,
  expectedIdentity: Sbx050ExpectedIdentity,
  exactConfiguredPolicy: NetworkPolicy,
  persistDiagnostic: (diagnostic: Sbx050PolicyReadbackDiagnostic) => Promise<void>,
): Promise<PhasePolicyProof> {
  const normalizedStage: ExactPhase = stage === "final-after" ? "final-before" : stage;
  const startedAt = new Date().toISOString();
  await persistDiagnostic(missingPolicyReadbackDiagnostic(stage));
  const activeSession = sandbox.currentSession();
  const activeOnly = diagnosePolicyReadbacks({
    stage,
    initialSessionId,
    expectedIdentity,
    configuredPolicy: exactConfiguredPolicy,
    activeSandboxName: sandbox.name,
    activeSandboxPolicy: sandbox.networkPolicy,
    activeSessionId: activeSession.sessionId,
    activeSessionPolicy: activeSession.networkPolicy,
    independentSandboxName: sandbox.name,
    independentSandboxPolicy: sandbox.networkPolicy,
    independentSessionId: activeSession.sessionId,
    independentSessionPolicy: activeSession.networkPolicy,
    aHostname: config.aOrigin.hostname,
    pOrigin: config.pOrigin,
    runId,
    credential,
    hiddenTrigger,
  });
  await persistDiagnostic({
    ...activeOnly,
    independentSandboxPolicy: "not-observed",
    independentSessionPolicy: "not-observed",
    independentIdentity: "not-observed",
    projectionMode: normalizedStage === "final-before" ? "undetermined" : "not-final",
    continuationAllowed: false,
  });
  const independent = await Sandbox.get({
    token: config.token,
    teamId: config.teamId,
    projectId: config.projectId,
    name: sandbox.name,
    resume: false,
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  });
  const independentSession = independent.currentSession();
  const diagnostic = diagnosePolicyReadbacks({
    stage,
    initialSessionId,
    expectedIdentity,
    configuredPolicy: exactConfiguredPolicy,
    activeSandboxName: sandbox.name,
    activeSandboxPolicy: sandbox.networkPolicy,
    activeSessionId: activeSession.sessionId,
    activeSessionPolicy: activeSession.networkPolicy,
    independentSandboxName: independent.name,
    independentSandboxPolicy: independent.networkPolicy,
    independentSessionId: independentSession.sessionId,
    independentSessionPolicy: independentSession.networkPolicy,
    aHostname: config.aOrigin.hostname,
    pOrigin: config.pOrigin,
    runId,
    credential,
    hiddenTrigger,
  });
  await persistDiagnostic(diagnostic);
  if (!diagnostic.continuationAllowed) {
    throw new Error(`${stage} policy readbacks were outside the closed accepted projections`);
  }
  const projectionMode: Sbx050PolicyProjectionMode = normalizedStage !== "final-before"
    ? "not-final"
    : diagnostic.projectionMode === "exact-matchers" ? "exact-matchers" : "matcherless-redacted";
  const finalHiddenMatcherComparedExactlyBeforeSanitization = projectionMode === "exact-matchers";
  const retained = {
    activeSandboxPolicy: sanitizeObservedPolicy(
      normalizedStage, sandbox.networkPolicy, config.aOrigin.hostname, credential, hiddenTrigger,
    ),
    activeSessionPolicy: sanitizeObservedPolicy(
      normalizedStage, activeSession.networkPolicy, config.aOrigin.hostname, credential, hiddenTrigger,
    ),
    independentSandboxPolicy: sanitizeObservedPolicy(
      normalizedStage, independent.networkPolicy, config.aOrigin.hostname, credential, hiddenTrigger,
    ),
    independentSessionPolicy: sanitizeObservedPolicy(
      normalizedStage, independentSession.networkPolicy, config.aOrigin.hostname, credential, hiddenTrigger,
    ),
  };
  const serializedRetained = JSON.stringify(retained);
  const serializedObserved = JSON.stringify([
    sandbox.networkPolicy, activeSession.networkPolicy, independent.networkPolicy, independentSession.networkPolicy,
  ]);
  const completedAt = await nextInstant(startedAt);
  return {
    stage,
    startedAt,
    completedAt,
    initialSessionId,
    activeSessionId: activeSession.sessionId,
    independentSessionId: independentSession.sessionId,
    ...retained,
    rawCredentialPresentInReadbacks: serializedRetained.includes(credential),
    hiddenTriggerPresentInRetainedReadbacks: serializedRetained.includes(hiddenTrigger),
    platformRedactionMarkerPresent: serializedRetained.includes(SBX050_REDACTED_VALUE),
    finalHiddenMatcherComparedExactlyBeforeSanitization,
    finalHiddenMatcherMarkerPresent: normalizedStage === "final-before" &&
      serializedRetained.includes(SBX050_TRIGGER_MARKER),
    projectionMode,
    readbackDiagnostic: diagnostic,
    identity: expectedIdentity,
    inMemoryReadbackExact: true,
    serverRedactionObserved: serializedObserved.includes(PLATFORM_REDACTION),
  };
}

function emptyProbe(
  runId: string,
  caseId: Sbx050CaseId,
  canary: string,
  hostname: string,
): Sbx050ProbeEvidence {
  return {
    schemaVersion: -1,
    testId: "missing",
    runId,
    caseId,
    correlationCanary: canary,
    commandExitCode: -1,
    startedAt: "missing",
    completedAt: "missing",
    ok: false,
    phase: "missing",
    requestHostname: hostname,
    requestServername: hostname,
    requestPath: "missing",
    sentCredentialHeader: false,
    sentHiddenTriggerHeader: false,
    sentPublicTriggerHeader: false,
    connectionAttempts: 0,
    actualConnections: 0,
    actualRequests: 0,
    retries: 0,
    redirectsFollowed: 0,
    rejectUnauthorized: true,
    controllerConfigurableCustomTrustAccepted: false,
    inheritedPlatformTrustEnvironmentNames: [],
    tcpConnected: false,
    tlsEstablished: false,
    tlsAuthorized: false,
    responseReceived: false,
    responseShapeValid: false,
    responseBodyRetained: false,
    timedOut: false,
    durationMs: -1,
    controllerIdentity: {
      aliasEmail: "missing",
      aliasIdentityVerified: false,
      teamId: "missing",
      projectId: "missing",
      sandboxName: "missing",
      sessionId: "missing",
    },
  };
}

export function sanitizeProbe(
  value: unknown,
  commandExitCode: number,
  startedAt: string,
  completedAt: string,
  controllerIdentity: Sbx050ExpectedIdentity,
): Sbx050ProbeEvidence {
  const root = object(value) ?? {};
  const trustNames = Array.isArray(root.inheritedPlatformTrustEnvironmentNames)
    ? root.inheritedPlatformTrustEnvironmentNames.filter((entry): entry is string => typeof entry === "string")
    : [];
  return {
    schemaVersion: number(root.schemaVersion) ?? -1,
    testId: string(root.testId, 64) ?? "missing",
    runId: string(root.runId, 128) ?? "missing",
    caseId: string(root.caseId, 64) ?? "missing",
    correlationCanary: string(root.correlationCanary, 128) ?? "missing",
    commandExitCode,
    startedAt,
    completedAt,
    ok: root.ok === true,
    phase: string(root.phase, 64) ?? "missing",
    requestHostname: string(root.requestHostname, 256) ?? "missing",
    requestServername: string(root.requestServername, 256) ?? "missing",
    requestPath: string(root.requestPath, 4_096) ?? "missing",
    sentCredentialHeader: root.sentCredentialHeader === true,
    sentHiddenTriggerHeader: root.sentHiddenTriggerHeader === true,
    sentPublicTriggerHeader: root.sentPublicTriggerHeader === true,
    connectionAttempts: number(root.connectionAttempts) ?? -1,
    actualConnections: number(root.actualConnections) ?? -1,
    actualRequests: number(root.actualRequests) ?? -1,
    retries: number(root.retries) ?? -1,
    redirectsFollowed: number(root.redirectsFollowed) ?? -1,
    rejectUnauthorized: root.rejectUnauthorized === true,
    controllerConfigurableCustomTrustAccepted: root.controllerConfigurableCustomTrustAccepted === true,
    inheritedPlatformTrustEnvironmentNames: trustNames,
    tcpConnected: root.tcpConnected === true,
    tlsEstablished: root.tlsEstablished === true,
    tlsAuthorized: root.tlsAuthorized === true,
    responseReceived: root.responseReceived === true,
    ...(number(root.responseStatusCode) !== undefined ? { responseStatusCode: number(root.responseStatusCode)! } : {}),
    responseShapeValid: root.responseShapeValid === true,
    ...(root.responseRole === "A" || root.responseRole === "P" ? { responseRole: root.responseRole } : {}),
    ...(typeof root.responseCredentialMatched === "boolean"
      ? { responseCredentialMatched: root.responseCredentialMatched } : {}),
    ...(typeof root.responseTriggerMatched === "boolean"
      ? { responseTriggerMatched: root.responseTriggerMatched } : {}),
    ...(typeof root.responseOidcVerified === "boolean"
      ? { responseOidcVerified: root.responseOidcVerified } : {}),
    ...(string(root.responseOperationId, 128)
      ? { responseOperationId: string(root.responseOperationId, 128)! } : {}),
    responseBodyRetained: root.responseBodyRetained === true,
    timedOut: root.timedOut === true,
    durationMs: number(root.durationMs) ?? -1,
    ...(string(root.errorCode, 64) ? { errorCode: string(root.errorCode, 64)! } : {}),
    ...(string(root.errorSyscall, 64) ? { errorSyscall: string(root.errorSyscall, 64)! } : {}),
    ...(number(root.errorErrno) !== undefined ? { errorErrno: number(root.errorErrno)! } : {}),
    ...(root.errorClass === "dns-resolution" || root.errorClass === "connection-reset" ||
      root.errorClass === "route-unreachable" ? { errorClass: root.errorClass } : {}),
    controllerIdentity,
  };
}

export function fixedGuestConfiguration(
  runId: string,
  caseId: Sbx050CaseId,
  canary: string,
  aOrigin: URL,
  pOrigin: URL,
): Record<string, unknown> {
  const directP = caseId === "direct-p-pre" || caseId === "direct-p-post";
  return {
    scopeConfirmation: "researcher-controlled-sbx050-origins-only",
    testId: SBX050_TEST_ID,
    runId,
    caseId,
    correlationCanary: canary,
    targetOrigin: directP ? pOrigin.origin : aOrigin.origin,
    requestPath: requestPath(runId, caseId, canary),
    sendPublicTrigger: caseId === "public-forward-control",
    timeoutMs: directP ? 3_000 : 10_000,
  };
}

async function runGuest(
  sandbox: Sandbox,
  runId: string,
  caseId: Sbx050CaseId,
  canary: string,
  config: Sbx050ExplicitConfiguration,
  secrets: readonly string[],
  controllerIdentity: Sbx050ExpectedIdentity,
): Promise<{ probe: Sbx050ProbeEvidence; command: CommandRecord }> {
  const session = sandbox.currentSession();
  if (session.sessionId !== controllerIdentity.sessionId) {
    throw new Error(`${caseId} was not bound to the pinned SBX-050 session`);
  }
  const configuration = fixedGuestConfiguration(runId, caseId, canary, config.aOrigin, config.pOrigin);
  const serialized = JSON.stringify(configuration);
  if (secrets.some((secret) => serialized.includes(secret))) {
    throw new Error(`${caseId} guest configuration contained controller-only material`);
  }
  const startedAt = new Date().toISOString();
  const command = await session.runCommand({
    cmd: "node",
    args: [REMOTE_GUEST_PATH, Buffer.from(serialized).toString("base64url")],
    timeoutMs: COMMAND_TIMEOUT_MS,
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  });
  const [stdout, stderr] = await Promise.all([
    command.stdout({ signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) }),
    command.stderr({ signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) }),
  ]);
  const completedAt = await nextInstant(startedAt);
  if (sandbox.currentSession().sessionId !== controllerIdentity.sessionId) {
    throw new Error(`${caseId} session identity changed during the guest command`);
  }
  if (Buffer.byteLength(stdout) > MAX_STDOUT_BYTES || Buffer.byteLength(stderr) > MAX_STDERR_BYTES) {
    throw new Error(`${caseId} guest output exceeded fixed bounds`);
  }
  if (secrets.some((secret) => stdout.includes(secret) || stderr.includes(secret))) {
    throw new Error(`${caseId} guest output contained controller-only material`);
  }
  let raw: unknown;
  try { raw = JSON.parse(stdout.trimEnd()); }
  catch { throw new Error(`${caseId} guest output was not one JSON object`); }
  return {
    probe: sanitizeProbe(raw, command.exitCode, startedAt, completedAt, controllerIdentity),
    command: {
      caseId,
      commandId: command.cmdId,
      exitCode: command.exitCode,
      startedAt,
      completedAt,
      stdoutBytes: Buffer.byteLength(stdout),
      stderrBytes: Buffer.byteLength(stderr),
    },
  };
}

function exactEarlyResponse(
  probe: Sbx050ProbeEvidence,
  input: { runId: string; caseId: Sbx050EventCaseId; canary: string; hostname: string; role: "A" | "P";
    credential: boolean; trigger: boolean; oidc: boolean; operationId: string },
): boolean {
  return probe.schemaVersion === 1 && probe.testId === SBX050_TEST_ID && probe.runId === input.runId &&
    probe.caseId === input.caseId && probe.correlationCanary === input.canary &&
    probe.commandExitCode === 0 && probe.ok && probe.phase === "response" &&
    probe.requestHostname === input.hostname && probe.requestServername === input.hostname &&
    probe.responseStatusCode === 200 && probe.responseShapeValid && probe.responseRole === input.role &&
    probe.responseCredentialMatched === input.credential && probe.responseTriggerMatched === input.trigger &&
    probe.responseOidcVerified === input.oidc && probe.responseOperationId === input.operationId &&
    !probe.sentCredentialHeader && !probe.sentHiddenTriggerHeader &&
    probe.sentPublicTriggerHeader === (input.caseId === "public-forward-control") &&
    probe.connectionAttempts === 1 && probe.actualConnections === 1 && probe.actualRequests === 1 &&
    probe.retries === 0 && probe.redirectsFollowed === 0 && probe.rejectUnauthorized &&
    !probe.controllerConfigurableCustomTrustAccepted && probe.tlsAuthorized && probe.responseReceived &&
    !probe.responseBodyRetained && !probe.timedOut;
}

export interface Sbx050CleanupDependencies {
  getSandbox?: (params: {
    token: string;
    teamId: string;
    projectId: string;
    name: string;
    resume: false;
    signal: AbortSignal;
  }) => Promise<Sandbox>;
  wait?: (milliseconds: number) => Promise<void>;
  discoveryDelaysMs?: readonly number[];
  absenceDelaysMs?: readonly number[];
}

export function exactSbx050OwnedSessionId(
  candidate: Sandbox,
  expectedName: string,
  expectedTags: Record<string, string>,
): string | undefined {
  try {
    const sessionId = candidate.currentSession().sessionId;
    if (
      candidate.name !== expectedName || candidate.persistent !== false ||
      candidate.tags?.harness !== expectedTags.harness ||
      candidate.tags?.test !== expectedTags.test || candidate.tags?.run !== expectedTags.run ||
      expectedTags.harness !== "vsc" || expectedTags.test !== SBX050_TEST_ID ||
      typeof sessionId !== "string" || !SBX050_SESSION_ID.test(sessionId)
    ) return undefined;
    return sessionId;
  } catch {
    return undefined;
  }
}

export async function cleanupSandbox(
  sandbox: Sandbox | undefined,
  sandboxName: string,
  createAttempted: boolean,
  createProvenanceValidated: boolean,
  credentials: Pick<Sbx050ExplicitConfiguration, "token" | "teamId" | "projectId">,
  tags: Record<string, string>,
  secrets: readonly string[],
  dependencies: Sbx050CleanupDependencies = {},
): Promise<Sbx050CleanupEvidence["sandbox"]> {
  const cleanup = { stopped: false, deleted: false, absenceChecks: 0, errors: [] as string[] };
  if (!createAttempted) return { stopped: true, deleted: true, absenceChecks: 2, errors: [] };
  if (createProvenanceValidated && !sandbox) {
    cleanup.errors.push("create provenance was marked valid without a sandbox handle");
    return cleanup;
  }
  const getSandbox = dependencies.getSandbox ?? (async (params) => await Sandbox.get(params));
  const wait = dependencies.wait ?? (async (milliseconds) => await delay(milliseconds));
  const discoveryDelays = dependencies.discoveryDelaysMs ?? RECOVERY_DISCOVERY_DELAYS_MS;
  const absenceDelays = dependencies.absenceDelaysMs ?? POST_DELETE_ABSENCE_DELAYS_MS;
  const createResponseUncertain = !createProvenanceValidated;
  const exactOwned = (candidate: Sandbox): boolean =>
    exactSbx050OwnedSessionId(candidate, sandboxName, tags) !== undefined;
  const get = async (): Promise<Sandbox> => await getSandbox({
    ...credentials,
    name: sandboxName,
    resume: false,
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  });
  let handle = sandbox;
  if (handle && !exactOwned(handle)) {
    cleanup.errors.push("cleanup handle did not have the exact run name and tags; left untouched");
    return cleanup;
  }
  if (!handle) {
    for (const waitMs of discoveryDelays) {
      if (waitMs > 0) await wait(waitMs);
      try {
        const recovered = await get();
        if (!exactOwned(recovered)) {
          cleanup.errors.push("orphan recovery found a sandbox without exact run tags; left untouched");
          return cleanup;
        }
        handle = recovered;
        break;
      } catch (error) {
        if (isNotFound(error)) cleanup.absenceChecks += 1;
        else cleanup.errors.push(`orphan recovery: ${safeError(error, secrets)}`);
      }
    }
    if (!handle) {
      if (cleanup.errors.length === 0 && cleanup.absenceChecks === discoveryDelays.length) {
        cleanup.errors.push(
          "sandbox create returned no provenance-validated handle; bounded absence checks cannot exclude a late create",
        );
      } else if (cleanup.errors.length === 0) {
        cleanup.errors.push("late-create recovery did not reach the required delayed absence count");
      }
      return cleanup;
    }
  }

  cleanup.absenceChecks = 0;
  try { await handle.stop({ signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) }); cleanup.stopped = true; }
  catch (error) { if (isNotFound(error)) cleanup.stopped = true; else cleanup.errors.push(`stop: ${safeError(error, secrets)}`); }
  try {
    await handle.delete({ signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
    cleanup.deleted = true;
    cleanup.stopped = true;
  } catch (error) {
    if (isNotFound(error)) {
      cleanup.deleted = true;
      cleanup.stopped = true;
    } else cleanup.errors.push(`delete: ${safeError(error, secrets)}`);
  }
  if (cleanup.deleted) {
    let observedPresent = false;
    for (const waitMs of absenceDelays) {
      if (waitMs > 0) await wait(waitMs);
      try {
        const remaining = await get();
        if (!exactOwned(remaining)) {
          cleanup.errors.push("post-delete lookup returned a non-owned sandbox; left untouched");
          return cleanup;
        }
        observedPresent = true;
      } catch (error) {
        if (isNotFound(error)) cleanup.absenceChecks += 1;
        else cleanup.errors.push(`absence: ${safeError(error, secrets)}`);
      }
    }
    if (cleanup.absenceChecks !== absenceDelays.length || cleanup.absenceChecks < 2) {
      cleanup.errors.push(observedPresent
        ? "sandbox remained present during delayed post-delete checks"
        : "post-delete absence checks were insufficient");
    }
  }
  if (createResponseUncertain && cleanup.errors.length === 0) {
    cleanup.errors.push(
      "sandbox create provenance was not validated; cleanup remains uncertain until its terminal horizon",
    );
  }
  return cleanup;
}

function missingProof(stage: Sbx050PolicyStage): Sbx050PolicyProof {
  return {
    stage,
    startedAt: "missing",
    completedAt: "missing",
    initialSessionId: "missing",
    activeSessionId: "missing",
    independentSessionId: "missing",
    activeSandboxPolicy: null,
    activeSessionPolicy: null,
    independentSandboxPolicy: null,
    independentSessionPolicy: null,
    rawCredentialPresentInReadbacks: false,
    hiddenTriggerPresentInRetainedReadbacks: false,
    platformRedactionMarkerPresent: false,
    finalHiddenMatcherComparedExactlyBeforeSanitization: false,
    finalHiddenMatcherMarkerPresent: false,
    projectionMode: "not-final",
    readbackDiagnostic: missingPolicyReadbackDiagnostic(stage),
    identity: {
      aliasEmail: "missing",
      aliasIdentityVerified: false,
      teamId: "missing",
      projectId: "missing",
      sandboxName: "missing",
      sessionId: "missing",
    },
  };
}

type ReportabilityAssessment = Pick<Sbx050Assessment,
  "outcome" | "candidate" | "severity" | "reportReady" |
  "reportabilityStatus" | "semanticsClarificationRequired">;

export function reportabilityForAssessment(assessment: ReportabilityAssessment): Record<string, unknown> {
  const conditionalCandidate = assessment.outcome === "candidate-high" && assessment.candidate &&
    assessment.severity === "conditional-high" && !assessment.reportReady &&
    assessment.reportabilityStatus === "hold-pending-semantics-clarification" &&
    assessment.semanticsClarificationRequired;
  if (conditionalCandidate) {
    return {
      status: "hold-pending-semantics-clarification",
      reportReady: false,
      clarificationRequired: true,
      disposition: "conditional-candidate-hold",
      question: SBX050_SEMANTICS_QUESTION,
      intendedSequentialOrPhasedSemantics: "close-lane",
      confirmedOriginalRequestOnlyOrIsolatedSemantics: "conditional-high-only-with-exact-P-credential-proof",
    };
  }
  return {
    status: "not-reportable",
    reportReady: false,
    clarificationRequired: false,
    disposition: assessment.outcome === "pass" ? "closed-clean-negative" : "not-reportable",
  };
}

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  const config = explicitConfiguration();
  let credential = `s50_${randomBytes(32).toString("base64url")}`;
  let hiddenTrigger = `t50_${randomBytes(24).toString("base64url")}`;
  const runId = randomUUID();
  const canaries = Object.fromEntries(SBX050_CASES.map((caseId) => [
    caseId, `c50_${randomBytes(18).toString("base64url")}`,
  ])) as Record<Sbx050CaseId, string>;
  const expectedOperationIds = Object.fromEntries(SBX050_EVENT_CASES.map((caseId) => {
    const common = [config.actionKey, caseId === "public-forward-control" || caseId === "arm-without-trigger"
      ? config.pOrigin.hostname : config.aOrigin.hostname, runId, caseId, canaries[caseId]] as const;
    if (caseId === "public-forward-control") {
      return [caseId, { pass: expectedOperationId(...common, "P", false, false, true) }];
    }
    if (caseId === "transform-alone-control") {
      return [caseId, { pass: expectedOperationId(...common, "A", true, true, false) }];
    }
    if (caseId === "arm-without-trigger") {
      return [caseId, {
        pass: expectedOperationId(
          config.actionKey, config.aOrigin.hostname, runId, caseId, canaries[caseId], "A", true, true, false,
        ),
        candidate: expectedOperationId(...common, "P", true, true, true),
      }];
    }
    return [caseId, { pass: expectedOperationId(...common, "A", false, false, false) }];
  })) as Record<Sbx050EventCaseId, { pass: string; candidate?: string }>;
  const publicPolicy = publicForwardPolicy(config.aOrigin.hostname, config.pOrigin, runId);
  const transformPolicy = transformAlonePolicy(
    config.aOrigin.hostname, runId, credential, hiddenTrigger,
  );
  const finalPolicy = finalChainingPolicy(
    config.aOrigin.hostname, config.pOrigin, runId, credential, hiddenTrigger,
  );
  const secrets = [config.token, config.adminKey, config.actionKey, credential, hiddenTrigger];
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  const artifactPath = resolve(artifactsDirectory, `SBX-050-${runId}-private.json`);
  const lockPath = resolve(artifactsDirectory, "SBX-050-live-active.lock");
  const recoveryJournalPath = resolve(artifactsDirectory, `SBX-050-recovery-${runId}.json`);
  const sandboxName = `sbx-050-${runId.replaceAll("-", "")}`;
  const tags = { harness: "vsc", test: SBX050_TEST_ID, run: runId };
  const credentials = { token: config.token, teamId: config.teamId, projectId: config.projectId };
  const probes = Object.fromEntries(SBX050_CASES.map((caseId) => [
    caseId,
    emptyProbe(
      runId,
      caseId,
      canaries[caseId],
      caseId === "direct-p-pre" || caseId === "direct-p-post"
        ? config.pOrigin.hostname : config.aOrigin.hostname,
    ),
  ])) as Record<Sbx050CaseId, Sbx050ProbeEvidence>;
  const policyProofs = {} as Partial<Record<Sbx050PolicyStage, Sbx050PolicyProof>>;
  const policyReadbackDiagnostics = {} as Partial<
    Record<Sbx050PolicyStage, Sbx050PolicyReadbackDiagnostic>
  >;
  const commands: CommandRecord[] = [];
  let ledger: Sbx050LedgerEvidence = {
    configured: false,
    configuredAt: "missing",
    emptyReadAt: "missing",
    events: [],
    unexpectedARequests: 0,
    unexpectedPRequests: 0,
    unattributedRequests: 0,
    rawCredentialRetained: false,
    credentialDigestRetained: false,
    rawHiddenTriggerRetained: false,
    hiddenTriggerDigestRetained: false,
    rawOidcTokenRetained: false,
    oidcTokenDigestRetained: false,
    receiverRuntimeTrustExact: true,
    receiverRuntimeTrustEnvironmentNames: [],
    receiverNodeOptionsPresent: false,
    receiverTlsVerificationDisabled: false,
  };
  let identity: Awaited<ReturnType<typeof verifyEligibleAliasToken>> | undefined;
  let expectedIdentity: Sbx050ExpectedIdentity = {
    aliasEmail: "missing",
    aliasIdentityVerified: false,
    teamId: "missing",
    projectId: "missing",
    sandboxName,
    sessionId: "missing",
  };
  let sandbox: Sandbox | undefined;
  let initialSessionId: string | undefined;
  let createAttempted = false;
  let createProvenanceValidated = false;
  let receiverConfigureAttempted = false;
  let liveLock: FileHandle | undefined;
  let artifactHandle: FileHandle | undefined;
  let recoveryJournalHandle: FileHandle | undefined;
  let executionError: string | undefined;
  let guestSourceScanned = false;
  const localState: Sbx050LocalStateEvidence = {
    lockAcquired: false,
    lockMode: -1,
    artifactMode: -1,
    preexistingLockAbsent: false,
    lockReleased: false,
    recoveryJournalCreated: false,
    recoveryJournalMode: -1,
    recoveryJournalReleased: false,
  };
  let cleanupStartedAt = "missing";
  let cleanupCompletedAt = "missing";
  let sandboxCleanup: Sbx050CleanupEvidence["sandbox"] = {
    stopped: false, deleted: false, absenceChecks: 0, errors: [],
  };
  const receiverCleanup: Sbx050CleanupEvidence["receiver"] = {
    deleted: false, absent: false, absenceChecks: 0, errors: [],
  };

  const persistPolicyDiagnostic = async (
    diagnostic: Sbx050PolicyReadbackDiagnostic,
  ): Promise<void> => {
    policyReadbackDiagnostics[diagnostic.stage] = closedPolicyReadbackDiagnostic(diagnostic);
    if (!artifactHandle || localState.artifactMode !== 0o600) {
      throw new Error("SBX-050 cannot persist policy diagnostics without its mode-0600 artifact handle");
    }
    await writePolicyReadbackCheckpoint(artifactHandle, runId, policyReadbackDiagnostics);
  };

  try {
    await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
    liveLock = await open(lockPath, "wx", 0o600);
    localState.lockAcquired = true;
    localState.preexistingLockAbsent = true;
    localState.lockMode = (await liveLock.stat()).mode & 0o777;
    artifactHandle = await open(artifactPath, "wx", 0o600);
    localState.artifactMode = (await artifactHandle.stat()).mode & 0o777;
    recoveryJournalHandle = await open(recoveryJournalPath, "wx+", 0o600);
    localState.recoveryJournalCreated = true;
    localState.recoveryJournalMode = (await recoveryJournalHandle.stat()).mode & 0o777;
    await writeRecoveryJournal(recoveryJournalHandle, {
      runId, sandboxName, teamId: TEAM_ID, projectId: PROJECT_ID, tags, state: "prepared",
    });
    identity = await verifyEligibleAliasToken({
      token: config.token,
      expectedEmail: ALIAS_EMAIL,
      expectedTeamId: TEAM_ID,
      expectedProjectId: PROJECT_ID,
      manualEmailConfirmation: config.manualAliasConfirmation,
    });
    if (!(await health(config.aOrigin, "A")) || !(await health(config.pOrigin, "P"))) {
      throw new Error("both owned SBX-050 receiver roles must pass exact health checks");
    }
    const guestSource = await readFile(GUEST_SOURCE_PATH, "utf8");
    if (secrets.some((secret) => guestSource.includes(secret))) {
      throw new Error("fixed guest source contained controller-only material");
    }
    guestSourceScanned = true;
    createAttempted = true;
    await writeRecoveryJournal(recoveryJournalHandle, {
      runId, sandboxName, teamId: TEAM_ID, projectId: PROJECT_ID, tags, state: "sandbox-create-requested",
    });
    sandbox = await Sandbox.create({
      ...credentials,
      name: sandboxName,
      persistent: false,
      timeout: 360_000,
      resources: { vcpus: 2 },
      ports: [],
      networkPolicy: publicPolicy,
      tags,
      signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
    });
    const validatedSessionId = exactSbx050OwnedSessionId(sandbox, sandboxName, tags);
    initialSessionId = validatedSessionId;
    if (validatedSessionId === undefined) throw new Error("fresh sandbox identity was not exact");
    createProvenanceValidated = true;
    await writeRecoveryJournal(recoveryJournalHandle, {
      runId, sandboxName, teamId: TEAM_ID, projectId: PROJECT_ID, tags, state: "sandbox-create-confirmed",
    });
    expectedIdentity = {
      aliasEmail: ALIAS_EMAIL,
      aliasIdentityVerified: identity.email === ALIAS_EMAIL && identity.teamId === TEAM_ID &&
        identity.projectId === PROJECT_ID,
      teamId: TEAM_ID,
      projectId: PROJECT_ID,
      sandboxName,
      sessionId: validatedSessionId,
    };

    receiverConfigureAttempted = true;
    await writeRecoveryJournal(recoveryJournalHandle, {
      runId, sandboxName, teamId: TEAM_ID, projectId: PROJECT_ID, tags, state: "receiver-configure-requested",
    });
    const configurationResponse = await adminRequest(config, runId, {
      method: "PUT",
      body: JSON.stringify({
        runId,
        aHostname: config.aOrigin.hostname,
        forwardAudience: proxyAudience(config.pOrigin, runId),
        expectedTeamId: TEAM_ID,
        expectedProjectId: PROJECT_ID,
        expectedSessionId: validatedSessionId,
        expectedSandboxName: sandboxName,
        credentialCommitment: valueCommitment(config.actionKey, "credential", credential),
        hiddenTriggerCommitment: valueCommitment(config.actionKey, "trigger", hiddenTrigger),
        cases: SBX050_EVENT_CASES.map((caseId) => ({
          caseId,
          canary: canaries[caseId],
          requestPath: requestPath(runId, caseId, canaries[caseId]),
        })),
      }),
    });
    if (configurationResponse.status !== 201) {
      throw new Error(`receiver configuration returned ${configurationResponse.status}`);
    }
    await writeRecoveryJournal(recoveryJournalHandle, {
      runId, sandboxName, teamId: TEAM_ID, projectId: PROJECT_ID, tags, state: "receiver-configured",
    });
    if (configurationResponse.body) await configurationResponse.body.cancel().catch(() => undefined);
    await delay(2);
    ledger = await ledgerSnapshot(config, runId);
    if (ledger.events.length !== 0 || ledger.unexpectedARequests !== 0 ||
        ledger.unexpectedPRequests !== 0 || ledger.unattributedRequests !== 0) {
      throw new Error("receiver did not begin with an exact empty ledger");
    }
    await sandbox.currentSession().writeFiles(
      [{ path: REMOTE_GUEST_PATH, content: guestSource, mode: 0o700 }],
      { signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) },
    );

    await nextInstant(ledger.emptyReadAt);
    policyProofs["public-forward"] = await policyProof(
      "public-forward", sandbox, validatedSessionId, config, runId, credential, hiddenTrigger, expectedIdentity,
      publicPolicy, persistPolicyDiagnostic,
    );
    await nextInstant(policyProofs["public-forward"].completedAt);
    let execution = await runGuest(
      sandbox, runId, "public-forward-control", canaries["public-forward-control"], config, secrets,
      expectedIdentity,
    );
    probes["public-forward-control"] = execution.probe;
    commands.push(execution.command);
    if (!exactEarlyResponse(execution.probe, {
      runId,
      caseId: "public-forward-control",
      canary: canaries["public-forward-control"],
      hostname: config.aOrigin.hostname,
      role: "P",
      credential: false,
      trigger: false,
      oidc: true,
      operationId: expectedOperationIds["public-forward-control"].pass,
    })) throw new Error("public-trigger forward phase did not prove exact A-to-P forwarding");
    await delay(INTER_REQUEST_MS);
    ledger = await ledgerSnapshot(config, runId);
    if (ledger.events.length !== 1 || ledger.unexpectedARequests !== 0 ||
        ledger.unexpectedPRequests !== 0 || ledger.unattributedRequests !== 0) {
      throw new Error("public-forward phase did not produce one exact event");
    }

    await updatePhasePolicy(sandbox, transformPolicy);
    await nextInstant(probes["public-forward-control"].completedAt);
    policyProofs["transform-alone"] = await policyProof(
      "transform-alone", sandbox, validatedSessionId, config, runId, credential, hiddenTrigger, expectedIdentity,
      transformPolicy, persistPolicyDiagnostic,
    );
    await nextInstant(policyProofs["transform-alone"].completedAt);
    execution = await runGuest(
      sandbox, runId, "transform-alone-control", canaries["transform-alone-control"], config, secrets,
      expectedIdentity,
    );
    probes["transform-alone-control"] = execution.probe;
    commands.push(execution.command);
    if (!exactEarlyResponse(execution.probe, {
      runId,
      caseId: "transform-alone-control",
      canary: canaries["transform-alone-control"],
      hostname: config.aOrigin.hostname,
      role: "A",
      credential: true,
      trigger: true,
      oidc: false,
      operationId: expectedOperationIds["transform-alone-control"].pass,
    })) throw new Error("transform-only phase did not prove both host-injected values at A");
    await delay(INTER_REQUEST_MS);
    ledger = await ledgerSnapshot(config, runId);
    if (ledger.events.length !== 2 || ledger.unexpectedARequests !== 0 ||
        ledger.unexpectedPRequests !== 0 || ledger.unattributedRequests !== 0) {
      throw new Error("transform-only phase did not produce one exact fresh event");
    }

    await updatePhasePolicy(sandbox, finalPolicy);
    await nextInstant(probes["transform-alone-control"].completedAt);
    policyProofs["final-before"] = await policyProof(
      "final-before", sandbox, validatedSessionId, config, runId, credential, hiddenTrigger, expectedIdentity,
      finalPolicy, persistPolicyDiagnostic,
    );

    const finalCases = [
      "final-plain-pre", "direct-p-pre", "arm-without-trigger", "direct-p-post", "final-plain-post",
    ] as const;
    for (const [index, caseId] of finalCases.entries()) {
      const previous = index === 0
        ? policyProofs["final-before"].completedAt
        : probes[finalCases[index - 1]!].completedAt;
      await nextInstant(previous);
      execution = await runGuest(
        sandbox, runId, caseId, canaries[caseId], config, secrets, expectedIdentity,
      );
      probes[caseId] = execution.probe;
      commands.push(execution.command);
      if (caseId === "direct-p-pre" || caseId === "direct-p-post") {
        if (!exactDirectBlockProbe(execution.probe, {
          runId,
          caseId,
          canary: canaries[caseId],
          pHostname: config.pOrigin.hostname,
          expectedIdentity,
        })) {
          throw new Error(`${caseId} did not prove a fresh active direct-P network block`);
        }
      } else if (caseId === "arm-without-trigger") {
        const pass = exactEarlyResponse(execution.probe, {
          runId, caseId, canary: canaries[caseId], hostname: config.aOrigin.hostname,
          role: "A", credential: true, trigger: true, oidc: false,
          operationId: expectedOperationIds[caseId].pass,
        });
        const candidate = expectedOperationIds[caseId].candidate !== undefined && exactEarlyResponse(execution.probe, {
          runId, caseId, canary: canaries[caseId], hostname: config.aOrigin.hostname,
          role: "P", credential: true, trigger: true, oidc: true,
          operationId: expectedOperationIds[caseId].candidate!,
        });
        if (!pass && !candidate) throw new Error("decisive arm request was neither an exact A negative nor P candidate");
      } else {
        if (!exactEarlyResponse(execution.probe, {
          runId, caseId, canary: canaries[caseId], hostname: config.aOrigin.hostname,
          role: "A", credential: false, trigger: false, oidc: false,
          operationId: expectedOperationIds[caseId].pass,
        })) throw new Error(`${caseId} was not an exact plain-A control`);
      }
      await delay(INTER_REQUEST_MS);
      ledger = await ledgerSnapshot(config, runId);
      const expectedEvents = 2 + finalCases.slice(0, index + 1)
        .filter((entry) => entry !== "direct-p-pre" && entry !== "direct-p-post").length;
      if (ledger.events.length !== expectedEvents || ledger.unexpectedARequests !== 0 ||
          ledger.unexpectedPRequests !== 0 || ledger.unattributedRequests !== 0) {
        throw new Error(`${caseId} receiver event cardinality was not exact`);
      }
    }
    await nextInstant(probes["final-plain-post"].completedAt);
    policyProofs["final-after"] = await policyProof(
      "final-after", sandbox, validatedSessionId, config, runId, credential, hiddenTrigger, expectedIdentity,
      finalPolicy, persistPolicyDiagnostic,
    );
    if (policyProofs["final-after"].projectionMode !== policyProofs["final-before"].projectionMode) {
      throw new Error("final-after policy projection mode differed from final-before");
    }
    ledger = await ledgerSnapshot(config, runId);
  } catch (error) {
    executionError = safeError(error, secrets);
  } finally {
    const anchor = policyProofs["final-after"]?.completedAt ??
      probes["final-plain-post"].completedAt ?? startedAt;
    cleanupStartedAt = await nextInstant(anchor === "missing" ? startedAt : anchor);
    let journalWriteFailed = false;
    if (recoveryJournalHandle) {
      try {
        await writeRecoveryJournal(recoveryJournalHandle, {
          runId, sandboxName, teamId: TEAM_ID, projectId: PROJECT_ID, tags, state: "cleanup-started",
        });
      } catch (error) {
        journalWriteFailed = true;
        sandboxCleanup.errors.push(`recovery journal: ${safeError(error, secrets)}`);
      }
    }
    sandboxCleanup = await cleanupSandbox(
      sandbox, sandboxName, createAttempted, createProvenanceValidated, credentials, tags, secrets,
    );
    if (journalWriteFailed) sandboxCleanup.errors.push("recovery journal could not durably record cleanup start");
    if (receiverConfigureAttempted) {
      try {
        const response = await adminRequest(config, runId, { method: "DELETE" });
        receiverCleanup.deleted = response.status === 204 || response.status === 404;
        if (!receiverCleanup.deleted) receiverCleanup.errors.push(`receiver delete returned ${response.status}`);
        if (response.body) await response.body.cancel().catch(() => undefined);
      } catch (error) { receiverCleanup.errors.push(`receiver delete: ${safeError(error, secrets)}`); }
      for (const waitMs of POST_DELETE_ABSENCE_DELAYS_MS) {
        if (waitMs > 0) await delay(waitMs);
        try {
          const response = await adminRequest(config, runId);
          if (response.status === 404) {
            receiverCleanup.absenceChecks += 1;
          } else if (response.status === 200) {
            const retryDelete = await adminRequest(config, runId, { method: "DELETE" });
            receiverCleanup.deleted = receiverCleanup.deleted &&
              (retryDelete.status === 204 || retryDelete.status === 404);
            if (retryDelete.body) await retryDelete.body.cancel().catch(() => undefined);
          } else {
            receiverCleanup.errors.push(`receiver absence returned ${response.status}`);
          }
          if (response.body) await response.body.cancel().catch(() => undefined);
        } catch (error) { receiverCleanup.errors.push(`receiver absence: ${safeError(error, secrets)}`); }
      }
      receiverCleanup.absent = receiverCleanup.absenceChecks === POST_DELETE_ABSENCE_DELAYS_MS.length &&
        receiverCleanup.absenceChecks >= 2;
      if (!receiverCleanup.absent && receiverCleanup.errors.length === 0) {
        receiverCleanup.errors.push("receiver run state was present during delayed absence checks");
      }
    } else {
      receiverCleanup.deleted = true;
      receiverCleanup.absent = true;
      receiverCleanup.absenceChecks = 2;
    }

    const externalCleanupCertain = sandboxCleanup.stopped && sandboxCleanup.deleted &&
      sandboxCleanup.absenceChecks >= 2 && sandboxCleanup.errors.length === 0 &&
      receiverCleanup.deleted && receiverCleanup.absent && receiverCleanup.absenceChecks >= 2 &&
      receiverCleanup.errors.length === 0;
    let coordinationSafeToRelease = externalCleanupCertain && !journalWriteFailed;
    if (recoveryJournalHandle) {
      try {
        await writeRecoveryJournal(recoveryJournalHandle, {
          runId, sandboxName, teamId: TEAM_ID, projectId: PROJECT_ID, tags,
          state: coordinationSafeToRelease ? "cleanup-confirmed" : "cleanup-uncertain",
        });
        await recoveryJournalHandle.close();
        if (coordinationSafeToRelease) {
          await unlink(recoveryJournalPath);
          localState.recoveryJournalReleased = true;
        }
      } catch (error) {
        coordinationSafeToRelease = false;
        sandboxCleanup.errors.push(`recovery journal release: ${safeError(error, secrets)}`);
        try { await recoveryJournalHandle.close(); } catch { /* retain journal path */ }
      }
    } else if (createAttempted || receiverConfigureAttempted) {
      coordinationSafeToRelease = false;
      sandboxCleanup.errors.push("recovery journal was unavailable after an external create/configure attempt");
    }
    if (liveLock) {
      try {
        await liveLock.close();
        if (coordinationSafeToRelease) {
          await unlink(lockPath);
          localState.lockReleased = true;
        }
      } catch (error) {
        sandboxCleanup.errors.push(`lock cleanup: ${safeError(error, secrets)}`);
      }
    }
    cleanupCompletedAt = await nextInstant(cleanupStartedAt);
  }

  const completedPolicyProofs = Object.fromEntries(([
    "public-forward", "transform-alone", "final-before", "final-after",
  ] as const).map((stage) => [stage, policyProofs[stage] ?? missingProof(stage)])) as
    Record<Sbx050PolicyStage, Sbx050PolicyProof>;
  const guestConfigurations = SBX050_CASES.map((caseId) => fixedGuestConfiguration(
    runId, caseId, canaries[caseId], config.aOrigin, config.pOrigin,
  ));
  const guestMaterialSafe = !secrets.some((secret) => secret &&
    JSON.stringify(guestConfigurations).includes(secret));
  const completeGuestSweep = commands.length === SBX050_CASES.length &&
    SBX050_CASES.every((caseId) => probes[caseId].schemaVersion === 1);
  const prospectiveControllerMaterial = JSON.stringify({
    identity,
    expectedIdentity,
    completedPolicyProofs,
    policyReadbackDiagnostics,
    expectedOperationIds,
    probes,
    ledger,
    commands,
    sandboxCleanup,
    receiverCleanup,
    executionError,
  });
  const controllerMaterialSafe = !secrets.some((secret) => secret && prospectiveControllerMaterial.includes(secret));
  const retention: Sbx050RetentionEvidence = {
    guestSourceScanned,
    guestConfigurationsScanned: guestMaterialSafe && completeGuestSweep,
    guestArgvScanned: guestMaterialSafe && completeGuestSweep,
    guestEnvironmentScanned: completeGuestSweep,
    guestStagedFilesScanned: guestSourceScanned,
    guestStdoutScanned: completeGuestSweep,
    guestResultsScanned: completeGuestSweep,
    controllerArtifactScanned: controllerMaterialSafe,
    hiddenTriggerAbsentFromAllGuestMaterial: guestSourceScanned && guestMaterialSafe && completeGuestSweep,
    credentialAbsentFromAllGuestMaterial: guestSourceScanned && guestMaterialSafe && completeGuestSweep,
    rawCredentialRetained: false,
    credentialDigestRetained: false,
    rawHiddenTriggerRetained: false,
    hiddenTriggerDigestRetained: false,
    rawOidcTokenRetained: false,
    oidcTokenDigestRetained: false,
  };
  const assessmentInput: Sbx050AssessmentInput = {
    ...(executionError ? { executionError } : {}),
    runId,
    aOrigin: config.aOrigin.origin,
    aHostname: config.aOrigin.hostname,
    pHostname: config.pOrigin.hostname,
    pOrigin: config.pOrigin.origin,
    canaries,
    expectedOperationIds,
    expectedIdentity,
    probes,
    policyProofs: completedPolicyProofs,
    ledger,
    cleanup: {
      startedAt: cleanupStartedAt,
      completedAt: cleanupCompletedAt,
      sandbox: sandboxCleanup,
      receiver: receiverCleanup,
    },
    retention,
    localState,
  };
  const assessment = assessSbx050(assessmentInput);
  const reportability = reportabilityForAssessment(assessment);
  const evidence = {
    schemaVersion: 1,
    visibility: "private",
    testId: SBX050_TEST_ID,
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    hypothesis: "diagnostic question: whether a later forward rule matches a header injected by an earlier transform rule",
    reportability,
    identity,
    scope: {
      aliasEmail: ALIAS_EMAIL,
      teamId: TEAM_ID,
      projectId: PROJECT_ID,
      aOrigin: config.aOrigin.origin,
      pOrigin: config.pOrigin.origin,
      oneEphemeralSandbox: true,
    },
    sandbox: { name: sandboxName, sessionId: initialSessionId ?? "missing" },
    phasePolicies: completedPolicyProofs,
    policyReadbackDiagnostics,
    expectedOperationIds,
    matrix: probes,
    receiverLedger: ledger,
    commands,
    ...(executionError ? { executionError } : {}),
    cleanup: assessmentInput.cleanup,
    recovery: {
      journalPath: recoveryJournalPath,
      journalRetained: !localState.recoveryJournalReleased,
      lockPath,
      lockRetained: !localState.lockReleased,
    },
    assessment,
    retention,
    localState,
    evidencePath: artifactPath,
  };
  const serializedEvidence = `${JSON.stringify(evidence, null, 2)}\n`;
  if (secrets.some((secret) => secret && serializedEvidence.includes(secret))) {
    throw new Error("refusing to retain SBX-050 evidence containing controller-only material");
  }
  if (!artifactHandle || localState.artifactMode !== 0o600) {
    throw new Error("SBX-050 private artifact handle was not acquired with mode 0600");
  }
  await artifactHandle.truncate(0);
  await artifactHandle.write(serializedEvidence, 0, "utf8");
  await artifactHandle.sync();
  await artifactHandle.close();
  credential = "";
  hiddenTrigger = "";
  secrets.fill("");
  process.stdout.write(`${JSON.stringify({
    testId: SBX050_TEST_ID,
    runId,
    assessment,
    reportability: evidence.reportability,
    cleanup: assessmentInput.cleanup,
    recovery: evidence.recovery,
    evidencePath: artifactPath,
  }, null, 2)}\n`);
  process.exitCode = assessment.outcome === "candidate-high" ? 10
    : assessment.outcome === "pass" ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
