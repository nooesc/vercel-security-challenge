import {
  SBX057_CANARY,
  SBX057_CASES,
  SBX057_COMMITMENT,
  SBX057_OPERATION,
  SBX057_RECEIPT,
  SBX057_REDACTED_VALUE,
  SBX057_TEST_ID,
  SBX057_TRANSFORM_HEADER,
  SBX057_UUID,
  casePath,
  roleForCase,
  type Sbx057CaseId,
  type Sbx057Stage,
} from "./protocol.js";
import type { Sbx057ReceiverEvent, Sbx057ReceiverSnapshot } from "./receiver.js";

export interface Sbx057Identity {
  alias: string;
  teamId: string;
  projectId: string;
}

export interface Sbx057ExpectedResourceIdentity {
  role: Sbx057Stage;
  name: string;
  sessionId: string;
  persistent: false;
  tags: Record<string, string>;
}

export interface Sbx057PolicyProof {
  stage: Sbx057Stage;
  capturedAt: string;
  expectedSessionId: string;
  activeSessionId: string;
  independentSessionId: string;
  activeSandboxPolicy: unknown;
  activeSessionPolicy: unknown;
  independentSandboxPolicy: unknown;
  independentSessionPolicy: unknown;
  configuredPolicyComparedExactlyInMemory: true;
  rawSecretPresentInReadbacks: false;
  platformRedactionMarkerPresent: true;
}

export interface Sbx057ProbeEvidence {
  schemaVersion: number;
  testId: string;
  runId: string;
  caseId: string;
  canary: string;
  commandExitCode: number;
  ok: boolean;
  requestHostname: string;
  requestServername: string;
  requestHostHeader: string;
  requestPath: string;
  connectionAttempts: number;
  actualConnections: number;
  actualRequests: number;
  retries: number;
  redirectsFollowed: number;
  rejectUnauthorized: boolean;
  controllerConfigurableCustomTrustAccepted: boolean;
  inheritedPlatformTrustEnvironmentNames: string[];
  tcpConnected: boolean;
  tlsEstablished: boolean;
  tlsAuthorized: boolean;
  responseReceived: boolean;
  responseStatusCode?: number;
  responseShapeValid: boolean;
  responseRole?: string;
  responseReceipt?: string;
  responseOperationId?: string;
  responseBodyRetained: boolean;
  durationMs: number;
  startedAt: string;
  completedAt: string;
}

export interface Sbx057CleanupResource {
  role: Sbx057Stage;
  exactProvenance: boolean;
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  absenceChecks: number;
  errors: string[];
}

export interface Sbx057CleanupEvidence {
  resources: Sbx057CleanupResource[];
  receiverDeleteAttempted: boolean;
  receiverDeleted: boolean;
  receiverAbsenceChecks: number;
  completedAt?: string;
  journalRemoved: boolean;
  liveLockRemoved: boolean;
  lockTransactionRemoved: boolean;
  errors: string[];
}

export interface Sbx057RetentionEvidence {
  guestSourceContainsComparatorSecret: boolean;
  guestSourceContainsTargetSecret: boolean;
  guestConfigurationContainsComparatorSecret: boolean;
  guestConfigurationContainsTargetSecret: boolean;
  guestEnvironmentContainsSecrets: boolean;
  guestArgvContainsSecrets: boolean;
  guestFilesContainSecrets: boolean;
  guestStdoutContainsSecrets: boolean;
  guestResultContainsSecrets: boolean;
  artifactContainsRawSecrets: boolean;
  artifactContainsStandaloneSecretDigests: boolean;
  receiverRetainedRawSecrets: boolean;
  artifactMode: number;
  lockMode: number;
  journalMode: number;
}

export interface Sbx057AssessmentInput {
  runId: string;
  identity: Sbx057Identity;
  expectedIdentity: Sbx057Identity;
  aHostname: string;
  bHostname: string;
  comparatorCommitment: string;
  targetCommitment: string;
  canaries: Record<Sbx057CaseId, string>;
  expectedOperationIds: Record<Sbx057CaseId, string>;
  expectedReceipts: {
    comparatorAAction: string;
    comparatorBNone: string;
    comparatorBAction: string;
    targetAAction: string;
    targetBNone: string;
    targetBAction: string;
  };
  resources: Sbx057ExpectedResourceIdentity[];
  policies: {
    comparatorBefore: Sbx057PolicyProof;
    comparatorAfter: Sbx057PolicyProof;
    targetBefore?: Sbx057PolicyProof;
    targetAfter?: Sbx057PolicyProof;
  };
  probes: Partial<Record<Sbx057CaseId, Sbx057ProbeEvidence>>;
  ledger: Sbx057ReceiverSnapshot;
  cleanup: Sbx057CleanupEvidence;
  retention: Sbx057RetentionEvidence;
  comparatorCleanupCompletedAt?: string;
  receiverSnapshotAt: string;
  controllerError?: string;
}

export interface Sbx057Assessment {
  outcome: "candidate-high" | "alternate-root" | "pass" | "indeterminate" | "error";
  candidate: boolean;
  severity: "high" | "none" | "unknown";
  controlsPassed: boolean;
  wildcardCredentialLeakProven: boolean;
  summary: string;
}

const TRUST_NAMES = [
  "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF", "OPENSSL_MODULES",
  "SSL_CERT_DIR", "SSL_CERT_FILE",
].sort();

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function exactKeys(value: object, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((entry, index) => entry === wanted[index]);
}

function exactStringSet(value: unknown, expected: readonly string[]): boolean {
  return Array.isArray(value) && value.every((entry): entry is string => typeof entry === "string") &&
    value.length === expected.length && new Set(value).size === value.length &&
    [...value].sort().every((entry, index) => entry === [...expected].sort()[index]);
}

function exactRecord(value: unknown, expected: Record<string, string>): boolean {
  const root = object(value);
  return root !== undefined && exactKeys(root, Object.keys(expected)) &&
    Object.entries(expected).every(([key, expectedValue]) => root[key] === expectedValue);
}

function exactSandboxProjection(value: unknown, aHostname: string, other: string): boolean {
  const root = object(value);
  return root !== undefined && exactKeys(root, ["allow"]) &&
    exactStringSet(root.allow, [aHostname, other]);
}

function exactSessionProjection(value: unknown, aHostname: string, other: string): boolean {
  const root = object(value);
  if (root === undefined || !exactKeys(root, ["allow"])) return false;
  const allow = object(root.allow);
  if (allow === undefined || !exactKeys(allow, [aHostname, other]) || !Array.isArray(allow[aHostname]) ||
      allow[aHostname].length !== 1 || !Array.isArray(allow[other]) || allow[other].length !== 0) return false;
  const rule = object(allow[aHostname][0]);
  if (rule === undefined || !exactKeys(rule, ["transform"]) || !Array.isArray(rule.transform) ||
      rule.transform.length !== 1) return false;
  const transform = object(rule.transform[0]);
  const headers = object(transform?.headers);
  return transform !== undefined && exactKeys(transform, ["headers"]) && headers !== undefined &&
    exactKeys(headers, [SBX057_TRANSFORM_HEADER]) && headers[SBX057_TRANSFORM_HEADER] === SBX057_REDACTED_VALUE;
}

export function exactSbx057PolicyProof(
  proof: Sbx057PolicyProof,
  stage: Sbx057Stage,
  sessionId: string,
  aHostname: string,
  bHostname: string,
): boolean {
  const other = stage === "comparator" ? bHostname : "*";
  return proof.stage === stage && timestamp(proof.capturedAt) &&
    proof.expectedSessionId === sessionId && proof.activeSessionId === sessionId &&
    proof.independentSessionId === sessionId && proof.configuredPolicyComparedExactlyInMemory &&
    proof.rawSecretPresentInReadbacks === false && proof.platformRedactionMarkerPresent &&
    exactSandboxProjection(proof.activeSandboxPolicy, aHostname, other) &&
    exactSessionProjection(proof.activeSessionPolicy, aHostname, other) &&
    exactSandboxProjection(proof.independentSandboxPolicy, aHostname, other) &&
    exactSessionProjection(proof.independentSessionPolicy, aHostname, other);
}

function timestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value;
}

function exactIdentity(actual: Sbx057Identity, expected: Sbx057Identity): boolean {
  return actual.alias === expected.alias && actual.teamId === expected.teamId &&
    actual.projectId === expected.projectId;
}

function exactResource(resource: Sbx057ExpectedResourceIdentity, runId: string): boolean {
  return (resource.role === "comparator" || resource.role === "target") &&
    resource.name === `sbx-057-${resource.role}-${runId}` && resource.persistent === false &&
    /^sbx_[A-Za-z0-9_-]{20,100}$/u.test(resource.sessionId) && exactRecord(resource.tags, {
      harness: "vsc", test: SBX057_TEST_ID, run: runId, role: resource.role,
    });
}

function exactTrustNames(value: string[]): boolean {
  return value.length === new Set(value).size && value.every((entry) => TRUST_NAMES.includes(entry)) &&
    value.every((entry, index) => index === 0 || value[index - 1]! < entry);
}

function exactProbe(
  probe: Sbx057ProbeEvidence | undefined,
  input: Sbx057AssessmentInput,
  caseId: Sbx057CaseId,
  expectedStatus: number,
  event: Sbx057ReceiverEvent,
): boolean {
  if (probe === undefined) return false;
  const hostname = roleForCase(caseId) === "A" ? input.aHostname : input.bHostname;
  const operationExpected = expectedStatus === 200;
  return probe.schemaVersion === 1 && probe.testId === SBX057_TEST_ID && probe.runId === input.runId &&
    probe.caseId === caseId && probe.canary === input.canaries[caseId] && probe.commandExitCode === 0 &&
    probe.ok && probe.requestHostname === hostname && probe.requestServername === hostname &&
    probe.requestHostHeader === hostname && probe.requestPath === casePath(input.runId, caseId) &&
    probe.connectionAttempts === 1 && probe.actualConnections === 1 && probe.actualRequests === 1 &&
    probe.retries === 0 && probe.redirectsFollowed === 0 && probe.rejectUnauthorized &&
    probe.controllerConfigurableCustomTrustAccepted === false && exactTrustNames(probe.inheritedPlatformTrustEnvironmentNames) &&
    probe.tcpConnected && probe.tlsEstablished && probe.tlsAuthorized && probe.responseReceived &&
    probe.responseStatusCode === expectedStatus && probe.responseShapeValid &&
    probe.responseRole === roleForCase(caseId) && probe.responseReceipt === event.receipt &&
    (operationExpected ? probe.responseOperationId === event.operationId : probe.responseOperationId === undefined) &&
    probe.responseBodyRetained === false && Number.isFinite(probe.durationMs) && probe.durationMs >= 0 &&
    timestamp(probe.startedAt) && timestamp(probe.completedAt) &&
    Date.parse(probe.startedAt) <= Date.parse(event.observedAt) &&
    Date.parse(event.observedAt) <= Date.parse(probe.completedAt);
}

function exactEvent(
  event: Sbx057ReceiverEvent | undefined,
  input: Sbx057AssessmentInput,
  caseId: Sbx057CaseId,
  sequence: number,
  headerCount: number,
  commitmentMatched: boolean,
  crossMatched: boolean,
  status: number,
): boolean {
  if (event === undefined) return false;
  const receiptKey = caseId === "comparator-a" ? "comparatorAAction"
    : caseId === "comparator-b" && status === 200 ? "comparatorBAction"
    : caseId === "comparator-b" ? "comparatorBNone"
    : caseId === "target-a" ? "targetAAction"
    : status === 200 ? "targetBAction"
    : "targetBNone";
  const expectedOperation = input.expectedOperationIds[caseId];
  const expectedEventReceipt = input.expectedReceipts[receiptKey];
  return event.sequence === sequence && timestamp(event.observedAt) && event.kind === "expected" &&
    event.role === roleForCase(caseId) && event.caseId === caseId && event.method === "GET" &&
    event.hostMatched && event.pathMatched && event.correlationHeadersExact &&
    event.transformHeaderLines === headerCount && event.transformHeaderValues === headerCount &&
    event.transformCommitmentMatched === commitmentMatched && event.crossCommitmentMatched === crossMatched &&
    event.responseStatus === status && event.receipt === expectedEventReceipt &&
    SBX057_RECEIPT.test(expectedEventReceipt) &&
    (status === 200 && commitmentMatched
      ? event.operationId === expectedOperation && SBX057_OPERATION.test(expectedOperation)
      : event.operationId === undefined);
}

function cleanupExact(cleanup: Sbx057CleanupEvidence, expectedRoles: Sbx057Stage[]): boolean {
  return cleanup.resources.length === expectedRoles.length && cleanup.resources.every((resource, index) =>
    resource.role === expectedRoles[index] && resource.exactProvenance && resource.stopAttempted &&
    resource.stopped && resource.deleteAttempted && resource.deleted && resource.absenceChecks >= 3 &&
    resource.errors.length === 0) && cleanup.receiverDeleteAttempted && cleanup.receiverDeleted &&
    cleanup.receiverAbsenceChecks >= 2 && timestamp(cleanup.completedAt) && cleanup.journalRemoved &&
    cleanup.liveLockRemoved && cleanup.lockTransactionRemoved && cleanup.errors.length === 0;
}

function retentionExact(retention: Sbx057RetentionEvidence): boolean {
  return !retention.guestSourceContainsComparatorSecret && !retention.guestSourceContainsTargetSecret &&
    !retention.guestConfigurationContainsComparatorSecret && !retention.guestConfigurationContainsTargetSecret &&
    !retention.guestEnvironmentContainsSecrets && !retention.guestArgvContainsSecrets &&
    !retention.guestFilesContainSecrets && !retention.guestStdoutContainsSecrets &&
    !retention.guestResultContainsSecrets && !retention.artifactContainsRawSecrets &&
    !retention.artifactContainsStandaloneSecretDigests && !retention.receiverRetainedRawSecrets &&
    retention.artifactMode === 0o600 && retention.lockMode === 0o600 && retention.journalMode === 0o600;
}

function chronologyExact(input: Sbx057AssessmentInput, targetRan: boolean): boolean {
  const comparatorA = input.probes["comparator-a"];
  const comparatorB = input.probes["comparator-b"];
  if (comparatorA === undefined || comparatorB === undefined || !timestamp(input.ledger.configuredAt) ||
      !timestamp(input.receiverSnapshotAt) || !timestamp(input.comparatorCleanupCompletedAt) ||
      Date.parse(input.ledger.configuredAt) >= Date.parse(input.policies.comparatorBefore.capturedAt) ||
      Date.parse(input.policies.comparatorBefore.capturedAt) >= Date.parse(comparatorA.startedAt) ||
      Date.parse(comparatorA.completedAt) >= Date.parse(comparatorB.startedAt) ||
      Date.parse(comparatorB.completedAt) > Date.parse(input.policies.comparatorAfter.capturedAt) ||
      Date.parse(input.policies.comparatorAfter.capturedAt) >= Date.parse(input.comparatorCleanupCompletedAt)) return false;
  if (!targetRan) return Date.parse(input.comparatorCleanupCompletedAt) <= Date.parse(input.receiverSnapshotAt) &&
    Date.parse(input.receiverSnapshotAt) <= Date.parse(input.cleanup.completedAt ?? "");
  const targetA = input.probes["target-a"];
  const targetB = input.probes["target-b"];
  const before = input.policies.targetBefore;
  const after = input.policies.targetAfter;
  return targetA !== undefined && targetB !== undefined && before !== undefined && after !== undefined &&
    Date.parse(input.comparatorCleanupCompletedAt) < Date.parse(before.capturedAt) &&
    Date.parse(before.capturedAt) <= Date.parse(targetA.startedAt) &&
    Date.parse(targetA.completedAt) < Date.parse(targetB.startedAt) &&
    Date.parse(targetB.completedAt) <= Date.parse(after.capturedAt) &&
    Date.parse(after.capturedAt) <= Date.parse(input.receiverSnapshotAt) &&
    Date.parse(input.receiverSnapshotAt) <= Date.parse(input.cleanup.completedAt ?? "");
}

function baseControls(input: Sbx057AssessmentInput): boolean {
  const host = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.trycloudflare\.com$/u;
  const operationIds = Object.values(input.expectedOperationIds);
  const receipts = Object.values(input.expectedReceipts);
  if (!SBX057_UUID.test(input.runId) || !host.test(input.aHostname) || !host.test(input.bHostname) ||
      input.aHostname === input.bHostname || !SBX057_COMMITMENT.test(input.comparatorCommitment) ||
      !SBX057_COMMITMENT.test(input.targetCommitment) ||
      input.comparatorCommitment === input.targetCommitment ||
      operationIds.length !== SBX057_CASES.length || new Set(operationIds).size !== operationIds.length ||
      !operationIds.every((entry) => SBX057_OPERATION.test(entry)) || receipts.length !== 6 ||
      new Set(receipts).size !== receipts.length || !receipts.every((entry) => SBX057_RECEIPT.test(entry)) ||
      (input.resources.length !== 1 && input.resources.length !== 2) ||
      new Set(input.resources.map((resource) => resource.role)).size !== input.resources.length ||
      !input.resources.every((resource) => exactResource(resource, input.runId)) ||
      !exactIdentity(input.identity, input.expectedIdentity) ||
      Object.keys(input.canaries).length !== SBX057_CASES.length ||
      !SBX057_CASES.every((caseId) => SBX057_CANARY.test(input.canaries[caseId])) ||
      new Set(Object.values(input.canaries)).size !== SBX057_CASES.length ||
      input.ledger.schemaVersion !== 1 || input.ledger.testId !== SBX057_TEST_ID ||
      input.ledger.runId !== input.runId || !input.ledger.configurationValid || input.ledger.rawSecretsRetained ||
      input.ledger.unexpectedIngressCount !== 0 || input.ledger.unattributedIngressCount !== 0 ||
      !retentionExact(input.retention)) return false;
  const comparator = input.resources.find((resource) => resource.role === "comparator");
  return comparator !== undefined && exactResource(comparator, input.runId) &&
    exactSbx057PolicyProof(input.policies.comparatorBefore, "comparator", comparator.sessionId,
      input.aHostname, input.bHostname) &&
    exactSbx057PolicyProof(input.policies.comparatorAfter, "comparator", comparator.sessionId,
      input.aHostname, input.bHostname);
}

export function assessSbx057(input: Sbx057AssessmentInput): Sbx057Assessment {
  if (input.controllerError !== undefined) {
    return { outcome: "error", candidate: false, severity: "unknown", controlsPassed: false,
      wildcardCredentialLeakProven: false, summary: "The controller failed before an exact verdict." };
  }
  if (!baseControls(input)) {
    return { outcome: "indeterminate", candidate: false, severity: "unknown", controlsPassed: false,
      wildcardCredentialLeakProven: false, summary: "Identity, policy, receiver, or retention controls were not exact." };
  }
  const cA = input.ledger.events[0];
  const cB = input.ledger.events[1];
  const comparatorA = exactEvent(cA, input, "comparator-a", 1, 1, true, false, 200) &&
    exactProbe(input.probes["comparator-a"], input, "comparator-a", 200, cA!);
  const comparatorBClean = exactEvent(cB, input, "comparator-b", 2, 0, false, false, 202) &&
    exactProbe(input.probes["comparator-b"], input, "comparator-b", 202, cB!);
  const comparatorBLeak = exactEvent(cB, input, "comparator-b", 2, 1, true, false, 200) &&
    exactProbe(input.probes["comparator-b"], input, "comparator-b", 200, cB!);
  if (comparatorA && comparatorBLeak && input.ledger.events.length === 2 &&
      input.resources.length === 1 && input.resources[0]?.role === "comparator" &&
      chronologyExact(input, false) && cleanupExact(input.cleanup, ["comparator"])) {
    return { outcome: "alternate-root", candidate: true, severity: "high", controlsPassed: true,
      wildcardCredentialLeakProven: false,
      summary: "The exact-domain comparator leaked A's credential to B; stop before attributing a wildcard root." };
  }
  if (!comparatorA || !comparatorBClean) {
    return { outcome: "indeterminate", candidate: false, severity: "unknown", controlsPassed: false,
      wildcardCredentialLeakProven: false, summary: "The exact-domain isolation comparator did not pass." };
  }
  const target = input.resources.find((resource) => resource.role === "target");
  if (input.resources.length !== 2 || target === undefined || !exactResource(target, input.runId) ||
      input.policies.targetBefore === undefined ||
      input.policies.targetAfter === undefined ||
      !exactSbx057PolicyProof(input.policies.targetBefore, "target", target.sessionId,
        input.aHostname, input.bHostname) ||
      !exactSbx057PolicyProof(input.policies.targetAfter, "target", target.sessionId,
        input.aHostname, input.bHostname) || input.ledger.events.length !== 4 ||
      !chronologyExact(input, true) || !cleanupExact(input.cleanup, ["comparator", "target"])) {
    return { outcome: "indeterminate", candidate: false, severity: "unknown", controlsPassed: false,
      wildcardCredentialLeakProven: false, summary: "The wildcard target lifecycle or chronology was incomplete." };
  }
  const tA = input.ledger.events[2];
  const tB = input.ledger.events[3];
  const targetA = exactEvent(tA, input, "target-a", 3, 1, true, false, 200) &&
    exactProbe(input.probes["target-a"], input, "target-a", 200, tA!);
  const targetBClean = exactEvent(tB, input, "target-b", 4, 0, false, false, 202) &&
    exactProbe(input.probes["target-b"], input, "target-b", 202, tB!);
  const targetBLeak = exactEvent(tB, input, "target-b", 4, 1, true, false, 200) &&
    exactProbe(input.probes["target-b"], input, "target-b", 200, tB!);
  if (!targetA || (!targetBClean && !targetBLeak)) {
    return { outcome: "indeterminate", candidate: false, severity: "unknown", controlsPassed: false,
      wildcardCredentialLeakProven: false, summary: "The wildcard target event was not an exact clean or secret-bearing receipt." };
  }
  if (targetBLeak) {
    return { outcome: "candidate-high", candidate: true, severity: "high", controlsPassed: true,
      wildcardCredentialLeakProven: true,
      summary: "Only the wildcard catch-all target sent A's exact controller-only credential to direct B." };
  }
  return { outcome: "pass", candidate: false, severity: "none", controlsPassed: true,
    wildcardCredentialLeakProven: false,
    summary: "The documented wildcard catch-all allowed direct B without applying A's transform." };
}
