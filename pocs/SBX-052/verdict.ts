export const SBX052_TEST_ID = "SBX-052" as const;
export const SBX052_ALIAS_EMAIL = "swve@wearehackerone.com" as const;
export const SBX052_TEAM_ID = "team_n98ERpVwV7HqmWRudAyK8sXQ" as const;
export const SBX052_PROJECT_ID = "prj_CyyVykdN06Nrkla6KidZcecLgbCa" as const;
export const SBX052_BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id" as const;

export type Sbx052Verdict = "candidate-proc-context-differential" | "pass" | "indeterminate" | "error";

export interface Sbx052IdentityEvidence {
  email: string;
  teamId: string;
  projectId: string;
  method: "v2-user-email" | "manual-email-plus-exact-team-project-api";
}

export interface Sbx052ExpectedIdentity {
  runId: string;
  sandboxName: string;
  sessionId: string;
  tags: Record<string, string>;
}

export interface Sbx052SandboxEvidence {
  name: string;
  sessionId: string;
  persistent: boolean;
  status: string;
  networkPolicy: string;
  routesCount: number;
  createdAt: string;
  sandboxTimeoutMs: number | null;
  sessionTimeoutMs: number;
  tags: Record<string, string>;
}

export interface Sbx052ReadbackEvidence {
  stage: "initial" | "final";
  source: "active" | "independent";
  observedAt: string;
  name: string;
  sessionId: string;
  persistent: boolean;
  status: string;
  networkPolicy: string;
  routesCount: number;
  sandboxTimeoutMs: number | null;
  sessionTimeoutMs: number;
  tags: Record<string, string>;
}

export const SBX052_OPERATION_CASES = [
  "guest-setup",
  "guest-before",
  "owned-direct",
  "owned-symlink",
  "proc-direct",
  "guest-middle",
  "proc-symlink",
  "guest-after",
  "guest-cleanup",
] as const;

export type Sbx052OperationCase = typeof SBX052_OPERATION_CASES[number];

export interface Sbx052OperationEvidence {
  ordinal: number;
  caseId: Sbx052OperationCase;
  channel: "guest-command" | "Session.readFile";
  pathClass: "none" | "owned-file" | "owned-relative-symlink" | "proc-direct" | "proc-absolute-symlink";
  startedAt: string;
  completedAt: string;
  sdkInvocations: number;
  transportAttemptsObserved: false;
  found: boolean;
  returnedBytes: number;
  rawOutputRetained: false;
}

export interface Sbx052NamespaceEvidence {
  guestObservationCount: number;
  guestDirectFormatsValid: boolean;
  guestLinkedFormatsValid: boolean;
  guestDirectEqualsLinkedEveryTime: boolean;
  guestBootIdStableAcrossBrackets: boolean;
  guestBootBytes: number[];
  ownedDirectMatched: boolean;
  ownedSymlinkMatched: boolean;
  ownedDirectEqualsSymlink: boolean;
  ownedDirectBytes: number;
  ownedSymlinkBytes: number;
  apiDirectProcFormatValid: boolean;
  apiSymlinkProcFormatValid: boolean;
  apiDirectProcBytes: number;
  apiSymlinkProcBytes: number;
  apiDirectEqualsSymlink: boolean;
  apiDirectEqualsStableGuest: boolean;
  apiSymlinkEqualsStableGuest: boolean;
  apiPairDiffersFromStableGuest: boolean;
  rawBootIdsRetained: false;
  bootIdDigestsRetained: false;
  rawCanaryRetained: false;
  canaryDigestRetained: false;
}

export interface Sbx052CleanupEvidence {
  guestCleanupAttempted: boolean;
  guestDirectoryRemoved: boolean;
  guestProbeRemoved: boolean;
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  absenceChecks: number;
  exactNameAbsent: boolean;
  prefixListAbsent: boolean;
  unknownCreate: boolean;
  liveLockReleased: boolean;
  recoveryJournalDeleted: boolean;
  completedAt: string;
  errors: string[];
}

export interface Sbx052StorageEvidence {
  artifactMode: number;
  liveLockMode: number;
  recoveryJournalMode: number;
  rawBootIdsRetained: false;
  bootIdDigestsRetained: false;
  rawCanaryRetained: false;
  canaryDigestRetained: false;
  guestStdoutRetained: false;
  guestStderrRetained: false;
  apiResponseBodiesRetained: false;
}

export interface Sbx052AssessmentInput {
  executionError?: string;
  identityAndScopePassed: boolean;
  identity?: Sbx052IdentityEvidence;
  expected: Sbx052ExpectedIdentity;
  sandbox: Sbx052SandboxEvidence;
  readbacks: Sbx052ReadbackEvidence[];
  operations: Sbx052OperationEvidence[];
  namespace: Sbx052NamespaceEvidence;
  cleanup: Sbx052CleanupEvidence;
  storage: Sbx052StorageEvidence;
}

export interface Sbx052Assessment {
  verdict: Sbx052Verdict;
  candidate: boolean;
  controlsPassed: boolean;
  namespaceDifferentialProved: boolean;
  severity: "none" | "unknown";
  summary: string;
  signals: string[];
}

export interface Sbx052RawGuestObservation {
  directBootId: string;
  linkedBootId: string;
  directBytes: number;
  linkedBytes: number;
  ownedLinkTarget: string;
  procLinkTarget: string;
}

export interface BuildSbx052NamespaceInput {
  guest: readonly [Sbx052RawGuestObservation, Sbx052RawGuestObservation, Sbx052RawGuestObservation];
  ownedDirect: Buffer;
  ownedSymlink: Buffer;
  expectedCanary: Buffer;
  apiDirectProc: Buffer;
  apiSymlinkProc: Buffer;
}

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SESSION_ID = /^sbx_[A-Za-z0-9_-]{8,192}$/u;
const SANDBOX_NAME = /^sbx-052-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const BOOT_ID_TEXT = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const BOOT_ID_BYTES = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\n$/u;

function exactRecord(actual: Record<string, string>, expected: Record<string, string>): boolean {
  const keys = Object.keys(expected);
  return Object.keys(actual).length === keys.length && keys.every((key) => actual[key] === expected[key]);
}

function timestamp(value: string): boolean {
  const parsed = Date.parse(value);
  return value.length === 24 && Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function equalBytes(left: Buffer, right: Buffer): boolean {
  return left.length === right.length && left.equals(right);
}

function canonicalApiBootId(value: Buffer): boolean {
  return value.length === 37 && BOOT_ID_BYTES.test(value.toString("utf8"));
}

export function buildSbx052NamespaceEvidence(input: BuildSbx052NamespaceInput): Sbx052NamespaceEvidence {
  const guestDirectFormatsValid = input.guest.every((item) =>
    BOOT_ID_TEXT.test(item.directBootId) && item.directBytes === 37);
  const guestLinkedFormatsValid = input.guest.every((item) =>
    BOOT_ID_TEXT.test(item.linkedBootId) && item.linkedBytes === 37 &&
    item.ownedLinkTarget === "owned.txt" && item.procLinkTarget === SBX052_BOOT_ID_PATH);
  const guestDirectEqualsLinkedEveryTime = input.guest.every((item) =>
    item.directBootId === item.linkedBootId);
  const guestBootIdStableAcrossBrackets = input.guest.every((item) =>
    item.directBootId === input.guest[0].directBootId &&
    item.linkedBootId === input.guest[0].directBootId);
  const stableGuestBytes = Buffer.from(`${input.guest[0].directBootId}\n`, "utf8");
  const apiDirectProcFormatValid = canonicalApiBootId(input.apiDirectProc);
  const apiSymlinkProcFormatValid = canonicalApiBootId(input.apiSymlinkProc);
  const apiDirectEqualsStableGuest = equalBytes(input.apiDirectProc, stableGuestBytes);
  const apiSymlinkEqualsStableGuest = equalBytes(input.apiSymlinkProc, stableGuestBytes);
  return {
    guestObservationCount: input.guest.length,
    guestDirectFormatsValid,
    guestLinkedFormatsValid,
    guestDirectEqualsLinkedEveryTime,
    guestBootIdStableAcrossBrackets,
    guestBootBytes: input.guest.flatMap((item) => [item.directBytes, item.linkedBytes]),
    ownedDirectMatched: equalBytes(input.ownedDirect, input.expectedCanary),
    ownedSymlinkMatched: equalBytes(input.ownedSymlink, input.expectedCanary),
    ownedDirectEqualsSymlink: equalBytes(input.ownedDirect, input.ownedSymlink),
    ownedDirectBytes: input.ownedDirect.length,
    ownedSymlinkBytes: input.ownedSymlink.length,
    apiDirectProcFormatValid,
    apiSymlinkProcFormatValid,
    apiDirectProcBytes: input.apiDirectProc.length,
    apiSymlinkProcBytes: input.apiSymlinkProc.length,
    apiDirectEqualsSymlink: equalBytes(input.apiDirectProc, input.apiSymlinkProc),
    apiDirectEqualsStableGuest,
    apiSymlinkEqualsStableGuest,
    apiPairDiffersFromStableGuest: !apiDirectEqualsStableGuest && !apiSymlinkEqualsStableGuest,
    rawBootIdsRetained: false,
    bootIdDigestsRetained: false,
    rawCanaryRetained: false,
    canaryDigestRetained: false,
  };
}

function exactIdentity(input: Sbx052AssessmentInput): boolean {
  return input.identityAndScopePassed && input.identity !== undefined &&
    input.identity.email === SBX052_ALIAS_EMAIL && input.identity.teamId === SBX052_TEAM_ID &&
    input.identity.projectId === SBX052_PROJECT_ID &&
    (input.identity.method === "v2-user-email" ||
      input.identity.method === "manual-email-plus-exact-team-project-api");
}

function exactSandbox(input: Sbx052AssessmentInput): boolean {
  const expected = input.expected;
  const sandbox = input.sandbox;
  return UUID_V4.test(expected.runId) && SANDBOX_NAME.test(expected.sandboxName) &&
    SESSION_ID.test(expected.sessionId) && expected.sandboxName === `sbx-052-${expected.runId}` &&
    exactRecord(expected.tags, { harness: "vsc", test: SBX052_TEST_ID, run: expected.runId }) &&
    sandbox.name === expected.sandboxName && sandbox.sessionId === expected.sessionId &&
    sandbox.persistent === false && sandbox.status === "running" && sandbox.networkPolicy === "deny-all" &&
    sandbox.routesCount === 0 && sandbox.sandboxTimeoutMs === 240_000 &&
    sandbox.sessionTimeoutMs === 240_000 && timestamp(sandbox.createdAt) &&
    exactRecord(sandbox.tags, expected.tags);
}

function exactReadbacks(input: Sbx052AssessmentInput): boolean {
  if (input.readbacks.length !== 4) return false;
  const expectedPairs = [
    ["initial", "active"],
    ["initial", "independent"],
    ["final", "active"],
    ["final", "independent"],
  ] as const;
  return input.readbacks.every((readback, index) => {
    const pair = expectedPairs[index]!;
    return readback.stage === pair[0] && readback.source === pair[1] &&
      timestamp(readback.observedAt) && readback.name === input.expected.sandboxName &&
      readback.sessionId === input.expected.sessionId && readback.persistent === false &&
      readback.status === "running" && readback.networkPolicy === "deny-all" &&
      readback.routesCount === 0 && readback.sandboxTimeoutMs === 240_000 &&
      readback.sessionTimeoutMs === 240_000 && exactRecord(readback.tags, input.expected.tags);
  });
}

function exactOperations(input: Sbx052AssessmentInput): boolean {
  if (input.operations.length !== SBX052_OPERATION_CASES.length) return false;
  const channels = [
    "guest-command", "guest-command", "Session.readFile", "Session.readFile", "Session.readFile",
    "guest-command", "Session.readFile", "guest-command", "guest-command",
  ] as const;
  const pathClasses = [
    "none", "none", "owned-file", "owned-relative-symlink", "proc-direct",
    "none", "proc-absolute-symlink", "none", "none",
  ] as const;
  let priorCompletion = Number.NEGATIVE_INFINITY;
  for (let index = 0; index < input.operations.length; index += 1) {
    const operation = input.operations[index]!;
    if (operation.ordinal !== index + 1 || operation.caseId !== SBX052_OPERATION_CASES[index] ||
        operation.channel !== channels[index] || operation.pathClass !== pathClasses[index] ||
        operation.sdkInvocations !== 1 || operation.transportAttemptsObserved !== false ||
        operation.found !== true ||
        operation.returnedBytes < 1 || operation.returnedBytes > 4_096 ||
        operation.rawOutputRetained !== false || !timestamp(operation.startedAt) ||
        !timestamp(operation.completedAt)) return false;
    const started = Date.parse(operation.startedAt);
    const completed = Date.parse(operation.completedAt);
    if (started < priorCompletion || completed < started) return false;
    priorCompletion = completed;
  }
  const initialActive = Date.parse(input.readbacks[0]!.observedAt);
  const initialIndependent = Date.parse(input.readbacks[1]!.observedAt);
  const finalActive = Date.parse(input.readbacks[2]!.observedAt);
  const finalIndependent = Date.parse(input.readbacks[3]!.observedAt);
  const initialEnd = Math.max(...input.readbacks.slice(0, 2).map((entry) => Date.parse(entry.observedAt)));
  const finalStart = Math.min(...input.readbacks.slice(2).map((entry) => Date.parse(entry.observedAt)));
  const finalEnd = Math.max(...input.readbacks.slice(2).map((entry) => Date.parse(entry.observedAt)));
  return initialActive <= initialIndependent && finalActive <= finalIndependent &&
    initialEnd <= Date.parse(input.operations[0]!.startedAt) &&
    Date.parse(input.operations[7]!.completedAt) <= finalStart &&
    finalEnd <= Date.parse(input.operations[8]!.startedAt) &&
    Date.parse(input.operations[8]!.completedAt) <= Date.parse(input.cleanup.completedAt);
}

function exactNamespaceControls(namespace: Sbx052NamespaceEvidence): boolean {
  return namespace.guestObservationCount === 3 && namespace.guestDirectFormatsValid &&
    namespace.guestLinkedFormatsValid && namespace.guestDirectEqualsLinkedEveryTime &&
    namespace.guestBootIdStableAcrossBrackets && namespace.guestBootBytes.length === 6 &&
    namespace.guestBootBytes.every((bytes) => bytes === 37) && namespace.ownedDirectMatched &&
    namespace.ownedSymlinkMatched && namespace.ownedDirectEqualsSymlink &&
    namespace.ownedDirectBytes >= 16 && namespace.ownedDirectBytes <= 128 &&
    namespace.ownedSymlinkBytes === namespace.ownedDirectBytes && namespace.apiDirectProcFormatValid &&
    namespace.apiSymlinkProcFormatValid && namespace.apiDirectProcBytes === 37 &&
    namespace.apiSymlinkProcBytes === 37 && namespace.rawBootIdsRetained === false &&
    namespace.bootIdDigestsRetained === false && namespace.rawCanaryRetained === false &&
    namespace.canaryDigestRetained === false;
}

function exactCleanup(input: Sbx052AssessmentInput): boolean {
  const cleanup = input.cleanup;
  return cleanup.guestCleanupAttempted && cleanup.guestDirectoryRemoved && cleanup.guestProbeRemoved &&
    cleanup.stopAttempted && cleanup.stopped && cleanup.deleteAttempted && cleanup.deleted &&
    cleanup.absenceChecks >= 3 && cleanup.exactNameAbsent && cleanup.prefixListAbsent &&
    cleanup.unknownCreate === false && cleanup.liveLockReleased && cleanup.recoveryJournalDeleted &&
    timestamp(cleanup.completedAt) && cleanup.errors.length === 0;
}

function exactStorage(storage: Sbx052StorageEvidence): boolean {
  return storage.artifactMode === 0o600 && storage.liveLockMode === 0o600 &&
    storage.recoveryJournalMode === 0o600 && storage.rawBootIdsRetained === false &&
    storage.bootIdDigestsRetained === false && storage.rawCanaryRetained === false &&
    storage.canaryDigestRetained === false && storage.guestStdoutRetained === false &&
    storage.guestStderrRetained === false && storage.apiResponseBodiesRetained === false;
}

export function assessSbx052(input: Sbx052AssessmentInput): Sbx052Assessment {
  const signals: string[] = [];
  const controlsPassed = input.executionError === undefined && exactIdentity(input) && exactSandbox(input) &&
    exactReadbacks(input) && exactOperations(input) && exactNamespaceControls(input.namespace) &&
    exactCleanup(input) && exactStorage(input.storage);
  const namespaceDifferentialProved = controlsPassed && input.namespace.apiDirectEqualsSymlink &&
    input.namespace.apiPairDiffersFromStableGuest && !input.namespace.apiDirectEqualsStableGuest &&
    !input.namespace.apiSymlinkEqualsStableGuest;
  const cleanGuestResolution = controlsPassed && input.namespace.apiDirectEqualsSymlink &&
    input.namespace.apiDirectEqualsStableGuest && input.namespace.apiSymlinkEqualsStableGuest &&
    !input.namespace.apiPairDiffersFromStableGuest;
  if (!controlsPassed) signals.push("identity, chronology, controls, retention, or cleanup did not pass exactly");
  if (namespaceDifferentialProved) {
    signals.push("direct and symlinked server file reads agreed but differed from the stable command-visible proc context");
  } else if (cleanGuestResolution) {
    signals.push("direct and symlinked server file reads matched the same command-visible proc context");
  } else if (controlsPassed) {
    signals.push("server file-read results were internally inconsistent or ambiguous");
  }
  if (input.executionError !== undefined) {
    return {
      verdict: "error",
      candidate: false,
      controlsPassed: false,
      namespaceDifferentialProved: false,
      severity: "unknown",
      summary: "SBX-052 execution failed before an attributable result was established.",
      signals,
    };
  }
  if (namespaceDifferentialProved) {
    return {
      verdict: "candidate-proc-context-differential",
      candidate: true,
      controlsPassed: true,
      namespaceDifferentialProved: true,
      severity: "unknown",
      summary: "The session file API exposed a proc/mount context different from the stable context visible to sandbox commands; cause and security impact remain unestablished.",
      signals,
    };
  }
  if (cleanGuestResolution) {
    return {
      verdict: "pass",
      candidate: false,
      controlsPassed: true,
      namespaceDifferentialProved: false,
      severity: "none",
      summary: "The session file API direct and symlinked proc reads matched the stable context visible to sandbox commands.",
      signals,
    };
  }
  return {
    verdict: "indeterminate",
    candidate: false,
    controlsPassed,
    namespaceDifferentialProved: false,
    severity: "unknown",
    summary: "SBX-052 did not produce a clean same-context result or a defensible proc-context differential.",
    signals,
  };
}

export function assertSbx052EvidenceExcludesRawValues(
  value: unknown,
  forbidden: readonly (string | Buffer)[],
): void {
  const serialized = JSON.stringify(value);
  for (const item of forbidden) {
    const text = Buffer.isBuffer(item) ? item.toString("utf8") : item;
    if (text.length > 0 && serialized.includes(text)) {
      throw new Error("SBX-052 evidence retained a raw boot ID or canary value");
    }
  }
}
