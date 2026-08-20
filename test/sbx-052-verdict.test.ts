import { describe, expect, it } from "vitest";
import {
  assessSbx052,
  assertSbx052EvidenceExcludesRawValues,
  buildSbx052NamespaceEvidence,
  type Sbx052AssessmentInput,
  type Sbx052OperationEvidence,
  SBX052_OPERATION_CASES,
} from "../pocs/SBX-052/verdict.js";

const RUN_ID = "12345678-1234-4abc-8def-1234567890ab";
const NAME = `sbx-052-${RUN_ID}`;
const SESSION = "sbx_abcdefghijklmnopqrstuvwxyz123456";
const GUEST_BOOT = "11111111-2222-4333-8444-555555555555";
const OTHER_BOOT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const CANARY = Buffer.from("can52_abcdefghijklmnopqrstuvwxyzABCDEF\n", "utf8");

function iso(second: number): string {
  return `2026-08-19T00:00:${String(second).padStart(2, "0")}.000Z`;
}

function guest(bootId = GUEST_BOOT) {
  return {
    directBootId: bootId,
    linkedBootId: bootId,
    directBytes: 37,
    linkedBytes: 37,
    ownedLinkTarget: "owned.txt",
    procLinkTarget: "/proc/sys/kernel/random/boot_id",
  };
}

function namespace(apiBoot = GUEST_BOOT) {
  return buildSbx052NamespaceEvidence({
    guest: [guest(), guest(), guest()],
    ownedDirect: CANARY,
    ownedSymlink: CANARY,
    expectedCanary: CANARY,
    apiDirectProc: Buffer.from(`${apiBoot}\n`, "utf8"),
    apiSymlinkProc: Buffer.from(`${apiBoot}\n`, "utf8"),
  });
}

function operations(): Sbx052OperationEvidence[] {
  const channels = [
    "guest-command", "guest-command", "Session.readFile", "Session.readFile", "Session.readFile",
    "guest-command", "Session.readFile", "guest-command", "guest-command",
  ] as const;
  const paths = [
    "none", "none", "owned-file", "owned-relative-symlink", "proc-direct",
    "none", "proc-absolute-symlink", "none", "none",
  ] as const;
  return SBX052_OPERATION_CASES.map((caseId, index) => ({
    ordinal: index + 1,
    caseId,
    channel: channels[index]!,
    pathClass: paths[index]!,
    startedAt: iso(index === 8 ? 20 : 2 + index * 2),
    completedAt: iso(index === 8 ? 21 : 3 + index * 2),
    sdkInvocations: 1,
    transportAttemptsObserved: false,
    found: true,
    returnedBytes: caseId.includes("proc") ? 37 : caseId.startsWith("owned") ? CANARY.length : 128,
    rawOutputRetained: false,
  }));
}

function input(apiBoot = GUEST_BOOT): Sbx052AssessmentInput {
  const tags = { harness: "vsc", test: "SBX-052", run: RUN_ID };
  return {
    identityAndScopePassed: true,
    identity: {
      email: "swve@wearehackerone.com",
      teamId: "team_n98ERpVwV7HqmWRudAyK8sXQ",
      projectId: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
      method: "v2-user-email",
    },
    expected: { runId: RUN_ID, sandboxName: NAME, sessionId: SESSION, tags },
    sandbox: {
      name: NAME,
      sessionId: SESSION,
      persistent: false,
      status: "running",
      networkPolicy: "deny-all",
      routesCount: 0,
      createdAt: iso(0),
      sandboxTimeoutMs: 240_000,
      sessionTimeoutMs: 240_000,
      tags,
    },
    readbacks: [
      { stage: "initial", source: "active", observedAt: iso(0), name: NAME, sessionId: SESSION,
        persistent: false, status: "running", networkPolicy: "deny-all", routesCount: 0,
        sandboxTimeoutMs: 240_000, sessionTimeoutMs: 240_000, tags },
      { stage: "initial", source: "independent", observedAt: iso(1), name: NAME, sessionId: SESSION,
        persistent: false, status: "running", networkPolicy: "deny-all", routesCount: 0,
        sandboxTimeoutMs: 240_000, sessionTimeoutMs: 240_000, tags },
      { stage: "final", source: "active", observedAt: iso(18), name: NAME, sessionId: SESSION,
        persistent: false, status: "running", networkPolicy: "deny-all", routesCount: 0,
        sandboxTimeoutMs: 240_000, sessionTimeoutMs: 240_000, tags },
      { stage: "final", source: "independent", observedAt: iso(19), name: NAME, sessionId: SESSION,
        persistent: false, status: "running", networkPolicy: "deny-all", routesCount: 0,
        sandboxTimeoutMs: 240_000, sessionTimeoutMs: 240_000, tags },
    ],
    operations: operations(),
    namespace: namespace(apiBoot),
    cleanup: {
      guestCleanupAttempted: true,
      guestDirectoryRemoved: true,
      guestProbeRemoved: true,
      stopAttempted: true,
      stopped: true,
      deleteAttempted: true,
      deleted: true,
      absenceChecks: 3,
      exactNameAbsent: true,
      prefixListAbsent: true,
      unknownCreate: false,
      liveLockReleased: true,
      recoveryJournalDeleted: true,
      completedAt: iso(22),
      errors: [],
    },
    storage: {
      artifactMode: 0o600,
      liveLockMode: 0o600,
      recoveryJournalMode: 0o600,
      rawBootIdsRetained: false,
      bootIdDigestsRetained: false,
      rawCanaryRetained: false,
      canaryDigestRetained: false,
      guestStdoutRetained: false,
      guestStderrRetained: false,
      apiResponseBodiesRetained: false,
    },
  };
}

describe("SBX-052 verdict", () => {
  it("passes when both API paths resolve to the stable guest boot ID", () => {
    expect(assessSbx052(input())).toMatchObject({
      verdict: "pass",
      candidate: false,
      controlsPassed: true,
      namespaceDifferentialProved: false,
      severity: "none",
    });
  });

  it("produces a research candidate only for an attributable command/API proc-context differential", () => {
    expect(assessSbx052(input(OTHER_BOOT))).toMatchObject({
      verdict: "candidate-proc-context-differential",
      candidate: true,
      controlsPassed: true,
      namespaceDifferentialProved: true,
      severity: "unknown",
    });
  });

  it("rejects a direct/symlink disagreement as indeterminate", () => {
    const value = input(OTHER_BOOT);
    value.namespace.apiDirectEqualsSymlink = false;
    expect(assessSbx052(value).verdict).toBe("indeterminate");
  });

  it("rejects an unstable guest boot ID as indeterminate", () => {
    const value = input(OTHER_BOOT);
    value.namespace.guestBootIdStableAcrossBrackets = false;
    expect(assessSbx052(value).verdict).toBe("indeterminate");
  });

  it("rejects a missing owned symlink control", () => {
    const value = input(OTHER_BOOT);
    value.namespace.ownedSymlinkMatched = false;
    expect(assessSbx052(value)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
  });

  it("rejects a mismatched independent session readback", () => {
    const value = input(OTHER_BOOT);
    value.readbacks[3]!.sessionId = "sbx_otherotherotherother";
    expect(assessSbx052(value)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
  });

  it("requires actual sandbox and active/independent session timeout readbacks", () => {
    const sandboxTimeout = input(OTHER_BOOT);
    sandboxTimeout.sandbox.sandboxTimeoutMs = null;
    expect(assessSbx052(sandboxTimeout).controlsPassed).toBe(false);

    const sessionTimeout = input(OTHER_BOOT);
    sessionTimeout.sandbox.sessionTimeoutMs = 239_999;
    expect(assessSbx052(sessionTimeout).controlsPassed).toBe(false);

    const independentTimeout = input(OTHER_BOOT);
    independentTimeout.readbacks[3]!.sessionTimeoutMs = 300_000;
    expect(assessSbx052(independentTimeout).controlsPassed).toBe(false);
  });

  it("rejects out-of-order or overlapping operations", () => {
    const value = input(OTHER_BOOT);
    value.operations[6]!.startedAt = iso(1);
    expect(assessSbx052(value)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
  });

  it("requires ordered readback pairs and both final readbacks before guest cleanup", () => {
    const reversedInitial = input(OTHER_BOOT);
    reversedInitial.readbacks[0]!.observedAt = iso(1);
    reversedInitial.readbacks[1]!.observedAt = iso(0);
    expect(assessSbx052(reversedInitial).controlsPassed).toBe(false);

    const cleanupOverlap = input(OTHER_BOOT);
    cleanupOverlap.readbacks[3]!.observedAt = iso(21);
    expect(assessSbx052(cleanupOverlap).controlsPassed).toBe(false);
  });

  it("records SDK invocations without inventing transport-attempt visibility", () => {
    const multipleSdkCalls = input(OTHER_BOOT);
    multipleSdkCalls.operations[4]!.sdkInvocations = 2;
    expect(assessSbx052(multipleSdkCalls).controlsPassed).toBe(false);

    const inventedTransportClaim = input(OTHER_BOOT);
    inventedTransportClaim.operations[4]!.transportAttemptsObserved = true as false;
    expect(assessSbx052(inventedTransportClaim).controlsPassed).toBe(false);
  });

  it("rejects cleanup or private-storage uncertainty", () => {
    const cleanup = input(OTHER_BOOT);
    cleanup.cleanup.liveLockReleased = false;
    expect(assessSbx052(cleanup).controlsPassed).toBe(false);
    const storage = input(OTHER_BOOT);
    storage.storage.artifactMode = 0o644;
    expect(assessSbx052(storage).controlsPassed).toBe(false);
  });

  it("rejects raw-value retention and finds forbidden bytes recursively", () => {
    const value = input(OTHER_BOOT);
    value.namespace.rawBootIdsRetained = true as false;
    expect(assessSbx052(value).controlsPassed).toBe(false);
    expect(() => assertSbx052EvidenceExcludesRawValues({ nested: { value: OTHER_BOOT } }, [OTHER_BOOT]))
      .toThrow(/retained/u);
    expect(() => assertSbx052EvidenceExcludesRawValues({ safe: true }, [OTHER_BOOT, CANARY]))
      .not.toThrow();
  });

  it("does not treat a superficially different API value as a candidate without canonical format", () => {
    const evidence = buildSbx052NamespaceEvidence({
      guest: [guest(), guest(), guest()],
      ownedDirect: CANARY,
      ownedSymlink: CANARY,
      expectedCanary: CANARY,
      apiDirectProc: Buffer.from("not-a-boot-id\n"),
      apiSymlinkProc: Buffer.from("not-a-boot-id\n"),
    });
    expect(evidence.apiDirectEqualsSymlink).toBe(true);
    expect(evidence.apiDirectProcFormatValid).toBe(false);
    const value = input(OTHER_BOOT);
    value.namespace = evidence;
    expect(assessSbx052(value)).toMatchObject({ verdict: "indeterminate", controlsPassed: false });
  });

  it("rejects nil, non-v4, and non-RFC-variant boot identifiers", () => {
    for (const bootId of [
      "00000000-0000-0000-0000-000000000000",
      "11111111-2222-1333-8444-555555555555",
      "11111111-2222-4333-7444-555555555555",
    ]) {
      const evidence = buildSbx052NamespaceEvidence({
        guest: [guest(), guest(), guest()],
        ownedDirect: CANARY,
        ownedSymlink: CANARY,
        expectedCanary: CANARY,
        apiDirectProc: Buffer.from(`${bootId}\n`),
        apiSymlinkProc: Buffer.from(`${bootId}\n`),
      });
      expect(evidence.apiDirectProcFormatValid).toBe(false);
      expect(evidence.apiSymlinkProcFormatValid).toBe(false);

      const guestEvidence = buildSbx052NamespaceEvidence({
        guest: [guest(bootId), guest(bootId), guest(bootId)],
        ownedDirect: CANARY,
        ownedSymlink: CANARY,
        expectedCanary: CANARY,
        apiDirectProc: Buffer.from(`${GUEST_BOOT}\n`),
        apiSymlinkProc: Buffer.from(`${GUEST_BOOT}\n`),
      });
      expect(guestEvidence.guestDirectFormatsValid).toBe(false);
      expect(guestEvidence.guestLinkedFormatsValid).toBe(false);
    }
  });
});
