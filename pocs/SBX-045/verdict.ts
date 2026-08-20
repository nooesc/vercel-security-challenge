import { createHash, timingSafeEqual } from "node:crypto";

export interface DigestObservation {
  schemaVersion: 1;
  testId: "SBX-045";
  present: boolean;
  length: number;
  sha256: string | null;
}

export interface ExpectedDigest {
  present: true;
  length: number;
  sha256: string;
}

export interface ForkEnvOverrideAssessmentInput {
  sourceNameFreshAndExact: boolean;
  targetNameFreshAndExact: boolean;
  sourceAndTargetNamesDistinct: boolean;
  sourceSessionExact: boolean;
  targetSessionExact: boolean;
  sourceAndTargetSessionsDistinct: boolean;
  sourceDenyAllReadback: boolean;
  targetDenyAllReadback: boolean;
  sourceSnapshotExact: boolean;
  targetForkAttributedToSource: boolean;
  sourceDigestControlPassed: boolean;
  inheritanceControlEnabled: boolean;
  inheritanceControlPassed: boolean;
  fixedGuestCommandOnly: boolean;
  commandLevelSyntheticKeyAbsent: boolean;
  sourceExpected: ExpectedDigest;
  overrideExpected: ExpectedDigest;
  targetObserved: DigestObservation;
}

export interface ForkEnvOverrideAssessment {
  verdict: "candidate" | "pass" | "indeterminate";
  candidate: boolean;
  summary: string;
  targetClass: "exact-source" | "exact-override" | "unset" | "other";
}

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const MAXIMUM_GUEST_STDOUT_BYTES = 512;

function exactKeys(value: object, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) =>
    Object.prototype.hasOwnProperty.call(value, key));
}

export function expectedDigest(value: string): ExpectedDigest {
  return {
    present: true,
    length: Buffer.byteLength(value, "utf8"),
    sha256: createHash("sha256").update(value, "utf8").digest("hex"),
  };
}

export function parseGuestDigest(
  stdout: string,
  stderr: string,
  exitCode: number,
): DigestObservation {
  if (exitCode !== 0) throw new Error("SBX-045 guest command did not exit successfully");
  if (stderr !== "") throw new Error("SBX-045 guest command emitted stderr");
  if (Buffer.byteLength(stdout, "utf8") > MAXIMUM_GUEST_STDOUT_BYTES) {
    throw new Error("SBX-045 guest stdout exceeded its fixed byte limit");
  }
  if (!stdout.endsWith("\n") || stdout.indexOf("\n") !== stdout.length - 1) {
    throw new Error("SBX-045 guest stdout must be exactly one JSON line");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout.slice(0, -1));
  } catch {
    throw new Error("SBX-045 guest stdout was not valid JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed) ||
      !exactKeys(parsed, ["schemaVersion", "testId", "present", "length", "sha256"])) {
    throw new Error("SBX-045 guest result had unexpected or missing fields");
  }
  const value = parsed as Record<string, unknown>;
  if (value.schemaVersion !== 1 || value.testId !== "SBX-045" ||
      typeof value.present !== "boolean" || typeof value.length !== "number" ||
      !Number.isSafeInteger(value.length) || value.length < 0 || value.length > 4_096) {
    throw new Error("SBX-045 guest result was invalid");
  }
  if (value.present === false) {
    if (value.length !== 0 || value.sha256 !== null) {
      throw new Error("SBX-045 absent result carried value metadata");
    }
  } else if (typeof value.sha256 !== "string" || !SHA256_PATTERN.test(value.sha256)) {
    throw new Error("SBX-045 present result lacked one canonical SHA-256 digest");
  }
  return value as unknown as DigestObservation;
}

export function exactDigest(
  observed: DigestObservation,
  expected: ExpectedDigest,
): boolean {
  if (!observed.present || observed.sha256 === null ||
      observed.length !== expected.length || observed.sha256.length !== expected.sha256.length) {
    return false;
  }
  return timingSafeEqual(
    Buffer.from(observed.sha256, "ascii"),
    Buffer.from(expected.sha256, "ascii"),
  );
}

function controlsPassed(input: ForkEnvOverrideAssessmentInput): boolean {
  return input.sourceNameFreshAndExact && input.targetNameFreshAndExact &&
    input.sourceAndTargetNamesDistinct && input.sourceSessionExact &&
    input.targetSessionExact && input.sourceAndTargetSessionsDistinct &&
    input.sourceDenyAllReadback && input.targetDenyAllReadback &&
    input.sourceSnapshotExact && input.targetForkAttributedToSource &&
    input.sourceDigestControlPassed && input.fixedGuestCommandOnly &&
    input.commandLevelSyntheticKeyAbsent &&
    (!input.inheritanceControlEnabled || input.inheritanceControlPassed) &&
    input.sourceExpected.sha256 !== input.overrideExpected.sha256;
}

export function assessForkEnvOverride(
  input: ForkEnvOverrideAssessmentInput,
): ForkEnvOverrideAssessment {
  const exactSource = exactDigest(input.targetObserved, input.sourceExpected);
  const exactOverride = exactDigest(input.targetObserved, input.overrideExpected);
  const targetClass = exactSource
    ? "exact-source"
    : exactOverride
      ? "exact-override"
      : input.targetObserved.present
        ? "other"
        : "unset";

  if (!controlsPassed(input)) {
    return {
      verdict: "indeterminate",
      candidate: false,
      summary: "A required freshness, lifecycle, policy, command-integrity, or control condition failed.",
      targetClass,
    };
  }
  if (targetClass === "exact-source") {
    return {
      verdict: "candidate",
      candidate: true,
      summary: "The target fork retained the exact source digest despite an explicit same-key override.",
      targetClass,
    };
  }
  if (targetClass === "exact-override") {
    return {
      verdict: "pass",
      candidate: false,
      summary: "The target fork exposed the exact explicit override digest.",
      targetClass,
    };
  }
  return {
    verdict: "indeterminate",
    candidate: false,
    summary: "The target value was unset or matched neither controlled synthetic value.",
    targetClass,
  };
}

export function assertSerializedEvidenceExcludesRawValues(
  value: unknown,
  forbidden: readonly string[],
): void {
  const serialized = JSON.stringify(value);
  for (const secret of forbidden) {
    if (secret.length > 0 && serialized.includes(secret)) {
      throw new Error("SBX-045 evidence contained raw controller-only material");
    }
  }
}
