import { describe, expect, it } from "vitest";
import {
  assessForkEnvOverride,
  assertSerializedEvidenceExcludesRawValues,
  expectedDigest,
  parseGuestDigest,
  type DigestObservation,
  type ForkEnvOverrideAssessmentInput,
} from "../pocs/SBX-045/verdict.js";

const sourceValue = "source-synthetic-value-that-is-never-an-artifact";
const overrideValue = "target-synthetic-value-that-is-never-an-artifact";
const sourceExpected = expectedDigest(sourceValue);
const overrideExpected = expectedDigest(overrideValue);

function observed(expected = overrideExpected): DigestObservation {
  return {
    schemaVersion: 1,
    testId: "SBX-045",
    present: true,
    length: expected.length,
    sha256: expected.sha256,
  };
}

function validInput(): ForkEnvOverrideAssessmentInput {
  return {
    sourceNameFreshAndExact: true,
    targetNameFreshAndExact: true,
    sourceAndTargetNamesDistinct: true,
    sourceSessionExact: true,
    targetSessionExact: true,
    sourceAndTargetSessionsDistinct: true,
    sourceDenyAllReadback: true,
    targetDenyAllReadback: true,
    sourceSnapshotExact: true,
    targetForkAttributedToSource: true,
    sourceDigestControlPassed: true,
    inheritanceControlEnabled: false,
    inheritanceControlPassed: true,
    fixedGuestCommandOnly: true,
    commandLevelSyntheticKeyAbsent: true,
    sourceExpected,
    overrideExpected,
    targetObserved: observed(),
  };
}

describe("SBX-045 fork environment verdict", () => {
  it("reports a candidate only for the exact source A digest in the target", () => {
    expect(assessForkEnvOverride({
      ...validInput(),
      targetObserved: observed(sourceExpected),
    })).toEqual({
      verdict: "candidate",
      candidate: true,
      summary: "The target fork retained the exact source digest despite an explicit same-key override.",
      targetClass: "exact-source",
    });
  });

  it("passes only for the exact explicit override B digest", () => {
    expect(assessForkEnvOverride(validInput())).toMatchObject({
      verdict: "pass",
      candidate: false,
      targetClass: "exact-override",
    });
  });

  it("classifies unset and every third value as indeterminate", () => {
    const unset: DigestObservation = {
      schemaVersion: 1,
      testId: "SBX-045",
      present: false,
      length: 0,
      sha256: null,
    };
    const third = expectedDigest("neither-controlled-value");
    expect(assessForkEnvOverride({ ...validInput(), targetObserved: unset })).toMatchObject({
      verdict: "indeterminate",
      targetClass: "unset",
    });
    expect(assessForkEnvOverride({
      ...validInput(),
      targetObserved: observed(third),
    })).toMatchObject({ verdict: "indeterminate", targetClass: "other" });
  });

  it("withholds a candidate when any required lifecycle or integrity control fails", () => {
    const candidate = {
      ...validInput(),
      targetObserved: observed(sourceExpected),
    };
    for (const field of [
      "sourceNameFreshAndExact",
      "targetNameFreshAndExact",
      "sourceAndTargetNamesDistinct",
      "sourceSessionExact",
      "targetSessionExact",
      "sourceAndTargetSessionsDistinct",
      "sourceDenyAllReadback",
      "targetDenyAllReadback",
      "sourceSnapshotExact",
      "targetForkAttributedToSource",
      "sourceDigestControlPassed",
      "fixedGuestCommandOnly",
      "commandLevelSyntheticKeyAbsent",
    ] as const) {
      expect(assessForkEnvOverride({ ...candidate, [field]: false })).toMatchObject({
        verdict: "indeterminate",
        candidate: false,
      });
    }
    expect(assessForkEnvOverride({
      ...candidate,
      inheritanceControlEnabled: true,
      inheritanceControlPassed: false,
    })).toMatchObject({ verdict: "indeterminate", candidate: false });
  });

  it("rejects a degenerate A equals B control set", () => {
    expect(assessForkEnvOverride({
      ...validInput(),
      sourceExpected: overrideExpected,
      targetObserved: observed(overrideExpected),
    })).toMatchObject({ verdict: "indeterminate", candidate: false });
  });
});

describe("SBX-045 fixed guest result parser", () => {
  const valid = `${JSON.stringify(observed())}\n`;

  it("accepts only the fixed presence/length/SHA-256 schema", () => {
    expect(parseGuestDigest(valid, "", 0)).toEqual(observed());
    expect(parseGuestDigest(`${JSON.stringify({
      schemaVersion: 1,
      testId: "SBX-045",
      present: false,
      length: 0,
      sha256: null,
    })}\n`, "", 0)).toMatchObject({ present: false, length: 0, sha256: null });
  });

  it("rejects extra fields, raw values, multiple lines, stderr, and failed commands", () => {
    expect(() => parseGuestDigest(`${JSON.stringify({
      ...observed(),
      rawValue: sourceValue,
    })}\n`, "", 0)).toThrow();
    expect(() => parseGuestDigest(`${valid}${valid}`, "", 0)).toThrow();
    expect(() => parseGuestDigest(valid, "unexpected", 0)).toThrow();
    expect(() => parseGuestDigest(valid, "", 1)).toThrow();
  });

  it("rejects inconsistent absence and noncanonical digests", () => {
    expect(() => parseGuestDigest(`${JSON.stringify({
      schemaVersion: 1,
      testId: "SBX-045",
      present: false,
      length: 1,
      sha256: null,
    })}\n`, "", 0)).toThrow();
    expect(() => parseGuestDigest(`${JSON.stringify({
      schemaVersion: 1,
      testId: "SBX-045",
      present: true,
      length: 1,
      sha256: "A".repeat(64),
    })}\n`, "", 0)).toThrow();
  });
});

describe("SBX-045 artifact redaction guard", () => {
  it("allows digests but rejects either raw controlled value", () => {
    const safe = { sourceExpected, overrideExpected };
    expect(() => assertSerializedEvidenceExcludesRawValues(
      safe,
      [sourceValue, overrideValue],
    )).not.toThrow();
    expect(() => assertSerializedEvidenceExcludesRawValues(
      { ...safe, nested: { value: sourceValue } },
      [sourceValue, overrideValue],
    )).toThrow();
    expect(() => assertSerializedEvidenceExcludesRawValues(
      { ...safe, nested: overrideValue },
      [sourceValue, overrideValue],
    )).toThrow();
  });
});
