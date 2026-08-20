import { describe, expect, it } from "vitest";
import {
  assessSbx053,
  assertSbx053EvidenceExcludesRawSecrets,
  expectedSbx053Proof,
  parseSbx053Impact,
  parseSbx053Scan,
  type Sbx053AssessmentInput,
  type Sbx053ImpactResult,
  type Sbx053ScanResult,
  SBX053_SURFACES,
} from "../pocs/SBX-053/verdict.js";

const TOKEN = "offline-controller-only-git-token-ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const SENTINEL = "offline-uncloned-orphan-ref-sentinel-ABCDEFGHIJKLMNOPQRSTUVWXYZ\n";
const NONCE = "ab".repeat(32);
const CHALLENGE = "cd".repeat(32);
const tokenProof = expectedSbx053Proof(TOKEN, NONCE);
const sentinelProof = expectedSbx053Proof(SENTINEL, CHALLENGE);

function scan(matched = false, complete = true): Sbx053ScanResult {
  return {
    schemaVersion: 1,
    testId: "SBX-053",
    operation: "scan",
    complete,
    surfacesChecked: [...SBX053_SURFACES],
    observations: matched ? [{ surface: "repo-config", ...tokenProof }] : [],
    candidatesTruncated: false,
  };
}

function impact(): Sbx053ImpactResult {
  return {
    schemaVersion: 1,
    testId: "SBX-053",
    operation: "impact",
    scanComplete: true,
    credentialMatched: true,
    credentialSurface: "repo-config",
    localRefAbsentBefore: true,
    remoteRefAbsentBefore: true,
    sourceCommitPresentBefore: true,
    commitProbeExitCode: 128,
    commitAbsentBefore: true,
    anonymousFetchDenied: true,
    anonymousFetchExitCode: 128,
    anonymousHttpStatus: 404,
    anonymousTransportAttributed: true,
    anonymousControlRefDeleted: true,
    fetchSucceeded: true,
    fetchedCommitExact: true,
    sentinelLength: sentinelProof.length,
    sentinelHmacSha256: sentinelProof.hmacSha256,
    temporaryRefDeleted: true,
  };
}

function input(matched = false): Sbx053AssessmentInput {
  return {
    sourceCloneSucceeded: true,
    sourceRevisionPinned: true,
    privateRepositoryAuthorityConfirmed: true,
    authorityEvidencePassed: true,
    durableSafetyPassed: true,
    fixedGuestDigestMatched: true,
    sourceCredentialOnlySentInCreateSource: true,
    rawCredentialAbsentFromGuestCommand: true,
    denyAllConfirmedDuringScan: true,
    cleanupSucceeded: true,
    scan: scan(matched),
    expectedCredential: tokenProof,
  };
}

describe("SBX-053 verdict", () => {
  it("passes only a complete scan with no exact source credential proof", () => {
    expect(assessSbx053(input())).toMatchObject({
      verdict: "pass",
      candidate: false,
      credentialMatched: false,
      likelySeverity: "none",
    });
    const incomplete = input();
    incomplete.scan = scan(false, false);
    expect(assessSbx053(incomplete).verdict).toBe("indeterminate");
  });

  it("classifies an exact controller-token HMAC as a non-reportable retention signal", () => {
    expect(assessSbx053(input(true))).toEqual({
      verdict: "credential-retention-signal",
      candidate: false,
      credentialMatched: true,
      unclonedRefAccessProved: false,
      likelySeverity: "unknown",
      summary: "The exact source credential was retained, but reportability requires the private uncloned-ref impact control.",
      matchedSurface: "repo-config",
    });
  });

  it("records the stronger one-repo orphan-ref proof only with every absence and digest control", () => {
    const value = input(true);
    value.impact = impact();
    value.expectedSentinel = sentinelProof;
    expect(assessSbx053(value)).toMatchObject({
      verdict: "uncloned-ref-access-candidate",
      candidate: true,
      unclonedRefAccessProved: true,
      likelySeverity: "medium",
    });
    value.impact = { ...impact(), scanComplete: false };
    expect(assessSbx053(value)).toMatchObject({
      verdict: "uncloned-ref-access-candidate",
      candidate: true,
      likelySeverity: "medium",
    });

    for (const field of ["localRefAbsentBefore", "remoteRefAbsentBefore", "sourceCommitPresentBefore",
      "commitAbsentBefore", "anonymousFetchDenied", "anonymousTransportAttributed",
      "anonymousControlRefDeleted", "fetchSucceeded", "fetchedCommitExact",
      "temporaryRefDeleted"] as const) {
      const broken = input(true);
      broken.impact = { ...impact(), [field]: false };
      broken.expectedSentinel = sentinelProof;
      expect(assessSbx053(broken)).toMatchObject({
        verdict: "credential-retention-signal",
        candidate: false,
        unclonedRefAccessProved: false,
      });
    }
  });

  it("withholds a candidate when any core attribution or cleanup control fails", () => {
    const candidate = input(true);
    for (const field of ["sourceCloneSucceeded", "sourceRevisionPinned",
      "privateRepositoryAuthorityConfirmed",
      "authorityEvidencePassed", "durableSafetyPassed",
      "fixedGuestDigestMatched", "sourceCredentialOnlySentInCreateSource",
      "rawCredentialAbsentFromGuestCommand", "denyAllConfirmedDuringScan", "cleanupSucceeded"] as const) {
      expect(assessSbx053({ ...candidate, [field]: false })).toMatchObject({
        verdict: "indeterminate",
        candidate: false,
      });
    }
  });
});

describe("SBX-053 strict guest parsers and redaction", () => {
  it("accepts the exact scan and impact schemas", () => {
    expect(parseSbx053Scan(`${JSON.stringify(scan(true))}\n`, "", 0)).toEqual(scan(true));
    expect(parseSbx053Impact(`${JSON.stringify(impact())}\n`, "", 0)).toEqual(impact());
  });

  it("rejects extra fields, raw material, multiple lines, stderr, and inconsistent impact", () => {
    expect(() => parseSbx053Scan(`${JSON.stringify({ ...scan(true), rawToken: TOKEN })}\n`, "", 0))
      .toThrow();
    const line = `${JSON.stringify(scan(true))}\n`;
    expect(() => parseSbx053Scan(`${line}${line}`, "", 0)).toThrow();
    expect(() => parseSbx053Scan(line, "unexpected", 0)).toThrow();
    expect(() => parseSbx053Scan(line, "", 1)).toThrow();
    expect(() => parseSbx053Impact(`${JSON.stringify({
      ...impact(),
      fetchSucceeded: false,
      fetchedCommitExact: true,
    })}\n`, "", 0)).toThrow();
    expect(() => parseSbx053Impact(`${JSON.stringify({
      ...impact(),
      commitProbeExitCode: 1,
      commitAbsentBefore: false,
    })}\n`, "", 0)).toThrow();
    const transportFailure = {
      ...impact(),
      anonymousFetchDenied: false,
      anonymousFetchExitCode: 128 as const,
      anonymousHttpStatus: null,
      anonymousTransportAttributed: false,
      fetchSucceeded: false,
      fetchedCommitExact: false,
      sentinelLength: null,
      sentinelHmacSha256: null,
    };
    expect(parseSbx053Impact(`${JSON.stringify(transportFailure)}\n`, "", 0))
      .toEqual(transportFailure);
  });

  it("permits HMAC evidence but rejects either raw controller-only secret recursively", () => {
    const safe = { tokenProof, sentinelProof };
    expect(() => assertSbx053EvidenceExcludesRawSecrets(safe, [TOKEN, SENTINEL])).not.toThrow();
    expect(() => assertSbx053EvidenceExcludesRawSecrets({ safe, nested: TOKEN }, [TOKEN])).toThrow();
    expect(() => assertSbx053EvidenceExcludesRawSecrets({ safe, nested: SENTINEL }, [SENTINEL])).toThrow();
  });
});
