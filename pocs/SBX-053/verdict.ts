import { createHmac, timingSafeEqual } from "node:crypto";

export const SBX053_TEST_ID = "SBX-053" as const;
export const SBX053_SURFACES = [
  "remote-command",
  "repo-config",
  "worktree-config",
  "credential-helper-config",
  "global-config",
  "dynamic-config",
  "credential-store",
  "dynamic-credential-store",
  "relevant-environment",
  "self-cmdline",
  "parent-cmdline",
  "init-cmdline",
  "self-environ",
  "parent-environ",
  "init-environ",
  "askpass-script",
] as const;

export type Sbx053Surface = typeof SBX053_SURFACES[number];

export interface Sbx053CredentialObservation {
  surface: Sbx053Surface;
  length: number;
  hmacSha256: string;
}

export interface Sbx053ScanResult {
  schemaVersion: 1;
  testId: typeof SBX053_TEST_ID;
  operation: "scan";
  complete: boolean;
  surfacesChecked: Sbx053Surface[];
  observations: Sbx053CredentialObservation[];
  candidatesTruncated: boolean;
}

export interface Sbx053ImpactResult {
  schemaVersion: 1;
  testId: typeof SBX053_TEST_ID;
  operation: "impact";
  scanComplete: boolean;
  credentialMatched: boolean;
  credentialSurface: Sbx053Surface | null;
  localRefAbsentBefore: boolean;
  remoteRefAbsentBefore: boolean;
  sourceCommitPresentBefore: boolean;
  commitProbeExitCode: 128 | null;
  commitAbsentBefore: boolean;
  anonymousFetchDenied: boolean;
  anonymousFetchExitCode: 128 | null;
  anonymousHttpStatus: 401 | 404 | null;
  anonymousTransportAttributed: boolean;
  anonymousControlRefDeleted: boolean;
  fetchSucceeded: boolean;
  fetchedCommitExact: boolean;
  sentinelLength: number | null;
  sentinelHmacSha256: string | null;
  temporaryRefDeleted: boolean;
}

export interface Sbx053ExpectedProof {
  length: number;
  hmacSha256: string;
}

export interface Sbx053AssessmentInput {
  sourceCloneSucceeded: boolean;
  sourceRevisionPinned: boolean;
  privateRepositoryAuthorityConfirmed: boolean;
  authorityEvidencePassed: boolean;
  durableSafetyPassed: boolean;
  fixedGuestDigestMatched: boolean;
  sourceCredentialOnlySentInCreateSource: boolean;
  rawCredentialAbsentFromGuestCommand: boolean;
  denyAllConfirmedDuringScan: boolean;
  cleanupSucceeded: boolean;
  scan: Sbx053ScanResult;
  expectedCredential: Sbx053ExpectedProof;
  impact?: Sbx053ImpactResult;
  expectedSentinel?: Sbx053ExpectedProof;
}

export interface Sbx053Assessment {
  verdict: "credential-retention-signal" | "uncloned-ref-access-candidate" | "pass" | "indeterminate";
  candidate: boolean;
  credentialMatched: boolean;
  unclonedRefAccessProved: boolean;
  likelySeverity: "none" | "medium" | "unknown";
  summary: string;
  matchedSurface: Sbx053Surface | null;
}

const HMAC = /^[0-9a-f]{64}$/u;
const MAX_OUTPUT_BYTES = 64 * 1024;
const MAX_OBSERVATIONS = 128;
const SCAN_KEYS = ["schemaVersion", "testId", "operation", "complete", "surfacesChecked",
  "observations", "candidatesTruncated"] as const;
const IMPACT_KEYS = ["schemaVersion", "testId", "operation", "scanComplete", "credentialMatched",
  "credentialSurface", "localRefAbsentBefore", "remoteRefAbsentBefore", "commitAbsentBefore",
  "sourceCommitPresentBefore", "commitProbeExitCode", "anonymousFetchDenied",
  "anonymousFetchExitCode", "anonymousHttpStatus", "anonymousTransportAttributed",
  "anonymousControlRefDeleted", "fetchSucceeded", "fetchedCommitExact",
  "sentinelLength", "sentinelHmacSha256", "temporaryRefDeleted"] as const;

function exactKeys(value: object, expected: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === expected.length && expected.every((key) =>
    Object.prototype.hasOwnProperty.call(value, key));
}

function isSurface(value: unknown): value is Sbx053Surface {
  return typeof value === "string" && (SBX053_SURFACES as readonly string[]).includes(value);
}

function canonicalProof(value: Sbx053ExpectedProof): boolean {
  return Number.isSafeInteger(value.length) && value.length >= 1 && value.length <= 4_096 &&
    HMAC.test(value.hmacSha256);
}

function exactDigest(left: string, right: string): boolean {
  return HMAC.test(left) && HMAC.test(right) && left.length === right.length && timingSafeEqual(
    Buffer.from(left, "ascii"),
    Buffer.from(right, "ascii"),
  );
}

function parseLine(stdout: string, stderr: string, exitCode: number): Record<string, unknown> {
  if (exitCode !== 0 || stderr !== "" || Buffer.byteLength(stdout, "utf8") > MAX_OUTPUT_BYTES ||
      !stdout.endsWith("\n") || stdout.indexOf("\n") !== stdout.length - 1) {
    throw new Error("SBX-053 guest output was not one successful bounded JSON line");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout.slice(0, -1));
  } catch {
    throw new Error("SBX-053 guest output was not JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("SBX-053 guest output was not an object");
  }
  return parsed as Record<string, unknown>;
}

function parseObservation(value: unknown): Sbx053CredentialObservation {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      !exactKeys(value, ["surface", "length", "hmacSha256"])) {
    throw new Error("SBX-053 credential observation fields were not exact");
  }
  const item = value as Record<string, unknown>;
  if (!isSurface(item.surface) || typeof item.length !== "number" ||
      !Number.isSafeInteger(item.length) || item.length < 1 || item.length > 4_096 ||
      typeof item.hmacSha256 !== "string" || !HMAC.test(item.hmacSha256)) {
    throw new Error("SBX-053 credential observation was invalid");
  }
  return item as unknown as Sbx053CredentialObservation;
}

export function parseSbx053Scan(stdout: string, stderr: string, exitCode: number): Sbx053ScanResult {
  const value = parseLine(stdout, stderr, exitCode);
  if (!exactKeys(value, SCAN_KEYS) || value.schemaVersion !== 1 ||
      value.testId !== SBX053_TEST_ID || value.operation !== "scan" ||
      typeof value.complete !== "boolean" || typeof value.candidatesTruncated !== "boolean" ||
      !Array.isArray(value.surfacesChecked) || !Array.isArray(value.observations) ||
      value.observations.length > MAX_OBSERVATIONS ||
      (value.surfacesChecked as unknown[]).length !== SBX053_SURFACES.length ||
      !SBX053_SURFACES.every((surface, index) =>
        (value.surfacesChecked as unknown[])[index] === surface)) {
    throw new Error("SBX-053 scan result was invalid");
  }
  if (value.candidatesTruncated && value.complete) {
    throw new Error("SBX-053 scan truncation metadata was inconsistent");
  }
  const observations = value.observations.map(parseObservation);
  const dedupe = new Set(observations.map((item) => `${item.surface}\0${item.hmacSha256}`));
  if (dedupe.size !== observations.length) throw new Error("SBX-053 scan observations were duplicated");
  return { ...value, observations } as unknown as Sbx053ScanResult;
}

export function parseSbx053Impact(stdout: string, stderr: string, exitCode: number): Sbx053ImpactResult {
  const value = parseLine(stdout, stderr, exitCode);
  if (!exactKeys(value, IMPACT_KEYS) || value.schemaVersion !== 1 ||
      value.testId !== SBX053_TEST_ID || value.operation !== "impact" ||
      typeof value.scanComplete !== "boolean" || typeof value.credentialMatched !== "boolean" ||
      (value.credentialSurface !== null && !isSurface(value.credentialSurface)) ||
      typeof value.localRefAbsentBefore !== "boolean" || typeof value.remoteRefAbsentBefore !== "boolean" ||
      typeof value.sourceCommitPresentBefore !== "boolean" ||
      (value.commitProbeExitCode !== null && value.commitProbeExitCode !== 128) ||
      typeof value.commitAbsentBefore !== "boolean" || typeof value.anonymousFetchDenied !== "boolean" ||
      (value.anonymousFetchExitCode !== null && value.anonymousFetchExitCode !== 128) ||
      (value.anonymousHttpStatus !== null && value.anonymousHttpStatus !== 401 &&
        value.anonymousHttpStatus !== 404) ||
      typeof value.anonymousTransportAttributed !== "boolean" ||
      typeof value.anonymousControlRefDeleted !== "boolean" || typeof value.fetchSucceeded !== "boolean" ||
      typeof value.fetchedCommitExact !== "boolean" || typeof value.temporaryRefDeleted !== "boolean") {
    throw new Error("SBX-053 impact result was invalid");
  }
  const absentSentinel = value.sentinelLength === null && value.sentinelHmacSha256 === null;
  const presentSentinel = typeof value.sentinelLength === "number" &&
    Number.isSafeInteger(value.sentinelLength) && value.sentinelLength >= 1 && value.sentinelLength <= 8_192 &&
    typeof value.sentinelHmacSha256 === "string" && HMAC.test(value.sentinelHmacSha256);
  if ((!absentSentinel && !presentSentinel) ||
      (value.credentialMatched !== (value.credentialSurface !== null)) ||
      (value.commitAbsentBefore !== (value.commitProbeExitCode === 128)) ||
      (value.anonymousFetchDenied !== value.anonymousTransportAttributed) ||
      (value.anonymousTransportAttributed !==
        (value.anonymousFetchExitCode === 128 &&
          (value.anonymousHttpStatus === 401 || value.anonymousHttpStatus === 404))) ||
      (value.fetchedCommitExact && !value.fetchSucceeded) ||
      (presentSentinel && !value.fetchedCommitExact)) {
    throw new Error("SBX-053 impact result relationships were invalid");
  }
  return value as unknown as Sbx053ImpactResult;
}

export function expectedSbx053Proof(secret: string | Buffer, nonce: string): Sbx053ExpectedProof {
  if (!/^[0-9a-f]{64}$/u.test(nonce)) throw new Error("SBX-053 nonce was invalid");
  const bytes = Buffer.isBuffer(secret) ? secret : Buffer.from(secret, "utf8");
  if (bytes.length < 1 || bytes.length > 4_096) throw new Error("SBX-053 proof secret length was invalid");
  return {
    length: bytes.length,
    hmacSha256: createHmac("sha256", bytes).update(nonce, "ascii").digest("hex"),
  };
}

export function findSbx053CredentialMatch(
  scan: Sbx053ScanResult,
  expected: Sbx053ExpectedProof,
): Sbx053CredentialObservation | undefined {
  if (!canonicalProof(expected)) return undefined;
  return scan.observations.find((item) => item.length === expected.length &&
    exactDigest(item.hmacSha256, expected.hmacSha256));
}

function coreControls(input: Sbx053AssessmentInput): boolean {
  return input.sourceCloneSucceeded && input.sourceRevisionPinned &&
    input.privateRepositoryAuthorityConfirmed &&
    input.authorityEvidencePassed && input.durableSafetyPassed &&
    input.fixedGuestDigestMatched && input.sourceCredentialOnlySentInCreateSource &&
    input.rawCredentialAbsentFromGuestCommand && input.denyAllConfirmedDuringScan &&
    input.cleanupSucceeded && canonicalProof(input.expectedCredential);
}

export function assessSbx053(input: Sbx053AssessmentInput): Sbx053Assessment {
  const match = findSbx053CredentialMatch(input.scan, input.expectedCredential);
  if (!coreControls(input)) {
    return {
      verdict: "indeterminate",
      candidate: false,
      credentialMatched: match !== undefined,
      unclonedRefAccessProved: false,
      likelySeverity: "unknown",
      summary: "A source, scope, guest-integrity, policy, proof, or cleanup control failed.",
      matchedSurface: match?.surface ?? null,
    };
  }

  if (!match) {
    return input.scan.complete
      ? {
          verdict: "pass",
          candidate: false,
          credentialMatched: false,
          unclonedRefAccessProved: false,
          likelySeverity: "none",
          summary: "No tested guest-visible surface produced the exact source credential proof.",
          matchedSurface: null,
        }
      : {
          verdict: "indeterminate",
          candidate: false,
          credentialMatched: false,
          unclonedRefAccessProved: false,
          likelySeverity: "unknown",
          summary: "The bounded guest scan was incomplete and did not prove credential recovery.",
          matchedSurface: null,
        };
  }

  const impact = input.impact;
  const sentinel = input.expectedSentinel;
  const unclonedRefAccessProved = impact !== undefined && sentinel !== undefined &&
    canonicalProof(sentinel) && impact.credentialMatched &&
    impact.credentialSurface === match.surface && impact.localRefAbsentBefore &&
    impact.remoteRefAbsentBefore && impact.sourceCommitPresentBefore &&
    impact.commitProbeExitCode === 128 && impact.commitAbsentBefore &&
    impact.anonymousFetchDenied && impact.anonymousFetchExitCode === 128 &&
    (impact.anonymousHttpStatus === 401 || impact.anonymousHttpStatus === 404) &&
    impact.anonymousTransportAttributed &&
    impact.anonymousControlRefDeleted && impact.fetchSucceeded && impact.fetchedCommitExact &&
    impact.temporaryRefDeleted &&
    impact.sentinelLength === sentinel.length && impact.sentinelHmacSha256 !== null &&
    exactDigest(impact.sentinelHmacSha256, sentinel.hmacSha256);

  if (unclonedRefAccessProved) {
    return {
      verdict: "uncloned-ref-access-candidate",
      candidate: true,
      credentialMatched: true,
      unclonedRefAccessProved: true,
      likelySeverity: "medium",
      summary: "The guest recovered the exact bootstrap credential and used it to read a proved-uncloned orphan ref.",
      matchedSurface: match.surface,
    };
  }
  return {
    verdict: "credential-retention-signal",
    candidate: false,
    credentialMatched: true,
    unclonedRefAccessProved: false,
    likelySeverity: "unknown",
    summary: "The exact source credential was retained, but reportability requires the private uncloned-ref impact control.",
    matchedSurface: match.surface,
  };
}

export function assertSbx053EvidenceExcludesRawSecrets(
  evidence: unknown,
  forbidden: readonly (string | Buffer)[],
): void {
  const serialized = JSON.stringify(evidence);
  for (const raw of forbidden) {
    const secret = Buffer.isBuffer(raw) ? raw.toString("utf8") : raw;
    const encoded = secret.length === 0 ? "" : JSON.stringify(secret).slice(1, -1);
    if (secret.length > 0 && (serialized.includes(secret) || serialized.includes(encoded))) {
      throw new Error("SBX-053 evidence retained raw controller-only material");
    }
  }
}
