import "dotenv/config";

import { lstat, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { fetchDnsAnalytics } from "./analytics.js";
import {
  ANALYTICS_POLL_GUIDANCE_MS,
  EVENT_BRACKET_SKEW_MS,
  OPERATION_ID_PATTERN,
  QUERY_NONCE_PATTERN,
  SHA256_PATTERN,
  TEST_ID,
  ZONE_ID,
  ZONE_NAME,
  analyzeExactPositiveRows,
  assessStage,
  expectedOperationId,
  gateAuthorization,
  publicQueryName,
  sha256Bytes,
  type RunStage,
} from "./shared.js";

interface PendingPacket extends Record<string, unknown> {
  schemaVersion: 1;
  kind: "sbx-001-pending";
  testId: typeof TEST_ID;
  stage: "allow-control" | "deny-control";
  runId: string;
  queryNonce: string;
  startedAt: string;
  proof: {
    queryNameSha256: string;
    expectedOperationId: string;
  };
  queryAttempt: {
    sendStartedAt: string;
    sendCompletedAt: string;
    passed: true;
  };
  historicalPreSend: {
    matchingCollisionCount: 0;
    passed: true;
  };
  cleanup: Record<string, unknown>;
  runReadyForVerification: true;
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function proofKey(): string {
  const value = required("SBX001_PROOF_KEY");
  if (Buffer.byteLength(value) < 32 || Buffer.byteLength(value) > 256 || /[\0\r\n]/u.test(value)) {
    throw new Error("SBX001_PROOF_KEY must contain 32-256 bytes without control characters");
  }
  return value;
}

function cloudflareToken(): string {
  const value = required("CLOUDFLARE_API_TOKEN");
  if (Buffer.byteLength(value) < 20 || Buffer.byteLength(value) > 512 || /[\0\r\n]/u.test(value)) {
    throw new Error("CLOUDFLARE_API_TOKEN must contain 20-512 bytes without control characters");
  }
  return value;
}

function parseArguments(argv: string[]): { pendingPath: string } {
  if (argv.length !== 2 || argv[0] !== "--pending" || !argv[1]) {
    throw new Error("usage: verify.ts --pending <SBX-001 public-control pending artifact>");
  }
  return { pendingPath: resolve(argv[1]) };
}

function isoTimestamp(value: unknown, name: string): string {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) throw new Error(`${name} must be an ISO timestamp`);
  return new Date(value).toISOString();
}

function strictCleanupPassed(cleanup: Record<string, unknown>): boolean {
  const errors = cleanup.errors;
  if (!Array.isArray(errors) || errors.length !== 0) return false;
  return cleanup.stopAttempted === true && cleanup.stopped === true && cleanup.deleteAttempted === true &&
    cleanup.deleted === true && cleanup.deletionAbsenceCheckAttempted === true && cleanup.deletionAbsenceConfirmed === true;
}

function exactObject(value: unknown, name: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${name} must be an object`);
  return value as Record<string, unknown>;
}

async function readPending(path: string, key: string): Promise<{ packet: PendingPacket; bytes: Buffer }> {
  const metadata = await lstat(path);
  if (!metadata.isFile() || (metadata.mode & 0o077) !== 0 || metadata.size <= 0 || metadata.size > 1_000_000) {
    throw new Error("pending artifact must be one private bounded regular file, never a symlink");
  }
  const bytes = await readFile(path);
  const parsed = JSON.parse(bytes.toString("utf8")) as Record<string, unknown>;
  const stage = parsed.stage;
  const proof = exactObject(parsed.proof, "proof");
  const queryAttempt = exactObject(parsed.queryAttempt, "queryAttempt");
  const historical = exactObject(parsed.historicalPreSend, "historicalPreSend");
  const cleanup = exactObject(parsed.cleanup, "cleanup");
  const runId = parsed.runId;
  const queryNonce = parsed.queryNonce;
  if (parsed.schemaVersion !== 1 || parsed.kind !== "sbx-001-pending" || parsed.testId !== TEST_ID ||
    (stage !== "allow-control" && stage !== "deny-control") ||
    typeof runId !== "string" || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u.test(runId) ||
    typeof queryNonce !== "string" || !QUERY_NONCE_PATTERN.test(queryNonce) ||
    parsed.runReadyForVerification !== true || queryAttempt.passed !== true ||
    historical.passed !== true || historical.matchingCollisionCount !== 0 || !strictCleanupPassed(cleanup)) {
    throw new Error("pending artifact failed exact SBX-001 public-control prerequisites");
  }
  const queryNameSha256 = proof.queryNameSha256;
  const operationId = proof.expectedOperationId;
  if (typeof queryNameSha256 !== "string" || !SHA256_PATTERN.test(queryNameSha256) ||
    typeof operationId !== "string" || !OPERATION_ID_PATTERN.test(operationId)) {
    throw new Error("pending artifact contains invalid proof identifiers");
  }
  const queryName = publicQueryName(stage, queryNonce);
  if (sha256Bytes(queryName) !== queryNameSha256 ||
    expectedOperationId(key, runId, stage, queryNameSha256) !== operationId) {
    throw new Error("pending artifact proof receipt does not match its deterministic query identity");
  }
  isoTimestamp(parsed.startedAt, "run startedAt");
  isoTimestamp(queryAttempt.sendStartedAt, "sendStartedAt");
  isoTimestamp(queryAttempt.sendCompletedAt, "sendCompletedAt");
  return { packet: parsed as PendingPacket, bytes };
}

async function main(): Promise<void> {
  const { pendingPath } = parseArguments(process.argv.slice(2));
  const key = proofKey();
  const token = cloudflareToken();
  const { packet, bytes } = await readPending(pendingPath, key);
  let exactQueryName = publicQueryName(packet.stage, packet.queryNonce);
  const sendStartedAt = isoTimestamp(packet.queryAttempt.sendStartedAt, "sendStartedAt");
  const sendCompletedAt = isoTimestamp(packet.queryAttempt.sendCompletedAt, "sendCompletedAt");
  const verificationStartedAt = new Date().toISOString();
  const windowStart = new Date(Date.parse(sendStartedAt) - EVENT_BRACKET_SKEW_MS).toISOString();
  const windowEnd = new Date().toISOString();
  const fetched = await fetchDnsAnalytics({
    token,
    start: windowStart,
    end: windowEnd,
    queryName: exactQueryName,
  });
  const analysis = analyzeExactPositiveRows({
    rows: fetched.rows,
    expectedQueryName: exactQueryName,
    expectedQueryNameSha256: packet.proof.queryNameSha256,
    expectedOperationId: packet.proof.expectedOperationId,
    runId: packet.runId,
    stage: packet.stage,
    proofKey: key,
    bracket: { sendStartedAt, sendCompletedAt },
  });
  const assessment = assessStage({
    stage: packet.stage,
    runReadyForVerification: true,
    cleanupPassed: true,
    analysis,
  });
  const eligibleOutcome = packet.stage === "allow-control" ? "allow-observed" : "signal-medium";
  const authorization = assessment.outcome === eligibleOutcome
    ? gateAuthorization(key, packet.stage, packet.runId, eligibleOutcome, packet.proof.expectedOperationId)
    : undefined;
  const ageAtVerificationMs = Date.now() - Date.parse(sendCompletedAt);
  const sidecar = {
    schemaVersion: 1,
    kind: "sbx-001-verification",
    visibility: "private",
    testId: TEST_ID,
    stage: packet.stage,
    runId: packet.runId,
    outcome: assessment.outcome,
    candidate: assessment.candidate,
    secretPhaseAuthorized: assessment.secretPhaseAuthorized,
    maximumDemonstratedImpact: assessment.maximumDemonstratedImpact,
    summary: assessment.summary,
    operationId: packet.proof.expectedOperationId,
    hmacReceipt: packet.proof.expectedOperationId,
    ...(authorization ? { gateAuthorization: authorization } : {}),
    pendingArtifactSha256: sha256Bytes(bytes),
    cloudflareScope: {
      dataset: "zone.dnsAnalyticsAdaptive",
      zoneId: ZONE_ID,
      zoneName: ZONE_NAME,
      exactQueryNameFilter: true,
      expectedQueryType: "A",
      positiveRowsOnly: true,
      absenceCanPass: false,
    },
    analyticsFetch: {
      verificationStartedAt,
      verificationCompletedAt: new Date().toISOString(),
      windowStart,
      windowEnd,
      responseByteLength: fetched.responseByteLength,
      sampleIntervalRequested: fetched.sampleIntervalRequested,
      sampleIntervalAvailable: fetched.sampleIntervalAvailable,
      ageAtVerificationMs,
      guidanceMaturityMs: ANALYTICS_POLL_GUIDANCE_MS,
      guidanceMaturityReached: ageAtVerificationMs >= ANALYTICS_POLL_GUIDANCE_MS,
      absenceInterpretation: "no-candidate-observed-or-indeterminate-only",
    },
    analysis,
  };
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? dirname(pendingPath));
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const sidecarPath = resolve(
    artifactsDirectory,
    `SBX-001-${packet.stage}-${packet.runId}-verification-${Date.now()}-private.json`,
  );
  const serialized = `${JSON.stringify(sidecar, null, 2)}\n`;
  const forbidden = [key, token, exactQueryName];
  exactQueryName = "";
  if (forbidden.some((value) => value && serialized.includes(value)) || /"queryName"\s*:/u.test(serialized)) {
    throw new Error("refusing to persist a token, proof key, or raw query name");
  }
  await writeFile(sidecarPath, serialized, { mode: 0o600, flag: "wx" });
  process.stdout.write(`${JSON.stringify({
    testId: TEST_ID,
    stage: packet.stage,
    runId: packet.runId,
    outcome: assessment.outcome,
    candidate: assessment.candidate,
    secretPhaseAuthorized: assessment.secretPhaseAuthorized,
    maximumDemonstratedImpact: assessment.maximumDemonstratedImpact,
    guidanceMaturityReached: ageAtVerificationMs >= ANALYTICS_POLL_GUIDANCE_MS,
    exactPositiveObservationCount: analysis.exactObservationCount,
    sidecarPath,
    nextStep: authorization
      ? packet.stage === "allow-control"
        ? `run deny-control with --gate ${sidecarPath}`
        : `run deny-secret with --gate ${sidecarPath}; keep that process alive for its bounded analytics window`
      : "do not continue to the next stage; adaptive-analytics absence is never a pass",
  }, null, 2)}\n`);
  if (!authorization) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
