import "dotenv/config";

import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { APIError, Sandbox, type NetworkPolicy } from "@vercel/sandbox";
import { verifyEligibleAliasToken } from "../eligible-alias-identity.js";
import {
  assessSbx053,
  assertSbx053EvidenceExcludesRawSecrets,
  expectedSbx053Proof,
  findSbx053CredentialMatch,
  parseSbx053Impact,
  parseSbx053Scan,
  type Sbx053Assessment,
  type Sbx053CredentialObservation,
  type Sbx053ExpectedProof,
  type Sbx053ImpactResult,
  type Sbx053ScanResult,
  SBX053_SURFACES,
  SBX053_TEST_ID,
} from "./verdict.js";
import {
  acquireSbx053Lock,
  acquireSbx053RecoveryLock,
  createSettlementReached,
  createSbx053Journal,
  persistSbx053Journal,
  readSbx053Journal,
  releaseSbx053LockAndJournal,
  resumeSbx053InterruptedFinalization,
  safeSbx053Error,
  sbx053ArtifactPath,
  sbx053SandboxName,
  sbx053RecoveryArtifactPath,
  SBX053_CREATE_REQUEST_TIMEOUT_MS,
  SBX053_SANDBOX_TIMEOUT_MS,
  SBX053_UUID,
  type Sbx053HeldLock,
  type Sbx053RecoveryJournal,
  writeSbx053PrivateArtifact,
} from "./safety.js";

export const SBX053_ELIGIBLE_ALIAS = "swve@wearehackerone.com" as const;
export const SBX053_ELIGIBLE_TEAM = "team_n98ERpVwV7HqmWRudAyK8sXQ" as const;
export const SBX053_ELIGIBLE_PROJECT = "prj_CyyVykdN06Nrkla6KidZcecLgbCa" as const;
export const SBX053_SCOPE_CONFIRMATION =
  "I_RECHECKED_SBX053_SCOPE_AND_WILL_USE_ONE_OWNED_DISPOSABLE_PRIVATE_REPO_AND_SHORT_LIVED_TOKEN" as const;
export const SBX053_FIXED_GUEST_SHA256 =
  "78fe6cf5deeffbdfe988e02ab15d226566a2d4fe04774ff9f3c29b4767e6c39a" as const;

const EXPECTED_SDK_VERSION = "3.0.0";
const REPOSITORY_ROOT = fileURLToPath(new URL("../../", import.meta.url));
const GUEST_SOURCE = resolve(REPOSITORY_ROOT, "guest/sbx-053-git-credential-probe.mjs");
const REMOTE_GUEST = "/tmp/sbx-053-git-credential-probe.mjs";
const COMMAND_TIMEOUT_MS = 45_000;
const CONTROL_TIMEOUT_MS = 60_000;
const MAX_GUEST_OUTPUT_BYTES = 64 * 1024;
const COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const BRANCH = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,126}$/u;
const SENTINEL_PATH = /^[A-Za-z0-9._/-]{1,192}$/u;
const GITHUB_INSTALLATION_TOKEN = /^ghs_[A-Za-z0-9._-]{36,4092}$/u;
const FORBIDDEN_RUNTIME_VARIABLES = [
  "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NODE_TLS_REJECT_UNAUTHORIZED",
  "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "SSL_CERT_FILE", "SSL_CERT_DIR",
  "OPENSSL_CONF", "OPENSSL_MODULES", "VERCEL_API_URL",
] as const;

export interface Sbx053Config {
  vercelToken: string;
  teamId: typeof SBX053_ELIGIBLE_TEAM;
  projectId: typeof SBX053_ELIGIBLE_PROJECT;
  expectedAlias: typeof SBX053_ELIGIBLE_ALIAS;
  manualAliasConfirmation?: string;
  gitUrl: string;
  gitUsername: "x-access-token";
  gitToken: string;
  gitTokenExpiresAt: string;
  sourceRevision: string;
  sourceCommit: string;
  impactEnabled: boolean;
  sentinelRef?: string;
  sentinelCommit?: string;
  sentinelPath?: string;
  sentinelValue?: string;
}

export interface Sbx053RecoveryConfig {
  vercelToken: string;
  teamId: typeof SBX053_ELIGIBLE_TEAM;
  projectId: typeof SBX053_ELIGIBLE_PROJECT;
  expectedAlias: typeof SBX053_ELIGIBLE_ALIAS;
  manualAliasConfirmation?: string;
  recoveryRunId: string;
}

export interface Sbx053GitHubAuthorityEvidence {
  provider: "github-app-installation-token";
  repositoryFullName: string;
  repositoryPrivate: true;
  accessibleRepositoryCount: 1;
  repositoryPullProjection: boolean;
  contentsReadProved: true;
  effectivePush: false;
  effectiveAdmin: false;
  effectiveMaintain: false;
  sourceRef: string;
  sourceCommit: string;
  sourceRefRequestEvidenceSha256: string;
  tokenExpiresAt: string;
  remainingLifetimeSeconds: number;
  tokenExpirationEvidenceMethod: "mint-response" | "mint-response-and-get-headers";
  tokenExpirationHeaderCount: 0 | 1 | 2 | 3;
  tokenBindingNonce: string;
  tokenBindingHmacSha256: string;
  requestEvidenceSha256: string;
  rawProviderBodiesRetained: false;
}

export interface Sbx053ChronologyEntry {
  ordinal: number;
  phase: string;
  startedAt: string;
  completedAt: string;
  outcome: "passed" | "failed";
}

export interface Sbx053RunResult {
  runId: string;
  sandboxName: string;
  sessionId: string;
  authority: Sbx053GitHubAuthorityEvidence;
  evidenceBinding: Sbx053EvidenceBinding;
  scan: Sbx053ScanResult;
  impact?: Sbx053ImpactResult;
  assessment: Sbx053Assessment;
  cleanupSucceeded: true;
  evidencePath: string;
}

export interface Sbx053EvidenceBinding {
  schemaVersion: 1;
  runId: string;
  target: {
    teamId: typeof SBX053_ELIGIBLE_TEAM;
    projectId: typeof SBX053_ELIGIBLE_PROJECT;
    sandboxName: string;
    sessionId: string | null;
    repositoryUrl: string;
    repositoryFullName: string;
    sourceRef: string;
    sourceCommit: string;
  };
  credential: {
    nonce: string;
    expected: Sbx053ExpectedProof;
    observed: Sbx053CredentialObservation | null;
  };
  sentinel: {
    ref: string;
    commit: string;
    path: string;
    challenge: string;
    expected: Sbx053ExpectedProof;
  } | null;
}

interface GuestExecution {
  stdout: string;
  stderr: string;
  exitCode: number;
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function boundedSecret(value: string, label: string, minimum = 20, maximum = 4_096): string {
  if (Buffer.byteLength(value, "utf8") < minimum || Buffer.byteLength(value, "utf8") > maximum ||
      value.includes("\0") || /[\r\n]/u.test(value)) {
    throw new Error(`${label} was not one bounded secret`);
  }
  return value;
}

export function isSbx053GitHubInstallationToken(value: unknown): value is string {
  return typeof value === "string" && GITHUB_INSTALLATION_TOKEN.test(value) &&
    !/[\s\p{Cc}\p{Cf}]/u.test(value) && Buffer.byteLength(value, "utf8") <= 4_096;
}

function canonicalRepositoryUrl(raw: string): string {
  const value = new URL(raw);
  if (value.protocol !== "https:" || value.hostname !== "github.com" || value.port !== "" ||
      value.username !== "" || value.password !== "" || value.search !== "" || value.hash !== "" ||
      !/^\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\.git$/u.test(value.pathname)) {
    throw new Error("SBX053_GIT_URL must be one canonical credential-free GitHub HTTPS clone URL");
  }
  return value.toString();
}

function canonicalBranch(raw: string, label: string): string {
  if (!BRANCH.test(raw) || raw.includes("..") || raw.includes("//") || raw.endsWith("/") ||
      raw.includes("@{") || raw.endsWith(".")) throw new Error(`${label} was not a canonical branch`);
  return raw;
}

function canonicalSentinelPath(raw: string): string {
  if (!SENTINEL_PATH.test(raw) || raw.startsWith("/") || raw.split("/").some((part) =>
    part === "" || part === "." || part === "..")) {
    throw new Error("SBX053_SENTINEL_PATH was not one canonical relative path");
  }
  return raw;
}

export function repositoryDirectoryFromUrl(raw: string): string {
  const url = new URL(canonicalRepositoryUrl(raw));
  const name = url.pathname.split("/").at(-1)?.replace(/\.git$/u, "");
  if (!name || !/^[A-Za-z0-9_.-]{1,100}$/u.test(name)) {
    throw new Error("SBX-053 could not derive the repository directory");
  }
  return name;
}

function repositoryFullNameFromUrl(raw: string): string {
  const url = new URL(canonicalRepositoryUrl(raw));
  return url.pathname.slice(1, -".git".length);
}

async function boundedGitHubJson(response: Response): Promise<Record<string, unknown>> {
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^[0-9]{1,7}$/u.test(declared) || Number(declared) > 128 * 1024)) {
    throw new Error("SBX-053 GitHub authority response exceeded the declared byte ceiling");
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > 128 * 1024) {
    throw new Error("SBX-053 GitHub authority response exceeded the byte ceiling");
  }
  let value: unknown;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } finally {
    bytes.fill(0);
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("SBX-053 GitHub authority response was not an object");
  }
  return value as Record<string, unknown>;
}

interface Sbx053TokenExpiration {
  expiresAt: string;
  milliseconds: number;
  remainingLifetimeSeconds: number;
}

function canonicalTokenExpirationMilliseconds(raw: string, source: string): number {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(raw)) {
    throw new Error(`SBX-053 ${source} token expiry was not canonical ISO-8601 UTC`);
  }
  const milliseconds = Date.parse(raw);
  const normalized = Number.isFinite(milliseconds) ? new Date(milliseconds).toISOString() : "";
  const canonical = normalized === raw ||
    (normalized.endsWith(".000Z") && normalized.replace(".000Z", "Z") === raw);
  if (!canonical) {
    throw new Error(`SBX-053 ${source} token expiry was not canonical ISO-8601 UTC`);
  }
  return milliseconds;
}

function tokenExpiration(raw: string, now: number, source: string): Sbx053TokenExpiration {
  const milliseconds = canonicalTokenExpirationMilliseconds(raw, source);
  const remainingLifetimeSeconds = Math.floor((milliseconds - now) / 1_000);
  if (remainingLifetimeSeconds < 300 || remainingLifetimeSeconds > 3_700) {
    throw new Error(`SBX-053 ${source} token expiry was outside the bounded installation-token window`);
  }
  return { expiresAt: raw, milliseconds, remainingLifetimeSeconds };
}

function optionalAuthorityExpiration(response: Response, now: number): Sbx053TokenExpiration | undefined {
  const raw = response.headers.get("github-authentication-token-expiration");
  return raw === null ? undefined : tokenExpiration(raw, now, "authenticated GET header");
}

function githubRequestId(response: Response): string {
  const value = response.headers.get("x-github-request-id");
  if (!value || !/^[A-Za-z0-9:-]{8,128}$/u.test(value)) {
    throw new Error("SBX-053 GitHub request attribution header was absent or invalid");
  }
  return value;
}

export async function verifySbx053GitHubAuthority(input: {
  gitUrl: string;
  gitToken: string;
  mintExpiresAt: string;
  sourceRevision: string;
  sourceCommit: string;
  bindingNonce: string;
  now?: number;
  fetcher?: typeof fetch;
}): Promise<Sbx053GitHubAuthorityEvidence> {
  if (!/^[0-9a-f]{64}$/u.test(input.bindingNonce) ||
      !isSbx053GitHubInstallationToken(input.gitToken)) {
    throw new Error("SBX-053 GitHub authority binding input was invalid");
  }
  const now = input.now ?? Date.now();
  const mintExpiration = tokenExpiration(input.mintExpiresAt, now, "mint-response");
  const fetcher = input.fetcher ?? fetch;
  const fullName = repositoryFullNameFromUrl(input.gitUrl);
  const sourceRevision = canonicalBranch(input.sourceRevision, "SBX-053 authority source revision");
  if (!COMMIT.test(input.sourceCommit) || input.sourceCommit !== input.sourceCommit.toLowerCase()) {
    throw new Error("SBX-053 authority source commit was not canonical");
  }
  const sourceRef = `refs/heads/${sourceRevision}`;
  const encodedSourceRevision = sourceRevision.split("/").map(encodeURIComponent).join("/");
  const sourceRefUrl = `https://api.github.com/repos/${fullName}/git/ref/heads/${encodedSourceRevision}`;
  const request = async (url: string): Promise<Response> => fetcher(url, {
    method: "GET",
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${input.gitToken}`,
      "x-github-api-version": "2022-11-28",
      "user-agent": "vercel-security-challenge-sbx-053",
    },
    redirect: "error",
    cache: "no-store",
    credentials: "omit",
    signal: AbortSignal.timeout(15_000),
  });

  const installationResponse = await request(
    "https://api.github.com/installation/repositories?per_page=2",
  );
  if (installationResponse.status !== 200 || installationResponse.url !==
      "https://api.github.com/installation/repositories?per_page=2") {
    throw new Error("SBX-053 GitHub installation repository authority request failed");
  }
  const installationExpiry = optionalAuthorityExpiration(installationResponse, now);
  const installationRequestId = githubRequestId(installationResponse);
  const installation = await boundedGitHubJson(installationResponse);
  if (installation.total_count !== 1 || !Array.isArray(installation.repositories) ||
      installation.repositories.length !== 1) {
    throw new Error("SBX-053 GitHub token was not scoped to exactly one repository");
  }
  const listed = installation.repositories[0] as Record<string, unknown>;
  if (listed === null || typeof listed !== "object" || listed.full_name !== fullName ||
      listed.private !== true) {
    throw new Error("SBX-053 GitHub installation scope did not name the exact private repository");
  }

  const repositoryResponse = await request(`https://api.github.com/repos/${fullName}`);
  if (repositoryResponse.status !== 200 ||
      repositoryResponse.url !== `https://api.github.com/repos/${fullName}`) {
    throw new Error("SBX-053 exact GitHub repository authority request failed");
  }
  const repositoryExpiry = optionalAuthorityExpiration(repositoryResponse, now);
  const repositoryRequestId = githubRequestId(repositoryResponse);
  const headerExpirations = [installationExpiry, repositoryExpiry].filter(
    (value): value is Sbx053TokenExpiration => value !== undefined,
  );
  if (headerExpirations.some((value) => value.expiresAt !== mintExpiration.expiresAt)) {
    throw new Error("SBX-053 authenticated GET expiry did not match the mint-response expiry");
  }
  const repository = await boundedGitHubJson(repositoryResponse);
  const permissions = repository.permissions;
  if (repository.full_name !== fullName || repository.private !== true ||
      permissions === null || typeof permissions !== "object" || Array.isArray(permissions) ||
      typeof (permissions as Record<string, unknown>).pull !== "boolean" ||
      (permissions as Record<string, unknown>).push !== false ||
      (permissions as Record<string, unknown>).admin !== false ||
      (permissions as Record<string, unknown>).maintain !== false) {
    throw new Error("SBX-053 GitHub repository was not exact, private, and free of write authority");
  }
  const repositoryPullProjection = (permissions as Record<string, unknown>).pull as boolean;

  const sourceRefResponse = await request(sourceRefUrl);
  if (sourceRefResponse.status !== 200 || sourceRefResponse.url !== sourceRefUrl) {
    throw new Error("SBX-053 exact GitHub source-ref authority request failed");
  }
  const sourceRefExpiry = optionalAuthorityExpiration(sourceRefResponse, now);
  const sourceRefRequestId = githubRequestId(sourceRefResponse);
  const sourceRefBody = await boundedGitHubJson(sourceRefResponse);
  const sourceObject = sourceRefBody.object;
  if (sourceRefBody.ref !== sourceRef || sourceObject === null ||
      typeof sourceObject !== "object" || Array.isArray(sourceObject) ||
      (sourceObject as Record<string, unknown>).type !== "commit" ||
      (sourceObject as Record<string, unknown>).sha !== input.sourceCommit) {
    throw new Error("SBX-053 GitHub source ref did not resolve to the exact pinned commit");
  }
  const sourceRefRequestEvidenceSha256 = createHash("sha256").update([
    "github.com", fullName, sourceRef, input.sourceCommit, sourceRefRequestId,
  ].join("\0"), "utf8").digest("hex");
  if (sourceRefExpiry !== undefined) headerExpirations.push(sourceRefExpiry);
  if (headerExpirations.some((value) => value.expiresAt !== mintExpiration.expiresAt)) {
    throw new Error("SBX-053 authenticated GET expiry did not match the mint-response expiry");
  }
  const requestEvidenceSha256 = createHash("sha256").update([
    "github.com", fullName, installationRequestId, repositoryRequestId, sourceRefRequestId,
    sourceRef, input.sourceCommit,
    mintExpiration.expiresAt, `expiry-headers=${headerExpirations.length}`,
    "repositories=1", `pull-projection=${repositoryPullProjection}`, "contents-read=true",
    "push=false", "admin=false", "maintain=false",
  ].join("\0"), "utf8").digest("hex");
  return {
    provider: "github-app-installation-token",
    repositoryFullName: fullName,
    repositoryPrivate: true,
    accessibleRepositoryCount: 1,
    repositoryPullProjection,
    contentsReadProved: true,
    effectivePush: false,
    effectiveAdmin: false,
    effectiveMaintain: false,
    sourceRef,
    sourceCommit: input.sourceCommit,
    sourceRefRequestEvidenceSha256,
    tokenExpiresAt: mintExpiration.expiresAt,
    remainingLifetimeSeconds: mintExpiration.remainingLifetimeSeconds,
    tokenExpirationEvidenceMethod: headerExpirations.length === 0
      ? "mint-response"
      : "mint-response-and-get-headers",
    tokenExpirationHeaderCount: headerExpirations.length as 0 | 1 | 2 | 3,
    tokenBindingNonce: input.bindingNonce,
    tokenBindingHmacSha256: createHmac("sha256", input.gitToken)
      .update(input.bindingNonce, "ascii").digest("hex"),
    requestEvidenceSha256,
    rawProviderBodiesRetained: false,
  };
}

function canonicalSafeProof(value: Sbx053ExpectedProof): boolean {
  return Number.isSafeInteger(value.length) && value.length >= 1 && value.length <= 4_096 &&
    /^[0-9a-f]{64}$/u.test(value.hmacSha256);
}

export function createSbx053EvidenceBinding(input: {
  runId: string;
  teamId: string;
  projectId: string;
  sandboxName: string;
  sessionId: string | null;
  repositoryUrl: string;
  sourceRevision: string;
  sourceCommit: string;
  credentialNonce: string;
  expectedCredential: Sbx053ExpectedProof;
  authority: Sbx053GitHubAuthorityEvidence;
  scan: Sbx053ScanResult;
  assessment: Sbx053Assessment;
  sentinel?: {
    ref: string;
    commit: string;
    path: string;
    challenge: string;
    expected: Sbx053ExpectedProof;
  };
}): Sbx053EvidenceBinding {
  const repositoryUrl = canonicalRepositoryUrl(input.repositoryUrl);
  const repositoryFullName = repositoryFullNameFromUrl(repositoryUrl);
  const sourceRevision = canonicalBranch(input.sourceRevision, "SBX-053 evidence source revision");
  const sourceRef = `refs/heads/${sourceRevision}`;
  if (!SBX053_UUID.test(input.runId) || input.sandboxName !== sbx053SandboxName(input.runId) ||
      input.teamId !== SBX053_ELIGIBLE_TEAM || input.projectId !== SBX053_ELIGIBLE_PROJECT ||
      (input.sessionId !== null && !/^sbx_[A-Za-z0-9_-]{8,192}$/u.test(input.sessionId)) ||
      !COMMIT.test(input.sourceCommit) || input.sourceCommit !== input.sourceCommit.toLowerCase() ||
      input.authority.repositoryFullName !== repositoryFullName ||
      input.authority.sourceRef !== sourceRef || input.authority.sourceCommit !== input.sourceCommit ||
      !/^[0-9a-f]{64}$/u.test(input.authority.sourceRefRequestEvidenceSha256) ||
      input.authority.tokenBindingNonce !== input.credentialNonce ||
      !/^[0-9a-f]{64}$/u.test(input.credentialNonce) ||
      !canonicalSafeProof(input.expectedCredential) ||
      input.authority.tokenBindingHmacSha256 !== input.expectedCredential.hmacSha256) {
    throw new Error("SBX-053 evidence target or shared credential binding was inconsistent");
  }
  const observed = findSbx053CredentialMatch(input.scan, input.expectedCredential);
  if (input.assessment.credentialMatched !== (observed !== undefined) ||
      input.assessment.matchedSurface !== (observed?.surface ?? null)) {
    throw new Error("SBX-053 retained credential observation did not match its assessment");
  }

  let sentinel: Sbx053EvidenceBinding["sentinel"] = null;
  if (input.sentinel !== undefined) {
    if (!input.sentinel.ref.startsWith("refs/heads/") ||
        canonicalBranch(input.sentinel.ref.slice("refs/heads/".length),
          "SBX-053 evidence sentinel ref") === sourceRevision ||
        !COMMIT.test(input.sentinel.commit) || input.sentinel.commit !== input.sentinel.commit.toLowerCase() ||
        input.sentinel.commit === input.sourceCommit ||
        canonicalSentinelPath(input.sentinel.path) !== input.sentinel.path ||
        !/^[0-9a-f]{64}$/u.test(input.sentinel.challenge) ||
        !canonicalSafeProof(input.sentinel.expected)) {
      throw new Error("SBX-053 sentinel evidence binding was inconsistent");
    }
    sentinel = {
      ref: input.sentinel.ref,
      commit: input.sentinel.commit,
      path: input.sentinel.path,
      challenge: input.sentinel.challenge,
      expected: { ...input.sentinel.expected },
    };
  }
  if (input.assessment.unclonedRefAccessProved !== (sentinel !== null && input.assessment.candidate)) {
    throw new Error("SBX-053 sentinel proof binding did not match its assessment");
  }

  return {
    schemaVersion: 1,
    runId: input.runId,
    target: {
      teamId: SBX053_ELIGIBLE_TEAM,
      projectId: SBX053_ELIGIBLE_PROJECT,
      sandboxName: input.sandboxName,
      sessionId: input.sessionId,
      repositoryUrl,
      repositoryFullName,
      sourceRef,
      sourceCommit: input.sourceCommit,
    },
    credential: {
      nonce: input.credentialNonce,
      expected: { ...input.expectedCredential },
      observed: observed === undefined ? null : { ...observed },
    },
    sentinel,
  };
}

export function loadSbx053Config(
  environment: NodeJS.ProcessEnv = process.env,
): Sbx053Config | Sbx053RecoveryConfig {
  if (environment.SBX053_SCOPE_CONFIRMATION !== SBX053_SCOPE_CONFIRMATION ||
      environment.VERCEL_TEAM_ID !== SBX053_ELIGIBLE_TEAM ||
      environment.VERCEL_PROJECT_ID !== SBX053_ELIGIBLE_PROJECT ||
      environment.SBX053_EXPECTED_ALIAS !== SBX053_ELIGIBLE_ALIAS) {
    throw new Error("SBX-053 scope attestation or eligible Vercel identity binding was absent");
  }
  const vercelToken = boundedSecret(required(environment, "VERCEL_TOKEN"), "VERCEL_TOKEN");
  if (vercelToken.split(".").length === 3) {
    throw new Error("SBX-053 requires a non-JWT Vercel PAT so SDK refresh cannot leave the audited path");
  }
  for (const name of FORBIDDEN_RUNTIME_VARIABLES) {
    if (environment[name] !== undefined && environment[name] !== "") {
      throw new Error(`SBX-053 rejects runtime transport override ${name}`);
    }
  }
  const recoveryRunId = environment.SBX053_RECOVERY_RUN_ID;
  if (recoveryRunId !== undefined) {
    if (!SBX053_UUID.test(recoveryRunId)) {
      throw new Error("SBX053_RECOVERY_RUN_ID must be one canonical UUIDv4");
    }
    return {
      vercelToken,
      teamId: SBX053_ELIGIBLE_TEAM,
      projectId: SBX053_ELIGIBLE_PROJECT,
      expectedAlias: SBX053_ELIGIBLE_ALIAS,
      ...(environment.SBX053_MANUAL_ALIAS_CONFIRMATION === undefined
        ? {}
        : { manualAliasConfirmation: environment.SBX053_MANUAL_ALIAS_CONFIRMATION }),
      recoveryRunId,
    };
  }
  if (environment.SBX053_GIT_USERNAME !== "x-access-token") {
    throw new Error("SBX053_GIT_USERNAME must be x-access-token");
  }
  const gitUrl = canonicalRepositoryUrl(required(environment, "SBX053_GIT_URL"));
  const gitToken = boundedSecret(required(environment, "SBX053_GIT_TOKEN"), "SBX053_GIT_TOKEN");
  if (!isSbx053GitHubInstallationToken(gitToken)) {
    throw new Error("SBX053_GIT_TOKEN must be one short-lived GitHub App installation token");
  }
  const gitTokenExpiresAt = required(environment, "SBX053_GIT_TOKEN_EXPIRES_AT");
  canonicalTokenExpirationMilliseconds(gitTokenExpiresAt, "mint-response");
  const sourceRevision = canonicalBranch(required(environment, "SBX053_SOURCE_REVISION"),
    "SBX053_SOURCE_REVISION");
  const sourceCommit = required(environment, "SBX053_SOURCE_COMMIT").toLowerCase();
  if (!COMMIT.test(sourceCommit)) throw new Error("SBX053_SOURCE_COMMIT was not canonical");
  const impact = environment.SBX053_ENABLE_IMPACT ?? "0";
  if (impact !== "0" && impact !== "1") throw new Error("SBX053_ENABLE_IMPACT must be 0 or 1");

  const base: Sbx053Config = {
    vercelToken,
    teamId: SBX053_ELIGIBLE_TEAM,
    projectId: SBX053_ELIGIBLE_PROJECT,
    expectedAlias: SBX053_ELIGIBLE_ALIAS,
    ...(environment.SBX053_MANUAL_ALIAS_CONFIRMATION === undefined
      ? {}
      : { manualAliasConfirmation: environment.SBX053_MANUAL_ALIAS_CONFIRMATION }),
    gitUrl,
    gitUsername: "x-access-token",
    gitToken,
    gitTokenExpiresAt,
    sourceRevision,
    sourceCommit,
    impactEnabled: impact === "1",
  };
  if (impact !== "1") return base;

  const sentinelBranch = canonicalBranch(required(environment, "SBX053_SENTINEL_BRANCH"),
    "SBX053_SENTINEL_BRANCH");
  if (sentinelBranch === sourceRevision) throw new Error("source and sentinel branches must differ");
  const sentinelCommit = required(environment, "SBX053_SENTINEL_COMMIT").toLowerCase();
  if (!COMMIT.test(sentinelCommit) || sentinelCommit === sourceCommit) {
    throw new Error("SBX053_SENTINEL_COMMIT must be canonical and distinct from the source commit");
  }
  const sentinelValue = boundedSecret(required(environment, "SBX053_SENTINEL_VALUE"),
    "SBX053_SENTINEL_VALUE", 32, 4_096);
  return {
    ...base,
    sentinelRef: `refs/heads/${sentinelBranch}`,
    sentinelCommit,
    sentinelPath: canonicalSentinelPath(required(environment, "SBX053_SENTINEL_PATH")),
    sentinelValue,
  };
}

function exactTags(actual: Record<string, string> | undefined, expected: Record<string, string>): boolean {
  if (!actual) return false;
  const keys = Object.keys(expected);
  return Object.keys(actual).length === keys.length && keys.every((key) => actual[key] === expected[key]);
}

function isNotFound(error: unknown): boolean {
  return error instanceof APIError && error.response.status === 404;
}

function networkAllowsOnlyGitHub(policy: NetworkPolicy | undefined): boolean {
  return policy !== undefined && typeof policy === "object" && !Array.isArray(policy) &&
    Array.isArray(policy.allow) && policy.allow.length === 1 && policy.allow[0] === "github.com" &&
    policy.subnets === undefined;
}

async function exactPolicyReadback(input: {
  config: Sbx053Config;
  name: string;
  tags: Record<string, string>;
  sessionId: string;
  expected: "deny-all" | "github-only";
}): Promise<boolean> {
  const readback = await Sandbox.get({
    token: input.config.vercelToken,
    teamId: input.config.teamId,
    projectId: input.config.projectId,
    name: input.name,
    resume: false,
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  });
  const sandboxPolicyMatches = input.expected === "deny-all"
    ? readback.networkPolicy === "deny-all"
    : networkAllowsOnlyGitHub(readback.networkPolicy);
  const sessionPolicyMatches = input.expected === "deny-all"
    ? readback.currentSession().networkPolicy === "deny-all"
    : networkAllowsOnlyGitHub(readback.currentSession().networkPolicy);
  return readback.name === input.name && exactTags(readback.tags, input.tags) &&
    readback.persistent === false && readback.routes.length === 0 &&
    readback.currentSession().sessionId === input.sessionId && sandboxPolicyMatches &&
    sessionPolicyMatches;
}

async function assertSdkAndGuest(): Promise<string> {
  const metadata = JSON.parse(await readFile(
    new URL("../../node_modules/@vercel/sandbox/package.json", import.meta.url),
    "utf8",
  )) as { version?: unknown };
  if (metadata.version !== EXPECTED_SDK_VERSION) throw new Error("SBX-053 SDK version changed");
  const source = await readFile(GUEST_SOURCE, "utf8");
  const digest = createHash("sha256").update(source, "utf8").digest("hex");
  if (digest !== SBX053_FIXED_GUEST_SHA256) throw new Error("SBX-053 fixed guest digest changed");
  return source;
}

export function sbx053CreateParameters(config: Sbx053Config, name: string, tags: Record<string, string>) {
  return {
    token: config.vercelToken,
    teamId: config.teamId,
    projectId: config.projectId,
    name,
    source: {
      type: "git" as const,
      url: config.gitUrl,
      username: config.gitUsername,
      password: config.gitToken,
      depth: 1,
      revision: config.sourceRevision,
    },
    env: {},
    persistent: false,
    ports: [] as number[],
    networkPolicy: "deny-all" as const,
    timeout: SBX053_SANDBOX_TIMEOUT_MS,
    tags,
    signal: AbortSignal.timeout(SBX053_CREATE_REQUEST_TIMEOUT_MS),
  };
}

export function sbx053ScanArguments(repositoryRoot: string, nonce: string): string[] {
  return [REMOTE_GUEST, "scan", repositoryRoot, nonce];
}

export function sbx053ImpactArguments(input: {
  repositoryRoot: string;
  nonce: string;
  expectedCredentialHmac: string;
  expectedCredentialLength: number;
  sourceUrl: string;
  sentinelRef: string;
  sentinelCommit: string;
  sentinelPath: string;
  challenge: string;
}): string[] {
  return [
    REMOTE_GUEST,
    "impact",
    input.repositoryRoot,
    input.nonce,
    input.expectedCredentialHmac,
    String(input.expectedCredentialLength),
    input.sourceUrl,
    input.sentinelRef,
    input.sentinelCommit,
    input.sentinelPath,
    input.challenge,
  ];
}

async function runGuest(sandbox: Sandbox, args: string[]): Promise<GuestExecution> {
  const command = await sandbox.currentSession().runCommand({
    cmd: "node",
    args,
    timeoutMs: COMMAND_TIMEOUT_MS,
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  });
  const [stdout, stderr] = await Promise.all([command.stdout(), command.stderr()]);
  if (Buffer.byteLength(stdout, "utf8") > MAX_GUEST_OUTPUT_BYTES ||
      Buffer.byteLength(stderr, "utf8") > MAX_GUEST_OUTPUT_BYTES) {
    throw new Error("SBX-053 guest output exceeded the byte ceiling");
  }
  return { stdout, stderr, exitCode: command.exitCode };
}

async function fixedGit(sandbox: Sandbox, repositoryRoot: string, args: string[]) {
  const command = await sandbox.currentSession().runCommand({
    cmd: "git",
    args,
    cwd: repositoryRoot,
    timeoutMs: 15_000,
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  });
  const [stdout, stderr] = await Promise.all([command.stdout(), command.stderr()]);
  if (Buffer.byteLength(stdout, "utf8") > 4_096 || Buffer.byteLength(stderr, "utf8") > 4_096) {
    throw new Error("SBX-053 Git control output exceeded the byte ceiling");
  }
  return { stdout, stderr, exitCode: command.exitCode };
}

export interface Sbx053CleanupEvidence {
  createUnknown: boolean;
  recoveredByExactName: boolean;
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  absenceChecks: number;
  prefixListAbsent: boolean;
  liveLockReleased: boolean;
  recoveryJournalDeleted: boolean;
}

function emptyCleanupEvidence(): Sbx053CleanupEvidence {
  return {
    createUnknown: false,
    recoveredByExactName: false,
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    absenceChecks: 0,
    prefixListAbsent: false,
    liveLockReleased: false,
    recoveryJournalDeleted: false,
  };
}

async function prefixAbsent(
  config: Sbx053Config | Sbx053RecoveryConfig,
  journal: Sbx053RecoveryJournal,
): Promise<boolean> {
  const paginator = await Sandbox.list({
    token: config.vercelToken,
    teamId: config.teamId,
    projectId: config.projectId,
    namePrefix: journal.sandboxName,
    limit: 10,
    signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
  });
  const items = await paginator.toArray();
  return items.length === 0;
}

export async function cleanupSbx053Exact(input: {
  config: Sbx053Config | Sbx053RecoveryConfig;
  sandbox?: Sandbox;
  journal: Sbx053RecoveryJournal;
  lock: Sbx053HeldLock;
  allowSettledUnknownAbsence: boolean;
  evidence: Sbx053CleanupEvidence;
  persistOverride?: (lock: Sbx053HeldLock, journal: Sbx053RecoveryJournal) => Promise<void>;
}): Promise<boolean> {
  const persist = async () => (input.persistOverride ?? persistSbx053Journal)(
    input.lock,
    input.journal,
  );
  let target = input.sandbox;
  if (!target && input.journal.createAttemptedAt !== undefined) {
    try {
      const recovered = await Sandbox.get({
        token: input.config.vercelToken,
        teamId: input.config.teamId,
        projectId: input.config.projectId,
        name: input.journal.sandboxName,
        resume: false,
        signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
      });
      if (recovered.name !== input.journal.sandboxName ||
          !exactTags(recovered.tags, input.journal.tags) ||
          recovered.persistent !== false ||
          recovered.createdAt.getTime() < Date.parse(input.journal.startedAt) - 5_000 ||
          recovered.createdAt.getTime() > Date.now() + 5_000) return false;
      target = recovered;
      input.evidence.recoveredByExactName = true;
      input.journal.sessionId ??= recovered.currentSession().sessionId;
      input.journal.sandboxAttributed = true;
      await persist();
    } catch (error) {
      if (!isNotFound(error)) return false;
      if (input.journal.sessionId === undefined &&
          (!input.allowSettledUnknownAbsence || !createSettlementReached(input.journal))) {
        input.evidence.createUnknown = true;
        return false;
      }
    }
  }
  if (!target && input.journal.createAttemptedAt === undefined) return true;
  if (target && (target.name !== input.journal.sandboxName ||
      !exactTags(target.tags, input.journal.tags) || target.persistent !== false)) return false;
  try {
    if (target) {
      input.journal.denyAllRestored = false;
      await persist();
      if (target.status === "running" || target.status === "pending") {
        await target.update({ networkPolicy: "deny-all" },
          { signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
      }
      input.journal.denyAllRestored = true;
      await persist();
      input.evidence.stopAttempted = true;
      input.journal.stopAttempted = true;
      await persist();
      if (target.status === "running" || target.status === "pending") {
        await target.stop({ signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
      }
      input.evidence.stopped = true;
      input.journal.stopped = true;
      await persist();
      input.evidence.deleteAttempted = true;
      input.journal.deleteAttempted = true;
      await persist();
      await target.delete({ signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
      input.evidence.deleted = true;
      input.journal.deleted = true;
      await persist();
    }
    for (let index = 0; index < 3; index += 1) {
      try {
        await Sandbox.get({
          token: input.config.vercelToken,
          teamId: input.config.teamId,
          projectId: input.config.projectId,
          name: input.journal.sandboxName,
          resume: false,
          signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS),
        });
        return false;
      } catch (error) {
        if (!isNotFound(error)) return false;
        input.evidence.absenceChecks += 1;
        input.journal.absenceChecks += 1;
        await persist();
      }
    }
    input.evidence.prefixListAbsent = await prefixAbsent(input.config, input.journal);
    input.journal.prefixListAbsent = input.evidence.prefixListAbsent;
    await persist();
    return input.evidence.absenceChecks === 3 && input.evidence.prefixListAbsent;
  } catch {
    return false;
  }
}

function chronologyRecorder(entries: Sbx053ChronologyEntry[]) {
  return async <T>(phase: string, action: () => Promise<T>): Promise<T> => {
    const startedAt = new Date().toISOString();
    try {
      const value = await action();
      entries.push({
        ordinal: entries.length + 1,
        phase,
        startedAt,
        completedAt: new Date().toISOString(),
        outcome: "passed",
      });
      return value;
    } catch (error) {
      entries.push({
        ordinal: entries.length + 1,
        phase,
        startedAt,
        completedAt: new Date().toISOString(),
        outcome: "failed",
      });
      throw error;
    }
  };
}

export function sbx053ChronologyIsCanonical(entries: readonly Sbx053ChronologyEntry[]): boolean {
  let previousEnd = -Infinity;
  return entries.length > 0 && entries.every((entry, index) => {
    const started = Date.parse(entry.startedAt);
    const completed = Date.parse(entry.completedAt);
    const valid = entry.ordinal === index + 1 && entry.phase.length >= 1 && entry.phase.length <= 64 &&
      Number.isFinite(started) && Number.isFinite(completed) && previousEnd <= started &&
      started <= completed;
    previousEnd = completed;
    return valid;
  });
}

export interface Sbx053RecoveryRunResult {
  runId: string;
  recoveryAttemptId: string;
  recoveryOnly: true;
  outcome: "cleanup-complete" | "cleanup-incomplete";
  evidencePath: string;
  cleanup: Sbx053CleanupEvidence;
  failure?: string;
}

export interface Sbx053RecoveryRuntime {
  newAttemptId(): string;
  resumeInterruptedFinalization(runId: string): Promise<boolean>;
  acquireLock(runId: string): Promise<Sbx053HeldLock>;
  readJournal(runId: string): Promise<Sbx053RecoveryJournal>;
  verifyIdentity(config: Sbx053RecoveryConfig): Promise<void>;
  cleanup(input: Parameters<typeof cleanupSbx053Exact>[0]): Promise<boolean>;
  persist(lock: Sbx053HeldLock, journal: Sbx053RecoveryJournal): Promise<void>;
  release(lock: Sbx053HeldLock): Promise<void>;
  closeRetainingState(lock: Sbx053HeldLock): Promise<void>;
  writeArtifact(path: string, value: unknown): Promise<number>;
}

export async function runSbx053(config: Sbx053Config): Promise<Sbx053RunResult> {
  const journal = createSbx053Journal();
  const runId = journal.runId;
  const sandboxName = journal.sandboxName;
  const tags = journal.tags;
  const chronology: Sbx053ChronologyEntry[] = [];
  const record = chronologyRecorder(chronology);
  const cleanup = emptyCleanupEvidence();
  const credentialNonce = randomBytes(32).toString("hex");
  const expectedCredential = expectedSbx053Proof(config.gitToken, credentialNonce);
  const forbidden = [
    config.vercelToken,
    config.gitToken,
    ...(config.sentinelValue === undefined ? [] : [config.sentinelValue]),
  ];
  const repositoryDirectory = repositoryDirectoryFromUrl(config.gitUrl);
  let guestSource = "";
  let lock: Sbx053HeldLock | undefined;
  let sandbox: Sandbox | undefined;
  let scan: Sbx053ScanResult | undefined;
  let impact: Sbx053ImpactResult | undefined;
  let expectedSentinel: Sbx053ExpectedProof | undefined;
  let sentinelChallenge: string | undefined;
  let authority: Sbx053GitHubAuthorityEvidence | undefined;
  let sessionId = "";
  let sourceCloneSucceeded = false;
  let sourceRevisionPinned = false;
  let denyAllConfirmedDuringScan = false;
  let rawCredentialAbsentFromGuestCommand = false;
  let sourceCredentialOnlySentInCreateSource = false;
  let cleanupSucceeded = false;
  let executionError: string | undefined;
  let lockMode = 0;
  let journalMode = 0;

  const persist = async (): Promise<void> => {
    if (lock) await persistSbx053Journal(lock, journal);
  };

  try {
    lock = await record("durable-lock-and-journal", async () => acquireSbx053Lock(journal));
    lockMode = lock.lockMode;
    journalMode = lock.journalMode;
    guestSource = await record("fixed-sdk-and-guest", assertSdkAndGuest);
    await record("eligible-vercel-identity", async () => {
      await verifyEligibleAliasToken({
        token: config.vercelToken,
        expectedEmail: config.expectedAlias,
        expectedTeamId: config.teamId,
        expectedProjectId: config.projectId,
        ...(config.manualAliasConfirmation === undefined
          ? {}
          : { manualEmailConfirmation: config.manualAliasConfirmation }),
      });
    });
    authority = await record("github-token-authority", async () =>
      verifySbx053GitHubAuthority({
        gitUrl: config.gitUrl,
        gitToken: config.gitToken,
        mintExpiresAt: config.gitTokenExpiresAt,
        sourceRevision: config.sourceRevision,
        sourceCommit: config.sourceCommit,
        bindingNonce: credentialNonce,
      }));
    if (authority.tokenBindingNonce !== credentialNonce ||
        authority.tokenBindingHmacSha256 !== expectedCredential.hmacSha256) {
      throw new Error("SBX-053 GitHub authority did not share the guest credential binding");
    }
    journal.authorityPreflightPassed = true;
    await persist();

    await record("precreate-prefix-absence", async () => {
      if (!await prefixAbsent(config, journal)) {
        throw new Error("SBX-053 full-UUID sandbox name was not fresh");
      }
    });

    const createParameters = sbx053CreateParameters(config, sandboxName, tags);
    const { source: createSource, ...nonSourceCreateParameters } = createParameters;
    sourceCredentialOnlySentInCreateSource = createSource.password === config.gitToken &&
      !JSON.stringify(nonSourceCreateParameters).includes(config.gitToken);
    if (!sourceCredentialOnlySentInCreateSource) {
      throw new Error("SBX-053 source credential escaped the create source field");
    }
    journal.createAttemptedAt = new Date().toISOString();
    await persist();
    try {
      sandbox = await record("sandbox-create", async () => Sandbox.create(createParameters));
    } finally {
      journal.createRequestSettledAt = new Date().toISOString();
      await persist();
    }

    sessionId = sandbox.currentSession().sessionId;
    if (!/^sbx_[A-Za-z0-9_-]{8,192}$/u.test(sessionId) ||
        sandbox.name !== sandboxName || !exactTags(sandbox.tags, tags) ||
        sandbox.persistent !== false || sandbox.routes.length !== 0 ||
        sandbox.timeout !== SBX053_SANDBOX_TIMEOUT_MS ||
        sandbox.currentSession().timeout !== SBX053_SANDBOX_TIMEOUT_MS) {
      throw new Error("SBX-053 sandbox attribution failed");
    }
    journal.sessionId = sessionId;
    journal.sandboxAttributed = true;
    await persist();

    denyAllConfirmedDuringScan = await record("initial-deny-all-readback", async () => {
      const confirmed = sandbox!.networkPolicy === "deny-all" &&
        sandbox!.currentSession().networkPolicy === "deny-all" && await exactPolicyReadback({
        config,
        name: sandboxName,
        tags,
        sessionId,
        expected: "deny-all",
      });
      if (!confirmed) throw new Error("SBX-053 deny-all readback failed");
      return true;
    });

    const repositoryRoot = resolve(sandbox.cwd, repositoryDirectory);
    await record("source-clone-controls", async () => {
      const worktree = await fixedGit(sandbox!, repositoryRoot, ["rev-parse", "--is-inside-work-tree"]);
      sourceCloneSucceeded = worktree.exitCode === 0 && worktree.stderr === "" &&
        worktree.stdout === "true\n";
      const revision = await fixedGit(sandbox!, repositoryRoot, ["rev-parse", "HEAD"]);
      sourceRevisionPinned = revision.exitCode === 0 && revision.stderr === "" &&
        revision.stdout.trim().toLowerCase() === config.sourceCommit;
      if (!sourceCloneSucceeded || !sourceRevisionPinned) {
        throw new Error("SBX-053 source controls failed");
      }
    });

    await record("guest-stage", async () => {
      await sandbox!.currentSession().writeFiles([
        { path: REMOTE_GUEST, content: guestSource, mode: 0o700 },
      ], { signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
    });
    journal.guestProbeStaged = true;
    await persist();

    await record("credential-scan", async () => {
      const scanArgs = sbx053ScanArguments(repositoryRoot, credentialNonce);
      if (scanArgs.some((argument) => argument.includes(config.gitToken))) {
        throw new Error("SBX-053 controller attempted to pass the raw source credential to the guest command");
      }
      const scanRun = await runGuest(sandbox!, scanArgs);
      if (scanRun.stdout.includes(config.gitToken) || scanRun.stderr.includes(config.gitToken)) {
        throw new Error("SBX-053 guest emitted raw source credential material");
      }
      rawCredentialAbsentFromGuestCommand = true;
      scan = parseSbx053Scan(scanRun.stdout, scanRun.stderr, scanRun.exitCode);
    });

    if (config.impactEnabled && scan && findSbx053CredentialMatch(scan, expectedCredential)) {
      const sentinelRef = config.sentinelRef;
      const sentinelCommit = config.sentinelCommit;
      const sentinelPath = config.sentinelPath;
      const sentinelValue = config.sentinelValue;
      if (!sentinelRef || !sentinelCommit || !sentinelPath || !sentinelValue) {
        throw new Error("SBX-053 impact configuration was incomplete");
      }
      const challenge = randomBytes(32).toString("hex");
      sentinelChallenge = challenge;
      expectedSentinel = expectedSbx053Proof(sentinelValue, challenge);
      journal.githubOnlyOpened = true;
      journal.denyAllRestored = false;
      await persist();
      try {
        await record("github-only-impact", async () => {
          await sandbox!.update({ networkPolicy: { allow: ["github.com"] } },
            { signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
          if (!networkAllowsOnlyGitHub(sandbox!.networkPolicy) ||
              !networkAllowsOnlyGitHub(sandbox!.currentSession().networkPolicy) ||
              !await exactPolicyReadback({
                config,
                name: sandboxName,
                tags,
                sessionId,
                expected: "github-only",
              })) {
            throw new Error("SBX-053 GitHub-only policy readback failed");
          }
          const impactArgs = sbx053ImpactArguments({
            repositoryRoot,
            nonce: credentialNonce,
            expectedCredentialHmac: expectedCredential.hmacSha256,
            expectedCredentialLength: expectedCredential.length,
            sourceUrl: config.gitUrl,
            sentinelRef,
            sentinelCommit,
            sentinelPath,
            challenge,
          });
          if (impactArgs.some((argument) =>
            argument.includes(config.gitToken) || argument.includes(sentinelValue))) {
            throw new Error("SBX-053 controller attempted to pass a raw proof secret to the impact command");
          }
          const impactRun = await runGuest(sandbox!, impactArgs);
          if (impactRun.stdout.includes(config.gitToken) || impactRun.stderr.includes(config.gitToken) ||
              impactRun.stdout.includes(sentinelValue) || impactRun.stderr.includes(sentinelValue)) {
            throw new Error("SBX-053 impact guest emitted raw proof material");
          }
          impact = parseSbx053Impact(impactRun.stdout, impactRun.stderr, impactRun.exitCode);
          assertSbx053EvidenceExcludesRawSecrets({
            scan,
            impact,
            expectedCredential,
            expectedSentinel,
          }, [config.gitToken, sentinelValue]);
        });
      } finally {
        await record("deny-all-restoration", async () => {
          await sandbox!.update({ networkPolicy: "deny-all" },
            { signal: AbortSignal.timeout(CONTROL_TIMEOUT_MS) });
          if (!await exactPolicyReadback({
            config,
            name: sandboxName,
            tags,
            sessionId,
            expected: "deny-all",
          })) throw new Error("SBX-053 deny-all restoration readback failed");
        });
        journal.denyAllRestored = true;
        await persist();
      }
    }
  } catch (error) {
    executionError = safeSbx053Error(error, forbidden);
  } finally {
    if (lock) {
      try {
        cleanupSucceeded = await record("exact-cleanup", async () => {
          const succeeded = await cleanupSbx053Exact({
            config,
            ...(sandbox === undefined ? {} : { sandbox }),
            journal,
            lock: lock!,
            allowSettledUnknownAbsence: false,
            evidence: cleanup,
          });
          if (!succeeded) throw new Error("SBX-053 exact cleanup was not proved");
          return true;
        });
        journal.completed = cleanupSucceeded;
        await persist();
        await record("lock-and-journal-release", async () => releaseSbx053LockAndJournal(lock!));
        cleanup.liveLockReleased = true;
        cleanup.recoveryJournalDeleted = true;
      } catch (error) {
        executionError ??= safeSbx053Error(error, forbidden);
        await lock.liveLock.closeRetainingState().catch(() => undefined);
      }
    }
  }

  const scanEvidence: Sbx053ScanResult = scan ?? {
    schemaVersion: 1,
    testId: SBX053_TEST_ID,
    operation: "scan",
    complete: false,
    surfacesChecked: [...SBX053_SURFACES],
    observations: [],
    candidatesTruncated: false,
  };
  const durableSafetyPassed = lockMode === 0o600 && journalMode === 0o600 &&
    cleanupSucceeded && cleanup.liveLockReleased && cleanup.recoveryJournalDeleted &&
    executionError === undefined && sbx053ChronologyIsCanonical(chronology);
  const assessment = assessSbx053({
    sourceCloneSucceeded,
    sourceRevisionPinned,
    privateRepositoryAuthorityConfirmed: authority?.repositoryPrivate === true,
    authorityEvidencePassed: authority !== undefined,
    durableSafetyPassed,
    fixedGuestDigestMatched: guestSource !== "",
    sourceCredentialOnlySentInCreateSource,
    rawCredentialAbsentFromGuestCommand,
    denyAllConfirmedDuringScan,
    cleanupSucceeded,
    scan: scanEvidence,
    expectedCredential,
    ...(impact === undefined ? {} : { impact }),
    ...(expectedSentinel === undefined ? {} : { expectedSentinel }),
  });
  const evidenceBinding = authority === undefined ? null : createSbx053EvidenceBinding({
    runId,
    teamId: config.teamId,
    projectId: config.projectId,
    sandboxName,
    sessionId: sessionId === "" ? null : sessionId,
    repositoryUrl: config.gitUrl,
    sourceRevision: config.sourceRevision,
    sourceCommit: config.sourceCommit,
    credentialNonce,
    expectedCredential,
    authority,
    scan: scanEvidence,
    assessment,
    ...(expectedSentinel === undefined || sentinelChallenge === undefined ||
        config.sentinelRef === undefined || config.sentinelCommit === undefined ||
        config.sentinelPath === undefined
      ? {}
      : {
          sentinel: {
            ref: config.sentinelRef,
            commit: config.sentinelCommit,
            path: config.sentinelPath,
            challenge: sentinelChallenge,
            expected: expectedSentinel,
          },
        }),
  });
  const artifact = {
    schemaVersion: 1,
    testId: SBX053_TEST_ID,
    runId,
    recoveryOnly: false,
    mode: "experiment",
    ...(executionError === undefined ? {} : { executionError }),
    authority: authority ?? null,
    evidenceBinding,
    chronology,
    cleanup,
    storage: {
      liveLockMode: lockMode,
      recoveryJournalMode: journalMode,
      artifactModeRequired: 0o600,
      noClobber: true,
      rawSecretsRetained: false,
    },
    scan: scanEvidence,
    ...(impact === undefined ? {} : { impact }),
    assessment,
  };
  assertSbx053EvidenceExcludesRawSecrets(artifact, forbidden);
  const evidencePath = sbx053ArtifactPath(runId);
  const artifactMode = await writeSbx053PrivateArtifact(evidencePath, artifact);
  if (artifactMode !== 0o600) throw new Error("SBX-053 normal artifact mode changed");
  if (!cleanupSucceeded || !sandbox || sessionId === "" || scan === undefined ||
      authority === undefined || evidenceBinding === null) {
    throw new Error("SBX-053 live sequence was indeterminate; durable private evidence was written");
  }
  return {
    runId,
    sandboxName,
    sessionId,
    authority,
    evidenceBinding,
    scan,
    ...(impact === undefined ? {} : { impact }),
    assessment,
    cleanupSucceeded: true,
    evidencePath,
  };
}

export async function runSbx053Recovery(
  config: Sbx053RecoveryConfig,
  runId: string,
  overrides: Partial<Sbx053RecoveryRuntime> = {},
): Promise<Sbx053RecoveryRunResult> {
  const runtime: Sbx053RecoveryRuntime = {
    newAttemptId: randomUUID,
    resumeInterruptedFinalization: resumeSbx053InterruptedFinalization,
    acquireLock: acquireSbx053RecoveryLock,
    readJournal: readSbx053Journal,
    verifyIdentity: async (recoveryConfig) => {
      await verifyEligibleAliasToken({
        token: recoveryConfig.vercelToken,
        expectedEmail: recoveryConfig.expectedAlias,
        expectedTeamId: recoveryConfig.teamId,
        expectedProjectId: recoveryConfig.projectId,
        ...(recoveryConfig.manualAliasConfirmation === undefined
          ? {}
          : { manualEmailConfirmation: recoveryConfig.manualAliasConfirmation }),
      });
    },
    cleanup: cleanupSbx053Exact,
    persist: persistSbx053Journal,
    release: releaseSbx053LockAndJournal,
    closeRetainingState: async (held) => held.liveLock.closeRetainingState(),
    writeArtifact: writeSbx053PrivateArtifact,
    ...overrides,
  };
  if (!SBX053_UUID.test(runId)) throw new Error("SBX-053 recovery run ID was invalid");
  const recoveryAttemptId = runtime.newAttemptId();
  if (!SBX053_UUID.test(recoveryAttemptId)) {
    throw new Error("SBX-053 recovery attempt ID was invalid");
  }
  const chronology: Sbx053ChronologyEntry[] = [];
  const record = chronologyRecorder(chronology);
  const cleanup = emptyCleanupEvidence();
  const forbidden = [config.vercelToken];
  let lock: Sbx053HeldLock | undefined;
  let journal: Sbx053RecoveryJournal | undefined;
  let failure: string | undefined;
  let cleanupComplete = false;
  let interruptedFinalizationResumed = false;
  try {
    if (await record("recovery-finalization-check", async () =>
      runtime.resumeInterruptedFinalization(runId))) {
      interruptedFinalizationResumed = true;
      cleanup.liveLockReleased = true;
      cleanup.recoveryJournalDeleted = true;
      cleanupComplete = true;
    } else {
      lock = await record("recovery-lock", async () => runtime.acquireLock(runId));
      journal = await record("recovery-journal", async () => runtime.readJournal(runId));
      if (journal.createAttemptedAt !== undefined) {
        await record("recovery-identity", async () => runtime.verifyIdentity(config));
      }
      cleanupComplete = await record("recovery-cleanup", async () => {
        const succeeded = await runtime.cleanup({
          config,
          journal: journal!,
          lock: lock!,
          allowSettledUnknownAbsence: true,
          evidence: cleanup,
        });
        if (!succeeded) throw new Error("SBX-053 recovery cleanup was not proved");
        return true;
      });
      journal.completed = true;
      await runtime.persist(lock, journal);
      await record("recovery-release", async () => runtime.release(lock!));
      cleanup.liveLockReleased = true;
      cleanup.recoveryJournalDeleted = true;
    }
  } catch (error) {
    failure = safeSbx053Error(error, forbidden);
    if (lock) await runtime.closeRetainingState(lock).catch(() => undefined);
  }
  cleanupComplete &&= cleanup.liveLockReleased && cleanup.recoveryJournalDeleted &&
    sbx053ChronologyIsCanonical(chronology);
  const outcome = cleanupComplete ? "cleanup-complete" as const : "cleanup-incomplete" as const;
  const artifact = {
    schemaVersion: 1,
    testId: SBX053_TEST_ID,
    runId,
    recoveryAttemptId,
    recoveryOnly: true,
    mode: "cleanup-only",
    outcome,
    interruptedFinalizationResumed,
    ...(failure === undefined ? {} : { failure }),
    chronology,
    cleanup,
    retention: {
      experimentEvidenceOverwritten: false,
      rawSecretsRetained: false,
      vulnerabilityVerdictEmitted: false,
    },
  };
  assertSbx053EvidenceExcludesRawSecrets(artifact, forbidden);
  const evidencePath = sbx053RecoveryArtifactPath(runId, recoveryAttemptId);
  const artifactMode = await runtime.writeArtifact(evidencePath, artifact);
  if (artifactMode !== 0o600) throw new Error("SBX-053 recovery artifact mode changed");
  return {
    runId,
    recoveryAttemptId,
    recoveryOnly: true,
    outcome,
    evidencePath,
    cleanup,
    ...(failure === undefined ? {} : { failure }),
  };
}

async function main(): Promise<void> {
  const config = loadSbx053Config();
  const result = "recoveryRunId" in config
    ? await runSbx053Recovery(config, config.recoveryRunId)
    : await runSbx053(config);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

const invoked = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : "";
if (import.meta.url === invoked) {
  main().catch(() => {
    process.stderr.write("SBX-053 controller failed; no raw error or secret was emitted\n");
    process.exitCode = 1;
  });
}
