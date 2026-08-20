import "dotenv/config";

import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Sandbox, type NetworkPolicy } from "@vercel/sandbox";
// @ts-expect-error Shared guest policy data is deliberately executable plain Node ESM.
import * as discoveryRules from "../../guest/mmds-discovery-rules.mjs";

const { DIRECT_SECRET_LEAVES, DISCOVERY_NAMESPACE_RULES, SECRET_OBJECT_KEYS } = discoveryRules;

const target = "169.254.169.254";
const remoteProbe = "/tmp/sbx-020/mmds-link-local-probe.mjs";
const remoteDiscoveryRules = "/tmp/sbx-020/mmds-discovery-rules.mjs";
const rootIndexPath = "/latest/meta-data/";
const tokenPath = "/latest/api/token";
const identityPath = "/latest/dynamic/instance-identity/document";
const roleIndexPath = "/latest/meta-data/iam/security-credentials/";
const credentialPathTemplate = "/latest/meta-data/iam/security-credentials/<validated-role>";
const discoveryRootPath = "/";
const discoveryNamespacePathTemplate = "/<matched-secret-namespace>/";
const discoverySecretPathTemplate = "/<matched-secret-namespace?>/<matched-secret-leaf>";
const allowedEvidencePaths = [
  rootIndexPath,
  tokenPath,
  identityPath,
  roleIndexPath,
  credentialPathTemplate,
  discoveryRootPath,
  discoveryNamespacePathTemplate,
  discoverySecretPathTemplate,
] as const;
const maximumRequestCount = 8;
const expectedRequestFormatAttestation = {
  token: "imds-default-accept-omitted",
  rootAndDirectoryListings: "imds-default-accept-omitted",
  roleIndex: "imds-default-accept-omitted",
  structuredDocumentsAndSecretLeaf: "application/json",
} as const;
const expectedCredentialKeys = ["Code", "AccessKeyId", "SecretAccessKey", "Token", "Expiration"] as const;
const expectedIdentityKeys = ["accountId", "instanceId", "region"] as const;
const knownDiscoveryNamespaces = new Set(Object.keys(DISCOVERY_NAMESPACE_RULES));
const directDiscoverySecretLeaves = new Set<string>(DIRECT_SECRET_LEAVES);
const knownDiscoverySecretLeaves = new Set<string>([
  ...DIRECT_SECRET_LEAVES,
  ...Object.values(DISCOVERY_NAMESPACE_RULES).flat(),
]);
const knownSecretObjectKeys = new Set<string>(SECRET_OBJECT_KEYS);
const explicitDeniedCidrs = [
  "169.254.0.0/16",
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "100.64.0.0/10",
] as const;
const eligibleAliasEmail = "swve@wearehackerone.com";
const eligibleTeamId = "team_n98ERpVwV7HqmWRudAyK8sXQ";
const eligibleProjectId = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
const requestedPolicy = {
  allow: [],
  subnets: { deny: [...explicitDeniedCidrs] },
} satisfies NetworkPolicy;
const sha256Pattern = /^[a-f0-9]{64}$/u;
const safeChildKeyPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;
const listingRejectionReasons = new Set([
  "missing-or-oversized-listing", "json-container-listing", "empty-or-excessive-listing",
  "unsafe-child-key", "non-utf8-listing",
]);
const secretRejectionReasons = new Set([
  "missing-or-oversized-secret", "empty-secret", "non-object-json-secret",
  "unsafe-secret-object-keys", "unrecognized-secret-object", "non-scalar-secret",
  "non-utf8-or-invalid-json-secret", "unrecognized-secret-leaf",
  "unexpected-scalar-content-type", "weak-or-placeholder-secret",
]);

interface Attempt {
  classification?: unknown;
  method?: unknown;
  path?: unknown;
  requestSucceeded?: unknown;
  statusCode?: unknown;
  byteLength?: unknown;
  contentType?: unknown;
  sha256?: unknown;
  parsedJsonKeyNames?: unknown;
  errorCode?: unknown;
  durationMs?: unknown;
  listingSafe?: unknown;
  safeChildCount?: unknown;
  matchedAllowlistedChildKeyNames?: unknown;
  listingRejectionReason?: unknown;
  secretProofType?: unknown;
  secretObjectKeyNames?: unknown;
  secretRejectedUnsafe?: unknown;
  secretRejectionReason?: unknown;
  credentialValuesValidated?: unknown;
}

interface AssessmentInput {
  guestResult: Record<string, unknown> | undefined;
  policyConfirmed: boolean;
  credentialContextConfirmed: boolean;
  commandSucceeded: boolean;
  cleanupSucceeded: boolean;
  executionError?: string | undefined;
}

function requiredCredentials(): {
  credentials: { token: string; teamId: string; projectId: string };
  context: { mode: "explicit"; teamId: string; projectId: string; tokenProvided: true };
} {
  const token = process.env.VERCEL_TOKEN;
  const teamId = process.env.VERCEL_TEAM_ID;
  const projectId = process.env.VERCEL_PROJECT_ID;
  if (!token || !teamId || !projectId) {
    throw new Error(
      "VERCEL_TOKEN, VERCEL_TEAM_ID, and VERCEL_PROJECT_ID are all required so evidence records an explicit authorization context",
    );
  }
  if (teamId !== eligibleTeamId || projectId !== eligibleProjectId) {
    throw new Error("SBX-020 must use the verified HackerOne-alias Vercel team and project");
  }
  return {
    credentials: { token, teamId, projectId },
    context: { mode: "explicit", teamId, projectId, tokenProvided: true },
  };
}

async function verifyAliasIdentity(token: string): Promise<string> {
  const response = await fetch("https://api.vercel.com/v2/user", {
    headers: { Authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error(`could not verify Vercel token identity (${response.status})`);
  const payload = await response.json() as { user?: { email?: unknown } };
  const email = payload.user?.email;
  if (email !== eligibleAliasEmail) {
    throw new Error("Vercel token is not authenticated as the required HackerOne alias");
  }
  return email;
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function safeString(value: unknown, maximum: number): string | undefined {
  return typeof value === "string" ? value.replace(/[\0\r\n]/gu, "").slice(0, maximum) : undefined;
}

export function equivalentMmdsPolicy(observed: unknown): boolean {
  const policy = record(observed);
  if (!policy) return false;
  const policyKeys = Object.keys(policy).sort();
  const canonicalKeys = ["subnets"];
  const requestedKeys = ["allow", "subnets"];
  if (JSON.stringify(policyKeys) !== JSON.stringify(canonicalKeys) &&
    JSON.stringify(policyKeys) !== JSON.stringify(requestedKeys)) return false;
  if (Object.hasOwn(policy, "allow") && (!Array.isArray(policy.allow) || policy.allow.length !== 0)) return false;
  const subnets = record(policy.subnets);
  if (!subnets || JSON.stringify(Object.keys(subnets).sort()) !== JSON.stringify(["deny"])) return false;
  return Array.isArray(subnets.deny) &&
    JSON.stringify(subnets.deny) === JSON.stringify(explicitDeniedCidrs);
}

export function sanitizeGuestResult(value: unknown): Record<string, unknown> | undefined {
  const input = record(value);
  if (!input) return undefined;
  const runtime = record(input.runtime);
  const bounds = record(input.bounds);
  const route = record(input.routeControl);
  const requestFormats = record(input.requestFormatAttestation);
  const flow = record(input.flow);
  const attempts = Array.isArray(input.attempts) ? input.attempts : [];
  return {
    ok: input.ok === true,
    mode: input.mode === "execute" ? "execute" : safeString(input.mode, 32),
    runId: safeString(input.runId, 128),
    testId: safeString(input.testId, 128),
    caseId: safeString(input.caseId, 128),
    target: input.target === target ? target : undefined,
    startedAt: safeString(input.startedAt, 64),
    completedAt: safeString(input.completedAt, 64),
    runtime: runtime ? {
      nodeVersion: safeString(runtime.nodeVersion, 64),
      platform: safeString(runtime.platform, 64),
      arch: safeString(runtime.arch, 64),
    } : undefined,
    bounds: bounds ? {
      sequentialRequestsOnly: bounds.sequentialRequestsOnly === true,
      maximumRequestCount: Number.isInteger(bounds.maximumRequestCount) ? bounds.maximumRequestCount : undefined,
      actualRequestCount: Number.isInteger(bounds.actualRequestCount) ? bounds.actualRequestCount : undefined,
      interRequestDelayMs: Number.isInteger(bounds.interRequestDelayMs) ? bounds.interRequestDelayMs : undefined,
      maximumRequestsPerSecond: Number.isInteger(bounds.maximumRequestsPerSecond)
        ? bounds.maximumRequestsPerSecond
        : undefined,
      timeoutMs: Number.isInteger(bounds.timeoutMs) ? bounds.timeoutMs : undefined,
      maxResponseBytes: Number.isInteger(bounds.maxResponseBytes) ? bounds.maxResponseBytes : undefined,
    } : undefined,
    bodyRetention: input.bodyRetention === "none" ? "none" : "unexpected",
    tokenRetention: input.tokenRetention === "guest-memory-only-during-flow"
      ? "guest-memory-only-during-flow"
      : "unexpected",
    sensitiveLeafValueOrDigestRetention: input.sensitiveLeafValueOrDigestRetention === "none"
      ? "none"
      : "unexpected",
    requestFormatAttestation: requestFormats ? {
      token: safeString(requestFormats.token, 64),
      rootAndDirectoryListings: safeString(requestFormats.rootAndDirectoryListings, 64),
      roleIndex: safeString(requestFormats.roleIndex, 64),
      structuredDocumentsAndSecretLeaf: safeString(requestFormats.structuredDocumentsAndSecretLeaf, 64),
    } : undefined,
    routeControl: route ? {
      toolAvailable: route.toolAvailable === true,
      routePresent: route.routePresent === true,
      exitCode: Number.isInteger(route.exitCode) ? route.exitCode : undefined,
      errorCode: safeString(route.errorCode, 64),
      targetMentioned: route.targetMentioned === true,
      stdoutSha256: typeof route.stdoutSha256 === "string" && sha256Pattern.test(route.stdoutSha256)
        ? route.stdoutSha256
        : undefined,
      durationMs: Number.isInteger(route.durationMs) ? route.durationMs : undefined,
    } : undefined,
    attempts: attempts.slice(0, maximumRequestCount).map((attemptValue) => {
      const attempt = record(attemptValue) as Attempt | undefined;
      const classification = [
        "root-index", "token", "identity", "role-index", "credential-document",
        "discovery-root", "discovery-namespace", "discovery-secret",
      ]
        .includes(attempt?.classification as string) ? attempt?.classification : undefined;
      const suppressSensitiveDigest = classification === "token" || classification === "role-index" ||
        classification === "credential-document" || classification === "discovery-root" ||
        classification === "discovery-namespace" || classification === "discovery-secret";
      const suppressSensitiveJsonKeys = classification === "token" || classification === "role-index" ||
        classification === "discovery-root" || classification === "discovery-namespace" ||
        classification === "discovery-secret";
      const keyNames = !suppressSensitiveJsonKeys && Array.isArray(attempt?.parsedJsonKeyNames)
        ? attempt.parsedJsonKeyNames.filter((key): key is string => typeof key === "string").slice(0, 64)
          .map((key) => key.replace(/[\0\r\n]/gu, "").slice(0, 128))
        : [];
      const matchedAllowlistedChildKeyNames = Array.isArray(attempt?.matchedAllowlistedChildKeyNames)
        ? attempt.matchedAllowlistedChildKeyNames.filter(
          (key): key is string => typeof key === "string" && safeChildKeyPattern.test(key) &&
            (knownDiscoveryNamespaces.has(key) || knownDiscoverySecretLeaves.has(key)),
        ).slice(0, 64)
        : [];
      const secretObjectKeyNames = Array.isArray(attempt?.secretObjectKeyNames)
        ? attempt.secretObjectKeyNames.filter(
          (key): key is string => typeof key === "string" && safeChildKeyPattern.test(key),
        ).slice(0, 64)
        : [];
      return {
        classification,
        method: attempt?.method === "GET" || attempt?.method === "PUT" ? attempt.method : undefined,
        path: allowedEvidencePaths.includes(attempt?.path as never) ? attempt?.path : undefined,
        requestSucceeded: attempt?.requestSucceeded === true,
        statusCode: Number.isInteger(attempt?.statusCode) ? attempt?.statusCode : undefined,
        byteLength: Number.isInteger(attempt?.byteLength) ? attempt?.byteLength : undefined,
        contentType: safeString(attempt?.contentType, 256),
        sha256: !suppressSensitiveDigest && typeof attempt?.sha256 === "string" && sha256Pattern.test(attempt.sha256)
          ? attempt.sha256
          : undefined,
        parsedJsonKeyNames: keyNames,
        errorCode: safeString(attempt?.errorCode, 64),
        durationMs: Number.isInteger(attempt?.durationMs) ? attempt?.durationMs : undefined,
        listingSafe: attempt?.listingSafe === true,
        safeChildCount: Number.isInteger(attempt?.safeChildCount) &&
          typeof attempt?.safeChildCount === "number" && attempt.safeChildCount >= 0 && attempt.safeChildCount <= 64
          ? attempt.safeChildCount
          : undefined,
        matchedAllowlistedChildKeyNames,
        listingRejectionReason: typeof attempt?.listingRejectionReason === "string" &&
          listingRejectionReasons.has(attempt.listingRejectionReason)
          ? attempt.listingRejectionReason
          : undefined,
        secretProofType: attempt?.secretProofType === "scalar-text" || attempt?.secretProofType === "secret-object"
          ? attempt.secretProofType
          : undefined,
        secretObjectKeyNames,
        secretRejectedUnsafe: attempt?.secretRejectedUnsafe === true,
        secretRejectionReason: typeof attempt?.secretRejectionReason === "string" &&
          secretRejectionReasons.has(attempt.secretRejectionReason)
          ? attempt.secretRejectionReason
          : undefined,
        credentialValuesValidated: attempt?.credentialValuesValidated === true,
      };
    }),
    flow: flow ? {
      tokenAcquired: flow.tokenAcquired === true,
      tokenResponseRejectedUnsafe: flow.tokenResponseRejectedUnsafe === true,
      roleNameValidated: flow.roleNameValidated === true,
      roleResponseRejectedUnsafe: flow.roleResponseRejectedUnsafe === true,
      credentialDocumentRequested: flow.credentialDocumentRequested === true,
      credentialValuesValidated: flow.credentialValuesValidated === true,
      credentialProofObserved: flow.credentialProofObserved === true,
      unexpectedCredentialDocument: flow.unexpectedCredentialDocument === true,
      stoppedAfterCredentialDocument: flow.stoppedAfterCredentialDocument === true,
      discoveryStarted: flow.discoveryStarted === true,
      discoveryRootListingSafe: flow.discoveryRootListingSafe === true,
      discoveryNamespaceListingSafe: flow.discoveryNamespaceListingSafe === true,
      discoveryListingRejectedUnsafe: flow.discoveryListingRejectedUnsafe === true,
      matchedKnownNamespace: typeof flow.matchedKnownNamespace === "string" &&
        safeChildKeyPattern.test(flow.matchedKnownNamespace) ? flow.matchedKnownNamespace : undefined,
      matchedSecretLeaf: typeof flow.matchedSecretLeaf === "string" &&
        safeChildKeyPattern.test(flow.matchedSecretLeaf) ? flow.matchedSecretLeaf : undefined,
      discoverySecretRequested: flow.discoverySecretRequested === true,
      discoverySecretProofType: flow.discoverySecretProofType === "scalar-text" ||
        flow.discoverySecretProofType === "secret-object" ? flow.discoverySecretProofType : undefined,
      discoverySecretRejectedUnsafe: flow.discoverySecretRejectedUnsafe === true,
      stoppedAtProof: flow.stoppedAtProof === true,
    } : undefined,
  };
}

function populated(attempt: Attempt): boolean {
  return attempt.requestSucceeded === true && typeof attempt.statusCode === "number" &&
    attempt.statusCode >= 200 && attempt.statusCode < 300 && typeof attempt.byteLength === "number" &&
    attempt.byteLength > 0;
}

function includesExpectedKeys(attempt: Attempt | undefined, expected: readonly string[]): boolean {
  if (!attempt || !Array.isArray(attempt.parsedJsonKeyNames)) return false;
  const names = new Set(attempt.parsedJsonKeyNames.filter((name): name is string => typeof name === "string"));
  return expected.every((name) => names.has(name));
}

export function assessMmdsRun(input: AssessmentInput): Record<string, unknown> {
  const result = input.guestResult;
  const attempts = Array.isArray(result?.attempts) ? result.attempts as Attempt[] : [];
  const route = record(result?.routeControl);
  const bounds = record(result?.bounds);
  const requestFormats = record(result?.requestFormatAttestation);
  const flow = record(result?.flow);
  const rootAttempt = attempts.find((attempt) => attempt.classification === "root-index");
  const tokenAttempt = attempts.find((attempt) => attempt.classification === "token");
  const identityAttempt = attempts.find((attempt) => attempt.classification === "identity");
  const roleAttempt = attempts.find((attempt) => attempt.classification === "role-index");
  const credentialAttempt = attempts.find((attempt) => attempt.classification === "credential-document");
  const discoveryRootAttempt = attempts.find((attempt) => attempt.classification === "discovery-root");
  const discoveryNamespaceAttempt = attempts.find((attempt) => attempt.classification === "discovery-namespace");
  const discoverySecretAttempt = attempts.find((attempt) => attempt.classification === "discovery-secret");
  const anyHttpResponse = attempts.some((attempt) => attempt.requestSucceeded === true);
  const routeControlPassed = route?.routePresent === true && route.targetMentioned === true;
  const suitableNegativeControl = routeControlPassed || anyHttpResponse;
  const tokenDerivativeAbsent = tokenAttempt?.sha256 === undefined &&
    (!Array.isArray(tokenAttempt?.parsedJsonKeyNames) || tokenAttempt.parsedJsonKeyNames.length === 0);
  const roleDerivativeAbsent = roleAttempt?.sha256 === undefined &&
    (!Array.isArray(roleAttempt?.parsedJsonKeyNames) || roleAttempt.parsedJsonKeyNames.length === 0);
  const directoryDerivativesAbsent = [discoveryRootAttempt, discoveryNamespaceAttempt].every(
    (attempt) => attempt === undefined || (attempt.sha256 === undefined &&
      (!Array.isArray(attempt.parsedJsonKeyNames) || attempt.parsedJsonKeyNames.length === 0)),
  );
  const requestFormatAttestationPassed = requestFormats?.token === expectedRequestFormatAttestation.token &&
    requestFormats.rootAndDirectoryListings === expectedRequestFormatAttestation.rootAndDirectoryListings &&
    requestFormats.roleIndex === expectedRequestFormatAttestation.roleIndex &&
    requestFormats.structuredDocumentsAndSecretLeaf ===
      expectedRequestFormatAttestation.structuredDocumentsAndSecretLeaf;
  const fixedPrefixPassed = attempts[0]?.classification === "root-index" && attempts[0]?.method === "GET" &&
    attempts[0]?.path === rootIndexPath && attempts[1]?.classification === "token" &&
    attempts[1]?.method === "PUT" && attempts[1]?.path === tokenPath;
  const tokenAcquired = flow?.tokenAcquired === true;
  const roleNameValidated = flow?.roleNameValidated === true;
  const credentialDocumentPopulated = populated(credentialAttempt ?? {});
  const credentialStructureObserved = credentialDocumentPopulated &&
    includesExpectedKeys(credentialAttempt, expectedCredentialKeys) &&
    credentialAttempt?.credentialValuesValidated === true && flow?.credentialValuesValidated === true;
  const unexpectedCredentialDocument = credentialDocumentPopulated && !credentialStructureObserved;
  const discoveryExpected = tokenAcquired && !credentialStructureObserved && !unexpectedCredentialDocument &&
    flow?.roleResponseRejectedUnsafe !== true;
  const discoveryDecisionPassed = (flow?.discoveryStarted === true) === discoveryExpected;
  const matches = (attempt: Attempt | undefined, classification: string, path: string): boolean =>
    attempt?.classification === classification && attempt.method === "GET" && attempt.path === path;
  let cursor = 2;
  let authenticatedSequencePassed = true;
  if (tokenAcquired) {
    authenticatedSequencePassed = matches(attempts[cursor], "identity", identityPath);
    cursor += 1;
    authenticatedSequencePassed &&= matches(attempts[cursor], "role-index", roleIndexPath);
    cursor += 1;
    if (roleNameValidated) {
      authenticatedSequencePassed &&= matches(attempts[cursor], "credential-document", credentialPathTemplate) &&
        flow?.credentialDocumentRequested === true;
      cursor += 1;
    }
    if (flow?.discoveryStarted === true) {
      authenticatedSequencePassed &&= matches(attempts[cursor], "discovery-root", discoveryRootPath);
      cursor += 1;
      if (typeof flow.matchedKnownNamespace === "string") {
        authenticatedSequencePassed &&= matches(
          attempts[cursor],
          "discovery-namespace",
          discoveryNamespacePathTemplate,
        );
        cursor += 1;
      }
      if (flow.discoverySecretRequested === true) {
        authenticatedSequencePassed &&= matches(
          attempts[cursor],
          "discovery-secret",
          discoverySecretPathTemplate,
        );
        cursor += 1;
      }
    }
  }
  authenticatedSequencePassed &&= cursor === attempts.length;
  const flowBoundsPassed = bounds?.maximumRequestCount === maximumRequestCount &&
    bounds.actualRequestCount === attempts.length && attempts.length >= 2 && attempts.length <= maximumRequestCount &&
    typeof bounds.interRequestDelayMs === "number" && bounds.interRequestDelayMs >= 200 &&
    bounds.maximumRequestsPerSecond === 5;
  const knownNamespaceMatched = flow?.matchedKnownNamespace === undefined || (
    typeof flow.matchedKnownNamespace === "string" && knownDiscoveryNamespaces.has(flow.matchedKnownNamespace)
  );
  const knownSecretLeafMatched = flow?.matchedSecretLeaf === undefined || (
    typeof flow.matchedSecretLeaf === "string" && knownDiscoverySecretLeaves.has(flow.matchedSecretLeaf)
  );
  const rootMatchedChildren = Array.isArray(discoveryRootAttempt?.matchedAllowlistedChildKeyNames)
    ? discoveryRootAttempt.matchedAllowlistedChildKeyNames
    : [];
  const namespaceMatchedChildren = Array.isArray(discoveryNamespaceAttempt?.matchedAllowlistedChildKeyNames)
    ? discoveryNamespaceAttempt.matchedAllowlistedChildKeyNames
    : [];
  const matchedNamespace = typeof flow?.matchedKnownNamespace === "string"
    ? flow.matchedKnownNamespace
    : undefined;
  const matchedLeaf = typeof flow?.matchedSecretLeaf === "string" ? flow.matchedSecretLeaf : undefined;
  const configuredNamespaceLeaves = matchedNamespace
    ? (DISCOVERY_NAMESPACE_RULES[matchedNamespace] as readonly string[] | undefined)
    : undefined;
  const matchedPairAllowed = matchedLeaf === undefined || (
    matchedNamespace
      ? configuredNamespaceLeaves?.includes(matchedLeaf) === true
      : directDiscoverySecretLeaves.has(matchedLeaf)
  );
  const listingRejectedByAttempt = discoveryRootAttempt?.listingRejectionReason !== undefined ||
    discoveryNamespaceAttempt?.listingRejectionReason !== undefined;
  const listingAttributionPassed = flow?.discoveryStarted !== true || (
    discoveryRootAttempt !== undefined && flow.discoveryRootListingSafe === (discoveryRootAttempt.listingSafe === true) &&
    flow.discoveryListingRejectedUnsafe === listingRejectedByAttempt &&
    (matchedNamespace === undefined || (
      discoveryRootAttempt.listingSafe === true && rootMatchedChildren.includes(matchedNamespace) &&
      discoveryNamespaceAttempt !== undefined &&
      flow.discoveryNamespaceListingSafe === (discoveryNamespaceAttempt.listingSafe === true)
    )) &&
    (matchedLeaf === undefined || (
      matchedNamespace
        ? discoveryNamespaceAttempt?.listingSafe === true && namespaceMatchedChildren.includes(matchedLeaf)
        : discoveryRootAttempt.listingSafe === true && rootMatchedChildren.includes(matchedLeaf)
    ))
  );
  const flowIntegrityPassed = fixedPrefixPassed && authenticatedSequencePassed && flowBoundsPassed &&
    tokenDerivativeAbsent && roleDerivativeAbsent && knownNamespaceMatched && knownSecretLeafMatched &&
    directoryDerivativesAbsent && matchedPairAllowed && listingAttributionPassed && discoveryDecisionPassed &&
    requestFormatAttestationPassed;
  const guestIntegrityPassed = result?.ok === true && result.target === target &&
    result.bodyRetention === "none" && result.tokenRetention === "guest-memory-only-during-flow" &&
    result.sensitiveLeafValueOrDigestRetention === "none" &&
    bounds?.sequentialRequestsOnly === true && flowIntegrityPassed;
  const baseControlsPassed = input.policyConfirmed && input.credentialContextConfirmed &&
    input.commandSucceeded && input.cleanupSucceeded && input.executionError === undefined &&
    guestIntegrityPassed;
  const identityStructureObserved = populated(identityAttempt ?? {}) &&
    includesExpectedKeys(identityAttempt, expectedIdentityKeys);
  const discoverySecretPopulated = populated(discoverySecretAttempt ?? {});
  const discoveryProofType = discoverySecretAttempt?.secretProofType;
  const discoveryObjectStructurePassed = discoveryProofType !== "secret-object" || (
    Array.isArray(discoverySecretAttempt?.secretObjectKeyNames) &&
    discoverySecretAttempt.secretObjectKeyNames.some(
      (name) => typeof name === "string" && knownSecretObjectKeys.has(name),
    )
  );
  const discoverySecretProofObserved = discoverySecretPopulated &&
    (discoveryProofType === "scalar-text" || discoveryProofType === "secret-object") &&
    discoveryObjectStructurePassed && typeof flow?.matchedSecretLeaf === "string" &&
    knownDiscoverySecretLeaves.has(flow.matchedSecretLeaf);
  const unsafeProtocolValue = flow?.tokenResponseRejectedUnsafe === true ||
    flow?.roleResponseRejectedUnsafe === true || flow?.discoveryListingRejectedUnsafe === true ||
    flow?.discoverySecretRejectedUnsafe === true;
  const unexpectedDiscoverySecret = discoverySecretPopulated && !discoverySecretProofObserved;
  const proofStopPassed = (credentialStructureObserved || discoverySecretProofObserved)
    ? flow?.stoppedAtProof === true && attempts.at(-1) === (credentialStructureObserved
      ? credentialAttempt
      : discoverySecretAttempt)
    : flow?.stoppedAtProof !== true;
  const highCandidate = baseControlsPassed && proofStopPassed &&
    (credentialStructureObserved || discoverySecretProofObserved);
  const listingObserved = discoveryRootAttempt?.listingSafe === true ||
    discoveryNamespaceAttempt?.listingSafe === true;
  const supportingSignal = baseControlsPassed && proofStopPassed && !highCandidate && !unsafeProtocolValue &&
    !unexpectedCredentialDocument && !unexpectedDiscoverySecret &&
    (tokenAcquired || identityStructureObserved || roleNameValidated || listingObserved);
  const flowReachedSafeTerminal = tokenAttempt !== undefined && authenticatedSequencePassed;
  const pass = baseControlsPassed && !highCandidate && !supportingSignal && !unexpectedCredentialDocument &&
    !unexpectedDiscoverySecret && !unsafeProtocolValue && proofStopPassed &&
    flowReachedSafeTerminal && suitableNegativeControl;
  const outcome = highCandidate ? "candidate" : supportingSignal ? "supporting-signal" : pass ? "pass" : "indeterminate";
  return {
    outcome,
    candidate: highCandidate,
    controlsPassed: baseControlsPassed,
    controls: {
      policyConfirmed: input.policyConfirmed,
      credentialContextConfirmed: input.credentialContextConfirmed,
      commandSucceeded: input.commandSucceeded,
      cleanupSucceeded: input.cleanupSucceeded,
      guestIntegrityPassed,
      flowIntegrityPassed,
      tokenDerivativeAbsent,
      roleDerivativeAbsent,
      directoryDerivativesAbsent,
      requestFormatAttestationPassed,
      discoveryDecisionPassed,
      matchedPairAllowed,
      listingAttributionPassed,
      routeControlPassed,
      anyHttpResponse,
      suitableNegativeControl,
      flowReachedSafeTerminal,
      unsafeProtocolValue,
      unexpectedCredentialDocument,
      unexpectedDiscoverySecret,
      proofStopPassed,
    },
    signals: {
      rootStatus: rootAttempt?.statusCode,
      tokenStatus: tokenAttempt?.statusCode,
      tokenAcquired,
      identityStructureObserved,
      roleNameValidated,
      credentialDocumentRequested: flow?.credentialDocumentRequested === true,
      credentialValuesValidated: credentialAttempt?.credentialValuesValidated === true &&
        flow?.credentialValuesValidated === true,
      credentialDocumentPopulated,
      credentialStructureObserved,
      credentialStatus: credentialAttempt?.statusCode,
      credentialByteLength: credentialAttempt?.byteLength,
      credentialJsonKeyNames: credentialAttempt?.parsedJsonKeyNames,
      discoveryStarted: flow?.discoveryStarted === true,
      discoveryRootStatus: discoveryRootAttempt?.statusCode,
      discoveryRootListingSafe: discoveryRootAttempt?.listingSafe === true,
      discoveryRootChildCount: discoveryRootAttempt?.safeChildCount,
      discoveryRootMatchedAllowlistedChildKeyNames: discoveryRootAttempt?.matchedAllowlistedChildKeyNames,
      discoveryNamespaceStatus: discoveryNamespaceAttempt?.statusCode,
      discoveryNamespaceListingSafe: discoveryNamespaceAttempt?.listingSafe === true,
      discoveryNamespaceChildCount: discoveryNamespaceAttempt?.safeChildCount,
      discoveryNamespaceMatchedAllowlistedChildKeyNames: discoveryNamespaceAttempt?.matchedAllowlistedChildKeyNames,
      matchedKnownNamespace: flow?.matchedKnownNamespace,
      matchedSecretLeaf: flow?.matchedSecretLeaf,
      discoverySecretRequested: flow?.discoverySecretRequested === true,
      discoverySecretStatus: discoverySecretAttempt?.statusCode,
      discoverySecretPathTemplate: discoverySecretAttempt ? discoverySecretPathTemplate : undefined,
      discoverySecretByteLength: discoverySecretAttempt?.byteLength,
      discoverySecretProofType: discoveryProofType,
      discoverySecretObjectKeyNames: discoverySecretAttempt?.secretObjectKeyNames,
      discoverySecretProofObserved,
    },
  };
}

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  const runId = randomUUID();
  const { credentials, context } = requiredCredentials();
  const aliasEmail = await verifyAliasIdentity(credentials.token);
  const credentialContext = {
    ...context,
    mode: "explicit-alias-verified" as const,
    aliasEmail,
  };
  const guestSource = await readFile(resolve("guest/mmds-link-local-probe.mjs"), "utf8");
  const discoveryRulesSource = await readFile(resolve("guest/mmds-discovery-rules.mjs"), "utf8");
  const guestSourceSha256 = createHash("sha256").update(guestSource).digest("hex");
  const discoveryRulesSourceSha256 = createHash("sha256").update(discoveryRulesSource).digest("hex");
  const configuration = {
    scopeConfirmation: "I_UNDERSTAND_THIS_TARGETS_ONLY_FIRECRACKER_MMDS",
    runId,
    testId: "SBX-020-POC",
    caseId: "mmds-under-explicit-link-local-deny",
    target,
    timeoutMs: 2_000,
    routeTimeoutMs: 1_500,
    interRequestDelayMs: 250,
    maxResponseBytes: 16_384,
  };
  const serializedConfiguration = JSON.stringify(configuration);
  if (guestSource.includes(credentials.token) || discoveryRulesSource.includes(credentials.token) ||
    serializedConfiguration.includes(credentials.token)) {
    throw new Error("guest material unexpectedly contains the Vercel credential");
  }

  const cleanup = {
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    errors: [] as string[],
  };
  let sandbox: Sandbox | undefined;
  let sandboxIdentity: Record<string, unknown> | undefined;
  let observedPolicy: NetworkPolicy | undefined;
  let commandRecord: Record<string, unknown> | undefined;
  let sanitizedGuestResult: Record<string, unknown> | undefined;
  let executionError: string | undefined;

  try {
    sandbox = await Sandbox.create({
      name: `sbx-020-poc-${runId.slice(0, 8)}`,
      persistent: false,
      timeout: 120_000,
      networkPolicy: requestedPolicy,
      tags: { harness: "vsc", test: "SBX-020", run: runId.slice(0, 12) },
      ...credentials,
    });
    const session = sandbox.currentSession();
    observedPolicy = session.networkPolicy ?? sandbox.networkPolicy;
    sandboxIdentity = {
      name: sandbox.name,
      persistent: sandbox.persistent,
      sessionId: session.sessionId,
      region: session.region,
      requestedAt: session.requestedAt.toISOString(),
      createdAt: session.createdAt.toISOString(),
      startedAt: session.startedAt?.toISOString(),
      runtime: session.runtime ?? sandbox.runtime,
      image: sandbox.image,
      vcpus: session.vcpus,
      memoryMb: session.memory,
    };
    await sandbox.writeFiles([
      { path: remoteProbe, content: guestSource, mode: 0o700 },
      { path: remoteDiscoveryRules, content: discoveryRulesSource, mode: 0o600 },
    ]);
    const command = await sandbox.runCommand({
      cmd: "node",
      args: [remoteProbe, Buffer.from(serializedConfiguration).toString("base64url")],
      timeoutMs: 30_000,
    });
    const [stdout, stderr] = await Promise.all([command.stdout(), command.stderr()]);
    let decoded: unknown;
    try {
      decoded = JSON.parse(stdout);
    } catch {
      throw new Error("guest probe emitted invalid JSON");
    }
    sanitizedGuestResult = sanitizeGuestResult(decoded);
    commandRecord = {
      commandId: command.cmdId,
      exitCode: command.exitCode,
      durationMs: command.durationMs,
      stderrByteLength: Buffer.byteLength(stderr),
    };
  } catch (error) {
    executionError = error instanceof Error ? error.message : String(error);
  } finally {
    if (sandbox) {
      cleanup.stopAttempted = true;
      try {
        await sandbox.stop();
        cleanup.stopped = true;
      } catch (error) {
        cleanup.errors.push(`stop: ${error instanceof Error ? error.message : String(error)}`);
      }
      cleanup.deleteAttempted = true;
      try {
        await sandbox.delete();
        cleanup.deleted = true;
      } catch (error) {
        cleanup.errors.push(`delete: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }

  const policyConfirmed = equivalentMmdsPolicy(observedPolicy);
  const canonicalEmptyAllowOmitted = policyConfirmed && record(observedPolicy) !== undefined &&
    !Object.hasOwn(record(observedPolicy)!, "allow");
  const assessment = assessMmdsRun({
    guestResult: sanitizedGuestResult,
    policyConfirmed,
    credentialContextConfirmed: credentialContext.mode === "explicit-alias-verified" &&
      credentialContext.aliasEmail === eligibleAliasEmail,
    commandSucceeded: commandRecord?.exitCode === 0,
    cleanupSucceeded: cleanup.stopped && cleanup.deleted && cleanup.errors.length === 0,
    ...(executionError ? { executionError } : {}),
  });
  const evidence = {
    schemaVersion: 5,
    testId: "SBX-020",
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    assessment,
    target,
    policy: {
      requested: requestedPolicy,
      observed: observedPolicy,
      semantics: "custom-default-deny-with-explicit-link-local-and-private-cidr-denies",
      explicitLinkLocalDeny: explicitDeniedCidrs[0],
      canonicalEmptyAllowOmitted,
    },
    credentialContext,
    probeAttestation: {
      guestSourceSha256,
      discoveryRulesSourceSha256,
      requestFormats: expectedRequestFormatAttestation,
    },
    sandbox: sandboxIdentity,
    command: commandRecord,
    guestResult: sanitizedGuestResult,
    responseBodiesStored: false,
    tokenValueOrDigestStored: false,
    credentialOrDiscoveryValueOrDigestStored: false,
    roleNameStored: false,
    cleanup,
    executionError,
  };
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const privateEvidencePath = resolve(artifactsDirectory, `SBX-020-poc-${runId}-private.json`);
  await writeFile(privateEvidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify({
    assessment,
    policyConfirmed,
    sandbox: sandboxIdentity,
    cleanup,
    responseBodiesStored: false,
    tokenValueOrDigestStored: false,
    credentialOrDiscoveryValueOrDigestStored: false,
    roleNameStored: false,
    privateEvidencePath,
  }, null, 2)}\n`);
  if (executionError || cleanup.errors.length > 0) {
    throw new Error([executionError, ...cleanup.errors].filter(Boolean).join("; "));
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
