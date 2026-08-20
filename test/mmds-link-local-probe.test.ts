import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
// @ts-expect-error The guest probe is deliberately executable plain Node ESM.
import * as mmdsProbe from "../guest/mmds-link-local-probe.mjs";
import {
  assessMmdsRun,
  equivalentMmdsPolicy,
  sanitizeGuestResult,
} from "../pocs/SBX-020/mmds-link-local.js";

const {
  CREDENTIAL_PATH_TEMPLATE,
  DISCOVERY_NAMESPACE_PATH_TEMPLATE,
  DISCOVERY_ROOT_PATH,
  DISCOVERY_SECRET_PATH_TEMPLATE,
  IDENTITY_PATH,
  MMDS_REQUEST_FORMAT_ATTESTATION,
  ROLE_INDEX_PATH,
  ROOT_INDEX_PATH,
  TOKEN_PATH,
  TOKEN_TTL_SECONDS,
  requestHeadersForSpec,
  runMmdsProbe,
  validateMmdsProbeConfig,
} = mmdsProbe;
const executeFile = promisify(execFile);
const probePath = fileURLToPath(new URL("../guest/mmds-link-local-probe.mjs", import.meta.url));
const deniedCidrs = [
  "169.254.0.0/16",
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "100.64.0.0/10",
];

function rawConfig(overrides: Record<string, unknown> = {}) {
  return {
    scopeConfirmation: "I_UNDERSTAND_THIS_TARGETS_ONLY_FIRECRACKER_MMDS",
    runId: "run-mmds-test",
    testId: "SBX-020-TEST",
    caseId: "fixed-link-local",
    target: "169.254.169.254",
    timeoutMs: 500,
    routeTimeoutMs: 500,
    interRequestDelayMs: 200,
    maxResponseBytes: 4_096,
    ...overrides,
  };
}

function summary(path: string, statusCode: number, body: string, capturePrivateBody = false) {
  let keys: string[] = [];
  try {
    const value = JSON.parse(body) as unknown;
    if (value !== null && typeof value === "object" && !Array.isArray(value)) keys = Object.keys(value);
  } catch {
    // Plaintext token and role responses intentionally have no JSON keys.
  }
  return {
    path,
    requestSucceeded: true,
    statusCode,
    byteLength: Buffer.byteLength(body),
    contentType: keys.length > 0 ? "application/json" : "text/plain",
    sha256: createHash("sha256").update(body).digest("hex"),
    parsedJsonKeyNames: keys,
    privateBody: capturePrivateBody ? Buffer.from(body) : undefined,
    body,
    deliberatelyUnknownField: body,
    durationMs: 1,
  };
}

function routeControl(routePresent = true) {
  return {
    toolAvailable: true,
    routePresent,
    exitCode: routePresent ? 0 : 2,
    targetMentioned: routePresent,
    stdoutSha256: routePresent ? "a".repeat(64) : undefined,
    durationMs: 1,
  };
}

function assessmentControls(guestResult: Record<string, unknown> | undefined) {
  return {
    guestResult,
    policyConfirmed: true,
    credentialContextConfirmed: true,
    commandSucceeded: true,
    cleanupSucceeded: true,
  };
}

describe("SBX-020 MMDS guest probe", () => {
  it("plans only the bounded eight-request IMDSv2/discovery flow with no token/body retention", async () => {
    const encoded = Buffer.from(JSON.stringify(rawConfig())).toString("base64url");
    const result = await executeFile(process.execPath, [probePath, encoded, "--plan"]);
    const plan = JSON.parse(result.stdout) as Record<string, unknown>;

    expect(plan).toMatchObject({
      ok: true,
      mode: "plan",
      target: "169.254.169.254",
      port: 80,
      sequentialRequestsOnly: true,
      stopAtCredentialProof: true,
      maximumRequestCount: 8,
      maximumRequestsPerSecond: 5,
      tokenResponseDigestRetained: false,
      roleResponseDigestRetained: false,
      directoryResponseDigestRetained: false,
      credentialOrDiscoveryValueOrDigestRetained: false,
      responseBodiesRetained: false,
      tokenValueRetained: false,
      roleNameRetained: false,
      requestFormatAttestation: MMDS_REQUEST_FORMAT_ATTESTATION,
    });
    expect(plan.flow).toEqual([
      { method: "GET", path: ROOT_INDEX_PATH, authentication: "none" },
      { method: "PUT", path: TOKEN_PATH, fixedTtlSeconds: TOKEN_TTL_SECONDS },
      { method: "GET", path: IDENTITY_PATH, authentication: "in-memory-token" },
      { method: "GET", path: ROLE_INDEX_PATH, authentication: "in-memory-token" },
      { method: "GET", path: CREDENTIAL_PATH_TEMPLATE, condition: "one validated role segment" },
      {
        method: "GET",
        path: DISCOVERY_ROOT_PATH,
        responseFormat: "imds-default",
        acceptHeader: "omitted",
        condition: "no prior proof or unsafe response",
      },
      {
        method: "GET",
        path: DISCOVERY_NAMESPACE_PATH_TEMPLATE,
        responseFormat: "imds-default",
        acceptHeader: "omitted",
        condition: "one exact known namespace",
      },
      {
        method: "GET",
        path: DISCOVERY_SECRET_PATH_TEMPLATE,
        responseFormat: "json",
        acceptHeader: "application/json",
        condition: "one exact known secret leaf",
      },
    ]);
  });

  it("omits Accept on Firecracker IMDS listings and uses exact JSON only for a selected secret leaf", () => {
    const token = "mmdsv2-token-value-1234567890";
    const listingHeaders = requestHeadersForSpec({
      method: "GET",
      path: DISCOVERY_ROOT_PATH,
      headers: { "x-aws-ec2-metadata-token": token },
      discoveryKind: "directory",
    });
    const roleHeaders = requestHeadersForSpec({
      method: "GET",
      path: ROLE_INDEX_PATH,
      headers: { "x-aws-ec2-metadata-token": token },
    });
    const leafHeaders = requestHeadersForSpec({
      method: "GET",
      path: "/datadog/api_key",
      headers: { "x-aws-ec2-metadata-token": token },
      discoveryKind: "secret",
    });

    expect(listingHeaders).not.toHaveProperty("Accept");
    expect(roleHeaders).not.toHaveProperty("Accept");
    expect(leafHeaders).toMatchObject({ Accept: "application/json" });
  });

  it("rejects target overrides and every unrecognized configuration field", () => {
    expect(() => validateMmdsProbeConfig(rawConfig({ target: "169.254.169.253" }))).toThrow(
      "arbitrary link-local probing is forbidden",
    );
    expect(() => validateMmdsProbeConfig(rawConfig({ headers: { authorization: "secret" } }))).toThrow(
      "configuration field \"headers\" is not allowed",
    );
    expect(() => validateMmdsProbeConfig(rawConfig({ token: "secret" }))).toThrow(
      "configuration field \"token\" is not allowed",
    );
    expect(() => validateMmdsProbeConfig(rawConfig({ interRequestDelayMs: 199 }))).toThrow(
      "interRequestDelayMs must be an integer from 200 through 1000",
    );
  });

  it("stops after a rejected token request and suppresses the token-response digest", async () => {
    const calls: Array<Record<string, unknown>> = [];
    const result = await runMmdsProbe(validateMmdsProbeConfig(rawConfig()), {
      requester: async (spec: Record<string, unknown>) => {
        calls.push(spec);
        return summary(spec.path as string, 401, "token required");
      },
      routeInspector: async () => routeControl(),
      sleeper: async () => undefined,
    });

    expect(calls).toHaveLength(2);
    expect(calls[1]).toEqual({
      method: "PUT",
      path: TOKEN_PATH,
      headers: { "x-aws-ec2-metadata-token-ttl-seconds": "60" },
    });
    expect(result.attempts[1]).toMatchObject({ classification: "token", statusCode: 401 });
    expect(result.attempts[1].sha256).toBeUndefined();
    expect(result.attempts[1].parsedJsonKeyNames).toEqual([]);
    expect(JSON.stringify(result)).not.toContain("token required");
  });

  it("uses the token only in memory, validates one role segment, and stops at credential proof", async () => {
    const token = "mmdsv2-token-value-1234567890";
    const role = "research-role+safe";
    const identityBody = JSON.stringify({ accountId: "secret-account", instanceId: "i-secret", region: "us-test-1" });
    const credentialBody = JSON.stringify({
      Code: "Success",
      AccessKeyId: "AKIASECRET",
      SecretAccessKey: "secret-key-value",
      Token: "session-secret-value",
      Expiration: "2099-01-01T00:00:00Z",
    });
    const calls: Array<Record<string, unknown>> = [];
    let inFlight = 0;
    let maximumInFlight = 0;
    const requester = async (spec: Record<string, unknown>) => {
      calls.push(spec);
      inFlight += 1;
      maximumInFlight = Math.max(maximumInFlight, inFlight);
      await new Promise((resolveWait) => setTimeout(resolveWait, 3));
      inFlight -= 1;
      const path = spec.path as string;
      if (path === ROOT_INDEX_PATH) return summary(path, 401, "token required");
      if (path === TOKEN_PATH) return summary(path, 200, token, true);
      expect((spec.headers as Record<string, string>)["x-aws-ec2-metadata-token"]).toBe(token);
      if (path === IDENTITY_PATH) return summary(path, 200, identityBody);
      if (path === ROLE_INDEX_PATH) return summary(path, 200, `${role}\n`, true);
      expect(path).toBe(`${ROLE_INDEX_PATH}${encodeURIComponent(role)}`);
      return summary(path, 200, credentialBody, true);
    };
    const result = await runMmdsProbe(validateMmdsProbeConfig(rawConfig()), {
      requester,
      routeInspector: async () => routeControl(),
      sleeper: async () => undefined,
    });

    expect(maximumInFlight).toBe(1);
    expect(calls).toHaveLength(5);
    expect(result).toMatchObject({
      bodyRetention: "none",
      tokenRetention: "guest-memory-only-during-flow",
      sensitiveLeafValueOrDigestRetention: "none",
      bounds: { maximumRequestCount: 8, actualRequestCount: 5, sequentialRequestsOnly: true },
      flow: {
        tokenAcquired: true,
        roleNameValidated: true,
        credentialDocumentRequested: true,
        credentialProofObserved: true,
        stoppedAfterCredentialDocument: true,
        stoppedAtProof: true,
      },
    });
    expect(result.attempts.at(-1)).toMatchObject({
      classification: "credential-document",
      path: CREDENTIAL_PATH_TEMPLATE,
      statusCode: 200,
      parsedJsonKeyNames: ["Code", "AccessKeyId", "SecretAccessKey", "Token", "Expiration"],
    });
    const serialized = JSON.stringify(result);
    for (const forbidden of [token, role, "secret-account", "i-secret", "AKIASECRET", "secret-key-value", "session-secret-value"]) {
      expect(serialized).not.toContain(forbidden);
    }
    expect(serialized).not.toContain('"privateBody"');
    expect(serialized).not.toContain('"body"');
  });

  it("rejects key-complete IAM error/null documents without retaining their values", async () => {
    const token = "mmdsv2-token-value-1234567890";
    const role = "research-role-safe";
    const invalidCredentialBody = JSON.stringify({
      Code: "Error",
      AccessKeyId: null,
      SecretAccessKey: null,
      Token: null,
      Expiration: null,
      Message: "should-not-escape",
    });
    const result = await runMmdsProbe(validateMmdsProbeConfig(rawConfig()), {
      requester: async (spec: Record<string, unknown>) => {
        const path = spec.path as string;
        if (path === TOKEN_PATH) return summary(path, 200, token, true);
        if (path === ROLE_INDEX_PATH) return summary(path, 200, role, true);
        if (path.startsWith(ROLE_INDEX_PATH) && path !== ROLE_INDEX_PATH) {
          return summary(path, 200, invalidCredentialBody, true);
        }
        return summary(path, path === IDENTITY_PATH ? 404 : 401, "not available");
      },
      routeInspector: async () => routeControl(),
      sleeper: async () => undefined,
    });

    expect(result.flow).toMatchObject({
      credentialDocumentRequested: true,
      credentialValuesValidated: false,
      credentialProofObserved: false,
      unexpectedCredentialDocument: true,
      discoveryStarted: false,
      stoppedAtProof: false,
    });
    expect(JSON.stringify(result)).not.toContain("should-not-escape");
    const sanitized = sanitizeGuestResult(result);
    expect(assessMmdsRun(assessmentControls(sanitized))).toMatchObject({
      outcome: "indeterminate",
      candidate: false,
      controls: { unexpectedCredentialDocument: true },
    });
  });

  it("rejects a role index that is not one safe segment and never requests a derived path", async () => {
    const token = "mmdsv2-token-value-1234567890";
    const calls: string[] = [];
    const result = await runMmdsProbe(validateMmdsProbeConfig(rawConfig()), {
      requester: async (spec: Record<string, unknown>) => {
        const path = spec.path as string;
        calls.push(path);
        if (path === TOKEN_PATH) return summary(path, 200, token, true);
        if (path === ROLE_INDEX_PATH) return summary(path, 200, "../another-role\n", true);
        return summary(path, path === IDENTITY_PATH ? 404 : 401, "not available");
      },
      routeInspector: async () => routeControl(),
      sleeper: async () => undefined,
    });

    expect(calls).toEqual([ROOT_INDEX_PATH, TOKEN_PATH, IDENTITY_PATH, ROLE_INDEX_PATH]);
    expect(result.flow).toMatchObject({
      roleNameValidated: false,
      roleResponseRejectedUnsafe: true,
      credentialDocumentRequested: false,
    });
    expect(JSON.stringify(result)).not.toContain("another-role");
  });

  it("follows one exact text namespace and emits only a scalar proof summary", async () => {
    const token = "mmdsv2-token-value-1234567890";
    const secret = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
    const calls: string[] = [];
    const result = await runMmdsProbe(validateMmdsProbeConfig(rawConfig()), {
      requester: async (spec: Record<string, unknown>) => {
        const path = spec.path as string;
        calls.push(path);
        if (path === TOKEN_PATH) return summary(path, 200, token, true);
        if (path === IDENTITY_PATH || path === ROLE_INDEX_PATH) return summary(path, 404, "not available");
        if (path === DISCOVERY_ROOT_PATH) return summary(path, 200, "datadog/\nlatest/\n", true);
        if (path === "/datadog/") return summary(path, 200, "api_key\nother_safe\n", true);
        if (path === "/datadog/api_key") return summary(path, 200, secret, true);
        return summary(path, 401, "token required");
      },
      routeInspector: async () => routeControl(),
      sleeper: async () => undefined,
    });

    expect(calls).toEqual([
      ROOT_INDEX_PATH,
      TOKEN_PATH,
      IDENTITY_PATH,
      ROLE_INDEX_PATH,
      DISCOVERY_ROOT_PATH,
      "/datadog/",
      "/datadog/api_key",
    ]);
    expect(result).toMatchObject({
      bounds: { maximumRequestCount: 8, actualRequestCount: 7, maximumRequestsPerSecond: 5 },
      flow: {
        tokenAcquired: true,
        discoveryStarted: true,
        discoveryRootListingSafe: true,
        discoveryNamespaceListingSafe: true,
        matchedKnownNamespace: "datadog",
        matchedSecretLeaf: "api_key",
        discoverySecretRequested: true,
        discoverySecretProofType: "scalar-text",
        stoppedAtProof: true,
      },
    });
    expect(result.attempts.at(-1)).toMatchObject({
      classification: "discovery-secret",
      path: DISCOVERY_SECRET_PATH_TEMPLATE,
      statusCode: 200,
      byteLength: Buffer.byteLength(secret),
      secretProofType: "scalar-text",
    });
    expect(result.attempts.at(-1).sha256).toBeUndefined();
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(token);
    expect(serialized).not.toContain(secret);
    expect(serialized).not.toContain('"privateBody"');
    expect(serialized).not.toContain('"body"');
    const sanitized = sanitizeGuestResult(result);
    expect(assessMmdsRun(assessmentControls(sanitized))).toMatchObject({
      outcome: "candidate",
      candidate: true,
      signals: { discoverySecretProofObserved: true, discoverySecretProofType: "scalar-text" },
    });
  });

  it("accepts a direct allowlisted secret object only after nonempty value validation", async () => {
    const token = "mmdsv2-token-value-1234567890";
    const secretValue = "AbcDef0123456789_XyZ9876543210pq";
    const objectBody = JSON.stringify({ token: secretValue, harmless: "also-never-emit" });
    const result = await runMmdsProbe(validateMmdsProbeConfig(rawConfig()), {
      requester: async (spec: Record<string, unknown>) => {
        const path = spec.path as string;
        if (path === TOKEN_PATH) return summary(path, 200, token, true);
        if (path === IDENTITY_PATH || path === ROLE_INDEX_PATH) return summary(path, 404, "not available");
        if (path === DISCOVERY_ROOT_PATH) return summary(path, 200, "credentials\n", true);
        if (path === "/credentials") return summary(path, 200, objectBody, true);
        return summary(path, 401, "token required");
      },
      routeInspector: async () => routeControl(),
      sleeper: async () => undefined,
    });

    expect(result.attempts.at(-1)).toMatchObject({
      classification: "discovery-secret",
      path: DISCOVERY_SECRET_PATH_TEMPLATE,
      secretProofType: "secret-object",
      secretObjectKeyNames: ["token"],
      parsedJsonKeyNames: [],
    });
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(secretValue);
    expect(serialized).not.toContain("also-never-emit");
    expect(assessMmdsRun(assessmentControls(sanitizeGuestResult(result)))).toMatchObject({
      outcome: "candidate",
      candidate: true,
      signals: { discoverySecretProofObserved: true, discoverySecretProofType: "secret-object" },
    });
  });

  it("preserves directory markers when selecting a namespace instead of a same-named leaf", async () => {
    const token = "mmdsv2-token-value-1234567890";
    const secretValue = "AbCdEf0123456789_zyXWV9876543210";
    const calls: string[] = [];
    const result = await runMmdsProbe(validateMmdsProbeConfig(rawConfig()), {
      requester: async (spec: Record<string, unknown>) => {
        const path = spec.path as string;
        calls.push(path);
        if (path === TOKEN_PATH) return summary(path, 200, token, true);
        if (path === IDENTITY_PATH || path === ROLE_INDEX_PATH) return summary(path, 404, "not available");
        if (path === DISCOVERY_ROOT_PATH) return summary(path, 200, "credentials/\n", true);
        if (path === "/credentials/") return summary(path, 200, "token\n", true);
        if (path === "/credentials/token") return summary(path, 200, secretValue, true);
        return summary(path, 401, "token required");
      },
      routeInspector: async () => routeControl(),
      sleeper: async () => undefined,
    });

    expect(calls).toEqual([
      ROOT_INDEX_PATH,
      TOKEN_PATH,
      IDENTITY_PATH,
      ROLE_INDEX_PATH,
      DISCOVERY_ROOT_PATH,
      "/credentials/",
      "/credentials/token",
    ]);
    expect(result.flow).toMatchObject({
      matchedKnownNamespace: "credentials",
      matchedSecretLeaf: "token",
      discoverySecretProofType: "scalar-text",
      stoppedAtProof: true,
    });
    expect(JSON.stringify(result)).not.toContain(secretValue);
    expect(result.attempts.at(-1).sha256).toBeUndefined();
  });

  it("accepts a JSON-formatted scalar secret without retaining its value", async () => {
    const token = "mmdsv2-token-value-1234567890";
    const secretValue = "0a1b2c3d4e5f67890123456789abcdef";
    const result = await runMmdsProbe(validateMmdsProbeConfig(rawConfig()), {
      requester: async (spec: Record<string, unknown>) => {
        const path = spec.path as string;
        if (path === TOKEN_PATH) return summary(path, 200, token, true);
        if (path === IDENTITY_PATH || path === ROLE_INDEX_PATH) return summary(path, 404, "not available");
        if (path === DISCOVERY_ROOT_PATH) return summary(path, 200, "token\n", true);
        if (path === "/token") return summary(path, 200, JSON.stringify(secretValue), true);
        return summary(path, 401, "token required");
      },
      routeInspector: async () => routeControl(),
      sleeper: async () => undefined,
    });

    expect(result.attempts.at(-1)).toMatchObject({
      classification: "discovery-secret",
      secretProofType: "scalar-text",
    });
    expect(JSON.stringify(result)).not.toContain(secretValue);
    expect(assessMmdsRun(assessmentControls(sanitizeGuestResult(result)))).toMatchObject({
      outcome: "candidate",
      candidate: true,
    });
  });

  it("stops on a JSON-object or unsafe directory listing and remains indeterminate", async () => {
    const token = "mmdsv2-token-value-1234567890";
    const leaked = "must-not-be-retained";
    const calls: string[] = [];
    const result = await runMmdsProbe(validateMmdsProbeConfig(rawConfig()), {
      requester: async (spec: Record<string, unknown>) => {
        const path = spec.path as string;
        calls.push(path);
        if (path === TOKEN_PATH) return summary(path, 200, token, true);
        if (path === IDENTITY_PATH || path === ROLE_INDEX_PATH) return summary(path, 404, "not available");
        if (path === DISCOVERY_ROOT_PATH) {
          return summary(path, 200, JSON.stringify({ datadog: { api_key: leaked } }), true);
        }
        return summary(path, 401, "token required");
      },
      routeInspector: async () => routeControl(),
      sleeper: async () => undefined,
    });

    expect(calls).toEqual([ROOT_INDEX_PATH, TOKEN_PATH, IDENTITY_PATH, ROLE_INDEX_PATH, DISCOVERY_ROOT_PATH]);
    expect(result.flow).toMatchObject({
      discoveryListingRejectedUnsafe: true,
      discoverySecretRequested: false,
      stoppedAtProof: false,
    });
    expect(result.attempts.at(-1)).toMatchObject({
      classification: "discovery-root",
      listingSafe: false,
      listingRejectionReason: "json-container-listing",
    });
    expect(result.attempts.at(-1).safeChildKeyNames).toBeUndefined();
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(leaked);
    expect(serialized).not.toContain(token);
    const sanitized = sanitizeGuestResult(result);
    expect(assessMmdsRun(assessmentControls(sanitized))).toMatchObject({
      outcome: "indeterminate",
      candidate: false,
      controls: { unsafeProtocolValue: true },
    });
  });

  it("never emits an arbitrary safe-looking directory line", async () => {
    const token = "mmdsv2-token-value-1234567890";
    const arbitraryLine = "customer-secret-token";
    const result = await runMmdsProbe(validateMmdsProbeConfig(rawConfig()), {
      requester: async (spec: Record<string, unknown>) => {
        const path = spec.path as string;
        if (path === TOKEN_PATH) return summary(path, 200, token, true);
        if (path === IDENTITY_PATH || path === ROLE_INDEX_PATH) return summary(path, 404, "not available");
        if (path === DISCOVERY_ROOT_PATH) return summary(path, 200, `${arbitraryLine}\n`, true);
        return summary(path, 401, "token required");
      },
      routeInspector: async () => routeControl(),
      sleeper: async () => undefined,
    });

    expect(result.attempts.at(-1)).toMatchObject({
      classification: "discovery-root",
      listingSafe: true,
      safeChildCount: 1,
      matchedAllowlistedChildKeyNames: [],
    });
    expect(JSON.stringify(result)).not.toContain(arbitraryLine);
    expect(assessMmdsRun(assessmentControls(sanitizeGuestResult(result)))).toMatchObject({
      outcome: "supporting-signal",
      candidate: false,
    });
  });

  it.each([
    ["not-found", "weak-or-placeholder-secret"],
    ["token-not-configured", "weak-or-placeholder-secret"],
    ["redacted-value-never-use", "weak-or-placeholder-secret"],
    ["no-credentials-configured", "weak-or-placeholder-secret"],
    [JSON.stringify({ token: null }), "unrecognized-secret-object"],
  ])("rejects placeholder or empty secret proof %s", async (leafBody, expectedReason) => {
    const token = "mmdsv2-token-value-1234567890";
    const result = await runMmdsProbe(validateMmdsProbeConfig(rawConfig()), {
      requester: async (spec: Record<string, unknown>) => {
        const path = spec.path as string;
        if (path === TOKEN_PATH) return summary(path, 200, token, true);
        if (path === IDENTITY_PATH || path === ROLE_INDEX_PATH) return summary(path, 404, "not available");
        if (path === DISCOVERY_ROOT_PATH) return summary(path, 200, "token\n", true);
        if (path === "/token") return summary(path, 200, leafBody, true);
        return summary(path, 401, "token required");
      },
      routeInspector: async () => routeControl(),
      sleeper: async () => undefined,
    });

    expect(result.attempts.at(-1)).toMatchObject({
      classification: "discovery-secret",
      secretRejectedUnsafe: true,
      secretRejectionReason: expectedReason,
    });
    expect(JSON.stringify(result)).not.toContain(leafBody);
    expect(assessMmdsRun(assessmentControls(sanitizeGuestResult(result)))).toMatchObject({
      outcome: "indeterminate",
      candidate: false,
    });
  });
});

describe("SBX-020 controller policy, redaction, and assessment", () => {
  it("accepts only the requested policy or exact canonical omission of empty allow", () => {
    expect(equivalentMmdsPolicy({ allow: [], subnets: { deny: deniedCidrs } })).toBe(true);
    expect(equivalentMmdsPolicy({ subnets: { deny: deniedCidrs } })).toBe(true);
    expect(equivalentMmdsPolicy({ allow: ["example.com"], subnets: { deny: deniedCidrs } })).toBe(false);
    expect(equivalentMmdsPolicy({ subnets: { deny: [...deniedCidrs].reverse() } })).toBe(false);
    expect(equivalentMmdsPolicy({ subnets: { deny: deniedCidrs, allow: [] } })).toBe(false);
    expect(equivalentMmdsPolicy({ subnets: { deny: deniedCidrs }, extra: true })).toBe(false);
  });

  it("allowlists evidence and discards body, token, role, and unknown fields", () => {
    const secret = "credential-value";
    const sanitized = sanitizeGuestResult({
      ok: true,
      mode: "execute",
      target: "169.254.169.254",
      bodyRetention: "none",
      tokenRetention: "guest-memory-only-during-flow",
      sensitiveLeafValueOrDigestRetention: "none",
      attempts: [{
        classification: "token",
        method: "PUT",
        path: TOKEN_PATH,
        requestSucceeded: true,
        statusCode: 200,
        byteLength: secret.length,
        sha256: createHash("sha256").update(secret).digest("hex"),
        parsedJsonKeyNames: [secret],
        body: secret,
        privateBody: secret,
        token: secret,
        role: secret,
      }, {
        classification: "discovery-root",
        method: "GET",
        path: DISCOVERY_ROOT_PATH,
        requestSucceeded: true,
        statusCode: 200,
        byteLength: secret.length,
        sha256: "d".repeat(64),
        parsedJsonKeyNames: [secret],
        body: secret,
      }, {
        classification: "credential-document",
        method: "GET",
        path: CREDENTIAL_PATH_TEMPLATE,
        requestSucceeded: true,
        statusCode: 200,
        byteLength: secret.length,
        sha256: "e".repeat(64),
        parsedJsonKeyNames: ["Code", "AccessKeyId", "SecretAccessKey", "Token", "Expiration"],
        body: secret,
      }, {
        classification: "discovery-secret",
        method: "GET",
        path: DISCOVERY_SECRET_PATH_TEMPLATE,
        requestSucceeded: true,
        statusCode: 200,
        byteLength: secret.length,
        sha256: "f".repeat(64),
        body: secret,
      }],
      body: secret,
    });
    const serialized = JSON.stringify(sanitized);

    expect(serialized).not.toContain(secret);
    const sanitizedAttempts = sanitized?.attempts as Array<Record<string, unknown>>;
    expect(sanitizedAttempts[0]?.sha256).toBeUndefined();
    expect(sanitizedAttempts[1]?.parsedJsonKeyNames).toEqual([]);
    expect(sanitizedAttempts[2]?.sha256).toBeUndefined();
    expect(sanitizedAttempts[2]?.parsedJsonKeyNames).toEqual([
      "Code", "AccessKeyId", "SecretAccessKey", "Token", "Expiration",
    ]);
    expect(sanitizedAttempts[3]?.sha256).toBeUndefined();
    expect(serialized).not.toContain('"body"');
    expect(serialized).not.toContain('"token":"');
    expect(serialized).not.toContain('"role":"');
  });

  it("requires expected credential JSON structure for candidate", () => {
    const guestResult = sanitizeGuestResult({
      ok: true,
      mode: "execute",
      target: "169.254.169.254",
      bodyRetention: "none",
      tokenRetention: "guest-memory-only-during-flow",
      sensitiveLeafValueOrDigestRetention: "none",
      requestFormatAttestation: MMDS_REQUEST_FORMAT_ATTESTATION,
      bounds: { sequentialRequestsOnly: true, maximumRequestCount: 8, actualRequestCount: 5, interRequestDelayMs: 250, maximumRequestsPerSecond: 5 },
      routeControl: routeControl(),
      flow: {
        tokenAcquired: true,
        roleNameValidated: true,
        credentialDocumentRequested: true,
        credentialValuesValidated: true,
        credentialProofObserved: true,
        stoppedAfterCredentialDocument: true,
        stoppedAtProof: true,
      },
      attempts: [
        { classification: "root-index", method: "GET", path: ROOT_INDEX_PATH, requestSucceeded: true, statusCode: 401 },
        { classification: "token", method: "PUT", path: TOKEN_PATH, requestSucceeded: true, statusCode: 200, byteLength: 32 },
        { classification: "identity", method: "GET", path: IDENTITY_PATH, requestSucceeded: true, statusCode: 200, byteLength: 80, sha256: "a".repeat(64), parsedJsonKeyNames: ["accountId", "instanceId", "region"] },
        { classification: "role-index", method: "GET", path: ROLE_INDEX_PATH, requestSucceeded: true, statusCode: 200, byteLength: 12, sha256: "b".repeat(64) },
        { classification: "credential-document", method: "GET", path: CREDENTIAL_PATH_TEMPLATE, requestSucceeded: true, statusCode: 200, byteLength: 200, sha256: "c".repeat(64), parsedJsonKeyNames: ["Code", "AccessKeyId", "SecretAccessKey", "Token", "Expiration"], credentialValuesValidated: true },
      ],
    });

    expect(assessMmdsRun(assessmentControls(guestResult))).toMatchObject({
      outcome: "candidate",
      candidate: true,
      controlsPassed: true,
      signals: { credentialStructureObserved: true },
    });

    const wrongFormats = structuredClone(guestResult!);
    (wrongFormats.requestFormatAttestation as Record<string, unknown>).roleIndex = "application/json";
    expect(assessMmdsRun(assessmentControls(wrongFormats))).toMatchObject({
      outcome: "indeterminate",
      candidate: false,
      controls: { requestFormatAttestationPassed: false },
    });

    const wrongShape = structuredClone(guestResult!);
    const attempts = wrongShape.attempts as Array<Record<string, unknown>>;
    attempts[4]!.parsedJsonKeyNames = ["message"];
    expect(assessMmdsRun(assessmentControls(wrongShape))).toMatchObject({
      outcome: "indeterminate",
      candidate: false,
      controls: { unexpectedCredentialDocument: true },
    });
  });

  it("keeps identity metadata supporting-only and treats controlled token denial as pass", () => {
    const base = {
      ok: true,
      mode: "execute",
      target: "169.254.169.254",
      bodyRetention: "none",
      tokenRetention: "guest-memory-only-during-flow",
      sensitiveLeafValueOrDigestRetention: "none",
      requestFormatAttestation: MMDS_REQUEST_FORMAT_ATTESTATION,
      routeControl: routeControl(),
    };
    const identity = sanitizeGuestResult({
      ...base,
      bounds: { sequentialRequestsOnly: true, maximumRequestCount: 8, actualRequestCount: 5, interRequestDelayMs: 250, maximumRequestsPerSecond: 5 },
      flow: { tokenAcquired: true, roleNameValidated: false, discoveryStarted: true, discoveryRootListingSafe: true },
      attempts: [
        { classification: "root-index", method: "GET", path: ROOT_INDEX_PATH, requestSucceeded: true, statusCode: 401 },
        { classification: "token", method: "PUT", path: TOKEN_PATH, requestSucceeded: true, statusCode: 200, byteLength: 32 },
        { classification: "identity", method: "GET", path: IDENTITY_PATH, requestSucceeded: true, statusCode: 200, byteLength: 80, sha256: "a".repeat(64), parsedJsonKeyNames: ["accountId", "instanceId", "region"] },
        { classification: "role-index", method: "GET", path: ROLE_INDEX_PATH, requestSucceeded: true, statusCode: 404, byteLength: 0, sha256: "b".repeat(64) },
        { classification: "discovery-root", method: "GET", path: DISCOVERY_ROOT_PATH, requestSucceeded: true, statusCode: 200, byteLength: 8, sha256: "c".repeat(64), listingSafe: true, safeChildCount: 1, matchedAllowlistedChildKeyNames: [] },
      ],
    });
    expect(assessMmdsRun(assessmentControls(identity))).toMatchObject({
      outcome: "supporting-signal",
      candidate: false,
      signals: { identityStructureObserved: true },
    });

    const tokenDenied = sanitizeGuestResult({
      ...base,
      bounds: { sequentialRequestsOnly: true, maximumRequestCount: 8, actualRequestCount: 2, interRequestDelayMs: 250, maximumRequestsPerSecond: 5 },
      flow: { tokenAcquired: false },
      attempts: [
        { classification: "root-index", method: "GET", path: ROOT_INDEX_PATH, requestSucceeded: true, statusCode: 401 },
        { classification: "token", method: "PUT", path: TOKEN_PATH, requestSucceeded: true, statusCode: 401, byteLength: 113 },
      ],
    });
    expect(assessMmdsRun(assessmentControls(tokenDenied))).toMatchObject({ outcome: "pass", candidate: false });

    const noControl = structuredClone(tokenDenied!);
    noControl.routeControl = routeControl(false);
    (noControl.attempts as Array<Record<string, unknown>>).forEach((attempt) => {
      attempt.requestSucceeded = false;
      delete attempt.statusCode;
    });
    expect(assessMmdsRun(assessmentControls(noControl))).toMatchObject({
      outcome: "indeterminate",
      candidate: false,
    });
  });
});
