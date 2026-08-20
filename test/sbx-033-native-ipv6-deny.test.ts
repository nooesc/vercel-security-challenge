import { spawnSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  buildProbeConfiguration,
  controlledEndpointConfig,
  explicitCredentials,
  expectedOperationId,
  publicIPv4,
  publicNativeIPv6,
  sanitizeGuestResult,
} from "../pocs/SBX-033/native-ipv6-deny.js";
import {
  assessSbx033,
  authenticatedNativeIpOperationSuccess,
  conclusiveNativeIpFirewallBlock,
  exactDenyAllPolicy,
  type AddressFamily,
  type CanarySource,
  type NativeIpProbeExpectation,
  type NativeIpProbeRecord,
  type Sbx033AssessmentInput,
} from "../pocs/SBX-033/verdict.js";

const guestPath = fileURLToPath(new URL("../guest/native-ipv6-deny-probe.py", import.meta.url));
const controllerPath = fileURLToPath(new URL("../pocs/SBX-033/native-ipv6-deny.ts", import.meta.url));
const endpointUrl = "https://dualstack-owned.example.invalid/v1/h3-action";
const endpointHostname = "dualstack-owned.example.invalid";
const ipv4 = "8.8.8.8";
const ipv6 = "2606:4700:4700::1111";
const runId = "6f592df0-c2c2-4fd1-a63d-94db113bdf49";
const testId = "SBX-033-POC";
const publicCanary = "public_0123456789abcdefghijklmnop";
const operatorSecret = "operator_0123456789abcdefghijklmnop";
const hmacKey = "unit-test-controller-hmac-key-32-bytes-minimum";
const scope = "I_CONTROL_THE_ENDPOINT_AND_AUTHORIZE_BOUNDED_NATIVE_IPV6_DENY_TESTING";

type CaseId =
  | "allow-v4-control"
  | "allow-v6-control"
  | "deny-v4-control"
  | "deny-v6-public"
  | "deny-v6-secret-target";

function guestConfiguration(
  caseId: CaseId = "allow-v6-control",
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const secret = caseId === "deny-v6-secret-target";
  const family = caseId === "allow-v4-control" || caseId === "deny-v4-control" ? "ipv4" : "ipv6";
  return {
    scopeConfirmation: scope,
    endpointUrl,
    pinnedAddress: family === "ipv4" ? ipv4 : ipv6,
    addressFamily: family,
    runId,
    testId,
    caseId,
    canarySource: secret ? "operator-secret-file" : "controller-public-canary",
    ...(secret
      ? { operatorSecretPath: "/tmp/sbx-033/operator-secret" }
      : { publicCanary }),
    connectTimeoutSeconds: 8,
    ioTimeoutSeconds: 8,
    maxResponseBytes: 1_024,
    ...overrides,
  };
}

function runGuest(value: Record<string, unknown>, extraArgs: string[] = ["--plan"]) {
  const encoded = Buffer.from(JSON.stringify(value)).toString("base64url");
  return spawnSync("python3", [guestPath, encoded, ...extraArgs], {
    encoding: "utf8",
    timeout: 10_000,
  });
}

function expectation(
  caseId: CaseId,
  family: AddressFamily,
  source: CanarySource,
  pinnedAddress = family === "ipv4" ? ipv4 : ipv6,
): NativeIpProbeExpectation {
  return { runId, testId, caseId, addressFamily: family, canarySource: source, endpointHostname, pinnedAddress };
}

function successProbe(
  caseId: CaseId,
  family: AddressFamily,
  source: CanarySource,
  canary = source === "operator-secret-file" ? operatorSecret : publicCanary,
): NativeIpProbeRecord {
  const pinnedAddress = family === "ipv4" ? ipv4 : ipv6;
  const operationId = expectedOperationId(hmacKey, runId, caseId, canary);
  return {
    caseId,
    addressFamily: family,
    canarySource: source,
    expectedOperationId: operationId,
    commandExitCode: 0,
    result: {
      ok: true,
      phase: "response",
      runId,
      testId,
      caseId,
      addressFamily: family,
      canarySource: source,
      endpointHostname,
      pinnedAddress,
      pinnedPort: 443,
      attemptNumber: 1,
      maximumRequests: 1,
      retryCount: 0,
      redirectsAllowed: false,
      freshConnectionRequired: true,
      environmentProxyTrust: false,
      strictCertificateVerification: true,
      hostnameVerificationRequired: true,
      certificateVerified: true,
      hostnameVerified: true,
      selectedAlpn: "http/1.1",
      tlsVersion: "TLSv1.3",
      cipherSuite: "TLS_AES_256_GCM_SHA384",
      peerCertificateSha256: "d".repeat(64),
      peerAddress: pinnedAddress,
      peerAddressFamily: family,
      peerPort: 443,
      nativeIpv6: family === "ipv6",
      secretFileValidated: source === "operator-secret-file",
      ...(source === "operator-secret-file" ? { secretFileMode: "0600", secretByteLength: 41 } : {}),
      response: {
        statusCode: 200,
        contentType: "application/json; charset=utf-8",
        cacheControl: "no-store, max-age=0",
        bodyByteLength: 78,
        bodyContainsCanary: false,
        rawBodyRetained: false,
      },
      authorized: true,
      operationIdShapeValid: true,
      operationId,
    },
  };
}

function blockedProbe(caseId: CaseId, family: AddressFamily): NativeIpProbeRecord {
  const pinnedAddress = family === "ipv4" ? ipv4 : ipv6;
  return {
    caseId,
    addressFamily: family,
    canarySource: "controller-public-canary",
    expectedOperationId: `h3_${"a".repeat(43)}`,
    commandExitCode: 10,
    result: {
      ok: false,
      phase: "connect",
      runId,
      testId,
      caseId,
      addressFamily: family,
      canarySource: "controller-public-canary",
      endpointHostname,
      pinnedAddress,
      pinnedPort: 443,
      attemptNumber: 1,
      maximumRequests: 1,
      retryCount: 0,
      redirectsAllowed: false,
      freshConnectionRequired: true,
      environmentProxyTrust: false,
      strictCertificateVerification: true,
      hostnameVerificationRequired: true,
      secretFileValidated: false,
      errorType: "ConnectionResetError",
      errorErrno: 104,
      errorSyscall: "connect",
      timeout: false,
      responseStatusCode: 0,
    },
  };
}

function candidateInput(overrides: Partial<Sbx033AssessmentInput> = {}): Sbx033AssessmentInput {
  return {
    identityAndScopePassed: true,
    dnsSnapshotPassed: true,
    allowSandboxCreated: true,
    allowIpv4Succeeded: true,
    allowNativeIpv6Succeeded: true,
    denySandboxCreated: true,
    denyPolicyReadbackPassed: true,
    denyIpv4Blocked: true,
    denyIpv4UnexpectedlySucceeded: false,
    denyIpv6PublicBlocked: false,
    denyIpv6PublicSucceeded: true,
    secretTargetAttempted: true,
    secretFilePrepared: true,
    denyIpv6SecretSucceeded: true,
    denyIpv6SecretBlocked: false,
    postTargetReadbackPassed: true,
    cleanupPassed: true,
    ...overrides,
  };
}

describe("SBX-033 fixed-address guest plan", () => {
  it("fixes one fresh native IPv6 TLS request with strict verification and no retry, proxy, or redirect", () => {
    const child = runGuest(guestConfiguration());
    expect(child.status).toBe(0);
    expect(JSON.parse(child.stdout)).toMatchObject({
      ok: true,
      phase: "plan",
      runId,
      testId,
      caseId: "allow-v6-control",
      addressFamily: "ipv6",
      canarySource: "controller-public-canary",
      endpointHostname,
      pinnedAddress: ipv6,
      pinnedPort: 443,
      attemptNumber: 1,
      maximumRequests: 1,
      retryCount: 0,
      redirectsAllowed: false,
      freshConnectionRequired: true,
      environmentProxyTrust: false,
      strictCertificateVerification: true,
      hostnameVerificationRequired: true,
      secretFileValidated: false,
      rawHttpResponseRetained: false,
      rawRequestCanaryRetained: false,
    });
  });

  it("accepts only the exact fixed matrix, owned URL, canonical public pins, and secret file path", () => {
    for (const value of [
      guestConfiguration("allow-v6-control", { scopeConfirmation: "yes" }),
      guestConfiguration("allow-v6-control", { verify: false }),
      guestConfiguration("allow-v6-control", { endpointUrl: "https://dualstack-owned.example.invalid/other" }),
      guestConfiguration("allow-v6-control", { endpointUrl: `${endpointUrl}?x=1` }),
      guestConfiguration("allow-v6-control", { endpointUrl: "https://user@dualstack-owned.example.invalid/v1/h3-action" }),
      guestConfiguration("allow-v6-control", { endpointUrl: "https://[2606:4700:4700::1111]/v1/h3-action" }),
      guestConfiguration("allow-v6-control", { pinnedAddress: "::ffff:8.8.8.8" }),
      guestConfiguration("allow-v6-control", { pinnedAddress: "fd00::1" }),
      guestConfiguration("allow-v4-control", { pinnedAddress: "127.0.0.1" }),
      guestConfiguration("allow-v6-control", { addressFamily: "ipv4" }),
      guestConfiguration("allow-v6-control", { canarySource: "operator-secret-file" }),
      guestConfiguration("allow-v6-control", { caseId: "unknown" }),
      guestConfiguration("allow-v6-control", { connectTimeoutSeconds: 100 }),
      guestConfiguration("allow-v6-control", { publicCanary: "short" }),
      guestConfiguration("deny-v6-secret-target", { operatorSecretPath: "/tmp/other" }),
      guestConfiguration("deny-v6-secret-target", { rawSecret: operatorSecret }),
    ]) {
      const child = runGuest(value);
      expect(child.status).toBe(20);
      expect(JSON.parse(child.stdout)).toMatchObject({ ok: false, phase: "configuration" });
      expect(child.stdout).not.toContain(operatorSecret);
    }
    expect(runGuest(guestConfiguration("deny-v6-secret-target")).status).toBe(0);
  });

  it("rejects malformed envelopes and unknown modes without echoing their contents", () => {
    const malformed = spawnSync("python3", [guestPath, "!!!", "--plan"], { encoding: "utf8" });
    expect(malformed.status).toBe(20);
    expect(JSON.parse(malformed.stdout)).toMatchObject({ phase: "configuration" });
    const unknown = runGuest(guestConfiguration(), ["--network"]);
    expect(unknown.status).toBe(20);
  });
});

describe("SBX-033 controller gates", () => {
  it("requires the exact HackerOne-alias team/project and explicit ownership plus env-only pins", () => {
    expect(explicitCredentials({
      VERCEL_TOKEN: "alias-token",
      VERCEL_TEAM_ID: "team_n98ERpVwV7HqmWRudAyK8sXQ",
      VERCEL_PROJECT_ID: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    })).toEqual({
      token: "alias-token",
      teamId: "team_n98ERpVwV7HqmWRudAyK8sXQ",
      projectId: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    });
    expect(() => explicitCredentials({
      VERCEL_TOKEN: "alias-token",
      VERCEL_TEAM_ID: "team_wrong",
      VERCEL_PROJECT_ID: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    })).toThrow(/verified HackerOne-alias/u);
    expect(controlledEndpointConfig({
      SBX033_SCOPE_CONFIRMATION: scope,
      SBX033_ENDPOINT_URL: endpointUrl,
      SBX033_PINNED_IPV4: ipv4,
      SBX033_PINNED_IPV6: ipv6,
    })).toMatchObject({ url: new URL(endpointUrl), pinnedIPv4: ipv4, pinnedIPv6: ipv6 });
    for (const environment of [
      { SBX033_ENDPOINT_URL: endpointUrl, SBX033_PINNED_IPV4: ipv4, SBX033_PINNED_IPV6: ipv6 },
      { SBX033_SCOPE_CONFIRMATION: scope, SBX033_ENDPOINT_URL: endpointUrl },
      { SBX033_SCOPE_CONFIRMATION: scope, SBX033_ENDPOINT_URL: "https://dualstack-owned.example.invalid:443/v1/h3-action", SBX033_PINNED_IPV4: ipv4, SBX033_PINNED_IPV6: ipv6 },
      { SBX033_SCOPE_CONFIRMATION: scope, SBX033_ENDPOINT_URL: endpointUrl, SBX033_PINNED_IPV4: "127.0.0.1", SBX033_PINNED_IPV6: ipv6 },
      { SBX033_SCOPE_CONFIRMATION: scope, SBX033_ENDPOINT_URL: endpointUrl, SBX033_PINNED_IPV4: ipv4, SBX033_PINNED_IPV6: "::ffff:8.8.8.8" },
    ]) expect(() => controlledEndpointConfig(environment)).toThrow();
  });

  it("uses conservative canonical public native-address validation", () => {
    expect(publicIPv4(ipv4)).toBe(true);
    expect(publicIPv4("127.0.0.1")).toBe(false);
    expect(publicIPv4("8.08.8.8")).toBe(false);
    expect(publicNativeIPv6(ipv6)).toBe(true);
    for (const address of ["2606:4700:4700:0:0:0:0:1111", "::1", "fd00::1", "fe80::1", "ff02::1", "2001::1", "2001:db8::1", "::ffff:8.8.8.8"])
      expect(publicNativeIPv6(address)).toBe(false);
  });

  it("matches the non-reflecting HMAC receipt contract", () => {
    const expected = `h3_${createHmac("sha256", hmacKey)
      .update(`${runId}\ndeny-v6-public\n${publicCanary}`)
      .digest("base64url")}`;
    expect(expectedOperationId(hmacKey, runId, "deny-v6-public", publicCanary)).toBe(expected);
    expect(expected).toMatch(/^h3_[A-Za-z0-9_-]{43}$/u);
  });

  it("never places the operator secret or HMAC key in the target guest configuration", () => {
    const target = buildProbeConfiguration({ endpointUrl, pinnedAddress: ipv6, runId, caseId: "deny-v6-secret-target" });
    expect(target).toMatchObject({
      canarySource: "operator-secret-file",
      operatorSecretPath: "/tmp/sbx-033/operator-secret",
      addressFamily: "ipv6",
    });
    expect(JSON.stringify(target)).not.toContain(operatorSecret);
    expect(JSON.stringify(target)).not.toContain(hmacKey);
    expect(() => buildProbeConfiguration({
      endpointUrl,
      pinnedAddress: ipv6,
      runId,
      caseId: "deny-v6-secret-target",
      publicCanary: operatorSecret,
    })).toThrow();
  });

  it("sanitizes untrusted guest output and retains only shaped operation/certificate values", () => {
    const sanitized = sanitizeGuestResult({
      ok: true,
      operationId: "raw-secret-not-an-operation",
      peerCertificateSha256: "no",
      rawBody: operatorSecret,
      response: { statusCode: 200, rawBodyRetained: false },
    });
    expect(sanitized?.operationId).toBeUndefined();
    expect(sanitized?.peerCertificateSha256).toBeUndefined();
    expect(sanitized).not.toHaveProperty("rawBody");
    expect(JSON.stringify(sanitized)).not.toContain(operatorSecret);
  });
});

describe("SBX-033 authenticated proof predicates", () => {
  it("requires exact native peer, verified TLS, non-reflection, secret metadata, and HMAC proof", () => {
    const probe = successProbe("deny-v6-secret-target", "ipv6", "operator-secret-file");
    const expected = expectation("deny-v6-secret-target", "ipv6", "operator-secret-file");
    expect(authenticatedNativeIpOperationSuccess(probe, expected)).toBe(true);
    for (const mutate of [
      (value: NativeIpProbeRecord) => { value.result!.operationId = `h3_${"x".repeat(43)}`; },
      (value: NativeIpProbeRecord) => { value.result!.certificateVerified = false; },
      (value: NativeIpProbeRecord) => { value.result!.hostnameVerified = false; },
      (value: NativeIpProbeRecord) => { value.result!.peerAddress = "2606:4700:4700::1001"; },
      (value: NativeIpProbeRecord) => { value.result!.peerAddress = "::ffff:8.8.8.8"; },
      (value: NativeIpProbeRecord) => { value.result!.nativeIpv6 = false; },
      (value: NativeIpProbeRecord) => { value.result!.selectedAlpn = "h2"; },
      (value: NativeIpProbeRecord) => { value.result!.secretFileMode = "0644"; },
      (value: NativeIpProbeRecord) => { value.result!.secretByteLength = 8; },
      (value: NativeIpProbeRecord) => { value.result!.response!.bodyContainsCanary = true; },
      (value: NativeIpProbeRecord) => { value.result!.response!.rawBodyRetained = true; },
      (value: NativeIpProbeRecord) => { value.result!.response!.cacheControl = "public"; },
    ]) {
      const changed = structuredClone(probe);
      mutate(changed);
      expect(authenticatedNativeIpOperationSuccess(changed, expected)).toBe(false);
    }
  });

  it("requires public controls to prove that no file secret was consumed", () => {
    const probe = successProbe("allow-v4-control", "ipv4", "controller-public-canary");
    const expected = expectation("allow-v4-control", "ipv4", "controller-public-canary");
    expect(authenticatedNativeIpOperationSuccess(probe, expected)).toBe(true);
    probe.result!.secretFileValidated = true;
    probe.result!.secretFileMode = "0600";
    probe.result!.secretByteLength = 41;
    expect(authenticatedNativeIpOperationSuccess(probe, expected)).toBe(false);
  });

  it("accepts only one active pre-response firewall failure, never timeout, response, or ambiguity", () => {
    const probe = blockedProbe("deny-v6-public", "ipv6");
    const expected = expectation("deny-v6-public", "ipv6", "controller-public-canary");
    expect(conclusiveNativeIpFirewallBlock(probe, expected)).toBe(true);
    for (const mutate of [
      (value: NativeIpProbeRecord) => { value.result!.timeout = true; value.result!.errorType = "TimeoutError"; },
      (value: NativeIpProbeRecord) => { value.commandExitCode = 20; },
      (value: NativeIpProbeRecord) => { value.result!.errorErrno = 22; },
      (value: NativeIpProbeRecord) => { value.result!.operationId = `h3_${"a".repeat(43)}`; },
      (value: NativeIpProbeRecord) => { value.result!.responseStatusCode = 200; },
      (value: NativeIpProbeRecord) => { value.result!.response = { statusCode: 200 }; },
      (value: NativeIpProbeRecord) => { value.result!.pinnedAddress = ipv4; },
      (value: NativeIpProbeRecord) => { value.result!.attemptNumber = 2; },
      (value: NativeIpProbeRecord) => { value.result!.phase = "write"; },
      (value: NativeIpProbeRecord) => { value.result!.secretFileValidated = true; },
    ]) {
      const changed = structuredClone(probe);
      mutate(changed);
      expect(conclusiveNativeIpFirewallBlock(changed, expected)).toBe(false);
    }
  });
});

describe("SBX-033 pure verdict", () => {
  it("emits candidate only for IPv4 block plus public and file-secret native IPv6 HMAC success", () => {
    expect(assessSbx033(candidateInput())).toMatchObject({
      verdict: "candidate",
      candidate: true,
      controlsPassed: true,
      nativeIpv6Available: true,
    });
    for (const overrides of [
      { denyIpv4Blocked: false },
      { denyIpv4UnexpectedlySucceeded: true },
      { denyPolicyReadbackPassed: false },
      { postTargetReadbackPassed: false },
      { secretTargetAttempted: false },
      { secretFilePrepared: false },
      { denyIpv6SecretSucceeded: false },
      { denyIpv6SecretBlocked: true },
    ]) expect(assessSbx033(candidateInput(overrides))).not.toMatchObject({ verdict: "candidate" });
  });

  it("passes only on conclusive IPv4 and native IPv6 blocks with no secret attempt", () => {
    const pass = candidateInput({
      denyIpv6PublicBlocked: true,
      denyIpv6PublicSucceeded: false,
      secretTargetAttempted: false,
      secretFilePrepared: false,
      denyIpv6SecretSucceeded: false,
      denyIpv6SecretBlocked: false,
    });
    expect(assessSbx033(pass)).toMatchObject({ verdict: "pass", candidate: false, controlsPassed: true });
    expect(assessSbx033({ ...pass, secretTargetAttempted: true })).toMatchObject({ verdict: "indeterminate" });
    expect(assessSbx033({ ...pass, denyIpv6PublicBlocked: false })).toMatchObject({ verdict: "indeterminate" });
  });

  it("treats native IPv6 unavailability as indeterminate and cleanup/execution failure as error", () => {
    expect(assessSbx033(candidateInput({ allowNativeIpv6Succeeded: false }))).toMatchObject({
      verdict: "indeterminate",
      nativeIpv6Available: false,
    });
    expect(assessSbx033(candidateInput({ cleanupPassed: false }))).toMatchObject({ verdict: "error" });
    expect(assessSbx033(candidateInput({ executionError: true }))).toMatchObject({ verdict: "error" });
  });

  it("accepts only the literal deny-all policy", () => {
    expect(exactDenyAllPolicy("deny-all")).toBe(true);
    expect(exactDenyAllPolicy({ deny: ["0.0.0.0/0"] })).toBe(false);
    expect(exactDenyAllPolicy("DENY-ALL")).toBe(false);
  });
});

describe("SBX-033 source-level safety invariants", () => {
  it("keeps the hostname and both hardpins env-only and verifies the exact /v2/user identity", () => {
    const source = readFileSync(controllerPath, "utf8");
    expect(source).toContain('required(environment, "SBX033_ENDPOINT_URL")');
    expect(source).toContain('required(environment, "SBX033_PINNED_IPV4")');
    expect(source).toContain('required(environment, "SBX033_PINNED_IPV6")');
    expect(source).toContain('fetch("https://api.vercel.com/v2/user"');
    expect(source).toContain("resolvedA.some(({ address }) => address === input.pinnedIPv4)");
    expect(source).toContain("resolvedAAAA.some(({ address }) => address === input.pinnedIPv6)");
    expect(source).not.toContain(endpointHostname);
  });

  it("gates secret generation after public IPv6 success and writes exclusive mode-0600 evidence", () => {
    const source = readFileSync(controllerPath, "utf8");
    const gateIndex = source.indexOf("if (denyIpv6PublicSucceeded && !denyIpv6PublicBlocked)");
    const secretIndex = source.indexOf('operatorSecret = randomBytes(32).toString("base64url")');
    const targetIndex = source.indexOf('runProbe(denyFixture, "deny-v6-secret-target")');
    expect(gateIndex).toBeGreaterThan(0);
    expect(secretIndex).toBeGreaterThan(gateIndex);
    expect(targetIndex).toBeGreaterThan(secretIndex);
    expect(source).not.toContain("operatorSecretSha256");
    expect(source).toContain('{ encoding: "utf8", mode: 0o600, flag: "wx" }');
    expect(source).toContain("sbx-033-${role}-${runId}");
    expect(source).toContain("deletionAbsenceChecksAttempted === 3");
  });
});
