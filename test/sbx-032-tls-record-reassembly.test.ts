import { spawnSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  buildProbeConfiguration,
  explicitCredentials,
  expectedOperationId,
} from "../pocs/SBX-032/tls-record-reassembly.js";
import {
  assessSbx032,
  authenticatedTlsOperationSuccess,
  conclusiveTlsFirewallBlock,
  exactSingleHostAllowPolicy,
  type Sbx032AssessmentInput,
  type TlsProbeRecord,
  type TlsTransmissionMode,
} from "../pocs/SBX-032/verdict.js";

const guestPath = fileURLToPath(new URL("../guest/tls-record-reassembly-probe.py", import.meta.url));
const allowedEndpoint = "https://allowed-owned.example.invalid/v1/h3-action";
const deniedEndpoint = "https://denied-owned.example.invalid/v1/h3-action";
const allowedIp = "1.1.1.1";
const deniedIp = "8.8.8.8";
const runId = "run-sbx032-unit";
const publicCanary = "public_0123456789abcdef";
const operatorSecret = "operator_0123456789abcdef";
const hmacKey = "unit-test-controller-key-at-least-32-bytes";
const testId = "SBX-032-POC";

function configuration(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    scopeConfirmation: "I_CONTROL_BOTH_ENDPOINTS_AND_AUTHORIZE_BOUNDED_TLS_REASSEMBLY_TESTING",
    allowedEndpointUrl: allowedEndpoint,
    allowedPinnedIPv4: allowedIp,
    deniedEndpointUrl: deniedEndpoint,
    deniedPinnedIPv4: deniedIp,
    runId,
    testId,
    caseId: "allow-record-fragmented-b-control",
    transmissionMode: "record-fragmented",
    publicCanary,
    timeoutSeconds: 8,
    maxResponseBytes: 1_024,
    ...overrides,
  };
}

function runGuest(
  value: Record<string, unknown>,
  mode: "--plan" | "--inspect-first-flight",
) {
  const encoded = Buffer.from(JSON.stringify(value)).toString("base64url");
  return spawnSync("python3", [guestPath, encoded, mode], {
    encoding: "utf8",
    timeout: 10_000,
  });
}

function successProbe(
  caseId: string,
  endpointRole: "allowed" | "denied",
  transmissionMode: TlsTransmissionMode,
  hostname: string,
  pinnedIPv4: string,
  canary = publicCanary,
): TlsProbeRecord {
  const originalHash = "a".repeat(64);
  const transmittedHash = transmissionMode === "record-fragmented" ? "b".repeat(64) : originalHash;
  const originalRecordCount = 1;
  return {
    caseId,
    endpointRole,
    transmissionMode,
    canarySource: caseId === "restricted-record-fragmented-b-target"
      ? "operator-secret-file"
      : "controller-public-canary",
    expectedOperationId: expectedOperationId(hmacKey, runId, caseId, canary),
    commandExitCode: 0,
    result: {
      ok: true,
      phase: "response",
      runId,
      testId,
      caseId,
      endpointRole,
      transmissionMode,
      canarySource: caseId === "restricted-record-fragmented-b-target"
        ? "operator-secret-file"
        : "controller-public-canary",
      endpointHostname: hostname,
      pinnedIPv4,
      pinnedPort: 443,
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
      peerIPv4: pinnedIPv4,
      peerPort: 443,
      clientHello: {
        source: "python-sslobject-memorybio",
        outerSni: hostname,
        originalRecordCount,
        transmittedRecordCount: originalRecordCount + (transmissionMode === "record-fragmented" ? 1 : 0),
        originalFirstFlightSha256: originalHash,
        transmittedFirstFlightSha256: transmittedHash,
        clientHelloPayloadSha256: "c".repeat(64),
        reassembledClientHelloPayloadSha256: "c".repeat(64),
        reassemblyMatchesOriginal: true,
        splitLocation: "server_name.hostname",
        sniHostnameByteLength: hostname.length,
        sniHostnameStartOffsetInRecordPayload: 286,
        sniHostnameEndOffsetInRecordPayload: 286 + hostname.length,
        splitOffsetInRecordPayload: 300,
        originalRecordPayloadLength: 500,
        fragmentPayloadLengths: [300, 200],
        initialSocketWriteCount: transmissionMode === "tcp-segmented" ? 2 : 1,
        rawClientHelloRetained: false,
      },
      response: {
        statusCode: 200,
        contentType: "application/json; charset=utf-8",
        cacheControl: "no-store, max-age=0",
        bodyByteLength: 80,
        bodyContainsCanary: false,
        rawBodyRetained: false,
      },
      authorized: true,
      operationIdShapeValid: true,
      operationId: expectedOperationId(hmacKey, runId, caseId, canary),
    },
  };
}

function candidateInput(overrides: Partial<Sbx032AssessmentInput> = {}): Sbx032AssessmentInput {
  return {
    setupPassed: true,
    allowNormalDeniedControlPassed: true,
    allowTcpSegmentedDeniedControlPassed: true,
    allowRecordFragmentedDeniedControlPassed: true,
    restrictedUpdateAcknowledged: true,
    restrictedReadbackPassed: true,
    postTargetReadbackPassed: true,
    allowedNormalControlPassed: true,
    allowedRecordFragmentedControlPassed: true,
    allowedRecordFragmentedControlBlocked: false,
    restrictedNormalDeniedPreBlocked: true,
    restrictedNormalDeniedPostBlocked: true,
    restrictedRecordFragmentedPublicDeniedBlocked: false,
    restrictedRecordFragmentedDeniedSucceeded: true,
    restrictedRecordFragmentedDeniedBlocked: false,
    cleanupPassed: true,
    ...overrides,
  };
}

describe("SBX-032 guest ClientHello construction", () => {
  it("generates one strict SSLObject ClientHello and splits a TLS record inside SNI", () => {
    const normal = runGuest(configuration({
      caseId: "allow-normal-b-control",
      transmissionMode: "normal",
    }), "--inspect-first-flight");
    expect(normal.status).toBe(0);
    const normalResult = JSON.parse(normal.stdout);
    expect(normalResult).toMatchObject({
      ok: true,
      phase: "client-hello",
      endpointRole: "denied",
      transmissionMode: "normal",
      strictCertificateVerification: true,
      hostnameVerificationRequired: true,
      requiredAlpn: "http/1.1",
      clientHello: {
        source: "python-sslobject-memorybio",
        outerSni: "denied-owned.example.invalid",
        originalRecordCount: 1,
        transmittedRecordCount: 1,
        reassemblyMatchesOriginal: true,
        splitLocation: "server_name.hostname",
        initialSocketWriteCount: 1,
        rawClientHelloRetained: false,
      },
    });
    expect(normalResult.clientHello.originalFirstFlightSha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(normalResult.clientHello.originalFirstFlightSha256)
      .toBe(normalResult.clientHello.transmittedFirstFlightSha256);

    const tcp = runGuest(configuration({
      caseId: "allow-tcp-segmented-b-control",
      transmissionMode: "tcp-segmented",
    }), "--inspect-first-flight");
    expect(tcp.status).toBe(0);
    expect(JSON.parse(tcp.stdout)).toMatchObject({
      clientHello: {
        originalRecordCount: 1,
        transmittedRecordCount: 1,
        initialSocketWriteCount: 2,
      },
    });

    const fragmented = runGuest(configuration(), "--inspect-first-flight");
    expect(fragmented.status).toBe(0);
    const fragmentedResult = JSON.parse(fragmented.stdout);
    expect(fragmentedResult).toMatchObject({
      transmissionMode: "record-fragmented",
      recordSplitRequired: true,
      clientHello: {
        originalRecordCount: 1,
        transmittedRecordCount: 2,
        reassemblyMatchesOriginal: true,
        splitLocation: "server_name.hostname",
        initialSocketWriteCount: 1,
      },
    });
    expect(fragmentedResult.clientHello.transmittedFirstFlightSha256)
      .not.toBe(fragmentedResult.clientHello.originalFirstFlightSha256);
    expect(fragmentedResult.clientHello.fragmentPayloadLengths.reduce((sum: number, value: number) => sum + value))
      .toBe(fragmentedResult.clientHello.originalRecordPayloadLength);
    expect(fragmentedResult.clientHello.fragmentPayloadLengths[0])
      .toBe(fragmentedResult.clientHello.splitOffsetInRecordPayload);
    expect(fragmentedResult.clientHello.sniHostnameStartOffsetInRecordPayload)
      .toBeLessThan(fragmentedResult.clientHello.splitOffsetInRecordPayload);
    expect(fragmentedResult.clientHello.splitOffsetInRecordPayload)
      .toBeLessThan(fragmentedResult.clientHello.sniHostnameEndOffsetInRecordPayload);
    expect(fragmentedResult.clientHello.sniHostnameByteLength)
      .toBe(Buffer.byteLength(fragmentedResult.clientHello.outerSni));
  });

  it("fixes one verified, pinned, fresh, no-proxy request with no retry or redirect", () => {
    const child = runGuest(configuration(), "--plan");
    expect(child.status).toBe(0);
    expect(JSON.parse(child.stdout)).toMatchObject({
      ok: true,
      phase: "plan",
      endpointHostname: "denied-owned.example.invalid",
      pinnedIPv4: deniedIp,
      pinnedPort: 443,
      maximumRequests: 1,
      retryCount: 0,
      redirectsAllowed: false,
      freshConnectionRequired: true,
      environmentProxyTrust: false,
      strictCertificateVerification: true,
      hostnameVerificationRequired: true,
      requiredAlpn: "http/1.1",
      initialClientHelloSource: "python-sslobject-memorybio",
      recordSplitRequired: true,
      splitLocationRequired: "server_name.hostname",
    });
  });

  it("rejects caller weakening, endpoint ambiguity, and a target secret in configuration", () => {
    for (const overrides of [
      { verify: false },
      { proxy: "http://127.0.0.1:8080" },
      { deniedEndpointUrl: allowedEndpoint },
      { deniedEndpointUrl: "https://denied-owned.example.invalid/other" },
      { deniedPinnedIPv4: "127.0.0.1" },
      { transmissionMode: "normal" },
    ]) {
      const child = runGuest(configuration(overrides), "--plan");
      expect(child.status).toBe(2);
      expect(JSON.parse(child.stdout)).toMatchObject({ ok: false, phase: "configuration" });
    }

    const targetWithSecret = runGuest(configuration({
      caseId: "restricted-record-fragmented-b-target",
      transmissionMode: "record-fragmented",
      publicCanary: operatorSecret,
    }), "--plan");
    expect(targetWithSecret.status).toBe(2);
    const target = configuration({
      caseId: "restricted-record-fragmented-b-target",
      transmissionMode: "record-fragmented",
    });
    delete target.publicCanary;
    expect(runGuest(target, "--plan").status).toBe(0);
  });
});

describe("SBX-032 controller proof", () => {
  it("requires the exact eligible HackerOne alias scope credentials", () => {
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
    expect(() => explicitCredentials({})).toThrow(/are required/u);
  });

  it("accepts only an exact one-host allow policy", () => {
    const hostname = "allowed-owned.example.invalid";
    expect(exactSingleHostAllowPolicy({ allow: [hostname] }, hostname)).toBe(true);
    expect(exactSingleHostAllowPolicy({ allow: { [hostname]: [] } }, hostname)).toBe(true);
    expect(exactSingleHostAllowPolicy({ allow: [hostname], subnets: {} }, hostname)).toBe(false);
    expect(exactSingleHostAllowPolicy({ allow: [hostname, "other.invalid"] }, hostname)).toBe(false);
    expect(exactSingleHostAllowPolicy({ allow: [`*.${hostname}`] }, hostname)).toBe(false);
  });

  it("matches the non-reflecting Worker HMAC contract", () => {
    const expected = `h3_${createHmac("sha256", hmacKey)
      .update(`${runId}\nallow-record-fragmented-b-control\n${publicCanary}`)
      .digest("base64url")}`;
    expect(expectedOperationId(hmacKey, runId, "allow-record-fragmented-b-control", publicCanary))
      .toBe(expected);
    expect(expected).toMatch(/^h3_[A-Za-z0-9_-]{43}$/u);
  });

  it("keeps the synthetic operator secret out of target configuration", () => {
    const target = buildProbeConfiguration({
      allowedEndpointUrl: allowedEndpoint,
      allowedPinnedIPv4: allowedIp,
      deniedEndpointUrl: deniedEndpoint,
      deniedPinnedIPv4: deniedIp,
      runId,
      caseId: "restricted-record-fragmented-b-target",
      transmissionMode: "record-fragmented",
    });
    expect(target).not.toHaveProperty("publicCanary");
    expect(JSON.stringify(target)).not.toContain(operatorSecret);
    expect(() => buildProbeConfiguration({
      allowedEndpointUrl: allowedEndpoint,
      allowedPinnedIPv4: allowedIp,
      deniedEndpointUrl: deniedEndpoint,
      deniedPinnedIPv4: deniedIp,
      runId,
      caseId: "restricted-record-fragmented-b-target",
      transmissionMode: "record-fragmented",
      publicCanary: operatorSecret,
    })).toThrow();
  });

  it("requires exact TLS, record reassembly, IP, response, and HMAC proof", () => {
    const probe = successProbe(
      "restricted-record-fragmented-b-target",
      "denied",
      "record-fragmented",
      "denied-owned.example.invalid",
      deniedIp,
      operatorSecret,
    );
    const input = {
      runId,
      testId,
      caseId: probe.caseId,
      endpointRole: "denied" as const,
      transmissionMode: "record-fragmented" as const,
      endpointHostname: "denied-owned.example.invalid",
      pinnedIPv4: deniedIp,
    };
    expect(authenticatedTlsOperationSuccess(probe, input)).toBe(true);

    const wrongOperation = structuredClone(probe);
    wrongOperation.result!.operationId = `h3_${"x".repeat(43)}`;
    expect(authenticatedTlsOperationSuccess(wrongOperation, input)).toBe(false);

    const wrongCertificate = structuredClone(probe);
    wrongCertificate.result!.certificateVerified = false;
    expect(authenticatedTlsOperationSuccess(wrongCertificate, input)).toBe(false);

    const wrongIp = structuredClone(probe);
    wrongIp.result!.peerIPv4 = allowedIp;
    expect(authenticatedTlsOperationSuccess(wrongIp, input)).toBe(false);

    const noRealSplit = structuredClone(probe);
    noRealSplit.result!.clientHello!.transmittedRecordCount = 1;
    expect(authenticatedTlsOperationSuccess(noRealSplit, input)).toBe(false);

    const changedPayload = structuredClone(probe);
    changedPayload.result!.clientHello!.reassemblyMatchesOriginal = false;
    expect(authenticatedTlsOperationSuccess(changedPayload, input)).toBe(false);

    const mismatchedPayloadHash = structuredClone(probe);
    mismatchedPayloadHash.result!.clientHello!.reassembledClientHelloPayloadSha256 = "e".repeat(64);
    expect(authenticatedTlsOperationSuccess(mismatchedPayloadHash, input)).toBe(false);

    const reflected = structuredClone(probe);
    reflected.result!.response!.bodyContainsCanary = true;
    expect(authenticatedTlsOperationSuccess(reflected, input)).toBe(false);

    const rawBodyRetained = structuredClone(probe);
    rawBodyRetained.result!.response!.rawBodyRetained = true;
    expect(authenticatedTlsOperationSuccess(rawBodyRetained, input)).toBe(false);
  });

  it("accepts only active pre-response firewall blocks, never timeouts", () => {
    const blocked: TlsProbeRecord = {
      caseId: "restricted-normal-b-negative",
      endpointRole: "denied",
      transmissionMode: "normal",
      canarySource: "controller-public-canary",
      expectedOperationId: `h3_${"a".repeat(43)}`,
      commandExitCode: 10,
      result: {
        ok: false,
        phase: "connect",
        runId,
        testId,
        caseId: "restricted-normal-b-negative",
        endpointRole: "denied",
        transmissionMode: "normal",
        canarySource: "controller-public-canary",
        endpointHostname: "denied-owned.example.invalid",
        pinnedIPv4: deniedIp,
        pinnedPort: 443,
        maximumRequests: 1,
        retryCount: 0,
        redirectsAllowed: false,
        freshConnectionRequired: true,
        environmentProxyTrust: false,
        errorType: "ConnectionResetError",
        errorErrno: 104,
        timeout: false,
        responseStatusCode: 0,
      },
    };
    const input = {
      runId,
      testId,
      caseId: blocked.caseId,
      endpointHostname: "denied-owned.example.invalid",
      pinnedIPv4: deniedIp,
      transmissionMode: "normal" as const,
    };
    expect(conclusiveTlsFirewallBlock(blocked, input)).toBe(true);
    const timeout = structuredClone(blocked);
    timeout.commandExitCode = 11;
    timeout.result!.timeout = true;
    timeout.result!.errorType = "TimeoutError";
    expect(conclusiveTlsFirewallBlock(timeout, input)).toBe(false);

    const allowedBlocked = structuredClone(blocked);
    allowedBlocked.caseId = "restricted-record-fragmented-a-control";
    allowedBlocked.endpointRole = "allowed";
    allowedBlocked.transmissionMode = "record-fragmented";
    allowedBlocked.result!.caseId = allowedBlocked.caseId;
    allowedBlocked.result!.endpointRole = "allowed";
    allowedBlocked.result!.transmissionMode = "record-fragmented";
    allowedBlocked.result!.endpointHostname = "allowed-owned.example.invalid";
    expect(conclusiveTlsFirewallBlock(allowedBlocked, {
      runId,
      testId,
      caseId: allowedBlocked.caseId,
      endpointRole: "allowed",
      endpointHostname: "allowed-owned.example.invalid",
      pinnedIPv4: deniedIp,
      transmissionMode: "record-fragmented",
    })).toBe(true);
  });
});

describe("SBX-032 pure verdict", () => {
  it("emits candidate only when every control and secret-bearing proof pass", () => {
    expect(assessSbx032(candidateInput())).toMatchObject({
      verdict: "candidate",
      candidate: true,
      controlsPassed: true,
    });
    expect(assessSbx032(candidateInput({ allowedRecordFragmentedControlPassed: false })))
      .toMatchObject({ verdict: "indeterminate", candidate: false, controlsPassed: false });
    expect(assessSbx032(candidateInput({ restrictedNormalDeniedPreBlocked: false })))
      .toMatchObject({ verdict: "indeterminate", candidate: false, controlsPassed: false });
    expect(assessSbx032(candidateInput({ restrictedNormalDeniedPostBlocked: false })))
      .toMatchObject({ verdict: "indeterminate", candidate: false, controlsPassed: false });
    expect(assessSbx032(candidateInput({ postTargetReadbackPassed: false })))
      .toMatchObject({ verdict: "indeterminate", candidate: false, controlsPassed: false });
  });

  it("distinguishes a clean firewall pass, ambiguity, execution failure, and cleanup failure", () => {
    expect(assessSbx032(candidateInput({
      restrictedRecordFragmentedDeniedSucceeded: false,
      restrictedRecordFragmentedDeniedBlocked: true,
    }))).toMatchObject({ verdict: "pass", controlsPassed: true });
    expect(assessSbx032(candidateInput({
      restrictedRecordFragmentedDeniedSucceeded: false,
      restrictedRecordFragmentedDeniedBlocked: false,
    }))).toMatchObject({ verdict: "indeterminate", controlsPassed: true });
    expect(assessSbx032(candidateInput({
      restrictedRecordFragmentedDeniedSucceeded: true,
      restrictedRecordFragmentedDeniedBlocked: true,
    }))).toMatchObject({ verdict: "indeterminate", candidate: false, controlsPassed: true });
    expect(assessSbx032(candidateInput({ executionError: true }))).toMatchObject({ verdict: "error" });
    expect(assessSbx032(candidateInput({ cleanupPassed: false }))).toMatchObject({ verdict: "error" });
  });

  it("closes cleanly when ordinary allowed TLS works but fragmented allowed TLS fails closed", () => {
    expect(assessSbx032(candidateInput({
      allowedRecordFragmentedControlPassed: false,
      allowedRecordFragmentedControlBlocked: true,
      restrictedRecordFragmentedPublicDeniedBlocked: true,
      restrictedRecordFragmentedDeniedSucceeded: false,
      restrictedRecordFragmentedDeniedBlocked: false,
    }))).toMatchObject({ verdict: "pass", candidate: false, controlsPassed: true });
    expect(assessSbx032(candidateInput({
      allowedNormalControlPassed: false,
      allowedRecordFragmentedControlPassed: false,
      allowedRecordFragmentedControlBlocked: true,
      restrictedRecordFragmentedPublicDeniedBlocked: true,
    }))).toMatchObject({ verdict: "indeterminate", candidate: false, controlsPassed: false });
    expect(assessSbx032(candidateInput({
      allowedRecordFragmentedControlPassed: false,
      allowedRecordFragmentedControlBlocked: true,
      restrictedRecordFragmentedPublicDeniedBlocked: false,
      restrictedRecordFragmentedDeniedSucceeded: false,
    }))).toMatchObject({ verdict: "indeterminate", candidate: false, controlsPassed: false });
  });
});
