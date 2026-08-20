import { createHmac } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  assessQuicDenyAll,
  authenticatedProtocolSuccess,
  buildProbeConfiguration,
  conclusiveH3Block,
  conclusiveTcpBlock,
  controlledEndpoint,
  explicitCredentials,
  expectedOperationId,
  type ProbeRecord,
  type QuicAssessmentInput,
} from "../pocs/SBX-017/quic-deny-all.js";

const probePath = fileURLToPath(new URL("../guest/http3-deny-probe.py", import.meta.url));
const endpoint = new URL("https://h3-unit.invalid/v1/h3-action");
const pinnedIPv4 = "1.1.1.1";
const runId = "run-http3-unit";
const canary = "canary_0123456789abcdef";
const key = "unit-test-controller-key-32-bytes-minimum";

function guestConfiguration(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    scopeConfirmation: "I_CONTROL_THE_ENDPOINT_AND_AUTHORIZE_BOUNDED_HTTP3_TESTING",
    endpointUrl: endpoint.href,
    pinnedIPv4,
    runId,
    testId: "SBX-017-POC",
    caseId: "allow-h3-control",
    publicCanary: canary,
    mode: "h3-v3only",
    timeoutSeconds: 8,
    maxResponseBytes: 1_024,
    ...overrides,
  };
}

function runGuestPlan(configuration: Record<string, unknown>) {
  const encoded = Buffer.from(JSON.stringify(configuration)).toString("base64url");
  return spawnSync("python3", [probePath, encoded, "--plan"], {
    encoding: "utf8",
    timeout: 5_000,
  });
}

function commandRecord(exitCode = 0) {
  return {
    commandId: "cmd_unit",
    exitCode,
    stdoutByteLength: 100,
    stdoutSha256: "a".repeat(64),
    stderrByteLength: 0,
    stderrSha256: "b".repeat(64),
  };
}

function successfulProbe(caseId: string, mode: "h3-v3only" | "https-v1"): ProbeRecord {
  const operationId = expectedOperationId(key, runId, caseId, canary);
  return {
    caseId,
    mode,
    canarySource: caseId === "deny-h3-target"
      ? "operator-secret-file"
      : "controller-public-canary",
    configurationSha256: "c".repeat(64),
    expectedOperationId: operationId,
    command: commandRecord(),
    result: {
      ok: true,
      phase: "response",
      runId,
      testId: "SBX-017-POC",
      caseId,
      probeMode: mode,
      canarySource: caseId === "deny-h3-target"
        ? "operator-secret-file"
        : "controller-public-canary",
      requestedHttpVersion: mode === "h3-v3only" ? "v3only" : "v1",
      fallbackAllowed: false,
      endpointHostname: endpoint.hostname,
      pinnedIPv4,
      pinnedPort: 443,
      tlsVerificationRequired: true,
      tlsVerifiedByClient: true,
      redirectsAllowed: false,
      environmentProxyTrust: false,
      proxyOptionForcedEmpty: true,
      noProxyOption: "*",
      dnsPinnedWithCurlResolve: true,
      curlCffiVersion: "0.13.0",
      response: {
        statusCode: 200,
        actualHttpVersion: mode === "h3-v3only" ? 30 : 2,
        primaryIp: pinnedIPv4,
        primaryPort: 443,
        redirectCount: 0,
        contentType: "application/json; charset=utf-8",
        cacheControl: "no-store",
        bodyByteLength: 80,
      },
      authorized: true,
      operationIdShapeValid: true,
      operationId,
    },
  };
}

function blockedProbe(
  caseId: "deny-tcp-control" | "deny-tcp-post-control" | "deny-h3-target",
  mode: "h3-v3only" | "https-v1",
  curlErrorCode: number,
): ProbeRecord {
  return {
    caseId,
    mode,
    canarySource: caseId === "deny-h3-target"
      ? "operator-secret-file"
      : "controller-public-canary",
    configurationSha256: "d".repeat(64),
    expectedOperationId: expectedOperationId(key, runId, caseId, canary),
    command: commandRecord(),
    result: {
      ok: false,
      phase: "request",
      runId,
      testId: "SBX-017-POC",
      caseId,
      probeMode: mode,
      canarySource: caseId === "deny-h3-target"
        ? "operator-secret-file"
        : "controller-public-canary",
      requestedHttpVersion: mode === "h3-v3only" ? "v3only" : "v1",
      fallbackAllowed: false,
      endpointHostname: endpoint.hostname,
      pinnedIPv4,
      pinnedPort: 443,
      tlsVerificationRequired: true,
      redirectsAllowed: false,
      environmentProxyTrust: false,
      proxyOptionForcedEmpty: true,
      noProxyOption: "*",
      dnsPinnedWithCurlResolve: true,
      curlCffiVersion: "0.13.0",
      curlErrorCode,
      responseStatusCode: 0,
      actualHttpVersion: 0,
      primaryIp: "",
      primaryPort: 0,
    },
  };
}

function candidateInput(overrides: Partial<QuicAssessmentInput> = {}): QuicAssessmentInput {
  return {
    setupPassed: true,
    allowH3ControlPassed: true,
    allowTcpControlPassed: true,
    denyUpdateAcknowledged: true,
    denyReadbackPassed: true,
    postDenyReadbackPassed: true,
    denyTcpPreBlocked: true,
    denyTcpPostBlocked: true,
    denyH3Succeeded: true,
    denyH3Blocked: false,
    cleanupPassed: true,
    ...overrides,
  };
}

describe("SBX-017 guest plan", () => {
  it("fixes v3only, TLS verification, IP pinning, no proxy, no redirects, and one request", () => {
    const child = runGuestPlan(guestConfiguration());
    expect(child.status).toBe(0);
    const plan = JSON.parse(child.stdout) as Record<string, unknown>;
    expect(plan).toMatchObject({
      ok: true,
      mode: "plan",
      probeMode: "h3-v3only",
      canarySource: "controller-public-canary",
      endpointUrl: endpoint.href,
      pinnedIPv4,
      port: 443,
      requestedHttpVersion: "v3only",
      fallbackAllowed: false,
      tlsVerificationRequired: true,
      redirectsAllowed: false,
      environmentProxyTrust: false,
      proxyOptionForcedEmpty: true,
      noProxyOption: "*",
      dnsPinnedWithCurlResolve: true,
      maximumRequests: 1,
      maximumReceiveChunkBytes: 1_024,
    });
  });

  it("rejects TLS/proxy overrides and any endpoint path other than the owned action route", () => {
    for (const overrides of [
      { verify: false },
      { proxy: "http://127.0.0.1:8080" },
      { endpointUrl: "https://h3-unit.invalid/not-the-action" },
    ]) {
      const child = runGuestPlan(guestConfiguration(overrides));
      expect(child.status).toBe(2);
      expect(JSON.parse(child.stdout)).toMatchObject({ ok: false, phase: "configuration" });
    }
  });

  it("uses the fixed operator-secret source only for the target case", () => {
    const targetConfiguration = guestConfiguration({ caseId: "deny-h3-target" });
    delete targetConfiguration.publicCanary;
    const target = runGuestPlan(targetConfiguration);
    expect(target.status).toBe(0);
    expect(JSON.parse(target.stdout)).toMatchObject({
      ok: true,
      mode: "plan",
      canarySource: "operator-secret-file",
    });

    const forbiddenPublicCanary = runGuestPlan(guestConfiguration({ caseId: "deny-h3-target" }));
    expect(forbiddenPublicCanary.status).toBe(2);
    expect(JSON.parse(forbiddenPublicCanary.stdout)).toMatchObject({
      ok: false,
      phase: "configuration",
    });
  });
});

describe("SBX-017 scope identity", () => {
  it("hard-pins the owned endpoint and exact HackerOne-alias scope", () => {
    expect(controlledEndpoint({
      SBX017_SCOPE_CONFIRMATION: "I_CONTROL_THE_ENDPOINT_AND_AUTHORIZE_BOUNDED_HTTP3_TESTING",
      SBX017_H3_ENDPOINT_URL: "https://vsc-tls-deny-swve.cyrus-206.workers.dev/v1/h3-action",
    }).hostname).toBe("vsc-tls-deny-swve.cyrus-206.workers.dev");
    expect(() => controlledEndpoint({
      SBX017_SCOPE_CONFIRMATION: "I_CONTROL_THE_ENDPOINT_AND_AUTHORIZE_BOUNDED_HTTP3_TESTING",
      SBX017_H3_ENDPOINT_URL: "https://other-owned.example/v1/h3-action",
    })).toThrow();
    expect(explicitCredentials({
      VERCEL_TOKEN: "alias-token",
      VERCEL_TEAM_ID: "team_n98ERpVwV7HqmWRudAyK8sXQ",
      VERCEL_PROJECT_ID: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    })).toEqual({
      token: "alias-token",
      teamId: "team_n98ERpVwV7HqmWRudAyK8sXQ",
      projectId: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    });
    expect(() => explicitCredentials({})).toThrow(/are required/u);
    expect(() => explicitCredentials({
      VERCEL_TOKEN: "alias-token",
      VERCEL_TEAM_ID: "team_wrong",
      VERCEL_PROJECT_ID: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    })).toThrow(/verified HackerOne-alias/u);
  });
});

describe("SBX-017 authenticated endpoint contract", () => {
  it("matches the Worker HMAC contract exactly", () => {
    const caseId = "allow-h3-control";
    const independent = `h3_${createHmac("sha256", key)
      .update(`${runId}\n${caseId}\n${canary}`)
      .digest("base64url")}`;
    expect(expectedOperationId(key, runId, caseId, canary)).toBe(independent);
    expect(independent).toMatch(/^h3_[A-Za-z0-9_-]{43}$/u);
  });

  it("cannot place the synthetic operator secret in target configuration", () => {
    const syntheticOperatorSecret = "synthetic_operator_secret_0123456789abcdef";
    const targetConfiguration = buildProbeConfiguration({
      endpointUrl: endpoint.href,
      pinnedIPv4,
      runId,
      caseId: "deny-h3-target",
      mode: "h3-v3only",
    });
    expect(targetConfiguration).not.toHaveProperty("publicCanary");
    expect(JSON.stringify(targetConfiguration)).not.toContain(syntheticOperatorSecret);
    expect(() => buildProbeConfiguration({
      endpointUrl: endpoint.href,
      pinnedIPv4,
      runId,
      caseId: "deny-h3-target",
      mode: "h3-v3only",
      publicCanary: syntheticOperatorSecret,
    })).toThrow(/must not receive a canary/u);
  });

  it("requires actual HTTP/3, the exact pinned IP, verified TLS, and the exact operation ID", () => {
    const probe = successfulProbe("allow-h3-control", "h3-v3only");
    expect(authenticatedProtocolSuccess(
      probe,
      runId,
      probe.caseId,
      probe.mode,
      endpoint,
      pinnedIPv4,
    )).toBe(true);

    const wrongVersion = structuredClone(probe);
    (wrongVersion.result!.response as Record<string, unknown>).actualHttpVersion = 3;
    expect(authenticatedProtocolSuccess(
      wrongVersion,
      runId,
      wrongVersion.caseId,
      wrongVersion.mode,
      endpoint,
      pinnedIPv4,
    )).toBe(false);

    const wrongIp = structuredClone(probe);
    (wrongIp.result!.response as Record<string, unknown>).primaryIp = "8.8.8.8";
    expect(authenticatedProtocolSuccess(
      wrongIp,
      runId,
      wrongIp.caseId,
      wrongIp.mode,
      endpoint,
      pinnedIPv4,
    )).toBe(false);

    const wrongOperation = structuredClone(probe);
    wrongOperation.result!.operationId = `h3_${"x".repeat(43)}`;
    expect(authenticatedProtocolSuccess(
      wrongOperation,
      runId,
      wrongOperation.caseId,
      wrongOperation.mode,
      endpoint,
      pinnedIPv4,
    )).toBe(false);

    const missingNoFallbackProof = structuredClone(probe);
    delete missingNoFallbackProof.result!.fallbackAllowed;
    expect(authenticatedProtocolSuccess(
      missingNoFallbackProof,
      runId,
      missingNoFallbackProof.caseId,
      missingNoFallbackProof.mode,
      endpoint,
      pinnedIPv4,
    )).toBe(false);
  });

  it("requires the final authenticated success to identify the fixed secret-file source", () => {
    const target = successfulProbe("deny-h3-target", "h3-v3only");
    expect(authenticatedProtocolSuccess(
      target,
      runId,
      target.caseId,
      target.mode,
      endpoint,
      pinnedIPv4,
    )).toBe(true);
    target.result!.canarySource = "controller-public-canary";
    expect(authenticatedProtocolSuccess(
      target,
      runId,
      target.caseId,
      target.mode,
      endpoint,
      pinnedIPv4,
    )).toBe(false);
  });

  it("accepts only a pre-response connect failure as the TCP deny barrier", () => {
    expect(conclusiveTcpBlock(
      blockedProbe("deny-tcp-control", "https-v1", 7),
      runId,
      endpoint,
      pinnedIPv4,
    )).toBe(true);
    expect(conclusiveTcpBlock(
      blockedProbe("deny-tcp-post-control", "https-v1", 7),
      runId,
      endpoint,
      pinnedIPv4,
      "deny-tcp-post-control",
    )).toBe(true);
    expect(conclusiveTcpBlock(
      blockedProbe("deny-tcp-control", "https-v1", 28),
      runId,
      endpoint,
      pinnedIPv4,
    )).toBe(false);

    const libcurlUnsetPort = blockedProbe("deny-tcp-control", "https-v1", 7);
    libcurlUnsetPort.result!.primaryPort = -1;
    expect(conclusiveTcpBlock(
      libcurlUnsetPort,
      runId,
      endpoint,
      pinnedIPv4,
    )).toBe(true);
    libcurlUnsetPort.result!.primaryPort = -2;
    expect(conclusiveTcpBlock(
      libcurlUnsetPort,
      runId,
      endpoint,
      pinnedIPv4,
    )).toBe(false);
  });

  it("recognizes bounded pre-response network failures as an H3 block", () => {
    for (const code of [7, 28]) {
      expect(conclusiveH3Block(
        blockedProbe("deny-h3-target", "h3-v3only", code),
        runId,
        endpoint,
        pinnedIPv4,
      )).toBe(true);
    }

    const libcurlUnsetPort = blockedProbe("deny-h3-target", "h3-v3only", 7);
    libcurlUnsetPort.result!.primaryPort = -1;
    expect(conclusiveH3Block(
      libcurlUnsetPort,
      runId,
      endpoint,
      pinnedIPv4,
    )).toBe(true);
    libcurlUnsetPort.result!.primaryPort = -2;
    expect(conclusiveH3Block(
      libcurlUnsetPort,
      runId,
      endpoint,
      pinnedIPv4,
    )).toBe(false);
  });
});

describe("SBX-017 verdict", () => {
  it("reports a candidate only after every control and authenticated H3 success", () => {
    expect(assessQuicDenyAll(candidateInput())).toMatchObject({
      verdict: "candidate",
      candidate: true,
      controlsPassed: true,
    });
    expect(assessQuicDenyAll(candidateInput({ denyTcpPreBlocked: false }))).toMatchObject({
      verdict: "indeterminate",
      candidate: false,
    });
    expect(assessQuicDenyAll(candidateInput({ denyTcpPostBlocked: false }))).toMatchObject({
      verdict: "indeterminate",
      candidate: false,
    });
    expect(assessQuicDenyAll(candidateInput({ postDenyReadbackPassed: false }))).toMatchObject({
      verdict: "indeterminate",
      candidate: false,
    });
    expect(assessQuicDenyAll(candidateInput({
      denyH3Succeeded: true,
      denyH3Blocked: true,
    }))).toMatchObject({ verdict: "indeterminate", candidate: false, controlsPassed: true });
  });

  it("passes only for a conclusive H3 network block and treats cleanup failure as error", () => {
    expect(assessQuicDenyAll(candidateInput({
      denyH3Succeeded: false,
      denyH3Blocked: true,
    }))).toMatchObject({ verdict: "pass", candidate: false });
    expect(assessQuicDenyAll(candidateInput({ cleanupPassed: false }))).toMatchObject({
      verdict: "error",
      candidate: false,
    });
  });
});
