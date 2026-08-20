import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
// @ts-expect-error The guest is deliberately plain executable Node ESM.
import { encodeClientTextFrame, parseServerFrame } from "../guest/websocket-revocation-probe.mjs";
import { parseMaskedClientFrame } from "../pocs/SBX-035/receiver.js";
import {
  SBX035_CASE_ID,
  SBX035_TEST_ID,
  assessSbx035,
  derivePreOperationId,
  deriveSecretCommitment,
  deriveSecretOperationId,
  exactDenyAllSameSession,
  exactFreshActiveBlock,
  type Sbx035AssessmentInput,
  type Sbx035FreshBlockEvidence,
} from "../pocs/SBX-035/verdict.js";

const runId = "123e4567-e89b-42d3-a456-426614174000";
const host = "owned-tunnel.example.com";
const ip = "104.21.61.182";
const key = "receiver-key-that-is-long-enough-for-the-test";
const canary = "corr_ABCDEFGHIJKLMNOPQRSTUVWX";
const secret = "opsec_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq";
const preOperationId = derivePreOperationId(key, runId, SBX035_CASE_ID, canary);
const commitment = deriveSecretCommitment(key, runId, SBX035_CASE_ID, secret);
const secretOperationId = deriveSecretOperationId(key, runId, SBX035_CASE_ID, commitment);
const guestPath = resolve("guest/websocket-revocation-probe.mjs");

function configuration(mode: "retained" | "fresh-https" | "fresh-wss" = "retained") {
  return {
    scopeConfirmation: "I_CONTROL_THE_WSS_ORIGIN_AND_AUTHORIZE_ONE_SYNTHETIC_SECRET_SEND",
    mode,
    runId,
    testId: SBX035_TEST_ID,
    caseId: SBX035_CASE_ID,
    endpointHost: host,
    pinnedIPv4: ip,
    pinnedPort: 443,
    websocketPath: "/v1/sbx035/ws",
    healthPath: "/healthz",
    publicCanary: canary,
    expectedPreOperationId: preOperationId,
    readinessPath: `/tmp/sbx-035/${runId}-ready.json`,
    triggerPath: `/tmp/sbx-035/${runId}-trigger`,
    operatorSecretPath: "/tmp/sbx-035/operator-secret",
    connectTimeoutMs: 3_000,
    ioTimeoutMs: 5_000,
    triggerTimeoutMs: 90_000,
  };
}

function runPlan(value: unknown) {
  const encoded = Buffer.from(JSON.stringify(value)).toString("base64url");
  return spawnSync(process.execPath, [guestPath, encoded, "--plan"], { encoding: "utf8" });
}

function fresh(mode: "fresh-https" | "fresh-wss"): Sbx035FreshBlockEvidence {
  return {
    ok: true,
    mode,
    runId,
    testId: SBX035_TEST_ID,
    caseId: SBX035_CASE_ID,
    endpointHost: host,
    pinnedIPv4: ip,
    pinnedPort: 443,
    attemptCount: 1,
    retryCount: 0,
    strictCertificateVerification: true,
    environmentProxyTrust: false,
    tcpConnected: true,
    tlsEstablished: false,
    responseStarted: false,
    receivedResponse: false,
    timedOut: false,
    durationMs: 20,
    errorCode: "ECONNRESET",
  };
}

function candidateInput(): Sbx035AssessmentInput {
  return {
    runId,
    endpointHost: host,
    pinnedIPv4: ip,
    expectedPreOperationId: preOperationId,
    expectedSecretOperationId: secretOperationId,
    identityAndScopePassed: true,
    initialAllowReadbackPassed: true,
    denyAllSameSessionReadbackPassed: true,
    retainedReadyBeforeDeny: true,
    observerPre: {
      configured: true, preAccepted: true, preOperationId, registered: false,
      secretAccepted: false, secretMessageCount: 0, rawSecretStored: false,
    },
    freshHttps: fresh("fresh-https"),
    freshWss: fresh("fresh-wss"),
    retained: {
      ok: true,
      mode: "retained",
      runId,
      testId: SBX035_TEST_ID,
      caseId: SBX035_CASE_ID,
      endpointHost: host,
      pinnedIPv4: ip,
      pinnedPort: 443,
      tcpConnected: true,
      tlsEstablished: true,
      strictCertificateVerification: true,
      websocketStatusCode: 101,
      websocketAcceptVerified: true,
      preOperationId,
      operatorSecretFileValidated: true,
      operatorSecretFileMode: 0o600,
      secretFramesSent: 1,
      responseOperationId: secretOperationId,
      rawSecretRetained: false,
      rawConfigurationRetained: false,
      rawFramesRetained: false,
    },
    observerFinal: {
      configured: true, preAccepted: true, preOperationId, registered: true,
      secretAccepted: true, secretMessageCount: 1, operationId: secretOperationId, rawSecretStored: false,
    },
    policyUpdatedAt: "2026-08-19T01:00:00.000Z",
    freshControlsCompletedAt: "2026-08-19T01:00:01.000Z",
    operatorSecretCreatedAt: "2026-08-19T01:00:02.000Z",
    operatorSecretWrittenAt: "2026-08-19T01:00:03.000Z",
    triggerWrittenAt: "2026-08-19T01:00:04.000Z",
    observerReceiptAt: "2026-08-19T01:00:05.000Z",
    operatorSecretStagedMode0600: true,
    cleanupPassed: true,
    retention: {
      rawOperatorSecret: false,
      rawGuestConfiguration: false,
      rawCommandStdout: false,
      rawCommandStderr: false,
      rawWebSocketFrames: false,
      rawSecretInArtifact: false,
      secretDigestInArtifact: false,
    },
  };
}

describe("SBX-035 guest protocol", () => {
  it("plans only the fixed strict-TLS/pinned-IP matrix without embedding a secret", () => {
    for (const mode of ["retained", "fresh-https", "fresh-wss"] as const) {
      const child = runPlan(configuration(mode));
      expect(child.status).toBe(0);
      expect(JSON.parse(child.stdout)).toMatchObject({
        ok: true,
        phase: "plan",
        mode,
        runId,
        endpointHost: host,
        pinnedIPv4: ip,
        pinnedPort: 443,
        attemptCount: 1,
        retryCount: 0,
        strictCertificateVerification: true,
        environmentProxyTrust: false,
        rawSecretRetained: false,
        rawConfigurationRetained: false,
        rawFramesRetained: false,
      });
      expect(child.stdout).not.toContain(secret);
    }
  });

  it("rejects unknown fields, non-public pins, and any attempt to place the secret in configuration", () => {
    for (const value of [
      { ...configuration(), rawSecret: secret },
      { ...configuration(), pinnedIPv4: "127.0.0.1" },
      { ...configuration(), endpointHost: "104.21.61.182" },
      { ...configuration(), triggerPath: "/tmp/other" },
    ]) {
      const child = runPlan(value);
      expect(child.status).toBe(20);
      expect(JSON.parse(child.stdout)).toMatchObject({ ok: false, phase: "configuration" });
      expect(child.stdout).not.toContain(secret);
    }
  });

  it("uses one masked client text frame and accepts one bounded unmasked server frame", () => {
    const client = encodeClientTextFrame(canary, Buffer.from([1, 2, 3, 4]));
    expect(parseMaskedClientFrame(client.subarray(0, 5))).toBeUndefined();
    expect(parseMaskedClientFrame(client)).toMatchObject({ opcode: 1, payload: Buffer.from(canary), rest: Buffer.alloc(0) });

    const payload = Buffer.from(JSON.stringify({ type: "pre-ack", operationId: preOperationId }));
    const server = Buffer.concat([Buffer.from([0x81, payload.length]), payload]);
    expect(parseServerFrame(server)).toMatchObject({ opcode: 1, payload, rest: Buffer.alloc(0) });
  });
});

describe("SBX-035 verdict", () => {
  it("requires active non-timeout blocks for both fresh HTTPS and fresh WSS", () => {
    expect(exactFreshActiveBlock(fresh("fresh-https"), { mode: "fresh-https", runId, endpointHost: host, pinnedIPv4: ip })).toBe(true);
    expect(exactFreshActiveBlock({
      ...fresh("fresh-https"),
      tcpConnected: false,
      errorCode: "EHOSTUNREACH",
      durationMs: 31,
    }, { mode: "fresh-https", runId, endpointHost: host, pinnedIPv4: ip })).toBe(true);
    expect(exactFreshActiveBlock({
      ...fresh("fresh-wss"),
      tcpConnected: false,
      errorCode: "ECONNREFUSED",
    }, { mode: "fresh-wss", runId, endpointHost: host, pinnedIPv4: ip })).toBe(false);
    expect(exactFreshActiveBlock({ ...fresh("fresh-wss"), timedOut: true, errorCode: "VSC_TIMEOUT" }, {
      mode: "fresh-wss", runId, endpointHost: host, pinnedIPv4: ip,
    })).toBe(false);
  });

  it("requires literal deny-all on active and independent handles for the original session", () => {
    const valid = {
      originalSessionId: "sbx_same",
      activeSessionId: "sbx_same",
      independentSessionId: "sbx_same",
      activeSandboxPolicy: "deny-all",
      activeSessionPolicy: "deny-all",
      independentSandboxPolicy: "deny-all",
      independentSessionPolicy: "deny-all",
    };
    expect(exactDenyAllSameSession(valid)).toBe(true);
    expect(exactDenyAllSameSession({ ...valid, independentSessionId: "sbx_other" })).toBe(false);
  });

  it("reports High only for one post-barrier secret frame, matching HMAC receipts, cleanup, and zero retention", () => {
    expect(preOperationId).toMatch(/^pre_[A-Za-z0-9_-]{43}$/u);
    expect(commitment).toMatch(/^[a-f0-9]{64}$/u);
    expect(secretOperationId).toMatch(/^ws_[A-Za-z0-9_-]{43}$/u);
    expect(assessSbx035(candidateInput())).toMatchObject({ verdict: "candidate-high", severity: "high", candidate: true });
    expect(assessSbx035({ ...candidateInput(), cleanupPassed: false })).toMatchObject({ verdict: "error", candidate: false });
    expect(assessSbx035({
      ...candidateInput(),
      retention: { ...candidateInput().retention, rawOperatorSecret: true },
    })).toMatchObject({ verdict: "indeterminate", candidate: false });
    expect(assessSbx035({
      ...candidateInput(),
      retained: { ...candidateInput().retained, secretFramesSent: 2 },
    })).toMatchObject({ verdict: "indeterminate", candidate: false });
  });
});
