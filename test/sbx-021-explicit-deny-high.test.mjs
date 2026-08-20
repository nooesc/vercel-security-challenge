import { execFile } from "node:child_process";
import { createHmac } from "node:crypto";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import {
  assessExplicitDeny,
  baselinePolicy,
  buildProbeConfiguration,
  conclusivePreResponseBlock,
  expectedOperationId,
  explicitCredentials,
  matchesBaselinePolicy,
  matchesRestrictedPolicy,
  restrictedPolicy,
  selectAddressPair,
} from "../pocs/SBX-021/explicit-deny-precedence.mjs";

const executeFile = promisify(execFile);
const guestProbe = fileURLToPath(new URL("../guest/fixed-ip-deny-probe.py", import.meta.url));
const endpointUrl = "https://vsc-tls-deny-swve.cyrus-206.workers.dev/v1/h3-action";
const targetIPv4 = "104.21.61.182";
const safeIPv4 = "172.67.212.197";
const scopeConfirmation = "I_CONTROL_THE_ENDPOINT_AND_AUTHORIZE_BOUNDED_CIDR_PRECEDENCE_TESTING";

function fullAssessment(overrides = {}) {
  return {
    setupPassed: true,
    baselinePolicyReadbackPassed: true,
    baselineTargetSucceeded: true,
    updateAcknowledged: true,
    activeReadbackPassed: true,
    independentReadbackPassed: true,
    sameSessionReadbackPassed: true,
    restrictedSafeSucceeded: true,
    restrictedTargetSucceeded: false,
    restrictedTargetBlocked: true,
    cleanupPassed: true,
    ...overrides,
  };
}

function guestConfiguration(overrides = {}) {
  return {
    scopeConfirmation,
    endpointUrl,
    pinnedIPv4: targetIPv4,
    runId: "run-sbx-021",
    testId: "SBX-021-POC",
    caseId: "baseline-target-allow",
    publicCanary: "public_AAAAAAAAAAAAAAAAAAAAAAAA",
    timeoutSeconds: 8,
    maxResponseBytes: 1024,
    ...overrides,
  };
}

async function plan(configuration) {
  const encoded = Buffer.from(JSON.stringify(configuration)).toString("base64url");
  const { stdout } = await executeFile("python3", [guestProbe, encoded, "--plan"]);
  return JSON.parse(stdout);
}

describe("SBX-021 explicit CIDR-deny High packet", () => {
  it("selects two distinct current endpoint addresses and honors exact overrides", () => {
    expect(selectAddressPair([safeIPv4, targetIPv4, safeIPv4])).toEqual({
      target: targetIPv4,
      safe: safeIPv4,
      currentAddresses: [targetIPv4, safeIPv4],
    });
    expect(selectAddressPair([safeIPv4, targetIPv4], safeIPv4, targetIPv4)).toMatchObject({
      target: safeIPv4,
      safe: targetIPv4,
    });
    expect(() => selectAddressPair([targetIPv4])).toThrow(/at least two public IPv4/u);
    expect(() => selectAddressPair([targetIPv4, safeIPv4], "1.1.1.1")).toThrow(/not one of/u);
  });

  it("requires exact baseline and deny-precedence readbacks with no hidden extra rules", () => {
    const baseline = baselinePolicy("worker.research.test");
    const restricted = restrictedPolicy("worker.research.test", targetIPv4);
    expect(matchesBaselinePolicy(baseline, "worker.research.test")).toBe(true);
    expect(matchesRestrictedPolicy(restricted, "worker.research.test", targetIPv4)).toBe(true);
    expect(matchesRestrictedPolicy({
      ...restricted,
      subnets: { allow: ["0.0.0.0/0"], deny: [`${targetIPv4}/32`] },
    }, "worker.research.test", targetIPv4)).toBe(false);
    expect(matchesRestrictedPolicy({ allow: ["worker.research.test"] }, "worker.research.test", targetIPv4)).toBe(false);
  });

  it("keeps the target secret out of guest configuration and derives the Worker proof independently", () => {
    const target = buildProbeConfiguration({
      endpointUrl,
      pinnedIPv4: targetIPv4,
      runId: "run-sbx-021",
      caseId: "restricted-target-secret",
    });
    expect(target).not.toHaveProperty("publicCanary");
    expect(JSON.stringify(target)).not.toContain("operator-secret-value");
    expect(() => buildProbeConfiguration({
      endpointUrl,
      pinnedIPv4: targetIPv4,
      runId: "run-sbx-021",
      caseId: "restricted-target-secret",
      publicCanary: "public_AAAAAAAAAAAAAAAAAAAAAAAA",
    })).toThrow(/must not receive/u);

    const key = "k".repeat(32);
    const expected = `h3_${createHmac("sha256", key)
      .update("run-sbx-021\nrestricted-target-secret\nsecret-value")
      .digest("base64url")}`;
    expect(expectedOperationId(key, "run-sbx-021", "restricted-target-secret", "secret-value"))
      .toBe(expected);
  });

  it("classifies candidate only after every proof control and cleanup passes", () => {
    expect(assessExplicitDeny(fullAssessment())).toMatchObject({ verdict: "pass", candidate: false });
    expect(assessExplicitDeny(fullAssessment({
      restrictedTargetSucceeded: true,
      restrictedTargetBlocked: false,
    }))).toMatchObject({ verdict: "candidate", candidate: true, controlsPassed: true });
    expect(assessExplicitDeny(fullAssessment({ sameSessionReadbackPassed: false })))
      .toMatchObject({ verdict: "indeterminate", candidate: false });
    expect(assessExplicitDeny(fullAssessment({
      restrictedTargetSucceeded: true,
      restrictedTargetBlocked: false,
      cleanupPassed: false,
    }))).toMatchObject({ verdict: "error", candidate: false });
  });

  it("plans one strictly verified pinned request and fixes the secret to the target case", async () => {
    await expect(plan(guestConfiguration())).resolves.toMatchObject({
      ok: true,
      mode: "plan",
      caseId: "baseline-target-allow",
      canarySource: "controller-public-canary",
      endpointHostname: "vsc-tls-deny-swve.cyrus-206.workers.dev",
      pinnedIPv4: targetIPv4,
      protocol: "https-http1.1",
      tlsVerificationRequired: true,
      dnsLookupUsedForConnection: false,
      maximumRequests: 1,
    });
    const target = await plan(guestConfiguration({
      caseId: "restricted-target-secret",
      publicCanary: undefined,
    }));
    expect(target).toMatchObject({
      canarySource: "operator-secret-file",
      operatorSecretPath: "/tmp/sbx-021/operator-secret",
      pinnedIPv4: targetIPv4,
      secretBearingRequestMaterialRetention: "none",
    });
    expect(JSON.stringify(target)).not.toContain("secret-value");
  });

  it("rejects non-public pins, unknown cases, and a target canary supplied by configuration", async () => {
    await expect(plan(guestConfiguration({ pinnedIPv4: "127.0.0.1" }))).rejects.toThrow();
    await expect(plan(guestConfiguration({ caseId: "arbitrary-case" }))).rejects.toThrow();
    await expect(plan(guestConfiguration({
      caseId: "restricted-target-secret",
      publicCanary: "public_AAAAAAAAAAAAAAAAAAAAAAAA",
    }))).rejects.toThrow();
  });

  it("requires the explicit verified alias scope before any live controller work", () => {
    const credentials = explicitCredentials({
      VERCEL_TOKEN: "owned-alias-token",
      VERCEL_TEAM_ID: "team_n98ERpVwV7HqmWRudAyK8sXQ",
      VERCEL_PROJECT_ID: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    });
    expect(credentials).toMatchObject({
      token: "owned-alias-token",
      teamId: "team_n98ERpVwV7HqmWRudAyK8sXQ",
      projectId: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    });
    expect(() => explicitCredentials({})).toThrow(/VERCEL_TOKEN/u);
    expect(() => explicitCredentials({
      VERCEL_TOKEN: "wrong-account-token",
      VERCEL_TEAM_ID: "team_other",
      VERCEL_PROJECT_ID: "prj_other",
    })).toThrow(/verified HackerOne-alias/u);
  });

  it("accepts only the exact Linux EHOSTUNREACH connect signal as a clean firewall block", () => {
    const endpoint = new URL(endpointUrl);
    const base = {
      command: { exitCode: 0 },
      result: {
        ok: false,
        phase: "connect",
        errorType: "OSError",
        errorNumber: 113,
        runId: "run-sbx-021",
        testId: "SBX-021-POC",
        caseId: "restricted-target-secret",
        canarySource: "operator-secret-file",
        endpointHostname: endpoint.hostname,
        pinnedIPv4: targetIPv4,
        pinnedPort: 443,
        protocol: "https-http1.1",
        tlsVerificationRequired: true,
        sniEqualsEndpointHostname: true,
        dnsLookupUsedForConnection: false,
        redirectsAllowed: false,
        environmentProxyTrust: false,
        secretBearingRequestMaterialRetention: "none",
        responseStatusCode: 0,
      },
    };
    const input = { endpoint, pinnedIPv4: targetIPv4, runId: "run-sbx-021" };
    expect(conclusivePreResponseBlock(base, input)).toBe(true);
    for (const resultPatch of [
      { phase: "tls" },
      { phase: "request" },
      { errorType: "TimeoutError", errorNumber: 110 },
      { errorType: "ConnectionRefusedError", errorNumber: 111 },
      { requestTargetSha256: "a".repeat(64) },
    ]) {
      const mutated = structuredClone(base);
      Object.assign(mutated.result, resultPatch);
      expect(conclusivePreResponseBlock(mutated, input)).toBe(false);
    }
  });
});
