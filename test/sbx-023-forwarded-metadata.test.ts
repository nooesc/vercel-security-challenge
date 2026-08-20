import { describe, expect, it } from "vitest";
import {
  attackDefinitions,
  baselineDefinition,
  conclusiveDirectBReachability,
  conclusiveDirectBReset,
  controlledOrigins,
  exactAllowHostsPolicy,
  exactForwardPolicy,
  exactSandboxForwardProjection,
  exitCodeForVerdict,
  explicitCredentials,
  recoverableSandboxIdentity,
} from "../pocs/SBX-023/forwarded-metadata.js";
import {
  assessSbx023,
  rawAuditContainsOrderedPlan,
  rawAuditContainsUniqueValues,
  type GuestCaseAssessment,
  type ProxyAuthenticationRecord,
  type ProxyIdentity,
  type ProxyRawHeaderAudit,
  type Sbx023AssessmentInput,
} from "../pocs/SBX-023/verdict.js";

const identity: ProxyIdentity = {
  host: "proxy-b.example",
  teamId: "team_n98ERpVwV7HqmWRudAyK8sXQ",
  projectId: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
  sandboxId: "sbx_owned",
  sandboxName: "sbx-023-owned",
};
const baselineUrl = "https://source-a.example/v1/probe/run/forwarded-action";
const actionUrl = "https://proxy-b.example/v1/probe/run/forwarded-action";

function audit(
  caseId: string,
  fields: Array<{ position: number; name: string; value: string }> = [],
  overrides: Partial<ProxyRawHeaderAudit> = {},
): ProxyRawHeaderAudit {
  return {
    caseId,
    caseHeaderCount: 1,
    caseIdMatched: true,
    oidcHeaderCount: 1,
    oidcValueCount: 1,
    guestFakeOidcObserved: false,
    intermediaryOrderTrusted: false,
    forwardedFields: fields,
    ...overrides,
  };
}

function record(overrides: Partial<ProxyAuthenticationRecord> = {}): ProxyAuthenticationRecord {
  return {
    operationId: "proxy_baseline123456789012",
    caseId: "baseline-forward",
    authenticated: true,
    actionAuthorized: false,
    reconstructedUrl: baselineUrl,
    proxyMeta: identity,
    rawHeaderAudit: audit("baseline-forward"),
    ...overrides,
  };
}

function guestCase(overrides: Partial<GuestCaseAssessment> = {}): GuestCaseAssessment {
  return {
    caseId: "baseline-forward",
    guestOk: true,
    statusCode: 202,
    responseOperationId: "proxy_baseline123456789012",
    responseAuthenticated: true,
    responseActionAuthorized: false,
    observerEventCount: 1,
    records: [record()],
    ...overrides,
  };
}

const blocked = (caseId: string): GuestCaseAssessment => ({
  caseId,
  guestOk: false,
  observerEventCount: 0,
  records: [],
  conclusiveFirewallBlock: true,
});

const reachable: GuestCaseAssessment = {
  caseId: "direct-b-allow-control",
  guestOk: true,
  statusCode: 204,
  observerEventCount: 1,
  records: [],
  conclusiveDirectReachability: true,
};

function assessmentInput(overrides: Partial<Sbx023AssessmentInput> = {}): Sbx023AssessmentInput {
  return {
    cleanupErrors: [],
    initialPolicyProofPassed: true,
    finalPolicyUpdateAcknowledged: true,
    prePolicyProofPassed: true,
    postPolicyProofPassed: true,
    positiveDirectB: reachable,
    preDirectB: blocked("direct-b-pre-negative"),
    postDirectB: blocked("direct-b-post-negative"),
    baseline: guestCase(),
    attacks: [guestCase({
      caseId: "spoof-host",
      responseOperationId: "proxy_spoofhost1234567890",
      records: [record({
        operationId: "proxy_spoofhost1234567890",
        caseId: "spoof-host",
        rawHeaderAudit: audit("spoof-host"),
      })],
      attackAttributionClass: "unique-metadata",
      rawAttackEvidenceValid: false,
    })],
    allAttacksExecuted: true,
    baselineRawMetadataValid: true,
    expectedBaselineUrl: baselineUrl,
    expectedActionUrl: actionUrl,
    expectedIdentity: identity,
    ...overrides,
  };
}

function candidateAttack(
  attributionClass: GuestCaseAssessment["attackAttributionClass"] = "unique-metadata",
  rawAttackEvidenceValid = true,
): GuestCaseAssessment {
  return guestCase({
    caseId: "spoof-host",
    statusCode: 200,
    responseOperationId: "proxy_candidate123456789012",
    responseAuthenticated: true,
    responseActionAuthorized: true,
    records: [record({
      operationId: "proxy_candidate123456789012",
      caseId: "spoof-host",
      actionAuthorized: true,
      reconstructedUrl: actionUrl,
      rawHeaderAudit: audit("spoof-host", [
        { position: 8, name: "vercel-forwarded-host", value: "proxy-b.example" },
      ]),
    })],
    attackAttributionClass: attributionClass,
    rawAttackEvidenceValid,
  });
}

describe("SBX-023 verdict", () => {
  it("returns pass only when exact policy, pre/post denial, baseline, and complete-matrix controls hold", () => {
    expect(assessSbx023(assessmentInput())).toMatchObject({
      verdict: "pass",
      controlsPassed: true,
      candidate: false,
    });
    expect(assessSbx023(assessmentInput({ postPolicyProofPassed: false }))).toMatchObject({
      verdict: "indeterminate",
      controlsPassed: false,
      candidate: false,
    });
    expect(assessSbx023(assessmentInput({
      positiveDirectB: { ...reachable, conclusiveDirectReachability: false },
    }))).toMatchObject({ verdict: "indeterminate", controlsPassed: false, candidate: false });
    expect(assessSbx023(assessmentInput({ finalPolicyUpdateAcknowledged: false }))).toMatchObject({
      verdict: "indeterminate",
      controlsPassed: false,
      candidate: false,
    });
    expect(assessSbx023(assessmentInput({ allAttacksExecuted: false }))).toMatchObject({
      verdict: "indeterminate",
      controlsPassed: true,
      candidate: false,
    });
  });

  it("requires unique pre-helper metadata, exact identity, and the same opaque operation ID", () => {
    expect(assessSbx023(assessmentInput({ attacks: [candidateAttack()], allAttacksExecuted: false }))).toMatchObject({
      verdict: "candidate",
      controlsPassed: true,
      candidate: true,
      candidateCaseId: "spoof-host",
      candidateOperationId: "proxy_candidate123456789012",
    });

    expect(assessSbx023(assessmentInput({
      attacks: [candidateAttack("duplicate-order-only")],
      allAttacksExecuted: false,
    }))).toMatchObject({ verdict: "indeterminate", candidate: false });
    expect(assessSbx023(assessmentInput({
      attacks: [candidateAttack("unique-metadata", false)],
      allAttacksExecuted: false,
    }))).toMatchObject({ verdict: "indeterminate", candidate: false });

    const wrongIdentity = candidateAttack();
    wrongIdentity.records = wrongIdentity.records.map((entry) => ({
      ...entry,
      proxyMeta: { ...identity, sandboxName: "sbx_other" },
    }));
    expect(assessSbx023(assessmentInput({ attacks: [wrongIdentity], allAttacksExecuted: false }))).toMatchObject({
      verdict: "indeterminate",
      candidate: false,
    });
  });

  it("requires the same connected TCP peer and a fast pre-TLS reset as direct-firewall proof", () => {
    const exact = {
      ok: false,
      connectIpUsed: "203.0.113.10",
      tcpConnected: true,
      remoteAddress: "203.0.113.10",
      remotePort: 443,
      errorPhase: "connect",
      errorCode: "ECONNRESET",
      tlsEstablished: false,
      responseStarted: false,
      durationMs: 20,
    };
    expect(conclusiveDirectBReset(exact, "203.0.113.10", 443, 0, 0, 0)).toBe(true);
    expect(conclusiveDirectBReset(
      { ...exact, errorErrno: -104, errorSyscall: "read" },
      "203.0.113.10",
      443,
      0,
      0,
      0,
    )).toBe(true);
    expect(conclusiveDirectBReset({ ...exact, errorCode: "EHOSTUNREACH" }, "203.0.113.10", 443, 0, 0, 0)).toBe(false);
    expect(conclusiveDirectBReset({ ...exact, errorCode: "EAI_AGAIN" }, "203.0.113.10", 443, 0, 0, 0)).toBe(false);
    expect(conclusiveDirectBReset({ ...exact, errorCode: "SBX_REQUEST_TIMEOUT" }, "203.0.113.10", 443, 0, 0, 0)).toBe(false);
    expect(conclusiveDirectBReset({ ...exact, tcpConnected: false }, "203.0.113.10", 443, 0, 0, 0)).toBe(false);
    expect(conclusiveDirectBReset({ ...exact, remoteAddress: "203.0.113.11" }, "203.0.113.10", 443, 0, 0, 0)).toBe(false);
    expect(conclusiveDirectBReset({ ...exact, durationMs: 2_001 }, "203.0.113.10", 443, 0, 0, 0)).toBe(false);
    expect(conclusiveDirectBReset({ ...exact, tlsEstablished: true }, "203.0.113.10", 443, 0, 0, 0)).toBe(false);
    expect(conclusiveDirectBReset({ ...exact, responseStarted: true }, "203.0.113.10", 443, 0, 0, 0)).toBe(false);
    expect(conclusiveDirectBReset({ ...exact, errorErrno: -54 }, "203.0.113.10", 443, 0, 0, 0)).toBe(false);
    expect(conclusiveDirectBReset({ ...exact, errorSyscall: "write" }, "203.0.113.10", 443, 0, 0, 0)).toBe(false);
    expect(conclusiveDirectBReset(exact, "203.0.113.10", 443, 1, 0, 0)).toBe(false);
    expect(conclusiveDirectBReset(exact, "203.0.113.10", 443, 0, 0, 1)).toBe(false);
  });

  it("requires exact same-IP TCP, TLS, HTTP, and observer proof for the temporary-policy control", () => {
    const exact = {
      ok: true,
      statusCode: 204,
      bodyLength: 0,
      responseJsonValid: false,
      connectIpUsed: "203.0.113.10",
      tcpConnected: true,
      remoteAddress: "203.0.113.10",
      remotePort: 443,
      tlsEstablished: true,
      responseStarted: true,
    };
    expect(conclusiveDirectBReachability(exact, "203.0.113.10", 443, true, 0, 0)).toBe(true);
    expect(conclusiveDirectBReachability({ ...exact, remotePort: 8443 }, "203.0.113.10", 443, true, 0, 0)).toBe(false);
    expect(conclusiveDirectBReachability({ ...exact, tlsEstablished: false }, "203.0.113.10", 443, true, 0, 0)).toBe(false);
    expect(conclusiveDirectBReachability({ ...exact, statusCode: 502 }, "203.0.113.10", 443, true, 0, 0)).toBe(false);
    expect(conclusiveDirectBReachability(exact, "203.0.113.10", 443, false, 0, 0)).toBe(false);
    expect(conclusiveDirectBReachability(exact, "203.0.113.10", 443, true, 1, 0)).toBe(false);
    expect(conclusiveDirectBReachability(exact, "203.0.113.10", 443, true, 0, 2)).toBe(false);
  });

  it("separates unique-value evidence from untrusted duplicate ordering", () => {
    const raw = audit("full-forge", [
      { position: 7, name: "vercel-forwarded-host", value: "proxy-b.example" },
      { position: 10, name: "vercel-forwarded-host", value: "source-a.example" },
    ]);
    expect(rawAuditContainsUniqueValues(raw, "full-forge", [
      { name: "vercel-forwarded-host", value: "proxy-b.example" },
    ])).toBe(true);
    expect(rawAuditContainsOrderedPlan(raw, "full-forge", [
      { name: "vercel-forwarded-host", value: "proxy-b.example" },
      { name: "vercel-forwarded-host", value: "source-a.example" },
    ])).toBe(true);
    expect(raw.intermediaryOrderTrusted).toBe(false);
  });

  it("makes any cleanup failure an error", () => {
    expect(assessSbx023(assessmentInput({ cleanupErrors: ["sandbox delete failed"] }))).toMatchObject({
      verdict: "error",
      controlsPassed: false,
      candidate: false,
    });
  });
});

describe("SBX-023 scope and policy guards", () => {
  it("requires the exact eligible credential triple", () => {
    expect(explicitCredentials({
      VERCEL_TOKEN: "token",
      VERCEL_TEAM_ID: "team_n98ERpVwV7HqmWRudAyK8sXQ",
      VERCEL_PROJECT_ID: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    })).toEqual({
      token: "token",
      teamId: "team_n98ERpVwV7HqmWRudAyK8sXQ",
      projectId: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    });
    expect(() => explicitCredentials({
      VERCEL_TOKEN: "token",
      VERCEL_TEAM_ID: "team_wrong",
      VERCEL_PROJECT_ID: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    })).toThrow(/verified HackerOne-alias/u);
  });

  it("requires explicit scope confirmation for the two exact hard-pinned origins", () => {
    expect(() => controlledOrigins({})).toThrow(/SBX023_SCOPE_CONFIRMATION/u);
    expect(controlledOrigins({
      SBX023_SCOPE_CONFIRMATION:
        "I_CONTROL_BOTH_PINNED_TRYCLOUDFLARE_ORIGINS_AND_AUTHORIZE_BOUNDED_FORWARDING_TESTING",
      SBX023_A_PUBLIC_ORIGIN: "https://alpha-owned.trycloudflare.com",
      SBX023_B_PUBLIC_ORIGIN: "https://bravo-owned.trycloudflare.com",
    })).toMatchObject({
      observerA: { hostname: "alpha-owned.trycloudflare.com" },
      observerB: { hostname: "bravo-owned.trycloudflare.com" },
    });
    expect(() => controlledOrigins({
      SBX023_SCOPE_CONFIRMATION:
        "I_CONTROL_BOTH_PINNED_TRYCLOUDFLARE_ORIGINS_AND_AUTHORIZE_BOUNDED_FORWARDING_TESTING",
      SBX023_A_PUBLIC_ORIGIN: "https://same.trycloudflare.com",
      SBX023_B_PUBLIC_ORIGIN: "https://same.trycloudflare.com",
    })).toThrow(/must be distinct/u);
  });

  it("accepts only the exact single-host forwardURL policy", () => {
    const hostname = "a.example";
    const forwardUrl = "https://b.example/v1/proxy/run/forward";
    expect(exactForwardPolicy({ allow: { [hostname]: [{ forwardURL: forwardUrl }] } }, hostname, forwardUrl)).toBe(true);
    expect(exactForwardPolicy({ allow: { [hostname]: [{ forwardURL: forwardUrl }], extra: [] } }, hostname, forwardUrl)).toBe(false);
    expect(exactForwardPolicy({ allow: { [hostname]: [{ forwardURL: `${forwardUrl}/wrong` }] } }, hostname, forwardUrl)).toBe(false);
  });

  it("distinguishes the documented sandbox projection from the full session forwarding policy", () => {
    expect(exactSandboxForwardProjection({ allow: ["a.example"] }, "a.example")).toBe(true);
    expect(exactSandboxForwardProjection({ allow: { "a.example": [] } }, "a.example")).toBe(false);
    expect(exactSandboxForwardProjection({ allow: ["a.example", "b.example"] }, "a.example")).toBe(false);
    expect(exactAllowHostsPolicy({ allow: ["a.example", "b.example"] }, ["a.example", "b.example"])).toBe(true);
    expect(exactAllowHostsPolicy({ allow: ["b.example", "a.example"] }, ["a.example", "b.example"])).toBe(true);
    expect(exactAllowHostsPolicy({ allow: ["a.example", "a.example"] }, ["a.example", "b.example"])).toBe(false);
  });

  it("uses the same real A action path and leaves forwarded path/OIDC untouched in decisive authority cases", () => {
    const observerA = new URL("https://a.example");
    const observerB = new URL("https://b.example");
    const sourcePath = "/v1/probe/run/forward-source";
    const actionPath = "/v1/probe/run/forwarded-action";
    expect(baselineDefinition(observerA, actionPath)).toMatchObject({
      destination: observerA,
      rawPath: actionPath,
      reservedHeaders: [],
    });
    const definitions = attackDefinitions(observerA, observerB, sourcePath, actionPath, "fake-oidc");
    for (const caseId of ["spoof-host", "full-forge", "case-variant-full-forge", "full-forge-a-port"]) {
      const definition = definitions.find((entry) => entry.caseId === caseId);
      expect(definition?.rawPath).toBe(actionPath);
      expect(definition?.reservedHeaders.some(([name, value]) =>
        name.toLowerCase() === "vercel-forwarded-host" && value === observerB.host
      )).toBe(true);
      expect(definition?.reservedHeaders.some(([name]) =>
        name.toLowerCase() === "vercel-forwarded-path" || name.toLowerCase() === "vercel-sandbox-oidc-token"
      )).toBe(false);
    }
  });

  it("recovers only an exact full-run sandbox identity inside the creation window", () => {
    const expectedTags = { harness: "vsc", test: "SBX-023", run: "full-run-uuid" };
    const valid = {
      createdAtMs: 10_000,
      startedAtMs: 9_000,
      nowMs: 11_000,
      tags: expectedTags,
      expectedTags,
    };
    expect(recoverableSandboxIdentity(valid)).toBe(true);
    expect(recoverableSandboxIdentity({ ...valid, tags: { ...expectedTags, run: "other" } })).toBe(false);
    expect(recoverableSandboxIdentity({ ...valid, createdAtMs: 3_000 })).toBe(false);
  });

  it("makes candidate, indeterminate, and error verdicts nonzero", () => {
    expect(exitCodeForVerdict("pass")).toBe(0);
    expect(exitCodeForVerdict("candidate")).toBe(1);
    expect(exitCodeForVerdict("indeterminate")).toBe(1);
    expect(exitCodeForVerdict("error")).toBe(1);
  });
});
