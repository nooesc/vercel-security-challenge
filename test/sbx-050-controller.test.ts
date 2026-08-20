import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  classifyPolicyReadback,
  diagnosePolicyReadbacks,
  exactObservedPhasePolicy,
  exactMatcherlessRedactedFinalPolicy,
  exactSbx050OwnedSessionId,
  cleanupSandbox,
  explicitConfiguration,
  finalChainingPolicy,
  fixedGuestConfiguration,
  policyReadbackCheckpoint,
  publicForwardPolicy,
  reportabilityForAssessment,
  sanitizeObservedPolicy,
  sanitizeProbe,
  transformAlonePolicy,
  updatePhasePolicy,
} from "../pocs/SBX-050/action-chaining.js";
import { APIError, type Sandbox } from "@vercel/sandbox";
import {
  proxyAudience,
  requestPath,
  SBX050_CREDENTIAL_HEADER,
  SBX050_PUBLIC_TRIGGER,
  SBX050_REDACTED_VALUE,
  SBX050_TRIGGER_HEADER,
  SBX050_TRIGGER_MARKER,
} from "../pocs/SBX-050/protocol.js";
import { exactPhasePolicy, type Sbx050ExpectedIdentity } from "../pocs/SBX-050/verdict.js";

const RUN_ID = "12345678-1234-4123-8123-123456789abc";
const CANARY = "c50_abcdefghijklmnopqrstuvwx";
const CREDENTIAL = `s50_${"a".repeat(43)}`;
const HIDDEN_TRIGGER = `t50_${"b".repeat(32)}`;
const A = new URL("https://a.example.test");
const P = new URL("https://p.example.test");

function environment(): NodeJS.ProcessEnv {
  return {
    VERCEL_TOKEN: "opaque-test-pat",
    VERCEL_TEAM_ID: "team_n98ERpVwV7HqmWRudAyK8sXQ",
    VERCEL_PROJECT_ID: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    SBX050_ALIAS_EMAIL_CONFIRMATION: "swve@wearehackerone.com",
    SBX050_SCOPE_CONFIRMATION:
      "I_CONTROL_BOTH_SBX050_ORIGINS_AND_AUTHORIZE_BOUNDED_ACTION_CHAINING_TESTING",
    SBX050_ADMIN_KEY: "a".repeat(64),
    SBX050_ACTION_KEY: "b".repeat(64),
    SBX050_A_PUBLIC_ORIGIN: A.origin,
    SBX050_P_PUBLIC_ORIGIN: P.origin,
  };
}

const IDENTITY: Sbx050ExpectedIdentity = {
  aliasEmail: "swve@wearehackerone.com",
  aliasIdentityVerified: true,
  teamId: "team_n98ERpVwV7HqmWRudAyK8sXQ",
  projectId: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
  sandboxName: "sbx-050-owned",
  sessionId: "sbx_abcdefghijklmnopqrstuvwxyz1234",
};

function matcherlessFinalPolicy(): ReturnType<typeof finalChainingPolicy> {
  const policy = structuredClone(finalChainingPolicy(
    A.hostname, P, RUN_ID, CREDENTIAL, HIDDEN_TRIGGER,
  )) as { allow: Record<string, Array<Record<string, unknown>>> };
  const rules = policy.allow[A.hostname]!;
  delete rules[0]!.match;
  delete rules[1]!.match;
  const transform = (rules[0]!.transform as Array<{ headers: Record<string, string> }>)[0]!;
  transform.headers[SBX050_CREDENTIAL_HEADER] = "<redacted>";
  transform.headers[SBX050_TRIGGER_HEADER] = "<redacted>";
  return policy as ReturnType<typeof finalChainingPolicy>;
}

function finalObservation(
  activeSessionPolicy: unknown = finalChainingPolicy(A.hostname, P, RUN_ID, CREDENTIAL, HIDDEN_TRIGGER),
  independentSessionPolicy: unknown = activeSessionPolicy,
) {
  return {
    stage: "final-before" as const,
    initialSessionId: IDENTITY.sessionId,
    expectedIdentity: IDENTITY,
    configuredPolicy: finalChainingPolicy(A.hostname, P, RUN_ID, CREDENTIAL, HIDDEN_TRIGGER),
    activeSandboxName: IDENTITY.sandboxName,
    activeSandboxPolicy: { allow: [A.hostname] },
    activeSessionId: IDENTITY.sessionId,
    activeSessionPolicy,
    independentSandboxName: IDENTITY.sandboxName,
    independentSandboxPolicy: { allow: [A.hostname] },
    independentSessionId: IDENTITY.sessionId,
    independentSessionPolicy,
    aHostname: A.hostname,
    pOrigin: P,
    runId: RUN_ID,
    credential: CREDENTIAL,
    hiddenTrigger: HIDDEN_TRIGGER,
  };
}

describe("SBX-050 controller", () => {
  it("requires exact eligible scope, distinct owned origins and strict controller trust", () => {
    expect(explicitConfiguration(environment())).toMatchObject({
      teamId: environment().VERCEL_TEAM_ID,
      projectId: environment().VERCEL_PROJECT_ID,
      aOrigin: A,
      pOrigin: P,
    });
    for (const mutation of [
      { VERCEL_TEAM_ID: "team_other" },
      { VERCEL_PROJECT_ID: "prj_other" },
      { SBX050_ALIAS_EMAIL_CONFIRMATION: "owner@example.test" },
      { SBX050_SCOPE_CONFIRMATION: "yes" },
      { SBX050_A_PUBLIC_ORIGIN: "http://a.example.test" },
      { SBX050_A_PUBLIC_ORIGIN: "https://a.example.test/path" },
      { SBX050_P_PUBLIC_ORIGIN: A.origin },
      { SBX050_ADMIN_KEY: "short" },
      { SBX050_ACTION_KEY: "a".repeat(64) },
      { VERCEL_TOKEN: "header.payload.signature" },
      { NODE_TLS_REJECT_UNAUTHORIZED: "0" },
      { NODE_OPTIONS: "--require=/tmp/injected.cjs" },
      { NODE_EXTRA_CA_CERTS: "/tmp/custom.pem" },
      { NODE_USE_SYSTEM_CA: "1" },
      { OPENSSL_CONF: "/tmp/openssl.cnf" },
      { OPENSSL_MODULES: "/tmp/modules" },
      { SSL_CERT_DIR: "/tmp/certs" },
      { SSL_CERT_FILE: "/tmp/cert.pem" },
    ]) expect(() => explicitConfiguration({ ...environment(), ...mutation })).toThrow();
  });

  it("constructs three exact policies and preserves decisive rule order", () => {
    const publicPolicy = publicForwardPolicy(A.hostname, P, RUN_ID);
    const transformPolicy = transformAlonePolicy(A.hostname, RUN_ID, CREDENTIAL, HIDDEN_TRIGGER);
    const finalPolicy = finalChainingPolicy(A.hostname, P, RUN_ID, CREDENTIAL, HIDDEN_TRIGGER);
    expect(exactObservedPhasePolicy(
      "public-forward", publicPolicy, A.hostname, P, RUN_ID, CREDENTIAL, HIDDEN_TRIGGER,
    )).toBe(true);
    expect(exactObservedPhasePolicy(
      "transform-alone", transformPolicy, A.hostname, P, RUN_ID, CREDENTIAL, HIDDEN_TRIGGER,
    )).toBe(true);
    expect(exactObservedPhasePolicy(
      "final-before", finalPolicy, A.hostname, P, RUN_ID, CREDENTIAL, HIDDEN_TRIGGER,
    )).toBe(true);

    const allow = (finalPolicy as { allow: Record<string, unknown[]> }).allow[A.hostname]!;
    expect(allow).toHaveLength(2);
    expect(allow[0]).toMatchObject({
      match: { path: { exact: `/v1/sbx050/arm/${RUN_ID}` } },
      transform: [{ headers: {
        [SBX050_CREDENTIAL_HEADER]: CREDENTIAL,
        [SBX050_TRIGGER_HEADER]: HIDDEN_TRIGGER,
      } }],
    });
    expect(allow[1]).toMatchObject({
      match: { headers: [{
        key: { exact: SBX050_TRIGGER_HEADER },
        value: { exact: HIDDEN_TRIGGER },
      }] },
    });
    expect(JSON.stringify(publicPolicy)).toContain(SBX050_PUBLIC_TRIGGER);
  });

  it("accepts only the exact ordered all-matcher or all-matcherless final projection", () => {
    const exact = diagnosePolicyReadbacks(finalObservation());
    expect(exact).toMatchObject({
      configuredPolicy: "exact-final-matchers",
      activeSandboxPolicy: "exact-top-host-list",
      activeSessionPolicy: "exact-final-matchers",
      independentSessionPolicy: "exact-final-matchers",
      activeIdentity: "exact",
      independentIdentity: "exact",
      projectionMode: "exact-matchers",
      continuationAllowed: true,
      containsSecrets: false,
    });

    const matcherless = matcherlessFinalPolicy();
    expect(exactMatcherlessRedactedFinalPolicy(matcherless, A.hostname, P, RUN_ID)).toBe(true);
    expect(classifyPolicyReadback(
      "final-before", matcherless, A.hostname, P, RUN_ID, CREDENTIAL, HIDDEN_TRIGGER,
    )).toBe("exact-final-matcherless-redacted");
    expect(diagnosePolicyReadbacks(finalObservation(matcherless))).toMatchObject({
      activeSessionPolicy: "exact-final-matcherless-redacted",
      independentSessionPolicy: "exact-final-matcherless-redacted",
      projectionMode: "matcherless-redacted",
      continuationAllowed: true,
    });
  });

  it("rejects every hybrid, extra, reordered, wrong-audience, identity, configured, and missing readback", () => {
    const matcherless = matcherlessFinalPolicy() as { allow: Record<string, Array<Record<string, unknown>>> };
    const exact = finalChainingPolicy(A.hostname, P, RUN_ID, CREDENTIAL, HIDDEN_TRIGGER) as {
      allow: Record<string, Array<Record<string, unknown>>>;
    };
    const hybridRule = structuredClone(exact);
    delete hybridRule.allow[A.hostname]![0]!.match;
    const extra = structuredClone(matcherless);
    extra.allow[A.hostname]!.push({ forwardURL: proxyAudience(P, RUN_ID) });
    const reordered = structuredClone(matcherless);
    reordered.allow[A.hostname]!.reverse();
    const wrongAudience = structuredClone(matcherless);
    wrongAudience.allow[A.hostname]![1]!.forwardURL = "https://wrong.example.test/";

    const mutations = [
      finalObservation(hybridRule),
      finalObservation(exact, matcherless),
      finalObservation(extra),
      finalObservation(reordered),
      finalObservation(wrongAudience),
      { ...finalObservation(), activeSessionId: "sbx_wrongidentity000000000000" },
      { ...finalObservation(), independentSandboxName: "sbx-050-other" },
      { ...finalObservation(), expectedIdentity: { ...IDENTITY, aliasIdentityVerified: false } },
      { ...finalObservation(), configuredPolicy: { allow: [A.hostname] } },
      { ...finalObservation(), activeSessionPolicy: undefined },
      { ...finalObservation(), independentSessionPolicy: undefined },
      { ...finalObservation(), activeSandboxPolicy: undefined },
    ];
    for (const observation of mutations) {
      const diagnostic = diagnosePolicyReadbacks(observation);
      expect(diagnostic.continuationAllowed, JSON.stringify(diagnostic)).toBe(false);
      expect(diagnostic.projectionMode === "undetermined" ||
        diagnostic.activeIdentity === "unexpected" || diagnostic.independentIdentity === "unexpected" ||
        diagnostic.configuredPolicy === "unexpected" ||
        diagnostic.activeSandboxPolicy === "unexpected").toBe(true);
    }
  });

  it("persists only closed-vocabulary secret-free policy diagnostics before validation abort", () => {
    const matcherless = diagnosePolicyReadbacks(finalObservation(matcherlessFinalPolicy()));
    const poisoned = { ...matcherless, rawPolicy: CREDENTIAL, rawAudience: P.origin };
    const checkpoint = policyReadbackCheckpoint(RUN_ID, {
      "final-before": poisoned as typeof matcherless,
    });
    const serialized = JSON.stringify(checkpoint);
    expect(serialized).not.toContain(CREDENTIAL);
    expect(serialized).not.toContain(HIDDEN_TRIGGER);
    expect(serialized).not.toContain(A.hostname);
    expect(serialized).not.toContain(P.hostname);
    expect(checkpoint).toMatchObject({
      kind: "policy-readback-checkpoint",
      containsSecrets: false,
      policyReadbackDiagnostics: {
        "final-before": { projectionMode: "matcherless-redacted", continuationAllowed: true },
      },
    });
    expect(() => policyReadbackCheckpoint(RUN_ID, {
      "final-before": { ...matcherless, configuredPolicy: CREDENTIAL as never },
    })).toThrow(/closed vocabulary/u);
    const source = readFileSync(resolve("pocs/SBX-050/action-chaining.ts"), "utf8");
    expect(source.indexOf("await persistDiagnostic(diagnostic)")).toBeGreaterThan(-1);
    expect(source.indexOf("await persistDiagnostic(diagnostic)")).toBeLessThan(
      source.indexOf("if (!diagnostic.continuationAllowed)"),
    );
  });

  it("updates each phase through Sandbox so default and active-session policy are both refreshed", async () => {
    const sessionUpdate = vi.fn();
    const sandboxUpdate = vi.fn(async (_params: { networkPolicy: unknown }) => undefined);
    const sandbox = {
      currentSession: () => ({ sessionId: IDENTITY.sessionId, update: sessionUpdate }),
      update: sandboxUpdate,
    } as unknown as Sandbox;
    const policy = transformAlonePolicy(A.hostname, RUN_ID, CREDENTIAL, HIDDEN_TRIGGER);
    await updatePhasePolicy(sandbox, policy);
    expect(sandboxUpdate).toHaveBeenCalledOnce();
    expect(sandboxUpdate.mock.calls[0]?.[0]).toEqual({ networkPolicy: policy });
    expect(sessionUpdate).not.toHaveBeenCalled();
  });

  it("derives create and cleanup provenance only from one exact SDK handle", () => {
    const tags = { harness: "vsc", test: "SBX-050-POC", run: RUN_ID };
    const valid = {
      name: "sbx-050-owned",
      persistent: false,
      tags,
      currentSession: () => ({ sessionId: IDENTITY.sessionId }),
    } as unknown as Sandbox;
    expect(exactSbx050OwnedSessionId(valid, valid.name, tags)).toBe(IDENTITY.sessionId);

    for (const malformed of [
      { ...valid, name: "sbx-050-other" },
      { ...valid, persistent: true },
      { ...valid, tags: { test: "SBX-050-POC", run: RUN_ID } },
      { ...valid, tags: { ...tags, harness: "other" } },
      { ...valid, tags: { ...tags, test: "SBX-OTHER" } },
      { ...valid, tags: { ...tags, run: "87654321-1234-4123-8123-123456789abc" } },
      { ...valid, currentSession: () => ({ sessionId: "not-canonical" }) },
      { ...valid, currentSession: () => ({ sessionId: "sbx_short" }) },
    ] as unknown as Sandbox[]) {
      expect(exactSbx050OwnedSessionId(malformed, valid.name, tags)).toBeUndefined();
    }
  });

  it("recovers and deletes a late sandbox but retains no-handle uncertainty through the terminal horizon", async () => {
    const stop = vi.fn(async () => undefined);
    const remove = vi.fn(async () => undefined);
    const owned = {
      name: "sbx-050-owned",
      persistent: false,
      tags: { harness: "vsc", run: RUN_ID, test: "SBX-050-POC" },
      currentSession: () => ({ sessionId: IDENTITY.sessionId }),
      stop,
      delete: remove,
    } as unknown as Sandbox;
    const notFound = () => new APIError(new Response(null, { status: 404, statusText: "Not Found" }));
    const getSandbox = vi.fn()
      .mockRejectedValueOnce(notFound())
      .mockRejectedValueOnce(notFound())
      .mockResolvedValueOnce(owned)
      .mockRejectedValueOnce(notFound())
      .mockRejectedValueOnce(notFound())
      .mockRejectedValueOnce(notFound());
    const wait = vi.fn(async () => undefined);
    const config = explicitConfiguration(environment());
    const result = await cleanupSandbox(
      undefined,
      owned.name,
      true,
      false,
      { token: config.token, teamId: config.teamId, projectId: config.projectId },
      owned.tags!,
      [],
      { getSandbox, wait, discoveryDelaysMs: [0, 1, 2], absenceDelaysMs: [0, 1, 2] },
    );
    expect(stop).toHaveBeenCalledOnce();
    expect(remove).toHaveBeenCalledOnce();
    expect(result).toEqual({
      stopped: true,
      deleted: true,
      absenceChecks: 3,
      errors: [
        "sandbox create provenance was not validated; cleanup remains uncertain until its terminal horizon",
      ],
    });
    expect(wait).toHaveBeenCalledTimes(4);
  });

  it("keeps cleanup uncertain when create returned no handle and a sandbox can appear after the bounded checks", async () => {
    const owned = {
      name: "sbx-050-owned",
      persistent: false,
      tags: { harness: "vsc", run: RUN_ID, test: "SBX-050-POC" },
      currentSession: () => ({ sessionId: IDENTITY.sessionId }),
      stop: vi.fn(async () => undefined),
      delete: vi.fn(async () => undefined),
    } as unknown as Sandbox;
    const notFound = () => new APIError(new Response(null, { status: 404, statusText: "Not Found" }));
    const getSandbox = vi.fn()
      .mockRejectedValueOnce(notFound())
      .mockRejectedValueOnce(notFound())
      .mockRejectedValueOnce(notFound())
      .mockRejectedValueOnce(notFound())
      .mockResolvedValueOnce(owned);
    const config = explicitConfiguration(environment());
    const result = await cleanupSandbox(
      undefined,
      owned.name,
      true,
      false,
      { token: config.token, teamId: config.teamId, projectId: config.projectId },
      owned.tags!,
      [],
      { getSandbox, wait: async () => undefined, discoveryDelaysMs: [0, 1, 2, 3] },
    );
    expect(result).toEqual({
      stopped: false,
      deleted: false,
      absenceChecks: 4,
      errors: [
        "sandbox create returned no provenance-validated handle; bounded absence checks cannot exclude a late create",
      ],
    });
    expect(getSandbox).toHaveBeenCalledTimes(4);
    expect(await getSandbox()).toBe(owned);
    expect(owned.stop).not.toHaveBeenCalled();
    expect(owned.delete).not.toHaveBeenCalled();
  });

  it("retains uncertainty when a returned handle fails provenance/session validation even after deletion", async () => {
    const stop = vi.fn(async () => undefined);
    const remove = vi.fn(async () => undefined);
    const owned = {
      name: "sbx-050-owned",
      persistent: false,
      tags: { harness: "vsc", run: RUN_ID, test: "SBX-050-POC" },
      currentSession: () => ({ sessionId: IDENTITY.sessionId }),
      stop,
      delete: remove,
    } as unknown as Sandbox;
    const notFound = () => new APIError(new Response(null, { status: 404, statusText: "Not Found" }));
    const getSandbox = vi.fn().mockRejectedValue(notFound());
    const config = explicitConfiguration(environment());
    const result = await cleanupSandbox(
      owned,
      owned.name,
      true,
      false,
      { token: config.token, teamId: config.teamId, projectId: config.projectId },
      owned.tags!,
      [],
      { getSandbox, wait: async () => undefined, absenceDelaysMs: [0, 1, 2] },
    );
    expect(stop).toHaveBeenCalledOnce();
    expect(remove).toHaveBeenCalledOnce();
    expect(result).toEqual({
      stopped: true,
      deleted: true,
      absenceChecks: 3,
      errors: [
        "sandbox create provenance was not validated; cleanup remains uncertain until its terminal horizon",
      ],
    });
  });

  it("treats absent-present-absent post-delete observations as uncertain", async () => {
    const owned = {
      name: "sbx-050-owned",
      persistent: false,
      tags: { harness: "vsc", run: RUN_ID, test: "SBX-050-POC" },
      currentSession: () => ({ sessionId: IDENTITY.sessionId }),
      stop: vi.fn(async () => undefined),
      delete: vi.fn(async () => undefined),
    } as unknown as Sandbox;
    const notFound = () => new APIError(new Response(null, { status: 404, statusText: "Not Found" }));
    const getSandbox = vi.fn()
      .mockRejectedValueOnce(notFound())
      .mockResolvedValueOnce(owned)
      .mockRejectedValueOnce(notFound());
    const config = explicitConfiguration(environment());
    const result = await cleanupSandbox(
      owned,
      owned.name,
      true,
      true,
      { token: config.token, teamId: config.teamId, projectId: config.projectId },
      owned.tags!,
      [],
      { getSandbox, wait: async () => undefined, absenceDelaysMs: [0, 1, 2] },
    );
    expect(result.absenceChecks).toBe(2);
    expect(result.errors).toEqual(["sandbox remained present during delayed post-delete checks"]);
  });

  it("sanitizes observed secrets contextually without inventing rules", () => {
    const raw = finalChainingPolicy(A.hostname, P, RUN_ID, CREDENTIAL, HIDDEN_TRIGGER);
    const sanitized = sanitizeObservedPolicy(
      "final-before", raw, A.hostname, CREDENTIAL, HIDDEN_TRIGGER,
    );
    const serialized = JSON.stringify(sanitized);
    expect(serialized).not.toContain(CREDENTIAL);
    expect(serialized).not.toContain(HIDDEN_TRIGGER);
    expect(serialized).toContain(SBX050_REDACTED_VALUE);
    expect(serialized).toContain(SBX050_TRIGGER_MARKER);
    expect(exactPhasePolicy("final-before", sanitized, A.hostname, RUN_ID, P.origin)).toBe(true);
    expect(JSON.stringify(raw)).toContain(CREDENTIAL);
    expect(JSON.stringify(raw)).toContain(HIDDEN_TRIGGER);
    const hiddenMatcherRedacted = structuredClone(raw) as { allow: Record<string, Array<{
      match?: { headers?: Array<{ value?: { exact?: string } }> };
    }>> };
    hiddenMatcherRedacted.allow[A.hostname]![1]!.match!.headers![0]!.value!.exact = "<redacted>";
    expect(exactObservedPhasePolicy(
      "final-before", hiddenMatcherRedacted, A.hostname, P, RUN_ID, CREDENTIAL, HIDDEN_TRIGGER,
    )).toBe(false);
  });

  it("never places the hidden trigger or credential on the guest surface", () => {
    for (const caseId of [
      "public-forward-control", "transform-alone-control", "final-plain-pre", "direct-p-pre",
      "arm-without-trigger", "direct-p-post", "final-plain-post",
    ] as const) {
      const configuration = fixedGuestConfiguration(RUN_ID, caseId, CANARY, A, P);
      const serialized = JSON.stringify(configuration);
      expect(serialized).not.toContain(CREDENTIAL);
      expect(serialized).not.toContain(HIDDEN_TRIGGER);
      expect(configuration).toEqual({
        scopeConfirmation: "researcher-controlled-sbx050-origins-only",
        testId: "SBX-050-POC",
        runId: RUN_ID,
        caseId,
        correlationCanary: CANARY,
        targetOrigin: caseId.startsWith("direct-p-") ? P.origin : A.origin,
        requestPath: requestPath(RUN_ID, caseId, CANARY),
        sendPublicTrigger: caseId === "public-forward-control",
        timeoutMs: caseId.startsWith("direct-p-") ? 3_000 : 10_000,
      });
    }
  });

  it("binds controller time and identity while retaining only structured error facts", () => {
    const probe = sanitizeProbe({
      schemaVersion: 1,
      testId: "SBX-050-POC",
      runId: RUN_ID,
      caseId: "direct-p-pre",
      correlationCanary: CANARY,
      ok: false,
      phase: "network-error",
      requestHostname: P.hostname,
      requestServername: P.hostname,
      requestPath: requestPath(RUN_ID, "direct-p-pre", CANARY),
      sentCredentialHeader: false,
      sentHiddenTriggerHeader: false,
      sentPublicTriggerHeader: false,
      connectionAttempts: 1,
      actualConnections: 0,
      actualRequests: 0,
      retries: 0,
      redirectsFollowed: 0,
      rejectUnauthorized: true,
      controllerConfigurableCustomTrustAccepted: false,
      inheritedPlatformTrustEnvironmentNames: [],
      tcpConnected: false,
      tlsEstablished: false,
      tlsAuthorized: false,
      responseReceived: false,
      responseShapeValid: false,
      responseBodyRetained: false,
      timedOut: false,
      durationMs: 12,
      errorCode: "EAI_AGAIN",
      errorSyscall: "getaddrinfo",
      errorErrno: -3001,
      errorClass: "dns-resolution",
    }, 0, "2026-08-19T10:00:00.000Z", "2026-08-19T10:00:00.100Z", IDENTITY);
    expect(probe.controllerIdentity).toEqual(IDENTITY);
    expect(probe.startedAt).toBe("2026-08-19T10:00:00.000Z");
    expect(probe.completedAt).toBe("2026-08-19T10:00:00.100Z");
    expect(probe).toMatchObject({
      errorCode: "EAI_AGAIN",
      errorSyscall: "getaddrinfo",
      errorErrno: -3001,
      errorClass: "dns-resolution",
    });
  });

  it("holds reportability only for an exact technical candidate", () => {
    expect(reportabilityForAssessment({
      outcome: "candidate-high",
      candidate: true,
      severity: "conditional-high",
      reportReady: false,
      reportabilityStatus: "hold-pending-semantics-clarification",
      semanticsClarificationRequired: true,
    })).toMatchObject({
      status: "hold-pending-semantics-clarification",
      clarificationRequired: true,
      disposition: "conditional-candidate-hold",
    });

    expect(reportabilityForAssessment({
      outcome: "pass",
      candidate: false,
      severity: "none",
      reportReady: false,
      reportabilityStatus: "not-reportable",
      semanticsClarificationRequired: false,
    })).toEqual({
      status: "not-reportable",
      reportReady: false,
      clarificationRequired: false,
      disposition: "closed-clean-negative",
    });

    for (const outcome of ["indeterminate", "error"] as const) {
      expect(reportabilityForAssessment({
        outcome,
        candidate: false,
        severity: "unknown",
        reportReady: false,
        reportabilityStatus: "not-reportable",
        semanticsClarificationRequired: false,
      })).toEqual({
        status: "not-reportable",
        reportReady: false,
        clarificationRequired: false,
        disposition: "not-reportable",
      });
    }

    expect(reportabilityForAssessment({
      outcome: "pass",
      candidate: false,
      severity: "none",
      reportReady: false,
      reportabilityStatus: "hold-pending-semantics-clarification",
      semanticsClarificationRequired: true,
    })).toMatchObject({ status: "not-reportable", clarificationRequired: false });
  });

  it("uses exclusive mode-0600 local evidence and no configurable TLS trust", () => {
    const source = readFileSync(resolve("pocs/SBX-050/action-chaining.ts"), "utf8");
    expect(source).toContain('open(lockPath, "wx", 0o600)');
    expect(source).toContain('open(artifactPath, "wx", 0o600)');
    expect(source).toContain('open(recoveryJournalPath, "wx+", 0o600)');
    expect(source).toContain('state: "sandbox-create-requested"');
    expect(source).toContain('state: coordinationSafeToRelease ? "cleanup-confirmed" : "cleanup-uncertain"');
    expect(source).toContain('artifactHandle.write(serializedEvidence, 0, "utf8")');
    expect(source).not.toMatch(/\bca\s*:/u);
    expect(source).not.toMatch(/secureContext\s*:/u);
    expect(source).not.toMatch(/checkServerIdentity\s*:/u);
  });
});
