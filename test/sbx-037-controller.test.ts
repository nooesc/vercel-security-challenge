import { describe, expect, it } from "vitest";
// @ts-expect-error TS7016: integration guard validates the controller's exact object with the standalone guest parser.
import { validateRawTargetProbeConfig } from "../guest/raw-forwardurl-target-probe.mjs";
import {
  buildProbeConfiguration,
  conclusiveDirectBlock,
  conclusiveDirectReachability,
  conclusiveOriginTerminalControl,
  conclusivePSyntaxControl,
  conclusiveSyntaxControl,
  conclusiveUnsupportedSyntaxControl,
  controlledOrigins,
  exactAllowPolicy,
  exactForwardPolicy,
  exactForwardProjection,
  exitCodeForVerdict,
  explicitCredentials,
  fallbackEvent,
  recoverableSandboxIdentity,
  verifyAliasIdentity,
  type IdentityFetch,
} from "../pocs/SBX-037/request-target-origin-escape.js";
import type { IngressFallbackRecord } from "../pocs/SBX-037/receiver.js";
import {
  SBX037_ALIAS_EMAIL,
  SBX037_PROJECT_ID,
  SBX037_TEAM_ID,
} from "../pocs/SBX-037/verdict.js";

const PIN = "203.0.113.37";
const OPERATION_ID = "rt37r_abcdefghijklmnopqrstuvwx";

function reachable() {
  return {
    ok: true,
    actualConnections: 1,
    actualRequests: 1,
    responseStatusCode: 202,
    responseOperationId: OPERATION_ID,
    responseRole: "B" as const,
    pinnedDestinationIpv4: PIN,
    tlsTrust: {
      inheritedPlatformTrustEnvironmentNames: [
        "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF",
        "OPENSSL_MODULES", "SSL_CERT_DIR", "SSL_CERT_FILE",
      ],
      controllerConfigurableCustomTrustAccepted: false,
      rejectUnauthorized: true,
    },
    transport: {
      tcpConnected: true,
      tlsEstablished: true,
      authorized: true,
      remoteAddress: PIN,
      remotePort: 443,
      alpnProtocol: "http/1.1",
    },
  };
}

function blocked() {
  return {
    ok: false,
    actualConnections: 1,
    actualRequests: 0,
    durationMs: 750,
    errorCode: "ECONNRESET",
    pinnedDestinationIpv4: PIN,
    tlsTrust: {
      inheritedPlatformTrustEnvironmentNames: [
        "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF",
        "OPENSSL_MODULES", "SSL_CERT_DIR", "SSL_CERT_FILE",
      ],
      controllerConfigurableCustomTrustAccepted: false,
      rejectUnauthorized: true,
    },
    transport: {
      tcpConnected: true,
      tlsEstablished: false,
      remoteAddress: PIN,
      remotePort: 443,
    },
  };
}

describe("SBX-037 controller guards", () => {
  it("builds a direct-P control without collapsing canonical A/P/B scope", () => {
    const configuration = buildProbeConfiguration({
      a: new URL("https://a.example.test"),
      p: new URL("https://p.example.test"),
      b: new URL("https://b.example.test"),
      forwardAudience: "https://p.example.test/v1/sbx037/forward/run-controller",
      connectionRole: "p",
      pinnedDestinationIpv4: "104.18.1.10",
      expectedOperationId: OPERATION_ID,
      runId: "run-controller",
      caseId: "absolute-p-syntax-control",
      correlationId: "corr-controller-p",
      targetForm: "absolute",
      targetPath: "/v1/sbx037/collect/run-controller",
      bodySource: "public",
    });
    expect(configuration).toMatchObject({
      researcherControlledOrigins: [
        "https://a.example.test",
        "https://p.example.test",
        "https://b.example.test",
      ],
      aOrigin: "https://a.example.test",
      bOrigin: "https://b.example.test",
      pUrl: "https://p.example.test/v1/sbx037/forward/run-controller",
      connectionRole: "p",
      pinnedDestinationIpv4: "104.18.1.10",
      caseId: "absolute-p-syntax-control",
    });
    expect(validateRawTargetProbeConfig(configuration)).toMatchObject({
      connectionRole: "p",
      a: { origin: "https://a.example.test" },
      p: { origin: "https://p.example.test" },
      b: { origin: "https://b.example.test" },
      connection: { origin: "https://p.example.test", hostname: "p.example.test" },
    });
  });

  it("verifies an unscoped token only from the exact /v2/user alias", async () => {
    const calls: string[] = [];
    const fetchImpl: IdentityFetch = async (input, init) => {
      calls.push(String(input));
      expect(init?.redirect).toBe("error");
      expect(new Headers(init?.headers).get("connection")).toBe("close");
      return new Response(JSON.stringify({ user: { email: SBX037_ALIAS_EMAIL } }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };
    await expect(verifyAliasIdentity("synthetic-token", {}, fetchImpl)).resolves.toEqual({
      email: SBX037_ALIAS_EMAIL,
      method: "v2-user-email",
    });
    expect(calls).toEqual(["https://api.vercel.com/v2/user"]);
  });

  it("rejects a successful /v2/user response for any other email without fallback", async () => {
    let calls = 0;
    const fetchImpl: IdentityFetch = async () => {
      calls += 1;
      return new Response(JSON.stringify({ user: { email: "other@example.test" } }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };
    await expect(verifyAliasIdentity("synthetic-token", {
      SBX037_ALIAS_EMAIL_CONFIRMATION: SBX037_ALIAS_EMAIL,
    }, fetchImpl)).rejects.toThrow(/required HackerOne alias/u);
    expect(calls).toBe(1);
  });

  it("accepts a scoped 401/403 token only with exact manual alias confirmation and exact team/project reads", async () => {
    for (const status of [401, 403]) {
      const calls: Array<{ url: string; init: RequestInit | undefined }> = [];
      const fetchImpl: IdentityFetch = async (input, init) => {
        const url = String(input);
        calls.push({ url, init });
        if (url.endsWith("/v2/user")) return new Response(null, { status });
        if (url === `https://api.vercel.com/v2/teams/${SBX037_TEAM_ID}`) {
          return new Response(JSON.stringify({ id: SBX037_TEAM_ID }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        if (url === `https://api.vercel.com/v9/projects/${SBX037_PROJECT_ID}?teamId=${SBX037_TEAM_ID}`) {
          return new Response(JSON.stringify({ id: SBX037_PROJECT_ID }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        throw new Error(`unexpected URL ${url}`);
      };
      await expect(verifyAliasIdentity("synthetic-token", {
        SBX037_ALIAS_EMAIL_CONFIRMATION: SBX037_ALIAS_EMAIL,
      }, fetchImpl)).resolves.toEqual({
        email: SBX037_ALIAS_EMAIL,
        method: "manual-alias-confirmation-plus-exact-team-project-api",
      });
      expect(calls.map((call) => call.url)).toEqual([
        "https://api.vercel.com/v2/user",
        `https://api.vercel.com/v2/teams/${SBX037_TEAM_ID}`,
        `https://api.vercel.com/v9/projects/${SBX037_PROJECT_ID}?teamId=${SBX037_TEAM_ID}`,
      ]);
      for (const call of calls) {
        expect(call.init?.redirect).toBe("error");
        expect(new Headers(call.init?.headers).get("connection")).toBe("close");
        expect(new Headers(call.init?.headers).get("authorization")).toBe("Bearer synthetic-token");
      }
    }
  });

  it("does not use scoped-token fallback without exact confirmation or for other HTTP failures", async () => {
    const forbidden: IdentityFetch = async () => new Response(null, { status: 403 });
    await expect(verifyAliasIdentity("synthetic-token", {}, forbidden)).rejects.toThrow(/manual HackerOne alias/u);
    await expect(verifyAliasIdentity("synthetic-token", {
      SBX037_ALIAS_EMAIL_CONFIRMATION: "wrong@example.test",
    }, forbidden)).rejects.toThrow(/manual HackerOne alias/u);

    let calls = 0;
    const rateLimited: IdentityFetch = async () => {
      calls += 1;
      return new Response(null, { status: 429 });
    };
    await expect(verifyAliasIdentity("synthetic-token", {
      SBX037_ALIAS_EMAIL_CONFIRMATION: SBX037_ALIAS_EMAIL,
    }, rateLimited)).rejects.toThrow(/returned 429/u);
    expect(calls).toBe(1);
  });

  it("rejects scoped fallback when either exact resource read is wrong", async () => {
    const wrongTeam: IdentityFetch = async (input) => String(input).endsWith("/v2/user")
      ? new Response(null, { status: 403 })
      : new Response(JSON.stringify({ id: "team_wrong" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
    await expect(verifyAliasIdentity("synthetic-token", {
      SBX037_ALIAS_EMAIL_CONFIRMATION: SBX037_ALIAS_EMAIL,
    }, wrongTeam)).rejects.toThrow(/wrong team/u);

    const wrongProject: IdentityFetch = async (input) => {
      const url = String(input);
      if (url.endsWith("/v2/user")) return new Response(null, { status: 401 });
      return new Response(JSON.stringify({
        id: url.includes("/v2/teams/") ? SBX037_TEAM_ID : "prj_wrong",
      }), { status: 200, headers: { "content-type": "application/json" } });
    };
    await expect(verifyAliasIdentity("synthetic-token", {
      SBX037_ALIAS_EMAIL_CONFIRMATION: SBX037_ALIAS_EMAIL,
    }, wrongProject)).rejects.toThrow(/wrong project/u);
  });

  it("requires three distinct exact controlled HTTPS origins", () => {
    const environment = {
      SBX037_SCOPE_CONFIRMATION: "researcher-controlled-sbx037-origins-only",
      SBX037_A_PUBLIC_ORIGIN: "https://a.example.test",
      SBX037_P_PUBLIC_ORIGIN: "https://p.example.test",
      SBX037_B_PUBLIC_ORIGIN: "https://b.example.test",
    };
    expect(controlledOrigins(environment)).toEqual({
      a: new URL("https://a.example.test"),
      p: new URL("https://p.example.test"),
      b: new URL("https://b.example.test"),
    });
    expect(() => controlledOrigins({ ...environment, SBX037_B_PUBLIC_ORIGIN: environment.SBX037_A_PUBLIC_ORIGIN }))
      .toThrow(/three distinct/u);
    expect(() => controlledOrigins({ ...environment, SBX037_A_PUBLIC_ORIGIN: "https://a.example.test/path" }))
      .toThrow(/exact lower-case HTTPS origin/u);
    expect(() => controlledOrigins({ ...environment, SBX037_SCOPE_CONFIRMATION: "wrong" }))
      .toThrow(/SCOPE_CONFIRMATION/u);
  });

  it("hard-pins explicit alias team and project credentials", () => {
    expect(explicitCredentials({
      VERCEL_TOKEN: "synthetic-token",
      VERCEL_TEAM_ID: SBX037_TEAM_ID,
      VERCEL_PROJECT_ID: SBX037_PROJECT_ID,
    })).toEqual({ token: "synthetic-token", teamId: SBX037_TEAM_ID, projectId: SBX037_PROJECT_ID });
    expect(() => explicitCredentials({
      VERCEL_TOKEN: "synthetic-token",
      VERCEL_TEAM_ID: "team_wrong",
      VERCEL_PROJECT_ID: SBX037_PROJECT_ID,
    })).toThrow(/explicit credentials/u);
  });

  it("accepts only exact allow and forward policies", () => {
    const audience = "https://p.example.test/v1/sbx037/forward/run";
    expect(exactAllowPolicy({ allow: ["a.example.test", "b.example.test"] }, ["a.example.test", "b.example.test"]))
      .toBe(true);
    expect(exactAllowPolicy({ allow: ["a.example.test", "b.example.test"], deny: [] }, ["a.example.test", "b.example.test"]))
      .toBe(false);
    expect(exactAllowPolicy({ allow: ["a.example.test", "a.example.test"] }, ["a.example.test", "b.example.test"]))
      .toBe(false);
    expect(exactForwardPolicy({ allow: { "a.example.test": [{ forwardURL: audience }] } }, "a.example.test", audience))
      .toBe(true);
    expect(exactForwardPolicy({ allow: { "a.example.test": [{ forwardURL: audience, transform: [] }] } }, "a.example.test", audience))
      .toBe(false);
    expect(exactForwardProjection({ allow: ["a.example.test"] }, "a.example.test")).toBe(true);
    expect(exactForwardProjection({ allow: ["a.example.test", "b.example.test"] }, "a.example.test")).toBe(false);
  });

  it("requires exact verified pinned reachability and one observer event", () => {
    expect(conclusiveDirectReachability(reachable(), 0, PIN, OPERATION_ID, 1)).toBe(true);
    expect(conclusiveDirectReachability({ ...reachable(), responseOperationId: "rt37r_wrongwrongwrongwrongwr" }, 0, PIN, OPERATION_ID, 1))
      .toBe(false);
    expect(conclusiveDirectReachability({ ...reachable(), transport: { ...reachable().transport, remoteAddress: "203.0.113.38" } }, 0, PIN, OPERATION_ID, 1))
      .toBe(false);
    expect(conclusiveDirectReachability(reachable(), 0, PIN, OPERATION_ID, 0)).toBe(false);
    expect(conclusiveDirectReachability(reachable(), 1, PIN, OPERATION_ID, 1)).toBe(false);
  });

  it("classifies only a fast pre-TLS reset on the exact pinned peer as a firewall block", () => {
    expect(conclusiveDirectBlock(blocked(), 0, PIN, 0)).toBe(true);
    expect(conclusiveDirectBlock({
      ok: false,
      actualConnections: 0,
      actualRequests: 0,
      durationMs: 500,
      errorCode: "EHOSTUNREACH",
      pinnedDestinationIpv4: PIN,
      tlsTrust: {
        inheritedPlatformTrustEnvironmentNames: [
          "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF",
          "OPENSSL_MODULES", "SSL_CERT_DIR", "SSL_CERT_FILE",
        ],
        controllerConfigurableCustomTrustAccepted: false,
        rejectUnauthorized: true,
      },
      transport: { tcpConnected: false, tlsEstablished: false },
    }, 0, PIN, 0)).toBe(true);
    expect(conclusiveDirectBlock({
      ok: false,
      actualConnections: 0,
      actualRequests: 0,
      durationMs: 500,
      errorCode: "ENETUNREACH",
      pinnedDestinationIpv4: PIN,
      tlsTrust: {
        inheritedPlatformTrustEnvironmentNames: [
          "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "OPENSSL_CONF",
          "OPENSSL_MODULES", "SSL_CERT_DIR", "SSL_CERT_FILE",
        ],
        controllerConfigurableCustomTrustAccepted: false,
        rejectUnauthorized: true,
      },
      transport: { tcpConnected: false, tlsEstablished: false },
    }, 0, PIN, 0)).toBe(true);
    expect(conclusiveDirectBlock({ ...blocked(), errorCode: "ECONNREFUSED" }, 0, PIN, 0)).toBe(false);
    expect(conclusiveDirectBlock({ ...blocked(), errorCode: "ETIMEDOUT" }, 0, PIN, 0)).toBe(false);
    expect(conclusiveDirectBlock({ ...blocked(), durationMs: 2_001 }, 0, PIN, 0)).toBe(false);
    expect(conclusiveDirectBlock({ ...blocked(), transport: { ...blocked().transport, tlsEstablished: true } }, 0, PIN, 0))
      .toBe(false);
    expect(conclusiveDirectBlock({ ...blocked(), transport: { ...blocked().transport, remoteAddress: "203.0.113.38" } }, 0, PIN, 0))
      .toBe(false);
    expect(conclusiveDirectBlock(blocked(), 0, PIN, 1)).toBe(false);
    expect(conclusiveDirectBlock(blocked(), 1, PIN, 0)).toBe(false);
  });

  it("requires a raw-target syntax control to terminate exactly at A with no P/B event", () => {
    const runId = "run-037-controller";
    const caseId = "absolute-syntax-control" as const;
    const correlationId = "corr-037-controller";
    const rawRequestTarget = "https://b.example.test/v1/sbx037/collect/run-037-controller";
    const result = {
      ...reachable(),
      runId,
      testId: "SBX-037-POC",
      caseId,
      correlationId,
      targetForm: "absolute" as const,
      rawRequestTarget,
      syntaxSupported: true,
      responseRole: "A" as const,
    };
    const event = {
      observedAt: new Date().toISOString(),
      runId,
      testId: "SBX-037-POC" as const,
      caseId,
      correlationId,
      correlationMatched: true,
      method: "POST",
      rawTarget: rawRequestTarget,
      targetForm: "absolute" as const,
      exactSyntaxTarget: true,
      publicBodyMatched: true,
      bodyLength: 32,
      oidcHeaderCount: 0,
      operationId: OPERATION_ID,
      terminalResponse: true as const,
      responseStatus: 202,
    };
    const exact = {
      result,
      commandExitCode: 0,
      pinnedIp: PIN,
      runId,
      caseId,
      correlationId,
      targetForm: "absolute" as const,
      rawRequestTarget,
      operationId: OPERATION_ID,
      publicBodyBytes: 32,
      aRecords: [event],
      bEventCount: 0,
      pEventCount: 0,
    };
    expect(conclusiveSyntaxControl(exact)).toBe(true);
    expect(conclusiveSyntaxControl({ ...exact, bEventCount: 1 })).toBe(false);
    expect(conclusiveSyntaxControl({ ...exact, aRecords: [{ ...event, rawTarget: "/normalized" }] })).toBe(false);
    expect(conclusiveSyntaxControl({ ...exact, result: { ...result, transport: { ...result.transport, remoteAddress: "203.0.113.38" } } }))
      .toBe(false);
  });

  it("accepts only the exact joined public 400 normalization as an unsupported A-ingress form", () => {
    const runId = "run-037-unsupported";
    const caseId = "absolute-syntax-control" as const;
    const correlationId = "corr-037-unsupported";
    const rawRequestTarget = "https://b.example.test/v1/sbx037/collect/run-037-unsupported";
    const normalizedAPath = "/v1/sbx037/collect/run-037-unsupported";
    const { responseOperationId: _unusedReceipt, ...reachableWithoutReceipt } = reachable();
    const result = {
      ...reachableWithoutReceipt,
      runId,
      testId: "SBX-037-POC",
      caseId,
      correlationId,
      connectionRole: "a" as const,
      targetForm: "absolute" as const,
      method: "POST",
      bodySource: "public" as const,
      operatorSecretLoaded: false,
      requestBodyBytes: 32,
      httpVersion: "1.1",
      maximumConnections: 1,
      maximumRequests: 1,
      retryCount: 0,
      redirectsAllowed: false,
      redirectsFollowed: 0,
      connectionReused: false,
      environmentProxyTrust: false,
      rawRequestTarget,
      syntaxSupported: false,
      responseStatusCode: 400,
      responseRole: "A" as const,
    };
    const event = {
      observedAt: new Date().toISOString(), runId, testId: "SBX-037-POC" as const, caseId,
      correlationId, correlationMatched: true, method: "POST", rawTarget: normalizedAPath,
      targetForm: "other" as const, exactSyntaxTarget: false, publicBodyMatched: true,
      bodyLength: 32, oidcHeaderCount: 0, terminalResponse: true as const, responseStatus: 400,
    };
    const exact = {
      result, commandExitCode: 0, pinnedIp: PIN, runId, caseId, correlationId,
      targetForm: "absolute" as const, rawRequestTarget, normalizedAPath, publicBodyBytes: 32,
      aRecords: [event], bEventCount: 0, pEventCount: 0, pSyntaxEventCount: 0, directEventCount: 0,
    };
    expect(conclusiveUnsupportedSyntaxControl(exact)).toBe(true);
    expect(conclusiveUnsupportedSyntaxControl({ ...exact, aRecords: [{ ...event, rawTarget: rawRequestTarget }] })).toBe(false);
    expect(conclusiveUnsupportedSyntaxControl({ ...exact, result: { ...result, responseStatusCode: 403 } })).toBe(false);
    expect(conclusiveUnsupportedSyntaxControl({ ...exact, pSyntaxEventCount: 1 })).toBe(false);
    expect(conclusiveUnsupportedSyntaxControl({ ...exact, aRecords: [{ ...event, operationId: OPERATION_ID }] })).toBe(false);
  });

  it("requires a raw-target syntax control to terminate exactly at P with no OIDC, forwarding metadata, or A/B event", () => {
    const runId = "run-037-p-controller";
    const caseId = "absolute-p-syntax-control" as const;
    const correlationId = "corr-037-p-controller";
    const rawRequestTarget = "https://b.example.test/v1/sbx037/collect/run-037-p-controller";
    const result = {
      ...reachable(),
      runId,
      testId: "SBX-037-POC",
      caseId,
      correlationId,
      targetForm: "absolute" as const,
      rawRequestTarget,
      syntaxSupported: true,
      responseRole: "P" as const,
    };
    const event = {
      observedAt: new Date().toISOString(),
      runId,
      testId: "SBX-037-POC" as const,
      caseId,
      correlationId,
      correlationMatched: true,
      method: "POST",
      rawTarget: rawRequestTarget,
      targetForm: "absolute" as const,
      exactSyntaxTarget: true,
      hostMatched: true,
      publicBodyMatched: true,
      bodyLength: 32,
      oidcHeaderCount: 0,
      forwardedMetadataAbsent: true,
      operationId: OPERATION_ID,
      terminalResponse: true as const,
      redirectAttempted: false as const,
      fetchAttempted: false as const,
      proxyAttempted: false as const,
      locationHeaderPresent: false as const,
      responseStatus: 202,
    };
    const exact = {
      result,
      commandExitCode: 0,
      pinnedIp: PIN,
      runId,
      caseId,
      correlationId,
      targetForm: "absolute" as const,
      rawRequestTarget,
      operationId: OPERATION_ID,
      publicBodyBytes: 32,
      pSyntaxRecords: [event],
      aEventCount: 0,
      bEventCount: 0,
      forwardedPEventCount: 0,
    };
    expect(conclusivePSyntaxControl(exact)).toBe(true);
    expect(conclusivePSyntaxControl({ ...exact, bEventCount: 1 })).toBe(false);
    expect(conclusivePSyntaxControl({
      ...exact,
      pSyntaxRecords: [{ ...event, forwardedMetadataAbsent: false }],
    })).toBe(false);
  });

  it("checks only origin-case A/B records after earlier syntax records", () => {
    const exact = {
      result: { ...reachable(), responseRole: "P" as const },
      commandExitCode: 0,
      pinnedIp: PIN,
      operationId: OPERATION_ID,
      pRecords: [{ operationId: OPERATION_ID, tokenVerified: true }],
      originCaseAEventCount: 0,
      originCaseBEventCount: 0,
    };
    expect(conclusiveOriginTerminalControl(exact)).toBe(true);
    expect(conclusiveOriginTerminalControl({ ...exact, originCaseAEventCount: 1 })).toBe(false);
    expect(conclusiveOriginTerminalControl({ ...exact, originCaseBEventCount: 1 })).toBe(false);
  });

  it("recovers only the exact tagged sandbox created inside the run window", () => {
    const now = new Date();
    const tags = { harness: "vsc", test: "SBX-037-POC", run: "run-1" };
    expect(recoverableSandboxIdentity({ createdAt: now, startedAt: now.toISOString(), tags, expectedTags: tags })).toBe(true);
    expect(recoverableSandboxIdentity({
      createdAt: now,
      startedAt: now.toISOString(),
      tags: { ...tags, run: "other" },
      expectedTags: tags,
    })).toBe(false);
  });

  it("uses nonzero exit status for every non-pass verdict", () => {
    expect(exitCodeForVerdict("pass")).toBe(0);
    expect(exitCodeForVerdict("candidate-high")).toBe(1);
    expect(exitCodeForVerdict("candidate-medium")).toBe(1);
    expect(exitCodeForVerdict("indeterminate")).toBe(1);
  });

  it("maps fallback readback byte-for-byte without inventing secret or routing proof fields", () => {
    const record = {
      observedAt: "2026-08-19T04:00:00.000Z",
      role: "B",
      reason: "unmatched-collect-path",
      runId: "run-037-fallback",
      testId: "SBX-037-POC",
      caseId: "network-path-target-attack",
      correlationId: "corr-037-fallback",
      correlationMatched: true,
      method: "POST",
      requestTarget: "/rewritten/by/proxy",
      host: "b.example.test",
      forwardedHeaderCounts: {
        host: { lines: 1, values: 1 }, scheme: { lines: 1, values: 1 },
        port: { lines: 1, values: 1 }, path: { lines: 1, values: 1 },
      },
      oidcHeaderCount: 0,
      oidcValueCount: 0,
      tokenVerified: false,
      algorithmRs256: false,
      issuerVerified: false,
      audienceVerified: false,
      temporalClaimsVerified: false,
      exactClaimsVerified: false,
      oidcVerifications: [],
      operatorSecretBodyPresent: false,
      operatorSecretActionAttempted: false,
      operatorSecretActionAuthorized: false,
      operatorSecretActions: [],
      receiptId: "rt37f_ABCDEFGHIJKLMNOPQRSTUVWX",
      rawOidcTokenRetained: false,
      rawRequestBodyRetained: false,
      rawOperatorSecretRetained: false,
      rawOperatorSecretReflected: false,
      responseBodyContainedSecret: false,
      derivedSecretDigestRetained: false,
      terminalResponse: true,
      redirectAttempted: false,
      fetchAttempted: false,
      proxyAttempted: false,
      locationHeaderPresent: false,
      responseStatus: 404,
    } satisfies IngressFallbackRecord;
    const mapped = fallbackEvent(record);
    expect(mapped).toEqual(record);
    expect(mapped).not.toHaveProperty("bodyLength");
    expect(mapped).not.toHaveProperty("receiverOrigin");
    expect(mapped).not.toHaveProperty("operationId");
    expect(fallbackEvent(undefined)).toBeUndefined();
  });
});
