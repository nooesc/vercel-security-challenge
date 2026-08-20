import { request as httpRequest } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import {
  actionOperationId,
  createSbx037Receiver,
  exactAudienceClaim,
  vercelOidcIssuer,
  type ReceiverConfiguration,
  type ReceiverHandle,
} from "../pocs/SBX-037/receiver.js";

const adminKey = "admin-key-".padEnd(40, "a");
const actionKey = "action-key-".padEnd(40, "b");
const aOrigin = "https://a-owned.example.test";
const pOrigin = "https://p-owned.example.test";
const bOrigin = "https://b-owned.example.test";
const runId = "run-037-local";
const operatorSecret = "owned-file-secret-".padEnd(48, "s");

const correlations = {
  directBAllow: "corr_direct_allow",
  directBPre: "corr_direct_pre",
  directBPost: "corr_direct_post",
  originFormTerminal: "corr_origin_terminal",
  absoluteSyntaxControl: "corr_absolute_syntax",
  networkPathSyntaxControl: "corr_network_syntax",
  absolutePSyntaxControl: "corr_absolute_p_syntax",
  networkPSyntaxControl: "corr_network_p_syntax",
  absoluteTargetAttack: "corr_absolute_attack",
  networkPathTargetAttack: "corr_network_attack",
};

const receipts = {
  initial: `rt37r_${"i".repeat(24)}`,
  origin: `rt37r_${"o".repeat(24)}`,
  syntaxAbsolute: `rt37r_${"s".repeat(24)}`,
  syntaxNetwork: `rt37r_${"t".repeat(24)}`,
  pSyntaxAbsolute: `rt37r_${"u".repeat(24)}`,
  pSyntaxNetwork: `rt37r_${"v".repeat(24)}`,
  absolute: `rt37r_${"a".repeat(24)}`,
  network: `rt37r_${"n".repeat(24)}`,
};

const handles: ReceiverHandle[] = [];

afterEach(async () => {
  await Promise.all(handles.splice(0).map(async (handle) => handle.close()));
});

function configuration(): ReceiverConfiguration {
  return {
    runId,
    aOrigin,
    pOrigin,
    bOrigin,
    forwardAudience: new URL(`/v1/sbx037/forward/${runId}`, pOrigin).toString(),
    expectedTeamId: "team_test",
    expectedProjectId: "project_test",
    expectedSandboxId: "sbx_test_session",
    expectedSandboxName: "sbx-037-local",
    caseCorrelations: correlations,
    initialBOperationId: receipts.initial,
    originOperationId: receipts.origin,
    syntaxOperationIds: {
      absoluteSyntaxControl: receipts.syntaxAbsolute,
      networkPathSyntaxControl: receipts.syntaxNetwork,
      absolutePSyntaxControl: receipts.pSyntaxAbsolute,
      networkPSyntaxControl: receipts.pSyntaxNetwork,
    },
    caseOperationIds: {
      absoluteTargetAttack: receipts.absolute,
      networkPathTargetAttack: receipts.network,
    },
    expectedActionOperationIds: {
      absoluteTargetAttack: actionOperationId(actionKey, runId, "absolute-target-attack", operatorSecret),
      networkPathTargetAttack: actionOperationId(actionKey, runId, "network-path-target-attack", operatorSecret),
    },
  };
}

async function receiver(): Promise<ReceiverHandle> {
  const handle = await createSbx037Receiver({
    adminKey,
    actionKey,
    aPublicOrigin: aOrigin,
    pPublicOrigin: pOrigin,
    bPublicOrigin: bOrigin,
  });
  handles.push(handle);
  return handle;
}

function localP(handle: ReceiverHandle): string {
  return `http://127.0.0.1:${handle.pPort}`;
}

function localA(handle: ReceiverHandle): string {
  return `http://127.0.0.1:${handle.aPort}`;
}

function localB(handle: ReceiverHandle): string {
  return `http://127.0.0.1:${handle.bPort}`;
}

function adminUrl(handle: ReceiverHandle): string {
  return `${localP(handle)}/v1/sbx037/admin/runs/${runId}`;
}

const adminHeaders = { Authorization: `Bearer ${adminKey}` };

async function register(handle: ReceiverHandle, value: unknown = configuration()): Promise<Response> {
  return await fetch(adminUrl(handle), {
    method: "POST",
    headers: { ...adminHeaders, "Content-Type": "application/json" },
    body: JSON.stringify(value),
  });
}

async function readback(handle: ReceiverHandle): Promise<{ text: string; value: Record<string, unknown> }> {
  const response = await fetch(adminUrl(handle), { headers: adminHeaders });
  const text = await response.text();
  expect(response.status).toBe(200);
  return { text, value: JSON.parse(text) as Record<string, unknown> };
}

function correlatedHeaders(caseId: string): Record<string, string> {
  const correlation = caseId === "direct-b-allow" ? correlations.directBAllow
    : caseId === "direct-b-pre" ? correlations.directBPre
      : caseId === "direct-b-post" ? correlations.directBPost
        : caseId === "origin-form-terminal" ? correlations.originFormTerminal
          : caseId === "absolute-syntax-control" ? correlations.absoluteSyntaxControl
            : caseId === "network-path-syntax-control" ? correlations.networkPathSyntaxControl
              : caseId === "absolute-p-syntax-control" ? correlations.absolutePSyntaxControl
                : caseId === "network-p-syntax-control" ? correlations.networkPSyntaxControl
                  : caseId === "absolute-target-attack" ? correlations.absoluteTargetAttack
                    : correlations.networkPathTargetAttack;
  return {
    "x-sbx037-run": runId,
    "x-sbx037-case": caseId,
    "x-sbx-harness-canary": correlation,
    "content-type": "application/octet-stream",
  };
}

function forwardedPath(caseId: "origin-form-terminal" | "absolute-target-attack" | "network-path-target-attack"): string {
  return caseId === "origin-form-terminal"
    ? `/v1/sbx037/origin/${runId}`
    : `/v1/sbx037/collect/${runId}`;
}

function forwardedHeaders(
  caseId: "origin-form-terminal" | "absolute-target-attack" | "network-path-target-attack",
): Record<string, string> {
  return {
    ...correlatedHeaders(caseId),
    "vercel-forwarded-host": new URL(aOrigin).host,
    "vercel-forwarded-scheme": "https",
    "vercel-forwarded-port": "443",
    "vercel-forwarded-path": forwardedPath(caseId),
  };
}

function localForwardUrl(
  handle: ReceiverHandle,
  caseId: "origin-form-terminal" | "absolute-target-attack" | "network-path-target-attack",
): string {
  return `${localP(handle)}/v1/sbx037/forward/${runId}${forwardedPath(caseId)}`;
}

function localJwt(issuer: string): string {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "local-only" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ iss: issuer })).toString("base64url");
  return `${header}.${payload}.AA`;
}

function publicBodyFor(caseId: string): string {
  return `public:${correlatedHeaders(caseId)["x-sbx-harness-canary"]}`;
}

async function rawRequest(
  port: number,
  target: string,
  caseId: string,
  body?: string,
  hostOrigin = aOrigin,
  additionalHeaders: Record<string, string> = {},
): Promise<{ status: number; body: string; role?: string }> {
  const requestBody = body ?? publicBodyFor(caseId);
  return await new Promise((resolve, reject) => {
    const request = httpRequest({
      hostname: "127.0.0.1",
      port,
      method: "POST",
      path: target,
      headers: {
        ...correlatedHeaders(caseId),
        ...additionalHeaders,
        Host: new URL(hostOrigin).hostname,
        Connection: "close",
        "Content-Length": Buffer.byteLength(requestBody),
      },
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      response.on("end", () => resolve({
        status: response.statusCode ?? 0,
        body: Buffer.concat(chunks).toString("utf8"),
        ...(typeof response.headers["x-sbx-role"] === "string"
          ? { role: response.headers["x-sbx-role"] } : {}),
      }));
    });
    request.once("error", reject);
    request.end(requestBody);
  });
}

describe("SBX-037 receiver primitives", () => {
  it("derives case-bound action receipts and requires exact JWT audiences", () => {
    const absolute = actionOperationId(actionKey, runId, "absolute-target-attack", operatorSecret);
    const network = actionOperationId(actionKey, runId, "network-path-target-attack", operatorSecret);
    expect(absolute).toMatch(/^rt37a_[A-Za-z0-9_-]{24}$/u);
    expect(network).toMatch(/^rt37a_[A-Za-z0-9_-]{24}$/u);
    expect(network).not.toBe(absolute);

    const audience = configuration().forwardAudience;
    expect(exactAudienceClaim(audience, audience)).toBe(true);
    expect(exactAudienceClaim([audience], audience)).toBe(true);
    expect(exactAudienceClaim([audience, "https://elsewhere.example.test/"], audience)).toBe(false);
    expect(exactAudienceClaim("https://elsewhere.example.test/", audience)).toBe(false);
  });

  it("derives issuer-scoped JWKS URLs and rejects unsafe Vercel issuer lookalikes", () => {
    expect(vercelOidcIssuer("https://oidc.vercel.com")).toEqual({
      issuer: "https://oidc.vercel.com",
      jwksUrl: "https://oidc.vercel.com/.well-known/jwks",
    });
    expect(vercelOidcIssuer("https://oidc.vercel.com/team_example")).toEqual({
      issuer: "https://oidc.vercel.com/team_example",
      jwksUrl: "https://oidc.vercel.com/team_example/.well-known/jwks",
    });
    expect(vercelOidcIssuer("https://oidc.vercel.com/team_example/")).toEqual({
      issuer: "https://oidc.vercel.com/team_example/",
      jwksUrl: "https://oidc.vercel.com/team_example/.well-known/jwks",
    });
    for (const unsafe of [
      "http://oidc.vercel.com/team",
      "https://oidc.vercel.com.evil.example/team",
      "https://evil.example/oidc.vercel.com",
      "https://user@oidc.vercel.com/team",
      "https://oidc.vercel.com:8443/team",
      "https://oidc.vercel.com/team?redirect=evil",
      "https://oidc.vercel.com/team#fragment",
    ]) {
      expect(() => vercelOidcIssuer(unsafe)).toThrow();
    }
  });

  it("rejects weak keys, unsafe origins, and non-loopback binding", async () => {
    await expect(createSbx037Receiver({
      adminKey: "short",
      actionKey,
      aPublicOrigin: aOrigin,
      pPublicOrigin: pOrigin,
      bPublicOrigin: bOrigin,
    })).rejects.toThrow(/adminKey/u);
    await expect(createSbx037Receiver({
      adminKey,
      actionKey,
      aPublicOrigin: aOrigin,
      pPublicOrigin: aOrigin,
      bPublicOrigin: bOrigin,
    })).rejects.toThrow(/distinct/u);
    await expect(createSbx037Receiver({
      adminKey,
      actionKey,
      aPublicOrigin: aOrigin,
      pPublicOrigin: pOrigin,
      bPublicOrigin: bOrigin,
      host: "0.0.0.0",
    })).rejects.toThrow(/loopback/u);
    await expect(createSbx037Receiver({
      adminKey,
      actionKey: adminKey,
      aPublicOrigin: aOrigin,
      pPublicOrigin: pOrigin,
      bPublicOrigin: bOrigin,
    })).rejects.toThrow(/distinct/u);
  });
});

describe("SBX-037 three-role receiver", () => {
  it("provides role health, timing-safe admin authorization, secret-free readback, and deletion", async () => {
    const handle = await receiver();
    const healthResponses = await Promise.all([
      fetch(`http://127.0.0.1:${handle.aPort}/healthz`),
      fetch(`http://127.0.0.1:${handle.pPort}/healthz`),
      fetch(`http://127.0.0.1:${handle.bPort}/healthz`),
    ]);
    expect(healthResponses.map((response) => response.headers.get("x-sbx-role"))).toEqual(["A", "P", "B"]);
    const roles = await Promise.all(healthResponses.map(async (response) => await response.json()));
    expect(roles).toEqual([{ ok: true, role: "A" }, { ok: true, role: "P" }, { ok: true, role: "B" }]);

    const unauthorized = await fetch(adminUrl(handle), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(configuration()),
    });
    expect(unauthorized.status).toBe(401);
    expect(unauthorized.headers.get("x-sbx-role")).toBe("P");
    expect((await register(handle)).status).toBe(201);
    expect((await register(handle)).status).toBe(409);

    const state = await readback(handle);
    expect(state.value).toMatchObject({
      configured: true,
      aRecords: [],
      pSyntaxRecords: [],
      pRecords: [],
      bRecords: [],
      directRecords: [],
      fallbackRecords: [],
      terminalInvariant: {
        redirectsIssued: 0,
        locationHeadersIssued: 0,
        applicationFetches: 0,
        applicationProxyAttempts: 0,
        rawOidcTokensRetained: false,
        rawRequestBodiesRetained: false,
        failedSecretDerivationsRetained: false,
      },
    });
    expect(state.text).not.toContain(operatorSecret);
    expect(state.text).not.toContain(actionKey);
    expect(state.text).not.toContain(configuration().expectedActionOperationIds.absoluteTargetAttack);
    expect(state.text).not.toContain(configuration().expectedActionOperationIds.networkPathTargetAttack);

    const deleted = await fetch(adminUrl(handle), { method: "DELETE", headers: adminHeaders });
    expect(deleted.status).toBe(200);
    expect(await deleted.json()).toEqual({ deleted: true });
    expect((await fetch(adminUrl(handle), { headers: adminHeaders })).status).toBe(404);
  });

  it("records sanitized exact-envelope fallback diagnostics at A, P, and B", async () => {
    const handle = await receiver();
    expect((await register(handle)).status).toBe(201);
    const fakeToken = localJwt("https://evil.example");
    const attackHeaders = correlatedHeaders("absolute-target-attack");

    const atA = await fetch(`${localA(handle)}/blind-a`, {
      method: "POST",
      headers: { ...attackHeaders, Host: new URL(aOrigin).host },
      body: operatorSecret,
    });
    const atP = await fetch(`${localP(handle)}/blind-p`, {
      method: "POST",
      headers: {
        ...forwardedHeaders("absolute-target-attack"),
        Host: new URL(pOrigin).host,
        "vercel-sandbox-oidc-token": fakeToken,
      },
      body: operatorSecret,
    });
    const atB = await fetch(`${localB(handle)}/blind-b`, {
      method: "POST",
      headers: { ...attackHeaders, Host: new URL(bOrigin).host },
      body: operatorSecret,
    });

    const fallbackReceipts = [atA, atP, atB].map((response) => {
      expect(response.status).toBe(404);
      const receipt = response.headers.get("x-sbx037-fallback-receipt");
      expect(receipt).toMatch(/^rt37f_[A-Za-z0-9_-]{24}$/u);
      return receipt;
    });
    expect(new Set(fallbackReceipts).size).toBe(3);
    expect(atA.headers.get("x-sbx-role")).toBe("A");
    expect(atP.headers.get("x-sbx-role")).toBe("P");
    expect(atB.headers.get("x-sbx-role")).toBe("B");
    expect(await atA.text()).toBe("");
    expect(await atP.text()).toBe("");
    expect(await atB.text()).toBe("");

    const state = await readback(handle);
    expect(state.text).not.toContain(operatorSecret);
    expect(state.text).not.toContain(fakeToken);
    expect(state.text).not.toContain(actionKey);
    const parsed = state.value as { fallbackRecords: Array<Record<string, unknown>> };
    expect(parsed.fallbackRecords).toHaveLength(3);
    expect(parsed.fallbackRecords[0]).toEqual(expect.objectContaining({
      role: "A",
      reason: "unmatched-a-route",
      caseId: "absolute-target-attack",
      correlationMatched: true,
      method: "POST",
      requestTarget: "/blind-a",
      host: new URL(localA(handle)).host,
      oidcHeaderCount: 0,
      oidcValueCount: 0,
      operatorSecretBodyPresent: false,
      operatorSecretActionAttempted: false,
      operatorSecretActionAuthorized: false,
      operatorSecretActions: [],
      receiptId: fallbackReceipts[0],
      responseStatus: 404,
    }));
    expect(parsed.fallbackRecords[1]).toEqual(expect.objectContaining({
      role: "P",
      reason: "unmatched-forward-path",
      requestTarget: "/blind-p",
      host: new URL(localP(handle)).host,
      forwardedHeaderCounts: {
        host: { lines: 1, values: 1 },
        scheme: { lines: 1, values: 1 },
        port: { lines: 1, values: 1 },
        path: { lines: 1, values: 1 },
      },
      oidcHeaderCount: 1,
      oidcValueCount: 1,
      tokenVerified: false,
      oidcVerifications: [],
      receiptId: fallbackReceipts[1],
    }));
    const actionId = configuration().expectedActionOperationIds.absoluteTargetAttack;
    expect(parsed.fallbackRecords[2]).toEqual(expect.objectContaining({
      role: "B",
      reason: "unmatched-collect-path",
      requestTarget: "/blind-b",
      host: new URL(localB(handle)).host,
      operatorSecretBodyPresent: true,
      operatorSecretActionAttempted: true,
      operatorSecretActionAuthorized: true,
      actionOperationId: actionId,
      operatorSecretActions: [expect.objectContaining({
        verifier: "observer-b-independent-file-hmac",
        operationId: actionId,
        hmacVerified: true,
        actionAuthorized: true,
        nonReflecting: true,
        rawSecretRetained: false,
        rawSecretReflected: false,
        responseBodyContainedSecret: false,
      })],
      receiptId: fallbackReceipts[2],
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
    }));
    for (const record of parsed.fallbackRecords) expect(record).not.toHaveProperty("bodyLength");
  });

  it("retains only public fallback body length and ignores non-exact correlation envelopes", async () => {
    const handle = await receiver();
    expect((await register(handle)).status).toBe(201);
    const caseId = "network-path-syntax-control";
    const publicBody = publicBodyFor(caseId);
    const publicFallback = await fetch(`${localB(handle)}/wrong-collect-path`, {
      method: "POST",
      headers: { ...correlatedHeaders(caseId), Host: new URL(bOrigin).host },
      body: publicBody,
    });
    expect(publicFallback.status).toBe(404);
    expect(publicFallback.headers.get("x-sbx-role")).toBe("B");
    expect(publicFallback.headers.get("x-sbx037-fallback-receipt")).toMatch(/^rt37f_/u);

    const duplicateCorrelation = await new Promise<{ status: number; role?: string; receipt?: string }>((resolve, reject) => {
      const body = Buffer.from(operatorSecret);
      const request = httpRequest({
        hostname: "127.0.0.1",
        port: handle.pPort,
        method: "POST",
        path: "/duplicate-correlation",
        headers: [
          "Host", new URL(pOrigin).host,
          "Content-Length", String(body.length),
          "X-SBX037-Run", runId,
          "X-SBX037-Case", "absolute-target-attack",
          "X-SBX-Harness-Canary", correlations.absoluteTargetAttack,
          "X-SBX-Harness-Canary", correlations.absoluteTargetAttack,
          "Connection", "close",
        ],
      }, (response) => {
        response.resume();
        response.once("end", () => resolve({
          status: response.statusCode ?? 0,
          ...(typeof response.headers["x-sbx-role"] === "string"
            ? { role: response.headers["x-sbx-role"] } : {}),
          ...(typeof response.headers["x-sbx037-fallback-receipt"] === "string"
            ? { receipt: response.headers["x-sbx037-fallback-receipt"] } : {}),
        }));
      });
      request.once("error", reject);
      request.end(body);
    });
    expect(duplicateCorrelation).toEqual({ status: 404, role: "P" });

    const state = await readback(handle);
    expect(state.text).not.toContain(publicBody);
    const parsed = state.value as { fallbackRecords: Array<Record<string, unknown>> };
    expect(parsed.fallbackRecords).toEqual([
      expect.objectContaining({
        role: "B",
        reason: "unmatched-collect-path",
        caseId,
        bodyLength: Buffer.byteLength(publicBody),
        operatorSecretActionAttempted: false,
        operatorSecretActions: [],
      }),
    ]);
  });

  it("caps retained fallback diagnostics per run", async () => {
    const handle = await receiver();
    expect((await register(handle)).status).toBe(201);
    const caseId = "network-path-syntax-control";
    const responses = [];
    for (let index = 0; index < 18; index += 1) {
      responses.push(await fetch(`${localB(handle)}/bounded-fallback-${index}`, {
        method: "POST",
        headers: correlatedHeaders(caseId),
        body: publicBodyFor(caseId),
      }));
    }
    expect(responses.every((response) => response.status === 404)).toBe(true);
    expect(responses.every((response) => response.headers.get("x-sbx-role") === "B")).toBe(true);
    expect(new Set(responses.map((response) => response.headers.get("x-sbx037-fallback-receipt"))).size).toBe(18);
    const parsed = (await readback(handle)).value as { fallbackRecords: Array<{ receiptId: string }> };
    expect(parsed.fallbackRecords).toHaveLength(16);
    expect(new Set(parsed.fallbackRecords.map((record) => record.receiptId)).size).toBe(16);
  });

  it.each([
    ["extra top-level config field", (base: ReceiverConfiguration) => ({ ...base, extra: true })],
    ["mismatched origin", (base: ReceiverConfiguration) => ({ ...base, bOrigin: "https://other-owned.example.test" })],
    ["non-exact forward audience", (base: ReceiverConfiguration) => ({ ...base, forwardAudience: `${base.forwardAudience}/extra` })],
    ["duplicate public receipt", (base: ReceiverConfiguration) => ({
      ...base,
      caseOperationIds: { ...base.caseOperationIds, networkPathTargetAttack: base.caseOperationIds.absoluteTargetAttack },
    })],
    ["duplicate case correlation", (base: ReceiverConfiguration) => ({
      ...base,
      caseCorrelations: { ...base.caseCorrelations, directBPost: base.caseCorrelations.directBPre },
    })],
    ["extra nested operation field", (base: ReceiverConfiguration) => ({
      ...base,
      expectedActionOperationIds: { ...base.expectedActionOperationIds, extra: `rt37a_${"x".repeat(24)}` },
    })],
  ])("rejects %s", async (_name, mutate) => {
    const handle = await receiver();
    const response = await register(handle, mutate(configuration()));
    expect(response.status).toBe(400);
    expect((await fetch(adminUrl(handle), { headers: adminHeaders })).status).toBe(404);
  });

  it("records exact absolute-form and network-path syntax controls at A", async () => {
    const handle = await receiver();
    expect((await register(handle)).status).toBe(201);
    const collectPath = `/v1/sbx037/collect/${runId}`;

    const absolute = await rawRequest(
      handle.aPort,
      `${bOrigin}${collectPath}`,
      "absolute-syntax-control",
    );
    expect(absolute).toEqual({
      status: 202,
      body: JSON.stringify({ operationId: receipts.syntaxAbsolute }),
      role: "A",
    });

    const network = await rawRequest(
      handle.aPort,
      `//${new URL(bOrigin).host}${collectPath}`,
      "network-path-syntax-control",
    );
    expect(network).toEqual({
      status: 202,
      body: JSON.stringify({ operationId: receipts.syntaxNetwork }),
      role: "A",
    });

    const state = (await readback(handle)).value as {
      aRecords: Array<Record<string, unknown>>;
      bRecords: unknown[];
    };
    expect(state.aRecords).toEqual([
      expect.objectContaining({
        caseId: "absolute-syntax-control",
        targetForm: "absolute",
        exactSyntaxTarget: true,
        publicBodyMatched: true,
        operationId: receipts.syntaxAbsolute,
        responseStatus: 202,
      }),
      expect.objectContaining({
        caseId: "network-path-syntax-control",
        targetForm: "network-path",
        exactSyntaxTarget: true,
        publicBodyMatched: true,
        operationId: receipts.syntaxNetwork,
        responseStatus: 202,
      }),
    ]);
    expect(state.bRecords).toEqual([]);
  });

  it("records exact direct-P absolute and network syntax controls separately from authenticated forwarding", async () => {
    const handle = await receiver();
    expect((await register(handle)).status).toBe(201);
    const collectPath = `/v1/sbx037/collect/${runId}`;

    const absolute = await rawRequest(
      handle.pPort,
      `${bOrigin}${collectPath}`,
      "absolute-p-syntax-control",
      undefined,
      pOrigin,
    );
    expect(absolute).toEqual({
      status: 202,
      body: JSON.stringify({ operationId: receipts.pSyntaxAbsolute }),
      role: "P",
    });

    const network = await rawRequest(
      handle.pPort,
      `//${new URL(bOrigin).host}${collectPath}`,
      "network-p-syntax-control",
      undefined,
      pOrigin,
    );
    expect(network).toEqual({
      status: 202,
      body: JSON.stringify({ operationId: receipts.pSyntaxNetwork }),
      role: "P",
    });

    const state = (await readback(handle)).value as {
      pSyntaxRecords: Array<Record<string, unknown>>;
      pRecords: unknown[];
    };
    expect(state.pSyntaxRecords).toEqual([
      expect.objectContaining({
        caseId: "absolute-p-syntax-control",
        targetForm: "absolute",
        rawTarget: `${bOrigin}${collectPath}`,
        exactSyntaxTarget: true,
        hostMatched: true,
        publicBodyMatched: true,
        oidcHeaderCount: 0,
        forwardedMetadataAbsent: true,
        operationId: receipts.pSyntaxAbsolute,
        terminalResponse: true,
        redirectAttempted: false,
        fetchAttempted: false,
        proxyAttempted: false,
        locationHeaderPresent: false,
        responseStatus: 202,
      }),
      expect.objectContaining({
        caseId: "network-p-syntax-control",
        targetForm: "network-path",
        rawTarget: `//${new URL(bOrigin).host}${collectPath}`,
        exactSyntaxTarget: true,
        hostMatched: true,
        publicBodyMatched: true,
        oidcHeaderCount: 0,
        forwardedMetadataAbsent: true,
        operationId: receipts.pSyntaxNetwork,
        responseStatus: 202,
      }),
    ]);
    expect(state.pRecords).toEqual([]);
  });

  it("refuses direct-P syntax receipts for a wrong target, public body, OIDC, or forwarded metadata", async () => {
    const handle = await receiver();
    expect((await register(handle)).status).toBe(201);
    const collectPath = `/v1/sbx037/collect/${runId}`;
    const target = `${bOrigin}${collectPath}`;
    expect((await rawRequest(
      handle.pPort,
      `${bOrigin}/v1/sbx037/collect/wrong-run`,
      "absolute-p-syntax-control",
      undefined,
      pOrigin,
    )).status).toBe(400);
    expect((await rawRequest(
      handle.pPort,
      target,
      "absolute-p-syntax-control",
      "wrong-public-body",
      pOrigin,
    )).status).toBe(400);
    expect((await rawRequest(
      handle.pPort,
      target,
      "absolute-p-syntax-control",
      undefined,
      pOrigin,
      { "vercel-sandbox-oidc-token": "not.a.valid-token" },
    )).status).toBe(400);
    expect((await rawRequest(
      handle.pPort,
      target,
      "absolute-p-syntax-control",
      undefined,
      pOrigin,
      { "vercel-forwarded-host": new URL(aOrigin).host },
    )).status).toBe(400);
    expect((await rawRequest(
      handle.pPort,
      target,
      "absolute-p-syntax-control",
      undefined,
      aOrigin,
    )).status).toBe(400);
    expect((await rawRequest(
      handle.pPort,
      target,
      "absolute-p-syntax-control",
      undefined,
      pOrigin,
      { "x-sbx-harness-canary": "corr_wrong_p_syntax" },
    )).status).toBe(400);

    const state = await readback(handle);
    expect(state.text).not.toContain("not.a.valid-token");
    const parsed = state.value as { pSyntaxRecords: Array<Record<string, unknown>>; pRecords: unknown[] };
    expect(parsed.pSyntaxRecords).toHaveLength(6);
    expect(parsed.pSyntaxRecords.every((record) => record.responseStatus === 400)).toBe(true);
    expect(parsed.pSyntaxRecords.every((record) => !Object.hasOwn(record, "operationId"))).toBe(true);
    expect(parsed.pSyntaxRecords[0]).toEqual(expect.objectContaining({ exactSyntaxTarget: false }));
    expect(parsed.pSyntaxRecords[1]).toEqual(expect.objectContaining({ publicBodyMatched: false }));
    expect(parsed.pSyntaxRecords[2]).toEqual(expect.objectContaining({ oidcHeaderCount: 1 }));
    expect(parsed.pSyntaxRecords[3]).toEqual(expect.objectContaining({ forwardedMetadataAbsent: false }));
    expect(parsed.pSyntaxRecords[4]).toEqual(expect.objectContaining({ hostMatched: false }));
    expect(parsed.pSyntaxRecords[5]).toEqual(expect.objectContaining({ correlationMatched: false }));
    expect(parsed.pRecords).toEqual([]);
  });

  it("keeps P terminal on invalid authentication without invoking a JWKS request", async () => {
    const handle = await receiver();
    expect((await register(handle)).status).toBe(201);
    const fakeToken = "not.a.valid-platform-token";
    const response = await fetch(localForwardUrl(handle, "origin-form-terminal"), {
      method: "POST",
      headers: {
        ...forwardedHeaders("origin-form-terminal"),
        "vercel-sandbox-oidc-token": fakeToken,
      },
      body: publicBodyFor("origin-form-terminal"),
    });
    expect(response.status).toBe(403);
    expect(response.headers.has("location")).toBe(false);
    expect(await response.json()).toEqual({ accepted: false });

    const state = await readback(handle);
    expect(state.text).not.toContain(fakeToken);
    const parsed = state.value as { pRecords: Array<Record<string, unknown>> };
    expect(parsed.pRecords).toEqual([
      expect.objectContaining({
        caseId: "origin-form-terminal",
        correlationMatched: true,
        publicBodyMatched: true,
        requestUrl: new URL(localForwardUrl(handle, "origin-form-terminal")).toString()
          .replace(localP(handle), pOrigin),
        forwardedMetadataValid: true,
        tokenVerified: false,
        oidcHeaderCount: 1,
        oidcVerifications: [],
        terminalResponse: true,
        redirectAttempted: false,
        fetchAttempted: false,
        proxyAttempted: false,
        locationHeaderPresent: false,
        rawOidcTokenRetained: false,
        rawRequestBodyRetained: false,
        responseStatus: 403,
      }),
    ]);
  });

  it("rejects the bare P base and every non-exact appended guest path without recording a terminal event", async () => {
    const handle = await receiver();
    expect((await register(handle)).status).toBe(201);
    const baseOnly = await fetch(`${localP(handle)}/v1/sbx037/forward/${runId}`, {
      method: "POST",
      headers: forwardedHeaders("origin-form-terminal"),
      body: publicBodyFor("origin-form-terminal"),
    });
    expect(baseOnly.status).toBe(404);
    const mismatched = await fetch(
      `${localP(handle)}/v1/sbx037/forward/${runId}/v1/sbx037/collect/${runId}`,
      {
        method: "POST",
        headers: forwardedHeaders("origin-form-terminal"),
        body: publicBodyFor("origin-form-terminal"),
      },
    );
    expect(mismatched.status).toBe(404);
    const parsed = (await readback(handle)).value as { pRecords: unknown[] };
    expect(parsed.pRecords).toEqual([]);
  });

  it("requires exact single forwarded host, scheme, port, and path metadata before authentication", async () => {
    const handle = await receiver();
    expect((await register(handle)).status).toBe(201);
    const badPath = await fetch(localForwardUrl(handle, "origin-form-terminal"), {
      method: "POST",
      headers: {
        ...forwardedHeaders("origin-form-terminal"),
        "vercel-forwarded-path": `/v1/sbx037/collect/${runId}`,
        "vercel-sandbox-oidc-token": localJwt("https://evil.example"),
      },
      body: publicBodyFor("origin-form-terminal"),
    });
    expect(badPath.status).toBe(400);

    const duplicateHost = await fetch(localForwardUrl(handle, "origin-form-terminal"), {
      method: "POST",
      headers: {
        ...forwardedHeaders("origin-form-terminal"),
        "vercel-forwarded-host": `${new URL(aOrigin).host},${new URL(aOrigin).host}`,
        "vercel-sandbox-oidc-token": localJwt("https://evil.example"),
      },
      body: publicBodyFor("origin-form-terminal"),
    });
    expect(duplicateHost.status).toBe(400);

    const parsed = (await readback(handle)).value as { pRecords: Array<Record<string, unknown>> };
    expect(parsed.pRecords).toHaveLength(2);
    for (const record of parsed.pRecords) {
      expect(record).toEqual(expect.objectContaining({ forwardedMetadataValid: false, tokenVerified: false }));
      expect(record).not.toHaveProperty("operationId");
    }
  });

  it("rejects an unsafe decoded issuer locally before attempting a JWKS lookup", async () => {
    const handle = await receiver();
    expect((await register(handle)).status).toBe(201);
    const unsafeToken = localJwt("https://evil.example/oidc.vercel.com");
    const response = await fetch(localForwardUrl(handle, "origin-form-terminal"), {
      method: "POST",
      headers: {
        ...forwardedHeaders("origin-form-terminal"),
        "vercel-sandbox-oidc-token": unsafeToken,
      },
      body: publicBodyFor("origin-form-terminal"),
    });
    expect(response.status).toBe(403);
    const state = await readback(handle);
    expect(state.text).not.toContain(unsafeToken);
    const parsed = state.value as { pRecords: Array<Record<string, unknown>> };
    expect(parsed.pRecords).toEqual([
      expect.objectContaining({
        forwardedMetadataValid: true,
        tokenVerified: false,
        algorithmRs256: true,
        issuerVerified: false,
        oidcVerifications: [],
        responseStatus: 403,
      }),
    ]);
    expect(parsed.pRecords[0]).not.toHaveProperty("operationId");
  });

  it.each(["absolute-target-attack", "network-path-target-attack"] as const)(
    "accepts only the exact appended collect path and metadata envelope for %s",
    async (caseId) => {
      const handle = await receiver();
      expect((await register(handle)).status).toBe(201);
      const response = await fetch(localForwardUrl(handle, caseId), {
        method: "POST",
        headers: {
          ...forwardedHeaders(caseId),
          "vercel-sandbox-oidc-token": localJwt("https://evil.example"),
        },
        body: operatorSecret,
      });
      expect(response.status).toBe(403);
      const parsed = (await readback(handle)).value as { pRecords: Array<Record<string, unknown>> };
      expect(parsed.pRecords).toEqual([
        expect.objectContaining({
          caseId,
          requestUrl: new URL(localForwardUrl(handle, caseId)).toString().replace(localP(handle), pOrigin),
          forwardedMetadataValid: true,
          operatorSecretBodyPresent: true,
          tokenVerified: false,
          responseStatus: 403,
        }),
      ]);
      expect(parsed.pRecords[0]).not.toHaveProperty("bodyLength");
      expect(parsed.pRecords[0]).not.toHaveProperty("operationId");
    },
  );

  it("classifies a syntax control arriving at B without token or secret action", async () => {
    const handle = await receiver();
    expect((await register(handle)).status).toBe(201);
    const response = await fetch(`${localB(handle)}/v1/sbx037/collect/${runId}`, {
      method: "POST",
      headers: correlatedHeaders("network-path-syntax-control"),
      body: publicBodyFor("network-path-syntax-control"),
    });
    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({ operationId: receipts.syntaxNetwork });

    const parsed = (await readback(handle)).value as { bRecords: Array<Record<string, unknown>> };
    expect(parsed.bRecords).toEqual([
      expect.objectContaining({
        caseId: "network-path-syntax-control",
        syntaxControl: true,
        attackCase: false,
        publicBodyMatched: true,
        operatorSecretBodyPresent: false,
        operatorSecretActions: [],
        oidcHeaderCount: 0,
        operationId: receipts.syntaxNetwork,
        responseStatus: 202,
      }),
    ]);
    expect(parsed.bRecords[0]).not.toHaveProperty("targetForm");
    expect(parsed.bRecords[0]).not.toHaveProperty("rawRequestTarget");
    expect(parsed.bRecords[0]).not.toHaveProperty("attributableToRequestTarget");
  });

  it("records an initial direct-B control with its public receipt", async () => {
    const handle = await receiver();
    expect((await register(handle)).status).toBe(201);
    const response = await fetch(`${localB(handle)}/v1/sbx037/direct/${runId}`, {
      method: "POST",
      headers: correlatedHeaders("direct-b-allow"),
      body: publicBodyFor("direct-b-allow"),
    });
    expect(response.status).toBe(202);
    expect(response.headers.get("x-sbx-role")).toBe("B");
    expect(await response.json()).toEqual({ operationId: receipts.initial });
    const parsed = (await readback(handle)).value as { directRecords: Array<Record<string, unknown>> };
    expect(parsed.directRecords).toEqual([
      expect.objectContaining({
        caseId: "direct-b-allow",
        correlationMatched: true,
        publicBodyMatched: true,
        operationId: receipts.initial,
        responseStatus: 202,
      }),
    ]);
  });

  it("authorizes only an exact secret action while returning a separate public reachability receipt", async () => {
    const handle = await receiver();
    expect((await register(handle)).status).toBe(201);
    const actionId = configuration().expectedActionOperationIds.absoluteTargetAttack;
    const response = await fetch(`${localB(handle)}/v1/sbx037/collect/${runId}`, {
      method: "POST",
      headers: correlatedHeaders("absolute-target-attack"),
      body: operatorSecret,
    });
    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({ operationId: receipts.absolute });

    const state = await readback(handle);
    expect(state.text).not.toContain(operatorSecret);
    expect(state.text).not.toContain(actionKey);
    const parsed = state.value as { bRecords: Array<Record<string, unknown>> };
    expect(parsed.bRecords).toEqual([
      expect.objectContaining({
        caseId: "absolute-target-attack",
        correlationMatched: true,
        reachabilityObserved: true,
        operatorSecretBodyPresent: true,
        operatorSecretActionAttempted: true,
        operatorSecretActionAuthorized: true,
        operationId: receipts.absolute,
        operatorSecretActions: [{
          actionOrdinal: 1,
          verifier: "observer-b-independent-file-hmac",
          algorithm: "HMAC-SHA256",
          secretSource: "controller-file-mode-0600",
          secretFileMode: 384,
          hmacVerified: true,
          actionAuthorized: true,
          operationId: actionId,
          nonReflecting: true,
          rawSecretRetained: false,
          rawSecretReflected: false,
          responseBodyContainedSecret: false,
        }],
        tokenVerified: false,
        rawOidcTokenRetained: false,
        rawRequestBodyRetained: false,
        derivedSecretDigestRetained: false,
        responseStatus: 202,
      }),
    ]);
    expect(parsed.bRecords[0]).not.toHaveProperty("bodyLength");
    expect(parsed.bRecords[0]).not.toHaveProperty("targetForm");
    expect(parsed.bRecords[0]).not.toHaveProperty("rawRequestTarget");
    expect(parsed.bRecords[0]).not.toHaveProperty("attributableToRequestTarget");
  });

  it("records wrong-secret reachability but retains neither the body nor its failed derivation", async () => {
    const handle = await receiver();
    expect((await register(handle)).status).toBe(201);
    const wrongSecret = "wrong-owned-secret-".padEnd(48, "w");
    const wrongDerivation = actionOperationId(actionKey, runId, "network-path-target-attack", wrongSecret);
    const response = await fetch(`${localB(handle)}/v1/sbx037/collect/${runId}`, {
      method: "POST",
      headers: correlatedHeaders("network-path-target-attack"),
      body: wrongSecret,
    });
    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({ operationId: receipts.network });

    const state = await readback(handle);
    expect(state.text).not.toContain(wrongSecret);
    expect(state.text).not.toContain(wrongDerivation);
    expect(state.text).not.toContain(configuration().expectedActionOperationIds.networkPathTargetAttack);
    const parsed = state.value as { bRecords: Array<Record<string, unknown>> };
    expect(parsed.bRecords).toEqual([
      expect.objectContaining({
        caseId: "network-path-target-attack",
        operatorSecretBodyPresent: true,
        operatorSecretActionAttempted: true,
        operatorSecretActionAuthorized: false,
        operatorSecretActions: [],
        operationId: receipts.network,
        tokenVerified: false,
        responseStatus: 202,
      }),
    ]);
    expect(parsed.bRecords[0]).not.toHaveProperty("bodyLength");
  });
});
