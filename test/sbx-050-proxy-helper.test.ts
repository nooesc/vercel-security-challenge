import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

const runId = "12345678-1234-4123-8123-123456789abc";
const teamId = "team_abcdefghijklmno";
const projectId = "prj_abcdefghijklmno";
const sessionId = "sbx_abcdefghijklmnopqrstuvwxyz";
const sandboxName = "sbx050-owned-test";

import { defineSandboxProxy } from "@vercel/sandbox/proxy";
import { requestPath } from "../pocs/SBX-050/protocol.js";
import {
  exactProxyAttribution,
  type Sbx050ForwardedMetadata,
  type Sbx050ReceiverConfiguration,
} from "../pocs/SBX-050/receiver.js";

const caseId = "public-forward-control" as const;
const canary = "c50_abcdefghijklmnopqrstuvwx";
const originalPath = requestPath(runId, caseId, canary);
const forwardAudience = `https://p.example.test/v1/sbx050/proxy/${runId}`;
const configuration: Sbx050ReceiverConfiguration = {
  runId,
  aHostname: "a.example.test",
  forwardAudience,
  expectedTeamId: teamId,
  expectedProjectId: projectId,
  expectedSessionId: sessionId,
  expectedSandboxName: sandboxName,
  credentialCommitment: "a".repeat(43),
  hiddenTriggerCommitment: "b".repeat(43),
  cases: [{ caseId, canary, requestPath: originalPath }],
};
const forwarded: Sbx050ForwardedMetadata = {
  host: ["a.example.test"],
  scheme: ["https"],
  port: ["443"],
  path: [originalPath],
};

beforeEach(() => vi.clearAllMocks());
afterEach(() => vi.unstubAllGlobals());

describe("SBX-050 installed proxy helper attribution", () => {
  it("proves helper meta.host is P while reconstructed request URL/Host and forwarded metadata are A", async () => {
    const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
    const keyId = "sbx050-test-key";
    const publicJwk = {
      ...(await exportJWK(publicKey)),
      alg: "RS256",
      kid: keyId,
      use: "sig",
    };
    const issuedAt = Math.floor(Date.now() / 1_000);
    const issuer = `https://oidc.vercel.com/${teamId}`;
    const token = await new SignJWT({
      team_id: teamId,
      project_id: projectId,
      sandbox_id: sessionId,
      sandbox_name: sandboxName,
    })
      .setProtectedHeader({ alg: "RS256", kid: keyId })
      .setIssuer(issuer)
      .setAudience(forwardAudience)
      .setIssuedAt(issuedAt)
      .setExpirationTime(issuedAt + 60)
      .sign(privateKey);
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      expect(String(input)).toBe(`${issuer}/.well-known/jwks`);
      return Response.json({ keys: [publicJwk] });
    }));

    let observed: { url: string; host: string | null; metaHost: string; exact: boolean } | undefined;
    let rejection: string | undefined;
    const handler = defineSandboxProxy(async (proxiedRequest, meta) => {
      observed = {
        url: proxiedRequest.url,
        host: proxiedRequest.headers.get("host"),
        metaHost: meta.host,
        exact: exactProxyAttribution(proxiedRequest, meta.host, forwarded, caseId, configuration),
      };
      return new Response(null, { status: 204 });
    }, (_request, error) => {
      rejection = error.message;
      return new Response(null, { status: 403 });
    });
    const incoming = new Request(`${forwardAudience}${originalPath}`, {
      headers: {
        "vercel-forwarded-host": "a.example.test",
        "vercel-forwarded-scheme": "https",
        "vercel-forwarded-port": "443",
        "vercel-forwarded-path": originalPath,
        "vercel-sandbox-oidc-token": token,
      },
    });
    expect({ status: (await handler(incoming)).status, rejection }).toEqual({
      status: 204,
      rejection: undefined,
    });
    expect(observed).toEqual({
      url: `https://a.example.test${originalPath}`,
      host: "a.example.test",
      metaHost: "p.example.test",
      exact: true,
    });
  });

  it("rejects A as meta.host and any duplicate or rewritten forwarded field", () => {
    const proxied = new Request(`https://a.example.test${originalPath}`, {
      headers: { host: "a.example.test" },
    });
    expect(exactProxyAttribution(proxied, "a.example.test", forwarded, caseId, configuration)).toBe(false);
    expect(exactProxyAttribution(proxied, "p.example.test", {
      ...forwarded,
      host: ["a.example.test", "a.example.test"],
    }, caseId, configuration)).toBe(false);
    expect(exactProxyAttribution(proxied, "p.example.test", {
      ...forwarded,
      path: [`${originalPath}&extra=1`],
    }, caseId, configuration)).toBe(false);
  });
});
