import { describe, expect, it } from "vitest";
import { APIClient } from "../node_modules/@vercel/sandbox/dist/api-client/api-client.js";

function proxyShapedJwt(): string {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({
    iss: "https://oidc.vercel.com/team_example",
    aud: "https://p.example.test/v1/sbx048/forward/run",
    team_id: "team_example",
    project_id: "prj_example",
    sandbox_id: "sbx_example",
    sandbox_name: "sbx-048-poc-example",
    iat: 1,
    exp: 2,
  })).toString("base64url");
  return `${header}.${payload}.synthetic-signature`;
}

describe("SBX-048 installed SDK transport audit", () => {
  it("carries a proxy-shaped JWT unchanged as bearer auth to the exact session route", async () => {
    const token = proxyShapedJwt();
    const calls: Array<{ url: string; authorization: string | null }> = [];
    const fakeFetch = (async (input: string | URL | globalThis.Request, init?: RequestInit) => {
      calls.push({
        url: input.toString(),
        authorization: new Headers(init?.headers).get("authorization"),
      });
      return Response.json({
        session: {
          id: "sbx_example",
          memory: 4096,
          vcpus: 2,
          region: "iad1",
          timeout: 480_000,
          status: "running",
          requestedAt: 1,
          createdAt: 1,
          cwd: "/vercel/sandbox",
          updatedAt: 1,
          networkPolicy: { mode: "deny-all" },
        },
        routes: [],
      });
    }) as typeof fetch;
    const client = new APIClient({ token, teamId: "team_example", fetch: fakeFetch });
    const response = await client.getSession({ sessionId: "sbx_example" });
    expect(response.json.session.id).toBe("sbx_example");
    expect(calls).toEqual([{
      url: "https://vercel.com/api/v2/sandboxes/sessions/sbx_example?teamId=team_example",
      authorization: `Bearer ${token}`,
    }]);
  });
});
