import { execFile } from "node:child_process";
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";

const executeFile = promisify(execFile);
const redirectProbe = fileURLToPath(new URL("../guest/redirect-probe.mjs", import.meta.url));
const servers: http.Server[] = [];

type SeenRequest = {
  method: string | undefined;
  rawTarget: string | undefined;
  headers: IncomingMessage["headers"];
};

async function startServer(
  handler: (request: IncomingMessage, response: ServerResponse) => void,
): Promise<{ server: http.Server; origin: string }> {
  const server = http.createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test server has no TCP address");
  return { server, origin: `http://127.0.0.1:${address.port}` };
}

function encodeConfig(overrides: Record<string, unknown>): string {
  return Buffer.from(
    JSON.stringify({
      rawPath: "/start?seed=1",
      method: "GET",
      headers: {},
      preserveHeaders: [],
      maxRedirects: 5,
      timeoutMs: 2_000,
      correlation: {
        runId: "run-redirect-test",
        testId: "SBX-007",
        caseId: "cross-origin",
        canary: "nonsecret-correlation-canary",
      },
      ...overrides,
    }),
  ).toString("base64url");
}

async function runProbe(config: string): Promise<Record<string, unknown>> {
  const result = await executeFile(process.execPath, [redirectProbe, config]);
  return JSON.parse(result.stdout) as Record<string, unknown>;
}

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) => new Promise<void>((resolve) => server.close(() => resolve())),
    ),
  );
});

describe("guest redirect probe", () => {
  it("records raw targets and follows a cross-origin redirect without leaking credentials", async () => {
    const seenAtA: SeenRequest[] = [];
    const seenAtB: SeenRequest[] = [];
    const destination = await startServer((request, response) => {
      seenAtB.push({ method: request.method, rawTarget: request.url, headers: request.headers });
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ destination: "B" }));
    });
    const source = await startServer((request, response) => {
      seenAtA.push({ method: request.method, rawTarget: request.url, headers: request.headers });
      response.writeHead(302, {
        location: `${destination.origin}/landing?from=A#ignored-fragment`,
      });
      response.end();
    });

    const result = await runProbe(
      encodeConfig({
        baseUrl: source.origin,
        headers: {
          authorization: "Bearer synthetic-guest-only",
          cookie: "synthetic_session=guest-only",
          "x-guest-marker": "safe-marker",
          "x-not-preserved": "first-hop-only",
        },
        preserveHeaders: ["x-guest-marker"],
      }),
    );

    expect(result).toMatchObject({
      ok: true,
      redirectsFollowed: 1,
      final: { statusCode: 200, body: JSON.stringify({ destination: "B" }) },
      hops: [
        {
          index: 0,
          origin: source.origin,
          method: "GET",
          statusCode: 302,
          location: `${destination.origin}/landing?from=A#ignored-fragment`,
        },
        { index: 1, origin: destination.origin, method: "GET", statusCode: 200 },
      ],
    });
    expect(seenAtA).toHaveLength(1);
    expect(seenAtA[0]?.rawTarget).toBe(
      "/start?seed=1&__sbx_run=run-redirect-test&__sbx_test=SBX-007&__sbx_case=cross-origin&__sbx_canary=nonsecret-correlation-canary",
    );
    expect(seenAtA[0]?.headers.authorization).toBe("Bearer synthetic-guest-only");
    expect(seenAtA[0]?.headers.cookie).toBe("synthetic_session=guest-only");
    expect(seenAtB).toHaveLength(1);
    expect(seenAtB[0]?.rawTarget).toBe(
      "/landing?from=A&__sbx_run=run-redirect-test&__sbx_test=SBX-007&__sbx_case=cross-origin&__sbx_canary=nonsecret-correlation-canary",
    );
    expect(seenAtB[0]?.headers["x-guest-marker"]).toBe("safe-marker");
    expect(seenAtB[0]?.headers.authorization).toBeUndefined();
    expect(seenAtB[0]?.headers.cookie).toBeUndefined();
    expect(seenAtB[0]?.headers["x-not-preserved"]).toBeUndefined();
  });

  it("stops at the configured redirect cap and does not issue the next request", async () => {
    const seen: SeenRequest[] = [];
    let origin = "";
    const chain = await startServer((request, response) => {
      seen.push({ method: request.method, rawTarget: request.url, headers: request.headers });
      const match = /^\/hop\/(\d+)/.exec(request.url ?? "");
      const hop = Number(match?.[1] ?? 0);
      response.writeHead(307, { location: `${origin}/hop/${hop + 1}` });
      response.end();
    });
    origin = chain.origin;

    const result = await runProbe(
      encodeConfig({
        baseUrl: origin,
        rawPath: "/hop/0",
        method: "POST",
        maxRedirects: 2,
        correlation: {
          runId: "run-hop-cap",
          testId: "SBX-011",
          caseId: "bounded-307",
          canary: "hop-cap-marker",
        },
      }),
    );

    expect(result).toMatchObject({
      ok: false,
      error: "redirect limit reached",
      redirectsFollowed: 2,
      hops: [
        { index: 0, method: "POST", statusCode: 307 },
        { index: 1, method: "POST", statusCode: 307 },
        { index: 2, method: "POST", statusCode: 307 },
      ],
      final: { statusCode: 307 },
    });
    expect(seen).toHaveLength(3);
    expect(seen.map((request) => request.rawTarget)).toEqual([
      "/hop/0?__sbx_run=run-hop-cap&__sbx_test=SBX-011&__sbx_case=bounded-307&__sbx_canary=hop-cap-marker",
      "/hop/1?__sbx_run=run-hop-cap&__sbx_test=SBX-011&__sbx_case=bounded-307&__sbx_canary=hop-cap-marker",
      "/hop/2?__sbx_run=run-hop-cap&__sbx_test=SBX-011&__sbx_case=bounded-307&__sbx_canary=hop-cap-marker",
    ]);
  });

  it("rejects attempts to preserve sensitive custom headers", async () => {
    const result = await runProbe(
      encodeConfig({
        baseUrl: "http://127.0.0.1:9",
        headers: { "x-synthetic-api-key": "not-a-real-key" },
        preserveHeaders: ["x-synthetic-api-key"],
      }),
    );

    expect(result).toEqual({
      ok: false,
      error: "refusing to preserve sensitive or connection-specific header x-synthetic-api-key",
      hops: [],
    });
  });
});
