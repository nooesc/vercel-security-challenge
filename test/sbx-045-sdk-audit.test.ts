import { describe, expect, it } from "vitest";
import { Sandbox } from "@vercel/sandbox";
import { readFile } from "node:fs/promises";

function responsePayload(name: string): Record<string, unknown> {
  const now = Date.now();
  const sessionId = `sbx_${name.replaceAll("-", "_")}_session`;
  return {
    sandbox: {
      name,
      persistent: false,
      createdAt: now,
      updatedAt: now,
      currentSessionId: sessionId,
      status: "running",
      networkPolicy: { mode: "deny-all" },
      tags: { test: "SBX-045" },
    },
    session: {
      id: sessionId,
      memory: 2_048,
      vcpus: 1,
      region: "iad1",
      timeout: 180_000,
      status: "running",
      requestedAt: now,
      startedAt: now,
      createdAt: now,
      cwd: "/vercel/sandbox",
      updatedAt: now,
      sourceSnapshotId: "snap_source_control",
      networkPolicy: { mode: "deny-all" },
    },
    routes: [],
  };
}

async function captureForkBody(
  env: Record<string, string> | undefined,
): Promise<{ url: URL; body: Record<string, unknown> }> {
  let capturedUrl: URL | undefined;
  let capturedBody: Record<string, unknown> | undefined;
  const fakeFetch = (async (input: string | URL | Request, init?: RequestInit) => {
    capturedUrl = new URL(input instanceof Request ? input.url : input.toString());
    capturedBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
    return new Response(JSON.stringify(responsePayload("target-control")), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;

  await Sandbox.fork({
    token: "offline_fake_pat_that_is_never_sent",
    teamId: "team_offline",
    projectId: "prj_offline",
    fetch: fakeFetch,
    sourceSandbox: "source control",
    name: "target-control",
    networkPolicy: "deny-all",
    ...(env === undefined ? {} : { env }),
  });
  if (!capturedUrl || !capturedBody) throw new Error("offline fork capture did not run");
  return { url: capturedUrl, body: capturedBody };
}

describe("SBX-045 installed @vercel/sandbox v3 fork audit", () => {
  it("is pinned to the audited 3.0.0 distribution", async () => {
    const metadata = JSON.parse(await readFile(
      new URL("../node_modules/@vercel/sandbox/package.json", import.meta.url),
      "utf8",
    )) as { version?: unknown };
    expect(metadata.version).toBe("3.0.0");
  });

  it("sends an explicit same-key B value verbatim to the server fork endpoint", async () => {
    const capture = await captureForkBody({ SAME_KEY: "B", ONLY_OVERRIDE: "present" });
    expect(capture.url.origin).toBe("https://vercel.com");
    expect(capture.url.pathname).toBe("/api/v2/sandboxes/source%20control/fork");
    expect(capture.url.searchParams.get("teamId")).toBe("team_offline");
    expect(capture.url.searchParams.get("projectId")).toBe("prj_offline");
    expect(capture.body.env).toEqual({ SAME_KEY: "B", ONLY_OVERRIDE: "present" });
  });

  it("omits env when the inheritance control does not provide it", async () => {
    const capture = await captureForkBody(undefined);
    expect(Object.prototype.hasOwnProperty.call(capture.body, "env")).toBe(false);
  });

  it("serializes a missing command env as an empty map, never a synthetic-key override", async () => {
    const runtime = await readFile(
      new URL("../node_modules/@vercel/sandbox/dist/session.js", import.meta.url),
      "utf8",
    );
    expect(runtime).toContain("env: params.env ?? {}");
  });
});
