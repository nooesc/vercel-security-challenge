import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { Sandbox } from "@vercel/sandbox";
import {
  inheritanceForkParams,
  sbx047SourcePolicy,
  targetForkParams,
} from "../pocs/SBX-047/fork-network-policy.js";

const config = {
  token: "offline_fake_pat_that_is_never_sent",
  teamId: "team_n98ERpVwV7HqmWRudAyK8sXQ" as const,
  projectId: "prj_CyyVykdN06Nrkla6KidZcecLgbCa" as const,
};
const plan = {
  name: "sbx-047-target-00000000-0000-4000-8000-000000000047",
  tags: {
    harness: "vsc",
    test: "SBX-047",
    run: "00000000-0000-4000-8000-000000000047",
    role: "target",
  },
};

function responsePayload(name: string, networkPolicy: unknown): Record<string, unknown> {
  const now = Date.now();
  return {
    sandbox: {
      name,
      persistent: false,
      createdAt: now,
      updatedAt: now,
      currentSessionId: "sbx_offline_target_session_047",
      status: "running",
      networkPolicy: networkPolicy === "deny-all" ? { mode: "deny-all" } : networkPolicy,
      tags: plan.tags,
    },
    session: {
      id: "sbx_offline_target_session_047",
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
      networkPolicy: networkPolicy === "deny-all" ? { mode: "deny-all" } : networkPolicy,
    },
    routes: [],
  };
}

async function capture(
  kind: "target" | "inheritance",
): Promise<{ url: URL; body: Record<string, unknown> }> {
  let url: URL | undefined;
  let body: Record<string, unknown> | undefined;
  const fakeFetch = (async (input: string | URL | Request, init?: RequestInit) => {
    url = new URL(input instanceof Request ? input.url : input.toString());
    body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    return new Response(JSON.stringify(responsePayload(plan.name, "deny-all")), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  const params = kind === "target"
    ? targetForkParams(config, fakeFetch, "source control", plan)
    : inheritanceForkParams(config, fakeFetch, "source control", plan);
  await Sandbox.fork(params);
  if (url === undefined || body === undefined) throw new Error("offline fork capture did not run");
  return { url, body };
}

describe("SBX-047 installed SDK fork serialization", () => {
  it("is pinned to the audited @vercel/sandbox 3.0.0 distribution", async () => {
    const metadata = JSON.parse(await readFile(
      new URL("../node_modules/@vercel/sandbox/package.json", import.meta.url),
      "utf8",
    )) as { version?: unknown };
    expect(metadata.version).toBe("3.0.0");
  });

  it("sends the explicit deny-all override as the SDK's exact API representation to POST /fork", async () => {
    const captured = await capture("target");
    expect(captured.url.origin).toBe("https://vercel.com");
    expect(captured.url.pathname).toBe("/api/v2/sandboxes/source%20control/fork");
    expect(captured.url.searchParams.get("teamId")).toBe(config.teamId);
    expect(captured.url.searchParams.get("projectId")).toBe(config.projectId);
    expect(captured.body.networkPolicy).toEqual({ mode: "deny-all" });
  });

  it("sends one exact A-only source transform without placing it in guest environment", async () => {
    let body: Record<string, unknown> | undefined;
    const fakeFetch = (async (_input: string | URL | Request, init?: RequestInit) => {
      body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return new Response(JSON.stringify(responsePayload("source-control", "deny-all")), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;
    const policy = sbx047SourcePolicy("owned.example.test", "offline-controller-only");
    await Sandbox.create({
      ...config,
      fetch: fakeFetch,
      name: "source-control",
      ports: [],
      networkPolicy: policy,
      tags: { ...plan.tags, role: "source" },
    });
    expect(body?.networkPolicy).toEqual(policy);
    expect(Object.prototype.hasOwnProperty.call(body ?? {}, "env")).toBe(false);
  });

  it("omits networkPolicy completely for the config-copy inheritance control", async () => {
    const captured = await capture("inheritance");
    expect(Object.prototype.hasOwnProperty.call(captured.body, "networkPolicy")).toBe(false);
  });
});
