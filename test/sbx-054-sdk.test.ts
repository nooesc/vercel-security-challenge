import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { Sandbox } from "@vercel/sandbox";
import {
  auditSbx054SdkAndGuest,
  sbx054ComparatorCreateParameters,
  SBX054_FIXED_GUEST_SHA256,
  sbx054TargetCreateParameters,
} from "../pocs/SBX-054/legacy-create-policy.js";
import {
  createSbx054Journal,
  loadSbx054Config,
  parseSbx054Journal,
} from "../pocs/SBX-054/safety.js";

const config = {
  token: "offline_vercel_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  teamId: "team_n98ERpVwV7HqmWRudAyK8sXQ" as const,
  projectId: "prj_CyyVykdN06Nrkla6KidZcecLgbCa" as const,
};
const runId = "00000000-0000-4000-8000-000000000054";

function response(name: string, tags: Record<string, string>, runtime?: string) {
  const now = Date.now();
  return {
    sandbox: {
      name,
      persistent: false,
      createdAt: now,
      updatedAt: now,
      currentSessionId: `sbx_${name.replaceAll("-", "_")}_session`,
      status: "running",
      networkPolicy: { mode: "deny-all" },
      tags,
      ...(runtime === undefined ? {} : { runtime }),
    },
    session: {
      id: `sbx_${name.replaceAll("-", "_")}_session`,
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
      networkPolicy: { mode: "deny-all" },
    },
    routes: [],
  };
}

async function capture(kind: "comparator" | "target") {
  const name = kind === "comparator" ? `sbx-054-v3-${runId}` : `sbx-054-v2-${runId}`;
  const tags = { harness: "vsc", test: "SBX-054", run: runId, role: kind };
  let url: URL | undefined;
  let body: Record<string, unknown> | undefined;
  const fakeFetch = (async (input: string | URL | Request, init?: RequestInit) => {
    url = new URL(input instanceof Request ? input.url : input.toString());
    body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    return new Response(JSON.stringify(response(name, tags, kind === "target" ? "node24" : undefined)), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  const parameters = kind === "comparator"
    ? sbx054ComparatorCreateParameters(config, name, tags)
    : sbx054TargetCreateParameters(config, name, tags);
  await Sandbox.create({ ...parameters, fetch: fakeFetch });
  if (!url || !body) throw new Error("offline capture did not execute");
  return { url, body };
}

describe("SBX-054 installed SDK route differential", () => {
  it("sends the same literal deny-all policy to v3 without runtime and v2 with node24", async () => {
    const comparator = await capture("comparator");
    const target = await capture("target");
    expect(comparator.url.pathname).toBe("/api/v3/sandboxes");
    expect(target.url.pathname).toBe("/api/v2/sandboxes");
    expect(comparator.body.networkPolicy).toEqual({ mode: "deny-all" });
    expect(target.body.networkPolicy).toEqual({ mode: "deny-all" });
    expect(comparator.body.runtime).toBeUndefined();
    expect(target.body.runtime).toBe("node24");
    expect(comparator.body).toMatchObject({ ports: [], env: {}, persistent: false });
    expect(target.body).toMatchObject({ ports: [], env: {}, persistent: false });
  });

  it("pins the audited SDK branch and exact fixed guest", async () => {
    const result = await auditSbx054SdkAndGuest();
    expect(result.audit).toMatchObject({
      installedVersion: "3.0.0",
      runtimePresenceSelectsV2: true,
      runtimeAbsenceSelectsV3: true,
      sameNetworkPolicySerialization: true,
    });
    expect(createHash("sha256").update(result.guestSource).digest("hex"))
      .toBe(SBX054_FIXED_GUEST_SHA256);
  });

  it("requires fresh non-resuming policy readbacks around each request", async () => {
    const source = await readFile("pocs/SBX-054/legacy-create-policy.ts", "utf8");
    expect(source).toContain("resume: false");
    expect(source.match(/policyReadback\(\{/gu)?.length).toBeGreaterThanOrEqual(7);
    expect(source).toContain('stage: "pre-request"');
    expect(source).toContain('stage: "post-public"');
    expect(source).toContain('stage: "final"');
    expect(source).toContain('caseId: "v3-deny-comparator-post"');
    expect(source.indexOf('caseId: "v2-runtime-deny-target"'))
      .toBeLessThan(source.indexOf('caseId: "v3-deny-comparator-post"'));
    expect(source.indexOf('caseId: "v3-deny-comparator-post"'))
      .toBeLessThan(source.indexOf("secret = randomBytes(48)"));
    const provisional = source.indexOf("const provisional = assessSbx054");
    expect(source.indexOf("targetFinal = await policyReadback")).toBeLessThan(provisional);
    expect(source.indexOf("finalObserver = await getObserver")).toBeLessThan(provisional);
    expect(source.indexOf("receiverPostflightPassed = await publicHealth")).toBeLessThan(provisional);
    expect(source.indexOf("observer: finalObserver")).toBeGreaterThan(provisional);
    expect(source.indexOf("secret = randomBytes(48)")).toBeGreaterThan(provisional);
    expect(source.match(/targetFinal = await policyReadback/gu)?.length).toBe(2);
  });

  it("attests only the three observed inherited platform trust names and forbids trust injection", async () => {
    const guest = await readFile("guest/sbx-054-legacy-create-policy-probe.mjs", "utf8");
    for (const name of ["NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "SSL_CERT_FILE"]) {
      expect(guest).toContain(`"${name}"`);
    }
    expect(guest).toContain("inheritedPlatformTrustEnvironmentNames");
    expect(guest).toContain("controllerConfigurableCustomTrustAccepted: false");
    expect(guest).toContain('process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0"');
    expect(guest).toContain("runtimeInjectionOption");
  });

  it("fails closed across create/configure response loss and acquires recovery lock before journal read", async () => {
    const source = await readFile("pocs/SBX-054/legacy-create-policy.ts", "utf8");
    const checkpoint = source.slice(
      source.indexOf("async function checkpointCreate"),
      source.indexOf("async function waitUnknownCreate"),
    );
    expect(checkpoint).not.toContain("finally");
    expect(checkpoint.indexOf("createAttemptedAt")).toBeLessThan(checkpoint.indexOf("await input.create()"));
    expect(checkpoint.indexOf("createSettledAt")).toBeGreaterThan(checkpoint.indexOf("await input.create()"));
    expect(source).toContain("const checks = resource.sessionId === undefined ? 1 : 2;");
    expect(source).toContain("if (resource.sessionId === undefined) return false;");
    expect(source.indexOf("journal.receiverConfigureAttempted = true"))
      .toBeLessThan(source.indexOf("journal.receiverConfigured = true"));
    expect(source.indexOf("if (!targetPostPublic.passed)"))
      .toBeLessThan(source.indexOf("const provisional = assessSbx054"));
    const recovery = source.slice(source.indexOf("async function runRecovery"));
    expect(recovery.indexOf("acquireSbx054Lock(runId, true)"))
      .toBeLessThan(recovery.indexOf("readSbx054Journal(runId)"));
  });

  it("binds config to one eligible identity, fresh Quick Tunnel, and distinct keys", () => {
    const environment = {
      SBX054_SCOPE_CONFIRMATION:
        "I_RECHECKED_SBX054_SCOPE_AND_AUTHORIZE_ONE_BOUNDED_V2_V3_CREATE_POLICY_DIFFERENTIAL",
      VERCEL_TEAM_ID: config.teamId,
      VERCEL_PROJECT_ID: config.projectId,
      SBX054_EXPECTED_ALIAS: "swve@wearehackerone.com",
      VERCEL_TOKEN: config.token,
      SBX054_ADMIN_KEY: "a".repeat(64),
      SBX054_ACTION_KEY: "b".repeat(64),
      SBX054_PUBLIC_ORIGIN: "https://fresh-owned.trycloudflare.com",
      SBX054_ADMIN_ORIGIN: "http://127.0.0.1:43154",
    } as NodeJS.ProcessEnv;
    expect(loadSbx054Config(environment)).toMatchObject({
      teamId: config.teamId,
      projectId: config.projectId,
      expectedAlias: "swve@wearehackerone.com",
    });
    expect(() => loadSbx054Config({ ...environment, SBX054_ACTION_KEY: "a".repeat(64) }))
      .toThrow(/distinct/u);
    expect(() => loadSbx054Config({
      ...environment,
      SBX054_PUBLIC_ORIGIN: "https://example.com",
    })).toThrow(/Quick Tunnel/u);
  });

  it("keeps exact two-resource recovery provenance and rejects malformed completion", () => {
    const journal = createSbx054Journal(new Date("2026-08-19T12:00:00.000Z"), runId);
    expect(parseSbx054Journal(journal)).toEqual(journal);
    const malformed = structuredClone(journal);
    malformed.completed = true;
    expect(() => parseSbx054Journal(malformed)).toThrow(/cleanup/u);
  });
});
