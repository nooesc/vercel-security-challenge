import { describe, expect, it } from "vitest";
import {
  SBX047_GUEST_SHA256,
  createSbx047ExternalGate,
  exactSbx047DenyAll,
  exactSbx047SourcePolicy,
  exactSbx047SourceSandboxProjection,
  fixedSbx047GuestCommand,
  sbx047SourcePolicy,
} from "../pocs/SBX-047/fork-network-policy.js";
import {
  SBX047_ELIGIBLE_ALIAS,
  SBX047_ELIGIBLE_PROJECT,
  SBX047_ELIGIBLE_TEAM,
  SBX047_SCOPE_CONFIRMATION,
  createSbx047Journal,
  loadSbx047Config,
  parseSbx047Journal,
} from "../pocs/SBX-047/safety.js";

describe("SBX-047 controller invariants", () => {
  it("accepts only one exact A-only transform policy and literal deny-all", () => {
    const host = "owned.example.test";
    const credential = "controller-only";
    expect(exactSbx047SourcePolicy(sbx047SourcePolicy(host, credential), host, credential)).toBe(true);
    expect(exactSbx047SourcePolicy(sbx047SourcePolicy(host, "<redacted>"), host, "<redacted>"))
      .toBe(true);
    expect(exactSbx047SourcePolicy({
      allow: {
        [host]: [{ transform: [{ headers: { "x-sbx047-brokered-credential": credential } }] }],
      },
      deny: ["other.example.test"],
    }, host, credential)).toBe(false);
    expect(exactSbx047SourcePolicy(sbx047SourcePolicy(host, "wrong"), host, credential)).toBe(false);
    expect(exactSbx047DenyAll("deny-all")).toBe(true);
    expect(exactSbx047DenyAll({ mode: "deny-all" })).toBe(false);
  });

  it("accepts only the exact top-level source policy projection", () => {
    const host = "owned.example.test";
    expect(exactSbx047SourceSandboxProjection({ allow: [host] }, host)).toBe(true);
    expect(exactSbx047SourceSandboxProjection({ allow: [host, "extra.example"] }, host)).toBe(false);
    expect(exactSbx047SourceSandboxProjection({ allow: [host], deny: [] }, host)).toBe(false);
    expect(exactSbx047SourceSandboxProjection({ allow: { [host]: [] } }, host)).toBe(false);
  });

  it("pins the exact alias/team/project, public origin, admin loopback, and non-JWT PAT", () => {
    const environment = {
      SBX047_SCOPE_CONFIRMATION,
      SBX047_EXPECTED_ALIAS: SBX047_ELIGIBLE_ALIAS,
      VERCEL_TEAM_ID: SBX047_ELIGIBLE_TEAM,
      VERCEL_PROJECT_ID: SBX047_ELIGIBLE_PROJECT,
      VERCEL_TOKEN: "offline_pat_with_more_than_twenty_chars",
      SBX047_ADMIN_KEY: "a".repeat(64),
      SBX047_PUBLIC_ORIGIN: "https://owned.example.test",
      SBX047_ADMIN_ORIGIN: "http://127.0.0.1:43147",
    };
    const config = loadSbx047Config(environment);
    expect(config.publicOrigin.origin).toBe("https://owned.example.test");
    expect(config.adminOrigin.origin).toBe("http://127.0.0.1:43147");
    expect(() => loadSbx047Config({ ...environment, VERCEL_TEAM_ID: "team_wrong" }))
      .toThrow(/exact eligible alias/u);
    expect(() => loadSbx047Config({ ...environment, VERCEL_TOKEN: "a.b.c" }))
      .toThrow(/non-JWT/u);
  });

  it("creates three deterministic fresh UUID-tagged resource plans", () => {
    const journal = parseSbx047Journal(createSbx047Journal());
    expect(journal.resources.map((entry) => entry.role)).toEqual(["source", "inheritance", "target"]);
    for (const item of journal.resources) {
      expect(item.name).toContain(journal.runId);
      expect(item.tags).toEqual({
        harness: "vsc",
        test: "SBX-047",
        run: journal.runId,
        role: item.role,
      });
    }
  });

  it("uses one fixed secret-free guest command specification", () => {
    const command = fixedSbx047GuestCommand(
      "https://owned.example.test", "run-047", "public", "case-047", "canary-047",
    );
    expect(command).toEqual({
      cmd: "node",
      args: [
        "/tmp/sbx-047/network-request.mjs",
        "public",
        "https://owned.example.test",
        "run-047",
        "case-047",
        "canary-047",
      ],
      timeoutMs: 12_000,
    });
    expect(SBX047_GUEST_SHA256).toMatch(/^[a-f0-9]{64}$/u);
    expect(Object.prototype.hasOwnProperty.call(command, "env")).toBe(false);
  });

  it("serializes all external request starts at no more than four per second", async () => {
    let clock = 1_000;
    const rawFetch = (async () => new Response("{}", { status: 200 })) as typeof fetch;
    const gate = createSbx047ExternalGate(
      new URL("https://owned.example.test"),
      rawFetch,
      () => clock,
      async (milliseconds) => { clock += milliseconds; },
    );
    await gate.fetch("https://api.vercel.com/v2/user");
    await gate.fetch("https://owned.example.test/healthz");
    await gate.fetch(
      `https://vercel.com/api/v3/sandboxes?teamId=${SBX047_ELIGIBLE_TEAM}`,
      { method: "POST", body: JSON.stringify({ projectId: SBX047_ELIGIBLE_PROJECT }) },
    );
    await gate.fetch(
      `https://vercel.com/api/v2/sandboxes?teamId=${SBX047_ELIGIBLE_TEAM}&project=${SBX047_ELIGIBLE_PROJECT}`,
    );
    await gate.fetch(
      `https://vercel.com/api/v2/sandboxes/source/fork?teamId=${SBX047_ELIGIBLE_TEAM}&projectId=${SBX047_ELIGIBLE_PROJECT}`,
      { method: "POST", body: "{}" },
    );
    const guest = await gate.reserveGuest("/v1/sbx047/public/run/case/canary");
    gate.completeGuest(guest);
    const audit = gate.summary();
    expect(audit.count).toBe(6);
    expect(audit.contiguous).toBe(true);
    expect(audit.completed).toBe(true);
    expect(audit.withinRateLimit).toBe(true);
    expect(audit.minimumStartIntervalMs).toBe(250);
  });

  it("rejects nonallowlisted external destinations before fetch", async () => {
    let called = false;
    const gate = createSbx047ExternalGate(
      new URL("https://owned.example.test"),
      (async () => { called = true; return new Response(); }) as typeof fetch,
    );
    await expect(gate.fetch("https://example.org/")).rejects.toThrow(/non-allowlisted/u);
    await expect(gate.fetch(
      `https://vercel.com/api/v2/sandboxes?teamId=${SBX047_ELIGIBLE_TEAM}&project=prj_wrong`,
    )).rejects.toThrow(/outside the exact team\/project/u);
    expect(called).toBe(false);
  });
});
