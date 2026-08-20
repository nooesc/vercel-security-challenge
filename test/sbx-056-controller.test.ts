import { describe, expect, it } from "vitest";
import { Sandbox } from "@vercel/sandbox";
import {
  exactSbx056Handle,
  loadSbx056Config,
  oneSbx056Read,
  sbx056CreateParameters,
  sbx056CrossDispatchGate,
  Sbx056RequestGate,
  verifySbx056Authority,
  SBX056_ALIAS,
  SBX056_SCOPE_CONFIRMATION,
} from "../pocs/SBX-056/project-scoped-session-read.js";
import { createSbx056Journal, sbx056FixedPath } from "../pocs/SBX-056/safety.js";
import type { Sbx056AuthorityProof } from "../pocs/SBX-056/verdict.js";

const RUN = "12345678-1234-4abc-8def-1234567890ab";
const TEAM = "team_EligibleTeam1234567890";
const CONTROL = "prj_ControlProject1234567890";
const VICTIM = "prj_VictimProject1234567890";
const OWNER = "owner_token_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const SCOPED = "scoped_token_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

function environment(extra: Record<string, string> = {}): Record<string, string> {
  return {
    SBX056_SCOPE_CONFIRMATION,
    SBX056_EXPECTED_ALIAS: SBX056_ALIAS,
    SBX056_ALIAS_EMAIL_CONFIRMATION: SBX056_ALIAS,
    VERCEL_TEAM_ID: TEAM,
    SBX056_CONTROL_PROJECT_ID: CONTROL,
    SBX056_VICTIM_PROJECT_ID: VICTIM,
    SBX056_OWNER_TOKEN: OWNER,
    SBX056_PROJECT_SCOPED_TOKEN: SCOPED,
    ...extra,
  };
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
}

function sandboxResponse(name: string, tags: Record<string, string>) {
  const now = Date.now();
  const sessionId = "sbx_offline_session_abcdefghijklmnopqrstuvwxyz";
  return {
    sandbox: { name, persistent: false, createdAt: now, updatedAt: now,
      currentSessionId: sessionId, status: "running", networkPolicy: { mode: "deny-all" }, tags },
    session: { id: sessionId, memory: 2_048, vcpus: 1, region: "iad1", timeout: 180_000,
      status: "running", requestedAt: now, startedAt: now, createdAt: now,
      cwd: "/vercel/sandbox", updatedAt: now, networkPolicy: { mode: "deny-all" } },
    routes: [],
  };
}

describe("SBX-056 controller gates", () => {
  it("loads one owner PAT and one distinct project-only PAT for two distinct owned projects", () => {
    expect(loadSbx056Config(environment())).toEqual({
      ownerToken: OWNER, scopedToken: SCOPED, teamId: TEAM,
      controlProjectId: CONTROL, victimProjectId: VICTIM, expectedAlias: SBX056_ALIAS,
    });
    expect(() => loadSbx056Config(environment({ SBX056_PROJECT_SCOPED_TOKEN: OWNER })))
      .toThrow(/must differ/u);
    expect(() => loadSbx056Config(environment({ SBX056_VICTIM_PROJECT_ID: CONTROL })))
      .toThrow(/invalid/u);
    expect(() => loadSbx056Config(environment({ SBX056_EXPECTED_ALIAS: "other@example.com" })))
      .toThrow(/eligible/u);
    expect(() => loadSbx056Config(environment({ SBX056_SCOPE_CONFIRMATION: "no" })))
      .toThrow(/scope statement/u);
  });

  it("loads cleanup-only without requiring the scoped PAT", () => {
    const values = environment({ SBX056_RECOVERY_RUN_ID: RUN });
    delete values.SBX056_PROJECT_SCOPED_TOKEN;
    expect(loadSbx056Config(values)).toEqual({
      ownerToken: OWNER, teamId: TEAM, controlProjectId: CONTROL,
      victimProjectId: VICTIM, expectedAlias: SBX056_ALIAS, recoveryRunId: RUN,
    });
    expect(() => loadSbx056Config({ ...values, SBX056_RECOVERY_RUN_ID: "bad" })).toThrow(/UUID/u);
  });

  it("restricts every gated request to api.vercel.com, one team, and the two exact tokens", async () => {
    const fetcher = (async () => json({ ok: true })) as typeof fetch;
    const gate = new Sbx056RequestGate(OWNER, SCOPED, TEAM, fetcher, 0);
    const auth = { authorization: `Bearer ${OWNER}` };
    await gate.fetch(`https://api.vercel.com/v2/user`, { headers: auth });
    await gate.fetch(`https://vercel.com/api/v3/sandboxes?teamId=${TEAM}`, { headers: auth });
    expect(gate.records).toHaveLength(2);
    await expect(gate.fetch("https://example.test/v2/user", { headers: auth })).rejects.toThrow(/origin/u);
    await expect(gate.fetch("https://vercel.com/v2/user", { headers: auth })).rejects.toThrow(/origin/u);
    await expect(gate.fetch(`https://api.vercel.com/v2/user?teamId=team_other12345678`,
      { headers: auth })).rejects.toThrow(/team/u);
    await expect(gate.fetch("https://api.vercel.com/v2/user",
      { headers: { authorization: "Bearer wrong_token_ABCDEFGHIJKLMNOPQRSTUVWXYZ" } }))
      .rejects.toThrow(/bearer/u);
  });

  it("proves the scoped PAT's positive A authority and denied B authority without /v2/user", async () => {
    const calls: { url: string; token: string }[] = [];
    const fetcher = (async (input, init) => {
      const url = input.toString();
      const token = new Headers(init?.headers).get("authorization") ?? "";
      calls.push({ url, token });
      if (url.endsWith("/v2/user")) return json({ user: { email: SBX056_ALIAS } });
      if (url.includes(`/v2/teams/${TEAM}`)) return json({ id: TEAM });
      if (url.includes(`/v9/projects/${CONTROL}`)) return json({ id: CONTROL });
      if (url.includes(`/v9/projects/${VICTIM}`) && token === `Bearer ${OWNER}`) return json({ id: VICTIM });
      if (url.includes(`/v9/projects/${VICTIM}`) && token === `Bearer ${SCOPED}`) {
        return json({ error: { code: "forbidden" } }, 403);
      }
      return json({ error: "unexpected" }, 500);
    }) as typeof fetch;
    const config = loadSbx056Config(environment());
    const gate = new Sbx056RequestGate(OWNER, SCOPED, TEAM, fetcher, 0);
    const proof = await verifySbx056Authority({ ...config, scopedToken: SCOPED }, gate);
    expect(proof).toEqual({
      ownerAliasExact: true, ownerTeamExact: true, ownerControlProjectExact: true,
      ownerVictimProjectExact: true, scopedControlProjectExact: true,
      scopedVictimProjectDenied: true,
      scopedVictimProjectStatus: 403,
      scopedTokenProjectRestrictionManuallyConfirmed: true,
      ownerAndScopedTokensDistinct: true,
    });
    expect(calls.filter((call) => call.token === `Bearer ${SCOPED}`)).toHaveLength(2);
    expect(calls.filter((call) => call.url.endsWith("/v2/user") &&
      call.token === `Bearer ${SCOPED}`)).toHaveLength(0);
  });

  it("creates both fixtures only with owner credentials, no ports, deny-all, and exact timeout", () => {
    const config = loadSbx056Config(environment());
    const gate = new Sbx056RequestGate(OWNER, SCOPED, TEAM, (async () => json({})) as typeof fetch, 0);
    const target = createSbx056Journal(CONTROL, VICTIM, RUN).targets[0];
    const parameters = sbx056CreateParameters(config, target, gate);
    expect(parameters).toMatchObject({
      token: OWNER, teamId: TEAM, projectId: CONTROL, name: target.name,
      persistent: false, timeout: 180_000, ports: [], networkPolicy: "deny-all", tags: target.tags,
    });
    expect(parameters).not.toHaveProperty("env");
    expect(parameters).not.toHaveProperty("source");
  });

  it("derives provenance from the installed SDK's active server record", async () => {
    const config = loadSbx056Config(environment());
    const target = createSbx056Journal(CONTROL, VICTIM, RUN).targets[0];
    const fetcher = (async () => json(sandboxResponse(target.name, target.tags))) as typeof fetch;
    const gate = new Sbx056RequestGate(OWNER, SCOPED, TEAM, fetcher, 0);
    const sandbox = await Sandbox.create(sbx056CreateParameters(config, target, gate));
    expect(gate.records).toEqual([expect.objectContaining({
      method: "POST", pathname: "/api/v3/sandboxes", actor: "owner",
    })]);
    expect(exactSbx056Handle(sandbox, target)).toBe(true);
    expect(exactSbx056Handle(sandbox, { ...target, name: `${target.name}-wrong` })).toBe(false);
    expect(exactSbx056Handle(sandbox, { ...target, tags: { ...target.tags, extra: "bad" } })).toBe(false);
  });

  it("sends exactly the installed child-route wire shape with no project identifier", async () => {
    const expected = Buffer.from("SBX056-PUBLIC-OFFLINE\n");
    let capturedUrl = "";
    let capturedInit: RequestInit | undefined;
    const fetcher = (async (input, init) => {
      capturedUrl = input.toString();
      capturedInit = init;
      return new Response(expected, {
        status: 200, headers: { "content-type": "application/octet-stream" },
      });
    }) as typeof fetch;
    const gate = new Sbx056RequestGate(OWNER, SCOPED, TEAM, fetcher, 0);
    const result = await oneSbx056Read({ gate, token: SCOPED, teamId: TEAM,
      sessionId: "sbx_offline_session_abcdefghijklmnopqrstuvwxyz",
      path: sbx056FixedPath(RUN, "control"), expected,
      phase: "public-control", actor: "project-scoped", target: "control" });
    const url = new URL(capturedUrl);
    expect(url.origin).toBe("https://vercel.com");
    expect(url.pathname).toBe("/api/v2/sandboxes/sessions/sbx_offline_session_abcdefghijklmnopqrstuvwxyz/fs/read");
    expect(Object.fromEntries(url.searchParams)).toEqual({ teamId: TEAM });
    expect(capturedInit).toMatchObject({ method: "POST", redirect: "error" });
    expect(JSON.parse(String(capturedInit?.body))).toEqual({ path: sbx056FixedPath(RUN, "control") });
    expect(String(capturedInit?.body)).not.toContain(CONTROL);
    expect(result).toMatchObject({ exactExpectedMarker: true, projectIdentifierSent: false,
      transportCalls: 1, status: 200 });
  });

  it("sanitizes an exact JSON denial and refuses to turn transport failure into pass evidence", async () => {
    const expected = Buffer.from("SBX056-VICTIM-OFFLINE\n");
    const deniedGate = new Sbx056RequestGate(OWNER, SCOPED, TEAM,
      (async () => json({ error: { code: "forbidden" } }, 404)) as typeof fetch, 0);
    const denied = await oneSbx056Read({ gate: deniedGate, token: SCOPED, teamId: TEAM,
      sessionId: "sbx_offline_session_abcdefghijklmnopqrstuvwxyz",
      path: sbx056FixedPath(RUN, "victim"), expected,
      phase: "cross-project", actor: "project-scoped", target: "victim" });
    expect(denied).toMatchObject({ status: 404, contentType: "application/json",
      exactExpectedMarker: false, boundedAuthError: true, transportError: false });
    const failedGate = new Sbx056RequestGate(OWNER, SCOPED, TEAM,
      (async () => { throw new Error("offline transport"); }) as typeof fetch, 0);
    const failed = await oneSbx056Read({ gate: failedGate, token: SCOPED, teamId: TEAM,
      sessionId: "sbx_offline_session_abcdefghijklmnopqrstuvwxyz",
      path: sbx056FixedPath(RUN, "victim"), expected,
      phase: "cross-project", actor: "project-scoped", target: "victim" });
    expect(failed).toMatchObject({ status: null, boundedAuthError: false, transportError: true });
  });

  it("does not dispatch cross-project until both exact reads and both provenances pass", () => {
    const journal = createSbx056Journal(CONTROL, VICTIM, RUN);
    journal.targets[0].sessionId = "sbx_control_session_abcdefghijklmnopqrstuvwxyz";
    journal.targets[1].sessionId = "sbx_victim_session_abcdefghijklmnopqrstuvwxyz";
    journal.targets[0].provenanceValidated = true;
    journal.targets[1].provenanceValidated = true;
    const exact = (phase: "public-control" | "owner-victim-control", actor: "owner" | "project-scoped",
      target: "control" | "victim") => ({
      phase, actor, target, startedAt: "2026-08-19T12:00:00.000Z",
      completedAt: "2026-08-19T12:00:00.000Z", method: "POST" as const,
      routeShapeExact: true, teamQueryExact: true, projectIdentifierSent: false as const,
      redirectMode: "error" as const, transportCalls: 1 as const, status: 200,
      contentType: "application/octet-stream" as const, responseBytes: 64,
      exactExpectedMarker: true, boundedAuthError: false, transportError: false,
    });
    const authority: Sbx056AuthorityProof = {
      ownerAliasExact: true, ownerTeamExact: true, ownerControlProjectExact: true,
      ownerVictimProjectExact: true, scopedControlProjectExact: true,
      scopedVictimProjectDenied: true, scopedVictimProjectStatus: 403,
      scopedTokenProjectRestrictionManuallyConfirmed: true,
      ownerAndScopedTokensDistinct: true,
    };
    const input = { authority,
      control: exact("public-control", "project-scoped", "control"),
      victimOwner: exact("owner-victim-control", "owner", "victim"),
      controlTarget: journal.targets[0], victimTarget: journal.targets[1] };
    expect(sbx056CrossDispatchGate(input)).toBe(true);
    expect(sbx056CrossDispatchGate({ ...input,
      control: { ...input.control, exactExpectedMarker: false } })).toBe(false);
    expect(sbx056CrossDispatchGate({ ...input,
      authority: { ...authority, scopedVictimProjectDenied: false } })).toBe(false);
    expect(sbx056CrossDispatchGate({ ...input,
      victimTarget: { ...journal.targets[1], provenanceValidated: false } })).toBe(false);
  });

  it("is import-safe and does not execute main while being tested", () => {
    expect(exactSbx056Handle).toBeTypeOf("function");
  });
});
