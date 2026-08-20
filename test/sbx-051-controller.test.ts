import { readFileSync } from "node:fs";
import { Sandbox } from "@vercel/sandbox";
import { describe, expect, it } from "vitest";
import {
  createSbx051RequestGate,
} from "../pocs/SBX-051/interactive-token-binding.js";
import {
  SBX051_PROJECT,
  SBX051_TEAM,
  createSbx051Journal,
} from "../pocs/SBX-051/safety.js";

const pat = "offline_controller_pat_never_sent_051";
const sessionA = "sbx_offline_controller_session_A_051";

function fakeClock() {
  let milliseconds = 0;
  return {
    now: () => milliseconds,
    wait: async (duration: number) => { milliseconds += duration; },
  };
}

function authorization() {
  return { authorization: `Bearer ${pat}` };
}

describe("SBX-051 controller request and evidence gate", () => {
  it("serializes allowlisted starts, retains no IDs/query/token, and counts exact raw issuance", async () => {
    const rawUrls: string[] = [];
    const rawFetch = (async (input: string | URL | Request) => {
      rawUrls.push(input.toString());
      return Response.json({ ok: true });
    }) as typeof fetch;
    const journal = createSbx051Journal();
    const clock = fakeClock();
    const gate = createSbx051RequestGate(rawFetch, pat, journal.resources, clock);
    gate.registerSession("A", sessionA);

    await gate.fetch("https://api.vercel.com/v2/user", { headers: authorization() });
    await gate.fetch(
      `https://vercel.com/api/v2/sandboxes/sessions/${sessionA}/interactive?teamId=${SBX051_TEAM}`,
      {
        method: "POST",
        headers: { ...authorization(), "content-type": "application/json" },
        body: "{}",
      },
    );

    expect(rawUrls).toHaveLength(2);
    const summary = gate.summary();
    expect(summary).toMatchObject({
      count: 2,
      allAllowlisted: true,
      contiguous: true,
      completed: true,
      withinRateLimit: true,
      minimumStartIntervalMs: 250,
      rawInteractiveCredentialRequests: 1,
      websocketConnections: 0,
      unexpectedRequests: 0,
    });
    const durable = JSON.stringify(summary);
    expect(durable).not.toContain(pat);
    expect(durable).not.toContain(sessionA);
    expect(durable).not.toContain("teamId=");
  });

  it("admits only the exact interactive create shape and no guest environment", async () => {
    let rawCalls = 0;
    const rawFetch = (async () => {
      rawCalls += 1;
      return Response.json({ ok: true });
    }) as typeof fetch;
    const journal = createSbx051Journal();
    const clock = fakeClock();
    const gate = createSbx051RequestGate(rawFetch, pat, journal.resources, clock);
    const plan = journal.resources[0];
    const exactBody = {
      projectId: SBX051_PROJECT,
      ports: [],
      timeout: 240_000,
      resources: { vcpus: 2 },
      name: plan.name,
      persistent: false,
      networkPolicy: { mode: "deny-all" },
      tags: plan.tags,
      __interactive: true,
    };
    const url = `https://vercel.com/api/v3/sandboxes?teamId=${SBX051_TEAM}`;
    await gate.fetch(url, {
      method: "POST",
      headers: { ...authorization(), "content-type": "application/json" },
      body: JSON.stringify(exactBody),
    });
    await expect(gate.fetch(url, {
      method: "POST",
      headers: { ...authorization(), "content-type": "application/json" },
      body: JSON.stringify({ ...exactBody, env: { SECRET: "forbidden" } }),
    })).rejects.toThrow("nonexact sandbox create");
    expect(rawCalls).toBe(1);
  });

  it("blocks foreign origins, queries, credentials, and sessions before network I/O", async () => {
    let rawCalls = 0;
    const rawFetch = (async () => {
      rawCalls += 1;
      return Response.json({ ok: true });
    }) as typeof fetch;
    const journal = createSbx051Journal();
    const gate = createSbx051RequestGate(rawFetch, pat, journal.resources, fakeClock());
    for (const request of [
      gate.fetch("https://example.test/v2/user", { headers: authorization() }),
      gate.fetch(`https://api.vercel.com/v2/user?teamId=${SBX051_TEAM}`, { headers: authorization() }),
      gate.fetch("https://api.vercel.com/v2/user", { headers: { authorization: "Bearer wrong" } }),
      gate.fetch(`https://vercel.com/api/v2/sandboxes/sessions/${sessionA}/interactive?teamId=${SBX051_TEAM}`, {
        method: "POST",
        headers: authorization(),
        body: "{}",
      }),
    ]) await expect(request).rejects.toThrow("request gate rejected");
    expect(rawCalls).toBe(0);
    expect(gate.summary().unexpectedRequests).toBe(4);
  });

  it("turns retryable responses into one AbortError with no SDK-visible retry opportunity", async () => {
    let rawCalls = 0;
    const rawFetch = (async () => {
      rawCalls += 1;
      return new Response("discarded", { status: 503 });
    }) as typeof fetch;
    const journal = createSbx051Journal();
    const gate = createSbx051RequestGate(rawFetch, pat, journal.resources, fakeClock());
    await expect(gate.fetch("https://api.vercel.com/v2/user", { headers: authorization() }))
      .rejects.toMatchObject({ name: "AbortError" });
    expect(rawCalls).toBe(1);
    expect(gate.summary()).toMatchObject({ count: 1, completed: true });
  });

  it("keeps the live controller raw, fixed-command, cross-absence aware, and free of custom TLS hooks", () => {
    const source = readFileSync("pocs/SBX-051/interactive-token-binding.ts", "utf8");
    const protocol = readFileSync("pocs/SBX-051/protocol.ts", "utf8");
    expect(source).toContain("issueInteractiveCredential");
    expect(source).toContain("if (!exactSbx051ReadbackPair(preReadbacks))");
    expect(source.indexOf("if (!exactSbx051ReadbackPair(preReadbacks))")).toBeLessThan(
      source.indexOf('issueInteractiveCredential(config, gate, "A"'),
    );
    expect(protocol).toContain('command: "/bin/cat"');
    expect(source).toContain("otherMarkerAbsent");
    expect(source).toContain("aAttackTokenUses === 1");
    expect(source).toContain("bTargetTokenUseCount: bTargetTokenUses");
    expect(source.match(/baseUrl: bTarget\.baseUrl/gu)).toHaveLength(2);
    expect(protocol).toContain("new InstalledWebSocket(url, wsOptions)");
    expect(protocol).toContain("`${base}?token=${encodeURIComponent(token)}`");
    expect(protocol).toContain("followRedirects: false");
    expect(protocol).toContain('socket.once("unexpected-response"');
    expect(source).toContain("SBX051_UNKNOWN_SESSION_ABSENCE_DELAY_MS");
    expect(source).toContain("exactNamedAndPrefixAbsent");
    expect(source).toContain("writeSbx051PrivateJsonNoClobber(recoveryArtifactPath, artifact)");
    expect(source).toContain("cannot resolve a response-lost create");
    expect(source.indexOf("await lock.release();")).toBeLessThan(
      source.indexOf("await removeJournal();"),
    );
    expect(source).not.toContain(".openInteractive(");
    expect(source).not.toMatch(/\bca\s*:/u);
    expect(source).not.toMatch(/secureContext\s*:/u);
    expect(source).not.toMatch(/checkServerIdentity\s*:/u);
    expect(typeof Sandbox.create).toBe("function");
  });
});
