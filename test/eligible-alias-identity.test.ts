import { describe, expect, it, vi } from "vitest";
import { verifyEligibleAliasToken } from "../pocs/eligible-alias-identity.js";

const base = {
  token: "scoped-test-token",
  expectedEmail: "swve@wearehackerone.com",
  expectedTeamId: "team_owned",
  expectedProjectId: "prj_owned",
};

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("eligible alias identity verification", () => {
  it("prefers an exact user-email proof", async () => {
    const fetchImpl = vi.fn(async () => json(200, { user: { email: base.expectedEmail } }));
    await expect(verifyEligibleAliasToken({ ...base, fetchImpl })).resolves.toMatchObject({
      email: base.expectedEmail,
      method: "v2-user-email",
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("requires manual confirmation before scoped-token fallback", async () => {
    const fetchImpl = vi.fn(async () => json(403, {}));
    await expect(verifyEligibleAliasToken({ ...base, fetchImpl })).rejects.toThrow(/manual HackerOne alias/u);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("accepts fallback only when both exact resources are readable", async () => {
    const fetchImpl = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      if (url.endsWith("/v2/user")) return json(403, {});
      if (url.includes("/v2/teams/")) return json(200, { id: base.expectedTeamId });
      return json(200, { id: base.expectedProjectId });
    });
    await expect(verifyEligibleAliasToken({
      ...base,
      manualEmailConfirmation: base.expectedEmail,
      fetchImpl,
    })).resolves.toMatchObject({ method: "manual-email-plus-exact-team-project-api" });
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  it("rejects a wrong resource binding", async () => {
    const fetchImpl = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      if (url.endsWith("/v2/user")) return json(403, {});
      if (url.includes("/v2/teams/")) return json(200, { id: "team_wrong" });
      return json(200, { id: base.expectedProjectId });
    });
    await expect(verifyEligibleAliasToken({
      ...base,
      manualEmailConfirmation: base.expectedEmail,
      fetchImpl,
    })).rejects.toThrow(/wrong team or project/u);
  });
});
