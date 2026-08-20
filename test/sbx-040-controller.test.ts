import { describe, expect, it } from "vitest";
import {
  controlledOrigins,
  explicitCredentials,
  probeConfiguration,
  sanitizeGuest,
} from "../pocs/SBX-040/http1-desync.js";

const scope = "I_CONTROL_BOTH_SBX040_VIRTUAL_HOSTS_AND_AUTHORIZE_BOUNDED_HTTP1_DESYNC_TESTING";

describe("SBX-040 controller preflight", () => {
  it("requires two exact owned public origins and a loopback-only admin origin", () => {
    expect(controlledOrigins({
      SBX040_SCOPE_CONFIRMATION: scope,
      SBX040_A_PUBLIC_ORIGIN: "https://a.research.test",
      SBX040_B_PUBLIC_ORIGIN: "https://b.research.test",
      SBX040_ADMIN_ORIGIN: "http://127.0.0.1:43140",
    })).toMatchObject({
      a: { hostname: "a.research.test" },
      b: { hostname: "b.research.test" },
      admin: { hostname: "127.0.0.1", port: "43140" },
    });
    expect(() => controlledOrigins({
      SBX040_SCOPE_CONFIRMATION: scope,
      SBX040_A_PUBLIC_ORIGIN: "https://a.research.test",
      SBX040_B_PUBLIC_ORIGIN: "https://b.research.test",
      SBX040_ADMIN_ORIGIN: "https://receiver.example.test",
    })).toThrow(/loopback/u);
  });

  it("pins the verified HackerOne team/project and keeps transform material out of guest configuration", () => {
    expect(explicitCredentials({
      VERCEL_TOKEN: "token-fixture",
      VERCEL_TEAM_ID: "team_n98ERpVwV7HqmWRudAyK8sXQ",
      VERCEL_PROJECT_ID: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    })).toEqual({
      token: "token-fixture",
      teamId: "team_n98ERpVwV7HqmWRudAyK8sXQ",
      projectId: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    });
    const config = probeConfiguration({
      mode: "ambiguous-plus-a",
      caseId: "run:attack",
      runId: "run",
      canary: "canary",
      aHost: "a.research.test",
      bHost: "b.research.test",
    });
    expect(JSON.stringify(config)).not.toMatch(/credential|secret|token/iu);
    expect(config).toMatchObject({ outerHost: "a.research.test", outerPort: 443, mode: "ambiguous-plus-a" });
  });

  it("sanitizes malformed guest evidence into a non-candidate shape", () => {
    expect(sanitizeGuest({
      schemaVersion: 1,
      testId: "SBX-040-POC",
      caseId: "run:attack",
      mode: "invented-mode",
      rawCredentialRetained: true,
    }, "ambiguous-plus-a", "run:attack")).toMatchObject({
      mode: "ambiguous-plus-a",
      outerPort: -1,
      rawCredentialRetained: true,
      ok: false,
    });
  });
});
