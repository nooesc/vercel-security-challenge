import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  createVercelRequestGate,
  explicitConfiguration,
} from "../pocs/SBX-048/oidc-control-plane-confusion.js";

function environment(): NodeJS.ProcessEnv {
  return {
    VERCEL_TOKEN: "opaque-test-pat",
    VERCEL_TEAM_ID: "team_n98ERpVwV7HqmWRudAyK8sXQ",
    VERCEL_PROJECT_ID: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    SBX048_ALIAS_EMAIL_CONFIRMATION: "swve@wearehackerone.com",
    SBX048_SCOPE_CONFIRMATION: "I_CONTROL_SBX048_PROXY_ORIGIN_AND_AUTHORIZE_ONE_BOUNDED_OIDC_CONTROL_PLANE_TEST",
    SBX048_ADMIN_KEY: "a".repeat(64),
    SBX048_PUBLIC_ORIGIN: "https://p.example.test",
  };
}

describe("SBX-048 controller scope", () => {
  it("requires the exact alias team/project, owned origin, scope phrase, opaque PAT, and admin key", () => {
    expect(explicitConfiguration(environment())).toMatchObject({
      token: "opaque-test-pat",
      teamId: "team_n98ERpVwV7HqmWRudAyK8sXQ",
      projectId: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
      adminKey: "a".repeat(64),
    });
    for (const mutation of [
      { VERCEL_TEAM_ID: "team_other" },
      { VERCEL_PROJECT_ID: "prj_other" },
      { VERCEL_TOKEN: "eyJhbGciOiJSUzI1NiJ9.payload.signature" },
      { SBX048_SCOPE_CONFIRMATION: "yes" },
      { SBX048_PUBLIC_ORIGIN: "http://p.example.test" },
      { SBX048_PUBLIC_ORIGIN: "https://p.example.test/path" },
      { SBX048_ADMIN_KEY: "short" },
      { NODE_TLS_REJECT_UNAUTHORIZED: "0" },
      { NODE_OPTIONS: "--require=/tmp/injected.cjs" },
      { NODE_EXTRA_CA_CERTS: "/tmp/custom.pem" },
      { NODE_USE_SYSTEM_CA: "1" },
      { OPENSSL_CONF: "/tmp/openssl.cnf" },
      { OPENSSL_MODULES: "/tmp/modules" },
      { SSL_CERT_DIR: "/tmp/certs" },
      { SSL_CERT_FILE: "/tmp/cert.pem" },
    ]) expect(() => explicitConfiguration({ ...environment(), ...mutation })).toThrow();
  });

  it("allows only identity and Sandbox API families and records no query or credential values", async () => {
    const rawCalls: string[] = [];
    const rawFetch = (async (input: string | URL | globalThis.Request) => {
      rawCalls.push(input.toString());
      return Response.json({ ok: true });
    }) as typeof fetch;
    const gate = createVercelRequestGate(rawFetch);
    await gate.fetch("https://vercel.com/api/v2/sandboxes/sessions/sbx_owned?teamId=team_n98ERpVwV7HqmWRudAyK8sXQ");
    await expect(gate.fetch("https://vercel.com/api/v2/projects")).rejects.toThrow("request gate rejected");
    await expect(gate.fetch("https://vercel.com/api/v2/sandboxes?teamId=team_other")).rejects.toThrow("non-owned team");
    expect(rawCalls).toHaveLength(1);
    expect(gate.records).toHaveLength(1);
    expect(JSON.stringify(gate.records)).not.toContain("sbx_owned");
    expect(JSON.stringify(gate.records)).not.toContain("team_n98ERpVwV7HqmWRudAyK8sXQ");
  });

  it("keeps proxy-token use inside the raw receiver and fixes owner restoration", () => {
    const receiver = readFileSync(resolve("pocs/SBX-048/receiver.ts"), "utf8");
    const controller = readFileSync(resolve("pocs/SBX-048/oidc-control-plane-confusion.ts"), "utf8");
    expect(receiver).toContain("controlPlaneRead");
    expect(receiver).toContain("controlPlaneMutation");
    expect(receiver).not.toContain("new APIClient");
    expect(receiver).not.toContain("Sandbox.get");
    expect(controller).toContain("policyRestoreRequired");
    expect(controller).toContain("fail-safe restoration");
    expect(controller).not.toMatch(/\bca\s*:/u);
    expect(controller).not.toMatch(/secureContext\s*:/u);
    expect(controller).not.toMatch(/checkServerIdentity\s*:/u);
  });
});
