import { describe, expect, it } from "vitest";
import {
  SBX039_ALLOWED_HTTPS_ORIGIN,
  SBX039_SCOPE_CONFIRMATION,
  buildSbx039ProbeConfiguration,
  explicitSbx039Credentials,
  publicSbx039IPv4,
} from "../pocs/SBX-039/mysql-server-first-upgrade.js";

describe("SBX-039 public controller", () => {
  it("pins execution to the verified HackerOne-alias team and project", () => {
    expect(explicitSbx039Credentials({
      VERCEL_TOKEN: "token",
      VERCEL_TEAM_ID: "team_n98ERpVwV7HqmWRudAyK8sXQ",
      VERCEL_PROJECT_ID: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    })).toEqual({
      token: "token",
      teamId: "team_n98ERpVwV7HqmWRudAyK8sXQ",
      projectId: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    });
    expect(() => explicitSbx039Credentials({
      VERCEL_TOKEN: "token",
      VERCEL_TEAM_ID: "team_personal",
      VERCEL_PROJECT_ID: "prj_personal",
    })).toThrow(/HackerOne-alias/u);
  });

  it("builds one bounded public MySQL configuration without a secret source", () => {
    const configuration = buildSbx039ProbeConfiguration({
      mode: "mysql-coalesced-public",
      runId: "be44bfc6-064b-4080-a616-c93efef2d21f",
      caseId: "restricted-b-mysql-coalesced",
      endpointHostname: "b.example.com",
      endpointRole: "denied",
      pinnedIPv4: "8.8.8.8",
      pinnedPort: 3306,
      publicCanary: "0123456789abcdef0123456789abcdef",
      greetingTag: "0123456789abcdef",
    });
    expect(configuration).toMatchObject({
      scopeConfirmation: SBX039_SCOPE_CONFIRMATION,
      mode: "mysql-coalesced-public",
      testId: "SBX-039-POC",
      endpointRole: "denied",
      pinnedPort: 3306,
      timeoutMs: 3_000,
      maxResponseBytes: 512,
    });
    expect(configuration).not.toHaveProperty("operatorSecretPath");
    expect(configuration).not.toHaveProperty("expectedOperationId");
  });

  it("uses the fixed owned A origin and rejects non-public IPv4 topology", () => {
    expect(SBX039_ALLOWED_HTTPS_ORIGIN).toBe("https://vsc-h3-action-swve.cyrus-206.workers.dev");
    expect(publicSbx039IPv4("8.8.8.8")).toBe(true);
    expect(publicSbx039IPv4("127.0.0.1")).toBe(false);
    expect(publicSbx039IPv4("10.0.0.1")).toBe(false);
    expect(publicSbx039IPv4("198.51.100.20")).toBe(false);
    expect(publicSbx039IPv4("203.0.113.20")).toBe(false);
  });
});
