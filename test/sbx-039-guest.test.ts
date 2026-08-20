import { execFile as execFileCallback } from "node:child_process";
import { resolve } from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFile = promisify(execFileCallback);
const probe = resolve("guest/mysql-upgrade-probe.py");
const scopeConfirmation = "I_CONTROL_DISTINCT_ALLOWED_AND_DENIED_ENDPOINTS_AND_AUTHORIZE_BOUNDED_MYSQL_PRETLS_TESTING";
const runId = "eb8645e5-dfb0-4c0e-83d8-2268c6ce1cd2";

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function publicConfiguration(mode: "direct-tls" | "raw-public" | "mysql-split-public" | "mysql-coalesced-public") {
  return {
    scopeConfirmation,
    mode,
    runId,
    testId: "SBX-039-POC",
    caseId: "public-plan",
    endpointRole: "denied",
    endpointHostname: "b.example.com",
    pinnedIPv4: "8.8.8.8",
    pinnedPort: 3306,
    publicCanary: "0123456789abcdef0123456789abcdef",
    ...(mode.startsWith("mysql-") ? { greetingTag: "0123456789abcdef" } : {}),
    timeoutMs: 3_000,
    maxResponseBytes: 512,
  };
}

describe("SBX-039 guest probe", () => {
  it("plans one coalesced MySQL flight without making a network attempt", async () => {
    const { stdout, stderr } = await execFile("python3", [probe, encode(publicConfiguration("mysql-coalesced-public")), "--plan"]);
    expect(stderr).toBe("");
    expect(JSON.parse(stdout)).toMatchObject({
      ok: true,
      phase: "plan",
      mode: "mysql-coalesced-public",
      testId: "SBX-039-POC",
      attemptCount: 1,
      retryCount: 0,
      sslRequestExact: true,
      maximumNetworkAttempts: 1,
      serverFirstGreetingRequired: true,
      rawConfigurationRetained: false,
      rawServerNameRetained: false,
      rawOperatorSecretRetained: false,
    });
  });

  it("keeps the secret out of configuration and fixes its source to the mode-0600 guest file", async () => {
    const configuration = {
      scopeConfirmation,
      mode: "mysql-coalesced-secret",
      runId,
      testId: "SBX-039-POC",
      caseId: "secret-plan",
      endpointRole: "denied",
      endpointHostname: "b.example.com",
      pinnedIPv4: "8.8.8.8",
      pinnedPort: 3306,
      greetingTag: "0123456789abcdef",
      timeoutMs: 3_000,
      maxResponseBytes: 512,
    };
    const { stdout } = await execFile("python3", [probe, encode(configuration), "--plan"]);
    const parsed = JSON.parse(stdout);
    expect(parsed).toMatchObject({ mode: "mysql-coalesced-secret", secretPathFixed: true });
    expect(parsed).not.toHaveProperty("serverNameKind");
    expect(JSON.stringify(parsed)).not.toContain("operator-secret");
  });

  it("rejects unknown fields with a sanitized configuration error", async () => {
    const configuration = { ...publicConfiguration("direct-tls"), injectedSecret: "must-not-print" };
    let stdout = "";
    try {
      await execFile("python3", [probe, encode(configuration), "--plan"]);
      throw new Error("probe unexpectedly accepted an unknown field");
    } catch (error) {
      const failure = error as Error & { stdout?: string; code?: number };
      stdout = failure.stdout ?? "";
      expect(failure.code).toBe(20);
    }
    expect(JSON.parse(stdout)).toMatchObject({
      ok: false,
      phase: "configuration",
      rawConfigurationRetained: false,
      rawServerNameRetained: false,
      rawOperatorSecretRetained: false,
    });
    expect(stdout).not.toContain("must-not-print");
  });
});
