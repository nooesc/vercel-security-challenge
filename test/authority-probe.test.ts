import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const executeFile = promisify(execFile);
const authorityProbe = fileURLToPath(new URL("../guest/authority-probe.mjs", import.meta.url));

function payload(overrides: Record<string, unknown> = {}) {
  return Buffer.from(
    JSON.stringify({
      scopeConfirmation: "researcher-controlled-endpoints-only",
      researcherControlledHosts: [
        "203.0.113.10",
        "allowed.research.test",
        "denied.research.test",
      ],
      runId: "run-authority-test",
      testId: "SBX-008",
      caseId: "allowed-sni-denied-host",
      destinationHost: "203.0.113.10",
      destinationPort: 443,
      tlsServername: "allowed.research.test",
      httpHost: "denied.research.test:443",
      method: "GET",
      requestTarget: "/authority?case=fronting",
      headers: { "x-sbx-correlation": "non-secret-test-canary" },
      timeoutMs: 2_000,
      ...overrides,
    }),
  ).toString("base64url");
}

async function plan(encodedPayload: string) {
  const result = await executeFile(process.execPath, [authorityProbe, encodedPayload, "--plan"]);
  return JSON.parse(result.stdout) as {
    ok: boolean;
    mode: string;
    requestOptions: Record<string, unknown> & { headers: Record<string, string> };
  };
}

async function rejectedPlan(encodedPayload: string) {
  try {
    await executeFile(process.execPath, [authorityProbe, encodedPayload, "--plan"]);
    throw new Error("expected authority-probe validation to fail");
  } catch (error) {
    const failure = error as Error & { stdout?: string; code?: number };
    return {
      code: failure.code,
      result: JSON.parse(failure.stdout ?? "{}") as { ok: boolean; phase: string; error: string },
    };
  }
}

describe("guest authority probe", () => {
  it("separates the TCP destination, TLS SNI, and HTTP Host while keeping TLS verification enabled", async () => {
    const result = await plan(payload());

    expect(result).toMatchObject({
      ok: true,
      mode: "plan",
      requestOptions: {
        hostname: "203.0.113.10",
        port: 443,
        servername: "allowed.research.test",
        method: "GET",
        path: "/authority?case=fronting",
        timeout: 2_000,
        rejectUnauthorized: true,
        agent: false,
      },
    });
    expect(result.requestOptions.headers).toEqual({
      "x-sbx-correlation": "<redacted>",
      Host: "denied.research.test:443",
    });
  });

  it("rejects an authority not explicitly declared researcher-controlled", async () => {
    const failure = await rejectedPlan(payload({ httpHost: "unowned.example:443" }));

    expect(failure.code).toBe(2);
    expect(failure.result).toMatchObject({
      ok: false,
      phase: "configuration",
      error: "httpHost is not listed in researcherControlledHosts",
    });
  });

  it("rejects attempts to override certificate verification", async () => {
    const failure = await rejectedPlan(payload({ rejectUnauthorized: false }));

    expect(failure.code).toBe(2);
    expect(failure.result.ok).toBe(false);
    expect(failure.result.error).toContain("live TLS verification is mandatory");
  });

  it("rejects a competing Host header so the intended authority is unambiguous", async () => {
    const failure = await rejectedPlan(
      payload({ headers: { host: "another.research.test", "x-sbx-correlation": "test" } }),
    );

    expect(failure.code).toBe(2);
    expect(failure.result.error).toContain("use the dedicated httpHost field");
  });

  it("supports absolute-form request targets without conflating their authority with Host", async () => {
    const result = await plan(
      payload({ requestTarget: "https://allowed.research.test/authority?case=absolute-form" }),
    );

    expect(result.requestOptions).toMatchObject({
      servername: "allowed.research.test",
      path: "https://allowed.research.test/authority?case=absolute-form",
    });
    expect(result.requestOptions.headers.Host).toBe("denied.research.test:443");
  });

  it("rejects an undeclared absolute-form authority", async () => {
    const failure = await rejectedPlan(
      payload({ requestTarget: "https://unowned.example/authority?case=absolute-form" }),
    );

    expect(failure.code).toBe(2);
    expect(failure.result.error).toBe(
      "requestTarget authority is not listed in researcherControlledHosts",
    );
  });
});
