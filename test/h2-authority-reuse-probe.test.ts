import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const executeFile = promisify(execFile);
const probe = fileURLToPath(
  new URL("../guest/h2-authority-reuse-probe.mjs", import.meta.url),
);

function payload(overrides: Record<string, unknown> = {}): string {
  return Buffer.from(
    JSON.stringify({
      scopeConfirmation: "researcher-controlled-endpoints-only",
      researcherControlledHosts: [
        "203.0.113.20",
        "a.research.test",
        "b.research.test",
      ],
      runId: "run-h2-authority-test",
      testId: "SBX-009",
      caseId: "one-session-a-b-a-authorities",
      sequence: "a-b-a-reuse",
      destinationHost: "203.0.113.20",
      destinationPort: 443,
      tlsServername: "a.research.test",
      streams: [
        {
          id: "authority-a-control",
          authority: "a.research.test",
          method: "GET",
          path: "/h2?case=a",
          headers: { "x-sbx-correlation": "non-secret-a" },
        },
        {
          id: "authority-b-test",
          authority: "b.research.test:443",
          method: "GET",
          path: "/h2?case=b",
          headers: { "x-sbx-correlation": "non-secret-b" },
        },
        {
          id: "authority-a-final",
          authority: "a.research.test",
          method: "GET",
          path: "/h2?case=a-final",
          headers: { "x-sbx-correlation": "non-secret-a-final" },
        },
      ],
      timeoutMs: 2_000,
      ...overrides,
    }),
  ).toString("base64url");
}

async function plan(encodedPayload: string) {
  const result = await executeFile(process.execPath, [probe, encodedPayload, "--plan"]);
  return JSON.parse(result.stdout) as {
    ok: boolean;
    mode: string;
    connection: Record<string, unknown>;
    streams: Array<{ id: string; headers: Record<string, string> }>;
  };
}

async function rejectedPlan(encodedPayload: string) {
  try {
    await executeFile(process.execPath, [probe, encodedPayload, "--plan"]);
    throw new Error("expected HTTP/2 authority-reuse validation to fail");
  } catch (error) {
    const failure = error as Error & { stdout?: string; code?: number };
    return {
      code: failure.code,
      result: JSON.parse(failure.stdout ?? "{}") as { ok: boolean; phase: string; error: string },
    };
  }
}

describe("guest HTTP/2 authority-reuse probe", () => {
  it("plans one verified TLS session with a sequential A/B/A authority pattern", async () => {
    const result = await plan(payload());

    expect(result).toMatchObject({
      ok: true,
      mode: "plan",
      connection: {
        origin: "https://203.0.113.20:443",
        servername: "a.research.test",
        rejectUnauthorized: true,
      },
    });
    expect(result.streams.map((stream) => ({
      id: stream.id,
      method: stream.headers[":method"],
      authority: stream.headers[":authority"],
      path: stream.headers[":path"],
    }))).toEqual([
      {
        id: "authority-a-control",
        method: "GET",
        authority: "a.research.test",
        path: "/h2?case=a",
      },
      {
        id: "authority-b-test",
        method: "GET",
        authority: "b.research.test:443",
        path: "/h2?case=b",
      },
      {
        id: "authority-a-final",
        method: "GET",
        authority: "a.research.test",
        path: "/h2?case=a-final",
      },
    ]);
    expect(result.streams[0]?.headers["x-sbx-correlation"]).toBe("<redacted>");
  });

  it("rejects an undeclared B authority", async () => {
    const failure = await rejectedPlan(payload({
      streams: [
        { id: "a", authority: "a.research.test", path: "/a" },
        { id: "b", authority: "unowned.example", path: "/b" },
        { id: "a-final", authority: "a.research.test", path: "/a-final" },
      ],
    }));

    expect(failure.code).toBe(2);
    expect(failure.result.error).toBe(
      "streams[1].authority is not listed in researcherControlledHosts",
    );
  });

  it("rejects attempts to weaken certificate verification", async () => {
    const failure = await rejectedPlan(payload({ rejectUnauthorized: false }));

    expect(failure.code).toBe(2);
    expect(failure.result.error).toContain("live TLS verification is mandatory");
  });

  it("supports a fresh single-stream H2 mismatch control", async () => {
    const result = await plan(payload({
      sequence: "single-stream",
      streams: [
        { id: "fresh-b", authority: "b.research.test", path: "/fresh-b" },
      ],
    }));

    expect(result.streams).toHaveLength(1);
    expect(result.streams[0]?.headers[":authority"]).toBe("b.research.test");
    expect(result.connection).toMatchObject({ servername: "a.research.test" });
  });

  it("requires A/B/A authority placement in reuse mode", async () => {
    const failure = await rejectedPlan(payload({
      streams: [
        { id: "b-first", authority: "b.research.test", path: "/b" },
        { id: "a-second", authority: "a.research.test", path: "/a" },
        { id: "a-final", authority: "a.research.test", path: "/a-final" },
      ],
    }));

    expect(failure.code).toBe(2);
    expect(failure.result.error).toContain("first and third authorities");
  });

  it("requires a distinct B authority on the middle stream", async () => {
    const failure = await rejectedPlan(payload({
      streams: [
        { id: "a-one", authority: "a.research.test", path: "/one" },
        { id: "a-two", authority: "a.research.test:443", path: "/two" },
        { id: "a-three", authority: "a.research.test", path: "/three" },
      ],
    }));

    expect(failure.code).toBe(2);
    expect(failure.result.error).toContain("distinct authority B");
  });

  it("rejects a competing Host header", async () => {
    const failure = await rejectedPlan(payload({
      streams: [
        {
          id: "a",
          authority: "a.research.test",
          path: "/a",
          headers: { host: "b.research.test" },
        },
        { id: "b", authority: "b.research.test", path: "/b" },
        { id: "a-final", authority: "a.research.test", path: "/a-final" },
      ],
    }));

    expect(failure.code).toBe(2);
    expect(failure.result.error).toContain("use the stream authority field");
  });
});
