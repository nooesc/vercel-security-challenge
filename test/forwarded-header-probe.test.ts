import { execFile } from "node:child_process";
import http, { type IncomingMessage } from "node:http";
import net from "node:net";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";

const executeFile = promisify(execFile);
const guestProbe = fileURLToPath(new URL("../guest/forwarded-header-probe.mjs", import.meta.url));
const servers: Array<http.Server | net.Server> = [];

function encodeConfig(overrides: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify({
    scopeConfirmation: "researcher-controlled-endpoints-only",
    researcherControlledHosts: ["127.0.0.1"],
    allowInsecureLoopbackForTesting: true,
    baseUrl: "http://127.0.0.1:9",
    runId: "run-forward-test",
    testId: "SBX-023-POC",
    caseId: "duplicate-case",
    rawPath: "/forwarded-test",
    rawHeaders: [],
    timeoutMs: 2_000,
    ...overrides,
  })).toString("base64url");
}

async function startServer(): Promise<{ origin: string; seen: IncomingMessage[] }> {
  const seen: IncomingMessage[] = [];
  const server = http.createServer((request, response) => {
    seen.push(request);
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test server has no TCP address");
  return { origin: `http://127.0.0.1:${address.port}`, seen };
}

async function startResetServer(): Promise<{ origin: string; port: number }> {
  const server = net.createServer((socket) => socket.destroy());
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("reset server has no TCP address");
  return { origin: `http://127.0.0.1:${address.port}`, port: address.port };
}

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
  );
});

describe("guest forwarded-header probe", () => {
  it("puts differently cased duplicate reserved headers on the HTTP/1 wire in order", async () => {
    const { origin, seen } = await startServer();
    const result = await executeFile(process.execPath, [
      guestProbe,
      encodeConfig({
        baseUrl: origin,
        rawHeaders: [
          ["x-sbx-forward-case", "duplicate-host"],
          ["x-sbx-harness-canary", "correlation-only"],
          ["Vercel-Forwarded-Host", "b.controlled.example"],
          ["vercel-forwarded-host", "a.controlled.example"],
          ["VERCEL-FORWARDED-PATH", "/v1/probe/run-forward-test/forwarded-action"],
          ["vercel-forwarded-path", "/v1/probe/run-forward-test/source"],
        ],
      }),
    ]);
    expect(JSON.parse(result.stdout)).toMatchObject({
      ok: true,
      statusCode: 200,
      responseJsonValid: true,
      outboundHeaderNames: [
        "x-sbx-forward-case",
        "x-sbx-harness-canary",
        "Vercel-Forwarded-Host",
        "vercel-forwarded-host",
        "VERCEL-FORWARDED-PATH",
        "vercel-forwarded-path",
      ],
    });
    expect(JSON.parse(result.stdout)).not.toHaveProperty("body");
    expect(seen).toHaveLength(1);
    const raw = seen[0]?.rawHeaders ?? [];
    const relevant: string[] = [];
    for (let index = 0; index + 1 < raw.length; index += 2) {
      const name = raw[index];
      const value = raw[index + 1];
      if (name?.toLowerCase().startsWith("vercel-forwarded-")) relevant.push(name, value ?? "");
    }
    expect(relevant).toEqual([
      "Vercel-Forwarded-Host",
      "b.controlled.example",
      "vercel-forwarded-host",
      "a.controlled.example",
      "VERCEL-FORWARDED-PATH",
      "/v1/probe/run-forward-test/forwarded-action",
      "vercel-forwarded-path",
      "/v1/probe/run-forward-test/source",
    ]);
  });

  it("rejects non-controlled destinations and connection-shaping raw headers", async () => {
    const destination = await startServer();
    const uncontrolled = await executeFile(process.execPath, [
      guestProbe,
      encodeConfig({ baseUrl: destination.origin, researcherControlledHosts: ["example.com"] }),
    ]).catch((error: unknown) => error as { stdout?: string });
    expect(JSON.parse(uncontrolled.stdout ?? "{}")).toMatchObject({
      ok: false,
      errorPhase: "configuration",
      errorCode: "INVALID_CONFIGURATION",
    });

    const forbidden = await executeFile(process.execPath, [
      guestProbe,
      encodeConfig({ baseUrl: destination.origin, rawHeaders: [["Host", "spoofed.example"]] }),
    ]).catch((error: unknown) => error as { stdout?: string });
    expect(JSON.parse(forbidden.stdout ?? "{}")).toMatchObject({
      ok: false,
      errorPhase: "configuration",
      errorCode: "INVALID_CONFIGURATION",
    });
  });

  it("requires a pinned connect address to appear in the controlled IPv4 set", async () => {
    const destination = await startServer();
    const rejected = await executeFile(process.execPath, [
      guestProbe,
      encodeConfig({
        baseUrl: destination.origin,
        connectIp: "127.0.0.1",
        researcherControlledIpv4s: ["192.0.2.10"],
      }),
    ]).catch((error: unknown) => error as { stdout?: string });
    expect(JSON.parse(rejected.stdout ?? "{}")).toMatchObject({
      ok: false,
      errorPhase: "configuration",
      errorCode: "INVALID_CONFIGURATION",
    });

    const accepted = await executeFile(process.execPath, [
      guestProbe,
      encodeConfig({
        baseUrl: destination.origin,
        connectIp: "127.0.0.1",
        researcherControlledIpv4s: ["127.0.0.1"],
      }),
    ]);
    expect(JSON.parse(accepted.stdout)).toMatchObject({
      ok: true,
      connectIpUsed: "127.0.0.1",
      tcpConnected: true,
      remoteAddress: "127.0.0.1",
      remotePort: Number(new URL(destination.origin).port),
      responseStarted: true,
    });
  });

  it("retains the connected TCP peer when the peer resets before any response", async () => {
    const reset = await startResetServer();
    const result = await executeFile(process.execPath, [
      guestProbe,
      encodeConfig({
        baseUrl: reset.origin,
        connectIp: "127.0.0.1",
        researcherControlledIpv4s: ["127.0.0.1"],
      }),
    ]);
    expect(JSON.parse(result.stdout)).toMatchObject({
      ok: false,
      errorPhase: "connect",
      errorCode: "ECONNRESET",
      connectIpUsed: "127.0.0.1",
      tcpConnected: true,
      remoteAddress: "127.0.0.1",
      remotePort: reset.port,
      tlsEstablished: false,
      responseStarted: false,
    });
  });
});
