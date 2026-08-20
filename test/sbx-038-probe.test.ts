import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import net, { type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import tls, { type Server as TlsServer } from "node:tls";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const execute = promisify(execFile);
const probe = fileURLToPath(new URL("../guest/connect-authority-probe.mjs", import.meta.url));
let fixtureDirectory = "";
let certificate = "";
let privateKey = "";
let certificatePath = "";
const servers: TlsServer[] = [];

beforeAll(async () => {
  fixtureDirectory = await mkdtemp(join(tmpdir(), "sbx038-test-"));
  const keyPath = join(fixtureDirectory, "key.pem");
  const certPath = join(fixtureDirectory, "cert.pem");
  certificatePath = certPath;
  await execute("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
    "-keyout", keyPath, "-out", certPath,
  ]);
  [privateKey, certificate] = await Promise.all([readFile(keyPath, "utf8"), readFile(certPath, "utf8")]);
});

afterAll(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  if (fixtureDirectory) await rm(fixtureDirectory, { recursive: true });
});

function encode(overrides: Record<string, unknown> = {}): string {
  return Buffer.from(JSON.stringify({
    scopeConfirmation: "I_CONTROL_BOTH_SBX038_ORIGINS_AND_AUTHORIZE_BOUNDED_CONNECT_AUTHORITY_TESTING",
    researcherControlledHosts: ["localhost", "b.localhost"],
    runId: "local-sbx038-run",
    mode: "connect-a",
    caseId: "local-connect-a",
    correlationCanary: "public-canary",
    outerHost: "localhost",
    outerPort: 443,
    targetHost: "localhost",
    targetPort: 443,
    nestedPath: "/nested",
    timeoutMs: 3_000,
    maxResponseBytes: 4_096,
    ...overrides,
  })).toString("base64url");
}

async function run(configuration: string): Promise<Record<string, unknown>> {
  const environment: NodeJS.ProcessEnv = { ...process.env, NODE_EXTRA_CA_CERTS: certificatePath };
  delete environment.NODE_OPTIONS;
  delete environment.NODE_TLS_REJECT_UNAUTHORIZED;
  const result = await execute(process.execPath, [probe, configuration], { env: environment });
  return JSON.parse(result.stdout) as Record<string, unknown>;
}

async function startTlsServer(connection: (socket: tls.TLSSocket) => void): Promise<{ server: TlsServer; port: number }> {
  const server = tls.createServer({ key: privateKey, cert: certificate, ALPNProtocols: ["http/1.1"] }, connection);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, port: (server.address() as AddressInfo).port };
}

describe("SBX-038 guest CONNECT probe", () => {
  it("sends exact authority-form B with outer Host A and accepts a terminal 405", async () => {
    let request = "";
    const outer = await startTlsServer((socket) => {
      socket.once("data", (chunk) => {
        request = Buffer.from(chunk).toString("latin1");
        socket.end([
          "HTTP/1.1 405 Method Not Allowed",
          "Content-Length: 0",
          "X-SBX038-Terminal: 1",
          "Connection: close",
          "",
          "",
        ].join("\r\n"));
      });
    });
    const result = await run(encode({
      mode: "connect-b-public",
      caseId: "public-connect-b",
      outerPort: outer.port,
      targetHost: "b.localhost",
      targetPort: 443,
      nestedPath: "/v1/sbx038/action/run",
    }));
    expect(result).toMatchObject({
      ok: false,
      mode: "connect-b-public",
      outerHost: "localhost",
      targetHost: "b.localhost",
      connectAuthority: "b.localhost:443",
      connectHostHeader: "localhost",
      connectionAttempts: 1,
      retryCount: 0,
      maximumRequests: 2,
      actualRequests: 1,
      tunnelEstablished: false,
      connectResponse: { statusCode: 405, terminalConnectHeader: true, bodyBytes: 0 },
      trustEnvironmentNames: ["NODE_EXTRA_CA_CERTS"],
      trustEnvironmentScanComplete: true,
      trustOverridesForbidden: true,
    });
    expect(request.split("\r\n").slice(0, 3)).toEqual([
      "CONNECT b.localhost:443 HTTP/1.1",
      "Host: localhost",
      "User-Agent: sbx-038-deterministic-probe/1",
    ]);
  });

  it("performs verified TLS inside one established CONNECT tunnel", async () => {
    const nested = await startTlsServer((socket) => {
      socket.once("data", (chunk) => {
        expect(Buffer.from(chunk).toString("latin1")).toContain("GET /nested HTTP/1.1\r\nHost: localhost\r\n");
        const body = JSON.stringify({ operationId: `cx_${"A".repeat(32)}` });
        socket.end(`HTTP/1.1 200 OK\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`);
      });
    });
    const outer = await startTlsServer((socket) => {
      socket.once("data", (chunk) => {
        expect(Buffer.from(chunk).toString("latin1")).toContain(`CONNECT localhost:${nested.port} HTTP/1.1`);
        const upstream = net.connect(nested.port, "127.0.0.1", () => {
          socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
          socket.pipe(upstream).pipe(socket);
        });
      });
    });
    const result = await run(encode({ outerPort: outer.port, targetPort: nested.port }));
    expect(result).toMatchObject({
      ok: true,
      mode: "connect-a",
      connectionAttempts: 1,
      retryCount: 0,
      maximumRequests: 2,
      actualRequests: 2,
      tunnelEstablished: true,
      connectResponse: { statusCode: 200, terminalConnectHeader: false },
      outerTls: { servername: "localhost", authorized: true },
      nestedTls: { servername: "localhost", authorized: true },
      nestedResponse: { statusCode: 200, operationId: `cx_${"A".repeat(32)}` },
      trustEnvironmentNames: ["NODE_EXTRA_CA_CERTS"],
    });
  });

  it("rejects missing scope, unknown sensitive fields, and misplaced secret paths before connecting", async () => {
    await expect(run(encode({ scopeConfirmation: false, outerPort: 9 }))).resolves.toEqual({
      ok: false,
      error: "scopeConfirmation must equal I_CONTROL_BOTH_SBX038_ORIGINS_AND_AUTHORIZE_BOUNDED_CONNECT_AUTHORITY_TESTING",
    });
    await expect(run(encode({ authorization: "Bearer nope", outerPort: 9 }))).resolves.toEqual({
      ok: false,
      error: "sensitive configuration field authorization is not allowed",
    });
    await expect(run(encode({ secretFilePath: "/tmp/sbx-038/value", outerPort: 9 }))).resolves.toEqual({
      ok: false,
      error: "secretFilePath is allowed only for connect-b-secret",
    });
    await expect(run(encode({ caPem: certificate, outerPort: 9 }))).resolves.toEqual({
      ok: false,
      error: "unknown configuration field caPem",
    });
  });

  it("records zero HTTP writes when direct B fails before TLS", async () => {
    const result = await run(encode({
      researcherControlledHosts: ["localhost", "blocked.invalid"],
      mode: "direct-b",
      caseId: "public-direct-b-pre",
      outerHost: "blocked.invalid",
      outerPort: 443,
      outerPath: "/v1/sbx038/direct/run",
      targetHost: undefined,
      targetPort: undefined,
      nestedPath: undefined,
    }));
    expect(result).toMatchObject({
      ok: false,
      mode: "direct-b",
      maximumRequests: 1,
      actualRequests: 0,
      connectionAttempts: 1,
      retryCount: 0,
    });
  });
});
