import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import tls, { type Server as TlsServer } from "node:tls";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const execute = promisify(execFile);
const probe = fileURLToPath(new URL("../guest/tls-resumption-probe.mjs", import.meta.url));
let fixtureDirectory = "";
let certificate = "";
let privateKey = "";
let aOnlyCertificate = "";
let aOnlyPrivateKey = "";
const servers: TlsServer[] = [];

beforeAll(async () => {
  fixtureDirectory = await mkdtemp(join(tmpdir(), "sbx041-test-"));
  async function certificatePair(prefix: string, san: string): Promise<[string, string]> {
    const keyPath = join(fixtureDirectory, `${prefix}-key.pem`);
    const certPath = join(fixtureDirectory, `${prefix}-cert.pem`);
    await execute("openssl", [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
      "-subj", "/CN=a.localhost", "-addext", `subjectAltName=${san}`,
      "-keyout", keyPath, "-out", certPath,
    ]);
    return await Promise.all([readFile(keyPath, "utf8"), readFile(certPath, "utf8")]);
  }
  [privateKey, certificate] = await certificatePair("both", "DNS:a.localhost,DNS:b.localhost");
  [aOnlyPrivateKey, aOnlyCertificate] = await certificatePair("a-only", "DNS:a.localhost");
});

afterAll(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  if (fixtureDirectory) await rm(fixtureDirectory, { recursive: true });
});

async function startServer(input: {
  key: string;
  cert: string;
  ticketKeys: Buffer;
  operationId: string;
  onRequest?: (request: string) => void;
  onSecureConnection?: (servername: string | false) => void;
}): Promise<number> {
  const server = tls.createServer({
    key: input.key,
    cert: input.cert,
    ticketKeys: input.ticketKeys,
    minVersion: "TLSv1.2",
    maxVersion: "TLSv1.2",
    ALPNProtocols: ["http/1.1"],
  }, (socket) => {
    input.onSecureConnection?.((socket as unknown as { servername: string | false }).servername);
    let request = "";
    socket.on("data", (chunk) => {
      request += Buffer.from(chunk).toString("latin1");
      if (!request.includes("\r\n\r\n")) return;
      input.onRequest?.(request);
      const body = JSON.stringify({ operationId: input.operationId });
      socket.end(`HTTP/1.1 200 OK\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`);
    });
  });
  servers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "::1", () => { server.off("error", reject); resolve(); });
  });
  return (server.address() as AddressInfo).port;
}

function configuration(overrides: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify({
    scopeConfirmation: "I_CONTROL_BOTH_SBX041_ORIGINS_AND_AUTHORIZE_BOUNDED_TLS_RESUMPTION_TESTING",
    researcherControlledHosts: ["a.localhost", "b.localhost"],
    mode: "fronted-sni-resume",
    caseId: "fronted-sni-resume",
    correlationCanary: "local-canary",
    aHost: "a.localhost",
    aPort: 443,
    aPath: "/ticket",
    bHost: "b.localhost",
    bPort: 443,
    bPath: "/action",
    caPem: certificate,
    timeoutMs: 3_000,
    maxResponseBytes: 4_096,
    ...overrides,
  })).toString("base64url");
}

async function run(encoded: string): Promise<Record<string, unknown>> {
  const result = await execute(process.execPath, [probe, encoded]);
  return JSON.parse(result.stdout) as Record<string, unknown>;
}

describe("SBX-041 TLS resumption guest", () => {
  it.each([
    ["fronted-sni-resume", "b.localhost", false],
    ["fronted-nosni-resume", false, false],
  ] as const)("offers one A session on a fresh A-transport %s connection", async (mode, configuredBServername, onWireBServername) => {
    const observedSni: Array<string | false> = [];
    const requests: string[] = [];
    const serverPort = await startServer({
      key: privateKey,
      cert: certificate,
      ticketKeys: Buffer.alloc(48, 17),
      operationId: `rs_${"A".repeat(36)}`,
      onRequest: (request) => requests.push(request),
      onSecureConnection: (servername) => observedSni.push(servername),
    });
    const result = await run(configuration({ mode, caseId: mode, aPort: serverPort, bPort: serverPort }));
    expect(result).toMatchObject({
      ok: true,
      connectionAttempts: 2,
      retryCount: 0,
      totalHttpRequests: 2,
      bTargetRequests: 1,
      bAttackRequests: 1,
      sessionOffers: 1,
      freshBConnection: true,
      aCertificateValidForB: true,
      bIdentityValidatedAgainstAuthenticatedASessionCertificate: true,
      aTls: {
        transportHost: "a.localhost",
        identityHost: "a.localhost",
        configuredServername: "a.localhost",
        authorized: true,
        protocol: "TLSv1.2",
        sessionReused: false,
      },
      bTls: {
        transportHost: "a.localhost",
        identityHost: "b.localhost",
        configuredServername: configuredBServername || null,
        authorized: true,
        protocol: "TLSv1.2",
        sessionReused: true,
      },
    });
    expect(requests).toHaveLength(2);
    expect(requests[0]).toContain("Host: a.localhost\r\n");
    expect(requests[1]).toContain("Host: b.localhost\r\n");
    expect(observedSni).toEqual(["a.localhost", onWireBServername]);
  });

  it.each([
    ["fronted-sni-no-session", "b.localhost"],
    ["fronted-nosni-no-session", false],
  ] as const)("makes one matched %s no-session request with exact on-wire SNI", async (mode, expectedServername) => {
    const observedSni: Array<string | false> = [];
    const requests: string[] = [];
    const serverPort = await startServer({
      key: privateKey,
      cert: certificate,
      ticketKeys: Buffer.alloc(48, 19),
      operationId: `rs_${"B".repeat(36)}`,
      onRequest: (request) => requests.push(request),
      onSecureConnection: (servername) => observedSni.push(servername),
    });
    const result = await run(configuration({ mode, caseId: mode, aPort: serverPort, bPort: serverPort }));
    expect(result).toMatchObject({
      ok: true,
      connectionAttempts: 1,
      totalHttpRequests: 1,
      bTargetRequests: 1,
      bAttackRequests: 0,
      sessionOffers: 0,
      freshBConnection: true,
      bTls: {
        transportHost: "a.localhost",
        identityHost: "b.localhost",
        configuredServername: expectedServername || null,
        authorized: true,
        sessionReused: false,
      },
    });
    expect(requests).toHaveLength(1);
    expect(requests[0]).toContain("Host: b.localhost\r\n");
    expect(observedSni).toEqual([expectedServername]);
  });

  it("refuses to offer the session when A's authenticated certificate is not valid for B", async () => {
    const observedSni: Array<string | false> = [];
    const serverPort = await startServer({
      key: aOnlyPrivateKey,
      cert: aOnlyCertificate,
      ticketKeys: Buffer.alloc(48, 23),
      operationId: `rs_${"C".repeat(36)}`,
      onSecureConnection: (servername) => observedSni.push(servername),
    });
    const result = await run(configuration({
      aPort: serverPort,
      bPort: serverPort,
      caPem: `${aOnlyCertificate}\n${certificate}`,
    }));
    expect(result).toMatchObject({
      ok: false,
      connectionAttempts: 1,
      totalHttpRequests: 1,
      bTargetRequests: 0,
      bAttackRequests: 0,
      aCertificateValidForB: false,
      failClosedReason: "authenticated A session certificate is not valid for B",
    });
    expect(result).not.toHaveProperty("bTls");
    expect(observedSni).toEqual(["a.localhost"]);
  });
});
