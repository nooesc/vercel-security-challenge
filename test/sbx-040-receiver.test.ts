import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import tls from "node:tls";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { startSbx040Receiver, type Sbx040ReceiverHandle } from "../pocs/SBX-040/receiver.js";
import {
  SBX040_TRANSFORM_HEADER,
  deriveSbx040Commitment,
  deriveSbx040OperationId,
} from "../pocs/SBX-040/verdict.js";

const executeFile = promisify(execFile);
const guestProbe = fileURLToPath(new URL("../guest/http1-desync-probe.mjs", import.meta.url));
const handles: Sbx040ReceiverHandle[] = [];
let directory = "";
let key = "";
let certificate = "";

beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), "sbx040-cert-"));
  const keyPath = join(directory, "key.pem");
  const certificatePath = join(directory, "cert.pem");
  await executeFile("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", keyPath,
    "-out", certificatePath,
    "-subj", "/CN=a.research.test",
    "-days", "1",
    "-addext", "subjectAltName=DNS:a.research.test,DNS:b.research.test",
  ]);
  [key, certificate] = await Promise.all([readFile(keyPath, "utf8"), readFile(certificatePath, "utf8")]);
});

afterEach(async () => {
  await Promise.all(handles.splice(0).map((handle) => handle.close()));
});

afterAll(async () => {
  if (directory) await rm(directory, { recursive: true, force: true });
});

async function fixture() {
  const adminKey = randomBytes(32).toString("hex");
  const credential = `credential_${randomBytes(32).toString("base64url")}`;
  const runId = "receiver-local-run";
  const canary = "local-canary";
  const handle = await startSbx040Receiver({
    adminKey,
    key,
    cert: certificate,
    rawHost: "127.0.0.1",
    rawPort: 0,
    adminPort: 0,
  });
  handles.push(handle);
  const admin = (path: string, init: RequestInit = {}) => fetch(`http://127.0.0.1:${handle.adminPort}${path}`, {
    ...init,
    headers: { authorization: `Bearer ${adminKey}`, "content-type": "application/json", ...init.headers },
  });
  const configured = await admin(`/v1/sbx040/admin/runs/${runId}`, {
    method: "PUT",
    body: JSON.stringify({
      runId,
      aHost: "a.research.test",
      bHost: "b.research.test",
      canary,
      credentialCommitment: deriveSbx040Commitment(adminKey, runId, credential),
    }),
  });
  expect(configured.status).toBe(204);
  return { adminKey, credential, runId, canary, handle, admin };
}

class ResponseReader {
  private buffer = Buffer.alloc(0);
  private readonly iterator: AsyncIterator<Buffer>;

  constructor(socket: tls.TLSSocket) {
    this.iterator = socket[Symbol.asyncIterator]() as AsyncIterator<Buffer>;
  }

  async read(): Promise<string> {
    while (true) {
      const end = this.buffer.indexOf("\r\n\r\n");
      if (end >= 0) {
        const result = this.buffer.subarray(0, end + 4).toString("latin1");
        this.buffer = this.buffer.subarray(end + 4);
        return result;
      }
      const next = await this.iterator.next();
      if (next.done) throw new Error("socket closed early");
      this.buffer = Buffer.concat([this.buffer, Buffer.from(next.value)]);
    }
  }
}

function connect(port: number): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: "127.0.0.1",
      port,
      servername: "a.research.test",
      rejectUnauthorized: true,
      ca: certificate,
      ALPNProtocols: ["http/1.1"],
    });
    socket.once("secureConnect", () => resolve(socket));
    socket.once("error", reject);
  });
}

function nestedPrefix(runId: string, caseId: string, canary: string): Buffer {
  return Buffer.from([
    `POST /v1/sbx040/${runId}/capture HTTP/1.1`,
    "Host: b.research.test",
    `X-SBX040-Case: ${caseId}`,
    `X-SBX040-Canary: ${canary}`,
    "Content-Length: 65535",
    "",
    "",
  ].join("\r\n"), "latin1");
}

function firstRequest(runId: string, caseId: string, canary: string, kind: "cl" | "te" | "cl-te"): Buffer {
  const nested = nestedPrefix(runId, caseId, canary);
  const body = kind === "te"
    ? Buffer.concat([Buffer.from(`${nested.length.toString(16)}\r\n`), nested, Buffer.from("\r\n0\r\n\r\n")])
    : Buffer.concat([Buffer.from("0\r\n\r\n"), nested]);
  return Buffer.concat([Buffer.from([
    `POST /v1/sbx040/${runId}/${kind} HTTP/1.1`,
    "Host: a.research.test",
    `X-SBX040-Case: ${caseId}`,
    `X-SBX040-Canary: ${canary}`,
    ...(kind === "te" ? ["Transfer-Encoding: chunked"] : [`Content-Length: ${body.length}`]),
    ...(kind === "cl-te" ? ["Transfer-Encoding: chunked"] : []),
    "",
    "",
  ].join("\r\n"), "latin1"), body]);
}

describe("SBX-040 raw owned receiver", () => {
  it("runs the normal-A guest path over one certificate-verified TLS connection", async () => {
    const f = await fixture();
    const caseId = `${f.runId}:normal-a`;
    const encoded = Buffer.from(JSON.stringify({
      scopeConfirmation: "I_CONTROL_BOTH_SBX040_VIRTUAL_HOSTS_AND_AUTHORIZE_BOUNDED_HTTP1_DESYNC_TESTING",
      mode: "normal-a",
      runId: f.runId,
      caseId,
      canary: f.canary,
      aHost: "a.research.test",
      bHost: "b.research.test",
      outerHost: "a.research.test",
      outerPort: f.handle.rawPort,
      connectAddress: "127.0.0.1",
      timeoutMs: 2_000,
      caPem: certificate,
    })).toString("base64url");
    const result = await executeFile(process.execPath, [guestProbe, encoded]);
    expect(JSON.parse(result.stdout)).toMatchObject({
      schemaVersion: 1,
      testId: "SBX-040-POC",
      caseId,
      mode: "normal-a",
      connectionAttempts: 1,
      tlsHandshakes: 1,
      actualRequests: 1,
      strictCertificateVerification: true,
      ok: true,
      firstResponse: { statusCode: 204, terminalHeader: true, bodyBytes: 0 },
    });
  });

  it("rejects credential-bearing or unknown guest configuration fields before I/O", async () => {
    const encoded = Buffer.from(JSON.stringify({
      scopeConfirmation: "I_CONTROL_BOTH_SBX040_VIRTUAL_HOSTS_AND_AUTHORIZE_BOUNDED_HTTP1_DESYNC_TESTING",
      mode: "normal-a",
      runId: "invalid-config",
      caseId: "invalid-config:normal-a",
      canary: "canary",
      aHost: "a.research.test",
      bHost: "b.research.test",
      outerHost: "a.research.test",
      outerPort: 9,
      transformCredential: "must-not-enter-guest",
    })).toString("base64url");
    const result = await executeFile(process.execPath, [guestProbe, encoded]);
    expect(JSON.parse(result.stdout)).toMatchObject({
      ok: false,
      connectionAttempts: 0,
      actualRequests: 0,
      tlsHandshakes: 0,
    });
    expect(result.stdout).not.toContain("must-not-enter-guest");
  });

  it("implements the CL.TE origin differential and validates only the separately injected A credential", async () => {
    const f = await fixture();
    const caseId = "receiver-local-run:ambiguous-plus-a";
    const socket = await connect(f.handle.rawPort);
    const reader = new ResponseReader(socket);
    socket.write(firstRequest(f.runId, caseId, f.canary, "cl-te"));
    expect(await reader.read()).toMatch(/^HTTP\/1\.1 204 /u);

    socket.write([
      `GET /v1/sbx040/${f.runId}/next HTTP/1.1`,
      "Host: a.research.test",
      `X-SBX040-Case: ${caseId}`,
      `X-SBX040-Canary: ${f.canary}`,
      `${SBX040_TRANSFORM_HEADER}: ${f.credential}`,
      "Content-Length: 0",
      "Connection: close",
      "",
      "",
    ].join("\r\n"));
    const second = await reader.read();
    const operation = deriveSbx040OperationId(f.adminKey, f.runId, caseId);
    expect(second).toContain("HTTP/1.1 200 OK\r\n");
    expect(second).toContain(`X-SBX040-Operation: ${operation}\r\n`);

    const snapshot = await (await f.admin(`/v1/sbx040/admin/runs/${f.runId}`)).json() as Record<string, any>;
    expect(snapshot.bActions).toEqual([expect.objectContaining({
      caseId,
      canaryMatched: true,
      nestedAHostMatched: true,
      nestedCaseMatched: true,
      transformHeaderLines: 1,
      transformCredentialMatched: true,
      operationId: operation,
      rawCredentialRetained: false,
      rawBodyRetained: false,
    })]);
    expect(JSON.stringify(snapshot)).not.toContain(f.credential);
  });

  it("does not parse the embedded B prefix as a request for either single-framing control", async () => {
    const f = await fixture();
    for (const kind of ["cl", "te"] as const) {
      const socket = await connect(f.handle.rawPort);
      const reader = new ResponseReader(socket);
      socket.write(firstRequest(f.runId, `${f.runId}:${kind}`, f.canary, kind));
      expect(await reader.read()).toMatch(/^HTTP\/1\.1 204 /u);
      socket.end();
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
    const snapshot = await (await f.admin(`/v1/sbx040/admin/runs/${f.runId}`)).json() as Record<string, any>;
    expect(snapshot.bActions).toEqual([]);
    expect(snapshot.requests.filter((event: any) => event.caseId.endsWith(":cl") || event.caseId.endsWith(":te")))
      .toHaveLength(2);
    expect(snapshot.requests.filter((event: any) => event.role === "b")).toHaveLength(0);
  });

  it("records an ambiguous-alone B prefix but cannot create an action without the second A request", async () => {
    const f = await fixture();
    const caseId = `${f.runId}:ambiguous-alone`;
    const socket = await connect(f.handle.rawPort);
    const reader = new ResponseReader(socket);
    socket.write(firstRequest(f.runId, caseId, f.canary, "cl-te"));
    expect(await reader.read()).toMatch(/^HTTP\/1\.1 204 /u);
    socket.end();
    await new Promise((resolve) => setTimeout(resolve, 25));
    const snapshot = await (await f.admin(`/v1/sbx040/admin/runs/${f.runId}`)).json() as Record<string, any>;
    expect(snapshot.requests).toEqual(expect.arrayContaining([expect.objectContaining({ caseId, role: "b", complete: false })]));
    expect(snapshot.bActions).toEqual([]);
  });
});
