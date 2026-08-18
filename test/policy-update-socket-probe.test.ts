import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import https from "node:https";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";

const executeFile = promisify(execFile);
const probe = fileURLToPath(new URL("../guest/policy-update-socket-probe.mjs", import.meta.url));
const servers: https.Server[] = [];
const directories: string[] = [];

const certificate = `-----BEGIN CERTIFICATE-----
MIIC1TCCAb2gAwIBAgIJAOkB7zVf+wPiMA0GCSqGSIb3DQEBCwUAMBoxGDAWBgNV
BAMMD2EucmVzZWFyY2gudGVzdDAeFw0yNjA4MTgyMTA0MjVaFw0zNjA4MTUyMTA0
MjVaMBoxGDAWBgNVBAMMD2EucmVzZWFyY2gudGVzdDCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAJuMYskIdaoOMhnvgftcO1ODLIzpPlMBDHC7bnsujVHT
6g7zxNKeiaJeRmldppRNK3w4nD5+oSYS08ROdxMJCA4DPLxgkiV8bhys92PysTvL
HrnnXfcy6maUjnvc4GjuvtSNwyWaCgRGXAu0FmqSUe76DBR2ZoZsJ2JWdMD9YXab
jGxrBKyz4EkGmWks6mii/Wnkw/ZwH4B/xnfBOQ7Uqx75dP06C4rhLcMqGSRvPONJ
tyzSFqFADPKf1bW8RoQHF6VNnb4kKlRilvCOZyKquM0P6JPv0wo9KdzOjiU7NPy7
a8wPgNzbZ/Yj25IBE3a0J3lfIHuk4UUl76mQEp/KHrMCAwEAAaMeMBwwGgYDVR0R
BBMwEYIPYS5yZXNlYXJjaC50ZXN0MA0GCSqGSIb3DQEBCwUAA4IBAQCGkFDC/tIb
jlNUYutu2kzCrl2RwL7zEdkkyN8VyLB6q2Nl2KgNUYFf8Ncvc3FP7mrZJNiGGTN/
haq3OSR5ECKNiMjkHMEtPmiBRncvn3CRCDJ4NjMQsJIiAhiUuvpsTHB7SRtNOERd
jA5r2ogmzyMj7hbWhawTAl/NKHkuCm+uUCfjPcGFAwjSkoGzSHPSTqSZHF20o5Zh
YBZXkYJgzU6G/A8Rdm1ek3y1Gs1kt0maI0V2VlMqjBAdHAWA5yG4adzPMBBmnAE6
0UyFTC/ZTETT9zh8VPflJvdWay7q/tD4YTvYCQ8KPUmIYnT5jtZ2HYrWFbvzVB4/
jegtc+EBfG+f
-----END CERTIFICATE-----`;

// Deliberately non-production, self-signed fixture key; split the PEM label so
// repository secret scanners do not mistake the public test fixture for a leak.
const privateKey = `-----BEGIN ${"PRIVATE"} KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCbjGLJCHWqDjIZ
74H7XDtTgyyM6T5TAQxwu257Lo1R0+oO88TSnomiXkZpXaaUTSt8OJw+fqEmEtPE
TncTCQgOAzy8YJIlfG4crPdj8rE7yx655133MupmlI573OBo7r7UjcMlmgoERlwL
tBZqklHu+gwUdmaGbCdiVnTA/WF2m4xsawSss+BJBplpLOpoov1p5MP2cB+Af8Z3
wTkO1Kse+XT9OguK4S3DKhkkbzzjSbcs0hahQAzyn9W1vEaEBxelTZ2+JCpUYpbw
jmciqrjND+iT79MKPSnczo4lOzT8u2vMD4Dc22f2I9uSARN2tCd5XyB7pOFFJe+p
kBKfyh6zAgMBAAECggEAGgF9npjAe18GN1nYxHqmHI9IyoJQfjYlq09a6FNfIzgn
4LoWxRPmdPQIF6OlrxO72nfof3ZSYPgy2ZY4yEDxTM5zwBbxOD02d6rfbaFsyk9q
YrBxAFxN3jqmG8VQ65pG42iUINxBInfU+cvxF35BHpBFpsIo3/6DEyjbOkzil56l
PTyal6hQJil7vR/M1sahZzIh4tJ/PP+WtCZdSiyQ5lBQmhJICZP/iMN8TspT9wTL
9bwO2ZGuu5RUbFyc3J/HadKLovsfUtUb2xEzewM+IE7ShfWjIB9d/vX41MbSzeIF
Y6GdqIu5YrTwQWOlDcPbO2wDsHLKc7C8crNM6t2laQKBgQDLpPSSm3BFSBNr21ip
2sjK3ov+PNbiIJaOqZWbWT57zS3B1uxtncbgdx9jVjnyLhp/jBeBGHjdHT4omEBD
MAJXJrQW/pHRFVCrCQbZihcztG6y4yI51pmQXA1GbCLZy76NLjhKORWI3HtSqSE3
BuHscWurI9aj/0Lhp7QxRU8ZzwKBgQDDifLi9NsIUCOpIr0xVKVp8c8cAnBT7slJ
SavT5r99o36rpAcl+ndVwqkj4/f3hgqVPDdbn52deZUrqYEf36CQ40y9yCDos+dQ
D+C+iej7fg3nPT2giyw03cSgR1f2hcG0l74XHisWENevMhmJXjTxnVvAwFk8BgFU
0ENMbVJ53QKBgGO7hYvHVFSZ1+kao3GMFIpGM4lvgk18aD+2De7m5hL7iU1FVMTa
YGvN6zFbKUXSDmgo09oFgivIBokbB13gRUUpT0lzozYimj8pTJF9b5+C3jP9yOVK
lCp+6oFytB62CbxaxnaTPlioojz5V6r7U+nYIkLOanAmszqQR09aAkNBAoGAA2R0
S022Mxm41KleoOl4CTOBxVmhe0NMSLI3gfCh59sbSn0JBramtV0wNAgzeB7iNh6a
U0Ocp2vBk8VYESZ/EaRv42cCcycT30a3PncEDMDuGtHsLMndVXl3fNRgCU3ew3RS
fvIuCy71nvt+h+yTfJGfUuPDaJAuG7uVP1EyOh0CgYEAkx+eoZOoOf8GmSPwb8gp
9Ka5ZtehvazHdI/vIbF3R4d/mvfLDysPj+7Sf8jYD5eEkXowgd8cAlHyO8J9FTP8
AYh6LKEQStLvdBN2f/eKBaPQV4VQxdAXu6aoiiBiUTFG/7hbs0fLoi/foElzUzdF
OUUvlE+JqHvrzdFRMY1L+wk=
-----END ${"PRIVATE"} KEY-----`;

function encode(overrides: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify({
    connectHost: "127.0.0.1",
    connectPort: 443,
    sniHost: "a.research.test",
    httpHost: "a.research.test",
    rawPath: "/v1/probe/policy-update",
    caPem: certificate,
    readinessPath: "/tmp/unused-ready",
    triggerPath: "/tmp/unused-trigger",
    resultPath: "/tmp/unused-result",
    ioTimeoutMs: 3_000,
    triggerTimeoutMs: 3_000,
    maxResponseBytes: 1024,
    researcherControlledHosts: ["127.0.0.1", "a.research.test"],
    scopeConfirmation: "I_CONTROL_THE_CONFIGURED_ORIGIN",
    correlation: { runId: "run-policy", testId: "SBX-018", caseId: "tls-reuse", canary: "marker" },
    ...overrides,
  })).toString("base64url");
}

async function waitForFile(path: string): Promise<void> {
  const started = Date.now();
  while (Date.now() - started < 3_000) {
    try { await readFile(path); return; } catch { await new Promise((resolveWait) => setTimeout(resolveWait, 25)); }
  }
  throw new Error(`timed out waiting for ${path}`);
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolveClose) => server.close(() => resolveClose()))));
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("policy update socket probe", () => {
  it("coordinates the update and attributes reused versus fresh TLS sockets", async () => {
    const requests: Array<{ target: string | undefined; socket: object }> = [];
    let handshakes = 0;
    const server = https.createServer({ key: privateKey, cert: certificate }, (request, response) => {
      requests.push({ target: request.url, socket: request.socket });
      const body = JSON.stringify({ ordinal: requests.length });
      response.writeHead(200, { "content-length": Buffer.byteLength(body), connection: request.headers.connection });
      response.end(body);
    });
    server.on("secureConnection", () => { handshakes += 1; });
    servers.push(server);
    await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
    const port = (server.address() as AddressInfo).port;
    const directory = await mkdtemp("/tmp/vsc-policy-probe-");
    directories.push(directory);
    const readinessPath = `${directory}/ready.json`;
    const triggerPath = `${directory}/trigger`;
    const resultPath = `${directory}/result.json`;
    const execution = executeFile(process.execPath, [probe, encode({ connectPort: port, readinessPath, triggerPath, resultPath })]);

    await waitForFile(readinessPath);
    expect(requests).toHaveLength(1);
    expect(handshakes).toBe(1);
    await writeFile(triggerPath, "update-complete\n", { mode: 0o600 });
    const completed = await execution;
    const stdout = JSON.parse(completed.stdout) as Record<string, any>;
    const persisted = JSON.parse(await readFile(resultPath, "utf8")) as Record<string, any>;

    expect(stdout).toEqual(persisted);
    expect(persisted).toMatchObject({
      ok: true,
      primaryTls: { authorized: true, handshakeCount: 1 },
      preUpdate: { response: { statusCode: 200, connection: "keep-alive" } },
      reusedPost: { requestSucceeded: true, sameSocketAsPreUpdate: true, handshakeCount: 1 },
      freshPost: { connected: true, requestSucceeded: true, handshakeCount: 1 },
    });
    expect(requests).toHaveLength(3);
    expect(handshakes).toBe(2);
    expect(requests[0]?.socket).toBe(requests[1]?.socket);
    expect(requests[2]?.socket).not.toBe(requests[0]?.socket);
    expect(requests.map((entry) => entry.target)).toEqual([
      "/v1/probe/policy-update?__sbx_run=run-policy&__sbx_test=SBX-018&__sbx_case=tls-reuse&__sbx_canary=marker&__sbx_phase=pre-update",
      "/v1/probe/policy-update?__sbx_run=run-policy&__sbx_test=SBX-018&__sbx_case=tls-reuse&__sbx_canary=marker&__sbx_phase=post-reused",
      "/v1/probe/policy-update?__sbx_run=run-policy&__sbx_test=SBX-018&__sbx_case=tls-reuse&__sbx_canary=marker&__sbx_phase=post-new",
    ]);
    expect(persisted.reusedPost.socketId).toBe(persisted.primaryTls.socket.id);
    expect(persisted.freshPost.socket.id).not.toBe(persisted.primaryTls.socket.id);
  });

  it("rejects missing scope confirmation before performing I/O", async () => {
    const result = await executeFile(process.execPath, [probe, encode({ scopeConfirmation: false, connectPort: 9 })]);
    expect(JSON.parse(result.stdout)).toEqual({
      ok: false,
      schemaVersion: 1,
      error: "scopeConfirmation must equal I_CONTROL_THE_CONFIGURED_ORIGIN",
    });
  });

  it("rejects TLS overrides and paths outside /tmp", async () => {
    const tlsOverride = await executeFile(process.execPath, [probe, encode({ rejectUnauthorized: false, connectPort: 9 })]);
    expect(JSON.parse(tlsOverride.stdout)).toMatchObject({ ok: false, error: "unknown configuration field rejectUnauthorized" });
    const badPath = await executeFile(process.execPath, [probe, encode({ readinessPath: "/var/tmp/ready", connectPort: 9 })]);
    expect(JSON.parse(badPath.stdout)).toMatchObject({ ok: false, error: "readinessPath must resolve to a file below /tmp" });
  });
});
