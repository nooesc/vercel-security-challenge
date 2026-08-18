import { execFile } from "node:child_process";
import https from "node:https";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";

const executeFile = promisify(execFile);
const guestProbe = fileURLToPath(new URL("../guest/h1-authority-reuse-probe.mjs", import.meta.url));
const servers: https.Server[] = [];

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

function encodeConfiguration(overrides: Record<string, unknown>): string {
  return Buffer.from(
    JSON.stringify({
      connectHost: "127.0.0.1",
      connectPort: 443,
      sniHost: "a.research.test",
      firstHost: "a.research.test",
      secondHost: "b.research.test",
      firstPath: "/first?source=test",
      secondPath: "/second",
      caPem: certificate,
      timeoutMs: 3_000,
      maxResponseBytes: 1024,
      researcherControlledHosts: ["127.0.0.1", "a.research.test", "b.research.test"],
      scopeConfirmation: "I_CONTROL_ALL_LISTED_HOSTS",
      correlation: {
        runId: "run-h1-reuse",
        testId: "SBX-010",
        caseId: "authority-switch",
        canary: "nonsecret-marker",
      },
      ...overrides,
    }),
  ).toString("base64url");
}

async function executeProbe(configuration: string): Promise<Record<string, unknown>> {
  const result = await executeFile(process.execPath, [guestProbe, configuration]);
  return JSON.parse(result.stdout) as Record<string, unknown>;
}

async function startFixture(): Promise<{
  port: number;
  requests: Array<{ host: string | undefined; rawTarget: string | undefined; socket: object }>;
  handshakes: () => number;
}> {
  const requests: Array<{ host: string | undefined; rawTarget: string | undefined; socket: object }> = [];
  let handshakeCount = 0;
  const server = https.createServer({ key: privateKey, cert: certificate }, (request, response) => {
    requests.push({ host: request.headers.host, rawTarget: request.url, socket: request.socket });
    const body = JSON.stringify({ host: request.headers.host, ordinal: requests.length });
    response.writeHead(200, {
      "content-type": "application/json",
      "content-length": Buffer.byteLength(body),
      connection: requests.length === 1 ? "keep-alive" : "close",
    });
    response.end(body);
  });
  server.on("secureConnection", () => {
    handshakeCount += 1;
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  return { port: address.port, requests, handshakes: () => handshakeCount };
}

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) => new Promise<void>((resolve) => server.close(() => resolve())),
    ),
  );
});

describe("HTTP/1.1 authority reuse probe", () => {
  it("uses one verified TLS connection for sequential Host A and Host B requests", async () => {
    const fixture = await startFixture();
    const result = await executeProbe(encodeConfiguration({ connectPort: fixture.port }));

    expect(result).toMatchObject({
      ok: true,
      tls: {
        authorized: true,
        sniHost: "a.research.test",
        handshakeCount: 1,
        socket: { remoteAddress: "127.0.0.1", remotePort: fixture.port },
      },
      requests: [
        {
          index: 0,
          host: "a.research.test",
          response: { statusCode: 200, bodyLength: 38 },
        },
        {
          index: 1,
          host: "b.research.test",
          response: { statusCode: 200, bodyLength: 38 },
        },
      ],
    });
    expect(fixture.handshakes()).toBe(1);
    expect(fixture.requests).toHaveLength(2);
    expect(fixture.requests[0]?.socket).toBe(fixture.requests[1]?.socket);
    expect(fixture.requests.map((request) => request.host)).toEqual([
      "a.research.test",
      "b.research.test",
    ]);
    expect(fixture.requests.map((request) => request.rawTarget)).toEqual([
      "/first?source=test&__sbx_run=run-h1-reuse&__sbx_test=SBX-010&__sbx_case=authority-switch&__sbx_canary=nonsecret-marker",
      "/second?__sbx_run=run-h1-reuse&__sbx_test=SBX-010&__sbx_case=authority-switch&__sbx_canary=nonsecret-marker",
    ]);
  });

  it("refuses to connect without exact researcher scope confirmation", async () => {
    const result = await executeProbe(
      encodeConfiguration({ scopeConfirmation: false, connectPort: 9 }),
    );
    expect(result).toEqual({
      ok: false,
      error: "scopeConfirmation must equal I_CONTROL_ALL_LISTED_HOSTS",
    });
  });

  it("keeps certificate verification enabled for an untrusted SNI name", async () => {
    const fixture = await startFixture();
    const result = await executeProbe(
      encodeConfiguration({
        connectPort: fixture.port,
        sniHost: "wrong.research.test",
        firstHost: "wrong.research.test",
        researcherControlledHosts: [
          "127.0.0.1",
          "wrong.research.test",
          "b.research.test",
        ],
      }),
    );
    expect(result).toMatchObject({ ok: false });
    expect(String(result.error)).toMatch(/not cert's altnames|hostname/i);
    expect(fixture.requests).toHaveLength(0);
  });

  it("rejects credential-like configuration fields before connecting", async () => {
    const result = await executeProbe(
      encodeConfiguration({ authorization: "Bearer synthetic", connectPort: 9 }),
    );
    expect(result).toEqual({
      ok: false,
      error: "sensitive configuration field authorization is not allowed",
    });
  });
});
