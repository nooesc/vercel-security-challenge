import { execFile, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
// @ts-expect-error This is deliberately one standalone executable Node ESM guest program.
import { computeOperationId, loadServiceConfiguration, parseEncodedProbeConfiguration, runProbe, startService, validateProbeConfiguration, validateServiceConfiguration } from "../guest/published-port-revocation-service.mjs";

const execFileAsync = promisify(execFile);
const guestPath = resolve("guest/published-port-revocation-service.mjs");
const runId = "123e4567-e89b-42d3-a456-426614174000";
const sandboxName = "sbx-046-local-test";
const sessionId = `sbx_${"S".repeat(24)}`;
const serviceInstanceId = `svc46_${"I".repeat(24)}`;
const hmacKey = Buffer.alloc(32, 0x46).toString("base64url");
const caseIds = [
  "local-pre",
  "external-pre",
  "local-post-readback",
  "external-post-5s",
  "external-post-30s",
  "external-post-90s",
  "local-post-final",
] as const;

const temporaryPaths: string[] = [];
let runningService: Awaited<ReturnType<typeof startService>> | undefined;

afterEach(async () => {
  if (runningService) {
    await runningService.close();
    runningService = undefined;
  }
  for (const path of temporaryPaths.splice(0)) await rm(path, { force: true, recursive: true });
});

function challenge(index: number): string {
  const byte = 65 + index;
  return `ch46_${String.fromCharCode(byte).repeat(24)}`;
}

function identity() {
  return { runId, sandboxName, sessionId, port: 3000, serviceInstanceId };
}

function mapping(caseId: string, caseChallenge: string) {
  return {
    challenge: caseChallenge,
    operationId: computeOperationId({ ...identity(), caseId, challenge: caseChallenge, hmacKey }),
  };
}

function serviceConfiguration(eventLogPath: string, selectedCases: readonly string[] = caseIds) {
  return {
    schemaVersion: 1,
    testId: "SBX-046",
    ...identity(),
    hmacKey,
    eventLogPath,
    cases: Object.fromEntries(selectedCases.map((caseId, index) => [caseId, mapping(caseId, challenge(index))])),
  };
}

function caseMapping(config: ReturnType<typeof serviceConfiguration>, caseId: string): {
  challenge: string;
  operationId: string;
} {
  const selected = config.cases[caseId];
  if (!selected) throw new Error(`missing local test mapping ${caseId}`);
  return selected;
}

function probeConfiguration(config: ReturnType<typeof serviceConfiguration>, caseId: string) {
  const selected = caseMapping(config, caseId);
  return {
    schemaVersion: 1,
    testId: "SBX-046",
    ...identity(),
    baseUrl: "http://127.0.0.1:3000",
    caseId,
    challenge: selected.challenge,
    expectedOperationId: selected.operationId,
    timeoutMs: 2_000,
  };
}

async function temporaryDirectory(): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), "sbx-046-guest-"));
  temporaryPaths.push(path);
  return path;
}

async function rawRequest(input: {
  run?: string;
  caseId: string;
  challenge: string;
  body: string;
}): Promise<{ statusCode: number | undefined; body: string }> {
  const body = Buffer.from(input.body, "utf8");
  return await new Promise((resolvePromise, reject) => {
    const request = http.request({
      agent: false,
      hostname: "127.0.0.1",
      port: 3000,
      method: "POST",
      path: "/v1/sbx046/canary",
      headers: {
        connection: "close",
        "content-length": String(body.length),
        "content-type": "text/plain; charset=utf-8",
        "x-sbx046-run": input.run ?? runId,
        "x-sbx046-case": input.caseId,
        "x-sbx046-challenge": input.challenge,
      },
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      response.on("end", () => resolvePromise({
        statusCode: response.statusCode,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    request.once("error", reject);
    request.end(body);
  });
}

describe.sequential("SBX-046 published-port guest service", () => {
  it("derives a unique keyed operation ID over every exact identity component", () => {
    const base = { ...identity(), caseId: "local-pre", challenge: challenge(0), hmacKey };
    const expected = computeOperationId(base);
    expect(expected).toMatch(/^op46_[A-Za-z0-9_-]{43}$/u);
    const variants = [
      { ...base, runId: "123e4567-e89b-42d3-b456-426614174000" },
      { ...base, sandboxName: "sbx-046-other-test" },
      { ...base, sessionId: `sbx_${"T".repeat(24)}` },
      { ...base, serviceInstanceId: `svc46_${"J".repeat(24)}` },
      { ...base, caseId: "external-pre" },
      { ...base, challenge: challenge(1) },
      { ...base, hmacKey: randomBytes(32).toString("base64url") },
    ];
    expect(new Set(variants.map((value) => computeOperationId(value))).size).toBe(variants.length);
    expect(variants.map((value) => computeOperationId(value))).not.toContain(expected);
  });

  it("validates exact service/probe schemas and rejects unknown env, trust, proxy, and retry fields", async () => {
    const directory = await temporaryDirectory();
    const config = serviceConfiguration(join(directory, "events.jsonl"));
    expect(validateServiceConfiguration(config)).toMatchObject({
      schemaVersion: 1,
      testId: "SBX-046",
      ...identity(),
    });
    expect(validateProbeConfiguration(probeConfiguration(config, "local-pre"))).toMatchObject({
      baseUrl: "http://127.0.0.1:3000",
      caseId: "local-pre",
      timeoutMs: 2_000,
    });

    for (const forbidden of ["env", "proxy", "ca", "agent", "retryCount", "headers"]) {
      expect(() => validateProbeConfiguration({
        ...probeConfiguration(config, "local-pre"),
        [forbidden]: forbidden === "retryCount" ? 0 : {},
      })).toThrow(/forbidden|unknown/u);
    }
    expect(() => validateProbeConfiguration({
      ...probeConfiguration(config, "local-pre"),
      baseUrl: "http://localhost:3000",
    })).toThrow(/127\.0\.0\.1/u);
    expect(() => validateProbeConfiguration({
      ...probeConfiguration(config, "local-pre"),
      timeoutMs: 5_001,
    })).toThrow(/5000/u);
    expect(() => validateServiceConfiguration({ ...config, hmacKey: Buffer.alloc(31).toString("base64url") }))
      .toThrow(/32 through 64 bytes/u);
    expect(() => validateServiceConfiguration({ ...config, unexpected: true })).toThrow(/unknown/u);
    expect(() => validateServiceConfiguration({
      ...config,
      cases: {
        ...config.cases,
        extra: { ...mapping("extra", challenge(7)), unexpected: true },
      },
    })).toThrow(/unknown/u);
  });

  it("requires a bounded, single-link, regular mode-0600 configuration file", async () => {
    const directory = await temporaryDirectory();
    const eventLogPath = join(directory, "events.jsonl");
    const configPath = join(directory, "config.json");
    await writeFile(configPath, JSON.stringify(serviceConfiguration(eventLogPath)), { mode: 0o600 });
    expect(await loadServiceConfiguration(configPath)).toMatchObject({ eventLogPath });

    await chmod(configPath, 0o644);
    await expect(loadServiceConfiguration(configPath)).rejects.toThrow(/exact mode 0600/u);
    await chmod(configPath, 0o600);
    await writeFile(configPath, "x".repeat(32 * 1024 + 1));
    await expect(loadServiceConfiguration(configPath)).rejects.toThrow(/size is invalid/u);
    await expect(loadServiceConfiguration("relative-config.json")).rejects.toThrow(/absolute path/u);
  });

  it("caps case mappings and canonical encoded probe input", async () => {
    const directory = await temporaryDirectory();
    const config = serviceConfiguration(join(directory, "events.jsonl"));
    const nineCases = Object.fromEntries(Array.from({ length: 9 }, (_, index) => {
      const caseId = `case-${index}`;
      return [caseId, mapping(caseId, `ch46_${String(index).repeat(24)}`)];
    }));
    expect(() => validateServiceConfiguration({ ...config, cases: nineCases })).toThrow(/1 through 8/u);
    expect(() => validateServiceConfiguration({ ...config, cases: {} })).toThrow(/1 through 8/u);

    const encoded = Buffer.from(JSON.stringify(probeConfiguration(config, "local-pre"))).toString("base64url");
    expect(parseEncodedProbeConfiguration(encoded)).toMatchObject({ caseId: "local-pre" });
    expect(() => parseEncodedProbeConfiguration(`${encoded}=`)).toThrow(/canonical base64url/u);
    expect(() => parseEncodedProbeConfiguration("A".repeat(50_000))).toThrow(/bounded/u);
  });

  it("records exactly one sanitized keyed event and emits a flat exact loopback receipt", async () => {
    const directory = await temporaryDirectory();
    const eventLogPath = join(directory, "events.jsonl");
    const config = serviceConfiguration(eventLogPath);
    runningService = await startService(config);
    const selected = caseMapping(config, "local-pre");

    const probe = await runProbe(probeConfiguration(config, "local-pre"));
    expect(probe).toEqual({
      schemaVersion: 1,
      testId: "SBX-046",
      ...identity(),
      caseId: "local-pre",
      challenge: selected.challenge,
      expectedOperationId: selected.operationId,
      targetBaseUrl: "http://127.0.0.1:3000",
      targetPath: "/v1/sbx046/canary",
      requestOrigin: "http://127.0.0.1:3000",
      requestPath: "/v1/sbx046/canary",
      method: "POST",
      timeoutMs: 2_000,
      attemptCount: 1,
      requestAttempts: 1,
      connectionAttempts: 1,
      actualRequests: 1,
      retryCount: 0,
      redirectsFollowed: 0,
      freshConnection: true,
      strictTlsVerification: false,
      proxyConfigurationAccepted: false,
      tlsTrustConfigurationAccepted: false,
      rawConfigurationRetained: false,
      rawRequestBodyRetained: false,
      rawResponseBodyRetained: false,
      tcpConnected: true,
      tlsEstablished: false,
      tlsAuthorized: false,
      responseReceived: true,
      timedOut: false,
      receiptValidated: true,
      durationMs: expect.any(Number),
      statusCode: 200,
      responseBytes: expect.any(Number),
      serviceHeaderValidated: true,
      cacheControlValidated: true,
      connectionCloseValidated: true,
      contentTypeValidated: true,
      contentLengthValidated: true,
      operationId: selected.operationId,
      serviceResponse: {
        schemaVersion: 1,
        testId: "SBX-046",
        ...identity(),
        caseId: "local-pre",
        challenge: selected.challenge,
        operationId: selected.operationId,
        requestBodyValidated: true,
        ok: true,
      },
      ok: true,
    });
    expect(probe.durationMs).toBeGreaterThanOrEqual(0);

    const rawLog = await readFile(eventLogPath, "utf8");
    expect(rawLog.trim().split("\n")).toHaveLength(1);
    const event = JSON.parse(rawLog) as Record<string, unknown>;
    expect(event).toEqual({
      schemaVersion: 1,
      testId: "SBX-046",
      ...identity(),
      caseId: "local-pre",
      challenge: selected.challenge,
      operationId: selected.operationId,
      observedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/u),
      method: "POST",
      path: "/v1/sbx046/canary",
      requestBodyValidated: true,
      rawHmacKeyRetained: false,
      rawRequestBodyRetained: false,
      derivedDigestRetained: false,
    });
    expect(rawLog).not.toContain(hmacKey);
    expect(rawLog).not.toContain(`public:${selected.challenge}`);

    const duplicate = await rawRequest({
      caseId: "local-pre",
      challenge: selected.challenge,
      body: `public:${selected.challenge}`,
    });
    expect(duplicate.statusCode).toBe(403);
    expect((await readFile(eventLogPath, "utf8")).trim().split("\n")).toHaveLength(1);
  });

  it("does not record wrong case, challenge, run, or body requests", async () => {
    const directory = await temporaryDirectory();
    const eventLogPath = join(directory, "events.jsonl");
    const config = serviceConfiguration(eventLogPath, ["local-post-readback"]);
    const selected = caseMapping(config, "local-post-readback");
    runningService = await startService(config);

    const inputs = [
      { caseId: "unknown-case", challenge: selected.challenge, body: `public:${selected.challenge}` },
      { caseId: "local-post-readback", challenge: challenge(7), body: `public:${challenge(7)}` },
      { run: "223e4567-e89b-42d3-a456-426614174000", caseId: "local-post-readback", challenge: selected.challenge, body: `public:${selected.challenge}` },
      { caseId: "local-post-readback", challenge: selected.challenge, body: "public:wrong" },
    ];
    for (const input of inputs) {
      expect((await rawRequest(input)).statusCode).toBeGreaterThanOrEqual(400);
      expect(await readFile(eventLogPath, "utf8")).toBe("");
    }
  });

  it("supports the exact probe and serve CLI modes without accepting extras", async () => {
    const directory = await temporaryDirectory();
    const eventLogPath = join(directory, "events.jsonl");
    const config = serviceConfiguration(eventLogPath, ["local-post-final"]);
    runningService = await startService(config);
    const encoded = Buffer.from(JSON.stringify(probeConfiguration(config, "local-post-final"))).toString("base64url");
    const probeChild = await execFileAsync(process.execPath, [guestPath, "probe", encoded], {
      encoding: "utf8",
      timeout: 5_000,
    });
    expect(JSON.parse(probeChild.stdout)).toMatchObject({
      ok: true,
      caseId: "local-post-final",
      attemptCount: 1,
      retryCount: 0,
      redirectsFollowed: 0,
      receiptValidated: true,
    });
    await runningService.close();
    runningService = undefined;

    const secondEventLog = join(directory, "serve-cli-events.jsonl");
    const serveConfig = serviceConfiguration(secondEventLog, ["local-pre"]);
    const configPath = join(directory, "serve-config.json");
    await writeFile(configPath, JSON.stringify(serveConfig), { mode: 0o600 });
    const child = spawn(process.execPath, [guestPath, "serve", configPath], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    const readiness = await new Promise<Record<string, unknown>>((resolvePromise, reject) => {
      const timer = setTimeout(() => reject(new Error("serve CLI readiness timed out")), 5_000);
      child.once("error", reject);
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (chunk: string) => {
        output += chunk;
        const newline = output.indexOf("\n");
        if (newline !== -1) {
          clearTimeout(timer);
          resolvePromise(JSON.parse(output.slice(0, newline)) as Record<string, unknown>);
        }
      });
    });
    expect(readiness).toMatchObject({
      schemaVersion: 1,
      testId: "SBX-046",
      mode: "serve",
      ready: true,
      ...identity(),
      listenHost: "0.0.0.0",
      eventLogReady: true,
      rawHmacKeyRetained: false,
      rawConfigurationRetained: false,
    });
    child.kill("SIGTERM");
    await new Promise<void>((resolvePromise, reject) => {
      const timer = setTimeout(() => reject(new Error("serve CLI did not stop")), 5_000);
      child.once("exit", (code, signal) => {
        clearTimeout(timer);
        if (code === 0 || signal === "SIGTERM") resolvePromise();
        else reject(new Error(`serve CLI exited ${String(code)}/${String(signal)}`));
      });
    });

    const extra = await execFileAsync(process.execPath, [guestPath, "probe", encoded, "extra"], {
      encoding: "utf8",
    }).then(
      () => ({ status: 0, stderr: "" }),
      (error: { code?: number; stderr?: string }) => ({ status: error.code, stderr: error.stderr ?? "" }),
    );
    expect(extra.status).toBe(1);
    expect(extra.stderr).toContain("usage:");
  });

  it("preserves one failed fresh connection attempt without synthesizing a response or receipt", async () => {
    const directory = await temporaryDirectory();
    const config = serviceConfiguration(join(directory, "events.jsonl"), ["local-pre"]);
    const probe = await runProbe(probeConfiguration(config, "local-pre"));
    expect(probe).toMatchObject({
      ok: false,
      requestOrigin: "http://127.0.0.1:3000",
      requestPath: "/v1/sbx046/canary",
      requestAttempts: 1,
      connectionAttempts: 1,
      actualRequests: 1,
      freshConnection: true,
      strictTlsVerification: false,
      tcpConnected: false,
      tlsEstablished: false,
      tlsAuthorized: false,
      responseReceived: false,
      timedOut: false,
      receiptValidated: false,
      durationMs: expect.any(Number),
      errorCode: "ECONNREFUSED",
    });
    expect(probe).not.toHaveProperty("serviceResponse");
    expect(probe).not.toHaveProperty("operationId");
  });

  it("marks timedOut only when the single loopback request timeout actually fires", async () => {
    const directory = await temporaryDirectory();
    const config = serviceConfiguration(join(directory, "events.jsonl"), ["local-pre"]);
    const hangingServer = http.createServer((request) => request.resume());
    await new Promise<void>((resolvePromise, reject) => {
      hangingServer.once("error", reject);
      hangingServer.listen(3000, "127.0.0.1", () => resolvePromise());
    });
    try {
      const probe = await runProbe({ ...probeConfiguration(config, "local-pre"), timeoutMs: 250 });
      expect(probe).toMatchObject({
        ok: false,
        actualRequests: 1,
        connectionAttempts: 1,
        tcpConnected: true,
        responseReceived: false,
        timedOut: true,
        errorCode: "PROBE_TIMEOUT",
        receiptValidated: false,
        durationMs: expect.any(Number),
      });
      expect(probe).not.toHaveProperty("serviceResponse");
    } finally {
      await new Promise<void>((resolvePromise, reject) => {
        hangingServer.close((error) => error ? reject(error) : resolvePromise());
        hangingServer.closeAllConnections?.();
      });
    }
  });
});
