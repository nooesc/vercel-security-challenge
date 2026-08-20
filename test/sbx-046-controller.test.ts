import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import type { ClientRequest, IncomingMessage } from "node:http";
import type { RequestOptions } from "node:https";
import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import {
  SBX046_CASES,
  SBX046_PORT,
  SBX046_PROJECT_ID,
  SBX046_SCOPE_CONFIRMATION,
  SBX046_TEAM_ID,
  SBX046_TEST_ID,
  buildCaseMaterial,
  buildLocalProbeConfiguration,
  buildPortRemovalUpdate,
  buildSandboxName,
  buildServiceConfiguration,
  canonicalRouteOrigin,
  captureRouteReadback,
  conclusiveTerminalRouteDenial,
  deriveOperationId,
  evidenceExcludesSecrets,
  exactClearedRouteReadback,
  exactExternalResponse,
  exactInitialRouteReadback,
  explicitCredentials,
  performExternalProbe,
  newRecoveryJournal,
  recoverableSandboxIdentity,
  requireScopeConfirmation,
  requireStrictControllerTlsEnvironment,
  safeToReleaseSbx046Lock,
  sanitizeLocalProbeEvidence,
  type Sbx046ExternalProbeEvidence,
  type Sbx046Route,
} from "../pocs/SBX-046/published-port-revocation.js";

const runId = "11111111-2222-4333-8444-555555555555";
const sandboxName = `sbx-046-${runId}`;
const sessionId = "sbx_abcdefghijklmnopqrstuvwx";
const serviceInstanceId = `svc46_${"s".repeat(24)}`;
const hmacKey = Buffer.alloc(32, 0x46).toString("base64url");
const tags = { harness: "vsc", test: SBX046_TEST_ID, run: runId };
const route: Sbx046Route = {
  url: "https://route46.vercel.run",
  subdomain: "route46",
  port: SBX046_PORT,
};

class Readback {
  public constructor(
    public readonly routes: Sbx046Route[],
    public readonly name = sandboxName,
    public readonly persistent = false,
    public readonly status = "running",
    public readonly tagsValue: Record<string, string> | undefined = tags,
    public readonly session = sessionId,
    public readonly domainOverride?: string | undefined,
  ) {}

  public get tags(): Record<string, string> | undefined {
    return this.tagsValue;
  }

  public currentSession(): { sessionId: string } {
    return { sessionId: this.session };
  }

  public domain(port: number): string {
    if (this.domainOverride !== undefined) return this.domainOverride;
    const match = this.routes.find((item) => item.port === port);
    if (!match) throw new Error(`No route for port ${port}`);
    return `https://${match.subdomain}.vercel.run`;
  }
}

function external(overrides: Partial<Sbx046ExternalProbeEvidence> = {}): Sbx046ExternalProbeEvidence {
  const caseId = "external-post-90s";
  const challenge = `ch46_${"c".repeat(24)}`;
  return {
    schemaVersion: 1,
    testId: SBX046_TEST_ID,
    runId,
    sandboxName,
    sessionId,
    serviceInstanceId,
    caseId,
    challenge,
    expectedOperationId: `op46_${"o".repeat(43)}`,
    startedAt: "2026-08-19T12:00:00.000Z",
    completedAt: "2026-08-19T12:00:00.008Z",
    requestOrigin: route.url,
    requestPath: "/v1/sbx046/canary",
    method: "POST",
    attempts: 1,
    requests: 1,
    retries: 0,
    redirectsFollowed: 0,
    agentDisabled: true,
    rejectUnauthorized: true,
    tcpConnected: false,
    tlsEstablished: false,
    tlsAuthorized: false,
    responseReceived: false,
    responseBytes: 0,
    responseExact: false,
    serviceHeaderValidated: false,
    cacheControlValidated: false,
    connectionCloseValidated: false,
    contentTypeValidated: false,
    contentLengthValidated: false,
    errorCode: "ENOTFOUND",
    errorErrno: -3_008,
    errorSyscall: "getaddrinfo",
    timedOut: false,
    durationMs: 8,
    rawResponseRetained: false,
    ...overrides,
  };
}

function fakeExternalRequest(
  responseAction: (response: PassThrough) => void,
  onDestroy: () => void = () => {},
): typeof import("node:https").request {
  return ((_options: RequestOptions, callback?: (response: IncomingMessage) => void): ClientRequest => {
    const request = new EventEmitter() as ClientRequest;
    let activeResponse: (PassThrough & IncomingMessage) | undefined;
    request.setTimeout = (() => request) as ClientRequest["setTimeout"];
    request.destroy = (() => {
      onDestroy();
      activeResponse?.destroy();
      return request;
    }) as ClientRequest["destroy"];
    request.end = (() => {
      const response = new PassThrough() as PassThrough & IncomingMessage;
      activeResponse = response;
      response.statusCode = 200;
      response.headers = {};
      callback?.(response);
      responseAction(response);
      return request;
    }) as ClientRequest["end"];
    return request;
  }) as typeof import("node:https").request;
}

describe("SBX-046 controller safety and protocol", () => {
  it("keeps the server-side port removal as one literal full-state update", async () => {
    const source = await readFile(new URL(
      "../pocs/SBX-046/published-port-revocation.ts",
      import.meta.url,
    ), "utf8");
    expect(source.match(/await sandbox\.update\(\{ ports: \[\] \}/gu)).toHaveLength(1);
    expect(source).not.toMatch(/updateNetworkPolicy|currentSession\(\)\.update\(/u);
    expect(source).toContain('const requestPath = "/v1/sbx046/canary";');
    expect(source).not.toMatch(/\/v1\/sbx046\/canary\?/u);
  });

  it("requires exact alias credentials and explicit scope", () => {
    expect(explicitCredentials({
      VERCEL_TOKEN: "synthetic",
      VERCEL_TEAM_ID: SBX046_TEAM_ID,
      VERCEL_PROJECT_ID: SBX046_PROJECT_ID,
    })).toEqual({ token: "synthetic", teamId: SBX046_TEAM_ID, projectId: SBX046_PROJECT_ID });
    expect(() => explicitCredentials({
      VERCEL_TOKEN: "synthetic",
      VERCEL_TEAM_ID: "team_wrong",
      VERCEL_PROJECT_ID: SBX046_PROJECT_ID,
    })).toThrow(/exact verified HackerOne-alias/u);
    expect(() => requireScopeConfirmation({ SBX046_SCOPE_CONFIRMATION })).not.toThrow();
    expect(() => requireScopeConfirmation({})).toThrow(/SBX046_SCOPE_CONFIRMATION/u);
    expect(() => requireStrictControllerTlsEnvironment({})).not.toThrow();
    expect(() => requireStrictControllerTlsEnvironment({ NODE_TLS_REJECT_UNAUTHORIZED: "0" }))
      .toThrow(/TLS trust overrides/u);
    expect(() => requireStrictControllerTlsEnvironment({ NODE_EXTRA_CA_CERTS: "/tmp/custom.pem" }))
      .toThrow(/TLS trust overrides/u);
    expect(() => requireStrictControllerTlsEnvironment({ NODE_USE_SYSTEM_CA: "1" }))
      .toThrow(/TLS trust overrides/u);
  });

  it("keeps the full canonical UUID in the named sandbox", () => {
    expect(buildSandboxName(runId)).toBe(sandboxName);
    expect(() => buildSandboxName(runId.replace("4", "1"))).toThrow(/UUIDv4/u);
  });

  it("requires one exact canonical port-3000 route and matching active/independent domain reads", () => {
    expect(canonicalRouteOrigin(route)).toBe(route.url);
    const initial = captureRouteReadback({
      stage: "initial",
      expectedName: sandboxName,
      expectedSessionId: sessionId,
      expectedTags: tags,
      active: new Readback([route]),
      independent: new Readback([route]),
      savedOrigin: route.url,
    });
    expect(exactInitialRouteReadback(initial, tags)).toBe(true);

    const mismatchedUrl = { ...route, url: "https://other.vercel.run" };
    expect(canonicalRouteOrigin(mismatchedUrl)).toBeUndefined();
    const wrongIndependent = captureRouteReadback({
      stage: "initial",
      expectedName: sandboxName,
      expectedSessionId: sessionId,
      expectedTags: tags,
      active: new Readback([route]),
      independent: new Readback([route], sandboxName, false, "running", tags, sessionId, "https://other.vercel.run"),
      savedOrigin: route.url,
    });
    expect(exactInitialRouteReadback(wrongIndependent, tags)).toBe(false);
  });

  it("requires empty active and independent routes plus throwing domain() after literal removal", () => {
    expect(buildPortRemovalUpdate()).toEqual({ ports: [] });
    const cleared = captureRouteReadback({
      stage: "post-update",
      expectedName: sandboxName,
      expectedSessionId: sessionId,
      expectedTags: tags,
      active: new Readback([]),
      independent: new Readback([]),
      savedOrigin: route.url,
    });
    expect(exactClearedRouteReadback(cleared, tags, route.url)).toBe(true);

    const stale = captureRouteReadback({
      stage: "post-update",
      expectedName: sandboxName,
      expectedSessionId: sessionId,
      expectedTags: tags,
      active: new Readback([]),
      independent: new Readback([route]),
      savedOrigin: route.url,
    });
    expect(exactClearedRouteReadback(stale, tags, route.url)).toBe(false);
  });

  it("derives unique keyed operations and exact mode-0600 guest configuration material", () => {
    let randomCounter = 0;
    const cases = buildCaseMaterial({
      hmacKey,
      runId,
      sandboxName,
      sessionId,
      serviceInstanceId,
      randomBytesImpl: (size) => Buffer.alloc(size, 0x10 + randomCounter++),
    });
    expect(Object.keys(cases).sort()).toEqual([...SBX046_CASES].sort());
    for (const caseId of SBX046_CASES) {
      expect(cases[caseId].operationId).toBe(deriveOperationId({
        hmacKey,
        runId,
        sandboxName,
        sessionId,
        serviceInstanceId,
        caseId,
        challenge: cases[caseId].challenge,
      }));
    }
    const service = buildServiceConfiguration({
      hmacKey, runId, sandboxName, sessionId, serviceInstanceId, cases,
    });
    expect(service).toMatchObject({
      schemaVersion: 1, testId: SBX046_TEST_ID, runId, sandboxName, sessionId,
      port: SBX046_PORT, serviceInstanceId, hmacKey, cases,
    });
    expect(buildLocalProbeConfiguration({
      runId, sandboxName, sessionId, serviceInstanceId,
      caseId: "local-pre", material: cases["local-pre"],
    })).toMatchObject({
      baseUrl: "http://127.0.0.1:3000",
      caseId: "local-pre",
      challenge: cases["local-pre"].challenge,
      expectedOperationId: cases["local-pre"].operationId,
    });
  });

  it("accepts only the exact service response shape and keyed operation", () => {
    const input = {
      origin: route.url,
      runId,
      sandboxName,
      sessionId,
      serviceInstanceId,
      caseId: "external-pre" as const,
      challenge: `ch46_${"c".repeat(24)}`,
      expectedOperationId: `op46_${"o".repeat(43)}`,
    };
    const body = Buffer.from(`${JSON.stringify({
      schemaVersion: 1,
      testId: SBX046_TEST_ID,
      runId,
      sandboxName,
      sessionId,
      port: SBX046_PORT,
      serviceInstanceId,
      caseId: input.caseId,
      challenge: input.challenge,
      operationId: input.expectedOperationId,
      requestBodyValidated: true,
      ok: true,
    })}\n`);
    expect(exactExternalResponse(input, {
      statusCode: 200,
      headers: {
        "x-sbx046-service": "1",
        "cache-control": "no-store",
        connection: "close",
        "content-type": "application/json; charset=utf-8",
        "content-length": String(body.length),
      },
      body,
    })).toMatchObject({
      serviceHeader: "1",
      operationId: input.expectedOperationId,
      cacheControlValidated: true,
      connectionCloseValidated: true,
      contentTypeValidated: true,
      contentLengthValidated: true,
      exact: true,
    });
    expect(exactExternalResponse(input, {
      statusCode: 200,
      headers: {
        "x-sbx046-service": "1",
        "cache-control": "no-store",
        connection: "close",
        "content-type": "application/json; charset=utf-8",
      },
      body: Buffer.from(`${body.toString("utf8")} \n`),
    }).exact).toBe(false);
  });

  it("preserves the guest's exact loopback runtime facts and rejects missing evidence", () => {
    const challenge = `ch46_${"c".repeat(24)}`;
    const operationId = `op46_${"o".repeat(43)}`;
    const serviceResponse = {
      schemaVersion: 1,
      testId: SBX046_TEST_ID,
      runId,
      sandboxName,
      sessionId,
      port: SBX046_PORT,
      serviceInstanceId,
      caseId: "local-pre",
      challenge,
      operationId,
      requestBodyValidated: true,
      ok: true,
    };
    const value = {
      schemaVersion: 1,
      testId: SBX046_TEST_ID,
      runId,
      sandboxName,
      sessionId,
      port: SBX046_PORT,
      serviceInstanceId,
      caseId: "local-pre",
      challenge,
      expectedOperationId: operationId,
      targetBaseUrl: "http://127.0.0.1:3000",
      targetPath: "/v1/sbx046/canary",
      requestOrigin: "http://127.0.0.1:3000",
      requestPath: "/v1/sbx046/canary",
      method: "POST",
      timeoutMs: 3_000,
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
      statusCode: 200,
      responseBytes: 512,
      serviceHeaderValidated: true,
      cacheControlValidated: true,
      connectionCloseValidated: true,
      contentTypeValidated: true,
      contentLengthValidated: true,
      operationId,
      serviceResponse,
      ok: true,
      durationMs: 4.25,
    };
    const sanitized = sanitizeLocalProbeEvidence({
      value,
      commandExitCode: 0,
      stdoutBytes: 1_024,
      stderrBytes: 0,
      startedAt: "2026-08-19T12:00:00.000Z",
      completedAt: "2026-08-19T12:00:00.010Z",
      elapsedSinceRevocationAckMs: null,
    });
    expect(sanitized).toMatchObject({
      requestAttempts: 1,
      connectionAttempts: 1,
      actualRequests: 1,
      freshConnection: true,
      strictTlsVerification: false,
      tcpConnected: true,
      responseReceived: true,
      serviceResponse,
    });
    const missing = { ...value } as Partial<typeof value>;
    delete missing.actualRequests;
    expect(() => sanitizeLocalProbeEvidence({
      value: missing,
      commandExitCode: 0,
      stdoutBytes: 1_024,
      stderrBytes: 0,
      startedAt: "2026-08-19T12:00:00.000Z",
      completedAt: "2026-08-19T12:00:00.010Z",
      elapsedSinceRevocationAckMs: null,
    })).toThrow(/exact identity/u);
  });

  it("classifies only canonical DNS withdrawal or a short terminal edge response as conclusive denial", () => {
    expect(conclusiveTerminalRouteDenial(external())).toBe(true);
    expect(conclusiveTerminalRouteDenial(external({ requestPath: `/v1/sbx046/canary?run=${runId}` }))).toBe(false);
    expect(conclusiveTerminalRouteDenial(external({ requestOrigin: `${route.url}/not-an-origin` }))).toBe(false);
    expect(conclusiveTerminalRouteDenial(external({
      tcpConnected: true,
      tlsEstablished: true,
      tlsAuthorized: true,
      responseReceived: true,
      responseStatusCode: 404,
      errorCode: undefined,
      errorErrno: undefined,
      errorSyscall: undefined,
    }))).toBe(true);

    for (const ambiguous of [
      external({ errorCode: "EAI_AGAIN", errorErrno: -3_001 }),
      external({ errorCode: "ETIMEDOUT", errorErrno: undefined, errorSyscall: "connect", timedOut: true }),
      external({ errorCode: "ECONNRESET", errorErrno: -54, errorSyscall: "read", tcpConnected: true }),
      external({
        tcpConnected: true,
        tlsEstablished: true,
        tlsAuthorized: true,
        responseReceived: true,
        responseStatusCode: 200,
        errorCode: undefined,
        errorErrno: undefined,
        errorSyscall: undefined,
      }),
      external({
        tcpConnected: true,
        tlsEstablished: true,
        tlsAuthorized: true,
        responseReceived: true,
        responseStatusCode: 502,
        errorCode: undefined,
        errorErrno: undefined,
        errorSyscall: undefined,
      }),
      external({
        tcpConnected: true,
        tlsEstablished: true,
        tlsAuthorized: true,
        responseReceived: true,
        responseStatusCode: 503,
        errorCode: undefined,
        errorErrno: undefined,
        errorSyscall: undefined,
      }),
    ]) expect(conclusiveTerminalRouteDenial(ambiguous)).toBe(false);
  });

  it("settles partial resets and oversized responses without an unhandled response-stream error", async () => {
    const input = {
      origin: route.url,
      runId,
      sandboxName,
      sessionId,
      serviceInstanceId,
      caseId: "external-post-5s" as const,
      challenge: `ch46_${"c".repeat(24)}`,
      expectedOperationId: `op46_${"o".repeat(43)}`,
      timeoutMs: 250,
    };
    const reset = await performExternalProbe(input, fakeExternalRequest((response) => {
      response.write(Buffer.from("partial", "utf8"));
      response.destroy(Object.assign(new Error("synthetic reset"), {
        code: "ECONNRESET",
        syscall: "read",
      }));
    }));
    expect(reset).toMatchObject({
      responseReceived: true,
      responseBytes: 7,
      responseExact: false,
      errorCode: "ECONNRESET",
      errorSyscall: "read",
      rawResponseRetained: false,
    });

    const oversized = await performExternalProbe(input, fakeExternalRequest((response) => {
      response.write(Buffer.alloc(4_097, 0x46));
    }));
    expect(oversized).toMatchObject({
      responseReceived: true,
      responseBytes: 4_097,
      responseExact: false,
      errorCode: "EMSGSIZE",
      errorSyscall: "response",
      rawResponseRetained: false,
    });
  });

  it("uses one absolute deadline even while a response trickles without ending", async () => {
    const input = {
      origin: route.url,
      runId,
      sandboxName,
      sessionId,
      serviceInstanceId,
      caseId: "external-post-30s" as const,
      challenge: `ch46_${"d".repeat(24)}`,
      expectedOperationId: `op46_${"p".repeat(43)}`,
      timeoutMs: 250,
    };
    let destroyCount = 0;
    let resolutionCount = 0;
    const evidencePromise = performExternalProbe(input, fakeExternalRequest((response) => {
      const trickle = setInterval(() => response.write(Buffer.from("x", "utf8")), 20);
      response.once("close", () => clearInterval(trickle));
    }, () => {
      destroyCount += 1;
    })).then((evidence) => {
      resolutionCount += 1;
      return evidence;
    });
    const evidence = await evidencePromise;
    await new Promise<void>((resolveImmediate) => setImmediate(resolveImmediate));
    expect(evidence).toMatchObject({
      responseReceived: true,
      responseExact: false,
      timedOut: true,
      errorCode: "ETIMEDOUT",
      errorSyscall: "request",
      rawResponseRetained: false,
    });
    expect(evidence.responseBytes).toBeGreaterThan(0);
    expect(evidence.responseBytes).toBeLessThan(4_096);
    expect(evidence.durationMs).toBeGreaterThanOrEqual(200);
    expect(evidence.durationMs).toBeLessThan(1_000);
    expect(destroyCount).toBe(1);
    expect(resolutionCount).toBe(1);
  });

  it("will recover only one exact tagged nonpersistent resource in the bounded creation window", () => {
    const createAttemptedAt = "2026-08-19T12:00:00.000Z";
    const exact = {
      name: sandboxName,
      tags,
      persistent: false,
      createdAt: Date.parse(createAttemptedAt) + 500,
    };
    expect(recoverableSandboxIdentity({
      expectedName: sandboxName,
      expectedTags: tags,
      expectedPersistent: false,
      createAttemptedAt,
      candidate: exact,
      nowMs: exact.createdAt + 1_000,
    })).toBe(true);
    expect(recoverableSandboxIdentity({
      expectedName: sandboxName,
      expectedTags: tags,
      expectedPersistent: false,
      createAttemptedAt,
      candidate: { ...exact, tags: { ...tags, run: "other" } },
      nowMs: exact.createdAt + 1_000,
    })).toBe(false);
  });

  it("builds a secret-free recovery journal and refuses serialized raw secrets", () => {
    const journal = newRecoveryJournal({ runId, sandboxName, tags, startedAt: "2026-08-19T12:00:00.000Z" });
    expect(journal).toMatchObject({
      schemaVersion: 1,
      testId: SBX046_TEST_ID,
      sandboxName,
      persistent: false,
      keyStaged: false,
      completed: false,
    });
    expect(evidenceExcludesSecrets(journal, [hmacKey, "synthetic-token"])).toBe(true);
    expect(evidenceExcludesSecrets({ journal, accidental: hmacKey }, [hmacKey])).toBe(false);
    expect(safeToReleaseSbx046Lock(journal)).toBe(true);
    journal.createAttemptedAt = "2026-08-19T12:00:01.000Z";
    expect(safeToReleaseSbx046Lock(journal)).toBe(false);
    journal.completed = true;
    expect(safeToReleaseSbx046Lock(journal)).toBe(true);
  });
});
