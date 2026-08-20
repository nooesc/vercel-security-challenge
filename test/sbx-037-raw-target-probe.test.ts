import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

// This probe is intentionally shipped as a standalone guest .mjs without an out-of-scope declaration file.
// @ts-expect-error TS7016: focused tests exercise its narrow exported builder API directly.
import { buildRawRequest, responseReceipt, selectedHeaders, validateRawTargetProbeConfig } from "../guest/raw-forwardurl-target-probe.mjs";

const executeFile = promisify(execFile);
const probePath = fileURLToPath(new URL("../guest/raw-forwardurl-target-probe.mjs", import.meta.url));
const inheritedPlatformTrustEnvironmentNames = [
  "NODE_EXTRA_CA_CERTS",
  "NODE_USE_SYSTEM_CA",
  "OPENSSL_CONF",
  "OPENSSL_MODULES",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
] as const;

function configuration(overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: 1,
    scopeConfirmation: "researcher-controlled-sbx037-origins-only",
    researcherControlledOrigins: [
      "https://a.sbx037.example",
      "https://b.sbx037.example",
      "https://p.sbx037.example",
    ],
    runId: "run_sbx037_local",
    testId: "SBX-037-POC",
    caseId: "origin-control",
    correlationId: "corr_sbx037_local",
    expectedOperationId: "rt37r_ABCDEFGHIJKLMNOPQRSTUVWX",
    connectionRole: "a",
    aOrigin: "https://a.sbx037.example",
    bOrigin: "https://b.sbx037.example",
    pUrl: "https://p.sbx037.example/v1/proxy/run_sbx037_local/terminal",
    pinnedDestinationIpv4: "104.18.1.10",
    targetForm: "origin",
    targetPath: "/collect?case=origin-control",
    bodySource: "public",
    publicBody: "public:corr_sbx037_local",
    timeoutMs: 2_000,
    maxResponseHeaderBytes: 4_096,
    maxResponseBodyBytes: 2_048,
    ...overrides,
  };
}

function encoded(value: unknown) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

async function plan(value: unknown, env: NodeJS.ProcessEnv = process.env) {
  const result = await executeFile(process.execPath, [probePath, encoded(value), "--plan"], { env });
  return JSON.parse(result.stdout) as Record<string, any>;
}

async function rejected(value: unknown, env: NodeJS.ProcessEnv = process.env) {
  try {
    await executeFile(process.execPath, [probePath, encoded(value), "--plan"], { env });
    throw new Error("expected SBX-037 probe plan to fail");
  } catch (error) {
    const failure = error as Error & { code?: number; stdout?: string };
    return { code: failure.code, result: JSON.parse(failure.stdout ?? "{}") as Record<string, any> };
  }
}

describe("SBX-037 raw forwardURL request-target guest probe", () => {
  it("plans one POST origin-form control over fresh verified HTTP/1.1 TLS to A", async () => {
    const result = await plan(configuration());
    expect(result).toMatchObject({
      schemaVersion: 1,
      ok: true,
      phase: "plan",
      targetForm: "origin",
      method: "POST",
      bodySource: "public",
      requestBodyBytes: 24,
      operatorSecretLoaded: false,
      httpVersion: "1.1",
      tcpHost: "a.sbx037.example",
      tcpPort: 443,
      pinnedDestinationIpv4: "104.18.1.10",
      tlsServername: "a.sbx037.example",
      httpHost: "a.sbx037.example",
      rawRequestTarget: "/collect?case=origin-control",
      maximumConnections: 1,
      maximumRequests: 1,
      retryCount: 0,
      redirectsAllowed: false,
      redirectsFollowed: 0,
      connectionReused: false,
      environmentProxyTrust: false,
      tlsTrust: {
        inheritedPlatformTrustEnvironmentNames: inheritedPlatformTrustEnvironmentNames.filter(
          (name) => typeof process.env[name] === "string" && process.env[name]!.length > 0,
        ),
        controllerConfigurableCustomTrustAccepted: false,
        rejectUnauthorized: true,
      },
      connection: {
        host: "104.18.1.10",
        servername: "a.sbx037.example",
        rejectUnauthorized: true,
        minimumTlsVersion: "TLSv1.2",
        alpnProtocols: ["http/1.1"],
        freshConnection: true,
        absoluteDeadline: true,
      },
      request: {
        requestLine: "POST /collect?case=origin-control HTTP/1.1",
        rawRequestBytesExposed: false,
        responseBodyExposed: false,
        requiredControllerMinimumIntervalMs: 200,
        maximumQps: 5,
      },
    });
    expect(result.request.headerNames).toEqual([
      "host", "user-agent", "accept", "content-type", "content-length",
      "x-sbx037-run", "x-sbx037-test", "x-sbx037-case", "x-sbx-harness-canary", "connection",
    ]);
  });

  it("constructs absolute and network-path targets from owned B while retaining A Host byte-exactly", () => {
    for (const [targetForm, expectedTarget] of [
      ["absolute", "https://b.sbx037.example/collect?case=attack"],
      ["network-path", "//b.sbx037.example/collect?case=attack"],
    ] as const) {
      const config = validateRawTargetProbeConfig(configuration({
        caseId: `${targetForm}-attack`,
        targetForm,
        targetPath: "/collect?case=attack",
        bodySource: "file",
        bodyFile: "/tmp/sbx-037/operator-secret",
        publicBody: undefined,
      }));
      const synthetic = Buffer.from("synthetic-local-fixture", "ascii");
      const raw = buildRawRequest(config, synthetic).toString("ascii");
      expect(raw.startsWith(`POST ${expectedTarget} HTTP/1.1\r\nHost: a.sbx037.example\r\n`)).toBe(true);
      expect(raw.match(/\r\nContent-Length:/g)).toHaveLength(1);
      expect(raw).toContain(`\r\nContent-Length: ${synthetic.length}\r\n`);
      expect(raw).not.toMatch(/\r\nTransfer-Encoding:/iu);
      expect(raw.endsWith("\r\n\r\nsynthetic-local-fixture")).toBe(true);
    }
  });

  it("keeps canonical A/P/B distinct while selecting P as the verified socket/SNI/Host destination", async () => {
    const value = configuration({
      caseId: "absolute-p-syntax-control",
      correlationId: "corr_sbx037_p_syntax",
      connectionRole: "p",
      targetForm: "absolute",
      targetPath: "/v1/sbx037/collect/run_sbx037_local",
      publicBody: "public:corr_sbx037_p_syntax",
    });
    const validated = validateRawTargetProbeConfig(value);
    const raw = buildRawRequest(validated, Buffer.from(value.publicBody, "ascii")).toString("ascii");
    expect(raw).toContain("\r\nHost: p.sbx037.example\r\n");
    const result = await plan(value);
    expect(result).toMatchObject({
      connectionRole: "p",
      tcpHost: "p.sbx037.example",
      tlsServername: "p.sbx037.example",
      httpHost: "p.sbx037.example",
      rawRequestTarget: "https://b.sbx037.example/v1/sbx037/collect/run_sbx037_local",
      connection: {
        host: "104.18.1.10",
        servername: "p.sbx037.example",
        httpHost: "p.sbx037.example",
      },
    });
  });

  it("plans both attack forms without reading or exposing the fixed file secret", async () => {
    for (const targetForm of ["absolute", "network-path"] as const) {
      const result = await plan(configuration({
        caseId: `${targetForm}-attack`,
        targetForm,
        bodySource: "file",
        bodyFile: "/tmp/sbx-037/operator-secret",
        publicBody: undefined,
      }));
      expect(result.bodySource).toBe("file");
      expect(result.operatorSecretLoaded).toBe(false);
      expect(result.request.contentLengthComputedOnlyAtRuntime).toBe(true);
      expect(result.request.requestLine).toBe(
        targetForm === "absolute"
          ? "POST https://b.sbx037.example/collect?case=origin-control HTTP/1.1"
          : "POST //b.sbx037.example/collect?case=origin-control HTTP/1.1",
      );
      const serialized = JSON.stringify(result);
      expect(serialized).not.toContain("/tmp/sbx-037/operator-secret");
      expect(serialized).not.toContain("synthetic-local-fixture");
      expect(serialized).not.toContain("requestBodyBytes");
      expect(serialized).not.toContain("rawRequestBase64");
      expect(serialized).not.toContain('"rawRequestBytes":"');
      expect(serialized).not.toContain("sha256");
    }
  });

  it("cannot serialize a reflected file secret through receipt or selected-header fields", () => {
    const config = validateRawTargetProbeConfig(configuration({
      targetForm: "absolute",
      bodySource: "file",
      bodyFile: "/tmp/sbx-037/operator-secret",
      publicBody: undefined,
    }));
    const reflected = "synthetic-file-secret-that-must-not-escape";
    const headers = new Map<string, string[]>([
      ["content-type", [reflected]],
      ["x-sbx-operation-id", [reflected]],
      ["x-sbx037-run", [reflected]],
      ["x-sbx-role", [reflected]],
      ["x-sbx037-fallback-receipt", [reflected]],
    ]);
    const body = Buffer.from(JSON.stringify({
      operationId: reflected,
      runId: reflected,
      testId: reflected,
      caseId: reflected,
      correlationId: reflected,
      role: reflected,
      receivedBy: reflected,
      authenticated: true,
    }));
    const evidence = {
      headers: selectedHeaders(headers, config),
      receipt: responseReceipt(body, headers, config),
    };
    expect(JSON.stringify(evidence)).not.toContain(reflected);
    expect(evidence.receipt).toEqual({
      jsonObject: true,
      authenticated: true,
      fallbackReceiptConflict: true,
    });

    const exact = new Map<string, string[]>([["x-sbx-operation-id", [config.expectedOperationId]]]);
    expect(responseReceipt(
      Buffer.from(JSON.stringify({ operationId: config.expectedOperationId })),
      exact,
      config,
    )).toMatchObject({ operationId: config.expectedOperationId });
  });

  it("retains only a canonical fallback receipt and an exact receiver role", () => {
    const config = validateRawTargetProbeConfig(configuration());
    const fallbackReceiptId = "rt37f_ABCDEFGHIJKLMNOPQRSTUVWX";
    const headers = new Map<string, string[]>([
      ["content-type", ["application/json; charset=utf-8"]],
      ["x-sbx-role", ["P"]],
      ["x-sbx037-fallback-receipt", [fallbackReceiptId]],
    ]);
    expect(selectedHeaders(headers, config)).toMatchObject({
      "x-sbx-role": "P",
      "x-sbx037-fallback-receipt": fallbackReceiptId,
    });
    expect(responseReceipt(Buffer.from("{}"), headers, config)).toEqual({
      jsonObject: true,
      fallbackReceiptId,
      role: "P",
    });

    expect(responseReceipt(Buffer.from('{"role":"B"}'), headers, config)).toMatchObject({
      jsonObject: true,
      fallbackReceiptId,
      roleConflict: true,
    });
  });

  it("is deterministic and network-free in plan mode", async () => {
    const input = configuration({ targetForm: "network-path", caseId: "network-b" });
    expect(await plan(input)).toEqual(await plan(input));
  });

  it.each([
    ["scope mismatch", { scopeConfirmation: "yes" }, "scopeConfirmation"],
    ["wrong schema", { schemaVersion: 2 }, "schemaVersion"],
    ["unsupported target form", { targetForm: "authority" }, "targetForm"],
    ["unsupported connection role", { connectionRole: "outside" }, "connectionRole"],
    ["raw CRLF in path", { targetPath: "/collect\r\nHost: attacker.test" }, "control character"],
    ["raw tab in path", { targetPath: "/collect\tmore" }, "control character"],
    ["double slash path", { targetPath: "//attacker.test/collect" }, "single-slash"],
    ["path backslash", { targetPath: "/collect\\escape" }, "single-slash"],
    ["path fragment", { targetPath: "/collect#fragment" }, "single-slash"],
    ["invalid identifier", { correlationId: "corr with spaces" }, "unsupported characters"],
    ["non-HTTPS A", { aOrigin: "http://a.sbx037.example" }, "HTTPS origin"],
    ["origin credentials", { bOrigin: "https://user:pass@b.sbx037.example" }, "without credentials"],
    ["origin path", { aOrigin: "https://a.sbx037.example/path" }, "without credentials, path"],
    ["P fragment", { pUrl: "https://p.sbx037.example/terminal#fragment" }, "without credentials"],
    ["IP SNI", { aOrigin: "https://203.0.113.10" }, "DNS hostname"],
    ["body control", { publicBody: "public\r\nsmuggled" }, "control character"],
  ])("rejects %s", async (_name, override, message) => {
    const failure = await rejected(configuration(override));
    expect(failure.code).toBe(2);
    expect(failure.result).toMatchObject({ ok: false, phase: "configuration" });
    expect(failure.result.errorMessage).toContain(message);
  });

  it("requires ownership declarations to match exact distinct A, B, and P origins", async () => {
    const mismatched = await rejected(configuration({ researcherControlledOrigins: [
      "https://a.sbx037.example", "https://b.sbx037.example", "https://unowned.example",
    ] }));
    expect(mismatched.result.errorMessage).toContain("exactly match A, B, and P");

    const collapsed = await rejected(configuration({
      pUrl: "https://a.sbx037.example/terminal",
      researcherControlledOrigins: [
        "https://a.sbx037.example", "https://b.sbx037.example", "https://a.sbx037.example",
      ],
    }));
    expect(collapsed.result.errorMessage).toContain("three distinct HTTPS origins");
  });

  it.each([
    [undefined, "canonical public IPv4"],
    ["a.sbx037.example", "canonical public IPv4"],
    ["::1", "canonical public IPv4"],
    ["127.0.0.1", "canonical public IPv4"],
    ["10.0.0.1", "canonical public IPv4"],
    ["169.254.169.254", "canonical public IPv4"],
    ["192.168.1.1", "canonical public IPv4"],
    ["203.0.113.10", "canonical public IPv4"],
  ])("rejects unsafe pinned destination %s", async (pinnedDestinationIpv4, message) => {
    const failure = await rejected(configuration({ pinnedDestinationIpv4 }));
    expect(failure.code).toBe(2);
    expect(failure.result.errorMessage).toContain(message);
  });

  it.each([
    ["rejectUnauthorized", false], ["ca", "test"], ["caPem", "test"],
    ["checkServerIdentity", "test"], ["servername", "b.sbx037.example"],
    ["proxy", "http://127.0.0.1:8080"], ["headers", { Host: "b.sbx037.example" }],
    ["retryCount", 1], ["maxRedirects", 1],
  ])("rejects configurable transport override %s", async (key, value) => {
    const failure = await rejected(configuration({ [key]: value }));
    expect(failure.code).toBe(2);
    expect(failure.result.errorMessage).toContain("cannot be configured");
  });

  it("rejects a process-wide TLS verification bypass even in plan mode", async () => {
    const failure = await rejected(configuration(), { ...process.env, NODE_TLS_REJECT_UNAUTHORIZED: "0" });
    expect(failure.code).toBe(2);
    expect(failure.result.errorMessage).toContain("NODE_TLS_REJECT_UNAUTHORIZED=0 is forbidden");
  });

  it("permits inherited platform trust inputs without exposing or accepting their values as configuration", async () => {
    const inheritedValues = Object.fromEntries(inheritedPlatformTrustEnvironmentNames.map(
      (name, index) => [name, `/private/platform-trust-value-${index}-${name.toLowerCase()}`],
    ));
    const result = await plan(configuration(), { ...process.env, ...inheritedValues });
    expect(result.tlsTrust).toEqual({
      inheritedPlatformTrustEnvironmentNames: [...inheritedPlatformTrustEnvironmentNames],
      controllerConfigurableCustomTrustAccepted: false,
      rejectUnauthorized: true,
    });
    for (const value of Object.values(inheritedValues)) expect(JSON.stringify(result)).not.toContain(value);
    for (const name of inheritedPlatformTrustEnvironmentNames) {
      const configured = await rejected(configuration({ [name]: inheritedValues[name] }));
      expect(configured.result.errorMessage).toContain("unknown configuration field");
    }
  });

  it.each(["--no-warnings", "\"--use-system-ca\"", "--require=node:assert"]) (
    "rejects NODE_OPTIONS %s",
    async (nodeOptions) => {
      const failure = await rejected(configuration(), { ...process.env, NODE_OPTIONS: nodeOptions });
      expect(failure.code).toBe(2);
      expect(failure.result.errorMessage).toContain("NODE_OPTIONS is forbidden");
    },
  );
  it("uses only public bodies for origin controls and only the fixed file for attacks", async () => {
    const originFile = await rejected(configuration({
      bodySource: "file", bodyFile: "/tmp/sbx-037/operator-secret", publicBody: undefined,
    }));
    expect(originFile.result.errorMessage).toContain("only for absolute or network-path");

    const wrongFile = await rejected(configuration({
      targetForm: "absolute", bodySource: "file", bodyFile: "/tmp/other", publicBody: undefined,
    }));
    expect(wrongFile.result.errorMessage).toContain("fixed SBX-037 operator-secret path");

    const unusedFile = await rejected(configuration({ bodyFile: "/tmp/sbx-037/operator-secret" }));
    expect(unusedFile.result.errorMessage).toContain("forbidden for a public body");
  });

  it("enforces response and timeout bounds", async () => {
    for (const override of [
      { timeoutMs: 16_000 }, { maxResponseHeaderBytes: 16_385 },
      { maxResponseBodyBytes: 8_193 }, { maxResponseBodyBytes: 0 },
    ]) {
      const failure = await rejected(configuration(override));
      expect(failure.code).toBe(2);
      expect(failure.result.errorMessage).toContain("must be an integer");
    }
  });

  it("rejects malformed base64url and extra CLI modes before probing", async () => {
    for (const argument of ["%%%", "e30="]) {
      try {
        await executeFile(process.execPath, [probePath, argument, "--plan"]);
        throw new Error("expected malformed configuration to fail");
      } catch (error) {
        const failure = error as Error & { code?: number; stdout?: string };
        expect(failure.code).toBe(2);
        expect(JSON.parse(failure.stdout ?? "{}").phase).toBe("configuration");
      }
    }
    try {
      await executeFile(process.execPath, [probePath, encoded(configuration()), "--live-twice"]);
      throw new Error("expected extra mode to fail");
    } catch (error) {
      const failure = error as Error & { code?: number; stdout?: string };
      expect(failure.code).toBe(2);
      expect(JSON.parse(failure.stdout ?? "{}").errorMessage).toContain("only --plan");
    }
  });
});
