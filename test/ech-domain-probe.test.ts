import { spawnSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  assessEchAllowlist,
  authenticatedSuccess,
  buildProbeConfiguration,
  conclusiveFirewallBlock,
  expectedOperationId,
  extractEchConfigFromDnsJson,
  isExactCoverOnlyPolicy,
  parseEchConfigList,
  type EchAssessmentInput,
  type ProbeRecord,
} from "../pocs/SBX-031/ech-domain-allowlist.js";

const probePath = fileURLToPath(new URL("../guest/ech-domain-probe.py", import.meta.url));
const endpoint = new URL("https://owned-worker.example.invalid/v1/h3-action");
const pinnedIPv4 = "1.1.1.1";
const runId = "run-ech-unit";
const publicCanary = "public_0123456789abcdef";
const operatorSecret = "operator_0123456789abcdef";
const key = "unit-test-controller-key-32-bytes-minimum";
const publicName = "cloudflare-ech.com";

function syntheticEchConfigList(name = publicName): string {
  const publicNameBytes = Buffer.from(name, "ascii");
  const contents = Buffer.concat([
    Buffer.from([0x17]),
    Buffer.from([0x00, 0x20]),
    Buffer.from([0x00, 0x20]),
    Buffer.alloc(32, 0xa5),
    Buffer.from([0x00, 0x04, 0x00, 0x01, 0x00, 0x01]),
    Buffer.from([0x00, publicNameBytes.length]),
    publicNameBytes,
    Buffer.from([0x00, 0x00]),
  ]);
  const config = Buffer.concat([
    Buffer.from([0xfe, 0x0d, contents.length >> 8, contents.length & 0xff]),
    contents,
  ]);
  return Buffer.concat([
    Buffer.from([config.length >> 8, config.length & 0xff]),
    config,
  ]).toString("base64");
}

const echConfigListBase64 = syntheticEchConfigList();

function u16(value: number): Buffer {
  return Buffer.from([value >> 8, value & 0xff]);
}

function syntheticClientHello(hostname: string, ech: boolean): { header: Buffer; payload: Buffer } {
  const hostnameBytes = Buffer.from(hostname, "ascii");
  const serverName = Buffer.concat([Buffer.from([0]), u16(hostnameBytes.length), hostnameBytes]);
  const sniData = Buffer.concat([u16(serverName.length), serverName]);
  const extension = (type: number, data: Buffer) => Buffer.concat([u16(type), u16(data.length), data]);
  const extensions = Buffer.concat([
    extension(0, sniData),
    ...(ech ? [extension(0xfe0d, Buffer.from([0]))] : []),
  ]);
  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    Buffer.alloc(32, 0x42),
    Buffer.from([0]),
    u16(2),
    Buffer.from([0x13, 0x01]),
    Buffer.from([1, 0]),
    u16(extensions.length),
    extensions,
  ]);
  const payload = Buffer.concat([
    Buffer.from([1, body.length >> 16, (body.length >> 8) & 0xff, body.length & 0xff]),
    body,
  ]);
  return {
    header: Buffer.concat([Buffer.from([22, 3, 1]), u16(payload.length)]),
    payload,
  };
}

function runGuestWireParser(hostname: string, ech: boolean) {
  const hello = syntheticClientHello(hostname, ech);
  return spawnSync("python3", [
    "-c",
    [
      "import base64,importlib.util,json,sys",
      "spec=importlib.util.spec_from_file_location('sbx031_guest',sys.argv[1])",
      "module=importlib.util.module_from_spec(spec)",
      "spec.loader.exec_module(module)",
      "_,callback,summarize=module.new_wire_collector(sys.argv[2])",
      "callback(6,b'\\x01\\x00\\x00\\x00')",
      "callback(6,base64.b64decode(sys.argv[3]))",
      "callback(6,base64.b64decode(sys.argv[4]))",
      "print(json.dumps(summarize(),separators=(',',':')))",
    ].join(";"),
    probePath,
    hostname,
    hello.header.toString("base64"),
    hello.payload.toString("base64"),
  ], { encoding: "utf8", timeout: 5_000 });
}

function guestConfiguration(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    scopeConfirmation: "I_CONTROL_THE_ENDPOINT_AND_AUTHORIZE_BOUNDED_ECH_TESTING",
    endpointUrl: endpoint.href,
    pinnedIPv4,
    echConfigListBase64,
    echPublicName: publicName,
    runId,
    testId: "SBX-031-POC",
    caseId: "allow-ech-control",
    publicCanary,
    mode: "ech",
    timeoutSeconds: 8,
    maxResponseBytes: 1_024,
    ...overrides,
  };
}

function runGuestPlan(configuration: Record<string, unknown>) {
  const encoded = Buffer.from(JSON.stringify(configuration)).toString("base64url");
  return spawnSync("python3", [probePath, encoded, "--plan"], {
    encoding: "utf8",
    timeout: 5_000,
  });
}

function commandRecord(exitCode = 0) {
  return {
    commandId: "cmd_unit",
    exitCode,
    stdoutByteLength: 100,
    stdoutSha256: "a".repeat(64),
    stderrByteLength: 0,
    stderrSha256: "b".repeat(64),
  };
}

function successfulProbe(
  caseId: string,
  mode: "plain" | "ech",
  canary: string,
): ProbeRecord {
  const operationId = expectedOperationId(key, runId, caseId, canary);
  return {
    caseId,
    mode,
    canarySource: caseId === "restricted-ech-target"
      ? "operator-secret-file"
      : "controller-public-canary",
    configurationSha256: "c".repeat(64),
    expectedOperationId: operationId,
    command: commandRecord(),
    result: {
      ok: true,
      phase: "response",
      runId,
      testId: "SBX-031-POC",
      caseId,
      probeMode: mode,
      canarySource: caseId === "restricted-ech-target"
        ? "operator-secret-file"
        : "controller-public-canary",
      requestedHttpVersion: "v2",
      echRequired: mode === "ech",
      echDisabled: mode === "plain",
      echPublicName: publicName,
      onWireClientHelloAttestationRequired: true,
      expectedOuterSni: mode === "ech" ? publicName : endpoint.hostname,
      echExtensionRequiredOnWire: mode === "ech",
      exactlyOneFramedClientHelloRequired: true,
      echConfigurationSource: "controller-dns-https-record",
      endpointHostname: endpoint.hostname,
      pinnedIPv4,
      pinnedPort: 443,
      tlsVerificationRequired: true,
      tlsVerifiedByClient: true,
      redirectsAllowed: false,
      environmentProxyTrust: false,
      proxyOptionForcedEmpty: true,
      noProxyOption: "*",
      dnsPinnedWithCurlResolve: true,
      freshConnectionRequired: true,
      curlCffiVersion: "0.13.0",
      onWireClientHello: {
        source: "libcurl-debug-ssl-data-out-framed-record",
        sslDataOutEventCount: 6,
        sslDataOutByteLength: 700,
        collectorOverflow: false,
        collectorError: false,
        framedClientHelloCount: 1,
        expectedOuterSni: mode === "ech" ? publicName : endpoint.hostname,
        tlsRecordContentType: 22,
        tlsRecordByteLength: 517,
        clientHelloByteLength: 512,
        clientHelloSha256: "e".repeat(64),
        outerSni: mode === "ech" ? publicName : endpoint.hostname,
        echExtensionPresent: mode === "ech",
        outerSniMatchesExpected: true,
      },
      response: {
        statusCode: 200,
        actualHttpVersion: 3,
        primaryIp: pinnedIPv4,
        primaryPort: 443,
        redirectCount: 0,
        contentType: "application/json; charset=utf-8",
        cacheControl: "no-store",
        bodyByteLength: 80,
      },
      authorized: true,
      operationIdShapeValid: true,
      operationId,
      expectedHttp2ResponseVersion: 3,
    },
  };
}

function blockedProbe(
  caseId: "restricted-plain-negative" | "restricted-ech-target",
  mode: "plain" | "ech",
  curlErrorCode: number,
): ProbeRecord {
  return {
    caseId,
    mode,
    canarySource: caseId === "restricted-ech-target"
      ? "operator-secret-file"
      : "controller-public-canary",
    configurationSha256: "d".repeat(64),
    expectedOperationId: expectedOperationId(
      key,
      runId,
      caseId,
      caseId === "restricted-ech-target" ? operatorSecret : publicCanary,
    ),
    command: commandRecord(),
    result: {
      ok: false,
      phase: "request",
      runId,
      testId: "SBX-031-POC",
      caseId,
      probeMode: mode,
      canarySource: caseId === "restricted-ech-target"
        ? "operator-secret-file"
        : "controller-public-canary",
      requestedHttpVersion: "v2",
      echRequired: mode === "ech",
      echDisabled: mode === "plain",
      echPublicName: publicName,
      onWireClientHelloAttestationRequired: true,
      expectedOuterSni: mode === "ech" ? publicName : endpoint.hostname,
      echExtensionRequiredOnWire: mode === "ech",
      exactlyOneFramedClientHelloRequired: true,
      echConfigurationSource: "controller-dns-https-record",
      endpointHostname: endpoint.hostname,
      pinnedIPv4,
      pinnedPort: 443,
      tlsVerificationRequired: true,
      redirectsAllowed: false,
      environmentProxyTrust: false,
      proxyOptionForcedEmpty: true,
      noProxyOption: "*",
      dnsPinnedWithCurlResolve: true,
      freshConnectionRequired: true,
      curlCffiVersion: "0.13.0",
      onWireClientHello: {
        source: "libcurl-debug-ssl-data-out-framed-record",
        sslDataOutEventCount: 3,
        sslDataOutByteLength: 517,
        collectorOverflow: false,
        collectorError: false,
        framedClientHelloCount: 1,
        expectedOuterSni: mode === "ech" ? publicName : endpoint.hostname,
        tlsRecordContentType: 22,
        tlsRecordByteLength: 517,
        clientHelloByteLength: 512,
        clientHelloSha256: "f".repeat(64),
        outerSni: mode === "ech" ? publicName : endpoint.hostname,
        echExtensionPresent: mode === "ech",
        outerSniMatchesExpected: true,
      },
      curlErrorCode,
      responseStatusCode: 0,
      actualHttpVersion: 0,
      primaryIp: "",
      primaryPort: 0,
    },
  };
}

function candidateInput(overrides: Partial<EchAssessmentInput> = {}): EchAssessmentInput {
  return {
    setupPassed: true,
    allowPlainControlPassed: true,
    allowEchControlPassed: true,
    restrictedUpdateAcknowledged: true,
    restrictedReadbackPassed: true,
    restrictedPlainBlocked: true,
    restrictedEchSucceeded: true,
    restrictedEchBlocked: false,
    cleanupPassed: true,
    ...overrides,
  };
}

describe("SBX-031 ECHConfig parsing", () => {
  it("extracts one consistent public_name from a bounded ECHConfigList", () => {
    expect(parseEchConfigList(echConfigListBase64)).toMatchObject({
      configCount: 1,
      publicName,
      byteLength: 71,
    });
    expect(parseEchConfigList(echConfigListBase64).sha256).toMatch(/^[a-f0-9]{64}$/u);
  });

  it("extracts the ECHConfigList only from the endpoint's DNS HTTPS answer", () => {
    const selected = extractEchConfigFromDnsJson({
      Status: 0,
      TC: false,
      Answer: [
        { name: "other.invalid", type: 65, TTL: 300, data: `1 . ech=${echConfigListBase64}` },
        {
          name: `${endpoint.hostname}.`,
          type: 65,
          TTL: 300,
          data: `1 . alpn=h3,h2 ech=${echConfigListBase64} ipv4hint=1.1.1.1`,
        },
      ],
    }, endpoint.hostname);
    expect(selected).toMatchObject({ ttl: 300, base64: echConfigListBase64 });
    expect(selected.details.publicName).toBe(publicName);
  });

  it("rejects malformed lists and inconsistent DNS answers", () => {
    expect(() => parseEchConfigList(Buffer.from("not-ech").toString("base64"))).toThrow();
    expect(() => extractEchConfigFromDnsJson({ Status: 2, TC: false, Answer: [] }, endpoint.hostname)).toThrow();
  });
});

describe("SBX-031 guest plan", () => {
  it("strictly extracts outer SNI and ECH presence from one TLS-framed ClientHello", () => {
    const ech = runGuestWireParser(publicName, true);
    expect(ech.status).toBe(0);
    expect(JSON.parse(ech.stdout)).toMatchObject({
      source: "libcurl-debug-ssl-data-out-framed-record",
      framedClientHelloCount: 1,
      tlsRecordContentType: 22,
      outerSni: publicName,
      echExtensionPresent: true,
      outerSniMatchesExpected: true,
    });
    expect(JSON.parse(ech.stdout).clientHelloSha256).toMatch(/^[a-f0-9]{64}$/u);

    const plain = runGuestWireParser(endpoint.hostname, false);
    expect(plain.status).toBe(0);
    expect(JSON.parse(plain.stdout)).toMatchObject({
      outerSni: endpoint.hostname,
      echExtensionPresent: false,
    });
  });

  it("fixes ECH, HTTP/2, verified TLS, IP pinning, fresh connections, and one request", () => {
    const child = runGuestPlan(guestConfiguration());
    expect(child.status).toBe(0);
    expect(JSON.parse(child.stdout)).toMatchObject({
      ok: true,
      phase: "plan",
      probeMode: "ech",
      canarySource: "controller-public-canary",
      endpointHostname: endpoint.hostname,
      pinnedIPv4,
      requestedHttpVersion: "v2",
      actualHttpVersionRequired: "v2",
      echRequired: true,
      echDisabled: false,
      echPublicName: publicName,
      onWireClientHelloAttestationRequired: true,
      expectedOuterSni: publicName,
      echExtensionRequiredOnWire: true,
      exactlyOneFramedClientHelloRequired: true,
      tlsVerificationRequired: true,
      redirectsAllowed: false,
      environmentProxyTrust: false,
      proxyOptionForcedEmpty: true,
      noProxyOption: "*",
      dnsPinnedWithCurlResolve: true,
      freshConnectionRequired: true,
      maximumRequests: 1,
      maximumReceiveChunkBytes: 1_024,
    });
  });

  it("rejects caller overrides and a public canary in the target case", () => {
    for (const overrides of [
      { verify: false },
      { proxy: "http://127.0.0.1:8080" },
      { echPublicName: "different.invalid" },
      { endpointUrl: "https://owned-worker.example.invalid/not-action" },
    ]) {
      const child = runGuestPlan(guestConfiguration(overrides));
      expect(child.status).toBe(2);
      expect(JSON.parse(child.stdout)).toMatchObject({ ok: false, phase: "configuration" });
    }

    const forbiddenCanary = runGuestPlan(guestConfiguration({
      caseId: "restricted-ech-target",
      mode: "ech",
    }));
    expect(forbiddenCanary.status).toBe(2);
    const target = guestConfiguration({ caseId: "restricted-ech-target", mode: "ech" });
    delete target.publicCanary;
    expect(runGuestPlan(target).status).toBe(0);
  });
});

describe("SBX-031 policy and endpoint proof", () => {
  it("accepts only an exact cover-only domain policy", () => {
    expect(isExactCoverOnlyPolicy({ allow: [publicName] }, publicName)).toBe(true);
    expect(isExactCoverOnlyPolicy({ allow: { [publicName]: [] } }, publicName)).toBe(true);
    expect(isExactCoverOnlyPolicy({ allow: [publicName], subnets: {} }, publicName)).toBe(false);
    expect(isExactCoverOnlyPolicy({ allow: [publicName, endpoint.hostname] }, publicName)).toBe(false);
    expect(isExactCoverOnlyPolicy({ allow: ["*.cloudflare-ech.com"] }, publicName)).toBe(false);
  });

  it("matches the owned Worker HMAC contract exactly", () => {
    const independent = `h3_${createHmac("sha256", key)
      .update(`${runId}\nallow-ech-control\n${publicCanary}`)
      .digest("base64url")}`;
    expect(expectedOperationId(key, runId, "allow-ech-control", publicCanary)).toBe(independent);
    expect(independent).toMatch(/^h3_[A-Za-z0-9_-]{43}$/u);
  });

  it("keeps the synthetic operator secret out of target configuration", () => {
    const configuration = buildProbeConfiguration({
      endpointUrl: endpoint.href,
      pinnedIPv4,
      echConfigListBase64,
      echPublicName: publicName,
      runId,
      caseId: "restricted-ech-target",
      mode: "ech",
    });
    expect(configuration).not.toHaveProperty("publicCanary");
    expect(JSON.stringify(configuration)).not.toContain(operatorSecret);
    expect(() => buildProbeConfiguration({
      endpointUrl: endpoint.href,
      pinnedIPv4,
      echConfigListBase64,
      echPublicName: publicName,
      runId,
      caseId: "restricted-ech-target",
      mode: "ech",
      publicCanary: operatorSecret,
    })).toThrow();
  });

  it("requires exact ECH/H2/IP/TLS/operation proof for target success", () => {
    const target = successfulProbe("restricted-ech-target", "ech", operatorSecret);
    expect(authenticatedSuccess(target, runId, target.caseId, target.mode, endpoint, pinnedIPv4)).toBe(true);

    const wrongMode = structuredClone(target);
    wrongMode.result!.echRequired = false;
    expect(authenticatedSuccess(wrongMode, runId, wrongMode.caseId, wrongMode.mode, endpoint, pinnedIPv4)).toBe(false);

    const wrongVersion = structuredClone(target);
    (wrongVersion.result!.response as Record<string, unknown>).actualHttpVersion = 2;
    expect(authenticatedSuccess(wrongVersion, runId, wrongVersion.caseId, wrongVersion.mode, endpoint, pinnedIPv4)).toBe(false);

    const wrongIp = structuredClone(target);
    (wrongIp.result!.response as Record<string, unknown>).primaryIp = "8.8.8.8";
    expect(authenticatedSuccess(wrongIp, runId, wrongIp.caseId, wrongIp.mode, endpoint, pinnedIPv4)).toBe(false);

    const wrongOperation = structuredClone(target);
    wrongOperation.result!.operationId = `h3_${"x".repeat(43)}`;
    expect(authenticatedSuccess(wrongOperation, runId, wrongOperation.caseId, wrongOperation.mode, endpoint, pinnedIPv4)).toBe(false);

    const wrongOuterSni = structuredClone(target);
    (wrongOuterSni.result!.onWireClientHello as Record<string, unknown>).outerSni = endpoint.hostname;
    expect(authenticatedSuccess(wrongOuterSni, runId, wrongOuterSni.caseId, wrongOuterSni.mode, endpoint, pinnedIPv4)).toBe(false);

    const missingEchExtension = structuredClone(target);
    (missingEchExtension.result!.onWireClientHello as Record<string, unknown>).echExtensionPresent = false;
    expect(authenticatedSuccess(missingEchExtension, runId, missingEchExtension.caseId, missingEchExtension.mode, endpoint, pinnedIPv4)).toBe(false);

    const ambiguousClientHellos = structuredClone(target);
    (ambiguousClientHellos.result!.onWireClientHello as Record<string, unknown>).framedClientHelloCount = 2;
    expect(authenticatedSuccess(ambiguousClientHellos, runId, ambiguousClientHellos.caseId, ambiguousClientHellos.mode, endpoint, pinnedIPv4)).toBe(false);
  });

  it("accepts active pre-response firewall errors but not timeout or ECH rejection", () => {
    for (const code of [7, 35, 52, 56]) {
      expect(conclusiveFirewallBlock(
        blockedProbe("restricted-plain-negative", "plain", code),
        runId,
        "restricted-plain-negative",
        "plain",
        endpoint,
        pinnedIPv4,
      )).toBe(true);
    }
    for (const code of [28, 101]) {
      expect(conclusiveFirewallBlock(
        blockedProbe("restricted-ech-target", "ech", code),
        runId,
        "restricted-ech-target",
        "ech",
        endpoint,
        pinnedIPv4,
      )).toBe(false);
    }
  });
});

describe("SBX-031 assessment", () => {
  it("classifies exact exfiltration proof as a candidate", () => {
    expect(assessEchAllowlist(candidateInput())).toMatchObject({
      verdict: "candidate",
      candidate: true,
      controlsPassed: true,
    });
  });

  it("classifies a conclusive ECH block as pass", () => {
    expect(assessEchAllowlist(candidateInput({
      restrictedEchSucceeded: false,
      restrictedEchBlocked: true,
    }))).toMatchObject({ verdict: "pass", candidate: false, controlsPassed: true });
  });

  it("never upgrades missing controls, ambiguity, cleanup failure, or execution error", () => {
    expect(assessEchAllowlist(candidateInput({ restrictedPlainBlocked: false })).verdict).toBe("indeterminate");
    expect(assessEchAllowlist(candidateInput({
      restrictedEchSucceeded: false,
      restrictedEchBlocked: false,
    })).verdict).toBe("indeterminate");
    expect(assessEchAllowlist(candidateInput({ cleanupPassed: false })).verdict).toBe("error");
    expect(assessEchAllowlist(candidateInput({ executionError: true })).verdict).toBe("error");
  });
});
