import { execFile as execFileCallback, execFileSync, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer, connect } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import {
  Sbx036ReceiverLedger,
  encodeSbx036PreTlsFrame,
  parseSbx036PreTlsFrame,
  parseSbx036StartupMessage,
  startSbx036Receiver,
  type ConnectionMeta,
  type Sbx036EndpointIdentity,
  type Sbx036ListenerOptions,
  type Sbx036RunConfiguration,
} from "../pocs/SBX-036/receiver.js";
import {
  SBX036_PUBLIC_CASES,
  SBX036_SECRET_CASES,
  SBX036_SSL_REQUEST_CODE,
  SBX036_SSL_REQUEST_HEX,
  SBX036_TEST_ID,
  assessSbx036Public,
  assessSbx036Secret,
  deriveSbx036PublicOperationId,
  deriveSbx036SecretCommitment,
  deriveSbx036SecretOperationId,
  exactSbx036PolicyReadback,
  type Sbx036HttpsControlEvidence,
  type Sbx036PublicAssessmentInput,
  type Sbx036ProbeEvidence,
  type Sbx036ReceiverStatus,
} from "../pocs/SBX-036/verdict.js";
import {
  exactSbx036OutsidePreCreateGate,
  parseSbx036ReceiverStatus,
  runSbx036PreCreateGate,
  sanitizeHealth,
  sanitizeProbe,
} from "../pocs/SBX-036/postgres-pre-tls-coalescing.js";

const execFile = promisify(execFileCallback);
const guestPath = resolve("guest/postgres-pre-tls-coalescing-probe.py");
const scope = "I_CONTROL_DISTINCT_HTTPS_ALLOW_AND_DIRECT_POSTGRES_DENIED_ENDPOINTS_AND_AUTHORIZE_BOUNDED_PRETLS_TESTING";
const runId = "123e4567-e89b-42d3-a456-426614174000";
const secretRunId = "223e4567-e89b-42d3-a456-426614174001";
const publicCanary = "pub_ABCDEFGHIJKLMNOPQRSTUVWX";
const receiverKey = "receiver-key-that-is-long-enough-for-sbx036-tests";
const allowed: Sbx036EndpointIdentity = {
  hostname: "vsc-h3-action-swve.cyrus-206.workers.dev",
  publicIPv4: "8.8.8.8",
  port: 443,
};
const denied: Sbx036ListenerOptions = {
  hostname: "pg-b.example.test",
  publicIPv4: "9.9.9.9",
  bindHost: "127.0.0.1",
  port: 15432,
  certificatePath: "/unused/cert",
  privateKeyPath: "/unused/key",
};
const epoch = "323e4567-e89b-42d3-a456-426614174002";
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map(async (directory) => rm(directory, { recursive: true, force: true })));
});

function probeConfiguration(mode: string, caseId = "restricted-b-coalesced-target") {
  return {
    scopeConfirmation: scope,
    mode,
    runId,
    testId: SBX036_TEST_ID,
    caseId,
    endpointRole: "denied",
    endpointHostname: denied.hostname,
    pinnedIPv4: denied.publicIPv4,
    pinnedPort: 10_000,
    ...(mode === "coalesced-secret" ? {} : { publicCanary }),
    ...(mode === "postgres-tls" || mode === "coalesced-tls"
      ? { expectedOperationId: deriveSbx036PublicOperationId(receiverKey, runId, caseId, publicCanary) }
      : {}),
    timeoutMs: 3_000,
    maxResponseBytes: 1_024,
  };
}

function runPlan(mode: string) {
  const encoded = Buffer.from(JSON.stringify(probeConfiguration(mode))).toString("base64url");
  return spawnSync("python3", [guestPath, encoded, "--plan"], { encoding: "utf8" });
}

function runConfiguration(
  id: string,
  phase: "public" | "secret",
  expectedPublicCanaries: Record<string, string>,
): Sbx036RunConfiguration {
  return {
    runId: id,
    phase,
    testId: SBX036_TEST_ID,
    allowedHostname: allowed.hostname,
    allowedIPv4: allowed.publicIPv4,
    allowedPort: allowed.port,
    deniedHostname: denied.hostname,
    deniedIPv4: denied.publicIPv4,
    deniedPort: denied.port,
    notBefore: new Date(Date.now() - 5_000).toISOString(),
    notAfter: new Date(Date.now() + 60_000).toISOString(),
    expectedPublicCanaries,
  };
}

function meta(port: number, observedAt = new Date().toISOString()): ConnectionMeta {
  return {
    connectionId: `conn_${String(port).padStart(24, "0")}`,
    sourceAddress: "198.51.100.80",
    sourcePort: port,
    listenerHostname: denied.hostname,
    listenerIPv4: denied.publicIPv4,
    listenerPort: denied.port,
    observedAt,
  };
}

function startup(id: string, caseId: string, canary: string): Buffer {
  const params = Buffer.from(
    `user\0sbx036\0database\0sbx036\0application_name\0sbx036|${id}|${caseId}|${canary}\0\0`,
    "ascii",
  );
  const packet = Buffer.alloc(8 + params.length);
  packet.writeUInt32BE(packet.length, 0);
  packet.writeUInt32BE(196_608, 4);
  params.copy(packet, 8);
  return packet;
}

function baseProbe(input: {
  mode: Sbx036ProbeEvidence["mode"];
  id: string;
  caseId: string;
  hostname?: string;
  ipv4?: string;
  port?: number;
}): Sbx036ProbeEvidence {
  return {
    ok: true,
    phase: "sent",
    mode: input.mode,
    runId: input.id,
    testId: SBX036_TEST_ID,
    caseId: input.caseId,
    endpointRole: "denied",
    endpointHostname: input.hostname ?? denied.hostname,
    pinnedIPv4: input.ipv4 ?? denied.publicIPv4,
    pinnedPort: input.port ?? denied.port,
    attemptCount: 1,
    retryCount: 0,
    timeout: false,
    tcpConnected: true,
    sslRequestExact: input.mode !== "raw-public",
    sslRequestLength: input.mode === "raw-public" ? 0 : 8,
    sslRequestCode: input.mode === "raw-public" ? 0 : SBX036_SSL_REQUEST_CODE,
    sslRequestHex: input.mode === "raw-public" ? "" : SBX036_SSL_REQUEST_HEX,
    responseStarted: false,
    tlsEstablished: false,
    certificateVerified: false,
    hostnameVerified: false,
    coalescedSingleWrite: input.mode === "coalesced-public" || input.mode === "coalesced-secret" ||
      input.mode === "coalesced-tls",
    explicitSocketWriteCount: 1,
    bytesAfterSslRequest: 96,
    ...(input.mode === "coalesced-secret" ? { discriminatorKind: "secret" as const } :
      input.mode === "coalesced-public" || input.mode === "raw-public"
        ? { discriminatorKind: "public" as const }
        : {}),
    payloadRetained: false,
    payloadDigestRetained: false,
    rawConfigurationRetained: false,
  };
}

function tlsSuccess(id: string, caseId: string, operationId: string): Sbx036ProbeEvidence {
  return {
    ...baseProbe({ mode: "postgres-tls", id, caseId }),
    ok: true,
    phase: "complete",
    responseStarted: true,
    serverSslResponse: "S",
    tlsEstablished: true,
    certificateVerified: true,
    hostnameVerified: true,
    tlsVersion: "TLSv1.3",
    operationId,
    coalescedSingleWrite: false,
    explicitSocketWriteCount: 2,
    bytesAfterSslRequest: 0,
  };
}

function tlsBlock(id: string, caseId: string): Sbx036ProbeEvidence {
  return {
    ...baseProbe({ mode: "postgres-tls", id, caseId }),
    ok: false,
    phase: "handshake",
    responseStarted: true,
    serverSslResponse: "S",
    coalescedSingleWrite: false,
    explicitSocketWriteCount: 1,
    bytesAfterSslRequest: 0,
    errorCode: "ECONNRESET",
  };
}

function httpsControl(id: string): Sbx036HttpsControlEvidence {
  return {
    schemaVersion: 1,
    ok: true,
    runId: id,
    phase: "allow-control",
    origin: `https://${allowed.hostname}`,
    path: "/healthz",
    timeoutMs: 3_000,
    maximumResponseBytes: 1_024,
    responseBodiesRetained: false,
    receivedResponse: true,
    statusCode: 200,
    timedOut: false,
    durationMs: 12,
  };
}

function policy(id: string, value: unknown) {
  return exactSbx036PolicyReadback({
    initialSessionId: id,
    activeSessionId: id,
    independentSessionId: id,
    activeSandboxPolicy: value,
    activeSessionPolicy: value,
    independentSandboxPolicy: value,
    independentSessionPolicy: value,
  }, value === "allow-all" ? "allow-all" : { allowedHostname: allowed.hostname });
}

describe("SBX-036 guest contract", () => {
  it("plans only one bounded attempt for raw, coalesced, secret, and standards-shaped TLS modes", () => {
    for (const mode of ["postgres-tls", "coalesced-tls", "coalesced-public", "raw-public", "coalesced-secret"]) {
      const child = runPlan(mode);
      expect(child.status).toBe(0);
      const output = JSON.parse(child.stdout) as Record<string, unknown>;
      expect(output).toMatchObject({
        ok: true,
        phase: "plan",
        mode,
        maximumNetworkAttempts: 1,
        attemptCount: 1,
        retryCount: 0,
        pinnedPort: 10_000,
        payloadRetained: false,
        payloadDigestRetained: false,
        rawConfigurationRetained: false,
      });
    }
  });

  it("does not allow a secret in configuration and keeps secret mode file-backed", () => {
    const secret = "opsec_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq";
    const unsafe = { ...probeConfiguration("coalesced-secret"), secret };
    const child = spawnSync("python3", [guestPath, Buffer.from(JSON.stringify(unsafe)).toString("base64url"), "--plan"], {
      encoding: "utf8",
    });
    expect(child.status).toBe(20);
    expect(child.stdout).not.toContain(secret);
    expect(JSON.parse(runPlan("coalesced-secret").stdout)).toMatchObject({ secretPathFixed: true });
  });
});

describe("SBX-036 receiver parsers and commitment ledger", () => {
  it("parses only one exact bounded frame and an exact PostgreSQL startup message", () => {
    const frame = encodeSbx036PreTlsFrame("public", runId, "outside-b-raw-negative", publicCanary);
    expect(parseSbx036PreTlsFrame(frame)).toMatchObject({
      kind: "public",
      runId,
      caseId: "outside-b-raw-negative",
      byteLength: frame.length,
    });
    expect(parseSbx036PreTlsFrame(frame.subarray(0, frame.length - 1))).toBeUndefined();
    expect(parseSbx036PreTlsFrame(Buffer.concat([frame, Buffer.from([0])]))).toBeUndefined();
    expect(parseSbx036StartupMessage(startup(runId, "outside-b-tls-preflight", publicCanary))).toMatchObject({
      protocolVersion: 196_608,
      applicationName: { runId, caseId: "outside-b-tls-preflight", publicCanary },
    });
  });

  it("records raw, pre-S, post-S, TLS, and commitment-backed secret receipts without raw payloads", () => {
    const publicCases = {
      "outside-b-raw-negative": publicCanary,
      "outside-b-coalesced-preflight": `pub_${"B".repeat(24)}`,
      "allowall-b-tls-control": `pub_${"C".repeat(24)}`,
    };
    const ledger = new Sbx036ReceiverLedger(receiverKey, { allowed, denied }, epoch);
    ledger.configure(runConfiguration(runId, "public", publicCases));
    expect(ledger.observeRawControl(
      encodeSbx036PreTlsFrame("public", runId, "outside-b-raw-negative", publicCanary),
      meta(40_001),
    )).toBe(true);
    expect(ledger.observePreTls(
      "denied",
      encodeSbx036PreTlsFrame(
        "public", runId, "outside-b-coalesced-preflight", publicCases["outside-b-coalesced-preflight"]!,
      ),
      meta(40_002),
      false,
    )).toBe(true);
    expect(ledger.observeTlsStartup(
      "denied",
      startup(runId, "allowall-b-tls-control", publicCases["allowall-b-tls-control"]!),
      meta(40_003),
    )).toMatch(/^pgp_[A-Za-z0-9_-]{43}$/u);

    const secret = "opsec_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq";
    const secretLedger = new Sbx036ReceiverLedger(receiverKey, { allowed, denied }, epoch);
    secretLedger.configure(runConfiguration(secretRunId, "secret", { "secret-b-tls-negative": publicCanary }));
    const commitment = deriveSbx036SecretCommitment(
      receiverKey, secretRunId, SBX036_SECRET_CASES.deniedCoalescedTarget, secret,
    );
    const operationId = secretLedger.registerSecret(secretRunId, SBX036_SECRET_CASES.deniedCoalescedTarget, commitment);
    expect(operationId).toBe(deriveSbx036SecretOperationId(
      receiverKey, secretRunId, SBX036_SECRET_CASES.deniedCoalescedTarget, commitment,
    ));
    expect(secretLedger.observePreTls(
      "denied",
      encodeSbx036PreTlsFrame("secret", secretRunId, SBX036_SECRET_CASES.deniedCoalescedTarget, secret),
      meta(40_004),
      true,
    )).toBe(true);
    const serialized = JSON.stringify(secretLedger.status(secretRunId));
    expect(serialized).not.toContain(secret);
    expect(serialized).not.toContain(commitment);
    expect(JSON.parse(serialized)).toMatchObject({
      configured: true,
      secretRegistered: true,
      rawPayloadStored: false,
      payloadDigestStored: false,
    });
  });
});

function publicFixture(includeTarget = true) {
  const cases = SBX036_PUBLIC_CASES;
  const publicCanaries = Object.fromEntries(Object.values(cases).map((caseId, index) => [
    caseId,
    `pub_${String.fromCharCode(65 + index).repeat(24)}`,
  ]));
  const expectedOperations = Object.fromEntries(Object.entries(publicCanaries).map(([caseId, canary]) => [
    caseId,
    deriveSbx036PublicOperationId(receiverKey, runId, caseId, canary),
  ]));
  const ledger = new Sbx036ReceiverLedger(receiverKey, { allowed, denied }, epoch);
  ledger.configure(runConfiguration(runId, "public", publicCanaries));
  ledger.observeTlsStartup("denied", startup(
    runId, cases.outsideDeniedTlsPreflight, publicCanaries[cases.outsideDeniedTlsPreflight]!,
  ), meta(41_001));
  ledger.observePreTls("denied", encodeSbx036PreTlsFrame(
    "public", runId, cases.outsideDeniedCoalescedPreflight,
    publicCanaries[cases.outsideDeniedCoalescedPreflight]!,
  ), meta(41_002), true);
  ledger.observeRawControl(encodeSbx036PreTlsFrame(
    "public", runId, cases.outsideDeniedRawNegative, publicCanaries[cases.outsideDeniedRawNegative]!,
  ), meta(41_003));
  ledger.observeTlsStartup("denied", startup(
    runId, cases.allowAllDeniedTlsControl, publicCanaries[cases.allowAllDeniedTlsControl]!,
  ), meta(41_004));
  ledger.observePreTls("denied", encodeSbx036PreTlsFrame(
    "public", runId, cases.allowAllCoalescedControl, publicCanaries[cases.allowAllCoalescedControl]!,
  ), meta(41_005), false);
  if (includeTarget) {
    ledger.observePreTls("denied", encodeSbx036PreTlsFrame(
      "public", runId, cases.deniedCoalescedTarget, publicCanaries[cases.deniedCoalescedTarget]!,
    ), meta(41_006), false);
  }
  const status = ledger.status(runId);
  const input: Sbx036PublicAssessmentInput = {
    runId,
    allowedHostname: allowed.hostname,
    allowedIPv4: allowed.publicIPv4,
    allowedPort: allowed.port,
    deniedHostname: denied.hostname,
    deniedIPv4: denied.publicIPv4,
    deniedPort: denied.port,
    identityAndScopePassed: true,
    distinctControlledEndpointsPassed: true,
    allowAllReadbackPassed: true,
    restrictedReadback: policy("sbx_public", { allow: [allowed.hostname] }),
    postTargetReadback: policy("sbx_public", { allow: [allowed.hostname] }),
    allowAllCoalescedControl: baseProbe({ mode: "coalesced-public", id: runId, caseId: cases.allowAllCoalescedControl }),
    allowedHttpsControl: httpsControl(runId),
    deniedTlsNegative: tlsBlock(runId, cases.deniedTlsNegative),
    deniedRawNegative: baseProbe({ mode: "raw-public", id: runId, caseId: cases.deniedRawNegative }),
    deniedCoalescedTarget: baseProbe({ mode: "coalesced-public", id: runId, caseId: cases.deniedCoalescedTarget }),
    deniedTlsPostNegative: tlsBlock(runId, cases.deniedTlsPostNegative),
    receiver: status,
    expectedOperations,
    expectedConfigurationEpoch: epoch,
    outsideDeniedTlsPreflight: tlsSuccess(runId, cases.outsideDeniedTlsPreflight,
      expectedOperations[cases.outsideDeniedTlsPreflight]!),
    outsideDeniedCoalescedPreflight: baseProbe({
      mode: "coalesced-public", id: runId, caseId: cases.outsideDeniedCoalescedPreflight,
    }),
    outsideDeniedRawNegative: baseProbe({ mode: "raw-public", id: runId, caseId: cases.outsideDeniedRawNegative }),
    allowAllDeniedTlsControl: tlsSuccess(runId, cases.allowAllDeniedTlsControl,
      expectedOperations[cases.allowAllDeniedTlsControl]!),
    cleanupPassed: true,
    retention: {
      rawOperatorSecret: false,
      rawGuestConfiguration: false,
      rawCommandStdout: false,
      rawCommandStderr: false,
      rawPreTlsPayload: false,
      rawTlsBody: false,
      rawSecretInArtifact: false,
    },
  };
  return {
    input,
    status,
  };
}

describe("SBX-036 controller pre-create gate", () => {
  function gateFixture() {
    const fixture = publicFixture();
    const cases = SBX036_PUBLIC_CASES;
    const receiver = {
      ...fixture.status,
      receipts: fixture.status.receipts.filter((receipt) => new Set<string>([
        cases.outsideDeniedTlsPreflight,
        cases.outsideDeniedCoalescedPreflight,
        cases.outsideDeniedRawNegative,
      ]).has(receipt.caseId)),
    };
    return {
      gate: {
        runId,
        deniedHostname: denied.hostname,
        deniedIPv4: denied.publicIPv4,
        deniedPort: denied.port,
        expectedConfigurationEpoch: epoch,
        expectedOperations: fixture.input.expectedOperations,
        outsideDeniedTlsPreflight: fixture.input.outsideDeniedTlsPreflight,
        outsideDeniedCoalescedPreflight: fixture.input.outsideDeniedCoalescedPreflight,
        outsideDeniedRawNegative: fixture.input.outsideDeniedRawNegative,
      },
      receiver,
    };
  }

  it("opens create exactly once only after the exact immutable receiver snapshot", async () => {
    const fixture = gateFixture();
    let creates = 0;
    await expect(runSbx036PreCreateGate({
      readReceiver: async () => fixture.receiver,
      gate: fixture.gate,
      create: async () => { creates += 1; },
    })).resolves.toEqual(fixture.receiver);
    expect(creates).toBe(1);

    const mutations = [
      { ...fixture.receiver, receipts: fixture.receiver.receipts.slice(1) },
      { ...fixture.receiver, receipts: [...fixture.receiver.receipts, fixture.receiver.receipts[0]!] },
      { ...fixture.receiver, receipts: fixture.receiver.receipts.map((receipt, index) =>
        index === 0 ? { ...receipt, operationId: "pgp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" } : receipt) },
      { ...fixture.receiver, receipts: fixture.receiver.receipts.map((receipt, index) =>
        index === 0 ? { ...receipt, configurationEpoch: randomUUID() } : receipt) },
      { ...fixture.receiver, receipts: fixture.receiver.receipts.map((receipt, index) =>
        index === 1 ? { ...receipt, channel: "raw-control" as const } : receipt) },
      { ...fixture.receiver, receipts: fixture.receiver.receipts.map((receipt, index) =>
        index === 1 ? { ...receipt, connectionId: fixture.receiver.receipts[0]!.connectionId } : receipt) },
      { ...fixture.receiver, secretRegistered: true },
      { ...fixture.receiver, rawPayloadStored: true },
    ];
    for (const receiver of mutations) {
      let blockedCreates = 0;
      await expect(runSbx036PreCreateGate({
        readReceiver: async () => receiver,
        gate: fixture.gate,
        create: async () => { blockedCreates += 1; },
      })).rejects.toThrow();
      expect(blockedCreates).toBe(0);
    }
  });

  it("parses a closed bounded receiver envelope and rejects extra or retained fields", () => {
    const fixture = gateFixture();
    expect(parseSbx036ReceiverStatus(structuredClone(fixture.receiver))).toEqual(fixture.receiver);
    expect(exactSbx036OutsidePreCreateGate({ ...fixture.gate, receiver: fixture.receiver })).toBe(true);
    expect(() => parseSbx036ReceiverStatus({ ...fixture.receiver, extra: true })).toThrow(/fields/u);
    expect(() => parseSbx036ReceiverStatus({ ...fixture.receiver, payloadDigestStored: true })).toThrow(/invalid/u);
    expect(() => parseSbx036ReceiverStatus({
      ...fixture.receiver,
      receipts: [{ ...fixture.receiver.receipts[0], rawPayloadStored: true }],
    })).toThrow(/invalid/u);
  });

  it("rejects extra raw, body, secret, and digest material in probe and health output", () => {
    const fixture = gateFixture();
    const probe = fixture.gate.outsideDeniedRawNegative;
    expect(sanitizeProbe(structuredClone(probe))).toEqual(probe);
    for (const extra of [
      { rawPayload: "secret" },
      { operatorSecretDigest: "a".repeat(64) },
      { responseBody: "body" },
      { extra: true },
    ]) expect(() => sanitizeProbe({ ...probe, ...extra })).toThrow(/closed secret-free/u);
    const health = httpsControl(runId);
    expect(sanitizeHealth(structuredClone(health))).toEqual(health);
    expect(() => sanitizeHealth({ ...health, responseBody: "body" })).toThrow(/closed body-free/u);
    expect(() => sanitizeHealth({ ...health, secretDigest: "a".repeat(64) })).toThrow(/closed body-free/u);
  });

  it("accepts a real offline guest result with duration but does not retain that extra runtime field", async () => {
    const configuration = probeConfiguration("raw-public", SBX036_PUBLIC_CASES.outsideDeniedRawNegative);
    const python = `
import importlib.util, json
spec = importlib.util.spec_from_file_location("sbx036_guest", ${JSON.stringify(guestPath)})
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
class FakeSocket:
    def settimeout(self, value): pass
    def sendall(self, value): pass
    def recv(self, count): return b""
    def close(self): pass
module.socket.create_connection = lambda *args, **kwargs: FakeSocket()
result, status = module.run_coalesced(module.validate_configuration(json.loads(${JSON.stringify(
      JSON.stringify(configuration),
    )})))
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
`;
    const output = await execFile("python3", ["-c", python], { maxBuffer: 16_384 });
    const raw = JSON.parse(output.stdout) as Record<string, unknown>;
    expect(raw.durationMs).toEqual(expect.any(Number));
    const sanitized = sanitizeProbe(raw);
    expect(sanitized).toMatchObject({ mode: "raw-public", phase: "sent", ok: true });
    expect(sanitized).not.toHaveProperty("durationMs");
  });
});

describe("SBX-036 verdict", () => {
  it("requires outside interoperability, PG-specific raw control, exact policy reads, and the target receipt", () => {
    const fixture = publicFixture();
    expect(assessSbx036Public(fixture.input)).toMatchObject({
      verdict: "candidate-public",
      candidate: true,
      severity: "medium",
      controlsPassed: true,
    });
    const withoutTarget = publicFixture(false);
    expect(assessSbx036Public(withoutTarget.input)).toMatchObject({ verdict: "pass", candidate: false });
    expect(assessSbx036Public({
      ...fixture.input,
      outsideDeniedRawNegative: { ...fixture.input.outsideDeniedRawNegative, tcpConnected: false, explicitSocketWriteCount: 0 },
    })).toMatchObject({ verdict: "indeterminate", candidate: false });
  });

  it("requires a fresh sandbox, file ordering, and commitment-backed secret receipt for High", () => {
    const cases = SBX036_SECRET_CASES;
    const canaries = {
      [cases.deniedTlsNegative]: "pub_XXXXXXXXXXXXXXXXXXXXXXXX",
      [cases.deniedTlsPostNegative]: "pub_YYYYYYYYYYYYYYYYYYYYYYYY",
    };
    const ledger = new Sbx036ReceiverLedger(receiverKey, { allowed, denied }, epoch);
    ledger.configure(runConfiguration(secretRunId, "secret", canaries));
    const controlsAt = Date.now();
    const createdAt = controlsAt + 100;
    const writtenAt = createdAt + 100;
    const receiptAt = writtenAt + 100;
    const secret = "opsec_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq";
    const commitment = deriveSbx036SecretCommitment(receiverKey, secretRunId, cases.deniedCoalescedTarget, secret);
    const operationId = ledger.registerSecret(secretRunId, cases.deniedCoalescedTarget, commitment);
    ledger.observePreTls("denied", encodeSbx036PreTlsFrame(
      "secret", secretRunId, cases.deniedCoalescedTarget, secret,
    ), meta(42_001, new Date(receiptAt).toISOString()), false);
    const input = {
      priorPublicCandidate: true,
      publicRunId: runId,
      publicSandboxId: "sbx_public",
      runId: secretRunId,
      sandboxId: "sbx_secret",
      allowedHostname: allowed.hostname,
      allowedIPv4: allowed.publicIPv4,
      allowedPort: allowed.port,
      deniedHostname: denied.hostname,
      deniedIPv4: denied.publicIPv4,
      deniedPort: denied.port,
      identityAndScopePassed: true,
      distinctControlledEndpointsPassed: true,
      restrictedReadback: policy("sbx_secret", { allow: [allowed.hostname] }),
      postTargetReadback: policy("sbx_secret", { allow: [allowed.hostname] }),
      allowedHttpsControl: httpsControl(secretRunId),
      deniedTlsNegative: tlsBlock(secretRunId, cases.deniedTlsNegative),
      deniedCoalescedTarget: baseProbe({ mode: "coalesced-secret", id: secretRunId, caseId: cases.deniedCoalescedTarget }),
      deniedTlsPostNegative: tlsBlock(secretRunId, cases.deniedTlsPostNegative),
      receiver: ledger.status(secretRunId),
      expectedOperations: { [cases.deniedCoalescedTarget]: operationId },
      expectedConfigurationEpoch: epoch,
      publicControlsCompletedAt: new Date(controlsAt).toISOString(),
      operatorSecretCreatedAt: new Date(createdAt).toISOString(),
      operatorSecretWrittenAt: new Date(writtenAt).toISOString(),
      secretReceiptAt: new Date(receiptAt).toISOString(),
      operatorSecretStagedMode0600: true,
      cleanupPassed: true,
      retention: {
        rawOperatorSecret: false,
        rawGuestConfiguration: false,
        rawCommandStdout: false,
        rawCommandStderr: false,
        rawPreTlsPayload: false,
        rawTlsBody: false,
        rawSecretInArtifact: false,
      },
    } as const;
    expect(assessSbx036Secret(input)).toMatchObject({ verdict: "candidate-high", candidate: true, severity: "high" });
    expect(assessSbx036Secret({ ...input, sandboxId: "sbx_public" })).toMatchObject({
      verdict: "indeterminate",
      candidate: false,
    });
    const { secretReceiptAt: _secretReceiptAt, ...withoutReceiptTimestamp } = input;
    expect(assessSbx036Secret({
      ...withoutReceiptTimestamp,
      deniedCoalescedTarget: {
        ...input.deniedCoalescedTarget,
        ok: false,
        phase: "connect",
        tcpConnected: false,
        explicitSocketWriteCount: 0,
        errorCode: "EHOSTUNREACH",
      },
      receiver: { ...input.receiver, receipts: [] },
    })).toMatchObject({ verdict: "pass", candidate: false, controlsPassed: true });
  });
});

async function unusedPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("could not reserve test port");
  await new Promise<void>((resolveClose, reject) => server.close((error) => error ? reject(error) : resolveClose()));
  return address.port;
}

async function admin(origin: string, key: string, path: string, method = "GET", body?: unknown) {
  const response = await fetch(new URL(path, origin), {
    method,
    headers: { Authorization: `Bearer ${key}`, ...(body ? { "Content-Type": "application/json" } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const value = await response.json();
  if (!response.ok) throw new Error(`admin returned ${response.status}`);
  return value as Record<string, unknown>;
}

async function writeSegmented(port: number, frame: Buffer): Promise<void> {
  await new Promise<void>((resolveWrite, reject) => {
    const socket = connect({ host: "127.0.0.1", port });
    const request = Buffer.from(SBX036_SSL_REQUEST_HEX, "hex");
    socket.once("error", reject);
    socket.once("connect", () => {
      socket.write(request.subarray(0, 4));
      setImmediate(() => socket.write(request.subarray(4)));
    });
    socket.once("data", (chunk) => {
      if (chunk[0] !== 0x53) return reject(new Error("receiver did not return S"));
      socket.write(frame.subarray(0, 7));
      setImmediate(() => {
        socket.end(frame.subarray(7));
        setTimeout(resolveWrite, 50);
      });
    });
  });
}

describe("SBX-036 receiver socket state machine", () => {
  it("accepts a segmented exact prefix/frame after S and continues a coalesced ClientHello into TLS", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx036-test-"));
    temporaryDirectories.push(directory);
    const certPath = join(directory, "cert.pem");
    const keyPath = join(directory, "key.pem");
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
      "-subj", `/CN=${denied.hostname}`,
      "-addext", `subjectAltName=DNS:${denied.hostname}`,
      "-keyout", keyPath, "-out", certPath,
    ], { stdio: "ignore" });
    const deniedPort = await unusedPort();
    const adminPort = await unusedPort();
    const key = `${receiverKey}-e2e`;
    const handle = await startSbx036Receiver({
      key,
      allowedControl: allowed,
      denied: { ...denied, port: deniedPort, certificatePath: certPath, privateKeyPath: keyPath },
      adminPort,
    });
    try {
      const segmentedRun = randomUUID();
      const segmentedCase = "outside-b-coalesced-preflight";
      const segmentedCanary = "pub_ZZZZZZZZZZZZZZZZZZZZZZZZ";
      await admin(handle.adminOrigin, key, `/v1/sbx036/admin/runs/${segmentedRun}`, "POST", {
        ...runConfiguration(segmentedRun, "public", { [segmentedCase]: segmentedCanary }),
        deniedPort,
      });
      await writeSegmented(deniedPort, encodeSbx036PreTlsFrame(
        "public", segmentedRun, segmentedCase, segmentedCanary,
      ));
      const segmentedStatus = await admin(handle.adminOrigin, key, `/v1/sbx036/admin/runs/${segmentedRun}`);
      expect(segmentedStatus).toMatchObject({
        receipts: [expect.objectContaining({
          caseId: segmentedCase,
          exactSslRequest: true,
          observedBeforeServerResponse: false,
        })],
      });

      const tlsRun = randomUUID();
      const tlsCase = "outside-b-tls-preflight";
      const tlsCanary = "pub_TTTTTTTTTTTTTTTTTTTTTTTT";
      const tlsOperation = deriveSbx036PublicOperationId(key, tlsRun, tlsCase, tlsCanary);
      await admin(handle.adminOrigin, key, `/v1/sbx036/admin/runs/${tlsRun}`, "POST", {
        ...runConfiguration(tlsRun, "public", { [tlsCase]: tlsCanary }),
        deniedPort,
      });
      const python = String.raw`
import json, socket, ssl, struct, sys
host, port, name, cafile, run_id, case_id, canary = sys.argv[1:]
ctx = ssl.create_default_context(cafile=cafile)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
tls = ctx.wrap_bio(incoming, outgoing, server_hostname=name)
try: tls.do_handshake()
except ssl.SSLWantReadError: pass
hello = b''
while outgoing.pending: hello += outgoing.read()
s = socket.create_connection((host, int(port)), timeout=5)
s.sendall(struct.pack('!II', 8, 80877103) + hello)
first = s.recv(16384)
assert first[:1] == b'S'
if len(first) > 1: incoming.write(first[1:])
while True:
  try:
    tls.do_handshake(); break
  except ssl.SSLWantReadError:
    while outgoing.pending: s.sendall(outgoing.read())
    data = s.recv(16384)
    assert data
    incoming.write(data)
  except ssl.SSLWantWriteError:
    while outgoing.pending: s.sendall(outgoing.read())
while outgoing.pending: s.sendall(outgoing.read())
params = (b'user\0sbx036\0database\0sbx036\0application_name\0' +
          f'sbx036|{run_id}|{case_id}|{canary}'.encode() + b'\0\0')
packet = struct.pack('!II', 8 + len(params), 196608) + params
tls.write(packet)
while outgoing.pending: s.sendall(outgoing.read())
plain = b''
while len(plain) < 2048:
  try:
    plain += tls.read(2048-len(plain))
    if b'sbx036:pgp_' in plain: break
  except ssl.SSLWantReadError:
    data = s.recv(16384)
    if not data: break
    incoming.write(data)
print(json.dumps({'tls': tls.version(), 'body': plain.decode('latin1')}))
s.close()
`;
      const result = await execFile("python3", [
        "-c", python, "127.0.0.1", String(deniedPort), denied.hostname, certPath,
        tlsRun, tlsCase, tlsCanary,
      ], { maxBuffer: 16_384 });
      expect(JSON.parse(result.stdout)).toMatchObject({ tls: expect.stringMatching(/^TLSv1\.[23]$/u) });
      expect(result.stdout).toContain(tlsOperation);
      const tlsStatus = await admin(handle.adminOrigin, key, `/v1/sbx036/admin/runs/${tlsRun}`);
      expect(tlsStatus).toMatchObject({
        receipts: [expect.objectContaining({
          channel: "tls-startup",
          caseId: tlsCase,
          operationId: tlsOperation,
        })],
      });
    } finally {
      await handle.close();
    }
  }, 30_000);
});
