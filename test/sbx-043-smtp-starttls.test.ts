import { execFile as execFileCallback } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { connect as connectTcp, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { connect as connectTls, type TLSSocket } from "node:tls";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildSbx043ProbeConfiguration, explicitSbx043Credentials, publicSbx043IPv4, SBX043_SCOPE_CONFIRMATION } from "../pocs/SBX-043/smtp-starttls.js";
import { startSbx043Receiver, type Sbx043Receiver } from "../pocs/SBX-043/receiver.js";
import {
  SBX043_PUBLIC_CASES,
  SBX043_TEST_ID,
  assessSbx043Public,
  deriveSbx043GreetingTag,
  deriveSbx043PublicOperationId,
  exactSbx043PolicyReadback,
  type Sbx043ProbeEvidence,
  type Sbx043ReceiverStatus,
} from "../pocs/SBX-043/verdict.js";

const execFile = promisify(execFileCallback);
const probePath = resolve("guest/smtp-starttls-probe.py");
const key = "k".repeat(64);
const hostname = "smtp-b.example";
let directory = "";
let tlsKey: Buffer;
let tlsCert: Buffer;

beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), "sbx043-"));
  const keyPath = join(directory, "key.pem");
  const certPath = join(directory, "cert.pem");
  await execFile("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-subj", `/CN=${hostname}`, "-addext", `subjectAltName=DNS:${hostname}`, "-keyout", keyPath, "-out", certPath]);
  [tlsKey, tlsCert] = await Promise.all([readFile(keyPath), readFile(certPath)]);
});

afterAll(async () => { if (directory) await rm(directory, { recursive: true, force: true }); });

function encode(value: unknown): string { return Buffer.from(JSON.stringify(value)).toString("base64url"); }

function baseConfig(mode: "smtp-starttls-public" | "smtp-starttls-secret") {
  return {
    scopeConfirmation: SBX043_SCOPE_CONFIRMATION, mode, runId: randomUUID(), testId: SBX043_TEST_ID,
    caseId: "test-case", endpointRole: "denied", endpointHostname: hostname,
    pinnedIPv4: "8.8.8.8", pinnedPort: 587, greetingTag: "abcdefghijklmnop", timeoutMs: 1000,
    maxResponseBytes: 1024, ...(mode === "smtp-starttls-public" ? { publicCanary: "a".repeat(32) } : {}),
  };
}

async function readUntil(socket: Socket | TLSSocket, marker: string): Promise<string> {
  return await new Promise((resolveRead, reject) => {
    let value = "";
    const timeout = setTimeout(() => { cleanup(); reject(new Error("read timeout")); }, 3000);
    const onData = (chunk: Buffer): void => { value += chunk.toString("ascii"); if (value.includes(marker)) { cleanup(); resolveRead(value); } };
    const onError = (error: Error): void => { cleanup(); reject(error); };
    const cleanup = (): void => { clearTimeout(timeout); socket.off("data", onData); socket.off("error", onError); };
    socket.on("data", onData); socket.on("error", onError);
  });
}

async function admin(receiver: Sbx043Receiver, path: string, method: "GET" | "POST" | "DELETE", body?: unknown) {
  const response = await fetch(new URL(path, receiver.adminOrigin), { method, headers: { Authorization: `Bearer ${key}`, ...(body ? { "content-type": "application/json" } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
  expect(response.ok).toBe(true);
  return await response.json() as Record<string, unknown>;
}

describe("SBX-043 guest and controller bounds", () => {
  it("plans exactly one bounded public SMTP attempt without networking", async () => {
    const { stdout } = await execFile("python3", [probePath, encode(baseConfig("smtp-starttls-public")), "--plan"]);
    expect(JSON.parse(stdout)).toMatchObject({ mode: "smtp-starttls-public", maximumNetworkAttempts: 1,
      maximumSmtpLineBytes: 512, strictCertificateVerification: true, secretPathFixed: false });
  });

  it("keeps the secret at a fixed mode-0600 path and reads only after a valid greeting", async () => {
    const { stdout } = await execFile("python3", [probePath, encode(baseConfig("smtp-starttls-secret")), "--plan"]);
    expect(JSON.parse(stdout)).toMatchObject({ mode: "smtp-starttls-secret", maximumNetworkAttempts: 1,
      secretPathFixed: true, secretReadAfterValidGreeting: true });
  });

  it("builds a public config without any secret field", () => {
    const config = buildSbx043ProbeConfiguration({ mode: "smtp-starttls-public", runId: randomUUID(),
      caseId: "restricted-b-smtp", endpointHostname: hostname, endpointRole: "denied", pinnedIPv4: "8.8.8.8",
      pinnedPort: 587, publicCanary: "b".repeat(32), greetingTag: "abcdefghijklmnop" });
    expect(config).not.toHaveProperty("secret");
    expect(config).not.toHaveProperty("secretPath");
    expect(config.scopeConfirmation).toBe(SBX043_SCOPE_CONFIRMATION);
  });

  it("rejects non-alias credentials and private endpoint addresses", () => {
    expect(() => explicitSbx043Credentials({ VERCEL_TOKEN: "token", VERCEL_TEAM_ID: "team_wrong", VERCEL_PROJECT_ID: "prj_wrong" })).toThrow(/verified HackerOne-alias/u);
    expect(publicSbx043IPv4("8.8.8.8")).toBe(true);
    expect(publicSbx043IPv4("127.0.0.1")).toBe(false);
    expect(publicSbx043IPv4("100.64.0.1")).toBe(false);
  });
});

describe("SBX-043 raw SMTP receiver", () => {
  it("attributes exact EHLO, completes STARTTLS, and stores no transcript", async () => {
    const receiver = await startSbx043Receiver({ key, tlsKey, tlsCert, adminPort: 0, listenerPort: 0,
      listenerBindHost: "127.0.0.1", listenerHostname: hostname, listenerIPv4: "198.51.100.7" });
    const runId = randomUUID();
    const caseId = "smtp-public";
    const canary = "c".repeat(32);
    const path = `/v1/sbx043/admin/cases/${runId}/${caseId}`;
    try {
      const configured = await admin(receiver, path, "POST", { runId, caseId, phase: "public",
        mode: "smtp-starttls-public", endpointBaseHostname: hostname,
        notBefore: new Date(Date.now() - 1000).toISOString(), notAfter: new Date(Date.now() + 60_000).toISOString(),
        expectedPublicCanary: canary });
      expect(configured.greetingTag).toBe(deriveSbx043GreetingTag(key, runId, caseId));
      const socket = connectTcp({ host: "127.0.0.1", port: receiver.listenerPort });
      await new Promise<void>((resolveConnect, reject) => { socket.once("connect", resolveConnect); socket.once("error", reject); });
      expect(await readUntil(socket, "\r\n")).toBe(`220 s43-${configured.greetingTag}.${hostname} ESMTP SBX043\r\n`);
      socket.write(`EHLO s43p-${canary}.${hostname}\r\n`);
      expect(await readUntil(socket, "250 SIZE 1024\r\n")).toContain("250-STARTTLS\r\n");
      socket.write("STARTTLS\r\n");
      expect(await readUntil(socket, "\r\n")).toBe("220 2.0.0 Ready to start TLS\r\n");
      const secure = connectTls({ socket, servername: hostname, rejectUnauthorized: false });
      await new Promise<void>((resolveSecure, reject) => { secure.once("secureConnect", resolveSecure); secure.once("error", reject); });
      secure.write("EHLO post.sbx043.invalid\r\n");
      expect(await readUntil(secure, "\r\n")).toBe("250 post-tls-ok\r\n");
      secure.destroy();
      const status = await admin(receiver, path, "GET") as unknown as Sbx043ReceiverStatus;
      expect(status).toMatchObject({ connectionCount: 1, greetingWriteCount: 1, exactEhloCount: 1,
        startTlsCommandCount: 1, tlsHandshakeCount: 1, postTlsEhloCount: 1,
        exactPayloadReceiptCount: 1, operationId: deriveSbx043PublicOperationId(key, runId, caseId, canary),
        rawInboundStored: false, rawEhloStored: false, rawSecretStored: false, payloadDigestStored: false });
      expect((await admin(receiver, path, "DELETE")).deleted).toBe(true);
    } finally { await receiver.close(); }
  });
});

function probe(caseId: string, mode: Sbx043ProbeEvidence["mode"], overrides: Partial<Sbx043ProbeEvidence> = {}): Sbx043ProbeEvidence {
  return { ok: true, phase: "complete", mode, runId: "11111111-1111-4111-8111-111111111111", testId: SBX043_TEST_ID,
    caseId, endpointRole: mode === "https-control" ? "allowed" : "denied", endpointHostname: mode === "https-control" ? "a.example" : hostname,
    ...(mode === "https-control" ? {} : { pinnedIPv4: "8.8.8.8" }), pinnedPort: mode === "https-control" ? 443 : 587,
    attemptCount: 1, retryCount: 0, tcpConnected: mode !== "direct-tls" && mode !== "raw-public",
    validGreetingReceived: mode === "smtp-starttls-public", greetingTagMatched: mode === "smtp-starttls-public",
    ehloSent: mode === "smtp-starttls-public", ehloBytes: mode === "smtp-starttls-public" ? 64 : 0,
    startTlsAdvertised: mode === "smtp-starttls-public", startTlsCommandSent: mode === "smtp-starttls-public",
    startTlsReadyReceived: mode === "smtp-starttls-public", clientHelloGenerated: mode === "smtp-starttls-public",
    clientHelloSent: mode === "smtp-starttls-public", tlsHandshakeComplete: mode === "smtp-starttls-public",
    peerCertificateVerified: mode === "smtp-starttls-public", postTlsEhloComplete: mode === "smtp-starttls-public",
    explicitSocketWriteCount: mode === "smtp-starttls-public" ? 3 : 0, operatorSecretFileValidated: false,
    receivedResponse: mode === "smtp-starttls-public" || mode === "https-control", ...(mode === "https-control" ? { statusCode: 200 } : {}),
    timedOut: false, rawConfigurationRetained: false, rawEhloRetained: false, rawOperatorSecretRetained: false, ...overrides };
}

function receiver(runId: string, caseId: string, operationId?: string): Sbx043ReceiverStatus {
  return { configured: true, runId, caseId, phase: "public", mode: "smtp-starttls-public", connectionCount: operationId ? 1 : 0,
    greetingWriteCount: operationId ? 1 : 0, exactEhloCount: operationId ? 1 : 0, startTlsCommandCount: operationId ? 1 : 0,
    tlsHandshakeCount: operationId ? 1 : 0, postTlsEhloCount: operationId ? 1 : 0, clientHelloCount: 0, rawFrameCount: 0,
    exactPayloadReceiptCount: operationId ? 1 : 0, malformedCount: 0, ...(operationId ? { operationId } : {}),
    listenerHostname: hostname, listenerIPv4: "8.8.8.8", listenerPort: 587,
    configurationEpoch: "22222222-2222-4222-8222-222222222222", withinConfiguredWindow: true,
    secretCommitmentMatched: false, rawInboundStored: false, rawEhloStored: false, rawSecretStored: false, payloadDigestStored: false };
}

describe("SBX-043 verdict", () => {
  it("requires exact public receipt with silent direct/raw controls", () => {
    const runId = "11111111-1111-4111-8111-111111111111";
    const epoch = "22222222-2222-4222-8222-222222222222";
    const operations = Object.fromEntries(Object.values(SBX043_PUBLIC_CASES).filter((id) => id !== SBX043_PUBLIC_CASES.allowedHttps).map((id) => [id, deriveSbx043PublicOperationId(key, runId, id, "d".repeat(32))]));
    const readback = exactSbx043PolicyReadback({ initialSessionId: "session", activeSessionId: "session", independentSessionId: "session",
      activeSandboxPolicy: { allow: ["a.example"] }, activeSessionPolicy: { allow: ["a.example"] },
      independentSandboxPolicy: { allow: ["a.example"] }, independentSessionPolicy: { allow: ["a.example"] } }, { allowedHostname: "a.example" });
    const outside = receiver(runId, SBX043_PUBLIC_CASES.outsideSmtp, operations[SBX043_PUBLIC_CASES.outsideSmtp]);
    const allow = receiver(runId, SBX043_PUBLIC_CASES.allowAllSmtp, operations[SBX043_PUBLIC_CASES.allowAllSmtp]);
    const target = receiver(runId, SBX043_PUBLIC_CASES.deniedSmtp, operations[SBX043_PUBLIC_CASES.deniedSmtp]);
    const empty = (caseId: string) => ({ ...receiver(runId, caseId), mode: "direct-tls" as const });
    const assessment = assessSbx043Public({ runId, allowedHostname: "a.example", deniedHostname: hostname,
      deniedIPv4: "8.8.8.8", deniedPort: 587, identityAndScopePassed: true, distinctAddressSetsPassed: true,
      allowAllReadbackPassed: true, restrictedReadback: readback, postTargetReadback: readback,
      outsideSmtp: probe(SBX043_PUBLIC_CASES.outsideSmtp, "smtp-starttls-public"), outsideSmtpReceiver: outside,
      allowAllSmtp: probe(SBX043_PUBLIC_CASES.allowAllSmtp, "smtp-starttls-public"), allowAllSmtpReceiver: allow,
      allowedHttps: probe(SBX043_PUBLIC_CASES.allowedHttps, "https-control"),
      deniedDirectTls: probe(SBX043_PUBLIC_CASES.deniedDirectTls, "direct-tls"), deniedDirectTlsReceiver: empty(SBX043_PUBLIC_CASES.deniedDirectTls),
      deniedRaw: probe(SBX043_PUBLIC_CASES.deniedRaw, "raw-public"), deniedRawReceiver: { ...empty(SBX043_PUBLIC_CASES.deniedRaw), mode: "raw-public" },
      deniedSmtp: probe(SBX043_PUBLIC_CASES.deniedSmtp, "smtp-starttls-public"), deniedSmtpReceiver: target,
      deniedPostDirectTls: probe(SBX043_PUBLIC_CASES.deniedPostDirectTls, "direct-tls"), deniedPostDirectTlsReceiver: empty(SBX043_PUBLIC_CASES.deniedPostDirectTls),
      expectedOperations: operations, expectedConfigurationEpoch: epoch, cleanupPassed: true,
      retention: { rawOperatorSecret: false, rawGuestConfiguration: false, rawCommandStdout: false, rawCommandStderr: false,
        rawSmtpTranscript: false, rawEhlo: false, rawSecretInArtifact: false, secretDigestInArtifact: false } });
    expect(assessment).toMatchObject({ verdict: "candidate-public", candidate: true, severity: "medium", controlsPassed: true });
  });
});
