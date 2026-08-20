import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import dgram from "node:dgram";
import { EventEmitter, once } from "node:events";
import { existsSync } from "node:fs";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createConnection, createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { afterEach, describe, expect, it } from "vitest";
import { startSbx001AuthoritativeReceiver } from "../pocs/SBX-001/authoritative-receiver.js";
import {
  exactDelegationSets,
  assessSbx001DirectWithIngress,
  pollForLateSbx001Resource,
  sanitizeSbx001DnsEvidence,
  sanitizeSbx001HttpsEvidence,
  sanitizeSbx001ReceiverSnapshot,
} from "../pocs/SBX-001/direct-run.js";
import { createSbx001DirectJournal, parseSbx001DirectJournal } from "../pocs/SBX-001/direct-safety.js";
import {
  SBX001_CASES,
  SBX001_DIRECT_SCOPE_CONFIRMATION,
  SBX001_DIRECT_TEST_ID,
  assessSbx001Direct,
  buildDnsAQueryDirect,
  buildDnsQueryDirect,
  derivePublicDnsOperationId,
  deriveSecretDnsCommitment,
  deriveSecretDnsOperationId,
  parseDnsAQuestion,
  publicDnsLabel,
  secretDnsLabel,
  type Sbx001GuestDnsEvidence,
  type Sbx001GuestHttpsEvidence,
  type Sbx001CaseId,
  type Sbx001DirectAssessmentInput,
  type Sbx001PolicyReadback,
  type Sbx001Receipt,
} from "../pocs/SBX-001/direct-shared.js";

const proofKey = "unit-test-sbx001-proof-key-material-0123456789";
const adminKey = "unit-test-sbx001-admin-key-material-0123456789";
const zone = "auth.sbx001.form-app.app";
const nameserver = "ns1.sbx001.form-app.app";
const nonce = "0123456789abcdef0123456789abcdef";
const publicNonces = {
  [SBX001_CASES.outsideUdp]: nonce,
  [SBX001_CASES.outsideTcp]: "1123456789abcdef0123456789abcdef",
  [SBX001_CASES.allowPublic]: "2123456789abcdef0123456789abcdef",
  [SBX001_CASES.denyPublic]: "3123456789abcdef0123456789abcdef",
} as const;
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

async function admin(port: number, path: string, method: string, body?: unknown): Promise<Response> {
  return await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${adminKey}`,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

async function udpQuery(port: number, name: string, queryType = 1): Promise<Buffer> {
  const packet = buildDnsQueryDirect(name, 0x1234, queryType);
  const socket = dgram.createSocket("udp4");
  try {
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("local UDP query timed out")), 750);
      socket.once("error", (error) => {
        clearTimeout(timer);
        reject(error);
      });
      socket.once("message", (message) => {
        clearTimeout(timer);
        resolve(Buffer.from(message));
      });
      socket.send(packet, port, "127.0.0.1");
    });
  } finally {
    packet.fill(0);
    socket.close();
  }
}

async function tcpQuery(port: number, name: string, queryType = 1): Promise<Buffer> {
  const query = buildDnsQueryDirect(name, 0x5678, queryType);
  const frame = Buffer.alloc(query.length + 2);
  frame.writeUInt16BE(query.length, 0);
  query.copy(frame, 2);
  query.fill(0);
  return await new Promise((resolve, reject) => {
    let received = Buffer.alloc(0);
    const socket = createConnection({ host: "127.0.0.1", port });
    socket.once("connect", () => socket.write(frame));
    socket.once("error", reject);
    socket.on("data", (chunk) => {
      received = Buffer.concat([received, chunk]);
      if (received.length < 2) return;
      const length = received.readUInt16BE(0);
      if (received.length === length + 2) {
        socket.destroy();
        frame.fill(0);
        resolve(Buffer.from(received.subarray(2)));
      }
    });
  });
}

function labels(nonces = publicNonces): Record<Exclude<Sbx001CaseId, "deny-secret">, string> {
  return Object.fromEntries(Object.entries(nonces).map(([caseId, value]) => [
    caseId,
    publicDnsLabel(caseId as Exclude<Sbx001CaseId, "deny-secret">, value),
  ])) as Record<Exclude<Sbx001CaseId, "deny-secret">, string>;
}

function receiverConfiguration(runId: string, publicLabels = labels()): Record<string, unknown> {
  return {
    runId,
    testId: SBX001_DIRECT_TEST_ID,
    authoritativeZone: zone,
    nameserverHostname: nameserver,
    answerIPv4: "192.0.2.1",
    observationWindowMs: 20 * 60_000,
    publicLabels,
  };
}

function receiverOptions(): Parameters<typeof startSbx001AuthoritativeReceiver>[0] {
  return {
    adminKey,
    proofKey,
    authoritativeZone: zone,
    nameserverHostname: nameserver,
    bindHost: "127.0.0.1",
    dnsPort: 0,
    adminPort: 0,
  };
}

async function snapshot(port: number, runId: string): Promise<{
  receipts: Sbx001Receipt[];
  arms: Array<{ caseId: Sbx001CaseId; operationId: string; armedAt: string }>;
}> {
  const response = await admin(port, `/v1/sbx001/admin/runs/${runId}`, "GET");
  expect(response.status).toBe(200);
  return await response.json() as Awaited<ReturnType<typeof snapshot>>;
}

async function waitForReceipt(port: number, runId: string, caseId: Sbx001CaseId): Promise<Sbx001Receipt> {
  const deadline = Date.now() + 1_000;
  while (Date.now() <= deadline) {
    const found = (await snapshot(port, runId)).receipts.find((entry) => entry.caseId === caseId);
    if (found) return found;
    await delay(10);
  }
  throw new Error(`receipt ${caseId} was not observed`);
}

function skipDnsName(packet: Buffer, start: number): number {
  let cursor = start;
  for (let index = 0; index < 128; index += 1) {
    const length = packet[cursor];
    if (length === undefined) throw new Error("truncated DNS name");
    if ((length & 0xc0) === 0xc0) return cursor + 2;
    cursor += 1;
    if (length === 0) return cursor;
    cursor += length;
  }
  throw new Error("invalid DNS name");
}

function recordTypes(packet: Buffer): { answers: number[]; authorities: number[] } {
  let cursor = skipDnsName(packet, 12) + 4;
  const result = { answers: [] as number[], authorities: [] as number[] };
  for (const [countOffset, target] of [[6, result.answers], [8, result.authorities]] as const) {
    for (let index = 0; index < packet.readUInt16BE(countOffset); index += 1) {
      cursor = skipDnsName(packet, cursor);
      target.push(packet.readUInt16BE(cursor));
      cursor += 10 + packet.readUInt16BE(cursor + 8);
    }
  }
  return result;
}

async function listenTcp(port = 0): Promise<Server> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  return server;
}

async function closeTcp(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

describe("SBX-001 direct authoritative receiver", () => {
  it("accepts the bounded EDNS OPT record normally added by recursive resolvers", () => {
    const query = buildDnsAQueryDirect(`a${nonce}.${zone}`, 0x1111);
    query.writeUInt16BE(1, 10);
    const opt = Buffer.alloc(11);
    opt[0] = 0;
    opt.writeUInt16BE(41, 1);
    opt.writeUInt16BE(1_232, 3);
    const withEdns = Buffer.concat([query, opt]);
    expect(parseDnsAQuestion(withEdns)).toMatchObject({ queryName: `a${nonce}.${zone}`, queryType: 1 });
    query.fill(0);
    withEdns.fill(0);
  });

  it("requires distinct case arming in order and emits only opaque post-arm receipts", async () => {
    const runId = randomUUID();
    const receiver = await startSbx001AuthoritativeReceiver(receiverOptions());
    try {
      const publicLabels = labels();
      expect((await admin(receiver.adminPort, `/v1/sbx001/admin/runs/${runId}`, "PUT",
        receiverConfiguration(runId, publicLabels))).status).toBe(204);
      const operations = Object.fromEntries(Object.entries(publicLabels).map(([caseId, label]) => [
        caseId,
        derivePublicDnsOperationId(proofKey, runId, caseId as Exclude<Sbx001CaseId, "deny-secret">, label),
      ])) as Record<Exclude<Sbx001CaseId, "deny-secret">, string>;

      const preArm = await udpQuery(receiver.dnsPort, `${publicLabels[SBX001_CASES.denyPublic]}.${zone}`);
      expect(preArm.readUInt16BE(2) & 0xf).toBe(3);
      expect((await snapshot(receiver.adminPort, runId)).receipts).toEqual([]);
      expect((await admin(receiver.adminPort,
        `/v1/sbx001/admin/runs/${runId}/cases/${SBX001_CASES.denyPublic}/arm`, "PUT",
        { operationId: operations[SBX001_CASES.denyPublic] })).status).toBe(409);
      const prematureSecret = Buffer.alloc(16, 0x24);
      const prematureCommitment = deriveSecretDnsCommitment(proofKey, runId, prematureSecret);
      prematureSecret.fill(0);
      expect((await admin(receiver.adminPort, `/v1/sbx001/admin/runs/${runId}/secret`, "PUT", {
        secretCommitment: prematureCommitment,
        queryNonce: "4123456789abcdef0123456789abcdef",
      })).status).toBe(409);

      const arm = async (caseId: Exclude<Sbx001CaseId, "deny-secret">) => await admin(receiver.adminPort,
        `/v1/sbx001/admin/runs/${runId}/cases/${caseId}/arm`, "PUT", { operationId: operations[caseId] });
      expect((await arm(SBX001_CASES.outsideUdp)).status).toBe(200);
      const minimized = await udpQuery(receiver.dnsPort, `${publicLabels[SBX001_CASES.outsideUdp]}.${zone}`, 2);
      expect(minimized.readUInt16BE(2) & 0xf).toBe(0);
      expect(recordTypes(minimized)).toEqual({ answers: [], authorities: [6] });
      expect((await snapshot(receiver.adminPort, runId)).receipts).toEqual([]);
      const udp = await udpQuery(receiver.dnsPort, `${publicLabels[SBX001_CASES.outsideUdp]}.${zone}`);
      await waitForReceipt(receiver.adminPort, runId, SBX001_CASES.outsideUdp);
      expect((await arm(SBX001_CASES.outsideTcp)).status).toBe(200);
      const tcp = await tcpQuery(receiver.dnsPort, `${publicLabels[SBX001_CASES.outsideTcp]}.${zone}`);
      await waitForReceipt(receiver.adminPort, runId, SBX001_CASES.outsideTcp);
      expect(udp.readUInt16BE(0)).toBe(0x1234);
      expect(udp.readUInt16BE(2) & 0x0400).toBe(0x0400);
      expect(tcp.readUInt16BE(0)).toBe(0x5678);
      expect(tcp.readUInt16BE(2) & 0x0400).toBe(0x0400);
      expect((await arm(SBX001_CASES.allowPublic)).status).toBe(200);
      await udpQuery(receiver.dnsPort, `${publicLabels[SBX001_CASES.allowPublic]}.${zone}`);
      await waitForReceipt(receiver.adminPort, runId, SBX001_CASES.allowPublic);
      const denyArmResponse = await arm(SBX001_CASES.denyPublic);
      expect(denyArmResponse.status).toBe(200);
      const denyArm = await denyArmResponse.json() as { armedAt: string };
      const rearmResponse = await arm(SBX001_CASES.denyPublic);
      expect(rearmResponse.status).toBe(200);
      expect(await rearmResponse.json()).toMatchObject({ armedAt: denyArm.armedAt });
      expect((await admin(receiver.adminPort,
        `/v1/sbx001/admin/runs/${runId}/cases/${SBX001_CASES.denyPublic}/arm`, "PUT",
        { operationId: `dns_${"Z".repeat(43)}` })).status).toBe(409);
      expect((await snapshot(receiver.adminPort, runId)).receipts.some((entry) =>
        entry.caseId === SBX001_CASES.denyPublic)).toBe(false);
      await udpQuery(receiver.dnsPort, `${publicLabels[SBX001_CASES.denyPublic]}.${zone}`);
      const denyReceipt = await waitForReceipt(receiver.adminPort, runId, SBX001_CASES.denyPublic);
      expect(denyReceipt.armedAt).toBe(denyArm.armedAt);
      expect(Date.parse(denyReceipt.observedAt)).toBeGreaterThanOrEqual(Date.parse(denyReceipt.armedAt));

      const secret = Buffer.from("00112233445566778899aabbccddeeff", "hex");
      const commitment = deriveSecretDnsCommitment(proofKey, runId, secret);
      const secretNonce = "4123456789abcdef0123456789abcdef";
      expect((await admin(receiver.adminPort, `/v1/sbx001/admin/runs/${runId}/secret`, "PUT", {
        secretCommitment: commitment,
        queryNonce: publicNonces[SBX001_CASES.denyPublic],
      })).status).toBe(409);
      expect((await admin(receiver.adminPort, `/v1/sbx001/admin/runs/${runId}/secret`, "PUT", {
        secretCommitment: commitment,
        queryNonce: secretNonce,
      })).status).toBe(204);
      const secretLabel = secretDnsLabel(secret, secretNonce);
      const secretOperation = deriveSecretDnsOperationId(proofKey, runId, commitment);
      const preArmSecret = await udpQuery(receiver.dnsPort, `${secretLabel}.${zone}`);
      expect(preArmSecret.readUInt16BE(2) & 0xf).toBe(3);
      expect((await snapshot(receiver.adminPort, runId)).receipts.some((entry) =>
        entry.caseId === SBX001_CASES.denySecret)).toBe(false);
      expect((await admin(receiver.adminPort,
        `/v1/sbx001/admin/runs/${runId}/cases/${SBX001_CASES.denySecret}/arm`, "PUT",
        { operationId: secretOperation })).status).toBe(200);
      await udpQuery(receiver.dnsPort, `${secretLabel}.${zone}`);
      await waitForReceipt(receiver.adminPort, runId, SBX001_CASES.denySecret);
      const response = await admin(receiver.adminPort, `/v1/sbx001/admin/runs/${runId}`, "GET");
      const finalSnapshot = await response.json() as Record<string, unknown>;
      const serialized = JSON.stringify(finalSnapshot);
      expect(finalSnapshot).toMatchObject({
        configured: true,
        secretRegistered: true,
        secretRegisteredAt: expect.any(String),
        rawQueryNamesRetained: false,
        rawSecretsRetained: false,
        rawSecretDigestsRetained: false,
      });
      expect(serialized).toContain(deriveSecretDnsOperationId(proofKey, runId, commitment));
      expect(serialized).not.toContain(secretLabel);
      expect(serialized).not.toContain(secret.toString("hex"));
      for (const label of Object.values(publicLabels)) expect(serialized).not.toContain(label);
      for (const value of Object.values(publicNonces)) expect(serialized).not.toContain(value);
      expect(serialized).not.toContain(secretNonce);
      expect(serialized).not.toContain("queryName");
      expect(serialized).not.toContain("secretDigest");
      secret.fill(0);
    } finally {
      await receiver.close();
    }
  });

  it("serves apex NS/SOA and SOA-backed authoritative negative answers", async () => {
    const receiver = await startSbx001AuthoritativeReceiver(receiverOptions());
    try {
      const ns = await udpQuery(receiver.dnsPort, zone, 2);
      const soa = await udpQuery(receiver.dnsPort, zone, 6);
      const missing = await udpQuery(receiver.dnsPort, `missing.${zone}`, 1);
      const apexAaaa = await udpQuery(receiver.dnsPort, zone, 28);
      const outside = await udpQuery(receiver.dnsPort, "outside.example", 1);
      expect(ns.readUInt16BE(2) & 0x040f).toBe(0x0400);
      expect(recordTypes(ns)).toEqual({ answers: [2], authorities: [] });
      expect(recordTypes(soa)).toEqual({ answers: [6], authorities: [] });
      expect(missing.readUInt16BE(2) & 0x040f).toBe(0x0403);
      expect(recordTypes(missing)).toEqual({ answers: [], authorities: [6] });
      expect(apexAaaa.readUInt16BE(2) & 0x040f).toBe(0x0400);
      expect(recordTypes(apexAaaa)).toEqual({ answers: [], authorities: [6] });
      expect(outside.readUInt16BE(2) & 0x040f).toBe(0x0005);
    } finally {
      await receiver.close();
    }
  });

  it("commits exact UDP ingress before a failed authoritative response send", async () => {
    const runId = randomUUID();
    const receiver = await startSbx001AuthoritativeReceiver(receiverOptions());
    const originalSend = receiver.udpSocket.send.bind(receiver.udpSocket);
    try {
      const publicLabels = labels();
      expect((await admin(receiver.adminPort, `/v1/sbx001/admin/runs/${runId}`, "PUT",
        receiverConfiguration(runId, publicLabels))).status).toBe(204);
      const operationId = derivePublicDnsOperationId(
        proofKey,
        runId,
        SBX001_CASES.outsideUdp,
        publicLabels[SBX001_CASES.outsideUdp],
      );
      expect((await admin(receiver.adminPort,
        `/v1/sbx001/admin/runs/${runId}/cases/${SBX001_CASES.outsideUdp}/arm`, "PUT",
        { operationId })).status).toBe(200);
      receiver.udpSocket.send = ((...args: unknown[]) => {
        const callback = args.at(-1) as ((error: Error) => void) | undefined;
        queueMicrotask(() => callback?.(Object.assign(new Error("injected send failure"), { code: "EIO" })));
      }) as typeof receiver.udpSocket.send;
      const query = buildDnsAQueryDirect(`${publicLabels[SBX001_CASES.outsideUdp]}.${zone}`, 0x7001);
      receiver.udpSocket.emit("message", query, {
        address: "127.0.0.1",
        family: "IPv4",
        port: 53001,
        size: query.length,
      });
      const ingress = await waitForReceipt(receiver.adminPort, runId, SBX001_CASES.outsideUdp);
      expect(ingress).toMatchObject({
        caseId: SBX001_CASES.outsideUdp,
        operationId,
        authoritativeResponseSent: false,
        rawQueryNameRetained: false,
      });
    } finally {
      receiver.udpSocket.send = originalSend as typeof receiver.udpSocket.send;
      await receiver.close();
    }
  });

  it("commits exact TCP ingress before a peer reset prevents the response write", async () => {
    const runId = randomUUID();
    const receiver = await startSbx001AuthoritativeReceiver({
      ...receiverOptions(),
      beforeTcpResponse: (socket) => socket.resetAndDestroy(),
    });
    try {
      const publicLabels = labels();
      expect((await admin(receiver.adminPort, `/v1/sbx001/admin/runs/${runId}`, "PUT",
        receiverConfiguration(runId, publicLabels))).status).toBe(204);
      const outsideUdpOperation = derivePublicDnsOperationId(
        proofKey,
        runId,
        SBX001_CASES.outsideUdp,
        publicLabels[SBX001_CASES.outsideUdp],
      );
      expect((await admin(receiver.adminPort,
        `/v1/sbx001/admin/runs/${runId}/cases/${SBX001_CASES.outsideUdp}/arm`, "PUT",
        { operationId: outsideUdpOperation })).status).toBe(200);
      await udpQuery(receiver.dnsPort, `${publicLabels[SBX001_CASES.outsideUdp]}.${zone}`);
      await waitForReceipt(receiver.adminPort, runId, SBX001_CASES.outsideUdp);
      const outsideTcpOperation = derivePublicDnsOperationId(
        proofKey,
        runId,
        SBX001_CASES.outsideTcp,
        publicLabels[SBX001_CASES.outsideTcp],
      );
      expect((await admin(receiver.adminPort,
        `/v1/sbx001/admin/runs/${runId}/cases/${SBX001_CASES.outsideTcp}/arm`, "PUT",
        { operationId: outsideTcpOperation })).status).toBe(200);
      const query = buildDnsAQueryDirect(`${publicLabels[SBX001_CASES.outsideTcp]}.${zone}`, 0x7002);
      const frame = Buffer.alloc(query.length + 2);
      frame.writeUInt16BE(query.length, 0);
      query.copy(frame, 2);
      const client = createConnection({ host: "127.0.0.1", port: receiver.dnsPort });
      client.once("connect", () => client.write(frame));
      client.once("error", () => undefined);
      await new Promise<void>((resolveClose) => client.once("close", () => resolveClose()));
      query.fill(0);
      frame.fill(0);
      const ingress = await waitForReceipt(receiver.adminPort, runId, SBX001_CASES.outsideTcp);
      expect(ingress).toMatchObject({
        caseId: SBX001_CASES.outsideTcp,
        operationId: outsideTcpOperation,
        authoritativeResponseSent: false,
      });
    } finally {
      await receiver.close();
    }
  });

  it("rejects shared nonces and a second active run", async () => {
    const receiver = await startSbx001AuthoritativeReceiver(receiverOptions());
    try {
      const rejected = randomUUID();
      const reused = Object.fromEntries(Object.values(SBX001_CASES).filter((caseId) => caseId !== "deny-secret")
        .map((caseId) => [caseId, publicDnsLabel(caseId, nonce)]));
      expect((await admin(receiver.adminPort, `/v1/sbx001/admin/runs/${rejected}`, "PUT",
        receiverConfiguration(rejected, reused as ReturnType<typeof labels>))).status).toBe(400);
      const first = randomUUID();
      expect((await admin(receiver.adminPort, `/v1/sbx001/admin/runs/${first}`, "PUT",
        receiverConfiguration(first))).status).toBe(204);
      const second = randomUUID();
      expect((await admin(receiver.adminPort, `/v1/sbx001/admin/runs/${second}`, "PUT",
        receiverConfiguration(second))).status).toBe(409);
    } finally {
      await receiver.close();
    }
  });

  it("rolls back UDP when the matching TCP bind fails", async () => {
    const occupied = await listenTcp();
    const address = occupied.address();
    if (!address || typeof address === "string") throw new Error("test TCP listener has no port");
    try {
      await expect(startSbx001AuthoritativeReceiver({ ...receiverOptions(), dnsPort: address.port }))
        .rejects.toMatchObject({ code: "EADDRINUSE" });
      const probe = dgram.createSocket("udp4");
      await new Promise<void>((resolve, reject) => {
        probe.once("error", reject);
        probe.bind(address.port, "127.0.0.1", () => resolve());
      });
      probe.close();
    } finally {
      await closeTcp(occupied);
    }
  });

  it("rolls back both DNS transports when the admin bind fails", async () => {
    const occupiedAdmin = await listenTcp();
    const adminAddress = occupiedAdmin.address();
    if (!adminAddress || typeof adminAddress === "string") throw new Error("test admin listener has no port");
    const dnsReservation = await listenTcp();
    const dnsAddress = dnsReservation.address();
    if (!dnsAddress || typeof dnsAddress === "string") throw new Error("test DNS listener has no port");
    const dnsPort = dnsAddress.port;
    await closeTcp(dnsReservation);
    try {
      await expect(startSbx001AuthoritativeReceiver({
        ...receiverOptions(),
        dnsPort,
        adminPort: adminAddress.port,
      })).rejects.toMatchObject({ code: "EADDRINUSE" });
      const udpProbe = dgram.createSocket("udp4");
      await new Promise<void>((resolve, reject) => {
        udpProbe.once("error", reject);
        udpProbe.bind(dnsPort, "127.0.0.1", () => resolve());
      });
      udpProbe.close();
      const tcpProbe = await listenTcp(dnsPort);
      await closeTcp(tcpProbe);
    } finally {
      await closeTcp(occupiedAdmin);
    }
  });

  it("requires exact delegation and address sets", () => {
    const expected = { nameserver, expectedIPv4: "203.0.113.8" };
    const exact = { nameservers: [nameserver], nameserverIPv4: ["203.0.113.8"], nameserverIPv6: [], nameserverCname: [] };
    expect(exactDelegationSets(exact, expected)).toBe(true);
    expect(exactDelegationSets({ ...exact, nameservers: [nameserver, "ns2.sbx001.form-app.app"] }, expected)).toBe(false);
    expect(exactDelegationSets({ ...exact, nameserverIPv4: ["203.0.113.8", "203.0.113.9"] }, expected)).toBe(false);
    expect(exactDelegationSets({ ...exact, nameserverIPv6: ["2001:db8::1"] }, expected)).toBe(false);
    expect(exactDelegationSets({ ...exact, nameserverCname: ["alias.sbx001.form-app.app"] }, expected)).toBe(false);
  });

  const unboundPath = ["/opt/homebrew/sbin/unbound", "/usr/local/sbin/unbound", "/usr/sbin/unbound"]
    .find((candidate) => existsSync(candidate));
  it.skipIf(unboundPath === undefined)("works through a loopback recursive resolver without observer artifacts", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx001-unbound-"));
    temporaryDirectories.push(directory);
    const reservation = await listenTcp();
    const reservedAddress = reservation.address();
    if (!reservedAddress || typeof reservedAddress === "string") throw new Error("recursive port reservation failed");
    const recursivePort = reservedAddress.port;
    await closeTcp(reservation);
    const receiver = await startSbx001AuthoritativeReceiver(receiverOptions());
    const runId = randomUUID();
    const publicLabels = labels();
    const operationId = derivePublicDnsOperationId(
      proofKey,
      runId,
      SBX001_CASES.outsideUdp,
      publicLabels[SBX001_CASES.outsideUdp],
    );
    const configPath = join(directory, "unbound.conf");
    await writeFile(configPath, [
      "server:",
      `  interface: 127.0.0.1@${recursivePort}`,
      "  outgoing-interface: 127.0.0.1",
      "  access-control: 127.0.0.0/8 allow",
      "  do-daemonize: no",
      "  username: \"\"",
      "  chroot: \"\"",
      `  directory: \"${directory}\"`,
      "  pidfile: \"\"",
      "  logfile: \"\"",
      "  use-syslog: no",
      "  do-ip4: yes",
      "  do-ip6: no",
      "  do-not-query-localhost: no",
      "  module-config: \"iterator\"",
      "stub-zone:",
      `  name: \"${zone}.\"`,
      `  stub-addr: 127.0.0.1@${receiver.dnsPort}`,
      "  stub-prime: no",
      "  stub-first: no",
      "",
    ].join("\n"), { mode: 0o600 });
    const child = spawn(unboundPath!, ["-d", "-c", configPath], { stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      if (stderr.length < 8_192) stderr += String(chunk).slice(0, 8_192 - stderr.length);
    });
    try {
      expect((await admin(receiver.adminPort, `/v1/sbx001/admin/runs/${runId}`, "PUT",
        receiverConfiguration(runId, publicLabels))).status).toBe(204);
      expect((await admin(receiver.adminPort,
        `/v1/sbx001/admin/runs/${runId}/cases/${SBX001_CASES.outsideUdp}/arm`, "PUT",
        { operationId })).status).toBe(200);
      const deadline = Date.now() + 5_000;
      let response: Buffer | undefined;
      while (!response && Date.now() < deadline && child.exitCode === null) {
        try {
          response = await udpQuery(recursivePort, `${publicLabels[SBX001_CASES.outsideUdp]}.${zone}`);
        } catch {
          await delay(25);
        }
      }
      if (!response) throw new Error(`local Unbound recursion failed: ${stderr}`);
      expect(response.readUInt16BE(2) & 0xf).toBe(0);
      expect(recordTypes(response).answers).toEqual([1]);
      expect((await waitForReceipt(receiver.adminPort, runId, SBX001_CASES.outsideUdp)).operationId).toBe(operationId);
    } finally {
      child.kill("SIGTERM");
      if (child.exitCode === null) await Promise.race([once(child, "exit"), delay(2_000)]);
      if (child.exitCode === null) child.kill("SIGKILL");
      await receiver.close();
    }
  }, 15_000);
});

function policy(sessionId: string, expected: "allow-all" | "deny-all"): Sbx001PolicyReadback {
  return {
    observedAt: "2026-08-19T04:00:00.000Z",
    originalSessionId: sessionId,
    activeSessionId: sessionId,
    independentSessionId: sessionId,
    activeSandboxPolicy: expected,
    activeSessionPolicy: expected,
    independentSandboxPolicy: expected,
    independentSessionPolicy: expected,
    exact: true,
    sameSession: true,
    passed: true,
  };
}

function dns(runId: string, caseId: "allow-public" | "deny-public" | "deny-secret"): Sbx001GuestDnsEvidence {
  return {
    schemaVersion: 1,
    ok: true,
    mode: "dns",
    runId,
    testId: SBX001_DIRECT_TEST_ID,
    guestNodeVersion: process.version,
    caseId,
    queryType: "A",
    queryAttempts: 1,
    retryCount: 0,
    resolverFamily: 4,
    resolverPort: 53,
    sendInvoked: true,
    datagramAcceptedByKernel: true,
    responseReceived: caseId !== "deny-public",
    timedOut: caseId === "deny-public",
    secretFileValidated: caseId === "deny-secret",
    ...(caseId === "deny-secret" ? { secretFileMode: 0o600, secretBytes: 16 } : {}),
    secretEncodedInOneLabel: caseId === "deny-secret",
    rawQueryNameRetained: false,
    rawSecretRetained: false,
    rawSecretDigestRetained: false,
  };
}

function httpsEvidence(runId: string, caseId: "allow-https" | "deny-https"): Sbx001GuestHttpsEvidence {
  return {
    schemaVersion: 1,
    ok: true,
    mode: "https",
    runId,
    testId: SBX001_DIRECT_TEST_ID,
    guestNodeVersion: process.version,
    caseId,
    origin: "https://vsc-h3-action-swve.cyrus-206.workers.dev",
    path: "/healthz",
    connectionAttempts: 1,
    retryCount: 0,
    responseBodiesRetained: false,
    durationMs: 1,
    receivedResponse: caseId === "allow-https",
    ...(caseId === "allow-https" ? { statusCode: 200 } : { errorCode: "EAI_AGAIN" }),
    timedOut: false,
  };
}

function receipt(
  runId: string,
  caseId: Sbx001Receipt["caseId"],
  operationId: string,
  armedAt: string,
  observedAt: string,
): Sbx001Receipt {
  return {
    runId,
    caseId,
    kind: caseId === SBX001_CASES.denySecret ? "secret" : "public",
    transport: caseId === SBX001_CASES.outsideTcp ? "tcp" : "udp",
    queryType: "A",
    authoritativeResponseSent: true,
    operationId,
    armedAt,
    observedAt,
    sourceAddress: "127.0.0.1",
    sourcePort: 12345,
    duplicateCount: 0,
    withinConfiguredWindow: true,
    rawQueryNameRetained: false,
    rawSecretRetained: false,
    rawSecretDigestRetained: false,
  };
}

describe("SBX-001 direct evidence validation", () => {
  it("fails closed on minimal, malformed, or identity-substituted guest evidence", () => {
    const runId = randomUUID();
    const validDns = dns(runId, SBX001_CASES.allowPublic);
    expect(sanitizeSbx001DnsEvidence(validDns, SBX001_CASES.allowPublic, runId)).toEqual(validDns);
    for (const malformed of [
      { ok: true, sendInvoked: true },
      { ...validDns, schemaVersion: 2 },
      { ...validDns, testId: "SBX-001" },
      { ...validDns, caseId: SBX001_CASES.denyPublic },
      { ...validDns, queryAttempts: 2 },
      { ...validDns, rawQueryNameRetained: true },
      { ...validDns, unexpected: true },
    ]) {
      expect(sanitizeSbx001DnsEvidence(malformed, SBX001_CASES.allowPublic, runId).ok).toBe(false);
    }

    const origin = "https://vsc-h3-action-swve.cyrus-206.workers.dev";
    const validHttps = httpsEvidence(runId, "allow-https");
    expect(sanitizeSbx001HttpsEvidence(validHttps, "allow-https", runId, origin)).toEqual(validHttps);
    for (const malformed of [
      { ok: true, receivedResponse: true },
      { ...validHttps, schemaVersion: 0 },
      { ...validHttps, runId: randomUUID() },
      { ...validHttps, path: "/other" },
      { ...validHttps, durationMs: 10_001 },
      { ...validHttps, responseBodiesRetained: true },
      { ...validHttps, unexpected: true },
    ]) {
      expect(sanitizeSbx001HttpsEvidence(malformed, "allow-https", runId, origin).ok).toBe(false);
    }
  });

  it("validates the complete receiver provenance envelope and arm/receipt linkage", () => {
    const runId = randomUUID();
    const label = publicDnsLabel(SBX001_CASES.outsideUdp, publicNonces[SBX001_CASES.outsideUdp]);
    const operationId = derivePublicDnsOperationId(proofKey, runId, SBX001_CASES.outsideUdp, label);
    const configuredAt = "2026-08-19T04:00:00.000Z";
    const armedAt = "2026-08-19T04:00:01.000Z";
    const observedAt = "2026-08-19T04:00:02.000Z";
    const valid = {
      configured: true,
      runId,
      configuredAt,
      expiresAt: "2026-08-19T04:20:00.000Z",
      observationWindowMs: 20 * 60_000,
      arms: [{ caseId: SBX001_CASES.outsideUdp, operationId, armedAt }],
      receipts: [receipt(runId, SBX001_CASES.outsideUdp, operationId, armedAt, observedAt)],
      secretRegistered: false,
      rawQueryNamesRetained: false,
      rawSecretsRetained: false,
      rawSecretDigestsRetained: false,
    };
    expect(sanitizeSbx001ReceiverSnapshot(valid, runId)).toEqual(valid);
    const recursiveTcp = {
      ...valid,
      arms: [{ caseId: SBX001_CASES.denyPublic, operationId, armedAt }],
      receipts: [{
        ...receipt(runId, SBX001_CASES.denyPublic, operationId, armedAt, observedAt),
        transport: "tcp" as const,
      }],
    };
    expect(sanitizeSbx001ReceiverSnapshot(recursiveTcp, runId).receipts[0]?.transport).toBe("tcp");
    expect(sanitizeSbx001ReceiverSnapshot({
      ...valid,
      receipts: [{ ...valid.receipts[0], authoritativeResponseSent: false }],
    }, runId).receipts[0]?.authoritativeResponseSent).toBe(false);
    expect(() => sanitizeSbx001ReceiverSnapshot({ ...valid, unexpected: true }, runId)).toThrow();
    expect(() => sanitizeSbx001ReceiverSnapshot({
      ...valid,
      expiresAt: "2026-08-19T04:19:59.000Z",
    }, runId)).toThrow();
    expect(() => sanitizeSbx001ReceiverSnapshot({
      ...valid,
      receipts: [{ ...valid.receipts[0], operationId: `dns_${"Z".repeat(43)}` }],
    }, runId)).toThrow();
  });

  it("models a late create becoming visible and a full bounded absence window", async () => {
    let clock = 0;
    const sequence: Array<{ id: string } | undefined> = [undefined, undefined, { id: "late" }];
    const recovered = await pollForLateSbx001Resource({
      checks: 16,
      intervalMs: 2_000,
      lookup: async () => sequence.shift(),
      wait: async (milliseconds) => { clock += milliseconds; },
      now: () => clock,
    });
    expect(recovered).toEqual({ resource: { id: "late" }, checks: 3, observationMs: 4_000 });

    clock = 0;
    const absent = await pollForLateSbx001Resource({
      checks: 16,
      intervalMs: 2_000,
      lookup: async () => undefined,
      wait: async (milliseconds) => { clock += milliseconds; },
      now: () => clock,
    });
    expect(absent).toEqual({ checks: 16, observationMs: 30_000 });
  });

  it("validates every durable mutation checkpoint and fails closed on impossible progress", () => {
    const journal = createSbx001DirectJournal(new Date("2026-08-19T04:00:00.000Z"), randomUUID());
    expect(parseSbx001DirectJournal(journal)).toEqual(journal);
    journal.receiverConfigureAttemptedAt = "2026-08-19T04:00:01.000Z";
    journal.receiverConfigured = true;
    journal.createAttemptedAt = "2026-08-19T04:00:02.000Z";
    journal.createRequestSettledAt = "2026-08-19T04:00:03.000Z";
    journal.sessionId = "sbx_exact_owned_session";
    journal.sandboxAttributed = true;
    journal.stopAttempted = true;
    journal.stopped = true;
    journal.deleteAttempted = true;
    journal.deleted = true;
    journal.sandboxAbsenceChecks = 3;
    journal.sandboxPrefixAbsent = true;
    journal.finalReceiverSnapshot = {
      configured: true,
      runId: journal.runId,
      configuredAt: "2026-08-19T04:00:00.000Z",
      expiresAt: "2026-08-19T04:20:00.000Z",
      observationWindowMs: 20 * 60_000,
      arms: [],
      receipts: [],
      secretRegistered: false,
      rawQueryNamesRetained: false,
      rawSecretsRetained: false,
      rawSecretDigestsRetained: false,
    };
    journal.finalReceiverSnapshotCaptured = true;
    journal.receiverDeleteAttempted = true;
    journal.receiverDeleted = true;
    journal.receiverAbsenceChecks = 3;
    journal.artifactWriteAttemptedAt = "2026-08-19T04:00:04.000Z";
    journal.artifactWritten = true;
    journal.completed = true;
    journal.updatedAt = "2026-08-19T04:00:05.000Z";
    expect(parseSbx001DirectJournal(journal)).toEqual(journal);
    expect(() => parseSbx001DirectJournal({
      ...createSbx001DirectJournal(),
      completed: true,
    })).toThrow(/checkpoint dependencies/u);
    expect(() => parseSbx001DirectJournal({
      ...createSbx001DirectJournal(),
      receiverConfigured: true,
    })).toThrow(/checkpoint dependencies/u);
  });
});

describe("SBX-001 direct verdict", () => {
  it("requires public receipt before mode-0600 secret staging and classifies the exact HMAC receipt High", () => {
    const runId = randomUUID();
    const sessionId = "sbx_owned_session";
    const labels = {
      [SBX001_CASES.outsideUdp]: publicDnsLabel(SBX001_CASES.outsideUdp, nonce),
      [SBX001_CASES.outsideTcp]: publicDnsLabel(SBX001_CASES.outsideTcp, nonce),
      [SBX001_CASES.allowPublic]: publicDnsLabel(SBX001_CASES.allowPublic, nonce),
      [SBX001_CASES.denyPublic]: publicDnsLabel(SBX001_CASES.denyPublic, nonce),
    };
    const secret = Buffer.alloc(16, 0x42);
    const commitment = deriveSecretDnsCommitment(proofKey, runId, secret);
    const operations = {
      [SBX001_CASES.outsideUdp]: derivePublicDnsOperationId(proofKey, runId, SBX001_CASES.outsideUdp, labels[SBX001_CASES.outsideUdp]),
      [SBX001_CASES.outsideTcp]: derivePublicDnsOperationId(proofKey, runId, SBX001_CASES.outsideTcp, labels[SBX001_CASES.outsideTcp]),
      [SBX001_CASES.allowPublic]: derivePublicDnsOperationId(proofKey, runId, SBX001_CASES.allowPublic, labels[SBX001_CASES.allowPublic]),
      [SBX001_CASES.denyPublic]: derivePublicDnsOperationId(proofKey, runId, SBX001_CASES.denyPublic, labels[SBX001_CASES.denyPublic]),
      [SBX001_CASES.denySecret]: deriveSecretDnsOperationId(proofKey, runId, commitment),
    };
    const t0 = "2026-08-19T04:00:00.000Z";
    const t1 = "2026-08-19T04:00:01.000Z";
    const t2 = "2026-08-19T04:00:02.000Z";
    const t3 = "2026-08-19T04:00:03.000Z";
    const base = {
      runId,
      authoritativeZone: zone,
      httpsControlOrigin: "https://vsc-h3-action-swve.cyrus-206.workers.dev",
      identityAndScopePassed: true,
      delegationPreflightPassed: true,
      outsideHttpsPassed: true,
      outsideUdpPassed: true,
      outsideTcpPassed: true,
      allowReadback: policy(sessionId, "allow-all"),
      allowHttps: httpsEvidence(runId, "allow-https"),
      allowDns: dns(runId, "allow-public"),
      denyReadback: policy(sessionId, "deny-all"),
      denyPostReadback: policy(sessionId, "deny-all"),
      denyHttps: httpsEvidence(runId, "deny-https"),
      denyDns: dns(runId, "deny-public"),
      secretDns: dns(runId, "deny-secret"),
      receiver: {
        configured: true,
        runId,
        configuredAt: t0,
        expiresAt: "2026-08-19T04:20:00.000Z",
        observationWindowMs: 20 * 60_000,
        receipts: [
          receipt(runId, SBX001_CASES.outsideUdp, operations[SBX001_CASES.outsideUdp], t0, t0),
          receipt(runId, SBX001_CASES.outsideTcp, operations[SBX001_CASES.outsideTcp], t0, t0),
          receipt(runId, SBX001_CASES.allowPublic, operations[SBX001_CASES.allowPublic], t0, t0),
          receipt(runId, SBX001_CASES.denyPublic, operations[SBX001_CASES.denyPublic], t0, t0),
          receipt(runId, SBX001_CASES.denySecret, operations[SBX001_CASES.denySecret], t2, t3),
        ],
        arms: [
          { caseId: SBX001_CASES.outsideUdp, operationId: operations[SBX001_CASES.outsideUdp], armedAt: t0 },
          { caseId: SBX001_CASES.outsideTcp, operationId: operations[SBX001_CASES.outsideTcp], armedAt: t0 },
          { caseId: SBX001_CASES.allowPublic, operationId: operations[SBX001_CASES.allowPublic], armedAt: t0 },
          { caseId: SBX001_CASES.denyPublic, operationId: operations[SBX001_CASES.denyPublic], armedAt: t0 },
          { caseId: SBX001_CASES.denySecret, operationId: operations[SBX001_CASES.denySecret], armedAt: t2 },
        ],
        secretRegistered: true,
        secretRegisteredAt: t1,
        rawQueryNamesRetained: false as const,
        rawSecretsRetained: false as const,
        rawSecretDigestsRetained: false as const,
      },
      controllerArms: {
        [SBX001_CASES.outsideUdp]: {
          caseId: SBX001_CASES.outsideUdp,
          operationId: operations[SBX001_CASES.outsideUdp],
          armedAt: t0,
          requestedAt: t0,
          acknowledgedAt: t0,
        },
        [SBX001_CASES.outsideTcp]: {
          caseId: SBX001_CASES.outsideTcp,
          operationId: operations[SBX001_CASES.outsideTcp],
          armedAt: t0,
          requestedAt: t0,
          acknowledgedAt: t0,
        },
        [SBX001_CASES.allowPublic]: {
          caseId: SBX001_CASES.allowPublic,
          operationId: operations[SBX001_CASES.allowPublic],
          armedAt: t0,
          requestedAt: t0,
          acknowledgedAt: t0,
        },
        [SBX001_CASES.denyPublic]: {
          caseId: SBX001_CASES.denyPublic,
          operationId: operations[SBX001_CASES.denyPublic],
          armedAt: t0,
          requestedAt: t0,
          acknowledgedAt: t0,
        },
        [SBX001_CASES.denySecret]: {
          caseId: SBX001_CASES.denySecret,
          operationId: operations[SBX001_CASES.denySecret],
          armedAt: t2,
          requestedAt: t2,
          acknowledgedAt: t2,
        },
      },
      receiverObservations: Object.fromEntries(Object.values(SBX001_CASES).map((caseId) => [caseId, {
        caseId,
        operationId: operations[caseId],
        startedAt: t0,
        completedAt: caseId === SBX001_CASES.denySecret ? t3 : t0,
        maximumWindowMs: 5_000 as const,
        pollCount: 1,
        receiptObserved: true,
      }])) as Sbx001DirectAssessmentInput["receiverObservations"],
      expectedOperations: operations,
      denyPublicReceiptObservedAt: t0,
      denyPublicReceiptFetchedAt: t0,
      secretCreatedAt: t1,
      secretRegisteredAt: t1,
      secretWrittenAt: t2,
      secretAttempted: true,
      secretStagedBeforePublicSignal: false,
      cleanup: {
        sandboxCreateAttempted: true,
        sandboxRecovered: false,
        sandboxAlreadyAbsent: false,
        sandboxRecoveryChecks: 0,
        sandboxRecoveryObservationMs: 0,
        stopAttempted: true,
        stopped: true,
        deleteAttempted: true,
        deleted: true,
        absenceChecks: 3,
        absenceConfirmed: true,
        receiverConfigureAttempted: true,
        receiverAlreadyAbsent: false,
        receiverDeleteAttempted: true,
        receiverDeleted: true,
        receiverAbsenceChecks: 3,
        receiverAbsenceConfirmed: true,
        errors: [],
      },
      retention: {
        rawQueryName: false as const,
        rawOperatorSecret: false as const,
        rawSecretDigest: false as const,
        rawGuestConfiguration: false as const,
        rawCommandOutput: false as const,
      },
    } satisfies Sbx001DirectAssessmentInput;
    expect(assessSbx001Direct(base)).toMatchObject({ verdict: "candidate-high", severity: "high", candidate: true });
    expect(assessSbx001Direct({
      ...base,
      receiver: {
        ...base.receiver,
        receipts: base.receiver.receipts.map((entry) =>
          entry.caseId === SBX001_CASES.denyPublic || entry.caseId === SBX001_CASES.denySecret
            ? { ...entry, transport: "tcp" as const }
            : entry),
      },
    })).toMatchObject({ verdict: "candidate-high", severity: "high", candidate: true });
    expect(assessSbx001Direct({
      ...base,
      receiver: {
        ...base.receiver,
        receipts: base.receiver.receipts.map((entry) => entry.caseId === SBX001_CASES.denyPublic
          ? { ...entry, armedAt: t1, observedAt: t1 }
          : entry),
      },
    })).toMatchObject({ verdict: "indeterminate", candidate: false });
    expect(assessSbx001Direct({
      ...base,
      secretCreatedAt: new Date(Date.parse(t0) - 1).toISOString(),
      secretStagedBeforePublicSignal: true,
    })).toMatchObject({ verdict: "candidate-medium", severity: "medium" });
    const {
      secretDns: _secretDns,
      secretCreatedAt: _secretCreatedAt,
      secretRegisteredAt: _secretRegisteredAt,
      secretWrittenAt: _secretWrittenAt,
      ...withoutSecret
    } = base;
    expect(assessSbx001Direct({
      ...withoutSecret,
      secretAttempted: false,
      receiver: { ...base.receiver, receipts: base.receiver.receipts.filter((entry) => entry.caseId !== SBX001_CASES.denySecret), secretRegistered: false },
    })).toMatchObject({ verdict: "candidate-medium", severity: "medium", secretPhaseAuthorized: true });
    const { denyPublicReceiptObservedAt: _denyPublicReceiptObservedAt, ...withoutPublicTimestamp } = withoutSecret;
    const cleanNegative = {
      ...withoutPublicTimestamp,
      denyDns: {
        ...base.denyDns,
        datagramAcceptedByKernel: false,
        responseReceived: false,
        timedOut: false,
        errorCode: "EHOSTUNREACH",
      },
      secretAttempted: false,
      receiver: {
        ...base.receiver,
        receipts: base.receiver.receipts.filter((entry) =>
          entry.caseId !== SBX001_CASES.denyPublic && entry.caseId !== SBX001_CASES.denySecret),
        arms: base.receiver.arms.filter((entry) => entry.caseId !== SBX001_CASES.denySecret),
        secretRegistered: false,
      },
      receiverObservations: {
        ...base.receiverObservations,
        [SBX001_CASES.denyPublic]: {
          caseId: SBX001_CASES.denyPublic,
          operationId: operations[SBX001_CASES.denyPublic],
          startedAt: t0,
          completedAt: "2026-08-19T04:00:05.000Z",
          maximumWindowMs: 5_000,
          pollCount: 21,
          receiptObserved: false,
        },
      },
    } satisfies Sbx001DirectAssessmentInput;
    expect(assessSbx001Direct(cleanNegative)).toMatchObject({ verdict: "pass", severity: "none", candidate: false });
    const { errorCode: _denyErrorCode, ...acceptedDenyDns } = cleanNegative.denyDns;
    expect(assessSbx001DirectWithIngress({
      ...cleanNegative,
      denyDns: {
        ...acceptedDenyDns,
        datagramAcceptedByKernel: true,
        timedOut: true,
      },
    })).toMatchObject({ verdict: "indeterminate", candidate: false });
    const failedResponseIngress = {
      ...withoutSecret,
      secretAttempted: false,
      receiver: {
        ...base.receiver,
        receipts: base.receiver.receipts
          .filter((entry) => entry.caseId !== SBX001_CASES.denySecret)
          .map((entry) => entry.caseId === SBX001_CASES.denyPublic
            ? { ...entry, authoritativeResponseSent: false }
            : entry),
        secretRegistered: false,
      },
    } satisfies Sbx001DirectAssessmentInput;
    expect(assessSbx001Direct(failedResponseIngress)).toMatchObject({ verdict: "indeterminate", candidate: false });
    expect(assessSbx001DirectWithIngress(failedResponseIngress))
      .toMatchObject({ verdict: "candidate-medium", candidate: true });
    secret.fill(0);
  });
});

describe("SBX-001 direct guest", () => {
  it("forms one bounded secret-bearing label guest-side and never requires a pad or digest", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx001-direct-guest-"));
    temporaryDirectories.push(directory);
    const secretPath = join(directory, "operator-secret");
    const secret = Buffer.from("00112233445566778899aabbccddeeff", "hex");
    await writeFile(secretPath, secret, { mode: 0o600 });
    await chmod(secretPath, 0o600);
    const source = await readFile("guest/dns-authoritative-probe.mjs", "utf8");
    expect(source).not.toContain("secretSha256");
    expect(source).not.toContain("oneTimePad");
    const isolated = source.replace(
      'export const SECRET_FILE_PATH = "/tmp/sbx-001/operator-secret";',
      `export const SECRET_FILE_PATH = ${JSON.stringify(secretPath)};`,
    );
    const modulePath = join(directory, "probe.mjs");
    await writeFile(modulePath, isolated, { mode: 0o600 });
    const guest = await import(`${pathToFileURL(modulePath).href}?test=${Date.now()}`);
    const result = await guest.secretQueryName(secretPath, nonce, zone) as Record<string, unknown>;
    const queryName = String(result.queryName);
    expect(queryName.split(".")[0]).toHaveLength(59);
    expect(queryName).toMatch(new RegExp(`^s[a-z2-7]{26}${nonce}\\.${zone.replaceAll(".", "\\.")}$`, "u"));
    expect(result).toMatchObject({ secretFileMode: 0o600, secretBytes: 16, secretEncodedInOneLabel: true });
  });

  it("requires the exact ownership confirmation in every guest configuration", async () => {
    // @ts-expect-error standalone guest intentionally has no declaration file
    const guest = await import("../guest/dns-authoritative-probe.mjs");
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
    const common = {
      scopeConfirmation: SBX001_DIRECT_SCOPE_CONFIRMATION,
      runId: randomUUID(),
      testId: SBX001_DIRECT_TEST_ID,
      mode: "dns",
      caseId: "allow-public",
      authoritativeZone: zone,
      queryNonce: nonce,
      timeoutMs: 2_500,
    };
    expect(guest.parseConfiguration(encode(common))).toMatchObject({ caseId: "allow-public" });
    expect(() => guest.parseConfiguration(encode({ ...common, scopeConfirmation: "wrong" }))).toThrow(/scope/u);
    expect(() => guest.parseConfiguration(encode({ ...common, secretFilePath: "/tmp/secret" }))).toThrow(/public DNS case/u);
  });

  it("does not invent kernel acceptance when the UDP send callback never completes", async () => {
    // @ts-expect-error standalone guest intentionally has no declaration file
    const guest = await import("../guest/dns-authoritative-probe.mjs");
    class NeverCompletingSocket extends EventEmitter {
      send(): void {}
      close(): void {}
    }
    const result = await guest.sendDnsOnce({
      resolverAddress: "127.0.0.1",
      queryName: `a${nonce}.${zone}`,
      timeoutMs: 500,
      socketFactory: () => new NeverCompletingSocket(),
    }) as Record<string, unknown>;
    expect(result).toMatchObject({
      sendInvoked: true,
      datagramAcceptedByKernel: false,
      responseReceived: false,
      timedOut: true,
    });
  });
});
