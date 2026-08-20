import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { isIP } from "node:net";
import { pathToFileURL } from "node:url";
import {
  SBX057_CANARY,
  SBX057_CASES,
  SBX057_COMMITMENT,
  SBX057_TEST_ID,
  SBX057_TRANSFORM_HEADER,
  SBX057_RUN_HEADER,
  SBX057_CASE_HEADER,
  SBX057_CANARY_HEADER,
  SBX057_UUID,
  casePath,
  expectedOperationId,
  expectedReceipt,
  isSbx057CaseId,
  roleForCase,
  safeEqual,
  secretCommitment,
  stageForCase,
  type Sbx057CaseId,
  type Sbx057Role,
} from "./protocol.js";

const MAX_BODY = 16_384;
const MAX_EVENTS = 32;

export interface Sbx057ReceiverCaseConfiguration {
  caseId: Sbx057CaseId;
  canary: string;
}

export interface Sbx057ReceiverConfiguration {
  testId: typeof SBX057_TEST_ID;
  runId: string;
  aHostname: string;
  bHostname: string;
  comparatorCommitment: string;
  targetCommitment: string;
  cases: Sbx057ReceiverCaseConfiguration[];
}

export interface Sbx057ReceiverEvent {
  sequence: number;
  observedAt: string;
  kind: "expected" | "unexpected";
  role: Sbx057Role;
  caseId: Sbx057CaseId | "unknown";
  method: string;
  hostMatched: boolean;
  pathMatched: boolean;
  correlationHeadersExact: boolean;
  transformHeaderLines: number;
  transformHeaderValues: number;
  transformCommitmentMatched: boolean;
  crossCommitmentMatched: boolean;
  responseStatus: number;
  receipt?: string;
  operationId?: string;
}

export interface Sbx057ReceiverSnapshot {
  schemaVersion: 1;
  testId: typeof SBX057_TEST_ID;
  runId: string;
  configuredAt: string;
  configurationValid: true;
  rawSecretsRetained: false;
  unexpectedIngressCount: number;
  unattributedIngressCount: number;
  events: Sbx057ReceiverEvent[];
}

interface RunState {
  configuration: Sbx057ReceiverConfiguration;
  configuredAt: string;
  unexpectedIngressCount: number;
  unattributedIngressCount: number;
  events: Sbx057ReceiverEvent[];
}

export interface Sbx057ReceiverOptions {
  adminKey: string;
  actionKey: string;
  aOrigin: URL;
  bOrigin: URL;
  aPort: number;
  bPort: number;
  adminPort: number;
  host?: string;
  adminHost?: string;
}

export interface Sbx057ReceiverHandle {
  aPort: number;
  bPort: number;
  adminPort: number;
  close(): Promise<void>;
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function exactKeys(value: object, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function exactHostname(value: unknown): value is string {
  return typeof value === "string" && value.length <= 253 && value === value.toLowerCase() &&
    !value.endsWith(".") && value.endsWith(".trycloudflare.com") && isIP(value) === 0;
}

function exactKey(value: string, name: string): string {
  if (Buffer.byteLength(value) < 32 || Buffer.byteLength(value) > 256 ||
      !/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error(`${name} must be one bounded opaque key`);
  return value;
}

function exactOrigin(value: URL, name: string): URL {
  if (value.protocol !== "https:" || value.port !== "" || value.username !== "" ||
      value.password !== "" || value.pathname !== "/" || value.search !== "" ||
      value.hash !== "" || !exactHostname(value.hostname) || value.origin !== value.toString().replace(/\/$/u, "")) {
    throw new Error(`${name} must be one canonical Quick Tunnel HTTPS origin`);
  }
  return value;
}

function exactPort(value: number, name: string): number {
  if (!Number.isInteger(value) || value < 1 || value > 65_535) throw new Error(`${name} was invalid`);
  return value;
}

export function parseSbx057ReceiverConfiguration(value: unknown): Sbx057ReceiverConfiguration {
  const root = object(value);
  if (root === undefined || !exactKeys(root, [
    "testId", "runId", "aHostname", "bHostname", "comparatorCommitment", "targetCommitment", "cases",
  ]) || root.testId !== SBX057_TEST_ID || typeof root.runId !== "string" || !SBX057_UUID.test(root.runId) ||
      !exactHostname(root.aHostname) || !exactHostname(root.bHostname) || root.aHostname === root.bHostname ||
      typeof root.comparatorCommitment !== "string" || !SBX057_COMMITMENT.test(root.comparatorCommitment) ||
      typeof root.targetCommitment !== "string" || !SBX057_COMMITMENT.test(root.targetCommitment) ||
      root.comparatorCommitment === root.targetCommitment || !Array.isArray(root.cases) ||
      root.cases.length !== SBX057_CASES.length) {
    throw new Error("SBX-057 receiver configuration was not exact");
  }
  const cases = root.cases.map((entry, index): Sbx057ReceiverCaseConfiguration => {
    const item = object(entry);
    const expectedCase = SBX057_CASES[index]!;
    if (item === undefined || !exactKeys(item, ["caseId", "canary"]) || item.caseId !== expectedCase ||
        typeof item.canary !== "string" || !SBX057_CANARY.test(item.canary)) {
      throw new Error("SBX-057 receiver case configuration was not exact");
    }
    return { caseId: expectedCase, canary: item.canary };
  });
  if (new Set(cases.map((entry) => entry.canary)).size !== cases.length) {
    throw new Error("SBX-057 receiver canaries were not distinct");
  }
  return {
    testId: SBX057_TEST_ID,
    runId: root.runId,
    aHostname: root.aHostname,
    bHostname: root.bHostname,
    comparatorCommitment: root.comparatorCommitment,
    targetCommitment: root.targetCommitment,
    cases,
  };
}

function singleHeader(request: IncomingMessage, name: string): string | undefined {
  const values: string[] = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === name) values.push(request.rawHeaders[index + 1] ?? "");
  }
  return values.length === 1 ? values[0] : undefined;
}

function rawHeaderValues(request: IncomingMessage, name: string): string[] {
  const output: string[] = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === name) output.push(request.rawHeaders[index + 1] ?? "");
  }
  return output;
}

function json(response: ServerResponse, status: number, value: unknown, headers: Record<string, string> = {}): void {
  const body = `${JSON.stringify(value)}\n`;
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(Buffer.byteLength(body)),
    "cache-control": "no-store",
    ...headers,
  });
  response.end(body);
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk);
    length += bytes.length;
    if (length > MAX_BODY) throw new Error("SBX-057 request body exceeded its bound");
    chunks.push(bytes);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function snapshot(state: RunState): Sbx057ReceiverSnapshot {
  return {
    schemaVersion: 1,
    testId: SBX057_TEST_ID,
    runId: state.configuration.runId,
    configuredAt: state.configuredAt,
    configurationValid: true,
    rawSecretsRetained: false,
    unexpectedIngressCount: state.unexpectedIngressCount,
    unattributedIngressCount: state.unattributedIngressCount,
    events: state.events.map((event) => ({ ...event })),
  };
}

function listen(server: Server, port: number, host: string): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      const address = server.address();
      if (address === null || typeof address === "string") return reject(new Error("SBX-057 listener address failed"));
      resolve(address.port);
    });
  });
}

function close(server: Server): Promise<void> {
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

export async function createSbx057Receiver(options: Sbx057ReceiverOptions): Promise<Sbx057ReceiverHandle> {
  const adminKey = exactKey(options.adminKey, "SBX057_ADMIN_KEY");
  const actionKey = exactKey(options.actionKey, "SBX057_ACTION_KEY");
  if (adminKey === actionKey) throw new Error("SBX-057 receiver keys must be distinct");
  const aOrigin = exactOrigin(options.aOrigin, "SBX057_A_PUBLIC_ORIGIN");
  const bOrigin = exactOrigin(options.bOrigin, "SBX057_B_PUBLIC_ORIGIN");
  if (aOrigin.hostname === bOrigin.hostname) throw new Error("SBX-057 receiver requires distinct A and B origins");
  const aPort = exactPort(options.aPort, "SBX057_A_PORT");
  const bPort = exactPort(options.bPort, "SBX057_B_PORT");
  const adminPort = exactPort(options.adminPort, "SBX057_ADMIN_PORT");
  if (new Set([aPort, bPort, adminPort]).size !== 3) throw new Error("SBX-057 receiver ports must be distinct");
  const states = new Map<string, RunState>();

  const publicServer = (role: Sbx057Role): Server => createServer((request, response) => {
    void (async () => {
      const pathname = new URL(request.url ?? "/", "http://receiver.invalid").pathname;
      if (pathname === "/healthz" && request.method === "GET") {
        return json(response, 200, { ok: true, testId: SBX057_TEST_ID, role });
      }
      const runHeader = singleHeader(request, SBX057_RUN_HEADER);
      const state = runHeader === undefined ? undefined : states.get(runHeader);
      if (state === undefined) {
        for (const current of states.values()) current.unattributedIngressCount += 1;
        return json(response, 404, { ok: false });
      }
      if (state.events.length >= MAX_EVENTS) {
        state.unexpectedIngressCount += 1;
        return json(response, 429, { ok: false });
      }
      const caseRaw = singleHeader(request, SBX057_CASE_HEADER);
      const caseId = isSbx057CaseId(caseRaw) ? caseRaw : "unknown";
      const expected = caseId === "unknown"
        ? undefined
        : state.configuration.cases.find((entry) => entry.caseId === caseId);
      const expectedHost = role === "A" ? state.configuration.aHostname : state.configuration.bHostname;
      const canary = singleHeader(request, SBX057_CANARY_HEADER);
      const correlationHeadersExact = expected !== undefined && runHeader === state.configuration.runId &&
        caseRaw === expected.caseId && canary === expected.canary;
      const pathMatched = expected !== undefined && pathname === casePath(state.configuration.runId, expected.caseId);
      const hostMatched = singleHeader(request, "host") === expectedHost;
      const roleMatched = expected !== undefined && roleForCase(expected.caseId) === role;
      const methodMatched = request.method === "GET";
      const headerValues = rawHeaderValues(request, SBX057_TRANSFORM_HEADER);
      const currentCommitment = expected !== undefined && stageForCase(expected.caseId) === "comparator"
        ? state.configuration.comparatorCommitment
        : state.configuration.targetCommitment;
      const otherCommitment = currentCommitment === state.configuration.comparatorCommitment
        ? state.configuration.targetCommitment
        : state.configuration.comparatorCommitment;
      const observed = headerValues.length === 1 ? headerValues[0] : undefined;
      const observedCommitment = observed === undefined || expected === undefined
        ? undefined
        : secretCommitment(actionKey, state.configuration.runId, stageForCase(expected.caseId), observed);
      const otherObservedCommitment = observed === undefined || expected === undefined
        ? undefined
        : secretCommitment(
          actionKey,
          state.configuration.runId,
          stageForCase(expected.caseId) === "comparator" ? "target" : "comparator",
          observed,
        );
      const commitmentMatched = observedCommitment !== undefined && safeEqual(observedCommitment, currentCommitment);
      const crossCommitmentMatched = otherObservedCommitment !== undefined && safeEqual(otherObservedCommitment, otherCommitment);
      const shapeExact = correlationHeadersExact && pathMatched && hostMatched && roleMatched && methodMatched;
      const isA = role === "A";
      const status = !shapeExact ? 400
        : isA ? (commitmentMatched && headerValues.length === 1 ? 200 : 401)
        : headerValues.length === 0 ? 202
        : commitmentMatched && headerValues.length === 1 ? 200
        : 409;
      const operationId = status === 200 && commitmentMatched && expected !== undefined
        ? expectedOperationId(
          actionKey,
          state.configuration.runId,
          expected.caseId,
          expected.canary,
          currentCommitment,
        )
        : undefined;
      const sequence = state.events.length + 1;
      const receipt = expected === undefined || canary === undefined ? undefined : expectedReceipt(
        adminKey,
        state.configuration.runId,
        sequence,
        expected.caseId,
        canary,
        role,
        headerValues.length,
        commitmentMatched,
        crossCommitmentMatched,
        status,
        operationId,
      );
      const kind = shapeExact ? "expected" as const : "unexpected" as const;
      if (kind === "unexpected") state.unexpectedIngressCount += 1;
      state.events.push({
        sequence,
        observedAt: new Date().toISOString(),
        kind,
        role,
        caseId,
        method: request.method ?? "",
        hostMatched,
        pathMatched,
        correlationHeadersExact,
        transformHeaderLines: headerValues.length,
        transformHeaderValues: headerValues.length,
        transformCommitmentMatched: commitmentMatched,
        crossCommitmentMatched,
        responseStatus: status,
        ...(receipt === undefined ? {} : { receipt }),
        ...(operationId === undefined ? {} : { operationId }),
      });
      return json(response, status, {
        ok: status === 200 || status === 202,
        role,
        ...(receipt === undefined ? {} : { receipt }),
        ...(operationId === undefined ? {} : { operationId }),
      }, { "x-sbx057-role": role });
    })().catch(() => {
      if (!response.headersSent) json(response, 500, { ok: false });
      else response.destroy();
    });
  });

  const aServer = publicServer("A");
  const bServer = publicServer("B");
  const adminServer = createServer((request, response) => {
    void (async () => {
      if (request.socket.remoteAddress !== "127.0.0.1" && request.socket.remoteAddress !== "::ffff:127.0.0.1") {
        return json(response, 403, { ok: false });
      }
      if (singleHeader(request, "authorization") !== `Bearer ${adminKey}`) {
        return json(response, 403, { ok: false });
      }
      const match = new URL(request.url ?? "/", "http://admin.invalid").pathname
        .match(/^\/v1\/sbx057\/admin\/runs\/([0-9a-f-]+)$/u);
      if (!match?.[1] || !SBX057_UUID.test(match[1])) return json(response, 404, { ok: false });
      const runId = match[1];
      if (request.method === "POST") {
        if (states.has(runId)) return json(response, 409, { ok: false });
        const configuration = parseSbx057ReceiverConfiguration(await readJson(request));
        if (configuration.runId !== runId || configuration.aHostname !== aOrigin.hostname ||
            configuration.bHostname !== bOrigin.hostname) return json(response, 400, { ok: false });
        states.set(runId, {
          configuration,
          configuredAt: new Date().toISOString(),
          unexpectedIngressCount: 0,
          unattributedIngressCount: 0,
          events: [],
        });
        return json(response, 201, { ok: true, runId });
      }
      const state = states.get(runId);
      if (state === undefined) return json(response, 404, { ok: false });
      if (request.method === "GET") return json(response, 200, snapshot(state));
      if (request.method === "DELETE") {
        states.delete(runId);
        return json(response, 200, { ok: true, runId, deleted: true });
      }
      return json(response, 405, { ok: false });
    })().catch(() => {
      if (!response.headersSent) json(response, 500, { ok: false });
      else response.destroy();
    });
  });

  let boundA: number | undefined;
  let boundB: number | undefined;
  let boundAdmin: number | undefined;
  try {
    [boundA, boundB, boundAdmin] = await Promise.all([
      listen(aServer, aPort, options.host ?? "127.0.0.1"),
      listen(bServer, bPort, options.host ?? "127.0.0.1"),
      listen(adminServer, adminPort, options.adminHost ?? "127.0.0.1"),
    ]);
  } catch (error) {
    await Promise.allSettled([close(aServer), close(bServer), close(adminServer)]);
    throw error;
  }
  return {
    aPort: boundA,
    bPort: boundB,
    adminPort: boundAdmin,
    async close(): Promise<void> {
      await Promise.all([close(aServer), close(bServer), close(adminServer)]);
    },
  };
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function port(environment: NodeJS.ProcessEnv, name: string, fallback: number): number {
  const raw = environment[name];
  return exactPort(raw === undefined ? fallback : Number(raw), name);
}

export async function main(environment: NodeJS.ProcessEnv = process.env): Promise<void> {
  const handle = await createSbx057Receiver({
    adminKey: required(environment, "SBX057_ADMIN_KEY"),
    actionKey: required(environment, "SBX057_ACTION_KEY"),
    aOrigin: new URL(required(environment, "SBX057_A_PUBLIC_ORIGIN")),
    bOrigin: new URL(required(environment, "SBX057_B_PUBLIC_ORIGIN")),
    aPort: port(environment, "SBX057_A_PORT", 43157),
    bPort: port(environment, "SBX057_B_PORT", 43158),
    adminPort: port(environment, "SBX057_ADMIN_PORT", 43159),
    host: "127.0.0.1",
    adminHost: "127.0.0.1",
  });
  process.stdout.write(`${JSON.stringify({
    ready: true,
    testId: SBX057_TEST_ID,
    aPort: handle.aPort,
    bPort: handle.bPort,
    adminPort: handle.adminPort,
  })}\n`);
  await new Promise<void>((resolve) => {
    const stop = (): void => { void handle.close().finally(resolve); };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => {
    process.stderr.write("SBX-057 receiver failed without emitting raw state\n");
    process.exitCode = 1;
  });
}
