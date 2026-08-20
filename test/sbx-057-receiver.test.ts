import { createServer, request } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import {
  SBX057_CASES,
  SBX057_TEST_ID,
  SBX057_TRANSFORM_HEADER,
  casePath,
  secretCommitment,
  type Sbx057CaseId,
} from "../pocs/SBX-057/protocol.js";
import {
  createSbx057Receiver,
  parseSbx057ReceiverConfiguration,
  type Sbx057ReceiverHandle,
} from "../pocs/SBX-057/receiver.js";

const RUN = "123e4567-e89b-42d3-a456-426614174000";
const A = new URL("https://a-sbx057.trycloudflare.com");
const B = new URL("https://b-sbx057.trycloudflare.com");
const ADMIN = "A".repeat(43);
const ACTION = "B".repeat(43);
const COMPARATOR_SECRET = "comparator-controller-only";
const TARGET_SECRET = "target-controller-only";
const CANARIES = Object.fromEntries(SBX057_CASES.map((caseId, index) => [
  caseId, `s57_${caseId}_${String.fromCharCode(65 + index).repeat(22)}`,
])) as Record<Sbx057CaseId, string>;

async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("port allocation failed");
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return address.port;
}

async function call(port: number, path: string, method = "GET", headers: Record<string, string> = {},
  body?: unknown): Promise<{ status: number; body: Record<string, unknown> }> {
  const payload = body === undefined ? undefined : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = request({ hostname: "127.0.0.1", port, path, method, headers: {
      ...headers,
      ...(payload === undefined ? {} : { "content-type": "application/json", "content-length": String(Buffer.byteLength(payload)) }),
    } }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      response.on("end", () => resolve({
        status: response.statusCode ?? 0,
        body: JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>,
      }));
    });
    req.on("error", reject);
    if (payload !== undefined) req.end(payload);
    else req.end();
  });
}

function configuration() {
  return {
    testId: SBX057_TEST_ID,
    runId: RUN,
    aHostname: A.hostname,
    bHostname: B.hostname,
    comparatorCommitment: secretCommitment(ACTION, RUN, "comparator", COMPARATOR_SECRET),
    targetCommitment: secretCommitment(ACTION, RUN, "target", TARGET_SECRET),
    cases: SBX057_CASES.map((caseId) => ({ caseId, canary: CANARIES[caseId] })),
  };
}

function probeHeaders(caseId: Sbx057CaseId, hostname: string, secret?: string): Record<string, string> {
  return {
    host: hostname,
    "x-sbx057-run": RUN,
    "x-sbx057-case": caseId,
    "x-sbx057-canary": CANARIES[caseId],
    ...(secret === undefined ? {} : { [SBX057_TRANSFORM_HEADER]: secret }),
  };
}

let receiver: Sbx057ReceiverHandle | undefined;

afterEach(async () => {
  await receiver?.close();
  receiver = undefined;
});

async function start(): Promise<Sbx057ReceiverHandle> {
  receiver = await createSbx057Receiver({
    adminKey: ADMIN, actionKey: ACTION, aOrigin: A, bOrigin: B,
    aPort: await freePort(), bPort: await freePort(), adminPort: await freePort(),
  });
  const created = await call(receiver.adminPort, `/v1/sbx057/admin/runs/${RUN}`, "POST", {
    authorization: `Bearer ${ADMIN}`,
  }, configuration());
  expect(created.status).toBe(201);
  return receiver;
}

describe("SBX-057 receiver", () => {
  it("accepts only the exact two-host, four-case configuration", () => {
    expect(parseSbx057ReceiverConfiguration(configuration())).toMatchObject({ runId: RUN });
    expect(() => parseSbx057ReceiverConfiguration({ ...configuration(), bHostname: A.hostname })).toThrow();
    const duplicate = configuration();
    duplicate.cases[1]!.canary = duplicate.cases[0]!.canary;
    expect(() => parseSbx057ReceiverConfiguration(duplicate)).toThrow();
  });

  it("records comparator A action and ordinary direct B isolation without raw secrets", async () => {
    const handle = await start();
    const a = await call(handle.aPort, casePath(RUN, "comparator-a"), "GET",
      probeHeaders("comparator-a", A.hostname, COMPARATOR_SECRET));
    const b = await call(handle.bPort, casePath(RUN, "comparator-b"), "GET",
      probeHeaders("comparator-b", B.hostname));
    expect(a).toMatchObject({ status: 200, body: { ok: true, role: "A" } });
    expect(b).toMatchObject({ status: 202, body: { ok: true, role: "B" } });
    const snapshot = await call(handle.adminPort, `/v1/sbx057/admin/runs/${RUN}`, "GET", {
      authorization: `Bearer ${ADMIN}`,
    });
    expect(snapshot.body.events).toHaveLength(2);
    expect(snapshot.body).toMatchObject({ unexpectedIngressCount: 0, unattributedIngressCount: 0, rawSecretsRetained: false });
    expect(JSON.stringify(snapshot.body)).not.toContain(COMPARATOR_SECRET);
    expect(JSON.stringify(snapshot.body)).not.toContain(TARGET_SECRET);
  });

  it("distinguishes a target-B credential leak from clean B reachability", async () => {
    const handle = await start();
    await call(handle.aPort, casePath(RUN, "target-a"), "GET", probeHeaders("target-a", A.hostname, TARGET_SECRET));
    const clean = await call(handle.bPort, casePath(RUN, "target-b"), "GET", probeHeaders("target-b", B.hostname));
    expect(clean.status).toBe(202);
  });

  it("returns a keyed nonreflecting action for the exact target secret at B", async () => {
    const handle = await start();
    const response = await call(handle.bPort, casePath(RUN, "target-b"), "GET",
      probeHeaders("target-b", B.hostname, TARGET_SECRET));
    expect(response.status).toBe(200);
    expect(response.body.operationId).toMatch(/^s57op_/u);
    expect(JSON.stringify(response.body)).not.toContain(TARGET_SECRET);
  });

  it("rejects a cross-stage secret and marks the cross commitment", async () => {
    const handle = await start();
    const response = await call(handle.bPort, casePath(RUN, "target-b"), "GET",
      probeHeaders("target-b", B.hostname, COMPARATOR_SECRET));
    expect(response.status).toBe(409);
    const snapshot = await call(handle.adminPort, `/v1/sbx057/admin/runs/${RUN}`, "GET", {
      authorization: `Bearer ${ADMIN}`,
    });
    expect((snapshot.body.events as Array<Record<string, unknown>>)[0]).toMatchObject({
      transformCommitmentMatched: false, crossCommitmentMatched: true,
    });
  });

  it("counts correlated wrong-path ingress before returning 400", async () => {
    const handle = await start();
    const response = await call(handle.bPort, "/rewritten", "GET", probeHeaders("target-b", B.hostname));
    expect(response.status).toBe(400);
    const snapshot = await call(handle.adminPort, `/v1/sbx057/admin/runs/${RUN}`, "GET", {
      authorization: `Bearer ${ADMIN}`,
    });
    expect(snapshot.body.unexpectedIngressCount).toBe(1);
    expect((snapshot.body.events as Array<Record<string, unknown>>)[0]).toMatchObject({ kind: "unexpected", pathMatched: false });
  });

  it("counts ingress with no exact run attribution", async () => {
    const handle = await start();
    const response = await call(handle.aPort, "/unknown", "GET", { host: A.hostname });
    expect(response.status).toBe(404);
    const snapshot = await call(handle.adminPort, `/v1/sbx057/admin/runs/${RUN}`, "GET", {
      authorization: `Bearer ${ADMIN}`,
    });
    expect(snapshot.body.unattributedIngressCount).toBe(1);
  });

  it("deletes run state and proves repeated absence", async () => {
    const handle = await start();
    expect((await call(handle.adminPort, `/v1/sbx057/admin/runs/${RUN}`, "DELETE", {
      authorization: `Bearer ${ADMIN}`,
    })).status).toBe(200);
    expect((await call(handle.adminPort, `/v1/sbx057/admin/runs/${RUN}`, "GET", {
      authorization: `Bearer ${ADMIN}`,
    })).status).toBe(404);
  });
});
