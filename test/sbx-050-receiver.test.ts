import { afterEach, describe, expect, it } from "vitest";
import {
  proxyAudience,
  requestPath,
  SBX050_EVENT_CASES,
  valueCommitment,
} from "../pocs/SBX-050/protocol.js";
import {
  createSbx050Receiver,
  receiverRuntimeAttestation,
  validateReceiverConfiguration,
  type Sbx050ReceiverHandle,
} from "../pocs/SBX-050/receiver.js";

const runId = "12345678-1234-4123-8123-123456789abc";
const aOrigin = new URL("https://a.example.test");
const pOrigin = new URL("https://p.example.test");
const actionKey = "action-key-".padEnd(40, "a");
const adminKey = "admin-key-".padEnd(40, "b");
const credential = `s50_${"c".repeat(43)}`;
const trigger = `t50_${"t".repeat(32)}`;
let handle: Sbx050ReceiverHandle | undefined;

function configuration() {
  return {
    runId,
    aHostname: aOrigin.hostname,
    forwardAudience: proxyAudience(pOrigin, runId),
    expectedTeamId: "team_abcdefghijklmno",
    expectedProjectId: "prj_abcdefghijklmno",
    expectedSessionId: "sbx_abcdefghijklmnopqrstuvwxyz",
    expectedSandboxName: "sbx050-owned-test",
    credentialCommitment: valueCommitment(actionKey, "credential", credential),
    hiddenTriggerCommitment: valueCommitment(actionKey, "trigger", trigger),
    cases: SBX050_EVENT_CASES.map((caseId, index) => {
      const canary = `c50_${String(index).padStart(24, "0")}`;
      return { caseId, canary, requestPath: requestPath(runId, caseId, canary) };
    }),
  };
}

afterEach(async () => {
  await handle?.close();
  handle = undefined;
});

describe("SBX-050 receiver", () => {
  it("accepts only the exact ordered five-event configuration", () => {
    expect(validateReceiverConfiguration(configuration(), runId, aOrigin, pOrigin)).toMatchObject({
      runId,
      aHostname: "a.example.test",
      forwardAudience: proxyAudience(pOrigin, runId),
    });
    const duplicate = configuration();
    duplicate.cases[4]!.canary = duplicate.cases[3]!.canary;
    duplicate.cases[4]!.requestPath = requestPath(runId, duplicate.cases[4]!.caseId, duplicate.cases[4]!.canary);
    expect(() => validateReceiverConfiguration(duplicate, runId, aOrigin, pOrigin)).toThrow(/exact, ordered, and unique/u);
    expect(() => validateReceiverConfiguration({ ...configuration(), rawCredential: credential }, runId, aOrigin, pOrigin)).toThrow();
  });

  it("creates, empty-reads, and deletes one local run without retaining hidden material", async () => {
    handle = await createSbx050Receiver({
      adminKey,
      actionKey,
      aPublicOrigin: aOrigin.origin,
      pPublicOrigin: pOrigin.origin,
      aPort: 0,
      pPort: 0,
    });
    const endpoint = `http://127.0.0.1:${handle.aPort}/v1/sbx050/admin/runs/${runId}`;
    const headers = { authorization: `Bearer ${adminKey}`, "content-type": "application/json" };
    const created = await fetch(endpoint, { method: "PUT", headers, body: JSON.stringify(configuration()) });
    expect(created.status).toBe(201);
    const initial = await created.json() as Record<string, unknown>;
    expect(initial).not.toHaveProperty("emptyReadAt");
    expect(JSON.stringify(initial)).not.toContain(credential);
    expect(JSON.stringify(initial)).not.toContain(trigger);

    const read = await fetch(endpoint, { headers: { authorization: `Bearer ${adminKey}` } });
    const ledger = await read.json() as Record<string, unknown>;
    expect(read.status).toBe(200);
    expect(ledger).toMatchObject({
      configured: true,
      events: [],
      unexpectedARequests: 0,
      unexpectedPRequests: 0,
      unattributedRequests: 0,
      rawCredentialRetained: false,
      credentialDigestRetained: false,
      rawHiddenTriggerRetained: false,
      hiddenTriggerDigestRetained: false,
      rawOidcTokenRetained: false,
      oidcTokenDigestRetained: false,
      receiverRuntimeTrustExact: true,
      receiverRuntimeTrustEnvironmentNames: [],
      receiverNodeOptionsPresent: false,
      receiverTlsVerificationDisabled: false,
    });
    expect(typeof ledger.emptyReadAt).toBe("string");

    const publicCase = configuration().cases[0]!;
    const unexpectedOidcAtA = await fetch(`http://127.0.0.1:${handle.aPort}${publicCase.requestPath}`, {
      headers: {
        "x-sbx050-run": runId,
        "x-sbx050-case": publicCase.caseId,
        "x-sbx050-canary": publicCase.canary,
        "vercel-sandbox-oidc-token": "synthetic-test-token",
      },
    });
    expect(unexpectedOidcAtA.status).toBe(200);
    const afterIngress = await fetch(endpoint, { headers: { authorization: `Bearer ${adminKey}` } });
    const afterLedger = await afterIngress.json() as { events: Array<Record<string, unknown>> };
    expect(afterLedger.events).toHaveLength(1);
    expect(afterLedger.events[0]).toMatchObject({ role: "A", oidcHeaderCount: 1, oidcOfficialVerified: false });

    expect((await fetch(`http://127.0.0.1:${handle.aPort}${publicCase.requestPath}`, {
      method: "POST",
      headers: {
        "x-sbx050-run": runId,
        "x-sbx050-case": publicCase.caseId,
        "x-sbx050-canary": publicCase.canary,
      },
    })).status).toBe(405);
    expect((await fetch(
      `http://127.0.0.1:${handle.pPort}/v1/sbx050/proxy/${runId}${publicCase.requestPath}`,
      {
        method: "POST",
        headers: {
          "x-sbx050-run": runId,
          "x-sbx050-case": publicCase.caseId,
          "x-sbx050-canary": publicCase.canary,
        },
      },
    )).status).toBe(405);

    const exactCorrelationHeaders = {
      "x-sbx050-run": runId,
      "x-sbx050-case": publicCase.caseId,
      "x-sbx050-canary": publicCase.canary,
    };
    expect((await fetch(`http://127.0.0.1:${handle.aPort}/v1/sbx050/rewritten`, {
      headers: exactCorrelationHeaders,
    })).status).toBe(400);
    expect((await fetch(`http://127.0.0.1:${handle.pPort}/v1/sbx050/rewritten`, {
      headers: exactCorrelationHeaders,
    })).status).toBe(404);
    expect((await fetch(`http://127.0.0.1:${handle.aPort}/healthz?wrong=1`, {
      headers: exactCorrelationHeaders,
    })).status).toBe(400);
    expect((await fetch(`http://127.0.0.1:${handle.pPort}/healthz?wrong=1`, {
      headers: exactCorrelationHeaders,
    })).status).toBe(404);
    expect((await fetch(`http://127.0.0.1:${handle.aPort}/healthz`, {
      headers: exactCorrelationHeaders,
    })).status).toBe(400);
    expect((await fetch(`http://127.0.0.1:${handle.pPort}/healthz`, {
      headers: exactCorrelationHeaders,
    })).status).toBe(404);
    expect((await fetch(`${endpoint}?wrong=1`, {
      headers: {
        ...exactCorrelationHeaders,
        authorization: `Bearer ${adminKey}`,
      },
    })).status).toBe(400);
    expect((await fetch(endpoint, {
      headers: {
        ...exactCorrelationHeaders,
        authorization: `Bearer ${adminKey}`,
      },
    })).status).toBe(400);
    const afterWrongMethods = await (await fetch(endpoint, {
      headers: { authorization: `Bearer ${adminKey}` },
    })).json() as Record<string, unknown>;
    expect(afterWrongMethods).toMatchObject({ unexpectedARequests: 6, unexpectedPRequests: 4 });

    expect((await fetch(endpoint, { method: "DELETE", headers: { authorization: `Bearer ${adminKey}` } })).status).toBe(204);
    expect((await fetch(endpoint, { headers: { authorization: `Bearer ${adminKey}` } })).status).toBe(404);
  });

  it("requires distinct strong admin/action keys and distinct owned origins", async () => {
    await expect(createSbx050Receiver({
      adminKey,
      actionKey: adminKey,
      aPublicOrigin: aOrigin.origin,
      pPublicOrigin: pOrigin.origin,
      aPort: 0,
      pPort: 0,
    })).rejects.toThrow(/distinct/u);
    await expect(createSbx050Receiver({
      adminKey,
      actionKey,
      aPublicOrigin: aOrigin.origin,
      pPublicOrigin: aOrigin.origin,
      aPort: 0,
      pPort: 0,
    })).rejects.toThrow(/distinct/u);
  });

  it("rejects receiver-process TLS trust and runtime injection without retaining values", () => {
    expect(receiverRuntimeAttestation({})).toEqual({
      receiverRuntimeTrustExact: true,
      receiverRuntimeTrustEnvironmentNames: [],
      receiverNodeOptionsPresent: false,
      receiverTlsVerificationDisabled: false,
    });
    for (const environment of [
      { NODE_TLS_REJECT_UNAUTHORIZED: "0" },
      { NODE_OPTIONS: "--require=/tmp/injected.cjs" },
      { NODE_EXTRA_CA_CERTS: "/tmp/custom.pem" },
      { NODE_USE_SYSTEM_CA: "1" },
      { OPENSSL_CONF: "/tmp/openssl.cnf" },
      { OPENSSL_MODULES: "/tmp/modules" },
      { SSL_CERT_DIR: "/tmp/certs" },
      { SSL_CERT_FILE: "/tmp/cert.pem" },
    ]) expect(() => receiverRuntimeAttestation(environment)).toThrow(/refuses TLS trust overrides/u);
  });
});
