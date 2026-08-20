import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { Sandbox } from "@vercel/sandbox";
import { describe, expect, it } from "vitest";
import {
  RequestGate,
  SBX057_FIXED_GUEST_SHA256,
  classifySbx057Comparator,
  exactSbx057CreateProvenance,
  parseSbx057ReceiverSnapshot,
  sanitizeSbx057SessionPolicy,
  sanitizeSbx057TopPolicy,
  sbx057CreateParameters,
  sbx057Policy,
} from "../pocs/SBX-057/wildcard-empty-isolation.js";
import {
  SBX057_REDACTED_VALUE,
  SBX057_TEST_ID,
  SBX057_TRANSFORM_HEADER,
  expectedOperationId,
  expectedReceipt,
  secretCommitment,
} from "../pocs/SBX-057/protocol.js";
import { createSbx057Journal } from "../pocs/SBX-057/safety.js";
import { SBX057_PROJECT, SBX057_TEAM } from "../pocs/SBX-057/safety.js";
import type { Sbx057ProbeEvidence } from "../pocs/SBX-057/verdict.js";

const RUN = "123e4567-e89b-42d3-a456-426614174000";
const A = "a-sbx057.trycloudflare.com";
const B = "b-sbx057.trycloudflare.com";
const SECRET = "controller-only-secret";
const ACTION = "B".repeat(43);
const ADMIN = "A".repeat(43);
const CA = `s57_comparator-a_${"A".repeat(22)}`;
const CB = `s57_comparator-b_${"B".repeat(22)}`;
const COMMITMENT = secretCommitment(ACTION, RUN, "comparator", SECRET);
const OP_A = expectedOperationId(ACTION, RUN, "comparator-a", CA, COMMITMENT);
const OP_B = expectedOperationId(ACTION, RUN, "comparator-b", CB, COMMITMENT);

function sessionPolicy(other: string, value: string = SBX057_REDACTED_VALUE): unknown {
  return { allow: {
    [A]: [{ transform: [{ headers: { [SBX057_TRANSFORM_HEADER]: value } }] }],
    [other]: [],
  } };
}

describe("SBX-057 controller contracts", () => {
  it("builds the exact comparator and wildcard target policies", () => {
    expect(sbx057Policy("comparator", A, B, SECRET)).toEqual({ allow: {
      [A]: [{ transform: [{ headers: { [SBX057_TRANSFORM_HEADER]: SECRET } }] }],
      [B]: [],
    } });
    expect(sbx057Policy("target", A, B, SECRET)).toEqual({ allow: {
      [A]: [{ transform: [{ headers: { [SBX057_TRANSFORM_HEADER]: SECRET } }] }],
      "*": [],
    } });
  });

  it("creates nonpersistent zero-port, zero-env resources with exact tags", () => {
    const params = sbx057CreateParameters({ token: "offline", teamId: SBX057_TEAM, projectId: SBX057_PROJECT },
      new RequestGate(), "target", RUN, A, B, SECRET);
    expect(params).toMatchObject({
      name: `sbx-057-target-${RUN}`, persistent: false, timeout: 180_000,
      ports: [], env: {}, tags: { harness: "vsc", test: SBX057_TEST_ID, run: RUN, role: "target" },
    });
    expect(params.networkPolicy).toEqual(sbx057Policy("target", A, B, SECRET));
  });

  it("accepts only exact top-level host-list projections", () => {
    expect(sanitizeSbx057TopPolicy({ allow: [A, "*"] }, A, "*")).toEqual({ allow: [A, "*"] });
    expect(() => sanitizeSbx057TopPolicy({ allow: [A] }, A, "*")).toThrow();
    expect(() => sanitizeSbx057TopPolicy({ allow: { [A]: [], "*": [] } }, A, "*")).toThrow();
    expect(() => sanitizeSbx057TopPolicy({ allow: [A, "*"], subnets: {} }, A, "*")).toThrow();
  });

  it("sanitizes only the exact A-transform plus exact empty comparator/wildcard entry", () => {
    expect(sanitizeSbx057SessionPolicy(sessionPolicy("*", SECRET), A, "*", SECRET)).toEqual(sessionPolicy("*"));
    expect(sanitizeSbx057SessionPolicy(sessionPolicy(B), A, B, SECRET)).toEqual(sessionPolicy(B));
    expect(() => sanitizeSbx057SessionPolicy(sessionPolicy("*", "wrong"), A, "*", SECRET)).toThrow();
    expect(() => sanitizeSbx057SessionPolicy({ allow: {
      [A]: [{ transform: [{ headers: { [SBX057_TRANSFORM_HEADER]: SECRET } }] }],
      "*": [{ transform: [{ headers: { extra: "value" } }] }],
    } }, A, "*", SECRET)).toThrow();
  });

  it("requires canonical session/name/tag/nonpersistent create provenance", () => {
    const journal = createSbx057Journal(new Date(), RUN);
    const resource = journal.resources[0];
    const sandbox = {
      name: resource.name,
      persistent: false,
      tags: resource.tags,
      createdAt: new Date(),
      currentSession: () => ({ sessionId: `sbx_${"a".repeat(24)}` }),
    } as unknown as Sandbox;
    expect(exactSbx057CreateProvenance(sandbox, journal, resource)).toBe(true);
    expect(exactSbx057CreateProvenance({ ...sandbox, persistent: true } as unknown as Sandbox,
      journal, resource)).toBe(false);
    expect(exactSbx057CreateProvenance({ ...sandbox, tags: { ...resource.tags, extra: "x" } } as unknown as Sandbox,
      journal, resource)).toBe(false);
  });

  it("parses only exhaustive receiver snapshots with exact sequence", () => {
    const value = {
      schemaVersion: 1, testId: SBX057_TEST_ID, runId: RUN,
      configuredAt: "2026-08-19T00:00:00.000Z", configurationValid: true,
      rawSecretsRetained: false, unexpectedIngressCount: 0, unattributedIngressCount: 0,
      events: [{
        sequence: 1, observedAt: "2026-08-19T00:00:01.000Z", kind: "expected", role: "B",
        caseId: "target-b", method: "GET", hostMatched: true, pathMatched: true,
        correlationHeadersExact: true, transformHeaderLines: 0, transformHeaderValues: 0,
        transformCommitmentMatched: false, crossCommitmentMatched: false, responseStatus: 202,
      }],
    };
    expect(parseSbx057ReceiverSnapshot(value).events).toHaveLength(1);
    expect(() => parseSbx057ReceiverSnapshot({ ...value, extra: true })).toThrow();
    const wrongSequence = structuredClone(value);
    wrongSequence.events[0]!.sequence = 2;
    expect(() => parseSbx057ReceiverSnapshot(wrongSequence)).toThrow();
  });

  it("classifies comparator clean/leak only with exact keyed receipts", () => {
    const receiptA = expectedReceipt(ADMIN, RUN, 1, "comparator-a", CA, "A", 1, true, false, 200, OP_A);
    const receiptNone = expectedReceipt(ADMIN, RUN, 2, "comparator-b", CB, "B", 0, false, false, 202);
    const receiptLeak = expectedReceipt(ADMIN, RUN, 2, "comparator-b", CB, "B", 1, true, false, 200, OP_B);
    const expected = {
      commitments: { comparator: COMMITMENT, target: secretCommitment(ACTION, RUN, "target", "other") },
      operationIds: { "comparator-a": OP_A, "comparator-b": OP_B, "target-a": "unused", "target-b": "unused" },
      receipts: { comparatorAAction: receiptA, comparatorBNone: receiptNone, comparatorBAction: receiptLeak,
        targetAAction: "unused", targetBNone: "unused", targetBAction: "unused" },
    };
    const event = (leak: boolean) => ({
      schemaVersion: 1 as const, testId: SBX057_TEST_ID, runId: RUN,
      configuredAt: "2026-08-19T00:00:00.000Z", configurationValid: true as const,
      rawSecretsRetained: false as const, unexpectedIngressCount: 0, unattributedIngressCount: 0,
      events: [
        { sequence: 1, observedAt: "2026-08-19T00:00:01.000Z", kind: "expected" as const, role: "A" as const,
          caseId: "comparator-a" as const, method: "GET", hostMatched: true, pathMatched: true,
          correlationHeadersExact: true, transformHeaderLines: 1, transformHeaderValues: 1,
          transformCommitmentMatched: true, crossCommitmentMatched: false, responseStatus: 200,
          receipt: receiptA, operationId: OP_A },
        { sequence: 2, observedAt: "2026-08-19T00:00:02.000Z", kind: "expected" as const, role: "B" as const,
          caseId: "comparator-b" as const, method: "GET", hostMatched: true, pathMatched: true,
          correlationHeadersExact: true, transformHeaderLines: leak ? 1 : 0, transformHeaderValues: leak ? 1 : 0,
          transformCommitmentMatched: leak, crossCommitmentMatched: false, responseStatus: leak ? 200 : 202,
          receipt: leak ? receiptLeak : receiptNone, ...(leak ? { operationId: OP_B } : {}) },
      ],
    });
    const probes = (leak: boolean) => ({
      "comparator-a": { responseStatusCode: 200, responseReceipt: receiptA, responseOperationId: OP_A },
      "comparator-b": { responseStatusCode: leak ? 200 : 202,
        responseReceipt: leak ? receiptLeak : receiptNone, ...(leak ? { responseOperationId: OP_B } : {}) },
    }) as unknown as Partial<Record<"comparator-a" | "comparator-b", Sbx057ProbeEvidence>>;
    expect(classifySbx057Comparator(event(false), probes(false), expected)).toBe("clean");
    expect(classifySbx057Comparator(event(true), probes(true), expected)).toBe("leak");
    const wrong = event(true);
    wrong.events[1]!.crossCommitmentMatched = true;
    expect(classifySbx057Comparator(wrong, probes(true), expected)).toBe("invalid");
  });

  it("pins the guest digest and installed SDK wildcard/projection source semantics", async () => {
    const guest = await readFile(resolve("guest/sbx-057-wildcard-empty-probe.mjs"), "utf8");
    expect(createHash("sha256").update(guest).digest("hex")).toBe(SBX057_FIXED_GUEST_SHA256);
    const declarations = await readFile(resolve("node_modules/@vercel/sandbox/dist/network-policy.d.ts"), "utf8");
    const serializer = await readFile(resolve("node_modules/@vercel/sandbox/dist/utils/network-policy.js"), "utf8");
    expect(declarations).toContain('"*": []');
    expect(serializer).toContain("for (const rule of api.injectionRules ?? [])");
    expect(serializer).toContain("rulesByDomain.get(rule.domain) ?? []");
  });

  it("is import-safe and makes no calls without explicit main execution", async () => {
    const moduleUrl = pathToFileURL(resolve("pocs/SBX-057/wildcard-empty-isolation.ts")).href;
    await expect(import(`${moduleUrl}?import-safe=${Date.now()}`)).resolves.toBeDefined();
  });
});
