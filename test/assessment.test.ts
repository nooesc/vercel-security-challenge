import { describe, expect, it } from "vitest";
import { assessTest } from "../src/assessment.js";
import type { BuiltTest, ObserverEvent, ProbeCase } from "../src/contracts.js";

const canary = "sbx_unit_test_canary";
const canaryHeader = "x-sbx-harness-canary";

function probe(overrides: Partial<ProbeCase> = {}): ProbeCase {
  return {
    id: "case-1",
    description: "test probe",
    method: "GET",
    rawPath: "/v1/probe/run-1/case-1",
    expectedNetwork: "hit",
    expectedCanary: "ignore",
    ...overrides,
  };
}

function built(cases: ProbeCase[]): BuiltTest {
  return { policy: "allow-all", cases };
}

function event(
  caseId: string,
  headers: Record<string, string | string[]> = {},
): ObserverEvent {
  return {
    schemaVersion: 1,
    observedAt: "2026-08-18T12:00:00.000Z",
    runId: "run-1",
    testId: "TEST-001",
    caseId,
    canary: "request-correlation-canary",
    method: "GET",
    rawUrl: `https://observer.example/v1/probe/run-1/${caseId}`,
    normalizedPath: `/v1/probe/run-1/${caseId}`,
    headers,
    rawHeaders: [],
    bodyLength: 0,
    bodySha256: "0".repeat(64),
  };
}

describe("assessTest", () => {
  it("passes when all positive controls arrive with their expected brokered canary", () => {
    const result = assessTest(
      built([
        probe({ id: "network-control" }),
        probe({ id: "broker-control", expectedCanary: "present" }),
      ]),
      [
        event("network-control"),
        event("broker-control", { "X-SBX-Harness-Canary": canary }),
      ],
      canary,
      canaryHeader,
    );

    expect(result.verdict).toBe("pass");
    expect(result.signals).toEqual(["no contradictory boundary signal observed"]);
  });

  it("marks an observer hit that policy should block as a candidate", () => {
    const result = assessTest(
      built([probe({ id: "blocked-case", expectedNetwork: "blocked" })]),
      [event("blocked-case")],
      canary,
      canaryHeader,
    );

    expect(result.verdict).toBe("candidate");
    expect(result.signals).toContain(
      "blocked-case: observer recorded 1 request(s) that policy should block",
    );
  });

  it("marks a brokered canary outside its transform rule as a candidate", () => {
    const result = assessTest(
      built([probe({ id: "outside-rule", expectedCanary: "absent" })]),
      [event("outside-rule", { [canaryHeader]: [`prefix-${canary}-suffix`] })],
      canary,
      canaryHeader,
    );

    expect(result.verdict).toBe("candidate");
    expect(result.signals).toContain(
      "outside-rule: observer received a canary on a request outside the transform rule",
    );
  });

  it("is indeterminate when a required network control is missing", () => {
    const result = assessTest(
      built([probe({ id: "missing-control" })]),
      [],
      canary,
      canaryHeader,
    );

    expect(result.verdict).toBe("indeterminate");
    expect(result.signals).toContain(
      "missing-control: positive-control request did not reach the observer",
    );
  });

  it("is indeterminate when a credential-brokering control arrives without the canary", () => {
    const result = assessTest(
      built([probe({ id: "missing-canary", expectedCanary: "present" })]),
      [event("missing-canary")],
      canary,
      canaryHeader,
    );

    expect(result.verdict).toBe("indeterminate");
    expect(result.signals).toContain(
      "missing-canary: credential-brokering control did not contain the injected canary",
    );
  });
});
