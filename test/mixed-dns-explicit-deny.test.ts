import { describe, expect, it } from "vitest";
import {
  classifyMixedDns,
  parseMixedDnsEnvironment,
  type EpochAssessment,
  type MixedDnsAssessmentInput,
} from "../pocs/SBX-003-021/mixed-dns-explicit-deny.js";

function environment(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    SBX_MIXED_DNS_SCOPE_CONFIRMATION: "I_CONTROL_THE_HOSTNAME_AND_BOTH_IPV4S",
    SBX_MIXED_DNS_HOSTNAME: "rotate.researcher.test",
    SBX_MIXED_DNS_DENIED_IPV4: "203.0.113.10",
    SBX_MIXED_DNS_ALLOWED_IPV4: "203.0.113.11",
    OBSERVER_BASE_URL: "https://rotate.researcher.test",
    OBSERVER_ADMIN_KEY: "a".repeat(32),
    ...overrides,
  };
}

function epoch(overrides: Partial<EpochAssessment> = {}): EpochAssessment {
  return {
    symbol: "S",
    controllerConfirmed: true,
    guestLookupMatches: true,
    targetCrossed: false,
    targetBlocked: false,
    safeReached: true,
    ...overrides,
  };
}

function assessment(epochs: EpochAssessment[]): MixedDnsAssessmentInput {
  return {
    baselineControlsPassed: true,
    baselineCleanupPassed: true,
    fixedTargetBlocked: true,
    fixedSafeReached: true,
    denyCleanupPassed: true,
    observerConfigCleanupPassed: true,
    executionErrors: [],
    epochs,
  };
}

describe("SBX-003/SBX-021 mixed DNS discriminator", () => {
  it("requires exact controlled endpoints and a bounded rotating epoch plan", () => {
    const parsed = parseMixedDnsEnvironment(environment());
    expect(parsed.hostname).toBe("rotate.researcher.test");
    expect(parsed.deniedIPv4).toBe("203.0.113.10");
    expect(parsed.allowedIPv4).toBe("203.0.113.11");
    expect(parsed.epochPlan).toEqual(["S", "T", "S"]);
    expect(parsed.epochTimeoutMs).toBe(60_000);
    expect(parsed.dnsPollIntervalMs).toBe(1_000);
  });

  it("rejects an observer hostname or address pair outside the declaration", () => {
    expect(() => parseMixedDnsEnvironment(environment({
      OBSERVER_BASE_URL: "https://different.researcher.test",
    }))).toThrow(/declared researcher-owned HTTPS hostname/u);
    expect(() => parseMixedDnsEnvironment(environment({
      SBX_MIXED_DNS_ALLOWED_IPV4: "203.0.113.10",
    }))).toThrow(/must be different/u);
    expect(() => parseMixedDnsEnvironment(environment({
      SBX_MIXED_DNS_EPOCH_PLAN: "S,S",
    }))).toThrow(/including both S and T/u);
    expect(() => parseMixedDnsEnvironment(environment({
      SBX_MIXED_DNS_EPOCH_PLAN: "S,T,S,T",
      SBX_MIXED_DNS_EPOCH_TIMEOUT_MS: "60000",
    }))).toThrow(/at most 180000 ms/u);
  });

  it("classifies a denied-address event only when the full target epoch is conclusive", () => {
    const result = classifyMixedDns(assessment([
      epoch(),
      epoch({ symbol: "T", safeReached: false, targetCrossed: true }),
      epoch(),
    ]));
    expect(result).toBe("candidate");
  });

  it("classifies a clean target block and safe-edge reachability as pass", () => {
    const result = classifyMixedDns(assessment([
      epoch(),
      epoch({ symbol: "T", safeReached: false, targetBlocked: true }),
      epoch(),
    ]));
    expect(result).toBe("pass");
  });

  it("keeps remote-address signals indeterminate without action/lookup and cleanup controls", () => {
    expect(classifyMixedDns(assessment([
      epoch({ symbol: "T", safeReached: false, targetCrossed: true }),
    ]))).toBe("indeterminate");

    expect(classifyMixedDns(assessment([
      epoch(),
      epoch({
        symbol: "T",
        safeReached: false,
        guestLookupMatches: false,
        targetCrossed: true,
      }),
    ]))).toBe("indeterminate");

    expect(classifyMixedDns({
      ...assessment([
        epoch(),
        epoch({ symbol: "T", safeReached: false, targetCrossed: true }),
      ]),
      observerConfigCleanupPassed: false,
    })).toBe("indeterminate");
  });
});
