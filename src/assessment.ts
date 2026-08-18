import type {
  Assessment,
  BuiltTest,
  ObserverEvent,
} from "./contracts.js";

export function assessTest(
  built: BuiltTest,
  events: ObserverEvent[],
  canary: string,
  canaryHeader: string,
  options?: { allowControlRunId?: string },
): Assessment {
  const signals: string[] = [];
  let candidate = false;
  let indeterminate = false;

  for (const probe of built.cases) {
    const matching = events.filter((event) => event.caseId === probe.id);
    if (probe.expectedNetwork === "blocked" && matching.length > 0) {
      candidate = true;
      signals.push(`${probe.id}: observer recorded ${matching.length} request(s) that policy should block`);
    }
    if (probe.expectedNetwork === "hit" && matching.length === 0) {
      indeterminate = true;
      signals.push(`${probe.id}: positive-control request did not reach the observer`);
      continue;
    }

    if (probe.expectedCanary === "ignore" || matching.length === 0) continue;
    const observedValues = matching.flatMap((event) => {
      const entry = Object.entries(event.headers).find(
        ([name]) => name.toLowerCase() === canaryHeader.toLowerCase(),
      );
      if (!entry) return [];
      return Array.isArray(entry[1]) ? entry[1] : [entry[1]];
    });
    const canaryPresent = observedValues.some((value) => value.includes(canary));
    const onlyCanaryValues =
      observedValues.length > 0 &&
      observedValues.every((value) =>
        value.split(",").every((part) => part.trim() === canary),
      );

    if (probe.expectedCanary === "present" && !canaryPresent) {
      indeterminate = true;
      signals.push(`${probe.id}: credential-brokering control did not contain the injected canary`);
    }
    if (probe.expectedCanary === "present" && canaryPresent && !onlyCanaryValues) {
      candidate = true;
      signals.push(`${probe.id}: a guest-controlled value survived alongside the brokered canary`);
    }
    if (probe.expectedCanary === "absent" && canaryPresent) {
      candidate = true;
      signals.push(`${probe.id}: observer received a canary on a request outside the transform rule`);
    }
  }

  if (candidate) {
    return {
      verdict: "candidate",
      summary: "At least one independently observed boundary signal contradicted the configured policy.",
      signals,
    };
  }
  const hasInlinePositiveControl = built.cases.some(
    (probe) => probe.expectedNetwork === "hit",
  );
  if (!hasInlinePositiveControl && !options?.allowControlRunId) {
    return {
      verdict: "indeterminate",
      summary: "This negative-only test requires a successful allow-path control in the same harness process.",
      signals: [
        ...signals,
        "no prior CONTROL-ALLOW run was available to validate guest-to-observer reachability",
      ],
    };
  }
  if (!hasInlinePositiveControl && options?.allowControlRunId) {
    signals.push(`guest reachability validated by CONTROL-ALLOW run ${options.allowControlRunId}`);
  }
  if (indeterminate) {
    return {
      verdict: "indeterminate",
      summary: "A required positive control failed, so blocked requests cannot be interpreted safely.",
      signals,
    };
  }
  return {
    verdict: "pass",
    summary: "All positive controls arrived and no unexpected observer or canary signal was recorded.",
    signals: signals.length ? signals : ["no contradictory boundary signal observed"],
  };
}
