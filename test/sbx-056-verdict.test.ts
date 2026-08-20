import { describe, expect, it } from "vitest";
import {
  assessSbx056,
  assertSbx056EvidenceExcludesRawValues,
  type Sbx056AssessmentInput,
  type Sbx056Attempt,
} from "../pocs/SBX-056/verdict.js";

const AT = "2026-08-19T12:00:00.000Z";

function attempt(
  phase: Sbx056Attempt["phase"],
  actor: Sbx056Attempt["actor"],
  target: Sbx056Attempt["target"],
  exact = true,
): Sbx056Attempt {
  return {
    phase, actor, target, startedAt: AT, completedAt: AT, method: "POST",
    routeShapeExact: true, teamQueryExact: true, projectIdentifierSent: false,
    redirectMode: "error", transportCalls: 1, status: exact ? 200 : 403,
    contentType: exact ? "application/octet-stream" : "application/json",
    responseBytes: exact ? 64 : 80, exactExpectedMarker: exact,
    boundedAuthError: !exact, transportError: false,
  };
}

function input(): Sbx056AssessmentInput {
  return {
    runIdCanonical: true,
    sameEligibleTeam: true,
    controlProjectId: "prj_ControlProject1234567890",
    victimProjectId: "prj_VictimProject1234567890",
    authority: {
      ownerAliasExact: true,
      ownerTeamExact: true,
      ownerControlProjectExact: true,
      ownerVictimProjectExact: true,
      scopedControlProjectExact: true,
      scopedVictimProjectDenied: true,
      scopedVictimProjectStatus: 403,
      scopedTokenProjectRestrictionManuallyConfirmed: true,
      ownerAndScopedTokensDistinct: true,
    },
    provenance: {
      controlCreatedByOwner: true,
      victimCreatedByOwner: true,
      controlProjectExact: true,
      victimProjectExact: true,
      projectsDistinct: true,
      sessionsDistinct: true,
      namesAndTagsExact: true,
      nonpersistent: true,
      denyAll: true,
      zeroRoutes: true,
      fixedPathsExact: true,
      publicMarkerWrittenBeforeVictimMarker: true,
      victimMarkerStagedAfterPublicControl: true,
    },
    publicControl: attempt("public-control", "project-scoped", "control"),
    ownerVictimControl: attempt("owner-victim-control", "owner", "victim"),
    crossProject: attempt("cross-project", "project-scoped", "victim"),
    crossDispatchGatePassed: true,
    exactlyThreeReadRequests: true,
    minimumRequestIntervalPassed: true,
    chronologyExact: true,
    rawTokensOrMarkersRetained: false,
    cleanup: {
      controlStopped: true,
      controlDeleted: true,
      controlExactNameAbsent: true,
      controlPrefixAbsent: true,
      victimStopped: true,
      victimDeleted: true,
      victimExactNameAbsent: true,
      victimPrefixAbsent: true,
      journalCompleted: true,
      liveLockReleased: true,
    },
  };
}

describe("SBX-056 verdict", () => {
  it("classifies only the exact victim marker as the High-capable candidate", () => {
    expect(assessSbx056(input())).toEqual(expect.objectContaining({
      verdict: "cross-project-read-candidate", candidate: true, likelySeverity: "high",
    }));
  });

  it("passes only an exact bounded 403/404 authorization denial after both controls", () => {
    for (const status of [403, 404]) {
      const value = input();
      value.crossProject = { ...attempt("cross-project", "project-scoped", "victim", false), status };
      expect(assessSbx056(value)).toMatchObject({ verdict: "pass", candidate: false,
        likelySeverity: "none" });
    }
  });

  it("keeps 401, transport errors, other 2xx bodies, and malformed denials indeterminate", () => {
    const variants: Sbx056Attempt[] = [
      { ...attempt("cross-project", "project-scoped", "victim", false), status: 401 },
      { ...attempt("cross-project", "project-scoped", "victim", false), status: null,
        contentType: null, responseBytes: 0, boundedAuthError: false, transportError: true },
      { ...attempt("cross-project", "project-scoped", "victim", false), status: 200,
        contentType: "application/octet-stream", boundedAuthError: false },
      { ...attempt("cross-project", "project-scoped", "victim", false), boundedAuthError: false },
      { ...attempt("cross-project", "project-scoped", "victim", false), contentType: "other" },
    ];
    for (const crossProject of variants) {
      expect(assessSbx056({ ...input(), crossProject })).toMatchObject({
        verdict: "indeterminate", candidate: false,
      });
    }
  });

  it("fails closed on every authority gate", () => {
    for (const key of ["ownerAliasExact", "ownerTeamExact", "ownerControlProjectExact",
      "ownerVictimProjectExact", "scopedControlProjectExact", "scopedVictimProjectDenied",
      "scopedTokenProjectRestrictionManuallyConfirmed", "ownerAndScopedTokensDistinct"] as const) {
      const value = input();
      value.authority = { ...value.authority, [key]: false };
      expect(assessSbx056(value).verdict).toBe("indeterminate");
    }
    const wrongStatus = input();
    wrongStatus.authority = { ...wrongStatus.authority, scopedVictimProjectStatus: null };
    expect(assessSbx056(wrongStatus).verdict).toBe("indeterminate");
  });

  it("fails closed on every provenance gate", () => {
    for (const key of Object.keys(input().provenance) as (keyof Sbx056AssessmentInput["provenance"])[]) {
      const value = input();
      value.provenance = { ...value.provenance, [key]: false };
      expect(assessSbx056(value).verdict).toBe("indeterminate");
    }
  });

  it("fails closed on request, chronology, retention, and cleanup controls", () => {
    for (const key of ["runIdCanonical", "sameEligibleTeam", "crossDispatchGatePassed",
      "exactlyThreeReadRequests", "minimumRequestIntervalPassed", "chronologyExact"] as const) {
      expect(assessSbx056({ ...input(), [key]: false }).verdict).toBe("indeterminate");
    }
    for (const key of Object.keys(input().cleanup) as (keyof Sbx056AssessmentInput["cleanup"])[]) {
      const value = input();
      value.cleanup = { ...value.cleanup, [key]: false };
      expect(assessSbx056(value).verdict).toBe("indeterminate");
    }
  });

  it("rejects incoherent attempt identities, routes, status, content, and timing", () => {
    const mutations: Partial<Sbx056Attempt>[] = [
      { actor: "owner" }, { target: "control" }, { routeShapeExact: false },
      { teamQueryExact: false }, { redirectMode: "error", transportCalls: 2 as 1 },
      { startedAt: "invalid" }, { completedAt: "2026-08-19T11:59:59.000Z" },
      { responseBytes: 4_097 }, { status: 600 }, { contentType: "application/json" },
    ];
    for (const mutation of mutations) {
      const value = input();
      value.crossProject = { ...value.crossProject, ...mutation };
      expect(assessSbx056(value).verdict).toBe("indeterminate");
    }
  });

  it("allows sanitized booleans but rejects either raw token or marker recursively", () => {
    const token = "owner_token_ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const marker = "victim_marker_ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    expect(() => assertSbx056EvidenceExcludesRawValues({ exact: true }, [token, marker])).not.toThrow();
    expect(() => assertSbx056EvidenceExcludesRawValues({ nested: { token } }, [token])).toThrow();
    expect(() => assertSbx056EvidenceExcludesRawValues({ values: [marker] }, [marker])).toThrow();
    const escaped = "victim-marker-with-newline-and-quote-ABCDEFGHIJKLMNOPQRSTUVWXYZ\n\"\\tail";
    expect(JSON.stringify({ escaped })).not.toContain(escaped);
    expect(() => assertSbx056EvidenceExcludesRawValues({ escaped }, [escaped])).toThrow();
    expect(() => assertSbx056EvidenceExcludesRawValues({ bytes: Buffer.from(escaped) }, [escaped]))
      .toThrow();
    expect(() => assertSbx056EvidenceExcludesRawValues({ [escaped]: true }, [escaped])).toThrow();
    expect(() => assertSbx056EvidenceExcludesRawValues({}, ["short"])).toThrow();
  });
});
