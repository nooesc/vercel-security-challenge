export const SBX056_TEST_ID = "SBX-056-PROJECT-SCOPED-SESSION-READ" as const;

export type Sbx056Target = "control" | "victim";
export type Sbx056Actor = "owner" | "project-scoped";

export interface Sbx056Attempt {
  phase: "public-control" | "owner-victim-control" | "cross-project";
  actor: Sbx056Actor;
  target: Sbx056Target;
  startedAt: string;
  completedAt: string;
  method: "POST";
  routeShapeExact: boolean;
  teamQueryExact: boolean;
  projectIdentifierSent: false;
  redirectMode: "error";
  transportCalls: 1;
  status: number | null;
  contentType: "application/octet-stream" | "application/json" | "other" | null;
  responseBytes: number;
  exactExpectedMarker: boolean;
  boundedAuthError: boolean;
  transportError: boolean;
}

export interface Sbx056AuthorityProof {
  ownerAliasExact: boolean;
  ownerTeamExact: boolean;
  ownerControlProjectExact: boolean;
  ownerVictimProjectExact: boolean;
  scopedControlProjectExact: boolean;
  scopedVictimProjectDenied: boolean;
  scopedVictimProjectStatus: 403 | 404 | null;
  scopedTokenProjectRestrictionManuallyConfirmed: boolean;
  ownerAndScopedTokensDistinct: boolean;
}

export interface Sbx056ProvenanceProof {
  controlCreatedByOwner: boolean;
  victimCreatedByOwner: boolean;
  controlProjectExact: boolean;
  victimProjectExact: boolean;
  projectsDistinct: boolean;
  sessionsDistinct: boolean;
  namesAndTagsExact: boolean;
  nonpersistent: boolean;
  denyAll: boolean;
  zeroRoutes: boolean;
  fixedPathsExact: boolean;
  publicMarkerWrittenBeforeVictimMarker: boolean;
  victimMarkerStagedAfterPublicControl: boolean;
}

export interface Sbx056CleanupProof {
  controlStopped: boolean;
  controlDeleted: boolean;
  controlExactNameAbsent: boolean;
  controlPrefixAbsent: boolean;
  victimStopped: boolean;
  victimDeleted: boolean;
  victimExactNameAbsent: boolean;
  victimPrefixAbsent: boolean;
  journalCompleted: boolean;
  liveLockReleased: boolean;
}

export interface Sbx056AssessmentInput {
  runIdCanonical: boolean;
  sameEligibleTeam: boolean;
  controlProjectId: string;
  victimProjectId: string;
  authority: Sbx056AuthorityProof;
  provenance: Sbx056ProvenanceProof;
  publicControl: Sbx056Attempt;
  ownerVictimControl: Sbx056Attempt;
  crossProject: Sbx056Attempt;
  crossDispatchGatePassed: boolean;
  exactlyThreeReadRequests: boolean;
  minimumRequestIntervalPassed: boolean;
  chronologyExact: boolean;
  rawTokensOrMarkersRetained: false;
  cleanup: Sbx056CleanupProof;
}

export interface Sbx056Assessment {
  verdict: "cross-project-read-candidate" | "pass" | "indeterminate";
  candidate: boolean;
  likelySeverity: "high" | "none" | "unknown";
  summary: string;
}

const PROJECT = /^prj_[A-Za-z0-9]{8,128}$/u;

function timestamp(value: string): boolean {
  if (value.length !== 24) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function exactAttempt(
  attempt: Sbx056Attempt,
  phase: Sbx056Attempt["phase"],
  actor: Sbx056Actor,
  target: Sbx056Target,
): boolean {
  return attempt.phase === phase && attempt.actor === actor && attempt.target === target &&
    timestamp(attempt.startedAt) && timestamp(attempt.completedAt) &&
    Date.parse(attempt.completedAt) >= Date.parse(attempt.startedAt) &&
    attempt.method === "POST" && attempt.routeShapeExact && attempt.teamQueryExact &&
    attempt.projectIdentifierSent === false && attempt.redirectMode === "error" &&
    attempt.transportCalls === 1 && Number.isSafeInteger(attempt.responseBytes) &&
    attempt.responseBytes >= 0 && attempt.responseBytes <= 4_096 &&
    (attempt.status === null || (Number.isInteger(attempt.status) && attempt.status >= 100 &&
      attempt.status <= 599)) && !(attempt.transportError && attempt.status !== null) &&
    (!attempt.transportError || (attempt.status === null && attempt.contentType === null &&
      attempt.responseBytes === 0 && !attempt.exactExpectedMarker && !attempt.boundedAuthError)) &&
    (attempt.status !== null || attempt.transportError) &&
    (!attempt.boundedAuthError || ((attempt.status === 403 || attempt.status === 404) &&
      attempt.contentType === "application/json" && attempt.responseBytes > 0 &&
      !attempt.exactExpectedMarker && !attempt.transportError)) &&
    !(attempt.exactExpectedMarker && (attempt.status !== 200 ||
      attempt.contentType !== "application/octet-stream" || attempt.transportError ||
      attempt.boundedAuthError || attempt.responseBytes === 0));
}

function controls(input: Sbx056AssessmentInput): boolean {
  const a = input.authority;
  const p = input.provenance;
  const c = input.cleanup;
  return input.runIdCanonical && input.sameEligibleTeam &&
    PROJECT.test(input.controlProjectId) && PROJECT.test(input.victimProjectId) &&
    input.controlProjectId !== input.victimProjectId &&
    a.ownerAliasExact && a.ownerTeamExact && a.ownerControlProjectExact &&
    a.ownerVictimProjectExact && a.scopedControlProjectExact &&
    a.scopedVictimProjectDenied && (a.scopedVictimProjectStatus === 403 ||
      a.scopedVictimProjectStatus === 404) && a.scopedTokenProjectRestrictionManuallyConfirmed &&
    a.ownerAndScopedTokensDistinct && p.controlCreatedByOwner && p.victimCreatedByOwner &&
    p.controlProjectExact && p.victimProjectExact && p.projectsDistinct && p.sessionsDistinct &&
    p.namesAndTagsExact && p.nonpersistent && p.denyAll && p.zeroRoutes && p.fixedPathsExact &&
    p.publicMarkerWrittenBeforeVictimMarker && p.victimMarkerStagedAfterPublicControl &&
    input.crossDispatchGatePassed && input.exactlyThreeReadRequests &&
    input.minimumRequestIntervalPassed && input.chronologyExact &&
    input.rawTokensOrMarkersRetained === false && c.controlStopped && c.controlDeleted &&
    c.controlExactNameAbsent && c.controlPrefixAbsent && c.victimStopped && c.victimDeleted &&
    c.victimExactNameAbsent && c.victimPrefixAbsent && c.journalCompleted && c.liveLockReleased &&
    exactAttempt(input.publicControl, "public-control", "project-scoped", "control") &&
    exactAttempt(input.ownerVictimControl, "owner-victim-control", "owner", "victim") &&
    exactAttempt(input.crossProject, "cross-project", "project-scoped", "victim") &&
    input.publicControl.exactExpectedMarker && input.ownerVictimControl.exactExpectedMarker;
}

export function assessSbx056(input: Sbx056AssessmentInput): Sbx056Assessment {
  if (!controls(input)) {
    return {
      verdict: "indeterminate",
      candidate: false,
      likelySeverity: "unknown",
      summary: "An authority, provenance, control, chronology, retention, or cleanup gate failed.",
    };
  }
  if (input.crossProject.exactExpectedMarker) {
    return {
      verdict: "cross-project-read-candidate",
      candidate: true,
      likelySeverity: "high",
      summary: "A PAT restricted to the control project read the exact fresh victim-project marker through the victim session child route.",
    };
  }
  if ((input.crossProject.status === 403 || input.crossProject.status === 404) &&
      input.crossProject.contentType === "application/json" &&
      input.crossProject.boundedAuthError && !input.crossProject.transportError &&
      input.crossProject.responseBytes > 0) {
    return {
      verdict: "pass",
      candidate: false,
      likelySeverity: "none",
      summary: "The exact victim session read was denied to the project-scoped PAT after both positive controls.",
    };
  }
  return {
    verdict: "indeterminate",
    candidate: false,
    likelySeverity: "unknown",
    summary: "The cross-project response was neither the exact marker nor a conclusive bounded authorization denial.",
  };
}

export function assertSbx056EvidenceExcludesRawValues(
  evidence: unknown,
  forbidden: readonly string[],
): void {
  for (const value of forbidden) {
    if (value.length < 16) throw new Error("SBX-056 forbidden values must be at least 16 characters");
  }
  const forbiddenBytes = forbidden.map((value) => Buffer.from(value, "utf8"));
  const visited = new WeakSet<object>();
  const inspect = (value: unknown): void => {
    if (typeof value === "string") {
      if (forbidden.some((secret) => value.includes(secret))) {
        throw new Error("SBX-056 evidence retained a raw token or marker");
      }
      return;
    }
    if (value === null || typeof value !== "object") return;
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
      const bytes = Buffer.from(value);
      if (forbiddenBytes.some((secret) => bytes.includes(secret))) {
        throw new Error("SBX-056 evidence retained raw token or marker bytes");
      }
      return;
    }
    if (visited.has(value)) throw new Error("SBX-056 evidence contained a cycle");
    visited.add(value);
    if (Array.isArray(value)) {
      for (const item of value) inspect(item);
      return;
    }
    for (const [key, item] of Object.entries(value)) {
      inspect(key);
      inspect(item);
    }
  };
  inspect(evidence);
}
