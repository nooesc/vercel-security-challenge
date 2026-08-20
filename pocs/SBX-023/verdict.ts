export type Sbx023Verdict = "pass" | "candidate" | "indeterminate" | "error";

export interface ProxyIdentity {
  host: string;
  teamId: string;
  projectId: string;
  sandboxId: string;
  sandboxName: string;
}

export interface ProxyRawHeaderField {
  position: number;
  name: string;
  value: string;
}

export interface ProxyRawHeaderAudit {
  caseId: string;
  caseHeaderCount: number;
  caseIdMatched: boolean;
  oidcHeaderCount: number;
  oidcValueCount: number;
  guestFakeOidcObserved: boolean;
  intermediaryOrderTrusted: boolean;
  forwardedFields: ProxyRawHeaderField[];
}

export interface ProxyAuthenticationRecord {
  operationId: string;
  caseId: string;
  authenticated: boolean;
  actionAuthorized: boolean;
  reconstructedUrl?: string;
  proxyMeta?: ProxyIdentity;
  invalidReasonCode?: string;
  rawHeaderAudit: ProxyRawHeaderAudit;
}

export type AttackAttributionClass =
  | "unique-metadata"
  | "duplicate-order-only"
  | "oidc-only";

export interface GuestCaseAssessment {
  caseId: string;
  guestOk: boolean;
  statusCode?: number;
  responseOperationId?: string;
  responseAuthenticated?: boolean;
  responseActionAuthorized?: boolean;
  observerEventCount: number;
  records: ProxyAuthenticationRecord[];
  conclusiveDirectReachability?: boolean;
  conclusiveFirewallBlock?: boolean;
  rawAttackEvidenceValid?: boolean;
  attackAttributionClass?: AttackAttributionClass;
}

export interface Sbx023AssessmentInput {
  executionError?: string;
  cleanupErrors: string[];
  initialPolicyProofPassed: boolean;
  finalPolicyUpdateAcknowledged: boolean;
  prePolicyProofPassed: boolean;
  postPolicyProofPassed: boolean;
  positiveDirectB: GuestCaseAssessment;
  preDirectB: GuestCaseAssessment;
  postDirectB: GuestCaseAssessment;
  baseline: GuestCaseAssessment;
  attacks: GuestCaseAssessment[];
  allAttacksExecuted: boolean;
  baselineRawMetadataValid: boolean;
  expectedBaselineUrl: string;
  expectedActionUrl: string;
  expectedIdentity: ProxyIdentity;
}

export interface Sbx023Assessment {
  verdict: Sbx023Verdict;
  controlsPassed: boolean;
  candidate: boolean;
  summary: string;
  signals: string[];
  candidateCaseId?: string;
  candidateOperationId?: string;
}

function sameUrl(actual: string | undefined, expected: string): boolean {
  if (!actual) return false;
  try {
    const actualUrl = new URL(actual);
    const expectedUrl = new URL(expected);
    return actualUrl.origin === expectedUrl.origin &&
      actualUrl.pathname === expectedUrl.pathname &&
      actualUrl.search === expectedUrl.search;
  } catch {
    return false;
  }
}

function sameIdentity(actual: ProxyIdentity | undefined, expected: ProxyIdentity): boolean {
  return actual !== undefined &&
    actual.host.toLowerCase() === expected.host.toLowerCase() &&
    actual.teamId === expected.teamId &&
    actual.projectId === expected.projectId &&
    actual.sandboxId === expected.sandboxId &&
    actual.sandboxName === expected.sandboxName;
}

function responseMatchesRecord(testCase: GuestCaseAssessment, record: ProxyAuthenticationRecord): boolean {
  return testCase.responseOperationId === record.operationId &&
    testCase.responseAuthenticated === record.authenticated &&
    testCase.responseActionAuthorized === record.actionAuthorized;
}

export function rawAuditContainsOrderedPlan(
  audit: ProxyRawHeaderAudit | undefined,
  caseId: string,
  plannedFields: Array<{ name: string; value: string }>,
): boolean {
  if (
    !audit || audit.caseId !== caseId || audit.caseHeaderCount !== 1 || !audit.caseIdMatched ||
    audit.oidcHeaderCount < 1 || audit.oidcValueCount < 1
  ) {
    return false;
  }
  let lastPosition = -1;
  for (const planned of plannedFields) {
    const name = planned.name.toLowerCase();
    const match = audit.forwardedFields.find((field) =>
      field.position > lastPosition && field.name === name && field.value === planned.value
    );
    if (!match) return false;
    lastPosition = match.position;
  }
  return true;
}

export function rawAuditContainsUniqueValues(
  audit: ProxyRawHeaderAudit | undefined,
  caseId: string,
  plannedFields: Array<{ name: string; value: string }>,
): boolean {
  return audit !== undefined && audit.caseId === caseId && audit.caseHeaderCount === 1 &&
    audit.caseIdMatched && audit.oidcHeaderCount >= 1 && audit.oidcValueCount >= 1 &&
    plannedFields.length > 0 && plannedFields.every((planned) =>
      audit.forwardedFields.some((field) =>
        field.name === planned.name.toLowerCase() && field.value === planned.value
      )
    );
}

export function assessSbx023(input: Sbx023AssessmentInput): Sbx023Assessment {
  if (input.executionError || input.cleanupErrors.length > 0) {
    return {
      verdict: "error",
      controlsPassed: false,
      candidate: false,
      summary: input.cleanupErrors.length > 0
        ? "cleanup failed; stop live testing and inspect the owned resources"
        : "the probe did not complete",
      signals: [
        ...(input.executionError ? [`execution error: ${input.executionError}`] : []),
        ...input.cleanupErrors.map((error) => `cleanup error: ${error}`),
      ],
    };
  }

  const baselineRecord = input.baseline.records.find((record) =>
    record.caseId === input.baseline.caseId &&
    record.authenticated &&
    !record.actionAuthorized &&
    sameUrl(record.reconstructedUrl, input.expectedBaselineUrl) &&
    sameIdentity(record.proxyMeta, input.expectedIdentity) &&
    responseMatchesRecord(input.baseline, record)
  );
  const baseControlsPassed =
    input.initialPolicyProofPassed &&
    input.finalPolicyUpdateAcknowledged &&
    input.prePolicyProofPassed &&
    input.postPolicyProofPassed &&
    input.positiveDirectB.conclusiveDirectReachability === true &&
    input.preDirectB.conclusiveFirewallBlock === true &&
    input.postDirectB.conclusiveFirewallBlock === true &&
    input.baseline.guestOk &&
    input.baseline.statusCode === 202 &&
    input.baseline.observerEventCount === 1 &&
    input.baselineRawMetadataValid &&
    baselineRecord !== undefined && input.baseline.records.length === 1;

  if (!baseControlsPassed) {
    return {
      verdict: "indeterminate",
      controlsPassed: false,
      candidate: false,
      summary: "an exact policy transition/session, same-IP reachability/reset, or authenticated forwarding control failed",
      signals: [
        `initial policy proof/update acknowledged: ${input.initialPolicyProofPassed}/${input.finalPolicyUpdateAcknowledged}`,
        `pre/post policy proof: ${input.prePolicyProofPassed}/${input.postPolicyProofPassed}`,
        `temporary-policy direct B reachability: ${input.positiveDirectB.conclusiveDirectReachability === true}`,
        `pre/post direct B conclusively blocked: ${input.preDirectB.conclusiveFirewallBlock === true}/${input.postDirectB.conclusiveFirewallBlock === true}`,
        `baseline guest success/status 202: ${input.baseline.guestOk && input.baseline.statusCode === 202}`,
        `baseline raw metadata valid: ${input.baselineRawMetadataValid}`,
        `baseline authenticated record and exact identity valid: ${baselineRecord !== undefined}`,
      ],
    };
  }

  for (const attack of input.attacks) {
    const strongRecord = attack.records.find((record) =>
      record.caseId === attack.caseId &&
      record.authenticated &&
      record.actionAuthorized &&
      sameUrl(record.reconstructedUrl, input.expectedActionUrl) &&
      sameIdentity(record.proxyMeta, input.expectedIdentity) &&
      responseMatchesRecord(attack, record)
    );
    if (
      strongRecord && attack.records.length === 1 && attack.guestOk && attack.statusCode === 200 &&
      attack.observerEventCount === 1 &&
      attack.rawAttackEvidenceValid === true && attack.attackAttributionClass === "unique-metadata"
    ) {
      return {
        verdict: "candidate",
        controlsPassed: true,
        candidate: true,
        summary: "unique guest-controlled reserved metadata reached the proxy before helper parsing and selected the authenticated denied B-only action",
        signals: [
          `candidate case: ${attack.caseId}`,
          "pre-helper raw evidence contained the unique guest-controlled metadata values",
          "the official proxy helper accepted Vercel OIDC for the exact created sandbox identity",
          "the reconstructed URL matched the controller-configured B-only action URL",
          "the guest response and observer record shared the same opaque operation ID",
        ],
        candidateCaseId: attack.caseId,
        candidateOperationId: strongRecord.operationId,
      };
    }
  }

  const unattributedAction = input.attacks.find((attack) =>
    attack.records.some((record) => record.actionAuthorized) || attack.responseActionAuthorized === true
  );
  if (unattributedAction) {
    return {
      verdict: "indeterminate",
      controlsPassed: true,
      candidate: false,
      summary: "a B-only action signal appeared but failed unique raw-metadata, exact OIDC identity, URL, event, or operation-ID attribution",
      signals: [
        `unattributed action case: ${unattributedAction.caseId}`,
        `attribution class: ${unattributedAction.attackAttributionClass ?? "missing"}`,
      ],
    };
  }

  if (!input.allAttacksExecuted) {
    return {
      verdict: "indeterminate",
      controlsPassed: true,
      candidate: false,
      summary: "controls passed, but the complete fixed attack matrix did not execute",
      signals: ["one or more planned reserved-header cases is missing"],
    };
  }

  return {
    verdict: "pass",
    controlsPassed: true,
    candidate: false,
    summary: "the exact same-session policy transition and same-IP reachability/reset controls held, the proxy authenticated the baseline, and no attributable reserved-header case executed the B-only action",
    signals: [
      "the exact pinned B TCP/TLS/HTTP control succeeded before restriction",
      "the same B peer produced conclusive fast pre-TLS ECONNRESET blocks before and after attacks",
      "baseline forwarding reconstructed the exact A URL and exact sandbox identity",
      "no uniquely attributable attack response and observer record proved an authenticated B-only action",
    ],
  };
}
