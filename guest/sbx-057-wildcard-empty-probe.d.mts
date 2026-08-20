export interface Sbx057GuestConfiguration {
  schemaVersion: 1;
  testId: "SBX-057-WILDCARD-EMPTY-ISOLATION";
  runId: string;
  caseId: "comparator-a" | "comparator-b" | "target-a" | "target-b";
  canary: string;
  origin: string;
}

export interface ValidatedSbx057GuestConfiguration extends Sbx057GuestConfiguration {
  origin: URL;
  role: "A" | "B";
}

export interface Sbx057GuestResult {
  schemaVersion: 1;
  testId: "SBX-057-WILDCARD-EMPTY-ISOLATION";
  runId: string;
  caseId: Sbx057GuestConfiguration["caseId"];
  canary: string;
  ok: boolean;
  [key: string]: unknown;
}

export function validateConfiguration(value: unknown): ValidatedSbx057GuestConfiguration;
export function requestOnce(
  configuration: Sbx057GuestConfiguration,
  environment?: NodeJS.ProcessEnv,
): Promise<Sbx057GuestResult>;
