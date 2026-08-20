export type Sbx058GuestCaseId =
  | "direct-p-pre"
  | "exact-pair"
  | "key-half"
  | "value-half"
  | "combined-halves"
  | "direct-p-post";

export type Sbx058GuestHeaderMode =
  | "none"
  | "exact-pair"
  | "key-half"
  | "value-half"
  | "combined-halves";

export interface Sbx058GuestConfiguration {
  scopeConfirmation: "researcher-controlled-sbx058-origins-only";
  testId: "SBX-058-HEADER-ENTRY-BINDING";
  runId: string;
  caseId: Sbx058GuestCaseId;
  correlationCanary: string;
  headerMode: Sbx058GuestHeaderMode;
  targetRole: "A" | "P";
  targetOrigin: string;
  requestPath: string;
  timeoutMs: number;
}

export interface Sbx058ValidatedConfiguration extends Sbx058GuestConfiguration {
  hostname: string;
}

export function validateConfiguration(input: unknown): Sbx058ValidatedConfiguration;
export function requestOptions(configuration: Sbx058ValidatedConfiguration): Record<string, unknown>;
export function runProbe(input: unknown): Promise<Record<string, unknown>>;
