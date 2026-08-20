export interface Sbx049GuestConfiguration {
  scopeConfirmation: string;
  testId: string;
  runId: string;
  caseId: string;
  canary: string;
  origin: string;
  url: string;
  timeoutMs: number;
}

export function validateConfiguration(value: unknown): { origin: URL; url: URL };
export function requestOnce(configuration: Sbx049GuestConfiguration): Promise<unknown>;
