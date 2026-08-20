export type Sbx050GuestCaseId =
  | "public-forward-control"
  | "transform-alone-control"
  | "final-plain-pre"
  | "direct-p-pre"
  | "arm-without-trigger"
  | "direct-p-post"
  | "final-plain-post";

export interface Sbx050GuestConfiguration {
  scopeConfirmation: "researcher-controlled-sbx050-origins-only";
  testId: "SBX-050-POC";
  runId: string;
  caseId: Sbx050GuestCaseId;
  correlationCanary: string;
  targetOrigin: string;
  requestPath: string;
  sendPublicTrigger: boolean;
  timeoutMs: number;
}

export interface Sbx050ValidatedConfiguration extends Sbx050GuestConfiguration {
  hostname: string;
}

export interface Sbx050RequestOptions {
  hostname: string;
  port: 443;
  servername: string;
  method: "GET";
  path: string;
  headers: Record<string, string>;
  rejectUnauthorized: true;
  agent: false;
  timeout: number;
}

export function validateConfiguration(input: unknown): Sbx050ValidatedConfiguration;
export function requestOptions(configuration: Sbx050ValidatedConfiguration): Sbx050RequestOptions;
export function runProbe(input: unknown): Promise<Record<string, unknown>>;
