export interface Sbx048GuestConfiguration {
  scopeConfirmation: "researcher-controlled-sbx048-origin-only";
  runId: string;
  testId: "SBX-048-OIDC-CONTROL-PLANE-CONFUSION";
  caseId: "brokered-control-plane-probe";
  correlationCanary: string;
  expectedMode: "direct" | "forward";
  publicOrigin: string;
  sourcePath: string;
  timeoutMs: number;
}

export interface Sbx048GuestResult {
  schemaVersion: number;
  testId: string;
  runId: string;
  caseId: string;
  expectedMode: "direct" | "forward";
  requestCount: number;
  maximumRequests: number;
  retryCount: number;
  redirectsAllowed: boolean;
  redirectsFollowed: number;
  environmentProxyTrust: boolean;
  rejectUnauthorized: boolean;
  controllerConfigurableCustomTrustAccepted: false;
  inheritedPlatformTrustEnvironmentNames: string[];
  tcpConnected: boolean;
  tlsEstablished: boolean;
  tlsAuthorized: boolean;
  remoteAddress?: string;
  durationMs: number;
  rawResponseHeadersRetained: false;
  rawResponseBodyRetained: false;
  ok: boolean;
  responseStatus: number;
  responseBodyLength?: number;
  responseTruncated?: boolean;
  responseOperationId?: string;
  controlPlaneReadStatus?: number;
  mutationStatus?: number | null;
  errorCode?: string;
}

export function validateConfiguration(input: unknown): Sbx048GuestConfiguration & { hostname: string };
export function requestOptions(configuration: ReturnType<typeof validateConfiguration>): Record<string, unknown>;
export function runProbe(input: unknown): Promise<Sbx048GuestResult>;
