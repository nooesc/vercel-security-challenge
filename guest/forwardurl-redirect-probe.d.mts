export interface RedirectProbeConfiguration {
  runId: string;
  testId: string;
  caseId: string;
  correlationId: string;
  destinationHost: string;
  destinationPort: number;
  tlsServername: string;
  httpHost: string;
  path: string;
  headers: Record<string, string>;
  timeoutMs: number;
  researcherControlledHosts: string[];
}

export function validateRedirectProbeConfig(input: unknown): RedirectProbeConfiguration;

export function requestOptions(config: RedirectProbeConfiguration): {
  hostname: string;
  port: number;
  servername: string;
  method: "GET";
  path: string;
  headers: Record<string, string> & { Host: string; Connection: "close" };
  timeout: number;
  rejectUnauthorized: true;
  agent: false;
};

export function runProbe(input: unknown): Promise<Record<string, unknown>>;
