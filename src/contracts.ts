import type { NetworkPolicy } from "@vercel/sandbox";

export type Verdict =
  | "pass"
  | "candidate"
  | "indeterminate"
  | "error"
  | "skipped";

export type ExpectedNetwork = "hit" | "blocked";
export type ExpectedCanary = "present" | "absent" | "ignore";

export interface ProbeCase {
  id: string;
  description: string;
  method: string;
  rawPath: string;
  headers?: Record<string, string | string[]>;
  expectedNetwork: ExpectedNetwork;
  expectedCanary: ExpectedCanary;
}

export interface BuiltTest {
  policy: NetworkPolicy;
  cases: ProbeCase[];
  notes?: string[];
}

export interface BuildContext {
  runId: string;
  testId: string;
  observerBaseUrl: string;
  canary: string;
  canaryHeader: string;
}

export interface TestDefinition {
  id: string;
  title: string;
  priority: "baseline" | "P0" | "P1" | "P2";
  description: string;
  build(context: BuildContext): BuiltTest;
}

export interface GuestCommandResult {
  caseId: string;
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs?: number;
}

export interface ObserverEvent {
  schemaVersion: 1;
  observedAt: string;
  runId: string;
  testId: string;
  caseId: string;
  canary: string;
  method: string;
  rawUrl: string;
  host?: string;
  remoteAddress?: string;
  headers: Record<string, string | string[]>;
  rawHeaders: string[];
  bodyLength: number;
  bodySha256: string;
}

export interface Assessment {
  verdict: Verdict;
  summary: string;
  signals: string[];
}

export interface CleanupResult {
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  errors: string[];
}

export interface EvidenceRecord {
  schemaVersion: 1;
  runId: string;
  testId: string;
  title: string;
  startedAt: string;
  completedAt: string;
  sandbox?: {
    name: string;
    sessionId?: string;
  };
  configuration: {
    observerBaseUrl: string;
    policy: NetworkPolicy;
    cases: ProbeCase[];
    canaryHeader: string;
    canarySha256: string;
    allowControlRunId?: string;
  };
  guestResults: GuestCommandResult[];
  observerEvents: ObserverEvent[];
  assessment: Assessment;
  cleanup: CleanupResult;
  error?: string;
}

export interface SandboxCommand {
  cmd: string;
  args?: string[];
  env?: Record<string, string>;
  sudo?: boolean;
  timeoutMs?: number;
}

export interface SandboxCommandOutput {
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs?: number;
}

export interface SandboxHandle {
  readonly name: string;
  readonly sessionId: string | undefined;
  writeFiles(
    files: Array<{ path: string; content: string; mode?: number }>,
  ): Promise<void>;
  runCommand(command: SandboxCommand): Promise<SandboxCommandOutput>;
  stop(): Promise<void>;
  delete(): Promise<void>;
}

export interface SandboxFactory {
  create(input: {
    name: string;
    timeoutMs: number;
    policy: NetworkPolicy;
    tags: Record<string, string>;
  }): Promise<SandboxHandle>;
}

export interface ObserverReader {
  health(): Promise<void>;
  events(runId: string): Promise<ObserverEvent[]>;
}
