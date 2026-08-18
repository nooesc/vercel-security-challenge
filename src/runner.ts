import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import type {
  Assessment,
  CleanupResult,
  EvidenceRecord,
  GuestCommandResult,
  ObserverReader,
  SandboxFactory,
  SandboxHandle,
  TestDefinition,
} from "./contracts.js";
import type { HarnessConfig } from "./config.js";
import { assessTest } from "./assessment.js";
import { JsonlEvidenceWriter } from "./evidence.js";

const guestProbePath = fileURLToPath(new URL("../guest/http-probe.mjs", import.meta.url));
const remoteProbePath = "/tmp/vercel-security-harness/http-probe.mjs";

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function redactExactValue<T>(value: T, secret: string): T {
  if (typeof value === "string") {
    return value.replaceAll(secret, "<redacted-brokered-canary>") as T;
  }
  if (Array.isArray(value)) {
    return value.map((entry) => redactExactValue(entry, secret)) as T;
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, redactExactValue(entry, secret)]),
    ) as T;
  }
  return value;
}

function sandboxName(testId: string, runId: string): string {
  const normalized = testId.toLowerCase().replace(/[^a-z0-9-]/g, "-");
  return `vsc-${normalized}-${runId.slice(0, 8)}`.slice(0, 48);
}

async function cleanupSandbox(sandbox: SandboxHandle | undefined): Promise<CleanupResult> {
  const result: CleanupResult = {
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    errors: [],
  };
  if (!sandbox) return result;
  result.stopAttempted = true;
  try {
    await sandbox.stop();
    result.stopped = true;
  } catch (error) {
    result.errors.push(`stop: ${message(error)}`);
  }
  result.deleteAttempted = true;
  try {
    await sandbox.delete();
    result.deleted = true;
  } catch (error) {
    result.errors.push(`delete: ${message(error)}`);
  }
  return result;
}

export interface RunResult {
  evidence: EvidenceRecord;
  evidencePath: string;
}

export class HarnessRunner {
  private readonly writer: JsonlEvidenceWriter;
  private allowControlRunId: string | undefined;

  constructor(
    private readonly config: HarnessConfig,
    private readonly factory: SandboxFactory,
    private readonly observer: ObserverReader,
  ) {
    this.writer = new JsonlEvidenceWriter(config.artifactsDir);
  }

  async run(definition: TestDefinition): Promise<RunResult> {
    const runId = randomUUID();
    const correlationCanary = `corr_${randomBytes(18).toString("base64url")}`;
    const brokeredCanary = `broker_${randomBytes(24).toString("base64url")}`;
    const canaryHeader = "x-sbx-harness-canary";
    const startedAt = new Date().toISOString();
    const built = definition.build({
      runId,
      testId: definition.id,
      observerBaseUrl: this.config.observerBaseUrl,
      correlationCanary,
      brokeredCanary,
      canaryHeader,
    });
    let sandbox: SandboxHandle | undefined;
    let sandboxEvidence: EvidenceRecord["sandbox"];
    let guestResults: GuestCommandResult[] = [];
    let observerEvents: Awaited<ReturnType<ObserverReader["events"]>> = [];
    let assessment: Assessment = {
      verdict: "error",
      summary: "run did not reach assessment",
      signals: [],
    };
    let runError: string | undefined;

    try {
      await this.observer.health();
      sandbox = await this.factory.create({
        name: sandboxName(definition.id, runId),
        timeoutMs: this.config.sandboxTimeoutMs,
        policy: built.policy,
        tags: { harness: "vsc", test: definition.id, run: runId.slice(0, 12) },
      });
      sandboxEvidence = {
        name: sandbox.name,
        ...(sandbox.sessionId ? { sessionId: sandbox.sessionId } : {}),
      };
      const guestProbe = await readFile(guestProbePath, "utf8");
      await sandbox.writeFiles([{ path: remoteProbePath, content: guestProbe, mode: 0o700 }]);

      for (const probe of built.cases) {
        const serializedGuestConfiguration = JSON.stringify({
          baseUrl: this.config.observerBaseUrl,
          runId,
          testId: definition.id,
          caseId: probe.id,
          canary: correlationCanary,
          method: probe.method,
          rawPath: probe.rawPath,
          headers: probe.headers ?? {},
          timeoutMs: this.config.commandTimeoutMs,
        });
        if (serializedGuestConfiguration.includes(brokeredCanary)) {
          throw new Error("proof invalid: brokered canary entered the guest configuration");
        }
        const payload = Buffer.from(serializedGuestConfiguration).toString("base64url");
        const output = await sandbox.runCommand({
          cmd: "node",
          args: [remoteProbePath, payload],
          timeoutMs: this.config.commandTimeoutMs + 5_000,
        });
        guestResults.push({
          caseId: probe.id,
          exitCode: output.exitCode,
          stdout: output.stdout,
          stderr: output.stderr,
          ...(output.durationMs !== undefined ? { durationMs: output.durationMs } : {}),
        });
      }

      await new Promise((resolve) => setTimeout(resolve, this.config.observerSettleMs));
      observerEvents = await this.observer.events(runId);
      assessment = assessTest(built, observerEvents, brokeredCanary, canaryHeader, {
        ...(this.allowControlRunId ? { allowControlRunId: this.allowControlRunId } : {}),
      });
      if (definition.id === "CONTROL-ALLOW" && assessment.verdict === "pass") {
        this.allowControlRunId = runId;
      }
    } catch (error) {
      runError = message(error);
      assessment = {
        verdict: "error",
        summary: "The harness failed before it could produce a trustworthy verdict.",
        signals: [runError],
      };
    }

    const cleanup = await cleanupSandbox(sandbox);
    if (cleanup.errors.length > 0) {
      assessment.signals.push(...cleanup.errors.map((error) => `cleanup ${error}`));
      assessment.verdict = "error";
      assessment.summary = "Sandbox cleanup failed; stop further live testing and inspect the resource manually.";
      runError ??= cleanup.errors.join("; ");
    }
    const completedAt = new Date().toISOString();
    const rawEvidence: EvidenceRecord = {
      schemaVersion: 1,
      runId,
      testId: definition.id,
      title: definition.title,
      startedAt,
      completedAt,
      ...(sandboxEvidence ? { sandbox: sandboxEvidence } : {}),
      configuration: {
        observerBaseUrl: this.config.observerBaseUrl,
        policy: built.policy,
        cases: built.cases,
        canaryHeader,
        correlationCanarySha256: createHash("sha256").update(correlationCanary).digest("hex"),
        brokeredCanarySha256: createHash("sha256").update(brokeredCanary).digest("hex"),
        ...(this.allowControlRunId ? { allowControlRunId: this.allowControlRunId } : {}),
      },
      guestResults,
      observerEvents,
      assessment,
      cleanup,
      ...(runError ? { error: runError } : {}),
    };
    const evidence = redactExactValue(rawEvidence, brokeredCanary);
    const evidencePath = await this.writer.write(evidence);
    return { evidence, evidencePath };
  }
}
