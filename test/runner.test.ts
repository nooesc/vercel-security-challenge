import { readFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { HarnessConfig } from "../src/config.js";
import type {
  ObserverEvent,
  ObserverReader,
  SandboxCommand,
  SandboxCommandOutput,
  SandboxFactory,
  SandboxHandle,
  TestDefinition,
} from "../src/contracts.js";
import { HarnessRunner } from "../src/runner.js";

class FakeSandbox implements SandboxHandle {
  readonly name = "fake-sandbox";
  readonly sessionId = "fake-session";
  readonly writes: Array<{ path: string; content: string; mode?: number }> = [];
  readonly commands: SandboxCommand[] = [];
  stopCalls = 0;
  deleteCalls = 0;

  constructor(
    private readonly failCommandAt?: number,
    private readonly failCleanup = false,
  ) {}

  async writeFiles(files: Array<{ path: string; content: string; mode?: number }>): Promise<void> {
    this.writes.push(...files);
  }

  async runCommand(command: SandboxCommand): Promise<SandboxCommandOutput> {
    this.commands.push(command);
    if (this.commands.length === this.failCommandAt) {
      throw new Error("simulated guest command failure");
    }
    return {
      exitCode: 0,
      stdout: JSON.stringify({ ok: true }),
      stderr: "",
      durationMs: 7,
    };
  }

  async stop(): Promise<void> {
    this.stopCalls += 1;
    if (this.failCleanup) throw new Error("simulated stop failure");
  }

  async delete(): Promise<void> {
    this.deleteCalls += 1;
    if (this.failCleanup) throw new Error("simulated delete failure");
  }
}

class FakeFactory implements SandboxFactory {
  readonly creates: Array<Parameters<SandboxFactory["create"]>[0]> = [];

  constructor(readonly sandbox: FakeSandbox) {}

  async create(input: Parameters<SandboxFactory["create"]>[0]): Promise<SandboxHandle> {
    this.creates.push(input);
    return this.sandbox;
  }
}

class FakeObserver implements ObserverReader {
  healthCalls = 0;
  readonly eventRunIds: string[] = [];

  async health(): Promise<void> {
    this.healthCalls += 1;
  }

  async events(runId: string): Promise<ObserverEvent[]> {
    this.eventRunIds.push(runId);
    return [];
  }
}

const definition: TestDefinition = {
  id: "TEST-RUNNER",
  title: "Runner lifecycle test",
  priority: "baseline",
  description: "Exercises deterministic fake probes",
  build(context) {
    return {
      policy: {
        allow: {
          "observer.example": [
            { transform: [{ headers: { "x-test-broker": context.brokeredCanary } }] },
          ],
        },
      },
      cases: [
        {
          id: "case-a",
          description: "first blocked case",
          method: "GET",
          rawPath: `/v1/probe/${context.runId}/case-a`,
          expectedNetwork: "blocked",
          expectedCanary: "ignore",
        },
        {
          id: "case-b",
          description: "second blocked case",
          method: "POST",
          rawPath: `/v1/probe/${context.runId}/case-b`,
          expectedNetwork: "blocked",
          expectedCanary: "ignore",
        },
      ],
    };
  },
};

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

async function fixture(failCommandAt?: number, failCleanup = false): Promise<{
  config: HarnessConfig;
  factory: FakeFactory;
  observer: FakeObserver;
}> {
  const directory = await mkdtemp(join(tmpdir(), "vsc-harness-test-"));
  temporaryDirectories.push(directory);
  const sandbox = new FakeSandbox(failCommandAt, failCleanup);
  return {
    config: {
      observerBaseUrl: "https://observer.example",
      observerAdminKey: "unit-test-key-that-is-long-enough",
      artifactsDir: directory,
      sandboxTimeoutMs: 30_000,
      commandTimeoutMs: 1_000,
      observerSettleMs: 1,
    },
    factory: new FakeFactory(sandbox),
    observer: new FakeObserver(),
  };
}

function decodedPayload(command: SandboxCommand): Record<string, unknown> {
  expect(command.cmd).toBe("node");
  expect(command.args).toHaveLength(2);
  const encoded = command.args?.[1];
  if (!encoded) throw new Error("missing fake command payload");
  return JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as Record<string, unknown>;
}

describe("HarnessRunner", () => {
  it("uploads the guest probe, executes each unique case, writes evidence, then stops and deletes", async () => {
    const { config, factory, observer } = await fixture();
    const result = await new HarnessRunner(config, factory, observer).run(definition);
    const sandbox = factory.sandbox;

    expect(observer.healthCalls).toBe(1);
    expect(factory.creates).toHaveLength(1);
    expect(factory.creates[0]?.policy).toMatchObject({ allow: { "observer.example": expect.any(Array) } });
    expect(sandbox.writes).toHaveLength(1);
    expect(sandbox.writes[0]?.path).toBe("/tmp/vercel-security-harness/http-probe.mjs");
    expect(sandbox.writes[0]?.mode).toBe(0o700);
    expect(sandbox.writes[0]?.content).toContain("process.argv[2]");

    expect(sandbox.commands).toHaveLength(2);
    const payloads = sandbox.commands.map(decodedPayload);
    expect(payloads.map((payload) => payload.caseId)).toEqual(["case-a", "case-b"]);
    expect(new Set(payloads.map((payload) => payload.caseId)).size).toBe(2);
    expect(new Set(payloads.map((payload) => payload.runId)).size).toBe(1);
    expect(payloads.every((payload) => !("brokeredCanary" in payload))).toBe(true);
    const brokeredValue = JSON.stringify(factory.creates[0]?.policy).match(/broker_[A-Za-z0-9_-]+/)?.[0];
    expect(brokeredValue).toBeDefined();
    expect(payloads.every((payload) => !JSON.stringify(payload).includes(brokeredValue!))).toBe(true);
    const persistedPolicy = JSON.stringify(result.evidence.configuration.policy);
    expect(persistedPolicy).not.toContain("broker_");

    expect(sandbox.stopCalls).toBe(1);
    expect(sandbox.deleteCalls).toBe(1);
    expect(result.evidence.cleanup).toMatchObject({
      stopAttempted: true,
      stopped: true,
      deleteAttempted: true,
      deleted: true,
      errors: [],
    });
    expect(result.evidence.assessment.verdict).toBe("indeterminate");
    expect(result.evidence.assessment.signals).toContain(
      "no prior CONTROL-ALLOW run was available to validate guest-to-observer reachability",
    );
    expect(result.evidence.guestResults.map((entry) => entry.caseId)).toEqual([
      "case-a",
      "case-b",
    ]);
    expect(result.evidence.configuration.correlationCanarySha256).toMatch(/^[a-f0-9]{64}$/);
    expect(result.evidence.configuration.brokeredCanarySha256).toMatch(/^[a-f0-9]{64}$/);
    expect(result.evidencePath).toContain(config.artifactsDir);

    const lines = (await readFile(result.evidencePath, "utf8")).trim().split("\n");
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0] ?? "{}")).toEqual(result.evidence);
  });

  it("still stops, deletes, and writes error evidence when a guest command throws", async () => {
    const { config, factory, observer } = await fixture(1);
    const result = await new HarnessRunner(config, factory, observer).run(definition);
    const sandbox = factory.sandbox;

    expect(sandbox.commands).toHaveLength(1);
    expect(sandbox.stopCalls).toBe(1);
    expect(sandbox.deleteCalls).toBe(1);
    expect(result.evidence.assessment.verdict).toBe("error");
    expect(result.evidence.error).toBe("simulated guest command failure");
    expect(result.evidence.guestResults).toEqual([]);
    expect(result.evidence.cleanup).toMatchObject({ stopped: true, deleted: true, errors: [] });

    const persisted = JSON.parse((await readFile(result.evidencePath, "utf8")).trim()) as {
      error?: string;
      cleanup?: { stopped?: boolean; deleted?: boolean };
    };
    expect(persisted.error).toBe("simulated guest command failure");
    expect(persisted.cleanup).toMatchObject({ stopped: true, deleted: true });
  });

  it("turns cleanup failure into an error verdict", async () => {
    const { config, factory, observer } = await fixture(undefined, true);
    const result = await new HarnessRunner(config, factory, observer).run(definition);

    expect(factory.sandbox.stopCalls).toBe(1);
    expect(factory.sandbox.deleteCalls).toBe(1);
    expect(result.evidence.cleanup.errors).toEqual([
      "stop: simulated stop failure",
      "delete: simulated delete failure",
    ]);
    expect(result.evidence.assessment.verdict).toBe("error");
    expect(result.evidence.error).toContain("simulated stop failure");
  });
});
