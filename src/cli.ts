import "dotenv/config";

import { loadHarnessConfig } from "./config.js";
import { HttpObserverClient } from "./observer-client.js";
import { getTest, testRegistry } from "./registry.js";
import { HarnessRunner } from "./runner.js";
import { VercelSandboxFactory } from "./sandbox-adapter.js";
import type { TestDefinition, Verdict } from "./contracts.js";

const usage = `Usage: npm run harness -- [options]

Select tests:
  --test ID       Run one test (repeatable; IDs are case-insensitive)
  --all           Run every implemented test

Modes:
  --list          List implemented tests without loading credentials
  --dry-run       Print the selected policies and probe cases; create nothing
  -h, --help      Show this help

Examples:
  npm run harness -- --list
  npm run harness -- --test CONTROL-ALLOW --dry-run
  npm run harness -- --test CONTROL-ALLOW --test CONTROL-DENY
  npm run harness -- --all --dry-run`;

class CliError extends Error {}

interface CliOptions {
  help: boolean;
  list: boolean;
  all: boolean;
  dryRun: boolean;
  testIds: string[];
}

function parseArgs(args: string[]): CliOptions {
  const options: CliOptions = {
    help: false,
    list: false,
    all: false,
    dryRun: false,
    testIds: [],
  };

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "-h" || argument === "--help") {
      options.help = true;
    } else if (argument === "--list") {
      options.list = true;
    } else if (argument === "--all") {
      options.all = true;
    } else if (argument === "--dry-run") {
      options.dryRun = true;
    } else if (argument === "--test") {
      const value = args[index + 1];
      if (!value || value.startsWith("-")) {
        throw new CliError("--test requires an ID");
      }
      options.testIds.push(value);
      index += 1;
    } else if (argument?.startsWith("--test=")) {
      const value = argument.slice("--test=".length);
      if (!value) throw new CliError("--test requires an ID");
      options.testIds.push(value);
    } else {
      throw new CliError(`unknown argument: ${argument ?? ""}`);
    }
  }

  return options;
}

function validateOptions(options: CliOptions): void {
  if (options.help) return;
  if (options.list) {
    if (options.all || options.dryRun || options.testIds.length > 0) {
      throw new CliError("--list cannot be combined with --all, --test, or --dry-run");
    }
    return;
  }
  if (options.all && options.testIds.length > 0) {
    throw new CliError("--all cannot be combined with --test");
  }
  if (!options.all && options.testIds.length === 0) {
    throw new CliError("select at least one test with --test ID, or use --all");
  }
}

function selectedTests(options: CliOptions): TestDefinition[] {
  const addControlDependency = (tests: TestDefinition[]): TestDefinition[] => {
    const denyIndex = tests.findIndex((test) => test.id === "CONTROL-DENY");
    if (denyIndex === -1) return tests;

    const allowIndex = tests.findIndex((test) => test.id === "CONTROL-ALLOW");
    if (allowIndex === -1) {
      const allowControl = getTest("CONTROL-ALLOW");
      if (!allowControl) throw new Error("CONTROL-ALLOW is missing from the registry");
      return [allowControl, ...tests];
    }
    if (allowIndex < denyIndex) return tests;

    const reordered = tests.filter((test) => test.id !== "CONTROL-ALLOW");
    reordered.splice(denyIndex, 0, tests[allowIndex] as TestDefinition);
    return reordered;
  };

  if (options.all) return addControlDependency([...testRegistry]);

  const selected: TestDefinition[] = [];
  const seen = new Set<string>();
  for (const requestedId of options.testIds) {
    const definition = getTest(requestedId);
    if (!definition) {
      throw new CliError(
        `unknown test ID ${JSON.stringify(requestedId)}; use --list to see implemented tests`,
      );
    }
    if (!seen.has(definition.id)) {
      selected.push(definition);
      seen.add(definition.id);
    }
  }
  return addControlDependency(selected);
}

function listTests(): void {
  const idWidth = Math.max(...testRegistry.map((test) => test.id.length));
  for (const test of testRegistry) {
    console.log(`${test.id.padEnd(idWidth)}  ${test.priority.padEnd(8)}  ${test.title}`);
    console.log(`${"".padEnd(idWidth)}            ${test.description}`);
  }
}

function dryRunObserverUrl(): string {
  const raw = process.env.OBSERVER_BASE_URL ?? "https://observer.example.invalid";
  try {
    return new URL(raw).origin;
  } catch {
    throw new CliError("OBSERVER_BASE_URL must be a valid absolute URL when set");
  }
}

function printDryRun(tests: TestDefinition[]): void {
  const observerBaseUrl = dryRunObserverUrl();
  const output = tests.map((definition) => {
    const built = definition.build({
      runId: `dry-run-${definition.id.toLowerCase()}`,
      testId: definition.id,
      observerBaseUrl,
      correlationCanary: "DRY_RUN_CORRELATION_CANARY",
      brokeredCanary: "DRY_RUN_BROKERED_CANARY_REDACTED",
      canaryHeader: "x-sbx-harness-canary",
    });
    return {
      id: definition.id,
      title: definition.title,
      priority: definition.priority,
      description: definition.description,
      observerBaseUrl,
      policy: built.policy,
      cases: built.cases,
      ...(built.notes ? { notes: built.notes } : {}),
    };
  });

  console.log("Dry run only: no observer request was made and no sandbox was created.");
  console.log(JSON.stringify(output, null, 2));
}

function isFailureVerdict(verdict: Verdict): boolean {
  return verdict === "candidate" || verdict === "error" || verdict === "indeterminate";
}

async function runLive(tests: TestDefinition[]): Promise<number> {
  const config = loadHarnessConfig();
  const runner = new HarnessRunner(
    config,
    new VercelSandboxFactory(),
    new HttpObserverClient(config.observerBaseUrl, config.observerAdminKey),
  );
  let failed = false;

  for (const definition of tests) {
    console.log(`\n[${definition.id}] ${definition.title}`);
    const result = await runner.run(definition);
    const { assessment } = result.evidence;
    console.log(`verdict:  ${assessment.verdict}`);
    console.log(`summary:  ${assessment.summary}`);
    console.log(`evidence: ${result.evidencePath}`);
    for (const signal of assessment.signals) console.log(`signal:   ${signal}`);
    if (isFailureVerdict(assessment.verdict)) failed = true;
    if (result.evidence.cleanup.errors.length > 0) {
      console.error("cleanup failed; halting subsequent live tests");
      return 1;
    }
  }

  return failed ? 1 : 0;
}

async function main(): Promise<void> {
  try {
    const options = parseArgs(process.argv.slice(2));
    validateOptions(options);

    if (options.help) {
      console.log(usage);
      return;
    }
    if (options.list) {
      listTests();
      return;
    }

    const tests = selectedTests(options);
    if (options.dryRun) {
      printDryRun(tests);
      return;
    }
    process.exitCode = await runLive(tests);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`error: ${message}`);
    if (error instanceof CliError) console.error(`\n${usage}`);
    process.exitCode = 2;
  }
}

await main();
