import "dotenv/config";

import { randomBytes, randomUUID } from "node:crypto";
import { resolve4 } from "node:dns/promises";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { Sandbox, type NetworkPolicy } from "@vercel/sandbox";
import { HttpObserverClient } from "../../src/observer-client.js";
import type { ObserverEvent } from "../../src/contracts.js";

const remoteProbePath = "/tmp/sbx-006/authority-probe.mjs";

interface ProbeSpec {
  caseId: string;
  destinationHost: string;
}

interface ProbeRecord {
  caseId: string;
  destinationHost: string;
  exitCode: number;
  result: Record<string, unknown>;
  stderr: string;
}

interface PhaseRecord {
  phase: "baseline" | "deny";
  policy: NetworkPolicy;
  sandbox?: Record<string, unknown>;
  probes: ProbeRecord[];
  events: ObserverEvent[];
  error?: string;
  cleanup: {
    stopAttempted: boolean;
    stopped: boolean;
    deleteAttempted: boolean;
    deleted: boolean;
    errors: string[];
  };
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function controlledOrigin(): URL {
  const url = new URL(required("OBSERVER_BASE_URL"));
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash ||
    (url.port !== "" && url.port !== "443")
  ) {
    throw new Error(
      "OBSERVER_BASE_URL must be a researcher-controlled HTTPS origin on port 443 without credentials, path, query, or fragment",
    );
  }
  return url;
}

function explicitCredentials():
  | { token: string; teamId: string; projectId: string }
  | Record<string, never> {
  const token = process.env.VERCEL_TOKEN;
  const teamId = process.env.VERCEL_TEAM_ID;
  const projectId = process.env.VERCEL_PROJECT_ID;
  const count = [token, teamId, projectId].filter(Boolean).length;
  if (count !== 0 && count !== 3) {
    throw new Error("VERCEL_TOKEN, VERCEL_TEAM_ID, and VERCEL_PROJECT_ID must be supplied together");
  }
  return count === 3 ? { token: token!, teamId: teamId!, projectId: projectId! } : {};
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function singleEvent(events: ObserverEvent[], caseId: string): ObserverEvent | undefined {
  const matches = events.filter((event) => event.caseId === caseId);
  return matches.length === 1 ? matches[0] : undefined;
}

function remoteMatchesIPv4(value: unknown, address: string): boolean {
  if (typeof value !== "string") return false;
  const normalized = value.toLowerCase();
  return normalized === address || normalized === `::ffff:${address}`;
}

function successfulProbe(
  probe: ProbeRecord | undefined,
  event: ObserverEvent | undefined,
  observer: URL,
  runId: string,
  canary: string,
  expectedRemote?: string,
): boolean {
  if (!probe || probe.exitCode !== 0 || probe.result.ok !== true || !event) return false;
  const response = record(probe.result.response);
  const transport = record(probe.result.transport);
  const tls = record(transport?.tls);
  const certificate = record(tls?.peerCertificate);
  const eventHost = event.host?.toLowerCase();
  return response?.statusCode === 204 &&
    tls?.authorized === true &&
    typeof certificate?.fingerprint256 === "string" &&
    event.runId === runId &&
    event.testId === "SBX-006-POC" &&
    event.canary === canary &&
    eventHost === observer.host.toLowerCase() &&
    (expectedRemote === undefined || remoteMatchesIPv4(transport?.remoteAddress, expectedRemote));
}

function blockedProbe(probe: ProbeRecord | undefined, events: ObserverEvent[], caseId: string): boolean {
  return probe?.exitCode === 0 &&
    probe.result.ok === false &&
    events.every((event) => event.caseId !== caseId);
}

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  const observer = controlledOrigin();
  const adminKey = required("OBSERVER_ADMIN_KEY");
  const observerClient = new HttpObserverClient(observer.origin, adminKey);
  await observerClient.health();

  const dnsStartedAt = new Date().toISOString();
  const answers = await resolve4(observer.hostname, { ttl: true });
  const dnsCompletedAt = new Date().toISOString();
  const uniqueAnswers = answers.filter(
    (answer, index, all) =>
      isIP(answer.address) === 4 &&
      all.findIndex((candidate) => candidate.address === answer.address) === index,
  );
  if (uniqueAnswers.length === 0) {
    throw new Error("OBSERVER_BASE_URL did not resolve to a current IPv4 A record");
  }
  const target = uniqueAnswers[0]!.address;
  const secondary = uniqueAnswers[1]?.address;
  const mappedTarget = `::ffff:${target}`;
  const runId = randomUUID();
  const correlationCanary = `corr_${randomBytes(18).toString("base64url")}`;
  const guestForbiddenValues = [adminKey, process.env.VERCEL_TOKEN ?? ""].filter(Boolean);
  const controlledHosts = [observer.hostname, target, mappedTarget, ...(secondary ? [secondary] : [])];
  const guestProbeSource = await readFile(resolve("guest/authority-probe.mjs"), "utf8");
  const phases: PhaseRecord[] = [];

  async function runPhase(
    phase: "baseline" | "deny",
    policy: NetworkPolicy,
    specs: ProbeSpec[],
  ): Promise<PhaseRecord> {
    const phaseRecord: PhaseRecord = {
      phase,
      policy,
      probes: [],
      events: [],
      cleanup: {
        stopAttempted: false,
        stopped: false,
        deleteAttempted: false,
        deleted: false,
        errors: [],
      },
    };
    let sandbox: Sandbox | undefined;
    try {
      sandbox = await Sandbox.create({
        name: `sbx-006-${phase}-${runId.slice(0, 8)}`,
        persistent: false,
        timeout: 300_000,
        networkPolicy: policy,
        tags: { harness: "vsc", test: "SBX-006", phase, run: runId.slice(0, 12) },
        ...explicitCredentials(),
      });
      const session = sandbox.currentSession();
      phaseRecord.sandbox = {
        name: sandbox.name,
        sessionId: session.sessionId,
        sessionCreatedAt: session.createdAt.toISOString(),
        sessionRequestedAt: session.requestedAt.toISOString(),
        region: session.region,
      };
      await sandbox.writeFiles([{ path: remoteProbePath, content: guestProbeSource, mode: 0o700 }]);

      for (const spec of specs) {
        const query = new URLSearchParams({
          __sbx_run: runId,
          __sbx_test: "SBX-006-POC",
          __sbx_case: spec.caseId,
          __sbx_canary: correlationCanary,
        });
        const configuration = {
          scopeConfirmation: "researcher-controlled-endpoints-only",
          researcherControlledHosts: controlledHosts,
          runId,
          testId: "SBX-006-POC",
          caseId: spec.caseId,
          destinationHost: spec.destinationHost,
          destinationPort: 443,
          tlsServername: observer.hostname,
          httpHost: observer.host,
          method: "GET",
          requestTarget: `/v1/probe/${encodeURIComponent(runId)}/cidr?${query}`,
          headers: { "x-sbx-correlation": correlationCanary },
          timeoutMs: 20_000,
          maxResponseBodyBytes: 4_096,
        };
        const serialized = JSON.stringify(configuration);
        if (guestForbiddenValues.some((value) => serialized.includes(value))) {
          throw new Error(`${spec.caseId} guest configuration contains controller-only material`);
        }
        const command = await sandbox.runCommand({
          cmd: "node",
          args: [remoteProbePath, Buffer.from(serialized).toString("base64url")],
          timeoutMs: 25_000,
        });
        const [stdout, stderr] = await Promise.all([command.stdout(), command.stderr()]);
        let result: Record<string, unknown>;
        try {
          result = JSON.parse(stdout) as Record<string, unknown>;
        } catch {
          throw new Error(`${spec.caseId} emitted invalid JSON`);
        }
        phaseRecord.probes.push({
          caseId: spec.caseId,
          destinationHost: spec.destinationHost,
          exitCode: command.exitCode,
          result,
          stderr: stderr.slice(0, 2_000),
        });
      }
      await new Promise((resolveWait) => setTimeout(resolveWait, 1_000));
      const allEvents = await observerClient.events(runId);
      const caseIds = new Set(specs.map((spec) => spec.caseId));
      phaseRecord.events = allEvents.filter((event) => caseIds.has(event.caseId));
    } catch (error) {
      phaseRecord.error = error instanceof Error ? error.message : String(error);
      try {
        const allEvents = await observerClient.events(runId);
        const caseIds = new Set(specs.map((spec) => spec.caseId));
        phaseRecord.events = allEvents.filter((event) => caseIds.has(event.caseId));
      } catch (eventError) {
        phaseRecord.error += `; event query: ${eventError instanceof Error ? eventError.message : String(eventError)}`;
      }
    } finally {
      if (sandbox) {
        phaseRecord.cleanup.stopAttempted = true;
        try {
          await sandbox.stop();
          phaseRecord.cleanup.stopped = true;
        } catch (error) {
          phaseRecord.cleanup.errors.push(`stop: ${error instanceof Error ? error.message : String(error)}`);
        }
        phaseRecord.cleanup.deleteAttempted = true;
        try {
          await sandbox.delete();
          phaseRecord.cleanup.deleted = true;
        } catch (error) {
          phaseRecord.cleanup.errors.push(`delete: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
    }
    phases.push(phaseRecord);
    return phaseRecord;
  }

  const baselineSpecs: ProbeSpec[] = [
    { caseId: "baseline-hostname-a", destinationHost: observer.hostname },
    { caseId: "baseline-fixed-t", destinationHost: target },
    { caseId: "baseline-mapped-t", destinationHost: mappedTarget },
    ...(secondary ? [{ caseId: "baseline-fixed-s", destinationHost: secondary }] : []),
  ];
  const baseline = await runPhase("baseline", "allow-all", baselineSpecs);
  const baselineProbe = (caseId: string): ProbeRecord | undefined =>
    baseline.probes.find((probe) => probe.caseId === caseId);
  const baselineHostnamePassed = successfulProbe(
    baselineProbe("baseline-hostname-a"),
    singleEvent(baseline.events, "baseline-hostname-a"),
    observer,
    runId,
    correlationCanary,
  );
  const baselineFixedTargetPassed = successfulProbe(
    baselineProbe("baseline-fixed-t"),
    singleEvent(baseline.events, "baseline-fixed-t"),
    observer,
    runId,
    correlationCanary,
    target,
  );
  const baselineMappedTargetPassed = successfulProbe(
    baselineProbe("baseline-mapped-t"),
    singleEvent(baseline.events, "baseline-mapped-t"),
    observer,
    runId,
    correlationCanary,
    target,
  );
  const baselineSecondaryPassed = secondary === undefined || successfulProbe(
    baselineProbe("baseline-fixed-s"),
    singleEvent(baseline.events, "baseline-fixed-s"),
    observer,
    runId,
    correlationCanary,
    secondary,
  );
  const baselineMappedError = baselineProbe("baseline-mapped-t")?.result.error;
  const baselineMappedEnetunreach =
    typeof baselineMappedError === "string" && baselineMappedError.includes("ENETUNREACH");
  const baselineControlsPassed =
    baselineHostnamePassed &&
    baselineFixedTargetPassed &&
    baselineMappedTargetPassed &&
    baselineSecondaryPassed;
  const baselineOperationallyClean =
    baseline.error === undefined &&
    baseline.cleanup.errors.length === 0 &&
    baseline.cleanup.stopped &&
    baseline.cleanup.deleted;

  let deny: PhaseRecord | undefined;
  if (baselineControlsPassed && baselineOperationallyClean) {
    const denyPolicy: NetworkPolicy = {
      allow: [observer.hostname],
      subnets: { deny: [`${target}/32`] },
    };
    deny = await runPhase("deny", denyPolicy, [
      { caseId: "deny-fixed-t", destinationHost: target },
      ...(secondary ? [{ caseId: "deny-fixed-s", destinationHost: secondary }] : []),
      { caseId: "deny-mapped-t", destinationHost: mappedTarget },
    ]);
  }

  const denyProbe = (caseId: string): ProbeRecord | undefined =>
    deny?.probes.find((probe) => probe.caseId === caseId);
  const exactTargetBlocked = deny !== undefined && blockedProbe(
    denyProbe("deny-fixed-t"),
    deny.events,
    "deny-fixed-t",
  );
  const secondaryEdgePassed = secondary === undefined || (
    deny !== undefined && successfulProbe(
      denyProbe("deny-fixed-s"),
      singleEvent(deny.events, "deny-fixed-s"),
      observer,
      runId,
      correlationCanary,
      secondary,
    )
  );
  const mappedTargetReached = deny !== undefined && successfulProbe(
    denyProbe("deny-mapped-t"),
    singleEvent(deny.events, "deny-mapped-t"),
    observer,
    runId,
    correlationCanary,
    target,
  );
  const mappedTargetBlocked = deny !== undefined && blockedProbe(
    denyProbe("deny-mapped-t"),
    deny.events,
    "deny-mapped-t",
  );
  const cleanupErrors = phases.flatMap((phase) =>
    phase.cleanup.errors.map((error) => `${phase.phase}: ${error}`),
  );
  const executionErrors = phases.flatMap((phase) =>
    phase.error ? [`${phase.phase}: ${phase.error}`] : [],
  );
  const operationalFailure = cleanupErrors.length > 0 || executionErrors.length > 0;
  const candidate =
    !operationalFailure &&
    baselineControlsPassed &&
    exactTargetBlocked &&
    secondaryEdgePassed &&
    mappedTargetReached;
  const pass =
    !operationalFailure &&
    baselineControlsPassed &&
    exactTargetBlocked &&
    secondaryEdgePassed &&
    mappedTargetBlocked;
  const outcome = candidate ? "candidate" : pass ? "pass" : "indeterminate";

  const evidence = {
    schemaVersion: 1,
    testId: "SBX-006",
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    outcome,
    candidate,
    controls: {
      baselineControlsPassed,
      baselineOperationallyClean,
      baselineHostnamePassed,
      baselineFixedTargetPassed,
      baselineMappedTargetPassed,
      baselineSecondaryPassed,
      baselineMappedEnetunreach,
      exactTargetBlocked,
      secondaryEdgePassed,
    },
    signals: { mappedTargetReached, mappedTargetBlocked },
    dnsSnapshot: {
      hostname: observer.hostname,
      startedAt: dnsStartedAt,
      completedAt: dnsCompletedAt,
      answers: uniqueAnswers,
      selectedTarget: target,
      selectedSecondary: secondary,
      mappedTarget,
    },
    controlledOrigin: observer.origin,
    phases,
    executionErrors,
    cleanupErrors,
  };
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const privateEvidencePath = resolve(artifactsDirectory, `SBX-006-poc-${runId}-private.json`);
  await writeFile(privateEvidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify({
    outcome,
    candidate,
    controls: evidence.controls,
    signals: evidence.signals,
    dnsSnapshot: evidence.dnsSnapshot,
    cleanup: phases.map((phase) => ({ phase: phase.phase, cleanup: phase.cleanup })),
    privateEvidencePath,
  }, null, 2)}\n`);
  if (operationalFailure) {
    throw new Error([...executionErrors, ...cleanupErrors].join("; "));
  }
}

await main();
