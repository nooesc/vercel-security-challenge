import "dotenv/config";

import { randomBytes, randomUUID } from "node:crypto";
import { resolve4 } from "node:dns/promises";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { domainToASCII } from "node:url";
import { Sandbox, type NetworkPolicy } from "@vercel/sandbox";
import { HttpObserverClient } from "../../src/observer-client.js";
import type { ObserverEvent } from "../../src/contracts.js";

const testId = "SBX-003-021-POC";
const remoteProbePath = "/tmp/sbx-003-021/authority-probe.mjs";
const scopeConfirmation = "I_CONTROL_THE_HOSTNAME_AND_BOTH_IPV4S";
const minimumVercelCallIntervalMs = 250;

export type DnsEpochSymbol = "T" | "S";
export type MixedDnsOutcome = "candidate" | "pass" | "indeterminate";

export interface MixedDnsConfiguration {
  observer: URL;
  observerAdminKey: string;
  hostname: string;
  deniedIPv4: string;
  allowedIPv4: string;
  epochPlan: DnsEpochSymbol[];
  epochTimeoutMs: number;
  dnsPollIntervalMs: number;
}

export interface EpochAssessment {
  symbol: DnsEpochSymbol;
  controllerConfirmed: boolean;
  guestLookupMatches: boolean;
  targetCrossed: boolean;
  targetBlocked: boolean;
  safeReached: boolean;
}

export interface MixedDnsAssessmentInput {
  baselineControlsPassed: boolean;
  baselineCleanupPassed: boolean;
  fixedTargetBlocked: boolean;
  fixedSafeReached: boolean;
  denyCleanupPassed: boolean;
  observerConfigCleanupPassed: boolean;
  executionErrors: string[];
  epochs: EpochAssessment[];
}

interface RecordedAction {
  operationId: string;
  authorizedAt: string;
  caseId: string;
  normalizedPath: string;
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
  actions: RecordedAction[];
  error?: string;
  cleanup: {
    stopAttempted: boolean;
    stopped: boolean;
    deleteAttempted: boolean;
    deleted: boolean;
    errors: string[];
  };
}

interface DnsSnapshot {
  observedAt: string;
  answers: Array<{ address: string; ttl: number }>;
  error?: string;
}

interface DnsEpochRecord {
  index: number;
  symbol: DnsEpochSymbol;
  expectedAddress: string;
  startedAt: string;
  deadlineAt: string;
  snapshots: DnsSnapshot[];
  confirmedAt?: string;
  probeCaseId?: string;
  error?: string;
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function exactHostname(value: string): string {
  if (value.trim() !== value || /[\0\r\n/@:?#]/u.test(value)) {
    throw new Error("SBX_MIXED_DNS_HOSTNAME must be a bare DNS hostname without whitespace, a port, or URL syntax");
  }
  const hostname = domainToASCII(value).toLowerCase();
  if (!hostname || isIP(hostname) !== 0 || hostname.endsWith(".") || !hostname.includes(".")) {
    throw new Error("SBX_MIXED_DNS_HOSTNAME must be a non-IP fully qualified DNS hostname without a trailing dot");
  }
  return hostname;
}

function exactIPv4(environment: NodeJS.ProcessEnv, name: string): string {
  const value = required(environment, name);
  if (value.trim() !== value || isIP(value) !== 4) {
    throw new Error(`${name} must be one exact IPv4 address`);
  }
  return value;
}

function boundedInteger(
  environment: NodeJS.ProcessEnv,
  name: string,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const raw = environment[name];
  if (raw === undefined) return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function epochPlan(environment: NodeJS.ProcessEnv): DnsEpochSymbol[] {
  const raw = environment.SBX_MIXED_DNS_EPOCH_PLAN ?? "S,T,S";
  const plan = raw.split(",").map((entry) => entry.trim().toUpperCase());
  if (
    plan.length < 2 ||
    plan.length > 6 ||
    plan.some((entry) => entry !== "S" && entry !== "T") ||
    !plan.includes("S") ||
    !plan.includes("T")
  ) {
    throw new Error("SBX_MIXED_DNS_EPOCH_PLAN must contain 2-6 comma-separated S/T epochs including both S and T");
  }
  if (plan.every((entry, index) => index === 0 || entry === plan[index - 1])) {
    throw new Error("SBX_MIXED_DNS_EPOCH_PLAN must require at least one DNS answer transition");
  }
  return plan as DnsEpochSymbol[];
}

export function parseMixedDnsEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): MixedDnsConfiguration {
  if (required(environment, "SBX_MIXED_DNS_SCOPE_CONFIRMATION") !== scopeConfirmation) {
    throw new Error(`SBX_MIXED_DNS_SCOPE_CONFIRMATION must equal ${scopeConfirmation}`);
  }
  const hostname = exactHostname(required(environment, "SBX_MIXED_DNS_HOSTNAME"));
  const deniedIPv4 = exactIPv4(environment, "SBX_MIXED_DNS_DENIED_IPV4");
  const allowedIPv4 = exactIPv4(environment, "SBX_MIXED_DNS_ALLOWED_IPV4");
  if (deniedIPv4 === allowedIPv4) {
    throw new Error("SBX_MIXED_DNS_DENIED_IPV4 and SBX_MIXED_DNS_ALLOWED_IPV4 must be different");
  }
  const observer = new URL(required(environment, "OBSERVER_BASE_URL"));
  if (
    observer.protocol !== "https:" ||
    observer.username ||
    observer.password ||
    observer.pathname !== "/" ||
    observer.search ||
    observer.hash ||
    (observer.port !== "" && observer.port !== "443") ||
    observer.hostname.toLowerCase() !== hostname
  ) {
    throw new Error("OBSERVER_BASE_URL must be the declared researcher-owned HTTPS hostname on port 443 without a path, query, credentials, or fragment");
  }
  const observerAdminKey = required(environment, "OBSERVER_ADMIN_KEY");
  if (observerAdminKey.length < 24) {
    throw new Error("OBSERVER_ADMIN_KEY must contain at least 24 characters");
  }
  const epochTimeoutMs = boundedInteger(
    environment,
    "SBX_MIXED_DNS_EPOCH_TIMEOUT_MS",
    60_000,
    5_000,
    120_000,
  );
  const dnsPollIntervalMs = boundedInteger(
    environment,
    "SBX_MIXED_DNS_POLL_INTERVAL_MS",
    1_000,
    1_000,
    10_000,
  );
  if (dnsPollIntervalMs > epochTimeoutMs) {
    throw new Error("SBX_MIXED_DNS_POLL_INTERVAL_MS must not exceed SBX_MIXED_DNS_EPOCH_TIMEOUT_MS");
  }
  const parsedEpochPlan = epochPlan(environment);
  if (epochTimeoutMs * parsedEpochPlan.length > 180_000) {
    throw new Error("the DNS epoch plan may reserve at most 180000 ms across all epoch deadlines");
  }
  return {
    observer,
    observerAdminKey,
    hostname,
    deniedIPv4,
    allowedIPv4,
    epochPlan: parsedEpochPlan,
    epochTimeoutMs,
    dnsPollIntervalMs,
  };
}

export function classifyMixedDns(input: MixedDnsAssessmentInput): MixedDnsOutcome {
  const controlsPassed = input.baselineControlsPassed && input.baselineCleanupPassed &&
    input.fixedTargetBlocked && input.fixedSafeReached && input.denyCleanupPassed &&
    input.observerConfigCleanupPassed && input.executionErrors.length === 0;
  if (!controlsPassed || !input.epochs.some((epoch) => epoch.symbol === "S") ||
    !input.epochs.some((epoch) => epoch.symbol === "T")) return "indeterminate";
  const epochsConclusive = input.epochs.every((epoch) => {
    if (!epoch.controllerConfirmed || !epoch.guestLookupMatches) return false;
    return epoch.symbol === "S"
      ? epoch.safeReached && !epoch.targetCrossed && !epoch.targetBlocked
      : (epoch.targetCrossed || epoch.targetBlocked) && !epoch.safeReached;
  });
  if (!epochsConclusive) return "indeterminate";
  return input.epochs.some((epoch) => epoch.symbol === "T" && epoch.targetCrossed)
    ? "candidate"
    : "pass";
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

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function remoteMatchesIPv4(value: unknown, address: string): boolean {
  if (typeof value !== "string") return false;
  const normalized = value.toLowerCase();
  return normalized === address || normalized === `::ffff:${address}`;
}

function operationIdFromProbe(probe: ProbeRecord): string | undefined {
  const response = asRecord(probe.result.response);
  if (typeof response?.body !== "string") return undefined;
  try {
    const body = asRecord(JSON.parse(response.body));
    return body?.selected === true && body.authorized === true && typeof body.operationId === "string"
      ? body.operationId
      : undefined;
  } catch {
    return undefined;
  }
}

function exactEvent(
  events: ObserverEvent[],
  runId: string,
  caseId: string,
  canary: string,
  hostname: string,
): ObserverEvent | undefined {
  const expectedPath = `/v1/probe/${runId}/vhost-action`;
  const matches = events.filter((event) =>
    event.runId === runId && event.testId === testId && event.caseId === caseId &&
    event.canary === canary && event.normalizedPath === expectedPath &&
    event.host?.toLowerCase() === hostname
  );
  return matches.length === 1 ? matches[0] : undefined;
}

function exactAction(actions: RecordedAction[], probe: ProbeRecord): RecordedAction | undefined {
  const operationId = operationIdFromProbe(probe);
  const caseMatches = actions.filter((action) => action.caseId === probe.caseId);
  return operationId !== undefined && caseMatches.length === 1 &&
      caseMatches[0]?.operationId === operationId &&
      caseMatches[0].normalizedPath.endsWith("/vhost-action")
    ? caseMatches[0]
    : undefined;
}

function successfulProbe(
  phase: PhaseRecord | undefined,
  runId: string,
  caseId: string,
  canary: string,
  hostname: string,
  expectedRemote: string,
): boolean {
  const probe = phase?.probes.find((entry) => entry.caseId === caseId);
  if (!probe || probe.exitCode !== 0 || probe.stderr.length !== 0 || probe.result.ok !== true) return false;
  const response = asRecord(probe.result.response);
  const transport = asRecord(probe.result.transport);
  const tls = asRecord(transport?.tls);
  const certificate = asRecord(tls?.peerCertificate);
  return response?.statusCode === 200 && tls?.authorized === true &&
    typeof certificate?.fingerprint256 === "string" &&
    remoteMatchesIPv4(transport?.remoteAddress, expectedRemote) &&
    exactEvent(phase?.events ?? [], runId, caseId, canary, hostname) !== undefined &&
    exactAction(phase?.actions ?? [], probe) !== undefined;
}

function blockedProbe(
  phase: PhaseRecord | undefined,
  caseId: string,
  expectedLookup?: string,
): boolean {
  const probe = phase?.probes.find((entry) => entry.caseId === caseId);
  if (!probe || probe.exitCode !== 0 || probe.stderr.length !== 0 || probe.result.ok !== false ||
    typeof probe.result.error !== "string") return false;
  if ((phase?.events ?? []).some((event) => event.caseId === caseId)) return false;
  if ((phase?.actions ?? []).some((action) => action.caseId === caseId)) return false;
  if (expectedLookup !== undefined) {
    const transport = asRecord(probe.result.transport);
    const lookup = asRecord(transport?.lookup);
    if (!remoteMatchesIPv4(lookup?.address, expectedLookup)) return false;
  }
  return true;
}

function probeLookupMatches(phase: PhaseRecord | undefined, caseId: string, expected: string): boolean {
  const probe = phase?.probes.find((entry) => entry.caseId === caseId);
  const transport = asRecord(probe?.result.transport);
  const lookup = asRecord(transport?.lookup);
  return remoteMatchesIPv4(lookup?.address, expected);
}

function phaseCleanupPassed(phase: PhaseRecord | undefined): boolean {
  return phase !== undefined && phase.error === undefined && phase.cleanup.stopped &&
    phase.cleanup.deleted && phase.cleanup.errors.length === 0;
}

function preliminaryBlocked(probe: ProbeRecord | undefined): boolean {
  return probe?.exitCode === 0 && probe.stderr.length === 0 && probe.result.ok === false &&
    typeof probe.result.error === "string";
}

function preliminarySuccess(probe: ProbeRecord | undefined): boolean {
  const response = asRecord(probe?.result.response);
  return probe?.exitCode === 0 && probe.stderr.length === 0 && probe.result.ok === true &&
    response?.statusCode === 200 && operationIdFromProbe(probe) !== undefined;
}

class VercelRateGate {
  private lastStartMs = 0;

  async beforeCall(): Promise<void> {
    const remaining = minimumVercelCallIntervalMs - (Date.now() - this.lastStartMs);
    if (remaining > 0) await new Promise((resolveWait) => setTimeout(resolveWait, remaining));
    this.lastStartMs = Date.now();
  }
}

async function observerAdminRequest(
  configuration: MixedDnsConfiguration,
  runId: string,
  resource: "vhost-config" | "vhost-actions",
  init?: RequestInit,
): Promise<Response> {
  const headers = new Headers(init?.headers);
  headers.set("authorization", `Bearer ${configuration.observerAdminKey}`);
  return await fetch(
    new URL(`/v1/runs/${encodeURIComponent(runId)}/${resource}`, configuration.observer),
    { ...init, headers, signal: AbortSignal.timeout(10_000) },
  );
}

async function registerVhost(configuration: MixedDnsConfiguration, runId: string): Promise<void> {
  const response = await observerAdminRequest(configuration, runId, "vhost-config", {
    method: "POST",
    headers: { "x-observer-vhost": configuration.hostname },
  });
  if (response.status !== 201) throw new Error(`observer vhost registration returned ${response.status}`);
}

async function deleteVhost(configuration: MixedDnsConfiguration, runId: string): Promise<boolean> {
  const response = await observerAdminRequest(configuration, runId, "vhost-config", { method: "DELETE" });
  return response.status === 204;
}

async function vhostActions(
  configuration: MixedDnsConfiguration,
  runId: string,
): Promise<RecordedAction[]> {
  const response = await observerAdminRequest(configuration, runId, "vhost-actions");
  if (!response.ok) throw new Error(`observer vhost action query returned ${response.status}`);
  const payload = await response.json() as { actions?: RecordedAction[] };
  if (!Array.isArray(payload.actions)) throw new Error("observer returned an invalid vhost action payload");
  return payload.actions;
}

async function waitForDnsEpoch(
  configuration: MixedDnsConfiguration,
  symbol: DnsEpochSymbol,
  index: number,
): Promise<DnsEpochRecord> {
  const expectedAddress = symbol === "T" ? configuration.deniedIPv4 : configuration.allowedIPv4;
  const startedMs = Date.now();
  const epoch: DnsEpochRecord = {
    index,
    symbol,
    expectedAddress,
    startedAt: new Date(startedMs).toISOString(),
    deadlineAt: new Date(startedMs + configuration.epochTimeoutMs).toISOString(),
    snapshots: [],
  };
  process.stderr.write(`SBX-003-021 waiting for DNS epoch ${index + 1} (${symbol}=${expectedAddress})\n`);
  while (Date.now() <= startedMs + configuration.epochTimeoutMs) {
    const observedAt = new Date().toISOString();
    try {
      const answers = await resolve4(configuration.hostname, { ttl: true });
      const unique = answers.filter((answer, answerIndex, all) =>
        isIP(answer.address) === 4 &&
        all.findIndex((candidate) => candidate.address === answer.address) === answerIndex
      );
      epoch.snapshots.push({ observedAt, answers: unique });
      if (unique.length === 1 && unique[0]?.address === expectedAddress) {
        epoch.confirmedAt = new Date().toISOString();
        process.stderr.write(`SBX-003-021 confirmed DNS epoch ${index + 1} (${symbol})\n`);
        return epoch;
      }
    } catch (error) {
      epoch.snapshots.push({
        observedAt,
        answers: [],
        error: error instanceof Error ? error.message : String(error),
      });
    }
    const remaining = startedMs + configuration.epochTimeoutMs - Date.now();
    if (remaining <= 0) break;
    await new Promise((resolveWait) =>
      setTimeout(resolveWait, Math.min(configuration.dnsPollIntervalMs, remaining))
    );
  }
  epoch.error = `controller could not confirm the exact ${symbol} DNS answer before the bounded deadline`;
  return epoch;
}

async function main(): Promise<void> {
  const configuration = parseMixedDnsEnvironment();
  const startedAt = new Date().toISOString();
  const runId = randomUUID();
  const correlationCanary = `corr_${randomBytes(18).toString("base64url")}`;
  const observerClient = new HttpObserverClient(configuration.observer.origin, configuration.observerAdminKey);
  const guestProbeSource = await readFile(resolve("guest/authority-probe.mjs"), "utf8");
  const guestForbiddenValues = [
    configuration.observerAdminKey,
    process.env.VERCEL_TOKEN ?? "",
  ].filter(Boolean);
  if (guestForbiddenValues.some((value) => guestProbeSource.includes(value))) {
    throw new Error("proof invalid: uploaded guest source contains controller-only material");
  }
  const gate = new VercelRateGate();
  const phases: PhaseRecord[] = [];
  const dnsEpochs: DnsEpochRecord[] = [];
  const executionErrors: string[] = [];
  const observerConfigCleanup = {
    registrationAttempted: false,
    registered: false,
    deleteAttempted: false,
    deleted: false,
    errors: [] as string[],
  };

  async function runPhase(
    phase: "baseline" | "deny",
    policy: NetworkPolicy,
    work: (
      sandbox: Sandbox,
      phaseRecord: PhaseRecord,
      runProbe: (caseId: string, destinationHost: string) => Promise<ProbeRecord>,
    ) => Promise<void>,
  ): Promise<PhaseRecord> {
    const phaseRecord: PhaseRecord = {
      phase,
      policy,
      probes: [],
      events: [],
      actions: [],
      cleanup: {
        stopAttempted: false,
        stopped: false,
        deleteAttempted: false,
        deleted: false,
        errors: [],
      },
    };
    phases.push(phaseRecord);
    let sandbox: Sandbox | undefined;
    try {
      await gate.beforeCall();
      sandbox = await Sandbox.create({
        name: `sbx-003-021-${phase}-${runId.slice(0, 8)}`,
        persistent: false,
        timeout: 300_000,
        networkPolicy: policy,
        tags: { harness: "vsc", test: "SBX-003-021", phase, run: runId.slice(0, 12) },
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
      await gate.beforeCall();
      await sandbox.writeFiles([{ path: remoteProbePath, content: guestProbeSource, mode: 0o700 }]);

      const runProbe = async (caseId: string, destinationHost: string): Promise<ProbeRecord> => {
        const query = new URLSearchParams({
          __sbx_run: runId,
          __sbx_test: testId,
          __sbx_case: caseId,
          __sbx_canary: correlationCanary,
        });
        const guestConfiguration = {
          scopeConfirmation: "researcher-controlled-endpoints-only",
          researcherControlledHosts: [
            configuration.hostname,
            configuration.deniedIPv4,
            configuration.allowedIPv4,
          ],
          runId,
          testId,
          caseId,
          destinationHost,
          destinationPort: 443,
          tlsServername: configuration.hostname,
          httpHost: configuration.hostname,
          method: "GET",
          requestTarget: `/v1/probe/${encodeURIComponent(runId)}/vhost-action?${query}`,
          headers: { "x-sbx-correlation": correlationCanary },
          timeoutMs: 10_000,
          maxResponseBodyBytes: 4_096,
        };
        const serialized = JSON.stringify(guestConfiguration);
        if (guestForbiddenValues.some((value) => serialized.includes(value))) {
          throw new Error(`${caseId} guest configuration contains controller-only material`);
        }
        await gate.beforeCall();
        const command = await sandbox!.runCommand({
          cmd: "node",
          args: [remoteProbePath, Buffer.from(serialized).toString("base64url")],
          timeoutMs: 15_000,
        });
        const [stdout, stderr] = await Promise.all([command.stdout(), command.stderr()]);
        let result: Record<string, unknown>;
        try {
          result = JSON.parse(stdout) as Record<string, unknown>;
        } catch {
          throw new Error(`${caseId} emitted invalid JSON`);
        }
        const probe = {
          caseId,
          destinationHost,
          exitCode: command.exitCode,
          result,
          stderr: stderr.slice(0, 2_000),
        };
        phaseRecord.probes.push(probe);
        return probe;
      };

      await work(sandbox, phaseRecord, runProbe);
      await new Promise((resolveWait) => setTimeout(resolveWait, 1_000));
      const caseIds = new Set(phaseRecord.probes.map((probe) => probe.caseId));
      const [events, actions] = await Promise.all([
        observerClient.events(runId),
        vhostActions(configuration, runId),
      ]);
      phaseRecord.events = events.filter((event) => caseIds.has(event.caseId));
      phaseRecord.actions = actions.filter((action) => caseIds.has(action.caseId));
    } catch (error) {
      phaseRecord.error = error instanceof Error ? error.message : String(error);
      try {
        const caseIds = new Set(phaseRecord.probes.map((probe) => probe.caseId));
        const [events, actions] = await Promise.all([
          observerClient.events(runId),
          vhostActions(configuration, runId),
        ]);
        phaseRecord.events = events.filter((event) => caseIds.has(event.caseId));
        phaseRecord.actions = actions.filter((action) => caseIds.has(action.caseId));
      } catch (evidenceError) {
        phaseRecord.error += `; evidence query: ${evidenceError instanceof Error ? evidenceError.message : String(evidenceError)}`;
      }
    } finally {
      if (sandbox) {
        phaseRecord.cleanup.stopAttempted = true;
        try {
          await gate.beforeCall();
          await sandbox.stop();
          phaseRecord.cleanup.stopped = true;
        } catch (error) {
          phaseRecord.cleanup.errors.push(`stop: ${error instanceof Error ? error.message : String(error)}`);
        }
        phaseRecord.cleanup.deleteAttempted = true;
        try {
          await gate.beforeCall();
          await sandbox.delete();
          phaseRecord.cleanup.deleted = true;
        } catch (error) {
          phaseRecord.cleanup.errors.push(`delete: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
    }
    return phaseRecord;
  }

  let baseline: PhaseRecord | undefined;
  let deny: PhaseRecord | undefined;
  try {
    await observerClient.health();
    observerConfigCleanup.registrationAttempted = true;
    await registerVhost(configuration, runId);
    observerConfigCleanup.registered = true;

    baseline = await runPhase("baseline", "allow-all", async (_sandbox, _phase, runProbe) => {
      await runProbe("baseline-fixed-t", configuration.deniedIPv4);
      await runProbe("baseline-fixed-s", configuration.allowedIPv4);
    });

    const baselineTargetReached = successfulProbe(
      baseline,
      runId,
      "baseline-fixed-t",
      correlationCanary,
      configuration.hostname,
      configuration.deniedIPv4,
    );
    const baselineSafeReached = successfulProbe(
      baseline,
      runId,
      "baseline-fixed-s",
      correlationCanary,
      configuration.hostname,
      configuration.allowedIPv4,
    );
    if (baselineTargetReached && baselineSafeReached && phaseCleanupPassed(baseline)) {
      const denyPolicy: NetworkPolicy = {
        allow: [configuration.hostname],
        subnets: { deny: [`${configuration.deniedIPv4}/32`] },
      };
      deny = await runPhase("deny", denyPolicy, async (_sandbox, _phaseRecord, runProbe) => {
        const fixedTarget = await runProbe("deny-fixed-t", configuration.deniedIPv4);
        const fixedSafe = await runProbe("deny-fixed-s", configuration.allowedIPv4);
        if (!preliminaryBlocked(fixedTarget) || !preliminarySuccess(fixedSafe)) return;

        for (let index = 0; index < configuration.epochPlan.length; index += 1) {
          const symbol = configuration.epochPlan[index]!;
          const epoch = await waitForDnsEpoch(configuration, symbol, index);
          dnsEpochs.push(epoch);
          if (!epoch.confirmedAt) break;
          const caseId = `deny-hostname-epoch-${String(index + 1).padStart(2, "0")}-${symbol.toLowerCase()}`;
          epoch.probeCaseId = caseId;
          await runProbe(caseId, configuration.hostname);
        }
      });
    }
  } catch (error) {
    executionErrors.push(error instanceof Error ? error.message : String(error));
  } finally {
    if (observerConfigCleanup.registrationAttempted) {
      observerConfigCleanup.deleteAttempted = true;
      try {
        observerConfigCleanup.deleted = await deleteVhost(configuration, runId);
        if (!observerConfigCleanup.deleted) {
          observerConfigCleanup.errors.push("observer vhost config delete did not return 204");
        }
      } catch (error) {
        observerConfigCleanup.errors.push(error instanceof Error ? error.message : String(error));
      }
    }
  }

  const baselineTargetReached = successfulProbe(
    baseline,
    runId,
    "baseline-fixed-t",
    correlationCanary,
    configuration.hostname,
    configuration.deniedIPv4,
  );
  const baselineSafeReached = successfulProbe(
    baseline,
    runId,
    "baseline-fixed-s",
    correlationCanary,
    configuration.hostname,
    configuration.allowedIPv4,
  );
  const fixedTargetBlocked = blockedProbe(deny, "deny-fixed-t");
  const fixedSafeReached = successfulProbe(
    deny,
    runId,
    "deny-fixed-s",
    correlationCanary,
    configuration.hostname,
    configuration.allowedIPv4,
  );
  const epochAssessments: EpochAssessment[] = dnsEpochs.map((epoch) => {
    const caseId = epoch.probeCaseId;
    const guestLookupMatches = caseId !== undefined && probeLookupMatches(
      deny,
      caseId,
      epoch.expectedAddress,
    );
    return {
      symbol: epoch.symbol,
      controllerConfirmed: epoch.confirmedAt !== undefined,
      guestLookupMatches,
      targetCrossed: caseId !== undefined && epoch.symbol === "T" && successfulProbe(
        deny,
        runId,
        caseId,
        correlationCanary,
        configuration.hostname,
        configuration.deniedIPv4,
      ),
      targetBlocked: caseId !== undefined && epoch.symbol === "T" && blockedProbe(
        deny,
        caseId,
        configuration.deniedIPv4,
      ),
      safeReached: caseId !== undefined && epoch.symbol === "S" && successfulProbe(
        deny,
        runId,
        caseId,
        correlationCanary,
        configuration.hostname,
        configuration.allowedIPv4,
      ),
    };
  });
  const phaseErrors = phases.flatMap((phase) => phase.error ? [`${phase.phase}: ${phase.error}`] : []);
  const cleanupErrors = phases.flatMap((phase) =>
    phase.cleanup.errors.map((error) => `${phase.phase}: ${error}`)
  );
  executionErrors.push(...phaseErrors, ...cleanupErrors, ...observerConfigCleanup.errors);
  const assessmentInput: MixedDnsAssessmentInput = {
    baselineControlsPassed: baselineTargetReached && baselineSafeReached,
    baselineCleanupPassed: phaseCleanupPassed(baseline),
    fixedTargetBlocked,
    fixedSafeReached,
    denyCleanupPassed: phaseCleanupPassed(deny),
    observerConfigCleanupPassed: observerConfigCleanup.deleted && observerConfigCleanup.errors.length === 0,
    executionErrors,
    epochs: epochAssessments,
  };
  const outcome = classifyMixedDns(assessmentInput);
  const candidate = outcome === "candidate";
  const evidence = {
    schemaVersion: 1,
    testId: "SBX-003-021",
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    outcome,
    candidate,
    configuration: {
      hostname: configuration.hostname,
      deniedIPv4: configuration.deniedIPv4,
      allowedIPv4: configuration.allowedIPv4,
      epochPlan: configuration.epochPlan,
      epochTimeoutMs: configuration.epochTimeoutMs,
      dnsPollIntervalMs: configuration.dnsPollIntervalMs,
      scopeConfirmation,
      minimumVercelCallIntervalMs,
    },
    policies: {
      baseline: "allow-all",
      deny: {
        allow: [configuration.hostname],
        subnets: { deny: [`${configuration.deniedIPv4}/32`] },
      },
    },
    controls: {
      baselineTargetReached,
      baselineSafeReached,
      baselineCleanupPassed: phaseCleanupPassed(baseline),
      fixedTargetBlocked,
      fixedSafeReached,
      denyCleanupPassed: phaseCleanupPassed(deny),
      observerConfigCleanupPassed: assessmentInput.observerConfigCleanupPassed,
    },
    signals: {
      targetCrossed: epochAssessments.some((epoch) => epoch.targetCrossed),
      targetEpochBlocked: epochAssessments.some((epoch) => epoch.symbol === "T" && epoch.targetBlocked),
    },
    dnsEpochs,
    epochAssessments,
    phases,
    observerConfigCleanup,
    executionErrors,
  };
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const privateEvidencePath = resolve(
    artifactsDirectory,
    `SBX-003-021-poc-${runId}-private.json`,
  );
  await writeFile(privateEvidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify({
    outcome,
    candidate,
    controls: evidence.controls,
    signals: evidence.signals,
    epochs: epochAssessments,
    cleanup: phases.map((phase) => ({ phase: phase.phase, cleanup: phase.cleanup })),
    observerConfigCleanup,
    privateEvidencePath,
  }, null, 2)}\n`);
  if (executionErrors.length > 0) throw new Error(executionErrors.join("; "));
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
