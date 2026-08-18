import "dotenv/config";

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { resolve4 } from "node:dns/promises";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Sandbox, type Command, type NetworkPolicy } from "@vercel/sandbox";
import { HttpObserverClient } from "../../src/observer-client.js";
import type { ObserverEvent } from "../../src/contracts.js";
import { waitUntil } from "../../src/timing.js";

const testId = "SBX-018-MULTI-POC";
const brokeredHeader = "x-sbx-harness-canary";
const remoteSocketProbe = "/tmp/sbx-018/policy-update-socket-probe.mjs";
const remoteAuthorityProbe = "/tmp/sbx-018/authority-probe.mjs";
const triggerOffsetsMs = [250, 750, 1_500] as const;

interface CommandRecord {
  commandId: string;
  exitCode: number;
  durationMs?: number;
  stdout: string;
  stderr: string;
}

interface SocketState {
  index: number;
  caseId: string;
  canary: string;
  readinessPath: string;
  triggerPath: string;
  resultPath: string;
  triggerOffsetMs: number;
  triggerWriteRequestedAt?: string;
  triggerWriteCompletedAt?: string;
  configurationSha256?: string;
  command?: Command;
  readiness?: Record<string, unknown>;
  guestResult?: Record<string, unknown>;
  commandRecord?: CommandRecord;
  stdoutMatchesPersistedResult: boolean;
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function controlledOrigin(): URL {
  const url = new URL(required("OBSERVER_BASE_URL"));
  if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
    throw new Error("OBSERVER_BASE_URL must be an HTTPS origin without credentials, path, query, or fragment");
  }
  return url;
}

function explicitCredentials(): { token: string; teamId: string; projectId: string } | Record<string, never> {
  const token = process.env.VERCEL_TOKEN;
  const teamId = process.env.VERCEL_TEAM_ID;
  const projectId = process.env.VERCEL_PROJECT_ID;
  const count = [token, teamId, projectId].filter(Boolean).length;
  if (count !== 0 && count !== 3) {
    throw new Error("VERCEL_TOKEN, VERCEL_TEAM_ID, and VERCEL_PROJECT_ID must be supplied together");
  }
  return count === 3 ? { token: token!, teamId: teamId!, projectId: projectId! } : {};
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function parseRecordJson(value: string, label: string): Record<string, unknown> {
  const record = asRecord(JSON.parse(value));
  if (!record) throw new Error(`${label} did not contain a JSON object`);
  return record;
}

function singleHeader(event: ObserverEvent | undefined, name: string): string | undefined {
  const value = event?.headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

function eventPhase(event: ObserverEvent): string | undefined {
  try {
    return new URL(event.rawUrl, "https://observer.invalid").searchParams.get("__sbx_phase") ?? undefined;
  } catch {
    return undefined;
  }
}

function eventHost(event: ObserverEvent): string | undefined {
  if (!event.host) return undefined;
  try {
    return new URL(`https://${event.host}/`).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

function timestamp(value: unknown): number {
  return typeof value === "string" ? Date.parse(value) : Number.NaN;
}

async function waitForSandboxFile(sandbox: Sandbox, path: string, timeoutMs: number): Promise<Buffer> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const value = await sandbox.readFileToBuffer({ path });
    if (value !== null) return value;
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  throw new Error(`timed out waiting for ${path}`);
}

function socketEvidence(state: SocketState): Record<string, unknown> {
  return {
    index: state.index,
    caseId: state.caseId,
    correlationCanarySha256: sha256(state.canary),
    triggerOffsetMs: state.triggerOffsetMs,
    triggerWriteRequestedAt: state.triggerWriteRequestedAt,
    triggerWriteCompletedAt: state.triggerWriteCompletedAt,
    configurationSha256: state.configurationSha256,
    readiness: state.readiness,
    guestResult: state.guestResult,
    command: state.commandRecord,
    stdoutMatchesPersistedResult: state.stdoutMatchesPersistedResult,
  };
}

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  const observer = controlledOrigin();
  const adminKey = required("OBSERVER_ADMIN_KEY");
  const observerClient = new HttpObserverClient(observer.origin, adminKey);
  await observerClient.health();
  const dnsResolvedAt = new Date().toISOString();
  const dnsAnswers = await resolve4(observer.hostname, { ttl: true });
  const fixedTargetIp = dnsAnswers[0]?.address;
  if (!fixedTargetIp) throw new Error("controlled observer did not resolve to an IPv4 address");

  const runId = randomUUID();
  const brokeredSecret = `broker_${randomBytes(24).toString("base64url")}`;
  const freshBarrierCaseId = "fresh-same-ip-barrier";
  const freshBarrierCanary = `corr_${randomBytes(18).toString("base64url")}`;
  const requestPath = `/v1/probe/${encodeURIComponent(runId)}/policy-update-multi`;
  const socketStates: SocketState[] = triggerOffsetsMs.map((triggerOffsetMs, index) => ({
    index,
    caseId: `existing-socket-${index + 1}`,
    canary: `corr_${randomBytes(18).toString("base64url")}`,
    readinessPath: `/tmp/sbx-018/${runId}-${index + 1}-ready.json`,
    triggerPath: `/tmp/sbx-018/${runId}-${index + 1}-trigger`,
    resultPath: `/tmp/sbx-018/${runId}-${index + 1}-result.json`,
    triggerOffsetMs,
    stdoutMatchesPersistedResult: false,
  }));
  const initialPolicy = {
    allow: {
      [observer.hostname]: [{ transform: [{ headers: { [brokeredHeader]: brokeredSecret } }] }],
    },
  } satisfies NetworkPolicy;
  const policyUpdate: {
    requestedAt?: string;
    completedAt?: string;
    returnedPolicy?: unknown;
  } = {};
  const freshBarrier: {
    requestedAt?: string;
    commandCompletedAt?: string;
    evidenceCheckedAt?: string;
    configurationSha256?: string;
    result?: Record<string, unknown>;
    command?: CommandRecord;
    blockedBeforeOldTriggers?: boolean;
  } = {};
  const triggerSchedule: { epochAt?: string } = {};
  const cleanup = { stopped: false, deleted: false, errors: [] as string[] };
  let sandbox: Sandbox | undefined;
  let sandboxIdentity: Record<string, unknown> | undefined;
  let allEvents: ObserverEvent[] = [];
  let executionError: string | undefined;
  let guestMaterialGuardPassed = false;

  try {
    sandbox = await Sandbox.create({
      name: `sbx-018-multi-${runId.slice(0, 8)}`,
      persistent: false,
      timeout: 300_000,
      networkPolicy: initialPolicy,
      tags: { harness: "vsc", test: "SBX-018-MULTI", run: runId.slice(0, 12) },
      ...explicitCredentials(),
    });
    const session = sandbox.currentSession();
    sandboxIdentity = {
      name: sandbox.name,
      sessionId: session.sessionId,
      sessionCreatedAt: session.createdAt.toISOString(),
      region: session.region,
    };
    const [socketProbeSource, authorityProbeSource] = await Promise.all([
      readFile(resolve("guest/policy-update-socket-probe.mjs"), "utf8"),
      readFile(resolve("guest/authority-probe.mjs"), "utf8"),
    ]);
    const forbiddenGuestValues = [adminKey, brokeredSecret, process.env.VERCEL_TOKEN ?? ""].filter(Boolean);
    if (forbiddenGuestValues.some((value) => socketProbeSource.includes(value) || authorityProbeSource.includes(value))) {
      throw new Error("proof invalid: uploaded guest source contains controller-only material");
    }
    await sandbox.writeFiles([
      { path: remoteSocketProbe, content: socketProbeSource, mode: 0o700 },
      { path: remoteAuthorityProbe, content: authorityProbeSource, mode: 0o700 },
    ]);
    const activeSandbox = sandbox;

    for (const state of socketStates) {
      const configuration = {
        scopeConfirmation: "I_CONTROL_THE_CONFIGURED_ORIGIN",
        researcherControlledHosts: [observer.hostname, fixedTargetIp],
        connectHost: fixedTargetIp,
        connectPort: observer.port ? Number(observer.port) : 443,
        sniHost: observer.hostname,
        httpHost: observer.hostname,
        rawPath: requestPath,
        correlation: { runId, testId, caseId: state.caseId, canary: state.canary },
        readinessPath: state.readinessPath,
        triggerPath: state.triggerPath,
        resultPath: state.resultPath,
        ioTimeoutMs: 12_000,
        triggerTimeoutMs: 90_000,
        maxResponseBytes: 4_096,
      };
      const serialized = JSON.stringify(configuration);
      if (forbiddenGuestValues.some((value) => serialized.includes(value))) {
        throw new Error(`proof invalid: ${state.caseId} configuration contains controller-only material`);
      }
      state.configurationSha256 = sha256(serialized);
      state.command = await activeSandbox.runCommand({
        cmd: "node",
        args: [remoteSocketProbe, Buffer.from(serialized).toString("base64url")],
        detached: true,
        timeoutMs: 120_000,
      });
    }
    guestMaterialGuardPassed = true;

    await Promise.all(socketStates.map(async (state) => {
      const value = await waitForSandboxFile(activeSandbox, state.readinessPath, 25_000);
      state.readiness = parseRecordJson(value.toString("utf8"), `${state.caseId} readiness`);
      if (
        state.readiness?.ready !== true ||
        state.readiness.handshakeCount !== 1 ||
        state.readiness.preStatusCode !== 204 ||
        typeof state.readiness.primarySocketId !== "string"
      ) {
        throw new Error(`${state.caseId} readiness control was invalid`);
      }
    }));
    const readinessIds = socketStates.map((state) => state.readiness?.primarySocketId);
    if (new Set(readinessIds).size !== socketStates.length) {
      throw new Error("pre-update probes did not establish three distinct socket identities");
    }

    await new Promise((resolveWait) => setTimeout(resolveWait, 750));
    const preUpdateEvents = await observerClient.events(runId);
    const exactPreEvent = (event: ObserverEvent, state: SocketState): boolean =>
      event.testId === testId && event.caseId === state.caseId && event.canary === state.canary &&
      eventPhase(event) === "pre-update" && eventHost(event) === observer.hostname &&
      event.normalizedPath === requestPath;
    const preControlsPassed = preUpdateEvents.length === socketStates.length && socketStates.every((state) => {
      const events = preUpdateEvents.filter((event) => exactPreEvent(event, state));
      return events.length === 1 && singleHeader(events[0], brokeredHeader) === brokeredSecret;
    });
    if (!preControlsPassed) throw new Error("three-socket pre-update transform controls failed");

    policyUpdate.requestedAt = new Date().toISOString();
    policyUpdate.returnedPolicy = await activeSandbox.updateNetworkPolicy("deny-all");
    policyUpdate.completedAt = new Date().toISOString();
    if (policyUpdate.returnedPolicy !== "deny-all") throw new Error("policy update did not return deny-all");

    const barrierQuery = new URLSearchParams({
      __sbx_run: runId,
      __sbx_test: testId,
      __sbx_case: freshBarrierCaseId,
      __sbx_canary: freshBarrierCanary,
      __sbx_phase: "fresh-barrier",
    });
    const barrierConfiguration = {
      scopeConfirmation: "researcher-controlled-endpoints-only",
      researcherControlledHosts: [observer.hostname, fixedTargetIp],
      runId,
      testId,
      caseId: freshBarrierCaseId,
      destinationHost: fixedTargetIp,
      destinationPort: observer.port ? Number(observer.port) : 443,
      tlsServername: observer.hostname,
      httpHost: observer.hostname,
      method: "GET",
      requestTarget: `${requestPath}?${barrierQuery}`,
      headers: {},
      timeoutMs: 12_000,
      maxResponseBodyBytes: 4_096,
      evidenceHeaderNames: [],
    };
    const serializedBarrier = JSON.stringify(barrierConfiguration);
    if (forbiddenGuestValues.some((value) => serializedBarrier.includes(value))) {
      throw new Error("proof invalid: fresh barrier configuration contains controller-only material");
    }
    freshBarrier.configurationSha256 = sha256(serializedBarrier);
    freshBarrier.requestedAt = new Date().toISOString();
    const barrierCommand = await activeSandbox.runCommand({
      cmd: "node",
      args: [remoteAuthorityProbe, Buffer.from(serializedBarrier).toString("base64url")],
      timeoutMs: 20_000,
    });
    freshBarrier.commandCompletedAt = new Date().toISOString();
    const [barrierStdout, barrierStderr] = await Promise.all([barrierCommand.stdout(), barrierCommand.stderr()]);
    freshBarrier.result = parseRecordJson(barrierStdout, "fresh barrier output");
    freshBarrier.command = {
      commandId: barrierCommand.cmdId,
      exitCode: barrierCommand.exitCode,
      ...(barrierCommand.durationMs !== undefined ? { durationMs: barrierCommand.durationMs } : {}),
      stdout: barrierStdout.slice(0, 16_000),
      stderr: barrierStderr.slice(0, 4_000),
    };
    await new Promise((resolveWait) => setTimeout(resolveWait, 750));
    const barrierEvents = await observerClient.events(runId);
    freshBarrier.evidenceCheckedAt = new Date().toISOString();
    const barrierEvent = barrierEvents.find((event) =>
      event.testId === testId && event.caseId === freshBarrierCaseId &&
      event.canary === freshBarrierCanary && eventPhase(event) === "fresh-barrier"
    );
    const prematureOldEvent = barrierEvents.find((event) =>
      socketStates.some((state) => event.testId === testId && event.caseId === state.caseId &&
        event.canary === state.canary && eventPhase(event) !== "pre-update")
    );
    freshBarrier.blockedBeforeOldTriggers = freshBarrier.result?.ok === false &&
      freshBarrier.command.exitCode === 0 && barrierStderr.length === 0 &&
      barrierEvent === undefined && prematureOldEvent === undefined;
    if (!freshBarrier.blockedBeforeOldTriggers) {
      throw new Error("fresh same-IP connection was not proven blocked before old-socket triggers");
    }

    const triggerEpochMs = Date.now();
    triggerSchedule.epochAt = new Date(triggerEpochMs).toISOString();
    for (const state of socketStates) {
      await waitUntil(triggerEpochMs + state.triggerOffsetMs);
      state.triggerWriteRequestedAt = new Date().toISOString();
      await activeSandbox.writeFiles([{
        path: state.triggerPath,
        content: `deny-all-barrier-complete ${freshBarrier.evidenceCheckedAt}\n`,
        mode: 0o600,
      }]);
      state.triggerWriteCompletedAt = new Date().toISOString();
    }

    await Promise.all(socketStates.map(async (state) => {
      if (!state.command) throw new Error(`${state.caseId} has no detached command`);
      const finished = await state.command.wait({ signal: AbortSignal.timeout(60_000) });
      const [stdout, stderr, persisted] = await Promise.all([
        finished.stdout(),
        finished.stderr(),
        waitForSandboxFile(activeSandbox, state.resultPath, 5_000),
      ]);
      state.guestResult = parseRecordJson(persisted.toString("utf8"), `${state.caseId} persisted result`);
      const stdoutResult = parseRecordJson(stdout, `${state.caseId} stdout`);
      state.stdoutMatchesPersistedResult = JSON.stringify(stdoutResult) === JSON.stringify(state.guestResult);
      state.commandRecord = {
        commandId: finished.cmdId,
        exitCode: finished.exitCode,
        ...(finished.durationMs !== undefined ? { durationMs: finished.durationMs } : {}),
        stdout: stdout.slice(0, 16_000),
        stderr: stderr.slice(0, 4_000),
      };
    }));
    await new Promise((resolveWait) => setTimeout(resolveWait, 1_500));
    allEvents = await observerClient.events(runId);
  } catch (error) {
    executionError = error instanceof Error ? error.message : String(error);
    try {
      allEvents = await observerClient.events(runId);
    } catch {
      // Preserve the original execution failure.
    }
  } finally {
    if (sandbox) {
      try {
        await sandbox.stop();
        cleanup.stopped = true;
      } catch (error) {
        cleanup.errors.push(`stop: ${error instanceof Error ? error.message : String(error)}`);
      }
      try {
        await sandbox.delete();
        cleanup.deleted = true;
      } catch (error) {
        cleanup.errors.push(`delete: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }

  const updateCompletedMs = timestamp(policyUpdate.completedAt);
  const barrierCompletedMs = timestamp(freshBarrier.evidenceCheckedAt);
  const triggerEpochMs = timestamp(triggerSchedule.epochAt);
  const exactEvent = (event: ObserverEvent, state: SocketState, phase: string): boolean =>
    event.testId === testId && event.caseId === state.caseId && event.canary === state.canary &&
    eventPhase(event) === phase && eventHost(event) === observer.hostname &&
    event.normalizedPath === requestPath;
  const socketAssessments = socketStates.map((state) => {
    const primaryTls = asRecord(state.guestResult?.primaryTls);
    const primarySocket = asRecord(primaryTls?.socket);
    const preUpdate = asRecord(state.guestResult?.preUpdate);
    const preResponse = asRecord(preUpdate?.response);
    const trigger = asRecord(state.guestResult?.trigger);
    const reusedPost = asRecord(state.guestResult?.reusedPost);
    const reusedResponse = asRecord(reusedPost?.response);
    const freshPost = asRecord(state.guestResult?.freshPost);
    const preEvents = allEvents.filter((event) => exactEvent(event, state, "pre-update"));
    const reusedEvents = allEvents.filter((event) =>
      exactEvent(event, state, "post-reused") && timestamp(event.observedAt) >= barrierCompletedMs &&
      timestamp(event.observedAt) >= timestamp(trigger?.observedAt)
    );
    const freshEvents = allEvents.filter((event) =>
      exactEvent(event, state, "post-new") && timestamp(event.observedAt) >= updateCompletedMs
    );
    const readinessId = state.readiness?.primarySocketId;
    const triggerTimingPassed = timestamp(state.triggerWriteRequestedAt) >= triggerEpochMs + state.triggerOffsetMs &&
      timestamp(trigger?.observedAt) >= timestamp(state.triggerWriteRequestedAt) &&
      timestamp(trigger?.observedAt) > barrierCompletedMs;
    const socketAttributionPassed = typeof readinessId === "string" &&
      readinessId === primarySocket?.id && readinessId === reusedPost?.socketId &&
      primarySocket?.remoteAddress === fixedTargetIp && primaryTls?.authorized === true &&
      primaryTls.handshakeCount === 1 && reusedPost?.handshakeCount === 1 &&
      reusedPost?.sameSocketAsPreUpdate === true;
    const preControlPassed = state.guestResult?.ok === true && preResponse?.statusCode === 204 &&
      preEvents.length === 1 && singleHeader(preEvents[0], brokeredHeader) === brokeredSecret;
    const commandIntegrityPassed = state.commandRecord?.exitCode === 0 &&
      state.commandRecord.stderr.length === 0 && state.stdoutMatchesPersistedResult;
    const builtInFreshBlocked = freshPost?.attempted === true && freshPost.requestSucceeded === false && freshEvents.length === 0;
    const guestResponseContainsBrokeredSecret = JSON.stringify(state.guestResult ?? {}).includes(brokeredSecret);
    const crossed = reusedPost?.requestSucceeded === true && reusedResponse?.statusCode === 204 &&
      reusedEvents.length === 1 && singleHeader(reusedEvents[0], brokeredHeader) === brokeredSecret;
    const reusedBlocked = reusedPost?.attempted === true && reusedPost.requestSucceeded === false && reusedEvents.length === 0;
    return {
      caseId: state.caseId,
      controlsPassed: preControlPassed && triggerTimingPassed && socketAttributionPassed &&
        commandIntegrityPassed && builtInFreshBlocked && !guestResponseContainsBrokeredSecret,
      preControlPassed,
      triggerTimingPassed,
      socketAttributionPassed,
      commandIntegrityPassed,
      builtInFreshBlocked,
      guestResponseContainsBrokeredSecret,
      crossed,
      reusedBlocked,
      preEventCount: preEvents.length,
      reusedEventCount: reusedEvents.length,
      builtInFreshEventCount: freshEvents.length,
      observedBrokeredSecretSha256: sha256(singleHeader(reusedEvents[0], brokeredHeader) ?? ""),
    };
  });
  const distinctSocketIds = new Set(socketStates.map((state) => state.readiness?.primarySocketId)).size === socketStates.length;
  const policyUpdateConfirmed = policyUpdate.returnedPolicy === "deny-all" && Number.isFinite(updateCompletedMs);
  const oldTriggersAfterBarrier = socketStates.every((state) =>
    timestamp(state.triggerWriteRequestedAt) > barrierCompletedMs
  );
  const finalFreshBarrierEventCount = allEvents.filter((event) =>
    event.testId === testId && event.caseId === freshBarrierCaseId &&
    event.canary === freshBarrierCanary && eventPhase(event) === "fresh-barrier"
  ).length;
  const commandAndSocketControlsPassed = socketAssessments.every((assessment) => assessment.controlsPassed);
  const freshBarrierPassed = freshBarrier.blockedBeforeOldTriggers === true &&
    timestamp(freshBarrier.requestedAt) >= updateCompletedMs &&
    timestamp(freshBarrier.evidenceCheckedAt) > timestamp(freshBarrier.commandCompletedAt) &&
    finalFreshBarrierEventCount === 0;
  const crossedCount = socketAssessments.filter((assessment) => assessment.crossed).length;
  const allReusedBlocked = socketAssessments.every((assessment) => assessment.reusedBlocked);
  const guestResponseContainsBrokeredSecret = socketAssessments.some((assessment) => assessment.guestResponseContainsBrokeredSecret) ||
    JSON.stringify(freshBarrier.result ?? {}).includes(brokeredSecret);
  const controlsPassed = guestMaterialGuardPassed && distinctSocketIds && policyUpdateConfirmed &&
    freshBarrierPassed && oldTriggersAfterBarrier && commandAndSocketControlsPassed;
  const operationalFailure = executionError !== undefined || cleanup.errors.length > 0;
  const outcome = operationalFailure || !controlsPassed
    ? "indeterminate"
    : crossedCount >= 1
      ? "candidate"
      : allReusedBlocked
        ? "pass"
        : "indeterminate";

  const evidence = {
    schemaVersion: 1,
    testId: "SBX-018-MULTI",
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    outcome,
    candidate: outcome === "candidate",
    crossedCount,
    controlsPassed,
    controls: {
      guestMaterialGuardPassed,
      distinctSocketIds,
      policyUpdateConfirmed,
      freshBarrierPassed,
      finalFreshBarrierEventCount,
      oldTriggersAfterBarrier,
      commandAndSocketControlsPassed,
      allBuiltInFreshAttemptsBlocked: socketAssessments.every((assessment) => assessment.builtInFreshBlocked),
    },
    guestConfigurationContainsBrokeredSecret: false,
    guestResponseContainsBrokeredSecret,
    controllerBrokeredSecretSha256: sha256(brokeredSecret),
    sandbox: sandboxIdentity,
    dns: { resolvedAt: dnsResolvedAt, answers: dnsAnswers, fixedTargetIp },
    initialPolicy,
    policyUpdate,
    freshBarrier: {
      caseId: freshBarrierCaseId,
      correlationCanarySha256: sha256(freshBarrierCanary),
      requestedAfterPolicyUpdateMs: timestamp(freshBarrier.requestedAt) - updateCompletedMs,
      evidenceCheckedAfterPolicyUpdateMs: timestamp(freshBarrier.evidenceCheckedAt) - updateCompletedMs,
      ...freshBarrier,
    },
    triggerSchedule,
    sockets: socketStates.map(socketEvidence),
    socketAssessments,
    observerEvents: allEvents,
    executionError,
    cleanup,
  };
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const privateEvidencePath = resolve(artifactsDirectory, `SBX-018-multi-poc-${runId}-private.json`);
  await writeFile(privateEvidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify({
    outcome,
    controlsPassed,
    candidate: outcome === "candidate",
    crossedCount,
    controls: evidence.controls,
    socketAssessments,
    cleanup,
    privateEvidencePath,
  }, null, 2)}\n`);
  if (operationalFailure) throw new Error([executionError, ...cleanup.errors].filter(Boolean).join("; "));
}

await main();
