import "dotenv/config";

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { resolve4 } from "node:dns/promises";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Sandbox, type NetworkPolicy } from "@vercel/sandbox";
import { HttpObserverClient } from "../../src/observer-client.js";
import type { ObserverEvent } from "../../src/contracts.js";

const brokeredHeader = "x-sbx-harness-canary";
const remoteProbe = "/tmp/sbx-018/policy-update-socket-probe.mjs";

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

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
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
  const correlationCanary = `corr_${randomBytes(18).toString("base64url")}`;
  const brokeredSecret = `broker_${randomBytes(24).toString("base64url")}`;
  const caseId = "existing-tls-after-deny";
  const readinessPath = `/tmp/sbx-018/${runId}-ready.json`;
  const triggerPath = `/tmp/sbx-018/${runId}-trigger`;
  const resultPath = `/tmp/sbx-018/${runId}-result.json`;
  const initialPolicy = {
    allow: {
      [observer.hostname]: [{ transform: [{ headers: { [brokeredHeader]: brokeredSecret } }] }],
    },
  } satisfies NetworkPolicy;
  const cleanup = { stopped: false, deleted: false, errors: [] as string[] };
  const policyUpdate: {
    requestedAt?: string;
    completedAt?: string;
    returnedPolicy?: unknown;
    settleDelayMs: number;
    triggerWriteRequestedAt?: string;
  } = { settleDelayMs: 5_000 };
  let sandbox: Sandbox | undefined;
  let sandboxIdentity: Record<string, unknown> | undefined;
  let readiness: Record<string, unknown> | undefined;
  let guestResult: Record<string, unknown> | undefined;
  let guestCommand: Record<string, unknown> | undefined;
  let stdoutMatchesPersistedResult = false;
  let allEvents: ObserverEvent[] = [];
  let executionError: string | undefined;

  try {
    sandbox = await Sandbox.create({
      name: `sbx-018-poc-${runId.slice(0, 8)}`,
      persistent: false,
      timeout: 300_000,
      networkPolicy: initialPolicy,
      tags: { harness: "vsc", test: "SBX-018", run: runId.slice(0, 12) },
      ...explicitCredentials(),
    });
    const session = sandbox.currentSession();
    sandboxIdentity = {
      name: sandbox.name,
      sessionId: session.sessionId,
      sessionCreatedAt: session.createdAt.toISOString(),
      region: session.region,
    };
    const probeSource = await readFile(resolve("guest/policy-update-socket-probe.mjs"), "utf8");
    await sandbox.writeFiles([{
      path: remoteProbe,
      content: probeSource,
      mode: 0o700,
    }]);

    const configuration = {
      scopeConfirmation: "I_CONTROL_THE_CONFIGURED_ORIGIN",
      researcherControlledHosts: [observer.hostname, fixedTargetIp],
      connectHost: fixedTargetIp,
      connectPort: observer.port ? Number(observer.port) : 443,
      sniHost: observer.hostname,
      httpHost: observer.hostname,
      rawPath: `/v1/probe/${encodeURIComponent(runId)}/policy-update`,
      correlation: { runId, testId: "SBX-018-POC", caseId, canary: correlationCanary },
      readinessPath,
      triggerPath,
      resultPath,
      ioTimeoutMs: 12_000,
      triggerTimeoutMs: 60_000,
      maxResponseBytes: 4_096,
    };
    const serialized = JSON.stringify(configuration);
    const forbiddenGuestValues = [adminKey, brokeredSecret, process.env.VERCEL_TOKEN ?? ""].filter(Boolean);
    if (forbiddenGuestValues.some((value) => serialized.includes(value) || probeSource.includes(value))) {
      throw new Error("proof invalid: uploaded guest material contains controller-only material");
    }

    const command = await sandbox.runCommand({
      cmd: "node",
      args: [remoteProbe, Buffer.from(serialized).toString("base64url")],
      detached: true,
      timeoutMs: 90_000,
    });
    readiness = asRecord(JSON.parse((await waitForSandboxFile(sandbox, readinessPath, 25_000)).toString("utf8")));
    if (readiness?.ready !== true || readiness.handshakeCount !== 1 || typeof readiness.primarySocketId !== "string") {
      throw new Error("guest readiness control was invalid");
    }

    await new Promise((resolveWait) => setTimeout(resolveWait, 750));
    const preUpdateEvents = await observerClient.events(runId);
    const preEvent = preUpdateEvents.find((event) => eventPhase(event) === "pre-update");
    if (preUpdateEvents.length !== 1 || preEvent === undefined || singleHeader(preEvent, brokeredHeader) !== brokeredSecret) {
      throw new Error("pre-update transform/reachability control failed");
    }

    policyUpdate.requestedAt = new Date().toISOString();
    policyUpdate.returnedPolicy = await sandbox.updateNetworkPolicy("deny-all");
    policyUpdate.completedAt = new Date().toISOString();
    if (policyUpdate.returnedPolicy !== "deny-all") throw new Error("policy update did not return deny-all");
    await new Promise((resolveWait) => setTimeout(resolveWait, policyUpdate.settleDelayMs));
    policyUpdate.triggerWriteRequestedAt = new Date().toISOString();
    await sandbox.writeFiles([{
      path: triggerPath,
      content: `deny-all-complete ${policyUpdate.completedAt}\n`,
      mode: 0o600,
    }]);

    const finished = await command.wait({ signal: AbortSignal.timeout(45_000) });
    const [stdout, stderr, persistedResult] = await Promise.all([
      finished.stdout(),
      finished.stderr(),
      waitForSandboxFile(sandbox, resultPath, 5_000),
    ]);
    guestResult = asRecord(JSON.parse(persistedResult.toString("utf8")));
    const stdoutResult = asRecord(JSON.parse(stdout));
    stdoutMatchesPersistedResult = JSON.stringify(stdoutResult) === JSON.stringify(guestResult);
    guestCommand = {
      commandId: finished.cmdId,
      exitCode: finished.exitCode,
      durationMs: finished.durationMs,
      stdout: stdout.slice(0, 16_000),
      stderr: stderr.slice(0, 4_000),
    };
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

  const primaryTls = asRecord(guestResult?.primaryTls);
  const preUpdate = asRecord(guestResult?.preUpdate);
  const preResponse = asRecord(preUpdate?.response);
  const reusedPost = asRecord(guestResult?.reusedPost);
  const freshPost = asRecord(guestResult?.freshPost);
  const exactEvent = (event: ObserverEvent, phase: string): boolean =>
    event.testId === "SBX-018-POC" && event.caseId === caseId && event.canary === correlationCanary &&
    eventPhase(event) === phase;
  const preEvent = allEvents.find((event) => exactEvent(event, "pre-update"));
  const updateCompletedMs = policyUpdate.completedAt ? Date.parse(policyUpdate.completedAt) : Number.NaN;
  const postEvent = (event: ObserverEvent, phase: string): boolean =>
    exactEvent(event, phase) && Date.parse(event.observedAt) >= updateCompletedMs;
  const reusedEvent = allEvents.find((event) => postEvent(event, "post-reused"));
  const freshEvent = allEvents.find((event) => postEvent(event, "post-new"));
  const trigger = asRecord(guestResult?.trigger);
  const triggerObservedAfterUpdate = typeof trigger?.observedAt === "string" &&
    Date.parse(trigger.observedAt) > updateCompletedMs;
  const socketAttributionPassed = typeof readiness?.primarySocketId === "string" &&
    readiness.primarySocketId === asRecord(primaryTls?.socket)?.id &&
    readiness.primarySocketId === reusedPost?.socketId &&
    primaryTls?.handshakeCount === 1 && reusedPost?.handshakeCount === 1 &&
    reusedPost?.sameSocketAsPreUpdate === true;
  const commandIntegrityPassed = guestCommand?.exitCode === 0 && stdoutMatchesPersistedResult;
  const preControlPassed = guestResult?.ok === true && primaryTls?.authorized === true &&
    primaryTls.handshakeCount === 1 && preResponse?.statusCode === 204 && preEvent !== undefined &&
    singleHeader(preEvent, brokeredHeader) === brokeredSecret;
  const policyUpdateConfirmed = policyUpdate.returnedPolicy === "deny-all" && policyUpdate.completedAt !== undefined &&
    typeof policyUpdate.triggerWriteRequestedAt === "string" &&
    Date.parse(policyUpdate.triggerWriteRequestedAt) - updateCompletedMs >= policyUpdate.settleDelayMs &&
    triggerObservedAfterUpdate;
  const reusedCrossedBoundary = reusedEvent !== undefined;
  const freshCrossedBoundary = freshEvent !== undefined;
  const anyPostUpdateBoundaryCrossing = reusedCrossedBoundary || freshCrossedBoundary;
  const postUpdateBrokeredSecretObserved = [reusedEvent, freshEvent].some(
    (event) => singleHeader(event, brokeredHeader) === brokeredSecret,
  );
  const reusedBlocked = reusedPost?.requestSucceeded === false && reusedEvent === undefined;
  const freshBlocked = freshPost?.requestSucceeded === false && freshEvent === undefined;
  const guestResponseContainsBrokeredSecret = JSON.stringify(guestResult ?? {}).includes(brokeredSecret);
  const operationalFailure = executionError !== undefined || cleanup.errors.length > 0;
  const controlsPassed = preControlPassed && policyUpdateConfirmed && socketAttributionPassed && commandIntegrityPassed;
  const outcome = operationalFailure || !controlsPassed
    ? "indeterminate"
    : anyPostUpdateBoundaryCrossing
      ? "candidate"
      : reusedBlocked && freshBlocked
        ? "pass"
        : "indeterminate";

  const evidence = {
    schemaVersion: 1,
    testId: "SBX-018",
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    outcome,
    candidate: outcome === "candidate",
    controlsPassed,
    controls: {
      preControlPassed,
      policyUpdateConfirmed,
      triggerObservedAfterUpdate,
      socketAttributionPassed,
      commandIntegrityPassed,
      reusedBlocked,
      freshBlocked,
    },
    signals: { reusedCrossedBoundary, freshCrossedBoundary, anyPostUpdateBoundaryCrossing, postUpdateBrokeredSecretObserved },
    guestConfigurationContainsBrokeredSecret: false,
    guestResponseContainsBrokeredSecret,
    controllerBrokeredSecretSha256: sha256(brokeredSecret),
    postUpdateObservedSecretSha256: sha256(singleHeader(reusedEvent, brokeredHeader) ?? singleHeader(freshEvent, brokeredHeader) ?? ""),
    sandbox: sandboxIdentity,
    dns: { resolvedAt: dnsResolvedAt, answers: dnsAnswers, fixedTargetIp },
    initialPolicy,
    policyUpdate,
    readiness,
    guestCommand,
    guestResult,
    observerEvents: allEvents,
    executionError,
    cleanup,
  };
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const privateEvidencePath = resolve(artifactsDirectory, `SBX-018-poc-${runId}-private.json`);
  await writeFile(privateEvidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify({
    outcome,
    controlsPassed,
    candidate: outcome === "candidate",
    controls: evidence.controls,
    signals: evidence.signals,
    cleanup,
    privateEvidencePath,
  }, null, 2)}\n`);
  if (operationalFailure) throw new Error([executionError, ...cleanup.errors].filter(Boolean).join("; "));
}

await main();
