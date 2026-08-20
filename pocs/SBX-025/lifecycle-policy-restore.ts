import "dotenv/config";

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { APIError, Sandbox, Snapshot, type NetworkPolicy } from "@vercel/sandbox";
import { HttpObserverClient } from "../../src/observer-client.js";
import type { ObserverEvent } from "../../src/contracts.js";
import {
  assessLifecyclePolicyRestore,
  type LifecycleAssessment,
} from "./verdict.js";

const brokeredHeader = "x-sbx-harness-canary";
const remoteProbePath = "/tmp/sbx-025/http-probe.mjs";

interface ActionRecord {
  operationId: string;
  authorizedAt: string;
  caseId: string;
  normalizedPath: string;
}

interface ProbeResult {
  ok: boolean;
  statusCode?: number;
  body?: string;
  error?: string;
  durationMs?: number;
}

interface ProbeRecord {
  caseId: string;
  startedAt: string;
  completedAt: string;
  configurationSha256: string;
  commandExitCode: number;
  result: ProbeResult;
  stdout: string;
  stderr: string;
}

interface SessionRecord {
  name: string;
  sessionId: string;
  sessionCreatedAt: string;
  sessionRequestedAt: string;
  region: string;
  sourceSnapshotId?: string;
  networkPolicy?: NetworkPolicy;
}

interface SnapshotCleanupRecord {
  snapshotId: string;
  attempted: boolean;
  deleted: boolean;
  alreadyAbsent?: boolean;
  error?: string;
}

class IndeterminateError extends Error {}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
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
    url.hash
  ) {
    throw new Error(
      "OBSERVER_BASE_URL must be a researcher-controlled HTTPS origin without credentials, path, query, or fragment",
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

function redact(value: string, secrets: string[]): string {
  return secrets.reduce(
    (result, secret) => secret.length === 0 ? result : result.split(secret).join("[REDACTED]"),
    value,
  );
}

function safeError(error: unknown, secrets: string[]): string {
  return redact(error instanceof Error ? error.message : String(error), secrets);
}

function isSnapshotAlreadyAbsent(error: unknown): boolean {
  if (!(error instanceof APIError)) return false;
  const payload = error.json as { error?: { code?: string } } | undefined;
  return error.response.status === 404 ||
    (error.response.status === 410 && payload?.error?.code === "snapshot_not_found");
}

function singleHeader(event: ObserverEvent | undefined, name: string): string | undefined {
  const value = event?.headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

function exactCaseEvent(events: ObserverEvent[], caseId: string): ObserverEvent | undefined {
  const matches = events.filter((event) => event.caseId === caseId);
  return matches.length === 1 ? matches[0] : undefined;
}

function exactCaseAction(actions: ActionRecord[], caseId: string): ActionRecord | undefined {
  const matches = actions.filter((action) => action.caseId === caseId);
  return matches.length === 1 ? matches[0] : undefined;
}

function parseActionBody(result: ProbeResult): {
  authorized?: boolean;
  operationId?: string;
  normalizedPath?: string;
} | undefined {
  if (!result.body) return undefined;
  try {
    const parsed = JSON.parse(result.body) as unknown;
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as { authorized?: boolean; operationId?: string; normalizedPath?: string }
      : undefined;
  } catch {
    return undefined;
  }
}

function sessionRecord(sandbox: Sandbox): SessionRecord {
  const session = sandbox.currentSession();
  return {
    name: sandbox.name,
    sessionId: session.sessionId,
    sessionCreatedAt: session.createdAt.toISOString(),
    sessionRequestedAt: session.requestedAt.toISOString(),
    region: session.region,
    ...(sandbox.sourceSnapshotId ? { sourceSnapshotId: sandbox.sourceSnapshotId } : {}),
    ...(sandbox.networkPolicy !== undefined ? { networkPolicy: sandbox.networkPolicy } : {}),
  };
}

function samePolicy(left: NetworkPolicy | undefined, right: NetworkPolicy): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

async function observerAdminRequest(
  observerBaseUrl: string,
  observerAdminKey: string,
  runId: string,
  resource: "action-config" | "actions",
  init?: RequestInit,
): Promise<Response> {
  const headers = new Headers(init?.headers);
  headers.set("authorization", `Bearer ${observerAdminKey}`);
  return fetch(new URL(`/v1/runs/${encodeURIComponent(runId)}/${resource}`, observerBaseUrl), {
    ...init,
    headers,
    signal: AbortSignal.timeout(10_000),
  });
}

async function observerActions(
  observerBaseUrl: string,
  observerAdminKey: string,
  runId: string,
): Promise<ActionRecord[]> {
  const response = await observerAdminRequest(observerBaseUrl, observerAdminKey, runId, "actions");
  if (!response.ok) throw new Error(`observer action query returned ${response.status}`);
  const payload = (await response.json()) as { actions?: ActionRecord[] };
  if (!Array.isArray(payload.actions)) throw new Error("observer returned invalid action evidence");
  return payload.actions;
}

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  const observer = controlledOrigin();
  const observerAdminKey = required("OBSERVER_ADMIN_KEY");
  const credentials = explicitCredentials();
  const observerClient = new HttpObserverClient(observer.origin, observerAdminKey);
  await observerClient.health();

  const runId = randomUUID();
  const sandboxName = `sbx-025-poc-${runId.slice(0, 8)}`;
  const correlationCanary = `corr_${randomBytes(18).toString("base64url")}`;
  const brokeredSecret = `broker_${randomBytes(24).toString("base64url")}`;
  const forbiddenGuestValues = [
    observerAdminKey,
    brokeredSecret,
    process.env.VERCEL_TOKEN ?? "",
  ].filter(Boolean);
  const actionPath = `/v1/probe/${runId}/outside`;
  const transformPolicy: NetworkPolicy = {
    allow: {
      [observer.hostname]: [
        { transform: [{ headers: { [brokeredHeader]: brokeredSecret } }] },
      ],
    },
  };
  const plainAllowPolicy: NetworkPolicy = { allow: [observer.hostname] };
  const guestProbeSource = await readFile(resolve("guest/http-probe.mjs"), "utf8");
  const probes: ProbeRecord[] = [];
  const snapshotIds = new Set<string>();
  const policyTransitions: Record<string, unknown>[] = [];
  const evidenceSnapshots: Array<{
    stage: string;
    events: ObserverEvent[];
    actions: ActionRecord[];
  }> = [];
  const controlSignals: Record<string, boolean> = {};
  const cleanup = {
    finalStopAttempted: false,
    finalStopped: false,
    snapshotEnumerationAttempted: false,
    snapshotEnumerationSucceeded: false,
    sandboxDeleteAttempted: false,
    sandboxDeleted: false,
    observerConfigDeleteAttempted: false,
    observerConfigDeleted: false,
    snapshots: [] as SnapshotCleanupRecord[],
    errors: [] as string[],
  };

  let sourceSandbox: Sandbox | undefined;
  let resumedSandbox: Sandbox | undefined;
  let activeHandleNeedsStop = false;
  let sourceSession: SessionRecord | undefined;
  let resumedSession: SessionRecord | undefined;
  let sourceStopRecord: Record<string, unknown> | undefined;
  let assessment: LifecycleAssessment | undefined;
  let executionError: string | undefined;
  let executionIndeterminate = false;

  async function snapshotEvidence(stage: string): Promise<{
    events: ObserverEvent[];
    actions: ActionRecord[];
  }> {
    const [events, actions] = await Promise.all([
      observerClient.events(runId),
      observerActions(observer.origin, observerAdminKey, runId),
    ]);
    evidenceSnapshots.push({ stage, events, actions });
    return { events, actions };
  }

  async function runProbe(sandbox: Sandbox, caseId: string): Promise<ProbeRecord> {
    const configuration = {
      baseUrl: observer.origin,
      runId,
      testId: "SBX-025-POC",
      caseId,
      canary: correlationCanary,
      method: "GET",
      rawPath: actionPath,
      headers: {},
      timeoutMs: 20_000,
    };
    const serialized = JSON.stringify(configuration);
    if (forbiddenGuestValues.some((value) => serialized.includes(value))) {
      throw new Error(`proof invalid: ${caseId} guest configuration contains controller-only material`);
    }
    const probeStartedAt = new Date().toISOString();
    const command = await sandbox.runCommand({
      cmd: "node",
      args: [remoteProbePath, Buffer.from(serialized).toString("base64url")],
      timeoutMs: 25_000,
    });
    const [stdout, stderr] = await Promise.all([command.stdout(), command.stderr()]);
    if (forbiddenGuestValues.some((value) => stdout.includes(value) || stderr.includes(value))) {
      throw new Error(`proof invalid: ${caseId} guest output disclosed controller-only material`);
    }
    let result: ProbeResult;
    try {
      result = JSON.parse(stdout) as ProbeResult;
    } catch {
      throw new Error(`${caseId} guest probe did not emit valid JSON`);
    }
    const record: ProbeRecord = {
      caseId,
      startedAt: probeStartedAt,
      completedAt: new Date().toISOString(),
      configurationSha256: sha256(serialized),
      commandExitCode: command.exitCode,
      result,
      stdout,
      stderr: stderr.slice(0, 2_000),
    };
    probes.push(record);
    return record;
  }

  function captureSnapshotId(value: string | undefined): void {
    if (value) snapshotIds.add(value);
  }

  try {
    if (guestProbeSource.includes(brokeredSecret) || guestProbeSource.includes(observerAdminKey)) {
      throw new Error("proof invalid: guest probe source contains controller-only material");
    }
    const registration = await observerAdminRequest(
      observer.origin,
      observerAdminKey,
      runId,
      "action-config",
      {
        method: "POST",
        headers: { "x-observer-action-secret": brokeredSecret },
      },
    );
    if (!registration.ok) throw new Error(`observer action registration returned ${registration.status}`);

    sourceSandbox = await Sandbox.create({
      name: sandboxName,
      persistent: true,
      timeout: 300_000,
      snapshotExpiration: 86_400_000,
      keepLastSnapshots: { count: 2, expiration: 86_400_000, deleteEvicted: true },
      networkPolicy: transformPolicy,
      tags: { harness: "vsc", test: "SBX-025", run: runId.slice(0, 12) },
      ...credentials,
    });
    activeHandleNeedsStop = true;
    sourceSession = sessionRecord(sourceSandbox);
    await sourceSandbox.writeFiles([{ path: remoteProbePath, content: guestProbeSource, mode: 0o700 }]);

    const preChangeProbe = await runProbe(sourceSandbox, "pre-change-transform-control");
    const preEvidence = await snapshotEvidence("pre-change-transform-control");
    const preEvent = exactCaseEvent(preEvidence.events, preChangeProbe.caseId);
    const preAction = exactCaseAction(preEvidence.actions, preChangeProbe.caseId);
    const preBody = parseActionBody(preChangeProbe.result);
    const preChangeTransformControlPassed =
      preChangeProbe.commandExitCode === 0 &&
      preChangeProbe.result.ok === true &&
      preChangeProbe.result.statusCode === 200 &&
      preBody?.authorized === true &&
      preBody.operationId !== undefined &&
      preBody.operationId === preAction?.operationId &&
      singleHeader(preEvent, brokeredHeader) === brokeredSecret &&
      preEvidence.actions.length === 1;
    controlSignals.preChangeTransformControlPassed = preChangeTransformControlPassed;
    if (!preChangeTransformControlPassed) {
      throw new IndeterminateError("pre-change credential transform control failed");
    }

    const tightenStartedAt = new Date().toISOString();
    await sourceSandbox.update({ networkPolicy: "deny-all" });
    const tightenCompletedAt = new Date().toISOString();
    const tightenAcknowledged = true;
    const tightenedReadback = await Sandbox.get({ name: sandboxName, resume: false, ...credentials });
    const tightenReadbackDenyAll = tightenedReadback.networkPolicy === "deny-all";
    controlSignals.tightenAcknowledged = tightenAcknowledged;
    controlSignals.tightenReadbackDenyAll = tightenReadbackDenyAll;
    policyTransitions.push({
      stage: "tighten-to-deny-all",
      startedAt: tightenStartedAt,
      completedAt: tightenCompletedAt,
      acknowledged: tightenAcknowledged,
      sourceHandleReadback: sourceSandbox.networkPolicy,
      independentReadback: tightenedReadback.networkPolicy,
    });
    if (!tightenReadbackDenyAll || sourceSandbox.networkPolicy !== "deny-all") {
      throw new IndeterminateError("deny-all update did not produce matching control-plane readback");
    }

    const postChangeProbe = await runProbe(sourceSandbox, "post-change-deny-control");
    const postChangeEvidence = await snapshotEvidence("post-change-deny-control");
    const postChangeBlocked =
      postChangeProbe.commandExitCode === 0 &&
      postChangeProbe.result.ok === false &&
      exactCaseEvent(postChangeEvidence.events, postChangeProbe.caseId) === undefined &&
      exactCaseAction(postChangeEvidence.actions, postChangeProbe.caseId) === undefined &&
      postChangeEvidence.actions.length === 1;
    controlSignals.postChangeBlocked = postChangeBlocked;
    if (!postChangeBlocked) {
      throw new IndeterminateError("fresh same-session request was not conclusively blocked after deny-all");
    }

    const sourceStopStartedAt = new Date().toISOString();
    const stopResult = await sourceSandbox.stop();
    activeHandleNeedsStop = false;
    const sourceSnapshotId = stopResult.snapshot?.id ?? sourceSandbox.currentSnapshotId;
    captureSnapshotId(sourceSnapshotId);
    sourceStopRecord = {
      startedAt: sourceStopStartedAt,
      completedAt: new Date().toISOString(),
      status: stopResult.status,
      sourceSessionId: sourceSession.sessionId,
      snapshotId: sourceSnapshotId,
      networkPolicyAtStop: sourceSandbox.networkPolicy,
    };
    const sourceStopSnapshotCaptured = typeof sourceSnapshotId === "string" && sourceSnapshotId.length > 0;
    controlSignals.sourceStopSnapshotCaptured = sourceStopSnapshotCaptured;
    if (!sourceStopSnapshotCaptured) {
      throw new IndeterminateError("persistent stop did not return or expose a snapshot ID");
    }

    resumedSandbox = await Sandbox.get({ name: sandboxName, resume: true, ...credentials });
    activeHandleNeedsStop = true;
    resumedSession = sessionRecord(resumedSandbox);
    const resumedReadback = await Sandbox.get({ name: sandboxName, resume: false, ...credentials });
    const resumedWithNewSession = resumedSession.sessionId !== sourceSession.sessionId;
    const resumedFromCapturedSnapshot =
      resumedSession.sourceSnapshotId === sourceSnapshotId ||
      resumedSandbox.currentSnapshotId === sourceSnapshotId ||
      resumedReadback.currentSnapshotId === sourceSnapshotId;
    const resumedReadbackDenyAll =
      resumedSandbox.networkPolicy === "deny-all" && resumedReadback.networkPolicy === "deny-all";
    controlSignals.resumedWithNewSession = resumedWithNewSession;
    controlSignals.resumedFromCapturedSnapshot = resumedFromCapturedSnapshot;
    controlSignals.resumedReadbackDenyAll = resumedReadbackDenyAll;
    policyTransitions.push({
      stage: "post-resume-readback",
      completedAt: new Date().toISOString(),
      resumedHandleReadback: resumedSandbox.networkPolicy,
      independentReadback: resumedReadback.networkPolicy,
      sourceSnapshotId: resumedSandbox.sourceSnapshotId,
      resumedCurrentSnapshotId: resumedSandbox.currentSnapshotId,
      independentCurrentSnapshotId: resumedReadback.currentSnapshotId,
      sessionId: resumedSession.sessionId,
    });

    const postLifecycleProbe = await runProbe(resumedSandbox, "post-resume-deny-probe");
    const postLifecycleEvidence = await snapshotEvidence("post-resume-deny-probe");
    const postLifecycleEvent = exactCaseEvent(postLifecycleEvidence.events, postLifecycleProbe.caseId);
    const postLifecycleAction = exactCaseAction(postLifecycleEvidence.actions, postLifecycleProbe.caseId);
    const postLifecycleBody = parseActionBody(postLifecycleProbe.result);
    const postLifecycleRemovedSecretAction =
      postLifecycleProbe.commandExitCode === 0 &&
      postLifecycleProbe.result.ok === true &&
      postLifecycleProbe.result.statusCode === 200 &&
      postLifecycleBody?.authorized === true &&
      postLifecycleBody.operationId !== undefined &&
      postLifecycleBody.operationId === postLifecycleAction?.operationId &&
      singleHeader(postLifecycleEvent, brokeredHeader) === brokeredSecret &&
      postLifecycleEvidence.actions.length === 2;
    const postLifecycleBlocked =
      postLifecycleProbe.commandExitCode === 0 &&
      postLifecycleProbe.result.ok === false &&
      postLifecycleEvent === undefined &&
      postLifecycleAction === undefined &&
      postLifecycleEvidence.actions.length === 1;
    const postLifecycleUnexpectedReachability =
      !postLifecycleRemovedSecretAction &&
      (postLifecycleProbe.result.ok === true || postLifecycleEvent !== undefined);
    controlSignals.postLifecycleRemovedSecretAction = postLifecycleRemovedSecretAction;
    controlSignals.postLifecycleBlocked = postLifecycleBlocked;
    controlSignals.postLifecycleUnexpectedReachability = postLifecycleUnexpectedReachability;

    let reachabilityControlPassed = false;
    if (postLifecycleBlocked) {
      const allowStartedAt = new Date().toISOString();
      await resumedSandbox.update({ networkPolicy: plainAllowPolicy });
      const allowCompletedAt = new Date().toISOString();
      const allowReadback = await Sandbox.get({ name: sandboxName, resume: false, ...credentials });
      const allowReadbackPassed =
        samePolicy(resumedSandbox.networkPolicy, plainAllowPolicy) &&
        samePolicy(allowReadback.networkPolicy, plainAllowPolicy);
      policyTransitions.push({
        stage: "plain-allow-reachability-control",
        startedAt: allowStartedAt,
        completedAt: allowCompletedAt,
        resumedHandleReadback: resumedSandbox.networkPolicy,
        independentReadback: allowReadback.networkPolicy,
      });

      const reachabilityProbe = await runProbe(resumedSandbox, "post-resume-plain-allow-control");
      const reachabilityEvidence = await snapshotEvidence("post-resume-plain-allow-control");
      const reachabilityEvent = exactCaseEvent(reachabilityEvidence.events, reachabilityProbe.caseId);
      const reachabilityAction = exactCaseAction(reachabilityEvidence.actions, reachabilityProbe.caseId);
      const reachabilityBody = parseActionBody(reachabilityProbe.result);
      reachabilityControlPassed =
        allowReadbackPassed &&
        reachabilityProbe.commandExitCode === 0 &&
        reachabilityProbe.result.ok === true &&
        reachabilityProbe.result.statusCode === 401 &&
        reachabilityBody?.authorized === false &&
        reachabilityEvent !== undefined &&
        singleHeader(reachabilityEvent, brokeredHeader) === undefined &&
        reachabilityAction === undefined &&
        reachabilityEvidence.actions.length === 1;
    }
    controlSignals.reachabilityControlPassed = reachabilityControlPassed;

    assessment = assessLifecyclePolicyRestore({
      preChangeTransformControlPassed,
      tightenAcknowledged,
      tightenReadbackDenyAll,
      postChangeBlocked,
      sourceStopSnapshotCaptured,
      resumedWithNewSession,
      resumedFromCapturedSnapshot,
      resumedReadbackDenyAll,
      postLifecycleRemovedSecretAction,
      postLifecycleBlocked,
      postLifecycleUnexpectedReachability,
      reachabilityControlPassed,
    });
  } catch (error) {
    executionError = safeError(error, forbiddenGuestValues);
    executionIndeterminate = error instanceof IndeterminateError;
    assessment = error instanceof IndeterminateError
      ? {
          verdict: "indeterminate",
          summary: "A required control failed before a valid lifecycle assessment completed.",
          signals: [executionError],
        }
      : undefined;
  } finally {
    const cleanupHandle = resumedSandbox ?? sourceSandbox;
    if (cleanupHandle && activeHandleNeedsStop) {
      cleanup.finalStopAttempted = true;
      try {
        const stopped = await cleanupHandle.stop();
        cleanup.finalStopped = true;
        captureSnapshotId(stopped.snapshot?.id ?? cleanupHandle.currentSnapshotId);
      } catch (error) {
        cleanup.errors.push(`stop: ${safeError(error, forbiddenGuestValues)}`);
      }
    }
    if (cleanupHandle) {
      cleanup.snapshotEnumerationAttempted = true;
      try {
        const listed = await cleanupHandle.listSnapshots({ limit: 10, sortOrder: "desc" });
        for (const snapshot of await listed.toArray()) captureSnapshotId(snapshot.id);
        cleanup.snapshotEnumerationSucceeded = true;
      } catch (error) {
        cleanup.errors.push(`snapshot enumeration: ${safeError(error, forbiddenGuestValues)}`);
      }
      cleanup.sandboxDeleteAttempted = true;
      try {
        await cleanupHandle.delete();
        cleanup.sandboxDeleted = true;
      } catch (error) {
        cleanup.errors.push(`sandbox delete: ${safeError(error, forbiddenGuestValues)}`);
      }
    }
    cleanup.observerConfigDeleteAttempted = true;
    try {
      const deletion = await observerAdminRequest(
        observer.origin,
        observerAdminKey,
        runId,
        "action-config",
        { method: "DELETE" },
      );
      cleanup.observerConfigDeleted = deletion.status === 204;
      if (!cleanup.observerConfigDeleted) {
        cleanup.errors.push(`observer config delete: HTTP ${deletion.status}`);
      }
    } catch (error) {
      cleanup.errors.push(`observer config delete: ${safeError(error, forbiddenGuestValues)}`);
    }
    for (const snapshotId of snapshotIds) {
      const record: SnapshotCleanupRecord = {
        snapshotId,
        attempted: true,
        deleted: false,
      };
      try {
        const snapshot = await Snapshot.get({ snapshotId, ...credentials });
        await snapshot.delete();
        record.deleted = true;
      } catch (error) {
        if (isSnapshotAlreadyAbsent(error)) {
          record.deleted = true;
          record.alreadyAbsent = true;
        } else {
          record.error = safeError(error, forbiddenGuestValues);
          cleanup.errors.push(`snapshot ${snapshotId} delete: ${record.error}`);
        }
      }
      cleanup.snapshots.push(record);
    }
  }

  const cleanupPassed =
    cleanup.errors.length === 0 &&
    (!sourceSandbox || (
      cleanup.sandboxDeleteAttempted &&
      cleanup.sandboxDeleted &&
      cleanup.snapshotEnumerationAttempted &&
      cleanup.snapshotEnumerationSucceeded &&
      cleanup.observerConfigDeleted &&
      cleanup.snapshots.every((snapshot) => snapshot.deleted)
    ));
  const finalVerdict = cleanupPassed
    ? assessment?.verdict ?? (executionIndeterminate ? "indeterminate" : "error")
    : "error";
  const finalSummary = cleanupPassed
    ? assessment?.summary ?? "Execution failed before producing an assessment."
    : "Cleanup failed; stop testing and inspect the owned sandbox and snapshots manually.";
  const candidate = finalVerdict === "candidate";
  const privateEvidence = {
    schemaVersion: 1,
    visibility: "private",
    testId: "SBX-025",
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    runtime: { sandboxSdk: "@vercel/sandbox@3.0.0", controllerNode: process.version },
    scope: "researcher-owned sandbox and observer only",
    requestRate: { guestRequests: probes.length, maximumAutomatedQueriesPerSecond: 5 },
    sandboxName,
    sourceSession,
    resumedSession,
    sourceStop: sourceStopRecord,
    policy: {
      initial: {
        allow: {
          [observer.hostname]: [
            { transform: [{ headers: { [brokeredHeader]: "<controller-only-synthetic-secret>" } }] },
          ],
        },
      },
      tightened: "deny-all",
      reachabilityControl: plainAllowPolicy,
      transitions: policyTransitions,
    },
    guestPayloadGuard: {
      brokeredSecretEnteredGuestConfiguration: false,
      observerAdminKeyEnteredGuestConfiguration: false,
      brokeredSecretAppearedInGuestOutput: false,
    },
    correlationCanarySha256: sha256(correlationCanary),
    controllerBrokeredSecretSha256: sha256(brokeredSecret),
    probes,
    evidenceSnapshots,
    controlSignals,
    assessment,
    finalVerdict,
    candidate,
    summary: finalSummary,
    cleanup,
    ...(executionError ? { executionError } : {}),
  };
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const privateEvidencePath = resolve(
    artifactsDirectory,
    `SBX-025-poc-${runId}-private.json`,
  );
  await writeFile(privateEvidencePath, `${JSON.stringify(privateEvidence, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify({
    testId: "SBX-025",
    runId,
    finalVerdict,
    candidate,
    summary: finalSummary,
    signals: assessment?.signals ?? [],
    sourceSessionId: sourceSession?.sessionId,
    resumedSessionId: resumedSession?.sessionId,
    snapshotIds: [...snapshotIds],
    controllerBrokeredSecretSha256: sha256(brokeredSecret),
    cleanup,
    privateEvidencePath,
    ...(executionError ? { executionError } : {}),
  }, null, 2)}\n`);
  if (finalVerdict !== "pass") process.exitCode = 1;
}

await main();
