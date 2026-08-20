import "dotenv/config";

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Sandbox } from "@vercel/sandbox";
import { HttpObserverClient } from "../../src/observer-client.js";
import type { ObserverEvent } from "../../src/contracts.js";

const remoteProbePath = "/tmp/sbx-008/authority-probe.mjs";
const scopeConfirmation = "researcher-controlled-endpoints-only";
const brokeredHeader = "x-sbx-harness-canary";

interface AuthorityProbeResult {
  ok: boolean;
  phase: "request" | "response" | "configuration";
  authority?: {
    destinationHost: string;
    destinationPort: number;
    tlsServername: string;
    httpHost: string;
    requestTarget: string;
  };
  transport?: Record<string, unknown>;
  response?: {
    statusCode?: number;
    statusMessage?: string;
    evidenceHeaders?: Record<string, string | string[]>;
    bodyLength: number;
    body: string;
    truncated: boolean;
  };
  error?: string;
  durationMs?: number;
}

interface CaseResult {
  caseId: string;
  commandExitCode: number;
  commandStderr: string;
  result: AuthorityProbeResult;
}

interface Cleanup {
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  observerVhostConfigDeleteAttempted: boolean;
  observerVhostConfigsDeleted: boolean;
  errors: string[];
}

interface VhostAction {
  operationId: string;
  authorizedAt: string;
  caseId: string;
  normalizedPath: string;
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function singleHeader(event: ObserverEvent | undefined, name: string): string | undefined {
  const value = event?.headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

function controlledOrigin(name: string): URL {
  const parsed = new URL(required(name));
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.pathname !== "/" ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error(`${name} must be an HTTPS origin without credentials, path, query, or fragment`);
  }
  return parsed;
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
  return count === 3
    ? { token: token!, teamId: teamId!, projectId: projectId! }
    : {};
}

function eventCases(events: ObserverEvent[]): string[] {
  return events.map((event) => event.caseId).sort();
}

function eventFor(events: ObserverEvent[], caseId: string): ObserverEvent | undefined {
  return events.find((event) => event.caseId === caseId);
}

function eventHostname(event: ObserverEvent): string | undefined {
  if (!event.host) return undefined;
  try {
    return new URL(`https://${event.host}/`).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

function isExpectedEvent(
  event: ObserverEvent | undefined,
  runId: string,
  caseId: string,
  canary: string,
  host: string,
): boolean {
  return event !== undefined &&
    event.runId === runId &&
    event.testId === "SBX-008-POC" &&
    event.caseId === caseId &&
    event.canary === canary &&
    event.host?.toLowerCase() === host.toLowerCase();
}

function port(url: URL): number {
  return url.port ? Number(url.port) : 443;
}

async function vhostAdminRequest(
  observerOrigin: string,
  observerAdminKey: string,
  runId: string,
  resource: "vhost-config" | "vhost-actions",
  init?: RequestInit,
): Promise<Response> {
  const headers = new Headers(init?.headers);
  headers.set("authorization", `Bearer ${observerAdminKey}`);
  return fetch(new URL(`/v1/runs/${encodeURIComponent(runId)}/${resource}`, observerOrigin), {
    ...init,
    headers,
    signal: AbortSignal.timeout(10_000),
  });
}

async function readVhostActions(
  observerOrigin: string,
  observerAdminKey: string,
  runId: string,
): Promise<VhostAction[]> {
  const response = await vhostAdminRequest(
    observerOrigin,
    observerAdminKey,
    runId,
    "vhost-actions",
  );
  if (!response.ok) throw new Error(`observer vhost action query returned ${response.status}`);
  const payload = (await response.json()) as { actions?: VhostAction[] };
  if (!Array.isArray(payload.actions)) throw new Error("observer returned invalid vhost actions");
  return payload.actions;
}

function responseJson(result: CaseResult | undefined): Record<string, unknown> | undefined {
  const body = result?.result.response?.body;
  if (!body) return undefined;
  try {
    const parsed = JSON.parse(body) as unknown;
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : undefined;
  } catch {
    return undefined;
  }
}

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  const observerA = controlledOrigin("OBSERVER_A_URL");
  const observerB = controlledOrigin("OBSERVER_B_URL");
  const observerAdminKey = required("OBSERVER_ADMIN_KEY");
  const mode = process.env.SBX008_MODE ?? "plain";
  if (mode !== "plain" && mode !== "credential") {
    throw new Error("SBX008_MODE must be plain or credential");
  }
  if (observerA.hostname === observerB.hostname) {
    throw new Error("OBSERVER_A_URL and OBSERVER_B_URL must use distinct researcher-controlled hostnames");
  }

  const observerAClient = new HttpObserverClient(observerA.origin, observerAdminKey);
  const observerBClient = new HttpObserverClient(observerB.origin, observerAdminKey);
  await Promise.all([observerAClient.health(), observerBClient.health()]);

  const runId = randomUUID();
  const correlationCanary = `corr_${randomBytes(18).toString("base64url")}`;
  const brokeredSecret = `broker_${randomBytes(24).toString("base64url")}`;
  const controlledHosts = [observerA.hostname, observerB.hostname];
  const cases = [
    {
      caseId: "positive-a",
      destination: observerA,
      httpHost: observerA.host,
      absoluteTarget: undefined,
      description: "allowed A destination, A SNI, and Host A",
    },
    {
      caseId: "absolute-a-control",
      destination: observerA,
      httpHost: observerA.host,
      absoluteTarget: observerA,
      description: "absolute-form syntax control with A destination, SNI, Host, and target",
    },
    {
      caseId: "direct-b-negative",
      destination: observerB,
      httpHost: observerB.host,
      absoluteTarget: undefined,
      description: "blocked direct B destination, B SNI, and Host B",
    },
    {
      caseId: "reverse-b-sni-host-a-negative",
      destination: observerB,
      httpHost: observerA.host,
      absoluteTarget: undefined,
      description: "blocked B destination and SNI with Host A",
    },
    {
      caseId: "front-a-sni-host-b",
      destination: observerA,
      httpHost: observerB.host,
      absoluteTarget: undefined,
      description: "test A destination and SNI with Host B",
    },
    {
      caseId: "absolute-b-target",
      destination: observerA,
      httpHost: observerA.host,
      absoluteTarget: observerB,
      description: "A destination, SNI, and Host with a B absolute-form request target",
    },
  ] as const;

  let sandbox: Sandbox | undefined;
  let sandboxIdentity: Record<string, unknown> | undefined;
  const caseResults: CaseResult[] = [];
  let observerAEvents: ObserverEvent[] = [];
  let observerBEvents: ObserverEvent[] = [];
  let observerAActions: VhostAction[] = [];
  let observerBActions: VhostAction[] = [];
  let executionError: string | undefined;
  const cleanup: Cleanup = {
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    observerVhostConfigDeleteAttempted: false,
    observerVhostConfigsDeleted: false,
    errors: [],
  };

  try {
    const registrations = await Promise.all(
      [observerA.origin, observerB.origin].map((origin) =>
        vhostAdminRequest(origin, observerAdminKey, runId, "vhost-config", {
          method: "POST",
          headers: {
            "x-observer-vhost": observerB.host,
            ...(mode === "credential" ? { "x-observer-action-secret": brokeredSecret } : {}),
          },
        }),
      ),
    );
    for (const registration of registrations) {
      if (!registration.ok) {
        throw new Error(`observer vhost registration returned ${registration.status}`);
      }
    }

    sandbox = await Sandbox.create({
      name: `sbx-008-poc-${runId.slice(0, 8)}`,
      persistent: false,
      timeout: 300_000,
      networkPolicy: mode === "credential"
        ? {
            allow: {
              [observerA.hostname]: [
                { transform: [{ headers: { [brokeredHeader]: brokeredSecret } }] },
              ],
            },
          }
        : { allow: [observerA.hostname] },
      tags: { harness: "vsc", test: "SBX-008", run: runId.slice(0, 12) },
      ...explicitCredentials(),
    });

    const session = sandbox.currentSession();
    sandboxIdentity = {
      name: sandbox.name,
      sessionId: session.sessionId,
      sessionCreatedAt: session.createdAt.toISOString(),
      sessionRequestedAt: session.requestedAt.toISOString(),
      region: session.region,
    };
    const guestProbe = await readFile(resolve("guest/authority-probe.mjs"), "utf8");
    await sandbox.writeFiles([{ path: remoteProbePath, content: guestProbe, mode: 0o700 }]);

    for (const probeCase of cases) {
      const query = new URLSearchParams({
        __sbx_run: runId,
        __sbx_test: "SBX-008-POC",
        __sbx_case: probeCase.caseId,
        __sbx_canary: correlationCanary,
      });
      const originFormTarget = `/v1/probe/${encodeURIComponent(runId)}/vhost-action?${query}`;
      const guestConfiguration = {
        scopeConfirmation,
        researcherControlledHosts: controlledHosts,
        runId,
        testId: "SBX-008-POC",
        caseId: probeCase.caseId,
        destinationHost: probeCase.destination.hostname,
        destinationPort: port(probeCase.destination),
        tlsServername: probeCase.destination.hostname,
        httpHost: probeCase.httpHost,
        method: "GET",
        requestTarget: probeCase.absoluteTarget === undefined
          ? originFormTarget
          : new URL(originFormTarget, probeCase.absoluteTarget).toString(),
        headers: { "x-sbx-correlation": correlationCanary },
        timeoutMs: 20_000,
        maxResponseBodyBytes: 4_096,
      };
      const serializedConfiguration = JSON.stringify(guestConfiguration);
      if (
        serializedConfiguration.includes(observerAdminKey) ||
        serializedConfiguration.includes(brokeredSecret)
      ) {
        throw new Error("proof invalid: controller-only material entered the guest configuration");
      }
      const command = await sandbox.runCommand({
        cmd: "node",
        args: [remoteProbePath, Buffer.from(serializedConfiguration).toString("base64url")],
        timeoutMs: 25_000,
      });
      const [stdout, stderr] = await Promise.all([command.stdout(), command.stderr()]);
      let result: AuthorityProbeResult;
      try {
        result = JSON.parse(stdout) as AuthorityProbeResult;
      } catch {
        throw new Error(`${probeCase.caseId} returned non-JSON output: ${stdout.slice(0, 500)}`);
      }
      caseResults.push({
        caseId: probeCase.caseId,
        commandExitCode: command.exitCode,
        commandStderr: stderr.slice(0, 2_000),
        result,
      });
    }

    await new Promise((resolveWait) => setTimeout(resolveWait, 1_500));
    const [allEvents, allActions] = await Promise.all([
      observerAClient.events(runId),
      readVhostActions(observerA.origin, observerAdminKey, runId),
    ]);
    observerAEvents = allEvents.filter((event) => eventHostname(event) === observerA.hostname);
    observerBEvents = allEvents.filter((event) => eventHostname(event) === observerB.hostname);
    observerAActions = allActions;
    observerBActions = [];
  } catch (error) {
    executionError = error instanceof Error ? error.message : String(error);
    try {
      const [allEvents, allActions] = await Promise.all([
        observerAClient.events(runId),
        readVhostActions(observerA.origin, observerAdminKey, runId),
      ]);
      observerAEvents = allEvents.filter((event) => eventHostname(event) === observerA.hostname);
      observerBEvents = allEvents.filter((event) => eventHostname(event) === observerB.hostname);
      observerAActions = allActions;
      observerBActions = [];
    } catch (observerError) {
      executionError += `; evidence query: ${observerError instanceof Error ? observerError.message : String(observerError)}`;
    }
  } finally {
    if (sandbox) {
      cleanup.stopAttempted = true;
      try {
        await sandbox.stop();
        cleanup.stopped = true;
      } catch (error) {
        cleanup.errors.push(`stop: ${error instanceof Error ? error.message : String(error)}`);
      }
      cleanup.deleteAttempted = true;
      try {
        await sandbox.delete();
        cleanup.deleted = true;
      } catch (error) {
        cleanup.errors.push(`delete: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
    cleanup.observerVhostConfigDeleteAttempted = true;
    try {
      const deletions = await Promise.all(
        [observerA.origin, observerB.origin].map((origin) =>
          vhostAdminRequest(origin, observerAdminKey, runId, "vhost-config", { method: "DELETE" }),
        ),
      );
      cleanup.observerVhostConfigsDeleted = deletions.every((response) => response.status === 204);
      if (!cleanup.observerVhostConfigsDeleted) {
        cleanup.errors.push(
          `observer vhost config delete: HTTP ${deletions.map((response) => response.status).join(",")}`,
        );
      }
    } catch (error) {
      cleanup.errors.push(
        `observer vhost config delete: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  const resultFor = (caseId: string): CaseResult | undefined =>
    caseResults.find((entry) => entry.caseId === caseId);
  const positiveResult = resultFor("positive-a");
  const absoluteAResult = resultFor("absolute-a-control");
  const directBResult = resultFor("direct-b-negative");
  const reverseResult = resultFor("reverse-b-sni-host-a-negative");
  const hostBResult = resultFor("front-a-sni-host-b");
  const absoluteBResult = resultFor("absolute-b-target");
  const aPositiveEvent = eventFor(observerAEvents, "positive-a");
  const bPositiveEvent = eventFor(observerBEvents, "positive-a");
  const directBEvents = [
    eventFor(observerAEvents, "direct-b-negative"),
    eventFor(observerBEvents, "direct-b-negative"),
  ].filter(Boolean);
  const reverseEvents = [
    eventFor(observerAEvents, "reverse-b-sni-host-a-negative"),
    eventFor(observerBEvents, "reverse-b-sni-host-a-negative"),
  ].filter(Boolean);
  const aHostBEvent = eventFor(observerAEvents, "front-a-sni-host-b");
  const bHostBEvent = eventFor(observerBEvents, "front-a-sni-host-b");
  const aAbsoluteAEvent = eventFor(observerAEvents, "absolute-a-control");
  const bAbsoluteAEvent = eventFor(observerBEvents, "absolute-a-control");
  const aAbsoluteBEvent = eventFor(observerAEvents, "absolute-b-target");
  const bAbsoluteBEvent = eventFor(observerBEvents, "absolute-b-target");
  const positiveBody = responseJson(positiveResult);
  const absoluteABody = responseJson(absoluteAResult);
  const hostBBody = responseJson(hostBResult);
  const absoluteBBody = responseJson(absoluteBResult);
  const uniqueActions = [...observerAActions, ...observerBActions].filter(
    (action, index, actions) =>
      actions.findIndex((candidateAction) => candidateAction.operationId === action.operationId) === index,
  );
  const hostBAction = uniqueActions.find((action) => action.caseId === "front-a-sni-host-b");
  const absoluteBAction = uniqueActions.find((action) => action.caseId === "absolute-b-target");
  const unexpectedActions = uniqueActions.filter(
    (action) => action.caseId !== "front-a-sni-host-b" && action.caseId !== "absolute-b-target",
  );
  const guestResponseContainsBrokeredSecret = caseResults.some((entry) =>
    entry.result.response?.body.includes(brokeredSecret) === true
  );

  const positiveControlPassed =
    positiveResult?.commandExitCode === 0 &&
    positiveResult.result.ok === true &&
    positiveResult.result.response?.statusCode === 421 &&
    positiveBody?.selected === false &&
    (
      mode === "credential"
        ? singleHeader(aPositiveEvent ?? bPositiveEvent, brokeredHeader) === brokeredSecret
        : singleHeader(aPositiveEvent ?? bPositiveEvent, brokeredHeader) === undefined
    ) &&
    (
      isExpectedEvent(aPositiveEvent, runId, "positive-a", correlationCanary, observerA.host) ||
      isExpectedEvent(bPositiveEvent, runId, "positive-a", correlationCanary, observerA.host)
    );
  const absoluteAControlPassed =
    absoluteAResult?.commandExitCode === 0 &&
    absoluteAResult.result.ok === true &&
    absoluteAResult.result.response?.statusCode === 421 &&
    absoluteABody?.selected === false &&
    bAbsoluteAEvent === undefined &&
    isExpectedEvent(
      aAbsoluteAEvent,
      runId,
      "absolute-a-control",
      correlationCanary,
      observerA.host,
    ) &&
    (
      mode === "credential"
        ? singleHeader(aAbsoluteAEvent, brokeredHeader) === brokeredSecret
        : singleHeader(aAbsoluteAEvent, brokeredHeader) === undefined
    );
  const directBBlocked =
    directBResult?.commandExitCode === 0 &&
    directBResult.result.ok === false &&
    directBEvents.length === 0;
  const reverseBBlocked =
    reverseResult?.commandExitCode === 0 &&
    reverseResult.result.ok === false &&
    reverseEvents.length === 0;
  const originFormMismatchRejected =
    hostBResult?.commandExitCode === 0 &&
    hostBResult.result.ok === true &&
    hostBResult.result.response?.statusCode === 403 &&
    aHostBEvent === undefined &&
    bHostBEvent === undefined &&
    hostBAction === undefined;
  const controlsPassed =
    positiveControlPassed &&
    absoluteAControlPassed &&
    directBBlocked &&
    reverseBBlocked &&
    (mode !== "credential" || originFormMismatchRejected);
  const bSpecificHostBEvent =
    hostBResult?.commandExitCode === 0 &&
    isExpectedEvent(
      bHostBEvent,
      runId,
      "front-a-sni-host-b",
      correlationCanary,
      observerB.host,
    ) &&
    aHostBEvent === undefined;
  const hostHeaderForwardedSignal =
    hostBResult?.result.ok === true &&
    (aHostBEvent?.host === observerB.host || bHostBEvent?.host === observerB.host);
  const vhostActionTriggered =
    hostBResult?.commandExitCode === 0 &&
    hostBResult.result.ok === true &&
    hostBResult.result.response?.statusCode === 200 &&
    hostBBody?.selected === true &&
    hostBBody.authorized === true &&
    !guestResponseContainsBrokeredSecret &&
    (
      mode === "credential"
        ? singleHeader(bHostBEvent, brokeredHeader) === brokeredSecret
        : singleHeader(bHostBEvent, brokeredHeader) === undefined
    ) &&
    typeof hostBBody.operationId === "string" &&
    hostBBody.operationId === hostBAction?.operationId &&
    unexpectedActions.length === 0;
  const absoluteBSpecificEvent =
    absoluteBResult?.commandExitCode === 0 &&
    isExpectedEvent(
      bAbsoluteBEvent,
      runId,
      "absolute-b-target",
      correlationCanary,
      observerB.host,
    ) &&
    aAbsoluteBEvent === undefined;
  const absoluteBActionTriggered =
    absoluteBResult?.commandExitCode === 0 &&
    absoluteBResult.result.ok === true &&
    absoluteBResult.result.response?.statusCode === 200 &&
    absoluteBBody?.selected === true &&
    absoluteBBody.authorized === true &&
    !guestResponseContainsBrokeredSecret &&
    mode === "credential" &&
    singleHeader(bAbsoluteBEvent, brokeredHeader) === brokeredSecret &&
    typeof absoluteBBody.operationId === "string" &&
    absoluteBBody.operationId === absoluteBAction?.operationId &&
    unexpectedActions.length === 0;
  const operationalFailure = executionError !== undefined || cleanup.errors.length > 0;
  const candidate =
    !operationalFailure &&
    controlsPassed &&
    (vhostActionTriggered || absoluteBActionTriggered);
  const outcome = operationalFailure
    ? "indeterminate"
    : !controlsPassed
      ? "indeterminate"
      : candidate
        ? "candidate"
        : "no-confirmed-exploit";

  const artifact = {
    schemaVersion: 1,
    testId: "SBX-008",
    mode,
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    outcome,
    candidate,
    controlsPassed,
    controls: {
      positiveControlPassed,
      absoluteAControlPassed,
      directBBlocked,
      reverseBBlocked,
      originFormMismatchRejected,
    },
    signals: {
      bSpecificHostBEvent,
      hostHeaderForwardedSignal,
      vhostActionTriggered,
      vhostActionOperationId: hostBAction?.operationId,
      absoluteBSpecificEvent,
      absoluteBActionTriggered,
      absoluteBActionOperationId: absoluteBAction?.operationId,
      note: "hostHeaderForwardedSignal alone is expected HTTP behavior and is not classified as an exploit",
    },
    guestConfigurationContainsBrokeredSecret: false,
    guestResponseContainsBrokeredSecret,
    runtime: {
      sandboxSdk: "@vercel/sandbox@3.0.0",
      controllerNode: process.version,
    },
    sandbox: sandboxIdentity,
    policy: mode === "credential"
      ? {
          allow: {
            [observerA.hostname]: [
              { transform: [{ headers: { [brokeredHeader]: brokeredSecret } }] },
            ],
          },
        }
      : { allow: [observerA.hostname] },
    controlledOrigins: { a: observerA.origin, b: observerB.origin },
    caseDefinitions: cases.map((entry) => ({
      caseId: entry.caseId,
      description: entry.description,
      destinationOrigin: entry.destination.origin,
      tlsServername: entry.destination.hostname,
      httpHost: entry.httpHost,
      requestTargetForm: entry.absoluteTarget === undefined ? "origin" : "absolute",
      requestTargetAuthority: entry.absoluteTarget?.host,
    })),
    caseResults,
    observerEventCases: {
      a: eventCases(observerAEvents),
      b: eventCases(observerBEvents),
    },
    observerEvents: {
      a: observerAEvents,
      b: observerBEvents,
    },
    vhostActions: {
      a: observerAActions,
      b: observerBActions,
      unique: uniqueActions,
    },
    correlationCanary,
    ...(mode === "credential" ? {
      controllerBrokeredSecretSha256: sha256(brokeredSecret),
      observerBrokeredSecretSha256: sha256(
        singleHeader(bAbsoluteBEvent ?? bHostBEvent, brokeredHeader) ?? "",
      ),
    } : {}),
    executionError,
    cleanup,
  };

  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const privateEvidencePath = resolve(artifactsDirectory, `SBX-008-poc-${runId}-private.json`);
  await writeFile(privateEvidencePath, `${JSON.stringify(artifact, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify({
    mode,
    outcome,
    candidate,
    controlsPassed,
    signals: artifact.signals,
    cleanup,
    privateEvidencePath,
  }, null, 2)}\n`);

  const failures = [
    ...(executionError ? [`execution: ${executionError}`] : []),
    ...cleanup.errors,
  ];
  if (failures.length > 0) throw new Error(failures.join("; "));
}

await main();
