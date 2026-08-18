import "dotenv/config";

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Sandbox } from "@vercel/sandbox";
import { HttpObserverClient } from "../../src/observer-client.js";
import type { ObserverEvent } from "../../src/contracts.js";

const brokeredHeader = "x-sbx-harness-canary";
const remoteAuthorityProbe = "/tmp/sbx-009/authority-probe.mjs";
const remoteH2Probe = "/tmp/sbx-009/h2-authority-reuse-probe.mjs";

interface CommandRecord {
  caseId: string;
  exitCode: number;
  result: Record<string, unknown>;
  stderr: string;
}

interface ActionRecord {
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

function controlledOrigin(name: string): URL {
  const url = new URL(required(name));
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  ) {
    throw new Error(`${name} must be an HTTPS origin without credentials, path, query, or fragment`);
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

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function originPort(url: URL): number {
  return url.port ? Number(url.port) : 443;
}

function singleHeader(event: ObserverEvent | undefined, name: string): string | undefined {
  const value = event?.headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

function eventHostname(event: ObserverEvent): string | undefined {
  if (!event.host) return undefined;
  try {
    return new URL(`https://${event.host}/`).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function parseJsonBody(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== "string" || value.length === 0) return undefined;
  try {
    return record(JSON.parse(value) as unknown);
  } catch {
    return undefined;
  }
}

function mergeEvents(...groups: ObserverEvent[][]): ObserverEvent[] {
  const events: ObserverEvent[] = [];
  const seen = new Set<string>();
  for (const event of groups.flat()) {
    const identity = JSON.stringify(event);
    if (seen.has(identity)) continue;
    seen.add(identity);
    events.push(event);
  }
  return events;
}

function mergeActions(...groups: ActionRecord[][]): ActionRecord[] {
  const actions: ActionRecord[] = [];
  const seen = new Set<string>();
  for (const action of groups.flat()) {
    if (seen.has(action.operationId)) continue;
    seen.add(action.operationId);
    actions.push(action);
  }
  return actions;
}

async function adminRequest(
  baseUrl: string,
  adminKey: string,
  runId: string,
  resource: "vhost-config" | "vhost-actions",
  init?: RequestInit,
): Promise<Response> {
  const headers = new Headers(init?.headers);
  headers.set("authorization", `Bearer ${adminKey}`);
  return fetch(new URL(`/v1/runs/${encodeURIComponent(runId)}/${resource}`, baseUrl), {
    ...init,
    headers,
    signal: AbortSignal.timeout(10_000),
  });
}

async function actions(baseUrl: string, adminKey: string, runId: string): Promise<ActionRecord[]> {
  const response = await adminRequest(baseUrl, adminKey, runId, "vhost-actions");
  if (!response.ok) throw new Error(`observer vhost action query returned ${response.status}`);
  const body = (await response.json()) as { actions?: ActionRecord[] };
  if (!Array.isArray(body.actions)) throw new Error("observer returned invalid vhost actions");
  return body.actions;
}

function probeQuery(runId: string, caseId: string, canary: string): URLSearchParams {
  return new URLSearchParams({
    __sbx_run: runId,
    __sbx_test: "SBX-009-POC",
    __sbx_case: caseId,
    __sbx_canary: canary,
  });
}

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  const observerA = controlledOrigin("OBSERVER_A_URL");
  const observerB = controlledOrigin("OBSERVER_B_URL");
  if (observerA.hostname === observerB.hostname) throw new Error("observer hostnames must be distinct");
  const adminKey = required("OBSERVER_ADMIN_KEY");
  const clients = [
    new HttpObserverClient(observerA.origin, adminKey),
    new HttpObserverClient(observerB.origin, adminKey),
  ];
  await Promise.all(clients.map((client) => client.health()));

  const runId = randomUUID();
  const correlationCanary = `corr_${randomBytes(18).toString("base64url")}`;
  const brokeredSecret = `broker_${randomBytes(24).toString("base64url")}`;
  const controlledHosts = [observerA.hostname, observerB.hostname];
  const forbiddenGuestValues = [adminKey, brokeredSecret, process.env.VERCEL_TOKEN ?? ""].filter(Boolean);
  const requestPath = `/v1/probe/${encodeURIComponent(runId)}/vhost-action`;
  const commandRecords: CommandRecord[] = [];
  const cleanup = {
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    vhostConfigDeleteAttempted: false,
    vhostConfigsDeleted: false,
    errors: [] as string[],
  };
  let sandbox: Sandbox | undefined;
  let sandboxIdentity: Record<string, unknown> | undefined;
  let observerAEvents: ObserverEvent[] = [];
  let observerBEvents: ObserverEvent[] = [];
  let observerAActions: ActionRecord[] = [];
  let observerBActions: ActionRecord[] = [];
  let executionError: string | undefined;

  try {
    const registrations = await Promise.all(
      [observerA.origin, observerB.origin].map((origin) =>
        adminRequest(origin, adminKey, runId, "vhost-config", {
          method: "POST",
          headers: {
            "x-observer-vhost": observerB.host,
            "x-observer-action-secret": brokeredSecret,
          },
        }),
      ),
    );
    if (registrations.some((response) => !response.ok)) {
      throw new Error(
        `observer vhost registration failed: ${registrations.map((response) => response.status).join(",")}`,
      );
    }

    sandbox = await Sandbox.create({
      name: `sbx-009-poc-${runId.slice(0, 8)}`,
      persistent: false,
      timeout: 300_000,
      networkPolicy: {
        allow: {
          [observerA.hostname]: [
            { transform: [{ headers: { [brokeredHeader]: brokeredSecret } }] },
          ],
        },
      },
      tags: { harness: "vsc", test: "SBX-009", run: runId.slice(0, 12) },
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
    const [authoritySource, h2Source] = await Promise.all([
      readFile(resolve("guest/authority-probe.mjs"), "utf8"),
      readFile(resolve("guest/h2-authority-reuse-probe.mjs"), "utf8"),
    ]);
    await sandbox.writeFiles([
      { path: remoteAuthorityProbe, content: authoritySource, mode: 0o700 },
      { path: remoteH2Probe, content: h2Source, mode: 0o700 },
    ]);

    const activeSandbox = sandbox;
    async function runProbe(
      caseId: string,
      remotePath: string,
      configuration: Record<string, unknown>,
    ): Promise<Record<string, unknown>> {
      const serialized = JSON.stringify(configuration);
      if (forbiddenGuestValues.some((value) => serialized.includes(value))) {
        throw new Error(`proof invalid: ${caseId} guest configuration contains controller-only material`);
      }
      const command = await activeSandbox.runCommand({
        cmd: "node",
        args: [remotePath, Buffer.from(serialized).toString("base64url")],
        timeoutMs: 35_000,
      });
      const [stdout, stderr] = await Promise.all([command.stdout(), command.stderr()]);
      let result: Record<string, unknown>;
      try {
        result = JSON.parse(stdout) as Record<string, unknown>;
      } catch {
        throw new Error(`${caseId} emitted invalid JSON`);
      }
      commandRecords.push({
        caseId,
        exitCode: command.exitCode,
        result,
        stderr: stderr.slice(0, 2_000),
      });
      return result;
    }

    await runProbe("direct-b-negative", remoteAuthorityProbe, {
      scopeConfirmation: "researcher-controlled-endpoints-only",
      researcherControlledHosts: controlledHosts,
      runId,
      testId: "SBX-009-POC",
      caseId: "direct-b-negative",
      destinationHost: observerB.hostname,
      destinationPort: originPort(observerB),
      tlsServername: observerB.hostname,
      httpHost: observerB.host,
      requestTarget: `${requestPath}?phase=direct-b&${probeQuery(runId, "direct-b-negative", correlationCanary)}`,
      headers: {},
      timeoutMs: 20_000,
    });

    await runProbe("fresh-h2-a-control", remoteH2Probe, {
      scopeConfirmation: "researcher-controlled-endpoints-only",
      researcherControlledHosts: controlledHosts,
      runId,
      testId: "SBX-009-POC",
      caseId: "fresh-h2-a-control",
      destinationHost: observerA.hostname,
      destinationPort: originPort(observerA),
      tlsServername: observerA.hostname,
      sequence: "single-stream",
      streams: [
        {
          id: "fresh-h2-a-control",
          authority: observerA.host,
          method: "GET",
          path: `${requestPath}?phase=fresh-a&${probeQuery(runId, "fresh-h2-a-control", correlationCanary)}`,
          headers: { "x-sbx-correlation": correlationCanary },
        },
      ],
      timeoutMs: 20_000,
      maxResponseBodyBytes: 4_096,
    });

    await runProbe("fresh-h2-b-mismatch", remoteH2Probe, {
      scopeConfirmation: "researcher-controlled-endpoints-only",
      researcherControlledHosts: controlledHosts,
      runId,
      testId: "SBX-009-POC",
      caseId: "fresh-h2-b-mismatch",
      destinationHost: observerA.hostname,
      destinationPort: originPort(observerA),
      tlsServername: observerA.hostname,
      sequence: "single-stream",
      streams: [
        {
          id: "fresh-h2-b-mismatch",
          authority: observerB.host,
          method: "GET",
          path: `${requestPath}?phase=fresh-b&${probeQuery(runId, "fresh-h2-b-mismatch", correlationCanary)}`,
          headers: { "x-sbx-correlation": correlationCanary },
        },
      ],
      timeoutMs: 20_000,
      maxResponseBodyBytes: 4_096,
    });

    const firstAPath = `${requestPath}?phase=h2-first&${probeQuery(runId, "h2-first-a", correlationCanary)}`;
    const secondBPath = `${requestPath}?phase=h2-second&${probeQuery(runId, "h2-second-b", correlationCanary)}`;
    const finalAPath = `${requestPath}?phase=h2-final&${probeQuery(runId, "h2-final-a", correlationCanary)}`;
    await runProbe("h2-authority-reuse", remoteH2Probe, {
      scopeConfirmation: "researcher-controlled-endpoints-only",
      researcherControlledHosts: controlledHosts,
      runId,
      testId: "SBX-009-POC",
      caseId: "h2-authority-reuse",
      destinationHost: observerA.hostname,
      destinationPort: originPort(observerA),
      tlsServername: observerA.hostname,
      sequence: "a-b-a-reuse",
      streams: [
        {
          id: "h2-first-a",
          authority: observerA.host,
          method: "GET",
          path: firstAPath,
          headers: { "x-sbx-correlation": correlationCanary },
        },
        {
          id: "h2-second-b",
          authority: observerB.host,
          method: "GET",
          path: secondBPath,
          headers: { "x-sbx-correlation": correlationCanary },
        },
        {
          id: "h2-final-a",
          authority: observerA.host,
          method: "GET",
          path: finalAPath,
          headers: { "x-sbx-correlation": correlationCanary },
        },
      ],
      timeoutMs: 20_000,
      maxResponseBodyBytes: 4_096,
    });

    await new Promise((resolveWait) => setTimeout(resolveWait, 1_500));
    [observerAEvents, observerBEvents, observerAActions, observerBActions] = await Promise.all([
      clients[0]!.events(runId),
      clients[1]!.events(runId),
      actions(observerA.origin, adminKey, runId),
      actions(observerB.origin, adminKey, runId),
    ]);
  } catch (error) {
    executionError = error instanceof Error ? error.message : String(error);
    try {
      [observerAEvents, observerBEvents, observerAActions, observerBActions] = await Promise.all([
        clients[0]!.events(runId),
        clients[1]!.events(runId),
        actions(observerA.origin, adminKey, runId),
        actions(observerB.origin, adminKey, runId),
      ]);
    } catch (evidenceError) {
      executionError += `; evidence query: ${evidenceError instanceof Error ? evidenceError.message : String(evidenceError)}`;
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
    cleanup.vhostConfigDeleteAttempted = true;
    try {
      const deletions = await Promise.all(
        [observerA.origin, observerB.origin].map((origin) =>
          adminRequest(origin, adminKey, runId, "vhost-config", { method: "DELETE" }),
        ),
      );
      cleanup.vhostConfigsDeleted = deletions.every((response) => response.status === 204);
      if (!cleanup.vhostConfigsDeleted) cleanup.errors.push("observer vhost cleanup failed");
    } catch (error) {
      cleanup.errors.push(`observer cleanup: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  const allEvents = mergeEvents(observerAEvents, observerBEvents);
  const allActions = mergeActions(observerAActions, observerBActions);
  const command = (caseId: string): CommandRecord | undefined =>
    commandRecords.find((entry) => entry.caseId === caseId);
  const directBCommand = command("direct-b-negative");
  const freshACommand = command("fresh-h2-a-control");
  const freshBCommand = command("fresh-h2-b-mismatch");
  const h2Command = command("h2-authority-reuse");
  const freshAResult = freshACommand?.result;
  const freshBResult = freshBCommand?.result;
  const h2Result = h2Command?.result;
  const streamResults = Array.isArray(h2Result?.streams)
    ? h2Result.streams.map((stream) => record(stream)).filter((stream): stream is Record<string, unknown> => stream !== undefined)
    : [];
  const firstStream = streamResults.find((stream) => stream.id === "h2-first-a");
  const secondStream = streamResults.find((stream) => stream.id === "h2-second-b");
  const finalStream = streamResults.find((stream) => stream.id === "h2-final-a");
  const firstBody = parseJsonBody(firstStream?.body);
  const secondBody = parseJsonBody(secondStream?.body);
  const finalBody = parseJsonBody(finalStream?.body);
  const freshAStreams = Array.isArray(freshAResult?.streams)
    ? freshAResult.streams.map((stream) => record(stream)).filter((stream): stream is Record<string, unknown> => stream !== undefined)
    : [];
  const freshBStreams = Array.isArray(freshBResult?.streams)
    ? freshBResult.streams.map((stream) => record(stream)).filter((stream): stream is Record<string, unknown> => stream !== undefined)
    : [];
  const freshAStream = freshAStreams.find((stream) => stream.id === "fresh-h2-a-control");
  const freshBStream = freshBStreams.find((stream) => stream.id === "fresh-h2-b-mismatch");
  const freshABody = parseJsonBody(freshAStream?.body);
  const directBEvents = allEvents.filter((event) => event.caseId === "direct-b-negative");
  const freshAEvents = allEvents.filter((event) => event.caseId === "fresh-h2-a-control");
  const freshBEvents = allEvents.filter((event) => event.caseId === "fresh-h2-b-mismatch");
  const firstEvents = allEvents.filter((event) => event.caseId === "h2-first-a");
  const secondEvents = allEvents.filter((event) => event.caseId === "h2-second-b");
  const finalEvents = allEvents.filter((event) => event.caseId === "h2-final-a");
  const freshAEvent = freshAEvents.find((event) => eventHostname(event) === observerA.hostname);
  const firstAEvent = firstEvents.find((event) => eventHostname(event) === observerA.hostname);
  const secondBEvent = secondEvents.find((event) => eventHostname(event) === observerB.hostname);
  const finalAEvent = finalEvents.find((event) => eventHostname(event) === observerA.hostname);
  const secondAction = allActions.find((action) => action.caseId === "h2-second-b");
  const unexpectedActions = allActions.filter((action) => action.caseId !== "h2-second-b");

  const verifiedH2 = (commandRecord: CommandRecord | undefined): boolean => {
    const result = commandRecord?.result;
    const candidateTransport = record(result?.transport);
    const candidateTls = record(candidateTransport?.tls);
    const certificate = record(candidateTls?.peerCertificate);
    return commandRecord?.exitCode === 0 &&
      result?.ok === true &&
      typeof candidateTransport?.sessionCorrelation === "string" &&
      candidateTls?.authorized === true &&
      candidateTls.alpnProtocol === "h2" &&
      typeof certificate?.fingerprint256 === "string";
  };

  const directBBlocked =
    directBCommand?.exitCode === 0 &&
    directBCommand.result.ok === false &&
    directBEvents.length === 0;
  const freshAReceivedCredential =
    verifiedH2(freshACommand) &&
    freshAStream?.ok === true &&
    freshAStream.statusCode === 421 &&
    freshABody?.selected === false &&
    freshAEvents.length === 1 &&
    singleHeader(freshAEvent, brokeredHeader) === brokeredSecret;
  const freshBMismatchRejected =
    verifiedH2(freshBCommand) &&
    freshBStream?.ok === true &&
    freshBStream.statusCode === 403 &&
    freshBEvents.length === 0 &&
    allActions.every((action) => action.caseId !== "fresh-h2-b-mismatch");
  const oneVerifiedH2Session =
    verifiedH2(h2Command) &&
    streamResults.length === 3;
  const reuseFirstAReceivedCredential =
    oneVerifiedH2Session &&
    firstStream?.ok === true &&
    firstStream.statusCode === 421 &&
    firstBody?.selected === false &&
    firstEvents.length === 1 &&
    singleHeader(firstAEvent, brokeredHeader) === brokeredSecret;
  const reuseFinalAReceivedCredential =
    oneVerifiedH2Session &&
    finalStream?.ok === true &&
    finalStream.statusCode === 421 &&
    finalBody?.selected === false &&
    finalEvents.length === 1 &&
    singleHeader(finalAEvent, brokeredHeader) === brokeredSecret;
  const guestResponseContainsBrokeredSecret = commandRecords.some((entry) =>
    JSON.stringify(entry.result).includes(brokeredSecret)
  );
  const secondStreamCleanlyRejected =
    oneVerifiedH2Session &&
    secondStream?.ok === true &&
    secondStream.statusCode === 403 &&
    secondEvents.length === 0 &&
    allActions.length === 0;
  const secondStreamBypassed =
    oneVerifiedH2Session &&
    secondStream?.ok === true &&
    secondStream.statusCode === 200 &&
    secondBody?.selected === true &&
    secondBody.authorized === true &&
    !guestResponseContainsBrokeredSecret &&
    typeof secondBody.operationId === "string" &&
    secondBody.operationId === secondAction?.operationId &&
    secondEvents.length === 1 &&
    singleHeader(secondBEvent, brokeredHeader) === brokeredSecret &&
    allActions.length === 1 &&
    unexpectedActions.length === 0;
  const controlsPassed = directBBlocked && freshAReceivedCredential && freshBMismatchRejected;
  const reuseAControlsPassed = reuseFirstAReceivedCredential && reuseFinalAReceivedCredential;
  const operationalFailure = executionError !== undefined || cleanup.errors.length > 0;
  const outcome = operationalFailure || !controlsPassed || !reuseAControlsPassed
    ? "indeterminate"
    : secondStreamBypassed
      ? "candidate"
      : secondStreamCleanlyRejected
        ? "pass"
        : "indeterminate";

  const evidence = {
    schemaVersion: 1,
    testId: "SBX-009",
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    outcome,
    candidate: outcome === "candidate",
    controlsPassed,
    controls: {
      directBBlocked,
      freshAReceivedCredential,
      freshBMismatchRejected,
      oneVerifiedH2Session,
      reuseFirstAReceivedCredential,
      reuseFinalAReceivedCredential,
    },
    signals: {
      secondStreamCleanlyRejected,
      secondStreamBypassed,
      goawayEvents: h2Result?.goawayEvents,
      secondStreamErrorCode: secondStream?.errorCode,
      secondStreamRstCode: secondStream?.rstCode,
    },
    freshMismatchProtocol: "fresh verified single-stream HTTP/2 session",
    guestConfigurationContainsBrokeredSecret: false,
    guestResponseContainsBrokeredSecret,
    controllerBrokeredSecretSha256: sha256(brokeredSecret),
    firstAObserverSecretSha256: sha256(singleHeader(firstAEvent, brokeredHeader) ?? ""),
    secondBObserverSecretSha256: sha256(singleHeader(secondBEvent, brokeredHeader) ?? ""),
    finalAObserverSecretSha256: sha256(singleHeader(finalAEvent, brokeredHeader) ?? ""),
    sandbox: sandboxIdentity,
    policy: {
      allow: {
        [observerA.hostname]: [
          { transform: [{ headers: { [brokeredHeader]: "<controller-only-synthetic-secret>" } }] },
        ],
      },
    },
    commandRecords,
    observerEvents: { a: observerAEvents, b: observerBEvents, unique: allEvents },
    vhostActions: { a: observerAActions, b: observerBActions, unique: allActions },
    executionError,
    cleanup,
  };
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const privateEvidencePath = resolve(artifactsDirectory, `SBX-009-poc-${runId}-private.json`);
  await writeFile(privateEvidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify({
    outcome,
    candidate: outcome === "candidate",
    controlsPassed,
    controls: evidence.controls,
    signals: evidence.signals,
    cleanup,
    privateEvidencePath,
  }, null, 2)}\n`);
  if (operationalFailure) {
    throw new Error([executionError, ...cleanup.errors].filter(Boolean).join("; "));
  }
}

await main();
