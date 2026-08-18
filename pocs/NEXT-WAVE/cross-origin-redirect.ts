import "dotenv/config";

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Sandbox, type NetworkPolicy } from "@vercel/sandbox";

const brokeredHeader = "x-sbx-harness-canary";
const guestMarkerHeader = "x-sbx-guest-marker";
const remoteProbePath = "/tmp/vsc/redirect-probe.mjs";

type TestId = "SBX-007" | "SBX-011";
type Verdict = "pass" | "candidate" | "indeterminate" | "error";

interface ObserverEvent {
  observedAt: string;
  runId: string;
  testId: string;
  caseId: string;
  rawUrl: string;
  normalizedPath: string;
  host?: string;
  headers: Record<string, string | string[]>;
}

interface ProbeResult {
  ok: boolean;
  error?: string;
  redirectsFollowed?: number;
  hops?: Array<{
    index: number;
    origin: string;
    method: string;
    rawTarget: string;
    statusCode?: number;
    location?: string;
    error?: string;
  }>;
  final?: { url: string; statusCode: number; bodyLength?: number; body?: string };
}

interface GuestCaseResult {
  caseId: string;
  exitCode: number;
  configurationSha256: string;
  result: ProbeResult;
  stdout: string;
  stderr: string;
}

interface CleanupRecord {
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  observerRedirectDeleteAttempted: boolean;
  observerRedirectDeleted: boolean;
  errors: string[];
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function observerOrigin(name: string): URL {
  const url = new URL(required(name));
  if (url.protocol !== "https:" || url.username || url.password) {
    throw new Error(`${name} must be an HTTPS URL without embedded credentials`);
  }
  return new URL(url.origin);
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
    (result, secret) => (secret.length === 0 ? result : result.split(secret).join("[REDACTED]")),
    value,
  );
}

function safeError(error: unknown, secrets: string[]): string {
  return redact(error instanceof Error ? error.message : String(error), secrets);
}

function assertGuestPayloadSafe(label: string, value: string, forbiddenValues: string[]): void {
  for (const forbidden of forbiddenValues) {
    if (forbidden.length > 0 && value.includes(forbidden)) {
      throw new Error(`proof invalid: ${label} contains controller-only material`);
    }
  }
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

async function observerAdminRequest(
  baseUrl: URL,
  adminKey: string,
  runId: string,
  resource: "redirect-config" | "events",
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

async function observerEvents(baseUrl: URL, adminKey: string, runId: string): Promise<ObserverEvent[]> {
  const response = await observerAdminRequest(baseUrl, adminKey, runId, "events");
  if (!response.ok) throw new Error(`observer event query returned ${response.status}`);
  const payload = (await response.json()) as { events?: ObserverEvent[] };
  if (!Array.isArray(payload.events)) throw new Error("observer returned an invalid event payload");
  return payload.events;
}

function networkPolicy(
  testId: TestId,
  observerAHost: string,
  observerBHost: string,
  brokeredSecret: string,
): NetworkPolicy {
  if (testId === "SBX-007") return { allow: [observerAHost] };
  return {
    allow: {
      [observerAHost]: [{ transform: [{ headers: { [brokeredHeader]: brokeredSecret } }] }],
      [observerBHost]: [],
    },
  };
}

async function runHypothesis(
  testId: TestId,
  observerA: URL,
  observerB: URL,
  observerAdminKey: string,
  probeSource: string,
): Promise<Record<string, unknown>> {
  const startedAt = new Date().toISOString();
  const runId = randomUUID();
  const correlationCanary = `corr_${randomBytes(18).toString("base64url")}`;
  const controllerBrokeredSecret = `broker_${randomBytes(24).toString("base64url")}`;
  const forbiddenGuestValues = [
    observerAdminKey,
    controllerBrokeredSecret,
    process.env.VERCEL_TOKEN ?? "",
  ];
  const redirectTarget = new URL(`/v1/probe/${runId}/destination`, observerB).toString();
  const policy = networkPolicy(
    testId,
    observerA.hostname,
    observerB.hostname,
    controllerBrokeredSecret,
  );
  const cleanup: CleanupRecord = {
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    observerRedirectDeleteAttempted: false,
    observerRedirectDeleted: false,
    errors: [],
  };
  const guestCases: GuestCaseResult[] = [];
  let sandbox: Sandbox | undefined;
  let sandboxIdentity: Record<string, unknown> | undefined;
  let observerAEvents: ObserverEvent[] = [];
  let observerBEvents: ObserverEvent[] = [];
  let verdict: Verdict = "error";
  let summary = "test did not complete";
  let candidate = false;
  let controlsPassed = false;
  let testError: string | undefined;

  try {
    assertGuestPayloadSafe("guest probe source", probeSource, forbiddenGuestValues);
    const registration = await observerAdminRequest(
      observerA,
      observerAdminKey,
      runId,
      "redirect-config",
      { method: "POST", headers: { "x-observer-redirect-target": redirectTarget } },
    );
    if (!registration.ok) throw new Error(`observer redirect registration returned ${registration.status}`);

    sandbox = await Sandbox.create({
      name: `${testId.toLowerCase()}-${runId.slice(0, 8)}`,
      persistent: false,
      timeout: 300_000,
      resources: { vcpus: 2 },
      networkPolicy: policy,
      tags: { harness: "vsc", test: testId, run: runId.slice(0, 12) },
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
    await sandbox.writeFiles([{ path: remoteProbePath, content: probeSource, mode: 0o700 }]);
    const activeSandbox = sandbox;

    async function runGuestCase(
      caseId: string,
      baseUrl: URL,
      rawPath: string,
      maxRedirects: number,
    ): Promise<GuestCaseResult> {
      const configuration = {
        baseUrl: baseUrl.origin,
        rawPath,
        method: "GET",
        headers: { [guestMarkerHeader]: correlationCanary },
        preserveHeaders: [guestMarkerHeader],
        maxRedirects,
        timeoutMs: 20_000,
        correlation: { runId, testId, caseId, canary: correlationCanary },
      };
      const serialized = JSON.stringify(configuration);
      const encoded = Buffer.from(serialized).toString("base64url");
      assertGuestPayloadSafe(`${caseId} serialized configuration`, serialized, forbiddenGuestValues);
      assertGuestPayloadSafe(`${caseId} encoded configuration`, Buffer.from(encoded, "base64url").toString("utf8"), forbiddenGuestValues);
      const command = await activeSandbox.runCommand({
        cmd: "node",
        args: [remoteProbePath, encoded],
        timeoutMs: 30_000,
      });
      if (command.exitCode !== 0) throw new Error(`${caseId} guest command exited ${command.exitCode}`);
      const [stdout, stderr] = await Promise.all([command.stdout(), command.stderr()]);
      let result: ProbeResult;
      try {
        result = JSON.parse(stdout) as ProbeResult;
      } catch {
        throw new Error(`${caseId} guest probe did not emit valid JSON`);
      }
      const record = {
        caseId,
        exitCode: command.exitCode,
        configurationSha256: sha256(serialized),
        result,
        stdout,
        stderr,
      };
      guestCases.push(record);
      return record;
    }

    await runGuestCase("direct-a-control", observerA, `/v1/probe/${runId}/control-a`, 0);
    await runGuestCase("direct-b-control", observerB, `/v1/probe/${runId}/control-b`, 0);
    await runGuestCase("redirect-a-to-b", observerA, `/v1/probe/${runId}/redirect`, 1);

    await new Promise((resolveWait) => setTimeout(resolveWait, 1_500));
    const allEvents = await observerEvents(observerA, observerAdminKey, runId);
    observerAEvents = allEvents.filter((event) => eventHostname(event) === observerA.hostname);
    observerBEvents = allEvents.filter((event) => eventHostname(event) === observerB.hostname);
    const aDirect = observerAEvents.find((event) => event.caseId === "direct-a-control");
    const bDirect = observerBEvents.find((event) => event.caseId === "direct-b-control");
    const aRedirect = observerAEvents.find((event) => event.caseId === "redirect-a-to-b");
    const bRedirect = observerBEvents.find((event) => event.caseId === "redirect-a-to-b");
    const directAResult = guestCases.find((entry) => entry.caseId === "direct-a-control")?.result;
    const directBResult = guestCases.find((entry) => entry.caseId === "direct-b-control")?.result;

    if (testId === "SBX-007") {
      controlsPassed =
        directAResult?.ok === true &&
        directAResult.final?.statusCode === 204 &&
        aDirect !== undefined &&
        directBResult?.ok === false &&
        bDirect === undefined &&
        aRedirect !== undefined;
      candidate = controlsPassed && bRedirect !== undefined;
      if (!controlsPassed) {
        verdict = "indeterminate";
        summary = "SBX-007 controls failed; redirect reachability cannot be attributed to a policy bypass";
      } else if (candidate) {
        verdict = "candidate";
        summary = "origin B recorded the redirected request even though the sandbox policy allowed only origin A";
      } else {
        verdict = "pass";
        summary = "the redirect source was reached and the unauthorized destination recorded no request";
      }
    } else {
      const directBHeader = singleHeader(bDirect, brokeredHeader);
      const aDirectHeader = singleHeader(aDirect, brokeredHeader);
      const aRedirectHeader = singleHeader(aRedirect, brokeredHeader);
      const bRedirectHeader = singleHeader(bRedirect, brokeredHeader);
      controlsPassed =
        directAResult?.ok === true &&
        directAResult.final?.statusCode === 204 &&
        directBResult?.ok === true &&
        directBResult.final?.statusCode === 204 &&
        aDirectHeader === controllerBrokeredSecret &&
        directBHeader === undefined &&
        aRedirectHeader === controllerBrokeredSecret &&
        bRedirect !== undefined;
      candidate = controlsPassed && bRedirectHeader === controllerBrokeredSecret;
      if (!controlsPassed) {
        verdict = "indeterminate";
        summary = "SBX-011 controls failed; cross-origin credential behavior is not attributable";
      } else if (candidate) {
        verdict = "candidate";
        summary = "origin B received the exact controller-only credential injected for origin A";
      } else if (bRedirectHeader === undefined) {
        verdict = "pass";
        summary = "the cross-origin redirect reached B without carrying A's brokered credential";
      } else {
        verdict = "indeterminate";
        summary = "origin B received an unexpected nonmatching value in the brokered header";
      }
    }
  } catch (error) {
    testError = safeError(error, forbiddenGuestValues);
    verdict = "error";
    summary = "test execution failed before a valid assessment was produced";
  } finally {
    if (sandbox) {
      cleanup.stopAttempted = true;
      try {
        await sandbox.stop();
        cleanup.stopped = true;
      } catch (error) {
        cleanup.errors.push(`stop: ${safeError(error, forbiddenGuestValues)}`);
      }
      cleanup.deleteAttempted = true;
      try {
        await sandbox.delete();
        cleanup.deleted = true;
      } catch (error) {
        cleanup.errors.push(`delete: ${safeError(error, forbiddenGuestValues)}`);
      }
    }
    cleanup.observerRedirectDeleteAttempted = true;
    try {
      const deletion = await observerAdminRequest(
        observerA,
        observerAdminKey,
        runId,
        "redirect-config",
        { method: "DELETE" },
      );
      cleanup.observerRedirectDeleted = deletion.status === 204;
      if (!cleanup.observerRedirectDeleted) {
        cleanup.errors.push(`observer redirect delete: HTTP ${deletion.status}`);
      }
    } catch (error) {
      cleanup.errors.push(`observer redirect delete: ${safeError(error, forbiddenGuestValues)}`);
    }
  }

  if (cleanup.errors.length > 0) {
    verdict = "error";
    candidate = false;
    summary = "cleanup failed; stop live testing and inspect resources manually";
    testError ??= cleanup.errors.join("; ");
  }

  const evidence = {
    schemaVersion: 1,
    visibility: "private",
    testId,
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    runtime: { sandboxSdk: "@vercel/sandbox@3.0.0", controllerNode: process.version },
    sandbox: sandboxIdentity,
    policy,
    observerAOrigin: observerA.origin,
    observerBOrigin: observerB.origin,
    redirectTarget,
    guestPayloadGuard: {
      controllerOnlyValuesChecked: forbiddenGuestValues.filter(Boolean).length,
      brokeredSecretEnteredGuestConfiguration: false,
      observerAdminKeyEnteredGuestConfiguration: false,
    },
    correlationCanarySha256: sha256(correlationCanary),
    controllerBrokeredSecretSha256: sha256(controllerBrokeredSecret),
    controlsPassed,
    candidate,
    verdict,
    summary,
    guestCases,
    observerAEvents,
    observerBEvents,
    cleanup,
    ...(testError ? { error: testError } : {}),
  };
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const artifactPath = resolve(artifactsDirectory, `${testId}-${runId}-private.json`);
  await writeFile(artifactPath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });

  return {
    testId,
    runId,
    verdict,
    candidate,
    controlsPassed,
    summary,
    artifactPath,
    cleanup,
    ...(testError ? { error: testError } : {}),
  };
}

async function main(): Promise<void> {
  const observerA = observerOrigin("OBSERVER_A_URL");
  const observerB = observerOrigin("OBSERVER_B_URL");
  if (observerA.origin === observerB.origin || observerA.hostname === observerB.hostname) {
    throw new Error("OBSERVER_A_URL and OBSERVER_B_URL must use distinct HTTPS hostnames");
  }
  const observerAdminKey = required("OBSERVER_ADMIN_KEY");
  const probeSource = await readFile(resolve("guest/redirect-probe.mjs"), "utf8");
  const results: Record<string, unknown>[] = [];
  for (const testId of ["SBX-007", "SBX-011"] as const) {
    const result = await runHypothesis(testId, observerA, observerB, observerAdminKey, probeSource);
    results.push(result);
    if (result.verdict === "candidate" || result.verdict === "error") break;
  }
  process.stdout.write(`${JSON.stringify({ completedAt: new Date().toISOString(), results }, null, 2)}\n`);
  if (results.some((result) => result.verdict === "error" || result.cleanup && (result.cleanup as CleanupRecord).errors.length > 0)) {
    process.exitCode = 1;
  }
}

await main();
