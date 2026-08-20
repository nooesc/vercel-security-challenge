import "dotenv/config";

import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { resolve4 } from "node:dns/promises";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { APIError, Sandbox } from "@vercel/sandbox";

const TEST_ID = "SBX-021-POC";
const SCOPE_CONFIRMATION = "I_CONTROL_THE_ENDPOINT_AND_AUTHORIZE_BOUNDED_CIDR_PRECEDENCE_TESTING";
const REMOTE_PROBE_PATH = "/tmp/sbx-021/fixed-ip-deny-probe.py";
const REMOTE_OPERATOR_SECRET_PATH = "/tmp/sbx-021/operator-secret";
const MINIMUM_CONTROLLER_CALL_INTERVAL_MS = 250;
const CONTROL_PLANE_TIMEOUT_MS = 30_000;
const ELIGIBLE_ALIAS_EMAIL = "swve@wearehackerone.com";
const ELIGIBLE_TEAM_ID = "team_n98ERpVwV7HqmWRudAyK8sXQ";
const ELIGIBLE_PROJECT_ID = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
const CONTROLLED_ENDPOINT_HOSTNAME = "vsc-tls-deny-swve.cyrus-206.workers.dev";
const OPERATION_ID = /^h3_[A-Za-z0-9_-]{43}$/u;
const CANARY = /^[A-Za-z0-9_-]{16,128}$/u;
const CONTROL_CASES = new Set(["baseline-target-allow", "restricted-safe-control"]);
const TARGET_CASE = "restricted-target-secret";

class IndeterminateError extends Error {}

class RateGate {
  #lastStartedAt = 0;

  async beforeCall() {
    const remaining = MINIMUM_CONTROLLER_CALL_INTERVAL_MS - (Date.now() - this.#lastStartedAt);
    if (remaining > 0) await new Promise((resolveWait) => setTimeout(resolveWait, remaining));
    this.#lastStartedAt = Date.now();
  }
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function required(environment, name) {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function operationSignal() {
  return AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS);
}

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value : undefined;
}

function exactBoolean(value) {
  return value === true ? true : value === false ? false : undefined;
}

function numeric(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function safeText(value, maximum = 256) {
  return typeof value === "string"
    ? value.replace(/[\0\r\n]/gu, " ").slice(0, maximum)
    : undefined;
}

function redact(value, secrets) {
  return secrets.reduce(
    (output, secret) => secret.length === 0 ? output : output.split(secret).join("[REDACTED]"),
    value,
  );
}

function safeError(error, secrets) {
  return redact(error instanceof Error ? error.message : String(error), secrets)
    .replace(/[\0\r\n]/gu, " ")
    .slice(0, 1_000);
}

function isNotFound(error) {
  return error instanceof APIError && error.response.status === 404;
}

export function isPublicIPv4(value) {
  if (isIP(value) !== 4) return false;
  const [a = -1, b = -1] = value.split(".").map(Number);
  if (a <= 0 || a >= 224 || a === 127) return false;
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return false;
  if ((a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127)) return false;
  if ((a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19))) return false;
  return true;
}

export function selectAddressPair(addresses, targetOverride, safeOverride) {
  const unique = [...new Set(addresses.filter(isPublicIPv4))].sort((left, right) =>
    left.localeCompare(right, "en", { numeric: true })
  );
  if (unique.length < 2) throw new Error("the controlled endpoint must currently resolve to at least two public IPv4 addresses");
  if (targetOverride !== undefined && !unique.includes(targetOverride)) {
    throw new Error("SBX021_TARGET_IPV4 is not one of the endpoint's current public A records");
  }
  if (safeOverride !== undefined && !unique.includes(safeOverride)) {
    throw new Error("SBX021_SAFE_IPV4 is not one of the endpoint's current public A records");
  }
  const target = targetOverride ?? unique[0];
  const safe = safeOverride ?? unique.find((address) => address !== target);
  if (!target || !safe || target === safe) {
    throw new Error("target and safe IPv4 controls must be distinct current A records");
  }
  return { target, safe, currentAddresses: unique };
}

export function expectedOperationId(key, runId, caseId, canary) {
  return `h3_${createHmac("sha256", key).update(`${runId}\n${caseId}\n${canary}`).digest("base64url")}`;
}

export function baselinePolicy(hostname) {
  return { allow: [hostname] };
}

export function restrictedPolicy(hostname, targetIPv4) {
  return { allow: [hostname], subnets: { deny: [`${targetIPv4}/32`] } };
}

function exactKeys(value, keys) {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

export function matchesBaselinePolicy(value, hostname) {
  const policy = record(value);
  return policy !== undefined && exactKeys(policy, ["allow"]) && Array.isArray(policy.allow) &&
    policy.allow.length === 1 && policy.allow[0] === hostname;
}

export function matchesRestrictedPolicy(value, hostname, targetIPv4) {
  const policy = record(value);
  const subnets = record(policy?.subnets);
  return policy !== undefined && exactKeys(policy, ["allow", "subnets"]) &&
    Array.isArray(policy.allow) && policy.allow.length === 1 && policy.allow[0] === hostname &&
    subnets !== undefined && exactKeys(subnets, ["deny"]) && Array.isArray(subnets.deny) &&
    subnets.deny.length === 1 && subnets.deny[0] === `${targetIPv4}/32`;
}

export function buildProbeConfiguration({ endpointUrl, pinnedIPv4, runId, caseId, publicCanary }) {
  if (!CONTROL_CASES.has(caseId) && caseId !== TARGET_CASE) {
    throw new Error("caseId is not one fixed SBX-021 case");
  }
  const configuration = {
    scopeConfirmation: SCOPE_CONFIRMATION,
    endpointUrl,
    pinnedIPv4,
    runId,
    testId: TEST_ID,
    caseId,
    timeoutSeconds: 8,
    maxResponseBytes: 1_024,
  };
  if (caseId === TARGET_CASE) {
    if (publicCanary !== undefined) throw new Error("target case must not receive a canary in guest configuration");
  } else {
    if (typeof publicCanary !== "string" || !CANARY.test(publicCanary)) {
      throw new Error("control cases require one bounded public canary");
    }
    configuration.publicCanary = publicCanary;
  }
  return configuration;
}

export function assessExplicitDeny(input) {
  if (!input.cleanupPassed) {
    return { verdict: "error", candidate: false, controlsPassed: false, summary: "Owned sandbox cleanup failed." };
  }
  if (input.executionError) {
    return { verdict: "error", candidate: false, controlsPassed: false, summary: "Controller execution failed before a valid verdict." };
  }
  const controlsPassed = input.setupPassed && input.baselinePolicyReadbackPassed &&
    input.baselineTargetSucceeded && input.updateAcknowledged && input.activeReadbackPassed &&
    input.independentReadbackPassed && input.sameSessionReadbackPassed &&
    input.restrictedSafeSucceeded;
  if (!controlsPassed) {
    return {
      verdict: "indeterminate",
      candidate: false,
      controlsPassed: false,
      summary: "A setup, baseline, exact-policy, same-session, or non-denied-address control failed.",
    };
  }
  if (input.restrictedTargetSucceeded) {
    return {
      verdict: "candidate",
      candidate: true,
      controlsPassed: true,
      summary: "The explicitly denied address received the file-backed synthetic operator secret despite documented deny precedence.",
    };
  }
  if (input.restrictedTargetBlocked) {
    return {
      verdict: "pass",
      candidate: false,
      controlsPassed: true,
      summary: "The explicit /32 deny overrode the domain allow while the non-denied address remained reachable.",
    };
  }
  return {
    verdict: "indeterminate",
    candidate: false,
    controlsPassed: true,
    summary: "The target result was neither an authenticated secret action nor a conclusive pre-response block.",
  };
}

function controlledEndpoint(environment) {
  if (required(environment, "SBX021_SCOPE_CONFIRMATION") !== SCOPE_CONFIRMATION) {
    throw new Error(`SBX021_SCOPE_CONFIRMATION must equal ${SCOPE_CONFIRMATION}`);
  }
  const endpoint = new URL(required(environment, "SBX021_ENDPOINT_URL"));
  if (
    endpoint.protocol !== "https:" || endpoint.username || endpoint.password || endpoint.search ||
    endpoint.hash || (endpoint.port !== "" && endpoint.port !== "443") ||
    isIP(endpoint.hostname) !== 0 || endpoint.hostname !== CONTROLLED_ENDPOINT_HOSTNAME ||
    endpoint.pathname !== "/v1/h3-action"
  ) {
    throw new Error(
      `SBX021_ENDPOINT_URL must be the owned HTTPS endpoint https://${CONTROLLED_ENDPOINT_HOSTNAME}/v1/h3-action`,
    );
  }
  return endpoint;
}

function hmacKey(environment) {
  const key = required(environment, "H3_ACTION_KEY");
  const bytes = Buffer.byteLength(key);
  if (bytes < 32 || bytes > 256 || /[\0\r\n]/u.test(key)) {
    throw new Error("H3_ACTION_KEY must contain 32-256 bytes without control characters");
  }
  return key;
}

function optionalIPv4(environment, name) {
  const value = environment[name];
  if (value === undefined) return undefined;
  if (!isPublicIPv4(value)) throw new Error(`${name} must be one public IPv4 address`);
  return value;
}

export function explicitCredentials(environment) {
  const token = required(environment, "VERCEL_TOKEN");
  const teamId = required(environment, "VERCEL_TEAM_ID");
  const projectId = required(environment, "VERCEL_PROJECT_ID");
  if (teamId !== ELIGIBLE_TEAM_ID || projectId !== ELIGIBLE_PROJECT_ID) {
    throw new Error("SBX-021 must use the verified HackerOne-alias Vercel team and project");
  }
  return { token, teamId, projectId };
}

async function verifyAliasIdentity(token) {
  const response = await fetch("https://api.vercel.com/v2/user", {
    headers: { Authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error(`could not verify Vercel token identity (${response.status})`);
  const payload = await response.json();
  if (payload?.user?.email !== ELIGIBLE_ALIAS_EMAIL) {
    throw new Error("Vercel token is not authenticated as the required HackerOne alias");
  }
  return payload.user.email;
}

function sanitizeProbeResult(value) {
  const input = record(value);
  if (!input) return undefined;
  const response = record(input.response);
  return {
    ok: exactBoolean(input.ok),
    phase: safeText(input.phase, 64),
    runId: safeText(input.runId, 128),
    testId: safeText(input.testId, 128),
    caseId: safeText(input.caseId, 128),
    canarySource: input.canarySource === "controller-public-canary" || input.canarySource === "operator-secret-file"
      ? input.canarySource
      : undefined,
    endpointHostname: safeText(input.endpointHostname, 253),
    pinnedIPv4: safeText(input.pinnedIPv4, 64),
    pinnedPort: numeric(input.pinnedPort),
    protocol: input.protocol === "https-http1.1" ? input.protocol : undefined,
    tlsVerificationRequired: exactBoolean(input.tlsVerificationRequired),
    tlsVerifiedByClient: exactBoolean(input.tlsVerifiedByClient),
    sniEqualsEndpointHostname: exactBoolean(input.sniEqualsEndpointHostname),
    dnsLookupUsedForConnection: exactBoolean(input.dnsLookupUsedForConnection),
    redirectsAllowed: exactBoolean(input.redirectsAllowed),
    environmentProxyTrust: exactBoolean(input.environmentProxyTrust),
    tlsVersion: safeText(input.tlsVersion, 32),
    tlsCipher: safeText(input.tlsCipher, 128),
    selectedAlpn: safeText(input.selectedAlpn, 32),
    peerCertificateSha256: safeText(input.peerCertificateSha256, 64),
    remoteIp: safeText(input.remoteIp, 64),
    remotePort: numeric(input.remotePort),
    requestTargetSha256: safeText(input.requestTargetSha256, 64),
    secretBearingRequestMaterialRetention:
      input.secretBearingRequestMaterialRetention === "none" ||
      input.secretBearingRequestMaterialRetention === "not-applicable"
        ? input.secretBearingRequestMaterialRetention
        : undefined,
    response: response ? {
      statusCode: numeric(response.statusCode),
      httpVersion: numeric(response.httpVersion),
      contentType: safeText(response.contentType, 128),
      cacheControl: safeText(response.cacheControl, 128),
      bodyByteLength: numeric(response.bodyByteLength),
    } : undefined,
    authorized: exactBoolean(input.authorized),
    operationId: typeof input.operationId === "string" && OPERATION_ID.test(input.operationId)
      ? input.operationId
      : undefined,
    operationIdShapeValid: exactBoolean(input.operationIdShapeValid),
    errorType: safeText(input.errorType, 96),
    errorNumber: numeric(input.errorNumber),
    responseStatusCode: numeric(input.responseStatusCode),
    durationMs: numeric(input.durationMs),
  };
}

function authenticatedSuccess(probe, { endpoint, pinnedIPv4, runId, caseId }) {
  const result = probe?.result;
  const response = record(result?.response);
  const cacheControl = typeof response?.cacheControl === "string"
    ? response.cacheControl.toLowerCase().split(",").map((entry) => entry.trim())
    : [];
  return probe?.command.exitCode === 0 && result?.ok === true && result.phase === "response" &&
    result.runId === runId && result.testId === TEST_ID && result.caseId === caseId &&
    result.endpointHostname === endpoint.hostname && result.pinnedIPv4 === pinnedIPv4 &&
    result.pinnedPort === 443 && result.protocol === "https-http1.1" &&
    result.tlsVerificationRequired === true && result.tlsVerifiedByClient === true &&
    result.sniEqualsEndpointHostname === true && result.dnsLookupUsedForConnection === false &&
    result.redirectsAllowed === false && result.environmentProxyTrust === false &&
    result.selectedAlpn === "http/1.1" && result.remoteIp === pinnedIPv4 && result.remotePort === 443 &&
    typeof result.peerCertificateSha256 === "string" && /^[a-f0-9]{64}$/u.test(result.peerCertificateSha256) &&
    response?.statusCode === 200 && response.httpVersion === 11 &&
    typeof response.contentType === "string" && response.contentType.toLowerCase().startsWith("application/json") &&
    cacheControl.includes("no-store") && typeof response.bodyByteLength === "number" && response.bodyByteLength <= 1_024 &&
    (caseId === TARGET_CASE
      ? result.secretBearingRequestMaterialRetention === "none" && result.requestTargetSha256 === undefined
      : result.secretBearingRequestMaterialRetention === "not-applicable" &&
        typeof result.requestTargetSha256 === "string" && /^[a-f0-9]{64}$/u.test(result.requestTargetSha256)) &&
    result.authorized === true && result.operationIdShapeValid === true &&
    result.operationId === probe.expectedOperationId;
}

export function conclusivePreResponseBlock(probe, { endpoint, pinnedIPv4, runId }) {
  const result = probe?.result;
  return probe?.command.exitCode === 0 && result?.ok === false &&
    result.phase === "connect" && result.errorType === "OSError" && result.errorNumber === 113 &&
    result.runId === runId &&
    result.testId === TEST_ID && result.caseId === TARGET_CASE &&
    result.canarySource === "operator-secret-file" && result.endpointHostname === endpoint.hostname &&
    result.pinnedIPv4 === pinnedIPv4 && result.pinnedPort === 443 &&
    result.protocol === "https-http1.1" && result.tlsVerificationRequired === true &&
    result.sniEqualsEndpointHostname === true && result.dnsLookupUsedForConnection === false &&
    result.redirectsAllowed === false && result.environmentProxyTrust === false &&
    result.secretBearingRequestMaterialRetention === "none" && result.requestTargetSha256 === undefined &&
    result.responseStatusCode === 0 && result.operationId === undefined;
}

async function captureCommand(sandbox, gate, params, secrets) {
  const serialized = JSON.stringify(params);
  if (secrets.some((secret) => secret && serialized.includes(secret))) {
    throw new Error("guest command arguments or environment contained controller-only material");
  }
  await gate.beforeCall();
  const command = await sandbox.runCommand({ ...params, signal: operationSignal() });
  const [stdout, stderr] = await Promise.all([
    command.stdout({ signal: operationSignal() }),
    command.stderr({ signal: operationSignal() }),
  ]);
  if (secrets.some((secret) => secret && (stdout.includes(secret) || stderr.includes(secret)))) {
    throw new Error("guest command output contained controller-only material");
  }
  return {
    record: {
      commandId: command.cmdId,
      exitCode: command.exitCode,
      ...(command.durationMs !== undefined ? { durationMs: command.durationMs } : {}),
      stdoutByteLength: Buffer.byteLength(stdout),
      stdoutSha256: sha256(stdout),
      stderrByteLength: Buffer.byteLength(stderr),
      stderrSha256: sha256(stderr),
    },
    stdout,
  };
}

export async function main(environment = process.env) {
  const startedAt = new Date().toISOString();
  const endpoint = controlledEndpoint(environment);
  const controllerHmacKey = hmacKey(environment);
  const credentials = explicitCredentials(environment);
  const verifiedAliasEmail = await verifyAliasIdentity(credentials.token);
  const operatorSecret = randomBytes(32).toString("base64url");
  const operatorSecretSha256 = sha256(operatorSecret);
  const controllerSecrets = [
    controllerHmacKey,
    operatorSecret,
    environment.VERCEL_TOKEN ?? "",
  ].filter(Boolean);
  const dnsStartedAt = new Date().toISOString();
  const resolved = await resolve4(endpoint.hostname, { ttl: true });
  const dnsCompletedAt = new Date().toISOString();
  const pair = selectAddressPair(
    resolved.map((answer) => answer.address),
    optionalIPv4(environment, "SBX021_TARGET_IPV4"),
    optionalIPv4(environment, "SBX021_SAFE_IPV4"),
  );
  const targetIPv4 = pair.target;
  const safeIPv4 = pair.safe;
  const runId = randomUUID();
  const sandboxName = `sbx-021-poc-${runId.replaceAll("-", "")}`;
  const sandboxTags = { harness: "vsc", test: "SBX-021", run: runId };
  const publicCanaries = {
    "baseline-target-allow": `public_${randomBytes(18).toString("base64url")}`,
    "restricted-safe-control": `public_${randomBytes(18).toString("base64url")}`,
  };
  const guestSource = await readFile(resolve("guest/fixed-ip-deny-probe.py"), "utf8");
  if (controllerSecrets.some((secret) => guestSource.includes(secret))) {
    throw new Error("guest source unexpectedly contains controller-only material");
  }
  const initialPolicy = baselinePolicy(endpoint.hostname);
  const tightenedPolicy = restrictedPolicy(endpoint.hostname, targetIPv4);
  const gate = new RateGate();
  const probes = [];
  let endpointRequestAttempts = 0;
  const transitions = [];
  const cleanup = {
    orphanRecoveryAttempted: false,
    recoveredHandle: false,
    orphanAbsenceConfirmed: false,
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    errors: [],
  };
  const operatorSecretSetup = {
    path: REMOTE_OPERATOR_SECRET_PATH,
    sha256: operatorSecretSha256,
    writtenBeforeRestrictedPolicy: false,
    verifiedBeforeRestrictedPolicy: false,
  };
  let sandbox;
  let createAttempted = false;
  let sandboxIdentity;
  let executionError;
  let executionIndeterminate = false;
  let setupPassed = false;
  let baselinePolicyReadbackPassed = false;
  let baselineTargetSucceeded = false;
  let updateAcknowledged = false;
  let activeReadbackPassed = false;
  let independentReadbackPassed = false;
  let sameSessionReadbackPassed = false;
  let restrictedSafeSucceeded = false;
  let restrictedTargetSucceeded = false;
  let restrictedTargetBlocked = false;

  async function runProbe(caseId, pinnedIPv4, publicCanary) {
    if (!sandbox) throw new Error("sandbox is not available");
    const configuration = buildProbeConfiguration({
      endpointUrl: endpoint.href,
      pinnedIPv4,
      runId,
      caseId,
      ...(publicCanary ? { publicCanary } : {}),
    });
    const serialized = JSON.stringify(configuration);
    if (controllerSecrets.some((secret) => serialized.includes(secret))) {
      throw new Error(`${caseId} guest configuration contains controller-only material`);
    }
    const requestCanary = caseId === TARGET_CASE ? operatorSecret : publicCanary;
    if (!requestCanary) throw new Error(`${caseId} has no request canary source`);
    endpointRequestAttempts += 1;
    const captured = await captureCommand(
      sandbox,
      gate,
      {
        cmd: "python3",
        args: [REMOTE_PROBE_PATH, Buffer.from(serialized).toString("base64url")],
        env: { HTTP_PROXY: "", HTTPS_PROXY: "", ALL_PROXY: "", NO_PROXY: "*" },
        timeoutMs: 15_000,
      },
      controllerSecrets,
    );
    let decoded;
    try {
      decoded = JSON.parse(captured.stdout);
    } catch {
      throw new Error(`${caseId} guest probe emitted invalid JSON`);
    }
    const result = sanitizeProbeResult(decoded);
    const probe = {
      caseId,
      pinnedIPv4,
      canarySource: caseId === TARGET_CASE ? "operator-secret-file" : "controller-public-canary",
      configurationSha256: sha256(serialized),
      ...(publicCanary ? { publicCanarySha256: sha256(publicCanary) } : {}),
      expectedOperationId: expectedOperationId(controllerHmacKey, runId, caseId, requestCanary),
      command: captured.record,
      ...(result ? { result } : {}),
    };
    probes.push(probe);
    return probe;
  }

  try {
    await gate.beforeCall();
    createAttempted = true;
    sandbox = await Sandbox.create({
      name: sandboxName,
      persistent: false,
      timeout: 240_000,
      networkPolicy: initialPolicy,
      tags: sandboxTags,
      signal: operationSignal(),
      ...credentials,
    });
    const initialSession = sandbox.currentSession();
    const initialSessionId = initialSession.sessionId;
    sandboxIdentity = {
      name: sandbox.name,
      sessionId: initialSessionId,
      sessionCreatedAt: initialSession.createdAt.toISOString(),
      sessionRequestedAt: initialSession.requestedAt.toISOString(),
      region: initialSession.region,
      persistent: sandbox.persistent,
      initialNetworkPolicy: sandbox.networkPolicy,
      initialSessionNetworkPolicy: initialSession.networkPolicy,
    };
    baselinePolicyReadbackPassed = matchesBaselinePolicy(sandbox.networkPolicy, endpoint.hostname) &&
      matchesBaselinePolicy(initialSession.networkPolicy, endpoint.hostname);
    if (!baselinePolicyReadbackPassed) {
      throw new IndeterminateError("fresh sandbox did not report the exact hostname-only baseline policy");
    }

    await gate.beforeCall();
    await sandbox.writeFiles([
      { path: REMOTE_PROBE_PATH, content: guestSource, mode: 0o700 },
      { path: REMOTE_OPERATOR_SECRET_PATH, content: operatorSecret, mode: 0o600 },
    ], { signal: operationSignal() });
    operatorSecretSetup.writtenBeforeRestrictedPolicy = true;
    const secretVerification = await captureCommand(
      sandbox,
      gate,
      {
        cmd: "python3",
        args: [
          "-c",
          `import hashlib,os,stat; p=${JSON.stringify(REMOTE_OPERATOR_SECRET_PATH)}; fd=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)); s=os.fstat(fd); d=os.read(fd,129); os.close(fd); assert stat.S_ISREG(s.st_mode) and not s.st_mode&0o077 and len(d)==s.st_size and 16<=len(d)<=128; print(hashlib.sha256(d).hexdigest())`,
        ],
        timeoutMs: 10_000,
      },
      controllerSecrets,
    );
    operatorSecretSetup.verificationCommand = secretVerification.record;
    operatorSecretSetup.observedSha256 = safeText(secretVerification.stdout.trim(), 64);
    operatorSecretSetup.verifiedBeforeRestrictedPolicy = secretVerification.record.exitCode === 0 &&
      secretVerification.stdout.trim() === operatorSecretSha256;
    if (!operatorSecretSetup.verifiedBeforeRestrictedPolicy) {
      throw new IndeterminateError("synthetic operator-secret file verification failed");
    }
    setupPassed = true;

    const baselineTarget = await runProbe(
      "baseline-target-allow",
      targetIPv4,
      publicCanaries["baseline-target-allow"],
    );
    baselineTargetSucceeded = authenticatedSuccess(baselineTarget, {
      endpoint,
      pinnedIPv4: targetIPv4,
      runId,
      caseId: "baseline-target-allow",
    });
    if (!baselineTargetSucceeded) {
      throw new IndeterminateError("hostname-only baseline did not reach the pinned target address");
    }

    const updateStartedAt = new Date().toISOString();
    await gate.beforeCall();
    await sandbox.update({ networkPolicy: tightenedPolicy }, { signal: operationSignal() });
    updateAcknowledged = true;
    const activeReadback = sandbox.networkPolicy;
    const activeSession = sandbox.currentSession();
    const activeSessionReadback = activeSession.networkPolicy;
    const activeSessionId = activeSession.sessionId;
    activeReadbackPassed = matchesRestrictedPolicy(activeReadback, endpoint.hostname, targetIPv4) &&
      matchesRestrictedPolicy(activeSessionReadback, endpoint.hostname, targetIPv4);
    await gate.beforeCall();
    const independent = await Sandbox.get({
      name: sandbox.name,
      resume: false,
      signal: operationSignal(),
      ...credentials,
    });
    const independentSession = independent.currentSession();
    const independentSessionId = independentSession.sessionId;
    independentReadbackPassed = matchesRestrictedPolicy(independent.networkPolicy, endpoint.hostname, targetIPv4) &&
      matchesRestrictedPolicy(independentSession.networkPolicy, endpoint.hostname, targetIPv4);
    sameSessionReadbackPassed = Boolean(initialSessionId) && initialSessionId === activeSessionId &&
      initialSessionId === independentSessionId;
    transitions.push({
      stage: "hostname-only-to-hostname-plus-explicit-target-deny",
      startedAt: updateStartedAt,
      completedAt: new Date().toISOString(),
      updateAcknowledged,
      activeSandboxReadback: activeReadback,
      activeSessionReadback,
      independentSandboxReadback: independent.networkPolicy,
      independentSessionReadback: independentSession.networkPolicy,
      initialSessionId,
      activeSessionId,
      independentSessionId,
      sameSessionReadbackPassed,
    });
    if (!activeReadbackPassed || !independentReadbackPassed || !sameSessionReadbackPassed) {
      throw new IndeterminateError("exact restricted policy or same-session independent readback failed");
    }

    const restrictedSafe = await runProbe(
      "restricted-safe-control",
      safeIPv4,
      publicCanaries["restricted-safe-control"],
    );
    restrictedSafeSucceeded = authenticatedSuccess(restrictedSafe, {
      endpoint,
      pinnedIPv4: safeIPv4,
      runId,
      caseId: "restricted-safe-control",
    });
    if (!restrictedSafeSucceeded) {
      throw new IndeterminateError("the non-denied address did not remain reachable under the restricted policy");
    }

    const restrictedTarget = await runProbe(TARGET_CASE, targetIPv4);
    restrictedTargetSucceeded = authenticatedSuccess(restrictedTarget, {
      endpoint,
      pinnedIPv4: targetIPv4,
      runId,
      caseId: TARGET_CASE,
    });
    restrictedTargetBlocked = !restrictedTargetSucceeded && conclusivePreResponseBlock(
      restrictedTarget,
      { endpoint, pinnedIPv4: targetIPv4, runId },
    );
  } catch (error) {
    executionError = safeError(error, controllerSecrets);
    executionIndeterminate = error instanceof IndeterminateError;
  } finally {
    if (!sandbox && createAttempted) {
      cleanup.orphanRecoveryAttempted = true;
      let notFoundCount = 0;
      for (let attempt = 0; attempt < 3 && !sandbox; attempt += 1) {
        if (attempt > 0) await new Promise((resolveWait) => setTimeout(resolveWait, 1_000));
        try {
          await gate.beforeCall();
          const recovered = await Sandbox.get({
            name: sandboxName,
            resume: false,
            signal: operationSignal(),
            ...credentials,
          });
          const createdAt = recovered.createdAt.getTime();
          const creationWindowValid = Number.isFinite(createdAt) &&
            createdAt >= Date.parse(startedAt) - 5_000 && createdAt <= Date.now() + 5_000;
          const tagsValid = recovered.tags?.harness === sandboxTags.harness &&
            recovered.tags?.test === sandboxTags.test && recovered.tags?.run === sandboxTags.run;
          if (!creationWindowValid || !tagsValid) {
            cleanup.errors.push("orphan recovery found a sandbox without the exact run identity; left untouched");
            break;
          }
          sandbox = recovered;
          cleanup.recoveredHandle = true;
        } catch (error) {
          if (isNotFound(error)) {
            notFoundCount += 1;
          } else {
            cleanup.errors.push(`orphan recovery: ${safeError(error, controllerSecrets)}`);
            break;
          }
        }
      }
      cleanup.orphanAbsenceConfirmed = !sandbox && notFoundCount === 3;
    }
    if (sandbox) {
      cleanup.stopAttempted = true;
      try {
        await gate.beforeCall();
        await sandbox.stop({ signal: operationSignal() });
        cleanup.stopped = true;
      } catch (error) {
        cleanup.errors.push(`stop: ${safeError(error, controllerSecrets)}`);
      }
      cleanup.deleteAttempted = true;
      try {
        await gate.beforeCall();
        await sandbox.delete({ signal: operationSignal() });
        cleanup.deleted = true;
      } catch (error) {
        cleanup.errors.push(`delete: ${safeError(error, controllerSecrets)}`);
      }
    }
  }

  const cleanupPassed = !createAttempted || (
    cleanup.errors.length === 0 && (
      (sandbox !== undefined && cleanup.stopped && cleanup.deleted) ||
      (sandbox === undefined && cleanup.orphanAbsenceConfirmed)
    )
  );
  const assessment = assessExplicitDeny({
    setupPassed,
    baselinePolicyReadbackPassed,
    baselineTargetSucceeded,
    updateAcknowledged,
    activeReadbackPassed,
    independentReadbackPassed,
    sameSessionReadbackPassed,
    restrictedSafeSucceeded,
    restrictedTargetSucceeded,
    restrictedTargetBlocked,
    cleanupPassed,
    ...(executionError && !executionIndeterminate ? { executionError: true } : {}),
  });
  const evidence = {
    schemaVersion: 1,
    visibility: "private",
    testId: "SBX-021",
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    scope: "one researcher-owned Vercel sandbox and one researcher-owned dual-address Worker endpoint",
    requestBounds: {
      endpointRequestAttempts,
      retainedProbeResults: probes.length,
      maximumEndpointRequests: 3,
      sequential: true,
      retryCount: 0,
      redirectsAllowed: false,
      minimumControllerCallIntervalMs: MINIMUM_CONTROLLER_CALL_INTERVAL_MS,
    },
    endpoint: {
      origin: endpoint.origin,
      path: endpoint.pathname,
      targetIPv4,
      safeIPv4,
      currentAddresses: pair.currentAddresses,
      controllerResolvedAt: { startedAt: dnsStartedAt, completedAt: dnsCompletedAt },
      resolvedARecords: resolved,
      contract: "{authorized:true,operationId:h3_+base64url(HMAC-SHA256(H3_ACTION_KEY,runId\\ncaseId\\ncanary))}",
    },
    hmacKeySha256: sha256(controllerHmacKey),
    operatorSecretSha256,
    credentialContext: {
      mode: "explicit-alias-verified",
      email: verifiedAliasEmail,
      teamId: credentials.teamId,
      projectId: credentials.projectId,
    },
    sandbox: sandboxIdentity,
    operatorSecretSetup,
    policy: { initial: initialPolicy, tightened: tightenedPolicy, transitions },
    guestMaterialGuards: {
      hmacKeyEnteredGuestSource: false,
      hmacKeyEnteredGuestConfiguration: false,
      operatorSecretEnteredGuestSource: false,
      operatorSecretEnteredGuestConfigurationOrCommandArguments: false,
      operatorSecretAppearedInGuestOutput: false,
      vercelTokenEnteredGuestSourceOrConfiguration: false,
      controllerOnlyMaterialAppearedInGuestOutput: false,
      secretBearingRequestTargetOrDigestRetained: false,
    },
    probes,
    controls: {
      setupPassed,
      baselinePolicyReadbackPassed,
      baselineTargetSucceeded,
      updateAcknowledged,
      activeReadbackPassed,
      independentReadbackPassed,
      sameSessionReadbackPassed,
      restrictedSafeSucceeded,
      restrictedTargetSucceeded,
      restrictedTargetBlocked,
    },
    assessment,
    cleanup,
    ...(executionError ? { executionError } : {}),
  };
  const artifactsDirectory = resolve(environment.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const privateEvidencePath = resolve(artifactsDirectory, `SBX-021-poc-${runId}-private.json`);
  await writeFile(privateEvidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify({
    testId: "SBX-021",
    runId,
    verdict: assessment.verdict,
    candidate: assessment.candidate,
    summary: assessment.summary,
    endpointHostname: endpoint.hostname,
    targetIPv4,
    safeIPv4,
    sandbox: sandboxIdentity,
    controls: evidence.controls,
    hmacKeySha256: evidence.hmacKeySha256,
    cleanup,
    privateEvidencePath,
    ...(executionError ? { executionError } : {}),
  }, null, 2)}\n`);
  if (assessment.verdict !== "pass") process.exitCode = 1;
  return evidence;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
