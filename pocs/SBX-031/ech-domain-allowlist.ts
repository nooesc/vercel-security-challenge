import "dotenv/config";

import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { resolve4 } from "node:dns/promises";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Sandbox, type NetworkPolicy } from "@vercel/sandbox";

const testId = "SBX-031-POC";
const scopeConfirmation = "I_CONTROL_THE_ENDPOINT_AND_AUTHORIZE_BOUNDED_ECH_TESTING";
const expectedCurlCffiVersion = "0.13.0";
const expectedEchPublicName = "cloudflare-ech.com";
const remoteProbePath = "/tmp/sbx-031/ech-domain-probe.py";
const remoteSitePackages = "/tmp/sbx-031/site-packages";
const remoteOperatorSecretPath = "/tmp/sbx-031/operator-secret";
const minimumControllerCallIntervalMs = 250;
const controlPlaneTimeoutMs = 30_000;
const operationIdPattern = /^h3_[A-Za-z0-9_-]{43}$/u;
const canaryPattern = /^[A-Za-z0-9_-]{16,128}$/u;
const sha256Pattern = /^[a-f0-9]{64}$/u;
const dnsNamePattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;

type ProbeMode = "plain" | "ech";
export type EchVerdict = "candidate" | "pass" | "indeterminate" | "error";

export interface CommandRecord {
  commandId: string;
  exitCode: number;
  durationMs?: number;
  stdoutByteLength: number;
  stdoutSha256: string;
  stderrByteLength: number;
  stderrSha256: string;
}

export interface ProbeRecord {
  caseId: string;
  mode: ProbeMode;
  canarySource: "controller-public-canary" | "operator-secret-file";
  configurationSha256: string;
  publicCanarySha256?: string;
  expectedOperationId: string;
  command: CommandRecord;
  result?: Record<string, unknown>;
}

export interface EchAssessmentInput {
  setupPassed: boolean;
  allowPlainControlPassed: boolean;
  allowEchControlPassed: boolean;
  restrictedUpdateAcknowledged: boolean;
  restrictedReadbackPassed: boolean;
  restrictedPlainBlocked: boolean;
  restrictedEchSucceeded: boolean;
  restrictedEchBlocked: boolean;
  cleanupPassed: boolean;
  executionError?: boolean;
}

export interface EchAssessment {
  verdict: EchVerdict;
  candidate: boolean;
  controlsPassed: boolean;
  summary: string;
}

export interface EchConfigDetails {
  configCount: number;
  publicName: string;
  sha256: string;
  byteLength: number;
}

class IndeterminateError extends Error {}

class RateGate {
  private lastStartedAt = 0;

  async beforeCall(): Promise<void> {
    const remaining = minimumControllerCallIntervalMs - (Date.now() - this.lastStartedAt);
    if (remaining > 0) await new Promise((resolveWait) => setTimeout(resolveWait, remaining));
    this.lastStartedAt = Date.now();
  }
}

function controlSignal(timeoutMs = controlPlaneTimeoutMs): AbortSignal {
  return AbortSignal.timeout(timeoutMs);
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function safeText(value: unknown, maximum = 256): string | undefined {
  return typeof value === "string"
    ? value.replace(/[\0\r\n]/gu, " ").slice(0, maximum)
    : undefined;
}

function numeric(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function exactBoolean(value: unknown): boolean | undefined {
  return value === true ? true : value === false ? false : undefined;
}

function redact(value: string, secrets: string[]): string {
  return secrets.reduce(
    (output, secret) => secret.length === 0 ? output : output.split(secret).join("[REDACTED]"),
    value,
  );
}

function safeError(error: unknown, secrets: string[]): string {
  return redact(error instanceof Error ? error.message : String(error), secrets)
    .replace(/[\0\r\n]/gu, " ")
    .slice(0, 1_000);
}

function canonicalDnsName(value: string, field: string): string {
  const canonical = value.toLowerCase();
  if (value !== canonical || !dnsNamePattern.test(canonical)) {
    throw new Error(`${field} must be a lowercase canonical DNS hostname`);
  }
  return canonical;
}

function controlledEndpoint(): URL {
  if (required("SBX031_SCOPE_CONFIRMATION") !== scopeConfirmation) {
    throw new Error(`SBX031_SCOPE_CONFIRMATION must equal ${scopeConfirmation}`);
  }
  const endpoint = new URL(required("SBX031_ENDPOINT_URL"));
  if (
    endpoint.protocol !== "https:" || endpoint.username || endpoint.password || endpoint.search ||
    endpoint.hash || (endpoint.port !== "" && endpoint.port !== "443") ||
    endpoint.pathname !== "/v1/h3-action" || isIP(endpoint.hostname) !== 0
  ) {
    throw new Error(
      "SBX031_ENDPOINT_URL must be a researcher-owned HTTPS URL on port 443 at /v1/h3-action with a DNS hostname and no credentials, query, or fragment",
    );
  }
  canonicalDnsName(endpoint.hostname, "SBX031_ENDPOINT_URL hostname");
  if (endpoint.hostname === expectedEchPublicName) {
    throw new Error("the owned inner endpoint must be distinct from the ECH public name");
  }
  return endpoint;
}

function hmacKey(): string {
  const key = required("H3_ACTION_KEY");
  if (Buffer.byteLength(key) < 32 || Buffer.byteLength(key) > 256 || /[\0\r\n]/u.test(key)) {
    throw new Error("H3_ACTION_KEY must contain 32-256 bytes without control characters");
  }
  return key;
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

function publicIPv4(value: string): boolean {
  if (isIP(value) !== 4) return false;
  const [a = -1, b = -1] = value.split(".").map(Number);
  if (a <= 0 || a >= 224 || a === 127) return false;
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return false;
  if ((a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127)) return false;
  if ((a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19))) return false;
  return true;
}

export function parseEchConfigList(encoded: string): EchConfigDetails {
  if (encoded.length < 16 || encoded.length > 4096 || !/^[A-Za-z0-9+/]+={0,2}$/u.test(encoded)) {
    throw new Error("ECHConfigList must be bounded canonical base64");
  }
  const raw = Buffer.from(encoded, "base64");
  if (raw.toString("base64") !== encoded || raw.length < 6 || raw.length > 2_048) {
    throw new Error("ECHConfigList must be bounded canonical base64");
  }
  if (raw.readUInt16BE(0) !== raw.length - 2) throw new Error("ECHConfigList length is invalid");

  let position = 2;
  let configCount = 0;
  const publicNames = new Set<string>();
  while (position < raw.length) {
    if (position + 4 > raw.length) throw new Error("ECHConfig header is truncated");
    const version = raw.readUInt16BE(position);
    const contentsLength = raw.readUInt16BE(position + 2);
    position += 4;
    const end = position + contentsLength;
    if (version !== 0xfe0d || end > raw.length) {
      throw new Error("ECHConfig version or length is unsupported");
    }
    let cursor = position;
    if (cursor + 5 > end) throw new Error("ECHConfig contents are truncated");
    cursor += 3;
    const publicKeyLength = raw.readUInt16BE(cursor);
    cursor += 2 + publicKeyLength;
    if (cursor + 2 > end) throw new Error("ECHConfig public key is truncated");
    const suitesLength = raw.readUInt16BE(cursor);
    cursor += 2;
    if (suitesLength < 4 || suitesLength % 4 !== 0 || cursor + suitesLength + 2 > end) {
      throw new Error("ECHConfig cipher suites are invalid");
    }
    cursor += suitesLength + 1;
    const nameLength = raw[cursor];
    if (nameLength === undefined || nameLength === 0 || cursor + 1 + nameLength + 2 > end) {
      throw new Error("ECHConfig public_name is invalid");
    }
    cursor += 1;
    const publicName = raw.subarray(cursor, cursor + nameLength).toString("ascii").toLowerCase();
    cursor += nameLength;
    const extensionsLength = raw.readUInt16BE(cursor);
    cursor += 2 + extensionsLength;
    if (cursor !== end || !dnsNamePattern.test(publicName)) {
      throw new Error("ECHConfig contents are malformed");
    }
    publicNames.add(publicName);
    configCount += 1;
    position = end;
  }
  if (position !== raw.length || configCount === 0 || publicNames.size !== 1) {
    throw new Error("ECHConfigList must contain one consistent public_name");
  }
  return {
    configCount,
    publicName: [...publicNames][0]!,
    sha256: sha256(raw),
    byteLength: raw.length,
  };
}

export function extractEchConfigFromDnsJson(
  value: unknown,
  endpointHostname: string,
): { base64: string; ttl: number; details: EchConfigDetails } {
  const payload = record(value);
  if (payload?.Status !== 0 || payload.TC !== false || !Array.isArray(payload.Answer)) {
    throw new Error("DNS HTTPS response was not a complete successful answer");
  }
  const expectedName = canonicalDnsName(endpointHostname, "endpoint hostname");
  const matches = payload.Answer.flatMap((answer) => {
    const item = record(answer);
    if (!item || item.type !== 65 || typeof item.name !== "string" || typeof item.data !== "string") {
      return [];
    }
    const answerName = item.name.toLowerCase().replace(/\.$/u, "");
    if (answerName !== expectedName) return [];
    const match = item.data.match(/(?:^|\s)ech="?([A-Za-z0-9+/]+={0,2})"?(?:\s|$)/u);
    if (!match?.[1]) return [];
    const ttl = numeric(item.TTL);
    return Number.isInteger(ttl) && ttl! >= 1 && ttl! <= 86_400
      ? [{ base64: match[1], ttl: ttl! }]
      : [];
  });
  if (matches.length !== 1) throw new Error("DNS HTTPS answer did not contain exactly one ECHConfigList");
  const selected = matches[0]!;
  return { ...selected, details: parseEchConfigList(selected.base64) };
}

async function fetchEchConfiguration(endpointHostname: string): Promise<{
  base64: string;
  ttl: number;
  details: EchConfigDetails;
  fetchedAt: string;
}> {
  const url = new URL("https://cloudflare-dns.com/dns-query");
  url.search = new URLSearchParams({ name: endpointHostname, type: "HTTPS" }).toString();
  const response = await fetch(url, {
    headers: { accept: "application/dns-json" },
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error(`DNS HTTPS lookup returned ${response.status}`);
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.includes("application/dns-json") && !contentType.includes("application/json")) {
    throw new Error("DNS HTTPS lookup returned an unexpected content type");
  }
  const selected = extractEchConfigFromDnsJson(await response.json(), endpointHostname);
  if (selected.details.publicName !== expectedEchPublicName) {
    throw new Error(`ECH public_name was not ${expectedEchPublicName}`);
  }
  return { ...selected, fetchedAt: new Date().toISOString() };
}

export function expectedOperationId(
  key: string,
  runId: string,
  caseId: string,
  canary: string,
): string {
  return `h3_${createHmac("sha256", key).update(`${runId}\n${caseId}\n${canary}`).digest("base64url")}`;
}

export function buildProbeConfiguration(input: {
  endpointUrl: string;
  pinnedIPv4: string;
  echConfigListBase64: string;
  echPublicName: string;
  runId: string;
  caseId: string;
  mode: ProbeMode;
  publicCanary?: string;
}): Record<string, unknown> {
  const configuration: Record<string, unknown> = {
    scopeConfirmation,
    endpointUrl: input.endpointUrl,
    pinnedIPv4: input.pinnedIPv4,
    echConfigListBase64: input.echConfigListBase64,
    echPublicName: input.echPublicName,
    runId: input.runId,
    testId,
    caseId: input.caseId,
    mode: input.mode,
    timeoutSeconds: 8,
    maxResponseBytes: 1_024,
  };
  if (input.caseId === "restricted-ech-target") {
    if (input.mode !== "ech" || input.publicCanary !== undefined) {
      throw new Error("restricted-ech-target must use ECH and cannot receive a public canary");
    }
  } else {
    if (!input.publicCanary || !canaryPattern.test(input.publicCanary)) {
      throw new Error("control probes require a bounded public canary");
    }
    configuration.publicCanary = input.publicCanary;
  }
  return configuration;
}

export function isExactCoverOnlyPolicy(value: unknown, coverName: string): boolean {
  const policy = record(value);
  if (!policy || Object.keys(policy).length !== 1 || !Object.hasOwn(policy, "allow")) return false;
  const canonicalCover = canonicalDnsName(coverName, "cover name");
  if (Array.isArray(policy.allow)) {
    return policy.allow.length === 1 && policy.allow[0] === canonicalCover;
  }
  const allow = record(policy.allow);
  if (!allow || Object.keys(allow).length !== 1 || !Object.hasOwn(allow, canonicalCover)) return false;
  const rules = allow[canonicalCover];
  return Array.isArray(rules) && rules.length === 0;
}

export function assessEchAllowlist(input: EchAssessmentInput): EchAssessment {
  if (!input.cleanupPassed) {
    return { verdict: "error", candidate: false, controlsPassed: false, summary: "Owned sandbox cleanup failed." };
  }
  if (input.executionError) {
    return { verdict: "error", candidate: false, controlsPassed: false, summary: "The controller failed before a valid assessment completed." };
  }
  const controlsPassed = input.setupPassed && input.allowPlainControlPassed &&
    input.allowEchControlPassed && input.restrictedUpdateAcknowledged &&
    input.restrictedReadbackPassed && input.restrictedPlainBlocked;
  if (!controlsPassed) {
    return { verdict: "indeterminate", candidate: false, controlsPassed: false, summary: "An endpoint, ECH, policy-readback, or direct-block control failed." };
  }
  if (input.restrictedEchSucceeded) {
    return {
      verdict: "candidate",
      candidate: true,
      controlsPassed: true,
      summary: "On-wire-attested ECH exfiltrated a fresh synthetic operator secret to the denied inner hostname while the exact same-session allowlist contained only the outer public name; program confirmation of intended ECH policy semantics is still required.",
    };
  }
  if (input.restrictedEchBlocked) {
    return {
      verdict: "pass",
      candidate: false,
      controlsPassed: true,
      summary: "The cover-only domain policy blocked both ordinary and ECH access to the denied inner hostname.",
    };
  }
  return {
    verdict: "indeterminate",
    candidate: false,
    controlsPassed: true,
    summary: "The ECH target result was neither an authenticated success nor a conclusive firewall block.",
  };
}

function sanitizeProbeResult(value: unknown): Record<string, unknown> | undefined {
  const input = record(value);
  if (!input) return undefined;
  const response = record(input.response);
  const wire = record(input.onWireClientHello);
  const operationId = typeof input.operationId === "string" && operationIdPattern.test(input.operationId)
    ? input.operationId
    : undefined;
  return {
    ok: exactBoolean(input.ok),
    phase: safeText(input.phase, 64),
    runId: safeText(input.runId, 128),
    testId: safeText(input.testId, 128),
    caseId: safeText(input.caseId, 128),
    probeMode: input.probeMode === "plain" || input.probeMode === "ech" ? input.probeMode : undefined,
    canarySource: input.canarySource === "controller-public-canary" || input.canarySource === "operator-secret-file"
      ? input.canarySource
      : undefined,
    requestedHttpVersion: input.requestedHttpVersion === "v2" ? "v2" : undefined,
    echRequired: exactBoolean(input.echRequired),
    echDisabled: exactBoolean(input.echDisabled),
    echPublicName: safeText(input.echPublicName, 253),
    onWireClientHelloAttestationRequired: exactBoolean(input.onWireClientHelloAttestationRequired),
    expectedOuterSni: safeText(input.expectedOuterSni, 253),
    echExtensionRequiredOnWire: exactBoolean(input.echExtensionRequiredOnWire),
    exactlyOneFramedClientHelloRequired: exactBoolean(input.exactlyOneFramedClientHelloRequired),
    echConfigurationSource: input.echConfigurationSource === "controller-dns-https-record"
      ? input.echConfigurationSource
      : undefined,
    endpointHostname: safeText(input.endpointHostname, 253),
    pinnedIPv4: safeText(input.pinnedIPv4, 64),
    pinnedPort: numeric(input.pinnedPort),
    tlsVerificationRequired: exactBoolean(input.tlsVerificationRequired),
    tlsVerifiedByClient: exactBoolean(input.tlsVerifiedByClient),
    redirectsAllowed: exactBoolean(input.redirectsAllowed),
    environmentProxyTrust: exactBoolean(input.environmentProxyTrust),
    proxyOptionForcedEmpty: exactBoolean(input.proxyOptionForcedEmpty),
    noProxyOption: input.noProxyOption === "*" ? "*" : undefined,
    dnsPinnedWithCurlResolve: exactBoolean(input.dnsPinnedWithCurlResolve),
    freshConnectionRequired: exactBoolean(input.freshConnectionRequired),
    curlCffiVersion: safeText(input.curlCffiVersion, 32),
    onWireClientHello: wire ? {
      source: wire.source === "libcurl-debug-ssl-data-out-framed-record" ? wire.source : undefined,
      sslDataOutEventCount: numeric(wire.sslDataOutEventCount),
      sslDataOutByteLength: numeric(wire.sslDataOutByteLength),
      collectorOverflow: exactBoolean(wire.collectorOverflow),
      collectorError: exactBoolean(wire.collectorError),
      framedClientHelloCount: numeric(wire.framedClientHelloCount),
      expectedOuterSni: safeText(wire.expectedOuterSni, 253),
      tlsRecordContentType: numeric(wire.tlsRecordContentType),
      tlsRecordByteLength: numeric(wire.tlsRecordByteLength),
      clientHelloByteLength: numeric(wire.clientHelloByteLength),
      clientHelloSha256: typeof wire.clientHelloSha256 === "string" && sha256Pattern.test(wire.clientHelloSha256)
        ? wire.clientHelloSha256
        : undefined,
      outerSni: safeText(wire.outerSni, 253),
      echExtensionPresent: exactBoolean(wire.echExtensionPresent),
      outerSniMatchesExpected: exactBoolean(wire.outerSniMatchesExpected),
    } : undefined,
    response: response ? {
      statusCode: numeric(response.statusCode),
      actualHttpVersion: numeric(response.actualHttpVersion),
      primaryIp: safeText(response.primaryIp, 64),
      primaryPort: numeric(response.primaryPort),
      redirectCount: numeric(response.redirectCount),
      contentType: safeText(response.contentType, 128),
      cacheControl: safeText(response.cacheControl, 128),
      bodyByteLength: numeric(response.bodyByteLength),
      elapsedMs: numeric(response.elapsedMs),
    } : undefined,
    operationId,
    operationIdShapeValid: exactBoolean(input.operationIdShapeValid),
    authorized: exactBoolean(input.authorized),
    expectedHttp2ResponseVersion: numeric(input.expectedHttp2ResponseVersion),
    errorCode: safeText(input.errorCode, 64),
    errorType: safeText(input.errorType, 96),
    curlErrorCode: numeric(input.curlErrorCode),
    responseStatusCode: numeric(input.responseStatusCode),
    actualHttpVersion: numeric(input.actualHttpVersion),
    primaryIp: safeText(input.primaryIp, 64),
    primaryPort: numeric(input.primaryPort),
    receivedBodyByteLength: numeric(input.receivedBodyByteLength),
    retainedBodyByteLength: numeric(input.retainedBodyByteLength),
    durationMs: numeric(input.durationMs),
  };
}

function commonProbeControls(
  probe: ProbeRecord | undefined,
  runId: string,
  caseId: string,
  mode: ProbeMode,
  endpoint: URL,
  pinnedIPv4: string,
): { result?: Record<string, unknown>; response?: Record<string, unknown> } {
  const result = probe?.result;
  const response = record(result?.response);
  const wire = record(result?.onWireClientHello);
  const expectedCanarySource = caseId === "restricted-ech-target"
    ? "operator-secret-file"
    : "controller-public-canary";
  const expectedOuterSni = mode === "ech" ? expectedEchPublicName : endpoint.hostname;
  const wirePassed = wire?.source === "libcurl-debug-ssl-data-out-framed-record" &&
    wire.collectorOverflow === false && wire.collectorError === false &&
    wire.framedClientHelloCount === 1 && wire.expectedOuterSni === expectedOuterSni &&
    wire.outerSni === expectedOuterSni && wire.outerSniMatchesExpected === true &&
    wire.echExtensionPresent === (mode === "ech") && wire.tlsRecordContentType === 22 &&
    typeof wire.tlsRecordByteLength === "number" && wire.tlsRecordByteLength >= 9 &&
    wire.tlsRecordByteLength <= 18_437 && typeof wire.clientHelloByteLength === "number" &&
    wire.clientHelloByteLength === wire.tlsRecordByteLength - 5 &&
    typeof wire.clientHelloSha256 === "string" && sha256Pattern.test(wire.clientHelloSha256) &&
    typeof wire.sslDataOutEventCount === "number" && wire.sslDataOutEventCount >= 2 &&
    wire.sslDataOutEventCount <= 64 && typeof wire.sslDataOutByteLength === "number" &&
    wire.sslDataOutByteLength >= wire.tlsRecordByteLength;
  const passed = probe?.command.exitCode === 0 && result !== undefined &&
    result.runId === runId && result.testId === testId && result.caseId === caseId &&
    result.probeMode === mode && result.canarySource === expectedCanarySource &&
    result.requestedHttpVersion === "v2" && result.echRequired === (mode === "ech") &&
    result.echDisabled === (mode === "plain") && result.echPublicName === expectedEchPublicName &&
    result.onWireClientHelloAttestationRequired === true && result.expectedOuterSni === expectedOuterSni &&
    result.echExtensionRequiredOnWire === (mode === "ech") &&
    result.exactlyOneFramedClientHelloRequired === true && wirePassed &&
    result.echConfigurationSource === "controller-dns-https-record" &&
    result.endpointHostname === endpoint.hostname && result.pinnedIPv4 === pinnedIPv4 &&
    result.pinnedPort === 443 && result.tlsVerificationRequired === true &&
    result.redirectsAllowed === false && result.environmentProxyTrust === false &&
    result.proxyOptionForcedEmpty === true && result.noProxyOption === "*" &&
    result.dnsPinnedWithCurlResolve === true && result.freshConnectionRequired === true &&
    result.curlCffiVersion === expectedCurlCffiVersion;
  return passed ? { result, ...(response ? { response } : {}) } : {};
}

export function authenticatedSuccess(
  probe: ProbeRecord | undefined,
  runId: string,
  caseId: string,
  mode: ProbeMode,
  endpoint: URL,
  pinnedIPv4: string,
): boolean {
  const { result, response } = commonProbeControls(probe, runId, caseId, mode, endpoint, pinnedIPv4);
  const cacheControl = typeof response?.cacheControl === "string"
    ? response.cacheControl.toLowerCase().split(",").map((value) => value.trim())
    : [];
  return result?.ok === true && result.phase === "response" && result.tlsVerifiedByClient === true &&
    response?.statusCode === 200 && response.actualHttpVersion === result.expectedHttp2ResponseVersion &&
    response.actualHttpVersion === 3 && response.primaryIp === pinnedIPv4 && response.primaryPort === 443 &&
    response.redirectCount === 0 && typeof response.contentType === "string" &&
    response.contentType.toLowerCase().startsWith("application/json") && cacheControl.includes("no-store") &&
    typeof response.bodyByteLength === "number" && response.bodyByteLength <= 1_024 &&
    result.authorized === true && result.operationIdShapeValid === true &&
    result.operationId === probe?.expectedOperationId;
}

export function conclusiveFirewallBlock(
  probe: ProbeRecord | undefined,
  runId: string,
  caseId: "restricted-plain-negative" | "restricted-ech-target",
  mode: ProbeMode,
  endpoint: URL,
  pinnedIPv4: string,
): boolean {
  const { result } = commonProbeControls(probe, runId, caseId, mode, endpoint, pinnedIPv4);
  const code = numeric(result?.curlErrorCode);
  return result?.ok === false && result.phase === "request" &&
    code !== 101 && code !== 28 && [7, 35, 52, 56].includes(code ?? -1) &&
    result.responseStatusCode === 0 && result.actualHttpVersion === 0 &&
    (result.primaryIp === "" || result.primaryIp === pinnedIPv4) &&
    (result.primaryPort === -1 || result.primaryPort === 0 || result.primaryPort === 443) &&
    result.operationId === undefined;
}

async function captureCommand(
  sandbox: Sandbox,
  gate: RateGate,
  params: Parameters<Sandbox["runCommand"]>[0] & { cmd: string },
  secrets: string[],
): Promise<{ record: CommandRecord; stdout: string; stderr: string }> {
  const serializedParameters = JSON.stringify(params);
  if (secrets.some((secret) => secret && serializedParameters.includes(secret))) {
    throw new Error("guest command arguments or environment contained controller-only material");
  }
  await gate.beforeCall();
  const commandApiTimeoutMs = Math.min(Math.max((params.timeoutMs ?? 15_000) + 15_000, 30_000), 150_000);
  const command = await sandbox.runCommand({
    ...params,
    signal: params.signal ?? controlSignal(commandApiTimeoutMs),
  });
  const outputSignal = controlSignal();
  const [stdout, stderr] = await Promise.all([
    command.stdout({ signal: outputSignal }),
    command.stderr({ signal: outputSignal }),
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
    stderr,
  };
}

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  const endpoint = controlledEndpoint();
  const controllerHmacKey = hmacKey();
  const credentials = explicitCredentials();
  const operatorSecret = randomBytes(32).toString("base64url");
  const operatorSecretSha256 = sha256(operatorSecret);
  const controllerSecrets = [controllerHmacKey, operatorSecret, process.env.VERCEL_TOKEN ?? ""].filter(Boolean);
  const dnsStartedAt = new Date().toISOString();
  const [resolved, echConfiguration] = await Promise.all([
    resolve4(endpoint.hostname, { ttl: true }),
    fetchEchConfiguration(endpoint.hostname),
  ]);
  const dnsCompletedAt = new Date().toISOString();
  const publicAnswers = resolved.filter((answer, index, all) =>
    publicIPv4(answer.address) && all.findIndex((candidate) => candidate.address === answer.address) === index
  ).sort((left, right) => left.address.localeCompare(right.address));
  if (publicAnswers.length === 0) throw new Error("SBX031_ENDPOINT_URL did not resolve to a public IPv4 address");
  const pinnedIPv4 = publicAnswers[0]!.address;
  const runId = randomUUID();
  const publicCanaries = {
    "allow-plain-control": `public_${randomBytes(18).toString("base64url")}`,
    "allow-ech-control": `public_${randomBytes(18).toString("base64url")}`,
    "restricted-plain-negative": `public_${randomBytes(18).toString("base64url")}`,
  } as const;
  const guestSource = await readFile(resolve("guest/ech-domain-probe.py"), "utf8");
  if (controllerSecrets.some((secret) => guestSource.includes(secret))) {
    throw new Error("guest source unexpectedly contains controller-only material");
  }

  const gate = new RateGate();
  const probes: ProbeRecord[] = [];
  const policyTransitions: Record<string, unknown>[] = [];
  const cleanup = {
    stopAttempted: false,
    stopped: false,
    deleteAttempted: false,
    deleted: false,
    errors: [] as string[],
  };
  const packageSetup: Record<string, unknown> = {
    requested: `curl_cffi==${expectedCurlCffiVersion}`,
    targetDirectory: remoteSitePackages,
  };
  const operatorSecretSetup: Record<string, unknown> = {
    path: remoteOperatorSecretPath,
    sha256: operatorSecretSha256,
    writtenBeforeRestriction: false,
    verifiedBeforeRestriction: false,
  };
  let sandbox: Sandbox | undefined;
  let originalSessionId: string | undefined;
  let sandboxIdentity: Record<string, unknown> | undefined;
  let executionError: string | undefined;
  let executionIndeterminate = false;
  let setupPassed = false;
  let allowPlainControlPassed = false;
  let allowEchControlPassed = false;
  let restrictedUpdateAcknowledged = false;
  let restrictedReadbackPassed = false;
  let restrictedPlainBlocked = false;
  let restrictedEchSucceeded = false;
  let restrictedEchBlocked = false;

  async function runProbe(caseId: string, mode: ProbeMode, publicCanary?: string): Promise<ProbeRecord> {
    if (!sandbox) throw new Error("sandbox is not available");
    const configuration = buildProbeConfiguration({
      endpointUrl: endpoint.href,
      pinnedIPv4,
      echConfigListBase64: echConfiguration.base64,
      echPublicName: echConfiguration.details.publicName,
      runId,
      caseId,
      mode,
      ...(publicCanary ? { publicCanary } : {}),
    });
    const serialized = JSON.stringify(configuration);
    if (controllerSecrets.some((secret) => serialized.includes(secret))) {
      throw new Error(`${caseId} guest configuration contains controller-only material`);
    }
    const requestCanary = caseId === "restricted-ech-target" ? operatorSecret : publicCanary;
    if (!requestCanary) throw new Error(`${caseId} has no request canary source`);
    const captured = await captureCommand(
      sandbox,
      gate,
      {
        cmd: "python3",
        args: [remoteProbePath, Buffer.from(serialized).toString("base64url")],
        env: {
          PYTHONPATH: remoteSitePackages,
          HTTP_PROXY: "",
          HTTPS_PROXY: "",
          ALL_PROXY: "",
          NO_PROXY: "*",
        },
        timeoutMs: 15_000,
      },
      controllerSecrets,
    );
    let decoded: unknown;
    try {
      decoded = JSON.parse(captured.stdout);
    } catch {
      throw new Error(`${caseId} guest probe emitted invalid JSON`);
    }
    const result = sanitizeProbeResult(decoded);
    const probe: ProbeRecord = {
      caseId,
      mode,
      canarySource: caseId === "restricted-ech-target" ? "operator-secret-file" : "controller-public-canary",
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
    sandbox = await Sandbox.create({
      name: `sbx-031-poc-${runId.slice(0, 8)}`,
      persistent: false,
      timeout: 300_000,
      networkPolicy: "allow-all",
      tags: { harness: "vsc", test: "SBX-031", run: runId.slice(0, 12) },
      signal: controlSignal(45_000),
      ...credentials,
    });
    const session = sandbox.currentSession();
    originalSessionId = session.sessionId;
    sandboxIdentity = {
      name: sandbox.name,
      sessionId: session.sessionId,
      sessionCreatedAt: session.createdAt.toISOString(),
      sessionRequestedAt: session.requestedAt.toISOString(),
      region: session.region,
      persistent: sandbox.persistent,
      initialNetworkPolicy: sandbox.networkPolicy,
      initialSessionNetworkPolicy: session.networkPolicy,
    };
    if (sandbox.networkPolicy !== "allow-all" || session.networkPolicy !== "allow-all") {
      throw new IndeterminateError("fresh sandbox did not report literal allow-all");
    }

    const install = await captureCommand(
      sandbox,
      gate,
      {
        cmd: "python3",
        args: [
          "-m", "pip", "install", "--disable-pip-version-check", "--no-input", "--no-cache-dir",
          "--retries", "0", "--only-binary=:all:", "--target", remoteSitePackages,
          `curl_cffi==${expectedCurlCffiVersion}`,
        ],
        timeoutMs: 120_000,
      },
      controllerSecrets,
    );
    packageSetup.install = install.record;
    if (install.record.exitCode !== 0) throw new IndeterminateError("pinned curl_cffi installation failed");
    const versionCheck = await captureCommand(
      sandbox,
      gate,
      {
        cmd: "python3",
        args: [
          "-c",
          "import curl_cffi,json; from curl_cffi import CurlOpt; from importlib.metadata import version; print(json.dumps({'distributionVersion':version('curl_cffi'),'curlBuild':curl_cffi.__curl_version__,'modulePath':curl_cffi.__file__,'echOption':int(CurlOpt.ECH)},separators=(',',':')))",
        ],
        env: { PYTHONPATH: remoteSitePackages },
        timeoutMs: 10_000,
      },
      controllerSecrets,
    );
    packageSetup.versionCheck = versionCheck.record;
    let runtimeDetails: Record<string, unknown> | undefined;
    try {
      runtimeDetails = record(JSON.parse(versionCheck.stdout));
    } catch {
      runtimeDetails = undefined;
    }
    const observedVersion = safeText(runtimeDetails?.distributionVersion, 32);
    const curlBuild = safeText(runtimeDetails?.curlBuild, 512);
    const modulePath = safeText(runtimeDetails?.modulePath, 512);
    const echOption = numeric(runtimeDetails?.echOption);
    packageSetup.runtime = { observedVersion, curlBuild, modulePath, echOption };
    if (
      versionCheck.record.exitCode !== 0 || observedVersion !== expectedCurlCffiVersion ||
      !curlBuild?.includes("BoringSSL") || !modulePath?.startsWith(`${remoteSitePackages}/curl_cffi/`) ||
      !Number.isInteger(echOption) || echOption! <= 0
    ) {
      throw new IndeterminateError("curl_cffi ECH runtime verification failed");
    }

    await gate.beforeCall();
    await sandbox.writeFiles([
      { path: remoteProbePath, content: guestSource, mode: 0o700 },
      { path: remoteOperatorSecretPath, content: operatorSecret, mode: 0o600 },
    ], { signal: controlSignal() });
    operatorSecretSetup.writtenBeforeRestriction = true;
    const secretVerification = await captureCommand(
      sandbox,
      gate,
      {
        cmd: "python3",
        args: [
          "-c",
          `import hashlib,os,stat; p=${JSON.stringify(remoteOperatorSecretPath)}; fd=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)); s=os.fstat(fd); d=os.read(fd,129); os.close(fd); assert stat.S_ISREG(s.st_mode) and not s.st_mode&0o077 and len(d)==s.st_size and 16<=len(d)<=128; print(hashlib.sha256(d).hexdigest())`,
        ],
        timeoutMs: 10_000,
      },
      controllerSecrets,
    );
    operatorSecretSetup.verificationCommand = secretVerification.record;
    operatorSecretSetup.observedSha256 = safeText(secretVerification.stdout.trim(), 64);
    operatorSecretSetup.verifiedBeforeRestriction = secretVerification.record.exitCode === 0 &&
      secretVerification.stdout.trim() === operatorSecretSha256;
    if (!operatorSecretSetup.verifiedBeforeRestriction) {
      throw new IndeterminateError("synthetic operator-secret file verification failed");
    }
    setupPassed = true;

    const allowPlain = await runProbe("allow-plain-control", "plain", publicCanaries["allow-plain-control"]);
    allowPlainControlPassed = authenticatedSuccess(
      allowPlain, runId, allowPlain.caseId, allowPlain.mode, endpoint, pinnedIPv4,
    );
    if (!allowPlainControlPassed) throw new IndeterminateError("allow-all ordinary HTTPS control failed");

    const allowEch = await runProbe("allow-ech-control", "ech", publicCanaries["allow-ech-control"]);
    allowEchControlPassed = authenticatedSuccess(
      allowEch, runId, allowEch.caseId, allowEch.mode, endpoint, pinnedIPv4,
    );
    if (!allowEchControlPassed) throw new IndeterminateError("allow-all ECH control failed");

    const restrictedPolicy = { allow: [expectedEchPublicName] } satisfies NetworkPolicy;
    const updateStartedAt = new Date().toISOString();
    await gate.beforeCall();
    await sandbox.update({ networkPolicy: restrictedPolicy }, { signal: controlSignal() });
    const activeSessionAfterUpdate = sandbox.currentSession();
    const activePolicyAfterUpdate = activeSessionAfterUpdate.networkPolicy;
    restrictedUpdateAcknowledged = activeSessionAfterUpdate.sessionId === originalSessionId &&
      isExactCoverOnlyPolicy(activePolicyAfterUpdate, expectedEchPublicName);
    await gate.beforeCall();
    const independentReadback = await Sandbox.get({
      name: sandbox.name,
      resume: false,
      signal: controlSignal(),
      ...credentials,
    });
    const independentSession = independentReadback.currentSession();
    restrictedReadbackPassed = independentSession.sessionId === originalSessionId &&
      isExactCoverOnlyPolicy(independentSession.networkPolicy, expectedEchPublicName);
    policyTransitions.push({
      stage: "allow-all-to-cover-only-domain-policy",
      startedAt: updateStartedAt,
      completedAt: new Date().toISOString(),
      requestedPolicy: restrictedPolicy,
      originalSessionId,
      activeHandleSessionId: activeSessionAfterUpdate.sessionId,
      activeHandleSessionPolicyReadback: activePolicyAfterUpdate,
      activeHandleSandboxPolicyReadback: sandbox.networkPolicy,
      independentSessionId: independentSession.sessionId,
      independentSessionPolicyReadback: independentSession.networkPolicy,
      independentSandboxPolicyReadback: independentReadback.networkPolicy,
      updateAcknowledged: restrictedUpdateAcknowledged,
      independentReadbackPassed: restrictedReadbackPassed,
    });
    if (!restrictedUpdateAcknowledged || !restrictedReadbackPassed) {
      throw new IndeterminateError("exact cover-only domain policy update or readback failed");
    }

    const restrictedPlain = await runProbe(
      "restricted-plain-negative",
      "plain",
      publicCanaries["restricted-plain-negative"],
    );
    restrictedPlainBlocked = conclusiveFirewallBlock(
      restrictedPlain,
      runId,
      "restricted-plain-negative",
      "plain",
      endpoint,
      pinnedIPv4,
    );
    if (!restrictedPlainBlocked) {
      throw new IndeterminateError("ordinary inner-SNI request was not conclusively blocked");
    }

    const restrictedEch = await runProbe("restricted-ech-target", "ech");
    restrictedEchSucceeded = authenticatedSuccess(
      restrictedEch, runId, restrictedEch.caseId, restrictedEch.mode, endpoint, pinnedIPv4,
    );
    restrictedEchBlocked = !restrictedEchSucceeded && conclusiveFirewallBlock(
      restrictedEch,
      runId,
      "restricted-ech-target",
      "ech",
      endpoint,
      pinnedIPv4,
    );
  } catch (error) {
    executionError = safeError(error, controllerSecrets);
    executionIndeterminate = error instanceof IndeterminateError;
  } finally {
    if (sandbox) {
      cleanup.stopAttempted = true;
      try {
        await gate.beforeCall();
        await sandbox.stop({ signal: controlSignal() });
        cleanup.stopped = true;
      } catch (error) {
        cleanup.errors.push(`stop: ${safeError(error, controllerSecrets)}`);
      }
      cleanup.deleteAttempted = true;
      try {
        await gate.beforeCall();
        await sandbox.delete({ signal: controlSignal() });
        cleanup.deleted = true;
      } catch (error) {
        cleanup.errors.push(`delete: ${safeError(error, controllerSecrets)}`);
      }
    }
  }

  const cleanupPassed = sandbox === undefined || (cleanup.stopped && cleanup.deleted && cleanup.errors.length === 0);
  const assessment = assessEchAllowlist({
    setupPassed,
    allowPlainControlPassed,
    allowEchControlPassed,
    restrictedUpdateAcknowledged,
    restrictedReadbackPassed,
    restrictedPlainBlocked,
    restrictedEchSucceeded,
    restrictedEchBlocked,
    cleanupPassed,
    ...(executionError && !executionIndeterminate ? { executionError: true } : {}),
  });
  const evidence = {
    schemaVersion: 1,
    visibility: "private",
    testId: "SBX-031",
    runId,
    startedAt,
    completedAt: new Date().toISOString(),
    scope: "one researcher-owned Vercel sandbox and one researcher-owned Cloudflare Worker endpoint",
    requestBounds: {
      endpointRequests: probes.length,
      maximumEndpointRequests: 4,
      sequential: true,
      retryCount: 0,
      redirectsAllowed: false,
      minimumControllerCallIntervalMs,
    },
    endpoint: {
      origin: endpoint.origin,
      path: endpoint.pathname,
      pinnedIPv4,
      controllerResolvedAt: { startedAt: dnsStartedAt, completedAt: dnsCompletedAt },
      resolvedARecords: publicAnswers,
      contract: "{authorized:true,operationId:h3_+base64url(HMAC-SHA256(H3_ACTION_KEY,runId\\ncaseId\\ncanary))}",
    },
    ech: {
      dnsResolver: "https://cloudflare-dns.com/dns-query",
      dnsRecordType: "HTTPS (65)",
      fetchedAt: echConfiguration.fetchedAt,
      ttl: echConfiguration.ttl,
      configListSha256: echConfiguration.details.sha256,
      configListByteLength: echConfiguration.details.byteLength,
      configCount: echConfiguration.details.configCount,
      publicName: echConfiguration.details.publicName,
      configListRetainedInEvidence: false,
    },
    hmacKeySha256: sha256(controllerHmacKey),
    operatorSecretSha256,
    credentialContext: Object.keys(credentials).length === 3
      ? { mode: "explicit", teamId: credentials.teamId, projectId: credentials.projectId }
      : { mode: "inferred-cli", requiredAccount: "HackerOne-alias Vercel account" },
    sandbox: sandboxIdentity,
    packageSetup,
    operatorSecretSetup,
    policy: {
      initial: "allow-all" satisfies NetworkPolicy,
      tightened: { allow: [expectedEchPublicName] } satisfies NetworkPolicy,
      transitions: policyTransitions,
    },
    guestMaterialGuards: {
      hmacKeyEnteredGuestSourceOrConfiguration: false,
      operatorSecretEnteredGuestSourceOrConfigurationOrArguments: false,
      operatorSecretAppearedInGuestOutput: false,
      vercelTokenEnteredGuestSourceOrConfiguration: false,
      controllerOnlyMaterialAppearedInGuestOutput: false,
    },
    probes,
    controls: {
      setupPassed,
      allowPlainControlPassed,
      allowEchControlPassed,
      restrictedUpdateAcknowledged,
      restrictedReadbackPassed,
      restrictedPlainBlocked,
      restrictedEchSucceeded,
      restrictedEchBlocked,
    },
    assessment,
    eligibilityCaveat: {
      potentialSeverity: "High only if Vercel confirms domain policy is intended to bind the effective inner hostname",
      alternativeInterpretation: "documented SNI-only enforcement behavior; potentially not eligible",
      submitWithoutProgramSemanticsConfirmation: false,
    },
    cleanup,
    ...(executionError ? { executionError } : {}),
  };
  const artifactsDirectory = resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts");
  await mkdir(artifactsDirectory, { recursive: true, mode: 0o700 });
  const privateEvidencePath = resolve(artifactsDirectory, `SBX-031-poc-${runId}-private.json`);
  await writeFile(privateEvidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify({
    testId: "SBX-031",
    runId,
    verdict: assessment.verdict,
    candidate: assessment.candidate,
    summary: assessment.summary,
    endpointHostname: endpoint.hostname,
    pinnedIPv4,
    echPublicName: echConfiguration.details.publicName,
    echConfigListSha256: echConfiguration.details.sha256,
    sandbox: sandboxIdentity,
    controls: evidence.controls,
    hmacKeySha256: evidence.hmacKeySha256,
    cleanup,
    privateEvidencePath,
    ...(executionError ? { executionError } : {}),
  }, null, 2)}\n`);
  if (assessment.verdict !== "pass") process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
