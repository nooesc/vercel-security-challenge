export type TlsTransmissionMode = "normal" | "tcp-segmented" | "record-fragmented";

export type Sbx032Verdict = "candidate" | "pass" | "indeterminate" | "error";

export interface Sbx032AssessmentInput {
  setupPassed: boolean;
  allowNormalDeniedControlPassed: boolean;
  allowTcpSegmentedDeniedControlPassed: boolean;
  allowRecordFragmentedDeniedControlPassed: boolean;
  restrictedUpdateAcknowledged: boolean;
  restrictedReadbackPassed: boolean;
  postTargetReadbackPassed: boolean;
  allowedNormalControlPassed: boolean;
  allowedRecordFragmentedControlPassed: boolean;
  allowedRecordFragmentedControlBlocked: boolean;
  restrictedNormalDeniedPreBlocked: boolean;
  restrictedNormalDeniedPostBlocked: boolean;
  restrictedRecordFragmentedPublicDeniedBlocked: boolean;
  restrictedRecordFragmentedDeniedSucceeded: boolean;
  restrictedRecordFragmentedDeniedBlocked: boolean;
  cleanupPassed: boolean;
  executionError?: boolean;
}

export interface Sbx032Assessment {
  verdict: Sbx032Verdict;
  candidate: boolean;
  controlsPassed: boolean;
  summary: string;
}

export interface SanitizedTlsProbeResult {
  ok?: boolean | undefined;
  phase?: string | undefined;
  runId?: string | undefined;
  testId?: string | undefined;
  caseId?: string | undefined;
  endpointRole?: string | undefined;
  transmissionMode?: string | undefined;
  canarySource?: string | undefined;
  endpointHostname?: string | undefined;
  pinnedIPv4?: string | undefined;
  pinnedPort?: number | undefined;
  maximumRequests?: number | undefined;
  retryCount?: number | undefined;
  redirectsAllowed?: boolean | undefined;
  freshConnectionRequired?: boolean | undefined;
  environmentProxyTrust?: boolean | undefined;
  strictCertificateVerification?: boolean | undefined;
  hostnameVerificationRequired?: boolean | undefined;
  certificateVerified?: boolean | undefined;
  hostnameVerified?: boolean | undefined;
  selectedAlpn?: string | undefined;
  tlsVersion?: string | undefined;
  cipherSuite?: string | undefined;
  peerCertificateSha256?: string | undefined;
  peerIPv4?: string | undefined;
  peerPort?: number | undefined;
  operationId?: string | undefined;
  authorized?: boolean | undefined;
  operationIdShapeValid?: boolean | undefined;
  response?: {
    statusCode?: number | undefined;
    contentType?: string | undefined;
    cacheControl?: string | undefined;
    bodyByteLength?: number | undefined;
    bodyContainsCanary?: boolean | undefined;
    rawBodyRetained?: boolean | undefined;
  };
  clientHello?: {
    source?: string | undefined;
    outerSni?: string | undefined;
    originalRecordCount?: number | undefined;
    transmittedRecordCount?: number | undefined;
    originalFirstFlightSha256?: string | undefined;
    transmittedFirstFlightSha256?: string | undefined;
    clientHelloPayloadSha256?: string | undefined;
    reassembledClientHelloPayloadSha256?: string | undefined;
    reassemblyMatchesOriginal?: boolean | undefined;
    splitLocation?: string | undefined;
    sniHostnameByteLength?: number | undefined;
    sniHostnameStartOffsetInRecordPayload?: number | undefined;
    sniHostnameEndOffsetInRecordPayload?: number | undefined;
    splitOffsetInRecordPayload?: number | undefined;
    originalRecordPayloadLength?: number | undefined;
    fragmentPayloadLengths?: number[] | undefined;
    initialSocketWriteCount?: number | undefined;
    rawClientHelloRetained?: boolean | undefined;
  };
  errorType?: string | undefined;
  errorErrno?: number | undefined;
  timeout?: boolean | undefined;
  responseStatusCode?: number | undefined;
}

export interface TlsProbeRecord {
  caseId: string;
  endpointRole: "allowed" | "denied";
  transmissionMode: TlsTransmissionMode;
  canarySource: "controller-public-canary" | "operator-secret-file";
  expectedOperationId: string;
  commandExitCode: number;
  result?: SanitizedTlsProbeResult;
}

const sha256Pattern = /^[a-f0-9]{64}$/u;
const operationIdPattern = /^h3_[A-Za-z0-9_-]{43}$/u;

export function exactSingleHostAllowPolicy(value: unknown, hostname: string): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const policy = value as Record<string, unknown>;
  if (Object.keys(policy).length !== 1 || !Object.hasOwn(policy, "allow")) return false;
  const allow = policy.allow;
  if (Array.isArray(allow)) return allow.length === 1 && allow[0] === hostname;
  if (allow === null || typeof allow !== "object" || Array.isArray(allow)) return false;
  const rules = allow as Record<string, unknown>;
  return Object.keys(rules).length === 1 && Object.hasOwn(rules, hostname) &&
    Array.isArray(rules[hostname]) && (rules[hostname] as unknown[]).length === 0;
}

function hasExactClientHelloProof(
  result: SanitizedTlsProbeResult,
  hostname: string,
  mode: TlsTransmissionMode,
): boolean {
  const hello = result.clientHello;
  if (
    hello?.source !== "python-sslobject-memorybio" || hello.outerSni !== hostname ||
    hello.splitLocation !== "server_name.hostname" ||
    typeof hello.splitOffsetInRecordPayload !== "number" || !Number.isInteger(hello.splitOffsetInRecordPayload) ||
    typeof hello.sniHostnameByteLength !== "number" || !Number.isInteger(hello.sniHostnameByteLength) ||
    typeof hello.sniHostnameStartOffsetInRecordPayload !== "number" ||
    !Number.isInteger(hello.sniHostnameStartOffsetInRecordPayload) ||
    typeof hello.sniHostnameEndOffsetInRecordPayload !== "number" ||
    !Number.isInteger(hello.sniHostnameEndOffsetInRecordPayload) ||
    typeof hello.originalRecordPayloadLength !== "number" || !Number.isInteger(hello.originalRecordPayloadLength) ||
    typeof hello.originalRecordCount !== "number" || !Number.isInteger(hello.originalRecordCount) ||
    typeof hello.transmittedRecordCount !== "number" || !Number.isInteger(hello.transmittedRecordCount) ||
    !sha256Pattern.test(hello.originalFirstFlightSha256 ?? "") ||
    !sha256Pattern.test(hello.transmittedFirstFlightSha256 ?? "") ||
    !sha256Pattern.test(hello.clientHelloPayloadSha256 ?? "") ||
    !sha256Pattern.test(hello.reassembledClientHelloPayloadSha256 ?? "") ||
    hello.clientHelloPayloadSha256 !== hello.reassembledClientHelloPayloadSha256 ||
    hello.reassemblyMatchesOriginal !== true ||
    !Array.isArray(hello.fragmentPayloadLengths) ||
    hello.fragmentPayloadLengths.length !== 2 ||
    !hello.fragmentPayloadLengths.every((length) => Number.isInteger(length) && length > 0) ||
    hello.originalRecordCount < 1 || hello.rawClientHelloRetained !== false
  ) return false;

  const [firstLength = 0, secondLength = 0] = hello.fragmentPayloadLengths;
  if (
    firstLength + secondLength !== hello.originalRecordPayloadLength ||
    hello.splitOffsetInRecordPayload !== firstLength ||
    hello.sniHostnameByteLength !== hostname.length ||
    hello.sniHostnameEndOffsetInRecordPayload - hello.sniHostnameStartOffsetInRecordPayload !==
      hello.sniHostnameByteLength ||
    !(hello.sniHostnameStartOffsetInRecordPayload < hello.splitOffsetInRecordPayload &&
      hello.splitOffsetInRecordPayload < hello.sniHostnameEndOffsetInRecordPayload)
  ) return false;

  if (mode === "record-fragmented") {
    return hello.transmittedRecordCount === hello.originalRecordCount + 1 &&
      hello.initialSocketWriteCount === 1 &&
      hello.transmittedFirstFlightSha256 !== hello.originalFirstFlightSha256;
  }
  if (mode === "tcp-segmented") {
    return hello.transmittedRecordCount === hello.originalRecordCount &&
      hello.initialSocketWriteCount === 2 &&
      hello.transmittedFirstFlightSha256 === hello.originalFirstFlightSha256;
  }
  return hello.transmittedRecordCount === hello.originalRecordCount &&
    hello.initialSocketWriteCount === 1 &&
    hello.transmittedFirstFlightSha256 === hello.originalFirstFlightSha256;
}

export function authenticatedTlsOperationSuccess(
  probe: TlsProbeRecord | undefined,
  input: {
    runId: string;
    testId: string;
    caseId: string;
    endpointRole: "allowed" | "denied";
    transmissionMode: TlsTransmissionMode;
    endpointHostname: string;
    pinnedIPv4: string;
  },
): boolean {
  const result = probe?.result;
  const response = result?.response;
  const expectedCanarySource = input.caseId === "restricted-record-fragmented-b-target"
    ? "operator-secret-file"
    : "controller-public-canary";
  const cacheControl = response?.cacheControl?.toLowerCase().split(",").map((item) => item.trim()) ?? [];
  return probe?.commandExitCode === 0 && probe.caseId === input.caseId &&
    probe.endpointRole === input.endpointRole && probe.transmissionMode === input.transmissionMode &&
    probe.canarySource === expectedCanarySource &&
    result?.ok === true && result.phase === "response" && result.runId === input.runId &&
    result.testId === input.testId && result.caseId === input.caseId &&
    result.endpointRole === input.endpointRole && result.transmissionMode === input.transmissionMode &&
    result.canarySource === probe.canarySource &&
    result.endpointHostname === input.endpointHostname && result.pinnedIPv4 === input.pinnedIPv4 &&
    result.pinnedPort === 443 && result.maximumRequests === 1 && result.retryCount === 0 &&
    result.redirectsAllowed === false && result.freshConnectionRequired === true &&
    result.environmentProxyTrust === false && result.strictCertificateVerification === true &&
    result.hostnameVerificationRequired === true && result.certificateVerified === true &&
    result.hostnameVerified === true && result.selectedAlpn === "http/1.1" &&
    (result.tlsVersion === "TLSv1.2" || result.tlsVersion === "TLSv1.3") &&
    typeof result.cipherSuite === "string" && result.cipherSuite.length >= 3 &&
    sha256Pattern.test(result.peerCertificateSha256 ?? "") &&
    result.peerIPv4 === input.pinnedIPv4 && result.peerPort === 443 &&
    hasExactClientHelloProof(result, input.endpointHostname, input.transmissionMode) &&
    response?.statusCode === 200 && response.contentType?.toLowerCase().startsWith("application/json") === true &&
    cacheControl.includes("no-store") && typeof response.bodyByteLength === "number" &&
    response.bodyByteLength > 0 && response.bodyByteLength <= 1_024 &&
    response.bodyContainsCanary === false && response.rawBodyRetained === false && result.authorized === true &&
    result.operationIdShapeValid === true && operationIdPattern.test(result.operationId ?? "") &&
    result.operationId === probe.expectedOperationId;
}

export function conclusiveTlsFirewallBlock(
  probe: TlsProbeRecord | undefined,
  input: {
    runId: string;
    testId: string;
    caseId: string;
    endpointRole?: "allowed" | "denied";
    endpointHostname: string;
    pinnedIPv4: string;
    transmissionMode: TlsTransmissionMode;
  },
): boolean {
  const result = probe?.result;
  const endpointRole = input.endpointRole ?? "denied";
  const expectedCanarySource = input.caseId === "restricted-record-fragmented-b-target"
    ? "operator-secret-file"
    : "controller-public-canary";
  if (
    probe?.commandExitCode !== 10 || probe.caseId !== input.caseId || probe.endpointRole !== endpointRole ||
    probe.transmissionMode !== input.transmissionMode || result?.ok !== false || result.runId !== input.runId ||
    probe.canarySource !== expectedCanarySource || result.canarySource !== expectedCanarySource ||
    result.testId !== input.testId || result.caseId !== input.caseId || result.endpointRole !== endpointRole ||
    result.transmissionMode !== input.transmissionMode || result.endpointHostname !== input.endpointHostname ||
    result.pinnedIPv4 !== input.pinnedIPv4 || result.pinnedPort !== 443 ||
    result.maximumRequests !== 1 || result.retryCount !== 0 || result.redirectsAllowed !== false ||
    result.freshConnectionRequired !== true || result.environmentProxyTrust !== false ||
    result.timeout !== false || result.operationId !== undefined || result.responseStatusCode !== 0 ||
    (result.phase !== "connect" && result.phase !== "handshake")
  ) return false;

  if (result.phase === "handshake" && !hasExactClientHelloProof(result, input.endpointHostname, input.transmissionMode)) {
    return false;
  }
  const activeFailures = new Set([
    "BrokenPipeError",
    "ConnectionAbortedError",
    "ConnectionRefusedError",
    "ConnectionResetError",
    "SSLEOFError",
    "SSLZeroReturnError",
  ]);
  return activeFailures.has(result.errorType ?? "") || [32, 54, 61, 104, 111].includes(result.errorErrno ?? -1);
}

export function assessSbx032(input: Sbx032AssessmentInput): Sbx032Assessment {
  if (!input.cleanupPassed) {
    return {
      verdict: "error",
      candidate: false,
      controlsPassed: false,
      summary: "The owned sandbox was not both stopped and deleted cleanly.",
    };
  }
  if (input.executionError) {
    return {
      verdict: "error",
      candidate: false,
      controlsPassed: false,
      summary: "Controller execution failed before a complete assessment.",
    };
  }
  const failClosedControlsPassed = input.setupPassed && input.allowNormalDeniedControlPassed &&
    input.allowTcpSegmentedDeniedControlPassed && input.allowRecordFragmentedDeniedControlPassed &&
    input.restrictedUpdateAcknowledged && input.restrictedReadbackPassed && input.postTargetReadbackPassed &&
    input.allowedNormalControlPassed && input.restrictedNormalDeniedPreBlocked &&
    !input.allowedRecordFragmentedControlPassed && input.allowedRecordFragmentedControlBlocked &&
    input.restrictedRecordFragmentedPublicDeniedBlocked && input.restrictedNormalDeniedPostBlocked;
  if (failClosedControlsPassed) {
    return {
      verdict: "pass",
      candidate: false,
      controlsPassed: true,
      summary: "The exact allowlist admitted ordinary TLS to the owned allowed hostname but actively blocked the same hostname when its ClientHello was split across TLS records inside SNI; the secret-bearing denied-host target was not sent.",
    };
  }
  const controlsPassed = input.setupPassed && input.allowNormalDeniedControlPassed &&
    input.allowTcpSegmentedDeniedControlPassed && input.allowRecordFragmentedDeniedControlPassed &&
    input.restrictedUpdateAcknowledged && input.restrictedReadbackPassed && input.postTargetReadbackPassed &&
    input.allowedNormalControlPassed && input.allowedRecordFragmentedControlPassed &&
    !input.allowedRecordFragmentedControlBlocked && input.restrictedNormalDeniedPreBlocked &&
    input.restrictedNormalDeniedPostBlocked;
  if (!controlsPassed) {
    return {
      verdict: "indeterminate",
      candidate: false,
      controlsPassed: false,
      summary: "A setup, standards-validity, allowed-target, policy-readback, or ordinary-deny control failed.",
    };
  }
  if (input.restrictedRecordFragmentedDeniedSucceeded && !input.restrictedRecordFragmentedDeniedBlocked) {
    return {
      verdict: "candidate",
      candidate: true,
      controlsPassed: true,
      summary: "A TLS ClientHello split into two valid records inside SNI reached the denied owned hostname and produced exact non-reflecting HMAC proof for a fresh synthetic operator secret.",
    };
  }
  if (input.restrictedRecordFragmentedDeniedBlocked && !input.restrictedRecordFragmentedDeniedSucceeded) {
    return {
      verdict: "pass",
      candidate: false,
      controlsPassed: true,
      summary: "The exact allowlist blocked both ordinary and record-fragmented TLS to the denied owned hostname.",
    };
  }
  return {
    verdict: "indeterminate",
    candidate: false,
    controlsPassed: true,
    summary: "The fragmented denied-host result was neither an authenticated success nor a conclusive active firewall block.",
  };
}
