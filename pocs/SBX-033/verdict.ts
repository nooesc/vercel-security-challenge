export type AddressFamily = "ipv4" | "ipv6";
export type CanarySource = "controller-public-canary" | "operator-secret-file";
export type Sbx033Verdict = "candidate" | "pass" | "indeterminate" | "error";

export interface SanitizedNativeIpProbeResult {
  ok?: boolean;
  phase?: string;
  runId?: string;
  testId?: string;
  caseId?: string;
  addressFamily?: string;
  canarySource?: string;
  endpointHostname?: string;
  pinnedAddress?: string;
  pinnedPort?: number;
  attemptNumber?: number;
  maximumRequests?: number;
  retryCount?: number;
  redirectsAllowed?: boolean;
  freshConnectionRequired?: boolean;
  environmentProxyTrust?: boolean;
  strictCertificateVerification?: boolean;
  hostnameVerificationRequired?: boolean;
  certificateVerified?: boolean;
  hostnameVerified?: boolean;
  selectedAlpn?: string;
  tlsVersion?: string;
  cipherSuite?: string;
  peerCertificateSha256?: string;
  peerAddress?: string;
  peerAddressFamily?: string;
  peerPort?: number;
  nativeIpv6?: boolean;
  secretFileValidated?: boolean;
  secretFileMode?: string;
  secretByteLength?: number;
  operationId?: string;
  authorized?: boolean;
  operationIdShapeValid?: boolean;
  response?: {
    statusCode?: number;
    contentType?: string;
    cacheControl?: string;
    bodyByteLength?: number;
    bodyContainsCanary?: boolean;
    rawBodyRetained?: boolean;
  };
  errorType?: string;
  errorErrno?: number;
  errorSyscall?: string;
  timeout?: boolean;
  responseStatusCode?: number;
}

export interface NativeIpProbeRecord {
  caseId: string;
  addressFamily: AddressFamily;
  canarySource: CanarySource;
  expectedOperationId: string;
  commandExitCode: number;
  result?: SanitizedNativeIpProbeResult;
}

export interface NativeIpProbeExpectation {
  runId: string;
  testId: string;
  caseId: string;
  addressFamily: AddressFamily;
  canarySource: CanarySource;
  endpointHostname: string;
  pinnedAddress: string;
}

export interface Sbx033AssessmentInput {
  identityAndScopePassed: boolean;
  dnsSnapshotPassed: boolean;
  allowSandboxCreated: boolean;
  allowIpv4Succeeded: boolean;
  allowNativeIpv6Succeeded: boolean;
  denySandboxCreated: boolean;
  denyPolicyReadbackPassed: boolean;
  denyIpv4Blocked: boolean;
  denyIpv4UnexpectedlySucceeded: boolean;
  denyIpv6PublicBlocked: boolean;
  denyIpv6PublicSucceeded: boolean;
  secretTargetAttempted: boolean;
  secretFilePrepared: boolean;
  denyIpv6SecretSucceeded: boolean;
  denyIpv6SecretBlocked: boolean;
  postTargetReadbackPassed: boolean;
  cleanupPassed: boolean;
  executionError?: boolean;
}

export interface Sbx033Assessment {
  verdict: Sbx033Verdict;
  candidate: boolean;
  controlsPassed: boolean;
  nativeIpv6Available: boolean;
  summary: string;
}

const sha256Pattern = /^[a-f0-9]{64}$/u;
const operationIdPattern = /^h3_[A-Za-z0-9_-]{43}$/u;

export function exactDenyAllPolicy(value: unknown): boolean {
  return value === "deny-all";
}

function baseProbeShape(
  probe: NativeIpProbeRecord | undefined,
  expected: NativeIpProbeExpectation,
): probe is NativeIpProbeRecord & { result: SanitizedNativeIpProbeResult } {
  const result = probe?.result;
  return probe !== undefined && result !== undefined &&
    probe.caseId === expected.caseId && probe.addressFamily === expected.addressFamily &&
    probe.canarySource === expected.canarySource &&
    result.runId === expected.runId && result.testId === expected.testId &&
    result.caseId === expected.caseId && result.addressFamily === expected.addressFamily &&
    result.canarySource === expected.canarySource &&
    result.endpointHostname === expected.endpointHostname &&
    result.pinnedAddress === expected.pinnedAddress && result.pinnedPort === 443 &&
    result.attemptNumber === 1 && result.maximumRequests === 1 && result.retryCount === 0 &&
    result.redirectsAllowed === false && result.freshConnectionRequired === true &&
    result.environmentProxyTrust === false && result.strictCertificateVerification === true &&
    result.hostnameVerificationRequired === true;
}

export function authenticatedNativeIpOperationSuccess(
  probe: NativeIpProbeRecord | undefined,
  expected: NativeIpProbeExpectation,
): boolean {
  if (!baseProbeShape(probe, expected)) return false;
  const result = probe.result;
  const response = result.response;
  const cacheDirectives = response?.cacheControl?.toLowerCase().split(",").map((item) => item.trim()) ?? [];
  const familyProof = expected.addressFamily === "ipv6"
    ? result.peerAddressFamily === "ipv6" && result.nativeIpv6 === true &&
      !result.peerAddress?.toLowerCase().startsWith("::ffff:")
    : result.peerAddressFamily === "ipv4" && result.nativeIpv6 === false;
  const secretProof = expected.canarySource === "operator-secret-file"
    ? result.secretFileValidated === true && result.secretFileMode === "0600" &&
      typeof result.secretByteLength === "number" && result.secretByteLength >= 24 &&
      result.secretByteLength <= 128
    : result.secretFileValidated === false && result.secretFileMode === undefined &&
      result.secretByteLength === undefined;

  return probe.commandExitCode === 0 && result.ok === true && result.phase === "response" &&
    result.certificateVerified === true && result.hostnameVerified === true &&
    result.selectedAlpn === "http/1.1" &&
    (result.tlsVersion === "TLSv1.2" || result.tlsVersion === "TLSv1.3") &&
    typeof result.cipherSuite === "string" && result.cipherSuite.length >= 3 &&
    sha256Pattern.test(result.peerCertificateSha256 ?? "") &&
    result.peerAddress === expected.pinnedAddress && result.peerPort === 443 && familyProof && secretProof &&
    response?.statusCode === 200 && response.contentType?.toLowerCase().startsWith("application/json") === true &&
    cacheDirectives.includes("no-store") && typeof response.bodyByteLength === "number" &&
    response.bodyByteLength > 0 && response.bodyByteLength <= 1_024 &&
    response.bodyContainsCanary === false && response.rawBodyRetained === false &&
    result.authorized === true && result.operationIdShapeValid === true &&
    operationIdPattern.test(result.operationId ?? "") && result.operationId === probe.expectedOperationId;
}

export function conclusiveNativeIpFirewallBlock(
  probe: NativeIpProbeRecord | undefined,
  expected: NativeIpProbeExpectation,
): boolean {
  if (!baseProbeShape(probe, expected)) return false;
  const result = probe.result;
  const publicSourceDidNotReadSecret = expected.canarySource !== "controller-public-canary" ||
    (result.secretFileValidated === false && result.secretFileMode === undefined &&
      result.secretByteLength === undefined);
  if (
    probe.commandExitCode !== 10 || result.ok !== false || result.timeout !== false ||
    result.operationId !== undefined || result.authorized !== undefined ||
    result.responseStatusCode !== 0 || result.response !== undefined ||
    !publicSourceDidNotReadSecret || !["connect", "handshake"].includes(result.phase ?? "")
  ) return false;

  const activeTypes = new Set([
    "BrokenPipeError",
    "ConnectionAbortedError",
    "ConnectionRefusedError",
    "ConnectionResetError",
    "OSError",
    "SSLEOFError",
    "SSLZeroReturnError",
  ]);
  const activeErrnos = new Set([32, 54, 61, 101, 104, 111, 113]);
  return activeTypes.has(result.errorType ?? "") && activeErrnos.has(result.errorErrno ?? -1);
}

export function assessSbx033(input: Sbx033AssessmentInput): Sbx033Assessment {
  if (!input.cleanupPassed) {
    return {
      verdict: "error",
      candidate: false,
      controlsPassed: false,
      nativeIpv6Available: input.allowNativeIpv6Succeeded,
      summary: "One or both owned sandbox fixtures failed strict stop, delete, and three-check absence cleanup.",
    };
  }
  if (input.executionError) {
    return {
      verdict: "error",
      candidate: false,
      controlsPassed: false,
      nativeIpv6Available: input.allowNativeIpv6Succeeded,
      summary: "Controller execution failed before a complete assessment.",
    };
  }
  const baselinePassed = input.identityAndScopePassed && input.dnsSnapshotPassed &&
    input.allowSandboxCreated && input.allowIpv4Succeeded;
  if (!baselinePassed) {
    return {
      verdict: "indeterminate",
      candidate: false,
      controlsPassed: false,
      nativeIpv6Available: input.allowNativeIpv6Succeeded,
      summary: "Identity, ownership, DNS hardpin, allow-all IPv4, or fixture attribution controls failed.",
    };
  }
  if (!input.allowNativeIpv6Succeeded) {
    return {
      verdict: "indeterminate",
      candidate: false,
      controlsPassed: false,
      nativeIpv6Available: false,
      summary: "The exact pinned native IPv6 endpoint was not reachable under allow-all; this environment cannot test the hypothesis.",
    };
  }
  const restrictedControlsPassed = input.denySandboxCreated && input.denyPolicyReadbackPassed &&
    input.denyIpv4Blocked && !input.denyIpv4UnexpectedlySucceeded && input.postTargetReadbackPassed;
  if (!restrictedControlsPassed) {
    return {
      verdict: "indeterminate",
      candidate: false,
      controlsPassed: false,
      nativeIpv6Available: true,
      summary: "The literal deny-all, same-session readback, or IPv4 deny discriminator failed.",
    };
  }
  if (
    input.denyIpv6PublicBlocked && !input.denyIpv6PublicSucceeded &&
    !input.secretTargetAttempted && !input.secretFilePrepared &&
    !input.denyIpv6SecretSucceeded && !input.denyIpv6SecretBlocked
  ) {
    return {
      verdict: "pass",
      candidate: false,
      controlsPassed: true,
      nativeIpv6Available: true,
      summary: "Literal deny-all conclusively blocked both fixed IPv4 and fixed native IPv6 HTTPS paths; no secret-bearing request was sent.",
    };
  }
  if (input.denyIpv6PublicSucceeded && !input.denyIpv6PublicBlocked) {
    if (
      input.secretTargetAttempted && input.secretFilePrepared &&
      input.denyIpv6SecretSucceeded && !input.denyIpv6SecretBlocked
    ) {
      return {
        verdict: "candidate",
        candidate: true,
        controlsPassed: true,
        nativeIpv6Available: true,
        summary: "Literal deny-all blocked the exact IPv4 control but native IPv6 exfiltrated a fresh file-backed synthetic operator secret with exact non-reflecting HMAC proof.",
      };
    }
    return {
      verdict: "indeterminate",
      candidate: false,
      controlsPassed: true,
      nativeIpv6Available: true,
      summary: "Native IPv6 carried the public canary under deny-all, but the gated file-secret proof was absent or inconsistent.",
    };
  }
  return {
    verdict: "indeterminate",
    candidate: false,
    controlsPassed: true,
    nativeIpv6Available: true,
    summary: "The deny-all native IPv6 result was neither one conclusive active block nor one authenticated success.",
  };
}
