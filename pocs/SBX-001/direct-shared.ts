import { createHmac, timingSafeEqual } from "node:crypto";

export const SBX001_DIRECT_TEST_ID = "SBX-001-DIRECT";
export const SBX001_DIRECT_SCOPE_CONFIRMATION =
  "I_CONTROL_THE_SBX001_AUTHORITATIVE_DNS_AND_HTTPS_ENDPOINTS_AND_AUTHORIZE_BOUNDED_TESTING";
export const SBX001_SECRET_FILE = "/tmp/sbx-001/operator-secret";
export const SBX001_SECRET_BYTES = 16;
export const SBX001_MIN_DNS_INTERVAL_MS = 250;
export const SBX001_RECEIPT_OBSERVATION_MS = 5_000;
export const SBX001_RECEIVER_WINDOW_MS = 20 * 60_000;

export const SBX001_CASES = {
  outsideUdp: "outside-udp",
  outsideTcp: "outside-tcp",
  allowPublic: "allow-public",
  denyPublic: "deny-public",
  denySecret: "deny-secret",
} as const;

export type Sbx001CaseId = typeof SBX001_CASES[keyof typeof SBX001_CASES];
export type Sbx001DnsTransport = "udp" | "tcp";
export type Sbx001Verdict = "candidate-high" | "candidate-medium" | "pass" | "indeterminate" | "error";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE32_REVERSE = new Map(
  [...BASE32_ALPHABET].map((character, index) => [character, index] as const),
);
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const noncePattern = /^[a-f0-9]{32}$/u;
const operationPattern = /^dns_[A-Za-z0-9_-]{43}$/u;
const commitmentPattern = /^dsc_[A-Za-z0-9_-]{43}$/u;
const dnsNamePattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;

export interface Sbx001DnsQuestion {
  transactionId: number;
  requestFlags: number;
  queryName: string;
  queryType: number;
  queryClass: 1;
  questionEnd: number;
}

export interface Sbx001CaseArm {
  caseId: Sbx001CaseId;
  armedAt: string;
  operationId: string;
}

export interface Sbx001ControllerArmEvidence extends Sbx001CaseArm {
  requestedAt: string;
  acknowledgedAt: string;
}

export interface Sbx001ReceiptObservationEvidence {
  caseId: Sbx001CaseId;
  operationId: string;
  startedAt: string;
  completedAt: string;
  maximumWindowMs: typeof SBX001_RECEIPT_OBSERVATION_MS;
  pollCount: number;
  receiptObserved: boolean;
}

export interface Sbx001Receipt {
  runId: string;
  caseId: Sbx001CaseId;
  kind: "public" | "secret";
  transport: Sbx001DnsTransport;
  queryType: "A";
  authoritativeResponseSent: boolean;
  operationId: string;
  armedAt: string;
  observedAt: string;
  sourceAddress: string;
  sourcePort: number;
  duplicateCount: number;
  withinConfiguredWindow: boolean;
  rawQueryNameRetained: false;
  rawSecretRetained: false;
  rawSecretDigestRetained: false;
}

export interface Sbx001ReceiverSnapshot {
  configured: boolean;
  runId?: string;
  configuredAt?: string;
  expiresAt?: string;
  observationWindowMs?: typeof SBX001_RECEIVER_WINDOW_MS;
  receipts: Sbx001Receipt[];
  arms: Sbx001CaseArm[];
  secretRegistered: boolean;
  secretRegisteredAt?: string;
  rawQueryNamesRetained: false;
  rawSecretsRetained: false;
  rawSecretDigestsRetained: false;
}

export interface Sbx001GuestDnsEvidence {
  schemaVersion: 1;
  ok: boolean;
  mode: "dns";
  runId: string;
  testId: typeof SBX001_DIRECT_TEST_ID;
  guestNodeVersion: string;
  caseId: "allow-public" | "deny-public" | "deny-secret";
  queryType: "A";
  queryAttempts: 1;
  retryCount: 0;
  resolverFamily: 4 | 6;
  resolverPort: 53;
  sendInvoked: boolean;
  datagramAcceptedByKernel: boolean;
  responseReceived: boolean;
  timedOut: boolean;
  transactionIdMatched?: boolean;
  responseCode?: number;
  secretFileValidated: boolean;
  secretFileMode?: number;
  secretBytes?: number;
  secretEncodedInOneLabel: boolean;
  rawQueryNameRetained: false;
  rawSecretRetained: false;
  rawSecretDigestRetained: false;
  errorCode?: string;
}

export interface Sbx001GuestHttpsEvidence {
  schemaVersion: 1;
  ok: boolean;
  mode: "https";
  runId: string;
  testId: typeof SBX001_DIRECT_TEST_ID;
  guestNodeVersion: string;
  caseId: "allow-https" | "deny-https";
  origin: string;
  path: "/healthz";
  connectionAttempts: 1;
  retryCount: 0;
  responseBodiesRetained: false;
  durationMs: number;
  receivedResponse: boolean;
  statusCode?: number;
  timedOut: boolean;
  errorCode?: string;
}

export interface Sbx001PolicyReadback {
  observedAt: string;
  originalSessionId: string;
  activeSessionId: string;
  independentSessionId: string;
  activeSandboxPolicy: unknown;
  activeSessionPolicy: unknown;
  independentSandboxPolicy: unknown;
  independentSessionPolicy: unknown;
  exact: boolean;
  sameSession: boolean;
  passed: boolean;
}

export interface Sbx001CleanupEvidence {
  sandboxCreateAttempted: boolean;
  sandboxRecovered: boolean;
  sandboxAlreadyAbsent: boolean;
  sandboxRecoveryChecks: number;
  sandboxRecoveryObservationMs: number;
  stopAttempted: boolean;
  stopped: boolean;
  deleteAttempted: boolean;
  deleted: boolean;
  absenceChecks: number;
  absenceConfirmed: boolean;
  receiverConfigureAttempted: boolean;
  receiverAlreadyAbsent: boolean;
  receiverDeleteAttempted: boolean;
  receiverDeleted: boolean;
  receiverAbsenceChecks: number;
  receiverAbsenceConfirmed: boolean;
  errors: string[];
}

export interface Sbx001DirectAssessmentInput {
  runId: string;
  authoritativeZone: string;
  httpsControlOrigin: string;
  identityAndScopePassed: boolean;
  delegationPreflightPassed: boolean;
  outsideHttpsPassed: boolean;
  outsideUdpPassed: boolean;
  outsideTcpPassed: boolean;
  allowReadback: Sbx001PolicyReadback;
  allowHttps: Sbx001GuestHttpsEvidence;
  allowDns: Sbx001GuestDnsEvidence;
  denyReadback: Sbx001PolicyReadback;
  denyPostReadback: Sbx001PolicyReadback;
  denyHttps: Sbx001GuestHttpsEvidence;
  denyDns: Sbx001GuestDnsEvidence;
  secretDns?: Sbx001GuestDnsEvidence;
  receiver: Sbx001ReceiverSnapshot;
  controllerArms: Partial<Record<Sbx001CaseId, Sbx001ControllerArmEvidence>>;
  receiverObservations: Partial<Record<Sbx001CaseId, Sbx001ReceiptObservationEvidence>>;
  expectedOperations: Record<Sbx001CaseId, string>;
  denyPublicReceiptObservedAt?: string;
  denyPublicReceiptFetchedAt?: string;
  secretCreatedAt?: string;
  secretRegisteredAt?: string;
  secretWrittenAt?: string;
  secretAttempted: boolean;
  secretStagedBeforePublicSignal: boolean;
  cleanup: Sbx001CleanupEvidence;
  retention: {
    rawQueryName: false;
    rawOperatorSecret: false;
    rawSecretDigest: false;
    rawGuestConfiguration: false;
    rawCommandOutput: false;
  };
  executionError?: boolean;
}

export interface Sbx001DirectAssessment {
  verdict: Sbx001Verdict;
  candidate: boolean;
  severity: "high" | "medium" | "none" | "unknown";
  controlsPassed: boolean;
  secretPhaseAuthorized: boolean;
  summary: string;
}

function validateKey(key: string): void {
  if (Buffer.byteLength(key) < 32 || Buffer.byteLength(key) > 256 || /[\0\r\n]/u.test(key)) {
    throw new Error("proof key must contain 32-256 bytes without control characters");
  }
}

function hmac(key: string, value: string | Buffer): string {
  validateKey(key);
  return createHmac("sha256", key).update(value).digest("base64url");
}

export function canonicalDnsName(value: string, field = "DNS name"): string {
  if (value !== value.toLowerCase() || value.endsWith(".") || !dnsNamePattern.test(value)) {
    throw new Error(`${field} must be a canonical lowercase DNS name`);
  }
  return value;
}

export function validateRunId(value: string): string {
  if (!uuidPattern.test(value)) throw new Error("runId must be a canonical UUIDv4");
  return value;
}

export function validateNonce(value: string): string {
  if (!noncePattern.test(value)) throw new Error("query nonce must contain 128 random bits as lowercase hex");
  return value;
}

export function base32EncodeDirect(value: Uint8Array): string {
  let accumulator = 0;
  let availableBits = 0;
  let output = "";
  for (const byte of value) {
    accumulator = (accumulator << 8) | byte;
    availableBits += 8;
    while (availableBits >= 5) {
      availableBits -= 5;
      output += BASE32_ALPHABET[(accumulator >>> availableBits) & 31];
      accumulator &= (1 << availableBits) - 1;
    }
  }
  if (availableBits > 0) output += BASE32_ALPHABET[(accumulator << (5 - availableBits)) & 31];
  return output;
}

export function base32DecodeDirect(encoded: string): Buffer {
  if (!/^[A-Z2-7]{1,63}$/u.test(encoded)) throw new Error("invalid unpadded base32 value");
  let accumulator = 0;
  let availableBits = 0;
  const bytes: number[] = [];
  for (const character of encoded) {
    const decoded = BASE32_REVERSE.get(character);
    if (decoded === undefined) throw new Error("invalid base32 character");
    accumulator = (accumulator << 5) | decoded;
    availableBits += 5;
    while (availableBits >= 8) {
      availableBits -= 8;
      bytes.push((accumulator >>> availableBits) & 0xff);
      accumulator &= (1 << availableBits) - 1;
    }
  }
  if (availableBits > 0 && accumulator !== 0) throw new Error("non-zero base32 padding bits");
  const output = Buffer.from(bytes);
  if (base32EncodeDirect(output) !== encoded) {
    output.fill(0);
    throw new Error("non-canonical base32 value");
  }
  return output;
}

const publicPrefixes: Record<Exclude<Sbx001CaseId, "deny-secret">, string> = {
  "outside-udp": "u",
  "outside-tcp": "t",
  "allow-public": "a",
  "deny-public": "d",
};

export function publicDnsLabel(caseId: Exclude<Sbx001CaseId, "deny-secret">, nonce: string): string {
  validateNonce(nonce);
  return `${publicPrefixes[caseId]}${nonce}`;
}

export function publicDnsName(
  caseId: Exclude<Sbx001CaseId, "deny-secret">,
  nonce: string,
  zone: string,
): string {
  return canonicalDnsName(`${publicDnsLabel(caseId, nonce)}.${canonicalDnsName(zone, "authoritative zone")}`);
}

export function secretDnsLabel(secret: Uint8Array, nonce: string): string {
  if (secret.byteLength !== SBX001_SECRET_BYTES) throw new Error("secret must contain exactly 16 bytes");
  validateNonce(nonce);
  const label = `s${base32EncodeDirect(secret).toLowerCase()}${nonce}`;
  if (label.length !== 59 || label.length > 63) throw new Error("secret label exceeded its exact bound");
  return label;
}

export function decodeSecretDnsLabel(label: string, nonce: string): Buffer | undefined {
  validateNonce(nonce);
  if (!new RegExp(`^s[a-z2-7]{26}${nonce}$`, "u").test(label)) return undefined;
  try {
    const decoded = base32DecodeDirect(label.slice(1, 27).toUpperCase());
    if (decoded.byteLength !== SBX001_SECRET_BYTES) {
      decoded.fill(0);
      return undefined;
    }
    return decoded;
  } catch {
    return undefined;
  }
}

export function derivePublicDnsOperationId(
  key: string,
  runId: string,
  caseId: Exclude<Sbx001CaseId, "deny-secret">,
  label: string,
): string {
  validateRunId(runId);
  if (publicDnsLabel(caseId, label.slice(1)) !== label) throw new Error("public label does not match its case");
  return `dns_${hmac(key, `public\0${runId}\0${caseId}\0${label}`)}`;
}

export function deriveSecretDnsCommitment(
  key: string,
  runId: string,
  secret: Uint8Array,
): string {
  validateRunId(runId);
  if (secret.byteLength !== SBX001_SECRET_BYTES) throw new Error("secret must contain exactly 16 bytes");
  const prefix = Buffer.from(`secret\0${runId}\0`, "ascii");
  const material = Buffer.concat([prefix, secret]);
  try {
    return `dsc_${hmac(key, material)}`;
  } finally {
    material.fill(0);
  }
}

export function deriveSecretDnsOperationId(key: string, runId: string, commitment: string): string {
  validateRunId(runId);
  if (!commitmentPattern.test(commitment)) throw new Error("secret commitment is invalid");
  return `dns_${hmac(key, `accepted\0${runId}\0${SBX001_CASES.denySecret}\0${commitment}`)}`;
}

export function equalSecretDnsCommitments(left: string, right: string): boolean {
  if (!commitmentPattern.test(left) || !commitmentPattern.test(right)) return false;
  return timingSafeEqual(Buffer.from(left), Buffer.from(right));
}

export function parseDnsQuestion(packet: Buffer): Sbx001DnsQuestion | undefined {
  if (packet.length < 17 || packet.length > 512) return undefined;
  const requestFlags = packet.readUInt16BE(2);
  if ((requestFlags & 0x8000) !== 0 || (requestFlags & 0x7800) !== 0 || packet.readUInt16BE(4) !== 1 ||
    packet.readUInt16BE(6) !== 0 || packet.readUInt16BE(8) !== 0 || packet.readUInt16BE(10) > 1) return undefined;
  const labels: string[] = [];
  let cursor = 12;
  while (cursor < packet.length) {
    const length = packet[cursor++]!;
    if (length === 0) break;
    if ((length & 0xc0) !== 0 || length > 63 || cursor + length > packet.length) return undefined;
    const labelBytes = packet.subarray(cursor, cursor + length);
    if (labelBytes.some((byte) => byte < 0x21 || byte > 0x7e)) return undefined;
    const label = labelBytes.toString("ascii").toLowerCase();
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label)) return undefined;
    labels.push(label);
    cursor += length;
  }
  if (labels.length === 0 || cursor + 4 > packet.length) return undefined;
  const queryType = packet.readUInt16BE(cursor);
  const queryClass = packet.readUInt16BE(cursor + 2);
  if (queryType < 1 || queryType > 65_535 || queryClass !== 1) return undefined;
  const questionEnd = cursor + 4;
  const additionalCount = packet.readUInt16BE(10);
  if (additionalCount === 0 && questionEnd !== packet.length) return undefined;
  if (additionalCount === 1) {
    let additional = questionEnd;
    if (additional + 11 > packet.length || packet[additional++] !== 0 || packet.readUInt16BE(additional) !== 41) return undefined;
    additional += 2;
    const udpPayloadSize = packet.readUInt16BE(additional);
    additional += 2;
    if (udpPayloadSize < 512 || udpPayloadSize > 4_096) return undefined;
    additional += 4;
    const dataLength = packet.readUInt16BE(additional);
    additional += 2;
    if (additional + dataLength !== packet.length || dataLength > 256) return undefined;
  }
  const queryName = labels.join(".");
  if (!dnsNamePattern.test(queryName)) return undefined;
  return {
    transactionId: packet.readUInt16BE(0),
    requestFlags,
    queryName,
    queryType,
    queryClass: 1,
    questionEnd,
  };
}

export function parseDnsAQuestion(packet: Buffer): Sbx001DnsQuestion | undefined {
  const parsed = parseDnsQuestion(packet);
  return parsed?.queryType === 1 ? parsed : undefined;
}

export function buildDnsQueryDirect(queryName: string, transactionId: number, queryType: number): Buffer {
  const canonical = canonicalDnsName(queryName);
  if (!Number.isInteger(transactionId) || transactionId < 0 || transactionId > 65_535) {
    throw new Error("transactionId is invalid");
  }
  if (!Number.isInteger(queryType) || queryType < 1 || queryType > 65_535) {
    throw new Error("queryType is invalid");
  }
  const labels: Buffer[] = [];
  for (const label of canonical.split(".")) {
    const bytes = Buffer.from(label, "ascii");
    labels.push(Buffer.from([bytes.length]), bytes);
  }
  const header = Buffer.alloc(12);
  header.writeUInt16BE(transactionId, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  const tail = Buffer.alloc(5);
  tail.writeUInt16BE(queryType, 1);
  tail.writeUInt16BE(1, 3);
  return Buffer.concat([header, ...labels, tail]);
}

export function buildDnsAQueryDirect(queryName: string, transactionId: number): Buffer {
  return buildDnsQueryDirect(queryName, transactionId, 1);
}

export function buildAuthoritativeAResponse(query: Buffer, answerIPv4: string): Buffer | undefined {
  const parsed = parseDnsAQuestion(query);
  if (!parsed) return undefined;
  const octets = answerIPv4.split(".").map(Number);
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
    throw new Error("answerIPv4 is invalid");
  }
  const header = Buffer.alloc(12);
  header.writeUInt16BE(parsed.transactionId, 0);
  header.writeUInt16BE(0x8400 | (parsed.requestFlags & 0x0100), 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(1, 6);
  const question = query.subarray(12, parsed.questionEnd);
  const answer = Buffer.alloc(16);
  answer.writeUInt16BE(0xc00c, 0);
  answer.writeUInt16BE(1, 2);
  answer.writeUInt16BE(1, 4);
  answer.writeUInt32BE(0, 6);
  answer.writeUInt16BE(4, 10);
  Buffer.from(octets).copy(answer, 12);
  return Buffer.concat([header, question, answer]);
}

export function validateAuthoritativeAResponse(response: Buffer, transactionId: number): boolean {
  return response.length >= 33 && response.readUInt16BE(0) === transactionId &&
    (response.readUInt16BE(2) & 0x840f) === 0x8400 && response.readUInt16BE(4) === 1 &&
    response.readUInt16BE(6) === 1;
}

export function exactPolicyReadback(
  value: Omit<Sbx001PolicyReadback, "exact" | "sameSession" | "passed">,
  expected: "allow-all" | "deny-all",
): Sbx001PolicyReadback {
  const exact = value.activeSandboxPolicy === expected && value.activeSessionPolicy === expected &&
    value.independentSandboxPolicy === expected && value.independentSessionPolicy === expected;
  const sameSession = value.originalSessionId.length > 0 && value.activeSessionId === value.originalSessionId &&
    value.independentSessionId === value.originalSessionId;
  return { ...value, exact, sameSession, passed: exact && sameSession };
}

function exactPublicReceipt(
  snapshot: Sbx001ReceiverSnapshot,
  runId: string,
  caseId: Exclude<Sbx001CaseId, "deny-secret">,
  operationId: string,
  transport?: Sbx001DnsTransport,
): Sbx001Receipt | undefined {
  const arms = snapshot.arms.filter((arm) => arm.caseId === caseId);
  if (arms.length !== 1) return undefined;
  const arm = arms[0]!;
  if (arm.operationId !== operationId || !operationPattern.test(arm.operationId) ||
    !Number.isFinite(Date.parse(arm.armedAt))) return undefined;
  const receipts = snapshot.receipts.filter((receipt) => receipt.runId === runId && receipt.caseId === caseId &&
    receipt.kind === "public" && receipt.queryType === "A" && receipt.authoritativeResponseSent === true &&
    receipt.operationId === operationId && operationPattern.test(receipt.operationId) &&
    receipt.withinConfiguredWindow === true && receipt.rawQueryNameRetained === false &&
    receipt.rawSecretRetained === false && receipt.rawSecretDigestRetained === false && receipt.armedAt === arm.armedAt &&
    Date.parse(receipt.observedAt) >= Date.parse(arm.armedAt) &&
    (transport === undefined || receipt.transport === transport));
  return receipts.length === 1 ? receipts[0] : undefined;
}

function exactSecretReceipt(
  snapshot: Sbx001ReceiverSnapshot,
  runId: string,
  operationId: string,
): Sbx001Receipt | undefined {
  const arms = snapshot.arms.filter((arm) => arm.caseId === SBX001_CASES.denySecret);
  if (arms.length !== 1) return undefined;
  const arm = arms[0]!;
  if (arm.operationId !== operationId || !operationPattern.test(arm.operationId) ||
    !Number.isFinite(Date.parse(arm.armedAt))) return undefined;
  const receipts = snapshot.receipts.filter((receipt) => receipt.runId === runId &&
    receipt.caseId === SBX001_CASES.denySecret && receipt.kind === "secret" && receipt.queryType === "A" &&
    receipt.authoritativeResponseSent === true && receipt.operationId === operationId &&
    operationPattern.test(receipt.operationId) && receipt.withinConfiguredWindow === true && receipt.armedAt === arm.armedAt &&
    Date.parse(receipt.observedAt) >= Date.parse(arm.armedAt) &&
    receipt.rawQueryNameRetained === false && receipt.rawSecretRetained === false &&
    receipt.rawSecretDigestRetained === false);
  return receipts.length === 1 ? receipts[0] : undefined;
}

function exactControllerArm(
  input: Sbx001DirectAssessmentInput,
  caseId: Sbx001CaseId,
  operationId: string,
  earliestControllerTime?: string,
): boolean {
  const arm = input.controllerArms[caseId];
  const receiverArms = input.receiver.arms.filter((entry) => entry.caseId === caseId);
  if (!arm || receiverArms.length !== 1 || arm.caseId !== caseId || arm.operationId !== operationId ||
    !operationPattern.test(arm.operationId) || arm.armedAt !== receiverArms[0]!.armedAt ||
    arm.operationId !== receiverArms[0]!.operationId ||
    !timestampsOrdered(arm.requestedAt, arm.acknowledgedAt)) return false;
  return earliestControllerTime === undefined || timestampsOrdered(earliestControllerTime, arm.requestedAt);
}

function exactReceiptObservation(
  input: Sbx001DirectAssessmentInput,
  caseId: Sbx001CaseId,
  operationId: string,
  receiptObserved: boolean,
): boolean {
  const observation = input.receiverObservations[caseId];
  if (!observation || observation.caseId !== caseId || observation.operationId !== operationId ||
    observation.maximumWindowMs !== SBX001_RECEIPT_OBSERVATION_MS ||
    !Number.isInteger(observation.pollCount) || observation.pollCount < 1 ||
    observation.receiptObserved !== receiptObserved ||
    !timestampsOrdered(observation.startedAt, observation.completedAt)) return false;
  const durationMs = Date.parse(observation.completedAt) - Date.parse(observation.startedAt);
  return receiptObserved || (observation.pollCount >= 2 &&
    durationMs >= SBX001_RECEIPT_OBSERVATION_MS - 100 && durationMs <= SBX001_RECEIPT_OBSERVATION_MS + 5_000);
}

function exactDnsGuest(
  value: Sbx001GuestDnsEvidence,
  runId: string,
  caseId: "allow-public" | "deny-public" | "deny-secret",
): boolean {
  const base = value.schemaVersion === 1 && value.ok === true && value.mode === "dns" && value.runId === runId &&
    value.testId === SBX001_DIRECT_TEST_ID && value.caseId === caseId && value.queryType === "A" &&
    /^v\d+\.\d+\.\d+(?:[-+].*)?$/u.test(value.guestNodeVersion) &&
    value.queryAttempts === 1 && value.retryCount === 0 && (value.resolverFamily === 4 || value.resolverFamily === 6) &&
    value.resolverPort === 53 && value.sendInvoked === true &&
    value.rawQueryNameRetained === false && value.rawSecretRetained === false &&
    value.rawSecretDigestRetained === false;
  const activeLocalBlock = value.datagramAcceptedByKernel === false && value.responseReceived === false &&
    value.timedOut === false && value.errorCode !== undefined &&
    ["EACCES", "EHOSTUNREACH", "ENETUNREACH", "EPERM"].includes(value.errorCode);
  return caseId === "deny-secret"
    ? base && value.datagramAcceptedByKernel === true && value.secretFileValidated === true && value.secretFileMode === 0o600 &&
      value.secretBytes === SBX001_SECRET_BYTES && value.secretEncodedInOneLabel === true
    : base && (caseId === "allow-public" ? value.datagramAcceptedByKernel === true
      : value.datagramAcceptedByKernel === true || activeLocalBlock) &&
      value.secretFileValidated === false && value.secretFileMode === undefined && value.secretBytes === undefined &&
      value.secretEncodedInOneLabel === false;
}

function exactAllowHttps(value: Sbx001GuestHttpsEvidence, runId: string, origin: string): boolean {
  return value.schemaVersion === 1 && value.ok === true && value.mode === "https" && value.runId === runId &&
    value.testId === SBX001_DIRECT_TEST_ID && value.caseId === "allow-https" && value.origin === origin &&
    /^v\d+\.\d+\.\d+(?:[-+].*)?$/u.test(value.guestNodeVersion) &&
    value.path === "/healthz" && value.connectionAttempts === 1 && value.retryCount === 0 &&
    Number.isInteger(value.durationMs) && value.durationMs >= 0 && value.durationMs <= 10_000 &&
    value.responseBodiesRetained === false && value.receivedResponse === true && value.statusCode === 200 &&
    value.timedOut === false && value.errorCode === undefined;
}

function exactDenyHttps(value: Sbx001GuestHttpsEvidence, runId: string, origin: string): boolean {
  return value.schemaVersion === 1 && value.ok === true && value.mode === "https" && value.runId === runId &&
    value.testId === SBX001_DIRECT_TEST_ID && value.caseId === "deny-https" && value.origin === origin &&
    /^v\d+\.\d+\.\d+(?:[-+].*)?$/u.test(value.guestNodeVersion) &&
    value.path === "/healthz" && value.connectionAttempts === 1 && value.retryCount === 0 &&
    Number.isInteger(value.durationMs) && value.durationMs >= 0 && value.durationMs <= 10_000 &&
    value.responseBodiesRetained === false && value.receivedResponse === false && value.statusCode === undefined &&
    value.timedOut === false && (value.errorCode === "EAI_AGAIN" || value.errorCode === "EHOSTUNREACH");
}

function cleanupPassed(value: Sbx001CleanupEvidence): boolean {
  const sandboxSafe = !value.sandboxCreateAttempted ||
    (value.sandboxAlreadyAbsent && value.sandboxRecoveryChecks === 16 &&
      value.sandboxRecoveryObservationMs >= 29_500 && value.absenceChecks === 0 && value.absenceConfirmed) ||
    (value.stopAttempted && value.deleteAttempted && value.deleted &&
      value.absenceChecks === 3 && value.absenceConfirmed);
  const receiverSafe = !value.receiverConfigureAttempted ||
    (value.receiverAbsenceChecks === 3 && value.receiverAbsenceConfirmed && (value.receiverAlreadyAbsent ||
      (value.receiverDeleteAttempted && value.receiverDeleted)));
  return value.errors.length === 0 && sandboxSafe && receiverSafe;
}

function timestampsOrdered(...values: Array<string | undefined>): boolean {
  const parsed = values.map((value) => value === undefined ? Number.NaN : Date.parse(value));
  return parsed.every(Number.isFinite) && parsed.every((value, index) => index === 0 || value >= parsed[index - 1]!);
}

export function assessSbx001Direct(input: Sbx001DirectAssessmentInput): Sbx001DirectAssessment {
  const cleaned = cleanupPassed(input.cleanup);
  if (!cleaned) {
    return {
      verdict: "error",
      candidate: false,
      severity: "unknown",
      controlsPassed: false,
      secretPhaseAuthorized: false,
      summary: "Sandbox or receiver cleanup did not complete and pass independent absence checks.",
    };
  }
  const retentionPassed = input.retention.rawQueryName === false && input.retention.rawOperatorSecret === false &&
    input.retention.rawSecretDigest === false && input.retention.rawGuestConfiguration === false &&
    input.retention.rawCommandOutput === false && input.receiver.rawQueryNamesRetained === false &&
    input.receiver.rawSecretsRetained === false && input.receiver.rawSecretDigestsRetained === false;
  const receiverIdentityPassed = input.receiver.configured === true && input.receiver.runId === input.runId &&
    input.receiver.observationWindowMs === SBX001_RECEIVER_WINDOW_MS &&
    timestampsOrdered(input.receiver.configuredAt, input.receiver.expiresAt) &&
    Date.parse(input.receiver.expiresAt!) - Date.parse(input.receiver.configuredAt!) === SBX001_RECEIVER_WINDOW_MS;
  const publicReceipt = exactPublicReceipt(input.receiver, input.runId, SBX001_CASES.denyPublic,
    input.expectedOperations[SBX001_CASES.denyPublic]);
  const outsidePassed = receiverIdentityPassed && input.identityAndScopePassed && input.delegationPreflightPassed &&
    input.outsideHttpsPassed &&
    input.outsideUdpPassed && input.outsideTcpPassed &&
    exactControllerArm(input, SBX001_CASES.outsideUdp, input.expectedOperations[SBX001_CASES.outsideUdp]) &&
    exactControllerArm(input, SBX001_CASES.outsideTcp, input.expectedOperations[SBX001_CASES.outsideTcp]) &&
    exactReceiptObservation(input, SBX001_CASES.outsideUdp,
      input.expectedOperations[SBX001_CASES.outsideUdp], true) &&
    exactReceiptObservation(input, SBX001_CASES.outsideTcp,
      input.expectedOperations[SBX001_CASES.outsideTcp], true) &&
    exactPublicReceipt(input.receiver, input.runId, SBX001_CASES.outsideUdp,
      input.expectedOperations[SBX001_CASES.outsideUdp], "udp") !== undefined &&
    exactPublicReceipt(input.receiver, input.runId, SBX001_CASES.outsideTcp,
      input.expectedOperations[SBX001_CASES.outsideTcp], "tcp") !== undefined;
  const allowPassed = input.allowReadback.passed && exactAllowHttps(input.allowHttps, input.runId, input.httpsControlOrigin) &&
    exactControllerArm(input, SBX001_CASES.allowPublic, input.expectedOperations[SBX001_CASES.allowPublic],
      input.allowReadback.observedAt) &&
    exactReceiptObservation(input, SBX001_CASES.allowPublic,
      input.expectedOperations[SBX001_CASES.allowPublic], true) &&
    exactDnsGuest(input.allowDns, input.runId, SBX001_CASES.allowPublic) &&
    exactPublicReceipt(input.receiver, input.runId, SBX001_CASES.allowPublic,
      input.expectedOperations[SBX001_CASES.allowPublic]) !== undefined;
  const denyControlsPassed = input.denyReadback.passed && input.denyPostReadback.passed &&
    input.denyReadback.originalSessionId === input.allowReadback.originalSessionId &&
    input.denyPostReadback.originalSessionId === input.allowReadback.originalSessionId &&
    exactControllerArm(input, SBX001_CASES.denyPublic, input.expectedOperations[SBX001_CASES.denyPublic],
      input.denyReadback.observedAt) &&
    exactReceiptObservation(input, SBX001_CASES.denyPublic,
      input.expectedOperations[SBX001_CASES.denyPublic], publicReceipt !== undefined) &&
    exactDenyHttps(input.denyHttps, input.runId, input.httpsControlOrigin) &&
    exactDnsGuest(input.denyDns, input.runId, SBX001_CASES.denyPublic);
  const controlsPassed = outsidePassed && allowPassed && denyControlsPassed && retentionPassed;
  if (input.executionError || !controlsPassed) {
    return {
      verdict: "indeterminate",
      candidate: false,
      severity: "unknown",
      controlsPassed: false,
      secretPhaseAuthorized: false,
      summary: "One or more identity, outside, allow-all, deny-all, ordinary-HTTPS, attribution, or retention controls failed.",
    };
  }
  if (!publicReceipt) {
    if (input.secretAttempted || input.secretStagedBeforePublicSignal || input.secretDns !== undefined ||
      input.secretCreatedAt !== undefined || input.secretRegisteredAt !== undefined) {
      return {
        verdict: "indeterminate",
        candidate: false,
        severity: "unknown",
        controlsPassed: true,
        secretPhaseAuthorized: false,
        summary: "The secret phase ran without an exact preceding public deny-all authoritative receipt.",
      };
    }
    return {
      verdict: "pass",
      candidate: false,
      severity: "none",
      controlsPassed: true,
      secretPhaseAuthorized: false,
      summary: "The authoritative allow control succeeded, ordinary HTTPS was actively blocked, and no deny-all DNS query reached the owned server.",
    };
  }
  const publicTimestampMatches = input.denyPublicReceiptObservedAt === publicReceipt.observedAt;
  if (!input.secretAttempted) {
    return {
      verdict: "candidate-medium",
      candidate: true,
      severity: "medium",
      controlsPassed: true,
      secretPhaseAuthorized: true,
      summary: "A fresh public DNS query reached the owned authoritative server under literal deny-all; no secret phase completed.",
    };
  }
  const secretReceipt = exactSecretReceipt(input.receiver, input.runId,
    input.expectedOperations[SBX001_CASES.denySecret]);
  const highPassed = publicTimestampMatches && !input.secretStagedBeforePublicSignal && input.receiver.secretRegistered &&
    input.secretDns !== undefined && exactDnsGuest(input.secretDns, input.runId, SBX001_CASES.denySecret) &&
    secretReceipt !== undefined && exactControllerArm(input, SBX001_CASES.denySecret,
      input.expectedOperations[SBX001_CASES.denySecret], input.secretWrittenAt) &&
    exactReceiptObservation(input, SBX001_CASES.denySecret,
      input.expectedOperations[SBX001_CASES.denySecret], true) &&
    timestampsOrdered(input.denyPublicReceiptFetchedAt, input.secretCreatedAt,
      input.secretRegisteredAt, input.secretWrittenAt) &&
    timestampsOrdered(publicReceipt.observedAt, input.receiver.secretRegisteredAt,
      secretReceipt.armedAt, secretReceipt.observedAt);
  if (highPassed) {
    return {
      verdict: "candidate-high",
      candidate: true,
      severity: "high",
      controlsPassed: true,
      secretPhaseAuthorized: true,
      summary: "After the public deny-all signal, one fresh mode-0600 file secret reached the owned authoritative server and produced the exact opaque HMAC receipt.",
    };
  }
  return {
    verdict: "candidate-medium",
    candidate: true,
    severity: "medium",
    controlsPassed: true,
    secretPhaseAuthorized: true,
    summary: "The public deny-all DNS boundary violation is exact, but the separately gated file-secret proof did not complete.",
  };
}
