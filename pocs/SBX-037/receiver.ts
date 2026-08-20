import "dotenv/config";

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { isIP } from "node:net";
import {
  createRemoteJWKSet,
  decodeJwt,
  decodeProtectedHeader,
  jwtVerify,
  type JWTPayload,
} from "jose";

const TEST_ID = "SBX-037-POC";
const VERCEL_OIDC_HOSTNAME = "oidc.vercel.com";
const OIDC_HEADER = "vercel-sandbox-oidc-token";
const FORWARDED_HOST_HEADER = "vercel-forwarded-host";
const FORWARDED_SCHEME_HEADER = "vercel-forwarded-scheme";
const FORWARDED_PORT_HEADER = "vercel-forwarded-port";
const FORWARDED_PATH_HEADER = "vercel-forwarded-path";
const CASE_HEADER = "x-sbx037-case";
const RUN_HEADER = "x-sbx037-run";
const CANARY_HEADER = "x-sbx-harness-canary";
const MAX_BODY_BYTES = 2_048;
const MAX_SECRET_BYTES = 512;
const MAX_STATES = 8;
const MAX_FALLBACK_RECORDS_PER_RUN = 16;
const ACTION_OPERATION_ID = /^rt37a_[A-Za-z0-9_-]{24}$/u;
const RECEIPT_ID = /^rt37r_[A-Za-z0-9_-]{24}$/u;
const FALLBACK_RECEIPT_ID = /^rt37f_[A-Za-z0-9_-]{24}$/u;
const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

export type AttackCaseId = "absolute-target-attack" | "network-path-target-attack";
export type SyntaxCaseId = "absolute-syntax-control" | "network-path-syntax-control";
export type PSyntaxCaseId = "absolute-p-syntax-control" | "network-p-syntax-control";
export type DirectCaseId = "direct-b-allow" | "direct-b-pre" | "direct-b-post";
export type ForwardCaseId = "origin-form-terminal" | AttackCaseId;

const ATTACK_CASES = new Set<AttackCaseId>(["absolute-target-attack", "network-path-target-attack"]);
const SYNTAX_CASES = new Set<SyntaxCaseId>(["absolute-syntax-control", "network-path-syntax-control"]);
const P_SYNTAX_CASES = new Set<PSyntaxCaseId>(["absolute-p-syntax-control", "network-p-syntax-control"]);
const DIRECT_CASES = new Set<DirectCaseId>(["direct-b-allow", "direct-b-pre", "direct-b-post"]);
const FORWARD_CASES = new Set<ForwardCaseId>([
  "origin-form-terminal",
  "absolute-target-attack",
  "network-path-target-attack",
]);

export interface ExpectedActionOperationIds {
  absoluteTargetAttack: string;
  networkPathTargetAttack: string;
}

export interface CaseOperationIds {
  absoluteTargetAttack: string;
  networkPathTargetAttack: string;
}

export interface SyntaxOperationIds {
  absoluteSyntaxControl: string;
  networkPathSyntaxControl: string;
  absolutePSyntaxControl: string;
  networkPSyntaxControl: string;
}

export interface CaseCorrelations {
  directBAllow: string;
  directBPre: string;
  directBPost: string;
  originFormTerminal: string;
  absoluteSyntaxControl: string;
  networkPathSyntaxControl: string;
  absolutePSyntaxControl: string;
  networkPSyntaxControl: string;
  absoluteTargetAttack: string;
  networkPathTargetAttack: string;
}

export interface ReceiverConfiguration {
  runId: string;
  aOrigin: string;
  pOrigin: string;
  bOrigin: string;
  forwardAudience: string;
  expectedTeamId: string;
  expectedProjectId: string;
  /** Vercel's `sandbox_id` OIDC claim is the SDK session/sandbox ID. */
  expectedSandboxId: string;
  expectedSandboxName: string;
  caseCorrelations: CaseCorrelations;
  initialBOperationId: string;
  originOperationId: string;
  syntaxOperationIds: SyntaxOperationIds;
  caseOperationIds: CaseOperationIds;
  expectedActionOperationIds: ExpectedActionOperationIds;
}

export interface VerifiedIdentity {
  teamId: string;
  projectId: string;
  sandboxId: string;
  sessionId: string;
  sandboxName: string;
}

export interface IndependentOidcVerification {
  tokenOrdinal: 1;
  verifier: "sink-p-independent-jose" | "observer-b-independent-jose";
  signatureVerified: true;
  algorithm: "RS256";
  issuer: string;
  jwksUrl: string;
  audience: string;
  temporalClaimsVerified: boolean;
  exactClaimsVerified: boolean;
  identity: VerifiedIdentity;
  rawTokenRetained: false;
  verificationError?: "non-exact-audience" | "exact-identity-mismatch" | "required-temporal-claims-invalid";
}

export type IngressFallbackOidcVerification = Omit<IndependentOidcVerification, "verifier"> & {
  verifier: "observer-a-independent-jose" | IndependentOidcVerification["verifier"];
};

interface OidcSummary {
  tokenVerified: boolean;
  algorithmRs256: boolean;
  issuerVerified: boolean;
  audienceVerified: boolean;
  temporalClaimsVerified: boolean;
  exactClaimsVerified: boolean;
  oidcVerifications: IndependentOidcVerification[];
}

export interface ARecord {
  observedAt: string;
  runId: string;
  testId: typeof TEST_ID;
  caseId: string;
  correlationId: string;
  correlationMatched: boolean;
  method: string;
  rawTarget: string;
  targetForm: "absolute" | "network-path" | "other";
  exactSyntaxTarget: boolean;
  publicBodyMatched: boolean;
  bodyLength?: number;
  oidcHeaderCount: number;
  operationId?: string;
  terminalResponse: true;
  responseStatus: number;
}

export interface PRecord extends OidcSummary {
  observedAt: string;
  runId: string;
  testId: typeof TEST_ID;
  caseId: string;
  correlationId: string;
  correlationMatched: boolean;
  method: string;
  requestUrl: string;
  publicBodyMatched: boolean;
  operatorSecretBodyPresent: boolean;
  bodyLength?: number;
  oidcHeaderCount: number;
  oidcValueCount: number;
  forwardedMetadataValid: boolean;
  originalHost?: string;
  operationId?: string;
  terminalResponse: true;
  redirectAttempted: false;
  fetchAttempted: false;
  proxyAttempted: false;
  locationHeaderPresent: false;
  rawOidcTokenRetained: false;
  rawRequestBodyRetained: false;
  responseStatus: number;
}

export interface PSyntaxRecord {
  observedAt: string;
  runId: string;
  testId: typeof TEST_ID;
  caseId: string;
  correlationId: string;
  correlationMatched: boolean;
  method: string;
  rawTarget: string;
  targetForm: "absolute" | "network-path" | "other";
  exactSyntaxTarget: boolean;
  hostMatched: boolean;
  publicBodyMatched: boolean;
  bodyLength: number;
  oidcHeaderCount: number;
  forwardedMetadataAbsent: boolean;
  operationId?: string;
  terminalResponse: true;
  redirectAttempted: false;
  fetchAttempted: false;
  proxyAttempted: false;
  locationHeaderPresent: false;
  responseStatus: number;
}

export interface BRecord extends OidcSummary {
  observedAt: string;
  runId: string;
  testId: typeof TEST_ID;
  caseId: string;
  correlationId: string;
  correlationMatched: boolean;
  method: string;
  requestUrl: string;
  syntaxControl: boolean;
  attackCase: boolean;
  reachabilityObserved: true;
  publicBodyMatched: boolean;
  operatorSecretBodyPresent: boolean;
  bodyLength?: number;
  oidcHeaderCount: number;
  oidcValueCount: number;
  operatorSecretActionAttempted: boolean;
  operatorSecretActionAuthorized: boolean;
  operatorSecretActions: OperatorSecretAction[];
  operationId?: string;
  rawOidcTokenRetained: false;
  rawRequestBodyRetained: false;
  derivedSecretDigestRetained: false;
  terminalResponse: true;
  redirectAttempted: false;
  fetchAttempted: false;
  proxyAttempted: false;
  responseStatus: number;
}

export interface OperatorSecretAction {
  actionOrdinal: 1;
  verifier: "observer-b-independent-file-hmac";
  algorithm: "HMAC-SHA256";
  secretSource: "controller-file-mode-0600";
  secretFileMode: 384;
  hmacVerified: true;
  actionAuthorized: true;
  operationId: string;
  nonReflecting: true;
  rawSecretRetained: false;
  rawSecretReflected: false;
  responseBodyContainedSecret: false;
}

export interface DirectRecord {
  observedAt: string;
  runId: string;
  testId: typeof TEST_ID;
  caseId: string;
  correlationId: string;
  correlationMatched: boolean;
  method: string;
  requestUrl: string;
  publicBodyMatched: boolean;
  bodyLength: number;
  operationId?: string;
  responseStatus: number;
}

export interface HeaderCardinality {
  lines: number;
  values: number;
}

export interface IngressFallbackRecord {
  observedAt: string;
  role: "A" | "P" | "B";
  reason: "unmatched-a-route" | "unmatched-forward-path" | "unmatched-collect-path";
  runId: string;
  testId: typeof TEST_ID;
  caseId: string;
  correlationId: string;
  correlationMatched: true;
  method: string;
  requestTarget: string;
  host: string;
  bodyLength?: number;
  forwardedHeaderCounts: {
    host: HeaderCardinality;
    scheme: HeaderCardinality;
    port: HeaderCardinality;
    path: HeaderCardinality;
  };
  oidcHeaderCount: number;
  oidcValueCount: number;
  tokenVerified: boolean;
  algorithmRs256: boolean;
  issuerVerified: boolean;
  audienceVerified: boolean;
  temporalClaimsVerified: boolean;
  exactClaimsVerified: boolean;
  oidcVerifications: IngressFallbackOidcVerification[];
  operatorSecretBodyPresent: boolean;
  operatorSecretActionAttempted: boolean;
  operatorSecretActionAuthorized: boolean;
  actionOperationId?: string;
  operatorSecretActions: OperatorSecretAction[];
  receiptId: string;
  rawOidcTokenRetained: false;
  rawRequestBodyRetained: false;
  rawOperatorSecretRetained: false;
  rawOperatorSecretReflected: false;
  responseBodyContainedSecret: false;
  derivedSecretDigestRetained: false;
  terminalResponse: true;
  redirectAttempted: false;
  fetchAttempted: false;
  proxyAttempted: false;
  locationHeaderPresent: false;
  responseStatus: 404;
}

interface RunState {
  configuration: ReceiverConfiguration;
  aRecords: ARecord[];
  pSyntaxRecords: PSyntaxRecord[];
  pRecords: PRecord[];
  bRecords: BRecord[];
  directRecords: DirectRecord[];
  fallbackRecords: IngressFallbackRecord[];
}

export interface ReceiverOptions {
  adminKey: string;
  actionKey: string;
  aPublicOrigin: string;
  pPublicOrigin: string;
  bPublicOrigin: string;
  aPort?: number;
  pPort?: number;
  bPort?: number;
  host?: string;
}

export interface ReceiverHandle {
  aServer: Server;
  pServer: Server;
  bServer: Server;
  aPort: number;
  pPort: number;
  bPort: number;
  close(): Promise<void>;
}

const jwks = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function safeOrigin(value: string, name: string): URL {
  const parsed = new URL(value);
  if (
    value !== parsed.origin || parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.port ||
    parsed.pathname !== "/" || parsed.search || parsed.hash || isIP(parsed.hostname) !== 0 ||
    parsed.hostname !== parsed.hostname.toLowerCase()
  ) {
    throw new Error(`${name} must be an exact lower-case HTTPS origin without credentials, path, port, query, or fragment`);
  }
  return parsed;
}

function safeString(value: unknown, name: string, maximum = 1_024): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[\0\r\n]/u.test(value)) {
    throw new Error(`${name} must be a bounded non-empty string without control characters`);
  }
  return value;
}

function safeRunId(value: unknown): string {
  const runId = safeString(value, "runId", 128);
  if (!RUN_ID.test(runId)) throw new Error("runId has invalid characters");
  return runId;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], name: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${name} fields are not exact`);
  }
}

function equalText(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function keyBytes(value: string, name: string): Buffer {
  if (/[\0\r\n]/u.test(value) || Buffer.byteLength(value, "utf8") < 32) {
    throw new Error(`${name} must contain at least 32 safe UTF-8 bytes`);
  }
  return Buffer.from(value, "utf8");
}

function operatorSecret(body: Buffer): string | undefined {
  if (body.length === 0 || body.length > MAX_SECRET_BYTES || body.includes(0) || body.includes(10) || body.includes(13)) {
    return undefined;
  }
  const value = body.toString("utf8");
  return Buffer.from(value, "utf8").equals(body) ? value : undefined;
}

/** The only secret-derived value the receiver is permitted to retain. */
export function actionOperationId(actionKey: string, runId: string, caseId: AttackCaseId, secret: string): string {
  const key = keyBytes(actionKey, "actionKey");
  if (!RUN_ID.test(runId)) throw new Error("runId is invalid");
  if (!ATTACK_CASES.has(caseId)) throw new Error("caseId is not an SBX-037 attack case");
  const boundedSecret = safeString(secret, "operator secret", MAX_SECRET_BYTES);
  const digest = createHmac("sha256", key).update(`${runId}\n${caseId}\n${boundedSecret}`, "utf8").digest("base64url");
  const id = `rt37a_${digest.slice(0, 24)}`;
  if (!ACTION_OPERATION_ID.test(id)) throw new Error("action operation ID invariant failed");
  return id;
}

function adminAuthorized(request: IncomingMessage, expectedKey: string): boolean {
  const supplied = request.headers.authorization;
  if (typeof supplied !== "string" || !supplied.startsWith("Bearer ")) return false;
  const left = createHash("sha256").update(supplied.slice(7)).digest();
  const right = createHash("sha256").update(expectedKey).digest();
  return timingSafeEqual(left, right);
}

function rawHeaderCount(request: IncomingMessage, name: string): { lines: number; values: number } {
  let lines = 0;
  let values = 0;
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() !== name) continue;
    lines += 1;
    const value = request.rawHeaders[index + 1] ?? "";
    values += value.split(",").filter((entry) => entry.trim().length > 0).length;
  }
  return { lines, values };
}

function exactSingleRawHeader(request: IncomingMessage, name: string): string | undefined {
  const lowerName = name.toLowerCase();
  const counts = rawHeaderCount(request, lowerName);
  if (counts.lines !== 1 || counts.values !== 1) return undefined;
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === lowerName) return request.rawHeaders[index + 1];
  }
  return undefined;
}

function sanitizedIngressText(value: string | undefined, maximum: number): string {
  const bounded = (value ?? "missing").slice(0, maximum);
  return bounded.replace(/[^\x20-\x7e]/gu, "?");
}

function fallbackReceiptId(): string {
  const receiptId = `rt37f_${randomBytes(18).toString("base64url")}`;
  if (!FALLBACK_RECEIPT_ID.test(receiptId)) throw new Error("fallback receipt invariant failed");
  return receiptId;
}

function sendFallback(response: ServerResponse, role: "A" | "P" | "B", receiptId: string): void {
  response.writeHead(404, {
    "cache-control": "no-store",
    "content-length": "0",
    "x-sbx-role": role,
    "x-sbx037-fallback-receipt": receiptId,
  });
  response.end();
}

async function readBody(request: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk);
    length += bytes.length;
    if (length > MAX_BODY_BYTES) throw new Error("request body exceeded bound");
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const bytes = await readBody(request);
  if (bytes.length === 0) throw new Error("request body is empty");
  return JSON.parse(bytes.toString("utf8"));
}

function sendJson(response: ServerResponse, status: number, value: unknown): void {
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    "content-length": String(body.length),
  });
  response.end(body);
}

function sendEmpty(response: ServerResponse, status: number): void {
  response.writeHead(status, { "cache-control": "no-store", "content-length": "0" });
  response.end();
}

function validateConfiguration(value: unknown, a: URL, p: URL, b: URL): ReceiverConfiguration {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("configuration must be an object");
  const input = value as Record<string, unknown>;
  exactKeys(input, [
    "aOrigin", "bOrigin", "caseCorrelations", "caseOperationIds", "expectedActionOperationIds",
    "expectedProjectId", "expectedSandboxId", "expectedSandboxName", "expectedTeamId", "forwardAudience",
    "initialBOperationId", "originOperationId", "pOrigin", "runId", "syntaxOperationIds",
  ], "configuration");

  const runId = safeRunId(input.runId);
  const aOrigin = safeString(input.aOrigin, "aOrigin", 2_048);
  const pOrigin = safeString(input.pOrigin, "pOrigin", 2_048);
  const bOrigin = safeString(input.bOrigin, "bOrigin", 2_048);
  if (aOrigin !== a.origin || pOrigin !== p.origin || bOrigin !== b.origin) {
    throw new Error("configuration origins do not match the receiver origins");
  }
  const forwardAudience = safeString(input.forwardAudience, "forwardAudience", 2_048);
  const expectedAudience = new URL(`/v1/sbx037/forward/${encodeURIComponent(runId)}`, p).toString();
  if (forwardAudience !== expectedAudience) throw new Error("forwardAudience is not the exact P terminal URL");

  if (!input.caseCorrelations || typeof input.caseCorrelations !== "object" || Array.isArray(input.caseCorrelations)) {
    throw new Error("caseCorrelations must be an object");
  }
  const rawCorrelations = input.caseCorrelations as Record<string, unknown>;
  const correlationKeys = [
    "directBAllow", "directBPre", "directBPost", "originFormTerminal", "absoluteSyntaxControl",
    "networkPathSyntaxControl", "absolutePSyntaxControl", "networkPSyntaxControl", "absoluteTargetAttack",
    "networkPathTargetAttack",
  ] as const;
  exactKeys(rawCorrelations, correlationKeys, "caseCorrelations");
  const caseCorrelations = Object.fromEntries(correlationKeys.map((key) => [
    key,
    safeString(rawCorrelations[key], `caseCorrelations.${key}`, 128),
  ])) as unknown as CaseCorrelations;
  if (new Set(Object.values(caseCorrelations)).size !== correlationKeys.length) {
    throw new Error("case correlations must be unique");
  }

  if (!input.syntaxOperationIds || typeof input.syntaxOperationIds !== "object" || Array.isArray(input.syntaxOperationIds) ||
      !input.caseOperationIds || typeof input.caseOperationIds !== "object" || Array.isArray(input.caseOperationIds) ||
      !input.expectedActionOperationIds || typeof input.expectedActionOperationIds !== "object" ||
      Array.isArray(input.expectedActionOperationIds)) {
    throw new Error("operation ID maps must be objects");
  }
  const syntaxIds = input.syntaxOperationIds as Record<string, unknown>;
  const caseIds = input.caseOperationIds as Record<string, unknown>;
  const actionIds = input.expectedActionOperationIds as Record<string, unknown>;
  exactKeys(syntaxIds, [
    "absolutePSyntaxControl", "absoluteSyntaxControl", "networkPSyntaxControl", "networkPathSyntaxControl",
  ], "syntaxOperationIds");
  exactKeys(caseIds, ["absoluteTargetAttack", "networkPathTargetAttack"], "caseOperationIds");
  exactKeys(actionIds, ["absoluteTargetAttack", "networkPathTargetAttack"], "expectedActionOperationIds");
  const absoluteSyntax = safeString(syntaxIds.absoluteSyntaxControl, "syntaxOperationIds.absoluteSyntaxControl", 64);
  const networkSyntax = safeString(syntaxIds.networkPathSyntaxControl, "syntaxOperationIds.networkPathSyntaxControl", 64);
  const absolutePSyntax = safeString(syntaxIds.absolutePSyntaxControl, "syntaxOperationIds.absolutePSyntaxControl", 64);
  const networkPSyntax = safeString(syntaxIds.networkPSyntaxControl, "syntaxOperationIds.networkPSyntaxControl", 64);
  const absoluteCase = safeString(caseIds.absoluteTargetAttack, "caseOperationIds.absoluteTargetAttack", 64);
  const networkCase = safeString(caseIds.networkPathTargetAttack, "caseOperationIds.networkPathTargetAttack", 64);
  const absoluteAction = safeString(actionIds.absoluteTargetAttack, "expectedActionOperationIds.absoluteTargetAttack", 64);
  const networkAction = safeString(actionIds.networkPathTargetAttack, "expectedActionOperationIds.networkPathTargetAttack", 64);
  const initialBOperationId = safeString(input.initialBOperationId, "initialBOperationId", 64);
  const originOperationId = safeString(input.originOperationId, "originOperationId", 64);
  const publicIds = [
    initialBOperationId, originOperationId, absoluteSyntax, networkSyntax, absolutePSyntax, networkPSyntax,
    absoluteCase, networkCase,
  ];
  const protectedIds = [absoluteAction, networkAction];
  if (publicIds.some((id) => !RECEIPT_ID.test(id)) || protectedIds.some((id) => !ACTION_OPERATION_ID.test(id)) ||
      new Set([...publicIds, ...protectedIds]).size !== publicIds.length + protectedIds.length) {
    throw new Error("expected action operation IDs are invalid or not case-distinct");
  }

  return {
    runId,
    aOrigin,
    pOrigin,
    bOrigin,
    forwardAudience,
    expectedTeamId: safeString(input.expectedTeamId, "expectedTeamId", 128),
    expectedProjectId: safeString(input.expectedProjectId, "expectedProjectId", 128),
    expectedSandboxId: safeString(input.expectedSandboxId, "expectedSandboxId", 128),
    expectedSandboxName: safeString(input.expectedSandboxName, "expectedSandboxName", 256),
    caseCorrelations,
    initialBOperationId,
    originOperationId,
    syntaxOperationIds: {
      absoluteSyntaxControl: absoluteSyntax,
      networkPathSyntaxControl: networkSyntax,
      absolutePSyntaxControl: absolutePSyntax,
      networkPSyntaxControl: networkPSyntax,
    },
    caseOperationIds: { absoluteTargetAttack: absoluteCase, networkPathTargetAttack: networkCase },
    expectedActionOperationIds: { absoluteTargetAttack: absoluteAction, networkPathTargetAttack: networkAction },
  };
}

function expectedCorrelation(configuration: ReceiverConfiguration, caseId: string): string | undefined {
  const key = caseId === "direct-b-allow" ? "directBAllow"
    : caseId === "direct-b-pre" ? "directBPre"
      : caseId === "direct-b-post" ? "directBPost"
        : caseId === "origin-form-terminal" ? "originFormTerminal"
          : caseId === "absolute-syntax-control" ? "absoluteSyntaxControl"
            : caseId === "network-path-syntax-control" ? "networkPathSyntaxControl"
              : caseId === "absolute-p-syntax-control" ? "absolutePSyntaxControl"
                : caseId === "network-p-syntax-control" ? "networkPSyntaxControl"
                  : caseId === "absolute-target-attack" ? "absoluteTargetAttack"
                    : caseId === "network-path-target-attack" ? "networkPathTargetAttack"
                  : undefined;
  return key ? configuration.caseCorrelations[key] : undefined;
}

function exactFallbackContext(
  states: Map<string, RunState>,
  request: IncomingMessage,
): { state: RunState; caseId: string; correlationId: string } | undefined {
  const runId = exactSingleRawHeader(request, RUN_HEADER);
  const caseId = exactSingleRawHeader(request, CASE_HEADER);
  const correlationId = exactSingleRawHeader(request, CANARY_HEADER);
  if (!runId || !caseId || !correlationId) return undefined;
  const state = states.get(runId);
  if (!state || expectedCorrelation(state.configuration, caseId) !== correlationId) return undefined;
  return { state, caseId, correlationId };
}

function publicBody(configuration: ReceiverConfiguration, caseId: string): Buffer | undefined {
  const correlation = expectedCorrelation(configuration, caseId);
  return correlation ? Buffer.from(`public:${correlation}`, "utf8") : undefined;
}

function publicBodyMatches(body: Buffer, configuration: ReceiverConfiguration, caseId: string): boolean {
  const expected = publicBody(configuration, caseId);
  return expected !== undefined && body.equals(expected);
}

function requestTextHeader(request: IncomingMessage, name: string): string | undefined {
  const value = request.headers[name];
  return typeof value === "string" ? value : undefined;
}

function correlated(request: IncomingMessage, configuration: ReceiverConfiguration): {
  caseId: string;
  correlationId: string;
  matched: boolean;
} {
  const caseId = requestTextHeader(request, CASE_HEADER) ?? "missing";
  const correlationId = requestTextHeader(request, CANARY_HEADER) ?? "missing";
  const wantedCorrelation = expectedCorrelation(configuration, caseId);
  return {
    caseId,
    correlationId,
    matched: requestTextHeader(request, RUN_HEADER) === configuration.runId &&
      wantedCorrelation !== undefined && correlationId === wantedCorrelation,
  };
}

export function exactAudienceClaim(actual: JWTPayload["aud"], expected: string): boolean {
  return actual === expected || (Array.isArray(actual) && actual.length === 1 && actual[0] === expected);
}

function claim(payload: JWTPayload, name: string): string | undefined {
  const value = payload[name];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

const EMPTY_OIDC: OidcSummary = {
  tokenVerified: false,
  algorithmRs256: false,
  issuerVerified: false,
  audienceVerified: false,
  temporalClaimsVerified: false,
  exactClaimsVerified: false,
  oidcVerifications: [],
};

export interface VercelOidcIssuer {
  issuer: string;
  jwksUrl: string;
}

/** Mirrors the SDK's issuer-scoped JWKS derivation while rejecting unsafe URL components. */
export function vercelOidcIssuer(issuerValue: unknown): VercelOidcIssuer {
  const issuer = safeString(issuerValue, "OIDC issuer", 2_048);
  let issuerUrl: URL;
  try {
    issuerUrl = new URL(issuer);
  } catch {
    throw new Error("OIDC issuer is not a URL");
  }
  if (
    issuerUrl.protocol !== "https:" || issuerUrl.hostname !== VERCEL_OIDC_HOSTNAME || issuerUrl.username ||
    issuerUrl.password || issuerUrl.port || issuerUrl.search || issuerUrl.hash
  ) {
    throw new Error("OIDC issuer is not a safe Vercel issuer");
  }
  const jwksUrl = new URL(`${issuer.replace(/\/$/u, "")}/.well-known/jwks`).toString();
  const parsedJwks = new URL(jwksUrl);
  if (
    parsedJwks.protocol !== "https:" || parsedJwks.hostname !== VERCEL_OIDC_HOSTNAME || parsedJwks.username ||
    parsedJwks.password || parsedJwks.port || parsedJwks.search || parsedJwks.hash
  ) {
    throw new Error("derived JWKS URL is unsafe");
  }
  return { issuer, jwksUrl };
}

function getJwks(issuer: string, jwksUrl: string): ReturnType<typeof createRemoteJWKSet> {
  const cached = jwks.get(issuer);
  if (cached) return cached;
  const created = createRemoteJWKSet(new URL(jwksUrl), {
    timeoutDuration: 5_000,
    cooldownDuration: 30_000,
  });
  jwks.set(issuer, created);
  return created;
}

async function verifyPlatformToken(
  token: string,
  configuration: ReceiverConfiguration,
  verifier: IndependentOidcVerification["verifier"],
): Promise<OidcSummary> {
  let algorithmRs256 = false;
  let issuerVerified = false;
  try {
    algorithmRs256 = decodeProtectedHeader(token).alg === "RS256";
    if (!algorithmRs256) throw new Error("unexpected algorithm");
    const decoded = decodeJwt(token);
    const issuerScope = vercelOidcIssuer(decoded.iss);
    issuerVerified = true;
    const { payload } = await jwtVerify(token, getJwks(issuerScope.issuer, issuerScope.jwksUrl), {
      algorithms: ["RS256"],
      issuer: issuerScope.issuer,
      audience: configuration.forwardAudience,
      clockTolerance: 60,
    });
    const audienceVerified = exactAudienceClaim(payload.aud, configuration.forwardAudience);
    const now = Math.floor(Date.now() / 1_000);
    const temporalClaimsVerified = typeof payload.iat === "number" && typeof payload.exp === "number" &&
      payload.exp > payload.iat && payload.iat <= now + 60 && payload.exp >= now - 60;
    const sandboxId = claim(payload, "sandbox_id") ?? "missing";
    const identity: VerifiedIdentity = {
      teamId: claim(payload, "team_id") ?? "missing",
      projectId: claim(payload, "project_id") ?? "missing",
      sandboxId,
      sessionId: sandboxId,
      sandboxName: claim(payload, "sandbox_name") ?? "missing",
    };
    const exactClaimsVerified = audienceVerified && identity.teamId === configuration.expectedTeamId &&
      identity.projectId === configuration.expectedProjectId && identity.sandboxId === configuration.expectedSandboxId &&
      identity.sessionId === configuration.expectedSandboxId &&
      identity.sandboxName === configuration.expectedSandboxName;
    const verification: IndependentOidcVerification = {
      tokenOrdinal: 1,
      verifier,
      signatureVerified: true,
      algorithm: "RS256",
      issuer: issuerScope.issuer,
      jwksUrl: issuerScope.jwksUrl,
      audience: audienceVerified ? configuration.forwardAudience : "non-exact-audience",
      temporalClaimsVerified,
      exactClaimsVerified,
      identity,
      rawTokenRetained: false,
      ...(!audienceVerified
        ? { verificationError: "non-exact-audience" as const }
        : !exactClaimsVerified
          ? { verificationError: "exact-identity-mismatch" as const }
          : !temporalClaimsVerified
            ? { verificationError: "required-temporal-claims-invalid" as const }
            : {}),
    };
    return {
      tokenVerified: audienceVerified && temporalClaimsVerified && exactClaimsVerified,
      algorithmRs256,
      issuerVerified,
      audienceVerified,
      temporalClaimsVerified,
      exactClaimsVerified,
      oidcVerifications: [verification],
    };
  } catch {
    return { ...EMPTY_OIDC, algorithmRs256, issuerVerified, oidcVerifications: [] };
  }
}

async function recordIngressFallback(input: {
  state: RunState;
  request: IncomingMessage;
  response: ServerResponse;
  role: "A" | "P" | "B";
  reason: IngressFallbackRecord["reason"];
  caseId: string;
  correlationId: string;
  actionKey: string;
}): Promise<void> {
  const { state, request, response, role, reason, caseId, correlationId } = input;
  const body = await readBody(request);
  const bodyLength = body.length;
  const oidcCount = rawHeaderCount(request, OIDC_HEADER);
  let token = oidcCount.lines === 1 && oidcCount.values === 1
    ? exactSingleRawHeader(request, OIDC_HEADER)
    : undefined;
  let secret = role === "B" && isAttackCase(caseId) ? operatorSecret(body) : undefined;
  const operatorSecretBodyPresent = secret !== undefined;
  const expectedActionOperationId = caseId === "absolute-target-attack"
    ? state.configuration.expectedActionOperationIds.absoluteTargetAttack
    : caseId === "network-path-target-attack"
      ? state.configuration.expectedActionOperationIds.networkPathTargetAttack
      : undefined;
  let actionOperationIdValue: string | undefined;
  if (role === "B" && isAttackCase(caseId) && secret && expectedActionOperationId) {
    const derived = actionOperationId(input.actionKey, state.configuration.runId, caseId, secret);
    if (equalText(derived, expectedActionOperationId)) actionOperationIdValue = expectedActionOperationId;
  }
  const operatorSecretActions: OperatorSecretAction[] = actionOperationIdValue
    ? [{
        actionOrdinal: 1,
        verifier: "observer-b-independent-file-hmac",
        algorithm: "HMAC-SHA256",
        secretSource: "controller-file-mode-0600",
        secretFileMode: 384,
        hmacVerified: true,
        actionAuthorized: true,
        operationId: actionOperationIdValue,
        nonReflecting: true,
        rawSecretRetained: false,
        rawSecretReflected: false,
        responseBodyContainedSecret: false,
      }]
    : [];
  body.fill(0);
  secret = undefined;
  const verifier: IndependentOidcVerification["verifier"] = role === "B"
    ? "observer-b-independent-jose"
    : "sink-p-independent-jose";
  const verifiedOidc = token
    ? await verifyPlatformToken(token, state.configuration, verifier)
    : EMPTY_OIDC;
  const oidc: Omit<OidcSummary, "oidcVerifications"> & {
    oidcVerifications: IngressFallbackOidcVerification[];
  } = role === "A"
    ? {
        ...verifiedOidc,
        oidcVerifications: verifiedOidc.oidcVerifications.map((verification) => ({
          ...verification,
          verifier: "observer-a-independent-jose" as const,
        })),
      }
    : verifiedOidc;
  token = undefined;
  const receiptId = fallbackReceiptId();
  const record: IngressFallbackRecord = {
    observedAt: new Date().toISOString(),
    role,
    reason,
    runId: state.configuration.runId,
    testId: TEST_ID,
    caseId,
    correlationId,
    correlationMatched: true,
    method: request.method ?? "missing",
    requestTarget: sanitizedIngressText(request.url, 2_048),
    host: sanitizedIngressText(requestTextHeader(request, "host"), 512),
    ...(!isAttackCase(caseId) ? { bodyLength } : {}),
    forwardedHeaderCounts: {
      host: rawHeaderCount(request, FORWARDED_HOST_HEADER),
      scheme: rawHeaderCount(request, FORWARDED_SCHEME_HEADER),
      port: rawHeaderCount(request, FORWARDED_PORT_HEADER),
      path: rawHeaderCount(request, FORWARDED_PATH_HEADER),
    },
    oidcHeaderCount: oidcCount.lines,
    oidcValueCount: oidcCount.values,
    operatorSecretBodyPresent,
    operatorSecretActionAttempted: role === "B" && isAttackCase(caseId) && operatorSecretBodyPresent,
    operatorSecretActionAuthorized: actionOperationIdValue !== undefined,
    ...(actionOperationIdValue ? { actionOperationId: actionOperationIdValue } : {}),
    operatorSecretActions,
    receiptId,
    ...oidc,
    rawOidcTokenRetained: false,
    rawRequestBodyRetained: false,
    rawOperatorSecretRetained: false,
    rawOperatorSecretReflected: false,
    responseBodyContainedSecret: false,
    derivedSecretDigestRetained: false,
    terminalResponse: true,
    redirectAttempted: false,
    fetchAttempted: false,
    proxyAttempted: false,
    locationHeaderPresent: false,
    responseStatus: 404,
  };
  if (state.fallbackRecords.length < MAX_FALLBACK_RECORDS_PER_RUN) state.fallbackRecords.push(record);
  sendFallback(response, role, receiptId);
}

function runIdFromExactPath(requestUrl: string | undefined, origin: URL, prefix: string): string | undefined {
  let url: URL;
  try {
    url = new URL(requestUrl ?? "/", origin);
  } catch {
    return undefined;
  }
  if (url.origin !== origin.origin || url.search || url.hash || !url.pathname.startsWith(prefix)) return undefined;
  const encoded = url.pathname.slice(prefix.length);
  if (!encoded || encoded.includes("/")) return undefined;
  let runId: string;
  try {
    runId = decodeURIComponent(encoded);
  } catch {
    return undefined;
  }
  return RUN_ID.test(runId) && url.pathname === `${prefix}${encodeURIComponent(runId)}` ? runId : undefined;
}

function forwardedGuestPath(configuration: ReceiverConfiguration, caseId: string): string | undefined {
  return caseId === "origin-form-terminal"
    ? `/v1/sbx037/origin/${encodeURIComponent(configuration.runId)}`
    : isAttackCase(caseId)
      ? `/v1/sbx037/collect/${encodeURIComponent(configuration.runId)}`
      : undefined;
}

function exactAppendedForwardUrl(
  requestUrl: string | undefined,
  publicOrigin: URL,
  configuration: ReceiverConfiguration,
  forwardedPath: string,
): boolean {
  let received: URL;
  try {
    received = new URL(requestUrl ?? "/", publicOrigin);
  } catch {
    return false;
  }
  const base = new URL(configuration.forwardAudience);
  return received.origin === publicOrigin.origin && !received.search && !received.hash &&
    received.pathname === `${base.pathname}${forwardedPath}`;
}

function exactSingleHeader(request: IncomingMessage, name: string, expected: string): boolean {
  const counts = rawHeaderCount(request, name);
  return counts.lines === 1 && counts.values === 1 && requestTextHeader(request, name) === expected;
}

function exactForwardedMetadata(
  request: IncomingMessage,
  configuration: ReceiverConfiguration,
  forwardedPath: string,
): boolean {
  const a = new URL(configuration.aOrigin);
  return exactSingleHeader(request, FORWARDED_HOST_HEADER, a.host) &&
    exactSingleHeader(request, FORWARDED_SCHEME_HEADER, "https") &&
    exactSingleHeader(request, FORWARDED_PORT_HEADER, "443") &&
    exactSingleHeader(request, FORWARDED_PATH_HEADER, forwardedPath);
}

function stateByHeader(states: Map<string, RunState>, request: IncomingMessage): RunState | undefined {
  const runId = requestTextHeader(request, RUN_HEADER);
  return runId ? states.get(runId) : undefined;
}

function stateReadback(state: RunState): object {
  return {
    configured: true,
    aRecords: state.aRecords,
    pSyntaxRecords: state.pSyntaxRecords,
    pRecords: state.pRecords,
    bRecords: state.bRecords,
    directRecords: state.directRecords,
    fallbackRecords: state.fallbackRecords,
    terminalInvariant: {
      redirectsIssued: 0,
      locationHeadersIssued: 0,
      applicationFetches: 0,
      applicationProxyAttempts: 0,
      rawOidcTokensRetained: false,
      rawRequestBodiesRetained: false,
      failedSecretDerivationsRetained: false,
    },
  };
}

async function listen(server: Server, port: number, host: string): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("receiver did not bind a TCP address");
  return address.port;
}

async function closeServer(server: Server): Promise<void> {
  if (!server.listening) return;
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

function isSyntaxCase(value: string): value is SyntaxCaseId {
  return SYNTAX_CASES.has(value as SyntaxCaseId);
}

function isPSyntaxCase(value: string): value is PSyntaxCaseId {
  return P_SYNTAX_CASES.has(value as PSyntaxCaseId);
}

function isAttackCase(value: string): value is AttackCaseId {
  return ATTACK_CASES.has(value as AttackCaseId);
}

function isForwardCase(value: string): value is ForwardCaseId {
  return FORWARD_CASES.has(value as ForwardCaseId);
}

function isDirectCase(value: string): value is DirectCaseId {
  return DIRECT_CASES.has(value as DirectCaseId);
}

function caseOperationId(configuration: ReceiverConfiguration, caseId: string): string | undefined {
  return caseId === "absolute-syntax-control"
    ? configuration.syntaxOperationIds.absoluteSyntaxControl
    : caseId === "network-path-syntax-control"
      ? configuration.syntaxOperationIds.networkPathSyntaxControl
      : caseId === "absolute-target-attack"
        ? configuration.caseOperationIds.absoluteTargetAttack
        : caseId === "network-path-target-attack"
          ? configuration.caseOperationIds.networkPathTargetAttack
          : caseId === "absolute-p-syntax-control"
            ? configuration.syntaxOperationIds.absolutePSyntaxControl
            : caseId === "network-p-syntax-control"
              ? configuration.syntaxOperationIds.networkPSyntaxControl
              : undefined;
}

export async function createSbx037Receiver(options: ReceiverOptions): Promise<ReceiverHandle> {
  keyBytes(options.adminKey, "adminKey");
  keyBytes(options.actionKey, "actionKey");
  if (equalText(options.adminKey, options.actionKey)) throw new Error("adminKey and actionKey must be distinct");
  const aOrigin = safeOrigin(options.aPublicOrigin, "aPublicOrigin");
  const pOrigin = safeOrigin(options.pPublicOrigin, "pPublicOrigin");
  const bOrigin = safeOrigin(options.bPublicOrigin, "bPublicOrigin");
  if (new Set([aOrigin.origin, pOrigin.origin, bOrigin.origin]).size !== 3) {
    throw new Error("A, P, and B origins must be distinct");
  }
  const host = options.host ?? "127.0.0.1";
  if (host !== "127.0.0.1" && host !== "::1") throw new Error("receiver host must be loopback");
  const states = new Map<string, RunState>();

  const aServer = createServer(async (request, response) => {
    response.setHeader("x-sbx-role", "A");
    try {
      if (request.method === "GET" && request.url === "/healthz") {
        return sendJson(response, 200, { ok: true, role: "A" });
      }
      const fallbackContext = exactFallbackContext(states, request);
      const state = stateByHeader(states, request);
      if (!state) return sendJson(response, 404, { error: "unknown run" });
      const correlation = correlated(request, state.configuration);
      if (fallbackContext && !isSyntaxCase(fallbackContext.caseId)) {
        return await recordIngressFallback({
          ...fallbackContext,
          request,
          response,
          role: "A",
          reason: "unmatched-a-route",
          actionKey: options.actionKey,
        });
      }
      const body = await readBody(request);
      const expectedPath = `/v1/sbx037/collect/${encodeURIComponent(state.configuration.runId)}`;
      const absoluteTarget = `${state.configuration.bOrigin}${expectedPath}`;
      const networkTarget = `//${new URL(state.configuration.bOrigin).host}${expectedPath}`;
      const exactSyntaxTarget = correlation.caseId === "absolute-syntax-control"
        ? request.url === absoluteTarget
        : correlation.caseId === "network-path-syntax-control"
          ? request.url === networkTarget
          : false;
      const targetForm = request.url?.startsWith("https://")
        ? "absolute" as const
        : request.url?.startsWith("//")
          ? "network-path" as const
          : "other" as const;
      const oidcCount = rawHeaderCount(request, OIDC_HEADER);
      const publicBodyMatched = publicBodyMatches(body, state.configuration, correlation.caseId);
      const bodyLength = body.length;
      body.fill(0);
      const valid = request.method === "POST" && isSyntaxCase(correlation.caseId) && correlation.matched &&
        exactSyntaxTarget && publicBodyMatched && oidcCount.lines === 0;
      const operationId = valid ? caseOperationId(state.configuration, correlation.caseId) : undefined;
      state.aRecords.push({
        observedAt: new Date().toISOString(),
        runId: state.configuration.runId,
        testId: TEST_ID,
        caseId: correlation.caseId,
        correlationId: correlation.correlationId,
        correlationMatched: correlation.matched,
        method: request.method ?? "missing",
        rawTarget: (request.url ?? "/").slice(0, 2_048),
        targetForm,
        exactSyntaxTarget,
        publicBodyMatched,
        bodyLength,
        oidcHeaderCount: oidcCount.lines,
        ...(operationId ? { operationId } : {}),
        terminalResponse: true,
        responseStatus: valid ? 202 : 400,
      });
      return operationId
        ? sendJson(response, 202, { operationId })
        : sendJson(response, 400, { error: "invalid syntax control" });
    } catch {
      return response.headersSent ? response.destroy() : sendJson(response, 400, { error: "invalid request" });
    }
  });

  const pServer = createServer(async (request, response) => {
    response.setHeader("x-sbx-role", "P");
    try {
      if (request.method === "GET" && request.url === "/healthz") {
        return sendJson(response, 200, { ok: true, role: "P" });
      }
      const pSyntaxState = stateByHeader(states, request);
      const pSyntaxCorrelation = pSyntaxState ? correlated(request, pSyntaxState.configuration) : undefined;
      if (pSyntaxState && pSyntaxCorrelation && isPSyntaxCase(pSyntaxCorrelation.caseId)) {
        const body = await readBody(request);
        const collectPath = `/v1/sbx037/collect/${encodeURIComponent(pSyntaxState.configuration.runId)}`;
        const absoluteTarget = `${pSyntaxState.configuration.bOrigin}${collectPath}`;
        const networkTarget = `//${new URL(pSyntaxState.configuration.bOrigin).host}${collectPath}`;
        const exactSyntaxTarget = pSyntaxCorrelation.caseId === "absolute-p-syntax-control"
          ? request.url === absoluteTarget
          : request.url === networkTarget;
        const targetForm = request.url?.startsWith("https://")
          ? "absolute" as const
          : request.url?.startsWith("//")
            ? "network-path" as const
            : "other" as const;
        const oidcCount = rawHeaderCount(request, OIDC_HEADER);
        const hostMatched = exactSingleHeader(request, "host", new URL(pSyntaxState.configuration.pOrigin).host);
        const forwardedMetadataAbsent = [
          FORWARDED_HOST_HEADER,
          FORWARDED_SCHEME_HEADER,
          FORWARDED_PORT_HEADER,
          FORWARDED_PATH_HEADER,
        ].every((name) => rawHeaderCount(request, name).lines === 0);
        const publicBodyMatched = publicBodyMatches(body, pSyntaxState.configuration, pSyntaxCorrelation.caseId);
        const bodyLength = body.length;
        body.fill(0);
        const valid = request.method === "POST" && pSyntaxCorrelation.matched && exactSyntaxTarget && hostMatched &&
          publicBodyMatched && oidcCount.lines === 0 && forwardedMetadataAbsent;
        const operationId = valid
          ? caseOperationId(pSyntaxState.configuration, pSyntaxCorrelation.caseId)
          : undefined;
        pSyntaxState.pSyntaxRecords.push({
          observedAt: new Date().toISOString(),
          runId: pSyntaxState.configuration.runId,
          testId: TEST_ID,
          caseId: pSyntaxCorrelation.caseId,
          correlationId: pSyntaxCorrelation.correlationId,
          correlationMatched: pSyntaxCorrelation.matched,
          method: request.method ?? "missing",
          rawTarget: (request.url ?? "/").slice(0, 2_048),
          targetForm,
          exactSyntaxTarget,
          hostMatched,
          publicBodyMatched,
          bodyLength,
          oidcHeaderCount: oidcCount.lines,
          forwardedMetadataAbsent,
          ...(operationId ? { operationId } : {}),
          terminalResponse: true,
          redirectAttempted: false,
          fetchAttempted: false,
          proxyAttempted: false,
          locationHeaderPresent: false,
          responseStatus: valid ? 202 : 400,
        });
        return operationId
          ? sendJson(response, 202, { operationId })
          : sendJson(response, 400, { error: "invalid P syntax control" });
      }
      const adminRunId = runIdFromExactPath(request.url, pOrigin, "/v1/sbx037/admin/runs/");
      if (adminRunId) {
        if (!adminAuthorized(request, options.adminKey)) return sendJson(response, 401, { error: "unauthorized" });
        if (request.method === "POST") {
          if (states.has(adminRunId)) return sendJson(response, 409, { error: "already configured" });
          if (states.size >= MAX_STATES) return sendJson(response, 429, { error: "receiver state limit reached" });
          const configuration = validateConfiguration(await readJson(request), aOrigin, pOrigin, bOrigin);
          if (configuration.runId !== adminRunId) return sendJson(response, 400, { error: "run mismatch" });
          states.set(adminRunId, {
            configuration,
            aRecords: [],
            pSyntaxRecords: [],
            pRecords: [],
            bRecords: [],
            directRecords: [],
            fallbackRecords: [],
          });
          return sendJson(response, 201, { configured: true });
        }
        if (request.method === "GET") {
          const state = states.get(adminRunId);
          return state ? sendJson(response, 200, stateReadback(state)) : sendJson(response, 404, { configured: false });
        }
        if (request.method === "DELETE") {
          const deleted = states.delete(adminRunId);
          return sendJson(response, deleted ? 200 : 404, { deleted });
        }
        return sendJson(response, 405, { error: "method not allowed" });
      }

      const fallbackContext = exactFallbackContext(states, request);
      const state = stateByHeader(states, request);
      if (!state) {
        if (fallbackContext) {
          return await recordIngressFallback({
            ...fallbackContext,
            request,
            response,
            role: "P",
            reason: "unmatched-forward-path",
            actionKey: options.actionKey,
          });
        }
        return sendJson(response, 404, { error: "not found" });
      }
      const correlation = correlated(request, state.configuration);
      const forwardedPath = forwardedGuestPath(state.configuration, correlation.caseId);
      if (!forwardedPath || !exactAppendedForwardUrl(request.url, pOrigin, state.configuration, forwardedPath)) {
        if (fallbackContext) {
          return await recordIngressFallback({
            ...fallbackContext,
            request,
            response,
            role: "P",
            reason: "unmatched-forward-path",
            actionKey: options.actionKey,
          });
        }
        return sendJson(response, 404, { error: "not found" });
      }
      const runId = state.configuration.runId;
      const forwardedMetadataValid = exactForwardedMetadata(request, state.configuration, forwardedPath);
      const body = await readBody(request);
      const oidcCount = rawHeaderCount(request, OIDC_HEADER);
      const token = oidcCount.lines === 1 && oidcCount.values === 1
        ? requestTextHeader(request, OIDC_HEADER)
        : undefined;
      const publicBodyMatched = publicBodyMatches(body, state.configuration, correlation.caseId);
      const secretBodyPresent = operatorSecret(body) !== undefined;
      const bodyLength = body.length;
      const bodyMatchedCase = correlation.caseId === "origin-form-terminal"
        ? publicBodyMatched
        : isAttackCase(correlation.caseId) && secretBodyPresent;
      const validEnvelope = request.method === "POST" && correlation.matched && forwardedMetadataValid &&
        isForwardCase(correlation.caseId) && bodyMatchedCase;
      body.fill(0);
      const oidc = token && forwardedMetadataValid
        ? await verifyPlatformToken(token, state.configuration, "sink-p-independent-jose")
        : EMPTY_OIDC;
      const accepted = validEnvelope && oidc.tokenVerified;
      const operationId = accepted
        ? correlation.caseId === "origin-form-terminal"
          ? state.configuration.originOperationId
          : caseOperationId(state.configuration, correlation.caseId)
        : undefined;
      const status = !validEnvelope ? 400 : accepted ? 202 : 403;
      const originalHost = forwardedMetadataValid ? new URL(state.configuration.aOrigin).host : undefined;
      state.pRecords.push({
        observedAt: new Date().toISOString(),
        runId,
        testId: TEST_ID,
        caseId: correlation.caseId,
        correlationId: correlation.correlationId,
        correlationMatched: correlation.matched,
        method: request.method ?? "missing",
        requestUrl: new URL(request.url ?? "/", pOrigin).toString(),
        publicBodyMatched,
        operatorSecretBodyPresent: isAttackCase(correlation.caseId) && secretBodyPresent,
        ...(correlation.caseId === "origin-form-terminal" ? { bodyLength } : {}),
        oidcHeaderCount: oidcCount.lines,
        oidcValueCount: oidcCount.values,
        forwardedMetadataValid,
        ...(originalHost ? { originalHost } : {}),
        ...oidc,
        ...(operationId ? { operationId } : {}),
        terminalResponse: true,
        redirectAttempted: false,
        fetchAttempted: false,
        proxyAttempted: false,
        locationHeaderPresent: false,
        rawOidcTokenRetained: false,
        rawRequestBodyRetained: false,
        responseStatus: status,
      });
      return operationId
        ? sendJson(response, 202, { accepted: true, operationId })
        : sendJson(response, status, { accepted: false });
    } catch {
      return response.headersSent ? response.destroy() : sendJson(response, 400, { error: "invalid request" });
    }
  });

  const bServer = createServer(async (request, response) => {
    response.setHeader("x-sbx-role", "B");
    try {
      if (request.method === "GET" && request.url === "/healthz") {
        return sendJson(response, 200, { ok: true, role: "B" });
      }
      const fallbackContext = exactFallbackContext(states, request);
      const directRunId = runIdFromExactPath(request.url, bOrigin, "/v1/sbx037/direct/");
      if (directRunId) {
        const state = states.get(directRunId);
        if (!state) {
          if (fallbackContext) {
            return await recordIngressFallback({
              ...fallbackContext,
              request,
              response,
              role: "B",
              reason: "unmatched-collect-path",
              actionKey: options.actionKey,
            });
          }
          return sendJson(response, 404, { error: "not configured" });
        }
        const correlation = correlated(request, state.configuration);
        if (!isDirectCase(correlation.caseId)) {
          if (fallbackContext) {
            return await recordIngressFallback({
              ...fallbackContext,
              request,
              response,
              role: "B",
              reason: "unmatched-collect-path",
              actionKey: options.actionKey,
            });
          }
          return sendJson(response, 400, { error: "invalid direct case" });
        }
        const body = await readBody(request);
        const valid = request.method === "POST" && isDirectCase(correlation.caseId) && correlation.matched &&
          publicBodyMatches(body, state.configuration, correlation.caseId);
        const operationId = valid && correlation.caseId === "direct-b-allow"
          ? state.configuration.initialBOperationId
          : undefined;
        const status = operationId ? 202 : valid ? 409 : 400;
        const bodyLength = body.length;
        const publicBodyMatched = publicBodyMatches(body, state.configuration, correlation.caseId);
        body.fill(0);
        state.directRecords.push({
          observedAt: new Date().toISOString(),
          runId: directRunId,
          testId: TEST_ID,
          caseId: correlation.caseId,
          correlationId: correlation.correlationId,
          correlationMatched: correlation.matched,
          method: request.method ?? "missing",
          requestUrl: new URL(request.url ?? "/", bOrigin).toString(),
          publicBodyMatched,
          bodyLength,
          ...(operationId ? { operationId } : {}),
          responseStatus: status,
        });
        return operationId
          ? sendJson(response, 202, { operationId })
          : sendJson(response, status, { error: valid ? "blocked direct control reached B" : "invalid direct control" });
      }

      const runId = runIdFromExactPath(request.url, bOrigin, "/v1/sbx037/collect/");
      const state = runId ? states.get(runId) : undefined;
      if (!runId || !state) {
        if (fallbackContext) {
          return await recordIngressFallback({
            ...fallbackContext,
            request,
            response,
            role: "B",
            reason: "unmatched-collect-path",
            actionKey: options.actionKey,
          });
        }
        return sendJson(response, 404, { error: "not found" });
      }
      const correlation = correlated(request, state.configuration);
      const syntaxControl = isSyntaxCase(correlation.caseId);
      const attackCase = isAttackCase(correlation.caseId);
      if (!syntaxControl && !attackCase) {
        if (fallbackContext) {
          return await recordIngressFallback({
            ...fallbackContext,
            request,
            response,
            role: "B",
            reason: "unmatched-collect-path",
            actionKey: options.actionKey,
          });
        }
        return sendJson(response, 400, { error: "invalid collect case" });
      }
      const body = await readBody(request);
      const oidcCount = rawHeaderCount(request, OIDC_HEADER);
      const token = oidcCount.lines === 1 && oidcCount.values === 1
        ? requestTextHeader(request, OIDC_HEADER)
        : undefined;
      let secret = attackCase ? operatorSecret(body) : undefined;
      const secretBodyPresent = secret !== undefined;
      const expectedOperationId = correlation.caseId === "absolute-target-attack"
        ? state.configuration.expectedActionOperationIds.absoluteTargetAttack
        : correlation.caseId === "network-path-target-attack"
          ? state.configuration.expectedActionOperationIds.networkPathTargetAttack
          : undefined;
      let authorizedOperationId: string | undefined;
      if (isAttackCase(correlation.caseId) && correlation.matched && secret && expectedOperationId) {
        const derived = actionOperationId(options.actionKey, runId, correlation.caseId, secret);
        if (equalText(derived, expectedOperationId)) authorizedOperationId = expectedOperationId;
      }
      const actionAuthorized = authorizedOperationId !== undefined;
      const operatorSecretActions: OperatorSecretAction[] = authorizedOperationId && isAttackCase(correlation.caseId)
        ? [{
            actionOrdinal: 1,
            verifier: "observer-b-independent-file-hmac",
            algorithm: "HMAC-SHA256",
            secretSource: "controller-file-mode-0600",
            secretFileMode: 384,
            hmacVerified: true,
            actionAuthorized: true,
            operationId: authorizedOperationId,
            nonReflecting: true,
            rawSecretRetained: false,
            rawSecretReflected: false,
            responseBodyContainedSecret: false,
          }]
        : [];
      const publicBodyMatched = publicBodyMatches(body, state.configuration, correlation.caseId);
      const bodyLength = body.length;
      const validSyntaxControl = syntaxControl && correlation.matched && request.method === "POST" &&
        publicBodyMatched && oidcCount.lines === 0;
      const validAttackEnvelope = attackCase && correlation.matched && request.method === "POST" && secret !== undefined;
      const operationId = validSyntaxControl || validAttackEnvelope
        ? caseOperationId(state.configuration, correlation.caseId)
        : undefined;
      const status = operationId ? 202 : 400;
      body.fill(0);
      secret = undefined;
      const oidc = attackCase && token
        ? await verifyPlatformToken(token, state.configuration, "observer-b-independent-jose")
        : EMPTY_OIDC;
      state.bRecords.push({
        observedAt: new Date().toISOString(),
        runId,
        testId: TEST_ID,
        caseId: correlation.caseId,
        correlationId: correlation.correlationId,
        correlationMatched: correlation.matched,
        method: request.method ?? "missing",
        requestUrl: new URL(request.url ?? "/", bOrigin).toString(),
        syntaxControl,
        attackCase,
        reachabilityObserved: true,
        publicBodyMatched,
        operatorSecretBodyPresent: attackCase && secretBodyPresent,
        ...(syntaxControl ? { bodyLength } : {}),
        oidcHeaderCount: oidcCount.lines,
        oidcValueCount: oidcCount.values,
        operatorSecretActionAttempted: attackCase && secretBodyPresent,
        operatorSecretActionAuthorized: actionAuthorized,
        operatorSecretActions,
        ...(operationId ? { operationId } : {}),
        ...oidc,
        rawOidcTokenRetained: false,
        rawRequestBodyRetained: false,
        derivedSecretDigestRetained: false,
        terminalResponse: true,
        redirectAttempted: false,
        fetchAttempted: false,
        proxyAttempted: false,
        responseStatus: status,
      });
      return operationId ? sendJson(response, 202, { operationId }) : sendEmpty(response, status);
    } catch {
      return response.headersSent ? response.destroy() : sendJson(response, 400, { error: "invalid request" });
    }
  });

  let aPort = 0;
  let pPort = 0;
  let bPort = 0;
  try {
    aPort = await listen(aServer, options.aPort ?? 0, host);
    pPort = await listen(pServer, options.pPort ?? 0, host);
    bPort = await listen(bServer, options.bPort ?? 0, host);
  } catch (error) {
    await Promise.allSettled([aServer, pServer, bServer].map(closeServer));
    throw error;
  }
  return {
    aServer,
    pServer,
    bServer,
    aPort,
    pPort,
    bPort,
    async close() {
      await Promise.all([closeServer(aServer), closeServer(pServer), closeServer(bServer)]);
    },
  };
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function environmentPort(name: string, fallback: number): number {
  const value = Number(process.env[name] ?? String(fallback));
  if (!Number.isInteger(value) || value < 1 || value > 65_535) throw new Error(`${name} is invalid`);
  return value;
}

async function cli(): Promise<void> {
  const receiver = await createSbx037Receiver({
    adminKey: requiredEnvironment("SBX037_ADMIN_KEY"),
    actionKey: requiredEnvironment("SBX037_ACTION_KEY"),
    aPublicOrigin: requiredEnvironment("SBX037_A_PUBLIC_ORIGIN"),
    pPublicOrigin: requiredEnvironment("SBX037_P_PUBLIC_ORIGIN"),
    bPublicOrigin: requiredEnvironment("SBX037_B_PUBLIC_ORIGIN"),
    aPort: environmentPort("SBX037_A_PORT", 43137),
    pPort: environmentPort("SBX037_P_PORT", 43138),
    bPort: environmentPort("SBX037_B_PORT", 43139),
    host: process.env.SBX037_LISTEN_HOST ?? "127.0.0.1",
  });
  process.stdout.write(`${JSON.stringify({
    ready: true,
    aPort: receiver.aPort,
    pPort: receiver.pPort,
    bPort: receiver.bPort,
  })}\n`);
  const shutdown = async (): Promise<void> => {
    await receiver.close();
    process.exit(0);
  };
  process.once("SIGINT", () => { void shutdown(); });
  process.once("SIGTERM", () => { void shutdown(); });
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  cli().catch((error) => {
    process.stderr.write(`${String(error instanceof Error ? error.message : error).slice(0, 512)}\n`);
    process.exitCode = 1;
  });
}
