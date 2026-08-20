import { randomUUID } from "node:crypto";
import { link, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { acquireSbx051LiveLock, type Sbx051HeldLock } from "./live-lock.js";

export type { Sbx051HeldLock } from "./live-lock.js";

export const SBX051_TEST_ID = "SBX-051-INTERACTIVE-TOKEN-BINDING" as const;
export const SBX051_ALIAS = "swve@wearehackerone.com" as const;
export const SBX051_TEAM = "team_n98ERpVwV7HqmWRudAyK8sXQ" as const;
export const SBX051_PROJECT = "prj_CyyVykdN06Nrkla6KidZcecLgbCa" as const;
export const SBX051_SCOPE_CONFIRMATION =
  "I_AUTHORIZE_ONE_BOUNDED_SBX051_INTERACTIVE_TOKEN_SESSION_BINDING_TEST" as const;
export const SBX051_ARTIFACTS_DIRECTORY = fileURLToPath(new URL("../../artifacts", import.meta.url));
export const SBX051_LIVE_LOCK = resolve(SBX051_ARTIFACTS_DIRECTORY, "SBX-051-live-active.lock");

export const SBX051_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SESSION_ID = /^sbx_[A-Za-z0-9_-]{8,192}$/u;
const LOCAL_TLS_TRUST_ENVIRONMENT_NAMES = [
  "NODE_EXTRA_CA_CERTS",
  "NODE_USE_SYSTEM_CA",
  "OPENSSL_CONF",
  "OPENSSL_MODULES",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
] as const;

export type Sbx051Role = "A" | "B";

export interface Sbx051Config {
  token: string;
  teamId: typeof SBX051_TEAM;
  projectId: typeof SBX051_PROJECT;
  expectedAlias: typeof SBX051_ALIAS;
  manualAliasConfirmation?: string;
  recoveryRunId?: string;
}

export interface Sbx051JournalResource {
  role: Sbx051Role;
  name: string;
  tags: Record<string, string>;
  markerPath: string;
  createAttempted: boolean;
  sessionId?: string;
}

export interface Sbx051Journal {
  schemaVersion: 1;
  testId: typeof SBX051_TEST_ID;
  runId: string;
  startedAt: string;
  updatedAt: string;
  resources: [Sbx051JournalResource, Sbx051JournalResource];
  rawMarkersRetained: false;
  rawInteractiveTokensRetained: false;
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

export function requireStrictSbx051Environment(environment: NodeJS.ProcessEnv = process.env): void {
  if (environment.NODE_TLS_REJECT_UNAUTHORIZED === "0" ||
      (environment.NODE_OPTIONS !== undefined && environment.NODE_OPTIONS.trim() !== "") ||
      LOCAL_TLS_TRUST_ENVIRONMENT_NAMES.some((name) => environment[name] !== undefined)) {
    throw new Error("SBX-051 refuses local TLS trust overrides or runtime injection");
  }
}

export function loadSbx051Config(environment: NodeJS.ProcessEnv = process.env): Sbx051Config {
  requireStrictSbx051Environment(environment);
  if (environment.SBX051_SCOPE_CONFIRMATION !== SBX051_SCOPE_CONFIRMATION) {
    throw new Error("SBX051_SCOPE_CONFIRMATION did not match the exact bounded-test attestation");
  }
  if (environment.VERCEL_TEAM_ID !== SBX051_TEAM || environment.VERCEL_PROJECT_ID !== SBX051_PROJECT ||
      environment.SBX051_EXPECTED_ALIAS !== SBX051_ALIAS) {
    throw new Error("SBX-051 is not bound to the exact eligible alias/team/project");
  }
  const token = required(environment, "VERCEL_TOKEN");
  if (token.length < 20 || token.length > 4_096 || /[\s\0]/u.test(token) || token.split(".").length === 3) {
    throw new Error("SBX-051 requires one bounded opaque non-JWT Vercel PAT");
  }
  const recoveryRunId = environment.SBX051_RECOVERY_RUN_ID;
  if (recoveryRunId !== undefined && !SBX051_UUID.test(recoveryRunId)) {
    throw new Error("SBX051_RECOVERY_RUN_ID must be one canonical UUIDv4");
  }
  return {
    token,
    teamId: SBX051_TEAM,
    projectId: SBX051_PROJECT,
    expectedAlias: SBX051_ALIAS,
    ...(environment.SBX051_ALIAS_EMAIL_CONFIRMATION
      ? { manualAliasConfirmation: environment.SBX051_ALIAS_EMAIL_CONFIRMATION }
      : {}),
    ...(recoveryRunId ? { recoveryRunId } : {}),
  };
}

function exactKeys(value: object, requiredKeys: readonly string[], optionalKeys: readonly string[] = []): boolean {
  const actual = Object.keys(value);
  const permitted = new Set([...requiredKeys, ...optionalKeys]);
  return requiredKeys.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    actual.every((key) => permitted.has(key)) &&
    actual.length === requiredKeys.length + optionalKeys.filter((key) =>
      Object.prototype.hasOwnProperty.call(value, key)).length;
}

function exactStringRecord(actual: unknown, expected: Record<string, string>): boolean {
  if (actual === null || typeof actual !== "object" || Array.isArray(actual)) return false;
  const value = actual as Record<string, unknown>;
  const keys = Object.keys(expected);
  return Object.keys(value).length === keys.length && keys.every((key) => value[key] === expected[key]);
}

function timestamp(value: unknown): value is string {
  if (typeof value !== "string" || value.length !== 24) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

export function sbx051Name(role: Sbx051Role, runId: string): string {
  if (!SBX051_UUID.test(runId)) throw new Error("SBX-051 name requires a UUIDv4");
  return `sbx-051-${role.toLowerCase()}-${runId}`;
}

export function sbx051Tags(role: Sbx051Role, runId: string): Record<string, string> {
  return { harness: "vsc", test: SBX051_TEST_ID, run: runId, role };
}

export function sbx051MarkerPath(role: Sbx051Role, runId: string): string {
  if (!SBX051_UUID.test(runId)) throw new Error("SBX-051 marker path requires a UUIDv4");
  return `/tmp/sbx-051/${role.toLowerCase()}-${runId}.marker`;
}

export function createSbx051Journal(now = new Date()): Sbx051Journal {
  const runId = randomUUID();
  const at = now.toISOString();
  const resource = (role: Sbx051Role): Sbx051JournalResource => ({
    role,
    name: sbx051Name(role, runId),
    tags: sbx051Tags(role, runId),
    markerPath: sbx051MarkerPath(role, runId),
    createAttempted: false,
  });
  return {
    schemaVersion: 1,
    testId: SBX051_TEST_ID,
    runId,
    startedAt: at,
    updatedAt: at,
    resources: [resource("A"), resource("B")],
    rawMarkersRetained: false,
    rawInteractiveTokensRetained: false,
  };
}

export function parseSbx051Journal(input: unknown): Sbx051Journal {
  if (input === null || typeof input !== "object" || Array.isArray(input) ||
      !exactKeys(input, ["schemaVersion", "testId", "runId", "startedAt", "updatedAt", "resources",
        "rawMarkersRetained", "rawInteractiveTokensRetained"])) {
    throw new Error("SBX-051 recovery journal fields were not exact");
  }
  const value = input as Record<string, unknown>;
  if (value.schemaVersion !== 1 || value.testId !== SBX051_TEST_ID ||
      typeof value.runId !== "string" || !SBX051_UUID.test(value.runId) ||
      !timestamp(value.startedAt) || !timestamp(value.updatedAt) ||
      Date.parse(value.updatedAt) < Date.parse(value.startedAt) ||
      value.rawMarkersRetained !== false || value.rawInteractiveTokensRetained !== false ||
      !Array.isArray(value.resources) || value.resources.length !== 2) {
    throw new Error("SBX-051 recovery journal was invalid");
  }
  const roles: Sbx051Role[] = ["A", "B"];
  const resources = value.resources.map((entry, index): Sbx051JournalResource => {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry) ||
        !exactKeys(entry, ["role", "name", "tags", "markerPath", "createAttempted"], ["sessionId"])) {
      throw new Error("SBX-051 recovery resource fields were not exact");
    }
    const record = entry as Record<string, unknown>;
    const role = roles[index]!;
    if (record.role !== role || record.name !== sbx051Name(role, value.runId as string) ||
        record.markerPath !== sbx051MarkerPath(role, value.runId as string) ||
        !exactStringRecord(record.tags, sbx051Tags(role, value.runId as string)) ||
        typeof record.createAttempted !== "boolean" ||
        !(record.sessionId === undefined || (typeof record.sessionId === "string" && SESSION_ID.test(record.sessionId)))) {
      throw new Error("SBX-051 recovery resource provenance was invalid");
    }
    return {
      role,
      name: record.name as string,
      tags: record.tags as Record<string, string>,
      markerPath: record.markerPath as string,
      createAttempted: record.createAttempted,
      ...(record.sessionId ? { sessionId: record.sessionId as string } : {}),
    };
  }) as [Sbx051JournalResource, Sbx051JournalResource];
  return {
    schemaVersion: 1,
    testId: SBX051_TEST_ID,
    runId: value.runId,
    startedAt: value.startedAt,
    updatedAt: value.updatedAt,
    resources,
    rawMarkersRetained: false,
    rawInteractiveTokensRetained: false,
  } as Sbx051Journal;
}

export function sbx051JournalPath(runId: string): string {
  if (!SBX051_UUID.test(runId)) throw new Error("SBX-051 journal path requires a UUIDv4");
  return resolve(SBX051_ARTIFACTS_DIRECTORY, `SBX-051-recovery-${runId}.json`);
}

export function sbx051ArtifactPath(runId: string): string {
  if (!SBX051_UUID.test(runId)) throw new Error("SBX-051 artifact path requires a UUIDv4");
  return resolve(SBX051_ARTIFACTS_DIRECTORY, `SBX-051-${runId}-private.json`);
}

export function sbx051RecoveryArtifactPath(runId: string, recoveryAttemptId: string): string {
  if (!SBX051_UUID.test(runId) || !SBX051_UUID.test(recoveryAttemptId)) {
    throw new Error("SBX-051 recovery artifact path requires two UUIDv4 values");
  }
  return resolve(
    SBX051_ARTIFACTS_DIRECTORY,
    `SBX-051-${runId}-recovery-${recoveryAttemptId}-private.json`,
  );
}

async function ensureArtifactsDirectory(): Promise<void> {
  await mkdir(SBX051_ARTIFACTS_DIRECTORY, { recursive: true, mode: 0o700 });
}

export async function writeSbx051PrivateJson(path: string, value: unknown): Promise<void> {
  await ensureArtifactsDirectory();
  const temporary = `${path}.tmp-${process.pid}-${randomUUID()}`;
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await rename(temporary, path);
  } catch (error) {
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

export async function writeSbx051PrivateJsonNoClobber(
  path: string,
  value: unknown,
): Promise<void> {
  await ensureArtifactsDirectory();
  const temporary = `${path}.tmp-${process.pid}-${randomUUID()}`;
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await link(temporary, path);
  } finally {
    await unlink(temporary).catch(() => undefined);
  }
}

export async function writeSbx051Journal(journal: Sbx051Journal): Promise<void> {
  journal.updatedAt = new Date().toISOString();
  await writeSbx051PrivateJson(sbx051JournalPath(journal.runId), parseSbx051Journal(journal));
}

export async function readSbx051Journal(runId: string): Promise<Sbx051Journal> {
  return parseSbx051Journal(JSON.parse(await readFile(sbx051JournalPath(runId), "utf8")));
}

export async function acquireSbx051Lock(runId: string, recovery: boolean): Promise<Sbx051HeldLock> {
  if (!SBX051_UUID.test(runId)) throw new Error("SBX-051 lock requires a UUIDv4");
  await ensureArtifactsDirectory();
  return acquireSbx051LiveLock(SBX051_LIVE_LOCK, runId, recovery);
}

export async function removeSbx051Journal(runId: string): Promise<void> {
  await unlink(sbx051JournalPath(runId));
}
