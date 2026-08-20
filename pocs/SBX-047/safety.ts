import { randomUUID } from "node:crypto";
import { mkdir, open, readFile, rename, unlink, type FileHandle } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { SBX047_TEST_ID } from "./verdict.js";

export const SBX047_ELIGIBLE_ALIAS = "swve@wearehackerone.com" as const;
export const SBX047_ELIGIBLE_TEAM = "team_n98ERpVwV7HqmWRudAyK8sXQ" as const;
export const SBX047_ELIGIBLE_PROJECT = "prj_CyyVykdN06Nrkla6KidZcecLgbCa" as const;
export const SBX047_SCOPE_CONFIRMATION =
  "I_RECHECKED_SBX047_SINGLE_ACCOUNT_SCOPE_AND_AUTHORIZE_ONE_BOUNDED_FORK_POLICY_TEST" as const;
export const SBX047_ARTIFACTS_DIRECTORY = fileURLToPath(
  new URL("../../artifacts", import.meta.url),
);
export const SBX047_LIVE_LOCK = resolve(SBX047_ARTIFACTS_DIRECTORY, "SBX-047-live-active.lock");

export const SBX047_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SESSION_ID = /^sbx_[A-Za-z0-9_-]{8,192}$/u;

export type Sbx047ResourceRole = "source" | "inheritance" | "target";

export interface Sbx047ExplicitConfig {
  token: string;
  teamId: typeof SBX047_ELIGIBLE_TEAM;
  projectId: typeof SBX047_ELIGIBLE_PROJECT;
  expectedAlias: typeof SBX047_ELIGIBLE_ALIAS;
  publicOrigin: URL;
  adminOrigin: URL;
  adminKey: string;
  recoveryRunId?: string;
}

export interface Sbx047JournalResource {
  role: Sbx047ResourceRole;
  name: string;
  tags: Record<string, string>;
  createAttempted: boolean;
  sessionId?: string;
}

export interface Sbx047RecoveryJournal {
  schemaVersion: 1;
  testId: typeof SBX047_TEST_ID;
  runId: string;
  startedAt: string;
  updatedAt: string;
  resources: Sbx047JournalResource[];
  rawSecretsRetained: false;
}

export interface Sbx047HeldLock {
  runId: string;
  path: string;
  release(): Promise<void>;
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function exactPublicOrigin(raw: string): URL {
  const result = new URL(raw);
  if (result.protocol !== "https:" || raw !== result.origin || result.port !== "" ||
      result.username !== "" || result.password !== "" || result.pathname !== "/" ||
      result.search !== "" || result.hash !== "" || result.hostname !== result.hostname.toLowerCase() ||
      result.hostname.endsWith(".")) {
    throw new Error("SBX047_PUBLIC_ORIGIN must be one exact canonical HTTPS hostname origin");
  }
  return result;
}

function exactAdminOrigin(raw: string): URL {
  const result = new URL(raw);
  if (result.protocol !== "http:" || raw !== result.origin || result.hostname !== "127.0.0.1" ||
      !/^[0-9]{1,5}$/u.test(result.port) || Number(result.port) < 1 || Number(result.port) > 65_535 ||
      result.username !== "" || result.password !== "" || result.pathname !== "/" ||
      result.search !== "" || result.hash !== "") {
    throw new Error("SBX047_ADMIN_ORIGIN must be an exact http://127.0.0.1:<port> origin");
  }
  return result;
}

export function loadSbx047Config(
  environment: NodeJS.ProcessEnv = process.env,
): Sbx047ExplicitConfig {
  if (environment.SBX047_SCOPE_CONFIRMATION !== SBX047_SCOPE_CONFIRMATION) {
    throw new Error("SBX047_SCOPE_CONFIRMATION did not match the exact bounded-test attestation");
  }
  if (environment.VERCEL_TEAM_ID !== SBX047_ELIGIBLE_TEAM ||
      environment.VERCEL_PROJECT_ID !== SBX047_ELIGIBLE_PROJECT ||
      environment.SBX047_EXPECTED_ALIAS !== SBX047_ELIGIBLE_ALIAS) {
    throw new Error("SBX-047 credentials are not bound to the exact eligible alias/team/project");
  }
  const token = required(environment, "VERCEL_TOKEN");
  if (token.length < 20 || token.length > 4_096 || /[\s\0]/u.test(token) ||
      token.split(".").length === 3) {
    throw new Error("SBX-047 requires one bounded non-JWT Vercel PAT");
  }
  const adminKey = required(environment, "SBX047_ADMIN_KEY");
  if (adminKey.length < 43 || adminKey.length > 256 || !/^[A-Za-z0-9_-]+$/u.test(adminKey)) {
    throw new Error("SBX047_ADMIN_KEY must be one fresh 43+ character base64url/hex value");
  }
  const publicOrigin = exactPublicOrigin(required(environment, "SBX047_PUBLIC_ORIGIN"));
  const adminOrigin = exactAdminOrigin(
    environment.SBX047_ADMIN_ORIGIN ?? "http://127.0.0.1:43147",
  );
  const recoveryRunId = environment.SBX047_RECOVERY_RUN_ID;
  if (recoveryRunId !== undefined && !SBX047_UUID.test(recoveryRunId)) {
    throw new Error("SBX047_RECOVERY_RUN_ID must be one canonical UUIDv4");
  }
  return {
    token,
    teamId: SBX047_ELIGIBLE_TEAM,
    projectId: SBX047_ELIGIBLE_PROJECT,
    expectedAlias: SBX047_ELIGIBLE_ALIAS,
    publicOrigin,
    adminOrigin,
    adminKey,
    ...(recoveryRunId === undefined ? {} : { recoveryRunId }),
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

function timestamp(value: unknown): value is string {
  if (typeof value !== "string" || value.length !== 24) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function expectedName(role: Sbx047ResourceRole, runId: string): string {
  return `sbx-047-${role}-${runId}`;
}

function expectedTags(role: Sbx047ResourceRole, runId: string): Record<string, string> {
  return { harness: "vsc", test: SBX047_TEST_ID, run: runId, role };
}

function exactStringRecord(actual: unknown, expected: Record<string, string>): boolean {
  if (actual === null || typeof actual !== "object" || Array.isArray(actual)) return false;
  const record = actual as Record<string, unknown>;
  const keys = Object.keys(expected);
  return Object.keys(record).length === keys.length && keys.every((key) => record[key] === expected[key]);
}

export function parseSbx047Journal(value: unknown): Sbx047RecoveryJournal {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      !exactKeys(value, ["schemaVersion", "testId", "runId", "startedAt", "updatedAt",
        "resources", "rawSecretsRetained"])) {
    throw new Error("SBX-047 recovery journal fields were not exact");
  }
  const journal = value as Record<string, unknown>;
  if (journal.schemaVersion !== 1 || journal.testId !== SBX047_TEST_ID ||
      typeof journal.runId !== "string" || !SBX047_UUID.test(journal.runId) ||
      !timestamp(journal.startedAt) || !timestamp(journal.updatedAt) ||
      Date.parse(journal.updatedAt) < Date.parse(journal.startedAt) ||
      journal.rawSecretsRetained !== false || !Array.isArray(journal.resources) ||
      journal.resources.length !== 3) {
    throw new Error("SBX-047 recovery journal was invalid");
  }
  const roles: Sbx047ResourceRole[] = ["source", "inheritance", "target"];
  const resources = journal.resources.map((entry, index): Sbx047JournalResource => {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry) ||
        !exactKeys(entry, ["role", "name", "tags", "createAttempted"], ["sessionId"])) {
      throw new Error("SBX-047 recovery resource fields were not exact");
    }
    const resource = entry as Record<string, unknown>;
    const role = roles[index]!;
    if (resource.role !== role || resource.name !== expectedName(role, journal.runId as string) ||
        !exactStringRecord(resource.tags, expectedTags(role, journal.runId as string)) ||
        typeof resource.createAttempted !== "boolean" ||
        !(resource.sessionId === undefined ||
          (typeof resource.sessionId === "string" && SESSION_ID.test(resource.sessionId)))) {
      throw new Error("SBX-047 recovery resource provenance was invalid");
    }
    return {
      role,
      name: resource.name as string,
      tags: resource.tags as Record<string, string>,
      createAttempted: resource.createAttempted,
      ...(resource.sessionId === undefined ? {} : { sessionId: resource.sessionId as string }),
    };
  });
  return {
    schemaVersion: 1,
    testId: SBX047_TEST_ID,
    runId: journal.runId,
    startedAt: journal.startedAt,
    updatedAt: journal.updatedAt,
    resources,
    rawSecretsRetained: false,
  } as Sbx047RecoveryJournal;
}

export function createSbx047Journal(now: Date = new Date()): Sbx047RecoveryJournal {
  const runId = randomUUID();
  const at = now.toISOString();
  const roles: Sbx047ResourceRole[] = ["source", "inheritance", "target"];
  return {
    schemaVersion: 1,
    testId: SBX047_TEST_ID,
    runId,
    startedAt: at,
    updatedAt: at,
    resources: roles.map((role) => ({
      role,
      name: expectedName(role, runId),
      tags: expectedTags(role, runId),
      createAttempted: false,
    })),
    rawSecretsRetained: false,
  };
}

export function sbx047JournalPath(runId: string): string {
  if (!SBX047_UUID.test(runId)) throw new Error("SBX-047 journal path requires a UUIDv4");
  return resolve(SBX047_ARTIFACTS_DIRECTORY, `SBX-047-recovery-${runId}.json`);
}

export function sbx047ArtifactPath(runId: string): string {
  if (!SBX047_UUID.test(runId)) throw new Error("SBX-047 artifact path requires a UUIDv4");
  return resolve(SBX047_ARTIFACTS_DIRECTORY, `SBX-047-${runId}-private.json`);
}

export async function ensureSbx047ArtifactsDirectory(): Promise<void> {
  await mkdir(SBX047_ARTIFACTS_DIRECTORY, { recursive: true, mode: 0o700 });
}

export async function writeSbx047PrivateJson(path: string, value: unknown): Promise<void> {
  await ensureSbx047ArtifactsDirectory();
  const temporary = `${path}.tmp-${process.pid}-${randomUUID()}`;
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(temporary, path);
}

export async function writeSbx047Journal(journal: Sbx047RecoveryJournal): Promise<void> {
  journal.updatedAt = new Date().toISOString();
  const checked = parseSbx047Journal(journal);
  await writeSbx047PrivateJson(sbx047JournalPath(journal.runId), checked);
}

export async function readSbx047Journal(runId: string): Promise<Sbx047RecoveryJournal> {
  const text = await readFile(sbx047JournalPath(runId), "utf8");
  return parseSbx047Journal(JSON.parse(text));
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

async function createLock(runId: string): Promise<Sbx047HeldLock> {
  const handle = await open(SBX047_LIVE_LOCK, "wx", 0o600);
  await handle.writeFile(`${JSON.stringify({
    schemaVersion: 1,
    testId: SBX047_TEST_ID,
    runId,
    pid: process.pid,
    createdAt: new Date().toISOString(),
  })}\n`, "utf8");
  await handle.sync();
  let released = false;
  return {
    runId,
    path: SBX047_LIVE_LOCK,
    async release(): Promise<void> {
      if (released) return;
      released = true;
      await handle.close();
      await unlink(SBX047_LIVE_LOCK);
    },
  };
}

export async function acquireSbx047Lock(
  runId: string,
  recovery: boolean,
): Promise<Sbx047HeldLock> {
  if (!SBX047_UUID.test(runId)) throw new Error("SBX-047 lock requires a UUIDv4");
  await ensureSbx047ArtifactsDirectory();
  try {
    return await createLock(runId);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST" || !recovery) throw error;
  }
  const parsed = JSON.parse(await readFile(SBX047_LIVE_LOCK, "utf8")) as Record<string, unknown>;
  if (!exactKeys(parsed, ["schemaVersion", "testId", "runId", "pid", "createdAt"]) ||
      parsed.schemaVersion !== 1 || parsed.testId !== SBX047_TEST_ID || parsed.runId !== runId ||
      typeof parsed.pid !== "number" || !Number.isSafeInteger(parsed.pid) || parsed.pid < 1 ||
      !timestamp(parsed.createdAt) || processAlive(parsed.pid)) {
    throw new Error("SBX-047 refused to reclaim a nonmatching or live lock");
  }
  await unlink(SBX047_LIVE_LOCK);
  return createLock(runId);
}

export async function removeSbx047Journal(runId: string): Promise<void> {
  await unlink(sbx047JournalPath(runId));
}
