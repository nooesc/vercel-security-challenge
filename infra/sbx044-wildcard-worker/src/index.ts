import { DurableObject } from "cloudflare:workers";
import { actionResponse, deriveOperationId, operationMessage } from "./protocol.js";

const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const canaryPattern = /^[A-Za-z0-9_-]{16,128}$/u;
const brokeredPattern = /^[A-Za-z0-9_-]{32,160}$/u;
const operationPattern = /^w44[rs]_[A-Za-z0-9_-]{43}$/u;
const maximumEvents = 16;

interface LedgerCase {
  caseId: string;
  canary: string;
}

interface LedgerConfiguration {
  cases: LedgerCase[];
}

export interface LedgerEvent {
  ordinal: number;
  observedAt: string;
  role: "allowed" | "denied";
  caseId: string;
  canaryMatched: boolean;
  brokered: boolean;
  operationId: string;
}

export interface LedgerSnapshot {
  configured: boolean;
  role: "allowed" | "denied";
  events: LedgerEvent[];
  rawBrokeredSecretRetained: false;
  brokeredSecretDigestRetained: false;
}

interface Env {
  SBX044_ACTION_KEY: string;
  SBX044_ADMIN_KEY: string;
  SBX044_ROLE: "allowed" | "denied";
  SBX044_HOST: string;
  SBX044_LEDGER: DurableObjectNamespace<Sbx044Ledger>;
}

function exactConfiguration(value: unknown): LedgerConfiguration | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 1 || !Array.isArray(record.cases)) return undefined;
  if (record.cases.length < 2 || record.cases.length > 12) return undefined;
  const cases: LedgerCase[] = [];
  for (const entry of record.cases) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return undefined;
    const item = entry as Record<string, unknown>;
    if (
      Object.keys(item).sort().join(",") !== "canary,caseId" ||
      typeof item.caseId !== "string" || !identifierPattern.test(item.caseId) ||
      typeof item.canary !== "string" || !canaryPattern.test(item.canary)
    ) return undefined;
    cases.push({ caseId: item.caseId, canary: item.canary });
  }
  if (new Set(cases.map((entry) => entry.caseId)).size !== cases.length) return undefined;
  return { cases };
}

export class Sbx044Ledger extends DurableObject<Env> {
  async configure(value: unknown): Promise<boolean> {
    const configuration = exactConfiguration(value);
    if (!configuration) return false;
    await this.ctx.storage.delete("events");
    await this.ctx.storage.put("configuration", configuration.cases);
    return true;
  }

  async record(input: {
    role: "allowed" | "denied";
    caseId: string;
    canary: string;
    brokered: boolean;
    operationId: string;
  }): Promise<boolean> {
    if (
      input.role !== this.env.SBX044_ROLE ||
      !identifierPattern.test(input.caseId) ||
      !canaryPattern.test(input.canary) ||
      typeof input.brokered !== "boolean" ||
      !operationPattern.test(input.operationId)
    ) return false;
    const cases = await this.ctx.storage.get<LedgerCase[]>("configuration");
    if (!cases) return false;
    if (!cases.some((entry) => entry.caseId === input.caseId && entry.canary === input.canary)) return false;
    const events = await this.ctx.storage.get<LedgerEvent[]>("events") ?? [];
    if (events.length >= maximumEvents) return false;
    events.push({
      ordinal: events.length + 1,
      observedAt: new Date().toISOString(),
      role: input.role,
      caseId: input.caseId,
      canaryMatched: true,
      brokered: input.brokered,
      operationId: input.operationId,
    });
    await this.ctx.storage.put("events", events);
    return true;
  }

  async snapshot(): Promise<LedgerSnapshot> {
    const [configuration, events] = await Promise.all([
      this.ctx.storage.get<LedgerCase[]>("configuration"),
      this.ctx.storage.get<LedgerEvent[]>("events"),
    ]);
    return {
      configured: configuration !== undefined,
      role: this.env.SBX044_ROLE,
      events: events ?? [],
      rawBrokeredSecretRetained: false,
      brokeredSecretDigestRetained: false,
    };
  }

  async clear(): Promise<boolean> {
    await this.ctx.storage.delete(["events", "configuration"]);
    // Early local/live preflight builds used user SQL tables for the same
    // per-run object names. Purge those tables as well so an admin DELETE is
    // backward-compatible and leaves no legacy receiver state behind.
    this.ctx.storage.sql.exec("DROP TABLE IF EXISTS events; DROP TABLE IF EXISTS configuration;").toArray();
    const legacyTables = this.ctx.storage.sql.exec<{ name: string }>(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('events', 'configuration')",
    ).toArray();
    return legacyTables.length === 0;
  }
}

function json(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: {
      "cache-control": "no-store, max-age=0",
      "content-security-policy": "default-src 'none'",
      "x-content-type-options": "nosniff",
    },
  });
}

function authorized(request: Request, key: string): boolean {
  const header = request.headers.get("authorization");
  return header !== null && header === `Bearer ${key}`;
}

async function admin(request: Request, env: Env, runId: string): Promise<Response> {
  if (!authorized(request, env.SBX044_ADMIN_KEY)) return json({ ok: false }, 401);
  if (!identifierPattern.test(runId)) return json({ ok: false }, 400);
  const ledger = env.SBX044_LEDGER.getByName(runId);
  if (request.method === "PUT") {
    const bytes = new Uint8Array(await request.arrayBuffer());
    if (bytes.byteLength > 8_192) return json({ ok: false }, 413);
    let value: unknown;
    try { value = JSON.parse(new TextDecoder().decode(bytes)); } catch { return json({ ok: false }, 400); }
    return await ledger.configure(value) ? json({ ok: true, role: env.SBX044_ROLE }, 201) : json({ ok: false }, 400);
  }
  if (request.method === "GET") return json(await ledger.snapshot());
  if (request.method === "DELETE") return await ledger.clear() ? json({ ok: true }) : json({ ok: false }, 500);
  return json({ ok: false }, 405);
}

async function handle(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (url.hostname !== env.SBX044_HOST) return json({ ok: false, role: env.SBX044_ROLE }, 421);
  if (url.pathname === "/healthz") return json({ ok: true, role: env.SBX044_ROLE, hostMatched: true });
  const adminMatch = /^\/v1\/sbx044\/admin\/runs\/([A-Za-z0-9._:-]{1,128})$/u.exec(url.pathname);
  if (adminMatch) return admin(request, env, adminMatch[1]!);
  if (url.pathname !== "/v1/sbx044/action") return json({ ok: false, role: env.SBX044_ROLE }, 404);
  if (request.method !== "GET") return json({ ok: false, role: env.SBX044_ROLE }, 405);
  const runId = url.searchParams.get("run");
  const caseId = url.searchParams.get("case");
  const canary = url.searchParams.get("canary");
  if (
    !runId || !caseId || !canary ||
    !identifierPattern.test(runId) ||
    !identifierPattern.test(caseId) ||
    !canaryPattern.test(canary)
  ) return json({ ok: false, role: env.SBX044_ROLE }, 400);
  const brokered = request.headers.get("x-sbx044-brokered-secret");
  const validBrokered = brokered !== null && brokeredPattern.test(brokered);
  const message = operationMessage({
    hostname: env.SBX044_HOST,
    role: env.SBX044_ROLE,
    runId,
    caseId,
    canary,
    ...(validBrokered ? { brokeredSecret: brokered } : {}),
  });
  const receipt = await deriveOperationId(env.SBX044_ACTION_KEY, message, validBrokered);
  const recorded = await env.SBX044_LEDGER.getByName(runId).record({
    role: env.SBX044_ROLE,
    caseId,
    canary,
    brokered: validBrokered,
    operationId: receipt,
  });
  if (!recorded) return json({ ok: false, role: env.SBX044_ROLE }, 409);
  return json(actionResponse(env.SBX044_ROLE, validBrokered, receipt));
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await handle(request, env);
    } catch {
      return json({ ok: false, role: env.SBX044_ROLE }, 500);
    }
  },
};
