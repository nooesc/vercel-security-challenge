import { resolve } from "node:path";

export interface HarnessConfig {
  observerBaseUrl: string;
  observerAdminKey: string;
  artifactsDir: string;
  sandboxTimeoutMs: number;
  commandTimeoutMs: number;
  observerSettleMs: number;
}

function positiveInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return value;
}

export function loadHarnessConfig(): HarnessConfig {
  const observerBaseUrl = process.env.OBSERVER_BASE_URL;
  const observerAdminKey = process.env.OBSERVER_ADMIN_KEY;
  if (!observerBaseUrl) throw new Error("OBSERVER_BASE_URL is required");
  if (!observerAdminKey || observerAdminKey.length < 24) {
    throw new Error("OBSERVER_ADMIN_KEY must contain at least 24 characters");
  }

  const parsed = new URL(observerBaseUrl);
  if (parsed.protocol !== "https:" && parsed.hostname !== "127.0.0.1" && parsed.hostname !== "localhost") {
    throw new Error("OBSERVER_BASE_URL must use HTTPS unless it is localhost");
  }

  return {
    observerBaseUrl: parsed.origin,
    observerAdminKey,
    artifactsDir: resolve(process.env.HARNESS_ARTIFACTS_DIR ?? "./artifacts"),
    sandboxTimeoutMs: positiveInt("HARNESS_SANDBOX_TIMEOUT_MS", 300_000),
    commandTimeoutMs: positiveInt("HARNESS_COMMAND_TIMEOUT_MS", 20_000),
    observerSettleMs: positiveInt("OBSERVER_SETTLE_MS", 1_500),
  };
}
