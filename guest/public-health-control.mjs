import https from "node:https";

export const HEALTH_ORIGIN = "https://vsc-h3-action-swve.cyrus-206.workers.dev";
export const HEALTH_PATH = "/healthz";
export const MAX_RESPONSE_BYTES = 1_024;

const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const PHASES = new Set(["allow-control", "deny-control"]);

function record(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

export function validateHealthControlConfig(input) {
  const config = record(input, "health control configuration");
  const keys = Object.keys(config).sort();
  if (JSON.stringify(keys) !== JSON.stringify(["phase", "runId", "timeoutMs"])) {
    throw new Error("health control configuration has unexpected fields");
  }
  if (typeof config.runId !== "string" || !RUN_ID.test(config.runId)) {
    throw new Error("runId must be a canonical random UUID");
  }
  if (!PHASES.has(config.phase)) throw new Error("phase is not recognized");
  if (!Number.isInteger(config.timeoutMs) || config.timeoutMs < 1_000 || config.timeoutMs > 5_000) {
    throw new Error("timeoutMs must be an integer from 1000 through 5000");
  }
  return { runId: config.runId, phase: config.phase, timeoutMs: config.timeoutMs };
}

function safeErrorCode(error, timedOut) {
  if (timedOut) return "ETIMEDOUT";
  const code = typeof error?.code === "string" ? error.code : undefined;
  if (code && /^[A-Z][A-Z0-9_]{0,63}$/u.test(code)) return code;
  const name = error instanceof Error ? error.name : "Error";
  return /^[A-Za-z][A-Za-z0-9]{0,63}$/u.test(name) ? name : "Error";
}

async function requestHealth(config) {
  const startedAt = Date.now();
  return await new Promise((resolve) => {
    let settled = false;
    let timedOut = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve({ ...result, durationMs: Date.now() - startedAt });
    };
    const request = https.request({
      protocol: "https:",
      hostname: "vsc-h3-action-swve.cyrus-206.workers.dev",
      port: 443,
      path: HEALTH_PATH,
      method: "GET",
      agent: false,
      headers: {
        Accept: "application/json",
        Connection: "close",
        "User-Agent": "vercel-sandbox-boundary-research/SBX-020",
      },
    }, (response) => {
      const statusCode = response.statusCode;
      // Header receipt is the control signal. Do not read or retain the body.
      response.destroy();
      finish({
        receivedResponse: true,
        statusCode: Number.isInteger(statusCode) ? statusCode : undefined,
        timedOut: false,
      });
    });
    request.setTimeout(config.timeoutMs, () => {
      timedOut = true;
      request.destroy(Object.assign(new Error("request timed out"), { code: "ETIMEDOUT" }));
    });
    request.once("error", (error) => {
      finish({
        receivedResponse: false,
        timedOut,
        errorCode: safeErrorCode(error, timedOut),
      });
    });
    request.end();
  });
}

export async function runHealthControl(configInput, { requester = requestHealth } = {}) {
  const config = validateHealthControlConfig(configInput);
  const result = await requester(config);
  return {
    schemaVersion: 1,
    ok: true,
    runId: config.runId,
    phase: config.phase,
    origin: HEALTH_ORIGIN,
    path: HEALTH_PATH,
    timeoutMs: config.timeoutMs,
    maximumResponseBytes: MAX_RESPONSE_BYTES,
    responseBodiesRetained: false,
    receivedResponse: result?.receivedResponse === true,
    ...(Number.isInteger(result?.statusCode) ? { statusCode: result.statusCode } : {}),
    timedOut: result?.timedOut === true,
    ...(typeof result?.errorCode === "string" ? { errorCode: result.errorCode.slice(0, 64) } : {}),
    ...(Number.isInteger(result?.durationMs) && result.durationMs >= 0 ? { durationMs: result.durationMs } : {}),
  };
}

async function main() {
  const encoded = process.argv[2];
  if (!encoded) throw new Error("missing base64url health control configuration");
  const decoded = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  const config = validateHealthControlConfig(decoded);
  const result = process.argv[3] === "--plan"
    ? {
        schemaVersion: 1,
        ok: true,
        mode: "plan",
        runId: config.runId,
        phase: config.phase,
        origin: HEALTH_ORIGIN,
        path: HEALTH_PATH,
        timeoutMs: config.timeoutMs,
        maximumResponseBytes: MAX_RESPONSE_BYTES,
        responseBodiesRetained: false,
      }
    : await runHealthControl(config);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1] && new URL(import.meta.url).pathname === new URL(`file://${process.argv[1]}`).pathname) {
  main().catch((error) => {
    process.stdout.write(`${JSON.stringify({
      schemaVersion: 1,
      ok: false,
      phase: "configuration",
      error: error instanceof Error ? error.message.slice(0, 256) : "Error",
    })}\n`);
    process.exitCode = 2;
  });
}
