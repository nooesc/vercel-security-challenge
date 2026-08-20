#!/usr/bin/env node

import { spawn } from "node:child_process";
import { chmod, lstat, mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const TEST_ID = "SBX-042-POC";
const MAX_OUTPUT = 96 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CASE = /^[a-z0-9][a-z0-9-]{0,63}$/u;
const HOST = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const PUBLIC_CANARY = /^pub_[A-Za-z0-9_-]{24}$/u;
const SESSION_ROOT = "/tmp/sbx-042";

function object(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("configuration must be an object");
  return value;
}

function text(value, name, pattern, maximum = 512) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[\0\r\n]/u.test(value) ||
      (pattern && !pattern.test(value))) throw new Error(`${name} is invalid`);
  return value;
}

function integer(value, name, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) throw new Error(`${name} is invalid`);
  return value;
}

function safeSessionPath(value, runId, caseId, suffix) {
  const expected = resolve(SESSION_ROOT, runId, `${caseId}.${suffix}`);
  if (value !== expected) throw new Error(`${suffix} path must equal ${expected}`);
  return expected;
}

export function validateSbx042ProbeConfiguration(raw) {
  const input = object(raw);
  const mode = text(input.mode, "mode", /^(?:bootstrap|fresh|early)$/u);
  const stage = text(input.stage, "stage", /^(?:preflight|public|secret)$/u);
  const runId = text(input.runId, "runId", UUID);
  const caseId = text(input.caseId, "caseId", CASE, 64);
  const hostname = text(input.hostname, "hostname", HOST, 253);
  if (hostname !== hostname.toLowerCase() || isIP(hostname) !== 0) throw new Error("hostname must be canonical DNS text");
  const pinnedIPv4 = text(input.pinnedIPv4, "pinnedIPv4", undefined, 15);
  if (isIP(pinnedIPv4) !== 4) throw new Error("pinnedIPv4 must be IPv4");
  const port = integer(input.port, "port", 1, 65_535);
  const timeoutMs = integer(input.timeoutMs, "timeoutMs", 1_000, 15_000);
  const opensslBin = text(input.opensslBin ?? "openssl", "opensslBin", undefined, 1_024);
  const sessionPath = safeSessionPath(input.sessionPath, runId, caseId, "session.pem");
  const output = { mode, stage, runId, caseId, hostname, pinnedIPv4, port, timeoutMs, opensslBin, sessionPath };
  if (mode === "early") {
    const earlyDataPath = safeSessionPath(input.earlyDataPath, runId, caseId, "early.bin");
    if (stage === "secret") {
      const secretPath = safeSessionPath(input.secretPath, runId, caseId, "operator-secret.bin");
      return { ...output, earlyDataPath, secretPath };
    }
    const publicCanary = text(input.publicCanary, "publicCanary", PUBLIC_CANARY, 32);
    return { ...output, earlyDataPath, publicCanary };
  }
  return output;
}

export function buildSbx042EarlyFrame(config, payload) {
  const kind = config.stage === "secret" ? "secret" : "public";
  const encoded = kind === "secret" ? Buffer.from(payload).toString("base64url") : String(payload);
  const frame = Buffer.from(`SBX042|1|${config.runId}|${config.caseId}|${kind}|${encoded}\n`, "ascii");
  if (frame.length < 32 || frame.length > 512) throw new Error("early-data frame is outside its bound");
  return frame;
}

function appendBounded(state, chunk) {
  const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
  state.bytes += bytes.length;
  if (state.bytes > MAX_OUTPUT) throw new Error("OpenSSL output exceeded its evidence bound");
  state.text += bytes.toString("utf8");
}

export function parseSbx042OpenSslOutput(output) {
  const connectErrnoMatch = /(?:connect:errno=|errno[=: ])(-?[0-9]+)/iu.exec(output);
  return {
    tcpConnected: /CONNECTED\(/u.test(output),
    tlsEstablished: /(?:New|Reused), TLSv1\.3,/u.test(output),
    verificationPassed: /Verification: OK/u.test(output) && /Verify return code: 0 \(ok\)/u.test(output),
    sessionTicketReceived: /Post-Handshake New Session Ticket arrived:/u.test(output),
    sessionReused: /Reused, TLSv1\.3,/u.test(output),
    earlyDataAccepted: /Early data was accepted/u.test(output),
    earlyDataRejected: /Early data was rejected/u.test(output),
    connectErrno: connectErrnoMatch ? Number(connectErrnoMatch[1]) : undefined,
    maxEarlyData: (() => {
      const matches = [...output.matchAll(/Max Early Data:\s*([0-9]+)/gu)];
      const value = matches.at(-1)?.[1];
      return value === undefined ? undefined : Number(value);
    })(),
  };
}

async function runOpenSsl(opensslBin, args, timeoutMs, waitForTicket = false) {
  const child = spawn(opensslBin, args, {
    stdio: ["pipe", "pipe", "pipe"],
    env: {
      ...process.env,
      HTTP_PROXY: "",
      HTTPS_PROXY: "",
      ALL_PROXY: "",
      http_proxy: "",
      https_proxy: "",
      all_proxy: "",
    },
  });
  const captured = { text: "", bytes: 0 };
  let timedOut = false;
  let stdinEnded = false;
  let ticketCloseScheduled = false;
  const endStdin = () => {
    if (!stdinEnded) {
      stdinEnded = true;
      child.stdin.end();
    }
  };
  const capture = (chunk) => {
    appendBounded(captured, chunk);
    if (waitForTicket && !ticketCloseScheduled && /Post-Handshake New Session Ticket arrived:/u.test(captured.text)) {
      ticketCloseScheduled = true;
      setTimeout(endStdin, 75).unref();
    }
  };
  child.stdout.on("data", capture);
  child.stderr.on("data", capture);
  if (!waitForTicket) endStdin();
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill("SIGKILL");
  }, timeoutMs);
  const result = await new Promise((resolveResult, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolveResult({ code, signal }));
  }).finally(() => clearTimeout(timer));
  return { ...result, timedOut, output: captured.text };
}

async function sessionEvidence(opensslBin, sessionPath) {
  const state = await lstat(sessionPath);
  if (!state.isFile() || state.isSymbolicLink() || state.size < 1 || state.size > 65_536 ||
      (state.mode & 0o777) !== 0o600) throw new Error("session file failed bounded mode-0600 validation");
  const inspected = await runOpenSsl(opensslBin, ["sess_id", "-in", sessionPath, "-text", "-noout"], 3_000);
  if (inspected.code !== 0 || inspected.timedOut) throw new Error("OpenSSL could not inspect its session file");
  const parsed = parseSbx042OpenSslOutput(inspected.output);
  const maxEarlyDataMatch = /Max Early Data:\s*([0-9]+)/u.exec(inspected.output);
  const maxEarlyData = maxEarlyDataMatch ? Number(maxEarlyDataMatch[1]) : parsed.maxEarlyData;
  return { mode: state.mode & 0o777, bytes: state.size, maxEarlyData };
}

function baseEvidence(config) {
  return {
    schemaVersion: 1,
    testId: TEST_ID,
    mode: config.mode,
    stage: config.stage,
    runId: config.runId,
    caseId: config.caseId,
    hostname: config.hostname,
    pinnedIPv4: config.pinnedIPv4,
    port: config.port,
    attemptCount: 1,
    retryCount: 0,
    strictCertificateVerification: true,
    environmentProxyTrust: false,
    tlsVersionPinned: "TLSv1.3",
    timedOut: false,
    tcpConnected: false,
    tlsEstablished: false,
    verificationPassed: false,
    sessionTicketReceived: false,
    sessionFileValidated: false,
    sessionReused: false,
    earlyDataAccepted: false,
    earlyPayloadBytes: 0,
    postHandshakeBytesSent: 0,
    secretFileValidated: false,
    rawConfigurationRetained: false,
    rawSessionRetained: false,
    rawPayloadRetained: false,
    rawSecretRetained: false,
    secretDigestRetained: false,
  };
}

function clientArgs(config) {
  return [
    "s_client",
    "-connect", `${config.pinnedIPv4}:${config.port}`,
    "-servername", config.hostname,
    "-verify_hostname", config.hostname,
    "-verify_return_error",
    "-tls1_3",
    "-no_ign_eof",
  ];
}

async function bootstrap(config) {
  await mkdir(dirname(config.sessionPath), { recursive: true, mode: 0o700 });
  await chmod(dirname(config.sessionPath), 0o700);
  await unlink(config.sessionPath).catch((error) => { if (error?.code !== "ENOENT") throw error; });
  const result = await runOpenSsl(config.opensslBin,
    [...clientArgs(config), "-sess_out", config.sessionPath], config.timeoutMs, true);
  const parsed = parseSbx042OpenSslOutput(result.output);
  let session;
  try { session = await sessionEvidence(config.opensslBin, config.sessionPath); } catch { session = undefined; }
  return {
    ...baseEvidence(config),
    timedOut: result.timedOut,
    tcpConnected: parsed.tcpConnected,
    tlsEstablished: parsed.tlsEstablished,
    verificationPassed: parsed.verificationPassed,
    sessionTicketReceived: parsed.sessionTicketReceived,
    sessionFileValidated: session !== undefined,
    ...(session ? { sessionFileMode: session.mode, sessionBytes: session.bytes, maxEarlyData: session.maxEarlyData } : {}),
    processExitCode: result.code ?? -1,
    ...(parsed.connectErrno === undefined ? {} : { connectErrno: parsed.connectErrno }),
  };
}

async function fresh(config) {
  const result = await runOpenSsl(config.opensslBin, clientArgs(config), config.timeoutMs);
  const parsed = parseSbx042OpenSslOutput(result.output);
  return {
    ...baseEvidence(config),
    timedOut: result.timedOut,
    tcpConnected: parsed.tcpConnected,
    tlsEstablished: parsed.tlsEstablished,
    verificationPassed: parsed.verificationPassed,
    processExitCode: result.code ?? -1,
    ...(parsed.connectErrno === undefined ? {} : { connectErrno: parsed.connectErrno }),
  };
}

async function early(config) {
  let secret;
  let frame;
  let secretMode;
  try {
    if (config.stage === "secret") {
      const state = await lstat(config.secretPath);
      if (!state.isFile() || state.isSymbolicLink() || state.size !== 32 || (state.mode & 0o777) !== 0o600) {
        throw new Error("operator secret failed exact regular-file mode-0600 validation");
      }
      secretMode = state.mode & 0o777;
      secret = await readFile(config.secretPath);
      await unlink(config.secretPath);
      frame = buildSbx042EarlyFrame(config, secret);
    } else {
      frame = buildSbx042EarlyFrame(config, config.publicCanary);
    }
    await writeFile(config.earlyDataPath, frame, { flag: "wx", mode: 0o600 });
    const session = await sessionEvidence(config.opensslBin, config.sessionPath);
    if ((session.maxEarlyData ?? 0) < frame.length) throw new Error("ticket does not authorize enough early data");
    const result = await runOpenSsl(config.opensslBin,
      [...clientArgs(config), "-sess_in", config.sessionPath, "-early_data", config.earlyDataPath], config.timeoutMs);
    const parsed = parseSbx042OpenSslOutput(result.output);
    return {
      ...baseEvidence(config),
      timedOut: result.timedOut,
      tcpConnected: parsed.tcpConnected,
      tlsEstablished: parsed.tlsEstablished,
      verificationPassed: parsed.verificationPassed,
      sessionFileValidated: true,
      sessionFileMode: session.mode,
      sessionBytes: session.bytes,
      maxEarlyData: session.maxEarlyData,
      sessionReused: parsed.sessionReused,
      earlyDataAccepted: parsed.earlyDataAccepted,
      earlyPayloadBytes: frame.length,
      secretFileValidated: config.stage === "secret",
      ...(secretMode === undefined ? {} : { secretFileMode: secretMode }),
      processExitCode: result.code ?? -1,
      ...(parsed.connectErrno === undefined ? {} : { connectErrno: parsed.connectErrno }),
    };
  } finally {
    if (secret) secret.fill(0);
    if (frame) frame.fill(0);
    await unlink(config.earlyDataPath).catch((error) => { if (error?.code !== "ENOENT") throw error; });
    await unlink(config.sessionPath).catch((error) => { if (error?.code !== "ENOENT") throw error; });
    if (config.stage === "secret") {
      await unlink(config.secretPath).catch((error) => { if (error?.code !== "ENOENT") throw error; });
    }
  }
}

export async function runSbx042Probe(raw) {
  const config = validateSbx042ProbeConfiguration(raw);
  if (config.mode === "bootstrap") return bootstrap(config);
  if (config.mode === "fresh") return fresh(config);
  return early(config);
}

async function main() {
  let evidence;
  try {
    if (process.argv.length !== 3) throw new Error("expected one base64url configuration argument");
    const raw = JSON.parse(Buffer.from(process.argv[2], "base64url").toString("utf8"));
    evidence = await runSbx042Probe(raw);
  } catch (error) {
    evidence = {
      schemaVersion: 1,
      testId: TEST_ID,
      ok: false,
      errorCode: error?.code ?? "PROBE_ERROR",
      rawConfigurationRetained: false,
      rawSessionRetained: false,
      rawPayloadRetained: false,
      rawSecretRetained: false,
      secretDigestRetained: false,
    };
  }
  process.stdout.write(`${JSON.stringify(evidence)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
