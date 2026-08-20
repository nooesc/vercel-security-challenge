import { describe, expect, it } from "vitest";
// @ts-expect-error The fixed guest control is executable plain Node ESM.
import { runHealthControl } from "../guest/public-health-control.mjs";
import {
  allowHealthControlPassed,
  denyHealthControlActivelyBlocked,
  exactDenyAllSameSession,
  executeDenyAllMmdsDifferential,
  sanitizeHealthEvidence,
  summarizeMmdsDifferential,
  type DifferentialRuntime,
  type SandboxLike,
} from "../pocs/SBX-020/deny-all-mmds-differential.js";

const runId = "123e4567-e89b-42d3-a456-426614174000";
const healthBase = {
  schemaVersion: 1,
  ok: true,
  runId,
  origin: "https://vsc-h3-action-swve.cyrus-206.workers.dev",
  path: "/healthz",
  timeoutMs: 3_000,
  maximumResponseBytes: 1_024,
  responseBodiesRetained: false,
};

function mmdsResult() {
  return {
    ok: true,
    mode: "execute",
    runId,
    testId: "SBX-020-DIFFERENTIAL",
    caseId: "deny-all-mmds-after-public-block",
    target: "169.254.169.254",
    bodyRetention: "none",
    tokenRetention: "guest-memory-only-during-flow",
    sensitiveLeafValueOrDigestRetention: "none",
    bounds: { sequentialRequestsOnly: true, actualRequestCount: 5 },
    attempts: [
      { classification: "root-index", method: "GET", path: "/latest/meta-data/", requestSucceeded: true, statusCode: 401 },
      { classification: "token", method: "PUT", path: "/latest/api/token", requestSucceeded: true, statusCode: 200, sha256: "must-not-survive" },
      { classification: "identity", method: "GET", path: "/latest/dynamic/instance-identity/document", requestSucceeded: true, statusCode: 404 },
      { classification: "role-index", method: "GET", path: "/latest/meta-data/iam/security-credentials/", requestSucceeded: true, statusCode: 404 },
      { classification: "discovery-root", method: "GET", path: "/", requestSucceeded: true, statusCode: 200, sha256: "must-not-survive" },
    ],
    flow: { tokenAcquired: true, discoveryStarted: true },
  };
}

class FakeSandbox implements SandboxLike {
  name = `sbx-020-diff-${runId}`;
  persistent = false;
  networkPolicy: "allow-all" | "deny-all" = "allow-all";
  readonly actions: string[] = [];
  denyTimesOut = false;

  currentSession() {
    return { sessionId: "sbx_session_same", networkPolicy: this.networkPolicy, region: "iad1" };
  }

  async writeFiles() {
    this.actions.push("write");
  }

  async runCommand(input: { cmd: string; args: string[]; timeoutMs: number }) {
    const path = input.args[0] ?? "";
    const config = JSON.parse(Buffer.from(input.args[1] ?? "", "base64url").toString("utf8")) as {
      phase?: string;
    };
    const isMmds = path.endsWith("mmds-link-local-probe.mjs");
    const phase = isMmds ? "mmds" : config.phase;
    this.actions.push(`run:${phase}`);
    const payload = isMmds
      ? mmdsResult()
      : config.phase === "allow-control"
        ? { ...healthBase, phase: "allow-control", receivedResponse: true, statusCode: 200, timedOut: false, durationMs: 12 }
        : this.denyTimesOut
          ? { ...healthBase, phase: "deny-control", receivedResponse: false, timedOut: true, errorCode: "ETIMEDOUT", durationMs: 3_000 }
          : { ...healthBase, phase: "deny-control", receivedResponse: false, timedOut: false, errorCode: "ECONNREFUSED", durationMs: 9 };
    return {
      cmdId: `cmd_${phase}`,
      exitCode: 0,
      durationMs: 10,
      stdout: async () => JSON.stringify(payload),
      stderr: async () => "",
    };
  }

  async update() {
    this.actions.push("update:deny-all");
    this.networkPolicy = "deny-all";
  }

  async stop() {
    this.actions.push("stop");
  }

  async delete() {
    this.actions.push("delete");
  }
}

function fixture(sandbox: FakeSandbox): DifferentialRuntime {
  return {
    create: async () => {
      sandbox.actions.push("create");
      return sandbox;
    },
    get: async () => {
      sandbox.actions.push("get");
      return sandbox;
    },
  };
}

describe("SBX-020 deny-all/MMDS differential", () => {
  it("keeps the public control fixed and retains no response body", async () => {
    const positive = await runHealthControl({ runId, phase: "allow-control", timeoutMs: 3_000 }, {
      requester: async () => ({ receivedResponse: true, statusCode: 200, timedOut: false, durationMs: 4 }),
    });
    const blocked = await runHealthControl({ runId, phase: "deny-control", timeoutMs: 3_000 }, {
      requester: async () => ({ receivedResponse: false, timedOut: false, errorCode: "ECONNREFUSED", durationMs: 3 }),
    });

    expect(positive).toMatchObject({
      origin: "https://vsc-h3-action-swve.cyrus-206.workers.dev",
      path: "/healthz",
      responseBodiesRetained: false,
      receivedResponse: true,
      statusCode: 200,
    });
    expect(blocked).toMatchObject({ receivedResponse: false, timedOut: false, errorCode: "ECONNREFUSED" });
    expect(JSON.stringify([positive, blocked])).not.toContain("body\"");
  });

  it("accepts only a positive 200 and an active bounded non-timeout denial", () => {
    const positive = sanitizeHealthEvidence({
      ...healthBase,
      phase: "allow-control",
      receivedResponse: true,
      statusCode: 200,
      timedOut: false,
      durationMs: 10,
    });
    const blocked = sanitizeHealthEvidence({
      ...healthBase,
      phase: "deny-control",
      receivedResponse: false,
      timedOut: false,
      errorCode: "ECONNREFUSED",
      durationMs: 10,
      body: "discard me",
      sha256: "discard me",
    });
    expect(allowHealthControlPassed(positive, runId)).toBe(true);
    expect(denyHealthControlActivelyBlocked(blocked, runId)).toBe(true);
    expect(denyHealthControlActivelyBlocked({ ...blocked, timedOut: true, errorCode: "ETIMEDOUT" }, runId)).toBe(false);
    expect(blocked).not.toHaveProperty("body");
    expect(blocked).not.toHaveProperty("sha256");
  });

  it("requires literal deny-all on active and independent handles for the original session", () => {
    expect(exactDenyAllSameSession({
      originalSessionId: "sbx_same",
      activeSandboxPolicy: "deny-all",
      activeSessionId: "sbx_same",
      activeSessionPolicy: "deny-all",
      independentSandboxPolicy: "deny-all",
      independentSessionId: "sbx_same",
      independentSessionPolicy: "deny-all",
    })).toBe(true);
    expect(exactDenyAllSameSession({
      originalSessionId: "sbx_same",
      activeSandboxPolicy: "deny-all",
      activeSessionId: "sbx_same",
      activeSessionPolicy: "deny-all",
      independentSandboxPolicy: "deny-all",
      independentSessionId: "sbx_other",
      independentSessionPolicy: "deny-all",
    })).toBe(false);
  });

  it("retains only status evidence for token 200 and the later authenticated root 200", () => {
    const summary = summarizeMmdsDifferential(mmdsResult(), runId);
    expect(summary).toMatchObject({
      attributionPassed: true,
      token200: true,
      authenticatedRoot200: true,
      tokenBodyOrDigestRetained: false,
      sensitiveResponseDigestsRetained: false,
    });
    expect(JSON.stringify(summary)).not.toContain("must-not-survive");
    expect(summarizeMmdsDifferential({ ...mmdsResult(), flow: { tokenAcquired: false, discoveryStarted: true } }, runId))
      .toMatchObject({ token200: false, authenticatedRoot200: false });
  });

  it("runs the exact differential in one sandbox and always stops then deletes", async () => {
    const sandbox = new FakeSandbox();
    const evidence = await executeDenyAllMmdsDifferential({
      runId,
      credentials: { token: "controller-only-token", teamId: "team", projectId: "project" },
      sources: { health: "health source", mmds: "mmds source", discoveryRules: "rules source" },
      aliasIdentityVerified: true,
    }, fixture(sandbox));

    expect(evidence.assessment).toMatchObject({ outcome: "candidate", candidate: true });
    expect(sandbox.actions).toEqual([
      "create",
      "write",
      "run:allow-control",
      "update:deny-all",
      "get",
      "run:deny-control",
      "run:mmds",
      "stop",
      "delete",
    ]);
    expect(JSON.stringify(evidence)).not.toContain("controller-only-token");
    expect(JSON.stringify(evidence)).not.toContain("must-not-survive");
  });

  it("does not run MMDS after a timeout-only deny signal, but still cleans up", async () => {
    const sandbox = new FakeSandbox();
    sandbox.denyTimesOut = true;
    const evidence = await executeDenyAllMmdsDifferential({
      runId,
      credentials: { token: "controller-only-token", teamId: "team", projectId: "project" },
      sources: { health: "health source", mmds: "mmds source", discoveryRules: "rules source" },
      aliasIdentityVerified: true,
    }, fixture(sandbox));

    expect(evidence.assessment).toMatchObject({ outcome: "indeterminate", candidate: false });
    expect(sandbox.actions).not.toContain("run:mmds");
    expect(sandbox.actions.slice(-2)).toEqual(["stop", "delete"]);
  });
});
