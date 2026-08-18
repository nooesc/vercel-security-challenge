import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { HttpObserverClient } from "../src/observer-client.js";
import { startObserverServer } from "../src/observer-server.js";

const executeFile = promisify(execFile);
const guestProbe = fileURLToPath(new URL("../guest/http-probe.mjs", import.meta.url));
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

describe("guest HTTP probe", () => {
  it("preserves the raw request path and produces an independently readable observer event", async () => {
    const directory = await mkdtemp(join(tmpdir(), "vsc-guest-probe-"));
    temporaryDirectories.push(directory);
    const adminKey = "test-admin-key-with-more-than-24-characters";
    const observer = await startObserverServer({
      adminKey,
      dataPath: join(directory, "events.jsonl"),
    });

    try {
      const payload = Buffer.from(
        JSON.stringify({
          baseUrl: observer.baseUrl,
          runId: "run-wire-test",
          testId: "SBX-013",
          caseId: "literal-dotdot",
          canary: "sbx_wire_canary",
          method: "GET",
          rawPath: "/v1/probe/run-wire-test/matched/../outside?tier=test",
          headers: { "x-sbx-harness-canary": "sbx_wire_canary" },
          timeoutMs: 2_000,
        }),
      ).toString("base64url");

      const result = await executeFile(process.execPath, [guestProbe, payload]);
      const guestResult = JSON.parse(result.stdout) as { ok: boolean; statusCode: number; body: string };
      expect(guestResult).toMatchObject({ ok: true, statusCode: 401 });
      expect(JSON.parse(guestResult.body)).toMatchObject({
        authorized: false,
        normalizedPath: "/v1/probe/run-wire-test/outside",
      });

      const client = new HttpObserverClient(observer.baseUrl, adminKey);
      const events = await client.events("run-wire-test");
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({
        testId: "SBX-013",
        caseId: "literal-dotdot",
        canary: "sbx_wire_canary",
        method: "GET",
        normalizedPath: "/v1/probe/run-wire-test/outside",
      });
      expect(events[0]?.rawUrl).toContain("/matched/../outside?tier=test&");
      expect(events[0]?.headers["x-sbx-harness-canary"]).toBe("sbx_wire_canary");
    } finally {
      await observer.close();
    }
  });
});
