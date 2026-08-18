import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { startObserverServer, type RunningObserverServer } from "../src/observer-server.js";
import type { ObserverEvent } from "../src/contracts.js";

const ADMIN_KEY = "observer-test-admin-key-at-least-24-characters";
const opened: RunningObserverServer[] = [];
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(opened.splice(0).map((observer) => observer.close()));
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

async function start(maxBodyBytes?: number): Promise<{ observer: RunningObserverServer; dataPath: string }> {
  const directory = await mkdtemp(join(tmpdir(), "vsc-observer-"));
  temporaryDirectories.push(directory);
  const dataPath = join(directory, "events.jsonl");
  const observer = await startObserverServer({
    adminKey: ADMIN_KEY,
    dataPath,
    ...(maxBodyBytes === undefined ? {} : { maxBodyBytes }),
  });
  opened.push(observer);
  return { observer, dataPath };
}

async function events(baseUrl: string, runId: string, key = ADMIN_KEY): Promise<Response> {
  return fetch(`${baseUrl}/v1/runs/${encodeURIComponent(runId)}/events`, {
    headers: { authorization: `Bearer ${key}` },
  });
}

describe("controlled observer", () => {
  it("reports health without authentication", async () => {
    const { observer } = await start();
    const response = await fetch(`${observer.baseUrl}/healthz`);
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ ok: true });
  });

  it("records probe evidence while scrubbing credential-bearing headers", async () => {
    const { observer, dataPath } = await start();
    const body = "bounded evidence body";
    const query = new URLSearchParams({
      __sbx_run: "run-001",
      __sbx_test: "SBX-004",
      __sbx_case: "trailing-dot",
      __sbx_canary: "canary-value",
    });
    const response = await fetch(`${observer.baseUrl}/arbitrary/probe?${query}`, {
      method: "POST",
      headers: {
        authorization: "Bearer do-not-record",
        cookie: "session=do-not-record",
        "x-api-key": "do-not-record",
        "x-sbx-harness-canary": "canary-value",
        "x-safe-observation": "keep-me",
      },
      body,
    });
    expect(response.status).toBe(204);

    expect((await events(observer.baseUrl, "run-001", "incorrect-key")).status).toBe(401);
    expect((await fetch(`${observer.baseUrl}/v1/runs/run-001/events`)).status).toBe(401);

    const eventResponse = await events(observer.baseUrl, "run-001");
    expect(eventResponse.status).toBe(200);
    const payload = (await eventResponse.json()) as { events: ObserverEvent[] };
    expect(payload.events).toHaveLength(1);
    const event = payload.events[0];
    expect(event).toMatchObject({
      schemaVersion: 1,
      runId: "run-001",
      testId: "SBX-004",
      caseId: "trailing-dot",
      canary: "canary-value",
      method: "POST",
      bodyLength: Buffer.byteLength(body),
      bodySha256: createHash("sha256").update(body).digest("hex"),
    });
    expect(event?.headers["x-sbx-harness-canary"]).toBe("canary-value");
    expect(event?.headers["x-safe-observation"]).toBe("keep-me");
    expect(event?.headers.authorization).toBeUndefined();
    expect(event?.headers.cookie).toBeUndefined();
    expect(event?.headers["x-api-key"]).toBeUndefined();
    expect(event?.rawHeaders.join("\n")).not.toContain("do-not-record");

    const lines = (await readFile(dataPath, "utf8")).trim().split("\n");
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0] ?? "{}")).toEqual(event);
  });

  it("isolates event queries by run and rejects oversized probe bodies", async () => {
    const { observer } = await start(8);
    const baseQuery = {
      __sbx_test: "SBX-001",
      __sbx_case: "deny-all",
      __sbx_canary: "bounded-canary",
    };
    const first = new URLSearchParams({ __sbx_run: "run-a", ...baseQuery });
    const second = new URLSearchParams({ __sbx_run: "run-b", ...baseQuery });

    expect((await fetch(`${observer.baseUrl}/probe?${first}`)).status).toBe(204);
    expect(
      (
        await fetch(`${observer.baseUrl}/probe?${second}`, {
          method: "POST",
          body: "body-larger-than-eight-bytes",
        })
      ).status,
    ).toBe(413);

    const runA = (await (await events(observer.baseUrl, "run-a")).json()) as { events: ObserverEvent[] };
    const runB = (await (await events(observer.baseUrl, "run-b")).json()) as { events: ObserverEvent[] };
    expect(runA.events.map((event) => event.runId)).toEqual(["run-a"]);
    expect(runB.events.map((event) => event.runId)).toEqual(["run-b"]);
    expect(runB.events[0]?.bodyLength).toBeGreaterThan(8);
  });

  it("does not record requests missing any required probe coordinate", async () => {
    const { observer } = await start();
    const response = await fetch(`${observer.baseUrl}/probe?__sbx_run=partial-run&__sbx_test=SBX-001`);
    expect(response.status).toBe(404);
    const payload = (await (await events(observer.baseUrl, "partial-run")).json()) as { events: ObserverEvent[] };
    expect(payload.events).toEqual([]);
  });
});
