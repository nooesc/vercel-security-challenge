import { createHash } from "node:crypto";
import { request as httpRequest } from "node:http";
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

async function requestWithHost(url: string, host: string): Promise<{ status: number; body: string }> {
  const parsed = new URL(url);
  return new Promise((resolve, reject) => {
    const request = httpRequest({
      hostname: parsed.hostname,
      port: parsed.port,
      path: `${parsed.pathname}${parsed.search}`,
      headers: { host },
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      response.on("end", () => resolve({
        status: response.statusCode ?? 0,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    request.on("error", reject);
    request.end();
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
    const response = await fetch(`${observer.baseUrl}/arbitrary/outside?${query}`, {
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
      normalizedPath: "/arbitrary/outside",
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

  it("executes the explicit outside action only with the controller-registered credential", async () => {
    const { observer } = await start();
    const runId = "run-action-001";
    const brokeredSecret = "brokered-test-secret-at-least-24-characters";
    const adminHeaders = { authorization: `Bearer ${ADMIN_KEY}` };
    expect(
      (
        await fetch(`${observer.baseUrl}/v1/runs/${runId}/action-config`, {
          method: "POST",
          headers: { "x-observer-action-secret": brokeredSecret },
        })
      ).status,
    ).toBe(401);
    expect(
      (
        await fetch(`${observer.baseUrl}/v1/runs/${runId}/actions`, {
          headers: { authorization: "Bearer incorrect-key" },
        })
      ).status,
    ).toBe(401);
    const registration = await fetch(`${observer.baseUrl}/v1/runs/${runId}/action-config`, {
      method: "POST",
      headers: {
        ...adminHeaders,
        "x-observer-action-secret": brokeredSecret,
      },
    });
    expect(registration.status).toBe(201);
    const query = new URLSearchParams({
      __sbx_run: runId,
      __sbx_test: "SBX-013-POC",
      __sbx_case: "outside-control",
      __sbx_canary: "non-secret-correlation-value",
    });
    const outsideUrl = `${observer.baseUrl}/v1/probe/${runId}/outside?${query}`;
    const denied = await fetch(outsideUrl);
    expect(denied.status).toBe(401);
    await expect(denied.json()).resolves.toMatchObject({ authorized: false });

    query.set("__sbx_case", "encoded-dotdot");
    const authorized = await fetch(`${observer.baseUrl}/v1/probe/${runId}/outside?${query}`, {
      headers: { "x-sbx-harness-canary": brokeredSecret },
    });
    expect(authorized.status).toBe(200);
    const actionResponse = (await authorized.json()) as { authorized: boolean; operationId: string };
    expect(actionResponse.authorized).toBe(true);
    expect(actionResponse.operationId).toMatch(/^op_[A-Za-z0-9_-]+$/);

    const actionQuery = await fetch(`${observer.baseUrl}/v1/runs/${runId}/actions`, {
      headers: adminHeaders,
    });
    expect(actionQuery.status).toBe(200);
    await expect(actionQuery.json()).resolves.toEqual({
      actions: [
        expect.objectContaining({
          operationId: actionResponse.operationId,
          caseId: "encoded-dotdot",
          normalizedPath: `/v1/probe/${runId}/outside`,
        }),
      ],
    });
  });

  it("serves only an authenticated, controller-configured HTTPS redirect", async () => {
    const { observer } = await start();
    const runId = "run-redirect-001";
    const redirectTarget = "https://controlled-b.example/v1/probe/run-redirect-001/target";
    expect(
      (
        await fetch(`${observer.baseUrl}/v1/runs/${runId}/redirect-config`, {
          method: "POST",
          headers: { "x-observer-redirect-target": redirectTarget },
        })
      ).status,
    ).toBe(401);
    expect(
      (
        await fetch(`${observer.baseUrl}/v1/runs/${runId}/redirect-config`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${ADMIN_KEY}`,
            "x-observer-redirect-target": "http://insecure.example/target",
          },
        })
      ).status,
    ).toBe(400);
    const registration = await fetch(`${observer.baseUrl}/v1/runs/${runId}/redirect-config`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${ADMIN_KEY}`,
        "x-observer-redirect-target": redirectTarget,
      },
    });
    expect(registration.status).toBe(201);

    const query = new URLSearchParams({
      __sbx_run: runId,
      __sbx_test: "SBX-007",
      __sbx_case: "redirect-source",
      __sbx_canary: "redirect-correlation",
    });
    const redirect = await fetch(`${observer.baseUrl}/v1/probe/${runId}/redirect?${query}`, {
      redirect: "manual",
    });
    expect(redirect.status).toBe(302);
    expect(redirect.headers.get("location")).toBe(redirectTarget);

    const deletion = await fetch(`${observer.baseUrl}/v1/runs/${runId}/redirect-config`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    });
    expect(deletion.status).toBe(204);
    expect(
      (
        await fetch(`${observer.baseUrl}/v1/probe/${runId}/redirect?${query}`, {
          redirect: "manual",
        })
      ).status,
    ).toBe(404);
  });

  it("executes a vhost-specific action only when the observed Host selects it", async () => {
    const { observer } = await start();
    const runId = "run-vhost-001";
    const vhostSecret = "vhost-test-secret-at-least-24-characters";
    const adminHeaders = { authorization: `Bearer ${ADMIN_KEY}` };
    const registration = await fetch(`${observer.baseUrl}/v1/runs/${runId}/vhost-config`, {
      method: "POST",
      headers: {
        ...adminHeaders,
        "x-observer-vhost": "b.controlled.example:443",
        "x-observer-action-secret": vhostSecret,
      },
    });
    expect(registration.status).toBe(201);

    const query = new URLSearchParams({
      __sbx_run: runId,
      __sbx_test: "SBX-008",
      __sbx_case: "sni-a-host-a",
      __sbx_canary: "vhost-correlation",
    });
    const path = `/v1/probe/${runId}/vhost-action?${query}`;
    const wrongVhost = await requestWithHost(new URL(path, observer.baseUrl).toString(), "a.controlled.example");
    expect(wrongVhost.status).toBe(421);
    expect(JSON.parse(wrongVhost.body)).toMatchObject({ selected: false });

    query.set("__sbx_case", "sni-a-host-b-no-credential");
    const selectedButUnauthorized = await requestWithHost(
      new URL(`/v1/probe/${runId}/vhost-action?${query}`, observer.baseUrl).toString(),
      "b.controlled.example",
    );
    expect(selectedButUnauthorized.status).toBe(401);
    expect(JSON.parse(selectedButUnauthorized.body)).toMatchObject({
      selected: true,
      authorized: false,
    });

    query.set("__sbx_case", "sni-a-host-b");
    const authorizedUrl = new URL(`/v1/probe/${runId}/vhost-action?${query}`, observer.baseUrl);
    const selected = await new Promise<{ status: number; body: string }>((resolve, reject) => {
      const request = httpRequest({
        hostname: authorizedUrl.hostname,
        port: authorizedUrl.port,
        path: `${authorizedUrl.pathname}${authorizedUrl.search}`,
        headers: {
          host: "b.controlled.example",
          "x-sbx-harness-canary": vhostSecret,
        },
      }, (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
        response.on("end", () => resolve({
          status: response.statusCode ?? 0,
          body: Buffer.concat(chunks).toString("utf8"),
        }));
      });
      request.on("error", reject);
      request.end();
    });
    expect(selected.status).toBe(200);
    const selectedBody = JSON.parse(selected.body) as { selected: boolean; operationId: string };
    expect(selectedBody).toMatchObject({ selected: true, authorized: true });
    expect(selectedBody.operationId).toMatch(/^vhost_[A-Za-z0-9_-]+$/);

    const actions = await fetch(`${observer.baseUrl}/v1/runs/${runId}/vhost-actions`, {
      headers: adminHeaders,
    });
    await expect(actions.json()).resolves.toEqual({
      actions: [
        expect.objectContaining({
          operationId: selectedBody.operationId,
          caseId: "sni-a-host-b",
        }),
      ],
    });
  });

  it("keeps forwarded proxy authentication server-side and scrubs supplied OIDC tokens", async () => {
    const { observer } = await start();
    const runId = "run-proxy-001";
    const adminHeaders = { authorization: `Bearer ${ADMIN_KEY}` };
    const actionUrl = "https://b.controlled.example/v1/probe/run-proxy-001/forwarded-action";
    const fakeOidc = "guest-supplied-invalid-oidc-value";
    const registration = await fetch(`${observer.baseUrl}/v1/runs/${runId}/proxy-config`, {
      method: "POST",
      headers: {
        ...adminHeaders,
        "x-observer-proxy-action-url": actionUrl,
        "x-observer-proxy-fake-oidc-sha256": createHash("sha256").update(fakeOidc).digest("hex"),
      },
    });
    expect(registration.status).toBe(201);
    const configuration = await fetch(`${observer.baseUrl}/v1/runs/${runId}/proxy-config`, {
      headers: adminHeaders,
    });
    await expect(configuration.json()).resolves.toEqual({ configured: true, actionUrl });

    const proxyAttempt = await fetch(`${observer.baseUrl}/v1/proxy/${runId}/forward`, {
      headers: {
        host: "proxy.controlled.example",
        "x-sbx-forward-case": "fake-oidc-control",
        "x-sbx-harness-canary": "proxy-correlation",
        "vercel-forwarded-host": "a.controlled.example",
        "vercel-forwarded-scheme": "https",
        "vercel-forwarded-port": "443",
        "vercel-forwarded-path": "/v1/probe/run-proxy-001/source",
        "vercel-sandbox-oidc-token": fakeOidc,
      },
    });
    expect(proxyAttempt.status).toBe(403);
    const attemptBody = (await proxyAttempt.json()) as {
      authenticated: boolean;
      actionAuthorized: boolean;
      operationId: string;
    };
    expect(attemptBody).toMatchObject({ authenticated: false, actionAuthorized: false });
    expect(attemptBody.operationId).toMatch(/^proxy_[A-Za-z0-9_-]+$/);

    const records = await fetch(`${observer.baseUrl}/v1/runs/${runId}/proxy-actions`, {
      headers: adminHeaders,
    });
    expect(records.status).toBe(200);
    await expect(records.json()).resolves.toEqual({
      records: [
        expect.objectContaining({
          operationId: attemptBody.operationId,
          caseId: "fake-oidc-control",
          authenticated: false,
          actionAuthorized: false,
          invalidReasonCode: "oidc-verification-failed",
          rawHeaderAudit: expect.objectContaining({
            caseId: "fake-oidc-control",
            caseHeaderCount: 1,
            caseIdMatched: true,
            oidcHeaderCount: 1,
            oidcValueCount: 1,
            guestFakeOidcObserved: true,
            intermediaryOrderTrusted: false,
          }),
        }),
      ],
    });

    const eventResponse = await events(observer.baseUrl, runId);
    const payload = (await eventResponse.json()) as { events: ObserverEvent[] };
    expect(payload.events).toHaveLength(1);
    expect(payload.events[0]?.headers["vercel-sandbox-oidc-token"]).toBeUndefined();
    expect(payload.events[0]?.rawHeaders.join("\n")).not.toContain(fakeOidc);

    const deletion = await fetch(`${observer.baseUrl}/v1/runs/${runId}/proxy-config`, {
      method: "DELETE",
      headers: adminHeaders,
    });
    expect(deletion.status).toBe(204);
    const afterDeletion = await fetch(`${observer.baseUrl}/v1/runs/${runId}/proxy-actions`, {
      headers: adminHeaders,
    });
    await expect(afterDeletion.json()).resolves.toEqual({ records: [] });
    const configAfterDeletion = await fetch(`${observer.baseUrl}/v1/runs/${runId}/proxy-config`, {
      headers: adminHeaders,
    });
    await expect(configAfterDeletion.json()).resolves.toEqual({ configured: false });
  });

  it("keeps the controlled policy-update endpoint alive with explicit framing", async () => {
    const { observer } = await start();
    const query = new URLSearchParams({
      __sbx_run: "policy-run",
      __sbx_test: "SBX-018-POC",
      __sbx_case: "existing-tls-after-deny",
      __sbx_canary: "policy-correlation",
    });
    const response = await fetch(
      `${observer.baseUrl}/v1/probe/policy-run/policy-update?${query}`,
    );
    expect(response.status).toBe(204);
    expect(response.headers.get("content-length")).toBe("0");
    expect(response.headers.get("connection")).toBe("keep-alive");
    expect(response.headers.get("keep-alive")).toBe("timeout=60");
    const multiResponse = await fetch(
      `${observer.baseUrl}/v1/probe/policy-run/policy-update-multi?${query}`,
    );
    expect(multiResponse.status).toBe(204);
    expect(multiResponse.headers.get("content-length")).toBe("0");
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
