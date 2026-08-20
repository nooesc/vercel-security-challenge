import { readFile } from "node:fs/promises";
import { Sandbox } from "@vercel/sandbox";
import { describe, expect, it } from "vitest";

const offlineToken = "offline_fake_pat_used_only_by_injected_fetch";
const teamId = "team_n98ERpVwV7HqmWRudAyK8sXQ";
const projectId = "prj_CyyVykdN06Nrkla6KidZcecLgbCa";
const sessionId = "sbx_offline_interactive_session_051";
const sandboxName = "sbx-051-a-00000000-0000-4000-8000-000000000051";
const tags = {
  harness: "vsc",
  test: "SBX-051-INTERACTIVE-TOKEN-BINDING",
  run: "00000000-0000-4000-8000-000000000051",
  role: "A",
};

interface CapturedRequest {
  url: URL;
  method: string;
  headers: Headers;
  body: string;
}

function createResponsePayload(): Record<string, unknown> {
  const now = Date.now();
  return {
    sandbox: {
      name: sandboxName,
      persistent: false,
      createdAt: now,
      updatedAt: now,
      currentSessionId: sessionId,
      status: "running",
      networkPolicy: { mode: "deny-all" },
      tags,
    },
    session: {
      id: sessionId,
      memory: 4_096,
      vcpus: 2,
      region: "iad1",
      timeout: 240_000,
      status: "running",
      requestedAt: now,
      startedAt: now,
      createdAt: now,
      cwd: "/vercel/sandbox",
      updatedAt: now,
      interactivePort: 7681,
      networkPolicy: { mode: "deny-all" },
    },
    routes: [{
      url: "https://offline-interactive.vercel.run",
      subdomain: "offline-interactive",
      port: 7681,
    }],
  };
}

async function captureCreateAndInteractive(): Promise<{
  requests: CapturedRequest[];
  credential: { url: string; token: string };
  interactivePort: number | undefined;
}> {
  const requests: CapturedRequest[] = [];
  const fakeFetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : input.toString());
    requests.push({
      url,
      method: init?.method ?? "GET",
      headers: new Headers(init?.headers),
      body: typeof init?.body === "string" ? init.body : "",
    });
    const payload = url.pathname.endsWith("/interactive")
      ? {
          url: "wss://offline-controller.vercel.run/pty/offline-session",
          token: "offline_ephemeral_interactive_token_never_sent",
        }
      : createResponsePayload();
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;

  const sandbox = await Sandbox.create({
    token: offlineToken,
    teamId,
    projectId,
    fetch: fakeFetch,
    name: sandboxName,
    persistent: false,
    timeout: 240_000,
    resources: { vcpus: 2 },
    ports: [],
    networkPolicy: "deny-all",
    tags,
    __interactive: true,
  });
  const interactivePort = sandbox.interactivePort;
  const credential = await sandbox.currentSession().openInteractive();
  return { requests, credential, interactivePort };
}

describe("SBX-051 installed SDK and CLI interactive wire audit", () => {
  it("pins the audited SDK and CLI source snapshots", async () => {
    const sdk = JSON.parse(await readFile(
      new URL("../node_modules/@vercel/sandbox/package.json", import.meta.url),
      "utf8",
    )) as { version?: unknown };
    const cli = JSON.parse(await readFile(
      new URL("../targets/vercel-sandbox/packages/sandbox/package.json", import.meta.url),
      "utf8",
    )) as { version?: unknown; dependencies?: Record<string, string> };
    const ws = JSON.parse(await readFile(
      new URL("../infra/h3-action-worker/node_modules/ws/package.json", import.meta.url),
      "utf8",
    )) as { version?: unknown };
    expect(sdk.version).toBe("3.0.0");
    expect(cli.version).toBe("4.0.0");
    expect(cli.dependencies?.ws).toBe("^8.21.0");
    expect(ws.version).toBe("8.21.0");
  });

  it("serializes __interactive:true at creation and POSTs the pinned session endpoint", async () => {
    const { requests, credential, interactivePort } = await captureCreateAndInteractive();
    expect(requests).toHaveLength(2);

    const create = requests[0]!;
    expect(create.url.origin).toBe("https://vercel.com");
    expect(create.url.pathname).toBe("/api/v3/sandboxes");
    expect(create.url.searchParams.get("teamId")).toBe(teamId);
    expect(create.url.searchParams.has("projectId")).toBe(false);
    expect(create.method).toBe("POST");
    expect(create.headers.get("authorization")).toBe(`Bearer ${offlineToken}`);
    const createBody = JSON.parse(create.body) as Record<string, unknown>;
    expect(Object.keys(createBody).sort()).toEqual([
      "__interactive",
      "name",
      "networkPolicy",
      "persistent",
      "ports",
      "projectId",
      "resources",
      "tags",
      "timeout",
    ]);
    expect(createBody).toMatchObject({
      projectId,
      name: sandboxName,
      persistent: false,
      timeout: 240_000,
      resources: { vcpus: 2 },
      ports: [],
      networkPolicy: { mode: "deny-all" },
      tags,
      __interactive: true,
    });
    expect(Object.prototype.hasOwnProperty.call(createBody, "env")).toBe(false);
    expect(interactivePort).toBe(7681);

    const interactive = requests[1]!;
    expect(interactive.url.origin).toBe("https://vercel.com");
    expect(interactive.url.pathname).toBe(`/api/v2/sandboxes/sessions/${sessionId}/interactive`);
    expect([...interactive.url.searchParams.entries()]).toEqual([["teamId", teamId]]);
    expect(interactive.url.searchParams.get("teamId")).toBe(teamId);
    expect(interactive.url.searchParams.has("projectId")).toBe(false);
    expect(interactive.method).toBe("POST");
    expect(interactive.headers.get("authorization")).toBe(`Bearer ${offlineToken}`);
    expect(JSON.parse(interactive.body)).toEqual({});
    expect(credential).toEqual({
      url: "wss://offline-controller.vercel.run/pty/offline-session",
      token: "offline_ephemeral_interactive_token_never_sent",
    });
  });

  it("preserves an omitted named-GET route projection without losing the interactive port", async () => {
    const requests: CapturedRequest[] = [];
    const payload = createResponsePayload();
    payload.routes = [];
    const fakeFetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : input.toString());
      requests.push({
        url,
        method: init?.method ?? "GET",
        headers: new Headers(init?.headers),
        body: typeof init?.body === "string" ? init.body : "",
      });
      return Response.json(payload);
    }) as typeof fetch;

    const independent = await Sandbox.get({
      token: offlineToken,
      teamId,
      projectId,
      fetch: fakeFetch,
      name: sandboxName,
      resume: false,
      __interactive: true,
    });

    expect(requests).toHaveLength(1);
    expect(requests[0]!.url.pathname).toBe(`/api/v2/sandboxes/${sandboxName}`);
    expect(Object.fromEntries(requests[0]!.url.searchParams)).toEqual({
      teamId,
      projectId,
      resume: "false",
      __interactive: "true",
    });
    expect(independent.currentSession().sessionId).toBe(sessionId);
    expect(independent.interactivePort).toBe(7681);
    expect(independent.routes).toEqual([]);
  });

  it("pins the CLI token transport and one start-frame schema", async () => {
    const interactiveSource = await readFile(
      new URL(
        "../targets/vercel-sandbox/packages/sandbox/src/interactive-shell/interactive-shell.ts",
        import.meta.url,
      ),
      "utf8",
    );
    const createSource = await readFile(
      new URL("../targets/vercel-sandbox/packages/sandbox/src/commands/create.ts", import.meta.url),
      "utf8",
    );

    expect(interactiveSource).toContain(
      "const { url, token } = await options.sandbox.openInteractive();",
    );
    expect(interactiveSource).toContain('import { WebSocket } from "ws";');
    expect(interactiveSource).toContain(
      "const client = new WebSocket(`${url}?token=${encodeURIComponent(token)}`);",
    );
    for (const fragment of [
      'type: "start"',
      "command: execution[0]",
      "args: execution.slice(1)",
      "env: toEnvArray",
      "cwd: options.cwd ?? options.sandbox.cwd",
      "cols: process.stdout.columns",
      "rows: process.stdout.rows",
      'if (msg.type === "exit")',
      'process.exitCode = typeof msg.code === "number" ? msg.code : undefined',
    ] as const) {
      expect(interactiveSource).toContain(fragment);
    }
    expect(interactiveSource).toContain("if (isBinary)");
    expect(createSource.match(/__interactive:\s*true/gu)?.length).toBeGreaterThanOrEqual(2);
  });

  it("pins the SDK endpoint body and controller-hosted credential response fields", async () => {
    const apiClientSource = await readFile(
      new URL("../node_modules/@vercel/sandbox/dist/api-client/api-client.js", import.meta.url),
      "utf8",
    );
    const validatorSource = await readFile(
      new URL("../node_modules/@vercel/sandbox/dist/api-client/validators.js", import.meta.url),
      "utf8",
    );
    expect(apiClientSource).toContain(
      "`/v2/sandboxes/sessions/${params.sessionId}/interactive`",
    );
    expect(apiClientSource).toContain('body: JSON.stringify({})');
    expect(validatorSource).toContain("const InteractiveSessionResponse = z.object({");
    expect(validatorSource).toContain("url: z.string(),\n\ttoken: z.string()");
  });
});
