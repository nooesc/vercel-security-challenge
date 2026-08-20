import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

function method(source: string, startText: string, endText: string): string {
  const start = source.indexOf(startText);
  const end = source.indexOf(endText, start + startText.length);
  expect(start).toBeGreaterThan(-1);
  expect(end).toBeGreaterThan(start);
  return source.slice(start, end);
}

describe("SBX-056 installed-wire and dedupe audit", () => {
  it("pins the audited @vercel/sandbox release", async () => {
    const metadata = JSON.parse(await readFile("node_modules/@vercel/sandbox/package.json", "utf8")) as {
      name: string;
      version: string;
    };
    expect(metadata).toMatchObject({ name: "@vercel/sandbox", version: "3.0.0" });
  });

  it("adds only teamId universally and does not infer project context from an opaque PAT", async () => {
    const source = await readFile("node_modules/@vercel/sandbox/dist/api-client/api-client.js", "utf8");
    expect(source).toContain('baseUrl: params.baseUrl ?? "https://vercel.com/api"');
    const request = method(source, "async request(path, params)", "async getSession(params)");
    expect(request).toContain("teamId: this.teamId");
    expect(request).not.toContain("projectId: this.projectId");
    expect(request).not.toMatch(/project_id|project:\s*this/u);
  });

  it("sends fs/read to a session child route with path/cwd and no project identifier", async () => {
    const source = await readFile("node_modules/@vercel/sandbox/dist/api-client/api-client.js", "utf8");
    const read = method(source, "async readFile(params)", "async killCommand");
    expect(read).toContain("`/v2/sandboxes/sessions/${params.sessionId}/fs/read`");
    expect(read).toContain('method: "POST"');
    expect(read).toContain("path: params.path");
    expect(read).toContain("cwd: params.cwd");
    expect(read).not.toMatch(/projectId|project_id|query:\s*\{[^}]*project/u);
    const controller = await readFile("pocs/SBX-056/project-scoped-session-read.ts", "utf8");
    expect(controller).toContain('const SDK_API = "https://vercel.com"');
    expect(controller).toContain("`${SDK_API}/api/v2/sandboxes/sessions/");
  });

  it("contrasts the child route with project-bound named get/list/delete routes", async () => {
    const source = await readFile("node_modules/@vercel/sandbox/dist/api-client/api-client.js", "utf8");
    const get = method(source, "async getSandbox(params)", "async listSandboxes(params)");
    const list = method(source, "async listSandboxes(params)", "async updateSandbox(params)");
    const remove = method(source, "async deleteSandbox(params)", "};\nasync function pipe");
    expect(get).toContain("projectId: params.projectId");
    expect(list).toContain("project: params.projectId");
    expect(remove).toContain("query: { projectId: params.projectId }");
  });

  it("proves Sandbox.readFile forwards only session ID, path, and cwd to that client method", async () => {
    const source = await readFile("node_modules/@vercel/sandbox/dist/session.js", "utf8");
    const read = method(source, "async readFile(file, opts)", "async readFileToBuffer");
    expect(read).toContain("sessionId: this.session.id");
    expect(read).toContain("path: file.path");
    expect(read).toContain("cwd: file.cwd");
    expect(read).not.toMatch(/projectId|project_id/u);
  });

  it("keeps the packet to the same root family as SBX-026 rather than inventing a second report", async () => {
    const readme = await readFile("pocs/SBX-056/README.md", "utf8");
    expect(readme).toContain("same root family as SBX-026");
    expect(readme).toContain("consolidate");
    expect(readme).toContain("not a second report");
  });

  it("keeps the live controller to three fixed-path reads and forbids command execution", async () => {
    const source = await readFile("pocs/SBX-056/project-scoped-session-read.ts", "utf8");
    expect(source.match(/oneSbx056Read\(\{/gu)).toHaveLength(3);
    expect(source).toContain("SBX056-PUBLIC-");
    expect(source).toContain("SBX056-VICTIM-");
    expect(source).not.toMatch(/runCommand|openInteractive|\/cmd(?:["'`/])/u);
    expect(source).toContain('networkPolicy: "deny-all"');
    expect(source).toContain("ports: [] as number[]");
  });
});
