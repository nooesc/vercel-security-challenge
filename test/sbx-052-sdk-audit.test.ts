import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

describe("SBX-052 installed SDK audit", () => {
  it("pins the audited @vercel/sandbox release", async () => {
    const metadata = JSON.parse(await readFile("node_modules/@vercel/sandbox/package.json", "utf8")) as {
      name: string;
      version: string;
    };
    expect(metadata).toEqual(expect.objectContaining({ name: "@vercel/sandbox", version: "3.0.0" }));
  });

  it("sends the caller path and cwd verbatim to the session-scoped server fs/read route", async () => {
    const source = await readFile("node_modules/@vercel/sandbox/dist/api-client/api-client.js", "utf8");
    const start = source.indexOf("async readFile(params)");
    const end = source.indexOf("async killCommand", start);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    const method = source.slice(start, end);
    expect(method).toContain("`/v2/sandboxes/sessions/${params.sessionId}/fs/read`");
    expect(method).toContain("path: params.path");
    expect(method).toContain("cwd: params.cwd");
    expect(method).not.toMatch(/normalizePath|realpath|resolve\(/u);
    expect(method).toContain('method: "POST"');
  });

  it("Session.readFile does not rewrite the path before invoking the API client", async () => {
    const source = await readFile("node_modules/@vercel/sandbox/dist/session.js", "utf8");
    const start = source.indexOf("async readFile(file, opts)");
    const end = source.indexOf("async readFileToBuffer", start);
    const method = source.slice(start, end);
    expect(method).toContain("sessionId: this.session.id");
    expect(method).toContain("path: file.path");
    expect(method).toContain("cwd: file.cwd");
    expect(method).not.toMatch(/normalizePath|realpath|resolve\(/u);
  });

  it("exposes sandbox and current-session timeouts from returned server records", async () => {
    const sandboxSource = await readFile("node_modules/@vercel/sandbox/dist/sandbox.js", "utf8");
    const sessionSource = await readFile("node_modules/@vercel/sandbox/dist/session.js", "utf8");
    expect(sandboxSource).toMatch(/get timeout\(\) \{\s*return this\.sandbox\.timeout;\s*\}/u);
    expect(sessionSource).toMatch(/get timeout\(\) \{\s*return this\.session\.timeout;\s*\}/u);
    const controller = await readFile("pocs/SBX-052/fs-namespace.ts", "utf8");
    expect(controller).toContain("sandboxTimeoutMs: sandbox.timeout ?? null");
    expect(controller).toContain("sessionTimeoutMs: sandbox.currentSession().timeout");
  });

  it("documents absolute-path reads as sandbox filesystem operations", async () => {
    const readme = await readFile("node_modules/@vercel/sandbox/README.md", "utf8");
    expect(readme).toContain("### File operations");
    expect(readme).toContain("Absolute paths also work");
    expect(readme).toContain('path: "/tmp/output.txt"');
    const declarations = await readFile("node_modules/@vercel/sandbox/dist/sandbox.d.ts", "utf8");
    expect(declarations).toContain("const content = await sandbox.fs.readFile('/etc/hostname', 'utf8')");
  });

  it("keeps the live matrix to one owned sandbox and two non-sensitive proc reads", async () => {
    const source = await readFile("pocs/SBX-052/fs-namespace.ts", "utf8");
    expect(source.match(/Sandbox\.create\(/gu)).toHaveLength(1);
    expect(source).toContain('networkPolicy: "deny-all"');
    expect(source).toContain("ports: []");
    expect(source).toContain("SBX052_BOOT_ID_PATH");
    expect(source).not.toMatch(/\/proc\/(?:[0-9]+|self)\/(?:environ|mem|root)/u);
    expect(source).not.toMatch(/\/etc\/(?:shadow|passwd)|\/home\/[^"'`\s]+\/\.ssh|\/proc\/[^"'`\s]+\/environ/iu);
  });
});
