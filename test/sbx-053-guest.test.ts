import { createHmac } from "node:crypto";
import { execFile } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { parseSbx053Impact, parseSbx053Scan } from "../pocs/SBX-053/verdict.js";

const execFileAsync = promisify(execFile);
const GUEST = resolve("guest/sbx-053-git-credential-probe.mjs");
const NONCE = "12".repeat(32);
const temporary: string[] = [];

async function repository(): Promise<string> {
  const root = await mkdtemp(resolve(tmpdir(), "sbx-053-guest-test-"));
  temporary.push(root);
  await execFileAsync("git", ["init", "--quiet", root], { encoding: "utf8" });
  return root;
}

async function scan(root: string, environment: NodeJS.ProcessEnv = {}) {
  try {
    return await execFileAsync(process.execPath, [GUEST, "scan", root, NONCE], {
      encoding: "utf8",
      env: {
        PATH: process.env.PATH,
        HOME: resolve(root, "empty-home"),
        ...environment,
      },
      maxBuffer: 128 * 1024,
    });
  } catch (error) {
    const failure = error as { code?: number; stdout?: string; stderr?: string };
    return { stdout: failure.stdout ?? "", stderr: failure.stderr ?? "", code: failure.code ?? 1 };
  }
}

afterEach(async () => {
  await Promise.all(temporary.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("SBX-053 fixed guest credential probe", () => {
  it("proves an embedded remote password by HMAC without emitting it", async () => {
    const root = await repository();
    const token = "github_pat_offline_fixture_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
    await execFileAsync("git", ["-C", root, "remote", "add", "origin",
      `https://x-access-token:${token}@github.com/example/disposable.git`], { encoding: "utf8" });

    const result = await scan(root);
    expect(result.stderr).toBe("");
    expect(result.stdout).not.toContain(token);
    const parsed = parseSbx053Scan(result.stdout, result.stderr, 0);
    const expected = createHmac("sha256", token).update(NONCE, "ascii").digest("hex");
    expect(parsed.observations).toEqual(expect.arrayContaining([
      expect.objectContaining({ length: Buffer.byteLength(token), hmacSha256: expected }),
    ]));
    expect(parsed.observations.some((item) =>
      item.surface === "repo-config" || item.surface === "remote-command")).toBe(true);
  });

  it("checks only relevant guest environment names and emits no raw value", async () => {
    const root = await repository();
    const token = "offline-source-password-ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const ignored = "unrelated-environment-value-DO-NOT-HASH";
    const result = await scan(root, { SOURCE_PASSWORD: token, UNRELATED_VALUE: ignored });
    expect(result.stderr).toBe("");
    expect(result.stdout).not.toContain(token);
    expect(result.stdout).not.toContain(ignored);
    const parsed = parseSbx053Scan(result.stdout, result.stderr, 0);
    const tokenProof = createHmac("sha256", token).update(NONCE, "ascii").digest("hex");
    const ignoredProof = createHmac("sha256", ignored).update(NONCE, "ascii").digest("hex");
    expect(parsed.observations).toContainEqual({
      surface: "relevant-environment",
      length: Buffer.byteLength(token),
      hmacSha256: tokenProof,
    });
    expect(parsed.observations.some((item) => item.hmacSha256 === ignoredProof)).toBe(false);
  });

  it("reads only an explicitly referenced askpass script and HMACs its fixed response", async () => {
    const root = await repository();
    const token = "offline-askpass-token-ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const askpass = resolve(root, "askpass.sh");
    await writeFile(askpass, `#!/bin/sh\necho '${token}'\n`, { mode: 0o700 });
    await chmod(askpass, 0o700);
    const result = await scan(root, { GIT_ASKPASS: askpass });
    expect(result.stderr).toBe("");
    expect(result.stdout).not.toContain(token);
    const parsed = parseSbx053Scan(result.stdout, result.stderr, 0);
    const expected = createHmac("sha256", token).update(NONCE, "ascii").digest("hex");
    expect(parsed.observations).toContainEqual({
      surface: "askpass-script",
      length: Buffer.byteLength(token),
      hmacSha256: expected,
    });
  });

  it("uses effective global/XDG config discovery and follows only declared helper stores", async () => {
    const root = await repository();
    const home = resolve(root, "dynamic-home");
    await mkdir(home);
    const xdgHome = resolve(home, "xdg");
    await mkdir(resolve(xdgHome, "git"), { recursive: true });
    const globalConfig = resolve(home, "git-global-config");
    const helperStore = resolve(home, ".git-credentials");
    const xdgHelperStore = resolve(xdgHome, "git/credentials");
    const defaultXdgHelperStore = resolve(home, ".config/git/credentials");
    const configToken = "offline-dynamic-config-token-ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const homeStoreToken = "offline-home-helper-store-token-ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const xdgStoreToken = "offline-xdg-helper-store-token-ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const defaultXdgStoreToken = "offline-default-xdg-helper-store-token-ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const basic = Buffer.from(`x-access-token:${configToken}`, "utf8").toString("base64");
    await writeFile(globalConfig, [
      '[http "https://github.com/"]',
      `  extraHeader = Authorization: Basic ${basic}`,
      "[credential]",
      "  helper = store",
      "",
    ].join("\n"), { mode: 0o600 });
    await writeFile(helperStore,
      `https://x-access-token:${homeStoreToken}@github.com/example/disposable.git\n`,
      { mode: 0o600 });
    await writeFile(xdgHelperStore,
      `https://x-access-token:${xdgStoreToken}@github.com/example/disposable.git\n`,
      { mode: 0o600 });
    await mkdir(resolve(home, ".config/git"), { recursive: true });
    await writeFile(defaultXdgHelperStore,
      `https://x-access-token:${defaultXdgStoreToken}@github.com/example/disposable.git\n`,
      { mode: 0o600 });

    const result = await scan(root, {
      HOME: home,
      XDG_CONFIG_HOME: xdgHome,
      GIT_CONFIG_GLOBAL: globalConfig,
    });
    expect(result.stderr).toBe("");
    expect(result.stdout).not.toContain(configToken);
    expect(result.stdout).not.toContain(homeStoreToken);
    expect(result.stdout).not.toContain(xdgStoreToken);
    const parsed = parseSbx053Scan(result.stdout, result.stderr, 0);
    expect(parsed.observations).toContainEqual({
      surface: "dynamic-config",
      length: Buffer.byteLength(configToken),
      hmacSha256: createHmac("sha256", configToken).update(NONCE, "ascii").digest("hex"),
    });
    expect(parsed.observations).toContainEqual({
      surface: "dynamic-credential-store",
      length: Buffer.byteLength(homeStoreToken),
      hmacSha256: createHmac("sha256", homeStoreToken).update(NONCE, "ascii").digest("hex"),
    });
    expect(parsed.observations).toContainEqual({
      surface: "dynamic-credential-store",
      length: Buffer.byteLength(xdgStoreToken),
      hmacSha256: createHmac("sha256", xdgStoreToken).update(NONCE, "ascii").digest("hex"),
    });

    const defaultResult = await scan(root, { HOME: home, GIT_CONFIG_GLOBAL: globalConfig });
    expect(defaultResult.stderr).toBe("");
    expect(defaultResult.stdout).not.toContain(defaultXdgStoreToken);
    expect(parseSbx053Scan(defaultResult.stdout, defaultResult.stderr, 0).observations).toContainEqual({
      surface: "dynamic-credential-store",
      length: Buffer.byteLength(defaultXdgStoreToken),
      hmacSha256: createHmac("sha256", defaultXdgStoreToken)
        .update(NONCE, "ascii").digest("hex"),
    });
  });

  it("covers targeted GitHub/Vercel/Git config environment credentials", async () => {
    const root = await repository();
    const github = "github_pat_targeted_environment_ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const gh = "ghp_targeted_environment_ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const vercel = "vercel-git-targeted-environment-ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const parameters = "github_pat_config_parameters_ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const result = await scan(root, {
      GITHUB_TOKEN: github,
      GH_TOKEN: gh,
      VERCEL_GIT_CREDENTIAL: vercel,
      GIT_CONFIG_PARAMETERS: `credential.password=${parameters}`,
    });
    expect(result.stderr).toBe("");
    expect(result.stdout).not.toContain(github);
    expect(result.stdout).not.toContain(gh);
    expect(result.stdout).not.toContain(vercel);
    expect(result.stdout).not.toContain(parameters);
    const parsed = parseSbx053Scan(result.stdout, result.stderr, 0);
    for (const token of [github, gh, vercel, parameters]) {
      expect(parsed.observations).toContainEqual({
        surface: "relevant-environment",
        length: Buffer.byteLength(token),
        hmacSha256: createHmac("sha256", token).update(NONCE, "ascii").digest("hex"),
      });
    }
  });

  it("marks environment and askpass truncation incomplete instead of silently skipping", async () => {
    const environmentRoot = await repository();
    const crowdedEnvironment = Object.fromEntries(
      Array.from({ length: 300 }, (_, index) => [`SBX053_NOISE_${index}`, String(index)]),
    );
    const environmentResult = await scan(environmentRoot, crowdedEnvironment);
    expect(parseSbx053Scan(environmentResult.stdout, environmentResult.stderr, 0).complete).toBe(false);

    const askpassRoot = await repository();
    const configPath = resolve(askpassRoot, ".git/config");
    const original = await readFile(configPath, "utf8");
    const paths = Array.from({ length: 17 }, (_, index) =>
      resolve(askpassRoot, `askpass-${index}.sh`));
    await writeFile(configPath, `${original}\n[core]\n${paths.map((path) =>
      `  askpass = ${path}`).join("\n")}\n`);
    const askpassResult = await scan(askpassRoot);
    expect(parseSbx053Scan(askpassResult.stdout, askpassResult.stderr, 0).complete).toBe(false);
  });

  it("treats git cat-file status 128 as proved absence and requires anonymous denial before impact", async () => {
    const root = await repository();
    const bin = resolve(root, "bin");
    await mkdir(bin);
    const fakeGit = resolve(bin, "git");
    const token = "offline-impact-token-ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const sentinel = "offline-private-orphan-ref-sentinel-ABCDEFGHIJKLMNOPQRSTUVWXYZ\n";
    const commit = "3".repeat(40);
    const credentialedRemote = `https://x-access-token:${token}@github.com/example/disposable.git`;
    await execFileAsync("git", ["-C", root, "remote", "add", "origin", credentialedRemote],
      { encoding: "utf8" });
    await writeFile(fakeGit, `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === "remote") { process.stdout.write(${JSON.stringify(`${credentialedRemote}\n`)}); process.exit(0); }
if (args[0] === "config") process.exit(args.includes("--list") ? 0 : 1);
if (args[0] === "show-ref") process.exit(1);
if (args[0] === "cat-file") process.exit(args[2] === "HEAD^{commit}" ? 0 : 128);
if (args[0] === "fetch") {
  if (process.env.GIT_CONFIG_VALUE_1?.startsWith("Authorization: Basic ")) process.exit(0);
  process.stderr.write(${JSON.stringify("00:00:00 <= Recv header: HTTP/2 404\r\n")});
  process.exit(128);
}
if (args[0] === "update-ref") process.exit(0);
if (args[0] === "rev-parse") { process.stdout.write("${commit}\\n"); process.exit(0); }
if (args[0] === "show") { process.stdout.write(${JSON.stringify(sentinel)}); process.exit(0); }
process.exit(2);
`, { mode: 0o700 });
    await chmod(fakeGit, 0o700);
    const tokenHmac = createHmac("sha256", token).update(NONCE, "ascii").digest("hex");
    const challenge = "34".repeat(32);
    const result = await execFileAsync(process.execPath, [
      GUEST,
      "impact",
      root,
      NONCE,
      tokenHmac,
      String(Buffer.byteLength(token)),
      "https://github.com/example/disposable.git",
      "refs/heads/sbx053-operator-sentinel",
      commit,
      ".sbx053-sentinel",
      challenge,
    ], {
      encoding: "utf8",
      env: {
        PATH: `${bin}:${process.env.PATH ?? ""}`,
        HOME: resolve(root, "empty-home"),
      },
      maxBuffer: 128 * 1024,
    });
    expect(result.stderr).toBe("");
    expect(result.stdout).not.toContain(token);
    expect(result.stdout).not.toContain(sentinel.trim());
    const rawImpact = JSON.parse(result.stdout) as Record<string, unknown>;
    expect(rawImpact).toMatchObject({
      credentialMatched: true,
      credentialSurface: "remote-command",
      sourceCommitPresentBefore: true,
      commitProbeExitCode: 128,
      commitAbsentBefore: true,
      anonymousFetchDenied: true,
      anonymousFetchExitCode: 128,
      anonymousHttpStatus: 404,
      anonymousTransportAttributed: true,
      anonymousControlRefDeleted: true,
      fetchSucceeded: true,
      fetchedCommitExact: true,
      sentinelLength: Buffer.byteLength(sentinel),
      sentinelHmacSha256: createHmac("sha256", sentinel).update(challenge, "ascii").digest("hex"),
      temporaryRefDeleted: true,
    });
    expect(parseSbx053Impact(result.stdout, result.stderr, 0)).toEqual(rawImpact);
  });

  it("fails closed on bad arguments and contains no broad proc or host scan", async () => {
    const root = await repository();
    const invalid = await execFileAsync(process.execPath, [GUEST, "scan", root, "bad"], {
      encoding: "utf8",
    }).then(
      (value) => ({ ...value, code: 0 }),
      (error: { code?: number; stdout?: string; stderr?: string }) => ({
        code: error.code ?? 1,
        stdout: error.stdout ?? "",
        stderr: error.stderr ?? "",
      }),
    );
    expect(invalid).toEqual({ code: 1, stdout: "", stderr: "SBX-053 guest probe failed\n" });

    const source = await readFile(GUEST, "utf8");
    expect(source).not.toMatch(/readdir\([^)]*\/proc|\/proc\/\*|\/proc\/(?:[2-9]|[1-9][0-9]+)/u);
    expect(source).not.toMatch(/node:(?:http|https|net|tls|dgram)/u);
    expect(source).not.toMatch(/\bfetch\s*\(/u);
    expect(source).toContain('"/proc/self/environ"');
    expect(source).toContain('"/proc/1/environ"');
    expect(source).toContain("collectParentProcesses");
    expect(source).toContain('statusPath = "/proc/self/status"');
    expect(source).toContain("depth < 8");
    expect(source).toContain("split.length <= 128");
    expect(source).toContain("entries.length <= 256");
    expect(source).toContain("boundedAskpassPaths.length > 16");
    expect(source).toContain('"--show-scope", "--list"');
    expect(source).toContain("GIT_CONFIG_GLOBAL");
    expect(source).toContain("dynamic-credential-store");
    expect(source).toContain("MAX_CANDIDATES = 128");
    expect(source).toContain("MAX_FILE_BYTES = 32 * 1024");
  });
});
