import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { Sandbox } from "@vercel/sandbox";
import {
  repositoryDirectoryFromUrl,
  createSbx053EvidenceBinding,
  isSbx053GitHubInstallationToken,
  loadSbx053Config,
  SBX053_FIXED_GUEST_SHA256,
  sbx053CreateParameters,
  sbx053ImpactArguments,
  sbx053ScanArguments,
  verifySbx053GitHubAuthority,
  type Sbx053Config,
} from "../pocs/SBX-053/git-source-credential-retention.js";
import {
  assertSbx053EvidenceExcludesRawSecrets,
  expectedSbx053Proof,
  SBX053_SURFACES,
  type Sbx053Assessment,
  type Sbx053ScanResult,
} from "../pocs/SBX-053/verdict.js";

const GIT_TOKEN = `ghs_${"A".repeat(48)}`;
const STATELESS_GIT_TOKEN =
  `ghs_4650082_${"A".repeat(80)}.${"b".repeat(120)}.${"C".repeat(176)}`;
const NOW = Date.parse("2026-08-19T12:00:00.000Z");
const MINT_EXPIRES_AT = new Date(NOW + 60 * 60_000).toISOString();
const SOURCE_REVISION = "sbx053-source";
const SOURCE_COMMIT = "1".repeat(40);

function githubResponse(url: string, body: unknown, requestId: string, options: {
  expiresAt?: string | null;
  status?: number;
} = {}): Response {
  const response = new Response(JSON.stringify(body), {
    status: options.status ?? 200,
    headers: {
      "content-type": "application/json",
      "x-github-request-id": requestId,
      ...(options.expiresAt === undefined || options.expiresAt === null
        ? {}
        : { "github-authentication-token-expiration": options.expiresAt }),
    },
  });
  Object.defineProperty(response, "url", { value: url });
  return response;
}

function authorityFetcher(options: {
  repositoryCount?: number;
  private?: boolean;
  pull?: boolean;
  push?: boolean;
  admin?: boolean;
  maintain?: boolean;
  expiresAt?: string | null;
  repositoryExpiresAt?: string | null;
  sourceExpiresAt?: string | null;
  sourceRef?: string;
  sourceCommit?: string;
  sourceRequestId?: string;
} = {}): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = input instanceof Request ? input.url : input.toString();
    if (url === "https://api.github.com/installation/repositories?per_page=2") {
      const repository = {
        full_name: "example/disposable-private",
        private: options.private ?? true,
      };
      return githubResponse(url, {
        total_count: options.repositoryCount ?? 1,
        repositories: options.repositoryCount === 2 ? [repository, {
          full_name: "example/other",
          private: true,
        }] : [repository],
      }, "AUTHORITY:INSTALLATION:0001", {
        ...(options.expiresAt === undefined ? {} : { expiresAt: options.expiresAt }),
      });
    }
    if (url === "https://api.github.com/repos/example/disposable-private") {
      return githubResponse(url, {
        full_name: "example/disposable-private",
        private: options.private ?? true,
        permissions: {
          pull: options.pull ?? false,
          push: options.push ?? false,
          admin: options.admin ?? false,
          maintain: options.maintain ?? false,
          triage: false,
        },
      }, "AUTHORITY:REPOSITORY:0002", {
        ...(options.repositoryExpiresAt !== undefined
          ? { expiresAt: options.repositoryExpiresAt }
          : options.expiresAt === undefined ? {} : { expiresAt: options.expiresAt }),
      });
    }
    return githubResponse(url, {
      ref: options.sourceRef ?? `refs/heads/${SOURCE_REVISION}`,
      object: {
        type: "commit",
        sha: options.sourceCommit ?? SOURCE_COMMIT,
      },
    }, options.sourceRequestId ?? "AUTHORITY:SOURCE-REF:0003", {
      ...(options.sourceExpiresAt !== undefined
        ? { expiresAt: options.sourceExpiresAt }
        : options.expiresAt === undefined ? {} : { expiresAt: options.expiresAt }),
    });
  }) as typeof fetch;
}

function config(): Sbx053Config {
  return {
    vercelToken: "offline_vercel_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    teamId: "team_n98ERpVwV7HqmWRudAyK8sXQ",
    projectId: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
    expectedAlias: "swve@wearehackerone.com",
    gitUrl: "https://github.com/example/disposable-private.git",
    gitUsername: "x-access-token",
    gitToken: GIT_TOKEN,
    gitTokenExpiresAt: MINT_EXPIRES_AT,
    sourceRevision: SOURCE_REVISION,
    sourceCommit: SOURCE_COMMIT,
    impactEnabled: false,
  };
}

function response(name: string) {
  const now = Date.now();
  return {
    sandbox: {
      name,
      persistent: false,
      createdAt: now,
      updatedAt: now,
      currentSessionId: "sbx_offline_session_abcdefghijklmnopqrstuvwxyz",
      status: "running",
      networkPolicy: { mode: "deny-all" },
      tags: { harness: "vsc", test: "SBX-053", run: "offline" },
    },
    session: {
      id: "sbx_offline_session_abcdefghijklmnopqrstuvwxyz",
      memory: 2_048,
      vcpus: 1,
      region: "iad1",
      timeout: 240_000,
      status: "running",
      requestedAt: now,
      startedAt: now,
      createdAt: now,
      cwd: "/vercel/sandbox",
      updatedAt: now,
      networkPolicy: { mode: "deny-all" },
    },
    routes: [],
  };
}

describe("SBX-053 installed SDK and contract audit", () => {
  it("loads recovery without Git material but requires a GitHub installation token for a normal run", () => {
    const common = {
      SBX053_SCOPE_CONFIRMATION:
        "I_RECHECKED_SBX053_SCOPE_AND_WILL_USE_ONE_OWNED_DISPOSABLE_PRIVATE_REPO_AND_SHORT_LIVED_TOKEN",
      VERCEL_TEAM_ID: "team_n98ERpVwV7HqmWRudAyK8sXQ",
      VERCEL_PROJECT_ID: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
      SBX053_EXPECTED_ALIAS: "swve@wearehackerone.com",
      VERCEL_TOKEN: "offline_vercel_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    };
    expect(loadSbx053Config({
      ...common,
      SBX053_RECOVERY_RUN_ID: "12345678-1234-4abc-8def-1234567890ab",
    })).toMatchObject({
      recoveryRunId: "12345678-1234-4abc-8def-1234567890ab",
    });
    expect(() => loadSbx053Config({
      ...common,
      SBX053_GIT_USERNAME: "x-access-token",
      SBX053_GIT_URL: config().gitUrl,
      SBX053_GIT_TOKEN: "github_pat_not-an-installation-token",
      SBX053_SOURCE_REVISION: "sbx053-source",
      SBX053_SOURCE_COMMIT: "1".repeat(40),
    })).toThrow(/installation token/u);
    expect(() => loadSbx053Config({
      ...common,
      SBX053_GIT_USERNAME: "x-access-token",
      SBX053_GIT_URL: config().gitUrl,
      SBX053_GIT_TOKEN: GIT_TOKEN,
      SBX053_SOURCE_REVISION: "sbx053-source",
      SBX053_SOURCE_COMMIT: "1".repeat(40),
    })).toThrow(/SBX053_GIT_TOKEN_EXPIRES_AT/u);
    expect(() => loadSbx053Config({
      ...common,
      SBX053_GIT_USERNAME: "x-access-token",
      SBX053_GIT_URL: config().gitUrl,
      SBX053_GIT_TOKEN: GIT_TOKEN,
      SBX053_GIT_TOKEN_EXPIRES_AT: "not-an-expiry",
      SBX053_SOURCE_REVISION: "sbx053-source",
      SBX053_SOURCE_COMMIT: "1".repeat(40),
    })).toThrow(/canonical ISO-8601/u);
  });

  it("accepts a bounded opaque stateless installation token and rejects malformed controls", async () => {
    expect(STATELESS_GIT_TOKEN).toHaveLength(390);
    expect(STATELESS_GIT_TOKEN.match(/\./gu)).toHaveLength(2);
    expect(isSbx053GitHubInstallationToken(STATELESS_GIT_TOKEN)).toBe(true);
    expect(isSbx053GitHubInstallationToken(`ghs_${"A".repeat(36)}`)).toBe(true);
    expect(isSbx053GitHubInstallationToken(`ghs_${"A".repeat(4_092)}`)).toBe(true);
    expect(isSbx053GitHubInstallationToken(`ghs_${"A".repeat(35)}`)).toBe(false);
    expect(isSbx053GitHubInstallationToken(`ghs_${"A".repeat(4_093)}`)).toBe(false);
    for (const invalid of [" ", "\t", "\n", "\r", "\0", "\u007f", "\u200b", "/", "+"]) {
      expect(isSbx053GitHubInstallationToken(
        `ghs_${"A".repeat(36)}${invalid}${"B".repeat(36)}`,
      )).toBe(false);
    }

    const loaded = loadSbx053Config({
      SBX053_SCOPE_CONFIRMATION:
        "I_RECHECKED_SBX053_SCOPE_AND_WILL_USE_ONE_OWNED_DISPOSABLE_PRIVATE_REPO_AND_SHORT_LIVED_TOKEN",
      VERCEL_TEAM_ID: "team_n98ERpVwV7HqmWRudAyK8sXQ",
      VERCEL_PROJECT_ID: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
      SBX053_EXPECTED_ALIAS: "swve@wearehackerone.com",
      VERCEL_TOKEN: "offline_vercel_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ",
      SBX053_GIT_USERNAME: "x-access-token",
      SBX053_GIT_URL: config().gitUrl,
      SBX053_GIT_TOKEN: STATELESS_GIT_TOKEN,
      SBX053_GIT_TOKEN_EXPIRES_AT: MINT_EXPIRES_AT,
      SBX053_SOURCE_REVISION: "sbx053-source",
      SBX053_SOURCE_COMMIT: "1".repeat(40),
    });
    expect(loaded).toMatchObject({ gitToken: STATELESS_GIT_TOKEN });

    const authority = await verifySbx053GitHubAuthority({
      gitUrl: config().gitUrl,
      gitToken: STATELESS_GIT_TOKEN,
      mintExpiresAt: MINT_EXPIRES_AT,
      sourceRevision: SOURCE_REVISION,
      sourceCommit: SOURCE_COMMIT,
      bindingNonce: "ab".repeat(32),
      now: NOW,
      fetcher: authorityFetcher(),
    });
    expect(authority.tokenBindingHmacSha256).toMatch(/^[0-9a-f]{64}$/u);
  });

  it("binds one private read-only repository to the mint expiry without requiring GET headers", async () => {
    const evidence = await verifySbx053GitHubAuthority({
      gitUrl: config().gitUrl,
      gitToken: GIT_TOKEN,
      mintExpiresAt: MINT_EXPIRES_AT,
      sourceRevision: SOURCE_REVISION,
      sourceCommit: SOURCE_COMMIT,
      bindingNonce: "ab".repeat(32),
      now: NOW,
      fetcher: authorityFetcher(),
    });
    expect(evidence).toMatchObject({
      provider: "github-app-installation-token",
      repositoryFullName: "example/disposable-private",
      repositoryPrivate: true,
      accessibleRepositoryCount: 1,
      repositoryPullProjection: false,
      contentsReadProved: true,
      effectivePush: false,
      effectiveAdmin: false,
      effectiveMaintain: false,
      sourceRef: `refs/heads/${SOURCE_REVISION}`,
      sourceCommit: SOURCE_COMMIT,
      sourceRefRequestEvidenceSha256: expect.stringMatching(/^[0-9a-f]{64}$/u),
      tokenExpiresAt: new Date(NOW + 60 * 60_000).toISOString(),
      remainingLifetimeSeconds: 3_600,
      tokenExpirationEvidenceMethod: "mint-response",
      tokenExpirationHeaderCount: 0,
      rawProviderBodiesRetained: false,
    });
    expect(JSON.stringify(evidence)).not.toContain(GIT_TOKEN);
    await expect(verifySbx053GitHubAuthority({
      gitUrl: config().gitUrl,
      gitToken: GIT_TOKEN,
      mintExpiresAt: MINT_EXPIRES_AT,
      sourceRevision: SOURCE_REVISION,
      sourceCommit: SOURCE_COMMIT,
      bindingNonce: "ab".repeat(32),
      now: NOW,
      fetcher: authorityFetcher({ repositoryCount: 2 }),
    })).rejects.toThrow(/exactly one/u);
    await expect(verifySbx053GitHubAuthority({
      gitUrl: config().gitUrl,
      gitToken: GIT_TOKEN,
      mintExpiresAt: MINT_EXPIRES_AT,
      sourceRevision: SOURCE_REVISION,
      sourceCommit: SOURCE_COMMIT,
      bindingNonce: "ab".repeat(32),
      now: NOW,
      fetcher: authorityFetcher({ private: false }),
    })).rejects.toThrow(/private/u);
    await expect(verifySbx053GitHubAuthority({
      gitUrl: config().gitUrl,
      gitToken: GIT_TOKEN,
      mintExpiresAt: MINT_EXPIRES_AT,
      sourceRevision: SOURCE_REVISION,
      sourceCommit: SOURCE_COMMIT,
      bindingNonce: "ab".repeat(32),
      now: NOW,
      fetcher: authorityFetcher({ push: true }),
    })).rejects.toThrow(/write authority/u);
    for (const writeAuthority of [{ admin: true }, { maintain: true }]) {
      await expect(verifySbx053GitHubAuthority({
        gitUrl: config().gitUrl,
        gitToken: GIT_TOKEN,
        mintExpiresAt: MINT_EXPIRES_AT,
        sourceRevision: SOURCE_REVISION,
        sourceCommit: SOURCE_COMMIT,
        bindingNonce: "ab".repeat(32),
        now: NOW,
        fetcher: authorityFetcher(writeAuthority),
      })).rejects.toThrow(/write authority/u);
    }
    await expect(verifySbx053GitHubAuthority({
      gitUrl: config().gitUrl,
      gitToken: GIT_TOKEN,
      mintExpiresAt: new Date(NOW + 4 * 60_000).toISOString(),
      sourceRevision: SOURCE_REVISION,
      sourceCommit: SOURCE_COMMIT,
      bindingNonce: "ab".repeat(32),
      now: NOW,
      fetcher: authorityFetcher({ expiresAt: new Date(NOW + 4 * 60_000).toISOString() }),
    })).rejects.toThrow(/expiry/u);

    const exactHeaders = await verifySbx053GitHubAuthority({
      gitUrl: config().gitUrl,
      gitToken: GIT_TOKEN,
      mintExpiresAt: MINT_EXPIRES_AT,
      sourceRevision: SOURCE_REVISION,
      sourceCommit: SOURCE_COMMIT,
      bindingNonce: "ab".repeat(32),
      now: NOW,
      fetcher: authorityFetcher({ expiresAt: MINT_EXPIRES_AT }),
    });
    expect(exactHeaders).toMatchObject({
      tokenExpirationEvidenceMethod: "mint-response-and-get-headers",
      tokenExpirationHeaderCount: 3,
    });
    await expect(verifySbx053GitHubAuthority({
      gitUrl: config().gitUrl,
      gitToken: GIT_TOKEN,
      mintExpiresAt: MINT_EXPIRES_AT,
      sourceRevision: SOURCE_REVISION,
      sourceCommit: SOURCE_COMMIT,
      bindingNonce: "ab".repeat(32),
      now: NOW,
      fetcher: authorityFetcher({
        expiresAt: MINT_EXPIRES_AT,
        repositoryExpiresAt: new Date(NOW + 59 * 60_000).toISOString(),
      }),
    })).rejects.toThrow(/did not match the mint-response expiry/u);

    const secondPrecisionExpiry = MINT_EXPIRES_AT.replace(".000Z", "Z");
    const secondPrecision = await verifySbx053GitHubAuthority({
      gitUrl: config().gitUrl,
      gitToken: GIT_TOKEN,
      mintExpiresAt: secondPrecisionExpiry,
      sourceRevision: SOURCE_REVISION,
      sourceCommit: SOURCE_COMMIT,
      bindingNonce: "ab".repeat(32),
      now: NOW,
      fetcher: authorityFetcher(),
    });
    expect(secondPrecision.tokenExpiresAt).toBe(secondPrecisionExpiry);
    await expect(verifySbx053GitHubAuthority({
      gitUrl: config().gitUrl,
      gitToken: GIT_TOKEN,
      mintExpiresAt: "2026-08-19 13:00:00Z",
      sourceRevision: SOURCE_REVISION,
      sourceCommit: SOURCE_COMMIT,
      bindingNonce: "ab".repeat(32),
      now: NOW,
      fetcher: authorityFetcher(),
    })).rejects.toThrow(/canonical ISO-8601/u);

    const collaboratorProjection = await verifySbx053GitHubAuthority({
      gitUrl: config().gitUrl,
      gitToken: GIT_TOKEN,
      mintExpiresAt: MINT_EXPIRES_AT,
      sourceRevision: SOURCE_REVISION,
      sourceCommit: SOURCE_COMMIT,
      bindingNonce: "ab".repeat(32),
      now: NOW,
      fetcher: authorityFetcher({ pull: true }),
    });
    expect(collaboratorProjection).toMatchObject({
      repositoryPullProjection: true,
      contentsReadProved: true,
    });
    for (const sourceFailure of [
      { sourceRef: "refs/heads/wrong-source" },
      { sourceCommit: "2".repeat(40) },
    ]) {
      await expect(verifySbx053GitHubAuthority({
        gitUrl: config().gitUrl,
        gitToken: GIT_TOKEN,
        mintExpiresAt: MINT_EXPIRES_AT,
        sourceRevision: SOURCE_REVISION,
        sourceCommit: SOURCE_COMMIT,
        bindingNonce: "ab".repeat(32),
        now: NOW,
        fetcher: authorityFetcher(sourceFailure),
      })).rejects.toThrow(/exact pinned commit/u);
    }
    await expect(verifySbx053GitHubAuthority({
      gitUrl: config().gitUrl,
      gitToken: GIT_TOKEN,
      mintExpiresAt: MINT_EXPIRES_AT,
      sourceRevision: SOURCE_REVISION,
      sourceCommit: SOURCE_COMMIT,
      bindingNonce: "ab".repeat(32),
      now: NOW,
      fetcher: authorityFetcher({ sourceRequestId: "bad" }),
    })).rejects.toThrow(/request attribution/u);
  });

  it("retains one self-contained sanitized authority, target, credential, and sentinel binding", async () => {
    const credentialNonce = "ab".repeat(32);
    const sentinelChallenge = "cd".repeat(32);
    const sentinel = "offline-private-sentinel-ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const expectedCredential = expectedSbx053Proof(GIT_TOKEN, credentialNonce);
    const expectedSentinel = expectedSbx053Proof(sentinel, sentinelChallenge);
    const authority = await verifySbx053GitHubAuthority({
      gitUrl: config().gitUrl,
      gitToken: GIT_TOKEN,
      mintExpiresAt: MINT_EXPIRES_AT,
      sourceRevision: SOURCE_REVISION,
      sourceCommit: SOURCE_COMMIT,
      bindingNonce: credentialNonce,
      now: NOW,
      fetcher: authorityFetcher(),
    });
    const scan: Sbx053ScanResult = {
      schemaVersion: 1,
      testId: "SBX-053",
      operation: "scan",
      complete: true,
      surfacesChecked: [...SBX053_SURFACES],
      observations: [{ surface: "repo-config", ...expectedCredential }],
      candidatesTruncated: false,
    };
    const assessment: Sbx053Assessment = {
      verdict: "uncloned-ref-access-candidate",
      candidate: true,
      credentialMatched: true,
      unclonedRefAccessProved: true,
      likelySeverity: "medium",
      summary: "offline fixture",
      matchedSurface: "repo-config",
    };
    const input = {
      runId: "12345678-1234-4abc-8def-1234567890ab",
      teamId: config().teamId,
      projectId: config().projectId,
      sandboxName: "sbx-053-12345678-1234-4abc-8def-1234567890ab",
      sessionId: "sbx_offline_session_abcdefghijklmnopqrstuvwxyz",
      repositoryUrl: config().gitUrl,
      sourceRevision: config().sourceRevision,
      sourceCommit: config().sourceCommit,
      credentialNonce,
      expectedCredential,
      authority,
      scan,
      assessment,
      sentinel: {
        ref: "refs/heads/sbx053-operator-sentinel",
        commit: "2".repeat(40),
        path: ".sbx053-sentinel",
        challenge: sentinelChallenge,
        expected: expectedSentinel,
      },
    };
    const evidenceBinding = createSbx053EvidenceBinding(input);
    expect(evidenceBinding).toMatchObject({
      target: {
        teamId: config().teamId,
        projectId: config().projectId,
        sandboxName: input.sandboxName,
        sessionId: input.sessionId,
        repositoryUrl: config().gitUrl,
        repositoryFullName: "example/disposable-private",
        sourceRef: `refs/heads/${config().sourceRevision}`,
        sourceCommit: config().sourceCommit,
      },
      credential: {
        nonce: credentialNonce,
        expected: expectedCredential,
        observed: { surface: "repo-config", ...expectedCredential },
      },
      sentinel: {
        ref: input.sentinel.ref,
        commit: input.sentinel.commit,
        path: input.sentinel.path,
        challenge: sentinelChallenge,
        expected: expectedSentinel,
      },
    });
    expect(evidenceBinding.credential.expected.hmacSha256)
      .toBe(authority.tokenBindingHmacSha256);

    const artifactFixture = { authority, evidenceBinding, scan, impact: {
      sentinelLength: expectedSentinel.length,
      sentinelHmacSha256: expectedSentinel.hmacSha256,
    } };
    expect(() => assertSbx053EvidenceExcludesRawSecrets(
      artifactFixture,
      [GIT_TOKEN, sentinel],
    )).not.toThrow();
    const serialized = JSON.stringify(artifactFixture);
    expect(serialized).not.toContain(GIT_TOKEN);
    expect(serialized).not.toContain(sentinel);
    expect(serialized).not.toContain(createHash("sha256").update(GIT_TOKEN).digest("hex"));
    expect(serialized).not.toContain(createHash("sha256").update(sentinel).digest("hex"));

    expect(() => createSbx053EvidenceBinding({
      ...input,
      authority: { ...authority, tokenBindingNonce: "ef".repeat(32) },
    })).toThrow(/shared credential binding/u);
    expect(() => createSbx053EvidenceBinding({
      ...input,
      expectedCredential: { ...expectedCredential, hmacSha256: "3".repeat(64) },
    })).toThrow(/shared credential binding/u);
    expect(() => createSbx053EvidenceBinding({
      ...input,
      assessment: { ...assessment, credentialMatched: false, matchedSurface: null },
    })).toThrow(/credential observation/u);
    expect(() => createSbx053EvidenceBinding({
      ...input,
      repositoryUrl: "https://github.com/example/other-private.git",
    })).toThrow(/shared credential binding/u);
    expect(() => createSbx053EvidenceBinding({
      ...input,
      authority: { ...authority, sourceRef: "refs/heads/wrong-source" },
    })).toThrow(/shared credential binding/u);
    expect(() => createSbx053EvidenceBinding({
      ...input,
      authority: { ...authority, sourceCommit: "3".repeat(40) },
    })).toThrow(/shared credential binding/u);

    const controller = await readFile("pocs/SBX-053/git-source-credential-retention.ts", "utf8");
    expect(controller).toContain("bindingNonce: credentialNonce");
    expect(controller).toContain("sbx053ScanArguments(repositoryRoot, credentialNonce)");
    expect(controller).not.toMatch(/authorityNonce|scanNonce/u);
    expect(controller).toContain("authority,\n    evidenceBinding,");
  });

  it("pins @vercel/sandbox 3.0.0 and sends source auth only in POST /v3/sandboxes", async () => {
    const metadata = JSON.parse(await readFile("node_modules/@vercel/sandbox/package.json", "utf8")) as {
      name?: unknown;
      version?: unknown;
    };
    expect(metadata).toMatchObject({ name: "@vercel/sandbox", version: "3.0.0" });

    let capturedUrl: URL | undefined;
    let capturedBody: Record<string, unknown> | undefined;
    const fakeFetch = (async (input: string | URL | Request, init?: RequestInit) => {
      capturedUrl = new URL(input instanceof Request ? input.url : input.toString());
      capturedBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return new Response(JSON.stringify(response("sbx-053-offline")), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;
    await Sandbox.create({
      ...sbx053CreateParameters(config(), "sbx-053-offline",
        { harness: "vsc", test: "SBX-053", run: "offline" }),
      fetch: fakeFetch,
    });
    expect(capturedUrl?.pathname).toBe("/api/v3/sandboxes");
    expect(capturedBody?.source).toEqual({
      type: "git",
      url: "https://github.com/example/disposable-private.git",
      username: "x-access-token",
      password: GIT_TOKEN,
      depth: 1,
      revision: "sbx053-source",
    });
    expect(capturedBody?.env).toEqual({});
    expect(capturedBody?.networkPolicy).toEqual({ mode: "deny-all" });
    expect(capturedBody?.ports).toEqual([]);
  });

  it("pins the exact fixed guest program uploaded by the controller", async () => {
    const source = await readFile("guest/sbx-053-git-credential-probe.mjs", "utf8");
    expect(createHash("sha256").update(source, "utf8").digest("hex"))
      .toBe(SBX053_FIXED_GUEST_SHA256);
  });

  it("the SDK response model omits source credentials and no local code hydrates them into guest state", async () => {
    const client = await readFile("node_modules/@vercel/sandbox/dist/api-client/api-client.js", "utf8");
    const validators = await readFile("node_modules/@vercel/sandbox/dist/api-client/validators.js", "utf8");
    const sandbox = await readFile("node_modules/@vercel/sandbox/dist/sandbox.js", "utf8");
    expect(client).toContain("source: params.source");
    expect(client).toContain('const endpoint = params.runtime === void 0 ? "/v3/sandboxes"');
    const sandboxValidator = validators.slice(validators.indexOf("const Sandbox = z.object({"),
      validators.indexOf("const StopSessionResponse"));
    expect(sandboxValidator).not.toMatch(/source|password|username/u);
    expect(sandbox).not.toMatch(/source\.password|credential\.helper|git-credentials/u);
  });

  it("official local docs promise authenticated initialization, not credential retention", async () => {
    const example = await readFile("targets/vercel-sandbox/examples/private-repo/private-repo.ts", "utf8");
    const exampleReadme = await readFile("targets/vercel-sandbox/examples/private-repo/README.md", "utf8");
    const skill = await readFile("targets/vercel-sandbox/skills/sandbox/SKILL.md", "utf8");
    expect(example).toContain("password: process.env.GIT_ACCESS_TOKEN!");
    expect(example).toContain("Repository contents:");
    expect(example).not.toMatch(/git.*(?:pull|fetch)|credential\.helper|git-credentials/iu);
    expect(exampleReadme).toContain("initializes the environment with the provided repository");
    expect(exampleReadme).not.toMatch(/credential.*(?:remain|retain|persist)|future.*(?:pull|fetch)/iu);
    expect(skill).toContain("running untrusted code");
    expect(skill).toContain("### With Private Git Repository");
  });

  it("never puts the raw Git token or sentinel in guest command arguments", () => {
    expect(repositoryDirectoryFromUrl(config().gitUrl)).toBe("disposable-private");
    const scan = sbx053ScanArguments("/vercel/sandbox/disposable-private", "ab".repeat(32));
    const impact = sbx053ImpactArguments({
      repositoryRoot: "/vercel/sandbox/disposable-private",
      nonce: "ab".repeat(32),
      expectedCredentialHmac: "1".repeat(64),
      expectedCredentialLength: GIT_TOKEN.length,
      sourceUrl: config().gitUrl,
      sentinelRef: "refs/heads/sbx053-operator-sentinel",
      sentinelCommit: "2".repeat(40),
      sentinelPath: ".sbx053-sentinel",
      challenge: "cd".repeat(32),
    });
    expect(JSON.stringify({ scan, impact })).not.toContain(GIT_TOKEN);
    expect(scan).toEqual([
      "/tmp/sbx-053-git-credential-probe.mjs",
      "scan",
      "/vercel/sandbox/disposable-private",
      "ab".repeat(32),
    ]);
  });

  it("requires independent non-resuming policy readbacks before and after the impact window", async () => {
    const controller = await readFile("pocs/SBX-053/git-source-credential-retention.ts", "utf8");
    expect(controller).toContain("async function exactPolicyReadback");
    expect(controller).toContain("resume: false");
    expect(controller).toContain('expected: "github-only"');
    expect(controller.match(/expected: "deny-all"/gu)?.length).toBeGreaterThanOrEqual(2);
    expect(controller).toContain("deny-all restoration readback failed");
  });
});
