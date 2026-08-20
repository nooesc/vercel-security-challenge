import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  exactSbx058CreateProvenance,
  sanitizeSbx058Probe,
  sbx058Policy,
  sbx058PrefixListOptions,
} from "../pocs/SBX-058/header-entry-binding.js";
import { createSbx058Journal } from "../pocs/SBX-058/safety.js";
import type { Sbx058Identity } from "../pocs/SBX-058/verdict.js";
import type { Sandbox } from "@vercel/sandbox";

const runId = "123e4567-e89b-42d3-a456-426614174058";
const identity: Sbx058Identity = {
  aliasEmail: "swve@wearehackerone.com",
  aliasIdentityVerified: true,
  teamId: "team_n98ERpVwV7HqmWRudAyK8sXQ",
  projectId: "prj_CyyVykdN06Nrkla6KidZcecLgbCa",
  sandboxName: `sbx-058-${runId}`,
  sessionId: "sbx_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
};

describe("SBX-058 controller", () => {
  it("constructs only the exact single header matcher and P forward", () => {
    expect(sbx058Policy("a.example.test", "https://p.example.test", runId)).toEqual({
      allow: {
        "a.example.test": [{
          match: { headers: [{ key: { exact: "x-sbx058-route" }, value: { exact: "privileged" } }] },
          forwardURL: `https://p.example.test/v1/sbx058/proxy/${runId}`,
        }],
      },
    });
  });

  it("uses the SDK-required deterministic name ordering for prefix absence", () => {
    expect(sbx058PrefixListOptions(`sbx-058-${runId}`)).toEqual({
      namePrefix: `sbx-058-${runId}`,
      limit: 10,
      sortBy: "name",
      sortOrder: "asc",
    });
  });

  it("derives provenance from the real handle fields rather than a supplied boolean", () => {
    const journal = createSbx058Journal(runId, new Date("2026-08-19T12:00:00.000Z"));
    const fake = {
      name: journal.name,
      persistent: false,
      tags: journal.tags,
      createdAt: new Date("2026-08-19T12:00:01.000Z"),
      currentSession: () => ({ sessionId: identity.sessionId }),
    } as unknown as Sandbox;
    expect(exactSbx058CreateProvenance(fake, journal)).toBe(true);
    expect(exactSbx058CreateProvenance({ ...fake, persistent: true } as unknown as Sandbox, journal)).toBe(false);
    expect(exactSbx058CreateProvenance({ ...fake, tags: { ...journal.tags, extra: "x" } } as unknown as Sandbox, journal)).toBe(false);
  });

  it("sanitizes only the verdict fields and binds controller identity", () => {
    const probe = sanitizeSbx058Probe({
      schemaVersion: 1,
      testId: "SBX-058-HEADER-ENTRY-BINDING",
      runId,
      caseId: "combined-halves",
      correlationCanary: `s58_combined-halves_${"A".repeat(22)}`,
      targetRole: "A",
      headerMode: "combined-halves",
      startedAt: "2026-08-19T12:00:00.000Z",
      completedAt: "2026-08-19T12:00:01.000Z",
      ok: true,
      phase: "response",
      requestHostname: "a.example.test",
      requestServername: "a.example.test",
      requestHostHeader: "a.example.test",
      requestPath: "/request",
      routeHeaderSent: true,
      decoyHeaderSent: true,
      connectionAttempts: 1,
      actualConnections: 1,
      actualRequests: 1,
      retries: 0,
      redirectsFollowed: 0,
      rejectUnauthorized: true,
      controllerConfigurableCustomTrustAccepted: false,
      inheritedPlatformTrustEnvironmentNames: [],
      tcpConnected: true,
      tlsEstablished: true,
      tlsAuthorized: true,
      responseReceived: true,
      responseStatusCode: 200,
      responseShapeValid: true,
      responseRole: "A",
      responseOidcVerified: false,
      responseOperationId: `s58op_${"A".repeat(43)}`,
      responseReceipt: `s58rcpt_${"B".repeat(43)}`,
      responseBodyRetained: false,
      timedOut: false,
      durationMs: 1_000,
      arbitraryRawBody: "must-not-survive",
    }, 0, identity);
    expect(probe.controllerIdentity).toEqual(identity);
    expect(probe).not.toHaveProperty("arbitraryRawBody");
  });

  it("is import-safe and main-guarded", () => {
    const source = readFileSync(resolve("pocs/SBX-058/header-entry-binding.ts"), "utf8");
    expect(source).toContain("import.meta.url === pathToFileURL(process.argv[1]).href");
    expect(source).not.toMatch(/runSbx058\(\);/u);
    expect(source).toContain("Object.values(process.env)");
    expect(source).toContain("let guestEnvironmentScanned = false");
    expect(source).toContain("guestEnvironmentScanned = true");
  });

  it("takes the terminal ledger snapshot after sandbox quiescence and before receiver deletion", () => {
    const source = readFileSync(resolve("pocs/SBX-058/header-entry-binding.ts"), "utf8");
    const cleanupStart = source.indexOf("const sandboxResult = await cleanupSbx058Sandbox");
    const finalSnapshot = source.indexOf("ledger = await ledgerSnapshot(config, runId);", cleanupStart);
    const receiverDelete = source.indexOf("receiverCleanup = await cleanupReceiver", cleanupStart);
    expect(cleanupStart).toBeGreaterThan(0);
    expect(finalSnapshot).toBeGreaterThan(cleanupStart);
    expect(receiverDelete).toBeGreaterThan(finalSnapshot);
  });
});
