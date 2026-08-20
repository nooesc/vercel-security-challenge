import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

describe("SBX-001 packet invariants", () => {
  it("uses only the exact zone-scoped Cloudflare analytics dataset", async () => {
    const source = await readFile("pocs/SBX-001/analytics.ts", "utf8");
    expect(source).toContain("zones(filter: { zoneTag: $zoneTag })");
    expect(source).not.toContain("accounts(filter:");
    expect(source).not.toContain("accountTag");
    expect(source).toContain("sampleInterval");
    expect(source).toContain("fixed response byte bound exceeded");
  });

  it("generates a fresh random secret and independent random pad only after historical preflight", async () => {
    const source = await readFile("pocs/SBX-001/run.ts", "utf8");
    const historicalIndex = source.indexOf("historicalCollisionCount !== 0");
    const secretIndex = source.indexOf("rawSecret = randomBytes(16)");
    const padIndex = source.indexOf("oneTimePad = randomBytes(16)");
    expect(historicalIndex).toBeGreaterThan(0);
    expect(secretIndex).toBeGreaterThan(historicalIndex);
    expect(padIndex).toBeGreaterThan(secretIndex);
    expect(source).not.toContain("deriveOneTimePad");
    expect(source).not.toContain("ciphertextQueryName");
    expect(source).toContain("historicalSuffixCollisionCount(historical.rows, queryNonce)");
  });

  it("cleans the sandbox before starting the long analytics poll", async () => {
    const source = await readFile("pocs/SBX-001/run.ts", "utf8");
    const cleanupIndex = source.indexOf("const cleaned = await cleanupSandbox");
    const pollIndex = source.indexOf("const poll = await pollSecretAnalytics");
    expect(cleanupIndex).toBeGreaterThan(0);
    expect(pollIndex).toBeGreaterThan(cleanupIndex);
    expect(source).toContain("verificationSecret?.fill(0)");
    expect(source).toContain("oneTimePad?.fill(0)");
  });

  it("forbids raw or reversible secret fields in persisted artifacts", async () => {
    const [runSource, verifySource] = await Promise.all([
      readFile("pocs/SBX-001/run.ts", "utf8"),
      readFile("pocs/SBX-001/verify.ts", "utf8"),
    ]);
    expect(runSource).toContain("oneTimePadBase64|secretSha256|padSha256|ciphertextSha256");
    expect(runSource).toContain("queryNamePersisted: false");
    expect(runSource).toContain("plaintextSecretPersisted: false");
    expect(runSource).toContain("oneTimePadPersisted: false");
    expect(verifySource).toContain("absenceCanPass: false");
    expect(verifySource).not.toContain('outcome: "pass"');
  });

  it("documents the DNS-only wildcard and sampled positive-only limitation", async () => {
    const readme = await readFile("pocs/SBX-001/README.md", "utf8");
    expect(readme).toContain("*.sbx001.form-app.app -> 192.0.2.1");
    expect(readme).toContain("sampleInterval");
    expect(readme).toContain("An absent row is therefore never a pass");
    expect(readme).toContain("Closing the process loses the ability to recover the secret");
  });
});
