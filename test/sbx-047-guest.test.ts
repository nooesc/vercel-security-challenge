import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const guest = new URL("../guest/sbx-047-network-request.mjs", import.meta.url);
const guestPath = fileURLToPath(guest);

describe("SBX-047 fixed one-request guest", () => {
  it("passes Node syntax validation", () => {
    const result = spawnSync(process.execPath, ["--check", guestPath], { encoding: "utf8" });
    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
  });

  it("fails before networking when TLS verification is globally disabled", () => {
    const result = spawnSync(process.execPath, [
      guestPath,
      "public",
      "https://owned.example.test",
      "run-047",
      "case-047",
      "canary-047",
    ], {
      encoding: "utf8",
      env: { ...process.env, NODE_TLS_REJECT_UNAUTHORIZED: "0" },
    });
    expect(result.status).toBe(2);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("refused disabled TLS certificate verification");
  });

  it("rejects a non-HTTPS origin before networking", () => {
    const environment = { ...process.env };
    delete environment.NODE_TLS_REJECT_UNAUTHORIZED;
    const result = spawnSync(process.execPath, [
      guestPath,
      "public",
      "http://127.0.0.1:9",
      "run-047",
      "case-047",
      "canary-047",
    ], { encoding: "utf8", env: environment });
    expect(result.status).toBe(2);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("origin is not one exact canonical HTTPS hostname origin");
  });

  it("contains one fetch site, disables redirects, and never reads the brokered header", async () => {
    const source = await readFile(guest, "utf8");
    expect(source.match(/\bfetch\s*\(/gu)).toHaveLength(1);
    expect(source).toContain('redirect: "error"');
    expect(source).toContain("AbortSignal.timeout(5_000)");
    expect(source).toContain("setTimeout(resolve, 350)");
    expect(source).not.toContain("x-sbx047-brokered-credential");
  });
});
