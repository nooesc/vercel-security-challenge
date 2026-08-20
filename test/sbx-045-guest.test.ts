import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { expectedDigest, parseGuestDigest } from "../pocs/SBX-045/verdict.js";

const execFileAsync = promisify(execFile);
const guestPath = new URL("../guest/sbx-045-env-digest.mjs", import.meta.url);
const guestFile = fileURLToPath(guestPath);

describe("SBX-045 fixed guest digest program", () => {
  it("emits only presence, UTF-8 length, and SHA-256 for a present value", async () => {
    const raw = "local-only-synthetic-value";
    const { stdout, stderr } = await execFileAsync(process.execPath, [guestFile], {
      env: { ...process.env, SBX045_SYNTHETIC_ENV: raw },
      encoding: "utf8",
    });
    expect(stdout).not.toContain(raw);
    expect(parseGuestDigest(stdout, stderr, 0)).toEqual({
      schemaVersion: 1,
      testId: "SBX-045",
      ...expectedDigest(raw),
    });
  });

  it("emits the fixed absent shape when the key is unset", async () => {
    const environment = { ...process.env };
    delete environment.SBX045_SYNTHETIC_ENV;
    const { stdout, stderr } = await execFileAsync(process.execPath, [guestFile], {
      env: environment,
      encoding: "utf8",
    });
    expect(parseGuestDigest(stdout, stderr, 0)).toEqual({
      schemaVersion: 1,
      testId: "SBX-045",
      present: false,
      length: 0,
      sha256: null,
    });
  });

  it("contains no networking, argument parser, or broad environment serialization", async () => {
    const source = await readFile(guestPath, "utf8");
    expect(source).not.toMatch(/\bfetch\s*\(/u);
    expect(source).not.toContain("process.argv");
    expect(source).not.toContain("JSON.stringify(process.env)");
    expect(source).toContain('const key = "SBX045_SYNTHETIC_ENV"');
  });
});
