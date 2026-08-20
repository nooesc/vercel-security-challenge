import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { base32DecodeStrict } from "../pocs/SBX-001/shared.js";

interface GuestModule {
  SCOPE_CONFIRMATION: string;
  ZONE_NAME: string;
  SECRET_FILE_PATH: string;
  publicQueryName(caseId: string, nonce: string): string;
  secretQueryName(path: string, nonce: string, pad: string): Promise<Record<string, unknown>>;
  parseConfiguration(value: string): Record<string, unknown>;
  parseResolverAddress(value: string): string;
  buildDnsAQuery(queryName: string, transactionId: number): Buffer;
}

// This JavaScript guest is deliberately standalone because it is uploaded without a build step.
// @ts-expect-error no declaration file is shipped into the sandbox
const guest = await import("../guest/dns-deny-probe.mjs") as GuestModule;
const temporaryDirectories: string[] = [];
const nonce = "0123456789abcdef0123456789abcdef";

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("SBX-001 standalone guest probe", () => {
  it("builds only one-label public wildcard names", () => {
    expect(guest.publicQueryName("allow-public", nonce)).toBe(`a${nonce}.sbx001.form-app.app`);
    expect(guest.publicQueryName("deny-public", nonce)).toBe(`d${nonce}.sbx001.form-app.app`);
    expect(() => guest.publicQueryName("other", nonce)).toThrow(/case/u);
  });

  it("encodes S XOR P, not the reversible plaintext secret", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sbx-001-guest-"));
    temporaryDirectories.push(directory);
    const secretPath = join(directory, "operator-secret");
    const secret = Buffer.from("00112233445566778899aabbccddeeff", "hex");
    const pad = Buffer.from("ffeeddccbbaa99887766554433221100", "hex");
    await writeFile(secretPath, secret, { mode: 0o600 });
    await chmod(secretPath, 0o600);

    const source = await readFile("guest/dns-deny-probe.mjs", "utf8");
    expect(source).toContain("secret[index] ^ oneTimePad[index]");
    expect(source).not.toContain("secretSha256");
    expect(source).not.toContain("padSha256");
    expect(source).not.toContain("ciphertextSha256");

    await expect(guest.secretQueryName(secretPath, nonce, pad.toString("base64url"))).rejects.toThrow(/unexpected secret path/u);
    const isolatedSource = source.replace(
      'export const SECRET_FILE_PATH = "/tmp/sbx-001/operator-secret";',
      `export const SECRET_FILE_PATH = ${JSON.stringify(secretPath)};`,
    );
    expect(isolatedSource).not.toBe(source);
    const isolatedModulePath = join(directory, "dns-deny-probe.mjs");
    await writeFile(isolatedModulePath, isolatedSource, { mode: 0o600 });
    const isolatedGuest = await import(`${pathToFileURL(isolatedModulePath).href}?unit=${Date.now()}`) as GuestModule;
    const result = await isolatedGuest.secretQueryName(secretPath, nonce, pad.toString("base64url"));
    expect(result).toMatchObject({ secretByteLength: 16, transform: "xor-one-time-pad" });
    expect(Object.keys(result).sort()).toEqual(["queryName", "secretByteLength", "transform"]);
    const queryName = String(result.queryName);
    expect(queryName).toMatch(new RegExp(`^s[a-z2-7]{26}${nonce}\\.sbx001\\.form-app\\.app$`, "u"));
    const ciphertext = Buffer.alloc(16);
    for (let index = 0; index < 16; index += 1) ciphertext[index] = secret[index]! ^ pad[index]!;
    const encodedCiphertext = queryName.slice(1, 27).toUpperCase();
    expect(base32DecodeStrict(encodedCiphertext)).toEqual(ciphertext);
    expect(base32DecodeStrict(encodedCiphertext)).not.toEqual(secret);
    expect(ciphertext.equals(secret)).toBe(false);
    ciphertext.fill(0);
  });

  it("rejects pad or secret fields on public cases and requires both on secret cases", () => {
    const common = {
      scopeConfirmation: guest.SCOPE_CONFIRMATION,
      zoneName: guest.ZONE_NAME,
      queryNonce: nonce,
      runId: "123e4567-e89b-42d3-a456-426614174000",
      testId: "SBX-001-POC",
      mode: "dns",
      timeoutMs: 2_500,
    };
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
    expect(() => guest.parseConfiguration(encode({
      ...common,
      caseId: "allow-public",
      oneTimePadBase64: Buffer.alloc(16).toString("base64url"),
    }))).toThrow(/public DNS cases/u);
    expect(() => guest.parseConfiguration(encode({ ...common, caseId: "deny-secret" }))).toThrow(/fixed secret path/u);
    expect(guest.parseConfiguration(encode({ ...common, caseId: "deny-public" }))).toMatchObject({ caseId: "deny-public" });
  });

  it("parses a bounded IP resolver and builds exactly one A question", () => {
    expect(guest.parseResolverAddress("# comment\nnameserver 10.0.0.2\n")).toBe("10.0.0.2");
    const packet = guest.buildDnsAQuery(guest.publicQueryName("allow-public", nonce), 0x1234);
    expect(packet.readUInt16BE(0)).toBe(0x1234);
    expect(packet.readUInt16BE(4)).toBe(1);
    expect(packet.readUInt16BE(packet.length - 4)).toBe(1);
    expect(packet.readUInt16BE(packet.length - 2)).toBe(1);
  });

  it("keeps ciphertext decodable only with the separately held pad", () => {
    const secret = Buffer.alloc(16, 0x42);
    const pad = Buffer.alloc(16, 0xa5);
    const ciphertext = Buffer.alloc(16);
    for (let index = 0; index < 16; index += 1) ciphertext[index] = secret[index]! ^ pad[index]!;
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let accumulator = 0;
    let bits = 0;
    let encoded = "";
    for (const byte of ciphertext) {
      accumulator = (accumulator << 8) | byte;
      bits += 8;
      while (bits >= 5) {
        bits -= 5;
        encoded += alphabet[(accumulator >>> bits) & 31];
        accumulator &= (1 << bits) - 1;
      }
    }
    if (bits > 0) encoded += alphabet[(accumulator << (5 - bits)) & 31];
    expect(base32DecodeStrict(encoded)).toEqual(ciphertext);
    expect(base32DecodeStrict(encoded)).not.toEqual(secret);
    ciphertext.fill(0);
  });
});
