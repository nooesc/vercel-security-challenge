import { describe, expect, it } from "vitest";
import {
  base32DecodeStrict,
  base32Encode,
  analyzeExactPositiveRows,
  analyzeSecretPositiveRows,
  assessStage,
  expectedOperationId,
  gateAuthorization,
  historicalSuffixCollisionCount,
  publicQueryName,
  querySuffix,
  sha256Bytes,
  xorBytes,
} from "../pocs/SBX-001/shared.js";

const key = "unit-test-proof-key-material-that-is-long-enough";
const runId = "123e4567-e89b-42d3-a456-426614174000";
const nonce = "0123456789abcdef0123456789abcdef";
const bracket = {
  sendStartedAt: "2026-08-18T20:00:00.000Z",
  sendCompletedAt: "2026-08-18T20:00:02.000Z",
};

describe("SBX-001 positive-only evidence rules", () => {
  it("uses a single wildcard-matching label with a 128-bit nonce", () => {
    expect(querySuffix(nonce)).toBe(`${nonce}.sbx001.form-app.app`);
    expect(publicQueryName("allow-control", nonce)).toBe(`a${nonce}.sbx001.form-app.app`);
    expect(publicQueryName("deny-control", nonce)).toBe(`d${nonce}.sbx001.form-app.app`);
    expect(publicQueryName("deny-control", nonce).split(".")[0]).toHaveLength(33);
  });

  it("round-trips canonical unpadded base32 and equal-length XOR", () => {
    expect(base32Encode(Buffer.from("f"))).toBe("MY");
    expect(base32Encode(Buffer.from("fo"))).toBe("MZXQ");
    expect(base32Encode(Buffer.from("foo"))).toBe("MZXW6");
    expect(base32Encode(Buffer.from("foobar"))).toBe("MZXW6YTBOI");
    const secret = Buffer.from("00112233445566778899aabbccddeeff", "hex");
    const pad = Buffer.from("ffeeddccbbaa99887766554433221100", "hex");
    const ciphertext = xorBytes(secret, pad);
    const encoded = base32Encode(ciphertext);
    expect(encoded).toMatch(/^[A-Z2-7]{26}$/u);
    expect(base32DecodeStrict(encoded)).toEqual(ciphertext);
    expect(xorBytes(ciphertext, pad)).toEqual(secret);
    const alphabetSample = base32Encode(Buffer.from("hello", "utf8"));
    expect(alphabetSample).toMatch(/[A-Z]/u);
    expect(() => base32DecodeStrict(alphabetSample.toLowerCase())).toThrow(/base32/u);
    ciphertext.fill(0);
  });

  it("accepts only an exact public A row inside the send-time bracket", () => {
    const queryName = publicQueryName("allow-control", nonce);
    const digest = sha256Bytes(queryName);
    const operationId = expectedOperationId(key, runId, "allow-control", digest);
    const analysis = analyzeExactPositiveRows({
      rows: [{
        datetime: "2026-08-18T20:00:01.000Z",
        queryName,
        queryType: "A",
        responseCode: "NOERROR",
        sampleInterval: 10,
      }],
      expectedQueryName: queryName,
      expectedQueryNameSha256: digest,
      expectedOperationId: operationId,
      runId,
      stage: "allow-control",
      proofKey: key,
      bracket,
    });
    expect(analysis).toMatchObject({ observed: true, ambiguous: false, exactObservationCount: 1 });
    expect(analysis.observations[0]).toMatchObject({
      queryNameSha256: digest,
      operationId,
      queryType: "A",
      responseCode: "NOERROR",
      sampleInterval: 10,
    });
    expect(JSON.stringify(analysis)).not.toContain(queryName);
  });

  it("never converts adaptive-analytics absence into a pass", () => {
    const absent = assessStage({
      stage: "allow-control",
      runReadyForVerification: true,
      cleanupPassed: true,
      analysis: {
        sourceRowCount: 0,
        exactObservationCount: 0,
        observations: [],
        observed: false,
        ambiguous: false,
        ambiguityReasons: [],
      },
    });
    expect(absent.outcome).toBe("no-candidate-observed");
    expect(absent.candidate).toBe(false);
    expect(absent.secretPhaseAuthorized).toBe(false);
    expect(absent.outcome).not.toBe("pass");
  });

  it("gates deny and secret stages only from exact positive rows", () => {
    const positive = {
      sourceRowCount: 1,
      exactObservationCount: 1,
      observations: [],
      observed: true,
      ambiguous: false,
      ambiguityReasons: [],
    };
    expect(assessStage({
      stage: "allow-control",
      runReadyForVerification: true,
      cleanupPassed: true,
      analysis: positive,
    }).outcome).toBe("allow-observed");
    expect(assessStage({
      stage: "deny-control",
      runReadyForVerification: true,
      cleanupPassed: true,
      analysis: positive,
    })).toMatchObject({ outcome: "signal-medium", secretPhaseAuthorized: true });
  });

  it("recovers a secret only from the exact ciphertext name and ephemeral pad", () => {
    const secret = Buffer.from("00112233445566778899aabbccddeeff", "hex");
    const pad = Buffer.from("0f0e0d0c0b0a09080706050403020100", "hex");
    const ciphertext = xorBytes(secret, pad);
    const queryName = `s${base32Encode(ciphertext).toLowerCase()}${querySuffix(nonce)}`;
    expect(queryName.split(".")[0]).toHaveLength(59);
    const queryNameSha256 = sha256Bytes(queryName);
    const operationId = expectedOperationId(key, runId, "deny-secret", queryNameSha256);
    const analysis = analyzeSecretPositiveRows({
      rows: [{
        datetime: "2026-08-18T20:00:01.000Z",
        queryName,
        queryType: "A",
        responseCode: "NOERROR",
        sampleInterval: 10,
      }],
      queryNonce: nonce,
      expectedQueryNameSha256: queryNameSha256,
      expectedSecret: secret,
      oneTimePad: pad,
      expectedOperationId: operationId,
      runId,
      proofKey: key,
      bracket,
    });
    expect(analysis).toMatchObject({ observed: true, ambiguous: false, exactObservationCount: 1 });
    expect(analysis.observations[0]).toMatchObject({
      queryNameSha256,
      operationId,
      recoveredSecretMatches: true,
      sampleInterval: 10,
    });
    const serialized = JSON.stringify(analysis);
    expect(serialized).not.toContain(queryName);
    expect(serialized).not.toContain(secret.toString("hex"));
    expect(serialized).not.toContain(pad.toString("hex"));
    expect(serialized).not.toContain(ciphertext.toString("hex"));
    ciphertext.fill(0);
  });

  it("rejects a suffix hit that cannot recover the exact in-memory secret", () => {
    const secret = Buffer.alloc(16, 0x11);
    const actualPad = Buffer.alloc(16, 0x22);
    const wrongPad = Buffer.alloc(16, 0x23);
    const ciphertext = xorBytes(secret, actualPad);
    const queryName = `s${base32Encode(ciphertext).toLowerCase()}${querySuffix(nonce)}`;
    const queryNameSha256 = sha256Bytes(queryName);
    const analysis = analyzeSecretPositiveRows({
      rows: [{ datetime: "2026-08-18T20:00:01.000Z", queryName, queryType: "A" }],
      queryNonce: nonce,
      expectedQueryNameSha256: queryNameSha256,
      expectedSecret: secret,
      oneTimePad: wrongPad,
      expectedOperationId: expectedOperationId(key, runId, "deny-secret", queryNameSha256),
      runId,
      proofKey: key,
      bracket,
    });
    expect(analysis.observed).toBe(false);
    expect(analysis.ambiguous).toBe(true);
    expect(analysis.ambiguityReasons).toContain("recovered-secret-mismatch");
    ciphertext.fill(0);
  });

  it("finds historical suffix contamination without knowing a secret query prefix", () => {
    const row = `s${"a".repeat(26)}${querySuffix(nonce)}`;
    expect(historicalSuffixCollisionCount([{ queryName: row }], nonce)).toBe(1);
    expect(historicalSuffixCollisionCount([{ queryName: row.toUpperCase() }], nonce)).toBe(0);
  });

  it("binds stage gates to the exact signed positive receipt", () => {
    const digest = sha256Bytes(publicQueryName("deny-control", nonce));
    const operationId = expectedOperationId(key, runId, "deny-control", digest);
    const gate = gateAuthorization(key, "deny-control", runId, "signal-medium", operationId);
    expect(gate).toMatch(/^gate_[A-Za-z0-9_-]{43}$/u);
    expect(gateAuthorization(key, "deny-control", runId, "signal-medium", operationId)).toBe(gate);
  });
});
