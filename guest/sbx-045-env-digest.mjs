import { createHash } from "node:crypto";

const key = "SBX045_SYNTHETIC_ENV";
const present = Object.prototype.hasOwnProperty.call(process.env, key);
const value = present ? process.env[key] : undefined;

const result = present && typeof value === "string"
  ? {
      schemaVersion: 1,
      testId: "SBX-045",
      present: true,
      length: Buffer.byteLength(value, "utf8"),
      sha256: createHash("sha256").update(value, "utf8").digest("hex"),
    }
  : {
      schemaVersion: 1,
      testId: "SBX-045",
      present: false,
      length: 0,
      sha256: null,
    };

process.stdout.write(`${JSON.stringify(result)}\n`);
