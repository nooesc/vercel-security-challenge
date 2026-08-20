import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  actionResponse,
  deriveOperationId,
  operationMessage,
} from "../infra/sbx044-wildcard-worker/src/protocol.js";
import { expectedOperationId } from "../pocs/SBX-044/wildcard-label-scope.js";

describe("SBX-044 Worker receipt protocol", () => {
  it("matches an independent Node HMAC over every identity and correlation field", async () => {
    const key = "k".repeat(48);
    const input = {
      hostname: "s44a.one.two.form-app.app",
      role: "denied" as const,
      runId: "11111111-2222-4333-8444-555555555555",
      caseId: "secret-denied" as const,
      canary: `c44_${"x".repeat(24)}`,
      brokeredSecret: `s44_${"y".repeat(43)}`,
    };
    const message = operationMessage(input);
    const expected = `w44s_${createHmac("sha256", key).update(message).digest("base64url")}`;
    expect(await deriveOperationId(key, message, true)).toBe(expected);
    expect(expectedOperationId(
      key,
      input.runId,
      input.caseId,
      input.canary,
      input.role,
      input.brokeredSecret,
    )).toBe(expected);
    expect(message).toContain(input.hostname);
    expect(message).toContain(input.role);
    expect(message).toContain(input.runId);
    expect(message).toContain(input.caseId);
    expect(message).toContain(input.canary);
  });

  it("returns only role, brokered state, and the opaque receipt", async () => {
    const secret = `s44_${"z".repeat(43)}`;
    const message = operationMessage({
      hostname: "s44a.one.two.form-app.app", role: "denied",
      runId: "11111111-2222-4333-8444-555555555555",
      caseId: "secret-denied", canary: `c44_${"x".repeat(24)}`, brokeredSecret: secret,
    });
    const operationId = await deriveOperationId("k".repeat(48), message, true);
    const response = actionResponse("denied", true, operationId);
    expect(response).toEqual({ ok: true, role: "denied", brokered: true, operationId });
    expect(JSON.stringify(response)).not.toContain(secret);
    expect(JSON.stringify(response)).not.toContain(createHmac("sha256", "").update(secret).digest("hex"));
  });
});
