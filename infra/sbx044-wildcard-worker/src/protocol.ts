const encoder = new TextEncoder();

export function operationMessage(input: {
  hostname: string;
  role: "allowed" | "denied";
  runId: string;
  caseId: string;
  canary: string;
  brokeredSecret?: string;
}): string {
  const prefix = `v1\nSBX-044-POC\n${input.hostname}\n${input.role}\n${input.runId}\n${input.caseId}\n${input.canary}`;
  return input.brokeredSecret === undefined
    ? `${prefix}\nreach`
    : `${prefix}\nsecret\n${input.brokeredSecret}`;
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, "");
}

export async function deriveOperationId(
  key: string,
  message: string,
  brokered: boolean,
): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(message));
  return `${brokered ? "w44s" : "w44r"}_${base64Url(new Uint8Array(signature))}`;
}

export function actionResponse(
  role: "allowed" | "denied",
  brokered: boolean,
  operationId: string,
): { ok: true; role: "allowed" | "denied"; brokered: boolean; operationId: string } {
  return { ok: true, role, brokered, operationId };
}
