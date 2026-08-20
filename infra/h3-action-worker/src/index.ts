const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const canaryPattern = /^[A-Za-z0-9_-]{16,128}$/u;
const encoder = new TextEncoder();

function json(body: unknown, status: number): Response {
  return Response.json(body, {
    status,
    headers: {
      "cache-control": "no-store, max-age=0",
      "x-content-type-options": "nosniff",
    },
  });
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, "");
}

export async function deriveOperationId(
  key: string,
  runId: string,
  caseId: string,
  canary: string,
): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    encoder.encode(`${runId}\n${caseId}\n${canary}`),
  );
  return `h3_${base64Url(new Uint8Array(signature))}`;
}

async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === "/healthz") return json({ ok: true }, 200);
  if (url.pathname !== "/v1/h3-action") return json({ authorized: false }, 404);
  if (request.method !== "GET") {
    return new Response(JSON.stringify({ authorized: false }), {
      status: 405,
      headers: {
        allow: "GET",
        "cache-control": "no-store, max-age=0",
        "content-type": "application/json; charset=utf-8",
        "x-content-type-options": "nosniff",
      },
    });
  }

  const runId = url.searchParams.get("run");
  const caseId = url.searchParams.get("case");
  const canary = url.searchParams.get("canary");
  if (
    !runId ||
    !caseId ||
    !canary ||
    !identifierPattern.test(runId) ||
    !identifierPattern.test(caseId) ||
    !canaryPattern.test(canary)
  ) {
    return json({ authorized: false }, 400);
  }

  return json({
    authorized: true,
    operationId: await deriveOperationId(env.H3_ACTION_KEY, runId, caseId, canary),
  }, 200);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await handleRequest(request, env);
    } catch (error) {
      console.error(JSON.stringify({
        message: "h3 action request failed",
        error: error instanceof Error ? error.message : String(error),
        path: new URL(request.url).pathname,
      }));
      return json({ authorized: false }, 500);
    }
  },
} satisfies ExportedHandler<Env>;
