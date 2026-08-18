import http from "node:http";
import https from "node:https";

const encoded = process.argv[2];
if (!encoded) throw new Error("missing base64url probe configuration");
const config = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
const base = new URL(config.baseUrl);
const client = base.protocol === "https:" ? https : http;
const separator = config.rawPath.includes("?") ? "&" : "?";
const metadata = new URLSearchParams({
  __sbx_run: config.runId,
  __sbx_test: config.testId,
  __sbx_case: config.caseId,
  __sbx_canary: config.canary,
});
const path = `${config.rawPath}${separator}${metadata}`;

const result = await new Promise((resolve) => {
  const startedAt = Date.now();
  const request = client.request(
    {
      protocol: base.protocol,
      hostname: base.hostname,
      port: base.port || undefined,
      method: config.method,
      path,
      headers: config.headers,
      timeout: config.timeoutMs,
    },
    (response) => {
      let bodyLength = 0;
      response.on("data", (chunk) => {
        bodyLength += chunk.length;
      });
      response.on("end", () => {
        resolve({
          ok: true,
          statusCode: response.statusCode,
          bodyLength,
          durationMs: Date.now() - startedAt,
        });
      });
    },
  );
  request.on("timeout", () => request.destroy(new Error("request timed out")));
  request.on("error", (error) => {
    resolve({
      ok: false,
      error: error instanceof Error ? error.message : String(error),
      durationMs: Date.now() - startedAt,
    });
  });
  request.end();
});

process.stdout.write(`${JSON.stringify(result)}\n`);
