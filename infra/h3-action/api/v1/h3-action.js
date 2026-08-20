import { createHmac } from "node:crypto";

const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const canaryPattern = /^[A-Za-z0-9_-]{16,128}$/u;

function singleQueryValue(value) {
  return typeof value === "string" ? value : undefined;
}

export function deriveOperationId(key, runId, caseId, canary) {
  const digest = createHmac("sha256", key)
    .update(`${runId}\n${caseId}\n${canary}`)
    .digest("base64url");
  return `h3_${digest}`;
}

export default function handler(request, response) {
  response.setHeader("cache-control", "no-store, max-age=0");
  response.setHeader("content-type", "application/json; charset=utf-8");

  if (request.method !== "GET") {
    response.setHeader("allow", "GET");
    response.status(405).json({ authorized: false });
    return;
  }

  const key = process.env.H3_ACTION_KEY;
  if (!key || key.length < 32) {
    response.status(503).json({ authorized: false });
    return;
  }

  const runId = singleQueryValue(request.query?.run);
  const caseId = singleQueryValue(request.query?.case);
  const canary = singleQueryValue(request.query?.canary);
  if (
    !runId ||
    !caseId ||
    !canary ||
    !identifierPattern.test(runId) ||
    !identifierPattern.test(caseId) ||
    !canaryPattern.test(canary)
  ) {
    response.status(400).json({ authorized: false });
    return;
  }

  response.status(200).json({
    authorized: true,
    operationId: deriveOperationId(key, runId, caseId, canary),
  });
}
