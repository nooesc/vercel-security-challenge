import {
  ANALYTICS_ROW_LIMIT,
  ZONE_ID,
  type CloudflareDnsRow,
} from "./shared.js";

const GRAPHQL_ENDPOINT = "https://api.cloudflare.com/client/v4/graphql";
const maximumResponseBytes = 5 * 1024 * 1024;

const commonVariables = `
  $zoneTag: string!
  $start: Time!
  $end: Time!
`;

function analyticsQuery(exact: boolean, includeSampleInterval: boolean): string {
  return `query SBX001DnsAnalytics(
    ${commonVariables}
    ${exact ? "$queryName: string!" : ""}
  ) {
    viewer {
      zones(filter: { zoneTag: $zoneTag }) {
        dnsAnalyticsAdaptive(
          filter: {
            datetime_gt: $start
            datetime_lt: $end
            queryType: "A"
            ${exact ? "queryName: $queryName" : ""}
          }
          limit: ${ANALYTICS_ROW_LIMIT}
          orderBy: [datetime_ASC]
        ) {
          datetime
          queryName
          queryType
          responseCode
          ${includeSampleInterval ? "sampleInterval" : ""}
        }
      }
    }
  }`;
}

interface GraphqlEnvelope {
  data?: unknown;
  errors?: Array<{ message?: unknown }>;
}

async function readBoundedText(response: Response): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      const chunk = Buffer.from(next.value);
      total += chunk.byteLength;
      if (total > maximumResponseBytes) {
        chunk.fill(0);
        await reader.cancel("fixed response byte bound exceeded");
        throw new Error("Cloudflare GraphQL response exceeded the fixed byte bound");
      }
      chunks.push(chunk);
    }
    return Buffer.concat(chunks, total).toString("utf8");
  } finally {
    for (const chunk of chunks) chunk.fill(0);
    reader.releaseLock();
  }
}

export interface DnsAnalyticsFetchResult {
  rows: CloudflareDnsRow[];
  sampleIntervalRequested: boolean;
  sampleIntervalAvailable: boolean;
  responseByteLength: number;
}

function apiToken(value: string): string {
  if (Buffer.byteLength(value) < 20 || Buffer.byteLength(value) > 512 || /[\0\r\n]/u.test(value)) {
    throw new Error("CLOUDFLARE_API_TOKEN must contain 20-512 bytes without control characters");
  }
  return value;
}

function isoTime(value: string, name: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) throw new Error(`${name} must be an ISO-8601 timestamp`);
  return new Date(timestamp).toISOString();
}

function rowsFromEnvelope(envelope: GraphqlEnvelope): CloudflareDnsRow[] {
  const data = envelope.data;
  if (data === null || typeof data !== "object" || Array.isArray(data)) throw new Error("Cloudflare GraphQL returned no data object");
  const viewer = (data as { viewer?: unknown }).viewer;
  if (viewer === null || typeof viewer !== "object" || Array.isArray(viewer)) throw new Error("Cloudflare GraphQL returned no viewer object");
  const zones = (viewer as { zones?: unknown }).zones;
  if (!Array.isArray(zones) || zones.length !== 1) throw new Error("Cloudflare GraphQL did not return the exact zone scope");
  const zone = zones[0];
  if (zone === null || typeof zone !== "object" || Array.isArray(zone)) throw new Error("Cloudflare GraphQL returned an invalid zone result");
  const rows = (zone as { dnsAnalyticsAdaptive?: unknown }).dnsAnalyticsAdaptive;
  if (!Array.isArray(rows) || rows.length > ANALYTICS_ROW_LIMIT) throw new Error("Cloudflare GraphQL returned an invalid or oversized DNS dataset");
  return rows.map((row) => {
    if (row === null || typeof row !== "object" || Array.isArray(row)) throw new Error("Cloudflare GraphQL returned a non-object DNS row");
    const value = row as Record<string, unknown>;
    return {
      datetime: value.datetime,
      queryName: value.queryName,
      queryType: value.queryType,
      responseCode: value.responseCode,
      ...(value.sampleInterval !== undefined ? { sampleInterval: value.sampleInterval } : {}),
    };
  });
}

async function performQuery(input: {
  token: string;
  start: string;
  end: string;
  queryName?: string;
  includeSampleInterval: boolean;
}): Promise<{ envelope: GraphqlEnvelope; responseByteLength: number }> {
  const exact = input.queryName !== undefined;
  const body = JSON.stringify({
    query: analyticsQuery(exact, input.includeSampleInterval),
    variables: {
      zoneTag: ZONE_ID,
      start: isoTime(input.start, "analytics start"),
      end: isoTime(input.end, "analytics end"),
      ...(input.queryName ? { queryName: input.queryName } : {}),
    },
  });
  const response = await fetch(GRAPHQL_ENDPOINT, {
    method: "POST",
    headers: {
      authorization: `Bearer ${apiToken(input.token)}`,
      "content-type": "application/json",
      accept: "application/json",
    },
    body,
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) throw new Error(`Cloudflare GraphQL returned HTTP ${response.status}`);
  const contentLength = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > maximumResponseBytes) {
    throw new Error("Cloudflare GraphQL response exceeded the fixed byte bound");
  }
  let text = await readBoundedText(response);
  try {
    if (Buffer.byteLength(text) > maximumResponseBytes) throw new Error("Cloudflare GraphQL response exceeded the fixed byte bound");
    const envelope = JSON.parse(text) as GraphqlEnvelope;
    return { envelope, responseByteLength: Buffer.byteLength(text) };
  } finally {
    text = "";
  }
}

function errorMessages(envelope: GraphqlEnvelope): string[] {
  if (!Array.isArray(envelope.errors)) return [];
  return envelope.errors
    .map((entry) => typeof entry.message === "string" ? entry.message.replace(/[\0\r\n]/gu, " ").slice(0, 500) : "GraphQL error")
    .slice(0, 10);
}

export async function fetchDnsAnalytics(input: {
  token: string;
  start: string;
  end: string;
  queryName?: string;
}): Promise<DnsAnalyticsFetchResult> {
  let result = await performQuery({ ...input, includeSampleInterval: true });
  let messages = errorMessages(result.envelope);
  let sampleIntervalAvailable = true;
  if (messages.some((message) => /sampleInterval|Cannot query field/iu.test(message))) {
    result = await performQuery({ ...input, includeSampleInterval: false });
    messages = errorMessages(result.envelope);
    sampleIntervalAvailable = false;
  }
  if (messages.length > 0) {
    const sanitizedMessages = input.queryName
      ? messages.map((message) => message.split(input.queryName!).join("[QUERY_NAME_REDACTED]"))
      : messages;
    throw new Error(`Cloudflare GraphQL query failed: ${sanitizedMessages.join("; ")}`);
  }
  return {
    rows: rowsFromEnvelope(result.envelope),
    sampleIntervalRequested: true,
    sampleIntervalAvailable,
    responseByteLength: result.responseByteLength,
  };
}
