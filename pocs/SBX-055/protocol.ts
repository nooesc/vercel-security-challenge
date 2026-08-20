import { createRequire } from "node:module";

export type Sbx055Role = "S1" | "S2";

export type Sbx055AttemptPurpose =
  | "missing-token-negative"
  | "random-token-negative"
  | "s1-owner-control"
  | "stale-s1-token-on-s2"
  | "s2-owner-control";

export type Sbx055TokenSourceSession = "none" | "random" | Sbx055Role;
export type Sbx055ExpectedRuntimeRole = "none" | Sbx055Role;
export type Sbx055UrlCredentialPurpose =
  | "s1-owner-control"
  | "s1-fresh-stale"
  | "s2-owner-control";
export type Sbx055TokenCredentialPurpose =
  | "none"
  | "random"
  | Sbx055UrlCredentialPurpose;

export type Sbx055StatusCategory =
  | "auth-rejected"
  | "other-http-response"
  | "websocket-opened"
  | "transport-error"
  | "protocol-error"
  | "timeout";

export interface Sbx055InteractiveAttempt {
  purpose: Sbx055AttemptPurpose;
  issuedUrlRole: Sbx055Role;
  tokenSourceSession: Sbx055TokenSourceSession;
  expectedRuntimeRole: Sbx055ExpectedRuntimeRole;
  urlCredentialPurpose: Sbx055UrlCredentialPurpose;
  tokenCredentialPurpose: Sbx055TokenCredentialPurpose;
  requestCount: 1;
  retryCount: 0;
  webSocketClient: "ws@8.21.0";
  statusCategory: Sbx055StatusCategory;
  unexpectedResponseObserved: boolean;
  handshakeStatusCode: number | null;
  handshakeResponseBodyRetained: false;
  handshakeResponseHeadersRetained: false;
  opened: boolean;
  authenticated: boolean;
  openedExactIssuedUrl: boolean;
  emptyNegotiatedProtocol: boolean;
  emptyNegotiatedExtensions: boolean;
  startMessageExpected: boolean;
  startMessagesSent: 0 | 1;
  exactStartMessage: boolean;
  binaryFrames: number;
  textControlFrames: number;
  outputBytes: number;
  markerMatched: boolean;
  crossMarkerAbsent: boolean;
  exitCode: number | null;
  protocolValid: boolean;
  terminal:
    | "http-response-before-open"
    | "closed-after-exit"
    | "opened-without-command"
    | "transport-error"
    | "protocol-error"
    | "timeout";
  rawOutputRetained: false;
  rawMarkerRetained: false;
  rawTokenRetained: false;
  rawTokenDigestRetained: false;
  queryBearingUrlRetained: false;
}

export interface Sbx055HandshakeRequest {
  abort(): void;
}

export interface Sbx055HandshakeResponse {
  statusCode?: number;
  destroy(): void;
}

export interface Sbx055WebSocketLike {
  binaryType: string;
  readonly url: string;
  readonly protocol: string;
  readonly extensions: string;
  once(type: "open", listener: () => void): this;
  once(type: "error", listener: (error: unknown) => void): this;
  once(type: "close", listener: (code: number, reason: Uint8Array) => void): this;
  once(
    type: "unexpected-response",
    listener: (request: Sbx055HandshakeRequest, response: Sbx055HandshakeResponse) => void,
  ): this;
  on(type: "message", listener: (data: unknown, isBinary: boolean) => void): this;
  send(data: string): void;
  terminate(): void;
}

export interface Sbx055WebSocketOptions {
  followRedirects: false;
  handshakeTimeout: number;
  maxPayload: 4_096;
  perMessageDeflate: false;
  rejectUnauthorized: true;
}

export type Sbx055WebSocketFactory = (
  url: string,
  options: Sbx055WebSocketOptions,
) => Sbx055WebSocketLike;

export interface Sbx055RunAttemptInput {
  purpose: Sbx055AttemptPurpose;
  issuedUrlRole: Sbx055Role;
  tokenSourceSession: Sbx055TokenSourceSession;
  expectedRuntimeRole: Sbx055ExpectedRuntimeRole;
  urlCredentialPurpose: Sbx055UrlCredentialPurpose;
  tokenCredentialPurpose: Sbx055TokenCredentialPurpose;
  baseUrl: string;
  token?: string;
  markerPath?: string;
  expectedMarker?: Uint8Array;
  crossMarker?: Uint8Array;
  timeoutMs?: number;
  createWebSocket?: Sbx055WebSocketFactory;
}

export const SBX055_WS_VERSION = "8.21.0" as const;

const MAX_OUTPUT_BYTES = 4_096;
const MAX_TEXT_CONTROL_BYTES = 1_024;
const MARKER_PATH =
  /^\/tmp\/sbx-055\/(s1|s2)-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.marker$/u;

interface InstalledWsConstructor {
  new(url: string, options: Sbx055WebSocketOptions): Sbx055WebSocketLike;
}

const requireFromInstalledWorker = createRequire(
  new URL("../../infra/h3-action-worker/package.json", import.meta.url),
);
const installedWsPackage = requireFromInstalledWorker("ws/package.json") as { version?: unknown };
if (installedWsPackage.version !== SBX055_WS_VERSION) {
  throw new Error("SBX-055 refused an unaudited installed WebSocket client version");
}
const { WebSocket: InstalledWebSocket } = requireFromInstalledWorker("ws") as {
  WebSocket: InstalledWsConstructor;
};

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((entry, index) => entry === wanted[index]);
}

export function exactSbx055BaseWebSocketUrl(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  const canonical = `${url.protocol}//${url.host}${url.pathname}`;
  return raw === canonical && url.protocol === "wss:" && url.username === "" &&
    url.password === "" && url.port === "" && url.search === "" && url.hash === "" &&
    url.hostname === url.hostname.toLowerCase() && !url.hostname.endsWith(".") &&
    url.hostname.endsWith(".vercel.run") && url.pathname.startsWith("/") &&
    url.pathname.length <= 1_024 && !/%(?:2f|5c)/iu.test(url.pathname);
}

export function buildSbx055StartMessage(markerPath: string): string {
  if (!MARKER_PATH.test(markerPath)) {
    throw new Error("SBX-055 refused a noncanonical marker path");
  }
  return JSON.stringify({
    type: "start",
    command: "/bin/cat",
    args: [markerPath],
    env: [],
    cwd: "/",
    cols: 80,
    rows: 24,
  });
}

export function exactSbx055StartMessage(raw: string, markerPath: string): boolean {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return false;
  }
  const value = object(parsed);
  return value !== undefined &&
    exactKeys(value, ["type", "command", "args", "env", "cwd", "cols", "rows"]) &&
    value.type === "start" && value.command === "/bin/cat" &&
    Array.isArray(value.args) && value.args.length === 1 && value.args[0] === markerPath &&
    Array.isArray(value.env) && value.env.length === 0 && value.cwd === "/" &&
    value.cols === 80 && value.rows === 24;
}

export function parseSbx055ExitFrame(raw: string): number | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  const value = object(parsed);
  // This is the installed CLI's audited subset: select by `type`, consume the
  // bounded numeric `code`, and ignore any additional server metadata.
  return value !== undefined && value.type === "exit" && typeof value.code === "number" &&
    Number.isSafeInteger(value.code) && value.code >= 0 && value.code <= 255
    ? value.code
    : undefined;
}

function exactPair(left: Uint8Array, right: Uint8Array | undefined): boolean {
  if (right === undefined || left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function binaryData(value: unknown): Uint8Array | undefined {
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  return undefined;
}

function commandExpected(purpose: Sbx055AttemptPurpose): boolean {
  return purpose === "s1-owner-control" || purpose === "stale-s1-token-on-s2" ||
    purpose === "s2-owner-control";
}

function exactPurpose(input: Sbx055RunAttemptInput): boolean {
  if (input.purpose === "missing-token-negative") {
    return input.issuedUrlRole === "S1" && input.tokenSourceSession === "none" &&
      input.expectedRuntimeRole === "none" && input.token === undefined &&
      input.urlCredentialPurpose === "s1-owner-control" && input.tokenCredentialPurpose === "none";
  }
  if (input.purpose === "random-token-negative") {
    return input.issuedUrlRole === "S1" && input.tokenSourceSession === "random" &&
      input.expectedRuntimeRole === "none" && input.token !== undefined &&
      input.urlCredentialPurpose === "s1-owner-control" && input.tokenCredentialPurpose === "random";
  }
  if (input.purpose === "s1-owner-control") {
    return input.issuedUrlRole === "S1" && input.tokenSourceSession === "S1" &&
      input.expectedRuntimeRole === "S1" && input.token !== undefined &&
      input.urlCredentialPurpose === "s1-owner-control" &&
      input.tokenCredentialPurpose === "s1-owner-control";
  }
  if (input.purpose === "stale-s1-token-on-s2") {
    return input.issuedUrlRole === "S1" && input.tokenSourceSession === "S1" &&
      input.expectedRuntimeRole === "S2" && input.token !== undefined &&
      input.urlCredentialPurpose === "s1-fresh-stale" &&
      input.tokenCredentialPurpose === "s1-fresh-stale";
  }
  return input.issuedUrlRole === "S2" && input.tokenSourceSession === "S2" &&
    input.expectedRuntimeRole === "S2" && input.token !== undefined &&
    input.urlCredentialPurpose === "s2-owner-control" &&
    input.tokenCredentialPurpose === "s2-owner-control";
}

function credentialedUrl(base: string, token: string | undefined): string {
  // Keep this byte-for-byte aligned with the installed CLI.
  return token === undefined ? base : `${base}?token=${encodeURIComponent(token)}`;
}

function statusCategory(
  terminal: Sbx055InteractiveAttempt["terminal"],
  statusCode: number | null,
): Sbx055StatusCategory {
  if (terminal === "http-response-before-open") {
    return statusCode === 401 || statusCode === 403 ? "auth-rejected" : "other-http-response";
  }
  if (terminal === "transport-error") return "transport-error";
  if (terminal === "protocol-error") return "protocol-error";
  if (terminal === "timeout") return "timeout";
  return "websocket-opened";
}

function emptyAttempt(
  input: Sbx055RunAttemptInput,
  expectsCommand: boolean,
  terminal: Sbx055InteractiveAttempt["terminal"],
): Sbx055InteractiveAttempt {
  return {
    purpose: input.purpose,
    issuedUrlRole: input.issuedUrlRole,
    tokenSourceSession: input.tokenSourceSession,
    expectedRuntimeRole: input.expectedRuntimeRole,
    urlCredentialPurpose: input.urlCredentialPurpose,
    tokenCredentialPurpose: input.tokenCredentialPurpose,
    requestCount: 1,
    retryCount: 0,
    webSocketClient: `ws@${SBX055_WS_VERSION}`,
    statusCategory: statusCategory(terminal, null),
    unexpectedResponseObserved: false,
    handshakeStatusCode: null,
    handshakeResponseBodyRetained: false,
    handshakeResponseHeadersRetained: false,
    opened: false,
    authenticated: false,
    openedExactIssuedUrl: false,
    emptyNegotiatedProtocol: false,
    emptyNegotiatedExtensions: false,
    startMessageExpected: expectsCommand,
    startMessagesSent: 0,
    exactStartMessage: !expectsCommand,
    binaryFrames: 0,
    textControlFrames: 0,
    outputBytes: 0,
    markerMatched: false,
    crossMarkerAbsent: false,
    exitCode: null,
    protocolValid: false,
    terminal,
    rawOutputRetained: false,
    rawMarkerRetained: false,
    rawTokenRetained: false,
    rawTokenDigestRetained: false,
    queryBearingUrlRetained: false,
  };
}

export async function runSbx055InteractiveAttempt(
  input: Sbx055RunAttemptInput,
): Promise<Sbx055InteractiveAttempt> {
  if (input.token !== undefined && (input.token.length < 16 || input.token.length > 8_192 ||
      /[\s\0]/u.test(input.token))) {
    throw new Error("SBX-055 refused an invalid transient interactive token");
  }
  if (!exactSbx055BaseWebSocketUrl(input.baseUrl) || !exactPurpose(input)) {
    throw new Error("SBX-055 refused an invalid interactive attempt binding");
  }
  const expectsCommand = commandExpected(input.purpose);
  const completeMarkerContract = input.markerPath !== undefined &&
    input.expectedMarker !== undefined && input.crossMarker !== undefined;
  if (expectsCommand !== completeMarkerContract || (!expectsCommand &&
      (input.markerPath !== undefined || input.expectedMarker !== undefined ||
        input.crossMarker !== undefined)) || (expectsCommand &&
      (input.expectedMarker!.byteLength < 32 || input.expectedMarker!.byteLength > 256 ||
        input.crossMarker!.byteLength < 32 || input.crossMarker!.byteLength > 256 ||
        exactPair(input.expectedMarker!, input.crossMarker)))) {
    throw new Error("SBX-055 refused an invalid command/marker contract");
  }
  if (expectsCommand) {
    const expectedPathRole = input.expectedRuntimeRole.toLowerCase();
    if (!input.markerPath!.startsWith(`/tmp/sbx-055/${expectedPathRole}-`)) {
      throw new Error("SBX-055 refused a marker path inconsistent with the attempt role");
    }
    // Validate the full path, including a canonical UUIDv4, before opening a socket.
    buildSbx055StartMessage(input.markerPath!);
  }
  const timeoutMs = input.timeoutMs ?? 10_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) {
    throw new Error("SBX-055 refused an invalid WebSocket timeout");
  }
  const queryUrl = credentialedUrl(input.baseUrl, input.token);
  const options: Sbx055WebSocketOptions = {
    followRedirects: false,
    handshakeTimeout: timeoutMs,
    maxPayload: 4_096,
    perMessageDeflate: false,
    rejectUnauthorized: true,
  };
  const factory = input.createWebSocket ?? ((url: string, wsOptions: Sbx055WebSocketOptions) =>
    new InstalledWebSocket(url, wsOptions));
  let socket: Sbx055WebSocketLike;
  try {
    socket = factory(queryUrl, options);
    socket.binaryType = "nodebuffer";
  } catch {
    return emptyAttempt(input, expectsCommand, "transport-error");
  }

  return new Promise<Sbx055InteractiveAttempt>((resolve) => {
    let completed = false;
    let opened = false;
    let unexpectedResponseObserved = false;
    let handshakeStatusCode: number | null = null;
    let openedExactIssuedUrl = false;
    let emptyNegotiatedProtocol = false;
    let emptyNegotiatedExtensions = false;
    let startMessagesSent: 0 | 1 = 0;
    let exactStartMessage = !expectsCommand;
    let binaryFrames = 0;
    let textControlFrames = 0;
    let outputBytes = 0;
    let markerMatched = false;
    let crossMarkerAbsent = false;
    let exitCode: number | null = null;
    const timeout = setTimeout(() => finish("timeout"), timeoutMs);

    function finish(terminal: Sbx055InteractiveAttempt["terminal"]): void {
      if (completed) return;
      completed = true;
      clearTimeout(timeout);
      // A completed WebSocket upgrade is the only protocol-level evidence that
      // the service accepted the supplied credential. Exact URL attribution is
      // recorded and gated separately; conflating the two would hide an
      // accepted-but-misattributed socket as an authentication failure.
      const authenticated = opened;
      const protocolValid = terminal === "closed-after-exit" && authenticated &&
        openedExactIssuedUrl && emptyNegotiatedProtocol && emptyNegotiatedExtensions && expectsCommand &&
        startMessagesSent === 1 && exactStartMessage && binaryFrames === 1 &&
        textControlFrames === 1 && markerMatched && crossMarkerAbsent && exitCode === 0;
      try {
        socket.terminate();
      } catch {
        // The one-use attempt is terminal. Termination is best effort and never retried.
      }
      resolve({
        purpose: input.purpose,
        issuedUrlRole: input.issuedUrlRole,
        tokenSourceSession: input.tokenSourceSession,
        expectedRuntimeRole: input.expectedRuntimeRole,
        urlCredentialPurpose: input.urlCredentialPurpose,
        tokenCredentialPurpose: input.tokenCredentialPurpose,
        requestCount: 1,
        retryCount: 0,
        webSocketClient: `ws@${SBX055_WS_VERSION}`,
        statusCategory: statusCategory(terminal, handshakeStatusCode),
        unexpectedResponseObserved,
        handshakeStatusCode,
        handshakeResponseBodyRetained: false,
        handshakeResponseHeadersRetained: false,
        opened,
        authenticated,
        openedExactIssuedUrl,
        emptyNegotiatedProtocol,
        emptyNegotiatedExtensions,
        startMessageExpected: expectsCommand,
        startMessagesSent,
        exactStartMessage,
        binaryFrames,
        textControlFrames,
        outputBytes,
        markerMatched,
        crossMarkerAbsent,
        exitCode,
        protocolValid,
        terminal,
        rawOutputRetained: false,
        rawMarkerRetained: false,
        rawTokenRetained: false,
        rawTokenDigestRetained: false,
        queryBearingUrlRetained: false,
      });
    }

    socket.once("unexpected-response", (request, response) => {
      if (completed) return;
      if (opened) {
        finish("protocol-error");
        return;
      }
      unexpectedResponseObserved = true;
      handshakeStatusCode = typeof response.statusCode === "number" &&
        Number.isSafeInteger(response.statusCode) && response.statusCode >= 100 &&
        response.statusCode <= 599
        ? response.statusCode
        : null;
      try {
        request.abort();
      } catch {
        // Request, headers, and body are never retained.
      }
      try {
        response.destroy();
      } catch {
        // Destruction of the unread response is best effort.
      }
      finish("http-response-before-open");
    });

    socket.once("open", () => {
      if (completed) return;
      opened = true;
      try {
        openedExactIssuedUrl = socket.url === queryUrl;
        emptyNegotiatedProtocol = socket.protocol === "";
        emptyNegotiatedExtensions = socket.extensions === "";
      } catch {
        finish("protocol-error");
        return;
      }
      if (!expectsCommand) {
        finish("opened-without-command");
        return;
      }
      const message = buildSbx055StartMessage(input.markerPath!);
      exactStartMessage = exactSbx055StartMessage(message, input.markerPath!);
      try {
        socket.send(message);
        startMessagesSent = 1;
      } catch {
        finish("transport-error");
      }
    });

    socket.on("message", (data, isBinary) => {
      if (completed) return;
      if (!opened || !expectsCommand) {
        finish("protocol-error");
        return;
      }
      if (isBinary) {
        const bytes = binaryData(data);
        if (bytes === undefined || binaryFrames !== 0 || exitCode !== null ||
            bytes.byteLength > MAX_OUTPUT_BYTES) {
          finish("protocol-error");
          return;
        }
        binaryFrames = 1;
        outputBytes = bytes.byteLength;
        const transient = new Uint8Array(bytes);
        markerMatched = exactPair(transient, input.expectedMarker);
        crossMarkerAbsent = !exactPair(transient, input.crossMarker);
        transient.fill(0);
        return;
      }
      textControlFrames += 1;
      const textBytes = typeof data === "string" ? Buffer.from(data, "utf8") : binaryData(data);
      if (textBytes === undefined || textControlFrames !== 1 || exitCode !== null ||
          textBytes.byteLength > MAX_TEXT_CONTROL_BYTES) {
        finish("protocol-error");
        return;
      }
      const parsedExit = parseSbx055ExitFrame(Buffer.from(textBytes).toString("utf8"));
      if (parsedExit === undefined) {
        finish("protocol-error");
        return;
      }
      exitCode = parsedExit;
    });

    socket.once("error", () => {
      if (!completed) finish("transport-error");
    });

    socket.once("close", () => {
      if (completed) return;
      if (!opened) finish("transport-error");
      else if (expectsCommand && exitCode !== null) finish("closed-after-exit");
      else finish("protocol-error");
    });
  });
}
