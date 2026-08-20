import { createRequire } from "node:module";

export type Sbx051Role = "A" | "B";

export type Sbx051AttemptPurpose =
  | "missing-token-negative"
  | "random-token-negative"
  | "a-owner-control"
  | "b-owner-control"
  | "a-token-b-attack"
  | "b-target-validation";

export type Sbx051TokenSource = "none" | "random" | Sbx051Role;
export type Sbx051UrlCredentialPurpose =
  | "a-owner-control"
  | "b-owner-control"
  | "b-attack-target";
export type Sbx051TokenCredentialPurpose =
  | "none"
  | "random"
  | "a-owner-control"
  | "b-owner-control"
  | "a-attack"
  | "b-attack-target";

export interface Sbx051InteractiveAttempt {
  purpose: Sbx051AttemptPurpose;
  urlRole: Sbx051Role;
  tokenSource: Sbx051TokenSource;
  urlCredentialPurpose: Sbx051UrlCredentialPurpose;
  tokenCredentialPurpose: Sbx051TokenCredentialPurpose;
  requestCount: 1;
  retryCount: 0;
  webSocketClient: "ws@8.21.0";
  unexpectedResponseObserved: boolean;
  handshakeStatusCode: number | null;
  handshakeResponseBodyRetained: false;
  handshakeResponseHeadersRetained: false;
  opened: boolean;
  openedExactIssuedUrl: boolean;
  emptyNegotiatedProtocol: boolean;
  emptyNegotiatedExtensions: boolean;
  startMessageExpected: boolean;
  startMessagesSent: 0 | 1;
  exactStartMessage: boolean;
  binaryFrames: number;
  textControlFrames: number;
  outputBytes: number;
  exactExpectedMarker: boolean;
  exactUnexpectedMarker: boolean;
  exitCode: number | null;
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

export interface Sbx051WebSocketLike {
  binaryType: string;
  readonly url: string;
  readonly protocol: string;
  readonly extensions: string;
  once(type: "open", listener: () => void): this;
  once(type: "error", listener: (error: unknown) => void): this;
  once(type: "close", listener: (code: number, reason: Uint8Array) => void): this;
  once(
    type: "unexpected-response",
    listener: (request: Sbx051HandshakeRequest, response: Sbx051HandshakeResponse) => void,
  ): this;
  on(type: "message", listener: (data: unknown, isBinary: boolean) => void): this;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  terminate(): void;
}

export interface Sbx051HandshakeRequest {
  abort(): void;
}

export interface Sbx051HandshakeResponse {
  statusCode?: number;
  destroy(): void;
}

export interface Sbx051WebSocketOptions {
  followRedirects: false;
  handshakeTimeout: number;
  maxPayload: 4_096;
  perMessageDeflate: false;
  rejectUnauthorized: true;
}

export type Sbx051WebSocketFactory = (
  url: string,
  options: Sbx051WebSocketOptions,
) => Sbx051WebSocketLike;

export interface Sbx051RunAttemptInput {
  purpose: Sbx051AttemptPurpose;
  urlRole: Sbx051Role;
  tokenSource: Sbx051TokenSource;
  urlCredentialPurpose: Sbx051UrlCredentialPurpose;
  tokenCredentialPurpose: Sbx051TokenCredentialPurpose;
  baseUrl: string;
  token?: string;
  markerPath?: string;
  expectedMarker?: Uint8Array;
  unexpectedMarker?: Uint8Array;
  timeoutMs?: number;
  createWebSocket?: Sbx051WebSocketFactory;
}

const MAX_OUTPUT_BYTES = 4_096;
const MAX_BINARY_FRAMES = 16;
const MAX_TEXT_FRAMES = 4;
const MARKER_PATH = /^\/tmp\/sbx-051\/[ab]-[0-9a-f-]{36}\.marker$/u;
export const SBX051_WS_VERSION = "8.21.0" as const;

interface InstalledWsConstructor {
  new(url: string, options: Sbx051WebSocketOptions): Sbx051WebSocketLike;
}

const requireFromInstalledWorker = createRequire(
  new URL("../../infra/h3-action-worker/package.json", import.meta.url),
);
const { WebSocket: InstalledWebSocket } = requireFromInstalledWorker("ws") as {
  WebSocket: InstalledWsConstructor;
};

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((entry, index) => entry === wanted[index]);
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

export function exactSbx051BaseWebSocketUrl(raw: string): boolean {
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

export function buildSbx051StartMessage(markerPath: string): string {
  if (!MARKER_PATH.test(markerPath)) {
    throw new Error("SBX-051 refused a noncanonical marker path");
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

export function exactSbx051StartMessage(raw: string, markerPath: string): boolean {
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

export function parseSbx051ExitFrame(raw: string): number | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  const value = object(parsed);
  // Match the audited @vercel/sandbox CLI's wire handling: it selects an exit
  // control frame by `type` and consumes only its numeric `code`, ignoring any
  // additional server metadata. The surrounding protocol still bounds the raw
  // frame, permits only one exit frame, and rejects any later output.
  return value !== undefined && value.type === "exit" &&
    typeof value.code === "number" && Number.isSafeInteger(value.code) && value.code >= 0 &&
    value.code <= 255
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

function commandExpected(purpose: Sbx051AttemptPurpose): boolean {
  return purpose === "a-owner-control" || purpose === "b-owner-control" ||
    purpose === "a-token-b-attack" || purpose === "b-target-validation";
}

function exactPurpose(input: Sbx051RunAttemptInput): boolean {
  if (input.purpose === "missing-token-negative") {
    return input.urlRole === "B" && input.tokenSource === "none" && input.token === undefined &&
      input.urlCredentialPurpose === "b-owner-control" && input.tokenCredentialPurpose === "none";
  }
  if (input.purpose === "random-token-negative") {
    return input.urlRole === "B" && input.tokenSource === "random" && input.token !== undefined &&
      input.urlCredentialPurpose === "b-owner-control" && input.tokenCredentialPurpose === "random";
  }
  if (input.purpose === "a-owner-control") {
    return input.urlRole === "A" && input.tokenSource === "A" && input.token !== undefined &&
      input.urlCredentialPurpose === "a-owner-control" &&
      input.tokenCredentialPurpose === "a-owner-control";
  }
  if (input.purpose === "b-owner-control") {
    return input.urlRole === "B" && input.tokenSource === "B" && input.token !== undefined &&
      input.urlCredentialPurpose === "b-owner-control" &&
      input.tokenCredentialPurpose === "b-owner-control";
  }
  if (input.purpose === "a-token-b-attack") {
    return input.urlRole === "B" && input.tokenSource === "A" && input.token !== undefined &&
      input.urlCredentialPurpose === "b-attack-target" && input.tokenCredentialPurpose === "a-attack";
  }
  return input.urlRole === "B" && input.tokenSource === "B" && input.token !== undefined &&
    input.urlCredentialPurpose === "b-attack-target" &&
    input.tokenCredentialPurpose === "b-attack-target";
}

function credentialedUrl(base: string, token: string | undefined): string {
  return token === undefined ? base : `${base}?token=${encodeURIComponent(token)}`;
}

export async function runSbx051InteractiveAttempt(
  input: Sbx051RunAttemptInput,
): Promise<Sbx051InteractiveAttempt> {
  if (input.token !== undefined && (input.token.length < 16 || input.token.length > 8_192 ||
      /[\s\0]/u.test(input.token))) {
    throw new Error("SBX-051 refused an invalid transient interactive token");
  }
  if (!exactSbx051BaseWebSocketUrl(input.baseUrl) || !exactPurpose(input)) {
    throw new Error("SBX-051 refused an invalid interactive attempt binding");
  }
  const expectsCommand = commandExpected(input.purpose);
  if (expectsCommand !== (input.markerPath !== undefined && input.expectedMarker !== undefined) ||
      (expectsCommand && (input.expectedMarker!.byteLength < 32 ||
        input.expectedMarker!.byteLength > 256 || input.unexpectedMarker === undefined ||
        input.unexpectedMarker.byteLength < 32 || input.unexpectedMarker.byteLength > 256 ||
        exactPair(input.expectedMarker!, input.unexpectedMarker)))) {
    throw new Error("SBX-051 refused an invalid command/marker contract");
  }
  if (expectsCommand) {
    const expectedPathRole = input.purpose === "a-owner-control" ? "a" : "b";
    if (!input.markerPath!.startsWith(`/tmp/sbx-051/${expectedPathRole}-`)) {
      throw new Error("SBX-051 refused a marker path inconsistent with the fixed attempt role");
    }
  }
  const queryUrl = credentialedUrl(input.baseUrl, input.token);
  const timeoutMs = input.timeoutMs ?? 10_000;
  const options: Sbx051WebSocketOptions = {
    followRedirects: false,
    handshakeTimeout: timeoutMs,
    maxPayload: 4_096,
    perMessageDeflate: false,
    rejectUnauthorized: true,
  };
  const factory = input.createWebSocket ?? ((url: string, wsOptions: Sbx051WebSocketOptions) =>
    new InstalledWebSocket(url, wsOptions));
  let socket: Sbx051WebSocketLike;
  try {
    socket = factory(queryUrl, options);
  } catch {
    return emptyAttempt(input, expectsCommand, "transport-error");
  }
  socket.binaryType = "nodebuffer";

  return new Promise<Sbx051InteractiveAttempt>((resolve) => {
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
    let exitCode: number | null = null;
    let protocolError = false;
    const chunks: Uint8Array[] = [];
    const timeout = setTimeout(() => finish("timeout"), timeoutMs);

    const finish = (terminal: Sbx051InteractiveAttempt["terminal"]): void => {
      if (completed) return;
      completed = true;
      clearTimeout(timeout);
      const output = new Uint8Array(outputBytes);
      let offset = 0;
      for (const chunk of chunks) {
        output.set(chunk, offset);
        offset += chunk.byteLength;
        chunk.fill(0);
      }
      const exactExpectedMarker = exactPair(output, input.expectedMarker);
      const exactUnexpectedMarker = exactPair(output, input.unexpectedMarker);
      output.fill(0);
      try {
        socket.terminate();
      } catch {
        // The attempt is already terminal; termination is best effort and creates no retry.
      }
      resolve({
        purpose: input.purpose,
        urlRole: input.urlRole,
        tokenSource: input.tokenSource,
        urlCredentialPurpose: input.urlCredentialPurpose,
        tokenCredentialPurpose: input.tokenCredentialPurpose,
        requestCount: 1,
        retryCount: 0,
        webSocketClient: `ws@${SBX051_WS_VERSION}`,
        unexpectedResponseObserved,
        handshakeStatusCode,
        handshakeResponseBodyRetained: false,
        handshakeResponseHeadersRetained: false,
        opened,
        openedExactIssuedUrl,
        emptyNegotiatedProtocol,
        emptyNegotiatedExtensions,
        startMessageExpected: expectsCommand,
        startMessagesSent,
        exactStartMessage,
        binaryFrames,
        textControlFrames,
        outputBytes,
        exactExpectedMarker,
        exactUnexpectedMarker,
        exitCode,
        terminal: protocolError ? "protocol-error" : terminal,
        rawOutputRetained: false,
        rawMarkerRetained: false,
        rawTokenRetained: false,
        rawTokenDigestRetained: false,
        queryBearingUrlRetained: false,
      });
    };

    socket.once("unexpected-response", (request, response) => {
      if (completed) return;
      unexpectedResponseObserved = true;
      handshakeStatusCode = typeof response.statusCode === "number" &&
        Number.isSafeInteger(response.statusCode) && response.statusCode >= 100 &&
        response.statusCode <= 599
        ? response.statusCode
        : null;
      try {
        request.abort();
      } catch {
        // No status/body/header material is retained even if abort is already complete.
      }
      try {
        response.destroy();
      } catch {
        // Destroying the unread response is best effort.
      }
      finish("http-response-before-open");
    });

    socket.once("open", () => {
      if (completed) return;
      opened = true;
      openedExactIssuedUrl = socket.url === queryUrl;
      emptyNegotiatedProtocol = socket.protocol === "";
      emptyNegotiatedExtensions = socket.extensions === "";
      if (!expectsCommand) {
        finish("opened-without-command");
        return;
      }
      const message = buildSbx051StartMessage(input.markerPath!);
      exactStartMessage = exactSbx051StartMessage(message, input.markerPath!);
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
        protocolError = true;
        finish("protocol-error");
        return;
      }
      if (!isBinary) {
        textControlFrames += 1;
        const textBytes = typeof data === "string"
          ? Buffer.from(data, "utf8")
          : binaryData(data);
        if (textBytes === undefined || textControlFrames > MAX_TEXT_FRAMES || exitCode !== null ||
            textBytes.byteLength > 1_024) {
          protocolError = true;
          finish("protocol-error");
          return;
        }
        const text = Buffer.from(textBytes).toString("utf8");
        const parsedExit = parseSbx051ExitFrame(text);
        if (parsedExit === undefined) {
          protocolError = true;
          finish("protocol-error");
          return;
        }
        exitCode = parsedExit;
        return;
      }
      const chunk = binaryData(data);
      if (chunk === undefined || exitCode !== null) {
        protocolError = true;
        finish("protocol-error");
        return;
      }
      binaryFrames += 1;
      if (binaryFrames > MAX_BINARY_FRAMES || chunk.byteLength > MAX_OUTPUT_BYTES - outputBytes) {
        protocolError = true;
        finish("protocol-error");
        return;
      }
      outputBytes += chunk.byteLength;
      chunks.push(new Uint8Array(chunk));
    });

    socket.once("error", () => {
      if (completed) return;
      finish("transport-error");
    });

    socket.once("close", () => {
      if (completed) return;
      if (!opened) finish("transport-error");
      else if (expectsCommand && exitCode !== null) finish("closed-after-exit");
      else finish(protocolError ? "protocol-error" : "transport-error");
    });
  });
}

function emptyAttempt(
  input: Sbx051RunAttemptInput,
  expectsCommand: boolean,
  terminal: Sbx051InteractiveAttempt["terminal"],
): Sbx051InteractiveAttempt {
  return {
    purpose: input.purpose,
    urlRole: input.urlRole,
    tokenSource: input.tokenSource,
    urlCredentialPurpose: input.urlCredentialPurpose,
    tokenCredentialPurpose: input.tokenCredentialPurpose,
    requestCount: 1,
    retryCount: 0,
    webSocketClient: `ws@${SBX051_WS_VERSION}`,
    unexpectedResponseObserved: false,
    handshakeStatusCode: null,
    handshakeResponseBodyRetained: false,
    handshakeResponseHeadersRetained: false,
    opened: false,
    openedExactIssuedUrl: false,
    emptyNegotiatedProtocol: false,
    emptyNegotiatedExtensions: false,
    startMessageExpected: expectsCommand,
    startMessagesSent: 0,
    exactStartMessage: !expectsCommand,
    binaryFrames: 0,
    textControlFrames: 0,
    outputBytes: 0,
    exactExpectedMarker: false,
    exactUnexpectedMarker: false,
    exitCode: null,
    terminal,
    rawOutputRetained: false,
    rawMarkerRetained: false,
    rawTokenRetained: false,
    rawTokenDigestRetained: false,
    queryBearingUrlRetained: false,
  };
}
