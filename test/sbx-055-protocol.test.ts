import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import {
  buildSbx055StartMessage,
  exactSbx055BaseWebSocketUrl,
  exactSbx055StartMessage,
  parseSbx055ExitFrame,
  runSbx055InteractiveAttempt,
  type Sbx055InteractiveAttempt,
  type Sbx055RunAttemptInput,
  type Sbx055WebSocketFactory,
  type Sbx055WebSocketOptions,
} from "../pocs/SBX-055/protocol.js";

const executeFile = promisify(execFile);
const s1Url = "wss://interactive.vercel.run/pty/session";
const s2Url = "wss://interactive.vercel.run/pty/session";
const s1Path = "/tmp/sbx-055/s1-123e4567-e89b-42d3-a456-426614174000.marker";
const s2Path = "/tmp/sbx-055/s2-123e4567-e89b-42d3-a456-426614174001.marker";
const m1 = new TextEncoder().encode("M1:" + "A".repeat(40));
const m2 = new TextEncoder().encode("M2:" + "B".repeat(40));
const s1Token = "s1-token-1234567890/?&=";
const s2Token = "s2-token-1234567890/?&=";

type FakeEvent = "open" | "error" | "close" | "message" | "unexpected-response";
type FakeListener = (...arguments_: any[]) => void;

class FakeWebSocket {
  binaryType = "";
  readonly sent: string[] = [];
  readonly listeners = new Map<FakeEvent, FakeListener[]>();
  terminateCalls = 0;
  handshakeAbortCalls = 0;
  responseDestroyCalls = 0;

  constructor(
    readonly url: string,
    readonly protocol = "",
    readonly extensions = "",
  ) {}

  once(type: FakeEvent, listener: FakeListener): this {
    const listeners = this.listeners.get(type) ?? [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
    return this;
  }

  on(type: FakeEvent, listener: FakeListener): this {
    return this.once(type, listener);
  }

  send(data: string): void {
    this.sent.push(data);
  }

  terminate(): void {
    this.terminateCalls += 1;
  }

  emit(type: FakeEvent, ...arguments_: unknown[]): void {
    for (const listener of this.listeners.get(type) ?? []) listener(...arguments_);
  }

  emitUnexpectedResponse(statusCode?: number): void {
    this.emit("unexpected-response", {
      abort: () => { this.handshakeAbortCalls += 1; },
    }, {
      ...(statusCode === undefined ? {} : { statusCode }),
      destroy: () => { this.responseDestroyCalls += 1; },
    });
  }
}

function scriptedFactory(
  script: (socket: FakeWebSocket) => void,
  negotiated: { protocol?: string; extensions?: string } = {},
): {
  factory: Sbx055WebSocketFactory;
  sockets: FakeWebSocket[];
  options: Sbx055WebSocketOptions[];
} {
  const sockets: FakeWebSocket[] = [];
  const options: Sbx055WebSocketOptions[] = [];
  const factory = ((url: string, wsOptions: Sbx055WebSocketOptions) => {
    const socket = new FakeWebSocket(url, negotiated.protocol, negotiated.extensions);
    sockets.push(socket);
    options.push(wsOptions);
    queueMicrotask(() => script(socket));
    return socket;
  }) as unknown as Sbx055WebSocketFactory;
  return { factory, sockets, options };
}

function bytes(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer;
}

function commandInput(overrides: Partial<Sbx055RunAttemptInput> = {}): Sbx055RunAttemptInput {
  return {
    purpose: "s1-owner-control",
    issuedUrlRole: "S1",
    tokenSourceSession: "S1",
    expectedRuntimeRole: "S1",
    urlCredentialPurpose: "s1-owner-control",
    tokenCredentialPurpose: "s1-owner-control",
    baseUrl: s1Url,
    token: s1Token,
    markerPath: s1Path,
    expectedMarker: m1,
    crossMarker: m2,
    timeoutMs: 50,
    ...overrides,
  };
}

function expectSecretFree(attempt: Sbx055InteractiveAttempt, forbidden: readonly string[]): void {
  expect(attempt).toMatchObject({
    requestCount: 1,
    retryCount: 0,
    rawOutputRetained: false,
    rawMarkerRetained: false,
    rawTokenRetained: false,
    rawTokenDigestRetained: false,
    queryBearingUrlRetained: false,
    handshakeResponseBodyRetained: false,
    handshakeResponseHeadersRetained: false,
  });
  const serialized = JSON.stringify(attempt);
  for (const value of forbidden) expect(serialized).not.toContain(value);
  expect(serialized).not.toMatch(/wss:\/\/|[?&]token=/iu);
}

describe("SBX-055 exact interactive primitives", () => {
  it("accepts only canonical query-free Vercel WSS URLs", () => {
    expect(exactSbx055BaseWebSocketUrl(s1Url)).toBe(true);
    for (const value of [
      "ws://interactive.vercel.run/pty/session",
      "https://interactive.vercel.run/pty/session",
      "wss://interactive.vercel.run:443/pty/session",
      "wss://user@interactive.vercel.run/pty/session",
      "wss://interactive.vercel.run/pty/session?token=x",
      "wss://interactive.vercel.run/pty/session#fragment",
      "wss://interactive.vercel.run./pty/session",
      "wss://INTERACTIVE.vercel.run/pty/session",
      "wss://interactive.example.test/pty/session",
      "wss://interactive.vercel.run/pty/%2fescape",
      "wss://interactive.vercel.run/pty/../other",
    ]) expect(exactSbx055BaseWebSocketUrl(value), value).toBe(false);
  });

  it("builds only the fixed /bin/cat command over canonical role paths", () => {
    const raw = buildSbx055StartMessage(s2Path);
    expect(JSON.parse(raw)).toEqual({
      type: "start",
      command: "/bin/cat",
      args: [s2Path],
      env: [],
      cwd: "/",
      cols: 80,
      rows: 24,
    });
    expect(exactSbx055StartMessage(raw, s2Path)).toBe(true);
    expect(exactSbx055StartMessage(raw, s1Path)).toBe(false);
    expect(exactSbx055StartMessage(JSON.stringify({ ...JSON.parse(raw), shell: true }), s2Path))
      .toBe(false);
    for (const path of [
      "/tmp/sbx-055/s2-not-a-uuid.marker",
      "/tmp/sbx-055/s2-123e4567-e89b-12d3-a456-426614174001.marker",
      "/tmp/sbx-055/../secret",
      "/etc/passwd",
    ]) expect(() => buildSbx055StartMessage(path), path).toThrow(/noncanonical/u);
  });

  it("uses the CLI-compatible exit subset while bounding the code", () => {
    expect(parseSbx055ExitFrame('{"type":"exit","code":0}')).toBe(0);
    expect(parseSbx055ExitFrame('{"type":"exit","code":255,"signal":null}')).toBe(255);
    for (const raw of [
      '{"type":"exit","code":-1}',
      '{"type":"exit","code":256}',
      '{"type":"exit","code":"0"}',
      '{"type":"exit"}',
      '{"type":"stdout","code":0}',
      "not-json",
    ]) expect(parseSbx055ExitFrame(raw), raw).toBeUndefined();
  });
});

describe("SBX-055 one-use WebSocket protocol", () => {
  it("constructs the exact CLI token query and accepts one marker plus one exit", async () => {
    const { factory, sockets, options } = scriptedFactory((socket) => {
      socket.emit("open");
      socket.emit("message", bytes(m1), true);
      socket.emit("message", '{"type":"exit","code":0,"durationMs":12}', false);
      socket.emit("close", 1000, new Uint8Array());
    });
    const result = await runSbx055InteractiveAttempt(commandInput({ createWebSocket: factory }));

    expect(sockets).toHaveLength(1);
    expect(sockets[0]!.url).toBe(`${s1Url}?token=${encodeURIComponent(s1Token)}`);
    expect(sockets[0]!.binaryType).toBe("nodebuffer");
    expect(sockets[0]!.sent).toEqual([buildSbx055StartMessage(s1Path)]);
    expect(sockets[0]!.terminateCalls).toBe(1);
    expect(options).toEqual([{
      followRedirects: false,
      handshakeTimeout: 50,
      maxPayload: 4_096,
      perMessageDeflate: false,
      rejectUnauthorized: true,
    }]);
    expect(result).toMatchObject({
      purpose: "s1-owner-control",
      issuedUrlRole: "S1",
      tokenSourceSession: "S1",
      expectedRuntimeRole: "S1",
      statusCategory: "websocket-opened",
      authenticated: true,
      openedExactIssuedUrl: true,
      emptyNegotiatedProtocol: true,
      emptyNegotiatedExtensions: true,
      startMessagesSent: 1,
      exactStartMessage: true,
      binaryFrames: 1,
      textControlFrames: 1,
      outputBytes: m1.byteLength,
      markerMatched: true,
      crossMarkerAbsent: true,
      exitCode: 0,
      protocolValid: true,
      terminal: "closed-after-exit",
    });
    expectSecretFree(result, [s1Url, s1Token, new TextDecoder().decode(m1)]);
  });

  it("uses the stale S1 pair only with the S2 command contract", async () => {
    const { factory, sockets } = scriptedFactory((socket) => socket.emitUnexpectedResponse(401));
    const result = await runSbx055InteractiveAttempt(commandInput({
      purpose: "stale-s1-token-on-s2",
      issuedUrlRole: "S1",
      tokenSourceSession: "S1",
      expectedRuntimeRole: "S2",
      urlCredentialPurpose: "s1-fresh-stale",
      tokenCredentialPurpose: "s1-fresh-stale",
      baseUrl: s2Url,
      markerPath: s2Path,
      expectedMarker: m2,
      crossMarker: m1,
      createWebSocket: factory,
    }));
    expect(sockets[0]!.url).toBe(`${s2Url}?token=${encodeURIComponent(s1Token)}`);
    expect(sockets[0]!.sent).toEqual([]);
    expect(result).toMatchObject({
      purpose: "stale-s1-token-on-s2",
      issuedUrlRole: "S1",
      tokenSourceSession: "S1",
      expectedRuntimeRole: "S2",
      urlCredentialPurpose: "s1-fresh-stale",
      tokenCredentialPurpose: "s1-fresh-stale",
      statusCategory: "auth-rejected",
      handshakeStatusCode: 401,
      opened: false,
      authenticated: false,
      markerMatched: false,
      protocolValid: false,
      terminal: "http-response-before-open",
    });
    expectSecretFree(result, [s1Url, s1Token]);
  });

  it("attributes an accepted stale pair to S1 issuance but only an exact S2 runtime marker", async () => {
    const { factory, sockets } = scriptedFactory((socket) => {
      socket.emit("open");
      socket.emit("message", Buffer.from(m2), true);
      socket.emit("message", '{"type":"exit","code":0,"ignored":"metadata"}', false);
      socket.emit("close", 1000, new Uint8Array());
    });
    const result = await runSbx055InteractiveAttempt(commandInput({
      purpose: "stale-s1-token-on-s2",
      issuedUrlRole: "S1",
      tokenSourceSession: "S1",
      expectedRuntimeRole: "S2",
      urlCredentialPurpose: "s1-fresh-stale",
      tokenCredentialPurpose: "s1-fresh-stale",
      markerPath: s2Path,
      expectedMarker: m2,
      crossMarker: m1,
      createWebSocket: factory,
    }));
    expect(sockets[0]!.sent).toEqual([buildSbx055StartMessage(s2Path)]);
    expect(result).toMatchObject({
      issuedUrlRole: "S1",
      tokenSourceSession: "S1",
      expectedRuntimeRole: "S2",
      markerMatched: true,
      crossMarkerAbsent: true,
      protocolValid: true,
      exitCode: 0,
    });
    expectSecretFree(result, [s1Token, new TextDecoder().decode(m1), new TextDecoder().decode(m2)]);
  });

  it.each([401, 403])("classifies exact HTTP %s as an auth rejection", async (code) => {
    const { factory, sockets } = scriptedFactory((socket) => socket.emitUnexpectedResponse(code));
    const result = await runSbx055InteractiveAttempt({
      purpose: "missing-token-negative",
      issuedUrlRole: "S1",
      tokenSourceSession: "none",
      expectedRuntimeRole: "none",
      urlCredentialPurpose: "s1-owner-control",
      tokenCredentialPurpose: "none",
      baseUrl: s1Url,
      timeoutMs: 50,
      createWebSocket: factory,
    });
    expect(sockets[0]!.url).toBe(s1Url);
    expect(sockets[0]!.handshakeAbortCalls).toBe(1);
    expect(sockets[0]!.responseDestroyCalls).toBe(1);
    expect(result).toMatchObject({
      statusCategory: "auth-rejected",
      unexpectedResponseObserved: true,
      handshakeStatusCode: code,
      opened: false,
      terminal: "http-response-before-open",
    });
    expectSecretFree(result, [s1Url]);
  });

  it.each([302, 429, 500, undefined])(
    "keeps non-auth HTTP status %s distinct and indeterminate",
    async (code) => {
      const { factory } = scriptedFactory((socket) => socket.emitUnexpectedResponse(code));
      const result = await runSbx055InteractiveAttempt({
        purpose: "random-token-negative",
        issuedUrlRole: "S1",
        tokenSourceSession: "random",
        expectedRuntimeRole: "none",
        urlCredentialPurpose: "s1-owner-control",
        tokenCredentialPurpose: "random",
        baseUrl: s1Url,
        token: "random-invalid-token-1234567890",
        timeoutMs: 50,
        createWebSocket: factory,
      });
      expect(result).toMatchObject({
        statusCategory: "other-http-response",
        handshakeStatusCode: code ?? null,
        opened: false,
        protocolValid: false,
      });
    },
  );

  it("keeps transport failure, timeout, and unexpected negative open separate", async () => {
    const input: Sbx055RunAttemptInput = {
      purpose: "missing-token-negative",
      issuedUrlRole: "S1",
      tokenSourceSession: "none",
      expectedRuntimeRole: "none",
      urlCredentialPurpose: "s1-owner-control",
      tokenCredentialPurpose: "none",
      baseUrl: s1Url,
      timeoutMs: 20,
    };
    const transport = scriptedFactory((socket) => socket.emit("error", new Error("raw-secret")));
    const transportResult = await runSbx055InteractiveAttempt({
      ...input,
      createWebSocket: transport.factory,
    });
    expect(transportResult).toMatchObject({
      statusCategory: "transport-error",
      terminal: "transport-error",
      authenticated: false,
    });
    expectSecretFree(transportResult, ["raw-secret", s1Url]);

    const silent = scriptedFactory(() => undefined);
    const timeoutResult = await runSbx055InteractiveAttempt({
      ...input,
      timeoutMs: 1,
      createWebSocket: silent.factory,
    });
    expect(timeoutResult).toMatchObject({ statusCategory: "timeout", terminal: "timeout" });

    const opened = scriptedFactory((socket) => socket.emit("open"));
    const openedResult = await runSbx055InteractiveAttempt({
      ...input,
      createWebSocket: opened.factory,
    });
    expect(openedResult).toMatchObject({
      statusCategory: "websocket-opened",
      terminal: "opened-without-command",
      authenticated: true,
      startMessagesSent: 0,
    });
    expect(opened.sockets[0]!.sent).toEqual([]);
  });

  it("distinguishes exact expected and cross-session markers without retaining either", async () => {
    const { factory } = scriptedFactory((socket) => {
      socket.emit("open");
      socket.emit("message", bytes(m1), true);
      socket.emit("message", '{"type":"exit","code":0}', false);
      socket.emit("close", 1000, new Uint8Array());
    });
    const result = await runSbx055InteractiveAttempt(commandInput({
      purpose: "s2-owner-control",
      issuedUrlRole: "S2",
      tokenSourceSession: "S2",
      expectedRuntimeRole: "S2",
      urlCredentialPurpose: "s2-owner-control",
      tokenCredentialPurpose: "s2-owner-control",
      token: s2Token,
      markerPath: s2Path,
      expectedMarker: m2,
      crossMarker: m1,
      createWebSocket: factory,
    }));
    expect(result).toMatchObject({
      markerMatched: false,
      crossMarkerAbsent: false,
      protocolValid: false,
      binaryFrames: 1,
      textControlFrames: 1,
    });
    expectSecretFree(result, [new TextDecoder().decode(m1), new TextDecoder().decode(m2), s2Token]);
  });

  it("fails closed on every extra or malformed frame", async () => {
    const scripts: Array<(socket: FakeWebSocket) => void> = [
      (socket) => {
        socket.emit("open");
        socket.emit("message", bytes(m1), true);
        socket.emit("message", bytes(m1), true);
      },
      (socket) => {
        socket.emit("open");
        socket.emit("message", bytes(m1), true);
        socket.emit("message", '{"type":"exit","code":0}', false);
        socket.emit("message", '{"type":"exit","code":0}', false);
      },
      (socket) => {
        socket.emit("open");
        socket.emit("message", bytes(m1), true);
        socket.emit("message", "not-json", false);
      },
      (socket) => {
        socket.emit("open");
        socket.emit("message", bytes(m1), true);
        socket.emit("message", '{"type":"exit","code":0}', false);
        socket.emit("message", bytes(m1), true);
      },
    ];
    for (const script of scripts) {
      const { factory } = scriptedFactory(script);
      const result = await runSbx055InteractiveAttempt(commandInput({ createWebSocket: factory }));
      expect(result.statusCategory).toBe("protocol-error");
      expect(result.terminal).toBe("protocol-error");
      expect(result.protocolValid).toBe(false);
      expect(result.requestCount).toBe(1);
      expect(result.retryCount).toBe(0);
    }
  });

  it("treats an impossible HTTP response after open as a protocol error, never a rejection", async () => {
    const { factory } = scriptedFactory((socket) => {
      socket.emit("open");
      socket.emitUnexpectedResponse(401);
    });
    const result = await runSbx055InteractiveAttempt(commandInput({ createWebSocket: factory }));
    expect(result).toMatchObject({
      opened: true,
      statusCategory: "protocol-error",
      unexpectedResponseObserved: false,
      handshakeStatusCode: null,
      terminal: "protocol-error",
      protocolValid: false,
    });
  });

  it("withholds protocol validity for altered negotiation, URL, nonzero exit, or missing close shape", async () => {
    const negotiated = scriptedFactory((socket) => {
      socket.emit("open");
      socket.emit("message", bytes(m1), true);
      socket.emit("message", '{"type":"exit","code":1}', false);
      socket.emit("close", 1000, new Uint8Array());
    }, { protocol: "unexpected", extensions: "permessage-deflate" });
    const result = await runSbx055InteractiveAttempt(commandInput({ createWebSocket: negotiated.factory }));
    expect(result).toMatchObject({
      emptyNegotiatedProtocol: false,
      emptyNegotiatedExtensions: false,
      exitCode: 1,
      protocolValid: false,
    });

    const wrongUrlFactory = ((url: string, _options: Sbx055WebSocketOptions) => {
      expect(url).toContain("?token=");
      const socket = new FakeWebSocket("wss://other.vercel.run/pty/different");
      queueMicrotask(() => {
        socket.emit("open");
        socket.emit("message", bytes(m1), true);
        socket.emit("message", '{"type":"exit","code":0}', false);
        socket.emit("close", 1000, new Uint8Array());
      });
      return socket;
    }) as unknown as Sbx055WebSocketFactory;
    const wrongUrl = await runSbx055InteractiveAttempt(commandInput({ createWebSocket: wrongUrlFactory }));
    expect(wrongUrl).toMatchObject({
      opened: true,
      authenticated: true,
      openedExactIssuedUrl: false,
      protocolValid: false,
    });
  });

  it("rejects binding, marker, token, and timeout drift before opening a socket", async () => {
    const never = (() => { throw new Error("factory must not run"); }) as Sbx055WebSocketFactory;
    await expect(runSbx055InteractiveAttempt(commandInput({ issuedUrlRole: "S2", createWebSocket: never })))
      .rejects.toThrow(/binding/u);
    await expect(runSbx055InteractiveAttempt(commandInput({ tokenSourceSession: "S2", createWebSocket: never })))
      .rejects.toThrow(/binding/u);
    await expect(runSbx055InteractiveAttempt(commandInput({ markerPath: s2Path, createWebSocket: never })))
      .rejects.toThrow(/attempt role/u);
    await expect(runSbx055InteractiveAttempt(commandInput({ crossMarker: m1, createWebSocket: never })))
      .rejects.toThrow(/marker contract/u);
    await expect(runSbx055InteractiveAttempt(commandInput({ token: "short", createWebSocket: never })))
      .rejects.toThrow(/token/u);
    await expect(runSbx055InteractiveAttempt(commandInput({ timeoutMs: 0, createWebSocket: never })))
      .rejects.toThrow(/timeout/u);
  });

  it("is import-safe and performs no socket creation at module load", async () => {
    const moduleUrl = new URL("../pocs/SBX-055/protocol.ts", import.meta.url).href;
    const { stdout, stderr } = await executeFile(process.execPath, [
      "--import",
      "tsx",
      "--eval",
      `await import(${JSON.stringify(moduleUrl)}); process.stdout.write("import-safe\\n")`,
    ], { timeout: 5_000 });
    expect(stdout).toBe("import-safe\n");
    expect(stderr).toBe("");
  });
});
