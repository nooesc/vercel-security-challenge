import { describe, expect, it } from "vitest";
import {
  buildSbx051StartMessage,
  exactSbx051BaseWebSocketUrl,
  exactSbx051StartMessage,
  parseSbx051ExitFrame,
  runSbx051InteractiveAttempt,
  type Sbx051InteractiveAttempt,
  type Sbx051RunAttemptInput,
  type Sbx051WebSocketFactory,
  type Sbx051WebSocketOptions,
} from "../pocs/SBX-051/protocol.js";

const aUrl = "wss://interactive-a.vercel.run/pty/a";
const bUrl = "wss://interactive-b.vercel.run/pty/b";
const aPath = "/tmp/sbx-051/a-123e4567-e89b-42d3-a456-426614174000.marker";
const bPath = "/tmp/sbx-051/b-123e4567-e89b-42d3-a456-426614174001.marker";
const aMarker = new TextEncoder().encode("A".repeat(43));
const bMarker = new TextEncoder().encode("B".repeat(43));
const aToken = "a-token-1234567890/?&=";
const bToken = "b-token-1234567890/?&=";

type FakeEvent = "open" | "error" | "close" | "message" | "unexpected-response";
type FakeListener = (...arguments_: any[]) => void;

class FakeWebSocket {
  binaryType = "";
  readonly sent: string[] = [];
  readonly listeners = new Map<FakeEvent, FakeListener[]>();
  closeCalls = 0;
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

  close(): void {
    this.closeCalls += 1;
  }

  terminate(): void {
    this.terminateCalls += 1;
  }

  emit(type: FakeEvent, ...arguments_: unknown[]): void {
    for (const listener of this.listeners.get(type) ?? []) {
      listener(...arguments_);
    }
  }

  emitUnexpectedResponse(statusCode: number): void {
    this.emit(
      "unexpected-response",
      { abort: () => { this.handshakeAbortCalls += 1; } },
      { statusCode, destroy: () => { this.responseDestroyCalls += 1; } },
    );
  }
}

function scriptedFactory(
  script: (socket: FakeWebSocket) => void,
  options: { protocol?: string; extensions?: string } = {},
): {
  factory: Sbx051WebSocketFactory;
  sockets: FakeWebSocket[];
  websocketOptions: Sbx051WebSocketOptions[];
} {
  const sockets: FakeWebSocket[] = [];
  const websocketOptions: Sbx051WebSocketOptions[] = [];
  const factory = ((url: string, wsOptions: Sbx051WebSocketOptions) => {
    const socket = new FakeWebSocket(url, options.protocol, options.extensions);
    sockets.push(socket);
    websocketOptions.push(wsOptions);
    queueMicrotask(() => script(socket));
    return socket;
  }) as unknown as Sbx051WebSocketFactory;
  return { factory, sockets, websocketOptions };
}

function commandInput(overrides: Partial<Sbx051RunAttemptInput> = {}): Sbx051RunAttemptInput {
  return {
    purpose: "a-owner-control",
    urlRole: "A",
    tokenSource: "A",
    urlCredentialPurpose: "a-owner-control",
    tokenCredentialPurpose: "a-owner-control",
    baseUrl: aUrl,
    token: aToken,
    markerPath: aPath,
    expectedMarker: aMarker,
    unexpectedMarker: bMarker,
    timeoutMs: 50,
    ...overrides,
  };
}

function bytes(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer;
}

function expectNoTransientMaterial(
  attempt: Sbx051InteractiveAttempt,
  forbidden: readonly string[],
): void {
  expect(attempt).toMatchObject({
    rawOutputRetained: false,
    rawMarkerRetained: false,
    rawTokenRetained: false,
    rawTokenDigestRetained: false,
    queryBearingUrlRetained: false,
    requestCount: 1,
    retryCount: 0,
  });
  const serialized = JSON.stringify(attempt);
  for (const value of forbidden) {
    if (value.length > 0) expect(serialized).not.toContain(value);
  }
  expect(serialized).not.toMatch(/[?&]token=|wss:\/\//iu);
}

describe("SBX-051 exact interactive wire primitives", () => {
  it("accepts only canonical query-free Vercel WSS base URLs", () => {
    expect(exactSbx051BaseWebSocketUrl(aUrl)).toBe(true);
    for (const raw of [
      "ws://interactive-a.vercel.run/pty/a",
      "https://interactive-a.vercel.run/pty/a",
      "wss://interactive-a.vercel.run:443/pty/a",
      "wss://user@interactive-a.vercel.run/pty/a",
      "wss://interactive-a.vercel.run/pty/a?token=x",
      "wss://interactive-a.vercel.run/pty/a#fragment",
      "wss://interactive-a.vercel.run./pty/a",
      "wss://INTERACTIVE-A.vercel.run/pty/a",
      "wss://interactive-a.example.test/pty/a",
      "wss://127.0.0.1/pty/a",
      "wss://interactive-a.vercel.run/pty/%2fescape",
      "wss://interactive-a.vercel.run/pty/../other",
    ]) {
      expect(exactSbx051BaseWebSocketUrl(raw), raw).toBe(false);
    }
  });

  it("builds exactly one fixed /bin/cat start frame and rejects altered frames", () => {
    const raw = buildSbx051StartMessage(aPath);
    expect(JSON.parse(raw)).toEqual({
      type: "start",
      command: "/bin/cat",
      args: [aPath],
      env: [],
      cwd: "/",
      cols: 80,
      rows: 24,
    });
    expect(exactSbx051StartMessage(raw, aPath)).toBe(true);
    expect(exactSbx051StartMessage(raw, bPath)).toBe(false);
    expect(exactSbx051StartMessage(JSON.stringify({ ...JSON.parse(raw), shell: true }), aPath))
      .toBe(false);
    expect(exactSbx051StartMessage(JSON.stringify({ ...JSON.parse(raw), command: "sh" }), aPath))
      .toBe(false);
    expect(() => buildSbx051StartMessage("/tmp/sbx-051/../secret")).toThrow();
  });

  it("parses the CLI-compatible bounded exit control shape and ignores server metadata", () => {
    expect(parseSbx051ExitFrame('{"type":"exit","code":0}')).toBe(0);
    expect(parseSbx051ExitFrame('{"type":"exit","code":255}')).toBe(255);
    expect(parseSbx051ExitFrame(
      '{"type":"exit","code":0,"signal":null,"durationMs":17}',
    )).toBe(0);
    for (const raw of [
      '{"type":"exit","code":-1}',
      '{"type":"exit","code":256}',
      '{"type":"exit"}',
      '{"type":"stdout","code":0}',
      '{"type":"exit","code":"0"}',
      '{"type":"exit","code":null}',
      "not-json",
    ]) {
      expect(parseSbx051ExitFrame(raw), raw).toBeUndefined();
    }
  });
});

describe("SBX-051 fake-WebSocket attempt protocol", () => {
  it("sends one exact command, matches only the expected marker, and retains no capability", async () => {
    const { factory, sockets, websocketOptions } = scriptedFactory((socket) => {
      socket.emit("open");
      socket.emit("message", bytes(aMarker), true);
      socket.emit("message", '{"type":"exit","code":0}', false);
      socket.emit("close", 1000, new Uint8Array());
    });
    const result = await runSbx051InteractiveAttempt(commandInput({ createWebSocket: factory }));

    expect(sockets).toHaveLength(1);
    expect(sockets[0]!.url).toBe(`${aUrl}?token=a-token-1234567890%2F%3F%26%3D`);
    expect(sockets[0]!.binaryType).toBe("nodebuffer");
    expect(websocketOptions).toEqual([{
      followRedirects: false,
      handshakeTimeout: 50,
      maxPayload: 4_096,
      perMessageDeflate: false,
      rejectUnauthorized: true,
    }]);
    expect(sockets[0]!.sent).toEqual([buildSbx051StartMessage(aPath)]);
    expect(result).toMatchObject({
      terminal: "closed-after-exit",
      opened: true,
      openedExactIssuedUrl: true,
      emptyNegotiatedProtocol: true,
      emptyNegotiatedExtensions: true,
      startMessageExpected: true,
      startMessagesSent: 1,
      exactStartMessage: true,
      binaryFrames: 1,
      textControlFrames: 1,
      outputBytes: 43,
      exactExpectedMarker: true,
      exactUnexpectedMarker: false,
      exitCode: 0,
    });
    expectNoTransientMaterial(result, [aToken, new TextDecoder().decode(aMarker), aUrl]);
  });

  it("accepts a zero exit with ignored server metadata without retaining the control frame", async () => {
    const exitFrame = '{"type":"exit","code":0,"signal":null,"durationMs":17}';
    const { factory } = scriptedFactory((socket) => {
      socket.emit("open");
      socket.emit("message", bytes(aMarker), true);
      socket.emit("message", exitFrame, false);
      socket.emit("close", 1000, new Uint8Array());
    });
    const result = await runSbx051InteractiveAttempt(commandInput({ createWebSocket: factory }));

    expect(result).toMatchObject({
      terminal: "closed-after-exit",
      binaryFrames: 1,
      textControlFrames: 1,
      exactExpectedMarker: true,
      exactUnexpectedMarker: false,
      exitCode: 0,
    });
    expect(JSON.stringify(result)).not.toContain(exitFrame);
  });

  it("records a nonzero CLI-compatible exit without making it a zero exit", async () => {
    const { factory } = scriptedFactory((socket) => {
      socket.emit("open");
      socket.emit("message", bytes(aMarker), true);
      socket.emit("message", '{"type":"exit","code":1,"signal":null}', false);
      socket.emit("close", 1000, new Uint8Array());
    });
    const result = await runSbx051InteractiveAttempt(commandInput({ createWebSocket: factory }));

    expect(result).toMatchObject({
      terminal: "closed-after-exit",
      exactExpectedMarker: true,
      exitCode: 1,
    });
  });

  it.each([
    {
      purpose: "missing-token-negative" as const,
      tokenSource: "none" as const,
      token: undefined,
      expectedUrl: bUrl,
    },
    {
      purpose: "random-token-negative" as const,
      tokenSource: "random" as const,
      token: "random-invalid-1234567890",
      expectedUrl: `${bUrl}?token=random-invalid-1234567890`,
    },
  ])("records $purpose only for an exact 401/403 pre-open HTTP response", async (entry) => {
    const { factory, sockets } = scriptedFactory((socket) => socket.emitUnexpectedResponse(403));
    const result = await runSbx051InteractiveAttempt({
      purpose: entry.purpose,
      urlRole: "B",
      tokenSource: entry.tokenSource,
      urlCredentialPurpose: "b-owner-control",
      tokenCredentialPurpose: entry.purpose === "missing-token-negative" ? "none" : "random",
      baseUrl: bUrl,
      ...(entry.token === undefined ? {} : { token: entry.token }),
      timeoutMs: 50,
      createWebSocket: factory,
    });

    expect(sockets[0]!.url).toBe(entry.expectedUrl);
    expect(sockets[0]!.sent).toEqual([]);
    expect(result).toMatchObject({
      terminal: "http-response-before-open",
      webSocketClient: "ws@8.21.0",
      unexpectedResponseObserved: true,
      handshakeStatusCode: 403,
      handshakeResponseBodyRetained: false,
      handshakeResponseHeadersRetained: false,
      opened: false,
      startMessageExpected: false,
      startMessagesSent: 0,
      exactExpectedMarker: false,
      exactUnexpectedMarker: false,
      outputBytes: 0,
      exitCode: null,
    });
    expect(sockets[0]!.handshakeAbortCalls).toBe(1);
    expect(sockets[0]!.responseDestroyCalls).toBe(1);
    expectNoTransientMaterial(result, [entry.token ?? "", bUrl]);
  });

  it.each([302, 503])("sanitizes HTTP %s without treating it as an auth rejection", async (status) => {
    const { factory } = scriptedFactory((socket) => socket.emitUnexpectedResponse(status));
    const result = await runSbx051InteractiveAttempt({
      purpose: "random-token-negative",
      urlRole: "B",
      tokenSource: "random",
      urlCredentialPurpose: "b-owner-control",
      tokenCredentialPurpose: "random",
      baseUrl: bUrl,
      token: "random-invalid-1234567890",
      timeoutMs: 50,
      createWebSocket: factory,
    });
    expect(result).toMatchObject({
      terminal: "http-response-before-open",
      unexpectedResponseObserved: true,
      handshakeStatusCode: status,
      opened: false,
    });
  });

  it.each(["dns failure", "tls failure", "closed before open"])(
    "keeps a sanitized %s indeterminate",
    async (failure) => {
      const { factory } = scriptedFactory((socket) => {
        if (failure === "closed before open") {
          socket.emit("close", 1006, new Uint8Array());
        } else {
          socket.emit("error", new Error(`secret ${failure}`));
        }
      });
      const result = await runSbx051InteractiveAttempt({
        purpose: "missing-token-negative",
        urlRole: "B",
        tokenSource: "none",
        urlCredentialPurpose: "b-owner-control",
        tokenCredentialPurpose: "none",
        baseUrl: bUrl,
        timeoutMs: 50,
        createWebSocket: factory,
      });
      expect(result).toMatchObject({
        terminal: "transport-error",
        unexpectedResponseObserved: false,
        handshakeStatusCode: null,
        opened: false,
      });
      expectNoTransientMaterial(result, [failure, bUrl]);
    },
  );

  it("constructs the token query byte-for-byte like the installed CLI", async () => {
    const punctuationToken = "punctuation-token-123!~*'()";
    const { factory, sockets } = scriptedFactory((socket) => socket.emit("error", new Error("stop")));
    await runSbx051InteractiveAttempt(commandInput({
      token: punctuationToken,
      createWebSocket: factory,
    }));
    expect(sockets[0]!.url).toBe(`${aUrl}?token=${encodeURIComponent(punctuationToken)}`);
    expect(sockets[0]!.url).toContain("!~*'()");
  });

  it("closes immediately without sending when a negative unexpectedly opens", async () => {
    const { factory, sockets } = scriptedFactory((socket) => socket.emit("open"));
    const result = await runSbx051InteractiveAttempt({
      purpose: "missing-token-negative",
      urlRole: "B",
      tokenSource: "none",
      urlCredentialPurpose: "b-owner-control",
      tokenCredentialPurpose: "none",
      baseUrl: bUrl,
      timeoutMs: 50,
      createWebSocket: factory,
    });
    expect(result.terminal).toBe("opened-without-command");
    expect(result.opened).toBe(true);
    expect(result.startMessagesSent).toBe(0);
    expect(sockets[0]!.sent).toEqual([]);
    expect(sockets[0]!.terminateCalls).toBe(1);
  });

  it("fails closed if the negotiated protocol, extension, or issued URL changes", async () => {
    const { factory } = scriptedFactory((socket) => {
      socket.emit("open");
      socket.emit("message", bytes(aMarker), true);
      socket.emit("message", '{"type":"exit","code":0}', false);
      socket.emit("close", 1000, new Uint8Array());
    }, { protocol: "unexpected", extensions: "permessage-deflate" });
    const result = await runSbx051InteractiveAttempt(commandInput({ createWebSocket: factory }));
    expect(result).toMatchObject({
      emptyNegotiatedProtocol: false,
      emptyNegotiatedExtensions: false,
      exactExpectedMarker: true,
    });
  });

  it("requires a distinct bounded unexpected marker for every command attempt", async () => {
    await expect(runSbx051InteractiveAttempt(commandInput({
      unexpectedMarker: undefined as never,
      createWebSocket: (() => {
        throw new Error("factory must not run");
      }) as Sbx051WebSocketFactory,
    }))).rejects.toThrow(/marker contract/u);
    await expect(runSbx051InteractiveAttempt(commandInput({
      unexpectedMarker: aMarker,
      createWebSocket: (() => {
        throw new Error("factory must not run");
      }) as Sbx051WebSocketFactory,
    }))).rejects.toThrow(/marker contract/u);
  });

  it("detects the swapped marker without retaining its bytes", async () => {
    const { factory } = scriptedFactory((socket) => {
      socket.emit("open");
      socket.emit("message", bytes(bMarker), true);
      socket.emit("message", '{"type":"exit","code":0}', false);
      socket.emit("close", 1000, new Uint8Array());
    });
    const result = await runSbx051InteractiveAttempt(commandInput({ createWebSocket: factory }));
    expect(result).toMatchObject({
      exactExpectedMarker: false,
      exactUnexpectedMarker: true,
      outputBytes: 43,
    });
    expectNoTransientMaterial(result, [new TextDecoder().decode(bMarker)]);
  });

  it("binds the one cross attempt to B's URL/path and a transient A-issued token", async () => {
    const { factory, sockets } = scriptedFactory((socket) => {
      socket.emit("open");
      socket.emit("message", bytes(bMarker), true);
      socket.emit("message", '{"type":"exit","code":0}', false);
      socket.emit("close", 1000, new Uint8Array());
    });
    const result = await runSbx051InteractiveAttempt(commandInput({
      purpose: "a-token-b-attack",
      urlRole: "B",
      tokenSource: "A",
      urlCredentialPurpose: "b-attack-target",
      tokenCredentialPurpose: "a-attack",
      baseUrl: bUrl,
      markerPath: bPath,
      expectedMarker: bMarker,
      unexpectedMarker: aMarker,
      createWebSocket: factory,
    }));
    expect(sockets).toHaveLength(1);
    expect(sockets[0]!.url).toBe(`${bUrl}?token=a-token-1234567890%2F%3F%26%3D`);
    expect(sockets[0]!.sent).toEqual([buildSbx051StartMessage(bPath)]);
    expect(result).toMatchObject({
      purpose: "a-token-b-attack",
      urlRole: "B",
      tokenSource: "A",
      urlCredentialPurpose: "b-attack-target",
      tokenCredentialPurpose: "a-attack",
      requestCount: 1,
      retryCount: 0,
      exactExpectedMarker: true,
      exactUnexpectedMarker: false,
      exitCode: 0,
    });
    expectNoTransientMaterial(result, [aToken, new TextDecoder().decode(bMarker), bUrl]);
  });

  it("records but does not bless a socket that reports a different URL", async () => {
    const sockets: FakeWebSocket[] = [];
    const factory = ((url: string, _options: Sbx051WebSocketOptions) => {
      expect(url).toContain("?token=");
      const socket = new FakeWebSocket("wss://different.vercel.run/pty/not-issued");
      sockets.push(socket);
      queueMicrotask(() => {
        socket.emit("open");
        socket.emit("message", bytes(aMarker), true);
        socket.emit("message", '{"type":"exit","code":0}', false);
        socket.emit("close", 1000, new Uint8Array());
      });
      return socket;
    }) as unknown as Sbx051WebSocketFactory;
    const result = await runSbx051InteractiveAttempt(commandInput({ createWebSocket: factory }));
    expect(sockets).toHaveLength(1);
    expect(result.openedExactIssuedUrl).toBe(false);
    expectNoTransientMaterial(result, [sockets[0]!.url, aUrl, aToken]);
  });

  it("fails closed on extra output after exit or on a second exit frame", async () => {
    for (const second of [bytes(aMarker), '{"type":"exit","code":0}']) {
      const { factory } = scriptedFactory((socket) => {
        socket.emit("open");
        socket.emit("message", bytes(aMarker), true);
        socket.emit("message", '{"type":"exit","code":0}', false);
        socket.emit("message", second, second instanceof ArrayBuffer);
      });
      const result = await runSbx051InteractiveAttempt(commandInput({ createWebSocket: factory }));
      expect(result.terminal).toBe("protocol-error");
      expect(result.requestCount).toBe(1);
      expect(result.retryCount).toBe(0);
    }
  });

  it("rejects an oversized text control frame before parsing it", async () => {
    const oversizedExit = `${" ".repeat(4_096)}{"type":"exit","code":0}`;
    const { factory } = scriptedFactory((socket) => {
      socket.emit("open");
      socket.emit("message", bytes(aMarker), true);
      socket.emit("message", oversizedExit, false);
      socket.emit("close", 1000, new Uint8Array());
    });
    const result = await runSbx051InteractiveAttempt(commandInput({ createWebSocket: factory }));
    expect(result.terminal).toBe("protocol-error");
    expect(result.exitCode).toBeNull();
  });

  it("does not allocate or account beyond the bounded output cap", async () => {
    const oversized = new Uint8Array(64 * 1_024).fill(65);
    const { factory } = scriptedFactory((socket) => {
      socket.emit("open");
      socket.emit("message", oversized.buffer, true);
    });
    const result = await runSbx051InteractiveAttempt(commandInput({ createWebSocket: factory }));
    expect(result.terminal).toBe("protocol-error");
    expect(result.outputBytes).toBeLessThanOrEqual(4_096);
    expect(result.exactExpectedMarker).toBe(false);
    expect(result.exactUnexpectedMarker).toBe(false);
  });

  it("stops after the seventeenth binary frame and never retries", async () => {
    const { factory } = scriptedFactory((socket) => {
      socket.emit("open");
      for (let index = 0; index < 17; index += 1) {
        socket.emit("message", bytes(new Uint8Array([65])), true);
      }
    });
    const result = await runSbx051InteractiveAttempt(commandInput({ createWebSocket: factory }));
    expect(result.terminal).toBe("protocol-error");
    expect(result.binaryFrames).toBeGreaterThan(16);
    expect(result.requestCount).toBe(1);
    expect(result.retryCount).toBe(0);
  });

  it("times out a silent socket and sanitizes synchronous transport failures", async () => {
    const silent = scriptedFactory(() => undefined);
    const timedOut = await runSbx051InteractiveAttempt(commandInput({
      timeoutMs: 1,
      createWebSocket: silent.factory,
    }));
    expect(timedOut.terminal).toBe("timeout");
    silent.sockets[0]!.emit("open");
    expect(silent.sockets[0]!.sent).toEqual([]);

    const transportSecret = "should-never-be-retained-transport-secret";
    const failed = await runSbx051InteractiveAttempt(commandInput({
      createWebSocket: (() => {
        throw new Error(transportSecret);
      }) as Sbx051WebSocketFactory,
    }));
    expect(failed.terminal).toBe("transport-error");
    expectNoTransientMaterial(failed, [transportSecret, aToken, aUrl]);
  });

  it("rejects role/token/purpose mismatches before constructing a socket", async () => {
    const never = (() => {
      throw new Error("factory must not run");
    }) as Sbx051WebSocketFactory;
    await expect(runSbx051InteractiveAttempt(commandInput({ urlRole: "B", createWebSocket: never })))
      .rejects.toThrow(/binding/u);
    await expect(runSbx051InteractiveAttempt(commandInput({ tokenSource: "B", createWebSocket: never })))
      .rejects.toThrow(/binding/u);
    await expect(runSbx051InteractiveAttempt(commandInput({
      urlCredentialPurpose: "b-attack-target",
      createWebSocket: never,
    }))).rejects.toThrow(/binding/u);
    await expect(runSbx051InteractiveAttempt(commandInput({ token: "short", createWebSocket: never })))
      .rejects.toThrow(/token/u);
  });
});
