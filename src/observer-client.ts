import type { ObserverEvent, ObserverReader } from "./contracts.js";

export class HttpObserverClient implements ObserverReader {
  constructor(
    private readonly baseUrl: string,
    private readonly adminKey: string,
  ) {}

  async health(): Promise<void> {
    const response = await fetch(new URL("/healthz", this.baseUrl), {
      signal: AbortSignal.timeout(5_000),
    });
    if (!response.ok) throw new Error(`observer health check returned ${response.status}`);
  }

  async events(runId: string): Promise<ObserverEvent[]> {
    const url = new URL(`/v1/runs/${encodeURIComponent(runId)}/events`, this.baseUrl);
    const response = await fetch(url, {
      headers: { authorization: `Bearer ${this.adminKey}` },
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error(`observer event query returned ${response.status}`);
    const payload = (await response.json()) as { events?: ObserverEvent[] };
    if (!Array.isArray(payload.events)) throw new Error("observer returned an invalid event payload");
    return payload.events;
  }
}
