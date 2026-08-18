import { describe, expect, it } from "vitest";
import { waitUntil } from "../src/timing.js";

describe("waitUntil", () => {
  it("rechecks the clock when a timer fires early", async () => {
    let nowMs = 1_000;
    const sleeps: number[] = [];

    await waitUntil(1_500, () => nowMs, async (milliseconds) => {
      sleeps.push(milliseconds);
      nowMs += sleeps.length === 1 ? milliseconds - 1 : milliseconds;
    });

    expect(sleeps).toEqual([500, 1]);
    expect(nowMs).toBe(1_500);
  });

  it("returns immediately when the target has already passed", async () => {
    let slept = false;
    await waitUntil(999, () => 1_000, async () => {
      slept = true;
    });
    expect(slept).toBe(false);
  });
});
