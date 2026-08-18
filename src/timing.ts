export type Sleep = (milliseconds: number) => Promise<void>;

const defaultSleep: Sleep = async (milliseconds) => {
  await new Promise((resolve) => setTimeout(resolve, milliseconds));
};

/** Wait until the wall clock reaches the requested epoch, tolerating early timers. */
export async function waitUntil(
  epochMs: number,
  now: () => number = Date.now,
  sleep: Sleep = defaultSleep,
): Promise<void> {
  while (now() < epochMs) {
    await sleep(Math.max(1, epochMs - now()));
  }
}
