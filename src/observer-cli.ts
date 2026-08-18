import "dotenv/config";
import { resolve } from "node:path";
import { startObserverServer } from "./observer-server.js";

function portFromEnvironment(): number {
  const raw = process.env.OBSERVER_PORT ?? "8787";
  const port = Number(raw);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error("OBSERVER_PORT must be an integer from 1 through 65535");
  }
  return port;
}

async function main(): Promise<void> {
  const adminKey = process.env.OBSERVER_ADMIN_KEY;
  if (!adminKey || adminKey.length < 24) {
    throw new Error("OBSERVER_ADMIN_KEY must contain at least 24 characters");
  }
  const host = process.env.OBSERVER_HOST ?? "127.0.0.1";
  if (host.trim().length === 0) throw new Error("OBSERVER_HOST cannot be empty");
  const dataPath = resolve(process.env.OBSERVER_DATA_FILE ?? "./observer-data/events.jsonl");

  const observer = await startObserverServer({
    adminKey,
    host,
    port: portFromEnvironment(),
    dataPath,
  });
  process.stdout.write(`observer listening at ${observer.baseUrl}\n`);
  process.stdout.write(`observer evidence path: ${dataPath}\n`);

  let stopping = false;
  const stop = (signal: NodeJS.Signals): void => {
    if (stopping) return;
    stopping = true;
    process.stdout.write(`received ${signal}; closing observer\n`);
    void observer.close().then(
      () => process.exit(0),
      (error: unknown) => {
        process.stderr.write(`failed to close observer: ${error instanceof Error ? error.message : String(error)}\n`);
        process.exit(1);
      },
    );
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
