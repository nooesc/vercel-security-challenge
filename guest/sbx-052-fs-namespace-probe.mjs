import { access, lstat, mkdir, readFile, readlink, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const TEST_ID = "SBX-052";
const BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id";
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const BOOT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\n$/u;
const CANARY = /^can52_[A-Za-z0-9_-]{32}$/u;

function exactArguments(expectedLength) {
  if (process.argv.length !== expectedLength) throw new Error("invalid_arguments");
}

function pathsFor(runId) {
  if (!UUID_V4.test(runId)) throw new Error("invalid_run_id");
  const directory = `/tmp/sbx-052-${runId}`;
  return {
    directory,
    owned: `${directory}/owned.txt`,
    ownedLink: `${directory}/owned-link`,
    procLink: `${directory}/proc-link`,
  };
}

async function setup(runId, canary) {
  exactArguments(5);
  if (!CANARY.test(canary)) throw new Error("invalid_canary");
  const paths = pathsFor(runId);
  await rm(paths.directory, { recursive: true, force: true });
  await mkdir(paths.directory, { mode: 0o700 });
  await writeFile(paths.owned, `${canary}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
  await symlink("owned.txt", paths.ownedLink);
  await symlink(BOOT_ID_PATH, paths.procLink);
  const [directoryStat, ownedStat, ownedLinkStat, procLinkStat, ownedTarget, procTarget] = await Promise.all([
    lstat(paths.directory),
    lstat(paths.owned),
    lstat(paths.ownedLink),
    lstat(paths.procLink),
    readlink(paths.ownedLink),
    readlink(paths.procLink),
  ]);
  const directoryMode = directoryStat.mode & 0o777;
  const ownedMode = ownedStat.mode & 0o777;
  if (!directoryStat.isDirectory() || !ownedStat.isFile() || directoryMode !== 0o700 ||
      ownedMode !== 0o600 || !ownedLinkStat.isSymbolicLink() || !procLinkStat.isSymbolicLink() ||
      ownedTarget !== "owned.txt" || procTarget !== BOOT_ID_PATH) {
    throw new Error("link_setup_failed");
  }
  process.stdout.write(`${JSON.stringify({
    schemaVersion: 1,
    testId: TEST_ID,
    operation: "setup",
    runId,
    ready: true,
    directoryMode,
    ownedMode,
    ownedRelativeLink: true,
    procAbsoluteLink: true,
  })}\n`);
}

async function observe(runId) {
  exactArguments(4);
  const paths = pathsFor(runId);
  const [direct, linked, ownedTarget, procTarget] = await Promise.all([
    readFile(BOOT_ID_PATH, "utf8"),
    readFile(paths.procLink, "utf8"),
    readlink(paths.ownedLink),
    readlink(paths.procLink),
  ]);
  if (!BOOT_ID.test(direct) || !BOOT_ID.test(linked) ||
      ownedTarget !== "owned.txt" || procTarget !== BOOT_ID_PATH) {
    throw new Error("observation_failed");
  }
  process.stdout.write(`${JSON.stringify({
    schemaVersion: 1,
    testId: TEST_ID,
    operation: "observe",
    runId,
    directBootId: direct.slice(0, -1),
    linkedBootId: linked.slice(0, -1),
    directBytes: Buffer.byteLength(direct),
    linkedBytes: Buffer.byteLength(linked),
    ownedLinkTarget: ownedTarget,
    procLinkTarget: procTarget,
  })}\n`);
}

async function cleanup(runId) {
  exactArguments(4);
  const paths = pathsFor(runId);
  await rm(paths.directory, { recursive: true, force: true });
  let directoryAbsent = false;
  try {
    await access(paths.directory);
  } catch {
    directoryAbsent = true;
  }
  if (!directoryAbsent) throw new Error("cleanup_failed");
  await unlink(fileURLToPath(import.meta.url));
  process.stdout.write(`${JSON.stringify({
    schemaVersion: 1,
    testId: TEST_ID,
    operation: "cleanup",
    runId,
    directoryRemoved: true,
    probeRemoved: true,
  })}\n`);
}

async function main() {
  const operation = process.argv[2];
  const runId = process.argv[3] ?? "";
  if (operation === "setup") return setup(runId, process.argv[4] ?? "");
  if (operation === "observe") return observe(runId);
  if (operation === "cleanup") return cleanup(runId);
  throw new Error("invalid_operation");
}

main().catch(() => {
  process.stderr.write("SBX-052 guest probe failed\n");
  process.exitCode = 1;
});
