import { appendFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import type { EvidenceRecord } from "./contracts.js";

export class JsonlEvidenceWriter {
  constructor(private readonly directory: string) {}

  async write(record: EvidenceRecord): Promise<string> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const filename = `${record.startedAt.slice(0, 10)}-${record.testId}.jsonl`;
    const path = join(this.directory, filename);
    await appendFile(path, `${JSON.stringify(record)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    return path;
  }
}
