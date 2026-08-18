import { Sandbox } from "@vercel/sandbox";
import type {
  SandboxCommand,
  SandboxCommandOutput,
  SandboxFactory,
  SandboxHandle,
} from "./contracts.js";

class VercelSandboxHandle implements SandboxHandle {
  constructor(private readonly sandbox: Sandbox) {}

  get name(): string {
    return this.sandbox.name;
  }

  get sessionId(): string | undefined {
    try {
      return this.sandbox.currentSession().sessionId;
    } catch {
      return undefined;
    }
  }

  async writeFiles(files: Array<{ path: string; content: string; mode?: number }>): Promise<void> {
    await this.sandbox.writeFiles(files);
  }

  async runCommand(command: SandboxCommand): Promise<SandboxCommandOutput> {
    const result = await this.sandbox.runCommand({
      cmd: command.cmd,
      ...(command.args ? { args: command.args } : {}),
      ...(command.env ? { env: command.env } : {}),
      ...(command.sudo !== undefined ? { sudo: command.sudo } : {}),
      ...(command.timeoutMs !== undefined ? { timeoutMs: command.timeoutMs } : {}),
    });
    const [stdout, stderr] = await Promise.all([result.stdout(), result.stderr()]);
    return {
      exitCode: result.exitCode,
      stdout,
      stderr,
      ...(result.durationMs !== undefined ? { durationMs: result.durationMs } : {}),
    };
  }

  async stop(): Promise<void> {
    await this.sandbox.stop();
  }

  async delete(): Promise<void> {
    await this.sandbox.delete();
  }
}

export class VercelSandboxFactory implements SandboxFactory {
  async create(input: Parameters<SandboxFactory["create"]>[0]): Promise<SandboxHandle> {
    const credentialValues = [
      process.env.VERCEL_TOKEN,
      process.env.VERCEL_TEAM_ID,
      process.env.VERCEL_PROJECT_ID,
    ];
    const suppliedCredentialCount = credentialValues.filter(Boolean).length;
    if (suppliedCredentialCount !== 0 && suppliedCredentialCount !== credentialValues.length) {
      throw new Error(
        "VERCEL_TOKEN, VERCEL_TEAM_ID, and VERCEL_PROJECT_ID must be supplied together",
      );
    }
    const explicitCredentials = suppliedCredentialCount === credentialValues.length
      ? {
          token: process.env.VERCEL_TOKEN!,
          teamId: process.env.VERCEL_TEAM_ID!,
          projectId: process.env.VERCEL_PROJECT_ID!,
        }
      : {};

    const sandbox = await Sandbox.create({
      name: input.name,
      timeout: input.timeoutMs,
      persistent: false,
      resources: { vcpus: 2 },
      networkPolicy: input.policy,
      tags: input.tags,
      ...explicitCredentials,
    });
    return new VercelSandboxHandle(sandbox);
  }
}
