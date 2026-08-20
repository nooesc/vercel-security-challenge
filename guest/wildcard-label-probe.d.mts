export function validateConfiguration(value: unknown): { url: URL; hosts: string[] };
export function requestOnce(configuration: unknown): Promise<unknown>;
