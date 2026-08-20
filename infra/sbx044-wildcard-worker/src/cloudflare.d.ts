declare module "cloudflare:workers" {
  export class DurableObject<Env = unknown> {
    protected readonly ctx: DurableObjectState;
    protected readonly env: Env;
    constructor(ctx: DurableObjectState, env: Env);
  }
}

interface DurableObjectSqlCursor<Row> {
  toArray(): Row[];
}

interface DurableObjectSqlStorage {
  exec<Row = Record<string, unknown>>(query: string, ...bindings: unknown[]): DurableObjectSqlCursor<Row>;
}

interface DurableObjectStorage {
  readonly sql: DurableObjectSqlStorage;
  get<T = unknown>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
  delete(keys: string[]): Promise<number>;
}

interface DurableObjectState {
  readonly storage: DurableObjectStorage;
}

interface DurableObjectNamespace<Stub> {
  getByName(name: string): Stub;
}
