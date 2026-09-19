export interface User {
  id: number | string;
  email: string;
  first_name?: string | null;
  last_name?: string | null;
  role: string;
  verified: number;
  [field: string]: unknown;
}

export interface ListOpts {
  limit?: number;
  offset?: number;
  cursor?: string;
  q?: string;
  where?: Record<string, string | number | boolean>;
}

export interface ApiResult<T = unknown> {
  ok: boolean;
  status: number;
  data: T | null;
}

export type ChangeEvent =
  | { action: "insert" | "update" | "delete"; table: string }
  | { action: "refresh"; table: "" };

export interface ApiCalls {
  raw: {
    get<T = unknown>(path: string): Promise<ApiResult<T>>;
    post<T = unknown>(path: string, body?: unknown): Promise<ApiResult<T>>;
    patch<T = unknown>(path: string, body?: unknown): Promise<ApiResult<T>>;
    delete<T = unknown>(path: string): Promise<ApiResult<T>>;
  };
  get<T = unknown>(path: string): Promise<T>;
  post<T = unknown>(path: string, body?: unknown): Promise<T>;
  patch<T = unknown>(path: string, body?: unknown): Promise<T>;
  delete(path: string): Promise<void>;
  optimistic<T = unknown, Snapshot = unknown>(opts: {
    apply: () => void;
    request: () => Promise<T> | T;
    snapshot?: () => Snapshot;
    revert?: (snapshot: Snapshot) => void;
  }): Promise<T>;
}

export interface AuthCalls {
  me(): Promise<User | null>;
  signOut(): Promise<void>;
  refreshMe(): Promise<User | null>;
  signIn(identifier: string, password: string): Promise<User | null>;
  signUp(fields: { email: string; password: string; [extraField: string]: unknown }): Promise<User | null>;
}

export interface UsersCalls {
  list(opts?: { limit?: number; offset?: number }): Promise<User[]>;
  get(id: number | string): Promise<User>;
}

export interface CountOpts {
  where?: Record<string, string | number | boolean>;
  q?: string;
}

export interface TableClient<Row = Record<string, unknown>> {
  readonly name: string;
  list(opts?: ListOpts): Promise<Row[]>;
  get(id: number | string): Promise<Row>;
  create(body: Partial<Row>): Promise<Row>;
  update(id: number | string, body: Partial<Row>): Promise<Row>;
  delete(id: number | string): Promise<void>;
  count(opts?: CountOpts): Promise<number>;
  restore(id: number | string): Promise<Row>;
  versions(id: number | string): Promise<Array<{ version: number; data: Row; created_at: string }>>;
  revertTo(id: number | string, version: number): Promise<Row>;
}

export interface RoomClient {
  readonly name: string;
  on(kind: string, fn: (payload: unknown, from: number | string) => void): this;
  onAny(fn: (payload: unknown, from: number | string, kind: string) => void): this;
  off(kind: string, fn: Function): this;
  send(payload: unknown): void;
  leave(): void;
  readonly raw: WebSocket;
}

export interface WorkflowClient {
  readonly table: string;
  readonly id: number | string;
  transitionTo(state: string): Promise<{ state: string }>;
  available(): Promise<string[]>;
  current(): Promise<string>;
}

export interface Job<Result = unknown> {
  job_id: string;
  status_url?: string;
  status(): Promise<JobStatus<Result>>;
  wait(opts?: JobWaitOpts): Promise<Result>;
}

export interface JobStatus<Result = unknown> {
  status: "pending" | "running" | "completed" | "failed" | string;
  result?: Result;
  error?: string;
  [field: string]: unknown;
}

export interface JobWaitOpts {
  intervalMs?: number;
  timeoutMs?: number;
  statusUrl?: string;
}

export interface Notification {
  id: number | string;
  [field: string]: unknown;
}

export interface UploadResult {
  path: string;
  url?: string;
  read_url?: string;
  size?: number;
  mime?: string;
  [field: string]: unknown;
}

export interface SafeHtml {
  readonly value: string;
  toString(): string;
}

export interface PresenceMember {
  user_id: number | string;
  joined_at: string;
  last_seen_at: string;
  [field: string]: unknown;
}

export interface PresenceHandle {
  readonly slug: string;
  members(): Promise<PresenceMember[]>;
  count(): Promise<number>;
  onChange(fn: () => void): () => void;
  leave(): void;
}

export interface CacheClient {
  readonly name: string;
  readonly version: string;
  get(): string | undefined;
  set(value: string): void;
  clear(): void;
  purgeOld(): void;
}

export interface StorePersistOpts {
  name: string;
  version?: string | number;
  storage?: "session" | "persistent";
}

export interface Store<State extends Record<string, unknown>> {
  get(): State;
  set(patch: Partial<State> | State | ((state: State) => Partial<State> | State | void | null)): State;
  subscribe(listener: (state: State, previous: State) => void): () => void;
  subscribe<Slice>(selector: (state: State) => Slice, listener: (slice: Slice, previous: Slice) => void, equal?: (a: Slice, b: Slice) => boolean): () => void;
  reset(nextState?: State): State;
}

export interface QuerySnapshot<T = unknown> {
  data: T | undefined;
  error: unknown;
  updatedAt: number;
  pending: boolean;
}

export interface QueryFetchOpts {
  key?: unknown;
  staleTime?: number;
  staleMs?: number;
  force?: boolean;
  live?: boolean;
}

export interface QuerySpec {
  table: string;
  select?: string[];
  where?: Record<string, unknown>;
  group_by?: string[];
  aggregates?: Array<{ fn: "count" | "sum" | "avg" | "min" | "max"; col?: string; as?: string }>;
  order_by?: Array<{ col: string; dir?: "asc" | "desc" }>;
  limit?: number;
}

export interface QueryMutateOpts<Result = unknown> {
  key?: unknown;
  keys?: unknown[];
  request: () => Promise<Result>;
  apply?: (current: unknown, key: unknown) => unknown;
  rollback?: (snapshot: unknown, error: unknown, key: unknown) => unknown;
  invalidate?: unknown | ((rawKey: unknown, stableKey: string) => boolean);
  refetch?: boolean;
}

export interface BroadcastPublisher {
  slug: string;
  sessionId: string;
  pc: RTCPeerConnection;
  stop(): Promise<void>;
}

export interface BroadcastSubscription {
  slug: string;
  sessionId: string;
  pc: RTCPeerConnection;
  stream: MediaStream;
  policy: RTCIceTransportPolicy;
  stop(): void;
}

export interface IceServer {
  urls: string | string[];
  username?: string;
  credential?: string;
}

export const api: ApiCalls;
export const auth: AuthCalls;
export const users: UsersCalls;

export function table<Row = Record<string, unknown>>(name: string): TableClient<Row>;
export namespace table {
  interface ReadContext { table: string; op: "list" | "get" | "count" }
  interface WriteContext { table: string; op: "create" | "update" | "delete" }
  function before(kind: "read", fn: (opts: unknown, context: ReadContext) => unknown | void): () => void;
  function before(kind: "write", fn: (opts: unknown, context: WriteContext) => unknown | void): () => void;
  function clearHooks(): void;
}

export function live(table: string, callback: (event: ChangeEvent) => void): () => void;
export namespace live {
  function scoped(table: string, fetchAndRender: () => unknown | Promise<unknown>, opts?: { debounce?: number }): () => void;
}

export function room(name: string): RoomClient;
export const flows: Record<string, (params?: Record<string, unknown>, body?: unknown) => Promise<unknown | Job>>;
export function workflow(table: string, id: number | string): WorkflowClient;
export function aggregate<Result = unknown>(name: string): Promise<Result | null>;
export const aggregates: {
  get<Result = unknown>(name: string): Promise<Result | null>;
  all(): Promise<Record<string, unknown>>;
};
export const jobs: {
  status<Result = unknown>(jobId: string, statusUrl?: string): Promise<JobStatus<Result>>;
  wait<Result = unknown>(jobId: string, opts?: JobWaitOpts): Promise<Result>;
};
export const notifications: {
  list(opts?: { limit?: number; offset?: number; unread?: boolean }): Promise<Notification[]>;
  markRead(id: number | string): Promise<void>;
  markAllRead(): Promise<void>;
  delete(id: number | string): Promise<void>;
  onNew(callback: (notification: Notification) => void): () => void;
};
export function upload(file: File | Blob, opts?: { filename?: string; kind?: string }): Promise<UploadResult>;
export const audit: { list(filter?: Record<string, string | number | boolean>): Promise<Record<string, unknown>[]> };
export const permissions: {
  share(table: string, id: number | string, email: string, permission?: "view" | "edit" | "delete" | "admin", expiresAt?: string): Promise<void>;
  revoke(table: string, id: number | string, email: string): Promise<void>;
  list(table: string, id: number | string): Promise<unknown>;
};
export function signedUrl(path: string, opts?: number | { ttl?: number; ttlSeconds?: number; record?: { table: string; id: number | string } }): Promise<string>;
export function t(key: string, vars?: Record<string, string | number>): string;
export const broadcast: {
  publish(slug: string, stream: MediaStream): Promise<BroadcastPublisher>;
  subscribe(slug: string, opts?: { waitForPublisher?: number; signal?: AbortSignal }): Promise<BroadcastSubscription>;
  stats(slug: string): Promise<{ live: boolean; viewers: number; started_at?: string }>;
};
export const webrtc: { iceServers(): Promise<IceServer[]> };
export const mfa: {
  enroll(): Promise<{ qr_data_url: string; secret: string; backup_codes: string[] }>;
  verify(code: string): Promise<{ ok: boolean }>;
  disable(password: string): Promise<{ ok: boolean }>;
};
export function html(strings: TemplateStringsArray, ...values: unknown[]): SafeHtml;
export function raw(value: string): SafeHtml;
export function createStore<State extends Record<string, unknown>>(initialState?: State, opts?: { persist?: StorePersistOpts; cache?: StorePersistOpts }): Store<State>;
export const query: {
  key(key: unknown): string;
  stableStringify(value: unknown): string;
  get<T = unknown>(key: unknown): T | undefined;
  set<T = unknown>(key: unknown, data: T): T;
  subscribe<T = unknown>(key: unknown, fn: (snapshot: QuerySnapshot<T>) => void): () => void;
  fetch<T = unknown>(key: unknown, fetcher: () => Promise<T> | T, opts?: QueryFetchOpts): Promise<T>;
  refetch<T = unknown>(key: unknown): Promise<T | undefined>;
  invalidate(match: unknown | ((rawKey: unknown, stableKey: string) => boolean), opts?: { refetch?: boolean }): string[];
  tableKey(table: string, spec?: Record<string, unknown>): unknown[];
  read<T = unknown>(spec: QuerySpec, opts?: QueryFetchOpts): Promise<T[]>;
  table<T = unknown>(table: string, opts?: Omit<QuerySpec, "table"> & QueryFetchOpts): Promise<T[]>;
  invalidateTable(table: string, opts?: { refetch?: boolean }): string[];
  mutate<T = unknown>(opts: QueryMutateOpts<T>): Promise<T>;
};

declare function markdown(text: string, opts?: { inline?: boolean }): Promise<string>;
declare function markdownBatch(items: Array<string | { text: string; inline?: boolean }>): Promise<string[]>;
declare function presence(slug: string): PresenceHandle;
declare const cache: {
  namespaced(name: string, version: string | number): CacheClient | null;
  persistent(name: string, version: string | number): CacheClient | null;
};

declare const bm: {
  api: typeof api;
  auth: typeof auth;
  users: typeof users;
  table: typeof table;
  live: typeof live;
  room: typeof room;
  flows: typeof flows;
  workflow: typeof workflow;
  aggregate: typeof aggregate;
  aggregates: typeof aggregates;
  jobs: typeof jobs;
  notifications: typeof notifications;
  upload: typeof upload;
  audit: typeof audit;
  permissions: typeof permissions;
  signedUrl: typeof signedUrl;
  t: typeof t;
  mfa: typeof mfa;
  webrtc: typeof webrtc;
  broadcast: typeof broadcast;
  markdown: typeof markdown;
  markdownBatch: typeof markdownBatch;
  presence: typeof presence;
  cache: typeof cache;
  createStore: typeof createStore;
  query: typeof query;
  html: typeof html;
  raw: typeof raw;
};

export default bm;
