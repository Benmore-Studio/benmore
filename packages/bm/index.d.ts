export interface User {
  id: number | string;
  email: string;
  first_name?: string | null;
  last_name?: string | null;
  role: string;
  verified: number;
  /** Every role the user holds: global roles plus the current tenant's roles. */
  roles?: string[];
  /** A groups: app's current tenant id (an admin's act-as tenant while stepped in); null without one. */
  group_id?: string | null;
  [field: string]: unknown;
}

export interface ListOpts {
  limit?: number;
  offset?: number;
  cursor?: string | number;
  q?: string;
  /** Column to order by (snake_case, as stored). */
  sort?: string;
  order?: 'asc' | 'desc';
  /** REST shorthand for sort + order: 'starts_at:asc'. Ignored when sort is set. */
  orderBy?: string;
  /** Related rows to embed (?include=): 'author' or ['author', 'comments']. */
  include?: string | string[];
  /** Columns to return (?fields=). */
  fields?: string | string[];
  /** Page number for page/per_page pagination (list() still returns the rows only). */
  page?: number;
  per_page?: number;
  /** Equality filters (col: value) and operator filters (col__gte: value). Other top-level keys are not sent. */
  where?: Record<string, string | number | boolean>;
}

export interface ApiResult<T = unknown> {
  ok: boolean;
  status: number;
  /**
   * Parsed JSON; the text of a 2xx text/* answer; a Blob for a 2xx answer of
   * any other type (an image, PDF or ZIP); {error, body} for a failed answer
   * that is not JSON (body is the text as received; error is that text when it
   * is one short line of plain text, else "Request failed (HTTP <status>)", so
   * an HTML error page never becomes a thrown Error's message); null for an
   * empty body.
   */
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
  /**
   * When the sign-in still needs a step ({otp_required | mfa_required |
   * mfa_setup_required, redirect}), the browser goes to that page (/verify-otp,
   * /verify-mfa, /mfa-setup, keeping ?next=) and the promise does not settle.
   */
  signIn(identifier: string, password: string): Promise<User | null>;
  signUp(fields: { email: string; password: string; [extraField: string]: unknown }): Promise<User | null>;
  /** Passkeys (WebAuthn): Face ID, Touch ID, Windows Hello, a phone. */
  passkey: PasskeyCalls;
}

export interface Passkey {
  id: number;
  name: string;
  created_at: string;
  last_used_at: string | null;
}

export interface PasskeyCalls {
  /** False where the browser has no WebAuthn. */
  supported(): boolean;
  /** Signed in: create a passkey on this device and save it. Send the current
   * password or an authenticator code; optional within 10 minutes of signing in. */
  register(name?: string, proof?: { password?: string; mfa_code?: string }): Promise<{ id: number; name: string }>;
  /** Signed out: sign in with any passkey saved for this site. */
  signIn(): Promise<User | null>;
  list(): Promise<Passkey[]>;
  remove(id: number): Promise<void>;
}

export interface UsersCalls {
  list(opts?: { limit?: number; offset?: number }): Promise<User[]>;
  get(id: number | string): Promise<User>;
}

export interface CountOpts {
  where?: Record<string, string | number | boolean>;
  q?: string;
}

export interface UpdateReceipt {
  status: 'updated';
}
export interface VersionMetadata {
  _version: number;
  _valid_from: string;
  _valid_to: string | null;
  _changed_by: number | null;
  _change_type: string;
}
export interface VersionHistory {
  id: string;
  versions: VersionMetadata[];
}
export interface RevertKeptColumn {
  column: string;
  reason: 'command_owned' | 'workflow_state' | 'protected' | 'hidden' | 'not_in_version';
}
export interface RevertReceipt {
  status: 'reverted';
  id: string;
  reverted_to_version: string;
  owned_fields_kept: string[] | null;
  /** Columns that kept their current value instead of the version's, and why. */
  kept: RevertKeptColumn[];
}

export interface TableClient<Row = Record<string, unknown>> {
  readonly name: string;
  list(opts?: ListOpts): Promise<Row[]>;
  get(id: number | string): Promise<Row>;
  create(body: Partial<Row>): Promise<Row>;
  update(id: number | string, body: Partial<Row>): Promise<UpdateReceipt>;
  delete(id: number | string): Promise<void>;
  count(opts?: CountOpts): Promise<number>;
  restore(id: number | string): Promise<Row>;
  versions(id: number | string): Promise<VersionHistory>;
  revertTo(id: number | string, version: number): Promise<RevertReceipt>;
}

/** bm.room() connection state, delivered as the 'bm:status' event (from is null). */
export interface RoomStatus {
  state: 'open' | 'reconnecting' | 'closed';
  /** 'open' after a reconnect: messages sent while it was down are not replayed. */
  reconnected?: boolean;
  /** 'reconnecting': retry number, delay in ms, and the socket's close code. */
  attempt?: number;
  retryIn?: number;
  code?: number;
  /** 'reconnecting' after a failed handshake: the GET /ws answer (429, 502, ...). */
  http?: number;
  /** 'closed': why the room ended for good. */
  reason?: 'left' | 'refused' | 'unauthorized' | 'forbidden';
  /** 'closed': queued messages that were never sent. */
  unsent?: number;
}

/** A refused join or handshake, delivered as the 'bm:error' event (from is null). The room then closes. */
export interface RoomError {
  code: 'not_member' | 'too_many_rooms' | 'join_refused' | 'unauthorized' | 'forbidden';
  message: string;
  room: string;
}

export interface RoomClient {
  readonly name: string;
  /** Reconnects with backoff after a drop; 'closed' is final (leave, refused join, 401/403). */
  readonly state: 'connecting' | 'open' | 'reconnecting' | 'closed';
  on(kind: 'bm:status', fn: (status: RoomStatus, from: null) => void): this;
  on(kind: 'bm:error', fn: (error: RoomError, from: null) => void): this;
  on(kind: string, fn: (payload: unknown, from: number | string) => void): this;
  onAny(fn: (payload: unknown, from: number | string | null, kind: string) => void): this;
  off(kind: string, fn: Function): this;
  /** true: sent; false: queued (16 max) until the room is open again.
   *  Throws (code 'room_closed' or 'room_queue_full') instead of dropping. */
  send(payload: unknown): boolean;
  leave(): void;
  /** The current WebSocket; a reconnect replaces it. */
  readonly raw: WebSocket;
}

/** POST /api/<table>/<id>/transition answer. */
export interface WorkflowTransitionResult {
  status: 'transitioned';
  from: string;
  to: string;
  /** The row id as it appeared in the URL (a string). */
  id: string;
}

/** GET /api/<table>/<id>/transitions answer: the row's state and the moves this caller may make. */
export interface WorkflowAvailable {
  current: string;
  /** role is set when the transition is role-gated (the caller holds it). */
  transitions: Array<{ to: string; role?: string }>;
}

export interface WorkflowClient {
  readonly table: string;
  readonly id: number | string;
  transitionTo(state: string): Promise<WorkflowTransitionResult>;
  available(): Promise<WorkflowAvailable>;
  /** The state stored in the workflow's own field (workflows.yaml field:). */
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
  /** The read is polling (X-Benmore-Background: 1), not activity for auth.idle_timeout. Not part of the request or the cache key. */
  background?: boolean;
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
/**
 * Call a flow by name. params fill the route's :path segments; a GET or HEAD
 * flow sends the other params as its query string (it has no body). Resolves
 * the parsed JSON answer, the text of a text/* answer (a CSV), or a Blob for
 * any other type (the image or PDF of run: proxy / serve_file); an async flow
 * resolves a Job.
 */
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
/** Time-limited URL for a file. Default lifetime 300s; audio/video default to 4h so playback does not outlive the link (max 6h). ttlSeconds (alias ttl) is whole seconds (120) or a duration string ('90s', '2h'). */
export function signedUrl(path: string, opts?: number | { ttl?: number | string; ttlSeconds?: number | string; record?: { table: string; id: number | string } }): Promise<string>;
export function t(key: string, vars?: Record<string, string | number>): string;
export const broadcast: {
  publish(slug: string, stream: MediaStream): Promise<BroadcastPublisher>;
  subscribe(slug: string, opts?: { waitForPublisher?: number; signal?: AbortSignal }): Promise<BroadcastSubscription>;
  stats(slug: string): Promise<{ live: boolean; viewers: number; started_at?: string }>;
};
export const webrtc: { iceServers(): Promise<IceServer[]> };
export const mfa: {
  /** From a signed-in session pass the current password; on the /mfa-setup page after a sign-in that requires enrollment, pass nothing. */
  enroll(password?: string): Promise<{ secret: string; otpauth_uri: string; backup_codes: string[] }>;
  /** After a sign-in that required enrollment this also signs the person in (token, user_id, email). */
  verify(code: string): Promise<{ status: "mfa_enabled"; token?: string; user_id?: number; email?: string }>;
  /** Turns the factor off. Takes a current 6-digit code from the authenticator (not the password, not a backup code). */
  disable(code: string): Promise<{ status: "mfa_disabled" }>;
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
  /** The key table(table, opts) caches under, for the same arguments: opts.key when given, else derived from the request. Pass it to subscribe/get/set/invalidate/mutate. */
  tableKey(table: string, opts?: Omit<QuerySpec, "table"> & QueryFetchOpts): unknown;
  /** Cached under opts.key when given: name one to subscribe to the result. */
  read<T = unknown>(spec: QuerySpec, opts?: QueryFetchOpts): Promise<T[]>;
  /** Cached under tableKey(table, opts). */
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

export function captureError(err: unknown, options?: { tags?: Record<string, string> }): void;
export function captureMessage(message: string, level?: 'warning' | 'error' | 'fatal'): void;
export function setTag(key: string, value: string): void;

declare const bm: {
  captureError: typeof captureError;
  captureMessage: typeof captureMessage;
  setTag: typeof setTag;
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
