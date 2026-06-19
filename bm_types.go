//go:build !cli

package main

// Generates TypeScript declaration file (.d.ts) for the bm SDK,
// scoped to THIS app's schema. The output is what Claude Code's TS
// server reads to autocomplete table names, column types, and the SDK
// surface. Served at /_internal/types.d.ts AND written into the
// workspace when the schema changes.
//
// Design notes:
//   - Pure-string output, no template engine. Easy to read, easy to
//     diff.
//   - Per-app: each app's types reflect THAT app's tables. A separate
//     deployment will get different output.
//   - Sensitive columns on _benmore_users are filtered (matching
//     isSensitiveUserColumn), so the agent's editor never autocompletes
//     `user.password_hash`.
//   - Schema-fingerprint header (`// schema: <hash>`) lets `benmore
//     check` warn when the workspace copy is stale vs. the deployed
//     state.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// GenerateBMTypes returns the contents of `bm.d.ts` for the given app.
// The output is a complete TypeScript declaration file: tables, the
// User shape, the SDK surface, and a schema fingerprint comment.
func GenerateBMTypes(app *App) string {
	var b strings.Builder

	// READ-FIRST header. Readers of bm.d.ts often scan for types and skim
	// past the SDK methods entirely - and then reach for raw `fetch()`
	// instead of `bm.table()` without realizing the typed client exists. This
	// front-loaded catalog puts the 5 canonical patterns at the top of
	// the file so the agent sees them BEFORE the interface blob below.
	//
	// Anti-patterns are explicit because the failure mode is consistent:
	// agents skip `bm.table` when they don't know it covers their case,
	// and they reach for bare `bm.live` when they don't know about
	// `bm.live.scoped`. Both rules below close the gap directly.
	b.WriteString(`// ═══════════════════════════════════════════════════════════
// Benmore SDK - typed client for THIS app.
//
// READ FIRST: these core patterns cover ~90% of real frontend code.
// Reach for them BEFORE fetch() or bm.api.* (lower-level escape hatches).
//
//   bm.table('notes').list({where:{user_id:5}})    typed CRUD reads
//   bm.table('notes').create({title:'x'})          typed CRUD writes
//   bm.live.scoped('notes', refresh)               SSE subs (debounced)
//   bm.auth.me() / bm.auth.signOut()               session
//   bm.upload(file)                                multipart upload → {path}
//   bm.html` + "`" + `<li>${name}</li>` + "`" + `                      XSS-safe HTML (auto-escapes)
//
// Anti-patterns to avoid:
//   ✗ fetch('/api/x')     - use bm.table() OR bm.api.* (auto CSRF + JSON)
//   ✗ bm.live(t, fn)      - use bm.live.scoped for ANY high-traffic table
//                           (debounces + dedupes + tab-visibility-pauses)
//   ✗ innerHTML += raw    - use bm.html` + "`" + `...` + "`" + ` (auto-escapes; bm.raw(x) opts out)
//
// For every other feature + recipe (auth, flows, hooks, encryption,
// rbac, realtime, uploads, …) run benmore docs.
// That's the canonical reference; this header is just the 90% shortcut.
//
// Multi-tenant apps that need to inject 'where[group_id]=N' on every
// read: register a scope provider once at app boot, then use bm.table
// normally - no per-call boilerplate.
//
//   bm.table.before('read', opts => ({
//     ...opts, where: { ...opts.where, group_id: currentGroupId() }
//   }));
//
// ═══════════════════════════════════════════════════════════

`)

	// Header.
	fingerprint := tablesFingerprint(app)
	b.WriteString("// AUTO-GENERATED - do not edit.\n")
	b.WriteString("// Regenerated from your schema.\n")
	b.WriteString("// Schema fingerprint (used by app validation to detect drift):\n")
	fmt.Fprintf(&b, "// schema: %s\n\n", fingerprint)

	// Branded IDs - make UserId/MessageId distinguishable at the type
	// level so passing a UserId where a MessageId is expected is a TS
	// error. Each table's PK column is branded by its singular interface
	// name (in writeTableInterface). UserId is special-cased here
	// because the User interface uses the User-table id column.
	b.WriteString("// ─── Branded ID types ───────────────────────────────────────\n")
	b.WriteString("export type UserId = number & { readonly __brand: 'UserId' };\n\n")

	// Imports / global aliases.
	b.WriteString("// ─── Tables (from schema.prisma) ────────────────────────────\n\n")

	tableNames := []string{}
	visibleTables := sortedTables(app)
	for _, t := range visibleTables {
		tableNames = append(tableNames, t.Name)
		writeTableInterface(&b, t)
		b.WriteString("\n")
	}

	// User shape (framework-owned, sensitive cols filtered).
	b.WriteString("// ─── Framework user (sensitive columns filtered) ────────────\n\n")
	writeUserInterface(&b, app)
	b.WriteString("\n")

	// Role union from app.yaml roles: + framework defaults.
	b.WriteString("// ─── Roles (from app.yaml roles:) ───────────────────────────\n")
	writeRoleUnion(&b, app)
	b.WriteString("\n")

	// Generic types the SDK uses.
	b.WriteString("// ─── SDK supporting types ──────────────────────────────────\n\n")
	if len(tableNames) > 0 {
		fmt.Fprintf(&b, "export type TableName = %s;\n\n", quotedUnion(tableNames))
	} else {
		b.WriteString("export type TableName = string;\n\n")
	}
	b.WriteString(`export interface ListOpts {
  limit?: number;
  offset?: number;
  cursor?: string;
  where?: Record<string, string | number | boolean>;
}

export interface ApiResult<T = unknown> {
  ok: boolean;
  status: number;
  data: T | null;
}

/**
 * CRUD event delivered to bm.live(table, cb).
 *
 * The SSE payload is ALWAYS { table, action } - never the row itself.
 * Pre-2.7.33 the type advertised a phantom 'row: T' on insert/update
 * and a phantom 'id: number' on delete; multiple apps both
 * wrote 'if (ev.row) …' handlers that never fired because the wire
 * format simply does not carry that data. The shape now matches reality.
 *
 * On every event, re-fetch the row data via bm.table('x').get(id) or
 * bm.table('x').list({...}). The framework's auto-CRUD endpoints are
 * the source of truth; the SSE channel is a 'something changed' tap.
 *
 *   bm.live('messages', ev => {
 *     if (ev.action === 'refresh') refetchList();
 *     else refetchList();   // every other action also re-fetches
 *   });
 */
export type ChangeEvent =
  | { action: 'insert' | 'update' | 'delete'; table: string }
  | { action: 'refresh'; table: '' };

/** Optional list options narrowed to ?q only on fulltext tables. */
export interface SearchableListOpts extends ListOpts {
  q?: string;
}

interface CountOpts {
  /** Equality + operator filters, same shape as ListOpts.where. */
  where?: Record<string, string | number | boolean>;
  /** FTS5 query (only honored on @@fulltext tables). */
  q?: string;
}

interface BaseTableClient<Row> {
  readonly name: string;
  list(opts?: ListOpts): Promise<Row[]>;
  get(id: number | string): Promise<Row>;
  create(body: Partial<Row>): Promise<Row>;
  update(id: number | string, body: Partial<Row>): Promise<Row>;
  delete(id: number | string): Promise<void>;
  /** TRUE row count, ignoring the LIMIT / per_page cap. Honors WHERE
   * filters + 'q'. Use this instead of (await list()).length when you
   * need the real total - list() caps at 50 by default. */
  count(opts?: CountOpts): Promise<number>;
}
interface FulltextTable<Row> {
  /** Search via SQLite FTS5. Only present on @@fulltext tables. */
  list(opts?: SearchableListOpts): Promise<Row[]>;
}
interface SoftDeleteTable<Row> {
  /** Clear deleted_at. Only present on tables that have the column. */
  restore(id: number | string): Promise<Row>;
}
interface VersionedTable<Row> {
  versions(id: number | string): Promise<Array<{ version: number; data: Row; created_at: string }>>;
  revertTo(id: number | string, version: number): Promise<Row>;
}

/** TableClient<Row, Features> - methods conditional on the table's feature flags. */
export type TableClient<Row, Features extends { softDelete: boolean; fulltext: boolean; versioned: boolean } = { softDelete: false; fulltext: false; versioned: false }> =
  & BaseTableClient<Row>
  & (Features['fulltext']    extends true ? FulltextTable<Row>   : {})
  & (Features['softDelete']  extends true ? SoftDeleteTable<Row> : {})
  & (Features['versioned']   extends true ? VersionedTable<Row>  : {});

export interface RoomClient {
  readonly name: string;
  on(kind: string, fn: (payload: any, from: number) => void): this;
  onAny(fn: (payload: any, from: number, kind: string) => void): this;
  off(kind: string, fn: Function): this;
  send(payload: any): void;
  leave(): void;
  readonly raw: WebSocket;
}

`)

	// Map table-name string → row type (lets table('messages') return TableClient<Message>).
	if len(visibleTables) > 0 {
		b.WriteString("// Table-name → row type mapping. Drives the generic on bm.table().\n")
		b.WriteString("export interface TableTypeMap {\n")
		for _, t := range visibleTables {
			fmt.Fprintf(&b, "  %s: %s;\n", tsKeyForTable(t.Name), pascalCase(singularize(t.Name)))
		}
		b.WriteString("}\n\n")

		// Per-table feature flags (soft-delete / fulltext / versioned).
		// Drives conditional method types on TableClient.
		writeTableFeatures(&b, visibleTables, app)
		b.WriteString("\n")
	}

	// Aggregates from app.yaml aggregates:
	writeAggregatesType(&b, app)

	// Workflows from workflows.yaml
	writeWorkflowsType(&b, app)

	// HTTP flows from flows.yaml
	writeFlowsType(&b, app)

	// I18n keys from i18n/*.yaml
	writeI18nType(&b, app)

	// Notification + AuditEntry types - small static shapes the SDK uses.
	writeAncillaryTypes(&b)

	// SDK surface - declared at the top level. The agent's tsconfig
	// adds `paths: { "bm": ["./bm.d.ts"] }` so `import * as bm from 'bm'`
	// resolves to THIS file's top-level exports. (Pre-2.7.18 we wrapped
	// everything in `declare module 'bm' { ... }` which TS treated as a
	// module AUGMENTATION when the file also had top-level exports -
	// triggering TS2666 on `export default bm`. Flat top-level layout
	// avoids that and is what every npm-published .d.ts uses anyway.)
	b.WriteString("// ─── bm SDK surface ────────────────────────────────────────\n\n")
	b.WriteString(`export interface ApiCalls {
    raw: {
      get<T = any>(path: string): Promise<ApiResult<T>>;
      post<T = any>(path: string, body?: unknown): Promise<ApiResult<T>>;
      patch<T = any>(path: string, body?: unknown): Promise<ApiResult<T>>;
      delete<T = any>(path: string): Promise<ApiResult<T>>;
    };
    get<T = any>(path: string): Promise<T>;
    post<T = any>(path: string, body?: unknown): Promise<T>;
    patch<T = any>(path: string, body?: unknown): Promise<T>;
    delete(path: string): Promise<void>;
    /** Optimistic mutation + reconcile. apply() runs immediately
     *  (instant UI), request() races, revert(snapshot) runs on rejection.
     *  Returns the server response or throws after revert. Replaces
     *  the ~40-line newer-wins guard an earlier app build wrote for
     *  last_read_at. */
    optimistic<T = any, S = unknown>(opts: {
      apply: () => void;
      request: () => Promise<T>;
      snapshot?: () => S;
      revert?: (snapshot: S) => void;
    }): Promise<T>;
  }

  export interface AuthCalls {
    me(): Promise<User | null>;
    signOut(): Promise<void>;
    refreshMe(): Promise<User | null>;
    /** Sign in with the configured identifier (email/phone/username) + password. Throws on failure. */
    signIn(identifier: string, password: string): Promise<User | null>;
    /** Sign up. Pass 'email' + 'password' plus any auth.signup_fields configured in app.yaml. Throws on failure. */
    signUp(fields: { email: string; password: string; [extraField: string]: unknown }): Promise<User | null>;
  }

  export interface UsersCalls {
    list(opts?: { limit?: number; offset?: number }): Promise<User[]>;
    get(id: number): Promise<User>;
  }

  export const api: ApiCalls;
  export const auth: AuthCalls;
  export const users: UsersCalls;

  // Strongly-typed: bm.table('messages') returns TableClient<Message, TableFeatures['messages']>.
  // Unknown table names are a TYPE ERROR (intentional - catches the
  // Prisma → snake_case_plural naming gotcha at compile time, not at
  // runtime). The escape hatch when you need a dynamic string is
  // bm.api.get('/api/<name>') directly.
  export function table<T extends keyof TableTypeMap>(
    name: T
  ): TableClient<TableTypeMap[T], TableFeatures[T]>;

  // Interceptors (v2.7.65+). Register transforms that run on every
  // table read/write call before the HTTP request fires. Use for
  // multi-tenant where-clause injection, audit logging, optimistic
  // local-cache updates, etc.
  //
  //   bm.table.before('read', (opts, ctx) => ({
  //     ...opts,
  //     where: { ...opts.where, group_id: currentGroupId() }
  //   }));
  //
  // Returns an unsubscribe function so feature modules can undo
  // their own hooks on teardown.
  export namespace table {
    interface ReadCtx { table: string; op: 'list' | 'get' | 'count' }
    interface WriteCtx { table: string; op: 'create' | 'update' | 'delete' }
    type Unsubscribe = () => void;
    function before(
      kind: 'read',
      fn: (opts: any, ctx: ReadCtx) => any | void
    ): Unsubscribe;
    function before(
      kind: 'write',
      fn: (opts: any, ctx: WriteCtx) => any | void
    ): Unsubscribe;
    /** Remove every registered hook. Test cleanup helper. */
    function clearHooks(): void;
  }

  // Subscribe to CRUD events for one table or all ('*').
  // Returns an unsubscribe fn. Two overloads - the strongly-typed one
  // (table is a TableName literal) infers the row type from
  // TableTypeMap; the '*' form fires for every table, so the row type
  // is generic.
  // The callback always receives { table, action } - no row data on the
  // wire. Re-fetch via bm.table(name).get/list on each event.
  export function live<T extends keyof TableTypeMap>(
    table: T,
    cb: (ev: ChangeEvent) => void
  ): () => void;
  export function live(
    table: '*',
    cb: (ev: ChangeEvent) => void
  ): () => void;
  export namespace live {
    interface LiveScopedOpts {
      /** Trailing-edge debounce window in ms. Default 60. Bursts of
       *  SSE events coalesce into a single fetchAndRender call fired
       *  this many ms after the LAST event. */
      debounce?: number;
    }
    /** live() with the production-grade plumbing baked in:
     *  generation-counter dedupe, trailing-edge debounce, visibility
     *  refresh on tab return, primed-on-mount. Replaces the ~60-line
     *  pattern an earlier app build re-derived for racing refetches. */
    function scoped(
      table: keyof TableTypeMap | '*',
      fetchAndRender: () => unknown | Promise<unknown>,
      opts?: LiveScopedOpts
    ): () => void;
  }

  // Join a WebSocket room. Returns a thin client; multi-tenant scope
  // isolation applies - same-app cross-user broadcast works since v2.7.10.
  export function room(name: string): RoomClient;

  // ── markdown - tiny safe renderer ────────────────────────────────────
  /** Render a Markdown subset to safe HTML.
   *
   * Escapes user input first, allowlists http/https/mailto links,
   * supports bold / italic / inline-code / fenced-code / links /
   * lists / blockquotes. Lazy-loaded from /_internal/markdown.js on
   * first call. Safe to assign the result to .innerHTML. */
  export function markdown(text: string): Promise<string>;

  // ── bm.html - XSS-safe tagged template literal (v2.7.66+) ─────────────
  //
  // Used as a tagged template literal, every interpolated value is
  // automatically HTML-escaped. Drop-in replacement for raw template
  // literals - stop writing manual escapeHtml() calls. The output is
  // a string-shaped value that coerces correctly when assigned to
  // innerHTML or concatenated. Nested bm.html outputs and arrays of
  // them are joined verbatim (the safe marker propagates).
  //
  // Use bm.raw() to opt out per-value when inserting already-safe
  // HTML (component output, sanitized markdown, framework icon
  // helpers) - bypasses escaping for that one interpolation only.
  //
  // null and undefined render as empty string (matches lit / Preact).
  // The five HTML-meaningful characters are escaped: & < > " '
  type SafeHtml = string & { readonly __brand: 'SafeHtml' };
  export function html(strings: TemplateStringsArray, ...values: any[]): SafeHtml;
  /** Mark a string as already-safe HTML; bypasses escaping in the
   *  surrounding bm.html tagged template's interpolation. Use ONLY for
   *  HTML you generated yourself (component primitives, sanitized markdown). */
  export function raw(htmlString: string): SafeHtml;

  // ── presence - who's live in this slug right now ─────────────────────
  export interface PresenceMember {
    user_id: number;
    joined_at: string;
    last_seen_at: string;
  }
  export interface PresenceHandle {
    readonly slug: string;
    /** Currently-live members of the slug. */
    members(): Promise<PresenceMember[]>;
    /** Just the count - cheaper than fetching the full list. */
    count(): Promise<number>;
    /** Subscribe to join/leave/sweep notifications. Returns unsubscribe. */
    onChange(fn: () => void): () => void;
    /** Explicit leave. pagehide also fires this automatically. */
    leave(): void;
  }
  /** Join a presence slug and start the heartbeat loop.
   *
   * Server-side: row in _benmore_presence keyed by (slug, user_id).
   * Sweep loop removes anyone whose last heartbeat is older than 90s
   * (browser crashed, OS killed the tab, etc.). pagehide on the
   * client fires sendBeacon so explicit closes are instant.
   *
   * Use for: live huddle participants, stream viewers, chat-room
   * typing indicators, "who's looking at this doc right now." */
  export function presence(slug: string): PresenceHandle;

  // ── cache - self-busting client storage ──────────────────────────────
  export interface CacheClient {
    readonly name: string;
    readonly version: string;
    /** Returns cached value or undefined when missing / stale. */
    get(): string | undefined;
    /** Store a string value at the (name, version) key. */
    set(value: string): void;
    /** Remove the current-version entry. */
    clear(): void;
    /** Remove every prior-version entry for this name (current stays). */
    purgeOld(): void;
  }
  export const cache: {
    /** Session-scoped (sessionStorage). Self-busts on version change. */
    namespaced(name: string, version: string | number): CacheClient | null;
    /** Persistent (localStorage). Self-busts on version change. */
    persistent(name: string, version: string | number): CacheClient | null;
  };

  // ── flows (from flows.yaml - typed per HTTP-triggered flow) ─────────
  export const flows: FlowMap;

  // ── workflows (from workflows.yaml - typed state machines) ──────────
  export function workflow<T extends keyof WorkflowMap>(
    table: T, id: number | string
  ): WorkflowClient<T>;

  export interface WorkflowClient<T extends keyof WorkflowMap> {
    transitionTo(state: WorkflowMap[T]['states']): Promise<{ state: WorkflowMap[T]['states'] }>;
    available(): Promise<WorkflowMap[T]['states'][]>;
    current(): Promise<WorkflowMap[T]['states']>;
  }

  // ── aggregates (from app.yaml aggregates:) ───────────────────────────
  export function aggregate<K extends AggregateName>(name: K): Promise<AggregateMap[K]>;
  export const aggregates: {
    get<K extends AggregateName>(name: K): Promise<AggregateMap[K]>;
    all(): Promise<Record<AggregateName, number | string | null>>;
  };

  // ── jobs (async-flow status + wait) ──────────────────────────────────
  export const jobs: {
    status<T = unknown>(jobId: string, statusUrl?: string): Promise<JobStatus<T>>;
    wait<T = unknown>(jobId: string, opts?: { intervalMs?: number; timeoutMs?: number; statusUrl?: string }): Promise<T>;
  };

  // ── notifications (in-app inbox) ─────────────────────────────────────
  export const notifications: {
    list(opts?: { limit?: number; offset?: number; unread?: boolean }): Promise<Notification[]>;
    markRead(id: number): Promise<void>;
    markAllRead(): Promise<void>;
    delete(id: number): Promise<void>;
    onNew(cb: (n: Notification) => void): () => void;
  };

  // ── upload (multipart → /uploads/<path>) ─────────────────────────────
  export function upload(
    file: File | Blob,
    opts?: { kind?: string; filename?: string }
  ): Promise<{ path: string; url?: string; size: number; mime: string }>;

  // ── audit (read the audit trail; admin endpoint) ─────────────────────
  export const audit: {
    list(filter?: {
      table?: TableName;
      row_id?: number;
      user_id?: number;
      action?: 'insert' | 'update' | 'delete';
      limit?: number;
      offset?: number;
    }): Promise<AuditEntry[]>;
  };

  // ── permissions (per-row ACL - permission enum matches framework) ───
  export const permissions: {
    /** permission: framework's permissionLevel map - view | edit | delete | admin. */
    share(
      table: TableName,
      id: number | string,
      email: string,
      permission?: 'view' | 'edit' | 'delete' | 'admin',
      expires_at?: string,
    ): Promise<void>;
    revoke(table: TableName, id: number | string, email: string): Promise<void>;
    list(table: TableName, id: number | string): Promise<{ permissions: Array<{ email: string; permission: string }> | null; resource_id: string; resource_type: string }>;
  };

  // ── signedUrl (time-limited file URL) ────────────────────────────────
  // PRIVATE files on the media CDN require the 'record' option - the
  // row that owns the file. The signature is authorized against that record's
  // access policy (roles, perms, scopes, group/owner/ACL), not just a logged-in
  // session. Public/local files don't need it.
  //   await bm.signedUrl(doc.file_url, { record: { table: 'documents', id: doc.id } })
  export function signedUrl(
    path: string,
    opts?: number | { ttlSeconds?: number; record?: { table: string; id: string | number } }
  ): Promise<string>;

  // ── t (i18n; keys are statically typed from i18n/*.yaml) ─────────────
  export function t(key: I18nKey, vars?: Record<string, string | number>): string;

  // ── mfa (TOTP enrollment + verification) ─────────────────────────────
  export const mfa: {
    enroll(): Promise<{ qr_data_url: string; secret: string; backup_codes: string[] }>;
    verify(code: string): Promise<{ ok: boolean }>;
    disable(password: string): Promise<{ ok: boolean }>;
  };

  // ── broadcast (SFU-backed 1:N livestream) ────────────────────────────
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
    stop(): void;
  }
  export interface BroadcastStats {
    live: boolean;
    viewers: number;
    started_at?: string;
  }
  export interface BroadcastSubscribeOpts {
    /** Milliseconds to keep retrying when no publisher is live yet
     *  (404 / 503). Default 30000. Set 0 for fail-fast (legacy).
     *  Covers the race where a second participant subscribes before
     *  the first participant's publish finishes ICE gathering. */
    waitForPublisher?: number;
    /** Cancel the retry loop. */
    signal?: AbortSignal;
  }
  export const broadcast: {
    /** Publish a MediaStream to the SFU. Throws { status: 503 } when SFU not configured. */
    publish(slug: string, stream: MediaStream): Promise<BroadcastPublisher>;
    /** Subscribe to a live broadcast. Retries on 404/503 up to
     *  waitForPublisher ms (default 30000) so the subscribe-before-
     *  publish race doesn't surface as an error. */
    subscribe(slug: string, opts?: BroadcastSubscribeOpts): Promise<BroadcastSubscription>;
    /** Stats for a slug - safe to poll for viewer-count pills. */
    stats(slug: string): Promise<BroadcastStats>;
  };

  // ── webrtc (ICE servers - STUN by default, TURN when configured) ─────
  export interface IceServer {
    urls: string | string[];
    username?: string;
    credential?: string;
  }
  export const webrtc: {
    /**
     * Fetch the configured ICE server list. Always includes STUN; includes
     * TURN when TURN_PROVIDER + credentials are configured via env.
     * Pass directly to new RTCPeerConnection({ iceServers: ... }).
     */
    iceServers(): Promise<IceServer[]>;
  };

declare const bm: {
  api: ApiCalls;
  auth: AuthCalls;
  users: UsersCalls;
  table: typeof table;
  live: typeof live;
  room: typeof room;
  flows: FlowMap;
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
};
export default bm;

// window.bm fallback for non-import-map pages. The cast is so the
// global mirrors the file's default export without an import - for
// agents who do plain <script src="/_internal/bm.js"> and want
// window.bm.foo to autocomplete in the editor.
declare global {
  interface Window {
    bm: typeof bm;
  }
}
`)

	// sdui - the schema-driven component library (/_internal/sdui.js),
	// mapped into the import map automatically by the server.
	b.WriteString(`
// ─── sdui - schema-driven components (import { DataTable } from 'sdui') ─
declare module 'sdui' {
  export interface DataTableOpts { table: TableName; columns?: string; limit?: number; perPage?: number; where?: Record<string, string | number | boolean>; onRowClick?: (id: string) => void; sortable?: boolean; sortField?: string; sortOrder?: 'asc' | 'desc'; search?: boolean; paginate?: boolean; }
  export interface RecordFormOpts { table: TableName; id?: string | number; onSaved?: (row: any) => void; sections?: { title?: string; fields: string }[]; }
  export interface DetailOpts { table: TableName; id: string | number; children?: string; }
  export interface SkinPrimitives { [name: string]: (args: any) => string; }
  /** Render a schema-derived table into target (CSS selector or element). Live-refreshes. */
  export function DataTable(target: string | HTMLElement, opts: DataTableOpts): Promise<{ refresh: () => Promise<void>; destroy: () => void }>;
  /** Render a schema-derived create/edit form. Omit id to create, pass id to edit. FK fields become relation pickers. */
  export function RecordForm(target: string | HTMLElement, opts: RecordFormOpts): Promise<{ destroy: () => void }>;
  export interface WizardStep { title?: string; fields: string; }
  export interface WizardFormOpts { table: TableName; steps: WizardStep[]; id?: string | number; onSaved?: (row: any) => void; }
  /** Multi-step RecordForm. You declare the step grouping (a UX choice the schema can't derive); controls/validation/submit are still derived. */
  export function WizardForm(target: string | HTMLElement, opts: WizardFormOpts): Promise<{ destroy: () => void }>;
  /** Read-only record view + embedded child tables (one-to-many relations from the schema). */
  export function Detail(target: string | HTMLElement, opts: DetailOpts): Promise<{ destroy: () => void }>;
  export interface FlowFormOpts { flow: keyof FlowMap | string; params?: Record<string, unknown>; onResult?: (res: any) => void; }
  /** Render a form from a flow's declared inputs: block, call it, auto-poll if async. */
  export function FlowForm(target: string | HTMLElement, opts: FlowFormOpts): Promise<{ destroy: () => void }>;
  export interface TransitionsOpts { table: TableName; id: string | number; onTransition?: (to: string) => void; }
  /** Render role-gated workflow transition buttons from bm.workflow().available(). */
  export function Transitions(target: string | HTMLElement, opts: TransitionsOpts): Promise<{ refresh: () => Promise<void>; destroy: () => void }>;
  /** Hide the target element unless the caller holds the perm/role. */
  export function Gate(target: string | HTMLElement, opts: { perm?: string; role?: string }): Promise<boolean>;
  /** True if the session's permissions cover this resource:action scope. */
  export function can(perm: string): Promise<boolean>;
  /** True if the session holds the role (comma-separated = any-of; admin always passes). */
  export function hasRole(role: string): Promise<boolean>;
  export interface UploaderOpts { onUpload?: (res: any) => void; }
  /** File upload wrapper over bm.upload. */
  export function Uploader(target: string | HTMLElement, opts?: UploaderOpts): Promise<{ destroy: () => void }>;
  /** The per-user /api/_schema descriptor (cached for the session). */
  export function schema(): Promise<Record<string, any>>;
  export function clearSchemaCache(): void;
  /** Replace presentation primitives - this is how you ship a design library. */
  export function registerSkin(overrides: SkinPrimitives): void;
  export function resetSkin(): void;
  /** Brand the accent color (buttons, links, active states, sparkbars, …) across EVERY component via the --bm-accent CSS var. Default #2563eb. */
  export function setAccent(color: string, textColor?: string): void;

  // ─── Wave 1: data + display + primitives ───────────────────────────
  export interface CardsOpts { table: TableName; where?: Record<string, string | number | boolean>; limit?: number; title?: string; subtitle?: string; badge?: string; onCardClick?: (id: string) => void; }
  /** Schema-derived card grid (title/subtitle/badge columns auto-pick from schema). Live-refreshes. */
  export function Cards(target: string | HTMLElement, opts: CardsOpts): Promise<{ refresh: () => Promise<void>; destroy: () => void }>;
  export interface BoardOpts { table: TableName; groupBy?: string; groups?: string[]; title?: string; where?: Record<string, string | number | boolean>; limit?: number; transition?: boolean; onMove?: (id: string, to: string) => void; }
  /** Kanban grouped by a column; drag a card to a lane to PATCH that column. Pass groups[] for ordered lanes (enums aren't in the schema). If the column is workflow-governed, pass transition:true to move via the state machine instead of a raw update. */
  export function Board(target: string | HTMLElement, opts: BoardOpts): Promise<{ refresh: () => Promise<void>; destroy: () => void }>;
  export interface StatOpts { table?: TableName; where?: Record<string, string | number | boolean>; q?: string; aggregate?: string; value?: unknown | (() => unknown | Promise<unknown>); label?: string; format?: (v: any) => string; live?: boolean; }
  /** A single metric tile - table row count, a materialized aggregate, or a custom value. Live-refreshes when bound to a table. */
  export function Stat(target: string | HTMLElement, opts: StatOpts): Promise<{ refresh: () => Promise<void>; destroy: () => void }>;
  export interface ChartOpts { type?: 'bar' | 'line' | 'pie' | 'doughnut'; table?: TableName; groupBy?: string; value?: string; data?: { labels: string[]; values: number[] }; where?: Record<string, string | number | boolean>; limit?: number; label?: string; height?: number; color?: string; live?: boolean; }
  /** Chart.js over a table group-by (value: 'count' | 'sum:<col>') or explicit { labels, values }. */
  export function Chart(target: string | HTMLElement, opts: ChartOpts): Promise<{ refresh: () => Promise<void>; destroy: () => void }>;

  export type Content = string | Node | ((el: HTMLElement) => string | void);
  export interface Overlay { close: () => void; el: HTMLElement; panel: HTMLElement; }
  /** Modal overlay. The .el handle is the body container - mount any component into it. */
  export function Modal(opts?: { title?: string; content?: Content; size?: 'sm' | 'md' | 'lg' | 'xl'; onClose?: () => void; dismissable?: boolean }): Overlay;
  /** Side drawer. Same handle shape as Modal. */
  export function Drawer(opts?: { side?: 'left' | 'right'; width?: string; title?: string; content?: Content; onClose?: () => void }): Overlay;
  /** Tabbed panels; each tab's content mounts lazily on select. */
  export function Tabs(target: string | HTMLElement, opts: { tabs: { label: string; content?: Content }[]; active?: number }): { select: (i: number) => void; destroy: () => void };
  /** Accordion; each item's content mounts lazily on first open. */
  export function Accordion(target: string | HTMLElement, opts: { items: { title: string; content?: Content; open?: boolean }[]; multi?: boolean }): { destroy: () => void };
  /** Transient toast in a global stack. */
  export function Toast(message: string, opts?: { type?: 'info' | 'success' | 'error' | 'warning'; duration?: number; action?: { label: string; onClick?: () => void } }): { dismiss: () => void };
  /** Dropdown menu button. */
  export function Dropdown(target: string | HTMLElement, opts: { label?: string; items: { label: string; onClick?: () => void; href?: string; danger?: boolean }[] }): { close: () => void; destroy: () => void };
  /** Hover tooltip on the target element. */
  export function Tooltip(target: string | HTMLElement, opts: { text: string }): { destroy: () => void };

  // Atoms - return HTML strings (use with bm.raw / innerHTML).
  export function Badge(text: string, opts?: { variant?: 'neutral' | 'success' | 'warning' | 'error' | 'info' }): string;
  export function Avatar(opts?: { name?: string; src?: string; size?: number }): string;
  export function Spinner(opts?: { size?: number }): string;
  export function Skeleton(opts?: { lines?: number; height?: number; width?: string }): string;
  export function ProgressBar(value: number, opts?: { max?: number; label?: string; color?: string }): string;

  // ─── Wave 2: auth · governance · files · workflow · realtime · ops ─
  export interface Handle { destroy: () => void; refresh?: () => Promise<void>; }
  export interface SignupField { name: string; label?: string; type?: string; required?: boolean; }
  /** Email+password sign-in form (bm.auth.signIn). */
  export function Login(target: string | HTMLElement, opts?: { onSuccess?: (user: any) => void; redirect?: string | false }): Handle;
  /** Registration form (bm.auth.signUp). Pass fields[] to collect signup_fields. */
  export function Signup(target: string | HTMLElement, opts?: { fields?: SignupField[]; onSuccess?: (user: any) => void; redirect?: string | false }): Handle;
  /** Forgot-password request form. */
  export function Forgot(target: string | HTMLElement, opts?: {}): Handle;
  /** Reset-password form (reads ?token= if not passed). */
  export function Reset(target: string | HTMLElement, opts?: { token?: string }): Handle;
  /** Edit the current user's profile (GET/PATCH /api/_auth/profile); protected fields filtered. */
  export function ProfileForm(target: string | HTMLElement, opts?: { onSaved?: (user: any) => void }): Promise<Handle>;
  /** TOTP enrollment + verify + disable (bm.mfa). */
  export function MfaSetup(target: string | HTMLElement, opts?: {}): Promise<Handle>;
  /** Connect/disconnect OAuth providers (GET/DELETE /api/_auth/oauth-tokens). */
  export function OAuthConnect(target: string | HTMLElement, opts?: { providers?: string[] }): Promise<Handle>;
  /** List + revoke active sessions. */
  export function SessionManager(target: string | HTMLElement, opts?: {}): Promise<Handle>;
  /** Create + revoke personal API tokens (raw token shown once). */
  export function ApiTokenManager(target: string | HTMLElement, opts?: {}): Promise<Handle>;
  /** Admin-only impersonation (requires admin's password re-auth). */
  export function ActAs(target: string | HTMLElement, opts?: {}): Promise<Handle>;

  /** Per-record version list + point-in-time revert. */
  export function VersionHistory(target: string | HTMLElement, opts: { table: TableName; id: string | number; onRevert?: () => void }): Promise<Handle>;
  /** Audit-log table (admin); filter by table/row_id/user_id/action. */
  export function AuditLog(target: string | HTMLElement, opts?: { table?: string; row_id?: string | number; user_id?: string | number; action?: string; limit?: number }): Promise<Handle>;
  /** Pessimistic lock state + acquire/release for a record. */
  export function RecordLock(target: string | HTMLElement, opts: { table: TableName; id: string | number }): Promise<Handle>;
  /** Per-record ACL share dialog (bm.permissions). */
  export function ShareDialog(target: string | HTMLElement, opts: { table: TableName; id: string | number }): Promise<Handle>;
  /** Export every readable table as a JSON download. */
  export function DownloadMyData(target: string | HTMLElement, opts?: { label?: string }): Promise<Handle>;

  /** Time-limited signed <img> (bm.signedUrl). */
  export function SignedImage(target: string | HTMLElement, opts: { path: string; ttl?: number; alt?: string; class?: string }): Promise<Handle>;
  /** Link to the server-rendered PDF of a page (/pdf/{page}). */
  export function PdfButton(target: string | HTMLElement, opts: { page: string; label?: string; query?: Record<string, string> }): Handle;
  /** Image grid from an app table (urlField/captionField). Live-refreshes. */
  export function MediaGallery(target: string | HTMLElement, opts: { table: TableName; urlField?: string; captionField?: string; where?: Record<string, string | number | boolean>; limit?: number }): Promise<Handle>;

  /** Button that calls a flow (async-aware via job.wait). */
  export function FlowButton(target: string | HTMLElement, opts: { flow: keyof FlowMap | string; params?: Record<string, unknown>; body?: unknown; label?: string; confirm?: string; onResult?: (res: any) => void }): Handle;
  /** Current workflow state as a colored Badge; live. */
  export function WorkflowBadge(target: string | HTMLElement, opts: { table: TableName; id: string | number }): Promise<Handle>;
  /** Poll a background job's status until terminal. */
  export function JobStatus(target: string | HTMLElement, opts: { jobId: string; onDone?: (s: any) => void; intervalMs?: number }): Promise<Handle>;
  /** Background-jobs table with retry. */
  export function JobsDashboard(target: string | HTMLElement, opts?: {}): Promise<Handle>;

  /** Notification inbox bell with unread count; live (bm.notifications). opts.icon: emoji or raw SVG/HTML to replace the default bell. */
  export function NotificationBell(target: string | HTMLElement, opts?: { icon?: string }): Promise<Handle>;
  /** Live presence for a slug (bm.presence). Default shows only online people; roster:true lists everyone with green=online, hollow grey=offline. */
  export function Presence(target: string | HTMLElement, opts: { slug: string; roster?: boolean }): Promise<Handle>;
  /** Table-backed live chat. */
  export function Chat(target: string | HTMLElement, opts: { table: TableName; bodyField?: string; where?: Record<string, string | number | boolean>; extra?: Record<string, unknown>; height?: string; limit?: number }): Promise<Handle>;
  /** Comment thread scoped to a parent record. */
  export function CommentThread(target: string | HTMLElement, opts: { table: TableName; where: Record<string, string | number | boolean>; bodyField?: string; limit?: number }): Promise<Handle>;
  /** Reverse-chron live activity feed over a table. */
  export function ActivityFeed(target: string | HTMLElement, opts: { table: TableName; titleField?: string; where?: Record<string, string | number | boolean>; limit?: number }): Promise<Handle>;

  /** Composite Stat + Chart grid. */
  export function Dashboard(target: string | HTMLElement, opts: { stats?: StatOpts[]; charts?: ChartOpts[] }): Promise<{ destroy: () => void }>;
  /** Per-user usage metrics (GET /api/_usage). */
  export function UsageMeter(target: string | HTMLElement, opts?: {}): Promise<Handle>;
  /** Manage outbound webhook subscriptions (list/add/test/delete). */
  export function WebhookManager(target: string | HTMLElement, opts?: {}): Promise<Handle>;

  // ─── Wave 3a: cross-table read/query layer (POST /api/_query) ──────
  export interface QueryAgg { fn: 'count' | 'sum' | 'avg' | 'min' | 'max'; col?: string; as?: string; }
  export interface QueryWhere { [col: string]: string | number | boolean | { eq?: any; ne?: any; gt?: any; gte?: any; lt?: any; lte?: any; like?: string; in?: any[] }; }
  export interface QueryOrder { col: string; dir?: 'asc' | 'desc'; }
  export interface QuerySpec { table: TableName; select?: string[]; where?: QueryWhere; group_by?: string[]; aggregates?: QueryAgg[]; order_by?: QueryOrder[]; limit?: number; }
  /** Run a declarative, scoped, column-validated read. Returns rows. */
  export function query(spec: QuerySpec): Promise<any[]>;
  /** Filtered/sorted table from a query spec (results need not be schema fields). Live. */
  export function QueryView(target: string | HTMLElement, opts: { table: TableName; select?: string[]; where?: QueryWhere; order_by?: QueryOrder[]; limit?: number; columns?: string[]; onRowClick?: (id: string) => void }): Promise<Handle>;
  /** Grouped aggregate report (+ optional chart). */
  export function Report(target: string | HTMLElement, opts: { table: TableName; group_by: string | string[]; aggregates?: QueryAgg[]; where?: QueryWhere; order_by?: QueryOrder[]; limit?: number; chart?: { type?: 'bar' | 'line' | 'pie' | 'doughnut' } }): Promise<Handle>;
  /** Two-dimension pivot table (rows × cols, aggregated value). */
  export function PivotTable(target: string | HTMLElement, opts: { table: TableName; rows: string; cols: string; value?: QueryAgg; where?: QueryWhere }): Promise<Handle>;
  /** List / save / delete persisted query specs. */
  export function SavedViews(target: string | HTMLElement, opts?: { spec?: QuerySpec; onSelect?: (spec: QuerySpec, view: any) => void }): Promise<Handle>;

  // ─── Wave 3b/3c: relations + scheduling + approvals ───────────────
  /** Many-to-many editor over a join table (add via picker, remove via ×). */
  export function MultiRelation(target: string | HTMLElement, opts: { table: TableName; parentField: string; parentId: string | number; childTable: TableName; childField: string; labelField?: string; onChange?: () => void }): Promise<Handle>;
  /** Hierarchy from a self-referential FK column. */
  export function TreeView(target: string | HTMLElement, opts: { table: TableName; parentField?: string; labelField?: string; onSelect?: (id: string) => void }): Promise<Handle>;
  /** Schedule an in-app reminder for now/a record (POST /api/_scheduled). */
  export function Reminder(target: string | HTMLElement, opts?: { table?: TableName; rowId?: string | number }): Promise<Handle>;
  /** Schedule a flow to run at a future time. */
  export function ScheduleAction(target: string | HTMLElement, opts: { flow: keyof FlowMap | string; body?: unknown; table?: TableName; rowId?: string | number; label?: string }): Promise<Handle>;
  /** Request + decide human approval on a record (/api/_approvals). */
  export function Approval(target: string | HTMLElement, opts: { table: TableName; id: string | number; approverEmail?: string; title?: string }): Promise<Handle>;

  // ─── Wave 4: tail (data views, layout, editors, livestream) ───────
  /** Month-grid calendar of records placed on a date column. */
  export function Calendar(target: string | HTMLElement, opts: { table: TableName; dateField: string; titleField?: string; where?: Record<string, string | number | boolean>; onSelect?: (id: string) => void }): Promise<Handle>;
  /** Vertical reverse-chron timeline of a table. */
  export function Timeline(target: string | HTMLElement, opts: { table: TableName; dateField?: string; titleField?: string; where?: Record<string, string | number | boolean>; limit?: number }): Promise<Handle>;
  /** Click-to-edit a single field (PATCH on enter/blur). */
  export function InlineEdit(target: string | HTMLElement, opts: { table: TableName; id: string | number; field: string; value?: any; onSaved?: (v: any) => void }): Promise<{ destroy: () => void }>;
  /** Conversion funnel - row counts per stage value. */
  export function Funnel(target: string | HTMLElement, opts: { table: TableName; stageField: string; stages: string[]; where?: Record<string, string | number | boolean> }): Promise<Handle>;
  /** CSV import → POST /api/{table}/batch. */
  export function Import(target: string | HTMLElement, opts: { table: TableName; onDone?: (res: any) => void }): { destroy: () => void };
  /** Manage runtime custom fields (/api/_schema/{table}/fields). */
  export function CustomFields(target: string | HTMLElement, opts: { table: TableName }): Promise<Handle>;
  /** App layout shell (sidebar nav + content slot). Returns the content element to mount into. */
  export function AppShell(target: string | HTMLElement, opts: { title?: string; brand?: string; nav?: { label: string; href?: string; onClick?: () => void; icon?: string }[]; active?: number }): { content: HTMLElement; destroy: () => void };
  /** Horizontal nav. */
  export function Nav(target: string | HTMLElement, opts: { items: { label: string; href?: string; onClick?: () => void }[]; active?: number }): { destroy: () => void };
  /** Breadcrumb trail. */
  export function Breadcrumbs(target: string | HTMLElement, opts: { items: { label: string; href?: string }[] }): { destroy: () => void };
  /** ⌘K command palette. */
  export function CommandPalette(opts: { commands: { label: string; run: () => void; hint?: string }[]; hotkey?: string }): { open: () => void; close: () => void; destroy: () => void };
  /** Native date input wrapper. */
  export function DatePicker(target: string | HTMLElement, opts?: { value?: string; onChange?: (v: string) => void }): { readonly value: string; destroy: () => void };
  /** Render markdown safely (bm.markdown). */
  export function Markdown(target: string | HTMLElement, opts: { text: string }): Promise<{ destroy: () => void }>;
  /** Minimal rich-text editor (bold/italic/list) → HTML. */
  export function RichText(target: string | HTMLElement, opts?: { value?: string; onChange?: (html: string) => void }): { readonly html: string; destroy: () => void };
  /** Code block with copy button. */
  export function Code(target: string | HTMLElement, opts: { code: string; lang?: string; copy?: boolean }): { destroy: () => void };
  /** Publish this device's camera/mic to a broadcast slug (bm.broadcast). */
  export function Broadcast(target: string | HTMLElement, opts: { slug: string }): Promise<{ stop: () => void; destroy: () => void }>;
  /** Subscribe to a broadcast slug. */
  export function Viewer(target: string | HTMLElement, opts: { slug: string }): Promise<{ destroy: () => void }>;

  // ─── Wave 5: additional component gaps + general additions ───────────
  /** Ordered stage tracker (done/current/upcoming). */
  export function Stepper(target: string | HTMLElement, opts: { steps: (string | { label: string })[]; current: number | string; onClick?: (i: number) => void }): { set: (i: number) => void; destroy: () => void };
  /** Filter controls that build a where-object and push it to a DataTable handle (target) / onChange. */
  export function FilterBar(target: string | HTMLElement, opts: { filters: { name: string; label?: string; type?: 'select' | 'date' | 'search'; options?: (string | { value: string; label: string })[] }[]; target?: { setWhere: (w: any) => void }; onChange?: (where: Record<string, string>) => void }): { value: () => Record<string, string>; apply: () => void; destroy: () => void };
  /** KPI metric tile with optional delta + sparkline. */
  export function KpiTile(target: string | HTMLElement, opts: { label: string; value: any; delta?: number; deltaUnit?: string; deltaLabel?: string; spark?: number[]; format?: (v: any) => string }): { destroy: () => void };
  /** Inline callout banner. */
  export function Alert(target: string | HTMLElement, opts: { type?: 'info' | 'success' | 'warning' | 'error'; title?: string; message: string; dismissible?: boolean; onDismiss?: () => void }): { destroy: () => void };
  /** Empty-state block with icon/title/body/CTA. */
  export function EmptyState(target: string | HTMLElement, opts: { icon?: string; title: string; body?: string; actionLabel?: string; onAction?: () => void }): { destroy: () => void };
  /** Promise-returning confirm modal. */
  export function ConfirmDialog(opts?: { title?: string; message?: string; confirmLabel?: string; cancelLabel?: string; danger?: boolean }): Promise<boolean>;
  /** Field-by-field diff of two objects (changed keys only). */
  export function DiffViewer(target: string | HTMLElement, opts: { before: Record<string, any>; after: Record<string, any>; fields?: string[] }): { destroy: () => void };
  /** Segmented pill toggle. */
  export function SegmentedControl(target: string | HTMLElement, opts: { options: (string | { value: string; label: string })[]; value?: string; onChange?: (v: string) => void }): { readonly value: string; set: (v: string) => void; destroy: () => void };
  /** From/to date range. */
  export function DateRangePicker(target: string | HTMLElement, opts?: { from?: string; to?: string; onChange?: (r: { from: string; to: string }) => void }): { readonly value: { from: string; to: string }; destroy: () => void };
  /** Radial gauge; pass threshold for pass/fail coloring. */
  export function Gauge(target: string | HTMLElement, opts: { value: number; min?: number; max?: number; threshold?: number; label?: string; unit?: string; color?: string; format?: (v: number) => string }): { set: (v: number) => void; destroy: () => void };
  /** Record header - title + subtitle + meta chips + action buttons. */
  export function DetailHeader(target: string | HTMLElement, opts: { title: string; subtitle?: string; meta?: string[]; badge?: string | { label: string; variant?: string }; actions?: { label: string; onClick?: () => void; variant?: 'primary'; danger?: boolean }[] }): { destroy: () => void };
  /** Master/detail two-pane layout; returns the two mount elements. */
  export function SplitLayout(target: string | HTMLElement, opts?: { leftWidth?: string; gap?: string }): { left: HTMLElement; right: HTMLElement; destroy: () => void };
  /** Leaflet + OSM map. Needs the app CSP to allow unpkg.com + *.tile.openstreetmap.org. */
  export function Map(target: string | HTMLElement, opts: { lat?: number; lng?: number; zoom?: number; markers?: { lat: number; lng: number; label?: string }[]; height?: string; label?: string }): Promise<{ map: any; destroy: () => void }>;
  /** Number input with a currency prefix. */
  export function MoneyInput(target: string | HTMLElement, opts?: { value?: number; currency?: string; width?: string; onChange?: (v: number | null) => void }): { readonly value: number | null; destroy: () => void };
  /** Number input with a percent suffix. */
  export function PercentInput(target: string | HTMLElement, opts?: { value?: number; width?: string; onChange?: (v: number | null) => void }): { readonly value: number | null; destroy: () => void };

  // ─── Wave 6: schedule + checklist ──────────────────────────────────
  /** Gantt bars on a date axis. Pass items[] or a table + start/end/label fields. */
  export interface GanttItem { id?: string | number; label: string; start: string; end?: string; color?: string; children?: GanttItem[] }
  export function GanttChart(target: string | HTMLElement, opts: { items?: GanttItem[]; table?: TableName; labelField?: string; startField?: string; endField?: string; colorField?: string; where?: Record<string, string | number | boolean>; limit?: number; labelWidth?: number; onClick?: (item: any) => void; tooltip?: (item: any) => string; today?: boolean; storageKey?: string; barLabel?: boolean | ((item: any) => string) }): Promise<Handle>;
  /** Checklist / data-room. items grouped by their group field → folder sections; completion %. */
  export function Checklist(target: string | HTMLElement, opts: { items: { label: string; done?: boolean; required?: boolean; fileUrl?: string; hint?: string; group?: string }[]; title?: string; onToggle?: (item: any, done: boolean) => void; onUpload?: (item: any, file: File) => Promise<string | void> }): { destroy: () => void };

  // ─── Wave 7: forms, inputs & primitives ───────────────────────────
  /** Typeahead select - table (server ?q= search, scales past <select>) or static options. */
  export function Combobox(target: string | HTMLElement, opts: { table?: TableName; options?: ({ value: string; label: string } | string)[]; labelField?: string; value?: string | number; placeholder?: string; where?: Record<string, string | number | boolean>; onChange?: (value: any, row?: any) => void }): Promise<{ readonly value: any; destroy: () => void }>;
  /** Tag-style multi-pick (table or options). */
  export function MultiSelect(target: string | HTMLElement, opts: { table?: TableName; options?: ({ value: string; label: string } | string)[]; value?: (string | number)[]; labelField?: string; placeholder?: string; where?: Record<string, string | number | boolean>; onChange?: (values: any[]) => void }): Promise<{ readonly value: any[]; destroy: () => void }>;
  /** Toggle switch. */
  export function Switch(target: string | HTMLElement, opts?: { checked?: boolean; label?: string; onChange?: (on: boolean) => void }): { readonly checked: boolean; destroy: () => void };
  /** Range slider with value readout. */
  export function Slider(target: string | HTMLElement, opts?: { min?: number; max?: number; step?: number; value?: number; label?: string; onChange?: (v: number) => void }): { readonly value: number; destroy: () => void };
  /** Star rating. */
  export function Rating(target: string | HTMLElement, opts?: { value?: number; max?: number; onChange?: (v: number) => void }): { readonly value: number; destroy: () => void };
  /** Native color picker + hex readout. */
  export function ColorPicker(target: string | HTMLElement, opts?: { value?: string; onChange?: (hex: string) => void }): { readonly value: string; destroy: () => void };
  /** − [n] + numeric stepper. */
  export function NumberStepper(target: string | HTMLElement, opts?: { value?: number; min?: number; max?: number; step?: number; onChange?: (v: number) => void }): { readonly value: number; destroy: () => void };
  /** Floating panel anchored to the target (click/hover). */
  export function Popover(target: string | HTMLElement, opts: { content?: Content; trigger?: 'click' | 'hover' }): { open: () => void; close: () => void; destroy: () => void };
  /** Right-click context menu on the target. */
  export function ContextMenu(target: string | HTMLElement, opts: { items: { label?: string; onClick?: () => void; danger?: boolean; divider?: boolean }[] }): { destroy: () => void };
  /** Image carousel (arrows + dots, optional autoplay + lightbox). */
  export function Carousel(target: string | HTMLElement, opts: { images: { src: string; caption?: string }[]; auto?: number; lightbox?: boolean; height?: string }): { destroy: () => void };
  /** Fullscreen image viewer overlay. */
  export function Lightbox(images: { src: string; caption?: string }[], start?: number): { close: () => void };
  /** Drag-to-reorder list. */
  export function Sortable(target: string | HTMLElement, opts: { items: ({ id: string; label: string } | string)[]; onReorder?: (ids: string[]) => void }): { order: () => string[]; destroy: () => void };
  /** Standalone pagination control. */
  export function Pagination(target: string | HTMLElement, opts: { page: number; perPage: number; total: number; onChange?: (page: number) => void }): { destroy: () => void };
  /** Drag-drop multi-file upload (bm.upload). */
  export function FileDropzone(target: string | HTMLElement, opts?: { onUpload?: (res: any, file: File) => void; multiple?: boolean; accept?: string }): { destroy: () => void };
  /** Keyboard-key badge(s) - returns an HTML string. */
  export function Kbd(keys: string | string[]): string;
  /** Inline SVG sparkline - returns an HTML string. */
  export function Sparkline(values: number[], opts?: { width?: number; height?: number; color?: string }): string;

  // ─── Wave 8: RBAC · security · data ops ────────────────────────────
  /** Read-only roles × scopes grid (GET /api/_auth/roles). */
  export function PermissionMatrix(target: string | HTMLElement, opts?: {}): Promise<{ destroy: () => void }>;
  /** Users + grant/revoke roles (RBAC join-table endpoints). */
  export function TeamManager(target: string | HTMLElement, opts?: {}): Promise<Handle>;
  /** Re-auth confirm before a sensitive action (verifies password). Resolves true if confirmed. */
  export function StepUp(opts?: { title?: string; message?: string }): Promise<boolean>;
  /** Masked field that reveals on click (optionally behind StepUp). The reveal callback supplies the real value. */
  export function SensitiveReveal(target: string | HTMLElement, opts: { label?: string; value?: any; reveal?: () => Promise<any> | any; stepUp?: boolean; stepUpMessage?: string; log?: () => void }): Promise<{ destroy: () => void }>;
  /** Fixed banner shown while acting as another group/user (GET /api/_auth/act_as). */
  export function ImpersonationBanner(target?: string | HTMLElement, opts?: {}): Promise<{ destroy: () => void }>;
  /** Hide the target unless a module is enabled. */
  export function ModuleGate(target: string | HTMLElement, opts: { module: string; enabled: string[] | (() => Promise<string[]>) }): Promise<boolean>;
  /** Export a table (or filtered subset) to a CSV download. */
  export function ExportButton(target: string | HTMLElement, opts: { table: TableName; columns?: string; where?: Record<string, string | number | boolean>; filename?: string; label?: string; limit?: number }): { destroy: () => void };
  /** Toggle which columns are visible (for driving a DataTable). */
  export function ColumnChooser(target: string | HTMLElement, opts: { columns: (string | { name: string; label?: string })[]; value?: string[]; onChange?: (cols: string[]) => void }): { value: () => string[]; destroy: () => void };
  /** Cookie-consent banner (localStorage-backed). */
  export function ConsentManager(opts?: { message?: string; policyUrl?: string; onAccept?: () => void; onDecline?: () => void }): { destroy: () => void };

  // ─── Wave 9: workflow & domain ─────────────────────────────────────
  /** Everything awaiting my decision (/api/_approvals?mine=1) with approve/reject. */
  export function ApprovalInbox(target: string | HTMLElement, opts?: { onDecide?: (id: any, decision: string) => void }): Promise<Handle>;
  /** filter → preview affected → apply (PATCH /api/{table}/batch). */
  export function BulkChangeWizard(target: string | HTMLElement, opts: { table: TableName; filters?: string[]; fields?: string[]; onDone?: (n: number) => void }): Promise<{ destroy: () => void }>;
  /** Review a batch's line items + approve/commit. */
  export function RunReview(target: string | HTMLElement, opts: { table: TableName; where?: Record<string, string | number | boolean>; columns?: string; title?: string; limit?: number; onApprove?: (rows: any[]) => Promise<void> | void }): Promise<{ destroy: () => void }>;
  /** Generic content multi-step wizard. */
  export function Wizard(target: string | HTMLElement, opts: { steps: { title?: string; content?: Content }[]; onFinish?: () => void }): { destroy: () => void };
  /** Vertical stage tracker. */
  export function VerticalStepper(target: string | HTMLElement, opts: { steps: (string | { label: string; detail?: string })[]; current?: number }): { destroy: () => void };
  /** Date-driven items with overdue/soon/ok status. */
  export function ExpirationTracker(target: string | HTMLElement, opts: { table: TableName; dateField: string; labelField?: string; warnDays?: number; where?: Record<string, string | number | boolean> }): Promise<Handle>;
  /** Searchable article browser (markdown body). */
  export function KnowledgeBase(target: string | HTMLElement, opts: { table: TableName; titleField?: string; bodyField?: string }): Promise<{ destroy: () => void }>;
  /** Plans as columns, features as rows (side-by-side compare). */
  export function PlanComparison(target: string | HTMLElement, opts: { plans?: any[]; table?: TableName; where?: Record<string, string | number | boolean>; features?: (string | { key: string; label: string })[]; nameField?: string }): Promise<{ destroy: () => void }>;
  /** Hierarchical table from a self-referential FK. */
  export function TreeTable(target: string | HTMLElement, opts: { table: TableName; parentField?: string; columns?: string; labelField?: string }): Promise<Handle>;
  /** Grid colored by value intensity. */
  export function Heatmap(target: string | HTMLElement, opts: { data: { x: any; y: any; value: number }[]; color?: string }): { destroy: () => void };
  /** Embed a PDF/doc via iframe. */
  export function DocViewer(target: string | HTMLElement, opts: { url: string; height?: string }): { destroy: () => void };
  /** Editable rows×cols spreadsheet with optional live totals. */
  export function EditableMatrix(target: string | HTMLElement, opts: { rows: (string | { key: string; label: string })[]; cols: (string | { key: string; label: string })[]; value?: (rowKey: string, colKey: string) => any; onChange?: (rowKey: string, colKey: string, value: string) => void; cornerLabel?: string; totals?: boolean }): { value: () => Record<string, any>; destroy: () => void };
  /** Week grid scheduler - resources × 7 days; click an empty cell to create. */
  export function Scheduler(target: string | HTMLElement, opts: { resources?: { id: any; label: string }[]; resourceTable?: TableName; shiftTable?: TableName; dateField?: string; resourceField?: string; labelField?: string; weekStart?: string; onCreate?: (resourceId: string, isoDate: string) => void }): Promise<Handle>;
  /** Ticket list + selected ticket's message thread. */
  export function TicketThread(target: string | HTMLElement, opts: { table: TableName; messageTable: TableName; parentField: string; subjectField?: string; statusField?: string; bodyField?: string; where?: Record<string, string | number | boolean> }): Promise<Handle>;
  /** Repeatable subform rows. */
  export function FieldArray(target: string | HTMLElement, opts: { fields: { name: string; label?: string; type?: string }[]; value?: any[]; onChange?: (rows: any[]) => void; addLabel?: string }): { value: () => any[]; destroy: () => void };
  /** File field - current file + upload/replace (bm.upload → url). */
  export function FileField(target: string | HTMLElement, opts?: { value?: string; onChange?: (url: string) => void }): { readonly value: string; destroy: () => void };
  /** Country-code + number phone input → combined string. */
  export function PhoneField(target: string | HTMLElement, opts?: { value?: string; onChange?: (v: string) => void }): { readonly value: string; destroy: () => void };

  const sdui: { schema: typeof schema; ApprovalInbox: typeof ApprovalInbox; BulkChangeWizard: typeof BulkChangeWizard; RunReview: typeof RunReview; Wizard: typeof Wizard; VerticalStepper: typeof VerticalStepper; ExpirationTracker: typeof ExpirationTracker; KnowledgeBase: typeof KnowledgeBase; PlanComparison: typeof PlanComparison; TreeTable: typeof TreeTable; Heatmap: typeof Heatmap; DocViewer: typeof DocViewer; EditableMatrix: typeof EditableMatrix; Scheduler: typeof Scheduler; TicketThread: typeof TicketThread; FieldArray: typeof FieldArray; FileField: typeof FileField; PhoneField: typeof PhoneField; PermissionMatrix: typeof PermissionMatrix; TeamManager: typeof TeamManager; StepUp: typeof StepUp; SensitiveReveal: typeof SensitiveReveal; ImpersonationBanner: typeof ImpersonationBanner; ModuleGate: typeof ModuleGate; ExportButton: typeof ExportButton; ColumnChooser: typeof ColumnChooser; ConsentManager: typeof ConsentManager; GanttChart: typeof GanttChart; Checklist: typeof Checklist; Combobox: typeof Combobox; MultiSelect: typeof MultiSelect; Switch: typeof Switch; Slider: typeof Slider; Rating: typeof Rating; ColorPicker: typeof ColorPicker; NumberStepper: typeof NumberStepper; Popover: typeof Popover; ContextMenu: typeof ContextMenu; Carousel: typeof Carousel; Lightbox: typeof Lightbox; Sortable: typeof Sortable; Pagination: typeof Pagination; FileDropzone: typeof FileDropzone; Kbd: typeof Kbd; Sparkline: typeof Sparkline; query: typeof query; QueryView: typeof QueryView; Report: typeof Report; PivotTable: typeof PivotTable; SavedViews: typeof SavedViews; MultiRelation: typeof MultiRelation; TreeView: typeof TreeView; Reminder: typeof Reminder; ScheduleAction: typeof ScheduleAction; Approval: typeof Approval; Calendar: typeof Calendar; Timeline: typeof Timeline; InlineEdit: typeof InlineEdit; Funnel: typeof Funnel; Import: typeof Import; CustomFields: typeof CustomFields; AppShell: typeof AppShell; Nav: typeof Nav; Breadcrumbs: typeof Breadcrumbs; CommandPalette: typeof CommandPalette; DatePicker: typeof DatePicker; Markdown: typeof Markdown; RichText: typeof RichText; Code: typeof Code; Broadcast: typeof Broadcast; Viewer: typeof Viewer; Stepper: typeof Stepper; FilterBar: typeof FilterBar; KpiTile: typeof KpiTile; Alert: typeof Alert; EmptyState: typeof EmptyState; ConfirmDialog: typeof ConfirmDialog; DiffViewer: typeof DiffViewer; SegmentedControl: typeof SegmentedControl; DateRangePicker: typeof DateRangePicker; Gauge: typeof Gauge; DetailHeader: typeof DetailHeader; SplitLayout: typeof SplitLayout; Map: typeof Map; MoneyInput: typeof MoneyInput; PercentInput: typeof PercentInput; DataTable: typeof DataTable; RecordForm: typeof RecordForm; WizardForm: typeof WizardForm; Detail: typeof Detail; FlowForm: typeof FlowForm; Transitions: typeof Transitions; Gate: typeof Gate; can: typeof can; hasRole: typeof hasRole; Uploader: typeof Uploader; Cards: typeof Cards; Board: typeof Board; Stat: typeof Stat; Chart: typeof Chart; Modal: typeof Modal; Drawer: typeof Drawer; Tabs: typeof Tabs; Accordion: typeof Accordion; Toast: typeof Toast; Dropdown: typeof Dropdown; Tooltip: typeof Tooltip; Badge: typeof Badge; Avatar: typeof Avatar; Spinner: typeof Spinner; Skeleton: typeof Skeleton; ProgressBar: typeof ProgressBar; Login: typeof Login; Signup: typeof Signup; Forgot: typeof Forgot; Reset: typeof Reset; ProfileForm: typeof ProfileForm; MfaSetup: typeof MfaSetup; OAuthConnect: typeof OAuthConnect; SessionManager: typeof SessionManager; ApiTokenManager: typeof ApiTokenManager; ActAs: typeof ActAs; VersionHistory: typeof VersionHistory; AuditLog: typeof AuditLog; RecordLock: typeof RecordLock; ShareDialog: typeof ShareDialog; DownloadMyData: typeof DownloadMyData; SignedImage: typeof SignedImage; PdfButton: typeof PdfButton; MediaGallery: typeof MediaGallery; FlowButton: typeof FlowButton; WorkflowBadge: typeof WorkflowBadge; JobStatus: typeof JobStatus; JobsDashboard: typeof JobsDashboard; NotificationBell: typeof NotificationBell; Presence: typeof Presence; Chat: typeof Chat; CommentThread: typeof CommentThread; ActivityFeed: typeof ActivityFeed; Dashboard: typeof Dashboard; UsageMeter: typeof UsageMeter; WebhookManager: typeof WebhookManager; registerSkin: typeof registerSkin; resetSkin: typeof resetSkin; setAccent: typeof setAccent; clearSchemaCache: typeof clearSchemaCache };
  export default sdui;
}
`)

	return b.String()
}

// writeRoleUnion emits a TS union of all roles the app knows about.
// Framework defaults (user, admin) are always included. Anything from
// app.yaml `roles:` is added on top, deduped + sorted for stability.
func writeRoleUnion(b *strings.Builder, app *App) {
	roles := map[string]bool{"user": true, "admin": true}
	if app.Roles != nil {
		for name := range app.Roles.Roles {
			roles[name] = true
		}
	}
	out := make([]string, 0, len(roles))
	for r := range roles {
		out = append(out, r)
	}
	sort.Strings(out)
	fmt.Fprintf(b, "export type Role = %s;\n", quotedUnion(out))
}

// writeTableInterface emits the TS interface for one table.
func writeTableInterface(b *strings.Builder, t Table) {
	interfaceName := pascalCase(singularize(t.Name))
	fmt.Fprintf(b, "/** Table: %s */\n", t.Name)
	fmt.Fprintf(b, "export interface %s {\n", interfaceName)
	for _, col := range t.Columns {
		// Sensitive cols on _benmore_users specifically are filtered in
		// the User interface, not here; this is the raw table shape.
		optional := ""
		if !col.NotNull && !col.PK {
			optional = "?"
		}
		fmt.Fprintf(b, "  %s%s: %s;\n", col.Name, optional, prismaToTS(col.Type))
	}
	b.WriteString("}\n")
}

// writeUserInterface emits the User shape used by bm.auth.me() and
// bm.users.get() - sensitive columns filtered the same way the runtime
// filters them.
func writeUserInterface(b *strings.Builder, app *App) {
	// Look up the _benmore_users table.
	var userTable *Table
	for i := range app.Tables {
		if app.Tables[i].Name == "_benmore_users" {
			userTable = &app.Tables[i]
			break
		}
	}
	b.WriteString("/** Public-safe user shape returned by bm.auth.me() and bm.users.*().\n")
	b.WriteString(" *  Sensitive columns are filtered by isSensitiveUserColumn at runtime\n")
	b.WriteString(" *  and excluded here so the editor never autocompletes them. */\n")
	b.WriteString("export interface User {\n")
	if userTable != nil {
		for _, col := range userTable.Columns {
			if isSensitiveUserColumn(col.Name) {
				continue
			}
			optional := ""
			if !col.NotNull && !col.PK {
				optional = "?"
			}
			// Special-cased columns:
			//   id   → UserId brand (so MessageId can't be passed where UserId expected)
			//   role → Role union (so r === 'superadmin' is a TS error)
			typeStr := prismaToTS(col.Type)
			if col.PK {
				typeStr = "UserId"
			}
			if col.Name == "role" {
				typeStr = "Role"
			}
			fmt.Fprintf(b, "  %s%s: %s;\n", col.Name, optional, typeStr)
		}
	} else {
		// Fallback when the user table wasn't discovered (app.Tables
		// doesn't always include framework-internal tables - depends on
		// whether LoadSchema introspected them). Use canonical shape.
		b.WriteString("  id: UserId;\n")
		b.WriteString("  email: string;\n")
		b.WriteString("  first_name?: string;\n")
		b.WriteString("  last_name?: string;\n")
		b.WriteString("  username?: string;\n")
		b.WriteString("  phone?: string;\n")
		b.WriteString("  avatar_url?: string;\n")
		b.WriteString("  role: Role;\n")
		b.WriteString("  verified: number;\n")
		b.WriteString("  deactivated_at?: string;\n")
		b.WriteString("  created_at: string;\n")
		b.WriteString("  last_login_at?: string;\n")
	}
	// Multi-role RBAC (v2.7.54+). /api/_auth/profile already returns these
	// alongside the legacy `role`, and bm.auth.me() passes the full payload
	// through - they were just missing from the type. Declared here so
	// policy components (e.g. <Gate perm="...">) can read me().permissions
	// and me().roles with autocomplete instead of casting.
	b.WriteString("  /** Every role the user holds (union across grants + inherits). */\n")
	b.WriteString("  roles: Role[];\n")
	b.WriteString("  /** Legacy primary role (mirror of `role`). */\n")
	b.WriteString("  primary_role: Role;\n")
	b.WriteString("  /** Unioned permission scopes (`resource:action`) across all held roles. */\n")
	b.WriteString("  permissions: string[];\n")
	b.WriteString("}\n")
}

// sortedTables returns the app's tables (minus framework-internal ones
// the agent shouldn't be calling directly) in alphabetical order so
// the generated output is diff-stable.
func sortedTables(app *App) []Table {
	hide := map[string]bool{
		"_benmore_sessions": true, "_benmore_jobs": true, "_benmore_audit_log": true,
		"_benmore_events": true, "_benmore_rate_limits": true, "_benmore_idempotency": true,
		"_benmore_locks": true, "_benmore_versions": true, "_benmore_permissions": true,
		"_benmore_password_resets": true, "_benmore_login_attempts": true,
		"_benmore_notifications": true, "_benmore_webhooks": true,
		"_benmore_devices": true, "_benmore_custom_fields": true,
		"_benmore_usage": true, "_benmore_read_audit": true,
		"_benmore_feedback": true, "_benmore_feedback_comments": true,
		"_benmore_cron_state": true,
		// _benmore_users IS exposed via the User interface (above), so
		// don't double-emit it as a Table.
		"_benmore_users": true,
	}
	out := make([]Table, 0, len(app.Tables))
	for _, t := range app.Tables {
		if hide[t.Name] {
			continue
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// tablesFingerprint is a stable hash of the table list + column shapes
// so a workspace `bm.d.ts` can detect when it drifts from the deployed
// schema. NOT cryptographic - collision-resistant enough for
// "did anything change."
func tablesFingerprint(app *App) string {
	h := sha256.New()
	for _, t := range sortedTables(app) {
		fmt.Fprintf(h, "%s|", t.Name)
		for _, c := range t.Columns {
			fmt.Fprintf(h, "%s:%s:%v:%v;", c.Name, c.Type, c.NotNull, c.PK)
		}
		h.Write([]byte{0})
	}
	// Include user columns in the fingerprint so a User-table change
	// (e.g., new signup_field) also flips it.
	for _, t := range app.Tables {
		if t.Name != "_benmore_users" {
			continue
		}
		for _, c := range t.Columns {
			if isSensitiveUserColumn(c.Name) {
				continue
			}
			fmt.Fprintf(h, "u.%s:%s;", c.Name, c.Type)
		}
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8]) // 16-char hex
}

// prismaToTS maps Prisma/SQLite column types to TypeScript types.
func prismaToTS(prismaType string) string {
	p := strings.ToUpper(strings.TrimSpace(prismaType))
	// Strip array suffix.
	isArray := strings.HasSuffix(p, "[]")
	if isArray {
		p = strings.TrimSuffix(p, "[]")
	}
	var base string
	switch {
	case strings.Contains(p, "INT"), p == "BIGINT", p == "SMALLINT":
		base = "number"
	case p == "REAL", p == "FLOAT", p == "DOUBLE", strings.HasPrefix(p, "DECIMAL"), strings.HasPrefix(p, "NUMERIC"):
		base = "number"
	case p == "BOOL", p == "BOOLEAN":
		base = "boolean"
	case strings.Contains(p, "DATETIME"), strings.Contains(p, "DATE"), strings.Contains(p, "TIME"):
		// SQLite stores datetimes as ISO strings via the framework.
		base = "string"
	case p == "JSON", p == "JSONB":
		base = "Record<string, unknown> | unknown[]"
	default:
		// TEXT, VARCHAR, CHAR, BLOB, anything else → string.
		base = "string"
	}
	if isArray {
		return base + "[]"
	}
	return base
}

// pascalCase converts snake_case → PascalCase for the TS interface name.
func pascalCase(s string) string {
	parts := strings.Split(s, "_")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "")
}

// singularize is a very lazy English singularizer. Good enough for
// table names like `messages` → `message`, `users` → `user`,
// `admin_logs` → `admin_log`. Edge cases (`stories`/`story`) hit
// the irregular list; everything else just drops trailing `s`.
func singularize(s string) string {
	irregular := map[string]string{
		"stories":     "story",
		"categories":  "category",
		"companies":   "company",
		"countries":   "country",
		"properties":  "property",
		"libraries":   "library",
		"queries":     "query",
		"replies":     "reply",
		"activities":  "activity",
		"strategies":  "strategy",
	}
	if v, ok := irregular[s]; ok {
		return v
	}
	// Strip trailing -ies → -y is too aggressive (handled by irregular above).
	// Trim trailing -es for -ses, -xes, -zes, -ches, -shes.
	for _, suf := range []string{"sses", "xes", "zes", "ches", "shes"} {
		if strings.HasSuffix(s, suf) {
			return s[:len(s)-2]
		}
	}
	if strings.HasSuffix(s, "s") && !strings.HasSuffix(s, "ss") {
		return s[:len(s)-1]
	}
	return s
}

// quotedUnion returns `'a' | 'b' | 'c'` for a string slice - the
// canonical TS string-literal union shape.
func quotedUnion(items []string) string {
	if len(items) == 0 {
		return "string"
	}
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = `'` + s + `'`
	}
	return strings.Join(out, " | ")
}

// tsKeyForTable returns the safe key form for a TS interface member
// - `messages` is a bare identifier, but `admin_logs` (snake_case)
// would also be safe; quote anything weird just in case.
func tsKeyForTable(name string) string {
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return `'` + name + `'`
		}
	}
	return name
}

// =========================================================================
//  v2.7.16: Expanded type surface - flows, workflows, aggregates, i18n,
//  per-table conditional methods.
// =========================================================================

// tableFeatureSet captures which optional methods a table exposes.
type tableFeatureSet struct {
	softDelete bool // has `deleted_at` column → .restore() available
	fulltext   bool // has @@fulltext        → list({q}) available
	versioned  bool // versioning enabled    → .versions() / .revertTo() available
}

func computeTableFeatures(t Table, app *App) tableFeatureSet {
	feat := tableFeatureSet{}
	for _, c := range t.Columns {
		if c.Name == "deleted_at" {
			feat.softDelete = true
		}
	}
	if len(t.FullText) > 0 {
		feat.fulltext = true
	}
	// Heuristic for versioning: a sibling _benmore_versions_<table> table.
	for _, t2 := range app.Tables {
		if t2.Name == "_benmore_versions_"+t.Name {
			feat.versioned = true
			break
		}
	}
	return feat
}

// writeTableFeatures emits the TableFeatures interface used to drive
// conditional methods on TableClient.
func writeTableFeatures(b *strings.Builder, tables []Table, app *App) {
	b.WriteString("// Per-table feature flags. Conditional methods on TableClient<Row, F> use these.\n")
	b.WriteString("export interface TableFeatures {\n")
	for _, t := range tables {
		f := computeTableFeatures(t, app)
		fmt.Fprintf(b, "  %s: { softDelete: %v; fulltext: %v; versioned: %v };\n",
			tsKeyForTable(t.Name), f.softDelete, f.fulltext, f.versioned)
	}
	b.WriteString("}\n")
}

// writeAggregatesType emits the AggregateName union + AggregateMap.
func writeAggregatesType(b *strings.Builder, app *App) {
	b.WriteString("// ─── Aggregates (from app.yaml aggregates:) ─────────────────\n")
	configs := LoadAggregateConfig(app.Dir)
	if len(configs) == 0 {
		b.WriteString("export type AggregateName = never;\n")
		b.WriteString("export interface AggregateMap {}\n\n")
		return
	}
	names := make([]string, 0, len(configs))
	for _, c := range configs {
		names = append(names, c.Name)
	}
	sort.Strings(names)
	fmt.Fprintf(b, "export type AggregateName = %s;\n", quotedUnion(names))
	b.WriteString("/** SQL aggregates resolve to a single scalar. */\n")
	b.WriteString("export interface AggregateMap {\n")
	for _, n := range names {
		fmt.Fprintf(b, "  %s: number | string | null;\n", tsKeyForTable(n))
	}
	b.WriteString("}\n\n")
}

// writeWorkflowsType emits the WorkflowMap from workflows.yaml - each
// table gets a typed state union + transition map.
func writeWorkflowsType(b *strings.Builder, app *App) {
	b.WriteString("// ─── Workflows (from workflows.yaml) ────────────────────────\n")
	if app.Workflows == nil || len(app.Workflows.Workflows) == 0 {
		b.WriteString("export interface WorkflowMap {}\n\n")
		return
	}
	b.WriteString("/** State machines keyed by the table they govern. */\n")
	b.WriteString("export interface WorkflowMap {\n")
	tableNames := make([]string, 0, len(app.Workflows.Workflows))
	for tn := range app.Workflows.Workflows {
		tableNames = append(tableNames, tn)
	}
	sort.Strings(tableNames)
	for _, tn := range tableNames {
		wf := app.Workflows.Workflows[tn]
		statesUnion := "string"
		if len(wf.States) > 0 {
			statesUnion = quotedUnion(wf.States)
		}
		fmt.Fprintf(b, "  %s: {\n", tsKeyForTable(tn))
		fmt.Fprintf(b, "    states: %s;\n", statesUnion)
		fmt.Fprintf(b, "    field: %q;\n", wf.Field)
		fmt.Fprintf(b, "    initial: %s;\n", quotedOrString(wf.Initial))
		b.WriteString("    transitions: {\n")
		fromStates := make([]string, 0, len(wf.Transitions))
		for from := range wf.Transitions {
			fromStates = append(fromStates, from)
		}
		sort.Strings(fromStates)
		for _, from := range fromStates {
			tos := wf.Transitions[from]
			toList := make([]string, 0, len(tos))
			for to := range tos {
				toList = append(toList, to)
			}
			sort.Strings(toList)
			toUnion := "never"
			if len(toList) > 0 {
				toUnion = quotedUnion(toList)
			}
			fmt.Fprintf(b, "      %s: %s;\n", quotedOrString(from), toUnion)
		}
		b.WriteString("    };\n")
		b.WriteString("  };\n")
	}
	b.WriteString("}\n\n")
}

// writeFlowsType emits FlowMap - one typed method signature per
// HTTP-triggered flow declared in flows.yaml.
func writeFlowsType(b *strings.Builder, app *App) {
	b.WriteString("// ─── Flows (from flows.yaml) ────────────────────────────────\n")
	httpFlows := []Flow{}
	for _, f := range app.Flows {
		if f.Trigger.Type == "http" || f.Trigger.Type == "" {
			httpFlows = append(httpFlows, f)
		}
	}
	if len(httpFlows) == 0 {
		b.WriteString("export interface FlowMap {}\n\n")
		return
	}
	sort.Slice(httpFlows, func(i, j int) bool { return httpFlows[i].Name < httpFlows[j].Name })
	b.WriteString("/** Custom HTTP flows. Async flows return Job<T>; call .wait() to block. */\n")
	b.WriteString("export interface FlowMap {\n")
	for _, f := range httpFlows {
		method := f.Trigger.Method
		if method == "" {
			method = "POST"
		}
		fmt.Fprintf(b, "  /** %s %s%s */\n", method, f.Trigger.Path, asyncSuffix(f.Async))
		params := extractPathParams(f.Trigger.Path)
		paramsType := "Record<string, never>"
		if len(params) > 0 {
			pairs := make([]string, 0, len(params))
			for _, p := range params {
				pairs = append(pairs, fmt.Sprintf("%s: string | number", p))
			}
			paramsType = "{ " + strings.Join(pairs, "; ") + " }"
		}
		returnType := "unknown"
		if f.Async {
			returnType = "Job<unknown>"
		}
		// Derive the body type from declared inputs: (0b). Without an
		// inputs: block the body stays the loose Record (back-compat).
		bodyParam := "body?: Record<string, unknown>"
		if len(f.Trigger.Inputs) > 0 {
			names := make([]string, 0, len(f.Trigger.Inputs))
			hasRequired := false
			for n, in := range f.Trigger.Inputs {
				names = append(names, n)
				if in.Required {
					hasRequired = true
				}
			}
			sort.Strings(names)
			fields := make([]string, 0, len(names))
			for _, n := range names {
				in := f.Trigger.Inputs[n]
				opt := "?"
				if in.Required {
					opt = ""
				}
				fields = append(fields, fmt.Sprintf("%s%s: %s", n, opt, flowInputTS(in)))
			}
			bodyType := "{ " + strings.Join(fields, "; ") + " }"
			if hasRequired {
				bodyParam = "body: " + bodyType
			} else {
				bodyParam = "body?: " + bodyType
			}
		}
		flowKey := camelCase(f.Name)
		fmt.Fprintf(b, "  %s: (params: %s, %s) => Promise<%s>;\n",
			tsKeyForTable(flowKey), paramsType, bodyParam, returnType)
	}
	b.WriteString("}\n\n")
}

// flowInputTS maps a declared FlowInput type to its TypeScript type for
// the generated bm.flows body signature. Mirrors the control vocabulary
// shared with the schema descriptor.
func flowInputTS(in FlowInput) string {
	switch in.Type {
	case "number":
		return "number"
	case "bool":
		return "boolean"
	case "enum":
		if len(in.Values) > 0 {
			return quotedUnion(in.Values)
		}
		return "string"
	default: // text, textarea, email, date
		return "string"
	}
}

// writeI18nType emits the I18nKey union from translation files.
func writeI18nType(b *strings.Builder, app *App) {
	b.WriteString("// ─── I18n keys (from i18n/*.yaml) ───────────────────────────\n")
	if i18n == nil || len(i18n.Translations) == 0 {
		b.WriteString("export type I18nKey = string;\n\n")
		return
	}
	keys := map[string]bool{}
	for _, dict := range i18n.Translations {
		for k := range dict {
			keys[k] = true
		}
	}
	if len(keys) == 0 {
		b.WriteString("export type I18nKey = string;\n\n")
		return
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	fmt.Fprintf(b, "export type I18nKey = %s;\n\n", quotedUnion(sorted))
}

// writeAncillaryTypes emits small static shapes the SDK uses but
// don't depend on the app's schema (Notification, AuditEntry, Job).
func writeAncillaryTypes(b *strings.Builder) {
	b.WriteString("// ─── SDK ancillary types ───────────────────────────────────\n\n")
	b.WriteString("export interface Notification {\n")
	b.WriteString("  id: number;\n")
	b.WriteString("  user_id: number;\n")
	b.WriteString("  kind: string;\n")
	b.WriteString("  title: string;\n")
	b.WriteString("  body: string;\n")
	b.WriteString("  href?: string;\n")
	b.WriteString("  read: number;\n")
	b.WriteString("  created_at: string;\n")
	b.WriteString("}\n\n")

	b.WriteString("export interface AuditEntry {\n")
	b.WriteString("  id: number;\n")
	b.WriteString("  table: string;\n")
	b.WriteString("  row_id: number;\n")
	b.WriteString("  action: 'insert' | 'update' | 'delete';\n")
	b.WriteString("  user_id: number;\n")
	b.WriteString("  before?: Record<string, unknown>;\n")
	b.WriteString("  after?: Record<string, unknown>;\n")
	b.WriteString("  created_at: string;\n")
	b.WriteString("}\n\n")

	b.WriteString("export interface Job<T = unknown> {\n")
	b.WriteString("  readonly job_id: string;\n")
	b.WriteString("  readonly status_url: string;\n")
	b.WriteString("  status(): Promise<JobStatus<T>>;\n")
	b.WriteString("  /** Polls until completed or failed. Throws on failure. */\n")
	b.WriteString("  wait(opts?: { intervalMs?: number; timeoutMs?: number; statusUrl?: string }): Promise<T>;\n")
	b.WriteString("}\n\n")

	b.WriteString("export interface JobStatus<T = unknown> {\n")
	b.WriteString("  job_id: string;\n")
	b.WriteString("  flow_name: string;\n")
	b.WriteString("  status: 'pending' | 'running' | 'completed' | 'failed';\n")
	b.WriteString("  error?: string;\n")
	b.WriteString("  started_at?: string;\n")
	b.WriteString("  completed_at?: string;\n")
	b.WriteString("  result?: T;\n")
	b.WriteString("}\n\n")
}

// =========================================================================
//  Small helpers used by the new sections
// =========================================================================

func quotedOrString(s string) string {
	if s == "" {
		return "string"
	}
	return "'" + s + "'"
}

func camelCase(s string) string {
	p := pascalCase(s)
	if len(p) == 0 {
		return p
	}
	return strings.ToLower(string([]rune(p)[0])) + p[1:]
}

func asyncSuffix(async bool) string {
	if async {
		return "   (async - returns Job<T>)"
	}
	return ""
}

func extractPathParams(path string) []string {
	out := []string{}
	for _, seg := range strings.Split(path, "/") {
		if strings.HasPrefix(seg, ":") {
			out = append(out, strings.TrimPrefix(seg, ":"))
		}
	}
	return out
}

// RegisterBMTypesRoute serves the generated .d.ts at /_internal/types.d.ts,
// plus a flows.json registry the runtime SDK uses to route bm.flows.<name>
// calls to the right URL.
func RegisterBMTypesRoute(mux *http.ServeMux, app *App) {
	serveTypes := func(w http.ResponseWriter, r *http.Request) {
		// Cloudflare ignores plain Cache-Control: no-store on static-looking
		// paths and applies its own max-age=86400 default. Sending the full
		// no-cache headerset + Pragma + Expires + private makes the edge
		// honor "do not cache" reliably.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "private, no-cache, no-store, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		w.Header().Set("CDN-Cache-Control", "no-store")
		w.Header().Set("Cloudflare-CDN-Cache-Control", "no-store")
		w.Write([]byte(GenerateBMTypes(app)))
	}
	mux.HandleFunc("GET /_internal/types.d.ts", serveTypes)
	mux.HandleFunc("GET /_internal/bm.d.ts", serveTypes)
	// /_internal/flows.json - runtime registry for the bm.flows proxy.
	// Maps flow name → { method, path, async }.
	mux.HandleFunc("GET /_internal/flows.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		entries := make(map[string]map[string]any)
		for _, f := range app.Flows {
			if f.Trigger.Type != "http" && f.Trigger.Type != "" {
				continue
			}
			method := f.Trigger.Method
			if method == "" {
				method = "POST"
			}
			entry := map[string]any{
				"method": method,
				"path":   f.Trigger.Path,
				"async":  f.Async,
			}
			if len(f.Trigger.Inputs) > 0 {
				entry["inputs"] = f.Trigger.Inputs
			}
			entries[camelCase(f.Name)] = entry
		}
		// json.Marshal sorts map string keys → stable output, and handles
		// the nested `inputs` object the old manual fmt.Fprintf (which only
		// emitted method/path/async) could not.
		out, _ := json.Marshal(entries)
		w.Write(out)
	})
}
