# Build a Benmore app

Benmore turns a **Prisma schema + YAML config + TSX/HTML pages** into a running
web app - one Go binary, no Node, no build step. You write the data model, a
little config, and your frontend; the framework gives you a SQLite-backed REST +
SSE + WebSocket API with auth, RBAC, validation, real-time, and a typed client
SDK, all served from a single process.

> The model, in one line: **Schema in Prisma. Config in YAML. UI in TSX
> (auto-compiled). Server logic (if any) in YAML hooks/flows/cron.**

## Quickstart

```bash
go build -tags sqlite_fts5 -o benmore .

./benmore new myapp              # scaffold a runnable TSX app
./benmore serve myapp --port 8080
# open http://localhost:8080
```

`benmore new` writes a complete starter app (see the tree below). `benmore
serve` loads it, applies migrations, compiles your TSX on the fly, and serves
the whole thing. Edit a file, refresh the browser - that's the loop.

## The agentic build loop (how to work)

Don't just write files and stop. Work in this loop until the app genuinely
**works and looks right**:

1. **Understand & plan.** Read the request. For an existing app, orient first:
   `list_files`, `get_app_map`/`describe`, `list_tables`. Decide the schema,
   pages, and any server logic before writing.
2. **Build in small, composed files.** Schema in `schema.prisma`, config in
   `app.yaml`, UI split into focused modules (`static/components/*.tsx`,
   `static/lib/*.ts`) imported into a thin `app.tsx`. esbuild bundles the import
   graph - never grow one giant file (it's slower + riskier to write and edit).
   Prefer `edit_file` on the small module that owns a thing over rewriting.
3. **Verify quickly (fast pass, not a test suite).** `check_app` (schema/config),
   `probe_route` the main routes + APIs (404 = route/file missing), `sql` to
   confirm data shape. Use `as:<email>` for auth-gated routes (`create_superuser`
   first). If a page looks broken or the user reports an issue, `get_client_errors`
   gives the real browser stack trace. Fix what you find and move on - favor a
   fast, responsive loop with the user over an exhaustive QA pass.
4. **Diagnose with tools, don't guess.** A 404 on `/api/<table>` means the table
   name is wrong or didn't migrate (`list_tables`), not that the feature is
   missing. Auto-CRUD already filters/scopes/paginates - don't hand-roll a flow
   to replace it. Read `api(at:<topic>)` before assuming the framework can't do
   something. Never debug by spraying `console.log` or telling the user to
   hard-refresh.

"The file is written" is not "it works." You're done when steps 3-5 pass.

## What an app looks like

```
myapp/
├── app.yaml          # config: theme, auth, features, access, roles, aggregates
├── schema.prisma     # data model → compiled to SQLite + migrations
├── tsconfig.json     # maps the `bm` import to ./src/bm.d.ts
├── src/
│   └── bm.d.ts       # generated per-app TypeScript types (do not hand-edit)
├── static/           # YOUR frontend lives here
│   ├── index.html    # served at /   (framework injects importmap + CSRF meta)
│   ├── login.html    # served at /login (clean-URL routing)
│   ├── signup.html
│   ├── app.tsx       # entry - compiled on the fly → /static/app.js
│   └── styles.css
├── flows.yaml or flows/*.yaml   # optional: custom HTTP routes
├── hooks.yaml        # optional: after-CRUD side effects
├── workflows.yaml    # optional: state machines
├── cron.yaml         # optional: scheduled jobs
├── emails/*.html     # optional: email templates
├── i18n/<lang>.yaml  # optional: translations
├── env.yaml          # secrets (gitignored)
└── data.db           # SQLite, auto-created on first serve
```

## What the framework adds at serve time

1. **Clean URL routing.** `/contacts` → `static/contacts.html`,
   `/settings/profile` → `static/settings/profile.html`, `/` →
   `static/index.html`. Unknown non-asset routes fall back to `index.html`
   (so a client router can take over); asset-looking paths 404 normally.

2. **On-the-fly TSX compilation.** A request for `/static/foo.js` compiles
   `static/foo.tsx` (or `.ts`/`.jsx`) via embedded esbuild (`bundle`, `esm`,
   `target es2020`, `bm` external) and serves the ES module. Cached by mtime,
   ~10ms recompile. A compile error emits a module that throws on load with a
   clear console message, so the page still boots.

3. **CSRF auto-injection.** Every served `.html` gets a
   `<meta name="csrf-token">` and a hidden `_csrf` input in native POST forms.
   The SDK reads the meta tag automatically. Bearer-auth requests are exempt.

4. **Import-map injection.** Every `.html` gets
   `<script type="importmap">{"imports":{"bm":"/_internal/bm.js"}}</script>`
   so `import bm from 'bm'` resolves to the framework SDK at runtime.

5. **Auto cache-busting.** `<script src="/static/x.js">` / `<link
   href="/static/x.css">` references are rewritten to `?v=<mtime>` so a changed
   file is never served stale. Don't add your own `?v=` - it blocks the
   auto-bust.

## `schema.prisma` - the data model

Standard Prisma, compiled to SQLite with migrations applied automatically on
`serve`. Every model is exposed at `/api/<table>` with full CRUD.

```prisma
model Note {
  id        Int      @id @default(autoincrement())
  title     String
  body      String   @default("")
  userId    Int      @map("user_id")
  createdAt DateTime @default(now()) @map("created_at")
  updatedAt DateTime @default(now()) @updatedAt @map("updated_at")

  @@index([userId, updatedAt])
  @@fulltext([title, body])   // optional - enables /api/notes/search?q=...
}
```

Conventions: snake_case columns in SQL, camelCase in Prisma via `@map`. Include
`userId` on owner-scoped tables and `createdAt`/`updatedAt` timestamps. The
framework fills `user_id` from the session - never accept it from the client.

**UUID primary keys:** declare `id String @id @default(uuid())`. The framework
generates the UUID server-side, returns it from POST, and makes referencing
foreign keys TEXT automatically. Use UUIDs for ids exposed in shareable links or
where sequential ids would leak counts / invite enumeration; otherwise prefer
INTEGER. Access scoping (owner/group) is the real authorization control - a UUID
is unguessability, not authorization.

## `app.yaml` - configuration

```yaml
site_name: "My App"
theme: zinc
mode: dark

auth:
  identifier: email           # email | phone | username
  session_duration: "30d"
  signup_fields: "first_name"

features:
  testing: true               # in-app visitor-feedback widget

frontend:
  stack: html                 # html (TSX, default) | gotmpl (SSR for SEO pages)
```

Other keys: `brand`, `font`, `seo.{description,url,favicon}`,
`auth.{otp,domain,redirect,require_verified,verify_email,oauth.<provider>,mfa}`,
`roles.<name>.scopes`, `features.{admin,sse,ws,ws_anonymous,analytics}`,
`groups.{table,key,user_field}` (multi-tenant isolation),
`pwa.{name,icon,offline}`, `backup.{interval,keep}`,
`aggregates.<name>.{sql,refresh}`, `access.<table>.{read,write,update,delete}`,
`auto_memberships.<parent>.{table,parent,members}`.

## The frontend - `static/app.tsx` and the `bm` SDK

The scaffold's `app.tsx` does the full loop with the typed `bm` SDK. The SDK is
a thin declarative wrapper over the REST/SSE/WS surface, not a framework.

```tsx
import bm, { type User, type Post, type ChangeEvent } from 'bm';

async function boot() {
  const me: User | null = await bm.auth.me();   // null if signed out
  if (!me) { location.href = '/login.html'; return; }

  // Strongly typed CRUD - bm.table('typo') is a compile error. Per-table
  // feature flags drive conditional methods (.list({q}) on @@fulltext tables,
  // .restore() on soft-delete tables, .versions() on versioned tables).
  const posts: Post[] = await bm.table('posts').list({ limit: 50 });

  // SSE invalidation. ChangeEvent<T> narrows ev.row by ev.action.
  // SSE is opportunistic - always refetch after your OWN mutations too.
  // FLICKER WARNING: in refresh(), don't do "ul.innerHTML = rows.map(...)" -
  // that rebuilds every row on each event (the whole list flashes, focus is
  // lost, icons re-init). Use the scaffold's reconcileList (static/lib/dom.ts),
  // which reuses unchanged rows and only touches what changed.
  bm.live('posts', (ev: ChangeEvent<Post>) => refresh());

  await bm.flows.publishPost({ id: posts[0].id as number });  // custom flow
  const total = await bm.aggregate('total_posts');            // materialized agg

  const room = bm.room('lobby');                              // WS room
  room.on('hello', (payload, from) => console.log('peer', from));
  room.send({ kind: 'hello' });
}
boot();
```

**Build in small, composed files from the start - don't grow one giant
`app.tsx`.** esbuild bundles the whole import graph, so split UI into focused
modules (`static/components/Sheet.tsx`, `static/lib/api.ts`) and import them:
`import { Sheet } from './components/Sheet'` (relative imports resolve `.tsx`/
`.ts` and are bundled into `app.js`; `bm` stays the bare SDK import). Keep each
file focused (~300 lines max); `app.tsx` is a thin entry (imports + wiring +
mount). This isn't just tidiness: a monolith is one multi-minute `write_file`
that can hit the output cap mid-file, and edits into a huge file mismatch far
more than into a small module. Edit the small module that owns a thing, not the
monolith.

Core SDK surface:

| Method | Notes |
|---|---|
| `bm.auth.{me, signIn, signUp, signOut, refreshMe}` | Session lifecycle |
| `bm.table(name).{list, get, create, update, delete}` | Strongly typed CRUD |
| `bm.table(...).{restore, list({q}), versions, revertTo}` | Conditional on table features |
| `bm.table(name).count(opts?)` | True row count (list defaults to a 50-row cap) |
| `bm.live(table, cb)` / `bm.live.scoped(table, fn, opts)` | SSE, refetch-safe variant |
| `bm.room(name)` | WS room broadcast (chat / presence / signaling) |
| `bm.broadcast.{publish, subscribe, stop}` | SFU livestream (1:N) |
| `bm.webrtc.iceServers()` | STUN/TURN config for peer-mesh |
| `bm.flows.<name>(params, body)` | One typed method per HTTP flow |
| `bm.workflow(table, id).{transitionTo, available, current}` | State machine |
| `bm.aggregate(name)` / `bm.aggregates.all()` | Materialized aggregates |
| `bm.jobs.{status, wait}` | Async-flow polling |
| `bm.notifications.{list, markRead, markAllRead, onNew}` | In-app inbox |
| `bm.upload(file, opts)` | Multipart upload → `{path}` |
| `bm.api.optimistic({apply, request, snapshot, revert})` | Optimistic mutation + reconcile |
| `bm.presence(slug)` | Heartbeat + cleanup + server sweep |
| `bm.cache.namespaced(n, v)` / `.persistent(n, v)` | Self-busting client cache |
| `bm.markdown(text)` | Tiny safe Markdown → HTML |
| `bm.permissions.{share, revoke, list}` | Per-row ACLs |
| `bm.signedUrl(path, ttl)` · `bm.audit.list(f)` · `bm.t(key, vars)` · `bm.mfa.{enroll,verify,disable}` | Signed URLs · audit · i18n · TOTP |
| `bm.api.{get, post, patch, delete}` | Raw escape hatch |

`src/bm.d.ts` is generated from your schema/config. The running app serves the
live types at `/_internal/bm.d.ts` - refresh your local copy any time with
`curl http://localhost:8080/_internal/bm.d.ts > src/bm.d.ts`.

Auto-served libraries (drop-in `<script>` tags, served from the binary, no CDN):
Tailwind, HTMX, Alpine, Chart.js, Mermaid, Lucide at `/_internal/*`.

**Icons: default to Lucide** (`/_internal/lucide.js`) - use `<i data-lucide="name"></i>`
and call `lucide.createIcons()` after rendering. Use it unless the user asks for a
different icon set. Gotcha: `createIcons()` swaps the `<i>` for an `<svg>`, so a
click handler bound to the `<i>` is lost - put the handler on the parent button
(icon `pointer-events:none`) or inline the SVG.

**Inputs (a recurring failure):** Tailwind's preflight strips native input
styling, so EVERY text input/textarea/select needs an explicit bg + text color +
border + placeholder - e.g. `class="w-full px-3 py-2 rounded-md border
border-zinc-300 bg-white text-zinc-900 placeholder-zinc-400"`. A bg without a
matching text color = invisible white-on-white. Never ship a bare `<input>`; reuse
the `Input`/`Field` primitives in `components/ui.tsx`.

**Theme determinism:** Tailwind's `dark:` variant keys off the viewer's OS
(`prefers-color-scheme`), NOT `app.yaml mode`. A dark-designed app built with light
base colors + `dark:` overrides looks broken (white-on-white) on a light OS. Pick
one theme and set its colors as the BASE classes (a dark app uses `bg-zinc-950
text-zinc-100` directly, not `dark:`), so everyone sees the intended design.

## Auto-CRUD - what you get for free

For every table:

| Method | Path | What it does |
|--------|------|------|
| GET | `/api/<table>` | List (auto-scoped to the caller) |
| GET | `/api/<table>/{id}` | Single row |
| POST | `/api/<table>` | Create (`user_id` auto-set); returns the full inserted row |
| PATCH | `/api/<table>/{id}` | Partial update |
| DELETE | `/api/<table>/{id}` | Delete (soft if a `deleted_at` column exists) |
| POST/PATCH/DELETE | `/api/<table>/batch` | Bulk operations |
| POST | `/api/<table>/ingest` | NDJSON streaming ingest (rate-limited) |
| GET | `/api/<table>/search?q=...` | FTS5 search (needs `@@fulltext`) |

List query params: `?orderBy=col:desc&limit=N&page=N&per_page=N&cursor=X&where[col]=val&where[col__gt]=val&q=keyword&count=true&as_of=<iso>&include=<rel>`.
`?count=true` returns `{count: N}` (true total, ignores the cap). Mutations
require `X-CSRF-Token` for cookie sessions; Bearer-auth requests don't.

Protected fields (`user_id`, `role`, `password_hash`, `created_at`,
`updated_at`) are **stripped from any client body** - the server sets them.
Dropped fields are listed in the `X-Stripped-Fields` response header.

## Auth, access & server logic

- **Auth** - `bm.auth.me()` gates the client; the `access:` block (and
  `roles:`) in `app.yaml` gates the server. Sessions are cookie-based for web
  and Bearer-token for API/native clients. MFA (TOTP), OAuth, password reset,
  and email verification are built in.
- **Access modes** - per table in `app.yaml`: `read/write/update/delete` set to
  `public`, `anon`, `self`, `admin`, `role:a,b` (any-of), or
  `perm:<resource>.<action>`. Multi-role RBAC with inheritance and optional
  per-group (tenant) scoping is supported.
- **Hooks** (`hooks.yaml`) - `before_*` (sync, can abort a mutation) and `on_*`
  (async side effects: SQL, webhook, email, notify) on insert/update/delete.
- **Flows** (`flows.yaml` / `flows/*.yaml`) - custom HTTP routes as a sequence
  of steps (sql / api / parse / compute / respond …). `on:` and `jobs:` are
  file-level keys. `mode: async` enqueues a job and returns a status URL.
  `run: compute` runs sandboxed server-side JS for logic that doesn't fit SQL.
  Numeric-looking `:params` bind as numbers (v2.7.162+), so SQL guards like
  `WHERE :amt >= (SELECT SUM(...))` compare numerically - no CAST needed.
- **Workflows** (`workflows.yaml`) - state machines with role guards, timeouts,
  and transition hooks.
- **Real-time** - SSE at `/sse/events` (named `change` events; payload is
  `{table, action}`, refetch the row), WebSocket at `/ws`. SSE is opportunistic;
  always refetch after your own writes.

Run `benmore docs <topic>` for any of the above in more depth.

## The dev loop

1. `benmore serve myapp --port 8080` - boots the app (migrations applied,
   schema/types regenerated).
2. Edit `static/*.tsx`, `schema.prisma`, `app.yaml`, `flows/*` - refresh the
   browser (TSX recompiles on request; restart `serve` after schema/config
   changes so migrations + type regen run).
3. Exercise the API directly: `curl http://localhost:8080/api/<table>`.
4. The framework captures client JS errors and logs server activity to stdout.

That's the whole loop: scaffold, serve, edit, refresh.

## Dev/prod environments (hosted)

On a dev/prod-enabled host, a new app is born as its **dev** instance at
`<sub>-dev.benmore.ai` (its own `data.db`); `benmore push` / edits land there.
When it's ready, `benmore promote <app>` ships the **code** dev→prod (never
data/secrets/uploads) and publishes at `<sub>.benmore.ai`. An existing prod app
gets a dev instance with `benmore seed-dev <app>` (prod, incl. any custom
domain, keeps serving). Target prod explicitly with `--env prod` on
`logs`/`sql`/`tail`/`restart`. Full reference: `api(at:"environments")`.
