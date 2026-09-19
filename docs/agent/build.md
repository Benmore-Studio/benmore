# Build a Benmore app

Benmore turns a **Prisma schema + YAML config + TSX/HTML pages** into a running
web app - one Go binary, no Node, no build step. You write the data model, a
little config, and your frontend; the framework gives you a SQLite-backed REST +
SSE + WebSocket API with auth, RBAC, validation, real-time, and a typed client
SDK, all served from a single process.

> The model, in one line: **Schema in Prisma. Config in YAML. UI in TSX
> (auto-compiled). Server logic (if any) in YAML hooks/flows/cron.**

## Recent

| Feature | Canonical reference |
|---|---|
| Security isolation update: private images, record reverts, live events, credentials and per-app secrets | `api(at:"uploads")`, `versioning`, `realtime`, `auth`, `encryption`, `environments`, `sign` |
| Durable scheduled-flow delegation and automatic legacy-task authorization; blocked tasks expose a reason | `api(at:"scheduling")` |
| Required password replacement for temporary credentials, with protected-data denial and atomic credential revocation | `api(at:"auth")` (`required_password_change`) |
| Framework security hardening: credential limits, tenant/query isolation, transactional hooks, safe fetch caching, scheduled-flow authorization and atomic retries | `api(at:"auth")`, `query`, `batch`, `cache`, `scheduling`, `idempotency` |
| Raw-body inbound verification: Autodesk-compatible HMAC-SHA1 with current/previous-secret rotation, plus path-bound HMAC-SHA256 bearer credentials | `api(at:"verify")` |
| Identity-bound account erasure: app-specific disposition followed by server-only `run: purge_current_user`, with session-only targeting and commit-before-success semantics | `api(at:"auth")` (`account_erasure`) |
| Bulk import: chunked, resumable, all-or-nothing loading of CSV/NDJSON into a table (or an owner-only SQL restore) | `api(at:"import")` |
| Api steps honor `with.timeout` (`570s` or bare seconds, default 30s; step-level `timeout:` wins), and `if:`-gated steps keep timeout/retry/expect_rows/on_error (v2.7.212) | `api(at:"flows")` |
| Agent usage: local Claude/Codex token and provider-reported prompt-cache counters, explicit sync, account opt-out, and strict no-transcript/no-path upload boundary. Uploads send only the tail since the last clean sync; a deleted app is skipped with a warning instead of failing the sync, and a session spanning several apps is coalesced (v2.7.212) | `api(at:"agent-usage")` |
| Stable API reference context: descriptive `benmore api` responses use ETags and replay exact cached bytes on 304; execution calls are never cached | `api(at:"api-reference-cache")` |
| Existing frontends: build Vite/Next static export/CRA externally, copy only generated output into `static/`, and deploy without a Benmore localhost or Node workflow | `api(at:"existing-frontends")` |
| Native CLI install: Homebrew on macOS; checksum-verifying curl installer on Linux/CI; `@benmore/cli` is only a deprecated correction | `api(at:"cli-install")` |
| Scriptable CLI semantics: workspace `.` resolution, dev-aware `open`, and stable usage/auth/not-found/transport exits | `api(at:"cli-contracts")` |
| Empty declarative queries return `{rows: [], count: 0}`, never `rows: null` | `api(at:"query")` |
| Machine discovery: authenticated OpenAPI 3.1 is identical at `/api/_openapi`, `/openapi.json`, and `/api/openapi.json`; public docs are identical at `/llms.txt` and `/.well-known/llms.txt` | `api(at:"machine-discovery")` |
| Browser SDK distribution: native apps keep `import 'bm'`; external frontends import zero-dependency ESM `@benmore/bm`; `benmore types [app] --out PATH` refreshes generated schema declarations | `api(at:"sdk")` |
| Headless CLI auth: `login`/`signup`/`bootstrap` accept token or email/password flags and `BENMORE_*` env vars; env tokens stay ephemeral and non-TTY credential gaps fail immediately | `api(at:"cli-auth")` |
| Reliable agent delivery loop: `benmore hooks` merges Claude Edit/Write validation + push hooks without replacing existing settings; `benmore sync-status --all` checks every pulled app and must be clean before completion. Codex/other agents push explicitly (no claimed automatic Codex hooks). | `api(at:"sync-status")` |
| Server-only `run: delete_upload` removes only this app's private stored references, rejects foreign/public/traversing URLs, and fails loud so active SQLite work rolls back (external bytes are not transactional) | `api(at:"uploads")` |
| Support operators can clear a reviewed email circuit-breaker pause with `benmore email <app-subdomain> resume`; reputation history and suppressions remain intact | `api(at:"email")` |
| `run: sms` flow step + `sms:` hook: text from a flow (`with: { to, body }` → `steps.<id>.outputs.to`) or on a data event (`sms: { to, body }` + `when:`). Both were documented but unimplemented, so apps silently sent nothing; hooks.yaml keys are now allowlisted at write time so an unrecognized key can't be dropped in silence | `api(at:"sms")` |
| `run: transcribe` flow step: local audio→text (ffmpeg + whisper.cpp on the host, no vendor/API key, every edition); `with: { file, model?, language? }` → `steps.<id>.outputs.text`; local-file-first, loud degrade when binaries/model missing | `api(at:"transcribe")` |
| Multiple custom domains per app: `benmore domain <app> <domain>` ADDS a domain (up to 10 per app, e.g. ceo.example.com + vc.example.com on one app); `--verify`/`--remove` target one domain, omit the domain to act on all (v2.7.205) | CLI skill → "Custom domains" |
| Robust Markdown: `bm.markdown(text)` now server-renders via the benmark engine (CommonMark + GFM + syntax highlighting + mermaid + media embeds + wikilinks + front matter), sanitized; `bm.markdownBatch()` + `{{ body \| markdown }}` pipe + `<Markdown>` component | `api(at:"markdown")` |
| Local/remote source safety (`benmore sync-status`, `.benmore/remote.json`, guarded push/pull/deploy/delete) + reusable `feature.yaml` packs including kanban, notify-hub, and foundry starters | `api(at:"sync-status")`, `api(at:"feature-packs")` |
| GitHub sync: one-way mirror of the app's git history to a user-owned GitHub repo/org - OAuth connect in dashboard → Version Control, auto-push on every commit (Live → main, Sandbox → dev) (v2.7.202) | `api(at:"github")` |
| `benmore deploy <dir>`: first-deploy uses a bare scaffold (no Notes demo merged into your app) + per-file push failures are reported while the rest still ship (v2.7.201) | - |
| Managed social login (zero-setup Google/Microsoft), Stripe Connect (per-env keys), managed DNS zones (v2.7.200) | `api(at:"oauth")`, `api(at:"payments")`, `api(at:"dns")` |
| Platform SMS service: zero-config transactional SMS + dedicated per-app numbers (v2.7.199) | `api(at:"sms")` |
| Platform email service: zero-config sending for every hosted app + BYO domain (DKIM), quotas, suppression, auto-pause (v2.7.197) | `api(at:"email")` |
| browser_check: viewport `width`/`height` args, overlay-proof trusted clicks (chrome hidden + targets centered), `deadline_exceeded` flag + no share links for incomplete runs (v2.7.195) | - |
| browser_check: native `fill`/`select` setters dispatch + verify `input`/`change`, empty values are valid, and all actions preflight before any mutation; see `api(at:"browser_check")` | - |
| Env-safe encryption: platform `sql` reads/writes use the tenant's own key, ENCRYPTION_KEY auto-pinned at provision, decrypt failures masked (never raw ciphertext); promote backup-preflight + `delete-file --env` + 48KB probe bodies (v2.7.194) | `api(at:"encryption")` |
| Tiered row access `read: owner_or_role:<roles>` (owner OR role-holder sees the row) | `api(at:"access")` |
| Per-flow `rate_limit: "5/hour per ip"` (429 + Retry-After) + `expect_rows:`/`rows_affected` (fail loud on guarded 0-row writes) | `api(at:"flows")` |
| `mode: async` flows: `respond:`/`redirect:` are no-ops in the worker (warned by `benmore check`) | `api(at:"async-flows")` |
| `benmore status`/`diff` (dev↔prod drift) + `benmore doctor` (release-readiness PASS/WARN) - CLI pre-flight before promote/publish | - |
| Enterprise hardening: idempotent async job replay, framework/cloud serve validators, `benmore test`, transactional migrations, `DB_SYNCHRONOUS=FULL|EXTRA`, and platform WAL shipping/PITR (`BENMORE_WAL_SHIP=1`, `benmore restore --pitr --as-of`) | `api(at:"async-flows")`, `api(at:"environments")` |

## Quickstart

Install the hosted CLI with Homebrew on macOS:

```bash
brew install Benmore-Studio/benmore/benmore-cli
```

On Linux or CI, use the checksum-verifying installer instead:

```bash
curl -fsSL https://benmore.ai/install-cli.sh | sh
```

Then create a live app:

```bash
benmore login
# Headless alternative:
# benmore login --email "$BENMORE_EMAIL" --password "$BENMORE_PASSWORD"

cd ~/Benmore
benmore new crm          # creates ./crm and prints its resolved directory
cd ./crm
benmore deploy
benmore open .           # prints the provisioned development URL
```

Open the printed HTTPS URL. A reachable live page is the quickstart success
criterion. `benmore new crm` always creates `./crm`; it never silently moves the
project into another directory. The cloud workflow does not use a localhost
development server: edits ship with `benmore push` (normally through the save
hook) and are verified through deployed app routes.

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
  const ui = bm.createStore({ filter: 'all' });
  const grouped = await bm.query.read({
    table: 'posts',
    group_by: ['status'],
    aggregates: [{ fn: 'count', as: 'n' }],
  });

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
| `bm.createStore(initial, {persist?})` | Selector subscriptions, reset, unsubscribe, optional versioned cache persistence |
| `bm.query.{fetch, read, table, subscribe, invalidate, mutate}` | Keyed read cache, dedupe, stale time, table live invalidation, optimistic rollback |
| `bm.presence(slug)` | Heartbeat + cleanup + server sweep |
| `bm.cache.namespaced(n, v)` / `.persistent(n, v)` | Self-busting client cache |
| `bm.markdown(text)` / `bm.markdownBatch(items)` | Server-rendered, sanitized CommonMark + GFM via benmark; batch rendering avoids one request per item |
| `bm.permissions.{share, revoke, list}` | Per-row ACLs |
| `bm.signedUrl(path, ttl)` · `bm.audit.list(f)` · `bm.t(key, vars)` · `bm.mfa.{enroll,verify,disable}` | Signed URLs · audit · i18n · TOTP |
| `bm.api.{get, post, patch, delete}` | Raw escape hatch |

`src/bm.d.ts` is generated from your schema/config. The running app serves the
live types at `/_internal/bm.d.ts` - refresh your local copy any time with
`benmore types [app] --out src/bm.d.ts --env dev`. Inside the app workspace,
omit `[app]`; the `.benmore/app` marker selects the deployment.

Native apps keep `import bm from 'bm'` so the import map and generated local
types work offline. Frontends built outside Benmore import the same runtime from
the zero-dependency ESM package: `import bm from '@benmore/bm'`.

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

## Deploy an existing frontend

Keep the framework build in its original project. Run its normal production build
there, then copy **only the generated browser files** into the Benmore app's
`static/` directory:

```bash
# Vite: set `base: "/"` in vite.config, then build externally.
cp -R /path/to/vite-project/dist/. ~/Benmore/crm/static/

# Next.js: set `output: "export"` (and `images: {unoptimized: true}` when needed).
cp -R /path/to/next-project/out/. ~/Benmore/crm/static/

# Create React App
cp -R /path/to/cra-project/build/. ~/Benmore/crm/static/

cd ~/Benmore/crm
benmore deploy
benmore open .
```

Never copy `node_modules`, `package.json`, lockfiles, or framework source/config
into the Benmore app. There is no Benmore localhost development mode and no Node
build inside the hosted app.

The contents of `static/` are also served from the URL root, so generated
root-relative paths such as `/assets/app.js` resolve to
`static/assets/app.js`. Unknown browser navigation routes fall back to
`static/index.html`, which preserves client-side routing. Asset-looking misses
such as `/assets/missing.js`, `.css`, or `.png` return real 404s instead of the SPA
shell. Full contract: `api(at:"existing-frontends")`.

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
  `anon`, `everyone`, `self`, `group`, `admin`, `role:a,b` (any-of),
  `perm:<resource>.<action>`, or `member-of:<table>(<join_col>,<user_col>)`
  (v2.7.164 - "visible to members of this room/channel/project" via a
  membership table; the framework emits the EXISTS guard on every read/write
  path, auto-joins the creator on parent creates). Multi-role RBAC with
  inheritance and optional per-group (tenant) scoping is supported.
- **Multi-tenant founding moment** - `groups.bootstrap: {org_table: companies,
  founding_role: company_admin}` enables `POST /api/_groups/create` (org +
  founding membership in one transaction); `groups.role_field: member_role`
  loads the member's in-tenant role into the session so `role:company_admin`
  access modes enforce tenant roles (v2.7.164).
- **WS room authorization** - `ws_rooms: {"room-:id": room_members(room_id,
  member_id)}` in app.yaml gates WebSocket `join` on a membership row
  (v2.7.164); undeclared rooms behave as before.
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

1. Edit `static/*.tsx`, `schema.prisma`, `app.yaml`, or `flows/*` in the local
   workspace cache; the save hook normally sends each change with
   `benmore push`.
2. Exercise the deployed development app with `benmore probe`,
   `benmore tool browser_check`, or its HTTPS URL.
3. Run `benmore verify --quick` while iterating, then `benmore verify --release`
   before publishing.
4. Inspect remote behavior with `benmore logs`, `benmore tail`, and
   `benmore sync-status`; do not infer success from a push exit code alone.

There is no localhost development server in the hosted v2.7+ workflow.

## Dev/prod environments (hosted)

On a dev/prod-enabled host, a new app is born as its **dev** instance at
`<sub>-dev.benmore.ai` (its own `data.db`); `benmore push` / edits land there.
When it's ready, `benmore promote <app>` ships the **code** dev→prod (never
data/secrets/uploads) and publishes at `<sub>.benmore.ai`. An existing prod app
gets a dev instance with `benmore seed-dev <app>` (prod, incl. any custom
domain, keeps serving). Target prod explicitly with `--env prod` on
`logs`/`sql`/`tail`/`restart`. Full reference: `api(at:"environments")`.

## Source sync and feature packs (hosted)

Hosted workspaces are local caches of deployed source. `benmore pull <app>`
writes `.benmore/remote.json`, a last-known deployed manifest. Before pushing
or deleting code, run:

```bash
benmore sync-status [dir] [--app NAME] [--env dev|prod] [--json]
```

Exit codes are part of the contract: `0` clean, `1` non-conflicting drift, `2`
conflict, `3` setup/auth/remote error. `push`, `delete-file`, `deploy`, `pull`,
and `sync` block stale/conflicting overwrites by default; `--force` is the
explicit bypass. Manifests exclude data, uploads, env values, `.git`,
`.benmore`, logs, and generated `src/bm.d.ts`.

Feature packs are the clone mechanism for reusable app pieces:

```bash
benmore feature list
benmore clone notify-hub --app target-app --env dev --dry-run
benmore clone notify-hub --app target-app --env dev --apply
benmore feature clone foundry --app target-app --env dev --dry-run

# Clone selected components straight from another app or app directory.
benmore clone source-app target-app \
  --paths static/page.tsx,flows/send.yaml \
  --models Notification,NotificationPreference \
  --flows send_notification \
  --env dev --dry-run

# Avoid route/model collisions when installing into a mature target app.
benmore clone notify-hub --app target-app --env dev \
  --route-prefix ops --model-prefix Ops --dry-run
benmore clone notify-hub --app target-app --env dev \
  --route-map /notify-hub=/alerts \
  --model-map Notification=AlertNotification --dry-run

# Clone a whole app over a target. Dry-run first; apply is explicit.
benmore clone source-app target-app --env dev --replace --delete-missing --dry-run
benmore clone source-app target-app --env dev --replace --delete-missing --apply
```

Curated packs include `kanban`, `notify-hub`, and `foundry`. Export lets you
pick specific files, models, and flows from an existing Benmore app, and
`benmore clone` can do that export+install in one dry-run. Install is dry-run by
default for remote apps, additive-only for schema, blocks file/model collisions
unless `--replace` is supplied, reports env var names without copying values, and
snapshots the destination git history before apply. Use `--delete-missing` only
with `--replace` when intentionally cloning a whole app over the target source.
Use `--route-prefix` and `--model-prefix` for broad component installs into apps
that already have matching route files or Prisma model names; use
`--route-map FROM=TO` and `--model-map Old=New` for exact collision rewrites when
a global prefix is too broad. Transformed installs are not allowed with
`--delete-missing`. Route prefixes move static files, rename `flows/*.yaml`
files, and rewrite known custom API route strings; exact route maps rewrite
static route files, single-route flow files, and route strings. Model prefixes
and exact model maps rewrite Prisma model names plus inferred table-name tokens
in text files/flows. Installed `static/*.tsx` files are feature modules: import
or link them from the existing app shell, or add a host `static/*.html` page, when
you want a clean navigable route. Feature install does not rewrite the target
app's nav automatically.
Pack installs are bounded before apply: decoded archive max 64 MiB,
uncompressed source max 128 MiB, per-entry max 64 MiB, `feature.yaml` max
1 MiB, and max 2000 archive entries.
