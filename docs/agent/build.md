# Build a Benmore app

Benmore turns a **Prisma schema + YAML config + TSX/HTML pages** into a running
web app - one Go binary, no Node, no build step. You write the data model, a
little config, and your frontend; the framework gives you a SQLite-backed REST +
SSE + WebSocket API with auth, RBAC, validation, real-time, and a typed client
SDK, all served from a single process.

> The model, in one line: **Schema in Prisma. Config in YAML. UI in TSX
> (auto-compiled). Server logic (if any) in YAML hooks/flows/cron.**

Read `benmore docs harness` first: identity, environment selection, the
lifecycle state tables, Codex/Claude setup, explicit pushes and verification.
This guide ships inside the CLI that prints it: `benmore version` names that CLI,
and a deployed app's `/health` (`version`) names the runtime.
`benmore docs changes` lists behavior changes by release, each with its topic.
`benmore help <command>` prints the flags the installed CLI accepts.

Hosted commands in this guide require the cloud or platform edition. Framework-only
operators use their generated app AGENTS.md, bundled guides, and authenticated
runtime OpenAPI; hosted account, push, skill, and MCP API commands are separate.

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
# Headless: set BENMORE_TOKEN in the environment (no login needed), or
# printf '%s\n' "$BENMORE_TOKEN" | benmore login --token-stdin

cd ~/Benmore
benmore new crm          # creates ./crm and prints its resolved directory
cd ./crm
benmore deploy
benmore open .           # prints the provisioned development URL
```

Open the printed HTTPS URL. A reachable live page is the quickstart success
criterion. `benmore new crm` always creates `./crm`; it never silently moves the
project into another directory. The cloud workflow does not use a localhost
development server: edits ship with explicit `benmore push` or a verified installed Claude
Edit/Write hook and are verified through deployed app routes.

## The agentic build loop (how to work)

Work in this loop until the app works and looks right; "the file is written" is
not "it works". CLI first, MCP tool in brackets.

1. **Orient.** `benmore sync-status . --json` (exit 0), `benmore api <app> '*'`,
   `benmore describe <app> tables` [`get_app_map`, `list_tables`]. Decide the
   schema, pages, server logic and the states each record moves through before
   writing.
2. **Build in small files.** Schema in `schema.prisma`, config in `app.yaml`,
   record lifecycles in `workflows.yaml`, UI in focused modules
   (`static/components/*.tsx`, `static/lib/*.ts`) imported by a thin `app.tsx`.
   Edit the module that owns a thing instead of rewriting a large file.
3. **Verify fast.** `benmore check <app>` [`check_app`], `benmore probe <app> GET
   /path` [`probe_route`] for the main routes (`--as <email>` for signed-in
   routes; create the user with `benmore users <app> create`), `benmore sql`
   [`sql`] for data shape, `benmore errors <app>` [`get_errors`] for grouped
   browser and server errors (scrubbed samples, breadcrumbs, request ids;
   `--source client` for the browser only). Fix what you find and keep the
   loop short.
4. **Diagnose, don't guess.** A 404 on `/api/<table>` means a wrong table name or
   a model that did not migrate (`benmore describe <app> tables`), not a missing
   feature. Auto-CRUD already filters, scopes and paginates; don't hand-roll a
   flow to replace it. Search the reference (`benmore api <app> --search
   "<words>"`, below) before deciding the framework can't do something. When
   an answer names a documentation address, fetch it before trying again.
   Never debug by spraying `console.log` or telling the user to hard-refresh.

## Look it up: search, index, key

Never guess a contract (a YAML key, a column, a response envelope, an auth
rule): look it up. The reference is large, so read one piece at a time (MCP
form in brackets):

1. **Search.** `benmore api <app> --search "<words>"` [`api(search:"<words>")`]
   returns up to ten addresses, each with a one-line description and a size.
2. **Index.** `benmore api <app> <topic>` [`api(at:"<topic>")`] returns a small
   topic whole and a large one as an index of its keys with sizes;
   `benmore api <app> index` [`api(at:"index")`] lists every topic.
3. **Key.** `benmore api <app> <topic>.<key>` [`api(at:"<topic>.<key>")`]
   returns one key. `--full` [`full:true`] returns a whole large topic; the
   largest are over 100 KB, so ask only when you need all of it.

The CLI carries the same reference, so the three steps also work offline and
without an app: `benmore docs --search "<words>"`, `benmore docs <topic>`,
`benmore docs <topic>.<key>` and `benmore docs index` (`--full` as above). A
name that is also a guide, such as `connector` or `harness`, prints the guide;
add `--reference` for the topic.

`benmore api <app> '*'`, `'table:<name>'` and `'POST /api/<table>'` describe
the deployed app itself: its routes, tables and flows.

| Area | Topics |
| --- | --- |
| Task recipes: complete working files | `tasks` (multi-tenant app, owner-only records, public form, inbound webhook, scheduled sync, status workflow) |
| Agent setup and CLI | `harness`, `cli-install`, `cli-auth`, `cli-contracts`, `agent-usage`, `api-reference-cache`, `machine-discovery` |
| Source, environments, recovery | `sync-status`, `environments`, `recovery`, `feature-packs`, `github`, `collaborators`, `compliance` |
| Verification | `verification`, `qa`, `browser_check` |
| Data model and reads | `schema`, `computed`, `aggregates`, `query`, `search`, `count`, `pagination`, `errors` |
| Writes and history | `batch`, `ingest`, `import`, `idempotency`, `concurrency`, `locks`, `versioning`, `audit`, `retention`, `analytics` |
| Identity and access (row access: start at `access.which_topic`) | `auth`, `csrf`, `mfa`, `oauth`, `access`, `scoping`, `rbac`, `permissions`, `act-as`, `auto_memberships`, `encryption`, `csp` |
| Server logic | `flows`, `async-flows`, `hooks`, `workflows`, `cron`, `scheduling`, `compute`, `sql-dynamic`, `parse`, `success_when`, `sign`, `verify`, `webhooks`, `transcribe` |
| Messages and services | `email`, `sms`, `notifications`, `payments`, `dns` |
| Frontend and SDK | `frontend`, `sdk`, `components`, `ssr`, `existing-frontends`, `mobile`, `i18n`, `markdown`, `cache`, `optimistic`, `live-scoped` |
| Real-time and files | `realtime`, `sse`, `websocket`, `webrtc`, `presence`, `uploads`, `signed-urls`, `pdf` |
| App MCP connector | `connector` (offline guide: `benmore docs connector`) |

## What an app looks like

```
myapp/
├── AGENTS.md         # shared project instructions (CLAUDE.md imports these)
├── app.yaml          # config: theme, auth, features, access, roles, aggregates
├── schema.prisma     # data model → compiled to SQLite + migrations
├── tsconfig.json     # maps the `bm` import to ./src/bm.d.ts
├── src/
│   └── bm.d.ts       # generated per-app TypeScript types (do not hand-edit)
├── static/           # YOUR frontend lives here
│   ├── index.html    # served at /   (framework injects importmap + CSRF meta)
│   ├── login.html    # served at /login (clean-URL routing)
│   ├── signup.html
│   ├── verify-mfa.html, mfa-setup.html, verify-otp.html,
│   │   forgot-password.html, reset-password.html  # sign-in step pages
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
   `target es2020`, `bm` external) and serves the ES module. Cached until any
   bundled file changes, ~10ms recompile. A syntax error emits a module that
   throws on load with a clear console message, so the page still boots.
   esbuild strips TypeScript types without checking them: a type error
   compiles, pushes and passes `benmore check`, then fails at runtime. Check
   types in your editor or with `tsc --noEmit` (tsconfig.json maps `bm` to
   `src/bm.d.ts`).

3. **CSRF auto-injection.** Every served `.html` gets a
   `<meta name="csrf-token">` and a hidden `_csrf` input in native POST forms
   (never in a GET form, so the token stays out of URLs).
   The SDK reads the meta tag automatically. Bearer-auth requests are exempt.

4. **Import-map injection.** Every `.html` gets
   `<script type="importmap">{"imports":{"bm":"/_internal/bm.js"}}</script>`
   so `import bm from 'bm'` resolves to the framework SDK at runtime.

5. **Auto cache-busting.** `<script src="/static/x.js">` / `<link
   href="/static/x.css">` references get `?v=<content hash>` so a changed file
   is never served stale. A `.js` version covers every file under `static/`,
   so editing an imported `.tsx`, `.json`, `.css` or text file changes it too.
   The framework replaces any `?v=` you write; another query string turns the
   rewrite off for that reference.

## `schema.prisma` - the data model

Benmore-supported Prisma syntax, compiled to SQLite with migrations applied automatically on
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
  @@fulltext([title, body])   // optional - enables /api/notes?q=...
}
```

Conventions: snake_case columns in SQL, camelCase in Prisma via `@map`. Include
`userId` on owner-scoped tables and `createdAt`/`updatedAt` timestamps. The
framework fills `user_id` from the session - never accept it from the client.

**Names on the wire.** A model's table is its snake_case plural (`Note` →
`notes`, `UserSession` → `user_sessions`, `Category` → `categories`) unless
`@@map("name")` sets it, and that table name is the API path and the SDK name:
`/api/notes`, `bm.table('notes')`. Rows come back keyed by the SQL column names
(`user_id`, `created_at`), not the Prisma field names; send the same snake_case
keys when writing, because a camelCase key matches no column and is ignored.

**UUID primary keys:** declare `id String @id @default(uuid())`. The framework
generates the UUID server-side, returns it from POST, and makes referencing
foreign keys TEXT automatically. Use UUIDs for ids exposed in shareable links or
where sequential ids would leak counts / invite enumeration; otherwise prefer
INTEGER. Access scoping (owner/group) is the real authorization control - a UUID
is unguessability, not authorization.

For v4 defaults on existing tables and the limits of native insert compatibility,
see `api(at:"scoping")` → `primary_keys.uuid_upgrade`.

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
```

Other keys: `brand`, `font`, `seo.{description,url,favicon}`,
`auth.{otp,domain,redirect,signup_redirect,require_verified,verify_email,require_mfa_for_roles,signup,password_reset,api_tokens}`,
`roles.<name>.scopes`, `features.{admin,sse,ws,ws_anonymous,analytics}`,
`groups.{table,key,user_field}` (multi-tenant isolation),
`pwa.{name,icon,theme_color,offline,offline_page,service_worker}`, `backup.{interval,keep}`,
`aggregates.<name>.{sql,refresh}`, `access.<table>.{read,write,update,delete}`,
`auto_memberships.<parent>.{table,parent,members}`.

OAuth provider metadata uses top-level `oauth:`; provider credentials come from
per-app environment values such as `GOOGLE_CLIENT_ID` and
`GOOGLE_CLIENT_SECRET`. Do not nest an OAuth object inside the scalar `auth:`
map. Built-in provider sign-in routes are `/auth/<provider>`; see
`api(at:"oauth")` for managed hosting, custom providers, and callbacks.

## `compliance: hipaa` - stricter defaults for apps holding PHI

Top-level `compliance: hipaa` in `app.yaml` is the only value of the key; unset
keeps the standard behavior. It turns on safeguards the framework enforces (it
is not a certification), and an `app.yaml` that sets it while weakening one is
refused by the write gate, `benmore check` and the loader. This is a summary of
the main controls; `api(at:"compliance")` is the contract: it lists every
control and names the topic for each.

1. **Idle logoff** - `auth.idle_timeout` defaults to `15m` and accepts only a
   duration from `2m` to `15m` (`"10m"`; not `10`, `0` or `1h`).
2. **MFA for every account** - `auth.require_mfa_for_roles` defaults to `"*"`
   (a list without `*` is refused). An account with no TOTP factor is sent to
   `auth.mfa_setup_redirect` (default `/mfa-setup`: the app needs that page) and
   until it enrolls its credentials get 403 `mfa_enrollment_required` from APIs
   and that redirect on pages. `benmore test` users are given a factor.
3. **Append-only audit** - `_benmore_audit_log` and `_benmore_read_audit` refuse
   UPDATE and DELETE; migrations, `seeds.sql` and `sql --write` may not name
   them, and audit rows are kept at least 6 years. In a YAML test, SQL that
   changes an audit table goes in `setup:`, not in a step.
4. **No GitHub sync** (hosted) - linking a repository and every push are refused.
5. **No production data in dev** - on the hosted platform `refresh_dev` with
   data is refused; everywhere the session recorder stays off
   (`recording.enabled: true` and `recording.production: true` are refused).

On the hosted platform the key only turns on: once an app has been seen with it,
an `app.yaml` without it is refused.

## The frontend - `static/app.tsx` and the `bm` SDK

The scaffold's `app.tsx` does the full loop with the typed `bm` SDK. The SDK is
a thin declarative wrapper over the REST/SSE/WS surface, not a framework.

```tsx
import bm, { type User, type Post, type ChangeEvent } from 'bm';

async function boot() {
  const me: User | null = await bm.auth.me();   // null if signed out
  if (!me) { location.href = '/login.html'; return; }

  // Strongly typed CRUD - bm.table('typo') is a type error in your editor
  // or `tsc --noEmit` (push does not type-check; it would 404). Per-table
  // feature flags drive conditional methods (.list({q}) on @@fulltext tables,
  // .restore() on soft-delete tables, .versions() on versioned tables).
  const posts: Post[] = await bm.table('posts').list({ limit: 50 });
  const ui = bm.createStore({ filter: 'all' });
  const grouped = await bm.query.read({
    table: 'posts',
    group_by: ['status'],
    aggregates: [{ fn: 'count', as: 'n' }],
  });

  // SSE invalidation. A ChangeEvent is { table, action } - never the row.
  // SSE is opportunistic - always refetch after your OWN mutations too.
  // FLICKER WARNING: in refresh(), don't do "ul.innerHTML = rows.map(...)" -
  // that rebuilds every row on each event (the whole list flashes, focus is
  // lost, icons re-init). Use the scaffold's reconcileList (static/lib/dom.ts),
  // which reuses unchanged rows and only touches what changed.
  bm.live('posts', (ev: ChangeEvent) => refresh());

  await bm.flows.publishPost({ id: posts[0].id as number });  // custom flow
  // Totals for a signed-in user come from bm.query.read with aggregates
  // (above). bm.aggregate('total_posts') reads app.yaml materialized
  // aggregates through GET /api/_aggregates, which is admin-only (403 for
  // every other user), so call it only on admin screens.

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
| `bm.broadcast.{publish, subscribe, stats}` | SFU livestream (1:N); the returned handle has `.stop()` |
| `bm.webrtc.iceServers()` | STUN/TURN config for peer-mesh |
| `bm.flows.<name>(params, body)` | One typed method per HTTP flow |
| `bm.workflow(table, id).{transitionTo, available, current}` | State machine |
| `bm.aggregate(name)` / `bm.aggregates.all()` | Materialized aggregates; admin only (`GET /api/_aggregates` answers 403 to other users) |
| `bm.jobs.{status, wait}` | Async-flow polling |
| `bm.notifications.{list, markRead, markAllRead, onNew}` | In-app inbox |
| `bm.upload(file, opts)` | Multipart upload → `{path, url, filename, size}`; `opts.kind: 'private'` for a private file |
| `bm.api.optimistic({apply, request, snapshot, revert})` | Optimistic mutation + reconcile |
| `bm.createStore(initial, {persist?})` | Selector subscriptions, reset, unsubscribe, optional versioned cache persistence |
| `bm.query.{fetch, read, table, tableKey, subscribe, invalidate, mutate}` | Keyed read cache, dedupe, stale time, table live invalidation, optimistic rollback; `subscribe(tableKey(t, opts), fn)` renders what `table(t, opts)` reads (`api(at:"sdk.query_live_snippet")`) |
| `bm.presence(slug)` | Heartbeat + cleanup + server sweep |
| `bm.cache.namespaced(n, v)` / `.persistent(n, v)` | Self-busting client cache |
| `bm.markdown(text)` / `bm.markdownBatch(items)` | Server-rendered, sanitized CommonMark + GFM via benmark; batch rendering avoids one request per item |
| `bm.permissions.{share, revoke, list}` | Per-row ACLs |
| `bm.signedUrl(path, {record, ttlSeconds})` · `bm.audit.list(f)` · `bm.t(key, vars)` · `bm.mfa.{enroll,verify,disable}` | Signed URLs · audit · i18n · TOTP |
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

**Theme determinism:** the Tailwind served at `/_internal/tailwind.js` uses
class-based dark mode: a `dark:` utility applies only to elements inside an
element with class `dark`. It follows neither the viewer's OS setting nor
`app.yaml` `mode`, and nothing adds that class to pages under `static/`. The
scaffold's pages pair light base classes with `dark:` overrides and set no
`dark` class, so they render light. For a dark design either set its colors as
the BASE classes (`bg-zinc-950 text-zinc-100`, no `dark:`) or put `class="dark"`
on `<html>` and keep the `dark:` classes on `<body>` and below (a `dark:` class
on the element that carries `dark` is not matched).

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
`static/assets/app.js`. An app with a reviewed `mcp.yaml` answers the same root-relative paths, from the source it last loaded. Unknown browser navigation routes fall back to
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
| GET | `/api/<table>?q=...` | FTS5 search (needs `@@fulltext`) |

List query params: `?orderBy=col:desc&limit=N&page=N&per_page=N&cursor=X&where[col]=val&where[col__gt]=val&q=keyword&count=true&as_of=<iso>&include=<rel>`.
`?count=true` returns `{count: N}` (true total, ignores the cap). Mutations
require `X-CSRF-Token` for cookie sessions; Bearer-auth requests don't.

Protected fields (`user_id`, `role`, `password_hash`, `created_at`,
`updated_at`, `deleted_at`) are **stripped from any client body** - the server sets them.
Dropped fields are listed in the `X-Stripped-Fields` response header.

## Auth, access & server logic

- **Auth** - `bm.auth.me()` gates the client; the `access:` block (and
  `roles:`) in `app.yaml` gates the server. Sessions are cookie-based for web
  and Bearer-token for API/native clients. MFA (TOTP), OAuth, password reset,
  and email verification are built in.
- **Self-service controls** - set `auth.signup: false` to refuse new password
  and OAuth accounts while allowing existing users to sign in;
  `auth.password_reset: false` closes forgot/reset links but leaves operator
  provisioning and required password changes available; `auth.api_tokens: false`
  closes password-to-token exchange and token creation while list/revoke remains.
  All default on. See `api(at:"auth")` (`self_service_controls`).
- **Passkeys** - on by default: `bm.auth.passkey.register(name, { password })`
  (signed in; the password is optional within 10 minutes of signing in) adds
  one, `bm.auth.passkey.signIn()` signs in with Face ID / Touch ID / Windows
  Hello / a phone, `.list()` / `.remove(id)` manage them; `auth.passkeys: false`
  turns them off (an `auth.oauth_only` app needs `auth.passkeys: true` to have
  them). A passkey works only on the host it was made on (dev, prod
  and a custom domain each need their own). See `api(at:"auth")`.
- **Test users and sign-up** - create users from the CLI instead of driving the
  form: `benmore users <app> create <email> --password-stdin [--role <role>] [--env dev|prod]`
  (hosted). Pipe or prompt for the password so it never appears in argv or shell
  history; for example, read it with shell echo disabled and pipe it using
  `printf '%s\n' "$PASSWORD" | benmore users <app> create <email> --password-stdin --env dev`,
  then unset the variable. The legacy `--password <pw>` form still works but
  warns that its value is visible to local process listings and shell history.
  Reset an existing user's password the same way with
  `benmore users <app> set-password <email> --password-stdin`; the user must
  replace it at next sign-in unless you pass `--no-change-required`.
  CLI creation refuses an existing email without resetting credentials or
  changing its role. `benmore users <app> list --all --env dev` includes
  deactivated accounts for provisioning checks. Cut an account off with
  `benmore users <app> deactivate <email>` and let it back in with
  `benmore users <app> reactivate <email>`; nothing is deleted
  (`api(at:"auth")` → `account_state_signin`). Stdin accepts up to 64 KiB and
  removes only trailing CR/LF. In the browser,
  `bm.auth.signUp({ email, password })` posts to
  `/signup`; there is no `/api/auth/signup`. Passwords need at least 8
  characters, an uppercase letter and a special character (`!@#$%^&*` etc.).
- **Access modes** - per table in `app.yaml`: `read/write/update/delete` set to
  `anon`, `everyone`, `self`, `group`, `admin`, `role:a,b` (any-of),
  `perm:<resource>.<action>`, or `member-of:<table>(<join_col>,<user_col>)`
  ("visible to members of this room/channel/project" via a membership table;
  the framework applies the membership check on every read/write path and
  auto-joins the creator on parent creates). A table without the join
  column must be the parent the join column points at (relation, or the
  `<singular>_id` name); write `member-of:<table>(<join_col>=id,<user_col>)`
  to declare it, otherwise the rule is refused (`api(at:"access")` →
  `member_of`). Multi-role RBAC with inheritance and optional per-group
  (tenant) scoping is supported.
- **Multi-tenant founding moment** - `groups.bootstrap: {org_table: companies,
  founding_role: company_admin}` enables `POST /api/_groups/create` (org +
  founding membership in one transaction); `groups.role_field: member_role`
  loads the member's in-tenant role into the session so `role:company_admin`
  access modes enforce tenant roles on tables with the group key;
  on a table without it only global roles pass (for `perm:` gates too: only
  permissions a global role grants), and on the org table itself a tenant role
  reaches only the caller's own org row (`api(at:"access")`). Adding, changing
  or removing rows of the membership table through `/api/<groups.table>` takes
  a tenant admin (the founding role, or `role:admin`) unless you declare an
  access rule on that table; a member can always leave
  (`api(at:"scoping")` → `membership_management`).
- **WS room authorization** - `ws_rooms: {"room-:id": room_members(room_id,
  member_id)}` in app.yaml gates WebSocket `join` on a membership row; a room
  that matches no pattern is not gated by one.
- **Hooks** (`hooks.yaml`) - `before_*` (sync, can abort a mutation) and `on_*`
  (async side effects: SQL, webhook, email, notify) on insert/update/delete.
  An email body is HTML: `{{col}}` values are escaped, `{{{col}}}` is
  sanitized HTML and `{{{{col}}}}` is raw (`api(at:"hooks")` → `html_emails`).
- **Flows** (`flows.yaml` / `flows/*.yaml`) - custom HTTP routes as a sequence
  of steps (sql / api / parse / compute / respond …). `on:` and `jobs:` are
  file-level keys. `mode: async` enqueues a job and returns a status URL.
  `run: compute` runs sandboxed server-side JS for logic that doesn't fit SQL.
  Numeric-looking `:params` bind as numbers, so SQL guards like
  `WHERE :amt >= (SELECT SUM(...))` compare numerically - no CAST needed.
- **Workflows** (`workflows.yaml`) - state machines with role guards, timeouts,
  and transition hooks. Use one for any record that moves through stages
  (order, ticket, application, approval) instead of a free `status` string or
  boolean pairs: `initial`, `states`, `transitions: {from: {to: {role, when}}}`.
  Creates start in `initial`, PATCH cannot write the state column, and every
  move is guarded and audited. Read state with `GET /api/<table>/<id>/transitions`
  (`api(at:"workflows")`).
- **Real-time** - SSE at `/sse/events` (named `change` events; payload is
  `{table, action}`, refetch the row), WebSocket at `/ws`. SSE is opportunistic;
  always refetch after your own writes.

Each topic named above answers in depth: search it, read its index, fetch the
key ("Look it up", above). Usage accounting for agent sessions:
`api(at:"agent-usage")`.

## The dev loop

1. Edit `static/*.tsx`, `schema.prisma`, `app.yaml`, `workflows.yaml` or
   `flows/*` in the workspace. Installed Claude Code hooks push Edit/Write
   changes; every other agent runs `benmore push <file>`. Exit 0 means written
   and reloaded; nonzero means a file was refused, the reload was rejected (the
   previous configuration keeps serving) or the app stopped answering: read the
   message and `benmore logs <app>`.
2. Exercise the deployed dev app: `benmore probe`, `benmore tool browser_check`,
   or its HTTPS URL (`benmore open .`).
3. `benmore verify --quick` while iterating; `benmore verify --release` before
   promoting. Exit 0 = pass; the report is in `.benmore/verify/<run>/`.
4. `benmore logs`, `benmore tail` and `benmore sync-status` for remote state.

There is no localhost development server in the hosted workflow.

## Dev/prod environments (hosted)

| State | How it arises | Shown by |
| --- | --- | --- |
| dev only (`<sub>-dev`, own `data.db`) | `benmore deploy` creates a new app this way | `benmore apps --json`: `dev_url`, no `url` |
| dev + prod | `benmore promote <app>` ships dev **code** to `<sub>` (never data, secrets or uploads) | `benmore status <app>`: `prod_exists`, `in_sync`, `prod_last_promoted` |
| prod only (older apps) | apps created before dev/prod | `benmore apps --json`: `url`, no `dev_url`; add dev with `benmore seed-dev <app>` |
| dev only, production removed | the owner ran `benmore remove-production <app>`: production is stopped and its live-app slot is free; production data is kept and `benmore promote <app>` publishes it again | `benmore status <app>`: `production: "removed"`, `production_removed_at`; `benmore apps --json`: no `url`. See `api(at:"environments")` (`remove_production`) |

`push` and edits target `--env`, else the `benmore use` pin, else dev when the app
has one and prod when it does not (`--env prod` is a hotfix that bypasses
promote). push, deploy, delete-file, `sql --write` and promote print a `target:`
line on stderr (the save hook prints it only when its push lands in prod).
Full reference: `api(at:"environments")`.

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
`.benmore`, logs, and generated `src/bm.d.ts`. `pull` and `sync` never write
hidden directories outside `static/` (other than `.well-known`/`.github`) or
editor/agent auto-run config (`.vscode`, `.claude`, `.mcp.json`, `.envrc`,
`*.code-workspace`, ...); they list them as skipped (`api(at:"sync-status")`).
The server leaves the same paths out of pull archives and manifests, and hosted
write tools refuse the named auto-run config outside `static/`. `deploy` and the
save hook upload the same set pull hands back: a hidden directory outside
`static/` (an agent's `.scratch/` or `.sdd/`) and the auto-run config stay in
the workspace, `deploy` prints how many files it left there, and `sync-status`
lists them as `kept_local`, not as drift. Keep scratch files and credentials in
such a directory or outside the app directory, and source the app needs in a
plain one (`.gitignore` does not decide what is uploaded; `deploy` warns after
uploading a file the root `.gitignore` excludes, see `api(at:"sync-status.excludes")`).

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
