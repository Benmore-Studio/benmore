# Changelog

All notable changes to the Benmore framework are recorded here. This file was
extracted from `CLAUDE.md` (which previously embedded the running release notes)
so the project memory stays lean and history has a single home.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/);
versions follow the framework's `v2.7.x` release tags (`benmore version` prints
the build). Entries are engineering-grade: they record *why* a change shipped and
the failure mode it closed, not just *what* changed.

> **Scope.** These notes cover the framework runtime + platform. The user-facing
> CLI ships on its own `cli-vX.Y.Z` tag cadence. For the complete tag list:
> `git tag --sort=-v:refname`.

---

## v2.7.202 — GitHub sync (one-way mirror) + CLI update warning (Jul 2, 2026)

- **GitHub sync.** Every app can mirror its per-app git history to a
  GitHub repository the user owns - personal account or organization.
  Connect once via OAuth (dashboard → app → **Version Control** →
  Connect GitHub; the "History" tab was renamed), link a repo (created
  automatically, private by default, org repos supported via the owner
  picker), and every commit - each write_file/edit_file/delete_file/
  promote/revert is one - auto-pushes ~15s after a burst of edits:
  Live instance → `main`, Sandbox → `dev`. One repo, two branches:
  dev-vs-live is a diffable, PR-able view for free.
  - **Security posture** (security.md 31h): client secret router-only;
    user token AES-GCM encrypted at rest, never returned by any API;
    HMAC state (15-min expiry, user-bound); pushes run router-side with
    the token delivered to git via GIT_ASKPASS env (never argv - /proc
    cmdline is world-readable - and never in the URL); owner/repo/
    branch regex-allowlisted; env.yaml/data.db/uploads gitignored by
    construction so secrets can't reach GitHub.
  - **One-way means one-way**: nothing is pulled from GitHub. A
    diverged remote (direct GitHub push) fails visibly in the tab;
    "Push (force)" is the explicit override. Platform history rewrites
    (promote-failure rollback) force the next mirror push automatically.
  - Surfaces: Version Control tab (connect/link/status/push/unlink),
    `benmore github <app> [link|push|unlink|connect]`, MCP tools
    `github_status`/`github_link`/`github_unlink`/`github_push`,
    `api(at:"github")`. Hook seam: `gitPostCommitHook` in git_app.go -
    all commit paths funnel through it.
  - **Operator setup (pending)**: register the GitHub OAuth App
    (callback `https://benmore.ai/platform/github/callback`) and set
    `BENMORE_PLATFORM_GITHUB_CLIENT_ID` / `_CLIENT_SECRET` in
    platform.env. Until then the tab shows "not configured".
  (platform_github.go, mcp_tools_github.go, git_app.go hooks,
  apps/_platform/app-history.html, cli_platform.go CLIGitHub)
- **CLI update warning.** The cloud CLI prints a one-line stderr hint
  when a newer release exists ("benmore vX is available - brew upgrade
  benmore"). Checked at most once per 24h against the public dist repo
  (1.5s hard timeout, result cached), shown only on interactive
  terminals (hooks/scripts/CI never see it), never blocks or fails a
  command. Opt out: BENMORE_NO_UPDATE_CHECK=1. Source builds never
  warn (version compare is numeric; unparseable → silent).
  (cli_update_check.go)

---

## v2.7.201 — `benmore deploy` stops dying silently mid-push + bare first-deploy scaffold (Jul 2, 2026)

A field session deployed a hand-rolled 4-file app (`benmore deploy <dir>`)
and ended up with a chimera: the deployed app served the scaffold's Notes
demo UI against the user's replaced schema (`/api/notes` 404 on every
page load), and the directory's own `static/index.html` never landed —
with no failure surfaced. Two distinct defects:

- **One rejected file no longer kills the whole deploy.** `mcpCall`
  `os.Exit`s the process when a tool returns `isError` — correct for
  single-shot CLI commands, fatal for the multi-file loops in `benmore
  deploy` and multi-path `benmore push`, both of which *documented*
  "a per-file failure is reported and the rest still ship" while their
  aggregation counters were unreachable dead code. A server-side
  validator refusal mid-loop printed one stderr line, exited 1, and
  silently stranded every file after the rejected one (no summary, no
  hint that N files never shipped). New `mcpCallChecked` seam returns
  `(result, ok)` instead of exiting; `pushOneFile` reports
  `✗ <path> rejected: …` and returns false; deploy/push aggregate and
  exit non-zero with the real count. Hook-mode exit-code contract
  (exit 2 so Claude Code blocks the edit) is preserved via the existing
  `hookExitCode` path. (cli_mcp.go, cli_thin_clients.go)
- **First deploy of an existing directory scaffolds BARE.** `create_app`
  always wrote the full TSX Notes demo (14 files); `benmore deploy` then
  overwrote only the files the local dir happened to contain, leaving
  every unshadowed demo file (`static/app.tsx`, `views/notes.tsx`, the
  demo `index.html`/`login.html`/`signup.html`, the `Note` schema…) live
  in the deployed app. The `template` param on `create_app` (previously
  reserved/ignored) now accepts `"bare"`: infra only — minimal
  `app.yaml`, `tsconfig.json`, `src/bm.d.ts` placeholder, `CLAUDE.md` —
  no demo content. `benmore deploy` passes it on first-run create; old
  servers ignore the param and keep the previous merge behavior.
  `benmore new` / dashboard / builder creates are unchanged (full demo
  scaffold). (mcp_tools_create.go, scaffold_html.go
  `WriteBareScaffoldFiles`, cli_deploy.go; test: scaffold_bare_test.go)

---

## v2.7.200 — managed social login, Stripe Connect, managed DNS (Jul 1, 2026)

Three platform wrappers that close the biggest remaining "every app needs
this" gaps. All follow the same trust model as email/SMS: the router owns
the one credential, apps get scoped hand-offs, BYO always wins.

- **Managed social login (the "own Clerk" play).** "Sign in with Google/
  Microsoft" works on every hosted app with ZERO client-ID setup: the
  platform OAuth broker (/platform/oauth/start+callback) owns shared
  provider credentials - possible in production, unlike Clerk (which
  requires per-customer credentials because auth runs on customer
  domains), because our apps live under *.benmore.ai; custom domains
  bounce through the broker. The handoff is a 60s single-audience
  assertion HMAC-signed with the target app's OWN server secret; the app
  side reuses the exact BYO find-or-create + session path. BYO
  <PROVIDER>_CLIENT_ID still takes precedence (white-label consent).
  Apple pending operator credentials (needs the Apple Developer account).
- **Stripe Connect (Standard).** Dashboard → Payments → Connect Stripe →
  Stripe-hosted onboarding → STRIPE_SECRET_KEY / _PUBLISHABLE_KEY /
  _ACCOUNT_ID land in the app env with TEST keys in dev and LIVE keys in
  prod automatically (livemode double-checked on the token itself). The
  user owns a full Standard account - so marketplace apps can enable
  Connect on THEIR account for their own sellers ("DoorDash on Benmore"
  works; platform-managed account types couldn't). Disconnect
  deauthorizes + clears keys. Beats the BYO-keys status quo (Lovable et
  al) on both UX and key hygiene.
- **Managed DNS (Route 53 wrap, Pro).** One hosted zone per customer
  domain: point registrar nameservers at the platform once, and every
  record the platform needs is auto-created - custom-domain routing +
  ownership TXT, email DKIM CNAMEs - plus a guarded record editor
  (NS/SOA protected, zone-scoped names). Delegation detected within ~5
  min; the email verifier is nudged on activation. Kills the
  copy-these-records step everywhere it exists today.
- **Surfaces**: dashboard Payments page + Managed DNS card in Settings,
  `benmore payments <app>` / `benmore dns <app> …`, api topics
  `payments` + `dns` + managed-mode note on `oauth`, security.md
  31e-31g. Tests: platform_wrappers_test.go (assertion sign/verify +
  wrong-secret + replay + return-host matrix, env-scope mapping, DNS
  validation).
- **Operator setup pending** (no APIs exist for these): create the
  platform Google OAuth client + consent verification, enable Stripe
  Connect + set ca_ client IDs, set BENMORE_PLATFORM_DNS=1. IAM user
  already extended with scoped route53 actions.

New files: platform_oauth_broker.go, oauth_managed.go,
platform_stripe_connect.go, route53_client.go, platform_dns.go,
apps/_platform/app-payments.html.

## v2.7.199 — platform SMS service: zero-config texting + dedicated numbers (Jul 1, 2026)

The SMS twin of the v2.7.197 email service, over AWS End User Messaging
(Pinpoint SMS v2), tuned for SMS's two hard differences: every message
costs real money, and sender identity is a carrier-REGISTERED phone
number (no DKIM analog).

- **Zero-config transactional SMS.** Apps with no explicit provider
  (Twilio/webhook still win) send phone-OTP auth + `run: sms` steps
  through the router's broker from the shared platform toll-free number.
  Activates when BENMORE_PLATFORM_SMS_FROM is set - i.e. once the
  toll-free carrier verification completes.
- **Abuse economics built in**: destination calling-prefix allowlist
  (default +1 - blocks international AIT toll fraud), per-recipient
  velocity (5/10min), plan quotas (free 5/day - enough to build OTP;
  paid 200/day; QUOTA_FREE=0 makes it paid-only), global rate bucket
  sized to shared toll-free throughput, per-app pause state.
- **Dedicated numbers (Phase 2, paid plans).** POST /platform/app-sms/number
  with a short company form: the platform leases a toll-free number,
  renders the app-branded opt-in evidence image server-side (headless
  Chrome), auto-fills + submits the US_TOLL_FREE_REGISTRATION, and a
  worker polls carrier review (days-to-weeks). On approval the broker
  automatically originates that app's SMS from its own number; a pending
  registration never originates. Full teardown releases the lease.
- **Surfaces**: dashboard tab renamed Email & SMS with an SMS card
  (shared number, quota, dedicated-number lifecycle, recent sends),
  `benmore sms <app>`, `api(at:"sms")` topic (incl. the consent-language
  compliance requirement for phone-auth apps), security.md 31d.
- **AWS side this release**: toll-free +18333532263 leased, carrier
  registration filled (pending 3 company fields) and associated, $100/mo
  spend increase requested, IAM user extended with scoped sms-voice
  actions. The service stays OFF until verification completes.

New files: sms_gateway.go, sms_client.go (AWS JSON 1.0 RPC, no SDK),
sms_broker.go, platform_sms.go. Tests: platform_sms_test.go (prefix
allowlist, plan quotas + accounting, origination selection incl.
pending-never-originates).

## v2.7.198 — quarantine keeps its port: no more double-assignment + cross-app routing (Jul 1, 2026)

Creating the email-test app exposed a serious routing bug: its dev
instance was assigned port 18102 - the SAME port a previously-quarantined
app's unit still carried in its EnvironmentFile. The two units fought
over the bind and the router cross-routed the new app's subdomain to the
old app's process (API requests answered by the wrong tenant).

Root cause chain: the quarantine watcher `Remove()`d a crash-looping
app's route from ports.json, FREEING its port for reallocation, while
the failed unit + its env file kept `BENMORE_PORT=<port>`. The comment
promised the inverse ("units that recover get a route back") but it was
never implemented - a manual `reset-failed + start` revival (the
documented recovery!) brought the app back with no route and a port the
allocator had since handed to someone else.

- **Quarantine now TOMBSTONES instead of removing** (`RouteTable.Quarantine`,
  negative-port entries in ports.json): the app is unrouted (friendly
  restarting page, as before) but its port stays reserved. `Remove()` is
  reserved for true deletions, where the env file dies with the dir.
- **Auto-restore implemented**: the watcher re-routes a tombstoned app as
  soon as its unit is active again (poll ≤30s) - manual systemd revival
  now self-heals, no redeploy needed.
- **Allocator is drift-proof**: `AllocatePort` also refuses any port
  referenced by an existing app unit env file, so even residual pre-fix
  drift can't produce a double assignment.
- **Dev units quarantine too**: the failed-unit scan only matched
  `benmore-app@`; a crash-looping `benmore-dev@` unit kept its route and
  served 502s forever. Now both prefixes are covered.
- Operationally: audited the fleet for env-file/route drift - three apps
  (two quarantine-stripped revivals + one stale husk) held colliding or
  unrouted ports; all reassigned unique ports + restored routes; 0 failed
  units.

Tests: router_table_quarantine_test.go (reserve/restore lifecycle,
tombstone survives reload, Remove still frees, env-file-port avoidance).

## v2.7.197 — platform email service: every app sends out of the box, BYO domains via SES (Jul 1, 2026)

Amazon SES wrapped as a first-class platform service. The old posture -
"set RESEND_API_KEY or email errors out" - is gone on the hosted platform.

- **Zero-config sending.** Apps with no explicit provider deliver flow/hook
  `run: email` steps and framework auth email (OTP, verification, resets)
  through the platform: default sender `<app-sub>@mail.benmore.ai` with the
  app's display name. Explicit providers (Resend/Postmark/SMTP) still win;
  self-hosted builds are untouched (no broker socket → old behavior).
- **Router-brokered trust boundary.** Tenant processes never see the SES
  credential: sends dial `/run/benmore/email.sock` (peer-uid authenticated,
  mirroring the presign broker), and the router enforces pause state →
  from-domain authorization → suppression → per-app plan quota (free
  100/day, paid 2,000/day) → a global token bucket matched to the SES
  account send rate. Tenants on the shared domain are pinned to their own
  local part (no cross-app sender spoofing).
- **BYO sending domains.** Dashboard → app → **Email** tab (new), `benmore
  email-domain <app> add <domain>`, or the `email_domains` MCP tool:
  registers an SES DKIM identity, returns the 3 CNAME records, and a worker
  auto-verifies (then re-checks daily - removing the DNS records flips the
  domain back to unverified and sends fail closed with an actionable
  error). One app per domain, ever.
- **Deliverability self-protection.** The existing SNS webhook
  (`/platform/ses-events`) now attributes bounce/complaint events per-app
  via message tags: hard bounces + complaints feed a platform-wide
  suppression list checked on every send, and a per-app circuit breaker
  pauses sending at >0.5% complaints or >10% bounces over 7 days
  (20-send sample floor) + emails the owner. Tenant events no longer touch
  _platform's marketing/user suppression (first-party only).
- **Surfaces**: `benmore email <app>` (status/quota/stats), `benmore
  email-domain add|verify|remove`, dashboard Email tab with DNS-record
  copy buttons + recent sends, MCP `email_domains`, canonical
  `api(at:"email")` topic.
- **Operator setup** (one-time): verify `mail.benmore.ai` in SES, config
  set `benmore-platform` → SNS topic `benmore-ses-events` → HTTPS
  subscription to /platform/ses-events, and `BENMORE_PLATFORM_SES_REGION/
  KEY/SECRET/MAIL_DOMAIN` in platform.env. Tunables:
  `BENMORE_PLATFORM_SES_RATE`, `_QUOTA_FREE`, `_QUOTA_PAID`.

New files: ses_client.go (SigV4 SESv2 client, no AWS SDK), email_gateway.go
(tenant-side socket client), email_broker.go (router-side broker),
platform_email.go (domains/quota/suppression/breaker), mcp_tools_email.go,
apps/_platform/app-email.html. Tests: platform_email_test.go (quota plans,
suppression, cross-app authorization, breaker thresholds + sample floor,
token bucket).

## v2.7.196 — router can never create (or strand) a tenant data.db it owns (Jul 1, 2026)

Rolling the v2.7.195 fleet exposed a tenant app crash-looping with "attempt
to write a readonly database": its data.db was owned by the ROUTER user
(0644, dated Jun 25), so the per-app process could read it but never write -
every boot-time migration failed. The file was an empty 4096-byte SQLite db:
a router-side open had CREATED it (SQLite creates missing files on writable
opens) and left it router-owned. The app had been silently broken since.

- `dashboardOpenRW` now REFUSES to open a data.db that doesn't exist, with
  an error saying the app process creates it at first boot - a dashboard/
  MCP call racing first boot can no longer plant an unwritable empty db.
- `swapInBackup` (corruption auto-recovery) chowns the restored data.db to
  the app dir's owner, so a router-context restore doesn't strand the app
  the same way.
- Operationally: the stranded app was fixed by chown + restart; fleet is
  healthy.

## v2.7.195 — browser_check field-report fixes: viewport control, overlay-proof clicks, honest deadlines (Jul 1, 2026)

The remaining PLI field-report items, all in `browser_check`:

- **Viewport control.** New `width`/`height` args (default 1440×810, clamped
  320-3840 / 480-2160) - previously any viewport argument was silently
  ignored, so mobile/responsive verification required driving local Chrome
  over CDP by hand. `390×844` ≈ iPhone portrait. The humanized cursor's
  start position follows the actual viewport.
- **Overlays can't eat trusted clicks.** Two standing interceptors: the
  cookie-consent banner caught bottom-of-page clicks (`#bm-cookie-decline`
  got the click meant for the element under it), and sticky headers ate
  clicks on elements chromedp scrolled to the viewport EDGE (exactly where
  sticky bars live). Fix: the framework's injected chrome (testing banner,
  cookie banner, feedback fab/badge) is now hidden in EVERY mode via an
  every-document boot script (recording already did this cosmetically -
  plain checks need it for correctness), and click targets are centered
  (`block:'center'`) before the trusted click is dispatched.
- **Honest deadline handling.** Recording runs get a 50s base budget (the
  rrweb boot + full-load snapshot + inlineStylesheet/inlineImages pass costs
  10s+ on a heavy page BEFORE action 1 - identical unrecorded runs passed
  while record:true died immediately) and 3s/action. When the budget DOES
  die mid-flow: the action loop breaks once with a clear "budget exhausted
  at action N, M remaining skipped" error instead of cascading identical
  context-deadline errors through every remaining action, the result
  carries a structured `deadline_exceeded: true`, and `share:true` is
  REFUSED for that run - previously a half-dead run still minted a public
  share link, shipping a "demo video" of nothing.
- **Quoted numbers in actions parse.** `{"do":"scroll","y":"800"}` /
  `{"do":"wait","ms":"500"}` now coerce; a quoted number used to silently
  fall back to the default (scroll-to-top / 300ms wait) with zero signal.

Server-side only (`mcp_tools_browser.go` is platform-tagged): no CLI or OSS
release required; docs in SKILL.md/build.md.

## v2.7.194 — encryption is environment-safe end to end + PLI field-report fixes (Jul 1, 2026)

Field report from the Philadelphia Literacy app surfaced a cluster of
platform bugs around field encryption in the dev/prod + router world, plus
several sharp edges. All fixed in one pass.

**Encryption (the serious ones)**

- **Per-DB encryption key registry — router and app process now agree on
  every tenant's key.** `appEncryptionKey` is a process global; in the
  ROUTER process (dashboard SQL console, MCP `sql`/`query_db`, promote) it
  was at best some other app's key and at worst nil. Router-side
  `sql --write` against an encrypted table therefore encrypted under the
  WRONG key — each path round-tripped its own writes fine, so it looked
  healthy until the app read what platform SQL wrote (raw ciphertext) or
  vice versa. New `dbCryptoRegistry` (encryption.go) maps canonical
  data.db paths → per-app keys; the `benmore_encrypt`/`benmore_decrypt`/
  `benmore_blind_index` SQL functions resolve their key from the
  CONNECTION's own filename (`conn.GetFilename`), and `dashboardOpenRO/RW`
  resolve each tenant's key (per-app env store first, then env.yaml) via
  `registerTenantCryptoKeys` before handing out a pool. `SELECT *` through
  the platform sql path now auto-decrypts too — `DecryptRowFields` falls
  back to trying every registered key (safe: AES-GCM authentication
  rejects wrong keys with 2^-128 false-accept).
- **ENCRYPTION_KEY survives restarts on prod.** First promote → fresh prod
  instance → framework auto-generated a key; if the env.yaml persist
  failed across the per-tenant ownership seam, the next restart silently
  generated a DIFFERENT key, turning everything already encrypted into
  unrecoverable ciphertext. Two-layer fix: `writeAppEnvFileFor` auto-PINS
  ENCRYPTION_KEY into the per-app env store (instance scope) for apps
  with encrypted fields (env.yaml's existing value if present, else
  generated at first provision — the app then boots with the key in its
  systemd env, deterministic forever), and `chownToDirOwner` fixes
  env.yaml ownership whenever a non-app-user process writes it.
- **Decrypt failure is masked, never leaked.** A value that looks
  encrypted but can't be decrypted under any known key now returns
  `[unavailable: decryption failed]` with a throttled server log line —
  previously the raw `enc:v1:…` ciphertext passed straight through to API
  clients (a confidentiality leak that read as silent data corruption,
  with zero log signal).

**Dev/prod + CLI sharp edges**

- **`promote` no longer false-fails on "prod pre-migrate backup dir is not
  writable: permission denied".** The preflight runs in the ROUTER but the
  backup is taken by the PER-APP process (the dir's owner) at boot;
  `.benmore/` is 0700 tenant-owned, so the router's own write probe was
  guaranteed EACCES after the first promote. `ensurePreMigrationBackupWritable`
  now passes when the dir is owned by a different uid with owner-write
  (`writableByOwningUser`); same-uid probes stay authoritative.
- **`delete-file` honors `--env`.** The flag parser rejected `--env` (and
  historically dropped it), so `benmore delete-file x --env prod` deleted
  the DEV copy while reporting ok:true — which is also why the deleted
  flow's route kept answering on prod (the file never left the prod tree;
  the hot reload that delete_file triggers rebuilds the mux and correctly
  drops routes once the right instance's file is removed). Now parsed +
  forwarded (injectActiveEnv), with the ⚠ PROD banner.
- **`probe_route` body cap 8KB → 48KB, rune-safe.** The old cap chopped
  JSON mid-string and forced per-row GET pagination. Bodies now cut at
  48KB on a rune boundary with an explicit truncation marker; the JSON
  shape hints (`body_parsed`, `body_keys`, `body_length`) parse the FULL
  body (read cap raised 64KB → 256KB) so they stay complete regardless.
- **Fleet deploys roll the per-app units.** `scripts/deploy-prod-ssm.sh`
  restarted only the router, leaving every benmore-app@/benmore-dev@ unit
  on the OLD binary inode indefinitely — the exact mixed-version skew that
  broke PLI dev ("wrong number of arguments to benmore_encrypt": newer
  triggers in the DB, older function registration in the still-running
  process). The script now rolls all running app units (staggered) after
  the router health gate; `--no-roll-apps` opts out.

Docs: `api(at:"encryption")` rewritten for the new key model (backfill via
`sql --write` now supported; decrypt-failure masking; auto-pin), Recent
tables in `build.md` + `SKILL.md`, security.md controls 26b–26d. Tests:
`encryption_registry_test.go` (registry beats global, DecryptRowFields
fallback + masking, owner-aware backup preflight).

## Fix — feedback list/show blind to rows on pre-`origin_host` instances (Jun 30, 2026)

`benmore feedback <app>` returned `count: 0, feedback: null` and `feedback show
<id>` returned `404 not found`, while `benmore testing-status <app>` on the SAME
instance counted the row (`total: 1`). Reproduced on a tenant app's dev instance.

- **Root cause: schema drift, not instance misresolution.** Both dashboard
  handlers resolve to the same `data.db`; the divergence was the SQL.
  `origin_host` is ALTER-added to `_benmore_feedback` by `EnsureFeedbackTables`,
  which only runs **inside the per-app process** at mux build. An instance
  created before that column and not redeployed since has a table without it. The
  dashboard reads run in the **router** process (newer binary) on a `mode=ro`
  connection — they can't run the heal ALTER — so `GET /platform/app-feedback`
  and `…/{id}` referenced a column the table lacked. The list 500'd (silently
  dropped from the dev+prod merge → empty), `show` 500'd; `testing-status`
  (`COUNT(*)` only) never touched the column, so it counted the row. The two
  paths *looked* identical but one query was schema-fragile.
- **Fix: degrade gracefully.** `feedbackOriginHostSelect(db)`
  (`platform_dashboard.go`) probes `pragma_table_info` and selects
  `COALESCE(origin_host,'')` when the column exists, else `''` (old rows carried
  no host anyway). Both dashboard read handlers AND the MCP
  `list_visitor_feedback` tool (`mcp_tools_feedback.go`, same `origin_host`
  reference, same failure) use it, so list/show work on old and new schemas
  alike. No write/ALTER from the read path — the `mode=ro` boundary stands; a
  redeploy still heals the column for real via `EnsureFeedbackTables`.
- **`show` no longer masks query faults as 404.** The handler turned *every*
  `db.Query` error into `404 not found`, which is how "no such column" read as
  "feedback not found". A query error is now a `500` with the cause; the genuine
  no-row case stays `404` (`!rows.Next()`).
- **CLI: merged empty list is `[]`, not `null`.** `listFeedbackMerged` seeds the
  slice non-nil so an empty result matches the raw endpoint's shape.

## Fix — auto-CRUD framework tests are access-aware (Jun 27, 2026)
The auto-generated `_framework_crud` suite assumed the synthetic test user
(`_test_user@benmore.test` — a plain authenticated user with no group, no extra
roles, and no access-level grant) could read and write **every** table. For any
app with real authorization — `groups:` tenancy, an RBAC / access-level matrix, a
`before_insert` hook, or `access.read: off` sensitive tables — that is false:
group-scoped writes are denied 404 (the framework's "don't leak existence"
posture), `read: off` reads are 404 by design, and RBAC / hook aborts return 422.
The result was a flood of false failures (a real 97-table app reported 134
"failures" that were all *correct* access denials) even though `benmore check`
and the deployed app were clean.

The generator is now access-aware (`testgen.go`):
- **`read: off` tables** — list/paginate/cursor assert closure (404) instead of a
  200 list.
- **Create** — strict 200 only when the synthetic user can *provably* write
  (owner/public-writable, no group key, no `before_insert` hook); otherwise it
  accepts success **or** a well-formed access-control denial via a new
  `status_in` expectation (`200/201/401/403/404/422`). 400 and 5xx are never
  accepted, so malformed-data and server bugs still fail.
- **audit / batch / bearer-skips-CSRF** — pick a provably-writable table and skip
  when none exists (they need a real successful write to assert anything).

Simple owner-scoped apps are unaffected: creates stay strict 200 and the audit/
batch suites still run. Adds `AppTestExpect.status_in` (any-of acceptable
statuses) in `testrunner.go`.

---

## Feature + fixes — visitor feedback: live-app widget, dev+prod merge, and a pile of attribution bugs (Jun 26, 2026)

Follow-up to the origin-host attribution fix. Visitor feedback worked but was
buggy across every surface and could only ever run on a draft; this lands the
`features.feedback` flag, fixes the dashboard, and unifies the data layer.

- **`features.feedback` — the widget on a published app.** New opt-in flag
  (`FeaturesConfig.Feedback`, default false) that turns the feedback widget + API
  on **independently of testing mode**. `publish` only flips `features.testing`,
  so a client who sets `features.feedback: true` keeps collecting feedback after
  going live — the biggest "lost feedback" lever (published apps previously
  collected zero, because `publish` stripped the widget with the testing banner).
  `app.FeedbackWidgetEnabled()` = `testing || feedback` gates widget injection
  (`layout.go`, `static_html.go`) and API registration (`server.go`); the amber
  testing banner + demo password gate stay gated on `testing` alone, so prod
  feedback is silent. CLI: **`benmore feedback-widget <app> [on|off]`** toggles it
  in `app.yaml` (inserts under `features:` if missing); no-arg prints state.
- **Prod read is now admin-only (data-leak fix).** On a published app the in-app
  `GET /api/_feedback` carries real visitors' emails. It previously returned the
  full list to *any* logged-in user. `feedbackReadAllowed` now requires admin on a
  published app (drafts keep any-tester-can-read); anonymous always gets `[]`.
- **Dashboard feedback tab rebuilt (decision #2).** It (a) merged nothing — it
  sent `&branch=` while the server reads `?env=`, so the Dev|Prod switch was dead
  and it always showed prod; (b) PATCHed `/app-feedback` without `/{id}`, so every
  status change 404'd; (c) referenced `has_screenshot`/`screenshot_data` the list
  endpoint never returned, so screenshots never rendered. Now fetches **both
  instances** and shows one merged, newest-first list (matching `benmore
  feedback`) with Sandbox/Live + `origin_host` badges, an instance/status filter,
  per-row env-correct PATCH, and lazy screenshot loading. List endpoint returns a
  cheap `has_screenshot` bool; the detail endpoint returns `origin_host`.
- **One status vocabulary, one webhook payload.** `{open, in_progress, resolved,
  wont_fix}` is now defined once (`ValidFeedbackStatus`) and enforced by the
  widget, MCP (`update_visitor_feedback_status` now accepts `wont_fix`), dashboard,
  and CLI — the dashboard's bogus `new` option and `wont_fix`-rejection are gone.
  Both submit handlers now build the `TESTING_WEBHOOK_URL` payload through one
  `feedbackWebhookPayload`, so every delivery carries `app_id` + `origin_host`
  (the testing payload used to omit `app_id`, leaving consumers unable to
  attribute a row).
- **`origin_host` surfaced everywhere** it's now stored: the in-app admin page
  gains a Host column, both in-app list endpoints + the dashboard return it.
  `get_testing_status` reports `feedback_enabled` / `widget_active`.
- **Triage loop — `benmore feedback <app> resolve|reopen <id>…`.** Batch,
  instance-aware status changes for the "pull feedback → fix → mark done" agent
  loop. Because dev and prod are separate `data.db`s with **colliding
  autoincrement ids**, a naive `status <id>` could resolve the wrong instance's
  row; `resolve`/`reopen` look the id up across both instances and route to the
  one it uniquely lives in, **erroring on a genuine collision** instead of
  guessing (`--env`/`benmore use` forces an instance). Status writes hit the live
  DB directly — no redeploy. `routeFeedbackEnv` is unit-tested. Hardened the
  dashboard list endpoint's `limit` (was raw-interpolated into SQL — now parsed +
  clamped) since the resolver passes a high limit to index every id.
- **No impact on existing feedback.** The flag defaults off (published apps
  unchanged unless opted in); the `origin_host` ALTER is idempotent (old rows →
  NULL → "unknown host"); testing-mode behavior is byte-for-byte preserved. Tests
  in `feedback_attribution_test.go` cover the gating matrix, prod admin-gating,
  status validation, and webhook payload parity.

## Release-readiness & flow-safety stack — 15 PRs (Waves 1–8, Jun 2026)

A stacked series (PRs #72–#86) hardening the dev→prod path, flow correctness, and
write-time safety. Grouped by wave; each shipped its `api(at:)` topic update where
app-builder-facing (`flows`, `access`, `async-flows`), but the markdown docs lagged
— this entry plus the SKILL/build/security/apps sweep closes that.

**CLI & dev→prod ergonomics (Waves 1–2, 5.3 + capstone)**
- **PR1 — CLI consistency.** Case-insensitive app-id resolution (`pull FERDA` works),
  `--version`/`-v`/`-V` aliases, `git log|show|revert` surfaced in `help`, a new
  `describe <app> tables` kind (row/col counts), and a `⚠ targeting PROD` banner on
  `sql --write` / manual `push --env prod` / `use prod`.
- **PR2 — promote ergonomics.** `promote --help` exits 0; interactive `promote <app>`
  shows the dry-run + y/N confirm on a TTY, `--yes`/`-y` skips; non-interactive
  unchanged. Pull tar now skips an open-failed entry instead of aborting the whole
  extract.
- **PR3 — `benmore status` / `diff`.** Read-only dev↔prod drift report before a
  promote: content-hash file drift (`modified`/`only_in_dev`/`only_in_prod`), schema
  drift (pending-additive vs blocked-destructive), `prod_last_promoted`, `in_sync`
  verdict. `GET /platform/app-status`.
- **PR4 — promote safety.** Pre-promote scan for `${{ env.X }}` refs unset in PROD →
  `env_warnings` (dry-run + real run); post-promote re-diff → `migration_verified` +
  `remaining_schema_additions`.
- **PR12 — payment-key preflight.** `benmore status` flags a LIVE key in dev, a TEST
  key in prod, or a secret-named key byte-identical across dev/prod
  (`payment_key_warnings`).
- **PR13 — `benmore doctor` (capstone).** `GET /platform/app-doctor` composes drift
  (PR3), env-parity (PR4), payment-keys (PR12), money-columns (PR6), PII-exposure
  (PR10) and secret-scan (PR9) into one PASS/WARN release-readiness report with an
  overall `ok`.

**Flow correctness (Wave 3)**
- **PR5 — fail loud on guarded 0-row writes.** Exec steps expose
  `steps.<id>.outputs.rows_affected`; new `expect_rows:` assertion (`">0"`, `>=1`,
  `=1`, `!=0`, bare `N`) fails the flow when a guarded `INSERT…SELECT…WHERE` writes
  nothing instead of returning a silent success. (`api(at:"flows")`)
- **PR6 — write-time validator catches.** Hard-rejects a flow `when:` key (→ `if:`);
  warns when a money-named column is typed `Float`/`REAL` (recommend integer cents +
  `bm.money()`).
- **PR15 — async respond/redirect warning.** `benmore check` warns when a
  `mode: async` flow carries `respond:`/`redirect:` (no-ops in the worker), recursing
  into `if`/`for_each`. (`api(at:"async-flows")` already documents the no-op.)

**Agent-IO robustness (Wave 4)**
- **PR7 — rune-safe `read_file`.** UTF-8-safe truncation (no split multibyte runes);
  default read 30→64 KB, cap 50→256 KB.
- **PR8 — content-hash asset versioning.** `?v=` is now a sha256 content hash (12 hex)
  instead of file mtime (hashing the whole source tree for JIT `.js`), closing the
  `git revert`-reuses-an-old-mtime → stale-CDN footgun.

**Write-time security (Waves 5–6, 8 — two P0s)**
- **PR9 — reject hardcoded secrets.** gitleaks-style high-confidence scan in
  `ValidateOnWrite` (Stripe `sk_/rk_`, AWS `AKIA`, GitHub `gh[pousr]_`, Google `AIza`,
  Slack `xox*`, Resend `re_`, OpenAI/Anthropic `sk-(ant-)`, PEM blocks) → rejects with
  "move it to `benmore env`". Publishable `pk_*` and `${{ env.X }}` are never blocked.
- **PR10 — PII-exposure flag.** `benmore check` warns when a model with PII columns
  (email/phone/address/ssn/dob/card/iban/tax_id/…) has an effective read mode of
  `everyone`/`anon`.
- **PR11 — tiered access `owner_or_role:<roles>` (P0).** Composite access mode
  expanded at `rowScopeClause`: a row is visible if owner (`user_id`) OR the caller
  holds a listed role (→ whole group on group-keyed tables, else all rows) OR an ACL
  grant. A group-less role-holder falls back to owner-only (cross-tenant leak guard).
  Replaces the old "`access:` is single-axis → write a secure read flow" workaround.
  (`api(at:"access")`)
- **PR14 — declarative per-flow `rate_limit` (P0).** `on.request: { rate_limit:
  "5/hour per ip" }` → 429 + `Retry-After` before any step runs. Form `<count>/<window>
  [per <scope>]`; windows s/m/h/d or Go duration; scopes ip(default)/user/email/group
  (anon falls back to IP). Malformed declarations rejected at write time.
  (`api(at:"flows")`)

## Fix — `benmore health --env prod` returned an all-zero snapshot (Jun 24, 2026)

`benmore health <app> --env prod` reported `tables: 0`, `row_counts: {}`,
`active_sessions: 0`, `audit_last_24h: 0` against a healthy, populated prod
instance — while `sql`/`errors`/`promote --env prod` all read the same data
correctly. Surfaced right after promoting `FERDA` (`ferda-fpaahg`): the snapshot
read as if prod had no tables and no data, which looks like a catastrophic
failure mid-release when nothing was actually wrong.

- **Root cause.** `/platform/app-health` was the *only* env-aware observability
  endpoint that opened its own **read-only** (`mode=ro`) connection via
  `dashboardOpenRO`. On a freshly-promoted prod instance whose schema/rows still
  live in the not-yet-checkpointed WAL, a read-only connection pins an empty
  pre-checkpoint snapshot and reports 0 tables / `{}` forever — the exact failure
  mode the `dashboardOpenRO` comment already documents ("the RW audit path, which
  never pins a snapshot, saw them fine"). The `_benmore_sessions`/
  `_benmore_audit_log` COUNTs then hit "no such table" and silently scanned to 0,
  so the response came back well-formed but all-zero instead of erroring.
- **Fix.** Health now resolves through the shared `httpOpCtx` env→instance→data.db
  resolver (the RW handle `errors`/`tail` already use) and reads via a new
  `OpGetHealth` op, so it stays in lockstep with every other env-aware command.
  No more bespoke read-only path. Regression test (`op_health_test.go`) asserts a
  populated DB reports `tables > 0` + non-empty `row_counts`, and that a nil DB
  fails loudly rather than zeroing out.

---

## Ops — SSM deploy automation (Jun 23, 2026)

No runtime change; this is a deploy-pipeline addition. It closes the gap called
out in `build-platform.yml` ("Auto-SSH-deploy from CI is intentionally NOT
wired… the prod host's security group restricts SSH to a fixed IP, so
GitHub-hosted runners can't reach it").

- **`scripts/deploy-prod-ssm.sh`** — zero-downtime production deploy of the
  platform binary over AWS Systems Manager (SSM) instead of SSH/scp. Same
  on-host logic as `deploy-prod.sh` (edition guard → backup → atomic swap →
  socket-activated router restart → health gate → auto-rollback), but the
  transport is `s3 cp` + presigned GET URL pulled by the host, and the command
  runs via `ssm send-command`. **No SSH key and no security-group change** — any
  caller holding the right IAM role deploys from anywhere (laptop off the
  allowlist, or a CI runner via OIDC). The host SSH allowlist stays a fixed
  operator `/32`.
- **`.github/workflows/deploy-platform.yml`** — push-button deploy gated by the
  protected `production` GitHub environment (required reviewers → only trusted
  users can release). Build job mirrors `build-platform.yml` (goreleaser-cross,
  cgo); deploy job assumes the prod OIDC role and runs the SSM script. Reuses the
  existing `BENMORE_AWS_ACCOUNT_ID` / `BENMORE_AWS_ROLE_TO_ASSUME` secrets; the
  OIDC role additionally needs `ec2:DescribeInstances`, `ssm:SendCommand` /
  `GetCommandInvocation` / `DescribeInstanceInformation`, and S3 R/W on
  `benmore-platform-uploads/deploy/*`.
- **Why SSM is safe here**: the binary's edition + sha256 are verified on the
  host before the swap; the deploy is router-only (no `--roll-apps`), so live app
  processes keep their open inode; health gate + auto-rollback are unchanged from
  the SSH path. First live use: redeployed `2.7.184` to `benmore-prod`
  zero-downtime, `https://benmore.ai` 200 throughout.
- Operator + runbook docs: `docs/deployment/release-runbook.md`,
  `docs/deployment/cloudformation.md`; full session writeup with the hiccups in
  `docs/handoffs/2026-06-23-ssm-deploy-automation.md`.

## v2.7.168a — enterprise-hardening review fixes (Jun 2026)

Correctness fixes from the PR review of the v2.7.168 workstreams. Several change
observable behavior:

- **WAL shipping/PITR (WS2) reworked for correctness.** The base snapshot no
  longer opens a second connection to checkpoint a live DB (which corrupted the
  running pool's shm mmap); it checkpoints through the live pool and copies via
  SQLite's online `.backup` under a per-app checkpoint mutex, so neither the
  5-minute maintenance loop nor a writer-connection autocheckpoint can produce a
  torn base. The shipper now tracks the WAL-header salt and rolls a fresh base on
  any reset/wrap instead of splicing byte-ranges across two WAL generations
  (which silently corrupted PITR). A final segment is flushed on shutdown (no
  per-deploy RPO hole); restore validates segment-sequence contiguity and
  hard-fails on a gap rather than silently restoring a truncated DB; segment
  `seq` advances only after a successful upload. PITR objects are now
  garbage-collected by generation (snapshot + its WAL atomically; newest kept;
  older dropped past `BENMORE_PITR_RETENTION_HOURS`, default 7d) — previously
  they grew in S3 forever. An unrecognized `DB_SYNCHRONOUS` value now warns
  instead of silently downgrading to NORMAL, and WAL shipping requires
  `BACKUP_S3_BUCKET` so a half-configured app keeps truncating its WAL.
- **Migrations: drift no longer auto-restores (WS5).** A `missing_column` drift
  after a clean migration now warns and keeps serving. The previous auto-restore
  reverted every write since the pre-migrate backup and re-detected the same
  drift on next boot — a permanent crash-loop with data loss. Only genuine
  corruption (`integrity_check`) auto-restores. Additive `ADD COLUMN` is now
  atomic across all tables (one transaction), not per-table.
- **Job recovery: cron no longer blanket-replays (WS1).** A crashed cron is
  re-run on recovery only if it opted into at-least-once retries
  (`max_attempts > 1`) with budget left; otherwise it fails closed, since a cron
  body runs the same arbitrary side-effecting flow steps as a flow job.
- **`benmore test` won't wipe a deployed app.** The DB reset refuses when a
  `.benmore/` dir is present unless `BENMORE_TEST_RESET=1`.

## v2.7.168 — enterprise hardening workstreams (Jun 2026)

Five reliability/security workstreams landed together:

- **CRUD row scoping now has one audited path.** `crud.go` list/read/update/
  delete/batch/tx all call `rowScopeClause`, preserving existing public-read
  widening while removing the previous hand-rolled scope cascade copies.
- **Background workers are bounded and panic-contained.** Long-lived workers
  use `safeGo` with reload-aware `app.Stop` exits, event flow fan-out is capped
  with synchronous backpressure, feedback webhook fan-out is capped best-effort,
  and idempotent async jobs can replay after worker crashes.
- **Migrations are transactional and recoverable.** Additive `ADD COLUMN`
  batches run in per-table transactions, prod migrations refuse to run without
  a usable pre-migrate backup, post-migration verification can auto-restore,
  and promote dry-runs call out expand/contract rename-shaped diffs.
- **Framework/cloud `serve` run the real validators and `benmore test` is
  dispatchable.** Validator core moved out of platform-tagged files, the serve
  shim is gone, test output supports human/JSON modes, and the runner resets
  `data.db` before loading test apps.
- **Durability depth:** backup retention is enforced through S3 List/Delete
  with `BENMORE_RETENTION_DRYRUN=1`, apps can opt into
  `DB_SYNCHRONOUS=FULL|EXTRA`, and platform builds can enable in-process WAL
  shipping/PITR via `BENMORE_WAL_SHIP=1` plus
  `benmore restore <app> --pitr --as-of <RFC3339>`.

## v2.7.164 — TeamUP field-report batch (Jun 2026)

A fixed-fee client build (TeamUP BEN-195, multi-tenant collaboration)
produced a field report; this release answers it. Three architectural
features + a DX batch:

- **`member-of:` access mode** (the report's top ask). `access: messages:
  member-of:room_members(room_id, member_id)` - the framework now emits
  the "visible to members of this room/channel/project" EXISTS guard
  that apps previously hand-wrote into every flow (TeamUP: 11 copies
  across 4 flows). Join col matches the protected table's same-named
  column (child) or its `id` (parent - one declaration covers rooms AND
  messages); user col compares user id (email when name contains
  "email"). Enforced via `rowScopeClause` + member-of branches in EVERY
  inline scope builder in crud.go (list/read/update/delete/batch/tx);
  child create/update verifies membership in the (new) parent; parent
  creates AUTO-JOIN the creator (idempotent; failure → X-Member-Of-
  AutoJoin header). Tenant clause AND'd on group-keyed tables. Unit
  tests in `access_memberof_test.go`. While wiring this: found+fixed
  `validateAccessMode` rejecting valid `perm:` modes (validator predated
  v2.7.54).
- **Tenant bootstrap + tenant roles.** `groups.bootstrap: {org_table,
  founding_role}` → `POST /api/_groups/create` (org + founding
  membership, ONE transaction, session group attached immediately) -
  the chicken-and-egg every multi-tenant app re-invented (group key is
  stripped from client bodies by design, so plain CRUD can't found a
  tenant). `groups.role_field: member_role` loads the membership-table
  role into session.Roles (effective-group-aware) so `role:company_admin`
  access modes enforce IN-TENANT roles declaratively. Group-key NOT NULL
  insert failures now return a guided 422, not the raw SQLite error.
  New file: `groups_bootstrap.go`.
- **`ws_rooms:` WS room authorization.** `ws_rooms: {"room-:id":
  room_members(room_id, member_id)}` gates WS `join` (and therefore
  `broadcast`) on a membership row. Undeclared rooms unchanged; anon
  always refused on declared rooms; longest pattern wins; malformed
  rules dropped loudly + caught by the validator.
- **demo-password was BROKEN on the fleet** (field report flagged it):
  `set_demo_password` wrote the legacy `builder_env_vars` vault and only
  reloaded under `benmore host` - per-app units materialize env from
  `platform_env` ONLY, so prod returned ok:true and stayed public. Now
  routes through SetEncryptedEnv + applyEnvLiveAllInstances (same as
  set_env, env-scopable), and the gate is DECOUPLED from
  features.testing (DEMO_PASSWORD alone arms it; `RegisterDemoLoginRoute`
  split out so the login POST exists without the feedback machinery).
  Dashboard handler got the same fix.
- **`benmore deploy` now exists** (docs had always advertised it; CLI
  0.1.7 errored). create_app-on-first-run + push-all through the
  validators, writes `.benmore/app`, `--name`/`--env` flags
  (`cli_deploy.go`). usage + deploy.md updated.
- **DX batch:** `bm.flows.<wrong>()` error lists every registered flow +
  snake/kebab aliases resolve (file `company-setup.yaml` → registry key
  `companySetup` was unguessable); full-HTML email templates allowed
  under `emails/` + `templates/` (page-contract carve-out); schema push
  warns (non-blocking) when a column collides with protected names
  (`role`, `password_hash` - silently stripped on POST/PATCH);
  `benmore serve` runs RunCompleteCheck at boot (platform build; shim
  elsewhere); embedded Tailwind's bogus "cdn.tailwindcss.com should not
  be used in production" console.warn neutralized at embed-init.
- Topics updated: `access` (member_of), `scoping` (tenant_bootstrap,
  tenant_roles), `websocket` (room_authorization), `flows` (sdk_naming,
  reusable_fragments). Field-report items REFUTED as docs gaps (already
  existed): INSERT id via RETURNING, `for_each`/`parallel` loops, loud
  empty-ref errors + `||` fallback, `brand:` theming, tenant-scoped RBAC.

## v2.7.163 — browser_check session replay (Jun 2026)

**Agent session replay (revived the dormant "watch-it-test" path).**
`browser_check` (CLI/MCP only - DENIED to the in-browser builder) gained
`record: true` and `share: true`. It injects the already-embedded rrweb
recorder (`embedded/rrweb.min.js`, the same DOM-snapshot tech Microsoft Clarity
uses), captures the run, and replays it via the embedded `rrweb-player`.

- **Continuous multi-page capture.** A CDP binding (`__bmEmit`) +
  `Page.addScriptToEvaluateOnNewDocument` re-arm rrweb on EVERY document and
  stream each event to Go (`recEvents`), so a full-page navigation
  (login.html → dashboard.html) is ONE replayable session, not a buffer wiped on
  nav. SPA navigations were already one stream. Verified: a login→signup flow
  came back as 2 meta + 2 full-snapshots + the mutations between.
- **`record: true`** → owner-gated `replay_url` (`/platform/replay/{id}`,
  `authenticateDashboardRequest` + ownership). **`share: true`** (implies record)
  → a public capability link `/r/{token}` + an `embed_html` `<iframe>` to paste
  into an EDGE for a shareable demo video. Inputs masked at capture
  (`maskAllInputs`); shared recordings skip the 200-cap GC.
- **Edge-embed contract wired both ways:** the share page sets
  `frame-ancestors 'self' <apex> *.<apex>` so any `edge-<slug>` origin may frame
  it; `edgeCSP` gained `frame-src 'self' blob: <apex>` so the paste may embed it.
- **Routing gotcha (fixed):** the `/r/` share routes were dispatched in
  `host.go` (`benmore host` mode) but PROD runs `benmore router` -
  `router.go`'s `isPlatformPath()` is the real apex dispatcher and needed `/r/`
  too. The owner route worked only because `/platform/` was already routed.
- Storage: `platform_recordings` (router-side, `platformDB`). New file:
  `browser_replay.go` (`!cli && platform`). CLI prints `▶ session replay` +
  `🔗 public share link` + the embed. Documented in `skills/benmore-cli/SKILL.md`
  (NOT an `api(at:)` topic - it's an agent dev tool, not an app feature).

## v2.7.162 — cross-session bug batch (Jun 2026)

Six field-reported fixes from an app-building session:

- **Workspace seeding broke every promote.** `maybeAutoInstallSkill` ran for
  EVERY command incl. `serve` - on the fleet a per-app unit's HOME is the app
  dir, so `/opt/benmore/apps/<app>/Benmore/` (0700, app-user-owned) got planted
  inside the app tree and the promote/refresh rsync exited 23 → rollback, and a
  successful promote re-planted it. Fixed three layers: skip seeding for
  server commands (`serve`/`host`/`router`/`migrate-media`, cli_skill.go),
  `/Benmore` in `promoteExcludes` (defends the ~22 already-planted dirs), and
  `/Benmore/` in the scaffolded `.gitignore`. No host cleanup required.
- **Flow SQL params bound as TEXT → numeric guards NEVER fired.** SQLite ranks
  TEXT above any number without column affinity, so `WHERE :amt >= (SELECT
  SUM(...))` was always true ('5000' >= 10515). `sqlBindValue` (flows.go) now
  binds canonical-round-trip numerics as int64/float64 at BOTH bind sites
  (`:param` + `{{expr}}` pipe results); '01234'/'1.50'/'5e3' stay TEXT so
  identifier-shaped values keep byte equality. Sibling of hooks.go's
  more-permissive `coerceNumericBind` - divergence is deliberate, see comments.
- **Media URLs now durable.** `benmore upload`/confirm/list_media returned ONLY
  1h-presigned S3 GETs while docs said "persistent". `/platform/media/file/
  {filename}` now 302s S3-backed rows to a fresh presigned GET; confirm + CLI
  return it as `url` (read_url stays, for immediate renders); list paths
  rewrite to it.
- **upload_static double-prefix**: `path:"static/x.png"` landed at
  static/static/. `normalizeStaticPath` strips leading `/`+`static/` in both
  upload tools.
- **`benmore probe` flags are position-independent** (`positionalArgs` helper
  in main.go - reusable; bool flags must be declared).
- **Edges can load parent-app images**: edgeCSP img-src += parent app origin
  (prod instance, like bm.api); paste wire-cap now 2× (JSON escaping made
  ~178KB pastes exceed the old cap+2048) with the decoded 200KB limit as the
  single user-visible gate + an actionable 413.

## v2.7.152 — dev/prod environments (Jun 2026)

**Dev/prod environments (Model B).** One logical app now has TWO instances:
prod (`<sub>.benmore.ai`) + dev (`<sub>-dev.benmore.ai`), each its own
`data.db`/git/port, sharing one `platform_apps` row keyed on the logical
(prod) subdomain. Gated host-wide by `BENMORE_DEV_ENV` (LIVE on the prod
host). Apps are born dev (lazy prod); `benmore promote` ships code dev→prod
(code-only, prod data migrated with a backup, refuses destructive schema
changes without `--force`, `--dry-run` previews the migration); `seed_dev`
adds a dev instance to an existing prod app (code, empty data); `refresh_dev`
pulls prod→dev (all files / `--files` / `--data-only` / `--with-data`, with
schema reconciliation + prod's ENCRYPTION_KEY so encrypted data decrypts).
`--env dev|prod` threads through the MCP tools + CLI; the `_platform` dashboard
has a Dev|Prod switcher + Promote button (diff preview).

**Code-overwrite safety (every cross-env copy).** `copyAppCodeRsync`/
`copySelectedFiles` are PURE rsync (`--omit-dir-times` so writing into the
per-app-owned dest can't fail-with-damage on dir mtimes); destructive callers
wrap them in `overwriteWithRollback(dstDir, …)` (mcp_tools_promote.go), which
git-snapshots the destination first (`gitSnapshotHead`) and auto-rolls-back
(`gitHardRestore`) if the copy fails - a partial transfer never leaves an
instance half-stomped. An all-files `refresh_dev` also computes `refreshCodeDiff`
and REFUSES (`errRefreshWouldDiscard`) when it would overwrite/delete un-promoted
dev code, unless `force`; `dry_run` previews. Responses surface
`benmore git revert <app> <sha> --env <dev|prod>`. **This closed the footgun
where a bare `refresh-dev` in the dev-first workflow silently reverted dev to
prod's older code.** Each env has its OWN git (`.git` is in `promoteExcludes`),
so the snapshot lands in the right instance's history.

- **Single source of truth for env↔subdomain↔unit↔user↔dir:** `env_model.go`
  (`InstanceSubdomain`/`LogicalSubdomain`/`InstanceUnit`/`PerAppUser`/
  `resolveBuildEnv`). Per-row instance resolution: `accessAppInstance`/
  `resolveApp` (mcp_tools.go), `dashInstanceSub`/`getInstanceSubdomainForUser`
  (platform). NEVER hand-concatenate `-dev`.
- **Locked decision:** dev REUSES prod's per-app Linux user (dedicated
  `benmore-dev@.service` template, `%i`=logical sub) - a separate `-dev` user
  overflows useradd's 32-char cap. Isolation preserved by the mount namespace.
- **Platform-feature env-scoping** (see security.md + the handoff): env vars
  split per-env (`shared`/`dev`/`prod`); analytics/observe views + edge
  `bm.api` are env-aware; collaborators/billing/custom-domain stay
  per-logical-app by design. Full design + rollout +
  per-feature classification: `docs/handoffs/2026-06-03-dev-prod-environments.md`.
- **CLI env context (`benmore use dev|prod`):** persisted pin in
  `~/Benmore/.config/active_env` (`cli_env_context.go`); injected at the two
  chokepoints - `callPlatform` query + `mcpCall` args - so ALL env-specific
  commands inherit it (don't enumerate per-command flags). Server honors it via
  `mcpContext.Env` → `resolveApp` (one change covers all 24 call sites). `--env`
  overrides per-call; `whoami` shows the pin. Raw-path exceptions handled
  explicitly: `pull` (CLI + `/platform/pull`), `logs` (streaming), env-vars
  scope, `refreshBMTypes` (was hardcoded to the prod URL).
- **Per-env env vars are separated by default:** dashboard env tab has a scope
  selector (this-env / shared) + per-var scope badges + scope-aware Remove.
  **Critical fix:** `writeAppEnvFile` looked up `platform_apps` by the dev
  subdomain (`appID=0`) → dev instances got ZERO user env vars at runtime; now
  looks up by the LOGICAL sub (keeps the instance sub as the name for scope).
- **`benmore users set-password` no longer promotes to admin:** `create_superuser`
  gained `preserve_role` (CLI passes it by default; `--promote` opts in) and
  refuses to create a user in reset mode (`mcp_tools_superuser.go`).
- **Backups view** (`api(at:"environments")` → `env_vars`): prod-only S3
  snapshots, owner-gated list + download (basename-only, `validBackupName`).
  `backup_worker.go` skips `IsDevSubdomain`. `S3Storage.List`/`Fetch` (upload.go).
- App-builder reference: `api(at:"environments")`. **When you change dev/prod,
  update that topic + this entry.**

## v2.7.67 (May 2026)

**Server-side JS compute.** New `run: compute` flow step runs a TS
or JS function from `static/<module>.ts` server-side via embedded
goja (Go-native ES engine). For algorithms that don't fit SQL -
iterative math, root-finding, financial pro-formas (IRR/goal-seek),
scoring, simulation. The SAME module imports client-side for instant
recompute as the user edits AND runs server-side for authoritative
gates, cron jobs, webhook handlers. One algorithm, two execution
paths, byte-identical math. Sandboxed (no fetch, no fs, no process,
no require, no timers, eval+Function explicitly stripped). 5s wall-
clock timeout per invocation, overridable. Compile cache keyed by
import-graph mtime (reuses the framework's existing esbuild path -
compiled output is CommonJS-shape so goja can pull named exports).

End-to-end verified on an internal payroll demo app: pushed a
score-engine.ts with
loan amortization + bisection rate-finder, wired a flow with two
compute steps + a respond step, hit it with probe - got back
{loan: {monthly_payment: 1580.17, total_interest: 318861.22},
implied_rate: 6.0069} for a $250k/6.5%/30yr loan. Math checks out
to the penny. The flow registered as
`POST /api/_test/compute → compute_smoke` on app boot. New deps:
github.com/dop251/goja + transitive (dlclark/regexp2,
go-sourcemap/sourcemap, google/pprof). Binary grew 55MB → 65MB.

Use case: a finance workflow with a 352 LOC pure-math projection
engine can re-derive IRR server-side from a `before_insert` hook on
the forecasts table to actually enforce "IRR ≥ 8% before publish"
gates - the client value is no longer trusted.

## v2.7.59 (May 2026)

**Tenant-scoped RBAC.** `_benmore_user_roles` gains optional
`group_id` column - a grant can be GLOBAL (NULL group_id, applies
in every group context) or scoped to a specific group. Same user
can be `admin` in tenant A AND `viewer` in tenant B with no cross-
tenant leakage. Session loader queries
`WHERE user_id=? AND (group_id IS NULL OR group_id=?)` against the
effective group (act-as target, else native). Schema migrates on
boot via the table-recreate dance (SQLite ALTER can't drop the old
(user_id, role) PK). Grant/PATCH/DELETE accept optional `group_id`
parameter to target a specific scope. Lockout-guard counts BOTH
primary-column admins AND globally-scoped (NULL group_id) join-table
admins. Act-as DELETE no longer requires admin (a user stuck in
step-in had no way out before). Probe sessions resolve native group
via ResolveGroupID. End-to-end verified on an internal multi-tenant
demo app: group-1 user with admin scoped to group 1 elevates to
admin in group 1 (status 200); group-2 user with no admin grants stays 403
on the same endpoint. Revoke is dynamic - next request reflects the
demotion. **v2.7.58 also shipped:** MaskEncryptedFields honors
session.IsAdmin() + the full Roles slice (closes the multi-role gap
in the encrypted-field unmask path).

## v2.7.57 (May 2026)

**Integer / numeric encryption.** `fields:` in `encrypted.yaml` now
works on any declared column type, not just TEXT. The framework
stringifies INTEGER/REAL values deterministically before encrypt
(`strconv.FormatInt`, `strconv.FormatFloat('f', -1)` - shortest
round-trip) and coerces decrypted plaintext back to the declared
schema type at the read boundary (`scanRows` consults
`rows.ColumnTypes()` for INTEGER/REAL/NUMERIC affinity). API
consumers see numbers, not strings. `blind_index:` extends to
numeric columns for equality search; `?col__gt=...` / `?col__like=...`
on an encrypted column is silently dropped instead of returning the
misleading-empty result you'd get from text-comparing ciphertext.
End-to-end verified on an internal payroll demo app - paychecks.wages_cents
encrypted+blind, two 50000 rows produce the same HMAC, equality
search returns them, rotate-key rebuilds blinds, round-trip
preserves `int` type. v2.7.56 (multi-role admin elevation,
`Session.IsAdmin()`) shipped just before this - closed the
"admin via join table doesn't elevate" gap from v2.7.54.

## v2.7.55 (May 2026)

**Blind index for encrypted columns** - `blind_index: [col, col]` in
`encrypted.yaml` enables equality-search on AES-encrypted data. The
framework provisions a `<col>_blind` sibling column populated by
INSERT/UPDATE triggers with `HMAC-SHA256(plaintext)` under an
HKDF-derived key (separate from the AES key, rotated in lockstep with
it). A B-tree index on the sibling column makes lookups fast. Auto-CRUD
filters (`?col=value`, `?col__in=a,b`) transparently rewrite to query
the blind column. `benmore rotate-key` recomputes every blind index
under the new HMAC key. Backfill for pre-existing rows via
`benmore blind-backfill <app> <table>.<col> --as <admin>` or MCP
`blind_index_backfill`. SQL function `benmore_blind_index(text)` is
available in flows/hooks for explicit lookups. Validator + recent
docs updated. The deterministic-leak trade-off (duplicates of the
same plaintext share the same HMAC) is called out explicitly in
`security.md`. Substring/prefix/range search on blind indices NOT
supported by design - separate primitive territory.

## v2.7.54 (May 2026)

**Multi-role RBAC** - a user can hold any number of roles simultaneously
via the new `_benmore_user_roles` join table. `roles:` in app.yaml now
accepts `inherits:` so a role can pull in another's scopes transitively;
the effective scope set on a session is the UNION across every held role
(plus inherited parents). Two new access modes: `role:a,b,c` (any-of) and
`perm:<resource>.<action>` (granular permission check against the unioned
scope set). Admin endpoints at `/api/_auth/users/{id}/roles`
(grant/revoke/update-expiry/list) + `/api/_auth/roles` for discovery.
`GET /api/_auth/profile` now returns `roles[]` + `permissions[]`
alongside the legacy `role` field. Grants can be time-bounded via
`expires_at` (RFC3339); a 5-minute background sweep evicts expired rows
and audit-logs the eviction. Lockout-guard rejects revoking the admin
role from the last active admin. `rbac.go` is the central module; see
`.claude/rules/apps.md` and `.claude/rules/security.md` for the full
surface.

## v2.7.31–v2.7.40 (May 2026)

Cross-session friction audit landed across ten releases. Key additions:

- **v2.7.39**: `success_when:` LHS double-wrap fix - GHA-normalized `${{ steps.X.outputs.Y }}` references in the `if`-condition LHS were being re-wrapped as `{{{{...}}}}` and silently halting flows with `template_unresolved`. Fixed in `flows.go evaluateFlowCondition`. Detected during fresh-session feature test against `/api/github-status`.
- **v2.7.40**: doc sync pass - 9 new `api({at:"<topic>"})` entries (count / presence / cache / markdown / optimistic / live-scoped / success_when / auto_memberships / recovery), `docs/agent/build.md` SDK table + topics list + auto-CRUD section updated, scaffolded `CLAUDE.md` template lists the new primitives + the recovery commands, `SKILL.md` typo `/api/_files` → `/api/_upload` in the upload recipe.

Earlier in the audit:

- **`bm.table('x').count()` + `?count=true`** (v2.7.33): TRUE row count, no LIMIT cap. Use instead of `(await list()).length`.
- **`bm.live.scoped(table, fetchFn, {debounce})`** (v2.7.37): live subscription with generation-counter dedupe + visibility hook + primed-on-mount.
- **`bm.api.optimistic({apply, request, snapshot, revert})`** (v2.7.37): optimistic local mutation + reconcile.
- **`bm.presence(slug)`** (v2.7.35): the canonical "who's live in this thing right now" pipeline - pagehide + 18s heartbeat + 60s server sweep, all wired.
- **`bm.cache.namespaced(name, version)` / `.persistent()`** (v2.7.35): self-busting sessionStorage / localStorage.
- **`bm.upload(file)`** (existing) + `bm.markdown(text)` (v2.7.35): tiny safe HTML renderer.
- **POST returns the full inserted row** (v2.7.33), not `{id, status}`.
- **CSP allowlists `rsms.me`** (v2.7.33) so Inter loads.
- **Scaffold ships dark-mode CSS variables** (v2.7.35) - `[data-theme=dark]` + `prefers-color-scheme` + `--surface`/`--card` tokens.
- **Scaffold ships `*[hidden]{display:none!important}`** (v2.7.33) so element.hidden actually hides.
- **`auto_memberships:` in app.yaml** (v2.7.35): "every active user auto-joins every row of <parent>" synthesized as on_insert hook.
- **`success_when:` on `run: api`** (v2.7.37): reject 200-with-error-envelope upstream responses.
- **`?q=` FTS5 auto-escapes `.`, `@`, etc.** (v2.7.37) so email-shaped queries work.
- **`benmore sql --write` fires SSE refresh broadcasts** (v2.7.35); same for hook SQL updates (v2.7.37).
- **`benmore delete-file <path>`** (v2.7.31) - there was no path to delete a server file before this.
- **`benmore integrity-check <app>` + `benmore restore <app> [--from]`** (v2.7.37): last-resort recovery surface.
- **DB-malformed root cause** (v2.7.32): the missing `ExecReload=` in the systemd unit meant every push fell through to SIGTERM-restart instead of SIGHUP hot-reload. Combined with VACUUM INTO for pre-migrate backups + WAL checkpoint on shutdown, the "rows vanish after flow ends" narrative is dead.
- **Migration generator is idempotent against live drift** (v2.7.37): no more `duplicate column name` loops.
- **401 hint nudges agents toward `access.read: anon`** (v2.7.37) when the table looks public-feed-shaped.
- **Step-type-specific flow error hints** (v2.7.37) - sql / api / parse / respond / etc. each have their own remediation pointers.


---

## Earlier history

Releases prior to v2.7.31 are captured in the git tag history (68 tags as of
v2.7.184). Notable lineage:

- **v2.7.21** — TSX-by-default: embedded esbuild + per-app typed SDK (`bm.d.ts`); the React/Preact SPA scaffold was removed in v2.4.0.
- **v2.7.x** — removal of the cross-platform compiler (RN/Flutter/Tauri) and the journey/design-phase tooling.
- **Pre-2.7** — see `git log` and the design notes under `docs/handoffs/`.

Browse any release in full:

```bash
git tag --sort=-v:refname        # list every release tag
git show v2.7.164                 # inspect a specific release
git log v2.7.152..v2.7.164        # diff between two releases
```
