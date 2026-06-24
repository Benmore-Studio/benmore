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
