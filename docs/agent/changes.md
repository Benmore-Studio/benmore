# Behavior changes by release (newest first)

What changes for an app when the runtime or the CLI is upgraded: an answer that
is different, something a builder has to change, or a new capability. Each entry
is one sentence followed by the topic that holds the full contract; read the
topic before you write code. `api(at:"<topic>")` is the MCP tool call; from the
CLI the same reference is `benmore api <app> <topic>`. A deployed app's `/health`
names the runtime version it runs, and `benmore version` names the CLI.

`## Next release` lists changes that no production release carries yet. An entry
is added there only when a working app behaves differently or a builder must
change something, and the section gets its version and date when the release is
tagged. Fixes and internal changes are not listed here; the framework
repository's `CHANGELOG.md` records every change.

## Next release

## 2.7.330 (2026-11-11)

- **The admin panel no longer writes an account's sign-in factor, and changing a sign-in address there signs the account out.** `POST /_admin/api/_benmore_users/create` and `/update/<id>` drop `totp_secret`, `backup_codes`, `mfa_last_totp`, `mfa_last_totp_at` and `email_grandfathered` (named in `X-Stripped-Fields`), and the user forms have no input for them. Changing another admin's `email` (or the `auth.identifier` column) answers 403 `admin_identifier_protected`; changing any other account's, or your own, saves it and ends that account's sessions, API tokens and connector grants and cancels its unused reset links. `benmore docs auth.admin_panel_accounts`.
- Flow, hook and page SQL can no longer create, drop or alter framework objects (`_benmore_*` tables, indexes, triggers and views, or an index or trigger on such a table) or set `PRAGMA writable_schema`: the step fails with `app SQL may not ...`. Under `compliance: hipaa` it also cannot UPDATE or DELETE audit rows. Reading and writing rows of framework tables, and DDL on your own tables, work as before. See `api(at:"schema.framework_tables")` and `api(at:"audit.append_only")`.
- In an app with `groups:`, an approval request on a tenant's record is assigned only to an approver in that tenant: naming an account of another tenant (or of none) still answers 200 `pending`, but that account is not notified and neither lists nor decides the request, and an approver who leaves the tenant stops listing and deciding it. See `api(at:"scheduling")` (`approver_tenant`).
- An approved connector command's SQL is not checked against the table's `access:` rule or row scope: a caller who holds the command's permission can change every row the SQL matches, and in an app with no `roles:` block every account holds every `<table>:write` scope. Check that the prepare and apply SQL of each command carries its owner, tenant and role predicate, bound from the actor (`${{ user.id }}`, `${{ user.group_id }}`, `${{ user.role }}`). See `api(at:"connector")` (`connector_hooks_effects`).
- `benmore deploy` and the save hook leave hidden directories outside `static/` (such as `.scratch/` or `.sdd/`; not `.well-known` or `.github`) in the workspace instead of uploading them, and `benmore sync-status` lists them as `kept_local` and the ones an app already holds as `server_kept`: keep source the app needs in a plain directory or send it with `benmore push <file>`, and read `api(at:"sync-status")` → `excludes`.
- Some refusals changed status to the documented one; no successful request changed. `/api/_transaction` answers 404 (it was 400) for an update or delete of a row that is missing or outside the caller's scope. A create or update naming a parent row that does not exist answers 422 naming the column (it was 400) when the parent table is readable by everyone, and for admins. Admin-only endpoints such as `/api/_audit` and `/api/_jobs` answer 401 (it was 403) when the request carries no valid credential. `/sse/events` and `/ws` answer 403 `mfa_enrollment_required` / `password_change_required` (it was 401) to a held account, and MFA setup answers an API token 403 (it was 401). Check client code that branches on those statuses. `POST /settings/password` accepts a JSON body, and `GET /api/_audit` is recorded in the read audit. See `api(at:"batch")` (`cross_table_transaction`), `api(at:"scoping")` (`foreign_keys`), `api(at:"auth")` (`credential_limits`) and `api(at:"mfa")` (`existing_credentials`).
- `run: extract_text` page text now reads as lines: the words of a line are separated by a space, lines by a newline and paragraphs by a blank line (it was one word per line), so `LIKE` phrase searches over stored text match. Text stored by earlier runs keeps the old shape until you extract the file again; code that split `text` on newlines to get words should split on whitespace. Read `api(at:"pdf")` → `extract_text`.
- A `transaction: true` flow whose respond step cannot produce its answer (a `${{ }}` reference with no value: 500 `template_unresolved`) rolls the transaction back instead of committing it: no row, queued job or notification of that request is kept, so it can be sent again; a flow without `transaction: true` is unchanged. See `api(at:"flows")` (`transactional_responses`).
- A flow gated `on.request.role: admin` answers 403 to a caller who holds `admin` only as a tenant role (a `groups.role_field` value, `groups.bootstrap.founding_role: admin`, or a grant scoped to one group): only a global admin passes it, as a request, an async job, a scheduled run or a connector tool. Flows gated on any other role name are unchanged. If a tenant's own admins should call the flow, check the caller's membership row in its first step, or gate it on a tenant role with another name. See `api(at:"rbac")` (`gotchas`).
- A flow's `on.request.role` takes one role name: `role: "warehouse,manager"` is one name nobody holds and admits only a global admin. A write of such a file, `benmore check` and the app log warn about it, about a role name the app declares nowhere when `roles:` is declared, and about `role: admin` where tenant members hold a role named admin; nothing about who passes a gate changes. For several roles, write `auth: required` and refuse in the first step. See `api(at:"flows")` (`role_gate`); `transaction` is the new key for `on.request.transaction`.
- A migration file can no longer set `PRAGMA writable_schema`, create a trigger whose name starts with `_benmore_`, drop a `_benmore_*` trigger from a `_benmore_*` table, or create a TEMP table or view with a `_benmore_` name; under `compliance: hipaa` it cannot change the audit tables or their rows. The file fails with `a migration may not ...`. Columns, indexes and your own triggers on framework tables work as before. See `api(at:"schema.framework_tables")`.
- PDFs from `GET /pdf/<page>` now hold only the page: the cookie-consent banner and the feedback widget are no longer printed on it, and neither is Chrome's print header and footer (date, title, page count and an internal address); connector PDF artifacts lose that header and footer too. If you relied on the footer's page count, number the pages with a CSS page margin box in the page's own `<style>`, e.g. `@page { margin: 20mm; @bottom-right { content: counter(page) " / " counter(pages); } }`: read `api(at:"pdf")` → `gotchas`.
- **The admin panel shows the audit and credential tables and no longer writes them.** `POST /_admin/api/<table>/create`, `/update/<id>` and `/delete/<id>` answer 403 `admin_table_read_only` for `_benmore_audit_log`, `_benmore_read_audit`, `_benmore_sessions`, `_benmore_api_tokens` and the other credential tables, and their pages have no Create, Edit or Delete control. Read-audit events of a support session carry `impersonator_user_id` / `impersonator_email`, and `GET /api/_audit/reads` returns them. `benmore docs audit.impersonation`, `audit.read_history`, `auth.credential_limits`.
- A `/ws` `subscribe` now delivers exactly the tables it named. A name the app has no table for is answered with `{type:'error', tables:[...], body}` and subscribes nothing; a subscribe whose names are all unknown used to leave every table's events on and now leaves none (the generic `{type:'change', action:'refresh'}` still arrives), so check the table names your client sends. `_benmore_notifications` and `_benmore_presence` are names a connection can subscribe to: a connection that sent a table subscribe gets the recipient's notification event when it names `_benmore_notifications` (before, it never did). A presence `leave` from a caller who is not a member of the slug's `ws_rooms` room answers without `members`. See `api(at:"websocket")` (`protocols`), `api(at:"notifications")` and `api(at:"presence")` (`endpoint`).
- A `run: respond` with a status and no body (`with: { status: 204 }`, a refusal written as `with: { status: 403 }`) answers that status with an empty body and ends the run; it used to do nothing, so the steps after such a refusal ran and a flow ending on one answered 500 `flow_no_response`. A respond step that has a `body` or `json` is unchanged. Check any respond step you wrote without a body: the run stops there. See `api(at:"flows")` (`step_types`, `response_reachability`).
- A version revert (`POST /api/<table>/<id>/revert/<version>`) writes only the columns whose value it changes, and its `before_update` hooks get only those in `_submitted` and in their SQL placeholders. A hook that refuses a client-set column refuses a revert only when the revert would change that column; a hook that expects a column in every update does not find it on a revert that leaves the column as it is. See `api(at:"versioning")` (`revert_security`).
- An approval request that names an app table in another letter case (`Docs` for `docs`) is an approval on that table: the requester must be able to read the record, the approver of a tenant's record must be in the tenant, and `table_name` is stored with the table's own spelling. See `api(at:"scheduling")` (`approvals`).
- `bm.query.tableKey(table, opts)` returns the key `bm.query.table(table, opts)` caches under, so `bm.query.subscribe(bm.query.tableKey(t, opts), render)` renders the read and its live refetches; code that matched its own cache entries by the old `['table', name, spec]` shape should use the returned key instead. Read `api(at:"sdk.query_live")` and `api(at:"sdk.query_live_snippet")`.
- `GET /api/_signed_url` (and `bm.signedUrl`, which calls it) reads `expires_in` as whole seconds or a duration (`30s`, `90m`, `2h`), and answers 400 with `code: "invalid_expires_in"` for a value it cannot read or one under a second (`abc`, `0`, `-5`, `1.5`), where it used to answer 200 with a one-hour link (four hours for audio and video). A request that sent a duration gets the shorter link it asked for; `bm.signedUrl(path, { ttlSeconds: 0 })`, a negative or a fractional `ttlSeconds` throws. Leave the value out for the default, or send whole seconds from 1 to 21600. See `api(at:"signed-urls")` (`lifetime`).
- On a table with the `groups:` key whose rule is `group`, `owner_or_role:`, `role:`/`perm:` or not declared, a signed-in user with no tenant (removed from it, or never in one) no longer reaches a row that carries a tenant just because its `user_id` is theirs: list, read, `?include=`, `/api/_query`, `/api/_my-data`, versions, locks, signed URLs, sharing, update and delete answer as for a row that is not theirs, until they are a member of that tenant again. Unchanged: an action declared `self` (declare it for rows that stay with their owner whatever tenant they name), rows shared with them, their own rows with an empty tenant key, and their own row of the groups membership table. See `api(at:"scoping")` (`missing_group`).
- **`benmore test` checks what a test wrote, so some tests change result.** `{{name}}` is read inside `expect`: a `not_contains: "{{name}}"` that always passed now compares the saved value, and an `expect` that names a variable nothing saved fails its step. A cookie-authenticated step with no body (`api: "DELETE /api/notes/1"`) sends the CSRF token in a header, so one that expected the runner's 403 now gets the app's real answer. `users:` accounts are created before `setup:` runs, and a step acts as one with `set_auth: "bob_token"`. `benmore docs verification.test_variables`, `verification.test_json_csrf`.
- A workflow transition's `when:` sees who makes the transition: `user_id`, `user_email`, `user_role`, `user_roles` and `user_group_id` are the caller's (on a table with a `user_id` column, `user_id` was the row's own value and is now the caller; the row's owner is `old_user_id`), and `old_<column>` holds the stored value where it was NULL, so `when: "old_user_id != user_id"` keeps a requester from deciding their own request. A before_update hook fired by a transition also sees `old_<column>` (`old_status` is the state it leaves). `GET /api/<table>/<id>/transitions` and the `<transitions>` tag no longer list a move whose `when:` is not met for the caller, nor any move of a command-owned state column, and list targets in alphabetical order. Check each transition `when:` that names one of those keys or `old_`. See `api(at:"hooks")` (`when_conditions`) and `api(at:"workflows")` (`transition_writes`).
- A refused file answers 415 (type or extension) or 413 (size) on a multipart `POST /api/<table>` and on `POST /api/_files` as on `POST /api/_upload`, and with `features.uploads: false` the two upload routes answer a JSON 404 with `error: uploads_disabled`. A multipart create no longer stores a file part whose field is not a column it writes; the field is named in `X-Ignored-Fields` or `X-Stripped-Fields`. Read `benmore docs uploads.multipart_bodies`.

## 2.7.327 (2026-11-10)

- `benmore docs` reads the reference offline in every edition, the framework edition included: `benmore docs <topic>` prints a topic (a large one as an index of its keys), `benmore docs <topic>.<key>` one key, `benmore docs index` every topic and `benmore docs --search "<words>"` the keys that answer a question, with the answers `api(at:"<topic>")` gives; a name that printed the whole build guide (`benmore docs auth`) now prints that topic, while `connector` and `harness` still print their guides (`--reference` reads the topic). See `benmore docs --help`.
- `benmore test` fails a test it cannot read in full instead of running it without that part: a key the runner does not read (`expects:` for `expect:`), no steps, a step with no action or more than one, or an `expect` key the step's action does not check (`contains` on a `sql` step). See `api(at:"verification")` (`test_keys`).
- On the hosted platform, each account has a media storage allowance from the owner's plan (1 GB on free, 10 GB on Pro, 100 GB on Scale), summed over all its apps: an upload that would exceed it answers 507 `storage cap reached` with code `media_storage_limit`, while stored files keep serving and can be deleted. See `api(at:"uploads")` (`storage_allowance`).
- On the hosted platform, plans are billed on published apps: the first `benmore promote` of an app needs a free live-app slot on the app owner's plan (none on free, 5 on Pro, 25 on Scale, more as a paid add-on) and is otherwise refused with `upgrade_required` and the way out, while an app that is already published can always be promoted; collaborators take seats on the owner's plan. See `api(at:"environments")` and `api(at:"collaborators")`.
- On the hosted platform, `benmore remove-production <app>` (owner only) takes an app out of production and frees its live-app slot; nothing is deleted, and `benmore promote <app>` publishes it again on the kept data. See `api(at:"environments")` (`remove_production`).
- A refusal names where its rule is documented: a refused write and a `benmore check` finding end with a `docs: api(at:"<topic>.<key>")` line, and JSON answers (check findings, the common auto-CRUD, flow and sign-in errors, a failed connector tool call's `_meta`) carry a new `docs` field with that address; no existing field changes, so a client that compares a whole error body must allow the extra field. See `api(at:"errors.docs_field")`.
- A scheduled `kind: flow` task interrupted by a crash is re-run only when its flow declares `idempotent: true`; otherwise it ends as `failed` instead of being re-run up to 3 times. See `api(at:"scheduling")`.
- A YAML test can run one sweep of due scheduled tasks with `flush: scheduled`. See `api(at:"scheduling")`.
- `run: email`, `run: sms` or `run: webhook` inside a `transaction: true` flow sends even when a later step rolls the transaction back: push and `benmore check` warn about each such step, so queue the send with `run: enqueue`. See `api(at:"flows")`.
- `auth.require_mfa_for_roles` accepts `*` to require a TOTP factor for every account. See `api(at:"mfa")`.
- `auth.idle_timeout` (for example `15m`, at least `2m`) ends a session after that long without a request; background polling and heartbeats do not count as activity, and `bmr_` API tokens are unaffected. See `api(at:"auth")`.
- app.yaml `compliance: hipaa` opts an app into stricter defaults (private uploads, MFA for every account, a 15-minute idle timeout, append-only audit tables, no GitHub sync, no production data in dev); once deployed the key cannot be removed. See `api(at:"compliance")`.
- Push and `benmore check` refuse a workflows.yaml `field:` that is not a column of the table; a `table:` or `field:` whose letter case differs from the schema is read as the schema spells it. See `api(at:"workflows")`.
- A create, a bulk import, the founding membership of `/api/_groups/create` and a member-of auto-join always start a workflow row in `initial`, whatever state value was sent; push and `benmore check` refuse a state column `@default` that differs from `initial:`. See `api(at:"workflows")` and `api(at:"import")`.
- Push and `benmore check` refuse a workflow with `timeout:` on an encrypted state column (such timeouts never fired). See `api(at:"workflows")`.
- A workflow timeout fires the table's on_update hooks, webhook subscriptions and on_update flows, like any other transition. See `api(at:"workflows")`.
- Flows can read the text of an app-private PDF page by page with `run: extract_text` (`with: { source_path, record: {table, id}, ocr? }`); it runs only in async, enqueued or scheduled flows, and `record:` must name the row that owns the file. See `api(at:"pdf")`.
- Platform email and SMS daily quotas, and the SMS cap of 5 messages per 10 minutes to one number, are also counted across all apps of the owner's account, and an account can create at most 60 apps in 24 hours. See `api(at:"email")` and `api(at:"sms")`.
- A database restore does not run finished work again: queued jobs and scheduled tasks in the snapshot take the outcome they already had, or are held as `failed`/`cancelled` with the reason, and `every <interval>` cron schedules count from their last real run. See `api(at:"recovery")`.
- `?q=` matches every word whatever its length (a 1-2 character word used to turn the whole query into one literal phrase); more than 8 different 1-2 character words in one search answers 400. See `api(at:"search")`.
- `probe_route`, `benmore probe` and an `api` call follow a redirect only inside the app; one that points anywhere else is returned as its 3xx with `location` instead of being fetched. See `api(at:"harness")`.
- The testing-mode reset (`POST /api/_testing/reset`, the admin panel's Reset & Reseed) accepts a seeds.sql of app-data INSERT/UPDATE/DELETE/REPLACE/WITH statements only, and a refused or failing seed answers 422 naming the statement, with no data changed. See `api(at:"recovery")`.
- `POST /signup` starts MFA enrollment (`{mfa_setup_required, redirect}` or a 303, and no session) when the new account's role is in `auth.require_mfa_for_roles`, as `/login` does. See `api(at:"mfa")`.
- A schema field, custom field or table can be named with an SQL reserved word (`order`, `group`, `from`, `to`, `index`, `select`). See `api(at:"schema")`.
- `DELETE /api/_scheduled/{id}` answers 200 `cancelled` only when it cancelled the task, 409 `{error, status}` for a task of yours that is running or finished, and 404 for an id that is missing or someone else's; it used to answer 200 in every case. See `api(at:"scheduling")`.
- `/api/` refusals that were sent as text/plain (the request limiter's and NDJSON ingest's 429, `admin required` on `/api/_analytics/*`, and others) answer the JSON error envelope with the same status and text; ingest's 429 carries `Retry-After`. See `api(at:"errors")`.
- `benmore test` answers an account held for MFA enrollment or a password change as the server does (403 `mfa_enrollment_required` / `password_change_required`, or the redirect on a page) instead of 401. See `api(at:"verification")`.
- `/api/_schema` marks a column `writable` only when a create stores it, and the OpenAPI `Create<Model>`/`Update<Model>` schemas list only columns a request stores (no computed columns, workflow state column, command-owned columns or tenant key). See `api(at:"components")` and `api(at:"machine-discovery")`.
- Promote refuses code whose migration would fail on production's data (the dry run and the preview say `would_fail`; force overrides it), and `restore_db` refuses a snapshot the current code cannot migrate unless forced. See `api(at:"environments")` and `api(at:"recovery")`.
- A support (impersonation) session ends with the admin sign-in that started it and with any revocation of that admin's credentials. See `api(at:"auth")`.
- An approval addressed by `approver_email` belongs to the account that has verified that address: an unverified account neither lists nor decides it, and the address is matched in any letter case. See `api(at:"scheduling")`.
- Auto-CRUD list filters and `/api/_query` where values on a DateTime column compare instants when the value is an ISO-8601 date or date-time, instead of comparing the stored text; sorts on a DateTime column other than `created_at`/`updated_at` order by instant. See `api(at:"scoping")`.
- Every app answer with status 400 or above carries `Cache-Control: no-store` (added to a flow's own value), so a CDN cannot store an error. See `api(at:"flows")`.
- `on.request.contract` describes a flow's request body, query, required headers and responses in the developer OpenAPI (it adds no runtime validation); with `docs: false`, only an admin on an unscoped credential can read `/api/_openapi`. See `api(at:"flows")` and `api(at:"machine-discovery")`.
- A query or form value that differs from a `:param` path value of the same name answers 400 before any flow step; a JSON body value of that name is ignored (the path wins). See `api(at:"flows")`.
- Read audit also records flow `run: sql` reads, `/_admin` pages and background reads (`system:<kind>`), with the client IP. See `api(at:"audit")`.
- A workflows.yaml write (or a promote, checked against production's rows) that removes a state rows still hold is refused; `benmore check` names rows left in an undeclared state. See `api(at:"workflows")`.
- `benmore help` shows the common workflows and `benmore help all` every command; commands that change something print a `target:` line on stderr naming the app and environment, repeated selector flags with different values exit 2, and `benmore verify` marks skipped checks `not_run` and lists `next_steps`. See `api(at:"cli-contracts")` and `api(at:"verification")`.
- App errors from the browser and the server are grouped and scrubbed in the app, shown by `benmore errors`, the `get_errors` MCP tool and the dashboard, and can be forwarded to Sentry or Slack; cron jobs can report check-ins (`monitor:` in cron.yaml). See `api(at:"errors")` and `api(at:"cron")`.
- Nobody approves their own request: `POST /api/_approvals` naming yourself as `approver_email`, and `/decide` on a request you made, answer 403, for admins too. See `api(at:"scheduling")`.
- `POST /api/_approvals/{id}/decide` answers 409 `{error, status}` for the opposite decision on an approval already decided, and 404 (admin) or 403 for an unknown id; repeating the same decision stays 200. See `api(at:"scheduling")`.
- `auth.session_duration` takes a positive Go duration (`12h`) or whole days (`7d`); push and `benmore check` refuse any other value (`1w`, `12`, `0`), which used to mean 30 days silently (a deployed app keeps loading, with a warning). See `api(at:"auth")`.
- Push refuses a table named like a framework route (`_upload`, `_jobs`, `_notifications`, ...) and suggests an `@@map` name. See `api(at:"schema")`.
- An admin's scoped API token or scoped session cannot read the feedback inbox or the detailed `/health` report, stop another user's stream, release another user's lock or decide someone else's approval; those need an admin sign-in or an unscoped token. See `api(at:"auth")`.

## 2.7.326 (2026-11-05)

- Acquiring a record lock answers `expires_at` in RFC 3339 form (`2026-11-05T04:04:21Z`), like the lock status and the 409 answer. See `api(at:"locks")`.
- Batch create and NDJSON ingest write one `insert` audit entry per created row with its id (batch used to log `create`, ingest a single `batch:<count>` entry). See `api(at:"audit")`.
- Auto-CRUD list filters on a Boolean column accept `true`/`false` or `1`/`0` and answer 400 for any other value. See `api(at:"scoping")`.
- Auto-CRUD reads name an `include` entry or a sort they did not apply in the `X-Ignored-Params` response header, and `?include=` also accepts the Prisma relation field name. See `api(at:"scoping")`.
- After a key rotation, equality filters on a blind-indexed column find rows written before the rotation; an app whose key was rotated on an earlier runtime needs one `blind-backfill --confirm` per blind-indexed column. See `api(at:"encryption")`.
- With `auth.require_verified`, signup, login and the token exchange give an unverified account no session and answer 403 `email_verification_required`; a deactivated account's sign-in answers exactly like a wrong password. See `api(at:"auth")`.
- On a page with `layout:`, `{{...}}` text that arrives in a URL parameter or a stored row is shown as text and is not expanded. See `api(at:"ssr")`.
- `refresh-dev` with data revokes every session, token, passkey and connector grant in the copy dev receives, so users sign in to dev again. See `api(at:"environments")`.
- When `roles:` does not declare `admin`, a global admin holds every scope instead of getting 403 `scope denied`; declare `admin` under `roles:` to narrow it. See `api(at:"rbac")`.
- Declare `on.request.permissions:` on every flow that an integration calls with a scoped token: such calls are logged and will be refused once enforcement is switched on; `GET /api/_auth/users` requires `_benmore_users:read` on a scoped credential. See `api(at:"flows")` and `api(at:"auth")`.
- Push and `benmore check` refuse a computed field or an aggregate that reads an encrypted column (a null test and `COUNT(col)` stay allowed); an app that already has one keeps loading. See `api(at:"encryption")`.
- A refused `run: purge_current_user` answers 400 `confirmation_required` or 403 `credential_not_allowed` instead of 500 `flow_no_response`. See `api(at:"auth")`.
- `bm.room()` reconnects and joins again after the server closes its socket, queues up to 16 sends while disconnected and throws when a send cannot be queued; a refused join stops it and reaches `on`/`onAny` as `bm:error`. See `api(at:"websocket")`.
- `auth.require_mfa_for_roles` holds every existing session and API token of an account with a listed role and no TOTP factor: until it enrolls, APIs answer 403 `mfa_enrollment_required` and pages redirect to the setup page. See `api(at:"mfa")`.
- A root server-rendered page named `event-:id.html` serves `/event/:id` and binds `:id`; push and `benmore check` refuse a malformed `:` filename or a route that another page or flow already answers. See `api(at:"ssr")`.
- The last-admin guard counts only permanent, usable admins (not deactivated, not on a temporary password, not on an expiring grant) and also covers deactivating or deleting that account; make another account a permanent admin first. See `api(at:"rbac")`.
- `RecordForm` and `WizardForm` send only the fields that changed, save a DateTime as the local time entered and send Booleans as true/false; `/api/_schema` reports a column's `default` as the plain value and leaves out `now()`/`uuid()` defaults. See `api(at:"components")`.
- A change to a table with no tenant key (or a `groups.shared` catalog) is announced to its readers in every tenant, and a WebSocket that never sends `subscribe` receives change events for every table it may read. See `api(at:"realtime")` and `api(at:"websocket")`.
- Profile values under `user.<column>` and the caller's email count as request input: push and `benmore check` refuse them in `run: sql_dynamic` text and in the scheme or host of a credentialed `run: api` call, so bind them with `:name` in `run: sql`. See `api(at:"flows")` and `api(at:"sql-dynamic")`.
- `for_each` iterates JSON text of an array and fails the step when a non-empty source is not a list (it used to run zero times and answer 200); push and `benmore check` refuse a `steps.<id>` reference that names no step in the flow. See `api(at:"flows")`.
- `auth.api_tokens: false` also stops existing `bmr_` tokens and token-exchange sessions while it is off (401); they work again when it is switched back on. See `api(at:"auth")`.
- A role grant that carries `group_id` answers 400 in an app without `groups:`. See `api(at:"rbac")`.
- `pwa:` also applies to `static/*.html` pages (manifest link, theme color, service-worker registration), and `offline: true` answers a failed navigation with the offline page, never a stored page. See `api(at:"mobile")`.
- `benmore env <app> list` names the scope of each value and `--env shared` lists only shared values; `env unset KEY --env <scope>` exits 5 when the key has no value in that scope. See `api(at:"environments")`.
- Only a dev instance admits the anonymous `/sse/events` reload stream; a testing-mode production instance answers 401. See `api(at:"sse")`.
- Flows can notify a user with `run: notify` (`with: { user_id, title, body?, link?, type? }`), from any trigger including cron. See `api(at:"flows")` and `api(at:"notifications")`.
- A JSON `POST /login` for an account that must pass or set up MFA answers `{mfa_required | mfa_setup_required, redirect}` instead of a 303, and `bm.auth.signIn` goes there; new scaffolds ship the step pages under `static/` (`verify-mfa.html`, `mfa-setup.html`, `verify-otp.html`, `forgot-password.html`, `reset-password.html`), which an older app copies from a new scaffold. See `api(at:"auth")` and `api(at:"mfa")`.
- A `<query>` template key that names no page value stops the page with a 500 and a request id instead of binding NULL (URL values are `{{param_<name>}}`); POST forms need no hand-written `_csrf` field. See `api(at:"ssr")`.
- `/.well-known/security.txt` answers 404 unless `seo.security_contact` is set or the app ships its own file, and `bm.d.ts` types nullable columns as `T | null`. See `api(at:"frontend")`.
- Push, `benmore delete-file` and `benmore check` build the TSX bundles a change affects and refuse an import outside `static/`, an import that does not resolve, a missing export, a bare package import, deleting a module another script imports, and an `<include>` whose target is missing. See `api(at:"frontend")`.
- In a `transaction: true` flow, the `on_error` handler does not see the outputs of writes the rollback undid. See `api(at:"flows")`.
- An update that sends back the `****` mask of an encrypted field keeps the stored value and names the field in `X-Ignored-Fields`, instead of saving `****` over it. See `api(at:"encryption")`.
- A computed column that encrypted.yaml also lists is stored encrypted; rows written earlier stay plaintext until they are next written (`UPDATE <table> SET <column> = <column>` seals them). See `api(at:"encryption")`.
- `GET /api/_aggregates` and `{{aggregate.<name>}}` serve only the aggregates app.yaml declares, and a failing aggregate keeps its last value and is listed with `stale: true`, `stale_since` and `error`. See `api(at:"GET /api/_aggregates")`.
- A version revert keeps hidden credential columns (`*_token`, `*_secret`, `api_key`, ...) at their current value and lists them in `kept` with reason `hidden`. See `api(at:"versioning")`.

## 2.7.325 (2026-11-04)

- A masked encrypted field reads `****` for every non-NULL value, numbers and Booleans included, instead of keeping the last four characters and the length. See `api(at:"encryption")`.
- gotmpl page `queries:` bind `:param_<name>` and the route's parameters as SQL NULL when absent or empty, so `(:param_status IS NULL OR status = :param_status)` is an optional filter; a page render error shows its text only to a signed-in admin and the request id to everyone else. See `api(at:"frontend")` and `api(at:"errors")`.
- `benmore push` and `benmore deploy` exit non-zero and print each error when the files are saved but the app's source check reports errors, such as two flows on one route. See `api(at:"recovery")`.
- `benmore test` runs on a disposable copy of the app's source, so it works in a workspace linked by deploy or pull and never touches the workspace's `data.db`. See `api(at:"verification")`.
- A workflow transition's `role:` takes an any-of list (`role: "owner, manager"` or `role: [owner, manager]`); push and `benmore check` refuse a `role:` that names no role. See `api(at:"workflows")`.
- Reverting to a version older than a column keeps that column's current value, and the answer lists every column left as it was in `kept: [{column, reason}]`. See `api(at:"versioning")`.
- `DownloadMyData` downloads the signed-in user's own data from `GET /api/_my-data` (profile, every row they own, the latest 1,000 audit events) instead of one page of every readable table. See `api(at:"components")`.
- `/api/_query` accepts `contains`, `starts_with` and `ends_with` (literal text) beside `like`. See `api(at:"query")`.
- An MCP command dependency must return exactly one `id` column: review, `benmore mcp check`, push and `benmore check` refuse any other shape, and a constraint failure in an approved write answers `constraint_failed` with `retryable: false`. See `api(at:"connector")`.
- When the server defers a reload (5 reloads in a minute, or a slow last reload), `benmore push` and `benmore deploy` say the change is saved but not live yet and wait up to 3 minutes for it; `write_file` and `edit_file` answer `reload: {scheduled_at, reason, deferred, message}`. See `api(at:"recovery")`.
- Insert events (webhook subscriptions, a hook's default `webhook:` body, event flows) carry the row as stored, with typed values and defaulted columns, and outbound payloads leave out `user_admin_bypass` and `user_act_as_group_id`. See `api(at:"webhooks")` and `api(at:"hooks")`.
- Batch create honours `X-Idempotency-Key`. See `api(at:"idempotency")`.
- `run: serve_file` and `run: delete_upload` take `with: { record: { table, id } }` naming the row that owns a private upload; without `record:` the ownership rule is only logged for now and will be enforced, so add it to every step that serves or deletes user uploads. See `api(at:"uploads")`.
- `verify: benmore` (with `secret:`) accepts deliveries from another Benmore app's webhook subscription; push and `benmore check` refuse `secret:` without `verify:` and a string `verify:` without `secret:`. See `api(at:"verify")`.
- A `run: webhook` with no `body:` does not post values derived from env (name a secret in `body:` or `payload:` to send it), and a failed job's stored error is redacted like a synchronous flow failure. See `api(at:"flows")` and `api(at:"async-flows")`.
- Push refuses, and `benmore check` reports as an error, config that names a column, table or field the schema does not have (encrypted.yaml, versioning, computed.yaml, `@@fulltext`) and a schema.prisma that removes a model or field another file still names; remove the reference first, or `benmore deploy` both together. See `api(at:"schema")`.
- `GET /api/_webhooks` rows carry `status`; a subscription whose secret was stored under a lost encryption key reads `secret_unreadable` and has to be deleted and created again. See `api(at:"webhooks")`.
- `POST /api/_groups/create` fires on_insert hooks, event flows, webhook subscriptions and realtime for the founding membership row, like a CRUD insert; a member-of write refusal is the JSON 404 `{"error":"Not found"}`. See `api(at:"scoping")`.
- In `run: proxy`, a path value that is not written literally must be one plain segment (a `/`, `\` or dot segment fails the step); set `path_slashes: true` for a stored file key such as `users/42/a.png`. See `api(at:"flows")`.
- `bm.flows` and `bm.api` resolve a 2xx answer that is not JSON as data (a Blob for an image, audio, PDF or ZIP, the text for `text/*`) instead of `{error: <body>}`. See `api(at:"sdk")`.
- In an app scaffolded earlier, add `method="POST"` to the forms in `static/login.html` and `static/signup.html`: a push otherwise rewrites them, or refuses them when the app has a reviewed `mcp.yaml`. See `api(at:"connector")`.
- Uploads are stored per instance: a dev instance keeps its uploads apart from production's, still serves production files copied by `refresh-dev`, and refuses to delete them with `run: delete_upload`. See `api(at:"uploads")`.
- `/pdf/<page>` answers 501 `PDF generation unavailable` with a reason header when the renderer cannot run, instead of a 500; only root-level server-rendered pages are printable. See `api(at:"pdf")`.
- A failed flow job (`mode: async`, `run: enqueue`) runs once and its `on_error` once; `on.request.max_attempts: N` (at most 5) opts into re-running the whole flow after a transient failure. See `api(at:"async-flows")`.

## 2.7.324 (2026-11-04)

- Flows can stream an outside service's answer (audio, a generated PDF or CSV, an image) to the caller with `run: proxy`; the scheme and host are literal or from env, only allow-listed media types are served and the body is capped (10 MiB by default). See `api(at:"flows")`.

## 2.7.323 (2026-11-04)

- A flow with `verify:` binds nothing from the URL query string (path parameters still bind); send everything the flow reads in the signed body. See `api(at:"verify")`.
- When the platform cannot complete a request it says whether the request ran: `X-Benmore-Outcome: not_delivered` (503, safe to retry) or `unknown` (500, check before resending); ingest, uploads and import chunks have 5 minutes for their body, synchronous flows 30 s. See `api(at:"flows")` and `api(at:"ingest")`.
- `run: parse` with a `source` other than `body` or `headers` is refused at push and by `benmore check`; it used to pass and produce no outputs. See `api(at:"parse")`.
- `/api/<table>/<id>/versions` reports `_changed_by` (the caller's user id) for versions recorded by API updates, deletes, reverts and workflow transitions. See `api(at:"versioning")`.
- `ExportButton` exports every readable row (up to `maxRows`, default 50,000) instead of the first 500, and a list request above the 500-row page cap gets the header `X-Limit-Capped: 500`. See `api(at:"components")` and `api(at:"pagination")`.
- `verify: <header name>` checks only that header; the bearer-secret, `X-Webhook-Secret` and `X-Signature` fallbacks are gone, and push refuses a `verify:` that is neither a provider nor a header name. See `api(at:"webhooks")`.
- `${{ params.<name> }}` reads only the request field: when a step id, `set` key or loop variable has the same name and the request omits the field, the value is missing (use `| default:`) instead of what the step wrote. See `api(at:"flows")`.
- A validators.yaml rule passes when a column it compares is NULL, like an SQL CHECK: `end_date >= start_date` accepts a row that has only one of the dates. See `api(at:"schema")`.
- A string the caller sent stays a string in a `respond:` JSON body, a `run: api` body, a webhook body and a broadcast payload; JSON text of an object or array is not decoded into structure there. See `api(at:"flows")`.
- A webhook subscription's `data` keeps the row's own `user_id`/`user_email` columns; the acting user is in the envelope as `triggered_by` and `triggered_by_user_id`. See `api(at:"webhooks")`.
- `POST /api/_query` answers 400 for an aggregate key it does not read (accepted: `fn`, `col`, `as`); `{fn:'count', field:'x'}` used to run as `COUNT(*)`. See `api(at:"query")`.
- A synchronous flow has a time limit, 30 s by default and `on.request.timeout:` per flow (at most 95 s hosted): past it a `transaction: true` flow rolls back and answers 503 `outcome: rolled_back`, any other flow stops and answers 500 `outcome: stopped`; declare `timeout:` or use `mode: async` for longer work. See `api(at:"flows")`.
- Audit `old_values` on an insert and `new_values` on a delete are NULL instead of `''` (rows written earlier keep `''`). See `api(at:"audit")`.
- A push of `schema.prisma` or `migrations/*.sql` whose migration would fail on the instance's data is refused with SQLite's error and the statement, instead of being saved and failing at the next restart. See `api(at:"recovery")`.
- Page queries (mustache `<query>` tags and gotmpl `queries:`) mask encrypted fields for the viewer and drop hidden columns, like `/api/_query`; a failed query answers 500 with the request id instead of an in-page notice or an empty page. See `api(at:"frontend")` and `api(at:"encryption")`.
- On a groups membership table keyed by `user_id`, a create that names another user answers 422 instead of creating a membership for the caller; add members with an invitation or a flow. See `api(at:"scoping")`.
- `run: parse` with `source: headers` is refused in async, scheduled and data-event flows; parse in the request flow and pass the value on with `run: enqueue`. See `api(at:"parse")`.
- `benmore push` waits for the reload after every file that changes what the app loads, and fails when the app stops answering afterwards. See `api(at:"recovery")`.
- Push refuses a `verify:` with `skew_seconds` above 86400, and the `hmac_sha256_body` and `hmac_timestamp_dot_body` recipes require a declared `prefix:`. See `api(at:"verify")`.
- The default CSP `connect-src` allows WebSockets only to the app's own origin and to hosts in `csp.connect_src`; declare any other WebSocket host with `csp: {connect_src: "wss://<host>"}`. See `api(at:"csp")`.
- A hosted instance stopped after repeated start failures answers 503 `App unavailable` instead of 404 `App not found`. See `api(at:"recovery")`.
- A membership table scoped by itself (`room_members: member-of:room_members(room_id, member_id)`) shows and edits only the rows of rooms the caller belongs to, not every roster row. See `api(at:"access")`.
- On a tenant-keyed table, `member-of:` membership counts only inside the caller's tenant; a caller with no tenant reaches nothing through old membership rows. See `api(at:"access")`.
- A pushed or written `migrations/*.sql` that drops a table or column still holding data on the target instance (directly, or by a rename or rebuild that loses rows or values) is refused unless `--allow-table-drop` / `allow_table_drop` is given. See `api(at:"schema")`.
- `benmore describe <app> table <t>` and `api(at:"table:<t>")` report each operation's effective access mode and which rows a signed-in non-admin reaches. See `api(at:"access")`.
- `POST /api/_query` clamps a `limit` above 1000 to 1000 rows instead of falling back to the 200-row default. See `api(at:"query")`.
- `sign: { recipe: bearer_token, prefix: "" }` sends the raw token (for example with `header: x-api-key`) instead of `Bearer <token>`. See `api(at:"sign")`.
- `GET /api/<table>/<id>?fields=a,b` returns only those columns instead of every column. See `api(at:"scoping")`.
- Version history records one version per update or delete and none per insert; a computed-field recalculation and the `@updatedAt` rewrite after a raw UPDATE add no versions of their own. See `api(at:"versioning")`.
- `benmore push` and `benmore deploy` print the reload error and exit non-zero when the app rejects the pushed source at reload (it keeps serving its previous configuration). See `api(at:"recovery")`.
- A queued hook (every on_insert hook) renders the row's integers as integers: `{{id}}` gives `4`, not `4.0`. See `api(at:"hooks")`.
- In a `respond:` JSON body (and an api `json:` or webhook `payload:`), a whole-value `${{ ... | length }}`, `| count` or `| cents` is a JSON number, not a string such as `"20"`. See `api(at:"flows")`.
- An `on_error` handler's `${{ error }}` is the redacted one-line error text (env and env-derived values read `[redacted]`), not the raw error. See `api(at:"flows")`.
- `GET /health?deep=1` answers 503 with a `reason` (`database_timeout`, `database_error`, `memory_pressure`) when users would see a stall; point uptime monitors at it (plain `/health` is unchanged). See `api(at:"recovery")`.
- `benmore test` fails on a file `benmore push` would refuse, and sends `X-CSRF-Token` on cookie-authenticated JSON steps so a signed-in JSON request can be tested without Bearer. See `api(at:"verification")`.

## 2.7.322 (2026-11-04)

- A hosted reload that takes 1 s or more delays the next reload of that instance by three times its duration (at most 2 minutes). See `api(at:"recovery")`.

## 2.7.321 (2026-10-30)

- A write transaction is rolled back after 60 s so one stuck writer cannot freeze the app (migrations, imports and key rotation are exempt), and read-only transactions do not take the write lock. See `api(at:"recovery")`.

## 2.7.319 (2026-10-27)

- gotmpl pages can declare `sources:`: single-table queries in the `/api/_query` spec that run with the viewer's access rules and masks and bind as lists at `.sources.<name>`, with optional `tenant_scope: current` and `overflow: error`. See `api(at:"query")`.

## 2.7.316 (2026-10-26)

- Edges (pastes) are retired: every `edge-<slug>` address answers 410 Gone, the `paste_*` MCP tools and `benmore edge` are gone and `auth.edge_scopes` is refused; build a shareable page inside the app instead. See `api(at:"frontend")`.
- Hosted dev instances send `X-Robots-Tag: noindex, nofollow` on every response and leave the Sitemap line out of the generated robots.txt; production and custom domains are unchanged. See `api(at:"environments")`.

## 2.7.315 (2026-10-26)

- Writes made through the dashboard's data views and the MCP data tools (`sql write:true`, `create_superuser`, `reset_and_seed`, ...) leave `data_*` rows in the app's audit log naming who made them. See `api(at:"query")`.

## 2.7.311 (2026-10-24)

- `benmore restart` exits 1 when the app never answers healthy, and `benmore pull <app>` run inside that app's workspace refreshes it instead of nesting a copy. See `api(at:"recovery")` and `api(at:"sync-status")`.
- `bm.flows.saveQuote` calls `flows/save-quote.yaml`, `bm.table().list()` sends `orderBy`, `include`, `fields`, `page` and `per_page` and warns on other keys, and `bm.auth.me().group_id` is the current tenant. See `api(at:"frontend")`.
- In flow SQL a boolean `${{ }}` value binds as 1/0 and an omitted flow input takes its `default:`; in an `on_transition` hook `{{user_id}}` is the caller and the row's owner is `{{old_user_id}}`. See `api(at:"flows")` and `api(at:"workflows")`.
- `benmore import <app> <table> <file> --owner EMAIL` assigns every imported row of a `user_id` table to that user; without it, a table whose `user_id` is required is refused before upload. See `api(at:"import")`.
- `benmore restore` refuses a backup that the app's current `ENCRYPTION_KEY` cannot decrypt, before anything is stopped. See `api(at:"recovery")`.
- A PATCH names the columns it never writes (a workflow state column, `user_id`, the tenant key, timestamps) in `X-Stripped-Fields` and `stripped_fields`, with a `hint` pointing state changes at `/transition`. See `api(at:"workflows")`.
- `/api` error bodies are JSON (a failed flow's text line is in `message`), and a create, update or delete refused on a table the caller may read answers 403 instead of 404. See `api(at:"errors")` and `api(at:"access")`.
- A push names the schema.prisma changes the live database will not make (a type, nullability or default change, a removed field) under `schema_not_applied`, as do `benmore check` and promote's preview; promote does not require force for them. See `api(at:"schema")`.

## 2.7.310 (2026-10-24)

- The page CSP allows unpkg, jsDelivr, esm.sh or Skypack only when the app's own files name that host; a CDN URL built from data or env needs `csp: script_src`. See `api(at:"csp")`.
- `benmore restore` refuses a snapshot that the app's current code would drop data from again at start (a removed model, or a drop in an unapplied migration file); `--force` overrides. See `api(at:"recovery")`.
- Promote refuses, without force, a copied migration file that would drop a production table or column holding data, and answers `ok: false` (CLI exit 1) when production does not come back healthy. See `api(at:"environments")`.
- A schema.prisma push that removes a model whose table holds rows is refused unless `--allow-table-drop` / `allow_table_drop` is given. See `api(at:"schema")`.
- `/static` refuses every file a `run: compute` module imports, not only the module itself. See `api(at:"compute")`.
- In `run: compute`, a backtracking regex that hits its 5-second match limit throws a RangeError instead of reporting no match. See `api(at:"compute")`.

## 2.7.309 (2026-10-23)

- Hosted CLI commands refuse an unknown flag with a did-you-mean hint instead of ignoring it, and treat `--help` anywhere on the line as a request for help. See `api(at:"cli-contracts")`.
- A flow on a route the framework registers (per-table `/share`, `/permissions`, `/versions`, `/transition`, `/health`, ...) is refused at push; give it a free path. See `api(at:"flows")`.
- Auto-CRUD routes whose access op is `off` are left out of OpenAPI and the docs, and `api(at:"*")` lists them under `crud_access_off` instead of as callable. See `api(at:"access")`.
- A flow or auto-CRUD request body over its limit (1 MiB for a flow's JSON body, otherwise `MAX_REQUEST_BODY_BYTES`, default 10 MiB) answers 413 with the limit, instead of running with every field empty. See `api(at:"flows")`.
- A failed flow step's 500 carries a fixed `reason`; the step's own error text is in the answer only for a signed-in app admin, and always in the app's log with the request id. See `api(at:"flows")`.
- `${{ }}` values take the `if:` expression grammar (`${{ params.id && 'yes' || 'no' }}`), and an expression that does not parse is refused at push. See `api(at:"flows")`.
- A `/static/` file is cached as immutable only at the exact `?v=` the served HTML writes for its current bytes; any other request revalidates against a content ETag. See `api(at:"frontend")`.
- `run: serve_file` signs private audio and video for 4 hours (2 minutes for other files), and `with.expires_in` accepts up to 6 hours. See `api(at:"uploads")`.

## 2.7.305 (2026-10-23)

- `on.schedule.transaction: true` runs a scheduled (cron) flow inside one transaction. See `api(at:"flows")`.
- An MCP command's SQL after-hooks can read the tool name as `{{_mcp_command_name}}`. See `api(at:"connector")`.

## 2.7.304 (2026-10-23)

- A list filter or sort that an encrypted column cannot answer (no blind index, a range or LIKE, a sort) answers 400 instead of empty or unfiltered rows. See `api(at:"encryption")`.
- An `if:` that reads a `steps.<id>.outputs.<name>` column the SQL step does not return is refused at push (it compared as empty, so the guard never fired). See `api(at:"flows")`.
- `benmore deploy` fails when the app does not come back healthy, and a push refuses `versioned:` or encrypted.yaml tables the app does not have. See `api(at:"encryption")` and `api(at:"recovery")`.
- `/static` does not serve TS/JSX source files or `run: compute` modules, and a table the caller is denied answers 404 like an unknown path. See `api(at:"compute")` and `api(at:"access")`.
- Flow SQL never returns `_benmore_users` credential columns, and push refuses `run: sql_dynamic` text that reads `params.X`; bind request values with `:name` in `run: sql`. See `api(at:"flows")` and `api(at:"sql-dynamic")`.
- Push refuses `${{ }}` inside a quoted SQL string in a flow, and data-event flows bind the triggering row's columns as `:name`. See `api(at:"flows")`.
- Numbers of a million or more reach flow SQL and templates in full (`1234567`, not `1.234567e+06`). See `api(at:"flows")`.
- `run: api` with `json: ${{ steps.x.outputs }}` sends the referenced object instead of an empty body, and any other text under `json:` is refused at push. See `api(at:"flows")`.
- Push and `benmore check` refuse a `static/` or `src/` script that does not parse, naming file, line and column. See `api(at:"compute")`.
- `benmore env set` returns after the app has restarted with the new value, and instances the key does not apply to are not restarted. See `api(at:"recovery")`.
- Framework answers about an unreachable app use 503 (the CDN replaces the body of a 502 or 504), and `benmore check` warns on a flow response with status 502 or 504. See `api(at:"flows")`.
- `static/` URLs without a version (images in TSX, CSS `url()`, icons) are revalidated instead of cached for a year, so a replaced file shows without `?v=2`. See `api(at:"frontend")`.
- `for_each` iterates lists of strings or numbers (they used to be skipped: zero iterations and a 200). See `api(at:"flows")`.
- Flows accept `auth: optional`: signed-in callers get `${{ user.* }}` and anonymous callers get null, on one route. See `api(at:"flows")`.
- `<meta name="bm-cookie-banner" content="off">` leaves the consent banner off one page, for example an embed. See `api(at:"analytics")`.
- Auto-CRUD names unknown body fields in the `X-Ignored-Fields` response header and list filters it did not apply in `X-Ignored-Params`. See `api(at:"scoping")`.
- With CLI 0.1.55, `benmore help <cmd>` shows that command, `benmore logs -n N` prints recent lines and `-f` streams. See `api(at:"cli-contracts")`.
- With CLI 0.1.55, a schema push copies the `migrations/*.sql` files the server generated back into the workspace. See `api(at:"schema")`.
- MCP file tools read DOCX paragraphs and tables and PPTX slides, as text only. See `api(at:"connector")`.

## 2.7.303 (2026-10-22)

- With CLI 0.1.54, `benmore users <app> delete <email> --confirm` accepts `--env dev|prod`. See `api(at:"auth")`.
- Reviewed MCP command SQL may call `json_array_length` and `json_group_array`. See `api(at:"connector")`.
- MCP file tools can bind `handler.file_column` to one reviewed file reference, constrain the caller's live group membership, expose a metadata-only `status` operation and opt into `handler.upload_tenant: current`. See `api(at:"connector")`.

## 2.7.300 (2026-10-21)

- A record share grants edit and delete separately, and listing a record's permissions requires current sharing authority. See `api(at:"permissions")`.
- Push and `benmore check` refuse `onDelete`/`onUpdate` arguments on `@relation`, which the runtime ignores; existing foreign keys keep their behavior. See `api(at:"schema")`.
- Flow mail supports CC and BCC, and opt-in `unsubscribe_one_click` (one recipient and an HTTPS URL). See `api(at:"email")` and `api(at:"flows")`.

## 2.7.298 (2026-10-16)

- Encrypted Boolean fields read as true/false (or null) in reads, projections, history and create responses. See `api(at:"encryption")`.
- `/api/_query` refuses an operation an encrypted column cannot answer instead of returning misleading totals or matches. See `api(at:"query")`.
- Adding `@relation` to an existing table installs the foreign key in the database; a table whose rows reference a missing parent, or a new required reference with no default on a populated table, stops the migration until an explicit migration fixes the data. See `api(at:"schema")`.

## 2.7.297 (2026-10-16)

- A create response returns encrypted numeric fields as numbers, like a read. See `api(at:"encryption")`.
- Full-text search works on tables with UUID or text primary keys (create, edit, delete and search). See `api(at:"search")`.

## 2.7.296 (2026-10-16)

- Push and `benmore check` refuse a schema field with an unsupported or undefined type, or a scalar list, instead of silently leaving the column out. See `api(at:"schema")`.
- A flow SQL parameter whose whole value is a boolean binds as 1/0. See `api(at:"flows")`.
- Prisma `@default(uuid())` generates version-4 UUIDs on create, batch, ingest and import; raw SQL inserts into an existing table still use the column's stored default. See `api(at:"scoping")`.

## 2.7.295 (2026-10-16)

- Create-time cross-field validators see the schema default of a field the request leaves out. See `api(at:"schema")`.
- `for_each` reads arrays nested in compute results and in request objects. See `api(at:"flows")`.
- A transactional flow rolls back before its `on_error` handler runs, so the handler's own writes are kept. See `api(at:"flows")`.
- The SDK clears private query state and rebinds live subscriptions when the session or tenant changes; a custom sign-in flow finishes with `bm.auth.refreshMe()`. See `api(at:"sdk")`.

## 2.7.294 (2026-10-16)

- An update refused by a database constraint answers 400 on PATCH, batch and `/api/_transaction`. See `api(at:"errors")`.
- Workflow role guards and server-rendered role checks use the tenant role from `groups.role_field`. See `api(at:"workflows")`.
- `/batch` runs hooks for each row, streaming ingest runs before-hooks only, and bulk import runs no per-row hooks. See `api(at:"batch")`, `api(at:"ingest")` and `api(at:"import")`.

## 2.7.288 (2026-10-14)

- A reviewed MCP read tool can declare `artifact:`, and `artifact.create` exports its result as XLSX, a branded HTML report or PDF. See `api(at:"connector")`.

## 2.7.286 (2026-10-14)

- Browser journeys check every action target before acting; set `sequential_actions: true` when an earlier action renders or replaces a later control. See `api(at:"verification")`.
- `csp.frame_ancestors: "'none'"` denies all framing, and a source list that mixes `'none'` with other sources is rejected. See `api(at:"csp")`.
- MCP connector pages share one branded layout (app name, favicon, `theme:`/`brand:`) and name workspaces from `groups.label`. See `api(at:"connector")`.
- MCP command tools can declare `title`, `review_summary`, `labels` and `review_changes` in mcp.yaml; review pages show labelled before-and-after rows, and prepared calls return `approval_reason`. See `api(at:"connector")`.
- Flow SQL can call `benmore_today('America/New_York')` for the current date in an IANA time zone. See `api(at:"flows")`.
- The flow steps `inspect_private_upload` and `render_pdf_signatures` inspect an app-private PDF or PNG signature and stamp a separate private PDF. See `api(at:"flows")`.

## 2.7.282 (2026-10-13)

- `features.account_settings: false` closes account self-service while sign-in, logout, login MFA and required password replacement keep working. See `api(at:"auth")`.
- Browser journeys can declare expected same-origin 4xx denials by method, path and status; every declared denial must occur. See `api(at:"verification")`.
- `features.exports: false` turns off the framework's HTTP PDF and user-data exports. See `api(at:"pdf")`.
- `features.uploads: false` closes both HTTP upload endpoints. See `api(at:"uploads")`.
- `run: parse` with `source: headers` exposes the inbound headers by canonical name, each as an array of values. See `api(at:"parse")`.
- `bm.api` accepts custom headers and an AbortSignal. See `api(at:"sdk")`.
- `on.request.strict_json: true` caps the request at 32 KiB and rejects duplicate JSON keys, malformed or trailing JSON, non-object bodies and non-JSON media types before any step runs. See `api(at:"flows")`.
- `auth.signup: false`, `auth.password_reset: false` and `auth.api_tokens: false` close public account creation, end-user password recovery and user token issuance; all three default to on. See `api(at:"auth")`.
- `benmore users <app> create <email> --password-stdin` reads the password from standard input and refuses an existing account; `benmore users <app> list --all` includes deactivated accounts. See `api(at:"auth")`.

## 2.7.280 (2026-10-13)

- MCP commands can draw server-generated tokens (`generated:`, for example for invitation links), sign a removed member out with `run: revoke_user_sessions`, and declare their own triggers with `app_triggers:`. See `api(at:"connector")`.

## 2.7.279 (2026-10-13)

- With CLI 0.1.44, `benmore login --device` signs in without a terminal. See `api(at:"cli-auth")`.

## 2.7.277 (2026-10-13)

- An MCP command declared `approval: grant` applies in one call when the owner ran `benmore mcp enable <app> --writes --auto-approve` and the user agreed at consent; other writes return `batch_review_url` so a connection's pending changes are approved together. See `api(at:"connector")`.
- An app can list and revoke the signed-in user's connected AI clients with `GET /api/_mcp/grants` and `DELETE /api/_mcp/grants/{id}`. See `api(at:"connector")`.

## 2.7.276 (2026-10-13)

- With `table_scopes: access`, declaring capability `roles:` (for example for MCP tool permissions) does not put every auto-CRUD call behind a scope; `access:` decides table access. See `api(at:"rbac")`.
- `benmore serve <app> --mcp-local [--mcp-writes]` serves the reviewed MCP connector on the local machine with OAuth, so a connector can be tested before deploy. See `api(at:"connector")`.

## 2.7.272 (2026-10-11)

- A flow response to a signed-in caller is sent `private, no-store`; a `run: api` or `run: webhook` step with a missing input stops before sending, and a webhook step fails unless the receiver answers 2xx. See `api(at:"flows")`.

## 2.7.271 (2026-10-11)

- Flow step values that used to be dropped are sent: a `run: webhook` `payload:` (or a map `body:`) is the JSON body instead of the whole context, a respond `status:` written as `${{ }}` or a quoted number is used, `run: api` sends a map `body:` as JSON, and respond `headers:`/`content_type:` are sent through an allowlist. See `api(at:"flows")`.
- A server error from a built-in route or a flow keeps its status and shape but answers the route's generic text with a request id (`X-Request-Id`, JSON `request_id`), never the database's error text; the detail is in the request log. See `api(at:"errors")`.

## 2.7.270 (2026-10-10)

- The database engine is SQLite 3.53: a number computed in SQL and written as text or JSON (`json_object('total', price * qty)`, `CAST(.. AS TEXT)`, a `SUM()` of REAL prices) keeps up to 17 digits (`434.99999999999994`, where it used to read `435.0`), so round it in the statement with `round(.., 2)`. See `api(at:"flows")` and `api(at:"query")`.

## 2.7.269 (2026-10-10)

- A flow step key that its step type does not read is refused at push (for example `retry`, `on_error`, `if` or `id` under `with:`, or `params` on `sql_dynamic`). See `api(at:"flows")`.

## 2.7.268 (2026-10-10)

- `expect_rows` is checked on every `run: sql` and `run: sql_dynamic` step: rows returned for a SELECT or a `RETURNING` write (it was ignored there), rows affected otherwise; an assertion that cannot be checked is refused at push. See `api(at:"flows")`.
- `${{ steps.<id>.outputs.rows_affected }}` resolves; conditions on it used to compare against nothing (`!=` always true, `==` always false). See `api(at:"flows")`.

## 2.7.267 (2026-10-10)

- A hard-bounce email pause ends by itself after 24 hours, then after 72 hours, then needs a manual resume (complaint pauses stay manual); accepting an ownership transfer is refused while the app uses paid features the recipient's plan lacks. See `api(at:"email")` and `api(at:"collaborators")`.

## 2.7.266 (2026-10-10)

- Generic CRUD writes to the groups membership table need a tenant admin unless the table declares its own access rule; `POST /signup` allows 30 sign-ups per 10 minutes from one client address, and `auth.signup_rate_limit` changes that. See `api(at:"scoping")` and `api(at:"auth")`.
- In flow email a `to:` value is one recipient (use `| recipients` for a list), and HTML bodies escape values (use `| raw` to keep markup). See `api(at:"email")`.

## 2.7.265 (2026-10-09)

- `self` and `group` access answer 404 on a table with no owner or tenant column; declare `everyone` if every signed-in user should reach it. See `api(at:"access")`.

## 2.7.264 (2026-10-09)

- `/sitemap.xml` and `/robots.txt` serve the app's own `static/sitemap.xml` and `static/robots.txt` when present. See `api(at:"frontend")`.
- A hook `ws:` broadcast with no declared payload sends only `{}` or `{"table": ...}`; declare the payload fields to send. See `api(at:"hooks")` and `api(at:"realtime")`.
- A tenant role does not pass a `perm:` gate on a table without the tenant key. See `api(at:"access")`.

## 2.7.263 (2026-10-08)

- An email change is applied when the user confirms it with a button on the linked page, and it revokes the account's tokens and grants; `/api/_schema` follows the caller's RBAC scopes. See `api(at:"auth")` and `api(at:"components")`.

## 2.7.262 (2026-10-08)

- A stale `mcp.yaml` review turns only the connector off: the app keeps reloading from its files and writes warn `mcp_connector_withheld`; review again and push `mcp.yaml`, or delete it if the app serves no connector. See `api(at:"connector")`.

## 2.7.260 (2026-10-08)

- An app can serve its own MCP connector, authored in `mcp.yaml` from app files, reviewed with `benmore mcp review` and deployed with the manifest last (`benmore docs connector`). See `api(at:"connector")`.
- `benmore mcp status|enable|disable <app> [--writes] [--export] [--publication] [--revoke] [--env dev|prod]` are the owner's switches for what an app's MCP connector exposes. See `api(at:"connector")`.
- MCP command tools only prepare a write (operation id, exact preview, 15-minute expiry, review link); a person approves it in the browser, then `_commit` applies it once and `_status` reads its state. See `api(at:"connector")`.

## 2.7.259 (2026-10-08)

- `pwa.service_worker: /static/sw.js` serves the app's own service worker at `/sw.js`. See `api(at:"mobile")`.

## 2.7.258 (2026-10-08)

- New apps start with a read-only MCP starter, which enables no connector access by itself; source review is explicit with `benmore mcp review <appdir> --reviewed`. See `api(at:"connector")`.

## 2.7.257 (2026-10-07)

- A tenant role does not pass a `role:` gate on a table without the tenant key; list shared catalogs under `groups.shared`. `GOMEMLIMIT` and `GOGC` are reserved env keys. See `api(at:"access")`.

## 2.7.256 (2026-10-07)

- `bm.auth.passkey.register(name, { password })` needs a proof such as the current password; a tenant role named `admin` is not a global admin, and a `perm:` mode needs `roles:` in app.yaml. See `api(at:"auth")` and `api(at:"rbac")`.
- Batch and ingest run the single-row gates; a foreign key must name a parent the caller can read (422 otherwise); a has-many `?include=` returns at most 100 children per parent and marks the cut with `_include_truncated`. See `api(at:"scoping")` and `api(at:"batch")`.
- `run: api` URL values are encoded for the position they land in: split `owner/repo` into two values and put query strings in `with.query`. See `api(at:"flows")`.
- On row-scoped tables other readers receive the generic realtime refresh; gotmpl pages have no Sprig `env` or DNS helpers; `sql write:true` takes one statement; collaborator invitations must be accepted. See `api(at:"realtime")`, `api(at:"frontend")`, `api(at:"query")` and `api(at:"collaborators")`.

## 2.7.255 (2026-10-07)

- A password change revokes the account's MCP connector grants. See `api(at:"connector")`.

## 2.7.254 (2026-10-06)

- `bm.auth.passkey.register()` and `.signIn()` add passkey sign-in (Face ID, Touch ID, a phone) to any app; it is on by default, `auth.passkeys: false` turns it off, and a passkey works only on the host it was created on. See `api(at:"auth")`.
- A hook or webhook subscription delivery counts as delivered only when the receiver answers 2xx. See `api(at:"webhooks")` and `api(at:"hooks")`.
- The built-in MCP tool `artifact.export` returns the receipt of a committed command as XLSX, HTML or PDF. See `api(at:"connector")`.
- `command.owns: [table.column]` on a command flow makes generic CRUD refuse that column with 403 `field_owned_by_command`, admins included; flows, hooks and other commands can still write it. See `api(at:"scoping")` and `api(at:"connector")`.
- MCP file tools read a private upload referenced by a row the caller can read: CSV and XLSX with cell coordinates, PDF as layout text with OCR (at most 200 pages; encrypted PDFs are refused). See `api(at:"connector")`.

## 2.7.253 (2026-10-05)

- A flow whose `auth:` is `true`, `yes` or a misspelling requires sign-in; it used to be public. See `api(at:"flows")`.
- Push refuses config keys the loader does not read (in flows, workflows.yaml, access ops, app.yaml `auth`/`features`, cron.yaml) and conditions that can never be true; a hosted app cannot set `PATH`, `LD_*`, `GIT_*` or transcribe binary paths in its env. See `api(at:"flows")`, `api(at:"workflows")`, `api(at:"access")` and `api(at:"environments")`.

## 2.7.250 (2026-10-03)

- `write_file` and `edit_file` validate only the source they wrote (app-load and drift checks are in `benmore check`), `write_file` takes `reload: false`, and `benmore deploy` reloads once per batch. See `api(at:"environments")`.

## 2.7.249 (2026-10-03)

- Each hosted app instance has its own request budget of 600 requests a minute per client IP, within 1200 a minute per IP overall; every 429 carries `Retry-After`. See `api(at:"environments")`.
- `run: api` can capture listed 4xx answers with `with.handled_statuses: [400]` instead of failing the step; 5xx, transport errors and answers over 1 MiB stay errors. See `api(at:"flows")`.
- A `transaction: true` flow sends its response only after the commit, buffers at most 1 MiB and may not use `serve_file`. See `api(at:"flows")`.
- `on.request.permissions: [projects:read]` makes a flow require a signed-in caller holding every listed scope. See `api(at:"flows")`.

## 2.7.248 (2026-09-29)

- A list filter or sort on a hidden column (`share_token`, `*_api_key`) answers 400; read those values through a flow. See `api(at:"scoping")`.
- `run: sql_dynamic` text may not use a step output built from request input (bind it with `:name` in `run: sql`), `run: enqueue` needs a literal `flow:` name, and a before-update hook's row holds only the columns being written. See `api(at:"flows")`, `api(at:"sql-dynamic")` and `api(at:"hooks")`.

## 2.7.247 (2026-09-26)

- Flow `if:` and `success_when:` take `&&`, `||`, `!` and parentheses; a hook or workflow `when:` is an SQLite condition over the row (`status IN (...)`, `old_x != x`) and is checked against schema.prisma at push. See `api(at:"flows")`, `api(at:"hooks")` and `api(at:"workflows")`.

## 2.7.246 (2026-09-26)

- A value substituted into a flow or hook template is never expanded again (a submitted `{{env.X}}` stays text); `if:` and `when:` compare numbers numerically, and `${{ user.group_id }}` in a flow is the session's tenant. See `api(at:"flows")` and `api(at:"hooks")`.
- Page frontmatter `require:` and `role:` are enforced, and a new workflow row starts in `initial`. See `api(at:"frontend")` and `api(at:"workflows")`.

## 2.7.245 (2026-09-25)

- `run: compute` receives a `${{ env.NAME }}` argument as its value instead of null, and a bare `if: ${{ env.NAME }} == 'x'` compares the real value. See `api(at:"compute")`.

## 2.7.244 (2026-09-25)

- The default cookie banner text describes only the framework's analytics: an app that adds its own trackers names them in `seo.cookie_notice` (with `seo.privacy_url`) and loads them only after `window.bmCookieConsent() === "accepted"` or the `bm:cookie-consent` event. See `api(at:"analytics")`.

## 2.7.243 (2026-09-25)

- String verifiers such as `verify: stripe` accept `secret: "${{ env.NAME }}"` and reject every request when it does not resolve; top-level `idempotent: true` on an async flow requeues its jobs after a crash. See `api(at:"webhooks")` and `api(at:"async-flows")`.
- `bm.notifications.list({limit, offset, unread})` and `bm.notifications.onNew` are available. See `api(at:"notifications")`.

## 2.7.242 (2026-09-24)

- Restoring a database backup rolls back data but not sign-in state: current passwords, MFA and deactivations carry over, and sessions, tokens and grants revoked since the backup stay revoked. See `api(at:"recovery")`.
- At the plan's storage limit, creates, tenant bootstrap and imports answer 507 `storage cap reached`. See `api(at:"recovery")`.
- A password that `create_superuser` or `benmore users set-password` sets on an existing account is temporary (the user must replace it before using the app) unless `--no-change-required` is passed. See `api(at:"auth")`.
- `benmore login` and `benmore bootstrap` take a token from `BENMORE_TOKEN` or `--token`; email/password flags and `benmore signup` answer 403 on a platform that requires the emailed sign-in code, so sign in through the browser there. See `api(at:"cli-auth")`.

## 2.7.240 (2026-09-23)

- Flow `run: sql` and `run: sql_dynamic` writes emit the same `{table, action}` live events as auto-CRUD, after commit; `run: broadcast` sends a server message to the members of a WebSocket room. See `api(at:"flows")` and `api(at:"websocket")`.

## 2.7.239 (2026-09-23)

- Over HTTPS the session cookie is `__Host-benmore_session`, so everyone signs in once after the upgrade; in apps that key grants by email, an account that never verified its email verifies it at the next password sign-in. See `api(at:"auth")`.

## 2.7.238 (2026-09-23)

- Browser bundles and `run: compute` modules may import only files inside `static/`, and a compute result must be JSON-serializable; admin-only management endpoints need an unscoped admin credential. See `api(at:"frontend")`, `api(at:"compute")` and `api(at:"auth")`.

## 2.7.237 (2026-09-23)

- Columns named like a credential (`*_token`, `*_secret`, `api_key`, ...) are hidden on every API read; `{{var}}` in a server-rendered page is escaped for the place it lands in (HTML, URL attribute, script), and a templated redirect must stay on the app's origin. See `api(at:"scoping")`, `api(at:"frontend")` and `api(at:"flows")`.
- `PATCH /api/_auth/profile` writes only the built-in profile columns, `auth.signup_fields` and the columns listed in `auth.profile_fields`; any other column answers 403. Before-hooks can read `{{_submitted}}`. See `api(at:"auth")` and `api(at:"hooks")`.

## 2.7.229 (2026-09-21)

- `qa_inventory` lists every page, control and declared access, flow and workflow expectation and drafts `tests/journeys/*.yaml`; `benmore verify` and `browser_batch` replay the journeys in a headless browser. See `api(at:"qa")` and `api(at:"verification")`.

## 2.7.224 (2026-09-19)

- Malformed configuration is refused at start and at reload, before migrations run. See `api(at:"recovery")`.
- The platform MCP tool `query_db` runs read-only SQL against an app's database with bounded results and cancellation. See `api(at:"query")`.

## 2.7.223 (2026-09-19)

- An account on a temporary password must replace it before it can reach protected data. See `api(at:"auth")`.

## 2.7.219 (2026-09-05)

- Inbound `verify:` recipes cover HMAC-SHA1 over the raw body with current and previous secrets (Autodesk style) and a path-bound HMAC-SHA256 bearer credential. See `api(at:"verify")`.
- The server-only flow step `run: purge_current_user` erases the signed-in account; it takes no target id and needs a confirmed, transactional POST or DELETE flow. See `api(at:"auth")`.
- Bulk import loads CSV or NDJSON into a table in resumable chunks, all or nothing (`benmore import`); an owner can also run an SQL restore. See `api(at:"import")`.

## 2.7.213 (2026-08-01)

- `run: api` steps honor `with.timeout` (`570s` or bare seconds, default 30 s; a step-level `timeout:` wins), and steps gated by `if:` keep their timeout, retry, `expect_rows` and `on_error`. See `api(at:"flows")`.
- The CLI can report local Claude and Codex token counts to the platform on an explicit sync, with an account opt-out; transcripts and paths are never uploaded. See `api(at:"agent-usage")`.
- An existing frontend (Vite, a Next static export, CRA) is built outside Benmore and deployed by copying only its generated output into `static/`. See `api(at:"existing-frontends")`.
- Install the CLI with Homebrew on macOS or the checksum-verifying installer on Linux and CI; the npm package `@benmore/cli` is deprecated. See `api(at:"cli-install")`.
- CLI commands accept `.` for the workspace's app, `benmore open` prints the dev address when dev is selected, and usage, auth, not-found and transport failures have stable exit codes. See `api(at:"cli-contracts")`.
- An empty declarative query returns `{rows: [], count: 0}`, never `rows: null`. See `api(at:"query")`.
- With docs enabled, the authenticated OpenAPI 3.1 document is served identically at `/api/_openapi`, `/openapi.json` and `/api/openapi.json`, and the public docs at `/llms.txt` and `/.well-known/llms.txt`. See `api(at:"machine-discovery")`.
- External frontends import the zero-dependency ESM package `@benmore/bm` (native apps keep `import 'bm'`), and `benmore types [app] --out PATH` writes the generated schema types. See `api(at:"sdk")`.
- `benmore hooks` adds Claude edit-validation and push hooks without replacing existing settings, and `benmore sync-status --all` checks every pulled app. See `api(at:"sync-status")`.
- The server-only flow step `run: delete_upload` removes one of the app's own private uploads and fails the flow on any other reference. See `api(at:"uploads")`.

## 2.7.210 (2026-07-21)

- `run: sms` in a flow (`with: { to, body }`) and `sms:` in hooks.yaml send a text message; push refuses a hooks.yaml key the runtime does not read. See `api(at:"sms")`.
- `run: transcribe` turns an audio file into text on the server (`with: { file, model?, language? }`, result in `steps.<id>.outputs.text`). See `api(at:"transcribe")`.
- An app can have up to 10 custom domains: `benmore domain <app> <domain>` adds one, and `--verify` / `--remove` act on one domain or, without a domain, on all. See `api(at:"dns")`.
- `bm.markdown(text)` renders on the server (CommonMark, GFM, syntax highlighting, mermaid, sanitized), with `bm.markdownBatch()`, the `{{ body | markdown }}` pipe and a `<Markdown>` component. See `api(at:"markdown")`.
- `benmore sync-status` compares a workspace with the server, and push, pull, deploy and delete refuse to overwrite changes they have not seen; reusable `feature.yaml` packs can be installed into an app. See `api(at:"sync-status")` and `api(at:"feature-packs")`.

## 2.7.202 (2026-07-02)

- GitHub sync mirrors an app's history one way to a repository you own: connect in the dashboard under Version Control, and every commit is pushed (production to `main`, dev to `dev`). See `api(at:"github")`.

## 2.7.201 (2026-07-01)

- `benmore deploy <dir>` starts a first deploy from a bare scaffold (no demo files merged into the app) and reports each file that failed to push while the rest still ship. See `benmore help deploy`.

## 2.7.200 (2026-07-01)

- Managed social login (Google and Microsoft without your own OAuth client), Stripe Connect with separate keys per environment, and managed DNS zones. See `api(at:"oauth")`, `api(at:"payments")` and `api(at:"dns")`.

## 2.7.199 (2026-07-01)

- Hosted apps can send transactional SMS with no setup, and an app can have its own dedicated number. See `api(at:"sms")`.

## 2.7.197 (2026-07-01)

- Hosted apps can send email with no setup; an app can send from its own domain (DKIM), within quotas, a suppression list and automatic pauses. See `api(at:"email")`.

## 2.7.194 (2026-07-01)

- A field that cannot be decrypted reads `[unavailable: decryption failed]`, never the stored ciphertext; hosted apps with encrypted fields get a persistent `ENCRYPTION_KEY` when they are provisioned. See `api(at:"encryption")`.

## 2.7.191 (2026-06-26)

- `read: owner_or_role:<roles>` gives a row to its owner and to holders of a listed role. See `api(at:"access")`.
- Flows take `rate_limit: "5/hour per ip"` (429 with `Retry-After`) and `expect_rows:` to fail when a guarded write changes no rows. See `api(at:"flows")`.
- In a `mode: async` flow, `respond:` and `redirect:` do nothing in the worker; `benmore check` warns about them. See `api(at:"async-flows")`.
- `benmore status` and `benmore diff` show how dev and production differ, and `benmore doctor` checks release readiness before a promote. See `api(at:"environments")`.
- `benmore test` runs an app's YAML tests, migrations apply in one transaction, and `benmore restore --pitr --as-of` restores a hosted app to a point in time when point-in-time recovery is on for it. See `api(at:"recovery")` and `api(at:"verification")`.
