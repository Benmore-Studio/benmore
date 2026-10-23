# Build a Benmore app

Benmore turns a **Prisma schema + YAML config + TSX/HTML pages** into a running
web app - one Go binary, no Node, no build step. You write the data model, a
little config, and your frontend; the framework gives you a SQLite-backed REST +
SSE + WebSocket API with auth, RBAC, validation, real-time, and a typed client
SDK, all served from a single process.

> The model, in one line: **Schema in Prisma. Config in YAML. UI in TSX
> (auto-compiled). Server logic (if any) in YAML hooks/flows/cron.**

Read `benmore docs harness` first for identity, environment selection, Codex/Claude
setup, explicit pushes, and verification. This guide accompanies runtime/framework
**2.7.248** and cloud CLI **0.1.34**, which include checked recovery and source-history handling alongside Codex installer targets and shared
app instructions. Use installed help to check whether an older CLI supports the
new skill flags.

Hosted commands in this guide require the cloud or platform edition. Framework-only
operators use their generated app AGENTS.md, bundled guides, and authenticated
runtime OpenAPI; hosted account, push, skill, and MCP API commands are separate.

## Recent

- Runtime 2.7.302: data-event transaction panics release their database connection after rollback. See `api(at:"flows")` (`event_transaction_cleanup`).
- Runtime 2.7.302: platform upload-retention sweeps keep selection and deletion on their captured database. See `api(at:"recovery")` (`worker_generations`).

- Runtime 2.7.302: PDF jobs isolate Chrome HOME/XDG caches, select disposable credential stores and report cleanup failures; host startup and old residue remain separate. See `api(at:"pdf")` (`runtime_cleanup`).

- CLI 0.1.53: confirmed user deletion accepts an explicit environment; invalid or duplicate flags refuse before dispatch. See `api(at:"auth")` (`cli_user_provisioning`).

- Runtime 2.7.302: source history separates successful Git warnings from parsed paths; unreadable-directory cleanup remains separate. See `api(at:"github")` (`git_diagnostics`).

- Runtime 2.7.302: test diagnostics retain published root pages and partials until validated reload. See `api(at:"frontend")` (`root_page_reload`).
- Runtime 2.7.302: route registration and graph extraction preserve published page definitions and use matching effective gates. See `api(at:"frontend")` (`root_page_reload`).

- Runtime 2.7.302: reviewed command SQL admits `json_array_length` and `json_group_array` without widening table or function authority. See `api(at:"connector")` (`connector_grants`).

- Runtime 2.7.302: native MCP file tools can bind `handler.file_column` to one reviewed current file reference; legacy omission retains broader matching. See `api(at:"connector")` (`connector_grants`) and `benmore docs connector`.

- Runtime 2.7.302: file tools can add bounded equalities on the actor's live group membership and expose a reviewed metadata-only `status` operation for known successful snapshot-backed processing results. Current file and row authority are rechecked; parsed blocks and snapshot payloads are not returned. See `api(at:"connector")` (`connector_grants`) and `benmore docs connector`.

- Runtime 2.7.302: file tools can opt into `handler.upload_tenant: current` to require private-upload provenance to match both the selected workspace and source-row tenant. Legacy omission keeps existing upload-vouch behavior. See `api(at:"connector")` (`connector_grants`) and `benmore docs connector`.

- Runtime 2.7.300: import launch synchronizes its cancellation generation with reload; cancellation still rolls back pending rows. See `api(at:"import")` (`reload_generation`).

- Runtime 2.7.300: YAML writes and checks reject over-budget content before repeated validation. See `api(at:"verification")` (`yaml_resource_limits`).

- Runtime 2.7.300: maintenance workers and lazy connector operation limiters keep their original stop generation across reloads. See `api(at:"recovery")` (`worker_generations`).

- Runtime 2.7.300: backup file uploads hash and stream without an object-sized buffer. See `api(at:"recovery")` (`backup_upload_memory`) for capacity limits.

- Runtime 2.7.300: scheduled snapshots include WAL-only writes and refresh idle production apps. See `api(at:"recovery")` (`scheduled_snapshots`).

- Runtime 2.7.300: platform PITR captures committed WAL boundaries with SQLite coordination. See `api(at:"recovery")` (`wal_committed_capture`) for outage and rollout limits.

- Runtime 2.7.300: durable jobs preserve project ordering across overlapping reload workers while unrelated jobs remain eligible. See `api(at:"async-flows")` (`ordering`).
- Runtime 2.7.300: backup listings require complete S3 inventories; the dashboard lists bounded ordinary snapshots. See `api(at:"recovery")` (`backup_inventory`).
- Runtime 2.7.300: active production apps retain their newest ordinary backup candidate; removed-app expiry requires a fresh route inventory. See `api(at:"recovery")` (`retention_safety`).
- Runtime 2.7.300: PITR base upload readiness gates WAL publication and retries while idle. See `api(at:"recovery")` (`wal_base_readiness`).

- Runtime 2.7.300: feature-pack model maps apply simultaneously, including references in unchanged models, so chained names and swaps do not collapse schemas or SQL/table references. See `api(at:"feature-packs")` (`model_maps`).
- Runtime 2.7.300: notification retention keeps the newest IDs when timestamps tie, independently of read state. See `api(at:"notifications")` (`retention`).
- Runtime 2.7.300: personal inbox badges and live hints honor delegated credential scopes. See `api(at:"notifications")` (`credentials`).
- Runtime 2.7.300: ordinary-app hot reloads refresh root page routes, access gates, partials and auth paths; rejected candidates retain the active page set. See `api(at:"frontend")` (`root_page_reload`) and `api(at:"recovery")` (`page_reload`).
- Runtime 2.7.300: frontmatter rendering preserves shared page metadata during concurrent requests and context-graph reads. See `api(at:"frontend")` (`ssr_page_gates`).
- Runtime 2.7.300: the standard sharing dialog displays and revokes the recipient from the native permission list. See `api(at:"permissions")` (`share_dialog`).

- Sharing grants keep edit and delete separate; permission lists also require current sharing authority. See `api(at:"permissions")` (`grant_actions`, `sharing_authority`).

- Runtime 2.7.300: local MCP review accepts omitted optional arrays and seals the YAML it writes; explicit null remains invalid. See `api(at:"connector")` (`review_serialization`).

- Runtime 2.7.300: new record shares resolve one existing account's stored email spelling and refuse legacy case ambiguity; future recipients and historical grants keep their exact-spelling limits. See `api(at:"permissions")` (`recipient_resolution`).
- Runtime 2.7.300: `bm.live.scoped` serializes callback promises and queues one trailing refresh; see `api(at:"live-scoped")` for ordering and teardown limits.

- Runtime 2.7.300: schema write/check refuses ignored `@relation` onDelete/onUpdate arguments, including reverse lists; existing foreign keys keep their behavior. See `api(at:"schema")` (`referential_actions`).
- Runtime 2.7.300: locale requests and HTML/raw-page dictionaries use the published app generation; `bm.t` treats variable names and values literally. See `api(at:"i18n")`.
- Runtime 2.7.300: stored SQL hooks recognize commented and quoted write targets so automatic enrollment refreshes live views after the job runs. Existing reader gates remain. See `api(at:"hooks")` (`sql_refresh`) and `api(at:"auto_memberships")` (`verifying`).
- Runtime 2.7.300: generated types and per-caller flow metadata share private origin cache headers; CDN bypass and removal of previously cached objects remain deployment requirements. See `api(at:"frontend")` (`private_metadata_cache`).

- Runtime 2.7.300: framework admin rows, command hook snapshots and transfer digests use trusted source columns; workspace identities stay literal. Older affected transfer previews require reprepare. See `api(at:"encryption")` (`framework_read_source`).

- Runtime 2.7.300: feature-pack route and model transforms preserve exact custom-route destinations while renaming native table references. See `api(at:"feature-packs")` (`route_composition`) for dynamic URL limits.

- Runtime 2.7.300: read-audit history has a bounded integer page size and rejects malformed limits with 400. See `api(at:"audit")` (`read_history`).

- Runtime 2.7.299: account/system metadata remains literal even with encrypted-envelope prefixes; webhook secret hints decode once. See `api(at:"encryption")` (`metadata_literals`) for the bounded coverage and remaining SQL limits.

- Runtime 2.7.299: feature-pack previews and applies verify original checksums before route/model transformations. See `api(at:"feature-packs")` (`payload_integrity`).

- Runtime 2.7.299: schema drift checks and cleanup preserve generated and retained history tables. See `api(at:"versioning")` (`drift_protection`).

- Runtime 2.7.299: canonical table reads preserve ordinary ciphertext-looking text and decrypt only configured source columns; generic SQL and other metadata paths retain their separate contract. See `api(at:"encryption")` (`native_read_source`).

- Runtime 2.7.299: configured encrypted fields seal native ciphertext-looking inputs as literal text, preserving blind indexes and mutation gates. See `api(at:"encryption")` (`ciphertext_input`).

- Runtime 2.7.298: inline GHA `sign.compute` preserves declaration order for dependent timestamp/HMAC bindings, including anchors and nested steps. See `api(at:"sign")` (`compute_order`).

- Runtime 2.7.298: encrypted Boolean fields retain true/false and nullable semantics in native reads, projections, history, and create responses. See `api(at:"encryption")` (`boolean_columns`).

- Runtime 2.7.298: query aggregate aliases remain derived values; source authorization and ordinary projection masks remain. See `api(at:"query")` (`aggregate_outputs`).

- Runtime 2.7.298: declarative queries refuse unsupported operations on encrypted ciphertext instead of returning misleading totals or matches. See `api(at:"query")` (`encrypted_operations`).

- Runtime 2.7.297: native query lists and summaries refresh on tableless private/member-of live hints. See `api(at:"sdk")` (`query_live`).
- Runtime 2.7.297: native create responses preserve encrypted numeric types immediately, matching canonical reads. See `api(at:"encryption")` (`create_readback`).

- Runtime 2.7.296: notification subscriptions discard old-session pending responses and restart their live cursor after native auth/scope changes. See `api(at:"notifications")` (`session_boundary`).
- Runtime 2.7.296: schema writes and checks refuse unsupported/undefined field types and scalar lists instead of silently omitting columns. See `api(at:"schema")` (`field_types`).

- Runtime 2.7.295: create-time cross-field validators see omitted schema defaults, evaluated once for validation and persistence across single/bulk/transaction/ingest/bootstrap writes; explicit null and submitted-field tracking stay distinct. See `api(at:"schema")` (`cross_field_validators`).

`api(at:"<topic>")` is the MCP tool call; on the CLI the same reference is
`benmore api <app> <topic>` (`--at <topic>` also works).

| Feature | Canonical reference |
|---|---|
| Unreleased sharing dialog load errors: failed permission listing shows an error and Retry, clears stale controls, and never claims the row is unshared | `api(at:"permissions")` (`share_dialog_errors`) |
| Unreleased record-share expiry validation rejects malformed dates before changing grants or audit; existing SQLite/RFC3339 formats, valid past dates and no-expiry behavior remain supported | `api(at:"permissions")` (`share_expiry`) |
| Unreleased: flow mail supports CC/BCC with shared recipient limits and private BCC envelopes; opt-in `unsubscribe_one_click` requires one recipient and a valid HTTPS URL | `api(at:"email")`, `api(at:"flows")` |
| Runtime 2.7.298: existing-table Prisma relations install physical constraints; upgrade-check preflights retained references and unsafe rebuilds | `api(at:"schema")` (`relation_migrations`) |
| Runtime 2.7.297: UUID/text-primary-key records support full-text create, edit, delete and search, with atomic repair of existing indexes | `api(at:"search")` (`record_ids`) |
| Runtime 2.7.297: MFA enrollment and removal consume TOTP proofs atomically; spent sign-in/enrollment codes cannot disable the factor | `api(at:"mfa")` (`code_replay`) |
| Runtime 2.7.296: whole boolean SQL parameter references use SQLite 1/0, preserving Boolean readback and predicates | `api(at:"flows")` (`sql_boolean_params`) |
| Runtime 2.7.296: workflow transitions and timeouts advance precise monotonic edit versions, including rapid state cycles and clock skew | `api(at:"workflows")` (`transition_writes`) |
| Runtime 2.7.296: Prisma uuid() uses v4 values; native create/import compatibility preserves stored IDs and custom defaults | `api(at:"scoping")` (`primary_keys.uuid_upgrade`) |
| Runtime 2.7.295: native SDK session and tenant changes clear private query state and rebind live subscriptions | `api(at:"sdk")` (`session_cache`) |
| Runtime 2.7.295: optimistic query rollback preserves newer cache publications and pending reads, including overlapping failed edits | `api(at:"sdk")` (`query_cache`) |
| Runtime 2.7.295: generated record-sharing list types use the actual grantee_id and grant metadata, with nullable expiry | `api(at:"permissions")` (`list_shape`) |
| Runtime 2.7.295: strict JSON numeric inputs remain native JavaScript numbers in compute, including nested arrays/objects | `api(at:"compute")` (`json_numbers`) |
| Runtime 2.7.295: for_each reads arrays nested in compute results and request objects | `api(at:"flows")` (`loop_sources`) |
| Runtime 2.7.295: transactional HTTP and worker flows roll back before independent on_error writes, avoiding lost failure journals | `api(at:"flows")` (`error_handler_response`) |
| Runtime 2.7.294: SQLite update constraint refusals return 400 across PATCH, batch and transactions while preserving rollback and production redaction | `api(at:"errors")` (`update_constraints`) |
| Runtime 2.7.294: workflows, approved commands and SSR membership roles honor groups.role_field; stale legacy roles cannot override it | `api(at:"workflows")` (`transition_roles`) |
| Bulk-write hook contracts: /batch runs per-row effects, streaming ingest runs before-hooks only, atomic import skips per-row hooks | `api(at:"batch")`, `api(at:"ingest")` (`hooks`), `api(at:"import")` (`hooks`) |
| CLI 0.1.51 / runtime 2.7.293: generated workflow tests choose deterministic unconditional transitions and isolated identities for required roles | `api(at:"workflows")` (`generated_tests`) |
| Runtime 2.7.293: hosted restart pins first field-encryption keys before boot; prepared restore/refresh environments stay intact | `api(at:"encryption")` (`hosted_restart`) |
| Runtime 2.7.293: precise generated history intervals, conservative historical gaps and monotonic Prisma timestamp maintenance | `api(at:"versioning")` (`precise_intervals`), `api(at:"concurrency")` |
| Runtime 2.7.292: pending MFA/OTP sign-ins are one-use, credential-bound and commit factor/session changes together | `api(at:"auth")` (`signin_steps`), `api(at:"mfa")` |
| CLI 0.1.50: deploy and multi-file push send schema/config before command flows, with the reviewed manifest last | `api(at:"connector")` (`manifest_authoring`) |
| Runtime 2.7.291: a compute argument that reads an output of a step the flow reached (no row, skipped by `if:`, key not returned) is null again instead of stopping the flow | `api(at:"compute")` (`missing_arguments`) |
| Runtime 2.7.292: `benmore check` refuses missing durable field-encryption keys before database changes; initialize through app startup/environment first | `api(at:"encryption")` (`validation`) |
| Runtime 2.7.292: encrypted fields and non-sensitive full-text columns coexist across checks and restarts; old FTS update triggers upgrade automatically | `api(at:"search")` (`index_lifecycle`) |
| Runtime 2.7.292: tenant-root role/permission policies use the effective tenant despite founder user_id; old ownership cannot cross tenants, and admin act-as stays bounded | `api(at:"access")` (`tenant_root_role_scope`) |
| Runtime 2.7.289: connector registration and authorization drop client-defined scopes (Claude's `claudeai`) instead of refusing the client | `api(at:"connector")` (`connector_grants`) |
| Runtime 2.7.288: a reviewed MCP read tool declares `artifact:` and `artifact.create` exports it as XLSX, a branded HTML report or PDF | `api(at:"connector")` (`connector_grants`) |
| v2.7.290 SDK: cache invalidation and optimistic edits prevent older in-flight reads from replacing newer state | `api(at:"sdk")` (`query_cache`) |
| CLI 0.1.49: automatic types refresh once after the push/deploy batch reload; unverified refresh preserves the file and warns | `api(at:"sdk")` (`types`) |
| v2.7.290: filtered INSERT/SELECT upserts keep their existing outer predicate; WHERE true is a separator fallback | `api(at:"flows")` (`upsert_select`) |
| Runtime 2.7.287 / CLI 0.1.48: guarded soft-delete restore, SDK pagination and accurate mutation/history result types | `api(at:"scoping")`, `api(at:"pagination")`, `api(at:"sdk")` |
| Runtime 2.7.287 / CLI 0.1.48: Prisma scalar validation, typed/null updates and precise optimistic edit timestamps | `api(at:"schema")`, `api(at:"batch")`, `api(at:"concurrency")` |
| Runtime 2.7.287 / CLI 0.1.48: first CLI deploy works and notification callbacks drain every page of a burst | `api(at:"connector")`, `api(at:"notifications")` |
| GHA durable enqueue and legacy active-job keys | `api(at:"flows")` → `enqueue` |
| Runtime 2.7.284: hosted API discovery advertises installed full-text search in CLI and MCP router contexts | `api(at:"search")` |
| Runtime 2.7.283 / CLI 0.1.47: deployed relationships and encrypted-field storage refresh correctly; SDK sharing revoke, row status responses, versioning YAML and mapped full-text search are repaired | `api(at:"permissions")`, `api(at:"encryption")`, `api(at:"versioning")`, `api(at:"search")`, `api(at:"sdk")` |
| Account self-service can be closed with `features.account_settings: false` while identity, password/passkey login, logout, login MFA and required password replacement remain; email changes recheck `auth.domain` / `auth.allow_emails` at request and confirmation | `api(at:"auth")` (`account_settings`) |
| Runtime 2.7.281 / CLI 0.1.46: approved MCP writes resume after a hosted restart or release (the boot check no longer forgets the approval) | `api(at:"connector")` (`connector_grants`) |
| Runtime 2.7.280 / CLI 0.1.45: MCP commands draw server-generated tokens (`generated:`, invitation links), sign a removed member out (`run: revoke_user_sessions`), and declare their own reviewed-migration triggers for approved-write enrollment (`app_triggers:`) | `api(at:"connector")` (`connector_grants`), `benmore docs connector` |
| Runtime 2.7.279 / CLI 0.1.44: approved MCP commands no longer re-scan every enrolled table per step (prepare/commit stay well inside the 30s deadline on large apps); `benmore login --device` works without a terminal | `api(at:"connector")` |
| Runtime 2.7.278 / CLI 0.1.43: pinned file reads, atomic grant cleanup, exact tenant event IDs, singleton detection, WebSocket cleanup, compute arguments, isolated parallel branches, HTTP error responses, response reachability and saved-environment notices | `api(at:"uploads")`, `api(at:"permissions")`, `api(at:"sse")`, `api(at:"scoping")`, `api(at:"websocket")`, `api(at:"compute")`, `api(at:"flows")`, `api(at:"environments")` |
| Unreleased: journeys can declare exact same-origin 4xx denials by method, path, and status; every expected denial must occur, and unrelated failures still fail | `api(at:"verification")` |
| Unreleased: journeys default to preflighting all action targets; `sequential_actions: true` revalidates each target just before trusted interaction when earlier actions render or replace controls | `api(at:"verification")` |
| Unreleased: `csp.frame_ancestors: "'none'"` denies all framing; mixed `'none'` source lists are rejected. `features.analytics: false` keeps HTML no-store and prevents intermediary script injection with `no-transform` | `api(at:"csp")`, `api(at:"analytics")` |
| Unreleased: disable framework HTTP PDF and user-data exports with `features.exports: false` | `api(at:"pdf")` (`availability`) |
| Runtime 2.7.277 / CLI 0.1.42: MCP writes without per-write approval (`approval: grant` + `--auto-approve` + consent), batch approval, writes survive restarts, capability-scope commands, grants API, nullable/optional args, prepare refusals, runtime-only execution digest | `api(at:"connector")` (`connector_grants`) |
| Unreleased generic upload opt-out: `features.uploads: false` closes both HTTP upload endpoints before parsing | `api(at:"uploads")` (`feature_gate`) |
| Unreleased MCP connector pages: one branded layout (app name, favicon, `theme:`/`brand:`), `groups.label` workspace names + single-workspace auto-skip, styled identical "can't be shown" errors, review/batch approve fixed in browsers (`Origin: null`) | `api(at:"connector")` (`connector_grants`) |
| Unreleased MCP auto-approval: a command declared `approval: grant` applies in one call (no browser trip) when the owner ran `benmore mcp enable <app> --writes --auto-approve` and the user ticked it at consent; other writes get `batch_review_url` to approve a connection's pending changes together | `api(at:"connector")` |
| Unreleased MCP review text: command tools declare `title`, `review_summary`, `labels`, `review_changes` in mcp.yaml; review pages show labelled before to after rows; prepared calls return `approval_reason` | `api(at:"connector")` → `connector_grants` |
| Unreleased: apps list and revoke the signed-in user's connected AI clients with `GET /api/_mcp/grants` and `DELETE /api/_mcp/grants/{id}` | `api(at:"connector")` → `connector_grants` |
| Runtime 2.7.276 / CLI 0.1.41: MCP connectors end to end (write-tool consent, hosted origin without seo.url, `table_scopes: access`, `serve --mcp-local`) | `api(at:"connector")` (`connector_grants`), `api(at:"rbac")` |
| Unreleased `table_scopes: access`: declaring capability roles: (e.g. for MCP tool permissions) no longer 403s every auto-CRUD call; access: decides table access | `api(at:"rbac")` |
| Unreleased local connector: `benmore serve <app> --mcp-local [--mcp-writes]` serves the reviewed MCP connector at http://localhost:N/api/_mcp with OAuth, so a connector can be tested before deploy; `scripts/mcp-smoke.py` drives it end to end | `api(at:"connector")` (`connector_grants`) |
| Runtime 2.7.275 / CLI 0.1.40: private upload ownership, feature export path checks, SSE reconnect/refresh, NULL and aggregate queries, and per-row loop values | `api(at:"uploads")`, `api(at:"feature-packs")`, `api(at:"sse")`, `api(at:"query")`, `api(at:"flows")` |
| Runtime 2.7.274 / CLI 0.1.39: encrypted history and schema repair, atomic password/workflow writes, safe migrations/backups/retention, related-row access, async tenant broadcasts, accurate pagination and source synchronization | `api(at:"encryption")`, `api(at:"versioning")`, `api(at:"auth")`, `api(at:"workflows")`, `api(at:"recovery")`, `api(at:"scoping")`, `api(at:"async-flows")`, `api(at:"flows")`, `api(at:"environments")` |
| Unreleased encrypted writes: `benmore_encrypt_plaintext(value, table, column)` seals prefix-looking plaintext; trigger replacement is transactional and a failed install refuses app load while preserving prior triggers | `api(at:"encryption")` |
| Unreleased: password recovery invalidates prior MFA enrollment grants; encrypted-field unmasking and filters honor the row's tenant | `api(at:"mfa")`, `api(at:"encryption")` |
| Unreleased: historical reads normalize timestamp offsets, interrupted ingestion reports committed counts, bulk booleans use 1/0, and malformed queued input fails before execution | `api(at:"versioning")`, `api(at:"ingest")`, `api(at:"batch")`, `api(at:"async-flows")` |
| Unreleased: signed-in flow responses use private/no-store caching; api/webhook missing inputs stop before delivery, webhooks require 2xx, and respond arrays resolve nested values | `api(at:"flows")` (`respond_headers`) |
| Unreleased: `run: parse` with `source: headers` exposes canonical inbound header names and all values as arrays, separate from the body and marked as request input | `api(at:"flows")` (`parse`) |
| Unreleased: `bm.api` accepts custom headers and AbortSignal options while retaining automatic CSRF and same-origin credentials | `api(at:"sdk")` (`request_options`) |
| Unreleased: opt-in `on.request.strict_json: true` caps requests at 32 KiB and rejects duplicate JSON keys, malformed/trailing JSON, non-object bodies, and non-JSON media types before flow steps | `api(at:"flows")` (`strict_json`) |
| Unreleased: flow step values that were dropped are sent - `run: webhook` `payload:` (or a map/list `body:`) is the JSON body (no longer the whole context); a `${{ }}` or quoted respond `status:` is rendered (an integer 200-599, else the step fails with a 500 - no silent 200); `run: api` `body:` as a map/list and `json:` as a list are sent as JSON; respond `headers:` / `content_type:` are sent through an allowlist (a declared type sends a text body as written); email `unsubscribe_url` becomes `List-Unsubscribe` (https only; one-click POST is opt-in) | `api(at:"flows")` (`respond_headers`), `api(at:"email")` |
| Unreleased: a server error from a built-in route or a flow keeps its status and shape, but outside `serve --dev` the answer is the route's generic text plus a request id (`list failed (request id: ...)`, JSON `{"error": ..., "request_id": ...}`, `X-Request-Id` header), never SQLite's text; the detail is in `_benmore_request_log.error` / `request_id`, `get_request_logs` (`request_id` filter) and a `SERVER ERROR` journal line | `api(at:"errors")` (`server_errors`) |
| Unreleased: the database engine is SQLite 3.53 - a number computed in SQL and written as text or JSON there (`json_object('total', price * qty)`, `CAST(.. AS TEXT)`, `||`, a `SUM()` of REAL prices) keeps up to 17 digits (`434.99999999999994`, was `435.0`): round it in the statement (`round(.., 2)`); a top-level `EXISTS (...)` with `LIMIT .. OFFSET` returns the right page and `EXISTS` over an `OR` of indexed columns finds its row (both were wrong before); the query deadline now stops a statement at any step | `api(at:"flows")`, `api(at:"query")` (`query_deadline`) |
| Unreleased: a flow step key its step type does not read is refused at write time and logged at load (`retry`/`on_error`/`if`/`id` under `with:`, `timeout` off api/compute/transcribe, `params` on `sql_dynamic`, `with.sql`, any `with:` key not listed for the type); `else:` on a gated `if:` + `run:` step, `with.timeout` on transcribe and step-root `timeout` on compute are read now; a SQL step with no statement fails with `no SQL statement` | `api(at:"flows")` (`step_keys`) |
| Unreleased: SQL flows can call `benmore_today('America/New_York')` for the server's current date in an IANA zone; blank, `Local`, and invalid zones fail the SQL statement | `api(at:"flows")` (`timezone_dates`) |
| Unreleased: a table/column name in config must be a plain identifier (letters, digits, `_`, not starting with a digit): `groups.table`/`key`/`user_field`/`role_field`/`bootstrap.org_table`, encrypted.yaml and inline `encrypted:` tables/columns, retention.yaml `table`/`column`, a workflow's `table`/`field` - a non-identifier is refused at push / `benmore check` instead of breaking at reload (plain names unchanged) | `api(at:"scoping")` (`tenant_bootstrap`) |
| Unreleased: `expect_rows` is checked on every `run: sql` / `sql_dynamic` step - rows returned for a SELECT or a `RETURNING` write (it was ignored there), rows affected otherwise - and under `with:` (was ignored; the step root is canonical); `WITH ... <write>` without RETURNING stores `rows_affected`; an assertion that cannot be checked is refused at write time and stops the step. A valid mismatch in an approved command records a retryable `conflict`; SQL/assertion/count errors remain operational | `api(at:"flows")`, `api(at:"connector")` |
| Unreleased: `${{ steps.<id>.outputs.rows_affected }}` resolves (it never did: `!=` on it was always true, `==` always false; same for any output column named `rows…`) | `api(at:"flows")` |
| Unreleased: a hard-bounce email pause ends by itself (24h, then 72h, then manual; complaints stay manual) and a resume restarts the measurement; accepting an ownership transfer is refused while the app carries paid features the recipient's plan lacks (`plan_gaps`); `GET /platform/ops/over-plan` for operators | `api(at:"email")`, `api(at:"collaborators")` |
| Unreleased security round seventeen: `before_update` hook SQL placeholders are the request's fields again (2.7.251 regression); the groups membership table needs a tenant admin unless it declares its own rule; `member-of:` parents can be explicit (`<join>=id`); encrypted secret-named columns stay hidden without unmask roles; email `to:` values are one recipient (`| recipients` for a list) and HTML email bodies escape values (`| raw` keeps markup); sign-up limits (`auth.signup_rate_limit`); support sessions can't manage credentials | `api(at:"hooks")`, `api(at:"scoping")`, `api(at:"access")`, `api(at:"encryption")`, `api(at:"email")`, `api(at:"auth")` |
| Unreleased security round sixteen: `self`/`group` access returns 404 on tables with no owner/tenant column (declare `everyone` if intended); membership identity and reactivation guarded; per-app Stripe events applied once and in order; presence honors `ws_rooms`; IPv6 /64 sign-in and flow rate limits | `api(at:"access")`, `api(at:"auth")`, `api(at:"payments")`, `api(at:"realtime")` |
| Unreleased: `/sitemap.xml` and `/robots.txt` serve your own `static/sitemap.xml` / `static/robots.txt` when present; generated links no longer point at localhost on hosted apps | `api(at:"frontend")` |
| Unreleased security round fifteen: JSON bodies/room payloads keep values whole; payload-less `ws:` sends only `{}`/`{"table":…}` (declare payloads); `validators.yaml` compares whole operands; tenant roles no longer pass `perm:` on un-grouped tables; hosted writes refuse editor auto-run config | `api(at:"hooks")`, `api(at:"flows")`, `api(at:"access")`, `api(at:"realtime")` |
| Unreleased security round fourteen: `benmore sync`/`pull` stay inside the workspace and skip hidden/auto-run files; an email change revokes tokens and grants and applies on a confirm button; `run: compute` gets copies of its args; `/api/_schema` follows RBAC scopes; session recordings mask secrets | `api(at:"auth")`, `api(at:"flows")`, `api(at:"components")`, `api(at:"frontend")` |
| Unreleased: a stale `mcp.yaml` review no longer freezes the app; it reloads from disk with only the connector off, writes warn `mcp_connector_withheld`; review again and push `mcp.yaml`, or delete it if the app serves no connector | `api(at:"connector")` (`manifest_authoring`) |
| Unreleased app MCP authoring from app files: unsealed review, complete native manifest and manifest-last deployment (target CLI 0.1.37 / runtime 2.7.259) | `benmore docs connector`, `api(at:"connector")` |
| Unreleased `pwa.service_worker: /static/sw.js` serves the app's own service worker at the reserved `/sw.js` (offline cold start); opt-in, other apps unchanged | `api(at:"mobile")` (`pwa_service_worker`) |
| Read-only MCP starter in server-created HTML apps and self-hosted framework starters; hosted CLI apps add a connector after first deploy and pull; explicit source review via `benmore mcp review <appdir> --reviewed` | `api(at:"connector")` (`connector_grants`) |
| Unreleased security round thirteen: tenant roles no longer pass `role:` gates on un-grouped tables (list shared catalogs under `groups.shared`); env-derived values make outbound calls credentialed; a recent sign-in can add a passkey; `GOMEMLIMIT`/`GOGC` reserved | `api(at:"access")`, `api(at:"flows")`, `api(at:"auth")` |
| Unreleased security & performance round twelve: `bm.auth.passkey.register(name, { password })` needs a proof; a tenant role named `admin` is not a global admin and `perm:` needs `roles:`; batch/ingest run the single-row gates and foreign keys must name readable parents (422); has-many `?include=` caps at 100 per parent (`_include_truncated`); `run: api` URL values are encoded per position (split `owner/repo`, use `with.query`); realtime row-scoped tables send others the generic refresh; `/static/*.js` revalidates; gotmpl lost Sprig env/DNS helpers; `sql write:true` takes one DML; collaborator invites need accepting | `api(at:"auth")` (`passkeys`, `recovery_hardening`), `api(at:"rbac")`, `api(at:"access")`, `api(at:"scoping")` (`includes`, `foreign_keys`, `automatic_indexes`, `deep_pagination`), `api(at:"batch")`, `api(at:"flows")`, `api(at:"realtime")`, `api(at:"frontend")`, `api(at:"query")` (`query_deadline`), `api(at:"recovery")` (`db_pool_sizing`, `audit_retention`), `api(at:"collaborators")` |
| Unreleased security round eleven (MCP connector): a password change revokes connector grants; command event flows keep row taint; command SQL with an unclosed `/*` is refused; commands, file ingest and artifacts work on apps without groups; `GODEBUG`/`MCPGODEBUG` are reserved env keys | `api(at:"connector")` (`connector_grants`) |
| Unreleased passkeys: `bm.auth.passkey.register()` / `.signIn()` add Face ID / Touch ID / phone sign-in to any app (on by default, `auth.passkeys: false` turns it off); a passkey works only on the host it was created on | `api(at:"auth")` (`passkeys`) |
| Unreleased auth controls: `auth.signup: false`, `auth.password_reset: false`, and `auth.api_tokens: false` close public account creation, end-user password recovery, and user token issuance; defaults stay on | `api(at:"auth")` (`self_service_controls`) |
| Unreleased immutable file originals/blocks: ingest returns a processing ID; verify rechecks current access against retained snapshots; every restore revokes delegated credentials | `api(at:"connector")` (`connector_grants`) |
| Unreleased fixed-tool PDF/OCR qualification: native, raster-only, rotated, encrypted and missing-provider paths run in Linux amd64 CI; Ubuntu 22 English data is installed at the frozen path | `api(at:"connector")` (`connector_grants`) |
| Unreleased artifact manifest schema version and private telemetry format/source-schema revisions; confirmed workflow terminal transitions are counted after commit without payloads | `api(at:"connector")` (`connector_grants`) |
| Unreleased hook/webhook delivery: only 2xx is delivered; ordinary subscription retries, permanent failures and unknown transport outcomes stay distinct; approved effects never blindly replay | `api(at:"connector")` (`connector_grants`) |
| MCP connector: reviewed manifests, tools and command approvals; durable execution and recovery; attributable files/artifacts; static resources; external connections and owner switches | `api(at:"connector")` (`connector_grants`) |
| Unreleased Notify Hub portability fixture: native and pinned remote status reads expose only id/status/timestamps through a shared StatusCard; recipient/subject remain outside tool output and observability, foreign reads are denied, and no send tool exists | `api(at:"connector")` (`connector_grants`) |
| Unreleased immutable MCP artifacts: `artifact.export` formats the caller's committed reviewed-command receipt as XLSX, escaped HTML or sandboxed PDF; private manifests bind owner, account incarnation, tenant and original scopes; byte retrieval is owner-only, cookie-session-only, rechecks current role/scopes, and verifies size/hash | `api(at:"connector")` (`connector_grants`) |
| Unreleased read-tool artifacts: a native read tool declares `artifact: {title, formats, sheets: [{name, source, columns}]}` in `mcp.yaml` (contract-digest content, omitted when absent) and the built-in `artifact.create` re-runs it with the caller's grant to store an XLSX (typed cells, frozen header), printable branded HTML or sandboxed PDF through the same immutable store, with per-user rate, size and 25-artifact/128 MiB ring budgets | `api(at:"connector")` (`connector_grants`) |
| Unreleased security round ten: flow `auth: true`/`yes`/typos now require sign-in (were public); `${{ a == steps.x.y }}` compares the ref's value; the write gate refuses config keys the parser drops (flows, workflows incl. parsed `states:`, access ops, app.yaml auth/features, cron.yaml) and conditions that can never be true; a step id that shadows a request field warns; renaming a model under `@@map` keeps its table; hosted apps can't set `PATH`/`LD_*`/`GIT_*`/transcribe binary paths; rotate keys with `rotate_encryption_key` | `api(at:"flows")`, `api(at:"workflows")`, `api(at:"access")`, `api(at:"encryption")`, `api(at:"environments")` |
| Unreleased command-owned fields: `command.owns: [table.column]` makes generic CRUD (create, update, batch, ingest, transaction, group bootstrap, admin panel, import Mode A, connector update; admins included) refuse the column with 403 `field_owned_by_command` (an unchanged echo on update is allowed for callers who can read the column; `deleted_at`/`updated_at` cannot be owned); ownership is CRUD-only, so flows, hooks, other commands and Mode B restore can still write it | `api(at:"scoping")` → `command_owned_fields`, `api(at:"connector")` (`connector_grants`) |
| MCP owner switches: `benmore mcp status\|enable\|disable <app> [--writes] [--export] [--publication] [--revoke] [--env dev\|prod]` control owner-only exposure; the hosted app still needs provisioned authority, live user grants and a real-client check. Disable is protective; revoke requires every client to reconnect | `benmore docs connector`, `api(at:"connector")` (`connector_grants`) |
| Unreleased hosted push fix: `write_file`/`edit_file` run only source validators after a write, scoped to the written file unless it is schema/app/flows config (app-load and drift moved to `check`); `write_file` takes `reload:false` and `benmore deploy` reloads once per batch; restart surfaces return 202 `verified:false` instead of 503 when the restart was issued but not verified in time | `api(at:"environments")` (`restart_and_reload`) |
| Unreleased per-app router request budgets: each app (dev and prod separately) gets 600/min per IP at the router, the platform API keeps its own 300/min, an overall 1200/min per IP caps the total, every 429 carries Retry-After, and the CLI retries such 429s | `api(at:"environments")` (`request_budgets`) |
| MCP read-flow prerequisite: `run: api` can capture explicitly listed integer 4xx responses with `with.handled_statuses`; malformed/duplicate values and pagination combinations are rejected, `success_when` still applies, and 5xx/read/transport/over-1-MiB responses remain errors | `api(at:"flows")` |
| MCP approved writes: with owner write exposure on and host authority provisioned, command tools only prepare (operation id, exact preview, 15-minute expiry, review link); a person approves in the browser, then `_commit` applies once and `_status` reads durable state; no approve tool exists and writes off hides and refuses every surface | `benmore docs connector`, `api(at:"connector")` (`connector_grants`) |
| Unreleased approved-command CRUD parity: validators, computed/encrypted fields, workflow role guards and outboxed event flows follow the command transaction; unsupported kinds remain refused | `api(at:"connector")` (`connector_grants`) |
| MCP synchronous command-flow prerequisite: `transaction: true` responses wait for commit, buffer up to 1 MiB, and reject nested `serve_file`; a missing `respond` still commits prior SQL and returns the existing diagnostic 500 | `api(at:"flows")` (`transactional_responses`) |
| MCP native update prerequisite: PATCH and atomic transaction updates share scoped validation/hooks and optimistic concurrency; SQL after-hooks, readback, audit and durable delivery intents commit together, while host connector retry/recovery acceptance remains open | `api(at:"PATCH /api/<table>/{id}")`, `api(at:"batch")` (`cross_table_transaction`) |
| MCP revision prerequisite: explicit opt-in bootstrap installs incarnation-bound revisions and retained tombstones; read-only verification fails closed on schema/trigger drift and unsupported tables. Hosted enrollment and restore-epoch acceptance remain separate gates | `api(at:"batch")` (`cross_table_transaction`) |
| MCP source CLI: inspect, generate disabled OpenAPI candidates, check and explicit review run from app files without a framework checkout; hosted authority and real-client acceptance remain separate gates | `benmore docs connector`, `api(at:"connector")` (`connector_grants`) |
| Unreleased private MCP file tools bind private upload references to a readable table row; bounded CSV/XLSX/XLSM results keep cell coordinates, `verify` checks `VerifySpan`, and PDF uses bounded Poppler layout plus Tesseract OCR when fixed binaries and English data exist | `api(at:"connector")` (`connector_grants`) |
| Unreleased MCP PDF extraction caps documents at 200 pages, 40 MP/page, 60s/512 MiB per child page, 512 MiB temp and 10 minutes total; encrypted PDFs fail closed; child processes require a proven seccomp socket-deny probe and fail closed if host policy blocks it | `api(at:"connector")` (`connector_grants`) |
| MCP SQL metadata/identifier matching and captured schema and user migration inputs preserve tenant guards and migration semantics; validate against the host's actual schema and migration state | `api(at:"schema")` (`sql_metadata`) |
| Unreleased B1: `on.request.permissions: [projects:read]` requires identity and all declared scopes on direct HTTP, discovery and scheduling; scoped admins cannot bypass it | `api(at:"flows")` (`permissions`) |
| Flow `if:`/`success_when:` take `&&`, `||`, `!` and parentheses (JavaScript semantics; one-comparison conditions unchanged) and serve_file `disposition:` takes a `${{ }}` expression; hook and workflow `when:` is a SQLite condition over the row (`status IN (...)`, `x IS NOT NULL`, `old_x != x`, subqueries), checked against schema.prisma at write time (v2.7.247) | `api(at:"flows")`, `api(at:"hooks")` (`when_conditions`), `api(at:"workflows")` |
| Security round eight: substituted values are never expanded as templates (a submitted `{{env.X}}` stays text), `if:`/`when:` read the operator from your condition and compare numbers numerically (`>=`/`<=` now fire), `${{ user.group_id }}` in flows is the session tenant, request fields can't stand in for step outputs, new workflow rows start in `initial`, frontmatter `require:`/`role:` are enforced, page query values bind as arguments, per-app OAuth tokens carry the approved scope (v2.7.246) | `api(at:"flows")`, `api(at:"workflows")`, `api(at:"frontend")` (`ssr_page_gates`), `api(at:"oauth")`, `api(at:"mfa")` |
| Security round nine: a list filter or sort on a hidden column (`share_token`, `*_api_key`) answers 400, so read those through a flow; `sql_dynamic` text can't use a step output built from request input (bind it with `:name` in `run: sql`); `enqueue` needs a literal `flow:`; a before-update hook row holds only the written columns; sending-domain claims need DKIM or a TXT proof; v2.7.248 | `api(at:"scoping")`, `api(at:"flows")`, `api(at:"sql-dynamic")`, `api(at:"email")` |
| `run: compute` args pass env: `key: "${{ env.NAME }}"` now arrives as the value instead of `null`/the default, and a bare `if: ${{ env.NAME }} == 'x'` compares the real value (v2.7.245) | `api(at:"compute")` (`args`) |
| Cookie banner text is truthful by default; set `seo.cookie_notice` / `seo.privacy_url` when your app adds trackers, and load them only after `window.bmCookieConsent() === "accepted"` or the `bm:cookie-consent` event (v2.7.244) | `api(at:"analytics")` (`consent_banner`) |
| `verify: stripe` style string verifiers accept `secret: "${{ env.NAME }}"` and reject every request when it doesn't resolve; top-level `idempotent: true` on an async flow requeues its crashed jobs; `bm.notifications.list({limit, offset, unread})` and `onNew` work (v2.7.243) | `api(at:"webhooks")`, `api(at:"async-flows")`, `api(at:"notifications")` |
| Restoring a database backup rolls back data but not sign-in state: live passwords, MFA and deactivations carry over, and sessions, tokens and grants revoked since the backup stay revoked (v2.7.242) | `api(at:"recovery")` (`database_restore`) |
| Hosted app databases: at the plan storage limit creates, tenant bootstrap and imports answer 507 `storage cap reached`; SQLite stops all growth a quarter (at least 64 MiB) past it on every connection. A password `create_superuser` / `set-password` sets on an existing account is temporary; flows without a session send live events only to the tenant their trusted trigger data names (v2.7.242) | `api(at:"recovery")` (`storage_limit`), `api(at:"auth")`, `api(at:"flows")` (`realtime_events`) |
| Flow `run: sql`/`sql_dynamic` writes now emit the same `{table, action}` live events as auto-CRUD (after commit; nothing on rollback), and `run: broadcast` sends a server message to a WebSocket room's members; TSX build errors in an imported file clear once it is fixed (v2.7.240) | `api(at:"flows")` (`realtime_events`, `broadcast_step`), `api(at:"websocket")` |
| Session cookie is `__Host-benmore_session` over HTTPS (everyone signs in once after upgrading); grandfathered unverified accounts verify their email at the next password sign-in in apps that key grants by email; edges can be served from a separate domain (v2.7.239) | `api(at:"auth")`, `api(at:"edges")` |
| Security round six: browser bundles and compute modules import only inside `static/`, compute results must be JSON and backtracking regex matches are time-bounded, admin-only management needs an unscoped admin credential, membership roles come from the current tenant, workflow transitions honor locks and races, `{{user_group_id}}`/`{{_submitted}}` in hooks are session-owned/written-columns-only, content checksums visible again (v2.7.238) | `api(at:"frontend")`, `api(at:"compute")`, `api(at:"auth")`, `api(at:"workflows")`, `api(at:"hooks")`, `api(at:"scoping")` |
| Security round five: per-caller docs/types/flow registry, text-credential columns hidden on every read, context-aware mustache escaping, same-origin templated redirects, `{{_submitted}}` in before-hooks, `auth.profile_fields`, `groups.active_field`, email-keyed grants after verification, hashed session ids and encrypted TOTP secrets at rest (v2.7.237) | `api(at:"scoping")`, `api(at:"auth")`, `api(at:"frontend")`, `api(at:"flows")`, `api(at:"hooks")` |
| QA at scale: `qa_inventory` surfaces every page/button/form and declared access, flow and workflow expectation and drafts `tests/journeys/*.yaml`; `browser_batch` and `benmore verify` replay journeys on one shared headless browser (isolated tab per journey, `pending` resubmission); scaffold carries `data-testid` on every control (v2.7.229) | `api(at:"qa")`, `api(at:"verification")` |
| Checked app history, protected staging, restore and GitHub push guards (v2.7.226) | `api(at:"github")`, `api(at:"environments")` |
| Dev refresh checks stop/drain, preserves the database/key pair and verifies activation (v2.7.226) | `api(at:"environments")` (`refresh_dev`) |
| Environment application preserves the previous snapshot on failure and distinguishes saved, materialized and restart-queued state (v2.7.226) | `api(at:"recovery")` (`environment_materialization`) |
| Database restore validates first, stops/drains writers, preserves the prior bundle and verifies a fresh runtime (v2.7.226) | `api(at:"recovery")` (`database_restore`) |
| Archive uploads stage before mutation and report verified activation or explicit failure state (v2.7.226) | `api(at:"recovery")` (`archive_deploy`) |
| Covered lifecycle changes share an app slot; stale reloads cannot revive deleted or replaced apps | `api(at:"recovery")` (`lifecycle_coordination`) |
| Pending migrations alone trigger their batch backup; startup reports migration failures and phase timings (v2.7.226) | `api(at:"recovery")` (`startup_migrations`) |
| OAuth connection controls reflect configured providers, show read failures, and keep custom definitions per app (v2.7.226) | `api(at:"oauth")` |
| Read-audit and usage buffers stay per app and flush during graceful worker shutdown (v2.7.226) | `api(at:"audit")` (`buffer_lifecycle`) |
| Analytics visits commit atomically and report storage failures; concurrent pageviews share the active visitor session (v2.7.226) | `api(at:"analytics")` |
| Dashboard publish confirms the previewed source; unreadable migration plans block publishing and post-restart verification is explicit (v2.7.226) | `api(at:"environments")` (`publish_preview`) |
| Dashboard and MCP resets roll back on failure, preserve framework/history tables and return committed counts (v2.7.226) | `api(at:"recovery")` (`reset_and_seed`) |
| App deletion retains the name on teardown failure and supports retry | `api(at:"recovery")` (`delete_app`) |
| Restart waits for a healthy new runtime; reload receipts advance only after handler installation | `api(at:"recovery")` (`restart_and_reload`) |
| Shared Codex/Claude skill bundle, edition-aware app AGENTS.md, explicit delivery and verification | `api(at:"harness")`, `api(at:"cli-install")` |
| Source-verified schema, cron and OAuth setup contracts | `api(at:"schema")`, `api(at:"cron")`, `api(at:"oauth")` |
| Malformed configuration rejects startup/reload before migrations or worker shutdown; explicit removal and supported legacy flow maps remain supported | `api(at:"recovery")` (`configuration_loading`) |
| Full-text indexes are reused on unchanged startup/reload and rebuilt atomically when definitions change | `api(at:"search")` (`index_lifecycle`) |
| Workflow validation and preservation of the running app on rejected reloads | `api(at:"workflows")` (`reload`) |
| Read-only MCP database inspection with bounded results and query cancellation | `api(at:"query")` (`mcp_query_db`) |
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
| Headless CLI auth: `login`/`bootstrap` accept `--token` or `BENMORE_TOKEN` (env tokens stay ephemeral; non-TTY credential gaps fail immediately). Email/password flags and `benmore signup` get 403 on a platform that requires the emailed sign-in code, as benmore.ai does - sign in through the browser | `api(at:"cli-auth")` |
| Reliable agent delivery loop: `benmore hooks` merges Claude Edit/Write validation + push hooks without replacing existing settings; `benmore sync-status --all` checks every pulled app and must be clean before completion. Codex/other agents push explicitly (no claimed automatic Codex hooks). | `api(at:"sync-status")` |
| Server-only `run: delete_upload` removes only this app's private stored references, rejects foreign/public/traversing URLs, and fails loud so active SQLite work rolls back (external bytes are not transactional) | `api(at:"uploads")` |
| Support operators can clear a reviewed email circuit-breaker pause with `benmore email <app-subdomain> resume`; reputation history and suppressions remain intact | `api(at:"email")` |
| `run: sms` flow step + `sms:` hook: text from a flow (`with: { to, body }` → `steps.<id>.outputs.to`) or on a data event (`sms: { to, body }` + `when:`). Both were documented but unimplemented, so apps silently sent nothing; hooks.yaml keys are now allowlisted at write time so an unrecognized key can't be dropped in silence | `api(at:"sms")` |
| `run: transcribe` flow step: local audio→text (ffmpeg + whisper.cpp on the host, no vendor/API key, every edition); `with: { file, model?, language? }` → `steps.<id>.outputs.text`; local-file-first, loud degrade when binaries/model missing | `api(at:"transcribe")` |
| Unreleased `inspect_private_upload` / `render_pdf_signatures` flow steps inspect app-private PDFs/PNG signatures and stamp a separate private PDF through the isolated parser; inspection is bounded to 90 seconds and render to 120 seconds across reads and worker work, while a started storage save may take up to 30 seconds. The app must authorize and snapshot exact source/image hashes and placement geometry, then use a durable completion CAS because renderer bytes are not deterministic | `api(at:"flows")` |
| Multiple custom domains per app: `benmore domain <app> <domain>` ADDS a domain (up to 10 per app, e.g. ceo.example.com + vc.example.com on one app); `--verify`/`--remove` target one domain, omit the domain to act on all (v2.7.205) | `benmore domain --help`; `api(at:"dns")` |
| Robust Markdown: `bm.markdown(text)` now server-renders via the benmark engine (CommonMark + GFM + syntax highlighting + mermaid + media embeds + wikilinks + front matter), sanitized; `bm.markdownBatch()` + `{{ body \| markdown }}` pipe + `<Markdown>` component | `api(at:"markdown")` |
| Local/remote source safety (`benmore sync-status`, `.benmore/remote.json`, guarded push/pull/deploy/delete) + reusable `feature.yaml` packs including kanban, notify-hub, and foundry starters | `api(at:"sync-status")`, `api(at:"feature-packs")` |
| GitHub sync: one-way mirror of the app's git history to a user-owned GitHub repo/org - OAuth connect in dashboard → Version Control, auto-push on every commit (Live → main, Sandbox → dev) (v2.7.202) | `api(at:"github")` |
| `benmore deploy <dir>`: first-deploy uses a bare scaffold (no Notes demo merged into your app) + per-file push failures are reported while the rest still ship (v2.7.201) | - |
| Managed social login (zero-setup Google/Microsoft), Stripe Connect (per-env keys), managed DNS zones (v2.7.200) | `api(at:"oauth")`, `api(at:"payments")`, `api(at:"dns")` |
| Platform SMS service: zero-config transactional SMS + dedicated per-app numbers (v2.7.199) | `api(at:"sms")` |
| Platform email service: zero-config sending for every hosted app + BYO domain (DKIM), quotas, suppression, auto-pause (v2.7.197) | `api(at:"email")` |
| browser_check: viewport `width`/`height` args, overlay-proof trusted clicks (chrome hidden + targets centered), `deadline_exceeded` flag + no share links for incomplete runs (v2.7.195) | - |
| browser_check: native `fill`/`select` setters dispatch + verify `input`/`change`, empty values are valid, date inputs accept only valid ISO values, actions preflight before mutation by default, and dynamic journeys can opt into `sequential_actions: true`; see `api(at:"browser_check")` | - |
| Env-safe encryption: platform `sql` reads/writes use the tenant's own key, ENCRYPTION_KEY auto-pinned at provision, decrypt failures masked (never raw ciphertext); promote backup-preflight + `delete-file --env` + 48KB probe bodies (v2.7.194) | `api(at:"encryption")` |
| Tiered row access `read: owner_or_role:<roles>` (owner OR role-holder sees the row) | `api(at:"access")` |
| Per-flow `rate_limit: "5/hour per ip"` (429 + Retry-After) + `expect_rows:`/`rows_affected` (fail loud on guarded 0-row writes) | `api(at:"flows")` |
| `mode: async` flows: `respond:`/`redirect:` are no-ops in the worker (warned by `benmore check`) | `api(at:"async-flows")` |
| `benmore status`/`diff` (dev↔prod drift) + `benmore doctor` (release-readiness PASS/WARN) - CLI pre-flight before promote/publish | - |
| Enterprise hardening: fail-closed recovery of interrupted async jobs, framework/cloud serve validators, `benmore test`, transactional migrations, `DB_SYNCHRONOUS=FULL|EXTRA`, and platform WAL shipping/PITR (`BENMORE_WAL_SHIP=1`, `benmore restore --pitr --as-of`) | `api(at:"async-flows")`, `api(at:"environments")` |

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
# Headless alternative (token from an earlier browser login):
# benmore login --token "$BENMORE_TOKEN"

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

Don't just write files and stop. Work in this loop until the app genuinely
**works and looks right**:

1. **Understand & plan.** Read the request. For an existing app, orient first:
   `get_app_map`/`describe`, `list_tables`. Decide the schema,
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

"The file is written" is not "it works." You're done when the relevant checks above pass.

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
   bundled file changes, ~10ms recompile. A compile error emits a module that
   throws on load with a clear console message, so the page still boots.

3. **CSRF auto-injection.** Every served `.html` gets a
   `<meta name="csrf-token">` and a hidden `_csrf` input in native POST forms.
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

frontend:
  stack: html                 # html (TSX, default) | gotmpl (SSR for SEO pages)
```

Other keys: `brand`, `font`, `seo.{description,url,favicon}`,
`auth.{otp,domain,redirect,require_verified,verify_email,mfa,signup,password_reset,api_tokens}`,
`roles.<name>.scopes`, `features.{admin,sse,ws,ws_anonymous,analytics}`,
`groups.{table,key,user_field}` (multi-tenant isolation),
`pwa.{name,icon,offline}`, `backup.{interval,keep}`,
`aggregates.<name>.{sql,refresh}`, `access.<table>.{read,write,update,delete}`,
`auto_memberships.<parent>.{table,parent,members}`.

OAuth provider metadata uses top-level `oauth:`; provider credentials come from
per-app environment values such as `GOOGLE_CLIENT_ID` and
`GOOGLE_CLIENT_SECRET`. Do not nest an OAuth object inside the scalar `auth:`
map. Built-in provider sign-in routes are `/auth/<provider>`; see
`api(at:"oauth")` for managed hosting, custom providers, and callbacks.

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

  // SSE invalidation. A ChangeEvent is { table, action } - never the row.
  // SSE is opportunistic - always refetch after your OWN mutations too.
  // FLICKER WARNING: in refresh(), don't do "ul.innerHTML = rows.map(...)" -
  // that rebuilds every row on each event (the whole list flashes, focus is
  // lost, icons re-init). Use the scaffold's reconcileList (static/lib/dom.ts),
  // which reuses unchanged rows and only touches what changed.
  bm.live('posts', (ev: ChangeEvent) => refresh());

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
| `bm.broadcast.{publish, subscribe, stats}` | SFU livestream (1:N); the returned handle has `.stop()` |
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
| GET | `/api/<table>?q=...` | FTS5 search (needs `@@fulltext`) |

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
  CLI creation refuses an existing email without resetting credentials or
  changing its role. It uses the distinct `create_app_user` platform tool, so
  a platform release that lacks the tool refuses before account mutation.
  `benmore users <app> list --all --env dev` includes
  deactivated accounts for provisioning checks. Stdin accepts up to 64 KiB and
  removes only trailing CR/LF. In the browser,
  `bm.auth.signUp({ email, password })` posts to
  `/signup`; there is no `/api/auth/signup`. Passwords need at least 8
  characters, an uppercase letter and a special character (`!@#$%^&*` etc.).
- **Access modes** - per table in `app.yaml`: `read/write/update/delete` set to
  `anon`, `everyone`, `self`, `group`, `admin`, `role:a,b` (any-of),
  `perm:<resource>.<action>`, or `member-of:<table>(<join_col>,<user_col>)`
  (v2.7.164 - "visible to members of this room/channel/project" via a
  membership table; the framework emits the EXISTS guard on every read/write
  path, auto-joins the creator on parent creates). A table without the join
  column must be the parent the join column points at (relation, or the
  `<singular>_id` name); write `member-of:<table>(<join_col>=id,<user_col>)`
  to declare it, otherwise the rule is refused (`api(at:"access")` →
  `member_of`). Multi-role RBAC with inheritance and optional per-group
  (tenant) scoping is supported.
- **Multi-tenant founding moment** - `groups.bootstrap: {org_table: companies,
  founding_role: company_admin}` enables `POST /api/_groups/create` (org +
  founding membership in one transaction); `groups.role_field: member_role`
  loads the member's in-tenant role into the session so `role:company_admin`
  access modes enforce tenant roles (v2.7.164) on tables with the group key;
  on a table without it only global roles pass (for `perm:` gates too: only
  permissions a global role grants), and on the org table itself a tenant role
  reaches only the caller's own org row (`api(at:"access")`). Adding, changing
  or removing rows of the membership table through `/api/<groups.table>` takes
  a tenant admin (the founding role, or `role:admin`) unless you declare an
  access rule on that table; a member can always leave
  (`api(at:"scoping")` → `membership_management`).
- **WS room authorization** - `ws_rooms: {"room-:id": room_members(room_id,
  member_id)}` in app.yaml gates WebSocket `join` on a membership row
  (v2.7.164); undeclared rooms behave as before.
- **Hooks** (`hooks.yaml`) - `before_*` (sync, can abort a mutation) and `on_*`
  (async side effects: SQL, webhook, email, notify) on insert/update/delete.
  An email body is HTML: `{{col}}` values are escaped, `{{{col}}}` is
  sanitized HTML and `{{{{col}}}}` is raw (`api(at:"hooks")` → `html_emails`).
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
`.benmore`, logs, and generated `src/bm.d.ts`. `pull` and `sync` never write
hidden directories outside `static/` (other than `.well-known`/`.github`) or
editor/agent auto-run config (`.vscode`, `.claude`, `.mcp.json`, `.envrc`,
`*.code-workspace`, ...); they list them as skipped (`api(at:"sync-status")`).
The server leaves the same paths out of pull archives and manifests, so older
CLIs never receive them either, and hosted write tools refuse the named
auto-run config outside `static/` (deploy and the save hook keep it local).

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
