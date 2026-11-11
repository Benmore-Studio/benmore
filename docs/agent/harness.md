# Benmore agent harness: discover, change, verify, deliver

This is the operating contract for an agent building an app with Benmore. Start
here to choose the right environment and tools, then read `benmore docs build`
for app anatomy and `api(at:"<topic>")` for the feature's current wire contract.
Agents editing Benmore's Go source should instead follow the repository's root
`AGENTS.md`, architecture guide, and `benmore-dev` skill.

## Know which surface you are using

| Surface | What it does | Source of truth |
| --- | --- | --- |
| Framework edition | Self-hosted app runtime, embedded TSX compiler, SQLite and generated APIs | Deployed app, installed binary help, generated schema/OpenAPI |
| Cloud edition | Runtime plus the hosted CLI used by app-building agents | Local CLI help and the selected server's `api` recipes/tool schemas |
| Platform edition | Runtime plus hosting/control-plane implementation | Same app contracts; operator procedures are separate |
| CLI skill | Guides Codex/Claude through app work | Bundled `benmore-cli` skill and its references |
| App `AGENTS.md` | Durable project instructions for Codex and other agents | Generated edition-aware app contract plus project-specific additions |
| App `CLAUDE.md` | Claude entry point | Imports that app's `AGENTS.md` |
| MCP `help` / documentation resources | Reads the same bundled guides | `help(topic:"harness")`, `help(topic:"build")` |
| MCP `api` | Describes live routes and feature recipes; can explicitly execute a call | Selected app/environment and current server implementation |

Run `benmore version --json` first. The cloud distribution and platform/runtime
have separate release version numbers. Check the edition and supported command,
not whether the version strings happen to match. The framework edition does not
provide the hosted `api`, `push`, `skill`, or account commands.

The hosted development loop runs against a deployed dev URL. A source workspace
is not a private local copy of the hosted database. There is no Benmore localhost
development mode. Self-hosted operators run the framework as a production service;
that is a different deployment choice.

## Set up Codex or Claude

Install the native cloud CLI using the installation guide, then authenticate.
`benmore bootstrap` authenticates, installs complete workspace/user skill bundles,
merges Claude hooks, and attempts to restore accessible apps. Inspect its sync
results; a successful setup message alone is not proof every app was pulled.

For only the skill installation:

```bash
benmore skill install --agent codex
benmore skill install --agent claude
benmore skill install --agent all
benmore skill path --agent codex
```

| Harness | User skill location | Workspace skill location | Edit delivery |
| --- | --- | --- | --- |
| Codex | `~/.agents/skills/benmore-cli` | `~/Benmore/.agents/skills/benmore-cli` | Explicit `benmore push` |
| Claude Code | `~/.claude/skills/benmore-cli` (or under `$CLAUDE_CONFIG_DIR`, else the legacy `$CLAUDE_HOME`) | `~/Benmore/.claude/skills/benmore-cli` | Configured Edit/Write hooks; explicit push for other edits |

The same skill, references, and optional Codex UI metadata are installed for both.
For compatibility, `benmore skill install`, `path`, and `uninstall` without
`--agent` target Claude. `show` prints the shared entry point. Uninstall removes
bundle-owned files and empty directories, preserving unrelated files.

`BENMORE_HOME` points to the CLI configuration directory (normally
`~/Benmore/.config`); its parent determines the workspace. `CODEX_HOME` selects
Codex's configuration home, not a replacement for `~/.agents/skills` discovery.
The user-level install covers apps with their own Git root, where a parent
workspace's skill may not be visible.

Launch Codex in the app directory, and invoke `$benmore-cli` when useful. Codex
uses `AGENTS.md` and discovers skills by name/description; the skill may also be
selected implicitly. If new instructions are not visible, start a new session.
No Codex save hook, sandbox exemption, or automatic approval is installed.
See the official [Codex skill discovery](https://learn.chatgpt.com/docs/build-skills)
and [AGENTS.md guidance](https://learn.chatgpt.com/docs/agent-configuration/agents-md).

Claude's hooks match Edit, Write, and NotebookEdit. Shell commands, custom tools,
or failed/missing hooks do not prove a file shipped. Check `benmore hooks status`,
read hook errors, and explicitly push any edits outside the installed matcher.

## Establish identity, app, and environment

```bash
benmore whoami
benmore use
benmore apps
benmore sync-status . --json
```

Use the existing `.benmore/app` marker or an explicit deployed app identifier.
Read the actual printed URL and the `target:` line a changing command prints
on stderr (see "CLI command contracts"). An environment pin persists; explicit `--env dev` or
`--env prod` overrides it on commands that support the flag. Do not substitute
production for a missing dev instance. See `api(at:"environments")`.

Credentials are per account; app runtime sessions and platform CLI credentials
are different. `BENMORE_TOKEN` is an ephemeral process credential. Use the existing
credential store or a secret environment variable instead of copying a token into
source, chat, or command examples. When the token is rejected (`benmore whoami`
exits 4) and this machine has no browser, run `benmore login --device` and give the
person the printed link and code to approve. See `api(at:"cli-auth")`.

## Lifecycles: state, transition, observe

Every long-lived thing an agent touches has named states. Move it only with the
listed command or event, and read its state with the listed command; never infer
it from an earlier success message.

| Lifecycle | States | Moves it | Shows it |
| --- | --- | --- | --- |
| CLI sign-in | signed out → signed in → token rejected | `benmore login` (`--device` without a browser, `--token-stdin` in CI), `benmore logout` | `benmore whoami --json`: `logged_in`; a rejected token exits 4 |
| Environment pin | none / dev / prod | `benmore use dev\|prod\|none`; `--env` overrides one call | `benmore use`; `benmore whoami --json`: `env` |
| Instances | dev only → dev + prod → dev only, production removed (its data kept; promote publishes it again); prod only (apps from before dev/prod) | `benmore deploy` (first run creates the app), `benmore promote <app>`, `benmore seed-dev <app>`, `benmore remove-production <app>` (owner only) | `benmore apps --json`: `dev_url`, `url` (no `url` and a `production_removed_at` once removed); `benmore status <app>`: `has_dev`, `prod_exists`, `production` (`none`, `live`, `removed`) (`api(at:"environments.remove_production")`) |
| Workspace source | clean / drift / conflict | `benmore push`, `benmore pull`, `benmore delete-file` | `benmore sync-status . --json`: exit 0 / 1 / 2 (3 = the check could not run) |
| A push | written → reloaded, or written → reload rejected (the previous config keeps serving), or written → not answering | `benmore push <files>` | push exit 0 only for reloaded; `benmore logs <app>` for the rejection |
| Release | dev ahead → in sync; destructive change blocked | `benmore promote <app>` (`--dry-run` first, `--force` only for an accepted drop) | `benmore status <app>`: `in_sync`, `blocked_destructive`, `prod_last_promoted` |
| Testing posture | testing on → published | `benmore publish <app>` / `benmore unpublish <app>` | `benmore testing-status <app>` |
| Serving | serving ↔ paused | `benmore disable <app>` / `benmore enable <app>` | the command's own `Paused:` / `Resumed:` line (no CLI command lists it afterwards; the dashboard app list shows it) |
| Async flow job | pending → running → completed \| failed (`pending` with an `error` = waiting for its retry) | a `mode: async` flow or `run: enqueue`; an admin `POST /api/_jobs/{id}/retry` | poll the returned `status_url` verbatim: `status`; `bm.jobs.wait(...)` (`api(at:"async-flows")`) |
| Workflow record | `initial` → the declared states | `POST /api/<table>/<id>/transition {to}` / `bm.workflow(t, id).transitionTo(s)`; a declared `timeout` | `GET /api/<table>/<id>/transitions`: `current`, allowed `transitions` (`api(at:"workflows")`) |
| Approval | pending → approved \| rejected (final) | `POST /api/_approvals`; the approver's `POST /api/_approvals/{id}/decide` | `GET /api/_approvals?table=&row_id=`: `status`; a conflicting decide answers 409 with the stored `status` (`api(at:"scheduling")`) |
| Bulk import | staging → running → completed \| failed \| cancelled | `benmore import <app> <table> <file>` (rerun the same command to resume a staging upload) | the command polls to a final state and exits nonzero on failure or zero rows (`api(at:"import")`) |
| App MCP connector | exposure off ↔ on; approved writes off ↔ on (needs exposure, command tools and a verified revision enrollment) | `benmore mcp enable\|disable <app> [--writes] --env dev\|prod`; `--revoke` ends every grant | `benmore mcp status <app>`: both switches and `approved_writes_off_reason` (`api(at:"connector")`) |
| End-user session with `auth.idle_timeout` | active → expired after the idle window (background polling does not count) | any user request keeps it active; sign in again after expiry | `bm.auth.me()` returns `null` / the API answers 401 (`api(at:"auth")` → `idle_timeout`) |
| `compliance: hipaa` | off → on, one way | add the key to app.yaml; nothing turns it off | app.yaml; refused `refresh-dev --with-data` and GitHub sync (`api(at:"compliance")`) |

Model your own app's stages the same way: a `workflows.yaml` entry with
`initial`, named `states` and `transitions` (role and `when` guards) instead of a
free `status` string or a pair of booleans. Creates then start in `initial`,
PATCH cannot write the state column, and every move is checked and audited.

## Read the smallest authoritative contract

```bash
benmore api <app> '*'                       # this app's routes, tables and flows
benmore api <app> 'table:notes'
benmore api <app> 'POST /api/notes'
benmore api <app> --search "upload private file"   # which key answers the question
benmore api <app> flows                     # a small topic whole, a large one as an index of its keys
benmore api <app> flows.step_keys           # one key
benmore api <app> index                     # every topic, one line each
```

Do not guess a contract: search, read the index of the topic, fetch the key.
The equivalent MCP tool accepts `app` and the same forms (`search:"<words>"`,
`at:"<topic>"`, `at:"<topic>.<key>"`, `at:"index"`); inspect the exposed tool
schema for additional arguments. `--full` (`full:true`) returns a whole large
topic. When an answer names a documentation address, fetch it before trying
again. `benmore api <app> <selector>` takes the selector positionally
(`--at <selector>` is accepted too). Generated OpenAPI is available to
authorized callers at `/api/_openapi`, `/openapi.json`, and `/api/openapi.json`.

Use descriptions before execution. `api --call`, `probe`, browser actions, and
flows can mutate real state or trigger external effects. Confirm the selected
identity, environment, and operation are covered by the user's request.

For external APIs, inspect an authorized real response or a representative fixture
before choosing JSON keys. For DB work, inspect the actual schema. Do not infer
column names, envelope shapes, cron keys, or signing recipes from an example alone.
An empty result needs an explanation; use expected-count assertions where work
should produce rows. Inspect `api(at:"query")` for read-only query limits.

## Iterate without losing source or runtime state

1. Read the existing source and `sync-status` report. Reconcile local/remote/base
   differences deliberately; a force flag is an overwrite decision.
2. Edit the smallest coherent feature. Keep the established app structure and
   preserve the CRUD/access/CSRF pipeline. Client UI guards do not protect data.
3. Push all changed files and dependencies. Validation errors and nonzero exits
   need resolution. A multi-file upload is not a transaction across all files.
4. Check the deployed app with `benmore check <app>` and inspect server errors.
   In cloud/platform builds, `check` validates the deployed state, not the local cache.
5. Exercise the changed API and real browser journey. Inspect persisted effects,
   console errors, failed requests, and the UI at relevant viewport sizes.
6. Run app verification where configured, then check the source manifest again.

Malformed core application, backup, hook, flow, cron, workflow, and encryption
configuration is rejected before startup/reload mutations. Supported legacy
root flows still work. A missing optional file can be intentional; an
unreadable or malformed existing file is an error.

Rejected reloads retain the active handler, configuration, and workers. This does
not make all loaders strict or undo already committed migrations/external effects.
Unchanged full-text indexes are reused; changed definitions rebuild transactionally.
A change to an unrelated encrypted, blind-index or timestamp column does not
rewrite the full-text index.
Read `api(at:"recovery")`, `api(at:"workflows")`, and `api(at:"search")` for limits.

## Prove the result

`benmore probe` verifies a response, not JavaScript execution. Use an available
browser or MCP `browser_check` for UI behavior. Inspect the current action schema:
`fill` requires `selector` and `text`; `select` requires `selector` and `value`.
An intentional empty value is valid. A screenshot without interaction does not
prove a form or permission boundary works.

`benmore verify .` reads the app's verification contract and journeys.
`--quick` and `--release` select profiles; evidence is written under
`.benmore/verify/<run-id>/`. Missing named test/journey references fail rather than
being silently skipped. Each check reads `pass`, `fail` or `not_run` (with its
`reason`); `next_steps` names the command or evidence file for every failure,
and `environment` is always dev. Exit 0 only when `ok` is true. See
`api(at:"verification")` for exact YAML and assertions.

`benmore ship . --promote` runs release verification, checks source identity again,
and uses an interactive promotion flow. It refuses non-interactive stdin. Do not
fake a terminal to bypass that requirement. Source promotion, `publish` testing
posture, source revert, and database restore have distinct effects.

Finish with `benmore sync-status .` and `benmore sync-status --all`; require exit 0
for a clean delivery. Report unrelated workspace drift without changing unrelated
apps. Preserve the evidence and state the app/environment, observed behavior,
validation performed, and any unresolved limitations. A failed check is not a
completed delivery.

## Diagnose rather than retry blindly

| Signal | Interpretation and next step |
| --- | --- |
| `sync-status` 1 | Non-conflicting drift; inspect which side changed |
| `sync-status` 2 | Conflict; reconcile before overwriting |
| `sync-status` 3 | Setup/auth/remote error; do not treat it as source conflict |
| Core YAML rejected | Read the exact key/shape and the canonical feature topic |
| Old behavior after push | Check reload errors, dependencies, selected environment and manifest |
| Slow startup | Inspect process/log/health progress; avoid restarting active migration/backup work |
| User cannot access app | Inspect credential state, tenant membership, role/access scopes and response |
| `ship` refuses stdin | Use the supported interactive release workflow |

General hosted CLI errors use usage/auth/not-found/transport categories; consult
`api(at:"cli-contracts")` because sync commands deliberately have a separate exit
contract. Secrets, customer data, outbound messages, billing, and destructive data
operations retain their existing authorization requirements.

## CLI command contracts

The developer journey is: sign in → select app and environment → inspect →
edit and push → verify → diagnose → promote explicitly. `benmore help` prints
that journey; `benmore help all` lists every command with its effect label.

Target selection for instance commands: `--env dev|prod` on the call, else the
`benmore use` pin, else the app's default (dev when it has one, else prod).
The app comes from `--app`/the positional app, else the `.benmore/app` marker
of the workspace. push, deploy, delete-file, `sql --write` and promote print one
line on stderr
before sending anything:

```text
target: push → app crm, environment dev (from --env)
```

It names where the environment came from (`--env`, the `benmore use` pin, or
the app's default). Giving one selector twice with different values
(`--env dev --env prod`, `--app a --app b`) is refused with exit 2 before
anything is sent. stdout stays data (JSON with `--json`, or when piped for the
commands that support it); progress, warnings and the target line go to stderr.
A trailing `-dev` on the app is dropped (the server addresses the logical app) and an
`--env` other than dev or prod exits 2 before anything is sent. The save hook
(`benmore push --from-claude-hook`) prints the line only when its push lands in prod.

| Command | Effect | Inputs | Exit codes | JSON |
| --- | --- | --- | --- | --- |
| `login`, `logout`, `whoami` | account | browser, `--device`, `--token-stdin`, `BENMORE_TOKEN` | 0; 4 rejected token | `whoami --json` |
| `use [dev\|prod\|none]` | local pin | — | 0; 1 bad value | — |
| `apps` | inspect | — | 0; 1 transport; 4 rejected token | `--json` (`dev_url`, `url`) |
| `pull <app> [dir]` | local files | `--env`, `--force` | 0; 1 | — |
| `sync` | local files | `--force` | 0; 1 | — |
| `sync-status [dir]` | inspect | `--app`, `--env`, `--all` | 0 clean, 1 drift, 2 conflict, 3 setup/auth/remote (also bad flags) | `--json` |
| `push <files>` | change source | `--app`, `--app-dir`, `--env`, `--force` | 0 written + reloaded; 1 failed; 2 usage (hook mode: 2 on failure) | — |
| `delete-file <path>` | change source | `--app`, `--app-dir`, `--env`, `--force` | shared | — |
| `deploy [dir]` | change source (creates the app on first run) | `--name`, `--env`, `--force` | 0; 1 failed/unhealthy; 2 file failures, usage or sync conflict; 3 sync check could not run | — |
| `check <app>` | inspect | `--env` | 0 (warnings allowed); 1 errors; 2 usage | `--json` |
| `verify [dir]` | inspect (dev only) | `--app`, `--quick`, `--release` | 0 pass; 1 fail; 2 usage | `--json` (report also in `.benmore/verify/<run>/report.json`) |
| `status`/`diff <app>`, `doctor <app>` | inspect | — | shared (HTTP 400 → 2, 401/403 → 4, 404 → 5) | always JSON |
| `promote <app>` | promote (dev → prod code) | `--dry-run`, `--force`, `--yes` | 0; 1 blocked or unhealthy; 2 usage | prints the server's JSON |
| `ship [dir] --promote` | promote (interactive only) | — | 0; 1 verification failed; 2 usage or no terminal | — |
| `env [<app>] list\|set\|unset` | change settings | `--env dev\|prod\|shared` | shared | — |
| `sql <app> "SQL"` | inspect; `--write --confirm` changes data | `--env` | shared | — |
| `mcp status\|enable\|disable <app>` | change settings | `--writes`, `--revoke`, `--env` | shared | — |

Shared codes: 0 ok, 1 generic failure, 2 usage (unknown flag,
missing argument), 3 operation-specific failure, 4 authentication/permission, 5
app/file not found. `sync-status` keeps its own 0/1/2/3 meaning. Aliases stay
valid: `diff` = `status`, `pause`/`resume` = `disable`/`enable`, `sync_status`,
`delete_file`, `integrity_check`, `email_domain`, `encrypt_backfill`,
`rotate_key`, `blind_backfill`, `features` = `feature`. `api(at:"cli-contracts")`
is the server-side reference.

## Usage accounting and context

`benmore usage --local [--json]` inspects offline numeric Claude/Codex counters.
`benmore usage sync` uploads attributed counters. Account telemetry is enabled by
default with disclosure; `benmore telemetry off` persists an opt-out and
`BENMORE_TELEMETRY=0` disables a process. Prompts, responses, code, tool payloads,
transcripts, provider session IDs, and local paths are not uploaded.

Descriptive API references use an account/app/environment-scoped cache and ETags;
an HTTP 304 replays the exact bytes. Executed calls are never cached. This improves
stable context, but Benmore does not control provider-side prompt caching or infer
monetary cost. See `api(at:"agent-usage")` and `api(at:"api-reference-cache")`.
