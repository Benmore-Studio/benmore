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

The explicit agent targets and shared scaffold instructions ship in cloud CLI
**0.1.30** and runtime/platform **2.7.225**. Older installed binaries may not
support `--agent`; check `benmore help` and the release notes.


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
| Claude Code | `~/.claude/skills/benmore-cli` (or `$CLAUDE_HOME/skills/benmore-cli`) | `~/Benmore/.claude/skills/benmore-cli` | Configured Edit/Write hooks; explicit push for other edits |

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
Read the actual printed URL. An environment pin persists; explicit `--env dev` or
`--env prod` overrides it on commands that support the flag. Do not substitute
production for a missing dev instance. See `api(at:"environments")`.

Credentials are per account; app runtime sessions and platform CLI credentials
are different. `BENMORE_TOKEN` is an ephemeral process credential. Use the existing
credential store or a secret environment variable instead of copying a token into
source, chat, or command examples. See `api(at:"cli-auth")`.

## Read the smallest authoritative contract

```bash
benmore api <app> '*'
benmore api <app> 'table:notes'
benmore api <app> 'POST /api/notes'
benmore api <app> flows
```

The equivalent MCP tool accepts `app` and `at`; inspect the exposed tool schema
for additional arguments. `benmore api <app> <selector>` uses a positional selector,
not an invented `--at` flag. Generated OpenAPI is available to authorized callers
at `/api/_openapi`, `/openapi.json`, and `/api/openapi.json`.

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

Framework/platform 2.7.224 rejects malformed core application, backup, hook, flow,
cron, workflow, and encryption configuration before startup/reload mutations.
Supported legacy root flows still work. A missing optional file can be intentional;
an unreadable or malformed existing file is an error.

Rejected reloads retain the active handler, configuration, and workers. This does
not make all loaders strict or undo already committed migrations/external effects.
Unchanged full-text indexes are reused; changed definitions rebuild transactionally.
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
being silently skipped. See `api(at:"verification")` for exact YAML and assertions.

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
