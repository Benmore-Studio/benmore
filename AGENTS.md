# AGENTS.md

Guidance for AI coding agents working **on the Benmore framework itself** (this Go
monorepo). Follows the [agents.md](https://agents.md) convention. If you are using
Claude Code, [`CLAUDE.md`](CLAUDE.md) is the richer superset of this file (it adds
`@.claude/rules/` includes and the `api(at:)` propagation contract); everything
here also applies there.

> **Two different "agent" contexts — don't confuse them.**
> - **This file** is for an agent editing the framework's Go source.
> - An agent *building an app* on Benmore should read the per-app scaffolded
>   `CLAUDE.md`, `docs/agent/build.md`, and the live `api(at:<topic>)` reference —
>   **not** this file.

---

## What this project is

One Go binary (`flat package main`, 341 Go files) that turns Prisma + TSX + YAML
into secure, full-stack web apps: auto-generated CRUD APIs, auth, real-time, and
one-command deploys. No Node, no `node_modules`, no external build step — esbuild
(TSX→JS) and goja (`run: compute`) are embedded as Go libraries.

## Build

There are **three editions**, selected by build tag. `benmore version` prints which.

```bash
# Framework edition — app runtime + `serve`, no platform/cloud. This is the
# public open-source export (scripts/export-public.sh).
go build -tags sqlite_fts5 -o benmore .

# Cloud edition — the binary shipped to users (Homebrew / install.sh):
# runtime + cloud client (signup/login/deploy/push), no fleet engine.
go build -tags "sqlite_fts5 cloud" -o benmore .

# Platform edition — the full benmore.ai product (hosting, router, MCP, billing).
# This is what deploys to the host.
go build -tags "sqlite_fts5 platform" -o benmore .
```

- The `sqlite_fts5` tag is **required** whenever any app declares `@@fulltext` in `schema.prisma`.
- **Edition seam:** `platform`-tagged files are the fleet/hosting engine. Client CLI files are tagged `cloud || platform`. The runtime is untagged/`!cli`. `platform_shims.go` (`!cli && !platform`) stubs fleet symbols so framework + cloud builds link without the engine. Edition constants: `edition_{platform,cloud,framework}.go`.
- **After adding a CLI command:** put client code in a `cloud || platform` file; fleet/server code stays `platform`. Then run `bash scripts/cloud-leak-guard.sh` — it fails the build if fleet code leaked into the cloud edition (release-blocking).

## Test

```bash
go vet ./...                         # static analysis — MUST pass on every change
go test -tags sqlite_fts5 ./...      # Go unit tests (e.g. access_memberof_test.go)
./benmore test example/              # YAML-defined framework + example-app tests
./benmore test example/ --framework  # framework tests only
```

- YAML tests live alongside features (`tests/*.yaml`). Auto-generated framework tests come from app introspection (`testgen.go`); add a generator to `GenerateFrameworkTests()` when you add a feature area.
- There is **no local dev server** in v2.7+. The development loop runs against a deployed app via `benmore push <file>` (or the editor save hook). Do not add or document a `localhost` dev mode.

## Code conventions

- **Flat `package main`.** No internal packages, no service registries. A new concern is a new file at repo root named for it (`oauth_provider.go`, `versioning.go`).
- **Constants over magic strings.** Check `types.go` and `config.go` first.
- **All SQL is parameterized.** Never interpolate user input into a query string.
- **Constant-time compares** for anything security-sensitive: `hmac.Equal` / `subtle.ConstantTimeCompare`, never `==`.
- **SSRF guard:** every outbound URL (webhooks, flows, `fetch` tags) must pass `isPrivateURL()` at *both* registration and delivery.
- **Never bypass `crud.go`'s mutation pipeline** — it *is* the security model (CSRF, scope check, audit, hooks, real-time broadcast). Routing around it defeats the runtime's central guarantee.
- **New CLI command:** register in the `main.go` switch *and* `printUsage()`.
- **Scaffold changes:** edit `WriteHTMLScaffoldFiles` in `scaffold_html.go` — single source of truth for both `benmore new` (CLI) and `create_app` (MCP).
- **New/changed validator:** keep `validators_write.go` (write-time gate) and `app_check.go` (`benmore check`) in sync — both feed the same dispatcher.
- **Routes** register in `buildAppMux()` — single source of truth for `server.go` and `host.go`.
- **Env vars are per-app** (`AppEnvStore`); never use the global `EnvVars` in host mode.
- **OAuth callback URL:** always build from `r.Host` + `r.TLS`; never hardcode.

## Dependency policy

Benmore has **4 direct dependencies** by design. Do **not** add a new external
dependency without strong justification — reimplementation is preferred (the
WebSocket server, XLSX writer, MCP server, OAuth provider, and TOTP are all
in-tree for this reason). A PR that adds a dep without justification won't merge.

## Documenting a feature (propagation contract)

`api(at:<topic>)` (`mcp_tools_api.go` → `topicRecipes`, ~51 topics) is the **canonical**
app-builder reference. When you ship a feature:

1. Update its `topicRecipes` entry in `mcp_tools_api.go` — *that* is the propagation.
2. Add a one-line pointer to the Recent table in `docs/agent/build.md` + `skills/benmore-cli/SKILL.md` (and `.claude/rules/security.md` if it's a security control).
3. Add a release entry to [`CHANGELOG.md`](CHANGELOG.md).

Do **not** re-document recipes in the rules files, scaffold, or `bm.d.ts` — they
point at `api(at:)` on purpose.

## Architecture (where things live)

Flat `package main`; files are named by concern. Request path and major subsystems:

```
Request:    server.go → template.go → directives.go → layout.go → css.go
Data:       db.go → migrate.go → crud.go → validate.go → prisma_parser.go
Auth:       auth.go → roles.go → scopes.go → permissions.go → oauth.go → mfa.go
Logic:      hooks.go → flows.go → workflows.go → jobs.go → operations.go
Real-time:  sse.go → websocket.go → pubsub.go → fetch.go
Security:   ratelimit.go → sanitize.go → signed_urls.go → circuitbreaker.go → encryption.go
Platform:   host.go → platform.go → deploy.go → multitenant.go
MCP:        mcp.go → mcp_tools.go → mcp_validators.go → mcp_resources.go
Compile:    embedded esbuild (TSX) · embedded goja (run: compute)
```

Full file-by-function map: [`CLAUDE.md`](CLAUDE.md) → "Architecture"; system design: [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Framework vs platform (never mix)

- **Framework (`*.go`)** must be 100% app-agnostic — zero hardcoded domains, emails, or branding. All config comes from `app.yaml`, `env.yaml`, or CLI flags.
- `RegisterPlatformAPI(mux, appsDir, domain)` — the domain is passed in, never hardcoded.
- A directory named `_platform` serves on the root domain; `_platform`/`platform` are blocked as subdomains.

## Pull-request expectations

- Branch from `main`, named after the feature/fix (`feat/flutter-data-table`, `fix/migration-rollback-ledger`).
- One concern per PR — smaller is better.
- Commit messages explain **why**, not what.
- Keep docs and code in the **same** PR.
- Include a YAML test that exercises the change where applicable.
- `go vet ./...` passes; the cloud-leak guard passes if you touched CLI/fleet code.

## Safety / don'ts for autonomous agents

- Never weaken or route around the `crud.go` mutation pipeline or the SSRF guard.
- Never hardcode secrets, domains, or emails into framework files.
- Never introduce a `localhost` dev mode or a Node/`node_modules` build step.
- Don't reintroduce deleted surfaces (MCP prompts, redundant resources, the old SPA scaffold).
- Don't commit `data.db*`, `env.yaml`, `uploads/`, or `.benmore/` (already gitignored).

## Security & conduct

Report vulnerabilities privately per [`SECURITY.md`](SECURITY.md) (do not open a
public issue). All participation is governed by the
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
