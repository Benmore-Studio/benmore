# CLAUDE.md

Guidance for Claude Code (and any AI agent) working in this repository — the
open-source **Benmore framework**.

## What this is

One Go binary (`benmore`) that turns a Prisma schema + HTML/TSX pages + YAML
config into a self-hostable, SQLite-backed web app: auto-CRUD REST/SSE/WebSocket
API, auth, RBAC, validation, and on-the-fly TSX compilation. No Node, no runtime
build step.

This repo is the **framework edition** (open source). The hosted **platform**
edition (deploy, fleet management, the agent build loop, billing) lives behind
the `platform` build tag and is a separate commercial product — its commands are
stubbed out here (`platformBuild = false` in `cli_dispatch_stub.go`). Do not add
hosted/proprietary behavior to the default build.

## Commands

Every `go` invocation needs the `sqlite_fts5` tag. The SQLite driver is cgo, so
you also need a C toolchain installed.

```bash
go build -tags sqlite_fts5 -o benmore .   # build the binary
go vet  -tags sqlite_fts5 ./...           # static analysis — MUST pass before a PR
go test -tags sqlite_fts5 ./...           # run tests
```

Run a scaffolded app locally:

```bash
./benmore new myapp                 # scaffold a runnable app (schema, config, TSX, SDK)
./benmore serve myapp --port 8080   # migrate + compile TSX on the fly + serve
```

CLI surface (framework edition): `new`, `serve`, `docs`, `version`, `help`.
`benmore docs [topic]` prints the in-binary app-builder guide.

There is **no Makefile/Taskfile** — the three `go` commands above are the whole
workflow.

## Architecture

A single flat `package main` at the repo root: ~136 source `.go` files (+38
tests), ~69k LoC. No internal packages — files group by concern by filename:

| Area | Representative files |
|---|---|
| Entry / CLI | `main.go`, `*_dispatch*.go`, `docs.go`, `cli_*` |
| HTTP / server / realtime | `server.go`, `main_server.go`, `sse.go`, `websocket*.go`, `webrtc.go`, `presence.go` |
| Auth & security | `auth.go`, `mfa.go`, `oauth_tokens.go`, `rbac.go`, `scopes.go`, `access.go`, `encryption.go`, `blindindex.go`, `signer*.go`, `ratelimit.go` |
| Data & schema | `schema*.go`, `crud.go`, `query.go`, `db.go`, `computed.go`, `aggregates*.go`, `fts.go`, `*migrate*.go`, `validators.go` |
| Business logic | `flows.go` (~3.6k LoC, the largest), `hooks.go`, `workflows.go`, `pipes*.go`, `compute*.go`, `*recipe*.go` |
| Frontend / TSX | `bm_tsx_compile.go`, `scaffold_*.go`, `layout.go`, `tailwind_embed.go`, `libs_embed.go`, `branding.go` |
| Ops | `upload*.go`, `pdf.go`, `s3_presign.go`, `media_cdn.go`, `metrics.go`, `cron.go`, `circuitbreaker.go`, `metering.go` |

`embedded/` holds the 12 vendored frontend assets (the `bm` SDK, Tailwind, HTMX,
Alpine, Chart.js, Lucide, Mermaid, …) compiled into the binary. `docs/agent/
build.md` is the canonical app-builder guide and is also embedded (`benmore docs`).

## Build tags (important)

- **`sqlite_fts5`** — always pass it for build/vet/test. Enables SQLite FTS5
  full-text search (used when an app declares `@@fulltext`).
- **`platform`** — gates the hosted-platform CLI/commands. Absent in this build.
- **`cli`** — selects the thin deployed-app client. ~155 server files carry
  `//go:build !cli`, so they are excluded from that build. The default framework
  build sets none of these beyond `sqlite_fts5`.

## Conventions

- **App-agnostic**: never hardcode domains, emails, or branding into the
  framework — config comes from `app.yaml` / `env.yaml` / CLI flags.
- **SQL is always parameterized** — never concatenate user input into queries.
- **CLI follows [clig.dev](https://clig.dev)** (see `docs/cli-conventions.md`):
  stdout = data, stderr = status; support `--json` / `--no-json` / `--yes`;
  documented exit codes (0 ok, 1 generic, 2 usage, 3 domain, 4 auth, 5
  not-found). New data-returning commands use the `cliWrite` helper.
- `go vet -tags sqlite_fts5 ./...` must pass before opening a PR; match the style
  of the surrounding code.

## Gotchas

- The compiled `benmore` binary (~41 MB) is a build artifact and is **gitignored**
  (`/benmore`, `/benmore-*`) — never commit it.
- `version` is baked into `main.go` and overridden at release via
  `-ldflags "-X main.version=<tag>"`. Bump it there when cutting a release.
- There is **no `example/` app** in the repo — generate one with `benmore new` to
  test against (don't trust older docs that reference `./example`).
- `cli_output.go`/`cliWrite` are the intended home for new CLI output; some older
  commands still use raw `fmt.Println` and migrate incrementally.

## Releasing

Releases are tag-driven. Pushing a `vX.Y.Z` tag triggers
`.github/workflows/release.yml`, which runs GoReleaser inside the
`goreleaser-cross` image to cross-build the cgo binaries for every platform and
publish a GitHub Release.

1. Bump `version` in `main.go` and add a `CHANGELOG.md` entry.
2. `go vet` + `go test` (both with `-tags sqlite_fts5`) must be green (CI runs the
   same).
3. `git tag -a vX.Y.Z -m "benmore vX.Y.Z" && git push origin vX.Y.Z`.
4. GoReleaser publishes the release with cross-platform archives + checksums.

Keep the `goreleaser-cross` image tag in `release.yml` in lockstep with the `go`
directive in `go.mod`.
