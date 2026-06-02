# Benmore

[![CI](https://github.com/Benmore-Studio/benmore/actions/workflows/ci.yml/badge.svg)](https://github.com/Benmore-Studio/benmore/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Benmore-Studio/benmore?sort=semver&display_name=tag)](https://github.com/Benmore-Studio/benmore/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/Benmore-Studio/benmore)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**Turn Prisma + HTML/TSX + YAML into a self-hostable web app — one Go binary, no Node, no build step.**

Benmore is an application framework. You describe your data in a Prisma schema,
write pages as plain HTML/TSX, and declare business logic (flows, hooks,
workflows) in YAML. The binary compiles your TSX on the fly, generates a full
REST + SSE + WebSocket API with auth, RBAC, and validation, and serves the
whole thing from a single SQLite-backed process.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/Benmore-Studio/benmore/main/install.sh | sh
```

Or grab a prebuilt binary for your platform from
[Releases](https://github.com/Benmore-Studio/benmore/releases), or build from
source (needs Go 1.26+ and a C toolchain — the SQLite driver uses cgo):

```bash
go install github.com/benmore-studio/benmore@latest
# or, from a clone:
go build -tags sqlite_fts5 -o benmore .
```

## Quickstart

```bash
benmore new myapp                  # scaffold a runnable TSX app
benmore serve myapp --port 8080    # run it
# open http://localhost:8080
```

`benmore new` writes a complete starter app (schema, config, TSX pages, typed
SDK); `benmore serve` applies migrations, compiles your TSX on the fly, and
serves it. Edit a file, refresh the browser.

> The `sqlite_fts5` build tag enables SQLite FTS5 full-text search (used when an
> app declares `@@fulltext`).

## Documentation

- **The guide** — [`docs/agent/build.md`](docs/agent/build.md): the model, app
  structure, schema, config, the `bm` SDK, auto-CRUD, auth, flows/hooks, and the
  dev loop. The same guide is built into the binary — run `benmore docs`.
- **CLI** — `benmore help` lists the commands (`new`, `serve`, `docs`,
  `version`).

## What you get

Everything below is handled by the runtime — no app code required:

- **Auto-CRUD** for every table: GET/POST/PATCH/DELETE, batch ops, pagination
  (offset + keyset), soft-delete, optimistic concurrency, idempotency keys.
- **Auth**: cookie sessions + Bearer tokens, CSRF, MFA (TOTP), OAuth, password
  reset, email verification, brute-force lockout.
- **Multi-role RBAC** with scopes, inheritance, granular per-record ACLs, and
  multi-tenant group scoping.
- **Business logic**: before/after hooks, custom HTTP flows (incl. async jobs
  and server-side JS `compute` via an embedded JS engine), state-machine
  workflows, outbound API signing + inbound webhook verification.
- **Data**: field-level AES encryption with blind-index search, content
  versioning, computed columns, materialized aggregates, custom fields,
  TTL retention, full audit trail.
- **Real-time**: SSE, WebSocket (stdlib RFC 6455), WebRTC helpers.
- **Frontend**: on-the-fly TSX→JS via embedded esbuild, a typed `bm` SDK,
  Tailwind/HTMX/Alpine/Chart.js/Lucide served from the binary. Optional Go
  `html/template` SSR mode for SEO pages.
- **Ops niceties**: PDF generation, XLSX export, signed URLs, rate limiting,
  circuit breaker, scheduled backups, per-app git history.

See `docs/agent/build.md` and `benmore docs` for the full app-builder guide.

## Project layout

The framework is a single Go binary — one flat `package main` at the repo root,
no internal packages.

```text
benmore/
├─ main.go              # CLI entry point + command dispatch
├─ *.go                 # the framework: one flat `package main`, ~136 source files (+38 tests)
├─ embedded/            # frontend assets compiled into the binary
│                       #   bm SDK, Tailwind, HTMX, Alpine, Chart.js, Lucide, Mermaid, markdown…
├─ docs/
│  ├─ agent/build.md    # the app-builder guide (also served by `benmore docs`)
│  └─ cli-conventions.md
├─ .github/
│  ├─ workflows/        # ci.yml (vet · build · test) · release.yml (tag → GoReleaser)
│  ├─ ISSUE_TEMPLATE/
│  └─ PULL_REQUEST_TEMPLATE.md
├─ .goreleaser.yaml     # cross-platform release build (runs in goreleaser-cross)
├─ install.sh           # one-line installer (the curl command above)
├─ go.mod · go.sum
├─ CHANGELOG.md · CLAUDE.md
└─ LICENSE · NOTICE · SECURITY.md · CONTRIBUTING.md · CODE_OF_CONDUCT.md
```

The `.go` files group by concern by filename:

| Area | Representative files |
|---|---|
| Entry / CLI | `main.go`, `*_dispatch*.go`, `docs.go`, `cli_*` |
| HTTP · server · realtime | `server.go`, `main_server.go`, `sse.go`, `websocket*.go`, `webrtc.go`, `presence.go` |
| Auth & security | `auth.go`, `mfa.go`, `oauth_tokens.go`, `rbac.go`, `scopes.go`, `encryption.go`, `blindindex.go`, `ratelimit.go` |
| Data & schema | `schema*.go`, `crud.go`, `query.go`, `db.go`, `computed.go`, `aggregates*.go`, `fts.go`, `*migrate*.go` |
| Business logic | `flows.go`, `hooks.go`, `workflows.go`, `pipes*.go`, `compute*.go`, `*recipe*.go` |
| Frontend / TSX | `bm_tsx_compile.go`, `scaffold_*.go`, `layout.go`, `tailwind_embed.go`, `libs_embed.go` |
| Ops | `upload*.go`, `pdf.go`, `s3_presign.go`, `media_cdn.go`, `metrics.go`, `cron.go`, `circuitbreaker.go` |

Agents and contributors: see [`CLAUDE.md`](CLAUDE.md) for the build-tag details
(`sqlite_fts5` / `platform` / `cli`), conventions, and gotchas.

## Status & scope

This repository is the **open-source Benmore framework** — the engine you can
build, self-host, and run with `benmore serve`. The hosted Benmore platform
(deployment, fleet management, the agent build loop, billing) is a separate
commercial product and is **not** part of this repository.

## Requirements

- Go 1.26+
- A C toolchain (the SQLite driver uses cgo)

## Contributing

Issues and pull requests are welcome. The whole workflow is three commands — no
Docker, no make, no frontend build:

```bash
go build -tags sqlite_fts5 -o benmore .   # build
go vet  -tags sqlite_fts5 ./...           # static analysis — must pass before a PR
go test -tags sqlite_fts5 ./...           # tests
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community standards. Please **do
not** file security vulnerabilities as public issues — follow
[SECURITY.md](SECURITY.md).

## Releasing

Releases are tag-driven and follow [semantic versioning](https://semver.org).
Pushing a `vX.Y.Z` tag triggers
[`release.yml`](.github/workflows/release.yml), which runs
[GoReleaser](https://goreleaser.com) inside the `goreleaser-cross` image to
cross-build the cgo binaries for linux/macOS/windows × amd64/arm64 and publish a
GitHub Release with archives and checksums.

```bash
# after bumping `version` in main.go and updating CHANGELOG.md:
git tag -a v2.7.151 -m "benmore v2.7.151"
git push origin v2.7.151
```

Past releases and notes live in [CHANGELOG.md](CHANGELOG.md) and on the
[Releases](https://github.com/Benmore-Studio/benmore/releases) page.

## License

MIT — see [LICENSE](LICENSE). "Benmore" and related marks are trademarks of
Benmore Technologies and are not licensed for use without permission. Security
reports: see [SECURITY.md](SECURITY.md).
