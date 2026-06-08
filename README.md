# Benmore

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

## Status & scope

This repository is the **open-source Benmore framework** — the engine you can
build, self-host, and run with `benmore serve`. The hosted Benmore platform
(deployment, fleet management, the agent build loop, billing) is a separate
commercial product and is **not** part of this repository.

## Requirements

- Go 1.26+
- A C toolchain (the SQLite driver uses cgo)

## License

MIT — see [LICENSE](LICENSE). "Benmore" and related marks are trademarks of
Benmore Technologies and are not licensed for use without permission. Security
reports: see [SECURITY.md](SECURITY.md).
