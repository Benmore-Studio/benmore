# Changelog

All notable changes to the open-source **Benmore framework** are documented in
this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

GitHub Releases (with prebuilt binaries) are published automatically by
GoReleaser on each `vX.Y.Z` tag — see [Releasing](README.md#releasing).

## [Unreleased]

## [2.7.151] - 2026-06-02

First public (open-source) release of the Benmore framework. Earlier history
predates the public repository and lives in the private development repo; the
version number is carried forward from there.

### Added
- **Auto-CRUD** for every table — GET/POST/PATCH/DELETE, batch ops, offset and
  keyset pagination, soft-delete, optimistic concurrency, idempotency keys.
- **Auth** — cookie sessions + Bearer tokens, CSRF, MFA (TOTP), OAuth, password
  reset, email verification, brute-force lockout.
- **RBAC** — multi-role with scopes and inheritance, per-record ACLs, and
  multi-tenant group scoping.
- **Business logic** — before/after hooks, custom HTTP flows (incl. async jobs
  and server-side JS `compute`), state-machine workflows, outbound API signing,
  and inbound webhook verification.
- **Data** — field-level AES encryption with blind-index search, content
  versioning, computed columns, materialized aggregates, custom fields, TTL
  retention, and a full audit trail.
- **Real-time** — SSE, WebSocket (stdlib RFC 6455), and WebRTC helpers.
- **Frontend** — on-the-fly TSX→JS via embedded esbuild, a typed `bm` SDK, and
  Tailwind/HTMX/Alpine/Chart.js/Lucide served from the binary; optional Go
  `html/template` SSR mode.
- **Ops** — PDF generation, XLSX export, signed URLs, rate limiting, circuit
  breaker, scheduled backups, and per-app git history.
- **Release pipeline** — GoReleaser cross-platform build (linux/macOS/windows ×
  amd64/arm64) and a one-line `install.sh`.

[Unreleased]: https://github.com/Benmore-Studio/benmore/compare/v2.7.151...HEAD
[2.7.151]: https://github.com/Benmore-Studio/benmore/releases/tag/v2.7.151
