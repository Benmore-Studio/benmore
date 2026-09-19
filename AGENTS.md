# Benmore framework contributors

This public repository contains the app runtime, not the hosted fleet or cloud
client. Read README.md and CONTRIBUTING.md. Build with `sqlite_fts5`; use the Go
version in go.mod. Run `go vet ./...` and `go test -tags sqlite_fts5 ./...`.

Keep the flat package main and app-agnostic runtime. Inspect actual schemas,
config parsers and responses before changing contracts. Preserve the CRUD mutation
pipeline, parameterized SQL, constant-time security comparisons, and outbound
SSRF checks. Do not commit databases, secrets, uploads, or .benmore state.

Update docs with behavior. App-building agents use their own generated AGENTS.md,
bundled guides, and authenticated runtime OpenAPI. Hosted MCP, account, push, and
fleet operations are not provided by this edition. The serve command is a
self-hosting service, not a localhost development mode.
