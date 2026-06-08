# Contributing to Benmore

Thanks for your interest in the Benmore framework.

## Build & test

No Docker, no make, no frontend build step.

```bash
go build -tags sqlite_fts5 -o benmore .   # build
go vet -tags sqlite_fts5 ./...            # static analysis (must pass)
go test -tags sqlite_fts5 ./...           # tests
./benmore serve ./example --port 8080     # run an app locally
```

The `sqlite_fts5` tag is required (the SQLite driver uses cgo, so you also need
a C toolchain).

## Guidelines

- Keep the framework **app-agnostic**: no hardcoded domains, emails, or
  branding. Configuration comes from `app.yaml` / `env.yaml` / CLI flags.
- All SQL is parameterized — never concatenate user input into queries.
- `go vet ./...` must pass before you open a PR.
- Match the style of the surrounding code.

## Reporting issues

- Bugs and feature requests: open a GitHub issue.
- Security vulnerabilities: **do not** open a public issue — see
  [SECURITY.md](SECURITY.md).
