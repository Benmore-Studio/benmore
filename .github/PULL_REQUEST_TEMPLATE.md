## What this changes


## Why


## Checklist
- [ ] `go build -tags sqlite_fts5 -o benmore .` builds
- [ ] `go vet -tags sqlite_fts5 ./...` passes
- [ ] `go test -tags sqlite_fts5 ./...` passes
- [ ] Framework stays app-agnostic — no hardcoded domains, emails, or branding
- [ ] All SQL is parameterized (no user input concatenated into queries)
- [ ] Docs updated (`docs/agent/build.md` / `benmore docs`) if behavior changed

## Notes for reviewers

