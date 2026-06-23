# Frontier — /docs page UX + "Copy for LLM"

Tracks #59. Draft/scaffold for improving the public docs site at
https://benmore.ai/docs (the auto-generated HTML from `apidocs.go`, served at
`/docs`, with the JSON contract at `/api/_docs`).

## Problem

The current `/docs` page is a dense left-nav layout ("Filter sections…" + a long
flat section list) that's hard to scan, has weak in-page search, and offers no
machine-friendly export — agents/LLMs can't pull a clean copy of a section.

## Plan (to implement on this branch)

1. **Copy-for-LLM** — ✅ **done**
   - Whole-page "Copy for LLM" button in the generated HTML (`apidocs.go`
     `renderDocsHTML`), backed by `GET /docs?format=md`.
   - `renderDocsMarkdown` emits clean, self-contained markdown from the SAME
     tables/columns/routes/features the HTML and JSON views use (`docsCRUDRoutes`
     / `docsPlatformFeatures` are the shared route/feature lists) — no second
     source of truth. (`/llms.txt` already exists for SEO, so the export lives at
     `?format=md` rather than colliding with it.)
2. **Usability** — deferred to **#62** (UI design pass)
   - Sticky section headers, collapsible/searchable nav, copy-code buttons, and
     the responsive/mobile layout are a visual-design concern handled with the
     design system in #62, to avoid two competing redesigns of the same markup.
3. **Tests** — ✅ **done**
   - Go unit test `TestRenderDocsMarkdownHasSectionsAndRoutes` (runs in
     `go test ./...`): markdown is non-empty, carries every section heading and
     CRUD route, includes pages, and never leaks `_benmore_*` tables or
     `password_hash`.
   - `testgen.go` framework tests assert `/docs` (200, has the Copy-for-LLM
     button) and `/docs?format=md` (200, contains the top-level headings).

## Status

The markdown export + Copy-for-LLM button + tests are implemented. The visual
usability/redesign work is intentionally left to #62.

## Source

`apidocs.go` (generator + `/docs`, `/api/_docs`), `static_html.go` (HTML
serving), `libs_embed.go` (asset embedding). Related: #60 (public OpenAPI +
Redoc + Swagger), #62 (UI design pass).
