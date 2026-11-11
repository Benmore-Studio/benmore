//go:build !cli && !platform && !cloud

package main

import "fmt"

func scaffoldAgentsGuide(title, name string) string {
	return fmt.Sprintf("# %s — Benmore app\n\n", title) + frameworkAgentContract + scaffoldAppContract + scaffoldEditionSections + scaffoldDeliveryEvidence
}

const frameworkAgentContract = `This app uses the self-hosted framework edition. Read ` + "`" + `benmore docs build` + "`" + ` and
` + "`" + `benmore docs harness` + "`" + ` for the edition boundary and runtime model. Hosted commands
such as ` + "`" + `push` + "`" + `, ` + "`" + `api` + "`" + `, ` + "`" + `skill` + "`" + `, and ` + "`" + `promote` + "`" + ` are not part of this edition.

` + "`" + `benmore serve <app-directory> --port <N>` + "`" + ` runs the app. It is the same runtime
an operator runs as a production service; there is no separate development mode.
Use the URL the app is served at, the current generated schema/OpenAPI when
available, and the installed binary's help to verify changes. Native TSX uses
embedded esbuild; no Node server or frontend build process is required.

Do not guess a contract (a YAML key, a column, a response shape): read it. The
reference is in the binary and needs no network: ` + "`" + `benmore docs --search "<words>"` + "`" + `
lists the keys that answer a question, ` + "`" + `benmore docs <topic>.<key>` + "`" + ` reads one,
` + "`" + `benmore docs <topic>` + "`" + ` prints a topic (a large one as an index of its keys) and
` + "`" + `benmore docs index` + "`" + ` lists every topic. When a refusal ends with
` + "`" + `docs: api(at:"<topic>.<key>")` + "`" + `, read that key before trying again. The reference
also covers the hosted platform: a command it names that ` + "`" + `benmore help` + "`" + ` does
not list is not part of this edition. ` + "`" + `benmore help <command>` + "`" + ` has a command's
flags, and the running app describes itself at ` + "`" + `/api/_schema` + "`" + ` and ` + "`" + `/api/_openapi` + "`" + `
(signed in).

Codex reads this AGENTS.md; Claude Code imports it through CLAUDE.md. Keep the same
app contract regardless of the agent. Never claim a hosted push or cloud validation
ran when using only the framework binary.

`

// scaffoldEditionSections are the self-hosted connector and test sections of
// the generated AGENTS.md. This edition has new, serve, test, mcp
// inspect|generate|check|review and docs (the guides and the api(at:)
// reference, read offline); it has no platform MCP tools, no `api` command
// and no hosted verify, so none is named as available.
const scaffoldEditionSections = `## App MCP connector

This app's own connector serves its users. Read ` + "`" + `benmore docs connector` + "`" + `
(offline). ` + "`" + `benmore new` + "`" + ` wrote a reviewed read-only ` + "`" + `mcp.yaml` + "`" + ` for the Notes
demo. Plain ` + "`" + `benmore serve <appdir>` + "`" + ` keeps the connector off (` + "`" + `/api/_mcp` + "`" + `
answers 404); ` + "`" + `benmore serve <appdir> --mcp-local` + "`" + ` runs it at
` + "`" + `http://localhost:<port>/api/_mcp` + "`" + `, and adding ` + "`" + `--mcp-writes` + "`" + ` turns approved
writes on for a manifest that declares command tools. When you replace the
Notes demo, replace its connector declarations too, or delete ` + "`" + `mcp.yaml` + "`" + ` if
the app serves no connector. After reviewing source changes run
` + "`" + `benmore mcp review <appdir> --reviewed` + "`" + ` and ` + "`" + `benmore mcp check <appdir>` + "`" + `, then
reload (SIGHUP) or restart the service. An edit to a file the app loads or
serves makes the old review stale: the app still starts, with the connector
withheld, until you review again (` + "`" + `--mcp-local` + "`" + ` then stops with the reason).
Never re-attest unreviewed source to get past a digest failure; attestation
grants no access and approves no operation.

## Tests

Give every interactive element a ` + "`" + `data-testid` + "`" + ` (the scaffold pages and the
` + "`" + `Button` + "`" + `/` + "`" + `Input` + "`" + ` helpers already do). Put YAML tests in ` + "`" + `tests/*.yaml` + "`" + ` and run
` + "`" + `benmore test <appdir>` + "`" + ` (` + "`" + `--app` + "`" + ` yours only, ` + "`" + `--framework` + "`" + ` the generated ones);
it runs on a copy of the source with a fresh database. ` + "`" + `tests/journeys/*.yaml` + "`" + `
are browser journeys for the hosted ` + "`" + `benmore verify` + "`" + `; this edition does not run
them, so check JavaScript, forms and layout in a real browser yourself.

`

// The starter files' comments that name a command or tool. The self-hosted
// wording lives here and the hosted wording in scaffold_claude_platform.go.
const (
	// app.yaml, after `testing: true   # `.
	scaffoldTestingFlagNote = `feedback flag widget (+ demo password gate if set); set false for a live app`

	// static/partials/head.html, above the icon link.
	scaffoldFaviconNote = `<!-- Without an icon link the browser asks for /favicon.ico and logs a 404
     on every page. Replace static/favicon.svg with your own icon, or point
     this link at another file. -->`

	// static/index.html, above the note form.
	scaffoldTestidNote = `<!-- data-testid marks every interactive element for tests and browser
           checks: select by it instead of ids/classes, so selectors survive
           restyling. Keep the convention on new UI. -->`

	// The pages' comment above <script src="/static/app.js">.
	scaffoldEditTSXNote = `Edit the .tsx file: the
       next page load compiles the new source. While features.testing is on,
       an open signed-in page reloads itself when the app reloads (SIGHUP).`

	// static/views/notes.tsx, the last line of the bm.live comment.
	scaffoldLiveScopedNote = `// Return the promise that covers all fetch/render work, so refreshes run one at a time.`

	// src/bm.d.ts placeholder: how the real types reach this file.
	scaffoldTypesRefreshNote = `// The running app serves them to a signed-in app admin: save
//   GET /_internal/bm.d.ts
// to this path after the first start, and again after a schema, config, flow,
// workflow, hook or i18n change.`

	// tests/journeys/home.yaml header.
	scaffoldJourneyHeader = `# Browser journey for the hosted ` + "`benmore verify`" + `. The self-hosted framework
# edition does not run journeys: put YAML tests in tests/*.yaml and run
# ` + "`benmore test`" + `. This starter only checks what every app keeps (the page
# renders, nothing overflows), so it survives replacing the demo.`
)
