//go:build !cli

package main

// Both harnesses use the same per-app contract; Claude imports AGENTS.md.
func scaffoldClaudeMD(title, name string) string {
	return "# Benmore app instructions for Claude Code\n\n@AGENTS.md\n\nRead AGENTS.md for this app's runtime, environment, and delivery contract.\n"
}

const scaffoldSharedAgentContract = `## App contract

Read the app's existing files before choosing a shape. The default frontend is
TSX under ` + "`" + `static/` + "`" + `, compiled to JavaScript by embedded esbuild. Keep the entry
small; put feature modules in ` + "`" + `static/views/` + "`" + `, shared UI in ` + "`" + `static/components/` + "`" + `,
and logic in ` + "`" + `static/lib/` + "`" + `. Existing ` + "`" + `frontend.stack: gotmpl` + "`" + ` apps use server-rendered
pages instead. Preserve the selected stack and the user's design conventions.

` + "`" + `schema.prisma` + "`" + ` is the usual model source; existing SQL-schema apps are also
supported. Configure access in ` + "`" + `app.yaml` + "`" + `, backend operations in flows/hooks, and
schedules in ` + "`" + `cron.yaml` + "`" + `. Inspect their actual contracts before writing YAML.
Generated ` + "`" + `src/bm.d.ts` + "`" + ` describes this app; do not edit it by hand. Use the ` + "`" + `bm` + "`" + ` SDK
for authentication, CRUD, and real-time APIs. The server enforces access: a hidden
button or client-side route guard is not authorization.

Since runtime 2.7.224, malformed core configuration fails startup/reload before
migration work or worker replacement. A rejected reload retains the previous app;
previously committed database changes and external effects are not automatically
rolled back. Check the resulting behavior, not just a successful upload message.

## App MCP compatibility

The platform MCP builds and manages apps; this app's connector serves its users.
Read ` + "`" + `benmore docs connector` + "`" + ` for the offline manifest example and
` + "`" + `api(at:"connector")` + "`" + ` for the hosted contract. No framework source is needed. Server-created HTML starters include
a read-only ` + "`" + `mcp.yaml` + "`" + `. Hosted CLI ` + "`" + `benmore new` + "`" + ` omits it so the first deploy can succeed;
deploy and pull the complete source before authoring and reviewing a connector.
Exposure and approved writes require owner opt-in. When
replacing the Notes demo, replace its connector declarations too. After reviewing
source changes, run ` + "`" + `benmore mcp review <appdir> --reviewed` + "`" + ` and
` + "`" + `benmore mcp check <appdir>` + "`" + ` before pushing the reviewed files together.
Never re-attest unreviewed source to bypass a digest failure. Source attestation
does not grant access or approve an operation.

## QA selectors and journeys

Give every interactive element a ` + "`" + `data-testid` + "`" + ` (the scaffold pages, ` + "`" + `Button` + "`" + ` and
` + "`" + `Input` + "`" + ` helpers already do). ` + "`" + `qa_inventory` + "`" + ` surfaces every page, button, form and
declared access rule and drafts ` + "`" + `tests/journeys/*.yaml` + "`" + `; ` + "`" + `browser_batch` + "`" + ` and
` + "`" + `benmore verify` + "`" + ` replay those journeys in a real browser without an agent in the
loop. Read ` + "`" + `api(at:"qa")` + "`" + ` before writing or repairing a journey.

## Delivery evidence

Exercise the changed user journey, including authorized/unauthorized cases when
access changes. Use a real browser for JavaScript, forms, responsive layout, and
visual checks; an HTML response alone is insufficient. Keep secrets and private
records out of logs and handoffs. Report what changed, where it was verified, and
any remaining limitation. Continue authorized work; ask only for a decision or
permission that is actually missing.
`
