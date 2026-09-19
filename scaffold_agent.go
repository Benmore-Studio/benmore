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

## Delivery evidence

Exercise the changed user journey, including authorized/unauthorized cases when
access changes. Use a real browser for JavaScript, forms, responsive layout, and
visual checks; an HTML response alone is insufficient. Keep secrets and private
records out of logs and handoffs. Report what changed, where it was verified, and
any remaining limitation. Continue authorized work; ask only for a decision or
permission that is actually missing.
`
