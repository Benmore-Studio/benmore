//go:build !cli

package main

// Both harnesses use the same per-app contract; Claude imports AGENTS.md.
func scaffoldClaudeMD(title, name string) string {
	return "# Benmore app instructions for Claude Code\n\n@AGENTS.md\n\nRead AGENTS.md for this app's runtime, environment, and delivery contract.\n"
}

// scaffoldAppContract opens every edition's AGENTS.md and
// scaffoldDeliveryEvidence closes it. The connector and test sections between
// them name commands and tools, so each edition writes its own
// (scaffoldEditionSections in scaffold_claude_platform.go and
// scaffold_claude_oss.go): generated instructions name only what the edition
// that wrote them can run.
const scaffoldAppContract = `## App contract

- Read the existing files before choosing a shape, and keep the app's stack
  (TSX under ` + "`" + `static/` + "`" + ` compiled by embedded esbuild, or server-rendered root
  ` + "`" + `*.html` + "`" + ` pages) and the user's design conventions. Keep the entry
  small: features in ` + "`" + `static/views/` + "`" + `, shared UI in ` + "`" + `static/components/` + "`" + `, logic in
  ` + "`" + `static/lib/` + "`" + `.
- Data model in ` + "`" + `schema.prisma` + "`" + ` (SQL-schema apps also work), access rules in
  ` + "`" + `app.yaml` + "`" + `, server logic in flows/hooks, schedules in ` + "`" + `cron.yaml` + "`" + `. Inspect the
  actual contract before writing YAML.
- A record that moves through stages gets a ` + "`" + `workflows.yaml` + "`" + ` entry (` + "`" + `initial` + "`" + `,
  ` + "`" + `states` + "`" + `, ` + "`" + `transitions` + "`" + ` with role/` + "`" + `when` + "`" + ` guards), not a free ` + "`" + `status` + "`" + ` string or
  a pair of booleans: the framework then refuses other moves and audits each one.
- Use the generated ` + "`" + `src/bm.d.ts` + "`" + ` (never hand-edit it) and the ` + "`" + `bm` + "`" + ` SDK. The
  server enforces access; a hidden button or client route guard is not
  authorization.
- Malformed core configuration is refused before a reload changes anything, and
  the previous app keeps serving; committed database changes and external effects
  are not rolled back. Check the resulting behavior, not the upload message.

`

const scaffoldDeliveryEvidence = `## Delivery evidence

Exercise the changed journey, including authorized and unauthorized cases when
access changes, in a real browser for JavaScript, forms and layout; an HTML
response alone is not proof. Keep secrets and private records out of logs and
handoffs. Report what changed, where it was verified, and what is left. Continue
authorized work; ask only for a decision or permission that is missing.
`
