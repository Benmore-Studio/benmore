//go:build !cli && !platform && !cloud

package main

import "fmt"

func scaffoldAgentsGuide(title, name string) string {
	return fmt.Sprintf("# %s — Benmore app\n\n", title) + frameworkAgentContract + scaffoldSharedAgentContract
}

const frameworkAgentContract = `This app uses the self-hosted framework edition. Read ` + "`" + `benmore docs build` + "`" + ` and
` + "`" + `benmore docs harness` + "`" + ` for the edition boundary and runtime model. Hosted commands
such as ` + "`" + `push` + "`" + `, ` + "`" + `api` + "`" + `, ` + "`" + `skill` + "`" + `, and ` + "`" + `promote` + "`" + ` are not part of this edition.

An operator deploys the app with ` + "`" + `benmore serve <app-directory>` + "`" + ` as a production
service. This is a self-hosted runtime, not a separate localhost development mode.
Use the configured deployed URL, current generated schema/OpenAPI when available,
and the installed binary's help to verify changes. Native TSX uses embedded esbuild;
no Node server or frontend build process is required.

Codex reads this AGENTS.md; Claude Code imports it through CLAUDE.md. Keep the same
app contract regardless of the agent. Never claim a hosted push or cloud validation
ran when using only the framework binary.

`
