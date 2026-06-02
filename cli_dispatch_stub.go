//go:build !platform

package main

// Open-source framework stubs for the platform CLI surface. The hosted-
// platform commands (login/signup, deploy, push/pull, the MCP thin-clients,
// edges, fleet ops) live only in the `platform` build. In the framework
// build they're absent, so dispatchPlatformCLI never handles a command,
// the usage text has no deployed-apps section, and the docs-read gate ping
// is a no-op (there is no hosted MCP to ping).

// platformBuild is false in the open-source framework build. `benmore
// version` surfaces this so a deploy can assert it shipped the full binary.
const platformBuild = false

func dispatchPlatformCLI(cmd string) bool { return false }

func platformUsageText() string { return "" }

func markDocsRead(topic string) {}
