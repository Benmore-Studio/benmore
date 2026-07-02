//go:build !platform && !cloud

package main

// Open-source framework stubs for the cloud CLI surface. The hosted-platform
// client commands (login/signup, deploy, push/pull, the MCP thin-clients,
// edges) live in the `cloud` and `platform` builds. In the pure framework
// build they're absent, so dispatchPlatformCLI never handles a command,
// the usage text has no deployed-apps section, and the docs-read gate ping
// is a no-op (there is no hosted MCP to ping).

func dispatchPlatformCLI(cmd string) bool { return false }

// maybeAutoInstallSkill is a no-op in the pure framework build - the bundled
// skill teaches the cloud workflow (deploy/push), which this edition lacks.
func maybeAutoInstallSkill() {}

func platformUsageText() string { return "" }

func markDocsRead(topic string) {}
