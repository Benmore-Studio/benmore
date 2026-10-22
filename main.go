package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// version is the release version. It defaults to the value baked here and is
// overridden at release time via -ldflags "-X main.version=<tag>" (see the
// public edition's .goreleaser.yaml).
var version = "2.7.301"

type appMCPCLIUsageError string

func (err appMCPCLIUsageError) Error() string { return string(err) }

// Full release history lives in the private development repo and git log.
func main() {
	if appMCPPDFHelperMain() {
		return
	}
	// GIT_ASKPASS mode (GitHub sync, platform_github.go): the router
	// execs `git push` with GIT_ASKPASS pointing back at this binary so
	// the access token reaches git via ENVIRONMENT, never argv
	// (/proc/<pid>/cmdline is world-readable; the environment is
	// uid-private). When invoked as askpass we print the token and exit
	// immediately - before any other init.
	if os.Getenv("BENMORE_GIT_ASKPASS") == "1" {
		fmt.Println(os.Getenv("BENMORE_GIT_TOKEN"))
		return
	}

	// Install JSON log formatter when BENMORE_LOG_FORMAT=json. No-op
	// otherwise. Must run before any log.Printf in the binary so every
	// init that logs lands in the configured format.
	InstallStructuredLogging()

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	if cmd == "mcp" {
		if help := mcpOwnerHelp(os.Args[2:]); help != "" {
			fmt.Print(help)
			return
		}
	}
	// Operator preflight must not log in, install skills, emit telemetry, or
	// start an app. The implementation exists only in the platform edition.
	if cmd == "upgrade-check" {
		if serverDispatch(cmd) {
			return
		}
		fmt.Fprintln(os.Stderr, "upgrade-check requires the platform edition")
		os.Exit(2)
	}
	if cmd == "api" && len(os.Args) > 2 && (os.Args[2] == "--help" || os.Args[2] == "-h") && dispatchPlatformCLI(cmd) {
		return
	}
	if (cmd == "edge" || cmd == "edges") && len(os.Args) > 2 && (os.Args[2] == "--help" || os.Args[2] == "-h" || os.Args[2] == "help") && dispatchPlatformCLI(cmd) {
		return
	}
	// `benmore <cmd> --help` prints that command's usage instead of running
	// it: `create-app --help` used to create an app named "--help".
	if len(os.Args) > 2 && (os.Args[2] == "--help" || os.Args[2] == "-h") && !commandsWithOwnHelp[cmd] {
		if usage := commandUsage(cmd); usage != "" {
			fmt.Print(usage)
		} else {
			printUsage()
		}
		return
	}
	// Local connector commands must never authenticate remotely, install skills,
	// emit telemetry, open app data or start workers. The owner switch verbs
	// (status|enable|disable) are the exception: they call the platform.
	if cmd == "mcp" && !isMCPConnectorSwitchCommand(os.Args[2:]) {
		if err := runAppMCPCLI(os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "mcp: %s\n", err)
			code := 1
			if _, usage := err.(appMCPCLIUsageError); usage {
				code = 2
			}
			os.Exit(code)
		}
		return
	}
	preflightPlatformCLIAuth(cmd)

	// One-line stderr hint when a newer CLI release exists (cloud
	// edition only; interactive terminals only; cached 24h; never
	// blocks or fails the command). See cli_update_check.go.
	runCLIUpdateCheck(cmd, maybeWarnNewerCLI)

	// Bootstrap must complete authentication before any setup writes and
	// installs both skills itself after successful authentication.
	if cmd != "bootstrap" && cmd != "login" && cmd != "signup" {
		maybeAutoInstallSkill()
	}
	maybeSyncAgentUsageOnStartup(cmd)

	switch cmd {
	case "version", "--version", "-v", "-V":
		edition := editionName
		if hasFlag("json") {
			fmt.Printf(`{"version": %q, "edition": %q}`+"\n", version, edition)
		} else {
			fmt.Printf("benmore %s (%s)\n", version, edition)
		}
	case "docs":
		cmdDocs()
	case "help", "--help", "-h":
		printUsage()
	default:
		// Platform CLI commands - login/signup, the deployed-app
		// thin-clients (push/pull/sql/probe/…), publish, edges, and the
		// hosted MCP surface - live behind the `platform` build tag. In the
		// open-source framework build dispatchPlatformCLI is a stub that
		// returns false, so those commands are simply absent.
		if dispatchPlatformCLI(cmd) {
			return
		}
		// Server-launch commands: `serve` in every build; host/router/
		// migrate-media in the platform build (main_server.go, behind !cli).
		if serverDispatch(cmd) {
			return
		}
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func runCLIUpdateCheck(cmd string, check func()) {
	switch cmd {
	case "bootstrap", "login", "signup":
		return
	default:
		check()
	}
}

func printUsage() {
	fmt.Print(usageText())
}

// commandUsage returns the usage lines for one command (with their wrapped
// continuation lines), or "" when the usage text doesn't list it.
func commandUsage(cmd string) string {
	var b strings.Builder
	inEntry := false
	for _, line := range strings.Split(usageText(), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "benmore "+cmd+" ") || trimmed == "benmore "+cmd:
			inEntry = true
		case inEntry && trimmed != "" && !strings.HasPrefix(trimmed, "benmore ") && strings.HasPrefix(line, "        "):
		default:
			inEntry = false
		}
		if inEntry {
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

func mcpOwnerHelp(args []string) string {
	if !isMCPConnectorSwitchCommand(args) {
		return ""
	}
	for _, arg := range args[1:] {
		if arg == "--help" || arg == "-h" {
			return commandUsage("mcp")
		}
	}
	return ""
}

// commandsWithOwnHelp parse --help themselves.
var commandsWithOwnHelp = map[string]bool{
	"api": true, "open": true, "logs": true, "env": true, "mcp": true, "promote": true,
	"login": true, "signup": true, "import": true, "verify": true, "ship": true, "qa": true,
}

// usageText is the command list; platformUsageText is empty in the
// open-source framework build and lists the hosted deployed-app / MCP
// commands in the platform build.
func usageText() string {
	return `benmore - turn Prisma + vanilla HTML/JS + YAML into web apps

  benmore new <dir>                 Scaffold a new app (runnable immediately)
  benmore serve [dir] [--port N]    Run an app from a directory on one port
  benmore serve [dir] --mcp-local [--mcp-writes]
                                    Also run its reviewed MCP connector at http://localhost:N/api/_mcp
  benmore test [dir] [--app|--framework] [--json]
  benmore upgrade-check <app-dir> [<app-dir>...] | --apps-dir <dir>  (platform)
  benmore mcp inspect <appdir> --json   Inspect source connector candidates
  benmore mcp generate <appdir> --openapi <file> --out <file>
  benmore mcp check <appdir>            Validate source connector bindings
  benmore mcp review <appdir> --reviewed   Bind reviewed manifest to current source
  benmore docs [topic]              Built-in framework docs
  benmore version [--json]
  benmore help
` + platformUsageText()
}

// getAppDir returns the app directory from args or defaults to current dir.
func getAppDir(argIndex int) string {
	if argIndex < len(os.Args) {
		dir := os.Args[argIndex]
		if !strings.HasPrefix(dir, "-") {
			abs, err := filepath.Abs(dir)
			if err == nil {
				return abs
			}
			return dir
		}
	}
	dir, _ := os.Getwd()
	return dir
}

func getFlag(name string, defaultVal string) string {
	for i, arg := range os.Args {
		if arg == "--"+name && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
		if strings.HasPrefix(arg, "--"+name+"=") {
			return strings.TrimPrefix(arg, "--"+name+"=")
		}
	}
	return defaultVal
}

func hasFlag(name string) bool {
	for _, arg := range os.Args {
		if arg == "--"+name {
			return true
		}
	}
	return false
}

// positionalArgs returns the non-flag arguments after the subcommand
// (os.Args[2:]), so commands can accept --flags in ANY position instead
// of only after the positionals. `--name value` consumes two tokens
// unless name is listed in boolFlags (then only one); `--name=value` is
// always a single token. Without this, `benmore probe <app> --env prod
// PATCH /api/x` silently parsed "prod" as the method - the request
// still fired, just wrong.
func positionalArgs(boolFlags ...string) []string {
	boolSet := make(map[string]bool, len(boolFlags))
	for _, f := range boolFlags {
		boolSet[f] = true
	}
	var pos []string
	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
		if !strings.HasPrefix(arg, "--") {
			pos = append(pos, arg)
			continue
		}
		name := strings.TrimPrefix(arg, "--")
		if strings.Contains(name, "=") || boolSet[name] {
			continue // self-contained flag token
		}
		i++ // skip the flag's value
	}
	return pos
}

// cmdDocs prints agent-oriented documentation embedded in the binary.
//
//	benmore docs           - list available topics
//	benmore docs <topic>   - print that topic
func cmdDocs() {
	topic := ""
	if len(os.Args) >= 3 && !strings.HasPrefix(os.Args[2], "-") {
		topic = os.Args[2]
	}
	if topic == "" || topic == "list" || topic == "topics" {
		fmt.Println("Benmore framework documentation.")
		fmt.Println()
		fmt.Println("Topics:")
		fmt.Print(AgentDocsCatalog())
		fmt.Println()
		fmt.Println("Usage: benmore docs <topic>     (e.g. benmore docs quickstart)")
		return
	}
	body := AgentDocs(topic)
	if body == "" {
		fmt.Fprintf(os.Stderr, "Unknown topic: %q\n\n", topic)
		fmt.Fprintln(os.Stderr, "Available topics:")
		fmt.Fprint(os.Stderr, AgentDocsCatalog())
		os.Exit(1)
	}
	fmt.Print(AgentDocsPointer(topic) + body)

	// Also mark the topic read server-side via the MCP help tool. The
	// docs-read gate is opt-in (BENMORE_DOCS_GATE=1) but when it IS on,
	// reading via CLI should satisfy it the same as the MCP help tool
	// - otherwise CLI users get gated even though they read the docs.
	// Best-effort, non-fatal: a CLI invocation without credentials or
	// network access shouldn't fail just because we couldn't ping MCP.
	// markDocsRead is a no-op in the open-source framework build (no hosted
	// MCP), and pings the help tool in the platform build.
	markDocsRead(topic)
}
