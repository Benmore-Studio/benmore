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
var version = "2.7.194"

// Full release history lives in the private development repo and git log.
func main() {
	// Install JSON log formatter when BENMORE_LOG_FORMAT=json. No-op
	// otherwise. Must run before any log.Printf in the binary so every
	// init that logs lands in the configured format.
	InstallStructuredLogging()

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	// First-run convenience: drop the Claude Code skill into ~/.claude if a
	// Claude home exists. No-op in the framework build and for `skill`.
	maybeAutoInstallSkill()

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
	case "help":
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

func printUsage() {
	fmt.Println(`benmore - turn Prisma + vanilla HTML/JS + YAML into web apps

  benmore new <dir>                 Scaffold a new app (runnable immediately)
  benmore serve [dir] [--port N]    Run an app from a directory on one port
  benmore test [dir] [--app|--framework] [--json]
  benmore docs [topic]              Built-in framework docs
  benmore version [--json]
  benmore help`)
	// platformUsageText is empty in the open-source framework build and lists
	// the hosted deployed-app / MCP commands in the platform build.
	fmt.Print(platformUsageText())
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
	fmt.Print(body)

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
