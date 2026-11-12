package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// version is the release version. It defaults to the value baked here and is
// overridden at release time via -ldflags "-X main.version=<tag>" (see the
// public edition's .goreleaser.yaml).
var version = "2.7.332"

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
	// `benmore help all` prints every command; plain `benmore help` prints the
	// common workflows (printUsage).
	if (cmd == "help" || cmd == "--help" || cmd == "-h") && len(os.Args) == 3 && (os.Args[2] == "all" || os.Args[2] == "--all") {
		fmt.Print(usageText())
		return
	}
	// `benmore help <cmd>` is `benmore <cmd> --help`; it used to print the
	// whole command list.
	if (cmd == "help" || cmd == "--help" || cmd == "-h") && len(os.Args) > 2 && !strings.HasPrefix(os.Args[2], "-") {
		if _, known := cliCommandFlagSpecs[os.Args[2]]; commandUsage(cliCanonicalCommand(os.Args[2])) == "" && !commandsWithOwnHelp[os.Args[2]] && !known {
			fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[2])
			printUsage()
			os.Exit(1)
		}
		os.Args = []string{os.Args[0], os.Args[2], "--help"}
		cmd = os.Args[1]
	}
	if cmd == "mcp" {
		if help := mcpOwnerHelp(os.Args[2:]); help != "" {
			fmt.Print(help)
			return
		}
	}
	// Operator host commands must not log in, install skills, emit telemetry,
	// or start an app. The implementations exist only in the platform edition.
	if cmd == "upgrade-check" || cmd == "operator-totp" || cmd == "dashboard-identity" || cmd == "tenant-helper" || cmd == "tenant-data-lock" || cmd == "backup-session" {
		if serverDispatch(cmd) {
			return
		}
		fmt.Fprintln(os.Stderr, cmd+" requires the platform edition")
		os.Exit(2)
	}
	if cmd == "api" && len(os.Args) > 2 && (os.Args[2] == "--help" || os.Args[2] == "-h") && dispatchPlatformCLI(cmd) {
		return
	}
	// `--help` anywhere prints the command's usage instead of running it, and
	// an undeclared flag stops the command before it authenticates or sends
	// anything (cli_flag_check.go). `create-app --help` used to create an app
	// named "--help", and `probe ... --data '{...}'` sent no body.
	args, code, stop := cliPreflight(cmd, os.Args[2:], os.Stdout, os.Stderr)
	if stop {
		if code != 0 {
			os.Exit(code)
		}
		return
	}
	os.Args = append([]string{os.Args[0], cmd}, args...)
	// Local connector commands must never authenticate remotely, install skills,
	// emit telemetry, open app data or start workers. The owner switch verbs
	// (status|enable|disable) are the exception: they call the platform.
	if cmd == "mcp" && !isMCPConnectorSwitchCommand(os.Args[2:]) {
		// review/check/inspect build the app's routes from source to check
		// them; the runtime's registration log lines ("feedback: API
		// registered") are not their output. They answer in JSON on stdout
		// and errors below.
		log.SetOutput(io.Discard)
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
	cliStartup(cmd, os.Args[2:])

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
		// thin-clients (push/pull/sql/probe/…), publish, and the
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

// cliStartup is what a command does before it is dispatched: the update
// hint, the skill setup and the usage sync. A `benmore docs` lookup in the
// reference does none of them: its answer is read from this binary and
// nothing is sent anywhere (docsReferenceLookup, docs_reference.go).
func cliStartup(cmd string, args []string) {
	offline := cmd == "docs" && docsReferenceLookup(args)

	// One-line stderr hint when a newer CLI release exists (cloud
	// edition only; interactive terminals only; cached 24h; never
	// blocks or fails the command). See cli_update_check.go.
	if !offline {
		runCLIUpdateCheck(cmd, maybeWarnNewerCLI)
	}

	// Bootstrap must complete authentication before any setup writes and
	// installs both skills itself after successful authentication.
	if cmd != "bootstrap" && cmd != "login" && cmd != "signup" {
		maybeAutoInstallSkill()
	}
	if !offline {
		maybeSyncAgentUsageOnStartup(cmd)
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

// printUsage prints the task-oriented overview; `benmore help all` prints
// usageText, the complete list.
func printUsage() {
	fmt.Print(workflowUsageText())
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

// commandsWithOwnHelp print their own, longer help for --help in any
// position; every other command gets its usage-text lines from cliPreflight.
var commandsWithOwnHelp = map[string]bool{
	"api": true, "open": true, "logs": true, "env": true, "mcp": true, "promote": true,
	"login": true, "signup": true, "import": true, "verify": true, "qa": true,
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
` + operatorUsageText() + `  benmore mcp inspect <appdir> --json   Inspect source connector candidates
  benmore mcp generate <appdir> --openapi <file> --out <file>
  benmore mcp check <appdir>            Validate source connector bindings
  benmore mcp review <appdir> --reviewed   Bind reviewed manifest to current source
` + docsUsageLines + `  benmore version [--json]
  benmore help [all|<command>]      Common workflows; all = this list; <command> = one command
` + platformUsageText()
}

// operatorUsageText lists the host commands only the platform edition
// implements. The other editions answer "requires the platform edition" for
// them, so their help does not offer them.
func operatorUsageText() string {
	if editionName != "platform" {
		return ""
	}
	return `  benmore upgrade-check <app-dir> [<app-dir>...] | --apps-dir <dir>  (platform)
  benmore operator-totp enroll|reset|remove|unlock <email> | status
                                    Operator step-up factors, on the router host (platform)
  benmore dashboard-identity status | check
                                    Router-owned dashboard sign-in, on the router host (platform)
  benmore tenant-data-lock status   Router callers of app databases left in this binary, and the
                                    router tenant-data lock, on the router host (platform)
  benmore backup-session mint <purpose> <instance> | url <instance> <key>
                                    Root only, run by benmore-appctl: a backup store session for one app (platform)
`
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

// cmdDocs prints documentation embedded in the binary: a bundled guide, or
// an answer from the app-builder reference (docs_reference.go).
func cmdDocs() {
	code, guide := docsRun(os.Args[2:], os.Stdout, os.Stderr)
	if code != 0 {
		os.Exit(code)
	}
	// A guide read here also counts as read on the platform: the opt-in
	// docs-read gate (BENMORE_DOCS_GATE=1) is satisfied by the CLI the same
	// as by the MCP help tool. Best-effort and non-fatal; a no-op in the
	// open-source framework build. A reference lookup sends nothing.
	if guide != "" {
		markDocsRead(guide)
	}
}
