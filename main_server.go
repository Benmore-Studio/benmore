//go:build !cli

package main

// Server-side command dispatch. Lives in the default build only - the
// CLI build (-tags cli) gets the stub in main_server_cli.go which
// returns false for every command, so `benmore host` / `benmore router`
// / `benmore serve` are unreachable from a CLI-tagged binary.
//
// These commands launch the multi-tenant platform server. They're
// invoked by a process supervisor (e.g. systemd) in multi-tenant mode:
//
//   benmore router  - front-door reverse proxy on :80/:443 (one process)
//   benmore host    - multi-app platform in a single process (dev mode)
//   benmore serve   - per-app HTTP server bound to one port; the router
//                     dispatches subdomain → port via ports.json. systemd
//                     manages one service unit per app.

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strconv"
)

// serverDispatch handles the framework's local commands (new, serve).
// Returns true when it ran the command, false otherwise (so main.go falls
// through to the unknown-command error).
func serverDispatch(cmd string) bool {
	switch cmd {
	case "new":
		runServerNew()
		return true
	case "serve":
		runServerServe()
		return true
	case "test":
		runServerTest()
		return true
	}
	// host / router / migrate-media are platform (fleet) commands; they
	// live behind the `platform` build tag. In the open-source framework
	// build dispatchPlatformServer is a stub that returns false, so the
	// only server command is `serve` - run one app on one port.
	return dispatchPlatformServer(cmd)
}

// runServerTest is `benmore test`. It runs on a disposable copy of the app's
// source (runServerTestsOnCopy), so the workspace is never written. A run that
// cannot reach the tests still prints a result with a SUMMARY entry, which
// --json consumers read as "nothing ran".
func runServerTest() {
	dir, mode, asJSON, err := parseServerTestArgs()
	if err != nil {
		if hasFlag("json") {
			printTestResults(testSetupFailure(nil, "arguments", err), true)
		}
		fmt.Fprintf(os.Stderr, "Usage: benmore test [dir] [--app|--framework] [--json]\n%s\n", err)
		os.Exit(1)
	}
	results, setupErr := runServerTestsOnCopy(dir, mode)
	printTestResults(results, asJSON)
	if setupErr != nil {
		fmt.Fprintf(os.Stderr, "test: %s\n", setupErr)
	}
	if !testResultsPassed(results) {
		os.Exit(1)
	}
}

func parseServerTestArgs() (dir, mode string, asJSON bool, err error) {
	pos := positionalArgs("app", "framework", "json")
	if len(pos) > 1 {
		return "", "", false, fmt.Errorf("expected at most one app directory, got %d", len(pos))
	}
	if hasFlag("app") && hasFlag("framework") {
		return "", "", false, fmt.Errorf("--app and --framework are mutually exclusive")
	}
	if len(pos) == 1 {
		dir = pos[0]
		if abs, absErr := filepath.Abs(dir); absErr == nil {
			dir = abs
		}
	} else {
		dir, _ = os.Getwd()
	}
	switch {
	case hasFlag("app"):
		mode = "app"
	case hasFlag("framework"):
		mode = "framework"
	default:
		mode = "all"
	}
	return dir, mode, hasFlag("json"), nil
}

func loadAppForServerTests(dir string) (*App, error) {
	if err := resetServerTestDatabase(dir); err != nil {
		return nil, err
	}
	oldTestBoot, hadTestBoot := os.LookupEnv("BENMORE_TEST_BOOT")
	_ = os.Setenv("BENMORE_TEST_BOOT", "1")
	defer func() {
		if hadTestBoot {
			_ = os.Setenv("BENMORE_TEST_BOOT", oldTestBoot)
		} else {
			_ = os.Unsetenv("BENMORE_TEST_BOOT")
		}
	}()
	// Nothing a test run reports reaches the developer's Sentry or Slack.
	return loadAppWithOptions(dir, appLoadOptions{noErrorDelivery: true})
}

func resetServerTestDatabase(dir string) error {
	// A test load ALWAYS deletes data.db for a clean run. `benmore test` and
	// `benmore verify` load a disposable copy of the source (copyTestSource),
	// which has no .benmore/, so this never meets a real app. It stays a
	// backstop: a directory with .benmore/ holds an app's state - a hosted app
	// instance, a workspace an app was served or deployed from - and its
	// data.db is not deleted unless the operator opts in with
	// BENMORE_TEST_RESET=1.
	if _, err := os.Stat(filepath.Join(dir, ".benmore")); err == nil && os.Getenv("BENMORE_TEST_RESET") != "1" {
		return fmt.Errorf("refusing to reset data.db in %s: .benmore/ holds this app's state (a deployed app or a linked workspace); benmore test runs on a copy of the source instead. Set BENMORE_TEST_RESET=1 to override", filepath.Base(dir))
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		path := filepath.Join(dir, "data.db"+suffix)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("reset %s: %w", filepath.Base(path), err)
		}
	}
	return nil
}

// runServerNew scaffolds a new app directory: `benmore new <dir>`. It writes
// the default TSX-stack app (app.yaml, schema.prisma, static/ pages + the
// typed bm SDK reference) so the directory is immediately runnable with
// `benmore serve`.
func runServerNew() {
	if len(os.Args) != 3 || os.Args[2] == "" || os.Args[2][0] == '-' {
		fmt.Fprintln(os.Stderr, "Usage: benmore new <dir>")
		os.Exit(2)
	}
	dir, err := scaffoldTargetDir(os.Args[2])
	if err != nil {
		log.Fatalf("refusing to scaffold: %s", err)
	}
	if err := writeHTMLScaffoldFiles(dir, "", editionName == "framework"); err != nil {
		log.Fatalf("scaffold failed: %s", err)
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		absDir = dir
	}
	fmt.Print(scaffoldNextSteps(absDir))
}

// scaffoldTargetDir is the directory `benmore new <dir>` writes: one that does
// not exist yet, or an empty one (`mkdir app && cd app && benmore new .` was
// refused as "already exists"; a `git init` there does not fill it). An
// existing directory comes back absolute: the app is named after the
// directory, which `.` does not spell.
func scaffoldTargetDir(dir string) (string, error) {
	if _, err := os.Stat(dir); err != nil {
		return dir, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil || slices.ContainsFunc(entries, func(e os.DirEntry) bool { return e.Name() != ".git" && e.Name() != ".DS_Store" }) {
		return "", fmt.Errorf("%s already exists and is not an empty directory", dir)
	}
	return filepath.Abs(dir)
}

// scaffoldNextSteps is what `benmore new` prints after it writes the app: the
// commands this edition runs next, and nothing it does not have. The
// framework edition has no development mode, so it names no local address
// (it used to print `open http://localhost:8080` beside a scaffolded
// AGENTS.md that says there is no localhost development mode).
func scaffoldNextSteps(absDir string) string {
	if editionName == "framework" {
		return fmt.Sprintf("Created %s\n\nNext:\n  benmore test %q\n  benmore serve %q --port 8080\n\n`benmore test` runs the generated tests and tests/*.yaml on a copy of the source.\n`benmore serve` is the self-hosted runtime, not a development mode: run it as a\nservice and open the app at the address your deployment gives that port.\nAGENTS.md in the new directory describes the runtime; `benmore docs build` is the guide.\n", absDir, absDir, absDir)
	}
	return fmt.Sprintf("Created %s\n\nNext:\n  cd %q\n  benmore deploy\n  benmore open .\n\nOptional app connector: after deploying, pull the complete source before authoring and reviewing mcp.yaml. See `benmore docs connector`.\n", absDir, absDir)
}

// startServedApp is the start of a served process: the boot check, the start-up
// load and the one-shot resume of approved connector writes, in that order.
// bootCheckApplies reports whether startup runs the full source check. A
// hosted app's files already passed the platform's write gate, and the check
// (a second app load plus a parse of every static/ and src/ script) ran before
// the app served anything, inside the unit's memory and CPU limits: a dev app
// with 16 MB of bundled JavaScript never finished starting under 2.7.306.
func bootCheckApplies() bool {
	return !hostedTenantProcess()
}

// Tests restart through it so they cannot skip a step the real process takes.
func startServedApp(dir string) (*App, error) {
	// Run the unified validators before boot (v2.7.164). The platform's
	// write-time gate is what catches broken flows / malformed YAML on
	// hosted apps; local serve historically skipped it entirely, so a
	// broken `INSERT…SELECT…ON CONFLICT` flow loaded silently and only
	// surfaced at push time. Findings print as warnings - serve still
	// boots so a stale finding can't brick local dev.
	if bootCheckApplies() {
		serveBootCheck(dir)
	}
	app, err := loadAppWithOptions(dir, appLoadOptions{startup: true})
	if err != nil {
		return nil, err
	}
	resumeAppMCPApprovedWrites(app)
	return app, nil
}

// runServerServe boots a single app on a single port.
func runServerServe() {
	// Before the load: boot (migrations, the source check) is when a
	// hosted app's heap first meets its unit's memory cap. The platform owns
	// a hosted tenant's memory policy; a self-hosted GOMEMLIMIT wins.
	startGoMemoryLimitFromCgroup(hostedTenantProcess())
	logMallocArenaCap()
	dir := getAppDir(2)
	port, _ := strconv.Atoi(getFlag("port", "8080"))

	mcpLocal := hasFlag("mcp-local") || hasFlag("mcp-writes")
	if mcpLocal {
		authority, err := prepareMCPLocalAuthority(dir)
		if err != nil {
			log.Fatalf("--mcp-local: %s", err)
		}
		log.Printf("  MCP local: authority directory %s", authority)
	}

	app, err := startServedApp(dir)
	if err != nil {
		log.Fatalf("Error loading app: %s", err)
	}
	app.MCPLocal, app.MCPLocalWrites = mcpLocal, hasFlag("mcp-writes")
	// app.Shutdown() does the WAL checkpoint + DB.Close pair, plus
	// signals every goroutine listening on app.Stop. Pre-2.7.32 only
	// app.DB.Close() ran here, which skipped the wal_checkpoint and
	// left torn frames at risk of triggering auto-recovery on next
	// boot. We still call this on the StartServer-returning path so
	// the deferred call runs even when graceful shutdown took the
	// full TimeoutStopSec window.
	defer app.Shutdown()
	// Let a job or scheduled flow in progress finish when systemd stops the
	// unit; past serveJobDrainTimeout the database closes under it.
	app.jobDrainTimeout = serveJobDrainTimeout

	if err := StartServer(app, port, false); err != nil {
		log.Fatalf("Server error: %s", err)
	}
}

// runServerHost / runServerRouter (the multi-tenant fleet commands) live in
// server_dispatch_platform.go behind the `platform` build tag.
