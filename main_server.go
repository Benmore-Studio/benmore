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
	case "git-init":
		runServerGitInit()
		return true
	}
	// host / router / migrate-media are platform (fleet) commands; they
	// live behind the `platform` build tag. In the open-source framework
	// build dispatchPlatformServer is a stub that returns false, so the
	// only server command is `serve` - run one app on one port.
	return dispatchPlatformServer(cmd)
}

func runServerTest() {
	dir, mode, asJSON, err := parseServerTestArgs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Usage: benmore test [dir] [--app|--framework] [--json]\n%s\n", err)
		os.Exit(1)
	}
	app, err := loadAppForServerTests(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "test: load app: %s\n", err)
		os.Exit(1)
	}
	defer app.Shutdown()

	var results []AppTestResult
	switch mode {
	case "app":
		results = RunAppTests(app)
	case "framework":
		results = RunAllTests(app, GenerateFrameworkTests(app), false)
	default:
		results = RunAllTests(app, GenerateFrameworkTests(app), true)
	}
	printTestResults(results, asJSON)
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
	return loadApp(dir)
}

func resetServerTestDatabase(dir string) error {
	// `benmore test` ALWAYS resets the DB for a clean run, and this command
	// ships in every edition (including the platform binary). Running it inside
	// a deployed app dir would wipe live data. A per-app `.benmore/` git dir is
	// the signature of a hosted/managed app (per-app git auto-commit) that a
	// freshly-scaffolded local app does not have, so refuse there unless the
	// operator explicitly opts in with BENMORE_TEST_RESET=1.
	if _, err := os.Stat(filepath.Join(dir, ".benmore")); err == nil && os.Getenv("BENMORE_TEST_RESET") != "1" {
		return fmt.Errorf("refusing to reset data.db in %s: looks like a deployed app (.benmore/ present); set BENMORE_TEST_RESET=1 to override", filepath.Base(dir))
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
	if len(os.Args) < 3 || os.Args[2] == "" || os.Args[2][0] == '-' {
		fmt.Fprintln(os.Stderr, "Usage: benmore new <dir>")
		os.Exit(1)
	}
	dir := os.Args[2]
	if _, err := os.Stat(dir); err == nil {
		log.Fatalf("refusing to scaffold: %s already exists", dir)
	}
	if err := WriteHTMLScaffoldFiles(dir, ""); err != nil {
		log.Fatalf("scaffold failed: %s", err)
	}
	// Deploy-on-merge automation, written BEFORE the repo is created so
	// both files land in the initial commit and the tree starts clean.
	if _, err := writeDeployAutomation(dir); err != nil {
		log.Printf("git: deploy automation not written: %s", err)
	}
	// Per-app git history from the first second. gitEnsureRepo writes the
	// protective .gitignore (env.yaml, data.db*, uploads/, .benmore/) and
	// makes the initial commit - so a scaffolded app is a real repo before
	// the user's first edit, and their first `git add .` can't sweep up
	// secrets or the SQLite file. Best-effort: a host without git in PATH
	// still gets a working app, just no history.
	if err := gitEnsureRepo(dir, filepath.Base(dir)); err != nil {
		log.Printf("git: per-app history unavailable: %s", err)
	} else if err := gitUseTrackedHooks(dir); err != nil {
		// Non-fatal: the repo and its history exist either way, only the
		// deploy-on-merge convenience would be missing.
		log.Printf("git: tracked hooks not enabled: %s", err)
	}
	fmt.Printf("Created %s\n\nNext:\n  benmore serve %s --port 8080\n  open http://localhost:8080\n", dir, dir)
}

// runServerGitInit retrofits an EXISTING app directory with the same git
// setup `benmore new` now creates: a repo, the protective .gitignore, the
// deploy-on-merge automation, and core.hooksPath.
//
//	benmore git-init [dir]
//
// This exists because `benmore new` is the rarest way an app reaches a
// developer's machine. Apps that arrive via `benmore pull` / `benmore
// sync` get a .benmore/ manifest but no repo at all, which is exactly the
// case this command fixes.
//
// Every step is idempotent and additive: an existing repo keeps its
// history, an existing .gitignore or hook keeps the user's version, and
// re-running is a no-op that reports "already set up". Nothing here can
// lose work, which is what makes it safe to point at a directory that
// already has months of it.
func runServerGitInit() {
	dir := getAppDir(2)

	// Refuse anything that isn't an app. Running this against a home dir
	// or a folder that merely CONTAINS apps would create a repo spanning
	// all of them - tedious to unpick, and the sort of thing that only
	// gets noticed after the first commit. Same markers `deploy` checks.
	hasYAML := fileExists(filepath.Join(dir, "app.yaml"))
	hasSchema := fileExists(filepath.Join(dir, "schema.prisma"))
	if !hasYAML && !hasSchema {
		fmt.Fprintf(os.Stderr, "git-init: %s doesn't look like a Benmore app (no app.yaml / schema.prisma).\nPass the app directory: benmore git-init <dir>\n", dir)
		os.Exit(1)
	}

	hadRepo := gitHasRepo(dir)

	wroteIgnore, err := gitEnsureIgnoreFile(dir)
	if err != nil {
		log.Fatalf("git-init: %s", err)
	}
	wroteFiles, err := writeDeployAutomation(dir)
	if err != nil {
		log.Fatalf("git-init: %s", err)
	}
	// Runs after the files above so a brand-new repo's initial commit
	// contains them instead of leaving the tree dirty on first use.
	if err := gitEnsureRepo(dir, filepath.Base(dir)); err != nil {
		log.Fatalf("git-init: %s", err)
	}
	hadHooksPath := gitHooksPathSet(dir)
	if err := gitUseTrackedHooks(dir); err != nil {
		log.Fatalf("git-init: %s", err)
	}

	// Report only what actually changed - a re-run that claims credit for
	// work it didn't do trains you to stop reading the output.
	var did []string
	if !hadRepo {
		did = append(did, "initialised a git repo (+ initial commit)")
	}
	if wroteIgnore {
		did = append(did, "wrote .gitignore (env.yaml, data.db*, uploads/, .benmore/)")
	}
	for _, f := range wroteFiles {
		did = append(did, "wrote "+f)
	}
	if !hadHooksPath {
		did = append(did, "set core.hooksPath to .githooks")
	}

	fmt.Println(filepath.Base(dir))
	if len(did) == 0 {
		fmt.Println("  already set up - nothing to do")
		return
	}
	for _, d := range did {
		fmt.Printf("  ✓ %s\n", d)
	}
	// New files in a repo that already had history are uncommitted right
	// now. Say so here rather than letting them surface in some later,
	// unrelated `git status`.
	if hadRepo && (wroteIgnore || len(wroteFiles) > 0) {
		fmt.Printf("\nExisting repo kept. Review and commit the new files:\n  git -C %s status\n", dir)
	}
	fmt.Printf("\nMerging to the default branch deploys to benmore dev.\nProduction stays manual: benmore promote <app>\n")
}

// fileExists reports whether path exists and is a regular file.
func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// runServerServe boots a single app on a single port.
func runServerServe() {
	dir := getAppDir(2)
	port, _ := strconv.Atoi(getFlag("port", "8080"))

	// Run the unified validators before boot (v2.7.164). The platform's
	// write-time gate is what catches broken flows / malformed YAML on
	// hosted apps; local serve historically skipped it entirely, so a
	// broken `INSERT…SELECT…ON CONFLICT` flow loaded silently and only
	// surfaced at push time. Findings print as warnings - serve still
	// boots so a stale finding can't brick local dev.
	serveBootCheck(dir)

	app, err := loadApp(dir)
	if err != nil {
		log.Fatalf("Error loading app: %s", err)
	}
	// app.Shutdown() does the WAL checkpoint + DB.Close pair, plus
	// signals every goroutine listening on app.Stop. Pre-2.7.32 only
	// app.DB.Close() ran here, which skipped the wal_checkpoint and
	// left torn frames at risk of triggering auto-recovery on next
	// boot. We still call this on the StartServer-returning path so
	// the deferred call runs even when graceful shutdown took the
	// full TimeoutStopSec window.
	defer app.Shutdown()

	if err := StartServer(app, port, false); err != nil {
		log.Fatalf("Server error: %s", err)
	}
}

// runServerHost / runServerRouter (the multi-tenant fleet commands) live in
// server_dispatch_platform.go behind the `platform` build tag.
