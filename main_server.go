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
	}
	// host / router / migrate-media are platform (fleet) commands; they
	// live behind the `platform` build tag. In the open-source framework
	// build dispatchPlatformServer is a stub that returns false, so the
	// only server command is `serve` - run one app on one port.
	return dispatchPlatformServer(cmd)
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
	fmt.Printf("Created %s\n\nNext:\n  benmore serve %s --port 8080\n  open http://localhost:8080\n", dir, dir)
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
	// boots so a stale finding can't brick local dev. (Platform builds
	// only - the validator stack lives behind the platform tag; the
	// framework/cloud shim is a no-op.)
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
