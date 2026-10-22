//go:build !cli

package main

import "path/filepath"

// dbFileReplacedHook is invoked whenever a live `data.db` is replaced by raw
// file I/O rather than through its own connection — a backup restore, a
// boot-time auto-recovery swap, or a dev-data refresh.
//
// It exists because `migrate.go` compiles into BOTH the per-app serve binary
// and the platform router (`!cli`), while the router's connection cache lives
// behind the `platform` build tag. A package-level hook lets the file-swapping
// code announce the swap without importing anything the serve binary lacks;
// `platform_dashboard.go` wires it to the real evictor in its init().
//
// Nil when the router is not part of the build. Always call through
// notifyDBFileReplaced, never directly.
var dbFileReplacedHook func(dbPath string)

// dbRestoredAppHook is invoked with the app directory after the same swap,
// for state kept OUTSIDE the app database that names its rows. The platform's
// edge grants carry the app's local user ids, and a replaced database can
// hand an id to a different account, so the platform build revokes them here
// (edge_auth.go). Nil when the platform is not part of the build.
var dbRestoredAppHook func(appDir string)

func notifyDBFileReplaced(dbPath string) {
	if dbFileReplacedHook != nil {
		dbFileReplacedHook(dbPath)
	}
	if dbRestoredAppHook != nil {
		dbRestoredAppHook(filepath.Dir(dbPath))
	}
}
