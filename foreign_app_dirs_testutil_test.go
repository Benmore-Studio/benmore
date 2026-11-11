//go:build !cli

package main

import "testing"

// restoreForeignAppDirsAfter puts foreignAppDirs back when t ends. Code that
// runs as its own process in production (the tenant helper, the lock canary)
// sets it for good; in a test it must not outlive the test, because an app
// load in a foreignAppDirs process is refused (errForeignAppLoad).
func restoreForeignAppDirsAfter(t *testing.T) {
	t.Helper()
	was := foreignAppDirs.Load()
	t.Cleanup(func() { foreignAppDirs.Store(was) })
}
