//go:build !cli

package main

// App-source file modes across the router/app-process seam.
//
// On a hosted platform two users touch an app's source tree: the router
// (user benmore) and the per-app service (benmore-app-<sub>), both in the
// shared benmore group. The per-app systemd unit runs with UMask=0077, so a
// file the APP PROCESS writes - the migration it generates at boot, the
// schema.sql it derives from schema.yaml - lands 0600 and owned by the app
// user no matter what mode os.WriteFile asks for. The router then cannot
// read it: `git add` for the per-app history fails with "Permission denied",
// every push reports history_committed:false/ok:false even though the source
// was saved, and the stale sync marker turns the next push into a false
// conflict. chmod is not subject to the umask, so widen explicitly after
// writing, and repair files an older runtime already created.

import (
	"os"
	"path/filepath"
	"strings"
)

// appSourceFileMode / appSourceDirMode are the modes both processes need:
// group read+write so either side can rewrite the other's files.
const (
	appSourceFileMode os.FileMode = 0o664
	appSourceDirMode  os.FileMode = 0o775
)

// writeAppSourceFile writes a source-tree file from the app process and makes
// it group read/writable despite the unit's umask.
func writeAppSourceFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, appSourceFileMode); err != nil {
		return err
	}
	_ = os.Chmod(path, appSourceFileMode)
	return nil
}

// repairAppSourceModes widens migrations/ and its *.sql files plus the
// derived schema.sql when this process owns them and they are narrower than
// the shared modes. Best-effort and silent: a file owned by the other user is
// left alone (chmod would fail), and nothing else in the tree is touched.
func repairAppSourceModes(dir string) {
	widen := func(path string, want os.FileMode) {
		info, err := os.Stat(path)
		if err != nil {
			return
		}
		if info.Mode().Perm()&want != want {
			_ = os.Chmod(path, info.Mode().Perm()|want)
		}
	}
	migDir := filepath.Join(dir, "migrations")
	if entries, err := os.ReadDir(migDir); err == nil {
		widen(migDir, appSourceDirMode)
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
				widen(filepath.Join(migDir, e.Name()), appSourceFileMode)
			}
		}
	}
	widen(filepath.Join(dir, "schema.sql"), appSourceFileMode)
}
