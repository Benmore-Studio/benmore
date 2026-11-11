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
// it group read/writable despite the unit's umask. A link at path is refused,
// never written through (a migration linked to data.db must not truncate the
// database or widen it to the source mode).
func writeAppSourceFile(path string, data []byte) error {
	f, err := openNoFollow(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, appSourceFileMode)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	_ = chmodNoFollow(path, appSourceFileMode)
	return nil
}

// repairAppSourceModes widens migrations/ and its *.sql files, the derived
// schema.sql and the history .gitignore when this process owns them and they
// are narrower than the shared modes (an older router wrote .gitignore 0600,
// and under the tenant-data lock the tree's owner is this process's user). Best-effort and silent: a file owned by the other user is
// left alone (chmod would fail), and nothing else in the tree is touched. Only
// a regular file or a directory is widened, never through a link (lstat, then
// a chmod through a descriptor opened without following one): a schema.sql
// or migration linked to data.db would otherwise open the database to the
// group at every start.
func repairAppSourceModes(dir string) {
	widen := func(path string, want os.FileMode) {
		info, err := os.Lstat(path)
		if err != nil || (!info.Mode().IsRegular() && !info.IsDir()) {
			return
		}
		if info.Mode().Perm()&want != want {
			_ = chmodNoFollow(path, info.Mode().Perm()|want)
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
	widen(filepath.Join(dir, ".gitignore"), appSourceFileMode)
}
