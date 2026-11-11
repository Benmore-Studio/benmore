//go:build !cli

package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
)

// openRestoreDB opens a database file a restore, refresh or backup step works
// on (a live data.db, a staged candidate, a backup). The path must name a
// regular file, and every connection is checked to have opened that file and
// not what a link swapped in afterwards points at (openTenantDB). This is the
// "nofollow" these steps need: SQLite has no nofollow URI parameter (an
// unknown one is ignored) and the driver does not pass SQLITE_OPEN_NOFOLLOW.
// extra is appended to the URI's query (it starts with "&").
func openRestoreDB(driver, path, mode, extra string) (*sql.DB, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errTenantDBRedirected
	}
	return openTenantDB(driver, path, sqliteRestoreURI(path, mode)+extra)
}

// openRestoreDBIn opens dir/rel like openRestoreDB, for a caller that does
// not own dir's contents (the router reading a stage in an instance's tree):
// no component of rel may be a link. dir, which the caller chose, is
// resolved; rel is joined to it as written; and every connection must have
// opened exactly that file. SQLite reports the name it opened with every
// link resolved, so a directory below dir that is (or becomes) a link fails
// the check whenever it is swapped in.
func openRestoreDBIn(driver, dir, rel, mode, extra string) (*sql.DB, error) {
	if !filepath.IsLocal(rel) {
		return nil, errTenantDBRedirected
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	base, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	if err := refuseRouterTenantData(filepath.Join(base, rel)); err != nil {
		return nil, err
	}
	parts := strings.Split(filepath.Clean(rel), string(filepath.Separator))
	want := base
	for i, part := range parts {
		want = filepath.Join(want, part)
		info, err := os.Lstat(want)
		if err != nil {
			return nil, err
		}
		if last := i == len(parts)-1; (last && !info.Mode().IsRegular()) || (!last && !info.IsDir()) {
			// A link is neither a directory nor a regular file here.
			return nil, errTenantDBRedirected
		}
	}
	probe, err := sql.Open(driver, "")
	if err != nil {
		return nil, err
	}
	drv := probe.Driver()
	probe.Close()
	return sql.OpenDB(&tenantDBConnector{drv: drv, dsn: sqliteRestoreURI(want, mode) + extra, want: want}), nil
}
