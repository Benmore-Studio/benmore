//go:build !cli

package main

// Opening a tenant's database from the router.
//
// The router can read every app's data.db, and a tenant process owns its own
// directory: it can put a symlink at data.db that points at another app's
// database, or at the platform's. SQLite follows it. Whatever the router
// then does with "this app's database" (answer the owner's SQL console, back
// it up to the owner's bucket prefix, copy it into the owner's dev instance)
// is done with somebody else's data. An lstat before the open only narrows
// the window: the link can be swapped in after the check, and a pool opens
// new connections for as long as it lives.
//
// So the answer is taken from the connection itself: SQLite reports the file
// it opened, with every link resolved, and a connection whose file is not the
// path that was asked for is closed before a statement runs on it.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

var errTenantDBRedirected = errors.New("database path leads to another file (symlink); refusing to open it")

// foreignAppDirs is set in a process that works on app directories owned by
// other accounts: the hosted router, the tenant file helper (which runs as
// the app's user but keeps these conservative paths) and the tenant-data
// lock canary. Such a process reads an app's files only through checked
// opens, and it never loads an app or opens its database for a load
// (errForeignAppLoad): the app's own process does that, and the router asks
// it over the data channel.
var foreignAppDirs atomic.Bool

// errForeignAppLoad refuses an app load (and the database open and
// pre-migrate snapshot that come with it) in a foreignAppDirs process. The
// router's last such load, check_app's validation load, now runs in the
// app's own process (data channel op check_live).
var errForeignAppLoad = errors.New("this process does not own the app's directory, so it does not load the app or open its database for it; the app's own process does (the router asks it over the data channel)")

// tenantDBConnector opens connections with a registered SQLite driver and
// accepts each one only if the file it opened is want.
type tenantDBConnector struct {
	drv       driver.Driver
	dsn, want string
}

func (c *tenantDBConnector) Driver() driver.Driver { return c.drv }

func (c *tenantDBConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.drv.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	named, ok := conn.(interface{ GetFilename(string) string })
	if !ok || named.GetFilename("main") != c.want {
		conn.Close()
		return nil, errTenantDBRedirected
	}
	return conn, nil
}

// canonicalTenantDBPath is the name SQLite reports for dbPath when the file
// itself is not a link: the directory with its links resolved (the apps
// directory may sit behind one), plus the file name as given.
func canonicalTenantDBPath(dbPath string) (string, error) {
	abs, err := filepath.Abs(dbPath)
	if err != nil {
		return "", err
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.Base(abs)), nil
}

// openTenantDB is sql.Open for a database inside a tenant's directory: dsn is
// the data source name for dbPath. Every connection of the returned pool is
// checked (tenantDBConnector). With the router tenant-data lock on, the
// hosted router refuses before touching the file (refuseRouterTenantData).
func openTenantDB(driverName, dbPath, dsn string) (*sql.DB, error) {
	if err := refuseRouterTenantData(dbPath); err != nil {
		return nil, err
	}
	want, err := canonicalTenantDBPath(dbPath)
	if err != nil {
		return nil, err
	}
	probe, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, err
	}
	drv := probe.Driver()
	probe.Close()
	return sql.OpenDB(&tenantDBConnector{drv: drv, dsn: dsn, want: want}), nil
}

// openForeignBackupDir opens an instance's existing .benmore/backups through
// directory handles (treeDir): every component must be a real directory of
// the one above it, never a link. Used where a foreignAppDirs process lists
// or prunes snapshots, so a tenant cannot point its backups at another app's.
func openForeignBackupDir(dir string) (*treeDir, error) {
	cur, err := openTreeDir(dir)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(backupDirName, "/") {
		next, err := cur.openDir(part)
		cur.Close()
		if err != nil {
			return nil, err
		}
		cur = next
	}
	return cur, nil
}

// foreignDirBackupDatabase snapshots an instance's data.db into that
// instance's .benmore/backups for the tenant file helper's backup-local (the
// pre-deploy snapshot), its only caller: the helper runs as the app's user
// but keeps the foreignAppDirs paths. The source is opened as openTenantDB
// opens it, and the snapshot reaches the backup directory through directory
// handles (treeDir), so neither a linked data.db nor a linked .benmore or
// backups directory can make it read or write another app's files. The
// router never snapshots an app itself (backupDatabase refuses in a
// foreignAppDirs process).
func foreignDirBackupDatabase(dir string) (string, error) {
	path, err := foreignDirBackup(dir)
	if err != nil || path == "" {
		return "", err
	}
	log.Printf("  backup: %s", path)
	return path, nil
}

func foreignDirBackup(dir string) (string, error) {
	dbPath := filepath.Join(dir, "data.db")
	info, err := os.Lstat(dbPath)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil // no database to back up
	}
	if err != nil {
		return "", fmt.Errorf("inspect database: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errTenantDBRedirected
	}
	stage, err := os.MkdirTemp("", "benmore-predeploy-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(stage)
	snapshot := filepath.Join(stage, "snapshot.db")
	src, err := openTenantDB("sqlite3", dbPath, dbPath+"?mode=ro")
	if err != nil {
		return "", err
	}
	_, err = src.Exec("VACUUM INTO ?", snapshot)
	if err = errors.Join(err, src.Close()); err != nil {
		return "", fmt.Errorf("vacuum into backup: %w", err)
	}
	in, err := os.Open(snapshot)
	if err != nil {
		return "", err
	}
	defer in.Close()

	top, err := openTreeDir(dir)
	if err != nil {
		return "", err
	}
	defer top.Close()
	// Under the tenant-data lock (tenant_data_lock_marker.go) the snapshot and
	// a backups directory made here are the app account's alone; .benmore
	// itself keeps the group mode (the router reads its env and secret).
	locked := tenantDataLockedFor(dir)
	fileMode := os.FileMode(backupPermission)
	if locked {
		fileMode = 0o600
	}
	backups := top
	parts := strings.Split(backupDirName, "/")
	for i, part := range parts {
		dirMode := backupDirMode
		if locked && i == len(parts)-1 {
			dirMode = 0o700
		}
		created := false
		if _, err := backups.lstat(part); errors.Is(err, fs.ErrNotExist) {
			if err := backups.root.Mkdir(part, dirMode.Perm()); err != nil && !errors.Is(err, fs.ErrExist) {
				return "", fmt.Errorf("create backup dir: %w", err)
			}
			created = true
		}
		next, err := backups.openDir(part)
		if backups != top {
			backups.Close()
		}
		if err != nil {
			return "", fmt.Errorf("backup dir: %w", err)
		}
		backups = next
		if created {
			// The app's own process must be able to write here too; set the
			// mode on the directory just opened, not on its name.
			if handle, err := backups.root.Open("."); err == nil {
				err = handle.Chmod(dirMode)
				handle.Close()
				if err != nil {
					backups.Close()
					return "", fmt.Errorf("set backup dir permissions: %w", err)
				}
			}
		}
	}
	if backups != top {
		defer backups.Close()
	}
	name := backupPrefix + time.Now().UTC().Format("20060102T150405Z")
	out, final := (*os.File)(nil), ""
	for n := 0; out == nil; n++ {
		final = name + ".db"
		if n > 0 {
			final = fmt.Sprintf("%s-%d-%d.db", name, os.Getpid(), n)
		}
		out, err = backups.root.OpenFile(final, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
		if err != nil && (!errors.Is(err, fs.ErrExist) || n > 100) {
			return "", fmt.Errorf("create backup: %w", err)
		}
	}
	_, err = io.Copy(out, in)
	if err = errors.Join(err, out.Chmod(fileMode), out.Close()); err != nil {
		_ = backups.root.Remove(final)
		return "", fmt.Errorf("write backup: %w", err)
	}
	return filepath.Join(dir, backupDirName, final), nil
}
