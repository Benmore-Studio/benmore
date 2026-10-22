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

// foreignAppDirs is set in a process that loads apps from directories owned
// by other accounts: the hosted router, which checks, backs up and queries
// every tenant's app. There an app's database is the data.db in its own
// directory and nothing else. The app's environment does not get to name
// another file (DATABASE_URL is for a process that runs one app as itself),
// and the file is opened as openTenantDB opens it.
var foreignAppDirs atomic.Bool

// openForeignAppDB is openDBWithPolicyLock for such a process. Repairing or
// restoring a damaged database is left to the app's own process, which does
// it at boot with the same code and owns the files.
func openForeignAppDB(dir string, appEnv map[string]string) (*sql.DB, error) {
	cfg := buildDBOpenConfigWithEnv(dir, "", appEnv)
	db, err := openTenantDB(cfg.DriverName, filepath.Join(dir, "data.db"), cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	applyAppDBPoolLimits(db, currentAppDBPoolLimits())
	return db, nil
}

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
// checked (tenantDBConnector).
func openTenantDB(driverName, dbPath, dsn string) (*sql.DB, error) {
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

// foreignDirBackupDatabase is backupDatabase for a process that does not own
// the directory (the router's pre-deploy snapshot and its check load): it
// snapshots an instance's data.db into that instance's .benmore/backups. The
// source is opened as openTenantDB opens it, and the snapshot reaches the
// backup directory through directory handles (treeDir), so neither a linked
// data.db nor a linked .benmore or backups directory can make the router read
// or write another app's files.
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
	backups := top
	for _, part := range strings.Split(backupDirName, "/") {
		created := false
		if _, err := backups.lstat(part); errors.Is(err, fs.ErrNotExist) {
			if err := backups.root.Mkdir(part, backupDirMode.Perm()); err != nil && !errors.Is(err, fs.ErrExist) {
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
				err = handle.Chmod(backupDirMode)
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
		out, err = backups.root.OpenFile(final, os.O_WRONLY|os.O_CREATE|os.O_EXCL, backupPermission)
		if err != nil && (!errors.Is(err, fs.ErrExist) || n > 100) {
			return "", fmt.Errorf("create backup: %w", err)
		}
	}
	_, err = io.Copy(out, in)
	if err = errors.Join(err, out.Chmod(backupPermission), out.Close()); err != nil {
		_ = backups.root.Remove(final)
		return "", fmt.Errorf("write backup: %w", err)
	}
	return filepath.Join(dir, backupDirName, final), nil
}
