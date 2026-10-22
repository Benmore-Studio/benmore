//go:build !cli

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// prepareRestoreSnapshot never mutates the live database. Work on private copies
// of the selected backup and its WAL, then let SQLite produce one complete file.
func prepareRestoreSnapshot(ctx context.Context, dir, backup string) (string, func(), error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", nil, err
	}
	defer root.Close()
	relative, err := filepath.Rel(dir, backup)
	if err != nil || !filepath.IsLocal(relative) {
		return "", nil, fmt.Errorf("backup must be inside the app directory")
	}
	stage, err := os.MkdirTemp(dir, ".restore-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { os.RemoveAll(stage) }
	fail := func(err error) (string, func(), error) { cleanup(); return "", nil, err }
	source := filepath.Join(stage, "source.db")
	for _, suffix := range []string{"", "-wal"} {
		info, err := root.Lstat(relative + suffix)
		if suffix != "" && os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fail(err)
		}
		if !info.Mode().IsRegular() {
			return fail(fmt.Errorf("backup member is not a regular file"))
		}
		if err := copyRestoreFile(ctx, root, relative+suffix, source+suffix); err != nil {
			return fail(err)
		}
	}
	if err := validateSQLiteDB(source); err != nil {
		return fail(err)
	}
	src, err := sql.Open("sqlite3", sqliteRestoreURI(source, "rw"))
	if err != nil {
		return fail(err)
	}
	defer src.Close()
	if err := checkRestoreIntegrity(ctx, src); err != nil {
		return fail(fmt.Errorf("backup integrity: %w", err))
	}
	candidate := filepath.Join(stage, "candidate.db")
	// VACUUM INTO accepts a bound filename expression; the selected snapshot
	// may include a WAL, which SQLite folds into this standalone destination.
	if _, err := src.ExecContext(ctx, "VACUUM INTO ?", candidate); err != nil {
		return fail(fmt.Errorf("prepare restore snapshot: %w", err))
	}
	if err := os.Chmod(candidate, 0600); err != nil {
		return fail(err)
	}
	f, err := os.OpenFile(candidate, os.O_RDWR, 0)
	if err != nil {
		return fail(err)
	}
	err = errors.Join(f.Sync(), f.Close())
	if err != nil {
		return fail(err)
	}
	return candidate, cleanup, nil
}

func sqliteRestoreURI(path, mode string) string {
	return (&url.URL{Scheme: "file", Path: path, RawQuery: url.Values{"mode": {mode}, "_busy_timeout": {"1000"}}.Encode()}).String()
}

func checkRestoreIntegrity(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var verdict string
		if err := rows.Scan(&verdict); err != nil {
			return err
		}
		if verdict != "ok" {
			return fmt.Errorf("SQLite integrity check failed: %s", verdict)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("SQLite returned no complete integrity verdict")
	}
	return nil
}

func copyRestoreFile(ctx context.Context, root *os.Root, src, dest string) error {
	in, err := root.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("restore source is not regular")
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, &restoreContextReader{ctx: ctx, r: in})
	return errors.Join(copyErr, out.Sync(), out.Close())
}

type restoreContextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *restoreContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

// installRestoreSnapshot requires stopped writers and drained DB pools. It keeps
// the original main/WAL/SHM bundle for recovery and never truncates the live file.
// On a pre-install failure, attempt to put every moved original member back.
func installRestoreSnapshot(dir, candidate string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	release, lease, err := beginAppMCPRestorePolicy(ctx, dir)
	if err != nil {
		return "", fmt.Errorf("connector restore lease: %w", err)
	}
	defer release()
	return installRestoreSnapshotWithLease(dir, candidate, lease)
}

func installRestoreSnapshotWithLease(dir, candidate string, lease *appMCPAuthorityLease) (string, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	for _, rel := range []string{".benmore", backupDirName} {
		if err := root.Mkdir(rel, 0700); err != nil && !os.IsExist(err) {
			return "", err
		}
		info, err := root.Lstat(rel)
		if err != nil {
			return "", err
		}
		if !info.IsDir() {
			return "", fmt.Errorf("backup directory crosses a non-directory or symlink")
		}
	}
	bundleRel := filepath.Join(backupDirName, "before-restore-"+time.Now().UTC().Format("20060102T150405Z")+"-"+generateToken(8))
	if err := root.Mkdir(bundleRel, 0700); err != nil {
		return "", err
	}
	originalRel := filepath.Join(bundleRel, "data.db")
	original := filepath.Join(dir, originalRel)
	live := filepath.Join(dir, "data.db")
	var moved []string
	rollback := func(cause error) (string, error) {
		for i := len(moved) - 1; i >= 0; i-- {
			suffix := moved[i]
			if err := root.Rename(originalRel+suffix, "data.db"+suffix); err != nil {
				cause = errors.Join(cause, fmt.Errorf("recover original from %s: %w", original+suffix, err))
			}
		}
		return original, cause
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := root.Lstat("data.db" + suffix)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return rollback(err)
		}
		if !info.Mode().IsRegular() {
			return rollback(fmt.Errorf("live database member is not regular: %s", suffix))
		}
		if err := root.Rename("data.db"+suffix, originalRel+suffix); err != nil {
			return rollback(err)
		}
		moved = append(moved, suffix)
	}
	candidateRel, err := filepath.Rel(dir, candidate)
	if err != nil || !filepath.IsLocal(candidateRel) {
		return rollback(fmt.Errorf("restore candidate escaped app directory"))
	}
	if err := root.Rename(candidateRel, "data.db"); err != nil {
		return rollback(fmt.Errorf("install restored database: %w", err))
	}
	notifyDBFileReplaced(live)
	return original, nil
}
