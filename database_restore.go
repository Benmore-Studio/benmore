//go:build !cli

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"time"
)

// restoreStageLeftoverAge is how long a stage must have gone unchanged before
// an app start removes it. A start cannot see the router's lifecycle slot, and
// the app can restart while a restore or refresh-dev is still preparing; each
// of their steps is bounded at 31 minutes (restoreHelperTimeout) and every
// step that uses a stage follows the one that last wrote it, so a stage
// nothing has touched for this long belongs to no running operation.
const restoreStageLeftoverAge = 2 * time.Hour

// newRestoreStage makes an empty stage directory .benmore/.<kind>-<id> in dir
// and returns its path and its slash name relative to dir. .benmore is
// resolved through an os.Root on dir: a link there is refused, not followed.
func newRestoreStage(dir, kind string) (string, string, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", "", err
	}
	defer root.Close()
	if err := root.Mkdir(restoreStageParent, 0700); err != nil && !os.IsExist(err) {
		return "", "", err
	}
	if info, err := root.Lstat(restoreStageParent); err != nil || !info.IsDir() {
		return "", "", fmt.Errorf("app metadata directory must be a directory, not a link")
	}
	rel := restoreStageParent + "/." + kind + "-" + generateToken(8)
	if err := root.Mkdir(rel, 0700); err != nil {
		return "", "", err
	}
	return filepath.Join(dir, filepath.FromSlash(rel)), rel, nil
}

// removeRestoreStages removes the stage directories in dir, in .benmore and at
// the top of the directory (where older releases made them), and returns the
// ones it removed. keep, a restoreStageRel name, is left alone: the PITR
// replay a restore is about to read. With unchangedFor > 0 a stage whose
// directory or members changed more recently is left too.
//
// Only a real directory is removed, never a link or a file that has a stage's
// name, and one at the top of the directory only when it holds nothing but
// database copies: that is the app's source tree, and a directory there that
// holds anything else is the app's own.
func removeRestoreStages(dir, keep string, unchangedFor time.Duration) ([]string, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	var removed []string
	var errs []error
	for _, parent := range []string{".", restoreStageParent} {
		if info, err := root.Lstat(parent); err != nil || !info.IsDir() {
			continue
		}
		names, err := readRestoreStageDir(root, parent)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, entry := range names {
			rel := path.Join(parent, entry.Name())
			if stage, _ := restoreStageRel(rel); stage != rel || rel == keep {
				continue
			}
			leftover, err := restoreStageLeftover(root, rel, parent == ".", unchangedFor)
			if err == nil && leftover {
				if err = root.RemoveAll(rel); err == nil {
					removed = append(removed, rel)
				}
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", rel, err))
			}
		}
	}
	return removed, errors.Join(errs...)
}

func readRestoreStageDir(root *os.Root, rel string) ([]os.DirEntry, error) {
	f, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.ReadDir(-1)
}

// restoreStageLeftover reports whether the stage at rel may be removed (see
// removeRestoreStages).
func restoreStageLeftover(root *os.Root, rel string, topLevel bool, unchangedFor time.Duration) (bool, error) {
	info, err := root.Lstat(rel)
	if err != nil || !info.IsDir() {
		return false, nil
	}
	members, err := readRestoreStageDir(root, rel)
	if err != nil {
		return false, err
	}
	changed := info.ModTime()
	for _, member := range members {
		if topLevel && (!member.Type().IsRegular() || !restoreStageMember(member.Name())) {
			return false, nil
		}
		if unchangedFor <= 0 {
			continue
		}
		mi, err := member.Info()
		if err != nil {
			// A member that went away while it was read: the stage is in use.
			return false, nil
		}
		if mi.ModTime().After(changed) {
			changed = mi.ModTime()
		}
	}
	return unchangedFor <= 0 || time.Since(changed) >= unchangedFor, nil
}

// sweepRestoreStages is removeRestoreStages for the callers that go on either
// way: the start of a restore and an app start.
func sweepRestoreStages(dir, keep string, unchangedFor time.Duration) {
	removed, err := removeRestoreStages(dir, keep, unchangedFor)
	for _, rel := range removed {
		log.Printf("restore: %s: removed leftover stage %s", filepath.Base(dir), rel)
	}
	if err != nil {
		log.Printf("restore: %s: leftover stages not removed: %v", filepath.Base(dir), err)
	}
}

// prepareRestoreSnapshot never mutates the live database. Work on private copies
// of the selected backup and its WAL, then let SQLite produce one complete file.
// The copies are made in a stage inside .benmore (newRestoreStage), never in
// the app's source tree.
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
	stage, _, err := newRestoreStage(dir, "restore")
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
	src, err := openRestoreDB("sqlite3", source, "rw", "")
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
	bundleRel, err := createRestoreBundle(dir, nil)
	if err != nil {
		return "", err
	}
	return installRestoreSnapshotInto(dir, candidate, bundleRel)
}

// createRestoreBundle makes the empty before-restore-<id> directory the live
// database moves into. A non-nil keyRecord (a sealed key record, see
// platform_restore_key.go) is written durably as its key.json first, so the
// replaced database's key is on disk before anything changes.
func createRestoreBundle(dir string, keyRecord []byte) (string, error) {
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
	if keyRecord != nil {
		recordRel := filepath.Join(bundleRel, "key.json")
		f, err := root.OpenFile(recordRel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			_, err = f.Write(keyRecord)
			err = errors.Join(err, f.Sync(), f.Close())
		}
		if err != nil {
			root.Remove(recordRel)
			root.Remove(bundleRel)
			return "", fmt.Errorf("record the replaced database's key: %w", err)
		}
	}
	return bundleRel, nil
}

// removeRestoreBundleRecord undoes createRestoreBundle for a restore that
// installed nothing and reports whether it did. A bundle holding any database
// member (a failed install that could not move it back) keeps its record.
func removeRestoreBundleRecord(dir, bundleRel string) (bool, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return false, err
	}
	defer root.Close()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if _, err := root.Lstat(filepath.Join(bundleRel, "data.db"+suffix)); err == nil {
			return false, nil
		}
	}
	if err := root.Remove(filepath.Join(bundleRel, "key.json")); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err := root.Remove(bundleRel); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	return true, nil
}

// installRestoreSnapshotInto moves the live database members into bundleRel
// (from createRestoreBundle) and installs candidate in their place.
func installRestoreSnapshotInto(dir, candidate, bundleRel string) (string, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer root.Close()
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
	// Records about the replaced file (clean-shutdown marker, integrity and
	// boot-state records) must not describe the restored one.
	if err := forgetDatabaseStateFiles(dir); err != nil {
		return rollback(fmt.Errorf("remove the replaced database's state records: %w", err))
	}
	if err := root.Rename(candidateRel, "data.db"); err != nil {
		return rollback(fmt.Errorf("install restored database: %w", err))
	}
	notifyDBFileReplaced(live)
	return original, nil
}
