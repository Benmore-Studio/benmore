//go:build !cli

package main

// The startup quick_check and the clean-shutdown marker.
//
// openDBWithPolicyLock runs PRAGMA quick_check before an app uses its
// database, because page-level corruption passes Ping and only detonates when
// a later step walks the bad page (that crash-looped units before the check
// existed). quick_check reads every page: 55.7s of a 778 MB app's boot. It is
// skipped only when the process that last served this exact file shut down
// cleanly and nothing has touched the file since:
//
//   - The serving process writes .benmore/db-clean-shutdown.json after its
//     connection pool is closed on a graceful stop (App.Shutdown), and only
//     when: its own open was verified (the check ran and passed, or a marker
//     vouched for the file); data.db is still the file it opened (device and
//     inode); SQLite logged no corruption or I/O error during the run
//     (db_fault_log.go: corruption is always logged, some I/O errors are not);
//     background jobs drained in time and no connection is still open; the
//     WAL is empty or gone and no rollback journal is left, so the main file
//     alone holds every committed page.
//     SQLite has already synced that file: a checkpoint ends with an fsync of
//     the database at the synchronous levels the app DSN allows (NORMAL, FULL,
//     EXTRA), and the marker is synced before it is renamed into place.
//   - The marker records the file's device, inode, size, mtime and ctime,
//     read with stat (the file is never opened: closing a descriptor drops
//     every POSIX lock this process holds on it, a lingering SQLite
//     connection's included). Timestamps come from a coarse clock, so the
//     stamp is taken only once the file has been unchanged for
//     cleanShutdownSettle (fileStampSettle): a later write then always moves
//     mtime and ctime.
//   - The next open reads the marker and REMOVES it before SQLite opens the
//     file, then trusts it only if all of that still matches and the WAL and
//     journal are still empty. A crash, kill -9, OOM kill or power loss leaves
//     no marker (the one this run consumed is gone); a restored, replaced or
//     copied file has another inode or device, and the framework's restore and
//     recovery paths delete the marker anyway; a write by any process changes
//     the size or the timestamps, or leaves WAL frames; a marker copied in from
//     another app names another file.
//   - A marker vouches for a file for at most cleanShutdownRecheckAfter (plus
//     a per-file jitter) after its last real check, so corruption that arises
//     in a file that keeps restarting cleanly is still found within days.
//
// Anything that cannot be proven (no marker, an unreadable or stale one, a
// platform without inode/ctime, a remote DATABASE_URL) runs the check, and a
// failing check keeps the REINDEX-then-restore recovery.

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const (
	cleanShutdownMarkerName    = "db-clean-shutdown.json"
	cleanShutdownMarkerVersion = 2
	// cleanShutdownRecheckAfter bounds how long clean restarts may skip the
	// startup quick_check (and the ledger the integrity_check, see
	// db_integrity_ledger.go); cleanShutdownRecheckJitter spreads the re-checks
	// of apps that were all verified by the same fleet release.
	cleanShutdownRecheckAfter  = 7 * 24 * time.Hour
	cleanShutdownRecheckJitter = 72 * time.Hour
)

// cleanShutdownSettle is how long data.db must have been unchanged before its
// stamp is taken (fileStampSettle). A variable so tests can shorten it; it
// must stay well above the filesystem's timestamp granularity.
var cleanShutdownSettle = fileStampSettle

// startupQuickCheck is the open-time structural check. A variable so tests can
// count the runs.
var startupQuickCheck = sqliteQuickCheck

// serveBootCheckActive is set while serve's boot check (serveBootCheck) runs
// its validation load, immediately before the start-up load in the same
// process: that load hands its verification (a marker) and its pre-migrate
// snapshot (serveBootCheckSnapshot) to the start-up load.
var serveBootCheckActive atomic.Bool

// serveBootHandoffMinBytes is the database size from which serve's boot check
// waits (up to cleanShutdownSettle) to hand a marker to the start-up load;
// a smaller file is quicker to check than to wait for. A variable for tests.
var serveBootHandoffMinBytes int64 = 256 << 20

func dbFileSize(dir string) int64 {
	info, err := os.Lstat(filepath.Join(dir, "data.db"))
	if err != nil {
		return 0
	}
	return info.Size()
}

// serveBootCheckSnapshot carries the first pre-migrate snapshot serve's boot
// check took to the start-up load of the same directory, which restores it if
// its own integrity_check fails.
var serveBootCheckSnapshot struct {
	sync.Mutex
	dir, path string
}

func handOffServeBootCheckSnapshot(dir, path string) {
	serveBootCheckSnapshot.Lock()
	serveBootCheckSnapshot.dir, serveBootCheckSnapshot.path = dir, path
	serveBootCheckSnapshot.Unlock()
}

// takeServeBootCheckSnapshot returns (once) the snapshot the boot check took
// for dir.
func takeServeBootCheckSnapshot(dir string) string {
	serveBootCheckSnapshot.Lock()
	defer serveBootCheckSnapshot.Unlock()
	path := ""
	if serveBootCheckSnapshot.dir == dir {
		path = serveBootCheckSnapshot.path
	}
	serveBootCheckSnapshot.dir, serveBootCheckSnapshot.path = "", ""
	return path
}

// dbFileIdentity pins one on-disk state of data.db.
type dbFileIdentity struct {
	Dev     uint64 `json:"dev"`
	Ino     uint64 `json:"ino"`
	Size    int64  `json:"size"`
	MtimeNS int64  `json:"mtime_ns"`
	CtimeNS int64  `json:"ctime_ns"`
}

// latestChange is the later of the file's mtime and ctime.
func (id dbFileIdentity) latestChange() time.Time {
	if id.CtimeNS > id.MtimeNS {
		return time.Unix(0, id.CtimeNS)
	}
	return time.Unix(0, id.MtimeNS)
}

type cleanShutdownMarker struct {
	Version    int            `json:"version"`
	Path       string         `json:"path"`
	File       dbFileIdentity `json:"file"`
	VerifiedAt time.Time      `json:"verified_at"`
	StampedAt  time.Time      `json:"stamped_at"`
}

func cleanShutdownMarkerPath(dir string) string {
	return filepath.Join(dir, ".benmore", cleanShutdownMarkerName)
}

// readDBFileIdentity stats path without following a link and without opening
// it.
func readDBFileIdentity(path string) (dbFileIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return dbFileIdentity{}, err
	}
	if !info.Mode().IsRegular() {
		return dbFileIdentity{}, fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	ctime, ino, dev, ok := fileStampSys(info)
	if !ok {
		return dbFileIdentity{}, errors.New("file identity (inode, ctime) is not available on this platform")
	}
	return dbFileIdentity{Dev: dev, Ino: ino, Size: info.Size(), MtimeNS: info.ModTime().UnixNano(), CtimeNS: ctime}, nil
}

// dbSidecarsEmpty reports why the main file alone may not hold every committed
// page: WAL frames not yet checkpointed, or a hot rollback journal.
func dbSidecarsEmpty(dbPath string) error {
	for _, suffix := range []string{"-wal", "-journal"} {
		info, err := os.Lstat(dbPath + suffix)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() != 0 {
			return fmt.Errorf("data.db%s holds %d bytes", suffix, info.Size())
		}
	}
	return nil
}

// cleanShutdownCheckDue is when a file last verified at verifiedAt must be
// checked again even after clean restarts. The jitter is fixed per file.
func cleanShutdownCheckDue(verifiedAt time.Time, dev, ino uint64) time.Time {
	h := fnv.New64a()
	var b [16]byte
	binary.LittleEndian.PutUint64(b[:8], dev)
	binary.LittleEndian.PutUint64(b[8:], ino)
	h.Write(b[:])
	jitter := time.Duration(h.Sum64() % uint64(cleanShutdownRecheckJitter))
	return verifiedAt.Add(cleanShutdownRecheckAfter + jitter)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// consumeCleanShutdownMarker removes dir's marker and returns when the file
// it vouches for last passed a full check, or a reason it vouches for nothing.
// It runs before SQLite opens the database, so nothing has written to it yet.
func consumeCleanShutdownMarker(dir, dbPath string, now time.Time) (time.Time, string) {
	markerPath := cleanShutdownMarkerPath(dir)
	info, err := os.Lstat(markerPath)
	if errors.Is(err, fs.ErrNotExist) {
		return time.Time{}, "no clean-shutdown marker"
	}
	var data []byte
	if err == nil && info.Mode().IsRegular() && info.Size() <= 4096 {
		data, err = os.ReadFile(markerPath)
	} else if err == nil {
		err = errors.New("not a small regular file")
	}
	// Whatever it says, a marker is spent once an open has seen it. If it
	// cannot be removed for good it could later vouch for a run that crashed.
	if rmErr := os.Remove(markerPath); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
		return time.Time{}, "clean-shutdown marker could not be removed: " + rmErr.Error()
	}
	if syncErr := syncDir(filepath.Dir(markerPath)); syncErr != nil {
		return time.Time{}, "clean-shutdown marker removal is not durable: " + syncErr.Error()
	}
	if err != nil {
		return time.Time{}, "clean-shutdown marker unreadable: " + err.Error()
	}
	var marker cleanShutdownMarker
	if err := json.Unmarshal(data, &marker); err != nil || marker.Version != cleanShutdownMarkerVersion {
		return time.Time{}, "clean-shutdown marker malformed"
	}
	canonical, err := canonicalTenantDBPath(dbPath)
	if err != nil || marker.Path != canonical {
		return time.Time{}, "clean-shutdown marker names another database"
	}
	current, err := readDBFileIdentity(dbPath)
	if err != nil {
		return time.Time{}, "database identity unavailable: " + err.Error()
	}
	if current != marker.File {
		return time.Time{}, "database file changed since the clean shutdown"
	}
	// The stamp is only as good as the timestamps were settled when it was taken.
	if marker.StampedAt.Sub(current.latestChange()) < cleanShutdownSettle {
		return time.Time{}, "clean-shutdown stamp taken too soon after the last write"
	}
	if err := dbSidecarsEmpty(dbPath); err != nil {
		return time.Time{}, err.Error()
	}
	if marker.VerifiedAt.IsZero() || marker.VerifiedAt.After(now.Add(5*time.Minute)) {
		return time.Time{}, "clean-shutdown marker has no usable check time"
	}
	if !now.Before(cleanShutdownCheckDue(marker.VerifiedAt, current.Dev, current.Ino)) {
		return time.Time{}, "periodic re-check (last full check " + marker.VerifiedAt.UTC().Format(time.RFC3339) + ")"
	}
	return marker.VerifiedAt, ""
}

// leaveCleanShutdownMarker runs after the app's pool was closed (closeErr is
// what Close returned). It writes the marker only for a load that serves the
// database (markCleanOnClose), after a clean close with nothing still using
// the file. waitToSettle lets it wait (up to cleanShutdownSettle) for data.db's
// timestamps to settle; without it a file written moments ago gets no marker.
func (app *App) leaveCleanShutdownMarker(closeErr error, waitToSettle bool) {
	if !app.markCleanOnClose {
		return
	}
	reason := ""
	switch {
	case closeErr != nil:
		reason = "closing failed: " + closeErr.Error()
	case app.jobDrainTimedOut:
		reason = "a background job was still running when the database closed"
	case app.DB != nil && app.DB.Stats().OpenConnections > 0:
		reason = fmt.Sprintf("%d connection(s) still open after close", app.DB.Stats().OpenConnections)
	default:
		if code, ok := sqliteFaultSeen(); !ok {
			reason = "SQLite error reporting is unavailable"
		} else if code != 0 {
			reason = fmt.Sprintf("SQLite reported a corruption or I/O error (code %d) during this run", code)
		}
	}
	if reason == "" {
		if err := writeCleanShutdownMarker(app.Dir, app.dbVerifiedAt, app.dbOpened, waitToSettle); err != nil {
			reason = err.Error()
		}
	}
	if reason != "" {
		log.Printf("  database: no clean-shutdown marker (%s); the next start runs quick_check", reason)
		return
	}
	log.Printf("  database: closed cleanly; the next start may skip quick_check")
}

// writeCleanShutdownMarker records that the database in dir was closed cleanly
// by a process whose open had verified it at verifiedAt. opened is the device
// and inode of the file that process opened: a marker vouches only for that
// file, never for one swapped in under the running process. Call it only after
// that process's pool is closed.
func writeCleanShutdownMarker(dir string, verifiedAt time.Time, opened dbFileIdentity, waitToSettle bool) error {
	if verifiedAt.IsZero() {
		return errors.New("this process never verified the database")
	}
	if foreignAppDirs.Load() {
		// The router does not serve tenant databases and does not write into
		// directories a tenant controls.
		return errors.New("not written by a process that does not own the app directory")
	}
	dbPath := filepath.Join(dir, "data.db")
	if err := dbSidecarsEmpty(dbPath); err != nil {
		return err
	}
	ident, err := readDBFileIdentity(dbPath)
	if err != nil {
		return err
	}
	if opened.Dev == 0 && opened.Ino == 0 {
		return errors.New("the file this process opened is unknown")
	}
	if ident.Dev != opened.Dev || ident.Ino != opened.Ino {
		return errors.New("data.db was replaced while this process had it open")
	}
	if wait := cleanShutdownSettle - time.Since(ident.latestChange()); wait > 0 {
		if !waitToSettle {
			return errors.New("data.db was written moments ago")
		}
		time.Sleep(wait + 10*time.Millisecond)
		settled, err := readDBFileIdentity(dbPath)
		if err != nil {
			return err
		}
		if settled != ident {
			return errors.New("data.db changed while its timestamps settled")
		}
	}
	stampedAt := time.Now()
	if stampedAt.Sub(ident.latestChange()) < cleanShutdownSettle {
		return errors.New("data.db timestamps did not settle")
	}
	canonical, err := canonicalTenantDBPath(dbPath)
	if err != nil {
		return err
	}
	data, err := json.Marshal(cleanShutdownMarker{
		Version:    cleanShutdownMarkerVersion,
		Path:       canonical,
		File:       ident,
		VerifiedAt: verifiedAt.UTC(),
		StampedAt:  stampedAt.UTC(),
	})
	if err != nil {
		return err
	}
	stateDir := filepath.Join(dir, ".benmore")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(stateDir, ".db-clean-shutdown-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	markerPath := cleanShutdownMarkerPath(dir)
	if err == nil {
		err = os.Rename(tmpName, markerPath)
	}
	if err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := syncDir(stateDir); err != nil {
		os.Remove(markerPath)
		return err
	}
	// A writer that slipped in between the stat and the rename makes the marker
	// stale: take it back.
	if after, err := readDBFileIdentity(dbPath); err != nil || after != ident || dbSidecarsEmpty(dbPath) != nil {
		os.Remove(markerPath)
		return errors.New("the database changed while the marker was written")
	}
	return nil
}

// dbStateFileNames are the .benmore files that describe one data.db: what
// vouches for it at the next open, its last passing integrity_check, the build
// and storage configuration its last snapshot covered, and a refused
// auto-recovery (db_recovery_refusal.go).
var dbStateFileNames = []string{cleanShutdownMarkerName, integrityLedgerName, dbBootStateName, recoveryRefusedName}

// forgetDatabaseStateFiles deletes them. Every framework path that swaps
// another file in as data.db (restore, PITR, refresh-dev, auto-recovery)
// calls it before the swap: device and inode numbers are reused, so a record
// must never outlive the file it describes. It resolves .benmore inside dir
// without following a link out of it, so the router can run it in a tenant's
// directory.
func forgetDatabaseStateFiles(dir string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	var errs []error
	for _, name := range dbStateFileNames {
		if err := root.Remove(filepath.Join(".benmore", name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
