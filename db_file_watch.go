//go:build !cli

package main

// Database file watch: a served app notices its data.db replaced or deleted
// while it runs.
//
// Why. The router tenant-data lock stops the router reading an app's
// database, but each instance directory stays group-writable by the router
// for deploys, so the router (or anything else with that access) can still
// rename or delete data.db. Nothing would notice: the app's open connections
// keep working on the old file while new ones open whatever now sits at the
// path, or create an empty database there. This makes it loud instead.
//
// What. Every dbFileWatchInterval one Lstat of data.db is compared with the
// device and inode the app's pool opened (App.dbOpened, which openDBChecked
// records after any boot-time recovery swap). A missing file reports
// "deleted"; another inode, a symbolic link or a non-regular file reports
// "replaced"; any other Lstat failure (the directory lost its search
// permission, say) reports "unverifiable". The watcher also holds one
// read-only descriptor of the opened file for as long as the app serves:
// while it is open the inode cannot be freed, so a deleted file can never be
// followed by a new one that reuses its inode number and passes the check,
// and the original stays readable at /proc/<pid>/fd/<n> for the runbook's
// recovery. That descriptor is closed only after the pool is: closing any
// descriptor of a file drops every POSIX lock the process holds on it,
// SQLite's included.
//
// On a mismatch the watcher logs one line starting "SECURITY ALERT: database
// file <state>" with the app, the opened and current device:inode and the
// time; again when the state or the file at the path changes, and otherwise
// as a reminder at most hourly. /health gets a db_file check and overall
// status "degraded" (runtime-change verification still counts that as up,
// runtimeServing), and a hosted app adds X-Benmore-DB-File to its /health
// answers so the router can relay the alert to the log that reaches a person
// (router_db_file_alert.go). Nothing else happens: no restart (it would drop
// the descriptors that are the only copy of a deleted database) and no
// refused writes (every request would fail on a false alarm, and the path
// cannot tell the original from an impostor).
//
// The framework's own replacements never meet a running watcher. Boot-time
// auto-recovery swaps the file before the pool opens the one the watcher arms
// from; a post-migration restore fails the load; restores and refresh-dev stop
// the unit before the tenant helper installs the file, and the next process
// arms from what it opens; `benmore db rollback` expects the app stopped. A
// swap under a running pool would leave that pool on the old file, which is
// exactly what this reports, so there is deliberately no way to disarm it.
//
// It runs only in `benmore serve` (StartServer). Tests that build a mux,
// `benmore check`, validation loads, the tenant helper, the router and
// `benmore host` never start it.

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	dbFileOK           = "ok"
	dbFileReplaced     = "replaced"
	dbFileDeleted      = "deleted"
	dbFileUnverifiable = "unverifiable"

	// dbFileAlertPrefix starts every alert line, in the app's journal and in
	// the router's relay; the CloudWatch metric filter matches it.
	dbFileAlertPrefix = "SECURITY ALERT: database file"
	// dbFileAlertHeader carries a non-ok state on a hosted app's /health
	// answer to the router, which strips it from what it forwards.
	dbFileAlertHeader = "X-Benmore-DB-File"
)

var (
	// dbFileWatchInterval spaces the checks; variables so tests can shorten them.
	dbFileWatchInterval = 30 * time.Second
	// dbFileAlertReminder is the most often an unchanged alert is logged again.
	dbFileAlertReminder = time.Hour
)

// dbFileAlertState reports whether s is one of the alert states.
func dbFileAlertState(s string) bool {
	return s == dbFileReplaced || s == dbFileDeleted || s == dbFileUnverifiable
}

// dbFileReport is the health check's db_file entry.
type dbFileReport struct {
	State   string `json:"status"` // ok | replaced | deleted | unverifiable
	Opened  string `json:"opened"` // device:inode the pool opened
	Current string `json:"current,omitempty"`
	Reason  string `json:"reason,omitempty"`
	// Since is when the current state began; LastAlert keeps the last alert
	// of this process after the path holds the opened file again.
	Since     time.Time `json:"since,omitzero"`
	LastAlert time.Time `json:"last_alert,omitzero"`
	CheckedAt time.Time `json:"checked_at,omitzero"`
}

type dbFileWatcher struct {
	app    string // the app directory's name, for log lines
	path   string
	opened dbFileIdentity
	held   *os.File
	now    func() time.Time
	logf   func(format string, args ...any)

	mu         sync.Mutex
	report     dbFileReport
	alertKey   string // state, file and reason of the last alert line, "" after ok
	lastLogged time.Time

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
	started  bool // run was started (startDBFileWatch)
}

func devIno(dev, ino uint64) string { return fmt.Sprintf("%d:%d", dev, ino) }

// newDBFileWatcher arms a watcher for path against the file opened, holding a
// descriptor of whatever path names now (normally that same file).
func newDBFileWatcher(app, path string, opened dbFileIdentity) *dbFileWatcher {
	w := &dbFileWatcher{
		app: app, path: path, opened: opened,
		now: time.Now, logf: log.Printf,
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	// Never closed while the pool is open, even if it names another file:
	// the pool may have connections on that one too (see above).
	if f, err := os.Open(path); err == nil {
		w.held = f
	}
	w.report = dbFileReport{State: dbFileOK, Opened: devIno(opened.Dev, opened.Ino)}
	return w
}

// check compares the path with the opened file once and records the result.
func (w *dbFileWatcher) check() dbFileReport {
	rep := dbFileReport{Opened: devIno(w.opened.Dev, w.opened.Ino), CheckedAt: w.now().UTC()}
	info, err := os.Lstat(w.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		rep.State, rep.Reason = dbFileDeleted, "no file at the path"
	case err != nil:
		rep.State, rep.Reason = dbFileUnverifiable, err.Error()
	default:
		_, ino, dev, ok := fileStampSys(info)
		if ok {
			rep.Current = devIno(dev, ino)
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			rep.State, rep.Reason = dbFileReplaced, "a symbolic link is at the path"
		case !info.Mode().IsRegular():
			rep.State, rep.Reason = dbFileReplaced, "not a regular file ("+info.Mode().Type().String()+")"
		case !ok:
			rep.State, rep.Reason = dbFileUnverifiable, "file identity is not available"
		case dev == w.opened.Dev && ino == w.opened.Ino:
			rep.State = dbFileOK
		default:
			rep.State, rep.Reason = dbFileReplaced, "another file is at the path"
		}
	}
	return w.record(rep)
}

// record keeps rep as the current report and logs what changed.
func (w *dbFileWatcher) record(rep dbFileReport) dbFileReport {
	w.mu.Lock()
	defer w.mu.Unlock()
	prev := w.report
	rep.LastAlert = prev.LastAlert
	rep.Since = rep.CheckedAt
	if prev.State == rep.State && prev.Current == rep.Current && prev.Reason == rep.Reason && !prev.Since.IsZero() {
		rep.Since = prev.Since
	}
	at := rep.CheckedAt.Format(time.RFC3339)
	if rep.State == dbFileOK {
		if prev.State != dbFileOK {
			w.logf("database file check: app %s: data.db is again the file this process opened (%s) at %s; the earlier alert still needs checking", w.app, rep.Opened, at)
		}
		w.alertKey = ""
		w.report = rep
		return rep
	}
	// The reason is part of what changed: a freed inode number can come back
	// as a different kind of file (a symlink replaced by a directory).
	key := rep.State + " " + rep.Current + " " + rep.Reason
	if key != w.alertKey || rep.CheckedAt.Sub(w.lastLogged) >= dbFileAlertReminder {
		what := "data.db is not the file this process opened"
		switch rep.State {
		case dbFileDeleted:
			what = "data.db is gone"
		case dbFileUnverifiable:
			what = "data.db cannot be checked"
		}
		current := rep.Current
		if current == "" {
			current = "none"
		}
		reminder := ""
		if key == w.alertKey {
			reminder = " (still, since " + rep.Since.Format(time.RFC3339) + ")"
		}
		w.logf("%s %s%s: app %s: %s (opened %s, now %s: %s) at %s; the app keeps serving its open connections. Do not restart it before saving the original: see the release runbook, \"Database file replaced or deleted\"",
			dbFileAlertPrefix, rep.State, reminder, w.app, what, rep.Opened, current, rep.Reason, at)
		w.alertKey, w.lastLogged = key, rep.CheckedAt
		rep.LastAlert = rep.CheckedAt
	}
	w.report = rep
	return rep
}

// current returns the last report.
func (w *dbFileWatcher) current() dbFileReport {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.report
}

func (w *dbFileWatcher) run(interval time.Duration) {
	defer close(w.done)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-t.C:
			w.check()
		}
	}
}

// halt stops the checks. The held descriptor stays open (closeHeld).
func (w *dbFileWatcher) halt() {
	w.stopOnce.Do(func() { close(w.stop) })
}

// closeHeld closes the held descriptor; only after the app's pool is closed.
func (w *dbFileWatcher) closeHeld() {
	if w.held != nil {
		w.held.Close()
		w.held = nil
	}
}

// startDBFileWatch starts the watch for a served app's own local data.db. The
// only caller is StartServer.
func startDBFileWatch(app *App) {
	if app == nil || app.dbFileWatch != nil {
		return
	}
	if !app.dbLocalSQLite || (app.dbOpened.Dev == 0 && app.dbOpened.Ino == 0) {
		log.Printf("  database file watch: off (no local database file identity on this platform or backend)")
		return
	}
	w := newDBFileWatcher(filepath.Base(app.Dir), filepath.Join(app.Dir, "data.db"), app.dbOpened)
	app.dbFileWatch = w
	first := w.check() // a file replaced during the boot is reported at once
	interval := dbFileWatchInterval
	w.started = true
	safeGo("db-file-watch", func() { w.run(interval) })
	log.Printf("  database file watch: checking data.db (opened %s, %s) every %s", first.Opened, first.State, interval)
}

// stopDBFileWatch ends the watch; App.Shutdown calls it after the pool closed.
func (app *App) stopDBFileWatch() {
	if w := app.dbFileWatch; w != nil {
		w.halt()
		if w.started {
			<-w.done
		}
		w.closeHeld()
	}
}

// dbFileHealth is the health check's db_file entry, present while the watch runs.
func dbFileHealth(app *App) (dbFileReport, bool) {
	if app == nil || app.dbFileWatch == nil {
		return dbFileReport{}, false
	}
	return app.dbFileWatch.current(), true
}
