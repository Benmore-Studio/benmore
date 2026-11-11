//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// dbFileWatchFixture is a WAL-mode SQLite data.db with a watcher armed on it,
// a fake clock and captured log lines.
type dbFileWatchFixture struct {
	dir, path string
	db        *sql.DB
	w         *dbFileWatcher
	clock     time.Time
	mu        sync.Mutex
	lines     []string
}

func newDBFileWatchFixture(t *testing.T) *dbFileWatchFixture {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "data.db")
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	mustExec(t, db, "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)")
	mustExec(t, db, "INSERT INTO notes (body) VALUES ('kept')")
	dev, ino, err := dbFileDevIno(path)
	if err != nil {
		t.Skipf("file identity unavailable here: %v", err)
	}
	f := &dbFileWatchFixture{dir: dir, path: path, db: db, clock: time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)}
	f.w = newDBFileWatcher("shop", path, dbFileIdentity{Dev: dev, Ino: ino})
	f.w.now = func() time.Time { return f.clock }
	f.w.logf = func(format string, args ...any) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.lines = append(f.lines, fmt.Sprintf(format, args...))
	}
	t.Cleanup(f.w.closeHeld)
	return f
}

// take returns and forgets the lines logged so far.
func (f *dbFileWatchFixture) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.lines
	f.lines = nil
	return out
}

func (f *dbFileWatchFixture) advance(d time.Duration) { f.clock = f.clock.Add(d) }

func alertLines(lines []string) []string {
	var out []string
	for _, l := range lines {
		if strings.HasPrefix(l, dbFileAlertPrefix) {
			out = append(out, l)
		}
	}
	return out
}

func TestDBFileWatchDetectsRenameOver(t *testing.T) {
	f := newDBFileWatchFixture(t)
	if rep := f.w.check(); rep.State != dbFileOK || len(f.take()) != 0 {
		t.Fatalf("an unchanged file: %+v", rep)
	}
	// What a rename into place does: another file takes the name.
	impostor := filepath.Join(f.dir, "impostor.db")
	if err := os.WriteFile(impostor, []byte("not the app's data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(impostor, f.path); err != nil {
		t.Fatal(err)
	}
	rep := f.w.check()
	if rep.State != dbFileReplaced || rep.Current == "" || rep.Current == rep.Opened {
		t.Fatalf("rename over data.db: %+v", rep)
	}
	lines := alertLines(f.take())
	if len(lines) != 1 {
		t.Fatalf("want one alert line, got %q", lines)
	}
	for _, want := range []string{"SECURITY ALERT: database file replaced:", "app shop", "opened " + rep.Opened, "now " + rep.Current, "2026-10-26T12:00:00Z"} {
		if !strings.Contains(lines[0], want) {
			t.Fatalf("alert line lacks %q: %s", want, lines[0])
		}
	}
	// The app's own connection still sees the original, and so does the
	// descriptor the watcher holds.
	var body string
	if err := f.db.QueryRow("SELECT body FROM notes").Scan(&body); err != nil || body != "kept" {
		t.Fatalf("open connection after the rename: %q %v", body, err)
	}
	if f.w.held == nil {
		t.Fatal("the watcher holds no descriptor of the opened file")
	}
	if st, err := f.w.held.Stat(); err != nil || devInoOf(t, st) != rep.Opened {
		t.Fatalf("held descriptor: %v %v", st, err)
	}
}

func devInoOf(t *testing.T, info os.FileInfo) string {
	t.Helper()
	_, ino, dev, ok := fileStampSys(info)
	if !ok {
		t.Skip("file identity unavailable here")
	}
	return devIno(dev, ino)
}

func TestDBFileWatchDetectsDeleteAndKeepsTheOriginalReadable(t *testing.T) {
	f := newDBFileWatchFixture(t)
	mustExec(t, f.db, "PRAGMA wal_checkpoint(TRUNCATE)")
	f.w.check()
	if err := os.Remove(f.path); err != nil {
		t.Fatal(err)
	}
	rep := f.w.check()
	if rep.State != dbFileDeleted || rep.Current != "" {
		t.Fatalf("deleted data.db: %+v", rep)
	}
	lines := alertLines(f.take())
	if len(lines) != 1 || !strings.Contains(lines[0], "SECURITY ALERT: database file deleted:") || !strings.Contains(lines[0], "now none") {
		t.Fatalf("alert lines: %q", lines)
	}
	// The held descriptor is what keeps a deleted database recoverable.
	head := make([]byte, 16)
	if _, err := f.w.held.ReadAt(head, 0); err != nil || string(head) != "SQLite format 3\x00" {
		t.Fatalf("held descriptor no longer reads the original: %q %v", head, err)
	}
}

func TestDBFileWatchFlagsSymlinkAndNonRegularFile(t *testing.T) {
	f := newDBFileWatchFixture(t)
	moved := filepath.Join(f.dir, "moved.db")
	if err := os.Rename(f.path, moved); err != nil {
		t.Fatal(err)
	}
	// A link to the very file the app opened is still not the file at the path.
	if err := os.Symlink(moved, f.path); err != nil {
		t.Fatal(err)
	}
	if rep := f.w.check(); rep.State != dbFileReplaced || !strings.Contains(rep.Reason, "symbolic link") {
		t.Fatalf("symlink: %+v", rep)
	}
	if err := os.Remove(f.path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.path, 0700); err != nil {
		t.Fatal(err)
	}
	if rep := f.w.check(); rep.State != dbFileReplaced || !strings.Contains(rep.Reason, "not a regular file") {
		t.Fatalf("directory: %+v", rep)
	}
	if lines := alertLines(f.take()); len(lines) != 2 {
		t.Fatalf("each change logs once: %q", lines)
	}
}

func TestDBFileWatchUnverifiableWhenDirectoryIsShut(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	f := newDBFileWatchFixture(t)
	if err := os.Chmod(f.dir, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(f.dir, 0700)
	if rep := f.w.check(); rep.State != dbFileUnverifiable {
		t.Fatalf("unsearchable directory: %+v", rep)
	}
	if lines := alertLines(f.take()); len(lines) != 1 || !strings.Contains(lines[0], "database file unverifiable") {
		t.Fatalf("alert lines: %q", lines)
	}
}

// Ordinary database work never moves the file: writes, WAL checkpoints of
// every kind and VACUUM keep its device and inode.
func TestDBFileWatchQuietForUnchangedFileAndCheckpoints(t *testing.T) {
	f := newDBFileWatchFixture(t)
	for i := 0; i < 50; i++ {
		mustExec(t, f.db, fmt.Sprintf("INSERT INTO notes (body) VALUES ('%s')", strings.Repeat("x", 500)))
	}
	for _, stmt := range []string{"PRAGMA wal_checkpoint(PASSIVE)", "PRAGMA wal_checkpoint(FULL)", "PRAGMA wal_checkpoint(RESTART)", "PRAGMA wal_checkpoint(TRUNCATE)", "VACUUM", "PRAGMA wal_checkpoint(TRUNCATE)"} {
		mustExec(t, f.db, stmt)
		f.advance(dbFileWatchInterval)
		if rep := f.w.check(); rep.State != dbFileOK {
			t.Fatalf("after %s: %+v", stmt, rep)
		}
	}
	if lines := f.take(); len(lines) != 0 {
		t.Fatalf("an unchanged file logged: %q", lines)
	}
}

func TestDBFileWatchLogRateLimit(t *testing.T) {
	f := newDBFileWatchFixture(t)
	f.w.check()
	moved := filepath.Join(f.dir, "aside.db")
	if err := os.Rename(f.path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.path, []byte("first impostor"), 0600); err != nil {
		t.Fatal(err)
	}
	first := f.w.check()
	if n := len(alertLines(f.take())); n != 1 {
		t.Fatalf("first detection logged %d lines", n)
	}
	// The same file for most of an hour: no repeat.
	for elapsed := time.Duration(0); elapsed < dbFileAlertReminder-dbFileWatchInterval; elapsed += dbFileWatchInterval {
		f.advance(dbFileWatchInterval)
		f.w.check()
	}
	if lines := f.take(); len(lines) != 0 {
		t.Fatalf("repeated an unchanged alert within the hour: %q", lines)
	}
	f.advance(dbFileWatchInterval)
	rep := f.w.check()
	lines := alertLines(f.take())
	if len(lines) != 1 || !strings.Contains(lines[0], "(still, since 2026-10-26T12:00:00Z)") {
		t.Fatalf("hourly reminder: %q", lines)
	}
	if !rep.Since.Equal(first.Since) {
		t.Fatalf("since moved: %v -> %v", first.Since, rep.Since)
	}
	// A different file is a change: logged at once. (Created before the first
	// one goes, so it cannot reuse that file's inode number.)
	second := filepath.Join(f.dir, "second.db")
	if err := os.WriteFile(second, []byte("second impostor"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(second, f.path); err != nil {
		t.Fatal(err)
	}
	f.advance(dbFileWatchInterval)
	if lines := alertLines(f.take()); len(lines) != 0 {
		t.Fatalf("logged without a check: %q", lines)
	}
	if rep := f.w.check(); rep.State != dbFileReplaced {
		t.Fatalf("second impostor: %+v", rep)
	}
	if lines := alertLines(f.take()); len(lines) != 1 || strings.Contains(lines[0], "still") {
		t.Fatalf("a new file must log a new alert: %q", lines)
	}
	// The original back in place: one plain line, no alert, and the health
	// report keeps when the last alert was.
	if err := os.Rename(moved, f.path); err != nil {
		t.Fatal(err)
	}
	f.advance(dbFileWatchInterval)
	rep = f.w.check()
	lines = f.take()
	if rep.State != dbFileOK || rep.LastAlert.IsZero() || len(lines) != 1 || strings.HasPrefix(lines[0], dbFileAlertPrefix) || !strings.Contains(lines[0], "again the file this process opened") {
		t.Fatalf("back to the original: %+v %q", rep, lines)
	}
	// Deleted afterwards: a new alert at once.
	if err := os.Remove(f.path); err != nil {
		t.Fatal(err)
	}
	f.advance(dbFileWatchInterval)
	f.w.check()
	if lines := alertLines(f.take()); len(lines) != 1 || !strings.Contains(lines[0], "database file deleted") {
		t.Fatalf("delete after recovery: %q", lines)
	}
}

func TestHealthReportsDBFileAndDegrades(t *testing.T) {
	app, _ := auditApp(t)
	// The watched file stands in for data.db, so the app's own pool keeps
	// answering the health queries.
	path := filepath.Join(app.Dir, "watched.db")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	dev, ino, err := dbFileDevIno(path)
	if err != nil {
		t.Skipf("file identity unavailable here: %v", err)
	}
	w := newDBFileWatcher(filepath.Base(app.Dir), path, dbFileIdentity{Dev: dev, Ino: ino})
	w.logf = func(string, ...any) {}
	app.dbFileWatch = w
	sess := seedAdminSession(t, app)

	read := func(admin bool) (map[string]any, *httptest.ResponseRecorder) {
		t.Helper()
		req := httptest.NewRequest("GET", "/health", nil)
		if admin {
			req = authedRequest("GET", "/health", "", sess)
		}
		rec := httptest.NewRecorder()
		healthHandler(app).ServeHTTP(rec, req)
		var body map[string]any
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
			t.Fatalf("health: %d %s", rec.Code, rec.Body.String())
		}
		return body, rec
	}
	w.check()
	body, rec := read(true)
	dbFile, _ := body["checks"].(map[string]any)["db_file"].(map[string]any)
	if body["status"] != "healthy" || dbFile["status"] != "ok" || dbFile["opened"] != devIno(dev, ino) || rec.Header().Get(dbFileAlertHeader) != "" {
		t.Fatalf("unchanged file: status %v db_file %v", body["status"], dbFile)
	}

	if err := os.Rename(path, path+".aside"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("impostor"), 0600); err != nil {
		t.Fatal(err)
	}
	w.check()
	body, rec = read(true)
	dbFile, _ = body["checks"].(map[string]any)["db_file"].(map[string]any)
	if body["status"] != "degraded" || dbFile["status"] != "replaced" || dbFile["current"] == "" || dbFile["since"] == nil {
		t.Fatalf("replaced file: status %v db_file %v", body["status"], dbFile)
	}
	if rec.Header().Get(dbFileAlertHeader) != "" {
		t.Fatal("a self-hosted app has no router to strip the header; it must not send it")
	}
	// Anonymous callers see the degraded status, never the details.
	body, _ = read(false)
	if body["status"] != "degraded" || body["checks"] != nil {
		t.Fatalf("anonymous health: %v", body)
	}
	// A hosted app names the state for the router.
	t.Setenv("BENMORE_BIND_LOOPBACK", "1")
	if _, rec = read(false); rec.Header().Get(dbFileAlertHeader) != "replaced" {
		t.Fatalf("hosted header: %q", rec.Header().Get(dbFileAlertHeader))
	}
	if !runtimeServing("degraded") || runtimeServing("unhealthy") || runtimeServing("") {
		t.Fatal("runtime-change checks must count degraded, and only it, as serving")
	}
}

// The framework's own replacements happen before the pool the watcher arms
// from is opened: boot-time auto-recovery, and a restore installed while the
// app is stopped (the router's restore and refresh-dev install through the
// same helper code with the unit stopped). The served app then reports ok.
func TestDBFileWatchArmsAfterFrameworkReplacements(t *testing.T) {
	dir := bootFixture(t)
	c := countBootChecks(t)
	app := bootServed(t, dir)
	for i := 0; i < 2000; i++ {
		mustExec(t, app.DB, fmt.Sprintf("INSERT INTO authors (name) VALUES ('%s')", strings.Repeat("a", 200)))
	}
	app.Shutdown()
	settle(t, dir, c)
	backup, err := backupDatabase(dir)
	if err != nil {
		t.Fatal(err)
	}
	inode := func() string {
		dev, ino, err := dbFileDevIno(filepath.Join(dir, "data.db"))
		if err != nil {
			t.Skipf("file identity unavailable here: %v", err)
		}
		return devIno(dev, ino)
	}
	servedOK := func(what string) {
		t.Helper()
		app := bootServed(t, dir)
		defer app.Shutdown()
		startDBFileWatch(app)
		rep, ok := dbFileHealth(app)
		if !ok || rep.State != dbFileOK || rep.Opened != inode() {
			t.Fatalf("%s: watch %v %+v (file now %s)", what, ok, rep, inode())
		}
		mustExec(t, app.DB, "INSERT INTO authors (name) VALUES ('after')")
		mustExec(t, app.DB, "PRAGMA wal_checkpoint(TRUNCATE)")
		if rep := app.dbFileWatch.check(); rep.State != dbFileOK {
			t.Fatalf("%s: after a write and checkpoint: %+v", what, rep)
		}
	}

	// 1. Boot-time auto-recovery swaps a backup in.
	before := inode()
	corruptTableRootPage(t, dir, "authors")
	servedOK("auto-recovery")
	if inode() == before {
		t.Fatal("fixture: auto-recovery did not replace the file")
	}
	if matches, _ := corruptCopies(dir); len(matches) == 0 {
		t.Fatal("fixture: auto-recovery did not run")
	}

	// 2. A restore installed while the app is stopped.
	before = inode()
	candidate, cleanup, err := prepareRestoreSnapshot(t.Context(), dir, backup)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err := installRestoreSnapshot(dir, candidate); err != nil {
		t.Fatal(err)
	}
	if inode() == before {
		t.Fatal("fixture: the restore did not replace the file")
	}
	servedOK("restore")
}

func TestShutdownEndsTheWatchAndClosesItsDescriptor(t *testing.T) {
	dir := bootFixture(t)
	countBootChecks(t)
	app := bootServed(t, dir)
	startDBFileWatch(app)
	w := app.dbFileWatch
	if w == nil || w.held == nil {
		t.Fatal("the watch did not start")
	}
	held := w.held
	app.Shutdown()
	select {
	case <-w.done:
	default:
		t.Fatal("the check loop still runs after Shutdown")
	}
	if _, err := held.Stat(); err == nil {
		t.Fatal("the held descriptor is still open after Shutdown")
	}
}

// Only a served process watches. Booting as serve does, a validation load and
// building the mux leave it off; StartServer is its one caller.
func TestDBFileWatchRunsOnlyInServe(t *testing.T) {
	dir := bootFixture(t)
	countBootChecks(t)
	app := bootServed(t, dir)
	buildAppMux(app, false, "http://localhost")
	if app.dbFileWatch != nil {
		t.Fatal("boot and mux construction started the watch")
	}
	if _, ok := dbFileHealth(app); ok {
		t.Fatal("health reports a watch that is not running")
	}
	app.Shutdown()
	checked, err := loadAppWithOptions(dir, appLoadOptions{checkOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if checked.dbFileWatch != nil {
		t.Fatal("a validation load started the watch")
	}
	checked.Shutdown()

	callers := map[string]int{}
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), "startDBFileWatch") {
			continue
		}
		file, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "startDBFileWatch" {
						callers[name+":"+fn.Name.Name]++
					}
				}
				return true
			})
		}
	}
	if len(callers) != 1 || callers["server.go:StartServer"] != 1 {
		t.Fatalf("startDBFileWatch must be called only by StartServer, found %v", callers)
	}
}
