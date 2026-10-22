//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
)

// withDBStorageLimit registers a limit for dir/data.db for one test, with the
// ceiling at the limit itself so small databases reach it.
func withDBStorageLimit(t *testing.T, dir string, limit int64) string {
	t.Helper()
	withoutStorageHeadroom(t)
	path := filepath.Join(dir, "data.db")
	setDBStorageLimit(path, limit)
	t.Cleanup(func() { dbStorageLimits.Delete(canonicalDBPath(path)) })
	return path
}

func withoutStorageHeadroom(t *testing.T) {
	t.Helper()
	saved := storageCeilingHeadroom
	storageCeilingHeadroom = func(int64) int64 { return 0 }
	t.Cleanup(func() { storageCeilingHeadroom = saved })
}

// The SQLite ceiling leaves room above the plan limit, so reaching the plan
// (where creates are refused by checkStorageCap) doesn't also stop sign-ins,
// jobs and migrations: a quarter of the limit, at least 64 MiB.
func TestStorageCeilingLeavesHeadroomAbovePlanLimit(t *testing.T) {
	const free, pro, scale int64 = 100 << 20, 1 << 30, 10 << 30 // the plan tiers
	for limit, want := range map[int64]int64{
		free:  free + 64<<20,
		pro:   pro + pro/4,
		scale: scale + scale/4,
	} {
		if got := limit + storageCeilingHeadroom(limit); got != want {
			t.Errorf("ceiling for %d = %d, want %d", limit, got, want)
		}
	}
	path := filepath.Join(t.TempDir(), "data.db")
	setDBStorageLimit(path, free)
	t.Cleanup(func() { dbStorageLimits.Delete(canonicalDBPath(path)) })
	db, err := sql.Open("sqlite3_benmore", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE t (v TEXT)"); err != nil {
		t.Fatal(err)
	}
	pageSize := storagePragma(t, db, "page_size")
	if max := storagePragma(t, db, "max_page_count") * pageSize; max < free+64<<20-pageSize || max > free+64<<20 {
		t.Fatalf("ceiling %d bytes, want the free limit plus 64 MiB", max)
	}
}

func storagePragma(t *testing.T, db *sql.DB, name string) int64 {
	t.Helper()
	var n int64
	if err := db.QueryRow("PRAGMA " + name).Scan(&n); err != nil {
		t.Fatalf("PRAGMA %s: %v", name, err)
	}
	return n
}

// fillUntilFull inserts rows until SQLite refuses to grow the file and
// returns the refusal.
func fillUntilFull(t *testing.T, db *sql.DB, table string, rowBytes int) error {
	t.Helper()
	blob := strings.Repeat("x", rowBytes)
	for i := 0; i < 100000; i++ {
		if _, err := db.Exec("INSERT INTO "+table+" (v) VALUES (?)", blob); err != nil {
			return err
		}
	}
	t.Fatal("the database never reached its storage limit")
	return nil
}

// Every framework-driver pool on a registered database is capped: the app's
// own OpenDB pool and a second pool opened the way the router opens tenant
// databases. A refused write leaves the file consistent, rolls back its
// transaction, and does not stop reads, deletes, or reuse of freed space.
func TestStorageLimitStopsGrowthOnEveryConnection(t *testing.T) {
	dir := t.TempDir()
	const limit = 256 << 10
	path := withDBStorageLimit(t, dir, limit)

	db, err := OpenDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mustExec(t, db, "CREATE TABLE items (id INTEGER PRIMARY KEY, v TEXT)")
	err = fillUntilFull(t, db, "items", 3000)
	if !isStorageFullError(err) {
		t.Fatalf("growth past the limit failed with %v, want SQLITE_FULL", err)
	}
	var se sqlite3.Error
	if !errors.As(err, &se) || se.Code != sqlite3.ErrFull {
		t.Fatalf("error is not a typed SQLITE_FULL: %#v", err)
	}
	pages, pageSize := storagePragma(t, db, "page_count"), storagePragma(t, db, "page_size")
	if pages*pageSize > limit {
		t.Fatalf("database grew to %d bytes past its %d byte limit", pages*pageSize, limit)
	}
	var before int
	if err := db.QueryRow("SELECT count(*) FROM items").Scan(&before); err != nil || before == 0 {
		t.Fatalf("reads failed at the limit: rows=%d err=%v", before, err)
	}

	// A transaction whose later statement hits the limit commits nothing.
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("DELETE FROM items WHERE id = (SELECT min(id) FROM items)"); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec("INSERT INTO items (v) VALUES (?)", strings.Repeat("y", 64<<10))
	if !isStorageFullError(err) {
		t.Fatalf("in-transaction growth failed with %v, want SQLITE_FULL", err)
	}
	_ = tx.Rollback()
	var after int
	if err := db.QueryRow("SELECT count(*) FROM items").Scan(&after); err != nil || after != before {
		t.Fatalf("failed transaction changed the table: before=%d after=%d err=%v", before, after, err)
	}

	// The router opens tenant databases with its own DSN; it is capped too.
	router, err := sql.Open("sqlite3_benmore", path+"?_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	if max := storagePragma(t, router, "max_page_count"); max*pageSize > limit {
		t.Fatalf("second pool max_page_count = %d pages, want at most %d bytes", max, limit)
	}
	if _, err := router.Exec("INSERT INTO items (v) VALUES (?)", strings.Repeat("z", 64<<10)); !isStorageFullError(err) {
		t.Fatalf("write through the second pool failed with %v, want SQLITE_FULL", err)
	}

	// Deleting frees pages the next writes reuse, without growing the file.
	if _, err := db.Exec("DELETE FROM items WHERE id IN (SELECT id FROM items ORDER BY id LIMIT 20)"); err != nil {
		t.Fatalf("delete at the limit: %v", err)
	}
	if _, err := db.Exec("INSERT INTO items (v) VALUES (?)", strings.Repeat("w", 3000)); err != nil {
		t.Fatalf("insert into freed space: %v", err)
	}
	if got := storagePragma(t, db, "page_count"); got*pageSize > limit {
		t.Fatalf("reuse grew the file to %d pages", got)
	}
	var verdict string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&verdict); err != nil || verdict != "ok" {
		t.Fatalf("integrity after refused writes: %q %v", verdict, err)
	}
}

// SQLite never lowers max_page_count below the current page count. A
// database already over its limit is frozen at its size: it serves reads and
// deletes and reuses freed space, but cannot grow.
func TestStorageLimitFreezesDatabaseAlreadyOverLimit(t *testing.T) {
	dir := t.TempDir()
	seed, err := OpenDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, seed, "CREATE TABLE items (id INTEGER PRIMARY KEY, v TEXT)")
	for i := 0; i < 200; i++ {
		if _, err := seed.Exec("INSERT INTO items (v) VALUES (?)", strings.Repeat("x", 3000)); err != nil {
			t.Fatal(err)
		}
	}
	grown := storagePragma(t, seed, "page_count")
	seed.Close()

	withDBStorageLimit(t, dir, 64<<10)
	db, err := OpenDB(dir)
	if err != nil {
		t.Fatalf("an over-limit database must still open: %v", err)
	}
	defer db.Close()
	if max := storagePragma(t, db, "max_page_count"); max != grown {
		t.Fatalf("max_page_count = %d, want it frozen at the current %d pages", max, grown)
	}
	var n int
	if err := db.QueryRow("SELECT count(*) FROM items").Scan(&n); err != nil || n != 200 {
		t.Fatalf("reads on an over-limit database: n=%d err=%v", n, err)
	}
	if _, err := db.Exec("INSERT INTO items (v) VALUES (?)", strings.Repeat("y", 64<<10)); !isStorageFullError(err) {
		t.Fatalf("growth of an over-limit database failed with %v, want SQLITE_FULL", err)
	}
	if _, err := db.Exec("DELETE FROM items WHERE id <= 50"); err != nil {
		t.Fatalf("delete on an over-limit database: %v", err)
	}
	if _, err := db.Exec("INSERT INTO items (v) VALUES (?)", strings.Repeat("z", 3000)); err != nil {
		t.Fatalf("write into freed space on an over-limit database: %v", err)
	}
	if got := storagePragma(t, db, "page_count"); got > grown {
		t.Fatalf("over-limit database grew from %d to %d pages", grown, got)
	}
}

// Without a registration (self-hosted, framework edition, `benmore serve`)
// nothing is capped.
func TestStorageLimitUnregisteredDatabaseIsUncapped(t *testing.T) {
	db, err := OpenDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if max := storagePragma(t, db, "max_page_count"); max < 1<<30 {
		t.Fatalf("unregistered database max_page_count = %d, want SQLite's default", max)
	}
}

func TestStorageFullErrorDetection(t *testing.T) {
	typed := sqlite3.Error{Code: sqlite3.ErrFull}
	for _, err := range []error{typed, fmt.Errorf("row 3: %w", typed), errors.New("database or disk is full")} {
		if !isStorageFullError(err) {
			t.Fatalf("%v not recognized as storage full", err)
		}
	}
	for _, err := range []error{nil, errors.New("UNIQUE constraint failed: t.id"), sqlite3.Error{Code: sqlite3.ErrConstraint}} {
		if isStorageFullError(err) {
			t.Fatalf("%v misread as storage full", err)
		}
	}
}

func assertStorageFullResponse(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusInsufficientStorage {
		t.Fatalf("status = %d, want 507; body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("refusal is not JSON: %s", rec.Body.String())
	}
	if body["error"] != "storage cap reached" {
		t.Fatalf("refusal error = %v, want the storage cap shape: %s", body["error"], rec.Body.String())
	}
	if strings.Contains(strings.ToLower(rec.Body.String()), "sqlite") {
		t.Fatalf("refusal leaks the driver error: %s", rec.Body.String())
	}
}

// A flow write past the limit answers 507 with the storage shape instead of a
// 500, and its transaction leaves nothing behind.
func TestStorageLimitFlowWriteReturnsInsufficientStorage(t *testing.T) {
	dir := t.TempDir()
	withDBStorageLimit(t, dir, 128<<10)
	db, err := OpenDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db}
	defer app.Shutdown()
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	mustExec(t, db, "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)")
	flow := &Flow{
		Name:        "save-note",
		Transaction: true,
		Trigger:     FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/save-note"},
		Steps: []FlowStep{
			{Name: "small", Type: "sql", SQL: "INSERT INTO notes (body) VALUES ('first')"},
			{Name: "big", Type: "sql", SQL: "INSERT INTO notes (body) VALUES (:body)"},
			{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"ok": true}}},
		},
	}
	payload, _ := json.Marshal(map[string]string{"body": strings.Repeat("n", 512<<10)})
	req := httptest.NewRequest(http.MethodPost, "/api/save-note", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	executeFlowHTTP(app, flow, rec, req)
	assertStorageFullResponse(t, rec)
	var n int
	if err := db.QueryRow("SELECT count(*) FROM notes").Scan(&n); err != nil || n != 0 {
		t.Fatalf("refused flow transaction left rows=%d err=%v", n, err)
	}
}

// Auto-CRUD creates past the limit answer 507; the rows already stored stay
// readable and deletable. In platform builds the pre-flight check may refuse
// first, with the same status and error.
func TestStorageLimitCRUDCreateReturnsInsufficientStorage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.db")
	setup, err := sql.Open("sqlite3_benmore", path+"?_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, setup, "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT)")
	app := &App{
		Dir:             dir,
		DB:              setup,
		SessionDuration: time.Hour,
		Stop:            make(chan struct{}),
		Tables:          []Table{{Name: "notes", Columns: []Column{{Name: "id"}, {Name: "user_id"}, {Name: "title"}}}},
	}
	mux := buildAppMux(app, true, "http://localhost")
	token := createCrudScopeSession(t, app, "owner@example.com", "user", "", "")
	// Set up the framework tables unlimited, then serve through a capped pool.
	// Checkpoint first so the platform pre-flight (file + WAL) starts level
	// with the page count the ceiling measures.
	if _, err := setup.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	used := storagePragma(t, setup, "page_count") * storagePragma(t, setup, "page_size")
	withDBStorageLimit(t, dir, used+1<<20)
	capped, err := sql.Open("sqlite3_benmore", path+"?_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	app.DB = capped
	setup.Close()
	// Workers flush through app.DB on shutdown; stop them before closing it.
	t.Cleanup(func() {
		app.Shutdown()
		capped.Close()
	})

	title := strings.Repeat("t", 32<<10)
	var rec *httptest.ResponseRecorder
	created := 0
	for i := 0; i < 200; i++ {
		rec = crudScopeRequest(t, mux, http.MethodPost, "/api/notes", token, map[string]any{"title": title})
		if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
			break
		}
		created++
	}
	if created == 0 {
		t.Fatalf("no create succeeded under the limit: %d %s", rec.Code, rec.Body.String())
	}
	assertStorageFullResponse(t, rec)
	list := crudScopeRequest(t, mux, http.MethodGet, "/api/notes", token, nil)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), title[:64]) {
		t.Fatalf("reads failed at the limit: %d", list.Code)
	}
	if del := crudScopeRequest(t, mux, http.MethodDelete, "/api/notes/1", token, nil); del.Code != http.StatusOK {
		t.Fatalf("delete at the limit: %d %s", del.Code, del.Body.String())
	}
}
