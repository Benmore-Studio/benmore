//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The audit row of a create, delete, batch, ingest or /api/_transaction write
// is inserted inside the mutation's transaction. When that insert is the
// statement that runs out of space (the storage cap or a full disk), the
// client must get the documented 507 storage refusal, not a generic 500
// "audit write failed", and nothing may commit.
func TestAuditInsertStorageFullAnswers507OnEveryWritePath(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, body TEXT)")
	EnsureJobsTable(app.DB)
	EnsureWebhooksTable(app.DB)
	uid, sid := gateUser(t, app, "owner@example.com")
	owner := strconv.FormatInt(uid, 10)
	mustExec(t, app.DB, "INSERT INTO notes (id, user_id, body) VALUES (1, "+owner+", 'one'), (2, "+owner+", 'two')")
	// Every audit insert now fails exactly as SQLite reports a full database.
	mustExec(t, app.DB, "CREATE TRIGGER audit_full BEFORE INSERT ON _benmore_audit_log BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END")

	transaction := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://app.example.com/api/_transaction", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+sid)
		w := httptest.NewRecorder()
		handleTransaction(w, r, app)
		return w
	}
	for name, w := range map[string]*httptest.ResponseRecorder{
		"create":             gateCall(app, handleCreate, "notes", "POST", "/api/notes", "application/json", `{"body":"new"}`, sid),
		"delete":             gateCall(app, handleDelete, "notes", "DELETE", "/api/notes/1", "application/json", "", sid),
		"batch create":       gateCall(app, handleBatchCreate, "notes", "POST", "/api/notes/batch", "application/json", `[{"body":"a"},{"body":"b"}]`, sid),
		"batch delete":       gateCall(app, handleBatchDelete, "notes", "DELETE", "/api/notes/batch", "application/json", `{"ids":[1,2]}`, sid),
		"ingest":             gateCall(app, handleStreamingIngest, "notes", "POST", "/api/notes/ingest", "application/x-ndjson", "{\"body\":\"a\"}\n{\"body\":\"b\"}\n", sid),
		"transaction insert": transaction(`{"operations":[{"table":"notes","action":"insert","data":{"body":"tx"}}]}`),
		"transaction delete": transaction(`{"operations":[{"table":"notes","action":"delete","id":2}]}`),
	} {
		if w.Code != http.StatusInsufficientStorage || !strings.Contains(w.Body.String(), "storage cap reached") {
			t.Errorf("%s: audit insert out of space answered %d %s, want 507 storage cap reached", name, w.Code, w.Body.String())
		}
	}
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM notes"); n != "2" {
		t.Fatalf("a write whose audit row could not be stored committed: %s rows", n)
	}
}

// The same mapping with a genuine SQLITE_FULL from the storage ceiling: a
// small PATCH to a large row fits in the pages the row already has, but its
// audit row (the old and new values) needs new pages and is refused.
func TestAuditInsertOverStorageCeilingAnswers507OnUpdate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.db")
	setup, err := sql.Open("sqlite3_benmore", path+"?_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, setup, "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, flag TEXT, body TEXT)")
	app := &App{
		Dir:             dir,
		DB:              setup,
		SessionDuration: time.Hour,
		Stop:            make(chan struct{}),
		Tables:          []Table{{Name: "notes", Columns: []Column{{Name: "id"}, {Name: "user_id"}, {Name: "flag"}, {Name: "body"}}}},
	}
	mux := buildAppMux(app, true, "http://localhost")
	token := createCrudScopeSession(t, app, "owner@example.com", "user", "", "")
	var uid int64
	if err := setup.QueryRow("SELECT id FROM _benmore_users WHERE email = 'owner@example.com'").Scan(&uid); err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("b", 64<<10)
	for i := 0; i < 2; i++ {
		if _, err := setup.Exec("INSERT INTO notes (user_id, flag, body) VALUES (?, 'a', ?)", uid, body); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := setup.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	used := storagePragma(t, setup, "page_count") * storagePragma(t, setup, "page_size")
	withDBStorageLimit(t, dir, used+(16<<10))
	capped, err := sql.Open("sqlite3_benmore", path+"?_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	app.DB = capped
	setup.Close()
	t.Cleanup(func() {
		app.Shutdown()
		capped.Close()
	})

	rec := crudScopeRequest(t, mux, http.MethodPatch, "/api/notes/1", token, map[string]any{"flag": "b"})
	assertStorageFullResponse(t, rec)
	rec = crudScopeRequest(t, mux, http.MethodPatch, "/api/notes/batch", token, map[string]any{"ids": []int{1, 2}, "fields": map[string]any{"flag": "b"}})
	assertStorageFullResponse(t, rec)
	var changed int
	if err := capped.QueryRow("SELECT COUNT(*) FROM notes WHERE flag <> 'a'").Scan(&changed); err != nil || changed != 0 {
		t.Fatalf("an update whose audit row could not be stored committed: %d %v", changed, err)
	}
}
