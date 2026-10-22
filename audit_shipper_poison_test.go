//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// An audit row is not always written by the framework: app flows record
// their own (INSERT INTO _benmore_audit_log ...), and nothing makes their
// old_values/new_values JSON or their user_id a number. One such row used to
// stop the shipper for good (the batch no longer marshalled, so the cursor
// never moved past it), and a row whose user_id did not scan was dropped from
// its batch while the cursor moved on - with retention enabled it was then
// deleted without ever reaching the long-term store.
func TestAuditShipperShipsRowsItCannotParse(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	EnsureAuditLogTable(db)
	ensureAuditShipperCursor(db)
	mustExec(t, db, `INSERT INTO _benmore_audit_log (action, table_name, row_id, user_id, new_values) VALUES ('insert', 'notes', '1', 7, '{"title":"a"}')`)
	mustExec(t, db, `INSERT INTO _benmore_audit_log (action, table_name, row_id, user_id, new_values) VALUES ('note', 'notes', '2', 7, 'free text, not JSON')`)
	mustExec(t, db, `INSERT INTO _benmore_audit_log (action, table_name, row_id, user_id, old_values) VALUES ('sync', 'notes', '3', 'system', '{"title":')`)
	mustExec(t, db, `INSERT INTO _benmore_audit_log (action, table_name, row_id, user_id, new_values) VALUES ('update', 'notes', '4', 8, '{"title":"b"}')`)

	var batches []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var batch map[string]any
		if err := json.Unmarshal(body, &batch); err != nil {
			t.Errorf("receiver got a body that is not JSON: %v", err)
		}
		batches = append(batches, batch)
	}))
	defer srv.Close()
	t.Setenv("BENMORE_AUDIT_WEBHOOK_ALLOW_HTTP", "1")
	t.Setenv("BENMORE_BIND_LOOPBACK", "")

	shipOnce(db, srv.URL, "0123456789abcdef0123456789abcdef", "", 100, "test")

	if len(batches) != 1 {
		t.Fatalf("shipper made %d deliveries, want 1", len(batches))
	}
	entries, _ := batches[0]["entries"].([]any)
	if len(entries) != 4 {
		t.Fatalf("shipped %d of 4 audit rows", len(entries))
	}
	byRow := map[string]map[string]any{}
	for _, e := range entries {
		m := e.(map[string]any)
		byRow[m["row_id"].(string)] = m
	}
	if got := byRow["2"]["new_values"]; got != "free text, not JSON" {
		t.Errorf("non-JSON new_values shipped as %#v, want the text itself", got)
	}
	if got := byRow["3"]["old_values"]; got != `{"title":` {
		t.Errorf("truncated old_values shipped as %#v, want the text itself", got)
	}
	if got, _ := byRow["1"]["new_values"].(map[string]any); got["title"] != "a" {
		t.Errorf("JSON new_values no longer shipped as an object: %#v", byRow["1"]["new_values"])
	}
	var cursor int64
	db.QueryRow("SELECT last_shipped_id FROM " + auditShipperCursorTable + " WHERE id = 1").Scan(&cursor)
	if cursor != 4 {
		t.Fatalf("cursor at %d after shipping 4 rows", cursor)
	}
}
