//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

// GET /api/_my-data reads every row the caller owns, so for a table listed in
// auth.read_audit it records a read event like every other read path: one
// per audited table in the export, query_type my_data. It recorded none, so
// a full export of an audited table left no trace in /api/_audit/reads.
func TestMyDataExportWritesReadAudit(t *testing.T) {
	app := newCrudScopeApp(t)
	EnsureAuditLogTable(app.DB)
	app.Design = &DesignConfig{Auth: map[string]string{"read_audit": "notes"}}
	// An app with an auth section has its sign-in routes, as a loaded app does.
	app.Paths = DiscoverAuthPaths(nil)
	mux := buildAppMux(app, true, "http://localhost")
	InitReadAudit(app, false)
	// notes rows 1 and 2 belong to user ids 1 and 2; this caller is user 1.
	owner := createCrudScopeSession(t, app, "exporter@example.com", "user", "", "")
	uid := GetSessionFromDB(app.DB, owner).UserID

	w := crudScopeRequest(t, mux, http.MethodGet, "/api/_my-data", owner, nil)
	var out struct {
		Tables map[string][]map[string]any `json:"tables"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != http.StatusOK || len(out.Tables["notes"]) != 1 {
		t.Fatalf("export = %d %s, want the caller's one note", w.Code, w.Body.String())
	}
	FlushReadAudit(app)

	rows, err := app.DB.Query("SELECT table_name, COALESCE(row_id,''), query_type, user_id, user_email FROM _benmore_read_audit ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var events []string
	for rows.Next() {
		var table, rowID, queryType, email string
		var actor int64
		if err := rows.Scan(&table, &rowID, &queryType, &actor, &email); err != nil {
			t.Fatal(err)
		}
		if table != "notes" || rowID != "" || queryType != "my_data" || actor != uid || email != "exporter@example.com" {
			t.Fatalf("read event %s/%q/%s by %d %s, want one my_data event on notes by the exporter", table, rowID, queryType, actor, email)
		}
		events = append(events, table)
	}
	// records is exported too but not read-audited.
	if len(events) != 1 {
		t.Fatalf("read events %v, want exactly one (notes)", events)
	}

	// The caller sees it in their own read history.
	mux2 := http.NewServeMux()
	RegisterReadAuditAPI(mux2, app)
	h := crudScopeRequest(t, mux2, http.MethodGet, "/api/_audit/reads?table=notes", owner, nil)
	var history []map[string]any
	if err := json.Unmarshal(h.Body.Bytes(), &history); err != nil || h.Code != http.StatusOK || len(history) != 1 || history[0]["query_type"] != "my_data" {
		t.Fatalf("read history = %d %s", h.Code, h.Body.String())
	}
}
