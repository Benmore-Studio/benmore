//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"testing"
)

type bulkAuditRow struct {
	Action string
	RowID  string
	UserID int64
	New    map[string]any
}

func bulkAuditRows(t *testing.T, app *App, table string) []bulkAuditRow {
	t.Helper()
	rows, err := app.DB.Query("SELECT action, row_id, user_id, COALESCE(new_values,'') FROM _benmore_audit_log WHERE table_name = ? ORDER BY id", table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []bulkAuditRow
	for rows.Next() {
		var r bulkAuditRow
		var raw string
		if err := rows.Scan(&r.Action, &r.RowID, &r.UserID, &raw); err != nil {
			t.Fatal(err)
		}
		if raw != "" {
			if err := json.Unmarshal([]byte(raw), &r.New); err != nil {
				t.Fatalf("new_values %q: %v", raw, err)
			}
		}
		out = append(out, r)
	}
	return out
}

func bulkRowIDs(t *testing.T, app *App, table string) []string {
	t.Helper()
	rows, err := app.DB.Query("SELECT id FROM " + quoteIdent(table) + " ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, strconv.FormatInt(id, 10))
	}
	return ids
}

// NDJSON ingest records one audit entry per committed row, inside the ingest
// transaction, like batch create: action insert, the row's id, its stored
// values (hidden columns as [hidden]). It used to write one entry with
// row_id "batch:<count>" and only the counts, so an ingested row could not be
// traced to its writer. Skipped and refused rows leave no entry.
func TestStreamingIngestAuditsEachCommittedRow(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, body TEXT NOT NULL, api_token TEXT)")
	uid, sid := gateUser(t, app, "loader@example.com")
	body := `{"body":"first","api_token":"tok-1"}` + "\n" +
		"{not json}\n" +
		`{"api_token":"refused by NOT NULL"}` + "\n" +
		`{"body":"second"}` + "\n"
	w := gateCall(app, handleStreamingIngest, "notes", "POST", "/api/notes/ingest", "application/x-ndjson", body, sid)
	var out ingestCompletionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != http.StatusOK || out.Ingested != 2 || out.Errors != 2 {
		t.Fatalf("ingest = %d %s", w.Code, w.Body.String())
	}

	ids := bulkRowIDs(t, app, "notes")
	audits := bulkAuditRows(t, app, "notes")
	if len(ids) != 2 || len(audits) != 2 {
		t.Fatalf("rows %v, audit entries %+v: want one entry per committed row", ids, audits)
	}
	for i, want := range []string{"first", "second"} {
		a := audits[i]
		if a.Action != "insert" || a.RowID != ids[i] || a.UserID != uid {
			t.Fatalf("audit %d = %+v, want insert of row %s by user %d", i, a, ids[i], uid)
		}
		if a.New["body"] != want || fmt.Sprint(a.New["id"]) != ids[i] || fmt.Sprint(a.New["user_id"]) != strconv.FormatInt(uid, 10) {
			t.Fatalf("audit %d new_values = %v, want the stored row %q", i, a.New, want)
		}
	}
	if audits[0].New["api_token"] != auditHiddenValue {
		t.Fatalf("hidden column recorded by value: %v", audits[0].New)
	}
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'ingest' OR row_id LIKE 'batch:%'"); n != "0" {
		t.Fatalf("aggregate ingest audit entry still written: %s", n)
	}
}

// Batch create records the same action as a single create, so an audit
// filter on action=insert finds every created row. It used to record
// "create" and `?action=insert` missed every /batch row.
func TestBatchCreateAuditsAsInsert(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, body TEXT)")
	EnsureJobsTable(app.DB)
	EnsureWebhooksTable(app.DB)
	uid, sid := gateUser(t, app, "writer@example.com")
	if w := gateCall(app, handleCreate, "notes", "POST", "/api/notes", "application/json", `{"body":"single"}`, sid); w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("single create = %d %s", w.Code, w.Body.String())
	}
	if w := gateCall(app, handleBatchCreate, "notes", "POST", "/api/notes/batch", "application/json", `[{"body":"a"},{"body":"b"}]`, sid); w.Code != http.StatusOK {
		t.Fatalf("batch create = %d %s", w.Code, w.Body.String())
	}
	ids := bulkRowIDs(t, app, "notes")
	audits := bulkAuditRows(t, app, "notes")
	if len(ids) != 3 || len(audits) != 3 {
		t.Fatalf("rows %v, audit entries %+v", ids, audits)
	}
	for i, a := range audits {
		if a.Action != "insert" || a.RowID != ids[i] || a.UserID != uid {
			t.Fatalf("audit %d = %+v, want insert of row %s", i, a, ids[i])
		}
	}

	// The admin audit API's action filter now returns all three.
	admin := createCrudScopeSession(t, app, "auditor@example.com", "admin", "", "")
	mux := http.NewServeMux()
	RegisterAuditAPI(mux, app)
	r := crudScopeRequest(t, mux, http.MethodGet, "/api/_audit?table=notes&action=insert", admin, nil)
	var listed []map[string]any
	if err := json.Unmarshal(r.Body.Bytes(), &listed); err != nil || r.Code != http.StatusOK || len(listed) != 3 {
		t.Fatalf("GET /api/_audit?action=insert = %d %s, want the single and both batch rows", r.Code, r.Body.String())
	}
}
