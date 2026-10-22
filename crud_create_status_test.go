//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// Creating an order must return its domain status, including database defaults
// and NULL, rather than replace it with the legacy operation marker.
func TestCreateResponsePreservesStatusColumn(t *testing.T) {
	for _, tc := range []struct {
		name      string
		column    string
		method    string
		body      map[string]any
		want      any
		singleton bool
	}{
		{"default", "status TEXT DEFAULT 'draft'", http.MethodPost, map[string]any{"title": "order"}, "draft", false},
		{"submitted", "status TEXT DEFAULT 'draft'", http.MethodPost, map[string]any{"title": "order", "status": "queued"}, "queued", false},
		{"null", "status TEXT", http.MethodPost, map[string]any{"title": "order"}, nil, false},
		{"singleton first write", "status TEXT DEFAULT 'draft'", http.MethodPatch, map[string]any{"title": "profile"}, "draft", true},
		{"singleton null", "status TEXT", http.MethodPatch, map[string]any{"title": "profile"}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, _ := auditApp(t)
			mustExec(t, app.DB, "ALTER TABLE notes ADD COLUMN "+tc.column)
			if tc.singleton {
				mustExec(t, app.DB, "CREATE UNIQUE INDEX notes_user_singleton ON notes(user_id)")
			}
			refreshTableColumns(t, app, "notes")
			sid := createCrudScopeSession(t, app, "creator@example.com", "user", "", "")
			mux := http.NewServeMux()
			RegisterCRUD(mux, app)
			w := crudScopeRequest(t, mux, tc.method, "/api/notes", sid, tc.body)
			if w.Code != http.StatusOK {
				t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
			}
			var created map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
				t.Fatal(err)
			}
			if status, exists := created["status"]; !exists || status != tc.want {
				t.Errorf("create status=%#v (present=%v), want %#v; body=%s", status, exists, tc.want, w.Body.String())
			}
			var stored sql.NullString
			if err := app.DB.QueryRow("SELECT status FROM notes WHERE id=?", created["id"]).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			if tc.want == nil && stored.Valid || tc.want != nil && (!stored.Valid || stored.String != tc.want) {
				t.Fatalf("stored status=%#v, want %#v", stored, tc.want)
			}
			read := crudScopeRequest(t, mux, http.MethodGet, "/api/notes/"+fmt.Sprint(created["id"]), sid, nil)
			if read.Code != http.StatusOK {
				t.Fatalf("read status=%d body=%s", read.Code, read.Body.String())
			}
			var fetched map[string]any
			if err := json.Unmarshal(read.Body.Bytes(), &fetched); err != nil {
				t.Fatal(err)
			}
			if got, exists := fetched["status"]; !exists || got != tc.want {
				t.Fatalf("read status=%#v (present=%v), want %#v", got, exists, tc.want)
			}
		})
	}
}

func TestCreateResponseStatusIdempotency(t *testing.T) {
	app, _ := auditApp(t)
	mustExec(t, app.DB, "ALTER TABLE notes ADD COLUMN status TEXT DEFAULT 'draft'")
	refreshTableColumns(t, app, "notes")
	sid := createCrudScopeSession(t, app, "creator@example.com", "user", "", "")
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	first := auditPost(mux, sid, "/api/notes", "order-create", `{"title":"order"}`, false)
	replay := auditPost(mux, sid, "/api/notes", "order-create", `{"title":"order"}`, false)
	if first.Code != http.StatusOK || replay.Code != http.StatusOK || first.Body.String() != replay.Body.String() {
		t.Fatalf("create/replay response mismatch: %d %s / %d %s", first.Code, first.Body.String(), replay.Code, replay.Body.String())
	}
	var row map[string]any
	if err := json.Unmarshal(replay.Body.Bytes(), &row); err != nil {
		t.Fatal(err)
	}
	if row["status"] != "draft" {
		t.Errorf("replayed status=%v, want draft", row["status"])
	}
	var count int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM notes").Scan(&count); err != nil || count != 1 {
		t.Fatalf("replay row count=%d err=%v", count, err)
	}
}

func TestCreateResponseLegacyStatusWithoutColumn(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "creator@example.com", "user", "", "")
	w := crudScopeRequest(t, mux, http.MethodPost, "/api/notes", sid, map[string]any{"title": "legacy"})
	if w.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	var row map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &row); err != nil {
		t.Fatal(err)
	}
	if row["status"] != "created" || row["title"] != "legacy" || row["id"] == nil {
		t.Fatalf("legacy create response changed: %v", row)
	}
}
