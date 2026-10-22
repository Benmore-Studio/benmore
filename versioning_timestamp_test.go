//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

func TestPointInTimeTimestampEquivalenceAndBoundaries(t *testing.T) {
	app, mux := newCrudScopeTestApp(t)
	sid := createCrudScopeSession(t, app, "historian@example.com", "user", "", "")
	crudScopeMustExec(t, app.DB, `ALTER TABLE notes ADD COLUMN created_at DATETIME`)
	crudScopeMustExec(t, app.DB, `ALTER TABLE notes ADD COLUMN updated_at DATETIME`)
	crudScopeMustExec(t, app.DB, `UPDATE notes SET created_at='2026-01-01 08:00:00', updated_at='2026-01-01 14:00:00', title='current-afternoon' WHERE id=1`)
	InstallVersioningTriggers(app.DB, &VersionedConfig{Tables: []string{"notes"}})
	crudScopeMustExec(t, app.DB, `INSERT INTO notes_history (id,user_id,title,created_at,updated_at,_version,_valid_from,_valid_to,_change_type) VALUES (1,1,'historical-morning','2026-01-01 08:00:00','2026-01-01 08:00:00',1,'2026-01-01 08:00:00','2026-01-01 14:00:00','update')`)

	for _, tc := range []struct {
		name  string
		asOf  string
		title string
	}{
		{"sqlite", "2026-01-01 10:00:00", "historical-morning"},
		{"rfc3339", "2026-01-01T10:00:00Z", "historical-morning"},
		{"negative offset", "2026-01-01T05:00:00-05:00", "historical-morning"},
		{"positive offset", "2026-01-01T15:30:00+05:30", "historical-morning"},
		{"offset date rollover", "2025-12-31T23:00:00-11:00", "historical-morning"},
		{"sqlite minute", "2026-01-01 10:00", "historical-morning"},
		{"sqlite offset", "2026-01-01 05:00:00-05:00", "historical-morning"},
		{"valid from inclusive", "2026-01-01T08:00:00Z", "historical-morning"},
		{"zero fraction", "2026-01-01T08:00:00.000000000Z", "historical-morning"},
		{"fraction before end", "2026-01-01T13:59:59.999999999Z", "historical-morning"},
		{"sqlite fraction before end", "2026-01-01 13:59:59.999999999", "historical-morning"},
		{"valid to exclusive", "2026-01-01T14:00:00Z", "current-afternoon"},
		{"offset valid to exclusive", "2026-01-01T09:00:00-05:00", "current-afternoon"},
		{"fraction after end", "2026-01-01T14:00:00.000000001Z", "current-afternoon"},
		{"sqlite date", "2026-01-02", "current-afternoon"},
		{"before creation", "2026-01-01T07:59:59.999999999Z", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := crudScopeRequest(t, mux, http.MethodGet, "/api/notes/1?as_of="+url.QueryEscape(tc.asOf), sid, nil)
			if tc.title == "" {
				if w.Code != http.StatusNotFound {
					t.Fatalf("timestamp %q: want 404, got %d %s", tc.asOf, w.Code, w.Body.String())
				}
				return
			}
			var row map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &row); err != nil {
				t.Fatalf("timestamp %q: %d %s: %v", tc.asOf, w.Code, w.Body.String(), err)
			}
			if w.Code != http.StatusOK || row["title"] != tc.title {
				t.Fatalf("timestamp %q: want %q, got %d %s", tc.asOf, tc.title, w.Code, w.Body.String())
			}
		})
	}
}

func TestPointInTimeCurrentFallbackTimestampBoundary(t *testing.T) {
	app, mux := newCrudScopeTestApp(t)
	sid := createCrudScopeSession(t, app, "historian@example.com", "user", "", "")
	crudScopeMustExec(t, app.DB, `ALTER TABLE notes ADD COLUMN created_at DATETIME`)
	crudScopeMustExec(t, app.DB, `UPDATE notes SET created_at='2026-01-01 12:00:00' WHERE id=1`)
	// No history table: the current row still must not appear before creation.
	for _, tc := range []struct {
		asOf   string
		status int
	}{
		{"2026-01-01T11:59:59.999999999Z", http.StatusNotFound},
		{"2026-01-01T06:59:59.999999999-05:00", http.StatusNotFound},
		{"2026-01-01T12:00:00Z", http.StatusOK},
		{"2026-01-01T07:00:00-05:00", http.StatusOK},
		{"2026-01-01 12:00:00", http.StatusOK},
		{"2026-01-01T12:00:00.000000001Z", http.StatusOK},
	} {
		t.Run(tc.asOf, func(t *testing.T) {
			w := crudScopeRequest(t, mux, http.MethodGet, "/api/notes/1?as_of="+url.QueryEscape(tc.asOf), sid, nil)
			if w.Code != tc.status {
				t.Fatalf("want %d, got %d %s", tc.status, w.Code, w.Body.String())
			}
		})
	}
}

func TestPointInTimeRejectsInvalidTimestamp(t *testing.T) {
	app, mux := newCrudScopeTestApp(t)
	sid := createCrudScopeSession(t, app, "historian@example.com", "user", "", "")
	for _, asOf := range []string{"not-a-date", "2026-02-30T12:00:00Z", "2026-13-01", "2026-01-01T25:00:00Z", "2026-01-01T12:00:00Z trailing"} {
		t.Run(asOf, func(t *testing.T) {
			w := crudScopeRequest(t, mux, http.MethodGet, "/api/notes/1?as_of="+url.QueryEscape(asOf), sid, nil)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d %s", w.Code, w.Body.String())
			}
		})
	}
}
