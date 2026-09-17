//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGroupedQueryColdStartReturnsEmptyArray(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE events (category TEXT)`); err != nil {
		t.Fatal(err)
	}

	app := &App{
		DB:     db,
		Tables: []Table{{Name: "events", Columns: []Column{{Name: "category"}}}},
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{
			"events": {OpRead: "anon"},
		}},
	}
	mux := http.NewServeMux()
	RegisterQueryAPI(mux, app)
	req := httptest.NewRequest(http.MethodPost, "/api/_query", strings.NewReader(
		`{"table":"events","group_by":["category"],"aggregates":[{"fn":"count","as":"count"}]}`,
	))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got, want := rec.Body.String(), "{\"count\":0,\"rows\":[]}\n"; got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
}
