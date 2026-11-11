//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// limit caps at 1000 (api(at:"query") spec). An oversized limit used to
// fall back to the 200-row default, so asking for more rows returned fewer:
// limit 1000 gave 1000 rows and limit 5000 gave 200.
func TestQueryLimitClampsToMaximum(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	for _, stmt := range []string{
		`CREATE TABLE events (id INTEGER PRIMARY KEY, category TEXT)`,
		`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 1200) INSERT INTO events (id, category) SELECT i, 'c' FROM n`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	app := &App{
		DB:     db,
		Tables: []Table{{Name: "events", Columns: []Column{{Name: "id"}, {Name: "category"}}}},
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{"events": {OpRead: "anon"}}},
	}
	mux := http.NewServeMux()
	RegisterQueryAPI(mux, app)

	for _, tc := range []struct {
		limit, want int
	}{
		{0, 200}, {-5, 200}, {5, 5}, {1000, 1000}, {1001, 1000}, {5000, 1000},
	} {
		body := fmt.Sprintf(`{"table":"events","select":["id"],"limit":%d}`, tc.limit)
		req := httptest.NewRequest(http.MethodPost, "/api/_query", strings.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("limit %d: status %d %s", tc.limit, rec.Code, rec.Body.String())
		}
		var out struct {
			Rows  []map[string]any `json:"rows"`
			Count int              `json:"count"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("limit %d: %v", tc.limit, err)
		}
		if len(out.Rows) != tc.want || out.Count != tc.want {
			t.Errorf("limit %d: %d rows (count %d), want %d", tc.limit, len(out.Rows), out.Count, tc.want)
		}
	}
}

// Report sources share the clamp. overflow: error keeps refusing a limit
// outside 1..1000 at authoring time, so its cap is never the clamped value.
func TestReportSourceLimitSharesQueryClamp(t *testing.T) {
	for limit, want := range map[int]int{0: 200, -1: 200, 1: 1, 1000: 1000, 1001: 1000, 5000: 1000} {
		if got := queryResultLimit(limit); got != want {
			t.Errorf("queryResultLimit(%d) = %d, want %d", limit, got, want)
		}
	}
	if err := (reportSource{querySpec: querySpec{Table: "t", Limit: 5000}, Overflow: "error"}).validate(); err == nil {
		t.Error("overflow: error accepted limit 5000")
	}
	if err := (reportSource{querySpec: querySpec{Table: "t", Limit: 5000}}).validate(); err != nil {
		t.Errorf("a source without overflow: error refused limit 5000: %v", err)
	}
}
