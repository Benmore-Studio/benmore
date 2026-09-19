//go:build !cli

package main

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// TestLoadAggregateValues_NumericCoercion locks the fix: aggregate values
// stored in the TEXT value column are served as NUMBERS when numeric, so
// bm.aggregate('x') / {{agg.x}} don't hand the client the string "9.12"
// (which threw `n.toFixed is not a function`). Non-numeric aggregates
// (e.g. a name) stay strings.
func TestLoadAggregateValues_NumericCoercion(t *testing.T) {
	db, _ := sql.Open("sqlite3", ":memory:")
	t.Cleanup(func() { _ = db.Close() })
	EnsureAggregatesTable(db)
	db.Exec(`INSERT INTO _benmore_aggregates (name, value) VALUES
		('revenue','9.12'), ('orders','42'), ('top_customer','Acme Corp'), ('avg','3.50')`)

	vals := LoadAggregateValues(db)

	if _, ok := vals["revenue"].(float64); !ok {
		t.Fatalf("revenue should be float64, got %T (%v)", vals["revenue"], vals["revenue"])
	}
	if _, ok := vals["orders"].(int64); !ok {
		t.Fatalf("orders should be int64, got %T (%v)", vals["orders"], vals["orders"])
	}
	if _, ok := vals["avg"].(float64); !ok {
		t.Fatalf("avg should be float64, got %T", vals["avg"])
	}
	if s, ok := vals["top_customer"].(string); !ok || s != "Acme Corp" {
		t.Fatalf("top_customer should stay string 'Acme Corp', got %T (%v)", vals["top_customer"], vals["top_customer"])
	}
}
