//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// newComputedTestDB opens a fresh SQLite database in a temp directory for
// testing computed-field triggers.  The plain "sqlite3" driver is sufficient
// here because computed expressions use only standard SQL — no custom SQLite
// functions required (unlike encryption/blind-index triggers).
func newComputedTestDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "computed_test.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return db, func() { db.Close() }
}

// TestComputedTriggerIntegerPK is the baseline: a table with the conventional
// integer PK column named "id".  The computed column must populate on INSERT
// and recompute on UPDATE.
func TestComputedTriggerIntegerPK(t *testing.T) {
	db, cleanup := newComputedTestDB(t)
	defer cleanup()

	if _, err := db.Exec(`CREATE TABLE order_lines (
		id       INTEGER PRIMARY KEY AUTOINCREMENT,
		quantity REAL    NOT NULL DEFAULT 0,
		price    REAL    NOT NULL DEFAULT 0,
		total    REAL
	)`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	config := &ComputedFieldConfig{
		Fields: map[string]map[string]*ComputedField{
			"order_lines": {
				"total": {
					Table:  "order_lines",
					Column: "total",
					Expr:   "quantity * price",
				},
			},
		},
	}
	InstallComputedTriggers(db, config)

	// INSERT: trigger must compute total = 3 * 25 = 75.
	if _, err := db.Exec("INSERT INTO order_lines (quantity, price) VALUES (3, 25)"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var total sql.NullFloat64
	if err := db.QueryRow("SELECT total FROM order_lines").Scan(&total); err != nil {
		t.Fatalf("read total after insert: %v", err)
	}
	if !total.Valid || total.Float64 != 75 {
		t.Fatalf("expected total=75 after INSERT, got %v (valid=%v)", total.Float64, total.Valid)
	}

	// UPDATE: trigger must recompute total = 5 * 10 = 50.
	if _, err := db.Exec("UPDATE order_lines SET quantity = 5, price = 10"); err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := db.QueryRow("SELECT total FROM order_lines").Scan(&total); err != nil {
		t.Fatalf("read total after update: %v", err)
	}
	if !total.Valid || total.Float64 != 50 {
		t.Fatalf("expected total=50 after UPDATE, got %v (valid=%v)", total.Float64, total.Valid)
	}
}

// TestComputedTriggerNonIdPrimaryKey is the regression test for the bug where
// installExprTriggers hardcoded "WHERE id = NEW.id" in the trigger body.
//
// For a table whose PK column is NOT named "id" (e.g. "order_uuid" TEXT PRIMARY
// KEY), SQLite would raise "no such column: id" inside the trigger, causing
// the INSERT itself to fail.
//
// The fix changes the WHERE clause to:
//
//	WHERE rowid = NEW.rowid
//
// SQLite's rowid pseudo-column is available on every ordinary table regardless
// of the PK column name, and equals id for INTEGER PRIMARY KEY tables — so this
// is fully back-compat.  This mirrors the same fix applied to encryption and
// blind-index triggers in PR #93.
//
// This test MUST FAIL against the old "WHERE id = NEW.id" code and MUST PASS
// after the fix.
func TestComputedTriggerNonIdPrimaryKey(t *testing.T) {
	db, cleanup := newComputedTestDB(t)
	defer cleanup()

	// Use a TEXT primary key with a non-"id" column name to reproduce the failure.
	if _, err := db.Exec(`CREATE TABLE purchase_items (
		item_uuid TEXT PRIMARY KEY,
		quantity  REAL NOT NULL DEFAULT 0,
		price     REAL NOT NULL DEFAULT 0,
		line_total REAL
	)`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	config := &ComputedFieldConfig{
		Fields: map[string]map[string]*ComputedField{
			"purchase_items": {
				"line_total": {
					Table:  "purchase_items",
					Column: "line_total",
					Expr:   "quantity * price",
				},
			},
		},
	}
	InstallComputedTriggers(db, config)

	// INSERT must NOT fail even though the table has no "id" column.
	// Before the fix this would fail with:
	//   "table purchase_items has no column named id"  (trigger body error)
	_, err := db.Exec(
		"INSERT INTO purchase_items (item_uuid, quantity, price) VALUES (?, ?, ?)",
		"item-001", 4.0, 12.5,
	)
	if err != nil {
		t.Fatalf("INSERT on non-id-PK table failed (trigger bug?): %v", err)
	}

	// The computed column must contain quantity * price = 4 * 12.5 = 50.
	var lineTotal sql.NullFloat64
	if err := db.QueryRow("SELECT line_total FROM purchase_items WHERE item_uuid = 'item-001'").Scan(&lineTotal); err != nil {
		t.Fatalf("read line_total after insert: %v", err)
	}
	if !lineTotal.Valid || lineTotal.Float64 != 50 {
		t.Fatalf("expected line_total=50 after INSERT, got %v (valid=%v)", lineTotal.Float64, lineTotal.Valid)
	}

	// UPDATE: trigger must also fire correctly via rowid.
	if _, err := db.Exec(
		"UPDATE purchase_items SET quantity = 2, price = 30 WHERE item_uuid = 'item-001'",
	); err != nil {
		t.Fatalf("UPDATE on non-id-PK table failed: %v", err)
	}
	if err := db.QueryRow("SELECT line_total FROM purchase_items WHERE item_uuid = 'item-001'").Scan(&lineTotal); err != nil {
		t.Fatalf("read line_total after update: %v", err)
	}
	if !lineTotal.Valid || lineTotal.Float64 != 60 {
		t.Fatalf("expected line_total=60 after UPDATE, got %v (valid=%v)", lineTotal.Float64, lineTotal.Valid)
	}
}

// TestComputedTriggerMultipleRowsNonIdPK verifies that the rowid-based WHERE
// clause correctly scopes updates to the NEWLY inserted/updated row only, even
// when multiple rows exist in a non-id-PK table.
func TestComputedTriggerMultipleRowsNonIdPK(t *testing.T) {
	db, cleanup := newComputedTestDB(t)
	defer cleanup()

	if _, err := db.Exec(`CREATE TABLE invoice_lines (
		line_key  TEXT PRIMARY KEY,
		qty       REAL NOT NULL DEFAULT 0,
		unit_cost REAL NOT NULL DEFAULT 0,
		subtotal  REAL
	)`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	config := &ComputedFieldConfig{
		Fields: map[string]map[string]*ComputedField{
			"invoice_lines": {
				"subtotal": {
					Table:  "invoice_lines",
					Column: "subtotal",
					Expr:   "qty * unit_cost",
				},
			},
		},
	}
	InstallComputedTriggers(db, config)

	// Insert two rows and verify each gets the correct computed value.
	rows := []struct {
		key      string
		qty      float64
		cost     float64
		expected float64
	}{
		{"line-A", 2, 10, 20},
		{"line-B", 3, 15, 45},
	}
	for _, r := range rows {
		if _, err := db.Exec(
			"INSERT INTO invoice_lines (line_key, qty, unit_cost) VALUES (?, ?, ?)",
			r.key, r.qty, r.cost,
		); err != nil {
			t.Fatalf("INSERT %s failed: %v", r.key, err)
		}
	}
	for _, r := range rows {
		var sub sql.NullFloat64
		if err := db.QueryRow("SELECT subtotal FROM invoice_lines WHERE line_key = ?", r.key).Scan(&sub); err != nil {
			t.Fatalf("read subtotal for %s: %v", r.key, err)
		}
		if !sub.Valid || sub.Float64 != r.expected {
			t.Fatalf("%s: expected subtotal=%.0f, got %v (valid=%v)", r.key, r.expected, sub.Float64, sub.Valid)
		}
	}

	// Update only line-B and confirm line-A is unchanged.
	if _, err := db.Exec(
		"UPDATE invoice_lines SET qty = 1, unit_cost = 100 WHERE line_key = 'line-B'",
	); err != nil {
		t.Fatalf("UPDATE line-B failed: %v", err)
	}
	var subA, subB sql.NullFloat64
	if err := db.QueryRow("SELECT subtotal FROM invoice_lines WHERE line_key = 'line-A'").Scan(&subA); err != nil {
		t.Fatalf("read subtotal for line-A after update: %v", err)
	}
	if err := db.QueryRow("SELECT subtotal FROM invoice_lines WHERE line_key = 'line-B'").Scan(&subB); err != nil {
		t.Fatalf("read subtotal for line-B after update: %v", err)
	}
	if !subA.Valid || subA.Float64 != 20 {
		t.Fatalf("line-A subtotal changed unexpectedly: got %v", subA.Float64)
	}
	if !subB.Valid || subB.Float64 != 100 {
		t.Fatalf("line-B subtotal after update: expected 100, got %v", subB.Float64)
	}
}
