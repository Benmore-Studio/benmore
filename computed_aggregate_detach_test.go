//go:build !cli

package main

import (
	"testing"
)

// An aggregate computed field is recalculated on the OLD parent when a child
// row's foreign key changes. The trigger compared with `!=`, which is NULL
// (not true) when the key is set to NULL, so detaching a child - a typed
// `null` through /api/_transaction - left it counted on the parent it had
// left; re-attaching it elsewhere then counted it twice.
func TestComputedAggregateRecalculatesWhenChildIsDetached(t *testing.T) {
	db, cleanup := newComputedTestDB(t)
	defer cleanup()
	for _, stmt := range []string{
		`CREATE TABLE invoices (id INTEGER PRIMARY KEY, paid REAL DEFAULT 0)`,
		`CREATE TABLE payments (id INTEGER PRIMARY KEY, invoice_id INTEGER, amount REAL)`,
		`INSERT INTO invoices (id) VALUES (1), (2)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	InstallComputedTriggers(db, &ComputedFieldConfig{Fields: map[string]map[string]*ComputedField{
		"invoices": {"paid": {
			Table: "invoices", Column: "paid",
			SQL:      "SELECT COALESCE(SUM(amount), 0) FROM payments WHERE invoice_id = ?",
			Triggers: []ComputedTriggerDef{{Table: "payments", On: []string{"insert", "update", "delete"}, FK: "invoice_id"}},
		}},
	}})
	paid := func(id int) float64 {
		t.Helper()
		var v float64
		if err := db.QueryRow("SELECT paid FROM invoices WHERE id = ?", id).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if _, err := db.Exec("INSERT INTO payments (id, invoice_id, amount) VALUES (1, 1, 100)"); err != nil {
		t.Fatal(err)
	}
	if paid(1) != 100 {
		t.Fatalf("fixture: invoice 1 paid = %v, want 100", paid(1))
	}
	// Detach the payment.
	if _, err := db.Exec("UPDATE payments SET invoice_id = NULL WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	if got := paid(1); got != 0 {
		t.Fatalf("a detached payment is still counted on the invoice it left: paid = %v, want 0", got)
	}
	// Attaching it elsewhere counts it once.
	if _, err := db.Exec("UPDATE payments SET invoice_id = 2 WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	if paid(1) != 0 || paid(2) != 100 {
		t.Fatalf("after re-attaching: invoice 1 = %v (want 0), invoice 2 = %v (want 100)", paid(1), paid(2))
	}
	// A plain move between parents still updates both.
	if _, err := db.Exec("UPDATE payments SET invoice_id = 1 WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	if paid(1) != 100 || paid(2) != 0 {
		t.Fatalf("after moving back: invoice 1 = %v (want 100), invoice 2 = %v (want 0)", paid(1), paid(2))
	}
}
