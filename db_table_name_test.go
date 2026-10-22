//go:build !cli

package main

import "testing"

// Table names from routes and tool arguments must be plain identifiers
// before they reach PRAGMA text.
func TestTableIntrospectionRejectsNonIdentifiers(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT)")

	if cols, err := GetTableColumns(app.DB, "notes"); err != nil || len(cols) != 2 {
		t.Fatalf("valid table: cols=%v err=%v", cols, err)
	}
	if _, err := GetForeignKeys(app.DB, "notes"); err != nil {
		t.Fatalf("valid table foreign keys: %v", err)
	}
	for _, name := range []string{"", "notes)", "notes; SELECT 1", "no tes", "notes--", `"notes"`} {
		if _, err := GetTableColumns(app.DB, name); err == nil {
			t.Fatalf("GetTableColumns(%q) must be refused", name)
		}
		if _, err := GetForeignKeys(app.DB, name); err == nil {
			t.Fatalf("GetForeignKeys(%q) must be refused", name)
		}
	}
}
