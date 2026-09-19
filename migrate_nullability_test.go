//go:build !cli

package main

import (
	"database/sql"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// TestMigrate_NullabilityChange locks the fix for the silent NOT NULL → NULL
// gap: the migrator must (a) NOTICE the divergence (not silently skip it),
// (b) block it by default, and (c) on --force rebuild the table so the column
// actually becomes nullable, preserving existing rows.
func TestMigrate_NullabilityChange(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Live DB: project_id is NOT NULL.
	if _, err := db.Exec(`CREATE TABLE leads (id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, name TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO leads (project_id, name) VALUES (5, 'acme')`); err != nil {
		t.Fatal(err)
	}

	// Schema now declares project_id nullable (Int?).
	schema := []Table{{
		Name: "leads",
		Columns: []Column{
			{Name: "id", Type: "INTEGER", PK: true},
			{Name: "project_id", Type: "INTEGER", NotNull: false},
			{Name: "name", Type: "TEXT"},
		},
	}}

	// (a) + (b): default migrate must NOTICE + BLOCK, and NOT change the DB.
	res, err := Migrate(db, schema, false)
	if err != nil {
		t.Fatalf("Migrate(force=false): %v", err)
	}
	if !hasSubstr(res.Blocked, "project_id nullability") {
		t.Fatalf("expected a nullability notice in Blocked, got: %v", res.Blocked)
	}
	if _, err := db.Exec(`INSERT INTO leads (project_id, name) VALUES (NULL, 'still-not-null')`); err == nil {
		t.Fatal("expected NULL insert to still fail before --force rebuild")
	}

	// (c): forced migrate rebuilds → column becomes nullable, row preserved.
	res, err = Migrate(db, schema, true)
	if err != nil {
		t.Fatalf("Migrate(force=true): %v", err)
	}
	if !hasSubstr(res.Added, "REBUILD") {
		t.Fatalf("expected a REBUILD entry in Added, got: %v", res.Added)
	}
	if _, err := db.Exec(`INSERT INTO leads (project_id, name) VALUES (NULL, 'now-nullable')`); err != nil {
		t.Fatalf("NULL insert should succeed after rebuild: %v", err)
	}
	var name string
	if err := db.QueryRow(`SELECT name FROM leads WHERE project_id = 5`).Scan(&name); err != nil || name != "acme" {
		t.Fatalf("original row lost after rebuild (name=%q, err=%v)", name, err)
	}

	// Idempotent: a second forced migrate finds nothing more to rebuild.
	res, _ = Migrate(db, schema, true)
	if hasSubstr(res.Added, "REBUILD") {
		t.Fatalf("rebuild should not recur once applied, got: %v", res.Added)
	}
}

func hasSubstr(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
