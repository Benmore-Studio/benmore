//go:build !cli && !windows

package main

import (
	"database/sql"
	"reflect"
	"testing"
)

func revisionTriggerNames(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name=? AND substr(name,1,17)='_benmore_mcp_rev_' ORDER BY name`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	return names
}

// F09.2: SQLite drops a table's triggers with DROP TABLE, so every table-rebuild
// path must replay the connector revision triggers or writes go untracked.
func TestAppMCPRevisionTriggersSurviveForcedMigratorRebuild(t *testing.T) {
	for name, rebuild := range map[string]func(*testing.T, *sql.DB){
		"nullability rebuild": func(t *testing.T, db *sql.DB) {
			schema := []Table{{Name: "notes", Columns: []Column{{Name: "id", Type: "INTEGER", PK: true}, {Name: "title", Type: "TEXT", NotNull: true}}}}
			if _, err := Migrate(db, schema, true); err != nil {
				t.Fatalf("forced migration: %v", err)
			}
		},
		"column type change": func(t *testing.T, db *sql.DB) {
			if err := AlterColumnType(db, "notes", "title", "TEXT NOT NULL"); err != nil {
				t.Fatalf("type change: %v", err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			db := newAppMCPReadConnectionTestDB(t)
			seedRevisionNote(t, db)
			initRevisionStorage(t, db, "notes")
			before := revisionTriggerNames(t, db, "notes")
			if len(before) == 0 {
				t.Fatal("fixture installed no revision triggers")
			}
			rebuild(t, db)
			if after := revisionTriggerNames(t, db, "notes"); !reflect.DeepEqual(before, after) {
				t.Fatalf("rebuild lost revision triggers: before=%v after=%v", before, after)
			}
			// Writes after the rebuild are still tracked.
			if _, err := db.Exec(`INSERT INTO notes(id,title) VALUES(2,'after rebuild')`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`UPDATE notes SET title='changed' WHERE id=1`); err != nil {
				t.Fatal(err)
			}
			if _, revision, _ := appMCPRevisionRow(t, db, "notes", "integer", "2"); revision != 1 {
				t.Fatalf("insert after rebuild untracked: revision=%d", revision)
			}
			if _, revision, _ := appMCPRevisionRow(t, db, "notes", "integer", "1"); revision != 2 {
				t.Fatalf("update after rebuild untracked: revision=%d", revision)
			}
			// The table schema changed, so the reviewed registry is stale and the
			// preflight fails closed until explicit repair reinitializes it.
			if err := verifyRevisionStorage(t, db, "notes"); err == nil {
				t.Fatal("stale revision registry still verified after the table was rebuilt")
			}
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if err := repairAppMCPRevisionStorage(tx, []string{"notes"}); err != nil {
				t.Fatalf("explicit repair after rebuild: %v", err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			if err := verifyRevisionStorage(t, db, "notes"); err != nil {
				t.Fatalf("storage did not verify after repair: %v", err)
			}
		})
	}
}
