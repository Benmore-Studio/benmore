//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// computed.yaml names are written into trigger DDL. One that is not a plain
// identifier never gets there: the write gate refuses it (it is not a table
// or column of the app), and the load refuses it before it builds any trigger
// text (computedFieldIdentError). A reserved word is a plain identifier; it
// is accepted and written quoted (testdata/reserved_word_columns).
func TestComputedNamesThatAreNotIdentifiersAreRefused(t *testing.T) {
	aggregate := func(table, fk string) string {
		return "fields:\n  - table: habits\n    column: note\n    sql: \"SELECT COUNT(*) FROM tags WHERE habit_id = ?\"\n    triggers:\n      - table: \"" + table + "\"\n        on: [insert, update, delete]\n        fk: \"" + fk + "\"\n"
	}
	expr := func(table, column string) string {
		return "fields:\n  - table: \"" + table + "\"\n    column: \"" + column + "\"\n    expr: \"1\"\n"
	}
	for _, tc := range []struct{ name, content, gate, load string }{
		{"trigger fk", aggregate("tags", "habit_id IS NOT NULL OR 1"), `names fk "habit_id IS NOT NULL OR 1"`, `computed.yaml: trigger fk "habit_id IS NOT NULL OR 1" is not a plain identifier`},
		{"trigger table", aggregate("tags; DROP TABLE habits", "habit_id"), `changes to the table "tags; DROP TABLE habits"`, `computed.yaml: trigger table "tags; DROP TABLE habits" is not a plain identifier`},
		{"column", expr("habits", "note = 'x', name"), `habits has no column "note = 'x', name"`, `computed.yaml: column "note = 'x', name" is not a plain identifier`},
		{"table", expr("habits; DROP TABLE tags", "note"), `computed on the table "habits; DROP TABLE tags"`, `computed.yaml: table "habits; DROP TABLE tags" is not a plain identifier`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := loadRefsApp(t, nil)
			if msg := ValidateOnWriteIn(dir, "computed.yaml", tc.content); !strings.Contains(msg, tc.gate) {
				t.Fatalf("the write gate accepted or misnamed it:\n%s\nwant %q", msg, tc.gate)
			}
			writeTestFile(t, dir, "computed.yaml", tc.content)
			if got := sourceErrorFor(dir, "computed.yaml"); !strings.Contains(got, tc.gate) {
				t.Errorf("benmore check has no error on computed.yaml for it; got %q", got)
			}
			if err := loadRefsLoad(t, dir); err == nil || !strings.Contains(err.Error(), tc.load) {
				t.Fatalf("load error = %v, want %q", err, tc.load)
			}
			db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var tables, triggers int
			if err := db.QueryRow(`SELECT SUM(type = 'table' AND name IN ('habits', 'tags')), SUM(type = 'trigger' AND name LIKE '\_benmore\_cf\_%' ESCAPE '\') FROM sqlite_master`).Scan(&tables, &triggers); err != nil {
				t.Fatal(err)
			}
			if tables != 2 || triggers != 0 {
				t.Fatalf("after the refused load: %d of the 2 tables, %d computed triggers", tables, triggers)
			}
		})
	}
}
