//go:build !cli

package main

import (
	"sort"
	"strings"
	"testing"
)

func extractAndSort(sql string) []string {
	out := ExtractTableRefs(sql)
	sort.Strings(out)
	return out
}

func TestExtractTableRefs_BasicFromAndJoin(t *testing.T) {
	got := extractAndSort(`SELECT a.*, b.name FROM notes a JOIN users b ON a.user_id = b.id`)
	want := []string{"notes", "users"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestExtractTableRefs_UpdateInsert(t *testing.T) {
	got := extractAndSort(`UPDATE notes SET title = 'x' WHERE id = 1`)
	if len(got) != 1 || got[0] != "notes" {
		t.Errorf("UPDATE: got %v", got)
	}
	got = extractAndSort(`INSERT INTO notes (title) VALUES ('x')`)
	if len(got) != 1 || got[0] != "notes" {
		t.Errorf("INSERT: got %v", got)
	}
}

func TestExtractTableRefs_CTE_ExcludesCTEName(t *testing.T) {
	// CTE `active` should NOT appear in refs; `notes` and `users` should.
	sql := `WITH active AS (SELECT id FROM notes WHERE archived = 0)
	        SELECT * FROM active JOIN users ON active.id = users.note_id`
	got := extractAndSort(sql)
	want := []string{"notes", "users"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("CTE: got %v, want %v", got, want)
	}
}

func TestExtractTableRefs_RecursiveCTE(t *testing.T) {
	sql := `WITH RECURSIVE tree AS (
	          SELECT id, parent_id FROM categories WHERE parent_id IS NULL
	          UNION ALL
	          SELECT c.id, c.parent_id FROM categories c JOIN tree ON c.parent_id = tree.id
	        ) SELECT * FROM tree`
	got := extractAndSort(sql)
	if len(got) != 1 || got[0] != "categories" {
		t.Errorf("recursive CTE: tree should be excluded, got %v", got)
	}
}

func TestExtractTableRefs_MultipleCTEs(t *testing.T) {
	sql := `WITH a AS (SELECT * FROM notes), b AS (SELECT * FROM users)
	        SELECT * FROM a JOIN b ON a.id = b.note_id`
	got := extractAndSort(sql)
	want := []string{"notes", "users"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestExtractTableRefs_Subquery_AliasDoesntCount(t *testing.T) {
	// `FROM (SELECT ...) AS t` - t is an alias, not a real table.
	// We should pick up `notes` (the inner FROM) but NOT `t`.
	sql := `SELECT * FROM (SELECT * FROM notes WHERE x = 1) AS t`
	got := extractAndSort(sql)
	if len(got) != 1 || got[0] != "notes" {
		t.Errorf("subquery: got %v, want [notes]", got)
	}
}

func TestExtractTableRefs_QuotedIdentifiers(t *testing.T) {
	// Double-quoted and backtick-quoted identifiers must be unquoted.
	got := extractAndSort(`SELECT * FROM "Notes" JOIN ` + "`Users`" + ` u ON 1=1`)
	want := []string{"notes", "users"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("quoted idents: got %v, want %v", got, want)
	}
}

func TestExtractTableRefs_SchemaQualified(t *testing.T) {
	got := extractAndSort(`SELECT * FROM main.notes WHERE id = 1`)
	if len(got) != 1 || got[0] != "notes" {
		t.Errorf("schema-qualified: got %v", got)
	}
}

func TestExtractTableRefs_NoTablesReferenced(t *testing.T) {
	got := extractAndSort(`SELECT 1`)
	if len(got) != 0 {
		t.Errorf("scalar SELECT shouldn't ref any table: %v", got)
	}
}

func TestExtractTableRefs_CommentsStripped(t *testing.T) {
	sql := `-- pull active notes
	        SELECT * FROM notes /* used by dashboard */ WHERE active = 1`
	got := extractAndSort(sql)
	if len(got) != 1 || got[0] != "notes" {
		t.Errorf("comments: got %v", got)
	}
}

func TestExtractTableRefs_StringLiteralsIgnored(t *testing.T) {
	// `FROM` inside a string literal must not be parsed as a keyword.
	sql := `SELECT 'value from foo' as x, * FROM notes`
	got := extractAndSort(sql)
	if len(got) != 1 || got[0] != "notes" {
		t.Errorf("string literal: got %v", got)
	}
}
