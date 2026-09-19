//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// An earlier app build crashed every FTS5 search with `fts5: syntax
// error near "."` when the user typed an email. escapeFTS5Query wraps
// each token as a phrase so any chars special to FTS5's MATCH syntax
// (`.` `:` `*` `@` `(` `)` `"`) become literal.
func TestEscapeFTS5Query(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"alice", `"alice"`},
		{"alice cooper", `"alice" "cooper"`},
		// The original a real app bug - email-shaped query.
		{"alice.garcia@cyberdyne.ai", `"alice.garcia@cyberdyne.ai"`},
		// Embedded double-quote doubled per FTS5 escape rule.
		{`he said "hi"`, `"he" "said" """hi"""`},
		// UUID-like / dot-laden.
		{"123e4567-e89b-12d3-a456-426614174000", `"123e4567-e89b-12d3-a456-426614174000"`},
		// Multi-space collapses cleanly.
		{"  multi   space   ", `"multi" "space"`},
		// Empty → empty (caller should skip the MATCH entirely).
		{"", ""},
		{"   ", ""},
	}
	for _, c := range cases {
		got := escapeFTS5Query(c.in)
		if got != c.want {
			t.Errorf("%q → %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFTSTrigramUsable(t *testing.T) {
	usable := []string{"test", "abc", "john smith", "abcd efg hij"}
	fallback := []string{"ab", "a", "x y", "ab cdef", "abcd ef gh", ""}
	for _, q := range usable {
		if !ftsTrigramUsable(q) {
			t.Errorf("ftsTrigramUsable(%q) = false, want true", q)
		}
	}
	for _, q := range fallback {
		if ftsTrigramUsable(q) {
			t.Errorf("ftsTrigramUsable(%q) = true, want false", q)
		}
	}
}

func TestBuildFTSLikeFallback_EscapesWildcards(t *testing.T) {
	clause, args := buildFTSLikeFallback("contacts", []string{"name", "email"}, "a%_x")
	if clause != `(contacts.name LIKE ? ESCAPE '\' OR contacts.email LIKE ? ESCAPE '\')` {
		t.Errorf("clause = %q", clause)
	}
	if len(args) != 2 || args[0] != `%a\%\_x%` {
		t.Errorf("args = %v (wildcards should be escaped literal)", args)
	}
}

// The core fix: trigram tokenizer → SUBSTRING search. Pre-fix, ?q=test matched
// only a standalone "test" token; now it matches "testing", "contest", etc.
func TestEnsureFTS_TrigramSubstringSearch(t *testing.T) {
	db := openFTSTestDB(t)
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE proj (id INTEGER PRIMARY KEY, name TEXT)`); err != nil {
		t.Fatal(err)
	}
	tables := []Table{{Name: "proj", FullText: [][]string{{"name"}}}}
	EnsureFTSTables(db, tables)

	// Confirm the FTS table is trigram.
	var ftsSQL string
	db.QueryRow(`SELECT sql FROM sqlite_master WHERE name='proj_fts'`).Scan(&ftsSQL)
	if !strings.Contains(strings.ToLower(ftsSQL), "trigram") {
		t.Fatalf("proj_fts not trigram: %s", ftsSQL)
	}

	for _, name := range []string{"test alpha", "Testing Beta", "contest gamma", "unrelated"} {
		if _, err := db.Exec(`INSERT INTO proj (name) VALUES (?)`, name); err != nil {
			t.Fatal(err)
		}
	}

	got := ftsMatchNames(t, db, "test") // substring + case-insensitive
	want := map[string]bool{"test alpha": true, "Testing Beta": true, "contest gamma": true}
	if len(got) != 3 {
		t.Fatalf("q=test matched %d rows, want 3 (substring): %v", len(got), got)
	}
	for _, n := range got {
		if !want[n] {
			t.Errorf("unexpected match %q", n)
		}
	}
}

// Legacy (non-trigram) FTS tables are migrated to trigram on EnsureFTSTables.
func TestEnsureFTS_MigratesLegacyToTrigram(t *testing.T) {
	db := openFTSTestDB(t)
	defer db.Close()
	db.Exec(`CREATE TABLE proj (id INTEGER PRIMARY KEY, name TEXT)`)
	// Pre-create a LEGACY (default-tokenizer) FTS table, as older versions did.
	if _, err := db.Exec(`CREATE VIRTUAL TABLE proj_fts USING fts5(name, content='proj', content_rowid='id')`); err != nil {
		t.Fatal(err)
	}
	EnsureFTSTables(db, []Table{{Name: "proj", FullText: [][]string{{"name"}}}})
	var ftsSQL string
	db.QueryRow(`SELECT sql FROM sqlite_master WHERE name='proj_fts'`).Scan(&ftsSQL)
	if !strings.Contains(strings.ToLower(ftsSQL), "trigram") {
		t.Errorf("legacy FTS not migrated to trigram: %s", ftsSQL)
	}
}

func ftsMatchNames(t *testing.T, db *sql.DB, q string) []string {
	t.Helper()
	rows, err := db.Query(
		`SELECT name FROM proj WHERE proj.id IN (SELECT rowid FROM proj_fts WHERE proj_fts MATCH ?)`,
		escapeFTS5Query(q))
	if err != nil {
		t.Fatalf("match query: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		rows.Scan(&n)
		out = append(out, n)
	}
	return out
}

func openFTSTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "fts.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return db
}
