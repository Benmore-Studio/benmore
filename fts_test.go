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
	if err := EnsureFTSTables(db, tables); err != nil {
		t.Fatal(err)
	}

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
	if err := EnsureFTSTables(db, []Table{{Name: "proj", FullText: [][]string{{"name"}}}}); err != nil {
		t.Fatal(err)
	}
	var ftsSQL string
	db.QueryRow(`SELECT sql FROM sqlite_master WHERE name='proj_fts'`).Scan(&ftsSQL)
	if !strings.Contains(strings.ToLower(ftsSQL), "trigram") {
		t.Errorf("legacy FTS not migrated to trigram: %s", ftsSQL)
	}
}

func TestEnsureFTSUnchangedIndexNeedsNoWrites(t *testing.T) {
	db := openFTSTestDB(t)
	defer db.Close()
	db.SetMaxOpenConns(1)
	mustExec(t, db, "CREATE TABLE proj(id INTEGER PRIMARY KEY, name TEXT)")
	mustExec(t, db, "INSERT INTO proj VALUES(1, 'original')")
	tables := []Table{{Name: "proj", FullText: [][]string{{"name"}}}}
	if err := EnsureFTSTables(db, tables); err != nil {
		t.Fatal(err)
	}
	var before, after int64
	if err := db.QueryRow("SELECT total_changes()").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := EnsureFTSTables(db, tables); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT total_changes()").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("unchanged index rewrote rows: before=%d after=%d", before, after)
	}
	var path string
	if err := db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path); err != nil {
		t.Fatal(err)
	}
	readOnly, err := sql.Open("sqlite3", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	if err := EnsureFTSTables(readOnly, tables); err != nil {
		t.Fatalf("unchanged startup required writes: %v", err)
	}
	if got := ftsMatchNames(t, readOnly, "original"); len(got) != 1 {
		t.Fatalf("reopened index lost data: %v", got)
	}
	mustExec(t, db, "UPDATE proj SET name='replacement' WHERE id=1")
	if got := ftsMatchNames(t, db, "replacement"); len(got) != 1 {
		t.Fatalf("update trigger stopped maintaining index: %v", got)
	}
	if got := ftsMatchNames(t, db, "original"); len(got) != 0 {
		t.Fatalf("old term remained indexed: %v", got)
	}
	mustExec(t, db, "DELETE FROM proj WHERE id=1")
	if got := ftsMatchNames(t, db, "replacement"); len(got) != 0 {
		t.Fatalf("delete trigger stopped maintaining index: %v", got)
	}
}

func TestEnsureFTSReconcilesColumnsAndRepairsTriggerGaps(t *testing.T) {
	db := openFTSTestDB(t)
	defer db.Close()
	mustExec(t, db, "CREATE TABLE proj(id INTEGER PRIMARY KEY, name TEXT, body TEXT)")
	mustExec(t, db, "INSERT INTO proj VALUES(1, 'original', 'hidden unicorn')")
	if err := EnsureFTSTables(db, []Table{{Name: "proj", FullText: [][]string{{"name"}}}}); err != nil {
		t.Fatal(err)
	}
	tables := []Table{{Name: "proj", FullText: [][]string{{"body"}}}}
	if err := EnsureFTSTables(db, tables); err != nil {
		t.Fatal(err)
	}
	if got := ftsMatchNames(t, db, "unicorn"); len(got) != 1 {
		t.Fatalf("changed columns were not rebuilt: %v", got)
	}
	if got := ftsMatchNames(t, db, "original"); len(got) != 0 {
		t.Fatalf("removed column remains searchable: %v", got)
	}
	mustExec(t, db, "DROP TRIGGER proj_fts_ai")
	mustExec(t, db, "INSERT INTO proj VALUES(2, 'gap', 'missed dragon')")
	if got := ftsMatchNames(t, db, "dragon"); len(got) != 0 {
		t.Fatal("fixture did not leave an indexing gap")
	}
	if err := EnsureFTSTables(db, tables); err != nil {
		t.Fatal(err)
	}
	if got := ftsMatchNames(t, db, "dragon"); len(got) != 1 {
		t.Fatalf("trigger repair did not recover missed rows: %v", got)
	}
	mustExec(t, db, "INSERT INTO proj VALUES(3, 'after repair', 'new phoenix')")
	if got := ftsMatchNames(t, db, "phoenix"); len(got) != 1 {
		t.Fatalf("repaired insert trigger failed: %v", got)
	}
}

func TestEnsureFTSFailedRebuildPreservesPreviousIndex(t *testing.T) {
	db := openFTSTestDB(t)
	defer db.Close()
	mustExec(t, db, "CREATE TABLE proj(id INTEGER PRIMARY KEY, name TEXT)")
	mustExec(t, db, "INSERT INTO proj VALUES(1, 'original')")
	tables := []Table{{Name: "proj", FullText: [][]string{{"name"}}}}
	if err := EnsureFTSTables(db, tables); err != nil {
		t.Fatal(err)
	}
	if err := EnsureFTSTables(db, []Table{{Name: "proj", FullText: [][]string{{"missing_column"}}}}); err == nil {
		t.Fatal("rebuild with a missing source column reported success")
	}
	if got := ftsMatchNames(t, db, "original"); len(got) != 1 {
		t.Fatalf("failed rebuild destroyed old index: %v", got)
	}
	mustExec(t, db, "INSERT INTO proj VALUES(2, 'after rollback')")
	if got := ftsMatchNames(t, db, "rollback"); len(got) != 1 {
		t.Fatalf("failed rebuild destroyed old triggers: %v", got)
	}
	if err := EnsureFTSTables(db, tables); err != nil {
		t.Fatalf("retry after rollback failed: %v", err)
	}
}

func TestEnsureFTSRefusesOrdinaryTableCollision(t *testing.T) {
	db := openFTSTestDB(t)
	defer db.Close()
	mustExec(t, db, "CREATE TABLE proj(id INTEGER PRIMARY KEY, name TEXT)")
	mustExec(t, db, "CREATE TABLE proj_fts(id INTEGER PRIMARY KEY, valuable TEXT)")
	mustExec(t, db, "INSERT INTO proj_fts VALUES(1, 'preserve')")
	if err := EnsureFTSTables(db, []Table{{Name: "proj", FullText: [][]string{{"name"}}}}); err == nil {
		t.Fatal("ordinary table collision reported success")
	}
	var value string
	if err := db.QueryRow("SELECT valuable FROM proj_fts WHERE id=1").Scan(&value); err != nil || value != "preserve" {
		t.Fatalf("ordinary table was replaced: value=%q err=%v", value, err)
	}
}

func TestEnsureFTSRefusesContentOwningFTSCollision(t *testing.T) {
	db := openFTSTestDB(t)
	defer db.Close()
	mustExec(t, db, "CREATE TABLE proj(id INTEGER PRIMARY KEY, name TEXT)")
	mustExec(t, db, "CREATE VIRTUAL TABLE proj_fts USING fts5(name)")
	mustExec(t, db, "INSERT INTO proj_fts VALUES('preserve independently stored content')")
	if err := EnsureFTSTables(db, []Table{{Name: "proj", FullText: [][]string{{"name"}}}}); err == nil {
		t.Fatal("content-owning FTS table collision reported success")
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM proj_fts WHERE proj_fts MATCH 'preserve'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("content-owning FTS table was replaced: count=%d err=%v", count, err)
	}
}

func TestFTSFailureRejectsStartupAndReload(t *testing.T) {
	for _, mode := range []string{"startup", "reload"} {
		t.Run(mode, func(t *testing.T) {
			app, cleanup := newTestApp(t)
			defer cleanup()
			app.Stop = make(chan struct{})
			defer close(app.Stop)
			app.Tables = []Table{{Name: "previous"}}
			mustExec(t, app.DB, "CREATE TABLE proj(id INTEGER PRIMARY KEY, name TEXT)")
			mustExec(t, app.DB, "CREATE TABLE proj_fts(valuable TEXT)")
			writeTestFile(t, app.Dir, "schema.prisma", `model Proj {
  id Int @id @default(autoincrement())
  name String?
  @@map("proj")
  @@fulltext([name])
}
`)
			var err error
			if mode == "startup" {
				_, err = loadApp(app.Dir)
			} else {
				err = hotReloadApp(app, false)
				if len(app.Tables) != 1 || app.Tables[0].Name != "previous" {
					t.Fatal("failed FTS initialization published the new schema")
				}
				select {
				case <-app.Stop:
					t.Fatal("failed FTS initialization stopped existing workers")
				default:
				}
			}
			if err == nil || !strings.Contains(err.Error(), "fts proj") {
				t.Fatalf("%s hid FTS initialization failure: %v", mode, err)
			}
		})
	}
}

func TestFTSStartupAndReloadRunAfterColumnMigrations(t *testing.T) {
	for _, mode := range []string{"startup", "reload"} {
		t.Run(mode, func(t *testing.T) {
			app, cleanup := newTestApp(t)
			defer cleanup()
			mustExec(t, app.DB, "CREATE TABLE proj(id INTEGER PRIMARY KEY, name TEXT)")
			mustExec(t, app.DB, "INSERT INTO proj VALUES(1, 'original')")
			writeTestFile(t, app.Dir, "schema.prisma", `model Proj {
  id Int @id @default(autoincrement())
  name String?
  body String @default("searchable")
  @@map("proj")
  @@fulltext([name, body])
}
`)
			if mode == "startup" {
				loaded, err := loadApp(app.Dir)
				if err != nil {
					t.Fatal(err)
				}
				defer loaded.Shutdown()
			} else if err := reloadAppConfig(app); err != nil {
				t.Fatal(err)
			}
			if got := ftsMatchNames(t, app.DB, "searchable"); len(got) != 1 {
				t.Fatalf("new source column was not indexed on first %s: %v", mode, got)
			}
		})
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
