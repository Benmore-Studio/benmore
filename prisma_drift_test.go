//go:build !cli

package main

// Tests for the schema drift detector. The detector compares declared
// Prisma models against the live SQLite schema and reports each
// difference. We exercise each drift kind in isolation.

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func openTestDriftDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestDetectSchemaDrift_AllInSync(t *testing.T) {
	db := openTestDriftDB(t)
	defer db.Close()
	_, _ = db.Exec(`CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL)`)
	models := []PrismaModel{{
		Name: "Note", Table: "notes",
		Fields: []PrismaField{
			{Name: "id", Column: "id", Type: "INTEGER", IsID: true, Autoincr: true},
			{Name: "title", Column: "title", Type: "TEXT"},
		},
	}}
	drifts, err := DetectSchemaDrift(db, models)
	if err != nil {
		t.Fatal(err)
	}
	if len(drifts) != 0 {
		t.Errorf("expected no drift, got: %v", drifts)
	}
}

func TestDetectSchemaDrift_MissingTable(t *testing.T) {
	db := openTestDriftDB(t)
	defer db.Close()
	models := []PrismaModel{{Name: "Note", Table: "notes",
		Fields: []PrismaField{{Column: "id", Type: "INTEGER"}}}}
	drifts, _ := DetectSchemaDrift(db, models)
	if len(drifts) != 1 || drifts[0].Kind != "missing_table" {
		t.Errorf("expected missing_table, got %v", drifts)
	}
}

func TestDetectSchemaDrift_ExtraTable(t *testing.T) {
	db := openTestDriftDB(t)
	defer db.Close()
	_, _ = db.Exec(`CREATE TABLE orphan (id INTEGER)`)
	drifts, _ := DetectSchemaDrift(db, nil)
	if len(drifts) != 1 || drifts[0].Kind != "extra_table" {
		t.Errorf("expected extra_table, got %v", drifts)
	}
}

func TestDetectSchemaDrift_SystemTablesExempt(t *testing.T) {
	// _benmore_ and sqlite_ prefixed tables are framework-/sqlite-
	// owned; agents don't declare them in schema.prisma. They must
	// NOT show up as drift.
	db := openTestDriftDB(t)
	defer db.Close()
	_, _ = db.Exec(`CREATE TABLE _benmore_users (id INTEGER)`)
	_, _ = db.Exec(`CREATE TABLE notes (id INTEGER)`)
	models := []PrismaModel{{Name: "Note", Table: "notes",
		Fields: []PrismaField{{Column: "id", Type: "INTEGER"}}}}
	drifts, _ := DetectSchemaDrift(db, models)
	for _, d := range drifts {
		if strings.HasPrefix(d.Table, "_benmore_") {
			t.Errorf("framework table flagged as drift: %v", d)
		}
	}
}

func TestDetectSchemaDrift_FTSShadowTablesExempt(t *testing.T) {
	// SQLite FTS5 creates five auxiliary tables around any virtual
	// <parent>_fts table the framework provisions for an @@fulltext
	// declaration. Those auxiliaries (<parent>_fts_data, _fts_idx,
	// _fts_config, _fts_docsize, plus the virtual <parent>_fts
	// itself) must NOT show up as orphan drift — the a real app
	// audit produced 10 false positives and threatened a `prisma_prune`
	// that would have destroyed the FTS indexes.
	db := openTestDriftDB(t)
	defer db.Close()
	_, _ = db.Exec(`CREATE TABLE articles (id INTEGER, title TEXT, body TEXT)`)
	for _, t := range []string{
		"articles_fts", "articles_fts_data", "articles_fts_idx",
		"articles_fts_config", "articles_fts_docsize",
	} {
		_, _ = db.Exec(`CREATE TABLE "` + t + `" (id INTEGER)`)
	}
	models := []PrismaModel{{
		Name:  "Article",
		Table: "articles",
		Fields: []PrismaField{
			{Column: "id", Type: "INTEGER"},
			{Column: "title", Type: "TEXT"},
			{Column: "body", Type: "TEXT"},
		},
		FullText: []PrismaIndex{{Columns: []string{"title", "body"}}},
	}}
	drifts, _ := DetectSchemaDrift(db, models)
	for _, d := range drifts {
		if strings.Contains(d.Table, "_fts") {
			t.Errorf("FTS5 shadow table flagged as drift: %v", d)
		}
	}
}

// A table that happens to end in _fts but whose parent didn't declare
// @@fulltext is NOT a shadow table — it must still surface as drift so
// agents don't silently lose an orphan.
func TestDetectSchemaDrift_FTSSuffixWithoutFulltextParent(t *testing.T) {
	db := openTestDriftDB(t)
	defer db.Close()
	_, _ = db.Exec(`CREATE TABLE notes_fts_idx (id INTEGER)`)
	// No declared model for `notes` (or anything else).
	drifts, _ := DetectSchemaDrift(db, nil)
	found := false
	for _, d := range drifts {
		if d.Table == "notes_fts_idx" && d.Kind == "extra_table" {
			found = true
		}
	}
	if !found {
		t.Errorf("name with _fts suffix but no @@fulltext parent should still drift: %v", drifts)
	}
}

func TestDetectSchemaDrift_MissingColumn(t *testing.T) {
	db := openTestDriftDB(t)
	defer db.Close()
	_, _ = db.Exec(`CREATE TABLE notes (id INTEGER PRIMARY KEY)`)
	models := []PrismaModel{{Name: "Note", Table: "notes",
		Fields: []PrismaField{
			{Column: "id", Type: "INTEGER"},
			{Column: "title", Type: "TEXT"},
		}}}
	drifts, _ := DetectSchemaDrift(db, models)
	if len(drifts) != 1 || drifts[0].Kind != "missing_column" || drifts[0].Column != "title" {
		t.Errorf("expected missing_column for title, got %v", drifts)
	}
}

func TestDetectSchemaDrift_ExtraColumn(t *testing.T) {
	db := openTestDriftDB(t)
	defer db.Close()
	_, _ = db.Exec(`CREATE TABLE notes (id INTEGER PRIMARY KEY, surprise TEXT)`)
	models := []PrismaModel{{Name: "Note", Table: "notes",
		Fields: []PrismaField{
			{Column: "id", Type: "INTEGER"},
		}}}
	drifts, _ := DetectSchemaDrift(db, models)
	if len(drifts) != 1 || drifts[0].Kind != "extra_column" || drifts[0].Column != "surprise" {
		t.Errorf("expected extra_column for surprise, got %v", drifts)
	}
}

func TestDetectSchemaDrift_TypeMismatch(t *testing.T) {
	db := openTestDriftDB(t)
	defer db.Close()
	_, _ = db.Exec(`CREATE TABLE notes (id INTEGER, body BLOB)`)
	models := []PrismaModel{{Name: "Note", Table: "notes",
		Fields: []PrismaField{
			{Column: "id", Type: "INTEGER"},
			{Column: "body", Type: "TEXT"},
		}}}
	drifts, _ := DetectSchemaDrift(db, models)
	found := false
	for _, d := range drifts {
		if d.Kind == "type_mismatch" && d.Column == "body" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected type_mismatch on body, got %v", drifts)
	}
}

func TestSQLiteTypesMatch_LooseAffinity(t *testing.T) {
	// SQLite is loose about types. INTEGER and INT should match.
	cases := []struct {
		declared, live string
		want           bool
	}{
		{"INTEGER", "INT", true},
		{"INTEGER", "INTEGER", true},
		{"TEXT", "VARCHAR(255)", true},
		{"TEXT", "CLOB", true},
		{"REAL", "FLOAT", true},
		{"DATETIME", "TEXT", true}, // SQLite stores DATETIME as TEXT
		{"INTEGER", "TEXT", false},
		{"BLOB", "TEXT", false},
	}
	for _, c := range cases {
		if got := sqliteTypesMatch(c.declared, c.live); got != c.want {
			t.Errorf("sqliteTypesMatch(%q, %q) = %v, want %v", c.declared, c.live, got, c.want)
		}
	}
}

func TestFormatDriftReport_Clean(t *testing.T) {
	report := FormatDriftReport(nil)
	if !strings.Contains(report, "no schema drift") {
		t.Errorf("clean report should say so, got: %s", report)
	}
}

func TestFormatDriftReport_Multi(t *testing.T) {
	report := FormatDriftReport([]SchemaDrift{
		{Kind: "missing_table", Table: "notes", Detail: "not in db"},
		{Kind: "extra_column", Table: "users", Column: "extra", Detail: "manual ALTER?"},
	})
	for _, want := range []string{"2 issue", "missing_table", "extra_column", "users.extra"} {
		if !strings.Contains(report, want) {
			t.Errorf("missing %q in:\n%s", want, report)
		}
	}
}
