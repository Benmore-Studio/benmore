//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// hostileNames are the names a migration or a raw schema file can legitimately
// create (and that an app author could put in config). Each one, spliced into
// SQL text without identifier quoting, changes the statement: a double quote
// closes a quoted name, a backslash and `;` end the statement, a space or a
// keyword-shaped name parses as several tokens. Go's %q quoting is not SQL
// identifier quoting - `a"; --` formatted with %q reads as table `a\`
// followed by an empty statement, which the driver's query path cannot run
// (and took the process down before release 2.7.268). quoteIdent writes the
// same text as before for an ordinary name and the right one for any other.
var hostileNames = []string{
	`a"; --`,
	`a\`,
	`x; DROP TABLE t; --`,
	`a b`,
	`"quoted"`,
	strings.Repeat("c", 300),
}

func TestQuoteIdentRoundTrips(t *testing.T) {
	// An ordinary name is written exactly as a bare name would be, so a plain
	// app's SQL text is unchanged at every quoteIdent call site.
	if got := quoteIdent("members"); got != `"members"` {
		t.Fatalf("quoteIdent(members) = %q, want \"members\"", got)
	}
	if got := quoteColumn("members", "email"); got != `"members"."email"` {
		t.Fatalf("quoteColumn = %q", got)
	}

	// Every hostile name survives a create/read round-trip through a quoted
	// identifier: the statement stays one statement, addresses that table,
	// and the process survives.
	db, err := sql.Open("sqlite3_benmore", filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, name := range hostileNames {
		col := name + "_c"
		if _, err := db.Exec("CREATE TABLE " + quoteIdent(name) + " (id INTEGER PRIMARY KEY, " + quoteIdent(col) + " TEXT)"); err != nil {
			t.Fatalf("create %q: %v", name, err)
		}
		if _, err := db.Exec("INSERT INTO " + quoteIdent(name) + " DEFAULT VALUES"); err != nil {
			t.Fatalf("insert %q: %v", name, err)
		}
		var n int64
		if err := db.QueryRow("SELECT COUNT(*) FROM " + quoteIdent(name)).Scan(&n); err != nil || n != 1 {
			t.Fatalf("count %q = %d (%v), want 1", name, n, err)
		}
		// The same name as a column reference, qualified.
		var c sql.NullString
		if err := db.QueryRow("SELECT " + quoteColumn(name, col) + " FROM " + quoteIdent(name)).Scan(&c); err != nil {
			t.Fatalf("select column of %q: %v", name, err)
		}
	}
}

func TestQuoteDeclType(t *testing.T) {
	// Ordinary declared types pass through unchanged (byte-identical DDL for a
	// plain app).
	for _, ok := range []string{"TEXT", "INTEGER", "REAL", "DATETIME", "VARCHAR(255)", "DECIMAL(10,2)", "DOUBLE PRECISION", ""} {
		if got := quoteDeclType(ok); got != ok {
			t.Errorf("quoteDeclType(%q) = %q, want unchanged", ok, got)
		}
	}
	// A type that is really an injection is written as one quoted token, so it
	// cannot end the CREATE and start another statement.
	evil := `INTEGER); DROP TABLE t; --`
	got := quoteDeclType(evil)
	if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `"`) || strings.Contains(got[1:len(got)-1], `";`) {
		t.Fatalf("quoteDeclType(%q) = %q, not a single quoted token", evil, got)
	}
	// It is still usable as a column type (SQLite takes any text as a type).
	db, err := sql.Open("sqlite3_benmore", filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE t (id INTEGER PRIMARY KEY, c " + got + ")"); err != nil {
		t.Fatalf("create with quoted type: %v", err)
	}
	var tables int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table'").Scan(&tables); err != nil || tables != 1 {
		t.Fatalf("exactly one table should exist (the DROP must not have run): %d (%v)", tables, err)
	}
}

func TestConfigIdentError(t *testing.T) {
	for _, ok := range []string{"members", "org_id", "_benmore_users", "Name", "a1"} {
		if err := configIdentError("x", ok); err != nil {
			t.Errorf("configIdentError rejected a plain identifier %q: %v", ok, err)
		}
	}
	// Punctuation, spaces, empties and dotted/qualified names are not plain
	// identifiers. (A 300-letter name IS a valid identifier, so it is tested
	// by the quoting round-trip above, not here.)
	for _, bad := range []string{`a"; --`, `a\`, `x; DROP TABLE t; --`, `a b`, `"quoted"`, "", "1col", "a.b", "a-b", "main.members"} {
		if err := configIdentError("x", bad); err == nil {
			t.Errorf("configIdentError accepted a non-identifier %q", bad)
		}
	}
}

// Config that names a SQL identifier is refused at load when the value is not
// a plain identifier. On origin/main these values were accepted (groups
// checked only non-empty; the encrypted/retention/workflow table and column
// names were not identifier-checked), so each sub-case fails there.
func TestConfigLoadRefusesNonIdentifierNames(t *testing.T) {
	cases := map[string]string{
		"groups.table":     "groups:\n  table: 'a\"; --'\n  key: org_id\n  user_field: email\n",
		"groups.key":       "groups:\n  table: members\n  key: 'a b'\n  user_field: email\n",
		"groups.userf":     "groups:\n  table: members\n  key: org_id\n  user_field: 'x; DROP TABLE t; --'\n",
		"groups.rolef":     "groups:\n  table: members\n  key: org_id\n  user_field: email\n  role_field: 'a\"b'\n",
		"groups.bootorg":   "groups:\n  table: members\n  key: org_id\n  user_field: email\n  bootstrap: { org_table: 'a b' }\n",
		"encrypted inline": "encrypted:\n  'a\"; --':\n    - ssn\n",
		"encrypted col":    "encrypted:\n  contacts:\n    - 'a b'\n",
	}
	for name, body := range cases {
		if _, _, err := parseAppConfigDocument([]byte(body)); err == nil {
			t.Errorf("%s: parseAppConfigDocument accepted a non-identifier", name)
		}
	}

	// A plain app.yaml with the same shape still loads.
	plain := "groups:\n  table: members\n  key: org_id\n  user_field: email\n  role_field: member_role\n  bootstrap: { org_table: orgs }\nencrypted:\n  contacts:\n    - ssn\n"
	if _, _, err := parseAppConfigDocument([]byte(plain)); err != nil {
		t.Fatalf("plain app.yaml refused: %v", err)
	}
}

func TestEncryptedYAMLRefusesNonIdentifierNames(t *testing.T) {
	if validateEncryptedYAML("tables:\n  'a\"; --':\n    fields: [ssn]\n") == "" {
		t.Error("encrypted.yaml with a non-identifier table name was accepted")
	}
	if validateEncryptedYAML("tables:\n  patients:\n    fields: ['a b']\n") == "" {
		t.Error("encrypted.yaml with a non-identifier field name was accepted")
	}
	if msg := validateEncryptedYAML("tables:\n  patients:\n    fields: [ssn, dob]\n    unmask_roles: [admin]\n"); msg != "" {
		t.Errorf("plain encrypted.yaml refused: %s", msg)
	}
}

func TestWorkflowConfigRefusesNonIdentifierTableField(t *testing.T) {
	if _, err := parseWorkflowsYAML([]byte("orders:\n  table: 'a\"; --'\n  field: status\n")); err == nil {
		t.Error("workflow with a non-identifier table was accepted")
	}
	if _, err := parseWorkflowsYAML([]byte("orders:\n  table: orders\n  field: 'a b'\n")); err == nil {
		t.Error("workflow with a non-identifier field was accepted")
	}
	if _, err := parseWorkflowsYAML([]byte("orders:\n  table: orders\n  field: status\n  initial: pending\n")); err != nil {
		t.Errorf("plain workflow refused: %v", err)
	}
	// The write gate (and `benmore check`) names it too.
	if msg := ValidateOnWrite("workflows.yaml", "orders:\n  table: 'a\"; --'\n  field: status\n  initial: p\n  transitions:\n    p:\n      q: {}\n"); msg == "" {
		t.Error("ValidateOnWrite accepted a workflow with a non-identifier table")
	}
}

// A catalog name a migration created with SQL punctuation is read back through
// the schema-drift column reader, which splices the table name into a
// `PRAGMA table_info(...)`. getLiveColumns has no plain-name guard (a drift
// check must read whatever the catalog holds), so quoting is what keeps the
// PRAGMA addressing the right table. On origin/main the name went in bare, so
// the PRAGMA was malformed and returned no columns; the process survives
// either way (the brief's hostile-name class), but the drift check read the
// wrong schema.
func TestLiveColumnsReadsHostileCatalogTable(t *testing.T) {
	db, err := sql.Open("sqlite3_benmore", filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, table := range []string{`a"; --`, `a\`, `a b`} {
		if _, err := db.Exec("CREATE TABLE " + quoteIdent(table) + " (id INTEGER PRIMARY KEY, title TEXT)"); err != nil {
			t.Fatalf("create %q: %v", table, err)
		}
		cols, err := getLiveColumns(db, table)
		if err != nil {
			t.Fatalf("getLiveColumns(%q): %v", table, err)
		}
		if _, ok := cols["id"]; !ok {
			t.Fatalf("columns of %q = %v, want id + title", table, cols)
		}
		if _, ok := cols["title"]; !ok {
			t.Fatalf("columns of %q = %v, want id + title", table, cols)
		}
	}
}

// A versioned table created by a migration with punctuation in its name and in
// its timestamped column: installVersioningForTable builds the history table
// and the BEFORE UPDATE/DELETE triggers around those names, quoted, so the DDL
// stays well-formed and a mutation is captured. (The table name must still be
// a plain identifier to reach GetTableColumns, which guards table reads with
// isValidColumnName; the column name is whatever the migration wrote.)
func TestVersioningQuotesHostileColumn(t *testing.T) {
	db, err := sql.Open("sqlite3_benmore", filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	table := "docs"
	col := `c"; --`
	if _, err := db.Exec("CREATE TABLE " + quoteIdent(table) + " (id INTEGER PRIMARY KEY, " + quoteIdent(col) + " TEXT, updated_at DATETIME)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO " + quoteIdent(table) + " (id, " + quoteIdent(col) + ", updated_at) VALUES (1, 'one', datetime('now'))"); err != nil {
		t.Fatal(err)
	}
	if _, err := installVersioningForTable(db, table); err != nil {
		t.Fatalf("installVersioningForTable: %v", err)
	}
	if _, err := db.Exec("UPDATE "+quoteIdent(table)+" SET "+quoteIdent(col)+" = ? WHERE id = 1", "two"); err != nil {
		t.Fatal(err)
	}
	var versions int
	if err := db.QueryRow("SELECT COUNT(*) FROM " + quoteIdent(table+"_history")).Scan(&versions); err != nil {
		t.Fatalf("read history: %v", err)
	}
	if versions != 1 {
		t.Fatalf("history rows = %d, want 1 (the pre-update snapshot)", versions)
	}
}

// The double-quoted-string finding the brief asks for. SQLite's build enables
// the legacy DQS fallback: a double-quoted token that names no column is read
// as a string LITERAL, not an error. So a config COLUMN name that reaches SQL
// as a lone quoted token (`"emial" = ?`) would, on a typo, compare the string
// 'emial' with the bound value - a silently-false comparison instead of a loud
// "no such column". Qualifying the column (`"members"."emial" = ?`, quoteColumn)
// defeats the fallback: SQLite only applies DQS to an UNqualified token, so a
// qualified typo is always a loud error. This is why config column names are
// written with quoteColumn (qualified) wherever the name could be a typo, and
// bare quoteIdent only where the column is proven to exist (hasColumn) or is
// an INSERT/UPDATE target (not a comparison).
func TestDoubleQuotedStringFallbackNeedsQualification(t *testing.T) {
	db, err := sql.Open("sqlite3_benmore", filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE members (id INTEGER PRIMARY KEY, email TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO members (email) VALUES ('a@x')`); err != nil {
		t.Fatal(err)
	}
	// Unqualified quoted typo: DQS fallback reads it as the string 'emial',
	// so the comparison is silently false (no error, zero rows) - the exact
	// trap quoting a bare column name would spring on a misspelling.
	var one int
	err = db.QueryRow(`SELECT 1 FROM members WHERE `+quoteIdent("emial")+` = ?`, "a@x").Scan(&one)
	if err != sql.ErrNoRows {
		t.Fatalf("unqualified quoted typo: want silent no-match (DQS fallback), got err=%v one=%d", err, one)
	}
	// Qualified quoted typo (quoteColumn): a loud "no such column" - the
	// comparison can never be a false negative.
	err = db.QueryRow(`SELECT 1 FROM members WHERE `+quoteColumn("members", "emial")+` = ?`, "a@x").Scan(&one)
	if err == nil || !strings.Contains(err.Error(), "no such column") {
		t.Fatalf("qualified quoted typo: want a loud 'no such column', got %v", err)
	}
	// The real qualified column resolves and matches.
	if err := db.QueryRow(`SELECT 1 FROM members WHERE `+quoteColumn("members", "email")+` = ?`, "a@x").Scan(&one); err != nil || one != 1 {
		t.Fatalf("real qualified column should match: one=%d err=%v", one, err)
	}
}
