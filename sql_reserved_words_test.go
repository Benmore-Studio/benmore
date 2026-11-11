//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sqliteKeywordList is every keyword of the SQLite this binary is built with
// (sqlite3_keyword_name; https://sqlite.org/lang_keywords.html), plus the
// names SQLite treats specially without making them keywords.
const sqliteKeywordList = `ABORT ACTION ADD AFTER ALL ALTER ALWAYS ANALYZE AND AS ASC ATTACH AUTOINCREMENT
BEFORE BEGIN BETWEEN BY CASCADE CASE CAST CHECK COLLATE COLUMN COMMIT CONFLICT CONSTRAINT CREATE CROSS
CURRENT CURRENT_DATE CURRENT_TIME CURRENT_TIMESTAMP DATABASE DEFAULT DEFERRABLE DEFERRED DELETE DESC DETACH
DISTINCT DO DROP EACH ELSE END ESCAPE EXCEPT EXCLUDE EXCLUSIVE EXISTS EXPLAIN FAIL FILTER FIRST FOLLOWING
FOR FOREIGN FROM FULL GENERATED GLOB GROUP GROUPS HAVING IF IGNORE IMMEDIATE IN INDEX INDEXED INITIALLY
INNER INSERT INSTEAD INTERSECT INTO IS ISNULL JOIN KEY LAST LEFT LIKE LIMIT MATCH MATERIALIZED NATURAL NO
NOT NOTHING NOTNULL NULL NULLS OF OFFSET ON OR ORDER OTHERS OUTER OVER PARTITION PLAN PRAGMA PRECEDING
PRIMARY QUERY RAISE RANGE RECURSIVE REFERENCES REGEXP REINDEX RELEASE RENAME REPLACE RESTRICT RETURNING
RIGHT ROLLBACK ROW ROWS SAVEPOINT SELECT SET TABLE TEMP TEMPORARY THEN TIES TO TRANSACTION TRIGGER
UNBOUNDED UNION UNIQUE UPDATE USING VACUUM VALUES VIEW VIRTUAL WHEN WHERE WINDOW WITH WITHIN WITHOUT
TRUE FALSE ROWID OID _ROWID_ STORED STRICT`

func reservedWordTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3_benmore", filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func catalogHasColumnForTest(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, table, column).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// The quoting rule for generated DDL rests on one claim: the names it quotes
// are exactly the names SQLite cannot take bare, so no schema that loads
// today gets different DDL text. This measures the claim against the engine
// for every keyword, in each position the generators write a name.
func TestReservedWordSetMatchesSQLite(t *testing.T) {
	db := reservedWordTestDB(t)
	for i, keyword := range strings.Fields(sqliteKeywordList) {
		name := strings.ToLower(keyword)
		bare, quoted := fmt.Sprintf("bare%d", i), fmt.Sprintf("quoted%d", i)

		// A column definition, bare. `constraint` is accepted and creates
		// no column, so the catalog decides, not the error.
		_, err := db.Exec(fmt.Sprintf("CREATE TABLE %s (id INTEGER PRIMARY KEY, %s INTEGER)", bare, name))
		bareWorks := err == nil && catalogHasColumnForTest(t, db, bare, name)
		if bareWorks == sqliteReservedWord(name) {
			t.Errorf("%s: a bare column definition works=%v, but sqliteReservedWord=%v", name, bareWorks, sqliteReservedWord(name))
		}

		// The same definition as the generators write it.
		if _, err := db.Exec(fmt.Sprintf("CREATE TABLE %s (id INTEGER PRIMARY KEY, %s INTEGER, other INTEGER)", quoted, ddlIdent(name))); err != nil {
			t.Errorf("%s: column definition written %s: %v", name, ddlIdent(name), err)
			continue
		}
		if !catalogHasColumnForTest(t, db, quoted, name) {
			t.Errorf("%s: column definition written %s created no such column", name, ddlIdent(name))
			continue
		}
		for _, stmt := range []string{
			fmt.Sprintf("CREATE TABLE alter%d (id INTEGER PRIMARY KEY)", i),
			fmt.Sprintf("ALTER TABLE alter%d ADD COLUMN %s INTEGER", i, ddlIdent(name)),
			fmt.Sprintf("ALTER TABLE alter%d DROP COLUMN %s", i, ddlIdent(name)),
			fmt.Sprintf("CREATE TABLE child%d (id INTEGER PRIMARY KEY, %s INTEGER, FOREIGN KEY (%s) REFERENCES %s(%s))", i, ddlIdent(name), ddlIdent(name), quoted, ddlIdent(name)),
			fmt.Sprintf("CREATE TRIGGER trg%d AFTER UPDATE ON %s FOR EACH ROW WHEN NEW.%s IS OLD.%s BEGIN UPDATE %s SET %s = 1 WHERE id = NEW.id AND %s IS NOT (1); END",
				i, quoted, ddlIdent(name), ddlIdent(name), quoted, ddlIdent(name), ddlExprIdent(name)),
			fmt.Sprintf("INSERT INTO %s (id, other) VALUES (1, 5)", quoted),
			// Runs the trigger: its SET must reach the column.
			fmt.Sprintf("UPDATE %s SET other = 6 WHERE id = 1", quoted),
		} {
			if _, err := db.Exec(stmt); err != nil {
				t.Errorf("%s: %s: %v", name, stmt, err)
			}
		}
		var got sql.NullInt64
		if err := db.QueryRow(fmt.Sprintf("SELECT %s FROM %s WHERE id = 1", quoteColumn(quoted, name), quoteIdent(quoted))).Scan(&got); err != nil || got.Int64 != 1 {
			t.Errorf("%s: the trigger's SET %s did not write the column: value=%v err=%v", name, ddlIdent(name), got, err)
		}

		// An index (or PRIMARY KEY) column is an expression. The name the
		// generators write must index the column itself, and a name they
		// leave bare must already have done so.
		if _, err := db.Exec(fmt.Sprintf("CREATE INDEX idx%d ON %s(%s)", i, quoted, ddlExprIdent(name))); err != nil {
			t.Errorf("%s: index column written %s: %v", name, ddlExprIdent(name), err)
			continue
		}
		var indexed sql.NullString
		if err := db.QueryRow(`SELECT name FROM pragma_index_info(?)`, fmt.Sprintf("idx%d", i)).Scan(&indexed); err != nil || indexed.String != name {
			t.Errorf("%s: index column written %s indexes %q (err=%v), not the column", name, ddlExprIdent(name), indexed.String, err)
		}
		// Bare, `null` and the current_* names index an expression, not
		// the column.
		bareIndexes := false
		if _, err := db.Exec(fmt.Sprintf("CREATE INDEX bareidx%d ON %s(%s)", i, quoted, name)); err == nil {
			var bareName sql.NullString
			_ = db.QueryRow(`SELECT name FROM pragma_index_info(?)`, fmt.Sprintf("bareidx%d", i)).Scan(&bareName)
			bareIndexes = bareName.String == name
		}
		if quotedInIndex := ddlExprIdent(name) != name; bareIndexes == quotedInIndex {
			t.Errorf("%s: a bare index column indexes the column=%v, but ddlExprIdent quotes=%v", name, bareIndexes, quotedInIndex)
		}
	}
}

func TestDDLIdentQuotesOnlyReservedWords(t *testing.T) {
	for name, want := range map[string]string{
		"order":        `"order"`,
		"Order":        `"Order"`,
		"GROUP":        `"GROUP"`,
		"constraint":   `"constraint"`,
		"orders":       "orders",
		"key":          "key",
		"desc":         "desc",
		"cast":         "cast",
		"current_date": "current_date",
		"user_id":      "user_id",
		// Not a plain identifier: still bare, still refused by the
		// statement it lands in (buildAlterAdd).
		"my col": "my col",
	} {
		if got := ddlIdent(name); got != want {
			t.Errorf("ddlIdent(%q) = %s, want %s", name, got, want)
		}
	}
	for name, want := range map[string]string{
		"order":        `"order"`,
		"cast":         `"cast"`,
		"raise":        `"raise"`,
		"current_date": `"current_date"`,
		"key":          "key",
		"title":        "title",
	} {
		if got := ddlExprIdent(name); got != want {
			t.Errorf("ddlExprIdent(%q) = %s, want %s", name, got, want)
		}
	}
}

// The list builder decided "this query already has a WHERE" by substring, so a
// projected column or a table whose name holds the letters (whereabouts,
// "where") got ` AND ...` appended to a query with no WHERE.
func TestSQLHasWhereKeyword(t *testing.T) {
	for query, want := range map[string]bool{
		`SELECT * FROM "steps"`:                                 false,
		`SELECT "steps"."where" FROM "steps"`:                   false,
		`SELECT whereabouts FROM "elsewhere"`:                   false,
		`SELECT * FROM "steps" WHERE deleted_at IS NULL`:        true,
		`SELECT "steps"."where" FROM "steps" where "where" = 1`: true,
	} {
		if got := sqlHasWhereKeyword(query); got != want {
			t.Errorf("sqlHasWhereKeyword(%s) = %v, want %v", query, got, want)
		}
	}
}

// The fixture app declares columns named with reserved words in every place
// the framework generates SQL for them: CREATE TABLE, a foreign key, single
// and compound indexes, @unique, @updatedAt, a full-text index, version
// history, and both kinds of computed column. Its tests then drive create,
// read, update, filter, sort, count, ?fields=, cursor pages, search, includes,
// /api/_query, batch, ingest, transactions, soft delete and restore, and
// custom fields named `order`, `group` and `select`. Before the fix the app
// did not load.
func TestReservedWordColumnsFixtureApp(t *testing.T) {
	results, err := runServerTestsOnCopy(filepath.Join("testdata", "reserved_word_columns"), "all")
	if err != nil {
		t.Fatalf("the fixture app did not run: %v", err)
	}
	appTests, failed := 0, 0
	for _, r := range results {
		if r.File == "SUMMARY" {
			continue
		}
		if r.File == "reserved_words" {
			appTests++
		}
		if r.Pass {
			continue
		}
		failed++
		msg := r.Message
		for _, step := range r.Steps {
			if !step.Pass {
				msg += "\n    - " + step.Action + ": " + step.Message
			}
		}
		t.Errorf("%s/%s: %s", r.File, r.Test, msg)
	}
	if appTests != 7 {
		t.Errorf("ran %d of the fixture's 7 tests", appTests)
	}
	t.Logf("%d results, %d failed", len(results), failed)
}

func reservedWordColumns(t *testing.T, db *sql.DB, table string) map[string]bool {
	t.Helper()
	cols, err := GetTableColumns(db, table)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, col := range cols {
		out[col.Name] = true
	}
	return out
}

// An app that exists gains reserved-word columns: the generated migration
// (ALTER TABLE ADD COLUMN, the unique and plain indexes, the columns with a
// non-constant default on an empty table and on one with rows) applies, its
// file says what ran, a second load generates nothing, and the file's DOWN
// section rolls it back.
func TestPrismaMigrationAddsReservedWordColumnsToExistingTables(t *testing.T) {
	dir := t.TempDir()
	db := openNonConstTestDB(t, dir)
	loadSchemaForTest(t, db, dir, `model Step {
  id    Int    @id @default(autoincrement())
  title String
}

model Empty {
  id    Int    @id @default(autoincrement())
  title String
}`)
	mustExec(t, db, `INSERT INTO steps (title) VALUES ('kept'), ('also kept')`)

	grown := `model Step {
  id      Int       @id @default(autoincrement())
  title   String
  order   Int       @default(0)
  group   String?   @unique
  from    DateTime  @default(now())
  to      DateTime?
  cast    String?

  @@index([order, cast])
}

model Empty {
  id     Int      @id @default(autoincrement())
  title  String
  values DateTime @default(now())
}

model Index {
  id    Int    @id @default(autoincrement())
  where String
  check Int    @default(0)

  @@unique([where, check])
  @@map("index")
}`
	loadSchemaForTest(t, db, dir, grown)

	for table, want := range map[string][]string{
		"steps":   {"order", "group", "from", "to", "cast"},
		"empties": {"values"},
		"index":   {"where", "check"},
	} {
		cols := reservedWordColumns(t, db, table)
		for _, col := range want {
			if !cols[col] {
				t.Errorf("%s.%s was not added (columns: %v)", table, col, cols)
			}
		}
	}
	// Rows kept, the new columns filled, the indexes on the columns.
	var kept, missing int
	if err := db.QueryRow(`SELECT COUNT(*), SUM("from" IS NULL OR "order" <> 0) FROM steps`).Scan(&kept, &missing); err != nil || kept != 2 || missing != 0 {
		t.Fatalf("steps after the migration: rows=%d with a missing value=%d err=%v", kept, missing, err)
	}
	mustExec(t, db, `INSERT INTO steps (title, "order", "group") VALUES ('new', 3, 'g')`)
	if _, err := db.Exec(`INSERT INTO steps (title, "group") VALUES ('dup', 'g')`); err == nil {
		t.Error(`@unique on "group" did not refuse a duplicate`)
	}
	mustExec(t, db, `INSERT INTO "index" ("where", "check") VALUES ('here', 1)`)
	if _, err := db.Exec(`INSERT INTO "index" ("where", "check") VALUES ('here', 1)`); err == nil {
		t.Error(`@@unique([where, check]) did not refuse a duplicate`)
	}
	for index, want := range map[string]string{"idx_steps_order_cast": "order,cast", "uniq_steps_group": "group", "uniq_index_where_check": "where,check"} {
		rows, err := db.Query(`SELECT name FROM pragma_index_info(?) ORDER BY seqno`, index)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for rows.Next() {
			var name sql.NullString
			if err := rows.Scan(&name); err != nil {
				t.Fatal(err)
			}
			names = append(names, name.String)
		}
		rows.Close()
		if got := strings.Join(names, ","); got != want {
			t.Errorf("index %s covers %q, want the columns %q", index, got, want)
		}
	}

	files := ddlMigrationFiles(t, dir)
	if len(files) != 2 {
		t.Fatalf("migrations: %v", files)
	}
	data, err := os.ReadFile(filepath.Join(dir, "migrations", files[1]))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		`ALTER TABLE steps ADD COLUMN "order" INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE steps ADD COLUMN "group" TEXT;`,
		`CREATE UNIQUE INDEX IF NOT EXISTS uniq_steps_group ON steps("group");`,
		`CREATE INDEX IF NOT EXISTS idx_steps_order_cast ON steps("order", "cast");`,
		`CREATE TABLE IF NOT EXISTS "index" (`,
		`ALTER TABLE empties ADD COLUMN "values" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;`,
		`ALTER TABLE steps DROP COLUMN "order";`,
		`DROP TABLE IF EXISTS "index";`,
		// A name SQLite takes bare is written as it always was.
		`ALTER TABLE steps ADD COLUMN cast TEXT;`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the migration file lacks %s\n%s", want, text)
		}
	}

	// The same schema again: nothing to do.
	loadSchemaForTest(t, db, dir, grown)
	if again := ddlMigrationFiles(t, dir); len(again) != 2 {
		t.Fatalf("a second load of the same schema wrote a migration: %v", again)
	}

	if _, err := RollbackPrismaMigration(db, dir, 1, true); err != nil {
		t.Fatalf("roll the migration back: %v", err)
	}
	cols := reservedWordColumns(t, db, "steps")
	for _, col := range []string{"order", "group", "from", "to", "cast"} {
		if cols[col] {
			t.Errorf("steps.%s is still there after the rollback", col)
		}
	}
	if exists, err := tableExists(db, "index"); err != nil || exists {
		t.Errorf(`table "index" after the rollback: exists=%v err=%v`, exists, err)
	}
	if kept := migTestRows(t, db, "steps"); kept != 3 {
		t.Errorf("steps holds %d rows after the rollback, want 3", kept)
	}
}

// A schema.sql app quotes such a column itself; the column the load adds to
// an existing table is written the same way (buildAlterAdd).
func TestSchemaSQLMigrationAddsAReservedWordColumn(t *testing.T) {
	db := reservedWordTestDB(t)
	mustExec(t, db, `CREATE TABLE steps (id INTEGER PRIMARY KEY, title TEXT)`)
	mustExec(t, db, `INSERT INTO steps (title) VALUES ('kept')`)
	tables := ParseCreateTables(`CREATE TABLE steps (id INTEGER PRIMARY KEY, title TEXT, "order" INTEGER DEFAULT 0, "check" TEXT, rank INTEGER);`)
	if len(tables) != 1 || len(tables[0].Columns) != 5 {
		t.Fatalf("parsed %+v", tables)
	}
	if _, err := Migrate(db, tables, false); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	cols := reservedWordColumns(t, db, "steps")
	if !cols["order"] || !cols["check"] || !cols["rank"] {
		t.Fatalf("columns after Migrate: %v", cols)
	}
	var order int
	if err := db.QueryRow(`SELECT "order" FROM steps WHERE title = 'kept'`).Scan(&order); err != nil || order != 0 {
		t.Fatalf(`"order" of the existing row = %d, err=%v`, order, err)
	}
}

// schema.yaml shorthand generates its tables the same way.
func TestSchemaShorthandQuotesReservedWords(t *testing.T) {
	generated := parseSchemaShorthand([]byte("order: item!, group, limit:int, contact:ref\ncontacts: name!, from, to\n"))
	db := reservedWordTestDB(t)
	if _, err := db.Exec(generated); err != nil {
		t.Fatalf("generated schema does not run: %v\n%s", err, generated)
	}
	if cols := reservedWordColumns(t, db, "order"); !cols["item"] || !cols["group"] || !cols["limit"] || !cols["contact_id"] {
		t.Errorf(`"order" columns: %v`, cols)
	}
	if cols := reservedWordColumns(t, db, "contacts"); !cols["from"] || !cols["to"] {
		t.Errorf("contacts columns: %v", cols)
	}
	// Ordinary names are written as they always were.
	if want := "CREATE TABLE IF NOT EXISTS contacts (\n  id INTEGER PRIMARY KEY AUTOINCREMENT,\n  name TEXT NOT NULL,\n"; !strings.Contains(generated, want) {
		t.Errorf("contacts DDL changed:\n%s", generated)
	}
}
