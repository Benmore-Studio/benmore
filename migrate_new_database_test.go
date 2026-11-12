//go:build !cli

package main

import (
	"bytes"
	"context"
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A field's type cannot be changed in place, so the documented way is a new
// field, a migrations/ file that copies the values and drops the old column,
// and the old field's removal from the schema. A database built later from
// the current schema never had the old column: the copy failed there with `no
// such column`, so `benmore test`, a new instance and a dev database built
// again could not load the app until the file was deleted from the source.

const (
	typeChangeSchemaBefore = "model Order {\n  id Int @id @default(autoincrement())\n  name String\n  amount String?\n}\n"
	typeChangeSchemaBoth   = "model Order {\n  id Int @id @default(autoincrement())\n  name String\n  amount String?\n  amountCents Int? @map(\"amount_cents\")\n}\n"
	typeChangeSchemaAfter  = "model Order {\n  id Int @id @default(autoincrement())\n  name String\n  amountCents Int? @map(\"amount_cents\")\n}\n"
	typeChangeFile         = "0005_amount_to_cents.sql"
	typeChangeBody         = "ALTER TABLE orders ADD COLUMN amount_cents INTEGER;\nUPDATE orders SET amount_cents = CAST(amount AS INTEGER) * 100;\nALTER TABLE orders DROP COLUMN amount;\n"
)

func typeChangeWarnings(logged string) []string {
	var lines []string
	for _, line := range strings.Split(logged, "\n") {
		if strings.Contains(line, "WARNING") && strings.Contains(line, "migrations/") {
			lines = append(lines, line)
		}
	}
	return lines
}

// typeChangeLivedApp is an app whose database has the old column with a value
// in it and, as the recipe's first step, the new field next to it. What is
// left is the step under test: the file, and the old field's removal.
func typeChangeLivedApp(t *testing.T, root string) string {
	t.Helper()
	lived := filepath.Join(root, "lived")
	if err := os.MkdirAll(lived, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, lived, "app.yaml", "name: orders\n")
	writeTestFile(t, lived, "schema.prisma", typeChangeSchemaBefore)
	if logged, err := dropFreshLoad(t, lived); err != nil {
		t.Fatalf("first load: %v\n%s", err, logged)
	}
	db, err := sql.Open("sqlite3", filepath.Join(lived, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `INSERT INTO orders (name, amount) VALUES ('first', '12')`)
	db.Close()
	writeTestFile(t, lived, "schema.prisma", typeChangeSchemaBoth)
	if logged, err := dropFreshLoad(t, lived); err != nil {
		t.Fatalf("load with the new field: %v\n%s", err, logged)
	}
	return lived
}

func TestTypeChangeFileRunsFullyOnTheDatabaseThatHasTheOldColumn(t *testing.T) {
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	lived := typeChangeLivedApp(t, t.TempDir())
	writeTestFile(t, lived, "schema.prisma", typeChangeSchemaAfter)
	writeTestFile(t, lived, "migrations/"+typeChangeFile, typeChangeBody)
	logged, err := dropFreshLoad(t, lived)
	if err != nil {
		t.Fatalf("load with the type-change file: %v\n%s", err, logged)
	}
	if warnings := typeChangeWarnings(logged); len(warnings) != 0 {
		t.Fatalf("an existing database skipped a statement: %v", warnings)
	}
	db, err := sql.Open("sqlite3", filepath.Join(lived, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var cents int
	if err := db.QueryRow(`SELECT amount_cents FROM orders WHERE name = 'first'`).Scan(&cents); err != nil || cents != 1200 {
		t.Fatalf("the copy did not run: amount_cents=%d err=%v", cents, err)
	}
	if dbColumnExists(db, "orders", "amount") {
		t.Fatal("the old column was not dropped")
	}
	if n := dropFreshLedgerCount(t, db, typeChangeFile); n != 1 {
		t.Fatalf("ledger records the file %d times, want 1", n)
	}
}

func TestTypeChangeFileLoadsOnANewDatabase(t *testing.T) {
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	root := t.TempDir()
	lived := typeChangeLivedApp(t, root)
	writeTestFile(t, lived, "schema.prisma", typeChangeSchemaAfter)
	writeTestFile(t, lived, "migrations/"+typeChangeFile, typeChangeBody)
	if logged, err := dropFreshLoad(t, lived); err != nil {
		t.Fatalf("load on the database that had the column: %v\n%s", err, logged)
	}

	// A new database of the same source: the current schema, then every file
	// the app carries (the generated ones too).
	fresh := filepath.Join(root, "fresh")
	if err := os.MkdirAll(fresh, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, fresh, "app.yaml", "name: orders\n")
	writeTestFile(t, fresh, "schema.prisma", typeChangeSchemaAfter)
	entries, err := os.ReadDir(filepath.Join(lived, "migrations"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(lived, "migrations", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, fresh, "migrations/"+e.Name(), string(data))
	}
	logged, err := dropFreshLoad(t, fresh)
	if err != nil {
		t.Fatalf("a new database does not load with the type-change file: %v\n%s", err, logged)
	}
	// One statement skipped as stale: the copy. (The ADD COLUMN is already in
	// place and the DROP COLUMN has nothing to drop; both were skipped before.)
	warnings := typeChangeWarnings(logged)
	if len(warnings) != 1 {
		t.Fatalf("want one warning for the skipped copy, got %d:\n%s", len(warnings), logged)
	}
	for _, want := range []string{"migrations/" + typeChangeFile, "statement 2 (UPDATE)", "`orders.amount`", "current schema does not have", "skips the statement", "misspelt"} {
		if !strings.Contains(warnings[0], want) {
			t.Errorf("warning lacks %q: %s", want, warnings[0])
		}
	}
	if _, err := os.Stat(filepath.Join(fresh, "migrations", typeChangeFile)); err != nil {
		t.Fatalf("the file was set aside on the new database: %v", err)
	}
	db, err := sql.Open("sqlite3", filepath.Join(fresh, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if n := dropFreshLedgerCount(t, db, typeChangeFile); n != 1 {
		t.Fatalf("ledger records the file %d times on the new database, want 1", n)
	}
	if dbColumnExists(db, "orders", "amount") || !dbColumnExists(db, "orders", "amount_cents") {
		t.Fatal("the new database does not have the current schema's columns")
	}
	var declared string
	if err := db.QueryRow(`SELECT type FROM pragma_table_info('orders') WHERE name = 'amount_cents'`).Scan(&declared); err != nil || declared != "INTEGER" {
		t.Fatalf("amount_cents type = %q %v", declared, err)
	}
	var rows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM orders`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("the new database holds %d orders (%v), want none", rows, err)
	}
	mustExec(t, db, `INSERT INTO orders (name, amount_cents) VALUES ('second', 500)`)
	// The next load is of an existing database with nothing left to apply.
	if logged, err := dropFreshLoad(t, fresh); err != nil || len(typeChangeWarnings(logged)) != 0 {
		t.Fatalf("second load of the new database: %v\n%s", err, logged)
	}
}

// A misspelt name on a database that has data is a mistake, as before: the
// file fails, nothing of it stays, and it is set aside.
func TestMisspeltNameStillFailsOnAnExistingDatabase(t *testing.T) {
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	lived := typeChangeLivedApp(t, t.TempDir())
	writeTestFile(t, lived, "schema.prisma", typeChangeSchemaAfter)
	const file = "0005_amount_to_cents.sql"
	writeTestFile(t, lived, "migrations/"+file, "UPDATE orders SET name = 'changed';\nUPDATE orders SET amount_cents = CAST(amuont AS INTEGER) * 100;\n")
	logged, err := dropFreshLoad(t, lived)
	if err == nil || !strings.Contains(err.Error(), "no such column: amuont") {
		t.Fatalf("want the load to fail on the misspelt column, got %v\n%s", err, logged)
	}
	if warnings := typeChangeWarnings(logged); len(warnings) != 0 {
		t.Fatalf("an existing database skipped a statement: %v", warnings)
	}
	if _, err := os.Stat(filepath.Join(lived, "migrations", file+".failed.sql")); err != nil {
		t.Fatalf("the failed file was not set aside: %v", err)
	}
	db, err := sql.Open("sqlite3", filepath.Join(lived, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var name string
	if err := db.QueryRow(`SELECT name FROM orders`).Scan(&name); err != nil || name != "first" {
		t.Fatalf("the failed file left a change behind: name=%q %v", name, err)
	}
	if n := dropFreshLedgerCount(t, db, file); n != 0 {
		t.Fatalf("the failed file was recorded %d times", n)
	}
}

// What apps keep in migration files (a trigger, an index, a seed row) lands
// on a new database, next to a statement of the same file that is skipped.
func TestTriggerAndSeedRowOfAMigrationFileLandOnANewDatabase(t *testing.T) {
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "name: orders\n")
	writeTestFile(t, dir, "schema.prisma", typeChangeSchemaAfter+"\nmodel Setting {\n  id Int @id @default(autoincrement())\n  key String @unique\n  value String\n}\n\nmodel OrderEvent {\n  id Int @id @default(autoincrement())\n  orderId Int @map(\"order_id\")\n  kind String\n\n  @@map(\"order_events\")\n}\n")
	writeTestFile(t, dir, "migrations/0003_order_rules.sql", strings.Join([]string{
		"-- the old text amount, long gone from the schema",
		"UPDATE orders SET amount_cents = CAST(amount AS INTEGER) * 100;",
		"CREATE TRIGGER orders_log_insert AFTER INSERT ON orders BEGIN",
		"  INSERT INTO order_events (order_id, kind) VALUES (NEW.id, 'created');",
		"END;",
		"CREATE INDEX idx_orders_name_lower ON orders(lower(name));",
		"INSERT INTO settings (key, value) VALUES ('currency', 'USD');",
		"DELETE FROM legacy_orders;",
		"INSERT INTO settings (key, value) VALUES ('rounding', 'half-up');",
		"",
	}, "\n"))
	logged, err := dropFreshLoad(t, dir)
	if err != nil {
		t.Fatalf("load: %v\n%s", err, logged)
	}
	warnings := typeChangeWarnings(logged)
	if len(warnings) != 2 || !strings.Contains(warnings[0], "statement 1 (UPDATE) names `orders.amount`, a column") || !strings.Contains(warnings[1], "statement 5 (DELETE) names `legacy_orders`, a table") {
		t.Fatalf("warnings = %v\n%s", warnings, logged)
	}
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var seeds int
	if err := db.QueryRow(`SELECT COUNT(*) FROM settings WHERE (key = 'currency' AND value = 'USD') OR (key = 'rounding' AND value = 'half-up')`).Scan(&seeds); err != nil || seeds != 2 {
		t.Fatalf("seed rows = %d (%v), want 2", seeds, err)
	}
	var objects int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE (type = 'trigger' AND name = 'orders_log_insert') OR (type = 'index' AND name = 'idx_orders_name_lower')`).Scan(&objects); err != nil || objects != 2 {
		t.Fatalf("trigger and index in the database = %d (%v), want 2", objects, err)
	}
	mustExec(t, db, `INSERT INTO orders (name, amount_cents) VALUES ('first', 100)`)
	var kind string
	if err := db.QueryRow(`SELECT kind FROM order_events`).Scan(&kind); err != nil || kind != "created" {
		t.Fatalf("the trigger did not fire: %q %v", kind, err)
	}
	if n := dropFreshLedgerCount(t, db, "0003_order_rules.sql"); n != 1 {
		t.Fatalf("ledger records the file %d times, want 1", n)
	}
}

// newDatabaseRunnerFixture is a database as a load leaves it before its first
// migration file: built from the current schema, nothing applied.
func newDatabaseRunnerFixture(t *testing.T) (string, *sql.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(1)
	if !migrationDatabaseIsNew(db) {
		t.Fatal("an empty database is not new")
	}
	prismaShapedTracking(t, db)
	if !migrationDatabaseIsNew(db) {
		t.Fatal("a database with an empty ledger and no application table is not new")
	}
	mustExec(t, db, `CREATE TABLE attachments (id INTEGER PRIMARY KEY, name TEXT, content_type TEXT, seen INTEGER)`)
	mustExec(t, db, `CREATE TABLE labels (id INTEGER PRIMARY KEY, label TEXT)`)
	mustExec(t, db, `CREATE TABLE scans (id INTEGER PRIMARY KEY)`)
	mustExec(t, db, `CREATE VIEW attachment_names AS SELECT name FROM attachments`)
	mustExec(t, db, `INSERT INTO attachments (name, content_type) VALUES ('a.txt', 'text/plain')`)
	return dir, db
}

func runNewDatabaseMigrations(t *testing.T, db *sql.DB, dir string) (*migrationSkipLog, string, error) {
	t.Helper()
	ctx, skips := withMigrationSkipLog(withMigrationNewDatabase(context.Background(), db))
	var logged bytes.Buffer
	log.SetOutput(&logged)
	err := runMigrationsCtx(ctx, db, dir, nil)
	log.SetOutput(os.Stderr)
	return skips, logged.String(), err
}

// Each statement below names a table or column the current schema does not
// have. On a new database it is skipped and reported once, the statements
// around it run, and the file is recorded; the same file on an existing
// database fails.
func TestNewDatabaseSkipsAStatementThatNamesWhatTheSchemaLost(t *testing.T) {
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	for name, tc := range map[string]struct {
		stmt string
		want migrationSkippedDrop
	}{
		"copy from a removed column":       {`UPDATE attachments SET name = checksum;`, migrationSkippedDrop{Kind: "column", Missing: "attachments.checksum", Verb: "UPDATE"}},
		"write to a removed column":        {`UPDATE attachments SET checksum = 'x';`, migrationSkippedDrop{Kind: "column", Missing: "attachments.checksum", Verb: "UPDATE"}},
		"qualified removed column":         {`UPDATE attachments SET name = attachments.Checksum;`, migrationSkippedDrop{Kind: "column", Missing: "attachments.Checksum", Verb: "UPDATE"}},
		"insert into a removed column":     {`INSERT INTO attachments (name, checksum) VALUES ('b.txt', 'x');`, migrationSkippedDrop{Kind: "column", Missing: "attachments.checksum", Verb: "INSERT"}},
		"index on a removed column":        {`CREATE INDEX idx_attachments_checksum ON attachments(checksum);`, migrationSkippedDrop{Kind: "column", Missing: "attachments.checksum", Verb: "CREATE"}},
		"rename of a removed column":       {`ALTER TABLE attachments RENAME COLUMN checksum TO digest;`, migrationSkippedDrop{Kind: "column", Missing: "attachments.checksum", Verb: "ALTER"}},
		"removed column, two tables read":  {`UPDATE attachments SET name = (SELECT checksum FROM scans);`, migrationSkippedDrop{Kind: "column", Missing: "checksum", Verb: "UPDATE"}},
		"column held by another table":     {`UPDATE attachments SET name = attachments.label WHERE id IN (SELECT id FROM labels);`, migrationSkippedDrop{Kind: "column", Missing: "attachments.label", Verb: "UPDATE"}},
		"delete from a removed table":      {`DELETE FROM legacy_scans;`, migrationSkippedDrop{Kind: "table", Missing: "legacy_scans", Verb: "DELETE"}},
		"copy from a removed table":        {`INSERT INTO attachments (name) SELECT name FROM main.legacy_scans;`, migrationSkippedDrop{Kind: "table", Missing: "legacy_scans", Verb: "INSERT"}},
		"add column to a removed table":    {`ALTER TABLE legacy_scans ADD COLUMN checksum TEXT;`, migrationSkippedDrop{Kind: "table", Missing: "legacy_scans", Verb: "ALTER"}},
		"trigger on a removed table":       {"CREATE TRIGGER legacy_touch AFTER INSERT ON legacy_scans BEGIN\n  UPDATE attachments SET seen = 1;\nEND;", migrationSkippedDrop{Kind: "table", Missing: "legacy_scans", Verb: "CREATE"}},
		"index on a removed table, quoted": {`CREATE INDEX idx_legacy ON "legacy_scans"(id);`, migrationSkippedDrop{Kind: "table", Missing: "legacy_scans", Verb: "CREATE"}},
	} {
		t.Run(name, func(t *testing.T) {
			const file = "0005_old_shape.sql"
			body := "UPDATE attachments SET name = name || '!';\n" + tc.stmt + "\nUPDATE attachments SET name = name || '?';\n"

			dir, db := newDatabaseRunnerFixture(t)
			writeMig(t, dir, file, body)
			skips, logged, err := runNewDatabaseMigrations(t, db, dir)
			if err != nil {
				t.Fatalf("run on a new database: %v", err)
			}
			want := tc.want
			want.File, want.Statement = file, 2
			if len(skips.drops) != 1 || skips.drops[0] != want {
				t.Fatalf("skipped = %+v, want %+v", skips.drops, want)
			}
			if !strings.Contains(logged, "WARNING: "+want.warning()) {
				t.Fatalf("no warning line for the skipped statement:\n%s", logged)
			}
			var got string
			db.QueryRow(`SELECT name FROM attachments WHERE id = 1`).Scan(&got)
			if got != "a.txt!?" {
				t.Fatalf("the statements around the skipped one did not both run: name=%q", got)
			}
			if n := dropFreshLedgerCount(t, db, file); n != 1 {
				t.Fatalf("ledger records the file %d times, want 1", n)
			}
			if _, err := os.Stat(filepath.Join(dir, "migrations", file)); err != nil {
				t.Fatalf("the file was set aside: %v", err)
			}

			// The same file on an existing database: a mistake, as before.
			dir, db = newDatabaseRunnerFixture(t)
			writeMig(t, dir, file, body)
			if err := RunMigrations(db, dir); err == nil || !strings.Contains(err.Error(), "no ") {
				t.Fatalf("an existing database did not fail the file: %v", err)
			}
			db.QueryRow(`SELECT name FROM attachments WHERE id = 1`).Scan(&got)
			if got != "a.txt" || dropFreshLedgerCount(t, db, file) != 0 {
				t.Fatalf("the failed file left something behind: name=%q", got)
			}
			if _, err := os.Stat(filepath.Join(dir, "migrations", file+".failed.sql")); err != nil {
				t.Fatalf("the failed file was not set aside: %v", err)
			}
		})
	}
}

// A new database skips nothing else. Each file below fails there as on any
// database: nothing is recorded, nothing it did stays, and it is set aside.
func TestNewDatabaseStillFailsWhatIsNotAStaleName(t *testing.T) {
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	for name, tc := range map[string]struct {
		file string
		want string
	}{
		// The schema declares the column and the table; an earlier statement
		// of the file took them away, so the later one should have run.
		"column the schema declares":  {"ALTER TABLE attachments DROP COLUMN content_type;\nUPDATE attachments SET content_type = 'x';", "no such column"},
		"table the schema declares":   {"DROP TABLE scans;\nDELETE FROM scans;", "no such table"},
		"column renamed away earlier": {"ALTER TABLE labels RENAME COLUMN label TO title;\nUPDATE labels SET label = 'x';", "no such column"},
		// The statement names nothing that is missing: the trigger it fires does.
		"trigger body reads a missing column": {"CREATE TRIGGER attachments_seen AFTER UPDATE OF name ON attachments BEGIN UPDATE attachments SET seen = length(NEW.checksum) WHERE id = NEW.id; END;\nUPDATE attachments SET name = 'b.txt';", "no such column"},
		"trigger body writes a missing table": {"CREATE TRIGGER attachments_log AFTER UPDATE OF name ON attachments BEGIN INSERT INTO legacy_scans (id) VALUES (NEW.id); END;\nUPDATE attachments SET name = 'b.txt';", "no such table"},
		// The words of SQLite's message, raised by a trigger.
		"trigger raises the same words": {"CREATE TRIGGER attachments_keep BEFORE DELETE ON attachments BEGIN SELECT RAISE(ABORT, 'no such table: legacy_scans'); END;\nDELETE FROM attachments AS legacy_scans;", "no such table"},
		// The column exists in a table the statement reads.
		"column of an alias, held by a table it reads": {"UPDATE attachments SET name = (SELECT x.label FROM scans AS x, labels LIMIT 1);", "no such column"},
		// Not the app's schema.
		"temp table":  {"DELETE FROM temp.legacy_scans;", "no such table"},
		"temp column": {"UPDATE temp.attachments SET checksum = 1;", "no such table"},
		// Other failures.
		"syntax":            {"UPDATE attachments SET name = ;", "syntax error"},
		"constraint":        {"INSERT INTO attachments (id, name) VALUES (1, 'again');", "UNIQUE constraint"},
		"view drop":         {"DROP VIEW legacy_names;", "no such view"},
		"trigger drop":      {"DROP TRIGGER legacy_touch;", "no such trigger"},
		"missing function":  {"UPDATE attachments SET name = legacy_fn(name);", "no such function"},
		"view over nothing": {"CREATE VIEW broken AS SELECT checksum FROM attachments;\nUPDATE attachments SET name = (SELECT checksum FROM broken);", "no such column"},
	} {
		t.Run(name, func(t *testing.T) {
			const file = "0005_old_shape.sql"
			dir, db := newDatabaseRunnerFixture(t)
			writeMig(t, dir, file, "UPDATE attachments SET seen = 7;\n"+tc.file+"\n")
			skips, logged, err := runNewDatabaseMigrations(t, db, dir)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want a failure naming %q, got %v\n%s", tc.want, err, logged)
			}
			if len(skips.drops) != 0 || strings.Contains(logged, "WARNING") {
				t.Fatalf("a statement was skipped: %+v\n%s", skips.drops, logged)
			}
			if n := dropFreshLedgerCount(t, db, file); n != 0 {
				t.Fatalf("the failed file was recorded %d times", n)
			}
			var name, contentType string
			var seen sql.NullInt64
			if err := db.QueryRow(`SELECT name, content_type, seen FROM attachments WHERE id = 1`).Scan(&name, &contentType, &seen); err != nil {
				t.Fatalf("the failed file changed the table: %v", err)
			}
			if name != "a.txt" || contentType != "text/plain" || seen.Valid {
				t.Fatalf("the failed file left a change behind: name=%q content_type=%q seen=%v", name, contentType, seen)
			}
			if _, err := os.Stat(filepath.Join(dir, "migrations", file+".failed.sql")); err != nil {
				t.Fatalf("the failed file was not set aside: %v", err)
			}
		})
	}
}

// "New" is read from the database: an application table or an applied
// migration makes it an existing one. Framework tables do not.
func TestMigrationDatabaseIsNewReadsTheDatabase(t *testing.T) {
	open := func(t *testing.T) *sql.DB {
		db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "data.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	}
	db := open(t)
	mustExec(t, db, `CREATE TABLE _benmore_users (id INTEGER PRIMARY KEY)`)
	if !migrationDatabaseIsNew(db) {
		t.Fatal("a database with only framework tables is not new")
	}
	mustExec(t, db, `CREATE TABLE notes (id INTEGER PRIMARY KEY)`)
	if migrationDatabaseIsNew(db) {
		t.Fatal("a database with an application table is new")
	}
	db = open(t)
	prismaShapedTracking(t, db)
	mustExec(t, db, `INSERT INTO _benmore_migrations (name, source, source_hash) VALUES ('0001_x.sql', '', '')`)
	if migrationDatabaseIsNew(db) {
		t.Fatal("a database with an applied migration is new")
	}
}

// What SQLite says about a name it cannot resolve, as the runner reads it.
func TestParseSQLiteMissingObject(t *testing.T) {
	for msg, want := range map[string]sqliteMissingObject{
		"no such table: scans":            {table: "scans"},
		"no such table: main.scans":       {schema: "main", table: "scans"},
		"no such table: temp.scans":       {schema: "temp", table: "scans"},
		"no such column: checksum":        {column: "checksum"},
		"no such column: t.checksum":      {table: "t", column: "checksum"},
		"no such column: main.t.checksum": {schema: "main", table: "t", column: "checksum"},
		`no such column: "checksum"`:      {column: "checksum"},
		`no such column: "checksum" - should this be a string literal in single-quotes?`: {column: "checksum"},
		"table t has no column named checksum":                                           {table: "t", column: "checksum"},
	} {
		got, ok := parseSQLiteMissingObject(msg)
		if !ok || got != want {
			t.Errorf("%q = %+v ok=%v, want %+v", msg, got, ok, want)
		}
	}
	for _, msg := range []string{"no such view: v", "no such index: i", "near \"x\": syntax error", "no such table: ", "no such column: a.b.c.d", "UNIQUE constraint failed: t.c"} {
		if got, ok := parseSQLiteMissingObject(msg); ok {
			t.Errorf("%q read as %+v", msg, got)
		}
	}
}

// `benmore test` builds its database from the current schema on every run and
// prints the load's WARNING lines: the skipped statement is one of them.
func TestBenmoreTestLoadPrintsTheSkippedStatement(t *testing.T) {
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "name: orders\n")
	writeTestFile(t, dir, "schema.prisma", typeChangeSchemaAfter)
	writeTestFile(t, dir, "migrations/"+typeChangeFile, typeChangeBody)
	var printed bytes.Buffer
	log.SetOutput(&printed)
	release := holdLoadLog()
	app, err := loadAppForServerTests(dir)
	release(err != nil)
	log.SetOutput(os.Stderr)
	if err != nil {
		t.Fatalf("the test copy does not load with the type-change file: %v\n%s", err, printed.String())
	}
	defer app.Shutdown()
	warnings := typeChangeWarnings(printed.String())
	if len(warnings) != 1 || !strings.Contains(warnings[0], "statement 2 (UPDATE) names `orders.amount`") {
		t.Fatalf("the run printed %d warning(s) for the skipped copy:\n%s", len(warnings), printed.String())
	}
	if dbColumnExists(app.DB, "orders", "amount") || !dbColumnExists(app.DB, "orders", "amount_cents") {
		t.Fatal("the test database does not have the current schema's columns")
	}
}

// The fixture app carries a type-change file written when its table still had
// the old column, and a file with a trigger and a seed row. `benmore test`
// runs its tests on a database built from the current schema: before, the
// copy never loaded and none of its tests ran.
func TestOldShapeMigrationFixtureApp(t *testing.T) {
	results, err := runServerTestsOnCopy(filepath.Join("testdata", "migration-old-shape"), "app")
	if err != nil {
		t.Fatalf("the fixture app did not run: %v", err)
	}
	appTests := 0
	for _, r := range results {
		if r.File == "SUMMARY" {
			continue
		}
		if r.File == "old_shape" {
			appTests++
		}
		if r.Pass {
			continue
		}
		msg := r.Message
		for _, step := range r.Steps {
			if !step.Pass {
				msg += "\n    - " + step.Action + ": " + step.Message
			}
		}
		t.Errorf("%s/%s: %s", r.File, r.Test, msg)
	}
	if appTests != 3 {
		t.Errorf("ran %d of the fixture's 3 tests", appTests)
	}
}

// A statement that names a framework table (`_benmore_*`) or a SQLite one
// (`sqlite_*`) is never skipped. Such a table is not something the schema
// lost: the start creates several of them after the migration files, so the
// statement fails on a new database although it ran on every database that
// already existed, and skipping it would bring a new instance up without what
// the file put there (a trigger that expires reset links, a role grant). It
// fails as on an existing database, with the same text, and nothing of the
// file stays.
func TestNewDatabaseNeverSkipsAStatementThatNamesAFrameworkTable(t *testing.T) {
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	for name, tc := range map[string]struct {
		stmt string
		want string
	}{
		"trigger on a framework table":            {"CREATE TRIGGER reset_expiry AFTER INSERT ON main._benmore_password_resets BEGIN\n  DELETE FROM main._benmore_password_resets WHERE created_at < datetime('now', '-1 hour');\nEND;", "no such table: main._benmore_password_resets"},
		"insert into a framework table":           {"INSERT OR IGNORE INTO _benmore_user_roles (user_id, role) SELECT id, 'manager' FROM attachments;", "no such table: _benmore_user_roles"},
		"update reading a framework table":        {"UPDATE attachments SET seen = COALESCE((SELECT user_id FROM _benmore_audit_log WHERE record_id = attachments.id LIMIT 1), 0);", "no such table: _benmore_audit_log"},
		"framework table, quoted, other case":     {`DELETE FROM "_BenMore_Password_Resets";`, "no such table: _BenMore_Password_Resets"},
		"framework table, bracketed, main schema": {"DELETE FROM main.[_benmore_api_tokens];", "no such table: main._benmore_api_tokens"},
		"column of a framework table it holds":    {"UPDATE _benmore_users SET legacy_plan = 'pro';", "no such column: legacy_plan"},
		"insert column of a framework table":      {"INSERT INTO _benmore_users (email, legacy_plan) VALUES ('a@example.test', 'pro');", "table _benmore_users has no column named legacy_plan"},
		// A name the schema lost next to a framework table: SQLite names one
		// of the two, and either way the statement is not skipped.
		"lost column and a missing framework table":  {"UPDATE attachments SET checksum = (SELECT action FROM _benmore_audit_log LIMIT 1);", "no such "},
		"lost column and a framework table it holds": {"UPDATE attachments SET name = checksum WHERE id IN (SELECT id FROM _benmore_users);", "no such column: checksum"},
		"lost table and a framework table it holds":  {"INSERT INTO legacy_scans (id) SELECT id FROM _benmore_users;", "no such table: legacy_scans"},
		"sqlite table": {"DELETE FROM sqlite_stat1;", "no such table: sqlite_stat1"},
	} {
		t.Run(name, func(t *testing.T) {
			const file = "0005_framework_tables.sql"
			body := "UPDATE attachments SET seen = 7;\n" + tc.stmt + "\n"
			fixture := func() (string, *sql.DB) {
				dir, db := newDatabaseRunnerFixture(t)
				mustExec(t, db, `CREATE TABLE _benmore_users (id INTEGER PRIMARY KEY, email TEXT)`)
				writeMig(t, dir, file, body)
				return dir, db
			}

			dir, db := fixture()
			skips, logged, err := runNewDatabaseMigrations(t, db, dir)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want a failure naming %q, got %v\n%s", tc.want, err, logged)
			}
			if len(skips.drops) != 0 || strings.Contains(logged, "WARNING") || strings.Contains(logged, "skipping") {
				t.Fatalf("a statement was skipped: %+v\n%s", skips.drops, logged)
			}
			if n := dropFreshLedgerCount(t, db, file); n != 0 {
				t.Fatalf("the failed file was recorded %d times", n)
			}
			var seen sql.NullInt64
			if err := db.QueryRow(`SELECT seen FROM attachments WHERE id = 1`).Scan(&seen); err != nil || seen.Valid {
				t.Fatalf("the failed file left a change behind: seen=%v err=%v", seen, err)
			}
			if _, statErr := os.Stat(filepath.Join(dir, "migrations", file+".failed.sql")); statErr != nil {
				t.Fatalf("the failed file was not set aside: %v", statErr)
			}

			// The same text as on a database that is not new.
			dir, db = fixture()
			existing := RunMigrations(db, dir)
			if existing == nil || existing.Error() != err.Error() {
				t.Fatalf("error on a new database:\n  %v\non an existing one:\n  %v", err, existing)
			}
		})
	}
}

// The names the framework and SQLite own, compared as SQLite compares them.
func TestMigrationReservedName(t *testing.T) {
	for name, want := range map[string]bool{
		"_benmore_users": true, "_BENMORE_Audit_Log": true, "_benmore_": true,
		"sqlite_master": true, "SQLite_Sequence": true, "sqlite_stat1": true,
		"benmore_users": false, "my_benmore_users": false, "_benmore": false,
		"sqlite": false, "mysqlite_copy": false, "orders": false, "": false,
	} {
		if got := migrationReservedName(name); got != want {
			t.Errorf("migrationReservedName(%q) = %v, want %v", name, got, want)
		}
	}
}
