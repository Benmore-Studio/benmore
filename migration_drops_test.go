//go:build !cli

package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A user migration that dropped a column holding data was logged only as
// "migration: applied <name>" (2026-10-29); a destructive generated migration
// prints a DESTRUCTIVE MIGRATION line. The runner now prints it for both.
func TestUserMigrationThatDropsDataIsLoggedAsDestructive(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mustExec(t, db, `CREATE TABLE contacts (id INTEGER PRIMARY KEY, name TEXT, job_title TEXT)`)
	mustExec(t, db, `INSERT INTO contacts (name, job_title) VALUES ('Ada', 'CTO'), ('Bo', 'CEO')`)
	if err := os.MkdirAll(filepath.Join(dir, "migrations"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"0005a_add_team.sql":              "-- UP --\nALTER TABLE contacts ADD COLUMN team TEXT;\n",
		"0005b_hotfix_drop_job_title.sql": "-- UP --\nALTER TABLE contacts DROP COLUMN job_title;\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, "migrations", name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := captureLog(t, func() {
		if err := RunMigrations(db, dir); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "DESTRUCTIVE MIGRATION 0005b_hotfix_drop_job_title.sql: DROP COLUMN contacts.job_title (2 rows with a value)") {
		t.Fatalf("the drop was not logged as destructive:\n%s", out)
	}
	if strings.Count(out, "DESTRUCTIVE MIGRATION") != 1 {
		t.Fatalf("a migration that drops nothing was logged as destructive:\n%s", out)
	}
	if dbColumnExists(db, "contacts", "job_title") {
		t.Fatal("the migration did not run")
	}
}

func TestUserMigrationFileName(t *testing.T) {
	for path, want := range map[string]string{
		"migrations/0005_x.sql":        "0005_x.sql",
		"./migrations/0005_x.sql":      "0005_x.sql",
		`migrations\0005_x.sql`:        "", // one name at the app root on Linux
		"migrations/0005_x.failed.sql": "",
		"migrations/old/0005_x.sql":    "",
		"migrations/0005_x.sql.txt":    "",
		"0005_x.sql":                   "",
		"static/migrations/0005_x.sql": "",
		"migrations/../schema.sql":     "",
	} {
		got, ok := userMigrationFileName(path)
		if got != want || ok != (want != "") {
			t.Errorf("userMigrationFileName(%q) = %q, %v; want %q", path, got, ok, want)
		}
	}
}

// The detection reads statements the way SQLite does: a statement that starts
// with a block comment, names its table through the main schema, quotes its
// names or shares a line with another statement is the same drop. Regexes over
// the statement text missed the first two, so such a file was neither refused
// nor logged.
func TestMigrationDataDropsReadsStatementsAsSQLiteDoes(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mustExec(t, db, `CREATE TABLE contacts (id INTEGER PRIMARY KEY, name TEXT, job_title TEXT, nickname TEXT)`)
	mustExec(t, db, `INSERT INTO contacts (name, job_title) VALUES ('Ada', 'CTO'), ('Bo', 'CEO')`)
	mustExec(t, db, `CREATE TABLE drafts (id INTEGER PRIMARY KEY)`)
	const column = "DROP COLUMN contacts.job_title (2 rows with a value)"
	const table = "DROP TABLE contacts (2 rows)"
	for body, want := range map[string]string{
		"/* hotfix */ ALTER TABLE contacts DROP COLUMN job_title;":                        column,
		"/* a\nmulti-line note */\nALTER TABLE contacts DROP COLUMN job_title;":           column,
		"ALTER TABLE main.contacts DROP COLUMN job_title;":                                column,
		`ALTER TABLE "main"."contacts" DROP COLUMN "job_title";`:                          column,
		"ALTER TABLE [contacts] DROP [job_title];":                                        column,
		"alter table contacts /* why */ drop column job_title;":                           column,
		"ALTER TABLE contacts ADD COLUMN team TEXT; ALTER TABLE contacts DROP job_title;": column,
		"/* tidy */ DROP TABLE contacts;":                                                 table,
		"DROP TABLE IF EXISTS main.contacts;":                                             table,
		"DROP TABLE `contacts`;":                                                          table,
		"DROP TABLE CONTACTS;":                                                            "DROP TABLE CONTACTS (2 rows)",
		"ALTER TABLE Contacts DROP COLUMN Job_Title;":                                     "DROP COLUMN Contacts.Job_Title (2 rows with a value)",
		"-- note\nDROP TABLE main . contacts;":                                            table,
		// Not a loss: another schema, an empty table or column, a constraint,
		// the generator's rebuild (comments included), text that only mentions a drop.
		"DROP TABLE temp.contacts;":                                   "",
		"ALTER TABLE temp.contacts DROP COLUMN job_title;":            "",
		"DROP TABLE drafts;":                                          "",
		"ALTER TABLE contacts DROP COLUMN nickname;":                  "",
		"ALTER TABLE contacts DROP CONSTRAINT fk;":                    "",
		"INSERT INTO drafts (id) VALUES (1); -- DROP TABLE contacts;": "",
		"UPDATE contacts SET name = 'DROP TABLE contacts';":           "",
		"CREATE TABLE contacts_new (id INTEGER PRIMARY KEY);\n/* copy */ INSERT INTO contacts_new SELECT id FROM contacts;\n/* swap */ DROP TABLE main.contacts;\n/* name */ ALTER TABLE main.contacts_new RENAME TO \"contacts\";": "",
	} {
		drops, err := migrationDataDrops(db, "-- UP --\n"+body+"\n")
		if err != nil {
			t.Fatalf("%q: %v", body, err)
		}
		if got := strings.Join(drops, ", "); got != want {
			t.Errorf("%q: drops %q, want %q", body, got, want)
		}
	}
}

// The reader follows a table through the file: rows renamed onto another name
// and dropped there are the same loss as a plain DROP TABLE, and a rebuild is
// exempt only when the file fills the table that takes the dropped one's place.
// `ALTER TABLE scratches RENAME TO scratches_retired; DROP TABLE
// scratches_retired;` passed the write gate, promote and restore (2026-11-04),
// and so did a rebuild that copied nothing.
func TestMigrationDataDropsFollowsRenamesAndCopies(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mustExec(t, db, `CREATE TABLE scratches (id INTEGER PRIMARY KEY, body TEXT, note TEXT)`)
	mustExec(t, db, `INSERT INTO scratches (body, note) VALUES ('a', 'x'), ('b', 'y')`)
	mustExec(t, db, `CREATE TABLE drafts (id INTEGER PRIMARY KEY)`)
	const create = "CREATE TABLE scratches_new (id INTEGER PRIMARY KEY, body TEXT, note TEXT);\n"
	for body, want := range map[string]string{
		"ALTER TABLE scratches RENAME TO scratches_retired;\nDROP TABLE scratches_retired;":                                  "scratches: 2 rows, by RENAME TO scratches_retired + DROP TABLE scratches_retired",
		"ALTER TABLE scratches RENAME TO scratches_retired; DROP TABLE IF EXISTS main.\"scratches_retired\";":                "scratches: 2 rows, by RENAME TO scratches_retired + DROP TABLE scratches_retired",
		"ALTER TABLE Scratches RENAME TO a;\nALTER TABLE A RENAME TO b;\nDROP TABLE b;":                                      "Scratches: 2 rows, by RENAME TO a + RENAME TO b + DROP TABLE b",
		"ALTER TABLE scratches RENAME TO scratches_old;\nALTER TABLE drafts RENAME TO scratches;\nDROP TABLE scratches_old;": "scratches: 2 rows, by RENAME TO scratches_old + DROP TABLE scratches_old",
		create + "DROP TABLE scratches;\nALTER TABLE scratches_new RENAME TO scratches;":                                     "DROP TABLE scratches (2 rows)",
		"CREATE TABLE archive AS SELECT * FROM scratches;\nDROP TABLE scratches;":                                            "DROP TABLE scratches (2 rows)",
		"ALTER TABLE scratches RENAME TO s2;\nALTER TABLE s2 DROP COLUMN note;":                                              "DROP COLUMN s2.note (2 rows with a value)",
		"ALTER TABLE scratches RENAME COLUMN note TO memo;\nALTER TABLE scratches DROP COLUMN memo;":                         "DROP COLUMN scratches.memo (2 rows with a value)",
		// Kept: a rebuild that fills the replacement, either way round, and a
		// rename that keeps the rows under another name.
		create + "INSERT INTO scratches_new SELECT id, body, note FROM scratches;\nDROP TABLE scratches;\nALTER TABLE scratches_new RENAME TO scratches;":                                                       "",
		"ALTER TABLE scratches RENAME TO scratches_old;\nCREATE TABLE scratches (id INTEGER PRIMARY KEY, body TEXT, note TEXT);\nINSERT INTO scratches SELECT * FROM scratches_old;\nDROP TABLE scratches_old;": "",
		"ALTER TABLE scratches RENAME TO scratches_retired;":                                         "",
		"ALTER TABLE scratches RENAME TO tmp;\nALTER TABLE tmp RENAME TO scratches;":                 "",
		"ALTER TABLE drafts RENAME TO drafts_old;\nDROP TABLE drafts_old;":                           "",
		"CREATE TABLE IF NOT EXISTS scratches (id INTEGER PRIMARY KEY);\nDROP TABLE scratches_gone;": "",
	} {
		drops, err := migrationDataDrops(db, "-- UP --\n"+body+"\n")
		if err != nil {
			t.Fatalf("%q: %v", body, err)
		}
		if got := strings.Join(drops, ", "); got != want {
			t.Errorf("%q:\n drops %q\n want  %q", body, got, want)
		}
	}
}
