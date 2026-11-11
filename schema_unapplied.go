//go:build !cli

package main

// Schema changes the migration generator does not apply.
//
// The Prisma generator (prisma_migrate.go) turns added models, fields,
// indexes and uniques into SQL. A changed field type, nullability or default,
// a removed field and a removed @unique produce no SQL: SQLite cannot alter a
// column in place, and the rebuild that would (a type cast, a NOT NULL over
// NULL rows, dropping a column with data) can lose or reject data. Those
// changes used to vanish without a word when they were the whole edit: no
// migration file, no log line, ok:true on the push, while the live column
// kept its old type (round-2 finding L5: Int -> String left an INTEGER column
// that stored "007" as 7, and dev and prod drifted apart physically).
//
// The generator still leaves the live column as it is, here and on prod
// after a promote, so both instances stay alike. What changed is that the
// edit is no longer silent: DiffSchemas names each such change and what the
// live database will and will not do, and the same list is
//   - returned by the schema.prisma write (write_file / edit_file,
//     `benmore push`) as schema_not_applied,
//   - reported by `benmore check` before the app reloads, and
//   - logged by the load that records the new schema.
// To make the change for real, write a migrations/ file (see each message).

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func unappliedColumnRemoved(table, col string) string {
	return fmt.Sprintf("field removed: %s.%s - the live column and its data stay, and API reads keep returning it; Benmore never drops a column on its own. To drop it, add a migrations/ file with `ALTER TABLE %s DROP COLUMN %s;` (promote asks for force before that file runs on prod).",
		table, col, ddlIdent(table), ddlIdent(col))
}

func unappliedTypeChange(table, col, from, to string) string {
	example := ""
	switch fromNum, toNum := sqliteNumericAffinity(from), sqliteNumericAffinity(to); {
	case fromNum && !toNum:
		example = ` (a value like "007" is stored as 7)`
	case !fromNum && toNum:
		example = " (numbers are stored as text and sort as text)"
	}
	return fmt.Sprintf("type changed: %s.%s %s → %s - the live column keeps type %s and stores new values with that type's affinity%s, here and on prod after promote. Benmore does not change a column's type in place: add a field with the new type, copy the values over in a migrations/ file, then remove the old field.",
		table, col, from, to, from, example)
}

func unappliedNullabilityChange(table, col string, nowOptional bool) string {
	if nowOptional {
		return fmt.Sprintf("now optional: %s.%s - the live column stays NOT NULL, so creating a row without a value still fails unless the column has a default. Accepting NULL takes a table rebuild in a migrations/ file.", table, col)
	}
	return fmt.Sprintf("now required: %s.%s - the live column still accepts NULL and rows that hold NULL keep it; the API refuses a create without a value, but SQL writes (flows, hooks, imports) can still store NULL. Backfill those rows in a migrations/ file (`UPDATE %s SET %s = ... WHERE %s IS NULL;`).", table, col, table, col, col)
}

func unappliedDefaultChange(table, col, from, to string) string {
	label := func(d string) string {
		if d == "" {
			return "(none)"
		}
		return d
	}
	return fmt.Sprintf("default changed: %s.%s %s → %s - the live column keeps the default it was created with, so a row created without a value still gets the old one, here and on prod after promote; only a new database uses %s. Send the value explicitly where it matters, or rebuild the table in a migrations/ file.",
		table, col, label(from), label(to), label(to))
}

// requiredFieldBackfill describes a required field added to an existing table
// without @default: the migration adds the column NOT NULL with the type's
// zero value as its DEFAULT (prismaAddColumnDefinition), so existing rows get
// that value and the column keeps it as a database default, while the API
// refuses a create without the field. It used to happen in silence: an Int
// field read 0 on every old row, and SQL inserts that left it out stored 0.
func requiredFieldBackfill(table string, f PrismaField) string {
	fill := notNullBackfillDefault(f.Type)
	value := fill
	switch fill {
	case "''":
		value = "'' (an empty string)"
	case "CURRENT_TIMESTAMP":
		value = "the time the migration ran"
	case "0":
		if strings.EqualFold(f.Type, "BOOLEAN") || strings.EqualFold(f.Type, "BOOL") {
			value = "0 (false)"
		}
	}
	return fmt.Sprintf("required field added without a default: %s.%s (%s) - every row that already exists gets %s = %s, and the live column keeps DEFAULT %s, so a SQL insert (flow, hook, import) that leaves %s out stores %s while the API refuses a create without it (a new database has no such default). To choose the value, add the field with `@default(<value>)`, or set existing rows in a migrations/ file (`UPDATE %s SET %s = <value>;`).",
		table, f.Column, f.Type, f.Column, value, fill, f.Column, fill, table, f.Column)
}

// prismaBackfillNotices lists requiredFieldBackfill for each column diff adds
// to an existing table, in table and declaration order. A field that is
// optional, has a @default, is a foreign key (never backfilled) or is
// @updatedAt (its value is the write time by design) is not listed.
func prismaBackfillNotices(diff MigrationDiff) []string {
	tables := make([]string, 0, len(diff.ColumnsAdded))
	for t := range diff.ColumnsAdded {
		tables = append(tables, t)
	}
	sort.Strings(tables)
	var out []string
	for _, t := range tables {
		for _, f := range diff.ColumnsAdded[t] {
			if f.Optional || f.Default != "" || f.FKTable != "" || f.IsID || f.Autoincr || f.UpdatedAt {
				continue
			}
			out = append(out, requiredFieldBackfill(t, f))
		}
	}
	return out
}

// sqliteNumericAffinity reports whether SQLite gives a column of this declared
// type INTEGER, REAL or NUMERIC affinity (sqlite.org/datatype3.html 3.1), so
// that text which looks like a number is stored as a number.
func sqliteNumericAffinity(declared string) bool {
	t := strings.ToUpper(declared)
	switch {
	case strings.Contains(t, "INT"):
		return true
	case strings.Contains(t, "CHAR"), strings.Contains(t, "CLOB"), strings.Contains(t, "TEXT"):
		return false
	case strings.Contains(t, "BLOB"), strings.TrimSpace(t) == "":
		return false
	}
	return true // REAL, FLOA, DOUB, and everything else (NUMERIC, DATETIME, BOOLEAN)
}

// prismaUnappliedChanges lists the changes in src, a schema.prisma source,
// that db's next migration will not apply as declared: the generator's own
// warnings for the step from the schema db last recorded to src, then the
// required fields it adds with a backfill default (prismaBackfillNotices). A database that has not
// applied a schema yet gets every table created from src, so it has none.
func prismaUnappliedChanges(db *sql.DB, src string) ([]string, error) {
	curr, err := ParsePrismaSchema(src)
	if err != nil {
		return nil, err
	}
	if ok, err := tableExists(db, "_benmore_migrations"); err != nil || !ok {
		return nil, err
	}
	var last string
	err = db.QueryRow(`SELECT source FROM _benmore_migrations WHERE source <> '' ORDER BY id DESC LIMIT 1`).Scan(&last)
	if err == sql.ErrNoRows || err == nil && last == "" {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	prev, err := ParsePrismaSchema(last)
	if err != nil {
		return nil, nil // a recorded source this parser refuses: nothing to compare
	}
	diff := DiffSchemas(prev, curr)
	changes := diff.Warnings
	// The backfill of a required field is applied, but not as declared: the
	// live column gets a default the schema does not have. Columns the live
	// table already holds are left out, as the migration leaves them out.
	return append(changes, prismaBackfillNotices(reconcileDiffAgainstLive(diff, db))...), nil
}

// schemaUnappliedFindings is `benmore check`'s view of the same list: the
// on-disk schema.prisma against the app's live database, read-only. It runs
// before the check's own validation load, which records the schema.
func schemaUnappliedFindings(dir string) []CheckFinding {
	src, err := os.ReadFile(filepath.Join(dir, "schema.prisma"))
	if err != nil {
		return nil
	}
	// openCheckDB refuses a data.db that is, or becomes, a link to another
	// file (this runs in the app's own process: check_live, the boot check).
	db, err := openCheckDB(filepath.Join(dir, "data.db"), "ro")
	if err != nil {
		return nil
	}
	defer db.Close()
	changes, err := prismaUnappliedChanges(db, string(src))
	if err != nil {
		return nil // a parse error is the syntax layer's; an unreadable DB the load's
	}
	findings := make([]CheckFinding, 0, len(changes))
	for _, c := range changes {
		findings = append(findings, CheckFinding{
			Severity: "warning",
			Source:   "schema_not_applied",
			File:     "schema.prisma",
			Message:  c,
		})
	}
	return findings
}
