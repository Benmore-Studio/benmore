//go:build !cli

package main

// Migration files on a database that is new in this load.
//
// A new database (the copy `benmore test` runs on, a new instance, a dev
// database built again) is created from the current schema and then handed
// every file in migrations/. A file written for an older shape names what the
// schema has since lost: the copy of a type change (`UPDATE t SET new = old`)
// fails with `no such column: old`, and so does anything that names a table
// or column removed later. Such a file could not be written to suit both
// databases, and recording every file as applied without running it would
// drop the triggers, indexes, constraints and seed rows apps keep in these
// files.
//
// So on a database that is new in this load, a statement that fails ONLY
// because it names a table or column the current schema does not have is
// skipped, reported, and the rest of the file runs. Everything else fails as
// before, and on an existing database nothing changes: there the same
// statement is a mistake.
//
// "New in this load" is read from the database before the load's schema
// step: no application table and no applied migration (migrationDatabaseIsNew).
// "The current schema does not have it" is read twice: from what the schema
// step and the start's own set-up gave the database before its first
// migration file (the snapshot taken by withMigrationNewDatabase), and from
// the database as the failing statement finds it. A table or column the
// schema declares is in the snapshot, so a statement that misses it (an
// earlier file dropped it) still fails. A statement that names a framework
// table (`_benmore_*`) or a SQLite one (`sqlite_*`) is never skipped.

import (
	"context"
	"errors"
	"regexp"
	"strings"

	sqlite3 "github.com/mattn/go-sqlite3"
)

// migrationDatabaseIsNew reports a database with no application table and no
// applied migration: nothing has been built in it yet, so this load creates
// it from the current schema. An unreadable catalog counts as not new.
func migrationDatabaseIsNew(q mutationQuerier) bool {
	var tables int
	if err := q.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE '\\_benmore\\_%' ESCAPE '\\' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'").Scan(&tables); err != nil || tables > 0 {
		return false
	}
	var ledger int
	if err := q.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_benmore_migrations'").Scan(&ledger); err != nil {
		return false
	}
	if ledger == 0 {
		return true
	}
	var applied int
	return q.QueryRow("SELECT count(*) FROM _benmore_migrations").Scan(&applied) == nil && applied == 0
}

// migrationNewDatabase is what the current schema gave a new database before
// its first migration file: each table and view of the main schema (lower
// case) with its columns (lower case). nil columns: they could not be read (a
// view over something missing), so nothing is known to be absent from it.
type migrationNewDatabase struct {
	schema map[string]map[string]bool
}

type migrationNewDatabaseKey struct{}

// withMigrationNewDatabase marks ctx's migration run as one on a database
// that is new in this load, and records the schema q holds now. Call it after
// the load's schema step and before the first migration file, and only when
// migrationDatabaseIsNew said so before the schema step. A schema that cannot
// be read leaves ctx as it was: the files run as on an existing database.
func withMigrationNewDatabase(ctx context.Context, q sqlQuerier) context.Context {
	schema, err := migrationSchemaColumns(q)
	if err != nil {
		return ctx
	}
	return context.WithValue(ctx, migrationNewDatabaseKey{}, &migrationNewDatabase{schema: schema})
}

// migrationSchemaColumns reads the main schema's tables and views with their
// columns (table_xinfo also lists generated columns).
func migrationSchemaColumns(q sqlQuerier) (map[string]map[string]bool, error) {
	rows, err := q.Query(`SELECT name FROM main.sqlite_master WHERE type IN ('table', 'view')`)
	if err != nil {
		return nil, err
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return nil, err
		}
		names = append(names, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	schema := make(map[string]map[string]bool, len(names))
	for _, name := range names {
		columns, err := migrationTableColumns(q, name)
		if err != nil {
			columns = nil
		}
		schema[strings.ToLower(name)] = columns
	}
	return schema, nil
}

// migrationTableColumns is the lower-cased column set of one main-schema
// table or view; an empty set for a name the schema does not hold.
func migrationTableColumns(q sqlQuerier, table string) (map[string]bool, error) {
	rows, err := q.Query(`SELECT name FROM pragma_table_xinfo(?, 'main')`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		columns[strings.ToLower(name)] = true
	}
	return columns, rows.Err()
}

// sqliteMissingObject is the table or column a SQLite "no such" error names.
type sqliteMissingObject struct {
	schema, table, column string
}

var sqliteNoColumnNamedRe = regexp.MustCompile(`^table (.+) has no column named (.+)$`)

// parseSQLiteMissingObject reads SQLite's three messages for a name it could
// not resolve: `no such table: [schema.]t`, `no such column: [[schema.]t.]c`
// (ALTER quotes the name, and a double-quoted one may carry a hint after it)
// and `table t has no column named c`.
func parseSQLiteMissingObject(msg string) (sqliteMissingObject, bool) {
	var missing sqliteMissingObject
	if rest, ok := strings.CutPrefix(msg, "no such table: "); ok {
		parts := strings.Split(rest, ".")
		switch len(parts) {
		case 1:
			missing.table = parts[0]
		case 2:
			missing.schema, missing.table = parts[0], parts[1]
		default:
			return missing, false
		}
		return missing, missing.table != ""
	}
	if rest, ok := strings.CutPrefix(msg, "no such column: "); ok {
		if strings.HasPrefix(rest, `"`) {
			end := strings.Index(rest[1:], `"`)
			if end <= 0 {
				return missing, false
			}
			missing.column = rest[1 : 1+end]
			return missing, true
		}
		if i := strings.IndexByte(rest, ' '); i >= 0 {
			rest = rest[:i]
		}
		parts := strings.Split(rest, ".")
		switch len(parts) {
		case 1:
			missing.column = parts[0]
		case 2:
			missing.table, missing.column = parts[0], parts[1]
		case 3:
			missing.schema, missing.table, missing.column = parts[0], parts[1], parts[2]
		default:
			return missing, false
		}
		return missing, missing.column != ""
	}
	if m := sqliteNoColumnNamedRe.FindStringSubmatch(msg); m != nil {
		missing.table, missing.column = m[1], m[2]
		return missing, true
	}
	return missing, false
}

// migrationSkipVerbs are the leading keywords a skipped statement is reported
// with.
var migrationSkipVerbs = map[string]bool{
	"UPDATE": true, "INSERT": true, "REPLACE": true, "DELETE": true, "SELECT": true,
	"WITH": true, "ALTER": true, "CREATE": true, "DROP": true,
}

// staleStatement reports whether stmt, which failed with err, failed only
// because it names a table or column the current schema does not have, and
// names what is missing: kind "table" with the table, or kind "column" with
// table.column (the column alone when the statement reads several tables).
// Deliberately narrow, and every doubt is a real failure:
//   - SQLite's own "no such table", "no such column" or "has no column
//     named", never a trigger's RAISE with the same text;
//   - in the main schema;
//   - the statement itself names the missing table or column: a statement
//     that only fires a trigger whose body names it is a broken trigger, and
//     so is a column SQLite reports as NEW.c or OLD.c;
//   - the table is in neither the snapshot nor the database now;
//   - the column is in no table the statement reads (the one SQLite named,
//     when it named one), in neither the snapshot nor the database now;
//   - nothing in it is the framework's or SQLite's (migrationReservedName):
//     not the missing table, not the table of the missing column, and no
//     other name the statement uses. Those tables are not something the
//     schema lost. The start creates several of them after the migration
//     files (password resets, role grants, the audit log), so a trigger on
//     one or a statement that reads or writes one fails here although it ran
//     on every database that already existed; skipping it would bring a new
//     instance up without what the file put there. SQLite names one missing
//     object per error, so a statement that also names a lost app column is
//     judged by its names, not by which of the two SQLite met first.
func (n *migrationNewDatabase) staleStatement(q sqlQuerier, stmt string, err error) (kind, missing string, ok bool) {
	var se sqlite3.Error
	if n == nil || !errors.As(err, &se) || se.Code != sqlite3.ErrError {
		return "", "", false
	}
	object, parsed := parseSQLiteMissingObject(se.Error())
	if !parsed || (object.schema != "" && !strings.EqualFold(object.schema, "main")) {
		return "", "", false
	}
	if migrationReservedName(object.table) || migrationReservedName(object.column) {
		return "", "", false
	}
	named := map[string]bool{}
	for _, tok := range sqlTokenize(stmt) {
		if tok.kind == sqlTokWord || tok.kind == sqlTokIdent {
			if migrationReservedName(tok.text) {
				return "", "", false
			}
			named[strings.ToLower(tok.text)] = true
		}
	}
	table, column := strings.ToLower(object.table), strings.ToLower(object.column)
	if column == "" {
		if !named[table] || n.holdsTable(q, table) {
			return "", "", false
		}
		return "table", object.table, true
	}
	if !named[column] || table == "new" || table == "old" {
		return "", "", false
	}
	// The tables whose column this could be.
	var candidates []string
	if table != "" && n.holdsTable(q, table) {
		candidates = []string{table}
	} else {
		live, err := migrationSchemaColumns(q)
		if err != nil {
			return "", "", false
		}
		for name := range named {
			_, snapshot := n.schema[name]
			if _, now := live[name]; snapshot || now {
				candidates = append(candidates, name)
			}
		}
	}
	if len(candidates) == 0 {
		return "", "", false
	}
	for _, candidate := range candidates {
		if columns, known := n.schema[candidate]; known && (columns == nil || columns[column]) {
			return "", "", false
		}
		now, err := migrationTableColumns(q, candidate)
		if err != nil || now[column] {
			return "", "", false
		}
	}
	if len(candidates) == 1 {
		return "column", candidates[0] + "." + object.column, true
	}
	return "column", object.column, true
}

// migrationReservedName reports a name the framework (`_benmore_*`) or SQLite
// (`sqlite_*`) owns, compared as SQLite compares identifiers. The caller
// passes names without their quoting and without a schema qualifier.
func migrationReservedName(name string) bool {
	return frameworkObjectName(name) || strings.HasPrefix(sqliteIdentifierFold(name), "sqlite_")
}

// holdsTable reports whether the snapshot or the database now holds a table
// or view of that (lower-cased) name. A check that cannot be made says yes.
func (n *migrationNewDatabase) holdsTable(q sqlQuerier, table string) bool {
	if _, ok := n.schema[table]; ok {
		return true
	}
	held, err := migrationSchemaHolds(q, `SELECT 1 FROM main.sqlite_master WHERE type IN ('table', 'view') AND name = ? COLLATE NOCASE`, table)
	return err != nil || held
}

// migrationStatementStaleOnNewDatabase is the runner's question for a failed
// statement: on a database that is new in this load (ctx carries
// withMigrationNewDatabase), is it skipped? position is the statement's place
// in its file, from 1. The answer is the record to report.
func migrationStatementStaleOnNewDatabase(ctx context.Context, q sqlQuerier, stmt string, position int, err error) (migrationSkippedDrop, bool) {
	n, _ := ctx.Value(migrationNewDatabaseKey{}).(*migrationNewDatabase)
	kind, missing, ok := n.staleStatement(q, stmt, err)
	if !ok {
		return migrationSkippedDrop{}, false
	}
	skipped := migrationSkippedDrop{Kind: kind, Missing: missing, Statement: position}
	if toks := sqlTokenize(stmt); len(toks) > 0 && toks[0].kind == sqlTokWord {
		if verb := strings.ToUpper(toks[0].text); migrationSkipVerbs[verb] {
			skipped.Verb = verb
		}
	}
	return skipped, true
}
