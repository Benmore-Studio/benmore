//go:build !cli

package main

import (
	"context"
	"database/sql"
	"regexp"
	"strings"

	"github.com/mattn/go-sqlite3"
)

// Read-only SQL written by a person (query_db, `benmore sql`, the dashboard
// console) must never hand back ciphertext (rule 26c). DecryptRowFields opens
// a value that IS a ciphertext, but `substr(ssn, 2)`, `hex(ssn)` or
// `'x' || ssn` is a piece of one that no longer starts with `enc:`, so what a
// value looks like cannot decide it. Where the result column comes from does,
// and SQLite says so itself:
//
//   - the authorizer names every table.column a statement reads while it is
//     compiled (views, subqueries and CTEs included), and is called once for
//     each SELECT it compiles;
//   - a result column has a declared type only when it is a table column
//     selected as it is, not an expression.
//
// A statement that reads no sealed column is left alone. One that does keeps
// the values of its plain table columns (the sealed one decrypted as before)
// and shows the field mask for every other result column.

// readOnlySealedColumns lists the columns whose stored value is ciphertext:
// every encrypted.yaml column and its copy in the table's version history,
// keyed like the rotation targets (folded table, NUL, folded column). The
// blind-index sibling is an HMAC, not ciphertext, and is not listed. nil for
// an app with no encrypted column, whose statements are then not inspected.
func readOnlySealedColumns(app *App) map[string]bool {
	if app == nil || app.Encrypted == nil {
		return nil
	}
	var sealed map[string]bool
	for table, defs := range app.Encrypted.Fields {
		for _, def := range defs {
			if sealed == nil {
				sealed = map[string]bool{}
			}
			column := sqliteIdentifierFold(def.Column)
			sealed[sqliteIdentifierFold(table)+"\x00"+column] = true
			sealed[sqliteIdentifierFold(table+versionHistorySuffix)+"\x00"+column] = true
		}
	}
	return sealed
}

// readOnlySealedReads records, for one statement on one pinned connection,
// whether it reads a sealed column and how many SELECTs SQLite compiled for
// it. The authorizer runs on the goroutine that prepares and steps the
// statement, which is the one that reads the answer afterwards.
type readOnlySealedReads struct {
	sealed  map[string]bool
	selects int
	read    bool
}

func (r *readOnlySealedReads) authorize(action int, arg1, arg2, database string) int {
	switch action {
	case sqlite3.SQLITE_SELECT, sqliteRecursiveSelect:
		r.selects++
	case sqlite3.SQLITE_READ:
		if r.sealed[sqliteIdentifierFold(arg1)+"\x00"+sqliteIdentifierFold(arg2)] {
			r.read = true
		}
	}
	return authorizeReadOnlyQuery(action, arg1, arg2, database)
}

// readOnlyDeclaredColumns reports, per result column, whether SQLite gives it
// a declared type.
func readOnlyDeclaredColumns(rows *sql.Rows, n int) []bool {
	declared := make([]bool, n)
	types, err := rows.ColumnTypes()
	if err != nil || len(types) != n {
		return declared
	}
	for i, t := range types {
		declared[i] = t != nil && t.DatabaseTypeName() != ""
	}
	return declared
}

// derived reports whether the statement's computed columns must be masked: it
// read a sealed column, or it may have without the authorizer knowing: it was
// never seen compiled (a statement cache would do that; the app DSN sets
// none), or it holds a FULL join by column name.
// Asked after the last row was stepped, so reads SQLite reports late (a
// virtual table compiles its own statements while stepping) are counted.
func (r *readOnlySealedReads) derived(query string) bool {
	return r.read || r.selects == 0 || readOnlyUnrecordedRead(query)
}

// A join that names its columns (USING, NATURAL) is the one place SQLite reads
// a column without asking the authorizer: it builds those column references
// itself. The join condition compares the columns, and a FULL join's result
// column is coalesce() of both sides, so `SELECT code FROM _benmore_otp a FULL
// JOIN _benmore_otp b USING (code)` returned a column the authorizer answers
// SQLITE_IGNORE for, and `substr(ssn, 2)` over such a join read a sealed
// column unrecorded. Both keywords must be written bare (a quoted join word is
// a syntax error) and a keyword cannot touch a letter, digit or underscore, so
// a word match finds every one; a false match only refuses or masks more.
var (
	readOnlyNamedJoinRe = regexp.MustCompile(`(?i)\b(using|natural)\b`)
	readOnlyFullJoinRe  = regexp.MustCompile(`(?i)\bfull\b`)
)

// readOnlyNamedJoinRefusal is the answer to a statement that joins by column
// name and names a framework table: its credential columns read as NULL only
// where the authorizer is asked.
const readOnlyNamedJoinRefusal = "read-only SQL refuses the words USING and NATURAL in a statement that names a framework table (_benmore_*): write the join with ON"

func readOnlyNamedJoinOnFrameworkTable(query string) bool {
	return readOnlyNamedJoinRe.MatchString(query) && strings.Contains(strings.ToLower(query), "_benmore_")
}

// readOnlyUnrecordedRead reports a statement whose FULL join by column name
// can read a sealed column without the authorizer hearing of it.
func readOnlyUnrecordedRead(query string) bool {
	return readOnlyFullJoinRe.MatchString(query) && readOnlyNamedJoinRe.MatchString(query)
}

// readOnlyCompoundWords are the only ways SQLite's grammar joins the rows of
// several SELECTs into one result: the three compound operators and a
// multi-row VALUES. Matched as raw substrings, like load_extension: a keyword
// cannot be written any other way, and a false match only masks more.
var readOnlyCompoundWords = []string{"union", "intersect", "except", "values"}

// readOnlyMayCombine reports whether a statement SQLite compiled as several
// SELECTs could join the rows of two of them: its text holds a compound word,
// or the database has a view (whose text is not in the statement). The
// connection is the statement's own, after its rows are closed. An error
// counts as yes.
func readOnlyMayCombine(ctx context.Context, conn *sql.Conn, query string) bool {
	lower := strings.ToLower(query)
	for _, word := range readOnlyCompoundWords {
		if strings.Contains(lower, word) {
			return true
		}
	}
	var views int
	err := conn.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM sqlite_master WHERE type = 'view') + (SELECT count(*) FROM sqlite_temp_master WHERE type = 'view')`).Scan(&views)
	return err != nil || views != 0
}

// readOnlyMaskDerived replaces what a statement that read a sealed column
// computed. A result column keeps its value only when it is provably a table
// column selected as it is: it has a declared type AND that type is known to
// describe every row (oneOrigin).
//
// The second half matters because SQLite takes the declared types of combined
// SELECTs from one of them only: `SELECT name FROM t WHERE 0 UNION ALL SELECT
// substr(ssn, 2) FROM t` reports the type of `name`, and the same holds for a
// compound inside a subquery, CTE or view. So the types are trusted when the
// whole statement compiled as one SELECT, or when it compiled as several that
// cannot be combined (readOnlyMayCombine): then each column SQLite traces
// through a subquery or CTE has exactly one expression behind it.
//
// Not proven, so masked: COUNT(col), `col IS NULL`, length(col), and a column
// created without a type. NULL stays NULL, as under the field mask.
func readOnlyMaskDerived(rows []map[string]any, cols []string, declared []bool, oneOrigin bool) {
	var masked []string
	for i, name := range cols {
		// Checked per column, not per name: two result columns may share a
		// name and the row keeps the last one.
		if !oneOrigin || i >= len(declared) || !declared[i] {
			masked = append(masked, name)
		}
	}
	for _, row := range rows {
		for _, name := range masked {
			if row[name] != nil {
				row[name] = encryptedFieldMask
			}
		}
	}
}
