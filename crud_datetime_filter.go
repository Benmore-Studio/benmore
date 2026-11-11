//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DateTime filter and sort operands. A DATETIME column holds whatever spelling
// its writer sent: `2026-01-15 10:00:00` from CURRENT_TIMESTAMP,
// `2026-01-15T10:00:00.000Z` from a browser, an offset form, or a bare date
// (a write is validated as an instant and stored as sent). Reads return every
// one of them as RFC 3339 UTC. Filters and sorts compared the stored text, so
// a value in the form the API itself returns matched the wrong rows: on the
// boundary day ' ' sorts before 'T', and an offset moves the instant but not
// the text. `created_at__gte=<midnight, toISOString()>` answered [] for rows
// made that day, and count agreed with it.
//
// On a column the API reads as an instant, an operand that parses as an
// instant is now compared as one: equality, the range operators, `__ne` and
// `__in`, on every list surface (count, paged total and cursor share
// applyAPIWhereWithApp) and in /api/_query and report `sources:`. A sort on
// such a column orders by instant, except where the stored text is known to
// order the same way (instantSortsAsText: created_at and updated_at).
// An operand that is no instant is compared as before, and so is a stored
// value SQLite cannot read as a date (julianday NULL): for those rows the
// predicate falls back to the old text comparison, so only rows whose stored
// value is a date can change sides.
//
// Shape. `julianday(col) op julianday(?)` alone cannot use an index on the
// column. Every stored spelling starts with its local date, and SQLite reads
// zone offsets up to 14:59 (and an hour field up to 24), so the start of a
// row's text date is within 16 hours of its instant. The operand therefore
// has a text window [lo, hi): lo is the date 16 hours before it, hi the day
// after the date 16 hours past it. A row whose text sorts before lo is before
// the operand and a row at or past hi is after it, without looking closer;
// only rows inside the window (two or three days of data) are compared as
// instants. The window bounds are plain text comparisons on the column, so an
// index on it keeps serving the range. (A text date no calendar has, such as
// 02-31, which SQLite reads as a day in March, is outside this reasoning: the
// write path refuses it, and outside the window it is placed by its text.)

// instantFilterSlack is how far the start of a stored value's text date can
// sit from its instant (see above).
const instantFilterSlack = 16 * time.Hour

// instantMaxZoneOffset is the largest zone offset SQLite's date functions
// read, in seconds.
const instantMaxZoneOffset = 14*3600 + 59*60

// columnTypeIsInstant reports whether a declared column type is one the
// SQLite driver scans into a time (so reads return it as RFC 3339 UTC).
func columnTypeIsInstant(declared string) bool {
	switch strings.ToUpper(strings.TrimSpace(declared)) {
	case "DATETIME", "DATE", "TIMESTAMP":
		return true
	}
	return false
}

// instantFilterColumns names the columns of cols compared as instants. An
// encrypted column is never one: SQL sees its ciphertext. nil when the table
// has none.
func instantFilterColumns(app *App, table string, cols []Column) map[string]bool {
	var out map[string]bool
	for _, c := range cols {
		if !columnTypeIsInstant(c.Type) || (app != nil && encryptedDefFor(app, table, c.Name) != nil) {
			continue
		}
		if out == nil {
			out = map[string]bool{}
		}
		out[c.Name] = true
	}
	return out
}

// listInstantFilterColumns is instantFilterColumns for the columns the list
// handler reads (crudTableColumns, which honors a connector's private read).
func listInstantFilterColumns(r *http.Request, app *App, table string) map[string]bool {
	if app == nil {
		return nil
	}
	cols, err := crudTableColumns(r, app, table)
	if err != nil {
		return nil
	}
	return instantFilterColumns(app, table, cols)
}

// queryInstantFilterColumns is instantFilterColumns for a table of the
// published schema generation (the columns /api/_query validates against).
func queryInstantFilterColumns(app *App, table string) map[string]bool {
	for _, t := range app.Tables {
		if t.Name == table {
			return instantFilterColumns(app, table, t.Columns)
		}
	}
	return nil
}

// instantOperand is a filter value read as an instant.
type instantOperand struct {
	utc    string // RFC 3339 UTC, the text julianday() reads
	lo, hi string // text window: rows before lo are earlier, rows at or past hi later
	raw    any    // the value as the caller sent it, for the text fallback
}

// instantOperandAt builds the operand for t. ok is false for a year or a zone
// offset SQLite's date functions cannot read (Go parses offsets up to 24:00):
// such a value keeps the text comparison.
func instantOperandAt(t time.Time, raw any) (instantOperand, bool) {
	if _, offset := t.Zone(); offset > instantMaxZoneOffset || offset < -instantMaxZoneOffset {
		return instantOperand{}, false
	}
	t = t.UTC()
	if y := t.Year(); y < 1 || y > 9998 {
		return instantOperand{}, false
	}
	return instantOperand{
		utc: t.Format(time.RFC3339Nano),
		lo:  t.Add(-instantFilterSlack).Format(time.DateOnly),
		hi:  t.Add(instantFilterSlack).AddDate(0, 0, 1).Format(time.DateOnly),
		raw: raw,
	}, true
}

// parseInstantOperand reads a filter value the way a DATETIME write is
// validated (crossFieldInstant: an ISO-8601 date or date-time, zone-less
// meaning UTC). A value that is no instant keeps the text comparison.
func parseInstantOperand(v any) (instantOperand, bool) {
	switch x := v.(type) {
	case string:
		if t, ok := crossFieldInstant(x); ok {
			return instantOperandAt(t, x)
		}
	case time.Time:
		// A report source's YAML where value (`gte: 2026-01-15`).
		return instantOperandAt(x, x)
	}
	return instantOperand{}, false
}

// instantComparisonSQL is `col op operand` compared as instants: the text
// window first (index-friendly, and it settles every row outside it), then
// the instants, falling back to the text comparison for a stored value that
// is no date. col is the column as the caller writes it in SQL; op is one of
// = != > >= < <=. ok is false for any other operator.
func instantComparisonSQL(col, op string, o instantOperand) (cond string, args []any, ok bool) {
	exact := fmt.Sprintf("COALESCE(julianday(%[1]s) %[2]s julianday(?), %[1]s %[2]s ?)", col, op)
	switch op {
	case "=":
		return fmt.Sprintf("(%[1]s >= ? AND %[1]s < ? AND %[2]s)", col, exact), []any{o.lo, o.hi, o.utc, o.raw}, true
	case "!=":
		return fmt.Sprintf("(%[1]s < ? OR %[1]s >= ? OR %[2]s)", col, exact), []any{o.lo, o.hi, o.utc, o.raw}, true
	case ">", ">=":
		return fmt.Sprintf("(%[1]s >= ? AND (%[1]s >= ? OR %[2]s))", col, exact), []any{o.lo, o.hi, o.utc, o.raw}, true
	case "<", "<=":
		return fmt.Sprintf("(%[1]s < ? AND (%[1]s < ? OR %[2]s))", col, exact), []any{o.hi, o.lo, o.utc, o.raw}, true
	}
	return "", nil, false
}

// instantInSQL is `col IN (operands)` compared as instants: one `=`
// comparison (instantComparisonSQL) per operand, OR-ed, so each keeps its own
// two- or three-day text window and SQLite serves the list as several index
// ranges. One window spanning every operand turned `__in` on two dates years
// apart into a scan of every row between them, each read as an instant.
func instantInSQL(col string, operands []instantOperand) (string, []any) {
	conds := make([]string, len(operands))
	var args []any
	for i, o := range operands {
		cond, a, _ := instantComparisonSQL(col, "=", o)
		conds[i] = cond
		args = append(args, a...)
	}
	return "(" + strings.Join(conds, " OR ") + ")", args
}

// instantListFilter builds a list filter (`?col=`, `?col__gte=`, `?col__in=`)
// on an instant column. ok is false when the value (for `__in`, any value of
// the comma list) is no instant or the operator matches text (`__like`): the
// caller then compares as written.
func instantListFilter(col, op, value string) (cond string, args []any, ok bool) {
	if op != "IN" {
		o, parsed := parseInstantOperand(value)
		if !parsed {
			return "", nil, false
		}
		return instantComparisonSQL(col, op, o)
	}
	parts := strings.Split(value, ",")
	operands := make([]instantOperand, len(parts))
	for i, p := range parts {
		o, parsed := parseInstantOperand(p)
		if !parsed {
			return "", nil, false
		}
		operands[i] = o
	}
	cond, args = instantInSQL(col, operands)
	return cond, args, true
}

// queryInstantComparison is one /api/_query comparison (`col: value`, or
// {eq|ne|gt|gte|lt|lte: value}) on an instant column. ok is false when the
// column is not one or the value is no instant.
func queryInstantComparison(instantCols map[string]bool, col, colSQL, op string, value any) (cond string, args []any, ok bool) {
	if !instantCols[col] {
		return "", nil, false
	}
	o, parsed := parseInstantOperand(value)
	if !parsed {
		return "", nil, false
	}
	return instantComparisonSQL(colSQL, op, o)
}

// instantQueryIn is instantListFilter's `__in` for an /api/_query `in` list.
func instantQueryIn(col string, list []any) (cond string, args []any, ok bool) {
	operands := make([]instantOperand, len(list))
	for i, item := range list {
		o, parsed := parseInstantOperand(item)
		if !parsed {
			return "", nil, false
		}
		operands[i] = o
	}
	cond, args = instantInSQL(col, operands)
	return cond, args, true
}

// instantOrderBy orders by an instant column: by instant, then by the stored
// text so that values SQLite cannot read as a date (NULL instants, first when
// ascending as NULLs always were) and equal instants keep one stable order.
// dir is ASC or DESC. The expression cannot be served by an index on the
// column, so the sort reads every row the WHERE matches (about 40 ms for a
// first page over 300,000 unfiltered rows, where walking an index took
// microseconds; a table without such an index already sorted every row).
// Columns the framework alone writes, created_at and updated_at, keep the
// plain sort (instantSortsAsText).
func instantOrderBy(col, dir string) string {
	return fmt.Sprintf("julianday(%[1]s) %[2]s, %[1]s %[2]s", col, dir)
}

// instantSortsAsText reports whether an instant column's stored text already
// orders as its instants, so a sort keeps the plain `ORDER BY col` an index
// can walk. That holds for the two timestamps no request can write (both are
// in protectedCreateFields and protectedUpdateFields, and bulk import refuses
// them) and the framework writes in spellings whose text orders as time:
//
//   - created_at, when its default is CURRENT_TIMESTAMP: no framework path
//     writes it either, so every row the framework made holds the default's
//     one fixed-width UTC spelling, `2026-01-15 10:00:00`.
//   - updated_at, when its default is CURRENT_TIMESTAMP or it has none: the
//     default and the @updatedAt trigger write that same spelling, and
//     prepareUpdateTimestamp (update, restore, revert, workflow transition
//     and timeout) writes it with fractional seconds,
//     `2026-01-15 10:00:00.123456789`. The two differ only by that suffix and
//     order as text exactly as they order as instants, mixed in one column
//     (TestFrameworkTimestampSpellingsOrderAsInstants).
//
// A row put there in another spelling by SQL the app or its operator wrote (a
// flow, a hook, a trigger, a migration, a SQL restore) sorts by its text, as
// it always did; filters on the column still compare instants. A column
// whose default is some other expression gets the instant sort. deleted_at
// needs no rule: lists and /api/_query return only rows where it is NULL.
func instantSortsAsText(c Column) bool {
	if !columnTypeIsInstant(c.Type) {
		return false
	}
	switch {
	case identIs(c.Name, "created_at"):
		return columnDefaultIsUTCNow(c.Default)
	case identIs(c.Name, "updated_at"):
		return columnDefaultIsUTCNow(c.Default) || columnHasNoDefault(c.Default)
	}
	return false
}

// columnHasNoDefault reports whether PRAGMA table_info gave no default for a
// column (or an explicit NULL): inserts leave it NULL.
func columnHasNoDefault(dflt string) bool {
	d := strings.TrimSpace(dflt)
	return d == "" || strings.EqualFold(d, "NULL")
}

// columnDefaultIsUTCNow reports whether a column default, as PRAGMA
// table_info returns it, is SQLite's current UTC time in the
// `YYYY-MM-DD HH:MM:SS` spelling.
func columnDefaultIsUTCNow(dflt string) bool {
	d := strings.ToLower(strings.Join(strings.Fields(dflt), ""))
	for strings.HasPrefix(d, "(") && strings.HasSuffix(d, ")") {
		d = d[1 : len(d)-1]
	}
	return d == "current_timestamp" || d == "datetime('now')"
}

// sortsByInstant reports whether a sort on col must order by instant: col is
// an instant column of cols and its text order is not known to be enough.
func sortsByInstant(app *App, table string, cols []Column, col string) bool {
	for _, c := range cols {
		if c.Name == col {
			return instantFilterColumns(app, table, []Column{c})[col] && !instantSortsAsText(c)
		}
	}
	return false
}

// listSortsByInstant is sortsByInstant for the columns the list handler reads
// (crudTableColumns: the database's own column definitions, defaults included).
func listSortsByInstant(r *http.Request, app *App, table, col string) bool {
	if app == nil {
		return false
	}
	cols, err := crudTableColumns(r, app, table)
	if err != nil {
		return false
	}
	return sortsByInstant(app, table, cols, col)
}

// querySortsByInstant is sortsByInstant for an /api/_query order_by column.
// instantCols comes from the published schema generation; whether created_at
// or updated_at keeps the plain sort is read from the database's own column
// default, and a default that cannot be read means the instant sort.
func querySortsByInstant(app *App, table, col string, instantCols map[string]bool) bool {
	if !instantCols[col] {
		return false
	}
	if !identIs(col, "created_at") && !identIs(col, "updated_at") {
		return true
	}
	cols, err := cachedTableColumns(app.DB, table)
	if err != nil {
		return true
	}
	for _, c := range cols {
		if c.Name == col {
			return !instantSortsAsText(c)
		}
	}
	return true
}
