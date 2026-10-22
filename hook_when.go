//go:build !cli

package main

// Hook and workflow `when:` conditions: a SQLite boolean evaluated against
// the event row.
//
// The row is presented as a one-row CTE named after the table, so
// `when: "status IN ('approved','denied') AND old_status != status"` or
// `NOT EXISTS (SELECT 1 FROM exceptions x WHERE x.booking_id = bookings.id)`
// read the row's values, and `main.<table>` still reaches the stored table:
//
//	WITH "bookings" AS (SELECT CAST(? AS TEXT) AS "status", ...)
//	SELECT CASE WHEN (<when>) THEN 1 ELSE 0 END FROM "bookings"
//
// Every value is bound, never interpolated, and the query is read-only:
// on the app database it runs on a pinned connection with query_only and
// a SELECT-only authorizer; inside a transaction (before-hooks of
// transactional writes) with query_only, after the text has been checked
// to be one expression. Any error is "not met" for the caller to act on
// (before-hooks refuse the write), logged once.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mattn/go-sqlite3"
)

// whenConditionTimeout bounds one `when:` evaluation. Hooks run inline on
// write paths, so a heavy subquery must not hold the request.
var whenConditionTimeout = 2 * time.Second

// whenExtraKeyCap bounds the row keys beyond the table's columns, old_*
// and session keys (update rows carry every submitted key).
const whenExtraKeyCap = 200

// whenRecursiveSelect is SQLITE_RECURSIVE from sqlite3.h; go-sqlite3 does
// not export it.
const whenRecursiveSelect = 33

// whenSessionKeys are the caller keys injectSessionContext adds, plus the
// before-hook submitted-field list. They are always defined (NULL when
// absent), so a condition that names one never fails for a sessionless
// event.
var whenSessionKeys = []string{"user_id", "user_email", "user_role", "user_roles", "user_group_id", submittedFieldsKey}

// whenKeyRe is a row key that can be a CTE column without quoting games.
var whenKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// whenColumn is one CTE column: its name and the declared type whose
// affinity its value takes ("" for keys that aren't table columns).
type whenColumn struct {
	name     string
	declType string
	loose    bool
}

// evaluateWhen evaluates a hook or workflow `when:` against row. q is the
// app database or the transaction the hook runs in. An error means the
// condition could not be evaluated; callers fail closed.
func evaluateWhen(q mutationQuerier, app *App, table, when string, row map[string]any) (bool, error) {
	cols := whenColumns(app, q, table, row)
	args := make([]any, 0, len(cols))
	exprs := make([]string, 0, len(cols))
	for _, c := range cols {
		expr, arg := whenBind(c, row[c.name])
		exprs = append(exprs, expr)
		args = append(args, arg)
	}
	query, err := buildWhenQuery(table, when, whenSelectList(exprs, cols))
	if err != nil {
		return false, err
	}
	if bound, ok := q.(appMCPContextTx); ok && bound.private {
		if err := bound.cleanMain(); err != nil {
			return false, err
		}
		if !isReadOnlyQuery(query) {
			return false, fmt.Errorf("when: condition is not read-only")
		}
	}
	parent := context.Background()
	if bound, ok := q.(appMCPContextTx); ok {
		parent = bound.ctx
	}
	ctx, cancel := context.WithTimeout(parent, whenConditionTimeout)
	defer cancel()
	var met int64
	switch db := q.(type) {
	case *sql.DB:
		if db == nil {
			return false, fmt.Errorf("when: no database")
		}
		err = queryWhenOnConn(ctx, db, query, args, &met)
	case *sql.Tx:
		if db == nil {
			return false, fmt.Errorf("when: no database")
		}
		err = queryWhenInTx(ctx, db, query, args, &met)
	case appMCPContextTx:
		if db.tx == nil || db.ctx == nil {
			return false, fmt.Errorf("when: no context-bound transaction")
		}
		err = queryWhenInTx(ctx, db.tx, query, args, &met)
	default:
		err = fmt.Errorf("when: unsupported database handle %T", q)
	}
	if err != nil {
		return false, err
	}
	return met == 1, nil
}

// whenHolds is evaluateWhen for callers whose failure mode is "the
// condition is not met" (after-hooks, transitions, on_transition hooks).
// A failure is logged once per app, table, condition and reason.
func whenHolds(q mutationQuerier, app *App, table, when string, row map[string]any) bool {
	ok, err := evaluateWhen(q, app, table, when, row)
	if err != nil {
		logWhenFailure(app, table, when, err)
		return false
	}
	return ok
}

var (
	whenFailuresLogged sync.Map
	whenFailureCount   atomic.Int64
)

func logWhenFailure(app *App, table, when string, err error) {
	dir := ""
	if app != nil {
		dir = app.Dir
	}
	key := dir + "\x00" + table + "\x00" + when + "\x00" + err.Error()
	if whenFailureCount.Load() < 1000 {
		if _, loaded := whenFailuresLogged.LoadOrStore(key, true); loaded {
			return
		}
		whenFailureCount.Add(1)
	}
	log.Printf("WHEN [%s] condition %q could not be evaluated (%v) - failing closed", table, truncate(when, 200), err)
}

// whenColumns lists the CTE columns for an event on table: every table
// column, old_<column> for each, the session keys, then any other
// identifier-shaped row key (capped). Names are unique case-insensitively,
// as SQLite column names are.
func whenColumns(app *App, q mutationQuerier, table string, row map[string]any) []whenColumn {
	var tableCols []Column
	found := false
	if app != nil {
		for _, t := range app.Tables {
			if t.Name == table {
				tableCols, found = t.Columns, true
				break
			}
		}
	}
	if !found && whenQuerierUsable(q) {
		tableCols, _ = tableColumnsWith(q, table)
	}
	seen := map[string]bool{}
	var cols []whenColumn
	add := func(c whenColumn) {
		k := strings.ToLower(c.name)
		if seen[k] || !whenKeyRe.MatchString(c.name) {
			return
		}
		seen[k] = true
		cols = append(cols, c)
	}
	for _, c := range tableCols {
		add(whenColumn{name: c.Name, declType: c.Type})
	}
	for _, c := range tableCols {
		add(whenColumn{name: "old_" + c.Name, declType: c.Type})
	}
	for _, k := range whenSessionKeys {
		switch k {
		case "user_email", "user_role", "user_roles", submittedFieldsKey:
			add(whenColumn{name: k, declType: "TEXT"})
		default:
			add(whenColumn{name: k, loose: true})
		}
	}
	var extra []string
	for k := range row {
		if !seen[strings.ToLower(k)] && whenKeyRe.MatchString(k) {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	if len(extra) > whenExtraKeyCap {
		extra = extra[:whenExtraKeyCap]
	}
	for _, k := range extra {
		add(whenColumn{name: k, loose: true})
	}
	return cols
}

// whenQuerierUsable reports whether q is a non-nil database or transaction.
func whenQuerierUsable(q mutationQuerier) bool {
	switch db := q.(type) {
	case *sql.DB:
		return db != nil
	case *sql.Tx:
		return db != nil
	}
	return q != nil
}

func whenSelectList(exprs []string, cols []whenColumn) string {
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = exprs[i] + " AS " + quoteIdent(c.name)
	}
	return strings.Join(parts, ", ")
}

// buildWhenQuery checks the condition and wraps it around the CTE. The
// condition sits on its own lines so a trailing `-- comment` can't swallow
// the wrapper.
func buildWhenQuery(table, when, selectList string) (string, error) {
	cond, err := prepareWhenCondition(when)
	if err != nil {
		return "", err
	}
	if selectList == "" {
		return "", fmt.Errorf("no row columns")
	}
	t := quoteIdent(table)
	// The condition is an app author's text inside framework SQL: the result
	// goes to QueryRow and Prepare in the form the driver can run.
	query, ok := sqlRunnableText("WITH " + t + " AS (SELECT " + selectList + ")\nSELECT CASE WHEN (\n" + cond + "\n) THEN 1 ELSE 0 END FROM " + t)
	if !ok {
		return "", errNoSQLStatement
	}
	return query, nil
}

// prepareWhenCondition validates a condition's text and rewrites `!=`/`<>`
// to be NULL-safe.
//
// A `when:` is one SQL expression: a `{{template}}`, a `;`, a parameter
// (`?`, `:name`, `@name`, `$name`), unbalanced parentheses, an
// unterminated string/identifier/comment or load_extension is refused. Outside subqueries, `a != b` becomes
// `a IS NOT b`, so it holds when exactly one side is NULL (`status !=
// 'paid'` for a NULL status, `old_x != x` when x is first set or cleared).
// Next to an empty-string literal it stays `!=`, so a NULL counts as
// empty and "phone != (empty string)" still means "has a value". Inside a
// subquery SQL's own `!=` applies.
func prepareWhenCondition(when string) (string, error) {
	if strings.Contains(when, "{{") {
		return "", fmt.Errorf("when: is a SQL condition, not a template: name the column (status = 'paid'), not {{status}}")
	}
	if strings.TrimSpace(when) == "" {
		return "", fmt.Errorf("empty condition")
	}
	// Anywhere in the text, not only as a bare word: SQLite also calls a
	// function spelled as a quoted identifier ("load_extension"(...),
	// [load_extension](...)), and the transaction path has no authorizer.
	if strings.Contains(strings.ToLower(when), "load_extension") {
		return "", fmt.Errorf("load_extension is not allowed")
	}
	s := when
	kinds := make([]sqlByteKind, 0, len(s))
	_ = scanSQLBytes(s, func(_ byte, k sqlByteKind) error {
		kinds = append(kinds, k)
		return nil
	})
	if len(kinds) > 0 {
		if last := kinds[len(kinds)-1]; last.quoted() && !whenQuotedRegionClosed(s, kinds) {
			return "", fmt.Errorf("unterminated quote")
		}
		if kinds[len(kinds)-1] == sqlInBlockComment && !strings.HasSuffix(s, "*/") {
			return "", fmt.Errorf("unterminated comment")
		}
	}
	code := func(i int) bool { return i >= 0 && i < len(s) && kinds[i] == sqlCode }
	isSpace := func(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f' }
	// skip returns the next index at or after i that is code and not
	// whitespace, stepping over comments; len(s) if none.
	skip := func(i int) int {
		for i < len(s) && (kinds[i] == sqlInLineComment || kinds[i] == sqlInBlockComment || (kinds[i] == sqlCode && isSpace(s[i]))) {
			i++
		}
		return i
	}
	skipBack := func(i int) int {
		for i >= 0 && (kinds[i] == sqlInLineComment || kinds[i] == sqlInBlockComment || (kinds[i] == sqlCode && isSpace(s[i]))) {
			i--
		}
		return i
	}
	// emptyForward / emptyBackward report whether an empty-string literal
	// starts / ends at i.
	emptyForward := func(i int) bool {
		return i+1 < len(s) && kinds[i] == sqlInSingleQuote && s[i] == '\'' && s[i+1] == '\'' &&
			(i+2 >= len(s) || kinds[i+2] != sqlInSingleQuote)
	}
	emptyBackward := func(i int) bool {
		return i >= 1 && kinds[i] == sqlInSingleQuote && s[i] == '\'' && s[i-1] == '\'' && kinds[i-1] == sqlInSingleQuote &&
			(i-2 < 0 || kinds[i-2] != sqlInSingleQuote)
	}
	var out strings.Builder
	var frames []bool // one per open paren: true when it opens a subquery
	subqueries := 0
	for i := 0; i < len(s); i++ {
		if !code(i) {
			out.WriteByte(s[i])
			continue
		}
		c := s[i]
		switch {
		case c == ';':
			return "", fmt.Errorf("a condition is one expression; remove the ';'")
		case c == '?',
			(c == ':' || c == '@') && code(i+1) && (isLetter(s[i+1]) || s[i+1] == '_'),
			c == '$' && (i == 0 || !code(i-1) || !sqlIdentByte(s[i-1])) && code(i+1) && sqlIdentByte(s[i+1]):
			// A parameter would bind positionally among the row's values.
			return "", fmt.Errorf("a condition has no parameters; name the column instead of %q", s[i:min(i+2, len(s))])
		case c == '(':
			j := skip(i + 1)
			k := j
			for k < len(s) && code(k) && sqlIdentByte(s[k]) {
				k++
			}
			word := strings.ToUpper(s[j:k])
			sub := word == "SELECT" || word == "WITH" || word == "VALUES"
			frames = append(frames, sub)
			if sub {
				subqueries++
			}
		case c == ')':
			if len(frames) == 0 {
				return "", fmt.Errorf("unbalanced ')'")
			}
			if frames[len(frames)-1] {
				subqueries--
			}
			frames = frames[:len(frames)-1]
		case (c == '!' || c == '<') && code(i+1) && ((c == '!' && s[i+1] == '=') || (c == '<' && s[i+1] == '>')):
			if subqueries == 0 && !emptyBackward(skipBack(i-1)) && !emptyForward(skip(i+2)) {
				out.WriteString(" IS NOT ")
			} else {
				out.WriteString(s[i : i+2])
			}
			i++
			continue
		case sqlIdentByte(c) && (i == 0 || !code(i-1) || !sqlIdentByte(s[i-1])):
			k := i
			for k < len(s) && code(k) && sqlIdentByte(s[k]) {
				k++
			}
			out.WriteString(s[i:k])
			i = k - 1
			continue
		}
		out.WriteByte(c)
	}
	if len(frames) != 0 {
		return "", fmt.Errorf("unbalanced '('")
	}
	return out.String(), nil
}

// whenQuotedRegionClosed reports whether the quoted region the text ends
// in is closed by its last byte (a region whose closing delimiter is the
// final byte of the string is complete).
func whenQuotedRegionClosed(s string, kinds []sqlByteKind) bool {
	last := len(s) - 1
	k := kinds[last]
	start := last
	for start > 0 && kinds[start-1] == k {
		start--
	}
	closer := map[sqlByteKind]byte{sqlInSingleQuote: '\'', sqlInDoubleQuote: '"', sqlInBracket: ']', sqlInBacktick: '`'}[k]
	// The region (possibly several doubled-delimiter runs) is closed when
	// it has an even number of delimiter bytes for quote kinds, or ends in
	// ']' for brackets.
	if k == sqlInBracket {
		return s[last] == ']' && last > start
	}
	n := 0
	for i := start; i <= last; i++ {
		if s[i] == closer {
			n++
		}
	}
	return n%2 == 0
}

// whenBind returns a column's SQL expression and bound value. The value
// takes the storage class it would have in the table: a column's declared
// affinity applies (numeric text in an INTEGER/REAL/NUMERIC column becomes
// a number, a TEXT column's value is text), and the CAST gives the CTE
// column that affinity for comparisons, as a real column has. Keys that
// aren't table columns are numbers when they look like one, else text.
func whenBind(c whenColumn, v any) (string, any) {
	v = whenNormalizeValue(v, c.declType)
	numeric := false
	switch t := v.(type) {
	case int64, float64:
		numeric = true
	case string:
		numeric = sqliteNumericText(t)
	}
	if c.loose {
		switch {
		case numeric:
			return "CAST(? AS NUMERIC)", v
		case v == nil:
			return "?", nil
		}
		if _, ok := v.(string); ok {
			return "CAST(? AS TEXT)", v
		}
		return "?", v
	}
	switch sqliteAffinity(c.declType) {
	case "TEXT":
		return "CAST(? AS TEXT)", v
	case "INTEGER", "NUMERIC":
		if numeric || v == nil {
			return "CAST(? AS NUMERIC)", v
		}
	case "REAL":
		if numeric || v == nil {
			return "CAST(? AS REAL)", v
		}
	}
	return "?", v
}

// whenNormalizeValue converts a row value to something the driver binds:
// bools become 1/0 (as SQLite stores them), integral floats integers (the
// %v text 2.7.246 compared), and maps/slices JSON text.
func whenNormalizeValue(v any, declType string) any {
	switch t := v.(type) {
	case nil:
		return nil
	case bool:
		if t {
			return int64(1)
		}
		return int64(0)
	case int:
		return int64(t)
	case int32:
		return int64(t)
	case int64:
		return t
	case uint:
		return int64(t)
	case uint32:
		return int64(t)
	case uint64:
		if t > 1<<63-1 {
			return float64(t)
		}
		return int64(t)
	case float32:
		return whenNormalizeValue(float64(t), declType)
	case float64:
		if t == float64(int64(t)) && t >= -(1<<53) && t <= 1<<53 {
			return int64(t)
		}
		return t
	case string:
		// Boolean columns are written as 1/0 (coerceBoolString).
		if strings.Contains(strings.ToUpper(declType), "BOOL") {
			switch strings.ToLower(t) {
			case "true":
				return int64(1)
			case "false":
				return int64(0)
			}
		}
		return t
	case []byte:
		return t
	case time.Time:
		return t
	case map[string]any, []any, []map[string]any:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprint(t)
		}
		return string(b)
	}
	return fmt.Sprint(v)
}

// sqliteNumericTextRe is text SQLite converts to a number when it is
// stored in a column with numeric affinity: optional surrounding spaces
// and sign, digits with an optional fraction, optional exponent.
var sqliteNumericTextRe = regexp.MustCompile(`^\s*[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\s*$`)

func sqliteNumericText(s string) bool { return sqliteNumericTextRe.MatchString(s) }

// sqliteAffinity is SQLite's column affinity for a declared type
// (https://sqlite.org/datatype3.html#determination_of_column_affinity).
func sqliteAffinity(declType string) string {
	u := strings.ToUpper(declType)
	switch {
	case strings.Contains(u, "INT"):
		return "INTEGER"
	case strings.Contains(u, "CHAR"), strings.Contains(u, "CLOB"), strings.Contains(u, "TEXT"):
		return "TEXT"
	case strings.Contains(u, "BLOB"), strings.TrimSpace(u) == "":
		return "BLOB"
	case strings.Contains(u, "REAL"), strings.Contains(u, "FLOA"), strings.Contains(u, "DOUB"):
		return "REAL"
	}
	return "NUMERIC"
}

// queryWhenOnConn runs the condition on a connection held for this call,
// with query_only and a read-only authorizer, restoring both after.
func queryWhenOnConn(ctx context.Context, db *sql.DB, query string, args []any, met *int64) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	var wasReadOnly bool
	if err := conn.QueryRowContext(ctx, "PRAGMA query_only").Scan(&wasReadOnly); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "PRAGMA query_only=ON"); err != nil {
		return err
	}
	defer conn.Raw(func(raw any) error {
		sqlite, ok := raw.(*sqlite3.SQLiteConn)
		if !ok {
			return driver.ErrBadConn
		}
		restoreConnAuthorizer(sqlite)
		restore := "PRAGMA query_only=OFF"
		if wasReadOnly {
			restore = "PRAGMA query_only=ON"
		}
		// Discard the connection rather than hand it back to writers in a
		// state other than the one it came in.
		if _, err := sqlite.Exec(restore, nil); err != nil {
			return driver.ErrBadConn
		}
		return nil
	})
	if err := conn.Raw(func(raw any) error {
		sqlite, ok := raw.(*sqlite3.SQLiteConn)
		if !ok {
			return fmt.Errorf("when: needs a SQLite connection")
		}
		sqlite.RegisterAuthorizer(authorizeWhenQuery)
		return nil
	}); err != nil {
		return err
	}
	return conn.QueryRowContext(ctx, query, args...).Scan(met)
}

// queryWhenInTx runs the condition inside the hook's transaction, so it
// sees the transaction's own writes. The transaction's connection can't
// take an authorizer through database/sql; query_only still blocks writes,
// and prepareWhenCondition has already refused anything but a single
// expression inside the SELECT.
func queryWhenInTx(ctx context.Context, tx *sql.Tx, query string, args []any, met *int64) (retErr error) {
	var wasReadOnly bool
	if err := tx.QueryRowContext(ctx, "PRAGMA query_only").Scan(&wasReadOnly); err != nil {
		return err
	}
	if !wasReadOnly {
		if _, err := tx.Exec("PRAGMA query_only=ON"); err != nil {
			return err
		}
		defer func() {
			restoreCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer cancel()
			if _, err := tx.ExecContext(restoreCtx, "PRAGMA query_only=OFF"); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("when: could not restore query_only on transaction connection: %w", err))
			}
		}()
	}
	return tx.QueryRowContext(ctx, query, args...).Scan(met)
}

// authorizeWhenQuery admits reads, SELECTs and function calls (except
// load_extension); everything else is denied.
func authorizeWhenQuery(action int, arg1, arg2, database string) int {
	switch action {
	case sqlite3.SQLITE_READ, sqlite3.SQLITE_SELECT, whenRecursiveSelect:
		return sqlite3.SQLITE_OK
	case sqlite3.SQLITE_FUNCTION:
		if !strings.EqualFold(arg2, "load_extension") {
			return sqlite3.SQLITE_OK
		}
	case sqlite3.SQLITE_UPDATE:
		// Connecting an existing virtual table (FTS) authorizes synthetic
		// schema updates; query_only still forbids a real write.
		if arg1 == "sqlite_master" || arg1 == "sqlite_temp_master" {
			return sqlite3.SQLITE_OK
		}
	case sqlite3.SQLITE_PRAGMA:
		if strings.EqualFold(arg1, "data_version") && arg2 == "" {
			return sqlite3.SQLITE_OK
		}
	}
	return sqlite3.SQLITE_DENY
}

// checkWhenCondition prepares (without running) a condition against q's
// schema for table: the write-time check and the load-time warning.
func checkWhenCondition(q *sql.DB, app *App, table, when string) error {
	cols := whenColumns(app, q, table, nil)
	exprs := make([]string, len(cols))
	for i, c := range cols {
		exprs[i], _ = whenBind(c, nil)
	}
	query, err := buildWhenQuery(table, when, whenSelectList(exprs, cols))
	if err != nil {
		return err
	}
	stmt, err := q.Prepare(query)
	if err != nil {
		return err
	}
	return stmt.Close()
}
