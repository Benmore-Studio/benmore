//go:build !cli

package main

// Parameterized SQL steps, row-count assertions, and trusted dynamic-SQL guards.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
)

// resolveSQLParamValue evaluates a `with.params:` value for a sql step.
// The raw expression has already had its GHA refs normalized to `{{...}}`
// shape; we run interpolateCtx to fully resolve it against the current
// flow context, then string-coerce. Complex values (slices/maps) get
// JSON-encoded so the agent can pair them with SQLite's json_each() /
// json_extract() without an explicit `| json` pipe in the YAML.
//
// The rawExpr is typically a single `{{...}}` placeholder. If it
// resolves to a boolean, use SQLite's 0/1 representation so BOOLEAN
// affinity and subsequent predicates/readback agree with a direct bound
// reference. Other primitives retain their rendered form. If it resolves
// to a slice or map, the resolved value (not the rendered string) is
// JSON-encoded.
//
// Returns (rendered, isNil). isNil is true when a single-placeholder
// expression resolved to Go `nil`; the SQL bind path uses this to
// bind SQL NULL instead of the literal string. Before this signal
// existed, nil values rendered as `"<nil>"` (Go's fmt default) and
// landed in DB columns as the literal three-character string.
func resolveSQLParamValue(rawExpr string, ctx *FlowContext) (string, bool) {
	rendered := interpolateCtx(rawExpr, ctx)
	// Fast path: pure scalar (no leftover template, value already
	// rendered to a primitive string representation). Most params hit
	// this - IDs, status filters, counts.
	trimmed := strings.TrimSpace(rawExpr)
	if !strings.HasPrefix(trimmed, "{{") || !strings.HasSuffix(trimmed, "}}") {
		return rendered, false
	}
	// Single-placeholder form: check the raw value type in ctx.Data so
	// slices/maps can be JSON-encoded.
	inner := strings.TrimSpace(trimmed[2 : len(trimmed)-2])
	// Strip any pipe chain - `{{ x | length }}` always produces a
	// string from ApplyPipe, never nil.
	key := inner
	if strings.Contains(inner, "|") {
		// Piped expressions don't go through the nil-checks below.
		return rendered, false
	}
	// The run's cached lookup table (flatDataForCtx), not a fresh
	// flattenData per param: inside a for_each that re-flattened all of
	// ctx.Data for every param of every iteration.
	flat := flatDataForCtx(ctx)
	if v, ok := flowLookup(flat, key); ok {
		if v == nil {
			return "", true
		}
		switch value := v.(type) {
		case bool:
			if value {
				return "1", false
			}
			return "0", false
		case []any, []map[string]any, map[string]any:
			if b, err := json.Marshal(v); err == nil {
				return string(b), false
			}
		}
	}
	return rendered, false
}

// flowDB returns the transaction if active, otherwise the app database.
func flowDB(ctx *FlowContext) interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
} {
	if ctx.Tx != nil {
		return ctx.Tx
	}
	return ctx.App.DB
}

func execStepSQL(ctx *FlowContext, step *FlowStep) error {
	// Resolve any explicit step-local params (`with.params:` in the
	// flow YAML) and merge them into ctx.Params for the duration of
	// this step. interpolateCtxSafe reads `:name` placeholders from
	// ctx.Params, so this is the simplest plumbing. Complex values
	// (slice/map) are JSON-encoded so they pair with SQLite's
	// json_each() / json_extract() without any extra agent ceremony.
	var restoreParams func()
	if len(step.SQLParams) > 0 {
		backup := make(map[string]string, len(step.SQLParams))
		backupNull := make(map[string]bool, len(step.SQLParams))
		for k := range step.SQLParams {
			if old, ok := ctx.Params[k]; ok {
				backup[k] = old
			}
			if ctx.NullParams != nil {
				if wasNull, ok := ctx.NullParams[k]; ok {
					backupNull[k] = wasNull
				}
			}
		}
		if ctx.NullParams == nil {
			ctx.NullParams = make(map[string]bool, len(step.SQLParams))
		}
		for k, rawExpr := range step.SQLParams {
			val, isNil := resolveSQLParamValue(rawExpr, ctx)
			ctx.Params[k] = val
			if isNil {
				ctx.NullParams[k] = true
			} else {
				delete(ctx.NullParams, k)
			}
		}
		restoreParams = func() {
			for k := range step.SQLParams {
				if old, ok := backup[k]; ok {
					ctx.Params[k] = old
				} else {
					delete(ctx.Params, k)
				}
				if wasNull, ok := backupNull[k]; ok {
					ctx.NullParams[k] = wasNull
				} else {
					delete(ctx.NullParams, k)
				}
			}
		}
		defer restoreParams()
	}

	// Use safe interpolation to prevent SQL injection from external data
	query, args := interpolateCtxSafe(step.SQL, ctx)
	db := flowDB(ctx)

	// Detect statement shape. SELECT and any mutation that carries a
	// `RETURNING …` clause both produce rows; route them through Query
	// so ctx.Data[step.Name] captures the values exactly the way
	// `${{ steps.X.outputs.<col> }}` expects. Pre-v2.7.5 every non-
	// SELECT went to db.Exec, which silently dropped RETURNING output
	// - agents wrote
	//   `INSERT … RETURNING id` followed by `${{ steps.ws.outputs.id }}`
	// expecting it to work (it matches every other SQL framework's
	// shape), found `{{ws.id}}` leaking literally into responses,
	// and then had to rewrite as INSERT + follow-up SELECT.
	//
	// Detection is regex-free on purpose: `\bRETURNING\b` test against
	// the uppercased query, after a quick prefix check so we don't pay
	// the scan cost on the common SELECT path.
	//
	// THREE row-producing shapes:
	//   1. `SELECT …` - plain query
	//   2. `WITH foo AS (…) SELECT …` - CTE. Pre-v2.7.6 the prefix
	//      check missed this (starts with WITH, not SELECT), so every
	//      CTE-shaped step landed in db.Exec and the output silently
	//      vanished. Every agent writing non-trivial business rules
	//      hit this - risk-gate calcs (`WITH ref AS …, calc AS …
	//      SELECT …`) are the canonical case. An earlier app build
	//      worked around it by rewriting CTEs as nested subqueries.
	//   3. `INSERT/UPDATE/DELETE … RETURNING …` - already handled by
	//      hasReturningClause since v2.7.5.
	//
	// db.Query is safe for any statement type in SQLite - non-row-
	// producing variants just return an empty result set, no error.
	upper := strings.TrimSpace(strings.ToUpper(query))
	startsWithRowProducer := strings.HasPrefix(upper, "SELECT") ||
		strings.HasPrefix(upper, "WITH")
	hasReturning := !startsWithRowProducer && hasReturningClause(upper)
	// Serialize the actual DB call when running inside a transaction:
	// *sql.Tx is not safe for concurrent use, so a `parallel:` block of
	// SQL steps inside a `transaction: true` flow would otherwise race.
	// The DB pool (ctx.Tx == nil path) is already concurrency-safe, so we
	// only pay the lock on the transactional path.
	if ctx.Tx != nil || ctx.mcpReadConn != nil {
		ctx.transactionMutex().Lock()
		defer ctx.transactionMutex().Unlock()
	}
	if ctx.mcpReadConn != nil {
		if !isReadOnlyQuery(query) {
			return fmt.Errorf("connector SQL must be one read-only statement")
		}
		startsWithRowProducer = true
	}
	// The prefix checks above are the historical routing, and a step without
	// expect_rows keeps it, so its outputs are what they always were. Two
	// cases read the statement off the shared lexer instead:
	//   - a step WITH expect_rows (routeAssertedFlowSQL), so the count it
	//     compares is always the statement's own;
	//   - a single `WITH ... INSERT/UPDATE/DELETE` without RETURNING. Its
	//     WITH prefix sent it through Query, which ran the write, stored an
	//     empty row list and hid the affected count - the guarded write
	//     (`INSERT INTO t SELECT ... WHERE <guard>`) written with a CTE. It
	//     runs through Exec like any other write and exposes rows_affected.
	rowProducing, shape := startsWithRowProducer || hasReturning, flowSQLShape{}
	switch {
	case step.ExpectRows != "":
		var err error
		if rowProducing, shape, query, err = routeAssertedFlowSQL(step, query, ctx.mcpReadConn != nil); err != nil {
			return err
		}
	case ctx.mcpReadConn == nil && strings.HasPrefix(upper, "WITH"):
		if s := classifyFlowSQL(query); s.kind == flowSQLWrite && s.statements == 1 {
			rowProducing, shape, query = false, s, s.text(query)
		}
	}
	if rowProducing {
		// Query runs the script's last statement and nothing may follow it: a
		// comment or a second `;` after the final statement is dropped here.
		runnable, ok := sqlRunnableText(query)
		if !ok {
			return fmt.Errorf("sql: %w", errNoSQLStatement)
		}
		query = runnable
		var key []byte
		var sqlRows *sql.Rows
		var err error
		if ctx.mcpReadConn != nil {
			key = ctx.mcpReadKey
			sqlRows, err = ctx.mcpReadConn.QueryContext(ctx.Request.Context(), query, args...)
		} else {
			key = cryptoKeyForQuerier(db)
			sqlRows, err = db.Query(query, args...)
		}
		if err != nil {
			return fmt.Errorf("sql: %w", err)
		}
		limit := 0
		if ctx.mcpReadConn != nil {
			limit = readOnlyQueryMaxRows + 1
		}
		rows, err := scanRowsLimit(sqlRows, key, limit)
		if ctx.mcpReadConn != nil && len(rows) > readOnlyQueryMaxRows {
			return fmt.Errorf("connector SQL result limit exceeded")
		}
		if err != nil {
			return fmt.Errorf("sql scan: %w", err)
		}
		recordFlowSQLWrites(ctx, query, shape.queryWriteCount(upper, rows))
		if step.Name != "" {
			// Always store as a slice. Pre-v2.3.2 we collapsed a
			// single-row result into a bare map at ctx.Data[step.Name]
			// - that was nice for `{{step.field}}` templates after a
			// single-row WHERE id = :id query, but it made
			// `outputs.rows` / `outputs.*` templates return an object
			// instead of a 1-element array when there was exactly one
			// match. Frontend code then had to handle both shapes.
			//
			// flattenData below restores the per-field shortcut for
			// the 1-row case, so `{{step.field}}` still works AND
			// `{{step.rows}}` returns a real slice.
			ctx.DataMu.Lock()
			ctx.Data[step.Name] = rows
			ctx.DataMu.Unlock()
		}
		// expect_rows on a statement that returns rows (a SELECT, or a write
		// with RETURNING, which returns one row per row it changed) compares
		// the rows returned. Checked after the output is stored, like the
		// affected count below, so an on_error handler can read it.
		if err := checkExpectRows(ctx, step, shape, int64(len(rows))); err != nil {
			return err
		}
	} else {
		// Exec skips a text that holds no statement and reports success, so a
		// step whose statement never reached it (a missing `query`, `with.sql`
		// for `with.query`, a text that is only a comment) ran nothing and the
		// flow went on. The Query path above already refuses such a text.
		if _, ok := sqlRunnableText(query); !ok {
			return fmt.Errorf("sql: %w", errNoSQLStatement)
		}
		res, err := db.Exec(query, args...)
		if err != nil {
			return fmt.Errorf("sql: %w", err)
		}
		affected, _ := res.RowsAffected()
		recordFlowSQLWrites(ctx, query, affected)
		// Expose the affected count as a step output so authors can branch on
		// it (`if: ${{ steps.x.outputs.rows_affected }}`) and so the previously
		// invisible "0 rows" case is observable. Additive: exec steps stored
		// nothing here before, and no existing key is named rows_affected.
		if step.Name != "" {
			ctx.DataMu.Lock()
			ctx.Data[step.Name] = map[string]any{"rows_affected": affected}
			ctx.DataMu.Unlock()
		}
		// expect_rows: fail the flow LOUD when a guarded write affected the
		// wrong number of rows, instead of silently falling through to a 200.
		if err := checkExpectRows(ctx, step, shape, affected); err != nil {
			return err
		}
	}
	return nil
}

// flowQueryWriteCount is the rows-changed count of a statement that ran
// through Query, for recordFlowSQLWrites: a RETURNING write returns one row
// per changed row; anything else (a script of several statements, a
// sql_dynamic WITH … INSERT without RETURNING, which writes but returns
// nothing) is unknown (-1).
func flowQueryWriteCount(upperQuery string, rows []map[string]any) int64 {
	if hasReturningClause(upperQuery) {
		return int64(len(rows))
	}
	return -1
}

// flowSQLKind is what a rendered flow SQL script does, read off the shared
// SQLite lexer (sql_scan.go) rather than guessed from its first characters.
type flowSQLKind int

const (
	// flowSQLUnclassified: the script was not tokenized (a step without
	// expect_rows on the historical routing) or has no row count that
	// expect_rows could compare (DDL, PRAGMA, EXPLAIN, a mix of statements).
	flowSQLUnclassified flowSQLKind = iota
	flowSQLRead                     // one SELECT / VALUES, with or without a WITH prefix
	flowSQLReturning                // one INSERT / UPDATE / DELETE ... RETURNING
	flowSQLWrite                    // INSERT / UPDATE / DELETE statement(s), none with RETURNING
)

// flowSQLShape is classifyFlowSQL's reading of one script.
type flowSQLShape struct {
	kind       flowSQLKind
	statements int // non-empty statements (comments are not statements)
	start, end int // byte span from the first statement's first token to the last one's last
}

// classifyFlowSQL tokenizes a rendered script and says which row count it
// has. Comments, quoting and a WITH prefix cannot hide the verb: it is the
// statement's first code token, or after a WITH clause the first DML/SELECT
// keyword outside every parenthesis. A script of several statements has a
// count only when every one is a write without RETURNING: Exec runs them all
// and reports the last one's affected rows, whereas Query runs only the last
// statement of a script.
func classifyFlowSQL(query string) flowSQLShape {
	statements := sqlTokenStatements(sqlTokenize(query))
	shape := flowSQLShape{statements: len(statements)}
	if n := len(statements); n > 0 {
		last := statements[n-1]
		shape.start, shape.end = statements[0][0].start, last[len(last)-1].end
	}
	for i, stmt := range statements {
		kind := flowStatementKind(stmt)
		switch {
		case i == 0:
			shape.kind = kind
		case shape.kind != flowSQLWrite || kind != flowSQLWrite:
			shape.kind = flowSQLUnclassified
		}
	}
	return shape
}

func flowStatementKind(toks []sqlToken) flowSQLKind {
	i := sqlStatementVerbIndex(toks)
	kw := func(j int, word string) bool {
		return j < len(toks) && toks[j].kind == sqlTokWord && strings.EqualFold(toks[j].text, word)
	}
	switch {
	case kw(i, "SELECT"), kw(i, "VALUES"):
		return flowSQLRead
	// REPLACE is also an ordinary identifier (a CTE may be named replace),
	// so it is the verb only as REPLACE INTO.
	case kw(i, "INSERT"), kw(i, "UPDATE"), kw(i, "DELETE"), kw(i, "REPLACE") && kw(i+1, "INTO"):
		if sqlStatementReturns(toks) {
			return flowSQLReturning
		}
		return flowSQLWrite
	}
	return flowSQLUnclassified
}

// uncheckable says why a script of this shape has no row count for
// expect_rows to compare; "" when it has one. Shared by the runtime, which
// refuses to run such a step, and the write gate (expectRowsViolation).
func (s flowSQLShape) uncheckable() string {
	switch {
	case s.kind != flowSQLUnclassified:
		return ""
	case s.statements == 0:
		return "the step has no SQL statement"
	case s.statements == 1:
		return "its statement does not read as a SELECT, INSERT, UPDATE or DELETE, so it has no row count to compare"
	}
	return fmt.Sprintf("it holds %d statements and they are not all INSERT/UPDATE/DELETE without RETURNING (a script's row count is its last write's; a SELECT or RETURNING statement in a script is never read)", s.statements)
}

// expectRowsUncheckableAdvice is the fix that goes with uncheckable().
const expectRowsUncheckableAdvice = "Put the statement to assert in its own step: one SELECT (rows returned), one INSERT/UPDATE/DELETE ... RETURNING (rows returned), or INSERT/UPDATE/DELETE without RETURNING (rows affected; in a step of several such statements the last one is counted)"

// queryWriteCount is the rows-changed count recordFlowSQLWrites gets for a
// statement that ran through Query: exact when the lexer classified it,
// otherwise the keyword scan's answer (flowQueryWriteCount).
func (s flowSQLShape) queryWriteCount(upperQuery string, rows []map[string]any) int64 {
	if s.kind == flowSQLReturning {
		return int64(len(rows))
	}
	return flowQueryWriteCount(upperQuery, rows)
}

// routeAssertedFlowSQL decides how the rendered script of a step WITH
// expect_rows runs: through Query, so the rows it returns are counted
// (rowProducing), or through Exec, so the rows it affected are. It returns the
// text to run.
//
// Such a step is routed by classifyFlowSQL alone. The historical routing
// (Query when the text starts with SELECT or WITH or holds a RETURNING
// keyword, else Exec) can hand it a count that is not the statement's own: a
// write the keyword scan took for a RETURNING one (the word inside a string or
// comment) returns no rows, and a SELECT or RETURNING write sent through Exec
// reports the affected count of whichever write last finished on that
// connection. A script with no row count at all is refused before it runs, so
// an authored assertion is checked or the step fails - it is never skipped.
//
// On a connector read (pinnedRead) the statement was already admitted as one
// read-only statement and must stay on the pinned connection: it is always a
// Query, and expect_rows compares the rows it returned.
func routeAssertedFlowSQL(step *FlowStep, query string, pinnedRead bool) (rowProducing bool, shape flowSQLShape, text string, err error) {
	// A value the runtime cannot parse used to surface only after the
	// statement had run.
	if _, err := evalExpectRows(step.ExpectRows, 0); err != nil {
		return false, shape, query, err
	}
	if pinnedRead {
		return true, flowSQLShape{kind: flowSQLRead, statements: 1}, query, nil
	}
	shape = classifyFlowSQL(query)
	if why := shape.uncheckable(); why != "" {
		return false, shape, query, fmt.Errorf("sql: expect_rows on step %q cannot be checked: %s. Nothing was run. %s", step.Name, why, expectRowsUncheckableAdvice)
	}
	return shape.kind != flowSQLWrite, shape, shape.text(query), nil
}

// text is the script from its first statement's first token to its last
// statement's last token: no leading or trailing comment, whitespace or empty
// statement (`;;`). The driver prepares whatever follows the final `;` as one
// more, empty, statement: Exec then reports THAT statement's result (zero
// rows affected for a write that changed rows), and Query cannot run a script
// that ends in one.
func (s flowSQLShape) text(query string) string {
	if s.statements > 0 && s.start < s.end && s.end <= len(query) {
		return query[s.start:s.end]
	}
	return query
}

// checkExpectRows compares the step's `expect_rows` with n, the count the
// routing arranged for: rows returned by a SELECT or a RETURNING write, rows
// affected by a write without RETURNING.
func checkExpectRows(ctx *FlowContext, step *FlowStep, shape flowSQLShape, n int64) error {
	if step.ExpectRows == "" {
		return nil
	}
	ok, err := evalExpectRows(step.ExpectRows, n)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	return expectRowsFailure(step, shape, n, ctx.Tx != nil)
}

// expectRowsFailure words a failed assertion so that it is true for the
// statement that ran. "The write did NOT happen" holds only for a write that
// changed nothing; a write that changed the wrong number of rows did happen,
// and stays applied unless the step runs inside the flow's transaction (inTx;
// an on_error handler never does).
func expectRowsFailure(step *FlowStep, shape flowSQLShape, n int64, inTx bool) error {
	counted := "affected"
	if shape.kind != flowSQLWrite {
		counted = "returned"
	}
	msg := fmt.Sprintf("sql: expect_rows assertion failed on step %q: %d row(s) %s, expected %s", step.Name, n, counted, step.ExpectRows)
	fate := "the change stays applied: this step runs outside a `transaction: true` transaction"
	if inTx {
		fate = "the flow's `transaction: true` rolls the change back"
	}
	switch {
	case shape.kind == flowSQLRead:
		// A query changes nothing; the counts say it all.
	case shape.statements > 1 && n == 0:
		msg += fmt.Sprintf(" (the step's last statement changed no rows; its earlier statements did run - %s)", fate)
	case shape.statements > 1:
		msg += fmt.Sprintf(" (the step's statements DID run - %s)", fate)
	case n == 0:
		msg += " (the guard/WHERE matched nothing - the write did NOT happen)"
	default:
		msg += fmt.Sprintf(" (the write DID happen - %s)", fate)
	}
	return errors.New(msg)
}

// evalExpectRows evaluates an `expect_rows` assertion (e.g. ">0", ">=1", "=1",
// "!=0", or a bare "1" meaning "=1") against the affected row count.
func evalExpectRows(expr string, n int64) (bool, error) {
	e := strings.TrimSpace(expr)
	op := "="
	for _, o := range []string{">=", "<=", "!=", "==", ">", "<", "="} {
		if strings.HasPrefix(e, o) {
			op = o
			e = strings.TrimSpace(e[len(o):])
			break
		}
	}
	want, err := strconv.ParseInt(strings.TrimSpace(e), 10, 64)
	if err != nil {
		return false, fmt.Errorf("sql: invalid expect_rows %q - use a comparison like \">0\", \">=1\", \"=1\", \"!=0\"", expr)
	}
	switch op {
	case ">":
		return n > want, nil
	case ">=":
		return n >= want, nil
	case "<":
		return n < want, nil
	case "<=":
		return n <= want, nil
	case "!=":
		return n != want, nil
	default: // "=" / "=="
		return n == want, nil
	}
}

// hasReturningClause reports whether the (already-uppercased) query
// contains a `RETURNING …` clause as a standalone keyword. We do a
// substring match guarded by simple word-boundary checks so an
// identifier or string literal that happens to contain "RETURNING"
// doesn't trip the detector. The guard is intentionally permissive:
// `RETURNING` is so uncommon outside its SQL keyword usage that a
// false positive would only land if someone named a column `returning`
// AND referenced it as a bare identifier in a non-RETURNING statement
// - vanishingly rare and the worst outcome is a Query call instead
// of an Exec call on a mutation, which still executes correctly.
func hasReturningClause(upperQuery string) bool {
	const kw = "RETURNING"
	idx := strings.Index(upperQuery, kw)
	if idx < 0 {
		return false
	}
	// Require a non-identifier char before the keyword (start of string
	// or whitespace/punctuation). Without this, an identifier ending in
	// "RETURNING" (e.g. a column literally named `is_returning`) would
	// match.
	if idx > 0 {
		prev := upperQuery[idx-1]
		if (prev >= 'A' && prev <= 'Z') || (prev >= '0' && prev <= '9') || prev == '_' {
			return false
		}
	}
	// Require a non-identifier char after the keyword.
	end := idx + len(kw)
	if end < len(upperQuery) {
		next := upperQuery[end]
		if (next >= 'A' && next <= 'Z') || (next >= '0' && next <= '9') || next == '_' {
			return false
		}
	}
	return true
}

// execStepSQLDynamic is the text-interpolation counterpart to
// execStepSQL. It uses interpolateCtx (which substitutes `{{ ... }}`
// values as raw text into the query string) instead of
// interpolateCtxSafe (which replaces them with `?` placeholders and
// binds values). This is the only path that lets an AI agent's
// generated SQL actually execute: a query string cannot be
// param-bound into itself.
//
// SECURITY: the template (not the resolved text) is logged and the WHOLE statement is
// inherently injection-shaped - `{{ q }}` becomes literal SQL bytes,
// not a bound value. Use only when the SQL is assembled by trusted
// internal callers (LLM agent flow, admin tooling). NEVER funnel
// user-typed input through this path.
func execStepSQLDynamic(ctx *FlowContext, step *FlowStep) error {
	// Same per-step param overlay as execStepSQL - but written into
	// BOTH ctx.Params (for `:name` placeholders) AND ctx.Data (for
	// `{{name}}` text substitutions, which is the dominant form in
	// sql_dynamic since the whole point is text interpolation).
	// Restored on exit so the overlay doesn't leak into siblings.
	var restoreParams func()
	if len(step.SQLParams) > 0 {
		paramBackup := make(map[string]string, len(step.SQLParams))
		dataBackup := make(map[string]any, len(step.SQLParams))
		dataHad := make(map[string]bool, len(step.SQLParams))
		ctx.DataMu.Lock()
		for k := range step.SQLParams {
			if old, ok := ctx.Params[k]; ok {
				paramBackup[k] = old
			}
			if old, ok := ctx.Data[k]; ok {
				dataBackup[k] = old
				dataHad[k] = true
			}
		}
		for k, rawExpr := range step.SQLParams {
			resolved, _ := resolveSQLParamValue(rawExpr, ctx)
			// sql_dynamic is text-substitution only - NULL has no
			// stable serialization in raw SQL bytes anyway. Resolved
			// empty string is the closest sensible value for nil here.
			ctx.Params[k] = resolved
			ctx.Data[k] = resolved
		}
		ctx.DataMu.Unlock()
		restoreParams = func() {
			ctx.DataMu.Lock()
			defer ctx.DataMu.Unlock()
			for k := range step.SQLParams {
				if old, ok := paramBackup[k]; ok {
					ctx.Params[k] = old
				} else {
					delete(ctx.Params, k)
				}
				if dataHad[k] {
					ctx.Data[k] = dataBackup[k]
				} else {
					delete(ctx.Data, k)
				}
			}
		}
		defer restoreParams()
	}

	// M-1: sql_dynamic substitutes refs as raw SQL TEXT (no param bind),
	// so a request-controlled value reaching the query is an injection
	// sink. Request-sourced refs are always refused; there is no opt-out.
	// The comment in the template "never funnel user input here" is
	// enforced, not just advisory.
	if err := flowDynamicGuardRequestRefs(step, ctx); err != nil {
		return err
	}

	query := interpolateCtx(step.SQL, ctx)
	db := flowDB(ctx)

	// Log the author's template and the resolved length - sql_dynamic is
	// high-risk, so every run is traceable, but the resolved SQL holds row
	// values (names, emails, ...) that do not belong in the process log.
	// (No digest either: a hash of a known template plus one low-entropy
	// value can be brute-forced back to the value.)
	if ctx.mcpReadConn == nil {
		log.Printf("flows: sql_dynamic step=%q template=%q resolved_len=%d", step.Name, step.SQL, len(query))
	}

	// Same prefix detection as execStepSQL - SELECT, WITH (CTE), or
	// INSERT/UPDATE/DELETE … RETURNING all produce rows we want to
	// capture into ctx.Data[step.Name]. See the longer comment in
	// execStepSQL for context.
	upper := strings.TrimSpace(strings.ToUpper(query))
	startsWithRowProducer := strings.HasPrefix(upper, "SELECT") ||
		strings.HasPrefix(upper, "WITH")
	hasReturning := !startsWithRowProducer && hasReturningClause(upper)
	if ctx.mcpReadConn != nil {
		ctx.transactionMutex().Lock()
		defer ctx.transactionMutex().Unlock()
		if !isReadOnlyQuery(query) {
			return fmt.Errorf("connector SQL must be one read-only statement")
		}
		startsWithRowProducer = true
	}
	// As in execStepSQL: a step with expect_rows is routed off the lexer so
	// the count it compares is the rendered statement's own; without it the
	// historical routing and outputs stand (rows on the Query path, nothing
	// on the Exec path).
	rowProducing, shape := startsWithRowProducer || hasReturning, flowSQLShape{}
	if step.ExpectRows != "" {
		var err error
		if rowProducing, shape, query, err = routeAssertedFlowSQL(step, query, ctx.mcpReadConn != nil); err != nil {
			return err
		}
	}
	if rowProducing {
		// As in execStepSQL: nothing may follow the statement Query runs.
		runnable, ok := sqlRunnableText(query)
		if !ok {
			return fmt.Errorf("sql_dynamic: %w", errNoSQLStatement)
		}
		query = runnable
		var key []byte
		var sqlRows *sql.Rows
		var err error
		if ctx.mcpReadConn != nil {
			key = ctx.mcpReadKey
			sqlRows, err = ctx.mcpReadConn.QueryContext(ctx.Request.Context(), query)
		} else {
			key = cryptoKeyForQuerier(db)
			sqlRows, err = db.Query(query)
		}
		if err != nil {
			return fmt.Errorf("sql_dynamic: %w", err)
		}
		limit := 0
		if ctx.mcpReadConn != nil {
			limit = readOnlyQueryMaxRows + 1
		}
		rows, err := scanRowsLimit(sqlRows, key, limit)
		if ctx.mcpReadConn != nil && len(rows) > readOnlyQueryMaxRows {
			return fmt.Errorf("connector SQL result limit exceeded")
		}
		if err != nil {
			return fmt.Errorf("sql scan: %w", err)
		}
		recordFlowSQLWrites(ctx, query, shape.queryWriteCount(upper, rows))
		if step.Name != "" {
			ctx.DataMu.Lock()
			ctx.Data[step.Name] = rows
			ctx.DataMu.Unlock()
		}
		if err := checkExpectRows(ctx, step, shape, int64(len(rows))); err != nil {
			return err
		}
	} else {
		// As in execStepSQL: a template that rendered no statement (an empty
		// generated query) is an error, not a step that did nothing.
		if _, ok := sqlRunnableText(query); !ok {
			return fmt.Errorf("sql_dynamic: %w", errNoSQLStatement)
		}
		res, err := db.Exec(query)
		if err != nil {
			return fmt.Errorf("sql_dynamic: %w", err)
		}
		affected, _ := res.RowsAffected()
		recordFlowSQLWrites(ctx, query, affected)
		if err := checkExpectRows(ctx, step, shape, affected); err != nil {
			return err
		}
	}
	return nil
}

// flowDynamicGuardRequestRefs enforces M-1: a `run: sql_dynamic` step
// interpolates references as RAW SQL TEXT, so any request-sourced value
// reaching the query string is a SQL-injection sink. Reject the step at
// run time when its query template references a request-tainted key
// (path/query/form/JSON-body param).
//
// Invariant: request-controlled data MUST NOT be funnelled into a
// sql_dynamic query body. There is deliberately no per-step opt-out: an
// earlier error message advertised `trusted: true`, but no parser ever
// set it, and an escape hatch that bypasses the only injection guard on
// raw-text SQL is exactly the wrong default. Request values belong in a
// `run: sql` step, where `:name` / `${{ }}` bind as ? placeholders; a
// request-chosen identifier (sort column, direction) is selected from
// fixed literals with `if:` branches or `CASE :sort WHEN 'name' THEN
// name END` inside that parameterized query.
func flowDynamicGuardRequestRefs(step *FlowStep, ctx *FlowContext) error {
	if step == nil || ctx == nil {
		return nil
	}
	// Taint also arrives through `run: set` outputs, for_each loop
	// variables, parsed request bodies and enqueued job payloads (see
	// flows_taint.go), and through every `||` operand of an expression,
	// not just its leading identifier.
	if key := ctx.taintedRef(step.SQL); key != "" {
		return fmt.Errorf("sql_dynamic: step %q references request-sourced value %q as raw SQL text (injection risk); move it to a `run: sql` step where `:%s` binds as a ? placeholder, and choose any request-selected identifier (sort column/direction) from fixed literals with `if:` branches or `CASE :%s WHEN 'name' THEN name END`. A value computed from request input by an earlier sql, compute, api, set or for_each step is still request-sourced: bind it with `:name` in a parameterized `run: sql` step instead of a `{{ref}}` in sql_dynamic text", step.Name, key, key, key)
	}
	// Also guard any `with.params:` overlay: its values are written into
	// ctx.Data/ctx.Params and substituted as text, so an overlay named after
	// a request key or computed from one is the same sink.
	for name, expr := range step.SQLParams {
		key := ctx.taintedRef(expr)
		if key == "" && ctx.isTainted(name) {
			key = name
		}
		if key != "" {
			return fmt.Errorf("sql_dynamic: step %q binds request-sourced value %q via with.params into raw SQL text (injection risk); bind it in a `run: sql` step with `:%s` instead", step.Name, key, key)
		}
	}
	return nil
}

// flowSQLReferencesKey reports whether a sql_dynamic template references
// `key` either as a `:key` placeholder (substituted as text by
// interpolateCtx) or inside a `{{ ... }}` expression (dotted, indexed,
// piped and `||`-fallback forms). Match boundaries are checked so `:user`
// doesn't spuriously match `:user_id`.
func flowSQLReferencesKey(sql, key string) bool {
	return flowTemplateRefsKey(sql, key)
}

// flowIsIdentChar reports whether b can appear inside a `:param` name
// (used to enforce a word boundary when matching `:key`).
func flowIsIdentChar(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}
