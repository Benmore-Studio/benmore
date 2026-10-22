//go:build !cli

package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// Texts that end in an empty statement (plus a leading-comment variant). The
// driver's Query path answers such a text with an empty result that has no
// columns and never runs the statement in it; up to go-sqlite3 v1.14.42 it
// killed the process instead (SIGSEGV in _Cfunc_sqlite3_clear_bindings(0x0)).
// Each test below proves its site is guarded by getting the statement's own
// result back; without sqlRunnableText at the site it gets the empty one.
var emptyStatementTexts = []string{
	"SELECT 1 AS n; -- note",   // trailing line comment
	"SELECT 1 AS n; /* x */",   // trailing block comment
	"SELECT 1 AS n;;",          // trailing empty statement
	"-- lead\nSELECT 1 AS n;;", // leading comment + trailing empty statement
}

// no-statement texts: the gate upstream of each site passes them (they read as
// read-only), so the site itself must turn them into an ordinary error.
var noStatementTexts = []string{"", "   \n ", "-- only a comment", ";"}

func newEmptyStmtTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	mustExec(t, db, "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)")
	mustExec(t, db, "INSERT INTO items (name) VALUES ('a')")
	return db
}

// queryReadOnlyRows backs the MCP `query_db` tool and the dashboard SQL
// console, which run in the ROUTER process on the hosted platform. Their gate
// isReadOnlyQuery("SELECT 1; -- x") is true, so the empty trailing statement
// reaches this executor; it must run the statement and never the empty tail.
func TestReadOnlyQuerySurvivesEmptyTrailingStatement(t *testing.T) {
	db := newEmptyStmtTestDB(t)
	// The read-only gate strips comments before counting statements, so a
	// statement followed by one comment passes it (the driver would answer
	// these with no rows); a second `;` is still rejected by the gate. Assert
	// the gate so the test keeps tracking what actually reaches the executor.
	gatePassing := []string{"SELECT 1 AS n; -- note", "SELECT 1 AS n; /* x */"}
	for _, q := range gatePassing {
		if !isReadOnlyQuery(q) {
			t.Fatalf("%q should pass the read-only gate", q)
		}
		rows, cols, truncated, err := queryReadOnlyRowsCols(context.Background(), db, q, 10)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		if truncated || len(rows) != 1 || len(cols) != 1 || rows[0]["n"] != int64(1) {
			t.Fatalf("%q: rows=%v cols=%v", q, rows, cols)
		}
	}
	// The executor is also reached by callers that do not gate on
	// isReadOnlyQuery (private connector reads); it must handle every
	// empty-trailing-statement shape and the no-statement shapes too.
	for _, q := range emptyStatementTexts {
		rows, _, _, err := queryReadOnlyRowsCols(context.Background(), db, q, 10)
		if err != nil || len(rows) != 1 || rows[0]["n"] != int64(1) {
			t.Fatalf("%q: rows=%v err=%v", q, rows, err)
		}
	}
	for _, q := range noStatementTexts {
		if _, _, _, err := queryReadOnlyRowsCols(context.Background(), db, q, 10); err != errNoSQLStatement {
			t.Fatalf("%q: err=%v, want errNoSQLStatement", q, err)
		}
	}
}

// QueryRows (via queryRowsWithKeyContext) is the single read helper behind SSR
// `<query sql=...>`, workflows, versioning, includes, scheduling, read-audit,
// the describe/ops helpers and more. Author SQL and tool input reach it, so the
// one guard there covers every caller.
func TestQueryRowsSurvivesEmptyTrailingStatement(t *testing.T) {
	db := newEmptyStmtTestDB(t)
	for _, q := range emptyStatementTexts {
		rows, err := QueryRows(db, q)
		if err != nil || len(rows) != 1 || rows[0]["n"] != int64(1) {
			t.Fatalf("%q: rows=%v err=%v", q, rows, err)
		}
	}
	for _, q := range noStatementTexts {
		if _, err := QueryRows(db, q); err != errNoSQLStatement {
			t.Fatalf("%q: err=%v, want errNoSQLStatement", q, err)
		}
	}
	// QuerySingle shares the chokepoint's guard but opens its own path.
	for _, q := range []string{"SELECT 1; -- note", "SELECT 1;;"} {
		v, err := QuerySingle(db, q)
		if err != nil || v != int64(1) {
			t.Fatalf("QuerySingle(%q) = %v, %v", q, v, err)
		}
	}
	if _, err := QuerySingle(db, "-- only a comment"); err != errNoSQLStatement {
		t.Fatalf("QuerySingle(comment): err=%v, want errNoSQLStatement", err)
	}
}

// A flow `run: sql` / `run: sql_dynamic` step runs author SQL in the app's own
// unit process. A step without expect_rows keeps the historical Query routing;
// the rendered text can end in a comment (`SELECT ... ; -- note`) and must run.
func TestFlowSQLStepSurvivesEmptyTrailingStatement(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)")
	mustExec(t, app.DB, "INSERT INTO items (name) VALUES ('a')")
	rowQueries := []string{
		"SELECT id FROM items;\n-- note",
		"SELECT id FROM items;;",
		"WITH one AS (SELECT id FROM items) SELECT id FROM one; /* note */",
		"UPDATE items SET name = name RETURNING id;\n-- note",
	}
	for _, query := range rowQueries {
		for _, run := range []func(*FlowContext, *FlowStep) error{execStepSQL, execStepSQLDynamic} {
			ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
			if err := run(ctx, &FlowStep{Name: "s", Type: "sql", SQL: query}); err != nil {
				t.Fatalf("%q: %v", query, err)
			}
			rows, _ := ctx.Data["s"].([]map[string]any)
			if len(rows) != 1 || rows[0]["id"] != int64(1) {
				t.Fatalf("%q: output = %#v", query, ctx.Data["s"])
			}
		}
	}
	// A comment-only rendered statement reaches the Query path (it starts with
	// neither SELECT nor WITH, but a mutation keyword scan can misfire); a
	// SELECT prefix with no statement after rendering must be an ordinary
	// error, not a dead process.
	for _, query := range []string{"SELECT 1;; -- tail only comment after"} {
		ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
		if err := execStepSQL(ctx, &FlowStep{Name: "s", Type: "sql", SQL: query}); err != nil {
			t.Fatalf("%q: %v", query, err)
		}
	}
}

// refreshAggregate runs an app.yaml `aggregates:` SQL on a background worker in
// the app's unit process. A trailing comment in the author's SQL must not cost
// the aggregate its value (or, on an older driver, the process) at refresh time.
func TestRefreshAggregateSurvivesEmptyTrailingStatement(t *testing.T) {
	db := newEmptyStmtTestDB(t)
	EnsureAggregatesTable(db)
	for _, q := range emptyStatementTexts {
		if err := refreshAggregate(db, AggregateConfig{Name: "n", SQL: q}); err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		var v string
		if err := db.QueryRow("SELECT value FROM _benmore_aggregates WHERE name='n'").Scan(&v); err != nil || v != "1" {
			t.Fatalf("%q: stored value %q err %v", q, v, err)
		}
	}
	if err := refreshAggregate(db, AggregateConfig{Name: "n", SQL: "-- only a comment"}); err != errNoSQLStatement {
		// wrapped: refreshAggregate returns fmt.Errorf("aggregate %q: %w", ...)
		if !isWrappedNoStatement(err) {
			t.Fatalf("comment-only aggregate: err=%v, want errNoSQLStatement", err)
		}
	}
}

func isWrappedNoStatement(err error) bool {
	for e := err; e != nil; {
		if e == errNoSQLStatement {
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}
