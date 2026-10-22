//go:build !cli

package main

// expect_rows on every statement shape and through every flow executor.
//
// Before this change the assertion was read only on the db.Exec branch of
// execStepSQL: a SELECT, a write with RETURNING, a `WITH ... <DML>` and any
// `run: sql_dynamic` statement were accepted at write time and never
// compared. Each test below runs the authored YAML through the real loader
// and executor.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func expectRowsApp(t *testing.T) *App {
	t.Helper()
	app, cleanup := newTestApp(t)
	t.Cleanup(cleanup)
	mustExec(t, app.DB, `CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, qty INTEGER NOT NULL DEFAULT 0)`)
	mustExec(t, app.DB, `CREATE TABLE log (id INTEGER PRIMARY KEY, note TEXT)`)
	return app
}

// expectRowsFlow wraps step YAML (already indented six spaces) in a POST
// flow; onRequest adds on.request keys such as `    transaction: true\n`.
func expectRowsFlow(onRequest, steps string) string {
	return "on:\n  request:\n    method: POST\n    path: /api/probe\n" + onRequest +
		"jobs:\n  probe:\n    steps:\n" + steps +
		"      - run: respond\n        with: { status: 200, body: { ok: true } }\n"
}

func parseExpectRowsFlow(t *testing.T, app *App, source string) Flow {
	t.Helper()
	flows, err := parseGHAFlowFile(filepath.Join(app.Dir, "flows", "probe.yaml"), []byte(source))
	if err != nil || len(flows) != 1 {
		t.Fatalf("parse flow: %v (%d flows)\n%s", err, len(flows), source)
	}
	return flows[0]
}

// runExpectRowsFlow runs one flow file over HTTP and returns the response and
// the flow's own error (what the server log line carries).
func runExpectRowsFlow(t *testing.T, app *App, source string) (*httptest.ResponseRecorder, error) {
	t.Helper()
	flow := parseExpectRowsFlow(t, app, source)
	req := httptest.NewRequest(flow.Trigger.Method, flow.Trigger.Path, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	err := executeFlowHTTP(app, &flow, rr, req)
	return rr, err
}

func expectRowsInt(t *testing.T, app *App, query string) int {
	t.Helper()
	var n int
	if err := app.DB.QueryRow(query).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// wantExpectRowsFailure checks a failed assertion: the flow errors with the
// step's name and the true count, and the caller gets a 500.
func wantExpectRowsFailure(t *testing.T, rr *httptest.ResponseRecorder, err error, step, counted string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expect_rows on step %q was not enforced: flow succeeded with %d %s", step, rr.Code, rr.Body.String())
	}
	want := fmt.Sprintf("sql: expect_rows assertion failed on step %q: %s", step, counted)
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q", err, want)
	}
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body %s)", rr.Code, rr.Body.String())
	}
}

// A SELECT's expect_rows compares the rows it returned.
func TestExpectRowsOnSelect(t *testing.T) {
	for _, tc := range []struct {
		rows int
		expr string
		pass bool
	}{
		{0, "=1", false}, {1, "=1", true}, {2, "=1", false},
		{0, ">0", false}, {1, ">0", true}, {2, ">0", true},
		{0, "0", true}, {1, "0", false}, {2, "0", false},
	} {
		t.Run(fmt.Sprintf("%d rows %s", tc.rows, tc.expr), func(t *testing.T) {
			app := expectRowsApp(t)
			for i := 0; i < tc.rows; i++ {
				mustExec(t, app.DB, `INSERT INTO items (name) VALUES ('k')`)
			}
			rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", `      - id: found
        run: sql
        with:
          query: "SELECT id FROM items WHERE name = 'k'"
        expect_rows: "`+tc.expr+`"
`))
			if tc.pass {
				if err != nil || rr.Code != http.StatusOK {
					t.Fatalf("assertion %s holds for %d rows but the flow failed: %d %v", tc.expr, tc.rows, rr.Code, err)
				}
				return
			}
			wantExpectRowsFailure(t, rr, err, "found", fmt.Sprintf("%d row(s) returned, expected %s", tc.rows, tc.expr))
			// A query changed nothing: the text must not talk about a write.
			if strings.Contains(err.Error(), "write") || strings.Contains(err.Error(), "affected") {
				t.Fatalf("a SELECT's failure text talks about a write: %q", err)
			}
		})
	}
}

// A CTE query is a SELECT too.
func TestExpectRowsOnWithSelect(t *testing.T) {
	app := expectRowsApp(t)
	rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", `      - id: found
        run: sql
        with:
          query: "WITH hits AS (SELECT id FROM items WHERE qty > 100) SELECT id FROM hits"
        expect_rows: ">0"
`))
	wantExpectRowsFailure(t, rr, err, "found", "0 row(s) returned, expected >0")
}

// A write with RETURNING returns one row per row it changed; expect_rows
// compares those.
func TestExpectRowsOnUpdateReturning(t *testing.T) {
	step := func(id int) string {
		return fmt.Sprintf(`      - id: take
        run: sql
        with:
          query: "UPDATE items SET qty = qty - 1 WHERE id = %d AND qty > 0 RETURNING id, qty"
        expect_rows: "=1"
      - id: seen
        run: sql
        with:
          query: "INSERT INTO log (note) VALUES ('after')"
`, id)
	}
	t.Run("one row", func(t *testing.T) {
		app := expectRowsApp(t)
		mustExec(t, app.DB, `INSERT INTO items (id, name, qty) VALUES (1, 'a', 5)`)
		if rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", step(1))); err != nil || rr.Code != http.StatusOK {
			t.Fatalf("matching write failed: %d %v", rr.Code, err)
		}
		if got := expectRowsInt(t, app, `SELECT qty FROM items WHERE id = 1`); got != 4 {
			t.Fatalf("qty = %d, want 4", got)
		}
	})
	t.Run("no row", func(t *testing.T) {
		app := expectRowsApp(t)
		mustExec(t, app.DB, `INSERT INTO items (id, name, qty) VALUES (1, 'a', 5)`)
		rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", step(99)))
		wantExpectRowsFailure(t, rr, err, "take", "0 row(s) returned, expected =1 (the guard/WHERE matched nothing - the write did NOT happen)")
		// The flow stopped at the failed guard.
		if got := expectRowsInt(t, app, `SELECT COUNT(*) FROM log`); got != 0 {
			t.Fatalf("the step after the failed guard ran (%d log rows)", got)
		}
	})
}

// The classic guarded write, written with RETURNING: when the guard is false
// nothing is inserted and no row comes back.
func TestExpectRowsOnGuardedInsertReturning(t *testing.T) {
	app := expectRowsApp(t)
	rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", `      - id: cap
        run: sql
        with:
          query: "INSERT INTO items (name, qty) SELECT 'capped', 1 WHERE (SELECT COUNT(*) FROM items) > 5 RETURNING id"
        expect_rows: ">0"
`))
	wantExpectRowsFailure(t, rr, err, "cap", "0 row(s) returned, expected >0 (the guard/WHERE matched nothing - the write did NOT happen)")
	if got := expectRowsInt(t, app, `SELECT COUNT(*) FROM items`); got != 0 {
		t.Fatalf("guard was false but %d row(s) were inserted", got)
	}
}

// `WITH ... INSERT` without RETURNING is a write that returns nothing. It used
// to be sent through Query on its WITH prefix: the write ran, the step's
// output was an empty row list, rows_affected did not exist and expect_rows
// was skipped.
func TestExpectRowsOnWithInsert(t *testing.T) {
	step := func(guard, expect string) string {
		s := `      - id: ins
        run: sql
        with:
          query: "WITH src AS (SELECT 'from-cte' AS name WHERE ` + guard + `) INSERT INTO items (name) SELECT name FROM src"
`
		if expect != "" {
			s += "        expect_rows: \"" + expect + "\"\n"
		}
		return s
	}
	t.Run("guard false fails", func(t *testing.T) {
		app := expectRowsApp(t)
		rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", step("1 = 0", ">0")))
		wantExpectRowsFailure(t, rr, err, "ins", "0 row(s) affected, expected >0 (the guard/WHERE matched nothing - the write did NOT happen)")
	})
	t.Run("guard true passes", func(t *testing.T) {
		app := expectRowsApp(t)
		// "=1" also proves the count is the write's own: a Query-routed
		// write returns no rows, so comparing rows returned would say 0.
		rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", step("1 = 1", "=1")))
		if err != nil || rr.Code != http.StatusOK {
			t.Fatalf("inserting write failed: %d %v %s", rr.Code, err, rr.Body.String())
		}
		if got := expectRowsInt(t, app, `SELECT COUNT(*) FROM items WHERE name = 'from-cte'`); got != 1 {
			t.Fatalf("inserted %d rows, want 1", got)
		}
	})
	// A flow that asserts "nothing was written" was passing vacuously.
	t.Run("guard true fails an assertion of zero", func(t *testing.T) {
		app := expectRowsApp(t)
		rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", step("1 = 1", "=0")))
		wantExpectRowsFailure(t, rr, err, "ins", "1 row(s) affected, expected =0 (the write DID happen")
	})
	// Without expect_rows the only change is the output: {rows_affected: n}
	// where there was an empty row list.
	for _, tc := range []struct {
		guard string
		want  int64
	}{{"1 = 1", 1}, {"1 = 0", 0}} {
		t.Run("output without expect_rows, guard "+tc.guard, func(t *testing.T) {
			app := expectRowsApp(t)
			ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
			err := execStepSQL(ctx, &FlowStep{Name: "ins", Type: "sql",
				SQL: "WITH src AS (SELECT 'from-cte' AS name WHERE " + tc.guard + ") INSERT INTO items (name) SELECT name FROM src"})
			if err != nil {
				t.Fatal(err)
			}
			out, _ := ctx.Data["ins"].(map[string]any)
			if out == nil || out["rows_affected"] != tc.want || len(out) != 1 {
				t.Fatalf("output = %#v, want {rows_affected: %d}", ctx.Data["ins"], tc.want)
			}
			if got := expectRowsInt(t, app, `SELECT COUNT(*) FROM items`); int64(got) != tc.want {
				t.Fatalf("inserted %d rows, want %d", got, tc.want)
			}
		})
	}
	// UPDATE and DELETE behind a CTE are the same shape.
	t.Run("with update and delete", func(t *testing.T) {
		app := expectRowsApp(t)
		mustExec(t, app.DB, `INSERT INTO items (id, name, qty) VALUES (1, 'a', 1), (2, 'b', 2)`)
		for _, tc := range []struct {
			sql  string
			want int64
		}{
			{"WITH low AS (SELECT id FROM items WHERE qty < 2) UPDATE items SET qty = 9 WHERE id IN (SELECT id FROM low)", 1},
			{"WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 2) DELETE FROM items WHERE id IN (SELECT i FROM n)", 2},
		} {
			ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
			if err := execStepSQL(ctx, &FlowStep{Name: "w", Type: "sql", SQL: tc.sql, ExpectRows: fmt.Sprintf("=%d", tc.want)}); err != nil {
				t.Fatalf("%s: %v", tc.sql, err)
			}
			if out, _ := ctx.Data["w"].(map[string]any); out == nil || out["rows_affected"] != tc.want {
				t.Fatalf("%s: output = %#v, want rows_affected %d", tc.sql, ctx.Data["w"], tc.want)
			}
		}
	})
}

// A failed assertion fails the flow like any step error: a transactional flow
// rolls back what earlier steps wrote, a non-transactional one keeps it.
func TestExpectRowsFailureRollsBackOnlyInATransaction(t *testing.T) {
	steps := `      - id: first
        run: sql
        with:
          query: "INSERT INTO log (note) VALUES ('first')"
      - id: must_exist
        run: sql
        with:
          query: "SELECT id FROM items WHERE name = 'absent'"
        expect_rows: ">0"
`
	for _, tc := range []struct {
		name      string
		onRequest string
		kept      int
	}{
		{"transaction", "    transaction: true\n", 0},
		{"no transaction", "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := expectRowsApp(t)
			rr, err := runExpectRowsFlow(t, app, expectRowsFlow(tc.onRequest, steps))
			wantExpectRowsFailure(t, rr, err, "must_exist", "0 row(s) returned, expected >0")
			if got := expectRowsInt(t, app, `SELECT COUNT(*) FROM log`); got != tc.kept {
				t.Fatalf("earlier write: %d row(s) kept, want %d", got, tc.kept)
			}
		})
	}
}

// A write that changed rows, but not the asserted number, DID happen. The
// failure says so and says whether the flow's transaction undoes it.
func TestExpectRowsFailureTextIsTrueForAWrongCount(t *testing.T) {
	steps := func(returning string) string {
		return `      - id: bump
        run: sql
        with:
          query: "UPDATE items SET qty = qty + 1 WHERE name = 'dup'` + returning + `"
        expect_rows: "=1"
`
	}
	for _, tc := range []struct {
		name, onRequest, returning, counted, fate string
		qty                                       int
	}{
		{"exec, no transaction", "", "", "2 row(s) affected, expected =1", "the change stays applied: this step runs outside a `transaction: true` transaction", 2},
		{"exec, transaction", "    transaction: true\n", "", "2 row(s) affected, expected =1", "the flow's `transaction: true` rolls the change back", 0},
		{"returning, no transaction", "", " RETURNING id", "2 row(s) returned, expected =1", "the change stays applied: this step runs outside a `transaction: true` transaction", 2},
		{"returning, transaction", "    transaction: true\n", " RETURNING id", "2 row(s) returned, expected =1", "the flow's `transaction: true` rolls the change back", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := expectRowsApp(t)
			mustExec(t, app.DB, `INSERT INTO items (name, qty) VALUES ('dup', 0), ('dup', 0)`)
			rr, err := runExpectRowsFlow(t, app, expectRowsFlow(tc.onRequest, steps(tc.returning)))
			wantExpectRowsFailure(t, rr, err, "bump", tc.counted+" (the write DID happen - "+tc.fate+")")
			if strings.Contains(err.Error(), "did NOT happen") {
				t.Fatalf("a write that changed 2 rows is reported as not having happened: %q", err)
			}
			if got := expectRowsInt(t, app, `SELECT COALESCE(SUM(qty), 0) FROM items`); got != tc.qty {
				t.Fatalf("rows changed = %d, want %d (%s)", got, tc.qty, tc.fate)
			}
		})
	}
}

// The usage the canned text used to get backwards: a no-op UPDATE that matches
// only in the broken state, asserted with "=0".
func TestExpectRowsZeroAssertionOnABrokenState(t *testing.T) {
	app := expectRowsApp(t)
	mustExec(t, app.DB, `INSERT INTO items (id, name, qty) VALUES (1, 'broken', -1)`)
	rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", `      - id: assert_no_negative_stock
        run: sql
        with:
          query: "UPDATE items SET id = id WHERE qty < 0"
        expect_rows: "=0"
`))
	wantExpectRowsFailure(t, rr, err, "assert_no_negative_stock", "1 row(s) affected, expected =0 (the write DID happen")
}

// expect_rows inside a for_each body is checked on every iteration.
func TestExpectRowsInsideForEach(t *testing.T) {
	app := expectRowsApp(t)
	mustExec(t, app.DB, `INSERT INTO items (id, name, qty) VALUES (1, 'a', 1), (2, 'b', 0), (3, 'c', 1)`)
	rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", `      - id: all
        run: sql
        with:
          query: "SELECT id FROM items ORDER BY id"
      - for_each: ${{ steps.all.outputs.rows }}
        as: item
        steps:
          - id: take
            run: sql
            with:
              query: "UPDATE items SET qty = qty - 1 WHERE id = :id AND qty > 0 RETURNING id"
              params: { id: "${{ item.id }}" }
            expect_rows: "=1"
`))
	wantExpectRowsFailure(t, rr, err, "take", "0 row(s) returned, expected =1")
	// Item 1 was taken, item 2 failed the guard, item 3 was never reached.
	if got := expectRowsInt(t, app, `SELECT COUNT(*) FROM items WHERE qty = 0`); got != 2 {
		t.Fatalf("loop did not stop at the failed guard: %d items at 0", got)
	}
	if got := expectRowsInt(t, app, `SELECT qty FROM items WHERE id = 3`); got != 1 {
		t.Fatalf("item 3 was changed after the failed guard (qty %d)", got)
	}
}

// Every way a flow reaches a `run: sql` step evaluates its expect_rows: an
// `if:` gate, an `if`/`else` block, a parallel block, an enqueued flow
// (executeFlowJob), a cron `flow:` target (runCronJob) and a data-event flow.
// (for_each and on_error have their own tests.)
func TestExpectRowsOnEveryExecutionPath(t *testing.T) {
	const guard = `run: sql
%[1]swith:
%[1]s  query: "SELECT id FROM items WHERE name = 'absent'"
%[1]sexpect_rows: ">0"
`
	at := func(indent string) string { return fmt.Sprintf(guard, indent) }
	const sw = "      - id: sw\n        query: \"SELECT 1 AS yes, 0 AS no\"\n"
	for _, tc := range []struct{ name, steps string }{
		{"if gate", "      - id: g\n        if: ${{ steps.sw.outputs.yes }}\n        " + at("        ")},
		{"if block", "      - if: ${{ steps.sw.outputs.yes }}\n        steps:\n          - id: g\n            " + at("            ")},
		{"else block", "      - if: ${{ steps.sw.outputs.no }}\n        steps:\n          - run: sql\n            with: { query: \"SELECT 1\" }\n        else:\n          - id: g\n            " + at("            ")},
		{"parallel", "      - run: parallel\n        steps:\n          - id: g\n            " + at("            ")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := expectRowsApp(t)
			source := expectRowsFlow("", sw+tc.steps+"      - run: sql\n        with: { query: \"INSERT INTO log (note) VALUES ('reached')\" }\n")
			flow := parseExpectRowsFlow(t, app, source)
			req := httptest.NewRequest(http.MethodPost, "/api/probe", strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			ctx := &FlowContext{App: app, Request: req, Writer: httptest.NewRecorder(), Data: map[string]any{}, Params: map[string]string{}, Writes: newFlowWriteLog()}
			executeSteps(ctx, flow.Steps)
			if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), `expect_rows assertion failed on step "g": 0 row(s) returned, expected >0`) {
				t.Fatalf("assertion not enforced on this path: %v", ctx.Error)
			}
			if got := expectRowsInt(t, app, `SELECT COUNT(*) FROM log`); got != 0 {
				t.Fatalf("flow continued past the failed guard (%d log rows)", got)
			}
		})
	}

	steps := "      - id: first\n        run: sql\n        with: { query: \"INSERT INTO log (note) VALUES ('first')\" }\n" +
		"      - id: g\n        " + at("        ")
	for name, run := range map[string]func(*App) error{
		"enqueued flow":    func(app *App) error { return executeFlowJob(app, "nightly", map[string]any{}) },
		"cron flow target": func(app *App) error { return runCronJob(app, CronJob{ID: "tick", Flow: "nightly"}, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			app := expectRowsApp(t)
			flow := parseExpectRowsFlow(t, app, expectRowsFlow("    transaction: true\n", steps))
			flow.Name = "nightly"
			app.Flows = []Flow{flow}
			err := run(app)
			if err == nil || !strings.Contains(err.Error(), `expect_rows assertion failed on step "g": 0 row(s) returned`) {
				t.Fatalf("flow did not enforce the assertion: %v", err)
			}
			if got := expectRowsInt(t, app, `SELECT COUNT(*) FROM log`); got != 0 {
				t.Fatalf("the flow's transaction kept %d row(s) after a failed assertion", got)
			}
		})
	}
	t.Run("data-event flow", func(t *testing.T) {
		app := expectRowsApp(t)
		flow := parseExpectRowsFlow(t, app, expectRowsFlow("    transaction: true\n", steps))
		var failure error
		runFlowEventWith(app, flow, map[string]any{"id": 1}, func(ctx *FlowContext) { failure = ctx.Error })
		if failure == nil || !strings.Contains(failure.Error(), `expect_rows assertion failed on step "g": 0 row(s) returned`) {
			t.Fatalf("event flow did not enforce the assertion: %v", failure)
		}
		if got := expectRowsInt(t, app, `SELECT COUNT(*) FROM log`); got != 0 {
			t.Fatalf("event flow's transaction kept %d row(s) after a failed assertion", got)
		}
	})
}

// An on_error handler's own guard stops the handler.
func TestExpectRowsStopsAnOnErrorHandler(t *testing.T) {
	app := expectRowsApp(t)
	_, err := runExpectRowsFlow(t, app, expectRowsFlow("", `      - id: boom
        run: sql
        with: { query: "SELECT * FROM no_such_table" }
        on_error:
          - id: g
            run: sql
            with:
              query: "SELECT id FROM items WHERE name = 'absent'"
            expect_rows: ">0"
          - run: sql
            with: { query: "INSERT INTO log (note) VALUES ('handler continued')" }
`))
	if err == nil {
		t.Fatal("flow with a failing step succeeded")
	}
	if got := expectRowsInt(t, app, `SELECT COUNT(*) FROM log`); got != 0 {
		t.Fatalf("on_error handler ran past its failed guard (%d log rows)", got)
	}
}

// `run: sql_dynamic` never looked at expect_rows, on either branch.
func TestExpectRowsOnSQLDynamic(t *testing.T) {
	app := expectRowsApp(t)
	mustExec(t, app.DB, `INSERT INTO items (id, name, qty) VALUES (1, 'a', 1)`)
	for _, tc := range []struct {
		name, sql, expect, counted string
	}{
		{"select", "SELECT id FROM items WHERE qty > 5", ">0", "0 row(s) returned, expected >0"},
		{"write", "UPDATE items SET qty = 2 WHERE id = 99", "=1", "0 row(s) affected, expected =1 (the guard/WHERE matched nothing - the write did NOT happen)"},
		{"returning", "UPDATE items SET qty = 2 WHERE id = 99 RETURNING id", "=1", "0 row(s) returned, expected =1"},
		{"with write", "WITH s AS (SELECT 1 AS id WHERE 1 = 0) DELETE FROM items WHERE id IN (SELECT id FROM s)", ">0", "0 row(s) affected, expected >0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", "      - id: dyn\n        run: sql_dynamic\n        with:\n          query: \""+tc.sql+"\"\n        expect_rows: \""+tc.expect+"\"\n"))
			wantExpectRowsFailure(t, rr, err, "dyn", tc.counted)
		})
	}
	// A matching statement still passes, and a step without expect_rows keeps
	// its outputs: rows on the Query path, nothing on the Exec path.
	rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", "      - id: dyn\n        run: sql_dynamic\n        with:\n          query: \"UPDATE items SET qty = 3 WHERE id = 1\"\n        expect_rows: \"=1\"\n"))
	if err != nil || rr.Code != http.StatusOK {
		t.Fatalf("matching sql_dynamic write failed: %d %v", rr.Code, err)
	}
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	if err := execStepSQLDynamic(ctx, &FlowStep{Name: "w", Type: "sql_dynamic", SQL: "UPDATE items SET qty = 4 WHERE id = 1"}); err != nil {
		t.Fatal(err)
	}
	if _, stored := ctx.Data["w"]; stored {
		t.Fatalf("sql_dynamic write without expect_rows gained an output: %#v", ctx.Data["w"])
	}
	if err := execStepSQLDynamic(ctx, &FlowStep{Name: "r", Type: "sql_dynamic", SQL: "SELECT qty FROM items WHERE id = 1"}); err != nil {
		t.Fatal(err)
	}
	if rows, _ := ctx.Data["r"].([]map[string]any); len(rows) != 1 || rows[0]["qty"] != int64(4) {
		t.Fatalf("sql_dynamic select output = %#v", ctx.Data["r"])
	}
}

// Steps without expect_rows are untouched: a SELECT and a RETURNING write
// store their rows, a plain write stores rows_affected, and a statement the
// historical prefix routing sends to Exec (a leading comment) still goes
// there.
func TestSQLStepOutputsWithoutExpectRowsAreUnchanged(t *testing.T) {
	app := expectRowsApp(t)
	mustExec(t, app.DB, `INSERT INTO items (id, name, qty) VALUES (1, 'a', 5), (2, 'b', 6)`)
	run := func(name, sql string) any {
		t.Helper()
		ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
		if err := execStepSQL(ctx, &FlowStep{Name: name, Type: "sql", SQL: sql}); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return ctx.Data[name]
	}
	if rows, _ := run("s", "SELECT id, qty FROM items ORDER BY id").([]map[string]any); len(rows) != 2 || rows[0]["id"] != int64(1) || rows[1]["qty"] != int64(6) {
		t.Fatalf("SELECT output changed: %#v", rows)
	}
	if rows, ok := run("e", "SELECT id FROM items WHERE id > 99").([]map[string]any); !ok || rows == nil || len(rows) != 0 {
		t.Fatalf("empty SELECT output changed: %#v", rows)
	}
	if rows, _ := run("c", "WITH big AS (SELECT id FROM items WHERE qty > 5) SELECT id FROM big").([]map[string]any); len(rows) != 1 || rows[0]["id"] != int64(2) {
		t.Fatalf("WITH ... SELECT output changed: %#v", rows)
	}
	if rows, _ := run("r", "UPDATE items SET qty = qty + 1 WHERE id = 1 RETURNING id, qty").([]map[string]any); len(rows) != 1 || rows[0]["qty"] != int64(6) {
		t.Fatalf("RETURNING output changed: %#v", rows)
	}
	if rows, _ := run("cr", "WITH one AS (SELECT 2 AS id) UPDATE items SET qty = qty + 1 WHERE id IN (SELECT id FROM one) RETURNING qty").([]map[string]any); len(rows) != 1 || rows[0]["qty"] != int64(7) {
		t.Fatalf("WITH ... RETURNING output changed: %#v", rows)
	}
	if out, _ := run("w", "UPDATE items SET qty = 0 WHERE id IN (1, 2)").(map[string]any); len(out) != 1 || out["rows_affected"] != int64(2) {
		t.Fatalf("write output changed: %#v", out)
	}
	if out, isMap := run("lc", "-- how many\nSELECT COUNT(*) AS n FROM items").(map[string]any); !isMap || len(out) != 1 {
		t.Fatalf("a comment-led SELECT without expect_rows left the historical Exec routing: %#v", out)
	}
}

// With expect_rows the statement is classified by the lexer, so the count is
// its own even where the historical prefix routing would misread it.
func TestExpectRowsCountsTheStatementItself(t *testing.T) {
	seed := func(t *testing.T) *App {
		app := expectRowsApp(t)
		mustExec(t, app.DB, `CREATE TABLE flags (id INTEGER PRIMARY KEY, is_returning INTEGER NOT NULL DEFAULT 0, note TEXT)`)
		mustExec(t, app.DB, `INSERT INTO flags (id) VALUES (1), (2), (3)`)
		// Leave a 3-row change as the connection's last finished write: a
		// SELECT sent through Exec reports THAT as its affected count.
		mustExec(t, app.DB, `UPDATE flags SET note = 'seed'`)
		app.DB.SetMaxOpenConns(1)
		return app
	}
	step := func(sql, expect string) *FlowStep {
		return &FlowStep{Name: "s", Type: "sql", SQL: sql, ExpectRows: expect}
	}
	run := func(app *App, s *FlowStep) (any, error) {
		ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
		err := execStepSQL(ctx, s)
		return ctx.Data["s"], err
	}
	t.Run("comment-led select", func(t *testing.T) {
		app := seed(t)
		out, err := run(app, step("-- none of these\nSELECT id FROM flags WHERE id > 99", "=3"))
		if err == nil || !strings.Contains(err.Error(), "0 row(s) returned, expected =3") {
			t.Fatalf("a SELECT that returned nothing passed =3 on a stale count: %v", err)
		}
		if rows, ok := out.([]map[string]any); !ok || len(rows) != 0 {
			t.Fatalf("asserted SELECT did not store its rows: %#v", out)
		}
		if _, err := run(app, step("/* all */ SELECT id FROM flags", "=3")); err != nil {
			t.Fatalf("a SELECT that returned 3 rows failed =3: %v", err)
		}
	})
	t.Run("values", func(t *testing.T) {
		if _, err := run(seed(t), step("VALUES (1), (2)", "=2")); err != nil {
			t.Fatalf("VALUES returned 2 rows but failed =2: %v", err)
		}
	})
	t.Run("the word returning in a string", func(t *testing.T) {
		app := seed(t)
		out, err := run(app, step("UPDATE flags SET note = 'returning customer' WHERE id = 1", "=1"))
		if err != nil {
			t.Fatalf("a write that changed one row failed =1 because its text holds the word RETURNING: %v", err)
		}
		if m, _ := out.(map[string]any); m == nil || m["rows_affected"] != int64(1) {
			t.Fatalf("output = %#v, want rows_affected 1", out)
		}
	})
	t.Run("a column named like the keyword before the real clause", func(t *testing.T) {
		app := seed(t)
		out, err := run(app, step("UPDATE flags SET is_returning = 1 WHERE id = 1 RETURNING id", "=1"))
		if err != nil {
			t.Fatalf("a RETURNING write that changed one row failed =1: %v", err)
		}
		if rows, _ := out.([]map[string]any); len(rows) != 1 || rows[0]["id"] != int64(1) {
			t.Fatalf("RETURNING rows were not read: %#v", out)
		}
	})
	t.Run("a comment after the final semicolon", func(t *testing.T) {
		app := seed(t)
		if _, err := run(app, step("UPDATE flags SET note = 'x' WHERE id = 1;\n-- one row", "=1")); err != nil {
			t.Fatalf("a write that changed one row failed =1 because a comment follows it: %v", err)
		}
		for _, sql := range []string{"SELECT id FROM flags;\n-- all three", "SELECT id FROM flags;;", "; SELECT id FROM flags; /* all three */"} {
			if _, err := run(app, step(sql, "=3")); err != nil {
				t.Fatalf("%q: a SELECT of 3 rows failed =3: %v", sql, err)
			}
		}
	})
	t.Run("a bind parameter named returning", func(t *testing.T) {
		app := seed(t)
		ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
		s := step("UPDATE flags SET note = :returning WHERE id = 1", "=1")
		s.SQLParams = map[string]string{"returning": "yes"}
		if err := execStepSQL(ctx, s); err != nil {
			t.Fatalf("write with a :returning parameter: %v", err)
		}
		if m, _ := ctx.Data["s"].(map[string]any); m == nil || m["rows_affected"] != int64(1) {
			t.Fatalf("output = %#v, want rows_affected 1", ctx.Data["s"])
		}
	})
	t.Run("several writes assert the last one", func(t *testing.T) {
		app := seed(t)
		if _, err := run(app, step("UPDATE flags SET note = 'a'; UPDATE flags SET note = 'b' WHERE id = 1;", "=1")); err != nil {
			t.Fatalf("script of writes: %v", err)
		}
		_, err := run(app, step("UPDATE flags SET note = 'c'; UPDATE flags SET note = 'd' WHERE id = 99", "=1"))
		if err == nil || !strings.Contains(err.Error(), "0 row(s) affected, expected =1 (the step's last statement changed no rows; its earlier statements did run") {
			t.Fatalf("script whose last write matched nothing: %v", err)
		}
		if got := expectRowsInt(t, app, `SELECT COUNT(*) FROM flags WHERE note = 'c'`); got != 3 {
			t.Fatalf("earlier statement of the script did not run (%d rows)", got)
		}
	})
}

// A statement with no row count is refused before it runs: the assertion is
// checked or the step fails, never skipped.
func TestExpectRowsRefusesAStatementItCannotCount(t *testing.T) {
	for _, tc := range []struct{ name, sql, why string }{
		{"ddl", "CREATE TABLE made (id INTEGER)", "its statement does not read as a SELECT, INSERT, UPDATE or DELETE"},
		{"pragma", "PRAGMA table_info(items)", "its statement does not read as a SELECT, INSERT, UPDATE or DELETE"},
		{"write then select", "INSERT INTO log (note) VALUES ('x'); SELECT 1", "it holds 2 statements"},
		{"write then returning", "INSERT INTO log (note) VALUES ('x'); UPDATE items SET qty = 1 RETURNING id", "it holds 2 statements"},
		{"empty", "-- nothing here", "the step has no SQL statement"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := expectRowsApp(t)
			mustExec(t, app.DB, `INSERT INTO items (id, name, qty) VALUES (1, 'a', 0)`)
			ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
			err := execStepSQL(ctx, &FlowStep{Name: "s", Type: "sql", SQL: tc.sql, ExpectRows: ">0"})
			if err == nil || !strings.Contains(err.Error(), `sql: expect_rows on step "s" cannot be checked: `+tc.why) || !strings.Contains(err.Error(), "Nothing was run.") {
				t.Fatalf("error = %v", err)
			}
			if expectRowsInt(t, app, `SELECT COUNT(*) FROM log`) != 0 || expectRowsInt(t, app, `SELECT qty FROM items WHERE id = 1`) != 0 ||
				expectRowsInt(t, app, `SELECT COUNT(*) FROM sqlite_master WHERE name = 'made'`) != 0 {
				t.Fatal("the refused step ran part of its SQL")
			}
			if _, stored := ctx.Data["s"]; stored {
				t.Fatalf("refused step stored an output: %#v", ctx.Data["s"])
			}
		})
	}
	// An unparsable value is refused before the write too (it used to
	// surface only after the statement had run).
	app := expectRowsApp(t)
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	err := execStepSQL(ctx, &FlowStep{Name: "s", Type: "sql", SQL: "INSERT INTO log (note) VALUES ('x')", ExpectRows: "at least one"})
	if err == nil || !strings.Contains(err.Error(), "invalid expect_rows") {
		t.Fatalf("error = %v", err)
	}
	if got := expectRowsInt(t, app, `SELECT COUNT(*) FROM log`); got != 0 {
		t.Fatalf("statement ran under an unparsable assertion (%d rows)", got)
	}
}
