//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// evaluateCondition246 is the 2.7.246 hook/workflow `when:` evaluator,
// kept verbatim as the reference for the compatibility table.
func evaluateCondition246(condition string, row map[string]any) bool {
	field, op, expected, ok := splitConditionOperator(strings.TrimSpace(condition))
	if !ok || !conditionFieldName(field) {
		return false
	}
	return compareLiteralCondition(conditionRowValue(row, field), op, strings.Trim(expected, `"'`))
}

// newWhenTestApp has an orders table with the column types a Prisma schema
// emits, loaded into app.Tables the way the loader does.
func newWhenTestApp(t *testing.T) *App {
	t.Helper()
	app, cleanup := newTestApp(t)
	t.Cleanup(cleanup)
	mustExec(t, app.DB, `CREATE TABLE orders (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER,
		stage TEXT,
		note TEXT,
		zip TEXT,
		amount INTEGER,
		price REAL,
		active BOOLEAN,
		hold_until DATETIME,
		assignee_id INTEGER,
		tracking_number TEXT
	)`)
	mustExec(t, app.DB, `CREATE TABLE exceptions (id INTEGER PRIMARY KEY, booking_id INTEGER)`)
	cols, err := GetTableColumns(app.DB, "orders")
	if err != nil {
		t.Fatal(err)
	}
	app.Tables = []Table{{Name: "orders", Columns: cols}}
	return app
}

func whenMust(t *testing.T, app *App, cond string, row map[string]any) bool {
	t.Helper()
	got, err := evaluateWhen(app.DB, app, "orders", cond, row)
	if err != nil {
		t.Fatalf("when %q: %v", cond, err)
	}
	return got
}

// `field = 'x'`, `field != 'x'`, `field = 1`, `field > 5` and the other
// single comparisons give the 2.7.246 result for real values, whether the
// row came from a form (strings) or the database (typed).
func TestWhenSingleComparisonsMatch246OnRealValues(t *testing.T) {
	app := newWhenTestApp(t)
	conds := []string{
		"stage = 'won'", "stage == 'won'", "stage != 'lost'", "stage != 'won'", `stage = "won"`,
		"note = 'a=b'", "note != 'a=b'", "zip = '01234'", "zip != '1234'",
		"amount = 1", "amount = 250", "amount != 250", "amount = '250'",
		"amount > 5", "amount > 99", "amount >= 100", "amount >= 250", "amount <= 100", "amount < 1000", "amount < 5",
		"price = 2.5", "price > 2", "price <= 2.5", "price < 1",
	}
	rows := []map[string]any{
		{"stage": "won", "note": "a=b", "zip": "01234", "amount": int64(250), "price": 2.5},
		{"stage": "lost", "note": "x", "zip": "1234", "amount": "250", "price": "2.5"},
		{"stage": "won", "note": "a=b", "zip": "01234", "amount": "10", "price": float64(3)},
		{"stage": "won", "note": "", "zip": "99", "amount": int64(1), "price": "0.5"},
		{"stage": "lost", "note": "a", "zip": "0", "amount": "5", "price": int64(2)},
	}
	for _, cond := range conds {
		for i, row := range rows {
			if got, want := whenMust(t, app, cond, row), evaluateCondition246(cond, row); got != want {
				t.Errorf("%q on row %d (%v): got %v, 2.7.246 gave %v", cond, i, row, got, want)
			}
		}
	}
}

// NULL and missing values: 2.7.246 compared a missing or NULL field as the
// empty string.
// SQL NULL comparisons are false, except that != is NULL-safe (IS NOT)
// unless one side is the empty string, where NULL counts as empty.
func TestWhenNullSemantics(t *testing.T) {
	app := newWhenTestApp(t)
	null := map[string]any{"stage": nil} // amount, price absent: bound NULL too
	cases := []struct {
		cond      string
		now, then bool // result for a NULL field now, and in 2.7.246
	}{
		{"stage = 'won'", false, false},
		{"stage != 'won'", true, true},
		{"stage != ''", false, false},
		{"'' != stage", false, false},
		{"stage <> 'won'", true, true},
		{"stage = ''", false, true},
		{"coalesce(stage, '') = ''", true, false},
		{"stage IS NULL", true, false},
		{"stage IS NOT NULL", false, false},
		{"amount > 5", false, false},
		{"amount < 5", false, true},
		{"amount <= 5", false, true},
		{"amount >= 5", false, false},
		{"amount = 0", false, false},
		{"old_stage != stage", false, true},
	}
	for _, c := range cases {
		if got := whenMust(t, app, c.cond, null); got != c.now {
			t.Errorf("%q with NULL: got %v, want %v", c.cond, got, c.now)
		}
		if got := evaluateCondition246(c.cond, null); got != c.then {
			t.Errorf("%q with NULL in 2.7.246: got %v, documented %v", c.cond, got, c.then)
		}
	}
	// NULL-safe != between columns: a value set, cleared or changed counts
	// as a change; NULL to NULL does not.
	for _, c := range []struct {
		old, cur any
		want     bool
	}{
		{nil, int64(5), true}, {int64(5), nil, true}, {int64(5), int64(6), true},
		{int64(5), int64(5), false}, {nil, nil, false}, {"5", int64(5), false},
	} {
		row := map[string]any{"old_assignee_id": c.old, "assignee_id": c.cur}
		if got := whenMust(t, app, "old_assignee_id != assignee_id", row); got != c.want {
			t.Errorf("old %v -> %v: changed = %v, want %v", c.old, c.cur, got, c.want)
		}
	}
	// Inside a subquery SQL's own != applies.
	mustExec(t, app.DB, `INSERT INTO exceptions (id, booking_id) VALUES (1, NULL)`)
	if whenMust(t, app, "EXISTS (SELECT 1 FROM exceptions x WHERE x.booking_id != 7)", map[string]any{}) {
		t.Error("a subquery's != matched a NULL column")
	}
}

// The production shapes that 2.7.246 evaluated false (or compared as
// text) now evaluate as SQL.
func TestWhenProductionSQLShapes(t *testing.T) {
	app := newWhenTestApp(t)
	mustExec(t, app.DB, `INSERT INTO exceptions (id, booking_id) VALUES (1, 42)`)
	past := time.Now().UTC().Add(-time.Hour).Format("2006-01-02 15:04:05")
	future := time.Now().UTC().Add(time.Hour).Format("2006-01-02 15:04:05")
	cases := []struct {
		cond string
		row  map[string]any
		want bool
	}{
		{"stage IN ('approved','denied')", map[string]any{"stage": "denied"}, true},
		{"stage IN ('approved','denied')", map[string]any{"stage": "pending"}, false},
		{"assignee_id IS NOT NULL", map[string]any{"assignee_id": "7"}, true},
		{"assignee_id IS NOT NULL", map[string]any{}, false},
		{"tracking_number IS NOT NULL", map[string]any{"tracking_number": "1Z999"}, true},
		{"tracking_number IS NOT NULL", map[string]any{"tracking_number": nil}, false},
		{"hold_until <= datetime('now') AND NOT EXISTS (SELECT 1 FROM exceptions x WHERE x.booking_id = orders.id)", map[string]any{"id": int64(7), "hold_until": past}, true},
		{"hold_until <= datetime('now') AND NOT EXISTS (SELECT 1 FROM exceptions x WHERE x.booking_id = orders.id)", map[string]any{"id": int64(42), "hold_until": past}, false},
		{"hold_until <= datetime('now') AND NOT EXISTS (SELECT 1 FROM exceptions x WHERE x.booking_id = orders.id)", map[string]any{"id": int64(7), "hold_until": future}, false},
		{"assignee_id IS NOT NULL AND (old_assignee_id IS NULL OR old_assignee_id != assignee_id)", map[string]any{"assignee_id": int64(3)}, true},
		{"assignee_id IS NOT NULL AND (old_assignee_id IS NULL OR old_assignee_id != assignee_id)", map[string]any{"assignee_id": int64(3), "old_assignee_id": int64(3)}, false},
		{"assignee_id IS NOT NULL AND (old_assignee_id IS NULL OR old_assignee_id != assignee_id)", map[string]any{"assignee_id": int64(3), "old_assignee_id": int64(2)}, true},
		{"stage = 'paid' AND old_stage != 'paid'", map[string]any{"stage": "paid", "old_stage": "open"}, true},
		{"stage = 'paid' AND old_stage != 'paid'", map[string]any{"stage": "paid", "old_stage": "paid"}, false},
		{"active", map[string]any{"active": true}, true},
		{"active = 1", map[string]any{"active": true}, true},
		{"active = 1", map[string]any{"active": "false"}, false},
		{"user_role = 'admin' OR user_id = orders.user_id", map[string]any{"user_id": int64(9), "user_role": "user"}, true},
		{"amount > 5 -- over the minimum", map[string]any{"amount": "10"}, true},
		{"note LIKE '%urgent%'", map[string]any{"note": "very urgent"}, true},
		{"json_extract(note, '$.a') = 1", map[string]any{"note": `{"a":1}`}, true},
		{"(SELECT count(*) FROM main.orders) = 0", map[string]any{}, true},
	}
	for _, c := range cases {
		if got := whenMust(t, app, c.cond, c.row); got != c.want {
			t.Errorf("%q on %v = %v, want %v", c.cond, c.row, got, c.want)
		}
	}
}

// Values are bound, never SQL: a row value that looks like SQL is data, and
// keys that aren't identifiers are left out.
func TestWhenValuesAreBound(t *testing.T) {
	app := newWhenTestApp(t)
	for _, v := range []string{"x' OR '1'='1", "x'); DELETE FROM orders; --", `x" OR 1=1 --`} {
		if whenMust(t, app, "stage = 'won'", map[string]any{"stage": v}) {
			t.Errorf("value %q satisfied stage = 'won'", v)
		}
	}
	row := map[string]any{"stage": "won", `x" AS y) SELECT 1 --`: 1, "a b": 2, "": 3}
	if !whenMust(t, app, "stage = 'won'", row) {
		t.Error("odd row keys broke the evaluation")
	}
	// Many submitted keys don't break it either.
	big := map[string]any{"stage": "won"}
	for i := 0; i < 5000; i++ {
		big[fmt.Sprintf("k%d", i)] = i
	}
	if !whenMust(t, app, "stage = 'won'", big) {
		t.Error("a row with many keys broke the evaluation")
	}
}

// A condition runs read-only, and the connection (or transaction) it ran
// on is left writable.
func TestWhenIsReadOnly(t *testing.T) {
	app := newWhenTestApp(t)
	app.DB.SetMaxOpenConns(1)
	for _, cond := range []string{
		"1); DELETE FROM orders; SELECT (1",
		"stage = 'won'; DELETE FROM orders",
		"load_extension('x') IS NULL",
		"1) THEN 1 END FROM orders; PRAGMA query_only=OFF; --",
		"{{stage}} = 'won'",
		"stage = 'won",
		"(stage = 'won'",
		"stage = 'won')",
		"/* open",
		"stage = ?",
		"?1 = 'won'",
		"stage = :stage",
		"stage = @stage",
		"stage = $stage",
	} {
		if _, err := evaluateWhen(app.DB, app, "orders", cond, map[string]any{"stage": "won"}); err == nil {
			t.Errorf("%q was accepted", cond)
		}
	}
	whenMust(t, app, "stage = 'won'", map[string]any{"stage": "won"})
	if _, err := app.DB.Exec(`INSERT INTO orders (stage) VALUES ('after')`); err != nil {
		t.Fatalf("the pooled connection stayed read-only: %v", err)
	}

	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO orders (id, stage) VALUES (100, 'in-tx')`); err != nil {
		t.Fatal(err)
	}
	// The transaction's own write is visible to the condition.
	met, err := evaluateWhen(tx, app, "orders", "EXISTS (SELECT 1 FROM main.orders WHERE id = 100)", map[string]any{})
	if err != nil || !met {
		t.Fatalf("condition in the transaction: met=%v err=%v", met, err)
	}
	if _, err := tx.Exec(`INSERT INTO orders (id, stage) VALUES (101, 'after-when')`); err != nil {
		t.Fatalf("the transaction stayed read-only: %v", err)
	}
}

// A runaway condition is stopped by the timeout and fails closed.
func TestWhenTimeout(t *testing.T) {
	app := newWhenTestApp(t)
	prev := whenConditionTimeout
	whenConditionTimeout = 100 * time.Millisecond
	defer func() { whenConditionTimeout = prev }()
	start := time.Now()
	_, err := evaluateWhen(app.DB, app, "orders",
		"(WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT count(*) FROM c) > 0", map[string]any{})
	if err == nil {
		t.Fatal("a runaway condition returned a result")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("the timeout did not stop the query (%s)", time.Since(start))
	}
	if _, err := app.DB.Exec(`INSERT INTO orders (stage) VALUES ('after')`); err != nil {
		t.Fatalf("database unusable after the timeout: %v", err)
	}
}

// Before-hooks: the condition sees the row, a condition that can't be
// evaluated refuses the write, and inside a transaction it runs on it.
func TestBeforeHookWhenIsSQL(t *testing.T) {
	app := newWhenTestApp(t)
	gate := Hook{SQL: "SELECT 'held orders need a note' AS error WHERE {{note}} = ''", When: "stage = 'held' AND old_stage IS NOT 'held'"}
	app.Hooks = &HookConfig{BeforeUpdate: map[string][]Hook{"orders": {gate}}}
	if err := FireBeforeHooks(app, "update", "orders", map[string]any{"stage": "held", "note": ""}); err == nil {
		t.Fatal("the gate did not apply when its condition held")
	}
	if err := FireBeforeHooks(app, "update", "orders", map[string]any{"stage": "open", "note": ""}); err != nil {
		t.Fatalf("the gate applied when its condition did not hold: %v", err)
	}
	// Can't be evaluated: the write is refused, not let through.
	for _, when := range []string{"{{stage}} = 'held'", "no_such_column = 1"} {
		app.Hooks.BeforeUpdate["orders"][0].When = when
		if err := FireBeforeHooks(app, "update", "orders", map[string]any{"stage": "open", "note": "x"}); err == nil {
			t.Errorf("when %q: an unevaluable gate let the write through", when)
		}
	}
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	mustExecTx := func(q string) {
		if _, err := tx.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	mustExecTx(`INSERT INTO exceptions (id, booking_id) VALUES (5, 5)`)
	app.Hooks.BeforeUpdate["orders"][0] = Hook{SQL: "SELECT 'excepted' AS error", When: "EXISTS (SELECT 1 FROM exceptions x WHERE x.booking_id = orders.id)"}
	if err := fireBeforeHooksWith(tx, app, "update", "orders", map[string]any{"id": int64(5)}); err == nil || err.Error() != "excepted" {
		t.Fatalf("the condition did not see the transaction's write: %v", err)
	}
}

// After-hooks and on_transition hooks fire only when the condition holds;
// one that can't be evaluated doesn't fire.
func TestAfterHookWhenIsSQL(t *testing.T) {
	app := newWhenTestApp(t)
	EnsureJobsTable(app.DB)
	app.Hooks = &HookConfig{OnUpdate: map[string][]Hook{"orders": {
		{SQL: "UPDATE orders SET note = 'fired' WHERE id = 1", When: "stage = 'paid' AND old_stage != 'paid'"},
		{SQL: "UPDATE orders SET note = 'template' WHERE id = 1", When: "{{stage}} = 'paid'"},
	}}}
	count := func() int {
		var n int
		app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_jobs WHERE job_type = 'hook'`).Scan(&n)
		return n
	}
	FireHooks(app, "update", "orders", map[string]any{"id": int64(1), "stage": "paid", "old_stage": "paid"})
	if n := count(); n != 0 {
		t.Fatalf("%d hooks enqueued for an unchanged stage", n)
	}
	FireHooks(app, "update", "orders", map[string]any{"id": int64(1), "stage": "paid", "old_stage": nil})
	if n := count(); n != 1 {
		t.Fatalf("%d hooks enqueued, want 1 (the template condition must not fire)", n)
	}
}

// A workflow transition's `when:` is SQL over the stored row.
func TestWorkflowTransitionWhenIsSQL(t *testing.T) {
	app, wf, cleanup := newWorkflowTenantApp(t)
	defer cleanup()
	mustExec(t, app.DB, "ALTER TABLE orders ADD COLUMN tracking_number TEXT")
	cols, _ := GetTableColumns(app.DB, "orders")
	for i := range app.Tables {
		if app.Tables[i].Name == "orders" {
			app.Tables[i].Columns = cols
		}
	}
	wf.Transitions["pending"]["approved"] = Transition{When: "tracking_number IS NOT NULL"}
	uid := workflowTestUser(t, app, "wf@example.com")
	addMember(t, app, "A", uid, "member")
	mustExec(t, app.DB, "INSERT INTO orders (id, org_id, user_id, status) VALUES (1, 'A', "+fmt.Sprint(uid)+", 'pending')")
	sid := CreateSession(app.DB, uid, "wf@example.com", "A", time.Hour)
	if w := transitionAs(app, wf, sid, "1", "approved"); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("transition without a tracking number: %d %s", w.Code, w.Body.String())
	}
	mustExec(t, app.DB, "UPDATE orders SET tracking_number = '1Z' WHERE id = 1")
	if w := transitionAs(app, wf, sid, "1", "approved"); w.Code != http.StatusOK {
		t.Fatalf("transition with a tracking number: %d %s", w.Code, w.Body.String())
	}
}

// != and <> become NULL-safe outside subqueries and away from the empty
// string; quoted text and comments are left alone.
func TestPrepareWhenConditionRewritesNotEqual(t *testing.T) {
	for in, want := range map[string]string{
		"a != b":              "a IS NOT b",
		"a<>b":                "a IS NOT b",
		"a != ''":             "a != ''",
		"'' <> a":             "'' <> a",
		"a != ''''":           "a IS NOT ''''",
		"(a != b)":            "(a IS NOT b)",
		"'x != y' = s":        "'x != y' = s",
		`"x!=y" = 1`:          `"x!=y" = 1`,
		"a = 1 -- a!=b":       "a = 1 -- a!=b",
		"coalesce(a != b, 0)": "coalesce(a IS NOT b, 0)",
		"a != 1 AND EXISTS (SELECT 1 FROM t WHERE t.c != a) AND b != 2": "a IS NOT 1 AND EXISTS (SELECT 1 FROM t WHERE t.c != a) AND b IS NOT 2",
	} {
		got, err := prepareWhenCondition(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if strings.Join(strings.Fields(got), " ") != want {
			t.Errorf("%q became %q, want %q", in, got, want)
		}
	}
}

// The transaction path has no authorizer, so the text check is what keeps
// load_extension out; SQLite also calls a function named by a quoted
// identifier.
func TestWhenRefusesQuotedLoadExtension(t *testing.T) {
	for _, cond := range []string{
		`"load_extension"('x') IS NULL`,
		`[load_extension]('x') IS NULL`,
		"`load_extension`('x') IS NULL",
		`"LOAD_EXTENSION"('x') IS NULL`,
		`load_extension ('x') IS NULL`,
	} {
		if _, err := prepareWhenCondition(cond); err == nil {
			t.Errorf("%s passed the condition check", cond)
		}
	}
}
