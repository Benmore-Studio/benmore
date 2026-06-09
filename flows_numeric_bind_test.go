//go:build !cli

package main

// Pins the v2.7.162 fix for flow SQL params binding as TEXT. SQLite
// ranks TEXT above ANY number when neither comparison operand has
// column affinity, so a numeric guard against an expression -
// `WHERE :amt >= (SELECT SUM(...))` - was ALWAYS true ('5000' >= 10515)
// with no error and no warning. sqlBindValue converts canonical numeric
// strings to int64/float64 at bind time; non-canonical strings (leading
// zeros, exponents) keep binding as TEXT so identifier-shaped values
// still compare byte-for-byte.

import "testing"

func TestSQLBindValue(t *testing.T) {
	cases := []struct {
		in   string
		want any
	}{
		{"5000", int64(5000)},
		{"-42", int64(-42)},
		{"0", int64(0)},
		{"6.5", 6.5},
		{"-0.25", -0.25},
		// Non-canonical numerics keep their TEXT identity.
		{"01234", "01234"}, // zip code - leading zero doesn't round-trip
		{"+1", "+1"},
		{"5e3", "5e3"},
		{"1.50", "1.50"}, // trailing zero doesn't round-trip
		{"", ""},
		{"abc", "abc"},
		{"12abc", "12abc"},
		{"-", "-"},
		{"--5", "--5"},
		// int64 overflow falls back to TEXT, not float silently.
		{"99999999999999999999", "99999999999999999999"},
	}
	for _, c := range cases {
		if got := sqlBindValue(c.in); got != c.want {
			t.Errorf("sqlBindValue(%q) = %#v, want %#v", c.in, got, c.want)
		}
	}
}

// TestInterpolateCtxSafe_NumericGuardFires runs the exact failing shape
// from the field report end-to-end: a cap-reduction floor comparing a
// request param against a SUM(). Pre-fix the TEXT bind made the guard
// pass for ANY param value; now 5000 >= 10515 is correctly false.
func TestInterpolateCtxSafe_NumericGuardFires(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	mustExec(t, app.DB, `CREATE TABLE nums (v INTEGER)`)
	mustExec(t, app.DB, `INSERT INTO nums (v) VALUES (10000), (515)`) // SUM = 10515

	ctx := &FlowContext{
		App:    app,
		Data:   map[string]any{},
		Params: map[string]string{"amt": "5000"},
	}
	query, args := interpolateCtxSafe("SELECT (:amt >= (SELECT SUM(v) FROM nums)) AS ok", ctx)
	var ok int
	if err := app.DB.QueryRow(query, args...).Scan(&ok); err != nil {
		t.Fatalf("query: %v", err)
	}
	if ok != 0 {
		t.Errorf("guard 5000 >= SUM(10515) evaluated true - param still binding as TEXT")
	}

	// And the guard still passes when it genuinely should.
	ctx.Params["amt"] = "20000"
	query, args = interpolateCtxSafe("SELECT (:amt >= (SELECT SUM(v) FROM nums)) AS ok", ctx)
	if err := app.DB.QueryRow(query, args...).Scan(&ok); err != nil {
		t.Fatalf("query: %v", err)
	}
	if ok != 1 {
		t.Errorf("guard 20000 >= SUM(10515) evaluated false")
	}
}

// TestInterpolateCtxSafe_PipeResultBindsNumerically covers the {{ }}
// bind path: pipe results stringify by design, so `{{ rows | length }}`
// arrives as "2" - it must get the same numeric treatment as :params.
func TestInterpolateCtxSafe_PipeResultBindsNumerically(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	mustExec(t, app.DB, `CREATE TABLE nums (v INTEGER)`)
	mustExec(t, app.DB, `INSERT INTO nums (v) VALUES (10000), (515)`)

	ctx := &FlowContext{
		App: app,
		Data: map[string]any{
			"rows": []any{map[string]any{"id": 1}, map[string]any{"id": 2}},
		},
		Params: map[string]string{},
	}
	query, args := interpolateCtxSafe("SELECT ({{rows | length}} >= (SELECT SUM(v) FROM nums)) AS ok", ctx)
	var ok int
	if err := app.DB.QueryRow(query, args...).Scan(&ok); err != nil {
		t.Fatalf("query: %v", err)
	}
	if ok != 0 {
		t.Errorf("pipe result '2' >= SUM(10515) evaluated true - still binding as TEXT")
	}
}

// TestInterpolateCtxSafe_TextParamsStillMatchTextColumns guards the
// other direction: identifier-shaped values with leading zeros must
// keep comparing byte-for-byte against TEXT columns.
func TestInterpolateCtxSafe_TextParamsStillMatchTextColumns(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	mustExec(t, app.DB, `CREATE TABLE addrs (zip TEXT)`)
	mustExec(t, app.DB, `INSERT INTO addrs (zip) VALUES ('01234')`)

	ctx := &FlowContext{
		App:    app,
		Data:   map[string]any{},
		Params: map[string]string{"zip": "01234"},
	}
	query, args := interpolateCtxSafe("SELECT COUNT(*) FROM addrs WHERE zip = :zip", ctx)
	var n int
	if err := app.DB.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("query: %v", err)
	}
	if n != 1 {
		t.Errorf("zip '01234' equality returned %d rows, want 1 - leading-zero value coerced", n)
	}
}
