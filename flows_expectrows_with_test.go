//go:build !cli

package main

// `expect_rows` written under `with:`. Only the step-root key was read, so a
// guard written next to `params` was accepted and never compared.

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// `expect_rows` under `with:` (next to `params`) is the step's assertion. It
// used to be accepted and never read, even on a plain UPDATE.
func TestExpectRowsUnderWith(t *testing.T) {
	update := func(id int, expect string) string {
		return fmt.Sprintf(`      - id: apply
        run: sql
        with:
          query: "UPDATE items SET qty = :qty WHERE id = :id AND qty = 5"
          params: { id: "%d", qty: "6" }
          expect_rows: %s
`, id, expect)
	}
	t.Run("plain update, no row", func(t *testing.T) {
		app := expectRowsApp(t)
		mustExec(t, app.DB, `INSERT INTO items (id, name, qty) VALUES (1, 'a', 5)`)
		rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", update(99, `"=1"`)))
		wantExpectRowsFailure(t, rr, err, "apply", "0 row(s) affected, expected =1 (the guard/WHERE matched nothing - the write did NOT happen)")
	})
	t.Run("plain update, one row", func(t *testing.T) {
		app := expectRowsApp(t)
		mustExec(t, app.DB, `INSERT INTO items (id, name, qty) VALUES (1, 'a', 5)`)
		if rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", update(1, `"=1"`))); err != nil || rr.Code != http.StatusOK {
			t.Fatalf("matching write failed: %d %v", rr.Code, err)
		}
		if got := expectRowsInt(t, app, `SELECT qty FROM items WHERE id = 1`); got != 6 {
			t.Fatalf("qty = %d, want 6", got)
		}
	})
	// A bare YAML integer means the same in both positions.
	for _, position := range []string{"step root", "with"} {
		t.Run("bare integer at the "+position, func(t *testing.T) {
			app := expectRowsApp(t)
			mustExec(t, app.DB, `INSERT INTO items (id, name, qty) VALUES (1, 'a', 5)`)
			step := update(99, "1")
			if position == "step root" {
				step = "      - id: apply\n        run: sql\n        with:\n          query: \"UPDATE items SET qty = 6 WHERE id = 99\"\n        expect_rows: 1\n"
			}
			rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", step))
			wantExpectRowsFailure(t, rr, err, "apply", "0 row(s) affected, expected 1")
		})
	}
	t.Run("returning", func(t *testing.T) {
		app := expectRowsApp(t)
		rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", `      - id: apply
        run: sql
        with:
          query: "UPDATE items SET qty = 6 WHERE id = 99 RETURNING id"
          expect_rows: "=1"
`))
		wantExpectRowsFailure(t, rr, err, "apply", "0 row(s) returned, expected =1")
	})
	t.Run("select", func(t *testing.T) {
		app := expectRowsApp(t)
		rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", `      - id: apply
        run: sql
        with:
          query: "SELECT id FROM items WHERE id = 99"
          expect_rows: ">0"
`))
		wantExpectRowsFailure(t, rr, err, "apply", "0 row(s) returned, expected >0")
	})
	t.Run("query shorthand with a with block", func(t *testing.T) {
		app := expectRowsApp(t)
		rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", `      - id: apply
        query: "UPDATE items SET qty = :qty WHERE id = 99"
        with:
          params: { qty: "6" }
          expect_rows: ">0"
`))
		wantExpectRowsFailure(t, rr, err, "apply", "0 row(s) affected, expected >0")
	})
	t.Run("sql_dynamic", func(t *testing.T) {
		app := expectRowsApp(t)
		rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", `      - id: apply
        run: sql_dynamic
        with:
          query: "UPDATE items SET qty = 6 WHERE id = 99"
          expect_rows: "=1"
`))
		wantExpectRowsFailure(t, rr, err, "apply", "0 row(s) affected, expected =1")
	})
	t.Run("same value in both positions", func(t *testing.T) {
		app := expectRowsApp(t)
		rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", `      - id: apply
        run: sql
        expect_rows: "=1"
        with:
          query: "UPDATE items SET qty = 6 WHERE id = 99"
          expect_rows: "=1"
`))
		wantExpectRowsFailure(t, rr, err, "apply", "0 row(s) affected, expected =1")
	})
}

// Two different guards on one step: the loader picks neither and the step
// refuses to run, so the statement is never executed under half its guard.
func TestExpectRowsDeclaredTwiceWithDifferentValuesDoesNotRun(t *testing.T) {
	app := expectRowsApp(t)
	mustExec(t, app.DB, `INSERT INTO items (id, name, qty) VALUES (1, 'a', 5)`)
	source := expectRowsFlow("", `      - id: apply
        run: sql
        expect_rows: ">0"
        with:
          query: "UPDATE items SET qty = 6 WHERE id = 1"
          expect_rows: "=2"
`)
	rr, err := runExpectRowsFlow(t, app, source)
	if err == nil || !strings.Contains(err.Error(), `step "apply" was not run: expect_rows is declared twice with different values (">0" at the step root, "=2" under with:)`) {
		t.Fatalf("error = %v (status %d)", err, rr.Code)
	}
	if got := expectRowsInt(t, app, `SELECT qty FROM items WHERE id = 1`); got != 5 {
		t.Fatalf("the statement ran under contradictory guards (qty %d)", got)
	}
}

// `expect_rows` reads the same from the step root and from `with:`: a quoted
// comparison or a bare integer is the assertion; a float or boolean is
// refused in both; an empty value is no assertion in both (and refused at
// write time).
func TestExpectRowsPositionsReadTheSame(t *testing.T) {
	for _, tc := range []struct {
		yaml  string
		valid bool
		count int64 // a row count the assertion accepts, when valid
	}{
		{`1`, true, 1}, {`0`, true, 0}, {`"=1"`, true, 1}, {`'>0'`, true, 7}, {`=2`, true, 2},
		{`">= 1"`, true, 1}, {`<1`, true, 0}, {`+1`, true, 1}, {`01`, true, 1},
		{`1.0`, false, 0}, {`1e3`, false, 0}, {`true`, false, 0}, {`at least one`, false, 0}, {`[1]`, false, 0},
	} {
		var file FlowFileGHA
		source := "on:\n  request: { method: POST, path: /api/p }\njobs:\n  p:\n    steps:\n" +
			"      - run: sql\n        with:\n          query: \"UPDATE t SET a = 1\"\n          expect_rows: " + tc.yaml + "\n"
		if err := yamlUnmarshal([]byte(source), &file); err != nil {
			t.Fatalf("%s under with: %v", tc.yaml, err)
		}
		under, present := ghaWithExpectRows(file.Jobs["p"].Steps[0].With)
		if !present {
			t.Fatalf("%s: with.expect_rows not seen", tc.yaml)
		}
		check := func(position, expr string) {
			ok, err := evalExpectRows(expr, tc.count)
			if tc.valid && (err != nil || !ok) {
				t.Errorf("expect_rows: %s at the %s read as %q: evalExpectRows(%d) = %v, %v", tc.yaml, position, expr, tc.count, ok, err)
			}
			if !tc.valid && err == nil {
				t.Errorf("expect_rows: %s at the %s read as %q and was accepted", tc.yaml, position, expr)
			}
		}
		check("with position", under)
		var root FlowFileGHA
		source = "on:\n  request: { method: POST, path: /api/p }\njobs:\n  p:\n    steps:\n" +
			"      - run: sql\n        with:\n          query: \"UPDATE t SET a = 1\"\n        expect_rows: " + tc.yaml + "\n"
		if err := yamlUnmarshal([]byte(source), &root); err != nil {
			// A list cannot decode into the step-root string field at all.
			if tc.valid {
				t.Fatalf("%s at the step root: %v", tc.yaml, err)
			}
			continue
		}
		check("step root", strings.TrimSpace(root.Jobs["p"].Steps[0].ExpectRows))
	}
	// Absent, null and the unquoted `!=0` (a YAML tag on an empty scalar).
	if expr, present := ghaWithExpectRows(map[string]any{"query": "SELECT 1"}); expr != "" || present {
		t.Errorf("absent key read as %q, present=%v", expr, present)
	}
	for _, empty := range []any{nil, "", "  "} {
		if expr, present := ghaWithExpectRows(map[string]any{"expect_rows": empty}); expr != "" || !present {
			t.Errorf("empty value %#v read as %q, present=%v", empty, expr, present)
		}
	}
}
