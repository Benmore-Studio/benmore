//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A computed false must remain false after with.params -> SQLite -> CRUD
// readback. Text "false" in a BOOLEAN column is truthy to an SDK consumer.
func TestFlowSQLComputedBooleanParameterRoundTrip(t *testing.T) {
	app, _ := auditApp(t)
	mustExec(t, app.DB, "CREATE TABLE grades (id INTEGER PRIMARY KEY, passed BOOLEAN, direct BOOLEAN)")
	if err := os.MkdirAll(filepath.Join(app.Dir, "static"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app.Dir, "static", "grading.ts"), []byte(`export function grade(x) { return {passed:x.score >= 80}; }`), 0644); err != nil {
		t.Fatal(err)
	}
	const source = `on:
  request: {method: POST, path: /api/grade, strict_json: true, transaction: true}
jobs:
  main:
    steps:
      - id: grade
        run: compute
        with: {module: grading, function: grade, args: {score: '${{ params.score }}'}}
      - run: sql
        with:
          query: "INSERT INTO grades(passed,direct) VALUES(:passed,${{ steps.grade.outputs.passed }})"
          params: {passed: '${{ steps.grade.outputs.passed }}'}
      - run: respond
        with: {json: {ok: true}}
`
	flows, err := parseGHAFlowFile("flows/grade.yaml", []byte(source))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterFlows(mux, app, flows)
	for _, score := range []int{33, 100} {
		r := httptest.NewRequest(http.MethodPost, "/api/grade", strings.NewReader(fmt.Sprintf(`{"score":%d}`, score)))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("grade status=%d body=%s", w.Code, w.Body.String())
		}
	}
	rows, err := app.DB.Query("SELECT passed,direct,typeof(passed) AS storage FROM grades ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	got, err := scanRows(rows, nil)
	if err != nil || len(got) != 2 {
		t.Fatalf("readback=%#v err=%v", got, err)
	}
	for i, expected := range []bool{false, true} {
		if got[i]["passed"] != expected || got[i]["direct"] != expected || got[i]["storage"] != "integer" {
			t.Errorf("row %d=%#v, want both bindings to round-trip boolean %t with integer storage", i, got[i], expected)
		}
	}
	var failed int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM grades WHERE passed=0").Scan(&failed); err != nil || failed != 1 {
		t.Fatalf("false SQL predicate count=%d err=%v", failed, err)
	}
}

func TestFlowSQLBooleanParametersPreserveTextAndNull(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, "CREATE TABLE param_values (value, kind TEXT)")
	for _, tc := range []struct {
		name, expr string
		value      any
		want       any
	}{
		{"false", "{{v}}", false, int64(0)},
		{"true", "{{v}}", true, int64(1)},
		{"string_false", "{{v}}", "false", "false"},
		{"string_true", "{{v}}", "true", "true"},
		{"literal", "false", false, "false"},
		{"embedded", "flag={{v}}", false, "flag=false"},
		{"json_text", "{{v | json}}", false, "false"},
		{"null", "{{v}}", nil, nil},
		{"array", "{{v}}", []any{false, true}, "[false,true]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &FlowContext{App: app, Data: map[string]any{"v": tc.value}, Params: map[string]string{"bound": "previous"}, NullParams: map[string]bool{"bound": true}}
			step := &FlowStep{Type: "sql", SQL: "INSERT INTO param_values(value,kind) VALUES(:bound,:kind)", SQLParams: map[string]string{"bound": tc.expr, "kind": tc.name}}
			if err := execStepSQL(ctx, step); err != nil {
				t.Fatal(err)
			}
			var got any
			if err := app.DB.QueryRow("SELECT value FROM param_values WHERE kind=?", tc.name).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("value=%#v want=%#v", got, tc.want)
			}
			if ctx.Params["bound"] != "previous" || !ctx.NullParams["bound"] {
				t.Fatal("step-local parameter state was not restored")
			}
		})
	}
}

// A boolean computed by a value expression or passed through a `default:`
// pipe binds SQLite's 1/0 like a plain boolean ref, in with.params and inline
// in the query alike. Both used to bind the text 'true'/'false', which SQLite
// reads as 0 in a condition: `CASE WHEN :rush` was false for every request,
// so the quote below ignored the rush surcharge when the client asked for it.
func TestFlowSQLExpressionAndPipeBooleansBindAsIntegers(t *testing.T) {
	app, _ := auditApp(t)
	mustExec(t, app.DB, "CREATE TABLE quotes (id INTEGER PRIMARY KEY, label TEXT, big INTEGER, rush INTEGER, rush_inline INTEGER)")
	const source = `on:
  request: {method: POST, path: /api/quote}
jobs:
  main:
    steps:
      - run: sql
        with:
          query: "INSERT INTO quotes(label, big, rush, rush_inline) VALUES(:label, CASE WHEN :big THEN 1 ELSE 0 END, CASE WHEN :rush THEN 1 ELSE 0 END, CASE WHEN ${{ params.rush | default:'0' }} THEN 1 ELSE 0 END)"
          params:
            label: '${{ params.label }}'
            big: '${{ params.n > 3 }}'
            rush: '${{ params.rush | default:''0'' }}'
      - run: respond
        with: {json: {ok: true}}
`
	flows, err := parseGHAFlowFile("flows/quote.yaml", []byte(source))
	if err != nil {
		t.Fatal(err)
	}
	if msg := ValidateOnWrite("flows/quote.yaml", source); msg != "" {
		t.Fatalf("write gate refused the flow: %s", msg)
	}
	mux := http.NewServeMux()
	RegisterFlows(mux, app, flows)
	for _, body := range []string{
		`{"label":"rush-big","n":5,"rush":true}`,
		`{"label":"plain-small","n":2,"rush":false}`,
		`{"label":"omitted","n":4}`,
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/quote", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status=%d body=%s", body, w.Code, w.Body.String())
		}
	}
	for _, want := range []struct {
		label                 string
		big, rush, rushInline int64
	}{
		{"rush-big", 1, 1, 1},
		{"plain-small", 0, 0, 0},
		// rush omitted: the default pipe's literal '0' binds 0.
		{"omitted", 1, 0, 0},
	} {
		var big, rush, rushInline int64
		if err := app.DB.QueryRow("SELECT big, rush, rush_inline FROM quotes WHERE label = ?", want.label).Scan(&big, &rush, &rushInline); err != nil {
			t.Fatalf("%s: %v", want.label, err)
		}
		if big != want.big || rush != want.rush || rushInline != want.rushInline {
			t.Errorf("%s: big=%d rush=%d rush_inline=%d, want %d %d %d", want.label, big, rush, rushInline, want.big, want.rush, want.rushInline)
		}
	}
}

// with.params binds a whole-value expression by the type of its result, as
// the same `${{ }}` inline in the query does: a comparison or `!` binds 1/0,
// an `&&`/`||` operand keeps its own type (a number stays a number, null
// binds NULL), and other pipes keep producing text.
func TestFlowSQLParamExpressionResultTypes(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, "CREATE TABLE expr_values (kind TEXT, value)")
	data := map[string]any{"n": float64(5), "on": true, "off": false, "nothing": nil, "word": "true"}
	for _, tc := range []struct {
		name, expr string
		want       any
	}{
		{"comparison_true", "{{ params.n > 3 }}", int64(1)},
		{"comparison_false", "{{ params.n > 9 }}", int64(0)},
		{"not", "{{ !params.on }}", int64(0)},
		{"and_boolean", "{{ params.on && params.off }}", int64(0)},
		{"or_expression", "{{ params.off || params.on && true }}", int64(1)},
		{"and_number", "{{ params.on && params.n }}", int64(5)},
		{"and_null", "{{ params.on && params.nothing }}", nil},
		{"default_true", "{{ params.on | default:'0' }}", int64(1)},
		{"default_false", "{{ params.off | default:'1' }}", int64(0)},
		{"default_missing", "{{ params.absent | default:'0' }}", int64(0)},
		{"default_string", "{{ params.word | default:'x' }}", "true"},
		{"upper_text", "{{ params.on | upper }}", "TRUE"},
		{"literal_text", "{{ params.on && 'yes' }}", "yes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
			for k, v := range data {
				ctx.Data[k] = v
			}
			step := &FlowStep{Type: "sql", SQL: "INSERT INTO expr_values(kind, value) VALUES(:kind, :v)", SQLParams: map[string]string{"v": tc.expr, "kind": tc.name}}
			if err := execStepSQL(ctx, step); err != nil {
				t.Fatal(err)
			}
			if len(ctx.MissingRefs) > 0 {
				t.Fatalf("unresolved refs: %v", ctx.MissingRefs)
			}
			var got any
			if err := app.DB.QueryRow("SELECT value FROM expr_values WHERE kind = ?", tc.name).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("value=%#v want=%#v", got, tc.want)
			}
		})
	}
}
