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
