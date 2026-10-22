//go:build !cli

package main

import (
	"reflect"
	"strings"
	"testing"
)

// TestSQLDynamicGuardHasNoTrustedEscapeHatch pins item 20: the runtime taint
// guard used to tell authors to set `trusted: true`, but no parser ever set
// FlowStep.Trusted, so the hint sent authors to a knob that did nothing. The
// field is gone (the guard has no opt-out) and the error names the supported
// alternative instead.
func TestSQLDynamicGuardHasNoTrustedEscapeHatch(t *testing.T) {
	if _, ok := reflect.TypeOf(FlowStep{}).FieldByName("Trusted"); ok {
		t.Fatal("FlowStep.Trusted must not exist: sql_dynamic's request-taint guard has no opt-out")
	}

	ctx := &FlowContext{
		Data:        map[string]any{"sort": "name"},
		Params:      map[string]string{"sort": "name"},
		RequestKeys: map[string]bool{"sort": true},
	}
	step := &FlowStep{Name: "list", Type: "sql_dynamic", SQL: "SELECT * FROM notes ORDER BY {{sort}}"}
	err := flowDynamicGuardRequestRefs(step, ctx)
	if err == nil {
		t.Fatal("request-sourced ref in sql_dynamic must be refused")
	}
	msg := err.Error()
	if strings.Contains(msg, "trusted") {
		t.Fatalf("error still advertises the dead `trusted` escape hatch: %s", msg)
	}
	for _, want := range []string{"run: sql", ":sort", "CASE :sort WHEN"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error should point at the parameterized alternative (%q): %s", want, msg)
		}
	}

	step = &FlowStep{Name: "p", Type: "sql_dynamic", SQL: "SELECT 1", SQLParams: map[string]string{"sort": "x"}}
	if err := flowDynamicGuardRequestRefs(step, ctx); err == nil || strings.Contains(err.Error(), "trusted") {
		t.Fatalf("with.params branch must refuse without a trusted hint, got %v", err)
	}
}

// TestSQLDynamicGuardAlternativeWorks proves the alternative the error names
// is real: a request-chosen sort column selected from fixed literals inside a
// parameterized `run: sql` step orders rows and cannot inject.
func TestSQLDynamicGuardAlternativeWorks(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)`)
	mustExec(t, app.DB, `INSERT INTO notes (body) VALUES ('b'), ('c'), ('a')`)

	run := func(sort string) []map[string]any {
		ctx := &FlowContext{
			App:         app,
			Data:        map[string]any{"sort": sort},
			Params:      map[string]string{"sort": sort},
			RequestKeys: map[string]bool{"sort": true},
		}
		step := &FlowStep{Name: "rows", Type: "sql", SQL: "SELECT body FROM notes ORDER BY CASE :sort WHEN 'body' THEN body END, id"}
		if err := execStepSQL(ctx, step); err != nil {
			t.Fatalf("execStepSQL(sort=%q): %v", sort, err)
		}
		rows, _ := ctx.Data["rows"].([]map[string]any)
		return rows
	}
	if rows := run("body"); len(rows) != 3 || rows[0]["body"] != "a" {
		t.Fatalf("sort=body should order alphabetically, got %v", rows)
	}
	if rows := run("id; DROP TABLE notes"); len(rows) != 3 || rows[0]["body"] != "b" {
		t.Fatalf("unknown sort must fall back to id order without injecting, got %v", rows)
	}
}
