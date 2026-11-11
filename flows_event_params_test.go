//go:build !cli

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// A data-event flow's SQL binds the row's columns as :name. They reached only
// ctx.Data, so `:title` silently bound NULL (SQLite's value for an unbound
// named parameter) while `${{ title }}` worked.
func TestEventFlowBindsRowColumnsAsColonParams(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE copies (title TEXT NOT NULL, n INTEGER, r REAL, missing TEXT)`)
	flows, err := parseGHAFlowFile(filepath.Join(app.Dir, "flows", "copy.yaml"), []byte(`on:
  event: {table: probes, op: insert}
jobs:
  copy:
    steps:
      - run: sql
        with:
          query: "INSERT INTO copies (title, n, r, missing) VALUES (:title, CAST(:n AS INTEGER), :r, :gone)"
`))
	if err != nil || len(flows) != 1 {
		t.Fatalf("parse: %v", err)
	}
	var flowErr error
	runFlowEventWith(app, flows[0], map[string]any{"id": int64(1), "title": "hello", "n": float64(1234567), "r": 1234567.5, "gone": nil}, func(ctx *FlowContext) { flowErr = ctx.Error })
	if flowErr != nil {
		t.Fatal(flowErr)
	}
	var title string
	var n int64
	var r float64
	var missing any
	if err := app.DB.QueryRow(`SELECT title, n, r, missing FROM copies`).Scan(&title, &n, &r, &missing); err != nil {
		t.Fatal(err)
	}
	if title != "hello" || n != 1234567 || r != 1234567.5 || missing != nil {
		t.Fatalf("copied %q %d %v %v", title, n, r, missing)
	}
}

func TestSQLQuotedRefProblem(t *testing.T) {
	for query, refused := range map[string]bool{
		"INSERT INTO t (a) VALUES ('n=${{ params.n }}')":             true,
		"SELECT 'a {{x}} b'":                                         true,
		"INSERT INTO t (a) VALUES ('${{ params.n }}')":               false,
		"INSERT INTO t (a) VALUES ('n=' || :n)":                      false,
		"SELECT * FROM t WHERE a = {{x}} AND b = 'literal {braces}'": false,
		"SELECT '{{a}} and {{b}}'":                                   true,
	} {
		if got := sqlQuotedRefProblem(query) != ""; got != refused {
			t.Errorf("%s: refused=%v, want %v", query, got, refused)
		}
	}
	msg := ValidateOnWrite("flows/x.yaml", "on:\n  request: {method: POST, path: /api/x}\njobs:\n  x:\n    steps:\n      - run: sql\n        with:\n          query: \"INSERT INTO t (a) VALUES ('n=${{ params.n }}')\"\n")
	if !strings.Contains(msg, "inside the quoted string") {
		t.Fatalf("write gate did not refuse a reference inside a SQL string: %q", msg)
	}
}
