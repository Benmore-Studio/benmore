//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A `:name` in a run: sql query binds the request field, path parameter or
// with.params value of that name. When the request did not send it, the
// placeholder stayed in the SQL and the driver failed with "not enough args
// to execute query: want 4 got 3", which names no field. The step now fails
// before the statement runs and names every parameter it could not bind.
func TestFlowSQLMissingBindNamesTheParameter(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, body TEXT, tag TEXT, kind TEXT)")

	run := func(sqlText string, params map[string]string) error {
		ctx := &FlowContext{App: app, Data: map[string]any{}, Params: params}
		return execStepSQL(ctx, &FlowStep{Name: "insert_note", Type: "sql", SQL: sqlText})
	}

	err := run("INSERT INTO notes (title, body, tag, kind) VALUES (:title, :body, :tag, :kind)", map[string]string{"body": "b", "tag": "t", "kind": "k"})
	if err == nil || !strings.Contains(err.Error(), ":title is not set") || strings.Contains(err.Error(), "not enough args") {
		t.Fatalf("missing :title answered %v; want the parameter named", err)
	}
	err = run("INSERT INTO notes (title, body, tag, kind) VALUES (:title, :body, :tag, :title)", map[string]string{"tag": "t"})
	if err == nil || !strings.Contains(err.Error(), ":title and :body are not set") {
		t.Fatalf("two missing parameters answered %v; want both named once, in query order", err)
	}

	// A script stops before its first statement: without the check the
	// first INSERT ran and only the second one failed.
	err = run("INSERT INTO notes (body) VALUES (:body); INSERT INTO notes (title) VALUES (:title)", map[string]string{"body": "b"})
	if err == nil || !strings.Contains(err.Error(), ":title is not set") {
		t.Fatalf("script with a missing parameter answered %v", err)
	}
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM notes").Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d rows written before the missing parameter was found (err %v)", n, err)
	}

	// `:name` text inside a string literal, a quoted identifier or a comment
	// is not a parameter, and a query whose parameters are all set runs.
	if err := run(`INSERT INTO notes ("title", body, tag, kind) VALUES ('at 10:30 :not_a_param', :body, '', '') -- :also_not`, map[string]string{"body": "b"}); err != nil {
		t.Fatalf("query with :name only inside literals and comments failed: %v", err)
	}
	if err := run("INSERT INTO notes (title) VALUES (:title) /* :not_either */", map[string]string{"title": ""}); err != nil {
		t.Fatalf("an empty request field is set and must bind: %v", err)
	}
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM notes").Scan(&n); err != nil || n != 2 {
		t.Fatalf("want the 2 complete inserts, got %d (err %v)", n, err)
	}

	// `b` was sent, but `x:b` is not a bind (a :name binds only where it
	// starts a token), so the step must not claim :b is missing.
	for _, q := range []string{"SELECT title FROM notes WHERE title = x:b", "SELECT x::b FROM notes"} {
		if err := run(q, map[string]string{"b": "sent"}); err == nil || strings.Contains(err.Error(), "is not set") {
			t.Fatalf("%s answered %v; want the driver's own error, not a missing :b", q, err)
		}
	}
}

// Over HTTP the failed step's answer names the parameter for those who may
// see step errors, and gives every caller a fixed reason.
func TestFlowSQLMissingBindAnswer(t *testing.T) {
	f := newServerErrorFixture(t, true)
	mustExec(t, f.app.DB, "CREATE TABLE memos (id INTEGER PRIMARY KEY, title TEXT, body TEXT)")
	flow := &Flow{Name: "add-note", Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/add-note"},
		Steps: []FlowStep{
			{Name: "insert_note", Type: "sql", SQL: `INSERT INTO memos (title, body) VALUES (:title, :body)`},
			{Type: "respond", Respond: &FlowRespond{Status: 200, Body: "ok"}},
		}}
	f.handler = func(w http.ResponseWriter, r *http.Request) { executeFlowHTTP(f.app, flow, w, r) }
	r := httptest.NewRequest(http.MethodPost, "https://app.example.com/api/add-note", strings.NewReader(`{"body":"hello"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	captureLog(t, func() { f.logged.ServeHTTP(w, r) })
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	_, diag := flowFailureAnswer(t, w)
	if stepErr, _ := diag["step_error"].(string); !strings.Contains(stepErr, ":title is not set") {
		t.Fatalf("step_error %q does not name :title", stepErr)
	}
	if reason, _ := diag["reason"].(string); reason != "a :name the statement binds had no value; the request did not send it" {
		t.Fatalf("reason = %q", reason)
	}
	if hint, _ := diag["hint"].(string); !strings.Contains(hint, "with.params") || !strings.Contains(hint, "params.title || 'Untitled'") {
		t.Fatalf("hint %q does not say how to supply the value", hint)
	}

	// The fallback the hint suggests binds when the field is missing.
	flows, err := parseGHAFlowFile("flows/add-memo.yaml", []byte(`on:
  request: {method: POST, path: /api/add-memo}
jobs:
  main:
    steps:
      - run: sql
        with:
          query: "INSERT INTO memos (title, body) VALUES (:title, :body)"
          params: {title: "${{ params.title || 'Untitled' }}"}
      - run: respond
        with: {json: {ok: true}}
`))
	if err != nil {
		t.Fatal(err)
	}
	f.handler = func(w http.ResponseWriter, r *http.Request) { executeFlowHTTP(f.app, &flows[0], w, r) }
	r = httptest.NewRequest(http.MethodPost, "https://app.example.com/api/add-memo", strings.NewReader(`{"body":"hello"}`))
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	captureLog(t, func() { f.logged.ServeHTTP(w, r) })
	var title string
	if err := f.app.DB.QueryRow("SELECT title FROM memos WHERE body = 'hello'").Scan(&title); w.Code != http.StatusOK || err != nil || title != "Untitled" {
		t.Fatalf("fallback: status %d body %s; title %q err %v", w.Code, w.Body.String(), title, err)
	}
}
