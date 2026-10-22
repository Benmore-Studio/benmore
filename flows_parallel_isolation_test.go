//go:build !cli

package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
)

// A real SQL call holds the first branch's with.params overlay open while an
// independent branch binds the incoming parameter. The latter must see the
// block's input, never another branch's temporary SQL parameter.
func parallelBarrierContext(t *testing.T) *FlowContext {
	t.Helper()
	app, cleanup := newTestApp(t)
	t.Cleanup(cleanup)
	app.DB.SetMaxOpenConns(2)
	started, release := make(chan struct{}), make(chan struct{})
	var conns []*sql.Conn
	for i := 0; i < 2; i++ {
		conn, err := app.DB.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
		if err := conn.Raw(func(raw any) error {
			native := raw.(*sqlite3.SQLiteConn)
			if err := native.RegisterFunc("parallel_first", func() (int, error) {
				close(started)
				select {
				case <-release:
					return 1, nil
				case <-time.After(5 * time.Second):
					return 0, fmt.Errorf("timed out waiting for sibling query")
				}
			}, false); err != nil {
				return err
			}
			return native.RegisterFunc("parallel_second", func() int {
				close(release)
				return 1
			}, false)
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, conn := range conns {
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	}
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{"value": "incoming"}}
	ctx.apiClient = &http.Client{Transport: apiStatusRoundTripper(func(req *http.Request) (*http.Response, error) {
		select {
		case <-started:
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`)), Request: req}, nil
		case <-time.After(5 * time.Second):
			return nil, fmt.Errorf("timed out waiting for first query")
		}
	})}
	return ctx
}

func TestParallelSQLParamsStayInBranch(t *testing.T) {
	ctx := parallelBarrierContext(t)
	parallel := &FlowStep{Type: "parallel", Steps: []FlowStep{
		{Type: "sql", Name: "first", SQL: `SELECT parallel_first(), :value AS value`, SQLParams: map[string]string{"value": "branch-only"}},
		{Type: "if", Condition: "true", Steps: []FlowStep{
			{Type: "api", API: &FlowAPICall{URL: "https://8.8.8.8/fixture-barrier"}},
			{Type: "sql", Name: "second", SQL: `SELECT parallel_second(), :value AS value`},
		}},
	}}
	if err := executeStep(ctx, parallel); err != nil {
		t.Fatalf("parallel: %v", err)
	}
	for name, want := range map[string]string{"first": "branch-only", "second": "incoming"} {
		rows, ok := ctx.Data[name].([]map[string]any)
		if !ok || len(rows) != 1 || rows[0]["value"] != want {
			t.Errorf("%s query output = %#v, want value %q", name, ctx.Data[name], want)
		}
	}
	if got := ctx.Params["value"]; got != "incoming" {
		t.Errorf("parallel changed incoming parameter to %q", got)
	}
}

func TestParallelMissingReferencesStayInBranch(t *testing.T) {
	ctx := parallelBarrierContext(t)
	step := &FlowStep{Type: "parallel", Steps: []FlowStep{
		{Type: "sql", Name: "missing_input", SQL: `SELECT parallel_first(), :value AS value`, SQLParams: map[string]string{"value": "{{not_provided}}"}},
		{Type: "if", Condition: "true", Steps: []FlowStep{
			{Type: "api", API: &FlowAPICall{URL: "https://8.8.8.8/fixture-barrier"}},
			{Type: "sql", Name: "sibling", SQL: `SELECT parallel_second() AS done`},
		}},
	}}
	if err := executeStep(ctx, step); err == nil || !strings.Contains(err.Error(), "not_provided") || !strings.Contains(err.Error(), "missing_input") {
		t.Fatalf("sibling must not clear another branch's missing references: %v", err)
	}
	if len(ctx.Data) != 0 {
		t.Fatalf("failed parallel block published outputs: %#v", ctx.Data)
	}
}

func TestParallelNestedOutputsMergeInDeclarationOrder(t *testing.T) {
	ctx := &FlowContext{Data: map[string]any{
		"shared": "input", "untouched": "keep",
		"left":  []map[string]any{{"id": "left-1"}, {"id": "left-2"}},
		"right": []map[string]any{{"id": "right-1"}, {"id": "right-2"}},
	}, Params: map[string]string{}}
	step := &FlowStep{Type: "parallel", Steps: []FlowStep{
		{Type: "if", Condition: "true", Steps: []FlowStep{
			{Type: "for_each", ForEach: "left", ForAs: "item", Steps: []FlowStep{
				{Type: "set", Name: "left_result", Set: map[string]string{"left_value": "{{item.id}}"}},
			}},
			{Type: "set", Set: map[string]string{"shared": "first"}},
		}},
		{Type: "parallel", Steps: []FlowStep{
			{Type: "for_each", ForEach: "right", ForAs: "item", Steps: []FlowStep{
				{Type: "set", Name: "right_result", Set: map[string]string{"right_value": "{{item.id}}"}},
			}},
			{Type: "set", Set: map[string]string{"shared": "input"}},
		}},
	}}
	if err := executeStep(ctx, step); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"left_value": "left-2", "right_value": "right-2", "shared": "input", "untouched": "keep", "item.id": "right-2"} {
		if got := ctx.Data[key]; got != want {
			t.Errorf("%s = %#v, want %q", key, got, want)
		}
	}
}

func TestParallelLoopAssignmentsReplaceTheWholeAlias(t *testing.T) {
	t.Run("body_replaces_iterable", func(t *testing.T) {
		ctx := &FlowContext{Data: map[string]any{
			"item": map[string]any{"id": "base"}, "item.id": "base",
			"rows": []map[string]any{{"id": "base"}},
		}, Params: map[string]string{}}
		step := &FlowStep{Type: "parallel", Steps: []FlowStep{
			{Type: "set", Set: map[string]string{"item.id": "first"}},
			{Type: "for_each", ForEach: "rows", ForAs: "item", Steps: []FlowStep{{Type: "set", Set: map[string]string{"rows": ""}}}},
		}}
		if err := executeStep(ctx, step); err != nil {
			t.Fatal(err)
		}
		if got := ctx.Data["item.id"]; got != "base" {
			t.Fatalf("completed loop assignment lost when its body replaced the iterable: %#v", got)
		}
	})
	t.Run("later_alias_has_fewer_fields", func(t *testing.T) {
		ctx := &FlowContext{Data: map[string]any{
			"left":  []map[string]any{{"id": "left", "secret": "left-only"}},
			"right": []map[string]any{{"id": "right"}},
		}, Params: map[string]string{}}
		step := &FlowStep{Type: "parallel", Steps: []FlowStep{
			{Type: "for_each", ForEach: "left", ForAs: "item"},
			{Type: "for_each", ForEach: "right", ForAs: "item"},
		}}
		if err := executeStep(ctx, step); err != nil {
			t.Fatal(err)
		}
		if got := ctx.Data["item.id"]; got != "right" {
			t.Fatalf("later alias did not win: %#v", got)
		}
		if value, present := flowDataValue(ctx, "item.secret"); present {
			t.Fatalf("later alias inherited a missing field from its sibling: %#v", value)
		}
	})
}

func TestParallelMergesRequestSecretTaintAndProvenance(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{App: app,
		Data:   map[string]any{"request_value": "user-choice", "secret_value": "fixture-secret"},
		Params: map[string]string{}, RequestKeys: map[string]bool{"request_value": true}, SecretKeys: map[string]bool{"secret_value": true},
	}
	step := &FlowStep{Type: "parallel", Steps: []FlowStep{
		{Type: "sql", Name: "pick", SQL: `SELECT {{request_value}} AS value, 'https://api.example.com/token' AS url`},
		{Type: "set", Name: "copies", Set: map[string]string{"request_copy": "{{request_value}}", "secret_copy": "{{secret_value}}"}},
	}}
	if err := executeStep(ctx, step); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"request_value", "pick", "request_copy", "copies.request_copy"} {
		if !ctx.RequestKeys[key] {
			t.Errorf("request taint lost for %q", key)
		}
	}
	for _, key := range []string{"secret_value", "secret_copy", "copies.secret_copy"} {
		if !ctx.SecretKeys[key] {
			t.Errorf("secret taint lost for %q", key)
		}
	}
	if !ctx.flowValueAuthoredByStep("{{pick.url}}", "https://api.example.com/token") {
		t.Error("authored URL provenance was lost at the join")
	}
	if err := executeStep(ctx, &FlowStep{Type: "sql_dynamic", SQL: `SELECT '{{pick.value}}'`}); err == nil || !strings.Contains(err.Error(), "request-sourced") {
		t.Fatalf("request-derived output reached raw SQL after parallel: %v", err)
	}
}

func TestParallelFailureFinishesSiblingsAndRetainsDurableWrites(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE parallel_log (value TEXT)`)
	ctx := &FlowContext{App: app, Data: map[string]any{"items": []map[string]any{{"id": "a"}, {"id": "b"}, {"id": "c"}}}, Params: map[string]string{}, Writes: newFlowWriteLog()}
	step := &FlowStep{Type: "parallel", Steps: []FlowStep{
		{Type: "if", Condition: "true", Steps: []FlowStep{{Type: "sql", SQL: "SELECT missing_first"}}},
		{Type: "for_each", ForEach: "items", ForAs: "item", Steps: []FlowStep{
			{Type: "sql", Name: "written", SQL: "INSERT INTO parallel_log (value) VALUES ({{item.id}})"},
		}},
		{Type: "sql", SQL: "SELECT missing_last"},
	}}
	if err := executeStep(ctx, step); err == nil || !strings.Contains(err.Error(), "missing_first") {
		t.Fatalf("first declared error must win: %v", err)
	}
	if got := gateScalar(t, app, `SELECT COUNT(*) FROM parallel_log`); got != "3" {
		t.Fatalf("failed sibling stopped independent loop after %s writes", got)
	}
	if len(ctx.Data) != 1 {
		t.Fatalf("failed block published branch outputs: %#v", ctx.Data)
	}
	if writes := ctx.Writes.take(false); len(writes) != 1 || writes[0].Table != "parallel_log" {
		t.Fatalf("durable writes lost on sibling failure: %#v", writes)
	}
}

func TestParallelProvenanceFollowsWinningOutput(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{App: app, Data: map[string]any{"request_value": "https://api.example.com/token"}, Params: map[string]string{}, RequestKeys: map[string]bool{"request_value": true}}
	step := &FlowStep{Type: "parallel", Steps: []FlowStep{
		{Type: "sql", Name: "pick", SQL: `SELECT {{request_value}} AS value, 'https://api.example.com/token' AS url`},
		{Type: "set", Name: "pick", Set: map[string]string{"url": "{{request_value}}"}},
	}}
	if err := executeStep(ctx, step); err != nil {
		t.Fatal(err)
	}
	if ctx.flowValueAuthoredByStep("{{pick.url}}", "https://api.example.com/token") {
		t.Fatal("earlier sibling's source certified a later request-controlled output")
	}
}

func TestParallelEnqueuesStayInParentTransaction(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureJobsTable(app.DB)
	for _, commit := range []bool{false, true} {
		tx, err := app.DB.Begin()
		if err != nil {
			t.Fatal(err)
		}
		ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}, Tx: tx}
		step := &FlowStep{Type: "parallel", Steps: []FlowStep{
			{Type: "enqueue", Name: "first", Enqueue: &FlowEnqueue{Flow: "worker", With: map[string]string{"value": "first"}}},
			{Type: "enqueue", Name: "second", Enqueue: &FlowEnqueue{Flow: "worker", With: map[string]string{"value": "second"}}},
		}}
		if err := executeStep(ctx, step); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		var count int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM _benmore_jobs`).Scan(&count); err != nil || count != 2 {
			_ = tx.Rollback()
			t.Fatalf("parallel enqueue did not use the parent transaction: count=%d err=%v", count, err)
		}
		want := "0"
		if commit {
			err = tx.Commit()
			want = "2"
		} else {
			err = tx.Rollback()
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := gateScalar(t, app, `SELECT COUNT(*) FROM _benmore_jobs`); got != want {
			t.Fatalf("parallel enqueues after commit=%t: %s rows, want %s", commit, got, want)
		}
	}
}

func TestParallelRejectsSharedHTTPBeforeAnyBranch(t *testing.T) {
	for _, unsafe := range []FlowStep{
		{Type: "respond", Respond: &FlowRespond{Body: "unsafe"}},
		{Type: "redirect", Redirect: "/after"},
		{Type: "serve_file"},
		{Type: "parse", Parse: "body"},
	} {
		t.Run(unsafe.Type, func(t *testing.T) {
			app, cleanup := newTestApp(t)
			defer cleanup()
			mustExec(t, app.DB, `CREATE TABLE parallel_log (value TEXT)`)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/parallel", strings.NewReader(`{"untouched":true}`))
			ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}, Request: r, Writer: w}
			step := &FlowStep{Type: "parallel", Steps: []FlowStep{
				{Type: "sql", SQL: `INSERT INTO parallel_log (value) VALUES ('must not run')`},
				{Type: "if", Condition: "false", Steps: []FlowStep{{Type: "for_each", ForEach: "items", Steps: []FlowStep{unsafe}}}},
			}}
			if err := executeStep(ctx, step); err == nil || !strings.Contains(err.Error(), "before or after the parallel block") {
				t.Fatalf("shared HTTP state was not refused before fan-out: %v", err)
			}
			if got := gateScalar(t, app, `SELECT COUNT(*) FROM parallel_log`); got != "0" {
				t.Fatalf("preflight rejection ran %s sibling writes", got)
			}
			if w.Body.Len() != 0 {
				t.Fatalf("preflight rejection wrote HTTP body: %s", w.Body.String())
			}
			body, err := io.ReadAll(r.Body)
			if err != nil || string(body) != `{"untouched":true}` {
				t.Fatalf("preflight consumed request body: %q %v", body, err)
			}
		})
	}
}

func TestParallelHTTPBoundarySourceValidation(t *testing.T) {
	for _, run := range []string{"respond", "redirect", "serve_file", "parse"} {
		source := stepKeyFlow("      - run: parallel\n        steps:\n          - if: true\n            steps:\n              - run: " + run + "\n")
		if msg := ValidateOnWrite("flows/parallel.yaml", source); !strings.Contains(msg, "before or after the parallel block") {
			t.Errorf("%s write/check gate = %q", run, msg)
		}
		if _, err := parseGHAFlowFile("flows/parallel.yaml", []byte(source)); err == nil || !strings.Contains(err.Error(), "before or after the parallel block") {
			t.Errorf("%s checked loader = %v", run, err)
		}
	}
	// The parallel block's own handler executes after the join, so it retains
	// ordinary HTTP responses. A direct child's handler remains ignored.
	source := stepKeyFlow("      - run: parallel\n        steps:\n          - run: sql\n            with: { query: 'SELECT 1' }\n            on_error:\n              - run: respond\n                with: { body: ignored }\n        on_error:\n          - run: respond\n            with: { body: failed }\n")
	if msg := ValidateOnWrite("flows/parallel.yaml", source); msg != "" {
		t.Fatalf("sequential/ignored handler compatibility: %s", msg)
	}
}

func TestParallelSQLParameterOverlayRace(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	for i := 0; i < 10; i++ {
		ctx := &FlowContext{App: app, Data: map[string]any{"nil_value": nil}, Params: map[string]string{"value": "incoming"}}
		step := &FlowStep{Type: "parallel", Steps: []FlowStep{
			{Type: "sql", Name: "first", SQL: `SELECT :value AS value`, SQLParams: map[string]string{"value": "first"}},
			{Type: "sql", Name: "second", SQL: `SELECT :value AS value`, SQLParams: map[string]string{"value": "{{nil_value}}"}},
		}}
		if err := executeStep(ctx, step); err != nil {
			t.Fatal(err)
		}
		first := ctx.Data["first"].([]map[string]any)[0]["value"]
		second := ctx.Data["second"].([]map[string]any)[0]["value"]
		if first != "first" || second != nil || ctx.Params["value"] != "incoming" || ctx.NullParams["value"] {
			t.Fatalf("branch SQL parameters leaked: first=%#v second=%#v incoming=%q null=%t", first, second, ctx.Params["value"], ctx.NullParams["value"])
		}
	}
}
