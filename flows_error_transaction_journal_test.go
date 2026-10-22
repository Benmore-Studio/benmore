//go:build !cli

package main

import (
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func errorJournalApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	dsn := sqliteAppDSN(filepath.Join(dir, "data.db"), dir)
	dsn = strings.ReplaceAll(dsn, "_busy_timeout=10000", "_busy_timeout=50")
	db, err := sql.Open("sqlite3_benmore", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(2)
	app := &App{Dir: dir, DB: db}
	t.Cleanup(app.Shutdown)
	mustExec(t, db, `CREATE TABLE stock (id INTEGER PRIMARY KEY, available INTEGER); INSERT INTO stock VALUES(1,10); CREATE TABLE failure_journal (reason TEXT, remaining INTEGER); CREATE TABLE shipment (id INTEGER)`)
	return app
}

func journalFailureStep() FlowStep {
	return FlowStep{Type: "sql", Name: "packing", SQL: "INSERT INTO missing_packing_station VALUES(1)", OnError: []FlowStep{
		{Type: "sql", SQL: "INSERT INTO failure_journal(reason,remaining) SELECT :reason,available FROM stock", SQLParams: map[string]string{"reason": "{{error}}"}},
	}}
}

func assertJournalAfterRollback(t *testing.T, app *App, want int) {
	t.Helper()
	var stock, ships, journals int
	for q, to := range map[string]*int{"SELECT available FROM stock WHERE id=1": &stock, "SELECT COUNT(*) FROM shipment": &ships, "SELECT COUNT(*) FROM failure_journal WHERE remaining=10 AND reason LIKE '%missing_packing_station%'": &journals} {
		if err := app.DB.QueryRow(q).Scan(to); err != nil {
			t.Fatal(err)
		}
	}
	if stock != 10 || ships != 0 || journals != want {
		t.Fatalf("rollback/journal: stock=%d shipment=%d journal=%d; want 10/0/%d", stock, ships, journals, want)
	}
}

func TestFlowErrorJournalRunsAfterTransactionRollback(t *testing.T) {
	for _, kind := range []string{"direct", "if", "loop"} {
		t.Run(kind, func(t *testing.T) {
			app := errorJournalApp(t)
			failed := journalFailureStep()
			failed.OnError = append(failed.OnError, FlowStep{Type: "respond", Respond: &FlowRespond{Status: 409, Body: "packing failed"}})
			var boundary FlowStep
			switch kind {
			case "direct":
				boundary = failed
			case "if":
				boundary = FlowStep{Type: "if", Condition: "true", Steps: []FlowStep{failed}, OnError: []FlowStep{{Type: "sql", SQL: "INSERT INTO shipment VALUES(99)"}}}
			case "loop":
				boundary = FlowStep{Type: "for_each", ForEach: "items", ForAs: "item", Steps: []FlowStep{failed}, OnError: []FlowStep{{Type: "sql", SQL: "INSERT INTO shipment VALUES(99)"}}}
			}
			flow := transactionalResponseFlow(FlowStep{Type: "sql", SQL: "UPDATE stock SET available=available-3 WHERE id=1"}, boundary, FlowStep{Type: "sql", SQL: "INSERT INTO shipment VALUES(1)"})
			r := httptest.NewRequest("POST", flow.Trigger.Path, strings.NewReader(`{"items":[{"id":1},{"id":2}]}`))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			err := executeFlowHTTP(app, flow, w, r)
			if err == nil || !strings.Contains(err.Error(), "missing_packing_station") || w.Code != 409 || w.Body.String() != "packing failed" {
				t.Fatalf("original failure/handler response lost: %v %d %q", err, w.Code, w.Body.String())
			}
			assertJournalAfterRollback(t, app, 1)
		})
	}
}

func TestWorkerErrorJournalSurvivesFailureAndRetry(t *testing.T) {
	app := errorJournalApp(t)
	app.Flows = []Flow{{Name: "fulfill", Transaction: true, Steps: []FlowStep{{Type: "sql", SQL: "UPDATE stock SET available=available-3 WHERE id=1"}, journalFailureStep(), {Type: "sql", SQL: "INSERT INTO shipment VALUES(1)"}}}}
	for attempt := 1; attempt <= 2; attempt++ {
		err := executeFlowJob(app, "fulfill", map[string]any{})
		if err == nil || !strings.Contains(err.Error(), "missing_packing_station") {
			t.Fatalf("job lost failure: %v", err)
		}
		assertJournalAfterRollback(t, app, attempt)
	}
}

func TestErrorJournalReleasesSingleConnectionBeforeHandler(t *testing.T) {
	app := errorJournalApp(t)
	app.DB.SetMaxOpenConns(1)
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	ctx := &FlowContext{App: app, Tx: tx, Data: map[string]any{}, Params: map[string]string{}}
	done := make(chan struct{})
	go func() {
		executeSteps(ctx, []FlowStep{{Type: "sql", SQL: "UPDATE stock SET available=7"}, journalFailureStep()})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		// Release the fixture's held transaction so a regression cannot strand a
		// goroutine or hang test cleanup after this assertion fails.
		tx.Rollback()
		<-done
		t.Fatal("handler waited for the transaction's only connection")
	}
	if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "missing_packing_station") {
		t.Fatalf("original failure=%v", ctx.Error)
	}
	assertJournalAfterRollback(t, app, 1)
}

func TestTransactionErrorJournalStopsEnclosingRetries(t *testing.T) {
	for _, kind := range []string{"if", "loop"} {
		t.Run(kind, func(t *testing.T) {
			app := errorJournalApp(t)
			var beforeFailure int
			failed := journalFailureStep()
			children := []FlowStep{{Type: "api", API: &FlowAPICall{URL: "https://8.8.8.8/fixture-effect"}}, {Type: "sql", SQL: "UPDATE stock SET available=available-1"}, failed}
			boundary := FlowStep{Type: "if", Condition: "true", Steps: children, Retry: 2, RetryDelay: time.Millisecond, OnError: []FlowStep{{Type: "sql", SQL: "INSERT INTO failure_journal(reason,remaining) SELECT :reason,available FROM stock", SQLParams: map[string]string{"reason": "{{error}}"}}}}
			if kind == "loop" {
				boundary.Type = "for_each"
				boundary.ForEach = "items"
				boundary.ForAs = "item"
			}
			tx, err := app.DB.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			ctx := &FlowContext{App: app, Tx: tx, Data: map[string]any{"items": []any{map[string]any{"id": 1}, map[string]any{"id": 2}}}, Params: map[string]string{}}
			ctx.apiClient = &http.Client{Transport: apiStatusRoundTripper(func(req *http.Request) (*http.Response, error) {
				beforeFailure++
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`)), Request: req}, nil
			})}
			executeSteps(ctx, []FlowStep{boundary})
			var terminal *flowTransactionRolledBackError
			if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "missing_packing_station") || !errors.As(ctx.Error, &terminal) {
				t.Fatalf("enclosing retry lost original terminal failure: %v", ctx.Error)
			}
			if beforeFailure != 1 {
				t.Fatalf("enclosing retry replayed an external effect: calls=%d, want 1", beforeFailure)
			}
			assertJournalAfterRollback(t, app, 2)
		})
	}
}

func TestTransactionErrorJournalPreservesParallelTerminalFailure(t *testing.T) {
	app := errorJournalApp(t)
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var calls int32
	ctx := &FlowContext{App: app, Tx: tx, Data: map[string]any{}, Params: map[string]string{}}
	ctx.apiClient = &http.Client{Transport: apiStatusRoundTripper(func(req *http.Request) (*http.Response, error) {
		atomic.AddInt32(&calls, 1)
		return &http.Response{StatusCode: 500, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error":"fixture"}`)), Request: req}, nil
	})}
	parallel := FlowStep{Type: "parallel", Retry: 2, RetryDelay: time.Millisecond, Steps: []FlowStep{
		{Type: "api", Name: "first_failure", API: &FlowAPICall{URL: "https://8.8.8.8/fixture-failing-effect"}},
		{Type: "if", Condition: "true", Steps: []FlowStep{
			{Type: "compute", Compute: &FlowCompute{Module: "missing-fixture-module", Function: "run"}, OnError: []FlowStep{{Type: "set", Set: map[string]string{"handled": "true"}}}},
		}},
	}}
	executeSteps(ctx, []FlowStep{{Type: "sql", SQL: "UPDATE stock SET available=7"}, parallel})
	var terminal *flowTransactionRolledBackError
	if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "500") || strings.Contains(ctx.Error.Error(), "missing-fixture-module") || !errors.As(ctx.Error, &terminal) {
		t.Fatalf("first parallel failure or sibling terminal state lost: %v", ctx.Error)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("parallel first-error selection hid sibling rollback: request effects=%d, want 1", got)
	}
	assertJournalAfterRollback(t, app, 0)
}
