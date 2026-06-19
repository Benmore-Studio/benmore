//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestExecStepEnqueueUsesActiveTransaction(t *testing.T) {
	app := newJobsTestApp(t)

	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	ctx := &FlowContext{
		App:    app,
		Data:   map[string]any{},
		Params: map[string]string{},
		Tx:     tx,
	}
	step := &FlowStep{
		Name: "queued",
		Type: "enqueue",
		Enqueue: &FlowEnqueue{
			Flow: "worker",
			With: map[string]string{"source": "transactional"},
		},
	}
	if err := execStepEnqueue(ctx, step); err != nil {
		t.Fatalf("enqueue in tx: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback tx: %v", err)
	}
	if got := countJobs(t, app.DB); got != 0 {
		t.Fatalf("rolled-back enqueue left %d job(s), want 0", got)
	}

	tx, err = app.DB.Begin()
	if err != nil {
		t.Fatalf("begin tx 2: %v", err)
	}
	ctx.Tx = tx
	if err := execStepEnqueue(ctx, step); err != nil {
		t.Fatalf("enqueue in tx 2: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tx: %v", err)
	}
	if got := countJobs(t, app.DB); got != 1 {
		t.Fatalf("committed enqueue produced %d job(s), want 1", got)
	}
}

func TestExecuteFlowJobHonorsTransactionRollback(t *testing.T) {
	app := newJobsTestApp(t)
	if _, err := app.DB.Exec("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)"); err != nil {
		t.Fatalf("create events: %v", err)
	}
	app.Flows = []Flow{{
		Name:        "atomic_job",
		Transaction: true,
		Steps: []FlowStep{
			{Type: "sql", SQL: "INSERT INTO events (name) VALUES ('before failure')"},
			{Type: "sql", SQL: "INSERT INTO missing_table (name) VALUES ('boom')"},
		},
	}}

	err := executeFlowJob(app, "atomic_job", map[string]any{})
	if err == nil {
		t.Fatal("executeFlowJob should return the failing SQL error")
	}
	var count int
	if scanErr := app.DB.QueryRow("SELECT COUNT(*) FROM events").Scan(&count); scanErr != nil {
		t.Fatalf("count events: %v", scanErr)
	}
	if count != 0 {
		t.Fatalf("transactional job left %d committed event(s), want 0", count)
	}
}

func TestExecuteFlowJobHonorsTransactionCommit(t *testing.T) {
	app := newJobsTestApp(t)
	if _, err := app.DB.Exec("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)"); err != nil {
		t.Fatalf("create events: %v", err)
	}
	app.Flows = []Flow{{
		Name:        "atomic_job",
		Transaction: true,
		Steps: []FlowStep{
			{Type: "sql", SQL: "INSERT INTO events (name) VALUES ('committed')"},
		},
	}}

	if err := executeFlowJob(app, "atomic_job", map[string]any{}); err != nil {
		t.Fatalf("executeFlowJob: %v", err)
	}
	var count int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM events").Scan(&count); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if count != 1 {
		t.Fatalf("transactional job committed %d event(s), want 1", count)
	}
}

// TestExecuteFlowJobParallelSQLInTransaction exercises the combination a
// `parallel:` SQL block inside a `transaction: true` flow. *sql.Tx is not
// safe for concurrent use, so without serialization (FlowContext.TxMu) the
// fan-out goroutines race on the shared transaction. Run under `-race` to
// catch the data race; the functional assertion is that every branch's
// write commits exactly once.
func TestExecuteFlowJobParallelSQLInTransaction(t *testing.T) {
	app := newJobsTestApp(t)
	if _, err := app.DB.Exec("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)"); err != nil {
		t.Fatalf("create events: %v", err)
	}
	app.Flows = []Flow{{
		Name:        "parallel_atomic_job",
		Transaction: true,
		Steps: []FlowStep{{
			Type: "parallel",
			Steps: []FlowStep{
				{Type: "sql", SQL: "INSERT INTO events (name) VALUES ('a')"},
				{Type: "sql", SQL: "INSERT INTO events (name) VALUES ('b')"},
				{Type: "sql", SQL: "INSERT INTO events (name) VALUES ('c')"},
				{Type: "sql", SQL: "INSERT INTO events (name) VALUES ('d')"},
			},
		}},
	}}

	if err := executeFlowJob(app, "parallel_atomic_job", map[string]any{}); err != nil {
		t.Fatalf("executeFlowJob: %v", err)
	}
	var count int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM events").Scan(&count); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if count != 4 {
		t.Fatalf("parallel transactional job committed %d row(s), want 4", count)
	}
}

// TestJobStatusEndpointRequiresToken locks in the server-side contract the
// SDK status_url fix depends on the public /api/_jobs/{id}/status endpoint
// returns 404 for an anonymous caller WITHOUT the capability token and 200
// WITH it. Before the SDK fix, the handle polled the bare (token-less) path
// and always got 404 for non-admin callers.
func TestJobStatusEndpointRequiresToken(t *testing.T) {
	app := newJobsTestApp(t)
	mux := http.NewServeMux()
	RegisterJobsAPI(mux, app)

	id, token, err := EnqueueJob(app.DB, "worker", map[string]any{"k": "v"}, nil)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty status token")
	}

	// Without the token an anonymous caller must not be able to read status.
	reqNoToken := httptest.NewRequest("GET", fmt.Sprintf("/api/_jobs/%d/status", id), nil)
	recNoToken := httptest.NewRecorder()
	mux.ServeHTTP(recNoToken, reqNoToken)
	if recNoToken.Code != http.StatusNotFound {
		t.Fatalf("status without token = %d, want 404", recNoToken.Code)
	}

	// With the tokenized status_url the same caller gets the job status.
	reqToken := httptest.NewRequest("GET", fmt.Sprintf("/api/_jobs/%d/status?token=%s", id, token), nil)
	recToken := httptest.NewRecorder()
	mux.ServeHTTP(recToken, reqToken)
	if recToken.Code != http.StatusOK {
		t.Fatalf("status with token = %d, want 200", recToken.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(recToken.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode status body: %v", err)
	}
	if got, _ := body["job_id"].(float64); int64(got) != id {
		t.Fatalf("status body job_id = %v, want %d", body["job_id"], id)
	}
}

func newJobsTestApp(t *testing.T) *App {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	EnsureJobsTable(db)
	return &App{DB: db, Dir: t.TempDir(), Stop: make(chan struct{})}
}

func countJobs(t *testing.T, db *sql.DB) int {
	t.Helper()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM _benmore_jobs").Scan(&count); err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	return count
}
