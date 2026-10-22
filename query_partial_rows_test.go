//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
)

// QueryRows returns the rows it read before a failure together with the
// error (a deadline, or a row whose value cannot be computed). Callers that
// dropped the error showed or acted on those rows as if they were all.
//
// The fixtures make one row unreadable with a VIRTUAL generated column that
// raises "malformed JSON" only for that row's state, so a scan stops there.

func partialRowsApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db}
	t.Cleanup(app.Shutdown)
	EnsureSessionsTable(db)
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureAuditLogTable(db)
	EnsureLocksTable(db)
	EnsureJobsTable(db)
	return app
}

func TestAnalyticsSummaryFailsInsteadOfReturningPartialData(t *testing.T) {
	app := partialRowsApp(t)
	EnsureAnalyticsTables(app.DB)
	mustExec(t, app.DB, `INSERT INTO _benmore_users (id, username, email, role) VALUES (1, 'admin', 'admin@test.com', 'admin')`)
	sid := CreateSession(app.DB, 1, "admin@test.com", "", time.Hour)
	mux := http.NewServeMux()
	RegisterAnalyticsRoutes(mux, app)

	withTestQueryDeadline(t, time.Nanosecond)
	req := httptest.NewRequest("GET", "/api/_analytics/summary", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("summary with failed breakdown queries: %d %s, want 503", rec.Code, rec.Body.String())
	}
}

func TestAdminPagesReportFailedReadsInsteadOfPartialRows(t *testing.T) {
	app := partialRowsApp(t)
	mustExec(t, app.DB, `CREATE TABLE orders (id INTEGER PRIMARY KEY, name TEXT, status TEXT)`)
	mustExec(t, app.DB, `INSERT INTO orders (id, name, status) VALUES (1, 'row-one', 'ok'), (2, 'row-two', 'broken'), (3, 'row-three', 'ok')`)
	mustExec(t, app.DB, `CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT)`)
	mustExec(t, app.DB, `INSERT INTO customers (id, name) VALUES (7, 'Ada')`)
	mustExec(t, app.DB, `CREATE TABLE notes (id INTEGER PRIMARY KEY, customer_id INTEGER, body TEXT, status TEXT)`)
	mustExec(t, app.DB, `INSERT INTO notes (id, customer_id, body, status) VALUES (1, 7, 'note-one', 'broken'), (2, 7, 'note-two', 'ok')`)
	// Added after the rows exist, so only reading a broken row fails.
	for _, table := range []string{"orders", "notes"} {
		mustExec(t, app.DB, `ALTER TABLE `+table+` ADD COLUMN bad TEXT GENERATED ALWAYS AS (CASE WHEN status = 'broken' THEN json_extract('x', '$') END) VIRTUAL`)
	}
	app.Tables = []Table{
		{Name: "orders", Columns: []Column{{Name: "id", PK: true}, {Name: "name"}, {Name: "status"}}},
		{Name: "customers", Columns: []Column{{Name: "id", PK: true}, {Name: "name"}}},
		{Name: "notes", Columns: []Column{{Name: "id", PK: true}, {Name: "customer_id"}, {Name: "body"}, {Name: "status"}}},
	}

	// ORDER BY id DESC reads row-three, then fails on row-two.
	rec := httptest.NewRecorder()
	serveAdminTable(rec, httptest.NewRequest("GET", "/_admin/orders", nil), app, "orders")
	page := rec.Body.String()
	if strings.Contains(page, "row-three") || !strings.Contains(page, "Could not load") {
		t.Errorf("table page showed the rows before the failure as the whole list (row-three shown=%v)", strings.Contains(page, "row-three"))
	}

	rec = httptest.NewRecorder()
	serveAdminDetail(rec, httptest.NewRequest("GET", "/_admin/customers/7", nil), app, "customers", "7")
	if page := rec.Body.String(); !strings.Contains(page, "Could not load") {
		t.Errorf("detail page hid the failed related-rows read")
	}

	// The dashboard must surface failures from both recent-list reads. A
	// nanosecond deadline is timing-dependent: a tiny query can finish before
	// cancellation is observed. Closing the DB makes both reads fail reliably;
	// the table/detail cases above separately exercise partial-row failures.
	mustExec(t, app.DB, `INSERT INTO _benmore_users (id, username, email, role) VALUES (1, 'admin', 'admin@test.com', 'admin')`)
	if err := app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	serveAdminDashboard(rec, httptest.NewRequest("GET", "/_admin", nil), app)
	if page := rec.Body.String(); strings.Contains(page, "No users yet.") || strings.Contains(page, "No activity recorded yet.") || strings.Count(page, "Could not load") < 2 {
		t.Errorf("dashboard reported failed reads as empty lists")
	}
}

// partialRowsArmDriver is the framework driver plus test_arm_query_deadline(),
// which makes every later QueryRows statement miss its deadline. A
// transition `when:` calls it, so the transition's first read succeeds and
// the read after the UPDATE fails.
var partialRowsArmDriver sync.Once

func openArmDeadlineApp(t *testing.T) *App {
	t.Helper()
	partialRowsArmDriver.Do(func() {
		base := benmoreSQLiteDriver(true)
		sql.Register("sqlite3_benmore_arm_deadline", &sqlite3.SQLiteDriver{ConnectHook: func(c *sqlite3.SQLiteConn) error {
			if err := base.ConnectHook(c); err != nil {
				return err
			}
			return c.RegisterFunc("test_arm_query_deadline", func() int64 {
				queryDeadlineValue = time.Nanosecond
				return 1
			}, false)
		}})
	})
	withTestQueryDeadline(t, time.Minute)
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore_arm_deadline", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db}
	t.Cleanup(app.Shutdown)
	EnsureSessionsTable(db)
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureAuditLogTable(db)
	EnsureLocksTable(db)
	EnsureJobsTable(db)
	return app
}

// Workflow reads after validation share the mutation transaction, whose
// lifetime is request-bound rather than using the standalone query deadline.
// Hook jobs must still capture the committed target state.
func TestWorkflowTransitionReadsAndHooksShareTransaction(t *testing.T) {
	app := openArmDeadlineApp(t)
	EnsureWebhooksTable(app.DB)
	mustExec(t, app.DB, `CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, status TEXT)`)
	app.Tables = []Table{{Name: "orders", Columns: []Column{{Name: "id", PK: true}, {Name: "user_id"}, {Name: "status"}}}}
	wf := &Workflow{Name: "orders", Table: "orders", Field: "status", Initial: "pending",
		States:      []string{"pending", "approved"},
		Transitions: map[string]map[string]Transition{"pending": {"approved": {When: "test_arm_query_deadline() = 1"}}},
	}
	app.Workflows = &WorkflowConfig{Workflows: map[string]*Workflow{"orders": wf}}
	app.Hooks = &HookConfig{OnUpdate: map[string][]Hook{"orders": {{Webhook: "https://hooks.example.com/x"}}}}
	uid := workflowTestUser(t, app, "a@example.com")
	if _, err := app.DB.Exec(`UPDATE _benmore_users SET role = 'admin' WHERE id = ?`, uid); err != nil {
		t.Fatal(err)
	}
	sid := CreateSession(app.DB, uid, "a@example.com", "", time.Hour)
	if _, err := app.DB.Exec(`INSERT INTO orders (id, user_id, status) VALUES (1, ?, 'pending')`, uid); err != nil {
		t.Fatal(err)
	}

	rec := transitionAs(app, wf, sid, "1", "approved")
	if rec.Code != http.StatusOK {
		t.Fatalf("transition: %d %s", rec.Code, rec.Body.String())
	}
	var payload string
	if err := app.DB.QueryRow(`SELECT payload FROM _benmore_jobs WHERE job_type = 'hook'`).Scan(&payload); err != nil {
		t.Fatalf("no update hook job: %v", err)
	}
	var job struct {
		Row map[string]any `json:"_row"`
	}
	json.Unmarshal([]byte(payload), &job)
	if job.Row["status"] != "approved" {
		t.Fatalf("update hook saw status %v, want approved (payload %s)", job.Row["status"], payload)
	}
}

// A timeout whose row cannot be read is left for the next sweep instead of
// being applied with no hooks.
func TestWorkflowTimeoutSkipsRowItCannotRead(t *testing.T) {
	app := partialRowsApp(t)
	mustExec(t, app.DB, `CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, status TEXT, updated_at DATETIME)`)
	mustExec(t, app.DB, `INSERT INTO orders (id, status, updated_at) VALUES (1, 'pending', '2000-01-01 00:00:00')`)
	mustExec(t, app.DB, `ALTER TABLE orders ADD COLUMN bad TEXT GENERATED ALWAYS AS (CASE WHEN status = 'pending' THEN json_extract('x', '$') END) VIRTUAL`)
	app.Tables = []Table{{Name: "orders", Columns: []Column{{Name: "id", PK: true}, {Name: "status"}, {Name: "updated_at"}}}}
	wf := &Workflow{Name: "orders", Table: "orders", Field: "status", Initial: "pending",
		States:   []string{"pending", "expired"},
		Timeouts: map[string]WorkflowTimeout{"pending": {After: time.Second, To: "expired"}},
	}
	checkWorkflowTimeouts(app, wf)
	var status string
	if err := app.DB.QueryRow(`SELECT status FROM orders WHERE id = 1`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		t.Fatalf("timeout applied to a row whose hooks could not be built: status=%s", status)
	}
}
