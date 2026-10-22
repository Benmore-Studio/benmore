//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// A connector-command effect job that failed (blocked, or an unknown
// delivery outcome) is never re-run: a blind replay could send a webhook or
// transfer twice. The admin retry endpoint used to flip any failed job back
// to pending, effect jobs included. Other failed jobs still retry.
func TestJobRetryRefusesConnectorEffectJobs(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db}
	t.Cleanup(app.Shutdown)
	EnsureUsersTable(db)
	EnsureSessionsTable(db)
	EnsureJobsTable(db)
	mustExec(t, db, `INSERT INTO _benmore_users (id, username, email, role) VALUES (1, 'admin', 'admin@test.com', 'admin')`)
	sid := CreateSession(db, 1, "admin@test.com", "", time.Hour)
	mustExec(t, db, `INSERT INTO _benmore_jobs (id, job_type, flow_name, status, error, payload) VALUES
		(1, 'hook', 'hook', 'failed', 'unknown: webhook response was not confirmed', '{"_hook":{"webhook":"https://hooks.example.invalid/x"},"_row":{"id":1},"_mcp_effect":{"grant_id":"g","operation_id":"op"}}'),
		(2, 'hook', 'hook', 'failed', 'webhook returned 500', '{"_hook":{"webhook":"https://hooks.example.invalid/x"},"_row":{"id":1}}'),
		(3, 'flow', 'f', 'failed', 'boom', NULL)`)

	mux := http.NewServeMux()
	RegisterJobsAPI(mux, app)
	retry := func(id string) int {
		req := httptest.NewRequest("POST", "/api/_jobs/"+id+"/retry", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		req.Header.Set("X-CSRF-Token", authMintCSRFToken(sid))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	status := func(id int) string {
		var s string
		db.QueryRow(`SELECT status FROM _benmore_jobs WHERE id = ?`, id).Scan(&s)
		return s
	}
	if code := retry("1"); code != http.StatusConflict || status(1) != "failed" {
		t.Fatalf("retry of a connector effect job: %d, status %s; want 409 and still failed", code, status(1))
	}
	for _, id := range []int{2, 3} {
		if code := retry(map[int]string{2: "2", 3: "3"}[id]); code != http.StatusOK || status(id) != "pending" {
			t.Fatalf("retry of ordinary failed job %d: %d, status %s", id, code, status(id))
		}
	}
}
