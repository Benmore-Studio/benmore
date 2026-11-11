//go:build !cli

package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// jobErrorRedactToken stands in for a partner API token held in the app's env.
const jobErrorRedactToken = "r1104-outbound-token-ABCDEF123456"

// jobErrorRedactApp is an app with the jobs API, an admin session and the
// partner token in its env. The flow's host is unresolvable, so its api step
// stops at the SSRF guard with the whole URL in the error, as an upstream
// 404 does, without reaching the network.
func jobErrorRedactApp(t *testing.T) (*App, *http.ServeMux, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db, Stop: make(chan struct{})}
	t.Cleanup(app.Shutdown)
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	EnsureJobsTable(db)
	mustExec(t, db, `INSERT INTO _benmore_users (id, username, email, role) VALUES (1, 'admin', 'admin@test.com', 'admin')`)
	sid := CreateSession(db, 1, "admin@test.com", "", time.Hour)
	SetAppEnv(dir, "PARTNER_API_TOKEN", jobErrorRedactToken)
	mux := http.NewServeMux()
	RegisterJobsAPI(mux, app)
	return app, mux, sid
}

// jobErrorSecrets are the forms of the token a failure text must not carry:
// the env value and a value an earlier step derived from it.
func jobErrorSecrets() []string {
	return []string{jobErrorRedactToken, base64.StdEncoding.EncodeToString([]byte(jobErrorRedactToken)), "ABCDEF123456"}
}

func checkJobErrorRedacted(t *testing.T, surface, text string) {
	t.Helper()
	checkJobErrorRedactedHost(t, surface, text, "partner.invalid")
}

func checkJobErrorRedactedHost(t *testing.T, surface, text, host string) {
	t.Helper()
	for _, secret := range jobErrorSecrets() {
		if strings.Contains(text, secret) {
			t.Errorf("%s carries the secret %q:\n%s", surface, secret, text)
		}
	}
	if !strings.Contains(text, host) || !strings.Contains(text, "[redacted]") {
		t.Errorf("%s lost the error's useful detail:\n%s", surface, text)
	}
}

func getJobJSON(t *testing.T, mux *http.ServeMux, path, sid string) map[string]any {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if sid != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	var out map[string]any
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatalf("GET %s: %d %s", path, w.Code, w.Body.String())
	}
	return out
}

// A public `mode: async` flow whose `run: api` URL carried an env token in
// its path and query failed in the worker. The anonymous caller's status_url
// answer, GET /api/_jobs and the journal's JOB RETRY / JOB FAILED lines
// showed the raw token, although the synchronous path and an on_error
// handler's `${{ error }}` redact it (round 2026-11-04, hooks finding 1).
func TestAsyncFlowJobErrorIsRedacted(t *testing.T) {
	app, mux, sid := jobErrorRedactApp(t)
	// The partner answers 503, a failure a later run can change, and the flow
	// opts in to retries (async flow jobs run once by default), so the job
	// takes the retry branch first and the failed branch last.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"ok":false}`))
	}))
	t.Cleanup(upstream.Close)
	savedTransport := strictOutboundTransport
	strictOutboundTransport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", upstream.Listener.Addr().String())
	}}
	t.Cleanup(func() { strictOutboundTransport = savedTransport })
	const partnerHost = "93.184.216.34"
	flow := Flow{Name: "partner_status", Auth: "none", Async: true, MaxAttempts: 3,
		Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/partner-status"},
		Steps: []FlowStep{
			{Name: "auth", Type: "set", Set: map[string]string{"sig": "{{ env.PARTNER_API_TOKEN | base64 }}"}},
			{Name: "call", Type: "api", API: &FlowAPICall{Method: "GET",
				URL: "http://" + partnerHost + "/v1/{{sig}}/status/503/{{env.PARTNER_API_TOKEN}}?key={{env.PARTNER_API_TOKEN}}"}},
		}}
	app.Flows = []Flow{flow}
	checkJobErrorRedacted := func(t *testing.T, surface, text string) {
		t.Helper()
		checkJobErrorRedactedHost(t, surface, text, partnerHost)
	}

	r := httptest.NewRequest(http.MethodPost, "/api/partner-status", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	if err := executeFlowHTTP(app, &flow, w, r); err != nil || w.Code != http.StatusAccepted {
		t.Fatalf("enqueue: %d %v %s", w.Code, err, w.Body.String())
	}
	var queued struct {
		JobID     int64  `json:"job_id"`
		StatusURL string `json:"status_url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &queued); err != nil || queued.StatusURL == "" {
		t.Fatalf("202 answer: %s (%v)", w.Body.String(), err)
	}

	// First attempt: the job goes back to pending with its error stored.
	logs := captureLog(t, func() {
		if !processNextJob(app) {
			t.Fatal("no job was claimed")
		}
	})
	if !strings.Contains(logs, "JOB RETRY") {
		t.Fatalf("first attempt did not retry:\n%s", logs)
	}
	checkJobErrorRedacted(t, "JOB RETRY journal line", logs)

	var stored, status string
	if err := app.DB.QueryRow("SELECT COALESCE(error,''), status FROM _benmore_jobs WHERE id = ?", queued.JobID).Scan(&stored, &status); err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		t.Fatalf("status after the first attempt = %q, want pending", status)
	}
	checkJobErrorRedacted(t, "stored retry error", stored)

	statusURL, err := url.Parse(queued.StatusURL)
	if err != nil {
		t.Fatal(err)
	}
	polled := getJobJSON(t, mux, statusURL.RequestURI(), "")
	checkJobErrorRedacted(t, "anonymous status_url answer", fmt.Sprint(polled["error"]))

	// Last attempt: the job fails for good.
	mustExec(t, app.DB, fmt.Sprintf("UPDATE _benmore_jobs SET not_before = NULL, attempts = max_attempts - 1 WHERE id = %d", queued.JobID))
	logs = captureLog(t, func() {
		if !processNextJob(app) {
			t.Fatal("the retry was not claimed")
		}
	})
	if !strings.Contains(logs, "JOB FAILED") {
		t.Fatalf("last attempt did not fail:\n%s", logs)
	}
	checkJobErrorRedacted(t, "JOB FAILED journal line", logs)
	if err := app.DB.QueryRow("SELECT COALESCE(error,''), status FROM _benmore_jobs WHERE id = ?", queued.JobID).Scan(&stored, &status); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("status after the last attempt = %q, want failed", status)
	}
	checkJobErrorRedacted(t, "stored failed error", stored)

	polled = getJobJSON(t, mux, statusURL.RequestURI(), "")
	checkJobErrorRedacted(t, "anonymous status_url answer (failed)", fmt.Sprint(polled["error"]))
	one := getJobJSON(t, mux, fmt.Sprintf("/api/_jobs/%d", queued.JobID), sid)
	checkJobErrorRedacted(t, "GET /api/_jobs/{id}", fmt.Sprint(one["error"]))
	list := getJobJSON(t, mux, "/api/_jobs", sid)
	listed, _ := json.Marshal(list["jobs"])
	checkJobErrorRedacted(t, "GET /api/_jobs", string(listed))
}

// A job row written before the fix keeps its raw error. Reading it back
// (status_url, GET /api/_jobs, GET /api/_jobs/{id}) redacts the app's env
// values and credential-shaped text the same way.
func TestJobErrorReadsRedactStoredSecrets(t *testing.T) {
	app, mux, sid := jobErrorRedactApp(t)
	id, token, err := EnqueueJob(app.DB, "partner_status", map[string]any{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := "SECURITY: blocked API request to private URL: https://partner.invalid/status/404/" + jobErrorRedactToken + "?key=" + jobErrorRedactToken
	if _, err := app.DB.Exec("UPDATE _benmore_jobs SET status = 'failed', error = ? WHERE id = ?", raw, id); err != nil {
		t.Fatal(err)
	}
	polled := getJobJSON(t, mux, fmt.Sprintf("/api/_jobs/%d/status?token=%s", id, token), "")
	checkJobErrorRedacted(t, "status_url answer", fmt.Sprint(polled["error"]))
	one := getJobJSON(t, mux, fmt.Sprintf("/api/_jobs/%d", id), sid)
	checkJobErrorRedacted(t, "GET /api/_jobs/{id}", fmt.Sprint(one["error"]))
	list := getJobJSON(t, mux, "/api/_jobs", sid)
	listed, _ := json.Marshal(list["jobs"])
	checkJobErrorRedacted(t, "GET /api/_jobs", string(listed))
}

// Cron runs and data-event flows log their step failure to the journal; a
// queued cron job also stores it. Both carried the raw URL.
func TestCronAndEventFlowErrorsAreRedacted(t *testing.T) {
	app, _, _ := jobErrorRedactApp(t)
	call := FlowStep{Name: "call", Type: "api", API: &FlowAPICall{Method: "GET",
		URL: "https://partner.invalid/status/404/{{env.PARTNER_API_TOKEN}}?key={{env.PARTNER_API_TOKEN}}"}}

	var cronErr error
	logs := captureLog(t, func() {
		cronErr = runCronJob(app, CronJob{ID: "partner_sync", Steps: []FlowStep{call}}, nil)
	})
	if cronErr == nil {
		t.Fatal("cron run did not fail")
	}
	checkJobErrorRedacted(t, "cron error", cronErr.Error())
	checkJobErrorRedacted(t, "cron journal line", logs)

	app.Flows = []Flow{{Name: "partner_tx", Transaction: true, Steps: []FlowStep{call}}}
	logs = captureLog(t, func() {
		cronErr = runCronJob(app, CronJob{ID: "partner_sync_tx", Flow: "partner_tx"}, nil)
	})
	if cronErr == nil {
		t.Fatal("transactional cron run did not fail")
	}
	checkJobErrorRedacted(t, "transactional cron error", cronErr.Error())
	checkJobErrorRedacted(t, "transactional cron journal line", logs)

	event := Flow{Name: "on_order", Trigger: FlowTrigger{Type: "on_insert", Table: "orders"}, Steps: []FlowStep{call}}
	logs = captureLog(t, func() {
		runFlowEventWith(app, event, map[string]any{"id": 1}, nil)
	})
	if !strings.Contains(logs, "FLOW ERROR [on_order]") {
		t.Fatalf("event flow did not log its failure:\n%s", logs)
	}
	checkJobErrorRedacted(t, "event flow journal line", logs)
}

// A scheduled flow's failure was logged raw on the SCHEDULE line next to the
// flow's own redacted FLOW ERROR line.
func TestScheduledFlowFailureLogIsRedacted(t *testing.T) {
	app, mux := auditApp(t)
	SetAppEnv(app.Dir, "PARTNER_API_TOKEN", jobErrorRedactToken)
	sid := createCrudScopeSession(t, app, "delegate@example.com", "user", "a", "")
	auditExec(t, app.DB, "INSERT INTO members(org_id,email) VALUES ('a','delegate@example.com')")
	app.Flows = []Flow{{Name: "partner_sync", Auth: "required", Trigger: FlowTrigger{Type: "http", Method: "POST"},
		Steps: []FlowStep{{Name: "call", Type: "api", API: &FlowAPICall{Method: "GET",
			URL: "https://partner.invalid/status/404/{{env.PARTNER_API_TOKEN}}?key={{env.PARTNER_API_TOKEN}}"}}}}}
	if w := auditPost(mux, sid, "/api/_scheduled", "", `{"kind":"flow","flow":"partner_sync","run_at":"2000-01-01T00:00:00Z"}`, true); w.Code != 200 {
		t.Fatalf("schedule failed: %d %s", w.Code, w.Body.String())
	}
	logs := captureLog(t, func() { sweepScheduledTasks(app) })
	if !strings.Contains(logs, "SCHEDULE failed") {
		t.Fatalf("the scheduled flow did not fail:\n%s", logs)
	}
	checkJobErrorRedacted(t, "SCHEDULE journal line", logs)
}
