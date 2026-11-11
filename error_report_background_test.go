//go:build !cli

package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type reportingPanicJSON struct{}

func (reportingPanicJSON) MarshalJSON() ([]byte, error) { panic("cron marshal crash") }

func TestErrorReportBackgroundFailures(t *testing.T) {
	app := newJobsTestApp(t)
	t.Cleanup(func() { stopReportingTest(app) })
	if err := ensureErrorGroups(app.DB); err != nil {
		t.Fatal(err)
	}
	const kind = "error_reporting_failed_job"
	testJobExecutors[kind] = func(*App, string, map[string]any) error { return errors.New("final job failure") }
	t.Cleanup(func() { delete(testJobExecutors, kind) })
	if _, err := app.DB.Exec(`INSERT INTO _benmore_jobs(job_type,flow_name,payload,status,run_at,max_attempts) VALUES(?, 'test', '{}','pending',datetime('now'),3)`, kind); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		if !processNextJob(app) {
			t.Fatalf("attempt %d did not execute", attempt)
		}
		flushReportingTest(t, app)
		want := 0
		if attempt == 3 {
			want = 1
		}
		assertCount(t, app, "SELECT count(*) FROM _benmore_error_groups WHERE kind='job'", want)
		mustExec(t, app.DB, "UPDATE _benmore_jobs SET not_before=NULL")
	}
	job := CronJob{ID: "panic-test", Steps: []FlowStep{{Type: "api", API: &FlowAPICall{Method: "POST", URL: "https://93.184.216.34/never-sent", JSON: map[string]any{"payload": reportingPanicJSON{}}}}}}
	if err := runCronJob(app, job, nil); err == nil {
		t.Fatal("cron panic was not recovered as failure")
	}
	flushReportingTest(t, app)
	assertCount(t, app, "SELECT count(*) FROM _benmore_error_groups WHERE kind='cron' AND level='fatal'", 1)
	// Through the job worker a failed cron run is still one report: the
	// cron's own, never a second job_failed group.
	mustExec(t, app.DB, "DELETE FROM _benmore_error_groups")
	app.Cron = &CronConfig{Jobs: []CronJob{job}}
	if _, err := app.DB.Exec(`INSERT INTO _benmore_jobs(job_type,flow_name,payload,status,run_at,max_attempts) VALUES('cron', ?, '{}','pending',datetime('now'),1)`, job.ID); err != nil {
		t.Fatal(err)
	}
	if !processNextJob(app) {
		t.Fatal("cron job did not execute")
	}
	flushReportingTest(t, app)
	assertCount(t, app, "SELECT count(*) FROM _benmore_error_groups WHERE kind='cron'", 1)
	assertCount(t, app, "SELECT count(*) FROM _benmore_error_groups WHERE kind='job'", 0)
	_ = executeHookResult(app, Hook{SQL: "SELECT private_sql_text FROM absent", reportEvent: "insert"}, "items", nil)
	flushReportingTest(t, app)
	assertCount(t, app, "SELECT count(*) FROM _benmore_error_groups WHERE kind='hook' AND level='warning' AND sample NOT LIKE '%private_sql_text%'", 1)
}

func TestErrorReportAccountPurgeClearsOnlyOwnedSample(t *testing.T) {
	app, cleanup := newPurgeTestApp(t)
	defer cleanup()
	insertPurgeUser(t, app, 1, "one@example.com")
	insertPurgeUser(t, app, 2, "two@example.com")
	if err := ensureErrorGroups(app.DB); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{1, 2} {
		ev := errorEvent{Source: "client", Kind: "error", Type: strings.Repeat("x", int(id)), Message: "saved sample", UserID: id}
		if _, _, err := recordGroup(app, ev); err != nil {
			t.Fatal(err)
		}
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(entered); <-release })
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()
	defer stopReportingTest(app)
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	storeAppEnv(app.Dir, map[string]string{"SENTRY_DSN": "https://purge@93.184.216.34/1"})
	app.getErrorReporter().client = reportingTestClient(sink)
	reportError(app, errorEvent{Source: "server", Level: "error", Message: "blocked delivery"})
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("delivery did not start")
	}
	reportError(app, errorEvent{Source: "client", Kind: "error", Message: "queued sensitive sample", UserID: 1})
	sessionID := CreateSession(app.DB, 1, "one@example.com", "", time.Hour)
	flow := &Flow{Name: "account-delete", Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/account-delete"}, Auth: "required", Transaction: true,
		Steps: []FlowStep{{Name: "purge", Type: "purge_current_user", PurgeCurrentUserConfirm: "{{confirm}}"}, {Type: "respond", Respond: &FlowRespond{Status: 200, JSON: map[string]any{"deleted": true}}}}}
	req := httptest.NewRequest(http.MethodPost, "/api/account-delete", strings.NewReader(`{"confirm":"DELETE"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionID)
	w := httptest.NewRecorder()
	executeFlowHTTP(app, flow, w, req)
	if w.Code != 200 {
		t.Fatalf("purge %d: %s", w.Code, w.Body.String())
	}
	assertCount(t, app, "SELECT count(*) FROM _benmore_error_groups WHERE sample IS NULL AND sample_user_id IS NULL AND message IS NULL AND last_request_id IS NULL", 1)
	assertCount(t, app, "SELECT count(*) FROM _benmore_error_groups WHERE sample IS NOT NULL AND sample_user_id=2", 1)
	close(release)
	flushReportingTest(t, app)
	assertCount(t, app, "SELECT count(*) FROM _benmore_error_groups WHERE sample_user_id=1 OR sample LIKE '%queued sensitive sample%'", 0)
}
