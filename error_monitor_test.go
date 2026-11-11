//go:build !cli

package main

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestErrorMonitorValidation(t *testing.T) {
	for _, value := range []string{"true", "True", "{checkin_margin: 2, max_runtime: 10}", "{}"} {
		source := "sample:\n  schedule: '@daily'\n  sql: SELECT 1\n  monitor: " + value + "\n"
		cfg, err := parseCronYAML([]byte(source))
		if err != nil || cfg.Jobs[0].Monitor == nil {
			t.Fatalf("valid monitor %s: %v", value, err)
		}
		if msg := ValidateOnWriteIn("", "cron.yaml", source); msg != "" {
			t.Fatalf("write gate: %s", msg)
		}
	}
	cfg, err := parseCronYAML([]byte("sample:\n  schedule: '@daily'\n  sql: SELECT 1\n  monitor: false\n"))
	if err != nil || cfg.Jobs[0].Monitor != nil {
		t.Fatalf("monitor: false: %v", err)
	}
	if msg := ValidateOnWriteIn("", "cron.yaml", "sample:\n  schedule: '@daily'\n  sql: SELECT 1\n  monitor: false\n"); msg != "" {
		t.Fatalf("write gate refused monitor: false: %s", msg)
	}
	for _, value := range []string{"null", "yes", "3", "[]", "{unknown: 1}", "{checkin_margin: 0}", "{max_runtime: 1441}", "{max_runtime: 1.5}"} {
		source := "jobs:\n  - id: sample\n    schedule: '@daily'\n    sql: SELECT 1\n    monitor: " + value + "\n"
		_, err := parseCronYAML([]byte(source))
		if err == nil {
			t.Fatalf("accepted invalid monitor %s", value)
		}
		if msg := ValidateOnWriteIn("", "cron.yaml", source); !strings.Contains(msg, "monitor") {
			t.Fatalf("write gate ignored monitor: %s", msg)
		}
	}
	if got := cronMonitorSlug("My_App-dev", "Daily__Report!!"); !strings.HasPrefix(got, "my-app-daily-report-") {
		t.Fatalf("slug=%q", got)
	}
	if len(cronMonitorSlug(strings.Repeat("a", 60), "long")) > 50 {
		t.Fatal("slug too long")
	}
	if got := cronMonitorSchedule("every 90s"); got["type"] != "interval" || got["value"] != int64(2) || got["unit"] != "minute" {
		t.Fatalf("minute-tick interval: %+v", got)
	}
}

func TestErrorMonitorSourceWarning(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "cron.yaml", "sample:\n  schedule: '@daily'\n  sql: SELECT 1\n  monitor: true\n")
	report := RunSourceCheck(dir, "cron.yaml")
	for _, finding := range report.Findings {
		if strings.Contains(finding.Message, "monitor: true has no effect without SENTRY_DSN") && finding.Severity == "warning" {
			return
		}
	}
	t.Fatalf("missing no-DSN warning: %+v", report)
}

func TestErrorMonitorCheckIns(t *testing.T) {
	var mu sync.Mutex
	var checkins []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reader io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			defer gz.Close()
			reader = gz
		}
		b, _ := io.ReadAll(reader)
		lines := strings.Split(string(b), "\n")
		if len(lines) >= 3 && strings.Contains(lines[1], `"type":"check_in"`) {
			var item map[string]any
			if err := json.Unmarshal([]byte(lines[2]), &item); err != nil {
				t.Error(err)
			}
			mu.Lock()
			checkins = append(checkins, item)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	app := newJobsTestApp(t)
	t.Cleanup(func() { stopReportingTest(app) })
	storeAppEnv(app.Dir, map[string]string{"SENTRY_DSN": "https://monitor@93.184.216.34/1", "BENMORE_APP_NAME": "example-dev"})
	app.getErrorReporter().client = reportingTestClient(server)
	job := CronJob{ID: "daily", Schedule: "@daily", Monitor: &CronMonitor{CheckinMargin: 5, MaxRuntime: 30}, Steps: []FlowStep{{Type: "sql", SQL: "SELECT 1"}}}
	if err := runCronJob(app, job, nil); err != nil {
		t.Fatal(err)
	}
	job.Steps = []FlowStep{{Type: "sql", SQL: "SELECT * FROM missing_monitor_table"}}
	if err := runCronJob(app, job, nil); err == nil {
		t.Fatal("step failure lost")
	}
	flushReportingTest(t, app)
	stopReportingTest(app)
	app.mu.Lock()
	app.Stop = make(chan struct{})
	app.mu.Unlock()
	app.getErrorReporter().client = reportingTestClient(server)
	job.Steps = []FlowStep{{Type: "api", API: &FlowAPICall{Method: "POST", URL: "https://93.184.216.34/never-sent", JSON: map[string]any{"payload": reportingPanicJSON{}}}}}
	if err := runCronJob(app, job, nil); err == nil {
		t.Fatal("panic failure lost")
	}
	flushReportingTest(t, app)
	mu.Lock()
	observed := append([]map[string]any(nil), checkins...)
	mu.Unlock()
	if len(observed) != 6 {
		t.Fatalf("checkins=%v", observed)
	}
	for i, want := range []string{"in_progress", "ok", "in_progress", "error", "in_progress", "error"} {
		item := observed[i]
		if item["status"] != want || item["monitor_slug"] != cronMonitorSlug("example", "daily") {
			t.Fatalf("item=%v", item)
		}
		if (item["monitor_config"] != nil) != (i == 0) {
			t.Fatalf("config occurrence %d: %v", i, item)
		}
		if i%2 == 1 && (item["check_in_id"] != observed[i-1]["check_in_id"] || item["duration"] == nil) {
			t.Fatal("completion lost correlation/duration")
		}
	}
	storeAppEnv(app.Dir, map[string]string{})
	_ = runCronJob(app, job, nil)
	flushReportingTest(t, app)
	mu.Lock()
	defer mu.Unlock()
	if len(checkins) != 6 {
		t.Fatal("sent check-in without DSN")
	}
}

func TestErrorMonitorDistinctProductionSlugs(t *testing.T) {
	var slugs []string
	var mu sync.Mutex
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			defer gz.Close()
			body = gz
		}
		data, err := io.ReadAll(body)
		if err != nil {
			t.Error(err)
			return
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) != 3 {
			t.Errorf("envelope lines=%d", len(lines))
			return
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(lines[2]), &payload); err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		slugs = append(slugs, payload["monitor_slug"].(string))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()
	app := errorGroupsFixture(t)
	defer close(app.Stop)
	r := &errorReporter{app: app, client: reportingTestClient(sink), now: time.Now, limiter: NewRateLimiterStoppable(30, time.Minute, app.Stop)}
	for _, name := range []string{"customer-one", "customer-two", "customer-one"} {
		storeAppEnv(app.Dir, map[string]string{"BENMORE_APP_NAME": name, "SENTRY_DSN": "https://monitor@93.184.216.34/1"})
		r.sendCheckIn(t.Context(), &cronCheckIn{ID: newSentryEventID(), Status: "in_progress", Job: CronJob{ID: "daily", Schedule: "@daily", Monitor: &CronMonitor{CheckinMargin: 5, MaxRuntime: 30}}})
	}
	mu.Lock()
	defer mu.Unlock()
	if len(slugs) != 3 || slugs[0] == slugs[1] || slugs[0] != slugs[2] {
		t.Fatalf("monitor identities collapsed or unstable: %v", slugs)
	}
	for _, slug := range slugs {
		if strings.Contains(slug, "customer-") || strings.Contains(slug, "redacted") {
			t.Fatalf("private identity must remain distinct and opaque: %q", slug)
		}
	}
}

// Anyone can post browser reports; spending their whole delivery budget must
// leave cron check-ins and server events deliverable (review errors-b F2).
func TestErrorCheckInsSurviveBrowserFlood(t *testing.T) {
	var delivered atomic.Int64
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delivered.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()
	app := errorGroupsFixture(t)
	defer close(app.Stop)
	storeAppEnv(app.Dir, map[string]string{"SENTRY_DSN": "https://monitor@93.184.216.34/1"})
	r := &errorReporter{app: app, client: reportingTestClient(sink), now: time.Now, limiter: NewRateLimiterStoppable(30, time.Minute, app.Stop)}
	for r.allow(errorBudget("forward", "client")) {
	}
	if result := r.sendEvent(t.Context(), errorEvent{Source: "client", Level: "error", Message: "flood"}); result.OK {
		t.Fatal("browser budget was not spent")
	}
	job := CronJob{ID: "every-minute", Schedule: "* * * * *", Monitor: &CronMonitor{CheckinMargin: 5, MaxRuntime: 30}}
	for i := 0; i < 20; i++ {
		r.sendCheckIn(t.Context(), &cronCheckIn{ID: newSentryEventID(), Status: "ok", Job: job})
	}
	r.sendEvent(t.Context(), errorEvent{Source: "server", Level: "error", Message: "real failure"})
	if got := delivered.Load(); got != 21 {
		t.Fatalf("delivered %d of 20 check-ins and 1 server event after a browser flood", got)
	}
}
