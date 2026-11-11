//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Slack has its own per-app budget (errorBudget), separate from Sentry's.
func TestErrorReportSlackHasItsOwnLimit(t *testing.T) {
	var delivered atomic.Int64
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { delivered.Add(1); w.WriteHeader(http.StatusOK) }))
	defer sink.Close()
	app := errorGroupsFixture(t)
	defer close(app.Stop)
	storeAppEnv(app.Dir, map[string]string{"ERROR_SLACK_WEBHOOK": "https://93.184.216.34/slack"})
	r := &errorReporter{app: app, client: reportingTestClient(sink), now: time.Now, limiter: NewRateLimiterStoppable(30, time.Minute, app.Stop)}
	for i := 0; i < 40; i++ {
		r.process(t.Context(), errorEvent{Source: "client", Kind: "error", Level: "error", Type: fmt.Sprintf("failure_%d", i), Message: "distinct browser failure"})
	}
	if got := delivered.Load(); got != 30 {
		t.Fatalf("Slack deliveries=%d, want 30", got)
	}
	if got := r.counters.throttled.Load(); got != 10 {
		t.Fatalf("throttled=%d, want 10", got)
	}
}

func TestErrorReportMetadataExportsConfiguredNames(t *testing.T) {
	app := errorGroupsFixture(t)
	ev := errorEvent{Source: "server", Kind: "test", Level: "error", Message: "failure"}
	event := func(name, published, environment, release string) map[string]any {
		storeAppEnv(app.Dir, map[string]string{"BENMORE_APP_NAME": name, "BENMORE_PUBLISHED_AT": published, "SENTRY_ENVIRONMENT": environment, "SENTRY_RELEASE": release})
		return errorSentryEvent(app, ev, time.Now())
	}
	one := event("customer-one", "2026-10-27T12:00:00Z", "production", "")
	two := event("customer-two", "2026-10-27T12:00:00Z", "production", "")
	if one["tags"].(map[string]string)["app"] == two["tags"].(map[string]string)["app"] {
		t.Fatal("production app identities collapsed")
	}
	next := event("customer-one", "2026-10-27T13:00:00Z", "production", "")
	if one["release"] == next["release"] {
		t.Fatal("successive deployment releases collapsed")
	}
	if one["environment"] != "production" || next["environment"] != "production" {
		t.Fatalf("configured environment not exported as is: %v", one["environment"])
	}
	// The release and environment the owner configures are names Sentry
	// matches on (source maps, release health), never hashed.
	custom := event("customer-one", "", "staging-east", "web@1.4.2-first")
	if custom["environment"] != "staging-east" || custom["release"] != "web@1.4.2-first" {
		t.Fatalf("configured names hashed: %v %v", custom["environment"], custom["release"])
	}
	// The app's own name stays private: the app tag and the default release
	// (<subdomain>@<published>) carry it, so they keep an opaque identity.
	for _, got := range []string{one["tags"].(map[string]string)["app"], one["release"].(string)} {
		if strings.Contains(got, "customer-one") || strings.Contains(got, "[redacted:env]") {
			t.Fatalf("identity did not preserve private distinction: %q", got)
		}
	}
	if got := scrubForExport(app, "customer-one staging-east web@1.4.2-first"); got != "[redacted:env] staging-east web@1.4.2-first" {
		t.Fatalf("scrubbing: %q", got)
	}
}

// A wedged database is what the owner configured Sentry and Slack for: the
// export goes out even when the local group cannot be written, and a group
// table that could not be created is retried rather than stopping the worker.
func TestErrorReportExportsWhenLocalWriteFails(t *testing.T) {
	var delivered atomic.Int64
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { delivered.Add(1); w.WriteHeader(http.StatusOK) }))
	defer sink.Close()
	app := errorGroupsFixture(t)
	defer close(app.Stop)
	storeAppEnv(app.Dir, map[string]string{"SENTRY_DSN": "https://k@93.184.216.34/1", "ERROR_SLACK_WEBHOOK": "https://93.184.216.34/slack"})
	working := app.DB
	broken, err := sql.Open("sqlite3", filepath.Join(app.Dir, "broken.db"))
	if err != nil {
		t.Fatal(err)
	}
	broken.Close()
	app.DB = broken
	r := &errorReporter{app: app, client: reportingTestClient(sink), now: time.Now, lastReport: map[string]int64{}, limiter: NewRateLimiterStoppable(30, time.Minute, app.Stop)}
	r.ensureTable(t.Context())
	if r.tableReady {
		t.Fatal("table creation on a closed database reported success")
	}
	r.process(t.Context(), errorEvent{Source: "server", Kind: "server", Level: "error", Type: "db_locked", Message: "database is locked"})
	if got := delivered.Load(); got != 2 {
		t.Fatalf("deliveries with a failing local write=%d, want Sentry and Slack", got)
	}
	app.DB = working
	r.process(t.Context(), errorEvent{Source: "server", Kind: "server", Level: "warning", Type: "recovered", Message: "later"})
	if !r.tableReady {
		t.Fatal("group table was not retried")
	}
	assertCount(t, app, "SELECT count(*) FROM _benmore_error_groups WHERE type='recovered'", 1)
}

// A sibling tenant is same-site: its page could make a signed-in visitor's
// browser post here with the session cookie and file reports as that user.
func TestErrorCaptureRefusesForeignOriginWithSession(t *testing.T) {
	app := errorGroupsFixture(t)
	defer stopReportingTest(app)
	mux := http.NewServeMux()
	RegisterErrorCaptureRoute(mux, app)
	post := func(origin string, cookie bool) int {
		req := httptest.NewRequest(http.MethodPost, "/api/_errors", strings.NewReader(`{"message":"boom"}`))
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if cookie {
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "victim"})
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w.Code
	}
	for _, c := range []struct {
		origin string
		cookie bool
		want   int
	}{
		{"https://evil.example", true, http.StatusForbidden},
		{"http://example.com", true, http.StatusNoContent},
		{"", true, http.StatusNoContent},
		{"https://evil.example", false, http.StatusNoContent},
	} {
		if got := post(c.origin, c.cookie); got != c.want {
			t.Fatalf("origin %q cookie %v: %d, want %d", c.origin, c.cookie, got, c.want)
		}
	}
}

func TestCronMonitorFalseTurnsMonitoringOff(t *testing.T) {
	cfg, err := parseCronYAML([]byte("nightly:\n  schedule: \"@daily\"\n  sql: \"SELECT 1\"\n  monitor: false\nhourly:\n  schedule: \"@hourly\"\n  sql: \"SELECT 1\"\n  monitor: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	monitors := map[string]bool{}
	for _, job := range cfg.Jobs {
		monitors[job.ID] = job.Monitor != nil
	}
	if monitors["nightly"] || !monitors["hourly"] {
		t.Fatalf("monitors: %v", monitors)
	}
}
