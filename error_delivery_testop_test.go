//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestErrorReportingSyntheticBypassesOnlyGroupThrottle(t *testing.T) {
	var sentry, slack atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/envelope/") {
			sentry.Add(1)
		} else {
			slack.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	app := errorGroupsFixture(t)
	t.Cleanup(func() { stopReportingTest(app) })
	storeAppEnv(app.Dir, map[string]string{"SENTRY_DSN": "https://test@93.184.216.34/1", "ERROR_SLACK_WEBHOOK": "https://93.184.216.34/slack"})
	r := app.getErrorReporter()
	r.client = reportingTestClient(server)
	for i := 0; i < 2; i++ {
		result, err := testErrorReporting(t.Context(), app)
		if err != nil || !result.Sentry.OK || !result.Slack.OK {
			t.Fatalf("test %d: %+v %v", i, result, err)
		}
	}
	if sentry.Load() != 2 || slack.Load() != 2 {
		t.Fatalf("group throttle blocked synthetic test: %d/%d", sentry.Load(), slack.Load())
	}
	// The test has its own budgets: exhausting the ones real failures use
	// does not mute it, and it never spends them.
	for r.limiter.Allow("forward") {
	}
	for r.limiter.Allow("slack") {
	}
	result, err := testErrorReporting(t.Context(), app)
	if err != nil || !result.Sentry.OK || !result.Slack.OK {
		t.Fatalf("test spent the real budgets: %+v %v", result, err)
	}
	var open int
	if err := app.DB.QueryRow(`SELECT count(*) FROM _benmore_error_groups WHERE type='error_reporting_test' AND resolved_at IS NULL`).Scan(&open); err != nil || open != 0 {
		t.Fatalf("test group left unresolved: %d %v", open, err)
	}
	for r.limiter.Allow("test") {
	}
	for r.limiter.Allow("test:slack") {
	}
	result, err = testErrorReporting(t.Context(), app)
	if err != nil || result.Sentry.OK || result.Slack.OK || !result.Sentry.Muted || !result.Slack.Muted {
		t.Fatalf("limiter bypassed: %+v %v", result, err)
	}
	if sentry.Load() != 3 || slack.Load() != 3 {
		t.Fatal("limiter allowed outbound delivery")
	}
	storeAppEnv(app.Dir, map[string]string{})
	result, err = testErrorReporting(t.Context(), app)
	if err != nil || result.Sentry.Configured || result.Slack.Configured {
		t.Fatalf("unconfigured result: %+v %v", result, err)
	}
}
