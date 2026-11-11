//go:build !cli

package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestErrorAuditWarningDoesNotSuppressFatal(t *testing.T) {
	var sent atomic.Int64
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sent.Add(1); w.WriteHeader(200) }))
	defer sink.Close()
	app := errorGroupsFixture(t)
	defer close(app.Stop)
	storeAppEnv(app.Dir, map[string]string{"SENTRY_DSN": "https://audit@93.184.216.34/1"})
	r := &errorReporter{app: app, client: reportingTestClient(sink), now: time.Now, limiter: NewRateLimiterStoppable(30, time.Minute, app.Stop)}
	ev := errorEvent{Source: "client", Kind: "message", Message: "same failure", Level: "warning"}
	r.process(t.Context(), ev)
	if sent.Load() != 0 {
		t.Fatal("warning was sent")
	}
	ev.Level = "fatal"
	r.process(t.Context(), ev)
	if sent.Load() != 1 {
		t.Fatal("fatal was suppressed by local warning")
	}
	assertCount(t, app, "SELECT count(*) FROM _benmore_error_groups WHERE count=2", 1)
	fingerprint := errorSentryEvent(app, ev, time.Now())["fingerprint"].([]string)
	if len(fingerprint) != 1 || fingerprint[0] != errorGroupKey(ev) {
		t.Fatalf("group key not authoritative: %v", fingerprint)
	}
}

func TestErrorAuditDNSHonorsCancellation(t *testing.T) {
	original := net.DefaultResolver
	defer func() { net.DefaultResolver = original }()
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if !isPrivateURLContext(ctx, "https://never-resolves.invalid/1") {
		t.Fatal("unresolved host accepted")
	}
	if time.Since(start) > time.Second {
		t.Fatal("DNS ignored cancellation")
	}
}

func TestErrorAuditMonitorIdentityAndSchedule(t *testing.T) {
	seen := map[string]bool{}
	for _, id := range []string{"sync_a", "sync-a", "Sync-a", strings.Repeat("x", 80) + "a", strings.Repeat("x", 80) + "b"} {
		slug := cronMonitorSlug("app", id)
		if seen[slug] || len(slug) > 50 {
			t.Fatalf("colliding or oversized slug: %s", slug)
		}
		seen[slug] = true
	}
	if cronMonitorSchedule("0 0 1 * 1") != nil {
		t.Fatal("incompatible day semantics exported")
	}
	for _, schedule := range []string{"0 0 1 * *", "0 0 * * 1", "0 0 */2 * 1", "@daily"} {
		if cronMonitorSchedule(schedule) == nil {
			t.Fatalf("compatible schedule rejected: %s", schedule)
		}
	}
}

func TestErrorAuditMonitorRefreshesChangedConfig(t *testing.T) {
	var configs []any
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		lines := strings.Split(string(b), "\n")
		var item map[string]any
		if len(lines) > 2 {
			_ = json.Unmarshal([]byte(lines[2]), &item)
		}
		configs = append(configs, item["monitor_config"])
		w.WriteHeader(200)
	}))
	defer sink.Close()
	app := errorGroupsFixture(t)
	defer close(app.Stop)
	storeAppEnv(app.Dir, map[string]string{"SENTRY_DSN": "https://audit@93.184.216.34/1"})
	r := &errorReporter{app: app, client: reportingTestClient(sink), now: time.Now, limiter: NewRateLimiterStoppable(30, time.Minute, app.Stop)}
	item := &cronCheckIn{ID: newSentryEventID(), Status: "in_progress", Job: CronJob{ID: "daily", Schedule: "@daily", Monitor: &CronMonitor{CheckinMargin: 5, MaxRuntime: 30}}}
	r.sendCheckIn(t.Context(), item)
	r.sendCheckIn(t.Context(), item)
	item.Job.Schedule = "@hourly"
	r.sendCheckIn(t.Context(), item)
	r.sendCheckIn(t.Context(), item)
	if len(configs) != 4 || configs[0] == nil || configs[1] != nil || configs[2] == nil || configs[3] != nil {
		t.Fatalf("config updates: %v", configs)
	}
}
