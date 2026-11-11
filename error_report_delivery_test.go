//go:build !cli

package main

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func reportingTestClient(server *httptest.Server) *http.Client {
	target, _ := url.Parse(server.URL)
	return &http.Client{Transport: sentryTestTransport{target: target, base: server.Client().Transport}, Timeout: 3 * time.Second}
}
func stopReportingTest(app *App) {
	select {
	case <-app.Stop:
	default:
		close(app.Stop)
	}
	app.workerWG.Wait()
}
func flushReportingTest(t *testing.T, app *App) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := flushErrorReports(ctx, app); err != nil {
		t.Fatal(err)
	}
}

func TestErrorReportHostIsolation(t *testing.T) {
	var counts [2]atomic.Int64
	var servers [2]*httptest.Server
	for i := range servers {
		servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.Contains(r.Header.Get("X-Sentry-Auth"), []string{"sentry_key=first", "sentry_key=second"}[i]) {
				t.Error("cross-app key")
			}
			counts[i].Add(1)
			w.WriteHeader(200)
		}))
		defer servers[i].Close()
	}
	for i := 0; i < 3; i++ {
		app := errorGroupsFixture(t)
		t.Cleanup(func() { stopReportingTest(app) })
		if i < 2 {
			storeAppEnv(app.Dir, map[string]string{"SENTRY_DSN": "https://" + []string{"first", "second"}[i] + "@93.184.216.34/1"})
		}
		r := app.getErrorReporter()
		r.client = reportingTestClient(servers[i%2])
		reportError(app, errorEvent{Source: "server", Kind: "server", Level: "error", Message: "isolated failure"})
		flushReportingTest(t, app)
	}
	if counts[0].Load() != 1 || counts[1].Load() != 1 {
		t.Fatalf("cross-app delivery counts %d/%d", counts[0].Load(), counts[1].Load())
	}
}

func TestErrorReportQueueOverflowAndClientReport(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var clientReports atomic.Int64
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
		data, err := io.ReadAll(reader)
		if err != nil {
			t.Error(err)
			return
		}
		if strings.Contains(string(data), `"type":"client_report"`) {
			if !strings.Contains(string(data), "queue_overflow") {
				t.Error("missing overflow reason")
			}
			clientReports.Add(1)
		} else {
			once.Do(func() { close(started) })
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	app := errorGroupsFixture(t)
	t.Cleanup(func() { stopReportingTest(app) })
	storeAppEnv(app.Dir, map[string]string{"SENTRY_DSN": "https://first@93.184.216.34/1"})
	r := app.getErrorReporter()
	r.client = reportingTestClient(server)
	ev := errorEvent{Source: "server", Kind: "server", Level: "error", Message: "blocked sink"}
	reportError(app, ev)
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("sink did not start")
	}
	start := time.Now()
	for i := 0; i < 1000; i++ {
		reportError(app, ev)
	}
	elapsed := time.Since(start)
	close(release)
	if elapsed >= 50*time.Millisecond {
		t.Errorf("reporting blocked for %s", elapsed)
	}
	if r.counters.dropped.Load() == 0 {
		t.Error("full queue did not count drops")
	}
	flushReportingTest(t, app)
	stopReportingTest(app)
	r.sendClientReport(context.Background())
	if clientReports.Load() != 1 {
		t.Fatalf("client reports=%d", clientReports.Load())
	}
}

// `benmore test` copies env.yaml, so SENTRY_DSN and ERROR_SLACK_WEBHOOK are
// live in the test app: its reports must stay local (the generated probe
// asserts the group), and nothing may reach the developer's Sentry or Slack.
func TestErrorReportTestRunDeliversNothing(t *testing.T) {
	var delivered atomic.Int64
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { delivered.Add(1); w.WriteHeader(http.StatusOK) }))
	defer sink.Close()
	env := map[string]string{"SENTRY_DSN": "https://k@93.184.216.34/1", "ERROR_SLACK_WEBHOOK": "https://93.184.216.34/slack"}
	ev := errorEvent{Source: "server", Kind: "server", Level: "fatal", Type: "probe", Message: "test run failure"}

	// Control: the same configuration delivers outside a test run.
	live := errorGroupsFixture(t)
	t.Cleanup(func() { stopReportingTest(live) })
	storeAppEnv(live.Dir, env)
	r := live.getErrorReporter()
	r.client = reportingTestClient(sink)
	reportError(live, ev)
	flushReportingTest(t, live)
	if delivered.Load() == 0 {
		t.Fatal("control app delivered nothing")
	}
	delivered.Store(0)

	app := loadGeneratedFixtureApp(t, map[string]string{
		"app.yaml": "name: probe\n",
		"env.yaml": "SENTRY_DSN: \"" + env["SENTRY_DSN"] + "\"\nERROR_SLACK_WEBHOOK: \"" + env["ERROR_SLACK_WEBHOOK"] + "\"\n",
	})
	if GetEnv(app.Dir, "SENTRY_DSN") == "" || GetEnv(app.Dir, "ERROR_SLACK_WEBHOOK") == "" {
		t.Fatal("env.yaml delivery settings not live in the test app")
	}
	r = app.getErrorReporter()
	r.client = reportingTestClient(sink)
	reportError(app, ev)
	flushReportingTest(t, app)
	if n := delivered.Load(); n != 0 {
		t.Fatalf("a test run delivered %d requests", n)
	}
	var groups int
	if err := app.DB.QueryRow(`SELECT count(*) FROM _benmore_error_groups WHERE type='probe'`).Scan(&groups); err != nil || groups != 1 {
		t.Fatalf("local group not recorded: %d %v", groups, err)
	}
}
