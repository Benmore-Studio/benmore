//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestAnalyticsConcurrentBeacons(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterAnalyticsRoutes(mux, app)
	const requests = 64
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := range requests {
		workers.Add(1)
		go func() {
			defer workers.Done()
			req := httptest.NewRequest("POST", "/api/_analytics", strings.NewReader(`{"p":"/concurrent"}`))
			req.AddCookie(&http.Cookie{Name: "bm_cookie_consent", Value: "accepted"})
			req.AddCookie(&http.Cookie{Name: "_bm_vid", Value: fmt.Sprintf("visitor-%d", i)})
			rec := httptest.NewRecorder()
			<-start
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusNoContent {
				t.Errorf("beacon returned %d", rec.Code)
			}
		}()
	}
	close(start)
	workers.Wait()
	var events, visitors int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_analytics").Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow("SELECT SUM(pageview_count) FROM _benmore_visitors").Scan(&visitors); err != nil {
		t.Fatal(err)
	}
	if events != requests || visitors != requests {
		t.Fatalf("concurrent beacons lost data: events=%d views=%d want=%d", events, visitors, requests)
	}
}

func TestAnalyticsFailedWriteRollsBackBeacon(t *testing.T) {
	for _, target := range []string{"_benmore_analytics", "_benmore_visitors"} {
		t.Run(target, func(t *testing.T) {
			app, cleanup := newTestApp(t)
			defer cleanup()
			mux := http.NewServeMux()
			RegisterAnalyticsRoutes(mux, app)
			mustExec(t, app.DB, "CREATE TRIGGER reject_beacon BEFORE INSERT ON "+target+" BEGIN SELECT RAISE(ABORT, 'fixture failure'); END")
			rec := analyticsTestBeacon(mux, "visitor", `{"p":"/atomic"}`)
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("failed write returned %d, want 503: %s", rec.Code, rec.Body.String())
			}
			for _, table := range []string{"_benmore_analytics", "_benmore_visitors"} {
				var count int
				if err := app.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != 0 {
					t.Errorf("failed beacon left %d rows in %s", count, table)
				}
			}
		})
	}
}

func TestAnalyticsConcurrentSingleVisitor(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterAnalyticsRoutes(mux, app)
	const requests = 32
	var workers sync.WaitGroup
	start := make(chan struct{})
	for range requests {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			if rec := analyticsTestBeacon(mux, "same-visitor", `{"p":"/concurrent"}`); rec.Code != 204 {
				t.Errorf("beacon returned %d: %s", rec.Code, rec.Body.String())
			}
		}()
	}
	close(start)
	workers.Wait()
	var events, sessions, entries, exits, bounces int
	if err := app.DB.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT session_id), SUM(is_entry), SUM(is_exit), SUM(is_bounce) FROM _benmore_analytics`).Scan(&events, &sessions, &entries, &exits, &bounces); err != nil {
		t.Fatal(err)
	}
	if events != requests || sessions != 1 || entries != 1 || exits != 1 || bounces != 1 {
		t.Fatalf("events=%d sessions=%d entries=%d exits=%d bounces=%d", events, sessions, entries, exits, bounces)
	}
	var views, sessionCount int
	if err := app.DB.QueryRow("SELECT pageview_count, session_count FROM _benmore_visitors WHERE visitor_id='same-visitor'").Scan(&views, &sessionCount); err != nil {
		t.Fatal(err)
	}
	if views != requests || sessionCount != 1 {
		t.Fatalf("visitor views=%d sessions=%d", views, sessionCount)
	}
}

func analyticsTestBeacon(mux *http.ServeMux, visitor, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/api/_analytics", strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "bm_cookie_consent", Value: "accepted"})
	req.AddCookie(&http.Cookie{Name: "_bm_vid", Value: visitor})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestAnalyticsFinalBeaconAndSessionExpiry(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	app.DB.SetMaxOpenConns(1)
	mux := http.NewServeMux()
	RegisterAnalyticsRoutes(mux, app)
	post := func(body string, want int) {
		t.Helper()
		if rec := analyticsTestBeacon(mux, "visitor", body); rec.Code != want {
			t.Fatalf("beacon status=%d want=%d body=%s", rec.Code, want, rec.Body.String())
		}
	}
	post(`{"p":"/page","fin":1,"d":120}`, 204) // No initial visit: no counters or sessions.
	var count int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_visitors").Scan(&count); err != nil || count != 0 {
		t.Fatalf("orphan final beacon created visitor: count=%d err=%v", count, err)
	}
	post(`{"p":"/page"}`, 204)
	post(`{"p":"/page","fin":1,"d":120}`, 204)
	var duration, views, sessions int
	if err := app.DB.QueryRow("SELECT duration_ms FROM _benmore_analytics").Scan(&duration); err != nil || duration != 120 {
		t.Fatalf("duration=%d err=%v", duration, err)
	}
	if err := app.DB.QueryRow("SELECT pageview_count, session_count FROM _benmore_visitors").Scan(&views, &sessions); err != nil || views != 1 || sessions != 1 {
		t.Fatalf("after final beacon: views=%d sessions=%d err=%v", views, sessions, err)
	}
	mustExec(t, app.DB, "UPDATE _benmore_analytics SET created_at=datetime('now', '-31 minutes')")
	post(`{"p":"/page"}`, 204)
	if err := app.DB.QueryRow("SELECT pageview_count, session_count FROM _benmore_visitors").Scan(&views, &sessions); err != nil || views != 2 || sessions != 2 {
		t.Fatalf("after expiry: views=%d sessions=%d err=%v", views, sessions, err)
	}
	mustExec(t, app.DB, "CREATE TRIGGER reject_duration BEFORE UPDATE OF duration_ms ON _benmore_analytics BEGIN SELECT RAISE(ABORT, 'fixture failure'); END")
	post(`{"p":"/page","fin":1,"d":200}`, 503)
}
