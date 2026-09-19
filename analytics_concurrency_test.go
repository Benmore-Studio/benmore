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
