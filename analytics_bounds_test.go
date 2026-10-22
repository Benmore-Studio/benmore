//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func analyticsBeaconWithCookie(mux *http.ServeMux, visitor string, header http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/api/_analytics", strings.NewReader(`{"p":"/landing"}`))
	req.AddCookie(&http.Cookie{Name: "bm_cookie_consent", Value: "accepted"})
	if visitor != "" {
		req.AddCookie(&http.Cookie{Name: "_bm_vid", Value: visitor})
	}
	for k, v := range header {
		req.Header[k] = v
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// The beacon is public, and it stored whatever the visitor cookie held as the
// visitor id: a caller could write a cookie-sized value into two tables with
// every request. Only an id the framework minted is accepted; anything else
// gets a fresh one.
func TestAnalyticsBeaconIgnoresForeignVisitorIDs(t *testing.T) {
	minted := regexp.MustCompile(`^[0-9a-f]{16}$`)
	for name, cookie := range map[string]string{
		"oversized":  strings.Repeat("a", 6000),
		"wrong form": "visitor-1",
		"uppercase":  "ABCDEF0123456789",
		"too long":   "0123456789abcdef0",
	} {
		t.Run(name, func(t *testing.T) {
			app, cleanup := newTestApp(t)
			defer cleanup()
			mux := http.NewServeMux()
			RegisterAnalyticsRoutes(mux, app)
			rec := analyticsBeaconWithCookie(mux, cookie, nil)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("beacon returned %d", rec.Code)
			}
			var stored string
			if err := app.DB.QueryRow("SELECT visitor_id FROM _benmore_visitors").Scan(&stored); err != nil {
				t.Fatal(err)
			}
			if !minted.MatchString(stored) {
				t.Errorf("stored a caller-chosen visitor id (%d bytes)", len(stored))
			}
			if set := rec.Header().Get("Set-Cookie"); !strings.Contains(set, "_bm_vid="+stored) {
				t.Errorf("the replacement id was not issued as a cookie: %q", set)
			}
		})
	}

	// A framework-issued id is kept, so a returning visitor stays one visitor.
	app, cleanup := newTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterAnalyticsRoutes(mux, app)
	for i := 0; i < 2; i++ {
		if rec := analyticsBeaconWithCookie(mux, "0123456789abcdef", nil); rec.Code != http.StatusNoContent || rec.Header().Get("Set-Cookie") != "" {
			t.Fatalf("returning visitor: %d, Set-Cookie %q", rec.Code, rec.Header().Get("Set-Cookie"))
		}
	}
	var visitors, views int
	app.DB.QueryRow("SELECT COUNT(*), SUM(pageview_count) FROM _benmore_visitors WHERE visitor_id = '0123456789abcdef'").Scan(&visitors, &views)
	if visitors != 1 || views != 2 {
		t.Fatalf("returning visitor recorded as %d visitors / %d views", visitors, views)
	}
}

// The country comes from a request header (Cloudflare's, when the app is
// behind it); a direct caller can send any text there.
func TestAnalyticsBeaconStoresOnlyACountryCode(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterAnalyticsRoutes(mux, app)
	analyticsBeaconWithCookie(mux, "00000000000000a1", http.Header{"Cf-Ipcountry": {strings.Repeat("Z", 4000)}})
	analyticsBeaconWithCookie(mux, "00000000000000a2", http.Header{"Cf-Ipcountry": {"DE"}})
	rows, err := app.DB.Query("SELECT visitor_id, country FROM _benmore_analytics ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]string{}
	for rows.Next() {
		var v, c string
		rows.Scan(&v, &c)
		got[v] = c
	}
	if got["00000000000000a1"] != "" || got["00000000000000a2"] != "DE" {
		t.Fatalf("stored countries: %q", got)
	}
}

// _benmore_analytics is a ring, but every new visitor also got a row in
// _benmore_visitors that nothing ever removed. Any caller could add one per
// request until the app's database reached its storage cap and every write
// in the app failed.
func TestAnalyticsVisitorsTableIsBounded(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	app.DB.SetMaxOpenConns(1)
	oldCap := analyticsVisitorCap
	analyticsVisitorCap = 40
	defer func() { analyticsVisitorCap = oldCap }()
	mux := http.NewServeMux()
	RegisterAnalyticsRoutes(mux, app)

	// A long-standing visitor, seen again just before the flood ends.
	analyticsBeaconWithCookie(mux, "00000000000000fe", nil)
	for i := 0; i < analyticsPruneEvery+5; i++ {
		if i == analyticsPruneEvery-3 {
			analyticsBeaconWithCookie(mux, "00000000000000fe", nil)
			continue
		}
		analyticsBeaconWithCookie(mux, "", nil)
	}
	var visitors, kept int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_visitors").Scan(&visitors)
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_visitors WHERE visitor_id = '00000000000000fe'").Scan(&kept)
	if visitors > analyticsVisitorCap+analyticsPruneEvery {
		t.Fatalf("%d visitor rows with a cap of %d", visitors, analyticsVisitorCap)
	}
	if visitors > analyticsVisitorCap+10 {
		t.Fatalf("%d visitor rows right after a prune with a cap of %d", visitors, analyticsVisitorCap)
	}
	if kept != 1 {
		t.Fatal("the prune dropped a recently seen visitor before older ones")
	}
}
