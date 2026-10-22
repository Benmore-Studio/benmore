//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func broadcastLivenessFixture(t *testing.T) (*App, func(path, sid, body string) *httptest.ResponseRecorder) {
	t.Helper()
	app, _ := auditApp(t)
	app.Group = nil // a single-tenant app
	EnsureBroadcastTable(app.DB)
	t.Setenv("BENMORE_PLATFORM_SFU_CF_APP_ID", platformCFAppID)
	t.Setenv("BENMORE_PLATFORM_SFU_CF_APP_TOKEN", "sfu-token")
	old := http.DefaultTransport
	http.DefaultTransport = &sfuStub{}
	t.Cleanup(func() { http.DefaultTransport = old })
	mux := http.NewServeMux()
	RegisterBroadcastRoutes(mux, app)
	post := func(path, sid, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		req.Header.Set("X-CSRF-Token", generateCSRFToken())
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	return app, post
}

// Only the publisher's heartbeat keeps a slug claimed. A subscribe used to
// refresh last_seen_at too, so any viewer re-subscribing every minute kept
// a crashed publisher's slug live and locked out everyone else.
func TestBroadcastSubscribeDoesNotKeepCrashedPublisherAlive(t *testing.T) {
	app, post := broadcastLivenessFixture(t)
	mustExec(t, app.DB, `INSERT INTO _benmore_users (id, username, email) VALUES (1, 'a', 'a@example.test'), (2, 'b', 'b@example.test'), (3, 'c', 'c@example.test')`)
	publisher := CreateSession(app.DB, 1, "a@example.test", "", time.Hour)
	viewer := CreateSession(app.DB, 2, "b@example.test", "", time.Hour)
	other := CreateSession(app.DB, 3, "c@example.test", "", time.Hour)
	offer := `{"slug":"live","sdp":"v=0\r\na=mid:0\r\n"}`
	if rec := post("/api/_broadcast/publish", publisher, offer); rec.Code != 200 {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	// The publisher crashes: its last heartbeat ages past the stale window.
	mustExec(t, app.DB, `UPDATE _benmore_broadcasts SET last_seen_at = datetime('now', '-10 minutes') WHERE slug = 'live'`)
	if rec := post("/api/_broadcast/subscribe", viewer, offer); rec.Code != 200 {
		t.Fatalf("subscribe: %d %s", rec.Code, rec.Body.String())
	}
	var viewers int
	app.DB.QueryRow(`SELECT viewer_count FROM _benmore_broadcasts WHERE slug = 'live'`).Scan(&viewers)
	if viewers != 1 {
		t.Fatalf("viewer_count = %d, want 1", viewers)
	}
	if rec := post("/api/_broadcast/publish", other, offer); rec.Code != 200 {
		t.Fatalf("a subscribe kept the crashed publisher's slug claimed: %d %s", rec.Code, rec.Body.String())
	}
}
