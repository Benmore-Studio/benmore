//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pullRecorder is an SFU stub that remembers which publisher session each
// subscriber pull asked for.
type pullRecorder struct {
	n     atomic.Int32
	mu    sync.Mutex
	pulls []string
}

func (p *pullRecorder) RoundTrip(r *http.Request) (*http.Response, error) {
	body := `{"sessionDescription":{"type":"answer","sdp":"v=0"}}`
	if strings.HasSuffix(r.URL.Path, "/sessions/new") {
		body = fmt.Sprintf(`{"sessionId":"sfu-session-%d"}`, p.n.Add(1))
	} else if r.Body != nil {
		raw, _ := io.ReadAll(r.Body)
		var req cfTracksReq
		if json.Unmarshal(raw, &req) == nil {
			for _, tr := range req.Tracks {
				if tr.Location == "remote" {
					p.mu.Lock()
					p.pulls = append(p.pulls, tr.SessionID)
					p.mu.Unlock()
					break
				}
			}
		}
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

func (p *pullRecorder) last() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.pulls) == 0 {
		return ""
	}
	return p.pulls[len(p.pulls)-1]
}

func tenantBroadcastFixture(t *testing.T) (*App, *pullRecorder, func(path, sid, body string) *httptest.ResponseRecorder) {
	t.Helper()
	app, _ := auditApp(t)
	EnsureBroadcastTable(app.DB)
	t.Setenv("BENMORE_PLATFORM_SFU_CF_APP_ID", platformCFAppID)
	t.Setenv("BENMORE_PLATFORM_SFU_CF_APP_TOKEN", "sfu-token")
	stub := &pullRecorder{}
	old := http.DefaultTransport
	http.DefaultTransport = stub
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
	return app, stub, post
}

func publisherSession(t *testing.T, app *App, group string) string {
	t.Helper()
	var sid string
	if err := app.DB.QueryRow(`SELECT publisher_session_id FROM _benmore_broadcasts WHERE publisher_group_id = ?`, group).Scan(&sid); err != nil {
		t.Fatalf("no broadcast row for %s: %v", group, err)
	}
	return sid
}

// In an app with groups:, broadcast slugs were one namespace for the whole
// app, so a user of one tenant could hold a slug ("standup", "room-43")
// another tenant needed, heartbeating to keep it. Each tenant now has its
// own slug namespace.
func TestBroadcastSlugsAreTenantNamespaces(t *testing.T) {
	app, stub, post := tenantBroadcastFixture(t)
	mustExec(t, app.DB, `INSERT INTO members (org_id, email) VALUES ('tenant-a', 'host@example.com'), ('tenant-a', 'peer@example.com'), ('tenant-b', 'squatter@example.com'), ('tenant-b', 'viewer@example.com')`)
	host := createCrudScopeSession(t, app, "host@example.com", "user", "tenant-a", "")
	peer := createCrudScopeSession(t, app, "peer@example.com", "user", "tenant-a", "")
	squatter := createCrudScopeSession(t, app, "squatter@example.com", "user", "tenant-b", "")
	viewerB := createCrudScopeSession(t, app, "viewer@example.com", "user", "tenant-b", "")
	admin := createCrudScopeSession(t, app, "ops@example.com", "admin", "", "")
	offer := `{"slug":"standup","sdp":"v=0\r\nm=video 9 UDP 96\r\na=mid:0\r\n"}`

	if rec := post("/api/_broadcast/publish", squatter, offer); rec.Code != 200 {
		t.Fatalf("tenant-b publish: %d %s", rec.Code, rec.Body.String())
	}
	if rec := post("/api/_broadcast/heartbeat", squatter, `{"slug":"standup"}`); rec.Code != 200 {
		t.Fatalf("tenant-b heartbeat: %d", rec.Code)
	}
	if rec := post("/api/_broadcast/publish", host, offer); rec.Code != 200 {
		t.Fatalf("another tenant's live slug blocked tenant-a's publisher: %d %s", rec.Code, rec.Body.String())
	}
	if rec := post("/api/_broadcast/subscribe", peer, offer); rec.Code != 200 || stub.last() != publisherSession(t, app, "tenant-a") {
		t.Fatalf("tenant-a viewer: %d, pulled %q", rec.Code, stub.last())
	}
	if rec := post("/api/_broadcast/subscribe", viewerB, offer); rec.Code != 200 || stub.last() != publisherSession(t, app, "tenant-b") {
		t.Fatalf("tenant-b viewer: %d, pulled %q", rec.Code, stub.last())
	}
	// The other tenant's publisher can't stop this tenant's stream.
	if rec := post("/api/_broadcast/stop", squatter, `{"slug":"standup"}`); rec.Code != 200 {
		t.Fatalf("tenant-b stop of its own stream: %d", rec.Code)
	}
	if rec := post("/api/_broadcast/subscribe", peer, offer); rec.Code != 200 || stub.last() != publisherSession(t, app, "tenant-a") {
		t.Fatalf("tenant-b's stop ended tenant-a's stream: %d", rec.Code)
	}
	// An admin outside the tenants still reaches a live stream by slug.
	if rec := post("/api/_broadcast/subscribe", admin, offer); rec.Code != 200 || stub.last() != publisherSession(t, app, "tenant-a") {
		t.Fatalf("admin subscribe: %d %s", rec.Code, rec.Body.String())
	}
}

// A row published before tenant namespaces (stored under the bare slug)
// keeps working for its tenant until it ends: viewers find it and the
// publisher's heartbeat keeps it.
func TestBroadcastLegacySlugRowStillServesItsTenant(t *testing.T) {
	app, stub, post := tenantBroadcastFixture(t)
	mustExec(t, app.DB, `INSERT INTO members (org_id, email) VALUES ('tenant-a', 'host@example.com'), ('tenant-a', 'peer@example.com'), ('tenant-b', 'rival@example.com')`)
	host := createCrudScopeSession(t, app, "host@example.com", "user", "tenant-a", "")
	peer := createCrudScopeSession(t, app, "peer@example.com", "user", "tenant-a", "")
	rival := createCrudScopeSession(t, app, "rival@example.com", "user", "tenant-b", "")
	hostID := GetSessionFromDB(app.DB, host).UserID
	if _, err := app.DB.Exec(`INSERT INTO _benmore_broadcasts (slug, publisher_session_id, publisher_user_id, publisher_group_id) VALUES ('standup', 'legacy-session', ?, 'tenant-a')`, hostID); err != nil {
		t.Fatal(err)
	}
	offer := `{"slug":"standup","sdp":"v=0\r\nm=video 9 UDP 96\r\na=mid:0\r\n"}`
	if rec := post("/api/_broadcast/subscribe", peer, offer); rec.Code != 200 || stub.last() != "legacy-session" {
		t.Fatalf("legacy row for its tenant: %d, pulled %q", rec.Code, stub.last())
	}
	if rec := post("/api/_broadcast/heartbeat", host, `{"slug":"standup"}`); rec.Code != 200 {
		t.Fatalf("legacy publisher heartbeat: %d", rec.Code)
	}
	if rec := post("/api/_broadcast/subscribe", rival, offer); rec.Code != http.StatusNotFound {
		t.Fatalf("another tenant reached a legacy row: %d", rec.Code)
	}
}

// Apps without groups: keep storing the bare slug.
func TestBroadcastSingleTenantSlugUnchanged(t *testing.T) {
	app, _, post := tenantBroadcastFixture(t)
	app.Group = nil
	mustExec(t, app.DB, `INSERT INTO _benmore_users (id, username, email) VALUES (50, 'solo', 'solo@example.test')`)
	sid := CreateSession(app.DB, 50, "solo@example.test", "", time.Hour)
	if rec := post("/api/_broadcast/publish", sid, `{"slug":"standup","sdp":"v=0\r\nm=video 9 UDP 96\r\na=mid:0\r\n"}`); rec.Code != 200 {
		t.Fatalf("publish: %d", rec.Code)
	}
	var n int
	app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_broadcasts WHERE slug = 'standup'`).Scan(&n)
	if n != 1 {
		t.Fatalf("single-tenant slug not stored bare")
	}
}
