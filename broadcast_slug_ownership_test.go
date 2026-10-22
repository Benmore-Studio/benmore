//go:build !cli

package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type sfuStub struct{ n atomic.Int32 }

func (s *sfuStub) RoundTrip(r *http.Request) (*http.Response, error) {
	body := `{"sessionDescription":{"type":"answer","sdp":"v=0"}}`
	if strings.HasSuffix(r.URL.Path, "/sessions/new") {
		body = fmt.Sprintf(`{"sessionId":"sfu-session-%d"}`, s.n.Add(1))
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

// A live publisher keeps its slug: another user can't take it over until
// the publisher has stopped heartbeating, and the conflict never discloses
// the publisher's SFU session id (what subscribers pull tracks from).
func TestBroadcastSlugStaysWithLivePublisher(t *testing.T) {
	app, _ := auditApp(t)
	EnsureBroadcastTable(app.DB)
	t.Setenv("BENMORE_PLATFORM_SFU_CF_APP_ID", "0123456789abcdef0123456789abcdef")
	t.Setenv("BENMORE_PLATFORM_SFU_CF_APP_TOKEN", "sfu-token")
	old := http.DefaultTransport
	http.DefaultTransport = &sfuStub{}
	t.Cleanup(func() { http.DefaultTransport = old })
	mustExec(t, app.DB, `INSERT INTO _benmore_users (id, username, email) VALUES (1, 'a', 'a@example.test'), (2, 'b', 'b@example.test')`)
	sidA := CreateSession(app.DB, 1, "a@example.test", "", time.Hour)
	sidB := CreateSession(app.DB, 2, "b@example.test", "", time.Hour)
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
	offer := `{"slug":"live","sdp":"v=0\r\na=mid:0\r\n"}`

	if rec := post("/api/_broadcast/publish", sidA, offer); rec.Code != 200 {
		t.Fatalf("first publish: %d %s", rec.Code, rec.Body.String())
	}
	rec := post("/api/_broadcast/publish", sidB, offer)
	if rec.Code != http.StatusConflict || strings.Contains(rec.Body.String(), "sfu-session") {
		t.Fatalf("second user's publish on a live slug: %d %s", rec.Code, rec.Body.String())
	}
	if rec := post("/api/_broadcast/heartbeat", sidA, `{"slug":"live"}`); rec.Code != 200 {
		t.Fatalf("publisher heartbeat: %d %s", rec.Code, rec.Body.String())
	}
	if rec := post("/api/_broadcast/heartbeat", sidB, `{"slug":"live"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("non-publisher heartbeat: %d", rec.Code)
	}
	if rec := post("/api/_broadcast/publish", sidA, offer); rec.Code != 200 {
		t.Fatalf("publisher re-publishing its own slug: %d %s", rec.Code, rec.Body.String())
	}

	// A publisher that stopped heartbeating is treated as crashed.
	mustExec(t, app.DB, `UPDATE _benmore_broadcasts SET last_seen_at = datetime('now', '-10 minutes') WHERE slug = 'live'`)
	if rec := post("/api/_broadcast/publish", sidB, offer); rec.Code != 200 {
		t.Fatalf("takeover of a stale slug: %d %s", rec.Code, rec.Body.String())
	}
	var owner int64
	app.DB.QueryRow(`SELECT publisher_user_id FROM _benmore_broadcasts WHERE slug = 'live'`).Scan(&owner)
	if owner != 2 {
		t.Fatalf("stale slug owner after takeover = %d, want 2", owner)
	}
}

// A broadcast slug matching a declared ws_rooms pattern is a membership
// room like any bm.room: only members may publish or subscribe.
func TestBroadcastSlugsHonourWSRoomMembership(t *testing.T) {
	app, _ := auditApp(t)
	EnsureBroadcastTable(app.DB)
	t.Setenv("BENMORE_PLATFORM_SFU_CF_APP_ID", "0123456789abcdef0123456789abcdef")
	t.Setenv("BENMORE_PLATFORM_SFU_CF_APP_TOKEN", "sfu-token")
	old := http.DefaultTransport
	http.DefaultTransport = &sfuStub{}
	t.Cleanup(func() { http.DefaultTransport = old })
	app.WSRooms = []WSRoomRule{{Pattern: "stream-:id", Rule: &memberOfRule{Table: "room_members", JoinCol: "room_id", UserCol: "member_id"}}}
	mustExec(t, app.DB, `INSERT INTO _benmore_users (id, username, email) VALUES (1, 'a', 'a@example.test'), (2, 'b', 'b@example.test')`)
	mustExec(t, app.DB, `INSERT INTO room_members (id, room_id, member_id) VALUES (1, 1, 1)`)
	member := CreateSession(app.DB, 1, "a@example.test", "", time.Hour)
	outsider := CreateSession(app.DB, 2, "b@example.test", "", time.Hour)
	mux := http.NewServeMux()
	RegisterBroadcastRoutes(mux, app)
	post := func(path, sid, body string) int {
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		req.Header.Set("X-CSRF-Token", generateCSRFToken())
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	offer := `{"slug":"stream-1","sdp":"v=0\r\na=mid:0\r\n"}`
	if code := post("/api/_broadcast/publish", outsider, offer); code != http.StatusForbidden {
		t.Fatalf("non-member publish on a membership room: %d", code)
	}
	if code := post("/api/_broadcast/publish", member, offer); code != 200 {
		t.Fatalf("member publish: %d", code)
	}
	if code := post("/api/_broadcast/subscribe", outsider, offer); code != http.StatusForbidden {
		t.Fatalf("non-member subscribe on a membership room: %d", code)
	}
	if code := post("/api/_broadcast/subscribe", member, offer); code != 200 {
		t.Fatalf("member subscribe: %d", code)
	}
}

// In an app with groups:, bm.room rooms are partitioned by tenant; a
// broadcast slug must be too, or a signed-in user of another tenant can pull
// a tenant's live video by guessing its slug ("standup").
func TestBroadcastSubscribeStaysInPublisherTenant(t *testing.T) {
	app, _ := auditApp(t)
	EnsureBroadcastTable(app.DB)
	t.Setenv("BENMORE_PLATFORM_SFU_CF_APP_ID", "0123456789abcdef0123456789abcdef")
	t.Setenv("BENMORE_PLATFORM_SFU_CF_APP_TOKEN", "sfu-token")
	old := http.DefaultTransport
	http.DefaultTransport = &sfuStub{}
	t.Cleanup(func() { http.DefaultTransport = old })
	mustExec(t, app.DB, `INSERT INTO members (org_id, email) VALUES ('tenant-a', 'host@example.com'), ('tenant-a', 'peer@example.com'), ('tenant-b', 'rival@example.com')`)
	host := createCrudScopeSession(t, app, "host@example.com", "user", "tenant-a", "")
	peer := createCrudScopeSession(t, app, "peer@example.com", "user", "tenant-a", "")
	rival := createCrudScopeSession(t, app, "rival@example.com", "user", "tenant-b", "")
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
	offer := `{"slug":"standup","sdp":"v=0\r\na=mid:0\r\n"}`
	if rec := post("/api/_broadcast/publish", host, offer); rec.Code != 200 {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	if rec := post("/api/_broadcast/subscribe", peer, offer); rec.Code != 200 {
		t.Fatalf("same-tenant viewer: %d %s", rec.Code, rec.Body.String())
	}
	rec := post("/api/_broadcast/subscribe", rival, offer)
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "sdp") {
		t.Fatalf("other tenant's viewer pulled the stream: %d %s", rec.Code, rec.Body.String())
	}

	// Another tenant publishing the same slug (once this tenant's stream is
	// stale) is never served to the first tenant's viewers as if it were
	// theirs: each tenant resolves the slug in its own namespace.
	mustExec(t, app.DB, `UPDATE _benmore_broadcasts SET last_seen_at = datetime('now', '-10 minutes')`)
	if rec := post("/api/_broadcast/publish", rival, offer); rec.Code != 200 {
		t.Fatalf("other tenant's publish of a stale slug: %d %s", rec.Code, rec.Body.String())
	}
	key, ok := broadcastRowKey(app, GetSessionFromDB(app.DB, peer), "standup")
	var group string
	app.DB.QueryRow(`SELECT COALESCE(publisher_group_id, '') FROM _benmore_broadcasts WHERE slug = ?`, key).Scan(&group)
	if ok && group != "tenant-a" {
		t.Fatalf("viewer resolves another tenant's stream: key %q group %q", key, group)
	}
}
