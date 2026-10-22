//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// GET /api/_broadcast/stats/{slug} answered anyone, signed in or not, with a
// stream's live state, viewer count and start time, so an outsider could
// watch another tenant's (or a membership room's) streams come and go by
// slug. It now answers only callers who could subscribe to the stream; to
// everyone else a live stream reads as not live, like an unknown slug.
func TestBroadcastStatsFollowsSubscribeAudience(t *testing.T) {
	app, _ := auditApp(t)
	EnsureBroadcastTable(app.DB)
	app.WSRooms = []WSRoomRule{{Pattern: "stream-:id", Rule: &memberOfRule{Table: "room_members", JoinCol: "room_id", UserCol: "member_id"}}}
	mustExec(t, app.DB, `INSERT INTO members (org_id, email) VALUES ('tenant-a', 'host@example.com'), ('tenant-a', 'peer@example.com'), ('tenant-b', 'rival@example.com')`)
	host := createCrudScopeSession(t, app, "host@example.com", "user", "tenant-a", "")
	peer := createCrudScopeSession(t, app, "peer@example.com", "user", "tenant-a", "")
	rival := createCrudScopeSession(t, app, "rival@example.com", "user", "tenant-b", "")
	var hostID int64
	app.DB.QueryRow(`SELECT id FROM _benmore_users WHERE email = 'host@example.com'`).Scan(&hostID)
	for _, q := range []string{
		`INSERT INTO _benmore_broadcasts (slug, publisher_session_id, publisher_user_id, publisher_group_id, viewer_count) VALUES ('standup', 'sfu-1', ?, 'tenant-a', 3), ('stream-1', 'sfu-2', ?, 'tenant-a', 2)`,
		`INSERT INTO room_members (id, room_id, member_id) VALUES (1, 1, ?)`,
	} {
		args := []any{hostID, hostID}[:strings.Count(q, "?")]
		if _, err := app.DB.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	RegisterBroadcastRoutes(mux, app)
	stats := func(sid, slug string) map[string]any {
		req := httptest.NewRequest("GET", "/api/_broadcast/stats/"+slug, nil)
		if sid != "" {
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("stats %s as %q: %d %s", slug, sid, rec.Code, rec.Body.String())
		}
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	live := func(m map[string]any) bool { return m["live"] == true }

	if m := stats(peer, "standup"); !live(m) || m["viewers"] != float64(3) || m["started_at"] == nil {
		t.Fatalf("same-tenant viewer lost the stats: %v", m)
	}
	for name, sid := range map[string]string{"anonymous": "", "other tenant": rival} {
		if m := stats(sid, "standup"); live(m) || m["viewers"] != float64(0) || m["started_at"] != nil || strings.Contains(statsJSON(m), "tenant") {
			t.Errorf("%s caller learned about another tenant's stream: %v", name, m)
		}
	}
	// A slug under a membership room pattern answers members only.
	if m := stats(host, "stream-1"); !live(m) {
		t.Fatalf("room member lost the stats: %v", m)
	}
	if m := stats(peer, "stream-1"); live(m) {
		t.Errorf("non-member learned about a membership room's stream: %v", m)
	}

	// With features.ws_anonymous streams are watchable signed-out, and so
	// are their stats.
	yes := true
	app.Design = &DesignConfig{Features: &FeaturesConfig{WSAnonymous: &yes}}
	if m := stats("", "standup"); !live(m) || m["viewers"] != float64(3) {
		t.Errorf("ws_anonymous app hid stats from a signed-out viewer: %v", m)
	}
}

func statsJSON(m map[string]any) string { b, _ := json.Marshal(m); return string(b) }
