//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Presence rows are namespaced by tenant as "<group>\x00<slug>", but a slug
// was only length-checked. A signed-in user with no tenant (key = the raw
// slug) could send "<group>\x00<slug>" and read and write that tenant's
// presence list. A slug holding NUL is now refused.
func TestPresenceSlugCannotNameAnotherTenant(t *testing.T) {
	app, _ := auditApp(t)
	EnsurePresenceTable(app.DB)
	mustExec(t, app.DB, `INSERT INTO members (org_id, email) VALUES ('tenant-a', 'host@example.com')`)
	host := createCrudScopeSession(t, app, "host@example.com", "user", "tenant-a", "")
	// No membership row: a signed-in user who has not joined a tenant yet.
	outsider := createCrudScopeSession(t, app, "outsider@example.com", "user", "", "")
	mux := http.NewServeMux()
	RegisterPresenceRoutes(mux, app)

	heartbeat := func(sid, slug, action string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"slug": slug, "action": action})
		req := httptest.NewRequest("POST", "/api/_presence/heartbeat", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", generateCSRFToken())
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	list := func(sid, slug string) (int, []any) {
		req := httptest.NewRequest("GET", "/api/_presence?slug="+url.QueryEscape(slug), nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out struct {
			Members []any `json:"members"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out.Members
	}

	if rec := heartbeat(host, "huddle", "join"); rec.Code != 200 {
		t.Fatalf("tenant member join: %d %s", rec.Code, rec.Body.String())
	}
	if code, members := list(host, "huddle"); code != 200 || len(members) != 1 {
		t.Fatalf("tenant member's own presence list: %d %v", code, members)
	}

	forged := "tenant-a\x00huddle"
	if code, members := list(outsider, forged); code == 200 && len(members) > 0 {
		t.Errorf("a user outside the tenant read its presence list: %v", members)
	}
	if rec := heartbeat(outsider, forged, "join"); rec.Code == 200 {
		t.Errorf("a user outside the tenant joined its presence list: %d %s", rec.Code, rec.Body.String())
	}
	if _, members := list(host, "huddle"); len(members) != 1 {
		t.Errorf("tenant presence list after the forged join = %v, want only the member", members)
	}

	// Ordinary slugs, including the separators bm.presence callers use,
	// keep working for a user without a tenant.
	if rec := heartbeat(outsider, "doc:checkout spec/1", "join"); rec.Code != 200 {
		t.Fatalf("ordinary slug refused: %d %s", rec.Code, rec.Body.String())
	}
	if code, members := list(outsider, "doc:checkout spec/1"); code != 200 || len(members) != 1 {
		t.Fatalf("ordinary slug list: %d %v", code, members)
	}
}
