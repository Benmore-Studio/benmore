//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The badge and live hints belong to the same personal inbox as the REST API.
// A delegation for an unrelated table must not recover the unread count or
// infer new inbox activity through either alternative read surface.
func TestNotificationBadgeAndLiveHintsHonorCredentialScopes(t *testing.T) {
	app := ssrTestApp(t)
	owner := createCrudScopeSession(t, app, "badge-owner@example.com", "user", "", "")
	uid := GetSessionFromDB(app.DB, owner).UserID
	peer := createCrudScopeSession(t, app, "badge-peer@example.com", "user", "", "")
	EnsureNotificationsTable(app.DB)
	EnsureAPITokensTable(app.DB)
	for i := 0; i < 7; i++ {
		auditExec(t, app.DB, "INSERT INTO _benmore_notifications(user_id,title) VALUES(?,?)", uid, "private-title")
	}
	ssrLoadPages(t, app, map[string]string{"badge.html": "---\nengine: gotmpl\nauth: required\n---\n<output id=\"badge\">{{toJson .notification_count}}</output>"})
	mux := buildAppMux(app, false, "https://badge.example.invalid")
	for _, tc := range []struct {
		name, scope string
		read        bool
	}{
		{"unrelated", "notes:read", false},
		{"explicit-read", "_notifications:read", true},
		{"write-implies-read", "_notifications:write", true},
		{"wildcard", "*", true},
	} {
		for _, kind := range []string{"api-token", "bearer-session"} {
			t.Run(tc.name+"/"+kind, func(t *testing.T) {
				var credential string
				if kind == "api-token" {
					credential = "bmr_badge_fixture_" + tc.name
					auditExec(t, app.DB, "INSERT INTO _benmore_api_tokens(user_id,name,token_hash,scopes) VALUES(?,?,?,?)", uid, tc.name, hashToken(credential), tc.scope)
				} else {
					credential = authzSession(t, app, uid, "badge-owner@example.com", tc.scope)
				}
				w := ssrGet(mux, "/api/_notifications/count", credential)
				wantStatus, wantBadge := http.StatusForbidden, "null"
				if tc.read {
					wantStatus, wantBadge = http.StatusOK, "7"
				}
				if w.Code != wantStatus {
					t.Fatalf("REST scope control = %d, want %d", w.Code, wantStatus)
				}
				w = ssrGet(mux, "/badge", credential)
				if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `<output id="badge">`+wantBadge+`</output>`) {
					t.Errorf("badge = %d %s; want %s", w.Code, w.Body.String(), wantBadge)
				}
				if !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
					t.Error("personal badge is cacheable")
				}
				subscriber := subscribeFlowRealtime(t, app, credential)
				other := subscribeFlowRealtime(t, app, peer)
				deliverRealtimeChange(app, realtimeChange{table: notificationsTable, action: "insert", userID: uid})
				sse, ws := subscriber.drain()
				if tc.read {
					if len(sse) != 1 || len(ws) != 1 || !strings.Contains(sse[0], notificationsTable) || !strings.Contains(ws[0], notificationsTable) {
						t.Errorf("authorized inbox hint missing: SSE=%q WS=%q", sse, ws)
					}
				} else if len(sse) != 0 || len(ws) != 0 {
					t.Errorf("unrelated credential received inbox activity: SSE=%q WS=%q", sse, ws)
				}
				if a, b := other.drain(); len(a) != 0 || len(b) != 0 {
					t.Errorf("peer received another inbox activity: SSE=%q WS=%q", a, b)
				}
			})
		}
	}
	// Cookie login remains a full personal-inbox credential.
	r := httptest.NewRequest(http.MethodGet, "/badge", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: owner})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `<output id="badge">7</output>`) {
		t.Errorf("normal login badge: %d %s", w.Code, w.Body.String())
	}
}

func TestNotificationReadSurfacesSeparateRoleAndEdgeScopes(t *testing.T) {
	app := ssrTestApp(t)
	EnsureNotificationsTable(app.DB)
	crudScopeMustExec(t, app.DB, "INSERT INTO _benmore_notifications(user_id,title) VALUES(5,'private')")
	for _, tc := range []struct {
		name    string
		session *Session
		read    bool
	}{
		{"role-scopes-are-not-delegation", &Session{UserID: 5, Scopes: "notes:read"}, true},
		{"scoped-admin", &Session{UserID: 5, Role: "admin", CredentialScopes: "notes:read"}, false},
		{"edge-empty", &Session{UserID: 5, ID: "edge:badge"}, false},
		{"edge-unrelated", &Session{UserID: 5, ID: "edge:badge", CredentialScopes: "notes:read"}, false},
		{"edge-read", &Session{UserID: 5, ID: "edge:badge", CredentialScopes: "_notifications:read"}, true},
		{"anonymous", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &RenderContext{App: app, User: tc.session, Data: map[string]any{}}
			InjectNotificationCount(ctx)
			value, present := ctx.Data["notification_count"]
			if present != tc.read || (tc.read && fmt.Sprint(value) != "1") {
				t.Errorf("badge presence=%v value=%v, read allowed=%v", present, value, tc.read)
			}
			p := realtimePrincipal{app: app, session: tc.session}
			if got := p.canRead(notificationsTable, 5); got != tc.read {
				t.Errorf("live inbox read=%v, want %v", got, tc.read)
			}
		})
	}
}
