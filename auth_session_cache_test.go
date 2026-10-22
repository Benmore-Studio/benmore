//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func sessionCacheApp(t *testing.T) *App {
	t.Helper()
	app, done := newTestApp(t)
	t.Cleanup(done)
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(app.DB)
	EnsureLoginAttemptsTable(app.DB)
	app.Paths = DiscoverAuthPaths(nil)
	app.SessionDuration = time.Hour
	return app
}

// inRequest runs fn inside the per-request cache middleware.
func inRequest(t *testing.T, r *http.Request, fn func(r *http.Request)) {
	t.Helper()
	requestSessionCacheMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fn(r) })).
		ServeHTTP(httptest.NewRecorder(), r)
}

// One request resolves its session once; copies are independent; another
// credential in the same context is resolved separately; invalidation and
// the TTL send the next lookup back to the database.
func TestRequestSessionCache(t *testing.T) {
	app := sessionCacheApp(t)
	_, sid, uid := loginTestUser(app, "cache@example.com", "user")
	_, otherSID, otherUID := loginTestUser(app, "other@example.com", "user")
	r := httptest.NewRequest(http.MethodGet, "/api/notes", nil)
	r.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: sid})
	ran := false
	inRequest(t, r, func(r *http.Request) {
		ran = true
		first := getSession(app, r)
		if first == nil || first.UserID != uid {
			t.Fatalf("first lookup: %+v", first)
		}
		first.Email = "mutated"
		first.Roles = append(first.Roles, "admin")
		// Delete the row behind the cache's back: a repeat lookup in the
		// same request is answered from the cache, as an unmodified copy.
		mustExec(t, app.DB, "DELETE FROM _benmore_sessions WHERE id = '"+sessionStorageKey(sid)+"'")
		again := getSession(app, r)
		if again == nil || again.Email != "cache@example.com" || HasAnyRole(again, []string{"admin"}) {
			t.Fatalf("cached copy was not independent: %+v", again)
		}

		// A sub-request with another credential never reads this entry.
		sub := r.Clone(r.Context())
		sub.Header.Del("Cookie")
		sub.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: otherSID})
		if s := getSession(app, sub); s == nil || s.UserID != otherUID {
			t.Fatalf("other credential got %+v", s)
		}

		invalidateRequestSession(r)
		if s := getSession(app, r); s != nil {
			t.Fatal("invalidation did not reach the database")
		}

		// An entry older than the TTL is not used.
		holder := requestSessionHolderFor(r)
		cred, _ := requestSessionCredential(r)
		holder.put(app, cred, &Session{ID: "stale", UserID: 99}, time.Now().Add(-2*requestSessionCacheTTL))
		if s := getSession(app, r); s != nil {
			t.Fatalf("an expired entry answered: %+v", s)
		}
	})
	if !ran {
		t.Fatal("handler did not run")
	}

	// Streams re-check their session on every event, so they get no cache.
	stream := httptest.NewRequest(http.MethodGet, "/sse/events", nil)
	stream.Header.Set("Accept", "text/event-stream")
	inRequest(t, stream, func(r *http.Request) {
		if requestSessionHolderFor(r) != nil {
			t.Fatal("an event stream got a session cache")
		}
	})
	ws := httptest.NewRequest(http.MethodGet, "/ws", nil)
	ws.Header.Set("Upgrade", "websocket")
	inRequest(t, ws, func(r *http.Request) {
		if requestSessionHolderFor(r) != nil {
			t.Fatal("a WebSocket upgrade got a session cache")
		}
	})
}

// Logging out within a request drops the cached session, so middleware that
// runs after the handler (request log, analytics) sees no session.
func TestLogoutInvalidatesRequestSessionCache(t *testing.T) {
	app := sessionCacheApp(t)
	_, sid, _ := loginTestUser(app, "bye@example.com", "user")
	form := url.Values{"_csrf": {authMintCSRFToken(sid)}}
	r := httptest.NewRequest(http.MethodPost, app.Paths.Logout, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: sid})
	inRequest(t, r, func(r *http.Request) {
		if getSession(app, r) == nil {
			t.Fatal("not signed in")
		}
		handleLogout(httptest.NewRecorder(), r, app)
		if s := cachedRequestSession(app, r); s != nil {
			t.Fatalf("the logged-out session is still served: %+v", s)
		}
	})
}

// The password-change gate skips static assets and resolves a normal session
// through the request cache; a pending account is still routed to the
// change page.
func TestPasswordChangeGateWithSessionCache(t *testing.T) {
	app := sessionCacheApp(t)
	_, sid, uid := loginTestUser(app, "pending@example.com", "user")
	mustExec(t, app.DB, "UPDATE _benmore_users SET password_change_required = 1 WHERE id = "+itoa(int(uid)))
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	handler := requestSessionCacheMiddleware(passwordChangeMiddleware(next, app))
	serve := func(path string, sid string) int {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: sid})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	if code := serve("/static/app.js", sid); code != http.StatusTeapot {
		t.Fatalf("static asset gated: %d", code)
	}
	if code := serve("/dashboard", sid); code != http.StatusSeeOther {
		t.Fatalf("pending account not routed to the change page: %d", code)
	}
	_, normal, _ := loginTestUser(app, "normal@example.com", "user")
	if code := serve("/dashboard", normal); code != http.StatusTeapot {
		t.Fatalf("normal session gated: %d", code)
	}
}

// Session and login-attempt sweeps use indexes; the expiry sweep keeps its
// datetime() comparison and is served by an expression index.
func TestAuthTablesHaveSweepIndexes(t *testing.T) {
	app := sessionCacheApp(t)
	plan := func(q string) string {
		rows, err := app.DB.Query("EXPLAIN QUERY PLAN " + q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var id, parent, notused int
			var detail string
			if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
				t.Fatal(err)
			}
			out = append(out, detail)
		}
		return strings.Join(out, "; ")
	}
	for q, index := range map[string]string{
		"DELETE FROM _benmore_sessions WHERE datetime(expires_at) < datetime('now')":          "idx_benmore_sessions_expiry",
		"DELETE FROM _benmore_sessions WHERE user_id = 1":                                     "idx_benmore_sessions_user",
		"DELETE FROM _benmore_login_attempts WHERE attempted_at < datetime('now', '-1 hour')": "idx_login_attempts_time",
	} {
		if p := plan(q); !strings.Contains(p, index) {
			t.Errorf("%s: plan %q does not use %s", q, p, index)
		}
	}
}
