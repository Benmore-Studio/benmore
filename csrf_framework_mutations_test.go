//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Framework mutation endpoints that accept the session cookie must refuse a
// cookie request that carries no CSRF token, before any side effect. The
// bodies here are sent as text/plain, the shape a cross-site page can post
// without a CORS preflight.
func TestFrameworkMutationEndpointsRequireCSRF(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	EnsureJobsTable(app.DB)
	mustExec(t, app.DB, `INSERT INTO _benmore_users (id, username, email, role) VALUES (1, 'admin', 'admin@test.com', 'admin')`)
	sid := CreateSession(app.DB, 1, "admin@test.com", "", time.Hour)

	mux := http.NewServeMux()
	RegisterDeviceRoutes(mux, app)
	RegisterJobsAPI(mux, app)
	RegisterOAuthTokensAPI(mux, app)
	RegisterAnalyticsRoutes(mux, app)

	mustExec(t, app.DB, `INSERT INTO _benmore_devices (user_id, token, platform) VALUES (1, 'existing-device', 'ios')`)
	mustExec(t, app.DB, `INSERT INTO _benmore_jobs (id, status, error) VALUES (7, 'failed', 'boom')`)
	mustExec(t, app.DB, `INSERT INTO _benmore_funnels (id, name, steps) VALUES (5, 'kept', '["/","/b"]')`)
	mustExec(t, app.DB, `INSERT INTO _benmore_oauth_tokens (user_id, provider, access_token) VALUES (1, 'github', 'enc:placeholder')`)

	send := func(method, path, body, csrf string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "text/plain")
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		} else {
			req.Header.Set("Sec-Fetch-Site", "same-site")
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	count := func(q string) int {
		var n int
		app.DB.QueryRow(q).Scan(&n)
		return n
	}

	cases := []struct {
		method, path, body string
		unchanged          string // COUNT(*) query that must stay 1
		absent             string // COUNT(*) query that must stay 0
	}{
		{"POST", "/api/_devices", `{"token":"forged-device","platform":"ios"}`, "", `SELECT COUNT(*) FROM _benmore_devices WHERE token = 'forged-device'`},
		{"DELETE", "/api/_devices", `{}`, `SELECT COUNT(*) FROM _benmore_devices WHERE token = 'existing-device'`, ""},
		{"POST", "/api/_jobs/7/retry", ``, `SELECT COUNT(*) FROM _benmore_jobs WHERE id = 7 AND status = 'failed'`, ""},
		{"DELETE", "/api/_jobs/7", ``, `SELECT COUNT(*) FROM _benmore_jobs WHERE id = 7`, ""},
		{"DELETE", "/api/_auth/oauth-tokens/github", ``, `SELECT COUNT(*) FROM _benmore_oauth_tokens WHERE provider = 'github'`, ""},
		{"POST", "/api/_analytics/funnel", `{"name":"forged","steps":["/","/x"]}`, "", `SELECT COUNT(*) FROM _benmore_funnels WHERE name = 'forged'`},
		{"DELETE", "/api/_analytics/funnel?id=5", ``, `SELECT COUNT(*) FROM _benmore_funnels WHERE id = 5`, ""},
	}
	for _, c := range cases {
		rec := send(c.method, c.path, c.body, "")
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s without CSRF token: status %d, want 403 (%s)", c.method, c.path, rec.Code, rec.Body.String())
		}
		if c.unchanged != "" && count(c.unchanged) != 1 {
			t.Errorf("%s %s without CSRF token changed state", c.method, c.path)
		}
		if c.absent != "" && count(c.absent) != 0 {
			t.Errorf("%s %s without CSRF token changed state", c.method, c.path)
		}
	}

	// The SDK's session-bound token still works.
	token := authMintCSRFToken(sid)
	if rec := send("POST", "/api/_devices", `{"token":"real-device","platform":"ios"}`, token); rec.Code != http.StatusOK {
		t.Fatalf("device registration with a valid token: %d %s", rec.Code, rec.Body.String())
	}
	if rec := send("POST", "/api/_jobs/7/retry", ``, token); rec.Code != http.StatusOK {
		t.Fatalf("job retry with a valid token: %d %s", rec.Code, rec.Body.String())
	}
}
