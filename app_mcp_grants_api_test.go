//go:build !cli && !windows

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type grantsAPIFixture struct {
	*appMCPOAuthHTTPFixture
	otherSID  string
	otherUID  int64
	mine      *appMCPTokenPair
	theirs    *appMCPTokenPair
	mineGrant string
}

func newGrantsAPIFixture(t *testing.T) *grantsAPIFixture {
	t.Helper()
	f := &grantsAPIFixture{appMCPOAuthHTTPFixture: newAppMCPOAuthHTTPFixture(t)}
	f.otherSID = createCrudScopeSession(t, f.app, "other-owner@example.com", "editor", "17", "")
	f.otherUID = GetSessionFromDB(f.app.DB, f.otherSID).UserID
	auditExec(t, f.app.DB, "INSERT INTO members(org_id,email) VALUES ('17','other-owner@example.com')")
	var err error
	f.mine, err = createAppMCPGrant(f.app, f.session.UserID, "17", "client-fixture", grantFixtureResource, "notes:read", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.theirs, err = createAppMCPGrant(f.app, f.otherUID, "17", "client-fixture", grantFixtureResource, "notes:read", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.mineGrant = f.mine.GrantID
	return f
}

func (f *grantsAPIFixture) do(method, path string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, appMCPOAuthHTTPOrigin+path, nil)
	mutate(r)
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w
}

func (f *grantsAPIFixture) as(sid string, csrf bool) func(*http.Request) {
	return func(r *http.Request) {
		r.AddCookie(sessionCookie(sid, false, time.Hour))
		if csrf {
			r.Header.Set("X-CSRF-Token", authMintCSRFToken(sid))
		}
	}
}

// connectorStatus calls the MCP transport with a connector access token.
func (f *grantsAPIFixture) connectorStatus(token string) int {
	return f.do(http.MethodPost, "/api/_mcp", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Body = http.NoBody
	}).Code
}

func TestAppMCPGrantsAPIListShowsOnlyOwnLiveGrants(t *testing.T) {
	f := newGrantsAPIFixture(t)
	// An ended grant of the same user stays hidden.
	ended, err := createAppMCPGrant(f.app, f.session.UserID, "17", "client-fixture", grantFixtureResource, "notes:read", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	auditExec(t, f.app.DB, "UPDATE _benmore_mcp_grants SET revoked=1 WHERE id=?", ended.GrantID)
	w := f.do(http.MethodGet, "/api/_mcp/grants", f.as(f.sid, false))
	if w.Code != 200 {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var body struct {
		Grants []map[string]any `json:"grants"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || len(body.Grants) != 1 {
		t.Fatalf("grants: %v %s", err, w.Body.String())
	}
	g := body.Grants[0]
	if g["id"] != f.mineGrant || g["client_name"] != "Reviewed client" || g["scopes"] != "notes:read" || g["workspace"] != "17" || g["created_at"] == "" || g["expires_at"] == "" {
		t.Fatalf("wrong grant: %v", g)
	}
	for _, secret := range []string{f.mine.AccessToken, f.mine.RefreshToken, f.theirs.GrantID, "token_hash", "bmca_", "bmcr_"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("response leaks %q: %s", secret, w.Body.String())
		}
	}
}

func TestAppMCPGrantsAPIRevokeOwnGrantEndsBearer(t *testing.T) {
	f := newGrantsAPIFixture(t)
	if got := f.connectorStatus(f.mine.AccessToken); got == http.StatusUnauthorized {
		t.Fatalf("live grant refused before revoke: %d", got)
	}
	w := f.do(http.MethodDelete, "/api/_mcp/grants/"+f.mineGrant, f.as(f.sid, true))
	if w.Code != 200 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	if got := f.connectorStatus(f.mine.AccessToken); got != http.StatusUnauthorized {
		t.Fatalf("revoked access token still works: %d", got)
	}
	if _, err := refreshAppMCPGrant(f.app, f.mine.RefreshToken, "client-fixture", grantFixtureResource, time.Now()); err == nil {
		t.Fatal("revoked refresh token still works")
	}
	if n := appMCPOAuthHTTPCount(t, f.app, "_benmore_mcp_credentials WHERE grant_id='"+f.mineGrant+"'"); n != 0 {
		t.Fatalf("credentials kept: %d", n)
	}
	if n := appMCPOAuthHTTPCount(t, f.app, "_benmore_audit_log WHERE action='mcp_grant_revoke' AND row_id='"+f.mineGrant+"'"); n != 1 {
		t.Fatalf("audit rows: %d", n)
	}
	// Second revoke and the list agree it is gone.
	if got := f.do(http.MethodDelete, "/api/_mcp/grants/"+f.mineGrant, f.as(f.sid, true)).Code; got != 404 {
		t.Fatalf("repeat revoke: %d", got)
	}
	if body := f.do(http.MethodGet, "/api/_mcp/grants", f.as(f.sid, false)).Body.String(); strings.Contains(body, f.mineGrant) {
		t.Fatalf("revoked grant listed: %s", body)
	}
}

func TestAppMCPGrantsAPIOtherUsersGrantIs404AndKeepsWorking(t *testing.T) {
	f := newGrantsAPIFixture(t)
	unknown := f.do(http.MethodDelete, "/api/_mcp/grants/"+strings.Repeat("0", 32), f.as(f.sid, true))
	other := f.do(http.MethodDelete, "/api/_mcp/grants/"+f.theirs.GrantID, f.as(f.sid, true))
	if other.Code != 404 || unknown.Code != 404 || other.Body.String() != unknown.Body.String() {
		t.Fatalf("existence oracle: %d %q vs %d %q", other.Code, other.Body.String(), unknown.Code, unknown.Body.String())
	}
	if got := f.connectorStatus(f.theirs.AccessToken); got == http.StatusUnauthorized {
		t.Fatal("another user's grant was revoked")
	}
}

func TestAppMCPGrantsAPIRefusesNonInteractiveCallers(t *testing.T) {
	f := newGrantsAPIFixture(t)
	scoped := CreateSession(f.app.DB, f.session.UserID, f.session.Email, "17", time.Hour, "notes:read")
	delegated := createDelegatedSession(f.app.DB, f.session.UserID, f.session.Email, "17", time.Hour)
	apiToken := "bmr_" + strings.Repeat("a", 40)
	EnsureAPITokensTable(f.app.DB)
	auditExec(t, f.app.DB, "INSERT INTO _benmore_api_tokens(user_id,name,token_hash,scopes) VALUES (?,'t',?,'*')", f.session.UserID, hashToken(apiToken))
	cases := map[string]func(*http.Request){
		"anonymous":         func(*http.Request) {},
		"bearer session":    func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+f.sid) },
		"api token":         func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+apiToken) },
		"connector token":   func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+f.mine.AccessToken) },
		"cookie and bearer": func(r *http.Request) { f.as(f.sid, true)(r); r.Header.Set("Authorization", "Bearer "+f.sid) },
		"scoped session":    f.as(scoped, true),
		"delegated session": f.as(delegated, true),
	}
	for name, mutate := range cases {
		for _, method := range []string{http.MethodGet, http.MethodDelete} {
			path := "/api/_mcp/grants"
			if method == http.MethodDelete {
				path += "/" + f.mineGrant
			}
			if got := f.do(method, path, mutate).Code; got != 401 && got != 403 {
				t.Errorf("%s %s: %d", name, method, got)
			}
		}
	}
	if n := appMCPOAuthHTTPCount(t, f.app, "_benmore_mcp_grants WHERE revoked=1"); n != 0 {
		t.Fatalf("a refused caller revoked %d grants", n)
	}
}

func TestAppMCPGrantsAPIDeleteNeedsCSRF(t *testing.T) {
	f := newGrantsAPIFixture(t)
	if got := f.do(http.MethodDelete, "/api/_mcp/grants/"+f.mineGrant, f.as(f.sid, false)).Code; got != 403 {
		t.Fatalf("no csrf: %d", got)
	}
	if got := f.do(http.MethodDelete, "/api/_mcp/grants/"+f.mineGrant, func(r *http.Request) {
		f.as(f.sid, false)(r)
		r.Header.Set("X-CSRF-Token", authMintCSRFToken("some-other-session"))
	}).Code; got != 403 {
		t.Fatalf("foreign csrf: %d", got)
	}
	if n := appMCPOAuthHTTPCount(t, f.app, "_benmore_mcp_grants WHERE revoked=1"); n != 0 {
		t.Fatal("grant revoked without CSRF")
	}
}

func TestAppMCPGrantsAPIAbsentWithoutConnector(t *testing.T) {
	f := newGrantsAPIFixture(t)
	f.app.MCP = nil
	mux := buildAppMux(f.app, false, appMCPOAuthHTTPOrigin)
	r := httptest.NewRequest(http.MethodGet, appMCPOAuthHTTPOrigin+"/api/_mcp/grants", nil)
	r.AddCookie(sessionCookie(f.sid, false, time.Hour))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), `"grants"`) {
		t.Fatalf("route mounted without a connector: %d %s", w.Code, w.Body.String())
	}
}
