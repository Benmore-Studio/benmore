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

// The app's OAuth provider mints a full-access, 30-day bma_ token. Approving
// a grant is therefore credential minting: a scoped API token or a support
// (impersonation) session must not be able to do it, exactly as it can't
// mint through /api/_auth/api-tokens.
func TestAppOAuthConsentRequiresDirectLogin(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	appOAuthEnsureTables(app)
	mustExec(t, app.DB, `INSERT INTO _benmore_oauth_clients (client_id, name, redirect_uris, scopes) VALUES ('app_test', 'Tool', '["https://tool.example/cb"]', '*')`)
	sid := seedMemberSession(t, app)
	session := GetSessionFromDB(app.DB, sid)
	scoped := auditToken(t, app, sid, "notes:read")
	support := CreateSession(app.DB, session.UserID, session.Email, "", time.Hour)
	mustExec(t, app.DB, "UPDATE _benmore_sessions SET is_impersonation = 1 WHERE id = '"+sessionStorageKey(support)+"'")

	p := oauthAuthorizeParams{ClientID: "app_test", RedirectURI: "https://tool.example/cb", State: "st", Scope: "*",
		CodeChallenge: oauthPKCEChallenge("verifier-verifier-verifier-verifier-verifier-1"), CodeChallengeMethod: "S256"}
	query := url.Values{"response_type": {"code"}, "client_id": {p.ClientID}, "redirect_uri": {p.RedirectURI}, "state": {p.State},
		"scope": {p.Scope}, "code_challenge": {p.CodeChallenge}, "code_challenge_method": {"S256"}}
	approve := func(auth func(*http.Request)) *httptest.ResponseRecorder {
		form := url.Values{"decision": {"approve"}, "consent": {mintOAuthConsent(appOAuthSubject(session), p, time.Now())}}
		for k, v := range query {
			form[k] = v
		}
		r := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://example.com") // a non-browser client sets this freely
		auth(r)
		w := httptest.NewRecorder()
		appOAuthAuthorizeDecision(w, r, app)
		return w
	}
	bearer := func(tok string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
	}
	cookie := func(id string) func(*http.Request) {
		return func(r *http.Request) { r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: id}) }
	}

	for name, auth := range map[string]func(*http.Request){"scoped token": bearer(scoped), "impersonation": cookie(support)} {
		r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+query.Encode(), nil)
		auth(r)
		w := httptest.NewRecorder()
		appOAuthAuthorize(w, r, app)
		if strings.Contains(w.Body.String(), `name="consent"`) {
			t.Errorf("%s: consent page served: %d", name, w.Code)
		}
		if w := approve(auth); strings.Contains(w.Header().Get("Location"), "code=") {
			t.Errorf("%s: authorization code issued: %d %s", name, w.Code, w.Header().Get("Location"))
		}
	}
	var codes int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_oauth_codes").Scan(&codes); err != nil || codes != 0 {
		t.Fatalf("codes issued to delegated credentials: %d %v", codes, err)
	}

	// Control: the user's own login session can still approve.
	if w := approve(cookie(sid)); w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "code=") {
		t.Fatalf("direct login cannot approve: %d %s", w.Code, w.Header().Get("Location"))
	}
}

// The per-app provider had the two weaknesses the round fixed on the platform
// MCP OAuth server: open registration checked only the redirect host, so
// javascript://localhost/... registered, and authorization codes sat in the
// app database in plaintext. Redirects must now be https, or http to a
// loopback host, with no userinfo or fragment; codes are stored as SHA-256.
func TestAppOAuthProviderRedirectRulesAndHashedCodes(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	appOAuthEnsureTables(app)
	register := func(uri string) int {
		body := `{"client_name":"Tool","redirect_uris":["` + uri + `"]}`
		w := httptest.NewRecorder()
		appOAuthRegister(w, httptest.NewRequest(http.MethodPost, "https://app.example/oauth/register", strings.NewReader(body)), app)
		return w.Code
	}
	for _, bad := range []string{"javascript://localhost/%0aalert(1)", "data://localhost/x", "ftp://127.0.0.1/cb", "https://user@tool.example/cb", "https://tool.example/cb#frag", "http://tool.example/cb"} {
		if code := register(bad); code != http.StatusBadRequest {
			t.Errorf("registered %q: %d", bad, code)
		}
	}
	for _, good := range []string{"https://tool.example/cb", "http://localhost:8123/cb", "http://127.0.0.1/cb", "http://[::1]:9000/cb"} {
		if code := register(good); code != http.StatusCreated {
			t.Errorf("control: refused %q: %d", good, code)
		}
	}

	mustExec(t, app.DB, `INSERT INTO _benmore_oauth_clients (client_id, name, redirect_uris, scopes) VALUES ('app_test', 'Tool', '["https://tool.example/cb"]', '*')`)
	sid := seedMemberSession(t, app)
	session := GetSessionFromDB(app.DB, sid)
	p := oauthAuthorizeParams{ClientID: "app_test", RedirectURI: "https://tool.example/cb", State: "st", Scope: "*",
		CodeChallenge: oauthPKCEChallenge("verifier-verifier-verifier-verifier-verifier-1"), CodeChallengeMethod: "S256"}
	form := url.Values{"decision": {"approve"}, "consent": {mintOAuthConsent(appOAuthSubject(session), p, time.Now())},
		"response_type": {"code"}, "client_id": {p.ClientID}, "redirect_uri": {p.RedirectURI}, "state": {p.State},
		"scope": {p.Scope}, "code_challenge": {p.CodeChallenge}, "code_challenge_method": {"S256"}}
	r := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	w := httptest.NewRecorder()
	appOAuthAuthorizeDecision(w, r, app)
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("no code issued: %d %s", w.Code, w.Header().Get("Location"))
	}
	code := loc.Query().Get("code")
	var plain, hashed int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_oauth_codes WHERE code = ?", code).Scan(&plain)
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_oauth_codes WHERE code = ?", hashAPIToken(code)).Scan(&hashed)
	if plain != 0 || hashed != 1 {
		t.Fatalf("code stored in plaintext (plain=%d hashed=%d)", plain, hashed)
	}
	// The issued code still redeems.
	tok := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"app_test"},
		"redirect_uri": {p.RedirectURI}, "code_verifier": {"verifier-verifier-verifier-verifier-verifier-1"}}
	tr := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tok.Encode()))
	tr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tw := httptest.NewRecorder()
	appOAuthToken(tw, tr, app)
	if tw.Code != http.StatusOK || !strings.Contains(tw.Body.String(), "access_token") {
		t.Fatalf("hashed code did not redeem: %d %s", tw.Code, tw.Body.String())
	}
}
