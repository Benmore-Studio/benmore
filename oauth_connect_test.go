//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestOAuthProviderDiscoveryMatchesRegisteredRoutes(t *testing.T) {
	t.Setenv("BENMORE_OAUTH_BROKER_URL", "https://broker.example.com")
	t.Setenv("BENMORE_OAUTH_BROKER_PROVIDERS", "google,microsoft")
	t.Setenv("BENMORE_APP_NAME", "fixture-dev")
	app, cleanup := newTestApp(t)
	defer cleanup()
	token := createCrudScopeSession(t, app, "owner@example.com", "user", "", "")
	SetAppEnv(app.Dir, "GOOGLE_CLIENT_ID", "fixture-client")
	SetAppEnv(app.Dir, "GOOGLE_CLIENT_SECRET", "fixture-secret")
	SetAppEnv(app.Dir, "GITHUB_CLIENT_ID", "incomplete-client")
	mux := http.NewServeMux()
	RegisterOAuthRoutes(mux, app)
	if got := crudScopeRequest(t, mux, "GET", "/api/_auth/oauth-providers", "", nil).Code; got != 401 {
		t.Fatalf("anonymous discovery = %d", got)
	}
	w := crudScopeRequest(t, mux, "GET", "/api/_auth/oauth-providers", token, nil)
	var providers []struct {
		Provider     string `json:"provider"`
		TokenStorage bool   `json:"token_storage"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &providers); err != nil || w.Code != 200 {
		t.Fatalf("discovery: %d %s (%v)", w.Code, w.Body, err)
	}
	if len(providers) != 2 || providers[0].Provider != "google" || !providers[0].TokenStorage || providers[1].Provider != "microsoft" || providers[1].TokenStorage {
		t.Fatalf("unexpected capabilities: %+v", providers)
	}
	if strings.Contains(w.Body.String(), "fixture-secret") || strings.Contains(w.Body.String(), "fixture-client") {
		t.Fatal("discovery exposed credentials")
	}
	if got := strings.Join(GetConfiguredProviders(app.Dir), ","); got != "google,microsoft" {
		t.Fatalf("login controls disagree with registered providers: %s", got)
	}
	for _, p := range providers {
		w := crudScopeRequest(t, mux, "GET", "/auth/"+p.Provider, token, nil)
		u, err := url.Parse(w.Header().Get("Location"))
		if err != nil || w.Code < 300 || w.Code >= 400 {
			t.Fatalf("provider %s did not redirect: %d %s", p.Provider, w.Code, w.Body)
		}
		if p.TokenStorage {
			if u.Query().Get("code_challenge") == "" || u.Query().Get("state") == "" || !strings.HasSuffix(u.Query().Get("redirect_uri"), "/auth/google/callback") {
				t.Fatalf("BYO redirect lost callback/PKCE/state: %s", u)
			}
		} else if u.Host != "broker.example.com" || u.Query().Get("provider") != p.Provider {
			t.Fatalf("managed provider did not use broker: %s", u)
		}
	}
	if w := crudScopeRequest(t, mux, "GET", "/auth/google/callback?state=forged&code=forged", token, nil); w.Code != 400 {
		t.Fatalf("callback accepted missing state cookie: %d", w.Code)
	}
	if w := crudScopeRequest(t, mux, "GET", "/auth/github", token, nil); w.Code != 404 {
		t.Fatalf("incomplete provider unexpectedly registered: %d", w.Code)
	}
}

func TestCustomOAuthProvidersAreIsolatedAndDiscoverable(t *testing.T) {
	t.Setenv("BENMORE_OAUTH_BROKER_URL", "")
	for _, host := range []string{"one.example.com", "two.example.com"} {
		app, cleanup := newTestApp(t)
		defer cleanup()
		token := createCrudScopeSession(t, app, "owner@example.com", "user", "", "")
		writeTestFile(t, app.Dir, "app.yaml", "oauth:\n  custom:\n    auth_url: https://"+host+"/authorize\n    token_url: https://"+host+"/token\n    userinfo_url: https://"+host+"/userinfo\n")
		SetAppEnv(app.Dir, "CUSTOM_CLIENT_ID", "fixture-client")
		SetAppEnv(app.Dir, "CUSTOM_CLIENT_SECRET", "fixture-secret")
		if !HasOAuthProviders(app.Dir) || strings.Join(GetConfiguredProviders(app.Dir), ",") != "custom" {
			t.Fatal("custom-only provider is missing from login controls")
		}
		mux := http.NewServeMux()
		RegisterOAuthRoutes(mux, app)
		w := crudScopeRequest(t, mux, "GET", "/auth/custom", token, nil)
		u, err := url.Parse(w.Header().Get("Location"))
		if err != nil || u.Host != host {
			t.Fatalf("provider used another app's endpoint: %s (%v)", w.Header().Get("Location"), err)
		}
	}
	if _, leaked := oauthProviders["custom"]; leaked {
		t.Fatal("custom provider leaked into process defaults")
	}
	app, cleanup := newTestApp(t)
	defer cleanup()
	token := createCrudScopeSession(t, app, "owner@example.com", "user", "", "")
	mux := http.NewServeMux()
	RegisterOAuthRoutes(mux, app)
	w := crudScopeRequest(t, mux, "GET", "/api/_auth/oauth-providers", token, nil)
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("empty configuration should return an empty array: %d %s", w.Code, w.Body)
	}
}

func TestOAuthDisconnectIsolationAndDatabaseFailure(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	owner := createCrudScopeSession(t, app, "owner@example.com", "user", "", "")
	other := createCrudScopeSession(t, app, "other@example.com", "user", "", "")
	mux := http.NewServeMux()
	RegisterOAuthTokensAPI(mux, app)
	mustExec(t, app.DB, `INSERT INTO _benmore_oauth_tokens (user_id, provider, access_token) VALUES (1, 'google', 'fixture-access')`)
	for _, c := range []struct {
		token  string
		status int
	}{{"", 401}, {other, 404}, {owner, 200}, {owner, 404}} {
		w := crudScopeRequest(t, mux, "DELETE", "/api/_auth/oauth-tokens/google", c.token, nil)
		if w.Code != c.status {
			t.Fatalf("disconnect = %d, want %d: %s", w.Code, c.status, w.Body)
		}
	}
	if w := crudScopeRequest(t, mux, "GET", "/api/_auth/oauth-tokens", owner, nil); w.Code != 200 || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("disconnected state must be an empty array: %d %s", w.Code, w.Body)
	}
	mustExec(t, app.DB, `INSERT INTO _benmore_oauth_tokens (user_id, provider, access_token) VALUES (1, 'google', 'fixture-access')`)
	mustExec(t, app.DB, `CREATE TRIGGER reject_disconnect BEFORE DELETE ON _benmore_oauth_tokens BEGIN SELECT RAISE(ABORT, 'fixture failure'); END`)
	w := crudScopeRequest(t, mux, "DELETE", "/api/_auth/oauth-tokens/google", owner, nil)
	if w.Code != 500 {
		t.Fatalf("failed delete should return 500, got %d", w.Code)
	}
	w = crudScopeRequest(t, mux, "GET", "/api/_auth/oauth-tokens", owner, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "google") || strings.Contains(w.Body.String(), "fixture-access") {
		t.Fatalf("failed delete lost connection or exposed token: %d %s", w.Code, w.Body)
	}
}
