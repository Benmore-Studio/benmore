//go:build !cli && !windows

package main

import (
	"database/sql"
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const mcpOAuthFixtureRedirect = "https://client.example/callback"

func appMCPOAuthFixture(t *testing.T) (*App, *Session, url.Values, string, time.Time) {
	t.Helper()
	app, _, _ := appMCPGrantFixture(t)
	sid := createCrudScopeSession(t, app, "oauth-owner@example.com", "editor", "17", "")
	session := GetSessionFromDB(app.DB, sid)
	auditExec(t, app.DB, "INSERT INTO members(org_id,email) VALUES ('17',?),('29',?)", session.Email, session.Email)
	appOAuthEnsureTables(app)
	auditExec(t, app.DB, "INSERT INTO _benmore_oauth_clients(client_id,name,redirect_uris,scopes) VALUES ('client-fixture','Reviewed client',?,'notes:read')", `["`+mcpOAuthFixtureRedirect+`"]`)
	verifier := strings.Repeat("v", 43)
	values := url.Values{"response_type": {"code"}, "client_id": {"client-fixture"}, "redirect_uri": {mcpOAuthFixtureRedirect}, "state": {"client-state"}, "scope": {"notes:read"}, "code_challenge": {oauthPKCEChallenge(verifier)}, "code_challenge_method": {"S256"}, "resource": {grantFixtureResource}}
	return app, session, values, verifier, time.Now()
}
func fixtureMCPCode(t *testing.T, app *App, session *Session, values url.Values, now time.Time) (string, *appMCPOAuthConsent) {
	t.Helper()
	consent, err := prepareAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", now)
	if err != nil {
		t.Fatal(err)
	}
	code, err := approveAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", consent.Nonce, consent.Token, now)
	if err != nil {
		t.Fatal(err)
	}
	return code, consent
}
func TestAppMCPOAuthCodeBindsConsentAndMintsNarrowCredentials(t *testing.T) {
	app, session, values, verifier, now := appMCPOAuthFixture(t)
	code, consent := fixtureMCPCode(t, app, session, values, now)
	if _, err := approveAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", consent.Nonce, consent.Token, now); err == nil {
		t.Fatal("consent replay issued second code")
	}
	pair, err := exchangeAppMCPOAuthCode(app, code, "client-fixture", mcpOAuthFixtureRedirect, grantFixtureResource, verifier, grantFixtureResource, now)
	if err != nil {
		t.Fatal(err)
	}
	grant, actor, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, now)
	if err != nil || grant.UserID != session.UserID || grant.Tenant != "17" || actor.IsAdminBypass() || pair.Scopes != "notes:read" || pair.AccessExpiresAt != now.Add(15*time.Minute).Unix() || pair.GrantExpiresAt != now.Add(30*24*time.Hour).Unix() {
		t.Fatalf("wrong code grant: %+v %+v %v", grant, pair, err)
	}
	if _, err := exchangeAppMCPOAuthCode(app, code, "client-fixture", mcpOAuthFixtureRedirect, grantFixtureResource, verifier, grantFixtureResource, now); err == nil {
		t.Fatal("code reused")
	}
	rows, err := QueryRows(app.DB, "SELECT key_hash,payload FROM _benmore_mcp_authorizations")
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		text := row["key_hash"].(string) + row["payload"].(string)
		if strings.Contains(text, code) || strings.Contains(text, consent.Nonce) || strings.Contains(text, consent.Token) || strings.Contains(text, verifier) {
			t.Fatal("raw OAuth credential persisted")
		}
	}
}
func TestAppMCPOAuthConsentRejectsDelegationAndTupleChanges(t *testing.T) {
	app, session, values, _, now := appMCPOAuthFixture(t)
	consent, err := prepareAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := approveAppMCPOAuthConsent(app, session, values, grantFixtureResource, "29", consent.Nonce, consent.Token, now); err == nil {
		t.Fatal("consent tenant changed")
	}
	changed := cloneMCPOAuthValues(values)
	changed.Set("state", "changed")
	if _, err := approveAppMCPOAuthConsent(app, session, changed, grantFixtureResource, "17", consent.Nonce, consent.Token, now); err == nil {
		t.Fatal("consent state changed")
	}
	otherSID := CreateSession(app.DB, session.UserID, session.Email, "17", time.Hour)
	if _, err := approveAppMCPOAuthConsent(app, GetSessionFromDB(app.DB, otherSID), values, grantFixtureResource, "17", consent.Nonce, consent.Token, now); err == nil {
		t.Fatal("consent moved to another login")
	}
	scopedSID := CreateSession(app.DB, session.UserID, session.Email, "17", time.Hour, "notes:read")
	if _, err := prepareAppMCPOAuthConsent(app, GetSessionFromDB(app.DB, scopedSID), values, grantFixtureResource, "17", now); err == nil {
		t.Fatal("delegated login approved connector")
	}
	if _, err := prepareAppMCPOAuthConsent(app, session, values, grantFixtureResource, "", now); err == nil {
		t.Fatal("tenant inferred silently")
	}
	if _, err := approveAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", consent.Nonce, consent.Token, now); err != nil {
		t.Fatalf("invalid attempts consumed valid consent: %v", err)
	}
}

func TestAppMCPOAuthExpiredOrRevokedLoginCannotPrepareOrApprove(t *testing.T) {
	for _, tc := range []struct {
		name, step string
		revoke     bool
	}{
		{"expired before prepare", "prepare", false},
		{"revoked before prepare", "prepare", true},
		{"expired before approve", "approve", false},
		{"revoked before approve", "approve", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, session, values, _, now := appMCPOAuthFixture(t)
			var consent *appMCPOAuthConsent
			if tc.step == "approve" {
				var err error
				consent, err = prepareAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", now)
				if err != nil {
					t.Fatal(err)
				}
			}
			if tc.revoke {
				auditExec(t, app.DB, "DELETE FROM _benmore_sessions WHERE id=?", session.ID)
			} else {
				auditExec(t, app.DB, "UPDATE _benmore_sessions SET expires_at=? WHERE id=?", time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), session.ID)
			}
			if tc.step == "prepare" {
				if _, err := prepareAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", now); err == nil {
					t.Fatal("invalid login prepared consent")
				}
				return
			}
			if _, err := approveAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", consent.Nonce, consent.Token, now); err == nil {
				t.Fatal("invalid login approved consent")
			}
		})
	}
}

func TestAppMCPOAuthMembershipRemovalDeniesApproveAndExchange(t *testing.T) {
	t.Run("before approve", func(t *testing.T) {
		app, session, values, _, now := appMCPOAuthFixture(t)
		consent, err := prepareAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", now)
		if err != nil {
			t.Fatal(err)
		}
		auditExec(t, app.DB, "DELETE FROM members WHERE org_id='17' AND email=?", session.Email)
		if _, err := approveAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", consent.Nonce, consent.Token, now); err == nil {
			t.Fatal("approval succeeded after tenant membership removal")
		}
	})
	t.Run("before exchange", func(t *testing.T) {
		app, session, values, verifier, now := appMCPOAuthFixture(t)
		code, _ := fixtureMCPCode(t, app, session, values, now)
		auditExec(t, app.DB, "DELETE FROM members WHERE org_id='17' AND email=?", session.Email)
		if _, err := exchangeAppMCPOAuthCode(app, code, "client-fixture", mcpOAuthFixtureRedirect, grantFixtureResource, verifier, grantFixtureResource, now); err == nil {
			t.Fatal("exchange succeeded after tenant membership removal")
		}
	})
}

func TestAppMCPOAuthExpiredConsentAndCodeDenied(t *testing.T) {
	app, session, values, _, now := appMCPOAuthFixture(t)
	consent, err := prepareAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := approveAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", consent.Nonce, consent.Token, now.Add(oauthConsentTTL+time.Second)); err == nil {
		t.Fatal("expired consent approved")
	}

	app, session, values, verifier, now := appMCPOAuthFixture(t)
	code, _ := fixtureMCPCode(t, app, session, values, now)
	if _, err := exchangeAppMCPOAuthCode(app, code, "client-fixture", mcpOAuthFixtureRedirect, grantFixtureResource, verifier, grantFixtureResource, now.Add(appOAuthCodeTTL+time.Second)); err == nil {
		t.Fatal("expired code exchanged")
	}
}

func TestAppMCPOAuthMalformedAuthorizationBindingDenied(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*appMCPOAuthBinding)
	}{
		{"user", func(b *appMCPOAuthBinding) { b.Grant.UserID++ }},
		{"app", func(b *appMCPOAuthBinding) { b.Grant.App = "other-app" }},
		{"client", func(b *appMCPOAuthBinding) { b.Grant.Client = "other-client" }},
		{"resource", func(b *appMCPOAuthBinding) { b.Grant.Resource = "https://other.example/api/_mcp" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, session, values, _, now := appMCPOAuthFixture(t)
			consent, err := prepareAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", now)
			if err != nil {
				t.Fatal(err)
			}
			key, err := appMCPCredentialHash(consent.Nonce, "consent")
			if err != nil {
				t.Fatal(err)
			}
			var payload string
			if err := app.DB.QueryRow("SELECT payload FROM _benmore_mcp_authorizations WHERE key_hash=?", key).Scan(&payload); err != nil {
				t.Fatal(err)
			}
			var binding appMCPOAuthBinding
			if err := json.Unmarshal([]byte(payload), &binding); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&binding)
			malformed, err := json.Marshal(&binding)
			if err != nil {
				t.Fatal(err)
			}
			auditExec(t, app.DB, "UPDATE _benmore_mcp_authorizations SET payload=? WHERE key_hash=?", string(malformed), key)
			if _, err := approveAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", consent.Nonce, consent.Token, now); err == nil {
				t.Fatal("inconsistent persisted authorization binding accepted")
			}
		})
	}
}

// claude.ai asks for its own "claudeai" scope; scopes with no resource part
// are dropped and the client's registered scopes apply instead.
func TestAppMCPOAuthDropsClientDefinedScopes(t *testing.T) {
	app, session, values, _, now := appMCPOAuthFixture(t)
	for _, scope := range []string{"claudeai", "openid offline_access", "claudeai notes:read"} {
		request := cloneMCPOAuthValues(values)
		request.Set("scope", scope)
		p, err := parseAppMCPOAuthRequest(app, request, grantFixtureResource)
		if err != nil || p.Scope != "notes:read" {
			t.Errorf("scope %q: %q %v", scope, p.Scope, err)
		}
		if _, err := prepareAppMCPOAuthConsent(app, session, request, grantFixtureResource, "17", now); err != nil {
			t.Errorf("scope %q consent: %v", scope, err)
		}
	}
}

func TestAppMCPOAuthRejectsInvalidScopeRedirectAndPKCE(t *testing.T) {
	app, session, values, _, now := appMCPOAuthFixture(t)
	for _, mutation := range []struct{ key, value string }{{"scope", ""}, {"scope", "*"}, {"scope", "*:*"}, {"scope", "unknown:read"}, {"scope", "notes:read unknown:read"}, {"scope", "claudeai unknown:read"}, {"resource", "https://other.example/api/_mcp"}, {"redirect_uri", mcpOAuthFixtureRedirect + "/"}, {"code_challenge", "invalid"}, {"code_challenge_method", "plain"}, {"state", ""}} {
		request := cloneMCPOAuthValues(values)
		request.Set(mutation.key, mutation.value)
		if _, err := prepareAppMCPOAuthConsent(app, session, request, grantFixtureResource, "17", now); err == nil {
			t.Fatalf("invalid %s accepted", mutation.key)
		}
	}
	duplicate := cloneMCPOAuthValues(values)
	duplicate.Add("resource", grantFixtureResource)
	if _, err := prepareAppMCPOAuthConsent(app, session, duplicate, grantFixtureResource, "17", now); err == nil {
		t.Fatal("duplicate resource accepted")
	}
	for _, redirect := range []string{"file://localhost/callback", "ftp://localhost/callback", "javascript://localhost/callback", "http://10.0.0.1/callback", "https://client.example/callback#fragment"} {
		if validAppMCPOAuthRedirect(redirect) {
			t.Fatalf("unsafe redirect: %s", redirect)
		}
	}
	for _, verifier := range []string{"short", strings.Repeat("v", 129), strings.Repeat("v", 42) + "!"} {
		if validAppMCPPKCEVerifier(verifier) {
			t.Fatal("invalid verifier accepted")
		}
	}
}
func TestAppMCPOAuthFailedExchangeBurnsCodeAndRestoreCannotRevive(t *testing.T) {
	app, session, values, verifier, now := appMCPOAuthFixture(t)
	code, _ := fixtureMCPCode(t, app, session, values, now)
	if _, err := exchangeAppMCPOAuthCode(app, code, "wrong-client", mcpOAuthFixtureRedirect, grantFixtureResource, verifier, grantFixtureResource, now); err == nil {
		t.Fatal("wrong client accepted")
	}
	if _, err := exchangeAppMCPOAuthCode(app, code, "client-fixture", mcpOAuthFixtureRedirect, grantFixtureResource, verifier, grantFixtureResource, now); err == nil {
		t.Fatal("failed code reused")
	}
	code, _ = fixtureMCPCode(t, app, session, values, now)
	if err := invalidateAppMCPForRestore(app.Dir); err != nil {
		t.Fatal(err)
	}
	if _, err := updateAppMCPEpoch(app.Dir, true, false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := exchangeAppMCPOAuthCode(app, code, "client-fixture", mcpOAuthFixtureRedirect, grantFixtureResource, verifier, grantFixtureResource, now); err == nil {
		t.Fatal("old consent epoch minted new grant after restore")
	}
}
func TestAppMCPOAuthConcurrentCodeExchangeHasSingleWinner(t *testing.T) {
	for _, mode := range []string{"default", "deferred WAL"} {
		t.Run(mode, func(t *testing.T) {
			app, session, values, verifier, now := appMCPOAuthFixture(t)
			if mode == "deferred WAL" {
				if err := app.DB.Close(); err != nil {
					t.Fatal(err)
				}
				db, err := sql.Open("sqlite3", filepath.Join(app.Dir, "data.db")+"?_journal_mode=WAL&_busy_timeout=0")
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				app.DB = db
			}
			code, _ := fixtureMCPCode(t, app, session, values, now)
			var wait sync.WaitGroup
			start := make(chan struct{})
			pairs := make(chan *appMCPTokenPair, 2)
			for range 2 {
				wait.Add(1)
				go func() {
					defer wait.Done()
					<-start
					pair, err := exchangeAppMCPOAuthCode(app, code, "client-fixture", mcpOAuthFixtureRedirect, grantFixtureResource, verifier, grantFixtureResource, now)
					if err == nil {
						pairs <- pair
					}
				}()
			}
			close(start)
			wait.Wait()
			if len(pairs) != 1 {
				t.Fatalf("code exchange winners: %d", len(pairs))
			}
		})
	}
}

func TestAppMCPOAuthConcurrentConsentApprovalHasSingleWinner(t *testing.T) {
	app, session, values, _, now := appMCPOAuthFixture(t)
	consent, err := prepareAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", now)
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	start := make(chan struct{})
	codes := make(chan string, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			code, err := approveAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", consent.Nonce, consent.Token, now)
			if err == nil {
				codes <- code
			}
		}()
	}
	close(start)
	wait.Wait()
	if len(codes) != 1 {
		t.Fatalf("consent approval winners: %d", len(codes))
	}
}

func cloneMCPOAuthValues(values url.Values) url.Values {
	copy := make(url.Values, len(values))
	for key, value := range values {
		copy[key] = append([]string(nil), value...)
	}
	return copy
}

// Each consent page load stores a consent row. Expired consents and codes
// can never be claimed, so a later store drops them instead of letting a
// signed-in user grow the table without bound.
func TestAppMCPOAuthExpiredAuthorizationsArePrunedOnStore(t *testing.T) {
	app, session, values, _, now := appMCPOAuthFixture(t)
	for i := 0; i < 3; i++ {
		if _, err := prepareAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", now); err != nil {
			t.Fatal(err)
		}
	}
	fixtureMCPCode(t, app, session, values, now)
	count := func() int {
		var n int
		if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_mcp_authorizations").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(); n != 5 {
		t.Fatalf("live authorizations: %d", n)
	}
	later := now.Add(oauthConsentTTL + time.Minute)
	consent, err := prepareAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", later)
	if err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 1 {
		t.Fatalf("expired consents and codes were kept: %d rows", n)
	}
	if _, err := approveAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", consent.Nonce, consent.Token, later); err != nil {
		t.Fatalf("live consent pruned: %v", err)
	}
}
