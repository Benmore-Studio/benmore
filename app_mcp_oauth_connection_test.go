//go:build !cli && !windows

package main

import (
	"context"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
)

func TestAppMCPOAuthParserRejectsDirtyClientRegistrationAndRestoresPool(t *testing.T) {
	for _, column := range []string{"scopes", "redirect_uris"} {
		t.Run(column, func(t *testing.T) {
			app, _, values, _, _ := appMCPOAuthFixture(t)
			app.DB.SetMaxOpenConns(1)
			app.DB.SetMaxIdleConns(1)
			auditExec(t, app.DB, "BEGIN")
			if column == "scopes" {
				auditExec(t, app.DB, "UPDATE main._benmore_oauth_clients SET scopes='notes:read tasks:read' WHERE client_id='client-fixture'")
			} else {
				auditExec(t, app.DB, "UPDATE main._benmore_oauth_clients SET redirect_uris='[\"https://attacker.example/callback\"]' WHERE client_id='client-fixture'")
				values.Set("redirect_uri", "https://attacker.example/callback")
			}
			if _, err := parseAppMCPOAuthRequestFor(context.Background(), app, values, grantFixtureResource); err == nil {
				t.Fatal("dirty client registration authorized")
			}
			var scopes, redirects string
			if err := app.DB.QueryRow("SELECT scopes,redirect_uris FROM main._benmore_oauth_clients WHERE client_id='client-fixture'").Scan(&scopes, &redirects); err != nil || scopes != "notes:read" || redirects != "[\""+mcpOAuthFixtureRedirect+"\"]" {
				t.Fatalf("dirty client transaction survived: scopes=%q redirects=%q err=%v", scopes, redirects, err)
			}
			if _, err := app.DB.Exec("UPDATE main._benmore_oauth_clients SET name=name WHERE client_id='client-fixture'"); err != nil {
				t.Fatalf("ordinary write after protected query: %v", err)
			}
		})
	}
}

func TestAppMCPOAuthParserCannotUseTemporaryClientToWidenRegistration(t *testing.T) {
	app, _, values, _, _ := appMCPOAuthFixture(t)
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	auditExec(t, app.DB, "CREATE TEMP TABLE _benmore_oauth_clients AS SELECT * FROM main._benmore_oauth_clients")
	auditExec(t, app.DB, "UPDATE main._benmore_oauth_clients SET scopes='tasks:read' WHERE client_id='client-fixture'")
	auditExec(t, app.DB, "UPDATE temp._benmore_oauth_clients SET scopes='notes:read',redirect_uris='[\"https://attacker.example/callback\"]' WHERE client_id='client-fixture'")
	values.Set("redirect_uri", "https://attacker.example/callback")
	if _, err := parseAppMCPOAuthRequestFor(context.Background(), app, values, grantFixtureResource); err == nil {
		t.Fatal("temporary client widened registered scopes or redirect")
	}
	if _, err := app.DB.Exec("UPDATE main._benmore_oauth_clients SET name=name WHERE client_id='client-fixture'"); err != nil {
		t.Fatalf("ordinary write after protected query: %v", err)
	}
}

func TestAppMCPOAuthWorkspacesUsesPhysicalMainMembershipMetadata(t *testing.T) {
	app, session, _, _, _ := appMCPOAuthFixture(t)
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	auditExec(t, app.DB, "ALTER TABLE main.members ADD COLUMN deleted_at TEXT")
	auditExec(t, app.DB, "UPDATE main.members SET deleted_at='deleted' WHERE org_id='17' AND email=?", session.Email)
	auditExec(t, app.DB, "CREATE TEMP TABLE members AS SELECT * FROM main.members")
	auditExec(t, app.DB, "UPDATE temp.members SET deleted_at=NULL WHERE org_id='17' AND email=?", session.Email)

	workspaces, err := appMCPOAuthWorkspacesFor(context.Background(), app, session)
	if err != nil {
		t.Fatal(err)
	}
	var got17, got29 bool
	for _, workspace := range workspaces {
		got17 = got17 || workspace == "17"
		got29 = got29 || workspace == "29"
	}
	if got17 || !got29 {
		t.Fatalf("TEMP membership resurrected deleted main workspace: %v", workspaces)
	}
	if _, err := app.DB.Exec("UPDATE main.members SET org_id=org_id WHERE email=?", session.Email); err != nil {
		t.Fatalf("ordinary write after protected query: %v", err)
	}
}

func TestAppMCPDirectOAuthSessionUsesMainAuthorityOnly(t *testing.T) {
	for _, tc := range []struct {
		name, revoke string
	}{
		{"revoked session", "DELETE FROM main._benmore_sessions WHERE id=?"},
		{"pending password change", "UPDATE main._benmore_users SET password_change_required=1 WHERE id=?"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, session, _, _, _ := appMCPOAuthFixture(t)
			app.DB.SetMaxOpenConns(1)
			app.DB.SetMaxIdleConns(1)
			auditExec(t, app.DB, "CREATE TEMP TABLE _benmore_sessions AS SELECT * FROM main._benmore_sessions")
			auditExec(t, app.DB, "CREATE TEMP TABLE _benmore_users AS SELECT * FROM main._benmore_users")
			auditExec(t, app.DB, "UPDATE temp._benmore_users SET password_change_required=0 WHERE id=?", session.UserID)
			if tc.name == "revoked session" {
				auditExec(t, app.DB, tc.revoke, session.ID)
			} else {
				auditExec(t, app.DB, tc.revoke, session.UserID)
			}
			if got := appMCPDirectOAuthSessionFor(context.Background(), app, session); got != nil {
				t.Fatalf("TEMP session/account rows supplied direct-login authority: %+v", got)
			}
			if _, err := app.DB.Exec("UPDATE main._benmore_users SET role=role WHERE id=?", session.UserID); err != nil {
				t.Fatalf("ordinary write after protected query: %v", err)
			}
		})
	}
}

func TestAppMCPDirectOAuthSessionRejectsDirtyReactivationAndResetClear(t *testing.T) {
	for _, tc := range []struct {
		name, invalidate, dirty string
	}{
		{"session reactivation", "UPDATE main._benmore_sessions SET expires_at=? WHERE id=?", "UPDATE main._benmore_sessions SET expires_at=? WHERE id=?"},
		{"password reset clear", "UPDATE main._benmore_users SET password_change_required=1 WHERE id=?", "UPDATE main._benmore_users SET password_change_required=0 WHERE id=?"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, session, values, _, now := appMCPOAuthFixture(t)
			app.DB.SetMaxOpenConns(1)
			app.DB.SetMaxIdleConns(1)
			var expiredAt string
			if tc.name == "session reactivation" {
				expiredAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
				auditExec(t, app.DB, tc.invalidate, expiredAt, session.ID)
				auditExec(t, app.DB, "BEGIN")
				auditExec(t, app.DB, tc.dirty, time.Now().Add(time.Hour).UTC().Format(time.RFC3339), session.ID)
			} else {
				auditExec(t, app.DB, tc.invalidate, session.UserID)
				auditExec(t, app.DB, "BEGIN")
				auditExec(t, app.DB, tc.dirty, session.UserID)
			}
			if got := appMCPDirectOAuthSessionFor(context.Background(), app, session); got != nil {
				t.Fatalf("dirty authority state yielded consent session: %+v", got)
			}
			if _, err := prepareAppMCPOAuthConsentFor(context.Background(), app, session, values, grantFixtureResource, "17", now); err == nil {
				t.Fatal("dirty authority state yielded consent")
			}
			var expires string
			var pending int
			if err := app.DB.QueryRow("SELECT expires_at FROM main._benmore_sessions WHERE id=?", session.ID).Scan(&expires); err != nil {
				t.Fatal(err)
			}
			if err := app.DB.QueryRow("SELECT password_change_required FROM main._benmore_users WHERE id=?", session.UserID).Scan(&pending); err != nil {
				t.Fatal(err)
			}
			if tc.name == "session reactivation" && expires != expiredAt {
				t.Fatalf("dirty session reactivation survived: %q", expires)
			}
			if tc.name == "password reset clear" && pending != 1 {
				t.Fatalf("dirty reset-flag clear survived: %d", pending)
			}
			if _, err := app.DB.Exec("UPDATE main._benmore_users SET role=role WHERE id=?", session.UserID); err != nil {
				t.Fatalf("ordinary write after protected query: %v", err)
			}
		})
	}
}

func TestAppMCPOAuthCanceledDirectSessionReadRejectsAndRestoresPool(t *testing.T) {
	app, session, _, _, _ := appMCPOAuthFixture(t)
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	auditExec(t, app.DB, "CREATE TABLE session_read_effects(id INTEGER)")
	auditExec(t, app.DB, "ALTER TABLE main._benmore_users RENAME TO _benmore_users_session_backing")
	auditExec(t, app.DB, `CREATE VIEW main._benmore_users AS SELECT id,email,CASE WHEN oauth_session_read_started()=1 THEN role ELSE role END AS role,deactivated_at,verified,email_grandfathered,password_change_required,created_at FROM _benmore_users_session_backing`)
	conn, err := app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	started, unblock := make(chan struct{}, 1), make(chan struct{})
	err = conn.Raw(func(raw any) error {
		native := raw.(*sqlite3.SQLiteConn)
		return native.RegisterFunc("oauth_session_read_started", func() int64 {
			_, _ = native.Exec("INSERT INTO session_read_effects VALUES(1)", nil)
			select {
			case started <- struct{}{}:
			default:
			}
			<-unblock
			return 1
		}, false)
	})
	_ = conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan *Session, 1)
	go func() { done <- appMCPDirectOAuthSessionFor(ctx, app, session) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		close(unblock)
		t.Fatal("direct-session SQL never started")
	}
	cancel()
	close(unblock)
	select {
	case got := <-done:
		if got != nil {
			t.Fatalf("canceled direct-session read authorized: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled direct-session read did not finish")
	}
	var effects int
	if err := app.DB.QueryRow("SELECT count(*) FROM main.session_read_effects").Scan(&effects); err != nil || effects != 0 {
		t.Fatalf("protected read caused side effect: %d %v", effects, err)
	}
	if _, err := app.DB.Exec("INSERT INTO main.session_read_effects VALUES(2)"); err != nil {
		t.Fatalf("ordinary write after canceled read: %v", err)
	}
}

func TestAppMCPOAuthInvalidMainConsentCannotFallBackToTemporaryCopy(t *testing.T) {
	app, session, values, _, now := appMCPOAuthFixture(t)
	consent, err := prepareAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", now)
	if err != nil {
		t.Fatal(err)
	}
	key, err := appMCPCredentialHash(consent.Nonce, "consent")
	if err != nil {
		t.Fatal(err)
	}
	var validPayload string
	if err := app.DB.QueryRow("SELECT payload FROM main._benmore_mcp_authorizations WHERE key_hash=?", key).Scan(&validPayload); err != nil {
		t.Fatal(err)
	}
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	auditExec(t, app.DB, "CREATE TEMP TABLE _benmore_mcp_authorizations AS SELECT * FROM main._benmore_mcp_authorizations")
	auditExec(t, app.DB, "UPDATE main._benmore_mcp_authorizations SET payload='{}' WHERE key_hash=?", key)
	auditExec(t, app.DB, "UPDATE temp._benmore_mcp_authorizations SET payload=? WHERE key_hash=?", validPayload, key)
	if _, _, err := readAppMCPOAuthAuthorizationFor(context.Background(), app, consent.Nonce, "consent", now); err == nil {
		t.Fatal("invalid main consent fell back to TEMP payload")
	}
	if _, err := approveAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", consent.Nonce, consent.Token, now); err == nil {
		t.Fatal("TEMP payload supplied consent or yielded a code")
	}
	var used int
	if err := app.DB.QueryRow("SELECT used FROM main._benmore_mcp_authorizations WHERE key_hash=?", key).Scan(&used); err != nil || used != 0 {
		t.Fatalf("invalid main consent consumed nonce: used=%d err=%v", used, err)
	}
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_authorizations SET payload=payload WHERE key_hash=?", key); err != nil {
		t.Fatalf("ordinary write after protected query: %v", err)
	}
}

func TestAppMCPOAuthClaimsAndStoresOnlyMainAuthorizations(t *testing.T) {
	app, session, values, verifier, now := appMCPOAuthFixture(t)
	consent, err := prepareAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", now)
	if err != nil {
		t.Fatal(err)
	}
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	auditExec(t, app.DB, "CREATE TEMP TABLE _benmore_mcp_authorizations AS SELECT * FROM main._benmore_mcp_authorizations")
	code, err := approveAppMCPOAuthConsent(app, session, values, grantFixtureResource, "17", consent.Nonce, consent.Token, now)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := exchangeAppMCPOAuthCode(app, code, "client-fixture", mcpOAuthFixtureRedirect, grantFixtureResource, verifier, grantFixtureResource, now)
	if err != nil {
		t.Fatal(err)
	}
	var mainUsed, tempUsed, mainCount, tempCount int
	for _, check := range []struct {
		query string
		dest  *int
	}{
		{"SELECT sum(used) FROM main._benmore_mcp_authorizations", &mainUsed},
		{"SELECT sum(used) FROM temp._benmore_mcp_authorizations", &tempUsed},
		{"SELECT count(*) FROM main._benmore_mcp_authorizations", &mainCount},
		{"SELECT count(*) FROM temp._benmore_mcp_authorizations", &tempCount},
	} {
		if err := app.DB.QueryRow(check.query).Scan(check.dest); err != nil {
			t.Fatal(err)
		}
	}
	if mainUsed != 2 || tempUsed != 0 || mainCount != 2 || tempCount != 1 {
		t.Fatalf("authorization writes crossed database boundary: mainUsed=%d tempUsed=%d mainCount=%d tempCount=%d", mainUsed, tempUsed, mainCount, tempCount)
	}
	if _, _, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, now); err != nil {
		t.Fatalf("main code exchange did not mint usable credential: %v", err)
	}
}
