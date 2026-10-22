//go:build !cli && !windows

package main

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAppMCPRefreshPreflightUsesMainCredentialExpiry(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	auditExec(t, app.DB, "CREATE TEMP TABLE _benmore_mcp_credentials AS SELECT * FROM main._benmore_mcp_credentials")
	auditExec(t, app.DB, "CREATE TEMP TABLE _benmore_mcp_grants AS SELECT * FROM main._benmore_mcp_grants")
	auditExec(t, app.DB, "UPDATE main._benmore_mcp_credentials SET expires_at=0 WHERE token_hash=?", mustAppMCPCredentialHash(t, pair.RefreshToken, "refresh"))

	if _, err := refreshAppMCPGrant(app, pair.RefreshToken, "client-fixture", grantFixtureResource, now); err == nil {
		t.Fatal("temporary credential copy replaced expired main credential")
	}
	var used, revoked int
	if err := app.DB.QueryRow("SELECT used FROM main._benmore_mcp_credentials WHERE token_hash=?", mustAppMCPCredentialHash(t, pair.RefreshToken, "refresh")).Scan(&used); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow("SELECT revoked FROM main._benmore_mcp_grants WHERE id=?", pair.GrantID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if used != 0 || revoked != 0 {
		t.Fatalf("invalid preflight changed main family: used=%d revoked=%d", used, revoked)
	}
}

func TestAppMCPRefreshWritesOnlyMainWithTemporaryShadows(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	auditExec(t, app.DB, "CREATE TEMP TABLE _benmore_mcp_credentials AS SELECT * FROM main._benmore_mcp_credentials")
	auditExec(t, app.DB, "CREATE TEMP TABLE _benmore_mcp_grants AS SELECT * FROM main._benmore_mcp_grants")

	rotated, err := refreshAppMCPGrant(app, pair.RefreshToken, "client-fixture", grantFixtureResource, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("refresh with temporary shadows: %v", err)
	}
	oldHash := mustAppMCPCredentialHash(t, pair.RefreshToken, "refresh")
	newRefreshHash := mustAppMCPCredentialHash(t, rotated.RefreshToken, "refresh")
	var mainUsed, tempUsed, mainCount, tempCount, mainRevoked, tempRevoked int
	if err := app.DB.QueryRow("SELECT used FROM main._benmore_mcp_credentials WHERE token_hash=?", oldHash).Scan(&mainUsed); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow("SELECT used FROM temp._benmore_mcp_credentials WHERE token_hash=?", oldHash).Scan(&tempUsed); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow("SELECT count(*) FROM main._benmore_mcp_credentials WHERE grant_id=?", pair.GrantID).Scan(&mainCount); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow("SELECT count(*) FROM temp._benmore_mcp_credentials WHERE grant_id=?", pair.GrantID).Scan(&tempCount); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow("SELECT revoked FROM main._benmore_mcp_grants WHERE id=?", pair.GrantID).Scan(&mainRevoked); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow("SELECT revoked FROM temp._benmore_mcp_grants WHERE id=?", pair.GrantID).Scan(&tempRevoked); err != nil {
		t.Fatal(err)
	}
	var newMain int
	if err := app.DB.QueryRow("SELECT count(*) FROM main._benmore_mcp_credentials WHERE token_hash=? AND kind='refresh'", newRefreshHash).Scan(&newMain); err != nil {
		t.Fatal(err)
	}
	if mainUsed != 1 || tempUsed != 0 || mainCount != 4 || tempCount != 2 || mainRevoked != 0 || tempRevoked != 0 || newMain != 1 {
		t.Fatalf("refresh crossed database boundary: mainUsed=%d tempUsed=%d mainCount=%d tempCount=%d mainRevoked=%d tempRevoked=%d newMain=%d", mainUsed, tempUsed, mainCount, tempCount, mainRevoked, tempRevoked, newMain)
	}
}

func TestAppMCPRefreshDiscardsUncommittedCredentialResurrection(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	if _, err := refreshAppMCPGrant(app, pair.RefreshToken, "client-fixture", grantFixtureResource, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	hash := mustAppMCPCredentialHash(t, pair.RefreshToken, "refresh")
	auditExec(t, app.DB, "BEGIN")
	auditExec(t, app.DB, "UPDATE main._benmore_mcp_credentials SET used=0 WHERE token_hash=?", hash)
	if _, err := refreshAppMCPGrant(app, pair.RefreshToken, "client-fixture", grantFixtureResource, now.Add(2*time.Minute)); err == nil {
		t.Fatal("uncommitted credential resurrection authorized refresh")
	}
	var used, revoked int
	if err := app.DB.QueryRow("SELECT used FROM main._benmore_mcp_credentials WHERE token_hash=?", hash).Scan(&used); err != nil {
		t.Fatal(err)
	}
	if used != 1 {
		t.Fatalf("discarded pooled state changed spent main credential: used=%d", used)
	}
	if err := app.DB.QueryRow("SELECT revoked FROM main._benmore_mcp_grants WHERE id=?", pair.GrantID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked != 0 {
		t.Fatal("dirty credential rejection prematurely revoked main grant")
	}
	auditExec(t, app.DB, "UPDATE notes SET title='ordinary after dirty credential rejection'")
	if _, err := refreshAppMCPGrant(app, pair.RefreshToken, "client-fixture", grantFixtureResource, now.Add(3*time.Minute)); err == nil {
		t.Fatal("replayed refresh accepted")
	}
	if err := app.DB.QueryRow("SELECT revoked FROM main._benmore_mcp_grants WHERE id=?", pair.GrantID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked != 1 {
		t.Fatal("spent main refresh replay did not revoke its grant")
	}
}

func TestAppMCPCredentialReaderAllowsExpiredOnlyForRevocation(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	hash := mustAppMCPCredentialHash(t, pair.AccessToken, "access")
	later := time.Unix(pair.AccessExpiresAt+1, 0)
	grant, err := readAppMCPCredentialGrant(context.Background(), app, hash, "access", grantFixtureResource, later, false)
	if err != nil || grant.ID != pair.GrantID {
		t.Fatalf("expired credential unavailable for revocation: %+v %v", grant, err)
	}
	if grant, err := readAppMCPCredentialGrant(context.Background(), app, hash, "access", grantFixtureResource, later, true); err == nil || grant != nil {
		t.Fatalf("expired credential accepted for live use: %+v %v", grant, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if grant, err := readAppMCPCredentialGrant(ctx, app, hash, "access", grantFixtureResource, now, false); !errors.Is(err, context.Canceled) || grant != nil {
		t.Fatalf("canceled credential lookup: %+v %v", grant, err)
	}
	if _, err := refreshAppMCPGrantFor(ctx, app, pair.RefreshToken, "client-fixture", grantFixtureResource, "", now); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled refresh preflight lost context error: %v", err)
	}
}

func TestAppMCPOAuthRevokeAcceptsExpiredCredentialsAndChecksClient(t *testing.T) {
	app, uid, _ := appMCPGrantFixture(t)
	old := time.Now().Add(-31 * 24 * time.Hour)
	for _, kind := range []string{"refresh", "access"} {
		pair := fixtureGrant(t, app, uid, old)
		raw := pair.RefreshToken
		if kind == "access" {
			raw = pair.AccessToken
		}
		w := appMCPRevokeRequest(app, raw, "client-fixture")
		if w.Code != 200 {
			t.Fatalf("expired %s revoke status=%d body=%s", kind, w.Code, w.Body.String())
		}
		var revoked int
		if err := app.DB.QueryRow("SELECT revoked FROM main._benmore_mcp_grants WHERE id=?", pair.GrantID).Scan(&revoked); err != nil {
			t.Fatal(err)
		}
		if revoked != 1 {
			t.Fatalf("expired %s credential did not revoke grant", kind)
		}
	}

	pair := fixtureGrant(t, app, uid, time.Now())
	w := appMCPRevokeRequest(app, pair.RefreshToken, "other-client")
	if w.Code != 200 {
		t.Fatalf("client-mismatched revoke status=%d body=%s", w.Code, w.Body.String())
	}
	var revoked int
	if err := app.DB.QueryRow("SELECT revoked FROM main._benmore_mcp_grants WHERE id=?", pair.GrantID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked != 0 {
		t.Fatal("client-mismatched revoke revoked grant")
	}
}

func appMCPRevokeRequest(app *App, raw, client string) *httptest.ResponseRecorder {
	form := url.Values{"client_id": {client}, "resource": {grantFixtureResource}, "token": {raw}}
	req := httptest.NewRequest("POST", "https://fixture.example/api/_mcp/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	appMCPOAuthRevoke(w, req, app, grantFixtureResource)
	return w
}

func mustAppMCPCredentialHash(t *testing.T, raw, kind string) string {
	t.Helper()
	hash, err := appMCPCredentialHash(raw, kind)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}
