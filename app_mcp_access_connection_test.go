//go:build !cli && !windows

package main

import (
	"context"
	"errors"
	"github.com/mattn/go-sqlite3"
	"testing"
	"time"
)

func TestAppMCPAccessGrantRejectsDirtyConnectionAndRestoresPool(t *testing.T) {
	app, uid, _ := appMCPGrantFixture(t)
	now := time.Now()
	pair := fixtureGrant(t, app, uid, now)
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	hash, err := appMCPCredentialHash(pair.AccessToken, "access")
	if err != nil {
		t.Fatal(err)
	}
	grant, err := readAppMCPAccessGrant(context.Background(), app, hash, grantFixtureResource, now)
	if err != nil || grant.ID != pair.GrantID {
		t.Fatalf("valid grant: %+v %v", grant, err)
	}
	auditExec(t, app.DB, "UPDATE _benmore_mcp_credentials SET expires_at=0 WHERE kind='access'")
	auditExec(t, app.DB, "BEGIN")
	auditExec(t, app.DB, "UPDATE _benmore_mcp_credentials SET expires_at=? WHERE kind='access'", pair.AccessExpiresAt)
	if grant, err := readAppMCPAccessGrant(context.Background(), app, hash, grantFixtureResource, now); err == nil || grant != nil {
		t.Fatalf("uncommitted credential authorized: %+v %v", grant, err)
	}
	if grant, err := readAppMCPAccessGrant(context.Background(), app, hash, grantFixtureResource, now); err == nil || grant != nil {
		t.Fatalf("discarded transaction credential authorized: %+v %v", grant, err)
	}
	auditExec(t, app.DB, "UPDATE _benmore_mcp_credentials SET expires_at=? WHERE kind='access'", pair.AccessExpiresAt)
	if _, actor, err := resolveAppMCPAccessFor(context.Background(), app, pair.AccessToken, grantFixtureResource, now); err != nil || actor.UserID != uid {
		t.Fatalf("max1 pool did not recover canonical actor: %+v %v", actor, err)
	}
	rows, _, _, err := queryReadOnlyRowsCols(context.Background(), app.DB, "SELECT token_hash FROM _benmore_mcp_credentials", 10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("viewer read: %v %v", rows, err)
	}
	for _, row := range rows {
		if row["token_hash"] != nil {
			t.Fatal("internal comparison relaxed viewer hash mask")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if grant, err := readAppMCPAccessGrant(ctx, app, hash, grantFixtureResource, now); !errors.Is(err, context.Canceled) || grant != nil {
		t.Fatalf("canceled lookup: %+v %v", grant, err)
	}
	auditExec(t, app.DB, "UPDATE notes SET title='ordinary after cancel'")
}

func TestAppMCPAccessAuthorizerPreservesViewerControlRestrictions(t *testing.T) {
	app, uid, _ := appMCPGrantFixture(t)
	now := time.Now()
	pair := fixtureGrant(t, app, uid, now)
	hash, err := appMCPCredentialHash(pair.AccessToken, "access")
	if err != nil {
		t.Fatal(err)
	}
	if grant, err := readAppMCPAccessGrant(context.Background(), app, hash, "https://wrong.example/api/_mcp", now); err == nil || grant != nil {
		t.Fatal("wrong resource authorized")
	}
	if grant, err := readAppMCPAccessGrant(context.Background(), app, hash, grantFixtureResource, time.Unix(pair.AccessExpiresAt, 0)); err == nil || grant != nil {
		t.Fatal("expired credential authorized")
	}
	if authorizeAppMCPAccess(sqlite3.SQLITE_READ, "_benmore_mcp_credentials", "token_hash", "temp") != sqlite3.SQLITE_DENY {
		t.Fatal("temporary credential hash read expanded")
	}
	for _, action := range []int{sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_INSERT, sqlite3.SQLITE_DELETE, sqlite3.SQLITE_TRANSACTION, sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH, sqlite3.SQLITE_PRAGMA} {
		if authorizeAppMCPAccess(action, "_benmore_mcp_credentials", "token_hash", "main") != sqlite3.SQLITE_DENY {
			t.Fatalf("control action %d authorized", action)
		}
	}
	if authorizeAppMCPAccess(sqlite3.SQLITE_READ, "_benmore_users", "password_change_required", "main") != sqlite3.SQLITE_IGNORE {
		t.Fatal("unrelated masked account column expanded")
	}
}

func TestAppMCPAccessGrantIgnoresTemporaryAuthorityShadow(t *testing.T) {
	app, uid, _ := appMCPGrantFixture(t)
	now := time.Now()
	pair := fixtureGrant(t, app, uid, now)
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	hash, err := appMCPCredentialHash(pair.AccessToken, "access")
	if err != nil {
		t.Fatal(err)
	}
	auditExec(t, app.DB, "CREATE TEMP TABLE _benmore_mcp_credentials AS SELECT * FROM main._benmore_mcp_credentials")
	auditExec(t, app.DB, "UPDATE main._benmore_mcp_credentials SET expires_at=0 WHERE kind='access'")
	if grant, err := readAppMCPAccessGrant(context.Background(), app, hash, grantFixtureResource, now); err == nil || grant != nil {
		t.Errorf("temporary credentials replaced main authority: %+v %v", grant, err)
	}
	if _, actor, err := resolveAppMCPAccessFor(context.Background(), app, pair.AccessToken, grantFixtureResource, now); err == nil || actor != nil {
		t.Errorf("temporary credentials authorized dispatch: %+v %v", actor, err)
	}
	auditExec(t, app.DB, "UPDATE main._benmore_mcp_credentials SET expires_at=? WHERE kind='access'", pair.AccessExpiresAt)
	auditExec(t, app.DB, "CREATE TEMP TABLE _benmore_mcp_grants AS SELECT * FROM main._benmore_mcp_grants")
	auditExec(t, app.DB, "UPDATE temp._benmore_mcp_grants SET tenant='29'")
	grant, err := readAppMCPAccessGrant(context.Background(), app, hash, grantFixtureResource, now)
	if err != nil || grant.Tenant != "17" {
		t.Fatalf("temporary grant replaced main authority: %+v %v", grant, err)
	}
	if _, actor, err := resolveAppMCPAccessFor(context.Background(), app, pair.AccessToken, grantFixtureResource, now); err != nil || actor.GroupID != "17" {
		t.Fatalf("temporary grant substituted delegated tenant: %+v %v", actor, err)
	}
}
