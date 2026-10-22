//go:build !cli && !windows

package main

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const grantFixtureResource = "https://fixture.example/api/_mcp"

func appMCPGrantFixture(t *testing.T) (*App, int64, time.Time) {
	t.Helper()
	epochFixture(t)
	app, _ := auditApp(t)
	// auditApp bypasses the production loader. Match its always-on per-app
	// encryption-key registration without mutating the process-global key.
	testKey, err := cryptoDeriveAppKey(strings.Repeat("42", 32))
	if err != nil {
		t.Fatal(err)
	}
	RegisterDBEncryptionKey(filepath.Join(app.Dir, "data.db"), testKey)
	if err := EnsureUserRolesTable(app.DB); err != nil {
		t.Fatal(err)
	}
	sid := createCrudScopeSession(t, app, "delegate@example.com", "editor", "17", "")
	uid := GetSessionFromDB(app.DB, sid).UserID
	auditExec(t, app.DB, "INSERT INTO members(org_id,email) VALUES ('17',?),('29',?)", "delegate@example.com", "delegate@example.com")
	app.Roles = &RolesConfig{Roles: map[string]RoleDef{"editor": {Scopes: "notes:read"}, "admin": {Scopes: "notes:read"}}}
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);\n")
	writeTestFile(t, app.Dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	app.MCP = config.mcp
	if err := ensureAppMCPGrantTables(app.DB); err != nil {
		t.Fatal(err)
	}
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatal(err)
	}
	return app, uid, time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
}
func fixtureGrant(t *testing.T, app *App, uid int64, now time.Time) *appMCPTokenPair {
	t.Helper()
	pair, err := createAppMCPGrant(app, uid, "17", "client-fixture", grantFixtureResource, "notes:read", now)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}
func TestAppMCPGrantFixedLifetimeAndHashedCredentials(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	if pair.AccessExpiresAt != now.Add(15*time.Minute).Unix() || pair.GrantExpiresAt != now.Add(30*24*time.Hour).Unix() || pair.Scopes != "notes:read" {
		t.Fatalf("wrong lifecycle: %+v", pair)
	}
	rows, err := QueryRows(app.DB, "SELECT token_hash FROM _benmore_mcp_credentials")
	if err != nil || len(rows) != 2 {
		t.Fatalf("credentials: %v %v", rows, err)
	}
	for _, row := range rows {
		stored := row["token_hash"].(string)
		if stored == pair.AccessToken || stored == pair.RefreshToken || len(stored) != 64 {
			t.Fatal("raw credential persisted")
		}
		if _, _, err := resolveAppMCPAccess(app, stored, grantFixtureResource, now); err == nil {
			t.Fatal("stored hash accepted as bearer")
		}
	}
	grant, actor, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, now)
	if err != nil || grant.Client != "client-fixture" || actor.UserID != uid || actor.GroupID != "17" || actor.IsAdminBypass() || actor.CredentialScopes != "notes:read" {
		t.Fatalf("wrong pinned identity: %v %+v %v", grant, actor, err)
	}
	if _, _, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, now.Add(15*time.Minute)); err == nil {
		t.Fatal("expired access accepted")
	}
	later := now.Add(30*24*time.Hour - time.Minute)
	rotated, err := refreshAppMCPGrant(app, pair.RefreshToken, "client-fixture", grantFixtureResource, later)
	if err != nil || rotated.GrantExpiresAt != pair.GrantExpiresAt || rotated.AccessExpiresAt != pair.GrantExpiresAt {
		t.Fatalf("refresh extended fixed chain: %+v %v", rotated, err)
	}
	if _, err := refreshAppMCPGrant(app, rotated.RefreshToken, "client-fixture", grantFixtureResource, now.Add(30*24*time.Hour)); err == nil {
		t.Fatal("expired fixed chain refreshed")
	}
}
func TestAppMCPGrantRefreshReuseRevokesWholeChain(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	rotated, err := refreshAppMCPGrant(app, pair.RefreshToken, "client-fixture", grantFixtureResource, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := refreshAppMCPGrant(app, pair.RefreshToken, "client-fixture", grantFixtureResource, now.Add(2*time.Minute)); err == nil {
		t.Fatal("refresh reuse accepted")
	}
	for _, raw := range []string{pair.AccessToken, rotated.AccessToken} {
		if _, _, err := resolveAppMCPAccess(app, raw, grantFixtureResource, now.Add(2*time.Minute)); err == nil {
			t.Fatal("reuse left access active")
		}
	}
	if _, err := refreshAppMCPGrant(app, rotated.RefreshToken, "client-fixture", grantFixtureResource, now.Add(2*time.Minute)); err == nil {
		t.Fatal("reuse left successor refresh active")
	}
}
func TestAppMCPGrantConcurrentRefreshHasSingleWinnerAndRevokesReuse(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	// Explicit DATABASE_URL may omit immediate transactions and busy timeout.
	if err := app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", filepath.Join(app.Dir, "data.db")+"?_journal_mode=WAL&_busy_timeout=0")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	app.DB = db

	pair := fixtureGrant(t, app, uid, now)
	var wait sync.WaitGroup
	start := make(chan struct{})
	results := make(chan *appMCPTokenPair, 2)
	failures := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			next, err := refreshAppMCPGrant(app, pair.RefreshToken, "client-fixture", grantFixtureResource, now.Add(time.Minute))
			if err != nil {
				failures <- err
			} else {
				results <- next
			}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(failures)
	if len(results) != 1 || len(failures) != 1 {
		t.Fatalf("concurrent winners=%d failures=%d", len(results), len(failures))
	}
	winner := <-results
	if _, _, err := resolveAppMCPAccess(app, winner.AccessToken, grantFixtureResource, now.Add(time.Minute)); err == nil {
		t.Fatal("detected concurrent reuse did not revoke winner")
	}
}
func TestAppMCPGrantTupleAndScopeDenialsDoNotSpendRefresh(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	for _, scope := range []string{"", "*", "*:read", "notes:*", "notes:read notes:read", "unknown:read", "_none_:read"} {
		if _, err := createAppMCPGrant(app, uid, "17", "client-fixture", grantFixtureResource, scope, now); err == nil {
			t.Fatalf("invalid scope accepted: %q", scope)
		}
	}
	for _, resource := range []string{"https://fixture.example/", "https://fixture.example/api/_mcp?x=1", "https://fixture.example/api/_mcp#", "https://fixture.example/api/%5Fmcp", "http://fixture.example/api/_mcp"} {
		if _, err := createAppMCPGrant(app, uid, "17", "client-fixture", resource, "notes:read", now); err == nil {
			t.Fatalf("invalid audience accepted: %q", resource)
		}
	}
	for _, tenant := range []string{"", "0", "88"} {
		if _, err := createAppMCPGrant(app, uid, tenant, "client-fixture", grantFixtureResource, "notes:read", now); err == nil {
			t.Fatalf("unselected/nonmember tenant accepted: %q", tenant)
		}
	}
	pair := fixtureGrant(t, app, uid, now)
	if _, err := refreshAppMCPGrant(app, pair.RefreshToken, "other-client", grantFixtureResource, now); err == nil {
		t.Fatal("wrong client refreshed")
	}
	if _, err := refreshAppMCPGrant(app, pair.RefreshToken, "client-fixture", "https://other.example/api/_mcp", now); err == nil {
		t.Fatal("wrong resource refreshed")
	}
	if _, _, err := resolveAppMCPAccess(app, pair.AccessToken, "https://other.example/api/_mcp", now); err == nil {
		t.Fatal("wrong access audience accepted")
	}
	for _, raw := range []string{pair.RefreshToken, "bma_" + strings.Repeat("a", 64), "bmr_" + strings.Repeat("a", 64)} {
		if _, _, err := resolveAppMCPAccess(app, raw, grantFixtureResource, now); err == nil {
			t.Fatal("wrong credential class accepted")
		}
	}
	if _, err := refreshAppMCPGrant(app, pair.RefreshToken, "client-fixture", grantFixtureResource, now); err != nil {
		t.Fatalf("bad tuple spent correct refresh: %v", err)
	}
}
func TestAppMCPGrantRechecksRoleMembershipAndAdminTenant(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	auditExec(t, app.DB, "UPDATE _benmore_users SET role='admin' WHERE id=?", uid)
	_, actor, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, now)
	if err != nil || !actor.IsAdmin() || actor.IsAdminBypass() {
		t.Fatalf("admin delegation bypass: %+v %v", actor, err)
	}
	auditExec(t, app.DB, "DELETE FROM members WHERE org_id='17'")
	if _, _, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, now); err == nil {
		t.Fatal("admin lost tenant membership but still authorized")
	}
	auditExec(t, app.DB, "INSERT INTO members(org_id,email) VALUES ('17','delegate@example.com')")
	app.Roles = &RolesConfig{Roles: map[string]RoleDef{"admin": {Scopes: "other:read"}}}
	if _, _, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, now); err == nil {
		t.Fatal("removed role scope still authorized")
	}
}
func TestAppMCPGrantRevocationEpochAndSourceChangesDeny(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	if err := revokeAppMCPGrant(app, pair.GrantID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, now); err == nil {
		t.Fatal("revoked grant authorized")
	}
	pair = fixtureGrant(t, app, uid, now)
	if err := invalidateAppMCPForRestore(app.Dir); err != nil {
		t.Fatal(err)
	}
	if _, err := updateAppMCPEpoch(app.Dir, true, false, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, now); err == nil {
		t.Fatal("old epoch authorized after restore re-enable")
	}
	pair = fixtureGrant(t, app, uid, now)
	writeTestFile(t, app.Dir, "static/changed.ts", "export const changed=true")
	if _, _, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, now); err == nil {
		t.Fatal("changed unreviewed source authorized")
	}
}

func TestAppMCPGrantRestoredCredentialsCannotRevive(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	candidate := filepath.Join(app.Dir, "candidate.db")
	snapshotTo(t, app.DB, candidate)
	if err := revokeAppMCPGrant(app, pair.GrantID); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := installRestoreSnapshot(app.Dir, candidate); err != nil {
		t.Fatal(err)
	}
	db, err := OpenDB(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	app.DB = db
	grant, err := readAppMCPGrant(db, pair.GrantID)
	if err != nil || grant.Revoked {
		t.Fatalf("snapshot did not restore active grant: %+v %v", grant, err)
	}
	if _, err := updateAppMCPEpoch(app.Dir, true, false, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, now); err == nil {
		t.Fatal("restored old access credential revived")
	}
	if _, err := refreshAppMCPGrant(app, pair.RefreshToken, "client-fixture", grantFixtureResource, now); err == nil {
		t.Fatal("restored old refresh credential revived")
	}
}

func TestAppMCPGrantRefreshReuseRevokesWhileAuthorityUnavailable(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	next, err := refreshAppMCPGrant(app, pair.RefreshToken, "client-fixture", grantFixtureResource, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	auditExec(t, app.DB, "DELETE FROM members WHERE org_id='17'")
	if _, err := refreshAppMCPGrant(app, pair.RefreshToken, "client-fixture", grantFixtureResource, now.Add(2*time.Minute)); err == nil {
		t.Fatal("spent refresh accepted without authority")
	}
	auditExec(t, app.DB, "INSERT INTO members(org_id,email) VALUES ('17','delegate@example.com')")
	if _, _, err := resolveAppMCPAccess(app, next.AccessToken, grantFixtureResource, now.Add(3*time.Minute)); err == nil {
		t.Fatal("membership restoration revived reused grant")
	}
	if _, err := refreshAppMCPGrant(app, next.RefreshToken, "client-fixture", grantFixtureResource, now.Add(3*time.Minute)); err == nil {
		t.Fatal("successor refresh survived replay revocation")
	}
}

func TestAppMCPGrantCancelledRefreshDoesNotSpendCredential(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	if err := app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", filepath.Join(app.Dir, "data.db")+"?_journal_mode=WAL&_busy_timeout=0")
	if err != nil {
		t.Fatal(err)
	}
	app.DB = db
	pair := fixtureGrant(t, app, uid, now)
	lock, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err := lock.Exec("UPDATE _benmore_mcp_grants SET scopes=scopes WHERE id=?", pair.GrantID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if _, err := refreshAppMCPGrantFor(ctx, app, pair.RefreshToken, "client-fixture", grantFixtureResource, "notes:read", now); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled refresh: %v", err)
	}
	if err := lock.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := refreshAppMCPGrant(app, pair.RefreshToken, "client-fixture", grantFixtureResource, now); err != nil {
		t.Fatalf("cancelled refresh spent credential: %v", err)
	}
}

func TestAppMCPGrantRefreshReplayRevokesEvenWithInvalidScope(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	for _, scope := range []string{"notes:write", "*"} {
		if _, err := refreshAppMCPGrantFor(context.Background(), app, pair.RefreshToken, "client-fixture", grantFixtureResource, scope, now); err == nil {
			t.Fatal("invalid refresh scope accepted")
		}
	}
	rotated, err := refreshAppMCPGrant(app, pair.RefreshToken, "client-fixture", grantFixtureResource, now)
	if err != nil {
		t.Fatalf("invalid scope spent unused credential: %v", err)
	}
	if _, err := refreshAppMCPGrantFor(context.Background(), app, pair.RefreshToken, "client-fixture", grantFixtureResource, "notes:write", now); err == nil {
		t.Fatal("refresh replay accepted")
	}
	if _, _, err := resolveAppMCPAccess(app, rotated.AccessToken, grantFixtureResource, now); err == nil {
		t.Fatal("invalid scope hid refresh replay and left family active")
	}
}

// A connector grant is a reusable credential the old password could have
// produced: replacing the password or claiming a never-verified account must
// end it with the account's sessions and API tokens.
func TestAppMCPGrantPasswordReplacementAndAccountClaimRevoke(t *testing.T) {
	for _, tc := range []struct {
		name   string
		revoke func(*App, int64) error
	}{
		{"signed_in_change", func(app *App, uid int64) error {
			auditExec(t, app.DB, "UPDATE _benmore_users SET password_hash=? WHERE id=?", "fixture-old-hash", uid)
			sess := GetSessionFromDB(app.DB, CreateSession(app.DB, uid, "delegate@example.com", "", time.Hour))
			_, err := changeSignedInPassword(app, sess, "fixture-old-hash", "$2a$12$replacement")
			return err
		}},
		{"reset", func(app *App, uid int64) error {
			tx, err := app.DB.Begin()
			if err != nil {
				return err
			}
			defer tx.Rollback()
			if err := revokePasswordCredentials(tx, uid); err != nil {
				return err
			}
			return tx.Commit()
		}},
		{"verify_claim", func(app *App, uid int64) error { return revokeOtherCredentials(app.DB, uid, "") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, uid, now := appMCPGrantFixture(t)
			pair := fixtureGrant(t, app, uid, now)
			auditExec(t, app.DB, "INSERT INTO _benmore_mcp_authorizations(key_hash,kind,user_id,app,payload,expires_at) VALUES ('pending','code',?,'app','{}',?)", uid, now.Add(time.Minute).Unix())
			if _, _, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, now); err != nil {
				t.Fatalf("fixture grant unusable: %v", err)
			}
			if err := tc.revoke(app, uid); err != nil {
				t.Fatal(err)
			}
			if _, _, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, now); err == nil {
				t.Fatal("connector access token survived credential revocation")
			}
			if _, err := refreshAppMCPGrant(app, pair.RefreshToken, "client-fixture", grantFixtureResource, now); err == nil {
				t.Fatal("connector refresh token survived credential revocation")
			}
			var pending int
			if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_mcp_authorizations WHERE user_id=?", uid).Scan(&pending); err != nil || pending != 0 {
				t.Fatalf("pending connector consent/code survived: %d %v", pending, err)
			}
		})
	}
}
