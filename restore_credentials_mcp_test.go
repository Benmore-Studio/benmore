//go:build !cli

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mcpGrantFixture(t *testing.T, db *sql.DB) {
	t.Helper()
	if err := ensureAppMCPGrantTables(db); err != nil {
		t.Fatal(err)
	}
}

func mcpGrantRow(t *testing.T, db *sql.DB, id string, user int, revoked int) {
	t.Helper()
	credExec(t, db, `INSERT INTO _benmore_mcp_grants (id, app, user_id, user_created, tenant, client, resource, epoch, scopes, expires_at, revoked)
		VALUES (?, 'app', ?, 'c', 't', 'client', 'https://r.test', 'epoch', 'notes:read', 4102444800, ?)`, id, user, revoked)
}

// Every restore requires new delegated consent, even when the router cannot
// rotate the connector authority epoch.
func TestRestoreRevokesSnapshotMCPGrantsAndCredentials(t *testing.T) {
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", "")
	dir := t.TempDir()
	livePath := filepath.Join(dir, "data.db")
	db := credentialFixtureDB(t, livePath)
	mcpGrantFixture(t, db)
	credExec(t, db, `INSERT INTO _benmore_users (id, username, email, password_hash, verified, created_at) VALUES
		(1, 'alice', 'alice@x.test', '$2a$12$a', 1, '2026-01-01 10:00:00'),
		(2, 'bob',   'bob@x.test',   '$2a$12$b', 1, '2026-01-02 10:00:00')`)

	// --- When the snapshot is taken: everything live and unused.
	mcpGrantRow(t, db, "g-revoked-later", 1, 0)
	mcpGrantRow(t, db, "g-kept", 2, 0)
	mcpGrantRow(t, db, "g-deleted-later", 2, 0)
	credExec(t, db, `INSERT INTO _benmore_mcp_credentials (token_hash, grant_id, kind, expires_at, used) VALUES
		('h-refresh-used-later', 'g-revoked-later', 'refresh', 4102444800, 0),
		('h-access-old', 'g-revoked-later', 'access', 4102444800, 0),
		('h-kept', 'g-kept', 'refresh', 4102444800, 0),
		('h-deleted-grant', 'g-deleted-later', 'refresh', 4102444800, 0)`)
	credExec(t, db, `INSERT INTO _benmore_mcp_authorizations (key_hash, kind, user_id, app, payload, expires_at, used) VALUES
		('a-code-used-later', 'code', 1, 'app', '{}', 4102444800, 0),
		('a-consent-kept', 'consent', 2, 'app', '{}', 4102444800, 0)`)
	credExec(t, db, `INSERT INTO notes (id, body) VALUES (1, 'snapshot data')`)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)

	// --- Afterwards: revocations, consumption, a new grant, a new account.
	credExec(t, db, `UPDATE _benmore_mcp_grants SET revoked = 1 WHERE id = 'g-revoked-later'`)
	credExec(t, db, `UPDATE _benmore_mcp_credentials SET used = 1 WHERE token_hash = 'h-refresh-used-later'`)
	credExec(t, db, `DELETE FROM _benmore_mcp_credentials WHERE token_hash = 'h-access-old'`)
	credExec(t, db, `UPDATE _benmore_mcp_authorizations SET used = 1 WHERE key_hash = 'a-code-used-later'`)
	credExec(t, db, `DELETE FROM _benmore_mcp_credentials WHERE grant_id = 'g-deleted-later'`)
	credExec(t, db, `DELETE FROM _benmore_mcp_grants WHERE id = 'g-deleted-later'`)
	mcpGrantRow(t, db, "g-new-alice", 1, 0)
	credExec(t, db, `INSERT INTO _benmore_mcp_credentials (token_hash, grant_id, kind, expires_at, used) VALUES ('h-new', 'g-new-alice', 'refresh', 4102444800, 0)`)
	credExec(t, db, `INSERT INTO _benmore_users (id, username, email, password_hash, verified, created_at) VALUES (3, 'carol', 'carol@x.test', '$2a$12$c', 1, '2026-02-01 10:00:00')`)
	mcpGrantRow(t, db, "g-live-only-account", 3, 0)
	credExec(t, db, `INSERT INTO _benmore_mcp_credentials (token_hash, grant_id, kind, expires_at, used) VALUES ('h-carol', 'g-live-only-account', 'refresh', 4102444800, 0)`)
	db.Close()

	if err := restoreDatabase(dir, snapshot); err != nil {
		t.Fatal(err)
	}
	got := openRO(t, livePath)
	defer got.Close()
	if credString(t, got, `SELECT body FROM notes WHERE id = 1`) != "snapshot data" {
		t.Fatal("data was not restored")
	}
	revoked := func(id string) string {
		return credString(t, got, `SELECT revoked FROM _benmore_mcp_grants WHERE id = ?`, id)
	}
	if revoked("g-revoked-later") != "1" || revoked("g-kept") != "1" || revoked("g-deleted-later") != "1" {
		t.Fatal("a delegated grant remained usable after restore")
	}
	if n := credCount(t, got, `SELECT count(*) FROM _benmore_mcp_grants WHERE id = 'g-live-only-account'`); n != 0 {
		t.Fatalf("%d grants for a live-only account came back", n)
	}
	if n := credCount(t, got, `SELECT (SELECT count(*) FROM _benmore_mcp_credentials) + (SELECT count(*) FROM _benmore_mcp_authorizations)`); n != 0 {
		t.Fatalf("%d access/refresh credentials or pending authorizations survived restore", n)
	}
	var summary restoreCredentialSummary
	if err := json.Unmarshal([]byte(credString(t, got, `SELECT new_values FROM _benmore_audit_log WHERE action = 'restore_credentials'`)), &summary); err != nil || summary.Mode != restoreCredentialsCarried || summary.MCPGrantsRevoked != 3 {
		t.Fatalf("summary = %+v %v", summary, err)
	}
}

func TestRouterRestoreCannotReviveAccessRefreshOrConsentAfterMembershipReturns(t *testing.T) {
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", "")
	app, uid, _ := appMCPGrantFixture(t)
	authorityRoot := os.Getenv("BENMORE_MCP_AUTHORITY_DIR")
	if authorityRoot == "" {
		t.Fatal("fixture did not configure its authority root")
	}
	now := time.Now().UTC().Truncate(time.Second)
	pair := fixtureGrant(t, app, uid, now)
	generation := snapshotAppMCPGeneration(app)
	if _, actor, err := resolveAppMCPAccessForGeneration(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, now); err != nil || actor.UserID != uid {
		t.Fatalf("valid delegated access fixture: actor=%+v err=%v", actor, err)
	}
	if _, err := app.DB.Exec(`INSERT INTO _benmore_mcp_authorizations(key_hash,kind,user_id,app,payload,expires_at,used) VALUES('pending-before-restore','consent',?,'app','{}',?,0)`, uid, now.Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(app.Dir, ".benmore", "backups", "mcp-grant-snapshot.db")
	if err := os.MkdirAll(filepath.Dir(backup), 0700); err != nil {
		t.Fatal(err)
	}
	if err := sqliteVacuumInto(filepath.Join(app.Dir, "data.db"), backup); err != nil {
		t.Fatal(err)
	}
	beforeEpoch, err := currentAppMCPEpoch(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`DELETE FROM members WHERE org_id='17' AND email='delegate@example.com'`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveAppMCPAccessForGeneration(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, now); err == nil {
		t.Fatal("delegated token remained authorized after its snapshot membership was removed")
	}
	if err := app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	// The router process does not have an owner-controlled app authority
	// directory. Exercise that exact restore path, where DB membership comes
	// back from the snapshot without an epoch change to mask grant revocation.
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", "")
	if err := restoreDatabase(app.Dir, backup); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authorityRoot)
	db, err := openDBWithEnv(app.Dir, app.environment)
	if err != nil {
		t.Fatal(err)
	}
	app.DB = db
	defer db.Close()
	afterEpoch, err := currentAppMCPEpoch(app.Dir)
	if err != nil || beforeEpoch.Epoch != afterEpoch.Epoch {
		t.Fatalf("router restore unexpectedly changed the authority epoch: before=%+v after=%+v err=%v", beforeEpoch, afterEpoch, err)
	}
	generation = snapshotAppMCPGeneration(app)
	if n := credCount(t, app.DB, `SELECT count(*) FROM members WHERE org_id='17' AND email='delegate@example.com'`); n != 1 {
		t.Fatalf("restored fixture membership count = %d, want 1", n)
	}
	fresh := fixtureGrant(t, app, uid, now)
	if _, actor, err := resolveAppMCPAccessForGeneration(context.Background(), app, generation, fresh.AccessToken, grantFixtureResource, now); err != nil || actor.UserID != uid {
		t.Fatalf("positive control: fresh consent grant did not resolve against restored membership: actor=%+v err=%v", actor, err)
	}
	if _, _, err := resolveAppMCPAccessForGeneration(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, now); err == nil {
		t.Fatal("restored membership revived the pre-restore access token")
	}
	if _, err := refreshAppMCPGrant(app, pair.RefreshToken, "client-fixture", grantFixtureResource, now); err == nil {
		t.Fatal("restore retained a pre-restore refresh token")
	}
	if n := credCount(t, app.DB, `SELECT count(*) FROM _benmore_mcp_authorizations WHERE key_hash='pending-before-restore'`); n != 0 {
		t.Fatal("restore retained a pre-restore pending consent authorization")
	}
}

// With no readable live database nothing is known to be live: every connector
// grant is revoked and its credentials and authorizations are deleted.
func TestRestoreRevokesMCPGrantsWhenLiveIsUnreadable(t *testing.T) {
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", "")
	dir := t.TempDir()
	livePath := filepath.Join(dir, "data.db")
	src := filepath.Join(dir, "source.db")
	db := credentialFixtureDB(t, src)
	mcpGrantFixture(t, db)
	credExec(t, db, `INSERT INTO _benmore_users (id, username, email, password_hash) VALUES (1, 'alice', 'alice@x.test', '$2a$12$a')`)
	mcpGrantRow(t, db, "g1", 1, 0)
	mcpGrantRow(t, db, "g2", 1, 0)
	credExec(t, db, `INSERT INTO _benmore_mcp_credentials (token_hash, grant_id, kind, expires_at, used) VALUES ('h1', 'g1', 'refresh', 4102444800, 0), ('h2', 'g2', 'access', 4102444800, 0)`)
	credExec(t, db, `INSERT INTO _benmore_mcp_authorizations (key_hash, kind, user_id, app, payload, expires_at, used) VALUES ('a1', 'code', 1, 'app', '{}', 4102444800, 0)`)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)
	db.Close()
	if err := os.WriteFile(livePath, []byte("SQLite format 3\x00this file is damaged beyond reading"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreDatabase(dir, snapshot); err != nil {
		t.Fatal(err)
	}
	got := openRO(t, livePath)
	defer got.Close()
	if n := credCount(t, got, `SELECT count(*) FROM _benmore_mcp_grants WHERE revoked = 0`); n != 0 {
		t.Fatalf("%d grants still live after an unreadable live database", n)
	}
	if credCount(t, got, `SELECT count(*) FROM _benmore_mcp_grants`) != 2 {
		t.Fatal("grant rows should be kept, revoked")
	}
	if n := credCount(t, got, `SELECT (SELECT count(*) FROM _benmore_mcp_credentials) + (SELECT count(*) FROM _benmore_mcp_authorizations)`); n != 0 {
		t.Fatalf("%d connector credentials or authorizations survived", n)
	}
	var summary restoreCredentialSummary
	if err := json.Unmarshal([]byte(credString(t, got, `SELECT new_values FROM _benmore_audit_log WHERE action = 'restore_credentials'`)), &summary); err != nil || summary.MCPGrantsRevoked != 2 {
		t.Fatalf("summary = %+v %v", summary, err)
	}
}

// A live database with no connector tables holds no live grants either.
func TestRestoreRevokesSnapshotMCPGrantsWhenLiveHasNoConnectorState(t *testing.T) {
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", "")
	dir := t.TempDir()
	livePath := filepath.Join(dir, "data.db")
	live := credentialFixtureDB(t, livePath)
	credExec(t, live, `INSERT INTO _benmore_users (id, username, email, password_hash) VALUES (1, 'alice', 'alice@x.test', '$2a$12$a')`)
	src := credentialFixtureDB(t, filepath.Join(dir, "source.db"))
	mcpGrantFixture(t, src)
	credExec(t, src, `INSERT INTO _benmore_users (id, username, email, password_hash) VALUES (1, 'alice', 'alice@x.test', '$2a$12$a')`)
	mcpGrantRow(t, src, "g1", 1, 0)
	credExec(t, src, `INSERT INTO _benmore_mcp_credentials (token_hash, grant_id, kind, expires_at, used) VALUES ('h1', 'g1', 'refresh', 4102444800, 0)`)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, src, snapshot)
	src.Close()
	live.Close()
	if err := restoreDatabase(dir, snapshot); err != nil {
		t.Fatal(err)
	}
	got := openRO(t, livePath)
	defer got.Close()
	if credCount(t, got, `SELECT count(*) FROM _benmore_mcp_grants WHERE revoked = 0`) != 0 || credCount(t, got, `SELECT count(*) FROM _benmore_mcp_credentials`) != 0 {
		t.Fatal("a snapshot grant came back live although the live database had none")
	}
}
