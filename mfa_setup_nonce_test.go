//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mfaTestNonce(t *testing.T, app *App, uid int64) string {
	t.Helper()
	var nonce string
	if err := app.DB.QueryRow("SELECT mfa_setup_nonce FROM _benmore_users WHERE id=?", uid).Scan(&nonce); err != nil {
		t.Fatal(err)
	}
	return nonce
}

func mfaTestGrantValid(app *App, grant string) bool {
	r := httptest.NewRequest(http.MethodPost, "/api/_auth/mfa/setup", nil)
	r.Header.Set("X-MFA-Setup-Token", grant)
	_, _, _, err := mfaCallerIdentity(app, r)
	return err == nil
}

func TestMFASetupGrantRevokedByIdenticalCredentialWrite(t *testing.T) {
	app := recoveryHardeningApp(t)
	uid := recoveryUser(t, app, "owner@example.test", "", 1)
	// The supported default-password reset can repeat this exact state.
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_hash='fixed-fixture-hash',password_change_required=1 WHERE id=?", uid)
	grant := mintMFASetupToken(app, uid, "owner@example.test", "fixed-fixture-hash")
	if !mfaTestGrantValid(app, grant) {
		t.Fatal("initial enrollment grant is invalid")
	}
	before := mfaTestNonce(t, app, uid)
	// Match reset_client_password.yaml's credential UPDATE: no value changes.
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_hash='fixed-fixture-hash',password_change_required=1 WHERE id=?", uid)
	if after := mfaTestNonce(t, app, uid); after == before || len(after) != 32 {
		t.Fatal("same-value reset did not rotate the durable enrollment marker")
	}
	mux := http.NewServeMux()
	RegisterMFARoutes(mux, app)
	for _, endpoint := range []string{"setup", "verify"} {
		if w := mfaRecoveryCall(mux, grant, endpoint, "{}"); w.Code != http.StatusUnauthorized {
			t.Fatalf("same-value reset kept old grant on %s: %d", endpoint, w.Code)
		}
	}
	if fresh := mintMFASetupToken(app, uid, "owner@example.test", "fixed-fixture-hash"); !mfaTestGrantValid(app, fresh) {
		t.Fatal("same-value reset prevented a fresh enrollment")
	}
}

func TestMFASetupNonceRotationIsTransactional(t *testing.T) {
	app := recoveryHardeningApp(t)
	uid := recoveryUser(t, app, "owner@example.test", "", 1)
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_hash='original-fixture-hash' WHERE id=?", uid)
	grant := mintMFASetupToken(app, uid, "owner@example.test")
	before := mfaTestNonce(t, app, uid)
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE _benmore_users SET password_hash=password_hash WHERE id=?", uid); err != nil {
		t.Fatal(err)
	}
	var inTx string
	if err := tx.QueryRow("SELECT mfa_setup_nonce FROM _benmore_users WHERE id=?", uid).Scan(&inTx); err != nil || inTx == before {
		t.Fatalf("reset did not rotate inside the transaction: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if after := mfaTestNonce(t, app, uid); after != before || !mfaTestGrantValid(app, grant) {
		t.Fatal("rolled-back reset invalidated the original grant")
	}
	// A storage error rotating the nonce must abort the credential UPDATE,
	// rather than replace the password while leaving an old enrollment valid.
	passwordChangeExec(t, app.DB, `CREATE TRIGGER fixture_refuse_nonce BEFORE UPDATE OF mfa_setup_nonce ON _benmore_users BEGIN
		SELECT RAISE(ABORT, 'synthetic nonce write failure'); END`)
	if _, err := app.DB.Exec("UPDATE _benmore_users SET password_hash='replacement-fixture-hash' WHERE id=?", uid); err == nil {
		t.Fatal("credential write ignored nonce rotation failure")
	}
	var hash string
	if err := app.DB.QueryRow("SELECT password_hash FROM _benmore_users WHERE id=?", uid).Scan(&hash); err != nil || hash != "original-fixture-hash" {
		t.Fatalf("nonce failure partially replaced the credential: %v", err)
	}
	if after := mfaTestNonce(t, app, uid); after != before || !mfaTestGrantValid(app, grant) {
		t.Fatal("failed credential write changed the enrollment marker")
	}
}

func legacyMFANonceApp(t *testing.T) *App {
	t.Helper()
	app, done := newTestApp(t)
	t.Cleanup(done)
	passwordChangeExec(t, app.DB, `CREATE TABLE _benmore_users (
		id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE,
		password_hash TEXT, password_change_required INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`)
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_users (username,email) VALUES ('owner','owner@example.test')")
	return app
}

func TestMFASetupNonceMigratesAndSurvivesReload(t *testing.T) {
	app := legacyMFANonceApp(t)
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	before := mfaTestNonce(t, app, 1)
	if len(before) != 32 {
		t.Fatal("legacy account was not backfilled")
	}
	grant := mintMFASetupToken(app, 1, "owner@example.test")
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	if mfaTestNonce(t, app, 1) != before || !mfaTestGrantValid(app, grant) {
		t.Fatal("a repeated migration/reload revoked an unchanged enrollment")
	}
	passwordChangeExec(t, app.DB, "PRAGMA recursive_triggers=ON")
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_change_required=password_change_required WHERE id=1")
	if mfaTestGrantValid(app, grant) {
		t.Fatal("migrated credential trigger did not revoke the old grant")
	}
}

func TestMFASetupNonceMigrationRollsBackOnFailure(t *testing.T) {
	app := legacyMFANonceApp(t)
	passwordChangeExec(t, app.DB, `CREATE TRIGGER fixture_refuse_backfill BEFORE UPDATE ON _benmore_users BEGIN
		SELECT RAISE(ABORT, 'synthetic backfill failure'); END`)
	if err := EnsureUsersTable(app.DB); err == nil {
		t.Fatal("failed enrollment migration reported success")
	}
	if recoveryCount(t, app.DB, "SELECT COUNT(*) FROM pragma_table_info('_benmore_users') WHERE name='mfa_setup_nonce'") != 0 ||
		recoveryCount(t, app.DB, "SELECT COUNT(*) FROM sqlite_schema WHERE type='trigger' AND name LIKE '_benmore_mfa_setup_nonce_%'") != 0 {
		t.Fatal("failed migration left a partial nonce/trigger installation")
	}
	if grant := mintMFASetupToken(app, 1, "owner@example.test"); grant != "" {
		t.Fatal("missing nonce migration still minted a setup grant")
	}
	passwordChangeExec(t, app.DB, "DROP TRIGGER fixture_refuse_backfill")
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	if grant := mintMFASetupToken(app, 1, "owner@example.test"); !mfaTestGrantValid(app, grant) {
		t.Fatal("repaired migration did not restore enrollment")
	}
}

func TestMFASetupNonceWaitsForConcurrentWriter(t *testing.T) {
	app := legacyMFANonceApp(t)
	passwordChangeExec(t, app.DB, "PRAGMA journal_mode=WAL")
	migrating, err := sql.Open("sqlite3", filepath.Join(app.Dir, "data.db")+"?_journal_mode=WAL&_busy_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer migrating.Close()
	writer, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	if _, err := writer.Exec("UPDATE _benmore_users SET email=email WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- ensureMFASetupNonce(migrating) }()
	select {
	case err := <-finished:
		t.Fatalf("migration returned while another writer held the database: %v", err)
	case <-time.After(50 * time.Millisecond):
		// A deferred read-before-write used to fail here immediately with BUSY
		// despite busy_timeout; the migration now waits without a read snapshot.
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("migration failed after competing writer committed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("migration did not finish after the writer released its lock")
	}
	if len(mfaTestNonce(t, app, 1)) != 32 ||
		recoveryCount(t, app.DB, "SELECT COUNT(*) FROM sqlite_schema WHERE type='trigger' AND name LIKE '_benmore_mfa_setup_nonce_%'") != 2 {
		t.Fatal("migration left incomplete revocation state after write contention")
	}
}

func TestMFASetupNonceMalformedOrMissingTriggerFailsClosed(t *testing.T) {
	for _, state := range []string{"empty", "short", "not_hex", "missing_trigger"} {
		t.Run(state, func(t *testing.T) {
			app := recoveryHardeningApp(t)
			uid := recoveryUser(t, app, "owner@example.test", "", 1)
			grant := mintMFASetupToken(app, uid, "owner@example.test")
			if state == "missing_trigger" {
				passwordChangeExec(t, app.DB, "DROP TRIGGER _benmore_mfa_setup_nonce_reset")
			} else {
				value := map[string]string{"empty": "", "short": "abcd", "not_hex": strings.Repeat("z", 32)}[state]
				passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET mfa_setup_nonce=? WHERE id=?", value, uid)
			}
			if mfaTestGrantValid(app, grant) || mintMFASetupToken(app, uid, "owner@example.test") != "" {
				t.Fatal("invalid revocation state authorized enrollment")
			}
			if err := EnsureUsersTable(app.DB); err != nil {
				t.Fatal(err)
			}
			if !mfaTestGrantValid(app, mintMFASetupToken(app, uid, "owner@example.test")) {
				t.Fatal("repaired state did not allow fresh enrollment")
			}
		})
	}
}

func TestMFASetupNonceRecreatedAccountCannotReuseGrant(t *testing.T) {
	app := recoveryHardeningApp(t)
	uid := recoveryUser(t, app, "owner@example.test", "", 1)
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET created_at='2026-01-01 00:00:00' WHERE id=?", uid)
	grant := mintMFASetupToken(app, uid, "owner@example.test")
	before := mfaTestNonce(t, app, uid)
	passwordChangeExec(t, app.DB, "DELETE FROM _benmore_users WHERE id=?", uid)
	passwordChangeExec(t, app.DB, `INSERT INTO _benmore_users (id,username,email,created_at,mfa_setup_nonce)
		VALUES (?,'owner','owner@example.test','2026-01-01 00:00:00',?)`, uid, before)
	if mfaTestNonce(t, app, uid) == before || mfaTestGrantValid(app, grant) {
		t.Fatal("recreated account reused an earlier account's enrollment grant")
	}
}

func TestMFASetupNonceHiddenAndProtectedFromClients(t *testing.T) {
	app := recoveryHardeningApp(t)
	uid := recoveryUser(t, app, "owner@example.test", "", 1)
	sid := CreateSession(app.DB, uid, "owner@example.test", "", time.Hour)
	before := mfaTestNonce(t, app, uid)
	app.Design.Auth["profile_fields"] = "mfa_setup_nonce"
	app.Design.Auth["signup_fields"] = "mfa_setup_nonce"
	mux := http.NewServeMux()
	RegisterSettingsRoutes(mux, app)
	w := profilePatch(t, mux, sid, map[string]any{"first_name": "Updated", "mfa_setup_nonce": strings.Repeat("0", 32)})
	if w.Code != http.StatusOK || mfaTestNonce(t, app, uid) != before {
		t.Fatalf("profile wrote the server marker or refused ordinary fields: %d", w.Code)
	}
	if _, exposed := loadUserForJSON(app, uid)[mfaSetupNonceColumn]; exposed {
		t.Fatal("user JSON exposed the revocation marker")
	}
	if _, exposed := LoadUserFields(app.DB, uid)[mfaSetupNonceColumn]; exposed {
		t.Fatal("template user fields exposed the revocation marker")
	}
	for _, column := range []string{"mfa_setup_nonce", "MFA_SETUP_NONCE"} {
		if !protectedCreateFields(app, "_benmore_users").has(column) ||
			!protectedFields(protectedUpdateFields(app, "_benmore_users")).has(column) ||
			signupFieldRefusal(column, nil) == "" || !apiHiddenColumn(app, "_benmore_users", column) {
			t.Fatalf("client guard missing for %s", column)
		}
	}
}
