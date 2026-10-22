//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// credentialFixtureDB opens a database with every framework credential table.
func credentialFixtureDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureMFAColumns(db)
	EnsureSessionsTable(db)
	EnsureAPITokensTable(db)
	EnsurePasswordResetsTable(db)
	EnsureOAuthTokensTable(db)
	ensureEmailChangesTable(db)
	EnsureLoginAttemptsTable(db)
	EnsureAuditLogTable(db)
	appOAuthEnsureTables(&App{DB: db})
	mustExec(t, db, "CREATE TABLE IF NOT EXISTS _benmore_otp (email TEXT, code TEXT, attempts INTEGER DEFAULT 0, expires_at DATETIME)")
	mustExec(t, db, "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, body TEXT)")
	return db
}

func credExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

func credString(t *testing.T, db *sql.DB, query string, args ...any) string {
	t.Helper()
	var v sql.NullString
	if err := db.QueryRow(query, args...).Scan(&v); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return v.String
}

func credCount(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return n
}

func snapshotTo(t *testing.T, db *sql.DB, path string) {
	t.Helper()
	if _, err := db.Exec("VACUUM INTO ?", path); err != nil {
		t.Fatal(err)
	}
}

const (
	sealedTOTPLive   = "enc:v2:live-sealed-secret"
	aliceHashOld     = "$2a$12$snapshot-alice-hash"
	aliceHashLive    = "$2a$12$current-alice-hash"
	erinHashLive     = "$2a$12$current-erin-hash"
	frankHashOld     = "$2a$12$snapshot-frank-hash"
	liveAccessToken  = "enc:v2:rotated-access"
	legacySessionRaw = "legacy-raw-session-token"
)

// A restore rolls data back but carries the live sign-in state forward: the
// snapshot's revoked sessions, tokens and grants are gone, surviving accounts
// keep their current credentials and identifiers, and a deleted account comes
// back without any way in beyond its own password.
func TestRestoreCarriesLiveCredentialsForward(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "data.db")
	db := credentialFixtureDB(t, livePath)

	// --- State when the snapshot is taken.
	credExec(t, db, `INSERT INTO _benmore_users (id, username, email, password_hash, verified, created_at) VALUES
		(1, 'alice', 'alice@x.test', ?, 1, '2026-01-01 10:00:00'),
		(2, 'bob',   'bob@x.test',   '$2a$12$bob', 1, '2026-01-02 10:00:00'),
		(3, 'carol', 'carol@x.test', '$2a$12$carol-old', 1, '2026-01-03 10:00:00'),
		(4, 'dave',  'dave@x.test',  '$2a$12$dave', 1, '2026-01-04 10:00:00'),
		(6, 'frank', 'frank@x.test', ?, 1, '2026-01-06 10:00:00'),
		(7, 'gina',  'gina@x.test',  '$2a$12$gina', 1, '2026-01-07 10:00:00')`, aliceHashOld, frankHashOld)
	credExec(t, db, `INSERT INTO _benmore_sessions (id, user_id, email, expires_at) VALUES
		(?, 1, 'alice@x.test', '2027-01-01T00:00:00Z'),
		(?, 1, 'alice@x.test', '2027-01-01T00:00:00Z'),
		(?, 2, 'bob@x.test',   '2027-01-01T00:00:00Z'),
		(?, 3, 'carol@x.test', '2027-01-01T00:00:00Z'),
		(?, 6, 'frank@x.test', '2027-01-01T00:00:00Z')`,
		legacySessionRaw, sessionStorageKey("alice-revoked"), sessionStorageKey("bob-live"),
		sessionStorageKey("carol-old"), sessionStorageKey("frank-old"))
	credExec(t, db, `INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes) VALUES
		(1, 'ci', 'hash-alice-revoked', '*'), (2, 'cli', 'hash-bob-live', '*'), (6, 'bot', 'hash-frank', '*')`)
	credExec(t, db, `INSERT INTO _benmore_password_resets (token, email, expires_at) VALUES ('reset-used', 'alice@x.test', '2027-01-01 00:00:00')`)
	credExec(t, db, `INSERT INTO _benmore_otp (email, code, attempts, expires_at) VALUES ('bob@x.test', 'code-live', 1, '2027-01-01 00:00:00'), ('bob@x.test', 'code-spent', 0, '2027-01-01 00:00:00')`)
	credExec(t, db, `INSERT INTO _benmore_oauth_tokens (user_id, provider, access_token) VALUES (1, 'google', 'enc:v2:old-access'), (1, 'github', 'enc:v2:disconnected')`)
	credExec(t, db, `INSERT INTO _benmore_email_changes (user_id, new_email, token_hash, expires_at) VALUES (4, 'pending@x.test', 'change-hash', '2027-01-01 00:00:00')`)
	credExec(t, db, `INSERT INTO _benmore_oauth_clients (client_id, name, redirect_uris) VALUES ('kept-client', 'Kept', 'https://a.test/cb'), ('removed-client', 'Removed', 'https://b.test/cb')`)
	credExec(t, db, `INSERT INTO notes (id, body) VALUES (1, 'snapshot data')`)
	credExec(t, db, `INSERT INTO _benmore_signin_challenges(token_hash,user_id,purpose,email,otp_key,credential_binding,expires_at) VALUES('spent-step',1,'mfa-step','alice@x.test','','binding',9999999999)`)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)

	// --- What happens after the snapshot.
	credExec(t, db, `DELETE FROM _benmore_signin_challenges WHERE token_hash='spent-step'`)
	credExec(t, db, `UPDATE notes SET body = 'later data'`)
	// frank and gina are deleted.
	credExec(t, db, `DELETE FROM _benmore_sessions WHERE user_id IN (6, 7)`)
	credExec(t, db, `DELETE FROM _benmore_api_tokens WHERE user_id = 6`)
	credExec(t, db, `DELETE FROM _benmore_users WHERE id IN (6, 7)`)
	// alice: new password, MFA enrolled, one session revoked, legacy session
	// rekeyed to its stored form, a brand-new session, a revoked token, the
	// reset grant used, one OAuth connection rotated and one disconnected,
	// and a new username that a deleted account used to hold.
	credExec(t, db, `UPDATE _benmore_users SET password_hash = ?, totp_secret = ?, backup_codes = 'hashed-codes', username = 'gina' WHERE id = 1`, aliceHashLive, sealedTOTPLive)
	credExec(t, db, `DELETE FROM _benmore_sessions WHERE id = ?`, sessionStorageKey("alice-revoked"))
	credExec(t, db, `UPDATE _benmore_sessions SET id = ? WHERE id = ?`, sessionStorageKey(legacySessionRaw), legacySessionRaw)
	credExec(t, db, `INSERT INTO _benmore_sessions (id, user_id, email, expires_at) VALUES (?, 1, 'alice@x.test', '2027-06-01T00:00:00Z')`, sessionStorageKey("alice-new"))
	credExec(t, db, `DELETE FROM _benmore_api_tokens WHERE token_hash = 'hash-alice-revoked'`)
	credExec(t, db, `DELETE FROM _benmore_password_resets WHERE token = 'reset-used'`)
	credExec(t, db, `UPDATE _benmore_oauth_tokens SET access_token = ? WHERE provider = 'google'`, liveAccessToken)
	credExec(t, db, `DELETE FROM _benmore_oauth_tokens WHERE provider = 'github'`)
	// bob: deactivated and told to replace his password; one OTP spent, the
	// other has absorbed guesses; five failed sign-ins recorded.
	credExec(t, db, `UPDATE _benmore_users SET deactivated_at = '2026-09-01 12:00:00', password_change_required = 1 WHERE id = 2`)
	credExec(t, db, `DELETE FROM _benmore_otp WHERE code = 'code-spent'`)
	credExec(t, db, `UPDATE _benmore_otp SET attempts = 4 WHERE code = 'code-live'`)
	for i := 0; i < 5; i++ {
		credExec(t, db, `INSERT INTO _benmore_login_attempts (email, success) VALUES ('bob@x.test', 0)`)
	}
	// carol deletes her account; erin signs up with the same email.
	credExec(t, db, `DELETE FROM _benmore_sessions WHERE user_id = 3`)
	credExec(t, db, `DELETE FROM _benmore_users WHERE id = 3`)
	credExec(t, db, `INSERT INTO _benmore_users (id, username, email, password_hash, verified, created_at) VALUES (5, 'erin', 'carol@x.test', ?, 1, '2026-08-01 10:00:00')`, erinHashLive)
	// dave confirms a new email that a deleted account used to hold.
	credExec(t, db, `DELETE FROM _benmore_email_changes`)
	credExec(t, db, `UPDATE _benmore_users SET email = 'gina@x.test' WHERE id = 4`)
	credExec(t, db, `DELETE FROM _benmore_oauth_clients WHERE client_id = 'removed-client'`)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if err := restoreDatabase(dir, snapshot); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, err := sql.Open("sqlite3", sqliteRestoreURI(livePath, "ro"))
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()

	if body := credString(t, got, `SELECT body FROM notes WHERE id = 1`); body != "snapshot data" {
		t.Fatalf("data was not rolled back: %q", body)
	}
	if n := credCount(t, got, `SELECT COUNT(*) FROM _benmore_signin_challenges`); n != 0 {
		t.Fatal("a consumed sign-in challenge came back")
	}
	// alice keeps her current credentials and identifier.
	if h := credString(t, got, `SELECT password_hash FROM _benmore_users WHERE id = 1`); h != aliceHashLive {
		t.Fatalf("alice's revoked password came back: %q", h)
	}
	if s := credString(t, got, `SELECT totp_secret FROM _benmore_users WHERE id = 1`); s != sealedTOTPLive {
		t.Fatalf("alice's MFA state = %q, want the live sealed secret unchanged", s)
	}
	if u := credString(t, got, `SELECT username FROM _benmore_users WHERE id = 1`); u != "gina" {
		t.Fatalf("alice's username = %q, want the live one", u)
	}
	// Only sessions that are live survive; nothing live-only is added.
	var ids []string
	rows, err := got.Query(`SELECT id FROM _benmore_sessions ORDER BY user_id, id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	want := []string{legacySessionRaw, sessionStorageKey("bob-live")}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("restored sessions = %v, want only the live ones %v", ids, want)
	}
	if n := credCount(t, got, `SELECT count(*) FROM _benmore_api_tokens`); n != 1 || credString(t, got, `SELECT token_hash FROM _benmore_api_tokens`) != "hash-bob-live" {
		t.Fatalf("api tokens after restore: %d", n)
	}
	if n := credCount(t, got, `SELECT count(*) FROM _benmore_password_resets`); n != 0 {
		t.Fatal("a used reset grant came back")
	}
	if n := credCount(t, got, `SELECT count(*) FROM _benmore_otp`); n != 1 || credCount(t, got, `SELECT attempts FROM _benmore_otp`) != 4 {
		t.Fatalf("one-time codes after restore: %d", n)
	}
	if tok := credString(t, got, `SELECT access_token FROM _benmore_oauth_tokens WHERE user_id = 1 AND provider = 'google'`); tok != liveAccessToken {
		t.Fatalf("OAuth token = %q, want the live one", tok)
	}
	if n := credCount(t, got, `SELECT count(*) FROM _benmore_oauth_tokens WHERE provider = 'github'`); n != 0 {
		t.Fatal("a disconnected OAuth grant came back")
	}
	if n := credCount(t, got, `SELECT count(*) FROM _benmore_email_changes`); n != 0 {
		t.Fatal("a withdrawn email-change grant came back")
	}
	if n := credCount(t, got, `SELECT count(*) FROM _benmore_oauth_clients WHERE client_id = 'removed-client'`); n != 0 {
		t.Fatal("a removed OAuth client came back")
	}
	if n := credCount(t, got, `SELECT count(*) FROM _benmore_login_attempts WHERE email = 'bob@x.test'`); n != 5 {
		t.Fatalf("lockout state = %d attempts, want the live 5", n)
	}
	// bob's deactivation and password requirement hold, stored exactly as live.
	if v := credString(t, got, `SELECT typeof(deactivated_at) || ':' || deactivated_at FROM _benmore_users WHERE id = 2`); v != "text:2026-09-01 12:00:00" {
		t.Fatalf("bob's deactivation = %q", v)
	}
	if n := credCount(t, got, `SELECT password_change_required FROM _benmore_users WHERE id = 2`); n != 1 {
		t.Fatal("bob's password-change requirement was rolled back")
	}
	// carol's restored account answers to her email's current credentials.
	if h := credString(t, got, `SELECT password_hash FROM _benmore_users WHERE id = 3`); h != erinHashLive {
		t.Fatalf("carol@x.test signs in with %q, want the live account's password", h)
	}
	// dave holds his live email; gina, deleted, loses it and her username.
	if e := credString(t, got, `SELECT email FROM _benmore_users WHERE id = 4`); e != "gina@x.test" {
		t.Fatalf("dave's email = %q", e)
	}
	if e := credString(t, got, `SELECT email FROM _benmore_users WHERE id = 7`); e != "" {
		t.Fatalf("a deleted account kept an email a live account holds: %q", e)
	}
	if n := credCount(t, got, `SELECT verified FROM _benmore_users WHERE id = 7`); n != 0 {
		t.Fatal("a cleared email kept its verification")
	}
	if u := credString(t, got, `SELECT username FROM _benmore_users WHERE id = 7`); !strings.HasPrefix(u, "restored-7-") {
		t.Fatalf("gina's username = %q, want it released", u)
	}
	// frank, deleted since, is back with his own password and nothing else.
	if h := credString(t, got, `SELECT password_hash FROM _benmore_users WHERE id = 6`); h != frankHashOld {
		t.Fatalf("frank = %q", h)
	}
	if n := credCount(t, got, `SELECT (SELECT count(*) FROM _benmore_sessions WHERE user_id = 6) + (SELECT count(*) FROM _benmore_api_tokens WHERE user_id = 6)`); n != 0 {
		t.Fatal("a deleted account came back with sessions or tokens")
	}

	// One audit row with counts and no credential material.
	audit := credString(t, got, `SELECT new_values FROM _benmore_audit_log WHERE action = 'restore_credentials'`)
	var summary restoreCredentialSummary
	if err := json.Unmarshal([]byte(audit), &summary); err != nil {
		t.Fatalf("audit row: %v %q", err, audit)
	}
	if summary.Mode != restoreCredentialsCarried || summary.UsersMatched != 4 || summary.UsersSnapshotOnly != 2 ||
		summary.Removed["_benmore_sessions"] != 3 || summary.Kept["_benmore_sessions"] != 2 || summary.IdentifiersCleared != 2 {
		t.Fatalf("summary = %+v", summary)
	}
	for _, secret := range []string{aliceHashLive, aliceHashOld, sealedTOTPLive, "hash-bob-live", legacySessionRaw, liveAccessToken} {
		if strings.Contains(audit, secret) {
			t.Fatalf("audit row leaks %q", secret)
		}
	}
	if n := credCount(t, got, `SELECT count(*) FROM _benmore_audit_log WHERE action = 'restore_credentials'`); n != 1 {
		t.Fatalf("%d credential audit rows, want 1", n)
	}
	var verdict string
	if err := got.QueryRow("PRAGMA integrity_check").Scan(&verdict); err != nil || verdict != "ok" {
		t.Fatalf("integrity: %q %v", verdict, err)
	}
}

// An id that an earlier restore let the sequence hand out again belongs to
// a different account: its credentials are not copied onto the snapshot's.
func TestRestoreDoesNotMergeReusedAccountIDs(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "data.db")
	db := credentialFixtureDB(t, livePath)
	credExec(t, db, `INSERT INTO _benmore_users (id, username, email, password_hash, created_at) VALUES (8, 'hank', 'hank@x.test', '$2a$12$hank', '2026-01-08 10:00:00')`)
	credExec(t, db, `INSERT INTO _benmore_sessions (id, user_id, email, expires_at) VALUES (?, 8, 'hank@x.test', '2027-01-01T00:00:00Z')`, sessionStorageKey("shared"))
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)
	credExec(t, db, `DELETE FROM _benmore_users WHERE id = 8`)
	credExec(t, db, `INSERT INTO _benmore_users (id, username, email, password_hash, created_at) VALUES (8, 'ivy', 'ivy@x.test', '$2a$12$ivy', '2026-09-08 10:00:00')`)
	db.Close()
	if err := restoreDatabase(dir, snapshot); err != nil {
		t.Fatal(err)
	}
	got, err := sql.Open("sqlite3", sqliteRestoreURI(livePath, "ro"))
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	if h := credString(t, got, `SELECT password_hash || ' ' || email FROM _benmore_users WHERE id = 8`); h != "$2a$12$hank hank@x.test" {
		t.Fatalf("reused id merged two accounts: %q", h)
	}
	if n := credCount(t, got, `SELECT count(*) FROM _benmore_sessions`); n != 0 {
		t.Fatal("the session of a different account survived under a reused id")
	}
}

// When the live database cannot be read, nothing is known to be live, so
// every restored session, token and grant is revoked.
func TestRestoreRevokesEverythingWhenLiveIsUnreadable(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "data.db")
	src := filepath.Join(dir, "source.db")
	db := credentialFixtureDB(t, src)
	credExec(t, db, `INSERT INTO _benmore_users (id, username, email, password_hash) VALUES (1, 'alice', 'alice@x.test', '$2a$12$a')`)
	credExec(t, db, `INSERT INTO _benmore_sessions (id, user_id, email, expires_at) VALUES (?, 1, 'alice@x.test', '2027-01-01T00:00:00Z')`, sessionStorageKey("s"))
	credExec(t, db, `INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes) VALUES (1, 'ci', 'h', '*')`)
	credExec(t, db, `INSERT INTO _benmore_password_resets (token, email, expires_at) VALUES ('r', 'alice@x.test', '2027-01-01 00:00:00')`)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)
	db.Close()
	if err := os.WriteFile(livePath, []byte("SQLite format 3\x00this file is damaged beyond reading"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreDatabase(dir, snapshot); err != nil {
		t.Fatal(err)
	}
	got, err := sql.Open("sqlite3", sqliteRestoreURI(livePath, "ro"))
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	if n := credCount(t, got, `SELECT (SELECT count(*) FROM _benmore_sessions) + (SELECT count(*) FROM _benmore_api_tokens) + (SELECT count(*) FROM _benmore_password_resets)`); n != 0 {
		t.Fatalf("%d credentials survived an unreadable live database", n)
	}
	if n := credCount(t, got, `SELECT count(*) FROM _benmore_users`); n != 1 {
		t.Fatal("accounts must come back")
	}
	var summary restoreCredentialSummary
	if err := json.Unmarshal([]byte(credString(t, got, `SELECT new_values FROM _benmore_audit_log WHERE action = 'restore_credentials'`)), &summary); err != nil || summary.Mode != restoreCredentialsUnreadable {
		t.Fatalf("summary = %+v %v", summary, err)
	}
}

// A carry-forward failure aborts the restore before installation: the live
// database stays in place, unchanged.
func TestRestoreCredentialFailureLeavesLiveDatabase(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "data.db")
	db := credentialFixtureDB(t, livePath)
	credExec(t, db, `INSERT INTO notes (id, body) VALUES (1, 'live data')`)
	db.Close()
	src := filepath.Join(dir, "odd.db")
	odd, err := sql.Open("sqlite3", src)
	if err != nil {
		t.Fatal(err)
	}
	// A snapshot whose token table has no credential column cannot be
	// reconciled; the restore must refuse rather than keep its rows.
	credExec(t, odd, `CREATE TABLE _benmore_api_tokens (id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT)`)
	credExec(t, odd, `INSERT INTO _benmore_api_tokens (user_id, name) VALUES (1, 'x')`)
	credExec(t, odd, `CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)`)
	credExec(t, odd, `INSERT INTO notes (id, body) VALUES (1, 'snapshot data')`)
	odd.Close()
	if err := restoreDatabase(dir, src); err == nil || !strings.Contains(err.Error(), "credentials") {
		t.Fatalf("restore with an irreconcilable snapshot = %v, want a credential failure", err)
	}
	if got := credString(t, openRO(t, livePath), `SELECT body FROM notes`); got != "live data" {
		t.Fatalf("live database changed: %q", got)
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, backupDirName)); len(entries) != 0 {
		t.Fatal("a failed carry-forward still moved the live database aside")
	}
}

func openRO(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", sqliteRestoreURI(path, "ro"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// Boot-time auto-recovery swaps in an older backup for a damaged database;
// the damaged original is the live state, and when it cannot be read every
// restored session and token is revoked.
func TestAutoRecoveryDoesNotReviveCredentials(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "data.db")
	src := filepath.Join(dir, "source.db")
	db := credentialFixtureDB(t, src)
	credExec(t, db, `INSERT INTO _benmore_users (id, username, email, password_hash) VALUES (1, 'alice', 'alice@x.test', '$2a$12$a')`)
	credExec(t, db, `INSERT INTO _benmore_sessions (id, user_id, email, expires_at) VALUES (?, 1, 'alice@x.test', '2027-01-01T00:00:00Z')`, sessionStorageKey("s"))
	backup := filepath.Join(dir, "backup.db")
	snapshotTo(t, db, backup)
	db.Close()
	if err := os.WriteFile(livePath, []byte("not a database at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := swapInBackup(dir, backup, nil); err != nil {
		t.Fatal(err)
	}
	if n := credCount(t, openRO(t, livePath), `SELECT count(*) FROM _benmore_sessions`); n != 0 {
		t.Fatal("auto-recovery revived sessions from an older backup")
	}
}
