//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// auditFixtureAccount adds alice with one ordinary browser session and
// returns the session a password change needs.
func auditFixtureAccount(t *testing.T, db *sql.DB) *Session {
	t.Helper()
	credExec(t, db, `INSERT INTO _benmore_users (id, username, email, password_hash, verified, created_at) VALUES (1, 'alice', 'alice@x.test', ?, 1, '2026-01-01 10:00:00')`, aliceHashOld)
	id := sessionStorageKey("alice-browser")
	credExec(t, db, `INSERT INTO _benmore_sessions (id, user_id, email, expires_at) VALUES (?, 1, 'alice@x.test', '2099-01-01T00:00:00Z')`, id)
	return &Session{ID: id, UserID: 1, Email: "alice@x.test"}
}

// changeAlicePassword runs the signed-in password change, the writer of the
// password_change audit row.
func changeAlicePassword(t *testing.T, db *sql.DB, session *Session, from, to string) {
	t.Helper()
	if _, err := changeSignedInPassword(&App{DB: db}, session, from, to); err != nil {
		t.Fatalf("password change: %v", err)
	}
}

// A password changed after the snapshot stays changed after a restore, and
// the audit row that records the change is in the restored database too.
func TestRestoreKeepsAuditRowOfLaterPasswordChange(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "data.db")
	db := credentialFixtureDB(t, livePath)
	session := auditFixtureAccount(t, db)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)

	changeAlicePassword(t, db, session, aliceHashOld, aliceHashLive)
	changedAt := credString(t, db, `SELECT CAST(created_at AS TEXT) FROM _benmore_audit_log WHERE action = 'password_change'`)
	if changedAt == "" {
		t.Fatal("the password change wrote no audit row")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := restoreDatabase(dir, snapshot); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got := openRO(t, livePath)
	if h := credString(t, got, `SELECT password_hash FROM _benmore_users WHERE id = 1`); h != aliceHashLive {
		t.Fatalf("the restore brought back the old password: %q", h)
	}
	if n := credCount(t, got, `SELECT count(*) FROM _benmore_audit_log WHERE action = 'password_change' AND user_id = 1 AND user_email = 'alice@x.test' AND created_at = ?`, changedAt); n != 1 {
		t.Fatalf("the restored database holds the changed password and %d audit rows of the change, want 1", n)
	}
}

type carriedAuditRow struct {
	id                        int64
	userID                    int64
	email, old, new, at, mark string
}

// auditRowsOf reads every audit row with an action, oldest id first.
func auditRowsOf(t *testing.T, db *sql.DB, action string) []carriedAuditRow {
	t.Helper()
	rows, err := db.Query(`SELECT id, COALESCE(user_id, 0), COALESCE(user_email, ''), COALESCE(old_values, ''), COALESCE(new_values, ''),
		CAST(created_at AS TEXT), COALESCE(CAST(restore_carried_at AS TEXT), '') FROM _benmore_audit_log WHERE action = ? ORDER BY id`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []carriedAuditRow
	for rows.Next() {
		var r carriedAuditRow
		if err := rows.Scan(&r.id, &r.userID, &r.email, &r.old, &r.new, &r.at, &r.mark); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// oneAuditRow is the single row with an action.
func oneAuditRow(t *testing.T, db *sql.DB, action string) carriedAuditRow {
	t.Helper()
	rows := auditRowsOf(t, db, action)
	if len(rows) != 1 {
		t.Fatalf("%d %s audit rows, want exactly 1: %+v", len(rows), action, rows)
	}
	return rows[0]
}

// latestRestoreSummary is the summary of the newest restore_credentials row.
func latestRestoreSummary(t *testing.T, db *sql.DB) restoreCredentialSummary {
	t.Helper()
	var summary restoreCredentialSummary
	raw := credString(t, db, `SELECT new_values FROM _benmore_audit_log WHERE action = 'restore_credentials' ORDER BY id DESC LIMIT 1`)
	if err := json.Unmarshal([]byte(raw), &summary); err != nil {
		t.Fatalf("audit row: %v %q", err, raw)
	}
	if summary.AuditRows == nil {
		t.Fatalf("the restore audit row says nothing about audit rows: %s", raw)
	}
	return summary
}

// The audit rows of account, role and credential events written after the
// snapshot are in the restored database once each, as they were written and
// marked as copied; the rows of app tables are not, and a second restore of
// the same snapshot copies nothing twice.
func TestRestoreCarriesCredentialAuditRowsOnceUnchanged(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "data.db")
	db := credentialFixtureDB(t, livePath)
	session := auditFixtureAccount(t, db)
	app := &App{DB: db}
	admin := &Session{UserID: 1, Email: "alice@x.test"}
	// Before the snapshot: one role grant and one app-table write.
	credExec(t, db, `INSERT INTO _benmore_audit_log (action, table_name, row_id, user_id, user_email, new_values, created_at)
		VALUES ('role_granted', '_benmore_user_roles', '1', 1, 'alice@x.test', '{"role":"editor"}', '2026-01-05 10:00:00')`)
	credExec(t, db, `INSERT INTO _benmore_audit_log (action, table_name, row_id, user_id, user_email, new_values, created_at)
		VALUES ('insert', 'notes', '1', 1, 'alice@x.test', '{"body":"snapshot data"}', '2026-01-05 10:00:01')`)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)

	// After the snapshot. heidi signs up and is granted a role: the restore
	// drops her account, her rows are history all the same.
	changeAlicePassword(t, db, session, aliceHashOld, aliceHashLive)
	credExec(t, db, `INSERT INTO _benmore_users (id, username, email, password_hash, verified) VALUES (8, 'heidi', 'heidi@x.test', '$2a$12$heidi', 1)`)
	LogAudit(app, "role_granted", "_benmore_user_roles", "8", admin, nil, map[string]any{"role": "manager", "group_id": "all"})
	LogAudit(app, "passkey_added", "_benmore_passkeys", "3", session, nil, map[string]any{"name": "laptop"})
	LogAudit(app, "update", "_benmore_users", "8", admin, map[string]any{"deactivated_at": nil}, map[string]any{"deactivated_at": "2026-09-01 12:00:00"})
	LogAudit(app, "insert", "notes", "2", session, nil, map[string]any{"body": "later data"})
	LogAudit(app, "share", "notes", "1", session, nil, map[string]any{"user_id": 8})
	want := map[string]carriedAuditRow{}
	for _, action := range []string{"password_change", "passkey_added", "update"} {
		want[action] = oneAuditRow(t, db, action)
	}
	grant := auditRowsOf(t, db, "role_granted")
	if len(grant) != 2 {
		t.Fatalf("fixture: %d role grants", len(grant))
	}
	want["role_granted"] = grant[1]
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	check := func(pass string) *sql.DB {
		t.Helper()
		got, err := sql.Open("sqlite3", sqliteRestoreURI(livePath, "rw"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { got.Close() })
		for action, w := range want {
			rows := auditRowsOf(t, got, action)
			if action == "role_granted" {
				// The snapshot's own grant is there once, unmarked.
				if len(rows) != 2 || rows[0].mark != "" || rows[0].at != "2026-01-05 10:00:00" {
					t.Fatalf("%s: role grants = %+v, want the snapshot's own and the later one", pass, rows)
				}
				rows = rows[1:]
			}
			if len(rows) != 1 {
				t.Fatalf("%s: %d %s audit rows, want 1: %+v", pass, len(rows), action, rows)
			}
			r := rows[0]
			if r.at != w.at || r.userID != w.userID || r.email != w.email || r.old != w.old || r.new != w.new {
				t.Fatalf("%s: %s was copied as %+v, want it as written %+v", pass, action, r, w)
			}
			if r.id != w.id {
				t.Fatalf("%s: %s took id %d; its own id %d was free", pass, action, r.id, w.id)
			}
			if r.mark == "" {
				t.Fatalf("%s: the copied %s row is not marked", pass, action)
			}
		}
		// Stored as the writers store them: text, and no value where none was.
		if n := credCount(t, got, `SELECT count(*) FROM _benmore_audit_log WHERE restore_carried_at IS NOT NULL AND
			(typeof(created_at) <> 'text' OR typeof(action) <> 'text' OR typeof(new_values) NOT IN ('text', 'null') OR typeof(old_values) NOT IN ('text', 'null') OR typeof(user_id) <> 'integer')`); n != 0 {
			t.Fatalf("%s: %d copied rows changed storage class", pass, n)
		}
		if v := credString(t, got, `SELECT typeof(old_values) || ':' || typeof(new_values) FROM _benmore_audit_log WHERE action = 'password_change'`); v != "null:null" {
			t.Fatalf("%s: the copied password change has values %s, want none as written", pass, v)
		}
		if n := credCount(t, got, `SELECT count(*) FROM _benmore_audit_log WHERE table_name = 'notes'`); n != 1 {
			t.Fatalf("%s: %d audit rows of the app table, want only the snapshot's", pass, n)
		}
		if n := credCount(t, got, `SELECT count(*) FROM _benmore_audit_log WHERE table_name = 'notes' AND restore_carried_at IS NOT NULL`); n != 0 {
			t.Fatalf("%s: a row the snapshot holds is marked as copied", pass)
		}
		if n := credCount(t, got, `SELECT count(*) FROM _benmore_users WHERE id = 8`); n != 0 {
			t.Fatalf("%s: an account created after the snapshot came back", pass)
		}
		return got
	}

	if err := restoreDatabase(dir, snapshot); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got := check("first restore")
	if s := latestRestoreSummary(t, got); s.AuditRows.Carried != 4 || s.AuditRows.Skipped != "" || s.AuditRows.LiveError != "" {
		t.Fatalf("summary = %+v, want 4 rows copied", s.AuditRows)
	}
	if mark := oneAuditRow(t, got, "restore_credentials").mark; mark != "" {
		t.Fatalf("the restore's own row is marked as copied: %q", mark)
	}
	// A row copied by an earlier restore keeps that restore's mark.
	credExec(t, got, `UPDATE _benmore_audit_log SET restore_carried_at = '2026-02-02 02:02:02' WHERE action = 'password_change'`)
	if err := got.Close(); err != nil {
		t.Fatal(err)
	}

	if err := restoreDatabase(dir, snapshot); err != nil {
		t.Fatalf("second restore: %v", err)
	}
	got = check("second restore")
	if mark := oneAuditRow(t, got, "password_change").mark; mark != "2026-02-02 02:02:02" {
		t.Fatalf("the mark of the first restore was replaced: %q", mark)
	}
	// The first restore is history too: its row came along, marked.
	restores := auditRowsOf(t, got, "restore_credentials")
	if len(restores) != 2 || restores[0].mark == "" || restores[1].mark != "" {
		t.Fatalf("restore rows after two restores = %+v, want the first copied and the second written in place", restores)
	}
	if s := latestRestoreSummary(t, got); s.AuditRows.Carried != 5 {
		t.Fatalf("second summary = %+v, want the 4 rows and the first restore's", s.AuditRows)
	}
	var verdict string
	if err := got.QueryRow("PRAGMA integrity_check").Scan(&verdict); err != nil || verdict != "ok" {
		t.Fatalf("integrity: %q %v", verdict, err)
	}
}

// hipaaAuditFixture is a compliance: hipaa database: both audit tables with
// their append-only triggers.
func hipaaAuditFixture(t *testing.T, path string) *sql.DB {
	t.Helper()
	db := credentialFixtureDB(t, path)
	EnsureReadAuditTable(db)
	if err := ensureAuditAppendOnly(&App{DB: db, Design: &DesignConfig{Compliance: complianceHIPAA}}); err != nil {
		t.Fatal(err)
	}
	return db
}

// assertAuditAppendOnly fails unless the database still refuses to change,
// delete or overwrite an audit row, with the framework's exact triggers.
func assertAuditAppendOnly(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, table := range auditAppendOnlyTables {
		stored, err := auditTableTriggers(db, table)
		if err != nil {
			t.Fatal(err)
		}
		for _, kind := range auditAppendOnlyKinds {
			if name := auditTriggerName(table, kind); stored[name] != auditTriggerSQL(table, kind) {
				t.Fatalf("trigger %s after the restore = %q", name, stored[name])
			}
		}
		if len(stored) != len(auditAppendOnlyKinds) {
			t.Fatalf("%s carries %d triggers after the restore: %v", table, len(stored), stored)
		}
	}
	for _, stmt := range []string{
		`UPDATE _benmore_audit_log SET user_email = 'x' WHERE action = 'password_change'`,
		`DELETE FROM _benmore_audit_log WHERE action = 'password_change'`,
		`INSERT OR REPLACE INTO _benmore_audit_log (id, action, table_name) SELECT id, 'forged', 'notes' FROM _benmore_audit_log WHERE action = 'password_change'`,
	} {
		if _, err := db.Exec(stmt); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("%q after the restore = %v, want the append-only refusal", stmt, err)
		}
	}
}

// Under compliance: hipaa the audit tables only take new rows. The restore
// copies the later credential rows by inserting them, an id the snapshot
// already uses is not overwritten, and the triggers are the same afterwards.
func TestRestoreCarriesCredentialAuditRowsUnderHIPAA(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "data.db")
	db := hipaaAuditFixture(t, livePath)
	session := auditFixtureAccount(t, db)
	app := &App{DB: db}
	older := filepath.Join(dir, "older.db")
	snapshotTo(t, db, older)

	// The first timeline: a password change, then two app-table writes.
	changeAlicePassword(t, db, session, aliceHashOld, aliceHashLive)
	first := oneAuditRow(t, db, "password_change")
	LogAudit(app, "insert", "notes", "1", session, nil, map[string]any{"body": "one"})
	LogAudit(app, "insert", "notes", "2", session, nil, map[string]any{"body": "two"})
	later := filepath.Join(dir, "later.db")
	snapshotTo(t, db, later)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if err := restoreDatabase(dir, older); err != nil {
		t.Fatalf("restore: %v", err)
	}
	db, err := sql.Open("sqlite3", sqliteRestoreURI(livePath, "rw"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if got := oneAuditRow(t, db, "password_change"); got.at != first.at || got.id != first.id || got.email != "alice@x.test" || got.mark == "" {
		t.Fatalf("the password change after the restore = %+v, want %+v, marked", got, first)
	}
	if n := credCount(t, db, `SELECT count(*) FROM _benmore_audit_log WHERE table_name = 'notes'`); n != 0 {
		t.Fatalf("%d app-table audit rows newer than the snapshot were copied", n)
	}
	if s := latestRestoreSummary(t, db); s.AuditRows.Carried != 1 {
		t.Fatalf("summary = %+v", s.AuditRows)
	}
	assertAuditAppendOnly(t, db)

	// The second timeline: a role grant, whose id the later snapshot uses for
	// an app-table row of the first timeline.
	LogAudit(&App{DB: db}, "role_granted", "_benmore_user_roles", "1", session, nil, map[string]any{"role": "manager"})
	granted := oneAuditRow(t, db, "role_granted")
	restoredAt := oneAuditRow(t, db, "restore_credentials")
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	taken := openRO(t, later)
	if n := credCount(t, taken, `SELECT count(*) FROM _benmore_audit_log WHERE id IN (?, ?) AND table_name = 'notes'`, restoredAt.id, granted.id); n != 2 {
		t.Fatalf("fixture: the later snapshot does not use ids %d and %d for other rows", restoredAt.id, granted.id)
	}
	taken.Close()

	if err := restoreDatabase(dir, later); err != nil {
		t.Fatalf("restore of the later snapshot: %v", err)
	}
	db, err = sql.Open("sqlite3", sqliteRestoreURI(livePath, "rw"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	// The password change is the later snapshot's own row: there once, unmarked.
	if got := oneAuditRow(t, db, "password_change"); got.at != first.at || got.id != first.id || got.mark != "" {
		t.Fatalf("the password change = %+v, want the snapshot's own row", got)
	}
	// The grant took a new id; the rows that had its id are untouched.
	got := oneAuditRow(t, db, "role_granted")
	if got.id == granted.id || got.at != granted.at || got.new != granted.new || got.userID != 1 || got.mark == "" {
		t.Fatalf("the role grant = %+v, want %+v under a new id, marked", got, granted)
	}
	if n := credCount(t, db, `SELECT count(*) FROM _benmore_audit_log WHERE id IN (?, ?) AND table_name = 'notes' AND restore_carried_at IS NULL`, restoredAt.id, granted.id); n != 2 {
		t.Fatal("a row of the snapshot was overwritten by a copied one")
	}
	if n := credCount(t, db, `SELECT count(*) FROM _benmore_audit_log WHERE id < ? AND restore_carried_at IS NOT NULL`, got.id-1); n != 0 {
		t.Fatal("a copied row sorts among the snapshot's own rows")
	}
	if s := latestRestoreSummary(t, db); s.AuditRows.Carried != 2 {
		t.Fatalf("summary = %+v, want the grant and the first restore's row", s.AuditRows)
	}
	assertAuditAppendOnly(t, db)
}

// Account erasure blanks the addresses in the audit rows of the erased
// account, also in rows older than the snapshot. Such a row is the
// snapshot's own and is not copied beside it.
func TestRestoreDoesNotCopyAuditRowsRewrittenSinceTheSnapshot(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "data.db")
	db := credentialFixtureDB(t, livePath)
	session := auditFixtureAccount(t, db)
	legacy := "legacy-session-id"
	credExec(t, db, `INSERT INTO _benmore_audit_log (action, table_name, row_id, user_id, user_email, new_values, created_at)
		VALUES ('role_granted', '_benmore_user_roles', '1', 1, 'alice@x.test', '{"role":"editor"}', '2026-01-05 10:00:00')`)
	// The snapshot's newest second holds two rows that are rewritten later.
	changeAlicePassword(t, db, session, aliceHashOld, aliceHashLive)
	LogAudit(&App{DB: db}, "act_as_start", "_benmore_sessions", legacy, session, nil, map[string]any{"group": "7"})
	at := oneAuditRow(t, db, "password_change").at
	credExec(t, db, `UPDATE _benmore_audit_log SET created_at = ? WHERE action = 'act_as_start'`, at)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)

	credExec(t, db, `UPDATE _benmore_audit_log SET user_email = '' WHERE user_id = 1`)
	credExec(t, db, `UPDATE _benmore_audit_log SET row_id = ? WHERE action = 'act_as_start'`, sessionStorageKey(legacy))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := restoreDatabase(dir, snapshot); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got := openRO(t, livePath)
	for _, action := range []string{"role_granted", "password_change", "act_as_start"} {
		if r := oneAuditRow(t, got, action); r.mark != "" || r.email != "alice@x.test" {
			t.Fatalf("%s after the restore = %+v, want the snapshot's own row", action, r)
		}
	}
	if s := latestRestoreSummary(t, got); s.AuditRows.Carried != 0 {
		t.Fatalf("summary = %+v, want nothing copied", s.AuditRows)
	}
}

// With no readable live database there is no later audit row to copy, and
// the restore's own row says so.
func TestRestoreSaysWhyNoAuditRowsWereCopied(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "data.db")
	src := filepath.Join(dir, "source.db")
	db := credentialFixtureDB(t, src)
	auditFixtureAccount(t, db)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)
	db.Close()

	// No live database at all.
	if err := restoreDatabase(dir, snapshot); err != nil {
		t.Fatal(err)
	}
	if s := latestRestoreSummary(t, openRO(t, livePath)); s.AuditRows.Skipped != restoreAuditSkippedNoLive || s.AuditRows.Carried != 0 {
		t.Fatalf("no live database: %+v", s.AuditRows)
	}
	// A live database that cannot be read.
	if err := os.WriteFile(livePath, []byte("SQLite format 3\x00this file is damaged beyond reading"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreDatabase(dir, snapshot); err != nil {
		t.Fatal(err)
	}
	got := openRO(t, livePath)
	if s := latestRestoreSummary(t, got); s.Mode != restoreCredentialsUnreadable || s.AuditRows.Skipped != restoreAuditSkippedUnreadable || s.AuditRows.Carried != 0 {
		t.Fatalf("unreadable live database: %+v %+v", s, s.AuditRows)
	}
	if n := credCount(t, got, `SELECT count(*) FROM _benmore_audit_log`); n != 1 {
		t.Fatalf("%d audit rows after restoring over an unreadable database, want the restore's own", n)
	}
}

// The account security events (a factor enrolled or removed, a backup code
// spent, an address changed, a token minted or revoked, a session ended, a
// passkey added or removed) written after the snapshot are in the restored
// database once each, as written and marked as copied.
func TestRestoreCarriesAccountSecurityEventAuditRows(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "data.db")
	db := credentialFixtureDB(t, livePath)
	session := auditFixtureAccount(t, db)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)

	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for action := range accountAuditEventTables {
		if err := auditAccountEvent(tx, &App{DB: db}, action, "1", session, map[string]any{"was": action}, map[string]any{"is": action}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	want := map[string]carriedAuditRow{}
	for action := range accountAuditEventTables {
		want[action] = oneAuditRow(t, db, action)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := restoreDatabase(dir, snapshot); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got := openRO(t, livePath)
	for action, w := range want {
		r := oneAuditRow(t, got, action)
		if r.at != w.at || r.userID != 1 || r.email != "alice@x.test" || r.old != w.old || r.new != w.new || r.old == "" {
			t.Errorf("%s was copied as %+v, want it as written %+v", action, r, w)
		}
		if r.mark == "" {
			t.Errorf("the copied %s row is not marked", action)
		}
	}
	if s := latestRestoreSummary(t, got); s.AuditRows.Carried != len(want) {
		t.Fatalf("summary = %+v, want %d rows copied", s.AuditRows, len(want))
	}
}

// Every framework writer of an account, role or credential event names one of
// the copied tables in table_name; the writers of other events do not.
func TestRestoreAuditTablesCoverTheCredentialEventWriters(t *testing.T) {
	copied := map[string]string{
		"password_change, password_reset, role_changed, account_purge, impersonate": "_benmore_users",
		"role_granted, role_revoked, role_expiry_updated, role_expired":             "_benmore_user_roles",
		"passkey_added, passkey_removed, passkeys_removed_all":                      "_benmore_passkeys",
		"act_as_start, act_as_end, data_revoke_session, session_revoked":            "_benmore_sessions",
		"api_token_created, api_token_revoked":                                      "_benmore_api_tokens",
		"mfa_enrolled, mfa_removed, mfa_backup_code_used, email_changed":            "_benmore_users",
		"mcp_grant_revoke":              mcpGrantsTable,
		"mcp_connection_credential_set": appMCPConnectionCredentialsTable,
	}
	tables := restoreAuditTables()
	for actions, table := range copied {
		if !slices.Contains(tables, table) {
			t.Errorf("audit rows of %s (%s) are not copied by a restore", actions, table)
		}
	}
	for _, table := range []string{"notes", "", "_benmore_mcp_operations", "mcp_connector", "_benmore_audit_log", "_benmore_blind_index", "_benmore_feedback"} {
		if slices.Contains(tables, table) {
			t.Errorf("audit rows of %q are copied by a restore", table)
		}
	}
}

// Every snapshot taken before the mark column existed lacks it, and so does a
// live database no current binary has started on. The restore adds the column
// to the copy it installs, also on a compliance: hipaa database, and marks
// what it copies.
func TestRestoreMarksCopiedAuditRowsInASnapshotOlderThanTheMark(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "data.db")
	db := credentialFixtureDB(t, livePath)
	credExec(t, db, `ALTER TABLE _benmore_audit_log DROP COLUMN restore_carried_at`)
	EnsureReadAuditTable(db)
	if err := ensureAuditAppendOnly(&App{DB: db, Design: &DesignConfig{Compliance: complianceHIPAA}}); err != nil {
		t.Fatal(err)
	}
	session := auditFixtureAccount(t, db)
	credExec(t, db, `INSERT INTO _benmore_audit_log (action, table_name, row_id, user_id, user_email, created_at)
		VALUES ('password_reset', '_benmore_users', '1', 1, 'alice@x.test', '2026-01-05 10:00:00')`)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)
	changeAlicePassword(t, db, session, aliceHashOld, aliceHashLive)
	// A start of the app adds the column to the live table, triggers and all.
	EnsureAuditLogTable(db)
	if n := credCount(t, db, `SELECT count(*) FROM pragma_table_info('_benmore_audit_log') WHERE name = 'restore_carried_at'`); n != 1 {
		t.Fatal("starting the app did not add restore_carried_at to an append-only audit table")
	}
	assertAuditAppendOnly(t, db)
	if n := credCount(t, openRO(t, snapshot), `SELECT count(*) FROM pragma_table_info('_benmore_audit_log') WHERE name = 'restore_carried_at'`); n != 0 {
		t.Fatal("fixture: the snapshot already has the column")
	}
	changedAt := credString(t, db, `SELECT CAST(created_at AS TEXT) FROM _benmore_audit_log WHERE action = 'password_change'`)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := restoreDatabase(dir, snapshot); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, err := sql.Open("sqlite3", sqliteRestoreURI(livePath, "rw"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { got.Close() })
	if r := oneAuditRow(t, got, "password_change"); r.at != changedAt || r.email != "alice@x.test" || r.mark == "" {
		t.Fatalf("the password change after the restore = %+v, want it as written at %s, marked", r, changedAt)
	}
	if r := oneAuditRow(t, got, "password_reset"); r.mark != "" || r.at != "2026-01-05 10:00:00" {
		t.Fatalf("the snapshot's own row = %+v", r)
	}
	assertAuditAppendOnly(t, got)
}

// An app may put a trigger of its own on the audit table. One that refuses a
// copied row does not stop the restore: no row is copied, the credentials are
// carried all the same, and the restore's row says why.
func TestRestoreGoesOnWhenTheSnapshotRefusesACopiedAuditRow(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "data.db")
	db := credentialFixtureDB(t, livePath)
	session := auditFixtureAccount(t, db)
	credExec(t, db, `CREATE TRIGGER app_audit_rule BEFORE INSERT ON _benmore_audit_log WHEN NEW.action = 'password_change' AND NEW.restore_carried_at IS NOT NULL
		BEGIN SELECT RAISE(ABORT, 'app rule: no backdated rows'); END`)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)
	LogAudit(&App{DB: db}, "passkey_added", "_benmore_passkeys", "3", session, nil, map[string]any{"name": "laptop"})
	changeAlicePassword(t, db, session, aliceHashOld, aliceHashLive)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := restoreDatabase(dir, snapshot); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got := openRO(t, livePath)
	if h := credString(t, got, `SELECT password_hash FROM _benmore_users WHERE id = 1`); h != aliceHashLive {
		t.Fatalf("the restore brought back the old password: %q", h)
	}
	s := latestRestoreSummary(t, got)
	if s.AuditRows.Carried != 0 || !strings.Contains(s.AuditRows.Error, "app rule") {
		t.Fatalf("summary = %+v, want the refusal and no row copied", s.AuditRows)
	}
	// The passkey row was written before the refused one and is undone with it.
	if n := credCount(t, got, `SELECT count(*) FROM _benmore_audit_log WHERE action <> 'restore_credentials'`); n != 0 {
		t.Fatalf("%d audit rows were copied although the summary says none", n)
	}
}
