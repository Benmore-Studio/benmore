//go:build !cli

package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recordGrantFixtureDB is the role fixture plus the record-grant table and
// notes 1 to n.
func recordGrantFixtureDB(t *testing.T, path string, notes int) *sql.DB {
	t.Helper()
	db := roleFixtureDB(t, path)
	EnsurePermissionsTable(db)
	for i := 1; i <= notes; i++ {
		credExec(t, db, `INSERT INTO notes (id, body) VALUES (?, 'note')`, i)
	}
	return db
}

// share records a grant on a note the way the share route stores it.
func share(t *testing.T, db *sql.DB, note int, username, permission string, expires any) {
	t.Helper()
	credExec(t, db, `INSERT INTO _benmore_permissions (resource_type, resource_id, grant_type, grantee_id, permission, granted_by, expires_at)
		VALUES ('notes', ?, 'user', ?, ?, 1, ?)`, note, username+"@x.test", permission, expires)
}

// sharesOf lists the grants an address holds as "note:permission!expiry", sorted.
func sharesOf(t *testing.T, db *sql.DB, username string) string {
	t.Helper()
	rows, err := db.Query(`SELECT resource_id || ':' || permission || '!' || COALESCE(CAST(expires_at AS TEXT), '')
		FROM _benmore_permissions WHERE resource_type = 'notes' AND grantee_id = ? ORDER BY CAST(resource_id AS INTEGER)`, username+"@x.test")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return strings.Join(out, " ")
}

// A restore never gives an address access to a record it does not hold now:
// a share survives only when the live database still holds it unexpired, with
// the lower of the two permissions and the earlier expiry; nothing shared
// since the snapshot is added.
func TestRestoreDoesNotReviveRevokedRecordGrants(t *testing.T) {
	dir := t.TempDir()
	db := recordGrantFixtureDB(t, filepath.Join(dir, "data.db"), 8)
	roleFixtureUsers(t, db, [2]string{"root", "admin"}, [2]string{"alice", "user"}, [2]string{"bob", "user"},
		[2]string{"carol", "user"}, [2]string{"dave", "user"}, [2]string{"erin", "user"})
	share(t, db, 1, "alice", "view", nil)                   // unchanged
	share(t, db, 1, "bob", "edit", nil)                     // revoked since
	share(t, db, 2, "bob", "admin", nil)                    // lowered to view since
	share(t, db, 2, "carol", "view", nil)                   // raised to admin since
	share(t, db, 3, "carol", "edit", nil)                   // changed to delete since
	share(t, db, 3, "dave", "view", nil)                    // given an expiry that has passed
	share(t, db, 4, "dave", "edit", "2090-01-01 00:00:00")  // expiry brought forward
	share(t, db, 4, "erin", "view", "2080-01-01 00:00:00")  // expiry extended
	share(t, db, 6, "alice", "edit", nil)                   // its note was deleted since
	share(t, db, 7, "erin", "delete", nil)                  // unchanged
	share(t, db, 8, "nobody", "view", nil)                  // an address with no account, revoked since
	share(t, db, 8, "alice", "view", "2020-01-01 00:00:00") // lapsed before the snapshot, the row still there
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)

	// --- After the snapshot.
	credExec(t, db, `DELETE FROM _benmore_permissions WHERE resource_id = '1' AND grantee_id = 'bob@x.test'`)
	credExec(t, db, `UPDATE _benmore_permissions SET permission = 'view' WHERE resource_id = '2' AND grantee_id = 'bob@x.test'`)
	credExec(t, db, `UPDATE _benmore_permissions SET permission = 'admin' WHERE resource_id = '2' AND grantee_id = 'carol@x.test'`)
	credExec(t, db, `UPDATE _benmore_permissions SET permission = 'delete' WHERE resource_id = '3' AND grantee_id = 'carol@x.test'`)
	credExec(t, db, `UPDATE _benmore_permissions SET expires_at = '2021-06-01 00:00:00' WHERE resource_id = '3' AND grantee_id = 'dave@x.test'`)
	credExec(t, db, `UPDATE _benmore_permissions SET expires_at = '2085-01-01 00:00:00' WHERE resource_id = '4' AND grantee_id = 'dave@x.test'`)
	credExec(t, db, `UPDATE _benmore_permissions SET expires_at = '2099-01-01 00:00:00' WHERE resource_id = '4' AND grantee_id = 'erin@x.test'`)
	// Deleting a row deletes its shares (purgeRowKeyedState).
	credExec(t, db, `DELETE FROM _benmore_permissions WHERE resource_id = '6'`)
	credExec(t, db, `DELETE FROM notes WHERE id = 6`)
	credExec(t, db, `DELETE FROM _benmore_permissions WHERE grantee_id = 'nobody@x.test'`)
	// Shared since the snapshot.
	share(t, db, 5, "alice", "admin", nil)
	share(t, db, 1, "erin", "edit", nil)

	got, summary := restoreRoleFixture(t, db, dir, snapshot)

	for _, want := range [][3]string{
		{"alice", "1:view!", "a share of a deleted record or a lapsed one came back, or one made since the snapshot was carried"},
		{"bob", "2:view!", "a share revoked or lowered since the snapshot came back"},
		{"carol", "2:view! 3:view!", "a permission raised since the snapshot was carried, or one that was swapped kept more than both hold"},
		{"dave", "4:edit!2085-01-01 00:00:00", "a share that expired live came back, or kept the snapshot's later expiry"},
		{"erin", "4:view!2080-01-01 00:00:00 7:delete!", "an expiry extended since the snapshot was carried, or a share made since"},
		{"nobody", "", "a revoked share to an address with no account came back"},
	} {
		if shares := sharesOf(t, got, want[0]); shares != want[1] {
			t.Errorf("%s holds %q after the restore, want %q (%s)", want[0], shares, want[1], want[2])
		}
	}
	if n := credCount(t, got, `SELECT count(*) FROM notes WHERE id = 6`); n != 1 {
		t.Fatal("the data did not roll back: note 6 is missing")
	}
	r := summary.RecordGrants
	if r == nil {
		t.Fatalf("the restore audit row says nothing about record grants: %+v", summary)
	}
	if r.Kept != 7 || r.Removed != 5 || r.PermissionLowered != 2 || r.ExpiryShortened != 1 || r.KeptUnknown != 0 || r.Note != "" || r.Skipped != "" {
		t.Fatalf("record grant summary = %+v", *r)
	}
}

// The two permissions a share holds in the snapshot and live give, after a
// restore, only what both give: admin holds everything, edit and delete each
// hold view and not each other, and a name the access check does not know
// holds nothing.
func TestLowerRecordPermission(t *testing.T) {
	for _, c := range [][3]string{
		{"view", "view", "view"},
		{"admin", "admin", "admin"},
		{"admin", "edit", "edit"},
		{"edit", "admin", "edit"},
		{"admin", "view", "view"},
		{"view", "admin", "view"},
		{"edit", "view", "view"},
		{"view", "delete", "view"},
		{"edit", "delete", "view"},
		{"delete", "edit", "view"},
		{"owner", "admin", "owner"},
		{"admin", "owner", "owner"},
		{"edit", "", ""},
	} {
		if got := lowerRecordPermission(c[0], c[1]); got != c[2] {
			t.Errorf("snapshot %q, live %q: %q, want %q", c[0], c[1], got, c[2])
		}
	}
}

// recordGrantSnapshotOfAnotherDatabase builds a database with accounts 1 to 5,
// notes 1 to 6 and shares on them, and returns a snapshot of it.
func recordGrantSnapshotOfAnotherDatabase(t *testing.T, dir string) string {
	t.Helper()
	db := recordGrantFixtureDB(t, filepath.Join(dir, "source.db"), 6)
	roleFixtureUsers(t, db, [2]string{"root", "admin"}, [2]string{"mia", "user"}, [2]string{"max", "user"}, [2]string{"dan", "user"}, [2]string{"eve", "user"})
	share(t, db, 1, "mia", "edit", nil)
	share(t, db, 1, "eve", "view", nil)
	share(t, db, 2, "guest", "view", nil) // an address with no account
	share(t, db, 4, "mia", "admin", nil)
	share(t, db, 5, "eve", "delete", "2090-01-01 00:00:00")
	share(t, db, 6, "guest", "view", nil)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

// Disaster recovery: the database was lost and recreated, and the backup is
// brought back. The new database never held the backup's records, so nothing
// says a share was revoked: every share is restored.
func TestRestoreOntoAFreshDatabaseKeepsEveryRecordGrant(t *testing.T) {
	dir := t.TempDir()
	snapshot := recordGrantSnapshotOfAnotherDatabase(t, dir)
	db := recordGrantFixtureDB(t, filepath.Join(dir, "data.db"), 0)

	got, summary := restoreRoleFixture(t, db, dir, snapshot)
	for _, want := range [][2]string{
		{"mia", "1:edit! 4:admin!"},
		{"eve", "1:view! 5:delete!2090-01-01 00:00:00"},
		{"guest", "2:view! 6:view!"},
	} {
		if shares := sharesOf(t, got, want[0]); shares != want[1] {
			t.Errorf("%s restored onto a fresh database holds %q, want the snapshot's %q", want[0], shares, want[1])
		}
	}
	r := summary.RecordGrants
	if r == nil || r.Kept != 6 || r.KeptUnknown != 6 || r.Removed != 0 || !strings.Contains(r.Note, "6 record grant(s)") {
		t.Fatalf("record grant summary = %+v", r)
	}
}

// The recreated database already has two accounts and three notes of its own.
// A share on a note above its own ids, or to an account above its own ids, is
// one it never held and is kept. A share on one of its note ids to an account
// under one of its account ids, or to an address with no account, may be one
// it revoked: it is not restored.
func TestRestoreOntoAFreshDatabaseKeepsRecordGrantsItNeverHeld(t *testing.T) {
	dir := t.TempDir()
	snapshot := recordGrantSnapshotOfAnotherDatabase(t, dir)
	db := recordGrantFixtureDB(t, filepath.Join(dir, "data.db"), 3)
	credExec(t, db, `INSERT INTO _benmore_users (username, email, password_hash, role, verified, created_at) VALUES
		('new-one', 'new-one@x.test', '$2a$12$n1', 'admin', 1, '2026-10-01 09:00:00'),
		('new-two', 'new-two@x.test', '$2a$12$n2', 'user', 1, '2026-10-01 09:05:00')`)

	got, summary := restoreRoleFixture(t, db, dir, snapshot)
	for _, want := range [][3]string{
		{"mia", "4:admin!", "mia is account 2, an id the new database handed out, and note 1 is one of its note ids"},
		{"eve", "1:view! 5:delete!2090-01-01 00:00:00", "eve is account 5, which the new database never held"},
		{"guest", "6:view!", "note 2 is one of the new database's note ids and the address has no account; note 6 is not"},
	} {
		if shares := sharesOf(t, got, want[0]); shares != want[1] {
			t.Errorf("%s holds %q, want %q (%s)", want[0], shares, want[1], want[2])
		}
	}
	if r := summary.RecordGrants; r == nil || r.Kept != 4 || r.KeptUnknown != 4 || r.Removed != 2 {
		t.Fatalf("record grant summary = %+v", r)
	}
}

// A record whose id is no number is known to the live database by its row or
// by an audit row about it; one it has no trace of was never there.
func TestRestoreKnowsATextKeyedRecordByItsRowOrAuditRow(t *testing.T) {
	dir := t.TempDir()
	db := recordGrantFixtureDB(t, filepath.Join(dir, "data.db"), 0)
	roleFixtureUsers(t, db, [2]string{"root", "admin"}, [2]string{"alice", "user"})
	credExec(t, db, `CREATE TABLE docs (id TEXT PRIMARY KEY, body TEXT)`)
	credExec(t, db, `INSERT INTO docs (id, body) VALUES ('d-held', ''), ('d-deleted', ''), ('d-vanished', '')`)
	for _, id := range []string{"d-held", "d-deleted", "d-vanished"} {
		credExec(t, db, `INSERT INTO _benmore_permissions (resource_type, resource_id, grant_type, grantee_id, permission) VALUES ('docs', ?, 'user', 'alice@x.test', 'view')`, id)
	}
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)
	// Every share is revoked. One record stays, one is deleted through the
	// API (audited), one disappears with no record.
	credExec(t, db, `DELETE FROM _benmore_permissions`)
	credExec(t, db, `DELETE FROM docs WHERE id <> 'd-held'`)
	LogAudit(&App{DB: db}, "delete", "docs", "d-deleted", &Session{UserID: 1, Email: "root@x.test"}, nil, nil)

	got, summary := restoreRoleFixture(t, db, dir, snapshot)
	if ids := credString(t, got, `SELECT group_concat(resource_id) FROM _benmore_permissions WHERE resource_type = 'docs'`); ids != "d-vanished" {
		t.Fatalf("shares after the restore are on %q, want only the record the live database has no trace of", ids)
	}
	if r := summary.RecordGrants; r == nil || r.Removed != 2 || r.KeptUnknown != 1 {
		t.Fatalf("record grant summary = %+v", r)
	}
}

// With no readable live database nothing says which shares were revoked: they
// stay as the snapshot has them and the summary says so.
func TestRestoreLeavesRecordGrantsWhenLiveIsUnreadable(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "data.db")
	db := recordGrantFixtureDB(t, filepath.Join(dir, "source.db"), 2)
	roleFixtureUsers(t, db, [2]string{"root", "admin"}, [2]string{"alice", "user"})
	share(t, db, 1, "alice", "edit", nil)
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
	if shares := sharesOf(t, got, "alice"); shares != "1:edit!" {
		t.Fatalf("shares after a restore over an unreadable database = %q, want the snapshot's", shares)
	}
	if r := latestRestoreSummary(t, got).RecordGrants; r == nil || r.Skipped != restoreAuditSkippedUnreadable {
		t.Fatalf("record grant summary = %+v", r)
	}
}

// Under compliance: hipaa the rewrite deletes shares and nothing else: the
// audit tables stay append-only and the restore's row carries the counts.
func TestRestoreDoesNotReviveRevokedRecordGrantsUnderHIPAA(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "data.db")
	db := hipaaAuditFixture(t, livePath)
	EnsurePermissionsTable(db)
	roleFixtureUsers(t, db, [2]string{"root", "admin"}, [2]string{"alice", "user"})
	credExec(t, db, `INSERT INTO notes (id, body) VALUES (1, 'chart'), (2, 'chart')`)
	share(t, db, 1, "alice", "edit", nil)
	share(t, db, 2, "alice", "view", nil)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)
	credExec(t, db, `DELETE FROM _benmore_permissions WHERE resource_id = '1'`)
	root := &Session{UserID: 1, Email: "root@x.test"}
	LogAudit(&App{DB: db}, "revoke_share", "notes", "1", root, nil, map[string]any{"shared_with": "alice@x.test"})
	LogAudit(&App{DB: db}, "password_change", "_benmore_users", "1", root, nil, nil) // the row assertAuditAppendOnly tries to change
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := restoreDatabase(dir, snapshot); err != nil {
		t.Fatalf("restore: %v", err)
	}
	db, err := sql.Open("sqlite3", sqliteRestoreURI(livePath, "rw"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if shares := sharesOf(t, db, "alice"); shares != "2:view!" {
		t.Fatalf("alice holds %q after the restore, want the revocation to hold", shares)
	}
	if r := latestRestoreSummary(t, db).RecordGrants; r == nil || r.Kept != 1 || r.Removed != 1 {
		t.Fatalf("record grant summary = %+v", r)
	}
	assertAuditAppendOnly(t, db)
}

// refresh-dev's copy of production keeps its record grants: nothing on dev
// says which are current.
func TestRefreshCopyKeepsItsRecordGrants(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "copy.db")
	db := recordGrantFixtureDB(t, path, 1)
	roleFixtureUsers(t, db, [2]string{"root", "admin"}, [2]string{"alice", "user"})
	share(t, db, 1, "alice", "edit", nil)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	summary, err := revokeCopiedCredentials(t.Context(), path, "refresh-dev")
	if err != nil {
		t.Fatal(err)
	}
	if shares := sharesOf(t, openRO(t, path), "alice"); shares != "1:edit!" || summary.RecordGrants != nil {
		t.Fatalf("a refreshed copy holds %q and reports %+v, want its shares unchanged and no report", shares, summary.RecordGrants)
	}
}

// writeAppYAML puts an app.yaml beside the database a restore replaces.
func writeAppYAML(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// verifiedAdminFixture is root (an admin whose email was never verified),
// alice (an admin, demoted after the snapshot) and bob (made an admin after
// the snapshot). It returns the open live database and the snapshot.
func verifiedAdminFixture(t *testing.T, dir string) (*sql.DB, string) {
	t.Helper()
	db := roleFixtureDB(t, filepath.Join(dir, "data.db"))
	roleFixtureUsers(t, db, [2]string{"root", "admin"}, [2]string{"alice", "admin"}, [2]string{"bob", "user"})
	credExec(t, db, `UPDATE _benmore_users SET verified = 0 WHERE username = 'root'`)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)
	credExec(t, db, `UPDATE _benmore_users SET role = 'user' WHERE username = 'alice'`)
	credExec(t, db, `UPDATE _benmore_users SET role = 'admin' WHERE username = 'bob'`)
	return db, snapshot
}

// Under auth.require_verified an admin whose email is not verified cannot
// sign in and is no usable admin, exactly as the last-admin guard counts: the
// restore keeps the standing of an admin who can.
func TestRestoreCountsOnlyVerifiedAdminsWhenTheAppRequiresVerification(t *testing.T) {
	dir := t.TempDir()
	writeAppYAML(t, dir, "name: fixture\nauth:\n  require_verified: yes\n")
	db, snapshot := verifiedAdminFixture(t, dir)

	got, summary := restoreRoleFixture(t, db, dir, snapshot)
	app := &App{Design: &DesignConfig{Auth: map[string]string{"require_verified": "true"}}}
	self, others, err := durableAdminCounts(app, got, 3)
	if err != nil || !self || others != 0 {
		t.Fatalf("admins who can sign in after the restore: bob=%v others=%d (%v), want bob alone", self, others, err)
	}
	if role := roleOf(t, got, "alice"); role != "user" {
		t.Fatalf("alice, demoted since the snapshot, is %q after the restore", role)
	}
	r := summary.Roles
	if r.AdminsKept != restoreAdminsKeptLive || r.AdminsKeptCount != 1 || r.UsableAdmins != 1 || r.Warning == "" || r.RequireVerified != "true" {
		t.Fatalf("role summary = %+v", *r)
	}
}

// Without the setting an unverified admin signs in, counts, and nothing
// gained since the snapshot is kept.
func TestRestoreCountsUnverifiedAdminsWhenTheAppDoesNotRequireVerification(t *testing.T) {
	for name, appYAML := range map[string]string{"no app.yaml": "", "setting off": "name: fixture\nauth:\n  require_verified: false\n"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if appYAML != "" {
				writeAppYAML(t, dir, appYAML)
			}
			db, snapshot := verifiedAdminFixture(t, dir)
			got, summary := restoreRoleFixture(t, db, dir, snapshot)
			if a, b := roleOf(t, got, "alice"), roleOf(t, got, "bob"); a != "user" || b != "user" {
				t.Fatalf("alice = %q, bob = %q, want both at the lower role", a, b)
			}
			if r := summary.Roles; r.AdminsKept != "" || r.UsableAdmins != 1 || r.Warning != "" || r.RequireVerified != "" {
				t.Fatalf("role summary = %+v", *r)
			}
		})
	}
}

// An app.yaml that cannot be read does not say whether unverified admins can
// sign in. The restore then keeps an admin who can sign in either way, and
// does not bring back an admin role that was taken away while the app has an
// admin under the reading that the setting is off.
func TestRestoreKeepsAVerifiedAdminWhenTheSettingCannotBeRead(t *testing.T) {
	dir := t.TempDir()
	writeAppYAML(t, dir, "name: fixture\nauth: [not, a, mapping\n")
	db, snapshot := verifiedAdminFixture(t, dir)

	got, summary := restoreRoleFixture(t, db, dir, snapshot)
	if a, b := roleOf(t, got, "alice"), roleOf(t, got, "bob"); a != "user" || b != "admin" {
		t.Fatalf("alice = %q, bob = %q, want bob (an admin now, verified) kept and alice not brought back", a, b)
	}
	if r := summary.Roles; r.AdminsKept != restoreAdminsKeptLive || r.UsableAdmins != 1 || r.RequireVerified != restoreVerifiedUnknown {
		t.Fatalf("role summary = %+v", *r)
	}

	// No admin now is verified and none is in reach: the snapshot's revoked
	// admin does not come back, because root is an admin if the setting is off.
	dir = t.TempDir()
	writeAppYAML(t, dir, "name: fixture\nauth: [not, a, mapping\n")
	db = roleFixtureDB(t, filepath.Join(dir, "data.db"))
	roleFixtureUsers(t, db, [2]string{"root", "admin"}, [2]string{"alice", "admin"})
	credExec(t, db, `UPDATE _benmore_users SET verified = 0 WHERE username = 'root'`)
	snapshot = filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)
	credExec(t, db, `UPDATE _benmore_users SET role = 'user' WHERE username = 'alice'`)
	got, summary = restoreRoleFixture(t, db, dir, snapshot)
	if role := roleOf(t, got, "alice"); role != "user" {
		t.Fatalf("alice, demoted since the snapshot, is %q after the restore", role)
	}
	if r := summary.Roles; r.AdminsKept != "" || r.UsableAdmins != 0 || !strings.Contains(r.Warning, "require_verified") {
		t.Fatalf("role summary = %+v", *r)
	}
}

// The restore counts usable admins with the last-admin guard's own condition.
func TestRestoreUsableAdminConditionIsTheLastAdminGuards(t *testing.T) {
	dir := t.TempDir()
	db := roleFixtureDB(t, filepath.Join(dir, "data.db"))
	users, err := readCredTable(t.Context(), db, "_benmore_users", true, []string{"id"})
	if err != nil {
		t.Fatal(err)
	}
	grants, err := readCredTable(t.Context(), db, restoreRoleGrantsTable, true, []string{})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []bool{false, true} {
		app := &App{Design: &DesignConfig{Auth: map[string]string{"require_verified": map[bool]string{true: "true", false: "false"}[required]}}}
		if got, want := restoreUsableAdminWhere(users, grants, required), durableAdminWhere(app, true); got != want {
			t.Errorf("require_verified %v: the restore counts admins WHERE %s, the guard WHERE %s", required, got, want)
		}
		if got, want := restoreUsableAdminWhere(users, nil, required), durableAdminWhere(app, false); got != want {
			t.Errorf("require_verified %v, no grants table: the restore counts admins WHERE %s, the guard WHERE %s", required, got, want)
		}
	}
	// An account whose deactivated_at holds the empty string is deactivated to
	// every sign-in path and to the guard, so it is no usable admin here.
	roleFixtureUsers(t, db, [2]string{"blank", "admin"})
	credExec(t, db, `UPDATE _benmore_users SET deactivated_at = '' WHERE username = 'blank'`)
	if n := credCount(t, db, `SELECT COUNT(*) FROM _benmore_users u WHERE `+restoreUsableAdminWhere(users, grants, false)); n != 0 {
		t.Fatalf("%d usable admins, want none: the only admin is deactivated", n)
	}
}
