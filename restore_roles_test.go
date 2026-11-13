//go:build !cli

package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// roleFixtureDB is the credential fixture plus the role grants table.
func roleFixtureDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db := credentialFixtureDB(t, path)
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}
	return db
}

// roleFixtureUsers adds one verified account per name, ids from 1, each with
// its primary role.
func roleFixtureUsers(t *testing.T, db *sql.DB, accounts ...[2]string) {
	t.Helper()
	for i, a := range accounts {
		credExec(t, db, `INSERT INTO _benmore_users (id, username, email, password_hash, role, verified, created_at) VALUES (?, ?, ?, '$2a$12$fixture', ?, 1, ?)`,
			i+1, a[0], a[0]+"@x.test", a[1], "2026-01-01 10:00:0"+string(rune('0'+i%10)))
	}
}

func roleOf(t *testing.T, db *sql.DB, username string) string {
	t.Helper()
	return credString(t, db, `SELECT role FROM _benmore_users WHERE username = ?`, username)
}

// grantsOf lists an account's grants as "role@group!expiry", sorted.
func grantsOf(t *testing.T, db *sql.DB, username string) string {
	t.Helper()
	rows, err := db.Query(`SELECT g.role || '@' || COALESCE(g.group_id, '') || '!' || COALESCE(CAST(g.expires_at AS TEXT), '')
		FROM _benmore_user_roles g JOIN _benmore_users u ON u.id = g.user_id WHERE u.username = ? ORDER BY 1`, username)
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

// restoreRoleFixture closes db, restores snapshot over it and returns the
// restored database with the restore's summary.
func restoreRoleFixture(t *testing.T, db *sql.DB, dir, snapshot string) (*sql.DB, restoreCredentialSummary) {
	t.Helper()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := restoreDatabase(dir, snapshot); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got := openRO(t, filepath.Join(dir, "data.db"))
	summary := latestRestoreSummary(t, got)
	if summary.Roles == nil {
		t.Fatalf("the restore audit row says nothing about roles: %+v", summary)
	}
	return got, summary
}

// A restore never gives an account a role it does not hold now. The primary
// role is the lower of the snapshot's and the live one, a grant survives only
// when the live database still holds it unexpired, and an account deleted
// since comes back with the default role and no grants.
func TestRestoreDoesNotReviveRevokedRoles(t *testing.T) {
	dir := t.TempDir()
	db := roleFixtureDB(t, filepath.Join(dir, "data.db"))
	roleFixtureUsers(t, db,
		[2]string{"root", "admin"},    // 1 admin throughout
		[2]string{"alice", "admin"},   // 2 demoted since
		[2]string{"bob", "user"},      // 3 promoted since
		[2]string{"carol", "manager"}, // 4 demoted to the default since
		[2]string{"dave", "user"},     // 5 given a role since
		[2]string{"erin", "manager"},  // 6 moved to another role since
		[2]string{"frank", "admin"},   // 7 deleted since
		[2]string{"gina", "manager"},  // 8 deleted since
		[2]string{"hank", "manager"},  // 9 unchanged
	)
	credExec(t, db, `INSERT INTO _benmore_user_roles (user_id, role, group_id, expires_at) VALUES
		(2, 'admin',    NULL,    NULL),
		(4, 'editor',   NULL,    NULL),
		(4, 'auditor',  'org-1', NULL),
		(4, 'auditor',  'org-2', NULL),
		(5, 'editor',   NULL,    NULL),
		(5, 'reviewer', NULL,    NULL),
		(7, 'admin',    NULL,    NULL),
		(8, 'editor',   'org-1', NULL),
		(9, 'reviewer', NULL,    '2090-01-01 00:00:00'),
		(9, 'editor',   'org-1', NULL),
		(9, 'lapsed',   NULL,    '2020-01-01 00:00:00')`)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)

	// --- After the snapshot.
	credExec(t, db, `UPDATE _benmore_users SET role = 'user' WHERE username IN ('alice', 'carol')`)
	credExec(t, db, `UPDATE _benmore_users SET role = 'admin' WHERE username = 'bob'`)
	credExec(t, db, `UPDATE _benmore_users SET role = 'manager' WHERE username = 'dave'`)
	credExec(t, db, `UPDATE _benmore_users SET role = 'editor' WHERE username = 'erin'`)
	credExec(t, db, `DELETE FROM _benmore_user_roles WHERE user_id IN (7, 8)`)
	credExec(t, db, `DELETE FROM _benmore_users WHERE id IN (7, 8)`)
	// alice's global admin grant and carol's grant in org-1 are revoked.
	credExec(t, db, `DELETE FROM _benmore_user_roles WHERE (user_id = 2 AND role = 'admin') OR (user_id = 4 AND group_id = 'org-1')`)
	// dave's editor grant was given an expiry that has passed; his reviewer
	// grant one that is still ahead.
	credExec(t, db, `UPDATE _benmore_user_roles SET expires_at = '2021-06-01 00:00:00' WHERE user_id = 5 AND role = 'editor'`)
	credExec(t, db, `UPDATE _benmore_user_roles SET expires_at = '2080-01-01 00:00:00' WHERE user_id = 5 AND role = 'reviewer'`)
	// hank's reviewer grant was extended, and his org-1 grant replaced by a
	// global one.
	credExec(t, db, `UPDATE _benmore_user_roles SET expires_at = '2099-01-01 00:00:00' WHERE user_id = 9 AND role = 'reviewer'`)
	credExec(t, db, `UPDATE _benmore_user_roles SET group_id = NULL WHERE user_id = 9 AND role = 'editor'`)
	// Granted since: bob is a global admin by grant too, carol an auditor of org-3.
	credExec(t, db, `INSERT INTO _benmore_user_roles (user_id, role, group_id) VALUES (3, 'admin', NULL), (4, 'auditor', 'org-3')`)

	got, summary := restoreRoleFixture(t, db, dir, snapshot)

	for _, want := range [][3]string{
		{"root", "admin", "an admin throughout stays one"},
		{"alice", "user", "an admin demoted since the snapshot is an admin again"},
		{"bob", "user", "a role gained since the snapshot was carried into the restored data"},
		{"carol", "user", "a role taken away since the snapshot came back"},
		{"dave", "user", "a role gained since the snapshot was carried into the restored data"},
		{"erin", "editor", "an account moved to another role holds a role it does not hold now"},
		{"frank", "user", "an admin deleted since the snapshot came back an admin"},
		{"gina", "user", "an account deleted since the snapshot came back with its role"},
		{"hank", "manager", "an unchanged role changed"},
	} {
		if role := roleOf(t, got, want[0]); role != want[1] {
			t.Errorf("%s: primary role after the restore = %q, want %q (%s)", want[0], role, want[1], want[2])
		}
	}
	for _, want := range [][3]string{
		{"alice", "", "a revoked global admin grant came back"},
		{"bob", "", "a grant made since the snapshot was added"},
		{"carol", "auditor@org-2! editor@!", "only the grants still held live survive; the org-1 one was revoked, the org-3 one is newer"},
		{"dave", "reviewer@!2080-01-01 00:00:00", "a grant expired live came back, or a live expiry was dropped"},
		{"frank", "", "a deleted account came back with its admin grant"},
		{"gina", "", "a deleted account came back with a tenant grant"},
		{"hank", "reviewer@!2090-01-01 00:00:00", "an extension made since was carried, or a grant expired live or moved to another scope survived"},
	} {
		if grants := grantsOf(t, got, want[0]); grants != want[1] {
			t.Errorf("%s: grants after the restore = %q, want %q (%s)", want[0], grants, want[1], want[2])
		}
	}
	// What the session loader makes of it: alice is no admin.
	if admin, err := userHasGlobalAdminGrantWith(got, 2); err != nil || admin {
		t.Errorf("alice holds a global admin grant after the restore (%v)", err)
	}
	r := summary.Roles
	if r.Skipped != "" || r.PrimaryLowered != 3 || r.PrimaryReset != 2 || r.KeptUnknown != 0 || r.Note != "" || r.GrantsKept != 4 || r.GrantsRemoved != 7 ||
		r.GrantsShortened != 1 || r.AdminsKept != "" || r.UsableAdmins != 1 {
		t.Errorf("role summary = %+v", *r)
	}
	if t.Failed() {
		return
	}
	if n := credCount(t, got, `SELECT count(*) FROM _benmore_audit_log WHERE action = 'restore_credentials' AND new_values LIKE '%"roles":{%"grants_removed":7%'`); n != 1 {
		t.Fatal("the restore_credentials audit row does not carry the role counts")
	}
}

// An account deleted and signed up again under the same email is the same
// account to a restore: it holds no more than the new account does.
func TestRestoreAppliesLiveRolesToAReRegisteredAccount(t *testing.T) {
	dir := t.TempDir()
	db := roleFixtureDB(t, filepath.Join(dir, "data.db"))
	roleFixtureUsers(t, db, [2]string{"root", "admin"}, [2]string{"carol", "admin"})
	credExec(t, db, `INSERT INTO _benmore_user_roles (user_id, role, group_id) VALUES (2, 'editor', NULL), (2, 'auditor', 'org-1')`)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)
	credExec(t, db, `DELETE FROM _benmore_user_roles WHERE user_id = 2`)
	credExec(t, db, `DELETE FROM _benmore_users WHERE id = 2`)
	credExec(t, db, `INSERT INTO _benmore_users (id, username, email, password_hash, role, verified, created_at) VALUES (5, 'carol2', 'carol@x.test', '$2a$12$new', 'user', 1, '2026-08-01 10:00:00')`)
	credExec(t, db, `INSERT INTO _benmore_user_roles (user_id, role, group_id) VALUES (5, 'auditor', 'org-1')`)

	got, summary := restoreRoleFixture(t, db, dir, snapshot)
	if role := credString(t, got, `SELECT role FROM _benmore_users WHERE id = 2`); role != "user" {
		t.Fatalf("the restored account for carol@x.test is %q, want the new account's role", role)
	}
	if grants := grantsOf(t, got, "carol2"); grants != "auditor@org-1!" {
		t.Fatalf("grants = %q, want only the one the new account holds", grants)
	}
	if r := summary.Roles; r.PrimaryLowered != 1 || r.GrantsKept != 1 || r.GrantsRemoved != 1 {
		t.Fatalf("role summary = %+v", *r)
	}
}

// When the rule would leave no usable admin, an account that is an admin now
// keeps that standing, so nobody whose admin role was taken away gets it back.
func TestRestoreKeepsACurrentAdminWhenTheRuleLeavesNone(t *testing.T) {
	for _, viaGrant := range []bool{false, true} {
		name := "primary role"
		if viaGrant {
			name = "global grant"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			db := roleFixtureDB(t, filepath.Join(dir, "data.db"))
			roleFixtureUsers(t, db, [2]string{"alice", "admin"}, [2]string{"bob", "user"}, [2]string{"temp", "user"})
			snapshot := filepath.Join(dir, "snapshot.db")
			snapshotTo(t, db, snapshot)
			// alice hands over to bob. temp holds admin for a limited time,
			// which is no durable standing.
			credExec(t, db, `UPDATE _benmore_users SET role = 'user' WHERE username = 'alice'`)
			if viaGrant {
				credExec(t, db, `INSERT INTO _benmore_user_roles (user_id, role, group_id, granted_by) VALUES (2, 'admin', NULL, 1)`)
			} else {
				credExec(t, db, `UPDATE _benmore_users SET role = 'admin' WHERE username = 'bob'`)
			}
			credExec(t, db, `INSERT INTO _benmore_user_roles (user_id, role, group_id, expires_at) VALUES (3, 'admin', NULL, '2099-01-01 00:00:00')`)

			got, summary := restoreRoleFixture(t, db, dir, snapshot)
			if role := roleOf(t, got, "alice"); role != "user" {
				t.Fatalf("alice, demoted since the snapshot, is %q after the restore", role)
			}
			self, others, err := durableAdminCounts(nil, got, 2)
			if err != nil || !self || others != 0 {
				t.Fatalf("usable durable admins after the restore: bob=%v others=%d (%v), want bob alone", self, others, err)
			}
			if grants := grantsOf(t, got, "temp"); grants != "" {
				t.Fatalf("a time-limited admin grant made since the snapshot was carried: %q", grants)
			}
			r := summary.Roles
			if r.AdminsKept != restoreAdminsKeptLive || r.AdminsKeptCount != 1 || r.UsableAdmins != 1 || r.Warning == "" {
				t.Fatalf("role summary = %+v", *r)
			}
		})
	}
}

// When no account that is an admin now exists in the snapshot, the snapshot's
// admins keep their standing: a restore never leaves an app without an admin.
func TestRestoreKeepsSnapshotAdminsWhenNoCurrentAdminIsInTheSnapshot(t *testing.T) {
	dir := t.TempDir()
	db := roleFixtureDB(t, filepath.Join(dir, "data.db"))
	roleFixtureUsers(t, db, [2]string{"alice", "admin"}, [2]string{"bob", "user"}, [2]string{"carol", "manager"}, [2]string{"dan", "admin"})
	credExec(t, db, `INSERT INTO _benmore_user_roles (user_id, role, group_id) VALUES (2, 'admin', NULL), (2, 'editor', NULL), (3, 'editor', 'org-1')`)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)
	// alice is demoted, bob's grants are revoked, carol loses her role, dan is
	// deleted, and the only admin left signed up after the snapshot.
	credExec(t, db, `UPDATE _benmore_users SET role = 'user' WHERE username IN ('alice', 'carol')`)
	credExec(t, db, `DELETE FROM _benmore_user_roles`)
	credExec(t, db, `DELETE FROM _benmore_users WHERE username = 'dan'`)
	credExec(t, db, `INSERT INTO _benmore_users (id, username, email, password_hash, role, verified, created_at) VALUES (9, 'zed', 'zed@x.test', '$2a$12$zed', 'admin', 1, '2026-09-01 10:00:00')`)

	got, summary := restoreRoleFixture(t, db, dir, snapshot)
	if role := roleOf(t, got, "alice"); role != "admin" {
		t.Fatalf("alice = %q, want the snapshot's admin kept", role)
	}
	if grants := grantsOf(t, got, "bob"); grants != "admin@!" {
		t.Fatalf("bob's grants = %q, want the snapshot's global admin grant and nothing else", grants)
	}
	if role := roleOf(t, got, "dan"); role != "admin" {
		t.Fatalf("dan = %q, want the snapshot's admin kept", role)
	}
	// Only admin standing is kept: every other revoked role stays revoked.
	if role, grants := roleOf(t, got, "carol"), grantsOf(t, got, "carol"); role != "user" || grants != "" {
		t.Fatalf("carol = %q with grants %q: a role that is no admin standing came back", role, grants)
	}
	r := summary.Roles
	if r.AdminsKept != restoreAdminsKeptSnapshot || r.AdminsKeptCount != 3 || r.UsableAdmins != 3 || !strings.Contains(r.Warning, "3") {
		t.Fatalf("role summary = %+v", *r)
	}
}

// An admin who cannot sign in is no usable admin: a deactivated one does not
// stop the restore from keeping another.
func TestRestoreDoesNotCountADeactivatedAdminAsUsable(t *testing.T) {
	dir := t.TempDir()
	db := roleFixtureDB(t, filepath.Join(dir, "data.db"))
	roleFixtureUsers(t, db, [2]string{"old", "admin"}, [2]string{"bob", "user"})
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)
	credExec(t, db, `UPDATE _benmore_users SET deactivated_at = '2026-09-01 12:00:00' WHERE username = 'old'`)
	credExec(t, db, `UPDATE _benmore_users SET role = 'admin' WHERE username = 'bob'`)

	got, summary := restoreRoleFixture(t, db, dir, snapshot)
	if role := roleOf(t, got, "bob"); role != "admin" {
		t.Fatalf("bob = %q: the app has no admin who can sign in", role)
	}
	if v := credString(t, got, `SELECT deactivated_at FROM _benmore_users WHERE username = 'old'`); v == "" {
		t.Fatal("the deactivation was rolled back")
	}
	if r := summary.Roles; r.AdminsKept != restoreAdminsKeptLive || r.UsableAdmins != 1 {
		t.Fatalf("role summary = %+v", *r)
	}
}

// With no readable live database nothing says which roles were taken away:
// they stay as the snapshot has them and the summary says so.
func TestRestoreLeavesRolesWhenLiveIsUnreadable(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "data.db")
	db := roleFixtureDB(t, filepath.Join(dir, "source.db"))
	roleFixtureUsers(t, db, [2]string{"alice", "admin"}, [2]string{"bob", "manager"})
	credExec(t, db, `INSERT INTO _benmore_user_roles (user_id, role, group_id) VALUES (2, 'editor', 'org-1')`)
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
	if a, b, g := roleOf(t, got, "alice"), roleOf(t, got, "bob"), grantsOf(t, got, "bob"); a != "admin" || b != "manager" || g != "editor@org-1!" {
		t.Fatalf("roles after a restore over an unreadable database = %q %q %q, want the snapshot's", a, b, g)
	}
	summary := latestRestoreSummary(t, got)
	if summary.Roles == nil || summary.Roles.Skipped != restoreAuditSkippedUnreadable {
		t.Fatalf("role summary = %+v", summary.Roles)
	}
}

// Under compliance: hipaa the role rewrite touches only accounts and grants:
// the audit tables stay append-only and record the counts.
func TestRestoreDoesNotReviveRevokedRolesUnderHIPAA(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "data.db")
	db := hipaaAuditFixture(t, livePath)
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}
	roleFixtureUsers(t, db, [2]string{"root", "admin"}, [2]string{"alice", "admin"})
	credExec(t, db, `INSERT INTO _benmore_user_roles (user_id, role, group_id) VALUES (2, 'admin', NULL), (2, 'auditor', 'org-1')`)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)
	app := &App{DB: db}
	root := &Session{UserID: 1, Email: "root@x.test"}
	credExec(t, db, `UPDATE _benmore_users SET role = 'user' WHERE username = 'alice'`)
	LogAudit(app, "role_changed", "_benmore_users", "2", root, map[string]any{"role": "admin"}, map[string]any{"role": "user"})
	credExec(t, db, `DELETE FROM _benmore_user_roles WHERE user_id = 2`)
	LogAudit(app, "role_revoked", "_benmore_user_roles", "2", root, map[string]any{"role": "admin"}, nil)
	LogAudit(app, "password_change", "_benmore_users", "1", root, nil, nil)
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
	if role, grants := roleOf(t, db, "alice"), grantsOf(t, db, "alice"); role != "user" || grants != "" {
		t.Fatalf("alice = %q with grants %q after the restore, want the revocations to hold", role, grants)
	}
	// The log and the database agree: the revocations are recorded and true.
	if n := credCount(t, db, `SELECT count(*) FROM _benmore_audit_log WHERE action IN ('role_changed', 'role_revoked') AND restore_carried_at IS NOT NULL`); n != 2 {
		t.Fatalf("%d of the 2 revocation audit rows were carried", n)
	}
	if r := latestRestoreSummary(t, db).Roles; r == nil || r.PrimaryLowered != 1 || r.GrantsRemoved != 2 || r.UsableAdmins != 1 {
		t.Fatalf("role summary = %+v", r)
	}
	assertAuditAppendOnly(t, db)
}

// refresh-dev's copy of production is another instance's accounts: nothing
// on dev says which roles are current, so the copy keeps its own.
func TestRefreshCopyKeepsItsRoles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "copy.db")
	db := roleFixtureDB(t, path)
	roleFixtureUsers(t, db, [2]string{"alice", "admin"}, [2]string{"bob", "manager"})
	credExec(t, db, `INSERT INTO _benmore_user_roles (user_id, role, group_id) VALUES (2, 'editor', NULL)`)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	summary, err := revokeCopiedCredentials(t.Context(), path, "refresh-dev")
	if err != nil {
		t.Fatal(err)
	}
	got := openRO(t, path)
	if a, b, g := roleOf(t, got, "alice"), roleOf(t, got, "bob"), grantsOf(t, got, "bob"); a != "admin" || b != "manager" || g != "editor@!" {
		t.Fatalf("roles in a refreshed copy = %q %q %q, want them unchanged", a, b, g)
	}
	if summary.Roles != nil {
		t.Fatalf("a refreshed copy reports a role rewrite: %+v", summary.Roles)
	}
}

// The primary role after a restore is never above the live one, and never one
// gained since the snapshot where the two roles have an order.
func TestLowerPrimaryRole(t *testing.T) {
	for _, c := range [][3]string{
		{"admin", "admin", "admin"},
		{"admin", "user", "user"},
		{"admin", "manager", "manager"},
		{"user", "admin", "user"},
		{"manager", "admin", "manager"},
		{"manager", "user", "user"},
		{"user", "manager", "user"},
		{"manager", "editor", "editor"},
		{"manager", "manager", "manager"},
	} {
		if got := lowerPrimaryRole(c[0], c[1]); got != c[2] {
			t.Errorf("snapshot %q, live %q: %q, want %q", c[0], c[1], got, c[2])
		}
	}
	if got := restoreRoleName(nil) + restoreRoleName("") + restoreRoleName([]byte("admin")); got != "useruseradmin" {
		t.Fatalf("stored role names read as %q", got)
	}
}

// roleSnapshotOfAnotherDatabase builds a database with accounts 1 to 5 and
// their grants, and returns a snapshot of it: root and dan are admins, mia and
// max managers, eve holds grants (global, for a group, time-limited).
func roleSnapshotOfAnotherDatabase(t *testing.T, dir string) string {
	t.Helper()
	db := roleFixtureDB(t, filepath.Join(dir, "source.db"))
	roleFixtureUsers(t, db, [2]string{"root", "admin"}, [2]string{"mia", "manager"}, [2]string{"max", "manager"}, [2]string{"dan", "admin"}, [2]string{"eve", "user"})
	credExec(t, db, `INSERT INTO _benmore_user_roles (user_id, role, group_id, expires_at) VALUES
		(2, 'editor', NULL,    NULL),
		(3, 'admin',  NULL,    NULL),
		(5, 'editor', NULL,    NULL),
		(5, 'auditor', 'org-1', NULL),
		(5, 'reviewer', NULL,  '2090-01-01 00:00:00')`)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

// Disaster recovery: the database was lost and recreated, and the backup is
// brought back. The new database never held the backup's accounts, so nothing
// says a role was taken away: every role and grant is restored.
func TestRestoreOntoAFreshDatabaseKeepsEveryRole(t *testing.T) {
	dir := t.TempDir()
	snapshot := roleSnapshotOfAnotherDatabase(t, dir)
	db := roleFixtureDB(t, filepath.Join(dir, "data.db"))

	got, summary := restoreRoleFixture(t, db, dir, snapshot)
	for _, want := range [][3]string{
		{"root", "admin", ""},
		{"mia", "manager", "editor@!"},
		{"max", "manager", "admin@!"},
		{"dan", "admin", ""},
		{"eve", "user", "auditor@org-1! editor@! reviewer@!2090-01-01 00:00:00"},
	} {
		if role, grants := roleOf(t, got, want[0]), grantsOf(t, got, want[0]); role != want[1] || grants != want[2] {
			t.Errorf("%s restored onto a fresh database: role %q grants %q, want the snapshot's %q %q", want[0], role, grants, want[1], want[2])
		}
	}
	r := summary.Roles
	if r.KeptUnknown != 5 || !strings.Contains(r.Note, "5 account(s)") || r.PrimaryReset != 0 || r.PrimaryLowered != 0 ||
		r.GrantsRemoved != 0 || r.GrantsKept != 5 || r.AdminsKept != "" || r.Warning != "" || r.UsableAdmins != 3 {
		t.Fatalf("role summary = %+v", *r)
	}
}

// The recreated database already has two accounts of its own. Their ids are
// ids it handed out, so the backup's accounts under those ids are not known
// to be other people's and lose their roles; every account above them is one
// the new database never held and keeps its role and grants.
func TestRestoreOntoAFreshDatabaseKeepsRolesAboveItsOwnIDs(t *testing.T) {
	dir := t.TempDir()
	snapshot := roleSnapshotOfAnotherDatabase(t, dir)
	db := roleFixtureDB(t, filepath.Join(dir, "data.db"))
	credExec(t, db, `INSERT INTO _benmore_users (username, email, password_hash, role, verified, created_at) VALUES
		('new-one', 'new-one@x.test', '$2a$12$n1', 'user', 1, '2026-10-01 09:00:00'),
		('new-two', 'new-two@x.test', '$2a$12$n2', 'admin', 1, '2026-10-01 09:05:00')`)

	got, summary := restoreRoleFixture(t, db, dir, snapshot)
	for _, want := range [][3]string{
		{"root", "user", ""},
		{"mia", "user", ""},
		{"max", "manager", "admin@!"},
		{"dan", "admin", ""},
		{"eve", "user", "auditor@org-1! editor@! reviewer@!2090-01-01 00:00:00"},
	} {
		if role, grants := roleOf(t, got, want[0]), grantsOf(t, got, want[0]); role != want[1] || grants != want[2] {
			t.Errorf("%s: role %q grants %q, want %q %q", want[0], role, grants, want[1], want[2])
		}
	}
	r := summary.Roles
	if r.KeptUnknown != 3 || r.PrimaryReset != 2 || r.GrantsRemoved != 1 || r.GrantsKept != 4 || r.AdminsKept != "" || r.UsableAdmins != 2 {
		t.Fatalf("role summary = %+v", *r)
	}
}

// Without an id sequence the highest id the live database holds is all it
// says about ids, and an account deleted above it is known by its audit row:
// it comes back with the default role. An account above it with no audit row
// was never there and keeps its role.
func TestRestoreKnowsADeletedAccountByItsAuditRow(t *testing.T) {
	dir := t.TempDir()
	db := roleFixtureDB(t, filepath.Join(dir, "data.db"))
	roleFixtureUsers(t, db, [2]string{"root", "admin"}, [2]string{"gone", "admin"}, [2]string{"other", "manager"})
	credExec(t, db, `INSERT INTO _benmore_user_roles (user_id, role, group_id) VALUES (2, 'editor', NULL), (3, 'editor', NULL)`)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)
	// gone is deleted by an admin, which is audited. other's row disappears
	// with no record, and the sequence is lost: the live database holds
	// nothing that says account 3 ever existed.
	credExec(t, db, `DELETE FROM _benmore_user_roles`)
	credExec(t, db, `DELETE FROM _benmore_users WHERE id IN (2, 3)`)
	LogAudit(&App{DB: db}, "delete", "_benmore_users", "2", &Session{UserID: 1, Email: "root@x.test"}, map[string]any{"username": "gone"}, nil)
	credExec(t, db, `DELETE FROM sqlite_sequence WHERE name = '_benmore_users'`)

	got, summary := restoreRoleFixture(t, db, dir, snapshot)
	if role, grants := roleOf(t, got, "gone"), grantsOf(t, got, "gone"); role != "user" || grants != "" {
		t.Fatalf("an account whose deletion the live audit log records came back as %q with grants %q", role, grants)
	}
	if role, grants := roleOf(t, got, "other"), grantsOf(t, got, "other"); role != "manager" || grants != "editor@!" {
		t.Fatalf("an account the live database has no trace of came back as %q with grants %q, want the snapshot's", role, grants)
	}
	if r := summary.Roles; r.KeptUnknown != 1 || r.PrimaryReset != 1 || r.GrantsRemoved != 1 || r.GrantsKept != 1 {
		t.Fatalf("role summary = %+v", *r)
	}
}
