//go:build !cli

package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A member with two live rows in one tenant gets the oldest row's role. The
// index below makes SQLite read the rows in role order, so the newer
// duplicate ("member" sorts before "org_admin") is the one an unordered
// LIMIT 1 returned.
func TestMembershipRoleUsesOldestDuplicate(t *testing.T) {
	for _, shape := range []string{"rowid", "without rowid"} {
		t.Run(shape, func(t *testing.T) {
			dir := t.TempDir()
			db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err := EnsureUsersTable(db); err != nil {
				t.Fatal(err)
			}
			EnsureSessionsTable(db)
			ddl := `CREATE TABLE org_members (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT, user_id INTEGER, member_role TEXT)`
			if shape == "without rowid" {
				ddl = `CREATE TABLE org_members (id INTEGER PRIMARY KEY, org_id TEXT, user_id INTEGER, member_role TEXT) WITHOUT ROWID`
			}
			mustExec(t, db, ddl)
			mustExec(t, db, `CREATE INDEX org_members_lookup ON org_members (user_id, org_id, member_role)`)
			res, err := db.Exec(`INSERT INTO _benmore_users (username, email, role, verified) VALUES ('ada', 'ada@example.com', 'user', 1)`)
			if err != nil {
				t.Fatal(err)
			}
			uid, _ := res.LastInsertId()
			mustExecArgs(t, db, `INSERT INTO org_members (id, org_id, user_id, member_role) VALUES (1, 'acme', ?, 'org_admin')`, uid)
			mustExecArgs(t, db, `INSERT INTO org_members (id, org_id, user_id, member_role) VALUES (2, 'acme', ?, 'member')`, uid)
			group := &GroupConfig{Table: "org_members", Key: "org_id", UserField: "user_id", RoleField: "member_role"}
			want := "org_admin"
			if shape == "without rowid" {
				// No rowid to order by: the lookup is still deterministic,
				// ordered by the role column.
				want = "member"
			}
			for _, schema := range []string{"", "main"} {
				role, err := resolveMembershipRoleForValueWith(db, group, uid, "ada@example.com", "acme", schema)
				if err != nil || role != want {
					t.Fatalf("schema %q: role=%q err=%v, want %q", schema, role, err, want)
				}
			}
			if shape == "rowid" {
				app := &App{Dir: dir, DB: db, Group: group, Tables: []Table{{Name: "org_members", Columns: []Column{{Name: "id"}, {Name: "org_id"}, {Name: "user_id"}, {Name: "member_role"}}}}}
				session := &Session{UserID: uid, Email: "ada@example.com", GroupID: "acme"}
				if got := resolveAppRole(app, session); got != want {
					t.Fatalf("workflow/SSR role=%q, want %q", got, want)
				}
			}
		})
	}
}

// benmore check and the post-write check warn when nothing makes a member's
// row unique within a tenant.
func TestMembershipUniqueWarning(t *testing.T) {
	const appYAML = "groups:\n  table: org_members\n  key: org_id\n  user_field: user_id\n  role_field: member_role\n"
	for _, tc := range []struct {
		name, constraint, migration string
		warn                        bool
	}{
		{"none", "", "", true},
		{"pair", "@@unique([orgId, userId])", "", false},
		{"reversed pair", "@@unique([userId, orgId])", "", false},
		{"with another column", "@@unique([orgId, userId, memberRole])", "", true},
		{"compound id", "@@id([orgId, userId])", "", false},
		{"partial index in a migration", "", "CREATE UNIQUE INDEX IF NOT EXISTS org_members_live ON org_members (org_id, user_id) WHERE deleted_at IS NULL;\n", false},
		{"other table's index", "", "CREATE UNIQUE INDEX x ON invites (org_id, user_id);\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "app.yaml", appYAML)
			id := "  id Int @id @default(autoincrement())\n"
			if strings.HasPrefix(tc.constraint, "@@id") {
				id = ""
			}
			writeTestFile(t, dir, "schema.prisma", "model OrgMember {\n"+id+"  orgId String @map(\"org_id\")\n  userId Int @map(\"user_id\")\n  memberRole String @default(\"member\") @map(\"member_role\")\n  deletedAt DateTime? @map(\"deleted_at\")\n  "+tc.constraint+"\n  @@map(\"org_members\")\n}\n")
			if tc.migration != "" {
				if err := os.MkdirAll(filepath.Join(dir, "migrations"), 0o755); err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, dir, "migrations/001_unique.sql", tc.migration)
			}
			var found []string
			for _, f := range authzWarnings(dir) {
				if strings.Contains(f.Message, "groups membership table") {
					if f.Severity != "warning" {
						t.Fatalf("severity %q", f.Severity)
					}
					found = append(found, f.Message)
				}
			}
			if tc.warn != (len(found) == 1) {
				t.Fatalf("warn=%v, got %q", tc.warn, found)
			}
			if tc.warn && !strings.Contains(found[0], "@@unique([orgId, userId])") {
				t.Fatalf("warning does not name the fix: %s", found[0])
			}
			// The write gate stays advisory.
			if report := RunSourceCheck(dir, "schema.prisma"); !report.Clean() {
				t.Fatalf("the membership warning must not block the write: %+v", report.Findings)
			}
		})
	}
}
