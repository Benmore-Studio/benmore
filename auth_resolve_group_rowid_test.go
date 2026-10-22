//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// ResolveGroupID ordered by rowid, which a view or a WITHOUT ROWID membership
// table does not have: the query failed and every user resolved to no tenant.
func TestResolveGroupIDWithoutRowID(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`INSERT INTO _benmore_users (username, email, role, verified) VALUES ('a', 'a@example.com', 'user', 1)`,
		`CREATE TABLE raw_members (email TEXT, org_id TEXT)`,
		`INSERT INTO raw_members (email, org_id) VALUES ('a@example.com', 'org-b'), ('a@example.com', 'org-a')`,
		`CREATE VIEW view_members AS SELECT email, org_id FROM raw_members`,
		`CREATE TABLE wr_members (email TEXT NOT NULL, org_id TEXT NOT NULL, PRIMARY KEY (email, org_id)) WITHOUT ROWID`,
		`INSERT INTO wr_members (email, org_id) VALUES ('a@example.com', 'org-b'), ('a@example.com', 'org-a')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	for _, table := range []string{"view_members", "wr_members"} {
		g := &GroupConfig{Table: table, Key: "org_id", UserField: "email"}
		// No rowid to order by: the lowest tenant key, every time.
		if got := ResolveGroupID(db, g, "a@example.com"); got != "org-a" {
			t.Errorf("%s: ResolveGroupID = %q, want org-a", table, got)
		}
		if got := ResolveGroupID(db, g, "nobody@example.com"); got != "" {
			t.Errorf("%s: a non-member resolved to %q", table, got)
		}
	}
	// An ordinary table keeps the oldest-membership (rowid) order.
	if got := ResolveGroupID(db, &GroupConfig{Table: "raw_members", Key: "org_id", UserField: "email"}, "a@example.com"); got != "org-b" {
		t.Errorf("rowid table: ResolveGroupID = %q, want the oldest membership org-b", got)
	}
}
