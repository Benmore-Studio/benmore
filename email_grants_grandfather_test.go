//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// Accounts that existed before email-keyed grants required verification keep
// them (so apps that never sent verification links don't lock out current
// members); accounts created afterwards must verify. A grandfathered account
// is not "claimed" by a later OAuth sign-in either.
func TestExistingAccountsKeepEmailKeyedGrants(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	// A users table from before the grandfathering column existed.
	mustExec(t, db, `CREATE TABLE _benmore_users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE,
		password_hash TEXT, verified INTEGER DEFAULT 0, role TEXT DEFAULT 'user', deactivated_at DATETIME)`)
	mustExec(t, db, `INSERT INTO _benmore_users (id, username, email, password_hash) VALUES (1, 'old', 'old@corp.example', 'old-hash')`)
	mustExec(t, db, `CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, email TEXT)`)
	mustExec(t, db, `INSERT INTO members (org_id, email) VALUES ('tenant-a', 'old@corp.example'), ('tenant-a', 'new@corp.example')`)
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `INSERT INTO _benmore_users (id, username, email, password_hash) VALUES (2, 'new', 'new@corp.example', 'new-hash')`)
	// A second startup must not grandfather accounts created since.
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	group := &GroupConfig{Table: "members", Key: "org_id", UserField: "email"}
	if g := ResolveGroupID(db, group, "old@corp.example"); g != "tenant-a" {
		t.Fatalf("existing unverified member lost their tenant: %q", g)
	}
	if g := ResolveGroupID(db, group, "new@corp.example"); g != "" {
		t.Fatalf("account created after the upgrade got an email-keyed tenant unverified: %q", g)
	}

	app := &App{DB: db}
	if _, err := oauthFindOrCreateUser(app, "old@corp.example", "Old", true); err != nil {
		t.Fatal(err)
	}
	var hash string
	var verified int
	db.QueryRow(`SELECT password_hash, verified FROM _benmore_users WHERE id = 1`).Scan(&hash, &verified)
	if hash != "old-hash" || verified != 1 {
		t.Fatalf("grandfathered account after OAuth sign-in: hash kept=%v verified=%d", hash == "old-hash", verified)
	}
}
