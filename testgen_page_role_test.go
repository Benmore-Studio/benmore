//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestGeneratePageTestsRespectsGenericUserPageRole(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}

	app := &App{DB: db, Paths: DiscoverAuthPaths(nil), Pages: map[string]*Page{
		"/specialist": {Route: "/specialist", Auth: "required", Role: "specialist"},
		"/account":    {Route: "/account", Auth: "required", Role: "user"},
	}}
	tests := generatePageTests(app).Tests
	if got := tests["page_specialist_role_denied"].Steps[0].Expect.Status; got != 403 {
		t.Fatalf("generic user role denial status = %d, want 403", got)
	}
	if got := tests["page_account_authenticated"].Steps[0].Expect.Status; got != 200 {
		t.Fatalf("generic user authenticated status = %d, want 200", got)
	}
	if _, ok := tests["page_specialist_auth_redirect"]; !ok {
		t.Fatal("role-aware generation removed anonymous auth redirect")
	}
}
