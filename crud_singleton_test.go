//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func openSingletonDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestTableHasUniqueUserID(t *testing.T) {
	db := openSingletonDB(t)
	defer db.Close()

	// Singleton: user_id is UNIQUE.
	if _, err := db.Exec(`CREATE TABLE profiles (id INTEGER PRIMARY KEY, user_id INTEGER UNIQUE, bio TEXT)`); err != nil {
		t.Fatal(err)
	}
	// Not a singleton: user_id has no unique constraint.
	if _, err := db.Exec(`CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER, body TEXT)`); err != nil {
		t.Fatal(err)
	}
	// Composite unique - not a per-user singleton.
	if _, err := db.Exec(`CREATE TABLE memberships (id INTEGER PRIMARY KEY, user_id INTEGER, org_id INTEGER, UNIQUE(user_id, org_id))`); err != nil {
		t.Fatal(err)
	}
	// No user_id at all.
	if _, err := db.Exec(`CREATE TABLE config (id INTEGER PRIMARY KEY, key TEXT UNIQUE, value TEXT)`); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		table string
		want  bool
	}{
		{"profiles", true},
		{"notes", false},
		{"memberships", false},
		{"config", false},
	}
	for _, tc := range cases {
		got := tableHasUniqueUserID(db, tc.table)
		if got != tc.want {
			t.Errorf("tableHasUniqueUserID(%q) = %v, want %v", tc.table, got, tc.want)
		}
	}
}
