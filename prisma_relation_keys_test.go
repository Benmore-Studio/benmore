//go:build !cli

package main

import "testing"

func TestPrismaRelationParentKeyMetadataMatchesNativeSQLite(t *testing.T) {
	for _, tc := range []struct {
		name, columns, indexSQL, status string
		valid                           bool
	}{
		{"rowid primary key", "id INTEGER PRIMARY KEY", "", "valid", true},
		{"text primary key", "id TEXT PRIMARY KEY", "", "valid", true},
		{"column unique", "id TEXT UNIQUE", "", "valid", true},
		{"nonunique", "id TEXT", "", "invalid", false},
		{"partial unique", "id TEXT", "CREATE UNIQUE INDEX candidate ON parents(id) WHERE id IS NOT NULL", "invalid", false},
		{"expression unique", "id TEXT", "CREATE UNIQUE INDEX candidate ON parents(lower(id))", "invalid", false},
		{"composite primary key", "id TEXT, other TEXT DEFAULT 'x', PRIMARY KEY(id,other)", "", "invalid", false},
		{"composite unique", "id TEXT, other TEXT DEFAULT 'x', UNIQUE(id,other)", "", "invalid", false},
		{"explicit binary", "id TEXT UNIQUE COLLATE BINARY", "", "unknown", true},
		{"matching nocase", "id TEXT PRIMARY KEY COLLATE NOCASE", "", "unknown", true},
		{"table key overrides column collation", "id TEXT, PRIMARY KEY(id COLLATE NOCASE)", "", "unknown", false},
		{"index overrides default binary", "id TEXT", "CREATE UNIQUE INDEX candidate ON parents(id COLLATE NOCASE)", "invalid", false},
		{"index overrides declared nocase", "id TEXT COLLATE NOCASE", "CREATE UNIQUE INDEX candidate ON parents(id COLLATE BINARY)", "unknown", false},
		{"conservative literal presence", "id TEXT UNIQUE, note TEXT DEFAULT 'COLLATE'", "", "unknown", true},
		{"alternate compatible index", "id TEXT", "CREATE UNIQUE INDEX candidate ON parents(id COLLATE NOCASE); CREATE UNIQUE INDEX compatible ON parents(id)", "valid", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := migrationSafetyDB(t)
			mustExec(t, db, "CREATE TABLE parents("+tc.columns+")")
			if tc.indexSQL != "" {
				mustExec(t, db, tc.indexSQL)
			}
			mustExec(t, db, "INSERT INTO parents(id) VALUES('1')")
			mustExec(t, db, "CREATE TABLE constrained(parent_id REFERENCES parents(id))")
			_, nativeErr := db.Exec("INSERT INTO constrained VALUES('1')")
			if (nativeErr == nil) != tc.valid {
				t.Fatalf("native FK oracle disagrees: %v", nativeErr)
			}
			status, err := prismaRelationParentKeyStatus(db, "parents", "id")
			if err != nil || status != tc.status {
				t.Fatalf("metadata status = %q, %v; want %s", status, err, tc.status)
			}
			mustExec(t, db, "CREATE TABLE retained(parent_id)")
			mustExec(t, db, "INSERT INTO retained VALUES('1')")
			unknown, err := checkPrismaRelationRepairs(db, map[string][]PrismaField{"retained": {{Column: "parent_id", FKTable: "parents", FKColumn: "id"}}})
			if (err != nil) != (tc.status == "invalid") || (len(unknown) > 0) != (tc.status == "unknown") {
				t.Fatalf("repair did not retain valid/invalid/unknown distinction: %v, %v", unknown, err)
			}
		})
	}
}
