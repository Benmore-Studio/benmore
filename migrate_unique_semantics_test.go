//go:build !cli

package main

import (
	"context"
	"testing"
)

func TestUserMigrationUsesSQLiteUniqueSemantics(t *testing.T) {
	cases := []struct {
		name, setup, migration string
		wantError              bool
	}{
		{"nullable", `CREATE TABLE items(id INTEGER PRIMARY KEY,value TEXT); INSERT INTO items VALUES(1,NULL),(2,NULL)`, `CREATE UNIQUE INDEX uq ON items(value)`, false},
		{"composite null", `CREATE TABLE items(a TEXT,b TEXT); INSERT INTO items VALUES('x',NULL),('x',NULL)`, `CREATE UNIQUE INDEX uq ON items(a,b)`, false},
		{"partial", `CREATE TABLE items(value TEXT,active INTEGER); INSERT INTO items VALUES('x',0),('x',0),('x',1)`, `CREATE UNIQUE INDEX uq ON items(value) WHERE active=1`, false},
		{"dedupe within migration", `CREATE TABLE items(id INTEGER PRIMARY KEY,value TEXT); INSERT INTO items VALUES(1,'x'),(2,'x')`, `DELETE FROM items WHERE id=2; CREATE UNIQUE INDEX uq ON items(value)`, false},
		{"duplicate", `CREATE TABLE items(value TEXT); INSERT INTO items VALUES('x'),('x')`, `CREATE UNIQUE INDEX uq ON items(value)`, true},
		{"collation", `CREATE TABLE items(value TEXT); INSERT INTO items VALUES('x'),('X')`, `CREATE UNIQUE INDEX uq ON items(value COLLATE NOCASE)`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			db := migrationSafetyDB(t)
			mustExec(t, db, c.setup)
			mustExec(t, db, `CREATE TABLE migration_ledger(name TEXT PRIMARY KEY)`)
			err := runMigrationDataCtx(context.Background(), db, []byte(c.migration), "migration.sql", `INSERT INTO migration_ledger VALUES(?)`)
			if (err != nil) != c.wantError {
				t.Fatalf("migration err=%v wantError=%v", err, c.wantError)
			}
			var n int
			if err := db.QueryRow(`SELECT COUNT(*) FROM migration_ledger`).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if (n == 0) != c.wantError {
				t.Fatalf("ledger rows=%d wantError=%v", n, c.wantError)
			}
			if c.wantError {
				if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_schema WHERE name='uq'`).Scan(&n); err != nil || n != 0 {
					t.Fatalf("failed migration left index: %d %v", n, err)
				}
			}
		})
	}
}
