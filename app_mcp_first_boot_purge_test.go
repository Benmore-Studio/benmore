//go:build !cli

package main

import (
	"context"
	"strings"
	"testing"
)

// A new app's first start creates the connector tables (they reference
// _benmore_users) before the users table exists, and the manifest-load purge
// then ran a DELETE on the credential table. SQLite refuses DML on a child
// table whose parent is missing, so every first boot (and every `benmore
// test`, which starts from a fresh database) logged
// "ERROR mcp: purging credentials of removed connections failed ... no such
// table: main._benmore_users" although there was nothing to purge.
func TestFreshScaffoldFirstLoadLogsNoError(t *testing.T) {
	dir := t.TempDir()
	if err := WriteHTMLScaffoldFiles(dir, "First boot"); err != nil {
		t.Fatal(err)
	}
	var app *App
	var err error
	out := captureLog(t, func() { app, err = loadAppForServerTests(dir) })
	if err != nil {
		t.Fatalf("first load: %v\n%s", err, out)
	}
	t.Cleanup(app.Shutdown)
	if app.MCP == nil {
		t.Fatal("the scaffold's starter mcp.yaml did not load, so the purge under test never ran")
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "ERROR") {
			t.Errorf("first load of a new app logged: %s", line)
		}
	}
}

// Nothing stored means nothing to purge, whether or not the users table
// exists yet; the purge still deletes, and a failure to delete a stored
// credential still surfaces.
func TestPurgeConnectionCredentialsBeforeUsersTableExists(t *testing.T) {
	db, err := OpenDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := ensureAppMCPGrantTables(db); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, keep := range [][]string{nil, {"items"}} {
		if n, err := purgeAppMCPConnectionCredentials(ctx, db, keep); err != nil || n != 0 {
			t.Fatalf("purge (keep %v) with no users table and no credentials: %d, %v", keep, n, err)
		}
	}
	out := captureLog(t, func() { purgeUndeclaredAppMCPConnectionCredentials(db, nil) })
	if out != "" {
		t.Fatalf("purge with nothing stored logged: %s", out)
	}

	// With the users table in place the purge deletes what the manifest no
	// longer declares and keeps the rest.
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO _benmore_users (id, username, email, password_hash) VALUES (1, 'u', 'u@test.com', 'x')`,
		`INSERT INTO _benmore_mcp_connection_credentials (user_id, connection, upstream_host, secret_ciphertext, updated_at) VALUES (1, 'items', 'h', 'c', 1), (1, 'gone', 'h', 'c', 1)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := purgeAppMCPConnectionCredentials(ctx, db, []string{"items"}); err != nil || n != 1 {
		t.Fatalf("purge of the removed connection: %d, %v", n, err)
	}
	var left string
	if err := db.QueryRow(`SELECT group_concat(connection) FROM _benmore_mcp_connection_credentials`).Scan(&left); err != nil || left != "items" {
		t.Fatalf("credentials left: %q, %v", left, err)
	}

	// A stored credential the purge cannot delete is a real failure: its
	// ERROR line stays. Dropping the users table with foreign keys off leaves
	// the credential row behind, and the DELETE is then refused.
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{`PRAGMA foreign_keys = OFF`, `DROP TABLE _benmore_users`, `PRAGMA foreign_keys = ON`} {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	conn.Close()
	if n, err := purgeAppMCPConnectionCredentials(ctx, db, nil); err == nil {
		t.Fatalf("purge of a credential that cannot be deleted reported success (%d deleted)", n)
	}
	out = captureLog(t, func() { purgeUndeclaredAppMCPConnectionCredentials(db, nil) })
	if !strings.Contains(out, "ERROR mcp: purging credentials of removed connections failed") {
		t.Fatalf("a failed purge of a stored credential logged no error: %q", out)
	}
}
