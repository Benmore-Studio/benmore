//go:build !cli && !platform

package main

import (
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestServeBootCheckRunsValidatorsInFrameworkBuild(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte("broken: [\n"), 0600); err != nil {
		t.Fatal(err)
	}

	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	serveBootCheck(dir)
	_ = w.Close()
	os.Stderr = oldStderr

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if !strings.Contains(got, "flows.yaml") || !strings.Contains(got, "ERROR [syntax]") {
		t.Fatalf("serveBootCheck output = %q, want syntax finding for flows.yaml", got)
	}
}

func TestLoadAppForServerTestsResetsDatabaseBeforeLoad(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "schema.sql"), []byte(`CREATE TABLE contacts (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT
);
`), 0600); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE contacts (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO contacts (name) VALUES ('stale')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	app, err := loadAppForServerTests(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown()

	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM contacts`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("test DB was not reset before load; contacts count = %d", count)
	}
}

func TestLoadAppForServerTestsDoesNotWritePrismaMigrationFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte(`model Note {
  id    Int     @id @default(autoincrement())
  title String?
}
`), 0600); err != nil {
		t.Fatal(err)
	}

	app, err := loadAppForServerTests(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown()

	if _, err := os.Stat(filepath.Join(dir, "migrations")); !os.IsNotExist(err) {
		t.Fatalf("benmore test boot should not write migrations/, stat err=%v", err)
	}
}

// TestResetServerTestDatabaseGuardsDeployedApp locks in the WS4 guard: `benmore
// test` must not wipe a deployed app's DB (signalled by a .benmore/ dir) unless
// the operator explicitly opts in.
func TestResetServerTestDatabaseGuardsDeployedApp(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "data.db")
	if err := os.WriteFile(dbPath, []byte("SQLite format 3\x00"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".benmore"), 0700); err != nil {
		t.Fatal(err)
	}

	if err := resetServerTestDatabase(dir); err == nil {
		t.Fatal("reset must refuse a deployed app (.benmore/ present)")
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("data.db must be left intact when reset refuses: %v", err)
	}

	t.Setenv("BENMORE_TEST_RESET", "1")
	if err := resetServerTestDatabase(dir); err != nil {
		t.Fatalf("reset with BENMORE_TEST_RESET=1 should succeed: %v", err)
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatal("data.db should be removed when BENMORE_TEST_RESET=1")
	}
}
