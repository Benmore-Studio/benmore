//go:build !cli

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAppUsesStagedDatabaseEnvironment(t *testing.T) {
	dir := t.TempDir()
	stagedDB := filepath.Join(dir, "staged.db")
	publishedDB := filepath.Join(dir, "published.db")
	before := AppEnvSnapshot(dir)
	storeAppEnv(dir, map[string]string{
		"DATABASE_URL":   "file:" + publishedDB + "?mode=rwc",
		"DB_SYNCHRONOUS": "NORMAL",
	})
	t.Cleanup(func() { storeAppEnv(dir, before) })
	t.Setenv("DATABASE_URL", "")
	t.Setenv("DB_SYNCHRONOUS", "")
	// An unset process key allows env.yaml to supply it; empty process values override YAML.
	if err := os.Unsetenv("DATABASE_URL"); err != nil {
		t.Fatal(err)
	}
	if err := os.Unsetenv("DB_SYNCHRONOUS"); err != nil {
		t.Fatal(err)
	}

	env := fmt.Sprintf("DATABASE_URL: %q\n", "file:"+stagedDB+"?mode=rwc")
	if err := os.WriteFile(filepath.Join(dir, "env.yaml"), []byte(env), 0600); err != nil {
		t.Fatal(err)
	}

	app, err := loadAppWithOptions(dir, appLoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown()

	if _, err := os.Stat(stagedDB); err != nil {
		t.Fatalf("staged SQLite database was not opened: %v", err)
	}
	if _, err := os.Stat(publishedDB); !os.IsNotExist(err) {
		t.Fatalf("published SQLite database should not be opened, stat error = %v", err)
	}
}

func TestOpenDBUsesStagedSynchronousSetting(t *testing.T) {
	dir := t.TempDir()
	before := AppEnvSnapshot(dir)
	storeAppEnv(dir, map[string]string{"DB_SYNCHRONOUS": "NORMAL"})
	t.Cleanup(func() { storeAppEnv(dir, before) })
	t.Setenv("DATABASE_URL", "")
	t.Setenv("DB_SYNCHRONOUS", "")

	db, err := openDBWithEnv(dir, map[string]string{"DB_SYNCHRONOUS": "FULL"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var synchronous int
	if err := db.QueryRow("PRAGMA synchronous").Scan(&synchronous); err != nil {
		t.Fatal(err)
	}
	if synchronous != 2 { // SQLite FULL
		t.Fatalf("PRAGMA synchronous = %d, want FULL (2)", synchronous)
	}
}
