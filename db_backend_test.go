//go:build !cli

package main

import (
	"strings"
	"testing"
)

func TestBuildDBOpenConfigLocalSQLite(t *testing.T) {
	cfg := buildDBOpenConfig("/tmp/example-app", "")
	if cfg.Backend != DatabaseBackendSQLite {
		t.Fatalf("backend = %s, want sqlite", cfg.Backend)
	}
	if cfg.DriverName != "sqlite3_benmore" {
		t.Fatalf("driver = %s, want sqlite3_benmore", cfg.DriverName)
	}
	if !cfg.LocalSQLite {
		t.Fatal("local sqlite should be marked LocalSQLite")
	}
	if !strings.Contains(cfg.DSN, "data.db?_journal_mode=WAL") {
		t.Fatalf("local DSN missing sqlite tuning: %s", cfg.DSN)
	}
}

func TestBuildDBOpenConfigRemoteSQLite(t *testing.T) {
	cfg := buildDBOpenConfig("/tmp/example-app", "file:remote.db?cache=shared")
	if cfg.Backend != DatabaseBackendSQLite {
		t.Fatalf("backend = %s, want sqlite", cfg.Backend)
	}
	if cfg.DriverName != "sqlite3_benmore" {
		t.Fatalf("driver = %s, want sqlite3_benmore", cfg.DriverName)
	}
	if cfg.LocalSQLite {
		t.Fatal("external sqlite URL should not be treated as a local data.db")
	}
}

func TestBuildDBOpenConfigRecognizesPostgres(t *testing.T) {
	for _, raw := range []string{
		"postgres://user:pass@example.com/db",
		"postgresql://user:pass@example.com/db",
	} {
		cfg := buildDBOpenConfig("/tmp/example-app", raw)
		if cfg.Backend != DatabaseBackendPostgres {
			t.Fatalf("%s backend = %s, want postgres", raw, cfg.Backend)
		}
		if cfg.DriverName != "pgx" {
			t.Fatalf("%s driver = %s, want pgx", raw, cfg.DriverName)
		}
	}
}

func TestRewritePlaceholdersForPostgres(t *testing.T) {
	in := `SELECT * FROM notes WHERE title = ? AND body != '?' AND "weird?" = ? AND note = 'it''s ?'`
	got := rewritePlaceholders(in, DatabaseBackendPostgres)
	want := `SELECT * FROM notes WHERE title = $1 AND body != '?' AND "weird?" = $2 AND note = 'it''s ?'`
	if got != want {
		t.Fatalf("rewrite:\n got: %s\nwant: %s", got, want)
	}

	if sqlite := rewritePlaceholders(in, DatabaseBackendSQLite); sqlite != in {
		t.Fatalf("sqlite placeholders should be unchanged: %s", sqlite)
	}
}

func TestOpenDBPostgresURLFailsClosed(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@example.com/db")
	_, err := OpenDB(t.TempDir())
	if err == nil {
		t.Fatal("OpenDB should fail closed for postgres URLs until runtime support is complete")
	}
	if !strings.Contains(err.Error(), "pgx support is not enabled yet") {
		t.Fatalf("unexpected error: %v", err)
	}
}
