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
		// DriverName must stay empty until a pgx driver is actually registered;
		// advertising "pgx" before that would be a "sql: unknown driver" trap.
		if cfg.DriverName != "" {
			t.Fatalf("%s driver = %q, want empty until pgx is registered", raw, cfg.DriverName)
		}
	}
}

func TestBuildDBOpenConfigRecognizesLibpqKeywordDSN(t *testing.T) {
	for _, raw := range []string{
		"host=localhost dbname=app user=x",
		"dbname=app sslmode=require",
		"  host=db.internal port=5432 user=svc ",
	} {
		cfg := buildDBOpenConfig("/tmp/example-app", raw)
		if cfg.Backend != DatabaseBackendPostgres {
			t.Fatalf("%q backend = %s, want postgres (libpq keyword form)", raw, cfg.Backend)
		}
	}
}

func TestBuildDBOpenConfigSQLiteNotMistakenForPostgres(t *testing.T) {
	for _, raw := range []string{
		"file:remote.db?cache=shared",
		"file:/var/data/app.db",
		"./data.db",
	} {
		cfg := buildDBOpenConfig("/tmp/example-app", raw)
		if cfg.Backend != DatabaseBackendSQLite {
			t.Fatalf("%q backend = %s, want sqlite", raw, cfg.Backend)
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

func TestRewritePlaceholdersEdgeCases(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "line comment does not consume a parameter",
			in:   "SELECT ? -- trailing ? comment\n , ?",
			want: "SELECT $1 -- trailing ? comment\n , $2",
		},
		{
			name: "block comment does not consume a parameter",
			in:   "SELECT ? /* mid ? comment */, ?",
			want: "SELECT $1 /* mid ? comment */, $2",
		},
		{
			name: "dollar-quoted body untouched",
			in:   "INSERT INTO t VALUES ($$ has ? inside $$, ?)",
			want: "INSERT INTO t VALUES ($$ has ? inside $$, $1)",
		},
		{
			name: "tagged dollar quote untouched",
			in:   "SELECT $tag$ a ? b $tag$, ?",
			want: "SELECT $tag$ a ? b $tag$, $1",
		},
		{
			name: "E-string with backslash-escaped quote",
			in:   `SELECT E'\'?', ?`,
			want: `SELECT E'\'?', $1`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rewritePlaceholders(tc.in, DatabaseBackendPostgres); got != tc.want {
				t.Fatalf("rewrite mismatch:\n got: %s\nwant: %s", got, tc.want)
			}
		})
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
