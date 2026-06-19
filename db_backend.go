//go:build !cli

package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type DatabaseBackend string

const (
	DatabaseBackendSQLite   DatabaseBackend = "sqlite"
	DatabaseBackendPostgres DatabaseBackend = "postgres"
)

type DBOpenConfig struct {
	Backend     DatabaseBackend
	DriverName  string
	DSN         string
	LocalSQLite bool
}

func resolveDatabaseURL(dir string) string {
	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		return dbURL
	}
	return GetEnv(dir, "DATABASE_URL")
}

func buildDBOpenConfig(dir, dbURL string) DBOpenConfig {
	if dbURL == "" {
		dbPath := filepath.Join(dir, "data.db")
		return DBOpenConfig{
			Backend:     DatabaseBackendSQLite,
			DriverName:  "sqlite3_benmore",
			DSN:         sqliteAppDSN(dbPath),
			LocalSQLite: true,
		}
	}
	if isPostgresDatabaseURL(dbURL) {
		return DBOpenConfig{
			Backend:    DatabaseBackendPostgres,
			DriverName: "pgx",
			DSN:        dbURL,
		}
	}
	return DBOpenConfig{
		Backend:    DatabaseBackendSQLite,
		DriverName: "sqlite3_benmore",
		DSN:        dbURL,
	}
}

func sqliteAppDSN(dbPath string) string {
	return dbPath + "?_journal_mode=WAL" +
		"&_foreign_keys=on" +
		"&_busy_timeout=5000" +
		"&_synchronous=NORMAL" +
		"&_cache_size=-64000" +
		"&_mmap_size=268435456" +
		"&_temp_store=MEMORY"
}

func isPostgresDatabaseURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "postgres", "postgresql":
		return true
	default:
		return false
	}
}

func experimentalPostgresEnabled() bool {
	for _, key := range []string{"BENMORE_EXPERIMENTAL_POSTGRES", "BENMORE_EXPERIMENTAL_PGX"} {
		if enabledEnv(os.Getenv(key)) {
			return true
		}
	}
	return false
}

func enabledEnv(v string) bool {
	if v == "" {
		return false
	}
	if b, err := strconv.ParseBool(v); err == nil {
		return b
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func rewritePlaceholders(sqlText string, backend DatabaseBackend) string {
	if backend != DatabaseBackendPostgres || !strings.Contains(sqlText, "?") {
		return sqlText
	}

	var out strings.Builder
	out.Grow(len(sqlText) + 8)
	arg := 1
	inSingle := false
	inDouble := false
	for i := 0; i < len(sqlText); i++ {
		ch := sqlText[i]
		if inSingle {
			out.WriteByte(ch)
			if ch == '\'' {
				if i+1 < len(sqlText) && sqlText[i+1] == '\'' {
					i++
					out.WriteByte(sqlText[i])
					continue
				}
				inSingle = false
			}
			continue
		}
		if inDouble {
			out.WriteByte(ch)
			if ch == '"' {
				inDouble = false
			}
			continue
		}
		switch ch {
		case '\'':
			inSingle = true
			out.WriteByte(ch)
		case '"':
			inDouble = true
			out.WriteByte(ch)
		case '?':
			out.WriteByte('$')
			out.WriteString(strconv.Itoa(arg))
			arg++
		default:
			out.WriteByte(ch)
		}
	}
	return out.String()
}

func unsupportedPostgresRuntimeError() error {
	return fmt.Errorf("postgres DATABASE_URL detected, but app-runtime pgx support is not enabled yet; SQLite remains the production backend while the dialect, migration, encryption, FTS, backup, and insert-returning layers are ported")
}
