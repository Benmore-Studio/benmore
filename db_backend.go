//go:build !cli

package main

import (
	"fmt"
	"log"
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
		// DriverName is intentionally left empty: there is no pgx driver
		// registered in this tree yet, so advertising "pgx" here would be a
		// trap - any caller that honored it would hit a "sql: unknown driver"
		// panic/error. OpenDB fails closed on the Postgres backend before any
		// sql.Open(cfg.DriverName, ...) is reached. The next pgx slice should
		// set DriverName once the driver is actually registered.
		return DBOpenConfig{
			Backend: DatabaseBackendPostgres,
			DSN:     dbURL,
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

// isPostgresDatabaseURL reports whether raw names a Postgres database. It
// recognizes both the URL form (postgres:// / postgresql://) and the libpq
// keyword/value form (e.g. "host=localhost dbname=app user=x"). The keyword
// form has no URL scheme, so url.Parse would silently classify it as SQLite
// and hand it to the SQLite driver - exactly the misconfiguration this layer
// exists to fail closed on.
func isPostgresDatabaseURL(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return false
	}
	if u, err := url.Parse(trimmed); err == nil {
		switch strings.ToLower(u.Scheme) {
		case "postgres", "postgresql":
			return true
		}
	} else {
		// A parse failure is treated as SQLite below, but surface a hint so a
		// fat-fingered Postgres URL doesn't only show up as an opaque SQLite
		// error deep in Ping().
		log.Printf("db backend: DATABASE_URL did not parse as a URL (%v); treating as a non-URL DSN", err)
	}
	if looksLikeLibpqKeywordDSN(trimmed) {
		return true
	}
	return false
}

// looksLikeLibpqKeywordDSN detects the libpq keyword/value connection-string
// form, which carries no URL scheme. We only treat a string as keyword-form
// Postgres when it contains no scheme separator ("://") and includes at least
// one of the canonical libpq connection keywords as a "key=" token. This is
// deliberately conservative: a SQLite "file:..." DSN or a bare path won't match.
func looksLikeLibpqKeywordDSN(raw string) bool {
	if strings.Contains(raw, "://") {
		return false
	}
	lower := strings.ToLower(raw)
	for _, key := range []string{"host=", "hostaddr=", "dbname=", "user=", "port=", "sslmode="} {
		if strings.Contains(lower, key) {
			return true
		}
	}
	return false
}

// rewritePlaceholders converts SQLite-style "?" parameter markers into the
// numbered "$N" markers Postgres/pgx expects. It is experimental scaffolding
// for the future pgx slice and is not yet wired into any runtime CRUD path;
// it is exercised only by unit tests. Do not trust it for production SQL until
// the pgx backend is actually enabled and this has broader coverage.
//
// The scanner emits literal/comment bodies verbatim so a "?" appearing inside
// any of the following does NOT consume a parameter slot:
//   - single-quoted string literals ('...'), including doubled-quote escapes
//     and, in E'...' escape strings, backslash escapes (\' , \\)
//   - double-quoted identifiers ("...")
//   - dollar-quoted strings ($$...$$ and $tag$...$tag$)
//   - line comments (-- ... newline)
//   - block comments (/* ... */)
func rewritePlaceholders(sqlText string, backend DatabaseBackend) string {
	if backend != DatabaseBackendPostgres || !strings.Contains(sqlText, "?") {
		return sqlText
	}

	var out strings.Builder
	out.Grow(len(sqlText) + 8)
	arg := 1
	n := len(sqlText)
	for i := 0; i < n; i++ {
		ch := sqlText[i]
		switch {
		case ch == '-' && i+1 < n && sqlText[i+1] == '-':
			// Line comment: copy verbatim through the next newline (or EOF).
			j := i
			for j < n && sqlText[j] != '\n' {
				j++
			}
			out.WriteString(sqlText[i:j])
			i = j - 1
		case ch == '/' && i+1 < n && sqlText[i+1] == '*':
			// Block comment: copy verbatim through the closing "*/".
			j := i + 2
			for j < n && !(sqlText[j] == '*' && j+1 < n && sqlText[j+1] == '/') {
				j++
			}
			if j < n {
				j += 2 // include the closing "*/"
			} else {
				j = n
			}
			out.WriteString(sqlText[i:j])
			i = j - 1
		case ch == '\'':
			// Single-quoted string literal. If the immediately preceding
			// non-emitted context was an E/e flag we still handle backslash
			// escapes; rather than look behind, we always honor backslash
			// escapes inside single quotes, which is safe for both '...' and
			// E'...' bodies (a stray backslash in a standard string is just a
			// byte and never the closing quote anyway).
			escape := i > 0 && (sqlText[i-1] == 'E' || sqlText[i-1] == 'e')
			j := i + 1
			out.WriteByte(ch)
			for j < n {
				c := sqlText[j]
				if escape && c == '\\' && j+1 < n {
					out.WriteByte(c)
					out.WriteByte(sqlText[j+1])
					j += 2
					continue
				}
				if c == '\'' {
					if j+1 < n && sqlText[j+1] == '\'' {
						// Doubled '' escape: emit both, stay in the literal.
						out.WriteByte(c)
						out.WriteByte(sqlText[j+1])
						j += 2
						continue
					}
					out.WriteByte(c)
					j++
					break
				}
				out.WriteByte(c)
				j++
			}
			i = j - 1
		case ch == '"':
			// Double-quoted identifier. "" is a doubled-quote escape.
			j := i + 1
			out.WriteByte(ch)
			for j < n {
				c := sqlText[j]
				if c == '"' {
					if j+1 < n && sqlText[j+1] == '"' {
						out.WriteByte(c)
						out.WriteByte(sqlText[j+1])
						j += 2
						continue
					}
					out.WriteByte(c)
					j++
					break
				}
				out.WriteByte(c)
				j++
			}
			i = j - 1
		case ch == '$':
			// Possible dollar-quoted string: $tag$...$tag$ (tag may be empty).
			if tag, ok := dollarQuoteTag(sqlText, i); ok {
				closing := tag
				end := strings.Index(sqlText[i+len(tag):], closing)
				var j int
				if end < 0 {
					j = n
				} else {
					j = i + len(tag) + end + len(closing)
				}
				out.WriteString(sqlText[i:j])
				i = j - 1
			} else {
				out.WriteByte(ch)
			}
		case ch == '?':
			out.WriteByte('$')
			out.WriteString(strconv.Itoa(arg))
			arg++
		default:
			out.WriteByte(ch)
		}
	}
	return out.String()
}

// dollarQuoteTag returns the opening dollar-quote tag (e.g. "$$" or "$tag$")
// starting at index i if sqlText[i:] begins one, along with ok=true. A tag is
// a leading '$', an optional identifier (letters, digits, underscores; not
// starting with a digit), and a closing '$'.
func dollarQuoteTag(sqlText string, i int) (string, bool) {
	if i >= len(sqlText) || sqlText[i] != '$' {
		return "", false
	}
	j := i + 1
	for j < len(sqlText) {
		c := sqlText[j]
		if c == '$' {
			tag := sqlText[i : j+1]
			// The body between the first and last '$' must be a valid tag.
			inner := tag[1 : len(tag)-1]
			if inner == "" || isDollarTagIdent(inner) {
				return tag, true
			}
			return "", false
		}
		if !(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9')) {
			return "", false
		}
		if j == i+1 && c >= '0' && c <= '9' {
			return "", false // tag may not start with a digit
		}
		j++
	}
	return "", false
}

func isDollarTagIdent(s string) bool {
	for k := 0; k < len(s); k++ {
		c := s[k]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			continue
		}
		if c >= '0' && c <= '9' {
			if k == 0 {
				return false
			}
			continue
		}
		return false
	}
	return true
}

func unsupportedPostgresRuntimeError(scheme string) error {
	prefix := "postgres DATABASE_URL detected"
	if scheme != "" {
		prefix = fmt.Sprintf("postgres DATABASE_URL detected (scheme %q)", scheme)
	}
	return fmt.Errorf("%s, but app-runtime pgx support is not enabled yet; SQLite remains the production backend while the dialect, migration, encryption, FTS, backup, and insert-returning layers are ported", prefix)
}

// detectedPostgresScheme returns the URL scheme of a Postgres DATABASE_URL for
// diagnostics, or "keyword" for the libpq keyword/value form. It is only called
// once the URL has already been classified as Postgres.
func detectedPostgresScheme(raw string) string {
	if u, err := url.Parse(strings.TrimSpace(raw)); err == nil && u.Scheme != "" {
		return strings.ToLower(u.Scheme)
	}
	return "keyword"
}
