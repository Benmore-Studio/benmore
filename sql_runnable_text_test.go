//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// sqlRunnableText must never change the meaning of a text every part of which
// holds a statement, and must drop exactly the trailing (or interleaved) empty
// statements the driver cannot run - a comment or a second `;` after the last
// statement - returning ok=false only when there is no statement at all.
func TestSQLRunnableText(t *testing.T) {
	cases := []struct {
		name   string
		query  string
		want   string
		wantOK bool
	}{
		// A working text is returned byte-for-byte. The column name SQLite
		// derives from the source text (trailing comment and all) must not
		// change, so a one-statement text is never rewritten.
		{"plain", "SELECT 1", "SELECT 1", true},
		{"one with semicolon", "SELECT 1;", "SELECT 1;", true},
		{"trailing inline comment on the SELECT", "SELECT 1 -- note", "SELECT 1 -- note", true},
		{"two statements", "SELECT 1; SELECT 2", "SELECT 1; SELECT 2", true},
		{"string holding a semicolon", "SELECT ';'", "SELECT ';'", true},
		{"string holding a comment marker", "SELECT '; -- x'", "SELECT '; -- x'", true},
		{"identifier holding a semicolon", `SELECT "a;b" FROM t`, `SELECT "a;b" FROM t`, true},
		{"bracket identifier holding a semicolon", "SELECT [a;b]", "SELECT [a;b]", true},
		{"backtick identifier holding a semicolon", "SELECT `a;b`", "SELECT `a;b`", true},
		{"parameter with parenthesized suffix holding ; and quote", "SELECT $a('); SELECT 2", "SELECT $a('); SELECT 2", true},
		{"leading comment then statement", "-- lead\nSELECT 1", "-- lead\nSELECT 1", true},
		{"block comment then statement", "/* lead */ SELECT 1", "/* lead */ SELECT 1", true},
		{"empty statement between two statements is left alone", "SELECT 1;; SELECT 2", "SELECT 1;; SELECT 2", true},
		{"CTE write without returning", "WITH x AS (SELECT 1) INSERT INTO t SELECT id FROM x", "WITH x AS (SELECT 1) INSERT INTO t SELECT id FROM x", true},

		// A trailing empty statement is dropped, back to the last statement's
		// own end.
		{"trailing line comment after ;", "SELECT 1; -- note", "SELECT 1;", true},
		{"trailing block comment after ;", "SELECT 1; /* note */", "SELECT 1;", true},
		{"trailing double semicolon", "SELECT 1;;", "SELECT 1;", true},
		{"trailing semicolon-space-comment", "SELECT 1;\n-- tail\n", "SELECT 1;", true},
		{"second statement then trailing comment", "SELECT 1; SELECT 2; -- x", "SELECT 1; SELECT 2;", true},
		{"returning write then trailing comment", "UPDATE t SET name = name RETURNING id; -- note", "UPDATE t SET name = name RETURNING id;", true},
		{"empty statement inside then trailing comment", "SELECT 1; -- c\n; SELECT 2; /* z */", "SELECT 1; -- c\n; SELECT 2;", true},
		{"trailing comment keeps the string-with-semicolon statement", "SELECT ';' ; -- x", "SELECT ';' ;", true},

		// No statement at all: ok=false, never touch the driver.
		{"empty", "", "", false},
		{"whitespace", "   \n\t", "", false},
		{"single semicolon", ";", "", false},
		{"several semicolons", ";;;", "", false},
		{"only a line comment", "-- only a comment", "", false},
		{"only a block comment", "/* only */", "", false},
		{"byte order mark only", "\xEF\xBB\xBF", "", false},
		{"bom then only a comment", "\xEF\xBB\xBF -- c", "", false},
		{"comment then semicolons", "-- c\n ;; ", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := sqlRunnableText(c.query)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v (got text %q)", ok, c.wantOK, got)
			}
			if !ok {
				return
			}
			if got != c.want {
				t.Fatalf("text = %q, want %q", got, c.want)
			}
			// What it returns must be a prefix of the input: statements, order
			// and parameters are preserved; only the tail is dropped.
			if !strings.HasPrefix(c.query, got) {
				t.Fatalf("text %q is not a prefix of %q", got, c.query)
			}
		})
	}
}

// TestSQLRunnableTextRunsOnDriver proves the returned text is one the real
// SQLite driver runs to its end: Query answers with the rows of the last
// statement, and a prepared statement runs the first. Had sqlRunnableText left
// an empty statement at the end, Query would answer with no columns and no
// rows (and up to go-sqlite3 v1.14.42 the process died there).
func TestSQLRunnableTextRunsOnDriver(t *testing.T) {
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(t.TempDir(), "data.db"), t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mustExec(t, db, "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)")
	mustExec(t, db, "INSERT INTO t (name) VALUES ('a'),('b')")
	// read returns the first value of the first row and the row count.
	read := func(rows *sql.Rows) (first int64, n int) {
		t.Helper()
		defer rows.Close()
		for rows.Next() {
			var v int64
			if err := rows.Scan(&v); err != nil {
				t.Fatal(err)
			}
			if n == 0 {
				first = v
			}
			n++
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return first, n
	}
	runnable := []struct {
		query                string
		last, lastRows       int64 // what Query answers: the last statement
		firstStmt, firstRows int64 // what a prepared statement answers: the first
	}{
		{"SELECT 1 AS n; -- note", 1, 1, 1, 1},
		{"SELECT 1 AS n; /* note */", 1, 1, 1, 1},
		{"SELECT 1 AS n;;", 1, 1, 1, 1},
		{"-- lead\nSELECT 1 AS n;\n-- tail\n", 1, 1, 1, 1},
		{"SELECT 1 AS n; SELECT 2 AS n; -- x", 2, 1, 1, 1},
		{"SELECT id FROM t; -- c\n; ", 1, 2, 1, 2},
	}
	for _, c := range runnable {
		q := c.query
		text, ok := sqlRunnableText(q)
		if !ok {
			t.Fatalf("%q: no statement found", q)
		}
		rows, err := db.Query(text)
		if err != nil {
			t.Fatalf("Query(%q from %q): %v", text, q, err)
		}
		if first, n := read(rows); first != c.last || int64(n) != c.lastRows {
			t.Fatalf("Query(%q from %q): first value %d in %d row(s), want %d in %d", text, q, first, n, c.last, c.lastRows)
		}
		stmt, err := db.Prepare(text)
		if err != nil {
			t.Fatalf("Prepare(%q from %q): %v", text, q, err)
		}
		rows, err = stmt.Query()
		if err != nil {
			t.Fatalf("prepared Query(%q from %q): %v", text, q, err)
		}
		if first, n := read(rows); first != c.firstStmt || int64(n) != c.firstRows {
			t.Fatalf("prepared Query(%q from %q): first value %d in %d row(s), want %d in %d", text, q, first, n, c.firstStmt, c.firstRows)
		}
		stmt.Close()
	}
	for _, q := range []string{"", "   ", "-- c", ";", "/* x */", "\xEF\xBB\xBF"} {
		if _, ok := sqlRunnableText(q); ok {
			t.Fatalf("%q: expected no statement", q)
		}
	}
}
