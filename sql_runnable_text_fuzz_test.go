//go:build !cli

package main

import (
	"database/sql"
	"math/rand"
	"path/filepath"
	"strings"
	"testing"
)

// sqlRunnableTextFragments: statements, tokens and comment/quote edge cases the
// generator splices together. Each must survive being passed to the driver.
var sqlRunnableTextFragments = []string{
	"SELECT 1", "SELECT 2 AS n", "SELECT 'a;b'", "SELECT '; -- x'", `SELECT "x;--"`, "SELECT [a;b]", "SELECT `q;`",
	"SELECT name FROM t", "SELECT $a('); SELECT 1", "SELECT :a(x)", "SELECT 1.$x(--)", "SELECT 1e-5", "SELECT x'ab'", "SELECT 0x1F",
	"WITH a AS (SELECT 1) SELECT id FROM a", "VALUES (1)", "EXPLAIN SELECT 1", "PRAGMA user_version",
	"UPDATE t SET name = name", "DELETE FROM t WHERE id < 0", "INSERT INTO t(name) VALUES ('z') RETURNING id",
	";", ";;", " ", "\n", "\t", "\v", "\r\n",
	"-- c", "-- c\n", "--", "/* c */", "/* ; */", "/* c", "/*", "/*/", "/**/", "/*/ */",
	"\xEF\xBB\xBF", "\xC2\xA0", "\xE2\x80\xA8", "\xC2\x85", "abc\xC2\xA0", "\xEF\xBB\xBFabc",
	"$a(", "@a('", "?", "#a", "'unterminated", `"unterminated`, "[unterminated", "`unterminated",
	"x", "FROM t", ",", "(", ")", "->", "->>", "==", "<>", "||",
}

func genRunnableText(r *rand.Rand) string {
	var b strings.Builder
	for i, n := 0, 1+r.Intn(6); i < n; i++ {
		b.WriteString(sqlRunnableTextFragments[r.Intn(len(sqlRunnableTextFragments))])
		switch r.Intn(5) {
		case 0:
			b.WriteByte(' ')
		case 1:
			b.WriteByte(';')
		case 2:
			b.WriteString("; ")
		case 3:
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// TestSQLRunnableTextDifferential drives the real SQLite driver with the text
// sqlRunnableText returns for thousands of generated inputs, and checks the
// text is always a prefix of the input (statements, order and parameters
// preserved).
//
// What the driver does with a text the helper got wrong depends on the path.
// A prepared statement run on a text with no statement kills the test binary
// (SIGSEGV in cgo), so every accepted text is prepared and run. Query no longer
// dies on an empty last statement (it did up to go-sqlite3 v1.14.42): it
// answers with an empty result. That is checked by result: a text that gives a
// marker row when the marker statement is its last one must give the same row
// when an empty statement is appended and the whole goes through the helper.
func TestSQLRunnableTextDifferential(t *testing.T) {
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(t.TempDir(), "data.db"), t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mustExec(t, db, "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)")
	mustExec(t, db, "INSERT INTO t (name) VALUES ('a'),('b')")

	seen := map[string]bool{}
	add := func(q string) { seen[q] = true }
	// Exhaustively cover single fragments and fragments wrapped in the trailing
	// shapes that trip the driver.
	for _, f := range sqlRunnableTextFragments {
		add(f)
		add(f + ";")
		add("SELECT 1; " + f)
		add("SELECT 1;" + f)
		add(f + "; SELECT 1")
		add(f + ";;")
		add(f + "; -- c")
		add(f + "; /* c */")
	}
	r := rand.New(rand.NewSource(1))
	for len(seen) < 8000 {
		add(genRunnableText(r))
	}

	for q := range seen {
		text, ok := sqlRunnableText(q)
		if !ok {
			continue
		}
		if !strings.HasPrefix(q, text) {
			t.Fatalf("returned text %q is not a prefix of %q", text, q)
		}
		// A syntax error in the data is fine, a dead process is not. The
		// prepared statement is run, not only compiled: running is where the
		// driver dies on a text without a statement.
		if rows, err := db.Query(text); err == nil {
			rows.Close()
		}
		if st, err := db.Prepare(text); err == nil {
			if rows, err := st.Query(); err == nil {
				rows.Close()
			}
			st.Close()
		}
	}

	const marker = "SELECT 424242 AS marker"
	answersMarker := func(text string) bool {
		rows, err := db.Query(text)
		if err != nil {
			return false
		}
		defer rows.Close()
		cols, _ := rows.Columns()
		if len(cols) != 1 || cols[0] != "marker" || !rows.Next() {
			return false
		}
		var v int64
		return rows.Scan(&v) == nil && v == 424242 && !rows.Next()
	}
	emptyTails := []string{"; -- note", "; /* note */", ";;", ";\n-- a\n;\n/* b */ ; "}
	checked := 0
	for q := range seen {
		base := q + ";\n" + marker
		if !answersMarker(base) {
			continue // q fails, or leaves a quote or comment open over the marker
		}
		for _, tail := range emptyTails {
			text, ok := sqlRunnableText(base + tail)
			if !ok {
				t.Fatalf("%q: no statement found", base+tail)
			}
			if !answersMarker(text) {
				t.Fatalf("%q (from %q) does not answer with its last statement's row", text, base+tail)
			}
		}
		checked++
	}
	if checked < 200 {
		t.Fatalf("only %d generated texts reached the result check", checked)
	}
}
