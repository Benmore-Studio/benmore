//go:build !cli

package main

// The lexer's reading of a flow SQL statement, which decides what
// expect_rows compares.

import (
	"testing"
)

func TestClassifyFlowSQL(t *testing.T) {
	for _, tc := range []struct {
		sql        string
		kind       flowSQLKind
		statements int
	}{
		{"SELECT 1", flowSQLRead, 1},
		{"  select id from t;  ", flowSQLRead, 1},
		{"-- lead\n/* in */ SELECT id FROM t -- trail", flowSQLRead, 1},
		{"VALUES (1), (2)", flowSQLRead, 1},
		{"WITH a AS (SELECT 1) SELECT * FROM a", flowSQLRead, 1},
		{"WITH a AS (SELECT 'INSERT INTO t' AS s) SELECT s FROM a", flowSQLRead, 1},
		{"WITH replace AS (SELECT 1 AS a) SELECT a FROM replace", flowSQLUnclassified, 1},
		{"SELECT REPLACE(name, 'a', 'b') FROM t WHERE note = 'delete me'", flowSQLRead, 1},
		{"INSERT INTO t (a) VALUES (1)", flowSQLWrite, 1},
		{"insert or ignore into t values (1)", flowSQLWrite, 1},
		{"REPLACE INTO t VALUES (1)", flowSQLWrite, 1},
		{"UPDATE t SET a = 1 WHERE id = ?", flowSQLWrite, 1},
		{"DELETE FROM t WHERE id = ?", flowSQLWrite, 1},
		{"INSERT INTO temp.scratch VALUES (1)", flowSQLWrite, 1},
		{"WITH a AS (SELECT 1 AS x) INSERT INTO t SELECT x FROM a", flowSQLWrite, 1},
		{"WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 3) DELETE FROM t WHERE id IN (SELECT i FROM n)", flowSQLWrite, 1},
		{"WITH a(x, y) AS MATERIALIZED (SELECT 1, (2)) UPDATE t SET a = 1 WHERE id IN (SELECT x FROM a)", flowSQLWrite, 1},
		{"UPDATE t SET a = 1 RETURNING id", flowSQLReturning, 1},
		{"INSERT INTO t (a) VALUES (1) ON CONFLICT (a) DO UPDATE SET a = 2 returning *", flowSQLReturning, 1},
		{"WITH a AS (SELECT 1 AS x) DELETE FROM t WHERE id IN (SELECT x FROM a) RETURNING id", flowSQLReturning, 1},
		// The word is not the clause inside a string, a quoted name, a
		// comment, a longer identifier or a bind parameter.
		{"UPDATE t SET note = 'returning customer' WHERE id = 1", flowSQLWrite, 1},
		{`UPDATE t SET "returning" = 1 WHERE id = 1`, flowSQLWrite, 1},
		{"UPDATE t SET a = 1 -- RETURNING id\nWHERE id = 1", flowSQLWrite, 1},
		{"UPDATE t SET is_returning = 1, returning_at = 2 WHERE id = 1", flowSQLWrite, 1},
		{"UPDATE t SET a = :returning, b = @returning WHERE id = 1", flowSQLWrite, 1},
		{"UPDATE t SET is_returning = 1 WHERE id = 1 RETURNING id", flowSQLReturning, 1},
		// Several statements have a count only as writes without RETURNING.
		{"UPDATE t SET a = 1; DELETE FROM u;", flowSQLWrite, 2},
		{"INSERT INTO t VALUES ('a;b'); UPDATE t SET a = 1 -- ; SELECT 1", flowSQLWrite, 2},
		{"UPDATE t SET a = 1; SELECT 1", flowSQLUnclassified, 2},
		{"SELECT 1; UPDATE t SET a = 1", flowSQLUnclassified, 2},
		{"UPDATE t SET a = 1; UPDATE t SET a = 2 RETURNING id", flowSQLUnclassified, 2},
		{"SELECT 1; SELECT 2", flowSQLUnclassified, 2},
		// No row count at all.
		{"CREATE TABLE t (id INTEGER)", flowSQLUnclassified, 1},
		{"PRAGMA table_info(t)", flowSQLUnclassified, 1},
		{"EXPLAIN SELECT 1", flowSQLUnclassified, 1},
		{"BEGIN", flowSQLUnclassified, 1},
		{"(SELECT 1)", flowSQLUnclassified, 1},
		{"WITH a AS (SELECT 1)", flowSQLUnclassified, 1},
		{"", flowSQLUnclassified, 0},
		{" ;; -- nothing\n", flowSQLUnclassified, 0},
	} {
		got := classifyFlowSQL(tc.sql)
		if got.kind != tc.kind || got.statements != tc.statements {
			t.Errorf("classifyFlowSQL(%q) = kind %d, %d statement(s); want kind %d, %d", tc.sql, got.kind, got.statements, tc.kind, tc.statements)
		}
		if (got.uncheckable() == "") != (tc.kind != flowSQLUnclassified) {
			t.Errorf("classifyFlowSQL(%q).uncheckable() = %q for kind %d", tc.sql, got.uncheckable(), tc.kind)
		}
	}
}

// text is the script without leading or trailing comments, whitespace and
// empty statements, and nothing else is cut: the driver would prepare what
// follows the final `;` as one more, empty, statement.
func TestFlowSQLShapeText(t *testing.T) {
	for in, want := range map[string]string{
		"UPDATE t SET a = 1;\n-- one row\n":       "UPDATE t SET a = 1",
		"SELECT 'a -- b' /* why */  ":             "SELECT 'a -- b'",
		"SELECT 1":                                "SELECT 1",
		"SELECT 1;;":                              "SELECT 1",
		" ; -- lead\n SELECT 1 ; ; /* tail */ ":   "SELECT 1",
		"  UPDATE t SET a = ? WHERE b = 'x;'  \n": "UPDATE t SET a = ? WHERE b = 'x;'",
		"UPDATE t SET a = 1; -- then\nDELETE FROM u WHERE a = ?;\n-- done": "UPDATE t SET a = 1; -- then\nDELETE FROM u WHERE a = ?",
		"-- only a comment": "-- only a comment",
	} {
		if got := classifyFlowSQL(in).text(in); got != want {
			t.Errorf("text(%q) = %q, want %q", in, got, want)
		}
	}
}
