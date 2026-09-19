//go:build !cli

package main

// Restore validation and read-only queries use the same SQLite scanner in every edition.

import "testing"

func TestStripRestoreSQLCommentsMatchesStripSQLComments(t *testing.T) {
	corpus := []string{
		"",
		"SELECT 1",
		"INSERT INTO t VALUES ('a', 'b')",
		"INSERT INTO t VALUES ('a''b')", // doubled single-quote escape
		`INSERT INTO t VALUES ("a""b")`, // doubled double-quote escape
		"SELECT 1 -- a trailing comment",
		"SELECT 1 -- a comment; with a semicolon\nSELECT 2", // line comment absorbs to newline
		"SELECT /* a block comment */ 1",
		"SELECT /* unterminated block comment",              // runs to EOF (SQLite behavior)
		"INSERT INTO t VALUES ('--not a comment')",          // -- inside a single-quoted literal
		`INSERT INTO t VALUES ("--not a comment either")`,   // -- inside a double-quoted region
		"INSERT INTO t VALUES ('/*not a comment*/')",        // /* inside a single-quoted literal
		`INSERT INTO t VALUES ("/*not a comment either*/")`, // /* inside a double-quoted region
		"SELECT '/* nested */ still one literal'",           // nesting attempt inside a literal
		"/*/",  // "/*/" is not a valid self-closing block comment
		"/**/", // minimal valid self-closing block comment
		"SELECT 1; DROP TABLE t; -- trailing",
		"SELECT 'multi\nline\nliteral'",
		"SELECT 1 AS [ok] -- trailing comment",
		// Each adjacent block comment contributes its own separator.
		"SELECT/*a*//*b*/1",
	}
	for _, sql := range corpus {
		want := stripSQLComments(sql)
		got := stripRestoreSQLComments(sql)
		if got != want {
			t.Errorf("drift on %q:\n stripSQLComments        = %q\n stripRestoreSQLComments = %q", sql, want, got)
		}
	}
}

func TestStripRestoreSQLCommentsHandlesBracketAndBacktick(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"bracket protects --", "SELECT 1 AS [a--b]", "SELECT 1 AS [a--b]"},
		{"backtick protects --", "SELECT 1 AS `a--b`", "SELECT 1 AS `a--b`"},
		{"bracket protects /*", "SELECT 1 AS [a/*b]", "SELECT 1 AS [a/*b]"},
		{"backtick protects /*", "SELECT 1 AS `a/*b`", "SELECT 1 AS `a/*b`"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := stripRestoreSQLComments(c.input)
			if got != c.want {
				t.Errorf("stripRestoreSQLComments(%q) = %q, want %q", c.input, got, c.want)
			}
			if got := stripSQLComments(c.input); got != c.want {
				t.Errorf("stripSQLComments(%q) = %q, want %q", c.input, got, c.want)
			}
		})
	}
}
