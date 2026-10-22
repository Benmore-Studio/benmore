//go:build !cli

package main

import "testing"

// `sql write:true` used a bare prefix match against a short DDL list, so a
// leading comment, any DDL verb not on the list, PRAGMA, VACUUM INTO and a
// ';'-chained second statement all ran. The gate is now an allowlist over
// the shared lexer.
func TestValidateSQLWriteStatementRefusesBypasses(t *testing.T) {
	refused := []string{
		"/*x*/ DROP TABLE t",
		"-- note\nDROP TABLE t",
		"  drop table t",
		"CREATE TRIGGER tr AFTER INSERT ON t BEGIN DELETE FROM u; END",
		"CREATE VIEW v AS SELECT 1",
		"CREATE TEMP TABLE x(a)",
		"ALTER TABLE t ADD COLUMN c",
		"PRAGMA writable_schema=1",
		"/**/PRAGMA writable_schema = ON",
		"VACUUM INTO '/tmp/copy.db'",
		"VACUUM",
		"REINDEX",
		"ATTACH DATABASE '/x' AS y",
		"BEGIN",
		"COMMIT",
		"UPDATE t SET a = 1; DROP TABLE t",
		"DELETE FROM t; PRAGMA writable_schema=1",
		"SELECT 1",
		"WITH x AS (SELECT 1) SELECT * FROM x",
		"",
		"   ;  ",
		"'DELETE' FROM t",
	}
	for _, s := range refused {
		if err := validateSQLWriteStatement(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
	accepted := []string{
		"INSERT INTO t (a) VALUES ('DROP TABLE t; --')",
		"insert or replace into t(a) values (1)",
		"REPLACE INTO t(a) VALUES (1)",
		"UPDATE t SET a = 'x;y' WHERE id = 1;",
		"/* fix */ DELETE FROM t WHERE id IN (SELECT id FROM t LIMIT 1)",
		"WITH old AS (SELECT id FROM t WHERE a < 0) DELETE FROM t WHERE id IN (SELECT id FROM old)",
		"WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 3) INSERT INTO t(a) SELECT i FROM n",
		"UPDATE \"create\" SET a = 1",
	}
	for _, s := range accepted {
		if err := validateSQLWriteStatement(s); err != nil {
			t.Errorf("refused %q: %v", s, err)
		}
	}
}
