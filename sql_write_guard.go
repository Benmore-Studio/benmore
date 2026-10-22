//go:build !cli

package main

import (
	"fmt"
	"strings"
)

// validateSQLWriteStatement is the statement gate for MCP `sql write:true`
// (and anything else that runs one caller-written DML statement on a tenant
// database from the router). It is an ALLOWLIST over the shared SQLite lexer
// (sqlTokenize), not a prefix match: comments, quoting and whitespace cannot
// hide the verb, because the verb is the first code token after the lexer has
// dropped comments.
//
// Accepted: exactly ONE statement whose verb is INSERT, REPLACE, UPDATE or
// DELETE, optionally preceded by a WITH clause. Everything else is refused:
// schema DDL (CREATE TABLE/INDEX/TRIGGER/VIEW, DROP, ALTER), PRAGMA (e.g.
// writable_schema), VACUUM (incl. VACUUM INTO, which writes a file),
// ATTACH/DETACH, transaction control and a second ';'-chained statement (the
// driver's Exec runs every statement in the string).
func validateSQLWriteStatement(stmt string) error {
	var statements [][]sqlToken
	var cur []sqlToken
	for _, t := range sqlTokenize(stmt) {
		if t.kind == sqlTokPunct && t.text == ";" {
			if len(cur) > 0 {
				statements = append(statements, cur)
				cur = nil
			}
			continue
		}
		cur = append(cur, t)
	}
	if len(cur) > 0 {
		statements = append(statements, cur)
	}
	if len(statements) == 0 {
		return fmt.Errorf("statement is empty")
	}
	if len(statements) > 1 {
		return fmt.Errorf("sql(write:true) runs exactly one statement; found %d. Send each statement in its own call", len(statements))
	}
	toks := statements[0]
	verb := sqlMainVerb(toks)
	switch verb {
	case "INSERT", "REPLACE", "UPDATE", "DELETE":
		return nil
	case "":
		return fmt.Errorf("sql(write:true) accepts only INSERT, UPDATE, DELETE, REPLACE or WITH ... (INSERT|UPDATE|DELETE)")
	}
	switch verb {
	case "CREATE", "DROP", "ALTER", "TRUNCATE", "REINDEX":
		return fmt.Errorf("schema DDL (`%s`) must go through schema.prisma + migrations, not sql(write:true). The migration runner re-reads loaders; raw DDL desyncs them. For one-off data fixes, use INSERT/UPDATE/DELETE; for shape changes, edit schema.prisma", verb)
	}
	return fmt.Errorf("statement type %q is not permitted with sql(write:true) - only INSERT, UPDATE, DELETE, REPLACE and WITH ... (INSERT|UPDATE|DELETE) are allowed", verb)
}

// sqlMainVerb returns the upper-cased verb of a single tokenized statement:
// its first word, or for a WITH statement the first DML/SELECT keyword outside
// every parenthesis (CTE bodies are parenthesized). "" when the statement does
// not start with a bare keyword.
func sqlMainVerb(toks []sqlToken) string {
	if len(toks) == 0 || toks[0].kind != sqlTokWord {
		return ""
	}
	first := strings.ToUpper(toks[0].text)
	if first != "WITH" {
		return first
	}
	depth := 0
	for _, t := range toks[1:] {
		if t.kind == sqlTokPunct {
			switch t.text {
			case "(":
				depth++
			case ")":
				if depth > 0 {
					depth--
				}
			}
			continue
		}
		if depth != 0 || t.kind != sqlTokWord {
			continue
		}
		switch w := strings.ToUpper(t.text); w {
		case "SELECT", "VALUES", "INSERT", "REPLACE", "UPDATE", "DELETE":
			return w
		}
	}
	return "WITH"
}
