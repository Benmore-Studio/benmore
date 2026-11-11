//go:build !cli

package main

import (
	"fmt"
	"regexp"
	"strings"
)

// attachDetachRe matches ATTACH/DETACH [DATABASE] as a whole word, case-
// insensitive - used to reject cross-tenant database attachment on the
// raw sql write path. \b boundaries so columns/identifiers like
// "attachment" or "detached_at" aren't falsely flagged.
var attachDetachRe = regexp.MustCompile(`(?i)\b(ATTACH|DETACH)\b`)

// validateTenantWriteSQL is the whole gate for one caller-written write
// statement (MCP sql write:true): ATTACH/DETACH and load_extension refused
// outright, then the single-DML allowlist. The router applies it before it
// forwards the statement and the app process applies it again before it runs
// it (app_data_ops_sql.go), with the same messages.
func validateTenantWriteSQL(stmt string) error {
	// ATTACH would reach another database file from this connection; the
	// engine-level SQLITE_LIMIT_ATTACHED=0 backstops it. Word-boundary match
	// so a column named e.g. "attachment" isn't caught.
	if attachDetachRe.MatchString(stmt) {
		return fmt.Errorf("ATTACH/DETACH DATABASE is not permitted - it would cross tenant boundaries. Each app's SQL is scoped to its own database.")
	}
	// load_extension() would be RCE if the driver ever allowed extensions.
	// Substring check is deliberately conservative.
	if strings.Contains(strings.ToLower(stmt), "load_extension") {
		return fmt.Errorf("load_extension is not permitted")
	}
	// An allowlist of ONE DML statement over the shared lexer. The old prefix
	// match let `/*x*/ DROP TABLE t`, CREATE TRIGGER/VIEW, PRAGMA
	// writable_schema, VACUUM INTO and a ';'-chained second statement through.
	return validateSQLWriteStatement(stmt)
}

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

// broadcastSQLWrite fires an SSE event after a raw `sql --write`
// statement so connected browsers re-fetch. Best-effort table
// extraction:
//
//   - `INSERT INTO <name>` / `UPDATE <name>` / `DELETE FROM <name>`
//     emit {table:"<name>", action:"refresh"} - same shape the
//     auto-CRUD path would have emitted.
//   - Anything else (multi-table CTE, REPLACE, json_each-driven bulk
//     inserts) emit the generic {table:"", action:"refresh"} hint.
//     Clients listening with bm.live() refresh their view either way.
//
// Pre-2.7.35 this was a documented hole - the beacon "phantom stream"
// debugging session traced two hours back to "I deleted the row via
// SQL but the API still serves it because no SSE fan-out fired."
func broadcastSQLWrite(app *App, stmt string) {
	if app == nil {
		return
	}
	table := extractTableFromStmt(stmt)
	if table != "" {
		BroadcastUnscoped(app, table, "refresh")
	} else {
		BroadcastUnscoped(app, "", "refresh")
	}
}

// extractTableFromStmt names the table a single INSERT / REPLACE / UPDATE /
// DELETE statement writes, so the SSE event can target the right listeners
// and the audit row can name it. It reads the statement with the shared SQLite
// lexer (sqlWriteTargets), so a WITH prefix, INSERT OR REPLACE, a quoted name
// or main.<table> resolve too; the prefix match it replaced returned "" for
// those, which left the audit row's table empty. Anything else - several
// statements, no write, temp.* or an attached schema - returns "" and callers
// fall back to a generic refresh hint.
func extractTableFromStmt(stmt string) string {
	writes, statements := sqlWriteTargets(stmt)
	if statements != 1 || len(writes) != 1 {
		return ""
	}
	return writes[0].Table
}
