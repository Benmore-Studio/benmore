//go:build !cli

package main

import (
	"fmt"
	"regexp"
	"strings"
)

// Identifiers in framework SQL.
//
// A table or column name that framework code splices into SQL text comes
// from app configuration (groups.table, an encrypted.yaml column) or from the
// database catalog (a table a migration created). It reaches the text one of
// two ways, never bare and unchecked:
//
//   - written with quoteIdent / quoteColumn, so the statement stays the
//     statement whatever the name holds;
//   - proven a plain identifier (membershipIdentRe) where it enters the
//     system. Configuration is checked that way at load and at write time
//     (configIdentError), and the CRUD inventory lists only plain table names
//     (eligibleCRUDTables). Request-supplied column names are checked at the
//     site with isValidColumnName and the table's column allowlist.
//
// Configuration names get both. Go's %q is string quoting, not identifier
// quoting, and is never used for a name.

// quoteIdent writes name as a SQL identifier. Use it for a table name, and for
// a column name where SQL takes only a name: an INSERT column list, an UPDATE
// SET target, ALTER TABLE, a PRAGMA argument.
func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// quoteColumn writes a column reference for an expression (WHERE, ON, ORDER
// BY, a select list): the quoted column qualified by its quoted table or
// alias. The qualifier is what keeps a mistyped name an error. SQLite reads a
// lone "x" that names no column as the string 'x' (double-quoted string
// literals are enabled in our build), so `"emial" = ?` would compare a
// constant with the parameter where `emial = ?` failed with "no such column";
// `"members"."emial" = ?` still fails. A column the caller has just found in
// the table's catalog needs no qualifier.
func quoteColumn(table, column string) string {
	return quoteIdent(table) + "." + quoteIdent(column)
}

// quoteIdents quotes each name, for a column list.
func quoteIdents(names []string) []string {
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = quoteIdent(name)
	}
	return quoted
}

// Names in generated schema DDL.
//
// The DDL the framework generates from an app's schema (the Prisma CREATE
// TABLE / ALTER / index / trigger text, schema.yaml tables, computed-field,
// full-text and encrypted-field triggers) is not only executed. It is parsed
// back (ParseCreateTables), compared as text with what the database stores
// (the @updatedAt trigger reconcile, the full-text definition match, the
// connector's trigger check), written to schema.sql for a schema.yaml app,
// and written to migrations/ files that travel between an app's dev and prod
// instances. So a name that works bare keeps the exact text it has always
// had: quoting every name would give every existing app different DDL for
// the same schema (testdata/ddl_text_baseline holds an app from before the
// rule and the tests that load it).
//
// Only a name SQLite cannot read bare is quoted: an SQL reserved word. A
// schema field named `order`, `group`, `from`, `to` or `index` used to fail
// the load with `near "order": syntax error`, so no app that loads today has
// one and none sees a different statement. A name that is not a plain
// identifier is still written bare and still fails the statement, as before
// (buildAlterAdd).

// sqliteReservedWords are the SQLite keywords that cannot be a bare table or
// column name in a definition: CREATE TABLE refuses them, except `constraint`,
// which it reads as an unnamed table constraint and creates no column for.
// Every other keyword (key, desc, action, end, first, offset, ...) falls back
// to an identifier there. The set is the engine's behaviour, measured by
// TestReservedWordSetMatchesSQLite against the SQLite this binary is built
// with.
var sqliteReservedWords = map[string]bool{
	"add": true, "all": true, "alter": true, "and": true, "as": true, "autoincrement": true,
	"between": true, "case": true, "check": true, "collate": true, "commit": true,
	"constraint": true, "create": true, "default": true, "deferrable": true, "delete": true,
	"distinct": true, "drop": true, "else": true, "escape": true, "except": true,
	"exists": true, "foreign": true, "from": true, "group": true, "having": true,
	"in": true, "index": true, "insert": true, "intersect": true, "into": true,
	"is": true, "isnull": true, "join": true, "limit": true, "not": true,
	"nothing": true, "notnull": true, "null": true, "on": true, "or": true,
	"order": true, "primary": true, "references": true, "returning": true, "select": true,
	"set": true, "table": true, "then": true, "to": true, "transaction": true,
	"union": true, "unique": true, "update": true, "using": true, "values": true,
	"when": true, "where": true,
}

// sqliteExprKeywords are keywords that are a fine bare name in a definition
// but not where SQL reads an expression: `cast` and `raise` start one
// (`cast(x AS t)`), and `current_date`, `current_time` and `current_timestamp`
// are the clock there, not the column.
var sqliteExprKeywords = map[string]bool{
	"cast": true, "raise": true,
	"current_date": true, "current_time": true, "current_timestamp": true,
}

// sqliteReservedWord reports a name SQLite cannot take bare as a table or
// column name. Keywords compare without case.
func sqliteReservedWord(name string) bool {
	return sqliteReservedWords[sqliteIdentifierFold(name)]
}

// ddlIdent writes a table or column name into generated schema DDL where SQL
// takes only a name: a column definition, ALTER TABLE, a FOREIGN KEY or
// REFERENCES list, an UPDATE SET target, NEW.x / OLD.x. A reserved word is
// quoted; every other name is written as it always was.
func ddlIdent(name string) string {
	if sqliteReservedWord(name) {
		return quoteIdent(name)
	}
	return name
}

// ddlExprIdent is ddlIdent for a column where generated DDL takes an
// expression: an index or PRIMARY KEY column list, a trigger's WHERE.
func ddlExprIdent(name string) string {
	if sqliteReservedWord(name) || sqliteExprKeywords[sqliteIdentifierFold(name)] {
		return quoteIdent(name)
	}
	return name
}

// ddlIdents writes each name with ddlIdent, for a column list.
func ddlIdents(names []string) []string {
	out := make([]string, len(names))
	for i, name := range names {
		out[i] = ddlIdent(name)
	}
	return out
}

// ddlExprIdents writes each name with ddlExprIdent, for an index column list.
func ddlExprIdents(names []string) []string {
	out := make([]string, len(names))
	for i, name := range names {
		out[i] = ddlExprIdent(name)
	}
	return out
}

// configIdentError reports a configuration value that must be a table or
// column name and is not a plain identifier. what names the field for the
// message ("app.yaml: groups.table").
func configIdentError(what, value string) error {
	if membershipIdentRe.MatchString(value) {
		return nil
	}
	return fmt.Errorf("%s %q is not a plain identifier: use letters, digits and _ only, not starting with a digit", what, value)
}

// plainDeclTypeRe matches a declared column type made of words with an
// optional (n) or (n,m): TEXT, DOUBLE PRECISION, VARCHAR(255), DECIMAL(10,2).
var plainDeclTypeRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*( [A-Za-z_][A-Za-z0-9_]*)*( ?\( ?[+-]?[0-9]+ ?(, ?[+-]?[0-9]+ ?)?\))?$`)

// quoteDeclType writes a column's declared type, as the catalog reports it,
// into a column definition. An ordinary type is written as it is. A type
// name is free text to SQLite (`a "INTEGER); DROP TABLE t; --"` declares a
// column), so anything else is written as one quoted name: SQLite reads the
// same type text back and derives the same affinity from it.
func quoteDeclType(decl string) string {
	decl = strings.TrimSpace(decl)
	if decl == "" || plainDeclTypeRe.MatchString(decl) {
		return decl
	}
	return quoteIdent(decl)
}
