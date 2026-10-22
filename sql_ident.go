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
