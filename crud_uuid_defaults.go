//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"strings"
)

// Existing tables retain the old generated expression: SQLite cannot ALTER a
// column default without rebuilding its table. Repair native inserts only when
// the published Prisma contract is uuid() and the physical default is one of
// our two known expressions. SQL-only schemas, custom defaults and cuid() keep
// their semantics. Existing rows and explicit submitted values are untouched.
const legacyPrismaUUIDDefault = `(lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(6))))`

func prismaUUIDDefaultColumns(schema map[string]Column, cols []Column) []string {
	var names []string
	for _, col := range cols {
		declared, ok := schema[col.Name]
		if !ok || declared.Default != SQLiteUUID4Default || !strings.EqualFold(col.Type, "TEXT") {
			continue
		}
		// PRAGMA table_info removes the default's outer parentheses.
		for _, known := range []string{legacyPrismaUUIDDefault, SQLiteUUID4Default} {
			if col.Default == known || col.Default == known[1:len(known)-1] {
				names = append(names, col.Name)
				break
			}
		}
	}
	return names
}

// Resolve once before validation/hooks and bind the same value into INSERT.
// The caller's _submitted fields remain unchanged, including explicit NULL.
func materializeUUIDDefaults(tx *sql.Tx, columns []string, fields *[]string, values *[]any) error {
	for _, name := range columns {
		present := false
		for _, field := range *fields {
			if identIs(field, name) {
				present = true
				break
			}
		}
		if present {
			continue
		}
		var value string
		if err := tx.QueryRow("SELECT " + SQLiteUUID4Default).Scan(&value); err != nil {
			return fmt.Errorf("resolve UUID default: %w", err)
		}
		*fields = append(*fields, name)
		*values = append(*values, value)
	}
	return nil
}
