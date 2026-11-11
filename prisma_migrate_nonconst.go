//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

// SQLite refuses ALTER TABLE ADD COLUMN with a non-constant default
// (CURRENT_TIMESTAMP, a parenthesized expression) once the table holds rows.
// Adding `createdAt DateTime @default(now())`, `updatedAt DateTime @updatedAt`
// or a required DateTime (backfilled with CURRENT_TIMESTAMP) to a table with
// data therefore failed the whole migration: a dev push took the app down at
// its next restart, and a promote left prod crash-looping (round-2 testing,
// 2026-10-23). These columns are added here instead: by ALTER on an empty
// table, otherwise by a preserving table rebuild whose CREATE carries the real
// definition, so existing rows get the migration time and later inserts the
// database default.

// prismaNonConstantColumns lists the added columns emitUpSQL leaves out.
func prismaNonConstantColumns(diff MigrationDiff) map[string][]PrismaField {
	out := map[string][]PrismaField{}
	for table, fields := range diff.ColumnsAdded {
		for _, f := range fields {
			if sqliteNonConstantDefault(prismaAddColumnDefault(f)) {
				out[table] = append(out[table], f)
			}
		}
	}
	return out
}

// addNonConstantDefaultColumns adds those columns inside the migration's
// transaction and returns the statements it ran, for the migration journal.
func addNonConstantDefaultColumns(tx *sql.Tx, columns map[string][]PrismaField) ([]string, error) {
	var tables []string
	for table := range columns {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	var journal []string
	exec := func(statement string) error {
		journal = append(journal, statement+";")
		_, err := tx.Exec(statement)
		return err
	}
	for _, table := range tables {
		fields := columns[table]
		var hasRows bool
		if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM " + quoteIdent(table) + ")").Scan(&hasRows); err != nil {
			return journal, fmt.Errorf("inspect %s: %w", table, err)
		}
		if !hasRows {
			for _, f := range fields {
				if err := exec("ALTER TABLE " + ddlIdent(table) + " ADD COLUMN " + prismaAddColumnDefinition(f)); err != nil {
					return journal, err
				}
			}
		} else {
			var defs []string
			for _, f := range fields {
				defs = append(defs, prismaAddColumnDefinition(f))
			}
			statements, err := rebuildTableInTx(tx, table, func(original, temporary string, cols []Column) (string, error) {
				unchanged := map[string]Column{}
				for _, col := range cols {
					unchanged[sqliteIdentifierFold(col.Name)] = col
				}
				ddl, err := rebuildCreateSQL(original, temporary, unchanged, unchanged)
				if err != nil {
					return "", err
				}
				return insertColumnDefinitions(ddl, defs)
			})
			journal = append(journal, statements...)
			if err != nil {
				var names []string
				for _, f := range fields {
					names = append(names, f.Column)
				}
				return journal, fmt.Errorf("add %s.%s: its default (%s) is not a constant, which SQLite can add to a table with rows only by rebuilding the table, and the rebuild was refused: %w. Make the field optional, give it a constant default, or add it in an explicit migration",
					table, strings.Join(names, ", "), prismaAddColumnDefault(fields[0]), err)
			}
		}
		for _, f := range fields {
			for _, statement := range splitStatements(prismaAddedColumnFollowUpSQL(table, f)) {
				if statement = strings.TrimSpace(statement); statement == "" {
					continue
				}
				if err := exec(statement); err != nil {
					return journal, err
				}
			}
		}
	}
	return journal, nil
}

// insertColumnDefinitions adds column definitions to a CREATE TABLE after its
// last column and before its table constraints, which SQLite requires.
func insertColumnDefinitions(ddl string, defs []string) (string, error) {
	start, end, depth := -1, -1, 0
	for _, token := range sqlTokenize(ddl) {
		if token.kind != sqlTokPunct {
			continue
		}
		if token.text == "(" {
			if start < 0 {
				start = token.start
			}
			depth++
		} else if token.text == ")" {
			depth--
			if depth == 0 && start >= 0 {
				end = token.start
				break
			}
		}
	}
	if start < 0 || end < 0 {
		return "", fmt.Errorf("unsupported table declaration")
	}
	parts := splitSchemaParts(ddl[start+1 : end])
	last := -1
	for i, part := range parts {
		if parseColumnDef(part) != nil {
			last = i
		}
	}
	if last < 0 {
		return "", fmt.Errorf("unsupported table declaration")
	}
	next := append([]string{}, parts[:last+1]...)
	next = append(next, defs...)
	next = append(next, parts[last+1:]...)
	return ddl[:start+1] + strings.Join(next, ", ") + ddl[end:], nil
}

// appendPrismaUpJournal records statements the applier ran itself in the UP
// section of the migration file, so the app's other instance replays them.
func appendPrismaUpJournal(journal string, statements []string) string {
	up, down := extractMigrationSection(journal)
	return up + "\n" + strings.Join(statements, "\n") + "\n" + migrationUpDownMarker + "\n" + down + "\n"
}
