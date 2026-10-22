//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

// missingPrismaForeignKeys is read-only. Compare the declared contract with
// physical metadata even when an older runtime has already recorded its hash.
// Never replace a conflicting/custom FK: its actions and related data require
// an explicit migration. New tables are handled by EmitSQL instead.
func missingPrismaForeignKeys(q mutationQuerier, models []PrismaModel) (map[string][]PrismaField, error) {
	missing := map[string][]PrismaField{}
	for _, model := range models {
		var exists int
		if err := q.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?`, model.Table).Scan(&exists); err != nil {
			return nil, fmt.Errorf("inspect relation table %s: %w", model.Table, err)
		}
		if exists == 0 {
			continue
		}
		for _, field := range model.Fields {
			if field.FKTable == "" {
				continue
			}
			rows, err := q.Query(`SELECT f."table", f."to", (SELECT count(*) FROM pragma_foreign_key_list(?) x WHERE x.id=f.id)
				FROM pragma_foreign_key_list(?) f WHERE f."from"=? COLLATE NOCASE`, model.Table, model.Table, field.Column)
			if err != nil {
				return nil, fmt.Errorf("inspect relation %s.%s: %w", model.Table, field.Column, err)
			}
			found, conflicting := false, false
			for rows.Next() {
				var target, column string
				var arity int
				if err := rows.Scan(&target, &column, &arity); err != nil {
					rows.Close()
					return nil, err
				}
				if arity == 1 && strings.EqualFold(target, field.FKTable) && strings.EqualFold(column, field.FKColumn) {
					found = true
				} else {
					conflicting = true
				}
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return nil, err
			}
			if conflicting {
				return nil, fmt.Errorf("relation %s.%s conflicts with its physical foreign key; use an explicit migration", model.Table, field.Column)
			}
			if !found {
				missing[model.Table] = append(missing[model.Table], field)
			}
		}
	}
	return missing, nil
}

func rebuildPrismaRelations(tx *sql.Tx, table string, fields []PrismaField) ([]string, error) {
	if _, err := checkPrismaRelationRepairs(tx, map[string][]PrismaField{table: fields}); err != nil {
		return nil, err
	}
	return rebuildTableInTx(tx, table, func(original, temporary string, cols []Column) (string, error) {
		// Use the same catalog-preserving rewrite as type/nullability changes;
		// only the table name changes, then new table-level FKs are appended.
		unchanged := map[string]Column{}
		for _, col := range cols {
			unchanged[sqliteIdentifierFold(col.Name)] = col
		}
		ddl, err := rebuildCreateSQL(original, temporary, unchanged, unchanged)
		if err != nil {
			return "", err
		}
		depth := 0
		for _, token := range sqlTokenize(ddl) {
			if token.kind != sqlTokPunct {
				continue
			}
			switch token.text {
			case "(":
				depth++
			case ")":
				depth--
				if depth == 0 {
					var additions strings.Builder
					for _, field := range fields {
						fmt.Fprintf(&additions, ", FOREIGN KEY (%s) REFERENCES %s(%s)", quoteIdent(field.Column), quoteIdent(field.FKTable), quoteIdent(field.FKColumn))
					}
					return ddl[:token.start] + additions.String() + ddl[token.start:], nil
				}
			}
		}
		return "", fmt.Errorf("unsupported table declaration")
	})
}

// checkPrismaRelationRepairs shares the runtime's refusal rules with the
// read-only upgrade preflight. Only missing FKs on existing columns require a
// rebuild: a new nullable column is added inline, even on a referenced table.
// Inspect existence, never return row values (including soft-deleted rows).
func checkPrismaRelationRepairs(q mutationQuerier, missing map[string][]PrismaField) ([]string, error) {
	var unknownKeys []string
	var tables []string
	for table := range missing {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	for _, table := range tables {
		var retained []PrismaField
		for _, field := range missing[table] {
			var exists bool
			if err := q.QueryRow(`SELECT EXISTS(SELECT 1 FROM pragma_table_xinfo(?) WHERE name=? COLLATE NOCASE)`, table, field.Column).Scan(&exists); err != nil {
				return nil, fmt.Errorf("inspect relation %s.%s: %w", table, field.Column, err)
			}
			if exists {
				retained = append(retained, field)
			}
		}
		if len(retained) == 0 {
			continue
		}
		if err := checkTableRebuildReferences(q, table); err != nil {
			return nil, err
		}
		for _, field := range retained {
			var parentExists bool
			if err := q.QueryRow(`SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=? COLLATE NOCASE)`, field.FKTable).Scan(&parentExists); err != nil {
				return nil, fmt.Errorf("inspect relation parent %s: %w", field.FKTable, err)
			}
			if parentExists {
				status, err := prismaRelationParentKeyStatus(q, field.FKTable, field.FKColumn)
				if err != nil {
					return nil, fmt.Errorf("inspect relation %s.%s parent key: %w", table, field.Column, err)
				}
				if status == "invalid" {
					return nil, fmt.Errorf("relation %s.%s: target %s.%s lacks a compatible single-column primary or unique key; use an explicit migration", table, field.Column, field.FKTable, field.FKColumn)
				}
				if status == "unknown" {
					unknownKeys = append(unknownKeys, fmt.Sprintf("relation %s.%s: parent key collation is unverified; reconcile before upgrading", table, field.Column))
				}
			}
			// A declared parent table may be created by the pending schema.
			// It cannot satisfy any already non-null child reference yet.
			query := "SELECT EXISTS(SELECT 1 FROM " + quoteIdent(table) + " AS child WHERE child." + quoteIdent(field.Column) + " IS NOT NULL"
			if parentExists {
				// Remove the child's declared affinity with unary +. Only the
				// parent affinity/collation controls SQLite FK comparisons; a
				// child INTEGER column must not make parent TEXT '001' equal 1.
				query += " AND NOT EXISTS(SELECT 1 FROM " + quoteIdent(field.FKTable) + " AS parent WHERE parent." + quoteIdent(field.FKColumn) + " = +child." + quoteIdent(field.Column) + ")"
			}
			query += ")"
			var invalid bool
			if err := q.QueryRow(query).Scan(&invalid); err != nil {
				return nil, fmt.Errorf("inspect relation %s.%s references: %w", table, field.Column, err)
			}
			if invalid {
				return nil, fmt.Errorf("relation %s.%s: existing rows violate foreign key constraints; repair references in an explicit migration first", table, field.Column)
			}
		}
		// A rebuild also rechecks the table's retained physical constraints.
		if err := validateTableForeignKeys(q, table); err != nil {
			return nil, err
		}
	}
	return unknownKeys, nil
}

const prismaRelationExplicitRollback = "-- relation-rebuild: explicit rollback required"

func validateTableForeignKeys(q mutationQuerier, table string) error {
	rows, err := q.Query("PRAGMA foreign_key_check(" + quoteIdent(table) + ")")
	if err != nil {
		return fmt.Errorf("check %s references: %w", table, err)
	}
	invalid := rows.Next()
	err = rows.Err()
	rows.Close()
	if err != nil {
		return fmt.Errorf("check %s references: %w", table, err)
	}
	if invalid {
		return fmt.Errorf("table %s: existing rows violate foreign key constraints; repair references in an explicit migration first", table)
	}
	return nil
}

func appendPrismaRelationJournal(journal string, statements []string) string {
	up, down := extractMigrationSection(journal)
	if !strings.Contains(down, prismaRelationExplicitRollback) {
		down = prismaRelationExplicitRollback + "\n" + down
	}
	return up + "\n" + strings.Join(statements, "\n") + "\n" + migrationUpDownMarker + "\n" + down + "\n"
}
