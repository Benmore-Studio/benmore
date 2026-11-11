//go:build !cli

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Keep emission, retained-trigger upgrades, and captured MCP trigger closure on
// one definition. Canonical CRUD supplies a precise timestamp itself. Storage
// maintenance must not replace it with SQLite's whole-second clock.
func prismaUpdatedAtTriggerSQL(table, column string) string {
	name := "trg_" + table + "_" + column + "_updated"
	// A reserved-word name is quoted, every other name is written bare as
	// before (ddlIdent), so the text stored for an existing trigger still
	// equals this one.
	table, column = ddlIdent(table), ddlIdent(column)
	return fmt.Sprintf("CREATE TRIGGER IF NOT EXISTS %s\n"+
		"AFTER UPDATE ON %s\n"+
		"FOR EACH ROW WHEN NEW.%s IS OLD.%s AND (NEW.%s IS NULL OR julianday(NEW.%s) < julianday(CURRENT_TIMESTAMP)) BEGIN\n"+
		"  UPDATE %s SET %s = CURRENT_TIMESTAMP WHERE rowid = NEW.rowid;\n"+
		"END;", name, table, column, column, column, column, table, column)
}

func legacyPrismaUpdatedAtTriggerSQL(table, column string) string {
	return fmt.Sprintf("CREATE TRIGGER IF NOT EXISTS trg_%s_%s_updated\n"+
		"AFTER UPDATE ON %s\nFOR EACH ROW BEGIN\n"+
		"  UPDATE %s SET %s = CURRENT_TIMESTAMP WHERE rowid = NEW.rowid;\nEND;",
		table, column, table, table, column)
}

// SQLite omits IF NOT EXISTS and the final semicolon in sqlite_schema. No
// comments, quoted identifiers, case changes, or extra SQL are normalized: only
// the exact two framework-generated definitions are eligible for replacement.
func normalizePrismaUpdatedAtSQL(stmt string) string {
	stmt = strings.Join(strings.Fields(strings.TrimSuffix(strings.TrimSpace(stmt), ";")), " ")
	return strings.Replace(stmt, "CREATE TRIGGER IF NOT EXISTS ", "CREATE TRIGGER ", 1)
}

// A reserved-word table or column is written quoted (ddlIdent); the candidate
// is still accepted only when it equals the regenerated definition.
var prismaUpdatedAtCandidate = regexp.MustCompile(`^CREATE TRIGGER [A-Za-z_][A-Za-z0-9_]* AFTER UPDATE ON "?([A-Za-z_][A-Za-z0-9_]*)"? FOR EACH ROW WHEN NEW\."?([A-Za-z_][A-Za-z0-9_]*)"? IS OLD\.`)

// The release preflight uses the same ownership check without loading an app,
// running migrations, or reading application rows. Its caller supplies the
// captured served Prisma source, never a second read of mutable source files.
func checkPrismaUpdatedAtTriggers(q mutationQuerier, schema []byte) error {
	if len(schema) == 0 {
		return nil
	}
	models, err := ParsePrismaSchema(string(schema))
	if err != nil {
		return fmt.Errorf("Prisma updatedAt preflight schema: %w", err)
	}
	for _, model := range models {
		for _, field := range model.Fields {
			if field.UpdatedAt {
				if _, err := existingPrismaUpdatedAtTrigger(q, model.Table, field.Column); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Return the exact stored definition, or an empty string for a missing trigger.
// Matching the name alone never grants authority to replace an authored object.
func existingPrismaUpdatedAtTrigger(q mutationQuerier, table, column string) (string, error) {
	name := "trg_" + table + "_" + column + "_updated"
	var kind, owner, existing string
	err := q.QueryRow(`SELECT type, tbl_name, COALESCE(sql,'') FROM main.sqlite_schema WHERE name=? COLLATE NOCASE`, name).Scan(&kind, &owner, &existing)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	normalized := normalizePrismaUpdatedAtSQL(existing)
	if kind != "trigger" || owner != table || (normalized != normalizePrismaUpdatedAtSQL(prismaUpdatedAtTriggerSQL(table, column)) && normalized != normalizePrismaUpdatedAtSQL(legacyPrismaUpdatedAtTriggerSQL(table, column))) {
		return "", fmt.Errorf("Prisma updatedAt trigger %q differs from its generated definition", name)
	}
	return existing, nil
}

type prismaUpdatedAtDeclaration struct{ table, column, name, sql string }

// prismaUpdatedAtDeclarations picks the deferred statements that are exactly
// the current compiler's updatedAt trigger.
func prismaUpdatedAtDeclarations(deferred []string) []prismaUpdatedAtDeclaration {
	var declarations []prismaUpdatedAtDeclaration
	for _, stmt := range deferred {
		normalized := normalizePrismaUpdatedAtSQL(stmt)
		match := prismaUpdatedAtCandidate.FindStringSubmatch(normalized)
		if len(match) != 3 {
			continue
		}
		table, column := match[1], match[2]
		canonical := prismaUpdatedAtTriggerSQL(table, column)
		if normalized != normalizePrismaUpdatedAtSQL(canonical) {
			continue
		}
		declarations = append(declarations, prismaUpdatedAtDeclaration{table, column, "trg_" + table + "_" + column + "_updated", canonical})
	}
	return declarations
}

// prismaUpdatedAtTriggersNeedUpgrade reports whether reconcilePrismaUpdatedAtTriggers
// would replace a stored trigger (a legacy definition). A missing trigger is
// creation, which the deferred-DDL plan sees by name; an error is returned for
// a trigger the reconcile would refuse, so the caller treats it as a change.
func prismaUpdatedAtTriggersNeedUpgrade(q mutationQuerier, deferred []string) (bool, error) {
	for _, def := range prismaUpdatedAtDeclarations(deferred) {
		existing, err := existingPrismaUpdatedAtTrigger(q, def.table, def.column)
		if err != nil {
			return true, err
		}
		if existing != "" && normalizePrismaUpdatedAtSQL(existing) != normalizePrismaUpdatedAtSQL(def.sql) {
			return true, nil
		}
	}
	return false, nil
}

// Reconcile only declarations regenerated by the current Prisma compiler. A
// similarly named authored trigger is not authority to overwrite it. The whole
// recognized set is validated and upgraded atomically; existing history and
// source rows are never changed. Run after schema columns have been migrated.
func reconcilePrismaUpdatedAtTriggers(db *sql.DB, deferred []string) error {
	declarations := prismaUpdatedAtDeclarations(deferred)
	if len(declarations) == 0 {
		return nil
	}
	tx, err := db.BeginTx(withLongWriteTx(context.Background(), "updated_at triggers"), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := reconcilePrismaUpdatedAtTriggersTx(tx, declarations); err != nil {
		return err
	}
	return tx.Commit()
}

func reconcilePrismaUpdatedAtTriggersTx(tx *sql.Tx, declarations []prismaUpdatedAtDeclaration) error {
	for _, def := range declarations {
		existing, err := existingPrismaUpdatedAtTrigger(tx, def.table, def.column)
		if err != nil {
			return err
		}
		if existing != "" {
			current := normalizePrismaUpdatedAtSQL(existing)
			if current != normalizePrismaUpdatedAtSQL(def.sql) {
				if _, err := tx.Exec("DROP TRIGGER " + quoteIdent(def.name)); err != nil {
					return err
				}
			}
		}
		if _, err := tx.Exec(def.sql); err != nil {
			return fmt.Errorf("prepare Prisma updatedAt trigger %q: %w", def.name, err)
		}
		// CREATE TRIGGER defers name resolution. Compile without executing a
		// row mutation so invalid generated declarations cannot replace a
		// working retained trigger set.
		rows, err := tx.Query("EXPLAIN UPDATE " + quoteIdent(def.table) + " SET " + quoteIdent(def.column) + "=" + quoteIdent(def.column) + " WHERE 0")
		if err != nil {
			return fmt.Errorf("compile Prisma updatedAt trigger %q: %w", def.name, err)
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	return nil
}
