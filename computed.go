//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
)

// ===== Types =====

// ComputedFieldConfig holds all computed field definitions.
type ComputedFieldConfig struct {
	Fields map[string]map[string]*ComputedField // table → column → definition
}

// ComputedField defines a single computed column.
type ComputedField struct {
	Table    string // owning table
	Column   string // column name
	Expr     string // same-row expression: "quantity * unit_price"
	SQL      string // cross-table aggregate: "SELECT SUM(...) FROM ... WHERE fk = ?"
	Triggers []ComputedTriggerDef
}

// ComputedTriggerDef defines when a cross-table computed field should recalculate.
type ComputedTriggerDef struct {
	Table string   // source table that triggers recalculation
	On    []string // mutation types: "insert", "update", "delete"
	FK    string   // FK column in source table pointing to owning table's id
}

// ===== SQLite Trigger Generator =====

// InstallComputedTriggers generates and installs SQLite triggers for all computed fields.
// Triggers fire at the database level on every mutation - regardless of whether the
// mutation comes from the CRUD API, hooks, flows, raw SQL, or any other path.
// Called once at app startup after loading computed.yaml.
func InstallComputedTriggers(db *sql.DB, config *ComputedFieldConfig) {
	if config == nil {
		return
	}
	if err := installComputedTriggersChecked(db, config); err != nil {
		log.Printf("COMPUTED TRIGGER ERROR: %s", err)
	}
}

// Replacement is atomic: a rejected definition retains the prior generation.
// A nil checked config removes computed triggers on deliberate feature removal.
func installComputedTriggersChecked(db *sql.DB, config *ComputedFieldConfig) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := dropExistingTriggers(tx); err != nil {
		return err
	}
	installed := 0
	if config != nil {
		for _, columns := range config.Fields {
			for _, cf := range columns {
				// The trigger text is written with bare names (and the
				// connector's trigger check regenerates exactly that text),
				// so every name in it must be a plain identifier.
				if err := computedFieldIdentError(cf); err != nil {
					return err
				}
				if cf.Expr != "" {
					n, err := installExprTriggers(tx, cf)
					if err != nil {
						return err
					}
					installed += n
				}
				if cf.SQL != "" {
					n, err := installAggregateTriggers(tx, cf)
					if err != nil {
						return err
					}
					installed += n
				}
			}
		}
	}
	if config != nil {
		tables := map[string]bool{}
		for _, columns := range config.Fields {
			for _, cf := range columns {
				tables[cf.Table] = true
				for _, trigger := range cf.Triggers {
					tables[trigger.Table] = true
				}
			}
		}
		for table := range tables {
			// EXPLAIN prepares trigger programs without executing any DML.
			rows, err := tx.Query("PRAGMA table_info(" + quoteIdent(table) + ")")
			if err != nil {
				return err
			}
			var assignments []string
			for rows.Next() {
				var cid, notnull, primary int
				var name, typ string
				var defaultValue any
				if err := rows.Scan(&cid, &name, &typ, &notnull, &defaultValue, &primary); err != nil {
					rows.Close()
					return err
				}
				assignments = append(assignments, quoteIdent(name)+"="+quoteIdent(name))
			}
			err = rows.Err()
			closeErr := rows.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			if len(assignments) == 0 {
				return fmt.Errorf("computed trigger table %q missing", table)
			}
			for _, statement := range []string{"INSERT INTO " + quoteIdent(table) + " DEFAULT VALUES", "UPDATE " + quoteIdent(table) + " SET " + strings.Join(assignments, ","), "DELETE FROM " + quoteIdent(table)} {
				program, err := tx.Query("EXPLAIN " + statement)
				if err != nil {
					return fmt.Errorf("computed trigger program %s: %w", table, err)
				}
				if err := program.Close(); err != nil {
					return err
				}
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if installed > 0 {
		log.Printf("  computed: %d triggers installed", installed)
	}
	return nil
}

// computedFieldIdentError refuses a computed field whose table, column or
// trigger source names are not plain identifiers. Only the names a trigger
// would be written with are checked: a field with neither expr nor sql
// installs nothing, and triggers: is read only next to sql.
func computedFieldIdentError(cf *ComputedField) error {
	if cf.Expr == "" && cf.SQL == "" {
		return nil
	}
	if err := configIdentError("computed.yaml: table", cf.Table); err != nil {
		return err
	}
	if err := configIdentError("computed.yaml: column", cf.Column); err != nil {
		return err
	}
	if cf.SQL == "" {
		return nil
	}
	for _, trigger := range cf.Triggers {
		if err := configIdentError("computed.yaml: trigger table", trigger.Table); err != nil {
			return err
		}
		if err := configIdentError("computed.yaml: trigger fk", trigger.FK); err != nil {
			return err
		}
	}
	return nil
}

// dropExistingTriggers removes only the framework's exact computed prefix.
func dropExistingTriggers(tx *sql.Tx) error {
	rows, err := tx.Query("SELECT name FROM sqlite_master WHERE type='trigger' AND substr(name, 1, 12) = '_benmore_cf_'")
	if err != nil {
		return err
	}
	var triggers []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		triggers = append(triggers, name)
	}
	err = rows.Err()
	closeErr := rows.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	for _, name := range triggers {
		if _, err := tx.Exec("DROP TRIGGER IF EXISTS " + quoteIdent(name)); err != nil {
			return err
		}
	}
	return nil
}

// installExprTriggers creates AFTER INSERT and AFTER UPDATE triggers for same-row expressions.
// Example: line_total = quantity * unit_price
// → AFTER INSERT: UPDATE table SET col = (expr) WHERE rowid = NEW.rowid
// → AFTER UPDATE: UPDATE table SET col = (expr) WHERE rowid = NEW.rowid
//
// We key on rowid (not id) so the trigger works for tables whose primary-key
// column is NOT named "id" (e.g. UUID PK tables, or tables keyed on account_id,
// mt_id, etc.).  Every ordinary SQLite table has a rowid regardless of how the
// PK column is named; for INTEGER PRIMARY KEY tables rowid == id, so this is
// fully back-compat.  (WITHOUT ROWID tables are never emitted by the framework.)
// This mirrors the same fix applied to the encryption/blind-index triggers in PR #93.
func installExprTriggers(db sqlExecutor, cf *ComputedField) (int, error) {
	count := 0

	// AFTER INSERT: compute the expression and store it on the new row.
	// Use WHERE rowid = NEW.rowid (not WHERE id = NEW.id) — see function
	// comment above for the full rationale.
	triggerName := fmt.Sprintf("_benmore_cf_%s_%s_insert", cf.Table, cf.Column)
	sql := fmt.Sprintf(
		"CREATE TRIGGER IF NOT EXISTS %s AFTER INSERT ON %s FOR EACH ROW BEGIN UPDATE %s SET %s = (%s) WHERE rowid = NEW.rowid; END",
		triggerName, cf.Table, cf.Table, cf.Column, cf.Expr,
	)
	if _, err := db.Exec(sql); err != nil {
		return count, fmt.Errorf("computed trigger %s: %w", triggerName, err)
	} else {
		count++
	}

	// AFTER UPDATE: recompute when any column changes.
	// Same rowid fix as the INSERT trigger above.
	triggerName = fmt.Sprintf("_benmore_cf_%s_%s_update", cf.Table, cf.Column)
	sql = fmt.Sprintf(
		"CREATE TRIGGER IF NOT EXISTS %s AFTER UPDATE ON %s FOR EACH ROW BEGIN UPDATE %s SET %s = (%s) WHERE rowid = NEW.rowid; END",
		triggerName, cf.Table, cf.Table, cf.Column, cf.Expr,
	)
	if _, err := db.Exec(sql); err != nil {
		return count, fmt.Errorf("computed trigger %s: %w", triggerName, err)
	} else {
		count++
	}

	return count, nil
}

// installAggregateTriggers creates triggers on the SOURCE table that recalculate
// the parent table's aggregate column.
// Example: contacts.deal_count = SELECT COUNT(*) FROM deals WHERE contact_id = ? AND deleted_at IS NULL
// Source table: deals, FK: contact_id
// → AFTER INSERT ON deals: UPDATE contacts SET deal_count = (...) WHERE id = NEW.contact_id
// → AFTER UPDATE ON deals: UPDATE contacts SET deal_count = (...) WHERE id = NEW.contact_id
//
//	(also recalc OLD.contact_id if FK changed)
//
// → AFTER DELETE ON deals: UPDATE contacts SET deal_count = (...) WHERE id = OLD.contact_id
func installAggregateTriggers(db sqlExecutor, cf *ComputedField) (int, error) {
	count := 0

	// Convert the SQL template: replace ? with the FK reference
	// For INSERT/UPDATE triggers, use NEW.fk_column
	// For DELETE triggers, use OLD.fk_column
	for _, trigger := range cf.Triggers {
		for _, event := range trigger.On {
			var ref string // NEW or OLD
			switch event {
			case "insert":
				ref = "NEW"
			case "update":
				ref = "NEW"
			case "delete":
				ref = "OLD"
			default:
				continue
			}

			// Build the recalculation SQL - replace ? with the FK reference
			recalcSQL := strings.Replace(cf.SQL, "?", fmt.Sprintf("%s.%s", ref, trigger.FK), 1)

			triggerName := fmt.Sprintf("_benmore_cf_%s_%s_%s_%s",
				cf.Table, cf.Column, trigger.Table, event)

			// For soft deletes (UPDATE sets deleted_at), also handle the "delete" case
			// via AFTER UPDATE when deleted_at changes from NULL to non-NULL
			triggerSQL := fmt.Sprintf(
				"CREATE TRIGGER IF NOT EXISTS %s AFTER %s ON %s FOR EACH ROW WHEN %s.%s IS NOT NULL BEGIN UPDATE %s SET %s = (%s) WHERE id = %s.%s; END",
				triggerName,
				strings.ToUpper(event),
				trigger.Table,
				ref, trigger.FK,
				cf.Table, cf.Column, recalcSQL,
				ref, trigger.FK,
			)

			if _, err := db.Exec(triggerSQL); err != nil {
				return count, fmt.Errorf("computed trigger %s: %w", triggerName, err)
			} else {
				count++
			}

			// For UPDATE events, also recalculate the OLD parent if the FK
			// changed. `IS NOT`, not `!=`: a key set to NULL (the child is
			// detached) compares as NULL with `!=`, the trigger did not fire
			// and the parent kept counting a child that had left it.
			if event == "update" {
				triggerName2 := fmt.Sprintf("_benmore_cf_%s_%s_%s_update_old",
					cf.Table, cf.Column, trigger.Table)
				recalcSQLOld := strings.Replace(cf.SQL, "?", fmt.Sprintf("OLD.%s", trigger.FK), 1)
				triggerSQL2 := fmt.Sprintf(
					"CREATE TRIGGER IF NOT EXISTS %s AFTER UPDATE ON %s FOR EACH ROW WHEN OLD.%s IS NOT NULL AND OLD.%s IS NOT NEW.%s BEGIN UPDATE %s SET %s = (%s) WHERE id = OLD.%s; END",
					triggerName2,
					trigger.Table,
					trigger.FK, trigger.FK, trigger.FK,
					cf.Table, cf.Column, recalcSQLOld,
					trigger.FK,
				)

				if _, err := db.Exec(triggerSQL2); err != nil {
					return count, fmt.Errorf("computed trigger %s: %w", triggerName2, err)
				} else {
					count++
				}
			}
		}
	}

	return count, nil
}

// ===== Helpers =====

func countComputedFields(config *ComputedFieldConfig) int {
	n := 0
	for _, cols := range config.Fields {
		n += len(cols)
	}
	return n
}

// computedColumns lists the columns of table that computed.yaml derives (a
// same-row expression or a cross-table aggregate). Their values come from
// triggers, so no create or update path may accept them from a client.
func computedColumns(app *App, table string) []string {
	if app == nil {
		return nil
	}
	config := app.computedConfig()
	if config == nil {
		return nil
	}
	var cols []string
	for t, fields := range config.Fields {
		if sqliteIdentifierFold(t) != sqliteIdentifierFold(table) {
			continue
		}
		for col := range fields {
			cols = append(cols, col)
		}
	}
	return cols
}

// computedAggregateRefs returns, for a SOURCE table of an aggregate computed
// field, each FK column whose value the aggregate trigger uses to pick the
// parent row it rewrites (`UPDATE parent ... WHERE id = NEW.<fk>`). The FK may
// be undeclared in the schema, so write gates treat these like real foreign
// keys: a row may only point at a parent its writer can read, or the trigger
// would rewrite another tenant's aggregate.
func computedAggregateRefs(app *App, table string) map[string]ForeignKey {
	if app == nil {
		return nil
	}
	config := app.computedConfig()
	if config == nil {
		return nil
	}
	refs := map[string]ForeignKey{}
	for _, fields := range config.Fields {
		for _, cf := range fields {
			if cf == nil || cf.SQL == "" {
				continue
			}
			for _, trigger := range cf.Triggers {
				if trigger.FK == "" || sqliteIdentifierFold(trigger.Table) != sqliteIdentifierFold(table) {
					continue
				}
				refs[trigger.FK] = ForeignKey{Table: cf.Table, Column: "id"}
			}
		}
	}
	return refs
}
