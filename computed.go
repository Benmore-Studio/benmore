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

	// Drop all existing computed field triggers (prefix: _benmore_cf_)
	dropExistingTriggers(db)

	var installed int

	for _, columns := range config.Fields {
		for _, cf := range columns {
			if cf.Expr != "" {
				installed += installExprTriggers(db, cf)
			}
			if cf.SQL != "" {
				installed += installAggregateTriggers(db, cf)
			}
		}
	}

	if installed > 0 {
		log.Printf("  computed: %d triggers installed", installed)
	}
}

// dropExistingTriggers removes all _benmore_cf_* triggers.
func dropExistingTriggers(db *sql.DB) {
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE '_benmore_cf_%'")
	if err != nil {
		return
	}
	defer rows.Close()

	var triggers []string
	for rows.Next() {
		var name string
		rows.Scan(&name)
		triggers = append(triggers, name)
	}

	for _, name := range triggers {
		db.Exec(fmt.Sprintf("DROP TRIGGER IF EXISTS %s", name))
	}
}

// installExprTriggers creates AFTER INSERT and AFTER UPDATE triggers for same-row expressions.
// Example: line_total = quantity * unit_price
// → AFTER INSERT: UPDATE table SET col = (expr) WHERE id = NEW.id
// → AFTER UPDATE: UPDATE table SET col = (expr) WHERE id = NEW.id
func installExprTriggers(db *sql.DB, cf *ComputedField) int {
	count := 0

	// AFTER INSERT
	triggerName := fmt.Sprintf("_benmore_cf_%s_%s_insert", cf.Table, cf.Column)
	sql := fmt.Sprintf(
		"CREATE TRIGGER IF NOT EXISTS %s AFTER INSERT ON %s FOR EACH ROW BEGIN UPDATE %s SET %s = (%s) WHERE id = NEW.id; END",
		triggerName, cf.Table, cf.Table, cf.Column, cf.Expr,
	)
	if _, err := db.Exec(sql); err != nil {
		log.Printf("COMPUTED TRIGGER ERROR [%s]: %s", triggerName, err)
	} else {
		count++
	}

	// AFTER UPDATE
	triggerName = fmt.Sprintf("_benmore_cf_%s_%s_update", cf.Table, cf.Column)
	sql = fmt.Sprintf(
		"CREATE TRIGGER IF NOT EXISTS %s AFTER UPDATE ON %s FOR EACH ROW BEGIN UPDATE %s SET %s = (%s) WHERE id = NEW.id; END",
		triggerName, cf.Table, cf.Table, cf.Column, cf.Expr,
	)
	if _, err := db.Exec(sql); err != nil {
		log.Printf("COMPUTED TRIGGER ERROR [%s]: %s", triggerName, err)
	} else {
		count++
	}

	return count
}

// installAggregateTriggers creates triggers on the SOURCE table that recalculate
// the parent table's aggregate column.
// Example: contacts.deal_count = SELECT COUNT(*) FROM deals WHERE contact_id = ? AND deleted_at IS NULL
// Source table: deals, FK: contact_id
// → AFTER INSERT ON deals: UPDATE contacts SET deal_count = (...) WHERE id = NEW.contact_id
// → AFTER UPDATE ON deals: UPDATE contacts SET deal_count = (...) WHERE id = NEW.contact_id
//                          (also recalc OLD.contact_id if FK changed)
// → AFTER DELETE ON deals: UPDATE contacts SET deal_count = (...) WHERE id = OLD.contact_id
func installAggregateTriggers(db *sql.DB, cf *ComputedField) int {
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
				log.Printf("COMPUTED TRIGGER ERROR [%s]: %s\n  SQL: %s", triggerName, err, triggerSQL)
			} else {
				count++
			}

			// For UPDATE events, also recalculate the OLD parent if the FK changed
			if event == "update" {
				triggerName2 := fmt.Sprintf("_benmore_cf_%s_%s_%s_update_old",
					cf.Table, cf.Column, trigger.Table)
				recalcSQLOld := strings.Replace(cf.SQL, "?", fmt.Sprintf("OLD.%s", trigger.FK), 1)
				triggerSQL2 := fmt.Sprintf(
					"CREATE TRIGGER IF NOT EXISTS %s AFTER UPDATE ON %s FOR EACH ROW WHEN OLD.%s IS NOT NULL AND OLD.%s != NEW.%s BEGIN UPDATE %s SET %s = (%s) WHERE id = OLD.%s; END",
					triggerName2,
					trigger.Table,
					trigger.FK, trigger.FK, trigger.FK,
					cf.Table, cf.Column, recalcSQLOld,
					trigger.FK,
				)

				if _, err := db.Exec(triggerSQL2); err != nil {
					log.Printf("COMPUTED TRIGGER ERROR [%s]: %s", triggerName2, err)
				} else {
					count++
				}
			}
		}
	}

	return count
}

// ===== Helpers =====

func countComputedFields(config *ComputedFieldConfig) int {
	n := 0
	for _, cols := range config.Fields {
		n += len(cols)
	}
	return n
}
