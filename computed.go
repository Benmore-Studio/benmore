//go:build !cli

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"sort"
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
	return installComputedTriggersSealed(db, config, nil)
}

// installComputedTriggersSealed is installComputedTriggersChecked for a load
// that knows the app's encrypted fields: a computed column encrypted also
// names is written sealed by its own trigger (computedSeal).
func installComputedTriggersSealed(db *sql.DB, config *ComputedFieldConfig, encrypted *EncryptedFieldConfig) error {
	tx, err := db.BeginTx(withLongWriteTx(context.Background(), "computed triggers"), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	installed, err := installComputedTriggersSealedTx(tx, config, encrypted)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if installed > 0 {
		log.Printf("  computed: %d triggers installed", installed)
	}
	return nil
}

// installComputedTriggersSealedTx is installComputedTriggersSealed in the
// caller's transaction, returning how many triggers it installed. A start
// runs it before its migration files; the dry run of a start replays it there
// (dryRunStartSetup).
func installComputedTriggersSealedTx(tx *sql.Tx, config *ComputedFieldConfig, encrypted *EncryptedFieldConfig) (int, error) {
	if err := dropExistingTriggers(tx); err != nil {
		return 0, err
	}
	installed := 0
	if config != nil {
		for _, columns := range config.Fields {
			for _, cf := range columns {
				// The trigger text is written with bare names (and the
				// connector's trigger check regenerates exactly that text),
				// so every name in it must be a plain identifier. One that
				// is an SQL reserved word is quoted (ddlIdent).
				if err := computedFieldIdentError(cf); err != nil {
					return 0, err
				}
				// expr and sql are written into the trigger between
				// parentheses: each must be one expression, or its text
				// could end the UPDATE and add statements of its own.
				if err := computedFieldTextError(cf); err != nil {
					return 0, err
				}
				seal := computedSealFor(encrypted, cf.Table, cf.Column)
				if seal != nil && seal.blind {
					// The trigger writes <column>_blind itself; a load
					// installs computed triggers before the encryption
					// machinery that otherwise adds that column.
					if err := ensureBlindColumnsWith(tx, &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{seal.table: {{Column: seal.column, BlindIndex: true}}}}); err != nil {
						return 0, err
					}
				}
				if cf.Expr != "" {
					n, err := installExprTriggers(tx, cf, seal)
					if err != nil {
						return 0, err
					}
					installed += n
				}
				if cf.SQL != "" {
					n, err := installAggregateTriggers(tx, cf, seal)
					if err != nil {
						return 0, err
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
				return 0, err
			}
			var assignments []string
			for rows.Next() {
				var cid, notnull, primary int
				var name, typ string
				var defaultValue any
				if err := rows.Scan(&cid, &name, &typ, &notnull, &defaultValue, &primary); err != nil {
					rows.Close()
					return 0, err
				}
				assignments = append(assignments, quoteIdent(name)+"="+quoteIdent(name))
			}
			err = rows.Err()
			closeErr := rows.Close()
			if err != nil {
				return 0, err
			}
			if closeErr != nil {
				return 0, closeErr
			}
			if len(assignments) == 0 {
				return 0, fmt.Errorf("computed trigger table %q missing", table)
			}
			for _, statement := range []string{"INSERT INTO " + quoteIdent(table) + " DEFAULT VALUES", "UPDATE " + quoteIdent(table) + " SET " + strings.Join(assignments, ","), "DELETE FROM " + quoteIdent(table)} {
				program, err := tx.Query("EXPLAIN " + statement)
				if err != nil {
					return 0, fmt.Errorf("computed trigger program %s: %w", table, err)
				}
				if err := program.Close(); err != nil {
					return 0, err
				}
			}
		}
	}
	// Recreated computed triggers are newer than an enrolled table's revision
	// triggers; put those first again (app_mcp_revision_order.go).
	if err := reseatAppMCPRevisionTriggers(tx); err != nil {
		return 0, err
	}
	return installed, nil
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
// → AFTER INSERT: UPDATE table SET col = (expr) WHERE rowid = NEW.rowid AND col IS NOT (expr)
// → AFTER UPDATE: UPDATE table SET col = (expr) WHERE rowid = NEW.rowid AND col IS NOT (expr)
//
// We key on rowid (not id) so the trigger works for tables whose primary-key
// column is NOT named "id" (e.g. UUID PK tables, or tables keyed on account_id,
// mt_id, etc.).  Every ordinary SQLite table has a rowid regardless of how the
// PK column is named; for INTEGER PRIMARY KEY tables rowid == id, so this is
// fully back-compat.  (WITHOUT ROWID tables are never emitted by the framework.)
// This mirrors the same fix applied to the encryption/blind-index triggers in PR #93.
func installExprTriggers(db sqlExecutor, cf *ComputedField, seal *computedSeal) (int, error) {
	count := 0
	for _, event := range []string{"insert", "update"} {
		name, sql := computedExprTriggerSQLFor(cf, event, seal)
		if _, err := db.Exec(sql); err != nil {
			return count, fmt.Errorf("computed trigger %s: %w", name, err)
		}
		count++
	}
	return count, nil
}

// computedExprTriggerSQL is the one definition of a same-row computed
// trigger (event "insert" or "update"); the installer and the connector's
// trigger closure both use it, so the stored text and the expected text
// cannot drift.
//
// The recalculation writes only when the stored value differs from the
// expression (`IS NOT`, so NULL compares as a value). An unconditional write
// was a second UPDATE of the row on every insert and update, and that write
// fired the row's other UPDATE triggers: content history recorded a version
// for it (a row state with the stale value that was never committed), and the
// Prisma @updatedAt trigger fired again. A write that does change the value
// is storage maintenance; versioning recognizes it (versionUpdateWhen).
func computedExprTriggerSQL(cf *ComputedField, event string) (name, sql string) {
	name = fmt.Sprintf("_benmore_cf_%s_%s_%s", cf.Table, cf.Column, event)
	table := ddlIdent(cf.Table)
	sql = fmt.Sprintf(
		"CREATE TRIGGER IF NOT EXISTS %s AFTER %s ON %s FOR EACH ROW BEGIN UPDATE %s SET %s = (%s) WHERE rowid = NEW.rowid AND %s IS NOT (%s); END",
		name, strings.ToUpper(event), table, table, ddlIdent(cf.Column), cf.Expr, ddlExprIdent(cf.Column), cf.Expr,
	)
	return name, sql
}

// computedSeal is how a computed field writes a column encrypted.yaml (or
// app.yaml encrypted:) also encrypts. Its trigger used to write the plaintext
// and leave sealing to the encryption trigger, but SQLite does not run a
// trigger that is already running: the computed update trigger, fired by the
// encryption trigger's own write, compared that ciphertext with the
// expression, wrote the plaintext back, and the encryption trigger could not
// fire again. The column stayed plaintext at rest. Now the computed trigger
// seals the value itself (benmore_encrypt_plaintext, bound to the field like
// the encryption trigger's ciphertext), keeps a blind index current, and
// writes only when the stored ciphertext does not already hold the computed
// value (benmore_ciphertext_holds), so an unchanged value is not rewritten
// with a new nonce and a stored plaintext value is sealed at its next
// recalculation.
type computedSeal struct {
	table, column string // the encrypted field as declared: the ciphertext's AAD
	blind         bool   // the field has a blind index, <column>_blind
}

// computedSealFor is the seal for a computed table.column when encrypted
// encrypts it, else nil (the plain trigger).
func computedSealFor(encrypted *EncryptedFieldConfig, table, column string) *computedSeal {
	if encrypted == nil {
		return nil
	}
	for name, defs := range encrypted.Fields {
		if sqliteIdentifierFold(name) != sqliteIdentifierFold(table) {
			continue
		}
		for _, def := range defs {
			if sqliteIdentifierFold(def.Column) == sqliteIdentifierFold(column) {
				return &computedSeal{table: name, column: def.Column, blind: def.BlindIndex}
			}
		}
	}
	return nil
}

func computedSealLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// assign is the SET list that stores value (an SQL expression) in column.
func (s *computedSeal) assign(column, value string) string {
	target := ddlIdent(column)
	if s == nil {
		return target + " = (" + value + ")"
	}
	set := target + " = benmore_encrypt_plaintext((" + value + "), " + computedSealLiteral(s.table) + ", " + computedSealLiteral(s.column) + ")"
	if s.blind {
		set += ", " + column + blindColSuffix + " = CASE WHEN (" + value + ") IS NULL THEN NULL ELSE benmore_blind_index((" + value + ")) END"
	}
	return set
}

// unlessHeld is the WHERE condition (with its leading AND) that skips the
// write when column already holds value sealed; empty for a plain column.
func (s *computedSeal) unlessHeld(column, value string) string {
	if s == nil {
		return ""
	}
	return " AND NOT benmore_ciphertext_holds(" + ddlExprIdent(column) + ", (" + value + "), " + computedSealLiteral(s.table) + ", " + computedSealLiteral(s.column) + ")"
}

// computedExprTriggerSQLFor is computedExprTriggerSQL for a field whose column
// is encrypted (seal not nil): the same trigger, writing the sealed value.
func computedExprTriggerSQLFor(cf *ComputedField, event string, seal *computedSeal) (name, sql string) {
	if seal == nil {
		return computedExprTriggerSQL(cf, event)
	}
	name = fmt.Sprintf("_benmore_cf_%s_%s_%s", cf.Table, cf.Column, event)
	table := ddlIdent(cf.Table)
	sql = fmt.Sprintf(
		"CREATE TRIGGER IF NOT EXISTS %s AFTER %s ON %s FOR EACH ROW BEGIN UPDATE %s SET %s WHERE rowid = NEW.rowid%s; END",
		name, strings.ToUpper(event), table, table, seal.assign(cf.Column, cf.Expr), seal.unlessHeld(cf.Column, cf.Expr),
	)
	return name, sql
}

// suspendSealedComputedTriggers drops, inside a key rotation's transaction,
// the triggers of computed fields whose column is encrypted (computedSeal):
// the rotation's own writes would run them while the old key is still the
// connection's, they would find the new ciphertext unreadable and seal the
// value again under the old key. Rotation re-seals those columns itself, and
// their values do not change. It returns the triggers' DDL to restore.
func suspendSealedComputedTriggers(tx *sql.Tx) ([]string, error) {
	rows, err := tx.Query(`SELECT name,sql FROM main.sqlite_schema WHERE type='trigger' AND substr(name,1,12)='_benmore_cf_' AND instr(sql,'benmore_ciphertext_holds(')>0 ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var names, ddls []string
	for rows.Next() {
		var name, ddl string
		if err := rows.Scan(&name, &ddl); err != nil {
			rows.Close()
			return nil, err
		}
		names = append(names, name)
		ddls = append(ddls, ddl)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	for _, name := range names {
		if _, err := tx.Exec("DROP TRIGGER " + quoteIdent(name)); err != nil {
			return nil, err
		}
	}
	return ddls, nil
}

// computedExprColumns lists the columns of table that a same-row computed
// expression derives. Content history treats their recalculation as storage
// maintenance rather than another version. Aggregate (sql:) fields are not
// listed: their value follows other tables, so a change is a real change of
// the row's state.
func computedExprColumns(config *ComputedFieldConfig, table string) []string {
	if config == nil {
		return nil
	}
	var cols []string
	for t, fields := range config.Fields {
		if sqliteIdentifierFold(t) != sqliteIdentifierFold(table) {
			continue
		}
		for col, cf := range fields {
			if cf != nil && cf.Expr != "" {
				cols = append(cols, col)
			}
		}
	}
	sort.Strings(cols)
	return cols
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
func installAggregateTriggers(db sqlExecutor, cf *ComputedField, seal *computedSeal) (int, error) {
	count := 0
	for _, trigger := range cf.Triggers {
		for _, event := range trigger.On {
			triggerName, triggerSQL, ok := computedAggregateTriggerSQL(cf, trigger, event, seal)
			if !ok {
				continue
			}
			if _, err := db.Exec(triggerSQL); err != nil {
				return count, fmt.Errorf("computed trigger %s: %w", triggerName, err)
			}
			count++

			// For UPDATE events, also recalculate the OLD parent if the FK
			// changed (computedAggregateOldTriggerSQL).
			if event == "update" {
				triggerName2, triggerSQL2 := computedAggregateOldTriggerSQL(cf, trigger, seal)
				if _, err := db.Exec(triggerSQL2); err != nil {
					return count, fmt.Errorf("computed trigger %s: %w", triggerName2, err)
				}
				count++
			}
		}
	}

	return count, nil
}

// computedAggregateTriggerSQL is the one definition of the trigger on a
// source table that recalculates the owning table's aggregate column for one
// event (insert, update or delete; ok is false for anything else). The
// installer and the connector's trigger closure both use it.
//
// The recalculation SQL's ? becomes the FK reference: NEW.fk for insert and
// update, OLD.fk for delete. Soft deletes (an UPDATE setting deleted_at) are
// covered by the update trigger.
func computedAggregateTriggerSQL(cf *ComputedField, trigger ComputedTriggerDef, event string, seal *computedSeal) (name, sql string, ok bool) {
	var ref string // NEW or OLD
	switch event {
	case "insert", "update":
		ref = "NEW"
	case "delete":
		ref = "OLD"
	default:
		return "", "", false
	}
	fk := ddlIdent(trigger.FK)
	recalc := strings.Replace(cf.SQL, "?", fmt.Sprintf("%s.%s", ref, fk), 1)
	name = fmt.Sprintf("_benmore_cf_%s_%s_%s_%s", cf.Table, cf.Column, trigger.Table, event)
	sql = fmt.Sprintf(
		"CREATE TRIGGER IF NOT EXISTS %s AFTER %s ON %s FOR EACH ROW WHEN %s.%s IS NOT NULL BEGIN UPDATE %s SET %s WHERE id = %s.%s%s; END",
		name, strings.ToUpper(event), ddlIdent(trigger.Table),
		ref, fk,
		ddlIdent(cf.Table), seal.assign(cf.Column, recalc),
		ref, fk, seal.unlessHeld(cf.Column, recalc),
	)
	return name, sql, true
}

// computedAggregateOldTriggerSQL recalculates the OLD parent when an update
// moves a source row to another parent. `IS NOT`, not `!=`: a key set to NULL
// (the child is detached) compares as NULL with `!=`, the trigger did not
// fire and the parent kept counting a child that had left it.
func computedAggregateOldTriggerSQL(cf *ComputedField, trigger ComputedTriggerDef, seal *computedSeal) (name, sql string) {
	name = fmt.Sprintf("_benmore_cf_%s_%s_%s_update_old", cf.Table, cf.Column, trigger.Table)
	fk := ddlIdent(trigger.FK)
	recalc := strings.Replace(cf.SQL, "?", fmt.Sprintf("OLD.%s", fk), 1)
	sql = fmt.Sprintf(
		"CREATE TRIGGER IF NOT EXISTS %s AFTER UPDATE ON %s FOR EACH ROW WHEN OLD.%s IS NOT NULL AND OLD.%s IS NOT NEW.%s BEGIN UPDATE %s SET %s WHERE id = OLD.%s%s; END",
		name, ddlIdent(trigger.Table),
		fk, fk, fk,
		ddlIdent(cf.Table), seal.assign(cf.Column, recalc),
		fk, seal.unlessHeld(cf.Column, recalc),
	)
	return name, sql
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
