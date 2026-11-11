//go:build !cli

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Revision triggers fire before every other trigger on an enrolled table.
//
// The ledger's insert trigger writes a new row's ledger entry AFTER INSERT,
// and the update and delete triggers refuse a row that has none ("revision
// ledger row missing"). Framework triggers on the same table (encrypted
// fields, same-row computed fields, blind indexes) rewrite the row they just
// saw inserted with an UPDATE. If such a trigger runs before the ledger's
// insert trigger, its UPDATE reaches the ledger's update trigger while the
// ledger entry does not exist yet, and the whole insert aborts.
//
// SQLite runs the triggers of one table and event newest first: a connection
// that creates a trigger puts it at the head of the table's list, and a
// connection that reads the schema parses sqlite_schema in rowid order, so the
// row with the highest rowid fires first. A new trigger always gets a rowid
// above every existing one. Enrollment creates the revision triggers last,
// but loads drop and create the encryption, computed and blind-index triggers
// again (and migrations, Prisma and full-text setup may add triggers), which
// put them ahead of the revision triggers: after any reload or restart every
// insert into an enrolled table with an encrypted or computed column failed.
//
// So every load step that creates triggers ends its transaction with
// reseatAppMCPRevisionTriggers, which drops and creates the revision triggers
// again when another trigger on their table is newer. They are recreated from
// the same generated SQL enrollment installed, so their text, the enrollment
// identity (incarnation, trigger set digest) and every row revision stay as
// they were; only their position changes, inside one transaction, so no write
// ever runs without them. Verification (verifyAppMCPRevisionStorage) refuses a
// table whose revision triggers are not the newest, and `mcp status` reports
// it, so a missed path fails closed instead of reporting an active enrollment
// whose inserts fail. TestSQLiteRunsNewestTriggerFirst pins the SQLite order.
//
// The revision triggers are not made order-independent instead: their text is
// the enrollment's verified identity (changing it re-enrolls every app with a
// fresh incarnation, which makes pending approvals stale), the missing-row
// refusal is what keeps a write the ledger did not see from passing silently,
// SQL in a trigger cannot tell a framework rewrite of the row being inserted
// from any other update, and an auto-assigned NEW.id is undefined in a BEFORE
// INSERT trigger. Keeping them first also covers an id-changing UPDATE whose
// @updatedAt or computed trigger would otherwise run before the move is
// recorded.

const appMCPRevisionTriggerPrefix = "_benmore_mcp_rev_"

type appMCPTableTriggerRowIDs struct {
	revision []int64 // rowids of the reserved revision triggers on the table
	other    []int64 // rowids of every other trigger on the table
}

// appMCPTriggerRowIDsByTable reads every main-schema trigger's sqlite_schema
// rowid, keyed by its table name folded to lower case (SQLite identifiers are
// case-insensitive).
func appMCPTriggerRowIDsByTable(q mutationQuerier) (map[string]*appMCPTableTriggerRowIDs, error) {
	rows, err := q.Query(`SELECT rowid,name,tbl_name FROM main.sqlite_schema WHERE type='trigger'`)
	if err != nil {
		return nil, fmt.Errorf("read trigger order: %w", err)
	}
	defer rows.Close()
	byTable := make(map[string]*appMCPTableTriggerRowIDs)
	for rows.Next() {
		var rowid int64
		var name, table string
		if err := rows.Scan(&rowid, &name, &table); err != nil {
			return nil, err
		}
		key := strings.ToLower(table)
		entry := byTable[key]
		if entry == nil {
			entry = &appMCPTableTriggerRowIDs{}
			byTable[key] = entry
		}
		if strings.HasPrefix(name, appMCPRevisionTriggerPrefix) {
			entry.revision = append(entry.revision, rowid)
		} else {
			entry.other = append(entry.other, rowid)
		}
	}
	return byTable, rows.Err()
}

// revisionFiresFirst reports whether every revision trigger on the table is
// newer than every other trigger on it (true when either set is empty).
func (ids *appMCPTableTriggerRowIDs) revisionFiresFirst() bool {
	if ids == nil || len(ids.revision) == 0 || len(ids.other) == 0 {
		return true
	}
	oldestRevision, newestOther := ids.revision[0], ids.other[0]
	for _, rowid := range ids.revision {
		if rowid < oldestRevision {
			oldestRevision = rowid
		}
	}
	for _, rowid := range ids.other {
		if rowid > newestOther {
			newestOther = rowid
		}
	}
	return oldestRevision > newestOther
}

// appMCPRevisionTriggerOrderProblem returns the first of tables (in sorted
// order) on which another trigger fires before the revision triggers, or "".
func appMCPRevisionTriggerOrderProblem(q mutationQuerier, tables []string) (string, error) {
	byTable, err := appMCPTriggerRowIDsByTable(q)
	if err != nil {
		return "", err
	}
	ordered := append([]string(nil), tables...)
	sort.Strings(ordered)
	for _, table := range ordered {
		if !byTable[strings.ToLower(table)].revisionFiresFirst() {
			return table, nil
		}
	}
	return "", nil
}

// appMCPRegisteredRevisionTables lists the revision registry's tables, or none
// when the app has no revision storage.
func appMCPRegisteredRevisionTables(q mutationQuerier) ([]string, error) {
	var registry int
	if err := q.QueryRow(`SELECT count(*) FROM main.sqlite_schema WHERE type='table' AND name=?`, appMCPRevisionTablesName).Scan(&registry); err != nil {
		return nil, fmt.Errorf("read revision registry: %w", err)
	}
	if registry == 0 {
		return nil, nil
	}
	rows, err := q.Query(`SELECT table_name FROM main._benmore_mcp_revision_tables ORDER BY table_name`)
	if err != nil {
		return nil, fmt.Errorf("read revision registry: %w", err)
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			return nil, err
		}
		tables = append(tables, table)
	}
	return tables, rows.Err()
}

func appMCPRevisionTriggerOrderError(table string) error {
	return fmt.Errorf("revision triggers on %q no longer fire before the table's other triggers, so inserts that another trigger rewrites fail; reload the app or run `benmore mcp enable --writes` to put them first again", table)
}

// reseatAppMCPRevisionTriggers puts each enrolled table's revision triggers
// back in front of the table's other triggers, in the caller's transaction.
// It is a no-op without revision storage or when the order is already right.
// Revision triggers whose stored text is not exactly one generated set are
// left alone: verification refuses them and only an explicit repair replaces
// them.
func reseatAppMCPRevisionTriggers(tx mutationTx) error {
	tables, err := appMCPRegisteredRevisionTables(tx)
	if err != nil || len(tables) == 0 {
		return err
	}
	byTable, err := appMCPTriggerRowIDsByTable(tx)
	if err != nil {
		return err
	}
	for _, table := range tables {
		lower := strings.ToLower(table)
		if byTable[lower].revisionFiresFirst() {
			continue
		}
		if !isValidColumnName(table) || strings.HasPrefix(lower, "_benmore_") || strings.HasPrefix(lower, "sqlite_") {
			continue
		}
		triggers, err := appMCPInstalledRevisionTriggerSet(tx, table)
		if err != nil {
			return err
		}
		if triggers == nil {
			continue
		}
		for _, trigger := range triggers {
			if _, err := tx.Exec("DROP TRIGGER main." + quoteIdent(trigger.name)); err != nil {
				return fmt.Errorf("reorder revision trigger %q: %w", trigger.name, err)
			}
		}
		for _, trigger := range triggers {
			if _, err := tx.Exec(trigger.sql); err != nil {
				return fmt.Errorf("reorder revision trigger %q: %w", trigger.name, err)
			}
		}
	}
	return nil
}

// appMCPInstalledRevisionTriggerSet returns the generated revision trigger set
// (plain or unique-reconciling) whose every member is installed on table with
// exactly that text, or nil when the installed triggers are not one such set.
func appMCPInstalledRevisionTriggerSet(q mutationQuerier, table string) ([]appMCPRevisionTrigger, error) {
	variants := [][]appMCPRevisionTrigger{appMCPRevisionTriggerSQL(table), appMCPRevisionTriggerSQLWithUniqueReconciliation(table)}
	installed := make(map[string]string, len(variants[0]))
	for _, trigger := range variants[0] {
		var stored, onTable string
		err := q.QueryRow(`SELECT sql,tbl_name FROM main.sqlite_schema WHERE type='trigger' AND name=?`, trigger.name).Scan(&stored, &onTable)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if !strings.EqualFold(onTable, table) {
			return nil, nil
		}
		installed[trigger.name] = stored
	}
	for _, variant := range variants {
		matches := true
		for _, trigger := range variant {
			ok, err := appMCPRevisionSQLMatches(installed[trigger.name], trigger.sql)
			if err != nil || !ok {
				matches = false
				break
			}
		}
		if matches {
			return variant, nil
		}
	}
	return nil, nil
}

// reseatAppMCPRevisionTriggersDB runs reseatAppMCPRevisionTriggers in its own
// transaction, for load steps whose trigger changes commit separately.
func reseatAppMCPRevisionTriggersDB(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return nil
	}
	tx, err := db.BeginTx(withLongWriteTx(ctx, "revision trigger order"), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := reseatAppMCPRevisionTriggers(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// appMCPRevisionTriggerOrderFindings is the serving process's check of its own
// database: an enrolled table whose revision triggers no longer fire first
// refuses inserts that another trigger rewrites. Nothing without revision
// storage, and nothing when the database cannot be read.
func appMCPRevisionTriggerOrderFindings(db *sql.DB) []CheckFinding {
	if db == nil {
		return nil
	}
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil
	}
	defer tx.Rollback()
	tables, err := appMCPRegisteredRevisionTables(tx)
	if err != nil || len(tables) == 0 {
		return nil
	}
	table, err := appMCPRevisionTriggerOrderProblem(tx, tables)
	if err != nil || table == "" {
		return nil
	}
	return []CheckFinding{{Severity: "error", Source: "mcp_connector", Message: fmt.Sprintf("inserts into %q that another trigger rewrites (an encrypted or computed field) fail with \"revision ledger row missing\": a trigger on this connector-enrolled table fires before its revision triggers; run `benmore mcp enable <app> --writes` or reload the app to put them first", table)}}
}

// appMCPRevisionTriggersOutOfOrder reports, read-only, whether an enrolled
// table's revision triggers no longer fire first. False when it cannot tell.
func appMCPRevisionTriggersOutOfOrder(ctx context.Context, db *sql.DB, tables []string) bool {
	if ctx == nil || db == nil || len(tables) == 0 {
		return false
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return false
	}
	defer tx.Rollback()
	table, err := appMCPRevisionTriggerOrderProblem(tx, tables)
	return err == nil && table != ""
}
