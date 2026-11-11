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

// InstallVersioningTriggers reconciles history columns, repairs legacy plaintext
// snapshots, and replaces the complete trigger set in one transaction. Callers
// must refuse startup/reload on error; the previous triggers survive rollback.
func InstallVersioningTriggers(db *sql.DB, config *VersionedConfig, encryption ...*EncryptedFieldConfig) error {
	var encrypted *EncryptedFieldConfig
	if len(encryption) != 0 {
		encrypted = encryption[0]
	}
	key := cryptoKeyForQuerier(db)
	tx, err := db.BeginTx(withLongWriteTx(context.Background(), "versioning triggers"), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := installVersioningTriggersTx(tx, config, encrypted, key); err != nil {
		return err
	}
	if err := reseatAppMCPRevisionTriggers(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func installVersioningTriggersTx(tx *sql.Tx, config *VersionedConfig, encrypted *EncryptedFieldConfig, key []byte) error {
	// Erase replaced payload bytes from database pages during legacy repair.
	// Historical backups and earlier WAL/free-page remnants are separate artifacts.
	if encrypted != nil {
		if _, err := tx.Exec("PRAGMA secure_delete=ON"); err != nil {
			return fmt.Errorf("secure history repair: %w", err)
		}
	}
	if _, err := suspendVersioningTriggers(tx); err != nil {
		return err
	}
	if config != nil {
		for _, table := range config.Tables {
			if err := configIdentError("app.yaml: versioned table", table); err != nil {
				return err
			}
			if err := reconcileVersionedTable(tx, table, encrypted, config.Derived[table]); err != nil {
				return fmt.Errorf("versioning %s: %w", table, err)
			}
		}
	}
	// Retained history must be repaired even when versioning was subsequently
	// disabled. It remains readable through exports/backups and may be re-enabled.
	if encrypted != nil {
		tables := make([]string, 0, len(encrypted.Fields))
		for table := range encrypted.Fields {
			tables = append(tables, table)
		}
		sort.Strings(tables)
		for _, table := range tables {
			history := table + "_history"
			exists, err := versionHistoryExists(tx, history)
			if err != nil {
				return err
			}
			if !exists {
				continue
			}
			cols, err := mainTableColumnsWith(tx, history)
			if err != nil {
				return err
			}
			for _, def := range encrypted.Fields[table] {
				if !versionHasColumn(cols, def.Column) {
					continue
				} // field added after versioning was disabled
				if len(key) != 32 {
					return fmt.Errorf("versioning %s: encryption key unavailable", table)
				}
				if err := repairVersionedColumn(tx, table, def.Column, key); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Reconcile existing source tables before migrations, then use the complete
// checked installer afterward. A migration may legitimately create a new source.
func installVersioningBeforeMigrations(db *sql.DB, config *VersionedConfig, encrypted *EncryptedFieldConfig) error {
	existing, err := versionedTablesThatExist(db, config)
	if err != nil {
		return err
	}
	return InstallVersioningTriggers(db, existing, encrypted)
}

// versionedTablesThatExist is config limited to the source tables the
// database has: what a start reconciles before its migration files run (they
// may create the rest). nil for a nil config.
func versionedTablesThatExist(q mutationQuerier, config *VersionedConfig) (*VersionedConfig, error) {
	if config == nil {
		return nil, nil
	}
	existing := &VersionedConfig{Derived: config.Derived}
	for _, table := range config.Tables {
		if err := configIdentError("app.yaml: versioned table", table); err != nil {
			return nil, err
		}
		var name string
		err := q.QueryRow(`SELECT name FROM main.sqlite_schema WHERE name=? COLLATE NOCASE AND type IN ('table','view')`, table).Scan(&name)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		existing.Tables = append(existing.Tables, table)
	}
	return existing, nil
}

// Refresh only one table, preserving every other active versioning policy.
// Runtime callers must supply the app's encryption configuration.
func installVersioningForTable(db *sql.DB, table string, encryption ...*EncryptedFieldConfig) (int, error) {
	var encrypted *EncryptedFieldConfig
	if len(encryption) != 0 {
		encrypted = encryption[0]
	}
	key := cryptoKeyForQuerier(db)
	tx, err := db.BeginTx(withLongWriteTx(context.Background(), "versioning install "+table), nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err := installVersioningForTableTx(tx, table, encrypted, nil, key); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return 2, nil
}

// computed supplies the table's derived columns (withComputedVersionMaintenance).
func installVersioningForTableTx(tx *sql.Tx, table string, encrypted *EncryptedFieldConfig, computed *ComputedFieldConfig, key []byte) error {
	if err := configIdentError("versioned table", table); err != nil {
		return err
	}
	if encrypted != nil {
		if _, err := tx.Exec("PRAGMA secure_delete=ON"); err != nil {
			return err
		}
	}
	for _, op := range []string{"update", "delete"} {
		if _, err := tx.Exec("DROP TRIGGER IF EXISTS " + quoteIdent("_benmore_ver_"+table+"_"+op)); err != nil {
			return err
		}
	}
	if err := reconcileVersionedTable(tx, table, encrypted, computedExprColumns(computed, table)); err != nil {
		return err
	}
	if encrypted != nil {
		cols, err := mainTableColumnsWith(tx, table+"_history")
		if err != nil {
			return err
		}
		for source, defs := range encrypted.Fields {
			if !strings.EqualFold(source, table) {
				continue
			}
			for _, def := range defs {
				if !versionHasColumn(cols, def.Column) {
					continue
				}
				if len(key) != 32 {
					return fmt.Errorf("versioning %s: encryption key unavailable", table)
				}
				if err := repairVersionedColumn(tx, source, def.Column, key); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func versionHasColumn(cols []Column, name string) bool {
	for _, c := range cols {
		if strings.EqualFold(c.Name, name) {
			return true
		}
	}
	return false
}

// Refuse to repurpose a same-named app table/view as framework history.
func versionHistoryExists(q mutationQuerier, history string) (bool, error) {
	var kind, ddl string
	err := q.QueryRow(`SELECT type, COALESCE(sql,'') FROM main.sqlite_schema WHERE name=? COLLATE NOCASE`, history).Scan(&kind, &ddl)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if kind != "table" || strings.Contains(strings.ToUpper(ddl), "CREATE VIRTUAL TABLE") || strings.Contains(strings.ToUpper(ddl), "WITHOUT ROWID") {
		return false, fmt.Errorf("history object %s is not an ordinary rowid table", history)
	}
	cols, err := mainTableColumnsWith(q, history)
	if err != nil {
		return false, err
	}
	metadata := 0
	for _, name := range versionMetadataColumns {
		if versionHasColumn(cols, name) {
			metadata++
		}
	}
	if metadata == 0 {
		return false, nil
	} // same-named application table, not retained framework history
	if !versionHasColumn(cols, "id") {
		return false, fmt.Errorf("history table %s lacks id", history)
	}
	if _, err := versionHistoryRowID(cols); err != nil {
		return false, err
	}
	for _, name := range versionMetadataColumns {
		if !versionHasColumn(cols, name) {
			return false, fmt.Errorf("history table %s lacks metadata column %s", history, name)
		}
	}
	var count int
	if err := q.QueryRow(`SELECT count(*) FROM main.sqlite_schema WHERE type='trigger' AND tbl_name=? COLLATE NOCASE`, history).Scan(&count); err != nil {
		return false, err
	}
	if count != 0 {
		return false, fmt.Errorf("history table %s has unsupported triggers", history)
	}
	return true, nil
}

func versionSQLLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// versionUpdateWhen builds the history UPDATE trigger's WHEN clause. A version
// is the state a user write replaced, so an UPDATE that changes no content is
// skipped when it is storage maintenance:
//
//   - every content column is unchanged (unchanged), and
//   - at least one maintenance column changed (normalized: encryption
//     normalization, blind-index siblings, computed recalculation), or the
//     row's updated_at moved to an instant the recorded history already
//     covers (stamp, compared with latestEnd, the newest version's end).
//
// The second rule is the Prisma @updatedAt touch: a raw UPDATE that leaves
// updated_at alone is versioned, then the trigger rewrites updated_at, and
// that second write used to record a version holding the new content with
// the old timestamp. A covered timestamp proves nothing is lost: point-in-time
// reads serve the current row from the newest boundary on. A timestamp-only
// write past that boundary (an explicit touch) still records a version, so
// the earlier interval keeps its state. Without maintenance columns or an
// updated_at column the trigger has no WHEN, as before.
func versionUpdateWhen(unchanged, normalized []string, stamp, latestEnd string) string {
	content := "1"
	if len(unchanged) != 0 {
		content = "(" + strings.Join(unchanged, " AND ") + ")"
	}
	if stamp == "" {
		if len(normalized) == 0 {
			return ""
		}
		return " WHEN NOT (" + content + " AND (" + strings.Join(normalized, " OR ") + "))"
	}
	newStamp := "NEW." + quoteIdent(stamp)
	covered := "benmore_history_covers(" + latestEnd + ", " + newStamp + ")"
	still := "(OLD." + quoteIdent(stamp) + " IS " + newStamp + " OR " + covered + ")"
	maintenance := append(append([]string(nil), normalized...), covered)
	return " WHEN NOT (" + content + " AND " + still + " AND (" + strings.Join(maintenance, " OR ") + "))"
}

// derived names the table's same-row computed columns; their recalculation
// is storage maintenance (see the WHEN clause below).
func reconcileVersionedTable(tx *sql.Tx, table string, encrypted *EncryptedFieldConfig, derived []string) error {
	cols, err := mainTableColumnsWith(tx, table)
	if err != nil {
		return err
	}
	if len(cols) == 0 || !versionHasColumn(cols, "id") {
		return errors.New("source table is missing or lacks id")
	}
	for _, name := range versionMetadataColumns {
		if versionHasColumn(cols, name) {
			return fmt.Errorf("source column %s conflicts with history metadata", name)
		}
	}
	history := table + "_history"
	exists, err := versionHistoryExists(tx, history)
	if err != nil {
		return err
	}
	var names, defs []string
	for _, col := range cols {
		names = append(names, quoteIdent(col.Name))
		defs = append(defs, strings.TrimSpace(quoteIdent(col.Name)+" "+quoteDeclType(col.Type)))
	}
	if !exists {
		defs = append(defs, `_version INTEGER NOT NULL`, `_valid_from DATETIME NOT NULL`, `_valid_to DATETIME NOT NULL DEFAULT (datetime('now'))`, `_changed_by INTEGER`, `_change_type TEXT NOT NULL`)
		if _, err := tx.Exec("CREATE TABLE " + quoteIdent(history) + " (" + strings.Join(defs, ", ") + ")"); err != nil {
			return err
		}
	} else {
		historyCols, err := mainTableColumnsWith(tx, history)
		if err != nil {
			return err
		}
		for i, col := range cols {
			if !versionHasColumn(historyCols, col.Name) {
				if _, err := tx.Exec("ALTER TABLE " + quoteIdent(history) + " ADD COLUMN " + defs[i]); err != nil {
					return err
				}
			}
		}
	}
	if _, err := tx.Exec("CREATE INDEX IF NOT EXISTS " + quoteIdent("idx_"+history+"_id_version") + " ON " + quoteIdent(history) + " (id, _version)"); err != nil {
		return err
	}
	encCols := map[string]string{}
	blindCols := map[string]bool{}
	aadTable := table
	if encrypted != nil {
		for name, fields := range encrypted.Fields {
			if strings.EqualFold(name, table) {
				aadTable = name
				for _, field := range fields {
					encCols[sqliteIdentifierFold(field.Column)] = field.Column
					if field.BlindIndex {
						blindCols[sqliteIdentifierFold(field.Column+blindColSuffix)] = true
					}
				}
			}
		}
	}
	derivedCols := map[string]bool{}
	for _, name := range derived {
		derivedCols[sqliteIdentifierFold(name)] = true
	}
	// The Prisma @updatedAt trigger rewrites updated_at after any UPDATE that
	// left it alone, including the framework's own maintenance writes. It is
	// judged separately below rather than as content.
	stamp := ""
	var oldRefs, unchanged, normalized []string
	for _, col := range cols {
		old, next := "OLD."+quoteIdent(col.Name), "NEW."+quoteIdent(col.Name)
		equal := old + " IS " + next
		if aadColumn, ok := encCols[sqliteIdentifierFold(col.Name)]; ok {
			oldRefs = append(oldRefs, "benmore_history_encrypt("+old+", "+versionSQLLiteral(aadTable)+", "+versionSQLLiteral(aadColumn)+")")
			if derivedCols[sqliteIdentifierFold(col.Name)] {
				// A computed column that is also encrypted is sealed by its
				// own trigger (computedSeal): its recalculation is storage
				// maintenance, as for a plain computed column below.
				normalized = append(normalized, "("+old+" IS NOT "+next+")")
				continue
			}
			// The encryption AFTER trigger performs a second UPDATE. That storage
			// normalization is not another user version (including on INSERT).
			norm := "benmore_history_normalized(" + old + ", " + next + ", " + versionSQLLiteral(aadTable) + ", " + versionSQLLiteral(aadColumn) + ")"
			unchanged = append(unchanged, "("+equal+" OR "+norm+")")
			normalized = append(normalized, norm)
		} else {
			oldRefs = append(oldRefs, old)
			switch {
			case blindCols[sqliteIdentifierFold(col.Name)], derivedCols[sqliteIdentifierFold(col.Name)]:
				// A derived blind-index write is storage maintenance too, and so
				// is a computed field's recalculation: the expression's inputs
				// are content, and the user's own write already recorded them.
				normalized = append(normalized, "("+old+" IS NOT "+next+")")
			case sqliteIdentifierFold(col.Name) == "updated_at":
				stamp = col.Name
			default:
				unchanged = append(unchanged, "("+equal+")")
			}
		}
	}
	// Chain retained boundaries; a maintenance trigger can have regressed the
	// source's updated_at, and imported/retained history is never rewritten.
	previous := func(column string) string {
		return "(SELECT " + column + " FROM " + quoteIdent(history) + " WHERE id=OLD.id ORDER BY _version DESC LIMIT 1)"
	}
	sourceDate := func(prefix, column string) string {
		if versionHasColumn(cols, column) {
			return prefix + "." + quoteIdent(column)
		}
		return "NULL"
	}
	validFrom := "benmore_history_start(" + previous("_valid_from") + ", " + previous("_valid_to") + ", " + sourceDate("OLD", "updated_at") + ", " + sourceDate("OLD", "created_at") + ")"
	version := "(SELECT COALESCE(MAX(_version), 0) + 1 FROM " + quoteIdent(history) + " WHERE id = OLD.id)"
	for _, op := range []string{"update", "delete"} {
		candidate := "NULL"
		if op == "update" {
			candidate = sourceDate("NEW", "updated_at")
		}
		validTo := "benmore_history_end(boundary.start, " + candidate + ")"
		when := ""
		if op == "update" {
			when = versionUpdateWhen(unchanged, normalized, stamp, previous("_valid_to"))
		}
		// MATERIALIZED prevents SQLite from evaluating the start clock twice
		// when a table has no source/retained timestamps, including clock rollback.
		boundary := "(WITH captured AS MATERIALIZED (SELECT " + validFrom + " AS start) SELECT start FROM captured) AS boundary"
		ddl := "CREATE TRIGGER " + quoteIdent("_benmore_ver_"+table+"_"+op) + " BEFORE " + strings.ToUpper(op) + " ON " + quoteIdent(table) + " FOR EACH ROW" + when + " BEGIN INSERT INTO " + quoteIdent(history) + " (" + strings.Join(names, ", ") + ", _version, _valid_from, _valid_to, _change_type) SELECT " + strings.Join(oldRefs, ", ") + ", " + version + ", boundary.start, " + validTo + ", '" + op + "' FROM " + boundary + "; END"
		if _, err := tx.Exec(ddl); err != nil {
			return err
		}
	}
	// CREATE TRIGGER defers name/function resolution. Compile both programs now,
	// without executing any app mutation, so a broken history never goes live.
	for _, query := range []string{"EXPLAIN UPDATE " + quoteIdent(table) + " SET id=id WHERE 0", "EXPLAIN DELETE FROM " + quoteIdent(table) + " WHERE 0"} {
		rows, err := tx.Query(query)
		if err != nil {
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	return nil
}

func sealVersionedValue(value any, key []byte, source, column string) (any, error) {
	// go-sqlite3 passes SQL NULL to generic callbacks as a nil []byte.
	if versionedValueIsNull(value) {
		return nil, nil
	}
	if len(key) != 32 {
		return nil, errors.New("history encryption key unavailable")
	}
	raw := stringifyForCrypto(value)
	plain, sealed, err := appEncryptionRotationOpen(raw, key, source, column)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext in history field %s.%s: %w", source, column, err)
	}
	if sealed && strings.HasPrefix(raw, encPrefixV2) {
		return raw, nil
	}
	if !sealed {
		plain = raw
	}
	return fieldEncryptCtx(key, source, column, plain)
}

func repairVersionedColumn(tx *sql.Tx, source, column string, key []byte) error {
	history := source + "_history"
	cols, err := mainTableColumnsWith(tx, history)
	if err != nil {
		return err
	}
	identity, err := versionHistoryRowID(cols)
	if err != nil {
		return err
	}
	rowID := quoteIdent(identity)
	// Keyset chunks bound memory and release cursors before writes on a single
	// SQLite connection. rowid starts at MinInt64 so imported negative IDs count.
	cursor := int64(-1 << 63)
	first := true
	for {
		comparator := ">"
		if first {
			comparator = ">="
			first = false
		}
		rows, err := tx.Query("SELECT "+rowID+", "+quoteColumn(history, column)+" FROM "+quoteIdent(history)+" WHERE "+rowID+" "+comparator+" ? AND "+quoteColumn(history, column)+" IS NOT NULL ORDER BY "+rowID+" LIMIT 256", cursor)
		if err != nil {
			return err
		}
		type cell struct {
			id    int64
			value any
		}
		var cells []cell
		for rows.Next() {
			var c cell
			if err := rows.Scan(&c.id, &c.value); err != nil {
				rows.Close()
				return err
			}
			cells = append(cells, c)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return err
		}
		if len(cells) == 0 {
			return nil
		}
		for _, c := range cells {
			sealed, err := sealVersionedValue(c.value, key, source, column)
			if err != nil {
				return fmt.Errorf("repair %s.%s rowid %d: %w", history, column, c.id, err)
			}
			if stringifyForCrypto(sealed) != stringifyForCrypto(c.value) {
				if _, err := tx.Exec("UPDATE "+quoteIdent(history)+" SET "+quoteIdent(column)+"=? WHERE "+rowID+"=?", sealed, c.id); err != nil {
					return err
				}
			}
			cursor = c.id
		}
	}
}

// Suspension and restoration happen in the rotation's own transaction. No
// source write may append history encrypted under the old key during rotation.
func suspendVersioningTriggers(tx *sql.Tx) ([]string, error) {
	rows, err := tx.Query(`SELECT name,sql FROM main.sqlite_schema WHERE type='trigger' AND substr(name,1,13)='_benmore_ver_' ORDER BY name`)
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

// suspendEncryptionTriggers keeps field-authentication triggers from rewriting
// freshly re-sealed values with the old process key during atomic key rotation.
// Rotation explicitly encrypts every configured value before restoring these
// triggers, and the transaction holds SQLite's write lock for the whole swap.
func suspendEncryptionTriggers(tx *sql.Tx) ([]string, error) {
	rows, err := tx.Query(`SELECT name,sql FROM main.sqlite_schema WHERE type='trigger' AND substr(name,1,13)='_benmore_enc_' ORDER BY name`)
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

// suspendRowMaintenanceTriggers keeps storage maintenance from reading as an
// edit of the row. The Prisma @updatedAt trigger stamps every UPDATE that
// leaves updated_at alone, and the computed-field triggers (_benmore_cf_)
// recalculate on every UPDATE; an aggregate rewrites its parent row, which
// stamps the parent too. Re-sealing a value under a new key or writing a
// blind-index sibling changes neither the plaintext nor anything a computed
// field can meaningfully derive from it, yet key rotation used to move
// updated_at on every encrypted row: ?as_of= before the rotation found no
// state for unedited rows and _expected_updated_at read before it got 409.
//
// Only the exact generated @updatedAt definitions are suspended; an app's own
// trigger keeps firing. The caller drops and restores inside one write
// transaction (SQLite's write lock is held throughout, so no other writer runs
// without them) and reseats connector revision triggers before committing.
// The returned DDL restores @updatedAt triggers before computed ones, the
// order a load creates them in.
func suspendRowMaintenanceTriggers(tx *sql.Tx) ([]string, error) {
	rows, err := tx.Query(`SELECT name,tbl_name,sql FROM main.sqlite_schema WHERE type='trigger' AND (substr(name,1,12)='_benmore_cf_' OR substr(name,1,4)='trg_') ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var names, stamps, computed []string
	for rows.Next() {
		var name, table string
		var ddl sql.NullString
		if err := rows.Scan(&name, &table, &ddl); err != nil {
			rows.Close()
			return nil, err
		}
		if strings.TrimSpace(ddl.String) == "" {
			continue // nothing to restore it from: leave it in place
		}
		if strings.HasPrefix(name, "_benmore_cf_") {
			names, computed = append(names, name), append(computed, ddl.String)
			continue
		}
		column, onTable := strings.CutPrefix(name, "trg_"+table+"_")
		column, stamp := strings.CutSuffix(column, "_updated")
		if !onTable || !stamp || column == "" {
			continue
		}
		stored := normalizePrismaUpdatedAtSQL(ddl.String)
		if stored == normalizePrismaUpdatedAtSQL(prismaUpdatedAtTriggerSQL(table, column)) || stored == normalizePrismaUpdatedAtSQL(legacyPrismaUpdatedAtTriggerSQL(table, column)) {
			names, stamps = append(names, name), append(stamps, ddl.String)
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	for _, name := range names {
		if _, err := tx.Exec("DROP TRIGGER " + quoteIdent(name)); err != nil {
			return nil, err
		}
	}
	return append(stamps, computed...), nil
}

func restoreRowMaintenanceTriggers(tx *sql.Tx, ddls []string) error {
	for _, ddl := range ddls {
		if _, err := tx.Exec(ddl); err != nil {
			return err
		}
	}
	return nil
}

func restoreEncryptionTriggers(tx *sql.Tx, ddls []string) error {
	for _, ddl := range ddls {
		if _, err := tx.Exec(ddl); err != nil {
			return err
		}
	}
	return nil
}

func restoreVersioningTriggers(tx *sql.Tx, ddls []string) error {
	for _, ddl := range ddls {
		if _, err := tx.Exec(ddl); err != nil {
			return err
		}
	}
	return nil
}

// Include legacy plaintext defensively as well as sealed historical values.
func versionedRotationRowIDsSQL(table, column, rowID string) string {
	return "SELECT " + quoteIdent(rowID) + " FROM " + quoteIdent(table) + " WHERE " + quoteColumn(table, column) + " IS NOT NULL"
}

func versionHistoryRowID(cols []Column) (string, error) {
	for _, name := range []string{"rowid", "_rowid_", "oid"} {
		if !versionHasColumn(cols, name) {
			return name, nil
		}
	}
	return "", errors.New("history table shadows every SQLite row identity")
}

// Compare canonical crypto scalars rather than SQLite CAST(... AS TEXT), which
// renders whole-valued REALs as "1.0" while encryption canonicalizes them to "1".
func versionedStorageNormalization(old, next any, key []byte, table, column string) (bool, error) {
	if versionedValueIsNull(old) || versionedValueIsNull(next) {
		return false, nil
	}
	original, replacement := stringifyForCrypto(old), stringifyForCrypto(next)
	if strings.HasPrefix(original, "enc:") || !cryptoIsEncrypted(replacement) {
		return false, nil
	}
	plain, sealed, err := appEncryptionRotationOpen(replacement, key, table, column)
	if err != nil {
		return false, err
	}
	return sealed && plain == original, nil
}

func versionedValueIsNull(value any) bool {
	if value == nil {
		return true
	}
	bytes, ok := value.([]byte)
	return ok && bytes == nil
}
