//go:build !cli

package main

import (
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
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := installVersioningTriggersTx(tx, config, encrypted, key); err != nil {
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
			if err := reconcileVersionedTable(tx, table, encrypted); err != nil {
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
	var existing *VersionedConfig
	if config != nil {
		existing = &VersionedConfig{}
		for _, table := range config.Tables {
			if err := configIdentError("app.yaml: versioned table", table); err != nil {
				return err
			}
			var name string
			err := db.QueryRow(`SELECT name FROM main.sqlite_schema WHERE name=? COLLATE NOCASE AND type IN ('table','view')`, table).Scan(&name)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			existing.Tables = append(existing.Tables, table)
		}
	}
	return InstallVersioningTriggers(db, existing, encrypted)
}

// Refresh only one table, preserving every other active versioning policy.
// Runtime callers must supply the app's encryption configuration.
func installVersioningForTable(db *sql.DB, table string, encryption ...*EncryptedFieldConfig) (int, error) {
	var encrypted *EncryptedFieldConfig
	if len(encryption) != 0 {
		encrypted = encryption[0]
	}
	key := cryptoKeyForQuerier(db)
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err := installVersioningForTableTx(tx, table, encrypted, key); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return 2, nil
}

func installVersioningForTableTx(tx *sql.Tx, table string, encrypted *EncryptedFieldConfig, key []byte) error {
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
	if err := reconcileVersionedTable(tx, table, encrypted); err != nil {
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

func reconcileVersionedTable(tx *sql.Tx, table string, encrypted *EncryptedFieldConfig) error {
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
	var oldRefs, unchanged, normalized []string
	for _, col := range cols {
		old, next := "OLD."+quoteIdent(col.Name), "NEW."+quoteIdent(col.Name)
		equal := old + " IS " + next
		if aadColumn, ok := encCols[sqliteIdentifierFold(col.Name)]; ok {
			oldRefs = append(oldRefs, "benmore_history_encrypt("+old+", "+versionSQLLiteral(aadTable)+", "+versionSQLLiteral(aadColumn)+")")
			// The encryption AFTER trigger performs a second UPDATE. That storage
			// normalization is not another user version (including on INSERT).
			norm := "benmore_history_normalized(" + old + ", " + next + ", " + versionSQLLiteral(aadTable) + ", " + versionSQLLiteral(aadColumn) + ")"
			unchanged = append(unchanged, "("+equal+" OR "+norm+")")
			normalized = append(normalized, norm)
		} else {
			oldRefs = append(oldRefs, old)
			if blindCols[sqliteIdentifierFold(col.Name)] {
				// A derived blind-index write is storage maintenance too.
				normalized = append(normalized, "("+old+" IS NOT "+next+")")
			} else {
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
		if op == "update" && len(normalized) != 0 {
			when = " WHEN NOT ((" + strings.Join(unchanged, " AND ") + ") AND (" + strings.Join(normalized, " OR ") + "))"
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
