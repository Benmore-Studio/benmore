//go:build !cli

package main

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

type appEncryptionRowRotationCounts struct {
	ConfiguredValues, TOTPSecrets, OAuthValues, WebhookSecrets, BlindValues int
}

type appEncryptionRotationCell struct {
	table, column, rowIDColumn string
	rowID                      int64
	original, originalType     any
	blindColumn                string
	originalBlind, blindType   any
	writeCipher                bool
	newCipher                  string
	writeBlind                 bool
	newBlind                   any
	family                     string
}

type appEncryptionRotationTarget struct {
	table, aadTable, aadColumn, column, blindColumn, rowIDColumn, family string
}

type appEncryptionRotationTable struct {
	name, objectType, tableKind string
	withoutRowID                bool
	columns                     map[string]appEncryptionRotationColumn
}

type appEncryptionRotationColumn struct {
	name, declaredType string
	primaryKey         bool
	hidden             int
}

// rotateAppEncryptionRowsTx prepares every supported ciphertext/blind value
// before its first write. The caller owns tx commit or rollback.
func rotateAppEncryptionRowsTx(ctx context.Context, tx *sql.Tx, config *EncryptedFieldConfig, oldKey, newKey []byte) (appEncryptionRowRotationCounts, error) {
	var zero appEncryptionRowRotationCounts
	if ctx == nil || tx == nil || len(oldKey) != 32 || len(newKey) != 32 || subtle.ConstantTimeCompare(oldKey, newKey) == 1 {
		return zero, errors.New("invalid encryption rotation context, transaction, or key pair")
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	q := appMCPContextTx{tx: tx, ctx: ctx, private: true}
	if err := q.cleanMain(); err != nil {
		return zero, fmt.Errorf("rotation database isolation check failed: %w", err)
	}
	if err := appEncryptionRotationRequireNoTriggers(ctx, tx); err != nil {
		return zero, err
	}
	var foreignKeys int
	if err := tx.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil || foreignKeys != 1 {
		return zero, errors.New("rotation requires SQLite foreign-key enforcement")
	}

	tables, err := appEncryptionRotationReadTables(ctx, tx)
	if err != nil {
		return zero, err
	}
	targets, err := appEncryptionRotationTargets(config, tables)
	if err != nil {
		return zero, err
	}
	fkTargets := append([]appEncryptionRotationTarget(nil), targets...)
	if table, ok := tables[sqliteIdentifierFold(totpSecretTable)]; ok {
		if table.objectType != "table" {
			return zero, errors.New("incompatible TOTP storage object")
		}
		if err := appEncryptionRotationValidateTOTPTable(ctx, tx); err != nil {
			return zero, err
		}
		if _, ok := table.columns[sqliteIdentifierFold(totpSecretColumn)]; ok {
			fkTargets = append(fkTargets, appEncryptionRotationTarget{table: table.name, column: totpSecretColumn})
		}
	}
	if err := appEncryptionRotationCheckForeignKeys(ctx, tx, tables, fkTargets); err != nil {
		return zero, err
	}

	blindKey, err := DeriveBlindIndexKey(newKey)
	if err != nil {
		return zero, errors.New("could not derive rotation blind-index key")
	}
	cells := make([]appEncryptionRotationCell, 0)
	counts := appEncryptionRowRotationCounts{}
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		part, err := appEncryptionRotationInventory(ctx, tx, target, oldKey, newKey, blindKey)
		if err != nil {
			return zero, fmt.Errorf("rotation inventory for %s.%s failed: %w", target.table, target.column, err)
		}
		cells = append(cells, part...)
	}
	totpRows, err := collectTOTPSecretRotations(ctx, tx, oldKey, newKey)
	if err != nil {
		return zero, err
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if err := appEncryptionRotationRequireNoTriggers(ctx, tx); err != nil {
		return zero, err
	}

	for _, cell := range cells {
		if err := appEncryptionRotationCASWrite(ctx, tx, cell); err != nil {
			return zero, fmt.Errorf("rotation compare-and-swap failed for %s.%s: %w", cell.table, cell.column, err)
		}
		switch cell.family {
		case "configured", "history":
			if cell.writeCipher {
				counts.ConfiguredValues++
			}
		case "oauth":
			counts.OAuthValues++
		case "webhook":
			counts.WebhookSecrets++
		}
		if cell.writeBlind {
			counts.BlindValues++
		}
	}
	if len(totpRows) != 0 {
		n, err := applyTOTPSecretRotationsContextTx(ctx, tx, totpRows)
		if err != nil {
			return zero, err
		}
		counts.TOTPSecrets = n
	}
	if err := appEncryptionRotationRequireNoTriggers(ctx, tx); err != nil {
		return zero, err
	}
	return counts, nil
}

func appEncryptionRotationTargets(config *EncryptedFieldConfig, tables map[string]appEncryptionRotationTable) ([]appEncryptionRotationTarget, error) {
	var targets []appEncryptionRotationTarget
	seen := map[string]bool{}
	fixed := map[string]string{
		"_benmore_users\x00totp_secret":          "TOTP",
		"_benmore_oauth_tokens\x00access_token":  "OAuth",
		"_benmore_oauth_tokens\x00refresh_token": "OAuth",
		"_benmore_webhooks\x00secret":            "webhook",
	}
	if config != nil {
		tableNames := make([]string, 0, len(config.Fields))
		for table := range config.Fields {
			tableNames = append(tableNames, table)
		}
		sort.Strings(tableNames)
		seenTables := map[string]bool{}
		for _, tableName := range tableNames {
			if !isValidColumnName(tableName) {
				return nil, errors.New("encrypted configuration contains an invalid table identifier")
			}
			foldedTable := sqliteIdentifierFold(tableName)
			if seenTables[foldedTable] {
				return nil, errors.New("encrypted configuration contains ambiguous table names")
			}
			seenTables[foldedTable] = true
			table, ok := tables[foldedTable]
			if !ok {
				return nil, fmt.Errorf("configured encrypted table %q is missing", tableName)
			}
			if table.objectType != "table" {
				return nil, fmt.Errorf("configured encrypted object %q is not a table", tableName)
			}
			rowID, err := appEncryptionRotationRowID(table)
			if err != nil {
				return nil, err
			}
			for _, existing := range table.columns {
				if existing.hidden != 0 {
					return nil, fmt.Errorf("generated or hidden columns are unsupported in rotation table %s", table.name)
				}
			}
			defs := config.Fields[tableName]
			for _, def := range defs {
				if !isValidColumnName(def.Column) {
					return nil, errors.New("encrypted configuration contains an invalid column identifier")
				}
				column, ok := table.columns[sqliteIdentifierFold(def.Column)]
				if !ok || column.hidden != 0 {
					return nil, fmt.Errorf("configured encrypted column %s.%s is missing or generated", table.name, def.Column)
				}
				if column.primaryKey {
					return nil, fmt.Errorf("primary-key encryption target is unsupported: %s.%s", table.name, column.name)
				}
				key := sqliteIdentifierFold(table.name) + "\x00" + sqliteIdentifierFold(column.name)
				if seen[key] || fixed[key] != "" {
					return nil, fmt.Errorf("ambiguous encrypted rotation target %s.%s", table.name, column.name)
				}
				seen[key] = true
				blindColumn := ""
				if def.BlindIndex {
					blindColumn = column.name + blindColSuffix
					blind, ok := table.columns[sqliteIdentifierFold(blindColumn)]
					if !ok || blind.hidden != 0 || blind.primaryKey || !strings.EqualFold(strings.TrimSpace(blind.declaredType), "TEXT") {
						return nil, fmt.Errorf("blind-index sibling %s.%s is missing or incompatible", table.name, blindColumn)
					}
					blindKey := sqliteIdentifierFold(table.name) + "\x00" + sqliteIdentifierFold(blind.name)
					if seen[blindKey] || fixed[blindKey] != "" {
						return nil, fmt.Errorf("ambiguous blind-index rotation target %s.%s", table.name, blind.name)
					}
					seen[blindKey] = true
				}
				targets = append(targets, appEncryptionRotationTarget{table: table.name, aadTable: tableName, aadColumn: def.Column, column: column.name, blindColumn: blindColumn, rowIDColumn: rowID, family: "configured"})
			}
		}
	}
	// Version snapshots use the source field's AAD, including retained history
	// after versioning is disabled. They must move with the source key.
	for _, source := range append([]appEncryptionRotationTarget(nil), targets...) {
		history, ok := tables[sqliteIdentifierFold(source.table+"_history")]
		if !ok {
			continue
		}
		metadata := 0
		for _, name := range versionMetadataColumns {
			if _, ok := history.columns[sqliteIdentifierFold(name)]; ok {
				metadata++
			}
		}
		if metadata == 0 {
			continue
		}
		if metadata != len(versionMetadataColumns) {
			return nil, fmt.Errorf("incomplete history metadata for %s", history.name)
		}
		rowID, err := appEncryptionRotationRowID(history)
		if err != nil {
			return nil, err
		}
		column, ok := history.columns[sqliteIdentifierFold(source.column)]
		if !ok {
			continue
		}
		if column.hidden != 0 || column.primaryKey {
			return nil, fmt.Errorf("incompatible encrypted history column %s.%s", history.name, column.name)
		}
		key := sqliteIdentifierFold(history.name) + "\x00" + sqliteIdentifierFold(column.name)
		if seen[key] {
			return nil, fmt.Errorf("ambiguous encrypted history target %s.%s", history.name, column.name)
		}
		seen[key] = true
		targets = append(targets, appEncryptionRotationTarget{table: history.name, aadTable: source.aadTable, aadColumn: source.aadColumn, column: column.name, rowIDColumn: rowID, family: "history"})
	}
	for _, spec := range []struct{ table, column, family string }{
		{"_benmore_oauth_tokens", "access_token", "oauth"},
		{"_benmore_oauth_tokens", "refresh_token", "oauth"},
		{"_benmore_webhooks", "secret", "webhook"},
	} {
		if table, ok := tables[sqliteIdentifierFold(spec.table)]; ok {
			if table.objectType != "table" {
				return nil, fmt.Errorf("optional %s storage object is not a table", spec.family)
			}
			rowID, err := appEncryptionRotationRowID(table)
			if err != nil {
				return nil, err
			}
			for _, existing := range table.columns {
				if existing.hidden != 0 {
					return nil, fmt.Errorf("generated or hidden columns are unsupported in rotation table %s", table.name)
				}
			}
			col, found := table.columns[sqliteIdentifierFold(spec.column)]
			if !found || col.hidden != 0 || col.primaryKey || !strings.EqualFold(strings.TrimSpace(col.declaredType), "TEXT") {
				return nil, fmt.Errorf("optional %s storage table has an incompatible %s column", spec.family, spec.column)
			}
			idColumn, hasID := table.columns[sqliteIdentifierFold("id")]
			if !hasID || !idColumn.primaryKey || !strings.Contains(strings.ToUpper(idColumn.declaredType), "INT") {
				return nil, fmt.Errorf("optional %s storage table lacks its native id column", spec.family)
			}
			targets = append(targets, appEncryptionRotationTarget{table: table.name, aadTable: "", aadColumn: "", column: col.name, rowIDColumn: rowID, family: spec.family})
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].table != targets[j].table {
			return targets[i].table < targets[j].table
		}
		return targets[i].column < targets[j].column
	})
	return targets, nil
}

func appEncryptionRotationReadTables(ctx context.Context, tx *sql.Tx) (map[string]appEncryptionRotationTable, error) {
	type tableMeta struct {
		kind         string
		withoutRowID bool
	}
	kinds := map[string]tableMeta{}
	kindRows, err := tx.QueryContext(ctx, "PRAGMA main.table_list")
	if err != nil {
		return nil, err
	}
	for kindRows.Next() {
		var schema, name, kind string
		var columnCount, withoutRowID, strict int
		if err := kindRows.Scan(&schema, &name, &kind, &columnCount, &withoutRowID, &strict); err != nil {
			kindRows.Close()
			return nil, err
		}
		if strings.EqualFold(schema, "main") {
			kinds[sqliteIdentifierFold(name)] = tableMeta{kind: kind, withoutRowID: withoutRowID != 0}
		}
	}
	if err := kindRows.Err(); err != nil {
		kindRows.Close()
		return nil, err
	}
	if err := kindRows.Close(); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT type, name FROM main.sqlite_schema WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY name")
	if err != nil {
		return nil, err
	}
	var list []appEncryptionRotationTable
	for rows.Next() {
		var table appEncryptionRotationTable
		if err := rows.Scan(&table.objectType, &table.name); err != nil {
			rows.Close()
			return nil, err
		}
		if !isValidColumnName(table.name) {
			rows.Close()
			return nil, errors.New("main schema contains an unsupported table identifier")
		}
		if meta, ok := kinds[sqliteIdentifierFold(table.name)]; ok {
			table.tableKind, table.withoutRowID = meta.kind, meta.withoutRowID
		}
		list = append(list, table)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	out := make(map[string]appEncryptionRotationTable, len(list))
	for i := range list {
		if err := appEncryptionRotationLoadColumns(ctx, tx, &list[i]); err != nil {
			return nil, err
		}
		out[sqliteIdentifierFold(list[i].name)] = list[i]
	}
	return out, nil
}

func appEncryptionRotationLoadColumns(ctx context.Context, tx *sql.Tx, table *appEncryptionRotationTable) error {
	rows, err := tx.QueryContext(ctx, "PRAGMA main.table_xinfo("+quoteIdent(table.name)+")")
	if err != nil {
		return err
	}
	columns := map[string]appEncryptionRotationColumn{}
	for rows.Next() {
		var cid, notNull, pk, hidden int
		var name, declared string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &declared, &notNull, &defaultValue, &pk, &hidden); err != nil {
			rows.Close()
			return err
		}
		columns[sqliteIdentifierFold(name)] = appEncryptionRotationColumn{name: name, declaredType: declared, primaryKey: pk > 0, hidden: hidden}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(columns) == 0 {
		return fmt.Errorf("table %s has no readable columns", table.name)
	}
	table.columns = columns
	return nil
}

func appEncryptionRotationCheckForeignKeys(ctx context.Context, tx *sql.Tx, tables map[string]appEncryptionRotationTable, targets []appEncryptionRotationTarget) error {
	byColumn := map[string]bool{}
	for _, target := range targets {
		byColumn[sqliteIdentifierFold(target.table)+"\x00"+sqliteIdentifierFold(target.column)] = true
		if target.blindColumn != "" {
			byColumn[sqliteIdentifierFold(target.table)+"\x00"+sqliteIdentifierFold(target.blindColumn)] = true
		}
	}
	for _, table := range tables {
		if table.objectType != "table" {
			continue
		}
		rows, err := tx.QueryContext(ctx, "PRAGMA main.foreign_key_list("+quoteIdent(table.name)+")")
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, seq int
			var parent, from, onUpdate, onDelete, match string
			var to sql.NullString
			if err := rows.Scan(&id, &seq, &parent, &from, &to, &onUpdate, &onDelete, &match); err != nil {
				rows.Close()
				return err
			}
			if byColumn[sqliteIdentifierFold(table.name)+"\x00"+sqliteIdentifierFold(from)] {
				rows.Close()
				return fmt.Errorf("rotation target participates in a foreign key: %s.%s", table.name, from)
			}
			if targetTable, ok := tables[sqliteIdentifierFold(parent)]; ok {
				if !to.Valid || to.String == "" {
					for _, col := range targetTable.columns {
						if col.primaryKey && byColumn[sqliteIdentifierFold(targetTable.name)+"\x00"+sqliteIdentifierFold(col.name)] {
							rows.Close()
							return fmt.Errorf("rotation target is a referenced foreign key: %s.%s", targetTable.name, col.name)
						}
					}
				} else if byColumn[sqliteIdentifierFold(targetTable.name)+"\x00"+sqliteIdentifierFold(to.String)] {
					rows.Close()
					return fmt.Errorf("rotation target is a referenced foreign key: %s.%s", targetTable.name, to.String)
				}
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	return nil
}

func appEncryptionRotationInventory(ctx context.Context, tx *sql.Tx, target appEncryptionRotationTarget, oldKey, newKey, blindKey []byte) ([]appEncryptionRotationCell, error) {
	table := target.table
	col := target.column
	rowID := target.rowIDColumn
	query := "SELECT " + quoteIdent(rowID) + ", " + quoteIdent(col) + ", typeof(" + quoteIdent(col) + ")"
	if target.blindColumn != "" {
		query += ", " + quoteIdent(target.blindColumn) + ", typeof(" + quoteIdent(target.blindColumn) + ")"
	}
	query += " FROM main." + quoteIdent(table) + " ORDER BY " + quoteIdent(rowID)
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	var cells []appEncryptionRotationCell
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		cell := appEncryptionRotationCell{table: table, column: col, rowIDColumn: rowID, family: target.family}
		var sourceType string
		if target.blindColumn != "" {
			if err := rows.Scan(&cell.rowID, &cell.original, &sourceType, &cell.originalBlind, &cell.blindType); err != nil {
				rows.Close()
				return nil, err
			}
			cell.blindColumn = target.blindColumn
		} else if err := rows.Scan(&cell.rowID, &cell.original, &sourceType); err != nil {
			rows.Close()
			return nil, err
		}
		cell.originalType = sourceType
		if sourceType != "null" && sourceType != "text" && sourceType != "integer" && sourceType != "real" {
			rows.Close()
			return nil, errors.New("unsupported runtime storage type in encrypted value")
		}
		if (target.family == "oauth" || target.family == "webhook") && sourceType != "null" && sourceType != "text" {
			rows.Close()
			return nil, errors.New("unsupported runtime storage type in framework secret")
		}
		plain, sealed, err := appEncryptionRotationOpen(cell.original, oldKey, target.aadTable, target.aadColumn)
		if err != nil {
			rows.Close()
			return nil, err
		}
		if target.family == "history" && !sealed && cell.original != nil {
			plain = stringifyForCrypto(cell.original)
		}
		if sealed || target.family == "history" && cell.original != nil {
			var cipher string
			// Framework OAuth/webhook consumers use the empty AAD context.
			if target.family == "oauth" || target.family == "webhook" {
				cipher, err = fieldEncryptWithKey(newKey, plain)
			} else {
				cipher, err = fieldEncryptCtx(newKey, target.aadTable, target.aadColumn, plain)
			}
			if err != nil {
				rows.Close()
				return nil, errors.New("could not reseal encrypted value")
			}
			cell.writeCipher, cell.newCipher = true, cipher
		}
		if target.blindColumn != "" {
			blindStorageType, ok := cell.blindType.(string)
			if !ok || blindStorageType != "null" && blindStorageType != "text" {
				rows.Close()
				return nil, errors.New("unsupported stored type in blind-index sibling")
			}
			canonical := plain
			if !sealed {
				if cell.original == nil {
					canonical = ""
				} else {
					var ok bool
					canonical, ok = appEncryptionRotationScalar(cell.original)
					if !ok {
						rows.Close()
						return nil, errors.New("unsupported SQLite scalar in blind-index source")
					}
				}
			}
			var wanted any
			if canonical != "" {
				wanted = BlindIndexHMACWithKey(blindKey, canonical)
			}
			if !appEncryptionRotationSame(cell.originalBlind, wanted) {
				cell.writeBlind, cell.newBlind = true, wanted
			}
		}
		if cell.writeCipher || cell.writeBlind {
			cells = append(cells, cell)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return cells, nil
}

func appEncryptionRotationRowID(table appEncryptionRotationTable) (string, error) {
	if table.objectType != "table" || table.tableKind != "table" || table.withoutRowID {
		return "", fmt.Errorf("unsupported row identity for table %s", table.name)
	}
	for _, name := range []string{"rowid", "_rowid_", "oid"} {
		if _, shadowed := table.columns[sqliteIdentifierFold(name)]; !shadowed {
			return name, nil
		}
	}
	return "", fmt.Errorf("table %s shadows every SQLite rowid alias", table.name)
}

func appEncryptionRotationOpen(value any, key []byte, table, column string) (string, bool, error) {
	stored, ok := value.(string)
	if !ok {
		if b, yes := value.([]byte); yes {
			stored, ok = string(b), true
		}
	}
	if !ok || !strings.HasPrefix(stored, "enc:") {
		return "", false, nil
	}
	if !strings.HasPrefix(stored, encPrefix) && !strings.HasPrefix(stored, encPrefixV2) {
		return "", false, errors.New("encrypted value has an unknown version")
	}
	if strings.HasPrefix(stored, encPrefixV2) {
		body := strings.TrimPrefix(stored, encPrefixV2)
		sep := strings.IndexByte(body, ':')
		if sep < 0 {
			return "", false, errors.New("malformed encrypted value")
		}
		aad, err := hex.DecodeString(body[:sep])
		if err != nil {
			return "", false, errors.New("malformed encrypted value")
		}
		gotTable, gotColumn, ok := cryptoParseAAD(aad)
		if !ok || gotTable != table || gotColumn != column {
			return "", false, errors.New("encrypted value has unexpected authenticated context")
		}
	}
	plain, err := fieldDecryptCtx(key, column, stored)
	if err != nil {
		return "", false, errors.New("encrypted value could not be authenticated")
	}
	return plain, true, nil
}

func appEncryptionRotationScalar(value any) (string, bool) {
	switch value.(type) {
	case string, []byte, int64, int, int32, float64, float32, bool:
		return stringifyForCrypto(value), true
	default:
		return "", false
	}
}

func appEncryptionRotationSame(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	switch x := a.(type) {
	case string:
		y, ok := b.(string)
		return ok && x == y
	case []byte:
		y, ok := b.([]byte)
		return ok && string(x) == string(y)
	case int64:
		y, ok := b.(int64)
		return ok && x == y
	case float64:
		y, ok := b.(float64)
		return ok && x == y
	default:
		return false
	}
}

// appEncryptionRotationCASWrite is the concrete SQL writer used for every
// configured, OAuth, webhook, and blind-index row update.
func appEncryptionRotationCASWrite(ctx context.Context, tx *sql.Tx, cell appEncryptionRotationCell) error {
	if ctx == nil || tx == nil {
		return errors.New("invalid rotation writer transaction")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !isValidColumnName(cell.table) || !isValidColumnName(cell.column) || !isValidColumnName(cell.rowIDColumn) || cell.blindColumn != "" && !isValidColumnName(cell.blindColumn) {
		return errors.New("invalid rotation writer identifier")
	}
	sets, args := []string{}, []any{}
	if cell.writeCipher {
		sets = append(sets, quoteIdent(cell.column)+"=?")
		args = append(args, cell.newCipher)
	}
	if cell.writeBlind {
		sets = append(sets, quoteIdent(cell.blindColumn)+"=?")
		args = append(args, cell.newBlind)
	}
	if len(sets) == 0 {
		return errors.New("rotation writer received an empty update")
	}
	where := quoteIdent(cell.rowIDColumn) + "=? AND " + quoteIdent(cell.column) + " COLLATE BINARY IS ? AND typeof(" + quoteIdent(cell.column) + ")=?"
	args = append(args, cell.rowID, cell.original, cell.originalType)
	if cell.blindColumn != "" {
		where += " AND " + quoteIdent(cell.blindColumn) + " COLLATE BINARY IS ? AND typeof(" + quoteIdent(cell.blindColumn) + ")=?"
		args = append(args, cell.originalBlind, cell.blindType)
	}
	res, err := tx.ExecContext(ctx, "UPDATE main."+quoteIdent(cell.table)+" SET "+strings.Join(sets, ", ")+" WHERE "+where, args...)
	if err != nil {
		return fmt.Errorf("update failed: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("affected-row count failed: %w", err)
	}
	if n != 1 {
		return errors.New("rotation compare-and-swap matched a different row count")
	}
	return nil
}

func appEncryptionRotationTablePresent(ctx context.Context, tx *sql.Tx, name string) (bool, error) {
	var count int
	err := tx.QueryRowContext(ctx, "SELECT count(*) FROM main.sqlite_schema WHERE type IN ('table','view') AND name=? COLLATE NOCASE", name).Scan(&count)
	if err != nil {
		return false, err
	}
	return count == 1, nil
}

func appEncryptionRotationValidateTOTPTable(ctx context.Context, tx *sql.Tx) error {
	var objectType string
	err := tx.QueryRowContext(ctx, "SELECT type FROM main.sqlite_schema WHERE name=? COLLATE NOCASE", totpSecretTable).Scan(&objectType)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil || objectType != "table" {
		return errors.New("incompatible TOTP storage object")
	}
	var tableKind string
	var withoutRowID int
	if err := tx.QueryRowContext(ctx, "SELECT type, wr FROM pragma_table_list WHERE schema='main' AND name=? COLLATE NOCASE", totpSecretTable).Scan(&tableKind, &withoutRowID); err != nil {
		return err
	}
	if tableKind != "table" || withoutRowID != 0 {
		return errors.New("unsupported TOTP row identity")
	}
	rows, err := tx.QueryContext(ctx, "PRAGMA main.table_xinfo("+quoteIdent(totpSecretTable)+")")
	if err != nil {
		return err
	}
	idFound, secretFound, invalidGenerated := false, false, false
	pkCount := 0
	for rows.Next() {
		var cid, notNull, pk, hidden int
		var name, declared string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &declared, &notNull, &defaultValue, &pk, &hidden); err != nil {
			rows.Close()
			return err
		}
		if pk > 0 {
			pkCount++
		}
		if hidden != 0 {
			invalidGenerated = true
		}
		switch sqliteIdentifierFold(name) {
		case "id":
			idFound = strings.Contains(strings.ToUpper(declared), "INT") && pk > 0
		case "totp_secret":
			secretFound = strings.EqualFold(strings.TrimSpace(declared), "TEXT")
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if !idFound || pkCount != 1 || !secretFound || invalidGenerated {
		return errors.New("incompatible TOTP storage schema")
	}
	return nil
}

func appEncryptionRotationTOTPPlain(stored string, oldKey []byte) (string, bool, bool, error) {
	pending := strings.HasPrefix(stored, totpPendingPrefix)
	value := strings.TrimPrefix(stored, totpPendingPrefix)
	plain, sealed, err := appEncryptionRotationOpen(value, oldKey, totpSecretTable, totpSecretColumn)
	if err != nil {
		return "", pending, false, err
	}
	return plain, pending, sealed, nil
}

func appEncryptionRotationRequireNoTriggers(ctx context.Context, tx *sql.Tx) error {
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM main.sqlite_schema WHERE type='trigger'").Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return errors.New("rotation requires trigger-free maintenance transaction")
	}
	return nil
}
