//go:build !cli

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	appMCPRevisionTablesName = "_benmore_mcp_revision_tables"
	appMCPRowRevisionsName   = "_benmore_mcp_row_revisions"
)

const appMCPRevisionTablesDDL = `CREATE TABLE main._benmore_mcp_revision_tables (
 table_name TEXT PRIMARY KEY NOT NULL,
 incarnation TEXT NOT NULL,
 schema_digest TEXT NOT NULL
)`

const appMCPRowRevisionsDDL = `CREATE TABLE main._benmore_mcp_row_revisions (
 table_name TEXT NOT NULL,
 incarnation TEXT NOT NULL,
 key_type TEXT NOT NULL CHECK(key_type IN ('integer','text')),
 row_key TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>0),
 deleted INTEGER NOT NULL CHECK(deleted IN (0,1)),
 PRIMARY KEY(table_name,incarnation,key_type,row_key)
)`

type appMCPRevisionTarget struct {
	name, schemaDigest string
	triggers           []appMCPRevisionTrigger
}

type appMCPRevisionTrigger struct{ name, sql string }

// initializeAppMCPRevisionStorage is the explicit bootstrap path. It installs
// sidecars, seeds existing rows and adds triggers atomically in the caller's
// transaction. Reuse/preflight callers must use verifyAppMCPRevisionStorage;
// this initializer refuses any existing sidecar state and is never called by
// the connector request path.
func initializeAppMCPRevisionStorage(tx *sql.Tx, tables []string) error {
	targets, err := appMCPRevisionTargets(tx, tables)
	if err != nil {
		return err
	}
	tablesExists, err := appMCPRevisionObjectExists(tx, appMCPRevisionTablesName)
	if err != nil {
		return err
	}
	rowsExists, err := appMCPRevisionObjectExists(tx, appMCPRowRevisionsName)
	if err != nil {
		return err
	}
	if tablesExists || rowsExists {
		return fmt.Errorf("revision storage already exists or is incomplete; use verification or explicit repair")
	}
	orphaned, err := appMCPExistingRevisionTriggers(tx)
	if err != nil {
		return err
	}
	if len(orphaned) != 0 {
		return fmt.Errorf("orphaned revision triggers require explicit repair")
	}
	if _, err := tx.Exec(appMCPRevisionTablesDDL); err != nil {
		return fmt.Errorf("create revision registry: %w", err)
	}
	if _, err := tx.Exec(appMCPRowRevisionsDDL); err != nil {
		return fmt.Errorf("create row revision ledger: %w", err)
	}
	for _, target := range targets {
		incarnation, err := appMCPNewRevisionIncarnation()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO main._benmore_mcp_revision_tables(table_name,incarnation,schema_digest) VALUES(?,?,?)`, target.name, incarnation, target.schemaDigest); err != nil {
			return fmt.Errorf("register revision table %q: %w", target.name, err)
		}
		if err := appMCPBackfillRevisionRows(tx, target.name, incarnation); err != nil {
			return err
		}
		for _, trigger := range target.triggers {
			if _, err := tx.Exec(trigger.sql); err != nil {
				return fmt.Errorf("install revision trigger %q: %w", trigger.name, err)
			}
		}
	}
	return nil
}

// repairAppMCPRevisionStorage is an explicit administrator/bootstrap action.
// It preserves app tables and unrelated triggers, removes only the reserved
// revision sidecars/triggers, then reinitializes every reviewed table with a
// fresh incarnation. Every comparison bound to the old incarnation is stale.
func repairAppMCPRevisionStorage(tx *sql.Tx, tables []string) error {
	_, err := appMCPRevisionTargets(tx, tables)
	if err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT name FROM main.sqlite_schema WHERE type='trigger' AND substr(name,1,17)='_benmore_mcp_rev_'`)
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, name := range names {
		if _, err := tx.Exec("DROP TRIGGER main." + quoteIdent(name)); err != nil {
			return fmt.Errorf("remove revision trigger %q: %w", name, err)
		}
	}
	if _, err := tx.Exec("DROP TABLE IF EXISTS main." + quoteIdent(appMCPRowRevisionsName)); err != nil {
		return fmt.Errorf("remove row revision sidecar: %w", err)
	}
	if _, err := tx.Exec("DROP TABLE IF EXISTS main." + quoteIdent(appMCPRevisionTablesName)); err != nil {
		return fmt.Errorf("remove revision registry sidecar: %w", err)
	}
	return initializeAppMCPRevisionStorage(tx, tables)
}

// verifyAppMCPRevisionStorage is the per-capability preflight. It is read-only
// and rejects missing, partial, altered or stale state; only a separate
// explicit bootstrap/repair action may create new incarnations.
func verifyAppMCPRevisionStorage(tx *sql.Tx, tables []string) error {
	targets, err := appMCPRevisionTargets(tx, tables)
	if err != nil {
		return err
	}
	tablesExists, err := appMCPRevisionObjectExists(tx, appMCPRevisionTablesName)
	if err != nil {
		return err
	}
	rowsExists, err := appMCPRevisionObjectExists(tx, appMCPRowRevisionsName)
	if err != nil {
		return err
	}
	if !tablesExists || !rowsExists {
		return fmt.Errorf("revision storage is missing or incomplete; explicit repair is required")
	}
	if err := appMCPVerifySidecarSchema(tx, appMCPRevisionTablesName, appMCPRevisionTablesDDL); err != nil {
		return err
	}
	if err := appMCPVerifySidecarSchema(tx, appMCPRowRevisionsName, appMCPRowRevisionsDDL); err != nil {
		return err
	}
	if err := appMCPVerifyRevisionRegistry(tx, targets); err != nil {
		return err
	}
	if err := appMCPVerifyRevisionTriggerSet(tx, targets); err != nil {
		return err
	}
	for _, target := range targets {
		if err := appMCPVerifyRevisionRows(tx, target.name); err != nil {
			return err
		}
	}
	return nil
}

func appMCPRevisionTargets(tx *sql.Tx, tables []string) ([]appMCPRevisionTarget, error) {
	if tx == nil || len(tables) == 0 {
		return nil, fmt.Errorf("revision storage requires a transaction and a non-empty reviewed table list")
	}
	ordered := append([]string(nil), tables...)
	sort.Strings(ordered)
	for i, table := range ordered {
		lowerTable := strings.ToLower(table)
		if !isValidColumnName(table) || strings.HasPrefix(lowerTable, "_benmore_") || strings.HasPrefix(lowerTable, "sqlite_") || i > 0 && table == ordered[i-1] {
			return nil, fmt.Errorf("invalid or duplicate revision table %q", table)
		}
	}

	targets := make([]appMCPRevisionTarget, 0, len(ordered))
	for _, table := range ordered {
		target, err := inspectAppMCPRevisionTarget(tx, table)
		if err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, nil
}

func inspectAppMCPRevisionTarget(tx *sql.Tx, table string) (appMCPRevisionTarget, error) {
	var ddl string
	if err := tx.QueryRow(`SELECT sql FROM main.sqlite_schema WHERE type='table' AND name=?`, table).Scan(&ddl); err != nil {
		return appMCPRevisionTarget{}, fmt.Errorf("revision table %q is not an ordinary main-schema table: %w", table, err)
	}
	upperDDL := strings.ToUpper(strings.TrimSpace(ddl))
	if strings.HasPrefix(upperDDL, "CREATE VIRTUAL TABLE") {
		return appMCPRevisionTarget{}, fmt.Errorf("revision table %q is virtual and unsupported", table)
	}

	rows, err := tx.Query("PRAGMA main.table_xinfo(" + quoteIdent(table) + ")")
	if err != nil {
		return appMCPRevisionTarget{}, err
	}
	var idType string
	var idFound bool
	var idNotNull bool
	var pkCount int
	var columns []string
	for rows.Next() {
		var cid, notNull, pk, hidden int
		var name, typ string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk, &hidden); err != nil {
			rows.Close()
			return appMCPRevisionTarget{}, err
		}
		columns = append(columns, fmt.Sprintf("%d:%s:%s:%d:%d:%v:%d", cid, name, strings.ToUpper(strings.TrimSpace(typ)), notNull, pk, defaultValue, hidden))
		if pk > 0 {
			pkCount++
			if strings.EqualFold(name, "id") {
				idFound = true
				idType, idNotNull = strings.ToUpper(strings.TrimSpace(typ)), notNull == 1
			}
		}
		if hidden != 0 {
			rows.Close()
			return appMCPRevisionTarget{}, fmt.Errorf("revision table %q has a hidden/generated column", table)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return appMCPRevisionTarget{}, err
	}
	if err := rows.Close(); err != nil {
		return appMCPRevisionTarget{}, err
	}
	if pkCount != 1 || !idFound {
		return appMCPRevisionTarget{}, fmt.Errorf("revision table %q must have a single id primary key", table)
	}
	integerAffinity := strings.Contains(idType, "INT")
	textAffinity := strings.Contains(idType, "CHAR") || strings.Contains(idType, "CLOB") || strings.Contains(idType, "TEXT")
	noAffinity := idType == "" || idType == "BLOB"
	if !integerAffinity && !textAffinity && !noAffinity {
		return appMCPRevisionTarget{}, fmt.Errorf("revision table %q id must use integer, text, or no affinity", table)
	}
	hasPKIndex, err := appMCPHasPrimaryKeyIndex(tx, table)
	if err != nil {
		return appMCPRevisionTarget{}, err
	}
	integerRowID := idType == "INTEGER" && !hasPKIndex
	if !idNotNull && !integerRowID {
		return appMCPRevisionTarget{}, fmt.Errorf("revision table %q id primary key must be non-null", table)
	}
	uniqueReconciliation, err := appMCPAlternateUniqueTrackingRequired(tx, table)
	if err != nil {
		return appMCPRevisionTarget{}, err
	}
	if err := appMCPVerifyPrimaryKeyCollation(tx, table, integerRowID); err != nil {
		return appMCPRevisionTarget{}, err
	}
	if err := appMCPRejectUnsupportedStoredKeys(tx, table); err != nil {
		return appMCPRevisionTarget{}, err
	}

	sort.Strings(columns)
	indexRows, err := tx.Query("PRAGMA main.index_list(" + quoteIdent(table) + ")")
	if err != nil {
		return appMCPRevisionTarget{}, err
	}
	var indexes []string
	for indexRows.Next() {
		var seq, unique, partial int
		var name, origin string
		if err := indexRows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			indexRows.Close()
			return appMCPRevisionTarget{}, err
		}
		// Framework scoping indexes (scoping_indexes.go) are performance-only
		// and appear at startup; they are not part of the table's identity.
		if unique == 0 && isFrameworkScopingIndex(name) {
			continue
		}
		var indexDDL sql.NullString
		if err := tx.QueryRow(`SELECT sql FROM main.sqlite_schema WHERE type='index' AND name=?`, name).Scan(&indexDDL); err != nil && err != sql.ErrNoRows {
			indexRows.Close()
			return appMCPRevisionTarget{}, err
		}
		indexes = append(indexes, fmt.Sprintf("%s:%d:%s:%d:%s", name, unique, origin, partial, indexDDL.String))
	}
	if err := indexRows.Err(); err != nil {
		indexRows.Close()
		return appMCPRevisionTarget{}, err
	}
	if err := indexRows.Close(); err != nil {
		return appMCPRevisionTarget{}, err
	}
	sort.Strings(indexes)
	normalizedDDL, err := normalizeAppMCPRevisionSQL(ddl)
	if err != nil {
		return appMCPRevisionTarget{}, fmt.Errorf("invalid schema SQL for %q: %w", table, err)
	}
	schema := normalizedDDL + "\n" + strings.Join(columns, "\n") + "\n" + strings.Join(indexes, "\n")
	digest := sha256.Sum256([]byte(schema))
	target := appMCPRevisionTarget{name: table, schemaDigest: hex.EncodeToString(digest[:])}
	if uniqueReconciliation {
		target.triggers = appMCPRevisionTriggerSQLWithUniqueReconciliation(table)
	} else {
		target.triggers = appMCPRevisionTriggerSQL(table)
	}
	return target, nil
}

func appMCPAlternateUniqueTrackingRequired(tx *sql.Tx, table string) (bool, error) {
	columnRows, err := tx.Query("PRAGMA main.table_xinfo(" + quoteIdent(table) + ")")
	if err != nil {
		return false, err
	}
	columns := make(map[int]string)
	for columnRows.Next() {
		var cid, notNull, primaryKey, hidden int
		var name, typ string
		var defaultValue any
		if err := columnRows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &primaryKey, &hidden); err != nil {
			columnRows.Close()
			return false, err
		}
		columns[cid] = name
	}
	if err := columnRows.Err(); err != nil {
		columnRows.Close()
		return false, err
	}
	if err := columnRows.Close(); err != nil {
		return false, err
	}
	rows, err := tx.Query("PRAGMA main.index_list(" + quoteIdent(table) + ")")
	if err != nil {
		return false, err
	}
	type uniqueIndex struct {
		name, origin string
		partial      int
	}
	var indexes []uniqueIndex
	for rows.Next() {
		var seq, unique, partial int
		var name, origin string
		if err := rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			rows.Close()
			return false, err
		}
		if unique != 0 && origin != "pk" {
			indexes = append(indexes, uniqueIndex{name: name, origin: origin, partial: partial})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return false, err
	}
	if err := rows.Close(); err != nil {
		return false, err
	}
	for _, index := range indexes {
		if index.partial != 0 || index.origin != "u" && index.origin != "c" {
			return false, fmt.Errorf("revision table %q has unsupported alternate UNIQUE index %q", table, index.name)
		}
		terms, err := tx.Query("PRAGMA main.index_xinfo(" + quoteIdent(index.name) + ")")
		if err != nil {
			return false, err
		}
		keyTerms := 0
		unsupported := ""
		for terms.Next() {
			var seq, cid, desc, key int
			var column, collation sql.NullString
			if err := terms.Scan(&seq, &cid, &column, &desc, &collation, &key); err != nil {
				terms.Close()
				return false, err
			}
			if key == 0 { // Auxiliary rowid entries do not participate in uniqueness.
				continue
			}
			keyTerms++
			if cid < 0 || !column.Valid || !strings.EqualFold(column.String, columns[cid]) || !collation.Valid || !strings.EqualFold(collation.String, "BINARY") {
				unsupported = "expression or non-BINARY key term"
			}
		}
		if err := terms.Err(); err != nil {
			terms.Close()
			return false, err
		}
		if err := terms.Close(); err != nil {
			return false, err
		}
		if keyTerms == 0 || unsupported != "" {
			return false, fmt.Errorf("revision table %q has unsupported alternate UNIQUE index %q: %s", table, index.name, unsupported)
		}
	}
	return len(indexes) != 0, nil
}

func appMCPVerifyPrimaryKeyCollation(tx *sql.Tx, table string, integerRowID bool) error {
	if integerRowID {
		return nil
	}
	rows, err := tx.Query("PRAGMA main.index_list(" + quoteIdent(table) + ")")
	if err != nil {
		return err
	}
	var name string
	for rows.Next() {
		var seq, unique, partial int
		var indexName, origin string
		if err := rows.Scan(&seq, &indexName, &unique, &origin, &partial); err != nil {
			rows.Close()
			return err
		}
		if origin == "pk" {
			name = indexName
			break
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("revision table %q primary key index is unavailable", table)
	}
	indexRows, err := tx.Query("PRAGMA main.index_xinfo(" + quoteIdent(name) + ")")
	if err != nil {
		return err
	}
	defer indexRows.Close()
	for indexRows.Next() {
		var seq, cid, desc, key int
		var column, collation sql.NullString
		if err := indexRows.Scan(&seq, &cid, &column, &desc, &collation, &key); err != nil {
			return err
		}
		// SQLite includes an auxiliary rowid entry in some primary-key
		// indexes. Its column name/collation are NULL and it is not part of
		// the key; only validate the actual id key column.
		if key == 1 && (!column.Valid || !strings.EqualFold(column.String, "id") || !collation.Valid || !strings.EqualFold(collation.String, "BINARY")) {
			return fmt.Errorf("revision table %q primary key must use the id column with BINARY collation", table)
		}
	}
	return indexRows.Err()
}

func appMCPHasPrimaryKeyIndex(tx *sql.Tx, table string) (bool, error) {
	rows, err := tx.Query("PRAGMA main.index_list(" + quoteIdent(table) + ")")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var seq, unique, partial int
		var name, origin string
		if err := rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			return false, err
		}
		if origin == "pk" {
			return true, nil
		}
	}
	return false, rows.Err()
}

func appMCPRejectUnsupportedStoredKeys(tx *sql.Tx, table string) error {
	var unsupported int
	query := "SELECT COUNT(*) FROM main." + quoteIdent(table) + " WHERE id IS NULL OR typeof(id) NOT IN ('integer','text')"
	if err := tx.QueryRow(query).Scan(&unsupported); err != nil {
		return err
	}
	if unsupported != 0 {
		return fmt.Errorf("revision table %q contains null or non-integer/text primary keys", table)
	}
	return nil
}

func appMCPRevisionTriggerSQL(table string) []appMCPRevisionTrigger {
	return appMCPRevisionTriggerSQLForUniqueMode(table, false)
}

func appMCPRevisionTriggerSQLWithUniqueReconciliation(table string) []appMCPRevisionTrigger {
	return appMCPRevisionTriggerSQLForUniqueMode(table, true)
}

func appMCPRevisionTriggerSQLForUniqueMode(table string, reconcileUniqueVictims bool) []appMCPRevisionTrigger {
	hash := sha256.Sum256([]byte(table))
	prefix := "_benmore_mcp_rev_" + hex.EncodeToString(hash[:8])
	t := quoteIdent(table)
	ledger := quoteIdent(appMCPRowRevisionsName)
	registry := quoteIdent(appMCPRevisionTablesName)
	key := func(ref string) string {
		return "typeof(" + ref + "." + quoteIdent("id") + "),CAST(" + ref + "." + quoteIdent("id") + " AS TEXT)"
	}
	keyWhere := func(ref string) string {
		return "table_name='" + table + "' AND incarnation=(SELECT incarnation FROM " + registry + " WHERE table_name='" + table + "') AND key_type=typeof(" + ref + "." + quoteIdent("id") + ") AND row_key=CAST(" + ref + "." + quoteIdent("id") + " AS TEXT)"
	}
	insertUpsert := "INSERT INTO " + ledger + "(table_name,incarnation,key_type,row_key,revision,deleted) VALUES('" + table + "',(SELECT incarnation FROM " + registry + " WHERE table_name='" + table + "')," + key("NEW") + ",1,0) ON CONFLICT(table_name,incarnation,key_type,row_key) DO UPDATE SET revision=revision+1,deleted=0;"
	validNewKey := "typeof(NEW." + quoteIdent("id") + ") NOT IN ('integer','text')"
	guardNewKey := "SELECT CASE WHEN " + validNewKey + " THEN RAISE(ABORT,'unsupported revision key type') END;"
	guardOldOverflow := "SELECT CASE WHEN EXISTS(SELECT 1 FROM " + ledger + " WHERE " + keyWhere("OLD") + " AND revision=9223372036854775807) THEN RAISE(ABORT,'revision overflow') END;"
	guardInsertOverflow := "SELECT CASE WHEN EXISTS(SELECT 1 FROM " + ledger + " WHERE " + keyWhere("NEW") + " AND revision=9223372036854775807) THEN RAISE(ABORT,'revision overflow') END;"
	reconcileUnique := ""
	if reconcileUniqueVictims {
		physical := "main." + t
		activeVictim := func(keyType, rowKey string) string {
			return "table_name='" + table + "' AND incarnation=(SELECT incarnation FROM " + registry + " WHERE table_name='" + table + "') AND deleted=0 AND NOT EXISTS(SELECT 1 FROM " + physical + " AS live_row WHERE typeof(live_row." + quoteIdent("id") + ")=" + keyType + " AND CAST(live_row." + quoteIdent("id") + " AS TEXT) COLLATE BINARY=" + rowKey + " COLLATE BINARY)"
		}
		guardVictim := activeVictim("victim.key_type", "victim.row_key")
		updateVictim := activeVictim(ledger+".key_type", ledger+".row_key")
		reconcileUnique = " SELECT CASE WHEN EXISTS(SELECT 1 FROM " + ledger + " AS victim WHERE " + guardVictim + " AND victim.revision=9223372036854775807) THEN RAISE(ABORT,'revision overflow') END; UPDATE " + ledger + " SET revision=revision+1,deleted=1 WHERE " + updateVictim + ";"
	}
	trigger := func(suffix, event, condition, body string) appMCPRevisionTrigger {
		name := prefix + "_" + suffix
		sql := "CREATE TRIGGER main." + quoteIdent(name) + " AFTER " + event + " ON " + t + " FOR EACH ROW"
		if condition != "" {
			sql += " WHEN " + condition
		}
		sql += " BEGIN " + body + " END"
		return appMCPRevisionTrigger{name: name, sql: sql}
	}
	missingOld := "SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM " + ledger + " WHERE " + keyWhere("OLD") + ") THEN RAISE(ABORT,'revision ledger row missing') END;"
	updateSame := guardNewKey + guardOldOverflow + missingOld + " UPDATE " + ledger + " SET revision=revision+1,deleted=0 WHERE " + keyWhere("OLD") + ";" + reconcileUnique
	updateMove := guardNewKey + guardOldOverflow + guardInsertOverflow + missingOld + " UPDATE " + ledger + " SET revision=revision+1,deleted=1 WHERE " + keyWhere("OLD") + "; " + insertUpsert + reconcileUnique
	sameKey := "typeof(OLD." + quoteIdent("id") + ")=typeof(NEW." + quoteIdent("id") + ") AND CAST(OLD." + quoteIdent("id") + " AS TEXT)=CAST(NEW." + quoteIdent("id") + " AS TEXT)"
	movedKey := "NOT (" + sameKey + ")"
	return []appMCPRevisionTrigger{
		trigger("insert", "INSERT", "", guardNewKey+guardInsertOverflow+insertUpsert+reconcileUnique),
		trigger("update_same", "UPDATE", sameKey, updateSame),
		trigger("update_move", "UPDATE", movedKey, updateMove),
		trigger("delete", "DELETE", "", guardOldOverflow+missingOld+" UPDATE "+ledger+" SET revision=revision+1,deleted=1 WHERE "+keyWhere("OLD")+";"),
	}
}

func appMCPNewRevisionIncarnation() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("create revision incarnation: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func appMCPBackfillRevisionRows(tx *sql.Tx, table, incarnation string) error {
	query := "INSERT INTO main." + quoteIdent(appMCPRowRevisionsName) + `(table_name,incarnation,key_type,row_key,revision,deleted) SELECT ?,?,typeof(id),CAST(id AS TEXT),1,0 FROM main.` + quoteIdent(table)
	if _, err := tx.Exec(query, table, incarnation); err != nil {
		return fmt.Errorf("seed revisions for %q: %w", table, err)
	}
	return nil
}

func appMCPRevisionObjectExists(tx *sql.Tx, name string) (bool, error) {
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM main.sqlite_schema WHERE type='table' AND name=?`, name).Scan(&count); err != nil {
		return false, err
	}
	return count == 1, nil
}

func appMCPVerifySidecarSchema(tx *sql.Tx, table, expected string) error {
	var actual string
	if err := tx.QueryRow(`SELECT sql FROM main.sqlite_schema WHERE type='table' AND name=?`, table).Scan(&actual); err != nil {
		return fmt.Errorf("revision sidecar %q is missing; explicit repair is required", table)
	}
	matches, compareErr := appMCPRevisionSQLMatches(actual, expected)
	if compareErr != nil || !matches {
		return fmt.Errorf("revision sidecar %q schema was changed; explicit repair is required", table)
	}
	return nil
}

func appMCPVerifyRevisionRegistry(tx *sql.Tx, targets []appMCPRevisionTarget) error {
	var names []string
	rows, err := tx.Query(`SELECT table_name,schema_digest FROM main._benmore_mcp_revision_tables ORDER BY table_name`)
	if err != nil {
		return fmt.Errorf("read revision registry: %w", err)
	}
	registered := make(map[string]string)
	for rows.Next() {
		var name, digest string
		if err := rows.Scan(&name, &digest); err != nil {
			rows.Close()
			return err
		}
		names = append(names, name)
		registered[name] = digest
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(names) != len(targets) {
		return fmt.Errorf("revision registry table set changed; explicit repair is required")
	}
	for i, target := range targets {
		if names[i] != target.name || registered[target.name] != target.schemaDigest {
			return fmt.Errorf("revision table %q schema or registration changed; explicit repair is required", target.name)
		}
	}
	return nil
}

func appMCPVerifyRevisionRows(tx *sql.Tx, table string) error {
	var incarnation string
	if err := tx.QueryRow(`SELECT incarnation FROM main._benmore_mcp_revision_tables WHERE table_name=?`, table).Scan(&incarnation); err != nil {
		return fmt.Errorf("revision incarnation for %q is missing", table)
	}
	decoded, err := hex.DecodeString(incarnation)
	if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != incarnation {
		return fmt.Errorf("revision incarnation for %q is malformed", table)
	}
	var stale, missing, activeOrphan int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM main._benmore_mcp_row_revisions WHERE table_name=? AND incarnation<>?`, table, incarnation).Scan(&stale); err != nil {
		return err
	}
	if stale != 0 {
		return fmt.Errorf("revision ledger for %q contains a stale incarnation", table)
	}
	quoted := "main." + quoteIdent(table)
	if err := tx.QueryRow(`SELECT COUNT(*) FROM `+quoted+` AS app_row LEFT JOIN main._benmore_mcp_row_revisions AS revision_row ON revision_row.table_name=? AND revision_row.incarnation=? AND revision_row.key_type=typeof(app_row.id) AND revision_row.row_key=CAST(app_row.id AS TEXT) AND revision_row.deleted=0 WHERE revision_row.row_key IS NULL`, table, incarnation).Scan(&missing); err != nil {
		return err
	}
	if missing != 0 {
		return fmt.Errorf("revision ledger for %q is missing a live row", table)
	}
	// The leading id equality lets SQLite probe the primary key per ledger row
	// (the CAST-only form scanned the table per row); the typeof/CAST terms keep
	// the exact match, so '05' never names row 5.
	if err := tx.QueryRow(`SELECT COUNT(*) FROM main._benmore_mcp_row_revisions AS revision_row WHERE table_name=? AND incarnation=? AND deleted=0 AND NOT EXISTS(SELECT 1 FROM `+quoted+` AS app_row WHERE app_row.id=(CASE revision_row.key_type WHEN 'integer' THEN CAST(revision_row.row_key AS INTEGER) ELSE revision_row.row_key END) AND typeof(app_row.id)=revision_row.key_type AND CAST(app_row.id AS TEXT)=revision_row.row_key)`, table, incarnation).Scan(&activeOrphan); err != nil {
		return err
	}
	if activeOrphan != 0 {
		return fmt.Errorf("revision ledger for %q marks an absent row live", table)
	}
	return nil
}

func appMCPExistingRevisionTriggers(tx *sql.Tx) (map[string]string, error) {
	rows, err := tx.Query(`SELECT name,sql FROM main.sqlite_schema WHERE type='trigger' AND substr(name,1,17)='_benmore_mcp_rev_'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	triggers := make(map[string]string)
	for rows.Next() {
		var name, sql string
		if err := rows.Scan(&name, &sql); err != nil {
			return nil, err
		}
		triggers[name] = sql
	}
	return triggers, rows.Err()
}

func appMCPVerifyRevisionTriggerSet(tx *sql.Tx, targets []appMCPRevisionTarget) error {
	actual, err := appMCPExistingRevisionTriggers(tx)
	if err != nil {
		return err
	}
	expected := make(map[string]string)
	for _, target := range targets {
		for _, trigger := range target.triggers {
			expected[trigger.name] = trigger.sql
		}
	}
	if len(actual) != len(expected) {
		return fmt.Errorf("revision trigger set is incomplete or contains unexpected triggers; explicit repair is required")
	}
	for name, sql := range expected {
		actualSQL, ok := actual[name]
		matches, compareErr := appMCPRevisionSQLMatches(actualSQL, sql)
		if !ok || compareErr != nil || !matches {
			return fmt.Errorf("revision trigger %q is missing or changed; explicit repair is required", name)
		}
	}
	return nil
}

func normalizeAppMCPRevisionSQL(sql string) (string, error) {
	kinds := make([]sqlByteKind, len(sql))
	// scanSQLBytes classifies bytes; this indexed pass consumes those same
	// categories and rejects unterminated quoted regions before normalization.
	var offset int
	if err := scanSQLBytes(sql, func(_ byte, kind sqlByteKind) error {
		kinds[offset] = kind
		offset++
		return nil
	}); err != nil {
		return "", err
	}
	for i := 0; i < len(sql); i++ {
		kind := kinds[i]
		if !kind.quoted() {
			continue
		}
		delim := byte('\'')
		switch kind {
		case sqlInDoubleQuote:
			delim = '"'
		case sqlInBracket:
			delim = ']'
		case sqlInBacktick:
			delim = '`'
		}
		closed := false
		for j := i + 1; j < len(sql) && kinds[j] == kind; j++ {
			if sql[j] != delim {
				continue
			}
			if kind != sqlInBracket && j+1 < len(sql) && kinds[j+1] == kind && sql[j+1] == delim {
				j++
				continue
			}
			closed = true
			i = j
			break
		}
		if !closed {
			return "", errors.New("unterminated quoted SQL token")
		}
	}
	var b strings.Builder
	space := false
	for i, c := range []byte(sql) {
		kind := kinds[i]
		if kind == sqlInLineComment || kind == sqlInBlockComment {
			space = true
			continue
		}
		if kind.quoted() {
			if space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			space = false
			b.WriteByte(c)
			continue
		}
		if kind == sqlCode && (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v') {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	normalized := strings.TrimSpace(b.String())
	tokens := sqlTokenize(normalized)
	remove := make([][2]int, 0, 2)
	word := func(i int, expected string) bool {
		return i < len(tokens) && tokens[i].kind == sqlTokWord && strings.EqualFold(tokens[i].text, expected)
	}
	for i := 0; i < len(tokens); i++ {
		if !word(i, "create") {
			continue
		}
		j := i + 1
		if word(j, "temp") || word(j, "temporary") || word(j, "unique") {
			j++
		}
		if !(word(j, "trigger") || word(j, "table") || word(j, "index")) {
			continue
		}
		object := strings.ToLower(tokens[j].text)
		if object == "trigger" && word(j+1, "if") && word(j+2, "not") && word(j+3, "exists") {
			remove = append(remove, [2]int{tokens[j].end, tokens[j+3].end})
		}
		if object == "table" {
			if word(j+1, "if") {
				j += 4
			} else {
				j++
			}
		} else if object == "trigger" || object == "index" {
			if word(j+1, "if") {
				j += 4
			} else {
				j++
			}
			if object == "trigger" && word(j, "main") && j+1 < len(tokens) && tokens[j+1].kind == sqlTokPunct && tokens[j+1].text == "." {
				remove = append(remove, [2]int{tokens[j].start, tokens[j+1].end})
			}
			if object == "trigger" || object == "index" {
				for j < len(tokens) && !word(j, "on") {
					j++
				}
				if j < len(tokens) {
					j++
				}
			}
		}
		if word(j, "main") && j+1 < len(tokens) && tokens[j+1].kind == sqlTokPunct && tokens[j+1].text == "." {
			remove = append(remove, [2]int{tokens[j].start, tokens[j+1].end})
		}
		break
	}
	for i := len(remove) - 1; i >= 0; i-- {
		r := remove[i]
		normalized = normalized[:r[0]] + normalized[r[1]:]
	}
	return strings.TrimSpace(normalized), nil
}

func appMCPRevisionSQLMatches(actual, expected string) (bool, error) {
	actualNormalized, err := normalizeAppMCPRevisionSQL(actual)
	if err != nil {
		return false, err
	}
	expectedNormalized, err := normalizeAppMCPRevisionSQL(expected)
	if err != nil {
		return false, err
	}
	return actualNormalized == expectedNormalized, nil
}
