//go:build !cli

package main

// blindindex.go - equality-searchable encrypted columns, v2.7.55+.
//
// AES-GCM ciphertext changes every write (random nonce), so a query like
// `WHERE email = 'foo@bar'` against an encrypted column never matches.
// The blind index is the standard fix: a deterministic HMAC of the
// plaintext stored in a sibling column `<col>_blind`. Equality search
// rewrites to `WHERE <col>_blind = HMAC(plaintext)` and the index hits.
//
// The blind-index key is HKDF-derived from the encryption key - distinct
// material, same lifecycle. When `RotateEncryptionKey` runs the blind-
// index key rotates with it, so every existing blind column must be
// recomputed (`RebuildAllBlindIndices`).
//
// Surface area:
//   - declarative config via `blind_index: [col, col]` in encrypted.yaml
//   - process-global `appBlindIndexKey` derived at boot
//   - `benmore_blind_index(text)` SQL function registered on the
//     sqlite3_benmore driver so flows and hooks can do explicit lookups
//   - sibling `<col>_blind` columns auto-created (idempotent ALTER)
//   - INSERT and UPDATE triggers populate the blind column from the
//     plaintext NEW.<col> - fire alongside the existing encryption
//     triggers, both reference the original INSERT/UPDATE value (NEW.*)
//   - per-blind-column indexes for query performance
//   - auto-CRUD query rewriting (`?email=foo` → `?email_blind=HMAC(foo)`)
//   - backfill endpoint
//   - audit-logged grants/rebuilds
//
// SECURITY: blind indexes intentionally leak EQUALITY. An attacker who
// reads the DB can count distinct plaintexts and identify duplicates
// across rows - the same plaintext always hashes the same way. This is
// fundamental to any equality-searchable-on-ciphertext design and
// documented in security.md. Substring / prefix / range search are NOT
// supported - those need n-gram, bloom, or order-preserving primitives
// that are separate, not-yet-shipped features.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/crypto/hkdf"
)

// appBlindIndexKey holds the 32-byte HMAC key derived from the current
// app encryption key via HKDF. nil until InitFieldEncryption has run.
// Read by the SQL function + the Go-level HMAC helper, written only by
// SetBlindIndexKey (called from InitFieldEncryption + RotateEncryptionKey).
//
// Wrapped in an atomic.Pointer because RotateEncryptionKey runs while
// the per-request SQL function may be live - we want a torn-free swap.
var appBlindIndexKey atomic.Pointer[[]byte]

// blindIndexHKDFInfo is the labeled context fed into HKDF so the
// derived key is domain-separated from the AES encryption key. Treat
// as a versioned constant - bumping to v2 invalidates every existing
// blind column.
const blindIndexHKDFInfo = "benmore-blind-index-v1"

// blindColSuffix is the suffix appended to encrypted columns to form
// their sibling blind-index column. Centralised so renaming is a
// one-line change.
const blindColSuffix = "_blind"

// SetBlindIndexKey derives a 32-byte HMAC key from the supplied
// encryption-key bytes via HKDF-SHA256 and installs it as the process-
// global blind-index key. Idempotent - repeat calls with the same input
// produce the same key.
//
// Called from InitFieldEncryption (once at boot) and from
// RotateEncryptionKey (after the new AES key has been installed).
func SetBlindIndexKey(encKey []byte) error {
	out, err := DeriveBlindIndexKey(encKey)
	if err != nil {
		return err
	}
	appBlindIndexKey.Store(&out)
	return nil
}

// DeriveBlindIndexKey computes the blind-index HMAC key for a given AES
// key without touching the process global. Used by the per-DB crypto
// registry (dbCryptoRegistry) so the router can hold distinct blind keys
// for many tenants at once.
func DeriveBlindIndexKey(encKey []byte) ([]byte, error) {
	if len(encKey) == 0 {
		return nil, fmt.Errorf("DeriveBlindIndexKey: empty encKey")
	}
	r := hkdf.New(sha256.New, encKey, nil, []byte(blindIndexHKDFInfo))
	out := make([]byte, 32)
	if _, err := r.Read(out); err != nil {
		return nil, fmt.Errorf("blind-index HKDF: %w", err)
	}
	return out, nil
}

// BlindIndexHMAC computes the hex-encoded HMAC-SHA256 of `plaintext`
// under the current blind-index key. Empty input maps to empty output
// (we never write an HMAC of "" - that would collide every NULL/empty
// row into the same bucket and break uniqueness assumptions).
//
// Returns an error only when the key has not been initialised - every
// other input is valid (a plaintext is just bytes).
func BlindIndexHMAC(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	key := appBlindIndexKey.Load()
	if key == nil || len(*key) == 0 {
		return "", fmt.Errorf("blind-index key not initialised (ENCRYPTION_KEY missing?)")
	}
	mac := hmac.New(sha256.New, *key)
	mac.Write([]byte(plaintext))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// BlindIndexHMACWithKey is the explicit-key variant used during key
// rotation, when the caller holds the OLD or the NEW key explicitly
// (the process global is whichever the rotation has reached).
func BlindIndexHMACWithKey(key []byte, plaintext string) string {
	if plaintext == "" || len(key) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(plaintext))
	return hex.EncodeToString(mac.Sum(nil))
}

// BlindIndexColumnsForTable returns the set of column names on `table`
// that are flagged `blind_index: true` in the loaded encrypted config.
// Empty when there's no config or the table has no blind-indexed fields.
//
// Used by the auto-CRUD query rewriter and by the backfill endpoint.
func BlindIndexColumnsForTable(config *EncryptedFieldConfig, table string) map[string]bool {
	out := map[string]bool{}
	if config == nil {
		return out
	}
	defs, ok := config.Fields[table]
	if !ok {
		return out
	}
	for _, d := range defs {
		if d.BlindIndex {
			out[d.Column] = true
		}
	}
	return out
}

// hasBlindIndexes reports whether any encrypted field is blind-indexed.
func hasBlindIndexes(config *EncryptedFieldConfig) bool {
	if config == nil {
		return false
	}
	for _, defs := range config.Fields {
		for _, d := range defs {
			if d.BlindIndex {
				return true
			}
		}
	}
	return false
}

// EnsureBlindColumns adds `<col>_blind` to every table that has at
// least one field flagged `blind_index: true`. Safe to call repeatedly
// - uses pragma_table_info to skip columns that already exist.
//
// Also creates the per-column unique-friendly index. Marked NON-unique
// because:
//   - several rows may legitimately share a plaintext (two users with the
//     same name, two events at the same timestamp, …)
//   - the same HMAC for the same plaintext is the WHOLE POINT - uniqueness
//     would forbid that and break equality search
//
// Index gives the query planner a B-tree to seek on, no more.
func EnsureBlindColumns(db *sql.DB, config *EncryptedFieldConfig) error {
	tx, err := db.BeginTx(withLongWriteTx(context.Background(), "blind index columns"), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := ensureBlindColumnsWith(tx, config); err != nil {
		return err
	}
	return tx.Commit()
}

func ensureBlindColumnsWith(db mutationTx, config *EncryptedFieldConfig) error {
	if config == nil {
		return nil
	}
	for table, defs := range config.Fields {
		for _, d := range defs {
			if !d.BlindIndex {
				continue
			}
			if !membershipIdentRe.MatchString(table) || !membershipIdentRe.MatchString(d.Column) {
				return fmt.Errorf("blind index %q.%q is not a plain table and column name", table, d.Column)
			}
			cols, err := mainTableColumnsWith(db, table)
			if err != nil {
				return err
			}
			if !versionHasColumn(cols, d.Column) {
				return fmt.Errorf("blind index %s.%s: source column does not exist", table, d.Column)
			}
			blindCol := d.Column + blindColSuffix
			if !versionHasColumn(cols, blindCol) {
				if _, err := db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s TEXT", ddlIdent(table), blindCol)); err != nil {
					return fmt.Errorf("blind column %s.%s: %w", table, blindCol, err)
				}
			}
			idxName := fmt.Sprintf("idx_blind_%s_%s", table, d.Column)
			if _, err := db.Exec(fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s(%s)", idxName, ddlIdent(table), blindCol)); err != nil {
				return fmt.Errorf("blind index %s: %w", idxName, err)
			}
		}
	}
	return nil
}

// InstallBlindIndexTriggers creates INSERT and UPDATE triggers that
// populate `<col>_blind` from the plaintext value of `<col>`.
//
// Trigger order vs the encryption triggers:
//
//	INSERT INTO users (email) VALUES ('foo@bar');
//	  → both blind + encryption triggers fire AFTER INSERT, in unspecified
//	    order. Both reference NEW.email, which is the ORIGINAL inserted
//	    plaintext (SQLite NEW reflects the user-supplied value, not the
//	    result of earlier trigger UPDATEs in the same statement). So the
//	    blind trigger sees plaintext regardless of whether the encryption
//	    trigger has already rewritten the visible row.
//
// The blind trigger updates a DIFFERENT column (<col>_blind) than the
// encryption trigger updates (<col>), so neither re-fires the other.
//
// Idempotency: triggers are named with a stable scheme and dropped/
// recreated each boot. The blind trigger's WHEN clause excludes NULL
// (so a row with no email stays NULL on the blind column too).
func InstallBlindIndexTriggers(db *sql.DB, config *EncryptedFieldConfig) error {
	tx, err := db.BeginTx(withLongWriteTx(context.Background(), "blind index triggers"), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := installBlindIndexTriggersWith(tx, config); err != nil {
		return err
	}
	if err := reseatAppMCPRevisionTriggers(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func installBlindIndexTriggersWith(db mutationTx, config *EncryptedFieldConfig) error {
	return installBlindIndexTriggersMode(db, config, true)
}

func installBlindIndexTriggersMode(db mutationTx, config *EncryptedFieldConfig, replace bool) error {
	if config == nil {
		return nil
	}
	// Drop any pre-existing blind triggers so renames/removes propagate.
	if replace {
		rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE '_benmore_blind_%'")
		if err != nil {
			return err
		}
		var existing []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return err
			}
			existing = append(existing, name)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, name := range existing {
			if _, err := db.Exec("DROP TRIGGER IF EXISTS " + quoteIdent(name)); err != nil {
				return err
			}
		}
	}

	var installed int
	for table, defs := range config.Fields {
		for _, d := range defs {
			if !d.BlindIndex {
				continue
			}
			col := d.Column
			if !membershipIdentRe.MatchString(table) || !membershipIdentRe.MatchString(col) {
				return fmt.Errorf("blind index %q.%q is not a plain table and column name", table, col)
			}
			blindCol := col + blindColSuffix
			// Bare names as always, an SQL reserved word quoted (ddlIdent).
			sqlTable, sqlCol := ddlIdent(table), ddlIdent(col)

			// AFTER INSERT - populate blind from the raw INSERT value.
			// The plaintext-only guard is the encryption triggers' own:
			// NOT benmore_ciphertext_matches(value, table, column), true
			// only for authentic ciphertext bound to this field. A row
			// already holding that ciphertext (a restore, a migration, the
			// encryption trigger's own UPDATE) skips the blind step.
			// It used to be NOT LIKE 'enc:%', which also skipped plaintext
			// such as "enc:x" or "ENC:1" (LIKE is case-insensitive) that the
			// encryption trigger then sealed as plaintext: the blind column
			// stayed NULL on insert, or kept the previous value's index on
			// update, so equality search missed or matched the wrong row.
			// The text differs from older builds, and every load drops and
			// recreates these triggers (replace), so existing apps get it.
			tableLit := "'" + strings.ReplaceAll(table, "'", "''") + "'"
			colLit := "'" + strings.ReplaceAll(col, "'", "''") + "'"
			triggerName := fmt.Sprintf("_benmore_blind_%s_%s_insert", table, col)
			triggerSQL := fmt.Sprintf(
				"CREATE TRIGGER IF NOT EXISTS %s AFTER INSERT ON %s FOR EACH ROW WHEN NEW.%s IS NOT NULL AND NOT benmore_ciphertext_matches(NEW.%s, %s, %s) BEGIN UPDATE %s SET %s = benmore_blind_index(NEW.%s) WHERE rowid = NEW.rowid; END",
				triggerName, sqlTable, sqlCol, sqlCol, tableLit, colLit, sqlTable, blindCol, sqlCol,
			)
			if _, err := db.Exec(triggerSQL); err != nil {
				return fmt.Errorf("blind trigger %s: %w", triggerName, err)
			} else {
				installed++
			}

			// AFTER UPDATE OF <col> - recompute on every plaintext write
			// to that column. We DO NOT recompute on updates to
			// <col>_blind itself (no loop) because the trigger is
			// scoped to UPDATE OF the named encrypted column.
			triggerName = fmt.Sprintf("_benmore_blind_%s_%s_update", table, col)
			triggerSQL = fmt.Sprintf(
				"CREATE TRIGGER IF NOT EXISTS %s AFTER UPDATE OF %s ON %s FOR EACH ROW WHEN NEW.%s IS NOT NULL AND NOT benmore_ciphertext_matches(NEW.%s, %s, %s) BEGIN UPDATE %s SET %s = benmore_blind_index(NEW.%s) WHERE rowid = NEW.rowid; END",
				triggerName, sqlCol, sqlTable, sqlCol, sqlCol, tableLit, colLit, sqlTable, blindCol, sqlCol,
			)
			if _, err := db.Exec(triggerSQL); err != nil {
				return fmt.Errorf("blind trigger %s: %w", triggerName, err)
			} else {
				installed++
			}

			// A row written WITH ciphertext (a bulk import, the
			// encryption trigger's own UPDATE) leaves <col>_blind NULL.
			// Backfill handles that case explicitly.
		}
	}
	if installed > 0 {
		log.Printf("BLIND INDEX: installed %d triggers", installed)
	}
	return nil
}

// RebuildAllBlindIndices recomputes every `<col>_blind` value under the
// database's current key in one transaction: every blind-indexed column is
// rebuilt, or nothing changes. It returns the number of rows that hold a
// value; each now carries the index its plaintext hashes to.
//
// Key rotation does the same work inside its own transaction
// (rebuildBlindIndicesTx), so re-sealed values and their indexes commit
// together. This entry point repairs indexes left stale some other way.
// Writing a blind sibling is not an edit of the row: updated_at, computed
// values and content history stay as they were.
func RebuildAllBlindIndices(app *App) (int, error) {
	if app == nil || app.DB == nil || app.Encrypted == nil {
		return 0, nil
	}
	key := cryptoKeyForQuerier(app.DB)
	if len(key) == 0 {
		return 0, fmt.Errorf("no encryption key is registered for this database")
	}
	var total int
	err := withRowMaintenanceTx(app.DB, "blind index rebuild", func(tx *sql.Tx) error {
		var err error
		total, err = rebuildBlindIndicesTx(tx, app.Encrypted, key)
		return err
	})
	if err != nil {
		return 0, err
	}
	LogAudit(app, "blind_index_rebuilt", "_benmore_blind_index", "",
		nil, nil, map[string]any{"rows_rebuilt": total})
	return total, nil
}

// rebuildBlindIndicesTx rebuilds every configured blind column under key
// within tx and returns the rows that hold a value. A configured column whose
// sibling does not exist yet (encrypted.yaml changed without a reload) has
// nothing to keep consistent and is skipped; the next load creates it and the
// backfill endpoint fills it.
func rebuildBlindIndicesTx(tx mutationTx, config *EncryptedFieldConfig, key []byte) (int, error) {
	if config == nil {
		return 0, nil
	}
	tables := make([]string, 0, len(config.Fields))
	for table := range config.Fields {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	total := 0
	for _, table := range tables {
		for _, d := range config.Fields[table] {
			if !d.BlindIndex {
				continue
			}
			present, err := blindColumnExists(tx, table, d.Column)
			if err != nil {
				return total, fmt.Errorf("rebuild %s.%s: %w", table, d.Column, err)
			}
			if !present {
				log.Printf("blind index: %s.%s%s does not exist yet; skipped (restart the app, then run the blind-index backfill)", table, d.Column, blindColSuffix)
				continue
			}
			r, err := rebuildBlindColumn(tx, table, d.Column, key, false)
			if err != nil {
				return total, fmt.Errorf("rebuild %s.%s: %w", table, d.Column, err)
			}
			total += r.Indexed
		}
	}
	return total, nil
}

// withRowMaintenanceTx runs fn in one write transaction with the
// row-maintenance triggers suspended (suspendRowMaintenanceTriggers), so a
// derived-column write does not stamp updated_at or recompute computed fields,
// and restores them before committing.
func withRowMaintenanceTx(db *sql.DB, label string, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(withLongWriteTx(context.Background(), label), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	suspended, err := suspendRowMaintenanceTriggers(tx)
	if err != nil {
		return fmt.Errorf("suspend row maintenance triggers: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := restoreRowMaintenanceTriggers(tx, suspended); err != nil {
		return fmt.Errorf("restore row maintenance triggers: %w", err)
	}
	if err := reseatAppMCPRevisionTriggers(tx); err != nil {
		return fmt.Errorf("revision trigger order: %w", err)
	}
	return tx.Commit()
}

func blindColumnExists(q mutationQuerier, table, col string) (bool, error) {
	var n int
	if err := q.QueryRow("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?", table, col+blindColSuffix).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// blindBackfillRefusal is a backfill refusal written for the operator who
// asked for it; a database failure is reported through serverErrorJSON.
type blindBackfillRefusal struct{ msg string }

func (e *blindBackfillRefusal) Error() string { return e.msg }

// blindIndexRebuild counts what recomputing one blind column found.
type blindIndexRebuild struct {
	Indexed int // rows whose source holds a non-empty value; each now carries its index
	Changed int // rows whose stored index was missing or stale (written, or would be)
}

// blindRebuildBatch bounds the rows held in memory between reading and
// writing; rows are read in rowid order, one batch at a time.
const blindRebuildBatch = 1000

// rebuildBlindColumn computes `<col>_blind` for every row of table whose
// source column holds a value, under key (the AES key that opens the values;
// the blind key is derived from it, as the write triggers do). Used by the
// backfill endpoint, RebuildAllBlindIndices and key rotation.
//
// Rows are scanned by position. The rebuild used to read `SELECT rowid, ...`
// into a map keyed "rowid", but SQLite labels that column after an INTEGER
// PRIMARY KEY (`id`), so on every Prisma model each row was skipped: rotation
// left every existing index stale and the backfill reported 0 rows. Now every
// row with a non-NULL source is accounted for - indexed, or empty (the empty
// index the write trigger stores) - and the count is checked against the
// table; a value the key cannot open fails the rebuild rather than indexing
// the decryption-failure mask.
//
// Only the blind column is written, and only where it differs. Callers run it
// with the row-maintenance triggers suspended; with dryRun nothing is written.
func rebuildBlindColumn(q mutationTx, table, col string, key []byte, dryRun bool) (blindIndexRebuild, error) {
	var out blindIndexRebuild
	if !isValidColumnName(table) || !isValidColumnName(col) {
		return out, &blindBackfillRefusal{"invalid identifier"}
	}
	if len(key) == 0 {
		return out, fmt.Errorf("no encryption key is registered for this database")
	}
	blindKey, err := DeriveBlindIndexKey(key)
	if err != nil {
		return out, err
	}
	cols, err := mainTableColumnsWith(q, table)
	if err != nil {
		return out, err
	}
	rowID, err := versionHistoryRowID(cols) // first of rowid/_rowid_/oid the table does not shadow
	if err != nil {
		return out, err
	}
	source, blindCol := quoteColumn(table, col), quoteIdent(col+blindColSuffix)
	selectBatch := "SELECT " + rowID + ", " + source + ", " + blindCol + " FROM " + quoteIdent(table) +
		" WHERE " + source + " IS NOT NULL AND " + rowID + " > ? ORDER BY " + rowID + " LIMIT " + strconv.Itoa(blindRebuildBatch)
	type pendingWrite struct {
		id    int64
		blind string
	}
	seen := 0
	for after := int64(math.MinInt64); ; {
		rows, err := q.Query(selectBatch, after)
		if err != nil {
			return out, err
		}
		var writes []pendingWrite
		n := 0
		for rows.Next() {
			var id int64
			var raw, current any
			if err := rows.Scan(&id, &raw, &current); err != nil {
				rows.Close()
				return out, err
			}
			n++
			after = id
			plain, sealed, err := appEncryptionRotationOpen(raw, key, table, col)
			if err != nil {
				rows.Close()
				return out, fmt.Errorf("row %d: %w", id, err)
			}
			if !sealed {
				var ok bool
				if plain, ok = appEncryptionRotationScalar(raw); !ok {
					rows.Close()
					return out, fmt.Errorf("row %d: unsupported stored value type %T", id, raw)
				}
			}
			// An empty value gets the empty index the write trigger stores.
			if plain != "" {
				out.Indexed++
			}
			want := BlindIndexHMACWithKey(blindKey, plain)
			if stored, ok := current.(string); ok && stored == want {
				continue
			}
			if stored, ok := current.([]byte); ok && string(stored) == want {
				continue
			}
			writes = append(writes, pendingWrite{id, want})
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return out, err
		}
		seen += n
		out.Changed += len(writes)
		if !dryRun {
			for _, w := range writes {
				res, err := q.Exec("UPDATE "+quoteIdent(table)+" SET "+blindCol+" = ? WHERE "+rowID+" = ?", w.blind, w.id)
				if err != nil {
					return out, err
				}
				if affected, err := res.RowsAffected(); err != nil || affected != 1 {
					return out, fmt.Errorf("row %d: blind index write matched %d rows (%v)", w.id, affected, err)
				}
			}
		}
		if n < blindRebuildBatch {
			break
		}
	}
	var total int
	if err := q.QueryRow("SELECT COUNT(*) FROM " + quoteIdent(table) + " WHERE " + source + " IS NOT NULL").Scan(&total); err != nil {
		return out, err
	}
	if seen != total {
		return out, fmt.Errorf("read %d of the %d rows that hold a value", seen, total)
	}
	return out, nil
}

// backfillBlindIndexOne is the backfill endpoint's work: rebuild one blind
// column under the database's current key, in one transaction (dryRun only
// counts). Rows already carrying the right index are left untouched, so a
// repeat run writes nothing.
func backfillBlindIndexOne(app *App, table, col string, dryRun bool) (blindIndexRebuild, error) {
	var out blindIndexRebuild
	if app == nil || app.DB == nil {
		return out, &blindBackfillRefusal{"app not initialised"}
	}
	if !isValidColumnName(table) || !isValidColumnName(col) {
		return out, &blindBackfillRefusal{"invalid identifier"}
	}
	// The boot path creates the sibling; a backfill can run before a restart
	// picks up a fresh encrypted.yaml.
	present, err := blindColumnExists(app.DB, table, col)
	if err != nil {
		return out, err
	}
	if !present {
		return out, &blindBackfillRefusal{fmt.Sprintf("blind column %s.%s does not exist (restart the app after enabling blind_index)", table, col+blindColSuffix)}
	}
	key := cryptoKeyForQuerier(app.DB)
	if len(key) == 0 {
		return out, &blindBackfillRefusal{"no encryption key is loaded for this app"}
	}
	if dryRun {
		tx, err := app.DB.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return out, err
		}
		defer tx.Rollback()
		return rebuildBlindColumn(tx, table, col, key, true)
	}
	err = withRowMaintenanceTx(app.DB, "blind index backfill", func(tx *sql.Tx) error {
		var err error
		out, err = rebuildBlindColumn(tx, table, col, key, false)
		return err
	})
	return out, err
}

// RegisterBlindIndexRoutes wires the per-app backfill endpoint.
//
// POST /api/_internal/blind/backfill
//
//	body: {table: "users", column: "email", confirm: true}
//
// Admin-only, audit-logged. Symmetric with the encryption backfill +
// rotation endpoints (item 4 + item 7 in the enterprise-hardening
// roadmap).
func RegisterBlindIndexRoutes(mux appRouteRegistrar, app *App) {
	mux.HandleFunc("POST /api/_internal/blind/backfill", func(w http.ResponseWriter, r *http.Request) {
		session := adminConsoleSession(w, r, app, "")
		if session == nil {
			return
		}
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}
		var body struct {
			Table   string `json:"table"`
			Column  string `json:"column"`
			Confirm bool   `json:"confirm"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
			return
		}
		body.Table = strings.TrimSpace(body.Table)
		body.Column = strings.TrimSpace(body.Column)
		if body.Table == "" || body.Column == "" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "table and column are required"})
			return
		}
		// Verify the column is actually flagged blind_index - refuse to
		// backfill arbitrary columns (would compute HMACs in places the
		// config doesn't know to maintain).
		blindMap := BlindIndexColumnsForTable(app.Encrypted, body.Table)
		if !blindMap[body.Column] {
			httpJSON(w, http.StatusBadRequest, map[string]any{
				"error": fmt.Sprintf("%s.%s is not declared `blind_index: true` in encrypted.yaml", body.Table, body.Column),
			})
			return
		}
		n, err := backfillBlindIndexOne(app, body.Table, body.Column, !body.Confirm)
		var refusal *blindBackfillRefusal
		if errors.As(err, &refusal) {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": refusal.Error()})
			return
		}
		if err != nil {
			serverErrorJSON(w, r, app, "blind index backfill", err, "backfill failed")
			return
		}
		// Audit only on real writes - dry-run is read-only.
		if body.Confirm {
			LogAudit(app, "blind_index_backfilled", "_benmore_blind_index", body.Table,
				session, nil, map[string]any{
					"table":   body.Table,
					"column":  body.Column,
					"rows":    n.Indexed,
					"changed": n.Changed,
				})
		}
		// rows: rows holding a value, each indexed once this commits;
		// changed: those whose index was missing or stale.
		httpJSON(w, http.StatusOK, map[string]any{
			"table":   body.Table,
			"column":  body.Column,
			"rows":    n.Indexed,
			"changed": n.Changed,
			"dry_run": !body.Confirm,
		})
	})
}

// applyBlindIndexRewrite returns a (column, hashed-value, ok) tuple
// when `col` is blind-indexed on `table`. Callers swap `col` for
// `<col>_blind` and substitute the hashed value for the user-supplied
// equality target.
//
// This is the auto-CRUD integration point: `?email=foo@bar` on a
// blind-indexed column rewrites to `WHERE email_blind = HMAC(foo@bar)`.
// Operators other than equality (__gt, __lt, __like, __in) cannot be
// satisfied by a blind index and pass through unchanged - the query
// will then match against the raw (encrypted) column and return zero
// rows, which is the safest failure mode.
func applyBlindIndexRewrite(app *App, table, col, plaintext string) (string, string, bool) {
	if app == nil || app.Encrypted == nil {
		return col, plaintext, false
	}
	if !BlindIndexColumnsForTable(app.Encrypted, table)[col] {
		return col, plaintext, false
	}
	hash, err := blindIndexForApp(app, plaintext)
	if err != nil || hash == "" {
		return col, plaintext, false
	}
	return col + blindColSuffix, hash, true
}

// blindFilterAccess is how far a caller may use a blind index as a filter.
type blindFilterAccess int

const (
	blindFilterRefused blindFilterAccess = iota
	blindFilterOwnRows
	blindFilterTenantRows
	blindFilterOwnerOrTenantRows
	blindFilterAllRows
)

// blindFilterAccessFor decides whether `session` may filter (or sort) `table`
// by the blind index of encrypted column `col`. A blind-index equality
// filter is a plaintext ORACLE: `?ssn=123-45-6789` answers "does any row I
// can list hold this value" even when every value in the response comes
// back masked. So it is honored only where the caller would see the
// plaintext anyway - the same unmask decision MaskEncryptedFields makes:
//
//   - column has no unmask roles, caller is an admin, or holds an unmask
//     role                                      → all rows in scope
//   - tenant-only role → matching tenant rows only
//   - `self`/`owner` unmask on a user_id table → the caller's OWN rows
//     (combined with tenant rows when both grants are configured)
//   - otherwise                                 → refused
func blindFilterAccessFor(app *App, table, col string, session *Session) blindFilterAccess {
	if app == nil || app.Encrypted == nil {
		return blindFilterAllRows
	}
	for _, def := range app.Encrypted.Fields[table] {
		if def.Column != col {
			continue
		}
		access := encryptedFieldAccessFor(app, app.DB, table, def, session)
		switch {
		case access.allRows:
			return blindFilterAllRows
		case access.tenantColumn != "" && access.ownerID != 0:
			return blindFilterOwnerOrTenantRows
		case access.tenantColumn != "":
			return blindFilterTenantRows
		case access.ownerID != 0:
			return blindFilterOwnRows
		default:
			return blindFilterRefused
		}
	}
	return blindFilterAllRows
}

// blindFilterColumn maps a filter/sort column onto the blind-indexed source
// column it probes: `email` (equality/IN only - other operators on an
// encrypted column are dropped, not rewritten) or the explicit sibling
// `email_blind` (any operator). ok=false when the column is not a blind
// index probe.
func blindFilterColumn(blindCols map[string]bool, col, op string) (string, bool) {
	if blindCols[col] {
		return col, op == "=" || op == "IN"
	}
	if base := strings.TrimSuffix(col, blindColSuffix); base != col && blindCols[base] {
		return base, true
	}
	return "", false
}

// blindFilterRefusal returns the first column the request filters or sorts
// on through a blind index that the caller may not use (see
// blindFilterAccessFor), or "". Own-rows callers pass here; the rewrite in
// applyAPIWhereWithApp restricts their probe to rows they own.
func blindFilterRefusal(r *http.Request, app *App, table string, session *Session) string {
	if app == nil || app.Encrypted == nil {
		return ""
	}
	blindCols := BlindIndexColumnsForTable(app.Encrypted, table)
	if len(blindCols) == 0 {
		return ""
	}
	q := r.URL.Query()
	for key := range q {
		if apiFilterReservedParam(key) {
			continue
		}
		col, op := splitAPIFilterKey(key)
		if col == "" {
			continue
		}
		if base, probe := blindFilterColumn(blindCols, col, op); probe && blindFilterAccessFor(app, table, base, session) == blindFilterRefused {
			return base
		}
	}
	sortCol := q.Get("sort")
	if ob := q.Get("orderBy"); sortCol == "" && ob != "" {
		sortCol = strings.SplitN(ob, ":", 2)[0]
	}
	if base := strings.TrimSuffix(sortCol, blindColSuffix); base != sortCol && blindCols[base] &&
		blindFilterAccessFor(app, table, base, session) != blindFilterAllRows {
		return base
	}
	return ""
}

// encryptedListParamProblem names a list filter or sort on an encrypted column
// that cannot give a true answer, and why. Ciphertext keeps no order,
// substring or (without a blind index) equality: an equality filter matched
// nothing, a range or LIKE filter was dropped so every row came back, and a
// sort ordered the ciphertext. Each looked like a real result.
func encryptedListParamProblem(r *http.Request, app *App, table string) (col, why string) {
	if app == nil || app.Encrypted == nil || len(app.Encrypted.Fields[table]) == 0 {
		return "", ""
	}
	encrypted := map[string]bool{}
	for _, def := range app.Encrypted.Fields[table] {
		encrypted[def.Column] = true
	}
	blind := BlindIndexColumnsForTable(app.Encrypted, table)
	q := r.URL.Query()
	keys := make([]string, 0, len(q))
	for key := range q {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if apiFilterReservedParam(key) {
			continue
		}
		col, op := splitAPIFilterKey(key)
		if !encrypted[col] {
			continue
		}
		if op != "=" && op != "IN" {
			return col, "ciphertext keeps no order or text, so only an equality filter (or __in) on a blind-indexed column can be applied; this one would be ignored and every row returned"
		}
		if !blind[col] {
			return col, "it has no blind index, so an equality filter compares your value with ciphertext and can never match. Add the column to blind_index: in encrypted.yaml to filter on it"
		}
	}
	sortCol := q.Get("sort")
	if ob := q.Get("orderBy"); sortCol == "" && ob != "" {
		sortCol = strings.SplitN(ob, ":", 2)[0]
	}
	if encrypted[sortCol] {
		return sortCol, "sorting by it would order the ciphertext, not the values"
	}
	return "", ""
}

// writeBlindFilterRefusal renders the refusal for a blind-index probe.
func writeBlindFilterRefusal(w http.ResponseWriter, table, col string) {
	httpJSON(w, http.StatusForbidden, map[string]any{
		"error": fmt.Sprintf("filtering %s by encrypted column %s is not allowed: you would see %s masked, and an equality filter would confirm guessed values. Only callers in the column's unmask roles (encrypted.yaml) may filter on it; `self`/`owner` unmask allows filtering your own rows.", table, col, col),
	})
}

// blindKeyMatchesEncryptionKey is a debug helper used only by tests -
// asserts the derivation actually executes (and isn't returning the
// raw encryption key by mistake). Constant-time compare avoids
// accidentally creating a timing oracle if a test exposes the result.
func blindKeyMatchesEncryptionKey(encKey, blindKey []byte) bool {
	return subtle.ConstantTimeCompare(encKey, blindKey) == 1
}

// blindIndexForApp binds lookup/rebuild HMACs to the same key as SQL triggers.
func blindIndexForApp(app *App, plaintext string) (string, error) {
	if app != nil && app.DB != nil {
		key := cryptoKeyForQuerier(app.DB)
		if len(key) > 0 {
			blind, err := DeriveBlindIndexKey(key)
			if err != nil {
				return "", err
			}
			return BlindIndexHMACWithKey(blind, plaintext), nil
		}
	}
	if isolateAppEnvironment.Load() {
		return "", fmt.Errorf("database encryption key is not registered")
	}
	return BlindIndexHMAC(plaintext)
}
