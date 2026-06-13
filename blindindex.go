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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
	if len(encKey) == 0 {
		return fmt.Errorf("SetBlindIndexKey: empty encKey")
	}
	r := hkdf.New(sha256.New, encKey, nil, []byte(blindIndexHKDFInfo))
	out := make([]byte, 32)
	if _, err := r.Read(out); err != nil {
		return fmt.Errorf("blind-index HKDF: %w", err)
	}
	appBlindIndexKey.Store(&out)
	return nil
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
func EnsureBlindColumns(db *sql.DB, config *EncryptedFieldConfig) {
	if config == nil {
		return
	}
	for table, defs := range config.Fields {
		for _, d := range defs {
			if !d.BlindIndex {
				continue
			}
			blindCol := d.Column + blindColSuffix
			var count int
			_ = db.QueryRow(
				"SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?",
				table, blindCol).Scan(&count)
			if count == 0 {
				stmt := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s TEXT", table, blindCol)
				if _, err := db.Exec(stmt); err != nil {
					log.Printf("BLIND COLUMN ERROR [%s.%s]: %s", table, blindCol, err)
					continue
				}
			}
			idxName := fmt.Sprintf("idx_blind_%s_%s", table, d.Column)
			_, _ = db.Exec(fmt.Sprintf(
				"CREATE INDEX IF NOT EXISTS %s ON %s(%s)", idxName, table, blindCol))
		}
	}
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
func InstallBlindIndexTriggers(db *sql.DB, config *EncryptedFieldConfig) {
	if config == nil {
		return
	}
	// Drop any pre-existing blind triggers so renames/removes propagate.
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE '_benmore_blind_%'")
	if err == nil {
		var existing []string
		for rows.Next() {
			var n string
			rows.Scan(&n)
			existing = append(existing, n)
		}
		rows.Close()
		for _, n := range existing {
			db.Exec("DROP TRIGGER IF EXISTS " + n)
		}
	}

	var installed int
	for table, defs := range config.Fields {
		for _, d := range defs {
			if !d.BlindIndex {
				continue
			}
			col := d.Column
			blindCol := col + blindColSuffix

			// AFTER INSERT - populate blind from the raw INSERT value.
			// The plaintext-only guard (NOT LIKE 'enc:%%') mirrors the
			// encryption triggers: a bulk INSERT that already contains
			// ciphertext (a restore, a migration) skips the blind step.
			// SECURITY: the WHEN clause cannot tell ciphertext-as-blob
			// from plaintext-with-prefix; the framework's encryption
			// scheme guarantees ciphertext always starts with `enc:v1:`.
			triggerName := fmt.Sprintf("_benmore_blind_%s_%s_insert", table, col)
			triggerSQL := fmt.Sprintf(
				"CREATE TRIGGER IF NOT EXISTS %s AFTER INSERT ON %s FOR EACH ROW WHEN NEW.%s IS NOT NULL AND NEW.%s NOT LIKE 'enc:%%' BEGIN UPDATE %s SET %s = benmore_blind_index(NEW.%s) WHERE id = NEW.id; END",
				triggerName, table, col, col, table, blindCol, col,
			)
			if _, err := db.Exec(triggerSQL); err != nil {
				log.Printf("BLIND TRIGGER ERROR [%s]: %s", triggerName, err)
			} else {
				installed++
			}

			// AFTER UPDATE OF <col> - recompute on every plaintext write
			// to that column. We DO NOT recompute on updates to
			// <col>_blind itself (no loop) because the trigger is
			// scoped to UPDATE OF the named encrypted column.
			triggerName = fmt.Sprintf("_benmore_blind_%s_%s_update", table, col)
			triggerSQL = fmt.Sprintf(
				"CREATE TRIGGER IF NOT EXISTS %s AFTER UPDATE OF %s ON %s FOR EACH ROW WHEN NEW.%s IS NOT NULL AND NEW.%s NOT LIKE 'enc:%%' BEGIN UPDATE %s SET %s = benmore_blind_index(NEW.%s) WHERE id = NEW.id; END",
				triggerName, col, table, col, col, table, blindCol, col,
			)
			if _, err := db.Exec(triggerSQL); err != nil {
				log.Printf("BLIND TRIGGER ERROR [%s]: %s", triggerName, err)
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
}

// RebuildAllBlindIndices recomputes every `<col>_blind` value under
// the current blind-index key. Called immediately after a key rotation
// has installed the new encryption key (and thus the new blind-index
// key derived from it), so the existing blind columns - which were
// computed under the OLD HMAC key - are stale and must be regenerated
// or equality search breaks silently.
//
// Returns the number of rows rebuilt across all blind columns.
//
// The rebuild query decrypts the ciphertext, hashes it under the
// current blind-index key, and writes the result. The trigger system
// stays out of the way: this is a direct UPDATE on the blind column,
// which is NOT what the blind trigger watches (it watches the source
// encrypted column). So no infinite-trigger loops.
func RebuildAllBlindIndices(app *App) (int, error) {
	if app == nil || app.DB == nil || app.Encrypted == nil {
		return 0, nil
	}
	if appBlindIndexKey.Load() == nil {
		return 0, fmt.Errorf("blind-index key not initialised")
	}
	total := 0
	for table, defs := range app.Encrypted.Fields {
		for _, d := range defs {
			if !d.BlindIndex {
				continue
			}
			n, err := backfillBlindIndexOne(app, table, d.Column, false)
			if err != nil {
				return total, fmt.Errorf("rebuild %s.%s: %w", table, d.Column, err)
			}
			total += n
		}
	}
	if total > 0 {
		LogAudit(app, "blind_index_rebuilt", "_benmore_blind_index", "",
			nil, nil, map[string]any{"rows_rebuilt": total})
	}
	return total, nil
}

// backfillBlindIndexOne computes `<col>_blind` for every row of `table`
// where the source column has a value. Used by:
//   - the per-app backfill endpoint (one-shot agent-driven catch-up)
//   - the rotation pathway (RebuildAllBlindIndices)
//
// Performs the computation in Go rather than via the SQL function so
// the work can be batched + audit-summarised. Each row is read
// (with auto-decryption via the scanRows pathway), the plaintext is
// hashed, and the blind column is updated via a parameterised UPDATE.
// Rows where the source value is NULL or empty get their blind set to
// NULL (consistent with the trigger's WHEN clause).
//
// dryRun=true counts rows without writing.
func backfillBlindIndexOne(app *App, table, col string, dryRun bool) (int, error) {
	if app == nil || app.DB == nil {
		return 0, fmt.Errorf("app not initialised")
	}
	if !isValidColumnName(table) || !isValidColumnName(col) {
		return 0, fmt.Errorf("invalid identifier")
	}
	blindCol := col + blindColSuffix
	// Verify the blind column actually exists (defensive - boot path
	// should have created it, but the backfill might be invoked before
	// a restart picks up a fresh encrypted.yaml).
	var exists int
	_ = app.DB.QueryRow(
		"SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?",
		table, blindCol).Scan(&exists)
	if exists == 0 {
		return 0, fmt.Errorf("blind column %s.%s does not exist (restart the app after enabling blind_index)", table, blindCol)
	}
	// Pull (id, plaintext). The framework's QueryRows wrapper auto-
	// decrypts via DecryptRowFields → so what comes back IS the
	// plaintext, even though the on-disk value is ciphertext.
	rows, err := QueryRows(app.DB, fmt.Sprintf("SELECT id, %s FROM %s WHERE %s IS NOT NULL AND %s != ''", col, table, col, col))
	if err != nil {
		return 0, err
	}
	updated := 0
	for _, row := range rows {
		idAny, ok := row["id"]
		if !ok {
			continue
		}
		var idStr string
		switch v := idAny.(type) {
		case int64:
			idStr = strconv.FormatInt(v, 10)
		case float64:
			idStr = strconv.FormatInt(int64(v), 10)
		case string:
			idStr = v
		default:
			continue
		}
		ptAny, ok := row[col]
		if !ok || ptAny == nil {
			continue
		}
		// v2.7.57+: encrypted INTEGER/REAL columns come back from
		// scanRows already coerced to int64/float64 (the type-aware
		// decode that lets API consumers see numbers, not strings).
		// Stringify with the same canonical form the SQL function
		// uses on the way IN so the round-trip HMAC matches.
		pt := stringifyForCrypto(ptAny)
		if pt == "" {
			continue
		}
		hash, err := BlindIndexHMAC(pt)
		if err != nil {
			return updated, err
		}
		if dryRun {
			updated++
			continue
		}
		// Direct UPDATE on the blind column - doesn't fire the
		// encryption trigger (different column) or the blind trigger
		// (which watches UPDATE OF the source col only).
		if _, err := app.DB.Exec(
			fmt.Sprintf("UPDATE %s SET %s = ? WHERE id = ?", table, blindCol),
			hash, idStr,
		); err != nil {
			return updated, err
		}
		updated++
	}
	return updated, nil
}

// RegisterBlindIndexRoutes wires the per-app backfill endpoint.
//
// POST /api/_internal/blind/backfill
//   body: {table: "users", column: "email", confirm: true}
//
// Admin-only, audit-logged. Symmetric with the encryption backfill +
// rotation endpoints (item 4 + item 7 in the enterprise-hardening
// roadmap).
func RegisterBlindIndexRoutes(mux *http.ServeMux, app *App) {
	mux.HandleFunc("POST /api/_internal/blind/backfill", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdmin() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
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
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		// Audit only on real writes - dry-run is read-only.
		if body.Confirm {
			LogAudit(app, "blind_index_backfilled", "_benmore_blind_index", body.Table,
				session, nil, map[string]any{
					"table":  body.Table,
					"column": body.Column,
					"rows":   n,
				})
		}
		httpJSON(w, http.StatusOK, map[string]any{
			"table":   body.Table,
			"column":  body.Column,
			"rows":    n,
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
	hash, err := BlindIndexHMAC(plaintext)
	if err != nil || hash == "" {
		return col, plaintext, false
	}
	return col + blindColSuffix, hash, true
}

// blindKeyMatchesEncryptionKey is a debug helper used only by tests -
// asserts the derivation actually executes (and isn't returning the
// raw encryption key by mistake). Constant-time compare avoids
// accidentally creating a timing oracle if a test exposes the result.
func blindKeyMatchesEncryptionKey(encKey, blindKey []byte) bool {
	return subtle.ConstantTimeCompare(encKey, blindKey) == 1
}
