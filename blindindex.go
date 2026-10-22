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
	"errors"
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
	tx, err := db.Begin()
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
				if _, err := db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s TEXT", table, blindCol)); err != nil {
					return fmt.Errorf("blind column %s.%s: %w", table, blindCol, err)
				}
			}
			idxName := fmt.Sprintf("idx_blind_%s_%s", table, d.Column)
			if _, err := db.Exec(fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s(%s)", idxName, table, blindCol)); err != nil {
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
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := installBlindIndexTriggersWith(tx, config); err != nil {
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

			// AFTER INSERT - populate blind from the raw INSERT value.
			// The plaintext-only guard (NOT LIKE 'enc:%%') mirrors the
			// encryption triggers: a bulk INSERT that already contains
			// ciphertext (a restore, a migration) skips the blind step.
			// SECURITY: the WHEN clause cannot tell ciphertext-as-blob
			// from plaintext-with-prefix; the framework's encryption
			// scheme guarantees ciphertext always starts with `enc:v1:`.
			triggerName := fmt.Sprintf("_benmore_blind_%s_%s_insert", table, col)
			triggerSQL := fmt.Sprintf(
				"CREATE TRIGGER IF NOT EXISTS %s AFTER INSERT ON %s FOR EACH ROW WHEN NEW.%s IS NOT NULL AND NEW.%s NOT LIKE 'enc:%%' BEGIN UPDATE %s SET %s = benmore_blind_index(NEW.%s) WHERE rowid = NEW.rowid; END",
				triggerName, table, col, col, table, blindCol, col,
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
				"CREATE TRIGGER IF NOT EXISTS %s AFTER UPDATE OF %s ON %s FOR EACH ROW WHEN NEW.%s IS NOT NULL AND NEW.%s NOT LIKE 'enc:%%' BEGIN UPDATE %s SET %s = benmore_blind_index(NEW.%s) WHERE rowid = NEW.rowid; END",
				triggerName, col, table, col, col, table, blindCol, col,
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

// blindBackfillRefusal is a backfill refusal written for the operator who
// asked for it; a database failure is reported through serverErrorJSON.
type blindBackfillRefusal struct{ msg string }

func (e *blindBackfillRefusal) Error() string { return e.msg }

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
		return 0, &blindBackfillRefusal{"app not initialised"}
	}
	if !isValidColumnName(table) || !isValidColumnName(col) {
		return 0, &blindBackfillRefusal{"invalid identifier"}
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
		return 0, &blindBackfillRefusal{fmt.Sprintf("blind column %s.%s does not exist (restart the app after enabling blind_index)", table, blindCol)}
	}
	// Pull (id, plaintext) using the configured physical source column.
	// Ordinary fields never gain decryption authority from a value prefix.
	// rowid (not id): backfill must work for tables whose PK column is not
	// named `id` (e.g. account_id TEXT PRIMARY KEY) — same reason the
	// encryption/blind-index triggers use NEW.rowid. rowid == id for
	// INTEGER PRIMARY KEY tables, so this is fully backward-compatible.
	source := quoteColumn(table, col)
	rows, err := queryNativeRowsWith(app.DB, app, table, fmt.Sprintf("SELECT rowid, %s FROM %s WHERE %s IS NOT NULL AND %s != ''", source, quoteIdent(table), source, source))
	if err != nil {
		return 0, err
	}
	updated := 0
	for _, row := range rows {
		idAny, ok := row["rowid"]
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
		hash, err := blindIndexForApp(app, pt)
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
			"UPDATE "+quoteIdent(table)+" SET "+quoteIdent(blindCol)+" = ? WHERE rowid = ?",
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
//
//	body: {table: "users", column: "email", confirm: true}
//
// Admin-only, audit-logged. Symmetric with the encryption backfill +
// rotation endpoints (item 4 + item 7 in the enterprise-hardening
// roadmap).
func RegisterBlindIndexRoutes(mux appRouteRegistrar, app *App) {
	mux.HandleFunc("POST /api/_internal/blind/backfill", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdminConsole() {
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
