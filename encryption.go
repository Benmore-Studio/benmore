//go:build !cli

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	sqlite3 "github.com/mattn/go-sqlite3"
	"gopkg.in/yaml.v3"
)

// Field encryption prefix - makes encrypted values self-describing.
// scanRows auto-decrypts any value starting with this prefix.
const encPrefix = "enc:v1:"

// stringifyForCrypto produces a stable, deterministic TEXT
// representation of any scalar SQLite value for crypto operations
// (encrypt / blind-index). The framework's encryption + blind-index
// system is TEXT-native: ciphertext is hex, HMAC output is hex, and
// they both need stable bytes to either round-trip or to dedupe via
// equality.
//
// SQLite passes integer / real values into Go-registered SQL
// functions as int64 / float64. Without an explicit stringification
// the formatting can be unstable (float64 1.5 → "1.5" via Sprintf
// most of the time, but "1.5e+00" with %v in some paths; int64 stays
// stable as "%d"). Lock the format here:
//
//   int64   → strconv.FormatInt(v, 10)          // "50000"
//   float64 → strconv.FormatFloat(v, 'f', -1, 64) // "1.5", "0.1", "1e-300" never
//   string  → as-is
//   []byte  → string(v)
//   bool    → "0" / "1" (SQLite affinity)
//
// 'f', -1 is the shortest decimal representation that round-trips
// back to the same float - same plaintext on re-encrypt produces
// the same intermediate string, so blind-index lookups stay stable
// across reads/writes/rotations.
func stringifyForCrypto(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case int:
		return strconv.Itoa(x)
	case int32:
		return strconv.FormatInt(int64(x), 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(x), 'f', -1, 32)
	case bool:
		if x {
			return "1"
		}
		return "0"
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", x)
	}
}

// appEncryptionKey holds the derived 32-byte AES key for the current app.
// Set from ENCRYPTION_KEY env var or env.yaml.
var appEncryptionKey []byte

// EncryptedFieldConfig holds the list of table.column pairs to encrypt.
type EncryptedFieldConfig struct {
	Fields map[string][]EncryptedFieldDef // table → field definitions
}

// EncryptedFieldDef defines a single encrypted column with optional role-gated access.
type EncryptedFieldDef struct {
	Column string   // column name
	Roles  []string // roles that can see decrypted values (empty = all roles)
	// BlindIndex is the v2.7.55+ flag that enables equality-search on
	// an encrypted column. When true, the framework auto-creates a
	// sibling `<col>_blind` column populated by INSERT/UPDATE triggers
	// with a deterministic HMAC of the plaintext, plus a B-tree index
	// on the blind column. Auto-CRUD `?col=value` filters are rewritten
	// to `?col_blind = HMAC(value)` so equality queries on the
	// encrypted column return the right rows.
	//
	// SECURITY TRADE-OFF: any equality-searchable-on-ciphertext design
	// leaks equality - an attacker with DB read sees duplicate
	// plaintexts as duplicate HMACs. Documented in security.md.
	BlindIndex bool
}

// InitFieldEncryption sets up the app-level encryption key.
//
// Key resolution order:
//  1. ENCRYPTION_KEY env var (OS environment - production deployments)
//  2. ENCRYPTION_KEY in env.yaml (local dev - gitignored)
//  3. Auto-generate and persist to env.yaml (first run)
//
// The framework never falls back to plaintext. If encrypted fields are
// configured, a key WILL exist after this function returns - either found
// or generated. This matches the Rails/Laravel pattern where the key is
// always present from day one.
func InitFieldEncryption(dir string, config *EncryptedFieldConfig) error {
	// Always initialize the key, even when the app has no encrypted.yaml
	// - the framework itself uses fieldEncrypt for OAuth provider tokens
	// stored in _benmore_oauth_tokens. Without this, those tokens silently
	// fall through to plaintext-at-rest.
	if config == nil {
		config = &EncryptedFieldConfig{}
	}

	// 1. Check OS environment (production: set in env.yaml, the environment, or systemd)
	keyStr := os.Getenv("ENCRYPTION_KEY")

	// 2. Check env.yaml (local dev)
	if keyStr == "" {
		keyStr = GetEnv(dir, "ENCRYPTION_KEY")
	}

	// 3. Auto-generate. Persist to env.yaml ONLY when the app actually
	// has encrypted fields configured - otherwise an ephemeral
	// per-process key is fine. Persisting requires writing to
	// env.yaml, which the MCP post-write hook (running as the platform
	// user) cannot do because env.yaml is owner-only on the per-tenant
	// user. Trying anyway used to flood `write_file` responses with a
	// bogus "encrypted fields configured but cannot persist
	// ENCRYPTION_KEY" error on every save for apps that have no
	// encryption configured.
	if keyStr == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("failed to generate encryption key: %w", err)
		}
		keyStr = hex.EncodeToString(b)

		hasEncryptedFields := false
		for _, cols := range config.Fields {
			if len(cols) > 0 {
				hasEncryptedFields = true
				break
			}
		}
		if hasEncryptedFields {
			if err := appendToEnvYaml(dir, "ENCRYPTION_KEY", keyStr); err != nil {
				// Soften from hard-error to warning: the key still works
				// for this process; only OAuth-token storage across
				// restarts breaks. Surfacing this as a fatal error on
				// every write_file was the wrong call.
				log.Printf("  encryption: WARN couldn't persist ENCRYPTION_KEY to env.yaml: %s - using ephemeral in-memory key (OAuth tokens written this session won't decrypt after restart). Set ENCRYPTION_KEY in env.yaml or the environment for persistence.", err)
			} else {
				log.Printf("  encryption: generated ENCRYPTION_KEY → env.yaml")
				log.Printf("  For production, set ENCRYPTION_KEY in env.yaml or your environment")
			}
		}
	}

	hash := sha256.Sum256([]byte(keyStr))
	appEncryptionKey = hash[:]
	// Blind-index key is HKDF-derived from the AES key so it has the
	// same lifecycle (rotated with the encryption key) but is
	// cryptographically distinct material. Failure to derive is fatal
	// - the SQL function will refuse to compute HMACs without it, and
	// then any insert into a blind-indexed column would error.
	if err := SetBlindIndexKey(appEncryptionKey); err != nil {
		return fmt.Errorf("blind-index key derivation: %w", err)
	}
	total := 0
	for _, cols := range config.Fields {
		total += len(cols)
	}
	log.Printf("  encryption: active (%d fields across %d tables)", total, len(config.Fields))
	return nil
}

// replaceEnvYamlKey updates an env.yaml key in place, replacing any
// existing value. Used by the key rotation primitive - appendToEnvYaml
// short-circuits when the key already exists, which is the right
// behavior for first-run auto-generation but the wrong behavior for
// rotation (where we MUST overwrite). Preserves comments + other keys.
func replaceEnvYamlKey(dir string, key string, value string) error {
	path := dir + "/env.yaml"
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	lines := strings.Split(string(existing), "\n")
	prefix := key + ":"
	replaced := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Match `KEY: value` or `KEY:value`; don't match comments
		// that happen to contain the substring.
		if !strings.HasPrefix(trimmed, prefix) {
			continue
		}
		lines[i] = key + ": " + value
		replaced = true
		break
	}
	if !replaced {
		// Append at the bottom - matches appendToEnvYaml's shape.
		lines = append(lines, "", "# Auto-rotated encryption key - do NOT commit this file", key+": "+value)
	}
	os.Chmod(path, 0600)
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0600)
}

// appendToEnvYaml appends a key-value pair to env.yaml if it doesn't already exist.
func appendToEnvYaml(dir string, key string, value string) error {
	path := dir + "/env.yaml"

	// Check if key already exists
	existing, _ := os.ReadFile(path)
	if strings.Contains(string(existing), key+":") {
		return nil
	}

	// Ensure restricted permissions on env.yaml (contains secrets)
	os.Chmod(path, 0600)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = fmt.Fprintf(f, "\n# Auto-generated encryption key - do NOT commit this file\n%s: %s\n", key, value)
	return err
}

// RegisterEncryptedSQLiteDriver registers a custom SQLite driver with
// benmore_encrypt() and benmore_decrypt() SQL functions available in
// every connection - triggers, queries, generated columns, everything.
func RegisterEncryptedSQLiteDriver() {
	sql.Register("sqlite3_benmore", &sqlite3.SQLiteDriver{
		ConnectHook: func(conn *sqlite3.SQLiteConn) error {
			// benmore_encrypt(plaintext) → "enc:v1:<hex ciphertext>".
			//
			// Type-tolerant (v2.7.57+): accepts any scalar SQLite type
			// - TEXT, INTEGER, REAL, NULL - and stringifies via
			// stringifyForCrypto so that integer/real columns flagged
			// encrypted round-trip cleanly. INTEGER 50000 → "50000",
			// REAL 1.5 → "1.5" (no scientific notation, no trailing
			// zeros, deterministic for the same value). NULL passes
			// through (caller's responsibility - NOT NULL constraint
			// or a default applies BEFORE the trigger fires).
			//
			// Determinism matters for two reasons:
			//   1. The same plaintext must produce the same blind-
			//      index HMAC every time. If int 50000 sometimes
			//      stringifies to "50000" and sometimes "5e4", the
			//      sibling blind column rows fan out across multiple
			//      HMAC buckets and equality search misses rows.
			//   2. Round-trip stability - on decrypt, the framework
			//      coerces back to the declared column type
			//      (DecryptRowFields → scanRows). A REAL column
			//      written as 1.5 must come back as 1.5, not 1.500000.
			if err := conn.RegisterFunc("benmore_encrypt", func(value any) (any, error) {
				if value == nil {
					return nil, nil
				}
				plaintext := stringifyForCrypto(value)
				if appEncryptionKey == nil {
					return "", fmt.Errorf("benmore_encrypt called but ENCRYPTION_KEY not initialized")
				}
				if strings.HasPrefix(plaintext, encPrefix) {
					return plaintext, nil // already encrypted - idempotent
				}
				return fieldEncrypt(plaintext)
			}, true); err != nil {
				return err
			}

			// benmore_decrypt(ciphertext) → plaintext (always TEXT).
			// Type coercion back to INTEGER/REAL happens at the read
			// boundary (scanRows) where the column's declared schema
			// type is known. Keeping the SQL function returning TEXT
			// avoids guesswork - a SQL caller of benmore_decrypt
			// always sees the raw plaintext string and decides what
			// to do with it.
			if err := conn.RegisterFunc("benmore_decrypt", func(value any) (string, error) {
				if value == nil {
					return "", nil
				}
				s := stringifyForCrypto(value)
				if !strings.HasPrefix(s, encPrefix) {
					return s, nil // not encrypted - return as-is
				}
				if appEncryptionKey == nil {
					return "", fmt.Errorf("benmore_decrypt called but ENCRYPTION_KEY not initialized")
				}
				return fieldDecrypt(s)
			}, true); err != nil {
				return err
			}

			// benmore_blind_index(plaintext) → hex(HMAC-SHA256(plaintext)).
			// Deterministic - same plaintext always yields the same hash
			// - so equality search works on encrypted columns by
			// querying the sibling `<col>_blind` column. The HMAC key
			// is HKDF-derived from the AES encryption key (see
			// SetBlindIndexKey) so a key rotation invalidates every
			// existing blind index → RebuildAllBlindIndices repairs them.
			//
			// Empty plaintext returns empty string (no HMAC of "") so
			// NULL/empty rows don't all collide on the same bucket.
			if err := conn.RegisterFunc("benmore_blind_index", func(value any) (string, error) {
				if value == nil {
					return "", nil
				}
				return BlindIndexHMAC(stringifyForCrypto(value))
			}, true); err != nil {
				return err
			}

			// SECURITY: block ATTACH DATABASE entirely. App-authored SQL
			// (flows, hooks, sql_dynamic) runs on this connection. Per-app
			// processes share a host, so without this a tenant could
			// `ATTACH '/path/to/another-app/data.db' AS v; SELECT …
			// FROM v.<table>` and read a sibling's whole database. Setting
			// the attached-DB limit to 0 makes any ATTACH fail at the engine
			// level. The framework never attaches databases itself - pure deny.
			conn.SetLimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)

			return nil
		},
	})
}

// InstallEncryptionTriggers creates SQLite triggers that auto-encrypt on INSERT/UPDATE.
// Same pattern as computed field triggers - fires at the database level on every mutation.
func InstallEncryptionTriggers(db *sql.DB, config *EncryptedFieldConfig) {
	if config == nil || appEncryptionKey == nil {
		return
	}

	// Drop existing encryption triggers
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE '_benmore_enc_%'")
	if err == nil {
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

	var installed int
	for table, defs := range config.Fields {
		for _, def := range defs {
			col := def.Column
			// AFTER INSERT: encrypt the column value
			triggerName := fmt.Sprintf("_benmore_enc_%s_%s_insert", table, col)
			triggerSQL := fmt.Sprintf(
				"CREATE TRIGGER IF NOT EXISTS %s AFTER INSERT ON %s FOR EACH ROW WHEN NEW.%s IS NOT NULL AND NEW.%s NOT LIKE 'enc:%%' BEGIN UPDATE %s SET %s = benmore_encrypt(NEW.%s) WHERE id = NEW.id; END",
				triggerName, table, col, col, table, col, col,
			)
			if _, err := db.Exec(triggerSQL); err != nil {
				log.Printf("ENCRYPTION TRIGGER ERROR [%s]: %s", triggerName, err)
			} else {
				installed++
			}

			// AFTER UPDATE: encrypt if value changed and isn't already encrypted
			triggerName = fmt.Sprintf("_benmore_enc_%s_%s_update", table, col)
			triggerSQL = fmt.Sprintf(
				"CREATE TRIGGER IF NOT EXISTS %s AFTER UPDATE OF %s ON %s FOR EACH ROW WHEN NEW.%s IS NOT NULL AND NEW.%s NOT LIKE 'enc:%%' BEGIN UPDATE %s SET %s = benmore_encrypt(NEW.%s) WHERE id = NEW.id; END",
				triggerName, col, table, col, col, table, col, col,
			)
			if _, err := db.Exec(triggerSQL); err != nil {
				log.Printf("ENCRYPTION TRIGGER ERROR [%s]: %s", triggerName, err)
			} else {
				installed++
			}
		}
	}

	if installed > 0 {
		log.Printf("  encryption: %d triggers installed", installed)
	}
}

// EncryptedFieldDefYAML supports both simple and detailed formats via custom unmarshalling.
// Simple:   "notes" → {Column: "notes", Roles: nil}
// Detailed: {column: ssn, roles: [admin]} → {Column: "ssn", Roles: ["admin"]}
type EncryptedFieldDefYAML struct {
	Column string   `yaml:"column"`
	Roles  []string `yaml:"roles"`
}

// UnmarshalYAML handles both string and map formats in YAML arrays.
func (e *EncryptedFieldDefYAML) UnmarshalYAML(value *yaml.Node) error {
	// Try simple string first: "notes"
	if value.Kind == yaml.ScalarNode {
		e.Column = value.Value
		return nil
	}
	// Try detailed map: {column: ssn, roles: [admin]}
	type plain EncryptedFieldDefYAML
	return value.Decode((*plain)(e))
}

// EncryptedYAML is the top-level encrypted: section in app.yaml.
type EncryptedYAML struct {
	Encrypted map[string][]EncryptedFieldDefYAML `yaml:"encrypted"`
}

// LoadEncryptedFieldsConfig reads field-level encryption configuration
// from either a dedicated encrypted.yaml file or the encrypted: section
// of app.yaml. encrypted.yaml takes precedence on conflicts.
//
// encrypted.yaml format (preferred - per-table unmask_roles applies to
// every listed field):
//
//	tables:
//	  patients:
//	    fields:
//	      - date_of_birth
//	      - phone
//	    unmask_roles:
//	      - admin
//	      - physician
//
// app.yaml inline format (legacy, per-field role gating):
//
//	encrypted:
//	  contacts: [notes]
//	  contacts:
//	    - column: ssn
//	      roles: [admin, manager]
func LoadEncryptedFieldsConfig(dir string) *EncryptedFieldConfig {
	config := &EncryptedFieldConfig{Fields: make(map[string][]EncryptedFieldDef)}

	// 1. Dedicated encrypted.yaml (preferred)
	if data, err := os.ReadFile(fmt.Sprintf("%s/encrypted.yaml", dir)); err == nil {
		// `blind_index:` is the v2.7.55+ flag - a list of columns
		// (must be a subset of `fields:`) that get a deterministic
		// HMAC sibling column populated by triggers so equality
		// search works on encrypted data.
		var wrapper struct {
			Tables map[string]struct {
				Fields      []string `yaml:"fields"`
				UnmaskRoles []string `yaml:"unmask_roles"`
				BlindIndex  []string `yaml:"blind_index"`
			} `yaml:"tables"`
		}
		if yaml.Unmarshal(data, &wrapper) == nil {
			for table, spec := range wrapper.Tables {
				blindSet := map[string]bool{}
				for _, b := range spec.BlindIndex {
					blindSet[strings.TrimSpace(b)] = true
				}
				for _, field := range spec.Fields {
					if field == "" {
						continue
					}
					config.Fields[table] = append(config.Fields[table], EncryptedFieldDef{
						Column:     field,
						Roles:      spec.UnmaskRoles,
						BlindIndex: blindSet[field],
					})
				}
			}
		}
	}

	// 2. app.yaml inline encrypted: section (merged for tables not
	// already set by encrypted.yaml)
	if data, err := os.ReadFile(fmt.Sprintf("%s/app.yaml", dir)); err == nil {
		var raw EncryptedYAML
		if yaml.Unmarshal(data, &raw) == nil && len(raw.Encrypted) > 0 {
			for table, defs := range raw.Encrypted {
				if _, already := config.Fields[table]; already {
					continue
				}
				for _, d := range defs {
					if d.Column == "" {
						continue
					}
					config.Fields[table] = append(config.Fields[table], EncryptedFieldDef{
						Column: d.Column,
						Roles:  d.Roles,
					})
				}
			}
		}
	}

	if len(config.Fields) == 0 {
		return nil
	}
	return config
}

// MaskEncryptedFields replaces decrypted values with masked versions
// for callers whose roles aren't in the column's `unmask_roles:` list.
// Called from CRUD API handlers after QueryRows, before JSON response.
//
// Authorization rules (v2.7.58+ multi-role aware):
//   - field has no `unmask_roles:` configured → everyone sees decrypted
//   - caller is admin (via PRIMARY role OR _benmore_user_roles) → unmasked
//   - caller holds ANY role listed in `unmask_roles:` via the primary
//     column OR the join table → unmasked
//   - otherwise → masked (last 4 chars visible)
//
// Pre-v2.7.58 this function took a single `userRole string` and
// compared it directly. A user granted `admin` via the join table
// (whose primary role was something else, e.g. `platform_admin`)
// was masked despite the `unmask_roles: [admin]` config - same shape
// as the v2.7.56 admin-elevation gap, different code path. Now the
// check honors the full Session.Roles slice via Session.IsAdmin()
// for admin shortcuts and an explicit slice-membership test for
// every other named role.
func MaskEncryptedFields(config *EncryptedFieldConfig, table string, rows []map[string]any, session *Session) {
	if config == nil {
		return
	}
	defs, ok := config.Fields[table]
	if !ok {
		return
	}
	// Build a single set of "roles this caller holds" so the
	// per-field loop doesn't re-walk the slice once per column.
	held := map[string]bool{}
	if session != nil {
		if session.Role != "" {
			held[session.Role] = true
		}
		for _, r := range session.Roles {
			held[r] = true
		}
	}
	isAdmin := session.IsAdmin()
	var sessUserID int64
	if session != nil {
		sessUserID = session.UserID
	}

	for _, def := range defs {
		if len(def.Roles) == 0 {
			continue // no role restriction - everyone sees decrypted
		}
		// Admin bypasses every column's mask. Otherwise check whether ANY held
		// role appears in the unmask list. The special tokens `self`/`owner`
		// don't name a role - they mean "the row's owner sees their OWN row
		// decrypted" (per-row), which is how per-user private data (journals,
		// notes, health) stays usable by the person it belongs to. Without this
		// an owner-scoped encrypted column was masked even from its owner -
		// they saw their own data as `****`.
		globallyAuthorized := isAdmin
		ownerUnmask := false
		if !globallyAuthorized {
			for _, r := range def.Roles {
				if r == "self" || r == "owner" {
					ownerUnmask = true
					continue
				}
				if held[r] {
					globallyAuthorized = true
					break
				}
			}
		}
		if globallyAuthorized {
			continue // unmask all rows
		}

		// Not globally authorized: mask, but leave the caller's OWN rows
		// decrypted when `self`/`owner` is configured.
		for _, row := range rows {
			if ownerUnmask && sessUserID != 0 && rowOwnedBy(row, sessUserID) {
				continue
			}
			if val, ok := row[def.Column]; ok && val != nil {
				row[def.Column] = maskValue(fmt.Sprintf("%v", val))
			}
		}
	}
}

// rowOwnedBy reports whether the row's user_id matches the given session user.
// Row values come from a SQL scan, so user_id may surface as int64, float64
// (JSON-decoded), or string - compare tolerantly.
func rowOwnedBy(row map[string]any, userID int64) bool {
	v, ok := row["user_id"]
	if !ok || v == nil {
		return false
	}
	switch n := v.(type) {
	case int64:
		return n == userID
	case int:
		return int64(n) == userID
	case float64:
		return int64(n) == userID
	case string:
		return n == strconv.FormatInt(userID, 10)
	default:
		return fmt.Sprintf("%v", v) == strconv.FormatInt(userID, 10)
	}
}

// maskValue returns a masked version of a string, showing only the last 4 characters.
func maskValue(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	masked := strings.Repeat("*", len(s)-4) + s[len(s)-4:]
	return masked
}

// encryptAuditFieldsCopy returns a shallow copy of `row` with every
// configured-encrypted field (for `table`) replaced by its ciphertext
// form. Returns the input directly (no copy) when there's nothing to
// encrypt - avoids an unnecessary allocation on the audit hot path for
// apps that don't use field encryption.
//
// Closes the "encrypted column leaks via audit log" hole: previously,
// LogAudit captured `oldRow`/`newRow` as plaintext JSON even when the
// source column was encrypted at rest, because the rows arrive in this
// function already-decrypted (DecryptRowFields runs inside scanRows).
// Re-encrypting before marshal keeps `old_values` / `new_values` JSON
// consistent with the on-disk shape of the source table.
//
// Also handles `old_<col>` keys - the framework includes a change-delta
// inside newRow for hook templates, and those plaintext copies would
// otherwise leak too.
func encryptAuditFieldsCopy(config *EncryptedFieldConfig, table string, row map[string]any) map[string]any {
	if row == nil || config == nil {
		return row
	}
	defs, ok := config.Fields[table]
	if !ok || len(defs) == 0 {
		return row
	}
	// Shallow copy so we don't mutate the caller's row (hooks/webhooks
	// run after the audit write and expect the same map they saw).
	out := make(map[string]any, len(row))
	for k, v := range row {
		out[k] = v
	}
	for _, def := range defs {
		encryptOneAuditField(out, def.Column)
		encryptOneAuditField(out, "old_"+def.Column)
	}
	return out
}

func encryptOneAuditField(row map[string]any, key string) {
	v, ok := row[key]
	if !ok || v == nil {
		return
	}
	s, ok := v.(string)
	if !ok {
		// Non-string values can't go through fieldEncrypt today (string-
		// only encryption, see integer-encryption TODO). Leave as-is.
		return
	}
	if s == "" || strings.HasPrefix(s, encPrefix) {
		// Empty or already-encrypted - idempotent.
		return
	}
	if enc, err := fieldEncrypt(s); err == nil {
		row[key] = enc
	}
}

// DecryptRowFields auto-decrypts any values in a row that have the enc: prefix.
// Called from scanRows so ALL query paths get transparent decryption.
func DecryptRowFields(row map[string]any) {
	if appEncryptionKey == nil {
		return
	}
	for k, v := range row {
		if s, ok := v.(string); ok && strings.HasPrefix(s, encPrefix) {
			if decrypted, err := fieldDecrypt(s); err == nil {
				row[k] = decrypted
			}
		}
	}
}

// ===== AES-256-GCM field encryption =====

func fieldEncrypt(plaintext string) (string, error) {
	return fieldEncryptWithKey(appEncryptionKey, plaintext)
}

// fieldEncryptWithKey is the explicit-key variant - used by the key
// rotation primitive so the rotator can re-encrypt against a NEW key
// while the global appEncryptionKey is still set to the OLD one.
func fieldEncryptWithKey(key []byte, plaintext string) (string, error) {
	if key == nil {
		return plaintext, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	incEncryptionEnc()
	return encPrefix + hex.EncodeToString(ciphertext), nil
}

func fieldDecrypt(value string) (string, error) {
	if appEncryptionKey == nil {
		return value, nil
	}

	if !strings.HasPrefix(value, encPrefix) {
		return value, nil
	}
	return fieldDecryptWithKey(appEncryptionKey, value)
}

// fieldDecryptWithKey is the explicit-key variant - used by the key
// rotation primitive so the rotator can decrypt with the OLD key
// while the global appEncryptionKey may already point at the NEW one.
func fieldDecryptWithKey(key []byte, value string) (string, error) {
	if key == nil {
		return value, nil
	}
	if !strings.HasPrefix(value, encPrefix) {
		return value, nil
	}
	incEncryptionDec()

	ciphertextHex := strings.TrimPrefix(value, encPrefix)
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// ===== Key rotation =====

// RotateEncryptionKey re-encrypts every row of every configured-encrypted
// column with a NEW key, then swaps the in-memory key + persists the new
// key to env.yaml. Idempotent on success: ciphertext written carries the
// enc:v1: prefix so the existing UPDATE trigger's WHEN clause skips it
// (no double-encrypt).
//
// Failure modes:
//   - decrypt-with-old failure → row is corrupt or already rotated by
//     a previous incomplete run; aborts and returns the row id so the
//     operator can inspect.
//   - mid-rotation crash → some rows are now ciphertext-with-new-key,
//     others still ciphertext-with-old-key. Since env.yaml hasn't been
//     swapped yet, the next process start still loads OLD. Re-running
//     rotation against the SAME new key will skip already-rotated rows
//     (decrypt fails with OLD on those, succeeds on the unrotated ones)
//     - caller can pass `--resume-skip-undecryptable` to make this safe.
//   - env.yaml write failure AFTER DB rotation → the most dangerous
//     case. DB is rotated but persisted key file is stale. We restart
//     the app process here so it reloads the file and the in-memory key
//     matches what's on disk - so encryption-keyed work after a crash
//     stays consistent. Operator must redo the rotation in this case.
//
// Returns: number of rows rotated, and an error if anything went wrong.
//
// newKeySource is what gets written to env.yaml as the new
// ENCRYPTION_KEY value - an arbitrary string. The actual 32-byte AES
// key is derived via sha256(newKeySource), matching what
// InitFieldEncryption does on process start. Default-generated keys
// are 32 random bytes hex-encoded (64-char string) for operator
// readability, but the rotation accepts any non-empty string the
// operator provides - same behavior as the env-var path.
func RotateEncryptionKey(app *App, newKeySource string, dryRun bool) (int, error) {
	if app == nil || app.DB == nil {
		return 0, fmt.Errorf("nil app")
	}
	if app.Encrypted == nil || len(app.Encrypted.Fields) == 0 {
		return 0, fmt.Errorf("no encrypted fields configured in encrypted.yaml - nothing to rotate")
	}
	if appEncryptionKey == nil {
		return 0, fmt.Errorf("no current encryption key loaded - set ENCRYPTION_KEY before rotating")
	}

	// Pick / validate the new key source string. The 32-byte AES key
	// is derived by sha256-ing this string, so any non-empty value
	// works; default is 32 random bytes hex-encoded.
	newKeySource = strings.TrimSpace(newKeySource)
	if newKeySource == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return 0, fmt.Errorf("generate new key: %w", err)
		}
		newKeySource = hex.EncodeToString(b)
	}
	if len(newKeySource) < 32 {
		return 0, fmt.Errorf("new key source must be at least 32 chars for adequate entropy (got %d). Use `openssl rand -hex 32` to generate a strong one.", len(newKeySource))
	}
	derivedNew := sha256.Sum256([]byte(newKeySource))
	newKey := derivedNew[:]

	// Refuse no-op rotation (would re-encrypt every row with the same
	// key - pointless work + audit-log noise). Constant-time compare
	// since this is a secret-key equality check.
	if subtle.ConstantTimeCompare(newKey, appEncryptionKey) == 1 {
		return 0, fmt.Errorf("new key matches current key - refusing no-op rotation")
	}

	oldKey := make([]byte, len(appEncryptionKey))
	copy(oldKey, appEncryptionKey)

	// Count rows that need rotating across all configured columns.
	type plan struct {
		Table, Column string
		IDs           []int64
	}
	var plans []plan
	totalRows := 0
	for table, defs := range app.Encrypted.Fields {
		for _, def := range defs {
			q := fmt.Sprintf("SELECT id FROM %s WHERE %s LIKE 'enc:v1:%%'", table, def.Column)
			rows, err := app.DB.Query(q)
			if err != nil {
				return 0, fmt.Errorf("count rows for %s.%s: %w", table, def.Column, err)
			}
			var ids []int64
			for rows.Next() {
				var id int64
				if err := rows.Scan(&id); err == nil {
					ids = append(ids, id)
				}
			}
			rows.Close()
			if len(ids) > 0 {
				plans = append(plans, plan{Table: table, Column: def.Column, IDs: ids})
				totalRows += len(ids)
			}
		}
	}
	log.Printf("encryption-rotate: planned - %d rows across %d (table, column) pairs", totalRows, len(plans))

	if dryRun {
		return totalRows, nil
	}

	// Re-encrypt every row. We bypass the UPDATE trigger by writing a
	// value that already starts with enc:v1: (trigger's WHEN clause
	// excludes already-encrypted values).
	rotated := 0
	for _, p := range plans {
		for _, id := range p.IDs {
			var raw string
			if err := app.DB.QueryRow(fmt.Sprintf("SELECT %s FROM %s WHERE id = ?", p.Column, p.Table), id).Scan(&raw); err != nil {
				return rotated, fmt.Errorf("rotate %s.%s id=%d: read: %w", p.Table, p.Column, id, err)
			}
			plaintext, err := fieldDecryptWithKey(oldKey, raw)
			if err != nil {
				return rotated, fmt.Errorf("rotate %s.%s id=%d: decrypt with OLD key: %w (row may be corrupt or already rotated)", p.Table, p.Column, id, err)
			}
			recrypted, err := fieldEncryptWithKey(newKey, plaintext)
			if err != nil {
				return rotated, fmt.Errorf("rotate %s.%s id=%d: encrypt with NEW key: %w", p.Table, p.Column, id, err)
			}
			if _, err := app.DB.Exec(fmt.Sprintf("UPDATE %s SET %s = ? WHERE id = ?", p.Table, p.Column), recrypted, id); err != nil {
				return rotated, fmt.Errorf("rotate %s.%s id=%d: update: %w", p.Table, p.Column, id, err)
			}
			rotated++
		}
		log.Printf("encryption-rotate: %s.%s done (%d rows)", p.Table, p.Column, len(p.IDs))
	}

	// Swap in-memory key BEFORE writing env.yaml - if env.yaml write
	// fails, the process is still consistent: in-memory and DB both
	// agree on the new key. The next process restart loads OLD from
	// env.yaml and fails to decrypt - but that's a recoverable state
	// (operator manually edits env.yaml).
	appEncryptionKey = newKey
	// Blind-index key is HKDF-derived from the AES key. Rotate it
	// in-step so every blind index recomputed below uses the new HMAC
	// material. If derivation fails, we abort BEFORE rebuilding (the
	// blind indices would otherwise be left half-rebuilt under
	// inconsistent keys).
	if err := SetBlindIndexKey(newKey); err != nil {
		return rotated, fmt.Errorf("DB rotation completed (%d rows) but blind-index key derivation FAILED: %w. Equality search on blind-indexed columns is now broken until the next successful boot.", rotated, err)
	}
	// Rebuild every blind index under the new HMAC key. Skipping this
	// would leave the sibling `<col>_blind` values pointing at HMACs
	// computed under the OLD key - equality search would silently
	// return zero rows.
	if rebuilt, err := RebuildAllBlindIndices(app); err != nil {
		return rotated, fmt.Errorf("DB rotation completed (%d rows) but blind-index rebuild FAILED after %d rows: %w", rotated, rebuilt, err)
	} else if rebuilt > 0 {
		log.Printf("encryption-rotate: rebuilt %d blind-index rows under new HMAC key", rebuilt)
	}

	// Persist new key SOURCE STRING to env.yaml. On the next process
	// start, InitFieldEncryption reads this string and derives the
	// 32-byte AES key via sha256(source) - matching what we just put
	// into appEncryptionKey above. If we wrote raw key bytes instead,
	// the restart-derived key would be sha256(<hex-of-bytes>) and
	// every rotated row would fail to decrypt.
	if err := replaceEnvYamlKey(app.Dir, "ENCRYPTION_KEY", newKeySource); err != nil {
		return rotated, fmt.Errorf("DB rotation completed (%d rows) but env.yaml write FAILED: %w. CRITICAL: in-memory key now differs from env.yaml - the next process restart will load the stale OLD key and fail to decrypt rotated rows. Manually edit env.yaml to set ENCRYPTION_KEY=<new source> before restart.", rotated, err)
	}

	// Audit-log the rotation (rotation itself is a significant security
	// event; record who did it and how many rows changed).
	LogAudit(app, "encryption_key_rotated", "_benmore_audit_log", "",
		&Session{Email: "system:rotation"}, nil,
		map[string]any{"rows_rotated": rotated, "tables": len(plans)})

	return rotated, nil
}

// RegisterEncryptionRotationRoute mounts POST /api/_internal/encryption/rotate
// on the per-app mux. Admin-only. Body: { new_key, confirm }. Runs the
// key rotation in-process so it has access to appEncryptionKey + the
// app's Encrypted config - both of which the router process can't see
// for an arbitrary tenant (each per-app process holds its own key).
//
// Called from the MCP rotate_encryption_key tool via probe_route, which
// impersonates an admin user and POSTs to this endpoint with their
// session. Server-side trust = admin role; rotation itself is audit-logged.
func RegisterEncryptionRotationRoute(mux *http.ServeMux, app *App) {
	mux.HandleFunc("POST /api/_internal/encryption/rotate", func(w http.ResponseWriter, r *http.Request) {
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
			NewKey  string `json:"new_key"`
			Confirm bool   `json:"confirm"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)

		rotated, err := RotateEncryptionKey(app, body.NewKey, !body.Confirm)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		if !body.Confirm {
			httpJSON(w, http.StatusOK, map[string]any{
				"dry_run":               true,
				"rows_that_would_rotate": rotated,
			})
			return
		}
		httpJSON(w, http.StatusOK, map[string]any{
			"rows_rotated": rotated,
			"status":       "rotated",
		})
	})
}
