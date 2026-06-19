//go:build !cli

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
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
	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v3"
)

// Field encryption prefix - makes encrypted values self-describing.
// scanRows auto-decrypts any value starting with this prefix.
//
// Two on-disk ciphertext versions coexist:
//   - encPrefix   ("enc:v1:") legacy AES-256-GCM, NO additional
//     authenticated data (AAD). Still DECRYPTABLE for backward compat;
//     never produced on new writes.
//   - encPrefixV2 ("enc:v2:") AES-256-GCM with table||column bound as
//     AAD (see M-3). New writes use v2 whenever the column context is
//     known (the SQLite trigger path passes it); otherwise v2 with an
//     empty AAD context. Any value that still carries the v1 prefix is
//     decrypted with the legacy no-AAD path.
const encPrefix = "enc:v1:"

// encPrefixV2 tags AAD-bound ciphertext. The benmore_decrypt SQL function,
// DecryptRowFields, and the rotation primitive all dispatch on prefix so
// v1 and v2 values can sit side-by-side in the same column during a
// gradual re-encrypt / key rotation.
const encPrefixV2 = "enc:v2:"

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
//	int64   → strconv.FormatInt(v, 10)          // "50000"
//	float64 → strconv.FormatFloat(v, 'f', -1, 64) // "1.5", "0.1", "1e-300" never
//	string  → as-is
//	[]byte  → string(v)
//	bool    → "0" / "1" (SQLite affinity)
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

// cryptoCtxArgs extracts the optional (table, column) context passed to
// the benmore_encrypt / benmore_decrypt SQL functions as trailing
// arguments. Either may be absent (returns ""). Used to bind v2
// ciphertext to its column via GCM AAD (M-3).
func cryptoCtxArgs(ctx []any) (table, column string) {
	if len(ctx) >= 1 && ctx[0] != nil {
		table = stringifyForCrypto(ctx[0])
	}
	if len(ctx) >= 2 && ctx[1] != nil {
		column = stringifyForCrypto(ctx[1])
	}
	return table, column
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

	derived, err := cryptoDeriveAppKey(keyStr)
	if err != nil {
		return fmt.Errorf("encryption key derivation: %w", err)
	}
	appEncryptionKey = derived
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
			// benmore_encrypt(value[, table, column]) → "enc:v2:...".
			// The optional table/column context (passed by the auto-
			// encryption triggers as SQL literals) binds the ciphertext
			// to its location via GCM AAD (M-3), so a DB-writer can't move
			// an encrypted value to another column and still decrypt it.
			// Called with one arg (no context) it still encrypts, just
			// without the column binding - backward compatible with any
			// hand-written SQL that calls benmore_encrypt(col).
			if err := conn.RegisterFunc("benmore_encrypt", func(value any, ctx ...any) (any, error) {
				if value == nil {
					return nil, nil
				}
				plaintext := stringifyForCrypto(value)
				// M-2: fail closed. Without a key we must NOT write
				// plaintext into a column declared encrypted.
				if appEncryptionKey == nil {
					return "", fmt.Errorf("benmore_encrypt called but ENCRYPTION_KEY not initialized")
				}
				if cryptoIsEncrypted(plaintext) {
					return plaintext, nil // already encrypted (v1 or v2) - idempotent
				}
				table, column := cryptoCtxArgs(ctx)
				return fieldEncryptCtx(appEncryptionKey, table, column, plaintext)
			}, true); err != nil {
				return err
			}

			// benmore_decrypt(ciphertext[, table, column]) → plaintext (TEXT).
			// Type coercion back to INTEGER/REAL happens at the read
			// boundary (scanRows) where the column's declared schema
			// type is known. Keeping the SQL function returning TEXT
			// avoids guesswork - a SQL caller of benmore_decrypt
			// always sees the raw plaintext string and decides what
			// to do with it.
			//
			// When the column is supplied it is enforced against the v2
			// AAD binding (M-3): decrypting a value whose embedded column
			// doesn't match fails closed instead of returning a moved
			// plaintext. Legacy v1 values carry no AAD and skip the check.
			if err := conn.RegisterFunc("benmore_decrypt", func(value any, ctx ...any) (string, error) {
				if value == nil {
					return "", nil
				}
				s := stringifyForCrypto(value)
				if !cryptoIsEncrypted(s) {
					return s, nil // not encrypted - return as-is
				}
				if appEncryptionKey == nil {
					return "", fmt.Errorf("benmore_decrypt called but ENCRYPTION_KEY not initialized")
				}
				_, column := cryptoCtxArgs(ctx)
				return fieldDecryptCtx(appEncryptionKey, column, s)
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
			// table/column SQL string literals passed to benmore_encrypt
			// so the ciphertext is GCM-AAD-bound to its location (M-3).
			// Single-quotes doubled defensively even though these are
			// framework-controlled identifiers, not user input.
			tableLit := "'" + strings.ReplaceAll(table, "'", "''") + "'"
			colLit := "'" + strings.ReplaceAll(col, "'", "''") + "'"
			// AFTER INSERT: encrypt the column value
			triggerName := fmt.Sprintf("_benmore_enc_%s_%s_insert", table, col)
			triggerSQL := fmt.Sprintf(
				"CREATE TRIGGER IF NOT EXISTS %s AFTER INSERT ON %s FOR EACH ROW WHEN NEW.%s IS NOT NULL AND NEW.%s NOT LIKE 'enc:%%' BEGIN UPDATE %s SET %s = benmore_encrypt(NEW.%s, %s, %s) WHERE id = NEW.id; END",
				triggerName, table, col, col, table, col, col, tableLit, colLit,
			)
			if _, err := db.Exec(triggerSQL); err != nil {
				log.Printf("ENCRYPTION TRIGGER ERROR [%s]: %s", triggerName, err)
			} else {
				installed++
			}

			// AFTER UPDATE: encrypt if value changed and isn't already encrypted
			triggerName = fmt.Sprintf("_benmore_enc_%s_%s_update", table, col)
			triggerSQL = fmt.Sprintf(
				"CREATE TRIGGER IF NOT EXISTS %s AFTER UPDATE OF %s ON %s FOR EACH ROW WHEN NEW.%s IS NOT NULL AND NEW.%s NOT LIKE 'enc:%%' BEGIN UPDATE %s SET %s = benmore_encrypt(NEW.%s, %s, %s) WHERE id = NEW.id; END",
				triggerName, col, table, col, col, table, col, col, tableLit, colLit,
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
	if s == "" || cryptoIsEncrypted(s) {
		// Empty or already-encrypted (v1 or v2) - idempotent.
		return
	}
	// Audit-log copies live in a different storage shape (JSON blob) than
	// the source table, so there's no stable table/column to bind as AAD
	// here - encrypt without context. The value is still confidential at
	// rest; the M-3 column-move protection applies to the source columns.
	if enc, err := fieldEncrypt(s); err == nil {
		row[key] = enc
	}
}

// cryptoIsEncrypted reports whether s carries a field-encryption prefix
// (legacy v1 or AAD-bound v2). Centralised so prefix checks stay in sync
// as new versions are added.
func cryptoIsEncrypted(s string) bool {
	return strings.HasPrefix(s, encPrefix) || strings.HasPrefix(s, encPrefixV2)
}

// DecryptRowFields auto-decrypts any values in a row that have the enc: prefix.
// Called from scanRows so ALL query paths get transparent decryption.
func DecryptRowFields(row map[string]any) {
	if appEncryptionKey == nil {
		return
	}
	for k, v := range row {
		if s, ok := v.(string); ok && cryptoIsEncrypted(s) {
			// Pass expectColumn="" here: a result-set key may be an alias
			// or a JOINed column, so we can't reliably equate it with the
			// AAD-bound source column without false rejections. The v2 AAD
			// is still GCM-authenticated (tamper-evident); strict column-
			// move enforcement happens in the benmore_decrypt SQL function
			// where the true column is known.
			if decrypted, err := fieldDecryptCtx(appEncryptionKey, "", s); err == nil {
				row[k] = decrypted
			}
		}
	}
}

// ===== Key derivation (M-4) =====

// cryptoArgon2Prefix tags an ENCRYPTION_KEY value that should be stretched
// with Argon2id instead of a bare SHA-256. Format (all fields decimal /
// base64-std, '$'-separated):
//
//	argon2id$<timeCost>$<memKiB>$<parallelism>$<base64Salt>$<base64Secret>
//
// The derived AES key is Argon2id over <Secret> with <Salt>. This is the
// opt-in strong path: an operator who has a human passphrase encodes it
// once (a small helper / docs cover the encoding) and from then on the
// passphrase is no longer offline-brute-forceable at SHA-256 speed, and
// the per-tenant salt makes identical passphrases derive distinct keys.
const cryptoArgon2Prefix = "argon2id$"

// cryptoDeriveAppKey turns the ENCRYPTION_KEY source string into the
// 32-byte AES-256 key.
//
// Versioned, backward-compatible derivation (M-4):
//
//   - "argon2id$..."  → Argon2id(secret, salt) with embedded params. The
//     safe path for human passphrases: salted + memory-hard, so identical
//     operator strings across tenants no longer collide and offline brute
//     force is expensive.
//   - 64 hex chars / 44-char base64 of exactly 32 bytes → ALREADY strong
//     random key material. We feed it through SHA-256 to land on 32 bytes,
//     which is exactly what InitFieldEncryption + RotateEncryptionKey have
//     always done, so existing ciphertext keeps decrypting.
//   - anything else (a raw passphrase) → legacy SHA-256(passphrase). This
//     is preserved ONLY for backward compatibility with data already
//     encrypted under the v1 single-SHA-256 scheme; changing it would make
//     every existing row undecryptable. We log a loud warning steering the
//     operator to strong key material or the argon2id$ path.
func cryptoDeriveAppKey(keyStr string) ([]byte, error) {
	if strings.HasPrefix(keyStr, cryptoArgon2Prefix) {
		return cryptoDeriveArgon2(keyStr)
	}
	if !cryptoIsStrongKeyMaterial(keyStr) {
		// Warn but stay back-compat: existing rows were sealed under
		// SHA-256(passphrase) and MUST keep decrypting.
		log.Printf("  encryption: WARN ENCRYPTION_KEY looks like a human passphrase, not 32 bytes of random key material. " +
			"Human passphrases are offline-brute-forceable and identical across tenants. " +
			"Use `openssl rand -hex 32`, or the argon2id$ key format, for new apps.")
	}
	// Legacy v1 derivation - kept for backward compatibility.
	hash := sha256.Sum256([]byte(keyStr))
	out := make([]byte, len(hash))
	copy(out, hash[:])
	return out, nil
}

// cryptoIsStrongKeyMaterial reports whether keyStr is exactly 32 bytes of
// random material encoded as hex or standard/URL base64 - i.e. the output
// of `openssl rand -hex 32` / `rand -base64 32`. Used only to decide
// whether to emit the weak-passphrase warning; derivation is unchanged.
func cryptoIsStrongKeyMaterial(keyStr string) bool {
	if b, err := hex.DecodeString(keyStr); err == nil && len(b) == 32 {
		return true
	}
	if b, err := base64.StdEncoding.DecodeString(keyStr); err == nil && len(b) == 32 {
		return true
	}
	if b, err := base64.RawStdEncoding.DecodeString(keyStr); err == nil && len(b) == 32 {
		return true
	}
	return false
}

// cryptoDeriveArgon2 parses the argon2id$ envelope and stretches the
// embedded secret with the embedded salt + params into a 32-byte key.
func cryptoDeriveArgon2(keyStr string) ([]byte, error) {
	parts := strings.Split(keyStr, "$")
	// argon2id $ time $ mem $ par $ salt $ secret  => 6 fields
	if len(parts) != 6 || parts[0] != "argon2id" {
		return nil, fmt.Errorf("argon2id key must be argon2id$<time>$<memKiB>$<par>$<b64salt>$<b64secret>")
	}
	timeCost, err1 := strconv.ParseUint(parts[1], 10, 32)
	memKiB, err2 := strconv.ParseUint(parts[2], 10, 32)
	par, err3 := strconv.ParseUint(parts[3], 10, 8)
	if err1 != nil || err2 != nil || err3 != nil || timeCost == 0 || memKiB == 0 || par == 0 {
		return nil, fmt.Errorf("argon2id params must be positive integers")
	}
	salt, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return nil, fmt.Errorf("argon2id salt must be >=8 bytes of base64")
	}
	secret, err := base64.StdEncoding.DecodeString(parts[5])
	if err != nil || len(secret) == 0 {
		return nil, fmt.Errorf("argon2id secret must be non-empty base64")
	}
	return argon2.IDKey(secret, salt, uint32(timeCost), uint32(memKiB), uint8(par), 32), nil
}

// ===== AES-256-GCM field encryption =====

// cryptoBuildAAD assembles the additional-authenticated-data string that
// binds a v2 ciphertext to its location (M-3). Encoded as
// "<table>\x00<column>". GCM authenticates this value, so a DB-writer who
// copies an encrypted blob into a different column/table produces an AAD
// mismatch and decryption FAILS closed rather than silently returning the
// moved plaintext. Either component may be empty when the context isn't
// known at the call site.
func cryptoBuildAAD(table, column string) []byte {
	return []byte(table + "\x00" + column)
}

func fieldEncrypt(plaintext string) (string, error) {
	return fieldEncryptWithKey(appEncryptionKey, plaintext)
}

// fieldEncryptWithKey is the explicit-key variant - used by the key
// rotation primitive so the rotator can re-encrypt against a NEW key
// while the global appEncryptionKey is still set to the OLD one.
//
// AAD-less convenience wrapper around fieldEncryptCtx. Callers that know
// the table/column should use fieldEncryptCtx so the ciphertext is bound
// to its location (M-3).
func fieldEncryptWithKey(key []byte, plaintext string) (string, error) {
	return fieldEncryptCtx(key, "", "", plaintext)
}

// fieldEncryptCtx seals plaintext with AES-256-GCM, binding table||column
// as AAD, and emits a v2 envelope:
//
//	enc:v2:<hex(aad)>:<hex(nonce||ciphertext)>
//
// The AAD is stored in the envelope so a context-free decrypt (e.g. the
// rotation re-encrypt loop, which only sees the blob) can still recover
// the exact bytes GCM authenticated. GCM integrity means tampering with
// the stored AAD breaks decryption; an additional caller-supplied-context
// check (fieldDecryptCtx) catches column moves where the stored AAD is
// internally consistent but points at the wrong column.
func fieldEncryptCtx(key []byte, table, column, plaintext string) (string, error) {
	// M-2: fail closed. The Go helper used to return plaintext when the
	// key was nil, silently writing cleartext into a column declared
	// encrypted (the SQL benmore_encrypt already failed closed - this
	// brings the Go path in line). A missing key is a configuration
	// error, never a license to store plaintext.
	if key == nil {
		return "", fmt.Errorf("field encryption requested but no encryption key is initialized (ENCRYPTION_KEY missing)")
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
	aad := cryptoBuildAAD(table, column)
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), aad)
	incEncryptionEnc()
	return encPrefixV2 + hex.EncodeToString(aad) + ":" + hex.EncodeToString(ciphertext), nil
}

func fieldDecrypt(value string) (string, error) {
	return fieldDecryptCtx(appEncryptionKey, "", value)
}

// fieldDecryptWithKey is the explicit-key variant - used by the key
// rotation primitive so the rotator can decrypt with the OLD key
// while the global appEncryptionKey may already point at the NEW one.
func fieldDecryptWithKey(key []byte, value string) (string, error) {
	return fieldDecryptCtx(key, "", value)
}

// fieldDecryptCtx decrypts a v1 (no-AAD) or v2 (AAD-bound) ciphertext.
//
// expectColumn, when non-empty, is the column the value is being read
// from. For v2 values it is checked against the column component embedded
// in the authenticated AAD: a mismatch means the blob was moved between
// columns by a DB-writer, so we fail closed rather than hand back the
// plaintext that GCM would otherwise validate (it validates because the
// stored AAD is self-consistent; only the caller knows the expected
// location). v1 values predate AAD and skip this check.
func fieldDecryptCtx(key []byte, expectColumn, value string) (string, error) {
	switch {
	case strings.HasPrefix(value, encPrefixV2):
		// fall through to v2 path
	case strings.HasPrefix(value, encPrefix):
		// fall through to legacy v1 path
	default:
		return value, nil // not encrypted - return as-is
	}
	if key == nil {
		// M-2 (read side): no key means we cannot authenticate the
		// ciphertext. Never strip the prefix and hand back a raw blob as
		// if it were plaintext; surface the misconfiguration instead.
		return "", fmt.Errorf("encrypted value encountered but no encryption key is initialized (ENCRYPTION_KEY missing)")
	}
	incEncryptionDec()

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()

	if strings.HasPrefix(value, encPrefixV2) {
		body := strings.TrimPrefix(value, encPrefixV2)
		sep := strings.IndexByte(body, ':')
		if sep < 0 {
			return "", fmt.Errorf("malformed v2 ciphertext envelope")
		}
		aad, err := hex.DecodeString(body[:sep])
		if err != nil {
			return "", fmt.Errorf("v2 ciphertext: bad AAD encoding: %w", err)
		}
		// Bind-check: the stored AAD's column component must match the
		// column we're reading from. Catches a DB-writer relocating an
		// encrypted value to a different column.
		if expectColumn != "" {
			if _, gotCol, ok := cryptoParseAAD(aad); !ok || gotCol != expectColumn {
				return "", fmt.Errorf("v2 ciphertext AAD does not match column %q (value may have been moved)", expectColumn)
			}
		}
		ciphertext, err := hex.DecodeString(body[sep+1:])
		if err != nil {
			return "", err
		}
		if len(ciphertext) < nonceSize {
			return "", fmt.Errorf("ciphertext too short")
		}
		nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
		plaintext, err := gcm.Open(nil, nonce, ct, aad)
		if err != nil {
			return "", err
		}
		return string(plaintext), nil
	}

	// Legacy v1: no AAD.
	ciphertextHex := strings.TrimPrefix(value, encPrefix)
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// cryptoParseAAD splits a "<table>\x00<column>" AAD blob back into its
// components. ok is false when the blob isn't in the expected shape.
func cryptoParseAAD(aad []byte) (table, column string, ok bool) {
	i := strings.IndexByte(string(aad), 0)
	if i < 0 {
		return "", "", false
	}
	s := string(aad)
	return s[:i], s[i+1:], true
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
//   - caller can pass `--resume-skip-undecryptable` to make this safe.
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
	// Derive the new AES key via the SAME versioned derivation as
	// InitFieldEncryption (M-4), so a restart that re-reads the persisted
	// source string lands on the identical key (whether it's strong hex
	// material or an argon2id$ envelope).
	newKey, err := cryptoDeriveAppKey(newKeySource)
	if err != nil {
		return 0, fmt.Errorf("derive new key: %w", err)
	}

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
			// Catch BOTH legacy v1 and AAD-bound v2 ciphertext (M-3) so a
			// key rotation re-encrypts every encrypted row regardless of
			// which format it was last written in.
			q := fmt.Sprintf("SELECT id FROM %s WHERE %s LIKE 'enc:v1:%%' OR %s LIKE 'enc:v2:%%'", table, def.Column, def.Column)
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
			// Decrypt enforcing the v2 column binding: a value whose AAD
			// names a different column than where it lives is a tamper /
			// move and must not be silently re-bound under the new key.
			// v1 values carry no AAD and skip the check.
			plaintext, err := fieldDecryptCtx(oldKey, p.Column, raw)
			if err != nil {
				return rotated, fmt.Errorf("rotate %s.%s id=%d: decrypt with OLD key: %w (row may be corrupt, moved, or already rotated)", p.Table, p.Column, id, err)
			}
			// Re-encrypt as v2, re-binding table||column as AAD (M-3) so
			// rotation upgrades legacy v1 rows to the bound format too.
			recrypted, err := fieldEncryptCtx(newKey, p.Table, p.Column, plaintext)
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
				"dry_run":                true,
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
