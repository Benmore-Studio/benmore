//go:build !cli

package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
//
// SCOPE WARNING: this is a process GLOBAL. In a per-app process (benmore
// serve / benmore-app@ unit) there is exactly one app, so the global is
// always the right key. In the ROUTER process (dashboard SQL console, MCP
// sql/query_db, promote) MANY tenants' databases are opened side by side -
// the global is at best some other app's key and at worst nil. Every
// multi-tenant path must resolve keys through dbCryptoRegistry (below),
// keyed by the canonical data.db path, with the global only as the
// single-app fallback. Pre-v2.7.194 the router used the bare global, which
// meant `benmore sql --write` encrypted tenant rows under the WRONG key -
// the app process could never read them back (and vice versa).
var appEncryptionKey []byte

// appEncryptionKeyEphemeral reports that appEncryptionKey was generated for
// this process only (no ENCRYPTION_KEY configured and none persisted), so
// nothing sealed under it survives a restart.
var appEncryptionKeyEphemeral bool

// dbCryptoKeys carries the derived key material for one database file.
type dbCryptoKeys struct {
	aes   []byte // 32-byte AES-256-GCM key
	blind []byte // HKDF-derived blind-index HMAC key
	// ephemeral: generated for this process only. Values that must outlive
	// the process (TOTP secrets) are not sealed under such a key.
	ephemeral bool
}

// dbCryptoRegistry maps canonical data.db paths → *dbCryptoKeys. Populated:
//   - by InitFieldEncryption (per-app process boot) for the app's own DB
//   - by the router's dashboardOpenRO/RW (platform_dashboard.go), which
//     resolve each tenant's ENCRYPTION_KEY from the per-app env store /
//     env.yaml before handing out a connection pool
//
// Consulted per-call by the benmore_encrypt / benmore_decrypt /
// benmore_blind_index SQL functions (via the connection's own filename)
// and by DecryptRowFields, so the same binary does the right thing in
// both single-app and multi-tenant processes.
var dbCryptoRegistry sync.Map

// canonicalDBPath normalizes a database file path for registry lookups.
// Symlinks resolved + absolute so the path SQLite reports for a connection
// (conn.GetFilename) and the path the opener registered always collide.
func canonicalDBPath(p string) string {
	if p == "" {
		return ""
	}
	if a, err := filepath.Abs(p); err == nil {
		p = a
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	// File may not exist yet (registration precedes first open/create).
	// Resolve the DIRECTORY instead - that's where the symlinks live
	// (macOS /var → /private/var, /tmp → /private/tmp) - and reattach
	// the basename.
	dir, base := filepath.Split(p)
	if r, err := filepath.EvalSymlinks(filepath.Clean(dir)); err == nil {
		return filepath.Join(r, base)
	}
	return p
}

// RegisterDBEncryptionKey installs the derived AES key (plus the HKDF
// blind-index sibling) for one database file. Idempotent; last write wins
// (key rotation re-registers). The key is a configured, durable one.
func RegisterDBEncryptionKey(dbPath string, aesKey []byte) {
	registerDBEncryptionKey(dbPath, aesKey, false)
}

func registerDBEncryptionKey(dbPath string, aesKey []byte, ephemeral bool) {
	if dbPath == "" || len(aesKey) == 0 {
		return
	}
	blind, err := DeriveBlindIndexKey(aesKey)
	if err != nil {
		log.Printf("  encryption: blind-index derivation for %s failed: %s", dbPath, err)
		blind = nil
	}
	dbCryptoRegistry.Store(canonicalDBPath(dbPath), &dbCryptoKeys{aes: aesKey, blind: blind, ephemeral: ephemeral})
}

// cryptoKeysForDBPath returns the registered keys for a database file, or
// nil when the path is unknown (single-app fallback: the process globals).
func cryptoKeysForDBPath(p string) *dbCryptoKeys {
	if p == "" {
		return nil
	}
	if v, ok := dbCryptoRegistry.Load(canonicalDBPath(p)); ok {
		return v.(*dbCryptoKeys)
	}
	return nil
}

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
	return initFieldEncryption(dir, config, GetEnv(dir, "ENCRYPTION_KEY"))
}

func initFieldEncryption(dir string, config *EncryptedFieldConfig, keyStr string) error {
	// Always initialize the key, even when the app has no encrypted.yaml
	// - the framework itself uses fieldEncrypt for OAuth provider tokens
	// stored in _benmore_oauth_tokens. Without this, those tokens silently
	// fall through to plaintext-at-rest.
	if config == nil {
		config = &EncryptedFieldConfig{}
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
	// ephemeral: the key below exists only in this process. TOTP secrets
	// stay unsealed under such a key (see totpSealKey).
	ephemeral := false
	if keyStr == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("failed to generate encryption key: %w", err)
		}
		keyStr = hex.EncodeToString(b)
		ephemeral = true

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
				ephemeral = false
				log.Printf("  encryption: generated ENCRYPTION_KEY → env.yaml")
				log.Printf("  For production, set ENCRYPTION_KEY in env.yaml or your environment")
			}
		}
	}

	derived, err := cryptoDeriveAppKey(keyStr)
	if err != nil {
		return fmt.Errorf("encryption key derivation: %w", err)
	}
	if !isolateAppEnvironment.Load() {
		appEncryptionKey = derived
		appEncryptionKeyEphemeral = ephemeral
	}
	// Shared processes use only the per-database registry.
	registerDBEncryptionKey(filepath.Join(dir, "data.db"), derived, ephemeral)
	// Blind-index key is HKDF-derived from the AES key so it has the
	// same lifecycle (rotated with the encryption key) but is
	// cryptographically distinct material. Failure to derive is fatal
	// - the SQL function will refuse to compute HMACs without it, and
	// then any insert into a blind-indexed column would error.
	if !isolateAppEnvironment.Load() {
		if err := SetBlindIndexKey(derived); err != nil {
			return fmt.Errorf("blind-index key derivation: %w", err)
		}
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
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0600); err != nil {
		return err
	}
	chownToDirOwner(path, dir) // ownership seam fix - see fileowner_unix.go
	return nil
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

	if _, err = fmt.Fprintf(f, "\n# Auto-generated encryption key - do NOT commit this file\n%s: %s\n", key, value); err != nil {
		return err
	}
	chownToDirOwner(path, dir)
	return nil
}

// RegisterEncryptedSQLiteDriver registers a custom SQLite driver with
// benmore_encrypt() and benmore_decrypt() SQL functions available in
// every connection - triggers, queries, generated columns, everything.
func RegisterEncryptedSQLiteDriver() {
	sql.Register("sqlite3_benmore", benmoreSQLiteDriver(true))
	// Framework maintenance on a database that is not being served (a restore
	// candidate, a file being recovered) needs the same SQL functions, so app
	// triggers still compile, but not the storage ceiling: it never grows the
	// served database through SQLite.
	sql.Register(sqliteMaintenanceDriver, benmoreSQLiteDriver(false))
}

// sqliteMaintenanceDriver is the framework driver without the storage
// ceiling. Only framework maintenance code opens it; app SQL never runs on it.
const sqliteMaintenanceDriver = "sqlite3_benmore_maintenance"

// benmoreSQLiteDriver prepares every framework-driver connection: the
// benmore_* SQL functions, the ATTACH ban and, when enforceStorageLimit is
// set, the storage ceiling.
func benmoreSQLiteDriver(enforceStorageLimit bool) *sqlite3.SQLiteDriver {
	return &sqlite3.SQLiteDriver{
		ConnectHook: func(conn *sqlite3.SQLiteConn) error {
			// Resolve the connection's OWN database file once, so the
			// SQL functions below can pick the per-DB key from
			// dbCryptoRegistry per call. Registration may happen after
			// the pool opened this connection, so the lookup is per-call
			// (cheap sync.Map read), only the filename is captured here.
			// Falls back to the process-global keys when the path is
			// unregistered - the single-app process case.
			connDB := canonicalDBPath(conn.GetFilename("main"))
			aesKeyForConn := func() []byte {
				if k := cryptoKeysForDBPath(connDB); k != nil {
					return k.aes
				}
				if isolateAppEnvironment.Load() {
					return nil
				}
				return appEncryptionKey
			}
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
				key := aesKeyForConn()
				// M-2: fail closed. Without a key we must NOT write
				// plaintext into a column declared encrypted.
				if key == nil {
					return "", fmt.Errorf("benmore_encrypt called but ENCRYPTION_KEY not initialized")
				}
				if cryptoIsEncrypted(plaintext) {
					return plaintext, nil // already encrypted (v1 or v2) - idempotent
				}
				table, column := cryptoCtxArgs(ctx)
				return fieldEncryptCtx(key, table, column, plaintext)
			}, true); err != nil {
				return err
			}
			// This entry point treats every non-NULL argument as plaintext; unlike
			// benmore_encrypt it never trusts a caller-supplied enc: prefix.
			if err := conn.RegisterFunc("benmore_encrypt_plaintext", func(value, tableValue, columnValue any) (any, error) {
				if value == nil {
					return nil, nil
				}
				table, column := stringifyForCrypto(tableValue), stringifyForCrypto(columnValue)
				if table == "" || column == "" {
					return "", fmt.Errorf("benmore_encrypt_plaintext requires table and column context")
				}
				key := aesKeyForConn()
				if len(key) == 0 {
					return "", fmt.Errorf("benmore_encrypt_plaintext called but ENCRYPTION_KEY not initialized")
				}
				return fieldEncryptCtx(key, table, column, stringifyForCrypto(value))
			}, false); err != nil {
				return err
			}
			// Trigger recursion and key rotation must recognize only authentic
			// ciphertext bound to this field, never an enc: prefix by itself.
			if err := conn.RegisterFunc("benmore_ciphertext_matches", func(value, tableValue, columnValue any) bool {
				if value == nil {
					return false
				}
				table, column := stringifyForCrypto(tableValue), stringifyForCrypto(columnValue)
				return fieldCiphertextMatches(aesKeyForConn(), table, column, stringifyForCrypto(value))
			}, false); err != nil {
				return err
			}

			// History retains the source field's AAD. Authenticate existing
			// ciphertext too: an enc: prefix alone is never proof of sealing.
			if err := conn.RegisterFunc("benmore_history_encrypt", func(value any, table, column string) (any, error) {
				return sealVersionedValue(value, aesKeyForConn(), table, column)
			}, false); err != nil {
				return err
			}

			if err := conn.RegisterFunc("benmore_history_normalized", func(old, next any, table, column string) (bool, error) {
				return versionedStorageNormalization(old, next, aesKeyForConn(), table, column)
			}, false); err != nil {
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
				key := aesKeyForConn()
				if key == nil {
					return "", fmt.Errorf("benmore_decrypt called but ENCRYPTION_KEY not initialized")
				}
				_, column := cryptoCtxArgs(ctx)
				return fieldDecryptCtx(key, column, s)
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
				// Per-DB blind key when registered (router / multi-app);
				// process-global fallback otherwise.
				if k := cryptoKeysForDBPath(connDB); k != nil && len(k.blind) > 0 {
					return BlindIndexHMACWithKey(k.blind, stringifyForCrypto(value)), nil
				}
				if isolateAppEnvironment.Load() {
					return "", fmt.Errorf("database encryption key is not registered")
				}
				return BlindIndexHMAC(stringifyForCrypto(value))
			}, true); err != nil {
				return err
			}

			// benmore_totp_valid(secret, code) → 1/0.
			//
			// Exposes the framework's authenticator check (ValidateTOTP,
			// mfa.go) to SQL so an app can build its own step-up gate -
			// "prove it's really you before entering the admin portal" -
			// against the user's ALREADY-ENABLED TOTP secret. The platform
			// MFA endpoints can't serve that: /api/_auth/mfa/verify only
			// validates the `pending:` enrollment secret and flips MFA on,
			// so there was no way to re-check an enrolled factor mid-session.
			//
			// Why a SQL function rather than an endpoint: the flow layer
			// (`run: sql`) is where app-authored gates live, and this keeps
			// the secret inside the database engine. It is read by the
			// comparison and never crosses into flow params, request bodies,
			// compute steps, or logs - all places an app author could
			// accidentally persist it.
			//
			// A `pending:` secret is deliberately refused: an enrollment
			// that was started and abandoned is not a factor anyone has
			// proven they hold.
			//
			// NOT pure (final arg false), unlike the crypto functions above:
			// the result depends on the current 30-second time step, so
			// SQLite must re-evaluate it per row and per statement rather
			// than caching or hoisting a verdict that goes stale.
			//
			// Secrets sealed at rest (mfa_secret_store.go) are opened here
			// with this connection's key; one that can't be opened fails
			// closed, like a malformed secret.
			if err := conn.RegisterFunc("benmore_totp_valid", func(secret, code string) bool {
				secret = strings.TrimSpace(secret)
				code = strings.TrimSpace(code)
				if secret == "" || code == "" || strings.HasPrefix(secret, totpPendingPrefix) {
					return false
				}
				if cryptoIsEncrypted(secret) {
					plain, err := fieldDecryptCtx(aesKeyForConn(), totpSecretColumn, secret)
					if err != nil {
						return false
					}
					secret = plain
				}
				return ValidateTOTP(secret, code)
			}, false); err != nil {
				return err
			}
			if err := registerBenmoreToday(conn, time.Now); err != nil {
				return err
			}
			if err := registerVersionHistoryClock(conn, time.Now); err != nil {
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

			// Storage ceiling (storage_limit.go): a write that would grow a
			// database with a registered limit past it fails with SQLITE_FULL
			// on every code path that uses this driver.
			if !enforceStorageLimit {
				return nil
			}
			return applyDBStorageLimit(conn, connDB)
		},
	}
}

// InstallEncryptionTriggers atomically replaces the INSERT/UPDATE triggers
// that encrypt configured columns. A failed replacement leaves the prior set.
func InstallEncryptionTriggers(db *sql.DB, config *EncryptedFieldConfig) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin encrypted-field trigger replacement: %w", err)
	}
	defer tx.Rollback()
	if err := installEncryptionTriggersWith(tx, config); err != nil {
		return err
	}
	return tx.Commit()
}

// Shared with reload's atomic encryption, blind-index and history installation.
func installEncryptionTriggersWith(tx mutationTx, config *EncryptedFieldConfig) error {
	return installEncryptionTriggersMode(tx, config, true)
}

func installEncryptionTriggersMode(tx mutationTx, config *EncryptedFieldConfig, replace bool) error {
	if config == nil {
		return nil
	}
	fields := 0
	for _, defs := range config.Fields {
		fields += len(defs)
	}
	if fields > 0 {
		key, err := cryptoKeyForQuerierChecked(tx)
		if err != nil {
			return fmt.Errorf("resolve encryption key for triggers: %w", err)
		}
		if len(key) == 0 {
			return fmt.Errorf("cannot install encrypted-field triggers without ENCRYPTION_KEY")
		}
	}
	if replace {
		rows, err := tx.Query("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE '_benmore_enc_%'")
		if err != nil {
			return fmt.Errorf("list existing encrypted-field triggers: %w", err)
		}
		var triggers []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return fmt.Errorf("read existing encrypted-field trigger: %w", err)
			}
			triggers = append(triggers, name)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return fmt.Errorf("read existing encrypted-field triggers: %w", err)
		}
		for _, name := range triggers {
			if _, err := tx.Exec("DROP TRIGGER IF EXISTS " + quoteIdent(name)); err != nil {
				return fmt.Errorf("drop encrypted-field trigger %q: %w", name, err)
			}
		}
	}

	var installed int
	for table, defs := range config.Fields {
		cols, err := mainTableColumnsWith(tx, table)
		if err != nil {
			return err
		}
		for _, def := range defs {
			col := def.Column
			if !versionHasColumn(cols, col) {
				return fmt.Errorf("encrypted field %s.%s: source column does not exist", table, col)
			}
			// The trigger text below is written with bare names, and the
			// connector's trigger check regenerates exactly that text
			// (verifyAppMCPDeclaredTriggerClosure), so the names must be
			// plain identifiers. A checked load already refused anything
			// else; a config read without that check gets no trigger.
			if !membershipIdentRe.MatchString(table) || !membershipIdentRe.MatchString(col) {
				return fmt.Errorf("encrypted-field trigger %q.%q is not a plain table and column name", table, col)
			}
			// Table/column SQL string literals bind ciphertext to its field
			// through benmore_encrypt_plaintext (M-3).
			// Single-quotes doubled defensively even though these are
			// framework-controlled identifiers, not user input.
			tableLit := "'" + strings.ReplaceAll(table, "'", "''") + "'"
			colLit := "'" + strings.ReplaceAll(col, "'", "''") + "'"
			// AFTER INSERT: encrypt the column value.
			//
			// Use WHERE rowid = NEW.rowid (not WHERE id = NEW.id):
			// every SQLite table has an integer rowid regardless of how
			// the primary-key column is named.  Tables whose PK is NOT
			// named "id" (e.g. account_id, external_id, mt_id…) would
			// produce "no such column: id" inside the trigger body,
			// causing the original INSERT to fail with a trigger error.
			// rowid is always available (except WITHOUT ROWID tables,
			// which the framework never emits) and equals NEW.id for
			// INTEGER PRIMARY KEY tables, so this is fully back-compat.
			triggerName := fmt.Sprintf("_benmore_enc_%s_%s_insert", table, col)
			triggerSQL := fmt.Sprintf(
				"CREATE TRIGGER IF NOT EXISTS %s AFTER INSERT ON %s FOR EACH ROW WHEN NEW.%s IS NOT NULL AND NOT benmore_ciphertext_matches(NEW.%s, %s, %s) BEGIN UPDATE %s SET %s = benmore_encrypt_plaintext(NEW.%s, %s, %s) WHERE rowid = NEW.rowid; END",
				triggerName, table, col, col, tableLit, colLit, table, col, col, tableLit, colLit,
			)
			if _, err := tx.Exec(triggerSQL); err != nil {
				return fmt.Errorf("create encrypted-field trigger %q: %w", triggerName, err)
			}
			installed++

			// AFTER UPDATE: encrypt if the value is not authentic field ciphertext.
			// Same rowid fix as the INSERT trigger above.
			triggerName = fmt.Sprintf("_benmore_enc_%s_%s_update", table, col)
			triggerSQL = fmt.Sprintf(
				"CREATE TRIGGER IF NOT EXISTS %s AFTER UPDATE OF %s ON %s FOR EACH ROW WHEN NEW.%s IS NOT NULL AND NOT benmore_ciphertext_matches(NEW.%s, %s, %s) BEGIN UPDATE %s SET %s = benmore_encrypt_plaintext(NEW.%s, %s, %s) WHERE rowid = NEW.rowid; END",
				triggerName, col, table, col, col, tableLit, colLit, table, col, col, tableLit, colLit,
			)
			if _, err := tx.Exec(triggerSQL); err != nil {
				return fmt.Errorf("create encrypted-field trigger %q: %w", triggerName, err)
			}
			installed++
		}
	}
	if installed > 0 {
		log.Printf("  encryption: %d triggers installed", installed)
	}
	return nil
}

// encryptedRowIDsSQL lists the rows of table whose column holds ciphertext
// (v1 or v2). The column is qualified so a name the table does not have is an
// error, not a comparison with a string (quoteColumn).
func encryptedRowIDsSQL(table, column string) string {
	col := quoteColumn(table, column)
	return "SELECT rowid FROM " + quoteIdent(table) + " WHERE " + col + " LIKE 'enc:v1:%' OR " + col + " LIKE 'enc:v2:%'"
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
	encData, encErr := os.ReadFile(fmt.Sprintf("%s/encrypted.yaml", dir))
	if encErr != nil {
		encData = nil
	}
	appData, appErr := os.ReadFile(fmt.Sprintf("%s/app.yaml", dir))
	if appErr != nil {
		appData = nil
	}
	return parseEncryptedFieldsConfig(encData, appData)
}

// parseEncryptedFieldsConfig is LoadEncryptedFieldsConfig over file
// contents (nil = file absent), so write-time validators can evaluate a
// not-yet-written encrypted.yaml / app.yaml with the same precedence.
func parseEncryptedFieldsConfig(encData, appData []byte) *EncryptedFieldConfig {
	config := &EncryptedFieldConfig{Fields: make(map[string][]EncryptedFieldDef)}

	// 1. Dedicated encrypted.yaml (preferred)
	if data := encData; data != nil {
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
		if yamlUnmarshal(data, &wrapper) == nil {
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
	if data := appData; data != nil {
		var raw EncryptedYAML
		if yamlUnmarshal(data, &raw) == nil && len(raw.Encrypted) > 0 {
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

// MaskEncryptedFields applies the column's unmask policy to each returned row.
// Tenant roles authorize only rows in the session's effective tenant. A row
// without its tenant key (or the tenant-root id) stays masked unless a global
// or explicit owner grant applies. It never reloads scope from a current row:
// historical rows and projected SQL results must carry their own identity.
func MaskEncryptedFields(app *App, table string, rows []map[string]any, session *Session) {
	if app == nil {
		return
	}
	var db rowQuerier
	if app.DB != nil {
		db = app.DB
	}
	maskEncryptedFieldsWith(app, db, table, rows, session)
}

// The explicit querier keeps command reads on their authority transaction,
// rather than opening another connection while that transaction holds locks.
func maskEncryptedFieldsWith(app *App, db rowQuerier, table string, rows []map[string]any, session *Session) {
	if app == nil || app.Encrypted == nil {
		return
	}
	for _, def := range app.Encrypted.Fields[table] {
		access := encryptedFieldAccessFor(app, db, table, def, session)
		for _, row := range rows {
			if def.BlindIndex {
				delete(row, def.Column+blindColSuffix)
			}
			if access.allowsRow(row) {
				continue
			}
			if val, ok := row[def.Column]; ok && val != nil {
				row[def.Column] = maskValue(fmt.Sprintf("%v", val))
			}
		}
	}
}

// encryptedFieldAccess is shared by response masking and SQL filtering so
// a filter cannot reveal a value that the matching response would mask.
type encryptedFieldAccess struct {
	allRows      bool
	tenantColumn string
	tenantID     string
	ownerID      int64
}

func encryptedTenantColumn(app *App, table string) string {
	if app == nil || app.Group == nil || app.Group.Key == "" {
		return ""
	}
	if hasColumn(app, table, app.Group.Key) {
		return app.Group.Key
	}
	if tenantRootTable(app, table) && hasColumn(app, table, "id") {
		return "id"
	}
	return ""
}

func encryptedFieldAccessFor(app *App, db rowQuerier, table string, def EncryptedFieldDef, session *Session) encryptedFieldAccess {
	if len(def.Roles) == 0 {
		return encryptedFieldAccess{allRows: true}
	}
	access := encryptedFieldAccess{}
	if q, ok := db.(*sql.DB); ok && q == nil {
		db = nil
	}
	if session == nil {
		return access
	}
	var roles []string
	for _, role := range def.Roles {
		if role == "self" || role == "owner" {
			if hasColumn(app, table, "user_id") {
				access.ownerID = session.UserID
			}
		} else {
			roles = append(roles, role)
		}
	}
	// A stepped-in admin or tenant-bound connector keeps authority inside
	// its selected tenant, but must not regain the cross-tenant shortcut.
	connectorBound := session.connectorGrant && (session.EffectiveHasGroup() || app != nil && app.Group != nil && app.Group.Table != "")
	bound := session.ActingAsGroup != "" || connectorBound
	if !bound {
		if tier, args, ok := globalRoleTier(session, roles); ok {
			if tier == "1=1" {
				access.allRows = true
			} else if db != nil {
				var held bool
				access.allRows = db.QueryRow("SELECT "+tier, args...).Scan(&held) == nil && held
			}
		}
		if session.IsAdminBypass() {
			access.allRows = true
		}
	}
	if access.allRows || !HasAnyRole(session, roles) {
		return access
	}
	col := encryptedTenantColumn(app, table)
	if col != "" && session.EffectiveHasGroup() {
		access.tenantColumn, access.tenantID = col, session.EffectiveGroupID()
	} else if col == "" && groupSharedTable(app, table) {
		// Explicit shared reference catalogs have no per-tenant rows. Their
		// role semantics match tableModeAllowed's groups.shared exception.
		access.allRows = true
	}
	return access
}

func (access encryptedFieldAccess) allowsRow(row map[string]any) bool {
	if access.allRows || access.ownerID != 0 && rowOwnedBy(row, access.ownerID) {
		return true
	}
	if access.tenantColumn != "" {
		for col, value := range row {
			if sqliteIdentifierFold(col) == sqliteIdentifierFold(access.tenantColumn) && value != nil {
				return stringifyForCrypto(value) == access.tenantID
			}
		}
	}
	return false
}

// scopePredicate bounds an operation that examines the encrypted value to
// exactly the rows the caller may unmask. Column names come from app schema.
func (access encryptedFieldAccess) scopePredicate(table string) (string, []any) {
	if access.allRows {
		return "", nil
	}
	var clauses []string
	var args []any
	if access.tenantColumn != "" {
		clauses = append(clauses, quoteColumn(table, access.tenantColumn)+" = ?")
		args = append(args, access.tenantID)
	}
	if access.ownerID != 0 {
		clauses = append(clauses, quoteColumn(table, "user_id")+" = ?")
		args = append(args, access.ownerID)
	}
	if len(clauses) == 0 {
		return "0=1", nil
	}
	return "(" + strings.Join(clauses, " OR ") + ")", args
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
func encryptAuditFieldsCopy(config *EncryptedFieldConfig, table string, row map[string]any, aesKey []byte) map[string]any {
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
		encryptOneAuditField(out, def.Column, aesKey)
		encryptOneAuditField(out, "old_"+def.Column, aesKey)
	}
	return out
}

func encryptOneAuditField(row map[string]any, key string, aesKey []byte) {
	v, ok := row[key]
	if !ok || v == nil {
		return
	}
	s := stringifyForCrypto(v)
	if s == "" || cryptoIsEncrypted(s) {
		// Empty or already-encrypted (v1 or v2) - idempotent.
		return
	}
	// Audit-log copies live in a different storage shape (JSON blob) than
	// the source table, so there's no stable table/column to bind as AAD
	// here - encrypt without context. The value is still confidential at
	// rest; the M-3 column-move protection applies to the source columns.
	if enc, err := fieldEncryptWithKey(aesKey, s); err == nil && cryptoIsEncrypted(enc) {
		row[key] = enc
	} else {
		row[key] = decryptFailMask
	}
}

// cryptoIsEncrypted reports whether s carries a field-encryption prefix
// (legacy v1 or AAD-bound v2). Centralised so prefix checks stay in sync
// as new versions are added.
func cryptoIsEncrypted(s string) bool {
	return strings.HasPrefix(s, encPrefix) || strings.HasPrefix(s, encPrefixV2)
}

func fieldCiphertextMatches(key []byte, table, column, value string) bool {
	if len(key) == 0 || table == "" || column == "" || !cryptoIsEncrypted(value) {
		return false
	}
	if strings.HasPrefix(value, encPrefixV2) {
		body := strings.TrimPrefix(value, encPrefixV2)
		sep := strings.IndexByte(body, ':')
		if sep < 0 {
			return false
		}
		aad, err := hex.DecodeString(body[:sep])
		if err != nil {
			return false
		}
		storedTable, storedColumn, ok := cryptoParseAAD(aad)
		if !ok || storedTable != table || storedColumn != column {
			return false
		}
	}
	_, err := fieldDecryptCtx(key, column, value)
	return err == nil
}

// decryptFailMask replaces a value that LOOKS encrypted but could not be
// decrypted under the owning database key. Returning the raw `enc:v1:…` ciphertext
// to an API client is both a data leak (ciphertext is still confidential
// material) and silent data corruption from the client's point of view -
// nothing errors, nothing logs, the UI just renders gibberish. The mask
// is deliberately bracketed prose (not hex-like) so a UI shows an
// obviously-wrong-but-diagnosable value, and it can never be mistaken
// for plaintext by a round-tripping client.
const decryptFailMask = "[unavailable: decryption failed]"

// decryptFailLastLog throttles the decrypt-failure log line (unix seconds).
// A 1000-row list of undecryptable values must not emit 1000 log lines.
var decryptFailLastLog atomic.Int64

func logDecryptFailureThrottled(key string) {
	now := time.Now().Unix()
	last := decryptFailLastLog.Load()
	if now-last < 30 {
		return
	}
	if decryptFailLastLog.CompareAndSwap(last, now) {
		log.Printf("ENCRYPTION: failed to decrypt value(s) in column %q under the owning database key - returning %q to callers. The active ENCRYPTION_KEY does not match the key that wrote this data (rotated env.yaml? seeded ciphertext from another environment?). Fix the key or re-encrypt the data. (throttled: at most one line per 30s)", key, decryptFailMask)
	}
}

// cryptoKeyForQuerier resolves only the database being queried. Resolve before
// opening result rows, including on *sql.Tx, to avoid nested active cursors.
func cryptoKeyForQuerier(db mutationQuerier) []byte {
	key, err := cryptoKeyForQuerierChecked(db)
	if err != nil && !isolateAppEnvironment.Load() {
		return appEncryptionKey
	}
	return key
}

func cryptoKeyForQuerierChecked(db mutationQuerier) ([]byte, error) {
	var path string
	if err := db.QueryRow("SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&path); err != nil {
		return nil, err
	}
	if keys := cryptoKeysForDBPath(path); keys != nil {
		return keys.aes, nil
	}
	if isolateAppEnvironment.Load() {
		return nil, nil
	}
	return appEncryptionKey, nil
}

// cryptoKeyForQuerierMainChecked is for strict transaction authority reads.
// Explicitly naming main prevents a TEMP pragma_database_list table from
// redirecting database identity. Unknown database identity fails closed; the
// process-wide single-app fallback is intentionally unavailable here.
func cryptoKeyForQuerierMainChecked(db mutationQuerier) ([]byte, error) {
	path, err := mainDatabasePathForQuerier(db)
	if err != nil {
		return nil, err
	}
	keys := cryptoKeysForDBPath(path)
	if keys == nil || len(keys.aes) == 0 {
		return nil, fmt.Errorf("database encryption key is not registered")
	}
	return keys.aes, nil
}

func mainDatabasePathForQuerier(db rowQuerier) (string, error) {
	var path string
	if err := db.QueryRow("SELECT file FROM main.pragma_database_list WHERE name = 'main'").Scan(&path); err != nil {
		return "", err
	}
	if path == "" {
		return "", fmt.Errorf("main database path is unavailable")
	}
	return path, nil
}

func fieldEncryptForDB(db mutationQuerier, value string) (string, error) {
	key := cryptoKeyForQuerier(db)
	if len(key) == 0 && isolateAppEnvironment.Load() {
		return "", fmt.Errorf("database encryption key is not registered")
	}
	return fieldEncryptWithKey(key, value)
}

func fieldDecryptForDB(db mutationQuerier, value string) (string, error) {
	return fieldDecryptCtx(cryptoKeyForQuerier(db), "", value)
}

// DecryptRowFields decrypts with the caller's database key only. Authenticated
// ciphertext does not grant permission to try another tenant's key.
func DecryptRowFields(row map[string]any, key []byte) {
	for k, v := range row {
		s, ok := v.(string)
		if !ok || !cryptoIsEncrypted(s) {
			continue
		}
		// Result names may be aliases; SQL functions enforce column AAD when known.
		if len(key) > 0 {
			if plain, err := fieldDecryptCtx(key, "", s); err == nil {
				row[k] = plain
				continue
			}
		}
		row[k] = decryptFailMask
		logDecryptFailureThrottled(k)
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
	// Warn (don't reject - rejecting would make an existing key un-derivable
	// and lose access to data already encrypted with it) when params are below
	// the OWASP-ish floor. A sub-floor KDF is a memory-hard KDF in name only.
	if timeCost < 2 || memKiB < 19456 {
		log.Printf("SECURITY: ENCRYPTION_KEY argon2id params are weak (time=%d mem=%dKiB) - recommend time>=2, mem>=19456KiB (19MiB)", timeCost, memKiB)
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

// rotationRefusal is a key-rotation refusal written for the operator who asked
// for it (nothing to rotate, no current key, a short new key).
type rotationRefusal struct{ msg string }

func (e *rotationRefusal) Error() string { return e.msg }

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
// key is derived via cryptoDeriveAppKey(newKeySource) (the same versioned
// derivation InitFieldEncryption uses on process start - SHA-256 for a bare
// string, or Argon2id for an argon2id$... envelope), NOT a bare SHA-256.
// Default-generated keys
// are 32 random bytes hex-encoded (64-char string) for operator
// readability, but the rotation accepts any non-empty string the
// operator provides - same behavior as the env-var path.
//
// A refusal written for the operator is a *rotationRefusal; any other error
// is a failure the HTTP endpoint reports through serverErrorJSON.
func RotateEncryptionKey(app *App, newKeySource string, dryRun bool) (int, error) {
	if app == nil || app.DB == nil {
		return 0, &rotationRefusal{"nil app"}
	}
	// TOTP secrets are sealed under this key too (mfa_secret_store.go), so
	// an app with MFA enrollments but no encrypted.yaml still has data to
	// rotate.
	totpSealed, err := countSealedTOTPSecrets(app.DB)
	if err != nil {
		return 0, fmt.Errorf("count sealed TOTP secrets: %w", err)
	}
	// Connector command storage (operations, approvals, marker) is sealed under
	// this key too; leaving it behind would make every command and the next
	// load fail.
	commandPresent, commandRows, err := appMCPCommandStorageRows(app.DB)
	if err != nil {
		return 0, fmt.Errorf("count command storage: %w", err)
	}
	// Per-user upstream connection credentials are sealed under this key too.
	credentialsPresent, credentialRows, err := appMCPConnectionCredentialRows(app.DB)
	if err != nil {
		return 0, fmt.Errorf("count connection credentials: %w", err)
	}
	// Hook and webhook-subscription jobs that can still be delivered carry
	// their row's encrypted.yaml values sealed under this key too.
	sealedJobs, err := countSealedJobRows(app.DB)
	if err != nil {
		return 0, fmt.Errorf("count sealed job rows: %w", err)
	}
	if (app.Encrypted == nil || len(app.Encrypted.Fields) == 0) && totpSealed == 0 && !commandPresent && credentialRows == 0 {
		return 0, &rotationRefusal{"no encrypted fields configured in encrypted.yaml - nothing to rotate"}
	}
	currentKey := cryptoKeyForQuerier(app.DB)
	if currentKey == nil {
		return 0, &rotationRefusal{"no current encryption key loaded - set ENCRYPTION_KEY before rotating"}
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
		return 0, &rotationRefusal{fmt.Sprintf("new key source must be at least 32 chars for adequate entropy (got %d). Use `openssl rand -hex 32` to generate a strong one.", len(newKeySource))}
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
	if subtle.ConstantTimeCompare(newKey, currentKey) == 1 {
		return 0, fmt.Errorf("new key matches current key - refusing no-op rotation")
	}

	oldKey := make([]byte, len(currentKey))
	copy(oldKey, currentKey)

	// Count rows that need rotating across all configured columns.
	type plan struct {
		Table, Column, Source, RowID string
		IDs                          []int64
	}
	var plans []plan
	totalRows := 0
	var fields map[string][]EncryptedFieldDef
	if app.Encrypted != nil {
		fields = app.Encrypted.Fields
	}
	for table, defs := range fields {
		history := table + "_history"
		hasHistory, err := versionHistoryExists(app.DB, history)
		if err != nil {
			return 0, err
		}
		var historyCols []Column
		if hasHistory {
			historyCols, err = mainTableColumnsWith(app.DB, history)
			if err != nil {
				return 0, err
			}
		}
		for _, def := range defs {
			targets := []string{table}
			if hasHistory && versionHasColumn(historyCols, def.Column) {
				targets = append(targets, history)
			}
			for _, target := range targets {
				q := encryptedRowIDsSQL(target, def.Column)
				rowID := "rowid"
				if target != table {
					rowID, err = versionHistoryRowID(historyCols)
					if err != nil {
						return 0, err
					}
					q = versionedRotationRowIDsSQL(target, def.Column, rowID)
				}
				rows, err := app.DB.Query(q)
				if err != nil {
					return 0, fmt.Errorf("count rows for %s.%s: %w", target, def.Column, err)
				}
				var ids []int64
				for rows.Next() {
					var id int64
					if err := rows.Scan(&id); err != nil {
						rows.Close()
						return 0, err
					}
					ids = append(ids, id)
				}
				if err := errors.Join(rows.Err(), rows.Close()); err != nil {
					return 0, err
				}
				// Keep empty targets: writers may insert between preflight and BEGIN.
				plans = append(plans, plan{Table: target, Column: def.Column, Source: table, RowID: rowID, IDs: ids})
				totalRows += len(ids)
			}
		}
	}

	log.Printf("encryption-rotate: planned - %d rows across %d (table, column) pairs, plus %d TOTP secret(s)", totalRows, len(plans), totpSealed)
	totalRows += totpSealed + commandRows + credentialRows

	if dryRun {
		return totalRows, nil
	}
	if commandPresent {
		// A connector command in flight seals under the registered key; hold
		// the policy lock so none can interleave with the swap below. Only the
		// wait is bounded: the lock is then held for the whole rotation.
		lockCtx, cancelLock := context.WithTimeout(context.Background(), 30*time.Second)
		_, release, _, err := acquireAppMCPWritePolicy(lockCtx, app.Dir)
		cancelLock()
		if err != nil {
			return 0, fmt.Errorf("command storage is in use, cannot rotate: %w", err)
		}
		defer release()
	}

	// Every sealed row moves in ONE transaction - configured columns, TOTP
	// secrets and the connector command stores - so either all of it is under
	// the new key or none is, and a retry still finds the old key everywhere.
	// app.DB opens with _txlock=immediate, so this takes the write lock at
	// BEGIN and no writer can break a later upgrade. We bypass the UPDATE
	// trigger by writing a value that already starts with enc:v: (the trigger's
	// WHEN clause excludes already-encrypted values).
	rotated := 0
	if len(plans) > 0 || totpSealed > 0 || commandPresent || credentialsPresent || sealedJobs > 0 {
		tx, err := app.DB.Begin()
		if err != nil {
			return 0, fmt.Errorf("begin rotation transaction: %w", err)
		}
		fail := func(err error) (int, error) {
			tx.Rollback()
			return 0, fmt.Errorf("rotation rolled back, nothing changed: %w", err)
		}
		versionTriggers, err := suspendVersioningTriggers(tx)
		if err != nil {
			return fail(fmt.Errorf("suspend history during rotation: %w", err))
		}
		encryptionTriggers, err := suspendEncryptionTriggers(tx)
		if err != nil {
			return fail(fmt.Errorf("suspend field encryption triggers during rotation: %w", err))
		}

		for _, p := range plans {
			// Re-select inside the transaction: it is the authoritative set.
			query := encryptedRowIDsSQL(p.Table, p.Column)
			if p.Table != p.Source {
				query = versionedRotationRowIDsSQL(p.Table, p.Column, p.RowID)
			}
			idRows, err := tx.Query(query)
			if err != nil {
				return fail(fmt.Errorf("rotate %s.%s: list rows: %w", p.Table, p.Column, err))
			}
			var ids []int64
			for idRows.Next() {
				var id int64
				if err := idRows.Scan(&id); err != nil {
					idRows.Close()
					return fail(fmt.Errorf("rotate %s.%s: scan row id: %w", p.Table, p.Column, err))
				}
				ids = append(ids, id)
			}
			if err := errors.Join(idRows.Err(), idRows.Close()); err != nil {
				return fail(fmt.Errorf("rotate %s.%s: list rows: %w", p.Table, p.Column, err))
			}
			for _, id := range ids {
				var raw string
				if err := tx.QueryRow("SELECT "+quoteColumn(p.Table, p.Column)+" FROM "+quoteIdent(p.Table)+" WHERE "+quoteIdent(p.RowID)+" = ?", id).Scan(&raw); err != nil {
					return fail(fmt.Errorf("rotate %s.%s id=%d: read: %w", p.Table, p.Column, id, err))
				}
				// Decrypt enforcing the v2 column binding: a value whose AAD
				// names a different column than where it lives is a tamper /
				// move and must not be silently re-bound under the new key.
				// v1 values carry no AAD and skip the check.
				plaintext, sealed, err := appEncryptionRotationOpen(raw, oldKey, p.Source, p.Column)
				if err == nil && !sealed {
					plaintext = raw
				}
				if err != nil {
					return fail(fmt.Errorf("rotate %s.%s id=%d: decrypt with OLD key: %w (row may be corrupt, moved, or already rotated)", p.Table, p.Column, id, err))
				}
				// Re-encrypt as v2, re-binding table||column as AAD (M-3) so
				// rotation upgrades legacy v1 rows to the bound format too.
				recrypted, err := fieldEncryptCtx(newKey, p.Source, p.Column, plaintext)
				if err != nil {
					return fail(fmt.Errorf("rotate %s.%s id=%d: encrypt with NEW key: %w", p.Table, p.Column, id, err))
				}
				if _, err := tx.Exec("UPDATE "+quoteIdent(p.Table)+" SET "+quoteIdent(p.Column)+" = ? WHERE "+quoteIdent(p.RowID)+" = ?", recrypted, id); err != nil {
					return fail(fmt.Errorf("rotate %s.%s id=%d: update: %w", p.Table, p.Column, id, err))
				}
				rotated++
			}
			log.Printf("encryption-rotate: %s.%s staged (%d rows)", p.Table, p.Column, len(ids))
		}
		// Each TOTP swap compares the value read, so a concurrent enrollment
		// or disable is never overwritten.
		n, commandMoved := 0, 0
		if totpSealed > 0 {
			if n, err = rotateTOTPSecretsTx(tx, oldKey, newKey); err != nil {
				return fail(fmt.Errorf("rotate _benmore_users.totp_secret: %w", err))
			}
		}
		if commandPresent {
			if commandMoved, err = rotateAppMCPCommandStorageTx(context.Background(), tx, app, oldKey, newKey); err != nil {
				return fail(err)
			}
		}
		credentialsMoved := 0
		if credentialsPresent {
			if credentialsMoved, err = rotateAppMCPConnectionCredentialsTx(context.Background(), tx, oldKey, newKey); err != nil {
				return fail(fmt.Errorf("rotate connection credentials: %w", err))
			}
		}
		// Queued job rows are re-sealed with everything else, so a job that
		// is delivered (or retried) after the swap still opens.
		jobsMoved, err := rotateSealedJobRowsTx(tx, oldKey, newKey)
		if err != nil {
			return fail(fmt.Errorf("rotate sealed job rows: %w", err))
		}
		if err := restoreEncryptionTriggers(tx, encryptionTriggers); err != nil {
			return fail(fmt.Errorf("restore field encryption triggers after rotation: %w", err))
		}
		if err := restoreVersioningTriggers(tx, versionTriggers); err != nil {
			return fail(fmt.Errorf("restore history after rotation: %w", err))
		}

		if err := tx.Commit(); err != nil {
			tx.Rollback()
			return 0, fmt.Errorf("rotation commit failed, nothing changed: %w", err)
		}
		n += credentialsMoved
		rotated += n + commandMoved
		log.Printf("encryption-rotate: committed %d row(s) (%d TOTP secret(s), %d command storage row(s)); re-sealed %d queued job(s)", rotated, n, commandMoved, jobsMoved)
	}

	// Swap in-memory key BEFORE writing env.yaml - if env.yaml write
	// fails, the process is still consistent: in-memory and DB both
	// agree on the new key. The next process restart loads OLD from
	// env.yaml and fails to decrypt - but that's a recoverable state
	// (operator manually edits env.yaml).
	RegisterDBEncryptionKey(filepath.Join(app.Dir, "data.db"), newKey)
	if !isolateAppEnvironment.Load() {
		appEncryptionKey = newKey
		appEncryptionKeyEphemeral = false
	}
	// Persist the new key SOURCE STRING to env.yaml right after the commit and
	// BEFORE any blind-index work, which can return early: the blind index is
	// derived and rebuildable, the key is not. On the next process start,
	// InitFieldEncryption reads this string and derives the 32-byte AES key
	// via the same versioned derivation - matching what we just registered.
	// Writing raw key bytes instead would make every rotated row undecryptable.
	if err := replaceEnvYamlKey(app.Dir, "ENCRYPTION_KEY", newKeySource); err != nil {
		return rotated, fmt.Errorf("DB rotation completed (%d rows) but env.yaml write FAILED: %w. CRITICAL: in-memory key now differs from env.yaml - the next process restart will load the stale OLD key and fail to decrypt rotated rows. Manually edit env.yaml to set ENCRYPTION_KEY=<new source> before restart.", rotated, err)
	}
	// Blind-index key is HKDF-derived from the AES key. Rotate it
	// in-step so every blind index recomputed below uses the new HMAC
	// material. If derivation fails, we abort BEFORE rebuilding (the
	// blind indices would otherwise be left half-rebuilt under
	// inconsistent keys). The new key is already persisted, so a later boot can rebuild.
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
func RegisterEncryptionRotationRoute(mux appRouteRegistrar, app *App) {
	mux.HandleFunc("POST /api/_internal/encryption/rotate", func(w http.ResponseWriter, r *http.Request) {
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
			NewKey  string `json:"new_key"`
			Confirm bool   `json:"confirm"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		// Hosted: the vault holds the key the next start loads, so only the
		// router's signed rotation (which saves it there) may commit one.
		if body.Confirm && hostedTenantProcess() && !rotateSigValid(r, body.NewKey) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "on the hosted platform the key is rotated by the app owner through rotate_encryption_key, which saves the new key to the app's environment; a rotation from inside the app would be undone at the next restart"})
			return
		}

		rotated, err := RotateEncryptionKey(app, body.NewKey, !body.Confirm)
		var refusal *rotationRefusal
		if errors.As(err, &refusal) {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": refusal.Error()})
			return
		}
		if err != nil {
			serverErrorJSON(w, r, app, "encryption rotate", err, "key rotation failed")
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
