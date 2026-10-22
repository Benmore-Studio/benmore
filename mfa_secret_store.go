//go:build !cli

package main

// TOTP secrets at rest.
//
// _benmore_users.totp_secret is the shared secret an authenticator derives
// every code from: whoever reads it can produce valid second factors for that
// account forever. It is sealed with the app's field-encryption key
// (AES-256-GCM bound to _benmore_users.totp_secret, the same envelope as
// encrypted.yaml columns), so a database read alone - a backup, a copied
// data.db, a SQL console - no longer yields it.
//
// Stored forms:
//
//	""/NULL                 no factor
//	"pending:" + X          enrollment started, not yet verified
//	X                       active factor
//
// where X is the sealed secret ("enc:v2:…") or, for rows written before
// sealing (or when no durable key exists), the base32 secret itself. The
// pending marker stays outside the ciphertext so enrollment state is readable
// in SQL without the key; activating an enrollment strips it.
//
// Key choice: only a DURABLE key seals. An app with no configured
// ENCRYPTION_KEY runs on a key generated for the process alone, and a secret
// sealed under it would be unreadable after a restart - every enrolled user
// locked out of their own second factor. Such apps keep storing the secret
// unsealed and the runtime warns at startup while any enrollment exists. The
// server secret is deliberately not used as a fallback: it can be ephemeral
// too, it differs between an app's dev and prod instances (so refresh_dev
// copies would stop verifying), and nothing re-encrypts under it when it
// changes. Existing unsealed rows are sealed at startup once a durable key is
// present, and on the next successful use; reads accept both forms.
//
// Every compare-and-swap in mfa.go compares the STORED value, so sealing
// changes nothing about their atomicity: a concurrent rewrite (another
// enrollment, a rotation, the startup seal) makes the swap miss and the
// request fail instead of acting on a stale secret.

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"
)

const (
	totpPendingPrefix = "pending:"
	totpSecretTable   = "_benmore_users"
	totpSecretColumn  = "totp_secret"
)

// totpUnsealedSQL matches a stored totp_secret that is not sealed. GLOB is
// case-sensitive, so only the exact envelope prefixes count as sealed.
const totpUnsealedSQL = `COALESCE(totp_secret, '') <> '' AND totp_secret NOT GLOB 'enc:v[12]:*' AND totp_secret NOT GLOB 'pending:enc:v[12]:*'`

// totpSealKey returns the key TOTP secrets are sealed under for db, or nil
// when the database has no durable key (see the file comment).
func totpSealKey(db mutationQuerier) []byte {
	var path string
	if err := db.QueryRow("SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&path); err == nil {
		if keys := cryptoKeysForDBPath(path); keys != nil {
			if keys.ephemeral {
				return nil
			}
			return keys.aes
		}
	}
	if isolateAppEnvironment.Load() || appEncryptionKeyEphemeral {
		return nil
	}
	return appEncryptionKey
}

// sealTOTPSecret returns the stored form of an active base32 secret; prefix
// it with totpPendingPrefix for an enrollment in progress.
func sealTOTPSecret(db mutationQuerier, secretB32 string) (string, error) {
	key := totpSealKey(db)
	if key == nil {
		return secretB32, nil
	}
	return fieldEncryptCtx(key, totpSecretTable, totpSecretColumn, secretB32)
}

// openTOTPSecret returns the base32 secret held by a stored value, with any
// pending marker removed. An unsealed (legacy) value is returned as-is; a
// sealed one that this database's key cannot open is an error, never a
// fallback to comparing the ciphertext.
func openTOTPSecret(db mutationQuerier, stored string) (string, error) {
	value := strings.TrimPrefix(stored, totpPendingPrefix)
	if !cryptoIsEncrypted(value) {
		return value, nil
	}
	secret, err := fieldDecryptCtx(cryptoKeyForQuerier(db), totpSecretColumn, value)
	if err != nil {
		logTOTPOpenFailure(err)
		return "", err
	}
	return secret, nil
}

// totpSecretSealed reports whether a stored value is in sealed form.
func totpSecretSealed(stored string) bool {
	return cryptoIsEncrypted(strings.TrimPrefix(stored, totpPendingPrefix))
}

var (
	totpOpenFailureLog sync.Once
	totpUnsealedWarned sync.Map // *sql.DB → true
)

func logTOTPOpenFailure(err error) {
	totpOpenFailureLog.Do(func() {
		log.Printf("MFA: a stored TOTP secret could not be decrypted (%v). The app's ENCRYPTION_KEY is not the key it was sealed under; affected users cannot pass MFA until the key is restored.", err)
	})
}

// resealTOTPSecret seals one user's unsealed secret in place. The swap only
// happens while the row still holds the value that was read, so it never
// overwrites a concurrent enrollment or disable.
func resealTOTPSecret(db mutationTx, userID int64, stored string) {
	if stored == "" || totpSecretSealed(stored) || totpSealKey(db) == nil {
		return
	}
	pending := strings.HasPrefix(stored, totpPendingPrefix)
	sealed, err := sealTOTPSecret(db, strings.TrimPrefix(stored, totpPendingPrefix))
	if err != nil {
		return
	}
	if pending {
		sealed = totpPendingPrefix + sealed
	}
	if _, err := db.Exec("UPDATE _benmore_users SET totp_secret = ? WHERE id = ? AND totp_secret = ?", sealed, userID, stored); err != nil {
		log.Printf("MFA: sealing TOTP secret for user %d failed: %v", userID, err)
	}
}

// sealStoredTOTPSecrets seals every unsealed TOTP secret when the app has a
// durable key, in one transaction, and otherwise warns while any exist.
func sealStoredTOTPSecrets(db *sql.DB) error {
	var unsealed int
	if err := db.QueryRow("SELECT COUNT(*) FROM _benmore_users WHERE " + totpUnsealedSQL).Scan(&unsealed); err != nil {
		return err
	}
	if unsealed == 0 {
		return nil
	}
	if totpSealKey(db) == nil {
		// Once per database per process: routes are re-registered on reload.
		if _, warned := totpUnsealedWarned.LoadOrStore(db, true); !warned {
			log.Printf("MFA: WARN %d TOTP secret(s) are stored unencrypted because this app has no durable ENCRYPTION_KEY. Set one (benmore env set ENCRYPTION_KEY=<32+ random chars>, or env.yaml) and restart to encrypt them at rest.", unsealed)
		}
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.Query("SELECT id, totp_secret FROM _benmore_users WHERE " + totpUnsealedSQL)
	if err != nil {
		return err
	}
	type pendingSeal struct {
		id     int64
		stored string
	}
	var todo []pendingSeal
	for rows.Next() {
		var p pendingSeal
		if err := rows.Scan(&p.id, &p.stored); err != nil {
			rows.Close()
			return err
		}
		todo = append(todo, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, p := range todo {
		pending := strings.HasPrefix(p.stored, totpPendingPrefix)
		sealed, err := sealTOTPSecret(tx, strings.TrimPrefix(p.stored, totpPendingPrefix))
		if err != nil {
			return err
		}
		if pending {
			sealed = totpPendingPrefix + sealed
		}
		if _, err := tx.Exec("UPDATE _benmore_users SET totp_secret = ? WHERE id = ? AND totp_secret = ?", sealed, p.id, p.stored); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	log.Printf("MFA: encrypted %d stored TOTP secret(s) at rest", len(todo))
	return nil
}

// appTOTPSecretRotation keeps the original value and new envelope for the
// transaction-local compare-and-swap write.
type appTOTPSecretRotation struct {
	id           int64
	original     any
	originalType string
	sealed       string
}

// collectTOTPSecretRotations authenticates every sealed TOTP row without
// writing. The outer field-rotation helper uses this during its global
// prevalidation pass before any family is changed.
func collectTOTPSecretRotations(ctx context.Context, tx *sql.Tx, oldKey, newKey []byte) ([]appTOTPSecretRotation, error) {
	if ctx == nil || tx == nil || len(oldKey) != 32 || len(newKey) != 32 || subtle.ConstantTimeCompare(oldKey, newKey) == 1 {
		return nil, fmt.Errorf("invalid TOTP rotation context, transaction, or key pair")
	}
	present, err := appEncryptionRotationTablePresent(ctx, tx, totpSecretTable)
	if err != nil || !present {
		return nil, err
	}
	if err := appEncryptionRotationValidateTOTPTable(ctx, tx); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT id, totp_secret, typeof(totp_secret) FROM main._benmore_users ORDER BY id")
	if err != nil {
		return nil, err
	}
	var todo []appTOTPSecretRotation
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		var id int64
		var original any
		var originalType string
		if err := rows.Scan(&id, &original, &originalType); err != nil {
			rows.Close()
			return nil, err
		}
		if originalType != "null" && originalType != "text" {
			rows.Close()
			return nil, fmt.Errorf("unsupported TOTP secret storage type for row %d", id)
		}
		if original == nil {
			continue
		}
		stored, ok := original.(string)
		if !ok {
			if b, yes := original.([]byte); yes {
				stored, ok = string(b), true
			}
		}
		if !ok {
			continue
		}
		if stored == "" {
			continue
		}
		plain, pending, sealed, err := appEncryptionRotationTOTPPlain(stored, oldKey)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("rotate TOTP secret for row %d: %w", id, err)
		}
		if !sealed {
			continue
		}
		newValue, err := fieldEncryptCtx(newKey, totpSecretTable, totpSecretColumn, plain)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("reseal TOTP secret for row %d", id)
		}
		if pending {
			newValue = totpPendingPrefix + newValue
		}
		todo = append(todo, appTOTPSecretRotation{id: id, original: original, originalType: originalType, sealed: newValue})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return todo, nil
}

func applyTOTPSecretRotationsContextTx(ctx context.Context, tx *sql.Tx, todo []appTOTPSecretRotation) (int, error) {
	if ctx == nil || tx == nil {
		return 0, fmt.Errorf("invalid TOTP rotation transaction")
	}
	for _, row := range todo {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		res, err := tx.ExecContext(ctx, "UPDATE main._benmore_users SET totp_secret=? WHERE id=? AND totp_secret COLLATE BINARY IS ? AND typeof(totp_secret)=?", row.sealed, row.id, row.original, row.originalType)
		if err != nil {
			return 0, fmt.Errorf("update TOTP secret for row %d: %w", row.id, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("TOTP affected-row count failed: %w", err)
		}
		if n != 1 {
			return 0, fmt.Errorf("TOTP compare-and-swap missed row %d", row.id)
		}
	}
	return len(todo), nil
}

// rotateTOTPSecretsContextTx re-seals sealed TOTP secrets inside the caller's
// transaction. It preserves pending markers and never owns transaction end.
func rotateTOTPSecretsContextTx(ctx context.Context, tx *sql.Tx, oldKey, newKey []byte) (int, error) {
	todo, err := collectTOTPSecretRotations(ctx, tx, oldKey, newKey)
	if err != nil {
		return 0, err
	}
	return applyTOTPSecretRotationsContextTx(ctx, tx, todo)
}

// rotateTOTPSecretsTx preserves the original API for existing callers.
func rotateTOTPSecretsTx(tx *sql.Tx, oldKey, newKey []byte) (int, error) {
	return rotateTOTPSecretsContextTx(context.Background(), tx, oldKey, newKey)
}

// countSealedTOTPSecrets is the rotation plan's TOTP share.
func countSealedTOTPSecrets(db *sql.DB) (int, error) {
	var n int
	err := db.QueryRow("SELECT COUNT(*) FROM _benmore_users WHERE totp_secret GLOB 'enc:v[12]:*' OR totp_secret GLOB 'pending:enc:v[12]:*'").Scan(&n)
	if err != nil && (strings.Contains(err.Error(), "no such table") || strings.Contains(err.Error(), "no such column")) {
		return 0, nil
	}
	return n, err
}
