//go:build !cli

package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func appEncryptionRotationTestDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "data.db")
	db, err := sql.Open(sqliteHistoryTestDriver, path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, path
}

func appEncryptionRotationMustExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatalf("fixture SQL failed: %v", err)
	}
}

func appEncryptionRotationV1(t *testing.T, key []byte, plaintext string) string {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return encPrefix + hex.EncodeToString(gcm.Seal(nonce, nonce, []byte(plaintext), nil))
}

type appEncryptionRotationFixture struct {
	db             *sql.DB
	path           string
	oldKey, newKey []byte
	config         *EncryptedFieldConfig
}

func appEncryptionRotationFullFixture(t *testing.T) appEncryptionRotationFixture {
	t.Helper()
	db, path := appEncryptionRotationTestDB(t)
	oldKey := make([]byte, 32)
	newKey := make([]byte, 32)
	for i := range oldKey {
		oldKey[i] = byte(i + 1)
		newKey[i] = byte(0x91 - i)
	}
	oldBlind, err := DeriveBlindIndexKey(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	appEncryptionRotationMustExec(t, db, `CREATE TABLE accounts (
		external_key TEXT PRIMARY KEY,
		email TEXT,
		email_blind TEXT,
		score INTEGER
	)`)
	appEncryptionRotationMustExec(t, db, `CREATE TABLE _benmore_users (
		id INTEGER PRIMARY KEY,
		totp_secret TEXT,
		totp_last_step INTEGER NOT NULL DEFAULT 0,
		mfa_backup_codes TEXT NOT NULL DEFAULT ''
	)`)
	appEncryptionRotationMustExec(t, db, `CREATE TABLE _benmore_oauth_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		provider TEXT NOT NULL,
		access_token TEXT NOT NULL,
		refresh_token TEXT,
		expires_at TEXT,
		UNIQUE(user_id,provider)
	)`)
	appEncryptionRotationMustExec(t, db, `CREATE TABLE _benmore_webhooks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		secret TEXT NOT NULL
	)`)

	emailV1 := appEncryptionRotationV1(t, oldKey, "same@example.test")
	emailV2, err := fieldEncryptCtx(oldKey, "accounts", "email", "same@example.test")
	if err != nil {
		t.Fatal(err)
	}
	scoreV2, err := fieldEncryptCtx(oldKey, "accounts", "score", "9007199254740993")
	if err != nil {
		t.Fatal(err)
	}
	oldEmailHash := BlindIndexHMACWithKey(oldBlind, "same@example.test")
	appEncryptionRotationMustExec(t, db, `INSERT INTO accounts VALUES
		('text-pk-a', ?, ?, ?), ('text-pk-b', ?, ?, 17), ('null-email', NULL, 'stale-null', NULL), ('empty-email', '', 'stale-empty', 0)`,
		emailV1, oldEmailHash, scoreV2, emailV2, oldEmailHash)

	activeV1 := appEncryptionRotationV1(t, oldKey, "JBSWY3DPEHPK3PXP")
	pendingV2, err := fieldEncryptCtx(oldKey, totpSecretTable, totpSecretColumn, "MZXW6YTBOI======")
	if err != nil {
		t.Fatal(err)
	}
	appEncryptionRotationMustExec(t, db, `INSERT INTO _benmore_users(id,totp_secret,totp_last_step,mfa_backup_codes) VALUES
		(1, ?, 44, 'backup-a'), (2, ?, 55, 'backup-b'), (3, 'legacy-plaintext', 66, 'backup-c'), (4, NULL, 77, 'backup-d'), (5, '', 88, 'backup-e'), (6, ?, 99, 'backup-f')`,
		activeV1, totpPendingPrefix+pendingV2, activeV1)

	access, err := fieldEncryptWithKey(oldKey, "access-token-native")
	if err != nil {
		t.Fatal(err)
	}
	refresh := appEncryptionRotationV1(t, oldKey, "refresh-token-native")
	appEncryptionRotationMustExec(t, db, `INSERT INTO _benmore_oauth_tokens(user_id,provider,access_token,refresh_token,expires_at) VALUES
		(1,'google',?,?,?), (2,'legacy','legacy-access',NULL,?)`, access, refresh, time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339), time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339))
	webhook, err := fieldEncryptWithKey(oldKey, "webhook-signing-native")
	if err != nil {
		t.Fatal(err)
	}
	appEncryptionRotationMustExec(t, db, "INSERT INTO _benmore_webhooks(secret) VALUES (?)", webhook)
	config := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"accounts": {
		{Column: "email", BlindIndex: true}, {Column: "score"},
	}}}
	return appEncryptionRotationFixture{db: db, path: path, oldKey: oldKey, newKey: newKey, config: config}
}

func appEncryptionRotationRows(t *testing.T, q interface {
	Query(string, ...any) (*sql.Rows, error)
}, query string) [][]any {
	t.Helper()
	rows, err := q.Query(query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var out [][]any
	for rows.Next() {
		values := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		out = append(out, values)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func appEncryptionRotationSnapshot(t *testing.T, q interface {
	Query(string, ...any) (*sql.Rows, error)
}) map[string][][]any {
	t.Helper()
	return map[string][][]any{
		"accounts": appEncryptionRotationRows(t, q, "SELECT external_key,email,email_blind,score FROM main.accounts ORDER BY external_key"),
		"totp":     appEncryptionRotationRows(t, q, "SELECT id,totp_secret,totp_last_step,mfa_backup_codes FROM main._benmore_users ORDER BY id"),
		"oauth":    appEncryptionRotationRows(t, q, "SELECT id,access_token,refresh_token FROM main._benmore_oauth_tokens ORDER BY id"),
		"webhooks": appEncryptionRotationRows(t, q, "SELECT id,secret FROM main._benmore_webhooks ORDER BY id"),
	}
}

func TestRotateAppEncryptionRowsTxNativeFamiliesAndRollback(t *testing.T) {
	fixture := appEncryptionRotationFullFixture(t)
	RegisterDBEncryptionKey(fixture.path, fixture.oldKey)
	t.Cleanup(func() { dbCryptoRegistry.Delete(canonicalDBPath(fixture.path)) })
	var oldEmail, oldAccess, oldWebhook, oldTOTP string
	if err := fixture.db.QueryRow("SELECT email FROM accounts WHERE external_key='text-pk-a'").Scan(&oldEmail); err != nil {
		t.Fatal(err)
	}
	if plain, err := fieldDecryptForDB(fixture.db, oldEmail); err != nil || plain != "same@example.test" {
		t.Fatalf("native old-key field read: %q %v", plain, err)
	}
	if err := fixture.db.QueryRow("SELECT access_token FROM _benmore_oauth_tokens WHERE user_id=1").Scan(&oldAccess); err != nil {
		t.Fatal(err)
	}
	if plain, err := fieldDecryptForDB(fixture.db, oldAccess); err != nil || plain != "access-token-native" {
		t.Fatalf("native old-key OAuth field read: %q %v", plain, err)
	}
	if got := GetOAuthToken(fixture.db, "", 1, "google"); got != "access-token-native" {
		t.Fatalf("native old-key OAuth read: %q", got)
	}
	if err := fixture.db.QueryRow("SELECT secret FROM _benmore_webhooks WHERE id=1").Scan(&oldWebhook); err != nil {
		t.Fatal(err)
	}
	if plain, err := fieldDecryptForDB(fixture.db, oldWebhook); err != nil || plain != "webhook-signing-native" {
		t.Fatalf("native old-key webhook read: %q %v", plain, err)
	}
	if err := fixture.db.QueryRow("SELECT totp_secret FROM _benmore_users WHERE id=1").Scan(&oldTOTP); err != nil {
		t.Fatal(err)
	}
	if plain, err := openTOTPSecret(fixture.db, oldTOTP); err != nil || plain != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("native old-key TOTP read: %q %v", plain, err)
	}
	globalKey := append([]byte(nil), appEncryptionKey...)
	globalBlind := appBlindIndexKey.Load()
	var globalBlindCopy []byte
	if globalBlind != nil {
		globalBlindCopy = append([]byte(nil), (*globalBlind)...)
	}
	otherKey, otherPath := bytesKey(0xa1), filepath.Join(t.TempDir(), "other.db")
	otherDB, err := sql.Open("sqlite3", otherPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { otherDB.Close() })
	RegisterDBEncryptionKey(otherPath, otherKey)
	t.Cleanup(func() { dbCryptoRegistry.Delete(canonicalDBPath(otherPath)) })
	ephemeralPath, ephemeralKey := filepath.Join(t.TempDir(), "ephemeral.db"), bytesKey(0xa2)
	registerDBEncryptionKey(ephemeralPath, ephemeralKey, true)
	t.Cleanup(func() { dbCryptoRegistry.Delete(canonicalDBPath(ephemeralPath)) })
	owningBefore := *cryptoKeysForDBPath(fixture.path)
	otherBefore := *cryptoKeysForDBPath(otherPath)
	ephemeralBefore := *cryptoKeysForDBPath(ephemeralPath)
	before := appEncryptionRotationSnapshot(t, fixture.db)
	ctx := context.Background()
	tx, err := fixture.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	counts, err := rotateAppEncryptionRowsTx(ctx, tx, fixture.config, fixture.oldKey, fixture.newKey)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if counts != (appEncryptionRowRotationCounts{ConfiguredValues: 3, TOTPSecrets: 3, OAuthValues: 2, WebhookSecrets: 1, BlindValues: 4}) {
		t.Fatalf("rotation counts = %+v", counts)
	}
	candidate := appEncryptionRotationSnapshot(t, tx)
	for _, family := range []string{"accounts", "totp", "oauth", "webhooks"} {
		if reflect.DeepEqual(candidate[family], before[family]) {
			tx.Rollback()
			t.Fatalf("successful helper left %s family unchanged inside caller transaction", family)
		}
	}
	if !reflect.DeepEqual(*cryptoKeysForDBPath(fixture.path), owningBefore) || !reflect.DeepEqual(*cryptoKeysForDBPath(otherPath), otherBefore) || !reflect.DeepEqual(*cryptoKeysForDBPath(ephemeralPath), ephemeralBefore) {
		tx.Rollback()
		t.Fatal("explicit-key rotation altered owning, unrelated, or ephemeral registry entries")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if got := appEncryptionRotationSnapshot(t, fixture.db); !reflect.DeepEqual(got, before) {
		t.Fatal("caller rollback did not restore every family")
	}
	if !reflect.DeepEqual(appEncryptionKey, globalKey) {
		t.Fatal("explicit-key rotation changed the process encryption key")
	}
	currentBlind := appBlindIndexKey.Load()
	if globalBlind == nil {
		if currentBlind != nil {
			t.Fatal("explicit-key rotation installed a global blind key")
		}
	} else if currentBlind == nil || !reflect.DeepEqual(*currentBlind, globalBlindCopy) {
		t.Fatal("explicit-key rotation changed the process blind key")
	}

	tx, err = fixture.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	counts, err = rotateAppEncryptionRowsTx(ctx, tx, fixture.config, fixture.oldKey, fixture.newKey)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	committedCandidate := appEncryptionRotationSnapshot(t, tx)
	for _, family := range []string{"accounts", "totp", "oauth", "webhooks"} {
		if reflect.DeepEqual(committedCandidate[family], before[family]) {
			tx.Rollback()
			t.Fatalf("second successful helper left %s family unchanged", family)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*cryptoKeysForDBPath(fixture.path), owningBefore) || !reflect.DeepEqual(*cryptoKeysForDBPath(otherPath), otherBefore) || !reflect.DeepEqual(*cryptoKeysForDBPath(ephemeralPath), ephemeralBefore) {
		t.Fatal("committed explicit-key rotation altered owning, unrelated, or ephemeral registry entries")
	}
	if !reflect.DeepEqual(appEncryptionKey, globalKey) {
		t.Fatal("committed explicit-key rotation changed process encryption key")
	}
	committedBlind := appBlindIndexKey.Load()
	if globalBlind == nil {
		if committedBlind != nil {
			t.Fatal("committed explicit-key rotation installed a global blind key")
		}
	} else if committedBlind == nil || !reflect.DeepEqual(*committedBlind, globalBlindCopy) {
		t.Fatal("committed explicit-key rotation changed process blind key")
	}
	if err := fixture.db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	newBytes := appEncryptionRotationSnapshot(t, db)
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotateAppEncryptionRowsTx(ctx, tx, fixture.config, fixture.oldKey, fixture.newKey); err == nil {
		tx.Rollback()
		t.Fatal("obsolete-key full rotation retry after reopen succeeded")
	}
	if got := appEncryptionRotationSnapshot(t, tx); !reflect.DeepEqual(got, newBytes) {
		tx.Rollback()
		t.Fatal("obsolete-key retry changed ciphertext or blind values")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	RegisterDBEncryptionKey(fixture.path, fixture.newKey)
	t.Cleanup(func() { dbCryptoRegistry.Delete(canonicalDBPath(fixture.path)) })
	afterReopen := appEncryptionRotationSnapshot(t, db)
	beforeTOTP, afterTOTP := map[int64][]any{}, map[int64][]any{}
	for _, row := range before["totp"] {
		beforeTOTP[row[0].(int64)] = row
	}
	for _, row := range afterReopen["totp"] {
		afterTOTP[row[0].(int64)] = row
	}
	if len(afterTOTP) != len(beforeTOTP) {
		t.Fatal("TOTP row count changed after commit")
	}
	for id, oldRow := range beforeTOTP {
		newRow, ok := afterTOTP[id]
		if !ok || !reflect.DeepEqual(newRow[2:], oldRow[2:]) {
			t.Fatalf("rotation changed replay or backup fields for TOTP row %d", id)
		}
	}

	rows, err := QueryRows(db, "SELECT external_key,email,email_blind,score FROM accounts ORDER BY external_key")
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]map[string]any{}
	for _, row := range rows {
		byKey[row["external_key"].(string)] = row
	}
	if len(rows) != 4 || byKey["text-pk-a"]["email"] != "same@example.test" || byKey["text-pk-b"]["email"] != "same@example.test" || byKey["text-pk-a"]["score"] != int64(9007199254740993) {
		t.Fatalf("native configured-column reads changed logical values: %#v", rows)
	}
	if byKey["null-email"]["email"] != nil || byKey["empty-email"]["email"] != "" || byKey["text-pk-b"]["score"] != int64(17) {
		t.Fatalf("legacy/null scalar storage changed: %#v", rows)
	}
	newBlind, err := DeriveBlindIndexKey(fixture.newKey)
	if err != nil {
		t.Fatal(err)
	}
	wantHash := BlindIndexHMACWithKey(newBlind, "same@example.test")
	var equalityCount int
	if err := db.QueryRow("SELECT count(*) FROM main.accounts WHERE email_blind=?", wantHash).Scan(&equalityCount); err != nil || equalityCount != 2 {
		t.Fatalf("native blind equality count=%d err=%v", equalityCount, err)
	}
	var nullBlind, emptyBlind sql.NullString
	if err := db.QueryRow("SELECT email_blind FROM accounts WHERE external_key='null-email'").Scan(&nullBlind); err != nil || nullBlind.Valid {
		t.Fatal("NULL source retained a blind value")
	}
	if err := db.QueryRow("SELECT email_blind FROM accounts WHERE external_key='empty-email'").Scan(&emptyBlind); err != nil || emptyBlind.Valid {
		t.Fatal("empty source retained a blind value")
	}

	if got := GetOAuthToken(db, "", 1, "google"); got != "access-token-native" {
		t.Fatalf("native OAuth reader returned %q", got)
	}
	var storedRefresh, legacyAccess string
	if err := db.QueryRow("SELECT refresh_token FROM _benmore_oauth_tokens WHERE user_id=1").Scan(&storedRefresh); err != nil {
		t.Fatal(err)
	}
	if plain, err := fieldDecryptForDB(db, storedRefresh); err != nil || plain != "refresh-token-native" {
		t.Fatalf("native OAuth refresh read: %q %v", plain, err)
	}
	if err := db.QueryRow("SELECT access_token FROM _benmore_oauth_tokens WHERE user_id=2").Scan(&legacyAccess); err != nil || legacyAccess != "legacy-access" {
		t.Fatal("legacy OAuth plaintext changed")
	}
	var storedWebhook string
	if err := db.QueryRow("SELECT secret FROM _benmore_webhooks WHERE id=1").Scan(&storedWebhook); err != nil {
		t.Fatal(err)
	}
	if got, err := fieldDecryptForDB(db, storedWebhook); err != nil || got != "webhook-signing-native" {
		t.Fatalf("native webhook decrypt path: %q %v", got, err)
	}
	var active, pending, legacy string
	if err := db.QueryRow("SELECT totp_secret FROM _benmore_users WHERE id=1").Scan(&active); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT totp_secret FROM _benmore_users WHERE id=2").Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if got, err := openTOTPSecret(db, active); err != nil || got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("active TOTP read: %q %v", got, err)
	}
	if !strings.HasPrefix(pending, totpPendingPrefix) {
		t.Fatal("pending enrollment marker was lost")
	}
	if got, err := openTOTPSecret(db, pending); err != nil || got != "MZXW6YTBOI======" {
		t.Fatalf("pending TOTP read: %q %v", got, err)
	}
	var repeatedTOTP string
	if err := db.QueryRow("SELECT totp_secret FROM _benmore_users WHERE id=6").Scan(&repeatedTOTP); err != nil {
		t.Fatal(err)
	}
	if got, err := openTOTPSecret(db, repeatedTOTP); err != nil || got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("repeated TOTP input read: %q %v", got, err)
	}
	if err := db.QueryRow("SELECT totp_secret FROM _benmore_users WHERE id=3").Scan(&legacy); err != nil || legacy != "legacy-plaintext" {
		t.Fatal("legacy TOTP value changed")
	}
	var nullTOTP, emptyTOTP sql.NullString
	if err := db.QueryRow("SELECT totp_secret FROM _benmore_users WHERE id=4").Scan(&nullTOTP); err != nil || nullTOTP.Valid {
		t.Fatal("NULL TOTP enrollment state changed")
	}
	if err := db.QueryRow("SELECT totp_secret FROM _benmore_users WHERE id=5").Scan(&emptyTOTP); err != nil || !emptyTOTP.Valid || emptyTOTP.String != "" {
		t.Fatal("empty TOTP enrollment state changed")
	}
	if _, err := fieldDecryptCtx(fixture.oldKey, totpSecretColumn, active); err == nil {
		t.Fatal("obsolete key opened rotated TOTP secret")
	}
	var newScore string
	if err := db.QueryRow("SELECT score FROM accounts WHERE external_key='text-pk-a'").Scan(&newScore); err != nil {
		t.Fatal(err)
	}
	if _, err := fieldDecryptCtx(fixture.oldKey, "score", newScore); err == nil {
		t.Fatal("obsolete key opened rotated numeric ciphertext")
	}
	if got, err := fieldDecryptCtx(fixture.newKey, "score", newScore); err != nil || got != "9007199254740993" {
		t.Fatalf("new key opened numeric ciphertext: %q %v", got, err)
	}
	var rotatedWebhook string
	for _, row := range appEncryptionRotationSnapshot(t, db)["webhooks"] {
		rotatedWebhook = row[1].(string)
	}
	if _, err := fieldDecryptCtx(fixture.oldKey, "", rotatedWebhook); err == nil {
		t.Fatal("obsolete key opened webhook ciphertext")
	}
	if got := GetOAuthToken(db, "", 1, "google"); got == "" {
		t.Fatal("new key did not open OAuth token")
	}
}

func TestRotateAppEncryptionRowsTxPrevalidatesEveryFamily(t *testing.T) {
	fixture := appEncryptionRotationFullFixture(t)
	appEncryptionRotationMustExec(t, fixture.db, "UPDATE _benmore_webhooks SET secret='enc:v3:unknown'")
	corrupt := appEncryptionRotationSnapshot(t, fixture.db)
	tx, err := fixture.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rotateAppEncryptionRowsTx(context.Background(), tx, fixture.config, fixture.oldKey, fixture.newKey)
	if err == nil {
		tx.Rollback()
		t.Fatal("malformed last-family ciphertext accepted")
	}
	if strings.Contains(err.Error(), "webhook-signing-native") {
		tx.Rollback()
		t.Fatal("rotation error exposed secret plaintext")
	}
	if got := appEncryptionRotationSnapshot(t, tx); !reflect.DeepEqual(got, corrupt) {
		tx.Rollback()
		t.Fatal("late corrupt family followed earlier writes")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(appEncryptionRotationSnapshot(t, fixture.db), corrupt) {
		t.Fatal("rollback changed corrupt fixture")
	}
}

func TestRotateAppEncryptionRowsTxPrevalidatesFinalTOTPFamily(t *testing.T) {
	fixture := appEncryptionRotationFullFixture(t)
	badCipher := "enc:v3:synthetic-bad-cipher"
	appEncryptionRotationMustExec(t, fixture.db, "UPDATE main._benmore_users SET totp_secret=? WHERE id=6", badCipher)
	before := appEncryptionRotationSnapshot(t, fixture.db)
	tx, err := fixture.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rotateAppEncryptionRowsTx(context.Background(), tx, fixture.config, fixture.oldKey, fixture.newKey)
	if err == nil {
		tx.Rollback()
		t.Fatal("corrupt final TOTP family accepted")
	}
	for _, secret := range []string{badCipher, "JBSWY3DPEHPK3PXP", "same@example.test"} {
		if strings.Contains(err.Error(), secret) {
			tx.Rollback()
			t.Fatalf("rotation error exposed sensitive or synthetic value %q", secret)
		}
	}
	if got := appEncryptionRotationSnapshot(t, tx); !reflect.DeepEqual(got, before) {
		tx.Rollback()
		t.Fatal("late TOTP corruption followed an earlier family write")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
}

func TestRotateAppEncryptionRowsTxRejectsWrongAADAndInputs(t *testing.T) {
	fixture := appEncryptionRotationFullFixture(t)
	baseline := appEncryptionRotationSnapshot(t, fixture.db)
	wtx, err := fixture.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotateAppEncryptionRowsTx(context.Background(), wtx, fixture.config, bytesKey(0x55), fixture.newKey); err == nil {
		wtx.Rollback()
		t.Fatal("wrong old key accepted")
	}
	if got := appEncryptionRotationSnapshot(t, wtx); !reflect.DeepEqual(got, baseline) {
		wtx.Rollback()
		t.Fatal("wrong-key prevalidation wrote rows")
	}
	if err := wtx.Rollback(); err != nil {
		t.Fatal(err)
	}
	wrong, err := fieldEncryptCtx(fixture.oldKey, "other_table", "email", "same@example.test")
	if err != nil {
		t.Fatal(err)
	}
	appEncryptionRotationMustExec(t, fixture.db, "UPDATE accounts SET email=? WHERE external_key='text-pk-a'", wrong)
	before := appEncryptionRotationSnapshot(t, fixture.db)
	tx, err := fixture.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotateAppEncryptionRowsTx(context.Background(), tx, fixture.config, fixture.oldKey, fixture.newKey); err == nil {
		tx.Rollback()
		t.Fatal("wrong AAD accepted")
	}
	if got := appEncryptionRotationSnapshot(t, tx); !reflect.DeepEqual(got, before) {
		tx.Rollback()
		t.Fatal("wrong AAD was discovered after writes")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	wrongColumn, err := fieldEncryptCtx(fixture.oldKey, "accounts", "score", "same@example.test")
	if err != nil {
		t.Fatal(err)
	}
	appEncryptionRotationMustExec(t, fixture.db, "UPDATE accounts SET email=? WHERE external_key='text-pk-a'", wrongColumn)
	tx, err = fixture.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotateAppEncryptionRowsTx(context.Background(), tx, fixture.config, fixture.oldKey, fixture.newKey); err == nil {
		tx.Rollback()
		t.Fatal("wrong-column AAD accepted")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	tx, err = fixture.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotateAppEncryptionRowsTx(nil, tx, fixture.config, fixture.oldKey, fixture.newKey); err == nil {
		tx.Rollback()
		t.Fatal("nil context accepted")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := rotateAppEncryptionRowsTx(context.Background(), nil, fixture.config, fixture.oldKey, fixture.newKey); err == nil {
		t.Fatal("nil transaction accepted")
	}
	for _, keys := range []struct {
		name     string
		old, new []byte
	}{{"identical", fixture.oldKey, fixture.oldKey}, {"short-old", fixture.oldKey[:31], fixture.newKey}, {"short-new", fixture.oldKey, fixture.newKey[:31]}} {
		t.Run(keys.name, func(t *testing.T) {
			fresh := appEncryptionRotationFullFixture(t)
			baseline := appEncryptionRotationSnapshot(t, fresh.db)
			validTx, err := fresh.db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := rotateAppEncryptionRowsTx(context.Background(), validTx, fresh.config, fresh.oldKey, fresh.newKey); err != nil {
				validTx.Rollback()
				t.Fatalf("valid distinct-key control failed before %s rejection: %v", keys.name, err)
			}
			if got := appEncryptionRotationSnapshot(t, validTx); reflect.DeepEqual(got, baseline) {
				validTx.Rollback()
				t.Fatal("valid distinct-key control did not change encrypted families")
			}
			if err := validTx.Rollback(); err != nil {
				t.Fatal(err)
			}
			if got := appEncryptionRotationSnapshot(t, fresh.db); !reflect.DeepEqual(got, baseline) {
				t.Fatal("valid control caller rollback changed persisted rows")
			}
			tx, err := fresh.db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = rotateAppEncryptionRowsTx(context.Background(), tx, fresh.config, keys.old, keys.new)
			if err == nil || !strings.Contains(err.Error(), "invalid encryption rotation context, transaction, or key pair") {
				tx.Rollback()
				t.Fatalf("expected initial invalid key-pair rejection for %s, got %v", keys.name, err)
			}
			if got := appEncryptionRotationSnapshot(t, tx); !reflect.DeepEqual(got, baseline) {
				tx.Rollback()
				t.Fatalf("invalid key pair %s changed rows before rollback", keys.name)
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRotateAppEncryptionRowsTxCASFaultAndCancellation(t *testing.T) {
	fixture := appEncryptionRotationFullFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tx, err := fixture.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotateAppEncryptionRowsTx(ctx, tx, fixture.config, fixture.oldKey, fixture.newKey); err == nil {
		tx.Rollback()
		t.Fatal("cancelled context accepted")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	tx, err = fixture.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	target := appEncryptionRotationTarget{table: "accounts", aadTable: "accounts", aadColumn: "email", column: "email", blindColumn: "email_blind", rowIDColumn: "rowid", family: "configured"}
	blind, err := DeriveBlindIndexKey(fixture.newKey)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	cells, err := appEncryptionRotationInventory(context.Background(), tx, target, fixture.oldKey, fixture.newKey, blind)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if len(cells) == 0 {
		tx.Rollback()
		t.Fatal("fixture produced no CAS cells")
	}
	stale := cells[0]
	if _, err := tx.Exec("UPDATE main.accounts SET email='concurrent-value' WHERE rowid=?", stale.rowID); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := appEncryptionRotationCASWrite(context.Background(), tx, stale); err == nil || !strings.Contains(err.Error(), "compare-and-swap") {
		tx.Rollback()
		t.Fatalf("stale CAS error = %v", err)
	}
	var got string
	if err := tx.QueryRow("SELECT email FROM accounts WHERE rowid=?", stale.rowID).Scan(&got); err != nil || got != "concurrent-value" {
		tx.Rollback()
		t.Fatal("stale CAS overwrote the row")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	beforeFault := appEncryptionRotationSnapshot(t, fixture.db)
	if _, err := fixture.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	tx, err = fixture.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotateAppEncryptionRowsTx(context.Background(), tx, fixture.config, fixture.oldKey, fixture.newKey); err == nil {
		tx.Rollback()
		t.Fatal("query-only SQL update fault accepted")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.db.Exec("PRAGMA query_only=OFF"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(appEncryptionRotationSnapshot(t, fixture.db), beforeFault) {
		t.Fatal("failed update changed persisted rows after caller rollback")
	}
	tx, err = fixture.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotateAppEncryptionRowsTx(context.Background(), tx, fixture.config, fixture.oldKey, fixture.newKey); err != nil {
		tx.Rollback()
		t.Fatalf("valid run after query_only cleanup: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
}

func TestRotateAppEncryptionRowsTxRollsBackPriorWritesAfterLateSQLFailure(t *testing.T) {
	db, _ := appEncryptionRotationTestDB(t)
	appEncryptionRotationMustExec(t, db, `CREATE TABLE _benmore_oauth_tokens(id INTEGER PRIMARY KEY,access_token TEXT,refresh_token TEXT)`)
	appEncryptionRotationMustExec(t, db, `CREATE TABLE _benmore_webhooks(id INTEGER PRIMARY KEY,secret TEXT CHECK(secret NOT LIKE 'enc:v2:%'))`)
	oldKey, newKey := bytesKey(0x17), bytesKey(0x3b)
	oldOAuth := appEncryptionRotationV1(t, oldKey, "oauth-before-late-fault")
	oldWebhook := appEncryptionRotationV1(t, oldKey, "webhook-before-late-fault")
	appEncryptionRotationMustExec(t, db, "INSERT INTO _benmore_oauth_tokens VALUES(1,?,NULL)", oldOAuth)
	appEncryptionRotationMustExec(t, db, "INSERT INTO _benmore_webhooks VALUES(1,?)", oldWebhook)
	before := map[string][][]any{"oauth": appEncryptionRotationRows(t, db, "SELECT access_token,refresh_token FROM main._benmore_oauth_tokens"), "webhooks": appEncryptionRotationRows(t, db, "SELECT secret FROM main._benmore_webhooks")}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rotateAppEncryptionRowsTx(context.Background(), tx, nil, oldKey, newKey)
	if err == nil {
		tx.Rollback()
		t.Fatal("later webhook CHECK denial was not propagated")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "check constraint") {
		tx.Rollback()
		t.Fatalf("later native constraint failure was not the observed update fault: %v", err)
	}
	inside := map[string][][]any{"oauth": appEncryptionRotationRows(t, tx, "SELECT access_token,refresh_token FROM main._benmore_oauth_tokens"), "webhooks": appEncryptionRotationRows(t, tx, "SELECT secret FROM main._benmore_webhooks")}
	if reflect.DeepEqual(inside["oauth"], before["oauth"]) {
		tx.Rollback()
		t.Fatal("native fixture did not reach and write the earlier OAuth family")
	}
	if !reflect.DeepEqual(inside["webhooks"], before["webhooks"]) {
		tx.Rollback()
		t.Fatal("failed later webhook update changed stored value")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	after := map[string][][]any{"oauth": appEncryptionRotationRows(t, db, "SELECT access_token,refresh_token FROM main._benmore_oauth_tokens"), "webhooks": appEncryptionRotationRows(t, db, "SELECT secret FROM main._benmore_webhooks")}
	if !reflect.DeepEqual(after, before) {
		t.Fatal("caller rollback did not restore earlier OAuth write")
	}
}

func TestAppEncryptionRotationWriterCancellationAfterWrite(t *testing.T) {
	fixture := appEncryptionRotationFullFixture(t)
	before := appEncryptionRotationSnapshot(t, fixture.db)
	ctx, cancel := context.WithCancel(context.Background())
	tx, err := fixture.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	blindKey, err := DeriveBlindIndexKey(fixture.newKey)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	cells, err := appEncryptionRotationInventory(context.Background(), tx, appEncryptionRotationTarget{table: "accounts", aadTable: "accounts", aadColumn: "email", column: "email", blindColumn: "email_blind", rowIDColumn: "rowid", family: "configured"}, fixture.oldKey, fixture.newKey, blindKey)
	if err != nil || len(cells) < 2 {
		tx.Rollback()
		t.Fatalf("writer cancellation setup: %d %v", len(cells), err)
	}
	if err := appEncryptionRotationCASWrite(ctx, tx, cells[0]); err != nil {
		tx.Rollback()
		t.Fatalf("first production writer update: %v", err)
	}
	cancel()
	if err := appEncryptionRotationCASWrite(ctx, tx, cells[1]); err == nil {
		tx.Rollback()
		t.Fatal("cancelled later production writer update succeeded")
	}
	inside := appEncryptionRotationSnapshot(t, tx)
	if reflect.DeepEqual(inside["accounts"], before["accounts"]) {
		tx.Rollback()
		t.Fatal("first writer update was not visible before outer rollback")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if got := appEncryptionRotationSnapshot(t, fixture.db); !reflect.DeepEqual(got, before) {
		t.Fatal("caller rollback did not undo pre-cancellation writer update")
	}
}

func TestRotateAppEncryptionRowsTxTriggerAndIsolationRefusal(t *testing.T) {
	fixture := appEncryptionRotationFullFixture(t)
	before := appEncryptionRotationSnapshot(t, fixture.db)
	appEncryptionRotationMustExec(t, fixture.db, "CREATE TABLE observer_effects(row_id INTEGER NOT NULL)")
	appEncryptionRotationMustExec(t, fixture.db, "CREATE TRIGGER observer AFTER UPDATE ON accounts BEGIN INSERT INTO observer_effects(row_id) VALUES(NEW.rowid); END")
	tx, err := fixture.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotateAppEncryptionRowsTx(context.Background(), tx, fixture.config, fixture.oldKey, fixture.newKey); err == nil {
		tx.Rollback()
		t.Fatal("observer trigger was not refused")
	}
	if got := appEncryptionRotationSnapshot(t, tx); !reflect.DeepEqual(got, before) {
		tx.Rollback()
		t.Fatal("trigger refusal changed ciphertext or blind values")
	}
	var observerCount int
	if err := tx.QueryRow("SELECT count(*) FROM main.observer_effects").Scan(&observerCount); err != nil || observerCount != 0 {
		tx.Rollback()
		t.Fatal("refused helper fired observer side effect")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	tx, err = fixture.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("DROP TRIGGER observer"); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if _, err := rotateAppEncryptionRowsTx(context.Background(), tx, fixture.config, fixture.oldKey, fixture.newKey); err != nil {
		tx.Rollback()
		t.Fatalf("maintenance transaction after explicit trigger suspension: %v", err)
	}
	if err := tx.QueryRow("SELECT count(*) FROM main.observer_effects").Scan(&observerCount); err != nil || observerCount != 0 {
		tx.Rollback()
		t.Fatal("explicit trigger suspension wrote observer row")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var triggerCount int
	if err := fixture.db.QueryRow("SELECT count(*) FROM main.sqlite_schema WHERE type='trigger' AND name='observer'").Scan(&triggerCount); err != nil || triggerCount != 1 {
		t.Fatal("caller rollback did not restore the trigger")
	}
	if !reflect.DeepEqual(appEncryptionRotationSnapshot(t, fixture.db), before) {
		t.Fatal("caller rollback did not restore data with trigger schema")
	}
	appEncryptionRotationMustExec(t, fixture.db, "DROP TRIGGER observer")

	// TEMP and ATTACH are state on the borrowed SQLite connection, not part of main.
	if _, err := fixture.db.Exec("CREATE TEMP TABLE rotation_shadow(value TEXT)"); err != nil {
		t.Fatal(err)
	}
	var tempCount int
	if err := fixture.db.QueryRow("SELECT count(*) FROM temp.sqlite_schema WHERE name='rotation_shadow'").Scan(&tempCount); err != nil || tempCount != 1 {
		t.Fatal("temporary fixture did not persist on the single connection")
	}
	if !appEncryptionRotationDatabaseListed(t, fixture.db, "temp") {
		t.Fatal("temp fixture absent from database_list")
	}
	tx, err = fixture.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotateAppEncryptionRowsTx(context.Background(), tx, fixture.config, fixture.oldKey, fixture.newKey); err == nil {
		tx.Rollback()
		t.Fatal("TEMP object accepted")
	}
	if got := appEncryptionRotationSnapshot(t, tx); !reflect.DeepEqual(got, before) {
		tx.Rollback()
		t.Fatal("TEMP refusal changed main rows")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.db.Exec("DROP TABLE rotation_shadow"); err != nil {
		t.Fatal(err)
	}
	if err := fixture.db.QueryRow("SELECT count(*) FROM temp.sqlite_schema WHERE name='rotation_shadow'").Scan(&tempCount); err != nil || tempCount != 0 {
		t.Fatal("TEMP fixture cleanup failed")
	}
	if !appEncryptionRotationDatabaseListed(t, fixture.db, "temp") {
		t.Fatal("single connection lost its temp schema before baseline check")
	}
	assertRotationIsolationCleanupBaseline(t, fixture, before)
	if _, err := fixture.db.Exec("ATTACH DATABASE ':memory:' AS rotation_attached"); err != nil {
		t.Fatal(err)
	}
	if !appEncryptionRotationDatabaseListed(t, fixture.db, "rotation_attached") {
		t.Fatal("attached fixture absent from database_list")
	}
	tx, err = fixture.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotateAppEncryptionRowsTx(context.Background(), tx, fixture.config, fixture.oldKey, fixture.newKey); err == nil {
		tx.Rollback()
		t.Fatal("attached database accepted")
	}
	if got := appEncryptionRotationSnapshot(t, tx); !reflect.DeepEqual(got, before) {
		tx.Rollback()
		t.Fatal("attached refusal changed main rows")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.db.Exec("DETACH DATABASE rotation_attached"); err != nil {
		t.Fatal(err)
	}
	if appEncryptionRotationDatabaseListed(t, fixture.db, "rotation_attached") {
		t.Fatal("attached fixture cleanup failed")
	}
	assertRotationIsolationCleanupBaseline(t, fixture, before)
}

func appEncryptionRotationDatabaseListed(t *testing.T, q interface {
	Query(string, ...any) (*sql.Rows, error)
}, name string) bool {
	t.Helper()
	rows, err := q.Query("PRAGMA database_list")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var seq int
		var schema, path string
		if err := rows.Scan(&seq, &schema, &path); err != nil {
			t.Fatal(err)
		}
		if schema == name {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return false
}

func assertRotationIsolationCleanupBaseline(t *testing.T, fixture appEncryptionRotationFixture, before map[string][][]any) {
	t.Helper()
	var queryOnly int
	if err := fixture.db.QueryRow("PRAGMA query_only").Scan(&queryOnly); err != nil || queryOnly != 0 {
		t.Fatalf("query_only state leaked: %d %v", queryOnly, err)
	}
	if got := appEncryptionRotationSnapshot(t, fixture.db); !reflect.DeepEqual(got, before) {
		t.Fatal("isolation cleanup changed main data")
	}
	tx, err := fixture.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotateAppEncryptionRowsTx(context.Background(), tx, fixture.config, fixture.oldKey, fixture.newKey); err != nil {
		tx.Rollback()
		t.Fatalf("valid run after isolation cleanup: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if got := appEncryptionRotationSnapshot(t, fixture.db); !reflect.DeepEqual(got, before) {
		t.Fatal("cleanup baseline helper rollback changed rows")
	}
}

func TestRotateAppEncryptionRowsTxRefusesBlindIndexForeignKeys(t *testing.T) {
	for _, tc := range []struct {
		name, schema string
		fkOnParent   bool
	}{
		{"blind-is-referenced-parent", `CREATE TABLE accounts(id INTEGER PRIMARY KEY,email TEXT,email_blind TEXT UNIQUE); CREATE TABLE child(id INTEGER PRIMARY KEY,blind TEXT REFERENCES accounts(email_blind) ON UPDATE CASCADE)`, true},
		{"blind-is-child", `CREATE TABLE parent(blind TEXT PRIMARY KEY); CREATE TABLE accounts(id INTEGER PRIMARY KEY,email TEXT,email_blind TEXT REFERENCES parent(blind) ON UPDATE CASCADE)`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, _ := appEncryptionRotationTestDB(t)
			for _, stmt := range strings.Split(tc.schema, ";") {
				appEncryptionRotationMustExec(t, db, stmt)
			}
			oldKey, newKey := bytesKey(0x13), bytesKey(0x37)
			blindKey, err := DeriveBlindIndexKey(oldKey)
			if err != nil {
				t.Fatal(err)
			}
			ciphertext, err := fieldEncryptCtx(oldKey, "accounts", "email", "parent@example.test")
			if err != nil {
				t.Fatal(err)
			}
			hash := BlindIndexHMACWithKey(blindKey, "parent@example.test")
			if tc.fkOnParent {
				appEncryptionRotationMustExec(t, db, "INSERT INTO accounts(id,email,email_blind) VALUES(1,?,?)", ciphertext, hash)
				appEncryptionRotationMustExec(t, db, "INSERT INTO child(id,blind) VALUES(1,?)", hash)
			} else {
				appEncryptionRotationMustExec(t, db, "INSERT INTO parent(blind) VALUES(?)", hash)
				appEncryptionRotationMustExec(t, db, "INSERT INTO accounts(id,email,email_blind) VALUES(1,?,?)", ciphertext, hash)
			}
			var actual int
			if tc.fkOnParent {
				if err := db.QueryRow("SELECT count(*) FROM accounts a JOIN child c ON c.blind=a.email_blind WHERE a.email_blind=?", hash).Scan(&actual); err != nil || actual != 1 {
					t.Fatalf("parent equality setup failed: %d %v", actual, err)
				}
			} else {
				if err := db.QueryRow("SELECT count(*) FROM accounts a JOIN parent p ON p.blind=a.email_blind WHERE a.email_blind=?", hash).Scan(&actual); err != nil || actual != 1 {
					t.Fatalf("child equality setup failed: %d %v", actual, err)
				}
			}
			before := map[string][][]any{"accounts": appEncryptionRotationRows(t, db, "SELECT id,email,email_blind FROM main.accounts ORDER BY id")}
			if tc.fkOnParent {
				before["child"] = appEncryptionRotationRows(t, db, "SELECT id,blind FROM main.child ORDER BY id")
			} else {
				before["parent"] = appEncryptionRotationRows(t, db, "SELECT blind FROM main.parent ORDER BY blind")
			}
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = rotateAppEncryptionRowsTx(context.Background(), tx, &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"accounts": {{Column: "email", BlindIndex: true}}}}, oldKey, newKey)
			if err == nil {
				tx.Rollback()
				t.Fatal("blind-index foreign key accepted")
			}
			after := map[string][][]any{"accounts": appEncryptionRotationRows(t, tx, "SELECT id,email,email_blind FROM main.accounts ORDER BY id")}
			if tc.fkOnParent {
				after["child"] = appEncryptionRotationRows(t, tx, "SELECT id,blind FROM main.child ORDER BY id")
			} else {
				after["parent"] = appEncryptionRotationRows(t, tx, "SELECT blind FROM main.parent ORDER BY blind")
			}
			if !reflect.DeepEqual(after, before) {
				tx.Rollback()
				t.Fatal("blind-index FK refusal occurred after same-transaction writes")
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
		})
	}
	valid := appEncryptionRotationFullFixture(t)
	tx, err := valid.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotateAppEncryptionRowsTx(context.Background(), tx, valid.config, valid.oldKey, valid.newKey); err != nil {
		tx.Rollback()
		t.Fatalf("valid non-FK blind-index control refused: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
}

func TestRotateAppEncryptionRowsTxUsesExactBinaryCAS(t *testing.T) {
	oldKey, newKey := bytesKey(0x14), bytesKey(0x38)
	makeDB := func(t *testing.T, collation string) (*sql.DB, appEncryptionRotationCell) {
		db, _ := appEncryptionRotationTestDB(t)
		appEncryptionRotationMustExec(t, db, "CREATE TABLE accounts(id INTEGER PRIMARY KEY,email TEXT COLLATE "+collation+",email_blind TEXT COLLATE RTRIM)")
		ciphertext, err := fieldEncryptCtx(oldKey, "accounts", "email", "case-sensitive@example.test")
		if err != nil {
			t.Fatal(err)
		}
		blindKey, err := DeriveBlindIndexKey(oldKey)
		if err != nil {
			t.Fatal(err)
		}
		hash := BlindIndexHMACWithKey(blindKey, "case-sensitive@example.test")
		appEncryptionRotationMustExec(t, db, "INSERT INTO accounts VALUES(1,?,?)", ciphertext, hash)
		tx, err := db.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		newBlind, err := DeriveBlindIndexKey(newKey)
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		cells, err := appEncryptionRotationInventory(context.Background(), tx, appEncryptionRotationTarget{table: "accounts", aadTable: "accounts", aadColumn: "email", column: "email", blindColumn: "email_blind", rowIDColumn: "rowid", family: "configured"}, oldKey, newKey, newBlind)
		if err != nil || len(cells) != 1 {
			tx.Rollback()
			t.Fatalf("CAS inventory: %d %v", len(cells), err)
		}
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
		return db, cells[0]
	}
	for _, tc := range []struct{ name, collation string }{{"nocase-source", "NOCASE"}, {"rtrim-source", "RTRIM"}} {
		t.Run(tc.name, func(t *testing.T) {
			db, cell := makeDB(t, tc.collation)
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := appEncryptionRotationCASWrite(context.Background(), tx, cell); err != nil {
				tx.Rollback()
				t.Fatalf("exact-image CAS positive control: %v", err)
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			tx, err = db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			current := cell.original.(string)
			stale := current + " "
			if tc.collation == "NOCASE" {
				stale = strings.ToUpper(current)
			}
			if stale == current {
				tx.Rollback()
				t.Fatal("fixture did not change stored bytes")
			}
			var collationEqual int
			if err := tx.QueryRow("SELECT ? COLLATE "+tc.collation+" = ?", stale, current).Scan(&collationEqual); err != nil || collationEqual != 1 {
				tx.Rollback()
				t.Fatalf("fixture values do not compare equal under %s: %d %v", tc.collation, collationEqual, err)
			}
			if _, err := tx.Exec("UPDATE main.accounts SET email=? WHERE id=1", stale); err != nil {
				tx.Rollback()
				t.Fatal(err)
			}
			if err := appEncryptionRotationCASWrite(context.Background(), tx, cell); err == nil || !strings.Contains(err.Error(), "compare-and-swap") {
				tx.Rollback()
				t.Fatalf("stale source CAS did not reject byte difference: %v", err)
			}
			var got string
			if err := tx.QueryRow("SELECT email FROM main.accounts WHERE id=1").Scan(&got); err != nil || got != stale {
				tx.Rollback()
				t.Fatal("stale source CAS overwrote stored bytes")
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
		})
	}
	db, cell := makeDB(t, "NOCASE")
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cell.writeCipher = false
	cell.newCipher = ""
	var rtrimEqual int
	if err := tx.QueryRow("SELECT ? COLLATE RTRIM = ?", cell.originalBlind.(string)+" ", cell.originalBlind).Scan(&rtrimEqual); err != nil || rtrimEqual != 1 {
		tx.Rollback()
		t.Fatalf("blind fixture is not RTRIM-equal: %d %v", rtrimEqual, err)
	}
	if _, err := tx.Exec("UPDATE main.accounts SET email_blind=email_blind||' ' WHERE id=1"); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := appEncryptionRotationCASWrite(context.Background(), tx, cell); err == nil || !strings.Contains(err.Error(), "compare-and-swap") {
		tx.Rollback()
		t.Fatalf("blind-only RTRIM CAS accepted a byte difference: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	totpDB, _ := appEncryptionRotationTestDB(t)
	appEncryptionRotationMustExec(t, totpDB, "CREATE TABLE _benmore_users(id INTEGER PRIMARY KEY,totp_secret TEXT COLLATE NOCASE)")
	secret, err := fieldEncryptCtx(oldKey, totpSecretTable, totpSecretColumn, "totp-case")
	if err != nil {
		t.Fatal(err)
	}
	appEncryptionRotationMustExec(t, totpDB, "INSERT INTO _benmore_users VALUES(1,?)", secret)
	tx, err = totpDB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	todo, err := collectTOTPSecretRotations(context.Background(), tx, oldKey, newKey)
	if err != nil || len(todo) != 1 {
		tx.Rollback()
		t.Fatalf("TOTP CAS setup: %d %v", len(todo), err)
	}
	if _, err := applyTOTPSecretRotationsContextTx(context.Background(), tx, todo); err != nil {
		tx.Rollback()
		t.Fatalf("exact TOTP CAS positive control: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	tx, err = totpDB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	todo, err = collectTOTPSecretRotations(context.Background(), tx, oldKey, newKey)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	stale := strings.ToUpper(todo[0].original.(string))
	if stale == todo[0].original {
		tx.Rollback()
		t.Fatal("TOTP fixture not case-discriminating")
	}
	var nocaseEqual int
	if err := tx.QueryRow("SELECT ? COLLATE NOCASE = ?", stale, todo[0].original).Scan(&nocaseEqual); err != nil || nocaseEqual != 1 {
		tx.Rollback()
		t.Fatalf("TOTP fixture is not NOCASE-equal: %d %v", nocaseEqual, err)
	}
	if _, err := tx.Exec("UPDATE main._benmore_users SET totp_secret=? WHERE id=1", stale); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if _, err := applyTOTPSecretRotationsContextTx(context.Background(), tx, todo); err == nil || !strings.Contains(err.Error(), "compare-and-swap missed") {
		tx.Rollback()
		t.Fatalf("TOTP NOCASE CAS accepted byte difference: %v", err)
	}
	var got string
	if err := tx.QueryRow("SELECT totp_secret FROM _benmore_users WHERE id=1").Scan(&got); err != nil || got != stale {
		tx.Rollback()
		t.Fatal("stale TOTP CAS overwrote stored bytes")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
}

func TestRotateAppEncryptionRowsTxRejectsUnsupportedSchema(t *testing.T) {
	cases := []struct {
		name, ddl string
		config    *EncryptedFieldConfig
	}{
		{"without-rowid", `CREATE TABLE accounts(key TEXT PRIMARY KEY,secret TEXT) WITHOUT ROWID`, &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"accounts": {{Column: "secret"}}}}},
		{"without-rowid-spaced-empty", `CREATE TABLE accounts(key TEXT PRIMARY KEY,secret TEXT) WITHOUT   ROWID`, &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"accounts": {{Column: "secret"}}}}},
		{"without-rowid-comment-empty", `CREATE TABLE accounts(key TEXT PRIMARY KEY,secret TEXT) WITHOUT /* gap */ ROWID`, &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"accounts": {{Column: "secret"}}}}},
		{"generated", `CREATE TABLE accounts(id INTEGER PRIMARY KEY,secret TEXT,copy TEXT GENERATED ALWAYS AS (secret) STORED)`, &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"accounts": {{Column: "secret"}}}}},
		{"rowid-shadow", `CREATE TABLE accounts(rowid TEXT,_rowid_ TEXT,oid TEXT,secret TEXT)`, &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"accounts": {{Column: "secret"}}}}},
		{"foreign-key", `CREATE TABLE parent(secret TEXT UNIQUE); CREATE TABLE accounts(id INTEGER PRIMARY KEY,secret TEXT REFERENCES parent(secret))`, &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"accounts": {{Column: "secret"}}}}},
		{"missing-config-table", "CREATE TABLE present(id INTEGER PRIMARY KEY,secret TEXT)", &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"missing": {{Column: "secret"}}}}},
		{"missing-config-column", `CREATE TABLE accounts(id INTEGER PRIMARY KEY,other TEXT)`, &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"accounts": {{Column: "secret"}}}}},
		{"optional-view", `CREATE VIEW _benmore_webhooks AS SELECT 1 AS id,'secret' AS secret`, nil},
		{"duplicate-target", `CREATE TABLE accounts(id INTEGER PRIMARY KEY,secret TEXT)`, &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"accounts": {{Column: "secret"}, {Column: "secret"}}}}},
		{"missing-blind", `CREATE TABLE accounts(id INTEGER PRIMARY KEY,email TEXT)`, &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"accounts": {{Column: "email", BlindIndex: true}}}}},
		{"partial-oauth", `CREATE TABLE _benmore_oauth_tokens(id INTEGER PRIMARY KEY,access_token TEXT)`, nil},
		{"oauth-wrong-fixed-type-empty", `CREATE TABLE _benmore_oauth_tokens(id INTEGER PRIMARY KEY,access_token BLOB,refresh_token TEXT)`, nil},
		{"webhook-wrong-fixed-type-empty", `CREATE TABLE _benmore_webhooks(id INTEGER PRIMARY KEY,secret INTEGER)`, nil},
		{"totp-without-rowid-empty", `CREATE TABLE _benmore_users(id INTEGER,totp_secret TEXT,PRIMARY KEY(id)) WITHOUT/* gap */ROWID`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, _ := appEncryptionRotationTestDB(t)
			for _, stmt := range strings.Split(tc.ddl, ";") {
				if strings.TrimSpace(stmt) != "" {
					appEncryptionRotationMustExec(t, db, stmt)
				}
			}
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = rotateAppEncryptionRowsTx(context.Background(), tx, tc.config, make([]byte, 32), bytesKey(0x91))
			if err == nil {
				tx.Rollback()
				t.Fatal("unsupported schema accepted")
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRotateAppEncryptionRowsTxRefusesBlindIndexPrimaryKey(t *testing.T) {
	db, _ := appEncryptionRotationTestDB(t)
	appEncryptionRotationMustExec(t, db, `CREATE TABLE accounts(id INTEGER,email TEXT,email_blind TEXT PRIMARY KEY)`)
	oldKey, newKey := bytesKey(0x18), bytesKey(0x91)
	ciphertext, err := fieldEncryptCtx(oldKey, "accounts", "email", "primary@example.test")
	if err != nil {
		t.Fatal(err)
	}
	blindKey, err := DeriveBlindIndexKey(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	hash := BlindIndexHMACWithKey(blindKey, "primary@example.test")
	appEncryptionRotationMustExec(t, db, "INSERT INTO accounts(id,email,email_blind) VALUES(1,?,?)", ciphertext, hash)
	before := appEncryptionRotationRows(t, db, "SELECT * FROM main.accounts")
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rotateAppEncryptionRowsTx(context.Background(), tx, &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"accounts": {{Column: "email", BlindIndex: true}}}}, oldKey, newKey)
	if err == nil || !strings.Contains(err.Error(), "blind-index sibling accounts.email_blind is missing or incompatible") {
		tx.Rollback()
		t.Fatalf("expected blind primary-key schema refusal, got %v", err)
	}
	if got := appEncryptionRotationRows(t, tx, "SELECT * FROM main.accounts"); !reflect.DeepEqual(got, before) {
		tx.Rollback()
		t.Fatal("blind primary-key refusal followed a write")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
}

func TestRotateAppEncryptionRowsTxRejectsUnsupportedRuntimeStorage(t *testing.T) {
	oldKey, newKey := bytesKey(0x15), bytesKey(0x39)
	cases := []struct {
		name, ddl, insert string
		config            *EncryptedFieldConfig
	}{
		{"configured-encrypted-blob", `CREATE TABLE accounts(id INTEGER PRIMARY KEY,email TEXT,email_blind TEXT)`, `INSERT INTO accounts VALUES(1,CAST(? AS BLOB),NULL)`, &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"accounts": {{Column: "email", BlindIndex: true}}}}},
		{"oauth-blob", `CREATE TABLE _benmore_oauth_tokens(id INTEGER PRIMARY KEY,access_token TEXT,refresh_token TEXT)`, `INSERT INTO _benmore_oauth_tokens VALUES(1,CAST(? AS BLOB),NULL)`, nil},
		{"webhook-blob", `CREATE TABLE _benmore_webhooks(id INTEGER PRIMARY KEY,secret TEXT)`, `INSERT INTO _benmore_webhooks VALUES(1,CAST(? AS BLOB))`, nil},
		{"totp-blob", `CREATE TABLE _benmore_users(id INTEGER PRIMARY KEY,totp_secret TEXT)`, `INSERT INTO _benmore_users VALUES(1,CAST(? AS BLOB))`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, _ := appEncryptionRotationTestDB(t)
			appEncryptionRotationMustExec(t, db, tc.ddl)
			value, err := fieldEncryptCtx(oldKey, "accounts", "email", "stored-as-blob")
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(tc.name, "oauth") {
				value, err = fieldEncryptWithKey(oldKey, "stored-as-blob")
				if err != nil {
					t.Fatal(err)
				}
			}
			if strings.Contains(tc.name, "webhook") {
				value, err = fieldEncryptWithKey(oldKey, "stored-as-blob")
				if err != nil {
					t.Fatal(err)
				}
			}
			if strings.Contains(tc.name, "totp") {
				value, err = fieldEncryptCtx(oldKey, totpSecretTable, totpSecretColumn, "stored-as-blob")
				if err != nil {
					t.Fatal(err)
				}
			}
			appEncryptionRotationMustExec(t, db, tc.insert, value)
			table := map[string]string{"configured-encrypted-blob": "accounts", "oauth-blob": "_benmore_oauth_tokens", "webhook-blob": "_benmore_webhooks", "totp-blob": "_benmore_users"}[tc.name]
			before := appEncryptionRotationRows(t, db, "SELECT * FROM main."+table)
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = rotateAppEncryptionRowsTx(context.Background(), tx, tc.config, oldKey, newKey)
			if err == nil {
				tx.Rollback()
				t.Fatal("unsupported BLOB storage accepted")
			}
			if strings.Contains(tc.name, "webhook") && !strings.Contains(err.Error(), "unsupported runtime storage type in encrypted value") {
				tx.Rollback()
				t.Fatalf("webhook BLOB was rejected for an unexpected reason: %v", err)
			}
			after := appEncryptionRotationRows(t, tx, "SELECT * FROM main."+table)
			if !reflect.DeepEqual(before, after) {
				tx.Rollback()
				t.Fatal("runtime storage refusal followed a write")
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRotateAppEncryptionRowsTxRejectsIncompatibleTypesAndRowIDs(t *testing.T) {
	types := []struct {
		name, ddl, insert, table string
		config                   *EncryptedFieldConfig
	}{
		{"oauth-text-empty", `CREATE TABLE _benmore_oauth_tokens(id INTEGER PRIMARY KEY,access_token INTEGER,refresh_token TEXT)`, "", "_benmore_oauth_tokens", nil},
		{"oauth-text-populated", `CREATE TABLE _benmore_oauth_tokens(id INTEGER PRIMARY KEY,access_token INTEGER,refresh_token TEXT)`, `INSERT INTO _benmore_oauth_tokens VALUES(1,7,NULL)`, "_benmore_oauth_tokens", nil},
		{"webhook-text-empty", `CREATE TABLE _benmore_webhooks(id INTEGER PRIMARY KEY,secret REAL)`, "", "_benmore_webhooks", nil},
		{"webhook-text-populated", `CREATE TABLE _benmore_webhooks(id INTEGER PRIMARY KEY,secret REAL)`, `INSERT INTO _benmore_webhooks VALUES(1,7.5)`, "_benmore_webhooks", nil},
	}
	for _, tc := range types {
		t.Run(tc.name, func(t *testing.T) {
			db, _ := appEncryptionRotationTestDB(t)
			appEncryptionRotationMustExec(t, db, tc.ddl)
			if tc.insert != "" {
				appEncryptionRotationMustExec(t, db, tc.insert)
			}
			rowsBefore := appEncryptionRotationRows(t, db, "SELECT * FROM main."+tc.table)
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := rotateAppEncryptionRowsTx(context.Background(), tx, tc.config, bytesKey(0x18), bytesKey(0x3c)); err == nil {
				tx.Rollback()
				t.Fatal("non-TEXT fixed storage accepted")
			}
			if got := appEncryptionRotationRows(t, tx, "SELECT * FROM main."+tc.table); !reflect.DeepEqual(got, rowsBefore) {
				tx.Rollback()
				t.Fatal("fixed storage refusal followed a write")
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
		})
	}

	for _, family := range []struct {
		name, table, ddl, insert string
		config                   *EncryptedFieldConfig
	}{
		{"configured", "accounts", `CREATE TABLE accounts(id INTEGER,secret TEXT,PRIMARY KEY(id)) WITHOUT /* gap */ ROWID`, `INSERT INTO accounts VALUES(1,'legacy')`, &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"accounts": {{Column: "secret"}}}}},
		{"oauth", "_benmore_oauth_tokens", `CREATE TABLE _benmore_oauth_tokens(id INTEGER,access_token TEXT,refresh_token TEXT,PRIMARY KEY(id)) WITHOUT /* gap */ ROWID`, `INSERT INTO _benmore_oauth_tokens VALUES(1,'legacy',NULL)`, nil},
		{"webhook", "_benmore_webhooks", `CREATE TABLE _benmore_webhooks(id INTEGER,secret TEXT,PRIMARY KEY(id)) WITHOUT /* gap */ ROWID`, `INSERT INTO _benmore_webhooks VALUES(1,'legacy')`, nil},
		{"totp", "_benmore_users", `CREATE TABLE _benmore_users(id INTEGER,totp_secret TEXT,PRIMARY KEY(id)) WITHOUT /* gap */ ROWID`, `INSERT INTO _benmore_users VALUES(1,'legacy')`, nil},
	} {
		for _, populated := range []bool{false, true} {
			name := family.name + "-empty"
			if populated {
				name = family.name + "-populated"
			}
			t.Run(name, func(t *testing.T) {
				db, _ := appEncryptionRotationTestDB(t)
				appEncryptionRotationMustExec(t, db, family.ddl)
				if populated {
					appEncryptionRotationMustExec(t, db, family.insert)
				}
				before := appEncryptionRotationRows(t, db, "SELECT * FROM main."+family.table)
				tx, err := db.BeginTx(context.Background(), nil)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := rotateAppEncryptionRowsTx(context.Background(), tx, family.config, bytesKey(0x19), bytesKey(0x3d)); err == nil {
					tx.Rollback()
					t.Fatal("WITHOUT ROWID target accepted")
				}
				if got := appEncryptionRotationRows(t, tx, "SELECT * FROM main."+family.table); !reflect.DeepEqual(got, before) {
					tx.Rollback()
					t.Fatal("row identity refusal followed a write")
				}
				if err := tx.Rollback(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestRotateAppEncryptionRowsTxAllowsUnrelatedImplicitForeignKey(t *testing.T) {
	db, _ := appEncryptionRotationTestDB(t)
	appEncryptionRotationMustExec(t, db, `CREATE TABLE accounts(id INTEGER PRIMARY KEY,secret TEXT)`)
	appEncryptionRotationMustExec(t, db, `CREATE TABLE parent(id INTEGER PRIMARY KEY)`)
	appEncryptionRotationMustExec(t, db, `CREATE TABLE child(parent_id INTEGER REFERENCES parent)`)
	appEncryptionRotationMustExec(t, db, `INSERT INTO parent VALUES(1)`)
	appEncryptionRotationMustExec(t, db, `INSERT INTO child VALUES(1)`)
	before := appEncryptionRotationRows(t, db, "SELECT id,secret FROM main.accounts")
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotateAppEncryptionRowsTx(context.Background(), tx, &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"accounts": {{Column: "secret"}}}}, bytesKey(0x16), bytesKey(0x3a)); err != nil {
		tx.Rollback()
		t.Fatalf("unrelated implicit-PK foreign key refused: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if got := appEncryptionRotationRows(t, db, "SELECT id,secret FROM main.accounts"); !reflect.DeepEqual(got, before) {
		t.Fatal("unrelated implicit FK control changed data")
	}
}

func TestRotateAppEncryptionRowsTxPreservesRealPlaintextBlindScalar(t *testing.T) {
	db, _ := appEncryptionRotationTestDB(t)
	appEncryptionRotationMustExec(t, db, "CREATE TABLE accounts(id INTEGER PRIMARY KEY,amount REAL,amount_blind TEXT)")
	oldKey, newKey := bytesKey(0x1a), bytesKey(0x3e)
	oldBlind, err := DeriveBlindIndexKey(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	oldHash := BlindIndexHMACWithKey(oldBlind, "1.25")
	appEncryptionRotationMustExec(t, db, "INSERT INTO accounts VALUES(1,1.25,?)", oldHash)
	before := appEncryptionRotationRows(t, db, "SELECT amount,typeof(amount),amount_blind FROM main.accounts")
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	counts, err := rotateAppEncryptionRowsTx(context.Background(), tx, &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"accounts": {{Column: "amount", BlindIndex: true}}}}, oldKey, newKey)
	if err != nil {
		tx.Rollback()
		t.Fatalf("REAL plaintext control: %v", err)
	}
	if counts != (appEncryptionRowRotationCounts{BlindValues: 1}) {
		tx.Rollback()
		t.Fatalf("REAL plaintext counts: %+v", counts)
	}
	var amount float64
	var storageType, blind string
	if err := tx.QueryRow("SELECT amount,typeof(amount),amount_blind FROM main.accounts WHERE id=1").Scan(&amount, &storageType, &blind); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	newBlind, err := DeriveBlindIndexKey(newKey)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if amount != 1.25 || storageType != "real" || blind != BlindIndexHMACWithKey(newBlind, "1.25") {
		tx.Rollback()
		t.Fatal("REAL scalar or its native blind representation changed incorrectly")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if got := appEncryptionRotationRows(t, db, "SELECT amount,typeof(amount),amount_blind FROM main.accounts"); !reflect.DeepEqual(got, before) {
		t.Fatal("caller rollback did not restore REAL plaintext and blind value")
	}
}

func TestRotateTOTPSecretsContextAndWrapperPreserveEnrollmentState(t *testing.T) {
	db, path := appEncryptionRotationTestDB(t)
	appEncryptionRotationMustExec(t, db, `CREATE TABLE _benmore_users(id INTEGER PRIMARY KEY,totp_secret TEXT,totp_last_step INTEGER,mfa_backup_codes TEXT)`)
	oldKey, newKey := bytesKey(0x21), bytesKey(0x42)
	active, err := fieldEncryptCtx(oldKey, totpSecretTable, totpSecretColumn, "active-secret")
	if err != nil {
		t.Fatal(err)
	}
	pending, err := fieldEncryptCtx(oldKey, totpSecretTable, totpSecretColumn, "pending-secret")
	if err != nil {
		t.Fatal(err)
	}
	appEncryptionRotationMustExec(t, db, `INSERT INTO _benmore_users VALUES(1,?,71,'a'),(2,?,82,'b'),(3,'plain',93,'c'),(4,NULL,104,'d'),(5,'',115,'e'),(6,?,126,'f')`, active, totpPendingPrefix+pending, active)
	before := appEncryptionRotationRows(t, db, "SELECT id,totp_secret,totp_last_step,mfa_backup_codes FROM main._benmore_users ORDER BY id")
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	n, err := rotateTOTPSecretsContextTx(context.Background(), tx, oldKey, newKey)
	if err != nil || n != 3 {
		tx.Rollback()
		t.Fatalf("context TOTP rotation %d %v", n, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(appEncryptionRotationRows(t, db, "SELECT id,totp_secret,totp_last_step,mfa_backup_codes FROM main._benmore_users ORDER BY id"), before) {
		t.Fatal("TOTP wrapper transaction rollback changed rows")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tx, err = db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotateTOTPSecretsContextTx(canceled, tx, oldKey, newKey); err == nil {
		tx.Rollback()
		t.Fatal("cancelled TOTP rotation accepted")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	tx, err = db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	todo, err := collectTOTPSecretRotations(context.Background(), tx, oldKey, newKey)
	if err != nil || len(todo) != 3 {
		tx.Rollback()
		t.Fatalf("TOTP stale-image setup %d %v", len(todo), err)
	}
	if _, err := tx.Exec("UPDATE _benmore_users SET totp_secret='concurrent-value' WHERE id=?", todo[0].id); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if _, err := applyTOTPSecretRotationsContextTx(context.Background(), tx, todo); err == nil || !strings.Contains(err.Error(), "compare-and-swap missed") {
		tx.Rollback()
		t.Fatalf("stale TOTP image error: %v", err)
	}
	var stale string
	if err := tx.QueryRow("SELECT totp_secret FROM _benmore_users WHERE id=?", todo[0].id).Scan(&stale); err != nil || stale != "concurrent-value" {
		tx.Rollback()
		t.Fatal("stale TOTP CAS overwrote changed row")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	tx, err = db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	n, err = rotateTOTPSecretsTx(tx, oldKey, newKey)
	if err != nil || n != 3 {
		tx.Rollback()
		t.Fatalf("compatibility TOTP wrapper %d %v", n, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	RegisterDBEncryptionKey(path, newKey)
	t.Cleanup(func() { dbCryptoRegistry.Delete(canonicalDBPath(path)) })
	var got string
	if err := db.QueryRow("SELECT totp_secret FROM _benmore_users WHERE id=2").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, totpPendingPrefix+encPrefixV2) {
		t.Fatal("pending marker or v2 encoding changed")
	}
	if plain, err := openTOTPSecret(db, got); err != nil || plain != "pending-secret" {
		t.Fatalf("pending TOTP read %q %v", plain, err)
	}
	var replay int
	var backup string
	for id, want := range map[int]struct {
		step   int
		backup string
	}{1: {71, "a"}, 2: {82, "b"}, 3: {93, "c"}, 4: {104, "d"}, 5: {115, "e"}, 6: {126, "f"}} {
		if err := db.QueryRow("SELECT totp_last_step,mfa_backup_codes FROM _benmore_users WHERE id=?", id).Scan(&replay, &backup); err != nil || replay != want.step || backup != want.backup {
			t.Fatalf("rotation changed replay or backup-code state for row %d", id)
		}
	}
}

func bytesKey(v byte) []byte {
	return []byte{v, v, v, v, v, v, v, v, v, v, v, v, v, v, v, v, v, v, v, v, v, v, v, v, v, v, v, v, v, v, v, v}
}
