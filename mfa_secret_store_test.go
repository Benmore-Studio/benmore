//go:build !cli

package main

import (
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// withTOTPKey registers key for the app's database for the duration of a test.
func withTOTPKey(t *testing.T, app *App, key []byte, ephemeral bool) {
	t.Helper()
	path := filepath.Join(app.Dir, "data.db")
	registerDBEncryptionKey(path, key, ephemeral)
	t.Cleanup(func() { dbCryptoRegistry.Delete(canonicalDBPath(path)) })
}

func storedTOTPSecret(t *testing.T, db *sql.DB, uid int64) string {
	t.Helper()
	var stored string
	if err := db.QueryRow("SELECT COALESCE(totp_secret,'') FROM _benmore_users WHERE id=?", uid).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	return stored
}

// A TOTP secret lets whoever holds it mint second factors forever, so the
// database must not hold it readable: enrollment, activation, login and
// disable all work on the sealed form, and a plain read reveals nothing.
func TestTOTPSecretsAreSealedAtRest(t *testing.T) {
	app, mux := auditApp(t)
	EnsureLoginAttemptsTable(app.DB)
	withTOTPKey(t, app, testKeyBytes(0x5C), false)
	sid := createCrudScopeSession(t, app, "mfa@example.com", "user", "", "")
	uid := GetSessionFromDB(app.DB, sid).UserID
	hash, _ := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	auditExec(t, app.DB, "UPDATE _benmore_users SET password_hash=? WHERE id=?", string(hash), uid)

	w := auditPost(mux, sid, "/api/_auth/mfa/setup", "", `{"password":"`+fixturePassword+`"}`, true)
	if w.Code != http.StatusOK {
		t.Fatalf("setup = %d %s", w.Code, w.Body.String())
	}
	var setup struct {
		Secret string `json:"secret"`
	}
	json.Unmarshal(w.Body.Bytes(), &setup)
	stored := storedTOTPSecret(t, app.DB, uid)
	if setup.Secret == "" || strings.Contains(stored, setup.Secret) || !strings.HasPrefix(stored, totpPendingPrefix+encPrefixV2) {
		t.Fatalf("pending enrollment stored as %q, want the sealed secret", stored)
	}

	// Each operation proves a different accepted step. Reusing enrollment's
	// code for login/removal is now refused even when the secret is sealed.
	if rem := 30 - time.Now().Unix()%30; rem < 5 {
		time.Sleep(time.Duration(rem+1) * time.Second)
	}
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	step := uint64(time.Now().Unix() / 30)
	body, _ := json.Marshal(map[string]string{"code": computeHOTP(secretBytes, step-1)})
	if w := auditPost(mux, sid, "/api/_auth/mfa/verify", "", string(body), true); w.Code != http.StatusOK {
		t.Fatalf("verify = %d %s", w.Code, w.Body.String())
	}
	stored = storedTOTPSecret(t, app.DB, uid)
	if strings.Contains(stored, setup.Secret) || !strings.HasPrefix(stored, encPrefixV2) || !CheckMFA(app.DB, uid) {
		t.Fatalf("active factor stored as %q, want the sealed secret", stored)
	}
	if !ValidateMFACode(app.DB, uid, computeHOTP(secretBytes, step)) {
		t.Fatal("login MFA step rejected a valid code for a sealed secret")
	}
	if ValidateMFACode(app.DB, uid, stored) {
		t.Fatal("the stored ciphertext was accepted as a code")
	}

	// App step-up gates check the enrolled factor in SQL without ever
	// holding the secret; that must keep working on the sealed form.
	gate := totpTestDB(t)
	gateKey := testKeyBytes(0x5D)
	gatePath := dbFilePath(t, gate)
	RegisterDBEncryptionKey(gatePath, gateKey)
	t.Cleanup(func() { dbCryptoRegistry.Delete(canonicalDBPath(gatePath)) })
	sealed, err := fieldEncryptCtx(gateKey, totpSecretTable, totpSecretColumn, setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if !totpValid(t, gate, sealed, GenerateTOTP(setup.Secret)) {
		t.Fatal("benmore_totp_valid rejected a sealed secret")
	}
	if totpValid(t, gate, totpPendingPrefix+sealed, GenerateTOTP(setup.Secret)) {
		t.Fatal("benmore_totp_valid accepted a pending sealed secret")
	}
	if foreign, _ := fieldEncryptCtx(testKeyBytes(0x5E), totpSecretTable, totpSecretColumn, setup.Secret); totpValid(t, gate, foreign, GenerateTOTP(setup.Secret)) {
		t.Fatal("benmore_totp_valid accepted a secret sealed under another key")
	}

	// Disabling proves and consumes a fresh step before removing the factor.
	body, _ = json.Marshal(map[string]string{"code": computeHOTP(secretBytes, step+1)})
	if w := auditPost(mux, sid, "/api/_auth/mfa/disable", "", string(body), true); w.Code != http.StatusOK {
		t.Fatalf("disable = %d %s", w.Code, w.Body.String())
	}
	if storedTOTPSecret(t, app.DB, uid) != "" || CheckMFA(app.DB, uid) {
		t.Fatal("disable left the factor in place")
	}
}

// Enrollments made before sealing keep working, and are sealed at startup or
// on first use once the app has a durable key.
func TestLegacyTOTPSecretsAreSealedWithoutLockout(t *testing.T) {
	app, _ := auditApp(t)
	const active, pending = "JBSWY3DPEHPK3PXP", "KRSXG5CTMVRXEZLU"
	ids := map[string]int64{}
	for _, email := range []string{"active@example.com", "pending@example.com", "used@example.com"} {
		sid := createCrudScopeSession(t, app, email, "user", "", "")
		ids[email] = GetSessionFromDB(app.DB, sid).UserID
	}
	auditExec(t, app.DB, "UPDATE _benmore_users SET totp_secret=? WHERE id IN (?, ?)", active, ids["active@example.com"], ids["used@example.com"])
	auditExec(t, app.DB, "UPDATE _benmore_users SET totp_secret=? WHERE id=?", totpPendingPrefix+pending, ids["pending@example.com"])

	// Without a durable key nothing is sealed: a secret sealed under a
	// per-process key would be lost at the next restart.
	withTOTPKey(t, app, testKeyBytes(0x61), true)
	if err := sealStoredTOTPSecrets(app.DB); err != nil {
		t.Fatal(err)
	}
	if storedTOTPSecret(t, app.DB, ids["active@example.com"]) != active {
		t.Fatal("secret sealed under an ephemeral key")
	}
	if !ValidateMFACode(app.DB, ids["used@example.com"], GenerateTOTP(active)) || storedTOTPSecret(t, app.DB, ids["used@example.com"]) != active {
		t.Fatal("plaintext factor must keep working, unsealed, without a durable key")
	}
	if sealed, _ := sealTOTPSecret(app.DB, active); sealed != active {
		t.Fatal("new enrollment sealed under an ephemeral key")
	}

	// With a durable key, first use seals the row it validated...
	withTOTPKey(t, app, testKeyBytes(0x62), false)
	auditExec(t, app.DB, "UPDATE _benmore_users SET mfa_last_totp=NULL WHERE id=?", ids["used@example.com"])
	if !ValidateMFACode(app.DB, ids["used@example.com"], GenerateTOTP(active)) {
		t.Fatal("legacy plaintext factor rejected")
	}
	if got := storedTOTPSecret(t, app.DB, ids["used@example.com"]); !strings.HasPrefix(got, encPrefixV2) {
		t.Fatalf("legacy secret not sealed on use: %q", got)
	}
	// ...and startup seals the rest, pending enrollments included.
	if err := sealStoredTOTPSecrets(app.DB); err != nil {
		t.Fatal(err)
	}
	gotActive := storedTOTPSecret(t, app.DB, ids["active@example.com"])
	gotPending := storedTOTPSecret(t, app.DB, ids["pending@example.com"])
	if !strings.HasPrefix(gotActive, encPrefixV2) || !strings.HasPrefix(gotPending, totpPendingPrefix+encPrefixV2) {
		t.Fatalf("startup left secrets unsealed: active=%q pending=%q", gotActive, gotPending)
	}
	if strings.Contains(gotActive, active) || strings.Contains(gotPending, pending) {
		t.Fatal("sealed value contains the secret")
	}
	if !CheckMFA(app.DB, ids["active@example.com"]) || CheckMFA(app.DB, ids["pending@example.com"]) {
		t.Fatal("sealing changed enrollment state")
	}
	if !ValidateMFACode(app.DB, ids["active@example.com"], GenerateTOTP(active)) {
		t.Fatal("factor lost when sealed at startup")
	}
	if open, err := openTOTPSecret(app.DB, gotPending); err != nil || open != pending {
		t.Fatalf("pending enrollment lost when sealed: %q %v", open, err)
	}
}

// Rotating ENCRYPTION_KEY moves TOTP secrets to the new key with everything
// else, including in an app that declares no encrypted.yaml fields.
func TestEncryptionKeyRotationResealsTOTPSecrets(t *testing.T) {
	app, _ := auditApp(t)
	oldGlobal, oldEphemeral, oldBlind := appEncryptionKey, appEncryptionKeyEphemeral, appBlindIndexKey.Load()
	t.Cleanup(func() {
		appEncryptionKey, appEncryptionKeyEphemeral = oldGlobal, oldEphemeral
		appBlindIndexKey.Store(oldBlind)
	})
	oldKey := testKeyBytes(0x71)
	withTOTPKey(t, app, oldKey, false)
	const secret = "JBSWY3DPEHPK3PXP"
	sid := createCrudScopeSession(t, app, "rotate@example.com", "user", "", "")
	uid := GetSessionFromDB(app.DB, sid).UserID
	sealed, err := sealTOTPSecret(app.DB, secret)
	if err != nil {
		t.Fatal(err)
	}
	auditExec(t, app.DB, "UPDATE _benmore_users SET totp_secret=? WHERE id=?", sealed, uid)

	if n, err := RotateEncryptionKey(app, "", true); err != nil || n != 1 {
		t.Fatalf("dry run = %d %v, want the TOTP secret planned", n, err)
	}
	newSource := strings.Repeat("r", 64)
	if n, err := RotateEncryptionKey(app, newSource, false); err != nil || n != 1 {
		t.Fatalf("rotation = %d %v", n, err)
	}
	newKey, _ := cryptoDeriveAppKey(newSource)
	stored := storedTOTPSecret(t, app.DB, uid)
	if stored == sealed || !strings.HasPrefix(stored, encPrefixV2) {
		t.Fatalf("TOTP secret not re-sealed: %q", stored)
	}
	if _, err := fieldDecryptCtx(oldKey, totpSecretColumn, stored); err == nil {
		t.Fatal("rotated secret still opens under the old key")
	}
	if got, err := fieldDecryptCtx(newKey, totpSecretColumn, stored); err != nil || got != secret {
		t.Fatalf("rotated secret under the new key = %q %v", got, err)
	}
	if !ValidateMFACode(app.DB, uid, GenerateTOTP(secret)) {
		t.Fatal("MFA broken after rotation")
	}
}

// dbFilePath reports the main database file of db.
func dbFilePath(t *testing.T, db *sql.DB) string {
	t.Helper()
	var path string
	if err := db.QueryRow("SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&path); err != nil {
		t.Fatal(err)
	}
	return path
}
