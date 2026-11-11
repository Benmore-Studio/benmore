//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mfaDurabilityApp starts an app with no configured ENCRYPTION_KEY (so it
// runs on a key generated for the process) whose `user` role must enroll.
func mfaDurabilityApp(t *testing.T) (string, *App, *http.ServeMux) {
	t.Helper()
	dir := webhookDurabilityFixture(t, false)
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte("site_name: MFA durability\nauth:\n  require_mfa_for_roles: user\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	app, err := startServedApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	// The fixture has no pages, so nothing created the auth tables yet.
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(app.DB)
	EnsureLoginAttemptsTable(app.DB)
	EnsurePasswordResetsTable(app.DB)
	EnsureAuditLogTable(app.DB)
	if err := EnsureUserRolesTable(app.DB); err != nil {
		t.Fatal(err)
	}
	if keys := cryptoKeysForDBPath(filepath.Join(dir, "data.db")); keys == nil || !keys.ephemeral {
		t.Fatal("fixture: the app should start on a generated per-process key")
	}
	mux := http.NewServeMux()
	RegisterMFARoutes(mux, app)
	return dir, app, mux
}

// MFA is on for every app, but the key was saved only for encrypted.yaml
// apps, so an app without a configured ENCRYPTION_KEY kept every TOTP secret
// in plaintext and said so only in a journal WARN. Enrolling now saves the
// generated key the way the first webhook subscription does (env.yaml, read
// back the way the next start reads it), seals the secret, and after a
// restart the factor still opens.
func TestMFAEnrollmentMakesGeneratedKeyDurableAndSeals(t *testing.T) {
	dir, app, mux := mfaDurabilityApp(t)
	dbPath := filepath.Join(dir, "data.db")
	const email = "mgr@example.test"
	uid := recoveryUser(t, app, email, "Original!Password1", 1)

	grant := mfaRecoveryLogin(t, app, email, "Original!Password1")
	secret := mfaRecoverySetup(t, mux, grant)
	keys := cryptoKeysForDBPath(dbPath)
	if keys == nil || keys.ephemeral {
		t.Fatal("enrollment left the app on a per-process key")
	}
	envYAML, err := os.ReadFile(filepath.Join(dir, "env.yaml"))
	if err != nil || !bytes.Contains(envYAML, []byte("ENCRYPTION_KEY:")) {
		t.Fatalf("the generated key was not saved to env.yaml: %v %q", err, envYAML)
	}
	if stored := storedTOTPSecret(t, app.DB, uid); !strings.HasPrefix(stored, totpPendingPrefix+encPrefixV2) || strings.Contains(stored, secret) {
		t.Fatalf("pending enrollment is not sealed at rest: %q", stored)
	}
	w := mfaRecoveryCall(mux, grant, "verify", `{"code":"`+GenerateTOTP(secret)+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("verify = %d %s", w.Code, w.Body.String())
	}
	active := storedTOTPSecret(t, app.DB, uid)
	if !strings.HasPrefix(active, encPrefixV2) {
		t.Fatalf("active factor is not sealed at rest: %q", active)
	}
	before := append([]byte(nil), keys.aes...)
	app.Shutdown()

	forgetProcessKeys(dir, false)
	restarted, err := startServedApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Shutdown()
	if keys := cryptoKeysForDBPath(dbPath); keys == nil || keys.ephemeral || !bytes.Equal(keys.aes, before) {
		t.Fatal("the restarted app did not load the saved key")
	}
	if got, err := openTOTPSecret(restarted.DB, storedTOTPSecret(t, restarted.DB, uid)); err != nil || got != secret {
		t.Fatalf("after restart the factor opens to %q (%v), want the enrolled secret", got, err)
	}
}

// A factor stored unsealed before this change is sealed on its next use,
// which makes the generated key durable first.
func TestMFAUnsealedFactorSealedOnUseUnderSavedKey(t *testing.T) {
	dir, app, _ := mfaDurabilityApp(t)
	const email = "legacy@example.test"
	uid := recoveryUser(t, app, email, "Original!Password1", 1)
	const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	if _, err := app.DB.Exec("UPDATE _benmore_users SET totp_secret = ? WHERE id = ?", secret, uid); err != nil {
		t.Fatal(err)
	}
	if !ValidateMFACode(app.DB, uid, GenerateTOTP(secret)) {
		t.Fatal("the unsealed factor did not verify")
	}
	stored := storedTOTPSecret(t, app.DB, uid)
	if !strings.HasPrefix(stored, encPrefixV2) {
		t.Fatalf("the used factor is still unsealed: %q", stored)
	}
	if keys := cryptoKeysForDBPath(filepath.Join(dir, "data.db")); keys == nil || keys.ephemeral {
		t.Fatal("the factor was sealed under a per-process key")
	}
	if got, err := openTOTPSecret(app.DB, stored); err != nil || got != secret {
		t.Fatalf("sealed factor opens to %q (%v)", got, err)
	}
}

// Where the generated key cannot be saved, enrollment still works and the
// secret stays unsealed: it is never sealed under a key the restart loses.
func TestMFAEnrollmentWithoutDurableKeyNeverSealsUnderProcessKey(t *testing.T) {
	dir, app, mux := mfaDurabilityApp(t)
	if err := os.Mkdir(filepath.Join(dir, "env.yaml"), 0o700); err != nil {
		t.Fatal(err)
	}
	const email = "mgr@example.test"
	uid := recoveryUser(t, app, email, "Original!Password1", 1)
	grant := mfaRecoveryLogin(t, app, email, "Original!Password1")
	secret := mfaRecoverySetup(t, mux, grant)
	if keys := cryptoKeysForDBPath(filepath.Join(dir, "data.db")); keys == nil || !keys.ephemeral {
		t.Fatal("a key that could not be saved was marked durable")
	}
	if stored := storedTOTPSecret(t, app.DB, uid); stored != totpPendingPrefix+secret {
		t.Fatalf("stored = %q, want the unsealed pending secret", stored)
	}
	w := mfaRecoveryCall(mux, grant, "verify", `{"code":"`+GenerateTOTP(secret)+`"}`)
	var result struct{ Token string }
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Token == "" {
		t.Fatalf("verify = %d %s", w.Code, w.Body.String())
	}
	if stored := storedTOTPSecret(t, app.DB, uid); stored != secret {
		t.Fatalf("active factor = %q, want the unsealed secret", stored)
	}
}
