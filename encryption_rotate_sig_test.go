//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// In a hosted tenant the vault's key overrides env.yaml at the next start, so
// a rotation the router did not sign (and therefore will not save) is refused:
// before, an app admin or editor could rotate from inside the app and the
// restart reverted to the old key, leaving every rotated value unreadable.
func TestHostedRotationNeedsRouterSignature(t *testing.T) {
	oldSecret := serverSecret
	serverSecret = strings.Repeat("s", 64)
	t.Cleanup(func() { serverSecret = oldSecret })
	t.Setenv("BENMORE_BIND_LOOPBACK", "1")

	newKey := strings.Repeat("k", 40)
	req := httptest.NewRequest(http.MethodPost, "/api/_internal/encryption/rotate", nil)
	if rotateSigValid(req, newKey) {
		t.Fatal("unsigned request accepted")
	}
	h := map[string]string{}
	if !signRotateHeaders(h, serverSecret, newKey) {
		t.Fatal("sign failed")
	}
	for k, v := range h {
		req.Header.Set(k, v)
	}
	if !rotateSigValid(req, newKey) {
		t.Fatal("router-signed request refused")
	}
	if rotateSigValid(req, strings.Repeat("x", 40)) {
		t.Fatal("signature accepted for a different key")
	}
	other := map[string]string{}
	signRotateHeaders(other, strings.Repeat("o", 64), newKey)
	forged := httptest.NewRequest(http.MethodPost, "/api/_internal/encryption/rotate", nil)
	for k, v := range other {
		forged.Header.Set(k, v)
	}
	if rotateSigValid(forged, newKey) {
		t.Fatal("signature from another app's secret accepted")
	}
}

func TestHostedRotationRouteRefusesUnsignedConfirm(t *testing.T) {
	oldSecret := serverSecret
	serverSecret = strings.Repeat("s", 64)
	t.Cleanup(func() { serverSecret = oldSecret })
	t.Setenv("BENMORE_BIND_LOOPBACK", "1")

	app, _, cleanup := signedURLApp(t)
	defer cleanup()
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(app.DB)
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES ('boss', 'boss@example.com', 'admin', 1)")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	sess := CreateSession(app.DB, uid, "boss@example.com", "", time.Hour)
	mux := http.NewServeMux()
	RegisterEncryptionRotationRoute(mux, app)
	body := map[string]any{"confirm": true, "new_key": strings.Repeat("k", 40)}
	rec := crudScopeRequest(t, mux, http.MethodPost, "/api/_internal/encryption/rotate", sess, body)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "rotate_encryption_key") {
		t.Fatalf("unsigned hosted rotation: status=%d body=%s, want 403", rec.Code, rec.Body.String())
	}
	// A dry run needs no signature.
	rec = crudScopeRequest(t, mux, http.MethodPost, "/api/_internal/encryption/rotate", sess, map[string]any{"confirm": false})
	if rec.Code == http.StatusForbidden {
		t.Fatalf("hosted dry run refused: %s", rec.Body.String())
	}
}
