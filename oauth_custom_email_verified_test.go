//go:build !cli

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A custom provider that never sends email_verified could return any address
// its user typed in, and the callback linked that to the existing account
// with the same email. Linking now needs an explicit verified claim, or the
// operator's statement (trust_email: true) that the provider verifies every
// address. Built-in providers keep their own checks.
func TestCustomOAuthProviderNeedsVerifiedEmailToLink(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	yaml := "oauth:\n  acme:\n    auth_url: https://acme.example/authorize\n    token_url: https://acme.example/token\n    userinfo_url: https://acme.example/me\n  corp:\n    auth_url: https://corp.example/authorize\n    token_url: https://corp.example/token\n    userinfo_url: https://corp.example/me\n    trust_email: true\n"
	if err := os.WriteFile(filepath.Join(app.Dir, "app.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	mustExec(t, app.DB, "INSERT INTO _benmore_users (id, username, email, password_hash, verified) VALUES (7, 'victim', 'victim@example.com', 'x', 1)")
	providers := oauthProvidersForApp(app.Dir)
	acme, corp, google := providers["acme"], providers["corp"], providers["google"]
	noClaim := map[string]any{"email": "victim@example.com"}

	verified := oauthEmailVerified(&acme, "acme", noClaim)
	if verified {
		t.Fatal("custom provider without an email_verified claim counted as verified")
	}
	if id, err := oauthFindOrCreateUser(app, "victim@example.com", "", verified); !errors.Is(err, errOAuthUnverifiedLink) || id != 0 {
		t.Fatalf("unverified custom-provider email linked to the existing account: id=%d err=%v", id, err)
	}

	for name, claims := range map[string]map[string]any{
		"bool claim":   {"email": "victim@example.com", "email_verified": true},
		"string claim": {"email": "victim@example.com", "email_verified": "true"},
	} {
		if !oauthEmailVerified(&acme, "acme", claims) {
			t.Errorf("%s not accepted", name)
		}
	}
	if !oauthEmailVerified(&corp, "corp", noClaim) {
		t.Error("trust_email: true provider not trusted")
	}
	if !oauthEmailVerified(&google, "google", noClaim) {
		t.Error("built-in provider lost its own verification handling")
	}
	if id, err := oauthFindOrCreateUser(app, "victim@example.com", "", true); err != nil || id != 7 {
		t.Fatalf("verified email did not link: id=%d err=%v", id, err)
	}

	// New accounts from an unverifying provider are still created, but the
	// address stays unverified.
	id, err := oauthFindOrCreateUser(app, "fresh@example.com", "", false)
	if err != nil || id == 0 {
		t.Fatalf("new account: %d %v", id, err)
	}
	var v int
	app.DB.QueryRow("SELECT COALESCE(verified,0) FROM _benmore_users WHERE id = ?", id).Scan(&v)
	if v != 0 {
		t.Fatal("unverified provider email marked the new account verified")
	}
}
