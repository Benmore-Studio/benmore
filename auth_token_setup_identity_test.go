//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// With auth.identifier: username the login value is a username, which the
// user can set to any string (including someone else's email) through the
// profile API. The MFA-setup token becomes the session identity on enrollment,
// and session email drives tenant membership and email-keyed grants, so it
// must carry the account's own email, never the typed identifier.
func TestTokenAuthSetupTokenCarriesAccountEmail(t *testing.T) {
	app, _, call := tokenAuthFixture(t, "attacker@own.example", fixturePassword, "192.0.2.43")
	mustExec(t, app.DB, "UPDATE _benmore_users SET username = 'victim@corp.example' WHERE email = 'attacker@own.example'")
	app.Design = &DesignConfig{Auth: map[string]string{"identifier": "username", "require_mfa_for_roles": "user"}}

	w := call(map[string]string{"email": "victim@corp.example", "password": fixturePassword})
	var resp struct {
		SetupToken string `json:"setup_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.SetupToken == "" {
		t.Fatalf("no setup token: %d %s", w.Code, w.Body.String())
	}
	r := httptest.NewRequest(http.MethodPost, "/api/_auth/mfa/setup", nil)
	r.Header.Set("X-MFA-Setup-Token", resp.SetupToken)
	_, email, fromSetup, err := mfaCallerIdentity(app, r)
	if err != nil || !fromSetup {
		t.Fatalf("setup token rejected: %v", err)
	}
	if email != "attacker@own.example" {
		t.Fatalf("setup token identity = %q, want the account email", email)
	}
}
