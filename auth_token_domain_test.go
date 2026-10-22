//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
)

// auth.domain / auth.allow_emails decide who may sign in at all. Login,
// signup and both OAuth callbacks enforce them; the Bearer exchange must too,
// or an account outside the gate keeps API access after interactive login is
// closed to it.
func TestTokenAuthEnforcesEmailGate(t *testing.T) {
	app, _, call := tokenAuthFixture(t, "outsider@elsewhere.example", fixturePassword, "192.0.2.42")
	mustExec(t, app.DB, "INSERT INTO _benmore_users (username, email, password_hash, verified) SELECT 'insider', 'insider@corp.example', password_hash, 1 FROM _benmore_users WHERE email = 'outsider@elsewhere.example'")
	app.Design = &DesignConfig{Auth: map[string]string{"domain": "corp.example"}}

	if w := call(map[string]string{"email": "outsider@elsewhere.example", "password": fixturePassword}); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("token issued outside auth.domain: %d %s", w.Code, w.Body.String())
	}
	app.Design.Auth = map[string]string{"allow_emails": "insider@corp.example"}
	if w := call(map[string]string{"email": "outsider@elsewhere.example", "password": fixturePassword}); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("token issued outside auth.allow_emails: %d %s", w.Code, w.Body.String())
	}
	// Control: an allowed address still gets its token.
	if w := call(map[string]string{"email": "insider@corp.example", "password": fixturePassword}); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("allowed address refused: %d %s", w.Code, w.Body.String())
	}
}
