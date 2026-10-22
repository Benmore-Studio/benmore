//go:build !cli

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The per-app consent page shows the requested scope, so the minted token
// must carry that scope, not full access.
func TestAuditAppOAuthTokenHonorsConsentedScope(t *testing.T) {
	app, cleanup := newOAuthTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `INSERT INTO _benmore_oauth_clients (client_id, name, redirect_uris, scopes)
		VALUES ('app_scoped', 'Reader', '["https://client.example/cb"]', 'notes:read')`)
	verifier := "synthetic-scope-verifier-with-enough-entropy-0001"
	sum := sha256.Sum256([]byte(verifier))
	if _, err := app.DB.Exec(`INSERT INTO _benmore_oauth_codes
		(client_id, user_id, code, code_challenge, code_challenge_method, redirect_uri, resource, scopes, expires_at)
		VALUES ('app_scoped', 1, ?, ?, 'S256', 'https://client.example/cb', '', 'notes:read', ?)`,
		hashAPIToken("scoped-code"), base64.RawURLEncoding.EncodeToString(sum[:]), time.Now().Add(5*time.Minute).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {"scoped-code"}, "client_id": {"app_scoped"},
		"redirect_uri": {"https://client.example/cb"}, "code_verifier": {verifier}}
	r := httptest.NewRequest("POST", "https://app.example/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	appOAuthToken(w, r, app)
	if w.Code != http.StatusOK {
		t.Fatalf("token exchange: %d %s", w.Code, w.Body.String())
	}
	var scopes string
	if err := app.DB.QueryRow(`SELECT scopes FROM _benmore_api_tokens WHERE name LIKE 'oauth:%'`).Scan(&scopes); err != nil {
		t.Fatal(err)
	}
	if scopes != "notes:read" {
		t.Fatalf("consent approved scope %q but the minted token holds %q", "notes:read", scopes)
	}
}
