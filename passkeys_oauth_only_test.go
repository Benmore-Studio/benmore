//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"testing"
)

// auth.oauth_only makes the identity provider the only way in: password,
// token and OTP sign-in are refused. Passkeys were on by default, so an
// account in such an app could add one and then sign in without the IdP
// (after the IdP disabled the user, for instance). In an oauth_only app
// passkeys are now off unless app.yaml says auth.passkeys: true.
func TestPasskeysOffInOAuthOnlyAppsUnlessExplicit(t *testing.T) {
	cases := []struct {
		auth map[string]string
		want bool
	}{
		{nil, true},
		{map[string]string{}, true},
		{map[string]string{"passkeys": "false"}, false},
		{map[string]string{"oauth_only": "true"}, false},
		{map[string]string{"oauth_only": "true", "passkeys": "false"}, false},
		{map[string]string{"oauth_only": "true", "passkeys": "true"}, true},
		{map[string]string{"oauth_only": "yes", "passkeys": "on"}, true},
		{map[string]string{"oauth_only": "false"}, true},
	}
	for _, c := range cases {
		app := &App{}
		if c.auth != nil {
			app.Design = &DesignConfig{Auth: c.auth}
		}
		if got := passkeysEnabled(app); got != c.want {
			t.Errorf("auth %v: passkeysEnabled = %v, want %v", c.auth, got, c.want)
		}
	}

	// The sign-in endpoints answer 404 in such an app.
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	app := &App{Dir: dir, DB: db}
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePasskeysTable(app.DB); err != nil {
		t.Fatal(err)
	}
	app.Design = &DesignConfig{Auth: map[string]string{"oauth_only": "true"}}
	client := &passkeyTestClient{t: t, app: app, cookies: map[string]*http.Cookie{}}
	if code, _ := client.do(passkeyLoginOptions(app), http.MethodPost, "/api/_auth/passkeys/login/options", map[string]any{}, authMintCSRFToken("")); code != http.StatusNotFound {
		t.Fatalf("passkey sign-in options in an oauth_only app: status %d, want 404", code)
	}
	if code, _ := client.do(passkeyLogin(app), http.MethodPost, "/api/_auth/passkeys/login", map[string]any{}, authMintCSRFToken("")); code != http.StatusNotFound {
		t.Fatalf("passkey sign-in in an oauth_only app: status %d, want 404", code)
	}
}
