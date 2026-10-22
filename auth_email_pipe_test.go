//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// "|" separated the fields of the signed sign-in step cookies, so an address
// holding one read back as a different address. Signup refused it, but the
// shared rule (validAuthEmail) did not, and OAuth sign-in applied no rule at
// all unless the app set auth.domain.
func TestValidAuthEmailRefusesPipeAndInvisibleCharacters(t *testing.T) {
	for _, email := range []string{
		"victim@corp.example|x",
		"a|b@corp.example",
		"a@corp.example|",
		"a\u0085b@corp.example", // C1 control (NEL)
		"a\u00a0b@corp.example", // no-break space
		"a\u200bb@corp.example", // zero-width space
		"a\u202eb@corp.example", // right-to-left override
		"a\ufeffb@corp.example", // byte order mark
		"a\u2028b@corp.example", // line separator
		"a\xffb@corp.example",   // not UTF-8
		"a\tb@corp.example",
		"a\x00b@corp.example",
	} {
		if validAuthEmail(email) {
			t.Errorf("validAuthEmail accepted %q", email)
		}
	}
	for _, email := range []string{
		"person@corp.example",
		"first.last+tag@corp.example",
		"o'brien@corp.example",
		"user_name-1@sub.corp.example",
		"user#ext#@tenant.example",
		"jörg@münchen.example",
		"用户@例子.example",
	} {
		if !validAuthEmail(email) {
			t.Errorf("validAuthEmail refused %q", email)
		}
	}
}

func TestOAuthSignInRefusesMalformedProviderEmail(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	for _, email := range []string{
		"victim@corp.example|x",
		"victim@corp.example,me@evil.example",
		"a\u200bdmin@corp.example",
	} {
		id, err := oauthFindOrCreateUser(app, email, "Mallory", true)
		if err == nil || id != 0 {
			t.Errorf("oauthFindOrCreateUser(%q) = %d, %v; want a refusal", email, id, err)
		}
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_users").Scan(&n)
	if n != 0 {
		t.Fatalf("a malformed provider email created %d account(s)", n)
	}
	// Control: a plain address still provisions.
	if id, err := oauthFindOrCreateUser(app, " Person@Corp.example ", "Pat Example", true); err != nil || id == 0 {
		t.Fatalf("control sign-in refused: %d %v", id, err)
	}
}

// A change requested before the rule tightened must not install an address
// the rule now refuses.
func TestEmailChangeConfirmRefusesPipeAddress(t *testing.T) {
	t.Setenv("BENMORE_PUBLIC_URL", "https://app.real")
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	EnsureAPITokensTable(app.DB)
	EnsurePasswordResetsTable(app.DB)
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{"url": "https://app.real"}}
	mustExec(t, app.DB, "INSERT INTO _benmore_users (id, username, email, password_hash) VALUES (1, 'u', 'owner@corp.example', 'x')")

	r := httptest.NewRequest(http.MethodPatch, "/api/_auth/profile", nil)
	if err := requestEmailChange(app, r, 1, "victim@corp.example|x"); err == nil {
		t.Fatal("email change accepted an address containing |")
	}

	ensureEmailChangesTable(app.DB)
	token := "pending-change-token"
	if _, err := app.DB.Exec("INSERT INTO _benmore_email_changes (user_id, new_email, token_hash, expires_at) VALUES (1, 'victim@corp.example|x', ?, ?)",
		hashResetToken(token), time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := confirmEmailChange(app, token); err == nil {
		t.Fatal("confirmation installed an address containing |")
	}
	var email string
	app.DB.QueryRow("SELECT email FROM _benmore_users WHERE id = 1").Scan(&email)
	if email != "owner@corp.example" {
		t.Fatalf("email changed to %q", email)
	}
}
