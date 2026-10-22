//go:build !cli && !windows

package main

import (
	"testing"
	"time"
)

// A confirmed email change is an identity change: whoever controlled the old
// address (or held the account before) may hold API tokens, OAuth codes or
// connector grants minted under it. Confirming the change must end all of
// them with the sessions, and cancel unused reset links for the old address,
// as the other credential changes do.
func TestEmailChangeConfirmationRevokesReusableCredentials(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	EnsureAPITokensTable(app.DB)
	EnsurePasswordResetsTable(app.DB)
	ensureEmailChangesTable(app.DB)
	appOAuthEnsureTables(app)
	pair := fixtureGrant(t, app, uid, now)
	auditExec(t, app.DB, "INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes) VALUES (?, 'cli', 'tokhash', '*')", uid)
	auditExec(t, app.DB, `INSERT INTO _benmore_oauth_codes (client_id, user_id, code, code_challenge, code_challenge_method, redirect_uri, expires_at)
		VALUES ('c', ?, 'code-1', 'x', 'S256', 'https://client.example/cb', datetime('now', '+5 minutes'))`, uid)
	auditExec(t, app.DB, "INSERT INTO _benmore_password_resets (token, email, expires_at, type) VALUES (?, 'delegate@example.com', datetime('now', '+1 hour'), 'reset')", hashResetToken("old-reset"))
	auditExec(t, app.DB, "INSERT INTO _benmore_email_changes (user_id, new_email, token_hash, expires_at) VALUES (?, 'moved@example.com', ?, ?)",
		uid, hashResetToken("change-token"), time.Now().Add(time.Hour).UTC().Format(time.RFC3339))

	gotID, oldEmail, newEmail, err := confirmEmailChange(app, "change-token")
	if err != nil || gotID != uid || oldEmail != "delegate@example.com" || newEmail != "moved@example.com" {
		t.Fatalf("confirm: %d %q %q %v", gotID, oldEmail, newEmail, err)
	}
	for _, q := range []string{
		"SELECT COUNT(*) FROM _benmore_sessions WHERE user_id = ?",
		"SELECT COUNT(*) FROM _benmore_api_tokens WHERE user_id = ?",
		"SELECT COUNT(*) FROM _benmore_oauth_codes WHERE user_id = ?",
		"SELECT COUNT(*) FROM _benmore_mcp_grants WHERE user_id = ? AND revoked = 0",
	} {
		var n int
		if err := app.DB.QueryRow(q, uid).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s: %d survived the email change (%v)", q, n, err)
		}
	}
	if _, _, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, now); err == nil {
		t.Error("connector access token survived the email change")
	}
	var used int
	app.DB.QueryRow("SELECT used FROM _benmore_password_resets WHERE token = ?", hashResetToken("old-reset")).Scan(&used)
	if used != 1 {
		t.Error("a reset link issued to the old address survived the email change")
	}
	var email string
	app.DB.QueryRow("SELECT email FROM _benmore_users WHERE id = ?", uid).Scan(&email)
	if email != "moved@example.com" {
		t.Fatalf("email = %q, want the confirmed address", email)
	}
}
