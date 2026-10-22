//go:build !cli

package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The confirmation mail of an email change goes to whatever address the
// account names. Each mailbox was capped, but one signed-in account could
// name a different mailbox every time and have the app mail strangers
// without limit, from the app's own sender.
func TestEmailChangeMailsPerAccountAreCapped(t *testing.T) {
	t.Setenv("BENMORE_PUBLIC_URL", "https://app.real")
	oldRecipient, oldRequester := emailChangeRecipientLimiter, emailChangeRequesterLimiter
	emailChangeRecipientLimiter = NewRateLimiter(recipientMailRate, recipientMailWindow)
	emailChangeRequesterLimiter = NewRateLimiter(emailChangeRequesterRate, emailChangeRequesterWindow)
	t.Cleanup(func() { emailChangeRecipientLimiter, emailChangeRequesterLimiter = oldRecipient, oldRequester })
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureUsersTable(app.DB)
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{"url": "https://app.real"}}
	mustExec(t, app.DB, `INSERT INTO _benmore_users (id, username, email, verified) VALUES (1, 'sender', 'sender@example.com', 1), (2, 'other', 'other@example.com', 1)`)
	r := httptest.NewRequest(http.MethodPatch, "/api/_auth/profile", nil)

	pending := func(uid int64) string {
		var addr string
		app.DB.QueryRow(`SELECT new_email FROM _benmore_email_changes WHERE user_id = ?`, uid).Scan(&addr)
		return addr
	}
	for i := 0; i < emailChangeRequesterRate; i++ {
		if err := requestEmailChange(app, r, 1, fmt.Sprintf("stranger%d@example.org", i)); errors.Is(err, errEmailChangeThrottled) {
			t.Fatalf("request %d of the account was throttled", i+1)
		}
	}
	// The link the account's last accepted request sent (this fixture has no
	// mail provider, so the row is put back by hand).
	ensureEmailChangesTable(app.DB)
	mustExec(t, app.DB, `DELETE FROM _benmore_email_changes`)
	mustExec(t, app.DB, `INSERT INTO _benmore_email_changes (user_id, new_email, token_hash, expires_at) VALUES (1, 'stranger4@example.org', 'hash', '2999-01-01T00:00:00Z')`)
	err := requestEmailChange(app, r, 1, "one-more-stranger@example.org")
	if !errors.Is(err, errEmailChangeThrottled) {
		t.Fatalf("the account mailed another new address past its budget: %v", err)
	}
	if err.Error() == errEmailChangeThrottled.Error() {
		t.Errorf("the refusal blames the address, not the account's own budget: %q", err)
	}
	// The refusal leaves the link already sent working.
	if got := pending(1); got != "stranger4@example.org" {
		t.Errorf("the refused request replaced the pending change: %q", got)
	}
	// Another account has its own budget, and may still write to that mailbox.
	if err := requestEmailChange(app, r, 2, "one-more-stranger@example.org"); errors.Is(err, errEmailChangeThrottled) {
		t.Error("another account was throttled on the first account's budget")
	}
}
