//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The confirmation link goes to an inbox the REQUESTER names. Opening it
// showed a confirm button that anyone holding the link could press, so the
// person the mail reached could be talked into pressing it ("confirm your
// address to accept the invitation"): the requester's account then owned
// that address, verified, with every membership, share and invite addressed
// to it. Confirming now also takes proof of the requesting account - its own
// signed-in browser, or its password - which the mailbox owner being phished
// does not have.
func TestEmailChangeConfirmNeedsTheRequestingAccount(t *testing.T) {
	app, mux, uid, sid := newEmailChangeTestApp(t)
	EnsureLoginAttemptsTable(app.DB)
	ensureEmailChangesTable(app.DB)
	pending := func(token string) {
		t.Helper()
		if _, err := app.DB.Exec("INSERT INTO _benmore_email_changes (user_id, new_email, token_hash, expires_at) VALUES (?, 'invited@corp.example', ?, ?)",
			uid, hashResetToken(token), time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	post := func(token, password, session string) *httptest.ResponseRecorder {
		form := url.Values{"token": {token}, "_csrf": {authMintCSRFToken(session)}}
		if password != "" {
			form.Set("password", password)
		}
		r := httptest.NewRequest(http.MethodPost, "/settings/confirm-email", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if session != "" {
			r.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: session})
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}

	// The mailbox owner opens the link and presses the button: no session of
	// the requesting account, no password.
	pending("phished")
	page := httptest.NewRecorder()
	mux.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/settings/confirm-email?token=phished", nil))
	if !strings.Contains(page.Body.String(), `type="password"`) {
		t.Fatalf("the page shown outside the account's session does not ask for its password: %s", page.Body.String())
	}
	if w := post("phished", "", ""); currentEmail(t, app, uid) != "amy@example.com" {
		t.Fatalf("the change applied on a bare click by whoever opened the mail (%d)", w.Code)
	}
	if w := post("phished", "not-the-password", ""); currentEmail(t, app, uid) != "amy@example.com" || w.Code != http.StatusForbidden {
		t.Fatalf("a wrong password confirmed the change (%d)", w.Code)
	}
	var left int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_email_changes WHERE user_id = ?", uid).Scan(&left)
	if left != 1 {
		t.Fatal("a refused confirmation spent the link")
	}

	// The requester on another device proves the account with its password.
	if post("phished", "Correct-Horse-1", ""); currentEmail(t, app, uid) != "invited@corp.example" {
		t.Fatal("the account's password did not confirm the change")
	}

	// The requester in the browser that is signed in as the account needs
	// only the button.
	mustExec(t, app.DB, "UPDATE _benmore_users SET email = 'amy@example.com'")
	sid = CreateSession(app.DB, uid, "amy@example.com", "", time.Hour)
	pending("own-browser")
	own := httptest.NewRequest(http.MethodGet, "/settings/confirm-email?token=own-browser", nil)
	own.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: sid})
	page = httptest.NewRecorder()
	mux.ServeHTTP(page, own)
	if strings.Contains(page.Body.String(), `type="password"`) {
		t.Fatal("the account's own signed-in browser was asked for the password")
	}
	if post("own-browser", "", sid); currentEmail(t, app, uid) != "invited@corp.example" {
		t.Fatal("the signed-in account could not confirm with the button")
	}

	// Someone else's session is not proof.
	mustExec(t, app.DB, "UPDATE _benmore_users SET email = 'amy@example.com'")
	mustExec(t, app.DB, "INSERT INTO _benmore_users (id, username, email, password_hash, verified) VALUES (99, 'other', 'other@example.com', 'x', 1)")
	otherSID := CreateSession(app.DB, 99, "other@example.com", "", time.Hour)
	pending("other-session")
	if post("other-session", "", otherSID); currentEmail(t, app, uid) != "amy@example.com" {
		t.Fatal("another account's session confirmed the change")
	}
}
