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

// Deleting the account can't be undone. A scoped API token (which can fetch
// an unbound CSRF token from /api/_csrf) or a support session must not be able
// to do it; only the user's own login may.
func TestDeleteAccountRequiresDirectLogin(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	mux := http.NewServeMux()
	RegisterSettingsRoutes(mux, app)
	sid := seedMemberSession(t, app)
	uid := GetSessionFromDB(app.DB, sid).UserID
	scoped := auditToken(t, app, sid, "notes:read")
	support := CreateSession(app.DB, uid, "member@test.local", "", time.Hour)
	mustExec(t, app.DB, "UPDATE _benmore_sessions SET is_impersonation = 1 WHERE id = '"+sessionStorageKey(support)+"'")

	deleteAccount := func(csrfSID string, auth func(*http.Request)) *httptest.ResponseRecorder {
		form := url.Values{"confirm": {"DELETE"}, "_csrf": {authMintCSRFToken(csrfSID)}}
		r := httptest.NewRequest(http.MethodPost, "/settings/delete-account", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		auth(r)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	exists := func() bool {
		var n int
		// Deletion leaves a non-login tombstone (purgeAccountTx); a live
		// account still has its email and no deactivation.
		app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_users WHERE id = ? AND deactivated_at IS NULL AND email IS NOT NULL", uid).Scan(&n)
		return n == 1
	}

	deleteAccount("", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+scoped) })
	if !exists() {
		t.Fatal("a notes:read API token deleted the account")
	}
	deleteAccount(support, func(r *http.Request) { r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: support}) })
	if !exists() {
		t.Fatal("an impersonation session deleted the account")
	}
	// Control: the user's own login session can.
	if w := deleteAccount(sid, func(r *http.Request) { r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) }); exists() || w.Code != http.StatusSeeOther {
		t.Fatalf("direct login could not delete the account: %d", w.Code)
	}
}
