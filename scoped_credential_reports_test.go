//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The client error report and the analytics beacon are open to signed-out
// visitors, and a signed-in one is recorded under the account. A credential
// narrowed to one table filed error reports under the account's id and
// address (which the app's error export then carries) and tied a visitor id
// of its choice to the account. A scoped credential is recorded as a
// signed-out visitor is; a sign-in and an unscoped token are recorded as
// before.
func TestScopedCredentialReportsAreRecordedWithoutTheAccount(t *testing.T) {
	f := newScopedRoutesFixture(t)
	report := func(cred, marker string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/_errors", strings.NewReader(`{"kind":"error","message":"`+marker+`"}`))
		req.Header.Set("Content-Type", "application/json")
		if cred != "" {
			req.Header.Set("Authorization", "Bearer "+cred)
		}
		rec := httptest.NewRecorder()
		f.mux.ServeHTTP(rec, req)
		if rec.Code >= 300 {
			t.Fatalf("report %s: %d %s", marker, rec.Code, rec.Body.String())
		}
	}
	reporter := func(marker string) int64 {
		t.Helper()
		var uid sql.NullInt64
		if err := f.app.DB.QueryRow(`SELECT user_id FROM _benmore_client_errors WHERE message = ?`, marker).Scan(&uid); err != nil {
			t.Fatalf("report %s was not stored: %v", marker, err)
		}
		return uid.Int64
	}
	beacon := func(cred, visitor string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/_analytics", strings.NewReader(`{"p":"/pricing","sw":1200,"sh":800}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "bm_cookie_consent", Value: "accepted"})
		req.AddCookie(&http.Cookie{Name: "_bm_vid", Value: visitor})
		if cred != "" {
			req.Header.Set("Authorization", "Bearer "+cred)
		}
		rec := httptest.NewRecorder()
		f.mux.ServeHTTP(rec, req)
		if rec.Code >= 300 {
			t.Fatalf("beacon %s: %d %s", visitor, rec.Code, rec.Body.String())
		}
	}
	visitorUser := func(visitor string) int64 {
		t.Helper()
		var uid sql.NullInt64
		if err := f.app.DB.QueryRow(`SELECT user_id FROM _benmore_visitors WHERE visitor_id = ?`, visitor).Scan(&uid); err != nil {
			t.Fatalf("visitor %s was not stored: %v", visitor, err)
		}
		return uid.Int64
	}
	visitor := func(n int) string { return fmt.Sprintf("abcdef012345678%x", n) }
	n := 0
	for name, cred := range f.without() {
		marker := "scoped-report-" + strings.ReplaceAll(name, " ", "-")
		report(cred, marker)
		if uid := reporter(marker); uid != 0 {
			t.Errorf("%s: the error report is filed under user %d, want no account", name, uid)
		}
		beacon(cred, visitor(n))
		if uid := visitorUser(visitor(n)); uid != 0 {
			t.Errorf("%s: the visitor is tied to user %d, want no account", name, uid)
		}
		n++
	}
	for name, cred := range f.unscoped() {
		marker := "full-report-" + strings.ReplaceAll(name, " ", "-")
		report(cred, marker)
		if uid := reporter(marker); uid != 1 {
			t.Errorf("%s: the error report is filed under user %d, want the account (1)", name, uid)
		}
		beacon(cred, visitor(n))
		if uid := visitorUser(visitor(n)); uid != 1 {
			t.Errorf("%s: the visitor is tied to user %d, want the account (1)", name, uid)
		}
		n++
	}
	report("", "signed-out-report")
	if uid := reporter("signed-out-report"); uid != 0 {
		t.Errorf("signed out: the error report is filed under user %d", uid)
	}
}
