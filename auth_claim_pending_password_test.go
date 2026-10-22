//go:build !cli

package main

import (
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// An account provisioned with a temporary password is marked
// password_change_required until the user replaces it. When the address is
// then proven through a verified OAuth sign-in (or the emailed link) before
// that, the claim replaces the password with a random one. The flag stayed
// set: no session of the account resolved, and the only way to clear it - the
// temporary password - no longer existed, so the sign-in that had just
// succeeded bounced back to the login page forever.
func TestClaimOfUnverifiedAccountEndsRequiredPasswordChange(t *testing.T) {
	app := recoveryHardeningApp(t)
	for _, action := range []string{"oauth", "email_claim_unverified"} {
		email := action + "@corp.example"
		uid := recoveryUser(t, app, email, "Temp!Password1", 0)
		mustExecArgs(t, app.DB, "UPDATE _benmore_users SET password_change_required = 1 WHERE id = ?", uid)
		var before string
		if err := app.DB.QueryRow("SELECT password_hash FROM _benmore_users WHERE id = ?", uid).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if action == "oauth" {
			// The sign-in path itself: a provider-proven address links the
			// unverified account by claiming it.
			got, err := oauthFindOrCreateUser(app, email, "", true)
			if err != nil || got != uid {
				t.Fatalf("oauth sign-in: user %d, %v", got, err)
			}
		} else if err := claimUnverifiedAccountAs(app, uid, email, action); err != nil {
			t.Fatal(err)
		}
		var after string
		var pending int
		if err := app.DB.QueryRow("SELECT password_hash, password_change_required FROM _benmore_users WHERE id = ?", uid).Scan(&after, &pending); err != nil {
			t.Fatal(err)
		}
		if after == before || bcrypt.CompareHashAndPassword([]byte(after), []byte("Temp!Password1")) == nil {
			t.Fatalf("%s: the temporary password survived the claim", action)
		}
		if pending != 0 {
			t.Errorf("%s: the account is still waiting for a password that no longer exists to be replaced", action)
		}
		if s := GetSessionFromDB(app.DB, CreateSession(app.DB, uid, email, "", time.Hour)); s == nil {
			t.Errorf("%s: the session issued after the claim does not resolve", action)
		}
	}

	// An account that is NOT claimed keeps the flag: a verified account, and
	// a grandfathered one (which keeps its credentials), still hold the
	// temporary password and must replace it.
	for name, setup := range map[string]string{
		"verified":      "UPDATE _benmore_users SET verified = 1, password_change_required = 1 WHERE id = ?",
		"grandfathered": "UPDATE _benmore_users SET email_grandfathered = 1, password_change_required = 1 WHERE id = ?",
	} {
		email := name + "@corp.example"
		uid := recoveryUser(t, app, email, "Temp!Password1", 0)
		mustExecArgs(t, app.DB, setup, uid)
		if got, err := oauthFindOrCreateUser(app, email, "", true); err != nil || got != uid {
			t.Fatalf("%s: oauth sign-in: user %d, %v", name, got, err)
		}
		var hash string
		var pending int
		if err := app.DB.QueryRow("SELECT password_hash, password_change_required FROM _benmore_users WHERE id = ?", uid).Scan(&hash, &pending); err != nil {
			t.Fatal(err)
		}
		kept := bcrypt.CompareHashAndPassword([]byte(hash), []byte("Temp!Password1")) == nil
		if pending != 1 || !kept {
			t.Errorf("%s account: pending=%d, temporary password kept=%v; an OAuth sign-in must not waive the replacement", name, pending, kept)
		}
		if s := GetSessionFromDB(app.DB, CreateSession(app.DB, uid, email, "", time.Hour)); s != nil {
			t.Errorf("%s account: a session resolved while the temporary password is still in place", name)
		}
	}
}
