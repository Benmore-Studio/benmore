//go:build !cli

package main

import (
	"errors"
	"testing"
)

// POST /api/_auth/token used to run bcrypt and then INSERT its session with no
// re-check, so a password reset (or change, or unverified-account claim) that
// landed during the ~250ms check left a 30-day Bearer session its revocation
// never saw. The session write now re-checks the generation captured before
// bcrypt, in the same transaction that spends the MFA code.
func TestTokenExchangeSessionRechecksPasswordGeneration(t *testing.T) {
	app, _, uid, _, codes := loginChallengeFixture(t)
	const email = "challenge@example.test"
	_, _, binding, err := mfaSetupAccountState(app, app.DB, uid, email)
	if err != nil {
		t.Fatal(err)
	}
	// A same-hash reset still rotates the generation.
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_hash=password_hash WHERE id=?", uid)
	before := challengeFactorState(t, app, uid)
	token, badCode, err := tokenExchangeSessionTx(app, uid, email, "", "", binding, codes[0])
	if token != "" || badCode || !errors.Is(err, errSignInCredentialsChanged) {
		t.Fatalf("stale proof: token=%q badCode=%v err=%v", token, badCode, err)
	}
	if challengeFactorState(t, app, uid) != before {
		t.Fatal("stale proof spent an MFA code")
	}
	if n := recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_sessions WHERE user_id=?", uid); n != 0 {
		t.Fatalf("stale proof created %d sessions", n)
	}

	// Without MFA the stale proof is refused the same way.
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET totp_secret=NULL,backup_codes=NULL WHERE id=?", uid)
	if token, _, err := tokenExchangeSessionTx(app, uid, email, "", "", binding, ""); token != "" || !errors.Is(err, errSignInCredentialsChanged) {
		t.Fatalf("stale proof without MFA: token=%q err=%v", token, err)
	}
}

func TestTokenExchangeSessionSpendsCodeAtomically(t *testing.T) {
	app, _, uid, _, codes := loginChallengeFixture(t)
	const email = "challenge@example.test"
	_, _, binding, err := mfaSetupAccountState(app, app.DB, uid, email)
	if err != nil {
		t.Fatal(err)
	}
	before := challengeFactorState(t, app, uid)
	if token, badCode, err := tokenExchangeSessionTx(app, uid, email, "", "", binding, "not-a-code"); token != "" || !badCode || err != nil {
		t.Fatalf("wrong code: token=%q badCode=%v err=%v", token, badCode, err)
	}
	if challengeFactorState(t, app, uid) != before {
		t.Fatal("wrong code changed factor state")
	}
	token, badCode, err := tokenExchangeSessionTx(app, uid, email, "", "read", binding, codes[0])
	if err != nil || badCode || token == "" {
		t.Fatalf("current proof: token=%q badCode=%v err=%v", token, badCode, err)
	}
	var loginAt int64
	var scopes string
	if err := app.DB.QueryRow("SELECT login_at, COALESCE(scopes,'') FROM _benmore_sessions WHERE id=?", sessionStorageKey(token)).Scan(&loginAt, &scopes); err != nil {
		t.Fatal(err)
	}
	if loginAt != loginAtTokenExchange || scopes != "read" {
		t.Fatalf("exchange session login_at=%d scopes=%q", loginAt, scopes)
	}
	// The backup code is spent: it cannot mint a second session.
	if token, badCode, _ := tokenExchangeSessionTx(app, uid, email, "", "", binding, codes[0]); token != "" || !badCode {
		t.Fatal("spent backup code minted another session")
	}
}
