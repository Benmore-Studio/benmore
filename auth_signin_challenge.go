//go:build !cli

package main

import (
	"crypto/hmac"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Half-finished sign-ins are credentials too. Keep only a hashed, purpose-bound
// challenge in SQLite and bind it to the credential generation already rotated
// by every password write, including same-value operator resets. Older signed
// step cookies carry neither revocation nor one-use state and fail closed.
const signInChallengePrefix = "signin-v1."

func ensureSignInChallenges(db *sql.DB) error {
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS _benmore_signin_challenges (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, purpose TEXT NOT NULL, email TEXT NOT NULL, otp_key TEXT NOT NULL, credential_binding TEXT NOT NULL, expires_at INTEGER NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS idx_benmore_signin_challenges_user ON _benmore_signin_challenges(user_id,expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_benmore_signin_challenges_expiry ON _benmore_signin_challenges(expires_at)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("ensure sign-in challenges: %w", err)
		}
	}
	return nil
}

type signInChallenge struct {
	UserID                       int64
	Email, OTPKey, Binding, Hash string
}

func signInChallengeIdentity(app *App, q mfaSetupQuerier, raw, purpose string) (signInChallenge, error) {
	var c signInChallenge
	if !strings.HasPrefix(raw, signInChallengePrefix) || len(raw) > 200 {
		return c, errors.New("invalid sign-in challenge")
	}
	c.Hash = sessionStorageKey(raw)
	err := q.QueryRow(`SELECT user_id,email,otp_key,credential_binding FROM _benmore_signin_challenges WHERE token_hash=? AND purpose=? AND expires_at>?`, c.Hash, purpose, time.Now().Unix()).Scan(&c.UserID, &c.Email, &c.OTPKey, &c.Binding)
	if err != nil {
		return c, errors.New("invalid sign-in challenge")
	}
	email, _, binding, err := mfaSetupAccountState(app, q, c.UserID, c.Email)
	if err != nil || !hmac.Equal([]byte(binding), []byte(c.Binding)) {
		return c, errors.New("invalid sign-in challenge")
	}
	if allowed, _ := emailAllowedForApp(app, email); !allowed {
		return c, errors.New("invalid sign-in challenge")
	}
	c.Email = email
	return c, nil
}

// The caller holds the writer transaction. expected is the account binding from
// before password verification (or the preceding verified step), preventing a
// reset racing that proof from blessing the old proof with a fresh generation.
func mintSignInChallengeTx(app *App, tx *sql.Tx, purpose string, userID int64, email, key, expected string) (string, error) {
	current, _, binding, err := mfaSetupAccountState(app, tx, userID, email)
	if err != nil || (expected != "" && !hmac.Equal([]byte(binding), []byte(expected))) {
		return "", errors.New("credentials changed")
	}
	if purpose != tempCookieMFA && purpose != tempCookieOTP {
		return "", errors.New("invalid sign-in purpose")
	}
	if _, err = tx.Exec("DELETE FROM _benmore_signin_challenges WHERE expires_at<=?", time.Now().Unix()); err != nil {
		return "", err
	}
	// Each authenticated issuance keeps at most 20 live steps for this account.
	if _, err = tx.Exec(`DELETE FROM _benmore_signin_challenges WHERE token_hash IN (SELECT token_hash FROM _benmore_signin_challenges WHERE user_id=? ORDER BY expires_at DESC, rowid DESC LIMIT -1 OFFSET 19)`, userID); err != nil {
		return "", err
	}
	token := signInChallengePrefix + generateToken(32)
	ttl := 5 * time.Minute
	if purpose == tempCookieOTP {
		ttl = 10 * time.Minute
	}
	_, err = tx.Exec(`INSERT INTO _benmore_signin_challenges(token_hash,user_id,purpose,email,otp_key,credential_binding,expires_at) VALUES (?,?,?,?,?,?,?)`, sessionStorageKey(token), userID, purpose, current, key, binding, time.Now().Add(ttl).Unix())
	if err != nil {
		return "", err
	}
	return token, nil
}

func signInWriteTx(db *sql.DB) (*sql.Tx, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	// Acquire the SQLite writer before reads even on a deferred fixture DSN.
	if _, err = tx.Exec("UPDATE _benmore_users SET id=id WHERE 0"); err != nil {
		tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func mintSignInChallenge(app *App, purpose string, userID int64, email, key string, expected ...string) string {
	if app == nil || app.DB == nil {
		return ""
	}
	tx, err := signInWriteTx(app.DB)
	if err != nil {
		return ""
	}
	defer tx.Rollback()
	binding := ""
	if len(expected) > 0 {
		binding = expected[0]
	}
	token, err := mintSignInChallengeTx(app, tx, purpose, userID, email, key, binding)
	if err != nil {
		return ""
	}
	if tx.Commit() != nil {
		return ""
	}
	return token
}

func consumeSignInChallenge(tx *sql.Tx, c signInChallenge) error {
	res, err := tx.Exec("DELETE FROM _benmore_signin_challenges WHERE token_hash=?", c.Hash)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("sign-in challenge already used")
	}
	return nil
}

func createPasswordSignInSession(app *App, id int64, email, groupID, binding string) (string, error) {
	tx, err := signInWriteTx(app.DB)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	_, _, current, err := mfaSetupAccountState(app, tx, id, email)
	if err != nil || binding == "" || !hmac.Equal([]byte(binding), []byte(current)) {
		return "", errors.New("credentials changed")
	}
	needsEnrollment, err := needsMFAEnrollmentWith(app, tx, id)
	if err != nil || needsEnrollment {
		return "", errors.New("sign-in requirements changed")
	}
	token, err := createSignInSessionTx(tx, id, email, groupID, app.SessionDuration)
	if err == nil {
		_, err = tx.Exec("UPDATE _benmore_users SET last_login_at=datetime('now') WHERE id=?", id)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		return "", err
	}
	return token, nil
}

// Inline password+MFA sign-in uses the same atomic successful-factor boundary
// as the separate MFA page. In particular a storage failure cannot eat a backup
// code, and a reset cannot create a new session from an earlier password proof.
func completeInlineMFALogin(w http.ResponseWriter, r *http.Request, app *App, id int64, email, key, passwordHash, binding, code string) {
	mfaKey := mfaLockKey(id)
	defer lockAttempt(mfaKey)()
	if isAccountLocked(app.DB, mfaKey) {
		authRedirect(w, r, app.Paths.Login, "Too many MFA attempts. Try again in 15 minutes.")
		return
	}
	groupID := ResolveGroupID(app.DB, app.Group, email)
	tx, err := signInWriteTx(app.DB)
	if err != nil {
		serverErrorJSON(w, r, app, "MFA sign-in", err, "Sign-in could not be saved")
		return
	}
	defer tx.Rollback()
	_, _, current, err := mfaSetupAccountState(app, tx, id, email)
	if err != nil || binding == "" || !hmac.Equal([]byte(binding), []byte(current)) {
		authRedirect(w, r, app.Paths.Login, "Credentials changed. Sign in again.")
		return
	}
	if !validateMFACodeWith(tx, id, code) {
		tx.Rollback()
		recordLoginAttempt(app.DB, mfaKey, false)
		authRedirect(w, r, app.Paths.Login, "Invalid MFA code")
		return
	}
	var sessionID, otpCode, otpToken string
	if otpLoginEnabled(app) {
		otpCode, otpToken, err = prepareLoginOTPTx(app, tx, id, email, key, binding)
	} else {
		sessionID, err = createSignInSessionTx(tx, id, email, groupID, app.SessionDuration)
	}
	if err == nil {
		_, err = tx.Exec("UPDATE _benmore_users SET last_login_at=datetime('now') WHERE id=?", id)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		serverErrorJSON(w, r, app, "MFA sign-in", err, "Sign-in could not be saved")
		return
	}
	recordLoginAttempt(app.DB, mfaKey, true)
	FireUserHooks(app, "update", id)
	syncPlatformUserFromDashboard(app, email, passwordHash)
	if otpToken != "" {
		sendLoginOTP(w, r, app, id, email, key, otpCode, otpToken)
		return
	}
	AttachSessionContext(app.DB, sessionID, r)
	http.SetCookie(w, sessionCookie(sessionID, app.DevMode, app.SessionDuration))
	if authSuccessJSON(w, r, app, id) {
		return
	}
	target := "/"
	if app.Design != nil && app.Design.Auth["redirect"] != "" {
		target = app.Design.Auth["redirect"]
	}
	if next := r.FormValue("next"); isSafeNext(next) {
		target = next
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}
