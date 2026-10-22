//go:build !cli

package main

import (
	"crypto/hmac"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const mfaSetupValueV3 = "v3"

type mfaSetupQuerier interface {
	QueryRow(string, ...any) *sql.Row
}

// mfaSetupAccountState keeps the credential material on the server. Only a
// purpose-separated MAC is carried in the enrollment token. A durable nonce
// rotates on every credential write, including same-value operator resets.
// created_at additionally binds the account record; inserts always get a fresh
// nonce even if a restored/recreated record repeats all of its other values.
func mfaSetupAccountState(app *App, q mfaSetupQuerier, userID int64, issuedFor string) (email, passwordHash, binding string, err error) {
	if app == nil || app.DB == nil || q == nil || userID <= 0 {
		return "", "", "", fmt.Errorf("invalid setup token")
	}
	var created, nonce string
	var passwordChangeRequired int
	// Missing migration/trigger state must fail closed, including callers that
	// predate checked startup migrations and ignored EnsureUsersTable's error.
	err = q.QueryRow(`SELECT COALESCE(email,''), COALESCE(password_hash,''), COALESCE(created_at,''), COALESCE(password_change_required,0), COALESCE(mfa_setup_nonce,'')
		FROM main._benmore_users WHERE id=? AND COALESCE(deactivated_at,'')=''
		AND (SELECT COUNT(*) FROM main.sqlite_schema WHERE type='trigger' AND tbl_name='_benmore_users'
			AND name IN ('_benmore_mfa_setup_nonce_insert','_benmore_mfa_setup_nonce_reset'))=2`, userID).Scan(&email, &passwordHash, &created, &passwordChangeRequired, &nonce)
	if err != nil || !validMFASetupNonce(nonce) || !strings.EqualFold(strings.TrimSpace(email), strings.TrimSpace(issuedFor)) {
		return "", "", "", fmt.Errorf("invalid setup token")
	}
	// Pending accounts may finish MFA before the existing password-change
	// gate, but a reset that changes the pending flag invalidates old grants.
	payload := fmt.Sprintf("%d|%s|%s|%s|%d|%s", userID, stepField(email), stepField(passwordHash), stepField(created), passwordChangeRequired, nonce)
	binding = tempCookiePurposeMAC(app, "mfa-setup-credentials", payload)
	return email, passwordHash, binding, nil
}

// mintMFASetupToken is issued only after the caller proves the sign-in factors.
// Direct password logins pass the hash they proved, so a reset interleaved with
// password verification cannot bless the old proof with a new credential state.
func mintMFASetupToken(app *App, userID int64, email string, verifiedPasswordHash ...string) string {
	if app == nil {
		return ""
	}
	return mintMFASetupTokenWith(app, app.DB, userID, email, verifiedPasswordHash...)
}

func mintMFASetupTokenWith(app *App, q mfaSetupQuerier, userID int64, email string, verifiedPasswordHash ...string) string {
	if app == nil || app.DB == nil {
		return ""
	}
	current, hash, binding, err := mfaSetupAccountState(app, q, userID, email)
	if err != nil || (len(verifiedPasswordHash) > 0 && !hmac.Equal([]byte(hash), []byte(verifiedPasswordHash[0]))) {
		return ""
	}
	// Browser password sign-in also supplies the generation captured before
	// bcrypt, so an identical-hash reset cannot bless an earlier proof.
	if len(verifiedPasswordHash) > 1 && (verifiedPasswordHash[1] == "" || !hmac.Equal([]byte(binding), []byte(verifiedPasswordHash[1]))) {
		return ""
	}
	exp := time.Now().Add(mfaSetupTokenTTL).Unix()
	return signTempCookieFor(app, tempCookieMFASetup,
		fmt.Sprintf("mfa-setup|%s|%d|%s|%d|%s", mfaSetupValueV3, userID, stepField(current), exp, binding))
}

// mfaSetupTokenIdentity is also called with the write transaction immediately
// before enrollment changes. That makes reset/revocation and the final
// factor+session write serialize, instead of trusting a pre-transaction check.
func mfaSetupTokenIdentity(app *App, q mfaSetupQuerier, r *http.Request) (userID int64, email string, err error) {
	raw := strings.TrimSpace(r.Header.Get("X-MFA-Setup-Token"))
	if raw == "" {
		if c, _ := requestFlowCookie(r, flowCookieMFASetup); c != nil {
			raw = c.Value
		}
	}
	if raw == "" {
		return 0, "", fmt.Errorf("authentication required")
	}
	value := verifyTempCookieFor(app, tempCookieMFASetup, raw)
	parts := strings.Split(value, "|")
	// Older formats carry no credential binding, so there is intentionally no
	// upgrade grace period: those users must sign in again to resume enrollment.
	if len(parts) != 6 || parts[0] != "mfa-setup" || parts[1] != mfaSetupValueV3 {
		return 0, "", fmt.Errorf("invalid setup token")
	}
	issuedFor, decoded := stepFieldDecode(parts[3])
	if !decoded {
		return 0, "", fmt.Errorf("invalid setup token")
	}
	exp, err := strconv.ParseInt(parts[4], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return 0, "", fmt.Errorf("setup token expired")
	}
	uid := parseTempCookieUserID(parts[2])
	current, _, binding, err := mfaSetupAccountState(app, q, uid, issuedFor)
	if err != nil || !hmac.Equal([]byte(binding), []byte(parts[5])) {
		return 0, "", fmt.Errorf("invalid setup token")
	}
	return uid, current, nil
}
