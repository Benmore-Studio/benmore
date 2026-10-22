//go:build !cli

package main

// Signed sign-in step values: the OTP step and MFA step cookies and the MFA
// setup token.
//
// Each names an account (user id + email) and, for a password sign-in, the
// key its emailed code is stored under. The fields used to be joined with "|"
// as they were, so an email or identifier holding a "|" shifted them:
// "<id>|victim@corp.example|x" read back as victim@corp.example, and the step
// then resolved that address's tenant and wrote the address to the session.
// Fields are now base64url-encoded, and the email is only a check: a step
// completes for the account its id names, under the email that account has
// now, and not at all when that is no longer the address the value was issued
// for.

import (
	"database/sql"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

// stepValueV2 marks the encoded field form. A legacy value starts with the
// decimal user id, so the two can't be confused.
const stepValueV2 = "v2"

func stepField(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func stepFieldDecode(s string) (string, bool) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return string(b), err == nil
}

// encodeStepValue is the payload of an OTP or MFA step cookie. key is the
// identifier the emailed code is stored under ("" after a social sign-in,
// which owes no emailed code).
func encodeStepValue(userID int64, email, key string) string {
	return stepValueV2 + "|" + strconv.FormatInt(userID, 10) + "|" + stepField(email) + "|" + stepField(key)
}

// parseStepValue reads a verified OTP or MFA step payload. Until
// tempCookieLegacyUntil it also reads the "<id>|<email>[|<key>]" form the
// previous binary minted, so a sign-in in flight across the upgrade can
// finish; callers hold the email against the account (stepAccountEmail), so a
// legacy value whose fields a "|" shifted completes nothing.
func parseStepValue(verified string) (userID int64, email, key string, ok bool) {
	parts := strings.Split(verified, "|")
	if parts[0] == stepValueV2 {
		if len(parts) != 4 {
			return 0, "", "", false
		}
		var okEmail, okKey bool
		email, okEmail = stepFieldDecode(parts[2])
		key, okKey = stepFieldDecode(parts[3])
		userID = parseTempCookieUserID(parts[1])
		return userID, email, key, userID != 0 && okEmail && okKey
	}
	if !time.Now().Before(tempCookieLegacyUntil) {
		return 0, "", "", false
	}
	parts = strings.SplitN(verified, "|", 3)
	if len(parts) < 2 {
		return 0, "", "", false
	}
	if len(parts) == 3 {
		key = parts[2]
	}
	userID = parseTempCookieUserID(parts[0])
	return userID, parts[1], key, userID != 0
}

// stepAccountEmail returns the current email of the account a step value
// names, when it is still the address the value was issued for. Everything a
// completed step does with an email (proof, tenant resolution, the session)
// uses this, never the value's own copy.
func stepAccountEmail(db *sql.DB, userID int64, issuedFor string) (string, bool) {
	if db == nil || userID <= 0 {
		return "", false
	}
	var email string
	if err := db.QueryRow("SELECT COALESCE(email, '') FROM _benmore_users WHERE id = ?", userID).Scan(&email); err != nil {
		return "", false
	}
	if !strings.EqualFold(strings.TrimSpace(email), strings.TrimSpace(issuedFor)) {
		return "", false
	}
	return email, true
}
