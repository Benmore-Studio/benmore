//go:build !cli

package main

// Verify-on-next-sign-in for grandfathered accounts.
//
// 2.7.237 let accounts that existed at the upgrade keep email-keyed grants
// without a verified address (email_grandfathered). Those accounts now prove
// the address at their next password sign-in: in an app that keys grants by
// email, a grandfathered, unverified account gets a verification link and
// its sign-in stops until the link is opened. Sessions that already exist
// keep working until they end. If no link can be sent, the sign-in goes
// ahead on the grandfathered grants and the log says why, so a mail outage
// never locks members out.

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"time"
)

// sendVerificationEmail is the verification-link transport; tests replace it.
var sendVerificationEmail = func(app *App, to, subject, body string) error {
	return SendEmail(app.Dir, to, subject, body)
}

// appKeysGrantsByEmail reports whether app names people by email in a grant
// it evaluates: an email-keyed tenant membership, member-of or ws_rooms rule,
// or a record share addressed to an email.
func appKeysGrantsByEmail(app *App) bool {
	if app == nil {
		return false
	}
	if g := app.Group; g != nil && g.Table != "" && emailKeyedColumn(g.UserField) {
		return true
	}
	if app.Access != nil {
		for _, ops := range app.Access.rules {
			for _, mode := range ops {
				if rule := parseMemberOf(mode); rule != nil && emailKeyedColumn(rule.UserCol) {
					return true
				}
			}
		}
	}
	for _, room := range app.wsRoomRules() {
		if room.Rule != nil && emailKeyedColumn(room.Rule.UserCol) {
			return true
		}
	}
	if app.DB != nil {
		var shared int
		app.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM _benmore_permissions WHERE grant_type = 'user' AND grantee_id LIKE '%@%')").Scan(&shared)
		return shared == 1
	}
	return false
}

// sendEmailVerificationLink mails a one-hour verification link for email.
// A link sent in the last five minutes is not sent again.
func sendEmailVerificationLink(app *App, r *http.Request, email, intro string) error {
	base, ok := securityLinkBaseURL(app, r)
	if !ok {
		return fmt.Errorf("no trusted public origin for the link")
	}
	var recent int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_password_resets WHERE email = ? COLLATE NOCASE AND type = 'verify' AND used = 0 AND datetime(expires_at) > datetime('now', '+55 minutes')", email).Scan(&recent)
	if recent > 0 {
		return nil
	}
	token := generateToken(32)
	expires := time.Now().Add(time.Hour)
	if _, err := app.DB.Exec("INSERT INTO _benmore_password_resets (token, email, expires_at, type) VALUES (?, ?, ?, 'verify')",
		hashResetToken(token), email, expires.UTC().Format(time.RFC3339)); err != nil {
		return fmt.Errorf("store verification link: %w", err)
	}
	siteName := "App"
	if app.Design != nil {
		if sn, ok := app.Design.SEO["site_name"]; ok && sn != "" {
			siteName = sn
		}
	}
	verifyURL := fmt.Sprintf("%s%s?token=%s", base, app.Paths.VerifyEmail, token)
	body := fmt.Sprintf(`<h2>Verify your email</h2>
<p>%s</p>
<p><a href="%s">Verify Email</a></p>`, fmt.Sprintf(intro, html.EscapeString(siteName)), verifyURL)
	return sendVerificationEmail(app, email, "Verify your email - "+siteName, body)
}

// grandfatheredSignInNeedsProof reports whether this password sign-in must
// stop until the account verifies its email, sending the link if so. It is
// false for verified or non-grandfathered accounts, apps that don't key
// grants by email, apps whose sign-in already proves the address (auth.otp),
// and whenever the link can't be sent.
func grandfatheredSignInNeedsProof(app *App, r *http.Request, userID int64) (email string, stop bool) {
	var verified, grandfathered int
	app.DB.QueryRow("SELECT COALESCE(email, ''), COALESCE(verified, 0), COALESCE(email_grandfathered, 0) FROM _benmore_users WHERE id = ?", userID).Scan(&email, &verified, &grandfathered)
	if email == "" || verified == 1 || grandfathered == 0 || otpLoginEnabled(app) || !appKeysGrantsByEmail(app) {
		return email, false
	}
	if err := sendEmailVerificationLink(app, r, email, "Confirm your email address to keep signing in to %s."); err != nil {
		log.Printf("auth: account %d signed in on grandfathered email grants; its verification link was not sent: %v", userID, err)
		return email, false
	}
	return email, true
}

const grandfatheredVerifyMessage = "Please verify your email to continue. We sent a link to your address; open it, then sign in again."

// emailVerificationRequiredCode is the error code for an account whose email
// must be verified before it may sign in: a grandfathered account at its next
// sign-in (above), and every unverified account in an app that sets
// auth.require_verified. Sign-in answers it with 403, a request that presents
// an existing credential of such an account with 401.
const emailVerificationRequiredCode = "email_verification_required"

const (
	unverifiedSignInMessage       = "Please verify your email to continue. This account can't sign in until its email address is verified."
	unverifiedSignupLinkMessage   = "Account created. We sent a verification link to your email address; open it, then sign in."
	unverifiedSignupNoLinkMessage = "Account created. Its email address must be verified before you can sign in."
	unverifiedCredentialLinkHint  = "Please verify your email to continue. Open the link we sent to your address, or sign in again to get a new one."
)

// requireVerifiedEmail reports whether app.yaml sets auth.require_verified:
// a session or token of an account whose email is unverified does not
// authenticate (resolveRequestSession).
func requireVerifiedEmail(app *App) bool {
	return app != nil && app.Design != nil && app.Design.Auth["require_verified"] == "true"
}

// signInProvesEmail reports whether this app's interactive sign-in itself
// verifies the address: the auth.otp code goes to the account's email (an
// SMS code for a phone identifier proves the phone, not the email).
func signInProvesEmail(app *App) bool {
	return otpLoginEnabled(app) && authIdentifier(app) != "phone"
}

// requireVerifiedSignInStop reports whether a sign-in whose password was just
// proven must stop because auth.require_verified is set and the account's
// email is not verified: a session or token issued now would be refused on
// every request. It returns the message to show. With auth.verify_email on
// it also mails a fresh verification link (the signup link lasts an hour; a
// link sent in the last five minutes is not sent again). Callers check the
// password first, so the answer never tells a stranger whether an address
// is verified.
func requireVerifiedSignInStop(app *App, r *http.Request, userID int64) (msg string, stop bool) {
	if !requireVerifiedEmail(app) || signInProvesEmail(app) {
		return "", false
	}
	var email string
	var verified int
	if err := app.DB.QueryRow("SELECT COALESCE(email, ''), COALESCE(verified, 0) FROM _benmore_users WHERE id = ?", userID).Scan(&email, &verified); err != nil {
		log.Printf("auth: reading verification state of account %d failed: %v", userID, err)
		return unverifiedSignInMessage, true
	}
	if verified == 1 {
		return "", false
	}
	if email != "" && app.Design.Auth["verify_email"] == "true" {
		err := sendEmailVerificationLink(app, r, email, "Confirm your email address to sign in to %s.")
		if err == nil {
			return grandfatheredVerifyMessage, true
		}
		log.Printf("auth: account %d must verify its email to sign in; its verification link was not sent: %v", userID, err)
	}
	return unverifiedSignInMessage, true
}

// refuseUnverifiedSignIn answers a sign-in or signup that auth.require_verified
// stops, without a session: JSON clients get 403 {ok:false, error:
// "email_verification_required", message} (bm.auth.signIn/signUp throw with
// the message), browser forms return to the login page showing it.
func refuseUnverifiedSignIn(w http.ResponseWriter, r *http.Request, app *App, msg string, extra map[string]any) {
	if wantsJSON(r) {
		body := withRefusalDocs(map[string]any{"ok": false, "error": emailVerificationRequiredCode, "message": msg}, emailVerificationRequiredCode)
		for k, v := range extra {
			body[k] = v
		}
		httpJSON(w, http.StatusForbidden, body)
		return
	}
	authRedirect(w, r, app.Paths.Login, msg)
}

// presentedCredentialAwaitsVerification reports whether the request presents
// a live session or token that auth.require_verified refuses only because its
// account's email is unverified. The 401 for such a request says so, instead
// of the generic "sign in again" (signing in again would be refused too).
func presentedCredentialAwaitsVerification(app *App, r *http.Request) bool {
	if !requireVerifiedEmail(app) {
		return false
	}
	s := presentedRequestSession(app, r)
	return s != nil && !s.Verified
}

// unverifiedCredentialBody is the 401 body for presentedCredentialAwaitsVerification.
func unverifiedCredentialBody(app *App) map[string]any {
	msg := unverifiedSignInMessage
	if app.Design.Auth["verify_email"] == "true" {
		msg = unverifiedCredentialLinkHint
	}
	return withRefusalDocs(map[string]any{"error": emailVerificationRequiredCode, "message": msg}, emailVerificationRequiredCode)
}
