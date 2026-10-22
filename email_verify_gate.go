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
