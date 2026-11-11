//go:build !cli

package main

// Email verification links.
//
// A verification link proves control of the mailbox, not who chose the
// account's password. Verifying an account turns on everything addressed to
// that email (tenant memberships, room and record shares, pending invites -
// see email_grants.go), so a click from the mailbox must not hand those to
// whoever registered the address first. The link therefore completes in one
// of three ways:
//
//   - The clicking browser is signed in as the account (the usual "sign up,
//     open the mail, click" path): verified at once; the account's other
//     sessions and tokens end.
//   - It is not: the page asks for the account's password before verifying.
//     The owner on another device types it and is done; a mailbox owner who
//     never set that password (someone squatted the address) is pointed at
//     password reset, which revokes the squatter's sessions, passkeys and
//     unverified MFA. The token is not spent until the password is proven.
//   - The account has no password at all: nobody chose a credential to
//     prove, so it is claimed - MFA, passkeys, sessions and tokens are
//     cleared - and then verified.
//
// Trade-off: verifying on a second device now needs the password once.

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// verifyEmailToken returns the address an unused, unexpired verification
// token names. It matches the HASH only: the old IN(hash, raw) fallback for
// pre-hashing links made the stored hash itself a working token for anyone
// who could read the table.
func verifyEmailToken(app *App, token string) (string, bool) {
	if token == "" {
		return "", false
	}
	var email string
	err := app.DB.QueryRow(
		"SELECT email FROM _benmore_password_resets WHERE token = ? AND datetime(expires_at) > datetime('now') AND used = 0 AND type = 'verify'",
		hashResetToken(token),
	).Scan(&email)
	return email, err == nil
}

// consumeVerifyEmailToken spends the token exactly once.
func consumeVerifyEmailToken(app *App, token string) bool {
	result, err := app.DB.Exec("UPDATE _benmore_password_resets SET used = 1 WHERE token = ? AND used = 0 AND type = 'verify' AND datetime(expires_at) > datetime('now')", hashResetToken(token))
	if err != nil {
		return false
	}
	n, _ := result.RowsAffected()
	return n == 1
}

type verifyEmailAccount struct {
	userID      int64
	verified    bool
	hasPassword bool
}

func lookupVerifyEmailAccount(app *App, email string) (verifyEmailAccount, bool) {
	var a verifyEmailAccount
	var verified int
	var hash string
	if err := app.DB.QueryRow("SELECT id, COALESCE(verified, 0), COALESCE(password_hash, '') FROM _benmore_users WHERE email = ? COLLATE NOCASE", email).Scan(&a.userID, &verified, &hash); err != nil {
		return a, false
	}
	a.verified, a.hasPassword = verified == 1, hash != ""
	return a, true
}

// restoreVerifyEmailToken makes a spent link usable again. The link is spent
// before the account is marked, so when the mark is not stored it is put
// back: it is the only link a sign-up gets, and under auth.require_verified
// the account cannot sign in to ask for another.
func restoreVerifyEmailToken(app *App, token string) {
	if _, err := app.DB.Exec("UPDATE _benmore_password_resets SET used = 0 WHERE token = ? AND used = 1 AND type = 'verify'", hashResetToken(token)); err != nil {
		log.Printf("auth: a verification link spent on a failed verification could not be restored: %v", err)
	}
}

// failEmailVerification answers a link whose account could not be marked
// verified: a server error, never the redirect a completed verification
// gets, with the link usable again.
func failEmailVerification(w http.ResponseWriter, r *http.Request, app *App, token string, err error) {
	restoreVerifyEmailToken(app, token)
	invalidateRequestSession(r)
	serverError(w, r, app, "verify email", err, "Your email could not be verified. Open the link again.")
}

// completeEmailVerification marks the account verified (attaching invites
// waiting on the address) and ends every session and token other than keep,
// as the other credential changes do. On an error the account is not
// verified and nothing was revoked.
func completeEmailVerification(app *App, userID int64, email, keep string) error {
	if err := markEmailVerified(app, userID, email); err != nil {
		return err
	}
	if err := revokeOtherCredentials(app.DB, userID, keep); err != nil {
		log.Printf("auth: revoking credentials after email verification failed (user %d): %v", userID, err)
	}
	return nil
}

func handleVerifyEmail(w http.ResponseWriter, r *http.Request, app *App) {
	token := r.URL.Query().Get("token")
	email, ok := verifyEmailToken(app, token)
	if !ok {
		http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
		return
	}
	account, found := lookupVerifyEmailAccount(app, email)
	switch {
	case !found || account.verified:
		// Nothing left to unlock: an address with no account, or an
		// account already verified (marking again only attaches invites).
		if !consumeVerifyEmailToken(app, token) {
			http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
			return
		}
		if found {
			if err := markEmailVerified(app, account.userID, email); err != nil {
				failEmailVerification(w, r, app, token, err)
				return
			}
		}
	case verifyEmailSessionOwner(app, r, account.userID) != "":
		if !consumeVerifyEmailToken(app, token) {
			http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
			return
		}
		if err := completeEmailVerification(app, account.userID, email, verifyEmailSessionOwner(app, r, account.userID)); err != nil {
			failEmailVerification(w, r, app, token, err)
			return
		}
	case !account.hasPassword:
		if !consumeVerifyEmailToken(app, token) {
			http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
			return
		}
		if err := claimUnverifiedAccountAs(app, account.userID, email, "email_claim_unverified"); err != nil {
			// The claim rolled back and nothing is verified: same answer
			// as a mark that was not stored (it used to be the redirect a
			// completed verification gets, with the link spent).
			failEmailVerification(w, r, app, token, fmt.Errorf("claiming unverified account %d: %w", account.userID, err))
			return
		}
		err := completeEmailVerification(app, account.userID, email, "")
		if err != nil {
			// A busy database is the likely cause; the claim is already in,
			// so one more try is cheap and spares the reset below.
			err = completeEmailVerification(app, account.userID, email, "")
		}
		if err != nil {
			// The claim committed: the account now has a password nobody
			// knows, so a restored link would only lead to a password form
			// that cannot be answered. Leave it spent and point at the reset,
			// which proves the same mailbox.
			invalidateRequestSession(r)
			serverError(w, r, app, "verify email", err, "Your email could not be verified. Use \"Forgot password\" with this address to finish setting up your account.")
			return
		}
	default:
		// Not signed in as the account: prove its password first. The
		// token stays unspent so the form can carry it.
		renderVerifyEmailConfirm(w, r, app, token, email, "", http.StatusOK)
		return
	}
	// Verification and revocation changed what this request's session is.
	invalidateRequestSession(r)
	// The link proves the address, not whoever chose the password.
	platformEmailProved(app, email, false)
	http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
}

// verifyEmailSessionOwner returns the stored id of the session the request
// presents when it belongs to userID, else "".
func verifyEmailSessionOwner(app *App, r *http.Request, userID int64) string {
	c, err := requestSessionCookie(r)
	if err != nil || c.Value == "" {
		return ""
	}
	if s := getAppSession(app, r, c.Value); s != nil && s.UserID == userID {
		return s.ID
	}
	return ""
}

// handleVerifyEmailConfirm completes a verification link opened outside
// the account's session, once the account's password is proven.
func handleVerifyEmailConfirm(w http.ResponseWriter, r *http.Request, app *App) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	r.ParseForm()
	token := r.FormValue("token")
	email, ok := verifyEmailToken(app, token)
	if !ok {
		http.Redirect(w, r, app.Paths.Login+"?error="+url.QueryEscape("This verification link is invalid or has expired."), http.StatusSeeOther)
		return
	}
	if !validateCSRF(r) {
		renderVerifyEmailConfirm(w, r, app, token, email, "This form expired. Try again.", http.StatusForbidden)
		return
	}
	account, found := lookupVerifyEmailAccount(app, email)
	if !found || account.verified || !account.hasPassword {
		// Those cases need no password; the link itself completes them.
		http.Redirect(w, r, app.Paths.VerifyEmail+"?token="+url.QueryEscape(token), http.StatusSeeOther)
		return
	}
	if matched, locked := currentPasswordMatches(app, account.userID, r.FormValue("password")); !matched {
		msg := "That password is not correct."
		status := http.StatusForbidden
		if locked {
			msg, status = "Too many attempts. Try again in 15 minutes.", http.StatusTooManyRequests
		}
		renderVerifyEmailConfirm(w, r, app, token, email, msg, status)
		return
	}
	if !consumeVerifyEmailToken(app, token) {
		http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
		return
	}
	if err := completeEmailVerification(app, account.userID, email, ""); err != nil {
		failEmailVerification(w, r, app, token, err)
		return
	}
	invalidateRequestSession(r)
	platformEmailProved(app, email, false)
	http.Redirect(w, r, app.Paths.Login+"?success="+url.QueryEscape("Email verified. Sign in to continue."), http.StatusSeeOther)
}

func renderVerifyEmailConfirm(w http.ResponseWriter, r *http.Request, app *App, token, email, message string, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// The token is in this page's URL and form: no other origin gets a
	// Referer. Not no-referrer, which makes the browser send Origin: null on
	// the page's own form POST.
	w.Header().Set("Referrer-Policy", "same-origin")
	denyFraming(w)
	w.WriteHeader(status)
	page := template.Must(template.New("verify-email").Parse(verifyEmailConfirmHTML))
	_ = page.Execute(w, map[string]string{
		"Error":  message,
		"Email":  strings.TrimSpace(email),
		"Token":  token,
		"CSRF":   authMintCSRFToken(authRawSessionID(r)),
		"Action": app.Paths.VerifyEmail,
		"Forgot": app.Paths.ForgotPassword,
	})
}

const verifyEmailConfirmHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Confirm your email</title>
<style>body{font:16px system-ui,sans-serif;max-width:28rem;margin:8vh auto;padding:1.5rem;color:#172033;background:#f8fafc}h1{font-size:1.8rem}label{display:block;margin:1rem 0}input{display:block;width:100%;box-sizing:border-box;padding:.7rem;margin-top:.4rem;border:1px solid #94a3b8;border-radius:.35rem;font:inherit}button{padding:.7rem 1rem;font:inherit;cursor:pointer}p{line-height:1.5}[role=alert]{color:#a11225}</style></head>
<body><main><h1>Confirm your email</h1><p>Enter the password for <strong>{{.Email}}</strong> to finish verifying this address.</p>
{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}"><input type="hidden" name="_csrf" value="{{.CSRF}}"><input type="hidden" name="token" value="{{.Token}}">
<label>Password<input type="password" name="password" autocomplete="current-password" maxlength="128" required autofocus></label>
<button type="submit">Verify email</button></form>
<p>Didn't create this account, or don't know its password? <a href="{{.Forgot}}">Reset the password</a> first, then open the link again.</p></main></body></html>`
