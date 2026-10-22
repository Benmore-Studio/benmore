//go:build !cli

package main

// Two-step email change.
//
// An account's email is an authorization input, not just contact data:
// tenant membership resolves by email (ResolveGroupID), record-sharing
// grants are keyed by email, and pending invites activate by email. Applying
// a new address immediately let a signed-in user take over whatever was
// granted to an address they don't control (any invite or share for an email
// that has no account yet). A change now takes effect only after the new
// address proves control by opening a single-use, one-hour link; applying it
// revokes every session, API token, OAuth code, connector and edge grant (and
// unused reset links for the old address), so all grants are re-resolved
// under the new identity.

import (
	"database/sql"
	"errors"
	"fmt"
	"html"
	htmltemplate "html/template"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const emailChangeTTL = time.Hour

var errEmailInUse = errors.New("that email is already in use")

// emailChangeFailure is a change request that failed on the server (the
// database, the mail send). Its text is what the caller is told; the cause
// stays server-side (serverErrorJSONBody, noteServerError).
type emailChangeFailure struct {
	msg   string
	cause error
}

func (e *emailChangeFailure) Error() string { return e.msg }
func (e *emailChangeFailure) Unwrap() error { return e.cause }

// errEmailChangeUnsupported refuses a self-service change on the platform
// dashboard app, where the email is also the platform account identity
// (platform_users: apps, plan, CLI tokens). Changing only the app's user row
// orphaned that account, so the change goes through support instead.
var errEmailChangeUnsupported = errors.New("the email on this account can't be changed here - contact support to change it")

// errEmailChangeThrottled refuses a confirmation mail to an address that was
// sent several in the last few minutes.
var errEmailChangeThrottled = errors.New("a confirmation link was sent to that address recently; try again in 15 minutes")

// emailChangeRecipientLimiter caps confirmation mails per mailbox (3 per 15
// minutes, per app). Any signed-in account can name any address, so without
// it one account, or many, could mail-bomb an inbox through the app. The key
// is the mailbox (mailboxRateKey), not the exact address: victim+1@,
// victim+2@, ... all land in victim@'s inbox.
var emailChangeRecipientLimiter = NewRateLimiter(recipientMailRate, recipientMailWindow)

// emailChangeRequesterLimiter caps the confirmation mails one account can
// cause (5 an hour, per app). The per-mailbox cap stops repeats to one inbox;
// without this an account could name a different stranger's address each
// time and send mail from the app's own sender for as long as it liked.
// Nobody retypes their new address more than a few times.
const (
	emailChangeRequesterRate   = 5
	emailChangeRequesterWindow = time.Hour
)

var emailChangeRequesterLimiter = NewRateLimiter(emailChangeRequesterRate, emailChangeRequesterWindow)

// errEmailChangeRequesterThrottled refuses an account past that budget. It
// is a throttle like errEmailChangeThrottled, so callers that answer 429 for
// one answer it for both.
var errEmailChangeRequesterThrottled error = emailChangeThrottle("you asked to change your email several times in the last hour; try again later")

type emailChangeThrottle string

func (e emailChangeThrottle) Error() string        { return string(e) }
func (e emailChangeThrottle) Is(target error) bool { return target == errEmailChangeThrottled }

func ensureEmailChangesTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_email_changes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		new_email TEXT NOT NULL,
		token_hash TEXT NOT NULL UNIQUE,
		expires_at DATETIME NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_email_changes_user ON _benmore_email_changes(user_id)`)
}

// emailTakenByOther reports whether another account already uses email.
func emailTakenByOther(db *sql.DB, email string, userID int64) bool {
	var otherID int64
	return db.QueryRow("SELECT id FROM _benmore_users WHERE lower(email) = lower(?) AND id != ?", email, userID).Scan(&otherID) == nil
}

// requestEmailChange records a pending change and mails a confirmation link
// to the NEW address. The caller has already verified the current password.
// The email is not changed here.
func requestEmailChange(app *App, r *http.Request, userID int64, newEmail string) error {
	if platformDashboardApp(app) {
		return errEmailChangeUnsupported
	}
	if !validAuthEmail(newEmail) {
		return errors.New("enter a single valid email address")
	}
	if allowed, reason := emailAllowedForApp(app, newEmail); !allowed {
		return errors.New(reason)
	}
	ensureEmailChangesTable(app.DB)
	if emailTakenByOther(app.DB, newEmail, userID) {
		return errEmailInUse
	}
	linkBase, ok := securityLinkBaseURL(app, r)
	if !ok {
		return errors.New("email links are not configured for this app (the operator must set seo.url or BENMORE_PUBLIC_URL), so the email was not changed")
	}
	// Checked before the pending change is replaced, so a refused request
	// leaves the link already sent working. The account's own budget comes
	// first: a request it refuses spends nothing of the mailbox's.
	if !emailChangeRequesterLimiter.Allow(appLimiterKey(app, "ec-user", strconv.FormatInt(userID, 10))) {
		return errEmailChangeRequesterThrottled
	}
	if !emailChangeRecipientLimiter.Allow(appLimiterKey(app, "ec", mailboxRateKey(newEmail))) {
		return errEmailChangeThrottled
	}
	token := generateToken(32)
	if _, err := app.DB.Exec("DELETE FROM _benmore_email_changes WHERE user_id = ?", userID); err != nil {
		return &emailChangeFailure{"could not start the email change", err}
	}
	if _, err := app.DB.Exec("INSERT INTO _benmore_email_changes (user_id, new_email, token_hash, expires_at) VALUES (?, ?, ?, ?)",
		userID, newEmail, hashResetToken(token), time.Now().Add(emailChangeTTL).UTC().Format(time.RFC3339)); err != nil {
		return &emailChangeFailure{"could not start the email change", err}
	}
	link := fmt.Sprintf("%s/settings/confirm-email?token=%s", linkBase, token)
	siteName := "your account"
	if app.Design != nil && app.Design.SEO != nil && app.Design.SEO["site_name"] != "" {
		siteName = app.Design.SEO["site_name"]
	}
	body := fmt.Sprintf(`<h2>Confirm your new email</h2>
<p>Someone asked to change the email on %s to this address. If that was you, confirm within one hour:</p>
<p><a href="%s">Confirm email change</a></p>
<p>If you didn't ask for this, ignore this message; nothing changes.</p>`, html.EscapeString(siteName), link)
	if err := SendEmail(app.Dir, newEmail, "Confirm your new email", body); err != nil {
		app.DB.Exec("DELETE FROM _benmore_email_changes WHERE user_id = ?", userID)
		return &emailChangeFailure{"could not send the confirmation email, so the email was not changed", err}
	}
	return nil
}

// confirmEmailChange applies a pending change for a valid, unexpired token.
// Returns the user id and old/new addresses.
func confirmEmailChange(app *App, token string) (int64, string, string, error) {
	// Also covers a change requested before the dashboard refused them.
	if platformDashboardApp(app) {
		return 0, "", "", errEmailChangeUnsupported
	}
	ensureEmailChangesTable(app.DB)
	if token == "" {
		return 0, "", "", errors.New("missing token")
	}
	var userID int64
	var newEmail, expires string
	if err := app.DB.QueryRow("SELECT user_id, new_email, expires_at FROM _benmore_email_changes WHERE token_hash = ?", hashResetToken(token)).Scan(&userID, &newEmail, &expires); err != nil {
		return 0, "", "", errors.New("this link is invalid or was already used")
	}
	// Single use, whatever happens next.
	app.DB.Exec("DELETE FROM _benmore_email_changes WHERE token_hash = ?", hashResetToken(token))
	if t, err := time.Parse(time.RFC3339, expires); err != nil || time.Now().After(t) {
		return 0, "", "", errors.New("this link has expired - request the change again")
	}
	// Checked again at confirmation: a change requested under an older rule
	// must not install an address the current one refuses.
	if !validAuthEmail(newEmail) {
		return 0, "", "", errors.New("this link is invalid or was already used")
	}
	if allowed, _ := emailAllowedForApp(app, newEmail); !allowed {
		return 0, "", "", errors.New("this link is invalid or was already used")
	}
	if emailTakenByOther(app.DB, newEmail, userID) {
		return 0, "", "", errEmailInUse
	}
	var oldEmail string
	app.DB.QueryRow("SELECT email FROM _benmore_users WHERE id = ?", userID).Scan(&oldEmail)
	// The new address just proved control, so it is verified. Check the live
	// table: framework tables are not part of the app's loaded schema.
	setVerified := ""
	if cols, err := GetTableColumns(app.DB, "_benmore_users"); err == nil && hasColumnInList(cols, "verified") {
		setVerified = ", verified = 1"
	}
	// The change is an identity change: every session, API token, OAuth code
	// and connector grant ends with it (whoever held the old address may hold
	// one), and unused reset links for the old address are cancelled, in the
	// same transaction as the update. Revoking first lets the reset-link
	// cancellation match the old address. Every session re-authenticates so
	// group, grants and invites are re-resolved for the new identity.
	tx, err := app.DB.Begin()
	if err != nil {
		return 0, "", "", errors.New("could not update the email")
	}
	defer tx.Rollback()
	if err := revokePasswordCredentials(tx, userID); err != nil {
		return 0, "", "", errors.New("could not update the email")
	}
	if _, err := tx.Exec("UPDATE _benmore_users SET email = ?"+setVerified+" WHERE id = ?", newEmail, userID); err != nil {
		return 0, "", "", errors.New("could not update the email")
	}
	if err := tx.Commit(); err != nil {
		return 0, "", "", errors.New("could not update the email")
	}
	revokeEdgeGrantsAfterCredentialChange(app, userID)
	if setVerified != "" {
		activateEmailInvites(app, userID, newEmail)
	}
	return userID, oldEmail, newEmail, nil
}

func registerEmailChangeConfirmRoute(mux *http.ServeMux, app *App) {
	ensureEmailChangesTable(app.DB)
	registerEmailChangeConfirmRoutes(mux, app)
}

func registerEmailChangeConfirmRoutes(mux appRouteRegistrar, app *App) {
	loginPath := func() string {
		if app.Paths != nil && app.Paths.Login != "" {
			return app.Paths.Login
		}
		return "/login"
	}
	// Opening the link only shows a confirm form. Mail scanners and link
	// previewers fetch every link in a message, so applying the change on
	// this GET let a recipient's scanner confirm a change nobody there asked
	// for (and hand the requester whatever is addressed to that inbox). The
	// token is not spent here.
	//
	// The form is also not enough on its own. The link goes to an inbox the
	// REQUESTER names, so whoever reads that mail can be talked into pressing
	// a button ("confirm your address to accept the invitation"); the
	// requester's account would then own the address. Confirming therefore
	// takes proof of the requesting account as well as the link: its own
	// signed-in browser (emailChangeSessionOwner), or the account's password.
	mux.HandleFunc("GET /settings/confirm-email", func(w http.ResponseWriter, r *http.Request) {
		if accountSettingsDisabled(w, r, app) {
			return
		}
		token := r.URL.Query().Get("token")
		userID, newEmail, ok := pendingEmailChange(app, token)
		if !ok {
			authRedirect(w, r, loginPath(), "this link is invalid, expired or was already used")
			return
		}
		if allowed, _ := emailAllowedForApp(app, newEmail); !allowed {
			authRedirect(w, r, loginPath(), "this link is invalid, expired or was already used")
			return
		}
		renderEmailChangeConfirm(w, r, app, token, newEmail, "", http.StatusOK, !emailChangeSessionOwner(app, r, userID))
	})
	mux.HandleFunc("POST /settings/confirm-email", func(w http.ResponseWriter, r *http.Request) {
		if accountSettingsDisabled(w, r, app) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		r.ParseForm()
		token := r.PostFormValue("token")
		userID, pendingEmail, ok := pendingEmailChange(app, token)
		if !ok {
			authRedirect(w, r, loginPath(), "this link is invalid, expired or was already used")
			return
		}
		if allowed, _ := emailAllowedForApp(app, pendingEmail); !allowed {
			authRedirect(w, r, loginPath(), "this link is invalid, expired or was already used")
			return
		}
		askPassword := !emailChangeSessionOwner(app, r, userID)
		if !validateCSRF(r) {
			renderEmailChangeConfirm(w, r, app, token, pendingEmail, "This form expired. Try again.", http.StatusForbidden, askPassword)
			return
		}
		// Refused before the dashboard's own check so the page never asks for
		// a password it would not use (confirmEmailChange refuses again).
		if askPassword && !platformDashboardApp(app) {
			if matched, locked := currentPasswordMatches(app, userID, r.PostFormValue("password")); !matched {
				msg, status := "That password is not correct.", http.StatusForbidden
				if locked {
					msg, status = "Too many attempts. Try again in 15 minutes.", http.StatusTooManyRequests
				}
				renderEmailChangeConfirm(w, r, app, token, pendingEmail, msg, status, true)
				return
			}
		}
		_, oldEmail, newEmail, err := confirmEmailChange(app, token)
		if err != nil {
			authRedirect(w, r, loginPath(), err.Error())
			return
		}
		invalidateRequestSession(r) // the account's sessions are gone
		if oldEmail != "" && !strings.EqualFold(oldEmail, newEmail) {
			go SendEmail(app.Dir, oldEmail, "Your email was changed",
				fmt.Sprintf("Your account email was changed to %s. If this wasn't you, contact support immediately.", html.EscapeString(newEmail)))
		}
		authRedirect(w, r, loginPath(), "Email confirmed. Sign in with your new address.")
	})
}

// emailChangeSessionOwner reports whether the request comes from the
// requesting account's own signed-in browser: its session cookie, for a
// direct sign-in (not support impersonation, act-as or a scoped session).
func emailChangeSessionOwner(app *App, r *http.Request, userID int64) bool {
	c, err := requestSessionCookie(r)
	if err != nil || c.Value == "" {
		return false
	}
	s := GetSessionFromDB(app.DB, c.Value)
	return s != nil && s.UserID == userID && directLoginSession(app, s)
}

// pendingEmailChange returns the requesting account and the new address of
// an unexpired pending change for token, without spending it.
func pendingEmailChange(app *App, token string) (int64, string, bool) {
	if token == "" {
		return 0, "", false
	}
	ensureEmailChangesTable(app.DB)
	var userID int64
	var newEmail, expires string
	if err := app.DB.QueryRow("SELECT user_id, new_email, expires_at FROM _benmore_email_changes WHERE token_hash = ?", hashResetToken(token)).Scan(&userID, &newEmail, &expires); err != nil {
		return 0, "", false
	}
	if t, err := time.Parse(time.RFC3339, expires); err != nil || time.Now().After(t) {
		return 0, "", false
	}
	return userID, newEmail, true
}

func renderEmailChangeConfirm(w http.ResponseWriter, r *http.Request, app *App, token, newEmail, message string, status int, askPassword bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// The token is in this page's URL and form: no other origin gets a
	// Referer. Not no-referrer, which makes the browser send Origin: null on
	// the page's own form POST.
	w.Header().Set("Referrer-Policy", "same-origin")
	denyFraming(w)
	w.WriteHeader(status)
	siteName := "your account"
	if app.Design != nil && app.Design.SEO != nil && app.Design.SEO["site_name"] != "" {
		siteName = app.Design.SEO["site_name"]
	}
	page := htmltemplate.Must(htmltemplate.New("confirm-email").Parse(emailChangeConfirmHTML))
	_ = page.Execute(w, map[string]any{
		"Error":       message,
		"Email":       newEmail,
		"Site":        siteName,
		"Token":       token,
		"CSRF":        authMintCSRFToken(authRawSessionID(r)),
		"AskPassword": askPassword,
	})
}

const emailChangeConfirmHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Confirm your new email</title>
<style>body{font:16px system-ui,sans-serif;max-width:28rem;margin:8vh auto;padding:1.5rem;color:#172033;background:#f8fafc}h1{font-size:1.8rem}label{display:block;margin:1rem 0}input[type=password]{display:block;width:100%;box-sizing:border-box;padding:.7rem;margin-top:.4rem;border:1px solid #94a3b8;border-radius:.35rem;font:inherit}button{padding:.7rem 1rem;font:inherit;cursor:pointer}p{line-height:1.5}[role=alert]{color:#a11225}</style></head>
<body><main><h1>Confirm your new email</h1><p>Make <strong>{{.Email}}</strong> the email for {{.Site}}? You will be signed out everywhere and sign in again with this address.</p>
{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}
<form method="post" action="/settings/confirm-email"><input type="hidden" name="_csrf" value="{{.CSRF}}"><input type="hidden" name="token" value="{{.Token}}">
{{if .AskPassword}}<p>You are not signed in to that account in this browser. To confirm, enter the password of the account that asked for this change.</p>
<label>Account password<input type="password" name="password" autocomplete="current-password" maxlength="128" required autofocus></label>{{end}}
<button type="submit">Confirm email change</button></form>
<p>If you didn't ask for this, close this page; nothing changes. Don't confirm because a message asked you to: only the account that requested the change can.</p></main></body></html>`
