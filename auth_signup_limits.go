//go:build !cli

package main

// Sign-up abuse limits.
//
// POST /signup creates an account for any address and, when auth.otp or
// auth.verify_email is on, mails that address a code or a link. Nothing
// bounded it but the app-wide request limiter: one client could create
// accounts (each a bcrypt hash and a row) as fast as it could post, and aim
// the mail at a single inbox through plus-addressing, which makes
// victim+1@, victim+2@, ... distinct accounts that all deliver to victim@.
//
//   - Per client address (an IPv6 client by its /64, clientRateBucket):
//     signupIPDefaultRate sign-ups per signupIPDefaultWindow, or app.yaml
//     auth.signup_rate_limit ("<count>/<window>") for an app whose users
//     legitimately share one address (an office, a classroom).
//   - Per mailbox: recipientMailRate sign-up mails per recipientMailWindow to
//     one inbox, counted by mailboxRateKey, which folds case, a "+tag" and
//     Gmail's dots.
//
// mailboxRateKey is for counting mail only. An account's identity is always
// the address as given: two plus-variants stay two accounts.

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	signupIPDefaultRate   = 30
	signupIPDefaultWindow = 10 * time.Minute

	// recipientMailRate per recipientMailWindow is the cap on credential mail
	// to one mailbox that the reset and email-change limiters already use.
	recipientMailRate   = 3
	recipientMailWindow = 15 * time.Minute
)

// signupMailboxLimiter caps sign-up mail (the auth.otp code, the
// auth.verify_email link) per mailbox, per app.
var signupMailboxLimiter = NewRateLimiter(recipientMailRate, recipientMailWindow)

// signupIPLimiters holds one limiter per configured rate; keys inside it are
// per app and client address.
var signupIPLimiters sync.Map // "<rate>/<window>" -> *RateLimiter

// parseSignupRateLimit reads "<count>/<window>" (windows as in a flow's
// rate_limit: s, m, h, d or a Go duration). The write gate refuses anything
// else; at run time a value that doesn't parse leaves the default in force.
func parseSignupRateLimit(s string) (rate int, window time.Duration, ok bool) {
	count, win, found := strings.Cut(strings.TrimSpace(s), "/")
	if !found {
		return 0, 0, false
	}
	rate, err := strconv.Atoi(strings.TrimSpace(count))
	if err != nil || rate <= 0 {
		return 0, 0, false
	}
	if window = parseRateWindow(win); window <= 0 {
		return 0, 0, false
	}
	return rate, window, true
}

// signupIPLimit is the app's per-address sign-up budget.
func signupIPLimit(app *App) (int, time.Duration) {
	if app != nil && app.Design != nil {
		if rate, window, ok := parseSignupRateLimit(app.Design.Auth["signup_rate_limit"]); ok {
			return rate, window
		}
	}
	return signupIPDefaultRate, signupIPDefaultWindow
}

func signupIPLimiterFor(rate int, window time.Duration) *RateLimiter {
	key := fmt.Sprintf("%d/%s", rate, window)
	if v, ok := signupIPLimiters.Load(key); ok {
		return v.(*RateLimiter)
	}
	actual, _ := signupIPLimiters.LoadOrStore(key, NewRateLimiter(rate, window))
	return actual.(*RateLimiter)
}

// signupSendsMail reports whether a sign-up mails the new address.
func signupSendsMail(app *App) bool {
	return app != nil && app.Design != nil && (app.Design.Auth["otp"] == "true" || app.Design.Auth["verify_email"] == "true")
}

// signupRateLimited spends one sign-up from the client's budget and, when the
// sign-up sends mail, one from the mailbox's. The address budget is checked
// first, so a client past its own limit can't also use up a mailbox's.
func signupRateLimited(app *App, r *http.Request, email string) (retryAfter time.Duration, limited bool) {
	rate, window := signupIPLimit(app)
	if ok, retry, _ := signupIPLimiterFor(rate, window).Check(appLimiterKey(app, "signup-ip", clientRateBucket(clientIP(r)))); !ok {
		return retry, true
	}
	if signupSendsMail(app) {
		if ok, retry, _ := signupMailboxLimiter.Check(appLimiterKey(app, "signup-mb", mailboxRateKey(email))); !ok {
			return retry, true
		}
	}
	return 0, false
}

// mailboxRateKey maps an address to the inbox its mail lands in, as far as
// that can be told without asking the provider: lower-cased, a "+tag"
// dropped from the local part, and for Gmail the dots it ignores. Rate-limit
// keys only - never compare or store identities with it.
func mailboxRateKey(email string) string {
	e := strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndexByte(e, '@')
	if at <= 0 || at == len(e)-1 {
		return e
	}
	local, domain := e[:at], e[at+1:]
	if i := strings.IndexByte(local, '+'); i > 0 {
		local = local[:i]
	}
	if domain == "googlemail.com" {
		domain = "gmail.com"
	}
	if domain == "gmail.com" {
		if undotted := strings.ReplaceAll(local, ".", ""); undotted != "" {
			local = undotted
		}
	}
	return local + "@" + domain
}
