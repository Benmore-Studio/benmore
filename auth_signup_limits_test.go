//go:build !cli

package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func signupLimitFixture(t *testing.T, auth map[string]string) *App {
	t.Helper()
	t.Setenv("BENMORE_PUBLIC_URL", "https://app.real")
	app, cleanup := newTestApp(t)
	t.Cleanup(cleanup)
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	EnsureLoginAttemptsTable(app.DB)
	EnsurePasswordResetsTable(app.DB)
	app.Paths = DiscoverAuthPaths(nil)
	app.Design = &DesignConfig{Auth: auth, SEO: map[string]string{}}
	return app
}

func postSignup(app *App, email, remoteAddr string) *httptest.ResponseRecorder {
	form := url.Values{"email": {email}, "password": {fixturePassword}, "_csrf": {authMintCSRFToken("")}}
	r := httptest.NewRequest(http.MethodPost, app.Paths.Signup, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "application/json")
	if remoteAddr != "" {
		r.RemoteAddr = remoteAddr
	}
	w := httptest.NewRecorder()
	handleSignup(w, r, app)
	return w
}

func signupAccounts(t *testing.T, app *App) int {
	t.Helper()
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_users").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Sign-up had no limit of its own: one client could create accounts (and, on
// an auth.otp or auth.verify_email app, send mail to any address) as fast as
// it could post.
func TestSignupIsLimitedPerClientAddress(t *testing.T) {
	app := signupLimitFixture(t, map[string]string{"signup_rate_limit": "3/1h"})
	for i := 0; i < 3; i++ {
		if w := postSignup(app, fmt.Sprintf("person%d@corp.example", i), "198.51.100.7:4000"); w.Code == http.StatusTooManyRequests {
			t.Fatalf("sign-up %d was limited", i+1)
		}
	}
	w := postSignup(app, "person3@corp.example", "198.51.100.7:4001")
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("a fourth sign-up from one address: %d (Retry-After %q) %s", w.Code, w.Header().Get("Retry-After"), w.Body.String())
	}
	if n := signupAccounts(t, app); n != 3 {
		t.Fatalf("accounts = %d, want 3", n)
	}
	// Another client is unaffected, and so is another app.
	if w := postSignup(app, "elsewhere@corp.example", "198.51.100.8:4000"); w.Code == http.StatusTooManyRequests {
		t.Fatal("the limit is not per client address")
	}
	other := signupLimitFixture(t, map[string]string{"signup_rate_limit": "3/1h"})
	if w := postSignup(other, "person@corp.example", "198.51.100.7:4000"); w.Code == http.StatusTooManyRequests {
		t.Fatal("one app's sign-ups spent another app's budget")
	}
}

// An IPv6 client is counted by its /64, as every other per-address limit.
func TestSignupLimitCountsIPv6BySlash64(t *testing.T) {
	app := signupLimitFixture(t, map[string]string{"signup_rate_limit": "2/1h"})
	postSignup(app, "a@corp.example", "[2001:db8:1:2::1]:4000")
	postSignup(app, "b@corp.example", "[2001:db8:1:2::2]:4000")
	if w := postSignup(app, "c@corp.example", "[2001:db8:1:2:ffff::3]:4000"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("a third address in the same /64 got a fresh budget: %d", w.Code)
	}
	if w := postSignup(app, "d@corp.example", "[2001:db8:1:3::1]:4000"); w.Code == http.StatusTooManyRequests {
		t.Fatal("another /64 shared the budget")
	}
}

func TestSignupDefaultAddressLimit(t *testing.T) {
	app := signupLimitFixture(t, map[string]string{})
	if rate, window := signupIPLimit(app); rate != signupIPDefaultRate || window != signupIPDefaultWindow {
		t.Fatalf("default = %d/%s", rate, window)
	}
	// A value that doesn't parse leaves the default in force.
	app.Design.Auth["signup_rate_limit"] = "lots"
	if rate, window := signupIPLimit(app); rate != signupIPDefaultRate || window != signupIPDefaultWindow {
		t.Fatalf("malformed value changed the limit to %d/%s", rate, window)
	}
	delete(app.Design.Auth, "signup_rate_limit")
	// Spend the default budget for one address, then sign up from it.
	key := appLimiterKey(app, "signup-ip", clientRateBucket("198.51.100.9"))
	for i := 0; i < signupIPDefaultRate; i++ {
		if !signupIPLimiterFor(signupIPDefaultRate, signupIPDefaultWindow).Allow(key) {
			t.Fatalf("budget ended after %d", i)
		}
	}
	if w := postSignup(app, "late@corp.example", "198.51.100.9:4000"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("sign-up past the default limit: %d %s", w.Code, w.Body.String())
	}
	if n := signupAccounts(t, app); n != 0 {
		t.Fatalf("a limited sign-up created an account (%d)", n)
	}
}

// Plus-addressing gives unlimited addresses for one inbox, and each sign-up
// on an auth.otp / auth.verify_email app mails it. The cap counts the
// mailbox; the accounts stay distinct.
func TestSignupMailIsCappedPerMailbox(t *testing.T) {
	for _, flag := range []string{"otp", "verify_email"} {
		app := signupLimitFixture(t, map[string]string{flag: "true"})
		for i := 0; i < recipientMailRate; i++ {
			if w := postSignup(app, fmt.Sprintf("victim+%d@corp.example", i), fmt.Sprintf("198.51.100.%d:4000", 20+i)); w.Code == http.StatusTooManyRequests {
				t.Fatalf("%s: sign-up %d for a fresh mailbox was limited", flag, i+1)
			}
		}
		// A different client, a different tag, different case: same inbox.
		if w := postSignup(app, "Victim+again@Corp.example", "198.51.100.40:4000"); w.Code != http.StatusTooManyRequests {
			t.Fatalf("%s: another plus-variant of the same inbox was mailed: %d %s", flag, w.Code, w.Body.String())
		}
		if w := postSignup(app, "victim@corp.example", "198.51.100.41:4000"); w.Code != http.StatusTooManyRequests {
			t.Fatalf("%s: the bare address of the same inbox was mailed: %d", flag, w.Code)
		}
		if n := signupAccounts(t, app); n != recipientMailRate {
			t.Fatalf("%s: accounts = %d, want %d", flag, n, recipientMailRate)
		}
		// Each allowed variant is its own account, stored as given.
		var stored int
		app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_users WHERE email LIKE 'victim+%@corp.example'").Scan(&stored)
		if stored != recipientMailRate {
			t.Fatalf("%s: plus-variants were not kept as distinct accounts (%d)", flag, stored)
		}
		if w := postSignup(app, "someone-else@corp.example", "198.51.100.42:4000"); w.Code == http.StatusTooManyRequests {
			t.Fatalf("%s: the cap is not per mailbox", flag)
		}
	}

	// An app that sends no sign-up mail has nothing to cap per mailbox.
	app := signupLimitFixture(t, map[string]string{})
	for i := 0; i < recipientMailRate+2; i++ {
		if w := postSignup(app, fmt.Sprintf("tester+%d@corp.example", i), fmt.Sprintf("198.51.100.%d:4000", 60+i)); w.Code == http.StatusTooManyRequests {
			t.Fatalf("sign-up %d on an app without sign-up mail was capped per mailbox", i+1)
		}
	}
}

func TestMailboxRateKey(t *testing.T) {
	for in, want := range map[string]string{
		"Person@Corp.Example":         "person@corp.example",
		"person+tag@corp.example":     "person@corp.example",
		"person+a+b@corp.example":     "person@corp.example",
		" person+x@corp.example ":     "person@corp.example",
		"first.last@corp.example":     "first.last@corp.example", // dots matter outside Gmail
		"First.Last+x@gmail.com":      "firstlast@gmail.com",
		"f.i.r.s.t@googlemail.com":    "first@gmail.com",
		"+tag@corp.example":           "+tag@corp.example", // no local part before the tag: left as is
		"not-an-address":              "not-an-address",
		"...@gmail.com":               "...@gmail.com",
		"person@sub.corp.example":     "person@sub.corp.example",
		"other.person@corp.example":   "other.person@corp.example",
		"person+tag@other.example":    "person@other.example",
		"PERSON+TAG@CORP.EXAMPLE":     "person@corp.example",
		"per.son+tag@GoogleMail.com":  "person@gmail.com",
		"person@corp.example+ignored": "person@corp.example+ignored",
	} {
		if got := mailboxRateKey(in); got != want {
			t.Errorf("mailboxRateKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// The email-change confirmation mail had a per-address cap that plus-variants
// stepped around: a signed-in account could mail one inbox without limit.
func TestEmailChangeCapCountsTheMailbox(t *testing.T) {
	t.Setenv("BENMORE_PUBLIC_URL", "https://app.real")
	old := emailChangeRecipientLimiter
	emailChangeRecipientLimiter = NewRateLimiter(recipientMailRate, recipientMailWindow)
	t.Cleanup(func() { emailChangeRecipientLimiter = old })
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureUsersTable(app.DB)
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{"url": "https://app.real"}}
	r := httptest.NewRequest(http.MethodPatch, "/api/_auth/profile", nil)
	for i := 0; i < recipientMailRate; i++ {
		if err := requestEmailChange(app, r, 1, fmt.Sprintf("victim+%d@example.com", i)); errors.Is(err, errEmailChangeThrottled) {
			t.Fatalf("request %d was throttled", i+1)
		}
	}
	if err := requestEmailChange(app, r, 1, "victim+more@example.com"); !errors.Is(err, errEmailChangeThrottled) {
		t.Fatalf("a further plus-variant of the same inbox was mailed: %v", err)
	}
}

func TestSignupRateLimitKeyIsValidatedAtWriteTime(t *testing.T) {
	for _, good := range []string{"100/hour", "30/10m", "5/min", "1000/d"} {
		if msg := validateAppYAML("site_name: demo\nauth:\n  signup_rate_limit: \"" + good + "\"\n"); msg != "" {
			t.Errorf("%q refused: %s", good, msg)
		}
	}
	for _, bad := range []string{"lots", "0/hour", "10", "10/fortnight", "-5/min"} {
		if msg := validateAppYAML("site_name: demo\nauth:\n  signup_rate_limit: \"" + bad + "\"\n"); !strings.Contains(msg, "signup_rate_limit") {
			t.Errorf("%q accepted (%q)", bad, msg)
		}
	}
	if rate, window, ok := parseSignupRateLimit(" 40 / 15m "); !ok || rate != 40 || window != 15*time.Minute {
		t.Errorf("parse = %d %s %v", rate, window, ok)
	}
}
