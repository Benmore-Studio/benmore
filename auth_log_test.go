//go:build !cli

package main

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)
	fn()
	return buf.String()
}

// authLogLines keeps the lines the auth code itself wrote (the mail sender's
// own "EMAIL [not sent ...]" line is checked in delivery_log_recipient_test.go).
func authLogLines(out string) string {
	var keep []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "auth: ") || strings.Contains(line, "OAuth login rejected") || strings.Contains(line, "MFA: ") {
			keep = append(keep, line)
		}
	}
	return strings.Join(keep, "\n")
}

// A failed code or link delivery was logged with the recipient's address or
// phone number.
func TestAuthSendFailuresDoNotLogTheRecipient(t *testing.T) {
	app := signupLimitFixture(t, map[string]string{"otp": "true", "verify_email": "true"})
	app.Design.SEO["url"] = "https://app.real"

	out := captureLog(t, func() { postSignup(app, "private.person@corp.example", "198.51.100.90:4000") })
	lines := authLogLines(out)
	if !strings.Contains(lines, "signup OTP email failed") || !strings.Contains(lines, "signup verification email failed") {
		t.Fatalf("the send failures were not logged at all: %q", out)
	}
	if strings.Contains(lines, "private.person") || strings.Contains(lines, "corp.example") {
		t.Fatalf("a sign-up send failure logged the recipient: %s", lines)
	}
	if !strings.Contains(lines, "user=1") {
		t.Fatalf("the line no longer says which account it is about: %s", lines)
	}

	// The sign-in code, by email and by SMS.
	mustExec(t, app.DB, "UPDATE _benmore_users SET phone = '+15550100123' WHERE id = 1")
	out = captureLog(t, func() {
		r := httptest.NewRequest(http.MethodPost, app.Paths.Login, nil)
		startLoginOTP(httptest.NewRecorder(), r, app, 1, "private.person@corp.example", "private.person@corp.example")
		app.Design.Auth["identifier"] = "phone"
		startLoginOTP(httptest.NewRecorder(), r, app, 1, "private.person@corp.example", "+15550100123")
	})
	lines = authLogLines(out)
	if !strings.Contains(lines, "email send failed for verification code") || !strings.Contains(lines, "SMS send failed for verification code") {
		t.Fatalf("the send failures were not logged at all: %q", out)
	}
	if strings.Contains(lines, "private.person") || strings.Contains(lines, "5550100") {
		t.Fatalf("a sign-in code send failure logged the recipient: %s", lines)
	}
}

func TestLogSendErrorRemovesTheRecipient(t *testing.T) {
	err := errors.New("550 5.1.1 <Private.Person@Corp.example>: Recipient address rejected: private.person@corp.example unknown")
	got := logSendError(err, "private.person@corp.example")
	if strings.Contains(strings.ToLower(got), "private.person") || !strings.Contains(got, "550 5.1.1") || !strings.Contains(got, logAddressRef("private.person@corp.example")) {
		t.Fatalf("logSendError = %q", got)
	}
	if logAddressRef("A@x.example") != logAddressRef(" a@x.example ") || logAddressRef("a@x.example") == logAddressRef("b@x.example") {
		t.Fatal("logAddressRef is not a stable per-address reference")
	}
	if strings.Contains(logAddressRef("a@x.example"), "a@x") {
		t.Fatal("logAddressRef leaks the address")
	}
}
