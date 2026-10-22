//go:build !cli

package main

// Password validation, token generation, constant-time comparison, and signed temporary cookies.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// tempCookieTTL bounds every temporary auth cookie (MFA step, OTP step,
// MFA setup). The longest browser MaxAge in use is 15 minutes.
const tempCookieTTL = 15 * time.Minute

// tempCookieDomain separates temp-cookie MACs from every other value signed
// with the server secret. Without it an unbound CSRF token
// (nonce|ts|HMAC(secret, "nonce|ts")) was byte-for-byte a valid temp cookie,
// so anyone could mint a "password already verified" MFA cookie.
const tempCookieDomain = "benmore-temp-cookie-v2\x00"

// tempCookieAudience names the app a temp cookie is for. `benmore host` serves
// many tenants from one process and one serverSecret, so without an audience
// a tenant could mint a valid setup token or step cookie for any user id and
// email at another tenant and present it there.
func tempCookieAudience(app *App) string {
	if app == nil || app.Dir == "" {
		return ""
	}
	if abs, err := filepath.Abs(app.Dir); err == nil {
		return filepath.Clean(abs)
	}
	return app.Dir
}

// tempCookieMAC is the unlabelled MAC. New temp cookies use
// tempCookiePurposeMAC; this one stays for values that must not change
// (passkey user handles stored in authenticators, challenge source keys)
// and for the transition in verifyTempCookieFor.
func tempCookieMAC(app *App, payload string) string {
	mac := hmac.New(sha256.New, []byte(serverSecret))
	mac.Write([]byte(tempCookieDomain))
	mac.Write([]byte(tempCookieAudience(app)))
	mac.Write([]byte{0})
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// Temp-cookie purposes. Each kind of half-finished sign-in signs under its
// own label, so a value minted for one step can never be presented as
// another: the OTP and MFA step cookies share the id|email|login shape, and
// without a label an OTP step cookie (issued right after a bare signup)
// verified as an MFA "password already checked" cookie for that account.
const (
	tempCookieMFA      = "mfa-step"
	tempCookieMFACLI   = "mfa-cli"
	tempCookieOTP      = "otp-step"
	tempCookieMFASetup = "mfa-setup"
	tempCookiePasskey  = "passkey-challenge"
)

// tempCookiePurposeDomain versions the labelled MAC away from the legacy
// unlabelled one (tempCookieDomain).
const tempCookiePurposeDomain = "benmore-temp-cookie-v3\x00"

// tempCookieLegacyUntil bounds the transition from unlabelled cookies. Every
// temp cookie lives at most tempCookieTTL, so an unlabelled cookie still in
// flight was minted at most that long before this process started; after
// the window only labelled cookies verify.
var tempCookieLegacyUntil = time.Now().Add(tempCookieTTL)

func tempCookiePurposeMAC(app *App, purpose, payload string) string {
	mac := hmac.New(sha256.New, []byte(serverSecret))
	mac.Write([]byte(tempCookiePurposeDomain))
	mac.Write([]byte(tempCookieAudience(app)))
	mac.Write([]byte{0})
	mac.Write([]byte(purpose))
	mac.Write([]byte{0})
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// signTempCookieFor creates an HMAC-signed, self-expiring value for a
// temporary auth cookie (MFA, OTP, MFA setup, passkey challenge), bound to
// app and purpose. Format: value|expUnix|hex(HMAC(domain||app||purpose||value|exp)).
func signTempCookieFor(app *App, purpose, value string) string {
	payload := value + "|" + strconv.FormatInt(time.Now().Add(tempCookieTTL).Unix(), 10)
	return payload + "|" + tempCookiePurposeMAC(app, purpose, payload)
}

// verifyTempCookieFor checks the signature, purpose and expiry of a
// temporary auth cookie and returns the original value, or "" if tampered,
// expired or signed for another purpose. Until tempCookieLegacyUntil it also
// accepts the unlabelled form that binaries before purpose labels minted.
func verifyTempCookieFor(app *App, purpose, signed string) string {
	lastPipe := strings.LastIndex(signed, "|")
	if lastPipe < 0 || purpose == "" {
		return ""
	}
	payload, sig := signed[:lastPipe], signed[lastPipe+1:]
	if !hmac.Equal([]byte(sig), []byte(tempCookiePurposeMAC(app, purpose, payload))) &&
		!(time.Now().Before(tempCookieLegacyUntil) && hmac.Equal([]byte(sig), []byte(tempCookieMAC(app, payload)))) {
		return "" // tampered, or signed for another purpose
	}
	expPipe := strings.LastIndex(payload, "|")
	if expPipe < 0 {
		return ""
	}
	exp, err := strconv.ParseInt(payload[expPipe+1:], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return ""
	}
	return payload[:expPipe]
}

// parseTempCookieUserID parses the leading user-id field strictly: the whole
// field must be a positive decimal integer (fmt.Sscanf("%d") accepted any
// value that merely STARTED with digits).
func parseTempCookieUserID(field string) int64 {
	id, err := strconv.ParseInt(field, 10, 64)
	if err != nil || id <= 0 {
		return 0
	}
	return id
}

// validAuthEmail reports whether s is one plain mailbox: a single "@" with a
// local part and a domain, no whitespace, control or invisible format
// characters, and none of the characters that turn a value into an address
// LIST or a display-name form. The mail senders split a To value on commas,
// and the auth.domain gate only compared the tail, so
// "me@evil.example,x@corp.example" passed a corp.example gate while every
// code and link was also delivered to evil.example.
//
// "|" is refused too. It never appears in a real mailbox, and it was the field
// separator of the signed sign-in step cookies and MFA setup tokens that
// carry an email: an address holding one shifted those fields, so
// "victim@corp.example|x" read back as victim@corp.example. Signup always
// refused it; this is the one rule for every path that admits an address
// (sign-up, the auth.domain gate, OAuth, email change, flow inputs).
func validAuthEmail(s string) bool {
	if s == "" || len(s) > 254 || strings.Count(s, "@") != 1 || !utf8.ValidString(s) {
		return false
	}
	at := strings.IndexByte(s, '@')
	if at == 0 || at == len(s)-1 {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f || strings.ContainsRune(",;<>()[]\\\":|", r) {
			return false
		}
		// C1 controls, Unicode spaces and separators, and format characters
		// (zero-width, bidi overrides): none belongs in an address, and an
		// invisible one makes two different accounts look the same.
		if r >= 0x80 && (unicode.IsControl(r) || unicode.IsSpace(r) || unicode.In(r, unicode.Cf, unicode.Zs, unicode.Zl, unicode.Zp)) {
			return false
		}
	}
	return true
}

// maxPasswordLength is the hard limit on password input length.
// bcrypt silently truncates at 72 bytes - we reject well before that.
const maxPasswordLength = 128

// bcrypt rejects longer inputs when generating a replacement password hash.
const maxBcryptBytes = 72

// validatePasswordComplexity checks password length, uppercase, and special char requirements.
// Returns an error message string, or "" if valid.
func validatePasswordComplexity(password string) string {
	if len(password) > maxPasswordLength {
		return fmt.Sprintf("Password must be at most %d characters", maxPasswordLength)
	}
	if len(password) < 8 {
		return "Password must be at least 8 characters"
	}
	hasUpper := false
	hasSpecial := false
	for _, c := range password {
		if c >= 'A' && c <= 'Z' {
			hasUpper = true
		}
		if (c >= '!' && c <= '/') || (c >= ':' && c <= '@') || (c >= '[' && c <= '`') || (c >= '{' && c <= '~') {
			hasSpecial = true
		}
	}
	if !hasUpper {
		return "Password must contain at least one uppercase letter"
	}
	if !hasSpecial {
		return "Password must contain at least one special character (!@#$%^&*)"
	}
	return ""
}

// generateBcryptHash wraps bcrypt for use by test runner.
// Cost 12 provides ~4x more work than the default cost of 10.
func generateBcryptHash(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, 12)
}

// appLimiterKey scopes a package-level limiter's key to one app. `benmore host`
// serves many tenants from one process, so a key made of an email, an IP or a
// user id alone lets one tenant's traffic spend another tenant's budget.
func appLimiterKey(app *App, kind, subject string) string {
	dir := ""
	if app != nil {
		dir = app.Dir
	}
	return kind + ":" + dir + ":" + subject
}

var (
	unknownAccountHash     []byte
	unknownAccountHashOnce sync.Once
)

// burnPasswordCheck spends one bcrypt comparison for a sign-in whose account
// does not exist. Without it an unknown identifier returned in about a
// millisecond and a known one after the ~250ms comparison, so response time
// told anyone which addresses have accounts - even where signup is closed.
func burnPasswordCheck(password string) {
	unknownAccountHashOnce.Do(func() {
		unknownAccountHash, _ = generateBcryptHash([]byte(generateToken(16)))
	})
	bcrypt.CompareHashAndPassword(unknownAccountHash, []byte(password))
}

func generateToken(bytes int) string {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		log.Printf("crypto/rand error: %v", err)
	}
	return hex.EncodeToString(b)
}

// SecureCompare performs constant-time string comparison.
func SecureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
