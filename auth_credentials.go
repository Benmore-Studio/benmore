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
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// signTempCookie creates an HMAC-signed value for temporary auth cookies (MFA, OTP).
// Prevents cookie forgery - attacker can't create valid cookies without the key.
// Uses full HMAC-SHA256 (64 hex chars) - no truncation.
func signTempCookie(value string) string {
	mac := hmac.New(sha256.New, []byte(serverSecret))
	mac.Write([]byte(value))
	sig := hex.EncodeToString(mac.Sum(nil))
	return value + "|" + sig
}

// verifyTempCookie checks the HMAC signature on a temporary auth cookie.
// Returns the original value (without signature) if valid, empty string if tampered.
func verifyTempCookie(signed string) string {
	lastPipe := strings.LastIndex(signed, "|")
	if lastPipe < 0 {
		return ""
	}
	value := signed[:lastPipe]
	sig := signed[lastPipe+1:]
	mac := hmac.New(sha256.New, []byte(serverSecret))
	mac.Write([]byte(value))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return "" // tampered
	}
	return value
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
