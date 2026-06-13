//go:build !cli

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// roleRequiresMFAEnrollment reports whether `role` appears in the
// `auth.require_mfa_for_roles` list in app.yaml (comma-separated).
// When the role is listed, password authentication alone does not grant
// a session - the user must enroll in MFA before one is issued.
func roleRequiresMFAEnrollment(app *App, role string) bool {
	if app == nil || app.Design == nil || role == "" {
		return false
	}
	raw := strings.TrimSpace(app.Design.Auth["require_mfa_for_roles"])
	if raw == "" {
		return false
	}
	for _, r := range strings.Split(raw, ",") {
		if strings.EqualFold(strings.TrimSpace(r), role) {
			return true
		}
	}
	return false
}

// mfaSetupTokenTTL is the lifetime of an MFA-setup token. Long enough
// to scan a QR + type a code; short enough that a leaked token is
// useless after a single sign-in attempt.
const mfaSetupTokenTTL = 15 * time.Minute

// mintMFASetupToken creates a short-lived HMAC-signed token that
// authorises the bearer to call /api/_auth/mfa/setup + /verify on
// behalf of (userID, email). Issued by the login handlers when the
// caller passed password auth but their role requires enrollment.
// On successful verify the token is exchanged for a real session.
func mintMFASetupToken(userID int64, email string) string {
	exp := time.Now().Add(mfaSetupTokenTTL).Unix()
	return signTempCookie(fmt.Sprintf("mfa-setup|%d|%s|%d", userID, email, exp))
}

// mfaCallerIdentity resolves the caller of an MFA endpoint. Prefers a
// real session; falls back to an MFA-setup token from the
// X-MFA-Setup-Token header or _benmore_mfa_setup cookie. Returns
// fromSetupToken=true when the latter was used, so /verify knows to
// mint a real session on success.
func mfaCallerIdentity(app *App, r *http.Request) (userID int64, email string, fromSetupToken bool, err error) {
	if s := getSession(app, r); s != nil {
		return s.UserID, s.Email, false, nil
	}
	raw := strings.TrimSpace(r.Header.Get("X-MFA-Setup-Token"))
	if raw == "" {
		if c, _ := r.Cookie("_benmore_mfa_setup"); c != nil {
			raw = c.Value
		}
	}
	if raw == "" {
		return 0, "", false, fmt.Errorf("authentication required")
	}
	value := verifyTempCookie(raw)
	if value == "" {
		return 0, "", false, fmt.Errorf("invalid setup token")
	}
	parts := strings.SplitN(value, "|", 4)
	if len(parts) < 4 || parts[0] != "mfa-setup" {
		return 0, "", false, fmt.Errorf("invalid setup token")
	}
	expUnix, perr := strconv.ParseInt(parts[3], 10, 64)
	if perr != nil || time.Now().Unix() > expUnix {
		return 0, "", false, fmt.Errorf("setup token expired")
	}
	uid, perr := strconv.ParseInt(parts[1], 10, 64)
	if perr != nil {
		return 0, "", false, fmt.Errorf("invalid setup token")
	}
	return uid, parts[2], true, nil
}

// MFA/2FA support via TOTP (RFC 6238) + backup codes.
// The runtime provides the mechanism: secret generation, code validation,
// backup codes, and login-time verification. The developer decides whether
// MFA is optional or required, and builds the UI.

// EnsureMFAColumns adds TOTP columns to _benmore_users if missing.
func EnsureMFAColumns(db *sql.DB) {
	for _, col := range []string{"totp_secret TEXT", "backup_codes TEXT", "mfa_last_totp TEXT", "mfa_last_totp_at DATETIME"} {
		name := strings.Fields(col)[0]
		var count int
		db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('_benmore_users') WHERE name=?", name).Scan(&count)
		if count == 0 {
			db.Exec(fmt.Sprintf("ALTER TABLE _benmore_users ADD COLUMN %s", col))
		}
	}
}

// RegisterMFARoutes sets up MFA setup, verification, and disable endpoints.
func RegisterMFARoutes(mux *http.ServeMux, app *App) {
	EnsureMFAColumns(app.DB)

	// POST /api/_auth/mfa/setup - generate TOTP secret + backup codes
	mux.HandleFunc("POST /api/_auth/mfa/setup", func(w http.ResponseWriter, r *http.Request) {
		userID, email, fromSetup, err := mfaCallerIdentity(app, r)
		if err != nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
			return
		}
		// CSRF only protects cookie-session callers. Bearer-auth and the
		// HMAC-signed setup-token path each carry their own integrity proof.
		if !isBearerAuth(r) && !fromSetup && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}
		// Setup tokens are for FIRST enrollment only. If MFA is already
		// active for the user, a stolen token can't be used to reset it -
		// the user must disable from a real session first.
		if fromSetup {
			var existing string
			app.DB.QueryRow("SELECT COALESCE(totp_secret, '') FROM _benmore_users WHERE id = ?", userID).Scan(&existing)
			if existing != "" && !strings.HasPrefix(existing, "pending:") {
				httpJSON(w, http.StatusForbidden, map[string]any{"error": "MFA already enabled - sign in and disable first"})
				return
			}
		}

		// Generate 20-byte secret (160 bits, standard for TOTP)
		secret := make([]byte, 20)
		rand.Read(secret)
		secretB32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)

		// Generate 10 backup codes
		backupCodes := generateBackupCodes(10)
		hashedCodes := make([]string, len(backupCodes))
		for i, code := range backupCodes {
			h, _ := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
			hashedCodes[i] = string(h)
		}
		codesJSON, _ := json.Marshal(hashedCodes)

		// Store secret + hashed backup codes (not yet enabled - user must verify first)
		app.DB.Exec("UPDATE _benmore_users SET totp_secret = ?, backup_codes = ? WHERE id = ?",
			"pending:"+secretB32, string(codesJSON), userID)

		// Build otpauth URI for QR code generation (client-side concern)
		issuer := "App"
		if app.Design != nil {
			if sn, ok := app.Design.SEO["site_name"]; ok && sn != "" {
				issuer = sn
			}
		}
		otpauthURI := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=6&period=30",
			issuer, email, secretB32, issuer)

		httpJSON(w, http.StatusOK, map[string]any{
			"secret":       secretB32,
			"otpauth_uri":  otpauthURI,
			"backup_codes": backupCodes, // shown ONCE, never again
		})
	})

	// POST /api/_auth/mfa/verify - validate a TOTP code to enable MFA.
	// When the caller authenticated via an MFA-setup token (i.e. came
	// from the login flow's enrollment branch), a successful verify
	// also mints a real session and returns it - that's how the
	// password+enrollment-required flow completes in a single request.
	mux.HandleFunc("POST /api/_auth/mfa/verify", func(w http.ResponseWriter, r *http.Request) {
		userID, email, fromSetup, err := mfaCallerIdentity(app, r)
		if err != nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
			return
		}
		if !isBearerAuth(r) && !fromSetup && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}

		var body struct {
			Code string `json:"code"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.Code == "" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "code required"})
			return
		}

		// Get pending secret
		var secretRaw string
		app.DB.QueryRow("SELECT COALESCE(totp_secret, '') FROM _benmore_users WHERE id = ?", userID).Scan(&secretRaw)
		if !strings.HasPrefix(secretRaw, "pending:") {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "MFA setup not started - call /api/_auth/mfa/setup first"})
			return
		}
		secretB32 := strings.TrimPrefix(secretRaw, "pending:")

		if !ValidateTOTP(secretB32, body.Code) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid code"})
			return
		}

		// Enable MFA - remove "pending:" prefix
		app.DB.Exec("UPDATE _benmore_users SET totp_secret = ? WHERE id = ?", secretB32, userID)
		log.Printf("MFA: enabled for user %d (%s)", userID, email)

		if fromSetup {
			// Exchange the setup token for a real session. The caller
			// passed password auth at login and has now enrolled, so
			// they earn the full session here. Mirrors the post-MFA
			// session-creation in handleLogin/handleTokenAuth.
			groupID := ResolveGroupID(app.DB, app.Group, email)
			token := CreateSession(app.DB, userID, email, groupID, app.SessionDuration)
			AttachSessionContext(app.DB, token, r)
			http.SetCookie(w, sessionCookie(token, app.DevMode, app.SessionDuration))
			http.SetCookie(w, &http.Cookie{Name: "_benmore_mfa_setup", Value: "", Path: "/", MaxAge: -1})
			app.DB.Exec("UPDATE _benmore_users SET last_login_at = datetime('now') WHERE id = ?", userID)
			FireUserHooks(app, "update", userID)
			httpJSON(w, http.StatusOK, map[string]any{
				"status":  "mfa_enabled",
				"token":   token,
				"user_id": userID,
				"email":   email,
			})
			return
		}

		httpJSON(w, http.StatusOK, map[string]any{"status": "mfa_enabled"})
	})

	// POST /api/_auth/mfa/disable - turn off MFA (requires current TOTP code)
	mux.HandleFunc("POST /api/_auth/mfa/disable", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}

		var body struct {
			Code string `json:"code"`
		}
		json.NewDecoder(r.Body).Decode(&body)

		var secretB32 string
		app.DB.QueryRow("SELECT COALESCE(totp_secret, '') FROM _benmore_users WHERE id = ?", session.UserID).Scan(&secretB32)
		if secretB32 == "" || strings.HasPrefix(secretB32, "pending:") {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "MFA not enabled"})
			return
		}

		if !ValidateTOTP(secretB32, body.Code) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid code"})
			return
		}

		app.DB.Exec("UPDATE _benmore_users SET totp_secret = NULL, backup_codes = NULL WHERE id = ?", session.UserID)
		log.Printf("MFA: disabled for user %d (%s)", session.UserID, session.Email)

		httpJSON(w, http.StatusOK, map[string]any{"status": "mfa_disabled"})
	})
}

// RegisterMFALoginRoute registers the POST handler for web MFA verification during login.
// After password success, if MFA is enabled, the user is redirected to the MFA page.
// The MFA page's form POSTs here with the TOTP code.
func RegisterMFALoginRoute(mux *http.ServeMux, app *App) {
	mux.HandleFunc(fmt.Sprintf("POST %s", app.Paths.VerifyMFA), func(w http.ResponseWriter, r *http.Request) {
		mergeJSONBodyIntoForm(r)
		code := strings.TrimSpace(r.FormValue("mfa_code"))
		if code == "" {
			code = strings.TrimSpace(r.FormValue("code"))
		}

		// Recover user ID from HMAC-signed temp cookie
		cookie, err := r.Cookie("_benmore_mfa_uid")
		if err != nil || cookie.Value == "" {
			authRedirect(w, r, app.Paths.Login, "Session expired. Please log in again.")
			return
		}
		verified := verifyTempCookie(cookie.Value)
		if verified == "" {
			authRedirect(w, r, app.Paths.Login, "Invalid session. Please log in again.")
			return
		}
		parts := strings.SplitN(verified, "|", 2)
		if len(parts) != 2 {
			authRedirect(w, r, app.Paths.Login, "Invalid session. Please log in again.")
			return
		}
		var userID int64
		fmt.Sscanf(parts[0], "%d", &userID)
		email := parts[1]

		if userID == 0 {
			authRedirect(w, r, app.Paths.Login, "Invalid session. Please log in again.")
			return
		}

		if code == "" {
			authRedirect(w, r, app.Paths.VerifyMFA, "MFA code is required")
			return
		}

		// Brute-force lockout - 5 fails / 15 min on the MFA step,
		// keyed separately from the password-login counter so a user
		// who fails MFA doesn't have their password counter ratcheted.
		mfaKey := mfaLockKey(userID)
		if isAccountLocked(app.DB, mfaKey) {
			authRedirect(w, r, app.Paths.VerifyMFA, "Too many MFA attempts. Try again in 15 minutes.")
			return
		}

		if !ValidateMFACode(app.DB, userID, code) {
			recordLoginAttempt(app.DB, mfaKey, false)
			authRedirect(w, r, app.Paths.VerifyMFA, "Invalid MFA code")
			return
		}
		recordLoginAttempt(app.DB, mfaKey, true)

		// Clear MFA cookie
		http.SetCookie(w, &http.Cookie{Name: "_benmore_mfa_uid", Value: "", Path: "/", MaxAge: -1})

		// Update last_login_at
		app.DB.Exec("UPDATE _benmore_users SET last_login_at = datetime('now') WHERE id = ?", userID)
		FireUserHooks(app, "update", userID)

		// Create session
		groupID := ResolveGroupID(app.DB, app.Group, email)
		sessionID := CreateSession(app.DB, userID, email, groupID, app.SessionDuration)
		http.SetCookie(w, sessionCookie(sessionID, app.DevMode, app.SessionDuration))

		redirectTo := "/"
		if app.Design != nil {
			if rd := app.Design.Auth["redirect"]; rd != "" {
				redirectTo = rd
			}
		}
		http.Redirect(w, r, redirectTo, http.StatusSeeOther)
	})
}

// CheckMFA returns true if the user has MFA enabled (active secret, not pending).
func CheckMFA(db *sql.DB, userID int64) bool {
	var secret string
	db.QueryRow("SELECT COALESCE(totp_secret, '') FROM _benmore_users WHERE id = ?", userID).Scan(&secret)
	return secret != "" && !strings.HasPrefix(secret, "pending:")
}

// mfaLockKey is the _benmore_login_attempts key used for MFA brute-force
// tracking. Separate from the password-login key so a user who failed
// the MFA step doesn't have their password-login counter inflated.
func mfaLockKey(userID int64) string {
	return fmt.Sprintf("mfa:%d", userID)
}

// ValidateMFACode checks a TOTP code OR a backup code for a user.
// Returns true if valid. Backup codes are single-use - consumed on success.
//
// Brute-force protection: callers should check isAccountLocked(db,
// mfaLockKey(userID)) before invoking, and recordLoginAttempt with the
// same key after. The two MFA entry points (web form + API token) both
// do this - see RegisterMFALoginRoute and the JSON token handler.
//
// Replay protection: TOTP codes accepted within the validity window
// are remembered for ~90 seconds via `mfa_last_totp_at` / `mfa_last_totp`.
// The same 6-digit code can't be replayed across two login attempts.
func ValidateMFACode(db *sql.DB, userID int64, code string) bool {
	var secretB32, backupJSON, lastTOTP, lastTOTPAtStr string
	db.QueryRow(`SELECT COALESCE(totp_secret, ''), COALESCE(backup_codes, '[]'),
		COALESCE(mfa_last_totp, ''), COALESCE(mfa_last_totp_at, '')
		FROM _benmore_users WHERE id = ?`, userID).
		Scan(&secretB32, &backupJSON, &lastTOTP, &lastTOTPAtStr)

	// Try TOTP first
	if secretB32 != "" && ValidateTOTP(secretB32, code) {
		// Replay check: same code accepted in the last 90s? Reject.
		if lastTOTP == code && lastTOTPAtStr != "" {
			if ts, err := time.Parse(time.RFC3339, lastTOTPAtStr); err == nil {
				if time.Since(ts) < 90*time.Second {
					return false
				}
			}
		}
		db.Exec(`UPDATE _benmore_users SET mfa_last_totp = ?, mfa_last_totp_at = ? WHERE id = ?`,
			code, time.Now().UTC().Format(time.RFC3339), userID)
		return true
	}

	// Try backup codes. Atomic compare-and-swap on the JSON column
	// closes the TOCTOU window where two concurrent submissions of the
	// same code could both pass bcrypt before either consumes it.
	var hashedCodes []string
	json.Unmarshal([]byte(backupJSON), &hashedCodes)
	for i, hashed := range hashedCodes {
		if bcrypt.CompareHashAndPassword([]byte(hashed), []byte(code)) == nil {
			remaining := make([]string, 0, len(hashedCodes)-1)
			remaining = append(remaining, hashedCodes[:i]...)
			remaining = append(remaining, hashedCodes[i+1:]...)
			updated, _ := json.Marshal(remaining)
			res, err := db.Exec(
				"UPDATE _benmore_users SET backup_codes = ? WHERE id = ? AND backup_codes = ?",
				string(updated), userID, backupJSON,
			)
			if err != nil {
				return false
			}
			n, _ := res.RowsAffected()
			if n != 1 {
				// Another request consumed this code first. Reject.
				return false
			}
			log.Printf("MFA: backup code used for user %d (%d remaining)", userID, len(remaining))
			return true
		}
	}

	return false
}

// ===== TOTP Implementation (RFC 6238) =====

// GenerateTOTP computes a 6-digit TOTP code for the current time window.
func GenerateTOTP(secretB32 string) string {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		return ""
	}
	counter := uint64(time.Now().Unix() / 30)
	return computeHOTP(secret, counter)
}

// ValidateTOTP checks a code against the current and adjacent time windows
// (±1 window = ±30 seconds) to handle clock drift.
func ValidateTOTP(secretB32, code string) bool {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		return false
	}
	counter := uint64(time.Now().Unix() / 30)
	// Check current window and ±1 for clock drift tolerance
	for _, offset := range []uint64{0, 1, math.MaxUint64} { // MaxUint64 wraps to -1
		expected := computeHOTP(secret, counter+offset)
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// computeHOTP implements HOTP (RFC 4226) - the core of TOTP.
func computeHOTP(secret []byte, counter uint64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, secret)
	mac.Write(buf)
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0x0f
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	return fmt.Sprintf("%06d", code%1000000)
}

// generateBackupCodes creates N random 8-character alphanumeric codes.
func generateBackupCodes(n int) []string {
	const charset = "abcdefghjkmnpqrstuvwxyz23456789" // no ambiguous chars (0/O, 1/l/I)
	codes := make([]string, n)
	for i := 0; i < n; i++ {
		b := make([]byte, 8)
		rand.Read(b)
		code := make([]byte, 8)
		for j := range code {
			code[j] = charset[b[j]%byte(len(charset))]
		}
		codes[i] = string(code)
	}
	return codes
}
