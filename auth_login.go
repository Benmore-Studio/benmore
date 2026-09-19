//go:build !cli

package main

// Interactive login, signup, OTP verification, logout, and group switching.

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func handleSwitchGroup(w http.ResponseWriter, r *http.Request, app *App) {
	mergeJSONBodyIntoForm(r)
	session := getSession(app, r)
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	newGroupID := r.FormValue("group_id")
	if newGroupID == "" {
		http.Error(w, "group_id required", http.StatusBadRequest)
		return
	}
	// Platform admins can switch to any org; others must belong to the org
	if !session.IsAdmin() {
		var count int
		query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s = ? AND %s = ?",
			app.Group.Table, app.Group.Key, app.Group.UserField)
		var lookupVal any
		if app.Group.UserField == "email" {
			lookupVal = session.Email
		} else {
			lookupVal = session.UserID
		}
		app.DB.QueryRow(query, newGroupID, lookupVal).Scan(&count)
		if count == 0 {
			http.Error(w, "Not a member of this organization", http.StatusForbidden)
			return
		}
	}
	// Update session org_id
	app.DB.Exec("UPDATE _benmore_sessions SET group_id = ? WHERE id = ?", newGroupID, session.ID)
	referer := r.Header.Get("Referer")
	if referer == "" {
		referer = "/"
	}
	http.Redirect(w, r, referer, http.StatusSeeOther)
}

// authIdentifier returns the configured login field: "email" (default), "username", or "phone".
func authIdentifier(app *App) string {
	if app.Design != nil {
		if id := app.Design.Auth["identifier"]; id == "username" || id == "phone" {
			return id
		}
	}
	return "email"
}

func handleLogin(w http.ResponseWriter, r *http.Request, app *App) {
	// OAuth-only mode (app.yaml auth.oauth_only): refuse password login.
	if oauthOnly(app) {
		authRedirect(w, r, app.Paths.Login, "Please sign in with Google.")
		return
	}
	// SPA / TSX clients post application/json; native HTML forms post
	// application/x-www-form-urlencoded. Shim JSON into the form layer
	// so r.FormValue works for both shapes.
	mergeJSONBodyIntoForm(r)

	// CSRF validation - prevent cross-site login attacks
	if !validateCSRF(r) {
		authRedirect(w, r, app.Paths.Login, "Invalid request")
		return
	}

	identifier := authIdentifier(app)
	// Accept the identifier from form field "email" (legacy) or the configured field name
	loginValue := strings.TrimSpace(r.FormValue("email"))
	if loginValue == "" {
		loginValue = strings.TrimSpace(r.FormValue(identifier))
	}
	if identifier == "email" {
		loginValue = normalizeEmail(loginValue)
	}
	password := r.FormValue("password")

	if loginValue == "" || password == "" {
		authRedirect(w, r, app.Paths.Login, "Credentials are required")
		return
	}
	if len(password) > maxPasswordLength {
		authRedirect(w, r, app.Paths.Login, "Invalid credentials")
		return
	}

	// Domain + allowlist restriction (only applies when identifier is
	// email). Multi-domain + exception-aware via emailAllowedForApp.
	if identifier == "email" {
		if ok, reason := emailAllowedForApp(app, loginValue); !ok {
			authRedirect(w, r, app.Paths.Login, reason)
			return
		}
	}

	// Brute force check (per-account). Stops a focused attack on one user.
	if isAccountLocked(app.DB, loginValue) {
		authRedirect(w, r, app.Paths.Login, "Too many failed attempts. Try again in 15 minutes.")
		return
	}
	// Per-IP cap (LOWER): the per-account lock above is trivially evaded by
	// a spray attack that rotates the username every request. Throttle the
	// source IP too. clientIP honors trusted forwarded headers only when
	// configured (see platform_shims.clientIP).
	loginIP := clientIP(r)
	if authIsIPLocked(app.DB, loginIP) {
		authRedirect(w, r, app.Paths.Login, "Too many failed attempts from this network. Try again in 15 minutes.")
		return
	}

	var id int64
	var hash string
	var email string
	// Look up user by configured identifier, also fetch email for session
	// creation. Email matches case-insensitively so legacy rows stored with
	// uppercase (pre-normalization) keep working.
	query := fmt.Sprintf("SELECT id, password_hash, COALESCE(email, '') FROM _benmore_users WHERE %s = ?", identifier)
	if identifier == "email" {
		query += " COLLATE NOCASE"
	}
	err := app.DB.QueryRow(query, loginValue).Scan(&id, &hash, &email)
	if err != nil {
		recordLoginAttempt(app.DB, loginValue, false)
		recordLoginAttempt(app.DB, authIPLockKey(loginIP), false) // per-IP counter (LOWER)
		authRedirect(w, r, app.Paths.Login, "Invalid credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		recordLoginAttempt(app.DB, loginValue, false)
		recordLoginAttempt(app.DB, authIPLockKey(loginIP), false) // per-IP counter (LOWER)
		authRedirect(w, r, app.Paths.Login, "Invalid credentials")
		return
	}

	// Success
	recordLoginAttempt(app.DB, loginValue, true)

	// MFA check: if user has TOTP enabled, require code before creating session
	if CheckMFA(app.DB, id) {
		mfaCode := strings.TrimSpace(r.FormValue("mfa_code"))
		if mfaCode == "" {
			// Redirect to MFA verification page
			http.SetCookie(w, &http.Cookie{
				Name: "_benmore_mfa_uid", Value: signTempCookie(fmt.Sprintf("%d|%s", id, email)),
				Path: "/", HttpOnly: true, Secure: !app.DevMode,
				SameSite: http.SameSiteLaxMode, MaxAge: 300,
			})
			http.Redirect(w, r, app.Paths.VerifyMFA, http.StatusSeeOther)
			return
		}
		mfaKey := mfaLockKey(id)
		if isAccountLocked(app.DB, mfaKey) {
			authRedirect(w, r, app.Paths.Login, "Too many MFA attempts. Try again in 15 minutes.")
			return
		}
		if !ValidateMFACode(app.DB, id, mfaCode) {
			recordLoginAttempt(app.DB, mfaKey, false)
			authRedirect(w, r, app.Paths.Login, "Invalid MFA code")
			return
		}
		recordLoginAttempt(app.DB, mfaKey, true)
	} else {
		// MFA not enrolled. If the user's role appears in
		// `auth.require_mfa_for_roles`, redirect to the enrollment
		// page instead of issuing a session. The setup-token cookie
		// authorises /api/_auth/mfa/setup + /verify on this user's
		// behalf; verify mints the real session on successful enroll.
		var role string
		app.DB.QueryRow("SELECT COALESCE(role, '') FROM _benmore_users WHERE id = ?", id).Scan(&role)
		if roleRequiresMFAEnrollment(app, role) {
			http.SetCookie(w, &http.Cookie{
				Name: "_benmore_mfa_setup", Value: mintMFASetupToken(id, email),
				Path: "/", HttpOnly: true, Secure: !app.DevMode,
				SameSite: http.SameSiteLaxMode, MaxAge: int(mfaSetupTokenTTL.Seconds()),
			})
			redirect := "/mfa-setup"
			if app.Design != nil {
				if v := strings.TrimSpace(app.Design.Auth["mfa_setup_redirect"]); v != "" {
					redirect = v
				}
			}
			http.Redirect(w, r, redirect, http.StatusSeeOther)
			return
		}
	}

	// Update last_login_at and fire user hooks (on_update: _benmore_users)
	app.DB.Exec("UPDATE _benmore_users SET last_login_at = datetime('now') WHERE id = ?", id)
	FireUserHooks(app, "update", id)

	// Dashboard login → heal platform_users with the verified hash so
	// existing accounts that pre-date the sync hook get auto-fixed on
	// next login. No-op for every app other than _platform.
	syncPlatformUserFromDashboard(app, email, hash)

	// OTP check: if auth_otp is set, send a code before creating session
	// Supports email OTP and phone OTP (SMS) depending on identifier config
	if app.Design != nil && app.Design.Auth["otp"] == "true" {
		code := generateOTP()
		app.DB.Exec("CREATE TABLE IF NOT EXISTS _benmore_otp (email TEXT, code TEXT, attempts INTEGER DEFAULT 0, expires_at DATETIME)")
		app.DB.Exec("DELETE FROM _benmore_otp WHERE email = ?", loginValue)
		app.DB.Exec("INSERT INTO _benmore_otp (email, code, attempts, expires_at) VALUES (?, ?, 0, datetime('now', '+10 minutes'))", loginValue, code)

		// Send OTP via SMS or email depending on identifier
		if identifier == "phone" {
			// Look up phone number
			var phone string
			app.DB.QueryRow("SELECT COALESCE(phone, '') FROM _benmore_users WHERE id = ?", id).Scan(&phone)
			if phone != "" {
				if err := SendSMS(app.Dir, phone, fmt.Sprintf("Your verification code: %s", code)); err != nil {
					log.Printf("auth: SMS send failed for verification code (phone=%s): %v", phone, err)
				}
			}
		} else {
			// Send via email (default) - branded shell + logo via the
			// shared template helper so OTP emails match every other
			// transactional email from this app.
			brand := AppEmailBrand(app, r)
			siteName := brand.SiteName
			body := RenderBrandedCodeEmail(
				brand,
				"Your verification code",
				fmt.Sprintf("Enter this code to finish signing in to %s. It expires in 10 minutes.", html.EscapeString(siteName)),
				code,
				"If you didn't try to sign in, you can ignore this email - your account is safe.",
			)
			if err := SendEmail(app.Dir, email, "Your verification code · "+siteName, body); err != nil {
				log.Printf("auth: email send failed for verification code (to=%s): %v", email, err)
			}
		}

		// Store user ID + the OTP lookup key in a temp cookie for the OTP
		// page. H-12: the OTP row was INSERTed under loginValue (the
		// normalized identifier - username/phone/email), but verify used
		// to look it up by email, so non-email identifiers never matched
		// and those users were locked out. Carry the exact send-time key
		// (loginValue) through the signed cookie so verify keys on the
		// SAME value. Format is id|email|otpkey; the 2-part legacy form
		// still parses (verify falls back to email as the key).
		http.SetCookie(w, &http.Cookie{Name: "_benmore_otp_uid", Value: signTempCookie(fmt.Sprintf("%d|%s|%s", id, email, loginValue)), Path: "/", HttpOnly: true, Secure: !app.DevMode, SameSite: http.SameSiteLaxMode, MaxAge: 600})
		sendOTPChallenge(w, r, app)
		return
	}

	groupID := ResolveGroupID(app.DB, app.Group, email)
	sessionID := CreateSession(app.DB, id, email, groupID, app.SessionDuration)

	AttachSessionContext(app.DB, sessionID, r)
	http.SetCookie(w, sessionCookie(sessionID, app.DevMode, app.SessionDuration))

	// SPA / API client wanted JSON - give it the user object. Cookie
	// is set above; the client just refreshes its useAuth state.
	if authSuccessJSON(w, r, app, id) {
		return
	}

	redirectTo := "/"
	if app.Design != nil {
		if rd := app.Design.Auth["redirect"]; rd != "" {
			redirectTo = rd
		}
	}
	// Support ?next= param to redirect back after login (e.g. from protected pages)
	if next := r.FormValue("next"); isSafeNext(next) {
		redirectTo = next
	}
	http.Redirect(w, r, redirectTo, http.StatusSeeOther)
}

func generateOTP() string {
	b := make([]byte, 3)
	rand.Read(b)
	n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	return fmt.Sprintf("%06d", n%1000000)
}

// sendOTPChallenge routes the caller to the OTP verification step after a code
// has been emailed/SMS'd + the _benmore_otp_uid cookie set. A JSON client (the
// benmore.ai auth modal sends Content-Type: application/json) gets a structured
// {otp_required, redirect} so it can navigate to the native /verify-otp page;
// a normal browser form submit gets a 303 to the same page.
func sendOTPChallenge(w http.ResponseWriter, r *http.Request, app *App) {
	// Preserve the post-auth destination across the OTP step. handleVerifyOTP
	// honors `next` on the verify POST, but only if the verify page receives
	// it to echo back as a hidden field - without this, a flow like
	// /cli-auth → /signup?next=/auth/cli-session?port=N dead-ends at the
	// default redirect and the waiting CLI never gets its token.
	target := app.Paths.VerifyOTP
	if next := r.FormValue("next"); isSafeNext(next) {
		target += "?next=" + url.QueryEscape(next)
	}
	if wantsJSON(r) {
		httpJSON(w, http.StatusOK, map[string]any{"ok": true, "otp_required": true, "redirect": target})
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func handleVerifyOTP(w http.ResponseWriter, r *http.Request, app *App) {
	mergeJSONBodyIntoForm(r)
	code := strings.TrimSpace(r.FormValue("code"))

	// Keep `next` attached to every bounce back to the verify page so a
	// mistyped code doesn't drop the post-auth destination mid-flow.
	otpPath := app.Paths.VerifyOTP
	if next := r.FormValue("next"); isSafeNext(next) {
		otpPath += "?next=" + url.QueryEscape(next)
	}

	cookie, err := r.Cookie("_benmore_otp_uid")
	if err != nil || cookie.Value == "" {
		authRedirect(w, r, otpPath, "Session expired. Please log in again.")
		return
	}

	// Verify cookie signature (prevents forgery)
	verified := verifyTempCookie(cookie.Value)
	if verified == "" {
		authRedirect(w, r, otpPath, "Invalid session. Please log in again.")
		return
	}
	// Cookie payload is id|email|otpkey (H-12). The 3rd field is the exact
	// key the OTP row was stored under at send time (the normalized
	// identifier - which for username/phone identifiers is NOT the email).
	// Older cookies are 2-part (id|email); for those we fall back to email
	// as the lookup key, matching the pre-fix behavior for email apps.
	parts := strings.SplitN(verified, "|", 3)
	if len(parts) < 2 {
		authRedirect(w, r, otpPath, "Invalid session. Please log in again.")
		return
	}
	uidStr, email := parts[0], parts[1]
	otpKey := email
	if len(parts) == 3 && parts[2] != "" {
		otpKey = parts[2]
	}

	// Verify OTP with attempt limiting. Keyed on otpKey so it matches the
	// value the row was INSERTed under on send (H-12).
	var storedCode string
	var attempts int
	err = app.DB.QueryRow("SELECT code, attempts FROM _benmore_otp WHERE email = ? AND datetime(expires_at) > datetime('now')", otpKey).Scan(&storedCode, &attempts)
	if err != nil {
		authRedirect(w, r, otpPath, "Code expired. Please log in again.")
		return
	}

	if attempts >= 5 {
		app.DB.Exec("DELETE FROM _benmore_otp WHERE email = ?", otpKey)
		authRedirect(w, r, otpPath, "Too many attempts. Please log in again.")
		return
	}

	if !SecureCompare(code, storedCode) {
		app.DB.Exec("UPDATE _benmore_otp SET attempts = attempts + 1 WHERE email = ?", otpKey)
		authRedirect(w, r, otpPath, fmt.Sprintf("Invalid code. %d attempts remaining.", 4-attempts))
		return
	}

	// OTP valid - clean up and create session
	app.DB.Exec("DELETE FROM _benmore_otp WHERE email = ?", otpKey)
	http.SetCookie(w, &http.Cookie{Name: "_benmore_otp_uid", Path: "/", MaxAge: -1})

	var id int64
	fmt.Sscanf(uidStr, "%d", &id)

	groupID := ResolveGroupID(app.DB, app.Group, email)
	sessionID := CreateSession(app.DB, id, email, groupID, app.SessionDuration)

	AttachSessionContext(app.DB, sessionID, r)
	http.SetCookie(w, sessionCookie(sessionID, app.DevMode, app.SessionDuration))

	// Redirect to dashboard if exists
	redirectTo := "/"
	if app.Design != nil {
		if rd := app.Design.Auth["redirect"]; rd != "" {
			redirectTo = rd
		}
	}
	// Support ?next= param to redirect back after login (e.g. from protected pages)
	if next := r.FormValue("next"); isSafeNext(next) {
		redirectTo = next
	}
	http.Redirect(w, r, redirectTo, http.StatusSeeOther)
}

// emailAllowedForApp enforces the app.yaml `auth.domain` + `auth.allow_emails`
// access gate. Returns (allowed, reason).
//
//   - auth.domain: comma-separated list of allowed email domains
//     ("example.com,example.org"). Empty → no domain restriction
//     (every email allowed). A single value still works as before.
//   - auth.allow_emails: comma-separated exception allowlist of exact
//     addresses that bypass the domain check ("founder@gmail.com").
//     Useful for personal accounts that should keep access on an
//     otherwise domain-locked platform.
//
// Matching is case-insensitive on both sides. Enforced identically on
// signup, login, AND the OAuth callback so no path bypasses the gate.
func emailAllowedForApp(app *App, email string) (bool, string) {
	if app == nil || app.Design == nil {
		return true, ""
	}
	return emailMatchesGate(email,
		app.Design.Auth["domain"], app.Design.Auth["allow_emails"])
}

// oauthOnly reports whether app.yaml set `auth.oauth_only: true` - social
// login is the ONLY path; password login + signup are refused. App-agnostic.
func oauthOnly(app *App) bool {
	if app == nil || app.Design == nil {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(app.Design.Auth["oauth_only"]))
	return v == "true" || v == "1" || v == "yes"
}

// emailMatchesGate is the pure matching core shared by the app-level gate
// (emailAllowedForApp, driven by app.yaml) and the platform-engine signup
// gate (platformSignupAllowed, driven by env vars). It keeps the two layers
// byte-identical in behavior so there's no drift between "who can sign up to
// an app" and "who can create a platform account from the CLI".
//
//   - domainRaw: comma-separated allowed email domains ("a.com,b.org").
//   - allowRaw: comma-separated EXACT allowed addresses ("founder@gmail.com").
//
// Three modes, by which of the two are set:
//   - both empty  → OPEN (no restriction). The caller's default.
//   - domain set  → domain-locked; allowRaw addresses are exact-match
//     exceptions that bypass the domain check.
//   - domain empty, allow set → CLOSED exact-allowlist: ONLY the addresses in
//     allowRaw are permitted, nobody else (used for the closed-access phase -
//     even same-domain addresses that aren't listed are rejected).
//
// Case-insensitive on both sides.
func emailMatchesGate(email, domainRaw, allowRaw string) (bool, string) {
	domainRaw = strings.TrimSpace(domainRaw)
	allowRaw = strings.TrimSpace(allowRaw)
	if domainRaw == "" && allowRaw == "" {
		return true, "" // no restriction configured
	}
	email = strings.ToLower(strings.TrimSpace(email))

	// Exact-address allowlist - bypasses the domain check (domain mode) AND is
	// the sole gate in closed exact-allowlist mode.
	if allowRaw != "" {
		for _, a := range strings.Split(allowRaw, ",") {
			if a = strings.ToLower(strings.TrimSpace(a)); a != "" && a == email {
				return true, ""
			}
		}
	}

	// Closed exact-allowlist mode: no domain configured, so a non-listed
	// address (regardless of its domain) is rejected.
	if domainRaw == "" {
		return false, "Access is restricted to approved accounts."
	}

	// Domain check - any one of the comma-separated domains matches.
	var domains []string
	for _, d := range strings.Split(domainRaw, ",") {
		if d = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(d, "@"))); d != "" {
			domains = append(domains, d)
			if strings.HasSuffix(email, "@"+d) {
				return true, ""
			}
		}
	}
	return false, "Only @" + strings.Join(domains, " / @") + " emails are allowed"
}

func handleSignup(w http.ResponseWriter, r *http.Request, app *App) {
	// OAuth-only mode (app.yaml auth.oauth_only): no password signup.
	if oauthOnly(app) {
		authRedirect(w, r, app.Paths.Signup, "Please sign up with Google.")
		return
	}
	// SPA / TSX clients post application/json; native HTML forms post
	// application/x-www-form-urlencoded. Shim JSON into the form layer
	// so r.FormValue works for both shapes - including signup_fields
	// like first_name, last_name, etc.
	mergeJSONBodyIntoForm(r)

	// CSRF validation - prevent cross-site signup attacks
	if !validateCSRF(r) {
		authRedirect(w, r, app.Paths.Signup, "Invalid request")
		return
	}

	email := normalizeEmail(r.FormValue("email"))
	password := r.FormValue("password")

	if email == "" || password == "" {
		authRedirect(w, r, app.Paths.Signup, "Email and password are required")
		return
	}
	// Reject pipe / control chars in the identifier (round-2 #M). The signed
	// OTP / MFA-setup / signed-URL cookies are `|`-delimited over this value;
	// a `|` (or CR/LF/NUL) would shift the field boundaries and let a crafted
	// identifier desync the parsed fields from what was signed.
	if strings.ContainsAny(email, "|\r\n\x00") {
		authRedirect(w, r, app.Paths.Signup, "Invalid email")
		return
	}

	// Brute force protection on signup
	if isAccountLocked(app.DB, email) {
		authRedirect(w, r, app.Paths.Signup, "Too many attempts. Try again in 15 minutes.")
		return
	}

	// Domain + allowlist restriction from app.yaml (auth.domain /
	// auth.allow_emails). Multi-domain + exception-aware.
	if ok, reason := emailAllowedForApp(app, email); !ok {
		authRedirect(w, r, app.Paths.Signup, reason)
		return
	}

	if msg := validatePasswordComplexity(password); msg != "" {
		authRedirect(w, r, app.Paths.Signup, msg)
		return
	}

	hash, err := generateBcryptHash([]byte(password))
	if err != nil {
		authRedirect(w, r, app.Paths.Signup, "Server error")
		return
	}

	username := GenerateUniqueUsername(app.DB, strings.Split(email, "@")[0], 0)

	// Build INSERT with base fields + any configured signup_fields
	fields := []string{"username", "email", "password_hash"}
	placeholders := []string{"?", "?", "?"}
	values := []any{username, email, string(hash)}

	if app.Design != nil {
		if sf := app.Design.Auth["signup_fields"]; sf != "" {
			for _, field := range strings.Split(sf, ",") {
				field = strings.TrimSpace(field)
				if field == "" || field == "email" || field == "password" || field == "password_hash" || field == "username" || field == "password_change_required" {
					continue
				}
				val := strings.TrimSpace(r.FormValue(field))
				if val != "" {
					fields = append(fields, field)
					placeholders = append(placeholders, "?")
					values = append(values, val)
				}
			}
		}
	}

	insertSQL := fmt.Sprintf("INSERT INTO _benmore_users (%s) VALUES (%s)",
		strings.Join(fields, ", "), strings.Join(placeholders, ", "))
	result, err := app.DB.Exec(insertSQL, values...)
	if err != nil {
		recordLoginAttempt(app.DB, email, false)
		if strings.Contains(err.Error(), "UNIQUE") {
			authRedirect(w, r, app.Paths.Signup, "An account with that email already exists")
			return
		}
		authRedirect(w, r, app.Paths.Signup, "Server error")
		return
	}
	recordLoginAttempt(app.DB, email, true)

	id, _ := result.LastInsertId()

	// Fire user hooks (on_insert: _benmore_users)
	FireUserHooks(app, "insert", id)

	// Dashboard signup → also seed platform_users with the same hash.
	// No-op for every app other than _platform.
	syncPlatformUserFromDashboard(app, email, string(hash))

	// Activate any pending invites for this email (app-level user_roles table)
	app.DB.Exec("UPDATE user_roles SET user_id = ?, is_active = 1, invite_accepted_at = datetime('now') WHERE email = ? AND user_id IS NULL AND is_active = 0", id, email)

	// Email verification (opt-in via auth.verify_email in app.yaml).
	//
	// SECURITY NOTE (LOWER): sending the verification email is DECORATIVE
	// on its own. This handler proceeds to mint a full session below even
	// when verify_email is set - the unverified user is logged in
	// immediately. Actual ENFORCEMENT is gated by a SEPARATE config key,
	// auth.require_verified: when that is "true", getSession() refuses to
	// resolve any session whose user row is not verified (see getSession,
	// "require_verified" branch), so the session minted here is inert until
	// the user clicks the link. So:
	//   - verify_email=true alone  → email sent, but login works unverified
	//   - require_verified=true    → unverified sessions are rejected at
	//                                every request until verified
	// Apps that need a hard gate MUST set require_verified. We intentionally
	// keep issuing the session here (back-compat: many apps rely on
	// immediate login + a soft "please verify" banner) and rely on the
	// request-time check rather than withholding the session at signup.
	needsVerification := app.Design != nil && app.Design.Auth["verify_email"] == "true"
	if needsVerification {
		token := generateToken(32)
		expires := time.Now().Add(1 * time.Hour)
		app.DB.Exec("INSERT INTO _benmore_password_resets (token, email, expires_at, type) VALUES (?, ?, ?, 'verify')",
			hashResetToken(token), email, expires.UTC().Format(time.RFC3339))

		verifyURL := fmt.Sprintf("%s/verify-email?token=%s", securityLinkBaseURL(app, r), token)

		siteName := "App"
		if sn, ok := app.Design.SEO["site_name"]; ok && sn != "" {
			siteName = sn
		}

		body := fmt.Sprintf(`<h2>Verify your email</h2>
<p>Thanks for signing up for %s! Click below to verify your email address.</p>
<p><a href="%s">Verify Email</a></p>`, html.EscapeString(siteName), verifyURL)

		if err := SendEmail(app.Dir, email, "Verify your email - "+siteName, body); err != nil {
			log.Printf("auth: signup verification email failed (to=%s): %v", email, err)
		}
	}

	// Email 2FA: when auth.otp is on, verify the new account's email with a
	// 6-digit code BEFORE issuing a session. Google/OAuth signups go through
	// the OAuth callback, not here, so they're exempt by construction. The
	// account row already exists; the session is only minted once the code is
	// confirmed on /verify-otp (same flow login uses).
	if app.Design != nil && app.Design.Auth["otp"] == "true" {
		code := generateOTP()
		app.DB.Exec("CREATE TABLE IF NOT EXISTS _benmore_otp (email TEXT, code TEXT, attempts INTEGER DEFAULT 0, expires_at DATETIME)")
		app.DB.Exec("DELETE FROM _benmore_otp WHERE email = ?", email)
		app.DB.Exec("INSERT INTO _benmore_otp (email, code, attempts, expires_at) VALUES (?, ?, 0, datetime('now', '+10 minutes'))", email, code)
		brand := AppEmailBrand(app, r)
		body := RenderBrandedCodeEmail(
			brand,
			"Your verification code",
			fmt.Sprintf("Enter this code to finish creating your %s account. It expires in 10 minutes.", html.EscapeString(brand.SiteName)),
			code,
			"If you didn't sign up, you can ignore this email.",
		)
		if err := SendEmail(app.Dir, email, "Your verification code · "+brand.SiteName, body); err != nil {
			log.Printf("auth: signup OTP email failed (to=%s): %v", email, err)
		}
		// H-12: signup keys the OTP row on email, so the cookie's OTP key
		// is email too. Carry it explicitly (id|email|otpkey) so the
		// verify handler uses the identical key on lookup.
		http.SetCookie(w, &http.Cookie{Name: "_benmore_otp_uid", Value: signTempCookie(fmt.Sprintf("%d|%s|%s", id, email, email)), Path: "/", HttpOnly: true, Secure: !app.DevMode, SameSite: http.SameSiteLaxMode, MaxAge: 600})
		sendOTPChallenge(w, r, app)
		return
	}

	groupID := ResolveGroupID(app.DB, app.Group, email)
	sessionID := CreateSession(app.DB, id, email, groupID, app.SessionDuration)

	AttachSessionContext(app.DB, sessionID, r)

	http.SetCookie(w, sessionCookie(sessionID, app.DevMode, app.SessionDuration))

	// SPA / API client wanted JSON - return the user object instead
	// of redirecting (the SPA has no /signup or / page to navigate to
	// at the server level; it owns the auth UI client-side).
	if authSuccessJSON(w, r, app, id) {
		return
	}

	// Redirect: check signup_redirect first, then redirect, then /
	redirectTo := "/"
	if app.Design != nil {
		if sr := app.Design.Auth["signup_redirect"]; sr != "" {
			redirectTo = sr
		} else if rd := app.Design.Auth["redirect"]; rd != "" {
			redirectTo = rd
		}
	}
	http.Redirect(w, r, redirectTo, http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request, app *App) {
	if !isBearerAuth(r) && !validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		DeleteSessionFromDB(app.DB, cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   !app.DevMode,
	})
	if wantsJSON(r) {
		httpJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
}

// handleTokenAuth exchanges email+password for a Bearer token (for native/API clients).
// POST /api/_auth/token with JSON body: {"email": "...", "password": "..."}
// Returns: {"token": "...", "user_id": N, "email": "..."}
func handleTokenAuth(w http.ResponseWriter, r *http.Request, app *App) {
	// OAuth-only mode (app.yaml auth.oauth_only): the email+password →
	// Bearer exchange is a password sign-in path, so it must be refused
	// too - otherwise oauth_only would close the interactive login/signup
	// but leave this API path open as a silent password bypass.
	if oauthOnly(app) {
		http.Error(w, `{"error":"password auth is disabled - this app uses social sign-in only"}`, http.StatusForbidden)
		return
	}
	if !tokenAuthIPLimiter.Allow("token:" + clientIP(r)) {
		http.Error(w, `{"error":"rate limited"}`, http.StatusTooManyRequests)
		return
	}
	var body struct {
		Email    string `json:"email"` // also accepts username/phone depending on auth.identifier
		Password string `json:"password"`
		Scopes   string `json:"scopes"`   // optional: "contacts:read deals:write"
		MFACode  string `json:"mfa_code"` // required if user has MFA enabled
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	if body.Email == "" || body.Password == "" {
		http.Error(w, `{"error":"email and password required"}`, http.StatusBadRequest)
		return
	}
	if len(body.Password) > maxPasswordLength {
		http.Error(w, `{"error":"password too long"}`, http.StatusBadRequest)
		return
	}
	if authIdentifier(app) == "email" {
		body.Email = normalizeEmail(body.Email)
	}

	// Validate scopes if provided
	if body.Scopes != "" {
		if err := validateScopes(body.Scopes); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
			return
		}
	}

	// Check brute force lockout
	if isAccountLocked(app.DB, body.Email) {
		http.Error(w, `{"error":"too many attempts, try again later"}`, http.StatusTooManyRequests)
		return
	}

	identifier := authIdentifier(app)
	var userID int64
	var pending int
	var hash, email string
	query := fmt.Sprintf("SELECT id, password_hash, COALESCE(email, ''), COALESCE(password_change_required,0) FROM _benmore_users WHERE %s = ?", identifier)
	if identifier == "email" {
		query += " COLLATE NOCASE"
	}
	err := app.DB.QueryRow(query, body.Email).Scan(&userID, &hash, &email, &pending)
	if err != nil {
		recordLoginAttempt(app.DB, body.Email, false)
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)); err != nil {
		recordLoginAttempt(app.DB, body.Email, false)
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	recordLoginAttempt(app.DB, body.Email, true)
	// Pending accounts must finish the interactive login path, including any
	// configured email OTP. A password-only token must not bypass that proof.
	if pending != 0 {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "password_change_required", "redirect": app.Paths.Login})
		return
	}

	// MFA check: if user has TOTP enabled, require mfa_code
	if CheckMFA(app.DB, userID) {
		if body.MFACode == "" {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "mfa_required", "message": "MFA code required"})
			return
		}
		mfaKey := mfaLockKey(userID)
		if isAccountLocked(app.DB, mfaKey) {
			httpJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many MFA attempts"})
			return
		}
		if !ValidateMFACode(app.DB, userID, body.MFACode) {
			recordLoginAttempt(app.DB, mfaKey, false)
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid MFA code"})
			return
		}
		recordLoginAttempt(app.DB, mfaKey, true)
	} else {
		// MFA not enrolled. If the user's role appears in
		// `auth.require_mfa_for_roles`, withhold the session and return
		// a short-lived setup token - the SPA then drives enrollment
		// via /api/_auth/mfa/setup + /verify, and verify mints the
		// real session on successful enrollment.
		var role string
		app.DB.QueryRow("SELECT COALESCE(role, '') FROM _benmore_users WHERE id = ?", userID).Scan(&role)
		if roleRequiresMFAEnrollment(app, role) {
			httpJSON(w, http.StatusOK, map[string]any{
				"mfa_setup_required": true,
				"setup_token":        mintMFASetupToken(userID, body.Email),
				"user_id":            userID,
				"email":              body.Email,
				"role":               role,
				"message":            "MFA enrollment is required for your role. Use setup_token via the X-MFA-Setup-Token header on /api/_auth/mfa/setup then /api/_auth/mfa/verify - a full session is returned on successful verify.",
			})
			return
		}
	}

	app.DB.Exec("UPDATE _benmore_users SET last_login_at = datetime('now') WHERE id = ?", userID)
	FireUserHooks(app, "update", userID)

	groupID := ResolveGroupID(app.DB, app.Group, email)
	token := CreateSession(app.DB, userID, email, groupID, app.SessionDuration, body.Scopes)

	AttachSessionContext(app.DB, token, r)

	resp := map[string]any{
		"token":   token,
		"user_id": userID,
		"email":   body.Email,
	}
	if body.Scopes != "" {
		resp["scopes"] = body.Scopes
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
