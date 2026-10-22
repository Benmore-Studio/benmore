//go:build !cli

package main

// Interactive login, signup, OTP verification, logout, and group switching.

import (
	"crypto/hmac"
	"crypto/rand"
	"database/sql"
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
		// Email-keyed memberships count only for a verified address.
		if _, ok := groupMemberValue(app.Group, session); !ok {
			http.Error(w, "Verify your email to join this organization", http.StatusForbidden)
			return
		}
		// Only a live membership row (not soft-deleted, active per
		// groups.active_field) lets the user into the organization.
		if !groupMembershipLive(app.DB, app.Group, session, newGroupID) {
			http.Error(w, "Not a member of this organization", http.StatusForbidden)
			return
		}
	}
	// Update session org_id. The tenant lives on the session row: an API
	// token or edge identity has none, and reporting a switch that did not
	// happen sent the caller's next writes to the tenant it left.
	res, err := app.DB.Exec("UPDATE _benmore_sessions SET group_id = ? WHERE id = ?", newGroupID, session.ID)
	if err != nil {
		serverError(w, r, app, "switch organization", err, "Could not switch organization")
		return
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		http.Error(w, "Switching organization needs a sign-in session: an API token or edge identity can't hold one", http.StatusBadRequest)
		return
	}
	invalidateRequestSession(r)
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
		authCSRFRefused(w, r, app.Paths.Login)
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
	defer lockAttempt(loginValue)() // serialize this account's check→verify→record (lockout race)
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
		burnPasswordCheck(password) // same cost as a wrong password: no timing oracle for account existence
		recordLoginAttempt(app.DB, loginValue, false)
		recordLoginAttempt(app.DB, authIPLockKey(loginIP), false) // per-IP counter (LOWER)
		authRedirect(w, r, app.Paths.Login, "Invalid credentials")
		return
	}

	// Capture the generation before checking the password. Challenge issuance
	// rechecks it while holding the writer, including same-hash resets.
	_, proofHash, proofBinding, err := mfaSetupAccountState(app, app.DB, id, email)
	if err != nil || !hmac.Equal([]byte(hash), []byte(proofHash)) {
		authRedirect(w, r, app.Paths.Login, "Credentials changed. Sign in again.")
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

	// A grandfathered, unverified account proves its email before any factor.
	if _, stop := grandfatheredSignInNeedsProof(app, r, id); stop {
		authRedirect(w, r, app.Paths.Login, grandfatheredVerifyMessage)
		return
	}

	// MFA check: if user has TOTP enabled, require code before creating session
	if CheckMFA(app.DB, id) {
		mfaCode := strings.TrimSpace(r.FormValue("mfa_code"))
		if mfaCode == "" {
			// Keep the accepted password generation and exact OTP lookup key
			// in a one-use challenge; social sign-ins carry no OTP key.
			token := mintSignInChallenge(app, tempCookieMFA, id, email, loginValue, proofBinding)
			if token == "" {
				authRedirect(w, r, app.Paths.Login, "Credentials changed. Sign in again.")
				return
			}
			setFlowCookie(w, flowCookieMFA, token, !app.DevMode, 300)
			http.Redirect(w, r, app.Paths.VerifyMFA, http.StatusSeeOther)
			return
		}
		completeInlineMFALogin(w, r, app, id, email, loginValue, hash, proofBinding, mfaCode)
		return
	} else {
		// MFA not enrolled. If the user's role appears in
		// `auth.require_mfa_for_roles`, redirect to the enrollment
		// page instead of issuing a session. The setup-token cookie
		// authorises /api/_auth/mfa/setup + /verify on this user's
		// behalf; verify mints the real session on successful enroll.
		//
		// With auth.otp on, the emailed code comes first: the setup token
		// ends in a full session, so minting it on the password alone would
		// skip the OTP. handleVerifyOTP starts enrollment once the code is
		// proven.
		if userRequiresMFAEnrollment(app, id) && !otpLoginEnabled(app) {
			redirectToMFAEnrollment(w, r, app, id, email, hash, proofBinding)
			return
		}
	}

	// OTP check: if auth_otp is set, send a code before creating session
	// Supports email OTP and phone OTP (SMS) depending on identifier config
	if otpLoginEnabled(app) {
		if startLoginOTP(w, r, app, id, email, loginValue, proofBinding) {
			app.DB.Exec("UPDATE _benmore_users SET last_login_at=datetime('now') WHERE id=?", id)
			FireUserHooks(app, "update", id)
			syncPlatformUserFromDashboard(app, email, hash)
		}
		return
	}

	groupID := ResolveGroupID(app.DB, app.Group, email)
	sessionID, err := createPasswordSignInSession(app, id, email, groupID, proofBinding)
	if err != nil {
		authRedirect(w, r, app.Paths.Login, "Credentials changed. Sign in again.")
		return
	}
	FireUserHooks(app, "update", id)
	// Dashboard-only healing happens after the accepted proof was rechecked.
	syncPlatformUserFromDashboard(app, email, hash)

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

// startLoginOTP sends the auth.otp sign-in code for an account whose
// password - and second factor, when one is enrolled - already passed, and
// routes the browser to the code step. No session exists until the code is
// proven (handleVerifyOTP). loginValue is the normalized identifier the
// account signed in with; the code row is keyed on it.
func startLoginOTP(w http.ResponseWriter, r *http.Request, app *App, id int64, email, loginValue string, expected ...string) bool {
	binding := ""
	if len(expected) > 0 {
		binding = expected[0]
	}
	code, token, err := prepareLoginOTP(app, id, email, loginValue, binding)
	if err != nil {
		authRedirect(w, r, app.Paths.Login, "Credentials changed. Sign in again.")
		return false
	}
	sendLoginOTP(w, r, app, id, email, loginValue, code, token)
	return true
}

func prepareLoginOTP(app *App, id int64, email, loginValue, binding string) (code, token string, err error) {
	tx, err := signInWriteTx(app.DB)
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	code, token, err = prepareLoginOTPTx(app, tx, id, email, loginValue, binding)
	if err == nil {
		err = tx.Commit()
	}
	return
}

func prepareLoginOTPTx(app *App, tx *sql.Tx, id int64, email, loginValue, binding string) (code, token string, err error) {
	token, err = mintSignInChallengeTx(app, tx, tempCookieOTP, id, email, loginValue, binding)
	if err != nil {
		return "", "", err
	}
	code = generateOTP()
	if _, err = tx.Exec("CREATE TABLE IF NOT EXISTS _benmore_otp (email TEXT, code TEXT, attempts INTEGER DEFAULT 0, expires_at DATETIME)"); err != nil {
		return "", "", err
	}
	if _, err = tx.Exec("DELETE FROM _benmore_otp WHERE email=?", loginValue); err != nil {
		return "", "", err
	}
	_, err = tx.Exec("INSERT INTO _benmore_otp(email,code,attempts,expires_at) VALUES (?,?,0,datetime('now','+10 minutes'))", loginValue, code)
	return
}

func sendLoginOTP(w http.ResponseWriter, r *http.Request, app *App, id int64, email, loginValue, code, token string) {
	identifier := authIdentifier(app)

	// Send OTP via SMS or email depending on identifier
	if identifier == "phone" {
		// Look up phone number
		var phone string
		app.DB.QueryRow("SELECT COALESCE(phone, '') FROM _benmore_users WHERE id = ?", id).Scan(&phone)
		if phone != "" {
			if err := SendSMS(app.Dir, phone, fmt.Sprintf("Your verification code: %s", code)); err != nil {
				log.Printf("auth: SMS send failed for verification code (user=%d): %s", id, logSendError(err, phone))
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
			log.Printf("auth: email send failed for verification code (user=%d): %s", id, logSendError(err, email))
		}
	}

	// The opaque cookie resolves to the account and exact send-time key in
	// SQLite; username/phone identifiers must not be replaced by the email.
	setFlowCookie(w, flowCookieOTP, token, !app.DevMode, 600)
	sendOTPChallenge(w, r, app)
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

	// The step cookie is the ambient credential here and the code is the only
	// secret, so the form carries no CSRF token; but another site (a sibling
	// tenant is same-site, so SameSite=Lax doesn't stop it) must not be able
	// to post guesses through a visitor's half-finished sign-in and burn the
	// code or lock the step.
	if _, ok := csrfOriginReason(r); !ok {
		authRedirect(w, r, otpPath, "This form expired. Reload the page and try again.")
		return
	}

	cookie, err := requestFlowCookie(r, flowCookieOTP)
	if err != nil || cookie.Value == "" {
		authRedirect(w, r, otpPath, "Session expired. Please log in again.")
		return
	}

	challenge, err := signInChallengeIdentity(app, app.DB, cookie.Value, tempCookieOTP)
	if err != nil {
		authRedirect(w, r, otpPath, "Invalid session. Please log in again.")
		return
	}
	id, email, otpKey := challenge.UserID, challenge.Email, challenge.OTPKey

	// Every correct-password login issues a fresh code with 5 tries, so
	// failures must also count per account across codes, or holding the
	// password alone lets a caller keep guessing the second factor.
	otpLockKey := "otp:" + otpKey
	defer lockAttempt(otpLockKey)() // serialize this account's check→verify→record (lockout race)
	if isAccountLocked(app.DB, otpLockKey) {
		authRedirect(w, r, otpPath, "Too many attempts. Try again in 15 minutes.")
		return
	}

	groupID := ResolveGroupID(app.DB, app.Group, email)
	tx, err := signInWriteTx(app.DB)
	if err != nil {
		serverErrorJSON(w, r, app, "OTP sign-in", err, "Sign-in could not be saved")
		return
	}
	defer tx.Rollback()
	challenge, err = signInChallengeIdentity(app, tx, cookie.Value, tempCookieOTP)
	if err != nil {
		authRedirect(w, r, otpPath, "Invalid session. Please log in again.")
		return
	}
	var storedCode string
	var attempts int
	err = tx.QueryRow("UPDATE _benmore_otp SET attempts=attempts+1 WHERE email=? AND attempts<5 AND datetime(expires_at)>datetime('now') RETURNING code,attempts", otpKey).Scan(&storedCode, &attempts)
	if err != nil {
		var exists int
		tx.QueryRow("SELECT COUNT(*) FROM _benmore_otp WHERE email=? AND datetime(expires_at)>datetime('now')", otpKey).Scan(&exists)
		if exists > 0 {
			if _, err = tx.Exec("DELETE FROM _benmore_otp WHERE email=?", otpKey); err == nil {
				err = tx.Commit()
			}
			if err != nil {
				serverErrorJSON(w, r, app, "OTP sign-in", err, "Sign-in could not be saved")
				return
			}
			authRedirect(w, r, otpPath, "Too many attempts. Please log in again.")
			return
		}
		authRedirect(w, r, otpPath, "Code expired. Please log in again.")
		return
	}
	if !SecureCompare(code, storedCode) {
		if err = tx.Commit(); err != nil {
			serverErrorJSON(w, r, app, "OTP sign-in", err, "Sign-in could not be saved")
			return
		}
		recordLoginAttempt(app.DB, otpLockKey, false)
		authRedirect(w, r, otpPath, fmt.Sprintf("Invalid code. %d attempts remaining.", 5-attempts))
		return
	}
	needsEnrollment, err := needsMFAEnrollmentWith(app, tx, id)
	if err != nil {
		serverErrorJSON(w, r, app, "OTP sign-in", err, "Sign-in could not be saved")
		return
	}
	var sessionID, setupToken string
	if err = consumeSignInChallenge(tx, challenge); err == nil {
		_, err = tx.Exec("DELETE FROM _benmore_otp WHERE email=?", otpKey)
	}
	if err == nil && authIdentifier(app) != "phone" {
		_, err = tx.Exec("UPDATE _benmore_users SET verified=1 WHERE id=? AND email=? COLLATE NOCASE", id, email)
	}
	if err == nil {
		if needsEnrollment {
			setupToken = mintMFASetupTokenWith(app, tx, id, email)
			if setupToken == "" {
				err = fmt.Errorf("could not issue enrollment grant")
			}
		} else {
			sessionID, err = createSignInSessionTx(tx, id, email, groupID, app.SessionDuration)
		}
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		serverErrorJSON(w, r, app, "OTP sign-in", err, "Sign-in could not be saved")
		return
	}
	recordLoginAttempt(app.DB, otpLockKey, true)
	clearFlowCookie(w, flowCookieOTP)
	platformEmailProved(app, email, true)
	if authIdentifier(app) != "phone" {
		activateEmailInvites(app, id, email)
	}
	if setupToken != "" {
		setFlowCookie(w, flowCookieMFASetup, setupToken, !app.DevMode, int(mfaSetupTokenTTL.Seconds()))
		redirect := "/mfa-setup"
		if app.Design != nil && strings.TrimSpace(app.Design.Auth["mfa_setup_redirect"]) != "" {
			redirect = app.Design.Auth["mfa_setup_redirect"]
		}
		http.Redirect(w, r, redirect, http.StatusSeeOther)
		return
	}
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
	// A gate compares the address, so it must be one address: a list or a
	// second "@" would let a foreign mailbox ride along with an allowed tail.
	if !validAuthEmail(email) {
		return false, "Enter a valid email address."
	}

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
	if refuseDisabledAuthFeature(w, r, app, "signup") {
		return
	}
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
		authCSRFRefused(w, r, app.Paths.Signup)
		return
	}

	email := normalizeEmail(r.FormValue("email"))
	password := r.FormValue("password")

	if email == "" || password == "" {
		authRedirect(w, r, app.Paths.Signup, "Email and password are required")
		return
	}
	// One plain mailbox: no list, display-name form, "|", control or
	// invisible characters (validAuthEmail, the rule OAuth sign-in and email
	// change share).
	if !validAuthEmail(email) {
		authRedirect(w, r, app.Paths.Signup, "Invalid email")
		return
	}

	// Brute force protection on signup
	defer lockAttempt(email)() // serialize this account's check→verify→record (lockout race)
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

	// Abuse limits (auth_signup_limits.go), before the bcrypt hash and the
	// account row: per client address, and per mailbox when this sign-up
	// sends mail (plus-addressing makes unlimited accounts for one inbox).
	if retry, limited := signupRateLimited(app, r, email); limited {
		if wantsJSON(r) {
			setRetryAfter(w, retry)
		}
		authRedirect(w, r, app.Paths.Signup, "Too many sign-up attempts. Try again later.")
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
		// Only plain profile columns: signupFieldList drops role, verified,
		// secrets, tenant columns and anything that isn't an identifier, so
		// a public signup can't name its own authority (or reach the SQL
		// text below with anything but a validated column name).
		for _, field := range signupFieldList(app.Design.Auth["signup_fields"], app.Group) {
			val := strings.TrimSpace(r.FormValue(field))
			if val != "" {
				fields = append(fields, quoteIdent(field))
				placeholders = append(placeholders, "?")
				values = append(values, val)
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

	// Pending invites for this email (app-level user_roles table) are not
	// activated here: the address is unproven until the verification link,
	// an emailed OTP or a verified OAuth sign-in (markEmailVerified).

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
	// No trustworthy origin → no link (securityLinkBaseURL logged why).
	linkBase, linkOK := "", false
	if needsVerification {
		linkBase, linkOK = securityLinkBaseURL(app, r)
	}
	if needsVerification && linkOK {
		token := generateToken(32)
		expires := time.Now().Add(1 * time.Hour)
		app.DB.Exec("INSERT INTO _benmore_password_resets (token, email, expires_at, type) VALUES (?, ?, ?, 'verify')",
			hashResetToken(token), email, expires.UTC().Format(time.RFC3339))

		verifyURL := fmt.Sprintf("%s/verify-email?token=%s", linkBase, token)

		siteName := "App"
		if sn, ok := app.Design.SEO["site_name"]; ok && sn != "" {
			siteName = sn
		}

		body := fmt.Sprintf(`<h2>Verify your email</h2>
<p>Thanks for signing up for %s! Click below to verify your email address.</p>
<p><a href="%s">Verify Email</a></p>`, html.EscapeString(siteName), verifyURL)

		if err := SendEmail(app.Dir, email, "Verify your email - "+siteName, body); err != nil {
			log.Printf("auth: signup verification email failed (user=%d): %s", id, logSendError(err, email))
		}
	}

	// Email 2FA: when auth.otp is on, verify the new account's email with a
	// 6-digit code BEFORE issuing a session. Google/OAuth signups go through
	// the OAuth callback, not here, so they're exempt by construction. The
	// account row already exists; the session is only minted once the code is
	// confirmed on /verify-otp (same flow login uses).
	if otpLoginEnabled(app) {
		code, token, err := prepareLoginOTP(app, id, email, email, "")
		if err != nil {
			serverErrorJSON(w, r, app, "OTP signup", err, "Sign-up could not be saved")
			return
		}
		// Signup proves the email, even when subsequent logins use a phone
		// identifier. Keep its delivery and message distinct from sign-in.
		brand := AppEmailBrand(app, r)
		body := RenderBrandedCodeEmail(
			brand,
			"Your verification code",
			fmt.Sprintf("Enter this code to finish creating your %s account. It expires in 10 minutes.", html.EscapeString(brand.SiteName)),
			code,
			"If you didn't sign up, you can ignore this email.",
		)
		if err := SendEmail(app.Dir, email, "Your verification code · "+brand.SiteName, body); err != nil {
			log.Printf("auth: signup OTP email failed (user=%d): %s", id, logSendError(err, email))
		}
		setFlowCookie(w, flowCookieOTP, token, !app.DevMode, 600)
		sendOTPChallenge(w, r, app)
		return
	}

	groupID := ResolveGroupID(app.DB, app.Group, email)
	sessionID := createSignInSession(app.DB, id, email, groupID, app.SessionDuration)

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
	// The session this request authenticates with: the cookie, or a Bearer
	// session token (persistent API tokens are revoked on their own route).
	if id := authRawSessionID(r); id != "" {
		DeleteSessionFromDB(app.DB, id)
	}
	invalidateRequestSession(r)
	clearSessionCookies(w, app.DevMode)
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
	if refuseDisabledAuthFeature(w, r, app, "api_tokens") {
		return
	}
	// OAuth-only mode (app.yaml auth.oauth_only): the email+password →
	// Bearer exchange is a password sign-in path, so it must be refused
	// too - otherwise oauth_only would close the interactive login/signup
	// but leave this API path open as a silent password bypass.
	if oauthOnly(app) {
		http.Error(w, `{"error":"password auth is disabled - this app uses social sign-in only"}`, http.StatusForbidden)
		return
	}
	if !tokenAuthIPLimiter.Allow(appLimiterKey(app, "token", clientRateBucket(clientIP(r)))) {
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
		// Same auth.domain / auth.allow_emails gate as interactive login.
		if ok, reason := emailAllowedForApp(app, body.Email); !ok {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": reason})
			return
		}
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
	defer lockAttempt(body.Email)() // serialize this account's check→verify→record (lockout race)
	if isAccountLocked(app.DB, body.Email) {
		http.Error(w, `{"error":"too many attempts, try again later"}`, http.StatusTooManyRequests)
		return
	}
	// The same per-IP failure cap as /login: this is a password sign-in
	// too, and without it a spray rotating identifiers here dodged the
	// network lock the interactive form applies.
	loginIP := clientIP(r)
	if authIsIPLocked(app.DB, loginIP) {
		http.Error(w, `{"error":"too many failed attempts from this network, try again later"}`, http.StatusTooManyRequests)
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
		burnPasswordCheck(body.Password) // same cost as a wrong password: no timing oracle for account existence
		recordLoginAttempt(app.DB, body.Email, false)
		recordLoginAttempt(app.DB, authIPLockKey(loginIP), false)
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)); err != nil {
		recordLoginAttempt(app.DB, body.Email, false)
		recordLoginAttempt(app.DB, authIPLockKey(loginIP), false)
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	recordLoginAttempt(app.DB, body.Email, true)
	if _, stop := grandfatheredSignInNeedsProof(app, r, userID); stop {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "email_verification_required", "message": grandfatheredVerifyMessage})
		return
	}
	// Pending accounts must finish the interactive login path, including any
	// configured email OTP. A password-only token must not bypass that proof.
	if pending != 0 {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "password_change_required", "redirect": app.Paths.Login})
		return
	}
	// The same holds for every account when auth.otp is set: only the
	// interactive login proves the emailed code, so this exchange can't
	// issue a session on the password alone.
	if app.Design != nil && app.Design.Auth["otp"] == "true" {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "otp_required", "redirect": app.Paths.Login})
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
		if userRequiresMFAEnrollment(app, userID) {
			setupToken := mintMFASetupToken(app, userID, email, hash)
			if setupToken == "" {
				httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "credentials changed; sign in again"})
				return
			}
			httpJSON(w, http.StatusOK, map[string]any{
				"mfa_setup_required": true,
				"setup_token":        setupToken, // the account's email, never the typed identifier
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
	// Each exchange leaves a session behind for the whole session lifetime;
	// the account keeps its newest ones (auth_credential_caps.go).
	trimTokenExchangeSessions(app.DB, userID)

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
