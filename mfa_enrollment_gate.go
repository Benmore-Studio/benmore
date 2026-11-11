//go:build !cli

package main

import (
	"database/sql"
	"log"
	"net/http"
	"strings"
)

// auth.require_mfa_for_roles at credential resolution.
//
// Sign-in (password form, sign-up, token exchange, social login, passkey)
// withholds the session of an account that holds a listed role and has no TOTP
// factor and hands out a setup token instead. Credentials the account already
// held were never checked again: a cookie or Bearer session from before the
// role was granted or listed, and API tokens, kept full access, and such a
// session could mint a year-long API token without the account ever enrolling.
//
// resolveRequestSession now applies the same decision to every credential and
// marks one it holds back (Session.mfaEnrollmentPending). getSession refuses
// it on every route, so no handler grants it anything. The account can still
// enroll from it (password-confirmed, as any signed-in enrollment) or sign out;
// once the factor is active the same credentials work again.
// mfaEnrollmentMiddleware only tells the client why and where to go.

const mfaEnrollmentRequiredError = "mfa_enrollment_required"

const mfaEnrollmentRequiredMessage = "Your role requires two-factor authentication. Set it up before this credential can be used: POST /api/_auth/mfa/setup with your current password, then POST /api/_auth/mfa/verify with a code from your authenticator (or sign in again to start enrollment)."

// mfaEnrollmentCannotEnrollMessage is for a held credential that may not
// enroll itself (an API token, a scoped or act-as session): the setup call the
// other message names refuses it, so it is told to sign in instead.
const mfaEnrollmentCannotEnrollMessage = "Your role requires two-factor authentication before this credential can be used, and an API token cannot enroll (nor can a scoped or act-as session). Sign in with the account's password to get a full session, then POST /api/_auth/mfa/setup with your current password and POST /api/_auth/mfa/verify with a code from your authenticator. This credential works again once the factor is active."

// mfaEnrollmentRefusal is the 403 body for a credential held until its
// account enrolls: what is required, where a browser goes, and the steps this
// credential can actually take.
func mfaEnrollmentRefusal(app *App, held *Session) map[string]any {
	message := mfaEnrollmentRequiredMessage
	if held != nil && (!credentialManagementSession(app, held) || !accountManagementSession(held)) {
		message = mfaEnrollmentCannotEnrollMessage
	}
	return map[string]any{"error": mfaEnrollmentRequiredError, "message": message, "redirect": mfaSetupPagePath(app)}
}

// mfaEnrollmentConfigured reports whether app.yaml lists any role in
// auth.require_mfa_for_roles.
func mfaEnrollmentConfigured(app *App) bool {
	return mfaRequiredRoles(app) != ""
}

// mfaSetupPagePath is where a held browser is sent: auth.mfa_setup_redirect,
// default /mfa-setup.
func mfaSetupPagePath(app *App) string {
	if app != nil && app.Design != nil {
		if v := strings.TrimSpace(app.Design.Auth["mfa_setup_redirect"]); v != "" {
			return v
		}
	}
	return "/mfa-setup"
}

// mfaEnrollmentWithheld reports whether s belongs to an account that must
// enroll a TOTP factor before any credential of it may act. The decision is
// the one sign-in makes (needsMFAEnrollmentWith): no live factor, and a listed
// role in the role column or a global grant. Accounts holding no listed role
// cost no lookup: Roles always contains the role column and every global
// grant. A read failure holds the credential back.
func mfaEnrollmentWithheld(app *App, s *Session) bool {
	if s == nil || s.UserID <= 0 || app == nil || app.DB == nil || !mfaEnrollmentConfigured(app) {
		return false
	}
	listed := roleRequiresMFAEnrollment(app, s.Role)
	for i := 0; !listed && i < len(s.Roles); i++ {
		listed = roleRequiresMFAEnrollment(app, s.Roles[i])
	}
	// A support impersonation runs on the signed-in admin's authority.
	if !listed || s.ImpersonatorUserID != 0 {
		return false
	}
	need, err := needsMFAEnrollmentWith(app, app.DB, s.UserID)
	if err != nil {
		log.Printf("MFA enrollment check for user %d failed: %v", s.UserID, err)
		return true
	}
	return need && !toolingDelegatedSession(app.DB, s)
}

// toolingDelegatedSession reports a session platform tooling minted to act as
// the user (createDelegatedSession: probe_route / browser_check `as`). It is
// the app editor's authority, not the account's sign-in, and every
// direct-login gate already refuses it. A read failure counts as the
// account's own credential.
func toolingDelegatedSession(db *sql.DB, s *Session) bool {
	if strings.HasPrefix(s.ID, "apitoken:") {
		return false
	}
	var flag int
	if err := db.QueryRow("SELECT COALESCE(is_impersonation,0) FROM _benmore_sessions WHERE id=?", s.ID).Scan(&flag); err != nil {
		return false
	}
	return flag != 0
}

// mfaEnrollmentSession returns the request's session when it is held for MFA
// enrollment, else nil. Only enrollment uses it as an identity.
func mfaEnrollmentSession(app *App, r *http.Request) *Session {
	if !mfaEnrollmentConfigured(app) {
		return nil
	}
	if _, private := appMCPPrivateSession(app, r); private {
		return nil
	}
	if s := requestCredentialSession(app, r); s != nil && s.mfaEnrollmentPending {
		return s
	}
	return nil
}

// mfaEnrollmentStepRequest reports a request a held credential may still
// reach: the setup page and the enrollment calls, the CSRF token they need,
// signing out, and the sign-in pages (signing in again, or signing up, starts
// enrollment with a setup token, which needs no password). The handlers
// behind them still get no session from getSession.
//
// The HTML stack serves static/login.html at /login and at /login.html, and
// scaffolds link to the file name. The login, sign-up and forgot-password
// pages are therefore reachable under both spellings; before, /login.html
// was sent back to the setup page, whose only link it was. No other .html
// path is exempt.
func mfaEnrollmentStepRequest(app *App, r *http.Request) bool {
	p := r.URL.Path
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if p == mfaSetupPagePath(app) || p == "/api/_csrf" || strings.HasPrefix(p, "/auth/") {
			return true
		}
	case http.MethodPost:
		switch p {
		case "/api/_auth/mfa/setup", "/api/_auth/mfa/verify", "/api/_auth/passkeys/login/options", "/api/_auth/passkeys/login":
			return true
		}
	}
	paths := app.Paths
	if paths == nil || (r.Method != http.MethodGet && r.Method != http.MethodPost) {
		return false
	}
	switch p {
	case paths.Login, paths.Signup, paths.VerifyOTP, paths.VerifyMFA, paths.ForgotPassword, paths.ResetPassword, paths.VerifyEmail:
		return true
	}
	if r.Method == http.MethodGet {
		for _, page := range []string{paths.Login, paths.Signup, paths.ForgotPassword} {
			if page != "" && p == page+".html" {
				return true
			}
		}
	}
	return r.Method == http.MethodPost && p == paths.Logout
}

// mfaEnrollmentMiddleware answers a held credential with where to go: 403
// mfa_enrollment_required (with the setup page as redirect) for API, JSON and
// Bearer callers, a redirect to the setup page for page navigation.
func mfaEnrollmentMiddleware(next http.Handler, app *App) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !mfaEnrollmentConfigured(app) || isStaticPath(r.URL.Path) || mfaEnrollmentStepRequest(app, r) {
			next.ServeHTTP(w, r)
			return
		}
		held := mfaEnrollmentSession(app, r)
		if held == nil {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		setup := mfaSetupPagePath(app)
		if strings.HasPrefix(r.URL.Path, "/api/") || wantsJSON(r) || isBearerAuth(r) {
			httpJSON(w, http.StatusForbidden, mfaEnrollmentRefusal(app, held))
			return
		}
		if isHTMX(r) {
			w.Header().Set("HX-Redirect", setup)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.Redirect(w, r, setup, http.StatusSeeOther)
	})
}
