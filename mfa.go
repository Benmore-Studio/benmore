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
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// roleRequiresMFAEnrollment reports whether `role` appears in the
// `auth.require_mfa_for_roles` list in app.yaml (comma-separated; `*` = every role).
// When the role is listed, password authentication alone does not grant
// a session - the user must enroll in MFA before one is issued.
func roleRequiresMFAEnrollment(app *App, role string) bool {
	if app == nil || app.Design == nil {
		return false
	}
	raw := mfaRequiredRoles(app)
	if raw == "" {
		return false
	}
	for _, r := range strings.Split(raw, ",") {
		// "*" lists every account, whatever its role (compliance: hipaa).
		if r = strings.TrimSpace(r); r == "*" || (role != "" && strings.EqualFold(r, role)) {
			return true
		}
	}
	return false
}

// userRequiresMFAEnrollment reports whether the account holds a role listed in
// auth.require_mfa_for_roles: the primary role column or any live global grant
// in _benmore_user_roles, the same set IsAdmin and the access gates honour.
// Grants scoped to one tenant are not consulted: no tenant is chosen yet.
func userRequiresMFAEnrollment(app *App, userID int64) bool {
	if roleRequiresMFAEnrollment(app, "") { // "*" lists every account, even one with no role
		return true
	}
	var role string
	app.DB.QueryRow("SELECT COALESCE(role, '') FROM _benmore_users WHERE id = ?", userID).Scan(&role)
	for _, held := range LoadSessionRoles(app.DB, userID, role, "") {
		if roleRequiresMFAEnrollment(app, held) {
			return true
		}
	}
	return false
}

// needsMFAEnrollmentWith makes the final enrollment decision under the same
// writer transaction that exchanges the OTP proof for its next credential.
func needsMFAEnrollmentWith(app *App, q mutationQuerier, userID int64) (bool, error) {
	if mfaRequiredRoles(app) == "" {
		return false, nil
	}
	var secret, role string
	if err := q.QueryRow("SELECT COALESCE(totp_secret,''),COALESCE(role,'') FROM _benmore_users WHERE id=?", userID).Scan(&secret, &role); err != nil {
		return false, err
	}
	if secret != "" && !strings.HasPrefix(secret, totpPendingPrefix) {
		return false, nil
	}
	if roleRequiresMFAEnrollment(app, role) {
		return true, nil
	}
	// The global-grants table is optional in older/lightweight app schemas.
	// Missing grants mean no additional roles; other query failures stay closed.
	var roleTable int
	if err := q.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_benmore_user_roles'").Scan(&roleTable); err != nil {
		return false, err
	}
	if roleTable == 0 {
		return false, nil
	}
	roles, err := loadSessionRolesWith(q, userID, role, "")
	if err != nil {
		return false, err
	}
	for _, held := range roles {
		if roleRequiresMFAEnrollment(app, held) {
			return true, nil
		}
	}
	return false, nil
}

// otpLoginEnabled reports whether app.yaml sets auth.otp: interactive
// logins must prove an emailed / texted code before any session.
func otpLoginEnabled(app *App) bool {
	return app != nil && app.Design != nil && app.Design.Auth["otp"] == "true"
}

// redirectToMFAEnrollment withholds the session and hands the browser the
// setup-token cookie for /api/_auth/mfa/setup + /verify. Callers must have
// proven every login factor the app requires first: verify turns the token
// into a full session.
func redirectToMFAEnrollment(w http.ResponseWriter, r *http.Request, app *App, userID int64, email string, verifiedPasswordHash ...string) {
	token := mintMFASetupToken(app, userID, email, verifiedPasswordHash...)
	if token == "" {
		authRedirect(w, r, app.Paths.Login, "Credentials changed. Sign in again.")
		return
	}
	setFlowCookie(w, flowCookieMFASetup, token, !app.DevMode, int(mfaSetupTokenTTL.Seconds()))
	sendMFASetupStep(w, r, app)
}

// sendMFASetupStep routes a caller whose role must enroll an authenticator
// to the enrollment page (auth.mfa_setup_redirect, default /mfa-setup) once
// the setup cookie is set: a JSON client gets {mfa_setup_required, redirect},
// a form post or a navigation a 303. The page completes with
// POST /api/_auth/mfa/setup and /verify; the cookie is its proof.
func sendMFASetupStep(w http.ResponseWriter, r *http.Request, app *App) {
	target := authStepTarget(mfaSetupPagePath(app), r)
	if wantsJSON(r) {
		httpJSON(w, http.StatusOK, map[string]any{"ok": true, "mfa_setup_required": true, "redirect": target})
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// mfaSetupTokenTTL is the lifetime of an MFA-setup token. Long enough
// to scan a QR + type a code; short enough that a leaked token is
// useless after a single sign-in attempt.
const mfaSetupTokenTTL = 15 * time.Minute

// errMFACredentialMayNotEnroll refuses a caller who is signed in with a
// credential that may not manage the account's factor: an API token, a scoped
// session, an act-as or support session. The credential is valid, so the
// answer is 403; a request with no credential stays 401.
var errMFACredentialMayNotEnroll = errors.New("MFA enrollment requires a full-access login session outside act-as mode: sign in with the account's password (an API token or a scoped session cannot enroll)")

// mfaCallerRefusalStatus maps a mfaCallerIdentity error onto its status.
func mfaCallerRefusalStatus(err error) int {
	if errors.Is(err, errMFACredentialMayNotEnroll) {
		return http.StatusForbidden
	}
	return http.StatusUnauthorized
}

// mfaCallerIdentity resolves the caller of an MFA endpoint. Prefers a
// real session; falls back to an MFA-setup token from the
// X-MFA-Setup-Token header or _benmore_mfa_setup cookie. Returns
// fromSetupToken=true when the latter was used, so /verify knows to
// mint a real session on success. Last comes a login session held until its
// account enrolls (mfa_enrollment_gate.go): it enrolls like any signed-in
// caller, with the current password and CSRF.
func mfaCallerIdentity(app *App, r *http.Request) (userID int64, email string, fromSetupToken bool, err error) {
	if s := getSession(app, r); s != nil {
		if !credentialManagementSession(app, s) || !accountManagementSession(s) {
			return 0, "", false, errMFACredentialMayNotEnroll
		}
		return s.UserID, s.Email, false, nil
	}
	uid, current, err := mfaSetupTokenIdentity(app, app.DB, r)
	if err == nil {
		return uid, current, true, nil
	}
	if s := mfaEnrollmentSession(app, r); s != nil {
		if !credentialManagementSession(app, s) || !accountManagementSession(s) {
			return 0, "", false, errMFACredentialMayNotEnroll
		}
		return s.UserID, s.Email, false, nil
	}
	return 0, "", false, err
}

// mfaSetupSameSite reports whether an enrollment call authenticated by the
// MFA setup token may proceed: any call that carries the token in the
// X-MFA-Setup-Token header (another site can't set it), or one from this
// origin. A setup-token COOKIE from another site's page is refused.
func mfaSetupSameSite(r *http.Request) bool {
	if strings.TrimSpace(r.Header.Get("X-MFA-Setup-Token")) != "" {
		return true
	}
	_, ok := csrfOriginReason(r)
	return ok
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
func RegisterMFARoutes(mux appRouteRegistrar, app *App) {
	EnsureMFAColumns(app.DB)
	EnsureAuditLogTable(app.DB) // factor changes audit in their own transaction
	// Seal TOTP secrets written before at-rest encryption (or before the
	// app had a durable key). Reads accept both forms, so a failure here
	// only delays sealing to the next use.
	if err := sealStoredTOTPSecrets(app.DB); err != nil {
		log.Printf("MFA: sealing stored TOTP secrets failed: %v", err)
	}
	registerMFARoutes(mux, app)
}

func registerMFARoutes(mux appRouteRegistrar, app *App) {
	// POST /api/_auth/mfa/setup - generate TOTP secret + backup codes
	mux.HandleFunc("POST /api/_auth/mfa/setup", func(w http.ResponseWriter, r *http.Request) {
		if accountSettingsMFASetupDisabled(w, r, app) {
			return
		}
		userID, email, fromSetup, err := mfaCallerIdentity(app, r)
		if err != nil {
			httpJSON(w, mfaCallerRefusalStatus(err), map[string]any{"error": err.Error()})
			return
		}
		// CSRF only protects cookie-session callers. Bearer-auth and the
		// HMAC-signed setup-token path each carry their own integrity proof.
		if !isBearerAuth(r) && !fromSetup && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}
		// The setup token also travels as a cookie, which a sibling site's
		// request would carry: it may not restart someone's enrollment.
		if fromSetup && !mfaSetupSameSite(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid request origin"})
			return
		}
		// Setup tokens are for FIRST enrollment only. If MFA is already
		// active for the user, a stolen token can't be used to reset it -
		// the user must disable from a real session first.
		var existing string
		if err := app.DB.QueryRow("SELECT COALESCE(totp_secret, '') FROM _benmore_users WHERE id = ? AND "+accountActiveSQL(""), userID).Scan(&existing); err != nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "account unavailable"})
			return
		}
		if existing != "" && !strings.HasPrefix(existing, "pending:") {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "MFA already enabled - verify the current factor to disable it first"})
			return
		}
		// From an ordinary session, enrolling a factor needs the current
		// password: otherwise a stolen cookie could bind the thief's
		// authenticator and lock the owner out of their own account. The
		// login-issued setup token already follows a password proof.
		if !fromSetup {
			var body struct {
				Password        string `json:"password"`
				CurrentPassword string `json:"current_password"`
			}
			json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body)
			password := body.Password
			if password == "" {
				password = body.CurrentPassword
			}
			if password == "" {
				httpJSON(w, http.StatusBadRequest, map[string]any{"error": "password required to enable MFA"})
				return
			}
			if ok, locked := currentPasswordMatches(app, userID, password); !ok {
				if locked {
					httpJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many attempts, try again in 15 minutes"})
					return
				}
				httpJSON(w, http.StatusForbidden, map[string]any{"error": "incorrect password"})
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
		// An app on a generated per-process key saves it first, so the
		// enrollment is sealed under a key the next start still has.
		prepareTOTPSealKey(app.DB)
		sealed, err := sealTOTPSecret(app.DB, secretB32)
		if err != nil {
			serverErrorJSON(w, r, app, "mfa setup", err, "MFA setup could not be saved")
			return
		}

		// Store the sealed secret + hashed backup codes (not yet enabled - user
		// must verify first). Recheck the setup grant inside the transaction:
		// password recovery may have completed while backup codes were hashed.
		tx, err := app.DB.Begin()
		if err != nil {
			serverErrorJSON(w, r, app, "mfa setup", err, "MFA setup could not be saved")
			return
		}
		defer tx.Rollback()
		if fromSetup {
			if _, _, err := mfaSetupTokenIdentity(app, tx, r); err != nil {
				httpJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
				return
			}
		}
		res, err := tx.Exec("UPDATE _benmore_users SET totp_secret = ?, backup_codes = ? WHERE id = ? AND COALESCE(totp_secret, '') = ? AND "+accountActiveSQL(""),
			totpPendingPrefix+sealed, string(codesJSON), userID, existing)
		if err != nil {
			serverErrorJSON(w, r, app, "mfa setup", err, "MFA setup could not be saved")
			return
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			httpJSON(w, http.StatusConflict, map[string]any{"error": "MFA enrollment changed; reload and try again"})
			return
		}
		// The codes are a way in once the factor is active: their issue is
		// recorded with them, by count.
		if err := auditAccountEvent(tx, app, accountAuditMFACodesGenerated, strconv.FormatInt(userID, 10),
			&Session{UserID: userID, Email: email}, nil, map[string]any{"factor": "totp", "count": len(backupCodes)}); err != nil {
			serverErrorJSON(w, r, app, "mfa setup", err, "MFA setup could not be saved")
			return
		}
		if err := tx.Commit(); err != nil {
			serverErrorJSON(w, r, app, "mfa setup", err, "MFA setup could not be saved")
			return
		}

		// Build otpauth URI for QR code generation (client-side concern)
		issuer := "App"
		if app.Design != nil {
			if sn, ok := app.Design.SEO["site_name"]; ok && sn != "" {
				issuer = sn
			}
		}
		httpJSON(w, http.StatusOK, map[string]any{
			"secret":       secretB32,
			"otpauth_uri":  totpKeyURI(issuer, email, secretB32),
			"backup_codes": backupCodes, // shown ONCE, never again
		})
	})

	// POST /api/_auth/mfa/verify - validate a TOTP code to enable MFA.
	// When the caller authenticated via an MFA-setup token (i.e. came
	// from the login flow's enrollment branch), a successful verify
	// also mints a real session and returns it - that's how the
	// password+enrollment-required flow completes in a single request.
	mux.HandleFunc("POST /api/_auth/mfa/verify", func(w http.ResponseWriter, r *http.Request) {
		if accountSettingsMFASetupDisabled(w, r, app) {
			return
		}
		userID, email, fromSetup, err := mfaCallerIdentity(app, r)
		if err != nil {
			httpJSON(w, mfaCallerRefusalStatus(err), map[string]any{"error": err.Error()})
			return
		}
		if !isBearerAuth(r) && !fromSetup && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}
		if fromSetup && !mfaSetupSameSite(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid request origin"})
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
		if !strings.HasPrefix(secretRaw, totpPendingPrefix) {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "MFA setup not started - call /api/_auth/mfa/setup first"})
			return
		}
		secretB32, err := openTOTPSecret(app.DB, secretRaw)
		if err != nil {
			serverErrorJSON(w, r, app, "mfa verify", err, "MFA enrollment cannot be read; start setup again")
			return
		}

		verifiedAt := time.Now()
		step, valid := matchTOTPStep(secretB32, body.Code, verifiedAt)
		if !valid {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid code"})
			return
		}

		// Enable MFA - drop the "pending:" marker. A sealed enrollment keeps
		// its ciphertext; one started before sealing is sealed now.
		active := strings.TrimPrefix(secretRaw, totpPendingPrefix)
		if !totpSecretSealed(active) {
			prepareTOTPSealKey(app.DB)
			if active, err = sealTOTPSecret(app.DB, secretB32); err != nil {
				serverErrorJSON(w, r, app, "mfa verify", err, "MFA verification could not be saved")
				return
			}
		}
		// Resolve through the app connection before opening the transaction (an
		// app may have only one connection). All final authorization and writes
		// happen together so a concurrent reset either prevents enrollment or
		// subsequently revokes its already-committed session.
		groupID := ""
		if fromSetup {
			groupID = ResolveGroupID(app.DB, app.Group, email)
		}
		tx, err := app.DB.Begin()
		if err != nil {
			serverErrorJSON(w, r, app, "mfa verify", err, "MFA verification could not be saved")
			return
		}
		defer tx.Rollback()
		if fromSetup {
			if _, _, err := mfaSetupTokenIdentity(app, tx, r); err != nil {
				httpJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
				return
			}
		}
		// Activation consumes its proof in the same transaction. Otherwise the
		// code that just established this factor could sign in or remove it a
		// second time. A replacement factor starts with its own watermark.
		res, err := tx.Exec(`UPDATE _benmore_users SET totp_secret = ?, mfa_setup_nonce=lower(hex(randomblob(16))),
			mfa_last_totp = ?, mfa_last_totp_at = ? WHERE id = ? AND totp_secret = ? AND `+accountActiveSQL(""),
			active, "s:"+strconv.FormatUint(step, 10), verifiedAt.UTC().Format(time.RFC3339), userID, secretRaw)
		if err != nil {
			serverErrorJSON(w, r, app, "mfa verify", err, "MFA verification could not be saved")
			return
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			httpJSON(w, http.StatusConflict, map[string]any{"error": "MFA enrollment changed; reload and try again"})
			return
		}
		// An OTP/password proof from before activation did not prove the new
		// factor. Rotate the credential generation and cancel pending steps in
		// the same transaction as activation (and any enrollment session).
		if _, err := tx.Exec("DELETE FROM _benmore_signin_challenges WHERE user_id=?", userID); err != nil {
			serverErrorJSON(w, r, app, "mfa verify", err, "MFA verification could not be saved")
			return
		}
		var token string
		if fromSetup {
			// Exchange the setup token for a real session. The caller
			// passed password auth at login and has now enrolled, so
			// they earn the full session here. Mirrors the post-MFA
			// session-creation in handleLogin/handleTokenAuth.
			token, err = createSignInSessionTx(tx, userID, email, groupID, app.SessionDuration)
			if err != nil {
				serverErrorJSON(w, r, app, "mfa verify", err, "MFA verification could not be saved")
				return
			}
			if _, err := tx.Exec("UPDATE _benmore_users SET last_login_at = datetime('now') WHERE id = ?", userID); err != nil {
				serverErrorJSON(w, r, app, "mfa verify", err, "MFA verification could not be saved")
				return
			}
		}
		if err := auditAccountEvent(tx, app, accountAuditMFAEnrolled, strconv.FormatInt(userID, 10),
			&Session{UserID: userID, Email: email}, nil, map[string]any{"factor": "totp"}); err != nil {
			serverErrorJSON(w, r, app, "mfa verify", err, "MFA verification could not be saved")
			return
		}
		if err := tx.Commit(); err != nil {
			serverErrorJSON(w, r, app, "mfa verify", err, "MFA verification could not be saved")
			return
		}
		log.Printf("MFA: enabled for user %d", userID)
		// A session held for enrollment acts again from now on.
		invalidateRequestSession(r)
		if fromSetup {
			AttachSessionContext(app.DB, token, r)
			http.SetCookie(w, sessionCookie(token, app.DevMode, app.SessionDuration))
			clearFlowCookie(w, flowCookieMFASetup)
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
		if accountSettingsDisabled(w, r, app) {
			return
		}
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		if !credentialManagementSession(app, session) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "MFA changes require a login session outside act-as mode"})
			return
		}
		if !requireAccountManagement(w, session) {
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

		var stored string
		app.DB.QueryRow("SELECT COALESCE(totp_secret, '') FROM _benmore_users WHERE id = ?", session.UserID).Scan(&stored)
		if stored == "" || strings.HasPrefix(stored, totpPendingPrefix) {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "MFA not enabled"})
			return
		}
		secretB32, err := openTOTPSecret(app.DB, stored)
		if err != nil {
			serverErrorJSON(w, r, app, "mfa disable", err, "MFA factor cannot be read; contact the app administrator")
			return
		}

		// Same budget as the login MFA step: a signed-in caller must not be
		// able to guess the code without limit.
		mfaKey := mfaLockKey(session.UserID)
		defer lockAttempt(mfaKey)() // serialize this account's check→verify→record (lockout race)
		if isAccountLocked(app.DB, mfaKey) {
			httpJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many MFA attempts, try again in 15 minutes"})
			return
		}
		if !ValidateTOTP(secretB32, body.Code) {
			recordLoginAttempt(app.DB, mfaKey, false)
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid code"})
			return
		}
		tx, err := signInWriteTx(app.DB)
		if err != nil {
			serverErrorJSON(w, r, app, "mfa disable", err, "MFA change could not be saved")
			return
		}
		defer tx.Rollback()
		// Keep TOTP-only removal, but share sign-in's consumed-step guard.
		// Spending the code and removing the factor must roll back together.
		if !consumeMFATOTPWith(tx, session.UserID, body.Code) {
			tx.Rollback()
			recordLoginAttempt(app.DB, mfaKey, false)
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid code"})
			return
		}
		// The shared consumer already bound the factor in this write transaction.
		// It may also have resealed a legacy plaintext secret, so the value read
		// before the transaction is no longer a valid removal predicate.
		res, err := tx.Exec("UPDATE _benmore_users SET totp_secret = NULL, backup_codes = NULL, mfa_setup_nonce=lower(hex(randomblob(16))) WHERE id = ?", session.UserID)
		if err != nil {
			serverErrorJSON(w, r, app, "mfa disable", err, "MFA change could not be saved")
			return
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			httpJSON(w, http.StatusConflict, map[string]any{"error": "MFA enrollment changed; reload and try again"})
			return
		}
		// A pending OTP continuation may already have passed this factor.
		// Removing it cancels those unfinished sign-ins in the same commit.
		if _, err = tx.Exec("DELETE FROM _benmore_signin_challenges WHERE user_id=?", session.UserID); err == nil {
			err = auditAccountEvent(tx, app, accountAuditMFARemoved, strconv.FormatInt(session.UserID, 10), session, map[string]any{"factor": "totp"}, nil)
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			serverErrorJSON(w, r, app, "mfa disable", err, "MFA change could not be saved")
			return
		}
		recordLoginAttempt(app.DB, mfaKey, true)
		log.Printf("MFA: disabled for user %d", session.UserID)

		httpJSON(w, http.StatusOK, map[string]any{"status": "mfa_disabled"})
	})
}

// RegisterMFALoginRoute registers the POST handler for web MFA verification during login.
// After password success, if MFA is enabled, the user is sent to the MFA page
// (a 303, or {mfa_required, redirect} for JSON). The app serves that page
// (the scaffold's static/verify-mfa.html); its form POSTs here with the TOTP
// or backup code as mfa_code (or code) and the page's ?next=.
func RegisterMFALoginRoute(mux appRouteRegistrar, app *App) {
	mux.HandleFunc(fmt.Sprintf("POST %s", app.Paths.VerifyMFA), func(w http.ResponseWriter, r *http.Request) {
		mergeJSONBodyIntoForm(r)
		code := strings.TrimSpace(r.FormValue("mfa_code"))
		if code == "" {
			code = strings.TrimSpace(r.FormValue("code"))
		}

		// Bounces back to the code page keep the post-sign-in destination.
		mfaPath := authStepTarget(app.Paths.VerifyMFA, r)

		// As on the emailed-code step: no CSRF token (the code is the
		// secret), but another site must not drive this step through a
		// visitor's browser and lock their second factor (csrfOriginReason).
		if _, ok := csrfOriginReason(r); !ok {
			authRedirect(w, r, mfaPath, "This form expired. Reload the page and try again.")
			return
		}

		// Resolve the purpose-bound, one-use login challenge.
		cookie, err := requestFlowCookie(r, flowCookieMFA)
		if err != nil || cookie.Value == "" {
			authRedirect(w, r, app.Paths.Login, "Session expired. Please log in again.")
			return
		}
		challenge, err := signInChallengeIdentity(app, app.DB, cookie.Value, tempCookieMFA)
		if err != nil {
			authRedirect(w, r, app.Paths.Login, "Invalid session. Please log in again.")
			return
		}
		userID, email, otpKey := challenge.UserID, challenge.Email, challenge.OTPKey
		passwordSignIn := otpKey != ""

		if code == "" {
			authRedirect(w, r, mfaPath, "MFA code is required")
			return
		}

		// Brute-force lockout - 5 fails / 15 min on the MFA step,
		// keyed separately from the password-login counter so a user
		// who fails MFA doesn't have their password counter ratcheted.
		mfaKey := mfaLockKey(userID)
		defer lockAttempt(mfaKey)() // serialize this account's check→verify→record (lockout race)
		if isAccountLocked(app.DB, mfaKey) {
			authRedirect(w, r, mfaPath, "Too many MFA attempts. Try again in 15 minutes.")
			return
		}

		groupID := ResolveGroupID(app.DB, app.Group, email)
		tx, err := signInWriteTx(app.DB)
		if err != nil {
			serverErrorJSON(w, r, app, "MFA sign-in", err, "Sign-in could not be saved")
			return
		}
		defer tx.Rollback()
		challenge, err = signInChallengeIdentity(app, tx, cookie.Value, tempCookieMFA)
		if err != nil {
			authRedirect(w, r, app.Paths.Login, "Invalid session. Please log in again.")
			return
		}
		if !validateMFACodeWith(tx, userID, code) {
			tx.Rollback()
			recordLoginAttempt(app.DB, mfaKey, false)
			authRedirect(w, r, mfaPath, "Invalid MFA code")
			return
		}
		var sessionID, otpCode, otpToken string
		if err = consumeSignInChallenge(tx, challenge); err == nil {
			if passwordSignIn && otpLoginEnabled(app) {
				otpCode, otpToken, err = prepareLoginOTPTx(app, tx, userID, email, otpKey, challenge.Binding)
			} else {
				sessionID, err = createSignInSessionTx(tx, userID, email, groupID, app.SessionDuration)
			}
		}
		if err == nil {
			_, err = tx.Exec("UPDATE _benmore_users SET last_login_at=datetime('now') WHERE id=?", userID)
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			serverErrorJSON(w, r, app, "MFA sign-in", err, "Sign-in could not be saved")
			return
		}
		recordLoginAttempt(app.DB, mfaKey, true)
		clearFlowCookie(w, flowCookieMFA)
		FireUserHooks(app, "update", userID)
		if otpToken != "" {
			sendLoginOTP(w, r, app, userID, email, otpKey, otpCode, otpToken)
			return
		}
		AttachSessionContext(app.DB, sessionID, r)
		http.SetCookie(w, sessionCookie(sessionID, app.DevMode, app.SessionDuration))

		// A platform CLI login that went through a social provider resumes
		// here, only after the second factor passed.
		if cliPort := oauthPendingCLIPort(w, r, app, userID); cliPort != "" {
			if oauthMintCLIToken(w, r, app, email, cliPort) {
				return
			}
		}

		// A JSON caller gets the user, as from /login; a form post goes on
		// to the page it came for (?next=) or the app's sign-in landing page.
		if authSuccessJSON(w, r, app, userID) {
			return
		}
		redirectTo := "/"
		if app.Design != nil {
			if rd := app.Design.Auth["redirect"]; rd != "" {
				redirectTo = rd
			}
		}
		if next := r.FormValue("next"); isSafeNext(next) {
			redirectTo = next
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
// Replay protection: the last accepted time step is stored in
// `mfa_last_totp` ("s:<step>") and a code for that step or an earlier one
// is refused, so a code can't be replayed inside the drift window.
func ValidateMFACode(db *sql.DB, userID int64, code string) bool {
	// One transaction: a spent backup code and its audit row are written
	// together or not at all.
	tx, err := signInWriteTx(db)
	if err != nil {
		return false
	}
	defer tx.Rollback()
	return validateMFACodeWith(tx, userID, code) && tx.Commit() == nil
}

func validateMFACodeWith(db mutationTx, userID int64, code string) bool {
	if consumeMFATOTPWith(db, userID, code) {
		return true
	}

	// Try backup codes. Atomic compare-and-swap on the JSON column
	// closes the TOCTOU window where two concurrent submissions of the
	// same code could both pass bcrypt before either consumes it.
	var backupJSON string
	if err := db.QueryRow("SELECT COALESCE(backup_codes, '[]') FROM _benmore_users WHERE id = ?", userID).Scan(&backupJSON); err != nil {
		return false
	}
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
				return false // Another request consumed this code first.
			}
			// Recorded where the code is spent: every caller holds a
			// transaction, so a row that cannot be written leaves the code
			// unspent and the step refused.
			actor, err := accountAuditSelf(db, userID)
			if err == nil {
				err = auditAccountEvent(db, nil, accountAuditMFABackupCodeUsed, strconv.FormatInt(userID, 10), actor, nil, map[string]any{"remaining": len(remaining)})
			}
			if err != nil {
				log.Printf("MFA: backup code of user %d refused: %v", userID, err)
				return false
			}
			log.Printf("MFA: backup code used for user %d (%d remaining)", userID, len(remaining))
			return true
		}
	}
	return false
}

// consumeMFATOTPWith is the TOTP-only proof shared by sign-in and factor
// removal. The caller may bind consumption to a larger transaction.
func consumeMFATOTPWith(db mutationTx, userID int64, code string) bool {
	var stored, lastTOTP, lastTOTPAtStr string
	if err := db.QueryRow(`SELECT COALESCE(totp_secret, ''),
		COALESCE(mfa_last_totp, ''), COALESCE(mfa_last_totp_at, '')
		FROM _benmore_users WHERE id = ?`, userID).
		Scan(&stored, &lastTOTP, &lastTOTPAtStr); err != nil {
		return false
	}

	// Try TOTP first. An unverified enrollment is not a factor, and a
	// sealed secret this app's key can't open validates nothing.
	secretB32 := ""
	if stored != "" && !strings.HasPrefix(stored, totpPendingPrefix) {
		secretB32, _ = openTOTPSecret(db, stored)
	}
	if secretB32 != "" {
		if step, ok := matchTOTPStep(secretB32, code, time.Now()); ok {
			// Replay: each time step is spent once, and no step at or before
			// the last accepted one is accepted again - an older code that is
			// still inside the drift window can't be reused after a newer
			// one. mfa_last_totp holds "s:<step>"; a value written before
			// steps were recorded is the code itself (90s rule).
			if last, isStep := strings.CutPrefix(lastTOTP, "s:"); isStep {
				if n, err := strconv.ParseUint(last, 10, 64); err == nil && step <= n {
					return false
				}
			} else if lastTOTP == code && lastTOTPAtStr != "" {
				if ts, err := time.Parse(time.RFC3339, lastTOTPAtStr); err == nil && time.Since(ts) < 90*time.Second {
					return false
				}
			}
			// Compare-and-swap on the value read above, so two concurrent
			// submissions of one code can't both succeed.
			res, err := db.Exec(`UPDATE _benmore_users SET mfa_last_totp = ?, mfa_last_totp_at = ?
				WHERE id = ? AND COALESCE(mfa_last_totp, '') = ? AND totp_secret = ?`,
				"s:"+strconv.FormatUint(step, 10), time.Now().UTC().Format(time.RFC3339), userID, lastTOTP, stored)
			if err != nil {
				return false
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return false
			}
			// A secret stored before sealing is sealed on its first use.
			resealTOTPSecret(db, userID, stored)
			return true
		}
	}

	return false
}

// ===== TOTP Implementation (RFC 6238) =====

// totpKeyURI builds the otpauth:// URI an authenticator app scans, in the Key
// URI Format: otpauth://totp/<issuer>:<account>?secret=…&issuer=…. Every part
// is percent-encoded, so an app name with `&`, `?`, `#` or `%` (site_name is
// free text) can no longer end the label or the issuer parameter early and push
// the secret out of the query. The format forbids a colon inside either label
// part (it separates them), so colons are dropped from the label only; the
// issuer parameter, which authenticators show, keeps the exact name.
func totpKeyURI(issuer, account, secretB32 string) string {
	labelPart := func(s string) string {
		return totpURIEscape(strings.TrimSpace(strings.ReplaceAll(s, ":", "")))
	}
	return "otpauth://totp/" + labelPart(issuer) + ":" + labelPart(account) +
		"?secret=" + totpURIEscape(secretB32) + "&issuer=" + totpURIEscape(issuer) + "&digits=6&period=30"
}

// totpURIEscape percent-encodes s for any part of an otpauth URI. Spaces are
// %20, not "+": the label is a path, and some authenticators show a "+" in the
// issuer parameter literally.
func totpURIEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

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
	_, ok := matchTOTPStep(secretB32, code, time.Now())
	return ok
}

// matchTOTPStep returns the time step (current or ±1 for clock drift) whose
// code matches, so a caller can refuse a step it already accepted.
func matchTOTPStep(secretB32, code string, now time.Time) (uint64, bool) {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		return 0, false
	}
	counter := uint64(now.Unix() / 30)
	for _, offset := range []uint64{0, 1, math.MaxUint64} { // MaxUint64 wraps to -1
		expected := computeHOTP(secret, counter+offset)
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return counter + offset, true
		}
	}
	return 0, false
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
