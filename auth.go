//go:build !cli

package main

// Authentication route assembly, middleware, and process-wide initialization.
// The auth_*.go files own session, login, CSRF, credential, and recovery behavior.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// serverSecret is generated once on startup. Used for HMAC-based CSRF tokens.
// Persists for the lifetime of the process. CSRF tokens derived from session + secret.
var serverSecret string

func init() {
	// Prefer a stable env-provided secret so CSRF tokens, signed URLs,
	// and edge-auth tokens survive process restarts and (more importantly)
	// validate consistently across cluster instances. Falls back to a
	// random per-process value when the env var is missing - convenient
	// for single-instance dev, but a noisy warning lands so production
	// operators notice and provision one.
	// Use GetEnv (not os.Getenv) so the lookup falls through to
	// $CREDENTIALS_DIRECTORY/benmore_server_secret when the value is
	// provided via systemd LoadCredential= instead of Environment=.
	if s := GetEnv("", "BENMORE_SERVER_SECRET"); len(s) >= 32 {
		serverSecret = s
	} else {
		serverSecret = generateToken(32)
		// Warn only for long-running server commands (serve/host/router)
		// where an ephemeral secret breaks CSRF on restart and across
		// cluster instances. Short-lived CLI subcommands (push, pull,
		// whoami, deploy, apps, login, env, …) never reuse the secret
		// across processes, so the warning is just noise - and worse,
		// it pollutes JSON-shaped output that calling agents try to
		// parse. Keep the legacy BENMORE_SUPPRESS_SECRET_WARN escape
		// hatch so existing systemd drop-ins still work.
		if os.Getenv("BENMORE_SUPPRESS_SECRET_WARN") == "" && needsStableSecret(os.Args) {
			log.Printf("WARN: BENMORE_SERVER_SECRET not set (or <32 chars); using ephemeral per-process value. CSRF/signed-URL/edge tokens will not survive restart and will fail across cluster instances. Set BENMORE_SERVER_SECRET to a 32+ char random string.")
		}
	}
}

// needsStableSecret returns true when the invocation is a long-running
// server command (serve / host / router) that needs CSRF + signed-URL
// tokens to survive process restarts. CLI subcommands return false and
// silence the warning. Default: true - when we can't tell what's being
// run (no args), assume server mode so we don't accidentally hide a
// real misconfig.
func needsStableSecret(args []string) bool {
	if len(args) < 2 {
		return true
	}
	switch args[1] {
	case "serve", "host", "router", "dev":
		return true
	}
	return false
}

// AuthMiddleware checks authentication for pages that require it.
func AuthMiddleware(app *App, page *Page, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if page.Auth == "none" || page.Auth == "" {
			next(w, r)
			return
		}

		session := getSession(app, r)
		if session == nil {
			if isHTMX(r) {
				w.Header().Set("HX-Redirect", app.Paths.Login)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}

// RegisterAuthRoutes adds login, signup, logout routes.
func RegisterAuthRoutes(mux appRouteRegistrar, app *App) {
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	EnsureLoginAttemptsTable(app.DB)
	EnsureUserRolesTable(app.DB)
	CleanExpiredSessions(app)
	StartRoleExpirySweeper(app)

	// Apply configurable session duration from app.yaml - stored per-app, not global
	app.SessionDuration = defaultSessionDuration
	if app.Design != nil {
		if dur := app.Design.Auth["session_duration"]; dur != "" {
			app.SessionDuration = ParseSessionDuration(dur)
		}
	}

	EnsurePasswordResetsTable(app.DB)
	EnsureAPITokensTable(app.DB)
	EnsureAuditLogTable(app.DB)
	registerAuthRoutes(mux, app)
}

func registerAuthRoutes(mux appRouteRegistrar, app *App) {
	// POST handlers registered at discovered paths - no auto-generated GET pages.
	// The developer creates their own pages with type="login", type="signup", etc.
	// Errors are returned via ?error= query param (shown with {{param_error}}).
	mux.HandleFunc(fmt.Sprintf("POST %s", app.Paths.Login), func(w http.ResponseWriter, r *http.Request) {
		handleLogin(w, r, app)
	})
	mux.HandleFunc(fmt.Sprintf("POST %s", app.Paths.Signup), func(w http.ResponseWriter, r *http.Request) {
		handleSignup(w, r, app)
	})
	mux.HandleFunc(fmt.Sprintf("POST %s", app.Paths.Logout), func(w http.ResponseWriter, r *http.Request) {
		handleLogout(w, r, app)
	})
	mux.HandleFunc(fmt.Sprintf("POST %s", app.Paths.VerifyOTP), func(w http.ResponseWriter, r *http.Request) {
		handleVerifyOTP(w, r, app)
	})

	// Password reset
	registerPasswordChangeHandlers(mux, app)
	mux.HandleFunc(fmt.Sprintf("POST %s", app.Paths.ForgotPassword), func(w http.ResponseWriter, r *http.Request) {
		handleForgotPassword(w, r, app)
	})
	mux.HandleFunc(fmt.Sprintf("POST %s", app.Paths.ResetPassword), func(w http.ResponseWriter, r *http.Request) {
		handleResetPassword(w, r, app)
	})
	mux.HandleFunc(fmt.Sprintf("GET %s", app.Paths.VerifyEmail), func(w http.ResponseWriter, r *http.Request) {
		handleVerifyEmail(w, r, app)
	})
	// A link opened outside the account's session proves the password here.
	mux.HandleFunc(fmt.Sprintf("POST %s", app.Paths.VerifyEmail), func(w http.ResponseWriter, r *http.Request) {
		handleVerifyEmailConfirm(w, r, app)
	})

	// CSRF token fetch - for vanilla-HTML apps that prefer fetching the
	// token over reading the auto-injected <meta> tag, or for cases where
	// the meta tag has gone stale (page open for 24h+). Tokens are
	// stateless HMACs so this endpoint is read-only and side-effect-free.
	mux.HandleFunc("GET /api/_csrf", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		// H-11: bind the issued token to THIS request's session id when
		// one is present, so a token fetched from this unauthenticated
		// endpoint only validates mutations from the same session. A
		// session-less caller (pre-login) still gets a back-compat
		// unbound token (sid="").
		httpJSON(w, http.StatusOK, map[string]any{"token": authMintCSRFToken(authRawSessionID(r))})
	})

	// Token auth: native/API clients exchange email+password for a Bearer token
	mux.HandleFunc("POST /api/_auth/token", func(w http.ResponseWriter, r *http.Request) {
		handleTokenAuth(w, r, app)
	})

	// Persistent API tokens (hash-stored, prefixed with bmr_)
	mux.HandleFunc("POST /api/_auth/api-tokens", func(w http.ResponseWriter, r *http.Request) {
		handleCreateAPIToken(w, r, app)
	})
	mux.HandleFunc("GET /api/_auth/api-tokens", func(w http.ResponseWriter, r *http.Request) {
		handleListAPITokens(w, r, app)
	})
	mux.HandleFunc("DELETE /api/_auth/api-tokens/{id}", func(w http.ResponseWriter, r *http.Request) {
		handleRevokeAPIToken(w, r, app)
	})

	// Session management: list and revoke active sessions
	mux.HandleFunc("GET /api/_auth/sessions", func(w http.ResponseWriter, r *http.Request) {
		if accountSettingsDisabled(w, r, app) {
			return
		}
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		if !requireOwnAccountManagement(w, app, session) {
			return
		}
		// The list is the person's own sign-ins. A support impersonation
		// session, or one platform tooling minted to act as the user, is a
		// row under the same user id but carries the support admin's address
		// and browser; it is neither shown here nor revocable below
		// (userOwnSessionsSQL). The audit log is where support access is
		// recorded.
		rows, err := queryMetadataRows(app.DB,
			"SELECT id, created_at, expires_at, COALESCE(ip, '') AS ip, COALESCE(user_agent, '') AS user_agent FROM _benmore_sessions WHERE "+userOwnSessionsSQL+" ORDER BY created_at DESC",
			session.UserID)
		if err != nil {
			serverErrorJSON(w, r, app, "sessions", err, "query failed")
			return
		}
		// List a short, stable id rather than the stored key: the first 12
		// hex digits of the credential's SHA-256 (sessionOpaqueID).
		for _, row := range rows {
			storedID, _ := row["id"].(string)
			row["id"] = sessionOpaqueID(storedID)
			row["current"] = storedID == session.ID
		}
		httpJSON(w, http.StatusOK, map[string]any{"sessions": rows})
	})

	mux.HandleFunc("DELETE /api/_auth/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		if accountSettingsDisabled(w, r, app) {
			return
		}
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		if !requireOwnAccountManagement(w, app, session) {
			return
		}
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}
		targetHash := r.PathValue("id")
		// Look up real session ID by matching the opaque hash against user's sessions
		sessRows, err := queryMetadataRows(app.DB,
			"SELECT id FROM _benmore_sessions WHERE "+userOwnSessionsSQL,
			session.UserID)
		if err != nil {
			serverErrorJSON(w, r, app, "sessions", err, "revoke failed")
			return
		}
		var realID string
		for _, sr := range sessRows {
			storedID, _ := sr["id"].(string)
			if sessionOpaqueID(storedID) == targetHash {
				realID = storedID
				break
			}
		}
		if realID == "" {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
			return
		}
		app.DB.Exec("DELETE FROM _benmore_sessions WHERE id = ? AND user_id = ?", realID, session.UserID)
		invalidateRequestSession(r) // the revoked session may be this one
		httpJSON(w, http.StatusOK, map[string]any{"status": "revoked"})
	})

	// Impersonation: admin logs in as another user for support
	mux.HandleFunc("POST /api/_auth/impersonate", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		// The result is a full-access session as someone else, so a scoped
		// credential can't start it (same rule as role grants).
		if session == nil || !session.IsAdmin() || !sessionHasFullAccess(session) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin with a full-access session required"})
			return
		}
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}

		var body struct {
			UserID   int64  `json:"user_id"`
			Password string `json:"password"` // re-auth: admin must confirm their own password
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.UserID == 0 {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "user_id required"})
			return
		}

		// Re-authentication: require admin's own password to prevent stolen-session abuse
		if body.Password == "" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "password required for impersonation"})
			return
		}
		if ok, locked := currentPasswordMatches(app, session.UserID, body.Password); !ok {
			if locked {
				httpJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many attempts, try again in 15 minutes"})
				return
			}
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid password"})
			return
		}

		// Look up target user
		var email, role string
		err := app.DB.QueryRow("SELECT COALESCE(email, ''), COALESCE(role, 'user') FROM _benmore_users WHERE id = ?", body.UserID).Scan(&email, &role)
		if err != nil {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "user not found"})
			return
		}
		// Support impersonation is for seeing what a user sees, not for
		// borrowing another administrator's identity: that would let one
		// admin act (and be audited) as another. Refuse admin targets -
		// the primary role or a global admin grant, the same test IsAdmin
		// applies.
		if role == "admin" || UserHasGlobalAdminGrant(app.DB, body.UserID) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "administrators cannot be impersonated"})
			return
		}

		// Record the admin's cookie session so it can be restored later AND
		// bound to the impersonation record (H-13). This is the session's
		// stored key, never the cookie value: the row must not hold a
		// credential.
		adminSessionID := ""
		if cookie, err := requestSessionCookie(r); err == nil {
			if key, ok := presentedSessionKey(cookie.Value); ok && (key == session.ID || cookie.Value == session.ID) {
				adminSessionID = session.ID
			}
		}

		// Create impersonation session with 1-hour TTL (shorter than normal sessions)
		groupID := ResolveGroupID(app.DB, app.Group, email)
		impersonationDuration := 1 * time.Hour
		impersonatedSessionID := CreateSession(app.DB, body.UserID, email, groupID, impersonationDuration)

		AttachSessionContext(app.DB, impersonatedSessionID, r)

		// Mark session as impersonation AND record the originating admin
		// session id (H-13). end-impersonation will require the presented
		// admin_token to equal this exact session - not merely "some valid
		// admin token".
		// The admin's own identity is stored on the row too, so every audit
		// entry written through this session names the real actor even after
		// the originating admin session is gone. Without the marker the
		// session must not be handed out: its actions would read as the
		// target's alone.
		if impersonatedSessionID == "" {
			serverErrorJSON(w, r, app, "impersonation", errors.New("the impersonation session could not be created"), "could not start impersonation")
			return
		}
		if _, err := app.DB.Exec("UPDATE _benmore_sessions SET is_impersonation = 1, impersonator_session_id = ?, impersonator_user_id = ?, impersonator_email = ? WHERE id = ?",
			adminSessionID, session.UserID, session.Email, sessionStorageKey(impersonatedSessionID)); err != nil {
			DeleteSessionFromDB(app.DB, impersonatedSessionID)
			serverErrorJSON(w, r, app, "impersonation", err, "could not start impersonation")
			return
		}
		invalidateRequestSession(r)

		// Audit: log who impersonated whom
		LogAudit(app, "impersonate", "_benmore_users", fmt.Sprintf("%d", body.UserID),
			session, nil, map[string]any{"impersonated_by": session.Email, "target_user": email})

		// Set the impersonation session cookie server-side (replaces admin session).
		// Use protoOf(r) so the Secure flag tracks the public-facing scheme - behind
		// a TLS-terminating proxy r.TLS is always nil even when the user's transport
		// is https. See issue #18.
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieNameFor(protoOf(r) == "https"),
			Value:    impersonatedSessionID,
			Path:     "/",
			MaxAge:   3600, // 1 hour
			HttpOnly: true,
			Secure:   protoOf(r) == "https",
			SameSite: http.SameSiteLaxMode,
		})

		// NOTE: the originating admin session id is NOT returned. end-impersonation
		// restores it server-side from impersonator_session_id on the impersonation
		// row, so echoing the raw admin token here would only be an exfil risk.
		httpJSON(w, http.StatusOK, map[string]any{
			"token":      impersonatedSessionID,
			"user_id":    body.UserID,
			"email":      email,
			"role":       role,
			"expires_in": "1h",
			"admin_note": "Impersonated session - 1h TTL, all actions audited",
		})
	})

	// End impersonation: restore admin session
	mux.HandleFunc("POST /api/_auth/end-impersonation", func(w http.ResponseWriter, r *http.Request) {
		// CSRF protection
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}
		// Restore the ORIGINATING admin session recorded on this impersonation
		// session row (impersonator_session_id, set at start). Driven entirely
		// server-side from the caller's impersonation cookie - the client never
		// supplies, and the impersonate response never echoes, the admin token.
		// This closes the round-2 pivot where a leaked admin_token plus any
		// valid admin session could restore into that admin (H-13).
		cookie, cookieErr := requestSessionCookie(r)
		if cookieErr != nil || cookie.Value == "" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "not in an impersonation session"})
			return
		}
		cookieKey, ok := presentedSessionKey(cookie.Value)
		if !ok {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "not in an impersonation session"})
			return
		}
		var impersonationID string
		var isImpersonation int
		var impersonatorSessionID string
		app.DB.QueryRow(
			// An expired impersonation ends nothing; its row just awaits cleanup.
			"SELECT id, COALESCE(is_impersonation, 0), COALESCE(impersonator_session_id, '') FROM _benmore_sessions WHERE id IN (?, ?) AND datetime(expires_at) > datetime('now')",
			cookieKey, cookie.Value,
		).Scan(&impersonationID, &isImpersonation, &impersonatorSessionID)
		if isImpersonation != 1 || impersonatorSessionID == "" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "not in an impersonation session"})
			return
		}
		// The originating admin session must still be a valid, non-expired admin.
		adminSession := getSessionByStoredID(app.DB, impersonatorSessionID)
		if adminSession == nil || !adminSession.IsAdmin() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "originating admin session is no longer valid - please log in again"})
			return
		}
		// Authorized: tear down the impersonation session and hand the admin
		// session back under a fresh token. Only its hash is stored, so the
		// admin's original cookie value can't be recovered; rekeying the row
		// keeps everything else about the session (expiry, tenant, act-as).
		restoredToken := generateToken(32)
		tx, err := app.DB.Begin()
		if err != nil {
			serverErrorJSON(w, r, app, "impersonation", err, "could not end impersonation")
			return
		}
		defer tx.Rollback()
		// Both statements must hit exactly their row: a concurrent end (a
		// double submit) already moved the admin session, and handing out a
		// second token would replace the first with one that matches nothing.
		res, err := tx.Exec("DELETE FROM _benmore_sessions WHERE id = ?", impersonationID)
		if err != nil {
			serverErrorJSON(w, r, app, "impersonation", err, "could not end impersonation")
			return
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			httpJSON(w, http.StatusConflict, map[string]any{"error": "impersonation already ended"})
			return
		}
		if moved, err := rekeySession(tx, impersonatorSessionID, sessionStorageKey(restoredToken)); err != nil || !moved {
			httpJSON(w, http.StatusConflict, map[string]any{"error": "originating admin session is no longer valid - please log in again"})
			return
		}
		if err := tx.Commit(); err != nil {
			serverErrorJSON(w, r, app, "impersonation", err, "could not end impersonation")
			return
		}
		invalidateRequestSession(r) // this request's session row is gone
		// Restore admin session cookie (see #18 - protoOf for proxy-correct Secure flag).
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieNameFor(protoOf(r) == "https"),
			Value:    restoredToken,
			Path:     "/",
			MaxAge:   int(app.SessionDuration.Seconds()),
			HttpOnly: true,
			Secure:   protoOf(r) == "https",
			SameSite: http.SameSiteLaxMode,
		})
		httpJSON(w, http.StatusOK, map[string]any{"status": "restored", "email": adminSession.Email})
	})

	// Group switching: allows users who belong to multiple groups to switch context
	if app.Group != nil {
		mux.HandleFunc("POST /api/_switch_group", func(w http.ResponseWriter, r *http.Request) {
			handleSwitchGroup(w, r, app)
		})
	}

	// Admin step-in (act-as-group). Lets a platform admin opt INTO
	// per-tenant scoping for the duration of one session: while the
	// session is "acting as" a tenant, every read filters to that
	// tenant and every write auto-injects its group_key, exactly as
	// it would for an ordinary member of that group. The admin's
	// Role stays "admin" so /platform and /admin remain reachable;
	// only the data-scoping rule changes. Tenants are unaffected -
	// their isolation never depended on admins behaving.
	//
	//   GET    /api/_auth/act_as                     → { acting_as_group, role }
	//   POST   /api/_auth/act_as  { group_id: "7" }  → 200 {status:"acting_as", ...}
	//   DELETE /api/_auth/act_as                     → 200 {status:"cleared"}
	//
	// Admin-only. Persisted on _benmore_sessions.acting_as_group so it
	// survives router restarts and is visible in the audit trail.
	if app.Group != nil {
		mux.HandleFunc("GET /api/_auth/act_as", func(w http.ResponseWriter, r *http.Request) {
			session := getSession(app, r)
			if session == nil {
				httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
				return
			}
			httpJSON(w, http.StatusOK, map[string]any{
				"role":            session.Role,
				"group_id":        session.GroupID,
				"acting_as_group": session.ActingAsGroup,
				"effective_group": session.EffectiveGroupID(),
				"bypass":          session.IsAdminBypass(),
			})
		})

		mux.HandleFunc("POST /api/_auth/act_as", func(w http.ResponseWriter, r *http.Request) {
			session := getSession(app, r)
			if session == nil || !session.IsAdmin() {
				httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
				return
			}
			if !isBearerAuth(r) && !validateCSRF(r) {
				httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
				return
			}
			var body struct {
				GroupID  string `json:"group_id"`
				Password string `json:"password"` // re-auth: admin must confirm their own password (mirrors /impersonate)
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			target := strings.TrimSpace(body.GroupID)
			if target == "" || target == "0" {
				httpJSON(w, http.StatusBadRequest, map[string]any{"error": "group_id required (use DELETE to clear)"})
				return
			}
			// Re-authentication: require the admin's own password to
			// start step-in. Closes the stolen-cookie attack - even with
			// a valid session, the attacker also needs the admin's
			// password to scope themselves into a tenant. Same shape as
			// /api/_auth/impersonate. The DELETE (exit step-in) endpoint
			// doesn't need re-auth - exiting only RESTORES admin bypass,
			// which the attacker already had via the stolen cookie.
			if strings.TrimSpace(body.Password) == "" {
				httpJSON(w, http.StatusBadRequest, map[string]any{"error": "password required to start step-in"})
				return
			}
			if ok, locked := currentPasswordMatches(app, session.UserID, body.Password); !ok {
				log.Printf("act_as: bad password re-auth from user_id=%d", session.UserID)
				if locked {
					httpJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many attempts, try again in 15 minutes"})
					return
				}
				httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid password"})
				return
			}
			// Liveness check: the group_id must show up at least once
			// in the configured groups.table (under the configured
			// group key). Avoids stepping into a nonexistent tenant.
			var exists int
			app.DB.QueryRow(
				"SELECT 1 FROM "+quoteIdent(app.Group.Table)+" WHERE "+quoteColumn(app.Group.Table, app.Group.Key)+" = ? LIMIT 1",
				target,
			).Scan(&exists)
			if exists != 1 {
				httpJSON(w, http.StatusNotFound, map[string]any{"error": "no tenant with that group_id"})
				return
			}
			// Step-in lives on the session row. An API token or edge identity
			// has none, so the UPDATE matches nothing: answering "acting_as"
			// then left the caller with its cross-tenant bypass while it
			// believed it was scoped to one tenant.
			res, err := app.DB.Exec("UPDATE _benmore_sessions SET acting_as_group = ? WHERE id = ?", target, session.ID)
			if err != nil {
				serverErrorJSON(w, r, app, "act_as", err, "failed to set act_as")
				return
			}
			if n, err := res.RowsAffected(); err != nil || n != 1 {
				httpJSON(w, http.StatusBadRequest, map[string]any{"error": "step-in needs a sign-in session: an API token or edge identity can't hold it (sign in, or exchange the password at POST /api/_auth/token for a session token)"})
				return
			}
			invalidateRequestSession(r)
			log.Printf("act_as: admin user_id=%d stepped into group_id=%s", session.UserID, target)
			LogAudit(app, "act_as_start", "_benmore_sessions", session.ID, session, nil,
				map[string]any{"target_group_id": target, "admin_email": session.Email})
			httpJSON(w, http.StatusOK, map[string]any{
				"status":          "acting_as",
				"acting_as_group": target,
			})
		})

		// DELETE /api/_auth/act_as - step OUT of an active impersonation.
		//
		// v2.7.59+: this does NOT require admin role. Stepping out
		// is the operation that RESTORES the caller's native authority,
		// not one that grants new authority. Requiring admin here had
		// a real lockout failure mode: a group-scoped admin who'd
		// stepped into a tenant where they had no admin grants would
		// see session.IsAdmin()=false in the new context and become
		// permanently stuck - unable to step out. The fix: anyone
		// with an active ActingAsGroup can clear it.
		//
		// We still verify ActingAsGroup is non-empty so this can't
		// be used as a no-op pivot or trigger spurious audit entries.
		mux.HandleFunc("DELETE /api/_auth/act_as", func(w http.ResponseWriter, r *http.Request) {
			session := getSession(app, r)
			if session == nil {
				httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
				return
			}
			if !isBearerAuth(r) && !validateCSRF(r) {
				httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
				return
			}
			if session.ActingAsGroup == "" {
				// Idempotent - already not in step-in. Not an error;
				// matches the "DELETE on a clean slate is fine"
				// REST convention.
				httpJSON(w, http.StatusOK, map[string]any{"status": "already_cleared"})
				return
			}
			prev := session.ActingAsGroup
			app.DB.Exec("UPDATE _benmore_sessions SET acting_as_group = '' WHERE id = ?", session.ID)
			invalidateRequestSession(r)
			log.Printf("act_as: user_id=%d exited group_id=%s", session.UserID, prev)
			LogAudit(app, "act_as_end", "_benmore_sessions", session.ID, session, nil,
				map[string]any{"prior_group_id": prev, "user_email": session.Email})
			httpJSON(w, http.StatusOK, map[string]any{"status": "cleared"})
		})
	}
}

// authFeatureDisabled keeps direct handler calls and route aliases behind the
// same app.yaml opt-out; an omitted setting preserves the historical default.
func authFeatureDisabled(app *App, key string) bool {
	return app != nil && app.Design != nil && app.Design.Auth[key] == "false"
}

func refuseDisabledAuthFeature(w http.ResponseWriter, r *http.Request, app *App, key string) bool {
	if !authFeatureDisabled(app, key) {
		return false
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		httpJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	} else {
		http.NotFound(w, r)
	}
	return true
}

// userOwnSessionsSQL selects the live sessions a user started themselves (one
// argument: the user id). Rows marked is_impersonation - an admin's support
// session as the user, or a delegated session minted by platform tooling -
// belong to someone else acting as the user and are not theirs to list or
// revoke one by one; a password change or reset still ends them with the rest.
const userOwnSessionsSQL = "user_id = ? AND datetime(expires_at) > datetime('now') AND COALESCE(is_impersonation, 0) = 0"

// tokenAuthIPLimiter caps password attempts at the endpoint level so
// distributed spray (many emails × 5 attempts each) can't bypass the
// per-email lockout. 30 attempts/min/IP is generous for any legitimate
// SDK / CI rotation flow.
var tokenAuthIPLimiter = NewRateLimiter(30, time.Minute)

// forgotPasswordLimiter caps password-reset emails per target mailbox
// (3 per 15 minutes) so a known email can't be inbox-bombed and the
// _benmore_password_resets table can't be flooded. Per mailbox
// (mailboxRateKey: plus-variants of one inbox share the budget), distinct
// from the per-IP request limiter.
var forgotPasswordLimiter = NewRateLimiter(recipientMailRate, recipientMailWindow)

// NeedsAuth returns true if the app uses authentication - either a page
// is explicitly gated with auth="required", or the app declares an auth
// block in app.yaml. The latter covers SPAs (engine: raw) that handle
// login/signup inside the bundle and so never set auth="required" on a
// page, but still need POST /login + POST /signup endpoints registered.
func NeedsAuth(app *App) bool {
	if app == nil {
		return false
	}
	for _, p := range app.Pages {
		if p.Auth == "required" {
			return true
		}
	}
	if app.Design != nil && len(app.Design.Auth) > 0 {
		return true
	}
	return false
}

// Ensure imports are used
var _ = sql.ErrNoRows
