//go:build !cli

package main

// Authentication route assembly, middleware, and process-wide initialization.
// The auth_*.go files own session, login, CSRF, credential, and recovery behavior.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
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
func RegisterAuthRoutes(mux *http.ServeMux, app *App) {
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
	EnsurePasswordResetsTable(app.DB)
	registerPasswordChangeRoutes(mux, app)
	mux.HandleFunc(fmt.Sprintf("POST %s", app.Paths.ForgotPassword), func(w http.ResponseWriter, r *http.Request) {
		handleForgotPassword(w, r, app)
	})
	mux.HandleFunc(fmt.Sprintf("POST %s", app.Paths.ResetPassword), func(w http.ResponseWriter, r *http.Request) {
		handleResetPassword(w, r, app)
	})
	mux.HandleFunc(fmt.Sprintf("GET %s", app.Paths.VerifyEmail), func(w http.ResponseWriter, r *http.Request) {
		handleVerifyEmail(w, r, app)
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
	EnsureAPITokensTable(app.DB)
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
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		rows, err := QueryRows(app.DB,
			"SELECT id, created_at, expires_at, COALESCE(ip, '') AS ip, COALESCE(user_agent, '') AS user_agent FROM _benmore_sessions WHERE user_id = ? AND datetime(expires_at) > datetime('now') ORDER BY created_at DESC",
			session.UserID)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
			return
		}
		// Replace raw session tokens with truncated SHA-256 hashes - never expose tokens via API
		for _, row := range rows {
			rawID, _ := row["id"].(string)
			h := sha256.Sum256([]byte(rawID))
			opaqueID := hex.EncodeToString(h[:])[:12]
			row["id"] = opaqueID
			row["current"] = rawID == session.ID
		}
		httpJSON(w, http.StatusOK, map[string]any{"sessions": rows})
	})

	mux.HandleFunc("DELETE /api/_auth/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}
		targetHash := r.PathValue("id")
		// Look up real session ID by matching the opaque hash against user's sessions
		sessRows, err := QueryRows(app.DB,
			"SELECT id FROM _benmore_sessions WHERE user_id = ? AND datetime(expires_at) > datetime('now')",
			session.UserID)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "revoke failed"})
			return
		}
		var realID string
		for _, sr := range sessRows {
			rawID, _ := sr["id"].(string)
			h := sha256.Sum256([]byte(rawID))
			if hex.EncodeToString(h[:])[:12] == targetHash {
				realID = rawID
				break
			}
		}
		if realID == "" {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
			return
		}
		app.DB.Exec("DELETE FROM _benmore_sessions WHERE id = ? AND user_id = ?", realID, session.UserID)
		httpJSON(w, http.StatusOK, map[string]any{"status": "revoked"})
	})

	// Impersonation: admin logs in as another user for support
	mux.HandleFunc("POST /api/_auth/impersonate", func(w http.ResponseWriter, r *http.Request) {
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
		var adminHash string
		app.DB.QueryRow("SELECT password_hash FROM _benmore_users WHERE id = ?", session.UserID).Scan(&adminHash)
		if err := bcrypt.CompareHashAndPassword([]byte(adminHash), []byte(body.Password)); err != nil {
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

		// Save admin's original session ID so it can be restored later AND
		// bound to the impersonation record (H-13). Read it from the cookie
		// before we mint the new session.
		adminSessionID := ""
		if cookie, err := r.Cookie(sessionCookieName); err == nil {
			adminSessionID = cookie.Value
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
		app.DB.Exec("UPDATE _benmore_sessions SET is_impersonation = 1, impersonator_session_id = ? WHERE id = ?", adminSessionID, impersonatedSessionID)

		// Audit: log who impersonated whom
		LogAudit(app, "impersonate", "_benmore_users", fmt.Sprintf("%d", body.UserID),
			session, nil, map[string]any{"impersonated_by": session.Email, "target_user": email})

		// Set the impersonation session cookie server-side (replaces admin session).
		// Use protoOf(r) so the Secure flag tracks the public-facing scheme - behind
		// a TLS-terminating proxy r.TLS is always nil even when the user's transport
		// is https. See issue #18.
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
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
		cookie, cookieErr := r.Cookie(sessionCookieName)
		if cookieErr != nil || cookie.Value == "" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "not in an impersonation session"})
			return
		}
		var isImpersonation int
		var impersonatorSessionID string
		app.DB.QueryRow(
			"SELECT COALESCE(is_impersonation, 0), COALESCE(impersonator_session_id, '') FROM _benmore_sessions WHERE id = ?",
			cookie.Value,
		).Scan(&isImpersonation, &impersonatorSessionID)
		if isImpersonation != 1 || impersonatorSessionID == "" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "not in an impersonation session"})
			return
		}
		// The originating admin session must still be a valid, non-expired admin.
		adminSession := GetSessionFromDB(app.DB, impersonatorSessionID)
		if adminSession == nil || !adminSession.IsAdmin() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "originating admin session is no longer valid - please log in again"})
			return
		}
		// Authorized: tear down the impersonation session before restoring.
		app.DB.Exec("DELETE FROM _benmore_sessions WHERE id = ?", cookie.Value)
		// Restore admin session cookie (see #18 - protoOf for proxy-correct Secure flag).
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    impersonatorSessionID,
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
			var adminHash string
			app.DB.QueryRow("SELECT password_hash FROM _benmore_users WHERE id = ?", session.UserID).Scan(&adminHash)
			if err := bcrypt.CompareHashAndPassword([]byte(adminHash), []byte(body.Password)); err != nil {
				log.Printf("act_as: bad password re-auth from user_id=%d email=%s", session.UserID, session.Email)
				httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid password"})
				return
			}
			// Liveness check: the group_id must show up at least once
			// in the configured groups.table (under the configured
			// group key). Avoids stepping into a nonexistent tenant.
			var exists int
			app.DB.QueryRow(
				fmt.Sprintf("SELECT 1 FROM %s WHERE %s = ? LIMIT 1", app.Group.Table, app.Group.Key),
				target,
			).Scan(&exists)
			if exists != 1 {
				httpJSON(w, http.StatusNotFound, map[string]any{"error": "no tenant with that group_id"})
				return
			}
			if _, err := app.DB.Exec("UPDATE _benmore_sessions SET acting_as_group = ? WHERE id = ?", target, session.ID); err != nil {
				httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to set act_as"})
				return
			}
			log.Printf("act_as: admin user_id=%d email=%s stepped into group_id=%s", session.UserID, session.Email, target)
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
			log.Printf("act_as: user_id=%d email=%s exited group_id=%s", session.UserID, session.Email, prev)
			LogAudit(app, "act_as_end", "_benmore_sessions", session.ID, session, nil,
				map[string]any{"prior_group_id": prev, "user_email": session.Email})
			httpJSON(w, http.StatusOK, map[string]any{"status": "cleared"})
		})
	}
}

// tokenAuthIPLimiter caps password attempts at the endpoint level so
// distributed spray (many emails × 5 attempts each) can't bypass the
// per-email lockout. 30 attempts/min/IP is generous for any legitimate
// SDK / CI rotation flow.
var tokenAuthIPLimiter = NewRateLimiter(30, time.Minute)

// forgotPasswordLimiter caps password-reset emails per target address
// (3 per 15 minutes) so a known email can't be inbox-bombed and the
// _benmore_password_resets table can't be flooded. Per-email, distinct
// from the per-IP request limiter.
var forgotPasswordLimiter = NewRateLimiter(3, 15*time.Minute)

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
