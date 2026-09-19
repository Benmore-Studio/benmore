//go:build !cli

package main

// Session persistence, request identity resolution, and tenant role scopes.
// Auth routes and process-wide secret initialization remain in auth.go.

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

const sessionCookieName = "_benmore_session"

// EnsureSessionsTable creates the sessions table.
func EnsureSessionsTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_sessions (
		id TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		email TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	// Add org_id column if missing (for org-scoped apps)
	db.Exec("ALTER TABLE _benmore_sessions ADD COLUMN group_id INTEGER DEFAULT 0")
	// Add scopes column if missing (for scoped tokens)
	db.Exec("ALTER TABLE _benmore_sessions ADD COLUMN scopes TEXT DEFAULT ''")
	// Add is_impersonation column if missing (marks admin-impersonated sessions)
	db.Exec("ALTER TABLE _benmore_sessions ADD COLUMN is_impersonation INTEGER DEFAULT 0")
	// H-13: bind each impersonation session to the EXACT admin session that
	// started it. end-impersonation requires the supplied admin_token to
	// resolve to this originating session id - so a leaked impersonation
	// response (which echoes admin_token) plus any other valid admin token
	// can no longer pivot into the original admin's session.
	db.Exec("ALTER TABLE _benmore_sessions ADD COLUMN impersonator_session_id TEXT DEFAULT ''")
	// Add ip + user_agent columns so the Sessions tab on /profile can
	// show a real device label instead of "unknown ip". Captured by
	// AttachSessionContext right after CreateSession.
	db.Exec("ALTER TABLE _benmore_sessions ADD COLUMN ip TEXT DEFAULT ''")
	db.Exec("ALTER TABLE _benmore_sessions ADD COLUMN user_agent TEXT DEFAULT ''")
	// acting_as_group: admin step-in target. While non-empty, the
	// session's effective tenant is this value (see Session.EffectiveGroupID
	// and IsAdminBypass). Cleared on POST /api/_auth/act_as with no body.
	db.Exec("ALTER TABLE _benmore_sessions ADD COLUMN acting_as_group TEXT DEFAULT ''")
	// Cleanup expired on startup
	db.Exec("DELETE FROM _benmore_sessions WHERE datetime(expires_at) < datetime('now')")
}

// AttachSessionContext records the originating IP + user-agent on a
// session row. Called right after CreateSession from any handler that
// has the *http.Request available. Best-effort - failures are logged
// and ignored (the session is already valid).
func AttachSessionContext(db *sql.DB, sessionID string, r *http.Request) {
	if sessionID == "" || r == nil {
		return
	}
	ua := r.UserAgent()
	if len(ua) > 240 {
		ua = ua[:240]
	}
	if _, err := db.Exec(
		"UPDATE _benmore_sessions SET ip = ?, user_agent = ? WHERE id = ?",
		clientIP(r), ua, sessionID,
	); err != nil {
		log.Printf("session context update failed (id=%s): %v", sessionID[:8], err)
	}
}

// NewSessionStore creates a session store backed by SQLite.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Session),
	}
}

// ResolveMembershipRole reads the member's in-tenant role from the
// groups membership table (groups.role_field, v2.7.164) for the given
// effective group. Empty string when unset, unconfigured, or the user
// has no membership row in that group.
func ResolveMembershipRole(db *sql.DB, group *GroupConfig, email, effectiveGroupID string) string {
	if group == nil || group.Table == "" || group.Key == "" || group.UserField == "" || group.RoleField == "" || effectiveGroupID == "" {
		return ""
	}
	var role sql.NullString
	query := fmt.Sprintf("SELECT %s FROM %s WHERE %s = ? AND %s = ? LIMIT 1",
		group.RoleField, group.Table, group.UserField, group.Key)
	if err := db.QueryRow(query, email, effectiveGroupID).Scan(&role); err != nil {
		return ""
	}
	if !role.Valid {
		return ""
	}
	return strings.TrimSpace(role.String)
}

// ResolveGroupID looks up the user's organization from the configured
// membership table. v2.5.10: returns string (was int64) so UUID/slug/
// opaque-ID tenant keys work natively. Empty string means "no group".
func ResolveGroupID(db *sql.DB, group *GroupConfig, email string) string {
	if group == nil || group.Table == "" || group.Key == "" || group.UserField == "" {
		return ""
	}
	var groupID sql.NullString
	query := fmt.Sprintf("SELECT %s FROM %s WHERE %s = ? AND %s IS NOT NULL LIMIT 1",
		group.Key, group.Table, group.UserField, group.Key)
	if err := db.QueryRow(query, email).Scan(&groupID); err != nil {
		return ""
	}
	if !groupID.Valid {
		return ""
	}
	return groupID.String
}

const defaultSessionDuration = 30 * 24 * time.Hour // 30 days

// ParseSessionDuration parses duration strings like "30d", "7d", "24h", "1h".
func ParseSessionDuration(s string) time.Duration {
	if s == "" {
		return defaultSessionDuration
	}
	// Try standard Go duration first (e.g., "24h", "1h30m")
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	// Handle "Nd" (days) format
	var n int
	if _, err := fmt.Sscanf(s, "%dd", &n); err == nil && n > 0 {
		return time.Duration(n) * 24 * time.Hour
	}
	return defaultSessionDuration
}

// CreateSession creates a persistent session in SQLite. v2.5.10:
// groupID is now string (was int64). SQLite's group_id column has
// INTEGER affinity but dynamic typing accepts the string; UUID/slug
// tenant keys round-trip correctly.
func CreateSession(db *sql.DB, userID int64, email string, groupID string, duration time.Duration, scopes ...string) string {
	id := generateToken(32)
	if duration <= 0 {
		duration = defaultSessionDuration
	}
	expires := time.Now().Add(duration)
	scopeStr := ""
	if len(scopes) > 0 {
		scopeStr = scopes[0]
	}
	if _, err := db.Exec("INSERT INTO _benmore_sessions (id, user_id, email, group_id, scopes, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
		id, userID, email, groupID, scopeStr, expires.UTC().Format(time.RFC3339)); err != nil {
		log.Printf("ERROR creating session: %s", err)
		return ""
	}
	return id
}

// GetSessionFromDB retrieves a session from SQLite.
// Joins _benmore_users in a single query to get role, deactivated_at, and verified
// without extra round-trips.
func GetSessionFromDB(db *sql.DB, id string) *Session {
	if id == "" {
		return nil
	}
	var userID int64
	var email string
	// group_id may be either an INTEGER (legacy) or TEXT (UUID tenants
	// post v2.5.10). sql.NullString accepts both - SQLite's text
	// affinity coerces INT values to their decimal string form on read.
	var groupID sql.NullString
	var scopes string
	var role string
	var deactivatedAt sql.NullString
	var verified int
	var actingAs sql.NullString
	err := db.QueryRow(`
		SELECT s.user_id, s.email, COALESCE(s.group_id, ''), COALESCE(s.scopes, ''),
		       COALESCE(u.role, 'user'), u.deactivated_at, COALESCE(u.verified, 0),
		       COALESCE(s.acting_as_group, '')
		FROM _benmore_sessions s
		JOIN _benmore_users u ON u.id = s.user_id
		WHERE s.id = ? AND datetime(s.expires_at) > datetime('now')
		  AND COALESCE(u.password_change_required, 0) = 0`,
		id,
	).Scan(&userID, &email, &groupID, &scopes, &role, &deactivatedAt, &verified, &actingAs)
	if err != nil {
		return nil
	}
	// Block deactivated users at session resolution - no further processing
	if deactivatedAt.Valid && deactivatedAt.String != "" {
		return nil
	}
	gid := ""
	if groupID.Valid && groupID.String != "0" {
		gid = groupID.String
	}
	s := &Session{ID: id, UserID: userID, Email: email, GroupID: gid, Role: role, Scopes: scopes}
	s.Verified = verified == 1
	if actingAs.Valid && actingAs.String != "" && actingAs.String != "0" {
		s.ActingAsGroup = actingAs.String
	}
	// Multi-role: load assignments from _benmore_user_roles and dedupe
	// against the primary role. The join table is created lazily on
	// first auth boot - querying it before it exists silently returns
	// just the primary role (LoadSessionRoles swallows the error).
	//
	// v2.7.59+: pass the effective group ID so tenant-scoped role
	// grants only apply when the session is actually in that group's
	// context (native group OR act-as target). EffectiveGroupID
	// returns the act-as target when set, otherwise the native GroupID,
	// otherwise empty (apps without `groups:` config, or users with
	// no group membership yet - both cases mean "globals only").
	s.Roles = LoadSessionRoles(db, userID, role, s.EffectiveGroupID())
	// GlobalAdmin (cross-tenant bypass eligibility) comes ONLY from the
	// primary role column or a NULL-group admin grant - never from a
	// group-scoped grant or a (client-writable) membership role.
	s.GlobalAdmin = role == "admin" || UserHasGlobalAdminGrant(db, userID)
	return s
}

// DeleteSessionFromDB removes a session from SQLite.
func DeleteSessionFromDB(db *sql.DB, id string) {
	if _, err := db.Exec("DELETE FROM _benmore_sessions WHERE id = ?", id); err != nil {
		log.Printf("ERROR deleting session: %s", err)
	}
}

// CleanExpiredSessions removes expired sessions periodically.
func CleanExpiredSessions(app *App) {
	if app == nil || app.DB == nil {
		return
	}
	safeGo("auth.cleanExpiredSessions", func() {
		stop := app.Stop
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				app.DB.Exec("DELETE FROM _benmore_sessions WHERE datetime(expires_at) < datetime('now')")
				app.DB.Exec("DELETE FROM _benmore_api_tokens WHERE expires_at IS NOT NULL AND datetime(expires_at) < datetime('now')")
			}
		}
	})
}

// sessionCookie builds a session cookie with proper security flags.
func sessionCookie(sessionID string, devMode bool, duration time.Duration) *http.Cookie {
	if duration <= 0 {
		duration = defaultSessionDuration
	}
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(duration.Seconds()),
	}
	// Set Secure flag in production (HTTPS only)
	if !devMode {
		cookie.Secure = true
	}
	return cookie
}

// ===== Session Helpers =====

// isPersistentAPIToken reports whether a bearer value is a hash-stored
// _benmore_api_tokens credential rather than a raw session id. Two mints
// exist: user-created tokens ("bmr_", /api/_auth/api-tokens) and per-app
// OAuth access tokens ("bma_", app_oauth.go token endpoint).
func isPersistentAPIToken(tok string) bool {
	return strings.HasPrefix(tok, "bmr_") || strings.HasPrefix(tok, "bma_")
}

func getSession(app *App, r *http.Request) *Session {
	var session *Session

	// 1. Cookie (web clients) - always a session ID, never scoped
	if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
		session = GetSessionFromDB(app.DB, cookie.Value)
	}

	// 2. Bearer token (API/native clients) - either session ID or API token
	if session == nil {
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			token := strings.TrimPrefix(auth, "Bearer ")
			if isPersistentAPIToken(token) {
				// Prefixed token → persistent API token (hash-based lookup)
				session = GetSessionFromAPIToken(app.DB, token)
			} else {
				// Unprefixed → session ID (direct lookup)
				session = GetSessionFromDB(app.DB, token)
			}
		}
	}

	// 3. Edge-bridge identity. The router proxies authorized edge
	//    requests with `X-Benmore-Edge-User: <user_id>` after it has
	//    verified the visitor's consent token. Trusted ONLY when the
	//    request arrived from the loopback proxy (the per-app
	//    process listens on 127.0.0.1; only the router can hit it).
	//    See edge_router.go for the verification path.
	if session == nil {
		if uid := edgeBridgeUserID(r); uid > 0 {
			session = sessionForEdgeBridge(app, uid)
			if session != nil {
				session.Scopes = r.Header.Get("X-Benmore-Edge-Scope")
			}
		}
	}

	if session == nil {
		return nil
	}

	// Deactivation is already checked in GetSessionFromDB (returns nil if deactivated).
	// Check verified enforcement here since it depends on app config.
	if app.Design != nil && app.Design.Auth["require_verified"] == "true" && !session.Verified {
		return nil // unverified users blocked when require_verified is set
	}

	// Lazy-resolve org_id: if session has no org but app has org config,
	// re-check (handles signup → onboarding where user_roles is created after session)
	if !session.HasGroup() && app.Group != nil {
		resolved := ResolveGroupID(app.DB, app.Group, session.Email)
		if resolved != "" {
			session.GroupID = resolved
			// Only persist for real sessions, not API tokens
			if !strings.HasPrefix(session.ID, "apitoken:") && !strings.HasPrefix(session.ID, "edge:") {
				app.DB.Exec("UPDATE _benmore_sessions SET group_id = ? WHERE id = ?", resolved, session.ID)
			}
			// CRITICAL (v2.7.59+): re-load session.Roles now that the
			// effective group is known. The first load (in
			// GetSessionFromDB) ran with effectiveGroupID="" and only
			// picked up globally-scoped grants - group-scoped grants
			// for this user's newly-resolved group would be missed
			// for the rest of the request, breaking the tenant-aware
			// RBAC semantic. Re-running with the resolved group now
			// includes them.
			session.Roles = LoadSessionRoles(app.DB, session.UserID, session.Role, session.EffectiveGroupID())
		}
	}

	return applySessionRoleScopes(app, session)
}

// Shared by interactive sessions and durable scheduled-task identities.
func applySessionRoleScopes(app *App, session *Session) *Session {
	// Tenant role from the membership table (v2.7.164): when the
	// developer declares `groups.role_field`, the member's in-tenant
	// role (e.g. member_role on company_members) joins session.Roles
	// for the EFFECTIVE group, so `role:company_admin` access modes
	// enforce against the membership table directly. Runs BEFORE the
	// scope union below so a `roles:` mapping for the tenant role also
	// contributes its scopes.
	if app.Group != nil && app.Group.RoleField != "" && session.EffectiveHasGroup() {
		if mr := ResolveMembershipRole(app.DB, app.Group, session.Email, session.EffectiveGroupID()); mr != "" {
			held := false
			for _, r := range session.Roles {
				if r == mr {
					held = true
					break
				}
			}
			if !held {
				session.Roles = append(session.Roles, mr)
			}
		}
	}

	// Intersect explicit credential scopes with the UNION of current role
	// grants. A token may narrow a role, but must never bypass it.
	//
	// SECURITY: if roles are configured but NONE of the user's roles are
	// defined, deny access (empty scopes that will be checked = denied on
	// first API call). Undefined roles must NOT get full access.
	if app.Roles != nil {
		held := session.Roles
		if len(held) == 0 {
			held = []string{session.Role}
		}
		roleScopes := app.Roles.ResolveScopesForRoles(held)
		if roleScopes != "" {
			session.Scopes = intersectScopes(session.Scopes, roleScopes)
		} else {
			// No role defined in config matched - deny everything.
			session.Scopes = "_none_:read"
		}
	}
	// Permissions is the flattened scope tokens - used by the
	// `perm:<resource>:<action>` access mode and exposed in the
	// /api/_auth/profile payload for client-side gating.
	if session.Scopes != "" && session.Scopes != "_none_:read" {
		session.Permissions = strings.Fields(session.Scopes)
	}

	return session
}
